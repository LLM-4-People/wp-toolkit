"""reconcile-plugins action: rewrite ``active_plugins`` against the plugin
set that is actually INSTALLED.

After clean-files removes migration-plugin directories, the ``wp_options``
``active_plugins`` row still lists them. WordPress repairs this lazily and
only in wp-admin — ``wp-admin/plugins.php`` calls core's
``validate_active_plugins()``, which deactivates the entries whose main file
no longer exists — so a migrated dump stays inconsistent for every consumer
that never loads that screen (front-end, REST, cron) and, worse, keeps
re-importing the same stale list on the next migration.

This action is the headless equivalent, reached through the bridge's named-op
whitelist (``reconcile_active_plugins``): compare ``get_option('active_plugins')``
against ``get_plugins()`` and, on ``--apply``, drop exactly the entries whose
unit is missing through core's own 2-argument ``update_option()``. Registered
``applies=("ftp",)`` ONLY: the write is a bridge op against a live site, so
local mode is refused by the registry with rc 1 before a stack is built.

``plan`` (read-only):

1. ``bridge.reconcile_active_plugins()`` — the op WITHOUT its ``apply``
   flag, so the bridge's fail-closed default answers which entries are
   active-but-absent and rewrites nothing.
2. Nothing missing -> an EMPTY plan (the clean-db "nothing to do"
   precedent: no items, ``backup_tables == []`` deliberately, rc 0 in both
   phases, and no ``db_audit`` roundtrip).
3. ``bridge.call("db_audit")`` — the options-table identity, asked of
   :mod:`wpt.media_refs` (the ONE table-identity owner the analyzer, the
   keep-set and the witness ask). The pre-action snapshot scope stays the
   fail-safe "every audited table whose name ends in ``options``" (a stray
   ``wp_myoptions`` merely WIDENS it) and is pinned EXPLICITLY, the
   deactivate-plugin rule; the item's ``target`` is the ONE table that
   resolves. No options table, or a CONTESTED one (a second table ending
   in ``options`` this wire cannot tell apart — AIOSEO 4.x's
   ``aioseo_options`` really is one) -> :class:`SourceError`: never
   rewrite an option nobody snapshotted, and never name a target the run
   cannot prove.
4. One :class:`PlanItem` per missing entry: category ``db.active_plugins``,
   ``target`` = the resolved options table (display + fallback; the
   explicit pin is the authoritative scope), ``detail`` = the ``_LABEL``-owned
   ``"reconcile <plugin file> (not installed)"`` — the plugin file is the
   item's ONLY carrier and ``apply`` parses it back through this module's
   format.

``apply``:

* ONE ``bridge.reconcile_active_plugins(apply=True)`` — the op writes the
  rewritten list and then RE-READS the option, so its ``active_now`` is the
  persisted state, not the write's echo.
* Fail-closed verification: ``applied`` not True, ``updated`` not True (the
  rewrite was refused), a non-list ``removed``, a planned file absent from
  ``removed``, or an UNPLANNED file present in it (a plugin directory that
  disappeared between plan and apply) raises :class:`BridgeError` carrying
  the payload — the registry answers rc 1 and the snapshot is the revert.
  ``before``/``after`` counts are informational only.
* MANDATORY re-read (SPEC: verify after every change, never assume): a
  SECOND read-only call. It proves the persisted option no longer lists any
  absent plugin (``missing`` empty) and names none of the planned files.
  A non-empty answer raises — the option was not (fully) rewritten, so the
  run must not report success.
* Every planned item is marked done and enriched ``", deactivated (N->M
  active plugins)"``; ONE info apply summary.

``apply`` does NOT purge caches: the post-apply purge is the registry's job
(shared by every action), never this module's.

Logging: ``get_logger("actions.reconcile_plugins")`` — one info per phase,
plugin file names and counts only.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..audit.data import _opt_int, _tables_from_wire
from ..log import get_logger
from ..media_refs import resolve_role_by_name
from ..report import Plan, human_bytes
from ..types import BridgeError, PlanItem, SourceError
from .registry import register_action

if TYPE_CHECKING:
    from ..cli import Ctx

__all__ = ["ReconcilePluginsAction"]

log = get_logger("actions.reconcile_plugins")

#: Plan-item detail format — the ONE owner of the label shape; ``apply``
#: parses the plugin file back out after this fixed prefix. A plugin FILE
#: path contains no space and no "(", so the split below is exact.
_LABEL = "reconcile "

#: db_audit table-name suffix of the ONE table the rewrite mutates (the
#: wp_options ``active_plugins`` row) — structural, never a tunable.  TWO
#: facts hang off it: the SNAPSHOT scope is every table that merely ends in
#: it (fail-safe: a stray ``wp_xoptions`` widens the scope, never a miss),
#: while the plan item's TARGET is the one table the
#: :func:`~wpt.media_refs.resolve_role_by_name` identity rule resolves —
#: see :func:`_options_table`.
_OPTIONS_SUFFIX = "options"


def _options_table(tables: dict) -> str:
    """The table the plan item NAMES — the ONE table-identity owner's answer.

    Not ``sorted(matches)[0]``: ``db_audit`` reports the WHOLE
    ``information_schema`` base-table set, and on a site running All in One
    SEO 4.x — which really creates its own ``aioseo_options`` carrying the
    same ``option_name``/``option_value`` pair — the sorted first match is
    the PLUGIN's table, so the plan and every ``--report`` artifact named a
    table the rewrite never touches (the bridge rewrites through
    ``$wpdb->options``).  A contested identity is refused instead, with
    every candidate named: a plan may not aim a displayed target it cannot
    prove.
    """
    found = resolve_role_by_name(_OPTIONS_SUFFIX, tables)
    if not found.candidates:
        raise SourceError(
            "db_audit lists no table to back up the reconciliation "
            f"(needs a table ending with {_OPTIONS_SUFFIX!r}); "
            "refusing an unbacked mutation"
        )
    if found.ambiguous:
        raise SourceError(
            "db_audit lists several tables that could be this site's "
            f"{_OPTIONS_SUFFIX} table ({', '.join(found.candidates)}) and the "
            "wire carries no column list to tell them apart, so the "
            "reconciliation's target is unknown: refusing rather than naming "
            "the wrong table"
        )
    return found.name


def _label(plugin_file: str) -> str:
    """The human label for one planned reconciliation."""
    return f"{_LABEL}{plugin_file} (not installed)"


def _file_of(item: PlanItem) -> str:
    """The plugin file carried by one item's label (inverse of :func:`_label`).

    The trailing " (not installed)" group is taken off the END, not split at
    the first " (": a plugin directory name may itself contain a space and a
    parenthesis, and a first-match split would truncate the file path the
    plan is verified against.
    """
    body = item.detail[len(_LABEL):]
    plugin_file, sep, _suffix = body.rpartition(" (")
    return plugin_file if sep and body.endswith(")") else body


def _missing_of(payload: dict, action: str) -> list[str]:
    """The op's ``missing`` list, validated — a malformed answer is a
    :class:`BridgeError` carrying the payload, never a guessed plan."""
    raw = payload.get("missing")
    if not isinstance(raw, list) or any(not isinstance(f, str) or not f for f in raw):
        raise BridgeError(
            f"{action} response anomaly: missing={raw!r}", payload=payload
        )
    return list(raw)


class ReconcilePluginsAction:
    """The plan/apply pair; ``stack`` is the registry-built source trio."""

    def plan(self, ctx: "Ctx", stack: tuple) -> Plan:
        bridge = stack[2]
        if bridge is None:
            # Unreachable through the registry (ftp-only applicability);
            # guarded so a direct misuse fails inside the error contract.
            raise SourceError("reconcile-plugins requires the bridge (ftp mode only)")
        payload = bridge.reconcile_active_plugins()
        missing = _missing_of(payload, "reconcile_active_plugins")
        if not missing:
            log.info("plan: every active plugin is installed "
                     "(nothing to reconcile)")
            return Plan(items=[], backup_tables=[])

        # The options table, asked of the ONE identity owner (never a second
        # rule): the target is the table the bridge will really rewrite, and
        # the snapshot scope stays the over-inclusive "every table that ends
        # in 'options'".
        tables = _tables_from_wire(bridge.call("db_audit").get("tables"))
        options_table = _options_table(tables)
        options_tables = sorted(
            name for name in tables if name.endswith(_OPTIONS_SUFFIX)
        )

        items = [
            PlanItem(
                category="db.active_plugins",
                target=options_table,
                detail=_label(plugin_file),
            )
            for plugin_file in missing
        ]
        plan = Plan(items=items, backup_tables=options_tables)
        log.info(
            "plan: %d item(s), %s estimated",
            len(items), human_bytes(plan.est_bytes()),
        )
        return plan

    def apply(self, ctx: "Ctx", stack: tuple, plan: Plan) -> Plan:
        bridge = stack[2]
        if bridge is None:
            raise SourceError("reconcile-plugins requires the bridge (ftp mode only)")
        files = [
            _file_of(item) for item in plan.items if item.requires_apply
        ]
        if not files:
            return plan  # nothing planned — no bridge roundtrip

        payload = bridge.reconcile_active_plugins(apply=True)
        # Fail-closed verification: the payload must PROVE the rewrite.
        removed_raw = payload.get("removed")
        if payload.get("applied") is not True or payload.get("updated") is not True \
                or not isinstance(removed_raw, list):
            raise BridgeError(
                f"reconcile_active_plugins response anomaly: "
                f"applied={payload.get('applied')!r}, "
                f"updated={payload.get('updated')!r}, "
                f"removed={removed_raw!r}",
                payload=payload,
            )
        removed = {name for name in removed_raw if isinstance(name, str)}
        missing = [plugin_file for plugin_file in files if plugin_file not in removed]
        if missing:
            raise BridgeError(
                "reconcile_active_plugins did not remove "
                + ", ".join(missing)
                + f" (removed: {sorted(removed)})",
                payload=payload,
            )
        # The mirror image, and the same honesty rule users_reset follows: a
        # plugin directory that disappeared between plan and apply is
        # dropped too, and the operator must hear about an entry the printed
        # plan never named.
        unplanned = sorted(removed - set(files))
        if unplanned:
            raise BridgeError(
                "reconcile_active_plugins deactivated plugin(s) that were "
                "not in the plan: " + ", ".join(unplanned),
                payload=payload,
            )

        # MANDATORY re-read (verify-after-mutate): a SECOND read-only call
        # proves the PERSISTED option no longer lists an absent plugin, and
        # that it no longer names anything we planned to drop. The op's own
        # active_now is the write's own re-read; this is an independent one.
        check = bridge.reconcile_active_plugins()
        still = _missing_of(check, "reconcile_active_plugins (verification)")
        if still:
            raise BridgeError(
                "the active_plugins option still lists plugin(s) that are "
                "not installed: " + ", ".join(still),
                payload=check,
            )
        active_now = check.get("active_now")
        if not isinstance(active_now, list):
            raise BridgeError(
                f"reconcile_active_plugins response anomaly: "
                f"active_now={active_now!r}",
                payload=check,
            )
        lingering = [plugin_file for plugin_file in files
                     if plugin_file in active_now]
        if lingering:
            raise BridgeError(
                "the active_plugins option still lists " + ", ".join(lingering),
                payload=check,
            )

        # before/after are informational: unusable values degrade the
        # enrichment, never the verification above.
        before = _opt_int(payload.get("active_before"))
        after = _opt_int(payload.get("active_after"))
        note = (
            f", deactivated ({before}->{after} active plugins)"
            if before is not None and after is not None
            else ", deactivated"
        )
        for item in plan.items:
            if not item.requires_apply or _file_of(item) not in removed:
                continue
            item.done = True
            item.detail = item.detail + note
        log.info("apply: %d plugin file(s) deactivated (active plugins %s->%s)",
                 len(files), before, after)
        return plan


# The registry stores the decorated OBJECT and calls .plan/.apply on it
# (the deactivate/clean_files precedent: a bare class would be invoked with
# plan(ctx, stack) unbound and crash in run_action).
register_action("reconcile-plugins", applies=("ftp",))(ReconcilePluginsAction())
