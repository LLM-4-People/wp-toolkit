"""deactivate-plugin action: the bridge's plugin_deactivate capability as a
safe mutating command — rewrite the wp_options ``active_plugins`` row so the
plugin stops loading BEFORE anyone deletes its directory, making the change
reversible by reactivating the plugin in wp-admin (or by restoring the
options table from the pre-action snapshot with ``wpt restore --table``).

Command surface: ``wpt deactivate-plugin <slug>`` with
``ctx.extra = {"plugin": "<slug>"}`` (the CLI wiring owns argv; this module
reads only the Ctx). Registered ``applies=("ftp",)`` ONLY: the
deactivation is a DB write through the bridge — the toolkit's only DB
write path — and local mode is audit-only in v1, so a local run never
reaches ``plan`` (the registry refuses with rc 1 before building a stack).

Slug semantics — the toolkit's ONE rule (``wpt.audit.webroot.
_active_plugin_slugs``): the slug is the FIRST COMPONENT of an active
plugin FILE path ("akismet/akismet.php" -> "akismet"); a dirless
single-file plugin keeps its whole name ("hello.php"). The slug is used
as given (whitespace-stripped only, never case-folded); a
"folder/file.php" input is reduced to its directory exactly like the
bridge reduces the ``slugs`` entries it receives (bridge.php takes
``dirname``), so plan-side and bridge-side matching can never disagree.
Missing/empty/non-string -> :class:`WptError` (rc 1 via the registry
contract) before any bridge roundtrip.

``plan`` (read-only):

1. ONE ``bridge.call("info")`` — the plugin catalog (via the audit's own
   wire->fact converter ``_plugin_catalog``, the single owner of the
   unknown/active-flag semantics). The planned files are the ACTIVE
   entries whose first component equals the slug, in catalog order — a
   slug matching several active files plans ONE item per file (all are
   deactivated; the bridge's dirname match covers the whole directory).
2. Nothing active under the slug -> an EMPTY plan (the clean-db "nothing
   to do" precedent: no items, ``backup_tables == []`` deliberately
   empty, rc 0 in both phases, no ``db_audit`` roundtrip — the trim-media
   precedent of querying the audit only when something needs backing
   up). One info log names WHY: "installed but not active" (goal already
   met) vs "matches no installed plugin" (likely a typo) — both from the
   one catalog already fetched.
3. ``bridge.call("db_audit")`` — the options-table identity, asked of
   :mod:`wpt.media_refs` (the ONE table-identity owner the analyzer, the
   keep-set and the witness ask): the plan item's ``target`` is the ONE
   table that resolves, and a contested identity — a second table ending
   in ``options`` that this wire cannot tell apart, which AIOSEO 4.x's
   ``aioseo_options`` really is — is a :class:`SourceError`: the run
   refuses rather than naming a table it cannot prove.  NO options table
   at all -> :class:`SourceError` as before: never mutate unbacked (the
   framework's rule).

Item shape: category ``db.active_plugins`` (the ``db.`` prefix is what
the registry's fallback snapshot-scope derivation reads), ``target`` =
the resolved options table (display + fallback; the explicit
``backup_tables`` below is the authoritative scope), ``detail`` =
"deactivate <plugin file>" — the label is the plugin file's ONLY carrier,
and ``apply`` parses it back through this module's ``_LABEL`` format
(the single owner).  ``bytes_est`` = 0 (an options-row rewrite reclaims
nothing estimable — same reasoning as clean-db's row ops).

``plan.backup_tables`` is set EXPLICITLY to every discovered options
table (clean-db style: the deliberate pin documents the snapshot scope;
the category+target derivation would name only one entry, and the
fail-safe direction wants them all) — so the over-inclusive scope and the
proved target are BOTH right and are not the same question.  The empty
plan pins ``[]`` deliberately (nothing to mutate), same as clean-db's
optimize-only plans.


``apply`` (the plan is executed as-is — no re-resolution, no live re-read):

* ONE ``bridge.call("plugin_deactivate", slugs=<planned files>)`` — the
  bridge's param name is ``slugs`` (a string LIST; the handler takes
  ``dirname`` of "folder/file.php" entries itself and matches dirless
  plugins by filename — mirroring this plan's first-component match
  exactly), so the planned FILES are sent verbatim.
* Response verification (fail-closed mid-apply): ``ok:true`` with
  ``updated`` not True (update_option refused the rewrite), a
  missing/non-list ``removed``, or a planned file ABSENT from
  ``removed`` raises :class:`BridgeError` carrying the payload — the
  registry aborts with rc 1 and nothing prints as success; the
  pre-action snapshot (the options table) already exists, so the state
  is reversible. ``before``/``after`` counts are informational: unusable
  ones degrade the detail enrichment, never the verification.
* ``ok:true`` + every planned file in ``removed``: each matching item is
  marked done and enriched ``", deactivated (N->M active plugins)"``;
  ONE info apply summary. An ``ok:false`` :class:`BridgeError` from the
  client propagates UNTOUCHED (no partial state exists to mark — ONE
  update_option covers every file), items stay ``done=False``, rc 1
  after the backup.
* Files that activated under the same slug between plan and apply may
  ride ``removed`` without being planned: they are the same slug the
  operator asked to deactivate — visible in the payload's ``removed``
  list, never an error.

``apply`` does NOT purge caches: a post-apply LiteSpeed purge is the
registry's job (shared by every action), never this module's.

Logging: ``get_logger("actions.deactivate")`` — one info per phase
(plan summary / apply summary); never cell contents.
"""

from __future__ import annotations

import posixpath
from typing import TYPE_CHECKING

from ..audit.data import _opt_int, _plugin_catalog, _tables_from_wire
from ..log import get_logger
from ..media_refs import resolve_role_by_name
from ..report import Plan, human_bytes
from ..types import BridgeError, PlanItem, SourceError, WptError
from .registry import register_action

if TYPE_CHECKING:
    from ..cli import Ctx

__all__ = ["DeactivatePluginAction"]

log = get_logger("actions.deactivate")

#: Plan-item detail format — the ONE owner of the label shape; ``apply``
#: parses the plugin file back out after this fixed prefix (the item
#: target carries the options TABLE, so the label is the file's only
#: carrier).
_LABEL = "deactivate "

#: The db_audit table-name suffix of the ONE table plugin_deactivate mutates
#: (the wp_options ``active_plugins`` row) — structural, never a tunable.
#: TWO facts hang off it and they are not the same: the SNAPSHOT scope is
#: every table that merely ENDS in it (fail-safe: a stray ``wp_xoptions``
#: widens the scope, never a miss), while the plan item's TARGET is the one
#: table the :func:`~wpt.media_refs.resolve_role_by_name` identity rule
#: resolves — see :func:`_options_table`.
_OPTIONS_SUFFIX = "options"


def _options_table(tables: dict) -> str:
    """The table the plan item NAMES — the ONE table-identity owner's answer.

    Not ``sorted(matches)[0]``: ``db_audit`` reports the WHOLE
    ``information_schema`` base-table set, and on a site running All in One
    SEO 4.x — which really creates its own ``aioseo_options`` carrying the
    same ``option_name``/``option_value`` pair — the sorted first match is
    the PLUGIN's table.  The mutation was never aimed at it (the bridge
    rewrites through ``$wpdb->options``) and the snapshot scope stays
    over-inclusive, so the WRITE was safe and the REPORT was wrong: the
    item target and every ``--report`` artifact named a table nothing
    touches.  A plan that names the wrong table is a plan the operator
    cannot trust, so the target is asked of the owner and a contested
    identity refuses the run instead of guessing.
    """
    found = resolve_role_by_name(_OPTIONS_SUFFIX, tables)
    if not found.candidates:
        raise SourceError(
            "db_audit lists no table to back up the deactivation "
            f"(needs a table ending with {_OPTIONS_SUFFIX!r}); "
            "refusing an unbacked mutation"
        )
    if found.ambiguous:
        raise SourceError(
            "db_audit lists several tables that could be this site's "
            f"{_OPTIONS_SUFFIX} table ({', '.join(found.candidates)}) and the "
            "wire carries no column list to tell them apart, so the "
            "deactivation's target is unknown: refusing rather than naming "
            "the wrong table"
        )
    return found.name


def _label(file: str) -> str:
    """The human label for one planned deactivation."""
    return _LABEL + file


def _file_of(item: PlanItem) -> str:
    """The plugin file carried by one item's label (inverse of _label)."""
    return item.detail[len(_LABEL):]


class DeactivatePluginAction:
    """The plan/apply pair; ``stack`` is the registry-built source trio."""

    def plan(self, ctx: "Ctx", stack: tuple) -> Plan:
        bridge = stack[2]
        if bridge is None:
            # Unreachable through the registry (ftp-only applicability);
            # guarded so a direct misuse fails inside the error contract.
            raise SourceError("deactivate-plugin requires the bridge (ftp mode only)")
        slug = ctx.extra.get("plugin")
        if not isinstance(slug, str) or not slug.strip():
            raise WptError(
                "deactivate-plugin requires a plugin slug "
                '(e.g. "litespeed-cache" — the plugin directory name)'
            )
        slug = slug.strip()
        # The bridge's own input tolerance: "folder/file.php" -> directory.
        if "/" in slug:
            slug = posixpath.dirname(slug)

        catalog = _plugin_catalog(bridge.call("info").get("plugins"))
        files = [
            file
            for file, meta in catalog.items()
            if meta["active"] and file.split("/")[0] == slug
        ]
        if not files:
            if any(file.split("/")[0] == slug for file in catalog):
                log.info("plan: %s is installed but not active "
                         "(nothing to deactivate)", slug)
            else:
                log.info("plan: %s matches no installed plugin "
                         "(nothing to deactivate)", slug)
            return Plan(items=[], backup_tables=[])

        # The options table, asked of the ONE identity owner (never a second
        # rule): the target is the table the bridge will really rewrite, and
        # the snapshot scope stays the over-inclusive "every table that ends
        # in 'options'" (a stray one only ever widens a backup).
        tables = _tables_from_wire(bridge.call("db_audit").get("tables"))
        options_table = _options_table(tables)
        options_tables = sorted(
            name for name in tables if name.endswith(_OPTIONS_SUFFIX)
        )

        items = [
            PlanItem(
                category="db.active_plugins",
                target=options_table,
                detail=_label(file),
            )
            for file in files
        ]
        plan = Plan(items=items, backup_tables=options_tables)
        log.info(
            "plan: %d item(s), %s estimated", len(items), human_bytes(plan.est_bytes())
        )
        return plan

    def apply(self, ctx: "Ctx", stack: tuple, plan: Plan) -> Plan:
        bridge = stack[2]
        if bridge is None:
            raise SourceError("deactivate-plugin requires the bridge (ftp mode only)")
        files = [
            _file_of(item) for item in plan.items if item.requires_apply
        ]
        if not files:
            return plan  # nothing planned — no bridge roundtrip
        payload = bridge.call("plugin_deactivate", slugs=files)

        # Fail-closed verification: the payload must PROVE the rewrite.
        removed_raw = payload.get("removed")
        updated = payload.get("updated")
        if not isinstance(removed_raw, list) or updated is not True:
            raise BridgeError(
                f"plugin_deactivate response anomaly: updated={updated!r}, "
                f"removed={removed_raw!r}",
                payload=payload,
            )
        removed = {name for name in removed_raw if isinstance(name, str)}
        missing = [file for file in files if file not in removed]
        if missing:
            raise BridgeError(
                "plugin_deactivate did not remove " + ", ".join(missing)
                + f" (removed: {sorted(removed)})",
                payload=payload,
            )

        # before/after are informational: unusable values degrade the
        # enrichment, never the verification above.
        before = _opt_int(payload.get("before"))
        after = _opt_int(payload.get("after"))
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


# The registry stores the decorated OBJECT and calls .plan/.apply on it,
# so the registered action is the instance (same as clean_files/clean_db:
# a bare class would be invoked with plan(ctx, stack) unbound and crash
# in run_action).
register_action("deactivate-plugin", applies=("ftp",))(DeactivatePluginAction())
