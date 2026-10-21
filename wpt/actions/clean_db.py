"""clean-db action (W7e): the four named DB cleanups.

Two-phase action over the shared registry flow (``wpt.actions.registry`` —
the registry owns dry-run, confirmation, the fail-closed pre-action backup
and the mode-applicability refusal; this module is pure domain logic).
Registered ``applies=("ftp",)`` ONLY: the bridge is the toolkit's only DB
write path, so a local clean-db never reaches ``plan`` (the registry refuses
with rc 1 before building a stack) — UNLESS the operator points the run at
a database of their own with ``--db-uri`` (see the OFFLINE path below).

``plan`` (read-only) issues ONE ``bridge.call("db_audit")`` and derives
PlanItems with EXACTLY the trigger semantics of the matching audit checks
(``wpt.audit.dbcheck`` — the single semantic owner; the wire→fact
conversion helpers are imported from ``wpt.audit.data`` so the action and
the audit can never disagree about unknown vs measured zero):

============================  ==========================================
audit check (owner)           action trigger (same rule)
============================  ==========================================
db.revisions                  revisions > 0 (None/absent unknown; 0 is
                              a measured zero — both never trigger)
db.transients                 expired_transients > 0 (same three states)
db.orphan_meta                orphan_meta kind present with count > 0
                              (absent kind = unknown; present at 0 =
                              measured zero — key presence, never a
                              default-0 lookup)
db.optimize                   table data_free_bytes known (not None) and
                              >= settings.db.free_space_warn_bytes
============================  ==========================================

Item shape (category, target, bytes_est); ``target`` is always the
``db_clean`` OP NAME (the bridge whitelist vocabulary — never a table):

* ``db.optimize`` / ``optimize_tables`` — one item when any table
  qualifies; detail ``"N tables, ~X reclaimable"`` (X = human_bytes of the
  summed free bytes), bytes_est = that sum (the only estimable bytes;
  revision/transient/orphan ROW bytes are unknowable from the audit, so
  those items carry bytes_est=0 — same reasoning as the checks).
* ``db.orphan_meta`` / ``orphan_meta`` — ONE item even when several kinds
  trigger (ONE bridge op covers all kinds): detail is
  ``"{kind}: {n} orphan rows"`` for a single kind and the same shape with
  the triggering kinds joined by ``+`` (sorted) and their counts summed
  for several, e.g. ``"commentmeta+postmeta: 7 orphan rows"``.
* ``db.revisions`` / ``revisions`` — detail ``"{n} revisions + auto-drafts"``.
* ``db.transients`` / ``expired_transients`` — detail
  ``"{n} expired transients"``.

Items are sorted by ``(category, target)`` — deterministic plans and
apply order; an empty audit (or a fully clean one) yields an empty plan.

``plan.backup_tables`` (the registry's preferred pre-action snapshot
scope) lists the tables the planned ops would MUTATE, derived from the
db_audit table names: ``revisions`` → the table(s) ending with ``posts``,
``expired_transients`` → ``options``, ``orphan_meta`` → ``postmeta`` +
``termmeta`` + ``commentmeta`` (the op DELETEs from all three even when
only one kind is orphaned). Suffix matching is a plain ``endswith`` —
fail-safe in the safe direction (a stray ``wp_myoptions`` would merely be
snapshotted too, never a miss). ``optimize_tables`` mutates no rows and
is EXCLUDED, so an OPTIMIZE-only plan carries ``backup_tables == []``.
Fail-closed: if a triggering row-op's table cannot be located in the
audit, ``plan`` raises SourceError instead of planning an unbacked
mutation ("never mutate unbacked" is the framework's rule).

``apply`` collects ``item.target`` for every ``requires_apply`` item,
dedupes preserving plan order (defensive — the plan builds one item per
op), and issues ONE ``bridge.call("db_clean", ops=ops)`` (the bridge runs
every op in one request with per-op try/catch). An empty plan applies
without any bridge call. Outcomes:

* ``ok:true`` — every ``requires_apply`` item is marked done and its
  detail is enriched with the op's reported count: ``", removed N rows"``
  (revisions / expired_transients / orphan_meta) or
  ``", optimized N tables"`` (optimize_tables reports the count of
  tables it optimized, not rows).
* ``BridgeError`` (``ok:false`` — at least one op failed) — the payload
  still carries the per-op ``results`` and ``errors``: each failed op is
  logged at warning (op name + server message), items whose op is in
  ``results`` are marked done and enriched, the rest stay ``done=False``,
  and the BridgeError is RE-RAISED so the registry reports the failure
  (the pre-action backup already exists; the operator can restore). The
  partially-applied plan is therefore NOT printed as success.

THE OFFLINE PATH (``--db-uri``, local mode) — the same ops, no second
implementation. A migration session that wanted "clean → optimize → TEST →
publish later" had no choice but to publish first or hand-port the bridge's
SQL against a local server; that hand-port is exactly the drift this path
removes. ``run_offline`` (below) reuses :meth:`CleanDbAction._plan_from_audit`
and :meth:`CleanDbAction._settle` — the SAME plan builder and the SAME
results contract — and only replaces the two roundtrips:

* the audit is :meth:`OfflineDb.audit`, which runs the bridge's own SQL
  against the URI and returns the same wire dict, so
  ``_tables_from_wire``/``_orphan_meta_from_wire``/``_opt_int`` still
  decide every fact;
* the apply is :meth:`OfflineDb.clean`, which runs the SAME per-op
  statements in the same per-op try/catch and returns the same
  ``{op: count}`` results map.

The SQL itself is the bridge's, mirrored ONCE in the constants below
(``{p}`` = the discovered table prefix) and CONTRACT-PINNED against
``wpt/wpbridge/bridge.php`` by ``tests/test_dbconn.py`` — the mirror
convention the autoload set already uses. Editing either side alone
fails the suite. (The schema introspection and the reserved-name filter
are mirrored the same way, and live with the connection in
``wpt.localmode.dbconn`` — one query, read by the audit, the dump and the
doctor's connectivity row.)

``--db-uri`` NAMES A DATABASE, and the operator can name the WRONG one:
an apply deletes rows, and there is no snapshot behind it on this path.
So the offline run compares the database's OWN identity with the run's
``--wp-url`` immediately after connecting — one two-row read of
``siteurl``/``home``, before the audit, before the plan and before any
statement (:func:`site_identity_gate`; the comparison rule is
``wpt.actions.dump_witness``'s own, imported, because a dump witness and
a live-database gate cannot be held to two different notions of "the
same site"). A mismatch, and a database that states neither option at
all, are refused by name; a database that states only one of the two
proceeds with a warning, because half the evidence is not a mismatch.

Three things the offline flow deliberately does NOT pretend to have:

* **no pre-action snapshot.** The registry's snapshot needs the bridge's
  ``db_dump``; offline the rollback is the dump the operator imported this
  database from. The apply says so out loud (one info line) instead of
  implying a safety net that does not exist.
* **no rehearsal, no webroot.** Local mode's registry branch materializes a
  ``<zip>-rehearsed-*.zip``; clean-db over a URI touches no file at all, so
  it does not go through that branch (it is why ``run_offline`` is a
  separate entry point rather than a second registration).
* **no cache purge.** Nothing was deployed.

After a successful apply the offline path VERIFIES: it re-reads the same
audit facts and re-checks every applied op's trigger. An op whose trigger
still holds — or whose fact could not be re-measured at all — is NOT
done, so the run reports failure rather than a clean report over a
database that did not change (``optimize_tables`` is exempt — reclaiming
free space is the server's business, and its own "N tables optimized"
count is its evidence; the fact is logged).

Logging: ``get_logger("actions.clean_db")``; one info plan summary;
warnings carry op names and server error text only — never cell contents,
never a credential.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from ..audit.data import _opt_int, _orphan_meta_from_wire, _tables_from_wire
from ..config import redact_text
from ..deadline import Deadline
from ..localmode.analyzer import php_unserialize
from ..localmode.dbconn import (DbUri, connect, dump_database, parse_db_uri,
                                quote_ident, schema_tables)
from ..log import get_logger
from ..media_refs import options_prefix, resolve_role
from ..report import Plan, human_bytes, render_json, render_report
from ..report import write_stdout
from ..types import (BridgeError, PlanItem, RunControl, SourceError, WptError)
from .dump_witness import site_identity
from .registry import (_audit_stub, confirm, not_complete, register_action,
                       write_report, write_failure_report)

if TYPE_CHECKING:
    from ..cli import Ctx
    from ..localmode.dbconn import DbConnection

__all__ = ["CleanDbAction", "OfflineDb", "run_offline", "site_identity_gate"]

log = get_logger("actions.clean_db")

#: db_audit table-name suffixes each ROW-mutating op touches — the op→tables
#: map for the pre-action backup scope. ``optimize_tables`` mutates no rows
#: and is deliberately absent. The orphan_meta op DELETEs from all three
#: meta tables even when only one kind is orphaned.
_ROW_OP_TABLES: dict[str, tuple[str, ...]] = {
    "revisions": ("posts",),
    "expired_transients": ("options",),
    "orphan_meta": ("postmeta", "termmeta", "commentmeta"),
}

# ---------------------------------------------------------------------------
# The bridge's SQL, mirrored. ``{p}`` stands for the table prefix ($wpdb's).
# Contract-pinned against wpt/wpbridge/bridge.php — see the module docstring.
# ---------------------------------------------------------------------------

#: revisions: the audit COUNT and the db_clean DELETE are the same predicate.
REVISIONS_TAIL = (
    "{p}posts WHERE post_type = 'revision' OR post_status = 'auto-draft'"
)

#: The shared expired-transient body (bridge: wpt_expired_transients_sql),
#: parameterised by its head exactly as the PHP is (``$head``): the audit
#: passes ``SELECT COUNT(*)``, db_clean passes ``DELETE t, s``. The join is
#: what makes the cleanup correct — a ``_transient_x`` row is only expired
#: when its ``_transient_timeout_x`` companion is in the past, and the
#: multi-table DELETE takes the companion row with it.
EXPIRED_TRANSIENTS_SQL = (
    " FROM {p}options t"
    " INNER JOIN {p}options s ON s.option_name = REPLACE("
    " t.option_name, '_transient_', '_transient_timeout_' )"
    " WHERE ( t.option_name LIKE '\\_transient\\_%'"
    " OR t.option_name LIKE '\\_site_transient\\_%' )"
    " AND t.option_name NOT LIKE '%\\_transient\\_timeout\\_%'"
    " AND s.option_value < UNIX_TIMESTAMP()"
)

#: orphan_meta per kind: the DELETE and the COUNT share the tail, and the
#: DELETE's head carries the alias (``DELETE pm FROM ...``).
_ORPHAN_HEADS = ("DELETE {a}", "SELECT COUNT(*)")
_ORPHAN_TAILS: dict[str, tuple[str, str]] = {
    "postmeta": (
        "pm",
        "FROM {p}postmeta pm LEFT JOIN {p}posts p ON p.ID = pm.post_id"
        " WHERE p.ID IS NULL",
    ),
    "termmeta": (
        "tm",
        "FROM {p}termmeta tm LEFT JOIN {p}terms t ON t.term_id = tm.term_id"
        " WHERE t.term_id IS NULL",
    ),
    "commentmeta": (
        "cm",
        "FROM {p}commentmeta cm LEFT JOIN {p}comments c ON c.comment_ID = cm.comment_id"
        " WHERE c.comment_ID IS NULL",
    ),
}


def orphan_sql(kind: str, *, head_index: int) -> str:
    """One orphan_meta statement: ``head_index`` 0 = the DELETE, 1 = the COUNT."""
    alias, tail = _ORPHAN_TAILS[kind]
    head = _ORPHAN_HEADS[head_index].format(a=alias)
    return f"{head} {tail}"


def revisions_sql(*, count: bool) -> str:
    """The revisions statement: the audit COUNT or the db_clean DELETE.

    Built by concatenation, never ``str.format``: the statement already
    carries the ``{p}`` prefix placeholder, which the caller substitutes
    once, with the resolved table prefix.
    """
    head = "SELECT COUNT(*)" if count else "DELETE"
    return f"{head} FROM {REVISIONS_TAIL}"


def transients_sql(*, count: bool) -> str:
    """The expired-transient statement (the bridge's shared body + head)."""
    head = "SELECT COUNT(*)" if count else "DELETE t, s"
    return f"{head}{EXPIRED_TRANSIENTS_SQL}"


def optimize_sql(table: str) -> str:
    """One OPTIMIZE TABLE, over the whitelisted (information_schema) name."""
    return f"OPTIMIZE TABLE {quote_ident(table)}"


def _tables_for_op(tables: dict[str, Any], op: str) -> tuple[list[str], list[str]]:
    """Audit tables whose name ends with one of ``op``'s suffixes.

    Returns ``(found, missing_suffixes)`` — every suffix of a triggered op
    must match at least one audited table (fail-closed: a mutation must
    never run against a table the snapshot could not locate).
    """
    found: list[str] = []
    missing: list[str] = []
    for suffix in _ROW_OP_TABLES[op]:
        matches = sorted(name for name in tables if name.endswith(suffix))
        found.extend(matches)
        if not matches:
            missing.append(suffix)
    return found, missing



def _as_map(raw: Any) -> dict[str, Any]:
    """A dict payload field; {} for anything missing or malformed."""
    return raw if isinstance(raw, dict) else {}


def _op_note(op: str, count: int) -> str:
    """Detail suffix for one op's reported count (op-aware noun)."""
    if op == "optimize_tables":
        return f"optimized {count} tables"
    return f"removed {count} rows"


class CleanDbAction:
    """The plan/apply pair; ``stack`` is the registry-built source trio."""

    def plan(self, ctx: "Ctx", stack: tuple) -> Plan:
        bridge = stack[2]
        if bridge is None:
            # Unreachable through the registry (ftp-only applicability);
            # guarded so a direct misuse fails inside the error contract.
            raise SourceError("clean-db requires the bridge (ftp mode only)")
        return self._plan_from_audit(bridge.call("db_audit"), ctx.settings)

    @classmethod
    def _plan_from_audit(cls, db_audit: dict[str, Any], settings) -> Plan:
        """THE plan builder — shared verbatim by the bridge and the URI.

        One implementation, so an offline plan can never disagree with an
        ftp plan about a trigger, an item's wording or the snapshot scope.
        Takes the db_audit WIRE dict (whatever produced it) and the
        settings, and returns the Plan.
        """
        # Wire -> facts through the audit's own converters: the unknown-vs-
        # measured-zero contract and the kb/mb->bytes rounding live in ONE
        # place (wpt.audit.data), never mirrored here.
        revisions = _opt_int(db_audit.get("revisions"))
        transients = _opt_int(db_audit.get("expired_transients"))
        orphans = _orphan_meta_from_wire(db_audit.get("orphan_meta"))
        tables = _tables_from_wire(db_audit.get("tables"))

        items: list[PlanItem] = []
        backup: set[str] = set()
        missing: list[tuple[str, str]] = []  # (op, suffix) with no table

        # db.optimize — same trigger as check_db_optimize: free bytes known
        # and at/above settings.db.free_space_warn_bytes.
        threshold = settings.db.free_space_warn_bytes
        free_bytes = [
            fact.data_free_bytes
            for fact in tables.values()
            if fact.data_free_bytes is not None and fact.data_free_bytes >= threshold
        ]
        if free_bytes:
            total = sum(free_bytes)
            items.append(
                PlanItem(
                    category="db.optimize",
                    target="optimize_tables",
                    detail=f"{len(free_bytes)} tables, ~{human_bytes(total)} reclaimable",
                    bytes_est=total,
                )
            )

        # db.orphan_meta — ONE item (one op covers all kinds); triggering
        # kinds only, joined sorted with their counts summed.
        triggered = {kind: count for kind, count in orphans.items() if count > 0}
        if triggered:
            items.append(
                PlanItem(
                    category="db.orphan_meta",
                    target="orphan_meta",
                    detail=(
                        f"{'+'.join(sorted(triggered))}: "
                        f"{sum(triggered.values())} orphan rows"
                    ),
                )
            )
            cls._scope_tables(tables, "orphan_meta", backup, missing)

        # db.revisions — None (unknown) and 0 (measured) are both silent.
        if revisions is not None and revisions > 0:
            items.append(
                PlanItem(
                    category="db.revisions",
                    target="revisions",
                    detail=f"{revisions} revisions + auto-drafts",
                )
            )
            cls._scope_tables(tables, "revisions", backup, missing)

        # db.transients — same three-state rule.
        if transients is not None and transients > 0:
            items.append(
                PlanItem(
                    category="db.transients",
                    target="expired_transients",
                    detail=f"{transients} expired transients",
                )
            )
            cls._scope_tables(tables, "expired_transients", backup, missing)

        # Fail-closed: a triggering row-op whose mutation tables the audit
        # cannot name must never become a plan (the apply would run unbacked).
        if missing:
            detail = "; ".join(
                f"{op} needs a table ending with {suffix!r}" for op, suffix in missing
            )
            raise SourceError(
                f"db_audit lists no table to back up the cleanup ({detail}); "
                "refusing an unbacked mutation"
            )

        items.sort(key=lambda item: (item.category, item.target))
        plan = Plan(items=items, backup_tables=sorted(backup))
        log.info(
            "plan: %d item(s), %s estimated", len(items), human_bytes(plan.est_bytes())
        )
        return plan

    def apply(self, ctx: "Ctx", stack: tuple, plan: Plan) -> Plan:
        bridge = stack[2]
        if bridge is None:
            raise SourceError("clean-db requires the bridge (ftp mode only)")
        ops = planned_ops(plan)
        if not ops:
            return plan  # nothing to clean — no bridge roundtrip
        try:
            payload = bridge.call("db_clean", ops=ops)
        except BridgeError as exc:
            # Partial results ride the exception payload. Log each failed
            # op at warning FIRST (the registry will only report the
            # overall failure), mark what succeeded, then re-raise so the
            # registry reports it — the pre-action backup exists.
            for op, message in sorted(_as_map(exc.payload.get("errors")).items()):
                log.warning("db_clean op %s failed: %s", op, message)
            self._settle(plan, _as_map(exc.payload.get("results")), mark_all=False)
            raise
        self._settle(plan, _as_map(payload.get("results")), mark_all=True)
        return plan

    # ----------------------------------------------------------- internals

    @staticmethod
    def _scope_tables(
        tables: dict[str, Any],
        op: str,
        backup: set[str],
        missing: list[tuple[str, str]],
    ) -> None:
        """Add op's mutation tables to the snapshot scope (or record gaps)."""
        found, gaps = _tables_for_op(tables, op)
        backup.update(found)
        missing.extend((op, suffix) for suffix in gaps)

    @staticmethod
    def _settle(plan: Plan, results: dict[str, Any], *, mark_all: bool) -> None:
        """Mark items done from the db_clean results; enrich with counts.

        ``mark_all`` is the ok:true contract (every requested op ran); a
        partial failure passes ``mark_all=False`` so only ops the payload
        reports in ``results`` are marked done. Counts are enriched only
        when the payload carries a usable integer.
        """
        for item in plan.items:
            if not item.requires_apply:
                continue
            if not (mark_all or item.target in results):
                continue
            item.done = True
            count = _opt_int(results.get(item.target))
            if count is not None:
                item.detail = f"{item.detail}, {_op_note(item.target, count)}"


def planned_ops(plan: Plan) -> list[str]:
    """The bridge/db_clean op names a plan would run, deduped, in plan order.

    The ONE place the op list is derived — the ftp apply and the offline
    apply both call it, so the two can never send a different set.
    """
    ops: list[str] = []
    for item in plan.items:
        if item.requires_apply and item.target not in ops:
            ops.append(item.target)
    return ops


# ===========================================================================
# The offline path: local mode + --db-uri.  Same plan, same ops, same
# results contract — the direct database replaces the bridge roundtrips.
# ===========================================================================


#: The options table is the DB's own proof of its prefix.  Both questions
#: are asked of :mod:`wpt.media_refs` — the ONE table-identity owner, which
#: the analyzer and the media keep-set measurement ask over a dump: WHICH
#: table proves the role (:func:`~wpt.media_refs.resolve_role`) and what
#: PREFIX its name declares (:func:`~wpt.media_refs.options_prefix`), so
#: ``wp_`` is never assumed and no reader re-derives the identity.
#:
#: What is decided HERE is only the POLICY, which genuinely differs from a
#: measurement's: a destructive plan built on a wrong prefix deletes the
#: wrong rows, so a CONTESTED options identity REFUSES the run instead of
#: picking one.  The old behaviour (warn, then take the first by name) is
#: exactly the false certainty this refuses: on a site running All in One
#: SEO 4.x — which really creates its own ``aioseo_options`` — the
#: ``sorted()`` winner is the PLUGIN's table, every statement would have
#: been aimed at it, and the report would have read as a clean run.
_OPTIONS_COLUMNS_SQL = (
    "SELECT TABLE_NAME, COLUMN_NAME FROM information_schema.COLUMNS"
    " WHERE TABLE_SCHEMA = DATABASE() AND COLUMN_NAME IN"
    " ('option_name', 'option_value')"
)


def discover_prefix(conn: "DbConnection") -> str:
    """The table prefix of the connected database (never guessed).

    Refuses on BOTH facts the owner's rule can report: no table proves the
    options role (is this even the site's database?) and more than one does
    (which one is it? — a destructive plan cannot be built on a guess).
    """
    columns: dict[str, set[str]] = {}
    for row in conn.query_rows(_OPTIONS_COLUMNS_SQL):
        if len(row) < 2:
            continue
        name, column = str(row[0] or ""), str(row[1] or "")
        columns.setdefault(name, set()).add(column)
    found = resolve_role("options", columns)
    if not found.candidates:
        raise WptError(
            "no WordPress options table in this database (looked for a table "
            "ending in 'options' with option_name + option_value columns) — "
            "is --db-uri pointing at the site's own database?")
    if found.ambiguous:
        raise WptError(
            "multiple tables in this database prove the options role ("
            + ", ".join(found.candidates) + "): the table prefix is unknown, "
            "so there is nothing safe to clean — remove the plugin table or "
            "the stale copy and run again (refusing rather than guessing "
            "which one is the site's)")
    return options_prefix(found.name)


# ---------------------------------------------------------------------------
# "Is this the DATABASE the operator meant?" — the one place both identities
# are visible.
# ---------------------------------------------------------------------------

#: The two options that NAME a WordPress install, read straight from the
#: table the prefix was derived from (never from a guess, and never from a
#: dump of another site).  Two rows maximum — this is a lookup, not a scan.
_IDENTITY_SQL = (
    "SELECT option_name, option_value FROM {options}"
    " WHERE option_name IN ('siteurl', 'home')"
)


def _identity_values(conn: "DbConnection", prefix: str) -> dict[str, str]:
    """The database's own ``siteurl``/``home``, as read strings.

    One row per option, values read with the ONE option-value policy
    (:func:`wpt.localmode.analyzer.php_unserialize`, the analyzer's own
    delegate to the one PHP decoder): a real store keeps a scalar option
    PLAIN (``maybe_serialize`` leaves scalars alone — corpus-proven in
    SPEC) and a serialized string is also accepted, so both real shapes
    answer.  An option that is absent, non-text, or a value of another
    shape is simply not in the map — the caller decides what a missing
    identity means, and a cell nobody can read must not be turned into
    one that matches.
    """
    sql = _IDENTITY_SQL.format(options=quote_ident(f"{prefix}options"))
    found: dict[str, str] = {}
    for row in conn.query_rows(sql):
        if len(row) < 2:
            continue
        name, raw = str(row[0] or ""), row[1]
        if name not in ("siteurl", "home") or not isinstance(raw, str):
            continue
        value = raw
        if value[:2] in ("s:", "a:", "i:", "b:", "d:", "O:", "C:", "E:"):
            try:
                value = php_unserialize(value)
            except ValueError:
                continue
        if isinstance(value, str) and value.strip():
            found[name] = value.strip()
    return found


def site_identity_gate(conn: "DbConnection", prefix: str,
                       wp_url: str | None) -> None:
    """REFUSE a ``--db-uri`` that is not the site this run is about.

    The reproduced harm: ``--db-uri mysql://…/otherapp_db clean-db --apply
    --yes`` against a database whose own ``siteurl``/``home`` are another
    site's, with ``--wp-url`` naming this one.  Nothing compared the two
    identities, so the plan built happily, the apply deleted THAT site's
    revisions and termmeta rows, and the verification pass reported
    "revisions is clean after the apply" — a clean report over another
    site's data.  The offline path is the only place that sees BOTH (the
    operator's requested URL and the database's own answer), so this is
    where the question belongs, and it runs immediately after the
    connection: one two-row lookup, before the audit, before the plan and
    long before any statement.

    The comparison is :func:`wpt.actions.dump_witness.site_identity` —
    the cross-mode witness's OWN rule, imported, not re-derived: host and
    path, insensitive to scheme, port, a ``www.`` prefix and a trailing
    slash.  Two sites could not agree on that question and the offline
    apply would have no idea which rule it was held to.

    The three answers, and why they differ:

    * **both options present, neither matching** — REFUSED, naming the
      DATABASE's own ``siteurl`` and the requested URL.  This is a
      wrong-database refusal, so the line names the database (and what an
      apply would have deleted from it), never the site the operator meant
      to protect: the mistake is a pointing error, and pointing it at the
      other site would send the operator to inspect the wrong host.
    * **neither option present** — REFUSED as not a WordPress database at
      all.  A database with no ``siteurl``/``home`` is not the wrong
      site's, it is some other application's tables; the discovered
      options role proves a table shape, never that WordPress wrote it.
    * **exactly one present** — PROCEED with ONE warning.  Half the
      evidence is not a mismatch, and a refusal here would refuse a real
      site whose ``siteurl`` went stale in a migration while ``home``
      stayed current — the case the witness's own rule was widened for.

    With no ``--wp-url`` there is no second identity to compare against:
    one warning says the run could not check, and the plan proceeds (the
    operator named a database and no site, which is a legitimate use of
    this path — refusing it would break the documented CLI).
    """
    stated = _identity_values(conn, prefix)
    siteurl, home = stated.get("siteurl"), stated.get("home")
    if not siteurl and not home:
        raise WptError(
            "this database states neither siteurl nor home, so it is not a "
            "WordPress database (is --db-uri pointing at a WordPress "
            "database?); refusing before any statement runs"
        )
    if siteurl and not home:
        log.warning("this database states siteurl %r but no home, so the "
                    "wrong-database check is running on half its evidence; "
                    "a stale siteurl is not a mismatch on its own", siteurl)
    elif home and not siteurl:
        log.warning("this database states home %r but no siteurl, so the "
                    "wrong-database check is running on half its evidence; "
                    "a missing siteurl is not a mismatch on its own", home)
    target = site_identity(wp_url) if wp_url else None
    if target is None:
        log.warning("no --wp-url to compare this database against (it "
                    "states siteurl %r, home %r): the wrong-database check "
                    "could not run", siteurl, home)
        return
    identities = [identity for identity in
                  (site_identity(siteurl), site_identity(home))
                  if identity is not None]
    if target not in identities:
        raise WptError(
            f"the database --db-uri names is ANOTHER SITE's database: it "
            f"states siteurl {siteurl!r} and home {home!r}, while this run "
            f"targets {wp_url} — an apply here would delete that site's own "
            f"revisions, expired transients and orphaned meta rows; point "
            f"--db-uri at this site's database"
        )
    log.info("database identity matches this run: siteurl %r, home %r",
             siteurl, home)


class OfflineDb:
    """The bridge's DB surface, spoken directly to a database.

    :meth:`audit` returns the db_audit WIRE dict and :meth:`clean` the
    db_clean ``results`` map, so everything downstream of them is literally
    the same code the ftp path runs.
    """

    def __init__(self, conn: "DbConnection", prefix: str) -> None:
        self.conn = conn
        self.prefix = prefix

    def _sql(self, template: str) -> str:
        return template.format(p=self.prefix)

    # ------------------------------------------------------------- reading

    def audit(self) -> dict[str, Any]:
        """The clean-db-scoped subset of db_audit, in the bridge's wire shape.

        Deliberately NOT the whole db_audit payload: the other facts belong
        to audit checks, not to this action, and every statement here is
        one the bridge's db_audit already runs (so there is nothing to
        drift). ``tables`` comes from the shared introspection query.
        """
        payload = {
            "revisions": self._count(revisions_sql(count=True)),
            "expired_transients": self._count(transients_sql(count=True)),
            "orphan_meta": {
                kind: self._count(self._sql(orphan_sql(kind, head_index=1)))
                for kind in _ORPHAN_TAILS
            },
            "tables": schema_tables(self.conn),
        }
        return payload

    def _count(self, sql: str) -> int:
        rows = self.conn.query_rows(self._sql(sql))
        if not rows or not rows[0]:
            raise WptError(f"count query returned no value: {sql}")
        return int(rows[0][0] or 0)

    # ------------------------------------------------------------ mutating

    def clean(self, ops: list[str]) -> tuple[dict[str, int], dict[str, str]]:
        """Run the named ops; return ``(results, errors)`` like the bridge.

        The bridge's per-op try/catch, verbatim: every requested op runs,
        a failing one is collected, and the caller decides the verdict.
        Unknown op names are refused (the bridge raises InvalidArgument on
        them) — the op vocabulary stays the bridge's whitelist.
        """
        unknown = [op for op in ops if op not in _ROW_OP_TABLES
                   and op != "optimize_tables"]
        if unknown:
            raise WptError(f"unknown db_clean op(s): {', '.join(sorted(unknown))}")
        results: dict[str, int] = {}
        errors: dict[str, str] = {}
        for op in dict.fromkeys(ops):
            try:
                results[op] = self._run_op(op)
            except Exception as exc:  # the bridge's per-op catch-all
                errors[op] = redact_text(str(exc))
        return results, errors

    def _run_op(self, op: str) -> int:
        if op == "revisions":
            return self.conn.execute(self._sql(revisions_sql(count=False)))
        if op == "expired_transients":
            return self.conn.execute(self._sql(transients_sql(count=False)))
        if op == "orphan_meta":
            # the bridge SUMS the three deletes into one op result
            return sum(
                self.conn.execute(self._sql(orphan_sql(kind, head_index=0)))
                for kind in _ORPHAN_TAILS
            )
        if op == "optimize_tables":
            # the bridge counts the tables whose OPTIMIZE did not fail
            # (wpt_table_whitelist(): this database's base tables).
            done = 0
            for table in (row["name"] for row in schema_tables(self.conn)):
                self.conn.execute(optimize_sql(table))
                done += 1
            return done
        raise WptError(f"unknown db_clean op: {op}")

    # -------------------------------------------------------- verification

    def verify(self, plan: Plan) -> None:
        """Re-read the facts and un-mark every op whose trigger survived.

        The verify-after-change rule, measured on the same statements the
        plan was built from. A still-triggering op means the mutation did
        not land, so its item is NOT done and the run reports failure
        instead of a clean report over an unchanged database. An op whose
        fact is unmeasurable is treated the same way (fail-closed).
        ``optimize_tables`` is exempt: reclaiming free space is the
        server's own behaviour, and its "N tables optimized" count is the
        evidence it reports.
        """
        facts = self.audit()
        remaining = {
            "revisions": _opt_int(facts.get("revisions")),
            "expired_transients": _opt_int(facts.get("expired_transients")),
            "orphan_meta": _orphan_remaining(facts.get("orphan_meta")),
        }
        for item in plan.items:
            if not item.requires_apply or not item.done:
                continue
            if item.target == "optimize_tables":
                log.debug("verify: optimize_tables reports its own count")
                continue
            left = remaining.get(item.target)
            if left is None:
                # unmeasured is not clean: the apply did not prove itself
                log.error("verify: could not re-measure %s after the apply",
                          item.target)
                item.done = False
            elif left:
                log.error("verify: %s still reports %s after the apply",
                          item.target, left)
                item.done = False
            else:
                log.info("verify: %s is clean after the apply", item.target)


def _orphan_remaining(raw: Any) -> int | None:
    """Orphan rows still present across every kind, or None when unknown."""
    orphans = _orphan_meta_from_wire(raw)
    if not orphans or len(orphans) != len(_ORPHAN_TAILS):
        return None  # a kind could not be measured — unproven, not clean
    return sum(orphans.values())


def _emit(ctx: "Ctx", plan: Plan, *, failure: str | None = None) -> int:
    """Print the offline plan and write the shared md+JSON report pair.

    The `--db-uri` path is still `clean-db`: it must honour the universal
    ``--report`` contract exactly like the registry's ``_emit``.  Returns
    0 written/no path, 1 when the caller asked for a file that could not
    be written.

    ``failure`` is a run-level reason (the re-dump artifact could not be
    written).  The plan is still rendered — the applied state is real and
    an operator needs it — but the pair carries the shared not-complete
    block and ``run`` object, so no caller can read it as a clean success.
    """
    audit = _audit_stub(ctx)
    markdown = render_report(audit, plan, title="wpt clean-db")
    twin = json.loads(render_json(audit, plan))
    if failure is not None:
        block, payload = not_complete(failure, status="failed")
        markdown += block
        twin["run"] = payload
    write_stdout(markdown)
    return write_report(
        ctx, "clean-db", markdown,
        json.dumps(twin, ensure_ascii=False, sort_keys=True, indent=2))


def _fail_offline(ctx: "Ctx", reason: str, *,
                  status: str = "failed") -> int:
    """One shared failure artifact for every offline rc-1 path."""
    log.error("%s", redact_text(reason))
    try:
        write_failure_report(ctx, "clean-db", reason, status=status,
                             title="wpt clean-db")
    except (Exception, RunControl) as report_exc:  # noqa: BLE001
        # The primary reason stays the run's verdict; a second stop during
        # the report write is only a warning.
        log.warning("clean-db: could not write the failure report: %s",
                    redact_text(str(report_exc)))
    return 1


def run_offline(ctx: "Ctx") -> int:
    """``clean-db`` against ``--db-uri`` — the local-mode entry point.

    Same flow shape as the registry's (read-only plan, dry-run boundary,
    the canonical confirmation, apply, verification, report print) and the
    SAME plan/ops/results code — only the transport differs. It is a
    separate entry point rather than a second registration because the
    registry's local branch is the zip REHEARSAL (it materializes a new
    archive), and this run touches no file at all.

    ``--report`` is honoured on EVERY exit: the dry run and the apply write
    the printed plan plus its JSON twin through the shared writer, and a
    connect/apply/verify failure writes the shared failure pair.  Before
    this, the offline path accepted the flag and silently ignored it.

    Error contract: never raises. A refused or failed run is one logged
    error and rc 1; an op that failed keeps the run at rc 1 even when
    others succeeded (a partially-cleaned database is not a clean one), and
    so does a post-apply verification that did not prove the work.
    """
    conn = None
    deadline = Deadline.from_ctx(ctx)
    try:
        if deadline is not None:
            deadline.check("clean-db offline setup")
        uri = _ctx_uri(ctx)
        conn = connect(uri, password=ctx.db_password, deadline=deadline,
                       settings=ctx.settings.db)
        prefix = discover_prefix(conn)
        # BEFORE the audit, the plan and every statement: is this the
        # database the operator meant?  The offline path is the only place
        # that sees both identities (see site_identity_gate).
        site_identity_gate(conn, prefix, ctx.wp_url)
        db = OfflineDb(conn, prefix)
        log.info("offline db source: %s (prefix %r)", uri.redacted, db.prefix)
        if deadline is not None:
            deadline.check("clean-db offline audit")
        plan = CleanDbAction._plan_from_audit(db.audit(), ctx.settings)
        if deadline is not None:
            deadline.check("clean-db offline audit end")
        if not ctx.apply:
            rc = _emit(ctx, plan)
            log.info("clean-db: dry run — %d items, %s estimated (pass --apply "
                     "to execute)", len(plan.items), human_bytes(plan.est_bytes()))
            return rc
        if not confirm(ctx):
            return _fail_offline(ctx, "clean-db: aborted by the operator",
                                 status="refused")
        ops = planned_ops(plan)
        if not ops:
            rc = _emit(ctx, plan)
            log.info("clean-db: nothing to clean; no re-dump written%s",
                     f" (--re-dump {ctx.re_dump} ignored)" if ctx.re_dump else "")
            return rc
        # Say the quiet part out loud: the registry's fail-closed pre-action
        # snapshot needs the bridge's db_dump, so offline the rollback is
        # the dump this database was imported from.
        log.info("no pre-action snapshot in --db-uri mode (no bridge): the "
                 "rollback for this database is the dump it was imported from")
        if deadline is not None:
            deadline.check("clean-db offline apply")
        results, errors = db.clean(ops)
        for op, message in sorted(errors.items()):
            log.warning("db_clean op %s failed: %s", op, message)
        CleanDbAction._settle(plan, results, mark_all=not errors)
        if errors:
            return _fail_offline(
                ctx, "clean-db: %d of %d op(s) failed (%s); not verifying"
                     % (len(errors), len(ops), ", ".join(sorted(errors))))
        db.verify(plan)
        return _verdict(ctx, plan, db, uri)
    except RunControl as exc:
        return _fail_offline(ctx, f"clean-db stopped: {exc}")
    except (WptError, OSError) as exc:
        return _fail_offline(ctx, f"clean-db failed: {exc}")
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception as exc:
                log.warning("db connection close failed: %s", redact_text(str(exc)))


def _verdict(ctx: "Ctx", plan: Plan, db: OfflineDb, uri: DbUri) -> int:
    """The applied report, then the optional re-dump, then the exit code.

    The re-dump runs only over a VERIFIED apply: a dump of a half-cleaned
    database is an artifact an operator could publish by mistake, and the
    whole point of this path is "clean, then publish later".

    A failed re-dump is a FAILED RUN, not a warning beside a success pair:
    the artifact the operator asked for does not exist.  The plan's applied
    state is preserved in the same report (the database really was
    cleaned), while the shared not-complete block names the re-dump cause.
    """
    pending = [item for item in plan.items if item.requires_apply]
    complete = all(item.done for item in pending)
    dumped = None
    failure = None
    if complete and ctx.re_dump is not None:
        try:
            dumped = dump_database(db.conn, ctx.re_dump, source=uri.redacted,
                                   deadline=Deadline.from_ctx(ctx))
        except (WptError, OSError, UnicodeError, RunControl) as exc:
            # A re-dump deadline/stop (RunControl) and an unencodable
            # --re-dump name are FAILURES OF THIS RUN, not reasons to lose
            # the record of the work already applied: render the plan with
            # the not-complete block instead of letting the exception reach
            # run_offline's bare _fail_offline stub.
            cause = redact_text(str(exc))
            log.error("re-dump failed (%s): %s", ctx.re_dump, cause)
            complete = False
            failure = (f"the re-dump artifact {ctx.re_dump} was not "
                       f"written ({cause})")
    rc = _emit(ctx, plan, failure=failure)
    done = sum(1 for item in pending if item.done)
    log.info("clean-db: applied %d/%d item(s)%s", done, len(pending),
             f"; re-dump at {dumped.path}" if dumped is not None else "")
    if not complete:
        if failure is not None:
            log.error("clean-db: %s", failure)
        else:
            log.error("clean-db: %d/%d applicable item(s) were not applied",
                      done, len(pending))
    if rc:
        return 1
    return 0 if complete else 1


def _ctx_uri(ctx: "Ctx") -> DbUri:
    """The run's parsed --db-uri (the CLI validated its presence)."""
    if not getattr(ctx, "db_uri", None):
        raise WptError("clean-db over a database needs --db-uri")
    return parse_db_uri(ctx.db_uri)


# The registry stores the decorated OBJECT and calls .plan/.apply on it,
# so the registered action is the instance (same as clean_files).
register_action("clean-db", applies=("ftp",))(CleanDbAction())
