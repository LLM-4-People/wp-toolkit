"""cull-media action: delete OVERSIZED image derivatives of DEAD stem families.

Two-phase action over the shared registry flow (``wpt.actions.registry``).
Registered ``applies=("ftp",)``: the plan's safety proof is the site's full
reference set, and offline there is none (see ``Why ftp only``).

WHY: WordPress and a page-builder theme register a size set, and an
observed site carried many ``-WxH`` derivatives over many stems — a large
derivative set — most of which are named in ``srcset`` and MUST stay.
An honest bounded cull still exists, and it is narrow: a derivative whose
entire stem family is DEAD (no member referenced by a rendered page, none in
a ``srcset``, none attached in the database) and which is a DERIVATIVE at
all (its name carries a ``-WxH``/``-scaled`` suffix, never a bare original)
can only be a leftover of an intermediate export.  The measured potential on
that site was small, so the plan is honest about it: a dry run that names an
exact total, and an ``--apply`` behind the same fail-closed full reference
set trim-media uses.

Never resize, re-encode or re-upload anything here.  This action only
DELETES derivatives whose whole stem family is dead; the bare original of
even a dead family is ``trim-media``'s business (a family can be dead for
reasons wpt cannot see, and the original is the one file a re-import can
still regenerate a family from).

THE FULL REFERENCE SET (the fail-closed core)

A family is dead only when EVERY leg of the union says so — and an
unmeasurable leg is a REFUSAL, never a keep-by-default guess:

* ``rendered`` + ``srcset`` + generated-CSS ``url()`` refs — ONE live walk
  (``walk_site``; the walker's ``live_refs`` IS the union of those three
  legs, per ``wpt/audit/media.py``'s contract).  A PARTIAL or EMPTY walk
  measures nothing provable, so the plan REFUSES: an incomplete reference
  set turns every genuinely-used derivative into a false "dead".
* ``DB-referenced`` — ``wpt.media_refs.db_refs_from_bridge``: the ONE owner
  of the database half of the keep-set (attachment rows, attachment
  metadata size maps, and every uploads path named in post content, option
  values, termmeta — the observed fact that most of a site's media
  is database-referenced and the walk never sees it).  A bridge failure
  propagates (``BridgeError`` -> rc 1) and an unanswerable leg is never
  half a keep-set.

SHARED SEAM: ``trim_media`` builds the SAME union from the same two owners
and ``_MEDIA_TABLE_SUFFIXES`` below is imported from it, so a cull can never
be measured against a WEAKER set than a trim.

MODE PARITY (why the database leg is the bridge's and never a local
re-measurement).  The database half of the union has two implementations
by design — offline from the .sql dump, live from the bridge — and a
regression sweep measured the two disagreeing on an observed site: the
local dump kept a multi-size attachment family as database-referenced
while the live map kept NONE of them, so an
ftp apply would have deleted the family.  ``wpt.media_refs`` now owns ONE
rule (normalize, the extension family, the is-a-directory belt, PHP's
``unserialize`` semantics), mirrored in bridge.php and pinned by a
differential test that diffs the two implementations over one row fixture,
so the two halves of the union can no longer answer differently for the
same database.  What survives a rule fix is a SNAPSHOT difference — and a
SNAPSHOT difference is what this action's own cross-mode gate is for.

THE CROSS-MODE GATE (mandatory here, exactly as in trim_media).  This
action deletes through the SAME ``media_delete`` op in the SAME ftp mode,
and it used to do it with NO cross-check at all: a run whose keep-set came
from one live measurement deleted on that measurement alone, while
trim_media — which deletes strictly MORE per run (a bare original as well
as its derivatives) — refused without a second measurement of the same
database.  That is the weaker answer to the same question, and it is the
one that deletes.  So the gate is the ONE implementation in
``wpt.actions.dump_witness`` (imported, never re-implemented): the same
five conditions, the same memo, and LITERALLY the same refusal strings,
asked in the same three places — refused in the PLAN phase before the
registry takes the pre-action snapshot, where a missing ``--sql`` costs one
``stat`` instead of a full-site walk, an FTP download of the whole
deletion scope and a ``db_dump`` of three tables (a cost that evicted a
real snapshot from ``backup.keep_last`` on every attempt); the ADVICE form
in a dry run, so the operator learns from the run that recommends the
apply command that the apply will refuse; and the apply itself as the
backstop, including the per-file dispute (a planned file the dump says the
database references and the fresh live union does not).

Thresholds (``settings.cull_media``, both fail-loud on load): a floor on the
DECLARED dimension a cull may remove (``-scaled`` names carry none, so a
floor keeps them) and a self-bound on the plan's file count — a cull above
it refuses, naming both numbers, instead of emitting a huge destructive
plan.

APPLY — verify after every change

The reference set is RE-MEASURED before anything is deleted (SPEC: "mutating
actions end with a verification pass and refuse to report success without
it").  A planned path whose family is alive again, or that the new set
references, is RECLASSIFIED as a skipped item with the reason in its detail
and never sent to the bridge — the run deletes what is still provably dead
and says exactly what it left.  Then one ``media_map`` (attachment ids) plus
one ``media_delete``, and the server's ``unlink_failures`` answer is
authoritative: a file the server could not remove fails the apply (rc 1)
instead of being reported as deleted.

Why ftp only: offline (local) there is no rendered walk and no database —
a plan built there could not tell a dead family from a live one, and
``wpt serve``/``wpt verify`` already cover the rehearsal case for media.
The registry's mode gate is the honest declaration of that; the plan
re-checks the stack anyway so a direct misuse fails inside the error
contract.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..audit.data import _opt_int, _tables_from_wire
# The reference-set union seam is SHARED with trim_media: the same two legs
# (live walk + the database owner), the same failure semantics, so a cull
# can never be measured against a weaker set than a trim.
from ..actions.trim_media import _MEDIA_TABLE_SUFFIXES
from ..audit.media import _UPLOADS_PREFIX, _dir_of, _file_stem, is_media
from ..deadline import Deadline
from ..log import get_logger
from ..media_refs import attachment_ids_for_files, db_refs_from_bridge
from ..report import Plan, human_bytes
from ..types import Entry, PlanItem, SourceError
# Imported INTO this module's namespace and called as a bare global so
# tests patch wpt.actions.cull_media.walk_site (the trim-media seam).
from ..walk import walk_site
# THE CROSS-MODE GATE, the one trim_media uses (see the module's own note
# on why a second answer to the same question is always the weaker one).
from .dump_witness import (
    LiveSchema,
    WitnessGate,
    dispute_refusal,
    live_schema_from_audit,
    witness_refusal,
)
from .registry import register_action

if TYPE_CHECKING:
    from ..cli import Ctx

__all__ = ["CullMediaAction"]

log = get_logger("actions.cull_media")

#: Plan category of a culled derivative.  Distinct from trim-media's
#: ``media.unreferenced``: this action removes an OVERSIZED derivative of a
#: family nothing references, never a bare original.
_CATEGORY = "media.oversized"

#: A trailing ``-WxH`` with ASCII digits only — the same character class
#: ``wpt/audit/media.py`` mirrors from bridge.php's ``wpt_file_stem`` (PCRE's
#: ``\d`` is ASCII-only without modifiers; Python's would not be).
_DERIVATIVE = re.compile(r"^(?P<stem>.+?)-(?P<w>[0-9]+)x(?P<h>[0-9]+)$")

#: A ``-scaled`` derivative: WordPress's big-image rewrite of the ORIGINAL.
#: It carries no dimensions, so it is measurable only under a 0 floor.
_SCALED_SUFFIX = "-scaled"


@dataclass
class _Family:
    """One stem family: its (directory, stripped stem) key, every media
    member, and the derived facts the rules read."""

    key: tuple[str, str]
    members: list[Entry] = field(default_factory=list)


def _is_derivative(rel: str) -> bool:
    """True when a member's NAME carries a generated-size suffix (so it is
    a derivative, never a bare original)."""
    stem = rel.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    return bool(_DERIVATIVE.match(stem)) or stem.endswith(_SCALED_SUFFIX)


def _declared_px(rel: str) -> int | None:
    """The largest DECLARED dimension of a derivative, or None when the
    name carries none (``-scaled``).  WordPress only ever emits a size the
    theme registered, so a derivative's own name is the only evidence wpt
    has — and no evidence means no measurement."""
    stem = rel.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    match = _DERIVATIVE.match(stem)
    if not match:
        return None
    return max(int(match["w"]), int(match["h"]))


def _families(entries: list[Entry], extensions: list[str]
              ) -> dict[tuple[str, str], _Family]:
    """``(directory, stripped stem) -> family`` over the uploads MEDIA
    files — the ``wpt/audit/media.py`` stem semantics, unchanged (the L5
    mirror of bridge.php's ``wpt_file_stem``), so a family here is exactly
    the family trim-media's keep-set reasons about."""
    families: dict[tuple[str, str], _Family] = {}
    for entry in entries:
        if entry.is_dir or not entry.path.startswith(_UPLOADS_PREFIX):
            continue
        rel = entry.path[len(_UPLOADS_PREFIX):]
        if not is_media(rel, extensions):
            continue
        key = (_dir_of(rel), _file_stem(rel))
        families.setdefault(key, _Family(key)).members.append(entry)
    return families


def _alive_keys(refs: set[str]) -> set[tuple[str, str]]:
    """The family keys the live reference set keeps.  Keyed on the
    (directory, stem) of every ref, so a reference to ANY member — original,
    variant or a variant-only reference — keeps the whole family, exactly
    the symmetric L5 rule ``unreferenced_files`` applies per file."""
    return {(_dir_of(ref), _file_stem(ref)) for ref in refs}


class CullMediaAction:
    """The plan/apply pair; ``stack`` is the registry-built source trio.

    ONE piece of run-scoped state: ``_witness``, this run's cross-mode gate
    (:class:`~wpt.actions.dump_witness.WitnessGate`, the same instance type
    trim_media holds).  The registry always runs ``plan`` before ``apply`` on
    the registered object, and one run has one settings and one ``--sql``,
    so the plan's measurement and the apply's backstop are the same one.
    """

    def __init__(self) -> None:
        self._witness = WitnessGate()

    def plan(self, ctx: "Ctx", stack: tuple) -> Plan:
        source, session, bridge = stack
        if source is None or bridge is None or session is None:
            # Unreachable through the registry (ftp-only applicability);
            # guarded so a direct misuse fails inside the error contract.
            raise SourceError(
                "cull-media requires the live walk and the bridge (ftp mode only)"
            )
        cull = ctx.settings.cull_media
        extensions = ctx.settings.media.extensions

        # 0. THE PRE-SNAPSHOT GATE, and the cheapest chokepoint that can see
        #    it: a destructive cull needs a cross-checkable dump, and this
        #    plan phase runs BEFORE the registry takes the pre-action
        #    snapshot, so the refusal for the commonest way to have no
        #    witness (--sql is optional in ftp mode) costs one ``stat``
        #    instead of a full-site walk, an FTP download of the whole
        #    deletion scope and a db_dump of three tables.  Nothing
        #    destructive can have happened yet.
        if ctx.apply:
            absence = self._witness.absence(ctx.sql)
            if absence is not None:
                raise SourceError(
                    f"cull-media cannot cross-check a destructive apply: "
                    f"{absence}; nothing was deleted and no snapshot was "
                    f"taken — pass --sql and re-run"
                )

        # LEG 1 — rendered / srcset / CSS url(): one live walk, fail-closed.
        result = walk_site(
            session, ctx.wp_url, ctx.settings.walk,
            ctx.settings.http.timeout_s,
            deadline=Deadline.from_ctx(ctx),
        )
        if result.partial or not result.live_refs:
            raise SourceError(
                "the live walk did not produce a complete reference set "
                f"({len(result.live_refs)} reference(s)"
                f"{', PARTIAL' if result.partial else ''}) — refusing to "
                "cull: an incomplete set would call every used derivative "
                "dead"
            )
        # LEG 2 — the database half, from its one owner (a failing bridge
        # call propagates: half a keep-set is a deletion bug).
        db_refs = db_refs_from_bridge(
            bridge, ctx.settings.media.extensions)
        keep = set(result.live_refs) | db_refs
        alive = _alive_keys(keep)

        families = _families(list(source.walk()), extensions)
        dead = [fam for key, fam in sorted(families.items()) if key not in alive]
        if not dead:
            log.info("plan: every stem family is referenced — nothing to cull")
            return Plan(items=[], backup_tables=[])

        # Candidates: the DERIVATIVES of a dead family that clear the floor.
        # A bare original is never a candidate (trim-media owns it).
        candidates: list[tuple[str, Entry]] = []
        unmeasurable = 0
        for fam in dead:
            for entry in fam.members:
                rel = entry.path[len(_UPLOADS_PREFIX):]
                if not _is_derivative(rel):
                    continue
                declared = _declared_px(rel)
                if cull.min_oversize_px:
                    if declared is None or declared < cull.min_oversize_px:
                        unmeasurable += 1
                        continue
                candidates.append((rel, entry))
        if unmeasurable:
            log.info(
                "plan: %d derivative(s) below the %dpx floor (or with no "
                "declared size) are kept", unmeasurable, cull.min_oversize_px,
            )
        if not candidates:
            log.info("plan: no oversized derivative of a dead stem family")
            return Plan(items=[], backup_tables=[])

        # LEG 3 — the attachment rows themselves, over ONE media_map: a
        # candidate that maps to a positive attachment id IS attached (a
        # re-import can regenerate it) and is kept whatever the union said;
        # an answer without a usable refs OBJECT is unmeasurable and
        # REFUSES the plan.  The same map supplies the ids media_delete needs.
        attached = self._attached(bridge, [rel for rel, _ in candidates])
        kept_for_db = [
            entry for rel, entry in candidates
            if self._attachment_id(attached, rel) is not None
        ]
        if kept_for_db:
            log.info(
                "plan: %d candidate(s) are attached media rows and are kept: "
                "%s", len(kept_for_db),
                ", ".join(sorted(e.path for e in kept_for_db)),
            )
        candidates = [
            (rel, entry) for rel, entry in candidates
            if self._attachment_id(attached, rel) is None
        ]
        if not candidates:
            log.info("plan: every candidate is an attached media row")
            return Plan(items=[], backup_tables=[])

        # The self-bound: a cull above the configured file count refuses
        # rather than emitting a huge destructive plan.
        if cull.max_plan_files and len(candidates) > cull.max_plan_files:
            raise SourceError(
                f"the cull would remove {len(candidates)} file(s), above "
                f"cull_media.max_plan_files ({cull.max_plan_files}) — raise "
                f"the bound or narrow cull_media.min_oversize_px; nothing "
                f"was planned"
            )

        items = [
            PlanItem(
                category=_CATEGORY,
                target=entry.path,
                detail=(f"{rel} ({human_bytes(entry.size)}) — oversized "
                        f"derivative of a dead stem family"),
                bytes_est=entry.size,
            )
            for rel, entry in candidates
        ]
        # backup_tables: media_delete commits the mapped attachments' posts
        # + postmeta + term_relationships rows, so the pre-action snapshot
        # must capture those (trim-media's derivation, its fail-closed rule).
        # ONE db_audit answers both this and the witness' currency check —
        # the table NAMES for the backup scope, the table SET and the row
        # COUNTS for "is this dump at least as current as the site".
        live = self._live_schema(bridge)
        backup = self._backup_tables(live)

        # THE WITNESS, asked in the PLAN phase and refused in the PLAN phase
        # for an apply run (the same measurement the apply would make,
        # memoized, so the apply pays nothing for it) — but taken while the
        # pre-action snapshot does not exist yet.  A dry run cannot refuse
        # (it must stay informative), so it gets the ADVICE form: the
        # operator learns from the dry run — the run that RECOMMENDS the
        # apply command — that the apply will not proceed.
        planned = [item.target[len(_UPLOADS_PREFIX):] for item in items
                   if item.requires_apply]
        verdict = self._witness.witness(ctx, db_refs, live,
                                        deadline=Deadline.from_ctx(ctx))
        if verdict.problem is not None:
            if ctx.apply:
                raise witness_refusal("cull-media", planned, verdict.problem)
            listed = ", ".join(planned[:5]) + (" …" if len(planned) > 5 else "")
            items.insert(0, PlanItem(
                category="media.info",
                target="cross-mode check",
                detail=f"the --sql cross-check cannot corroborate this "
                       f"deletion — {verdict.problem}; --apply will refuse "
                       f"before touching {len(planned)} file(s) ({listed})",
                requires_apply=False,
            ))
        plan = Plan(items=items, backup_tables=backup)
        log.info(
            "plan: %d derivative(s) of %d dead stem family/families, %s "
            "estimated (dry run — pass --apply to cull)",
            len(items), len(dead), human_bytes(plan.est_bytes()),
        )
        return plan

    def apply(self, ctx: "Ctx", stack: tuple, plan: Plan) -> Plan:
        source, session, bridge = stack
        if bridge is None or session is None:
            raise SourceError("cull-media requires the bridge (ftp mode only)")
        planned = [item for item in plan.items if item.requires_apply]
        if not planned:
            return plan  # nothing planned — no bridge roundtrip, no walk

        # VERIFY BEFORE THE CHANGE: re-measure the full reference set (both
        # legs, same owners).  A path that is referenced now, or whose
        # family is alive now, is reclassified as skipped and never sent —
        # the run deletes what is still provably dead and reports exactly
        # what it left.
        result = walk_site(
            session, ctx.wp_url, ctx.settings.walk,
            ctx.settings.http.timeout_s,
            deadline=Deadline.from_ctx(ctx),
        )
        if result.partial or not result.live_refs:
            raise SourceError(
                "the verification walk did not produce a complete reference "
                "set — refusing to cull (nothing was deleted)"
            )
        db_refs = db_refs_from_bridge(bridge, ctx.settings.media.extensions)
        keep = set(result.live_refs) | db_refs
        alive = _alive_keys(keep)
        refs = set(result.live_refs)
        for item in planned:
            rel = item.target[len(_UPLOADS_PREFIX):] \
                if item.target.startswith(_UPLOADS_PREFIX) else item.target
            if rel in refs or (_dir_of(rel), _file_stem(rel)) in alive:
                log.warning(
                    "%s is referenced again — NOT culled (kept for this run)",
                    item.target,
                )
                item.detail += " — SKIPPED: referenced by the verification walk"
                item.requires_apply = False
                item.done = False
        planned = [item for item in planned if item.requires_apply]
        if not planned:
            return plan

        paths = [
            item.target[len(_UPLOADS_PREFIX):]
            for item in planned
        ]
        # THE BACKSTOP: the same witness, asked again against a FRESH live
        # schema (the apply re-measures everything it relies on — that is
        # what separates a verification from a replay).  Refused before the
        # media_map/media_delete pair, so a run that reached the apply
        # without the plan having asked still cannot delete through an
        # unusable witness.
        verdict = self._witness.witness(
            ctx, db_refs, self._live_schema(bridge),
            deadline=Deadline.from_ctx(ctx),
        )
        if verdict.problem is not None:
            raise witness_refusal("cull-media", paths, verdict.problem)
        dumped = verdict.refs or set()
        disputed = sorted(path for path in paths if path in dumped)
        if disputed:
            raise dispute_refusal("cull-media", disputed, ctx.sql)

        attached = self._attached(bridge, paths)
        # The same ownership rule trim-media uses: an id is accepted only
        # when its resolved attachment file is one of the deleted files.
        ids = attachment_ids_for_files(attached, paths)
        payload = bridge.call("media_delete", ids=sorted(ids), files=paths)
        # media_delete commits the DB rows and THEN unlinks the files,
        # swallowing per-file unlink errors: the server-side
        # ``unlink_failures`` answer is the authoritative verification
        # signal (``Source.exists`` is not — FtpSource.exists maps a
        # transient lookup error to False, which would read as "deleted").
        failures = payload.get("unlink_failures")
        if not isinstance(failures, list):
            failures = []
        failed = {
            p[len(_UPLOADS_PREFIX):] if p.startswith(_UPLOADS_PREFIX) else p
            for p in failures if isinstance(p, str)
        }
        for item in planned:
            rel = item.target[len(_UPLOADS_PREFIX):] \
                if item.target.startswith(_UPLOADS_PREFIX) else item.target
            if rel not in failed:
                item.done = True
        if failed:
            raise SourceError(
                f"cull-media: the server could not remove {len(failed)} "
                f"file(s) — the apply is reported as failed; restore from the "
                f"pre-action backup if needed"
            )
        log.info(
            "apply: %d derivative(s) deleted, %d attachment post(s), %d meta "
            "row(s), %d term relationship(s), %d already missing",
            _opt_int(payload.get("deleted_files")) or 0,
            _opt_int(payload.get("deleted_posts")) or 0,
            _opt_int(payload.get("deleted_meta")) or 0,
            _opt_int(payload.get("deleted_termrels")) or 0,
            _opt_int(payload.get("skipped_missing")) or 0,
        )
        return plan

    # ------------------------------------------------------------- internals

    def _attached(self, bridge, rels: list[str]) -> dict:
        """One ``media_map`` over every candidate; its ``refs`` map
        (uploads-relative path -> ``{id: ...}``).  An answer without a
        ``refs`` OBJECT is unmeasurable, and an unmeasurable database leg
        REFUSES the plan: a cull measured without the attachment rows is
        the false-positive this action must never ship."""
        mapped = bridge.call("media_map", refs=rels)
        refs_map = mapped.get("refs")
        if not isinstance(refs_map, dict):
            raise SourceError(
                "media_map answered without a usable refs map — the "
                "database leg of the reference set is unmeasurable, so no "
                "cull was planned"
            )
        return refs_map

    @staticmethod
    def _attachment_id(attached: dict, rel: str) -> int | None:
        """The positive attachment id a ref maps to, or None.  ``id: null``
        (or a non-positive one) is "never attached" — the answer trim-media
        reads with the same ``_opt_int`` shape."""
        ref = attached.get(rel)
        if not isinstance(ref, dict):
            return None
        attachment_id = _opt_int(ref.get("id"))
        return attachment_id if attachment_id is not None and attachment_id > 0 \
            else None

    def _live_schema(self, bridge) -> LiveSchema:
        """The live schema ONE ``db_audit`` reported: the table set and row
        counts the cross-mode witness measures this run's dump against, and
        the table names the pre-action backup scope is derived from."""
        return live_schema_from_audit(
            _tables_from_wire(bridge.call("db_audit").get("tables")))

    def _backup_tables(self, live) -> list[str]:
        """The DB side of the deletion's snapshot scope, derived like
        clean-db / trim-media from the run's ONE ``db_audit``: every audited
        table whose name ends with posts / postmeta / term_relationships.
        Fail-closed — a suffix the audit cannot locate means the deletion
        would run unbacked, so the plan refuses."""
        found: set[str] = set()
        missing: list[str] = []
        for suffix in _MEDIA_TABLE_SUFFIXES:
            matches = sorted(
                name for name in live.rows if name.endswith(suffix))
            found.update(matches)
            if not matches:
                missing.append(suffix)
        if missing:
            raise SourceError(
                "db_audit lists no table to back up the deletion (needs a "
                "table ending with "
                + ", ".join(repr(s) for s in missing)
                + "); refusing an unbacked mutation"
            )
        return sorted(found)


# The registry stores the decorated OBJECT and calls .plan/.apply on it,
# so the registered action is the instance (same as clean_files/trim_media).
register_action("cull-media", applies=("ftp",))(CullMediaAction())
