"""trim-media action (W7f): delete media referenced by neither the live
site nor the database.

Two-phase action over the shared registry flow (``wpt.actions.registry`` —
the registry owns dry-run, confirmation, the fail-closed pre-action backup
and the mode-applicability refusal; this module is pure domain logic).
Registered ``applies=("ftp", "local")``: the ftp run is the real one
(bridge + live walk), and the local run is the DEGRADED dry run (a zip
cannot render and no bridge exists, so the measurement is the database
side alone — informative, never applied).

THE KEEP-SET IS A UNION — the live-proven defect this rewrite fixes:
a WordPress page renders only a FRACTION of its attachment images.  On an
observed site, a walk-only keep-set covered most of the media files and
bytes only through database references the walk never sees (featured images
in menus/widgets/theme options, srcset candidates, attachment pages,
gallery templates, PDFs linked from post content).  A compliant apply
would have DELETED them and broken images across the site; the defensible
remainder was small.  Every deletion
decision here is therefore measured against
``live walk references`` ∪ ``database references``.

``plan`` (read-only):

1. THE REFERENCE SET, in two parts (this is the whole change):
   a. Rendered references — ONE live walk of the site
      (``walk_site(session, ctx.wp_url, ctx.settings.walk,
      ctx.settings.http.timeout_s)``; the W7i wiring recipe: the stack's
      own prepared session, the public site URL, the walk settings, the
      http timeout).  ``walk_site`` never raises; its ``live_refs``
      (uploads-relative POSIX paths) is one half of the keep-set.  A walk
      that measured ZERO references is a REAL result — the plan then
      contains every uploads file the database does not reference — and
      gets exactly ONE warning (the "everything is unreferenced" plan is
      the dangerous one).  The walker is imported INTO this module's
      namespace and called as a bare global so tests can patch
      ``wpt.actions.trim_media.walk_site`` (the pinned seam — no live
      HTTP server in the action tests; a transport failure escaping the
      seam is a ``requests.RequestException`` == ``OSError`` subclass, so
      the registry still answers rc 1 and the plan NEVER guesses a
      keep-set).  ftp mode only: local mode has no site to render, so
      this half is None (DEGRADED, labelled below).
   b. Database references — ``wpt.media_refs``, the owner of the database
      side: ONE read-only ``media_map`` call in ``mode=db`` over the
      bridge (ftp) or a streaming pass over the .sql dump (local, no
      ad-hoc SQL parsing).  A bridge call that fails is ONE warning plus
      None (UNKNOWN) — the dry run stays informative; the apply refuses.
2. Per-file enumeration from the shared keep-set owner:
   ``wpt.audit.media.unreferenced_files`` (one L5 implementation shared
   with the ``media.unreferenced`` check: refs ∪ same-directory stem
   siblings, symmetric, applied to the UNION, each candidate carrying the
   evidence class it rests on).  The source is walked ONCE and the entry
   list is reused: the enumeration reads it, and in local mode the
   enumerated uploads DIRECTORIES are the offline is-a-directory witness
   for the database keep-gate (the bridge asks ``is_dir()`` live, so the
   offline half must ask the walk, or the two modes gate differently).
3. ONE ``PlanItem`` per unreferenced FILE: category
   ``media.unreferenced``, ``target`` = the WEBROOT-relative path
   ("wp-content/uploads/2023/10/x.jpg") so the registry's pre-action
   backup captures it as a FILE (``_backup_file_scope`` — restoring the
   captured files reverses the file side of the deletion),
   ``bytes_est`` = the on-disk size, detail = the uploads-relative
   display path + a human-readable size + the EVIDENCE CLASS, so the
   operator sees WHY the file is a candidate.  Items are in the shared
   function's path order == target order (sorted).  Nothing
   unreferenced -> an EMPTY plan with NO bridge call at all.
3b. When the set is DEGRADED (either half missing) the plan leads with
   one ADVICE item (``requires_apply=False``, never in the snapshot scope,
   never applied) that names the missing side in the operator's words and
   the command that produces the full set.  A dry run therefore always
   works and always says what it could not see.
4. ``plan.backup_tables`` — the DB side of the deletion.
   ``media_delete`` removes the mapped attachments' wp_posts rows +
   wp_postmeta + wp_term_relationships, so the snapshot must capture
   THOSE tables for the deletion to be reversible: derived like
   clean-db from ONE ``bridge.call("db_audit")`` — every audited table
   whose name ends with ``posts`` / ``postmeta`` / ``term_relationships``
   (plain endswith, fail-safe in the safe direction: a stray
   ``wp_myoptions``-alike is merely snapshotted too, never a miss).
   Fail-closed: a suffix the audit cannot locate means the deletion
   would run unbacked -> :class:`SourceError`, never a plan.  Local mode
   has no bridge and no DB mutation path at all, so the scope is
   deliberately EMPTY there (its apply refuses before any mutation).

``apply`` — the fail-closed gate FIRST, then the re-verification, then
the deletion:

0. THE GATE.  An apply runs only on the FULL union: no bridge or no
   session (local mode) means no live walk, and a database map that could
   not be measured means the database half is missing.  Either way the
   apply REFUSES with one actionable line naming the command that
   produces the full set — a degraded dry run is informative, a degraded
   DESTRUCTION is refused.  This is the fail-closed discipline the tool
   is built on: the database-only defect was measured, and no half-measured
   reference set may delete anything.
1. RE-VERIFICATION over the same UNION, not a re-crawl alone: the live
   walk runs again (page-level references — a page published since the
   plan can reference a new file) AND the database map is fetched again
   (the walk never sees attachment metadata or option-held media, which
   is the bulk of the real reference set), and every planned path is
   re-tested against their union with
   ``wpt.audit.media.protected_by`` (the keep rule restricted to the
   planned paths — no second walk of a 9,000-file uploads tree over
   FTP).  A planned file the fresh union protects means the site changed
   under the plan: SourceError, NOTHING deleted.
1b. THE CROSS-MODE GATE — MANDATORY, and fail-closed.  The database
   half has TWO measurements of the same database — the .sql dump
   (``--sql``, offline) and the bridge (``media_map`` mode=db, live) —
   and they are the SAME rule now (one normalize + gate +
   PHP-unserialize implementation in ``wpt.media_refs``, mirrored in
   bridge.php, pinned by a differential test running the real
   ``wpt_media_db_map`` over the same rows), but they read different
   SNAPSHOTS.  The one disagreement a rule fix cannot remove is the
   measured live shape: the live tables no longer carry a row the dump
   still has, so one multi-size attachment family — the original plus its
   registered sizes — reads as referenced offline and unreferenced
   online, and the live apply would have deleted the whole family.  The
   tool cannot adjudicate which snapshot is right, so it refuses.

   So a destructive ftp apply MUST carry a second measurement of the same
   database: without a usable ``--sql`` the apply refuses in one line
   naming the flag, BEFORE any deletion call.  The gate used to be opt-in
   (``if ctx.sql is not None``), which left the very defect class it was
   built for deletable by the recommended live command — ``--sql`` is
   optional in ftp mode, so ``wpt --source ftp://… trim-media --apply``,
   the very workflow the dry run prints, never consulted a dump at all.

   A WITNESS, not merely a file: the gate's question is per planned path
   ("does the dump reference it?"), so a dump that references NOTHING
   answers "no" to all of them and agrees with the live union about the
   whole plan.  That is what a cut-off FTP transfer, another site's
   export and a schema-only dump each measured, and each of them would
   have deleted the family this gate exists to protect.

   The five conditions a dump must satisfy to corroborate anything live in
   ``wpt.actions.dump_witness`` — the ONE owner, imported here and by
   ``cull_media``, so both actions produce LITERALLY the same refusal: the
   ``-- Dump completed on`` trailer (a whole file, which is necessary and
   NOT sufficient), the dump's own ``siteurl``/``home`` naming THIS site, a
   measured reference set that is not empty where the live map's is, the
   dump's declared TABLE SET covering every table the live schema has
   (refused BY NAME), and its per-table ROW COUNTS not materially behind
   the live ones for the tables the decision is read from.  The last two
   are what a trailer cannot see: a dump cut inside the
   ``INSERT INTO wp_postmeta`` rows with the trailer APPENDED (a resumed
   transfer, a concatenation, a hand edit) satisfies the first three and
   authorizes exactly the deletion this gate exists to prevent, because
   the rows it lost are the ones that named the files.  Each refusal names
   the planned files it could not vouch for; the two phases of a run ask
   ONE witness, memoized.

   The refusal costs NOTHING: the plan phase asks the witness before the
   registry takes the pre-action snapshot, so the commonest way to have no
   witness (``--sql`` not passed, which the CLI treats as optional in ftp
   mode) is refused after one ``stat`` instead of after a full-site walk,
   an FTP download of the entire deletion scope and a ``db_dump`` of three
   tables — a cost that evicted a real snapshot from ``backup.keep_last``
   on every attempt.

   A dump that cannot be MEASURED (``db_refs_from_dump`` returning None:
   no usable options table) is the same fact as no dump — "no
   cross-check", never "no reference".  The dump is measured ONCE per run,
   with the same extensions and the same walked uploads directories the
   plan measured with (the two halves of one gate must measure one set),
   and the run's wall-time deadline is honoured while it is read, so the
   scan ends the run itself instead of answering with a partial keep-set.
2. Collect the planned uploads-RELATIVE paths (strip the
   ``wp-content/uploads/`` prefix from every ``requires_apply`` target)
   in plan order; an empty plan applies without any bridge roundtrip.
3. Resolve attachment IDs: ONE ``bridge.call("media_map", refs=paths)``.
   Stem matching may map several files to one id and leave
   never-attached files unmapped (``id: null``); ``ids`` is the sorted
   deduped set of mapped ids and may be EMPTY.
4. ONE ``bridge.call("media_delete", ids=ids, files=paths)``.
   Empty ``ids`` are fine on the wire: bridge.php's media_delete reads
   them with ``wpt_param_int_list(..., required=false)``, an empty list
   is accepted, and the ``if ($ids)`` guard then skips the DB
   transaction while the files are still unlinked — so never-attached
   files delete too (verified against the handler; no omission needed).
   SPEC "verify after every change": media_delete commits the DB rows and
   then unlinks files while SWALLOWING per-file unlink errors, so the apply
   re-checks every planned path on disk via the source and marks an item
   done only when the file is actually gone.  Any file the server refused to
   remove fails the apply (rc 1) instead of being reported as a success, and
   ONE info summary logs the reported counts (deleted files / posts / meta
   rows / term relationships / already-missing).  A :class:`BridgeError`
   propagates untouched — the registry reports it (rc 1, after the
   backup), items stay ``done=False``, and the pre-action backup exists
   for restore.

Idempotency: the deletions are what the next measurement sees — a second
plan over the trimmed tree is empty, so a second apply plans nothing and
makes no bridge call at all (the registry's ``if not paths`` early exit).

Media path scope: the bridge's ``media_delete`` accepts any path that
resolves INSIDE the uploads basedir (it no longer requires a ``YYYY/``
shape — that rule was a layout assumption, and a real migration's trim
plan carried many unreferenced uploads under plugin paths like
``bb-plugin/cache/…``, every one of which the op refused, so the whole
apply failed closed with zero deletions). A planned file OUTSIDE uploads
would be sent as an uploads-relative path and address a different file, so
the plan only ever carries uploads-relative targets; anything the shared
enumeration ever returns from outside ``wp-content/uploads/`` is excluded
with one warning naming it (defense in depth — today's enumeration cannot
produce one).

Logging: ``get_logger("actions.trim_media")`` — one info plan summary
(files + bytes + the evidence class of the run), the one empty-refs
warning, the one degraded-mode warning, ONE info apply summary
(media_delete counts).  Never file lists or cell contents in logs: the
plan print carries the paths.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..audit.data import _opt_int, _tables_from_wire
from ..audit.media import (
    _UPLOADS_PREFIX,
    DEGRADED_NO_WALK,
    degraded_note,
    protected_by,
    unreferenced_files,
)
from ..deadline import Deadline, bounded_walk
from ..log import get_logger
from ..media_refs import (db_refs_from_bridge, db_refs_from_dump,
                          attachment_ids_for_files, uploads_dirs)
from ..report import Plan, human_bytes
from ..types import PlanItem, SourceError, WptError
# Imported INTO this module's namespace and called as a bare global so
# tests patch wpt.actions.trim_media.walk_site (the pinned walk seam).
from ..walk import walk_site
# The cross-mode gate is SHARED with cull_media (one owner, one wording):
# a second implementation of it is a second, weaker answer to the same
# question, which is how cull-media came to delete media with no witness
# at all.
from .dump_witness import (
    DumpWitness,
    LiveSchema,
    WitnessGate,
    dispute_refusal,
    live_schema_from_audit,
    witness_refusal,
)
from .registry import register_action

if TYPE_CHECKING:
    from ..cli import Ctx

__all__ = ["ReferenceSet", "TrimMediaAction"]

log = get_logger("actions.trim_media")

#: db_audit table-name suffixes media_delete mutates on the DB side (the
#: mapped attachments' posts + postmeta + term_relationships rows) — the
#: pre-action backup scope, derived like clean-db's per-op table map.
_MEDIA_TABLE_SUFFIXES = ("posts", "postmeta", "term_relationships")

#: The one actionable line every refusal ends with: the command that
#: produces the FULL reference set (rendered pages + database).  There is
#: no profile knob for this (SPEC: no new tunables for a safety gate) —
#: the fail-closed default IS the policy.
_FULL_SET_COMMAND = (
    "run it against the live site for the full set: `wpt --source "
    "ftp://HOST --webroot WEBROOT --wp-url https://SITE --user U "
    "--password-env WP_PASSWORD trim-media --apply`"
)


@dataclass(frozen=True)
class ReferenceSet:
    """The measured reference set of one run: rendered ∪ database.

    ``live_refs`` (rendered pages) and ``db_refs`` (the database, see
    :mod:`wpt.media_refs`) are each ``None`` when that side could not be
    MEASURED — the tool-wide unknown-vs-empty contract.  ``degraded`` is
    True whenever the set is not the full union, which is what the plan
    labels and the apply refuses on.
    """

    live_refs: set[str] | None
    db_refs: set[str] | None

    @property
    def union(self) -> set[str]:
        """Both sides merged — the keep-set input.  Empty only when both
        sides are unknown, in which case nothing is enumerated at all."""
        return set(self.live_refs or ()) | set(self.db_refs or ())

    @property
    def degraded(self) -> bool:
        return self.live_refs is None or self.db_refs is None

    @property
    def note(self) -> str:
        """The operator-facing degraded marker ("" for a full union)."""
        return degraded_note(self.live_refs, self.db_refs)


class TrimMediaAction:
    """The plan/apply pair; ``stack`` is the registry-built source trio.

    TWO pieces of run-scoped state, and BOTH belong to the shared witness
    (the registry always runs ``plan`` before ``apply`` on the registered
    instance, and one run has one settings and one dump):

    * ``_dirs`` — the walked uploads DIRECTORY set, the is-a-directory
      witness the dump half of the keep-gate needs.  The plan walks the
      source once; the apply deliberately does NOT (a second walk of a
      9,000-file uploads tree over FTP is not an acceptable price for a
      guard), so the plan's measurement is what the cross-mode gate
      compares with.  ``None`` (an apply without a plan) skips the belt,
      which can only over-protect.  Handed to the gate, which measures
      with it.
    * ``_witness`` — the run's ONE :class:`~wpt.actions.dump_witness.WitnessGate`:
      the dump's verdict, memoized under a key carrying the file's
      identity, the family and the directories, so the plan phase and the
      apply phase ask ONE witness of ONE dump.  The gate, its five
      conditions and every refusal wording live in
      :mod:`wpt.actions.dump_witness`, shared verbatim with ``cull_media``.
    """

    def __init__(self) -> None:
        self._dirs: set[str] | None = None
        self._witness = WitnessGate()

    # ------------------------------------------------------------------ dump

    def _dump_refs(self, ctx: "Ctx") -> set[str] | None:
        """The dump's database reference set for this run — measured ONCE.

        ``None`` = the dump could not be MEASURED (no usable options
        table).  That is UNKNOWN, and every consumer of this value treats
        it as "no cross-check available" — never as an empty keep-set: an
        empty set would read as "the database references nothing" and
        authorize exactly the deletions the cross-mode gate exists to
        stop.  The run's deadline is honoured while the dump is read, so a
        run out of budget ends itself (a ``DeadlineExceeded``, already a
        ``WptError``) rather than returning a truncated set.
        """
        if ctx.sql is None:
            return None
        with open(ctx.sql, "rb") as dump:
            return db_refs_from_dump(
                dump, ctx.settings.media.extensions, self._dirs,
                deadline=Deadline.from_ctx(ctx),
            )

    def _live_schema(self, bridge) -> LiveSchema:
        """The live schema this run's completeness is measured against.

        ONE ``db_audit`` per ask, shared with the pre-action backup scope
        the plan already derives from the same answer: the witness needs
        the live table set and row counts, and the backup needs the table
        NAMES, so a second call would buy nothing.
        """
        return live_schema_from_audit(
            _tables_from_wire(bridge.call("db_audit").get("tables")))

    def _witness_verdict(self, ctx: "Ctx", live_refs: set[str] | None,
                         live: LiveSchema) -> DumpWitness:
        """Ask the shared gate about this run's dump, against the live
        schema this phase has just read."""
        return self._witness.witness(
            ctx, live_refs, live, deadline=Deadline.from_ctx(ctx),
        )

    def _cross_mode_refusal(self, paths: list[str], reason: str) -> SourceError:
        """The ONE line every unusable witness ends with (shared wording)."""
        return witness_refusal("trim-media", paths, reason)

    # ------------------------------------------------------------ references

    def _reference_set(self, ctx: "Ctx", session, bridge,
                       entries: list | None = None) -> ReferenceSet:
        """Measure BOTH halves of the keep-set for this run.

        ftp (bridge + session): one live walk (rendered references) and
        one read-only ``media_map`` ``mode=db`` call (database
        references).  A database call that fails degrades to None with ONE
        warning — a dry run stays informative and the apply refuses.

        local (zip only, no bridge, no session): there is no site to
        render and no bridge to ask, so the database half (the .sql dump
        the CLI already requires) is the WHOLE measurement and the set is
        DEGRADED by construction.  A dump that yields no usable tables is
        UNKNOWN (None) — the plan then enumerates nothing, which is the
        same never-guess posture the missing walk has always had.

        ``entries`` is the walked source, and it is passed to the dump path
        for ONE reason: the is-a-directory half of the keep-gate.  The
        bridge asks the live filesystem (``is_dir()``); offline the walk
        IS the authority on what exists, so the enumerated uploads
        directories are handed over as data.  Without it the offline
        measurement would skip that test while the live one applied it —
        the mode-dependent keep-set this action's apply refuses on.
        """
        if bridge is None or session is None:
            if ctx.sql is None:
                raise SourceError(
                    "trim-media needs the database to measure the reference "
                    "set: local mode requires --sql (and the ftp/live path "
                    "for the full set)"
                )
            db_refs = self._dump_refs(ctx)
            if db_refs is None:
                log.warning(
                    "no usable database media map in the dump: the reference "
                    "set is unknown, so nothing is planned"
                )
            return ReferenceSet(live_refs=None, db_refs=db_refs)

        result = walk_site(
            session, ctx.wp_url, ctx.settings.walk, ctx.settings.http.timeout_s,
            deadline=Deadline.from_ctx(ctx),
        )
        if result.partial:
            # A page-budget/deadline/breaker-truncated walk did not SEE every
            # rendered reference.  Treating its partial set as a complete
            # keep-set made every file referenced only by the unseen pages a
            # deletion candidate (and the apply posted media_delete for them).
            # UNKNOWN, not empty: the shared ReferenceSet.degraded contract
            # makes the plan advice-only and the apply refuse.
            log.warning(
                "the live walk was PARTIAL (%d reference(s) before it "
                "stopped): the rendered reference set is UNMEASURED, so this "
                "plan is degraded and the apply will refuse",
                len(result.live_refs),
            )
            live_refs = None
        else:
            live_refs = set(result.live_refs)
            if not live_refs:
                log.warning(
                    "live walk found 0 references: every uploads file the "
                    "database does not reference is planned (check the site "
                    "renders before applying)"
                )
        try:
            # The run's OWN family, carried into the read: the enumeration
            # below files uploads media by exactly this list, so a gate
            # answering from a different one makes a reference invisible
            # and a database-referenced file deletable.  The bridge unions
            # it with its mirrored default, so the gate is never narrower
            # than the enumeration whatever the profile says.
            db_refs = db_refs_from_bridge(
                bridge, ctx.settings.media.extensions)
        except (WptError, OSError) as exc:
            # BridgeError is a WptError: the whole registry contract. The
            # message carries no secret (the client redacts payloads).
            log.warning(
                "database media map unavailable (%s): this plan measures the "
                "live walk only and CANNOT be applied", exc
            )
            db_refs = None
        return ReferenceSet(live_refs=live_refs, db_refs=db_refs)

    # ------------------------------------------------------------------ plan

    def plan(self, ctx: "Ctx", stack: tuple) -> Plan:
        source, session, bridge = stack
        # 0a. THE PRE-SNAPSHOT GATE, and the cheapest chokepoint that can
        #     see it.  A destructive ftp apply needs a cross-checkable
        #     dump, and this plan phase runs BEFORE the registry takes the
        #     pre-action snapshot: a refusal raised here costs one stat,
        #     where the same refusal raised inside the apply used to cost
        #     a full-site walk, an FTP download of the whole deletion
        #     scope and a db_dump of three tables, and then evicted a real
        #     snapshot from the keep-last ring on every attempt.  Nothing
        #     destructive can have happened yet — the apply has not been
        #     reached, and the backup that had to precede it does not
        #     exist.  Local mode is not this gate's business (its apply
        #     refuses on the degraded reference set instead).
        if ctx.apply and bridge is not None and session is not None:
            absence = self._witness.absence(ctx.sql)
            if absence is not None:
                raise SourceError(
                    f"trim-media cannot cross-check a destructive apply: "
                    f"{absence}; nothing was deleted and no snapshot was "
                    f"taken — pass --sql and re-run"
                )

        # 0. One walk of the source, ONCE: the enumeration's entries and
        #    (local mode) the is-a-directory half of the database
        #    keep-gate both read this list, so no tree is walked twice.
        #    The walk is bounded per entry: a crawling FTP tree must end
        #    the run at --deadline, not after the whole listing.
        entries = list(bounded_walk(
            source, Deadline.from_ctx(ctx), "trim-media plan"))
        # The is-a-directory witness every offline keep-gate reads, kept for
        # the apply: the cross-mode gate below measures the dump with the
        # SAME directories the plan measured it with, and the apply does not
        # re-walk a 9,000-file uploads tree over FTP to recover them.
        self._dirs = uploads_dirs(entries)
        self._witness.remember_dirs(self._dirs)

        # 1. The measured UNION reference set (never a guess: a walk
        #    returning zero refs is a REAL result — warned in the helper).
        refs = self._reference_set(ctx, session, bridge, entries)

        # 2. Per-file enumeration from the shared keep-set owner [L5] —
        #    MEDIA files only (the settings allowlist): Wordfence's
        #    uploads .htaccess and core index.php guards are invisible
        #    to a trim plan, never deletable through it [L14].
        unreferenced = unreferenced_files(
            entries, refs.live_refs, refs.db_refs,
            ctx.settings.media.extensions,
        )

        items: list[PlanItem] = []
        backup: list[str] = []
        live = LiveSchema({})
        if unreferenced:
            # 4. DB-side backup scope, derived like clean-db from one
            #    audit.  No bridge (local mode) = no DB mutation path, so
            #    the scope is deliberately EMPTY and the apply refuses.
            live = self._live_schema(bridge) if bridge is not None \
                else LiveSchema({})
            if bridge is not None:
                found: set[str] = set()
                missing: list[str] = []
                for suffix in _MEDIA_TABLE_SUFFIXES:
                    matches = sorted(
                        name for name in live.rows if name.endswith(suffix)
                    )
                    found.update(matches)
                    if not matches:
                        missing.append(suffix)
                if missing:
                    raise SourceError(
                        "db_audit lists no table to back up the deletion "
                        "(needs a table ending with "
                        + ", ".join(repr(s) for s in missing)
                        + "); refusing an unbacked mutation"
                    )
                backup = sorted(found)

            # 3. One item per unreferenced FILE; target order == path order.
            #    Defense in depth: the plan carries only paths the media
            #    layer can round-trip. The shared enumeration already
            #    restricts itself to wp-content/uploads/, so nothing is
            #    dropped today — but an item from outside uploads would be
            #    handed to media_delete as an UPLOADS-relative path, where
            #    it would address a different file (or none). The check
            #    costs one prefix test and keeps a future enumeration
            #    change from turning into a wrong deletion.
            items = [
                PlanItem(
                    category="media.unreferenced",
                    target=candidate.entry.path,
                    detail=f"{candidate.entry.path[len(_UPLOADS_PREFIX):]} "
                    f"({human_bytes(candidate.entry.size)}) — "
                    f"{candidate.evidence}",
                    bytes_est=candidate.entry.size,
                )
                for candidate in unreferenced
                if candidate.entry.path.startswith(_UPLOADS_PREFIX)
            ]
            outside = [
                candidate.entry.path for candidate in unreferenced
                if not candidate.entry.path.startswith(_UPLOADS_PREFIX)
            ]
            if outside:
                log.warning(
                    "excluding %d media file(s) outside %s: the deletion "
                    "path is uploads-relative and cannot round-trip them "
                    "(%s)",
                    len(outside), _UPLOADS_PREFIX, ", ".join(outside),
                )

        # 3b. A DEGRADED set leads with one ADVICE item: never applied, never
        #     snapshotted (requires_apply=False), it tells the operator what
        #     the measurement could not see and what to run instead.  The
        #     dry run always works; the apply below refuses.  It qualifies
        #     the candidates, so an EMPTY plan carries no advice.
        if refs.degraded and items:
            items.insert(0, PlanItem(
                category="media.info",
                target="reference set",
                detail=f"DEGRADED reference set — {refs.note}; this plan is "
                       f"informative only, --apply refuses; {_FULL_SET_COMMAND}",
                requires_apply=False,
            ))

        # 3c. THE WITNESS, asked in the PLAN phase and refused in the PLAN
        #     phase for an apply run — the same measurement the apply would
        #     make (memoized, so the apply pays nothing for it), but taken
        #     while the pre-action snapshot does not exist yet.  A dry run
        #     cannot refuse (it must stay informative), so it gets the
        #     ADVICE form: the operator learns from the dry run — the run
        #     that RECOMMENDS the apply command — that the apply will not
        #     proceed, instead of finding out after confirming it.
        if items and not refs.degraded and bridge is not None:
            witness = self._witness_verdict(ctx, refs.db_refs, live)
            if witness.problem is not None:
                planned = [
                    item.target[len(_UPLOADS_PREFIX):] for item in items
                    if item.requires_apply
                ]
                if ctx.apply and planned:
                    raise self._cross_mode_refusal(planned, witness.problem)
                listed = ", ".join(planned[:5]) \
                    + (" …" if len(planned) > 5 else "")
                items.insert(0, PlanItem(
                    category="media.info",
                    target="cross-mode check",
                    detail=f"the --sql cross-check cannot corroborate this "
                           f"deletion — {witness.problem}; --apply will "
                           f"refuse before touching {len(planned)} file(s) "
                           f"({listed})",
                    requires_apply=False,
                ))

        plan = Plan(items=items, backup_tables=backup)
        log.info(
            "plan: %d item(s), %s estimated (evidence: %s)",
            # the APPLICABLE count: an advice item is prose about the run,
            # not a file the run would touch, and the operator reading
            # "N item(s)" is reading a deletion count
            sum(1 for item in items if item.requires_apply),
            human_bytes(plan.est_bytes()),
            sorted({candidate.evidence for candidate in unreferenced})
            or ["nothing unreferenced"],
        )
        return plan

    # ----------------------------------------------------------------- apply

    def apply(self, ctx: "Ctx", stack: tuple, plan: Plan) -> Plan:
        _source, session, bridge = stack
        paths = [
            item.target[len(_UPLOADS_PREFIX):]
            for item in plan.items
            if item.requires_apply and item.target.startswith(_UPLOADS_PREFIX)
        ]
        if not paths:
            return plan  # nothing planned — no bridge roundtrip, no gate

        if bridge is None or session is None:
            # THE GATE: a local run has no live walk and no bridge, so its
            # reference set is the database half only (DEGRADED).  Nothing
            # is mutated — the refusal happens before any deletion call.
            raise SourceError(
                "trim-media refuses to apply on a degraded reference set — a "
                f"local run measures the database half only ({DEGRADED_NO_WALK}"
                f"); {_FULL_SET_COMMAND}"
            )

        # THE GATE, second shape: the ftp run must be able to measure BOTH
        # halves.  A database map that fails here fails the apply.
        refs = self._reference_set(ctx, session, bridge)
        if refs.degraded:
            raise SourceError(
                "trim-media refuses to apply on a degraded reference set "
                f"({refs.note}); {_FULL_SET_COMMAND}"
            )

        # RE-VERIFICATION over the same UNION (not a re-crawl alone): the
        # walk above re-measured the page-level references, this call
        # re-measures the database half, and every planned path is re-tested
        # against their union.  protected_by() applies the keep rule to the
        # planned paths directly, so no second walk of a 9,000-file uploads
        # tree over FTP is needed.
        protected = sorted(
            path for path in paths if protected_by(refs.union, path)
        )
        if protected:
            raise SourceError(
                f"trim-media: {len(protected)} planned file(s) are now "
                f"referenced (the site changed since the plan): "
                f"{', '.join(protected[:5])}"
                f"{' …' if len(protected) > 5 else ''}; nothing was deleted"
            )

        # THE CROSS-MODE GATE — MANDATORY.  The two measurements of the SAME
        # database must never disagree about a file this apply is about to
        # delete.  The offline and live halves now implement one rule and are
        # pinned to agree by a differential test, but they read DIFFERENT
        # snapshots — a dump is a point in time, the bridge reads the live
        # tables — so one real disagreement survives that: the live database
        # no longer carries a row the dump still has (a plugin cleaned the
        # meta, a restore overwrote the dump), and the family an attachment
        # owned reads as referenced offline and as unreferenced online.
        # Measured on an observed site: a multi-size attachment family in
        # exactly that state, where the live path would have deleted the
        # original plus every registered size.  The dump is therefore a
        # CORROBORATING witness, and a run that cannot produce one may not
        # delete: `--sql` is OPTIONAL in ftp mode, so an opt-in gate left the
        # recommended live command (`wpt --source ftp://… trim-media
        # --apply`, the one every dry run prints) able to delete exactly the
        # family this gate was built for.  No witness means the cross-check
        # cannot be made, and an unmade cross-check on a DESTRUCTION is a
        # refusal, not a silent pass.
        #
        # An UNMEASURABLE dump is the same fact as no dump: `None` is
        # UNKNOWN, never "the database references nothing" (that reading
        # would wave through every planned file), so it refuses with the
        # reason instead of skipping the question.
        #
        # A witness is a witness only if it satisfies the FIVE conditions
        # of wpt.actions.dump_witness (whole file, THIS site, a measured
        # set, every live table declared, and not behind the live rows of
        # the tables the decision is read from): a dump that measured
        # nothing (a cut-off transfer, a foreign site's export, a
        # schema-only dump) agrees with the live union about every planned
        # file, and so does a dump that PREDATES the content — the rows it
        # lost are the ones that named the files.  The shared gate decides
        # all five and names the one that failed; the plan phase asks the
        # same question for the same reason (and memoizes the answer), so
        # a refusal raised there — before the pre-action snapshot exists —
        # and one raised here are the same verdict about the same dump.
        #
        # The dump is measured once per run, with the SAME extensions and
        # the SAME walked uploads directories the plan measured with
        # (`self._dirs`) — the two halves of one gate must measure one set,
        # not one set and a variant of it.
        #
        # The comparison is DATABASE against DATABASE, on a DIRECT
        # reference (``in``), not the L5 stem rule: the stem rule is a
        # client-side keep rule applied to whichever reference set is in
        # force, and re-applying the dump's to files the live set does not
        # reference would refuse runs whose keep-sets are identical.  The
        # live side is still tested with the full keep rule (``union``), so
        # a file protected by any leg on the live side is not a dispute.
        witness = self._witness_verdict(ctx, refs.db_refs,
                                        self._live_schema(bridge))
        if witness.problem is not None:
            raise self._cross_mode_refusal(paths, witness.problem)
        dumped = witness.refs or set()
        disputed = sorted(
            path for path in paths
            if path in dumped and not protected_by(refs.union, path)
        )
        if disputed:
            raise dispute_refusal("trim-media", disputed, ctx.sql)

        mapped = bridge.call("media_map", refs=paths)
        # An id is accepted ONLY when the attachment's OWN resolved file is
        # one of the files this run deletes.  Stem/basename matching can
        # point a stray duplicate (2023/09/pic.jpg) at an attachment in
        # another month (2023/10/pic.jpg) whose file is referenced and
        # protected; deleting that id's rows would corrupt it without
        # touching its file.
        ids = attachment_ids_for_files(mapped.get("refs"), paths)

        payload = bridge.call("media_delete", ids=sorted(ids), files=paths)
        # SPEC "verify after every change": media_delete commits the DB rows
        # and THEN unlinks the files, swallowing per-file unlink errors. The
        # bridge now reports the uploads-relative paths it could NOT remove
        # (unlink_failures) — that server-side answer is AUTHORITATIVE. (A
        # client-side source.exists() re-check is NOT: FtpSource.exists maps
        # transient lookup errors to False, which would look like "deleted".)
        # Mark an item done only when the server did NOT report a failure for
        # it; any reported failure fails the apply (rc 1) instead of claiming
        # a successful deletion.
        failures = payload.get("unlink_failures")
        if not isinstance(failures, list):
            failures = []
        failed_paths = {
            p[len(_UPLOADS_PREFIX):] if p.startswith(_UPLOADS_PREFIX) else p
            for p in failures if isinstance(p, str)
        }
        for item in plan.items:
            if not item.requires_apply:
                continue
            rel = item.target[len(_UPLOADS_PREFIX):] \
                if item.target.startswith(_UPLOADS_PREFIX) else item.target
            if rel not in failed_paths:
                item.done = True
        if failed_paths:
            raise SourceError(
                f"trim-media: the server could not remove {len(failed_paths)} "
                f"file(s) (the DB rows are already gone); the apply is reported "
                f"as failed — restore from the pre-action backup if needed"
            )
        log.info(
            "apply: %d file(s) deleted, %d attachment post(s), %d meta row(s), "
            "%d term relationship(s), %d already missing",
            _opt_int(payload.get("deleted_files")) or 0,
            _opt_int(payload.get("deleted_posts")) or 0,
            _opt_int(payload.get("deleted_meta")) or 0,
            _opt_int(payload.get("deleted_termrels")) or 0,
            _opt_int(payload.get("skipped_missing")) or 0,
        )
        return plan


# The registry stores the decorated OBJECT and calls .plan/.apply on it,
# so the registered action is the instance (same as clean_files/clean_db:
# a bare class would be invoked with plan(ctx, stack) unbound and crash
# in run_action).
register_action("trim-media", applies=("ftp", "local"))(TrimMediaAction())
