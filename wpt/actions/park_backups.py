"""park-backups action: move full-site backup payloads OUT of the webroot.

Two-phase action over the shared registry flow (``wpt.actions.registry`` —
the registry owns dry-run, confirmation, the fail-closed pre-action backup,
the local-mode rehearsal and the post-apply cache purge; this module is
pure domain logic).  Registered ``applies=("ftp", "local")``: the PLAN is a
walk + measurement in both modes, the MOVE is an ftp-mode path (see
``Local mode`` below).

WHY: full-site archive payloads can sit IN the document root beside a dead
duplicate webroot at a guessable path.  That is a live exposure (a guessable
URL serves another copy of the site's code, including its PHP) as much as it
is wasted bytes, and no wpt command could move it: clean-files only deletes a
bounded set of junk names, and everything here is somebody's backup — a
site's archives must be MOVED, never destroyed.

THE PLAN

1. ONE walk.  Candidates come from the shared owner
   (``settings.backup_payloads``, the same lists the clean-files
   backup-payload group reads): a FILE whose basename fnmatches an
   ``extensions`` pattern, or a DIRECTORY whose basename fnmatches a
   ``directories`` pattern.  A candidate nested inside a candidate
   directory is dropped (the directory move covers it).
2. Two structural exclusions, both STRICTLY STRONGER than the requirement
   and both mode-agnostic (no bridge/dump lookup, so a plan never fails
   closed for want of an active set): nothing under ``wp-content/uploads/``
   (attachment data and inbound form records — a ``.sql`` there is a form
   submission export, never a payload) and nothing under a plugin or theme
   UNIT (``wpt.actions.junk_categories.in_unit_subtree``).
3. Two MEASURED gates, each fail-closed to ADVICE:
   * rendered pages — the live walk's reference set (rendered HTML refs,
     srcset attributes, generated-CSS ``url()`` refs; ftp only).  A
     candidate whose basename is still referenced is KEPT, never moved out
     from under a page that points at it.  A partial or empty walk measures
     nothing provable, so nothing is parkable in that run.
   * the destination — see below.
4. Every candidate becomes exactly one item:
   * parkable (``requires_apply=True``, category ``webroot.backup_payload``)
     when the reference gate proved the payload unreferenced AND the
     destination is provably outside the document root;
   * ADVICE (``requires_apply=False``, category ``webroot.junk``, detail
     naming ``backup_payload_in_webroot``) otherwise.  This is the safety
     net the live site lacked: the audit — and any operator reading the dry
     run — sees the exposure even when nothing can be applied, and rc stays
     0 because advice is "needs your call" (the clean-files active-unit
     guard's contract).

THE DESTINATION

``<backup_dir>/parked/<site>-<ts>/`` by default (``--park-outside DIR``
overrides it; the CLI puts the flag in ``ctx.extra["park_outside"]``).  It
is the action's OWN directory, outside the webroot by construction, and a
plan whose destination is provably INSIDE the webroot refuses that
destination LOUDLY (one error naming both paths) and degrades every item to
advice, so the run still reports the exposure.

``_inside_webroot`` is the whole provability rule, and it is stated in the
one coordinate system a park destination and a webroot can be compared in:
the destination is a LOCAL filesystem path (the bytes are copied to the
operator's own machine — the Source protocol has no cross-tree write, so
that copy-out is what "moving out" IS here), and it is refused when it
resolves inside the source's own root, whether that root is a real local
directory (a directory-backed source) or an FTP-relative webroot path (the
mistake an operator actually makes: passing a webroot-relative path to
``--park-outside``).  Both checks refuse rather than park, so a wrong
destination can never reintroduce the exposure it was meant to remove.

THE MOVE (apply, ftp mode)

Copy out, verify, then remove — never the other way round:

1. read the payload through the batched ``read_many`` protocol
   (200-path batches, ``Deadline``-checked per batch; a read failure fails
   that item closed and the webroot file STAYS);
2. write it under the park directory at the SAME webroot-relative path
   (tmp-then-rename inside the destination, parents created), then
   RE-READ the written file and compare sha256 — verify-after-write, the
   SPEC rule; a mismatch fails the item and removes the copy, so a truncated
   or half-written archive is never mistaken for a parked one;
3. only then remove it from the webroot (``delete`` for a file,
   ``rmdir_recursive`` for a directory).  A removal failure leaves the item
   ``done=False`` and the parked copy in place — the bytes are safe, and
   the log line says where they are.
4. verify-after-change: the removal is proved by the ``delete`` call
   itself raising or not.  ``Source.exists`` is deliberately NOT used as the
   proof: ``FtpSource.exists`` maps a transient lookup error to False, which
   would read as "removed" (the trim-media comment on the same trap).

A payload LARGER than ``backup_payloads.max_park_file_bytes`` is reported as
advice instead of being buffered: the action moves what it can hold, and an
operator moves a multi-gigabyte archive by hand.  Directories are read in
batches, so a large subtree costs no extra memory.

Local mode: a zip cannot represent a file moved OUT of the webroot (the
rehearsal writes a NEW archive from the same tree), so every local item is
ADVICE — the dry run still enumerates the payloads and the exposure, and a
local ``--apply`` rehearses nothing and exits 0.  Running the action against
the live site is the only way to move one.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from ..backup import sanitize_site_label, site_label
from ..deadline import Deadline, bounded_walk
from ..log import get_logger
from ..report import Plan, human_bytes
from ..types import PlanItem, Source, SourceError, WptError
from .junk_categories import (
    PAYLOAD_CATEGORY,
    PAYLOAD_EXPOSURE,
    PayloadCandidate,
    payload_candidates,
)
from .registry import register_action
# Imported INTO this module's namespace and called as a bare global so
# tests patch wpt.actions.park_backups.walk_site (the trim-media seam).
from ..walk import walk_site

if TYPE_CHECKING:
    from ..cli import Ctx

__all__ = ["ParkBackupsAction"]

log = get_logger("actions.park_backups")

#: Plan category of a payload this action can move out of the webroot
#: (distinct from ``PAYLOAD_CATEGORY``, the exposure a plan reports when it
#: CANNOT move one).
_PARK_CATEGORY = "webroot.backup_payload"

#: The park directory's own subdirectory name, under ``--backup-dir``
#: (structural: the layout the SPEC fixes, not a profile knob).
_PARK_SUBDIR = "parked"

#: Read batch size, mirroring the backup capture's 200-path batches: the
#: memory bound and the deadline-check granularity.
_READ_BATCH = 200

#: The advice detail a candidate that cannot be moved carries.  It names the
#: exposure (an archive served from the document root is downloadable at a
#: guessable URL) and the two ways out, so the item is actionable on its own.
_ADVICE = (
    "{exposure}: a full-site backup payload is being served from the "
    "document root — move it out by hand (it is an exposure at a guessable "
    "URL, not only wasted bytes), or re-run `wpt park-backups --apply` with "
    "--park-outside <dir> naming a destination outside the webroot"
)


def _park_timestamp() -> str:
    """The park directory's timestamp component (local time, the backup
    snapshot's own convention)."""
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _deletable(source: Source, path: str) -> bool:
    """True unless the source guard refuses to delete ``path``."""
    try:
        source._check_deletable(path)
    except SourceError:
        return False
    return True


def _inside_webroot(destination: Path, webroot: str) -> bool:
    """True when the LOCAL park destination provably sits inside the
    webroot.

    Two provable shapes, one rule (the park destination is a local path, so
    it can only be "inside the webroot" in these):

    * the webroot is a real local path (a rehearsal/extraction root):
      the destination resolves under it;
    * the webroot is an FTP-relative path and the destination was given as
      a path under it — the mistake an operator actually makes when they
      pass a webroot-relative ``--park-outside``.  The comparison is
      textual on the FTP form (there is no local filesystem view of a
      remote webroot) and therefore conservative: a destination that even
      LOOKS like it lives under the webroot is refused.
    """
    root = (webroot or "").strip().strip("/")
    if not root:
        return False
    if os.path.isdir(root):
        base = Path(root).resolve()
        resolved = destination.resolve()
        return resolved == base or base in resolved.parents
    text = destination.as_posix().strip("/")
    return text == root or text.startswith(root + "/")


def _referenced_basenames(refs: set[str]) -> set[str]:
    """The basenames the live site still references.

    A candidate is kept when its basename is in this set.  Basename
    matching (not exact-path) is the KEEP side of the gate: it over-keeps
    (two files may share a name in different directories), and over-keep is
    the safe direction for a move — a payload is left alone whenever the
    walk cannot prove the name is unreferenced.
    """
    return {ref.rsplit("/", 1)[-1] for ref in refs}


class ParkBackupsAction:
    """The plan/apply pair; ``stack`` is the registry-built source trio.

    One run's park directory is resolved ONCE (in ``plan``) and reused by
    ``apply``: the destination carries a timestamp, and a plan that
    advertised one directory while the apply wrote into the next second's
    would leave the operator hunting for the payload.  The registry holds
    a single action instance per process, so the plan and the apply of one
    run always share it.
    """

    def plan(self, ctx: "Ctx", stack: tuple) -> Plan:
        # Re-resolve this run's park directory: the registered action is a
        # module-level singleton, so a previous run's cached path (its own
        # backup dir, its own timestamp) must never leak into this one.
        self._park_destination = None
        source, session, _bridge = stack
        settings = ctx.settings
        entries = list(bounded_walk(
            source, Deadline.from_ctx(ctx), "park-backups plan"))
        found = payload_candidates(entries, settings)
        deletable = [(cand, _deletable(source, cand.path)) for cand in found]
        guarded = [cand.path for cand, ok in deletable if not ok]
        candidates = [cand for cand, ok in deletable if ok]
        if guarded:
            log.warning(
                "excluding %d payload(s) the source refuses to delete: %s",
                len(guarded), ", ".join(sorted(guarded)),
            )
        if not candidates:
            log.info("plan: no backup payload in the webroot")
            return Plan(items=[])

        # GATE 1 — rendered pages.  Local mode has no live site, so the
        # gate is unprovable there (and local items are advice anyway).
        refs_proved, refs = self._reference_gate(ctx, session)
        referenced = _referenced_basenames(refs) if refs_proved else set()
        if refs_proved:
            kept = [c for c in candidates
                    if c.path.rsplit("/", 1)[-1] in referenced]
            if kept:
                log.info(
                    "plan: %d payload(s) are still referenced by a rendered "
                    "page — never moved: %s", len(kept),
                    ", ".join(sorted(c.path for c in kept)),
                )
            candidates = [c for c in candidates
                          if c.path.rsplit("/", 1)[-1] not in referenced]

        # GATE 2 — the destination.  A destination inside the webroot is
        # refused loudly and degrades every item to advice.
        destination = self._destination(ctx)
        problem = self._destination_problem(ctx, destination)
        if problem:
            log.error("%s", problem)
        parkable = ctx.mode == "ftp" and refs_proved and not problem

        # GATE 3 — the in-memory read bound: a payload bigger than the
        # bound is never buffered, so it is reported as advice instead.
        bound = settings.backup_payloads.max_park_file_bytes
        items: list[PlanItem] = []
        for cand in candidates:
            oversize = (not cand.is_dir and bound and cand.size > bound)
            if oversize:
                log.info(
                    "plan: %s is %s, above the park bound (%s) — reported as "
                    "advice, move it by hand", cand.path,
                    human_bytes(cand.size), human_bytes(bound),
                )
            can_park = parkable and not oversize
            items.append(PlanItem(
                category=(_PARK_CATEGORY if can_park else PAYLOAD_CATEGORY),
                target=cand.path,
                detail=self._detail(cand, destination, can_park, oversize,
                                    bound),
                bytes_est=cand.size,
                requires_apply=can_park,
            ))
        items.sort(key=lambda i: (i.category, i.target))
        plan = Plan(items=items)
        if parkable:
            log.info(
                "plan: %d payload(s), %s to be parked under %s",
                sum(1 for i in items if i.requires_apply),
                human_bytes(plan.est_bytes()), destination,
            )
        else:
            advice = sum(1 for i in items if not i.requires_apply)
            log.info(
                "plan: %d payload(s) (%s) reported as ADVICE — nothing is "
                "moved without a provable reference set and a destination "
                "outside the webroot", advice, human_bytes(
                    sum(i.bytes_est for i in items)),
            )
        return plan

    def apply(self, ctx: "Ctx", stack: tuple, plan: Plan) -> Plan:
        source = stack[0]
        pending = [i for i in plan.items if i.requires_apply]
        if not pending:
            # Local mode (a zip cannot represent a move out of the webroot)
            # and an advice-only plan: nothing to execute, by design.
            return plan
        if ctx.mode != "ftp":
            raise SourceError(
                "park-backups can only move a payload out of the webroot in "
                "ftp mode (a local zip rehearsal cannot represent it)"
            )
        destination = self._destination(ctx)
        deadline = Deadline.from_ctx(ctx)
        bound = ctx.settings.backup_payloads.max_park_file_bytes or None
        for item in pending:
            try:
                self._park(source, item.target, destination, deadline, bound)
            except (WptError, OSError) as exc:
                log.warning(
                    "could not park %s (%s: %s); it stays in the webroot",
                    item.target, type(exc).__name__, exc,
                )
                continue
            item.done = True
        log.info(
            "apply: %d/%d payload(s) moved out of the webroot under %s",
            sum(1 for i in pending if i.done), len(pending), destination,
        )
        return plan

    # ------------------------------------------------------------- internals

    def _reference_gate(self, ctx: "Ctx", session) -> tuple[bool, set[str]]:
        """``(proved, refs)`` — the rendered-page gate.

        ``walk_site`` never raises; a PARTIAL or EMPTY result measures
        nothing that can prove a payload unreferenced (an incomplete
        reference set makes every unreferenced-looking name look dead), so
        the gate reports unproved and every item degrades to advice.  The
        walk is imported as a module global (tests patch it) and is issued
        only when there is at least one candidate, so a clean tree costs no
        HTTP at all.
        """
        if ctx.mode != "ftp" or session is None:
            return False, set()
        result = walk_site(
            session, ctx.wp_url, ctx.settings.walk,
            ctx.settings.http.timeout_s,
            deadline=Deadline.from_ctx(ctx),
        )
        if result.partial or not result.live_refs:
            log.warning(
                "the live walk measured %d reference(s)%s — not enough to "
                "prove a payload is unreferenced, so nothing is moved",
                len(result.live_refs),
                " from a PARTIAL walk" if result.partial else "",
            )
            return False, set()
        log.debug("park-backups: %d live reference(s) measured",
                  len(result.live_refs))
        return True, result.live_refs

    def _destination(self, ctx: "Ctx") -> Path:
        """The park directory: ``--park-outside`` when given, else
        ``<backup_dir>/parked/<site>-<ts>/``.  The site label goes through
        the snapshot's own sanitizer, so a hostile hostname can never shape
        the path.  Resolved once per run (the class docstring)."""
        cached = getattr(self, "_park_destination", None)
        if cached is not None:
            return cached
        outside = ctx.extra.get("park_outside")
        if outside:
            base = Path(str(outside))
        else:
            base = ctx.backup_dir / _PARK_SUBDIR
        label = sanitize_site_label(site_label(ctx))
        self._park_destination = base / f"{label}-{_park_timestamp()}"
        return self._park_destination

    def _destination_problem(self, ctx: "Ctx", destination: Path) -> str | None:
        """The refusal message when the destination is inside the webroot,
        else None.  One line naming BOTH paths (the operator's mistake is
        which side of the boundary the value landed on)."""
        if _inside_webroot(destination, ctx.webroot or ""):
            return (
                f"--park-outside destination {destination} is INSIDE the "
                f"webroot ({ctx.webroot or 'the site root'}): parking there "
                f"would leave the payload served from the document root — "
                f"refusing that destination; every item is reported as "
                f"advice instead"
            )
        return None

    def _detail(self, cand: PayloadCandidate, destination: Path, can_park: bool,
                oversize: bool, bound: int) -> str:
        """The item's one-line detail."""
        if oversize:
            return (
                f"{PAYLOAD_EXPOSURE}: {cand.pattern} backup payload of "
                f"{human_bytes(cand.size)} — above the park bound "
                f"({human_bytes(bound)}), so wpt will not buffer it; "
                f"move it out of the webroot by hand"
            )
        if not can_park:
            return _ADVICE.format(exposure=PAYLOAD_EXPOSURE)
        if cand.is_dir:
            what = f"backup directory ({cand.pattern}, {cand.files} files)"
        else:
            what = f"{cand.pattern} backup payload"
        return f"{what} — moved to {destination}"

    def _park(self, source: Source, path: str, destination: Path,
              deadline, bound: int | None = None) -> None:
        """Copy one payload out of the webroot, verify the copy, then
        remove the original.  Directory-ness is re-derived from one fresh
        walk (``PlanItem`` carries no is_dir field).

        A symbolic link (the path itself or any member of the directory)
        is refused BEFORE anything is written: reading through it would
        park the TARGET's bytes as a regular file and delete the link, so
        the webroot would no longer match the tree that was measured.
        """
        # The walk of ``path`` yields only its CHILDREN; the item's own
        # type/link flag comes from its parent listing (one bounded listing,
        # never the old whole-webroot walk).
        parent = path.rpartition("/")[0]
        root_entry = next(
            (entry for entry in source.list_dir(parent)
             if entry.path == path), None)
        if root_entry is not None and root_entry.is_link:
            raise SourceError(
                f"{path} is a symbolic link; a parked copy would follow it "
                "and lose the link, so nothing is moved")
        entries = list(bounded_walk(
            source, deadline, "park-backups walk", path=path,
            include_links=True))
        prefix = f"{path}/"
        if any(entry.is_link and (entry.path == path
                                  or entry.path.startswith(prefix))
               for entry in entries):
            raise SourceError(
                f"{path} contains a symbolic link; a parked copy would "
                "follow it and lose the link, so nothing is moved")
        is_dir = bool(root_entry.is_dir) if root_entry is not None else False
        if is_dir:
            self._park_dir(source, path, destination, deadline, bound)
        else:
            size = source.size(path)
            if bound is not None and size > bound:
                raise SourceError(
                    f"{path} is {size} bytes, above the park bound "
                    f"({bound}); it stays in the webroot")
            self._park_file(source, path, destination / path, deadline, bound)

    def _park_dir(self, source: Source, path: str, destination: Path,
                  deadline, bound: int | None = None) -> None:
        """Move one backup directory in READ_BATCH-sized pieces.

        Each batch is written and verified before the next is read, so the
        whole subtree is never resident at once (the live finding was a
        large dead webroot).  Every read also carries the
        configured per-file bound: a directory member above
        ``backup_payloads.max_park_file_bytes`` is never buffered whole.
        A read failure still fails the item closed: the batches already
        written under this item's destination are discarded and the
        webroot directory STAYS.
        """
        entries = [entry for entry in bounded_walk(
            source, deadline, "park-backups walk", path=path,
            include_links=True)
                   if not entry.is_dir or entry.is_link]
        if any(entry.is_link for entry in entries):
            raise SourceError(
                f"{path} contains a symbolic link; a parked copy would "
                "follow it and lose the link, so the directory stays in "
                "the webroot")
        files = [entry.path for entry in entries]
        sizes = {entry.path: entry.size for entry in entries}
        if bound is not None:
            oversized = sorted(p for p, size in sizes.items() if size > bound)
            if oversized:
                raise SourceError(
                    f"{len(oversized)} file(s) of {path} are above the park "
                    f"bound ({bound} bytes; first: {oversized[0]}); the "
                    "directory stays in the webroot")
        parked: list[Path] = []
        try:
            for start in range(0, len(files), _READ_BATCH):
                if deadline is not None:
                    deadline.check("park-backups read")
                batch = files[start:start + _READ_BATCH]
                ok, failed = source.read_many(batch, max_bytes=bound)
                if failed:
                    name, error = sorted(failed.items())[0]
                    raise SourceError(
                        f"{len(failed)} file(s) of {path} could not be read, "
                        f"so the directory is not moved (first: {name}: "
                        f"{error})"
                    )
                for name, data in ok.items():
                    out = destination / name
                    self._write_verified(out, data)
                    parked.append(out)
        except BaseException:
            self._discard_parked(parked, destination)
            raise
        if deadline is not None:
            deadline.check("park-backups remove")
        source.rmdir_recursive(path)

    def _discard_parked(self, parked: list[Path], destination: Path) -> None:
        """Remove the copies THIS item wrote after a failed read/move.

        A failed read leaves the webroot untouched, so those copies are the
        only residue; only paths this call created are touched (never a
        pre-existing file from another run)."""
        for out in reversed(parked):
            out.unlink(missing_ok=True)
            parent = out.parent
            while parent != destination and parent != parent.parent:
                try:
                    parent.rmdir()
                except OSError:
                    break
                parent = parent.parent

    def _park_file(self, source: Source, path: str, out: Path,
                   deadline, bound: int | None = None) -> None:
        ok, failed = self._read_batch(source, [path], deadline, bound)
        if failed:
            error = next(iter(failed.values()))
            raise SourceError(f"could not read {path}: {error}")
        self._write_verified(out, ok[path])
        if deadline is not None:
            deadline.check("park-backups remove")
        source.delete(path)

    def _read_batch(self, source: Source, paths: list[str],
                    deadline,
                    bound: int | None = None
                    ) -> tuple[dict[str, bytes], dict[str, str]]:
        """``(ok, failed)`` over ``read_many`` in 200-path batches, checking
        the deadline once per batch.  Every read carries the configured
        per-file bound.  A read_many RAISE is run-level (a channel trip, an
        expired deadline) and propagates."""
        ok: dict[str, bytes] = {}
        failed: dict[str, str] = {}
        for start in range(0, len(paths), _READ_BATCH):
            if deadline is not None:
                deadline.check("park-backups read")
            batch = paths[start:start + _READ_BATCH]
            got, bad = source.read_many(batch, max_bytes=bound)
            ok.update(got)
            failed.update(bad)
        return ok, failed

    def _write_verified(self, out: Path, data: bytes) -> None:
        """Write one parked file (tmp-then-rename) and PROVE it: the bytes
        are re-read from disk and compared by sha256.  A mismatch removes
        the copy and fails, so a truncated archive can never be mistaken
        for a parked one."""
        out.parent.mkdir(parents=True, exist_ok=True)
        tmp = out.with_name(out.name + ".wpt-parking")
        try:
            tmp.write_bytes(data)
            tmp.replace(out)
        except OSError:
            tmp.unlink(missing_ok=True)
            raise
        if hashlib.sha256(out.read_bytes()).hexdigest() \
                != hashlib.sha256(data).hexdigest():
            out.unlink(missing_ok=True)
            raise SourceError(
                f"the parked copy of {out.name} did not verify after the "
                f"write (sha256 mismatch); it was removed and the webroot "
                f"file is untouched"
            )


# The registry stores the decorated OBJECT and calls .plan/.apply on it,
# so the registered action is the instance (same as clean_files/trim_media).
register_action("park-backups", applies=("ftp", "local"))(ParkBackupsAction())
