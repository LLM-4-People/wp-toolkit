"""Selected-file backup, edit and rollback behind ``wpt files``.

The command names REGULAR webroot files explicitly; it is deliberately not a
directory sync and it never edits WordPress core or configuration files:

* ``--backup PATH ...`` snapshots the named files (bytes + manifest + SHA-256)
  into ``<backup-dir>/<site>/files-<UTC>-<hex>/``.  The remote side is read
  only; the same mode works from an offline ``--zip``.
* ``--path PATH --from LOCAL`` pairs a webroot-relative target with a local
  body.  A dry run is a plan; ``--apply`` takes the shared
  ``wpt.actions.registry.confirm`` gate, snapshots the current state and then
  writes each body to a sibling temp name, reads it back and renames it into
  place.  Any failure rolls every already-changed target back from that
  snapshot and cleans the surviving temps.
* ``--restore SNAPSHOT`` restores a ``wpt-files`` snapshot (a directory name
  under the site's backup directory, an explicit path, or ``last``).  EVERY
  route requires the current identity: the manifest must record BOTH the
  exact raw site label and the webroot, and both must match the current run.
  An explicit path selects the snapshot LOCATION; it is never a trust
  bypass, because two labels can sanitize to one directory name.  The
  command verifies every stored SHA-256 before the first write, snapshots
  the current state first and uses the same temp+rename/rollback
  transaction.  Lookup uses ONE exact raw identity directory; pre-round-3
  spellings (``www.<host>``, original case, redacted label) are never
  searched or normalized, so a shared sanitized directory cannot
  cross-restore.

Safety boundaries owned here:

* every target is a safe, webroot-relative POSIX path (no absolute path, no
  ``..``/``.``/empty segment, backslashes normalized) and duplicates are
  refused;
* ``wpt.settings.files.max_files`` / ``max_file_bytes`` bound the run BEFORE
  the first read or write;
* apply/edit/restore targets are preflighted against ``Source.PROTECTED``,
  ``wp-admin/``, ``wp-includes/`` and the top-level ``index.php`` so no
  partial transaction can start on a path the source guard would refuse
  later (backup may still READ such a file; restoring it is refused);
* local mode is backup-only: edit/restore refuse before any write.

The one error contract is the rest of the CLI's: ``WptError``/``OSError`` is
one redacted ``log.error`` line, a failure report when ``--report`` was
asked for, and exit 1 — never a traceback.  The markdown report is written through the shared
``wpt.report.write_stdout`` sink; only the CLI prints directly.
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import secrets
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .backup import (MANIFEST_MAX_BYTES, open_private_site_dir,
                     private_dir_chain, read_regular_bounded,
                     sanitize_site_label, site_label,
                     sweep_stale_snapshot_temps, write_private_bytes)
from .bridge_name import is_wpt_endpoint_file
from .config import redact_text
from .deadline import Deadline
from .log import get_logger
from .remote import ftp_source_for
from .report import (AuditReport, human_bytes, md_escape,
                     record_snapshot_root, safe_source_label)
from .report import write_stdout
from .sources.base import close_source
from .sources.zip import ZipSource
from .types import (DeadlineExceeded, RunControl, Source, SourceError,
                    StopRequested, WptError, absence_proven, presence_proven)

if TYPE_CHECKING:  # annotation-only (cli lazy-calls every command)
    from .cli import Ctx

__all__ = ["run"]

log = get_logger("files")

#: Snapshot contract (single owner): directory names, manifest fields and the
#: stored-bytes hierarchy every reader/writer below agrees on.
MANIFEST_NAME = "manifest.json"
FILES_DIR = "files"
MANIFEST_FORMAT = "wpt-files"
MANIFEST_VERSION = 1
KINDS = ("files", "edit", "restore")

_SNAPSHOT_RE = re.compile(
    r"^(?P<kind>files|edit|restore)-"
    r"(?P<stamp>\d{8}T\d{6}Z)-(?P<nonce>[0-9a-f]{6})$"
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_STAMP_FORMAT = "%Y%m%dT%H%M%SZ"
_DRIVE_RE = re.compile(r"^[A-Za-z]:")

#: Structural retry bound for a temp/name collision (not a policy knob).
_COLLISION_ATTEMPTS = 5


class _Aborted(WptError):
    """The operator refused the apply gate (a refusal, not an error)."""


@dataclass
class _State:
    """One target's bytes and facts (``data`` stays in memory for a run)."""

    path: str
    exists: bool
    size: int = 0
    sha256: str | None = None
    data: bytes | None = None


@dataclass
class _SnapshotEntry:
    """One manifest record, with its verified bytes when it exists."""

    path: str
    exists: bool
    size: int = 0
    sha256: str | None = None
    stored: str | None = None
    data: bytes | None = None


@dataclass
class _Snapshot:
    path: Path
    kind: str
    webroot: str
    entries: list[_SnapshotEntry]
    by_path: dict[str, _SnapshotEntry] = field(init=False)

    def __post_init__(self) -> None:
        self.by_path = {entry.path: entry for entry in self.entries}


@dataclass
class _Row:
    path: str
    action: str
    current: str
    desired: str
    status: str
    exists: bool
    size: int
    sha256: str | None


@dataclass
class _Result:
    mode: str
    site: str
    snapshot: Path | None
    applied: bool
    rows: list[_Row]
    totals: dict[str, int]
    note: str


# --------------------------------------------------------------------- run


def run(ctx: "Ctx") -> int:
    """Run ``wpt files``; never raises for an operational failure."""
    mode: str | None = None
    source = None
    rc = 1
    close_stop: BaseException | None = None
    primary: BaseException | None = None
    try:
        mode = _selected_mode(ctx)
        if mode in ("edit", "restore") and ctx.mode == "local":
            raise WptError(
                f"files {mode} is ftp-only: local mode supports --backup from "
                "--zip only, so a mutating files run refuses before any write"
            )
        deadline = Deadline.from_ctx(ctx)
        _check(deadline, "files")
        source = _open_source(ctx)
        if mode == "backup":
            result = _run_backup(ctx, source, deadline)
        elif mode == "edit":
            result = _run_edit(ctx, source, deadline)
        else:
            result = _run_restore(ctx, source, deadline)

        markdown = _render(result)
        write_stdout(markdown, end="")
        if ctx.report_path is not None:
            rc = write_report(ctx, "files", markdown, _json_text(result))
        else:
            rc = 0
        if rc == 0:
            log.info("files: %s — %d file(s), snapshot %s", result.mode,
                     len(result.rows), result.snapshot or "-")
    except _Aborted as exc:
        primary = exc
        reason = redact_text(str(exc))
        log.info("files: %s", reason)
        _write_failure(ctx, mode or "unknown", reason, status="refused")
        rc = 1
    except RunControl as exc:
        primary = exc
        reason = redact_text(f"files stopped: {exc}")
        log.error("%s", reason)
        _write_failure(ctx, mode or "unknown", reason)
        rc = 1
    except (WptError, OSError) as exc:
        primary = exc
        reason = redact_text(str(exc))
        log.error("files: %s", reason)
        _write_failure(ctx, mode or "unknown", reason)
        rc = 1
    finally:
        if source is not None:
            try:
                close_source(source, "files")
            except (StopRequested, DeadlineExceeded) as exc:
                close_stop = exc
            except Exception as exc:  # noqa: BLE001 — never mask data
                log.warning("files: source close failed: %s",
                            redact_text(str(exc)))
    if close_stop is not None:
        reason = redact_text(str(close_stop))
        log.error("files: %s", reason)
        if primary is None:
            _write_failure(ctx, mode or "unknown", reason)
        else:
            log.error("files: the primary failure above stays the run's "
                      "reason (rc %d); the failure report was not replaced",
                      rc)
        return 1
    return rc


def _selected_mode(ctx: "Ctx") -> str:
    """Exactly one of backup/edit/restore; anything else is a usage refusal."""
    backup = list(ctx.extra.get("backup") or [])
    restore = ctx.extra.get("restore")
    paths = list(ctx.extra.get("paths") or [])
    from_paths = list(ctx.extra.get("from_paths") or [])
    selected = [
        name for name, enabled in (
            ("backup", bool(backup)),
            ("restore", restore is not None),
            ("edit", bool(paths) or bool(from_paths)),
        )
        if enabled
    ]
    if not selected:
        raise WptError(
            "wpt files needs one mode: --backup PATH, "
            "--path PATH --from LOCAL, or --restore SNAPSHOT"
        )
    if len(selected) > 1:
        raise WptError(
            "wpt files modes are mutually exclusive: " + ", ".join(selected)
        )
    return selected[0]


def _open_source(ctx: "Ctx") -> Source:
    """The one source for this run (the module seam tests monkeypatch)."""
    if ctx.mode == "local":
        if ctx.zip is None:
            raise SourceError("local mode requires --zip")
        return ZipSource(ctx.zip, deadline=Deadline.from_ctx(ctx))
    return ftp_source_for(ctx)


def confirm(ctx: "Ctx") -> bool:
    """The shared apply gate (thin module seam over the registry owner)."""
    from .actions.registry import confirm as gate

    return gate(ctx)


def write_report(ctx: "Ctx", name: str, markdown: str,
                 json_text: str | None = None) -> int:
    """The shared report writer (thin module seam over the registry owner)."""
    from .actions.registry import write_report as writer

    return writer(ctx, name, markdown, json_text)


def write_failure_report(ctx: "Ctx", name: str, reason: str,
                         **kwargs: Any) -> int:
    """The shared failed-run report writer (registry owner seam)."""
    from .actions.registry import write_failure_report as writer

    return writer(ctx, name, reason, **kwargs)


# ------------------------------------------------------------------ backup


def _run_backup(ctx: "Ctx", source: Source,
                deadline: Deadline | None = None) -> _Result:
    paths = _validate_targets(
        ctx, list(ctx.extra.get("backup") or []),
        protect=False, label="--backup",
    )
    max_bytes = _max_file_bytes(ctx)
    states = [
        _read_state(source, path, max_bytes, purpose="backup",
                    deadline=deadline)
        for path in paths
    ]
    snapshot = _create_snapshot(ctx, "files", states, deadline=deadline)
    rows = [
        _Row(
            path=state.path,
            action="backup",
            current=_facts(state),
            desired=_facts(state),
            status="captured" if state.exists else "absent",
            exists=state.exists,
            size=state.size,
            sha256=state.sha256,
        )
        for state in states
    ]
    return _Result(
        mode="backup",
        site=_site(ctx),
        snapshot=snapshot.path,
        applied=False,
        rows=rows,
        totals=_totals(rows),
        note=("snapshot written under the local backup directory; the "
              "remote webroot was not modified"),
    )


# -------------------------------------------------------------------- edit


def _run_edit(ctx: "Ctx", source: Source,
              deadline: Deadline | None = None) -> _Result:
    raw_paths = list(ctx.extra.get("paths") or [])
    local_paths = list(ctx.extra.get("from_paths") or [])
    if len(raw_paths) != len(local_paths):
        raise WptError(
            "--path and --from pair by position: got "
            f"{len(raw_paths)} target(s) and {len(local_paths)} local file(s)"
        )
    targets = _validate_targets(ctx, raw_paths, protect=True, label="--path")
    max_bytes = _max_file_bytes(ctx)

    # Read every local body and every current target ONCE, before the first
    # write.  Both are bounded by files.max_file_bytes (stat first, read,
    # then length-check so a raced growth is still refused).
    desired = [
        _state_from_local(path, local, max_bytes, deadline=deadline)
        for path, local in zip(targets, local_paths)
    ]
    current = [
        _read_state(source, path, max_bytes, purpose="edit",
                    deadline=deadline)
        for path in targets
    ]

    if not ctx.apply:
        rows = [
            _row_for(want, old, action="edit", status="planned")
            for want, old in zip(desired, current)
        ]
        return _Result(
            mode="edit",
            site=_site(ctx),
            snapshot=None,
            applied=False,
            rows=rows,
            totals=_totals(rows),
            note=("dry run: no snapshot and no remote file was written; "
                  "pass --apply to execute"),
        )

    if not confirm(ctx):
        raise _Aborted("edit: aborted by the operator")

    # The operator may have read the plan for minutes.  Re-read every target
    # AFTER the gate so the pre-edit snapshot (and the rollback baseline) is
    # the current state, never the plan-time state.
    current = [
        _read_state(source, path, max_bytes, purpose="edit",
                    deadline=deadline)
        for path in targets
    ]
    snapshot = _create_snapshot(ctx, "edit", current, deadline=deadline)
    try:
        statuses = _apply_transaction(source, snapshot, desired, max_bytes,
                                      deadline=deadline)
    except (WptError, OSError) as exc:
        raise WptError(
            f"edit failed: {exc}; snapshot kept at {snapshot.path}"
        ) from exc

    rows = [
        _row_for(want, old, action="edit", status=statuses.get(want.path, "written"))
        for want, old in zip(desired, current)
    ]
    return _Result(
        mode="edit",
        site=_site(ctx),
        snapshot=snapshot.path,
        applied=True,
        rows=rows,
        totals=_totals(rows),
        note=("transaction committed; the pre-edit snapshot is kept for "
              "wpt files --restore"),
    )


def _state_from_local(path: str, local: str, max_bytes: int,
                      deadline: Deadline | None = None) -> _State:
    """Read one local body, bounded before and after the read."""
    _check(deadline, "files local read")
    if "\x00" in str(local):
        raise WptError(f"local source for {path!r} contains a NUL byte")
    try:
        source_path = Path(local)
    except TypeError as exc:
        raise WptError(
            f"local source for {path!r} is not a path: {local!r}"
        ) from exc
    try:
        stat = source_path.stat()
    except OSError as exc:
        raise WptError(
            f"cannot read local source {local!r} for {path!r}: {exc}"
        ) from exc
    if not source_path.is_file():
        raise WptError(
            f"local source for {path!r} is not a regular file: {local!r}"
        )
    if stat.st_size > max_bytes:
        raise WptError(
            f"local source {local!r} is {stat.st_size} bytes, over "
            f"files.max_file_bytes={max_bytes}"
        )
    try:
        data = source_path.read_bytes()
    except OSError as exc:
        raise WptError(
            f"cannot read local source {local!r} for {path!r}: {exc}"
        ) from exc
    if len(data) > max_bytes:
        raise WptError(
            f"local source {local!r} is {len(data)} bytes, over "
            f"files.max_file_bytes={max_bytes}"
        )
    return _State(path, True, len(data), _sha256(data), data)


# ----------------------------------------------------------------- restore


def _run_restore(ctx: "Ctx", source: Source,
                 deadline: Deadline | None = None) -> _Result:
    reference = ctx.extra.get("restore")
    snapshot_dir = _resolve_snapshot(ctx, reference, deadline=deadline)
    # The selected snapshot/manifest is a local INPUT: record it before the
    # first read (and before any report/failure pair) so --report can never
    # overwrite the rollback basis this run is restoring from.
    ctx.extra["snapshot_dir"] = str(snapshot_dir)
    record_snapshot_root(ctx, snapshot_dir)
    max_bytes = _max_file_bytes(ctx)
    snapshot = _load_snapshot(ctx, snapshot_dir, max_bytes, deadline=deadline)

    # Current states are captured ONCE: they feed the pre-restore snapshot
    # and the concurrent-editor check, so a mutation between these reads and
    # the first rename is always detected.
    current = [
        _read_state(source, entry.path, max_bytes, purpose="restore",
                    deadline=deadline)
        for entry in snapshot.entries
    ]

    if not ctx.apply:
        rows = [
            _row_for(
                _State(entry.path, entry.exists, entry.size, entry.sha256,
                       entry.data),
                state,
                action="restore" if entry.exists else "delete",
                status="planned",
            )
            for entry, state in zip(snapshot.entries, current)
        ]
        return _Result(
            mode="restore",
            site=_site(ctx),
            snapshot=snapshot.path,
            applied=False,
            rows=rows,
            totals=_totals(rows),
            note=("dry run: no snapshot and no remote file was written; "
                  "pass --apply to execute"),
        )

    if not confirm(ctx):
        raise _Aborted("restore: aborted by the operator")

    # Same rule as edit: the pre-restore rollback snapshot must describe
    # the state at apply time, not the dry-run read that preceded a prompt.
    current = [
        _read_state(source, entry.path, max_bytes, purpose="restore",
                    deadline=deadline)
        for entry in snapshot.entries
    ]
    rollback_snapshot = _create_snapshot(
        ctx, "restore", current, deadline=deadline)
    desired = [
        _State(entry.path, entry.exists, entry.size, entry.sha256, entry.data)
        for entry in snapshot.entries
    ]
    try:
        statuses = _apply_transaction(source, rollback_snapshot, desired,
                                      max_bytes, deadline=deadline)
    except (WptError, OSError) as exc:
        raise WptError(
            f"restore failed: {exc}; pre-restore snapshot kept at "
            f"{rollback_snapshot.path}"
        ) from exc

    rows = [
        _row_for(
            want,
            old,
            action="restore" if want.exists else "delete",
            status=statuses.get(want.path, "written"),
        )
        for want, old in zip(desired, current)
    ]
    return _Result(
        mode="restore",
        site=_site(ctx),
        snapshot=snapshot.path,
        applied=True,
        rows=rows,
        totals=_totals(rows),
        note=("restored from the named snapshot; the pre-restore rollback "
              f"snapshot is {rollback_snapshot.path}"),
    )


def _resolve_snapshot(ctx: "Ctx", reference: Any,
                      deadline: Deadline | None = None) -> Path:
    """Resolve 'last', a snapshot directory name, or an explicit path.

    A snapshot found under this site's ONE exact raw identity directory
    (``last`` or a bare name) is selected by name; an explicit path selects
    the snapshot LOCATION directly.  Either way :func:`_load_snapshot`
    requires the SAME current raw site label and webroot: two sites whose
    labels sanitize to one directory name must never restore each other's
    bytes.  No legacy identity spelling is searched: the current raw label
    is the only directory this owner knows.
    """
    if isinstance(reference, Path):
        reference = str(reference)
    if not isinstance(reference, str) or not reference.strip():
        raise WptError(
            "--restore needs a snapshot directory name, an explicit path, "
            "or 'last'"
        )
    if "\x00" in reference:
        raise WptError("the --restore snapshot reference contains a NUL byte")
    site_dir = _site_dir(ctx)
    identity = _site_identity(ctx)
    if reference == "last":
        inspected: list[Path] = []
        try:
            selected = _newest_snapshot(
                site_dir, deadline=deadline, site_identity=identity,
                webroot=ctx.webroot, inspected=inspected)
            # Every candidate whose manifest was read while deciding `last`
            # is an input too: a report must not replace a discarded
            # candidate's manifest/payloads (R16-P1).
            record_snapshot_root(ctx, selected)
            return selected
        finally:
            # Selection can RAISE after reading every candidate (no
            # selectable snapshot, a corrupt/foreign manifest): those roots
            # were still read, so the failure writer's protected set must
            # include them.  The pre-dispatch resolver takes the same path.
            for root in inspected:
                record_snapshot_root(ctx, root)
    named = site_dir / reference
    if "/" not in reference and "\\" not in reference and named.is_dir():
        record_snapshot_root(ctx, named)
        return named
    candidate = Path(reference)
    if candidate.is_dir():
        record_snapshot_root(ctx, candidate)
        return candidate
    raise WptError(
        f"no files snapshot {reference!r} under {site_dir} "
        "(pass a snapshot directory, an explicit path, or 'last')"
    )


def _site_dir(ctx: "Ctx") -> Path:
    """The ONE exact raw identity directory for this run's snapshot family."""
    return Path(ctx.backup_dir) / sanitize_site_label(_site_identity(ctx))


def _identity_matches(recorded: str | None, identity: str) -> bool:
    """True only when a manifest records the EXACT same raw identity.

    No normalization fallback (case/trailing dot/``www.``) and no redacted
    comparison: those are pre-round-3 spellings and must never make two
    distinct raw labels share a snapshot family.
    """
    return bool(recorded) and recorded == identity


def _newest_snapshot(site_dir: Path,
                     deadline: Deadline | None = None,
                     site_identity: str | None = None,
                     webroot: str | None = None,
                     inspected: list[Path] | None = None) -> Path:
    """Newest ``wpt-files`` snapshot in the ONE raw identity directory.

    Selection is by DIRECTORY NAME only (the same name-first discipline
    ``wpt restore`` uses): a corrupt newest manifest must be selected and
    then REFUSED by :func:`_load_snapshot` (fail closed), never skipped in
    favour of an older snapshot the operator did not ask for.  The
    directory mtime breaks a same-second tie between two random nonces.

    ``site_identity``/``webroot`` filter out snapshots whose manifest
    positively names a DIFFERENT raw site OR a different webroot (two
    docroots can share one host label, and two labels can share one
    sanitized directory).  Filtering BOTH keys at selection is what lets an
    older snapshot for THIS webroot win over a newer one for another
    docroot (R6-26).  A manifest that cannot be read is kept as a candidate
    so the corrupt newest still fails closed; there is no alternate
    directory to skip to.
    """
    if not site_dir.is_dir():
        raise WptError(f"no files snapshots under {site_dir}")
    found: list[tuple[str, int, str, Path]] = []
    other_site = 0
    for entry in site_dir.iterdir():
        _check(deadline, "restore snapshot selection")
        if not entry.is_dir():
            continue
        match = _SNAPSHOT_RE.match(entry.name)
        if not match:
            continue
        if inspected is not None:
            # This root is READ (its manifest) even when identity filtering
            # later rejects it: a report must not replace it.
            inspected.append(entry)
        if site_identity is not None:
            recorded = _snapshot_identity(entry, deadline)
            if recorded is not None:
                raw_site, recorded_webroot = recorded
                if not _identity_matches(raw_site, site_identity) \
                        or recorded_webroot != (webroot or ""):
                    other_site += 1
                    continue
        try:
            mtime = entry.stat().st_mtime_ns
        except OSError:
            mtime = 0
        found.append((match.group("stamp"), mtime, entry.name, entry))
    if not found:
        suffix = (f" ({other_site} snapshot(s) belong to another site)"
                  if other_site else "")
        raise WptError(f"no files snapshots under {site_dir}{suffix}")
    found.sort(key=lambda item: (item[0], item[1], item[2]))
    return found[-1][3]


def _snapshot_identity(snapshot_dir: Path,
                       deadline: Deadline | None = None
                       ) -> tuple[str, str] | None:
    """The manifest's ``(site_raw, webroot)``, or None when unreadable.

    Selection-only: a malformed manifest yields None (kept as a candidate
    so :func:`_load_snapshot` refuses it), never an exception that would
    hide a corrupt snapshot behind an older one.  The manifest is read
    through the SAME link-free rooted reader as the stored bytes, so a
    symlinked snapshot directory is refused instead of followed (N-G2).
    """
    _check(deadline, "restore snapshot selection")
    try:
        raw = read_regular_bounded(
            Path(MANIFEST_NAME), MANIFEST_MAX_BYTES, "snapshot manifest",
            root=snapshot_dir).decode("utf-8")
        manifest = json.loads(raw)
    except (StopRequested, DeadlineExceeded):
        # A cooperative stop or the run deadline is not an unreadable
        # manifest: treating it as one kept the candidate and let a
        # mutating restore proceed after SIGTERM (FILE1).
        raise
    except (WptError, OSError, UnicodeDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(manifest, dict):
        return None
    raw = manifest.get("site_raw")
    webroot = manifest.get("webroot")
    if not isinstance(raw, str) or not raw or not isinstance(webroot, str):
        return None
    return raw, webroot


def _load_snapshot(ctx: "Ctx", snapshot_dir: Path, max_bytes: int,
                   deadline: Deadline | None = None) -> _Snapshot:
    """Parse + verify a snapshot BEFORE the first write.

    Every stored byte is read and hashed here: a snapshot whose manifest is
    malformed, whose recorded identity differs, whose paths are unsafe or
    protected, or whose SHA-256/size disagrees with the stored file is
    refused as a whole — no partial restore ever starts.  The manifest is
    read through the same rooted, link-free reader as the stored bytes (a
    symlinked snapshot directory is refused, never followed).  EVERY restore
    route (managed ``last``/named OR an explicit path) requires BOTH the
    exact raw site label and the webroot: an explicit path selects the
    snapshot location, never a trusted import, and a missing key is never a
    wildcard.
    """
    _check(deadline, "restore snapshot manifest")
    manifest_path = snapshot_dir / MANIFEST_NAME
    try:
        raw = read_regular_bounded(
            Path(MANIFEST_NAME), MANIFEST_MAX_BYTES, "snapshot manifest",
            root=snapshot_dir
        ).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WptError(
            f"snapshot manifest {manifest_path} is not UTF-8: {exc}"
        ) from exc
    try:
        manifest = json.loads(raw)
    except (ValueError, RecursionError, MemoryError) as exc:
        raise WptError(
            f"snapshot manifest {manifest_path} is not valid JSON: {exc}"
        ) from exc
    if not isinstance(manifest, dict):
        raise WptError(f"snapshot manifest {manifest_path} is not an object")
    if manifest.get("format") != MANIFEST_FORMAT:
        raise WptError(
            f"{snapshot_dir} is not a {MANIFEST_FORMAT} snapshot "
            f"(format={manifest.get('format')!r})"
        )
    if manifest.get("version") != MANIFEST_VERSION:
        raise WptError(
            f"snapshot {snapshot_dir} has unsupported version "
            f"{manifest.get('version')!r}"
        )
    if manifest.get("kind") not in KINDS:
        raise WptError(
            f"snapshot {snapshot_dir} has unknown kind "
            f"{manifest.get('kind')!r}"
        )

    recorded = manifest.get("webroot")
    expected = ctx.webroot or ""
    if not isinstance(recorded, str):
        raise WptError(
            f"snapshot {snapshot_dir} does not record its webroot; refusing "
            "the restore (every route requires the current site identity)"
        )
    if recorded != expected:
        raise WptError(
            f"snapshot {snapshot_dir} was taken for webroot "
            f"{recorded!r}, not {ctx.webroot!r}; refusing to "
            "restore it"
        )
    recorded_site = manifest.get("site_raw")
    if not isinstance(recorded_site, str) or not recorded_site:
        raise WptError(
            f"snapshot {snapshot_dir} does not record its raw site label; "
            "refusing the restore (every route requires the current site "
            "identity)"
        )
    if not _identity_matches(recorded_site, _site_identity(ctx)):
        # Two raw labels can sanitize to the same directory component
        # (bücher.example and b-cher.example both become b-cher.example).
        # The manifest records the RAW label so no snapshot can restore a
        # different site's bytes just because the webroot happened to
        # match.  The comparison is EXACT: `www.example.com` and
        # `example.com` are different identities.
        raise WptError(
            f"snapshot {snapshot_dir} belongs to site {recorded_site!r}, "
            f"not {_site_identity(ctx)!r}; refusing a cross-site restore"
        )

    records = manifest.get("files")
    if not isinstance(records, list):
        raise WptError(f"snapshot manifest {manifest_path} has no files list")
    max_files = _max_files(ctx)
    if len(records) > max_files:
        raise WptError(
            f"snapshot {snapshot_dir} carries {len(records)} file(s), over "
            f"files.max_files={max_files}"
        )

    entries: list[_SnapshotEntry] = []
    seen: set[str] = set()
    for record in records:
        _check(deadline, "restore snapshot record")
        if not isinstance(record, dict):
            raise WptError(f"snapshot manifest {manifest_path} has a bad file record")
        path = _safe_rel(record.get("path"))
        key = path.casefold()
        if key in seen:
            raise WptError(f"snapshot manifest repeats path {path!r}")
        seen.add(key)
        if is_wpt_endpoint_file(path):
            raise WptError(
                f"snapshot manifest holds wpt token endpoint {path!r}; "
                "refusing to restore it (a snapshot must never re-arm a "
                "bridge/probe) [L59]"
            )
        if _is_protected(path):
            raise WptError(
                f"refusing to restore protected WordPress path {path!r}; "
                "use heal-core/harden/deploy for core/config files"
            )
        exists = record.get("exists")
        if not isinstance(exists, bool):
            raise WptError(f"snapshot record {path!r} has a non-boolean exists")
        size = record.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise WptError(f"snapshot record {path!r} has a bad size")
        if size > max_bytes:
            raise WptError(
                f"snapshot record {path!r} is {size} bytes, over "
                f"files.max_file_bytes={max_bytes}"
            )

        if not exists:
            if record.get("sha256") is not None or record.get("stored") is not None:
                raise WptError(
                    f"snapshot record {path!r} is absent but carries stored "
                    "bytes"
                )
            entries.append(_SnapshotEntry(path=path, exists=False))
            continue

        sha = record.get("sha256")
        if not isinstance(sha, str) or not _SHA256_RE.match(sha):
            raise WptError(f"snapshot record {path!r} has a bad sha256")
        stored = _stored_path(record.get("stored"), path)
        # Version 1's stored hierarchy is part of the contract, not an
        # arbitrary pointer: a tampered manifest must not restore one
        # file's bytes under another file's name.
        if stored != f"{FILES_DIR}/{path}":
            raise WptError(
                f"snapshot record {path!r} has stored {stored!r}; "
                f"expected {FILES_DIR}/{path!r}"
            )
        _check(deadline, "restore stored bytes")
        try:
            data = read_regular_bounded(
                Path(stored), max_bytes, f"stored bytes for {path!r}",
                root=snapshot_dir)
        except WptError:
            raise
        except OSError as exc:
            raise WptError(
                f"cannot read stored bytes for {path!r}: {exc}"
            ) from exc
        if len(data) != size:
            raise WptError(
                f"snapshot record {path!r} stored bytes are {len(data)}, "
                f"expected {size}"
            )
        digest = _sha256(data)
        if digest != sha:
            raise WptError(
                f"snapshot record {path!r} SHA-256 mismatch: stored {digest}, "
                f"manifest {sha}"
            )
        entries.append(_SnapshotEntry(
            path=path, exists=True, size=size, sha256=sha, stored=stored,
            data=data,
        ))

    return _Snapshot(
        path=snapshot_dir,
        kind=manifest["kind"],
        webroot=recorded,
        entries=entries,
    )


def _stored_path(value: Any, path: str) -> str:
    """Validate the manifest's ``stored`` value as a snapshot-relative path."""
    if not isinstance(value, str) or not value:
        raise WptError(f"snapshot record {path!r} has no stored file")
    rel = value.replace("\\", "/")
    if rel.startswith("/") or _DRIVE_RE.match(rel) or "\x00" in rel:
        raise WptError(f"snapshot record {path!r} has an unsafe stored path")
    if any(_bad_segment(segment) for segment in rel.split("/")):
        raise WptError(f"snapshot record {path!r} has an unsafe stored path")
    return posixpath.normpath(rel)


# ----------------------------------------------------------- transaction


def _transaction_dirs(desired: list[_State]) -> list[str]:
    """Every directory prefix a target's parent chain may create, shallow first."""
    directories: set[str] = set()
    for want in desired:
        parent = posixpath.dirname(want.path)
        while parent:
            directories.add(parent)
            parent = posixpath.dirname(parent)
    return sorted(directories, key=lambda path: (path.count("/"), path))


def _dir_presence(source: Source, directories: list[str]) -> dict[str, bool]:
    """``directory -> existed before this transaction`` (fail-closed).

    Presence is answered by the parent's OWN listing: a directory name in a
    successful listing is present; an absent name is absent; a listing that
    cannot be read proves nothing, so the directory is treated as PRE-EXISTING
    and rollback never removes it.  A child of a known-missing parent is
    missing too, without paying for a listing that must fail.
    """
    presence: dict[str, bool] = {}
    listings: dict[str, set[str] | None] = {}
    for directory in directories:
        parent = posixpath.dirname(directory)
        if parent and presence.get(parent) is False:
            presence[directory] = False
            continue
        if parent not in listings:
            try:
                listing = source.list_dir(parent)
            except (StopRequested, DeadlineExceeded):
                raise
            except Exception:  # noqa: BLE001 — unprovable = assume present
                listings[parent] = None
            else:
                listings[parent] = {
                    entry.path.casefold() for entry in listing
                    if entry.is_dir
                }
        names = listings[parent]
        presence[directory] = (
            True if names is None else directory.casefold() in names)
    return presence


def _remove_created_dirs(source: Source, created_dirs: list[str]) -> list[str]:
    """Remove transaction-created directories, deepest first; return problems.

    Removal is the NON-RECURSIVE ``Source.rmdir`` primitive, so a file that
    arrives after the transaction's last listing makes the host refuse
    (FTP 550) instead of being recursively deleted by this transaction.
    A directory that cannot be removed is left in place and reported as
    residue; this owner never descends into content it did not write.
    """
    problems: list[str] = []
    for directory in sorted(created_dirs,
                            key=lambda path: (path.count("/"), path),
                            reverse=True):
        try:
            parent_entries = source.list_dir(posixpath.dirname(directory))
        except (StopRequested, DeadlineExceeded):
            raise
        except Exception as exc:  # noqa: BLE001 — residue is reported
            problems.append(
                f"{directory}: created directory presence could not be "
                f"checked ({redact_text(str(exc))})")
            continue
        if not any(entry.is_dir
                   and entry.path.casefold() == directory.casefold()
                   for entry in parent_entries):
            continue  # the write failed before this directory was made
        try:
            # Non-recursive by contract: the host re-proves emptiness at
            # delete time.  A late writer's file survives and is reported.
            source.rmdir(directory)
        except (StopRequested, DeadlineExceeded):
            raise
        except Exception as exc:  # noqa: BLE001 — residue is reported
            problems.append(
                f"{directory}: created directory could not be removed "
                f"({redact_text(str(exc))})")
            continue
        try:
            parent_listing = source.list_dir(posixpath.dirname(directory))
        except Exception:  # noqa: BLE001 — removal was attempted; unknown
            continue
        if any(entry.is_dir and entry.path.casefold() == directory.casefold()
               for entry in parent_listing):
            problems.append(
                f"{directory}: created directory is still present after rmdir")
    return problems


def _apply_transaction(
    source: Source,
    snapshot: _Snapshot,
    desired: list[_State],
    max_bytes: int,
    deadline: Deadline | None = None,
) -> dict[str, str]:
    """Write every desired state, rolling back already-changed targets.

    The snapshot is the pre-change state.  Before each rename/delete the
    current target is re-read and compared to that snapshot: a concurrent
    editor aborts the run instead of being overwritten.  On any failure every
    target already changed is restored from the snapshot; surviving temp
    names are removed in ``finally`` (best-effort, never masking the primary
    error).  Returns ``path -> status`` for the report.
    """
    statuses: dict[str, str] = {}
    changed: list[tuple[_SnapshotEntry, _State]] = []
    temps: set[str] = set()
    #: Directories the forward write will CREATE via ensure_write_dir.  Track
    #: presence BEFORE the first write so rollback can remove only those this
    #: transaction made (and only after proving them empty).
    transaction_dirs = _transaction_dirs(desired)
    directory_presence = _dir_presence(source, transaction_dirs)
    created_dirs = [
        directory for directory in transaction_dirs
        if not directory_presence[directory]
    ]
    primary: BaseException | None = None
    try:
        for want in desired:
            _check(deadline, "files transaction")
            old = snapshot.by_path.get(want.path)
            if old is None:
                raise WptError(
                    f"internal snapshot is missing {want.path!r}"
                )
            current = _read_state(source, want.path, max_bytes,
                                  purpose="transaction", deadline=deadline)
            if not _same(current, old):
                raise WptError(
                    f"concurrent change detected on {want.path!r}: the target "
                    "no longer matches the pre-change snapshot; aborting"
                )
            if not want.exists:
                if current.exists:
                    # Register the in-flight mutation BEFORE the DELE: a
                    # server can apply it and still report a timeout; the
                    # rollback must restore this path even if the call
                    # raised before returning.
                    changed.append((old, want))
                    source.delete(want.path)
                    statuses[want.path] = "deleted"
                else:
                    statuses[want.path] = "unchanged"
                continue
            if _same(current, want):
                statuses[want.path] = "unchanged"
                continue
            # Same rule for the rename: register before the temp upload so
            # an applied-but-raised RNTO is still represented in the
            # rollback set.  If the mutation never landed, rollback sees
            # the old state and skips the restore.
            changed.append((old, want))
            _write_target(
                source, want.path, want.data, temps,
                expected=old, max_bytes=max_bytes, deadline=deadline,
            )
            statuses[want.path] = "written"
    except BaseException as exc:
        primary = exc
        try:
            # The budget that expired (and caused this failure) must not
            # suppress the restore: cleanup runs with the source's deadline
            # suspended, then the exact previous budget is restored.
            with source.deadline_suspended():
                problems = _rollback(
                    source, snapshot, changed, temps, max_bytes)
                directory_problems = _remove_created_dirs(
                    source, created_dirs)
        except (StopRequested, DeadlineExceeded) as cleanup_exc:
            # CLEANUP must never replace the failure that caused it.  The
            # same rule _cleanup_temps already follows: re-raise the stop
            # only when there is no primary failure; otherwise keep the
            # primary and record the incomplete cleanup beside it.
            if primary is None:
                raise
            log.warning(
                "files: cleanup stop (%s) did not mask the primary failure: %s",
                type(cleanup_exc).__name__, redact_text(str(primary)))
            problems = (
                f"cleanup stopped ({type(cleanup_exc).__name__}) before "
                "rollback finished")
            directory_problems = []
        if directory_problems:
            problems = "; ".join(
                part for part in (problems, "; ".join(directory_problems))
                if part)
        residue = (f"; unremoved temp file(s): {', '.join(sorted(temps))}"
                   if temps else "")
        if problems:
            raise WptError(
                f"{exc}; rollback incomplete ({problems}); snapshot kept at "
                f"{snapshot.path}{residue}"
            ) from exc
        if isinstance(exc, Exception):
            raise WptError(
                f"{exc}; rolled back {len(changed)} changed target(s) from "
                f"{snapshot.path}{residue}"
            ) from exc
        raise
    finally:
        try:
            # Temp residue is cleanup too: an expired run budget must not
            # leave the uploaded NEW bytes beside the target.
            with source.deadline_suspended():
                _cleanup_temps(source, temps)
        except (StopRequested, DeadlineExceeded) as cleanup_exc:
            # Cleanup is complete, but its stop/deadline must not mask a
            # primary failure already unwinding this transaction.  With no
            # primary failure the stop IS the run-ending event: propagate.
            if primary is None:
                raise
            log.warning(
                "files: cleanup stop (%s) did not mask the primary failure: %s",
                type(cleanup_exc).__name__, redact_text(str(primary)))
    if temps:
        raise WptError(
            "the transaction committed but left temp file(s) that could "
            "not be removed: " + ", ".join(sorted(temps))
        )
    return statuses


def _write_target(
    source: Source, path: str, data: bytes | None, temps: set[str], *,
    expected: _State | _SnapshotEntry | None = None,
    max_bytes: int | None = None,
    deadline: Deadline | None = None,
) -> None:
    """Sibling temp -> write -> read-back -> rename into ``path``.

    ``expected`` (the snapshot state) turns this into the transaction's
    checked write: the target is re-read ONCE MORE immediately before the
    rename, because the temp upload takes time and a concurrent editor must
    never be overwritten silently.  Rollback passes the state the failed
    transaction WROTE as ``expected`` (its ``want``): an editor who saved
    after the failure changed it again, and that is a conflict, not lost
    bytes.
    """
    if data is None:
        raise WptError(f"no bytes to write for {path!r}")
    temp = _temp_sibling(source, path)
    temps.add(temp)
    source.write_bytes(temp, data)
    try:
        # The read-back compares EXACTLY the bytes just written, so it is
        # bounded by that length — never by a listing size that could lie.
        back = source.read_bytes_bounded(temp, len(data))
    except (SourceError, OSError) as exc:
        raise WptError(
            f"could not read back temp {temp!r} for {path!r}: {exc}"
        ) from exc
    if back != data:
        raise WptError(
            f"temp read-back mismatch for {path!r}: the uploaded bytes do "
            "not match the local body"
        )
    if expected is not None:
        if max_bytes is None:
            raise WptError(
                f"internal: no byte bound for the checked write of {path!r}"
            )
        current = _read_state(source, path, max_bytes, purpose="transaction",
                              deadline=deadline)
        if not _same(current, expected):
            raise WptError(
                f"concurrent change detected on {path!r}: the target no "
                "longer matches the pre-change snapshot; aborting"
            )
    source.rename(temp, path)
    temps.discard(temp)


def _temp_sibling(source: Source, path: str) -> str:
    """A unique sibling temp name; retries while the name is taken."""
    directory = posixpath.dirname(path)
    base = posixpath.basename(path)
    for _ in range(_COLLISION_ATTEMPTS):
        temp = posixpath.join(
            directory, f".{base}.wpt-edit-{secrets.token_hex(4)}.tmp"
        )
        if not presence_proven(source, temp):
            return temp
    raise WptError(f"could not allocate a temp sibling for {path!r}")


def _rollback(
    source: Source,
    snapshot: _Snapshot,
    changed: list[tuple[_SnapshotEntry, _State]],
    temps: set[str],
    max_bytes: int,
) -> str:
    """Restore every changed target from the snapshot; return problem text.

    A target is restored only when its CURRENT state matches the state this
    transaction wrote (``want``).  If it already matches the snapshot
    (``old``), the mutation never landed and there is nothing to undo.  Any
    third state is a concurrent editor: leave it alone and report the
    conflict instead of overwriting their work.

    Cleanup deliberately does NOT take the run deadline: expiry is
    permanent, and a budget that ran out during the forward write would
    otherwise suppress EVERY restore (the site would stay half-changed).
    ``_apply_transaction`` wraps this call in ``source.deadline_suspended``,
    which detaches the source's OWN attached budget too (passing
    ``deadline=None`` here only skips the helper's checks) and restores it
    afterwards.  Each network operation keeps its transport's own timeout,
    and the number of targets is already bounded by files.max_files.  Likewise
    every restore write is the same checked write as the transaction
    (``expected``): an editor who saves during the rollback's temp upload
    is a conflict, never silently overwritten bytes.
    """
    problems: list[str] = []
    # The source's OWN attached budget is suspended for the whole restore:
    # a run deadline that expired during the forward write must not suppress
    # the undo (a budget passed as ``None`` to the helpers above only skips
    # their checks; FtpSource still enforces ``source.deadline``).  The
    # context manager restores the exact previous budget on every path.
    with source.deadline_suspended():
        for old, want in reversed(changed):
            try:
                current = _read_state(
                    source, old.path, max_bytes, purpose="rollback",
                    deadline=None,
                )
                if _same(current, old):
                    continue
                if not _same(current, want):
                    problems.append(
                        f"{old.path}: changed concurrently during rollback; "
                        "left in place"
                    )
                    continue
                if old.exists:
                    _write_target(source, old.path, old.data, temps,
                                  expected=want, max_bytes=max_bytes,
                                  deadline=None)
                elif current.exists:
                    source.delete(old.path)
            except Exception as exc:
                problems.append(f"{old.path}: {redact_text(str(exc))}")
    if problems:
        log.warning(
            "files: rollback incomplete for %d target(s); snapshot kept at %s",
            len(problems), snapshot.path,
        )
    return "; ".join(problems)


def _cleanup_temps(source: Source, temps: set[str]) -> None:
    """Remove surviving temps; keep a failed name in ``temps`` for report.

    The set is the run's record of residue.  The delete is attempted
    UNCONDITIONALLY (doctor D-CLEAN's rule): ``Source.exists`` may map a
    lookup failure to False (FtpSource does), and trusting it left a temp
    holding the NEW bytes on the server with no warning (FILE2).  A failed
    delete discards the name only when a successful parent listing proves
    the file is gone; otherwise it stays for the report.

    A cooperative stop/deadline raised by a delete does not abandon the
    remaining temps: every name is attempted (each is the run's residue),
    then the FIRST stop/deadline is re-raised so the caller can end the run.
    """
    first_stop: StopRequested | DeadlineExceeded | None = None
    for temp in list(temps):
        try:
            source.delete(temp)
        except (StopRequested, DeadlineExceeded) as exc:
            if first_stop is None:
                first_stop = exc
            continue
        except Exception as exc:
            gone = False
            try:
                gone = absence_proven(source, temp)
            except (StopRequested, DeadlineExceeded) as stop_exc:
                if first_stop is None:
                    first_stop = stop_exc
                continue
            except Exception:
                gone = False
            if gone:
                temps.discard(temp)
                log.debug("files: temp %s was already absent after a failed "
                          "delete", redact_text(temp))
                continue
            log.warning("files: could not remove temp %s: %s",
                        redact_text(temp), redact_text(str(exc)))
            continue
        temps.discard(temp)
    if first_stop is not None:
        log.warning("files: temp cleanup stopped with %d temp(s) remaining: %s",
                    len(temps), redact_text(str(first_stop)))
        raise first_stop


def _same(left: _State | _SnapshotEntry, right: _State | _SnapshotEntry) -> bool:
    """Two states describe the same file (existence + size + SHA-256)."""
    if left.exists != right.exists:
        return False
    if not left.exists:
        return True
    return left.size == right.size and left.sha256 == right.sha256


# ------------------------------------------------------------- path guards


#: Windows device names (case-insensitive, reserved even with an extension).
#: A base segment that folds to one of these is a device alias on a Windows
#: FTP host, not a regular file: ``CON``, ``NUL``, ``COM1.txt``, ``LPT9``...
_RESERVED_WINDOWS_NAMES = frozenset(
    {"con", "prn", "aux", "nul", "clock$"}
    | {f"com{digit}" for digit in "123456789¹²³"}
    | {f"lpt{digit}" for digit in "123456789¹²³"}
)


def _bad_segment(segment: str) -> bool:
    """A segment Windows and POSIX could normalize differently/unsafely.

    POSIX accepts ``.. `` / ``wp-config.php.`` / ``WP-CONFIG.PHP`` as
    distinct names; a Windows FTP server folds the first two to ``..`` /
    ``wp-config.php`` and the last by case.  The files command is the one
    writer whose whole promise is a recoverable change, so it refuses the
    alias shapes before the Source guard sees them.  ``:`` also covers NTFS
    alternate data streams and drive syntax; C0/DEL/surrogates would reach
    ``ftplib.putline`` (or a local snapshot path) as an encoding error.
    Windows device names (``NUL``, ``CON``, ``COM1.txt``...) are aliases even
    with an extension, so their stem is matched after stripping trailing
    dots/spaces and casefolding.
    """
    if segment in ("", ".", ".."):
        return True
    if segment != segment.rstrip(" ."):
        return True
    if ":" in segment:
        return True
    if any(ord(char) < 32 or ord(char) == 127
           or 0xD800 <= ord(char) <= 0xDFFF for char in segment):
        return True
    stem = segment.split(".", 1)[0].rstrip(" ").casefold()
    return stem in _RESERVED_WINDOWS_NAMES


def _safe_rel(value: Any) -> str:
    """Normalize a webroot-relative path and reject every unsafe shape."""
    if not isinstance(value, str) or not value:
        raise WptError("a files target must be a non-empty string")
    raw = value.replace("\\", "/")
    if "\x00" in raw:
        raise WptError(f"unsafe files target rejected: {value!r}")
    if raw.startswith("/") or _DRIVE_RE.match(raw):
        raise WptError(f"absolute files target rejected: {value!r}")
    if any(_bad_segment(segment) for segment in raw.split("/")):
        raise WptError(f"unsafe files target rejected: {value!r}")
    norm = posixpath.normpath(raw)
    if norm in ("", ".", "..") or norm.startswith(("../", "/")):
        raise WptError(f"unsafe files target rejected: {value!r}")
    return norm


def _is_protected(path: str) -> bool:
    """The apply/edit/restore boundary (backup may still READ these).

    Case-folded so a case-insensitive remote cannot turn ``WP-CONFIG.PHP``
    into the protected name; every ``.htaccess`` (not only the webroot one)
    is configuration and stays write-refused.
    """
    norm = path.casefold()
    if posixpath.basename(norm) == ".htaccess":
        return True
    protected = {item.casefold() for item in Source.PROTECTED}
    if norm in protected:
        return True
    if norm.startswith(("wp-admin/", "wp-includes/")):
        return True
    return norm == "index.php"


def _validate_targets(
    ctx: "Ctx", paths: list[Any], *, protect: bool, label: str
) -> list[str]:
    """Normalize, bound and de-duplicate the named targets."""
    if not paths:
        raise WptError(f"{label} requires at least one path")
    max_files = _max_files(ctx)
    if len(paths) > max_files:
        raise WptError(
            f"{label}: {len(paths)} path(s) exceed files.max_files={max_files}"
        )
    out: list[str] = []
    seen: set[str] = set()
    for value in paths:
        rel = _safe_rel(value)
        key = rel.casefold()
        if key in seen:
            raise WptError(f"{label}: duplicate path {rel!r}")
        seen.add(key)
        if is_wpt_endpoint_file(rel):
            # A token endpoint is wpt's own live credential, never site
            # content: archiving it outlives the token, and restore would
            # re-arm it (L59).  Backup/restore enforce the same predicate.
            raise WptError(
                f"{label}: refusing {rel!r}: it is a wpt token endpoint "
                "(bridge or probe), not site content"
            )
        if protect and _is_protected(rel):
            raise WptError(
                f"{label}: refusing protected WordPress path {rel!r}; use "
                "heal-core/harden/deploy for core/config files"
            )
        out.append(rel)
    return out


# --------------------------------------------------------------- reading


def _read_state(
    source: Source, path: str, max_bytes: int, *, purpose: str,
    deadline: Deadline | None = None,
) -> _State:
    """Read one target once, bounded, with a clear error before any write."""
    _check(deadline, f"files {purpose} read")
    try:
        present = presence_proven(source, path)
    except (StopRequested, DeadlineExceeded):
        raise
    except (WptError, OSError) as exc:
        raise WptError(
            f"cannot check {purpose} target {path!r}: {exc}"
        ) from exc
    if not present:
        # Source.exists() is the owner's answer, but FtpSource maps a
        # non-channel SourceError to False.  Absence is only accepted when a
        # SUCCESSFUL listing proves it: either the parent lists and does not
        # contain the path, or a chain of successful listings proves the
        # parent itself is missing (the new-file case).  A failed listing —
        # transport, denied, or a dead channel — proves nothing and must
        # abort, never snapshot/overwrite a file as "absent".
        if absence_proven(source, path):
            return _State(path, False)
        raise WptError(
            f"source reported {purpose} target {path!r} absent but its "
            "parent listing contains it; refusing to guess"
        )
    try:
        size = source.size(path)
    except (SourceError, OSError) as exc:
        raise WptError(
            f"cannot size {purpose} target {path!r}: {exc}"
        ) from exc
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise WptError(
            f"{purpose} target {path!r} reported an invalid size {size!r}"
        )
    if size > max_bytes:
        raise WptError(
            f"{purpose} target {path!r} is {size} bytes, over "
            f"files.max_file_bytes={max_bytes}"
        )
    try:
        # Bounded at the Source: a lying SIZE (or a file that grows between
        # the size check and the read) stops at max_bytes + 1 instead of
        # materializing the whole body and refusing afterwards.
        data = source.read_bytes_bounded(path, max_bytes)
    except (SourceError, OSError) as exc:
        raise WptError(
            f"cannot read {purpose} target {path!r} as a regular file: {exc}"
        ) from exc
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise WptError(
            f"cannot read {purpose} target {path!r}: the source returned "
            f"{type(data).__name__}, not bytes"
        )
    data = bytes(data)
    if len(data) > max_bytes:
        raise WptError(
            f"{purpose} target {path!r} is {len(data)} bytes, over "
            f"files.max_file_bytes={max_bytes}"
        )
    return _State(path, True, len(data), _sha256(data), data)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# -------------------------------------------------------------- snapshots


def _create_snapshot(
    ctx: "Ctx", kind: str, states: list[_State],
    deadline: Deadline | None = None,
) -> _Snapshot:
    """Build a snapshot in a temp dir, then atomically rename it into place."""
    if kind not in KINDS:
        raise WptError(f"unknown snapshot kind {kind!r}")
    label = sanitize_site_label(_site_identity(ctx))
    try:
        site_dir = open_private_site_dir(Path(ctx.backup_dir), label)
    except WptError:
        raise
    except OSError as exc:
        raise WptError(f"cannot create backup directory {_site_dir(ctx)}: {exc}") from exc
    sweep_stale_snapshot_temps(
        site_dir, ctx.settings.backup, deadline=deadline)

    now = datetime.now(timezone.utc)
    # Journal the candidate BEFORE creating it: mkdtemp created the
    # ``.files-*`` directory first and returned its name afterwards, so a
    # stop on that boundary left an untracked directory no finally could
    # remove.  ``tmp`` is set before the mkdir and the whole creation sits
    # inside the cleanup try.
    tmp: Path | None = None
    final: Path | None = None
    try:
        for _ in range(100):
            candidate = site_dir / f".files-{secrets.token_hex(16)}"
            tmp = candidate
            try:
                os.mkdir(candidate, 0o700)
            except FileExistsError:
                tmp = None
                continue
            break
        if tmp is None:
            raise WptError(
                f"cannot reserve a files snapshot directory under {site_dir}")
        os.chmod(tmp, 0o700)
        entries: list[dict[str, Any]] = []
        files_root = tmp / FILES_DIR
        for state in states:
            _check(deadline, "files snapshot capture")
            if not state.exists:
                entries.append({
                    "path": state.path,
                    "exists": False,
                    "size": 0,
                    "sha256": None,
                    "stored": None,
                })
                continue
            if state.data is None:
                raise WptError(
                    f"cannot snapshot {state.path!r}: captured bytes are absent"
                )
            dest = files_root / state.path
            if not _inside(dest, tmp):
                raise WptError(
                    f"refusing to store {state.path!r} outside the snapshot"
                )
            dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            private_dir_chain(dest.parent, tmp)
            write_private_bytes(dest, state.data)
            entries.append({
                "path": state.path,
                "exists": True,
                "size": len(state.data),
                "sha256": _sha256(state.data),
                "stored": f"{FILES_DIR}/{state.path}",
            })

        manifest = {
            "format": MANIFEST_FORMAT,
            "version": MANIFEST_VERSION,
            "kind": kind,
            "created": now.isoformat(),
            "site": label,
            "site_raw": _site_identity(ctx),
            "source": safe_source_label(ctx.source or "unknown"),
            "webroot": ctx.webroot or "",
            "files": entries,
        }
        tmp_manifest = tmp / f"{MANIFEST_NAME}.tmp"
        payload = (
            json.dumps(manifest, ensure_ascii=True, sort_keys=True,
                       indent=2) + "\n"
        ).encode("utf-8")
        # ONE size contract: the manifest READER caps at
        # backup.MANIFEST_MAX_BYTES, so the writer must never emit a
        # manifest its own restore refuses (a 5000-target run did).
        if len(payload) > MANIFEST_MAX_BYTES:
            raise WptError(
                f"snapshot manifest would be {len(payload)} bytes, over "
                f"MANIFEST_MAX_BYTES ({MANIFEST_MAX_BYTES}); reduce the "
                "target count for this snapshot")
        write_private_bytes(tmp_manifest, payload)
        os.replace(tmp_manifest, tmp / MANIFEST_NAME)

        final = _snapshot_name(site_dir, kind, now)
        os.replace(tmp, final)
    except BaseException as exc:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)
            if tmp.exists():
                log.error(
                    "files: could not remove partial snapshot dir %s", tmp)
        if isinstance(exc, (ValueError, TypeError)):
            raise WptError(f"snapshot failed: {exc}") from exc
        raise

    snapshot = _Snapshot(
        path=final,
        kind=kind,
        webroot=ctx.webroot or "",
        entries=[
            _SnapshotEntry(
                path=entry["path"],
                exists=entry["exists"],
                size=entry["size"],
                sha256=entry["sha256"],
                stored=entry["stored"],
                data=(state.data if entry["exists"] else None),
            )
            for entry, state in zip(entries, states)
        ],
    )
    log.info("files: %s snapshot at %s", kind, final)
    # A snapshot this run CREATED is a protected input for the rest of the
    # run (files' own report/failure writer must never land inside it).
    # NEVER overwrite an already-selected snapshot (files --restore):
    # the selected root stays ``snapshot_dir`` and BOTH roots accumulate
    # in ``snapshot_roots`` so the writer protects the selected payloads
    # and the rollback basis.
    try:
        ctx.extra.setdefault("snapshot_dir", str(final))
    except (AttributeError, TypeError):
        pass
    record_snapshot_root(ctx, final)
    return snapshot


def _snapshot_name(site_dir: Path, kind: str, now: datetime) -> Path:
    """A free ``<kind>-<UTC>-<6 hex>`` directory name (collision-retried)."""
    stamp = now.strftime(_STAMP_FORMAT)
    for _ in range(_COLLISION_ATTEMPTS):
        candidate = site_dir / f"{kind}-{stamp}-{secrets.token_hex(3)}"
        if not candidate.exists():
            return candidate
    raise WptError(f"could not allocate a snapshot name under {site_dir}")


def _check(deadline: Deadline | None, context: str) -> None:
    if deadline is not None:
        deadline.check(context)


def _inside(path: Path, root: Path) -> bool:
    try:
        return path.resolve().is_relative_to(root.resolve())
    except OSError:
        return False


# ---------------------------------------------------------------- report


def _site(ctx: "Ctx") -> str:
    """A redacted site label that never raises on a malformed source URL.

    Rendering only: the snapshot directory and manifest ``site_raw`` use
    :func:`_site_identity`, because redaction is LOSSY and two credential-
    bearing labels could otherwise share one directory and cross-restore.
    """
    try:
        return redact_text(_site_identity(ctx))
    except (TypeError, ValueError):
        fallback = ctx.wp_url or ctx.webroot or ctx.source or "site"
        return redact_text(fallback)


def _site_identity(ctx: "Ctx") -> str:
    """The EXACT raw site identity recorded in a files manifest/directory.

    No normalizer: ``www.site.test`` and ``site.test`` are different identities,
    original case is preserved, and a credential-bearing label is never
    redacted for identity.  The string still distinguishes labels that
    sanitize to one directory component (``bücher.example`` vs
    ``b-cher.example``).
    """
    return site_label(ctx)


def _max_files(ctx: "Ctx") -> int:
    return ctx.settings.files.max_files


def _max_file_bytes(ctx: "Ctx") -> int:
    return ctx.settings.files.max_file_bytes


def _facts(value: _State | _SnapshotEntry) -> str:
    """A bounded SHA/size cell (full hashes stay in the JSON twin)."""
    if not value.exists:
        return "absent"
    digest = value.sha256 or ""
    return f"{human_bytes(value.size)} · sha {digest[:12]}"


def _row_for(
    want: _State, current: _State | _SnapshotEntry, *,
    action: str, status: str,
) -> _Row:
    return _Row(
        path=want.path,
        action=action,
        current=_facts(current),
        desired=_facts(want),
        status=status,
        exists=want.exists,
        size=want.size,
        sha256=want.sha256,
    )


def _totals(rows: list[_Row]) -> dict[str, int]:
    return {
        "files": len(rows),
        "present": sum(1 for row in rows if row.exists),
        "absent": sum(1 for row in rows if not row.exists),
        "captured": sum(1 for row in rows if row.status == "captured"),
        "written": sum(1 for row in rows if row.status == "written"),
        "deleted": sum(1 for row in rows if row.status == "deleted"),
        "unchanged": sum(1 for row in rows if row.status == "unchanged"),
        "planned": sum(1 for row in rows if row.status == "planned"),
        "bytes": sum(row.size for row in rows if row.exists),
    }


def _render(result: _Result) -> str:
    lines = [
        f"# wpt files — {result.site}",
        "",
        f"Mode: {result.mode}",
        f"Snapshot: {result.snapshot or '—'}",
    ]
    if result.mode != "backup":
        lines.append(f"Applied: {'yes' if result.applied else 'no'}")
    lines.extend([
        "",
        "| path | action | current | desired | status |",
        "|---|---|---|---|---|",
    ])
    for row in result.rows:
        lines.append(
            "| {} | {} | {} | {} | {} |".format(
                md_escape(redact_text(row.path)),
                row.action,
                row.current,
                row.desired,
                row.status,
            )
        )
    lines.extend([
        "",
        (f"Totals: {result.totals['files']} file(s), "
         f"{human_bytes(result.totals['bytes'])}"),
    ])
    if result.note:
        lines.extend(["", redact_text(result.note)])
    return "\n".join(lines).rstrip("\n") + "\n"


def _json_text(result: _Result) -> str:
    payload = {
        "command": "files",
        "mode": result.mode,
        "site": result.site,
        "snapshot": str(result.snapshot) if result.snapshot else None,
        "applied": result.applied,
        "files": [
            {
                "path": redact_text(row.path),
                "action": row.action,
                "exists": row.exists,
                "size": row.size,
                "sha256": row.sha256,
                "status": row.status,
            }
            for row in result.rows
        ],
        "totals": result.totals,
        "note": redact_text(result.note),
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def _write_failure(
    ctx: "Ctx", mode: str, reason: str, *, status: str = "failed"
) -> None:
    """Write the report of a run that did not complete (best effort).

    Called on every failed/refused run, with or without ``--report``: the
    shared writer is a no-op without a path, so a test or an embedding
    caller always sees the one contract point (and a broken writer can
    never mask the run's rc).
    """
    try:
        kwargs: dict[str, Any] = {
            "audit": AuditReport(
                site=_site(ctx),
                source_summary=(
                    f"files ({mode}) — the run did not complete"
                ),
            ),
            "title": "wpt files",
        }
        if status != "failed":
            kwargs["status"] = status
        write_failure_report(ctx, "files", reason, **kwargs)
    except (Exception, RunControl) as exc:  # reporting must never mask
        log.warning("files: could not write the failure report: %s",
                    redact_text(str(exc)))
