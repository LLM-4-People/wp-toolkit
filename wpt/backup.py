"""Pre-action snapshots — the reversibility substrate for every mutating action.

Layout (SPEC §backup; LOCAL disk, never inside the webroot [L1])::

    <backup_dir>/<site_label>/<YYYYmmdd-HHMMSS>[-N]/
        manifest.json          THE format `wpt restore` consumes (below)
        files/<target>         captured file bytes, webroot hierarchy preserved
        db/<table>.ndjson      per-table dump stream, one JSON object per line

``<site_label>`` is sanitized to ONE path component by :func:`sanitize_site_label`
(every character outside ``[A-Za-z0-9._-]`` becomes ``-``; the only regex-unchanged
forms that are unsafe as a path component — ``""``, ``"."``, ``".."`` — become
``"-"``, ``"-"``, ``"--"``). The sanitized form is what the manifest's ``site``
field records, so restore finds the same directory from the same host label.

``<YYYYmmdd-HHMMSS>[-N]`` is the LOCAL timestamp of the snapshot, so directory
name order == creation order; ``-N`` (N = 2, 3, ...) disambiguates snapshots that
collide within one second. Ordering rule: ascending by (timestamp parsed from
the name, suffix int; no suffix == 0).

manifest.json (UTF-8 JSON, indent 2) — the EXACT schema restore consumes::

    {
      "format": "wpt-backup-manifest",
      "version": 1,
      "site": "<sanitized site_label — the on-disk path component>",
      "site_raw": "<raw site label — one current identity key>",
      "webroot": "<webroot the captured bytes belong to — the other key>",
      "action": "<action name that triggered the snapshot>",
      "created": "<ISO 8601 with local UTC offset, e.g. 2026-09-15T10:30:05.123456-04:00>",
      "wpt_version": "<importlib.metadata version of wpt, or 'dev' if not installed>",
      "files": [        # in target order; one entry per requested target
                         # that was CAPTURED or ABSENT — a present target
                         # that fails to READ fails the whole snapshot
                         # closed (a hole in the reversibility substrate
                         # is never silently skipped; see create_snapshot)
        {"path": "<webroot-relative POSIX>", "absent": false,
         "sha256": "<hex of the captured bytes>", "size": <int>},
        {"path": "<webroot-relative POSIX>", "absent": true}
        # ^ target not on the source: NOTHING was captured and restore must
        #   NOT recreate it (deleting a not-yet-existing file stays reversible
        #   as "still absent"). No sha256/size keys on absent entries.
      ],
      "tables": [       # in requested-table order
        {"name": "<table>", "rows": <int from the stream's done line>,
         "sha256": "<hex of db/<name>.ndjson>", "size": <ndjson byte count>}
      ],
      "totals": {"files": <captured count>, "absent": <absent target count>,
                 "tables": <table count>, "bytes": <payload bytes: files + ndjson>}
    }

NDJSON disk rule (``db/<table>.ndjson``) — EXACT, byte-for-byte replayable:
each line is one ``db_dump`` stream object, re-serialized as strict JSON
(compact separators ``(",", ":"``), UTF-8, ``allow_nan=False``), in stream
order::

    {"table":<name>,"create":"<SHOW CREATE TABLE output>"}   # first line
    {"table":<name>,"row":[<cell>,...]}                      # one per row
    {"table":<name>,"done":<row count>}                      # last line

Every ``bytes`` cell ANYWHERE in an object is encoded as the bridge's wire
pair ``["__wpt_b64__", "<base64 of the bytes>"]`` — the exact inverse of
``Bridge._decode_cells`` — because ``call_stream`` has already decoded the
wire markers into Python ``bytes``. Restore replays a line with one rule:
JSON-parse it, then recursively convert every 2-element array whose first
element is ``"__wpt_b64__"`` back to ``bytes(base64)``. The disk form is thus
identical to the bridge wire form, including its single documented ambiguity
(a genuine string cell that is literally a 2-element marker array is
indistinguishable — same rule on both sides of the wire).

Fail-closed: ANY failure while capturing (source error mid-file — a
present target that cannot be read is a HOLE in the reversibility
substrate and aborts the snapshot; run-level raise out of the batched
reads — channel trip, expired run deadline — bridge error mid-dump,
disk error, wire anomaly) removes the partial snapshot
directory and re-raises — callers must treat the exception as "no backup
exists" and refuse to mutate.  A per-FILE read failure is NOT run-level:
the path lands in read_many's ``failed`` bucket and is skipped with one
debug log (no manifest entry, nothing captured) — the same per-file
read-failure semantics the audit checks use — so one unreadable file
among thousands cannot kill a whole snapshot.

Retention (:class:`~wpt.settings.BackupSettings`): after each snapshot,
:func:`prune` keeps the newest ``keep_last`` snapshots AND every snapshot
whose name timestamp is within ``keep_days`` days of now; everything else is
removed oldest-first (one info log line per removal). Directories whose name
is not ``<YYYYmmdd-HHMMSS>[-N]`` are never touched.
"""

import base64
import hashlib
import importlib.metadata
import json
import os
import posixpath
import re
import shutil
import stat
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .audit import remote_stack
from .config import redact_text
from .dbstream import TableStream
from .deadline import Deadline, check_deadline, transport_kwargs
from .jsonutil import loads_bounded
from .log import get_logger
from .report import (human_bytes, record_snapshot_root,
                     report_protected_inputs, report_protected_subtrees,
                     write_report_files)
from .report import write_stdout
from .settings import BackupSettings
from .bridge_name import is_wpt_endpoint_file
from .types import (DeadlineExceeded, RunControl, Source, StopRequested,
                    WptError, presence_proven)
from .wpbridge.client import B64_MARKER, Bridge

if TYPE_CHECKING:
    from .cli import Ctx

__all__ = [
    "MANIFEST_NAME", "MANIFEST_FORMAT", "MANIFEST_VERSION", "FILES_DIR",
    "DB_DIR", "SNAPSHOT_NAME_RE", "MANIFEST_MAX_BYTES",
    "read_regular_bounded", "read_snapshot_manifest", "SnapshotMeta",
    "sanitize_site_label", "site_label",
    "create_snapshot", "verify_snapshot", "prune", "run_backup",
    "open_private_site_dir", "private_dir_chain",
    "write_private_bytes",
    "open_private_binary", "sweep_stale_snapshot_temps",
]

log = get_logger("backup")

#: Filename of the manifest inside every snapshot directory.
MANIFEST_NAME = "manifest.json"

#: Manifest identity fields — wpt/backup.py is the single owner; restore
#: imports these for its format gate.
MANIFEST_FORMAT = "wpt-backup-manifest"
MANIFEST_VERSION = 1
#: Subdirectory holding captured file payloads (webroot hierarchy preserved).
FILES_DIR = "files"
#: Subdirectory holding per-table ``<table>.ndjson`` dump streams.
DB_DIR = "db"
#: Hard cap for a manifest (the same 1 MiB ``wpt files`` uses).  A manifest
#: is metadata, not payload: an unbounded read let a FIFO block the command
#: and a huge/corrupt file exhaust memory (R6-24).
MANIFEST_MAX_BYTES = 1024 * 1024
#: Snapshot directory names: ``YYYYmmdd-HHMMSS`` with optional ``-N`` collision
#: suffix. Prune only ever touches directories matching this pattern; the
#: creation-order sort key is (parsed timestamp, suffix int; none == 0).
SNAPSHOT_NAME_RE = re.compile(r"^(\d{8}-\d{6})(?:-(\d+))?$")

#: Hidden capture temp shapes this module owns:
#: ``.<stamp>-N.tmp`` (wpt backup) and ``.files-*`` (wpt files).  Anything
#: else in the site dir is never a sweep candidate.
_TEMP_SNAPSHOT_RE = re.compile(r"^\.\d{8}-\d{6}(?:-\d+)?\.tmp$")
_FILES_TEMP_PREFIX = ".files-"

_UNSAFE_LABEL_RE = re.compile(r"[^A-Za-z0-9._-]")

#: Heartbeat cadence of the file-capture loop: one info progress line every
#: this many CAPTURED files, strictly inside the capture (a milestone on the
#: last target is the success summary's job).  STRUCTURAL, not a settings
#: tunable: it sets log CADENCE, not behavior — no operator decision changes
#: what a snapshot captures — so the no-static-configurables rule stops at
#: the logging boundary.
_HEARTBEAT_EVERY = 500

#: Batch size of the file-capture loop: targets are chunked into batches
#: of this many webroot paths and fetched through ONE ``source.read_many``
#: call per batch.  STRUCTURAL, not a settings tunable: it bounds the
#: capture's in-flight memory (at most one batch of file payloads held at
#: a time) and sets the run-deadline check granularity (one
#: ``Deadline.check`` per batch — a pool trip or an expired budget ends
#: the capture between reads, never mid-read).  200 < _HEARTBEAT_EVERY
#: keeps progress observable between batch completions while keeping a
#: parallel FTP pool (ftp.parallel_reads workers) saturated.
_READ_BATCH = 200


def _casefold_collision(names) -> tuple[str, str] | None:
    """The first pair of distinct names that casefold to ONE name, or None.

    THE walk-to-snapshot boundary owner: a case-sensitive FTP host can
    legitimately list ``a.txt`` and ``A.txt`` (or MySQL can carry
    ``wp_posts`` and ``WP_POSTS``), but a restore plan addresses them as one
    path.  ``create_snapshot`` must keep rejecting that as a ValueError for
    programmatic callers; command/action bodies detect it HERE and answer a
    clean WptError (rc 1 + failure report) instead of letting a raw
    ValueError escape ``main`` as a traceback.
    """
    seen: dict[str, str] = {}
    for name in names:
        key = name.casefold()
        previous = seen.get(key)
        if previous is not None and previous != name:
            return previous, name
        seen[key] = name
    return None


def require_distinct_snapshot_names(names, kind: str) -> list[str]:
    """Return ``names`` sorted, refusing a casefold collision with WptError.

    ``kind`` only labels the refusal ("target"/"table").  Exact duplicates
    are deduped by the caller before this boundary; a casefold collision is
    never silently dropped because that would make the manifest claim a
    scope it cannot restore.
    """
    values = sorted(set(names))
    collision = _casefold_collision(values)
    if collision is not None:
        first, second = collision
        raise WptError(
            f"snapshot {kind} {first!r} and {second!r} differ only by case; "
            "a restore plan addresses them as one name, so the snapshot "
            "cannot be verified — refusing to create it"
        )
    return values


def require_snapshot_tables(names) -> list[str]:
    """The registry boundary's table list: sorted, distinct, and SAFE.

    ``create_snapshot`` still rejects an unsafe name internally, but its
    ``ValueError`` escaped the action error contract when a hostile/buggy
    bridge answered ``db_audit`` with a name like ``x/posts``: no rc-1
    report pair, only a traceback.  This ONE validator raises
    :class:`WptError` at the boundary, before any snapshot work.
    """
    values = require_distinct_snapshot_names(names, "table")
    for name in values:
        if not _table_name_ok(name):
            raise WptError(f"unsafe table name: {name!r}")
    return values


def _targets_exclude_bridges(entries, deadline=None, source=None) -> list[str]:
    """The snapshot's file list: every walked file EXCEPT a deployed wpt
    token endpoint (bridge or standalone PHP probe). One owner for the
    shapes (``bridge_name.is_wpt_endpoint_file``) and one place that drops
    them, so no future capture path can re-admit a token-authenticated
    script into an archive [L59/PROBE1].

    DEDUPED and normalized at this one walk-to-snapshot boundary: a source
    whose ``walk()`` repeats a path must not reach ``create_snapshot``'s
    duplicate-target guard as a raw ``ValueError`` (rc 0 report missing).
    Normalization is the source's OWN path guard (``./a.txt`` -> ``a.txt``)
    so two spellings of one FTP entry cannot become two targets.  The
    CONNECTOR-RETURNED door is used, not the operator one: a legal POSIX
    name containing a literal backslash must fail the snapshot closed
    rather than be rewritten to a different (usually absent) slash path --
    an ``absent: true`` manifest entry would claim the file never existed
    while leaving it uncaptured.  The deadline is checked per walked entry
    so a crawling walk ends the run instead of outliving the budget.
    """
    paths: set[str] = set()
    for entry in entries:
        if deadline is not None:
            deadline.check("backup walk")
        path = source._guard_returned_path(entry.path) if source is not None \
            else posixpath.normpath(entry.path)
        if not is_wpt_endpoint_file(path):
            paths.add(path)
    # Fail closed at THIS boundary: create_snapshot's ValueError is a
    # programmatic-API refusal, never a command/action answer.
    return require_distinct_snapshot_names(paths, "target")


def _wpt_version() -> str:
    try:
        return importlib.metadata.version("wpt")
    except importlib.metadata.PackageNotFoundError:
        return "dev"


_WPT_VERSION = _wpt_version()


def _now() -> datetime:
    """Snapshot clock (local, timezone-aware) — the seam tests pin."""
    return datetime.now().astimezone()


@dataclass
class SnapshotMeta:
    """Result of one snapshot: where it landed and how much it holds.

    ``files`` counts CAPTURED files only (absent targets are not files);
    ``bytes_written`` is the payload size (captured files + ndjson streams),
    identical to the manifest's ``totals.bytes``.
    """

    path: Path
    files: int
    tables: int
    bytes_written: int


#: Snapshot privacy modes (structural): a snapshot holds wp-config.php and
#: database bytes.  One owner for the permission policy, shared by the
#: backup writer and `wpt files`.
_PRIVATE_DIR_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600


def open_private_site_dir(backup_dir: Path, label: str) -> Path:
    """Create/open ``<backup-dir>/<site-label>`` WITHOUT following a link.

    ``--backup-dir`` is the caller's trust anchor (it may itself be a
    symlink).  The site-label component is derived from the site URL and is
    NOT trusted as a path: a planted ``<backup>/example.com -> victim``
    symlink made ``mkdir(exist_ok=True)`` + ``chmod`` write into and chmod
    the victim, and retention could then delete snapshots outside the
    backup tree.  ONE owner for both snapshot writers: open the directory
    with ``O_DIRECTORY|O_NOFOLLOW`` (created via a dir_fd first) and fchmod
    the descriptor.
    """
    backup_dir = Path(backup_dir)
    label = sanitize_site_label(label)
    backup_dir.mkdir(parents=True, exist_ok=True, mode=_PRIVATE_DIR_MODE)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) \
        | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        root_fd = os.open(backup_dir, flags & ~getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise WptError(
            f"cannot open backup directory {backup_dir}: {exc}") from exc
    try:
        try:
            os.mkdir(label, mode=_PRIVATE_DIR_MODE, dir_fd=root_fd)
        except FileExistsError:
            pass
        try:
            site_fd = os.open(label, flags, dir_fd=root_fd)
        except OSError as exc:
            raise WptError(
                f"snapshot site directory {backup_dir / label} is a "
                "symbolic link or not a directory; refusing to write "
                "through it") from exc
        try:
            os.fchmod(site_fd, _PRIVATE_DIR_MODE)
        finally:
            os.close(site_fd)
    finally:
        os.close(root_fd)
    return backup_dir / label


def _open_site_dir_no_follow(site_dir: Path) -> int:
    """Open one site-label directory for retention; links are refused.

    The returned fd is only used to LIST the directory (prune/sweep never
    need to follow the label), so a planted symlink cannot redirect a
    candidate scan or a removal outside ``--backup-dir``.
    """
    return os.open(
        site_dir,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )



def sweep_stale_snapshot_temps(site_dir: Path, settings: BackupSettings, *,
                               deadline: Deadline | None = None,
                               inspected: list[Path] | None = None) -> int:
    """Remove hidden capture temps left by a killed run; return the count.

    Only the two names this tool's capture paths create are candidates
    (``.<stamp>-N.tmp`` and ``.files-*``), and only when older than
    ``settings.stale_temp_age_s``: a recent temp may belong to a LIVE
    concurrent run, and deleting it would abort that run's capture.  A
    symlink is never followed or removed (it is not a directory we made).
    """
    try:
        dir_fd = _open_site_dir_no_follow(site_dir)
    except OSError as exc:
        # A symlinked site-label component is not a directory this tool
        # made; never list (or remove) through it.
        log.warning("snapshot temp sweep refused %s: %s",
                    site_dir, redact_text(str(exc)))
        return 0
    try:
        entries = [site_dir / name for name in os.listdir(dir_fd)]
    except OSError as exc:
        log.warning("snapshot temp sweep could not list %s: %s",
                    site_dir, redact_text(str(exc)))
        return 0
    finally:
        os.close(dir_fd)
    cutoff = time.time() - settings.stale_temp_age_s
    removed = 0
    for entry in entries:
        name = entry.name
        if not (_TEMP_SNAPSHOT_RE.match(name)
                or name.startswith(_FILES_TEMP_PREFIX)):
            continue
        if deadline is not None:
            deadline.check("snapshot temp sweep")
        if inspected is not None:
            inspected.append(entry)
        try:
            if entry.is_symlink() or not entry.is_dir():
                continue
            if entry.lstat().st_mtime > cutoff:
                continue  # may be a live concurrent capture
            shutil.rmtree(entry)
        except FileNotFoundError:
            continue
        except OSError as exc:
            log.warning("stale snapshot temp %s could not be removed: %s",
                        entry, redact_text(str(exc)))
            continue
        log.info("swept stale snapshot temp %s", entry)
        removed += 1
    return removed


def private_dir_chain(path: Path, stop: Path) -> None:
    """Force ``path`` and every ancestor up to ``stop`` to 0700.

    ``parents=True`` creates intermediate directories with the default
    umask, so the snapshot's nested payload tree (``files/wp-content/...``)
    needs each created level tightened explicitly.
    """
    current = path
    while True:
        os.chmod(current, _PRIVATE_DIR_MODE)
        if current == stop or current.parent == current:
            return
        current = current.parent


def write_private_bytes(path: Path, data: bytes) -> None:
    """Write one snapshot payload/manifest 0600, independent of umask."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                 _PRIVATE_FILE_MODE)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
    finally:
        os.close(fd)
    os.chmod(path, _PRIVATE_FILE_MODE)


def open_private_binary(path: Path):
    """Open a snapshot stream for writing, 0600 from the first byte."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                 _PRIVATE_FILE_MODE)
    try:
        os.chmod(path, _PRIVATE_FILE_MODE)
    except BaseException:
        os.close(fd)
        raise
    return os.fdopen(fd, "wb")


def sanitize_site_label(label: str) -> str:
    """Reduce a site label to ONE path-safe component.

    Every character outside ``[A-Za-z0-9._-]`` becomes ``-``; the only
    regex-unchanged results that would still be unsafe as a single path
    component (``""``, ``"."``, ``".."``) become ``"-"``, ``"-"``, ``"--"``.
    """
    cleaned = _UNSAFE_LABEL_RE.sub("-", label)
    if cleaned in ("", ".", ".."):
        cleaned = cleaned.replace(".", "-") or "-"
    return cleaned


def site_label(ctx: "Ctx") -> str:
    """The snapshot site label for one command run — the ONE authoritative
    derivation (the actions registry's auto-snapshots and the backup /
    restore CLI bodies share it): local mode is ``local:<zip name>``; ftp
    mode is the ``--wp-url`` hostname (the ftp URL's hostname as fallback).
    :func:`sanitize_site_label` makes it path-safe before any disk use.

    A malformed URL must not raise: ``urlparse`` raises ``ValueError`` for
    an invalid IPv6 literal (``http://[::1``), and a failure report or an
    ``--undo-last`` listing still needs a label.  The fallback is the
    webroot, then the generic ``"site"`` — never the raw URL, which may
    carry credentials.
    """
    if ctx.mode == "local":
        return f"local:{ctx.zip.name}" if ctx.zip else "local"
    from urllib.parse import urlparse

    try:
        host = urlparse(ctx.wp_url or ctx.source).hostname
    except (TypeError, ValueError):
        host = None
    return host or (ctx.webroot or "").strip("/") or "site"


def _is_safe_rel(path: object) -> bool:
    """True for a webroot-relative POSIX path that cannot escape its root."""
    if not isinstance(path, str) or not path:
        return False
    norm = posixpath.normpath(path.replace("\\", "/"))
    return not norm.startswith(("/", "..")) and norm not in ("", ".", "..")


def _table_name_ok(name: object) -> bool:
    """True for a table name that is safe both on disk and in the manifest."""
    return (
        isinstance(name, str)
        and name not in ("", ".", "..")
        and not any(c in name for c in ("/", "\\", "\x00"))
    )


def _remark_bytes(value: Any) -> Any:
    """Inverse of ``Bridge._decode_cells``: bytes -> ["__wpt_b64__", b64]."""
    if isinstance(value, bytes):
        return [B64_MARKER, base64.b64encode(value).decode("ascii")]
    if isinstance(value, list):
        return [_remark_bytes(v) for v in value]
    if isinstance(value, dict):
        return {k: _remark_bytes(v) for k, v in value.items()}
    return value


def _remove_empty_dir(directory: Path) -> None:
    """Remove ``directory`` if it happens to be empty (failure path only)."""
    try:
        directory.rmdir()
    except OSError:
        pass


def create_snapshot(
    source: Source | None,
    bridge: Bridge | None,
    site_label: str,
    targets: list[str],
    tables: list[str],
    backup_dir: Path,
    settings: BackupSettings,
    action: str,
    deadline: Any = None,
    *,
    site_raw: str,
    webroot: str,
    snapshot_roots: list[Path] | None = None,
) -> SnapshotMeta:
    """Snapshot ``targets`` (files) + ``tables`` (DB) for one mutating action.

    ``site_raw`` and ``webroot`` are REQUIRED current identity keys: the raw
    site label (before the lossy sanitizer that keys the directory) and the
    webroot the bytes belong to.  Every manifest records both unconditionally;
    there is no default and no identity fallback.  ``restore`` refuses any
    manifest missing either (a pre-identity snapshot is unsupported), so two
    docroots on one host and two labels that sanitize to one directory can
    never cross-restore.  A caller with no real identity must not create a
    managed snapshot.

    ``source``/``bridge`` may be None for file-only / DB-only actions, but
    targets require a source and tables require a bridge. Targets are
    webroot-relative FILE paths (a directory target fails closed on read);
    tables are dumped through ``bridge.call_stream("db_dump", ...)`` and
    every object is validated with the shared restore grammar
    (:mod:`wpt.dbstream`) BEFORE it is written — a snapshot must never
    report success for a stream ``wpt restore`` refuses.

    Batched reads: targets are read through ``source.read_many`` in
    batches of ``_READ_BATCH`` (200) — a memory bound (at most one batch
    of payloads in flight) and the deadline-check granularity.  Per the
    read_many contract, a path that fails to read lands in the call's
    ``failed`` bucket — and for a SNAPSHOT that is fail-closed: a present
    target that cannot be read is a hole in the reversibility substrate
    (--apply could still write it; restore would have nothing to bring
    back and no manifest entry to even know), so the failed bucket raises
    WptError naming the holes into the fail-closed cleanup.  Audit scans
    may skip an unreadable file; a snapshot may not silently lack one.
    A read_many RAISE is likewise run-level (channel trip, expired
    deadline) and fails the whole snapshot closed.

    ``deadline`` (a ``wpt.deadline.Deadline`` or None, default None =
    unbounded — the auto-snapshot call sites stay deadline-free) is the
    run's self-bounding budget: the capture loop checks it once per
    BATCH (label ``"snapshot capture"``) and the db-dump loop once per
    TABLE (label ``"snapshot db dump"``); a trip raises
    :class:`~wpt.types.DeadlineExceeded` (a RunControl, so no broad
    operational catch can turn it into a partial snapshot) into the
    fail-closed cleanup below.

    Fail-closed: any failure removes the partial snapshot directory and
    re-raises — the caller must abort the mutating action. An empty snapshot
    (no targets, no tables) still produces a directory + manifest: an action
    that mutates nothing is trivially reversible, and the trail is kept.

    Observability contract (a full-site capture runs for HOURS — the
    operator must see progress, pace and health without waiting for the
    end): the file loop emits ONE info heartbeat every
    ``_HEARTBEAT_EVERY`` captured files — ``snapshot progress:
    <N>/<total> files captured (<bytes> so far)`` with ``<total>`` =
    target count and ``<N>``/``<bytes>`` = files/bytes captured so far —
    strictly INSIDE the capture: a milestone landing on the last target
    would only echo the success summary a moment later, so a capture of at
    most ``_HEARTBEAT_EVERY`` targets logs no heartbeat at all.  The table
    loop logs ONE debug line per COMPLETED table — ``table captured:
    <name> (<rows> rows)`` — at the stream's ``done`` object: tables
    number a few dozen at most and complete fast, so no heartbeat there.
    The success summary ends with the capture duration, ``(%ds elapsed)``
    — ``time.monotonic`` from capture start to manifest completion, so
    wall-clock jumps cannot fake it.  ``_HEARTBEAT_EVERY`` is structural,
    NOT a settings tunable: it sets log cadence, not behavior — no
    operator decision changes what a snapshot captures — so the
    no-static-configurables rule stops at the logging boundary.
    """
    if not isinstance(site_label, str) or not site_label:
        raise ValueError("site_label must be a non-empty string")
    if not isinstance(site_raw, str) or not site_raw:
        raise ValueError("site_raw must be a non-empty string")
    if site_label != site_raw:
        # ONE identity: the sanitized on-disk label and the raw manifest key
        # are the same site.  Two different values would write a directory
        # that restore (which compares site_raw) can never match.
        raise ValueError(
            "site_label and site_raw must name the same site "
            f"({site_label!r} != {site_raw!r})")
    if not isinstance(webroot, str):
        raise ValueError("webroot must be a string")
    if not isinstance(action, str) or not action:
        raise ValueError("action must be a non-empty string")
    if targets and source is None:
        raise ValueError("file targets require a source")
    if tables and bridge is None:
        raise ValueError("table capture requires a bridge")
    norm_targets = [source._guard_returned_path(t) for t in targets]
    stray = [target for target in norm_targets
             if is_wpt_endpoint_file(target)]
    if stray:
        # A live bridge/probe is a token-authenticated endpoint, never site
        # content: an archive outlives the token and restore would re-arm it.
        raise ValueError(
            f"snapshot targets include {len(stray)} wpt token endpoint(s) "
            f"({stray[0]}) — refusing to archive them")
    if len(set(norm_targets)) != len(norm_targets) \
            or len({target.casefold() for target in norm_targets}) \
            != len(norm_targets):
        # The verifier rejects BOTH normalized and casefold duplicates: on a
        # case-sensitive FTP host ``a.txt`` and ``A.txt`` are real entries,
        # but a restore plan would address them as one path.  Creation must
        # fail closed here, so a snapshot we announce as valid is always one
        # ``verify_snapshot`` accepts.
        raise ValueError("duplicate targets")
    for name in tables:
        if not _table_name_ok(name):
            raise ValueError(f"unsafe table name: {name!r}")
    if len(set(tables)) != len(tables) \
            or len({name.casefold() for name in tables}) != len(tables):
        raise ValueError("duplicate tables")

    label = sanitize_site_label(site_label)
    site_dir = open_private_site_dir(backup_dir, label)
    sweep_stale_snapshot_temps(
        site_dir, settings, deadline=deadline, inspected=snapshot_roots)
    now = _now()
    base = now.strftime("%Y%m%d-%H%M%S")
    table_set = set(tables)

    snap_dir: Path | None = None
    file_entries: list[dict[str, Any]] = []
    table_entries: list[dict[str, Any]] = []
    captured = 0
    absent = 0
    payload_bytes = 0
    capture_started = time.monotonic()  # elapsed clock: jump-immune
    try:
        # Capture into a DOT temp name that SNAPSHOT_NAME_RE cannot match,
        # then rename to the timestamped final name only after the manifest
        # lands.  A stop/chmod failure in the old mkdir->register window
        # left an empty timestamp directory that --undo-last selected over
        # a valid older snapshot (and no manifest existed to restore).
        n = 1
        while True:
            candidate = site_dir / f".{base}-{n}.tmp"
            try:
                candidate.mkdir(mode=_PRIVATE_DIR_MODE)
            except FileExistsError:
                n += 1
                continue
            # Register BEFORE chmod/write: a stop in either window must
            # remove what this run just made.
            snap_dir = candidate
            os.chmod(candidate, _PRIVATE_DIR_MODE)
            break

        for offset in range(0, len(norm_targets), _READ_BATCH):
            if deadline is not None:
                deadline.check("snapshot capture")
            batch = norm_targets[offset:offset + _READ_BATCH]
            present: list[str] = []
            absent_batch: set[str] = set()
            for target in batch:
                if not presence_proven(source, target):
                    absent_batch.add(target)
                else:
                    present.append(target)
            # ONE read_many per batch — an all-absent batch reads nothing
            if present:
                ok, failed = source.read_many(present)
            else:
                ok, failed = {}, {}
            # emit in TARGET order: absent, skipped and captured entries
            # interleave exactly as the serial loop wrote them
            for target in batch:
                if target in absent_batch:
                    file_entries.append({"path": target, "absent": True})
                    absent += 1
                    continue
                if target in failed:
                    # A present target that cannot be READ is a HOLE in
                    # the reversibility substrate: --apply could still
                    # WRITE it, and restore would then have nothing to
                    # bring back — with no manifest entry it would not
                    # even know. The pre-batching code failed closed on
                    # exactly this (read_bytes raised into the cleanup),
                    # and a backup substrate must keep that invariant:
                    # list the holes, remove the partial snapshot,
                    # refuse. (Audit scans may skip a file; a snapshot
                    # may not silently lack one.)
                    preview = "; ".join(
                        f"{p}: {failed[p]}" for p in list(failed)[:3]
                    )
                    raise WptError(
                        f"snapshot capture: {len(failed)} of "
                        f"{len(batch)} present targets unreadable "
                        f"({preview}) — a snapshot with holes is not a "
                        "reversibility substrate; aborting before any "
                        "mutation (fix the channel or the files, or "
                        "narrow the action targets)"
                    )
                if target not in ok:
                    # read_many contract violation: a requested path in
                    # neither bucket — a wire anomaly, fail closed
                    raise ValueError(f"read_many lost target {target!r}")
                data = ok[target]
                dest = snap_dir / FILES_DIR / target
                dest.parent.mkdir(parents=True, exist_ok=True,
                                  mode=_PRIVATE_DIR_MODE)
                private_dir_chain(dest.parent, snap_dir)
                write_private_bytes(dest, data)
                file_entries.append(
                    {
                        "path": target,
                        "absent": False,
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "size": len(data),
                    }
                )
                captured += 1
                payload_bytes += len(data)
                # heartbeat: strictly inside the capture — ``captured + absent``
                # is the processed-target count, so the guard suppresses a
                # milestone on the last target (the success summary covers it)
                if (captured % _HEARTBEAT_EVERY == 0
                        and captured + absent < len(norm_targets)):
                    log.info(
                        "snapshot progress: %d/%d files captured "
                        "(%d bytes so far)",
                        captured, len(norm_targets), payload_bytes,
                    )

        if tables:
            db_dir = snap_dir / DB_DIR
            db_dir.mkdir(mode=_PRIVATE_DIR_MODE)
            os.chmod(db_dir, _PRIVATE_DIR_MODE)
            handles: dict[str, Any] = {}
            hashers: dict[str, Any] = {}
            sizes: dict[str, int] = {}
            streams: dict[str, TableStream] = {}
            try:
                for raw_obj in bridge.call_stream(
                        "db_dump", tables=list(tables),
                        **transport_kwargs(deadline)):
                    name = raw_obj.get("table")
                    if not isinstance(name, str) or name not in table_set:
                        raise ValueError(
                            "db_dump stream: object for a table not requested"
                        )
                    # Validate the EXACT disk form (bytes cells remarked as
                    # the wire marker) with the restore grammar BEFORE the
                    # write: a snapshot must never report success for a
                    # stream ``wpt restore`` refuses (P2-7/P2-19).
                    obj = _remark_bytes(raw_obj)
                    stream = streams.get(name)
                    if stream is None:
                        stream = streams[name] = TableStream(name)
                    was_done = stream.done is not None
                    stream.accept(obj, "db_dump stream")
                    if not was_done and stream.done is not None:
                        log.debug(
                            "table captured: %s (%d rows)", name, stream.rows
                        )
                    line = (
                        json.dumps(
                            obj,
                            ensure_ascii=False,
                            separators=(",", ":"),
                            allow_nan=False,
                        )
                        + "\n"
                    ).encode("utf-8")
                    handle = handles.get(name)
                    if handle is None:
                        if deadline is not None:
                            # per-TABLE check: fires at the table's FIRST
                            # stream object — bounds the dump at table
                            # granularity
                            deadline.check("snapshot db dump")
                        handle = open_private_binary(db_dir / f"{name}.ndjson")
                        handles[name] = handle
                        hashers[name] = hashlib.sha256()
                        sizes[name] = 0
                    handle.write(line)
                    hashers[name].update(line)
                    sizes[name] += len(line)
            finally:
                for handle in handles.values():
                    handle.close()
            for name in tables:
                stream = streams.get(name)
                if stream is None:
                    raise ValueError(
                        f"db_dump stream never mentioned table {name!r}"
                    )
                if stream.done is None:
                    # A stream without its done line is not restorable; the
                    # snapshot must refuse it NOW, not at restore time.
                    raise ValueError(
                        f"db_dump stream never finished table {name!r} "
                        "(missing done line)"
                    )
                table_entries.append(
                    {
                        "name": name,
                        "rows": stream.rows,
                        "sha256": hashers[name].hexdigest(),
                        "size": sizes[name],
                    }
                )
                payload_bytes += sizes[name]

        manifest = {
            "format": MANIFEST_FORMAT,
            "version": MANIFEST_VERSION,
            "site": label,
            "site_raw": site_raw,
            "webroot": webroot,
            "action": action,
            "created": now.isoformat(),
            "wpt_version": _WPT_VERSION,
            "files": file_entries,
            "tables": table_entries,
            "totals": {
                "files": captured,
                "absent": absent,
                "tables": len(table_entries),
                "bytes": payload_bytes,
            },
        }
        payload = (
            json.dumps(manifest, indent=2, ensure_ascii=True,
                       allow_nan=False) + "\n"
        ).encode("utf-8")
        # ONE size contract: the reader caps a manifest at
        # MANIFEST_MAX_BYTES, so the writer must never emit one its own
        # restore refuses.  Fail closed (the partial dir is removed by the
        # handler below) with a message that names the lever.
        if len(payload) > MANIFEST_MAX_BYTES:
            raise WptError(
                f"snapshot manifest would be {len(payload)} bytes, over "
                f"MANIFEST_MAX_BYTES ({MANIFEST_MAX_BYTES}); reduce the "
                "target/table count for this snapshot")
        write_private_bytes(snap_dir / MANIFEST_NAME, payload)
        # The manifest is complete: publish under the timestamped name that
        # restore/undo/list can select.  Existing names are retried, never
        # replaced.
        n = 1
        while True:
            final = site_dir / (base if n == 1 else f"{base}-{n}")
            if final.exists():
                n += 1
                continue
            os.replace(snap_dir, final)
            snap_dir = final
            break
    except BaseException as exc:
        if snap_dir is not None:
            shutil.rmtree(snap_dir, ignore_errors=True)
            if snap_dir.exists():
                log.error("could not remove partial snapshot dir %s", snap_dir)
            else:
                log.warning(
                    "snapshot for %s failed (%s); partial dir removed",
                    action,
                    type(exc).__name__,
                )
        _remove_empty_dir(site_dir)
        # Operational ValueErrors from INSIDE the capture (a NaN/Inf cell
        # rejected by the manifest/NDJSON encoders' allow_nan=False, an
        # anomalous db_dump stream) become WptError so every command
        # body's binding (WptError, OSError) never-raises contract holds.
        # The argument-validation ValueErrors raise BEFORE this handler.
        if isinstance(exc, ValueError):
            raise WptError(f"snapshot failed: {exc}") from exc
        raise

    meta = SnapshotMeta(
        path=snap_dir,
        files=captured,
        tables=len(table_entries),
        bytes_written=payload_bytes,
    )
    log.info(
        "snapshot for %s at %s: %d file(s) captured, %d absent, %d table(s), "
        "%d bytes (%ds elapsed)",
        action, snap_dir, captured, absent, len(table_entries), payload_bytes,
        int(time.monotonic() - capture_started),
    )
    if snapshot_roots is not None:
        snapshot_roots.append(snap_dir)
    prune(site_dir, settings, keep=snap_dir,
          site_raw=site_raw, webroot=webroot,
          inspected=snapshot_roots)
    return meta


#: Read flags for one snapshot payload: no link on the FINAL component, no
#: blocking open (a FIFO opened read-only without O_NONBLOCK waits forever),
#: and no descriptor inherited by a child process.  A non-regular target is
#: refused by the fstat after the open, never by a pre-open stat.
_READ_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
#: Directory-walk flags for the components BELOW a snapshot root.
_DIR_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


def _relative_parts(path: Path) -> tuple[str, ...]:
    """The POSIX components of a snapshot-relative path, or a refusal.

    An absolute path would make ``openat`` ignore the directory fd, and a
    ``..`` component would climb back out of the snapshot; both are refused
    before any syscall.
    """
    text = os.fspath(path)
    if not text or "\x00" in text or path.is_absolute():
        raise WptError(f"unsafe snapshot-relative path {text!r}")
    parts = path.parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise WptError(f"unsafe snapshot-relative path {text!r}")
    return parts


def _open_dir_beneath(root: Path, parts: tuple[str, ...]) -> int:
    """Open ``root/parts...`` as a DIRECTORY fd, refusing every link.

    Each component is opened with ``O_NOFOLLOW|O_DIRECTORY`` relative to
    its parent fd, so a symlinked directory component can neither be
    followed nor swapped in after a check (N-F1).
    """
    dir_fd = os.open(root, _DIR_FLAGS)
    try:
        for part in parts:
            next_fd = os.open(part, _DIR_FLAGS, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = next_fd
        return dir_fd
    except BaseException:
        os.close(dir_fd)
        raise


def _open_beneath(root: Path, rel: Path) -> int:
    """Open one REGULAR file below ``root`` without following any component."""
    parts = _relative_parts(rel)
    dir_fd = os.open(root, _DIR_FLAGS)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, _DIR_FLAGS, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = next_fd
        return os.open(parts[-1], _READ_FLAGS, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)


def _lexists_beneath(root: Path, rel: Path) -> bool:
    """``os.path.lexists`` for a path below ``root``, link-free all the way.

    ``lexists`` is what an ``absent`` manifest entry needs (a dangling
    symlink is PRESENT on disk).  The final component is stat'ed with
    ``follow_symlinks=False`` through a verified directory fd, so a
    symlinked directory component answers "not clean" instead of silently
    being followed outside the snapshot (N-F1).
    """
    parts = _relative_parts(rel)
    try:
        parent_fd = _open_dir_beneath(root, parts[:-1])
    except FileNotFoundError:
        # A missing files/ directory is the legitimate all-absent snapshot:
        # nothing was captured, so nothing can be present.
        return False
    try:
        try:
            os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return True
    finally:
        os.close(parent_fd)


def read_regular_bounded(path: Path, limit: int, label: str, *,
                         root: Path | None = None) -> bytes:
    """Read a REGULAR file with a hard byte bound; never a FIFO/device/link.

    The opened descriptor is the ONLY authority: there is no pre-open
    ``lstat`` whose identity could be compared, because an unlink+copy can
    reuse the freed inode and make such a comparison lie (N1).  The file is
    opened once (``O_NOFOLLOW`` for the final component, ``O_NONBLOCK`` so
    a FIFO cannot block the open), that fd is ``fstat``-ed and required to
    be regular, and exactly that fd is read.  A concurrent content swap is
    therefore either read and rejected by the caller's sha256 gate, or not
    seen at all — never "verified" against a different file's identity.
    The ``limit + 1`` read is the post-open race bound for a regular file
    that grows.

    With ``root``, ``path`` is a snapshot-relative path and every directory
    component is walked through ``openat`` fds with ``O_NOFOLLOW``, so a
    symlinked component under ``files/`` or ``db/`` can neither redirect a
    verification read nor a restore write outside the snapshot (N-F1).
    Without ``root`` the path is the caller's own source file (a live
    webroot read), where only the final component is ours to refuse.  This
    is the ONE reader every snapshot input uses (``wpt files``, ``wpt
    backup`` and ``wpt restore``): before it, backup/restore followed
    symlinks out of the snapshot and blocked forever on a FIFO (R6-24).
    """
    path = Path(path)
    try:
        if root is None:
            fd = os.open(path, _READ_FLAGS)
        else:
            fd = _open_beneath(Path(root), path)
    except WptError:
        raise
    except OSError as exc:
        raise WptError(f"cannot read {label} {path}: {exc}") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise WptError(f"{label} {path} is not a regular file")
        if opened.st_size > limit:
            raise WptError(
                f"{label} {path} is {opened.st_size} bytes, over {limit}")
        remaining = limit + 1
        chunks: list[bytes] = []
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
    except WptError:
        raise
    except OSError as exc:
        raise WptError(f"cannot read {label} {path}: {exc}") from exc
    finally:
        os.close(fd)
    if len(data) > limit:
        raise WptError(f"{label} {path} grew past {limit} bytes")
    return data


def read_snapshot_manifest(snapshot_dir: Path) -> Any:
    """Parse one snapshot manifest through the bounded regular-file reader.

    A deeply nested JSON body makes the C scanner raise ``RecursionError``
    (or ``MemoryError``) instead of a parse error; both are converted to
    :class:`WptError` here so every caller's existing error contract answers
    a refusal instead of a raw traceback (R6-37).
    """
    raw = read_regular_bounded(
        Path(MANIFEST_NAME), MANIFEST_MAX_BYTES, "snapshot manifest",
        root=Path(snapshot_dir))
    try:
        return loads_bounded(raw.decode("utf-8"))
    except (RecursionError, MemoryError) as exc:
        raise WptError(
            "snapshot manifest is too deeply nested or too large to parse"
        ) from exc


def _declared_size(entry: dict[str, Any]) -> int | None:
    """A manifest entry's non-negative integer size, or None."""
    value = entry.get("size")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def verify_snapshot(snapshot_dir: Path,
                    deadline: Deadline | None = None, *,
                    table_bytes: dict[str, bytes] | None = None,
                    manifest_out: dict[str, Any] | None = None) -> bool:
    """Recompute every manifest sha256 against the payload on disk.

    True only if the manifest parses, every captured file matches its
    sha256, every table stream matches, and no absent target has a stray
    captured file. Never raises an operational failure — EXCEPT a
    :class:`DeadlineExceeded` from the caller's own run budget, which is
    checked before the manifest and between payload entries so the
    verification pre-pass is inside ``--deadline`` (R6-38).

    Every read is rooted at the snapshot directory and walks each
    component without following links, so a symlinked directory cannot
    redirect verification outside the snapshot (N-F1).  When
    ``table_bytes`` is supplied, each table stream's EXACT verified bytes
    are stored under its name; restore replays those bytes instead of
    reading the stream a second time (N-F2).  When ``manifest_out`` is
    supplied, the EXACT parsed manifest verified here is stored into it
    (cleared first, filled only on success); restore selects and hashes
    from that object instead of re-reading ``manifest.json`` — a manifest
    swapped between the two opens could otherwise select unverified
    entries (N-G1).
    """
    snapshot_dir = Path(snapshot_dir)
    if manifest_out is not None:
        manifest_out.clear()
    try:
        check_deadline(deadline, "snapshot verification")
        manifest = read_snapshot_manifest(snapshot_dir)
        check_deadline(deadline, "snapshot verification")
        if not isinstance(manifest, dict):
            return False
        files = manifest.get("files")
        tables = manifest.get("tables")
        if not isinstance(files, list) or not isinstance(tables, list):
            return False
        seen_files: set[str] = set()
        seen_folded: set[str] = set()
        seen_tables: set[str] = set()
        for entry in files:
            check_deadline(deadline, "snapshot verification")
            if not isinstance(entry, dict) or not _is_safe_rel(entry.get("path")):
                return False
            normalized = posixpath.normpath(
                entry["path"].replace("\\", "/"))
            folded = normalized.casefold()
            if normalized in seen_files or folded in seen_folded:
                # A duplicate entry is not a second copy of one target: the
                # restore plan would delete/write the SAME path twice, and
                # a failed second delete leaves a partial restore.  Creation
                # already refuses duplicates; the verifier must too.
                return False
            seen_files.add(normalized)
            seen_folded.add(folded)
            rel = Path(FILES_DIR) / entry["path"]
            absent = entry.get("absent")
            if not isinstance(absent, bool):
                # ``"yes"``/``1``/``"false"`` are truthy strings/ints a
                # hand-edited manifest can carry.  Branching on truthiness
                # turned a captured-or-corrupt entry into a live DELETE on
                # restore; the schema says absent is a JSON boolean, so
                # anything else fails verification closed.
                return False
            if absent:
                if "size" in entry or "sha256" in entry:
                    # An absent entry records no stored bytes; size/sha
                    # here is a schema-invalid hybrid that restore must
                    # never interpret as either arm.
                    return False
                # lexists, not exists: a DANGLING symlink is present on
                # disk, and exists() follows it to False.  An absent entry
                # backed by a link (or by a symlinked directory component)
                # is a stray payload, not "still absent".
                if _lexists_beneath(snapshot_dir, rel):
                    return False
                continue
            size = _declared_size(entry)
            if size is None:
                return False
            data = read_regular_bounded(
                rel, size, "snapshot file", root=snapshot_dir)
            check_deadline(deadline, "snapshot verification")
            if len(data) != size:
                return False
            if hashlib.sha256(data).hexdigest() != entry.get("sha256"):
                return False
        for entry in tables:
            check_deadline(deadline, "snapshot verification")
            if not isinstance(entry, dict) or not _table_name_ok(entry.get("name")):
                return False
            table_key = entry["name"].casefold()
            if table_key in seen_tables:
                return False
            seen_tables.add(table_key)
            size = _declared_size(entry)
            if size is None:
                return False
            data = read_regular_bounded(
                Path(DB_DIR) / f"{entry['name']}.ndjson", size,
                "snapshot table", root=snapshot_dir)
            check_deadline(deadline, "snapshot verification")
            if len(data) != size:
                return False
            if hashlib.sha256(data).hexdigest() != entry.get("sha256"):
                return False
            if table_bytes is not None:
                table_bytes[entry["name"]] = data
        if manifest_out is not None:
            manifest_out.update(manifest)
        return True
    except DeadlineExceeded:
        raise
    except Exception:
        return False


def _snapshot_identity_matches(snapshot_dir: Path, site_raw: str,
                               webroot: str) -> bool:
    """True only when this directory's manifest proves the EXACT identity.

    Retention is destructive, so it uses the SAME gate restore's selection
    uses: the raw site key AND the recorded webroot compare exactly.  A
    normalized-only spelling (``/public_html/`` for ``public_html``) is a
    DIFFERENT identity to the restore gate, so deleting the exact snapshot
    while keeping the normalized one destroyed the only restorable
    ``--undo-last`` basis.  An unreadable, non-object, or pre-identity
    manifest proves NOTHING and is kept — a legacy/partial directory is
    never deleted on a name guess.
    """
    try:
        manifest = read_snapshot_manifest(snapshot_dir)
    except (StopRequested, DeadlineExceeded):
        raise
    except (WptError, OSError, ValueError, UnicodeError):
        return False
    if not isinstance(manifest, dict):
        return False
    raw = manifest.get("site_raw")
    recorded = manifest.get("webroot")
    if not isinstance(raw, str) or not raw or not isinstance(recorded, str):
        return False
    return raw == site_raw and recorded == webroot


def prune(site_dir: Path, settings: BackupSettings, *, keep: Path | None = None,
          site_raw: str, webroot: str,
          inspected: list[Path] | None = None) -> int:
    """Apply retention to one site's snapshot dir; return the number removed.

    A snapshot survives if it is among the newest ``keep_last`` (by the
    (timestamp, suffix) name sort key), OR its name timestamp is within
    ``keep_days`` days of now, OR it is ``keep`` (the snapshot just created).
    Everything else is removed oldest-first with one info log line each.

    ``site_raw``/``webroot`` are the CURRENT identity, REQUIRED: one host's
    label directory is shared by every docroot (``site.example`` with
    webroot A and B), so retention must group by the manifest identity, not
    by directory name.  Only a candidate whose capped, link-free manifest
    proves the exact identity is eligible; another docroot's snapshot, an
    unreadable manifest and a pre-identity manifest are all kept.

    Never raises on filesystem errors: scan/removal failures are logged at
    error level and skipped — a retention failure must not invalidate an
    already-completed snapshot. Non-matching directory names are untouched.
    """
    try:
        dir_fd = _open_site_dir_no_follow(site_dir)
    except OSError as e:
        log.error("prune: refused %s (%s)", site_dir, type(e).__name__)
        return 0
    try:
        candidates = [site_dir / name for name in os.listdir(dir_fd)]
    except OSError as e:
        log.error("prune: cannot list %s (%s)", site_dir, type(e).__name__)
        return 0
    finally:
        os.close(dir_fd)
    snaps: list[tuple[tuple[datetime, int], Path]] = []
    for entry in candidates:
        if not entry.is_dir():
            continue
        match = SNAPSHOT_NAME_RE.match(entry.name)
        if inspected is not None:
            inspected.append(entry)
        if not match:
            continue
        try:
            ts = datetime.strptime(match.group(1), "%Y%m%d-%H%M%S")
        except ValueError:
            continue
        if not _snapshot_identity_matches(entry, site_raw, webroot):
            log.debug("prune: keeping %s (different or unproven identity)",
                      entry.name)
            continue
        snaps.append(((ts, int(match.group(2) or 0)), entry))
    if not snaps:
        return 0
    snaps.sort(key=lambda item: item[0])
    now = _now()
    cutoff = now - timedelta(days=settings.keep_days)
    tzinfo = getattr(now, "tzinfo", None)
    keep_abs = keep.absolute() if keep is not None else None
    if settings.keep_last > 0:
        newest = {d.absolute() for _, d in snaps[-settings.keep_last:]}
    else:
        newest = set()
    removed = 0
    for (ts, _suffix), directory in snaps:  # ascending: oldest removed first
        d_abs = directory.absolute()
        if d_abs == keep_abs or d_abs in newest:
            continue
        if ts.replace(tzinfo=tzinfo) >= cutoff:
            continue
        try:
            shutil.rmtree(directory)
        except OSError as e:
            log.error(
                "prune: could not remove %s (%s)", directory, type(e).__name__
            )
            continue
        log.info("pruned old snapshot %s", directory)
        removed += 1
    return removed


def run_backup(ctx: "Ctx") -> int:
    """Run the ``wpt backup`` command body — one FULL-site explicit
    snapshot; 0 on success, 1 on failure, never raises.

    ``wpt.cli`` dispatches here via ``_lazy_call(ctx, "wpt.backup",
    "run_backup")`` with ``ctx.extra = {}`` (full scope, no per-command
    flags).  The snapshot is the SAME layout the actions registry's
    auto-snapshots write — :func:`create_snapshot` over every walked
    file plus every table the bridge's ``db_audit`` reports — so an
    explicit snapshot and a pre-action snapshot are interchangeable for
    ``wpt restore``.  Retention is applied by ``create_snapshot`` itself
    (it prunes internally after the manifest lands); this body never
    prunes a second time.

    * local mode REFUSES with rc 1: the zip + dump the user already
      holds ARE the offline snapshot — there is nothing to capture.
    * ftp mode builds the remote stack through the ONE construction
      seam :func:`wpt.audit.remote_stack` (imported into THIS namespace
      so tests can monkeypatch ``wpt.backup.remote_stack``, exactly
      like wpt.verify).  The tree is enumerated BEFORE the first bridge
      call (the audit's walk-before-bridge discipline: the snapshot can
      never contain our own deployed bridge file); ``db_audit`` then
      names the tables, defended at this trust boundary — anything but
      a list of dicts each carrying one disk-safe table name raises
      WptError, so a hostile payload answers rc 1 here instead of a
      ``ValueError`` escaping from inside the capture.  The bridge is
      destroyed and the source closed in a ``finally`` spanning the
      whole capture (mirror of ``registry.run_action``;
      ``Bridge.destroy`` is idempotent and a no-op when the bridge was
      never deployed).

    Output: a small markdown summary (:func:`_render`).  With
    ``ctx.report_path`` set the markdown is written there (utf-8) and a
    JSON twin of the same run (:func:`_render_json`) to
    ``report_path.with_suffix(".json")``, mirroring the audit / restore
    md+json pair; the markdown is ALWAYS written to stdout too through the
    shared ``wpt.report.write_stdout`` sink, exactly as in wpt.verify /
    the audit's ``_emit`` (the report IS the command's stdout
    surface), and the twin never reaches stdout.  One info summary
    (files, tables, human-readable size) is always logged.

    Error contract (binding, mirrors wpt.audit.run / wpt.verify.run):
    every :class:`~wpt.types.WptError` and ``OSError`` — stack failure,
    walk failure, unusable ``db_audit`` payload, any fail-closed capture
    failure (including a run-deadline trip: the snapshot receives
    ``Deadline.from_ctx(ctx)`` and checks it once per read batch and per
    dumped table, removing its partial dir on a trip), report write
    failure (markdown or JSON twin) — is logged at error and answered
    with rc 1; a traceback NEVER escapes :func:`run_backup`.
    """
    if ctx.mode == "local":
        reason = ("backup requires ftp mode: the zip + dump already are "
                  "the offline snapshot")
        log.error("%s", reason)
        _write_failure(ctx, reason)
        return 1
    # ONE budget, built BEFORE the stack/walk/db_audit pre-work — a later
    # Deadline.from_ctx would restart the clock after the very work that
    # overran it (R13/C8).
    deadline = Deadline.from_ctx(ctx)
    try:
        if deadline is not None:
            deadline.check("backup setup")
        source, session, bridge = remote_stack(ctx)
        label = site_label(ctx)
        primary: BaseException | None = None
        first_stop: BaseException | None = None
        inspected_roots: list[Path] = []
        try:
            # A live bridge (`bridge-<hex>.php`) or standalone probe
            # (`wpt-probe-<hex>.php`) is a token-authenticated endpoint wpt
            # deployed seconds ago. Archiving one would put a still-valid
            # secret in a snapshot that OUTLIVES the token, and a later
            # `restore` would write it back as a working endpoint [L59].
            targets = _targets_exclude_bridges(
                (e for e in source.walk() if not e.is_dir),
                deadline=deadline, source=source,
            )
            if deadline is not None:
                deadline.check("backup db audit")
            audit = bridge.call("db_audit")
            raw_tables = audit.get("tables")
            if (not isinstance(raw_tables, list)
                    or not all(isinstance(t, dict)
                               and _table_name_ok(t.get("name"))
                               for t in raw_tables)):
                raise WptError("db_audit returned an unusable tables list")
            tables = require_distinct_snapshot_names(
                (t["name"] for t in raw_tables), "table")
            meta = create_snapshot(
                source=source,
                bridge=bridge,
                site_label=label,
                targets=targets,
                tables=tables,
                backup_dir=ctx.backup_dir,
                settings=ctx.settings.backup,
                action="backup",
                deadline=deadline,
                site_raw=site_label(ctx),
                webroot=ctx.webroot or "",
                snapshot_roots=inspected_roots,
            )
            # The snapshot this run just CREATED is a protected input too:
            # its report (or its failure writer) must never land inside the
            # rollback basis it is announcing.
            ctx.extra.setdefault("snapshot_dir", str(meta.path))
            for root in inspected_roots:
                record_snapshot_root(ctx, root)
            record_snapshot_root(ctx, meta.path)
        except BaseException as exc:
            for root in inspected_roots:
                record_snapshot_root(ctx, root)
            primary = exc
            raise
        finally:
            # Teardown is INDEPENDENT and all-or-nothing in coverage: the
            # shared owner attempts bridge/source/session and a cooperative
            # stop in one step must not skip the others.  A teardown stop
            # must never mask the capture failure already in flight
            # (R6-28).
            from .teardown import teardown_stack

            first_stop = teardown_stack((source, session, bridge), "backup")
            if first_stop is not None and primary is None:
                raise first_stop
        markdown = _render(label, meta)
        if ctx.report_path is not None:
            write_report_files(
                ctx.report_path, markdown, _render_json(label, meta),
                protected_paths=report_protected_inputs(ctx),
                protected_subtrees=report_protected_subtrees(ctx))
        write_stdout(markdown)
        log.info("backup complete: %d files, %d tables, %s",
                 meta.files, meta.tables, human_bytes(meta.bytes_written))
        return 0
    except RunControl as exc:
        reason = redact_text(f"backup stopped: {exc}")
        log.error("%s", reason)
        _write_failure(ctx, reason)
        return 1
    except (WptError, OSError) as exc:
        reason = redact_text(str(exc))
        log.error("backup failed: %s", reason)
        _write_failure(ctx, reason)
        return 1


def _write_failure(ctx: "Ctx", reason: str) -> None:
    """Best-effort failure report for every ``wpt backup`` failure path.

    Local refusal, stack/walk/db_audit failures and capture deadlines all
    route through the ONE shared writer, so ``--report`` keeps its presence
    contract here exactly as files/restore/actions do (R6-29).
    """
    from .actions.registry import write_failure_report

    try:
        write_failure_report(ctx, "backup", reason, title="wpt backup")
    except (Exception, RunControl) as exc:  # noqa: BLE001 — reporting must not mask rc
        log.warning("backup: could not write the failure report: %s",
                    redact_text(str(exc)))


def _render(site: str, meta: SnapshotMeta) -> str:
    """The backup markdown summary; its machine-readable twin is
    :func:`_render_json` (the manifest stays the full-fidelity record
    of the snapshot itself)."""
    lines = [
        f"# wpt backup — {site}",
        "",
        f"Full snapshot at `{meta.path}`: {meta.files} files, "
        f"{meta.tables} tables, {human_bytes(meta.bytes_written)}.",
        "",
    ]
    return "\n".join(lines)


def _render_json(site: str, meta: SnapshotMeta) -> str:
    """The machine-readable twin of :func:`_render`: the site, the
    snapshot location and the three summary counters as ONE small
    snake_case dict — backup's OWN schema (the manifest remains the
    full-fidelity record of the snapshot).  Formatted exactly like
    :func:`wpt.report.render_json` (utf-8, sorted keys, indent 2) so
    the report surfaces stay consistent."""
    return json.dumps(
        {
            "site": site,
            "snapshot": str(meta.path),
            "files": meta.files,
            "tables": meta.tables,
            "bytes": meta.bytes_written,
        },
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    )
