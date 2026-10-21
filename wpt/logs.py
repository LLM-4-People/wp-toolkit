"""Read-only host/webroot error-log triage behind ``wpt logs``.

The command is FTP-only: host logs (DirectAdmin's ``domains/<domain>/logs``,
``<webroot-parent>/logs``, ``logs``) live OUTSIDE the webroot, while WordPress
also leaves ``error_log`` / ``php_errorlog`` / ``wp-content/debug.log`` inside
it.  :func:`collect` therefore reads two sources through the ONE construction
seam (``wpt.remote.ftp_source_for``): the webroot source addresses the direct
webroot files, the account-root source addresses the host log directories.

Every read is bounded before it happens (``settings.logs``): the candidate
set, a plain file, a compressed archive, and the decompressed bytes of a
single gzip.  Archive members are read in memory and never extracted to disk.
Missing directories/files are debug-logged and skipped: a host that has no
``logs`` directory is a fact, not a failure.

``LogScan`` is the reusable result the doctor will consume.  Its markdown is
a small triage table (file, line, pattern, match) plus a bounded skipped
list; its JSON twin is the same data sorted and indented.  Both pass every
rendered log line through :func:`wpt.config.redact_text`, and neither can
carry the FTP password (only ``ctx.source``/``ctx.webroot`` reach the source
summary, never ``ctx.password``).
"""

from __future__ import annotations

import gzip
import heapq
import io
import json
import lzma
import math
import posixpath
import re
import tarfile
import zlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from .config import redact_text
from .deadline import Deadline
from .log import get_logger
from .remote import DOCROOT_NAMES, ftp_source_for, normalize_domain
from .report import md_escape, safe_text
from .report import write_stdout
from .sources.base import close_source
from .types import (DeadlineExceeded, Entry, FtpChannelUnhealthy, RunControl,
                    SIZE_UNKNOWN, Source, SourceError, SourceLookupError,
                    StopRequested, WptError)

if TYPE_CHECKING:  # annotation-only (cli lazy-calls every command)
    from .cli import Ctx

__all__ = ["LogScan", "collect", "run"]

log = get_logger("logs")

#: The log files WordPress (or PHP) may leave DIRECTLY in the webroot.  Their
#: paths are webroot-relative, so they are read through the webroot source.
_DIRECT_WEBROOT_FILES = ("error_log", "php_errorlog", "wp-content/debug.log")

#: The candidate basename shapes: a log, any compressed log/archive, the two
#: bare PHP log names, and any name carrying the ``.error.log`` marker.
_LOG_SUFFIXES = (".log", ".gz", ".tar.gz", ".tgz")
_BARE_LOG_NAMES = frozenset({"error_log", "php_errorlog"})
_ERROR_LOG_MARKER = ".error.log"

#: A rendered match line's hard ceiling (the contract's display bound).
_MAX_RENDERED_LINE = 300

#: Structural domain logic (NOT profile tunables): the labels the operator
#: triages by, in report priority order.  A line can match several; the FIRST
#: label wins, so PHP's own fatal line stays "PHP fatal" even when it also
#: names "memory exhausted"/"maximum execution time".
_LOG_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (label, re.compile(pattern, re.IGNORECASE))
    for label, pattern in (
        ("PHP fatal", r"\bPHP\s+Fatal\b"),
        ("PHP parse", r"\bPHP\s+Parse\b"),
        ("PHP core error", r"\bPHP\s+Core\s+(?:Error|Warning)\b"),
        ("uncaught", r"\bUncaught\b"),
        ("memory exhausted",
         r"(?:\bAllowed memory size\b.*\bexhausted\b|\bmemory exhausted\b)"),
        ("maximum execution time", r"\bMaximum execution time\b"),
        ("SQLSTATE", r"\bSQLSTATE\b"),
        ("PDOException", r"\bPDOException\b"),
        ("mod_fcgid stderr", r"\bmod_fcgid\b.*\bstderr\b"),
        ("AH01071", r"\bAH01071\b"),
        ("premature end of script headers",
         r"\bpremature end of script headers\b"),
        ("worker timed out", r"\bworker timed out\b"),
        ("ERR_CONNECTION", r"\bERR_CONNECTION(?:_[A-Z]+)?\b"),
        ("no such file", r"\bno such file(?:\s+or\s+directory)?\b"),
        ("permission denied", r"\bpermission denied\b"),
        ("disk quota", r"(?:\bdisk quota\b|\bquota exceeded\b|\bover quota\b)"),
        ("no space left", r"\bno space left(?:\s+on device)?\b"),
        ("cannot allocate memory", r"\bcannot allocate memory\b"),
        ("out of memory", r"(?:\bout of memory\b|\bOOM\b)"),
    )
)


@dataclass
class LogScan:
    """One bounded log triage pass (the doctor's reusable result).

    ``files``: one record per source file actually read/parsed —
    ``{path, bytes, kind, members, matches}``.  ``kind`` is ``plain``,
    ``gzip`` or ``tar.gz``; ``members`` is the number of archive log members
    processed (1 for plain/gzip); ``matches`` is that file's matching line
    count (uncapped).
    ``matches``: at most ``settings.logs.detail_limit`` rows —
    ``{file, line, pattern, match}``.  ``total_matches`` counts EVERY match.
    ``latest_matches``: the LAST matching row of each file, computed while
    scanning — the detail list is capped, so reversing it would name an
    older line as "latest" on a noisy file.
    ``skipped``: ``{path, reason}`` for every bounded-out/unreadable file or
    archive member.  Missing paths are debug-logged only, never listed here.
    """

    site: str
    source_summary: str
    files: list[dict]
    matches: list[dict]
    skipped: list[dict]
    total_matches: int
    scanned: int
    latest_matches: dict[str, dict] = field(default_factory=dict)
    #: The same NEWEST-first rank the candidate selection used, per path
    #: that matched.  A tar MEMBER carries its own mtime rank (its archive's
    #: download rank applies only when the member mtime is unknown); before
    #: this every member inherited the archive rank and an older member
    #: inside a newer archive won "latest" (R6-06).
    latest_ranks: dict[str, tuple] = field(default_factory=dict)
    #: The file whose latest match is the NEWEST by the same rank/mtime the
    #: candidate selection used.  Doctor names THIS file; ``matches[0]`` is
    #: only the first scanned candidate and can be an older webroot log.
    latest_file: str | None = None

    def markdown(self) -> str:
        """The operator-facing triage report (always ends with a newline)."""
        lines = [
            f"# wpt logs — {self.site}",
            "",
            (f"Scanned {self.scanned} file(s); {self.total_matches} "
             f"matching line(s); {len(self.skipped)} skipped"),
            "",
        ]
        limit = getattr(self, "_detail_limit", None)
        if not isinstance(limit, int) or limit < 1:
            # A manually built LogScan carries no settings: fall back to the
            # settings owner's own default rather than inventing a number.
            from .settings import LogsSettings

            limit = LogsSettings().detail_limit
        shown = self.matches[:limit]
        if shown:
            lines.append("| file | line | pattern | match |")
            lines.append("|---|---|---|---|")
            for row in shown:
                lines.append(
                    "| {} | {} | {} | {} |".format(
                        md_escape(_text(row.get("file"))),
                        md_escape(_text(row.get("line"))),
                        md_escape(_text(row.get("pattern"))),
                        md_escape(_text(row.get("match"))),
                    )
                )
            lines.append("")
        else:
            lines.append("No error/fatal patterns found in the scanned logs.")
            lines.append("")
        if self.skipped:
            skipped = self.skipped[:limit]
            lines.append("## Skipped")
            lines.append("")
            for row in skipped:
                lines.append(
                    f"- {md_escape(_text(row.get('path')))} — "
                    f"{md_escape(_text(row.get('reason')))}"
                )
            remaining = len(self.skipped) - len(skipped)
            if remaining:
                lines.append(f"- ... and {remaining} more")
            lines.append("")
        return "\n".join(lines).rstrip("\n") + "\n"

    def json_text(self) -> str:
        """The machine-readable twin (sorted keys, indent 2, newline)."""
        payload = {
            "site": self.site,
            "source_summary": self.source_summary,
            "totals": {
                "scanned": self.scanned,
                "matches": self.total_matches,
                "skipped": len(self.skipped),
            },
            "files": self.files,
            "matches": self.matches,
            "skipped": self.skipped,
        }
        return json.dumps(payload, ensure_ascii=False, sort_keys=True,
                          indent=2) + "\n"


def collect(ctx: Ctx, *, webroot_source: Source | None = None,
            account_source: Source | None = None,
            deadline: Deadline | None = None) -> LogScan:
    """Collect one bounded :class:`LogScan` for ``ctx``.

    ``webroot_source``/``account_source`` are test/doctor seams: a passed
    source is NEVER closed here, while every source this function built is
    closed in ``finally``.  The webroot source reads the direct webroot log
    files; the account-root source reads the host log directories.

    ``deadline`` is the caller's run budget when it has one (the doctor
    panel's).  Without it a run's budget would restart at this row and the
    panel could overrun by a full extra budget (DOC1); a caller with no
    shared budget still gets the ordinary ``Deadline.from_ctx`` bound.
    """
    bounds = ctx.settings.logs
    created: list[Source] = []
    webroot = webroot_source
    account = account_source
    primary: BaseException | None = None
    try:
        if webroot is None:
            webroot = ftp_source_for(ctx)
            created.append(webroot)
        if account is None:
            account = ftp_source_for(ctx, root="")
            created.append(account)
        return _scan(ctx, webroot, account, bounds, deadline)
    except BaseException as exc:
        primary = exc
        raise
    finally:
        if primary is None:
            _close_sources(created)
        else:
            # A teardown stop must never REPLACE the scan's primary failure:
            # it is logged beside a reason that stays the run's own.
            try:
                _close_sources(created)
            except (StopRequested, DeadlineExceeded) as stop:
                log.error("logs: teardown stopped: %s; the primary failure "
                          "above stays the run's reason", stop)
            except Exception as exc:  # noqa: BLE001 — close is best-effort
                log.warning("logs: source close failed: %s",
                            redact_text(str(exc)))


def _close_sources(sources: list[Source]) -> None:
    """Close every source this owner built, then re-raise the FIRST stop.

    A cooperative stop raised while closing one source must not abandon the
    remaining sources: teardown is one shared pass, every close is attempted
    (deduplicated by identity), the first ``StopRequested``/``DeadlineExceeded``
    is remembered, and only after the loop does it end the run.
    """
    closed: set[int] = set()
    first_stop: BaseException | None = None
    for source in sources:
        if id(source) in closed:
            continue
        closed.add(id(source))
        try:
            close_source(source, "logs")
        except (StopRequested, DeadlineExceeded) as exc:
            if first_stop is None:
                first_stop = exc
        except Exception as exc:  # noqa: BLE001 — close is best-effort
            log.warning("logs: source close failed: %s",
                        redact_text(str(exc)))
    if first_stop is not None:
        raise first_stop


# --------------------------------------------------------------------- scan


def _scan(ctx: Ctx, webroot: Source, account: Source, bounds,
          deadline: Deadline | None = None) -> LogScan:
    """The bounded read pass shared by ``wpt logs`` and the doctor."""
    if deadline is None:
        deadline = Deadline.from_ctx(ctx)
    root = _clean_webroot(ctx.webroot)
    domain = _domain_from_url(ctx.wp_url) or _webroot_domain(root)
    webroot_candidates: list[tuple[Source, Entry]] = []
    seen: set[tuple[int, str]] = set()
    limit = bounds.max_files
    # A bounded newest heap for the host logs: the candidate set used to
    # materialize EVERY listing entry and then emit one skipped row per
    # dropped file (5,000 files -> 4,980 rows / >500 KB of JSON).  The heap
    # keeps at most ``max_files`` entries and the overflow becomes ONE
    # aggregate skipped row, exactly like the archive-member path (LOGS3).
    newest: list[tuple[tuple, int, Source, Entry]] = []
    sequence = 0
    host_total = 0
    dropped_paths: list[str] = []
    first_dropped_key: tuple | None = None
    #: Log-shaped symlinks met while listing host log directories, grouped
    #: by the directory whose listing produced them.  They are not read (a
    #: link target is outside the source's contract), but silently dropping
    #: one made "no logs" a false clean; ONE row per directory (the single
    #: link keeps the R6-13 per-link row) bounds a hostile listing
    #: (R6-13/R7-P2-19).
    linked_skips: dict[str, list[str]] = {}

    def _note_dropped(key: tuple, path: str) -> None:
        nonlocal first_dropped_key
        # Keep the NEWEST dropped name (the smallest key) so a one-file
        # overflow can still name the file it skipped.
        if first_dropped_key is None or key < first_dropped_key:
            first_dropped_key = key
            dropped_paths[:] = [path]

    def _add(source: Source, entry: Entry) -> None:
        nonlocal sequence, host_total
        key = (id(source), entry.path)
        if key in seen:
            return
        seen.add(key)
        if source is webroot:
            webroot_candidates.append((source, entry))
            return
        host_total += 1
        report_key = _entry_sort_key((source, entry))
        age_key = _age_key(entry)
        item = (age_key, sequence, source, entry)
        sequence += 1
        if len(newest) < limit:
            heapq.heappush(newest, item)
            return
        # The root is the OLDEST kept entry; a newer arrival replaces it.
        if age_key > newest[0][0]:
            evicted = heapq.heapreplace(newest, item)
            _note_dropped(_entry_sort_key((evicted[2], evicted[3])),
                          evicted[3].path)
        else:
            _note_dropped(report_key, entry.path)

    # Host log directories — ONE list_dir each, deduped in derivation order.
    for directory in _candidate_dirs(root, domain):
        _check(deadline, "logs candidate directory")
        try:
            listing = account.list_dir(directory)
        except FtpChannelUnhealthy:
            raise
        except SourceError as exc:
            log.debug("logs: no log directory %s (%s)", directory,
                      redact_text(str(exc)))
            continue
        for entry in listing:
            if entry.is_dir or entry.is_link:
                if entry.is_link and _is_log_name(entry.path):
                    linked_skips.setdefault(directory, []).append(entry.path)
                continue
            if _is_log_name(entry.path):
                _add(account, entry)

    # Direct webroot files — read through the webroot source.
    for path in _DIRECT_WEBROOT_FILES:
        _check(deadline, "logs webroot candidate")
        try:
            exists = webroot.exists(path)
        except FtpChannelUnhealthy:
            raise
        except SourceLookupError:
            # A failed lookup proves NOTHING about absence.  The generic
            # SourceError catch below used to continue, so the report said
            # "No error/fatal patterns found" over a log it never checked.
            raise
        except SourceError as exc:
            log.debug("logs: no webroot log file %s (%s)", path,
                      redact_text(str(exc)))
            continue
        if not exists:
            log.debug("logs: no webroot log file %s", path)
            continue
        try:
            size = webroot.size(path)
        except FtpChannelUnhealthy:
            raise
        except SourceLookupError:
            raise
        except SourceError as exc:
            log.debug("logs: webroot log file vanished %s (%s)", path,
                      redact_text(str(exc)))
            continue
        _add(webroot, Entry(path=path, is_dir=False, size=size))

    # Direct webroot logs first (they have no measured mtime, so a plain
    # newest-first sort would drop them behind every dated host log), then
    # newest host logs.  The cap is recorded, not silent: a bounded-out log
    # is exactly what an operator needs to know when triaging an outage.
    webroot_candidates.sort(key=lambda pair: pair[1].path)
    host_selected = sorted(
        newest, key=lambda item: _entry_sort_key((item[2], item[3])))
    webroot_kept_candidates = webroot_candidates
    host_candidates = [
        (source, entry) for _key, _seq, source, entry in host_selected
    ]
    candidates = webroot_kept_candidates + host_candidates
    kept = candidates[:limit]
    omitted = candidates[limit:]
    webroot_kept = sum(1 for pair in kept if pair[0] is webroot)
    host_kept = len(kept) - webroot_kept
    webroot_dropped = len(webroot_candidates) - webroot_kept
    host_dropped = max(0, host_total - host_kept)
    # ``host_total`` includes heap-evicted entries that never reached
    # ``host_candidates``; the two counts above are the only complete ones.
    candidates = kept

    scan = LogScan(
        site=_site_label(ctx),
        source_summary=_source_summary(ctx),
        files=[],
        matches=[],
        skipped=[],
        total_matches=0,
        scanned=0,
    )
    for directory, linked in linked_skips.items():
        if len(linked) == 1:
            _skip(scan, linked[0], "symbolic link is not a regular file")
        else:
            _skip(
                scan, directory or "/",
                f"{len(linked)} log-shaped symbolic link(s) skipped "
                f"(not regular files); first: {linked[0]}",
            )
    # Rendering bounds travel with the result without becoming JSON fields.
    scan._detail_limit = bounds.detail_limit
    dropped = webroot_dropped + host_dropped
    if dropped == 1:
        path = (omitted[0][1].path if omitted else
                (dropped_paths[0] if dropped_paths else "(log candidates)"))
        _skip(scan, path, f"exceeds logs.max_files ({limit})")
    elif dropped > 1:
        counts: list[str] = []
        if webroot_dropped:
            counts.append(f"{webroot_dropped} webroot log file(s)")
        if host_dropped:
            counts.append(f"{host_dropped} host log file(s)")
        # A dropped webroot candidate invalidates "newest": webroot logs
        # have no measured mtime and are considered first, so say "first"
        # instead of mislabelling them host logs.
        considered = (f"the first {len(kept)} were considered"
                      if webroot_dropped
                      else f"the newest {host_kept} were considered")
        _skip(
            scan, "(host log candidates)" if not webroot_dropped
            else "(log candidates)",
            f"{' and '.join(counts)} exceed logs.max_files ({limit}); "
            f"{considered}",
        )

    ranks: dict[str, tuple] = {}
    for source, entry in candidates:
        _check(deadline, "logs file")
        rank = _entry_sort_key((source, entry))
        ranks[redact_text(_valid_text(entry.path))] = rank
        _scan_entry(source, entry, bounds, scan, deadline, rank=rank)
        _check(deadline, "logs file end")
    if scan.latest_ranks:
        # Every matching row carries the rank of what ACTUALLY held it: a
        # plain file's own mtime, or a tar member's own mtime (archive rank
        # only when the member mtime is unknown).
        scan.latest_file = min(
            scan.latest_ranks.items(), key=lambda item: (item[1], item[0]))[0]
    elif scan.latest_matches:
        # Manually built/scripted LogScan without ranks: keep the historical
        # path/prefix ordering rather than inventing a file.
        ranked = [(ranks[path], path) for path in ranks
                  if path in scan.latest_matches]
        for path, rank in ranks.items():
            prefix = f"{path}:"
            ranked.extend((rank, member) for member in scan.latest_matches
                          if member.startswith(prefix))
        if ranked:
            scan.latest_file = min(ranked)[1]

    scan.scanned = len(scan.files)
    return scan


def _check(deadline: Deadline | None, context: str) -> None:
    if deadline is not None:
        deadline.check(context)


#: Every exception an untrusted archive can raise while opening, iterating
#: or extracting a member.  ``lzma.LZMAError`` is NOT an OSError (corrupt
#: .xz streams raised a raw traceback); one tuple so no entry point forgets
#: it.  ``_ArchiveWorkExceeded`` is the policy ceiling and maps to its own
#: skip reason, so it is handled separately.
_ARCHIVE_READ_ERRORS = (
    tarfile.TarError, OSError, EOFError, zlib.error, lzma.LZMAError,
)


def _scan_entry(source: Source, entry: Entry, bounds, scan: LogScan,
                deadline: Deadline | None = None,
                *, rank: tuple | None = None) -> None:
    """Dispatch one candidate by its basename (archive first)."""
    name = posixpath.basename(entry.path).lower()
    if rank is None:
        rank = _entry_sort_key((source, entry))
    try:
        if name.endswith((".tar.gz", ".tgz")):
            _scan_tar(source, entry, bounds, scan, deadline, rank=rank)
        elif name.endswith(".gz"):
            _scan_gzip(source, entry, bounds, scan, deadline, rank=rank)
        else:
            _scan_plain(source, entry, bounds, scan, deadline, rank=rank)
    except FtpChannelUnhealthy:
        raise
    except (SourceError, OSError) as exc:
        _skip(scan, entry.path, f"read failed: {redact_text(str(exc))}")


def _scan_plain(source: Source, entry: Entry, bounds, scan: LogScan,
                deadline: Deadline | None = None,
                *, rank: tuple | None = None) -> None:
    _check(deadline, "logs file read")
    limit = bounds.max_file_bytes
    if entry.size != SIZE_UNKNOWN and entry.size > limit:
        _skip(scan, entry.path,
              f"size {entry.size} exceeds logs.max_file_bytes ({limit})")
        return
    data = source.read_bytes_bounded(entry.path, limit)
    if len(data) > limit:
        _skip(scan, entry.path,
              f"read size {len(data)} exceeds logs.max_file_bytes ({limit})")
        return
    count = _collect_matches(scan, entry.path,
                             data.decode("utf-8", errors="replace"),
                             bounds.detail_limit, deadline, rank=rank)
    _check(deadline, "logs file end")
    scan.files.append(_file_record(entry.path, len(data), "plain", 1, count))


def _scan_gzip(source: Source, entry: Entry, bounds, scan: LogScan,
               deadline: Deadline | None = None,
               *, rank: tuple | None = None) -> None:
    _check(deadline, "logs gzip read")
    archive_limit = bounds.max_archive_bytes
    if entry.size != SIZE_UNKNOWN and entry.size > archive_limit:
        _skip(scan, entry.path,
              f"size {entry.size} exceeds logs.max_archive_bytes "
              f"({archive_limit})")
        return
    data = source.read_bytes_bounded(entry.path, archive_limit)
    if len(data) > archive_limit:
        _skip(scan, entry.path,
              f"read size {len(data)} exceeds logs.max_archive_bytes "
              f"({archive_limit})")
        return
    ceiling = min(bounds.max_file_bytes, bounds.max_decompressed_bytes)
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as handle:
            raw = handle.read(ceiling + 1)
    except _ARCHIVE_READ_ERRORS as exc:
        _skip(scan, entry.path,
              f"unreadable gzip: {redact_text(str(exc))}")
        return
    # A top-level .gz is charged to the SAME aggregate decompression
    # ceiling the tar members use: only the per-file bound was enforced,
    # so a 48 KB expansion under a 20 KB ceiling produced matches.
    if len(raw) > bounds.max_decompressed_bytes:
        _skip(scan, entry.path,
              _archive_ceiling_reason(bounds.max_decompressed_bytes))
        return
    if len(raw) > bounds.max_file_bytes:
        _skip(scan, entry.path,
              f"decompressed size exceeds logs.max_file_bytes "
              f"({bounds.max_file_bytes})")
        return
    count = _collect_matches(scan, entry.path,
                             raw.decode("utf-8", errors="replace"),
                             bounds.detail_limit, deadline, rank=rank)
    _check(deadline, "logs file end")
    scan.files.append(_file_record(entry.path, len(data), "gzip", 1, count))


#: The tar iterator decompresses the WHOLE stream, including members it never
#: reads (a non-log payload, padding).  The archive's COMPRESSED size says
#: nothing about that expansion, so one aggregate work ceiling aborts the
#: member walk before a 32 MiB archive can spend minutes expanding GiB.
class _ArchiveWorkExceeded(Exception):
    """Internal: the archive passed logs.max_decompressed_bytes."""


class _ArchiveWorkLimiter:
    """A file-like view that counts DECOMPRESSED bytes read or seeked over."""

    _DEADLINE_EVERY = 1024 * 1024

    def __init__(self, raw: Any, limit: int,
                 deadline: Deadline | None = None) -> None:
        self._raw = raw
        self._limit = limit
        self._deadline = deadline
        self._spent = 0
        self._next_deadline_check = self._DEADLINE_EVERY

    def _charge(self, amount: int) -> None:
        self._spent += max(0, amount)
        # The deadline is checked FIRST: one forward seek can represent
        # hundreds of MiB of decompression work, so an already-expired run
        # must end as DeadlineExceeded (rc 1), not be reported as an
        # archive-size skip that completed late.
        if self._deadline is not None \
                and self._spent >= self._next_deadline_check:
            self._next_deadline_check = self._spent + self._DEADLINE_EVERY
            self._deadline.check("logs archive decompression")
        if self._spent > self._limit:
            raise _ArchiveWorkExceeded

    def read(self, size: int = -1) -> bytes:
        # ``tarfile`` passes the DECLARED pax/GNU header size straight
        # through; a 64 MiB (or tar's 8 GiB) size field used to allocate
        # that whole buffer before the ceiling saw a byte.  Clamp every
        # underlying read to one byte past the remaining budget, so the
        # allocation itself can never pass the ceiling.
        remaining = self._limit - self._spent
        cap = max(0, remaining) + 1
        if size is None or size < 0 or size > cap:
            size = cap
        data = self._raw.read(size)
        self._charge(len(data))
        return data

    def readinto(self, buffer) -> int:
        readinto = getattr(self._raw, "readinto", None)
        remaining = self._limit - self._spent
        cap = max(0, remaining) + 1
        if len(buffer) > cap:
            buffer = memoryview(buffer)[:cap]
        if readinto is None:
            data = self.read(len(buffer))
            buffer[:len(data)] = data
            return len(data)
        count = readinto(buffer)
        self._charge(count)
        return count

    def seek(self, offset: int, whence: int = 0) -> int:
        before = self._raw.tell()
        # CHARGE BEFORE THE SEEK.  ``self._raw.seek`` on a gzip stream is
        # the decompression work itself; charging after it performed a
        # multi-GiB forward skip before the ceiling could refuse.  The
        # target is computable for the absolute/relative forms, so the
        # budget is spent first (and a trip raises before any raw seek).
        if whence == 0:
            target: int | None = offset
        elif whence == 1:
            target = before + offset
        else:
            target = None
        if target is not None:
            # A BACKWARD seek makes gzip re-decompress FROM THE START to
            # ``target``; charging only the distance travelled to the old
            # position undercounted the work by the whole prefix.  Forward
            # movement costs the distance actually skipped (R6-11).
            self._charge(target if target < before else target - before)
            return self._raw.seek(offset, whence)
        position = self._raw.seek(offset, whence)
        self._charge(position if position < before else position - before)
        return position

    def tell(self) -> int:
        return self._raw.tell()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._raw, name)


class _DeadlineInput:
    """Compressed-input view that checks the run deadline on every read.

    ``GzipFile.seek``/``read`` decompresses INSIDE the C/Python stdlib loop;
    one forward seek over a 512 MiB member can run for tenths of a second
    without returning to our caller.  Gzip still pulls compressed bytes from
    this view repeatedly, so the deadline is honoured during the expand, not
    after it.
    """

    def __init__(self, raw: Any, deadline: Deadline | None) -> None:
        self._raw = raw
        self._deadline = deadline

    def read(self, size: int = -1) -> bytes:
        data = self._raw.read(size)
        if self._deadline is not None:
            self._deadline.check("logs archive decompression")
        return data

    def __getattr__(self, name: str) -> Any:
        return getattr(self._raw, name)


def _tar_stream(data: bytes, deadline: Deadline | None = None) -> Any:
    """The decompressed tar stream for ``data`` (gzip/bzip2/xz/plain)."""
    source = _DeadlineInput(io.BytesIO(data), deadline)
    if data[:2] == b"\x1f\x8b":
        return gzip.GzipFile(fileobj=source)
    if data[:3] == b"BZh":
        import bz2

        return bz2.BZ2File(source)
    if data[:6] == b"\xfd7zXZ\x00":
        import lzma

        return lzma.LZMAFile(source)
    return source


def _archive_ceiling_reason(limit: int) -> str:
    """The ONE skip reason for an archive past the decompressed ceiling."""
    return ("archive decompression exceeds logs.max_decompressed_bytes "
            f"({limit})")


def _close_best_effort(handle: Any, message: str, *args: Any) -> None:
    """Close a stream/archive, but NEVER swallow a cooperative stop.

    ``tarfile``/gzip close is normally best-effort; both are cleaned up in
    ``finally`` blocks whose generic catch used to turn a SIGTERM or an
    expired run deadline raised by ``close`` into rc 0.  A stop is re-raised;
    any other close failure is debug-logged with its redacted text.
    """
    try:
        handle.close()
    except (StopRequested, DeadlineExceeded):
        raise
    except Exception as exc:  # noqa: BLE001 — close is best-effort
        log.debug(message + ": %s", *args, redact_text(str(exc)))


def _scan_tar(source: Source, entry: Entry, bounds, scan: LogScan,
              deadline: Deadline | None = None,
              *, rank: tuple | None = None) -> None:
    archive_limit = bounds.max_archive_bytes
    if entry.size != SIZE_UNKNOWN and entry.size > archive_limit:
        _skip(scan, entry.path,
              f"size {entry.size} exceeds logs.max_archive_bytes "
              f"({archive_limit})")
        return
    data = source.read_bytes_bounded(entry.path, archive_limit)
    if len(data) > archive_limit:
        _skip(scan, entry.path,
              f"read size {len(data)} exceeds logs.max_archive_bytes "
              f"({archive_limit})")
        return
    stream = _tar_stream(data, deadline)
    limiter = _ArchiveWorkLimiter(stream, bounds.max_decompressed_bytes,
                                  deadline)
    try:
        archive = tarfile.open(fileobj=limiter, mode="r:")
    except _ArchiveWorkExceeded:
        # The FIRST 512-byte header (or a pax header) can already exceed a
        # tiny ceiling.  That is the same policy skip as an oversized
        # member walk, not an unhandled internal exception.
        _close_best_effort(stream, "logs: archive stream close failed for %s",
                           entry.path)
        _skip(scan, entry.path,
              _archive_ceiling_reason(bounds.max_decompressed_bytes))
        return
    except _ARCHIVE_READ_ERRORS as exc:
        _close_best_effort(stream, "logs: archive stream close failed for %s",
                           entry.path)
        _skip(scan, entry.path,
              f"unreadable archive: {redact_text(str(exc))}")
        return
    count = 0
    selected: list[tarfile.TarInfo] = []
    dropped = 0
    nonregular = 0
    first_nonregular: str | None = None
    oversized_nonlog = 0
    first_oversized_nonlog: str | None = None
    limit = bounds.max_files
    # A min-heap of the newest members: iteration never materializes the
    # whole member list (a 32 MiB archive can hold millions of 0-byte
    # members), and the overflow becomes ONE aggregate skipped row instead
    # of one row per dropped member.  The key is OLDEST-first (the heap's
    # root is the oldest kept member); a newest-first key made the root the
    # newest and evicted the newest on every newer arrival.
    newest: list[tuple[tuple, int, tarfile.TarInfo]] = []
    sequence = 0
    try:
        try:
            for member in archive:
                _check(deadline, "logs archive member")
                name = _valid_text(member.name)
                if not member.isfile():
                    # A log-shaped SYMTYPE/LNKTYPE was dropped before the
                    # filter and produced a silent clean (no skip row).  One
                    # row is emitted per archive below: a hostile archive can
                    # carry tens of thousands of these, and one row each
                    # bypassed logs.max_files entirely.
                    if _is_log_name(member.name):
                        nonregular += 1
                        if first_nonregular is None:
                            first_nonregular = f"{entry.path}:{name}"
                    continue
                if not _is_log_name(member.name):
                    if member.size > bounds.max_file_bytes:
                        # ONE aggregate row, never one per member: a hostile
                        # archive can carry thousands of opaque oversized
                        # members and bypass logs.max_files row-by-row.
                        oversized_nonlog += 1
                        if first_oversized_nonlog is None:
                            first_oversized_nonlog = f"{entry.path}:{name}"
                    continue
                key = _member_age_key(member)
                item = (key, sequence, member)
                sequence += 1
                if len(newest) < limit:
                    heapq.heappush(newest, item)
                    continue
                dropped += 1
                if key > newest[0][0]:
                    heapq.heapreplace(newest, item)
            # A check AFTER the last member: a final very large member is
            # decompressed during iteration, and the loop's check ran before
            # it.  Never let the archive's tail escape the budget silently.
            _check(deadline, "logs archive end")
        except _ArchiveWorkExceeded:
            _skip(
                scan, entry.path,
                _archive_ceiling_reason(bounds.max_decompressed_bytes),
            )
            return
        except _ARCHIVE_READ_ERRORS as exc:
            _skip(scan, entry.path,
                  f"unreadable archive: {redact_text(str(exc))}")
            return
        # Newest first, from the SAME oldest-first ordering the heap used.
        selected = [item[2] for item in sorted(newest, reverse=True)]
        if nonregular == 1:
            _skip(scan, first_nonregular or entry.path,
                  "member is not a regular file")
        elif nonregular:
            _skip(
                scan, entry.path,
                f"{nonregular} archive log member(s) skipped: member is not "
                f"a regular file; first: {first_nonregular}",
            )
        if dropped:
            _skip(
                scan, entry.path,
                f"{dropped} archive log member(s) exceed logs.max_files "
                f"({limit}); the newest {limit} were considered",
            )
        if oversized_nonlog:
            _skip(
                scan, entry.path,
                f"{oversized_nonlog} non-log archive member(s) exceed "
                f"logs.max_file_bytes ({bounds.max_file_bytes}); "
                f"first: {first_oversized_nonlog}",
            )
        members = len(selected)
        for member in selected:
            _check(deadline, "logs archive member read")
            # tarfile decodes member names with surrogateescape.  A lone
            # surrogate reaches every report path (redact/md_escape keep it)
            # and then UTF-8 encoding raises while writing stdout/report
            # (LOGS2).  Sanitize ONCE here, before the name becomes a path.
            member_name = _valid_text(member.name)
            member_path = f"{entry.path}:{member_name}"
            if member.size > bounds.max_file_bytes:
                _skip(scan, member_path,
                      f"member size {member.size} exceeds "
                      f"logs.max_file_bytes ({bounds.max_file_bytes})")
                continue
            try:
                handle = archive.extractfile(member)
                if handle is None:
                    _skip(scan, member_path, "member is not a regular file")
                    continue
                with handle:
                    raw = handle.read(bounds.max_file_bytes + 1)
            except _ArchiveWorkExceeded:
                # The extraction phase seeks backward and re-reads selected
                # members; a ceiling trip there must be the SAME archive
                # skip, never a raw internal exception escaping wpt logs.
                # BREAK (not return): members already read may hold real
                # matches, and the partial record must still be appended so
                # doctor sees a scanned file instead of "no log files found".
                _skip(
                    scan, entry.path,
                    _archive_ceiling_reason(bounds.max_decompressed_bytes),
                )
                break
            except _ARCHIVE_READ_ERRORS as exc:
                _skip(scan, member_path,
                      f"member read failed: {redact_text(str(exc))}")
                continue
            _check(deadline, "logs archive member read end")
            if len(raw) > bounds.max_file_bytes:
                _skip(scan, member_path,
                      f"member size exceeds logs.max_file_bytes "
                      f"({bounds.max_file_bytes})")
                continue
            lowered = posixpath.basename(member_name).lower()
            if lowered.endswith(".gz") and not lowered.endswith(
                    (".tar.gz", ".tgz")):
                # A compressed LOG member is log content, not opaque bytes:
                # selected by ``_is_log_name`` but decoded raw it produced
                # zero matches and no skip row (LOGS5).  Decompress under the
                # same per-file bound the plain path uses.
                try:
                    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as handle:
                        text_bytes = handle.read(bounds.max_file_bytes + 1)
                    # Nested decompression happens OUTSIDE tarfile's limiter:
                    # a tiny compressed member can expand to GiB.  Charge the
                    # produced bytes to the SAME archive ceiling and turn a
                    # trip into the shared skip + break (members already
                    # read keep their matches).
                    limiter._charge(len(text_bytes))
                except _ArchiveWorkExceeded:
                    _skip(
                        scan, entry.path,
                        _archive_ceiling_reason(bounds.max_decompressed_bytes),
                    )
                    break
                except _ARCHIVE_READ_ERRORS as exc:
                    _skip(scan, member_path,
                          f"unreadable gzip member: "
                          f"{redact_text(str(exc))}")
                    continue
                if len(text_bytes) > bounds.max_file_bytes:
                    _skip(scan, member_path,
                          f"decompressed member size exceeds "
                          f"logs.max_file_bytes ({bounds.max_file_bytes})")
                    continue
            elif lowered.endswith((".tar.gz", ".tgz")):
                # A nested ARCHIVE member is not a log body; say so instead
                # of silently reporting zero matches.
                _skip(scan, member_path,
                      "nested archive member is not scanned")
                continue
            else:
                text_bytes = raw
            member_mtime = _member_mtime(member)
            member_rank = (
                rank if member_mtime is None
                else (False, -member_mtime, member_path))
            count += _collect_matches(
                scan, member_path,
                text_bytes.decode("utf-8", errors="replace"),
                bounds.detail_limit, deadline, rank=member_rank)
            _check(deadline, "logs archive member end")
    finally:
        _close_best_effort(archive, "logs: archive close failed for %s",
                           entry.path)
    scan.files.append(_file_record(entry.path, len(data), "tar.gz", members,
                                   count))


# ------------------------------------------------------------------ helpers


def _candidate_dirs(webroot: str, domain: str) -> list[str]:
    """Deduped host log directories, in the contract's derivation order."""
    parts = webroot.split("/") if webroot else []
    proposed: list[str] = []
    if len(parts) >= 3 and parts[0] == "domains":
        # DirectAdmin's per-domain host logs live at domains/<domain>/logs
        # regardless of how deep the webroot is below the domain root.  The
        # old docroot-leaf gate lost them for a nested webroot such as
        # domains/site.test/public_html/blog.
        proposed.append(f"domains/{normalize_domain(parts[1])}/logs")
    parent = posixpath.dirname(webroot)
    proposed.append(posixpath.join(parent, "logs") if parent else "logs")
    proposed.append("logs")
    if domain:
        proposed.append(f"domains/{domain}/logs")
        proposed.append(f"{domain}/logs")
    directories: list[str] = []
    for candidate in proposed:
        safe = _safe_rel(candidate)
        if safe is not None and safe not in directories:
            directories.append(safe)
    return directories


def _domain_from_url(wp_url: str | None) -> str:
    """The bare hostname of ``--wp-url`` (lowercase), or ''.

    A URL typed without a scheme is still read as a host; a malformed value
    simply yields no domain (the webroot derivation remains the fallback).
    """
    value = (wp_url or "").strip()
    if not value:
        return ""
    try:
        parsed = urlparse(value)
        host = parsed.hostname
        if host is None and "://" not in value:
            host = urlparse(f"//{value}").hostname
    except ValueError:
        return ""
    return normalize_domain(host)


def _webroot_domain(webroot: str) -> str:
    """The domain encoded by the webroot's own host-layout path, or ''."""
    parts = webroot.split("/") if webroot else []
    if len(parts) >= 3 and parts[0] == "domains":
        # The domain is the account-layout segment, not a property of the
        # leaf: a nested docroot still belongs to domains/<domain>.
        return normalize_domain(parts[1])
    if len(parts) >= 2 and parts[-1] in DOCROOT_NAMES:
        return normalize_domain(parts[-2])
    return ""


def _clean_webroot(value: str | None) -> str:
    """A normalized, `..`-free webroot-relative path ('' when unusable)."""
    raw = (value or "").replace("\\", "/").strip("/")
    return _safe_rel(raw) if raw else ""


def _safe_rel(path: str) -> str | None:
    """Normalize a relative POSIX path; None when it escapes or is empty."""
    norm = posixpath.normpath(path.replace("\\", "/"))
    if norm in ("", ".", "..") or norm.startswith("/") \
            or norm.startswith("../"):
        return None
    return norm


def _is_log_name(name: str) -> bool:
    """True when a basename carries one of the candidate log shapes."""
    base = posixpath.basename(name).lower()
    return (base.endswith(_LOG_SUFFIXES)
            or base in _BARE_LOG_NAMES
            or _ERROR_LOG_MARKER in base)


def _age_key(entry: Entry) -> tuple:
    """Oldest-first key for the bounded newest heap (root = OLDEST kept).

    Python's heap is a min-heap and ``_entry_sort_key`` sorts NEWEST first,
    so using it directly would make the root the newest entry and replace
    the wrong one.  This key inverts mtime (unknown = oldest) for the heap;
    the final report order still uses ``_entry_sort_key``.
    """
    return (entry.mtime is not None, entry.mtime or 0, entry.path)


def _entry_sort_key(candidate: tuple[Source, Entry]) -> tuple:
    """Newest mtime first; an unknown mtime sorts after every known one."""
    entry = candidate[1]
    return (entry.mtime is None, -(entry.mtime or 0), entry.path)


def _member_mtime(member: tarfile.TarInfo) -> int | float | None:
    """A tar member's POSITIVE mtime, or None when tar has no real one.

    ``TarInfo.mtime`` is never None: a defaulted/zero header parses as 0
    (and writing ``mtime=None`` raises).  Zero (and a pre-1970 negative) is
    an absent timestamp, so it must take the ARCHIVE's rank instead of
    ranking as epoch (R6-42).  PAX headers may carry a finite float, which
    is a real timestamp and must stay ranked.
    """
    value = member.mtime
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value) or value <= 0:
        return None
    return value


def _member_age_key(member: tarfile.TarInfo) -> tuple:
    """Oldest-first key for the bounded newest-member heap.

    The min-heap root must be the OLDEST kept member so a newer arrival
    replaces it.  The report order inverts this same key; one rule for
    selection and rendering, never a second newest-first key that made the
    root newest and evicted the newest member (LOG-TAR-HEAP).  An absent
    (None/zero) mtime counts as oldest, exactly like a missing LIST mtime.
    """
    mtime = _member_mtime(member)
    return (mtime is not None, mtime or 0, member.name)


def _first_pattern(line: str) -> str | None:
    """The FIRST matching label for a line (a line can match several)."""
    for label, pattern in _LOG_PATTERNS:
        if pattern.search(line):
            return label
    return None


def _collect_matches(scan: LogScan, path: str, text: str,
                     detail_limit: int,
                     deadline: Deadline | None = None,
                     *, rank: tuple | None = None) -> int:
    """Count every match; store the first ``detail_limit`` rows only."""
    safe_path = redact_text(_valid_text(path))
    count = 0
    for number, line in enumerate(text.splitlines(), 1):
        _check(deadline, "logs matches")
        label = _first_pattern(line)
        if label is None:
            continue
        count += 1
        scan.total_matches += 1
        rendered = redact_text(" ".join(line.split()))[:_MAX_RENDERED_LINE]
        row = {
            "file": safe_path,
            "line": number,
            "pattern": label,
            "match": rendered,
        }
        scan.latest_matches[safe_path] = row
        if rank is not None:
            scan.latest_ranks[safe_path] = rank
        if len(scan.matches) < detail_limit:
            scan.matches.append(row)
    return count


def _file_record(path: str, size: int, kind: str, members: int,
                 matches: int) -> dict:
    return {
        "path": redact_text(_valid_text(path)),
        "bytes": size,
        "kind": kind,
        "members": members,
        "matches": matches,
    }


def _skip(scan: LogScan, path: str, reason: str) -> None:
    scan.skipped.append({
        "path": redact_text(_valid_text(path)),
        "reason": redact_text(_valid_text(" ".join(reason.split()))),
    })


def _site_label(ctx: Ctx) -> str:
    """The report title's site: public URL, else webroot, else source."""
    return safe_text(redact_text(
        ctx.wp_url or _clean_webroot(ctx.webroot)
        or ctx.source or "unknown"))


def _source_summary(ctx: Ctx) -> str:
    """One line naming what was read — never a credential."""
    webroot = _clean_webroot(ctx.webroot) or "."
    return safe_text(redact_text(
        f"{ctx.source}; webroot {webroot}; account home"))


def _valid_text(value: Any) -> str:
    """Text that every UTF-8 sink can encode.

    tarfile names arrive as surrogateescape; a lone surrogate survives
    ``redact_text`` and then raises UnicodeEncodeError when the report is
    written (LOGS2).  ``report.safe_text`` is the ONE backslashreplace
    policy, shared with the audit/scan stdout headers.
    """
    return safe_text(value)


def _text(value) -> str:
    return "" if value is None else str(value)


# --------------------------------------------------------------------- run


def run(ctx: Ctx) -> int:
    """Run ``wpt logs``; never raises for an operational failure."""
    if ctx.mode == "local":
        reason = ("wpt logs is ftp-only: a local zip has no host/webroot "
                  "error-log history to read")
        log.error("logs: %s", reason)
        _write_failure(ctx, reason)
        return 1
    try:
        deadline = Deadline.from_ctx(ctx)
        if deadline is not None:
            deadline.check("logs setup")
        scan = collect(ctx)
        markdown = scan.markdown()
        write_stdout(markdown, end="")
        log.info("logs: scanned %d file(s), %d matches, %d skipped",
                 scan.scanned, scan.total_matches, len(scan.skipped))
        if ctx.report_path is not None:
            from .actions.registry import write_report

            if write_report(ctx, "logs", markdown, scan.json_text()):
                return 1
        return 0
    except RunControl as exc:
        reason = redact_text(f"logs stopped: {exc}")
        log.error("%s", reason)
        _write_failure(ctx, reason)
        return 1
    except (WptError, OSError) as exc:
        reason = redact_text(str(exc))
        log.error("logs failed: %s", reason)
        _write_failure(ctx, reason)
        return 1


def _write_failure(ctx: Ctx, reason: str) -> None:
    """Write the small failure report when ``--report`` was asked for."""
    if getattr(ctx, "report_path", None) is None:
        return
    from .actions.registry import not_complete, write_report

    block, run_payload = not_complete(reason, status="failed")
    site = _site_label(ctx)
    markdown = f"# wpt logs — {site}\n" + block
    payload = {
        "site": site,
        "source_summary": _source_summary(ctx),
        "totals": {"scanned": 0, "matches": 0, "skipped": 0},
        "files": [],
        "matches": [],
        "skipped": [],
        "run": run_payload,
    }
    json_text = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                           indent=2) + "\n"
    try:
        write_report(ctx, "logs", markdown, json_text)
    except (Exception, RunControl) as exc:  # noqa: BLE001 — never replace the reason
        log.warning("logs: could not write the failure report: %s",
                    redact_text(str(exc)))
