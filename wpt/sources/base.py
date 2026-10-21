"""Shared connector logic.

walk() is implemented ONCE here in terms of each connector's list_dir() — the
DRY choke point for tree traversal. Symlinked directories are never followed
(lesson L10: private_html -> public_html double-counts a whole webroot).

read_many() is the serial bulk-read DEFAULT every connector inherits; the
FTPS connector overrides it with parallel worker sessions (see ftp.py) under
the identical (ok, failed) contract.

Progress heartbeat [L15 — a live audit's tree walk ran ~10 minutes with
ZERO log output; the operator could not tell a crawling channel from a
wedged run]: walk() emits ONE info line — ``webroot walk: <N> entries so
far (<T>s elapsed)`` — at every _WALK_HEARTBEAT_EVERY-entry milestone once
_WALK_HEARTBEAT_MIN_S has passed since the last line.  The double gate
keeps an in-memory zip walk silent (it never lasts the interval) while a
crawling FTP channel reports pace every interval — log cadence only, never
behavior, the backup.py _HEARTBEAT_EVERY precedent: no operator decision
changes what a walk returns, so the no-static-configurables rule stops at
the logging boundary.  Both constants are module-level so tests can pin
them to (1, 0.0) and force deterministic heartbeats.
"""

import posixpath
import time
from typing import Iterator

from ..log import get_logger
from ..types import (DeadlineExceeded, Entry, Source, SourceError,
                     StopRequested)

log = get_logger("sources.walk")


def close_source(source: Source, label: str) -> None:
    """Close a source, re-raising a cooperative stop/deadline.

    Teardown is best-effort for ordinary errors, but ``StopRequested`` and
    ``DeadlineExceeded`` are the run-ending events: swallowing them made a
    SIGTERM during close report success (the run wrote its report and
    returned rc 0).  One helper so every command path applies the same rule;
    the stop is re-raised only AFTER the close attempt, never instead of it.
    """
    try:
        source.close()
    except (StopRequested, DeadlineExceeded):
        raise
    except Exception as exc:  # noqa: BLE001 — teardown must not mask data
        from ..config import redact_text

        log.warning("%s: source close failed: %s", label,
                    redact_text(str(exc)))

#: Heartbeat milestone (entries) — structural log-cadence constant (see
#: the module docstring), NOT a settings tunable.
_WALK_HEARTBEAT_EVERY = 500

#: Heartbeat minimum spacing (seconds) — structural log-cadence
#: constant; also the gate that keeps fast walks silent.
_WALK_HEARTBEAT_MIN_S = 10.0


class WalkMixin(Source):
    """Generic walk + serial bulk read built on the connector primitives
    (list_dir / read_bytes); connectors only implement the primitives."""

    def walk(self, path: str = "", *,
             include_links: bool = False) -> Iterator[Entry]:
        root = self._guard_path(path) if path else ""
        stack: list[str] = [root] if root else [""]
        seen_dirs: set[str] = set()
        emitted = 0
        started = time.monotonic()
        last_beat = started

        def _beat() -> None:
            nonlocal emitted, last_beat
            emitted += 1
            if emitted % _WALK_HEARTBEAT_EVERY == 0:
                now = time.monotonic()
                if now - last_beat >= _WALK_HEARTBEAT_MIN_S:
                    last_beat = now
                    log.info(
                        "webroot walk: %d entries so far (%.0fs elapsed)",
                        emitted, now - started,
                    )

        while stack:
            current = stack.pop(0)
            if current in seen_dirs:
                # A connector that lists its own current directory (a
                # normalized double separator once synthesized Entry(""))
                # could push the same path forever; one listing per
                # directory is the walk contract.
                continue
            seen_dirs.add(current)
            entries = self.list_dir(current)
            # A connector-returned name is DATA, not an operator path: the
            # shared guard refuses a name it would have to rewrite (a
            # literal backslash) instead of letting a later read address a
            # different file.  One validation point for every walker.
            for entry in entries:
                self._guard_returned_path(entry.path)
            dirs = sorted((e for e in entries if e.is_dir), key=lambda e: e.path)
            files = sorted((e for e in entries if not e.is_dir), key=lambda e: e.path)
            for entry in dirs:
                if not entry.path or entry.path == current:
                    continue
                if entry.is_link:
                    # never follow linked directories (double-count guard);
                    # a caller removing a tree can ASK for the link itself
                    # (delete it, never descend) — rmdir_recursive does.
                    if include_links:
                        yield entry
                        _beat()
                    continue
                yield entry
                _beat()
                stack.append(entry.path)
            for entry in files:
                if entry.is_link:
                    if include_links:
                        yield entry
                        _beat()
                    continue
                yield entry
                _beat()

    def read_many(self, paths: list[str], *, max_bytes: int | None = None
                  ) -> tuple[dict[str, bytes], dict[str, str]]:
        """Bulk-read many files; returns (ok, failed).

        ``max_bytes`` caps EVERY read through ``read_bytes_bounded`` so a
        lying listing size can never materialize an unbounded body; None
        keeps the historical unbounded contract.  ``ok`` maps path -> file
        bytes; ``failed`` maps path -> the error text of its per-path
        failure. A (SourceError, OSError) from one path's read_bytes lands
        in ``failed`` — callers treat entries there as PER-PATH answers
        (skip that file, debug the message) and keep going. Any OTHER
        exception propagates: a RAISE is RUN-LEVEL (the caller aborts the
        whole operation); it is never a per-path answer. Connectors with a
        faster bulk path (FTPS: parallel worker sessions) override this
        with the same semantics.
        """
        ok: dict[str, bytes] = {}
        failed: dict[str, str] = {}
        for path in paths:
            try:
                if max_bytes is None:
                    ok[path] = self.read_bytes(path)
                else:
                    ok[path] = self.read_bytes_bounded(path, max_bytes)
            except (SourceError, OSError) as e:
                failed[path] = str(e)
        return ok, failed

    @staticmethod
    def _join(parent: str, name: str) -> str:
        """POSIX-join a child name onto a parent relpath ('' == root)."""
        return posixpath.join(parent, name) if parent else name
