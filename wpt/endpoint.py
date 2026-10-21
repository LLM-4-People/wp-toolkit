"""The one expiry-aware sweep for wpt's deployed PHP endpoints.

The bridge and the standalone probe both upload a short-lived token-gated
file and both leave one behind when a run is killed.  Their stale-file
sweeps share one safety rule: a candidate is deletable ONLY when its own
embedded ``$wpt_expires`` literal has passed; an unreadable, oversized or
unparseable candidate is skipped with a warning, never guessed dead.  A
sibling wpt run may own a live endpoint, so a name alone is never proof.

This module owns the loop; callers own only the name predicate, the read
bound and the log noun.  The audit's sweep additionally owns the FTP
source it built, so it passes ``on_stop`` to close that source before a
cooperative stop or deadline propagates.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable

from .bridge_name import endpoint_expiry
from .log import get_logger
from .types import DeadlineExceeded, Entry, SIZE_UNKNOWN, Source, StopRequested

log = get_logger("endpoint")


def sweep_expired_endpoints(
    source: Source,
    entries: Iterable[Entry],
    *,
    kind: str,
    matches: Callable[[str], bool],
    read_limit: int,
    on_stop: Callable[[], None] | None = None,
    logger: logging.Logger | None = None,
    delete_label: str = "expired",
) -> tuple[int, int]:
    """Delete every expired ``kind`` endpoint under this sweep's rules.

    Returns ``(removed, skipped)`` and logs one info line for each non-zero
    count.  ``matches`` receives the webroot-relative path; ``on_stop`` is
    the caller's ownership hook (the audit closes the source it built).
    """
    _log = logger or log
    removed = skipped = 0
    for entry in entries:
        if entry.is_dir or entry.is_link or not matches(entry.path):
            continue
        if entry.size == SIZE_UNKNOWN:
            _log.warning("%s-shaped file %s has an unverifiable listing "
                        "size; leaving it in place", kind, entry.path)
            skipped += 1
            continue
        if entry.size > read_limit:
            _log.warning("%s-shaped file %s is %d B (over the %d B sweep "
                        "bound); leaving it in place", kind, entry.path,
                        entry.size, read_limit)
            skipped += 1
            continue
        try:
            raw = source.read_bytes_bounded(entry.path, read_limit)
            if len(raw) > read_limit:
                _log.warning("%s-shaped file %s read %d B (over the %d B "
                            "sweep bound); leaving it in place", kind,
                            entry.path, len(raw), read_limit)
                skipped += 1
                continue
            text = raw.decode("utf-8", "replace")
        except (StopRequested, DeadlineExceeded):
            if on_stop is not None:
                on_stop()
            raise
        except Exception as exc:  # noqa: BLE001 — one candidate must not
            # abort the sweep; an unreadable file is never deleted unverified.
            _log.warning("%s-shaped file %s not readable; leaving it in "
                        "place: %s", kind, entry.path, exc)
            skipped += 1
            continue
        try:
            expiry = endpoint_expiry(text)
        except ValueError:
            # Above Python's 4300-digit int limit; not verifiably expired.
            _log.warning("%s-shaped file %s carries an unparseable expiry "
                        "literal; leaving it in place", kind, entry.path)
            skipped += 1
            continue
        if expiry is None:
            _log.warning("%s-shaped file %s carries no expiry literal; "
                        "leaving it in place", kind, entry.path)
            skipped += 1
            continue
        # The PHP gate is ``time() > expiry``: at the exact expiry second
        # the endpoint still answers, so equality is LIVE.
        if expiry >= int(time.time()):
            skipped += 1
            continue
        try:
            source.delete(entry.path)
            removed += 1
        except (StopRequested, DeadlineExceeded):
            if on_stop is not None:
                on_stop()
            raise
        except Exception as exc:  # noqa: BLE001 — a stuck expired file must
            # not fail the command; its own TTL gate already neutralized it.
            _log.warning("%s %s file %s could not be removed: %s",
                        delete_label, kind, entry.path, exc)
    if removed:
        _log.info("swept %d expired %s file(s) from the webroot "
                 "(left by a killed run)", removed, kind)
    if skipped:
        _log.info("left %d %s file(s) in place (expiry still live or "
                 "unverifiable)", skipped, kind)
    return removed, skipped
