"""Bounded hostname resolution — ONE owner for every transport.

``socket.getaddrinfo`` is a blocking libc call that ignores socket timeouts.
A stalled resolver therefore outlived both the HTTP probe's absolute deadline
and the database/FTP connect budget.  Every transport that must honour a run
budget resolves through :func:`resolve_host_bounded`, which runs the lookup in
a daemon worker joined for the remaining budget.

LIMITATION (stated): a libc ``getaddrinfo`` that never returns cannot be
cancelled — up to :data:`DNS_WORKER_LIMIT` daemon workers linger until the
resolver answers, but each owns no socket and never blocks process exit.
The semaphore refuses a further lookup once that ceiling is reached instead
of growing the thread set without bound.
"""

from __future__ import annotations

import socket
import threading
import time

from .types import WptError

__all__ = [
    "DNS_WORKER_LIMIT", "DNS_WORKERS", "is_numeric_host",
    "resolve_host_bounded",
]

#: Structural resource ceiling, not an operator tunable: libc getaddrinfo
#: cannot be cancelled, so a resolver that never returns leaves its daemon
#: worker behind.  At most this many unresolved lookups may coexist; the
#: next caller fails fast instead of growing the thread set without bound.
DNS_WORKER_LIMIT = 4
DNS_WORKERS = threading.BoundedSemaphore(DNS_WORKER_LIMIT)


def is_numeric_host(host: str) -> bool:
    """True for an IPv4/IPv6 literal (no name resolution needed)."""
    candidate = host.strip("[]")
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, candidate)
            return True
        except OSError:
            continue
    return False


def resolve_host_bounded(host: str, port: int, deadline: float, *,
                         label: str = "DNS resolution",
                         thread_name: str = "wpt-dns") -> list[str]:
    """Resolve ``host`` to an ORDERED list of numeric addresses in budget.

    ``deadline`` is an absolute ``time.monotonic()`` instant.  EVERY address
    is returned, in the resolver's preference order, so callers can fall
    back across families exactly like stdlib ``socket.create_connection``
    (an IPv6-first host whose AAAA route is dead must still reach its IPv4
    address).  Duplicates are removed and numeric literals are returned
    unchanged without a lookup.

    ``label`` names the caller in the refusal (``probe DNS resolution``,
    ``database host DNS resolution``); ``thread_name`` keeps the worker
    attributable in diagnostics.
    """
    if is_numeric_host(host):
        return [host.strip("[]")]
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise WptError(
            f"{label} for {host!r} exceeded the request deadline")
    if not DNS_WORKERS.acquire(blocking=False):
        raise WptError(
            f"{label} for {host!r} is saturated: "
            f"{DNS_WORKER_LIMIT} resolver worker(s) are still blocked; "
            "refusing to start another (wait for the resolver or retry)")
    outcome: list[object] = []

    def _work() -> None:
        try:
            outcome.append(socket.getaddrinfo(
                host, port, type=socket.SOCK_STREAM))
        except BaseException as exc:  # noqa: BLE001 — relayed to the caller
            outcome.append(exc)
        finally:
            DNS_WORKERS.release()

    worker = threading.Thread(target=_work, name=thread_name, daemon=True)
    try:
        worker.start()
    except BaseException:
        DNS_WORKERS.release()
        raise
    worker.join(remaining)
    if worker.is_alive():
        raise WptError(
            f"{label} for {host!r} exceeded the request deadline")
    if not outcome:
        raise WptError(f"{label} for {host!r} returned nothing")
    result = outcome[0]
    if isinstance(result, BaseException):
        raise WptError(f"{label} for {host!r} failed: {result}")
    if not result:
        raise WptError(f"{label} for {host!r} found no address")
    addresses: list[str] = []
    for record in result:
        try:
            address = str(record[4][0])
        except (IndexError, TypeError):
            continue
        if address and address not in addresses:
            addresses.append(address)
    if not addresses:
        raise WptError(f"{label} for {host!r} found no address")
    return addresses
