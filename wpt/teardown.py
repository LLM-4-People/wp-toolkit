"""The ONE stack-teardown owner.

Every command that builds a ``(source, session, bridge)`` trio must end it
the same way: attempt EVERY cleanup independently (one stop must not skip
the next), keep ``StopRequested``/``DeadlineExceeded`` as the run-ending
verdict, and never let a generic cleanup error mask the command's result.
The session is part of the trio (HTTP pool + cookies); forgetting it leaked
one connection pool per embedded run.

This module exists so ``registry``, ``backup``, ``restore``, ``walk`` and
``verify`` cannot drift into five slightly different lifetimes.  It owns
ordering, message shape and the stop/deadline classification — nothing else.
"""

from __future__ import annotations

from contextlib import nullcontext

from .config import redact_text
from .log import get_logger
from .types import DeadlineExceeded, StopRequested

__all__ = ["source_cleanup_budget", "teardown_stack"]

log = get_logger("teardown")


def source_cleanup_budget(source):
    """A source's fresh finite cleanup budget, or a no-op context.

    Cleanup (bridge/probe deletion, close) runs BECAUSE a run stopped, often
    with its deadline already spent.  A source that keeps honouring the
    expired budget cannot issue the DELE/close it owes.  ``Source`` owns the
    fresh-budget swap; a non-Source double without it keeps working
    unchanged.  ONE owner so every teardown path applies the same rule.
    """
    suspend = getattr(source, "deadline_suspended", None)
    return suspend() if callable(suspend) else nullcontext()


def teardown_stack(stack: tuple, label: str) -> BaseException | None:
    """Run bridge/source/session cleanups; return the FIRST cooperative stop.

    ``stack`` is any ``(source, session, bridge)``-shaped tuple; missing or
    ``None`` members are skipped, so local-mode stacks and test doubles
    work unchanged.  Generic failures are warnings; a cooperative stop is
    remembered and returned to the caller, which decides whether it ends
    the run (and whether the report it already wrote must be replaced).
    """
    bridge = stack[2] if len(stack) > 2 else None
    source = stack[0] if stack else None
    session = stack[1] if len(stack) > 1 else None
    first_stop: BaseException | None = None

    if bridge is not None:
        destroy = getattr(bridge, "destroy", None)
        if callable(destroy):
            try:
                with source_cleanup_budget(source):
                    destroy()
            except (StopRequested, DeadlineExceeded) as exc:
                first_stop = first_stop or exc
            except Exception as exc:  # noqa: BLE001 — teardown is best-effort
                log.warning(
                    "%s: bridge teardown failed (the bridge may "
                    "self-destruct on its token expiry): %s",
                    label, redact_text(str(exc)))

    if source is not None:
        close = getattr(source, "close", None)
        if callable(close):
            try:
                with source_cleanup_budget(source):
                    close()
            except (StopRequested, DeadlineExceeded) as exc:
                first_stop = first_stop or exc
            except Exception as exc:  # noqa: BLE001 — teardown is best-effort
                log.warning("%s: source close failed: %s", label,
                            redact_text(str(exc)))

    if session is not None:
        close = getattr(session, "close", None)
        if callable(close):
            try:
                close()
            except (StopRequested, DeadlineExceeded) as exc:
                first_stop = first_stop or exc
            except Exception as exc:  # noqa: BLE001 — teardown is best-effort
                log.warning("%s: session close failed: %s", label,
                            redact_text(str(exc)))

    return first_stop
