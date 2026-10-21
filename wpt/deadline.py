"""Run deadlines — the tool's self-bounding primitive.

WHY THIS EXISTS (binding): wpt never gets killed from the outside. A wedged
or crawling run (a stale FTP passive channel grinding at one op per 30s,
a walk against a dying origin) ends ITSELF when its wall-time budget runs
out: :class:`Deadline` is that budget. Hot loops call :meth:`Deadline.check`
between work items; on expiry it raises :class:`~wpt.types.DeadlineExceeded`,
a :class:`~wpt.types.RunControl` ``BaseException``.  That class deliberately
bypasses every command's operational ``(WptError, OSError)`` contract and
every generic ``except Exception`` handler, so the expiry can never be
converted into a partial success or a diagnosis row.  The command's
``finally`` teardowns still run, then the ONE dispatch boundary (and
``run_action`` for registered actions) logs the reason, writes the shared
failure markdown + JSON pair when ``--report`` was asked for, and returns
rc 1.  No external kill, no orphaned bridge files, no partial snapshots
left lying around.

The budget is policy, so it is SETTINGS + CLI, never code: the packaged
default lives at ``run.deadline_s`` (3600s) and ``--deadline SECONDS``
overrides it per invocation; ``0`` disables the bound entirely (explicitly
opting out is a choice the operator can make — a hidden unbounded run is
not).

``Deadline.from_ctx(ctx)`` is the ONE construction seam: it reads
``ctx.deadline_s`` (cli resolves the flag-override into the field; ``None``
or falsy = unbounded) and MEMOIZES the instance on the ctx.  The CLI builds
it once at dispatch, before any command work, and every later
``from_ctx`` in that run returns the SAME budget — so a second call inside
a command can never restart the clock after expensive pre-work (walk,
identity read, scope expansion, wp.org fetch).  Hot loops that receive a
ctx build it once at loop entry and :meth:`check` per item with a short
human context label that names the phase in the expiry message ("capture",
"suspicious scan", "walk").  Checks between items are O(1) (a monotonic
read + compare) and never raise before the first item completes — a fast
run pays nothing.

THE DELIBERATE EXCEPTION: the two long-running listeners, ``wpt serve`` and
``wpt proxy``, own their process until interrupted. Their accept loop is not
bounded by ``--deadline`` (a served rehearsal or migrated browser session
must stay up for as long as the operator needs it); SIGTERM/SIGINT still end
both cleanly through their own teardown. Every other command ends itself
when the budget expires.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from .types import DeadlineExceeded

if TYPE_CHECKING:
    from .cli import Ctx

__all__ = ["Deadline", "bounded_walk", "check_deadline", "transport_kwargs"]


def transport_kwargs(deadline: "Deadline | None") -> dict[str, float]:
    """Keyword arguments for an absolute-deadline transport call.

    ONE owner for the ``bridge.call(..., deadline=<monotonic>)`` shape:
    an unbounded run passes NOTHING (so a wire double sees the same call it
    always did), and a bounded run passes the absolute instant
    :attr:`Deadline.at` — never a fresh relative timeout.
    """
    return {} if deadline is None else {"deadline": deadline.at}

_CLOCK = time.monotonic


def bounded_walk(source, deadline: "Deadline | None", context: str,
                 **walk_kwargs):
    """Walk a source under the run budget: per entry AND at the end.

    ``source.walk()`` is lazy, so a slow remote listing used to consume
    work until the loop ended and only THEN see an expired budget.  ONE
    helper for every action that walks a core tree, so the per-entry and
    end checks cannot drift between heal-core, update-core and prune-core.
    ``walk_kwargs`` pass the connector's own walk options (``path``,
    ``include_links``) without a second bounded-walk implementation.
    """
    for entry in source.walk(**walk_kwargs):
        if deadline is not None:
            deadline.check(context)
        yield entry
    if deadline is not None:
        deadline.check(f"{context} end")


def check_deadline(deadline: "Deadline | None", context: str) -> None:
    """Check a run budget when the caller may be unbounded.

    ONE shared wrapper for the ``if deadline is not None: deadline.check``
    shape: an unbounded run passes None and this is a no-op, while every
    bounded caller raises the same :class:`DeadlineExceeded` at the same
    owner.  Keeping this here means backup/media verification cannot drift
    into two private copies of the same rule.
    """
    if deadline is not None:
        deadline.check(context)


class Deadline:
    """One run's wall-time budget (monotonic; immune to clock jumps)."""

    def __init__(self, seconds: float) -> None:
        self._started = _CLOCK()
        self._seconds = float(seconds)
        self._expired_at: str | None = None

    @classmethod
    def from_ctx(cls, ctx: "Ctx") -> "Deadline | None":
        """The run's budget from ``ctx.deadline_s``; None = unbounded.

        ONE budget per ctx: the first call constructs and stores it on the
        ctx; every later call returns that same instance.  The CLI calls it
        before dispatch, so a command's own (later) call cannot restart the
        clock after its expensive pre-work.
        """
        existing = getattr(ctx, "_deadline", None)
        if isinstance(existing, Deadline):
            return existing
        seconds = getattr(ctx, "deadline_s", None)
        if not seconds or float(seconds) <= 0:
            return None
        deadline = cls(float(seconds))
        try:
            ctx._deadline = deadline
        except (AttributeError, TypeError):  # a frozen/slots ctx stays usable
            pass
        return deadline

    @property
    def expired(self) -> bool:
        return (_CLOCK() - self._started) > self._seconds

    @property
    def remaining(self) -> float:
        """Seconds left (never negative) — the transport-timeout cap."""
        return max(0.0, self.at - _CLOCK())

    @property
    def at(self) -> float:
        """The absolute ``time.monotonic()`` instant this budget expires.

        The ONE bridge from a run budget to an absolute-deadline transport
        (doctor's HTTP GETs, wp.org): the transport must not restart a full
        per-request timeout after the run has already spent its budget.
        """
        return self._started + self._seconds

    def check(self, context: str) -> None:
        """Raise DeadlineExceeded when the budget is spent.

        ``context`` names the phase in the message ("capture", "walk").
        Idempotent after the first raise (the run is ending anyway); a
        check before any work (budget already smaller than startup time)
        raises immediately — the honest early exit.
        """
        if self.expired:
            if self._expired_at is None:
                self._expired_at = context
            raise DeadlineExceeded(
                f"run deadline of {self._seconds:g}s exceeded at "
                f"{context!r} — the run ends itself now (cleanup runs; "
                "raise --deadline / run.deadline_s to extend, or set 0 "
                "to disable the bound)"
            )
