"""Tests for wpt.deadline — the self-bounding budget primitive.

The contract under test:
  from_ctx ................ ctx.deadline_s None/0/negative -> None
                            (unbounded); positive -> a Deadline
  check .................... raises DeadlineExceeded once expired, with
                            the phase name + the policy hint in the
                            message; never raises before expiry
  monotonic clock .......... the budget is a wall-time SPAN (immune to
                            clock jumps, verified via an injected clock)
  early exit ............... a budget already smaller than the elapsed
                            startup raises on the FIRST check
"""

import pytest

from wpt.cli import Ctx
from wpt.deadline import Deadline
from wpt.settings import load
from wpt.types import (DeadlineExceeded, RunControl, StopRequested, WptError)


def _ctx(seconds=None, **overrides):
    kwargs = dict(source="local", settings=load())
    if seconds is not None:
        kwargs["deadline_s"] = seconds
    kwargs.update(overrides)
    return Ctx(**kwargs)


def test_from_ctx_unbounded_shapes():
    assert Deadline.from_ctx(_ctx()) is None                # attribute absent
    assert Deadline.from_ctx(_ctx(0)) is None               # explicit off
    assert Deadline.from_ctx(_ctx(-5)) is None              # nonsense is off


def test_from_ctx_positive():
    d = Deadline.from_ctx(_ctx(120))
    assert d is not None
    assert d._seconds == 120.0


def test_from_ctx_is_one_budget_per_ctx():
    """A later call inside a command must NOT restart the wall clock after
    expensive pre-work (C8: deadline starts late)."""
    ctx = _ctx(120)
    first = Deadline.from_ctx(ctx)
    first._started -= 121
    second = Deadline.from_ctx(ctx)
    assert second is first
    assert second.expired


def test_check_raises_only_after_expiry():
    d = Deadline(60)
    d.check("capture")            # plenty of budget left
    d.check("capture")            # still fine
    d._started -= 61              # simulate elapsed wall time
    with pytest.raises(DeadlineExceeded) as ei:
        d.check("capture")
    assert "run deadline of 60s exceeded" in str(ei.value)
    assert "'capture'" in str(ei.value)
    assert "--deadline" in str(ei.value)


def test_expired_property_and_early_exit():
    d = Deadline(1)
    d._started -= 2
    assert d.expired
    with pytest.raises(DeadlineExceeded):
        d.check("first-check")


def test_deadline_exceeded_is_run_control_not_wpt_error():
    """RunControl is a BaseException: no operational catch can eat it."""
    assert issubclass(DeadlineExceeded, RunControl)
    assert issubclass(StopRequested, RunControl)
    assert not issubclass(RunControl, Exception)
    assert not issubclass(DeadlineExceeded, WptError)
    d = Deadline(1)
    d._started -= 5
    with pytest.raises(DeadlineExceeded):
        d.check("anything")


def test_generic_except_exception_cannot_eat_run_control():
    """A plain ``except Exception`` must not turn a stop/deadline into a
    partial result — the failure class the whole RunControl refactor fixes.
    """
    caught: list[str] = []
    for signal in (StopRequested("SIGTERM"), DeadlineExceeded("deadline")):
        try:
            try:
                raise signal
            except Exception:  # noqa: BLE001 — the pattern under test
                caught.append(type(signal).__name__)
        except RunControl as exc:
            assert exc is signal
    assert caught == []


def test_budget_is_monotonic_span(monkeypatch):
    """The clock seam is monotonic (jump-immune): patch wpt.deadline's
    clock and verify the span math, not the wall clock."""
    now = [1000.0]
    monkeypatch.setattr("wpt.deadline._CLOCK", lambda: now[0])
    d = Deadline(30)
    now[0] = 1031.0
    with pytest.raises(DeadlineExceeded):
        d.check("phase")
    now[0] = 1029.0  # back inside the budget: property reflects the span
    assert not d.expired


def test_R24_deadline_and_source_label_have_one_owner():
    """R24-P2: backup and media_refs each carried a private
    ``_check_deadline`` and discover/files each a ``_source_label``.  Both
    rules now live once, in the shared owners."""
    import wpt.backup as backup
    import wpt.discover as discover
    import wpt.files as files
    import wpt.media_refs as media_refs
    import wpt.report as report
    from wpt.deadline import check_deadline

    assert backup.check_deadline is check_deadline
    assert media_refs.check_deadline is check_deadline
    assert discover.safe_source_label is report.safe_source_label
    assert not hasattr(discover, "_source_label")
    assert not hasattr(files, "_source_label")
    assert not hasattr(backup, "_check_deadline")
    assert not hasattr(media_refs, "_check_deadline")
