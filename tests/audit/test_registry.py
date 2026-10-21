"""Unit tests for the audit check registry (registration, selection, pipeline).

Every check here is registered through the real decorator under a unique
"t.w6a."-prefixed dotted name: the registry is a process-global store with no
unregister API, so each test owns a fresh subgroup to stay isolated from the
other tests and from the real checks that land in W6b+.
"""

import logging

import pytest

from wpt.audit.registry import (
    MODES,
    all_checks,
    register_check,
    run_checks,
    select_checks,
)
from wpt.audit import registry as _registry
from wpt.settings import Settings
from wpt.types import Finding, WptError


@pytest.fixture(autouse=True)
def _isolate_registry():
    """Snapshot/restore the module-global check store around every test.

    ``_register`` mutates the real ``_CHECKS`` dict; without this, a
    throwaway check (especially one that RAISES) leaks into other test
    modules that run the full registry, polluting their findings.
    """
    saved = dict(_registry._CHECKS)
    yield
    _registry._CHECKS.clear()
    _registry._CHECKS.update(saved)


@pytest.fixture
def wpt_caplog(caplog):
    """caplog wired to the non-propagating wpt logger tree.

    The wpt parent logger has propagate=False (wpt.log), so its records never
    reach the root logger pytest listens on — attach the handler directly.
    """
    parent = logging.getLogger("wpt")
    parent.addHandler(caplog.handler)
    with caplog.at_level(logging.DEBUG, logger="wpt"):
        yield caplog
    parent.removeHandler(caplog.handler)


def _register(name, *, applies=("ftp", "local"), findings=(), calls=None, raises=None):
    """Register one throwaway check; records (name, data, settings) in ``calls``."""

    @register_check(name, applies=applies)
    def _check(data, settings):
        if calls is not None:
            calls.append((name, data, settings))
        if raises is not None:
            raise raises
        return list(findings)

    return _check


def _names(records):
    return [rec.name for rec in records]


def _finding(tag):
    return Finding(category="t.w6a.finding", name=tag, detail=f"detail for {tag}",
                   bytes=128, count=3, risk="medium", fix="do something")


# ------------------------------------------------------------ registration


def test_register_stores_name_applies_and_func():
    def _both(data, settings):
        return []

    def _ftp_only(data, settings):
        return []

    returned_both = register_check("t.w6a.store.both", applies=["ftp", "local"])(_both)
    returned_ftp = register_check("t.w6a.store.ftp", applies=("ftp",))(_ftp_only)
    assert returned_both is _both and returned_ftp is _ftp_only  # decorator returns the func
    rec_both = next(r for r in all_checks() if r.name == "t.w6a.store.both")
    rec_ftp = next(r for r in all_checks() if r.name == "t.w6a.store.ftp")
    assert rec_both.applies == ("ftp", "local")  # list input normalized to a tuple
    assert rec_ftp.applies == ("ftp",)
    assert rec_both.func is _both and rec_ftp.func is _ftp_only


def test_all_checks_preserves_registration_order():
    _register("t.w6a.order.second")
    _register("t.w6a.order.first")
    names = [r.name for r in all_checks()]
    assert names.index("t.w6a.order.second") < names.index("t.w6a.order.first")


def test_duplicate_name_raises_runtime_error():
    original = _register("t.w6a.dup.check", applies=("ftp",))

    with pytest.raises(RuntimeError):

        @register_check("t.w6a.dup.check", applies=["local"])
        def _impostor(data, settings):
            return []

    rec = next(r for r in all_checks() if r.name == "t.w6a.dup.check")
    assert rec.func is original  # first registration wins, never last-wins


def test_invalid_applies_raises_value_error():
    with pytest.raises(ValueError):

        @register_check("t.w6a.badap.cloud", applies=("ftp", "cloud"))
        def _cloud(data, settings):
            return []

    with pytest.raises(ValueError):  # a bare string would iterate per character

        @register_check("t.w6a.badap.bare", applies="ftp")
        def _bare(data, settings):
            return []

    with pytest.raises(ValueError):

        @register_check("t.w6a.badap.none", applies=None)
        def _none(data, settings):
            return []


def test_empty_name_raises_value_error():
    with pytest.raises(ValueError):
        register_check("", applies=("ftp",))


def test_empty_applies_is_a_valid_subset_but_never_selected():
    _register("t.w6a.empty.check", applies=())
    rec = next(r for r in all_checks() if r.name == "t.w6a.empty.check")
    assert rec.applies == ()
    for mode in MODES:
        assert rec not in select_checks(mode, None, None)


# ------------------------------------------------------------ selection


def test_select_filters_by_mode():
    _register("t.w6a.mode.ftp", applies=("ftp",))
    _register("t.w6a.mode.local", applies=("local",))
    _register("t.w6a.mode.both", applies=("ftp", "local"))
    ftp = [n for n in _names(select_checks("ftp", None, None)) if n.startswith("t.w6a.mode.")]
    local = [n for n in _names(select_checks("local", None, None)) if n.startswith("t.w6a.mode.")]
    assert ftp == ["t.w6a.mode.both", "t.w6a.mode.ftp"]
    assert local == ["t.w6a.mode.both", "t.w6a.mode.local"]


def test_select_only_union_and_dotted_prefix():
    _register("t.w6a.sel.g.one")
    _register("t.w6a.sel.g.two")
    _register("t.w6a.sel.exact")
    _register("t.w6a.sel.other")
    # dotted prefix selects the whole group
    assert _names(select_checks("ftp", ["t.w6a.sel.g"], None)) == \
        ["t.w6a.sel.g.one", "t.w6a.sel.g.two"]
    # exact-name selector
    assert _names(select_checks("ftp", ["t.w6a.sel.exact"], None)) == ["t.w6a.sel.exact"]
    # union across selectors
    assert _names(select_checks("ftp", ["t.w6a.sel.g.two", "t.w6a.sel.other"], None)) == \
        ["t.w6a.sel.g.two", "t.w6a.sel.other"]
    # a prefix must fall on a dot boundary: a partial component matches
    # nothing — and FAILS LOUD (a non-matching selector must never pass
    # silently as an empty selection)
    with pytest.raises(WptError, match="t.w6a.sel.g.o"):
        select_checks("ftp", ["t.w6a.sel.g.o"], None)


def test_select_skip_wins_over_only():
    _register("t.w6a.sk.g.one")
    _register("t.w6a.sk.g.two")
    _register("t.w6a.sk.h.one")
    assert _names(select_checks("ftp", ["t.w6a.sk.g"], ["t.w6a.sk.g.one"])) == \
        ["t.w6a.sk.g.two"]
    assert _names(select_checks("ftp", ["t.w6a.sk.g.one"], ["t.w6a.sk.g.one"])) == []


def test_select_skip_alone_subtracts():
    _register("t.w6a.skip.g.one")
    _register("t.w6a.skip.g.two")
    _register("t.w6a.skip.h.one")
    everything = set(_names(select_checks("ftp", None, None)))
    minus = _names(select_checks("ftp", None, ["t.w6a.skip.g"]))
    assert set(minus) == everything - {"t.w6a.skip.g.one", "t.w6a.skip.g.two"}
    assert minus == sorted(minus)  # subtraction keeps deterministic order


def test_select_none_and_empty_only_skip_equivalent():
    _register("t.w6a.none.check")
    base = _names(select_checks("ftp", None, None))
    assert _names(select_checks("ftp", [], [])) == base
    assert _names(select_checks("ftp", [], None)) == base
    assert _names(select_checks("ftp", None, [])) == base
    assert "t.w6a.none.check" in base


def test_select_returns_name_sorted():
    _register("t.w6a.sort.zeta")
    _register("t.w6a.sort.alpha")
    _register("t.w6a.sort.mid")
    assert _names(select_checks("ftp", ["t.w6a.sort"], None)) == \
        ["t.w6a.sort.alpha", "t.w6a.sort.mid", "t.w6a.sort.zeta"]


def test_select_unknown_selector_fails_loud():
    """A selector matching no applicable check is a USAGE ERROR: an empty
    selection would read as 'that check ran and passed' (live lesson: a
    validation step filtered to a nonexistent check name and produced an
    empty report mistaken for a confirmation)."""
    _register("t.w6a.warn.real")
    with pytest.raises(WptError, match="matched no ftp-mode check"):
        select_checks("ftp", ["t.w6a.warn.nothing"], None)

    # unknown selectors in skip fail identically (the operator asked to
    # exclude something that does not exist)
    with pytest.raises(WptError, match="t.w6a.warn.absent"):
        select_checks("ftp", ["t.w6a.warn.real"], ["t.w6a.warn.absent"])

    # a matching selection stays silent and succeeds
    assert _names(select_checks("ftp", ["t.w6a.warn.real"], None)) == \
        ["t.w6a.warn.real"]


def test_select_unknown_mode_raises():
    assert set(MODES) == {"ftp", "local"}
    with pytest.raises(ValueError):
        select_checks("cloud", None, None)


# ------------------------------------------------------------ run pipeline


def test_run_checks_passes_data_and_settings_positionally():
    calls = []
    _register("t.w6a.run.b", calls=calls)
    _register("t.w6a.run.a", calls=calls)

    @register_check("t.w6a.run.strict", applies=("ftp", "local"))
    def _positional_only(data, settings, /):  # keyword calls would TypeError
        calls.append(("t.w6a.run.strict", data, settings))
        return []

    data = object()
    settings = Settings()
    assert run_checks(data, settings, "ftp", ["t.w6a.run"], None) == []
    # executed in name-sorted order, each called with the very same objects
    assert [c[0] for c in calls] == ["t.w6a.run.a", "t.w6a.run.b", "t.w6a.run.strict"]
    assert all(c[1] is data and c[2] is settings for c in calls)


def test_run_checks_accumulates_findings_in_order():
    f_a1, f_a2 = _finding("a1"), _finding("a2")
    f_b1 = _finding("b1")
    _register("t.w6a.acc.b", findings=[f_b1])
    _register("t.w6a.acc.a", findings=[f_a1, f_a2])
    got = run_checks(object(), Settings(), "ftp", ["t.w6a.acc"], None)
    assert got == [f_a1, f_a2, f_b1]  # name-sorted check order, in-check order kept
    assert got[0] is f_a1 and got[1] is f_a2 and got[2] is f_b1


def test_run_checks_raising_check_is_contained(wpt_caplog):
    calls = []
    f_a, f_c = _finding("good-a"), _finding("good-c")
    _register("t.w6a.err.a", findings=[f_a], calls=calls)
    _register("t.w6a.err.boom", raises=RuntimeError("boom from t.w6a.err.boom"), calls=calls)
    _register("t.w6a.err.c", findings=[f_c], calls=calls)

    got = run_checks(object(), Settings(), "ftp", ["t.w6a.err"], None)

    # the raising check is contained (the other checks still ran) AND is
    # surfaced as a high-risk finding so the report never reads as a clean
    # pass for a check that produced no findings. The reserved category
    # matches no suggested-step rule (never a destructive action), and the
    # raw exception stays out of the report.
    assert got[0] is f_a and got[-1] is f_c
    fail = got[1]
    assert fail.category == "audit.check_failed"
    assert fail.name == "t.w6a.err.boom"
    assert fail.risk == "high"
    assert "RuntimeError" in fail.detail
    assert "boom from t.w6a.err.boom" not in fail.detail
    assert [c[0] for c in calls] == ["t.w6a.err.a", "t.w6a.err.boom", "t.w6a.err.c"]
    # one error line naming the check and carrying the exception message
    errors = [r.getMessage() for r in wpt_caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1
    assert "t.w6a.err.boom" in errors[0]
    assert "boom from t.w6a.err.boom" in errors[0]
    # the failed check's duration is logged at debug like every other check
    assert any("t.w6a.err.boom" in r.getMessage()
               for r in wpt_caplog.records if r.levelno == logging.DEBUG)


def test_run_check_failure_detail_does_not_suggest_a_destructive_action():
    # A failed core.integrity / media.unreferenced must NOT be routed to
    # heal-core / trim-media: the reserved category renders no suggested step.
    from wpt.report import suggested_step_for
    assert suggested_step_for("audit.check_failed") is None
    # sanity: a REAL finding category still maps to its action
    assert suggested_step_for("media.unreferenced") is not None


def test_run_checks_failed_check_does_not_change_a_clean_run(wpt_caplog):
    # a run where every check passes still returns exactly the real findings
    _register("t.w6a.clean", findings=[_finding("ok")])
    got = run_checks(object(), Settings(), "ftp", ["t.w6a.clean"], None)
    assert [f.name for f in got] == ["ok"]


def test_run_checks_logs_debug_durations_and_info_summary(wpt_caplog):
    _register("t.w6a.log.a", findings=[_finding("x")])
    _register("t.w6a.log.b")
    assert len(run_checks(object(), Settings(), "ftp", ["t.w6a.log"], None)) == 1

    debugs = [r.getMessage() for r in wpt_caplog.records if r.levelno == logging.DEBUG]
    assert len(debugs) == 2  # one duration line per check
    assert all("ms" in m for m in debugs)
    assert any("t.w6a.log.a" in m for m in debugs)
    assert any("t.w6a.log.b" in m for m in debugs)

    infos = [r.getMessage() for r in wpt_caplog.records if r.levelno == logging.INFO]
    assert len(infos) == 1  # exactly one summary line
    assert "2 checks run" in infos[0]
    assert "1 findings" in infos[0]


def test_run_checks_mode_isolation():
    calls = []
    _register("t.w6a.iso.ftp", applies=("ftp",), calls=calls)
    _register("t.w6a.iso.local", applies=("local",), calls=calls)

    run_checks(object(), Settings(), "local", ["t.w6a.iso"], None)
    assert [c[0] for c in calls] == ["t.w6a.iso.local"]

    calls.clear()
    run_checks(object(), Settings(), "ftp", ["t.w6a.iso"], None)
    assert [c[0] for c in calls] == ["t.w6a.iso.ftp"]


def test_AUDIT_STOP_SWALLOW_stop_and_deadline_end_the_run():
    """AUDIT-STOP-SWALLOW: the catch-all turned SIGTERM/deadline into a
    `check_failed` row and the audit returned rc 0."""
    from wpt.types import DeadlineExceeded, StopRequested

    for index, exc in enumerate(
            (StopRequested("received SIGTERM (15)"),
             DeadlineExceeded("run deadline"))):
        _register(f"t.w6a.stop.check.{index}", raises=exc)
        with pytest.raises(type(exc)):
            run_checks(None, Settings(), "local",
                       [f"t.w6a.stop.check.{index}"], None)
