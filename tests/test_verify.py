"""Tests for wpt.verify — the live reference re-check behind ``wpt verify`` [L2].

Everything goes THROUGH run(ctx) with real Ctx objects, the way the CLI's
_lazy_call invokes it.  Both construction seams are monkeypatched exactly
as the patchability contract prescribes: ``wpt.verify.remote_stack``
returns a scripted FakeSession + a destroy-recording bridge double (the
bridge is lifecycle-only here — verify never calls it), and
``wpt.verify.walk_site`` returns a canned WalkResult (the real walker is
pinned by tests/test_walk.py, the real stack by tests/audit/test_run.py).
No network, no PHP, no sleeps — deterministic.

Log capture uses the suite's own ``wpt_records`` handler (as
tests/audit/test_run.py): pytest's caplog cannot see ``wpt.*`` records
because the ``wpt`` parent logger does not propagate.

Test -> behavior map:
  test_local_mode_refusal ........ local mode: rc 1, error logged, the
        stack is never built (zero fetches), and the REFUSAL REPORT is
        written (a failed run used to write nothing at all)
  test_all_ok .................... 2 refs, both 200: rc 0; the GETs hit
        exactly the expected full URLs, streamed (stream=True + the
        profile timeout), closed without reading; report written with
        ok|2, no detail sections; the markdown ALSO printed to stdout;
        bridge destroyed exactly once
  test_broken_ref ................. a scripted 404: rc 1; report carries
        "## Broken references" and the "- HTTP 404 — <full url>" bullet;
        bridge still destroyed exactly once
  test_failed_fetch ............... a scripted requests.ConnectionError:
        rc 1; report carries "## Failed fetches" and the error bullet
  test_ref_tail_reencoded ......... a decoded ref tail ("with space.jpg")
        is percent-encoded back into the fetched URL (%20)
  test_zero_refs_is_not_a_pass .... the walk finds nothing: rc 1 with the
        explicit "found NO live references … this is not a pass" line
        (it used to be a green rc 0), no "refs ok" summary, the
        homepage probe still runs, the refusal report carries "| ok | 0 |"
  test_walk_failure_degrades ...... walk_site raising WptError: rc 1,
        the degraded warning, zero fetches, the failure report on disk
        naming the walk failure, bridge still destroyed
  test_refs_rechecked_sorted ...... {"b.jpg", "a.jpg"} re-checks in
        sorted order
  test_stack_failure_returns_1 ... remote_stack raising WptError: rc 1,
        the reason on disk, never a traceback
  test_recheck_honours_the_deadline . the loop that dominates this
        command's wall time is budget-bounded: 300 refs under a spent
        --deadline exit 1 with the deadline named, no "ok" summary, the
        bridge still destroyed
  test_the_same_fixture_passes_with_a_normal_budget . the SAME 300 refs
        with a normal budget: rc 0, 300 fetches, ok|300, and NO "run" key
        in the twin (a success needs none)
  test_a_successful_run_report_is_byte_identical . the failure report
        did not move the success report: markdown and twin pinned
        byte-for-byte
  test_the_failure_report_carries_zero_counts_and_a_reason . the twin
        keeps verify's own shape, every count zero, plus run.{status,
        findings, reason}
  test_the_failure_report_never_carries_a_credential . the reason
        crosses the redaction chokepoint like every log line
  test_a_failed_run_prints_no_report . stdout stays the surface of a
        report that EXISTS
  test_json_twin_all_ok .......... report_path set + 1 ok ref: the .md
         AND the .json twin exist; the JSON parses with EXACTLY the key
         set {site,total,ok,broken,failed}, ok==1, broken/failed []
  test_json_twin_broken_ref ...... the 404 ref lands in json broken[0]
         as {"label": "HTTP 404", "url": <full fetched url>}
  test_json_twin_failed_fetch .... the ConnectionError ref lands in
         json failed[0] with the exception text as the label
  test_no_report_path_writes_nothing .. no report_path: no .md, no
         .json, stdout stays markdown-only
"""

import json
import logging
import time

import pytest
import requests

import wpt.verify
from tests.fakes import FakeResponse, FakeSession
from wpt.cli import Ctx
from wpt.settings import load
from wpt.types import WptError
from wpt.walk import WalkResult

SITE = "https://site.test"
UPLOADS = f"{SITE}/wp-content/uploads"


# --------------------------------------------------------------- log capture


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def wpt_records():
    """Capture every wpt.* log record (the wpt parent does not propagate)."""
    handler = _Capture()
    parent = logging.getLogger("wpt")
    old_level = parent.level
    parent.addHandler(handler)
    parent.setLevel(logging.DEBUG)
    try:
        yield handler.records
    finally:
        parent.setLevel(old_level)
        parent.removeHandler(handler)


# ------------------------------------------------------------------ fixtures


class RecordingBridge:
    """Lifecycle-only bridge double: counts destroy() calls."""

    def __init__(self) -> None:
        self.destroyed = 0

    def destroy(self) -> None:
        self.destroyed += 1


def _walk(refs, fetched=1, partial=False):
    """A walk_site double returning exactly ``refs`` as the live set.

    ``fetched`` mirrors the real walker's field (ATTEMPTED requests, not
    successful pages); ``partial`` marks a walk that stopped early (budget /
    deadline / abort) so its reference set is incomplete.
    """
    pages = [SITE]
    def fake(_session, _site, _settings, _timeout_s, deadline=None):
        return WalkResult(live_refs=set(refs), pages=pages, forms=[],
                          fetched=fetched, partial=partial)
    return fake


def homepage(status):
    """A scripted homepage probe answer with the given HTTP status."""
    return FakeResponse(status)


def _ctx(tmp_path, **overrides):
    kwargs = dict(
        source="ftp://h", settings=load(),
        wp_url=SITE, report_path=tmp_path / "v.md",
    )
    kwargs.update(overrides)
    return Ctx(**kwargs)


def _patch(monkeypatch, script=(), refs=(), fetched=1, partial=False):
    """Patch both seams: scripted session + recording bridge + canned walk."""
    session = FakeSession(script)
    bridge = RecordingBridge()
    monkeypatch.setattr(wpt.verify, "remote_stack",
                        lambda ctx: (None, session, bridge))
    monkeypatch.setattr(wpt.verify, "walk_site",
                        _walk(refs, fetched=fetched, partial=partial))
    return session, bridge


# --------------------------------------------------------------------- tests


def test_local_mode_refusal(monkeypatch, tmp_path, wpt_records):
    def _never(ctx):
        raise AssertionError("remote_stack must not be called in local mode")

    monkeypatch.setattr(wpt.verify, "remote_stack", _never)
    ctx = _ctx(tmp_path, source="local", wp_url=None)

    assert wpt.verify.run(ctx) == 1
    errors = [r for r in wpt_records
              if r.name == "wpt.verify" and r.levelno == logging.ERROR]
    assert errors
    assert any("verify requires a live site" in r.getMessage()
               for r in errors)
    # the refusal is on disk too (L44: a failed run used to write nothing)
    written = ctx.report_path.read_text(encoding="utf-8")
    assert "## This run did not complete" in written
    assert "verify requires a live site" in written
    assert "| ok | 0 |" in written


def test_local_mode_with_wp_url_runs_against_serve(monkeypatch, tmp_path):
    """The wpt-serve pair: local mode + --wp-url verifies the rehearsal —
    a plain session, NO remote_stack, NO bridge; walk + recheck run
    against the served site exactly as in ftp mode."""
    def _never(ctx):
        raise AssertionError("remote_stack must not be called in local mode")

    monkeypatch.setattr(wpt.verify, "remote_stack", _never)
    session = FakeSession([FakeResponse(200), FakeResponse(200)])
    monkeypatch.setattr(wpt.verify.requests, "Session", lambda: session)
    monkeypatch.setattr(wpt.verify, "walk_site", _walk({"a.jpg", "b.jpg"}))
    ctx = _ctx(tmp_path, source="local",
               wp_url="http://127.0.0.1:8123", report_path=None)

    assert wpt.verify.run(ctx) == 0
    assert [url for url, _kw in session.gets] == [
        "http://127.0.0.1:8123/wp-content/uploads/a.jpg",
        "http://127.0.0.1:8123/wp-content/uploads/b.jpg",
    ]


def test_all_ok(monkeypatch, tmp_path, capsys):
    responses = [FakeResponse(200), FakeResponse(200)]
    session, bridge = _patch(monkeypatch, script=list(responses),
                             refs={"2023/10/a.jpg", "2023/10/b.jpg"})
    ctx = _ctx(tmp_path)

    assert wpt.verify.run(ctx) == 0

    assert [url for url, _kw in session.gets] == [
        f"{UPLOADS}/2023/10/a.jpg",
        f"{UPLOADS}/2023/10/b.jpg",
    ]
    for _url, kwargs in session.gets:
        assert kwargs["stream"] is True
        assert kwargs["timeout"] == ctx.settings.http.timeout_s
    # streamed fetch: status from headers, body never downloaded
    assert all(response.closed for response in responses)

    markdown = ctx.report_path.read_text(encoding="utf-8")
    assert markdown.startswith("# wpt verify — https://site.test")
    assert "Re-checked 2 live references" in markdown
    assert "| ok | 2 |" in markdown
    assert "| broken | 0 |" in markdown
    assert "| failed | 0 |" in markdown
    assert "## Broken references" not in markdown
    assert "## Failed fetches" not in markdown
    # the report is ALWAYS the stdout surface, even when written to disk
    assert "# wpt verify — https://site.test" in capsys.readouterr().out
    assert bridge.destroyed == 1


def test_broken_ref(monkeypatch, tmp_path):
    session, bridge = _patch(monkeypatch, script=[FakeResponse(404)],
                             refs={"2023/a.jpg"})
    ctx = _ctx(tmp_path)

    assert wpt.verify.run(ctx) == 1

    markdown = ctx.report_path.read_text(encoding="utf-8")
    assert "## Broken references" in markdown
    assert f"- HTTP 404 — {UPLOADS}/2023/a.jpg" in markdown
    assert "| broken | 1 |" in markdown
    assert "## Failed fetches" not in markdown
    # the bridge never outlives the run, even when a ref is broken
    assert bridge.destroyed == 1


def test_failed_fetch(monkeypatch, tmp_path):
    session, _bridge = _patch(monkeypatch,
                             script=[requests.ConnectionError("boom")],
                             refs={"c.jpg"})
    ctx = _ctx(tmp_path)

    assert wpt.verify.run(ctx) == 1

    markdown = ctx.report_path.read_text(encoding="utf-8")
    assert "## Failed fetches" in markdown
    assert f"- boom — {UPLOADS}/c.jpg" in markdown
    assert "| failed | 1 |" in markdown
    assert "## Broken references" not in markdown


def test_ref_tail_reencoded(monkeypatch, tmp_path):
    session, _bridge = _patch(monkeypatch, script=[FakeResponse(200)],
                              refs={"2023/with space.jpg"})
    ctx = _ctx(tmp_path)

    assert wpt.verify.run(ctx) == 0
    assert session.gets[0][0] == f"{UPLOADS}/2023/with%20space.jpg"


def test_zero_refs_is_not_a_pass(monkeypatch, tmp_path, wpt_records, capsys):
    # A reachable site (homepage 200) that yielded NO reference at all.
    # This used to answer rc 0 with "nothing to re-check", and it is how
    # the documented `serve` + `verify` rehearsal pair returned a GREEN
    # run having checked nothing: serve answers .php as text/plain, so
    # the walker's HTML test rejects the only servable root and the
    # reference set is empty.  A green pass over zero measurements is the
    # defect; the verdict is now explicitly NOT a pass.
    session, bridge = _patch(monkeypatch, script=[homepage(200)], refs=set())
    ctx = _ctx(tmp_path)

    assert wpt.verify.run(ctx) == 1
    # the only GET is the homepage probe
    assert [u for u, _ in session.gets] == [f"{SITE}/"]
    errors = [r for r in wpt_records
              if r.name == "wpt.verify" and r.levelno == logging.ERROR]
    assert len(errors) == 1
    message = errors[0].getMessage()
    assert "found NO live references" in message
    assert "this is not a pass" in message
    # no "ok" summary anywhere: nothing was verified
    assert not [r for r in wpt_records
                if r.name == "wpt.verify" and "refs ok" in r.getMessage()]
    assert "refs ok" not in capsys.readouterr().out
    # ... and the report says the same thing, with zero counts
    written = ctx.report_path.read_text(encoding="utf-8")
    assert "found NO live references" in written
    assert "| ok | 0 |" in written
    assert bridge.destroyed == 1


def test_collapsed_walk_is_not_verified(monkeypatch, tmp_path, wpt_records):
    # A COMPLETE zero-ref walk where the HOMEPAGE is 5xx: a collapsed site,
    # NOT a clean one. Verification is inconclusive -> rc 1. (WalkResult
    # .fetched is nonzero — attempts — so only the homepage probe catches it.)
    session, bridge = _patch(monkeypatch, script=[homepage(503)], refs=set())
    ctx = _ctx(tmp_path)

    assert wpt.verify.run(ctx) == 1
    assert [u for u, _ in session.gets] == [f"{SITE}/"]
    errors = [r for r in wpt_records
              if r.name == "wpt.verify" and r.levelno == logging.ERROR]
    assert any("INCONCLUSIVE" in r.getMessage() for r in errors)
    assert bridge.destroyed == 1


def test_partial_walk_zero_refs_is_inconclusive(monkeypatch, tmp_path, wpt_records):
    # A PARTIAL walk (stopped on its budget/deadline) that found 0 refs is
    # INCONCLUSIVE even when the homepage is 2xx: the uncrawled pages could
    # hold the media. Never read an empty partial set as "no media".
    session, bridge = _patch(monkeypatch, refs=set(), partial=True)
    ctx = _ctx(tmp_path)

    assert wpt.verify.run(ctx) == 1
    # the partial signal short-circuits before any homepage probe
    assert session.gets == []
    errors = [r for r in wpt_records
              if r.name == "wpt.verify" and r.levelno == logging.ERROR]
    assert any("PARTIAL" in r.getMessage() and "INCONCLUSIVE" in r.getMessage()
               for r in errors)
    assert bridge.destroyed == 1


def test_R22_a_partial_walk_with_references_is_still_inconclusive(
        monkeypatch, tmp_path, wpt_records):
    """R22-P1: a partial walk was refused only when it found ZERO refs.
    A failed homepage/seed plus one reachable page's image produced
    ``| ok | 1 |`` and rc 0 even though the uncrawled pages could reference
    anything.  Verify refuses ANY partial walk before the re-check."""
    session, bridge = _patch(monkeypatch, refs={"2023/10/a.jpg"},
                             partial=True)
    ctx = _ctx(tmp_path)

    assert wpt.verify.run(ctx) == 1
    assert session.gets == []           # no reference was "verified"
    assert ctx.report_path.exists()
    twin = json.loads(ctx.report_path.with_suffix(".json").read_text("utf-8"))
    assert twin["total"] == 0 and twin["ok"] == 0
    assert twin["run"]["status"] == "failed"
    assert "PARTIAL" in twin["run"]["reason"]
    assert "INCONCLUSIVE" in twin["run"]["reason"]
    markdown = ctx.report_path.read_text("utf-8")
    assert "| ok | 1 |" not in markdown
    errors = [r for r in wpt_records
              if r.name == "wpt.verify" and r.levelno == logging.ERROR]
    assert any("PARTIAL" in r.getMessage() for r in errors)
    assert bridge.destroyed == 1


def test_collapsed_walk_homepage_transport_error(monkeypatch, tmp_path, wpt_records):
    # A zero-ref walk where the homepage probe itself fails -> INCONCLUSIVE.
    import requests as _rq
    session, bridge = _patch(monkeypatch,
                             script=[_rq.ConnectionError("homepage down")],
                             refs=set())
    ctx = _ctx(tmp_path)

    assert wpt.verify.run(ctx) == 1
    errors = [r for r in wpt_records
              if r.name == "wpt.verify" and r.levelno == logging.ERROR]
    assert any("homepage probe failed" in r.getMessage() for r in errors)
    assert bridge.destroyed == 1


def test_walk_failure_degrades(monkeypatch, tmp_path, wpt_records):
    session = FakeSession()
    bridge = RecordingBridge()

    def _raising(_session, _site, _settings, _timeout_s, deadline=None):
        raise WptError("walk blew up")

    monkeypatch.setattr(wpt.verify, "remote_stack",
                        lambda ctx: (None, session, bridge))
    monkeypatch.setattr(wpt.verify, "walk_site", _raising)
    ctx = _ctx(tmp_path)

    assert wpt.verify.run(ctx) == 1
    assert session.gets == []
    warnings = [r for r in wpt_records
                if r.name == "wpt.verify" and r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "live walk failed; verification degraded: walk blew up" \
        in warnings[0].getMessage()
    # a failed run writes the report it can (L44)
    written = ctx.report_path.read_text(encoding="utf-8")
    assert "## This run did not complete" in written
    assert "walk blew up" in written
    twin = json.loads(ctx.report_path.with_suffix(".json").read_text("utf-8"))
    assert twin["run"]["status"] == "failed"
    assert twin["run"]["findings"] == 0
    assert twin["total"] == 0 and twin["ok"] == 0
    assert bridge.destroyed == 1


def test_refs_rechecked_sorted(monkeypatch, tmp_path):
    session, _bridge = _patch(monkeypatch,
                             script=[FakeResponse(200), FakeResponse(200)],
                             refs={"b.jpg", "a.jpg"})
    ctx = _ctx(tmp_path)

    assert wpt.verify.run(ctx) == 0
    assert [url for url, _kw in session.gets] == [
        f"{UPLOADS}/a.jpg",
        f"{UPLOADS}/b.jpg",
    ]


def test_stack_failure_returns_1(monkeypatch, tmp_path, wpt_records):
    def _boom(ctx):
        raise WptError("no host")

    monkeypatch.setattr(wpt.verify, "remote_stack", _boom)
    ctx = _ctx(tmp_path)

    assert wpt.verify.run(ctx) == 1
    errors = [r for r in wpt_records
              if r.name == "wpt.verify" and r.levelno == logging.ERROR]
    assert errors
    assert any("no host" in r.getMessage() for r in errors)
    # the refusal is on disk, naming WHY there is nothing in the file
    written = ctx.report_path.read_text(encoding="utf-8")
    assert "no host" in written
    assert "- findings: 0" in written


# ----------------------------------------------- the JSON report twin (md+json)


def test_json_twin_all_ok(monkeypatch, tmp_path):
    _patch(monkeypatch, script=[FakeResponse(200)], refs={"a.jpg"})
    ctx = _ctx(tmp_path)

    assert wpt.verify.run(ctx) == 0

    assert ctx.report_path.exists()
    twin = ctx.report_path.with_suffix(".json")
    assert twin.exists()
    data = json.loads(twin.read_text(encoding="utf-8"))
    assert set(data) == {"site", "total", "ok", "broken", "failed"}
    assert data["site"] == SITE
    assert data["total"] == 1
    assert data["ok"] == 1
    assert data["broken"] == []
    assert data["failed"] == []


def test_json_twin_broken_ref(monkeypatch, tmp_path):
    _patch(monkeypatch, script=[FakeResponse(404)], refs={"2023/a.jpg"})
    ctx = _ctx(tmp_path)

    assert wpt.verify.run(ctx) == 1

    twin = ctx.report_path.with_suffix(".json")
    data = json.loads(twin.read_text(encoding="utf-8"))
    assert data["broken"] == [{"label": "HTTP 404",
                               "url": f"{UPLOADS}/2023/a.jpg"}]
    assert data["ok"] == 0
    assert data["failed"] == []


def test_json_twin_failed_fetch(monkeypatch, tmp_path):
    _patch(monkeypatch, script=[requests.ConnectionError("boom")],
           refs={"c.jpg"})
    ctx = _ctx(tmp_path)

    assert wpt.verify.run(ctx) == 1

    twin = ctx.report_path.with_suffix(".json")
    data = json.loads(twin.read_text(encoding="utf-8"))
    assert data["failed"] == [{"label": "boom",
                               "url": f"{UPLOADS}/c.jpg"}]
    assert data["broken"] == []


def test_no_report_path_writes_nothing(monkeypatch, tmp_path, capsys):
    _patch(monkeypatch, script=[FakeResponse(200)], refs={"a.jpg"})
    ctx = _ctx(tmp_path, report_path=None)

    assert wpt.verify.run(ctx) == 0

    assert not (tmp_path / "v.md").exists()
    assert not (tmp_path / "v.json").exists()
    out = capsys.readouterr().out
    # stdout is still the markdown surface ONLY — no JSON leaks into it
    assert "# wpt verify — https://site.test" in out
    assert '"site"' not in out


# ------------------------------------- the self-bounding re-check loop (--deadline)


def _ref_set(count: int) -> set[str]:
    return {f"2023/{i:04d}/photo.jpg" for i in range(count)}


def test_recheck_honours_the_deadline(monkeypatch, tmp_path, wpt_records,
                                      capsys):
    """``--deadline`` bounds the loop that DOMINATES this command's wall
    time, not just the walk that precedes it.

    Reproduced: a page with 10,000 images under ``--deadline 3`` ran
    18.2 s and reported "10000 refs ok" at rc 0 — the budget was checked
    once per PAGE VISIT inside the walk, and the 10,000-reference
    re-check that followed was never bounded at all.  Now the same
    fixture ends itself: rc 1, the deadline named, no "ok" summary, and
    no report claiming anything was verified.
    """
    session, bridge = _patch(monkeypatch, script=[], refs=_ref_set(300))
    ctx = _ctx(tmp_path, deadline_s=1e-6)   # spent before the first ref

    assert wpt.verify.run(ctx) == 1
    errors = [r for r in wpt_records
              if r.name == "wpt.verify" and r.levelno == logging.ERROR]
    assert len(errors) == 1
    message = errors[0].getMessage()
    assert "verify did not verify" in message
    assert "deadline" in message and "verify re-check" in message
    # the run did not quietly report what it managed to check
    assert not [r for r in wpt_records
                if r.name == "wpt.verify" and "refs ok" in r.getMessage()]
    assert "refs ok" not in capsys.readouterr().out
    assert "| ok |" not in capsys.readouterr().out
    # fail-closed teardown still ran, and the report says what happened
    assert bridge.destroyed == 1
    written = ctx.report_path.read_text(encoding="utf-8")
    assert "deadline" in written
    assert "| ok | 0 |" in written


def test_the_same_fixture_passes_with_a_normal_budget(monkeypatch, tmp_path):
    """The bound is a bound, not a new refusal: the SAME 300-reference
    fixture with a normal budget verifies and returns 0."""
    session, bridge = _patch(monkeypatch, script=[FakeResponse(200)] * 300,
                             refs=_ref_set(300))
    ctx = _ctx(tmp_path)

    assert wpt.verify.run(ctx) == 0
    assert len(session.gets) == 300
    markdown = ctx.report_path.read_text(encoding="utf-8")
    assert "| ok | 300 |" in markdown
    twin = json.loads(ctx.report_path.with_suffix(".json").read_text("utf-8"))
    assert twin["ok"] == 300 and twin["total"] == 300
    assert "run" not in twin          # a success needs no such key
    assert bridge.destroyed == 1


# ------------------------------------------------ the failure report (L44)


def test_a_successful_run_report_is_byte_identical(monkeypatch, tmp_path):
    """The new failure report must not have moved the SUCCESS report: the
    markdown and the twin are pinned byte-for-byte, so a change to either
    is a change to the contract every consumer of ``verify --report`` has
    been reading."""
    _patch(monkeypatch, script=[FakeResponse(200), FakeResponse(404)],
           refs={"2023/a.jpg", "2023/b.jpg"})
    ctx = _ctx(tmp_path)

    assert wpt.verify.run(ctx) == 1   # a broken ref: the report still renders
    assert ctx.report_path.read_text(encoding="utf-8") == (
        "# wpt verify — https://site.test\n"
        "\n"
        "Re-checked 2 live references from a fresh walk of "
        "https://site.test.\n"
        "\n"
        "| result | count |\n"
        "|---|---|\n"
        "| ok | 1 |\n"
        "| broken | 1 |\n"
        "| failed | 0 |\n"
        "\n"
        "## Broken references\n"
        "\n"
        f"- HTTP 404 — {UPLOADS}/2023/b.jpg\n"
    )
    assert ctx.report_path.with_suffix(".json").read_text("utf-8") == (
        json.dumps(
            {"site": SITE, "total": 2, "ok": 1,
             "broken": [{"label": "HTTP 404",
                         "url": f"{UPLOADS}/2023/b.jpg"}],
             "failed": []},
            ensure_ascii=False, sort_keys=True, indent=2)
    )


def test_the_failure_report_carries_zero_counts_and_a_reason(
        monkeypatch, tmp_path):
    _patch(monkeypatch, refs=set(), partial=True)
    ctx = _ctx(tmp_path)

    assert wpt.verify.run(ctx) == 1

    twin = json.loads(ctx.report_path.with_suffix(".json").read_text("utf-8"))
    assert twin["total"] == 0 and twin["ok"] == 0
    assert twin["broken"] == [] and twin["failed"] == []
    assert twin["run"]["findings"] == 0
    assert twin["run"]["status"] == "failed"
    assert "PARTIAL" in twin["run"]["reason"]


def test_the_failure_report_never_carries_a_credential(monkeypatch, tmp_path):
    """The report is a file an operator keeps and shares, so the reason
    crosses the same redaction chokepoint every log line does."""
    def _boom(ctx):
        raise WptError("ftp login failed: password=hunter2 for admin")

    monkeypatch.setattr(wpt.verify, "remote_stack", _boom)
    ctx = _ctx(tmp_path)

    assert wpt.verify.run(ctx) == 1

    written = ctx.report_path.read_text(encoding="utf-8")
    assert "hunter2" not in written
    assert "***" in written
    twin = json.loads(ctx.report_path.with_suffix(".json").read_text("utf-8"))
    assert "hunter2" not in json.dumps(twin)


def test_a_failed_run_prints_no_report(monkeypatch, tmp_path, capsys):
    """stdout stays the surface of a report that EXISTS; a failed run has
    none, so stdout says nothing (the reason is the log's job)."""
    def _boom(ctx):
        raise WptError("no host")

    monkeypatch.setattr(wpt.verify, "remote_stack", _boom)
    ctx = _ctx(tmp_path)

    assert wpt.verify.run(ctx) == 1
    assert capsys.readouterr().out == ""


# ------------------------------------------------ triple-check round 8 (P1)


def test_P1_verify_report_redacts_wp_url_userinfo(monkeypatch, tmp_path,
                                                  capsys):
    """P1-03: --wp-url userinfo reached verify's markdown/twin (site AND the
    broken/failed reference URLs) and stdout."""
    secret = "s3cr3t-pass"
    site = f"https://admin:{secret}@site.test"
    _patch(monkeypatch, script=[FakeResponse(404)], refs=("a.jpg",))
    ctx = _ctx(tmp_path, wp_url=site)

    assert wpt.verify.run(ctx) == 1

    markdown = ctx.report_path.read_text("utf-8")
    twin_text = ctx.report_path.with_suffix(".json").read_text("utf-8")
    printed = capsys.readouterr().out
    for face in (markdown, twin_text, printed):
        assert secret not in face
        assert "admin:***@site.test" in face


# ------------------------------------------------ round-8 teardown regressions


class _CloseRecordingSession(FakeSession):
    def __init__(self, script=(), *, stop=False):
        super().__init__(script)
        self.closed = 0
        self._stop = stop

    def close(self):
        self.closed += 1
        if self._stop:
            from wpt.types import StopRequested

            raise StopRequested("SIGTERM during close")


def test_R8_P2_16_teardown_stop_replaces_the_success_report(
        monkeypatch, tmp_path):
    """R8-P2-16: the pass wrote a success report, then a close-time stop
    returned 1 beside it.  The report must be replaced with the failure
    pair so rc and artifact agree."""
    session = _CloseRecordingSession([FakeResponse(200)], stop=True)
    monkeypatch.setattr(wpt.verify, "remote_stack",
                        lambda ctx: (None, session, RecordingBridge()))
    monkeypatch.setattr(wpt.verify, "walk_site", _walk({"a.jpg"}))
    ctx = _ctx(tmp_path)

    assert wpt.verify.run(ctx) == 1
    markdown = ctx.report_path.read_text("utf-8")
    assert "This run did not complete" in markdown
    assert "SIGTERM" in markdown
    twin = json.loads(ctx.report_path.with_suffix(".json").read_text("utf-8"))
    assert twin["run"]["status"] == "failed"


def test_R8_P2_17_verify_closes_the_http_session(monkeypatch, tmp_path):
    """R8-P2-17: the HTTP session is part of the teardown trio."""
    session = _CloseRecordingSession([FakeResponse(200)])
    monkeypatch.setattr(wpt.verify, "remote_stack",
                        lambda ctx: (None, session, RecordingBridge()))
    monkeypatch.setattr(wpt.verify, "walk_site", _walk({"a.jpg"}))
    ctx = _ctx(tmp_path)

    assert wpt.verify.run(ctx) == 0
    assert session.closed == 1


def _drip_head_server(line: bytes, delay: float = 0.05):
    """A raw origin that drips the response head one byte at a time."""
    import socket
    import threading

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def _serve():
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        try:
            conn.recv(65536)
            for index in range(len(line)):
                conn.sendall(line[index:index + 1])
                time.sleep(delay)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    return (f"http://127.0.0.1:{listener.getsockname()[1]}",
            listener, thread)


def test_R21_recheck_per_request_timeout_is_one_failed_ref(monkeypatch):
    """R21-P1: the ref loop rides the bounded get with
    min(run, now + http.timeout_s).  A header drip that spends only the
    PER-REQUEST bound is one failed ref — the run is not over."""
    import requests
    from wpt.deadline import Deadline
    from wpt.verify import _recheck_refs

    site, listener, thread = _drip_head_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    session = requests.Session()
    session.trust_env = False
    try:
        started = time.monotonic()
        ok, broken, failed = _recheck_refs(
            session, site, ["2023/10/a.jpg"], 0.2,
            deadline=Deadline(5.0))
        elapsed = time.monotonic() - started
    finally:
        session.close()
        listener.close()
        thread.join(timeout=5)
    assert ok == 0 and broken == []
    assert len(failed) == 1
    assert elapsed < 1.5, elapsed


def test_R21_post_budget_verify_timeout_writes_the_failure_pair(
        monkeypatch, tmp_path, wpt_records):
    """A ref fetch that exhausts the RUN budget is rc 1 with the shared
    failure pair — never a success report over the refs checked so far."""
    import requests
    from wpt.walk import WalkResult

    site, listener, thread = _drip_head_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    session = requests.Session()
    session.trust_env = False
    monkeypatch.setattr(wpt.verify, "remote_stack",
                        lambda _ctx: (None, session, None))
    monkeypatch.setattr(
        wpt.verify, "walk_site",
        lambda *_a, **_k: WalkResult(live_refs={"2023/10/a.jpg"},
                                     pages=[site + "/"], forms=[], fetched=1))
    ctx = _ctx(tmp_path, wp_url=site, deadline_s=0.3)
    try:
        assert wpt.verify.run(ctx) == 1
    finally:
        listener.close()
        thread.join(timeout=5)
    written = ctx.report_path.read_text(encoding="utf-8")
    assert "deadline" in written
    assert "| ok | 0 |" in written
    assert "refs ok" not in written
    twin = json.loads(
        ctx.report_path.with_suffix(".json").read_text(encoding="utf-8"))
    assert twin["run"]["status"] == "failed"
    assert not [r for r in wpt_records
                if r.name == "wpt.verify" and "refs ok" in r.getMessage()]
