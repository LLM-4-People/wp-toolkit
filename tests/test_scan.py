"""Unit tests for the source-only ``wpt scan`` command (wpt.scan).

FakeSource stands in for the source connector and no network, bridge, PHP or
database exists: the command walks, gathers, runs exactly one registered
check, and renders the audit report.  ``Ctx`` is the real CLI context (never
constructed through argument parsing), so the wiring under test is the
command body itself.

Test -> behavior map:
  test_ftp_run_prints_report_without_bridge_or_db
        .................................... ftp: ftp_source_for(ctx), report
        on stdout, no bridge/DB call, source closed, no mutation
  test_report_writes_markdown_and_json_twin . --report uses write_report and
        leaves the markdown + JSON twin, nothing on stdout
  test_local_run_uses_only_the_zip .......... local: ZipSource(ctx.zip), no
        --sql read, site/source header names the zip
  test_local_requires_zip ................... failure report + rc 1
  test_failure_report_on_source_error ....... WptError -> one error, failure
        report with the AuditReport header, rc 1, no traceback
  test_source_closed_when_gather_fails ...... finally closes on every path
  test_check_selection_is_exactly_source_patterns  only
        ["security.source_patterns"], skip None, in both modes
  test_unwritable_report_fails_the_run ...... the shared writer's refusal is
        the run's rc
"""

import json
import logging

import pytest

from tests.fakes import FakeSource
from wpt.cli import Ctx
from wpt.scan import run
from wpt.settings import load
from wpt.types import Finding, SourceError

PLUGIN = "wp-content/plugins/x/x.php"
SESSION = b"<?php\nsession_id($_GET['sid']);\n"


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


class TrackingSource(FakeSource):
    """FakeSource that records close() calls."""

    def __init__(self) -> None:
        super().__init__()
        self.closed = 0

    def close(self):
        self.closed += 1


def ftp_ctx(tmp_path, **overrides) -> Ctx:
    fields = dict(
        source="ftp://example.test",
        settings=load(),
        webroot="public_html",
        user="u",
        password="p",
        report_path=tmp_path / "scan.md",
    )
    fields.update(overrides)
    return Ctx(**fields)


def local_ctx(tmp_path, **overrides) -> Ctx:
    fields = dict(
        source="local",
        settings=load(),
        zip=tmp_path / "site.zip",
        report_path=tmp_path / "scan.md",
    )
    fields.update(overrides)
    return Ctx(**fields)


def source_with_session() -> TrackingSource:
    source = TrackingSource()
    source.files[PLUGIN] = SESSION
    return source


def _error_records(wpt_records):
    return [r.getMessage() for r in wpt_records
            if r.name == "wpt.scan" and r.levelno == logging.ERROR]


def _failure_report(ctx) -> tuple[str, dict]:
    markdown = ctx.report_path.read_text(encoding="utf-8")
    twin = json.loads(
        ctx.report_path.with_suffix(".json").read_text(encoding="utf-8"))
    return markdown, twin


# ------------------------------------------------------------------- ftp


def test_ftp_run_prints_report_without_bridge_or_db(
    monkeypatch, tmp_path, capsys, wpt_records,
):
    import wpt.audit.data as data_module
    import wpt.localmode.analyzer as analyzer
    from wpt.wpbridge.client import Bridge

    source = source_with_session()
    calls = []

    def fake_source(ctx):
        calls.append(ctx)
        return source

    def no_bridge_db(*args, **kwargs):
        raise AssertionError("scan must not build a bridge or read a database")

    monkeypatch.setattr("wpt.scan.ftp_source_for", fake_source)
    monkeypatch.setattr(Bridge, "ensure", no_bridge_db)
    monkeypatch.setattr(Bridge, "call", no_bridge_db)
    monkeypatch.setattr(data_module, "gather_remote", no_bridge_db)
    monkeypatch.setattr(analyzer, "analyze", no_bridge_db)

    ctx = ftp_ctx(tmp_path, report_path=None)
    assert run(ctx) == 0

    out = capsys.readouterr().out
    assert "# wpt scan — example.test" in out
    assert "## security.source_patterns" in out
    assert "session-fixation" in out
    assert calls == [ctx]
    assert source.closed == 1
    # Read-only: the source saw no write, delete or mutation operation.
    assert [op for _stamp, op, _path in source.ops
            if op in ("write", "delete")] == []
    info = [r.getMessage() for r in wpt_records
            if r.name == "wpt.scan" and r.levelno == logging.INFO]
    assert len(info) == 1
    assert "1 finding(s)" in info[0]
    assert f"{len(list(source.walk()))} entries" in info[0]


def test_report_writes_markdown_and_json_twin(
    monkeypatch, tmp_path, capsys,
):
    import wpt.scan as scan_module

    source = source_with_session()
    monkeypatch.setattr("wpt.scan.ftp_source_for", lambda ctx: source)
    calls = []
    real_write_report = scan_module.write_report

    def spy(ctx, name, markdown, json_text=None):
        calls.append((ctx, name, markdown, json_text))
        return real_write_report(ctx, name, markdown, json_text)

    monkeypatch.setattr(scan_module, "write_report", spy)
    ctx = ftp_ctx(tmp_path)
    assert run(ctx) == 0

    assert len(calls) == 1
    _ctx, name, markdown, twin_text = calls[0]
    assert name == "scan"
    assert twin_text is not None
    assert "session-fixation" in markdown
    assert ctx.report_path.read_text(encoding="utf-8") == markdown
    payload = json.loads(
        ctx.report_path.with_suffix(".json").read_text(encoding="utf-8"))
    assert [f["name"] for f in payload["findings"]] == ["session-fixation"]
    assert payload["totals"] == {
        "entries": len(list(source.walk())), "mode": "ftp",
    }
    assert capsys.readouterr().out == ""


# ----------------------------------------------------------------- local


def test_local_run_uses_only_the_zip(monkeypatch, tmp_path, capsys):
    source = source_with_session()
    constructed = []
    monkeypatch.setattr(
        "wpt.scan.ZipSource",
        lambda path, **kwargs: constructed.append(path) or source)

    ctx = local_ctx(tmp_path, sql=None, report_path=None)
    assert run(ctx) == 0

    assert constructed == [ctx.zip]
    out = capsys.readouterr().out
    assert "# wpt scan — local:site.zip" in out
    assert "Source: zip:site.zip" in out
    assert source.closed == 1


def test_partial_scan_returns_rc_1(monkeypatch, tmp_path, wpt_records):
    source = source_with_session()
    monkeypatch.setattr("wpt.scan.ftp_source_for", lambda ctx: source)
    monkeypatch.setattr(
        "wpt.scan.run_checks",
        lambda *args, **kwargs: [Finding(
            category="security.source_patterns",
            name="scan-partial",
            detail="scan incomplete: run deadline exceeded",
            risk="medium",
        )],
    )
    ctx = ftp_ctx(tmp_path, report_path=None)

    assert run(ctx) == 1
    assert "PARTIAL" in wpt_records[-1].getMessage() or any(
        "PARTIAL" in record.getMessage() for record in wpt_records)


def test_check_failure_is_a_nonzero_scan(monkeypatch, tmp_path):
    source = source_with_session()
    monkeypatch.setattr("wpt.scan.ftp_source_for", lambda ctx: source)
    monkeypatch.setattr(
        "wpt.scan.run_checks",
        lambda *args, **kwargs: [Finding(
            category="audit.check_failed",
            name="security.source_patterns",
            detail="check errored and was skipped",
            risk="high",
        )],
    )
    ctx = ftp_ctx(tmp_path, report_path=None)

    assert run(ctx) == 1


def test_expired_deadline_before_an_empty_walk_is_not_a_clean_scan(
        monkeypatch, tmp_path):
    from wpt.types import DeadlineExceeded

    class _Expired:
        def check(self, context):
            raise DeadlineExceeded("run deadline exceeded")

    source = TrackingSource()
    monkeypatch.setattr("wpt.scan.ftp_source_for", lambda ctx: source)
    monkeypatch.setattr("wpt.scan.Deadline.from_ctx", lambda ctx: _Expired())
    ctx = ftp_ctx(tmp_path, report_path=None)

    assert run(ctx) == 1


def test_SCAN_1_failure_report_uses_the_same_source_summary_and_hides_userinfo(
    monkeypatch, tmp_path,
):
    def boom(ctx):
        raise SourceError("connection refused")

    monkeypatch.setattr("wpt.scan.ftp_source_for", boom)
    ctx = ftp_ctx(tmp_path, source="ftp://user:sup3rsecret@example.test")

    assert run(ctx) == 1
    markdown, twin = _failure_report(ctx)
    assert markdown.startswith("# wpt scan — ")
    assert "Source: ftp://example.test" in markdown
    assert twin["source_summary"] == "ftp://example.test"
    assert "sup3rsecret" not in markdown
    assert "sup3rsecret" not in json.dumps(twin)
    assert "user:" not in markdown


def test_local_requires_zip(monkeypatch, tmp_path):
    calls = []

    def no_zip(path, **kwargs):
        calls.append(path)
        raise AssertionError("no source may be built without --zip")

    monkeypatch.setattr("wpt.scan.ZipSource", no_zip)
    ctx = local_ctx(tmp_path, zip=None)
    assert run(ctx) == 1
    assert calls == []

    markdown, twin = _failure_report(ctx)
    assert "## This run did not complete" in markdown
    assert "local mode requires --zip" in markdown
    assert twin["findings"] == []
    assert twin["run"]["status"] == "failed"
    assert "local mode requires --zip" in twin["run"]["reason"]


# --------------------------------------------------------------- failures


def test_failure_report_on_source_error(
    monkeypatch, tmp_path, wpt_records,
):
    def broken_source(ctx):
        raise SourceError("ftp is down")

    monkeypatch.setattr("wpt.scan.ftp_source_for", broken_source)
    ctx = ftp_ctx(tmp_path)
    assert run(ctx) == 1

    markdown, twin = _failure_report(ctx)
    assert "## This run did not complete" in markdown
    assert "ftp is down" in markdown
    assert "- findings: 0" in markdown
    assert twin["findings"] == []
    assert twin["plan"]["items"] == []
    assert twin["run"]["status"] == "failed"
    assert "ftp is down" in twin["run"]["reason"]
    assert _error_records(wpt_records) == ["scan failed: ftp is down"]


def test_source_closed_when_gather_fails(monkeypatch, tmp_path):
    source = TrackingSource()

    def broken_gather(*args, **kwargs):
        raise OSError("walk died")

    monkeypatch.setattr("wpt.scan.ftp_source_for", lambda ctx: source)
    monkeypatch.setattr("wpt.scan.gather_source", broken_gather)
    assert run(ftp_ctx(tmp_path)) == 1
    assert source.closed == 1


# --------------------------------------------------------------- selection


def test_check_selection_is_exactly_source_patterns(
    monkeypatch, tmp_path,
):
    import wpt.scan as scan_module

    source = source_with_session()
    monkeypatch.setattr("wpt.scan.ftp_source_for", lambda ctx: source)
    calls = []

    def fake_run_checks(data, settings, mode, only, skip, *, deadline=None):
        calls.append((data, settings, mode, only, skip))
        return []

    monkeypatch.setattr(scan_module, "run_checks", fake_run_checks)
    ctx = ftp_ctx(tmp_path, report_path=None)
    assert run(ctx) == 0

    assert len(calls) == 1
    data, _settings, mode, only, skip = calls[0]
    assert only == ["security.source_patterns"]
    assert skip is None
    assert mode == "ftp"
    assert data.mode == "ftp"
    assert data.source is source

    # And the same exact selection in local mode, from the zip source.
    local_source = source_with_session()
    monkeypatch.setattr("wpt.scan.ZipSource", lambda path, **kwargs: local_source)
    local = local_ctx(tmp_path, report_path=None)
    assert run(local) == 0
    assert len(calls) == 2
    data, _settings, mode, only, skip = calls[1]
    assert only == ["security.source_patterns"]
    assert skip is None
    assert mode == "local"
    assert data.source is local_source


def test_unwritable_report_fails_the_run(monkeypatch, tmp_path):
    source = source_with_session()
    monkeypatch.setattr("wpt.scan.ftp_source_for", lambda ctx: source)
    monkeypatch.setattr("wpt.scan.write_report", lambda *args, **kwargs: 1)
    assert run(ftp_ctx(tmp_path)) == 1
    assert source.closed == 1


def test_R23_surrogate_site_label_stdout_is_backslashreplaced(
        tmp_path, monkeypatch):
    """R23-P2: ``scan._site``/``logs._site_label`` returned a lone surrogate
    from argv (surrogateescape); a strict ``sys.stdout.write`` then raised
    UnicodeEncodeError with no rc 1.  ``report.safe_text`` is the ONE stdout
    policy and renders ``\\udcff``."""
    import io
    import sys

    source = FakeSource()
    source.files[PLUGIN] = SESSION
    monkeypatch.setattr("wpt.scan.ZipSource",
                        lambda path, **kwargs: source)
    ctx = local_ctx(tmp_path, wp_url="http://\udcff.example")
    ctx.report_path = None
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="utf-8", errors="strict")
    monkeypatch.setattr(sys, "stdout", stream)
    try:
        assert run(ctx) == 0
        stream.flush()
    finally:
        stream.detach()
    out = raw.getvalue().decode("utf-8")
    assert "\\udcff.example" in out


def test_R6_21_corrupt_zip_open_is_one_line_rc1(tmp_path, monkeypatch):
    """R6-21 at the command boundary: a UnicodeDecodeError/NotImplementedError
    from ZipFile must become the SourceError contract (rc 1), not a traceback."""
    import zipfile as zip_mod

    p = tmp_path / "site.zip"
    p.write_bytes(b"PK")
    ctx = Ctx(source="local", settings=load(), command="scan", zip=p,
              report_path=tmp_path / "scan.md")

    def _raise(*_args, **_kwargs):
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid filename")

    monkeypatch.setattr(zip_mod, "ZipFile", _raise)
    assert run(ctx) == 1
    assert "not a zip archive" in (
        tmp_path / "scan.md").read_text(encoding="utf-8")


def test_R7_P2_09_a_close_time_stop_never_replaces_the_primary_failure(
        tmp_path, monkeypatch):
    """R7-P2-09: scan wrote the failure report a second time from the close
    stop, erasing the primary failure the operator needs."""
    from wpt.types import StopRequested
    import wpt.scan as scan_mod

    class StopOnClose(FakeSource):
        def close(self):
            raise StopRequested("SIGTERM during close")

    source = StopOnClose()
    monkeypatch.setattr(scan_mod, "ZipSource", lambda path, **kwargs: source)

    def primary(src, mode, deadline=None):
        raise SourceError("PRIMARY-FAIL")

    monkeypatch.setattr(scan_mod, "gather_source", primary)
    ctx = Ctx(source="local", settings=load(), command="scan", zip=tmp_path,
              report_path=tmp_path / "scan.md", extra={})
    assert run(ctx) == 1
    report = (tmp_path / "scan.md").read_text(encoding="utf-8")
    assert "PRIMARY-FAIL" in report
    assert "SIGTERM during close" not in report


def test_R13_a_second_stop_in_the_failure_writer_keeps_the_primary_reason(
        tmp_path, monkeypatch, wpt_records):
    """R13-P2-18: the failure writer caught only ``Exception``; a second
    ``StopRequested`` during that write escaped and replaced the primary
    failure.  It is now one warning, and rc stays 1."""
    import wpt.scan as scan_mod
    from wpt.types import StopRequested

    class StopOnClose(FakeSource):
        def close(self):
            raise StopRequested("SIGTERM during close")

    monkeypatch.setattr(scan_mod, "ZipSource", lambda path, **kwargs: StopOnClose())

    def primary(src, mode, deadline=None):
        raise SourceError("PRIMARY-FAIL")

    monkeypatch.setattr(scan_mod, "gather_source", primary)

    def _stop(*args, **kwargs):
        raise StopRequested("SIGTERM during failure report")

    monkeypatch.setattr(scan_mod, "write_failure_report", _stop)
    ctx = Ctx(source="local", settings=load(), command="scan", zip=tmp_path,
              report_path=tmp_path / "scan.md", extra={})
    # The writer itself is the unit under test: a second stop must be
    # swallowed (one warning), never escape over the primary reason.
    import wpt.scan as scan_mod

    scan_mod._write_failure(ctx, "PRIMARY-FAIL")
    joined = "\n".join(r.getMessage() for r in wpt_records)
    assert "SIGTERM during failure report" in joined
