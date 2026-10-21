"""Tests for wpt.discover — a read-only account-root webroot scan.

All sources are the shared in-memory ``tests.fakes.FakeSource``: a candidate
is just a few paths in its store, so no network, temp FTP or filesystem walk
is involved.  ``run`` tests monkeypatch ``wpt.discover.ftp_source_for`` and
prove the account-root source is built with ``root=""`` and closed in the
``finally`` path.

Test -> behavior map:
  test_full_candidate_at_domains_site_public_html
        the DirectAdmin ``domains/<domain>/public_html`` shape is discovered
        through the wildcard candidate (no --webroot given)
  test_full_candidate_at_public_html
        the shared-host ``public_html`` shape
  test_partial_candidate_names_exact_missing_markers
        two-marker and one-marker partials carry the exact missing tuple
  test_direct_child_domain_public_html
        the cPanel-style ``<domain>/public_html`` child shape
  test_domain_ranking
        complete first, domain-matching first inside each group, then more
        markers, then path
  test_max_candidates_caps_inspection
        discover.max_candidates bounds the candidate list BEFORE listing
  test_one_candidate_listing_failure_does_not_kill_scan
        a SourceError on one candidate is a debug skip
  test_root_listing_failure_propagates / test_unhealthy_channel_is_not_masked
        run-level listing failures are never silent skips
  test_run_no_candidates_returns_1 ..... print/report a clear --webroot line
  test_run_multiple_complete_returns_0_and_warns
        multiple complete roots are still rc 0 with an operator warning
  test_run_local_refusal ............... ftp only, one error + failure report
  test_run_writes_markdown_and_json .... stdout == report file; JSON shape;
        source built with root="" and closed
  test_run_report_write_failure_returns_1
        an unwritable --report path fails the run after stdout printed
  test_run_closes_source_in_finally_on_scan_failure
        a failing scan still closes the account-root source and writes the
        shared "This run did not complete" report (reason redacted)
"""

import json
import logging
from dataclasses import replace

import pytest

import wpt.discover
from tests.fakes import FakeSource
from wpt.cli import Ctx
from wpt.settings import load
from wpt.types import FtpChannelUnhealthy, SourceError


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


class RecordingSource(FakeSource):
    """FakeSource that records every list_dir call."""

    def __init__(self) -> None:
        super().__init__()
        self.listed: list[str] = []

    def list_dir(self, path):
        self.listed.append(path)
        return super().list_dir(path)


class CloseCountingSource(FakeSource):
    def __init__(self) -> None:
        super().__init__()
        self.closed = 0

    def close(self):
        self.closed += 1


class FailingSource(RecordingSource):
    """One candidate directory answers the way a real missing FTP dir does."""

    def __init__(self, failing: str) -> None:
        super().__init__()
        self.failing = failing

    def list_dir(self, path):
        self.listed.append(path)
        if path == self.failing:
            raise SourceError(f"no such directory: {path}")
        return FakeSource.list_dir(self, path)


class RootFailSource(CloseCountingSource):
    def __init__(self, error: Exception) -> None:
        super().__init__()
        self.error = error

    def list_dir(self, path):
        if path == "":
            raise self.error
        return super().list_dir(path)


class UnhealthySource(FakeSource):
    def list_dir(self, path):
        raise FtpChannelUnhealthy("ftp channel unhealthy: cannot list")


def _settings(**overrides):
    return replace(load().discover, **overrides)


def _ctx(**overrides):
    kwargs = dict(
        source="ftp://host:2121",
        settings=load(),
        webroot=None,
        wp_url=None,
        report_path=None,
    )
    kwargs.update(overrides)
    return Ctx(**kwargs)


def _factory(source, calls=None):
    def build(ctx, root=None, source_cls=None):
        if calls is not None:
            calls.append({"ctx": ctx, "root": root,
                          "source_cls": source_cls})
        return source

    return build


def _join(root: str, name: str) -> str:
    return f"{root}/{name}" if root else name


def _add_full(source: FakeSource, root: str) -> None:
    """A complete WordPress webroot at ``root`` (three exact markers)."""
    source.files[_join(root, "wp-config.php")] = b"<?php // config\n"
    source.files[_join(root, "wp-content") + "/index.php"] = b"<?php\n"
    source.files[_join(root, "wp-includes") + "/version.php"] = b"<?php\n"


def _add_partial(source: FakeSource, root: str, present) -> None:
    """A partial webroot carrying only ``present`` markers."""
    for name in present:
        if name == "wp-config.php":
            source.files[_join(root, name)] = b"<?php\n"
        else:
            source.files[_join(root, name) + "/index.php"] = b"<?php\n"


# --------------------------------------------------------------------- tests


def test_full_candidate_at_domains_site_public_html():
    source = RecordingSource()
    _add_full(source, "domains/site/public_html")

    candidates = wpt.discover.scan(source, _settings())

    assert [candidate.path for candidate in candidates] == [
        "domains/site/public_html"]
    candidate = candidates[0]
    assert candidate.markers == ("wp-config.php", "wp-content", "wp-includes")
    assert candidate.missing == ()
    assert candidate.full is True
    assert candidate.partial is False
    # The wildcard enumeration is ONE listing, and the candidate itself is
    # inspected exactly once.
    assert source.listed.count("domains") == 1
    assert source.listed.count("domains/site/public_html") == 1


def test_nested_wwwroot_is_generated_from_the_same_docroot_family():
    source = RecordingSource()
    _add_full(source, "domains/site/wwwroot")

    candidates = wpt.discover.scan(source, _settings())

    assert [candidate.path for candidate in candidates] == [
        "domains/site/wwwroot"]


def test_full_candidate_at_public_html():
    source = FakeSource()
    _add_full(source, "public_html")

    candidates = wpt.discover.scan(source, _settings())

    assert [candidate.path for candidate in candidates] == ["public_html"]
    assert candidates[0].full is True


@pytest.mark.parametrize(("present", "markers", "missing"), [
    (("wp-config.php", "wp-content"),
     ("wp-config.php", "wp-content"),
     ("wp-includes",)),
    (("wp-config.php",),
     ("wp-config.php",),
     ("wp-content", "wp-includes")),
    (("wp-content", "wp-includes"),
     ("wp-content", "wp-includes"),
     ("wp-config.php",)),
])
def test_partial_candidate_names_exact_missing_markers(present, markers,
                                                       missing):
    source = FakeSource()
    _add_partial(source, "public_html", present)

    candidates = wpt.discover.scan(source, _settings())

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.markers == markers
    assert candidate.missing == missing
    assert candidate.full is False
    assert candidate.partial is True


def test_direct_child_domain_public_html():
    source = FakeSource()
    _add_full(source, "example.com/public_html")

    candidates = wpt.discover.scan(source, _settings())

    assert [candidate.path for candidate in candidates] == [
        "example.com/public_html"]
    assert candidates[0].full is True


def test_domain_ranking():
    source = FakeSource()
    _add_full(source, "public_html")
    _add_full(source, "domains/site.test/public_html")
    _add_partial(source, "www", ("wp-content", "wp-includes"))
    _add_partial(source, "domains/site.test/httpdocs", ("wp-config.php",))

    candidates = wpt.discover.scan(source, _settings(), domain="site.test")

    # Complete group: the domain path wins before the generic one.
    # Partial group: the domain path wins even with FEWER markers; the
    # "more markers first" rule only orders inside that domain rank.
    assert [candidate.path for candidate in candidates] == [
        "domains/site.test/public_html",
        "public_html",
        "domains/site.test/httpdocs",
        "www",
    ]
    assert [candidate.full for candidate in candidates] == [
        True, True, False, False]
    assert [len(candidate.markers) for candidate in candidates] == [3, 3, 1, 2]


def test_max_candidates_caps_inspection():
    source = RecordingSource()
    _add_full(source, "public_html")
    _add_full(source, "www")

    candidates = wpt.discover.scan(source, _settings(max_candidates=2))

    assert [candidate.path for candidate in candidates] == ["public_html"]
    # The cap is applied BEFORE listing: only the root candidate and
    # public_html were inspected (www is candidate 3).
    assert source.listed == ["", "public_html"]


def test_one_candidate_listing_failure_does_not_kill_scan(wpt_records):
    source = FailingSource("public_html")
    _add_full(source, "domains/site/public_html")

    candidates = wpt.discover.scan(source, _settings())

    assert [candidate.path for candidate in candidates] == [
        "domains/site/public_html"]
    assert any(record.name == "wpt.discover"
               and record.levelno == logging.DEBUG
               and "no webroot at public_html" in record.getMessage()
               for record in wpt_records)


def test_root_listing_failure_propagates():
    source = RootFailSource(SourceError("permission denied: account root"))

    with pytest.raises(SourceError, match="permission denied"):
        wpt.discover.scan(source, _settings())


def test_unhealthy_channel_is_not_masked():
    with pytest.raises(FtpChannelUnhealthy):
        wpt.discover.scan(UnhealthySource(), _settings())


def test_run_no_candidates_returns_1(monkeypatch, tmp_path, capsys,
                                     wpt_records):
    source = CloseCountingSource()
    calls: list[dict] = []
    monkeypatch.setattr(wpt.discover, "ftp_source_for",
                        _factory(source, calls))
    ctx = _ctx(report_path=tmp_path / "discover.md")

    assert wpt.discover.run(ctx) == 1

    out = capsys.readouterr().out
    assert "Found 0 candidate(s); 0 complete WordPress webroot(s)." in out
    assert "No WordPress webroot was found" in out
    assert "--webroot" in out
    markdown = ctx.report_path.read_text(encoding="utf-8")
    assert markdown == out
    assert "## This run did not complete" not in markdown
    twin = json.loads(ctx.report_path.with_suffix(".json")
                      .read_text(encoding="utf-8"))
    assert twin["totals"] == {"candidates": 0, "complete": 0, "partial": 0}
    assert twin["candidates"] == []
    assert calls and calls[0]["root"] == ""
    assert source.closed == 1
    assert not [record for record in wpt_records
                if record.levelno == logging.WARNING]


def test_run_multiple_complete_returns_0_and_warns(monkeypatch, capsys,
                                                   wpt_records):
    source = FakeSource()
    _add_full(source, "public_html")
    _add_full(source, "www")
    monkeypatch.setattr(wpt.discover, "ftp_source_for", _factory(source))
    ctx = _ctx()

    assert wpt.discover.run(ctx) == 0

    out = capsys.readouterr().out
    assert "Found 2 candidate(s); 2 complete WordPress webroot(s)." in out
    warnings = [record for record in wpt_records
                if record.name == "wpt.discover"
                and record.levelno == logging.WARNING]
    assert len(warnings) == 1
    message = warnings[0].getMessage()
    assert "operator must choose" in message
    assert "--webroot" in message
    assert "public_html" in message and "www" in message


def test_malformed_wp_url_is_not_fatal(monkeypatch, tmp_path):
    source = FakeSource()
    _add_full(source, "public_html")
    monkeypatch.setattr(wpt.discover, "ftp_source_for", _factory(source))
    ctx = _ctx(wp_url="https://[", report_path=tmp_path / "discover.md")

    assert wpt.discover.run(ctx) == 0

    twin = json.loads(ctx.report_path.with_suffix(".json")
                      .read_text(encoding="utf-8"))
    assert twin["domain"] is None
    assert [row["path"] for row in twin["candidates"]] == ["public_html"]


def test_run_local_refusal(monkeypatch, tmp_path, wpt_records):
    def never(*args, **kwargs):
        raise AssertionError("ftp_source_for must not run in local mode")

    monkeypatch.setattr(wpt.discover, "ftp_source_for", never)
    ctx = _ctx(source="local", report_path=tmp_path / "discover.md")

    assert wpt.discover.run(ctx) == 1

    markdown = ctx.report_path.read_text(encoding="utf-8")
    assert markdown.startswith("# wpt discover — ")
    assert "## This run did not complete" in markdown
    assert "ftp-only" in markdown
    twin = json.loads(ctx.report_path.with_suffix(".json")
                      .read_text(encoding="utf-8"))
    assert twin["run"]["status"] == "failed"
    errors = [record for record in wpt_records
              if record.name == "wpt.discover"
              and record.levelno == logging.ERROR]
    assert len(errors) == 1
    assert "ftp-only" in errors[0].getMessage()


def test_run_writes_markdown_and_json(monkeypatch, tmp_path, capsys,
                                      wpt_records):
    source = CloseCountingSource()
    _add_full(source, "domains/site.test/public_html")
    _add_partial(source, "www", ("wp-config.php",))
    calls: list[dict] = []
    monkeypatch.setattr(wpt.discover, "ftp_source_for",
                        _factory(source, calls))
    ctx = _ctx(wp_url="https://www.Site.test/", password="s3cret-value",
               report_path=tmp_path / "discover.md")

    assert wpt.discover.run(ctx) == 0

    out = capsys.readouterr().out
    assert out.startswith("# wpt discover — ftp://host:2121")
    assert "Found 2 candidate(s); 1 complete WordPress webroot(s)." in out
    assert "| domains/site.test/public_html | complete |" in out
    assert "| www | partial |" in out
    assert "missing: wp-content, wp-includes" in out

    markdown = ctx.report_path.read_text(encoding="utf-8")
    assert markdown == out
    raw_json = ctx.report_path.with_suffix(".json").read_text(encoding="utf-8")
    assert raw_json.endswith("\n")
    twin = json.loads(raw_json)
    assert set(twin) == {"source", "domain", "candidates", "totals"}
    assert twin["source"] == "ftp://host:2121"
    assert twin["domain"] == "site.test"
    assert twin["totals"] == {"candidates": 2, "complete": 1, "partial": 1}
    assert [row["path"] for row in twin["candidates"]] == [
        "domains/site.test/public_html", "www"]
    assert twin["candidates"][0]["wordpress"] == "complete"
    assert twin["candidates"][0]["markers"] == [
        "wp-config.php", "wp-content", "wp-includes"]
    assert twin["candidates"][0]["missing"] == []
    assert twin["candidates"][1]["wordpress"] == "partial"
    assert twin["candidates"][1]["missing"] == [
        "wp-content", "wp-includes"]
    assert "s3cret-value" not in markdown
    assert "s3cret-value" not in raw_json
    assert len(calls) == 1 and calls[0]["root"] == ""
    assert source.closed == 1
    infos = [record for record in wpt_records
             if record.name == "wpt.discover"
             and record.levelno == logging.INFO]
    assert [record.getMessage() for record in infos] == [
        "discover: 2 candidate(s), 1 complete, 1 partial"]


def test_run_report_write_failure_returns_1(monkeypatch, tmp_path, capsys):
    source = FakeSource()
    _add_full(source, "public_html")
    monkeypatch.setattr(wpt.discover, "ftp_source_for", _factory(source))
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    ctx = _ctx(report_path=blocked)

    assert wpt.discover.run(ctx) == 1

    assert "Found 1 candidate(s); 1 complete WordPress webroot(s)." in \
        capsys.readouterr().out
    assert blocked.is_dir()


def test_run_closes_source_in_finally_on_scan_failure(monkeypatch, tmp_path,
                                                       wpt_records):
    source = RootFailSource(
        SourceError("ftp channel unhealthy: password=s3cret-value"))
    monkeypatch.setattr(wpt.discover, "ftp_source_for", _factory(source))
    ctx = _ctx(password="s3cret-value", report_path=tmp_path / "discover.md")

    assert wpt.discover.run(ctx) == 1

    assert source.closed == 1
    markdown = ctx.report_path.read_text(encoding="utf-8")
    assert "## This run did not complete" in markdown
    assert "s3cret-value" not in markdown
    twin = json.loads(ctx.report_path.with_suffix(".json")
                      .read_text(encoding="utf-8"))
    assert twin["run"]["status"] == "failed"
    assert "s3cret-value" not in json.dumps(twin)
    errors = [record for record in wpt_records
              if record.name == "wpt.discover"
              and record.levelno == logging.ERROR]
    assert len(errors) == 1
    assert "s3cret-value" not in errors[0].getMessage()


# ------------------------------------------------------- round-1 regressions


def test_LOGS_2_domain_ranking_uses_path_segments_not_substrings():
    source = FakeSource()
    _add_full(source, "domains/othersite.test/public_html")
    _add_full(source, "domains/site.test/public_html")

    candidates = wpt.discover.scan(source, _settings(), domain="site.test")

    # "site.test" is a SUBSTRING of "othersite.test"; only the exact path
    # segment is the known domain.
    assert [candidate.path for candidate in candidates] == [
        "domains/site.test/public_html",
        "domains/othersite.test/public_html",
    ]


def test_DEADLINE_1_discover_run_honours_an_expired_budget(
        monkeypatch, tmp_path):
    from wpt.types import DeadlineExceeded

    class _Expired:
        def check(self, context):
            raise DeadlineExceeded("run deadline exceeded")

    source = CloseCountingSource()
    _add_full(source, "public_html")
    monkeypatch.setattr(wpt.discover, "ftp_source_for", _factory(source))
    monkeypatch.setattr(wpt.discover.Deadline, "from_ctx",
                        lambda ctx: _Expired())
    ctx = _ctx(report_path=tmp_path / "discover.md")

    assert wpt.discover.run(ctx) == 1
    assert "deadline exceeded" in (
        tmp_path / "discover.md").read_text(encoding="utf-8").lower()
    assert source.closed == 1


def test_LOG_WWW_a_www_path_matches_the_known_domain():
    """LOG-WWW: _rank compared raw path segments to the normalized domain, so
    domains/www.site.test never matched site.test and lost lexically to an
    unrelated domain."""
    source = FakeSource()
    _add_full(source, "domains/othersite.test/public_html")
    _add_full(source, "domains/www.site.test/public_html")

    candidates = wpt.discover.scan(source, _settings(), domain="site.test")

    assert [candidate.path for candidate in candidates] == [
        "domains/www.site.test/public_html",
        "domains/othersite.test/public_html",
    ]


def test_CLOSE_STOP_discover_returns_1_and_still_writes_the_report(
        tmp_path, monkeypatch):
    """CLOSE-STOP: discover swallowed StopRequested raised by close() and
    wrote a success report with rc 0."""
    from wpt.types import StopRequested

    class StopOnClose(FakeSource):
        def close(self):
            raise StopRequested("SIGTERM during close")

    source = StopOnClose()
    monkeypatch.setattr(wpt.discover, "ftp_source_for",
                        lambda ctx, root=None: source)
    ctx = _ctx(report_path=tmp_path / "discover.md")
    assert wpt.discover.run(ctx) == 1
    assert "did not complete" in (tmp_path / "discover.md").read_text("utf-8")


def test_FTP_SYMLINK_CONFIG_discover_accepts_a_linked_config():
    """FTP-SYMLINK-CONFIG: the same exact-pair predicate in discover._markers
    rejected a symlinked wp-config.php."""
    from wpt.types import Entry

    entries = [
        Entry("wp-config.php", True, size=0, is_link=True),
        Entry("wp-content", True, size=0),
        Entry("wp-includes", True, size=0),
    ]
    assert wpt.discover._markers(entries, "") == (
        "wp-config.php", "wp-content", "wp-includes")


# ------------------------------------------------------- triple-check round 6


def test_R6_12_a_slow_last_listing_ends_rc1_at_the_deadline(monkeypatch,
                                                            tmp_path):
    """R6-12: the deadline was checked only BEFORE a listing, so one slow
    LIST overran the budget and still returned success.  Check after every
    listing and before the report."""
    import time

    class SlowSource(CloseCountingSource):
        def list_dir(self, path):
            time.sleep(0.06)
            return super().list_dir(path)

    source = SlowSource()
    _add_full(source, "public_html")
    monkeypatch.setattr(wpt.discover, "ftp_source_for",
                        lambda ctx, root=None, source_cls=None: source)
    ctx = _ctx(settings=load(), deadline_s=0.02)

    started = time.monotonic()
    assert wpt.discover.run(ctx) == 1
    assert time.monotonic() - started >= 0.05
    assert source.closed == 1


def test_R7_P2_09_a_close_time_stop_never_replaces_the_primary_failure(
        tmp_path, monkeypatch):
    """R7-P2-09: discover wrote the stop's failure report over the primary
    scan failure."""
    from wpt.types import SourceError, StopRequested

    class StopOnClose(FakeSource):
        def close(self):
            raise StopRequested("SIGTERM during close")

    source = StopOnClose()
    monkeypatch.setattr(wpt.discover, "ftp_source_for",
                        lambda ctx, root=None: source)

    def primary(*args, **kwargs):
        raise SourceError("PRIMARY-FAIL")

    monkeypatch.setattr(wpt.discover, "scan", primary)
    ctx = _ctx(report_path=tmp_path / "discover.md")
    assert wpt.discover.run(ctx) == 1
    report = (tmp_path / "discover.md").read_text(encoding="utf-8")
    assert "PRIMARY-FAIL" in report
    assert "SIGTERM during close" not in report


# ------------------------------------------------ triple-check round 8 (P2)


def test_P2_04_candidate_paths_are_redacted_in_both_faces(tmp_path):
    """P2-04: a directory named `password=HUNTER2` reached the markdown and
    JSON twin verbatim."""
    import wpt.discover as discover_mod
    from wpt.settings import load

    candidate = discover_mod.WebrootCandidate(
        path="domains/password=HUNTER2/public_html",
        markers=("wp-config.php", "wp-content", "wp-includes"),
        missing=(),
    )
    ctx = Ctx(source="ftp://h", settings=load(), webroot="")
    markdown = discover_mod._markdown(ctx, [candidate])
    twin = discover_mod._json_text(
        ctx, None, [candidate])

    assert "HUNTER2" not in markdown
    assert "HUNTER2" not in twin
    assert "password=***" in markdown
    assert "password=***" in twin


def test_R13_a_second_stop_in_the_discover_failure_writer_is_contained(
        tmp_path, monkeypatch, wpt_records):
    """R13-P2-18: discover's failure writer had no try at all, so a second
    stop escaped and replaced the primary reason."""
    import wpt.actions.registry as registry_mod
    from wpt.types import StopRequested

    def _stop(*args, **kwargs):
        raise StopRequested("SIGTERM during failure report")

    monkeypatch.setattr(registry_mod, "write_report", _stop)
    ctx = _ctx(report_path=tmp_path / "discover.md")
    wpt.discover._write_failure(ctx, "PRIMARY-FAIL")
    joined = "\n".join(r.getMessage() for r in wpt_records)
    assert "SIGTERM during failure report" in joined


def test_R24_surrogate_source_and_path_are_safe_on_strict_stdout(
        monkeypatch, tmp_path):
    """R24-P2: a lone surrogate from argv/bridge JSON reached
    ``sys.stdout.write`` through the header and table; a strict UTF-8 stream
    raised UnicodeEncodeError after the scan.  Both the source label and the
    displayed candidate path cross ``safe_text``."""
    import io

    source = CloseCountingSource()
    _add_full(source, "domains/site.test/public_html")
    source.files["bad\udcffpath/wp-config.php"] = b"x"
    monkeypatch.setattr(wpt.discover, "ftp_source_for",
                        _factory(source, []))
    ctx = _ctx(wp_url="https://site.test/", report_path=tmp_path / "d.md")
    ctx.source = "ftp://host/\udcff"
    stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8",
                              errors="strict", newline="")
    monkeypatch.setattr("wpt.report.sys.stdout", stream)
    assert wpt.discover.run(ctx) == 0
    stream.flush()
    written = stream.buffer.getvalue().decode("utf-8", "strict")
    assert "\\udcff" in written
    assert "# wpt discover — ftp://host/\\udcff" in written
    assert "bad\\udcffpath" in wpt.discover._display("bad\udcffpath")
