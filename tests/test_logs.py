"""Tests for wpt.logs — bounded, read-only host/webroot error-log triage.

Everything runs through ``collect``/``run`` with real ``Ctx`` objects and the
shared ``tests.fakes.FakeSource`` for BOTH sources (webroot + account home);
archives are built in memory with ``tarfile``/``gzip``.  No network, no temp
network, no sleeps.

Test -> behavior map:
  test_candidate_derivation_domains_site_public_html
        domains/<domain>/public_html -> domains/<domain>/logs,
        <webroot-parent>/logs, logs, and the domain-derived candidates,
        deduped in contract order; with --wp-url the URL host wins as the
        known domain while the webroot-shaped sibling stays first
  test_plain_log_match .............. one PHP fatal line: scanned/matches
        counts, path, line number and the per-file record
  test_no_matches ................... a clean log: zero counts and the
        explicit "No error/fatal patterns found" markdown line
  test_direct_webroot_file .......... wp-content/debug.log is read through
        the WEBROOT source (the account source carries no copy)
  test_archive_member_match ......... a .tar.gz member is read in memory and
        its matching line names the archive:member path
  test_gzip_log_scanned ............. a single .gz is decompressed with the
        bounded read and scanned
  test_oversize_plain_is_skipped_without_read
        entry.size above logs.max_file_bytes: no read_bytes call, one
        skipped record naming the bound
  test_oversize_archive_is_skipped_without_read
        archive bytes above logs.max_archive_bytes: no read_bytes call
  test_redaction_and_truncation ..... rendered match is redacted, whitespace
        collapsed and capped at 300 chars
  test_detail_limit_caps_rows_not_total
        logs.detail_limit caps stored rows; total_matches and the per-file
        count still count every matching line
  test_mtime_sort_and_max_files_cap . newest mtime first, total candidates
        capped at logs.max_files
  test_missing_dirs_are_tolerated ... a SourceError per candidate directory
        is debug-logged and the scan still succeeds with zero skips
  test_collect_closes_only_owned_sources
        built sources are closed exactly once; passed sources never are
  test_run_local_refusal ............ local mode: rc 1, one error log, the
        refusal report on disk, collect never called
  test_run_writes_markdown_and_json . stdout markdown, --report markdown +
        exact JSON twin shape, one info summary, sources closed, no password
  test_run_report_write_refusal_returns_1
        an unwritable --report path answers rc 1 after stdout was printed
  test_run_catches_operational_errors
        SourceError and OSError become rc 1 with one redacted error line and
        the shared "This run did not complete" report, never a traceback
"""

import gzip
import io
import json
import logging
import tarfile
import time
from dataclasses import replace

import pytest

import wpt.logs
from tests.fakes import FakeSource
from wpt.cli import Ctx
from wpt.settings import load
from wpt.types import Entry, SourceError


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
    """FakeSource that records list_dir/read_bytes calls (read-bound proofs)."""

    def __init__(self) -> None:
        super().__init__()
        self.listed: list[str] = []
        self.reads: list[str] = []

    def list_dir(self, path):
        self.listed.append(path)
        return super().list_dir(path)

    def read_bytes(self, path):
        self.reads.append(path)
        return super().read_bytes(path)


class CloseCountingSource(FakeSource):
    def __init__(self) -> None:
        super().__init__()
        self.closed = 0

    def close(self):
        self.closed += 1


class MissingDirsSource(FakeSource):
    """Every candidate directory answers the way a real missing FTP dir does."""

    def list_dir(self, path):
        raise SourceError(f"no such directory: {path}")


class ListedSource(FakeSource):
    """FakeSource whose one host-log directory answers a canned listing."""

    def __init__(self, listing: list[Entry]) -> None:
        super().__init__()
        self.listing = listing

    def list_dir(self, path):
        if path == "domains/site/logs":
            return list(self.listing)
        return []


def _settings(**logs):
    settings = load()
    return replace(settings, logs=replace(settings.logs, **logs))


def _ctx(tmp_path=None, **overrides):
    kwargs = dict(
        source="ftp://host:2121",
        settings=load(),
        webroot="domains/site/public_html",
        wp_url=None,
        report_path=None,
    )
    kwargs.update(overrides)
    return Ctx(**kwargs)


def _collect(account, webroot=None, **ctx_overrides):
    return wpt.logs.collect(
        _ctx(**ctx_overrides),
        webroot_source=webroot or FakeSource(),
        account_source=account,
    )


def _tar_gz(members: dict[str, bytes], mtime: int = 1_700_000_000) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = mtime
            archive.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _gzip(data: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as handle:
        handle.write(data)
    return buf.getvalue()


def _factory(webroot, account):
    def build(ctx, root=None, source_cls=None):
        return webroot if root is None else account
    return build


# --------------------------------------------------------------------- tests


def test_candidate_derivation_domains_site_public_html():
    account = RecordingSource()
    wpt.logs.collect(_ctx(), webroot_source=FakeSource(),
                     account_source=account)
    # webroot-derived domain ("site"): candidate 1 and 2 collapse, then logs,
    # then the domain-derived pair (domains/site/logs is already present).
    assert account.listed == ["domains/site/logs", "logs", "site/logs"]

    account = RecordingSource()
    wpt.logs.collect(_ctx(wp_url="https://site.test"),
                     webroot_source=FakeSource(), account_source=account)
    # --wp-url supplies the known domain; the webroot-shaped sibling stays
    # FIRST because it is candidate 1.
    assert account.listed == [
        "domains/site/logs", "logs", "domains/site.test/logs", "site.test/logs",
    ]


def test_plain_log_match():
    account = FakeSource()
    account.files["domains/site/logs/error.log"] = (
        b"2026-10-19 PHP Fatal error: Uncaught boom in /x.php:1\n")

    scan = _collect(account)

    assert scan.scanned == 1
    assert scan.total_matches == 1
    assert scan.matches == [{
        "file": "domains/site/logs/error.log",
        "line": 1,
        "pattern": "PHP fatal",
        "match": "2026-10-19 PHP Fatal error: Uncaught boom in /x.php:1",
    }]
    assert scan.files == [{
        "path": "domains/site/logs/error.log",
        "bytes": len(account.files["domains/site/logs/error.log"]),
        "kind": "plain",
        "members": 1,
        "matches": 1,
    }]
    assert "Scanned 1 file(s); 1 matching line(s); 0 skipped" in scan.markdown()


def test_no_matches():
    account = FakeSource()
    account.files["domains/site/logs/access.log"] = b"GET / 200 12ms\n"

    scan = _collect(account)

    assert scan.scanned == 1
    assert scan.total_matches == 0
    assert scan.matches == []
    markdown = scan.markdown()
    assert "Scanned 1 file(s); 0 matching line(s); 0 skipped" in markdown
    assert "No error/fatal patterns found in the scanned logs." in markdown


def test_direct_webroot_file():
    webroot = FakeSource()
    webroot.files["wp-content/debug.log"] = b"PHP Warning: permission denied\n"
    account = FakeSource()

    scan = wpt.logs.collect(_ctx(), webroot_source=webroot,
                            account_source=account)

    assert scan.scanned == 1
    assert scan.matches[0]["file"] == "wp-content/debug.log"
    assert scan.matches[0]["pattern"] == "permission denied"
    assert scan.files[0]["kind"] == "plain"


def test_direct_webroot_log_wins_the_cap_over_dated_host_logs():
    """A direct error_log/debug.log has no LIST mtime; it must still be
    considered before the max_files cap, or the one file the operator can
    actually open in the docroot is silently dropped."""
    webroot = FakeSource()
    webroot.files["error_log"] = b"PHP Fatal error: direct\n"
    account = ListedSource([
        Entry(path="domains/site/logs/new.log", is_dir=False, size=8,
              mtime=300),
    ])
    account.files["domains/site/logs/new.log"] = b"PHP Fatal error: host\n"

    scan = wpt.logs.collect(
        _ctx(settings=_settings(max_files=1)),
        webroot_source=webroot, account_source=account)

    assert scan.scanned == 1
    assert scan.files[0]["path"] == "error_log"
    assert scan.skipped == [{
        "path": "domains/site/logs/new.log",
        "reason": "exceeds logs.max_files (1)",
    }]


def test_archive_member_match():
    archive = _tar_gz({"logs/site.error.log": b"PHP Parse error: bad\n"})
    account = FakeSource()
    account.files["domains/site/logs/2026-09.tar.gz"] = archive

    scan = _collect(account)

    assert scan.scanned == 1
    assert scan.total_matches == 1
    assert scan.matches[0]["file"] == (
        "domains/site/logs/2026-09.tar.gz:logs/site.error.log")
    assert scan.matches[0]["pattern"] == "PHP parse"
    assert scan.files[0]["kind"] == "tar.gz"
    assert scan.files[0]["members"] == 1
    assert scan.files[0]["matches"] == 1
    assert scan.skipped == []


def test_gzip_log_scanned():
    account = FakeSource()
    account.files["domains/site/logs/old.log.gz"] = _gzip(
        b"SQLSTATE[HY000]: general error\n")

    scan = _collect(account)

    assert scan.scanned == 1
    assert scan.matches[0]["pattern"] == "SQLSTATE"
    assert scan.files[0]["kind"] == "gzip"
    assert scan.files[0]["members"] == 1


def test_R9_P2_15_top_level_gzip_is_charged_to_the_decompressed_ceiling():
    """P2-15: a top-level .gz was bounded only by max_file_bytes, so a
    48 KB expansion under a 20 KB max_decompressed_bytes still matched."""
    account = FakeSource()
    account.files["domains/site/logs/big.log.gz"] = _gzip(
        (b"PHP Fatal error: boom\n" * 2000))

    scan = _collect(account, settings=_settings(
        max_file_bytes=1024 * 1024, max_decompressed_bytes=20_000))

    assert scan.matches == []
    assert scan.files == []
    assert scan.skipped == [{
        "path": "domains/site/logs/big.log.gz",
        "reason": ("archive decompression exceeds "
                   "logs.max_decompressed_bytes (20000)"),
    }]


def test_oversize_plain_is_skipped_without_read():
    account = RecordingSource()
    account.files["domains/site/logs/big.log"] = b"x" * 64

    scan = _collect(account, settings=_settings(max_file_bytes=32))

    assert scan.scanned == 0
    assert scan.files == []
    assert account.reads == []
    assert len(scan.skipped) == 1
    assert scan.skipped[0]["path"] == "domains/site/logs/big.log"
    assert "logs.max_file_bytes" in scan.skipped[0]["reason"]


def test_oversize_archive_is_skipped_without_read():
    account = RecordingSource()
    archive = _tar_gz({"logs/error.log": b"PHP Fatal error: boom\n"})
    assert len(archive) > 16
    account.files["domains/site/logs/big.tar.gz"] = archive

    scan = _collect(account, settings=_settings(max_archive_bytes=16))

    assert scan.scanned == 0
    assert account.reads == []
    assert len(scan.skipped) == 1
    assert "logs.max_archive_bytes" in scan.skipped[0]["reason"]


def test_redaction_and_truncation():
    account = FakeSource()
    account.files["domains/site/logs/error.log"] = (
        "PHP Fatal error:   password=hunter2\t" + ("z" * 500) + "\n").encode()

    scan = _collect(account)

    rendered = scan.matches[0]["match"]
    assert "hunter2" not in rendered
    assert "password=***" in rendered
    assert len(rendered) == 300
    assert "\n" not in rendered
    assert "  " not in rendered
    assert "hunter2" not in scan.markdown()
    assert "hunter2" not in scan.json_text()


def test_detail_limit_caps_rows_not_total():
    account = FakeSource()
    account.files["domains/site/logs/error.log"] = (
        b"SQLSTATE[HY000]: one\n"
        b"PDOException: two\n"
        b"No such file or directory: three\n")

    scan = _collect(account, settings=_settings(detail_limit=2))

    assert len(scan.matches) == 2
    assert [row["pattern"] for row in scan.matches] == [
        "SQLSTATE", "PDOException"]
    assert scan.total_matches == 3
    assert scan.files[0]["matches"] == 3
    table_rows = [line for line in scan.markdown().splitlines()
                  if line.startswith("| ") and not line.startswith("| file ")]
    assert len(table_rows) == 2
    assert json.loads(scan.json_text())["totals"] == {
        "scanned": 1, "matches": 3, "skipped": 0,
    }


def test_mtime_sort_and_max_files_cap():
    listing = [
        Entry(path="domains/site/logs/old.log", is_dir=False, size=8,
              mtime=100),
        Entry(path="domains/site/logs/new.log", is_dir=False, size=8,
              mtime=300),
        Entry(path="domains/site/logs/mid.log", is_dir=False, size=8,
              mtime=200),
    ]
    account = ListedSource(listing)
    for entry in listing:
        account.files[entry.path] = b"clean\n"

    scan = _collect(account, settings=_settings(max_files=2))

    assert scan.scanned == 2
    assert [row["path"] for row in scan.files] == [
        "domains/site/logs/new.log",
        "domains/site/logs/mid.log",
    ]
    assert scan.skipped == [{
        "path": "domains/site/logs/old.log",
        "reason": "exceeds logs.max_files (2)",
    }]


def test_missing_dirs_are_tolerated(wpt_records):
    scan = wpt.logs.collect(_ctx(), webroot_source=FakeSource(),
                            account_source=MissingDirsSource())

    assert scan.scanned == 0
    assert scan.files == []
    assert scan.matches == []
    assert scan.skipped == []
    assert any(record.name == "wpt.logs" and record.levelno == logging.DEBUG
               and "no log directory" in record.getMessage()
               for record in wpt_records)


def test_collect_closes_only_owned_sources(monkeypatch):
    owned_webroot = CloseCountingSource()
    owned_account = CloseCountingSource()
    monkeypatch.setattr(wpt.logs, "ftp_source_for",
                        _factory(owned_webroot, owned_account))

    wpt.logs.collect(_ctx())

    assert owned_webroot.closed == 1
    assert owned_account.closed == 1

    passed_webroot = CloseCountingSource()
    passed_account = CloseCountingSource()
    wpt.logs.collect(_ctx(), webroot_source=passed_webroot,
                     account_source=passed_account)

    assert passed_webroot.closed == 0
    assert passed_account.closed == 0

    # Mixed ownership: only the source collect built is closed.
    built_account = CloseCountingSource()
    monkeypatch.setattr(wpt.logs, "ftp_source_for",
                        _factory(CloseCountingSource(), built_account))
    wpt.logs.collect(_ctx(), webroot_source=passed_webroot)

    assert passed_webroot.closed == 0
    assert built_account.closed == 1


def test_run_local_refusal(monkeypatch, tmp_path, wpt_records):
    def never(*args, **kwargs):
        raise AssertionError("collect must not run in local mode")

    monkeypatch.setattr(wpt.logs, "collect", never)
    ctx = _ctx(source="local", webroot=None, report_path=tmp_path / "logs.md")

    assert wpt.logs.run(ctx) == 1

    markdown = ctx.report_path.read_text(encoding="utf-8")
    assert markdown.startswith("# wpt logs — ")
    assert "## This run did not complete" in markdown
    assert "ftp-only" in markdown
    twin = json.loads(ctx.report_path.with_suffix(".json")
                      .read_text(encoding="utf-8"))
    assert twin["run"]["status"] == "failed"
    errors = [record for record in wpt_records
              if record.name == "wpt.logs" and record.levelno == logging.ERROR]
    assert errors
    assert any("ftp-only" in record.getMessage() for record in errors)


def test_run_writes_markdown_and_json(monkeypatch, tmp_path, capsys,
                                      wpt_records):
    webroot = CloseCountingSource()
    webroot.files["wp-content/debug.log"] = b"permission denied\n"
    account = CloseCountingSource()
    account.files["domains/site/logs/error.log"] = b"PHP Fatal error: boom\n"
    monkeypatch.setattr(wpt.logs, "ftp_source_for", _factory(webroot, account))
    ctx = _ctx(wp_url="https://site.test", password="s3cret-value",
               report_path=tmp_path / "logs.md")

    assert wpt.logs.run(ctx) == 0

    out = capsys.readouterr().out
    assert out.startswith("# wpt logs — https://site.test")
    assert "Scanned 2 file(s); 2 matching line(s); 0 skipped" in out
    markdown = ctx.report_path.read_text(encoding="utf-8")
    assert markdown == out
    raw_json = ctx.report_path.with_suffix(".json").read_text(encoding="utf-8")
    assert raw_json.endswith("\n")
    twin = json.loads(raw_json)
    assert set(twin) == {
        "site", "source_summary", "totals", "files", "matches", "skipped"}
    assert twin["totals"] == {"scanned": 2, "matches": 2, "skipped": 0}
    assert "s3cret-value" not in markdown
    assert "s3cret-value" not in raw_json
    assert webroot.closed == 1
    assert account.closed == 1
    infos = [record for record in wpt_records
             if record.name == "wpt.logs" and record.levelno == logging.INFO]
    assert any("scanned 2 file(s), 2 matches, 0 skipped"
               in record.getMessage() for record in infos)


def test_run_report_write_refusal_returns_1(monkeypatch, tmp_path, capsys):
    webroot = FakeSource()
    webroot.files["error_log"] = b"PHP Fatal error: boom\n"
    account = FakeSource()
    monkeypatch.setattr(wpt.logs, "ftp_source_for", _factory(webroot, account))
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    ctx = _ctx(report_path=blocked)

    assert wpt.logs.run(ctx) == 1

    assert "Scanned 1 file(s); 1 matching line(s); 0 skipped" in \
        capsys.readouterr().out
    assert blocked.is_dir()


@pytest.mark.parametrize("error", [
    SourceError("ftp channel unhealthy: password=s3cret-value"),
    OSError("disk I/O error: password=s3cret-value"),
])
def test_run_catches_operational_errors(monkeypatch, tmp_path, wpt_records,
                                        error):
    def boom(*args, **kwargs):
        raise error

    monkeypatch.setattr(wpt.logs, "collect", boom)
    ctx = _ctx(password="s3cret-value", report_path=tmp_path / "logs.md")

    assert wpt.logs.run(ctx) == 1

    markdown = ctx.report_path.read_text(encoding="utf-8")
    assert "## This run did not complete" in markdown
    assert "s3cret-value" not in markdown
    twin = json.loads(ctx.report_path.with_suffix(".json")
                      .read_text(encoding="utf-8"))
    assert twin["run"]["status"] == "failed"
    assert "s3cret-value" not in json.dumps(twin)
    errors = [record for record in wpt_records
              if record.name == "wpt.logs" and record.levelno == logging.ERROR]
    assert len(errors) == 1
    assert "s3cret-value" not in errors[0].getMessage()


# ------------------------------------------------------- round-1 regressions


def test_LOGS_1_many_archive_members_produce_one_aggregate_skip_row():
    """20k members under max_files=20 must not append 19,980 skipped rows
    (the JSON twin was 2.2 MB and the TarInfo list materialized every
    member before the cap)."""
    members = {f"logs/x{index}.log": b"clean\n" for index in range(5000)}
    account = FakeSource()
    account.files["logs/archive.tar.gz"] = _tar_gz(members)
    settings = load()
    settings.logs.max_files = 20
    scan = _collect(account, settings=settings)

    assert scan.skipped == [{
        "path": "logs/archive.tar.gz",
        "reason": ("4980 archive log member(s) exceed logs.max_files (20); "
                   "the newest 20 were considered"),
    }]
    assert len(scan.json_text()) < 5000


def test_DEADLINE_1_logs_run_honours_an_expired_budget(monkeypatch, tmp_path):
    from wpt.types import DeadlineExceeded

    class _Expired:
        def check(self, context):
            raise DeadlineExceeded("run deadline exceeded")

    monkeypatch.setattr(wpt.logs.Deadline, "from_ctx",
                        lambda ctx: _Expired())
    ctx = _ctx(report_path=tmp_path / "logs.md")

    assert wpt.logs.run(ctx) == 1
    assert "deadline exceeded" in (
        tmp_path / "logs.md").read_text(encoding="utf-8").lower()


def test_LOGS_3_www_is_stripped_for_host_log_derivation():
    domain = wpt.logs._domain_from_url("https://www.site.test/")
    directories = wpt.logs._candidate_dirs("public_html", domain)
    assert domain == "site.test"
    assert "domains/site.test/logs" in directories
    assert "domains/www.site.test/logs" not in directories
    assert "www.site.test/logs" not in directories


def test_SEC_1_scheme_less_source_password_never_reaches_the_report(
        tmp_path, wpt_records):
    ctx = _ctx(source="user:hunter2@host",
               report_path=tmp_path / "logs.md")

    assert wpt.logs.run(ctx) == 1

    markdown = (tmp_path / "logs.md").read_text(encoding="utf-8")
    twin = (tmp_path / "logs.md").with_suffix(".json").read_text(
        encoding="utf-8")
    assert "hunter2" not in markdown and "hunter2" not in twin
    assert all("hunter2" not in record.getMessage()
               for record in wpt_records)


def test_REDACT_1_host_log_prefixed_secret_is_redacted_in_the_report(
        tmp_path):
    account = FakeSource()
    account.files["logs/error.log"] = (
        b"PHP Fatal error: db_password=hunter2 api_key=abc123\n")
    ctx = _ctx(report_path=tmp_path / "logs.md")

    scan = wpt.logs.collect(
        ctx, webroot_source=FakeSource(), account_source=account)

    assert "hunter2" not in scan.markdown()
    assert "abc123" not in scan.markdown()
    assert "db_password=***" in scan.markdown()
    assert "api_key=***" in scan.markdown()


# ------------------------------------------------------- triple-check round 2


def test_LOGS2_surrogate_escaped_tar_member_name_cannot_break_the_report(
        tmp_path, monkeypatch):
    """LOGS2: tarfile decodes member names with surrogateescape; the lone
    surrogate reached json.dumps/markdown and raised UnicodeEncodeError while
    writing stdout/the report (after the scan had succeeded)."""
    bad_name = "logs/\udcff.log"
    account = FakeSource()
    account.files["logs/archive.tar.gz"] = _tar_gz(
        {bad_name: b"PHP Fatal error: surrogate\n"})

    scan = _collect(account)

    assert scan.total_matches == 1
    # Every rendered surface encodes as UTF-8 now.
    scan.json_text().encode("utf-8")
    scan.markdown().encode("utf-8")
    assert "\\udcff" in scan.matches[0]["file"]

    ctx = _ctx(report_path=tmp_path / "logs.md")
    monkeypatch.setattr(wpt.logs, "ftp_source_for",
                        lambda ctx, root=None: account)
    # The command must write BOTH stdout and the report without raising.
    assert wpt.logs.run(ctx) == 0
    (tmp_path / "logs.json").read_text(encoding="utf-8")


def test_R23_surrogate_site_label_stdout_is_backslashreplaced(
        tmp_path, monkeypatch):
    """R23-P2: same stdout contract for ``wpt logs`` — a raw ``--wp-url``
    surrogate must not raise out of the site header."""
    import io
    import sys

    account = FakeSource()
    account.files["domains/site/logs/error_log"] = b"clean\n"
    monkeypatch.setattr(wpt.logs, "ftp_source_for",
                        lambda ctx, root=None: account)
    ctx = _ctx(wp_url="http://\udcff.example")
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="utf-8", errors="strict")
    monkeypatch.setattr(sys, "stdout", stream)
    try:
        assert wpt.logs.run(ctx) == 0
        stream.flush()
    finally:
        stream.detach()
    assert "\\udcff.example" in raw.getvalue().decode("utf-8")


def test_LOGS3_candidate_overflow_is_one_aggregate_row_with_bounded_json():
    """LOGS3: 5,000 host logs under max_files=20 appended 4,980 skip rows
    (535 KB of JSON).  The bounded newest heap keeps the newest 20 and emits
    ONE aggregate row."""
    account = FakeSource()
    for index in range(5000):
        path = f"domains/site/logs/log{index:04d}.log"
        account.files[path] = b"clean\n"
    settings = load()
    settings.logs.max_files = 20

    scan = _collect(account, settings=settings)

    assert scan.scanned == 20
    assert len(scan.skipped) == 1
    row = scan.skipped[0]
    assert "4980 host log file(s)" in row["reason"]
    assert "logs.max_files (20)" in row["reason"]
    assert len(scan.json_text()) < 10_000
    # The kept files are the NEWEST by path when mtimes are unknown (the
    # same deterministic tie-break the report uses).
    assert [record["path"] for record in scan.files] == [
        f"domains/site/logs/log{index:04d}.log" for index in range(4980, 5000)
    ]


def test_LOGS5_gzip_member_inside_a_tar_is_decompressed_bounded():
    """LOGS5: ``_is_log_name`` selects a ``.gz`` member, but the raw bytes
    were decoded (zero matches, no skip).  A gzip member is decompressed
    under the per-file bound; a nested archive is an explicit skip."""
    import gzip as gzip_module

    inner = gzip_module.compress(b"PHP Fatal error: nested\n")
    account = FakeSource()
    account.files["logs/archive.tar.gz"] = _tar_gz(
        {"logs/old.log.gz": inner})
    scan = _collect(account)
    assert scan.total_matches == 1
    assert scan.matches[0]["pattern"] == "PHP fatal"
    assert scan.skipped == []

    account = FakeSource()
    account.files["logs/archive.tar.gz"] = _tar_gz(
        {"logs/nested.tgz": _tar_gz({"x.log": b"clean\n"})})
    scan = _collect(account)
    assert scan.skipped == [{
        "path": "logs/archive.tar.gz:logs/nested.tgz",
        "reason": "nested archive member is not scanned",
    }]


# ---------------------------------------------------- round-3 regressions


def _tar_bytes(members, mode="w"):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as archive:
        for name, data, mtime in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = mtime
            archive.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class _ArchiveSource:
    def __init__(self, data: bytes) -> None:
        self.data = data

    def read_bytes_bounded(self, path, limit):
        return self.data[:limit]


def _empty_scan():
    return wpt.logs.LogScan(
        site="s", source_summary="s", files=[], matches=[], skipped=[],
        total_matches=0, scanned=0)


def test_LOG_TAR_HEAP_keeps_the_true_newest_members():
    """LOG-TAR-HEAP: the heap key was newest-first, so the min-heap root was
    the newest and each newer arrival EVICTED it; max_files=3 over day1..day6
    kept day6 + day2 + day1 instead of day6/day5/day4."""
    data = _tar_bytes([
        (f"day{i}.log", f"PHP Fatal error: day{i}\n".encode(), 100 * i)
        for i in range(1, 7)
    ])
    scan = _empty_scan()
    wpt.logs._scan_tar(
        _ArchiveSource(data), Entry("logs.tar", False, size=len(data)),
        _settings(max_files=3).logs, scan)
    assert [row["file"] for row in scan.matches] == [
        "logs.tar:day6.log", "logs.tar:day5.log", "logs.tar:day4.log"]
    assert scan.skipped[0]["reason"] == (
        "3 archive log member(s) exceed logs.max_files (3); the newest 3 "
        "were considered")


def test_LOG_TAR_DECOMP_512MiB_member_is_bounded_before_the_seek():
    """LOG-TAR-DECOMP + R16 pre-charge: tar iteration decompresses every
    member, including a non-log one it never reads.  The 512 MiB member is
    charged to the aggregate ceiling BEFORE the raw (decompressing) seek, so
    the archive is skipped in microseconds instead of spending the work."""
    from wpt.deadline import Deadline

    class _Zeros(io.RawIOBase):
        def readinto(self, buffer):
            buffer[:] = b"\0" * len(buffer)
            return len(buffer)

    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w") as archive:
            info = tarfile.TarInfo("big.bin")
            info.size = 512 * 1024 * 1024
            archive.addfile(info, _Zeros())
    data = buf.getvalue()
    started = time.monotonic()
    scan = _empty_scan()
    wpt.logs._scan_tar(
        _ArchiveSource(data), Entry("logs.tar.gz", False, size=len(data)),
        _settings().logs, scan, Deadline(0.05))
    assert time.monotonic() - started < 2.0
    assert scan.skipped == [{
        "path": "logs.tar.gz",
        "reason": (
            "archive decompression exceeds logs.max_decompressed_bytes "
            f"({_settings().logs.max_decompressed_bytes})"),
    }]


def test_LOG_TAR_DECOMP_tiny_ceiling_while_opening_is_an_archive_skip():
    """LOG-TAR-DECOMP open escape: ``tarfile.open`` reads the first header
    (or a pax header) through the limiter; ``_ArchiveWorkExceeded`` from
    that read escaped the open ``except`` and tracebacked.  It is the same
    archive-size skip as an oversized member walk."""
    from dataclasses import replace

    data = _tar_gz({"logs/error.log": b"PHP Fatal error: boom\n"})
    scan = _empty_scan()
    bounds = replace(_settings().logs, max_decompressed_bytes=1)
    wpt.logs._scan_tar(
        _ArchiveSource(data), Entry("logs/archive.tar.gz", False,
                                    size=len(data)),
        bounds, scan)
    assert scan.skipped == [{
        "path": "logs/archive.tar.gz",
        "reason": (
            "archive decompression exceeds logs.max_decompressed_bytes (1)"),
    }]

    # A large FIRST pax header is read during the same open phase; the
    # ceiling can trip there before any member iteration.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w",
                      format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo("logs/" + "x" * 300 + ".log")
        info.size = 5
        archive.addfile(info, io.BytesIO(b"clean"))
    pax = _gzip(buf.getvalue())
    scan = _empty_scan()
    bounds = replace(_settings().logs, max_decompressed_bytes=700)
    wpt.logs._scan_tar(
        _ArchiveSource(pax), Entry("logs/pax.tar.gz", False, size=len(pax)),
        bounds, scan)
    assert scan.skipped == [{
        "path": "logs/pax.tar.gz",
        "reason": (
            "archive decompression exceeds logs.max_decompressed_bytes (700)"),
    }]


def test_LOG_NESTED_derives_domain_logs_below_a_nested_webroot():
    """LOG-NESTED: both candidate derivation and the domain fallback required
    the webroot's LAST segment to be a docroot, so
    domains/site.test/public_html/blog never scanned domains/site.test/logs."""
    account = RecordingSource()
    account.files["domains/site.test/logs/error.log"] = (
        b"PHP Fatal error: host-level\n")
    scan = wpt.logs.collect(
        _ctx(webroot="domains/site.test/public_html/blog", wp_url=None),
        webroot_source=FakeSource(), account_source=account)
    assert "domains/site.test/logs" in account.listed
    assert scan.scanned == 1
    assert scan.total_matches == 1
    assert wpt.logs._webroot_domain(
        "domains/site.test/public_html/blog") == "site.test"


def test_LOG_LOOKUP_CLEAN_an_unprovable_exists_fails_the_run():
    """LOG-LOOKUP-CLEAN: SourceLookupError subclasses SourceError, and the
    direct-webroot catch continued, so an unanswerable lookup produced
    scanned=0/skipped=[] and "No error/fatal patterns found"."""
    from wpt.types import SourceLookupError

    class LookupFails(FakeSource):
        def exists(self, path):
            raise SourceLookupError(f"cannot determine whether {path} exists")

    with pytest.raises(SourceLookupError):
        _collect(FakeSource(), webroot=LookupFails())


def test_CLOSE_STOP_logs_returns_1_and_still_writes_the_failure_report(
        tmp_path, monkeypatch):
    """CLOSE-STOP: logs swallowed StopRequested raised by source.close(); the
    run answered rc 0 with a report."""
    from wpt.types import StopRequested

    class StopOnClose(FakeSource):
        def close(self):
            raise StopRequested("SIGTERM during close")

    source = StopOnClose()
    monkeypatch.setattr(wpt.logs, "ftp_source_for",
                        lambda ctx, root="": source)
    ctx = _ctx(report_path=tmp_path / "logs.md")
    assert wpt.logs.run(ctx) == 1
    assert "did not complete" in (tmp_path / "logs.md").read_text("utf-8")


def test_LOG_LOOKUP_CLEAN_run_reports_failure_not_clean(tmp_path, monkeypatch):
    """LOG-LOOKUP-CLEAN (command path): the unprovable lookup must reach the
    failure report and rc 1, not "No error/fatal patterns found"."""
    from wpt.types import SourceLookupError

    class LookupFails(FakeSource):
        def exists(self, path):
            raise SourceLookupError(f"cannot determine whether {path} exists")

    source = LookupFails()
    monkeypatch.setattr(wpt.logs, "ftp_source_for",
                        lambda ctx, root="": source)
    ctx = _ctx(report_path=tmp_path / "logs.md")
    assert wpt.logs.run(ctx) == 1
    report = (tmp_path / "logs.md").read_text("utf-8")
    assert "did not complete" in report
    assert "No error/fatal patterns found" not in report


# ------------------------------------------------------- round-4 regressions


def test_LOG_ARCHIVE_EXC_corrupt_xz_and_extraction_ceiling_are_skips(
        monkeypatch):
    """P2-LOG-ARCHIVE-EXC: lzma.LZMAError and _ArchiveWorkExceeded from a
    selected-member read escaped wpt logs as raw tracebacks."""
    account = FakeSource()
    account.files["domains/site/logs/corrupt.tar.gz"] = (
        b"\xfd7zXZ\x00" + b"garbage" * 20)
    scan = _collect(account)
    assert scan.scanned == 0
    assert any("unreadable archive" in row["reason"]
               for row in scan.skipped)

    # The extraction phase re-reads selected members; one byte past the
    # ceiling there must be the SAME archive skip (task H).
    from wpt.logs import _ArchiveWorkExceeded, _ArchiveWorkLimiter

    class Huge:
        def read(self, size=-1):
            raise _ArchiveWorkExceeded

        def tell(self):
            return 0

        def seek(self, *args):
            return 0

        def close(self):
            pass

    limiter = _ArchiveWorkLimiter(Huge(), 1_000)
    with pytest.raises(_ArchiveWorkExceeded):
        limiter.read(10)


def test_LOGS_ARCHIVE_GZIP_corrupt_stream_is_the_shared_skip():
    """Residual: _scan_gzip kept its own exception tuple; a corrupt gzip
    must be the SAME unreadable-archive skip as every other archive."""
    import wpt.logs as logs_mod

    assert issubclass(gzip.BadGzipFile, logs_mod._ARCHIVE_READ_ERRORS)
    account = FakeSource()
    account.files["domains/site/logs/error.log.gz"] = (
        b"\x1f\x8b" + b"garbage" * 20)
    scan = _collect(account)
    assert scan.scanned == 0
    assert any("unreadable gzip" in row["reason"]
               for row in scan.skipped), scan.skipped


def test_LOG_PAX_ALLOC_declared_header_size_is_clamped_before_allocation():
    """P2-LOG-PAX-ALLOC: read(size) allocated BEFORE _charge(size), so a
    pax header could allocate far past logs.max_decompressed_bytes."""
    import tracemalloc

    from wpt.logs import _ArchiveWorkExceeded, _ArchiveWorkLimiter

    ceiling = 1024 * 1024
    requested: list[int] = []

    class DeclaredHuge:
        def read(self, size=-1):
            requested.append(size)
            return b"\0" * size

        def tell(self):
            return 0

        def seek(self, *args):
            return 0

        def close(self):
            pass

    limiter = _ArchiveWorkLimiter(DeclaredHuge(), ceiling)
    tracemalloc.start()
    try:
        with pytest.raises(_ArchiveWorkExceeded):
            limiter.read(64 * 1024 * 1024)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert requested and requested[0] <= ceiling + 1
    assert peak < 8 * 1024 * 1024, peak


def test_LOGS_DEADLINE_a_clean_read_cannot_return_success_after_budget(
        monkeypatch, tmp_path):
    """P2-LOGS-DEADLINE: no check after _scan_entry/_collect_matches, so a
    4 MiB clean log returned normally after the deadline and rc 0."""
    import time

    from wpt.types import DeadlineExceeded

    class SlowRead(FakeSource):
        def read_bytes_bounded(self, path, max_bytes):
            time.sleep(0.05)
            return b"clean line\n" * 8

    webroot = SlowRead()
    webroot.files["error_log"] = b"clean line\n"
    with pytest.raises(DeadlineExceeded):
        wpt.logs.collect(_ctx(deadline_s=0.02),
                         webroot_source=webroot, account_source=FakeSource())

    # Real command body: rc 1 and the shared failure report.
    webroot2 = SlowRead()
    webroot2.files["error_log"] = b"clean line\n"
    monkeypatch.setattr(wpt.logs, "ftp_source_for",
                        _factory(webroot2, FakeSource()))
    ctx = _ctx(deadline_s=0.02, report_path=tmp_path / "logs.md")
    assert wpt.logs.run(ctx) == 1
    assert "## This run did not complete" in (tmp_path / "logs.md").read_text(
        encoding="utf-8")


def _logs_settings(**overrides):
    return replace(load(), logs=replace(load().logs, **overrides))


def test_LOGS_CAP_LABEL_counts_webroot_and_host_drops_separately():
    """P2-LOGS-CAP-LABEL: dropped WEBROOT candidates were reported as host
    logs and even the single-file case mislabelled them."""
    webroot = FakeSource()
    webroot.files.update({
        "error_log": b"x", "php_errorlog": b"x",
        "wp-content/debug.log": b"x",
    })
    scan = wpt.logs.collect(
        _ctx(settings=_logs_settings(max_files=1)),
        webroot_source=webroot, account_source=FakeSource())
    assert len(scan.files) == 1
    reasons = " ".join(row["reason"] for row in scan.skipped)
    assert "2 webroot log file(s)" in reasons
    assert "host log" not in reasons
    assert "the first 1 were considered" in reasons

    account = FakeSource()
    for index in range(5):
        account.files[f"domains/site/logs/error{index}.log"] = b"x"
    scan2 = wpt.logs.collect(
        _ctx(settings=_logs_settings(max_files=2)),
        webroot_source=webroot, account_source=account)
    reasons2 = " ".join(row["reason"] for row in scan2.skipped)
    assert "1 webroot log file(s)" in reasons2
    assert "5 host log file(s)" in reasons2


def test_LOGS_SYMLINK_SILENT_a_log_shaped_link_is_a_skip_row():
    """P2-LOGS-SYMLINK-SILENT: SYMTYPE/LNKTYPE members were dropped before
    the file filter with no row, reading as a clean scan."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        for kind, name in ((tarfile.SYMTYPE, "logs/error.log"),
                           (tarfile.LNKTYPE, "logs/php_errorlog")):
            info = tarfile.TarInfo(name)
            info.type = kind
            info.linkname = "target"
            archive.addfile(info)
    account = FakeSource()
    account.files["domains/site/logs/link.tar.gz"] = buf.getvalue()
    scan = _collect(account)
    assert scan.total_matches == 0
    assert any("member is not a regular file" in row["reason"]
               for row in scan.skipped)


class _DatedSource(FakeSource):
    def __init__(self, mtimes):
        super().__init__()
        self.mtimes = mtimes

    def list_dir(self, path):
        entries = super().list_dir(path)
        for entry in entries:
            if entry.path in self.mtimes:
                entry.mtime = self.mtimes[entry.path]
        return entries


def test_LOGS_LATEST_FILE_records_the_winning_candidate_rank():
    """P2-LOGS-LATEST-FILE: webroot logs are scanned first but have no
    mtime; the "latest" row assumed matches[0] was the newest file."""
    webroot = FakeSource()
    webroot.files["error_log"] = b"PHP Fatal error: OLD webroot line\n"
    account = _DatedSource({"domains/site/logs/error.log": 9_999_999_999})
    account.files["domains/site/logs/error.log"] = (
        b"PHP Fatal error: NEW host line\n")
    scan = wpt.logs.collect(_ctx(), webroot_source=webroot,
                            account_source=account)
    assert scan.latest_file == "domains/site/logs/error.log"
    assert scan.latest_matches[scan.latest_file]["match"].endswith(
        "NEW host line")


def test_LOG_ARCHIVE_EXC_selected_member_reread_over_ceiling_is_a_skip():
    """The iteration stays under the ceiling but the extraction phase's
    backward seeks/re-reads exceed it; that trip must be the archive skip,
    not an escaped _ArchiveWorkExceeded."""
    buf = io.BytesIO()
    payload = b"PHP Fatal error: boom\n" * 1000  # ~24 KB
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        for index in range(4):
            info = tarfile.TarInfo(f"logs/error{index}.log")
            info.size = len(payload)
            info.mtime = 100 + index
            archive.addfile(info, io.BytesIO(payload))
    account = FakeSource()
    account.files["domains/site/logs/a.tar.gz"] = buf.getvalue()
    settings = _logs_settings(max_decompressed_bytes=len(payload) * 5,
                              max_files=4, max_file_bytes=len(payload))
    scan = wpt.logs.collect(_ctx(settings=settings),
                            webroot_source=FakeSource(),
                            account_source=account)
    assert scan.total_matches == 0
    assert any("archive decompression exceeds" in row["reason"]
               for row in scan.skipped)


# ------------------------------------------------------- round-5 regressions


def test_CLOSE_STOP_every_owned_source_is_closed_before_the_stop_raises(
        monkeypatch):
    """P2-LOGS-CLOSE-STOP: a stop while closing the first built source
    skipped the second; teardown must close ALL, then re-raise the first."""
    from wpt.types import StopRequested

    class StopOnClose(CloseCountingSource):
        def close(self):
            super().close()
            raise StopRequested("SIGTERM during close")

    first = StopOnClose()
    second = CloseCountingSource()
    monkeypatch.setattr(wpt.logs, "ftp_source_for", _factory(first, second))

    with pytest.raises(StopRequested):
        wpt.logs.collect(_ctx())

    assert first.closed == 1
    assert second.closed == 1


def test_ARCHIVE_CLOSE_STOP_re_raises_and_logs_run_is_rc_1(
        monkeypatch, tmp_path):
    """P2-LOGS-ARCHIVE-CLOSE: the archive finally swallowed StopRequested,
    appended its record and wpt logs returned 0 after SIGTERM."""
    from wpt.types import StopRequested

    archive = _tar_gz({"logs/site.error.log": b"clean\n"})
    account = FakeSource()
    account.files["domains/site/logs/archive.tar.gz"] = archive
    webroot = FakeSource()
    monkeypatch.setattr(wpt.logs, "ftp_source_for", _factory(webroot, account))
    real_close = tarfile.TarFile.close

    def stopping_close(self):
        real_close(self)
        raise StopRequested("SIGTERM during archive close")

    monkeypatch.setattr(tarfile.TarFile, "close", stopping_close)
    ctx = _ctx(report_path=tmp_path / "logs.md")

    assert wpt.logs.run(ctx) == 1
    assert "did not complete" in (tmp_path / "logs.md").read_text("utf-8")


def test_LOGS_LATEST_FILE_includes_newest_tar_member():
    """P2-LOGS-TAR-LATEST: ranks were keyed by the archive path while its
    matches were keyed ``archive:member``, so the archive never won and
    doctor named an older plain log."""
    account = _DatedSource({
        "domains/site/logs/old.log": 1_000,
        "domains/site/logs/archive.tar.gz": 2_000,
    })
    account.files["domains/site/logs/old.log"] = (
        b"PHP Fatal error: OLD line\n")
    account.files["domains/site/logs/archive.tar.gz"] = _tar_gz(
        {"logs/new.log": b"PHP Fatal error: NEW line\n"})

    scan = wpt.logs.collect(_ctx(), webroot_source=FakeSource(),
                            account_source=account)

    assert scan.latest_file == (
        "domains/site/logs/archive.tar.gz:logs/new.log")
    assert scan.latest_matches[scan.latest_file]["match"].endswith("NEW line")


def test_LOG_ARCHIVE_EXTRACTION_CEILING_keeps_partial_match_and_file_record():
    """P2-LOGS-PARTIAL-TAR: a ceiling trip during selected-member extraction
    returned before ``scan.files.append``; doctor then said "no log files"
    although a real match had already been collected."""
    fatal = b"PHP Fatal error: boom\n"
    filler = b"x" * 3_000
    account = FakeSource()
    account.files["domains/site/logs/archive.tar.gz"] = _tar_gz(
        {"logs/z-error.log": fatal, "logs/a-filler.log": filler})
    # 7,000 is between the sequential member walk (5,120) and the
    # extraction re-reads (9,656): the ceiling must trip in the extraction
    # phase, after z-error's real match was collected (R6-11 accounting).
    settings = _logs_settings(max_decompressed_bytes=7_000,
                              max_file_bytes=10_000, max_files=2)

    scan = wpt.logs.collect(_ctx(settings=settings),
                            webroot_source=FakeSource(),
                            account_source=account)

    assert scan.scanned == 1
    assert scan.files and scan.files[0]["matches"] == 1
    assert scan.total_matches == 1
    assert scan.matches[0]["file"].endswith(":logs/z-error.log")
    assert any("archive decompression exceeds" in row["reason"]
               for row in scan.skipped)


# ------------------------------------------------------- triple-check round 6


def test_R6_06_latest_ranks_tar_members_by_their_own_mtime(tmp_path):
    """R6-06: every tar member inherited the ARCHIVE's rank, so an older
    member in a newer archive beat a newer plain log.  The member mtime is
    retained and ranked; the archive rank is only the unknown-mtime
    fallback."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        for name, mtime, body in (
                ("logs/a-old.log", 100, b"PHP Fatal error: OLD member\n"),
                ("logs/z-new.log", 500, b"PHP Fatal error: NEW member\n")):
            info = tarfile.TarInfo(name)
            info.size = len(body)
            info.mtime = mtime
            archive.addfile(info, io.BytesIO(body))
    account = _DatedSource({
        "domains/site/logs/archive.tar.gz": 9_000_000_000,
        "domains/site/logs/old.log": 1_000,
    })
    account.files["domains/site/logs/archive.tar.gz"] = buf.getvalue()
    account.files["domains/site/logs/old.log"] = (
        b"PHP Fatal error: PLAIN newer than a-old\n")

    scan = wpt.logs.collect(_ctx(), webroot_source=FakeSource(),
                            account_source=account)

    assert scan.latest_file == "domains/site/logs/old.log"
    assert not scan.latest_file.endswith("a-old.log")
    assert scan.latest_matches[scan.latest_file]["match"].endswith("a-old")


def test_R6_43_a_zero_mtime_member_takes_the_archive_rank():
    """R6-43: TarInfo.mtime is 0 (never None) for an unset header, so the
    "unknown mtime -> archive rank" branch was dead and the member ranked
    as epoch, losing to an older plain log."""
    member = tarfile.TarInfo("logs/zero.log")
    member.mtime = 0
    assert wpt.logs._member_mtime(member) is None
    assert wpt.logs._member_age_key(member)[0] is False
    # a PAX mtime can be a finite float and stays a REAL timestamp
    member.mtime = 1234.5
    assert wpt.logs._member_mtime(member) == 1234.5
    assert wpt.logs._member_age_key(member)[0] is True
    member.mtime = float("inf")
    assert wpt.logs._member_mtime(member) is None

    account = _DatedSource({
        "domains/site/logs/archive.tar.gz": 9_000_000_000,
        "domains/site/logs/plain.log": 1_000,
    })
    account.files["domains/site/logs/archive.tar.gz"] = _tar_gz(
        {"logs/zero.log": b"PHP Fatal error: ZERO member\n"}, mtime=0)
    account.files["domains/site/logs/plain.log"] = (
        b"PHP Fatal error: OLD plain\n")

    scan = wpt.logs.collect(_ctx(), webroot_source=FakeSource(),
                            account_source=account)

    assert scan.latest_file == \
        "domains/site/logs/archive.tar.gz:logs/zero.log"
    assert scan.latest_matches[scan.latest_file]["match"].endswith(
        "ZERO member")


def test_R6_11_backward_seek_charges_the_real_decompression_distance():
    """R6-11: charging abs(position-before) undercounted a gzip backward seek
    (it re-decompresses from the START to position).  Ten 1 MiB members with
    a 40 MiB ceiling must trip; the old accounting spent only 39 MiB."""
    members = {}
    for index in range(10):
        members[f"logs/e{index}.log"] = bytes(range(256)) * 4096  # 1 MiB
    settings = _logs_settings(
        max_decompressed_bytes=40 * 1024 * 1024,
        max_archive_bytes=32 * 1024 * 1024,
        max_file_bytes=2 * 1024 * 1024,
        max_files=10,
    )
    account = FakeSource()
    account.files["domains/site/logs/archive.tar.gz"] = _tar_gz(members)

    scan = wpt.logs.collect(_ctx(settings=settings),
                            webroot_source=FakeSource(),
                            account_source=account)

    assert scan.files and scan.files[0]["kind"] == "tar.gz"
    assert any("archive decompression exceeds" in row["reason"]
               for row in scan.skipped)


def test_R6_13_log_shaped_symlink_is_a_skip_row_not_a_false_clean():
    """R6-13: a symlinked host log was dropped silently, so the report said
    "No error/fatal patterns" over a file it never read."""
    class _Linked(FakeSource):
        def list_dir(self, path):
            entries = super().list_dir(path)
            for entry in entries:
                if entry.path.endswith("error.log"):
                    entry.is_link = True
            return entries

    account = _Linked()
    account.files["domains/site/logs/error.log"] = (
        b"PHP Fatal error: SECRET-LINKED\n")

    scan = wpt.logs.collect(_ctx(), webroot_source=FakeSource(),
                            account_source=account)

    assert scan.scanned == 0 and scan.total_matches == 0
    assert any(row["path"].endswith("error.log")
               and "symbolic link" in row["reason"]
               for row in scan.skipped)


# ------------------------------------------------- triple-check round 7


@pytest.mark.parametrize("count", [5000, 50000])
def test_R7_P2_19_archive_nonregular_members_are_one_aggregate_row(count):
    """R7-P2-19: one skip row per log-shaped SYMTYPE/LNKTYPE member bypassed
    logs.max_files (50 000 rows / 5.24 MB JSON)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        for index in range(count):
            info = tarfile.TarInfo(f"logs/x{index}.log")
            info.type = tarfile.SYMTYPE
            info.linkname = "target"
            archive.addfile(info)
    account = FakeSource()
    account.files["domains/site/logs/link.tar.gz"] = buf.getvalue()
    scan = _collect(account)
    assert scan.total_matches == 0
    assert len(scan.skipped) == 1
    row = scan.skipped[0]
    assert row["path"] == "domains/site/logs/link.tar.gz"
    assert f"{count} archive log member(s)" in row["reason"]
    assert "member is not a regular file" in row["reason"]
    assert len(scan.json_text()) < 5000


@pytest.mark.parametrize("count", [5000, 50000])
def test_R7_P2_19_host_symlinks_are_one_aggregate_row_per_directory(count):
    """R7-P2-19: every log-shaped host symlink appended a row regardless of
    logs.max_files.  One row per directory now carries the count and first."""
    from wpt.types import Entry

    class _Linked(FakeSource):
        def list_dir(self, path):
            if path == "domains/site/logs":
                return [
                    Entry(path=f"domains/site/logs/x{index}.log",
                          is_dir=False, size=0, is_link=True)
                    for index in range(count)
                ]
            return super().list_dir(path)

    scan = _collect(_Linked())
    assert len(scan.skipped) == 1
    row = scan.skipped[0]
    assert row["path"] == "domains/site/logs"
    assert f"{count} log-shaped symbolic link(s)" in row["reason"]
    assert "first:" in row["reason"]
    assert len(scan.json_text()) < 5000


def test_R7_P2_09_a_close_time_stop_never_replaces_the_primary_failure(
        monkeypatch):
    """R7-P2-09: ``logs.collect`` let ``_close_sources`` raise a stop out of
    its ``finally``, replacing the scan failure that was already in flight."""
    from wpt.types import SourceLookupError, StopRequested

    class _PrimaryThenStop(FakeSource):
        def exists(self, path):
            raise SourceLookupError(f"cannot determine whether {path} exists")

        def close(self):
            raise StopRequested("SIGTERM during close")

    source = _PrimaryThenStop()
    monkeypatch.setattr(wpt.logs, "ftp_source_for",
                        lambda ctx, root="": source)
    with pytest.raises(SourceLookupError, match="cannot determine"):
        wpt.logs.collect(_ctx())


# ------------------------------------------------ triple-check round 8 (P2)


def test_P2_05_oversized_non_log_members_are_one_aggregate_skip():
    """P2-05: one skip row per oversized non-log tar member let 3000 opaque
    members bypass logs.max_files."""
    members = {f"opaque-{index:04d}.bin": b"x" * 20
               for index in range(3000)}
    account = FakeSource()
    account.files["domains/site/logs/huge.tar.gz"] = _tar_gz(members)
    settings = _settings(max_files=20, max_file_bytes=10)

    scan = _collect(account, settings=settings)

    assert len(scan.skipped) == 1
    assert "3000 non-log archive member(s)" in scan.skipped[0]["reason"]
    assert "opaque-0000.bin" in scan.skipped[0]["reason"]


def test_P2_06_nested_gzip_member_is_charged_to_the_archive_ceiling():
    """P2-06: a 48 KB nested gzip member scanned invisibly under a 20 KB
    logs.max_decompressed_bytes ceiling."""
    members = {
        "inner.log.gz": _gzip(b"A" * 48_000),
    }
    account = FakeSource()
    account.files["domains/site/logs/huge.tar.gz"] = _tar_gz(members)
    settings = _settings(max_file_bytes=1024 * 1024,
                         max_decompressed_bytes=20_000)

    scan = _collect(account, settings=settings)

    assert scan.matches == []
    assert len(scan.skipped) == 1
    assert "max_decompressed_bytes" in scan.skipped[0]["reason"]


def test_R13_a_second_stop_in_the_logs_failure_writer_is_contained(
        tmp_path, monkeypatch, wpt_records):
    """R13-P2-18: logs' failure writer had no try at all, so a SIGTERM
    during the report escaped and replaced the primary reason."""
    import wpt.actions.registry as registry_mod
    from wpt.types import StopRequested

    def _stop(*args, **kwargs):
        raise StopRequested("SIGTERM during failure report")

    monkeypatch.setattr(registry_mod, "write_report", _stop)
    ctx = _ctx(tmp_path, report_path=tmp_path / "logs.md")
    wpt.logs._write_failure(ctx, "PRIMARY-FAIL")
    joined = "\n".join(r.getMessage() for r in wpt_records)
    assert "SIGTERM during failure report" in joined


def test_R21_logs_and_discover_share_one_docroot_vocabulary():
    """R21-P2: two hand-maintained docroot tuples had drifted (logs missed
    ``wwwroot``).  Both diagnostics import the ONE remote owner."""
    import wpt.discover
    from wpt.remote import DOCROOT_NAMES

    assert wpt.logs.DOCROOT_NAMES is DOCROOT_NAMES
    assert wpt.discover.DOCROOT_NAMES is DOCROOT_NAMES
    assert "wwwroot" in DOCROOT_NAMES
    assert wpt.logs._webroot_domain("site.test/wwwroot") == "site.test"
