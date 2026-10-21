"""Tests for run_action's post-apply cache purge (wpt.actions.registry).

The registry end-to-end tests of the per-action files (tests/actions/
test_clean_files.py + friends) pin each action's plan/apply; this file
pins the ONE registry-owned step they share: after a SUCCESSFUL ftp-mode
apply, run_action asks the bridge to ``purge_cache`` exactly once —
LiteSpeed/W3TC/WP Super Cache otherwise keep serving stale pages and the
operator sees "no change" after a cleanup.  Purge is HYGIENE: a purge
failure logs one warning and changes nothing about the command's
success.

FakeSource-backed trees + a bridge double recording every call, both
appending to ONE shared event list so tests pin call ORDER (the
tests/actions/test_clean_files.py conventions for the stack seam and
the tree; the shared tests/fakes.py double does not record into a
shared timeline, so the recording fake is specialized here).  Log
capture uses the suite's own ``wpt_records`` handler (as
tests/test_verify.py): pytest's caplog cannot see ``wpt.*`` records
because the ``wpt`` parent logger does not propagate.

Test -> behavior map:
  test_ftp_apply_purges_once_after_apply ..... apply --yes over the fake
        stack: rc 0, purge_cache called EXACTLY once with no params,
        AFTER every file delete and BEFORE bridge destroy; one debug
        record carrying the purge payload; the success report intact
  test_dry_run_never_purges ................. apply=False: rc 0, plan
        printed, files untouched, zero purge calls (the bridge is still
        destroyed — the stack teardown is unconditional)
  test_apply_failure_never_purges ........... apply raising SourceError:
        rc 1 with the "apply failed after backup" error, zero purge
        calls, files untouched, bridge still destroyed
  test_purge_failure_is_warning_not_error ... purge_cache raising
        BridgeError: rc 0 PRESERVED, the applied report and summary
        still printed, ONE warning ("cache purge failed", "changes ARE
        applied", the exception text), zero errors, files really gone,
        bridge still destroyed

``--report`` is the tool's universal contract and the registry is where
an ACTION honours it (the audit/verify/doctor/walk/backup/restore paths
have their own emitters, deploy shares this writer):

  test_report_is_written_on_a_dry_action .... a dry clean-files run writes
        the SAME markdown it printed, plus the JSON twin
  test_report_is_written_on_a_local_....... a local rehearsal (a REAL zip
        rehearsal_apply ...................... over --zip) writes the
        applied plan; the original archive is still untouched
  test_report_is_written_for_an_empty_plan .. a plan with no items still
        creates the file — a caller can trust its presence
  test_report_is_written_by_deploy_........ the deploy DRY run (the other
        dry_run ............................. --report caller) writes its
        plan too
  test_unwritable_report_fails_the_run ..... a report path that cannot be
        written is rc 1, never a silent success
  test_a_successful_run_report_is_byte_identical . the failure report did
        not move the success report: markdown and twin pinned
        byte-for-byte, and the twin carries no ``run`` key

...and the report of a run that produced NOTHING (L44 one level up: every
dry run got a report, a failed run wrote none, so a caller could not tell
"planned nothing" from "never got far enough"):

  test_a_refused_run_writes_its_refusal ... a plan-phase failure writes
        the audit report's own shape with zero findings, zero planned
        items and one line naming the refusal
  test_a_failed_run_writes_its_refusal_not_a_plan . a failure AFTER a real
        plan exists still reports the failure, and never claims an item it
        did not apply
  test_the_failure_report_is_never_printed . a failed run has no report to
        SHOW: stdout stays the surface of a report that exists

Local mode needs no purge test here: local stacks carry bridge=None by
construction and the write refusal fires before apply — both pinned by
tests/actions/test_clean_files.py::test_registry_local_apply_refused.
"""

import json
import logging
import zipfile

import pytest

from tests.fakes import FakeSource
from wpt.actions import registry as registry_mod
from wpt.actions.registry import get_action, run_action
from wpt.cli import Ctx
from wpt.settings import load
from wpt.types import BridgeError, SourceError

#: The shipped profile — every pattern exactly as users get it.
DEFAULTS = load()

#: The purge_cache answer in the wire shape bridge.php's
#: wpt_action_purge_cache returns (array('purged' => true) merged over
#: the ok:true envelope the dispatcher adds).
PURGE_OK = {"ok": True, "purged": True}


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


# ------------------------------------------------------------------ doubles


class EventSource(FakeSource):
    """FakeSource whose every recorded op also lands in a shared event
    list — the order pin needs ONE timeline across the source and the
    bridge double (the shared tests/fakes.py double does not record
    into a shared timeline and is not owned by this task, so the
    recording fake is specialized here, as tests/actions/
    test_clean_files.py specializes its own)."""

    def __init__(self, events: list[str]) -> None:
        super().__init__()
        self.events = events

    def _rec(self, op, path):
        super()._rec(op, path)
        self.events.append(f"source:{op}:{path}")


class FakeBridge:
    """Bridge double recording every call and destroy() into the shared
    event list, scripting ONE purge_cache answer.

    ``purge_error`` (raised) takes precedence over ``purge_result``
    (returned); with neither scripted, any call raises AssertionError —
    a purge the test did not plan must fail loudly, not silently.
    clean-files is file-only, so purge_cache is the bridge's first and
    only call in these flows.
    """

    def __init__(self, events: list[str], *, purge_result=None,
                 purge_error: Exception | None = None) -> None:
        self.events = events
        self.calls: list[tuple[str, dict]] = []
        self.destroyed = 0
        self._result = purge_result
        self._error = purge_error

    def call(self, action, **params):
        self.calls.append((action, params))
        self.events.append(f"bridge:{action}")
        if self._error is not None:
            raise self._error
        if self._result is None:
            raise AssertionError(f"unexpected bridge action: {action}")
        return self._result

    def destroy(self):
        self.destroyed += 1
        self.events.append("bridge:destroy")


# ------------------------------------------------------------------ fixtures


def _ctx(tmp_path, **overrides):
    """A clean-files Ctx; ftp-mode defaults, overridable per test."""
    fields = dict(
        source="ftp://example.com",
        settings=DEFAULTS,
        command="clean-files",
        apply=False,
        yes=False,
        backup_dir=tmp_path / "backup",
        wp_url="https://example.com",
    )
    fields.update(overrides)
    return Ctx(**fields)


def _junk_tree(src):
    """Two planned junk files plus one leaf that must survive."""
    src.files = {
        "readme.html": b"x" * 100,
        "dump.sql": b"x" * 500,
        "wp-config.php": b"cfg",  # never planned
    }


def _stack(monkeypatch, *, purge_result=None, purge_error=None):
    """A fake ftp-mode stack (src, None, bridge) patched into the
    registry's pinned seam; returns (events, src, bridge)."""
    events: list[str] = []
    src = EventSource(events)
    _junk_tree(src)
    bridge = FakeBridge(events, purge_result=purge_result,
                        purge_error=purge_error)
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    return events, src, bridge


def _registry_records(wpt_records, level):
    return [
        r for r in wpt_records
        if r.name == "wpt.actions" and r.levelno == level
    ]


# --------------------------------------------------------------------- tests


def test_ftp_apply_purges_once_after_apply(tmp_path, capsys, monkeypatch,
                                           wpt_records):
    events, src, bridge = _stack(monkeypatch, purge_result=PURGE_OK)
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "clean-files")
    assert rc == 0
    assert set(src.files) == {"wp-config.php"}  # the apply really landed
    # purge_cache called EXACTLY once, with no params
    assert bridge.calls == [("purge_cache", {})]
    # ORDER: after every file delete, before the bridge teardown
    deletes = [e for e in events if e.startswith("source:delete:")]
    assert sorted(deletes) == [
        "source:delete:dump.sql", "source:delete:readme.html",
    ]
    purge_at = events.index("bridge:purge_cache")
    assert purge_at > max(events.index(e) for e in deletes)
    assert events.index("bridge:destroy") > purge_at
    # the returned payload is logged — one debug record from the registry
    purges = [
        r for r in _registry_records(wpt_records, logging.DEBUG)
        if "cache purge" in r.getMessage()
    ]
    assert len(purges) == 1
    assert "'purged': True" in purges[0].getMessage()
    # the success report path is intact
    out = capsys.readouterr().out
    assert out.count("| yes |") == 2


def test_dry_run_never_purges(tmp_path, capsys, monkeypatch, wpt_records):
    events, src, bridge = _stack(monkeypatch)
    rc = run_action(_ctx(tmp_path), "clean-files")
    assert rc == 0
    assert bridge.calls == []  # dry run: the bridge is never asked anything
    assert bridge.destroyed == 1  # the stack teardown is unconditional
    assert set(src.files) == {"readme.html", "dump.sql", "wp-config.php"}
    assert "## Plan" in capsys.readouterr().out
    assert not [
        r for r in wpt_records if "cache purge" in r.getMessage()
    ]


def test_apply_failure_never_purges(tmp_path, capsys, monkeypatch,
                                     wpt_records):
    events, src, bridge = _stack(monkeypatch)
    record = get_action("clean-files")

    def boom(ctx, stack, plan):
        raise SourceError("injected apply failure")

    # The shared registry instance is patched for this test only (the
    # per-item guards inside clean-files swallow source errors, so an
    # apply that RAISES cannot be induced through data alone).
    monkeypatch.setattr(record.action, "apply", boom)
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "clean-files")
    assert rc == 1  # unchanged by the purge step
    assert bridge.calls == []
    assert bridge.destroyed == 1  # teardown still runs
    assert set(src.files) == {"readme.html", "dump.sql", "wp-config.php"}
    errors = _registry_records(wpt_records, logging.ERROR)
    assert errors and "apply failed after backup" in errors[0].getMessage()
    assert not [r for r in wpt_records if "cache purge" in r.getMessage()]


def test_purge_failure_is_warning_not_error(tmp_path, capsys, monkeypatch,
                                            wpt_records):
    _events, src, bridge = _stack(
        monkeypatch,
        purge_error=BridgeError("bridge action failed: purge refused"),
    )
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "clean-files")
    assert rc == 0  # the apply's success is PRESERVED
    assert set(src.files) == {"wp-config.php"}  # the changes ARE applied
    assert bridge.calls == [("purge_cache", {})]  # it was attempted once
    assert bridge.destroyed == 1  # teardown still happens
    warnings = _registry_records(wpt_records, logging.WARNING)
    assert len(warnings) == 1
    message = warnings[0].getMessage()
    assert "cache purge failed" in message
    assert "changes ARE applied" in message
    assert "stale pages may persist until the cache expires" in message
    assert "purge refused" in message  # the exception text rides along
    # a purge failure never impersonates a command failure
    assert not _registry_records(wpt_records, logging.ERROR)
    # the success report and summary still print
    out = capsys.readouterr().out
    assert out.count("| yes |") == 2
    infos = _registry_records(wpt_records, logging.INFO)
    assert any("applied 2/2 items" in r.getMessage() for r in infos)


# ------------------------------------------------------- the --report contract

def zf_names(path):
    """The archive's member names (a real zip: the rehearsal reads it)."""
    with zipfile.ZipFile(path) as zf:
        return sorted(zf.namelist())


#: The plan table's item rows, read out of the FILE the way an operator
#: does rather than re-deriving the renderer (header excluded).
def _plan_rows(markdown):
    body = markdown.split("## Plan", 1)[1]
    return [line for line in body.splitlines()
            if line.startswith("| ") and line.endswith(" |")
            and "est. bytes" not in line]


def test_report_is_written_on_a_dry_action(tmp_path, capsys, monkeypatch):
    """--report is the tool's universal contract, so an ACTION honours it.

    A dry run printed its plan to stdout and left ``out.md`` UNCREATED:
    every registered action (clean-files, trim-media, optimize-media,
    harden, heal-core, deactivate-plugin, prune-core, park-backups,
    cull-media, webp-media, reconcile-plugins, users_reset) and the
    deploy dry run accepted the flag and silently dropped it, while the
    audit/verify/doctor paths honoured it.  The file carries exactly what
    the operator read on stdout, in the audit report's own shape.
    """
    _stack(monkeypatch)
    report = tmp_path / "out.md"
    rc = run_action(_ctx(tmp_path, report_path=report), "clean-files")
    assert rc == 0
    printed = capsys.readouterr().out
    assert report.exists()
    written = report.read_text(encoding="utf-8")
    # the file IS the printed report (print() adds the trailing newline)
    assert written + "\n" == printed
    assert "# wpt clean-files — " in written  # the command's own header
    assert "## Plan" in written
    rows = _plan_rows(written)
    assert len(rows) == 2              # one row per planned item
    assert any("| dump.sql |" in row for row in rows)
    assert any("| readme.html |" in row for row in rows)
    # a dry run applied nothing, and the file says so
    assert written.count("| no |") == 2
    assert "**Reclaimable estimate:" in written
    # the JSON twin the audit report pairs with its markdown
    twin = json.loads(report.with_suffix(".json").read_text(encoding="utf-8"))
    assert len(twin["plan"]["items"]) == 2
    assert {i["target"] for i in twin["plan"]["items"]} == {
        "dump.sql", "readme.html"}


def test_report_is_written_on_a_local_rehearsal_apply(tmp_path, monkeypatch):
    """The APPLIED local rehearsal writes its report too (a real zip, so
    the rehearsal is the real path: --apply stages in memory and never
    touches the original archive)."""
    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.html", b"junk")
        zf.writestr("wp-config.php", b"cfg")
    before = zf_names(zpath)
    report = tmp_path / "out.md"
    ctx = Ctx(source="local", settings=load(), command="clean-files",
              apply=True, yes=True, zip=zpath, sql=None,
              backup_dir=tmp_path / "backup", report_path=report)
    assert run_action(ctx, "clean-files") == 0
    assert zf_names(zpath) == before     # the original IS the rollback
    assert len(list(tmp_path.glob("site-rehearsed-*.zip"))) == 1
    written = report.read_text(encoding="utf-8")
    assert [r for r in _plan_rows(written) if "| readme.html |" in r]
    assert written.count("| yes |") == 1  # applied, not planned


def test_R20_a_report_naming_the_rehearsal_archive_is_refused(
        tmp_path, monkeypatch):
    """R20-P2: a ``--report`` equal to the run's own rehearsal archive
    replaced the freshly materialized zip with Markdown on a GREEN run.
    The path is recorded as a protected OUTPUT before materialization."""
    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.html", b"junk")
        zf.writestr("wp-config.php", b"cfg")
    archive = tmp_path / "site-rehearsed-fixed.zip"
    monkeypatch.setattr(registry_mod, "_rehearsal_path",
                        lambda ctx: archive)
    ctx = Ctx(source="local", settings=DEFAULTS, command="clean-files",
              apply=True, yes=True, zip=zpath, sql=None,
              backup_dir=tmp_path / "backup", report_path=archive)
    assert run_action(ctx, "clean-files") == 1
    assert zipfile.is_zipfile(archive)          # the deliverable survives
    with zipfile.ZipFile(archive) as zf:
        assert zf.namelist()
    assert not archive.read_bytes().startswith(b"# wpt audit")


def test_R20_a_report_naming_the_redump_is_refused(tmp_path):
    """Same protected-OUTPUT rule for clean-db's ``--re-dump`` file."""
    dump = tmp_path / "fresh.sql"
    dump.write_bytes(b"-- dump bytes\n")
    ctx = _ctx(tmp_path, report_path=dump, re_dump=dump)
    assert registry_mod.write_report(ctx, "clean-db", "# report\n", "{}") == 1
    assert dump.read_bytes() == b"-- dump bytes\n"


def test_report_is_written_for_an_empty_plan(tmp_path, capsys, monkeypatch):
    """An EMPTY plan still creates the file: a caller must be able to
    trust that ``--report`` was honoured (a plan with nothing to do is a
    result, not a reason for the file to be missing)."""
    _events, src, _bridge = _stack(monkeypatch)
    src.files = {"wp-config.php": b"cfg"}   # nothing junky: no items at all
    report = tmp_path / "out.md"
    rc = run_action(_ctx(tmp_path, report_path=report), "clean-files")
    assert rc == 0
    assert "## Plan" in capsys.readouterr().out
    assert report.exists()
    written = report.read_text(encoding="utf-8")
    assert "## Plan" in written
    assert _plan_rows(written) == []


def test_report_is_written_by_deploy_dry_run(tmp_path):
    """The OTHER dry-run path honours it: a deploy dry run printed the
    plan and created no file.  (deploy shares the registry's writer, so
    the contract cannot diverge between the two.)"""
    from wpt import deploy

    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("site.test/wp-config.php", b"cfg")
        zf.writestr("site.test/wp-content/index.php", b"<?php")
    report = tmp_path / "deploy.md"
    ctx = Ctx(source="local", settings=load(), command="deploy", apply=False,
              zip=zpath, webroot="/www", report_path=report,
              backup_dir=tmp_path / "backup",
              extra={"ssh_target": "root@box.example"})
    assert deploy.run(ctx) == 0
    assert report.exists()
    written = report.read_text(encoding="utf-8")
    assert "wpt deploy (dry run)" in written
    assert "root@box.example:/www" in written
    assert "`wp-content`" in written     # the plan table
    assert "| item | detail | bytes |" in written


def test_unwritable_report_fails_the_run(tmp_path, capsys, monkeypatch,
                                          wpt_records):
    """A report the operator asked for and the run could not write is a
    FAILED run (rc 1), never a success that silently dropped the output:
    the whole value of --report is that the file is there afterwards."""
    _stack(monkeypatch)
    unwritable = tmp_path / "as-a-directory.md"
    unwritable.mkdir()
    rc = run_action(_ctx(tmp_path, report_path=unwritable), "clean-files")
    assert rc == 1
    # the plan was still printed (stdout is never withheld), the files
    # were not touched (this was a dry run)
    assert "## Plan" in capsys.readouterr().out
    errors = _registry_records(wpt_records, logging.ERROR)
    assert errors and "could not write the report" in errors[0].getMessage()


# ---------------------------------- the report of a run that produced nothing
#
# L44 gave every dry run a report; a FAILED or REFUSING run still wrote
# NOTHING, so a caller reading --report could not tell "the run planned
# nothing" from "the run never got far enough" — one absence read two ways,
# and the refusal a caller most wants to read was the one never written.


def test_a_refused_run_writes_its_refusal(tmp_path, monkeypatch, wpt_records):
    """A refusal writes the report the caller asked for, in the audit
    report's own shape, with ZERO findings and ZERO planned items plus the
    one thing a success report can never say: why there is nothing there."""
    from wpt.types import SourceError

    _events, _src, _bridge = _stack(monkeypatch)
    report = tmp_path / "out.md"
    record = get_action("clean-files")

    def boom(ctx, stack):
        raise SourceError("the site refused the read")

    monkeypatch.setattr(record.action, "plan", boom)
    rc = run_action(_ctx(tmp_path, apply=True, yes=True, report_path=report),
                    "clean-files")

    assert rc == 1
    written = report.read_text(encoding="utf-8")
    assert "## This run did not complete" in written
    assert "the site refused the read" in written
    assert "- status: failed" in written
    assert "- findings: 0" in written
    assert "- planned items: 0" in written
    assert _plan_rows(written) == []
    twin = json.loads(report.with_suffix(".json").read_text(encoding="utf-8"))
    assert twin["findings"] == []
    assert twin["plan"]["items"] == []
    assert twin["run"] == {"status": "failed",
                           "reason": twin["run"]["reason"],
                           "findings": 0, "planned_items": 0}
    assert "the site refused the read" in twin["run"]["reason"]
    errors = _registry_records(wpt_records, logging.ERROR)
    assert errors and "the site refused the read" in errors[0].getMessage()


def test_a_failed_run_writes_its_refusal_not_a_plan(tmp_path, monkeypatch):
    """A failure AFTER a real plan exists still reports the FAILURE, and
    the report never claims items it did not apply: a caller must not read
    a failed apply as a clean dry run."""
    from wpt.types import SourceError

    _events, _src, _bridge = _stack(monkeypatch)
    report = tmp_path / "out.md"
    record = get_action("clean-files")

    def boom(ctx, stack, plan):
        raise SourceError("injected apply failure")

    monkeypatch.setattr(record.action, "apply", boom)
    rc = run_action(_ctx(tmp_path, apply=True, yes=True, report_path=report),
                    "clean-files")

    assert rc == 1
    written = report.read_text(encoding="utf-8")
    assert "injected apply failure" in written
    assert "## This run did not complete" in written
    assert _plan_rows(written) == []
    assert "| yes |" not in written


def test_a_successful_run_report_is_byte_identical(tmp_path, monkeypatch):
    """The failure report must not have moved the SUCCESS report: an
    action's ``--report`` file is pinned byte-for-byte, so a change to
    either the markdown or its JSON twin is a change to the contract every
    consumer of an action report has been reading."""
    _stack(monkeypatch)
    report = tmp_path / "out.md"
    ctx = _ctx(tmp_path, report_path=report)

    assert run_action(ctx, "clean-files") == 0

    assert report.read_text(encoding="utf-8") == (
        "# wpt clean-files — example.com\n"
        "\n"
        "Source: action plan (ftp)\n"
        "\n"
        "**Reclaimable estimate: 0 B**\n"
        "\n"
        "## Plan\n"
        "\n"
        "| action | target | detail | est. bytes | applied |\n"
        "|---|---|---|---|---|\n"
        "| webroot.junk | dump.sql | *.sql | 500 B | no |\n"
        "| webroot.junk | readme.html | readme.html | 100 B | no |\n"
        "\n"
        "**Plan total estimate: 600 B**\n"
    )
    twin = json.loads(report.with_suffix(".json").read_text(encoding="utf-8"))
    assert "run" not in twin            # a success needs no such key
    assert [i["target"] for i in twin["plan"]["items"]] == [
        "dump.sql", "readme.html"]


def test_the_failure_report_is_never_printed(tmp_path, monkeypatch, capsys):
    """A failed run has no report to SHOW: stdout stays the surface of a
    report that exists, and the reason is the log's single line."""
    from wpt.types import SourceError

    _stack(monkeypatch)
    record = get_action("clean-files")

    def boom(ctx, stack):
        raise SourceError("the site refused the read")

    monkeypatch.setattr(record.action, "plan", boom)
    rc = run_action(_ctx(tmp_path, apply=True, yes=True,
                         report_path=tmp_path / "out.md"), "clean-files")

    assert rc == 1
    assert capsys.readouterr().out == ""


# ------------------------------------------------------- triple-check round 6


def test_R6_35_a_teardown_stop_ends_rc1_and_writes_the_failure_report(
        tmp_path, capsys, monkeypatch, wpt_records):
    """R6-35: destroy() raising StopRequested was caught as a generic
    warning, so a SIGTERM'd dry run printed success and returned 0.  Finish
    both cleanups, then log/write/return 1."""
    from wpt.types import StopRequested

    events: list[str] = []
    src = EventSource(events)
    _junk_tree(src)

    class _StopBridge(FakeBridge):
        def destroy(self):
            super().destroy()
            raise StopRequested("received SIGTERM (15)")

    bridge = _StopBridge(events)
    monkeypatch.setattr(registry_mod, "_stack",
                        lambda ctx: (src, None, bridge))
    ctx = _ctx(tmp_path, report_path=tmp_path / "plan.md")

    assert run_action(ctx, "clean-files") == 1

    assert bridge.destroyed == 1
    assert set(src.files) == {"readme.html", "dump.sql", "wp-config.php"}
    written = ctx.report_path.read_text("utf-8")
    assert "teardown stopped" in written
    assert "SIGTERM" in written
    assert "readme.html" in capsys.readouterr().out  # the plan was printed


@pytest.mark.parametrize("stage, reason", [
    ("plan", "list_dir failed"),
    ("apply", "apply failed hard"),
])
def test_R6_46_a_teardown_stop_never_overwrites_the_primary_failure(
        stage, reason, tmp_path, monkeypatch, wpt_records):
    """R6-46: when the action already returned rc 1, destroy() raising
    StopRequested REPLACED its failure report with the teardown stop.  The
    primary reason must stay on disk; both are logged; rc is 1."""
    from wpt.types import SourceError, StopRequested

    events: list[str] = []
    src = EventSource(events)
    _junk_tree(src)

    class _StopBridge(FakeBridge):
        def destroy(self):
            super().destroy()
            raise StopRequested("received SIGTERM (15)")

    bridge = _StopBridge(events)
    monkeypatch.setattr(registry_mod, "_stack",
                        lambda ctx: (src, None, bridge))
    record = get_action("clean-files")

    def boom(*args):
        raise SourceError(reason)

    monkeypatch.setattr(record.action, stage, boom)
    ctx = _ctx(tmp_path, apply=True, yes=True,
               report_path=tmp_path / f"{stage}.md")

    assert run_action(ctx, "clean-files") == 1
    written = ctx.report_path.read_text("utf-8")
    assert reason in written
    assert "teardown stopped" not in written
    messages = [r.getMessage() for r in wpt_records
                if r.name == "wpt.actions"]
    assert any(reason in message for message in messages)
    assert any("teardown stopped" in message and "SIGTERM" in message
               for message in messages)


# ------------------------------------------------- triple-check round 7


@pytest.mark.parametrize("error", [
    registry_mod.StopRequested("received SIGTERM (15)"),
    registry_mod.DeadlineExceeded("run deadline exceeded"),
])
def test_R7_P2_07_purge_cooperative_stop_ends_rc1(
        tmp_path, capsys, monkeypatch, wpt_records, error):
    """R7-P2-07: the post-apply cache purge caught EVERY exception, so a
    SIGTERM/deadline during it was swallowed and the run answered rc 0."""
    events, src, bridge = _stack(monkeypatch, purge_error=error)
    report = tmp_path / "out.md"
    rc = run_action(_ctx(tmp_path, apply=True, yes=True,
                         report_path=report), "clean-files")
    assert rc == 1
    assert bridge.destroyed == 1  # teardown still runs
    written = report.read_text(encoding="utf-8")
    assert written.startswith("# wpt clean-files — ")
    assert "## This run did not complete" in written
    assert "post-apply cache purge" in written
    assert "| yes |" not in written  # no success report
    assert any("post-apply cache purge" in r.getMessage()
               for r in _registry_records(wpt_records, logging.ERROR))


def test_C8_the_pre_action_scope_walk_receives_the_run_deadline(
        tmp_path, monkeypatch):
    """C8: the pre-action scope walk ran before any deadline existed.  The
    budget is built at action entry and passed into the scope expansion."""
    from wpt.deadline import Deadline

    _events, _src, _bridge = _stack(monkeypatch)
    captured = {}

    def _scope(source, plan, deadline=None):
        captured["deadline"] = deadline
        return []

    monkeypatch.setattr(registry_mod, "_backup_file_scope", _scope)
    ctx = _ctx(tmp_path, apply=True, yes=True, deadline_s=120,
               report_path=None)
    assert run_action(ctx, "clean-files") == 0
    assert isinstance(captured["deadline"], Deadline)
    assert captured["deadline"]._seconds == 120


def test_C1_a_stop_in_the_report_step_is_answered_at_the_action_boundary(
        tmp_path, capsys, monkeypatch, wpt_records):
    """C1: ``_execute_action`` had only try/finally, so a StopRequested from
    ``_emit``/``render_report`` escaped ``run_action`` as a traceback with no
    report pair.  It must unwind through teardown and end rc 1 with the
    shared failure pair."""
    from wpt.types import StopRequested

    _events, _src, bridge = _stack(monkeypatch)

    def _stop(*_args, **_kwargs):
        raise StopRequested("received SIGTERM (15)")

    monkeypatch.setattr(registry_mod, "_emit", _stop)
    report = tmp_path / "out.md"
    rc = run_action(_ctx(tmp_path, report_path=report), "clean-files")

    assert rc == 1
    assert bridge.destroyed == 1
    written = report.read_text(encoding="utf-8")
    assert "## This run did not complete" in written
    assert "SIGTERM" in written
    assert capsys.readouterr().out == ""


def test_R20_an_expired_deadline_after_plan_is_not_a_success_plan(
        tmp_path, capsys, monkeypatch, wpt_records):
    """R20-P1: an action that SWALLOWED its own DeadlineExceeded (integrity's
    partial scan does) returned a partial/empty plan and the registry printed
    it as rc 0.  The post-plan and emit checks must end rc 1 with the shared
    failure pair, never a success plan."""
    import time

    from wpt.deadline import Deadline
    from wpt.report import Plan
    from wpt.types import DeadlineExceeded

    _events, _src, bridge = _stack(monkeypatch)
    record = get_action("clean-files")
    original = record.action.plan

    def _slow_plan(ctx, stack):
        time.sleep(0.12)
        try:
            Deadline.from_ctx(ctx).check("heal plan")
        except DeadlineExceeded:
            pass  # the swallowed-stop shape the action contract allows
        return Plan(items=[])

    monkeypatch.setattr(record.action, "plan", _slow_plan)
    report = tmp_path / "out.md"
    ctx = _ctx(tmp_path, deadline_s=0.05, report_path=report)
    try:
        assert run_action(ctx, "clean-files") == 1
    finally:
        monkeypatch.setattr(record.action, "plan", original)

    assert bridge.destroyed == 1
    written = report.read_text(encoding="utf-8")
    assert "## This run did not complete" in written
    assert "deadline" in written.lower()
    assert "| yes |" not in written
    assert capsys.readouterr().out == ""


def test_R20_emit_refuses_after_the_run_budget(tmp_path):
    """The shared plan emitter is bounded too: a render/write after the
    budget raises instead of publishing the plan."""
    from wpt.deadline import Deadline
    from wpt.report import Plan
    from wpt.types import DeadlineExceeded

    ctx = _ctx(tmp_path, deadline_s=60)
    deadline = Deadline(0.01)
    deadline._started -= 1.0
    ctx._deadline = deadline
    with pytest.raises(DeadlineExceeded):
        registry_mod._emit(ctx, "clean-files", Plan(items=[]))


def test_R9_P2_9_pre_action_snapshot_receives_the_run_deadline(
        tmp_path, capsys, monkeypatch, wpt_records):
    """P2-9: the pre-action snapshot armed no deadline, so a slow capture
    ran past --deadline before apply."""
    import time

    events, src, bridge = _stack(monkeypatch, purge_result=PURGE_OK)
    report = tmp_path / "out.md"
    captured = {}

    def _snapshot(**kwargs):
        captured.update(kwargs)
        deadline = kwargs.get("deadline")
        assert deadline is not None
        time.sleep(max(0.0, deadline.at - time.monotonic()))
        deadline.check("snapshot capture")
        raise AssertionError("deadline did not expire")

    monkeypatch.setattr(registry_mod, "create_snapshot", _snapshot)
    ctx = _ctx(tmp_path, apply=True, yes=True, deadline_s=0.2,
               report_path=report)

    assert run_action(ctx, "clean-files") == 1

    written = report.read_text(encoding="utf-8")
    assert "pre-action backup failed" in written
    assert "deadline" in written.lower()
    assert "## This run did not complete" in written
    assert not [event for event in events if event.startswith("source:delete")]
    assert not [event for event in events if event.startswith("bridge:purge")]
    assert captured["deadline"].at < float("inf")


def test_R11_backup_scope_normalizes_aliases_before_dedupe():
    """R11-P2-7: ``./a.txt`` and ``a.txt`` are one target in the pre-action
    scope too; passing both to create_snapshot raised a raw ValueError."""
    from wpt.report import Plan
    from wpt.types import PlanItem

    src = EventSource([])
    src.files["a.txt"] = b"a"
    plan = Plan(items=[
        PlanItem("webroot.junk", "./a.txt", "junk"),
        PlanItem("webroot.junk", "a.txt", "junk"),
    ])
    assert registry_mod._backup_file_scope(src, plan) == ["a.txt"]


def test_R18_backup_scope_refuses_casefold_targets_as_wpterror():
    """R18-P2: the pre-action scope deduped EXACTLY, so ``a.txt``+``A.txt``
    reached create_snapshot's ValueError and escaped the action boundary."""
    from wpt.report import Plan
    from wpt.types import PlanItem, WptError

    src = EventSource([])
    src.files["a.txt"] = b"a"
    src.files["A.txt"] = b"A"
    plan = Plan(items=[
        PlanItem("webroot.junk", "a.txt", "junk"),
        PlanItem("webroot.junk", "A.txt", "junk"),
    ])
    with pytest.raises(WptError, match="differ only by case"):
        registry_mod._backup_file_scope(src, plan)


def test_R7_P2_01_backup_scope_skips_wpt_endpoints():
    """R7-P2-01: a custom plan pattern could name a live token endpoint;
    the pre-action snapshot scope must drop it before create_snapshot."""
    from wpt.report import Plan
    from wpt.types import PlanItem

    src = EventSource([])
    src.files["index.php"] = b"<?php"
    src.files["bridge-deadbeef.php"] = b"<?php token"
    plan = Plan(items=[
        PlanItem("webroot.junk", "bridge-deadbeef.php", "junk"),
        PlanItem("webroot.junk", "index.php", "junk"),
    ])
    assert registry_mod._backup_file_scope(src, plan) == ["index.php"]


def test_R11_a_stop_during_the_failure_report_is_still_rc1(
        monkeypatch, tmp_path):
    """R11-P2-17: a second RunControl in the failure-report write escaped
    run_action; the first stop is the verdict, so it must stay rc 1."""
    from wpt.types import StopRequested

    def _stop(*_args, **_kwargs):
        raise StopRequested("SIGTERM during the failure report")

    monkeypatch.setattr(registry_mod, "write_failure_report", _stop)
    ctx = _ctx(tmp_path, source="local", command="clean-files")

    assert registry_mod.run_action(ctx, "clean-files") == 1


# ------------------------------------------------ round-8 teardown regression


def test_R8_P2_17_registry_closes_the_http_session(monkeypatch, tmp_path):
    """R8-P2-17: ``_teardown_action`` closed source and bridge but never
    stack[1], so every action leaked its HTTP session."""
    class _CloseRecordingSession:
        def __init__(self):
            self.closed = 0

        def close(self):
            self.closed += 1

    events: list[str] = []
    src = EventSource(events)
    _junk_tree(src)
    bridge = FakeBridge(events)
    session = _CloseRecordingSession()
    monkeypatch.setattr(registry_mod, "_stack",
                        lambda ctx: (src, session, bridge))

    assert run_action(_ctx(tmp_path), "clean-files") == 0
    assert session.closed == 1


def test_R21_unsafe_table_name_is_a_wpterror_with_a_report_pair(
        tmp_path, monkeypatch):
    """R21-P2: a hostile/buggy bridge db_audit table ``x/posts`` reached
    create_snapshot's ValueError and escaped the action boundary (no rc-1
    report pair, only a traceback).  The registry validates through the ONE
    table owner first, so the refusal is WptError -> shared pair."""
    from wpt.report import Plan

    record = get_action("clean-files")
    _stack(monkeypatch)

    def hostile_plan(_ctx, _stack):
        return Plan(backup_tables=["x/posts"])

    monkeypatch.setattr(record.action, "plan", hostile_plan)
    monkeypatch.setattr(
        registry_mod, "create_snapshot",
        lambda **_kwargs: pytest.fail("create_snapshot must not run"))
    report = tmp_path / "report.md"
    rc = run_action(_ctx(tmp_path, apply=True, yes=True, report_path=report),
                    "clean-files")
    assert rc == 1
    written = report.read_text(encoding="utf-8")
    assert "unsafe table name" in written
    assert "x/posts" in written
    twin = json.loads(report.with_suffix(".json").read_text(encoding="utf-8"))
    assert twin["run"]["status"] == "failed"


def test_R24_same_second_rehearsal_allocates_a_free_suffix(
        tmp_path, monkeypatch):
    """R24-P2: ``_rehearsal_path`` had second resolution and ``materialize``
    correctly refuses an existing destination, so a legitimate second apply
    in one second failed on its own artifact name.  The allocator retries."""
    import datetime as dt

    real = dt.datetime

    class Frozen(real):
        @classmethod
        def now(cls, tz=None):
            return real(2026, 10, 20, 20, 21, 47, tzinfo=tz)

    monkeypatch.setattr(dt, "datetime", Frozen)
    zpath = tmp_path / "site.zip"
    zpath.write_bytes(b"zip")
    ctx = Ctx(source="local", settings=DEFAULTS, command="clean-files",
              apply=True, yes=True, zip=zpath, sql=None,
              backup_dir=tmp_path / "backup")
    base = tmp_path / "site-rehearsed-20261020-202147.zip"
    base.write_bytes(b"first")
    (tmp_path / "site-rehearsed-20261020-202147-2.zip").write_bytes(b"second")
    assert registry_mod._rehearsal_path(ctx) == (
        tmp_path / "site-rehearsed-20261020-202147-3.zip")
