"""Tests for wpt doctor — the preflight self-check behind ``wpt doctor``.

Everything goes THROUGH run(ctx) with real Ctx objects, the way the CLI's
_lazy_call will invoke it.  The remote side is faked exactly as the
patchability contract prescribes: ``wpt.doctor.remote_stack`` (the seam
imported from wpt.audit) returns a preloaded FakeSource, a scripted
FakeSession and a call-recording bridge double; the PHP row is driven
through a monkeypatched ``wpt.doctor.PhpProbe``; the host-log row through
a monkeypatched ``wpt.doctor.collect_logs``; and the two network rows
(TLS certificate + HTTPS policy) are scripted at their module functions so
the panel tests stay deterministic.  The wp.org row is driven through the
REAL WpOrgApi (its 1h cache directory is pointed at a tmp_path — the same
isolation tests/audit/test_updates.py uses — so no test reads or writes
the repo's .wpt-cache/ and no stale entry can answer a scripted failure
with a cached PASS); free space comes from a monkeypatched
``shutil.disk_usage`` because the host's real value would make PASS/WARN
rows machine-dependent (flaky).  No network, no PHP, no sleeps —
deterministic.

Test -> behavior map:
  test_ftp_all_pass ................. full 11-row panel green: rc 0; the
        webroot count, layout markers, write probe, PHP runtime facts,
        bridge WP/PHP facts, homepage 200, TLS/HTTPS rows, host-log
        clean pass, wp.org offer and free-space details; the write probe
        is gone, the PHP probe and bridge destroyed exactly once; the
        table ALWAYS printed; --report writes the markdown + JSON twin
        with the EXACT shape {checks: [{name, result, detail}]}; the one
        info summary
  test_bridge_failure ............... bridge.call raises BridgeError:
        FAIL row carrying the message, rc 1, the other rows still
        measured, the bridge still destroyed exactly once
  test_site_500 ..................... the homepage answers 500: FAIL row
        (a server error is not healthy), rc 1
  test_wporg_unreachable ............ the wp.org GET raises a
        ConnectionError: WARN row (updates/integrity degrade), rc 0
  test_disk_below_floor ............. 400 MB free: disk FAIL, rc 1
  test_disk_between ................. 1 GB free: disk WARN, rc 0
  test_local_mode_reduced_panel ..... local mode: exactly the 2 reduced
        rows (disk + wp.org API), rc 0, the stack seam never called
  test_raising_seam_contained ....... remote_stack raises a RuntimeError:
        rc 1 (an int, never a traceback), the stack-dependent rows
        "not checked", wp.org still measured through the fallback
  test_layout_missing_bridge_gated_php_still_runs ... a non-WordPress
        root stands the bridge down but the generic PHP probe still runs
  test_write_failure_gates_bridge_and_probe ......... no writable
        webroot => write FAIL, bridge + PHP probe "not checked", the
        probe never constructed
  test_php_probe_warns_on_mysql_and_session ......... no MySQL extension
        and insecure session flags => WARN with the facts line, rc 0
  test_php_probe_call_failure_still_destroys ........ call raises => FAIL
        and destroy() still ran exactly once
  test_php_probe_without_version_is_warn ............ no php_version =>
        WARN, probe still destroyed
  test_probe_destroy_failure_is_one_warning ......... destroy raises =>
        the call result still stands and one warning is logged
  test_sweep_failure_is_one_warning ................. the stale sweep
        raises => the row continues and one warning is logged
  test_host_log_no_files ........................... scanned == 0 => WARN
  test_host_log_matches ............................ matches => WARN with
        the total, path/line/pattern and a 160-char excerpt
  test_host_log_error .............................. unreadable => WARN,
        never FAIL
  test_write_reported_success_but_probe_absent ...... a false exists()
        answer => FAIL, and the finally-delete still cleaned up
  test_write_cleanup_failure ....................... the probe cannot be
        removed => FAIL naming the path and reason
  test_no_report_path ............... no --report: stdout only, no
        markdown/json files written, stdout stays markdown-only
"""

import json
import logging
import shutil
import socket
import ssl
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

import wpt.audit.updates
import wpt.doctor
from tests.fakes import FakeResponse, FakeSession, FakeSource
from wpt.cli import Ctx
from wpt.settings import load
from wpt.types import (BridgeError, DeadlineExceeded, SourceError,
                       StopRequested, WptError)

SITE = "https://site.test"
WPORG_URL = "https://api.wordpress.org/core/version-check/1.7/?locale=en_US"
INFO = {"ok": True, "wp_version": "6.7.1", "php_version": "8.3.33"}
PHP_OK = {
    "ok": True,
    "php_version": "8.3.33",
    "php_sapi": "fpm-fcgi",
    "pdo_mysql": True,
    "mysqli": True,
    "ini": {"display_errors": "0"},
    "session": {
        "use_strict_mode": "1",
        "cookie_httponly": "1",
        "cookie_samesite": "Lax",
    },
}
PHP_DETAIL = ("PHP 8.3.33 (fpm-fcgi); mysql pdo_mysql,mysqli; "
              "session strict=1 httponly=1 samesite=Lax")
TLS_DETAIL = ("certificate verifies for site.test; SAN site.test; issuer Test CA; "
              "expires 2027-01-01 (73 day(s) left)")
HTTPS_DETAIL = "HTTP redirects to https://site.test/; HSTS max-age=31536000"

#: The fixture webroot: 4 root entries (wp-config.php + readme.html + the
#: wp-content and wp-includes directories).
WEBROOT = {
    "wp-config.php": b"<?php // config",
    "readme.html": b"<h1>WP</h1>",
    "wp-content/plugins/real/real.php": b"<?php /* real */",
    "wp-includes/version.php": b"<?php // version",
}

ROW_NAMES = [
    "ftp + webroot",
    "wordpress layout",
    "write access",
    "php runtime",
    "bridge round-trip",
    "site reachability",
    "tls certificate",
    "https policy",
    "host error log",
    "wp.org API",
    "disk",
]


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


@pytest.fixture(autouse=True)
def _wporg_cache_isolated(monkeypatch, tmp_path):
    """Point the real WpOrgApi's 1h cache at a fresh tmp_path: no test
    may read (or leave) the repo's .wpt-cache/, and no stale entry may
    turn a scripted failure into a cached PASS."""
    monkeypatch.setattr(wpt.audit.updates, "_CACHE_DIR", tmp_path / "cache")


# ------------------------------------------------------------------ fixtures


class ScriptedBridge:
    """Bridge double: records calls, answers the info payload (or raises
    the scripted error); counts destroy() calls."""

    def __init__(self, payload=None, error=None) -> None:
        self.payload = payload
        self.error = error
        self.calls: list[tuple[str, dict]] = []
        self.destroyed = 0

    def call(self, action, **params):
        self.calls.append((action, params))
        if self.error is not None:
            raise self.error
        return dict(self.payload)

    def destroy(self) -> None:
        self.destroyed += 1


class ScriptedProbe:
    """PhpProbe double: records construction, call and destroy."""

    def __init__(self, source, session, settings, site, *, payload,
                 error=None, destroy_error=None) -> None:
        self.source = source
        self.session = session
        self.settings = settings
        self.site = site
        self.payload = payload
        self.error = error
        self.destroy_error = destroy_error
        self.calls = 0
        self.destroyed = 0

    def call(self, *, deadline=None):
        self.calls += 1
        self.deadline = deadline
        if self.error is not None:
            raise self.error
        return self.payload

    def destroy(self) -> None:
        self.destroyed += 1
        if self.destroy_error is not None:
            raise self.destroy_error


def _install_probe(monkeypatch, payload=PHP_OK, error=None,
                   destroy_error=None):
    """Monkeypatch wpt.doctor.PhpProbe; return every constructed instance."""
    instances = []

    class _Probe(ScriptedProbe):
        def __init__(self, source, session, settings, site):
            super().__init__(
                source, session, settings, site, payload=payload,
                error=error, destroy_error=destroy_error)
            instances.append(self)

    monkeypatch.setattr(wpt.doctor, "PhpProbe", _Probe)
    return instances


def _patch_logs(monkeypatch, scan=None, error=None):
    """Fake wpt.doctor.collect_logs; return the sources it was handed."""
    calls = []
    if scan is None:
        scan = SimpleNamespace(
            scanned=2, total_matches=0, matches=[], files=[])

    def _collect(ctx, *, webroot_source=None, deadline=None):
        calls.append((webroot_source, deadline))
        if error is not None:
            raise error
        return scan

    monkeypatch.setattr(wpt.doctor, "collect_logs", _collect)
    return calls


def _patch_network(monkeypatch):
    """Script the two network rows so panel tests never dial out."""
    monkeypatch.setattr(
        wpt.doctor, "_tls_check",
        lambda ctx, *args: wpt.doctor._row(
            "tls certificate", "PASS", TLS_DETAIL))
    monkeypatch.setattr(
        wpt.doctor, "_https_policy_check",
        lambda session, ctx, *args: wpt.doctor._row(
            "https policy", "PASS", HTTPS_DETAIL))


def _wporg_ok(version="6.7.2"):
    """A 200 wp.org core version-check answer shaped for WpOrgApi."""
    return FakeResponse(200, json.dumps({"offers": [{"current": version}]}))


def _home_ok():
    return FakeResponse(200, "<html>home</html>")


def _ftp_ctx(tmp_path, **overrides):
    kwargs = dict(
        source="ftp://h:2121", settings=load(),
        user="u", password="s3cret-value", webroot="public_html",
        wp_url=SITE, backup_dir=tmp_path / "bk",
        report_path=tmp_path / "doctor.md",
    )
    kwargs.update(overrides)
    return Ctx(**kwargs)


def _patch(monkeypatch, bridge, script, free=3 * 1024 ** 3, files=None,
           source=None):
    """Fake the whole ftp remote side + disk: the seam returns
    (source, FakeSession, bridge double) and disk_usage reports ``free``
    bytes (3 GB by default => a PASS disk row)."""
    session = FakeSession(script)
    if source is None:
        source = FakeSource()
    source.files.update(WEBROOT if files is None else files)
    monkeypatch.setattr(wpt.doctor, "remote_stack",
                        lambda ctx: (source, session, bridge))
    monkeypatch.setattr(wpt.doctor.shutil, "disk_usage",
                        lambda _path: SimpleNamespace(free=free))
    return source, session


def _rows(ctx):
    """The JSON twin parsed into a name -> row map."""
    twin = ctx.report_path.with_suffix(".json")
    data = json.loads(twin.read_text(encoding="utf-8"))
    return data, {row["name"]: row for row in data["checks"]}


# --------------------------------------------------------------------- tests


def test_ftp_all_pass(monkeypatch, tmp_path, capsys, wpt_records):
    bridge = ScriptedBridge(INFO)
    source, session = _patch(
        monkeypatch, bridge, script=[_home_ok(), _wporg_ok()])
    probes = _install_probe(monkeypatch)
    log_sources = _patch_logs(monkeypatch)
    _patch_network(monkeypatch)
    closed: list[str] = []
    source.close = lambda: closed.append("source")
    session.close = lambda: closed.append("session")
    ctx = _ftp_ctx(tmp_path)

    assert wpt.doctor.run(ctx) == 0

    out = capsys.readouterr().out
    assert "# wpt doctor — https://site.test" in out
    pass_rows = [line for line in out.splitlines() if " | PASS | " in line]
    assert len(pass_rows) == 11
    assert "| ftp + webroot | PASS | 4 entries in webroot |" in out
    assert ("| wordpress layout | PASS | "
            "wp-config.php, wp-content, wp-includes |") in out
    assert ("| write access | PASS | "
            "webroot is writable (probe written and removed) |") in out
    assert f"| php runtime | PASS | {PHP_DETAIL} |" in out
    assert "| bridge round-trip | PASS | WP 6.7.1, PHP 8.3.33 |" in out
    assert "| site reachability | PASS | HTTP 200 at https://site.test/ |" in out
    assert f"| tls certificate | PASS | {TLS_DETAIL} |" in out
    assert f"| https policy | PASS | {HTTPS_DETAIL} |" in out
    assert ("| host error log | PASS | "
            "2 file(s); no fatal/error patterns |") in out
    assert "latest core offer 6.7.2" in out

    # the site GET rode the STACK session: exact URL, streamed, profile timeout
    assert session.gets[0][0] == f"{SITE}/"
    assert session.gets[0][1]["stream"] is True
    assert session.gets[0][1]["timeout"] == ctx.settings.http.timeout_s
    # the wp.org GET through the real WpOrgApi transport: the updates
    # checks' URL, the identifying UA, the profile timeout
    assert session.gets[1][0] == WPORG_URL
    assert session.gets[1][1]["headers"]["User-Agent"].startswith("wpt/")
    assert session.gets[1][1]["timeout"] == ctx.settings.http.timeout_s

    # the bridge: exactly one info round-trip, destroyed exactly once
    assert bridge.calls == [("info", {})]
    assert bridge.destroyed == 1
    # the PHP probe: one call, one destroy, same stack session
    assert len(probes) == 1
    assert probes[0].calls == 1
    assert probes[0].destroyed == 1
    assert probes[0].session is session
    assert probes[0].site == SITE
    # the host-log pass rode the webroot source the panel already built
    # (DOC1's shared-deadline proof lives in its own test below)
    assert [entry[0] for entry in log_sources] == [source]
    # the panel owns and closes the stack it built (bridge first, then the
    # FTP source and the HTTP session)
    assert closed == ["source", "session"]
    # successful writes leave nothing behind
    assert ".wpt-write-probe" not in source.files
    assert not any(name.startswith("wpt-probe-") for name in source.files)

    # --report: the markdown twin is byte-identical to stdout (+ print's
    # newline), the JSON twin carries the EXACT key shape
    markdown = ctx.report_path.read_text(encoding="utf-8")
    assert out == markdown + "\n"
    data, rows = _rows(ctx)
    assert set(data) == {"checks"}
    assert [row["name"] for row in data["checks"]] == ROW_NAMES
    assert all(set(row) == {"name", "result", "detail"}
               for row in data["checks"])
    assert all(row["result"] == "PASS" for row in data["checks"])
    assert rows["ftp + webroot"]["detail"] == "4 entries in webroot"
    assert rows["wordpress layout"]["detail"] == (
        "wp-config.php, wp-content, wp-includes")
    assert rows["php runtime"]["detail"] == PHP_DETAIL

    # exactly one info summary, counting the same rows the table carries
    infos = [r for r in wpt_records
             if r.name == "wpt.doctor" and r.levelno == logging.INFO]
    assert len(infos) == 1
    assert "doctor: 11 pass, 0 warn, 0 fail" in infos[0].getMessage()
    # the FTP password never reaches any log record
    assert not any("s3cret-value" in r.getMessage() for r in wpt_records)


def test_bridge_failure(monkeypatch, tmp_path):
    bridge = ScriptedBridge(error=BridgeError("bridge action failed: boom"))
    _patch(monkeypatch, bridge, script=[_home_ok(), _wporg_ok()])
    _install_probe(monkeypatch)
    _patch_logs(monkeypatch)
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path)

    assert wpt.doctor.run(ctx) == 1

    _data, rows = _rows(ctx)
    assert rows["bridge round-trip"]["result"] == "FAIL"
    assert "boom" in rows["bridge round-trip"]["detail"]
    # one broken row is the whole failure: the rest still measured
    assert rows["wordpress layout"]["result"] == "PASS"
    assert rows["write access"]["result"] == "PASS"
    assert rows["php runtime"]["result"] == "PASS"
    assert rows["site reachability"]["result"] == "PASS"
    assert rows["wp.org API"]["result"] == "PASS"
    assert rows["disk"]["result"] == "PASS"
    # the bridge never outlives the panel, failed round-trip included
    assert bridge.destroyed == 1


def test_site_500(monkeypatch, tmp_path):
    bridge = ScriptedBridge(INFO)
    _patch(monkeypatch, bridge,
           script=[FakeResponse(500, "oops"), _wporg_ok()])
    _install_probe(monkeypatch)
    _patch_logs(monkeypatch)
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path)

    assert wpt.doctor.run(ctx) == 1

    _data, rows = _rows(ctx)
    assert rows["site reachability"] == {
        "name": "site reachability",
        "result": "FAIL",
        "detail": "HTTP 500 at https://site.test/",
    }


def test_wporg_unreachable(monkeypatch, tmp_path):
    bridge = ScriptedBridge(INFO)
    _patch(monkeypatch, bridge,
           script=[_home_ok(), requests.ConnectionError("wp.org down")])
    _install_probe(monkeypatch)
    _patch_logs(monkeypatch)
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path)

    assert wpt.doctor.run(ctx) == 0

    _data, rows = _rows(ctx)
    assert rows["wp.org API"]["result"] == "WARN"
    assert "degrade" in rows["wp.org API"]["detail"]
    # a cold wp.org never blocks the session: the site row is still green
    assert rows["site reachability"]["result"] == "PASS"


def test_disk_below_floor(monkeypatch, tmp_path):
    bridge = ScriptedBridge(INFO)
    _patch(monkeypatch, bridge, script=[_home_ok(), _wporg_ok()],
           free=400 * 1024 ** 2)
    _install_probe(monkeypatch)
    _patch_logs(monkeypatch)
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path)

    assert wpt.doctor.run(ctx) == 1

    _data, rows = _rows(ctx)
    assert rows["disk"]["result"] == "FAIL"
    assert "400.0 MB free" in rows["disk"]["detail"]
    assert "snapshots cannot land" in rows["disk"]["detail"]


def test_disk_between(monkeypatch, tmp_path):
    bridge = ScriptedBridge(INFO)
    _patch(monkeypatch, bridge, script=[_home_ok(), _wporg_ok()],
           free=1024 ** 3)
    _install_probe(monkeypatch)
    _patch_logs(monkeypatch)
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path)

    assert wpt.doctor.run(ctx) == 0

    _data, rows = _rows(ctx)
    assert rows["disk"]["result"] == "WARN"
    assert "1.0 GB free" in rows["disk"]["detail"]
    assert "under 2.0 GB" in rows["disk"]["detail"]


def test_disk_nested_missing_backup_dir_uses_the_nearest_existing_ancestor(
        monkeypatch, tmp_path):
    """P2-DOCTOR-DISK: a nested, not-yet-created --backup-dir used its
    missing immediate parent directly and false-FAILed (rc 1) even though
    backup.create_snapshot does mkdir(parents=True)."""
    seen: list = []

    def usage(path):
        seen.append(path)
        return SimpleNamespace(free=3 * 1024 ** 3)

    monkeypatch.setattr(wpt.doctor.shutil, "disk_usage", usage)
    ctx = _ftp_ctx(
        tmp_path, backup_dir=tmp_path / "no-such" / "sub" / "bk")

    row = wpt.doctor._disk_check(ctx)

    assert row["result"] == "PASS"
    assert seen == [tmp_path]
    assert str(tmp_path) in row["detail"]


def test_disk_nested_missing_backup_dir_does_not_fail_the_local_panel(
        monkeypatch, tmp_path, capsys):
    """The nested target must not turn the local panel rc into 1 while
    backup.create_snapshot would happily mkdir(parents=True)."""
    session = FakeSession([_wporg_ok()])
    monkeypatch.setattr(wpt.doctor.requests, "Session", lambda: session)

    def usage(path):
        assert Path(path).is_dir()
        return SimpleNamespace(free=3 * 1024 ** 3)

    monkeypatch.setattr(wpt.doctor.shutil, "disk_usage", usage)
    ctx = Ctx(source="local", settings=load(),
              backup_dir=tmp_path / "no-such" / "sub" / "bk",
              report_path=tmp_path / "doctor.md")

    assert wpt.doctor.run(ctx) == 0
    _data, rows = _rows(ctx)
    assert rows["disk"]["result"] == "PASS"
    assert str(tmp_path) in rows["disk"]["detail"]
    assert "disk" in capsys.readouterr().out


def test_local_mode_reduced_panel(monkeypatch, tmp_path, capsys):
    def _never(ctx):
        raise AssertionError("remote_stack must not be called in local mode")

    monkeypatch.setattr(wpt.doctor, "remote_stack", _never)
    session = FakeSession([_wporg_ok()])
    monkeypatch.setattr(wpt.doctor.requests, "Session", lambda: session)
    monkeypatch.setattr(wpt.doctor.shutil, "disk_usage",
                        lambda _path: SimpleNamespace(free=3 * 1024 ** 3))
    ctx = Ctx(source="local", settings=load(),
              backup_dir=tmp_path / "bk",
              report_path=tmp_path / "doctor.md")

    assert wpt.doctor.run(ctx) == 0

    data, rows = _rows(ctx)
    assert set(data) == {"checks"}
    assert [row["name"] for row in data["checks"]] == ["disk", "wp.org API"]
    assert all(row["result"] == "PASS" for row in data["checks"])
    # wp.org through the plain patched session, never the stack seam
    assert session.gets[0][0] == WPORG_URL
    out = capsys.readouterr().out
    assert "Local mode — reduced panel" in out
    assert "11-check panel" in out
    assert "| disk | PASS |" in out
    assert "| wp.org API | PASS |" in out
    assert "ftp + webroot" not in out


def test_raising_seam_contained(monkeypatch, tmp_path, capsys):
    def _boom(ctx):
        raise RuntimeError("the seam exploded")

    monkeypatch.setattr(wpt.doctor, "remote_stack", _boom)
    # the wp.org fallback after a failed stack must not touch the network
    session = FakeSession([_wporg_ok()])
    monkeypatch.setattr(wpt.doctor.requests, "Session", lambda: session)
    monkeypatch.setattr(wpt.doctor.shutil, "disk_usage",
                        lambda _path: SimpleNamespace(free=3 * 1024 ** 3))
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path)

    rc = wpt.doctor.run(ctx)

    # contained: an int rc, never a traceback reaching the CLI
    assert rc == 1
    out = capsys.readouterr().out
    assert ("| ftp + webroot | FAIL | "
            "remote stack failed: the seam exploded |") in out
    data, rows = _rows(ctx)
    assert [row["name"] for row in data["checks"]] == ROW_NAMES
    assert rows["wordpress layout"]["result"] == "FAIL"
    assert rows["wordpress layout"]["detail"] == (
        "not checked — webroot listing failed")
    for name in ("write access", "php runtime", "bridge round-trip",
                 "site reachability", "https policy", "host error log"):
        assert rows[name]["result"] == "FAIL"
        assert "not checked" in rows[name]["detail"]
    # the independent rows still measured — wp.org through the fallback
    assert rows["tls certificate"]["result"] == "PASS"
    assert rows["wp.org API"]["result"] == "PASS"
    assert rows["disk"]["result"] == "PASS"


def test_layout_missing_bridge_gated_php_still_runs(monkeypatch, tmp_path):
    bridge = ScriptedBridge(INFO)
    _patch(monkeypatch, bridge, script=[_home_ok(), _wporg_ok()],
           files={
               "readme.html": b"<h1>not WP</h1>",
               "wp-content/plugins/real/real.php": b"<?php /* real */",
           })
    probes = _install_probe(monkeypatch)
    _patch_logs(monkeypatch)
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path)

    assert wpt.doctor.run(ctx) == 1

    _data, rows = _rows(ctx)
    assert rows["ftp + webroot"]["detail"] == "2 entries in webroot"
    assert rows["wordpress layout"]["result"] == "FAIL"
    assert rows["wordpress layout"]["detail"] == (
        "not a WordPress webroot — missing wp-config.php, wp-includes")
    assert rows["write access"]["result"] == "PASS"
    # the generic PHP probe is the diagnostic that must still run
    assert rows["php runtime"]["result"] == "PASS"
    assert len(probes) == 1 and probes[0].destroyed == 1
    # the bridge is gated on the layout, but the panel still retires it
    assert rows["bridge round-trip"]["result"] == "FAIL"
    assert rows["bridge round-trip"]["detail"] == (
        "not checked — not a WordPress webroot")
    assert bridge.calls == []
    assert bridge.destroyed == 1


def test_write_failure_gates_bridge_and_probe(monkeypatch, tmp_path):
    bridge = ScriptedBridge(INFO)
    source, _session = _patch(
        monkeypatch, bridge, script=[_home_ok(), _wporg_ok()])

    def _deny(path, data, **kwargs):
        raise SourceError("550 permission denied")

    source.write_bytes = _deny
    probes = _install_probe(monkeypatch)
    _patch_logs(monkeypatch)
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path)

    assert wpt.doctor.run(ctx) == 1

    _data, rows = _rows(ctx)
    assert rows["write access"]["result"] == "FAIL"
    assert rows["write access"]["detail"].startswith(
        "webroot is not writable over FTP: 550 permission denied; "
        "use the host file manager or fix ownership")
    assert ".wpt-write-probe" not in source.files
    assert rows["bridge round-trip"]["detail"] == (
        "not checked — write access failed")
    assert rows["php runtime"]["detail"] == (
        "not checked — write access failed")
    assert bridge.calls == []
    assert probes == []


def test_php_probe_warns_on_mysql_and_session(monkeypatch, tmp_path):
    bridge = ScriptedBridge(INFO)
    _patch(monkeypatch, bridge, script=[_home_ok(), _wporg_ok()])
    probes = _install_probe(monkeypatch, payload={
        "ok": True,
        "php_version": "8.1.2",
        "php_sapi": "fpm-fcgi",
        "pdo_mysql": False,
        "mysqli": False,
        "ini": {"display_errors": "1"},
        "session": {
            "use_strict_mode": "0",
            "cookie_httponly": "0",
            "cookie_samesite": "",
        },
    })
    _patch_logs(monkeypatch)
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path)

    assert wpt.doctor.run(ctx) == 0

    _data, rows = _rows(ctx)
    assert rows["php runtime"]["result"] == "WARN"
    assert rows["php runtime"]["detail"] == (
        "PHP 8.1.2 (fpm-fcgi); mysql none; "
        "session strict=0 httponly=0 samesite=unset")
    assert probes[0].destroyed == 1


def test_php_probe_call_failure_still_destroys(monkeypatch, tmp_path):
    bridge = ScriptedBridge(INFO)
    _patch(monkeypatch, bridge, script=[_home_ok(), _wporg_ok()])
    probes = _install_probe(
        monkeypatch, error=WptError("probe request failed: boom"))
    _patch_logs(monkeypatch)
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path)

    assert wpt.doctor.run(ctx) == 1

    _data, rows = _rows(ctx)
    assert rows["php runtime"]["result"] == "FAIL"
    assert rows["php runtime"]["detail"] == (
        "PHP runtime probe failed: probe request failed: boom")
    assert probes[0].calls == 1
    assert probes[0].destroyed == 1


def test_probe_destroy_failure_is_one_warning(
        monkeypatch, tmp_path, wpt_records):
    bridge = ScriptedBridge(INFO)
    _patch(monkeypatch, bridge, script=[_home_ok(), _wporg_ok()])
    probes = _install_probe(
        monkeypatch, destroy_error=WptError("unlink denied"))
    _patch_logs(monkeypatch)
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path)

    assert wpt.doctor.run(ctx) == 0

    _data, rows = _rows(ctx)
    assert rows["php runtime"]["result"] == "PASS"
    assert probes[0].destroyed == 1
    warnings = [r for r in wpt_records
                if r.name == "wpt.doctor" and r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "PHP probe destroy failed: unlink denied" in warnings[0].getMessage()


def test_sweep_failure_is_one_warning(monkeypatch, tmp_path, wpt_records):
    bridge = ScriptedBridge(INFO)
    _patch(monkeypatch, bridge, script=[_home_ok(), _wporg_ok()])

    def _sweep(source, settings):
        raise WptError("sweep exploded")

    monkeypatch.setattr(wpt.doctor, "sweep_stale_probes", _sweep)
    _install_probe(monkeypatch)
    _patch_logs(monkeypatch)
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path)

    assert wpt.doctor.run(ctx) == 0

    _data, rows = _rows(ctx)
    assert rows["php runtime"]["result"] == "PASS"
    warnings = [r for r in wpt_records
                if r.name == "wpt.doctor" and r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "stale probe sweep failed: sweep exploded" in (
        warnings[0].getMessage())


def test_host_log_no_files(monkeypatch, tmp_path):
    bridge = ScriptedBridge(INFO)
    _patch(monkeypatch, bridge, script=[_home_ok(), _wporg_ok()])
    _install_probe(monkeypatch)
    _patch_logs(monkeypatch, scan=SimpleNamespace(
        scanned=0, total_matches=0, matches=[], files=[]))
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path)

    assert wpt.doctor.run(ctx) == 0

    _data, rows = _rows(ctx)
    assert rows["host error log"]["result"] == "WARN"
    assert rows["host error log"]["detail"] == (
        "no host/webroot log files found")


def test_host_log_matches(monkeypatch, tmp_path):
    bridge = ScriptedBridge(INFO)
    _patch(monkeypatch, bridge, script=[_home_ok(), _wporg_ok()])
    _install_probe(monkeypatch)
    match = "2026-10-19 PHP Fatal error: " + "x" * 400
    _patch_logs(monkeypatch, scan=SimpleNamespace(
        scanned=2, total_matches=3, files=[{"path": "logs/error.log"}],
        matches=[{
            "file": "logs/error.log",
            "line": 12,
            "pattern": "PHP fatal",
            "match": match,
        }]))
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path)

    assert wpt.doctor.run(ctx) == 0

    _data, rows = _rows(ctx)
    detail = rows["host error log"]["detail"]
    assert rows["host error log"]["result"] == "WARN"
    assert detail.startswith(
        "3 matching line(s) in 2 file(s); latest logs/error.log:12 "
        "PHP fatal — 2026-10-19 PHP Fatal error: ")
    assert len(detail.rsplit(" — ", 1)[1]) == 160


def test_host_log_latest_is_the_last_line_of_the_newest_file(
        monkeypatch, tmp_path):
    bridge = ScriptedBridge(INFO)
    _patch(monkeypatch, bridge, script=[_home_ok(), _wporg_ok()])
    _install_probe(monkeypatch)
    _patch_logs(monkeypatch, scan=SimpleNamespace(
        scanned=1, total_matches=2,
        files=[{"path": "logs/error.log"}],
        matches=[
            {"file": "logs/error.log", "line": 10, "pattern": "PHP fatal",
             "match": "older"},
            {"file": "logs/error.log", "line": 20, "pattern": "PHP fatal",
             "match": "newer"},
        ]))
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path)

    assert wpt.doctor.run(ctx) == 0

    _data, rows = _rows(ctx)
    assert "logs/error.log:20" in rows["host error log"]["detail"]
    assert "newer" in rows["host error log"]["detail"]


def test_rows_and_site_label_redact_tokens_and_userinfo(tmp_path):
    row = wpt.doctor._row(
        "https policy", "WARN",
        "HTTP redirects to https://site.test/?token=sup3rsecret")
    assert "sup3rsecret" not in row["detail"]
    assert "***" in row["detail"]
    ctx = _ftp_ctx(
        tmp_path, wp_url="https://user:sup3rsecret@site.test")
    assert "sup3rsecret" not in wpt.doctor._site_label(ctx)


def test_host_log_error(monkeypatch, tmp_path):
    bridge = ScriptedBridge(INFO)
    _patch(monkeypatch, bridge, script=[_home_ok(), _wporg_ok()])
    _install_probe(monkeypatch)
    _patch_logs(monkeypatch, error=RuntimeError(
        "permission denied for token=abcd"))
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path)

    assert wpt.doctor.run(ctx) == 0

    _data, rows = _rows(ctx)
    assert rows["host error log"]["result"] == "WARN"
    assert rows["host error log"]["detail"].startswith(
        "could not read host logs: permission denied for token=***")


def test_write_reported_success_but_probe_absent(monkeypatch, tmp_path):
    bridge = ScriptedBridge(INFO)
    source, _session = _patch(
        monkeypatch, bridge, script=[_home_ok(), _wporg_ok()])
    real_exists = source.exists

    def _exists(path):
        if path.startswith(wpt.doctor._WRITE_PROBE_PREFIX):
            return False
        return real_exists(path)

    source.exists = _exists
    probes = _install_probe(monkeypatch)
    _patch_logs(monkeypatch)
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path)

    assert wpt.doctor.run(ctx) == 1

    _data, rows = _rows(ctx)
    assert rows["write access"]["result"] == "FAIL"
    assert rows["write access"]["detail"] == (
        "write reported success but the probe is absent")
    # the false answer did not stop the finally-delete cleanup
    assert ".wpt-write-probe" not in source.files
    assert rows["php runtime"]["detail"] == (
        "not checked — write access failed")
    assert probes == []


def test_php_probe_without_version_is_warn(monkeypatch, tmp_path):
    bridge = ScriptedBridge(INFO)
    _patch(monkeypatch, bridge, script=[_home_ok(), _wporg_ok()])
    probes = _install_probe(monkeypatch, payload={"ok": True})
    _patch_logs(monkeypatch)
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path)

    assert wpt.doctor.run(ctx) == 0

    _data, rows = _rows(ctx)
    assert rows["php runtime"]["result"] == "WARN"
    assert rows["php runtime"]["detail"] == (
        "probe answered ok but carried no php_version")
    assert probes[0].destroyed == 1


def test_write_cleanup_failure(monkeypatch, tmp_path):
    bridge = ScriptedBridge(INFO)
    source, _session = _patch(
        monkeypatch, bridge, script=[_home_ok(), _wporg_ok()])
    real_delete = source.delete

    def _delete(path):
        if path.startswith(wpt.doctor._WRITE_PROBE_PREFIX):
            raise SourceError("550 remove denied")
        return real_delete(path)

    source.delete = _delete
    probes = _install_probe(monkeypatch)
    _patch_logs(monkeypatch)
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path)

    assert wpt.doctor.run(ctx) == 1

    _data, rows = _rows(ctx)
    assert rows["write access"]["result"] == "FAIL"
    detail = rows["write access"]["detail"]
    assert detail.startswith(
        "write succeeded but the probe could not be removed: "
        + wpt.doctor._WRITE_PROBE_PREFIX)
    assert detail.endswith(": 550 remove denied")
    assert rows["bridge round-trip"]["detail"] == (
        "not checked — write access failed")
    assert probes == []


def test_update_core_residue_is_a_conditional_warn_row(monkeypatch, tmp_path):
    """A killed update-core left a retired root file: the panel must still
    surface it (the row is conditional, so the normal 11-row order is
    unchanged when the tree is clean)."""
    bridge = ScriptedBridge(INFO)
    _patch(
        monkeypatch, bridge, script=[_home_ok(), _wporg_ok()],
        files={
            **WEBROOT,
            "index.php.wpt-old": b"<?php // retired",
        })
    _install_probe(monkeypatch)
    _patch_logs(monkeypatch)
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path)

    assert wpt.doctor.run(ctx) == 0

    data, rows = _rows(ctx)
    assert data["checks"][1]["name"] == "wpt residue"
    assert rows["wpt residue"]["result"] == "WARN"
    assert "index.php.wpt-old (retired core)" in rows["wpt residue"]["detail"]


def test_no_report_path(monkeypatch, tmp_path, capsys):
    bridge = ScriptedBridge(INFO)
    _patch(monkeypatch, bridge, script=[_home_ok(), _wporg_ok()])
    _install_probe(monkeypatch)
    _patch_logs(monkeypatch)
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path, report_path=None)

    assert wpt.doctor.run(ctx) == 0

    assert not (tmp_path / "doctor.md").exists()
    assert not (tmp_path / "doctor.json").exists()
    out = capsys.readouterr().out
    assert "# wpt doctor — https://site.test" in out
    assert "| PASS |" in out
    # stdout is the markdown surface ONLY — no JSON leaks into it
    assert '"checks"' not in out


# ------------------------------------------------------- round-1 regressions


def test_DOCTOR_1_stop_request_is_never_a_diagnosis_row():
    def stop():
        raise StopRequested("received SIGTERM (15) — shutting down cleanly")

    with pytest.raises(StopRequested):
        wpt.doctor._guarded("check", stop)

    def plain_error():
        # Only StopRequested/DeadlineExceeded are run-level stops.  A plain
        # WptError whose text happens to name SIGTERM is a diagnosis row.
        raise WptError("received SIGTERM (15) — shutting down cleanly")

    row = wpt.doctor._guarded("check", plain_error)
    assert row["result"] == wpt.doctor.FAIL
    assert "received SIGTERM" in row["detail"]

    def expired():
        raise DeadlineExceeded("run deadline exceeded")

    with pytest.raises(DeadlineExceeded):
        wpt.doctor._guarded("check", expired)


def test_DEADLINE_1_doctor_expiry_ends_the_run_not_a_row(monkeypatch,
                                                         tmp_path):
    class _Expired:
        def check(self, context):
            raise DeadlineExceeded("run deadline exceeded")

    monkeypatch.setattr(wpt.doctor.Deadline, "from_ctx",
                        lambda ctx: _Expired())
    ctx = _ftp_ctx(tmp_path, report_path=None)
    _patch(monkeypatch, ScriptedBridge(INFO), script=[])
    assert wpt.doctor.run(ctx) == 1


class _ExistsRaises(FakeSource):
    def __init__(self):
        super().__init__()
        self.deletes: list[str] = []

    def write_bytes(self, path, data, *, allow_config=False,
                    allow_core=False):
        raise SourceError("STOR dropped mid-write")

    def exists(self, path):
        raise SourceError("control channel dead")

    def delete(self, path):
        self.deletes.append(path)


def test_D_CLEAN_write_probe_cleanup_attempts_delete_even_when_exists_raises():
    source = _ExistsRaises()
    row = wpt.doctor._write_check(source)
    assert row["result"] == "FAIL"
    assert len(source.deletes) == 1
    assert source.deletes[0].startswith(wpt.doctor._WRITE_PROBE_PREFIX)


def test_D_RESIDUE_core_updater_staging_is_detected(monkeypatch, tmp_path):
    bridge = ScriptedBridge(INFO)
    _patch(
        monkeypatch, bridge, script=[_home_ok(), _wporg_ok()],
        files={
            **WEBROOT,
            "wp-content/upgrade/wordpress-7.0/version.php": b"<?php",
        })
    _install_probe(monkeypatch)
    _patch_logs(monkeypatch)
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path)

    assert wpt.doctor.run(ctx) == 0

    _data, rows = _rows(ctx)
    assert rows["wpt residue"]["result"] == "WARN"
    assert "wp-content/upgrade" in rows["wpt residue"]["detail"]
    assert "WordPress's own updater staging" in rows["wpt residue"]["detail"]


def test_D_SKIP_host_log_skipped_file_is_a_warn_not_a_clean_pass(
        monkeypatch, tmp_path):
    bridge = ScriptedBridge(INFO)
    _patch(monkeypatch, bridge, script=[_home_ok(), _wporg_ok()])
    _install_probe(monkeypatch)
    _patch_logs(monkeypatch, scan=SimpleNamespace(
        scanned=1, total_matches=0, matches=[], files=[],
        skipped=[{"path": "logs/big.log",
                  "reason": "size exceeds logs.max_file_bytes"}]))
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path)

    assert wpt.doctor.run(ctx) == 0

    _data, rows = _rows(ctx)
    assert rows["host error log"]["result"] == "WARN"
    assert "1 skipped" in rows["host error log"]["detail"]


def test_D_LATEST_reports_the_latest_line_beyond_the_detail_cap(
        monkeypatch, tmp_path):
    bridge = ScriptedBridge(INFO)
    _patch(monkeypatch, bridge, script=[_home_ok(), _wporg_ok()])
    _install_probe(monkeypatch)
    detail = [
        {"file": "logs/error.log", "line": line, "pattern": "PHP fatal",
         "match": f"line {line}"}
        for line in range(1, 21)
    ]
    _patch_logs(monkeypatch, scan=SimpleNamespace(
        scanned=1, total_matches=25, files=[{"path": "logs/error.log"}],
        matches=detail,
        latest_matches={"logs/error.log": {
            "file": "logs/error.log", "line": 25, "pattern": "PHP fatal",
            "match": "newest"}}))
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path)

    assert wpt.doctor.run(ctx) == 0

    _data, rows = _rows(ctx)
    assert "logs/error.log:25" in rows["host error log"]["detail"]
    assert "newest" in rows["host error log"]["detail"]


def test_D_REPORT_json_report_path_is_refused_not_overwritten(
        monkeypatch, tmp_path, capsys):
    bridge = ScriptedBridge(INFO)
    _patch(monkeypatch, bridge, script=[_home_ok(), _wporg_ok()])
    _install_probe(monkeypatch)
    _patch_logs(monkeypatch)
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path, report_path=tmp_path / "doctor.json")

    assert wpt.doctor.run(ctx) == 1

    # nothing was half-written over the markdown surface
    assert not (tmp_path / "doctor.json").exists()
    assert "| check | result | detail |" in capsys.readouterr().out


_TLS_CERT_TOOLS = (
    shutil.which("openssl") is not None
    and hasattr(getattr(ssl, "_ssl", None), "_test_decode_cert")
)


@pytest.mark.skipif(not _TLS_CERT_TOOLS,
                    reason="openssl and CPython's DER decoder are required")
def test_D_TLS_unverified_retry_decodes_the_presented_certificate(tmp_path):
    key = tmp_path / "key.pem"
    cert_path = tmp_path / "cert.pem"
    subprocess.run(
        [shutil.which("openssl"), "req", "-x509", "-newkey", "rsa:2048",
         "-nodes", "-keyout", str(key), "-out", str(cert_path), "-days", "1",
         "-subj", "/CN=site.test",
         "-addext", "subjectAltName=DNS:site.test"],
        check=True, capture_output=True,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert_path), str(key))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve():
        conn, _addr = listener.accept()
        try:
            tls = context.wrap_socket(conn, server_side=True)
            tls.close()
        except OSError:
            conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        cert = wpt.doctor._tls_peer_cert(
            "127.0.0.1", "site.test", port, 5, verify=False)
    finally:
        listener.close()
        thread.join(5)

    assert cert.get("subjectAltName") == (("DNS", "site.test"),)
    facts = wpt.doctor._certificate_facts(cert, 0)
    assert "SAN site.test" in facts


# ------------------------------------------------------- triple-check round 2


@pytest.mark.skipif(not _TLS_CERT_TOOLS,
                    reason="openssl and CPython's DER decoder are required")
def test_R23_tls_peer_cert_falls_back_to_a_later_address_after_handshake(
        tmp_path, monkeypatch):
    """R23-P2: ``_tls_peer_cert`` broke out of the address loop after the
    first DIAL, so a stale/non-TLS service that accepted and then closed made
    the row WARN while the next address had a valid certificate.  Every
    address now gets its own dial+handshake share and a non-cert failure
    advances."""
    key = tmp_path / "key.pem"
    cert_path = tmp_path / "cert.pem"
    subprocess.run(
        [shutil.which("openssl"), "req", "-x509", "-newkey", "rsa:2048",
         "-nodes", "-keyout", str(key), "-out", str(cert_path), "-days", "1",
         "-subj", "/CN=site.test",
         "-addext", "subjectAltName=DNS:site.test"],
        check=True, capture_output=True,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert_path), str(key))
    if not socket.has_ipv6:
        pytest.skip("no IPv6 loopback for the address-fallback test")
    good = bad = None
    for _attempt in range(20):
        # 127.0.0.2 is not a loopback alias on macOS.  Two families on
        # loopback give the same port on two distinct dial addresses.
        candidate_good = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        candidate_good.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        try:
            candidate_good.bind(("::1", 0))
        except OSError:
            candidate_good.close()
            continue
        port = candidate_good.getsockname()[1]
        candidate_bad = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            candidate_bad.bind(("127.0.0.1", port))
        except OSError:
            candidate_bad.close()
            candidate_good.close()
            continue
        good, bad = candidate_good, candidate_bad
        break
    assert good is not None and bad is not None, \
        "could not bind the same port on ::1 and 127.0.0.1"
    good.listen(1)
    bad.listen(1)
    seen: list[str] = []

    def bad_serve():
        conn, _addr = bad.accept()
        seen.append("bad")
        conn.close()

    def good_serve():
        conn, _addr = good.accept()
        seen.append("good")
        try:
            tls = context.wrap_socket(conn, server_side=True)
            tls.close()
        except OSError:
            conn.close()

    threads = [threading.Thread(target=bad_serve, daemon=True),
               threading.Thread(target=good_serve, daemon=True)]
    for thread in threads:
        thread.start()
    monkeypatch.setattr(wpt.doctor, "_resolve_host_bounded",
                        lambda host, port, budget: ["127.0.0.1", "::1"])
    try:
        cert = wpt.doctor._tls_peer_cert(
            "resolved.test", "site.test", port, 5, verify=False)
    finally:
        bad.close()
        good.close()
        for thread in threads:
            thread.join(5)
    assert cert.get("subjectAltName") == (("DNS", "site.test"),)
    assert seen == ["bad", "good"]


def test_DOC1_host_log_row_uses_the_panels_deadline_not_a_fresh_one(
        monkeypatch, tmp_path):
    """DOC1: ``collect_logs`` built ``Deadline.from_ctx`` again, restarting
    the run budget at the row and overrunning doctor's deadline by a full
    extra budget."""
    marker = object()
    captured = {}

    def collect(ctx, *, webroot_source=None, deadline=None):
        captured["deadline"] = deadline
        return SimpleNamespace(scanned=0, total_matches=0, matches=[],
                               files=[], skipped=[])

    monkeypatch.setattr(wpt.doctor, "collect_logs", collect)
    row = wpt.doctor._host_log_check(_ftp_ctx(tmp_path), FakeSource(),
                                     marker)
    assert row["result"] == "WARN"
    assert captured["deadline"] is marker


def test_DOC1_logs_scan_does_not_rebuild_a_deadline_when_one_is_passed(
        monkeypatch, tmp_path):
    """The other half of DOC1: an explicitly passed (already expired)
    deadline raises before any candidate work; a fresh ``from_ctx`` would
    have restarted the budget and never been called."""
    from wpt.types import DeadlineExceeded

    class _Expired:
        def check(self, context):
            raise DeadlineExceeded("run deadline exceeded")

    monkeypatch.setattr(
        wpt.logs.Deadline, "from_ctx",
        lambda ctx: pytest.fail("a passed deadline must never be rebuilt"))
    ctx = _ftp_ctx(tmp_path)
    with pytest.raises(DeadlineExceeded):
        wpt.logs._scan(ctx, FakeSource(), FakeSource(), load().logs, _Expired())


def test_DOC2_run_level_deadline_still_writes_the_not_complete_report(
        tmp_path, monkeypatch):
    """DOC2: a run-level deadline/SIGTERM returned rc 1 with NO markdown or
    JSON artifact, indistinguishable from "measured nothing"."""
    ctx = wpt.cli.Ctx(source="local", settings=load(), command="doctor",
                      wp_url=SITE, deadline_s=1e-9,
                      report_path=tmp_path / "doctor.md")
    monkeypatch.setattr(wpt.doctor.shutil, "disk_usage",
                        lambda _path: SimpleNamespace(free=3 * 1024 ** 3))

    assert wpt.doctor.run(ctx) == 1

    markdown = (tmp_path / "doctor.md").read_text(encoding="utf-8")
    assert "# wpt doctor — https://site.test" in markdown
    assert "## This run did not complete" in markdown
    assert "deadline" in markdown.lower()
    twin = json.loads((tmp_path / "doctor.json").read_text(encoding="utf-8"))
    assert twin["checks"] == []
    assert twin["run"]["status"] == "failed"
    assert "deadline" in twin["run"]["reason"].lower()


def test_DOC3_a_regular_file_named_upgrade_is_not_updater_staging(
        monkeypatch, tmp_path):
    """DOC3: the residue row checked only the NAME, so an ordinary file
    ``wp-content/upgrade`` earned WordPress's staging label (twice)."""
    bridge = ScriptedBridge(INFO)
    _patch(
        monkeypatch, bridge, script=[_home_ok(), _wporg_ok()],
        files={**WEBROOT, "wp-content/upgrade": b"ordinary file"})
    _install_probe(monkeypatch)
    _patch_logs(monkeypatch)
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path)

    assert wpt.doctor.run(ctx) == 0

    _data, rows = _rows(ctx)
    assert "wpt residue" not in rows


class _StopOnWrite(FakeSource):
    def __init__(self):
        super().__init__()
        self.deletes: list[str] = []

    def write_bytes(self, path, data, *, allow_config=False,
                    allow_core=False):
        self.files[path] = data          # the STOR landed ...
        raise StopRequested("received SIGTERM (15)")  # ... then the stop

    def delete(self, path):
        self.deletes.append(path)
        self.files.pop(path, None)


def test_DOC4_write_probe_is_deleted_even_when_a_stop_lands_mid_write():
    """DOC4: ``_raise_stop`` ran before the cleanup delete, so a partial
    probe was left behind on SIGTERM/deadline."""
    source = _StopOnWrite()
    with pytest.raises(StopRequested):
        wpt.doctor._write_check(source)
    assert len(source.deletes) == 1
    probe = source.deletes[0]
    assert probe.startswith(wpt.doctor._WRITE_PROBE_PREFIX)
    assert probe not in source.files


def test_R16_write_probe_checks_the_budget_before_writing_or_sweeping():
    """R16-P2: the doctor write probe wrote (and swept stale probes) after
    the run budget expired, then the post-check raised.  Both actions now
    check first, so an expired budget leaves the webroot untouched."""
    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    source = FakeSource()
    with pytest.raises(DeadlineExceeded):
        wpt.doctor._write_check(source, 30, Deadline(-1))
    assert not any(name.startswith(wpt.doctor._WRITE_PROBE_PREFIX)
                   for name in source.files)

    stale = f"{wpt.doctor._WRITE_PROBE_PREFIX}{'a' * 16}"
    source.files[stale] = b"old"

    class _Aged(FakeSource):
        def list_dir(self, path):
            entries = super().list_dir(path)
            for entry in entries:
                if entry.path == stale:
                    entry.mtime = 1
            return entries

    aged = _Aged()
    aged.files[stale] = b"old"
    with pytest.raises(DeadlineExceeded):
        wpt.doctor._write_check(aged, 30, Deadline(-1))
    assert stale in aged.files


def test_R18_write_probe_cleanup_uses_a_fresh_cleanup_budget():
    """R18-P2: expiry after STOR made ``exists`` raise AND the finally
    ``delete`` raise against the same spent budget, leaving the probe.  The
    cleanup delete now runs under ``source_cleanup_budget``."""
    from contextlib import contextmanager

    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    class _ExpiredAfterWrite(FakeSource):
        def __init__(self) -> None:
            super().__init__()
            self.deadline = Deadline(0.2)
            self.deletes: list[str] = []

        @contextmanager
        def deadline_suspended(self):
            previous = self.deadline
            self.deadline = Deadline(30)
            try:
                yield
            finally:
                self.deadline = previous

        def exists(self, path):
            raise DeadlineExceeded("run deadline exceeded at exists")

        def delete(self, path, **kwargs):
            if self.deadline.remaining <= 0:
                raise DeadlineExceeded("run deadline exceeded at delete")
            self.deletes.append(path)
            return super().delete(path, **kwargs)

    source = _ExpiredAfterWrite()
    with pytest.raises(DeadlineExceeded):
        wpt.doctor._write_check(source)
    probes = [name for name in source.files
              if name.startswith(wpt.doctor._WRITE_PROBE_PREFIX)]
    assert probes == []
    assert len(source.deletes) == 1


class _StopDestroyBridge(ScriptedBridge):
    def destroy(self):
        super().destroy()
        raise StopRequested("received SIGTERM (15) during destroy")


def test_DOC5_a_stop_in_one_teardown_step_never_skips_the_others(
        monkeypatch, tmp_path):
    """DOC5: ``bridge.destroy()`` raising StopRequested inside the ``finally``
    skipped ``source.close()`` and ``session.close()``."""
    source = FakeSource()
    source.files.update(WEBROOT)
    session = FakeSession([_home_ok(), _wporg_ok()])
    closed: list[str] = []
    source.close = lambda: closed.append("source")
    session.close = lambda: closed.append("session")
    bridge = _StopDestroyBridge(INFO)
    monkeypatch.setattr(wpt.doctor, "remote_stack",
                        lambda ctx: (source, session, bridge))
    _install_probe(monkeypatch)
    _patch_logs(monkeypatch)
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path)

    with pytest.raises(StopRequested):
        wpt.doctor._ftp_panel(ctx, wpt.doctor.Deadline.from_ctx(ctx))

    assert bridge.destroyed == 1
    assert closed == ["source", "session"]


def test_FTP_SYMLINK_CONFIG_a_linked_wp_config_is_a_file_marker():
    """FTP-SYMLINK-CONFIG: FTP models a link as is_dir=True + is_link=True;
    the exact (name, is_dir=False) pair rejected a symlinked wp-config.php
    and the whole panel reported "not a WordPress webroot"."""
    from wpt.types import Entry

    entries = [
        Entry("wp-config.php", True, size=0, is_link=True),
        Entry("wp-content", True, size=0),
        Entry("wp-includes", True, size=0),
    ]
    row = wpt.doctor._layout_check(entries)
    assert row["result"] == "PASS", row


def test_REPORT_SURROGATE_bridge_payload_writes_both_faces(monkeypatch,
                                                           tmp_path, capsys):
    """REPORT-SURROGATE: the bridge's site-controlled wp_version carried a
    lone surrogate; _row redacts but does not encode, and write_text raised
    after the table, leaving a 0-byte markdown and no JSON twin."""
    bridge = ScriptedBridge({**INFO, "wp_version": "6.7.1\udcff"})
    _patch(monkeypatch, bridge, script=[_home_ok(), _wporg_ok()])
    _install_probe(monkeypatch)
    _patch_logs(monkeypatch)
    _patch_network(monkeypatch)
    from wpt.cli import main
    report = tmp_path / "doctor.md"
    rc = main(["--source", "ftp://h", "--webroot", "public_html",
               "--wp-url", SITE, "--report", str(report), "doctor"])
    assert rc == 0
    markdown = report.read_text(encoding="utf-8")
    twin = report.with_suffix(".json")
    assert "\\udcff" in markdown
    assert json.loads(twin.read_text(encoding="utf-8"))
    assert "\\udcff" in twin.read_text(encoding="utf-8")


def test_DOCTOR_HSTS_an_https_to_http_downgrade_is_a_warn(
        monkeypatch, tmp_path):
    """P2-DOCTOR-HSTS: allow_redirects followed an HTTPS->HTTP downgrade and
    the HSTS header on the plain-HTTP answer was reported as PASS."""
    redirect = FakeResponse(301)
    redirect.headers = {"Location": "http://127.0.0.1:1/"}
    downgraded = FakeResponse(200)
    downgraded.url = "http://127.0.0.1:1/"
    downgraded.headers = {"Strict-Transport-Security": "max-age=31536000"}
    session = FakeSession([redirect, downgraded])

    row = wpt.doctor._https_policy_check(session, _ftp_ctx(tmp_path))
    assert row["result"] == "WARN"
    assert "DOWNGRADE" in row["detail"]


def test_NEW5_hsts_missing_final_url_is_never_a_pass(tmp_path):
    """Without response.url the final scheme is unproven; the requested
    HTTPS URL must not be substituted and HSTS must not be trusted."""
    redirect = FakeResponse(301)
    redirect.headers = {"Location": "https://site.test/"}
    final = FakeResponse(200)
    final.headers = {"Strict-Transport-Security": "max-age=31536000"}
    assert not hasattr(final, "url")

    row = wpt.doctor._https_policy_check(
        FakeSession([redirect, final]), _ftp_ctx(tmp_path))
    assert row["result"] == "WARN"
    assert "final URL could not be verified" in row["detail"]

    redirect = FakeResponse(301)
    redirect.headers = {"Location": "https://site.test/"}
    verified = FakeResponse(200)
    verified.url = "https://site.test/"
    verified.headers = {"Strict-Transport-Security": "max-age=31536000"}
    row = wpt.doctor._https_policy_check(
        FakeSession([redirect, verified]), _ftp_ctx(tmp_path))
    assert row["result"] == "PASS"
    assert "HSTS max-age=31536000" in row["detail"]


def test_NEW5_uppercase_https_location_is_a_forced_redirect(tmp_path):
    """RFC 3986 schemes are case-insensitive: ``Location: HTTPS://...`` is
    the same forced redirect as lowercase, not "not forced"."""
    redirect = FakeResponse(301)
    redirect.headers = {"Location": "HTTPS://site.test/"}
    verified = FakeResponse(200)
    verified.url = "https://site.test/"
    verified.headers = {"Strict-Transport-Security": "max-age=31536000"}

    row = wpt.doctor._https_policy_check(
        FakeSession([redirect, verified]), _ftp_ctx(tmp_path))

    assert row["result"] == "PASS"
    assert "HTTP redirects to HTTPS://site.test/" in row["detail"]


def test_R11_hsts_from_a_foreign_redirect_origin_is_never_a_pass(
        tmp_path):
    """R11-P2-5: following a redirect to another host and reading THAT
    answer's HSTS reported the site's policy as PASS.  HSTS belongs to the
    configured origin."""
    redirect = FakeResponse(301)
    redirect.headers = {"Location": "https://evil.example/"}
    foreign = FakeResponse(200)
    foreign.url = "https://evil.example/"
    foreign.headers = {"Strict-Transport-Security": "max-age=31536000"}

    row = wpt.doctor._https_policy_check(
        FakeSession([redirect, foreign]), _ftp_ctx(tmp_path))

    assert row["result"] == "WARN"
    assert "different origin" in row["detail"]
    assert "HSTS is not trusted" in row["detail"]


def test_R11_hsts_a_subdomain_redirect_is_a_different_origin(tmp_path):
    """A subdomain is a different HSTS origin even on the same suffix."""
    redirect = FakeResponse(301)
    redirect.headers = {"Location": "https://www.site.test/"}
    subdomain = FakeResponse(200)
    subdomain.url = "https://www.site.test/"
    subdomain.headers = {"Strict-Transport-Security": "max-age=31536000"}

    row = wpt.doctor._https_policy_check(
        FakeSession([redirect, subdomain]), _ftp_ctx(tmp_path))

    assert row["result"] == "WARN"
    assert "different origin" in row["detail"]


def test_R11_hsts_same_origin_on_an_explicit_port_is_a_pass(tmp_path):
    redirect = FakeResponse(301)
    redirect.headers = {"Location": "https://site.test:8443/"}
    final = FakeResponse(200)
    final.url = "https://site.test:8443/"
    final.headers = {"Strict-Transport-Security": "max-age=31536000"}

    row = wpt.doctor._https_policy_check(
        FakeSession([redirect, final]),
        _ftp_ctx(tmp_path, wp_url="https://site.test:8443"))

    assert row["result"] == "PASS"
    assert "HSTS max-age=31536000" in row["detail"]


def test_DOCTOR_DEADLINE_a_slow_last_check_cannot_report_pass(
        monkeypatch, tmp_path):
    """P2-DOCTOR-DEADLINE: _guarded checked only BEFORE a check; a slow final
    wp.org row overran the budget and doctor returned rc 0."""
    import time

    monkeypatch.setattr(
        wpt.doctor, "_disk_check",
        lambda ctx: wpt.doctor._row("disk", "PASS", "enough"))
    monkeypatch.setattr(
        wpt.doctor, "_wporg_check",
        lambda *args, **kwargs: (
            time.sleep(0.08) or wpt.doctor._row("wp.org API", "PASS", "slow")))
    ctx = Ctx(source="local", settings=load(), command="doctor",
              wp_url=SITE, deadline_s=0.05,
              report_path=tmp_path / "doctor.md")

    assert wpt.doctor.run(ctx) == 1
    assert "## This run did not complete" in (
        tmp_path / "doctor.md").read_text(encoding="utf-8")


def test_DOCTOR_HOST_LOG_uses_the_recorded_latest_file(
        monkeypatch, tmp_path):
    """P2-LOGS-LATEST-FILE: the doctor named matches[0].file (scanned first)
    even when a NEWER host candidate supplied the latest match."""
    old = {"file": "error_log", "line": 1, "pattern": "PHP fatal",
           "match": "OLD webroot line"}
    new = {"file": "domains/site/logs/error.log", "line": 1,
           "pattern": "PHP fatal", "match": "NEW host line"}
    bridge = ScriptedBridge(INFO)
    _patch(monkeypatch, bridge, script=[_home_ok(), _wporg_ok()])
    _install_probe(monkeypatch)
    _patch_logs(monkeypatch, scan=SimpleNamespace(
        scanned=2, total_matches=2, files=[], skipped=[],
        matches=[old, new],
        latest_matches={"error_log": old,
                        "domains/site/logs/error.log": new},
        latest_file="domains/site/logs/error.log"))
    _patch_network(monkeypatch)
    ctx = _ftp_ctx(tmp_path)

    assert wpt.doctor.run(ctx) == 0
    _data, rows = _rows(ctx)
    detail = rows["host error log"]["detail"]
    assert "domains/site/logs/error.log:1" in detail
    assert "NEW host line" in detail


# ------------------------------------------------------- triple-check round 6


def test_R6_05_a_preexisting_probe_name_is_never_overwritten_or_deleted(tmp_path):
    """R6-05: the fixed ``.wpt-write-probe`` name overwrote and then deleted
    a site-owned file.  A unique per-run name leaves any pre-existing file
    untouched on PASS and on failure."""
    source = FakeSource()
    source.files[".wpt-write-probe"] = b"SITE OWNED"
    row = wpt.doctor._write_check(source)
    assert row["result"] == wpt.doctor.PASS
    assert source.files[".wpt-write-probe"] == b"SITE OWNED"
    assert not any(name.startswith(wpt.doctor._WRITE_PROBE_PREFIX)
                   for name in source.files)

    class _WriteFails(FakeSource):
        def write_bytes(self, path, data, *, allow_config=False,
                        allow_core=False):
            raise SourceError("550 permission denied")

    failing = _WriteFails()
    failing.files[".wpt-write-probe"] = b"SITE OWNED"
    row = wpt.doctor._write_check(failing)
    assert row["result"] == wpt.doctor.FAIL
    assert failing.files[".wpt-write-probe"] == b"SITE OWNED"


def test_R6_10_lax_session_doubles_are_measured_and_named(monkeypatch,
                                                          tmp_path):
    """R6-10: use_only_cookies=0 / use_trans_sid=1 were reported PASS.
    Present values must WARN and appear in the detail; absent ones stay
    not-measured rather than fabricated as lax."""
    payload = json.loads(json.dumps(PHP_OK))
    payload["session"]["use_only_cookies"] = "0"
    payload["session"]["use_trans_sid"] = "1"
    _install_probe(monkeypatch, payload=payload)
    ctx = _ftp_ctx(tmp_path, report_path=None)

    row = wpt.doctor._php_runtime_check(ctx, FakeSource(), FakeSession(), True)

    assert row["result"] == wpt.doctor.WARN
    assert "only_cookies=0" in row["detail"]
    assert "trans_sid=1" in row["detail"]

    # absent doubles are not measured: the strict-only payload still PASSes
    _install_probe(monkeypatch, payload=PHP_OK)
    row = wpt.doctor._php_runtime_check(ctx, FakeSource(), FakeSession(), True)
    assert row["result"] == wpt.doctor.PASS
    assert "only_cookies" not in row["detail"]
    assert "trans_sid" not in row["detail"]


def test_R6_40_present_but_empty_session_ini_is_measured_lax(monkeypatch,
                                                              tmp_path):
    """R6-40: PHP reports a present directive set to ``""`` (bool false,
    i.e. lax) as ``string(0) ""``; treating it as absent hid the risk."""
    assert wpt.doctor._measured_ini_flag("") == "0"
    assert wpt.doctor._measured_ini_flag(None) is None
    assert wpt.doctor._measured_ini_flag(False) is None

    payload = json.loads(json.dumps(PHP_OK))
    payload["session"]["use_only_cookies"] = ""
    payload["session"]["use_trans_sid"] = ""
    _install_probe(monkeypatch, payload=payload)
    ctx = _ftp_ctx(tmp_path, report_path=None)

    row = wpt.doctor._php_runtime_check(ctx, FakeSource(), FakeSession(), True)

    assert row["result"] == wpt.doctor.WARN
    assert "only_cookies=0" in row["detail"]
    assert "trans_sid=0" in row["detail"]


def test_N2_module_doc_describes_the_unique_per_run_probe():
    """N2: the module doc still said the write probe was DETERMINISTIC
    (the fixed name R6-05 removed).  The doc must name the unique shape the
    code actually generates."""
    doc = wpt.doctor.__doc__ or ""
    assert "one deterministic" not in doc
    assert ".wpt-write-probe-<16hex>" in doc


def test_R6_41_the_sweep_matches_the_probe_name_this_code_generates():
    """R6-41: the owner pattern accepted 8 hex while ``_write_check``
    generates ``token_hex(8)`` = 16 hex, so a killed run's probe could
    never be swept."""
    import secrets
    import time

    from tests.fakes import FakeSource

    name = f"{wpt.doctor._WRITE_PROBE_PREFIX}{secrets.token_hex(8)}"
    assert wpt.doctor._WRITE_PROBE_RE.match(name)
    legacy = f"{wpt.doctor._WRITE_PROBE_PREFIX}{'a' * 8}"
    assert not wpt.doctor._WRITE_PROBE_RE.match(legacy)

    class _OldProbeSource(FakeSource):
        def list_dir(self, path):
            entries = super().list_dir(path)
            for entry in entries:
                entry.mtime = time.time() - 3600
            return entries

    source = _OldProbeSource()
    source.files[name] = b"left by a killed run"
    source.files[legacy] = b"never ours"
    wpt.doctor._sweep_write_probes(source, ttl_minutes=15)
    assert name not in source.files       # real generated shape swept
    assert legacy in source.files         # a test-only 8-hex name never is


# ------------------------------------------------- triple-check round 7


def test_R7_P2_09_a_teardown_stop_never_replaces_the_primary_failure(
        monkeypatch, tmp_path):
    """R7-P2-09: the panel's ``finally`` raised a close-time stop over the
    deadline/failure already propagating."""
    source = FakeSource()
    source.files.update(WEBROOT)

    def stop_close():
        raise StopRequested("SIGTERM during close")

    source.close = stop_close
    session = FakeSession([_home_ok(), _wporg_ok()])
    bridge = ScriptedBridge(INFO)
    monkeypatch.setattr(wpt.doctor, "remote_stack",
                        lambda ctx: (source, session, bridge))
    _install_probe(monkeypatch)
    _patch_logs(monkeypatch)
    _patch_network(monkeypatch)

    def primary(*args, **kwargs):
        raise DeadlineExceeded("PRIMARY-DEADLINE")

    monkeypatch.setattr(wpt.doctor, "_layout_check", primary)
    ctx = _ftp_ctx(tmp_path)
    with pytest.raises(DeadlineExceeded, match="PRIMARY-DEADLINE"):
        wpt.doctor._ftp_panel(ctx, wpt.doctor.Deadline.from_ctx(ctx))


@pytest.mark.parametrize("error, raises", [
    (RuntimeError("close blew up"), False),
    (StopRequested("SIGTERM during close"), True),
])
def test_R7_P2_10_local_and_fallback_session_close_is_guarded(
        monkeypatch, tmp_path, error, raises):
    """R7-P2-10: ``_local_panel`` and the ftp fallback closed their own
    session raw, so a RuntimeError escaped a PASS panel and a stop could
    mask it.  One best-effort helper warns generic errors, re-raises stops."""
    class _Session:
        def close(self):
            raise error

    monkeypatch.setattr(wpt.doctor.requests, "Session", lambda: _Session())
    monkeypatch.setattr(
        wpt.doctor, "_wporg_check",
        lambda *args, **kwargs: {"name": "wp.org API", "result": "PASS",
                                 "detail": "ok"})
    ctx = _ftp_ctx(tmp_path)
    if raises:
        with pytest.raises(StopRequested):
            wpt.doctor._local_panel(ctx)
    else:
        checks = wpt.doctor._local_panel(ctx)
        assert checks[0]["name"] == "disk"

    # The ftp panel's stack-down fallback session goes through the same
    # helper: generic error warns, stop propagates.
    source = FakeSource()
    source.files.update(WEBROOT)
    bridge = ScriptedBridge(INFO)
    monkeypatch.setattr(wpt.doctor, "remote_stack",
                        lambda ctx: (source, None, bridge))
    _install_probe(monkeypatch)
    _patch_logs(monkeypatch)
    _patch_network(monkeypatch)
    if raises:
        with pytest.raises(StopRequested):
            wpt.doctor._ftp_panel(ctx, wpt.doctor.Deadline.from_ctx(ctx))
    else:
        wpt.doctor._ftp_panel(ctx, wpt.doctor.Deadline.from_ctx(ctx))
        assert bridge.destroyed == 1


@pytest.mark.parametrize("hsts", [
    "max-age=0",
    "max-age=-1",
    "max-age=abc",
    "max-age",
    "includeSubDomains",
    # RFC 6797 §6.1.1: every directive appears once; a non-conforming
    # header is ignored by the UA, so it can never be a doctor PASS.
    "max-age=abc; max-age=31536000",
    "max-age=31536000; max-age=86400",
    "max-age=31536000; includeSubDomains; includeSubDomains",
    "max-age=31536000; includeSubDomains=1",
    "max-age=31536000; max-age=86400; includeSubDomains",
    # RFC 6797 §6.1 directive-value = token | quoted-string: an empty,
    # unterminated-quoted, non-token or space-bearing extension value makes
    # the whole header non-conforming (the UA ignores it).
    'max-age=31536000; x=',
    'max-age=31536000; x="unterminated',
    'max-age=31536000; x=@',
    'max-age=31536000; x=a b',
    # Duplicate names are non-conforming regardless of the directive.
    'max-age=31536000; x=1; X=2',
])
def test_R7_P2_11_hsts_zero_or_invalid_max_age_is_warn(tmp_path, hsts):
    """R7-P2-11 + residual: any non-empty HSTS header was a PASS, including
    ``max-age=0`` (RFC 6797: disables HSTS), invalid values, and duplicate
    directives — a conformant UA ignores the whole header."""
    redirect = FakeResponse(301)
    redirect.headers = {"Location": "https://site.test/"}
    final = FakeResponse(200)
    final.url = "https://site.test/"
    final.headers = {"Strict-Transport-Security": hsts}
    row = wpt.doctor._https_policy_check(
        FakeSession([redirect, final]), _ftp_ctx(tmp_path))
    assert row["result"] == "WARN"
    assert hsts in row["detail"]


@pytest.mark.parametrize("hsts", [
    "max-age=31536000",
    "max-age=31536000; includeSubDomains",
    "max-age = 86400",
    "max-age=\"31536000\"",
    "max-age=31536000; preload",
    # A semicolon inside a quoted-string is qdtext, not a separator; the
    # whole header stays conforming.
    'max-age=31536000; x="a;b"',
    'max-age=31536000; x="a\\";b"; includeSubDomains',
    'max-age=31536000; x=token; y=other',
])
def test_R7_P2_11_hsts_positive_max_age_still_passes(tmp_path, hsts):
    redirect = FakeResponse(301)
    redirect.headers = {"Location": "https://site.test/"}
    final = FakeResponse(200)
    final.url = "https://site.test/"
    final.headers = {"Strict-Transport-Security": hsts}
    row = wpt.doctor._https_policy_check(
        FakeSession([redirect, final]), _ftp_ctx(tmp_path))
    assert row["result"] == "PASS"


def test_R21_wporg_per_request_timeout_is_warn_but_a_spent_run_is_a_stop(
        monkeypatch):
    """R21-P1: doctor passes the RUN budget to WpOrgApi; a per-request
    timeout is the documented WARN row, while a spent run raises through
    the panel (never a green table after the budget)."""
    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    seen = {}

    class _Api:
        def __init__(self, session, timeout_s, deadline=None, **kwargs):
            seen["deadline"] = deadline

        def latest_core_version(self):
            return None

    monkeypatch.setattr(wpt.doctor, "WpOrgApi", _Api)
    deadline = Deadline(10)
    row = wpt.doctor._wporg_check(object(), 5, deadline)
    assert row["result"] == "WARN"
    assert seen["deadline"] == deadline.at

    class _Stopped(_Api):
        def latest_core_version(self):
            raise DeadlineExceeded("run budget spent")

    monkeypatch.setattr(wpt.doctor, "WpOrgApi", _Stopped)
    with pytest.raises(DeadlineExceeded):
        wpt.doctor._wporg_check(object(), 5, deadline)


def test_R24_tls_attempt_share_covers_dial_and_handshake(monkeypatch):
    """R24-P2: doctor computed ``share`` for the dial, then a FRESH
    ``now + share`` for the handshake, so one address could spend two shares
    and overrun the absolute run budget.  The attempt deadline is computed
    before the dial and reused by both."""
    clock = [1000.0]
    dials = []
    wraps = []

    class FakeTLS:
        def getpeercert(self):
            return {"subject": (("commonName", "site.test"),)}

        def close(self):
            pass

    class FakeSock(FakeTLS):
        pass

    def fake_dial(address, port, timeout):
        dials.append((address, timeout))
        clock[0] += 0.2
        return FakeSock()

    def fake_wrap(sock, host, context, budget):
        wraps.append(budget)
        if len(wraps) == 1:
            clock[0] += 0.2
            raise OSError("peer closed during the handshake")
        return FakeTLS()

    monkeypatch.setattr(wpt.doctor, "_resolve_host_bounded",
                        lambda host, port, budget:
                        ["127.0.0.2", "127.0.0.1"])
    monkeypatch.setattr(wpt.doctor.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(wpt.doctor, "_dial_numeric", fake_dial)
    monkeypatch.setattr(wpt.doctor, "_tls_wrap_bounded", fake_wrap)
    cert = wpt.doctor._tls_peer_cert(
        "site.test", "site.test", 443, 5, verify=True, deadline=1000.6)
    assert cert.get("subject") == (("commonName", "site.test"),)
    assert dials[0][0] == "127.0.0.2"
    assert wraps[0] == 1000.3      # computed BEFORE the 0.2 s dial
    assert dials[1][0] == "127.0.0.1"
    assert wraps[1] == 1000.6      # the rest of the run budget
