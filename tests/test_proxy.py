"""Behavioral tests for wpt.proxy — the ``wpt proxy`` command body.

The engine (``wpt.dnsoverride.ProxyServer``) is tested against a real
local TLS server in tests/test_dnsoverride.py; this file covers only
what the command body owns: the CLI-shaped argument pass-through, the
blocking order (bind → receipt → serve), the rc contract, and
``--report`` — the run receipt that made ``--report`` true for every
command (SPEC) instead of silently accepted and ignored here.

A fake engine stands in for ``dnsoverride.ProxyServer`` (no cert, no
socket, no signal handler): the command body must not grow a second
engine, so the double records the constructor arguments, the start/serve/
stop order and the bound port, and the real engine stays covered by
tests/test_dnsoverride.py.

Test -> behavior map:
  test_proxy_passes_the_cli_flags_to_the_engine_unchanged ... the four
        CLI flags reach ProxyServer as keywords, and serve() blocks
        AFTER the receipt is written
  test_proxy_writes_a_run_receipt ................ the file exists, names
        the command / the site hostname / the upstream / the loopback
        URL, carries its JSON twin, and never a credential
  test_proxy_refuses_an_unwritable_report ........ a report path that
        cannot be written is rc 1 and the listener is stopped
  test_proxy_never_writes_a_report_without_a_path  no --report: nothing
        is written and the run is still rc 0
  test_proxy_refuses_without_its_engine ........... the ImportError
        fallback the CLI used to own: rc 2, the listener never built
  test_the_cli_dispatches_proxy_to_the_command_body  end to end through
        the real dispatcher: --report reaches the body, the file lands,
        and the CLI's own credential never reaches it
  test_proxy_refuses_a_listener_it_could_not_bind . a bind/cert failure
        is one logged error and rc 1 (never a traceback), and no receipt
        is written for a listener that never existed
  test_proxy_module_keeps_both_of_its_dependencies_deferred  neither the
        CLI nor the engine is imported at module scope
"""

import json
import logging
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

import wpt.proxy
from wpt.cli import Ctx
from wpt.settings import load

HOSTNAME = "local.test"
UPSTREAM_IP = "203.0.113.7"


class _FakeEngine:
    """A non-blocking ProxyServer double: records the constructor
    keywords and the start -> serve -> stop order, and reports a bound
    port the way the real one does (the receipt needs the real port)."""

    instances: list["_FakeEngine"] = []

    def __init__(self, hostname, ip, *, port=8443, upstream_port=443,
                 cert_dir=None, timeout=30.0, max_body_bytes=None,
                 max_request_bytes=None, cert_timeout_s=None,
                 cert_validity_days=None, cert_renew_before_s=None):
        self.hostname = hostname
        self.ip = ip
        self.port = port
        self.cert_dir = cert_dir
        self.max_body_bytes = max_body_bytes
        self.max_request_bytes = max_request_bytes
        self.cert_timeout_s = cert_timeout_s
        self.cert_validity_days = cert_validity_days
        self.cert_renew_before_s = cert_renew_before_s
        self.order: list[str] = []
        type(self).instances.append(self)

    def start(self):
        self.order.append("start")
        return 8123          # the bound port, never the requested one

    def browser_url(self):
        return "https://localhost:8123/"

    def serve(self):
        self.order.append("serve")

    def stop(self):
        self.order.append("stop")


@pytest.fixture()
def engine(monkeypatch):
    """Install the fake engine as ``dnsoverride.ProxyServer`` and hand
    back the class, so a test can read what the command body built."""
    import wpt.dnsoverride

    _FakeEngine.instances = []
    monkeypatch.setattr(wpt.dnsoverride, "ProxyServer", _FakeEngine)
    return _FakeEngine


def _ctx(tmp_path, **overrides):
    kwargs = dict(source="ftp://host", settings=load(), extra={})
    kwargs.update(overrides)
    return Ctx(**kwargs)


def test_proxy_passes_the_cli_flags_to_the_engine_unchanged(engine, tmp_path):
    """The four CLI flags (``--hostname/--ip/--port/--cert-dir``) reach
    the engine as keywords — the command body translates, never rewrites
    — and the blocking ``serve()`` happens AFTER the bind, which is what
    lets the receipt name the real port."""
    ctx = _ctx(tmp_path)
    assert wpt.proxy.run_proxy(ctx, hostname=HOSTNAME, ip=UPSTREAM_IP,
                               port=9443, cert_dir=tmp_path / ".wpt-cert") == 0
    (built,) = engine.instances
    assert (built.hostname, built.ip, built.port) == (HOSTNAME, UPSTREAM_IP,
                                                      9443)
    assert built.cert_dir == tmp_path / ".wpt-cert"
    assert built.order == ["start", "serve", "stop"]


def test_proxy_writes_a_run_receipt(engine, tmp_path):
    """``--report`` is honoured by EVERY command (SPEC), and the proxy
    swallowed it: a caller could not tell from the filesystem that a
    proxy run had happened.  A run with no plan records WHAT RAN — the
    command, the site hostname, the upstream, the loopback URL the
    browser talks to — plus the JSON twin every other surface writes.
    The BOUND port is the one in the file, not the requested one."""
    report = tmp_path / "proxy.md"
    ctx = _ctx(tmp_path, report_path=report, user="u", password="s3cr3t")

    assert wpt.proxy.run_proxy(ctx, hostname=HOSTNAME, ip=UPSTREAM_IP,
                               port=9443) == 0
    assert report.exists()
    markdown = report.read_text(encoding="utf-8")
    assert markdown.startswith("# wpt proxy")
    assert "- command: proxy" in markdown
    assert f"- site hostname: {HOSTNAME} (SNI and Host presented upstream)" \
        in markdown
    assert f"- upstream: {UPSTREAM_IP}:443" in markdown
    assert "- url: https://localhost:8123/" in markdown   # the BOUND port
    assert "- bind: 127.0.0.1:8123" in markdown
    assert "https://127.0.0.1:9443/" not in markdown      # not the request
    twin = json.loads(report.with_suffix(".json").read_text(encoding="utf-8"))
    assert twin["command"] == "proxy"
    assert twin["url"] == "https://localhost:8123/"
    assert twin["upstream"] == f"{UPSTREAM_IP}:443"
    # never a credential: no password, no key, no certificate path — the
    # three things the operator typed and the bound port are all it holds
    assert "s3cr3t" not in markdown
    assert "s3cr3t" not in json.dumps(twin)
    assert ".wpt-cert" not in markdown
    assert "key" not in json.dumps(twin).lower()
    (built,) = engine.instances
    assert built.order == ["start", "serve", "stop"]  # receipt, then serve


def test_proxy_refuses_an_unwritable_report(engine, tmp_path):
    """A report path that cannot be written is a FAILED run, and the
    listener is stopped in the same breath: a receipt that promised a
    proxy nobody can reach is worse than none."""
    blocked = tmp_path / "proxy.md"
    blocked.mkdir()
    ctx = _ctx(tmp_path, report_path=blocked)

    assert wpt.proxy.run_proxy(ctx, hostname=HOSTNAME,
                               ip=UPSTREAM_IP) == 1
    (built,) = engine.instances
    assert built.order == ["start", "stop"]       # never entered serve()


def test_proxy_never_writes_a_report_without_a_path(engine, tmp_path):
    """No --report: the run is unchanged (the receipt is a no-op) and
    still rc 0 — the flag adds a file, it never becomes a requirement."""
    ctx = _ctx(tmp_path)
    assert wpt.proxy.run_proxy(ctx, hostname=HOSTNAME, ip=UPSTREAM_IP) == 0
    assert list(tmp_path.iterdir()) == []


def test_proxy_refuses_without_its_engine(monkeypatch, tmp_path):
    """The engine import is DEFERRED, so a missing/incomplete
    ``wpt.dnsoverride`` is this command's refusal (rc 2, the CLI's own
    message) instead of an ImportError anywhere up the stack.  ``None``
    in ``sys.modules`` is CPython's own "this import is halted" sentinel,
    so the deferred ``from . import dnsoverride`` raises ImportError here
    for the same reason it would with the engine uninstalled."""
    import wpt

    monkeypatch.delattr(wpt, "dnsoverride", raising=False)
    monkeypatch.setitem(sys.modules, "wpt.dnsoverride", None)
    assert wpt.proxy.run_proxy(_ctx(tmp_path), hostname=HOSTNAME,
                               ip=UPSTREAM_IP) == 2


def test_proxy_module_keeps_both_of_its_dependencies_deferred():
    """The command body is imported by the dispatcher, so it must not
    import the CLI or the engine at module scope: the CLI annotation is
    TYPE_CHECKING-only (the serve.py/walk.py convention) and the engine
    import happens inside ``run_proxy``, where its absence is a refusal
    (rc 2) rather than an ImportError up the stack.  Asserted on the
    module's own namespace, which is what a module-scope import would
    leave behind."""
    assert not hasattr(wpt.proxy, "dnsoverride")
    assert not hasattr(wpt.proxy, "Ctx")


def test_the_cli_dispatches_proxy_to_the_command_body(engine, tmp_path,
                                                      monkeypatch):
    """END TO END through the real dispatcher: ``wpt ... proxy --report
    out.md`` reaches the command body with the Ctx's report path, writes
    the file and returns its rc.  This is the property the SPEC states
    ("--report is honoured by EVERY command") — it used to hold for
    nothing here, because the dispatcher called the engine directly and
    the flag died in the argument list."""
    from wpt.cli import main

    monkeypatch.setenv("WPT_PROXY_TEST_PASSWORD", "hunter2")
    report = tmp_path / "cli-proxy.md"
    rc = main([
        "--source", "ftp://h", "--user", "u",
        "--password-env", "WPT_PROXY_TEST_PASSWORD",
        "--webroot", "domains/x/public_html", "--wp-url", "https://x",
        "--report", str(report), "proxy",
        "--hostname", HOSTNAME, "--ip", UPSTREAM_IP, "--port", "9443",
    ])
    assert rc == 0
    assert report.exists()
    markdown = report.read_text(encoding="utf-8")
    assert "- command: proxy" in markdown
    # the CLI's own credential never reaches the report (SPEC secrets rule)
    assert "hunter2" not in markdown
    (built,) = engine.instances
    assert (built.hostname, built.ip, built.port) == (HOSTNAME, UPSTREAM_IP,
                                                      9443)


def test_proxy_refuses_a_listener_it_could_not_bind(monkeypatch, tmp_path,
                                                    wpt_records):
    """The command body keeps the never-raises contract the other command
    bodies keep: a bind/cert failure (no openssl, a taken port) is one
    logged error and rc 1 — never a traceback out of the dispatcher — and
    the shared failure pair is written for a listener that never existed
    (never the success receipt)."""
    import wpt

    class _Refusing(_FakeEngine):
        def start(self):
            raise OSError("[Errno 98] Address already in use")

    monkeypatch.setattr(wpt.dnsoverride, "ProxyServer", _Refusing)
    report = tmp_path / "proxy.md"
    ctx = _ctx(tmp_path, report_path=report)

    assert wpt.proxy.run_proxy(ctx, hostname=HOSTNAME, ip=UPSTREAM_IP) == 1
    written = report.read_text(encoding="utf-8")
    assert "## This run did not complete" in written
    assert "- command: proxy" not in written
    twin = report.with_suffix(".json").read_text(encoding="utf-8")
    assert '"status": "failed"' in twin
    errors = [r.getMessage() for r in wpt_records
              if r.name == "wpt.proxy" and r.levelno >= logging.ERROR]
    assert errors == ["proxy failed: [Errno 98] Address already in use"]


@pytest.mark.parametrize("port", [-1, 65536, 99999])
def test_proxy_refuses_an_out_of_range_port_before_the_engine(
        engine, tmp_path, wpt_records, port):
    """P2-PROXY-PORT: socket.bind raised OverflowError (NOT OSError), so a
    typo'd port escaped as a traceback.  The flag boundary refuses it with
    one logged line, rc 1, before any listener object exists."""
    report = tmp_path / "proxy.md"
    ctx = _ctx(tmp_path, report_path=report)

    assert wpt.proxy.run_proxy(
        ctx, hostname=HOSTNAME, ip=UPSTREAM_IP, port=port) == 1
    assert engine.instances == []
    assert "## This run did not complete" in report.read_text(encoding="utf-8")
    errors = [r.getMessage() for r in wpt_records
              if r.name == "wpt.proxy" and r.levelno >= logging.ERROR]
    assert errors == [
        "proxy failed: --port must be an integer between 0 and 65535 "
        f"(got {port})"
    ]


def test_proxy_a_stop_between_start_and_serve_still_stops(
        engine, tmp_path):
    """P2-PROXY-STOP: the receipt write sits between start() and serve();
    a cooperative stop raised there used to escape with the listener bound.
    The lifetime finally stops it and the run answers rc 1."""
    from wpt.types import StopRequested

    def stop(*args, **kwargs):
        raise StopRequested("SIGTERM during the receipt")

    import wpt.proxy as proxy_mod
    original = proxy_mod._write_receipt
    proxy_mod._write_receipt = stop
    try:
        assert wpt.proxy.run_proxy(_ctx(tmp_path), hostname=HOSTNAME,
                                   ip=UPSTREAM_IP) == 1
    finally:
        proxy_mod._write_receipt = original
    (built,) = engine.instances
    assert built.order == ["start", "stop"]


def test_the_real_cli_refuses_an_out_of_range_port_without_a_traceback(
        tmp_path, capsys):
    """The agent's proof was the REAL dispatcher: port 99999 reached
    socket.bind and printed an OverflowError traceback.  The flag boundary
    answers rc 1 before the engine exists."""
    from wpt.cli import main

    report = tmp_path / "cli-port.md"
    rc = main([
        "proxy", "--hostname", HOSTNAME, "--ip", UPSTREAM_IP,
        "--port", "99999", "--report", str(report),
    ])

    assert rc == 1
    assert "## This run did not complete" in report.read_text(encoding="utf-8")
    assert report.with_suffix(".json").is_file()
    err = capsys.readouterr().err
    assert "OverflowError" not in err
    assert ("--port must be an integer between 0 and 65535 (got 99999)"
            in err)


# ------------------------------------------------------- triple-check round 6


def test_R6_07_a_failing_stop_never_escapes_run_proxy(monkeypatch, tmp_path,
                                                     wpt_records):
    """R6-07: server.stop() in the start-failure branch and in ``finally``
    was unguarded; an OSError there escaped as a traceback instead of rc 1.
    One best-effort helper keeps the original verdict and logs one line."""
    import wpt.dnsoverride

    class _StartAndStopFail(_FakeEngine):
        def start(self):
            raise OSError("bind failed")

        def stop(self):
            raise OSError("shutdown failed")

    monkeypatch.setattr(wpt.dnsoverride, "ProxyServer", _StartAndStopFail)
    assert wpt.proxy.run_proxy(_ctx(tmp_path), hostname=HOSTNAME,
                               ip=UPSTREAM_IP) == 1
    errors = [r.getMessage() for r in wpt_records
              if r.name == "wpt.proxy" and r.levelno >= logging.ERROR]
    assert errors == ["proxy failed: bind failed"]
    warnings = [r.getMessage() for r in wpt_records
                if r.name == "wpt.proxy" and r.levelno == logging.WARNING]
    assert any("listener stop failed" in message for message in warnings)

    class _OnlyStopFails(_FakeEngine):
        def stop(self):
            raise OSError("shutdown failed")

    monkeypatch.setattr(wpt.dnsoverride, "ProxyServer", _OnlyStopFails)
    # the clean serve() path keeps rc 0; the teardown failure is a warning
    assert wpt.proxy.run_proxy(_ctx(tmp_path), hostname=HOSTNAME,
                               ip=UPSTREAM_IP) == 0


def test_R12_construction_and_start_share_the_one_lifetime(monkeypatch,
                                                            tmp_path):
    """R12-P2-1: start/cert failures escaped the try/finally (a
    KeyboardInterrupt exited 130 with no report pair; a RunControl after a
    bound listener left it running).  One finally stops every path."""
    from wpt.types import StopRequested

    class _InterruptStart(_FakeEngine):
        def start(self):
            self.order.append("start")
            raise KeyboardInterrupt

    _InterruptStart.instances = []
    monkeypatch.setattr(wpt.dnsoverride, "ProxyServer", _InterruptStart)
    report = tmp_path / "interrupt.md"
    ctx = _ctx(tmp_path, report_path=report)
    assert wpt.proxy.run_proxy(ctx, hostname=HOSTNAME,
                               ip=UPSTREAM_IP) == 1
    (built,) = _InterruptStart.instances
    assert built.order == ["start", "stop"]
    assert "did not complete" in report.read_text(encoding="utf-8")
    assert report.with_suffix(".json").is_file()

    class _StopStart(_FakeEngine):
        def start(self):
            self.order.append("start")
            raise StopRequested("SIGTERM during cert generation")

    _StopStart.instances = []
    monkeypatch.setattr(wpt.dnsoverride, "ProxyServer", _StopStart)
    stop_report = tmp_path / "stop.md"
    ctx = _ctx(tmp_path, report_path=stop_report)
    assert wpt.proxy.run_proxy(ctx, hostname=HOSTNAME,
                               ip=UPSTREAM_IP) == 1
    (built,) = _StopStart.instances
    assert built.order == ["start", "stop"]
    assert "SIGTERM during cert generation" in stop_report.read_text(
        encoding="utf-8")

    class _InterruptConstruct:
        def __init__(self, *_args, **_kwargs):
            raise KeyboardInterrupt

    monkeypatch.setattr(wpt.dnsoverride, "ProxyServer", _InterruptConstruct)
    construct_report = tmp_path / "construct.md"
    ctx = _ctx(tmp_path, report_path=construct_report)
    assert wpt.proxy.run_proxy(ctx, hostname=HOSTNAME,
                               ip=UPSTREAM_IP) == 1
    assert "did not complete" in construct_report.read_text(encoding="utf-8")


@pytest.mark.parametrize("name", ["cert.pem", "key.pem"])
def test_R13_proxy_refuses_a_report_that_would_replace_cert_or_key(
        engine, tmp_path, name):
    """R13-P2-13: ``--report`` was written after start(), and the cert/key
    paths were not in the protected set, so ``--report .../cert.pem``
    replaced the TLS material the listener reads (rc 0).  The resolved pair
    is recorded as an input, refused BEFORE the receipt, and the failure
    pair is NOT written on the colliding path either."""
    cert_dir = tmp_path / ".wpt-cert"
    cert_dir.mkdir()
    cert_path = cert_dir / "cert.pem"
    key_path = cert_dir / "key.pem"
    cert_path.write_bytes(b"CERT-BYTES")
    key_path.write_bytes(b"KEY-BYTES")
    target = cert_dir / name
    original = target.read_bytes()

    ctx = _ctx(tmp_path, report_path=target)
    assert wpt.proxy.run_proxy(ctx, hostname=HOSTNAME, ip=UPSTREAM_IP,
                               port=9443, cert_dir=cert_dir) == 1
    assert target.read_bytes() == original
    assert engine.instances == []           # refused before the listener
    assert ctx.extra["cert_path"] == cert_path.resolve()
    assert ctx.extra["key_path"] == key_path.resolve()
    assert not target.with_suffix(".json").exists()


def test_R13_proxy_stop_stoprequested_is_a_warning_not_a_traceback(
        engine, tmp_path, monkeypatch):
    """R13-P2-14: teardown caught only ``Exception``; ``StopRequested`` is a
    ``BaseException``, so a STOP landing during ``stop()`` escaped
    ``run_proxy`` (which promises never to raise).  It is now one warning
    and the clean verdict is preserved."""
    from wpt.types import StopRequested

    class _StopRaises(_FakeEngine):
        def stop(self):
            raise StopRequested("SIGTERM during proxy stop")

    monkeypatch.setattr("wpt.dnsoverride.ProxyServer", _StopRaises)
    ctx = _ctx(tmp_path)
    assert wpt.proxy.run_proxy(ctx, hostname=HOSTNAME, ip=UPSTREAM_IP,
                               port=9443, cert_dir=tmp_path / ".wpt-cert") == 0


def test_R13_proxy_teardown_survives_ctrl_c(engine, tmp_path, monkeypatch):
    """Ctrl-C in the same teardown window is a warning too, never a raise."""
    class _Interrupts(_FakeEngine):
        def stop(self):
            raise KeyboardInterrupt()

    monkeypatch.setattr("wpt.dnsoverride.ProxyServer", _Interrupts)
    ctx = _ctx(tmp_path)
    assert wpt.proxy.run_proxy(ctx, hostname=HOSTNAME, ip=UPSTREAM_IP,
                               port=9443, cert_dir=tmp_path / ".wpt-cert") == 0


@pytest.mark.parametrize("case", ["port", "deadline", "nan", "set"])
@pytest.mark.parametrize("name", ["cert.pem", "key.pem"])
def test_R14_early_proxy_refusals_never_overwrite_the_tls_pair(
        tmp_path, case, name):
    """R14-P1-1: ``coerce_port``/``--deadline``/``--set`` refusals ran
    BEFORE cert/key resolution, so ``--report <cert-dir>/cert.pem`` (or the
    key) replaced the TLS material and wrote its twin.  Both CLI builders
    now resolve the pair into the protected set before any refusal."""
    from wpt.cli import main

    cert_dir = tmp_path / ".wpt-cert"
    cert_dir.mkdir()
    cert_bytes = b"-----BEGIN CERTIFICATE-----\nCERTBYTES\n"
    key_bytes = b"-----BEGIN TEST KEY-----\nKEYBYTES\n"
    (cert_dir / "cert.pem").write_bytes(cert_bytes)
    (cert_dir / "key.pem").write_bytes(key_bytes)
    target = cert_dir / name
    argv = [
        "proxy", "--hostname", HOSTNAME, "--ip", UPSTREAM_IP,
        "--cert-dir", str(cert_dir), "--report", str(target),
    ]
    if case == "port":
        argv += ["--port", "99999"]
    elif case == "deadline":
        argv += ["--deadline", "-1"]
    elif case == "nan":
        argv += ["--deadline", "nan"]
    else:
        argv += ["--set", "bogus.key=1"]

    assert main(argv) == 1
    assert (cert_dir / "cert.pem").read_bytes() == cert_bytes
    assert (cert_dir / "key.pem").read_bytes() == key_bytes
    # the refusal pair never lands on the input OR its twin
    assert not target.with_suffix(".json").exists()
    assert not (cert_dir / "cert.json").exists()
    assert not (cert_dir / "key.json").exists()


@pytest.mark.parametrize("name", ["cert.pem", "key.pem"])
def test_R14_sigterm_before_the_body_never_overwrites_the_tls_pair(
        tmp_path, monkeypatch, name):
    """The minimal pre-dispatch Ctx builder protects the pair too: a
    SIGTERM answered before the command body still writes no refusal pair
    over the certificate/key it would have read."""
    import wpt.cli as cli_mod
    from wpt.types import StopRequested

    cert_dir = tmp_path / ".wpt-cert"
    cert_dir.mkdir()
    cert_bytes = b"CERT-ORIGINAL\n"
    key_bytes = b"KEY-ORIGINAL\n"
    (cert_dir / "cert.pem").write_bytes(cert_bytes)
    (cert_dir / "key.pem").write_bytes(key_bytes)
    target = cert_dir / name

    def _stop(_args):
        raise StopRequested("received SIGTERM (15)")

    monkeypatch.setattr(cli_mod, "_main_after_handler", _stop)
    rc = cli_mod.main([
        "proxy", "--hostname", HOSTNAME, "--ip", UPSTREAM_IP,
        "--cert-dir", str(cert_dir), "--report", str(target),
    ])
    assert rc == 1
    assert (cert_dir / "cert.pem").read_bytes() == cert_bytes
    assert (cert_dir / "key.pem").read_bytes() == key_bytes
    assert not target.with_suffix(".json").exists()


@pytest.mark.skipif(
    __import__("shutil").which("openssl") is None,
    reason="the proxy certificate needs openssl",
)
def test_R23_real_cli_sigterm_is_rc1_with_a_failure_pair(tmp_path):
    """R23-P2: ``ProxyServer.serve`` installed its OWN SIGTERM handler that
    only set an event, shadowing the CLI's StopRequested handler: a real
    SIGTERM ended rc 0 with a success receipt beside a stopped listener,
    while ``serve`` under the same signal is rc 1 + failure pair.  Only
    SIGINT is shadowed now."""
    root = Path(__file__).resolve().parents[1]
    report = tmp_path / "proxy.md"
    cert_dir = tmp_path / ".wpt-cert"
    # Isolate the SIGTERM contract from cold openssl/entropy startup: the
    # child reuses this pair and reaches bind+receipt promptly on macOS.
    from wpt.dnsoverride import ensure_cert

    ensure_cert(cert_dir)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root)
    proc = subprocess.Popen(
        [sys.executable, "-c",
         "import sys; from wpt.cli import main; sys.exit(main())",
         "--report", str(report),
         "proxy", "--hostname", "local.test", "--ip", "127.0.0.1",
         "--port", "0", "--cert-dir", str(cert_dir)],
        cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 30
        while (not report.exists() and proc.poll() is None
               and time.monotonic() < deadline):
            time.sleep(0.05)
        if not report.exists():
            # Capture the child's own refusal before cleanup; a bare
            # "never wrote" hides whether cert generation, bind, or the
            # report writer blocked.
            proc.terminate()
            try:
                out, err = proc.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, err = proc.communicate()
            raise AssertionError(
                "proxy never wrote its receipt\n"
                f"stdout={out[-2000:]!r}\nstderr={err[-4000:]!r}")
        proc.send_signal(signal.SIGTERM)
        _out, err = proc.communicate(timeout=15)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
    assert proc.returncode == 1, err
    markdown = report.read_text(encoding="utf-8")
    assert markdown.startswith("# wpt proxy — ")
    assert "## This run did not complete" in markdown
    twin = json.loads(report.with_suffix(".json").read_text(encoding="utf-8"))
    assert twin["run"]["status"] == "failed"
    assert "SIGTERM" in twin["run"]["reason"]
