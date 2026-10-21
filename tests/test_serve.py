"""Behavioral tests for wpt.serve — the offline rehearsal HTTP server.

A REAL ``wpt.serve.build_server`` on 127.0.0.1:0 (``serve_forever`` in a
daemon thread, shutdown in the fixture — the tests/test_walk.py
convention) serves tiny zips built in ``tmp_path``, shaped like the real
host-export twin: every member nested under ``"site.test/"`` WITH the root
dir entry, so ZipSource's root auto-detect is exercised by EVERY test.
Requests ride urllib with the proxy handler disabled (the env-proxy
hijack guard, urllib flavor of test_walk's trust_env=False session);
only 127.0.0.1 sockets are ever opened.  The run_serve contract tests
drive ``run_serve(ctx)`` with real Ctx objects the way the CLI's
``_lazy_call`` will, monkeypatching ``wpt.serve.build_server`` where a
blocking ``serve_forever`` must not run.

Test -> behavior map:
  test_root_serves_index_php_raw ....... "/" -> index.php bytes, raw
        text/plain (PHP is NEVER executed — the source is the answer)
  test_root_404_when_index_absent ...... no index.php in the zip:
        "/" answers 404 (no index resolution — documented KISS)
  test_nested_uploads_file ............. the full /wp-content/uploads/...
        URL -> 200, exact bytes, jpg -> image/jpeg (the verify shape)
  test_percent_encoded_name_roundtrip .. the on-disk name "with
        space.jpg" fetches as with%20space.jpg -> 200 (verify stores
        refs DECODED and re-encodes with quote(safe="/"): the
        round-trip MUST hold)
  test_traversal_resolves_to_nothing .. "/../wp-config.php",
        "/..%2Fx", deeper and dot-ENCODED escapes -> 404 with the
        constant not-found body: traversal NEVER leaks zip bytes
        (decode-before-collapse); PLUS a wire-level raw-socket probe —
        no client-side normalization can hide the escape attempt
        (requests collapses "../" before sending; urllib does not)
  test_handle_error_never_writes_stderr .. [found by the operator
        smoke] a client aborting mid-download (verify streams and
        closes WITHOUT reading, on purpose) must not spray
        socketserver's default traceback on stderr: disconnect noise
        is ONE debug record, a real handler bug an error record —
        never stderr, never a raise
  test_directory_404 ................... "wp-content/uploads" and its
        trailing-slash form both answer 404 (documented KISS)
  test_missing_file_404 ................ an absent member answers 404
  test_query_string_ignored ............ /a.jpg?ver=5 serves a.jpg
  test_post_405 ....................... POST (and PROPFIND — the
        do_* __getattr__ catch-all) answers 405 with Allow: GET, HEAD
  test_head_served_headers_only ....... HEAD: 200, empty body, the true
        Content-Length in the headers
  test_content_type_sniff ............. html/css/js/php/json/xml plus
        the unknown-extension application/octet-stream fallback
  test_root_autodetect_strips_site_dir . the nested "<site>/" root is
        stripped: webroot-relative URLs serve; the raw nested name
        ("/site.test/...") answers 404

run_serve (CLI contract):
  test_run_serve_ftp_mode_refusal ..... ftp mode: rc 1, the refusal
        error logged, build_server never called
  test_run_serve_missing_zip_rc1 ...... local mode, nonexistent zip:
        SourceError -> rc 1, "serve failed" logged, never a traceback
  test_run_serve_port_in_use_rc1 ...... a port another socket holds:
        the bind OSError -> rc 1, error logged
  test_run_serve_port_from_extra ...... build_server receives
        (ctx.zip, extra["port"]); the info line announces the REAL
        port; server_close runs in the finally exactly once
  test_run_serve_default_port ......... a Ctx without extra["port"]:
        build_server receives the 8080 fallback (the number the CLI's
        --port flag must default to)
  test_run_serve_ctrl_c_rc0 ........... KeyboardInterrupt from
        serve_forever (Ctrl-C): rc 0, clean shutdown, closed once
  test_run_serve_writes_a_run_receipt . --report is honoured (SPEC:
        EVERY command): the file exists after the run, names the command
        and the bound URL, carries its JSON twin, and never a credential
  test_run_serve_refuses_an_unwritable_report . a report path that cannot
        be written is a FAILED run (rc 1), never a silent success
  test_run_receipt_never_carries_a_secret . the receipt is built from the
        caller's own public facts and holds no path the operator did not
        type
  test_the_cli_dispatches_serve_to_the_command_body  end to end through
        the real dispatcher: --report reaches the body and the file lands
  test_the_receipt_states_the_pair_s_limit_before_the_operator_finds_it .
        the receipt says what the serve+verify pair canNOT do (this
        server cannot render, so a verify here finds no references and
        reports NOT a pass) — the honest limit is stated where the
        operator starts the rehearsal, not only where it fails
"""

import json
import logging
import socket
import threading
import urllib.error
import urllib.request
import zipfile

import pytest

import wpt.serve
from wpt.cli import Ctx
from wpt.settings import load

from tests.fakes import SERVE_POLL_INTERVAL_S

SITE = "site.test"

# Proxy-less opener: urllib would otherwise honor http_proxy env vars and
# send 127.0.0.1 requests through a stranger.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _zip(tmp_path, files, name="rehearsal", site=SITE):
    """A host-export-shaped zip: every member nested under ``"<site>/"``
    with the root dir entry present — ZipSource auto-detects and strips
    it (the real rehearsal-archive shape, pinned by
    tests/sources/test_zip.py)."""
    p = tmp_path / f"{name}.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr(f"{site}/", "")
        for member, data in files.items():
            zf.writestr(f"{site}/{member}", data)
    return p


@pytest.fixture()
def serve(tmp_path):
    """``build_server`` on an ephemeral port + ``serve_forever`` in a
    daemon thread; every built server is shut down and closed in the
    finalizer (``server_close`` ALSO closes the ZipSource)."""
    built = []

    def _make(files, name="rehearsal"):
        server = wpt.serve.build_server(_zip(tmp_path, files, name), 0)
        thread = threading.Thread(
            target=lambda: server.serve_forever(
                poll_interval=SERVE_POLL_INTERVAL_S),
            daemon=True)
        thread.start()
        built.append((server, thread))
        return server

    yield _make

    for server, thread in built:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _base(server):
    return f"http://127.0.0.1:{server.server_address[1]}"


def _request(url, method="GET", data=None):
    """(status, headers, body) for one request; an HTTPError (404/405)
    is the expected answer, not a failure."""
    req = urllib.request.Request(url, method=method, data=data)
    try:
        with _OPENER.open(req, timeout=10) as response:
            return response.status, response.headers, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read()


def _raw_get(port, raw_path):
    """Wire-level GET: the path goes on the request line EXACTLY as
    given — no client-side dot-segment normalization (requests would
    collapse "/../x" before sending; a raw socket cannot)."""
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        sock.sendall(f"GET {raw_path} HTTP/1.0\r\nHost: rehearsal\r\n\r\n"
                     .encode("ascii"))
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


# ------------------------------------------------------------- GET semantics


def test_root_serves_index_php_raw(serve):
    server = serve({"index.php": b"<?php // rehearsal index"})
    status, headers, body = _request(_base(server) + "/")
    assert status == 200
    assert body == b"<?php // rehearsal index"  # raw bytes, NOT executed
    assert headers["Content-Type"] == "text/plain; charset=utf-8"


def test_root_404_when_index_absent(serve):
    server = serve({"wp-content/uploads/2023/a.jpg": b"A"})
    status, _headers, body = _request(_base(server) + "/")
    assert status == 404
    assert body == b"not found\n"


def test_nested_uploads_file(serve):
    payload = b"\xff\xd8\xe0JPEGBYTES"
    server = serve({"wp-content/uploads/2023/10/pic.jpg": payload})
    status, headers, body = _request(
        _base(server) + "/wp-content/uploads/2023/10/pic.jpg")
    assert status == 200
    assert body == payload
    assert headers["Content-Type"] == "image/jpeg"


def test_percent_encoded_name_roundtrip(serve):
    server = serve({"wp-content/uploads/2023/10/with space.jpg": b"SPACED"})
    # verify stores refs DECODED ("with space.jpg") and re-encodes with
    # quote(safe="/") — the percent-encoded form is the URL the live
    # tools actually fetch, so the round-trip MUST hold.
    status, headers, body = _request(
        _base(server) + "/wp-content/uploads/2023/10/with%20space.jpg")
    assert status == 200
    assert body == b"SPACED"
    assert headers["Content-Type"] == "image/jpeg"


def test_traversal_resolves_to_nothing(serve):
    server = serve({"wp-config.php": b"WPT-SECRET-CONFIG-BYTES"})
    for url in ("/../wp-config.php", "/..%2Fx",
                "/wp-content/../../wp-config.php",
                "/%2e%2e/wp-config.php"):
        status, _headers, body = _request(_base(server) + url)
        assert status == 404, url
        # the constant not-found body: traversal NEVER leaks zip bytes
        assert body == b"not found\n", url
    # wire-level: the raw path reaches the server un-normalized and the
    # server-side collapse is what answers
    raw = _raw_get(server.server_address[1], "/../wp-config.php")
    assert raw.startswith(b"HTTP/1.1 404")
    assert b"WPT-SECRET-CONFIG-BYTES" not in raw


def test_directory_404(serve):
    server = serve({"wp-content/uploads/2023/a.jpg": b"A"})
    for url in ("/wp-content/uploads", "/wp-content/uploads/",
                "/wp-content/uploads/2023"):
        status, _headers, _body = _request(_base(server) + url)
        assert status == 404, url


def test_missing_file_404(serve):
    server = serve({"index.php": b"x"})
    status, _headers, body = _request(_base(server) + "/nope.jpg")
    assert status == 404
    assert body == b"not found\n"


def test_query_string_ignored(serve):
    server = serve({"a.jpg": b"A"})
    status, _headers, body = _request(_base(server) + "/a.jpg?ver=5")
    assert status == 200
    assert body == b"A"


def test_post_405(serve):
    server = serve({"index.php": b"x"})
    status, headers, _body = _request(_base(server) + "/", method="POST",
                                     data=b"payload")
    assert status == 405
    assert headers["Allow"] == "GET, HEAD"
    # the __getattr__ catch-all covers EVERY unimplemented method
    status, _headers, _body = _request(_base(server) + "/",
                                       method="PROPFIND")
    assert status == 405


def test_head_served_headers_only(serve):
    server = serve({"index.php": b"IDX"})
    status, headers, body = _request(_base(server) + "/", method="HEAD")
    assert status == 200
    assert body == b""
    assert headers["Content-Length"] == "3"


def test_content_type_sniff(serve):
    server = serve({
        "p.html": b"<html>", "p.css": b"a{}", "p.js": b"var x;",
        "p.php": b"<?php", "d.json": b"{}", "sitemap.xml": b"<x/>",
        "noext": b"\x00", "p.weird": b"\x00",
    })
    base = _base(server)
    expected = [
        ("/p.html", "text/html; charset=utf-8"),
        ("/p.css", "text/css; charset=utf-8"),
        ("/p.js", "text/javascript; charset=utf-8"),
        ("/p.php", "text/plain; charset=utf-8"),  # raw source, documented
        ("/d.json", "application/json"),
        ("/sitemap.xml", "application/xml"),
        ("/noext", "application/octet-stream"),
        ("/p.weird", "application/octet-stream"),
    ]
    for path, ctype in expected:
        status, headers, _body = _request(base + path)
        assert status == 200, path
        assert headers["Content-Type"] == ctype, path


def test_root_autodetect_strips_site_dir(serve):
    server = serve({"wp-config.php": b"ROOT-CONFIG", "index.php": b"IDX"})
    base = _base(server)
    # the "<site>/" root was stripped: webroot-relative URLs serve
    status, _headers, body = _request(base + "/wp-config.php")
    assert status == 200
    assert body == b"ROOT-CONFIG"
    # the raw nested name is NOT a webroot path
    status, _headers, _body = _request(base + "/site.test/wp-config.php")
    assert status == 404


# -------------------------------------------------- run_serve (CLI contract)


@pytest.fixture()
def wpt_caplog(caplog):
    """caplog wired to the non-propagating wpt logger tree (caplog alone
    cannot see wpt.* records — the tests/test_walk.py convention)."""
    parent = logging.getLogger("wpt")
    parent.addHandler(caplog.handler)
    with caplog.at_level(logging.DEBUG, logger="wpt"):
        yield caplog
    parent.removeHandler(caplog.handler)


def _ctx(tmp_path, **overrides):
    kwargs = dict(
        source="local", settings=load(),
        zip=tmp_path / "z.zip", extra={},
    )
    kwargs.update(overrides)
    return Ctx(**kwargs)


def _serve_errors(caplog):
    return [r.getMessage() for r in caplog.records
            if r.name == "wpt.serve" and r.levelno == logging.ERROR]


class _FakeServer:
    """A non-blocking server double: records serve_forever/server_close
    and reports the caller-given port (the info line needs one)."""

    def __init__(self, port):
        self.server_address = ("127.0.0.1", port)
        self.served = 0
        self.closed = 0

    def serve_forever(self):
        self.served += 1
        return None

    def server_close(self):
        self.closed += 1


def test_run_serve_ftp_mode_refusal(monkeypatch, tmp_path, wpt_caplog):
    """ftp mode: rc 1, the refusal error logged, build_server never
    called (serving against a live source makes no sense)."""
    def _never(zip_path, port):
        raise AssertionError("build_server must not run in ftp mode")

    monkeypatch.setattr(wpt.serve, "build_server", _never)
    ctx = _ctx(tmp_path, source="ftp://h")

    assert wpt.serve.run_serve(ctx) == 1
    assert _serve_errors(wpt_caplog) == [
        "serve requires local mode: the live site already has URLs "
        "(serve the rehearsal zip offline instead)"
    ]


def test_R9_P2_12_serve_startup_refusals_write_the_failure_pair(
        tmp_path, wpt_caplog):
    """P2-12: ftp-mode/port/missing-zip refusals returned 1 before the
    receipt, so --report left no artifact at all."""
    report = tmp_path / "serve.md"
    ctx = _ctx(tmp_path, source="ftp://h", report_path=report)
    assert wpt.serve.run_serve(ctx) == 1
    assert "## This run did not complete" in report.read_text(encoding="utf-8")
    assert report.with_suffix(".json").is_file()

    bad_port = tmp_path / "bad-port.md"
    ctx2 = _ctx(tmp_path, extra={"port": 99999}, report_path=bad_port)
    assert wpt.serve.run_serve(ctx2) == 1
    assert "## This run did not complete" in bad_port.read_text(
        encoding="utf-8")


def test_run_serve_missing_zip_rc1(tmp_path, wpt_caplog):
    """local mode, nonexistent zip: the SourceError contract — rc 1, the
    error logged, never a traceback."""
    ctx = _ctx(tmp_path, zip=tmp_path / "ghost.zip")

    assert wpt.serve.run_serve(ctx) == 1
    errors = _serve_errors(wpt_caplog)
    assert len(errors) == 1
    assert errors[0].startswith("serve failed: zip not found:")


def test_run_serve_port_in_use_rc1(tmp_path, wpt_caplog):
    """A port another socket holds: the bind OSError -> rc 1, error
    logged (the server never answers on someone else's port)."""
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    try:
        ctx = _ctx(tmp_path, zip=_zip(tmp_path, {"index.php": b"x"}),
                   extra={"port": blocker.getsockname()[1]})
        assert wpt.serve.run_serve(ctx) == 1
        assert any("serve failed" in e for e in _serve_errors(wpt_caplog))
    finally:
        blocker.close()


def test_run_serve_port_from_extra(monkeypatch, tmp_path, wpt_caplog):
    """build_server receives (ctx.zip, extra["port"]); the info line
    announces the REAL port; server_close runs in the finally."""
    seen = []
    made = []

    def _fake(zip_path, port):
        seen.append((zip_path, port))
        made.append(_FakeServer(port))
        return made[-1]

    monkeypatch.setattr(wpt.serve, "build_server", _fake)
    ctx = _ctx(tmp_path, extra={"port": 9123})

    assert wpt.serve.run_serve(ctx) == 0
    assert seen == [(tmp_path / "z.zip", 9123)]
    infos = [r.getMessage() for r in wpt_caplog.records
             if r.name == "wpt.serve" and r.levelno == logging.INFO]
    assert infos == [f"serving {tmp_path / 'z.zip'} at "
                     f"http://127.0.0.1:9123/ — Ctrl-C to stop"]
    assert made[0].served == 1
    assert made[0].closed == 1


def test_run_serve_default_port(monkeypatch, tmp_path):
    """A Ctx without extra["port"]: build_server receives the 8080
    fallback — the number the CLI's --port flag must default to."""
    seen = []

    def _fake(zip_path, port):
        seen.append(port)
        return _FakeServer(port)

    monkeypatch.setattr(wpt.serve, "build_server", _fake)
    ctx = _ctx(tmp_path)  # extra={} — the defensive fallback path

    assert wpt.serve.run_serve(ctx) == 0
    assert seen == [8080]


def test_R12_server_close_failure_keeps_the_verdict_and_pair(
        monkeypatch, tmp_path, wpt_caplog):
    """R12-P2-2: ``server_close`` was the only unguarded teardown; an
    OSError there wrote the success pair and then escaped main as a
    traceback.  The verdict/rc and both report faces stay."""
    report = tmp_path / "serve.md"

    class _CloseFails(_FakeServer):
        def server_close(self):
            self.closed += 1
            raise OSError("close exploded")

    server = _CloseFails(8080)
    monkeypatch.setattr(wpt.serve, "build_server",
                        lambda zip_path, port: server)
    ctx = _ctx(tmp_path, report_path=report)

    assert wpt.serve.run_serve(ctx) == 0
    assert server.served == 1 and server.closed == 1
    assert "# wpt serve" in report.read_text(encoding="utf-8")
    assert report.with_suffix(".json").is_file()
    warnings = [r.getMessage() for r in wpt_caplog.records
                if r.name == "wpt.serve" and r.levelno == logging.WARNING]
    assert any("server close failed" in m for m in warnings)


def test_run_serve_ctrl_c_rc0(monkeypatch, tmp_path):
    """KeyboardInterrupt from serve_forever (Ctrl-C): rc 0, clean
    shutdown, the server closed exactly once."""

    class _Interrupting(_FakeServer):
        def serve_forever(self):
            self.served += 1
            raise KeyboardInterrupt

    server = _Interrupting(8080)
    monkeypatch.setattr(wpt.serve, "build_server",
                        lambda zip_path, port: server)
    ctx = _ctx(tmp_path)

    assert wpt.serve.run_serve(ctx) == 0
    assert server.served == 1
    assert server.closed == 1


# ------------------------------------------------------------- server errors


def test_handle_error_never_writes_stderr(tmp_path, capsys, wpt_caplog):
    """[found by the operator smoke] a client aborting mid-download
    (verify streams and closes WITHOUT reading, on purpose) must not
    spray socketserver's default traceback on stderr: disconnect noise
    is ONE debug record, a real handler bug an error record — never
    stderr, never a raise."""
    server = wpt.serve.build_server(_zip(tmp_path, {"index.php": b"x"}), 0)
    try:
        try:
            raise ConnectionResetError("reset by peer")
        except ConnectionResetError:
            server.handle_error(None, ("127.0.0.1", 1))
        try:
            raise RuntimeError("boom")
        except RuntimeError:
            server.handle_error(None, ("127.0.0.1", 1))
    finally:
        server.server_close()
    records = [r for r in wpt_caplog.records if r.name == "wpt.serve"]
    debugs = [r.getMessage() for r in records if r.levelno == logging.DEBUG]
    errors = [r.getMessage() for r in records if r.levelno == logging.ERROR]
    assert any("disconnected" in m for m in debugs)
    assert errors and "boom" in errors[0]
    # the socketserver default (traceback -> stderr) is gone for good
    assert capsys.readouterr().err == ""


# ----------------------------------------------------------- the run receipt


def test_run_serve_writes_a_run_receipt(monkeypatch, tmp_path):
    """``--report`` is honoured by EVERY command (SPEC), and serve used to
    swallow it: a caller could not tell from the filesystem whether a
    serve run had happened.  What a run with no plan can honestly record
    is WHAT RAN, so the receipt carries the command, the archive NAME, the
    bound URL and the bind line — written after the bind, so it names the
    real port and exists even though this run only ends at Ctrl-C — plus
    the JSON twin every other report surface writes."""
    monkeypatch.setattr(wpt.serve, "build_server",
                        lambda zip_path, port: _FakeServer(port))
    report = tmp_path / "serve.md"
    ctx = _ctx(tmp_path, zip=_zip(tmp_path, {"index.php": b"x"}),
               extra={"port": 9123}, report_path=report,
               user="rehearsal", password="s3cr3t-p4ss")

    assert wpt.serve.run_serve(ctx) == 0
    assert report.exists()
    markdown = report.read_text(encoding="utf-8")
    assert markdown.startswith("# wpt serve")
    # the identifying lines: the command, the URL it answers on, the bind
    assert "- command: serve" in markdown
    assert "- url: http://127.0.0.1:9123/" in markdown
    assert "- bind: 127.0.0.1:9123" in markdown
    assert "rehearsal.zip" in markdown          # the archive NAME
    assert "PHP is NOT executed" in markdown
    # the twin: the same facts, machine-readable
    twin = json.loads(report.with_suffix(".json").read_text(encoding="utf-8"))
    assert twin["command"] == "serve"
    assert twin["url"] == "http://127.0.0.1:9123/"
    assert twin["archive"] == "rehearsal.zip"
    # never a credential: neither field carries the login or the password,
    # and the archive's full path (the operator's home) never appears —
    # the receipt names the archive, not where it sits
    assert "s3cr3t-p4ss" not in markdown
    assert "s3cr3t-p4ss" not in json.dumps(twin)
    assert "/" not in twin["archive"]
    assert str(tmp_path) not in markdown
    assert str(tmp_path) not in json.dumps(twin)


def test_run_serve_refuses_an_unwritable_report(monkeypatch, tmp_path):
    """A report path that cannot be written is a FAILED run: the contract
    that makes --report worth passing is that the file is there
    afterwards, so its absence must never read as success."""
    monkeypatch.setattr(wpt.serve, "build_server",
                        lambda zip_path, port: _FakeServer(port))
    blocked = tmp_path / "serve.md"
    blocked.mkdir()          # the report path is a directory: unwritable
    ctx = _ctx(tmp_path, zip=_zip(tmp_path, {"index.php": b"x"}),
               extra={"port": 9123}, report_path=blocked)

    assert wpt.serve.run_serve(ctx) == 1


def test_run_receipt_never_carries_a_secret():
    """The receipt renderer is handed the caller's public facts and adds
    nothing of its own — the ``command`` row it writes from its own
    argument, and nothing else.  So it cannot become a place a credential
    leaks into (the report layer's free-text scrubber is not the
    protection here; the absence of the value is)."""
    markdown, twin = wpt.serve.run_receipt("demo", (
        ("url", "https://127.0.0.1:8443/"),
        ("stop", "Ctrl-C"),
    ))
    assert markdown == (
        "# wpt demo\n\n"
        "- command: demo\n"
        "- url: https://127.0.0.1:8443/\n"
        "- stop: Ctrl-C\n"
    )
    assert json.loads(twin) == {"command": "demo",
                                "url": "https://127.0.0.1:8443/",
                                "stop": "Ctrl-C"}


def test_the_cli_dispatches_serve_to_the_command_body(monkeypatch, tmp_path):
    """END TO END through the real dispatcher: ``wpt ... serve --report
    out.md`` writes the receipt.  This is the SPEC property ("--report is
    honoured by EVERY command") — serve used to accept the flag and drop
    it on the floor, so a caller could not tell from the filesystem that
    the rehearsal server had ever run."""
    from wpt.cli import main

    monkeypatch.setattr(wpt.serve, "build_server",
                        lambda zip_path, port: _FakeServer(port))
    report = tmp_path / "serve.md"
    rc = main([
        "--source", "local", "--zip", str(_zip(tmp_path, {"index.php": b"x"})),
        "--report", str(report), "serve", "--port", "9123",
    ])
    assert rc == 0
    markdown = report.read_text(encoding="utf-8")
    assert "- command: serve" in markdown
    assert "- url: http://127.0.0.1:9123/" in markdown


def test_the_receipt_states_the_pair_s_limit_before_the_operator_finds_it(
        monkeypatch, tmp_path):
    """The rehearsal pair is honest at its SOURCE, not only at verify's.

    ``wpt serve`` + ``wpt verify`` is the documented offline rehearsal, and
    it cannot verify anything rendered: the only servable root is
    ``index.php`` answered as ``text/plain``, so the walker's HTML test
    rejects it and the reference set is empty.  ``verify`` now answers
    "this is not a pass" there — but the operator starts the rehearsal
    here, so the receipt they read first says what the pair can and cannot
    do.  The server was NOT taught to fake a rendering: a static server
    cannot render WordPress, and anything it emitted would be a pretence
    with a URL on it.
    """
    monkeypatch.setattr(wpt.serve, "build_server",
                        lambda zip_path, port: _FakeServer(port))
    report = tmp_path / "serve.md"
    ctx = _ctx(tmp_path, zip=_zip(tmp_path, {"index.php": b"x"}),
               extra={"port": 9123}, report_path=report)

    assert wpt.serve.run_serve(ctx) == 0

    markdown = report.read_text(encoding="utf-8")
    verify_row = [line for line in markdown.splitlines()
                  if line.startswith("- verify:")]
    assert len(verify_row) == 1
    assert "NOT a pass" in verify_row[0]
    assert "no live references" in verify_row[0]
    twin = json.loads(report.with_suffix(".json").read_text(encoding="utf-8"))
    assert "NOT a pass" in twin["verify"]


def test_R6_30_out_of_range_port_is_one_line_rc1_before_bind(tmp_path,
                                                              wpt_caplog):
    """R6-30: serve cast --port without a range check, so socket.bind raised
    OverflowError (not OSError) and escaped the command body."""
    ctx = _ctx(tmp_path, extra={"port": 70000})
    assert wpt.serve.run_serve(ctx) == 1
    errors = _serve_errors(wpt_caplog)
    assert any("between 0 and 65535" in message for message in errors)


@pytest.mark.parametrize("value", [
    float("inf"), float("-inf"), float("nan"), True, 1.9, "9123", -1,
])
def test_R6_44_programmatic_port_shapes_are_refused_before_bind(
        monkeypatch, tmp_path, value, wpt_caplog):
    """R6-44: ``extra={"port": inf}`` raised a raw OverflowError before
    validation; ``1.9`` silently truncated to port 1.  One coercion refuses
    every non-int shape with one line and never builds the server."""
    calls = []
    monkeypatch.setattr(wpt.serve, "build_server",
                        lambda zip_path, port: calls.append(port))
    ctx = _ctx(tmp_path, extra={"port": value})

    assert wpt.serve.run_serve(ctx) == 1
    assert calls == []
    assert any("between 0 and 65535" in message
               for message in _serve_errors(wpt_caplog))


def test_R13_server_close_stoprequested_and_ctrl_c_preserve_the_verdict(
        tmp_path, monkeypatch):
    """R13-P2-14: the serve teardown caught only ``Exception``; a
    ``StopRequested`` (BaseException) or Ctrl-C during ``server_close``
    escaped ``run_serve``.  Both are one warning; the run's verdict stays."""
    from wpt.types import StopRequested

    for raised in (StopRequested("SIGTERM during close"), KeyboardInterrupt()):
        class _CloseRaises(_FakeServer):
            def server_close(self):
                self.closed += 1
                raise raised

        monkeypatch.setattr("wpt.serve.build_server",
                            lambda zip_path, port: _CloseRaises(8123))
        ctx = _ctx(tmp_path, zip=tmp_path / "site.zip")
        assert wpt.serve.run_serve(ctx) == 0


def test_R21_405_answers_without_draining_an_unbounded_body(serve):
    """R21-P2: PUT with a 100 MB declared Content-Length and no body made
    the handler block in ``rfile.read`` before answering — one thread per
    request, no response.  405 is sent immediately and the connection
    closes, so the unread body dies with the socket."""
    import socket
    import time

    server = serve({"index.php": b"x"})
    port = server.server_address[1]
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(
            b"PUT / HTTP/1.1\r\nHost: rehearsal\r\n"
            b"Content-Length: 100000000\r\n\r\n")
        started = time.monotonic()
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\r\n\r\n" in b"".join(chunks):
                break
        elapsed = time.monotonic() - started
    assert elapsed < 2.0, elapsed
    response = b"".join(chunks)
    assert response.startswith(b"HTTP/1.1 405")
    assert b"Connection: close" in response
