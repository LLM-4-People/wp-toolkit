"""Real local-network tests for the DNS override.

A threaded TLS server on 127.0.0.1 (self-signed cert via ensure_cert) plays
the role of the remote site: it records the Host header of every request and
captures SNI via an ssl sni_callback, so both override surfaces are verified
against observed server-side evidence — no external hosts, no DNS.

Endpoint map (test rig):
  /ping      200 "pong" + headers the proxy must filter + one it must keep
  /redirect  302 Location: https://local.test/ping (absolute, same host)
  /asset     HTML with absolute https://, http://, JSON-escaped, uppercase and
             scheme-relative site URLs + an external URL
  /cookie    Set-Cookie with Domain=local.test
  /gzip      forced-gzip body containing a site URL
  /weird     unknown Content-Encoding (x-wpt-unknown) — must pass through untouched
  /echo      POST body echo
"""

import gzip
import io
import os
import socket
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest
import requests
import urllib3.connectionpool
import urllib3.poolmanager

from wpt.dnsoverride import (
    IPDialHTTPSConnectionPool,
    IPDialPoolManager,
    ProxyServer,
    ensure_cert,
    resolve_session,
)
from wpt.types import WptError

from tests.fakes import SERVE_POLL_INTERVAL_S

HOSTNAME = "local.test"

# InsecureRequestWarning is suppressed process-globally by the module at import
# (R1 pitfall: it fires per request and has no per-session scoping); pytest's
# warning capture ignores module-level filters, so keep the suite output clean
# without weakening production behavior.
pytestmark = pytest.mark.filterwarnings(
    "ignore::urllib3.exceptions.InsecureRequestWarning"
)


@pytest.fixture(autouse=True)
def _fast_proxy_accept_poll(monkeypatch):
    """Keep the proxy's own accept loop responsive without changing it.

    ``ProxyServer.stop()`` waits for the accept thread; http.server polls
    every 0.5 s by default, so every proxy test paid up to half a second.
    The real ``_ProxyHTTPServer.serve_forever`` still runs — only its poll
    interval is shortened."""
    import wpt.dnsoverride as dnsoverride_mod

    original = dnsoverride_mod._ProxyHTTPServer.serve_forever

    def serve_forever(self, poll_interval=0.5):
        return original(self, poll_interval=SERVE_POLL_INTERVAL_S)

    monkeypatch.setattr(
        dnsoverride_mod._ProxyHTTPServer, "serve_forever", serve_forever)


_ASSET_BODY = (
    b'<html><head><link rel="stylesheet" href="https://local.test/style.css">'
    b"</head><body>"
    b'<a href="https://local.test/page">absolute https</a>'
    b'<a href="http://local.test/plain">absolute http</a>'
    b'<a href="HTTPS://LOCAL.TEST/UP">uppercase</a>'
    b'<img src="//local.test/cached">'
    b'<a href="https://other.example/x">external stays</a>'
    b'<a href="/relative">relative stays</a>'
    b'<script>var cfg = {"url":"https:\\/\\/local.test\\/escaped"};</script>'
    b"</body></html>"
)


class _UpstreamHandler(BaseHTTPRequestHandler):
    """Records (method, Host, path) on the server instance; serves test routes."""

    protocol_version = "HTTP/1.1"

    def _respond(self, status=200, body=b"", content_type="text/plain; charset=utf-8",
                 headers=()):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def do_GET(self):
        self.server.requests.append((self.command, self.headers.get("Host"), self.path))
        route = self.path.split("?", 1)[0]
        if route == "/ping":
            self._respond(
                body=b"pong",
                headers=(
                    ("Strict-Transport-Security", "max-age=31536000"),
                    ("Content-Security-Policy", "default-src 'self'"),
                    ("Alt-Svc", 'h2=":443"; ma=2592000'),
                    ("X-Wpt-Marker", "kept"),
                ),
            )
        elif route == "/redirect":
            self._respond(status=302, headers=(("Location", f"https://{HOSTNAME}/ping"),))
        elif route == "/asset":
            self._respond(body=_ASSET_BODY, content_type="text/html; charset=utf-8")
        elif route == "/cookie":
            self._respond(
                headers=(("Set-Cookie",
                          f"wpt_session=kthxbai; Domain={HOSTNAME}; Path=/; HttpOnly"),)
            )
        elif route == "/gzip":
            payload = gzip.compress(f'<a href="https://{HOSTNAME}/gz">g</a>'.encode())
            self._respond(body=payload, content_type="text/html; charset=utf-8",
                          headers=(("Content-Encoding", "gzip"),))
        elif route == "/gzipmulti":
            # mtime=0 keeps the header deterministic across a test run (the
            # default embeds the current second).
            payload = (gzip.compress(b"FIRST-MEMBER;", mtime=0)
                       + gzip.compress(b"SECOND-MEMBER;", mtime=0))
            self._respond(body=payload, content_type="text/plain",
                          headers=(("Content-Encoding", "gzip"),))
        elif route == "/gziptruncated":
            payload = gzip.compress(b"HELLO WORLD" * 100, mtime=0)[:-20]
            self._respond(body=payload, content_type="text/plain",
                          headers=(("Content-Encoding", "gzip"),))
        elif route == "/weird":
            self._respond(body=b"\x00\x01https://local.test/x",
                          headers=(("Content-Encoding", "x-wpt-unknown"),))
        elif route == "/early":
            # An interim 103 (Early Hints) followed by the real answer on
            # the SAME connection: http.client itself skips only 100.
            self.send_response_only(103)
            self.send_header("Link", "</style.css>; rel=preload")
            self.end_headers()
            self.wfile.flush()
            self._respond(body=b"final after hints")
        elif route == "/echo":
            length = int(self.headers.get("Content-Length", "0"))
            data = self.rfile.read(length) if length else b""
            self._respond(body=data)
        elif route == "/drip":
            # 8 declared bytes, one every 0.4 s: a per-read timeout resets
            # forever while the proxy was never given the absolute budget.
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "8")
            self.end_headers()
            try:
                for _ in range(8):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.4)
            except (BrokenPipeError, ConnectionResetError):
                pass
        elif route == "/headdrip":
            # A status line/header dripped one byte at a time: readline
            # re-armed the per-read socket timeout forever.
            wire = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
            try:
                for index in range(len(wire)):
                    self.wfile.write(wire[index:index + 1])
                    self.wfile.flush()
                    time.sleep(0.1)
            except (BrokenPipeError, ConnectionResetError):
                pass
            self.close_connection = True
        elif route == "/gzipbomb":
            # 20 MiB of "A" compresses to ~20 KiB; the proxy's configured
            # body cap must apply to the DECODED payload.
            import gzip as _gzip
            payload = _gzip.compress(b"A" * (20 * 1024 * 1024), 9)
            self._respond(body=payload, content_type="text/html",
                          headers=(("Content-Encoding", "gzip"),))
        elif route == "/truncatedtrailer":
            self.wfile.write(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                b"Connection: close\r\n\r\n2\r\nhi\r\n0\r\n")
            self.wfile.flush()
            self.close_connection = True
        elif route == "/negchunk":
            # A negative chunk size is not a stream: int("-1", 16) used to
            # keep the parser reading forever.
            self.wfile.write(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                b"Connection: close\r\n\r\n-1\r\n\r\n")
            self.wfile.flush()
            self.close_connection = True
        else:
            self._respond(status=404, body=b"not found")

    do_POST = do_GET
    do_HEAD = do_GET

    def log_message(self, fmt, *args):
        pass  # keep test output quiet; the module under test logs through wpt.log


@pytest.fixture()
def upstream(tmp_path):
    """TLS server on an ephemeral 127.0.0.1 port recording Host + SNI."""
    cert_path, key_path = ensure_cert(tmp_path / "upstream-certs")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    sni: list[str] = []

    def _sni(sock, server_name, initial_context):
        sni.append(server_name)
        return None  # keep the server's own context

    context.sni_callback = _sni
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _UpstreamHandler)
    httpd.requests: list[tuple[str, str | None, str]] = []
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(
        target=lambda: httpd.serve_forever(
            poll_interval=SERVE_POLL_INTERVAL_S),
        daemon=True)
    thread.start()
    yield SimpleNamespace(port=httpd.server_address[1], requests=httpd.requests, sni=sni)
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=5)


@pytest.fixture()
def plain_upstream():
    """Plain-HTTP origin recording Host + path (the http:// override twin)."""
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _UpstreamHandler)
    httpd.requests: list[tuple[str, str | None, str]] = []
    thread = threading.Thread(
        target=lambda: httpd.serve_forever(
            poll_interval=SERVE_POLL_INTERVAL_S),
        daemon=True)
    thread.start()
    yield SimpleNamespace(port=httpd.server_address[1],
                          requests=httpd.requests)
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=5)


@pytest.fixture()
def client():
    """Plain requests client with env proxies disabled (trust_env hijack guard)."""
    session = requests.Session()
    session.trust_env = False
    yield session
    session.close()


@pytest.fixture()
def session(upstream):
    """resolve_session overriding HOSTNAME to the local TLS server."""
    s = resolve_session(HOSTNAME, "127.0.0.1", timeout=5, port=upstream.port)
    yield s
    s.close()


@pytest.fixture()
def proxy(upstream, tmp_path):
    server = ProxyServer(
        HOSTNAME, "127.0.0.1", port=0,
        upstream_port=upstream.port, cert_dir=tmp_path / "proxy-certs",
    )
    yield server
    server.stop()


# -- resolve_session -------------------------------------------------------


def test_resolve_session_dials_override_ip(session, upstream):
    response = session.get(f"https://{HOSTNAME}/ping")
    assert response.status_code == 200
    assert response.text == "pong"
    # server-side evidence: the site saw the hostname, not the IP
    assert ("GET", HOSTNAME, "/ping") in upstream.requests
    assert HOSTNAME in upstream.sni


def test_R15_resolve_session_dials_an_http_override(plain_upstream):
    """R15-P2: the dial adapter was mounted on ``https://`` only, so an
    ``http://`` site under --override-ip silently used real DNS (and a
    mutating bridge call could address the wrong host)."""
    s = resolve_session(HOSTNAME, "127.0.0.1", timeout=5,
                        port=plain_upstream.port)
    try:
        response = s.get(f"http://{HOSTNAME}:{plain_upstream.port}/ping")
        assert response.status_code == 200
        assert response.text == "pong"
        assert ("GET", f"{HOSTNAME}:{plain_upstream.port}", "/ping") \
            in plain_upstream.requests
    finally:
        s.close()


def test_resolve_session_security_flags_and_default_timeout(upstream):
    s = resolve_session(HOSTNAME, "127.0.0.1", timeout=7, port=upstream.port)
    try:
        assert s.trust_env is False
        assert s.verify is False
        assert s._default_timeout == 7
        assert isinstance(s.get_adapter(f"https://{HOSTNAME}/").poolmanager,
                          IPDialPoolManager)
    finally:
        s.close()


def test_resolve_session_follows_same_host_redirect(session, upstream):
    response = session.get(f"https://{HOSTNAME}/redirect")
    assert response.status_code == 200
    assert response.text == "pong"
    assert len(response.history) == 1
    assert response.history[0].status_code == 302
    # the redirected request kept the override (same host)
    assert ("GET", HOSTNAME, "/ping") in upstream.requests


def test_resolve_session_posts_through_override(session, upstream):
    response = session.post(f"https://{HOSTNAME}/echo", data=b"hello session")
    assert response.status_code == 200
    assert response.content == b"hello session"
    assert ("POST", HOSTNAME, "/echo") in upstream.requests


def test_pool_rebuild_reinjects_dial(session, upstream):
    assert session.get(f"https://{HOSTNAME}/ping").status_code == 200
    session.get_adapter(f"https://{HOSTNAME}/").poolmanager.clear()
    response = session.get(f"https://{HOSTNAME}/ping")
    assert response.status_code == 200
    assert response.text == "pong"


def test_pool_manager_host_gating_unit():
    """Unit-level (no DNS): only the configured hostname gets the override."""
    manager = IPDialPoolManager(HOSTNAME, "127.0.0.1", target_port=8443, num_pools=2)
    overridden = manager._new_pool("https", HOSTNAME, 443, request_context={})
    assert isinstance(overridden, IPDialHTTPSConnectionPool)
    assert overridden.conn_kw["dial_ip"] == "127.0.0.1"
    assert overridden.conn_kw["dial_port"] == 8443
    # case/trailing-dot normalization of the gate
    normalized = manager._new_pool("https", f"{HOSTNAME.upper()}.", 443, request_context={})
    assert isinstance(normalized, IPDialHTTPSConnectionPool)
    # any other host: the pool class is shared manager-wide (R1 design —
    # _new_pool picks it before gating), but the gate means NO dial override
    # is injected, so its connections fall back to stock DNS dialing.
    stock = manager._new_pool("https", "other.example", 443, request_context={})
    assert isinstance(stock, IPDialHTTPSConnectionPool)
    assert "dial_ip" not in stock.conn_kw
    assert "dial_port" not in stock.conn_kw


def test_pool_classes_by_scheme_not_globally_patched():
    """R1 pitfall: the module-level scheme map must stay untouched."""
    IPDialPoolManager(HOSTNAME, "127.0.0.1", num_pools=1)
    assert urllib3.poolmanager.pool_classes_by_scheme["https"] \
        is urllib3.connectionpool.HTTPSConnectionPool
    plain = urllib3.poolmanager.PoolManager(num_pools=1)
    pool = plain._new_pool("https", "other.example", 443, request_context={})
    assert type(pool) is urllib3.connectionpool.HTTPSConnectionPool


# -- ProxyServer -------------------------------------------------------------


def test_proxy_serves_and_filters_response_headers(proxy, client, upstream):
    proxy_port = proxy.start()
    response = client.get(f"https://localhost:{proxy_port}/ping",
                          verify=False, timeout=5)
    assert response.status_code == 200
    assert response.text == "pong"
    # headers that would re-pin the browser to the real origin are dropped
    assert "Strict-Transport-Security" not in response.headers
    assert "Content-Security-Policy" not in response.headers
    assert "Alt-Svc" not in response.headers
    # unrelated headers survive, and the proxy sets its own framing headers
    assert response.headers.get("X-Wpt-Marker") == "kept"
    assert response.headers.get("Connection") == "close"
    assert int(response.headers["Content-Length"]) == len(b"pong")
    # upstream saw the site origin, not localhost
    assert ("GET", HOSTNAME, "/ping") in upstream.requests
    assert HOSTNAME in upstream.sni


def test_proxy_rewrites_body_urls(proxy, client):
    proxy_port = proxy.start()
    response = client.get(f"https://localhost:{proxy_port}/asset",
                          verify=False, timeout=5)
    assert response.status_code == 200
    origin = f"https://localhost:{proxy_port}"
    assert f'href="{origin}/style.css"' in response.text
    assert f'href="{origin}/page"' in response.text        # https form
    assert f'href="{origin}/plain"' in response.text       # http -> https upgrade
    assert f'href="{origin}/UP"' in response.text           # case-insensitive
    assert f'"url":"{origin}\\/escaped"' in response.text   # JSON-escaped slashes
    assert f'src="{origin}/cached"' in response.text        # scheme-relative
    # resolves against the proxy origin too: the same host gate, optional
    # scheme (a scheme-less URL would otherwise resolve to the real origin)
    assert "https://other.example/x" in response.text       # external untouched
    assert "https://local.test" not in response.text
    assert "http://local.test" not in response.text
    assert "//local.test" not in response.text


def test_R15_proxy_skips_103_early_hints_and_serves_the_final_response(
        proxy, client):
    """R15-P2: ``getresponse()`` once returned the 103 head as the answer
    (empty body), so a page using Early Hints was blank through the proxy."""
    proxy_port = proxy.start()
    response = client.get(f"https://localhost:{proxy_port}/early",
                          verify=False, timeout=5)
    assert response.status_code == 200
    assert response.text == "final after hints"
    assert response.headers.get("Link") is None


def test_R17_upstream_head_reader_is_byte_and_header_count_bounded():
    """R17-3-P2: ``_read_upstream_head`` appended every line with no total
    byte or count ceiling, so a hostile upstream could grow a worker's memory
    without bound."""
    import http.client

    from wpt.dnsoverride import (_MAX_UPSTREAM_HEADERS,
                                 _read_upstream_head)

    many = (b"HTTP/1.1 200 OK\r\n"
            + b"".join(f"X-{i}: v\r\n".encode()
                       for i in range(_MAX_UPSTREAM_HEADERS + 1))
            + b"\r\n")
    with pytest.raises(http.client.LineTooLong):
        _read_upstream_head(io.BytesIO(many))

    huge = (b"HTTP/1.1 200 OK\r\n"
            + b"".join(b"X-Long: " + b"v" * 7000 + b"\r\n"
                       for _ in range(10))
            + b"\r\n")
    with pytest.raises(http.client.LineTooLong):
        _read_upstream_head(io.BytesIO(huge))


def test_R17_upstream_head_reader_has_an_absolute_deadline():
    """A peer that drips a header line just under a per-read timeout reset it
    forever; the reader now arms the socket to the SAME absolute deadline
    and refuses the late answer."""
    from wpt.dnsoverride import _read_upstream_head

    class _SlowFP:
        def readline(self, _limit):
            time.sleep(0.08)
            return b"HTTP/1.1 200 OK\r\n"

    with pytest.raises(TimeoutError):
        _read_upstream_head(_SlowFP(), deadline=time.monotonic() + 0.05)


def test_R17_interim_head_count_is_capped(monkeypatch):
    """An endless 100-Continue stream cannot keep a proxy worker spinning."""
    import http.client
    import wpt.dnsoverride as dnsoverride

    monkeypatch.setattr(
        dnsoverride, "_read_upstream_head",
        lambda *_args, **_kwargs: (100, []))
    with pytest.raises(http.client.LineTooLong):
        dnsoverride._read_final_upstream_head(io.BytesIO(), deadline=None)


def test_proxy_rewrites_location_and_cookie_domain(proxy, client):
    proxy_port = proxy.start()
    redirected = client.get(f"https://localhost:{proxy_port}/redirect",
                            verify=False, timeout=5, allow_redirects=False)
    assert redirected.status_code == 302
    assert redirected.headers["Location"] == f"https://localhost:{proxy_port}/ping"
    cookied = client.get(f"https://localhost:{proxy_port}/cookie",
                         verify=False, timeout=5)
    cookie = cookied.headers["Set-Cookie"]
    assert "Domain=localhost" in cookie
    assert HOSTNAME not in cookie


def test_proxy_forwards_post_and_head(proxy, client, upstream):
    proxy_port = proxy.start()
    posted = client.post(f"https://localhost:{proxy_port}/echo",
                         data=b"hello proxy", verify=False, timeout=5)
    assert posted.status_code == 200
    assert posted.content == b"hello proxy"
    assert ("POST", HOSTNAME, "/echo") in upstream.requests
    headed = client.head(f"https://localhost:{proxy_port}/ping",
                         verify=False, timeout=5)
    assert headed.status_code == 200
    assert headed.content == b""
    assert int(headed.headers["Content-Length"]) == 4  # mirrors upstream's length
    assert ("HEAD", HOSTNAME, "/ping") in upstream.requests


def test_proxy_decodes_gzip_and_passes_unknown_encoding(proxy, client):
    proxy_port = proxy.start()
    gzipped = client.get(f"https://localhost:{proxy_port}/gzip",
                         verify=False, timeout=5)
    assert gzipped.status_code == 200
    assert "Content-Encoding" not in gzipped.headers
    assert f'href="https://localhost:{proxy_port}/gz"' in gzipped.text
    # an encoding we cannot decode must pass through byte-identical with its
    # header kept (rewriting would corrupt it)
    weird = client.get(f"https://localhost:{proxy_port}/weird",
                       verify=False, timeout=5)
    assert weird.status_code == 200
    assert weird.headers.get("Content-Encoding") == "x-wpt-unknown"
    assert weird.content == b"\x00\x01https://local.test/x"


def test_proxy_reports_upstream_failure_as_502(tmp_path, client):
    # A bound-but-not-listening socket is not refused consistently on macOS;
    # a listener that accepts and closes is the portable "upstream is not a
    # TLS service" fixture and still exercises the documented 502 path.
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    dead_port = listener.getsockname()[1]

    def _refuse() -> None:
        try:
            conn, _address = listener.accept()
            conn.close()
        except OSError:
            pass

    thread = threading.Thread(target=_refuse, daemon=True)
    thread.start()
    try:
        server = ProxyServer(
            HOSTNAME, "127.0.0.1", port=0,
            upstream_port=dead_port, cert_dir=tmp_path / "certs",
        )
        proxy_port = server.start()
        try:
            response = client.get(f"https://localhost:{proxy_port}/ping",
                                  verify=False, timeout=5)
            assert response.status_code == 502
        finally:
            server.stop()
    finally:
        listener.close()
        thread.join(timeout=2)


def test_R19_upstream_body_drip_rides_one_absolute_deadline(
        upstream, tmp_path, client):
    """R19-P2: the body reader never received the absolute deadline built
    for the head.  An origin sending one byte/0.4 s made a timeout=0.5
    proxy answer 3.22 s later.  The same budget now covers the body."""
    server = ProxyServer(
        HOSTNAME, "127.0.0.1", port=0, upstream_port=upstream.port,
        cert_dir=tmp_path / "proxy-certs", timeout=0.5,
        max_body_bytes=1024 * 1024,
    )
    port = server.start()
    try:
        started = time.monotonic()
        response = client.get(f"https://localhost:{port}/drip",
                              verify=False, timeout=5)
        elapsed = time.monotonic() - started
        assert response.status_code == 502
        assert elapsed < 2.0, elapsed
    finally:
        server.stop()


def test_R19_negative_chunk_size_is_rejected_not_streamed(
        upstream, tmp_path, client):
    """R19-P2: ``int(b'-1', 16)`` was accepted, so the chunked parser kept
    reading an endless stream.  A negative/non-hex size and a bad CRLF are
    protocol errors answered by the existing 502 path."""
    server = ProxyServer(
        HOSTNAME, "127.0.0.1", port=0, upstream_port=upstream.port,
        cert_dir=tmp_path / "proxy-certs", timeout=2.0,
        max_body_bytes=1024 * 1024,
    )
    port = server.start()
    try:
        started = time.monotonic()
        response = client.get(f"https://localhost:{port}/negchunk",
                              verify=False, timeout=5)
        elapsed = time.monotonic() - started
        assert response.status_code == 502
        assert elapsed < 1.5, elapsed
    finally:
        server.stop()


def test_proxy_stop_is_idempotent_and_restartable(proxy, client):
    proxy_port = proxy.start()
    assert proxy.port == proxy_port
    proxy.stop()
    proxy.stop()
    with pytest.raises(requests.exceptions.ConnectionError):
        client.get(f"https://localhost:{proxy_port}/ping", verify=False, timeout=5)
    second_port = proxy.start()
    response = client.get(f"https://localhost:{second_port}/ping",
                          verify=False, timeout=5)
    assert response.status_code == 200
    assert response.text == "pong"


def test_serve_blocks_until_stopped(upstream, tmp_path):
    server = ProxyServer(
        HOSTNAME, "127.0.0.1", port=0,
        upstream_port=upstream.port, cert_dir=tmp_path / "certs",
    )
    thread = threading.Thread(target=server.serve, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            probe = socket.create_connection(("127.0.0.1", server.port), timeout=0.5)
            probe.close()
            break
        except OSError:
            time.sleep(0.05)
    else:
        server.stop()
        pytest.fail("proxy never started listening")
    assert thread.is_alive()
    server.stop()  # external stop unblocks serve()
    thread.join(timeout=5)
    assert not thread.is_alive()


# -- ensure_cert ---------------------------------------------------------------


def test_ensure_cert_creates_valid_pair(tmp_path):
    cert_path, key_path = ensure_cert(tmp_path)
    assert cert_path == tmp_path / "cert.pem"
    assert key_path == tmp_path / "key.pem"
    assert cert_path.is_file() and key_path.is_file()
    parsed = subprocess.run(
        ["openssl", "x509", "-in", str(cert_path), "-noout",
         "-subject", "-dates", "-ext", "subjectAltName"],
        capture_output=True, text=True, check=True,
    ).stdout
    assert "CN = localhost" in parsed or "CN=localhost" in parsed
    assert "DNS:localhost" in parsed
    assert "127.0.0.1" in parsed
    assert "0:0:0:0:0:0:0:1" in parsed  # ::1, printed expanded by openssl
    assert key_path.stat().st_mode & 0o077 == 0  # not group/world readable


def test_ensure_cert_is_idempotent(tmp_path):
    ensure_cert(tmp_path)
    first = ((tmp_path / "cert.pem").read_bytes(), (tmp_path / "key.pem").read_bytes())
    cert_path, key_path = ensure_cert(tmp_path)
    assert (cert_path.read_bytes(), key_path.read_bytes()) == first


def test_R20_ensure_cert_refuses_symlinked_targets_without_touching_them(
        tmp_path):
    """R20-P2: cert_paths() resolved the links, so openssl wrote THROUGH a
    planted ``key.pem``/``cert.pem`` symlink (an arbitrary-file overwrite).
    Generation must refuse the link and leave its target untouched."""
    directory = tmp_path / "certs"
    directory.mkdir()
    victims = {}
    for name in ("cert.pem", "key.pem"):
        victim = tmp_path / f"{name}.victim"
        victim.write_bytes(b"DO NOT TOUCH")
        victims[name] = victim
        (directory / name).symlink_to(victim)
    with pytest.raises(WptError, match="symbolic link"):
        ensure_cert(directory)
    for name, victim in victims.items():
        assert victim.read_bytes() == b"DO NOT TOUCH", name
        assert (directory / name).is_symlink()


def test_R20_ensure_cert_refuses_a_fifo_without_blocking(tmp_path):
    """R20-P2: openssl with ``-keyout <fifo>`` blocked past 3 s with no
    way for --deadline to end it.  A non-regular target is refused before
    any subprocess starts."""
    directory = tmp_path / "certs"
    directory.mkdir()
    os.mkfifo(directory / "key.pem")
    started = time.monotonic()
    with pytest.raises(WptError, match="not a regular file"):
        ensure_cert(directory)
    assert time.monotonic() - started < 2.0


def test_R20_ensure_cert_bounds_openssl_and_leaves_no_temp(
        tmp_path, monkeypatch):
    """R20-P2: a wedged openssl had no timeout; the generation is bounded
    and every temp name is removed on the failure path."""
    import wpt.dnsoverride as dnsoverride

    def _wedge(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("openssl", 0.1)

    monkeypatch.setattr(dnsoverride.subprocess, "run", _wedge)
    directory = tmp_path / "certs"
    with pytest.raises(WptError, match="did not finish"):
        ensure_cert(directory, timeout_s=0.1)
    assert sorted(p.name for p in directory.iterdir()) == []


def test_R25_cert_temp_is_journaled_before_creation(tmp_path, monkeypatch):
    """R25-P2: ``mkstemp`` created ``.cert.pem.tmp-*`` before its name was
    returned, so a stop on that boundary left residue.  The candidate enters
    the journal before ``O_CREAT|O_EXCL`` and the caller's finally unlinks
    every journaled name."""
    import wpt.dnsoverride as dnsoverride
    from wpt.types import StopRequested

    real_open = dnsoverride.os.open

    def _stopping_open(path, *args, **kwargs):
        fd = real_open(path, *args, **kwargs)
        if ".tmp-" in str(path):
            dnsoverride.os.close(fd)
            raise StopRequested("stop at certificate temp creation")
        return fd

    monkeypatch.setattr(dnsoverride.os, "open", _stopping_open)
    with pytest.raises(StopRequested):
        ensure_cert(tmp_path / "certs", timeout_s=5)
    assert not list((tmp_path / "certs").glob(".*.tmp-*"))


def test_R20_proxy_request_body_is_exact_and_bounded_under_one_deadline():
    """R20-P2: ``rfile.read(length)`` had only a per-read timeout (a 1 B
    drip reset it forever), never checked the received length (a half-closed
    short upload was forwarded as a complete POST), and ignored the proxy's
    configured body ceiling.  Exact length, one absolute deadline and 413 are
    the handler contract; a None answer means the caller never forwards."""
    import email.message

    from wpt.dnsoverride import _ProxyHandler

    class _Proxy:
        _timeout = 0.25
        _max_request_bytes = 1024

    def _handler(headers, left):
        handler = object.__new__(_ProxyHandler)
        handler.headers = headers
        handler.rfile = left.makefile("rb")
        handler.connection = left
        handler.server = SimpleNamespace(proxy=_Proxy())
        sent: list[tuple[int, str]] = []
        handler.send_error = lambda code, message=None, explain=None: \
            sent.append((code, message or ""))
        return handler, sent

    def _headers(length: int) -> email.message.Message:
        message = email.message.Message()
        message["Content-Length"] = str(length)
        return message

    # A short, half-closed body: 400 and nothing to forward.
    left, right = socket.socketpair()
    try:
        handler, sent = _handler(_headers(10), left)
        right.sendall(b"abc")
        right.shutdown(socket.SHUT_WR)
        assert handler._read_request_body() is None
        assert [code for code, _message in sent] == [400]
    finally:
        left.close()
        right.close()

    # A 1-byte drip cannot reset the socket timeout forever: one absolute
    # deadline from request start ends it (408) in about 0.25 s.
    left, right = socket.socketpair()
    try:
        handler, sent = _handler(_headers(100), left)
        right.sendall(b"x")
        started = time.monotonic()
        assert handler._read_request_body() is None
        elapsed = time.monotonic() - started
        assert [code for code, _message in sent] == [408]
        assert elapsed < 1.5, elapsed
    finally:
        left.close()
        right.close()

    # A declared body above the configured ceiling is 413 BEFORE buffering.
    left, right = socket.socketpair()
    try:
        handler, sent = _handler(_headers(2048), left)
        assert handler._read_request_body() is None
        assert [code for code, _message in sent] == [413]
    finally:
        left.close()
        right.close()


def _write_expired_pair(directory):
    """A real expired cert/key pair (openssl ca with 2020 dates)."""
    directory.mkdir(parents=True, exist_ok=True)
    key = directory / "key.pem"
    csr = directory / "req.pem"
    cert = directory / "cert.pem"
    subprocess.run(
        ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(csr), "-subj", "/CN=localhost"],
        check=True, capture_output=True, text=True)
    config = directory / "ca.cnf"
    config.write_text(
        "[ca]\ndefault_ca=CA_default\n[CA_default]\n"
        f"dir={directory}\ndatabase={directory / 'index.txt'}\n"
        f"new_certs_dir={directory}\nserial={directory / 'serial'}\n"
        "default_md=sha256\npolicy=policy_any\n"
        "[policy_any]\ncommonName=supplied\n", encoding="utf-8")
    (directory / "index.txt").write_text("", encoding="utf-8")
    (directory / "serial").write_text("01\n", encoding="utf-8")
    subprocess.run(
        ["openssl", "ca", "-batch", "-selfsign", "-config", str(config),
         "-keyfile", str(key), "-in", str(csr), "-out", str(cert),
         "-startdate", "20200101000000Z", "-enddate", "20200102000000Z"],
        check=True, capture_output=True, text=True)
    return cert, key


def test_R16_an_expired_certificate_is_regenerated_not_reused(tmp_path):
    """R16-P1: the shipped .wpt-cert outlived its 7 days and every browser
    refused the proxy.  An existing but expired pair is regenerated (and a
    near-expiry pair is treated the same); only a live, key-matched pair is
    reused."""
    expired_cert, expired_key = _write_expired_pair(tmp_path / "expired")
    before = (expired_cert.read_bytes(), expired_key.read_bytes())
    cert_path, key_path = ensure_cert(tmp_path / "expired")
    assert cert_path == expired_cert and key_path == expired_key
    assert (cert_path.read_bytes(), key_path.read_bytes()) != before
    checked = subprocess.run(
        ["openssl", "x509", "-in", str(cert_path), "-noout", "-checkend",
         "86400"], capture_output=True, text=True)
    assert checked.returncode == 0, checked.stdout + checked.stderr
    assert key_path.stat().st_mode & 0o077 == 0


def test_R12_idn_location_and_cookie_rewrite_accept_both_host_forms():
    """R12-P2-19: the URL regex used ``encoded_host`` but Location/Set-Cookie
    used the raw Unicode host, so a punycode Location was never rewritten
    (and the reverse).  Both spellings now match."""
    server = ProxyServer("bücher.example", "203.0.113.7", port=0)
    server._origin_prefix = "https://localhost:8443"

    assert server._rewrite_location(
        "https://xn--bcher-kva.example/x") == "https://localhost:8443/x"
    assert server._rewrite_location(
        "https://bücher.example/x") == "https://localhost:8443/x"
    assert server._rewrite_set_cookie(
        "sid=1; Domain=.xn--bcher-kva.example; Path=/") == \
        "sid=1; Domain=.localhost; Path=/"
    assert server._rewrite_set_cookie(
        "sid=1; domain=bücher.example; Path=/") == \
        "sid=1; domain=localhost; Path=/"


def test_R13_idn_body_rewrites_both_host_spellings():
    """R13-P2-19: the body pattern was built from ``encoded_host`` only, so
    a raw-Unicode URL inside a page was left byte-identical and bypassed the
    override.  Both spellings match, and a longer hostname never does."""
    server = ProxyServer("bücher.example", "203.0.113.7", port=0)
    server._origin_prefix = "https://localhost:8443"
    data = (
        b'<a href="https://xn--bcher-kva.example/x">a</a>'
        b'<a href="https://b\xc3\xbccher.example/y">b</a>'
        b'<a href="https://xn--bcher-kva.example.invalid/z">c</a>'
    )
    out = server._rewrite_body(data)
    assert b"https://localhost:8443/x" in out
    assert b"https://localhost:8443/y" in out
    assert b"xn--bcher-kva.example.invalid" in out


def test_R13_cookie_domain_suffix_does_not_match_a_longer_domain():
    r"""R13-P2-19: ``(?![\w-])`` allowed a dot, so ``Domain=.site.example.invalid``
    was rewritten to ``localhost.evil``.  A dot is part of the hostname."""
    server = ProxyServer("bücher.example", "203.0.113.7", port=0)
    server._origin_prefix = "https://localhost:8443"
    for evil in ("sid=1; Domain=.xn--bcher-kva.example.invalid; Path=/",
                 "sid=1; Domain=.bücher.example.invalid; Path=/"):
        assert server._rewrite_set_cookie(evil) == evil
    assert server._rewrite_set_cookie(
        "sid=1; Domain=.bücher.example; Path=/") == \
        "sid=1; Domain=.localhost; Path=/"


def test_R18_idn_uppercase_configuration_rewrites_lowercase_body():
    """R18-P2: the body regex is BYTES, where ``re.IGNORECASE`` is ASCII
    only.  A configured ``TÄST.EXAMPLE`` left a page's lowercase ``täst.example`` URL
    byte-identical, so the browser left the override.  The hostname is
    normalized once (NFC + lower) and both spellings are in host_forms."""
    server = ProxyServer("TÄST.EXAMPLE", "203.0.113.7", port=0)
    server._origin_prefix = "https://localhost:8443"
    out = server._rewrite_body(
        '<a href="https://täst.example/x">a</a>'
        '<a href="https://TÄST.EXAMPLE/y">b</a>'.encode("utf-8"))
    assert b"https://localhost:8443/x" in out
    assert b"https://localhost:8443/y" in out


def test_R19_idn_lowercase_configuration_rewrites_uppercase_body():
    """R19-P2: the inverse of R18 — with a LOWERCASE configured host, both
    Unicode forms were lowercase, and the bytes regex's IGNORECASE is
    ASCII-only, so an UPPERCASE body URL was never rewritten.  host_forms
    now carries Unicode upper and NFC/NFD spellings."""
    server = ProxyServer("täst.example", "203.0.113.7", port=0)
    server._origin_prefix = "https://localhost:8443"
    out = server._rewrite_body(
        '<a href="https://TÄST.EXAMPLE/x">a</a>'
        '<a href="https://täst.example/y">b</a>'
        '<a href="https://ta\u0308st.example/z">c</a>'.encode("utf-8"))
    assert b"https://localhost:8443/x" in out
    assert b"https://localhost:8443/y" in out
    assert b"https://localhost:8443/z" in out
    # The Location/cookie regexes share the SAME forms owner.
    assert server._rewrite_location("https://TÄST.EXAMPLE/a") == \
        "https://localhost:8443/a"


def test_R25_mixed_case_unicode_body_links_are_rewritten():
    """R25-P2: host_forms carried all-lower and all-upper spellings only,
    while the body regex ran over BYTES (ASCII IGNORECASE).  A mixed-case
    Unicode page link ``mÄrchenbücher.example`` was served byte-identical,
    so the browser left the override.  The body rewrite now runs the same
    Unicode-aware alternation as Location/cookie."""
    server = ProxyServer("märchenbücher.example", "203.0.113.7", port=0)
    server._origin_prefix = "https://localhost:8443"
    body = (
        '<a href="https://mÄrchenbücher.example/mixed">m</a>'
        '<a href="https://MÄRCHENBÜCHER.EXAMPLE/upper">u</a>'
        '<a href="https://märchenbücher.example/lower">l</a>'
        '<a href="https://märchenbücher.example.invalid/evil">e</a>'
    ).encode("utf-8")
    out = server._rewrite_body(body)
    assert b"https://localhost:8443/mixed" in out
    assert b"https://localhost:8443/upper" in out
    assert b"https://localhost:8443/lower" in out
    assert b"m\xc3\xa4rchenb\xc3\xbccher.example.invalid" in out


def test_R18_proxy_205_is_bodyless():
    """R18-P2: RFC 9110 §15.3.6 terminates 205 at the header section; the
    proxy's upstream reader treated it as close-delimited and waited for
    the origin (then answered 502)."""
    import io

    from wpt.dnsoverride import _read_upstream_body

    fp = io.BytesIO(b"should never be read")
    assert _read_upstream_body(fp, "GET", 205, []) == b""
    # A 204/304 and HEAD stay bodyless through the SAME shared owner.
    assert _read_upstream_body(io.BytesIO(b"x"), "GET", 204, []) == b""
    assert _read_upstream_body(io.BytesIO(b"x"), "HEAD", 200, []) == b""


def test_R14_idn_override_gate_matches_punycode_dial():
    """R14-P2: the gate stored the raw Unicode host while urllib3 presents
    punycode, so ``--override-ip`` silently dialed real DNS for an IDN
    site.  The owner now normalizes to IDNA and the real session dials the
    override for the punycode pool."""
    session = resolve_session("bücher.example", "203.0.113.7")
    adapter = session.get_adapter("https://xn--bcher-kva.example/")
    pool = adapter.poolmanager._new_pool(
        "https", "xn--bcher-kva.example", 443, None)
    assert pool.conn_kw["dial_ip"] == "203.0.113.7"
    assert pool.conn_kw["dial_port"] == 443
    # a different host is never overridden
    other = adapter.poolmanager._new_pool("https", "other.example", 443, None)
    assert "dial_ip" not in other.conn_kw


def test_R14_scheme_relative_urls_use_the_same_host_gate():
    """R14-P2: body/Location rewriting matched only an absolute
    ``https?://host``, so ``//host/path`` escaped to the real origin even
    though it is the same host.  The scheme is now optional; a longer or
    external host still never matches."""
    server = ProxyServer("local.test", "203.0.113.7", port=0)
    server._origin_prefix = "https://localhost:8443"
    assert server._rewrite_body(b'<img src="//local.test/x">') == \
        b'<img src="https://localhost:8443/x">'
    assert server._rewrite_body(b'<img src="//local.test.evil/x">') == \
        b'<img src="//local.test.evil/x">'
    assert server._rewrite_location("//local.test/x") == \
        "https://localhost:8443/x"
    assert server._rewrite_location("//other.example/x") == "//other.example/x"


def test_R23_scheme_relative_rewrite_has_a_left_boundary():
    """R23-P2: the optional scheme made the pattern match the ``//`` inside
    ``ftp://host``/``ws://host`` and a nested path (``/a//host``), corrupting
    a different origin or a path segment.  A bare ``//host`` still rewrites,
    but only at a real left boundary."""
    server = ProxyServer("local.test", "203.0.113.7", port=0)
    server._origin_prefix = "https://localhost:8443"
    untouched_body = (
        b"ftp://local.test/a",
        b"ws://local.test/a",
        b"wss://local.test/a",
        b"https://example.com/a//local.test/b",
        b"/a//local.test/b",
    )
    for data in untouched_body:
        assert server._rewrite_body(data) == data, data
    untouched_location = (
        "ftp://local.test/a",
        "ws://local.test/a",
        "wss://local.test/a",
        "https://example.com/a//local.test/b",
        "/a//local.test/b",
    )
    for value in untouched_location:
        assert server._rewrite_location(value) == value, value
    # real boundaries still rewrite
    for data in (b"//local.test/a", b'"//local.test/a"', b"=//local.test/a"):
        assert server._rewrite_body(data) == data.replace(
            b"//local.test", b"https://localhost:8443"), data
    for value in ("//local.test/a", '"//local.test/a"', "=//local.test/a"):
        assert server._rewrite_location(value) == value.replace(
            "//local.test", "https://localhost:8443"), value


def test_R21_a_dripped_head_rides_the_absolute_deadline(
        upstream, tmp_path, client):
    """R21-P2: status/header lines used ``fp.readline`` with one armed
    socket timeout; one byte per 0.1 s kept resetting it.  The re-armed
    byte loop answers 502 within the proxy's budget."""
    server = ProxyServer(
        HOSTNAME, "127.0.0.1", port=0, upstream_port=upstream.port,
        cert_dir=tmp_path / "proxy-certs", timeout=0.4,
        max_body_bytes=1024 * 1024,
    )
    port = server.start()
    try:
        started = time.monotonic()
        response = client.get(f"https://localhost:{port}/headdrip",
                              verify=False, timeout=5)
        elapsed = time.monotonic() - started
        assert response.status_code == 502
        assert elapsed < 2.0, elapsed
    finally:
        server.stop()


def test_R21_gzip_output_is_capped_before_buffering(
        upstream, tmp_path, client):
    """R21-P2: 20 MiB gzipped into ~20 KiB passed the compressed-wire cap
    and was unbounded-decompressed into a 200.  The decoded size is capped
    at the proxy's configured body bound -> 502."""
    server = ProxyServer(
        HOSTNAME, "127.0.0.1", port=0, upstream_port=upstream.port,
        cert_dir=tmp_path / "proxy-certs", timeout=5.0,
        max_body_bytes=30000,
    )
    port = server.start()
    try:
        response = client.get(f"https://localhost:{port}/gzipbomb",
                              verify=False, timeout=10)
        assert response.status_code == 502
    finally:
        server.stop()


def test_R21_eof_after_the_zero_chunk_is_a_truncated_body(
        upstream, tmp_path, client):
    """R21-P2: EOF after ``0\\r\\n`` (no final empty trailer line) was read
    as a complete message and forwarded as a 200.  RFC 9112 requires the
    CRLF; the truncation is the existing 502 path."""
    server = ProxyServer(
        HOSTNAME, "127.0.0.1", port=0, upstream_port=upstream.port,
        cert_dir=tmp_path / "proxy-certs", timeout=5.0,
        max_body_bytes=1024 * 1024,
    )
    port = server.start()
    try:
        response = client.get(f"https://localhost:{port}/truncatedtrailer",
                              verify=False, timeout=10)
        assert response.status_code == 502
    finally:
        server.stop()


def test_proxy_start_never_looks_up_a_canonical_hostname(tmp_path,
                                                          monkeypatch):
    """The local listener must not inherit HTTPServer's unbounded
    socket.getfqdn() call: a stalled reverse lookup kept the proxy from
    writing its receipt on macOS."""
    import wpt.dnsoverride as dnsoverride

    def _must_not_lookup(host):
        raise AssertionError(f"getfqdn({host!r}) during proxy start")

    monkeypatch.setattr(dnsoverride.socket, "getfqdn", _must_not_lookup)
    server = ProxyServer("local.test", "127.0.0.1", port=0,
                         cert_dir=tmp_path / "certs")
    try:
        assert server.start() > 0
    finally:
        server.stop()


def test_R24_proxy_advertised_origin_is_the_rewrite_origin(tmp_path):
    """R24-P1: the receipt/log advertised 127.0.0.1 while body/Location
    rewrites and cookie Domain used localhost.  A host-only cookie set on the
    advertised origin was never sent back to the rewritten origin, so
    WordPress's absolute login redirect dropped the session.  ONE owner."""
    server = ProxyServer("local.test", "127.0.0.1", port=0,
                         cert_dir=tmp_path / "certs")
    port = server.start()
    try:
        url = server.browser_url()
        origin = f"https://localhost:{port}"
        assert url == origin + "/"
        assert server.origin == origin
        assert server._rewrite_location(
            "https://local.test/next") == origin + "/next"
        assert origin.encode() in server._rewrite_body(
            b'<a href="https://local.test/next">')
        assert server._rewrite_set_cookie(
            "sid=abc; Domain=local.test; Path=/") == \
            "sid=abc; Domain=localhost; Path=/"
        assert server._rewrite_set_cookie(
            "sid=abc; Path=/") == "sid=abc; Path=/"  # host-only untouched
        assert "127.0.0.1" not in url
    finally:
        server.stop()


def test_R24_a_key_matched_wrong_host_certificate_is_regenerated(tmp_path):
    """R24-P2: ``_cert_pair_usable`` proved only expiry and key-match, so a
    7-day key-matched CN=wrong.example pair was reused and every browser
    failed with a hostname mismatch.  The exact localhost subject/SANs are
    part of the reuse proof."""
    directory = tmp_path / "wrong-host"
    directory.mkdir()
    key = directory / "key.pem"
    cert = directory / "cert.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256",
         "-days", "7", "-nodes", "-keyout", str(key), "-out", str(cert),
         "-subj", "/CN=wrong.example",
         "-addext", "subjectAltName=DNS:wrong.example"],
        check=True, capture_output=True, text=True,
    )
    before = (cert.read_bytes(), key.read_bytes())
    cert_path, key_path = ensure_cert(directory)
    assert (cert_path.read_bytes(), key_path.read_bytes()) != before
    checked = subprocess.run(
        ["openssl", "x509", "-in", str(cert_path), "-noout",
         "-checkhost", "localhost"], capture_output=True, text=True)
    assert checked.returncode == 0, checked.stdout + checked.stderr
    for address in ("127.0.0.1", "::1"):
        checked = subprocess.run(
            ["openssl", "x509", "-in", str(cert_path), "-noout",
             "-checkip", address], capture_output=True, text=True)
        assert checked.returncode == 0, checked.stdout + checked.stderr


@pytest.mark.parametrize("route", ["/gzipmulti", "/gziptruncated"])
def test_R24_multi_member_and_truncated_gzip_are_forwarded_not_served_as_200(
        proxy, client, route):
    """R24-P2: ``_decode_content`` ignored ``decomp.eof``/``unused_data``.
    A multi-member body re-served only its FIRST member as plaintext, and a
    truncated body re-served partial plaintext as a valid 200.  Both are
    passed through byte-identically with their Content-Encoding."""
    import gzip as _gzip

    port = proxy.start()
    response = client.get(f"https://localhost:{port}{route}",
                          verify=False, timeout=5, stream=True)
    try:
        body = response.raw.read(decode_content=False)
        assert response.status_code == 200
        assert response.headers.get("Content-Encoding") == "gzip"
        if route == "/gzipmulti":
            assert body == (_gzip.compress(b"FIRST-MEMBER;", mtime=0)
                            + _gzip.compress(b"SECOND-MEMBER;", mtime=0))
        else:
            assert body == _gzip.compress(
                b"HELLO WORLD" * 100, mtime=0)[:-20]
    finally:
        response.close()
