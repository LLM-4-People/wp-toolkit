"""Pure tests for doctor's TLS certificate and HTTPS-policy helpers.

``_certificate_row`` is the whole verdict function: the network path only
dials and hands it a certificate dict, so synthetic ``getpeercert()``
shapes pin PASS/WARN/FAIL without a socket.  ``_https_policy_check`` is
driven through ``tests.fakes.FakeSession`` with canned response headers,
and ``_tls_check`` is exercised through a monkeypatched
``wpt.doctor._tls_peer_cert`` to assert the dial target (``--override-ip``)
and the one unverified retry.  No network, no sleeps.
"""

import socket
import ssl
import threading
import time

import pytest
import requests

import wpt.doctor
import wpt.php_probe
from tests.fakes import FakeResponse, FakeSession, FakeSource
from wpt.cli import Ctx
from wpt.settings import load

NOW = ssl.cert_time_to_seconds("Oct 19 12:00:00 2026 GMT")


def _cert(not_after, *, sans=("site.test", "www.site.test"), cn="site.test",
          issuer="Test CA", organization=None):
    subject = [("commonName", cn)]
    if organization:
        subject.append(("organizationName", organization))
    cert = {
        "subject": (tuple(subject),),
        "issuer": ((("commonName", issuer),),),
        "notAfter": not_after,
    }
    if sans is not None:
        cert["subjectAltName"] = tuple(("DNS", name) for name in sans)
    return cert


VALID = _cert("Nov  1 12:00:00 2026 GMT")
FAR = _cert("Nov  1 12:00:00 2099 GMT")


def _ctx(**overrides):
    kwargs = dict(
        source="ftp://h:2121",
        settings=load(),
        wp_url="https://site.test",
    )
    kwargs.update(overrides)
    return Ctx(**kwargs)


def _response(status=200, *, location=None, hsts=None, url=None):
    response = FakeResponse(status, "")
    headers = {}
    if location is not None:
        headers["Location"] = location
    if hsts is not None:
        headers["Strict-Transport-Security"] = hsts
    response.headers = headers
    if url is not None:
        response.url = url
    return response


# ------------------------------------------------------- certificate verdict


def test_certificate_verified_valid_is_pass():
    row = wpt.doctor._certificate_row("site.test", VALID, True, None, 7, NOW)

    assert row["name"] == "tls certificate"
    assert row["result"] == "PASS"
    assert "SAN site.test, www.site.test" in row["detail"]
    assert "issuer Test CA" in row["detail"]
    assert "expires 2026-11-01" in row["detail"]
    assert "(13 day(s) left)" in row["detail"]


def test_certificate_expiring_inside_warn_days_is_warn():
    row = wpt.doctor._certificate_row("site.test", VALID, True, None, 14, NOW)

    assert row["result"] == "WARN"
    assert "expires in 13 day(s)" in row["detail"]
    assert "SAN site.test, www.site.test" in row["detail"]


def test_certificate_expired_is_fail_even_when_verified():
    expired = _cert("Oct  1 12:00:00 2026 GMT")

    row = wpt.doctor._certificate_row("site.test", expired, True, None, 14, NOW)

    assert row["result"] == "FAIL"
    assert row["detail"].startswith("certificate expired for site.test:")
    assert "expired 2026-10-01" in row["detail"]


def test_certificate_mismatch_carries_san_facts_not_full_subject():
    cert = _cert("Nov  1 12:00:00 2026 GMT", organization="Secret Org")
    error = "certificate verify failed: Hostname mismatch"

    row = wpt.doctor._certificate_row(
        "site.test", cert, False, error, 14, NOW)

    assert row["result"] == "FAIL"
    assert row["detail"].startswith(
        "certificate does not verify for site.test: "
        "certificate verify failed: Hostname mismatch; ")
    assert "SAN site.test, www.site.test" in row["detail"]
    assert "issuer Test CA" in row["detail"]
    assert "Secret Org" not in row["detail"]


def test_certificate_missing_is_fail():
    row = wpt.doctor._certificate_row("site.test", None, False, None, 14, NOW)

    assert row["result"] == "FAIL"
    assert row["detail"] == "no certificate presented for site.test"


def test_certificate_without_san_falls_back_to_subject_cn():
    cert = _cert("Nov  1 12:00:00 2026 GMT", sans=None, cn="site.test")

    row = wpt.doctor._certificate_row("site.test", cert, True, None, 7, NOW)

    assert row["result"] == "PASS"
    assert "CN site.test" in row["detail"]
    assert "SAN" not in row["detail"]


# ------------------------------------------------------------- TLS dial path


def test_tls_check_dials_override_ip_and_verified_host(monkeypatch):
    calls = []

    def _peer(dial_host, host, port, timeout_s, *, verify, deadline=None):
        calls.append((dial_host, host, port, timeout_s, verify))
        return FAR

    monkeypatch.setattr(wpt.doctor, "_tls_peer_cert", _peer)
    ctx = _ctx(override_ip="192.0.2.5")

    row = wpt.doctor._tls_check(ctx)

    assert row["result"] == "PASS"
    assert calls == [("192.0.2.5", "site.test", 443,
                      ctx.settings.http.timeout_s, True)]


def test_tls_check_retries_once_unverified_on_certificate_error(monkeypatch):
    calls = []

    def _peer(dial_host, host, port, timeout_s, *, verify, deadline=None):
        calls.append(verify)
        if verify:
            raise ssl.SSLCertVerificationError("hostname mismatch")
        return FAR

    monkeypatch.setattr(wpt.doctor, "_tls_peer_cert", _peer)
    ctx = _ctx()

    row = wpt.doctor._tls_check(ctx)

    assert row["result"] == "FAIL"
    assert row["detail"].startswith(
        "certificate does not verify for site.test: ")
    assert "hostname mismatch" in row["detail"]
    assert "SAN site.test, www.site.test" in row["detail"]
    assert calls == [True, False]


def test_tls_check_without_wp_url_is_not_checked(monkeypatch):
    def _never(*args, **kwargs):
        raise AssertionError("must not dial without a URL")

    monkeypatch.setattr(wpt.doctor, "_tls_peer_cert", _never)
    ctx = _ctx(wp_url=None)

    row = wpt.doctor._tls_check(ctx)

    assert row["result"] == "FAIL"
    assert row["detail"] == "no --wp-url to check"


# ------------------------------------------------------------ HTTPS policy


def test_https_redirect_and_hsts_is_pass():
    session = FakeSession([
        _response(301, location="https://site.test/"),
        _response(200, hsts="max-age=31536000", url="https://site.test/"),
    ])
    ctx = _ctx()

    row = wpt.doctor._https_policy_check(session, ctx)

    assert row == {
        "name": "https policy",
        "result": "PASS",
        "detail": "HTTP redirects to https://site.test/; "
                  "HSTS max-age=31536000",
    }
    http_url, http_kwargs = session.gets[0]
    https_url, https_kwargs = session.gets[1]
    assert http_url == "http://site.test/"
    assert http_kwargs["allow_redirects"] is False
    assert http_kwargs["verify"] is ctx.settings.http.verify_tls
    assert http_kwargs["timeout"] == ctx.settings.http.timeout_s
    assert https_url == "https://site.test/"
    assert https_kwargs["allow_redirects"] is True
    assert https_kwargs["verify"] is ctx.settings.http.verify_tls


def test_https_http_200_is_warn_even_with_hsts():
    session = FakeSession([
        _response(200),
        _response(200, hsts="max-age=3600", url="https://site.test/"),
    ])

    row = wpt.doctor._https_policy_check(session, _ctx())

    assert row["result"] == "WARN"
    assert "HTTP serves content; HTTPS is not forced" in row["detail"]
    assert "HSTS max-age=3600" in row["detail"]


def test_https_non_https_redirect_names_the_location():
    session = FakeSession([
        _response(302, location="http://site.test/home"),
        _response(200, hsts="max-age=3600", url="https://site.test/"),
    ])

    row = wpt.doctor._https_policy_check(session, _ctx())

    assert row["result"] == "WARN"
    assert "HTTP serves content; HTTPS is not forced" in row["detail"]
    assert "redirects to http://site.test/home" in row["detail"]


def test_https_hsts_absent_is_warn():
    session = FakeSession([
        _response(301, location="https://site.test/"),
        _response(200, url="https://site.test/"),
    ])

    row = wpt.doctor._https_policy_check(session, _ctx())

    assert row["result"] == "WARN"
    assert "HTTPS works but HSTS is absent" in row["detail"]


def test_https_request_failure_is_warn_and_redacted():
    session = FakeSession([
        _response(301, location="https://site.test/"),
        requests.ConnectionError("transport failed token=abcd"),
    ])

    row = wpt.doctor._https_policy_check(session, _ctx())

    assert row["result"] == "WARN"
    assert row["detail"].startswith("HTTPS request failed: ")
    assert "token=***" in row["detail"]
    assert "abcd" not in row["detail"]


def test_https_status_failure_is_warn():
    session = FakeSession([
        _response(301, location="https://site.test/"),
        _response(503, url="https://site.test/"),
    ])

    row = wpt.doctor._https_policy_check(session, _ctx())

    assert row["result"] == "WARN"
    assert row["detail"] == (
        "HTTPS request failed: HTTP 503 at https://site.test/")


def test_https_explicit_port_and_verify_setting():
    ctx = _ctx(wp_url="https://site.test:8443")
    ctx.settings.http.verify_tls = True
    session = FakeSession([
        _response(301, location="https://site.test:8443/"),
        _response(200, hsts="max-age=3600", url="https://site.test:8443/"),
    ])

    row = wpt.doctor._https_policy_check(session, ctx)

    assert row["result"] == "PASS"
    assert session.gets[0][0] == "http://site.test:8443/"
    assert session.gets[1][0] == "https://site.test:8443/"
    assert session.gets[0][1]["verify"] is True
    assert session.gets[1][1]["verify"] is True


def test_https_policy_without_wp_url_is_not_checked():
    session = FakeSession()

    row = wpt.doctor._https_policy_check(session, _ctx(wp_url=None))

    assert row["result"] == "FAIL"
    assert row["detail"] == "no --wp-url to check"
    assert session.gets == []


# ------------------------------------------------ triple-check round 8 (P1)


class _DripServer:
    """A server that drips one header byte at a time and never finishes.

    It sniffs the first byte: a TLS ClientHello starts with ``0x16`` and is
    wrapped with a throwaway local certificate; anything else is served as
    plain HTTP.  Accepts several sequential connections (doctor's HTTP and
    HTTPS policy rows).
    """

    def __init__(self, certdir, *, delay=0.03, connections=3):
        import socket
        import ssl
        import threading
        from wpt.dnsoverride import ensure_cert

        self.delay = delay
        cert, key = ensure_cert(certdir)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(connections)
        self.listener.settimeout(5)
        self.port = self.listener.getsockname()[1]
        self.connections = connections
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        for _ in range(self.connections):
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            try:
                conn.settimeout(5)
                first = conn.recv(1, socket.MSG_PEEK)
                if first == b"\x16":
                    conn = self.context.wrap_socket(conn, server_side=True)
                request = b""
                while b"\r\n\r\n" not in request:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    request += chunk
                conn.sendall(b"HTTP/1.1 200 OK\r\n")
                while True:
                    conn.sendall(b"X-Drip: a\r\n")
                    time.sleep(self.delay)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def close(self):
        try:
            self.listener.close()
        except OSError:
            pass
        self.thread.join(2)


def test_P1_doctor_site_get_is_bounded_by_the_absolute_deadline(tmp_path):
    """P1-04: a header byte every 30 ms kept ``_site_check`` alive past a
    0.25 s run deadline for as long as the peer dripped."""
    import time

    from wpt.deadline import Deadline

    server = _DripServer(tmp_path / "certs")
    session = requests.Session()
    session.trust_env = False
    session.verify = False
    ctx = _ctx(wp_url=f"http://127.0.0.1:{server.port}")
    try:
        started = time.monotonic()
        row = wpt.doctor._site_check(session, ctx, Deadline(0.25))
        elapsed = time.monotonic() - started
    finally:
        session.close()
        server.close()

    assert row["result"] == "FAIL"
    assert elapsed < 1.2, elapsed


def test_P1_doctor_https_policy_gets_share_the_absolute_deadline(tmp_path):
    """P1-04: both the HTTP and HTTPS policy GETs are bounded; the second
    gets only the run budget's remainder, never a fresh full timeout."""
    import time

    from wpt.deadline import Deadline

    server = _DripServer(tmp_path / "certs")
    session = requests.Session()
    session.trust_env = False
    session.verify = False
    ctx = _ctx(wp_url=f"https://127.0.0.1:{server.port}/")
    try:
        started = time.monotonic()
        row = wpt.doctor._https_policy_check(session, ctx, Deadline(0.25))
        elapsed = time.monotonic() - started
    finally:
        session.close()
        server.close()

    assert row["result"] == "WARN"
    assert "request failed" in row["detail"]
    assert elapsed < 1.5, elapsed


def test_P1_wporg_get_is_bounded_by_its_absolute_deadline(
        tmp_path, monkeypatch):
    """P1-04: WpOrgApi's GET used a per-read timeout; a drip outlived the
    doctor row's budget.  It now rides the shared bounded GET owner."""
    import time

    from wpt.audit import updates

    from wpt.types import DeadlineExceeded

    server = _DripServer(tmp_path / "certs")
    monkeypatch.setattr(updates, "_CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(
        updates, "_CORE_CHECK_URL",
        f"http://127.0.0.1:{server.port}/core/version-check/1.7/")
    monkeypatch.setattr(
        updates, "_cache_key", lambda url, form: "drip-test")
    session = requests.Session()
    session.trust_env = False
    try:
        started = time.monotonic()
        with pytest.raises(DeadlineExceeded):
            updates.WpOrgApi(
                session, 5, deadline=time.monotonic() + 0.25,
            ).latest_core_version()
        elapsed = time.monotonic() - started
    finally:
        session.close()
        server.close()

    assert elapsed < 1.2, elapsed


# ------------------------------------------------ triple-check round 9 (P1/P2)


def test_P1_doctor_tls_dns_resolution_is_bounded_by_the_run_deadline(
        monkeypatch):
    """P1: a libc getaddrinfo that never returns kept the TLS row alive
    for the resolver's full 2 s under a 0.25 s run budget."""
    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    release = threading.Event()

    def _slow(*args, **kwargs):
        # A resolver that never answers within the budget.  The Event lets
        # the test release the daemon worker instead of leaving it holding
        # the shared DNS-worker semaphore into the next test.
        release.wait(5)
        raise socket.gaierror("synthetic resolver stall")

    monkeypatch.setattr(wpt.php_probe.socket, "getaddrinfo", _slow)
    ctx = _ctx(wp_url="https://slow.example/")
    started = time.monotonic()
    budget = Deadline(0.25)
    try:
        with pytest.raises(DeadlineExceeded):
            wpt.doctor._guarded(
                "tls certificate", wpt.doctor._tls_check, ctx, budget,
                deadline=budget)
    finally:
        elapsed = time.monotonic() - started
        release.set()
        # Wait until every resolver slot is free again.
        wait_until = time.monotonic() + 2.0
        while time.monotonic() < wait_until:
            acquired = 0
            while wpt.php_probe._DNS_WORKERS.acquire(blocking=False):
                acquired += 1
            for _ in range(acquired):
                wpt.php_probe._DNS_WORKERS.release()
            if acquired == wpt.php_probe._DNS_WORKER_LIMIT:
                break
            time.sleep(0.01)
    assert elapsed < 1.0, elapsed


def test_P2_doctor_php_runtime_receives_the_run_deadline(monkeypatch):
    """P2: ``_php_runtime_check`` armed a fresh 15 s PhpProbe call after the
    run budget had already been spent; the probe must receive it."""
    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded, WptError

    captured = {}

    class _Probe:
        def __init__(self, *args, **kwargs):
            pass

        def call(self, *, deadline=None):
            captured["deadline"] = deadline
            if deadline is None:
                time.sleep(2.0)
            else:
                time.sleep(max(0.0, deadline - time.monotonic()))
            raise WptError("probe timed out")

        def destroy(self):
            pass

    monkeypatch.setattr(wpt.doctor, "PhpProbe", _Probe)
    ctx = _ctx()
    started = time.monotonic()
    budget = Deadline(0.25)
    try:
        with pytest.raises(DeadlineExceeded):
            wpt.doctor._guarded(
                "php runtime", wpt.doctor._php_runtime_check,
                ctx, FakeSource(), FakeSession(), True, budget,
                deadline=budget)
    finally:
        elapsed = time.monotonic() - started
    assert elapsed < 1.0, elapsed
    assert captured["deadline"] is not None
    assert captured["deadline"] <= budget.at


def test_P2_wire_headers_are_case_insensitive_for_doctor_lookups():
    """P2: the bounded transport lowercased headers while doctor looked up
    ``Location``/``Strict-Transport-Security``; a forced site read WARN."""
    status, headers = wpt.php_probe._parse_response_head(
        b"HTTP/1.1 301 Moved\r\n"
        b"location: https://site.test/\r\n"
        b"strict-transport-security: max-age=31536000\r\n\r\n")
    assert status == 301
    assert headers["Location"] == "https://site.test/"
    assert headers["Strict-Transport-Security"] == "max-age=31536000"
    assert headers["LOCATION"] == "https://site.test/"


def test_R12_duplicate_headers_are_combined_not_last_wins():
    """R12-P2-5: ``Strict-Transport-Security: max-age=0`` followed by
    ``max-age=31536000`` kept only the last value, so a non-conforming
    (ignored) header read as a forced site.  Repeated fields combine with
    ", " and the policy parser then rejects the duplicate max-age."""
    from wpt.doctor import _hsts_policy

    status, headers = wpt.php_probe._parse_response_head(
        b"HTTP/1.1 200 OK\r\n"
        b"Strict-Transport-Security: max-age=0\r\n"
        b"Strict-Transport-Security: max-age=31536000\r\n"
        b"X-Dup: a\r\nX-Dup: b\r\n\r\n")
    assert status == 200
    assert headers["Strict-Transport-Security"] == \
        "max-age=0, max-age=31536000"
    assert headers["X-Dup"] == "a, b"
    max_age, problem = _hsts_policy(headers["Strict-Transport-Security"])
    assert max_age is None
    assert problem is not None


def test_P2_doctor_redirect_loop_is_a_fail_not_a_pass():
    """P2: at the redirect ceiling the transport returned the final 302, so
    doctor answered PASS for a loop."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class _Loop(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 — http.server's API
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Loop)
    import threading

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    session = requests.Session()
    session.trust_env = False
    ctx = _ctx(wp_url=f"http://127.0.0.1:{server.server_address[1]}/")
    try:
        row = wpt.doctor._site_check(session, ctx)
    finally:
        session.close()
        server.shutdown()
        server.server_close()
        thread.join(2)

    assert row["result"] == "FAIL"
    assert "redirect" in row["detail"].lower()
