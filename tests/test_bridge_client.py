"""Unit tests for the bridge client (wpt.wpbridge.client) — no network, no PHP.

FakeSource/FakeResponse/FakeSession live in tests/fakes.py (shared doubles);
tokens are read back out of the uploaded bridge bytes, so the tests assert
against exactly what is on the (fake) server.
"""

import base64
import json
import logging
import re
from pathlib import Path
import time

import pytest
import requests

from tests.fakes import FakeResponse, FakeSession, FakeSource
from wpt.deadline import Deadline
from wpt.settings import BridgeSettings
from wpt.types import BridgeError, DeadlineExceeded, SourceError, StopRequested
from wpt.wpbridge.client import Bridge, _refusal_label

REPO = Path(__file__).resolve().parents[1]
BRIDGE_SOURCE = REPO / "wpt" / "wpbridge" / "bridge.php"
WEBROOT = "domains/example.com/public_html"
SITE = "https://example.com"


# ------------------------------------------------------------------- helpers


def make(script=(), settings=None, webroot=WEBROOT):
    src = FakeSource()
    session = FakeSession(script)
    bridge = Bridge(src, session, webroot, settings or BridgeSettings(), SITE)
    return bridge, src, session


def ok_response(**payload):
    return FakeResponse(200, json.dumps({"ok": True, **payload}))


def err_response(**payload):
    body = {"ok": False, "error": "boom"}
    body.update(payload)
    return FakeResponse(200, json.dumps(body))


def nf_response():
    return FakeResponse(404, "nf")  # the bridge's plain-text auth 404


def site_404():
    return FakeResponse(404, "<html><body>404 Not Found</body></html>")


def selfdestruct_server(src):
    """Script item simulating the server side of selfdestruct: unlink + gone.

    FakeSource stores source paths AS GIVEN (webroot-relative since the
    live-FTP I4 fix), so the unlink pops the bare name."""
    def handler(method, url, kwargs):
        name = url.removeprefix(f"{SITE}/").partition("?")[0]
        src.files.pop(name, None)
        return FakeResponse(200, "gone")
    return handler


def token_of(src, endpoint):
    m = re.search(rb"\$wpt_token\s*=\s*'([0-9a-f]{32})'", src.files[endpoint])
    assert m, "token placeholder not substituted"
    return m.group(1).decode()


def expiry_of(src, endpoint):
    m = re.search(rb"\$wpt_expires\s*=\s*'(\d+)'", src.files[endpoint])
    assert m, "expiry placeholder not substituted"
    return int(m.group(1))


def name_of_url(url):
    """Deployed bridge filename as it appears in a request URL."""
    return url.removeprefix(f"{SITE}/").partition("?")[0]


def endpoint_of(name):
    """Source-side path of a deployed bridge filename — WEBROOT-RELATIVE:
    the bare name (sources prefix the webroot themselves; FakeSource
    stores paths as given)."""
    return name


def token_of_url(url):
    return url.partition("t=")[2].partition("&")[0]


def op_paths(src, op):
    return [p for _, o, p in src.ops if o == op]


# -------------------------------------------------------------------- ensure


def test_ensure_deploys_fresh_name_and_token_every_call():
    bridge, src, _ = make()
    e1 = bridge.ensure()
    e2 = bridge.ensure()
    assert e1 != e2
    for endpoint in (e1, e2):
        # WEBROOT-RELATIVE: the endpoint is the bare filename — Source ops
        # prepend the webroot themselves (live-FTP I4: "{webroot}/{name}"
        # double-prefixes and 553s on a real server).
        assert re.fullmatch(r"bridge-[0-9a-f]{8}\.php", endpoint)
    assert token_of(src, e1) != token_of(src, e2)


def test_ensure_endpoint_is_webroot_relative_for_prefixing_sources():
    """The live-FTP contract pin: a source that PREFIXES its webroot (the
    real FtpSource semantics — write_bytes(path) lands at {webroot}/{path})
    must receive the bare filename, so the deployed file is
    {webroot}/bridge-<8hex>.php exactly once."""
    class PrefixingSource:
        def __init__(self) -> None:
            self.files: dict[str, bytes] = {}
            self.root = WEBROOT
            self._endpoints: list[str] = []

        def write_bytes(self, path: str, data: bytes) -> None:
            self._endpoints.append(path)
            self.files[f"{self.root}/{path}"] = data

        def exists(self, path: str) -> bool:
            return f"{self.root}/{path}" in self.files

        def delete(self, path: str) -> None:
            self.files.pop(f"{self.root}/{path}", None)

        def close(self) -> None:  # pragma: no cover - teardown no-op
            pass

    src = PrefixingSource()
    bridge = Bridge(src, FakeSession([FakeResponse(200, "gone")]),
                    WEBROOT, BridgeSettings(), SITE)
    endpoint = bridge.ensure()
    assert re.fullmatch(r"bridge-[0-9a-f]{8}\.php", endpoint)
    assert list(src.files) == [f"{WEBROOT}/{endpoint}"]
    bridge.destroy()  # HTTP selfdestruct answers "gone"
    assert src.files == {}  # nothing left behind at any path


def test_ensure_substitutes_placeholders_with_token_and_expiry():
    bridge, src, _ = make(settings=BridgeSettings(ttl_minutes=2))
    before = time.time()
    endpoint = bridge.ensure()
    after = time.time()
    data = src.files[endpoint]
    assert data.startswith(b"<?php") and b"wpt_actions" in data  # the real template
    assert b"__WPT_TOKEN__" not in data
    assert b"__WPT_EXPIRES__" not in data
    expiry = expiry_of(src, endpoint)
    assert before + 2 * 60 - 1 <= expiry <= after + 2 * 60


def test_ensure_ignores_webroot_for_the_endpoint():
    # The webroot is normalized on the Bridge (URL/doc-root semantics) but
    # never appears in source-side paths anymore: sources prefix it.
    bridge, src, _ = make(webroot=f"/{WEBROOT}/")
    endpoint = bridge.ensure()
    assert re.fullmatch(r"bridge-[0-9a-f]{8}\.php", endpoint)
    assert endpoint in src.files
    bare, bare_src, _ = make(webroot="")
    endpoint = bare.ensure()
    assert re.fullmatch(r"bridge-[0-9a-f]{8}\.php", endpoint)
    assert endpoint in bare_src.files


# ---------------------------------------------------------------------- call


def test_call_auto_ensures_posts_action_params_and_returns_full_payload():
    bridge, src, session = make(script=[ok_response(wp_version="6.7")])
    out = bridge.call("info")
    assert out == {"ok": True, "wp_version": "6.7"}  # full payload, "ok" kept
    (endpoint,) = src.files
    url, kwargs = session.posts[0]
    # I4 regression: the bridge is served at the DOCUMENT ROOT, so the URL is
    # {site}/{name}.php — the FTP webroot prefix must NEVER appear in it
    # (production layout: FTP login dir != document root).
    name = endpoint.rsplit("/", 1)[-1]
    assert url == f"{SITE}/{name}?t={token_of(src, endpoint)}"
    assert WEBROOT not in url
    assert kwargs["json"] == {"action": "info", "params": {}}
    assert kwargs["timeout"] == 30  # BridgeSettings.timeout_s


def test_call_passes_kwargs_as_the_params_object():
    bridge, _, session = make(script=[ok_response(n=3)])
    bridge.call("db_clean", ops=["revisions"], dry=True)
    assert session.posts[0][1]["json"] == {
        "action": "db_clean",
        "params": {"ops": ["revisions"], "dry": True},
    }


def test_R15_error_payload_sanitises_keys_and_bounds_depth():
    """R15-P2: ``_safe_payload`` recursed values only (a token echoed as a
    KEY leaked) and had no depth bound (999 levels raised RecursionError
    instead of the client's BridgeError contract)."""
    bridge, src, _ = make()
    endpoint = bridge.ensure()
    token = token_of(src, endpoint)

    payload = {"ok": False, "error": "boom",
               "details": {token: "leak", "x": f"value {token}"}}
    bridge._session.script.append(FakeResponse(200, json.dumps(payload)))
    with pytest.raises(BridgeError) as excinfo:
        bridge.call("info")
    rendered = json.dumps(excinfo.value.payload)
    assert token not in rendered
    assert "***" in rendered

    deep: dict = {}
    cursor = deep
    for _ in range(999):
        cursor["next"] = {}
        cursor = cursor["next"]
    with pytest.raises(BridgeError, match="deeper"):
        bridge._safe_payload(deep)


def test_call_ok_false_raises_bridgeerror_preserving_payload():
    payload = {"ok": False, "error": "db error: lock",
               "type": "RuntimeException", "line": 42}
    bridge, _, _ = make(script=[FakeResponse(200, json.dumps(payload))])
    with pytest.raises(BridgeError) as ei:
        bridge.call("db_audit")
    assert ei.value.payload == payload
    assert "db error: lock" in str(ei.value)


def test_call_404_nf_redeploys_under_new_name_and_retries_once():
    bridge, src, session = make(script=[nf_response(), ok_response(purged=True)])
    assert bridge.call("purge_cache") == {"ok": True, "purged": True}
    assert len(session.posts) == 2
    n_first = name_of_url(session.posts[0][0])
    n_second = name_of_url(session.posts[1][0])
    assert n_first != n_second
    assert set(src.files) == {endpoint_of(n_first), endpoint_of(n_second)}
    assert session.posts[1][0] == f"{SITE}/{n_second}?t={token_of(src, endpoint_of(n_second))}"
    assert token_of(src, endpoint_of(n_first)) != token_of(src, endpoint_of(n_second))


def test_call_404_nf_twice_exhausts_the_redeploy_retry():
    bridge, _, _ = make(script=[nf_response(), nf_response()])
    with pytest.raises(BridgeError) as ei:
        bridge.call("info")
    assert "nf" in str(ei.value)
    assert ei.value.payload == {"status": 404, "body": "nf"}


def test_call_L6_site_404_html_renames_within_name_retries():
    bridge, src, session = make(
        script=[site_404(), site_404(), ok_response(n=1)],
        settings=BridgeSettings(name_retries=3),
    )
    assert bridge.call("info") == {"ok": True, "n": 1}
    urls = [u for u, _ in session.posts]
    assert len(urls) == 3 and len(set(urls)) == 3  # a fresh name per attempt
    assert len(src.files) == 3


def test_call_L6_site_404_html_exhausting_name_retries_raises():
    bridge, src, _ = make(
        script=[site_404() for _ in range(3)],
        settings=BridgeSettings(name_retries=2),
    )
    with pytest.raises(BridgeError) as ei:
        bridge.call("info")
    assert "L6" in str(ei.value)
    assert ei.value.payload["status"] == 404
    assert "404 Not Found" in ei.value.payload["body"]
    assert len(src.files) == 3  # initial upload + 2 renames


def test_call_non_json_200_raises_with_redacted_excerpt():
    bridge, _, _ = make(script=[FakeResponse(200, "<html>Server error password=hunter2</html>")])
    with pytest.raises(BridgeError) as ei:
        bridge.call("info")
    msg = str(ei.value)
    assert "Server error" in msg
    assert "password=***" in msg  # redact_text applied to the excerpt
    assert "hunter2" not in msg


def test_call_unexpected_http_status_raises_with_excerpt():
    bridge, _, _ = make(script=[FakeResponse(502, "<html>bad gateway</html>")])
    with pytest.raises(BridgeError) as ei:
        bridge.call("info")
    assert "HTTP 502" in str(ei.value)
    assert ei.value.payload == {"status": 502, "body": "<html>bad gateway</html>"}


def test_call_network_error_retries_once_after_redeploy():
    bridge, src, session = make(
        script=[requests.ConnectionError("connection refused"), ok_response(x=9)]
    )
    assert bridge.call("info") == {"ok": True, "x": 9}
    assert len(session.posts) == 2
    assert len(src.files) == 2  # redeployed under a fresh name


def test_call_network_error_twice_raises_bridgeerror():
    bridge, _, _ = make(script=[requests.ConnectionError("connection refused"),
                                requests.ConnectionError("connection reset")])
    with pytest.raises(BridgeError) as ei:
        bridge.call("info")
    assert "ConnectionError" in str(ei.value)
    assert "connection reset" in str(ei.value)
    # the raw requests exception (it embeds the token-bearing URL) must never
    # enter the exception chain
    assert ei.value.__cause__ is None
    assert ei.value.__suppress_context__


# --------------------------------------------------------------- call_stream


def test_R15_call_absolute_deadline_bounds_a_dripping_body():
    """R15-P1-2: ``requests``' timeout is PER READ, so a server dripping
    one byte at a time kept ``Bridge.call`` alive indefinitely.  Both a
    relative call budget and an absolute monotonic deadline bound the whole
    POST + body, and an already-expired deadline never starts a request."""
    import http.server
    import threading

    class _Drip(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        requests = 0

        def do_POST(self):
            type(self).requests += 1
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            body = b'{"ok":true,"wp_version":"6.8.3"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            for byte in body:
                try:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                except OSError:
                    return
                time.sleep(0.02)

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Drip)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        src = FakeSource()
        session = requests.Session()
        session.trust_env = False
        bridge = Bridge(src, session, WEBROOT, BridgeSettings(),
                        f"http://127.0.0.1:{server.server_port}")

        started = time.monotonic()
        with pytest.raises(BridgeError, match="absolute call deadline"):
            bridge.call("info", timeout=0.05)
        assert 0.04 <= time.monotonic() - started < 0.3

        started = time.monotonic()
        with pytest.raises(DeadlineExceeded):
            bridge.call("info", deadline=time.monotonic() + 0.05)
        assert 0.04 <= time.monotonic() - started < 0.3

        # The stack seam arms the Bridge with the RUN deadline, so a call
        # site that passes neither argument is still bounded (R15-P1-2:
        # every caller, including convenience methods, inherits it).
        inherited = Bridge(src, session, WEBROOT, BridgeSettings(),
                           f"http://127.0.0.1:{server.server_port}",
                           deadline=time.monotonic() + 0.05)
        started = time.monotonic()
        with pytest.raises(DeadlineExceeded):
            inherited.call("info")
        assert 0.04 <= time.monotonic() - started < 0.3

        # A SHORTER relative call budget keeps its own verdict: it is a
        # transport failure, not the run's cooperative stop.
        longer_run = Bridge(src, session, WEBROOT, BridgeSettings(),
                            f"http://127.0.0.1:{server.server_port}",
                            deadline=time.monotonic() + 10)
        with pytest.raises(BridgeError, match="absolute call deadline"):
            longer_run.call("info", timeout=0.03)

        before = _Drip.requests
        with pytest.raises(DeadlineExceeded):
            bridge.call("info", deadline=time.monotonic() - 1)
        assert _Drip.requests == before
        session.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_call_stream_yields_decoded_ndjson_rows_and_closes_response():
    blob = b"\x00\xffbin"
    create = {"table": "wp_posts", "create": "CREATE TABLE `wp_posts` (ID bigint)"}
    row1 = {"table": "wp_posts", "row": ["1", "hello"]}
    row2 = {"table": "wp_posts", "row": ["2", ["__wpt_b64__", base64.b64encode(blob).decode()]]}
    done = {"table": "wp_posts", "done": 2}
    resp = FakeResponse(200, lines=["", json.dumps(create), json.dumps(row1),
                                    json.dumps(row2), json.dumps(done), ""])
    bridge, _, session = make(script=[resp])
    out = list(bridge.call_stream("db_dump", tables=["wp_posts"]))
    assert out == [create, row1, {"table": "wp_posts", "row": ["2", blob]}, done]
    url, kwargs = session.posts[0]
    assert kwargs["json"] == {"action": "db_dump", "params": {"tables": ["wp_posts"]}}
    assert kwargs["stream"] is True
    assert resp.closed  # closed on completion, not only on early close


def test_call_stream_close_closes_http_response():
    resp = FakeResponse(200, lines=[json.dumps({"table": "wp_posts", "done": 0})])
    bridge, _, _ = make(script=[resp])
    gen = bridge.call_stream("db_dump", tables=["wp_posts"])
    next(gen)
    assert not resp.closed
    gen.close()
    assert resp.closed


def test_call_stream_inline_error_envelope_raises_with_payload():
    envelope = {"ok": False, "error": "table not allowed: wp_x",
                "type": "InvalidArgumentException", "line": 649}
    bridge, _, _ = make(script=[FakeResponse(200, lines=[json.dumps(envelope)])])
    with pytest.raises(BridgeError) as ei:
        list(bridge.call_stream("db_dump", tables=["wp_x"]))
    assert ei.value.payload == envelope


@pytest.mark.parametrize("raw_line,fragment", [
    (b"not json at all", "malformed NDJSON"),
    (b'["a", 1]', "non-object"),
    (b"\xff\xfe\xfa", "UTF-8"),
    (json.dumps({"table": "t", "row": [["__wpt_b64__", "###not-base64###"]]}).encode(),
     "undecodable __wpt_b64__"),
    (json.dumps({"table": "t", "row": [["__wpt_b64__", 5]]}).encode(),
     "without a string payload"),
])
def test_call_stream_wire_contract_violations_raise(raw_line, fragment):
    resp = FakeResponse(200, lines=[raw_line])
    bridge, _, _ = make(script=[resp])
    with pytest.raises(BridgeError) as ei:
        list(bridge.call_stream("db_dump", tables=["t"]))
    assert fragment in str(ei.value)
    assert resp.closed


# ------------------------------------------------------------------- destroy


def test_destroy_requests_selfdestruct_and_removes_file():
    bridge, src, session = make(script=[])
    session.script.append(selfdestruct_server(src))
    endpoint = bridge.ensure()
    token = token_of(src, endpoint)
    bridge.destroy()
    assert len(session.gets) == 1
    url, kwargs = session.gets[0]
    name = endpoint.rsplit("/", 1)[-1]
    assert url == f"{SITE}/{name}?t={token}&selfdestruct=1"
    assert kwargs["timeout"] == 30
    assert endpoint not in src.files
    assert op_paths(src, "delete") == []  # removed remotely, not via the source


def test_destroy_selfdestruct_body_is_absolutely_bounded_and_falls_back():
    """R16-P1: a drip/endless "gone" body made teardown unbounded.  The
    self-destruct GET runs under min(bridge timeout, run deadline); on expiry
    it falls back to the source delete while every tracked endpoint is still
    attempted, and an already-spent budget sends no request at all."""
    import http.server
    import threading

    class _Drip(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        requests = 0

        def do_GET(self):
            type(self).requests += 1
            body = b"gone"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            for byte in body:
                try:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                except OSError:
                    return
                time.sleep(0.4)

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Drip)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    site = f"http://127.0.0.1:{server.server_port}"
    try:
        src = FakeSource()
        session = requests.Session()
        session.trust_env = False
        bridge = Bridge(src, session, WEBROOT, BridgeSettings(timeout_s=30),
                        site, deadline=time.monotonic() + 0.05)
        current = bridge.ensure()
        old = "bridge-deadbeef.php"
        src.files[old] = b"<?php old"
        bridge._uploads.insert(0, old)
        started = time.monotonic()
        bridge.destroy()
        elapsed = time.monotonic() - started
        assert elapsed < 0.75, elapsed
        assert _Drip.requests == 1
        # The HTTP body never completed, so BOTH endpoints were removed via
        # the source fallback: the old one was still attempted first.
        assert old not in src.files and current not in src.files
        assert old in op_paths(src, "delete") or current in op_paths(src, "delete")

        expired_src = FakeSource()
        expired = Bridge(expired_src, session, WEBROOT, BridgeSettings(),
                         site, deadline=time.monotonic() + 60)
        endpoint = expired.ensure()
        expired._run_deadline = time.monotonic() - 1
        stale = "bridge-cafebabe.php"
        expired_src.files[stale] = b"<?php old"
        expired._uploads.insert(0, stale)
        before = _Drip.requests
        expired.destroy()
        assert _Drip.requests == before       # no request after expiry
        assert endpoint not in expired_src.files
        assert stale not in expired_src.files
        session.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_R17_header_drip_is_bounded_for_call_and_destroy():
    """R17-2-P1-1: requests' timeout is per-read, so a server dripping the
    STATUS LINE/HEADERS one byte at a time held ``call``'s POST and
    ``destroy``'s self-destruct GET far past the run deadline.  Both now ride
    the same non-blocking absolute-deadline header/body transport, and an
    expired destroy still removes every endpoint via the source fallback."""
    import http.server
    import threading

    class _HeadDrip(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        requests = 0

        def _drip(self):
            type(self).requests += 1
            head = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    b"Content-Length: 2\r\n\r\n{}")
            try:
                for byte in head:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.12)
            except OSError:
                return

        do_GET = _drip
        do_POST = _drip

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _HeadDrip)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    site = f"http://127.0.0.1:{server.server_port}"
    session = requests.Session()
    session.trust_env = False
    try:
        src = FakeSource()
        bridge = Bridge(src, session, WEBROOT, BridgeSettings(timeout_s=30),
                        site, deadline=time.monotonic() + 0.5)
        started = time.monotonic()
        with pytest.raises(DeadlineExceeded):
            bridge.call("info")
        assert time.monotonic() - started < 1.5

        destroy_src = FakeSource()
        destroyer = Bridge(destroy_src, session, WEBROOT,
                           BridgeSettings(timeout_s=30), site,
                           deadline=time.monotonic() + 0.5)
        current = destroyer.ensure()
        old = "bridge-deadbeef.php"
        destroy_src.files[old] = b"<?php old"
        destroyer._uploads.insert(0, old)
        started = time.monotonic()
        destroyer.destroy()
        assert time.monotonic() - started < 1.5
        # Both the earlier and the CURRENT endpoint were attempted and gone.
        assert current not in destroy_src.files
        assert old not in destroy_src.files
        assert {current, old} <= set(op_paths(destroy_src, "delete"))
        assert _HeadDrip.requests >= 2  # both POST and GET reached the wire
    finally:
        session.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class _BudgetedSource(FakeSource):
    """FakeSource that enforces a run budget on the source operations that
    matter for teardown (the real FtpSource's ``_call`` shape)."""

    def __init__(self) -> None:
        super().__init__()
        self.deadline = Deadline(60)
        self.cleanup_deadline_s = 5
        self.closed_under_expired_budget = False

    def _check(self) -> None:
        if self.deadline is not None:
            self.deadline.check("test source operation")

    def exists(self, path):
        self._check()
        return super().exists(path)

    def list_dir(self, path):
        self._check()
        return super().list_dir(path)

    def delete(self, path, *, allow_config=False, allow_core=False):
        self._check()
        return super().delete(path, allow_config=allow_config,
                              allow_core=allow_core)

    def close(self):
        self.closed_under_expired_budget = bool(
            self.deadline is not None and self.deadline.expired)


def test_R17_destroy_uses_a_fresh_cleanup_budget_after_run_expiry():
    """R17-6-P1-1: an expired run budget made every source op raise before
    the DELE, leaving a token bridge live until TTL.  destroy() (and the
    shared teardown owner) swap in ``run.cleanup_deadline_s`` for cleanup."""
    from wpt.teardown import teardown_stack

    src = _BudgetedSource()
    bridge = Bridge(src, FakeSession([]), WEBROOT, BridgeSettings(), SITE,
                    deadline=time.monotonic() + 60)
    endpoint = bridge.ensure()
    src.deadline = Deadline(-1)
    bridge._run_deadline = time.monotonic() - 1

    bridge.destroy()
    assert endpoint not in src.files
    assert endpoint in op_paths(src, "delete")

    teardown_src = _BudgetedSource()
    teardown_src.deadline = Deadline(-1)
    seen: list[bool] = []

    class _Bridge:
        def destroy(self):
            seen.append(teardown_src.deadline.expired)
            teardown_src.delete("bridge-cafebabe.php")

    teardown_src.files["bridge-cafebabe.php"] = b"<?php"
    assert teardown_stack((teardown_src, None, _Bridge()), "test") is None
    assert seen == [False]
    assert teardown_src.closed_under_expired_budget is False
    assert "bridge-cafebabe.php" not in teardown_src.files


def test_destroy_is_idempotent_second_call_is_a_noop():
    bridge, src, session = make(script=[])
    session.script.append(selfdestruct_server(src))
    bridge.ensure()
    bridge.destroy()
    assert bridge._endpoint is None
    assert bridge._name is None and bridge._token is None
    assert bridge._uploads == []
    gets_before = len(session.gets)
    ops_before = len(src.ops)
    bridge.destroy()  # nothing tracked -> no request, no exists() probe
    assert len(session.gets) == gets_before
    assert len(src.ops) == ops_before


def test_destroy_network_failure_falls_back_to_source_delete():
    bridge, src, _ = make(script=[requests.ConnectionError("selfdestruct unreachable")])
    endpoint = bridge.ensure()
    bridge.destroy()
    assert endpoint not in src.files
    assert endpoint in op_paths(src, "delete")


def test_destroy_bad_selfdestruct_response_falls_back_to_source_delete():
    bridge, src, _ = make(script=[nf_response()])  # e.g. ttl already expired
    endpoint = bridge.ensure()
    bridge.destroy()
    assert endpoint not in src.files
    assert endpoint in op_paths(src, "delete")


def test_destroy_verifies_removal_and_deletes_when_file_lingers():
    # Server answers 'gone' but the file is still there (unlink failed):
    # the exists() verification must catch it and delete via the source.
    bridge, src, _ = make(script=[FakeResponse(200, "gone")])
    endpoint = bridge.ensure()
    bridge.destroy()
    assert endpoint in op_paths(src, "delete")
    assert endpoint not in src.files


def test_destroy_without_deployment_is_a_noop():
    bridge, _, session = make(script=[])
    bridge.destroy()
    assert session.posts == [] and session.gets == []


def test_destroy_clears_tracking_when_the_bridge_already_self_deleted():
    """Proven absence has the same owner rule as a successful delete: the
    endpoint must not stay tracked after the listing proves it gone."""
    bridge, src, session = make(script=[])
    endpoint = bridge.ensure()
    del src.files[endpoint]  # the server unlinked it (e.g. expiry/template)

    bridge.destroy()

    assert bridge._endpoint is None
    assert bridge._name is None and bridge._token is None
    assert bridge._uploads == []
    assert session.gets == []  # no self-destruct URL for an absent file


class _RefusingDeleteSource(FakeSource):
    """A source whose DELE is refused (and whose listing still shows it)."""

    def __init__(self):
        super().__init__()
        self.refuse = True
        self.deletes: list[str] = []

    def delete(self, path):
        self.deletes.append(path)
        if self.refuse:
            raise SourceError("delete refused")
        super().delete(path)


def test_destroy_keeps_tracking_when_the_delete_is_refused_and_retries():
    """The P3 owner rule: a refused delete must leave the endpoint tracked,
    so a later destroy retries it; only a successful delete (or proven
    absence) clears the current endpoint."""
    src = _RefusingDeleteSource()
    bridge = Bridge(src, FakeSession([nf_response(), selfdestruct_server(src)]),
                    WEBROOT, BridgeSettings(), SITE)
    endpoint = bridge.ensure()

    with pytest.raises(SourceError, match="delete refused"):
        bridge.destroy()

    assert src.deletes == [endpoint]
    assert bridge._endpoint == endpoint
    assert bridge._name is not None and bridge._token is not None
    assert bridge._uploads == [endpoint]

    src.refuse = False
    bridge.destroy()  # the server now self-destructs
    assert endpoint not in src.files
    assert src.deletes == [endpoint]  # HTTP removal, no second source delete
    assert bridge._endpoint is None
    assert bridge._name is None and bridge._token is None
    assert bridge._uploads == []


def test_destroy_drops_an_old_upload_only_after_its_delete_succeeds():
    """Renamed-away endpoints are retried independently: every endpoint is
    attempted even when an earlier one fails, and each is dropped only after
    its own removal succeeded.  The earlier failure is still reported (the
    retry contract), but it no longer leaves the CURRENT token bridge live
    until TTL."""
    src = _RefusingDeleteSource()
    bridge = Bridge(src, FakeSession([selfdestruct_server(src)]),
                    WEBROOT, BridgeSettings(), SITE)
    old = bridge.ensure()
    current = bridge.ensure()

    with pytest.raises(SourceError, match="delete refused"):
        bridge.destroy()

    # The old delete was refused; the current endpoint was still attempted
    # and self-destructed, so no live token bridge is left behind.
    assert current not in src.files
    assert bridge._endpoint is None and bridge._name is None
    assert bridge._uploads == [old]

    src.refuse = False
    bridge.destroy()
    assert src.files == {}
    assert bridge._endpoint is None and bridge._uploads == []
    # the old endpoint was retried through the source; the current one was
    # removed over HTTP and never needed a second delete
    assert src.deletes == [old, old]


class _StopOnceOnDelete(FakeSource):
    """A source whose first DELE of one old endpoint requests a stop."""

    def __init__(self, stop_path: str) -> None:
        super().__init__()
        self.stop_path = stop_path
        self.stopped = False

    def delete(self, path):
        if path == self.stop_path and not self.stopped:
            self.stopped = True
            raise StopRequested("SIGTERM while deleting an old endpoint")
        super().delete(path)


def test_R11_a_stop_on_an_old_endpoint_never_leaves_the_current_bridge():
    """R11-P2-12: an old endpoint's stop aborted destroy before the current
    endpoint's self-destruct, leaving a live token bridge until TTL.  Every
    endpoint is attempted; the first stop is re-raised afterwards."""
    src = _StopOnceOnDelete("")
    bridge = Bridge(src, FakeSession([selfdestruct_server(src)]),
                    WEBROOT, BridgeSettings(), SITE)
    first_old = bridge.ensure()
    src.stop_path = first_old
    second_old = bridge.ensure()
    current = bridge.ensure()

    with pytest.raises(StopRequested, match="old endpoint"):
        bridge.destroy()

    # The current endpoint was still removed (HTTP self-destruct), and the
    # old endpoint AFTER the stopped one was deleted too.
    assert current not in src.files
    assert second_old not in src.files
    assert bridge._endpoint is None and bridge._token is None
    # Only the endpoint whose delete actually stopped stays tracked.
    assert bridge._uploads == [first_old]


def test_R20_a_stop_in_selfdestruct_still_removes_the_current_endpoint():
    """R20-P2: ``_destroy_current`` caught only RequestException/WptError, so
    a StopRequested from the self-destruct skipped the source fallback and
    left the token-gated bridge on the site until TTL.  The stop is
    remembered, the fallback still runs, and the stop is re-raised."""
    src = FakeSource()

    def _stop(_method, _url, _kwargs):
        raise StopRequested("SIGTERM during self-destruct")

    session = FakeSession([_stop])
    bridge = Bridge(src, session, WEBROOT, BridgeSettings(), SITE)
    endpoint = bridge.ensure()

    with pytest.raises(StopRequested, match="SIGTERM"):
        bridge.destroy()

    assert endpoint not in src.files
    assert op_paths(src, "delete") == [endpoint]
    assert bridge._endpoint is None and bridge._uploads == []


# ----------------------------------------------------------- context manager


def test_context_manager_deploys_and_destroys_on_success():
    src = FakeSource()
    session = FakeSession([ok_response(a=1), selfdestruct_server(src)])
    with Bridge(src, session, WEBROOT, BridgeSettings(), SITE) as bridge:
        assert bridge.call("info") == {"ok": True, "a": 1}
    assert src.files == {}


def test_context_manager_destroys_even_when_body_raises():
    src = FakeSource()
    session = FakeSession([selfdestruct_server(src)])
    with pytest.raises(RuntimeError, match="boom"):
        with Bridge(src, session, WEBROOT, BridgeSettings(), SITE):
            raise RuntimeError("boom")
    assert src.files == {}  # L6 hygiene: never leave the bridge on disk


def test_destroy_L6_removes_all_renamed_bridge_files():
    src = FakeSource()
    session = FakeSession([site_404(), ok_response(), selfdestruct_server(src)])
    with Bridge(src, session, WEBROOT, BridgeSettings(name_retries=3), SITE) as bridge:
        bridge.call("info")  # forces one L6 rename -> two files on the server
    assert src.files == {}  # the renamed-away bridge is removed too
    assert len(session.gets) == 1  # only the current endpoint self-destructs over HTTP
    assert len(op_paths(src, "delete")) == 1  # the older one, via the source


# ------------------------------------------------------------------ logging


def test_token_never_appears_in_log_records_or_exceptions(caplog):
    def conn_error(method, url, kwargs):
        # Real requests exceptions embed the request URL — with the token.
        raise requests.ConnectionError(
            "HTTPSConnectionPool(host='example.com', port=443): "
            f"Max retries exceeded with url: {url}"
        )

    bridge, src, session = make(script=[
        conn_error, conn_error,  # network failure x2 -> BridgeError (error log)
        err_response(error="db error: lock"),  # ok:false -> warning
        ok_response(),  # success -> debug
        conn_error,  # destroy self-destruct -> warning + source fallback
        site_404(), site_404(), site_404(), site_404(),  # L6 exhaustion -> error
    ])
    raised: list[BridgeError] = []

    wpt_logger = logging.getLogger("wpt")
    wpt_logger.addHandler(caplog.handler)  # the wpt tree does not propagate to root
    caplog.set_level(logging.DEBUG, logger="wpt")
    try:
        with pytest.raises(BridgeError) as ei:
            bridge.call("info")
        raised.append(ei.value)
        with pytest.raises(BridgeError) as ei:
            bridge.call("db_audit")
        raised.append(ei.value)
        assert bridge.call("info") == {"ok": True}
        bridge.destroy()
        with pytest.raises(BridgeError) as ei:
            bridge.call("info")
        raised.append(ei.value)
    finally:
        wpt_logger.removeHandler(caplog.handler)

    tokens = {token_of_url(u) for u, _ in session.posts + session.gets}
    assert len(tokens) >= 2  # fresh tokens per deployment were exercised
    assert caplog.records, "no log records captured"
    for record in caplog.records:
        blob = str(record.__dict__)  # raw msg + args + every extra, pre-redaction
        for token in tokens:
            assert token not in blob, f"token leaked into log record {record!r}"
    for err in raised:
        assert not any(token in str(err) for token in tokens)
    assert raised[0].__cause__ is None
    assert raised[0].__suppress_context__


# ------------------------------------------------------------------ media map


def test_db_media_refs_asks_for_the_read_only_db_mode():
    # ONE call, mode=db: the database half of the media keep-set (a page
    # renders only a fraction of its attachments — measured live
    # an observed run, most of the media bytes were database-referenced and
    # invisible to the walk)
    bridge, _, session = make(script=[ok_response(
        db_refs=["2023/10/pic.jpg", "2023/10/pic-300x233.jpg"])])
    refs = bridge.db_media_refs()
    assert refs == {"2023/10/pic.jpg", "2023/10/pic-300x233.jpg"}
    assert session.posts[0][1]["json"] == {
        "action": "media_map", "params": {"mode": "db"},
    }


def test_db_media_refs_carries_the_callers_media_family():
    # D1: the gate answers from the list the ENUMERATION files by, so a
    # profile the operator widened widens the live keep-gate too.  Without
    # this a .psd the database references is invisible to the gate and the
    # widened enumeration plans it for deletion.
    bridge, _, session = make(script=[ok_response(
        db_refs=["2023/01/design.psd"], db_refs_gate=40)])
    refs = bridge.db_media_refs(extensions=["jpg", "psd"])
    assert refs == {"2023/01/design.psd"}
    assert session.posts[0][1]["json"]["params"] == {
        "mode": "db", "extensions": ["jpg", "psd"],
    }


def test_db_media_refs_normalizes_the_family_it_sends():
    # the wire carries sorted, deduplicated, lowercased plain suffixes —
    # the shape both sides accept (the bridge re-checks it: it is the
    # trust boundary a hand-written request reaches directly)
    bridge, _, session = make(script=[ok_response(db_refs=[],
                                                 db_refs_gate=39)])
    assert bridge.db_media_refs(
        extensions=[" JPG", "jpg", "PNG", "png"]) == set()
    assert session.posts[0][1]["json"]["params"]["extensions"] == [
        "jpg", "png"]


@pytest.mark.parametrize("family, why", [
    ([".psd"], "not a plain suffix"),
    (["../etc/passwd"], "not a plain suffix"),
    (["jpg", 7], "not a string"),
    (["e%d" % i for i in range(513)], "more than 512"),
    ("jpg", "not a list"),
])
def test_db_media_refs_refuses_a_family_the_wire_cannot_carry(family, why):
    # A run that enumerates by a family the live gate cannot be told about
    # would get back a keep-set measured with a DIFFERENT list than the
    # enumeration assumes — and a reference the gate cannot name is a file
    # the tool would delete.  There is no safe fallback, so the read
    # refuses and every consumer degrades to UNKNOWN.
    bridge, _, session = make(script=[ok_response(db_refs=["2023/01/design.psd"])])
    with pytest.raises(BridgeError) as ei:
        bridge.db_media_refs(extensions=family)
    assert why in str(ei.value)
    assert not session.posts, "the unexpressible family went on the wire"


def test_db_media_refs_sends_nothing_for_an_empty_family():
    # An EMPTY family is a legitimate "no uploads file is media": the run
    # enumerates nothing and has nothing to delete, so the bridge answering
    # on its mirrored default protects files the plan will never name.  No
    # request, no refusal.
    bridge, _, session = make(script=[ok_response(db_refs=["2023/10/a.jpg"])])
    assert bridge.db_media_refs(extensions=[]) == {"2023/10/a.jpg"}
    assert session.posts[0][1]["json"]["params"] == {"mode": "db"}


def test_db_media_refs_sends_nothing_when_no_family_is_asked_for():
    # the pre-existing contract: a caller that measures no enumeration of
    # its own (cull-media) sends no family and the bridge answers on its
    # own default.
    bridge, _, session = make(script=[ok_response(db_refs=["2023/10/a.jpg"])])
    assert bridge.db_media_refs() == {"2023/10/a.jpg"}
    assert session.posts[0][1]["json"]["params"] == {"mode": "db"}


@pytest.mark.parametrize("answer", [
    {"db_refs_gate_fallback": True},                 # refused outright
    {"db_refs_gate": 1},                             # narrower than asked
])
def test_db_media_refs_refuses_a_gate_that_does_not_contain_ours(answer):
    # THE FAIL-CLOSED HALF.  A keep-set measured with a family this run
    # never asked for is not the measurement the enumeration assumed, and
    # that is the D1 defect itself: a file the database references,
    # invisible to the gate, planned for deletion.  It raises instead, and
    # every consumer degrades to UNKNOWN (the audit says so, the
    # destructive apply refuses).
    bridge, _, _ = make(script=[ok_response(db_refs=["2023/01/design.psd"],
                                           **answer)])
    with pytest.raises(BridgeError) as ei:
        bridge.db_media_refs(extensions=["jpg", "psd"])
    assert "does not contain" in str(ei.value)


@pytest.mark.parametrize("answer", [
    {"db_refs_gate": 39},                            # exactly ours
    {"db_refs_gate": 41},                            # the default floor added
    {},                                              # no report at all
    {"db_refs_gate": "40"},                          # not a count
    {"db_refs_gate": True},                          # a bool is not a count
])
def test_db_media_refs_accepts_a_gate_at_least_as_wide_as_ours(answer):
    # a WIDER gate can only protect more files, so a profile the operator
    # NARROWED (the floor stays in force) is a measurement, not an anomaly.
    # An unreportable or unreported gate is not evidence of a narrower one
    # either: it is the pre-existing answer shape, tolerated but never
    # trusted to be wider than it says.
    bridge, _, _ = make(script=[ok_response(db_refs=["2023/10/a.jpg"],
                                           **answer)])
    assert bridge.db_media_refs(extensions=["jpg"]) == {"2023/10/a.jpg"}


def test_db_media_refs_empty_list_is_a_measured_empty():
    # [] is a REAL measurement ("this database references no uploads
    # file"), never confused with unknown
    bridge, _, _ = make(script=[ok_response(db_refs=[])])
    assert bridge.db_media_refs() == set()


@pytest.mark.parametrize("db_refs", [
    None,                    # key absent
    {},                      # a map, not a list
    "2023/10/pic.jpg",       # a bare string
])
def test_db_media_refs_missing_or_mistyped_list_raises(db_refs):
    # a half-understood answer must never become a keep-set: the caller
    # would delete everything the database protects
    bridge, _, _ = make(script=[ok_response(db_refs=db_refs)])
    with pytest.raises(BridgeError) as ei:
        bridge.db_media_refs()
    assert "anomaly" in str(ei.value)


@pytest.mark.parametrize("entry", [None, 7, "", "/2023/10/pic.jpg", {"p": 1},
                                  "2023//pic.jpg", "../pic.jpg", "2023/./pic.jpg"])
def test_db_media_refs_drops_one_unusable_entry_and_keeps_the_union(entry):
    # THE LIVE DEFECT (measured on an observed site): a stale
    # _transient_dirsize_cache option held many absolute paths to the site's
    # PREVIOUS host, several of them bare year DIRECTORIES.  The former
    # all-or-nothing validation refused the WHOLE answer, so one junk row
    # silently degraded the union keep-set to walk-only on the whole site
    # (and trim-media --apply then refused).  An entry this client cannot
    # union is dropped; the rest of the measurement is still a
    # measurement.
    bridge, _, _ = make(script=[ok_response(
        db_refs=["2023/10/pic.jpg", entry, "2023/11/pic.png"])])
    assert bridge.db_media_refs() == {"2023/10/pic.jpg", "2023/11/pic.png"}


def _lossy_warnings(caplog, run):
    """Run ``run`` with the wpt log tree captured (it does not propagate)."""
    wpt_logger = logging.getLogger("wpt")
    wpt_logger.addHandler(caplog.handler)
    caplog.set_level(logging.WARNING, logger="wpt")
    try:
        result = run()
    finally:
        wpt_logger.removeHandler(caplog.handler)
    return result, [r for r in caplog.records if "dropped" in r.getMessage()]


def test_db_media_refs_reports_the_lossy_count_once(caplog):
    # the drop is invisible unless it is said out loud: the operator has to
    # be able to see that the keep-set lost references.
    bridge, _, _ = make(script=[ok_response(
        db_refs=["2023/10/pic.jpg", "/home/old/wp-content/uploads/2019"],
        db_refs_dropped=6)])
    refs, dropped = _lossy_warnings(
        caplog, bridge.db_media_refs)
    assert refs == {"2023/10/pic.jpg"}
    assert len(dropped) == 1
    message = dropped[0].getMessage()
    assert "7" in message            # 6 refused by the server + 1 here
    assert "lossy" in message


def test_db_media_refs_silent_when_nothing_was_dropped(caplog):
    bridge, _, _ = make(script=[ok_response(db_refs=["2023/10/pic.jpg"],
                                            db_refs_dropped=0)])
    refs, dropped = _lossy_warnings(caplog, bridge.db_media_refs)
    assert refs == {"2023/10/pic.jpg"}
    assert dropped == []


def test_db_media_refs_truncated_answer_still_refuses():
    # the ONE case that stays fail-closed: a server that says it could not
    # measure the whole reference set.  A partial keep-set is how a
    # referenced file gets deleted, so this is never a "drop and continue".
    bridge, _, _ = make(script=[ok_response(db_refs=["2023/10/pic.jpg"],
                                            truncated=True)])
    with pytest.raises(BridgeError, match="truncated"):
        bridge.db_media_refs()


@pytest.mark.parametrize("reported", ["6", None, {"n": 1}, True])
def test_db_media_refs_a_nonsense_dropped_count_is_not_fatal(reported):
    # the count is INFORMATION: a bridge that cannot count must not take
    # the keep-set down with it.
    bridge, _, _ = make(script=[ok_response(db_refs=["2023/10/pic.jpg"],
                                            db_refs_dropped=reported)])
    assert bridge.db_media_refs() == {"2023/10/pic.jpg"}


def test_db_media_refs_server_error_propagates():
    bridge, _, _ = make(script=[err_response(error="db media map unavailable")])
    with pytest.raises(BridgeError, match="db media map unavailable"):
        bridge.db_media_refs()


# ------------------------------------------------- webp reference rewrite


def ndjson(*objects):
    """A scripted NDJSON stream, the way the op emits one."""
    return FakeResponse(200, lines=[json.dumps(o) for o in objects])


SCAN = (
    {"table": "wp_posts", "key": "ID", "id": 7, "value": "<p>…pic.jpg</p>",
     "gated": ["cover pic-300x233.jpg"]},
    {"table": "wp_comments", "key": "comment_ID", "id": 5,
     "gated": ["see pic.png"]},
)
SCAN_END = {"ok": True, "rows": 2, "gated_cells": 2, "truncated": False}


def scan_end(count, **extra):
    return {"ok": True, "rows": count, "gated_cells": 0,
            "truncated": False, **extra}


def test_iter_rewrite_refs_yields_the_rows_and_asks_for_the_read_mode():
    bridge, _, session = make(script=[ndjson(*SCAN, SCAN_END)])
    rows = list(bridge.iter_rewrite_refs())
    assert rows == list(SCAN)
    # the read mode: no apply flag on the wire, so the op's own default
    # (false) is the fail-closed path
    assert session.posts[0][1]["json"] == {
        "action": "media_rewrite_refs", "params": {}}


def test_iter_rewrite_refs_refuses_a_truncated_scan():
    # A half-measured reference set cannot prove that converting an image is
    # safe: the op's own marker ends the stream and the client refuses.
    bridge, _, _ = make(script=[ndjson(SCAN[0], {"truncated": True})])
    with pytest.raises(BridgeError, match="truncated"):
        list(bridge.iter_rewrite_refs())


def test_iter_rewrite_refs_refuses_a_stream_that_never_completed():
    # A connection cut or a fatal after the first lines would otherwise look
    # like a complete (and much smaller) answer.
    bridge, _, _ = make(script=[ndjson(SCAN[0])])
    with pytest.raises(BridgeError, match="without its completion marker"):
        list(bridge.iter_rewrite_refs())


@pytest.mark.parametrize("row", [
    {"key": "ID", "id": 7, "value": "x.jpg"},          # no table
    {"table": "wp_posts", "id": 7, "value": "x.jpg"},   # no key column
    {"table": "", "key": "ID", "id": 7},                # empty table
    {"table": "wp_posts", "key": "ID", "id": "7"},      # id is not an int
    {"table": "wp_posts", "key": "ID", "id": True},     # bool is not an id
    {"table": "wp_posts", "key": "ID", "id": 7, "value": 42},
    {"table": "wp_posts", "key": "ID", "id": 7, "gated": "a.jpg"},
    {"table": "wp_posts", "key": "ID", "id": 7, "gated": [7]},
])
def test_iter_rewrite_refs_refuses_a_malformed_row(row):
    # Never skipped: a silently dropped row is a reference the caller
    # believes nothing holds.
    bridge, _, _ = make(script=[ndjson(row, SCAN_END)])
    with pytest.raises(BridgeError, match="anomaly"):
        list(bridge.iter_rewrite_refs())


def test_iter_rewrite_refs_refuses_a_stream_that_lost_a_line():
    # The server counts what it emitted: a line lost in transit (a proxy
    # cut, a truncated chunk) must not pass as a finished scan, because a
    # lost row is a reference the caller believes nothing holds.
    bridge, _, _ = make(script=[ndjson(SCAN[0], scan_end(2))])
    with pytest.raises(BridgeError, match="the server reported 2 row"):
        list(bridge.iter_rewrite_refs())


@pytest.mark.parametrize("declared", ["2", True, None, 2.0, {}, [2]])
def test_iter_rewrite_refs_refuses_a_row_count_it_cannot_cross_check(declared):
    # THE COMPLETENESS PROOF IS THE COMPARISON, so a count the client
    # cannot read as a number must NOT skip it.  The old guard
    # (`isinstance(declared, int) and ...`) made the whole cross-check
    # conditional on a type nothing validated: a stream of 2 rows ended by
    # {"ok":true,"rows":"2"} was accepted as a FINISHED scan — exactly the
    # lost-line case the count exists to catch.  A non-int (or bool) count
    # is refused like a missing summary.
    bridge, _, _ = make(script=[ndjson(*SCAN, scan_end(declared))])
    with pytest.raises(BridgeError, match="instead of a row count"):
        list(bridge.iter_rewrite_refs())


def test_iter_rewrite_refs_accepts_a_matching_row_count():
    # the int count is the proof working as intended: cross-checked, equal
    # to the rows that arrived, and the scan completes
    bridge, _, _ = make(script=[ndjson(*SCAN, scan_end(2))])
    assert list(bridge.iter_rewrite_refs()) == list(SCAN)


def test_iter_rewrite_refs_accepts_a_binary_cell():
    # A non-UTF-8 BLOB arrives as bytes (the bridge's b64 wire form): it
    # holds no reference, and a caller that rewrites text ignores it.
    blob = b"\x00\xffbin"
    bridge, _, _ = make(script=[ndjson(
        {"table": "wp_postmeta", "key": "meta_id", "id": 3,
         "value": ["__wpt_b64__", base64.b64encode(blob).decode()]},
        scan_end(1))])
    rows = list(bridge.iter_rewrite_refs())
    assert rows[0]["value"] == blob


def test_iter_rewrite_refs_forwards_the_scan_cap_the_operator_asks_for():
    # THE DOOR, FROM THE SIDE THAT HAS TO REACH IT.  The op's `scan_cap` was
    # a parameter nothing in the tool could send (grep found it only in
    # tests), so a site with more image-bearing rows than the op's default
    # had exactly one way past it: edit the deployed PHP.  A keyword-only
    # argument is what makes it reachable, and the parameter travels on the
    # wire as itself — the op is the validating owner of the bound, so the
    # client forwards what it was given rather than second-guessing it here.
    bridge, _, session = make(script=[ndjson(*SCAN, scan_end(2))])
    assert list(bridge.iter_rewrite_refs(scan_cap=250_000)) == list(SCAN)
    assert session.posts[0][1]["json"] == {
        "action": "media_rewrite_refs", "params": {"scan_cap": 250_000}}


def test_iter_rewrite_refs_asks_for_no_cap_by_default():
    # No argument, no parameter: the answer of a scan nobody resized stays
    # byte-identical to one from before the door existed, and the mirror
    # constants are what a caller reasons about instead.
    from wpt.wpbridge import client
    bridge, _, session = make(script=[ndjson(*SCAN, scan_end(2))])
    list(bridge.iter_rewrite_refs())
    assert session.posts[0][1]["json"] == {
        "action": "media_rewrite_refs", "params": {}}
    assert client.REWRITE_REF_SCAN_CAP == 100_000
    assert client.REWRITE_REF_SCAN_CAP_MAX == 1_000_000


def _caplog_warnings(caplog, run):
    """Run ``run`` with the wpt log tree captured (it does not propagate)."""
    wpt_logger = logging.getLogger("wpt")
    wpt_logger.addHandler(caplog.handler)
    caplog.set_level(logging.WARNING, logger="wpt")
    try:
        result = run()
    finally:
        wpt_logger.removeHandler(caplog.handler)
    return result, [r for r in caplog.records
                    if r.levelno >= logging.WARNING]


def test_iter_rewrite_refs_warns_when_the_server_clamped_the_cap(caplog):
    # The op honours at most its ceiling, and says so ONCE on the line the
    # client already reads as "the scan finished".  That marker is only
    # useful if somebody sees it: a caller who asked to measure 5 million
    # rows and is handed the ceiling must not read the plan that follows as
    # a complete measurement of the site.
    bridge, _, _ = make(script=[ndjson(
        *SCAN, scan_end(2, scan_cap_clamped=1_000_000))])
    rows, warnings = _caplog_warnings(
        caplog, lambda: list(bridge.iter_rewrite_refs(scan_cap=5_000_000)))
    assert rows == list(SCAN)
    assert len(warnings) == 1, [r.getMessage() for r in warnings]
    message = warnings[0].getMessage()
    assert "CLAMPED" in message
    assert "1000000" in message


def test_iter_rewrite_refs_says_nothing_about_a_cap_the_server_honoured(caplog):
    # A cap inside the bounds leaves the completion line carrying nothing
    # about the request, and the log with it: a warning on every ordinary
    # scan is a warning nobody reads.
    bridge, _, _ = make(script=[ndjson(*SCAN, scan_end(2))])
    rows, warnings = _caplog_warnings(
        caplog, lambda: list(bridge.iter_rewrite_refs(scan_cap=250_000)))
    assert rows == list(SCAN)
    assert warnings == []


def test_rewrite_refs_sends_the_apply_mapping_and_rows_and_returns_the_re_read():
    bridge, _, session = make(script=[ok_response(rows=[
        {"table": "wp_posts", "id": 7, "value": "<p>pic.webp</p>"},
        {"table": "wp_postmeta", "id": 11, "value": 'a:1:{s:39:"…pic.webp";}'},
    ], failed=[])])
    rows = [{"table": "wp_posts", "key": "ID", "id": 7},
            {"table": "wp_postmeta", "key": "meta_id", "id": 11}]
    out = bridge.rewrite_refs(mapping={"2023/10/pic.jpg": "2023/10/pic.webp"},
                              rows=rows)
    assert [r["value"] for r in out] == [
        "<p>pic.webp</p>", 'a:1:{s:39:"…pic.webp";}']
    assert session.posts[0][1]["json"] == {
        "action": "media_rewrite_refs",
        "params": {"apply": True,
                   "mapping": {"2023/10/pic.jpg": "2023/10/pic.webp"},
                   "rows": rows},
    }


def test_rewrite_refs_raises_on_a_failed_row_naming_only_the_label():
    bridge, _, _ = make(script=[ok_response(
        rows=[], failed=["wp_postmeta[11] (did not verify)"])])

    with pytest.raises(BridgeError) as ei:
        bridge.rewrite_refs(mapping={"a.jpg": "a.webp"},
                            rows=[{"table": "wp_postmeta", "key": "meta_id",
                                   "id": 11}])
    assert "were not rewritten" in str(ei.value)
    assert "wp_postmeta[11]" in str(ei.value)


#: One entry per refusal shape bridge.php's ``failed`` channel carries, in the
#: server's own spelling.  The marked rows are the finding: the PHP label
#: prefixer adds the channel marker to a reason that ALREADY opens with it
#: (every shape-proof refusal does), so the operator read
#: ``refused: refused: …`` — one marker meaning "this row was not written",
#: printed twice.  The last entry is that shape verbatim, which is what a real
#: answer carries and is the only way this test can see the defect at all.
_FAILED_LABEL_SHAPES = [
    "wp_postmeta[11] (did not verify)",
    "wp_postmeta[11] (row not found)",
    "wp_postmeta[11] (write failed)",
    'wp_options[30] (refused: two keys of this value both rewrite to "a.webp",'
    ' and a PHP array would drop one of them)',
    "wp_options[30] (refused: this value is nested too deeply to prove — the "
    "shape walk spent its work budget of 1024 levels on it, and the row is "
    "left exactly as it is)",
    "wp_options[30] (refused: this value cannot be re-stored at all — PHP "
    "cannot encode it for storage a second time)",
    # what the deployed bridge really answers when a shape proof refuses
    "wp_options[30] (refused: refused: this value cannot be re-stored without "
    'losing a member — at level 2 its own serialize()/unserialize() round '
    'trip loses the key "s:k" (a PHP array holds each key once))',
]


@pytest.mark.parametrize("label", _FAILED_LABEL_SHAPES)
def test_a_per_row_refusal_renders_its_marker_exactly_once(label):
    """THE RENDERED TEXT, pinned: one channel marker, whatever the reason.

    The marker is the client-side rendering's to own (the server owns the
    reason and the label shape), so a reason that already opens with it must
    not print it twice.  Every other refusal shape is returned byte-for-byte:
    the marker is not this side's to add to a shape the server chose, and a
    normalizer that "helpfully" marked every parenthetical would turn "did
    not verify" into a different, louder claim.
    """
    carried = label.partition(" (")[2].startswith("refused:")
    rendered = _refusal_label(label)
    assert rendered.count("refused:") == (1 if carried else 0)
    if not carried:
        assert rendered == label          # untouched, marker and all
    # the corpus really does carry the shape the defect produced, or this
    # test would pass without ever measuring it
    assert any(e.count("refused:") > 1 for e in _FAILED_LABEL_SHAPES)
    # the same through the call that reports it
    bridge, _, _ = make(script=[ok_response(rows=[], failed=[label])])
    with pytest.raises(BridgeError) as ei:
        bridge.rewrite_refs(mapping={"a.jpg": "a.webp"},
                            rows=[{"table": "wp_options", "key": "option_id",
                                   "id": 30}])
    message = str(ei.value)
    assert "refused: refused:" not in message
    assert message.count("refused:") == (1 if carried else 0)
    assert rendered in message


def test_a_doubled_refusal_marker_is_collapsed_not_repeated():
    """Even a server label that arrives doubled is rendered once: the marker
    has one owner here, and it is written exactly once."""
    doubled = ("wp_options[30] (refused: refused: refused: this value cannot "
               "be re-stored at all)")
    rendered = _refusal_label(doubled)
    assert rendered == ("wp_options[30] (refused: this value cannot be "
                        "re-stored at all)")
    # a reason that is ONLY the marker keeps the label readable
    assert _refusal_label("wp_options[30] (refused:)") == \
        "wp_options[30] (refused:)"
    # ... and anything without the parenthesised reason shape is untouched
    assert _refusal_label("wp_options[30]") == "wp_options[30]"
    assert _refusal_label("") == ""


def test_a_bare_server_reason_is_marked_here_exactly_once():
    """THE OTHER HALF OF THE MARKER'S ONE OWNER.

    bridge.php's per-row catch used to prefix ``(refused: …)`` to a message
    whose own text already opened with the marker, and the client collapsed
    the duplicate — two producers of one fact.  The server now sends the
    BARE reason, so the marker has to be written HERE or a Throwable the
    shape proofs do not word (a wpdb error, a PHP-level TypeError) would
    reach the operator with no marker at all: the label shape is a
    diagnostic either way, but "this row was not written" is what the marker
    says and only this side says it.

    So a bare reason renders as ``(refused: …)`` — the same text the doubled
    label rendered to before the fix, which is what keeps the operator's
    view of a work-budget refusal unchanged."""
    bare = "wp_options[30] (this value is nested too deeply to prove)"
    rendered = _refusal_label(bare)
    assert rendered == ("wp_options[30] (refused: this value is nested too "
                        "deeply to prove)")
    assert rendered.count("refused:") == 1
    # the round-5 guard still holds on the OTHER producer's spelling: a
    # reason that already carries the marker renders once, byte-identical
    assert _refusal_label(rendered) == rendered
    # ... and the server's own status labels are still not marked (they are
    # not reasons; marking them is a louder claim, not a truer one)
    for status in ("row not found", "write failed", "did not verify"):
        assert _refusal_label(f"wp_postmeta[11] ({status})") == \
            f"wp_postmeta[11] ({status})"

    # ... and end to end through the real client, which is the only place
    # the channel is assembled
    bridge, _, _ = make(script=[ok_response(rows=[], failed=[bare])])
    with pytest.raises(BridgeError) as ei:
        bridge.rewrite_refs(mapping={"a.jpg": "a.webp"},
                            rows=[{"table": "wp_options", "key": "option_id",
                                   "id": 30}])
    message = str(ei.value)
    assert message.count("refused:") == 1
    assert rendered in message


def test_the_refusal_marker_is_defined_once():
    """No second copy of the marker can come back: the module names it once
    and the renderers reach for that name."""
    import inspect

    from wpt.wpbridge import client

    source = inspect.getsource(client)
    assert source.count('"refused:"') == 1, (
        "the refusal marker is spelled out more than once in the client; it "
        "has ONE owner (_REFUSAL_MARKER) or the rendering and the constant "
        "can drift")
    assert client._REFUSAL_MARKER == "refused:"


def test_the_row_status_labels_are_exactly_the_ones_the_server_writes():
    """The counterpart pin for :data:`client._ROW_STATUS_LABELS`, and the
    marker has no producer left on the server: the three labels the client
    leaves unmarked are the three the server writes itself, and nothing in
    the bridge ASSEMBLES a ``(refused: …)`` label any more.

    Read out of the DEPLOYED file, so a status the server adds is caught
    here instead of being silently marked as a reason, and a second prefixer
    cannot come back unnoticed.  (The four remaining ``refused:`` spellings
    in the bridge are the REASON vocabulary — the shape proofs word their
    refusals that way so a caller reading a refusal string always finds the
    marker — and the client's own test pins that the reason it renders
    carries the marker exactly once.)"""
    from wpt.wpbridge import client

    source = BRIDGE_SOURCE.read_text(encoding="utf-8")
    written = set(re.findall(
        r"\$failed\[\] = \$label \. ' \(([a-z ]+)\)'", source))
    assert written == {"row not found", "write failed", "did not verify"}, \
        written
    assert client._ROW_STATUS_LABELS == written
    # the per-row catch sends the BARE message: no label prefixer writes the
    # marker, so the client is its only producer
    catch = re.search(r"\$failed\[\] = \$label \. ' \('\s*\n"
                      r"\s*\. wpt_media_rewrite_label_key", source)
    assert catch, ("the per-row catch no longer sends a bare message; the "
                   "refusal marker must have exactly one producer and it is "
                   "the client's")
    assert "' (refused: '" not in source


def test_rewrite_refs_refuses_an_answer_that_omits_a_requested_row():
    # The op answers every row it wrote; an answer that quietly omits one
    # is a partial write, and a partial write fails the caller's run.
    bridge, _, _ = make(script=[ok_response(
        rows=[{"table": "wp_posts", "id": 7, "value": "x.webp"}], failed=[])])
    with pytest.raises(BridgeError, match="omits 1 requested row"):
        bridge.rewrite_refs(mapping={"a.jpg": "a.webp"}, rows=[
            {"table": "wp_posts", "key": "ID", "id": 7},
            {"table": "wp_posts", "key": "ID", "id": 8},
        ])


@pytest.mark.parametrize("payload", [
    {"failed": []},                                    # no rows list
    {"rows": {}, "failed": []},                        # rows not a list
    {"rows": [], "failed": "boom"},                    # failed not a list
    {"rows": [], "failed": [7]},                       # failed entry not a label
    {"rows": [{"table": "wp_posts", "id": 7}], "failed": []},        # no value
    {"rows": [{"table": "wp_posts", "id": "7", "value": "x"}], "failed": []},
    {"rows": [{"id": 7, "value": "x"}], "failed": []},  # no table
    {"rows": ["x"], "failed": []},                     # row not an object
])
def test_rewrite_refs_response_contract_violations_raise(payload):
    bridge, _, _ = make(script=[ok_response(**payload)])
    with pytest.raises(BridgeError, match="anomaly"):
        bridge.rewrite_refs(mapping={"a.jpg": "a.webp"},
                            rows=[{"table": "wp_posts", "key": "ID", "id": 7}])


# --- the client compares the re-read against what it asked to write (D1) ---

WANT = "<p>2023/10/pic.webp</p>"


def test_rewrite_refs_compares_every_value_it_supplied_and_passes_on_a_match():
    # The re-read EQUALS the value the client asked to write: the write is
    # proven WHAT was written, not merely THAT a write happened.
    bridge, _, _ = make(script=[ok_response(rows=[
        {"table": "wp_postmeta", "id": 7, "value": WANT}], failed=[])])
    out = bridge.rewrite_refs(mapping={"2023/10/pic.jpg": "2023/10/pic.webp"},
                              rows=[{"table": "wp_postmeta", "key": "meta_id",
                                     "id": 7, "value": WANT}])
    assert [r["value"] for r in out] == [WANT]
    assert "rewritten_by_server" not in out[0]  # compared, so not flagged


def test_rewrite_refs_refuses_a_re_read_that_is_not_what_it_asked_to_write():
    # The server's re-read proves THAT a write landed, never WHAT landed: a
    # server that re-reads the OLD value (or an unrelated row's content) and
    # the call said "fine" before.  The fake answers 'WRONG' for a row the
    # client asked to write '<p>…pic.webp</p>' — that is now refused.
    bridge, _, _ = make(script=[ok_response(rows=[
        {"table": "wp_postmeta", "id": 7, "value": "WRONG"}], failed=[])])
    with pytest.raises(BridgeError) as ei:
        bridge.rewrite_refs(mapping={"2023/10/pic.jpg": "2023/10/pic.webp"},
                            rows=[{"table": "wp_postmeta", "key": "meta_id",
                                   "id": 7, "value": WANT}])
    msg = str(ei.value)
    assert "does not match the value this client asked" in msg
    assert "wp_postmeta[7]" in msg          # the label identifies the row
    assert WANT not in msg and "WRONG" not in msg   # never a value


def test_rewrite_refs_refuses_a_re_read_that_echoed_the_pre_write_value():
    # the same defect in its most likely real shape: the row still holds the
    # value the client read BEFORE the rewrite, so the reference was never
    # moved even though the op claimed success.
    bridge, _, _ = make(script=[ok_response(rows=[
        {"table": "wp_postmeta", "id": 7,
         "value": "<p>2023/10/pic.jpg</p>"}], failed=[])])
    with pytest.raises(BridgeError, match="did not verify"):
        bridge.rewrite_refs(mapping={"2023/10/pic.jpg": "2023/10/pic.webp"},
                            rows=[{"table": "wp_postmeta", "key": "meta_id",
                                   "id": 7, "value": WANT}])


def test_rewrite_refs_refuses_a_binary_re_read_for_a_row_it_wrote_itself():
    # a text value cannot come back as bytes: types that cannot be equal are
    # not a match, and must not be waved through as one
    bridge, _, _ = make(script=[ok_response(rows=[
        {"table": "wp_postmeta", "id": 7,
         "value": ["__wpt_b64__", base64.b64encode(WANT.encode()).decode()]},
    ], failed=[])])
    with pytest.raises(BridgeError, match="did not verify"):
        bridge.rewrite_refs(mapping={"a.jpg": "a.webp"},
                            rows=[{"table": "wp_postmeta", "key": "meta_id",
                                   "id": 7, "value": WANT}])


def test_rewrite_refs_flags_a_server_rewritten_row_instead_of_proving_it():
    # A row the client gave NO value for: the server rewrote a serialized
    # value itself (only maybe_serialize can fix an s:NN: length).  The
    # client cannot recompute the answer, so the re-read is REPORTED, never
    # passed off as an equality proof — the flag says which it is.
    bridge, _, _ = make(script=[ok_response(rows=[
        {"table": "wp_postmeta", "id": 11,
         "value": 'a:1:{s:39:"2023/10/pic.webp";}'}], failed=[])])
    out = bridge.rewrite_refs(mapping={"2023/10/pic.jpg": "2023/10/pic.webp"},
                              rows=[{"table": "wp_postmeta", "key": "meta_id",
                                     "id": 11}])
    assert out[0]["rewritten_by_server"] is True
    assert out[0]["value"] == 'a:1:{s:39:"2023/10/pic.webp";}'  # the report


def test_rewrite_refs_flags_only_the_rows_it_could_not_itself_write():
    # mixed batch: the plain row is compared, the serialized one is flagged
    bridge, _, _ = make(script=[ok_response(rows=[
        {"table": "wp_posts", "id": 7, "value": WANT},
        {"table": "wp_postmeta", "id": 11,
         "value": 'a:1:{s:39:"2023/10/pic.webp";}'}], failed=[])])
    out = bridge.rewrite_refs(mapping={"2023/10/pic.jpg": "2023/10/pic.webp"}, rows=[
        {"table": "wp_posts", "key": "ID", "id": 7, "value": WANT},
        {"table": "wp_postmeta", "key": "meta_id", "id": 11},
    ])
    assert [("rewritten_by_server" in r) for r in out] == [False, True]


# --- a non-UTF-8 re-read cell in the APPLY answer (D2) ---------------------


def test_rewrite_refs_decodes_a_binary_re_read_cell():
    # call() never decodes __wpt_b64__ (only the stream reader does), and
    # the apply answer CAN carry a non-UTF-8 cell: the bridge wraps it as
    # ["__wpt_b64__", …] (a latin1/mojibake option_value is real).  Before,
    # the str|bytes shape check turned that into
    # "malformed row 0 in the re-read answer" — the WHOLE apply reported
    # failure AFTER the row had already been written.  It round-trips now,
    # through the same decoder the stream uses (no second copy).
    blob = b"caf\xe9 \xff pic.jpg"
    bridge, _, _ = make(script=[ok_response(rows=[
        {"table": "wp_options", "id": 9,
         "value": ["__wpt_b64__", base64.b64encode(blob).decode()]}], failed=[])])
    out = bridge.rewrite_refs(mapping={"a.jpg": "a.webp"},
                              rows=[{"table": "wp_options", "key": "option_id",
                                     "id": 9}])
    assert out[0]["value"] == blob
    assert out[0]["rewritten_by_server"] is True  # server-rewritten, still


@pytest.mark.parametrize("cell", [
    ["__wpt_b64__", "###not-base64###"],  # undecodable payload
    ["__wpt_b64__", 5],                  # payload is not a string
])
def test_rewrite_refs_an_undecodable_re_read_cell_is_unproven_not_a_shape_error(cell):
    # The write ALREADY happened for this row, so the failure has to name
    # the row and travel in the failed channel the caller already handles —
    # not abort as a shape error that says nothing about which row landed.
    bridge, _, _ = make(script=[ok_response(rows=[
        {"table": "wp_options", "id": 9, "value": cell},
        {"table": "wp_posts", "id": 7, "value": WANT}], failed=[])])
    with pytest.raises(BridgeError) as ei:
        bridge.rewrite_refs(mapping={"a.jpg": "a.webp"}, rows=[
            {"table": "wp_options", "key": "option_id", "id": 9},
            {"table": "wp_posts", "key": "ID", "id": 7, "value": WANT},
        ])
    msg = str(ei.value)
    assert "could not be proven" in msg
    assert "wp_options[9]" in msg     # the row id, and no value
    assert "malformed row" not in msg


@pytest.mark.parametrize("value", [[1, 2], {"a": 1}, 42, None])
def test_rewrite_refs_a_genuinely_malformed_cell_still_refuses_the_call(value):
    # The unproven channel is for a cell the bridge MARKED as binary and
    # could not decode — not a licence to tolerate a value that is not a
    # cell at all.
    bridge, _, _ = make(script=[ok_response(
        rows=[{"table": "wp_posts", "id": 7, "value": value}], failed=[])])
    with pytest.raises(BridgeError, match="anomaly"):
        bridge.rewrite_refs(mapping={"a.jpg": "a.webp"},
                            rows=[{"table": "wp_posts", "key": "ID", "id": 7,
                                   "value": WANT}])


# ------------------------------------------------------------------ users_reset


def users_payload(*rows, count=None):
    """A users_reset envelope in the wire shape bridge.php pins."""
    return ok_response(results={"users": list(rows),
                                "count": len(rows) if count is None else count})


def test_list_users_is_read_only_and_carries_no_password():
    bridge, _, session = make(script=[users_payload(
        {"login": "admin", "email": "a@example.test", "roles": ["administrator"]},
        {"login": "editor", "email": "e@example.test", "roles": []},
    )])
    users = bridge.list_users()
    assert [u["login"] for u in users] == ["admin", "editor"]
    # NO apply flag on the wire: the bridge defaults it to false, so a
    # dry run can never generate a password or touch a session.
    assert session.posts[0][1]["json"] == {
        "action": "users_reset", "params": {},
    }


def test_reset_users_sends_the_strict_apply_flag():
    bridge, _, session = make(script=[users_payload(
        {"login": "admin", "email": "a@example.test",
         "roles": ["administrator"], "sessions_destroyed": True,
         "password": "s3cr3t!"},
    )])
    users = bridge.reset_users()
    assert users[0]["password"] == "s3cr3t!"
    assert session.posts[0][1]["json"] == {
        "action": "users_reset", "params": {"apply": True},
    }


def test_reset_users_targets_named_logins():
    bridge, _, session = make(script=[users_payload(
        {"login": "editor", "email": "e@example.test", "roles": ["editor"],
         "sessions_destroyed": True, "password": "s3cr3t!"},
    )])
    users = bridge.reset_users(logins=["editor"])
    assert [u["login"] for u in users] == ["editor"]
    assert session.posts[0][1]["json"] == {
        "action": "users_reset",
        "params": {"apply": True, "logins": ["editor"]},
    }


def test_reset_users_accepts_any_iterable_of_logins():
    bridge, _, session = make(script=[users_payload(
        {"login": "editor", "email": "e@example.test", "roles": ["editor"],
         "sessions_destroyed": True, "password": "s3cr3t!"},
    )])
    bridge.reset_users(logins=iter(["editor"]))
    assert session.posts[0][1]["json"]["params"]["logins"] == ["editor"]


@pytest.mark.parametrize("results", [
    None,                                  # no results map
    {"count": 1},                          # no users list
    {"users": {}, "count": 0},             # users not a list
    {"users": [{"login": "a"}], "count": 2},  # count disagrees
    {"users": [{"login": "a", "email": "e", "roles": ["x"]}], "count": "1"},
    {"users": [{"email": "e", "roles": []}], "count": 1},        # no login
    {"users": [{"login": "", "email": "e", "roles": []}], "count": 1},
    {"users": [{"login": "a", "roles": []}], "count": 1},        # no email
    {"users": [{"login": "a", "email": "e", "roles": "x"}], "count": 1},
    {"users": [{"login": "a", "email": "e", "roles": [1]}], "count": 1},
    {"users": ["admin"], "count": 1},                            # row not a map
])
def test_users_payload_contract_violations_raise(results):
    # A half-understood answer must never be returned as a successful
    # reset: the caller would report users it knows nothing about.
    bridge, _, _ = make(script=[ok_response(results=results)])
    with pytest.raises(BridgeError) as ei:
        bridge.list_users()
    assert "anomaly" in str(ei.value)
    assert ei.value.payload == {"ok": True, "results": results}


@pytest.mark.parametrize("row", [
    {"login": "admin", "email": "e", "roles": []},                       # none
    {"login": "admin", "email": "e", "roles": [], "password": ""},       # empty
    {"login": "admin", "email": "e", "roles": [], "password": None},     # none
])
def test_reset_users_requires_a_password_on_every_row(row):
    bridge, _, _ = make(script=[users_payload(row)])
    with pytest.raises(BridgeError) as ei:
        bridge.reset_users()
    assert "no password" in str(ei.value)


def test_reset_users_failure_carries_the_complete_partial_rows():
    """C12: the bridge answers ok:false WITH the accounts whose password was
    already set.  The client validates and attaches them so the action can
    publish every live credential before failing closed; an incomplete row
    is dropped, never published half-filled."""
    complete = {"login": "admin", "email": "a@example.test",
                "roles": ["administrator"], "sessions_destroyed": True,
                "password": "PARTIAL-PASSWORD"}
    bridge, _, _ = make(script=[err_response(results={
        "users": [complete, {"login": "editor"}], "count": 2})])

    with pytest.raises(BridgeError) as ei:
        bridge.reset_users()
    assert ei.value.payload["partial_users"] == [complete]
    assert "PARTIAL-PASSWORD" not in str(ei.value)


def test_reset_users_failure_surfaces_the_scrubbed_failed_reasons():
    """R20-P2: the bridge emits per-login ``failed_reasons`` (password set
    but a later step failed vs. the reset failing), but BridgeError kept only
    ``error``.  The operator's one diagnosis must carry them."""
    bridge, _, _ = make(script=[err_response(
        results={"users": [], "count": 0},
        failed=["editor"],
        failed_reasons={
            "editor": "password was reset but a later step failed: "
                      "session cleanup",
        },
    )])
    with pytest.raises(BridgeError) as ei:
        bridge.reset_users()
    message = str(ei.value)
    assert "bridge action failed" in message
    assert "editor: password was reset but a later step failed" in message
    assert ei.value.payload["failed_reasons"]["editor"].startswith("password")


def test_reset_users_never_logs_the_password(caplog):
    # The secrets discipline: the client returns the credentials and logs
    # NOTHING about them (not even at debug level).
    logging.getLogger("wpt").addHandler(caplog.handler)
    caplog.set_level(logging.DEBUG, logger="wpt")
    try:
        bridge, _, _ = make(script=[users_payload(
            {"login": "admin", "email": "a@example.test", "roles": [],
             "password": "UNIQUE-PASSWORD-VALUE"},
        )])
        bridge.reset_users()
    finally:
        logging.getLogger("wpt").removeHandler(caplog.handler)
    assert caplog.records
    for record in caplog.records:
        assert "UNIQUE-PASSWORD-VALUE" not in str(record.__dict__)


# ------------------------------------------------------------------ user_create


def created_payload(row, *, apply=False):
    """A user_create envelope in the wire shape bridge.php pins."""
    return ok_response(results={"user": row, "apply": apply})


def test_check_create_user_is_read_only_and_carries_no_password():
    bridge, _, session = make(script=[created_payload(
        {"login": "newadmin", "email": "n@example.test",
         "roles": ["administrator"]},
    )])
    row = bridge.check_create_user("newadmin", "n@example.test", "administrator")
    assert row["login"] == "newadmin"
    # NO apply flag on the wire: the bridge defaults it to false, so a
    # dry run can never generate a password or write a row.
    assert session.posts[0][1]["json"] == {
        "action": "user_create",
        "params": {"login": "newadmin", "email": "n@example.test",
                   "role": "administrator"},
    }


def test_create_user_failure_carries_the_complete_created_row():
    """C12: the insert succeeded before the read-back failed.  The client
    attaches that complete row (password included) to the error so the
    action can hand over a credential that is already live."""
    row = {"login": "newadmin", "email": "n@example.test",
           "roles": ["administrator"], "password": "LIVE-PASSWORD"}
    bridge, _, _ = make(script=[err_response(
        results={"user": row, "apply": True}, created=True)])

    with pytest.raises(BridgeError) as ei:
        bridge.create_user("newadmin", "n@example.test", "administrator")
    assert ei.value.payload["partial_user"] == row
    assert "LIVE-PASSWORD" not in str(ei.value)


def test_create_user_sends_the_strict_apply_flag():
    bridge, _, session = make(script=[created_payload(
        {"login": "newadmin", "email": "n@example.test",
         "roles": ["administrator"], "password": "s3cr3t!"},
        apply=True,
    )])
    row = bridge.create_user("newadmin", "n@example.test", "administrator")
    assert row["password"] == "s3cr3t!"
    assert session.posts[0][1]["json"] == {
        "action": "user_create",
        "params": {"apply": True, "login": "newadmin",
                   "email": "n@example.test", "role": "administrator"},
    }


@pytest.mark.parametrize("results", [
    None,                                   # no results map
    {"apply": False},                       # no user row
    {"user": "newadmin"},                   # row not a map
    {"user": {"email": "n@example.test", "roles": []}},      # no login
    {"user": {"login": "", "email": "n@example.test", "roles": []}},
    {"user": {"login": "a", "roles": []}},                 # no email
    {"user": {"login": "a", "email": "e", "roles": "administrator"}},
    {"user": {"login": "a", "email": "e", "roles": [1]}},
])
def test_created_user_payload_contract_violations_raise(results):
    bridge, _, _ = make(script=[ok_response(results=results)])
    with pytest.raises(BridgeError) as ei:
        bridge.check_create_user("newadmin", "n@example.test", "administrator")
    assert "anomaly" in str(ei.value)


@pytest.mark.parametrize("row", [
    {"login": "a", "email": "e", "roles": []},                  # none
    {"login": "a", "email": "e", "roles": [], "password": ""},  # empty
    {"login": "a", "email": "e", "roles": [], "password": None},
])
def test_create_user_requires_a_password_on_the_row(row):
    bridge, _, _ = make(script=[created_payload(row, apply=True)])
    with pytest.raises(BridgeError) as ei:
        bridge.create_user("newadmin", "n@example.test", "administrator")
    assert "no password" in str(ei.value)


def test_create_user_is_not_replayed_after_a_network_error():
    # A lost response after the insert must NOT be retried: the retry
    # would fail on the duplicate the first attempt just created and the
    # live account would stay hidden behind an ordinary error. The failure
    # instead reports that the outcome is unknown.
    bridge, src, session = make(script=[
        requests.ConnectionError("connection reset"),
        created_payload({"login": "newadmin", "email": "n@example.test",
                         "roles": ["administrator"],
                         "password": "s3cr3t!"}, apply=True),
    ])
    with pytest.raises(BridgeError) as ei:
        bridge.create_user("newadmin", "n@example.test", "administrator")
    assert "cannot be replayed safely" in str(ei.value)
    assert "MAY have applied" in str(ei.value)
    assert len(session.posts) == 1     # NO replay
    assert len(src.files) == 1         # and no redeploy, which would only
    #                                    invite the operator to retry blind


def test_create_user_retries_a_connect_timeout():
    # A ConnectTimeout is provably pre-send (no connection was established),
    # so the replay is safe and still happens.
    bridge, _, session = make(script=[
        requests.ConnectTimeout("connect timed out"),
        created_payload({"login": "newadmin", "email": "n@example.test",
                         "roles": ["administrator"],
                         "password": "s3cr3t!"}, apply=True),
    ])
    row = bridge.create_user("newadmin", "n@example.test", "administrator")
    assert row["password"] == "s3cr3t!"
    assert len(session.posts) == 2


def test_create_user_anomaly_redacts_the_password():
    # A validation failure on an APPLY call must not echo the credential:
    # neither the message nor the payload attached to the exception.
    bridge, _, _ = make(script=[created_payload(
        {"login": "newadmin", "email": "n@example.test",
         "roles": "not-a-list", "password": "UNIQUE-PASSWORD-VALUE"},
        apply=True,
    )])
    with pytest.raises(BridgeError) as ei:
        bridge.create_user("newadmin", "n@example.test", "administrator")
    assert "UNIQUE-PASSWORD-VALUE" not in str(ei.value)
    assert "UNIQUE-PASSWORD-VALUE" not in json.dumps(ei.value.payload)
    assert ei.value.payload["results"]["user"]["password"] == "***"


def test_create_user_body_never_reaches_a_log_or_an_exception(caplog):
    # The same withheld-body rule users_reset needs (the shared free-text
    # redactor cannot blank a JSON `"password":"..."` pair), pinned for the
    # second credential-bearing op.
    secret = "UNIQUE-PASSWORD-VALUE"
    body = FakeResponse(200, "<br />Notice: leading html\n"
                             + json.dumps({"ok": True, "results": {
                                 "user": {"login": "a", "email": "e",
                                          "roles": [], "password": secret},
                                 "apply": True}}))
    logging.getLogger("wpt").addHandler(caplog.handler)
    caplog.set_level(logging.DEBUG, logger="wpt")
    try:
        bridge, _, _ = make(script=[body])
        with pytest.raises(BridgeError) as ei:
            bridge.create_user("newadmin", "n@example.test", "administrator")
    finally:
        logging.getLogger("wpt").removeHandler(caplog.handler)
    assert secret not in str(ei.value)
    assert caplog.records
    for record in caplog.records:
        assert secret not in str(record.__dict__)


# ------------------------------------------------------- reconcile_active_plugins


def test_reset_users_anomaly_redacts_the_password(caplog):
    # A validation failure on an APPLY call must not echo the credential:
    # neither the message nor the payload attached to the exception (a
    # caller may log either).
    logging.getLogger("wpt").addHandler(caplog.handler)
    caplog.set_level(logging.DEBUG, logger="wpt")
    try:
        bridge, _, _ = make(script=[users_payload(
            {"login": "admin", "email": "a@example.test",
             "roles": "not-a-list", "password": "UNIQUE-PASSWORD-VALUE"},
        )])
        with pytest.raises(BridgeError) as ei:
            bridge.reset_users()
    finally:
        logging.getLogger("wpt").removeHandler(caplog.handler)
    assert "UNIQUE-PASSWORD-VALUE" not in str(ei.value)
    assert "UNIQUE-PASSWORD-VALUE" not in json.dumps(ei.value.payload)
    assert ei.value.payload["results"]["users"][0]["password"] == "***"
    assert ei.value.payload["results"]["users"][0]["login"] == "admin"
    for record in caplog.records:
        assert "UNIQUE-PASSWORD-VALUE" not in str(record.__dict__)


def test_reset_users_body_never_reaches_a_log_or_an_exception(caplog):
    # The one leak path the happy-path test above cannot see: the ERROR
    # paths that excerpt the response body. A users_reset answer is the only
    # place a plaintext password exists, the shared free-text redactor
    # cannot blank a JSON `"password":"..."` pair (the closing quote sits
    # between key and separator), and those error paths fire exactly when
    # the body did NOT parse — which is a documented condition on real sites
    # (SPEC R12: a WP_DEBUG + display_errors site emits HTML before the
    # bridge's JSON). So no body excerpt at all for this op.
    secret = "UNIQUE-PASSWORD-VALUE"
    bodies = [
        # 200 + leading PHP notice: json() fails -> "non-JSON" excerpt.
        FakeResponse(200, "<br />Notice: something\n"
                          + json.dumps({"ok": True, "results": {"users": [
                              {"login": "admin", "email": "a@example.test",
                               "roles": [], "sessions_destroyed": True,
                               "password": secret}], "count": 1}})),
        # 200 + valid JSON, but not an object: the "non-object" excerpt.
        FakeResponse(200, json.dumps([{"password": secret}])),
        # A non-200 carrying the payload.
        FakeResponse(502, json.dumps({"ok": True, "results": {
            "users": [{"login": "admin", "password": secret}], "count": 1}})),
    ]
    for body in bodies:
        logging.getLogger("wpt").addHandler(caplog.handler)
        caplog.set_level(logging.DEBUG, logger="wpt")
        caplog.clear()
        try:
            bridge, _, _ = make(script=[body])
            with pytest.raises(BridgeError) as ei:
                bridge.reset_users()
        finally:
            logging.getLogger("wpt").removeHandler(caplog.handler)
        assert secret not in str(ei.value), body.status_code
        assert secret not in json.dumps(ei.value.payload), body.status_code
        assert caplog.records, body.status_code
        for record in caplog.records:
            assert secret not in str(record.__dict__), record
    # A NON-secret op keeps its excerpt: the evidence an operator needs to
    # diagnose an L6 404 or a site's leading-HTML response.
    bridge, _, _ = make(script=[FakeResponse(
        200, "<br />Notice: leading html\n" + json.dumps({"ok": True}))])
    with pytest.raises(BridgeError) as ei:
        bridge.call("info")
    assert "leading html" in str(ei.value)


def test_reconcile_active_plugins_is_read_only_by_default():
    bridge, _, session = make(script=[ok_response(
        installed=4, active_before=3, missing=["gone/gone.php"],
        applied=False, updated=None, removed=[], active_after=3,
        active_now=["akismet/akismet.php", "hello.php", "gone/gone.php"],
    )])
    payload = bridge.reconcile_active_plugins()
    assert payload["missing"] == ["gone/gone.php"]
    assert session.posts[0][1]["json"] == {
        "action": "reconcile_active_plugins", "params": {},
    }


def test_reconcile_active_plugins_apply_sends_the_strict_flag():
    bridge, _, session = make(script=[ok_response(
        installed=4, active_before=3, missing=["gone/gone.php"],
        applied=True, updated=True, removed=["gone/gone.php"],
        active_after=2, active_now=["akismet/akismet.php", "hello.php"],
    )])
    payload = bridge.reconcile_active_plugins(apply=True)
    assert payload["removed"] == ["gone/gone.php"]
    assert session.posts[0][1]["json"] == {
        "action": "reconcile_active_plugins", "params": {"apply": True},
    }


# ------------------------------------------------------- triple-check round 2


class _StoreThenRaise(FakeSource):
    """A protocol that stores the STOR bytes and then reports a failure."""

    def __init__(self, refuse_cleanup=False):
        super().__init__()
        self.refuse_cleanup = refuse_cleanup
        self.deletes = []
        self.writes = []

    def write_bytes(self, path, data, *, allow_config=False,
                    allow_core=False):
        self.writes.append(path)
        self.files[path] = data
        raise requests.ConnectionError("STOR landed; the 226 never arrived")

    def delete(self, path):
        self.deletes.append(path)
        if self.refuse_cleanup:
            raise requests.ConnectionError("DELE refused for now")
        self.files.pop(path, None)


def test_BRG1_a_stor_that_lands_then_raises_is_still_cleaned():
    """BRG1: endpoint/token were recorded BEFORE the write, the failed
    ensure attempts cleanup, and a refused cleanup stays destroyable."""
    source = _StoreThenRaise()
    bridge = Bridge(source, FakeSession(), WEBROOT, BridgeSettings(), SITE)
    with pytest.raises(requests.ConnectionError):
        bridge.ensure()
    (endpoint,) = source.writes
    assert endpoint.startswith("bridge-")
    assert endpoint not in source.files
    assert source.deletes == [endpoint]
    assert bridge._endpoint is None and bridge._uploads == []


def test_BRG1_a_refused_cleanup_stays_tracked_and_destroy_removes_it():
    source = _StoreThenRaise(refuse_cleanup=True)
    bridge = Bridge(source, FakeSession([site_404()]),
                    WEBROOT, BridgeSettings(), SITE)
    with pytest.raises(requests.ConnectionError):
        bridge.ensure()
    (endpoint,) = source.writes
    # The cleanup refusal kept the endpoint tracked for the caller's
    # finally-destroy instead of leaving an untracked live bridge.
    assert bridge._endpoint == endpoint
    assert bridge._uploads == [endpoint]

    source.refuse_cleanup = False
    bridge.destroy()

    assert endpoint not in source.files
    # destroy is idempotent: a proven removal clears the tracking, so a
    # second destroy has nothing to check or retry.
    assert bridge._endpoint is None
    assert bridge._name is None and bridge._token is None
    assert bridge._uploads == []


class _MaskedExistsStoreThenRaise(_StoreThenRaise):
    """BRG1/N1: the failure shape plus an exists() that masks ``False``."""

    def exists(self, path):
        if path.startswith("bridge-"):
            return False
        return super().exists(path)


def test_N1_a_masked_exists_does_not_leave_a_stored_bridge_untracked():
    """N1: trusting exists() after a STOR-then-raise skipped the delete and
    cleared the endpoint tracking, so destroy() could never remove the live
    token-gated file."""
    source = _MaskedExistsStoreThenRaise()
    bridge = Bridge(source, FakeSession(), WEBROOT, BridgeSettings(), SITE)

    with pytest.raises(requests.ConnectionError):
        bridge.ensure()

    (endpoint,) = source.writes
    assert endpoint not in source.files
    assert source.deletes == [endpoint]
    assert bridge._endpoint is None and bridge._uploads == []


def test_N1_a_masked_exists_refusal_stays_tracked_until_destroy():
    """N1: when the unconditional cleanup delete is refused too, the
    endpoint stays tracked even though exists() says absent; destroy() then
    corroborates it against the listing and removes it."""
    source = _MaskedExistsStoreThenRaise(refuse_cleanup=True)
    bridge = Bridge(source, FakeSession([site_404()]),
                    WEBROOT, BridgeSettings(), SITE)

    with pytest.raises(requests.ConnectionError):
        bridge.ensure()

    (endpoint,) = source.writes
    assert bridge._endpoint == endpoint
    assert bridge._uploads == [endpoint]

    source.refuse_cleanup = False
    bridge.destroy()

    assert endpoint not in source.files


class _MaskedExistsStore(FakeSource):
    """A successful write whose exists() cannot see bridge names."""

    def exists(self, path):
        if path.startswith("bridge-"):
            return False
        return super().exists(path)


def test_N1_destroy_does_not_trust_a_masked_exists():
    """N1: an exists() that always says False must not make destroy() skip
    the endpoint it deployed."""
    source = _MaskedExistsStore()
    bridge = Bridge(source, FakeSession([site_404()]),
                    WEBROOT, BridgeSettings(), SITE)
    endpoint = bridge.ensure()

    bridge.destroy()

    assert endpoint not in source.files


def test_CLEANUP_STOP_a_stop_during_bridge_cleanup_is_not_masked():
    """P2-CLEANUP-STOP: Bridge.ensure's cleanup catch swallowed
    StopRequested and re-raised the original write failure."""
    from wpt.types import StopRequested

    class WriteFailDeleteStop(FakeSource):
        def write_bytes(self, path, data, *, allow_config=False,
                        allow_core=False):
            raise SourceError("upload refused")

        def delete(self, path):
            raise StopRequested("received SIGTERM (15)")

    bridge, _src, _session = make()
    bridge._source = WriteFailDeleteStop()
    with pytest.raises(StopRequested):
        bridge.ensure()


# ------------------------------------------------------- round-8 regressions


def test_R8_P2_22_deep_json_is_a_bridge_error_not_recursion():
    """R8-P2-22: ``response.json()`` on a 100 000-deep payload raised
    RecursionError out of Bridge.call; the parse boundary must translate it."""
    deep = ('{"ok": true, "value": ' + "[" * 100_000 + "0"
            + "]" * 100_000 + "}")
    bridge, _src, _session = make([FakeResponse(200, deep)])

    with pytest.raises(BridgeError, match="non-JSON"):
        bridge.call("info")


def test_R8_P2_22_decode_cells_has_an_explicit_depth_bound():
    """R8-P2-22: the cell decoder recursed without a bound (2 000 levels
    raised RecursionError); past the wire bound it is a BridgeError."""
    bridge, _src, _session = make()
    payload = []
    cursor = payload
    for _ in range(100):
        child = []
        cursor.append(child)
        cursor = child

    with pytest.raises(BridgeError, match="deeper than"):
        bridge._decode_cells(payload)


def test_R8_P2_22_deep_stream_line_is_a_bridge_error():
    """The streaming parse boundary is the same untrusted JSON: a deep
    NDJSON line answers BridgeError, never RecursionError."""
    deep = "[" * 100_000 + "0" + "]" * 100_000
    bridge, _src, _session = make([FakeResponse(200, lines=[deep])])

    with pytest.raises(BridgeError, match="malformed NDJSON"):
        list(bridge.call_stream("db_dump"))


def test_R13_raw_bridge_error_is_sanitized_at_both_raise_sites(tmp_path):
    """R13-P2-20: ``BridgeError`` interpolated the raw wire ``error`` text,
    so the bridge token in a server message reached ``str(exc)`` and the
    failure report.  Both the JSON call and the NDJSON stream sanitize at
    the raise site."""
    from wpt.actions.registry import write_failure_report
    from wpt.cli import Ctx
    from wpt.settings import load

    bridge, src, session = make(script=[])
    endpoint = bridge.ensure()
    token = token_of(src, endpoint)
    session.script.append(err_response(
        error=f"plugin exploded on {SITE}/{endpoint}?t={token}"))
    with pytest.raises(BridgeError) as ei:
        bridge.call("info")
    assert token not in str(ei.value)
    assert "***" in str(ei.value)

    stream, src2, session2 = make(script=[])
    endpoint2 = stream.ensure()
    token2 = token_of(src2, endpoint2)
    session2.script.append(FakeResponse(
        200, lines=[json.dumps({"ok": False,
                                "error": f"stream exploded on {SITE}/"
                                         f"{endpoint2}?t={token2}"})]))
    with pytest.raises(BridgeError) as stream_exc:
        list(stream.call_stream("db_dump", tables=["wp_posts"]))
    assert token2 not in str(stream_exc.value)
    assert "***" in str(stream_exc.value)

    report = tmp_path / "failure.md"
    ctx = Ctx(source="ftp://example.test", settings=load(),
              command="info", report_path=report, extra={})
    write_failure_report(ctx, "info", str(ei.value))
    assert token not in report.read_text(encoding="utf-8")
    assert token not in report.with_suffix(".json").read_text(encoding="utf-8")


def test_R14_bridge_error_payload_never_carries_the_raw_token():
    """R14-P2: ``str(exc)`` was sanitized but ``exc.payload['error']``
    still held the raw server text (and therefore the request token).
    The payload is sanitized (structurally) before it is stored."""
    bridge, src, session = make()
    endpoint = bridge.ensure()
    token = token_of(src, endpoint)
    session.script.append(FakeResponse(200, json.dumps({
        "ok": False,
        "error": f"bad request t={token}",
        "type": "RuntimeException",
        "line": 9,
    })))
    with pytest.raises(BridgeError) as ei:
        bridge.call("info")
    assert token not in str(ei.value)
    assert token not in json.dumps(ei.value.payload, default=str)


# ------------------------------------------- round 18: transport size/speed


class _JSONServer:
    """A real HTTP/1.1 server answering every POST with one JSON body."""

    def __init__(self, body: bytes, *, chunk: int = 65536):
        import http.server
        import threading

        self.body = body
        self.chunk = chunk

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    for offset in range(0, len(body), chunk):
                        self.wfile.write(body[offset:offset + chunk])
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *_args):
                pass

        self._server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.site = f"http://127.0.0.1:{self._server.server_port}"

    def close(self):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


def _real_bridge(site: str, settings: BridgeSettings):
    session = requests.Session()
    session.trust_env = False
    bridge = Bridge(FakeSource(), session, WEBROOT, settings, site)
    bridge.ensure()
    return bridge, session


def test_R18_bridge_large_valid_answers_are_not_capped_at_256k():
    """R18-P1: the 16 MiB ``bridge.max_response_bytes`` bound applies on
    BOTH transports.  A real 339,095-byte core map and a 300 KiB answer used
    to fail against the standalone probe's 256 KiB ``_BODY_LIMIT``."""
    for size in (339_095, 300_000):
        payload = json.dumps({"ok": True, "blob": "x" * size}).encode()
        server = _JSONServer(payload)
        sessions = []
        try:
            bridge, session = _real_bridge(server.site, BridgeSettings(
                timeout_s=30))
            sessions.append(session)
            # No run deadline.
            assert len(bridge.call("info")["blob"]) == size
            # And one with an absolute budget.
            bridge2, session2 = _real_bridge(server.site, BridgeSettings(
                timeout_s=30))
            sessions.append(session2)
            assert len(bridge2.call(
                "info", deadline=time.monotonic() + 10)["blob"]) == size
        finally:
            for session in sessions:
                session.close()
            server.close()


def test_R18_bridge_response_cap_bounds_a_runaway_answer():
    """A 32 MiB answer is refused at the 16 MiB cap, never buffered whole."""
    size = 32 * 1024 * 1024
    payload = (b'{"ok": true, "blob": "' + b"x" * size + b'"}')
    server = _JSONServer(payload)
    session = None
    try:
        bridge, session = _real_bridge(server.site, BridgeSettings())
        started = time.monotonic()
        with pytest.raises(BridgeError, match="max_response_bytes"):
            bridge.call("info", deadline=time.monotonic() + 20)
        assert time.monotonic() - started < 15
        # The no-deadline transport has the SAME cap.
        with pytest.raises(BridgeError, match="max_response_bytes"):
            bridge.call("info")
    finally:
        if session is not None:
            session.close()
        server.close()


def test_R18_db_dump_stream_is_exempt_from_the_one_shot_cap():
    """``db_dump`` is NDJSON and streams line-by-line: the one-shot answer
    cap must never truncate/refuse it."""
    lines = [
        json.dumps({"ok": True, "n": i, "pad": "x" * 4096}) + "\n"
        for i in range(3)
    ]
    payload = "".join(lines).encode()
    server = _JSONServer(payload, chunk=8192)
    session = None
    try:
        bridge, session = _real_bridge(server.site, BridgeSettings(
            max_response_bytes=1024, timeout_s=30))
        got = list(bridge.call_stream("db_dump", tables=["wp_posts"]))
        assert [row["n"] for row in got] == [0, 1, 2]
    finally:
        if session is not None:
            session.close()
        server.close()


def test_R18_bridge_64k_reads_keep_512k_under_a_one_second_budget():
    """R18-P1: ``_SocketResponse.raw.read1`` replaced ``iter_content(1)``;
    a fully-buffered 512 KiB answer must fit a 1 s absolute budget, and a
    2 MiB answer must complete at ordinary throughput (not 60 s)."""
    for size, ceiling in ((512 * 1024, 10.0), (2 * 1024 * 1024, 20.0)):
        payload = json.dumps({"ok": True, "blob": "x" * size}).encode()
        server = _JSONServer(payload)
        session = None
        try:
            bridge, session = _real_bridge(server.site, BridgeSettings())
            started = time.monotonic()
            assert len(bridge.call(
                "info", deadline=time.monotonic() + ceiling)["blob"]) == size
            elapsed = time.monotonic() - started
            # Wall-clock shape assertions run under -n 20 --dist worksteal;
            # the one-byte read1 regression took ~60 s, so a generous ceiling
            # proves the mechanism without racing a loaded worker against the
            # transport deadline itself.
            assert elapsed < ceiling, (size, elapsed)
        finally:
            if session is not None:
                session.close()
            server.close()


def test_R21_a_stop_proving_absence_still_deletes_the_endpoint():
    """R21-P2: the initial ``path_may_exist`` sat outside the
    stop-remembering block, so a StopRequested from ``exists`` skipped the
    source fallback and kept the token endpoint tracked.  The stop is
    remembered and the delete is attempted without re-asking the stopped
    lookup."""
    class _StopOnExists(FakeSource):
        stopped = False

        def exists(self, path):
            if self.stopped:
                raise StopRequested("SIGTERM while proving absence")
            return super().exists(path)

    src = _StopOnExists()
    bridge = Bridge(src, FakeSession([]), WEBROOT, BridgeSettings(), SITE)
    endpoint = bridge.ensure()
    src.stopped = True

    with pytest.raises(StopRequested, match="proving absence"):
        bridge.destroy()

    assert endpoint not in src.files
    assert bridge._endpoint is None and bridge._uploads == []


@pytest.mark.parametrize("status", [500, 404])
def test_R24_stream_error_body_is_capped_without_a_deadline(status):
    """R24-P2: both non-200 stream branches called ``_read_body_bounded`` only
    when an absolute deadline existed, so an unbounded run materialized an
    arbitrary error body through ``.text``.  The cap applies unconditionally."""
    bridge, _, _ = make(
        script=[FakeResponse(status, "x" * 100_000)],
        settings=BridgeSettings(max_response_bytes=1024))
    with pytest.raises(BridgeError, match="max_response_bytes"):
        list(bridge.call_stream("db_dump", tables=["wp_posts"]))
