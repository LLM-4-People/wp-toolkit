"""Unit tests for the standalone PHP runtime probe — no network, no WordPress.

``tests.fakes`` supplies the in-memory source and the scripted HTTP double.
Tokens and expiries are read back out of the uploaded bytes, so every
assertion is against what a real host would serve.  The PHP template gets a
syntax check through the local CLI when one exists; the behavioral contract
(403/410/200, self-unlink) lives in the template itself and is pinned by the
rendered-byte tests here.
"""

import base64
import contextlib
import json
import re
import shutil
import socket
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

from tests.fakes import (
    SERVE_POLL_INTERVAL_S,
    FakeResponse,
    FakeSession,
    FakeSource,
)
from wpt import php_probe
from wpt.php_probe import PhpProbe, get_bounded, sweep_stale_probes
from wpt.settings import ProbeSettings
from wpt.types import (DeadlineExceeded, Entry, SIZE_UNKNOWN, SourceError,
                       StopRequested, WptError)

REPO = Path(__file__).resolve().parents[1]
PHP_TEMPLATE = REPO / "wpt" / "php_probe.php"
SITE = "https://site.test"
PHP_CLI = shutil.which("php")

_TOKEN_RE = re.compile(rb"\$wpt_token\s*=\s*'([0-9a-f]{32})'")
_EXPIRES_RE = re.compile(rb"\$wpt_expires\s*=\s*'(\d+)';")
_NAME_RE = re.compile(r"wpt-probe-[0-9a-f]{8}\.php")


# ------------------------------------------------------------------- helpers


def make(script=(), settings=None):
    src = FakeSource()
    session = FakeSession(script)
    probe = PhpProbe(src, session, settings or ProbeSettings(), SITE)
    return probe, src, session


def ok(**payload):
    return FakeResponse(200, json.dumps({"ok": True, **payload}))


def token_of(src, endpoint):
    match = _TOKEN_RE.search(src.files[endpoint])
    assert match, "token placeholder not substituted"
    return match.group(1).decode()


def expiry_of(src, endpoint):
    match = _EXPIRES_RE.search(src.files[endpoint])
    assert match, "expiry literal not rendered"
    return int(match.group(1))


def ops(src, op):
    return [path for _, kind, path in src.ops if kind == op]


def probe_body(expiry):
    return (f"<?php\n$wpt_token = '{'a' * 32}';\n"
            f"$wpt_expires = '{expiry}';\n").encode()


def script_token_hex(monkeypatch, pairs):
    """Make ``secrets.token_hex`` answer the given ``(token, name_suffix)``
    pairs in deployment order (token call then name call per attempt)."""
    queue = []
    for token, suffix in pairs:
        queue.extend([(16, token), (4, suffix)])

    def fake(size):
        expected, value = queue.pop(0)
        assert size == expected
        return value

    monkeypatch.setattr(php_probe.secrets, "token_hex", fake)


# -------------------------------------------------------------------- ensure


def test_ensure_deploys_root_level_hex_name_with_token_and_expiry():
    probe, src, _ = make(settings=ProbeSettings(ttl_minutes=2))
    before = time.time()
    endpoint = probe.ensure()
    after = time.time()

    assert _NAME_RE.fullmatch(endpoint)
    assert endpoint in src.files and "/" not in endpoint
    assert ops(src, "write") == [endpoint]
    data = src.files[endpoint].decode("utf-8")
    assert "__WPT_TOKEN__" not in data and "__WPT_EXPIRES__" not in data
    assert len(token_of(src, endpoint)) == 32
    expiry = expiry_of(src, endpoint)
    assert before + 2 * 60 - 1 <= expiry <= after + 2 * 60


def test_ensure_generates_a_fresh_name_and_token_every_call():
    probe, src, _ = make()
    first = probe.ensure()
    second = probe.ensure()
    assert first != second
    assert _NAME_RE.fullmatch(first) and _NAME_RE.fullmatch(second)
    assert token_of(src, first) != token_of(src, second)
    assert set(src.files) == {first, second}


def test_ensure_retries_a_name_collision_without_overwriting_it(monkeypatch):
    probe, src, _ = make(settings=ProbeSettings(name_retries=3))
    taken = "wpt-probe-00000001.php"
    src.files[taken] = b"the site's own file"
    script_token_hex(monkeypatch, [
        ("1" * 32, "00000001"),   # collision -> retry
        ("2" * 32, "00000002"),   # free -> deploy
    ])

    endpoint = probe.ensure()

    assert endpoint == "wpt-probe-00000002.php"
    assert src.files[taken] == b"the site's own file"  # never overwritten
    assert token_of(src, endpoint) == "2" * 32
    assert ("1" * 32).encode() not in src.files[endpoint]


def test_ensure_exhausts_name_retries_with_a_clear_error(monkeypatch):
    probe, src, _ = make(settings=ProbeSettings(name_retries=2))
    suffixes = ["00000001", "00000002", "00000003"]
    for suffix in suffixes:
        src.files[f"wpt-probe-{suffix}.php"] = b"site file"
    script_token_hex(monkeypatch, [
        (f"{index:032x}", suffix)
        for index, suffix in enumerate(suffixes, start=1)
    ])

    with pytest.raises(WptError, match=r"name_retries=2"):
        probe.ensure()

    assert probe._endpoint is None and probe._deployed == []
    assert ops(src, "write") == []


def test_ensure_write_failure_leaves_no_partial_endpoint_recorded():
    class RefusingSource(FakeSource):
        def write_bytes(self, path, data, *, allow_config=False,
                        allow_core=False):
            raise SourceError("upload refused")

    src = RefusingSource()
    probe = PhpProbe(src, FakeSession([]), ProbeSettings(), SITE)

    with pytest.raises(SourceError, match="upload refused"):
        probe.ensure()

    assert probe._endpoint is None
    assert probe._name is None and probe._token is None
    assert probe._deployed == []
    # N1 rule: the cleanup delete is attempted unconditionally, because a
    # failed write may still have stored the bytes (and exists() may mask
    # that).  This source refused before storing, so the delete is a no-op.
    (endpoint,) = ops(src, "delete")
    assert _NAME_RE.fullmatch(endpoint)
    probe.destroy()  # nothing is tracked -> no second delete attempt
    assert ops(src, "delete") == [endpoint]
    assert src.files == {}


def test_ensure_removes_a_probe_stored_by_a_failing_write():
    """A protocol can store the bytes and still report a failure.  The
    endpoint is recorded before the write so cleanup can remove that file;
    a failed ensure must never leave an untracked live probe."""
    class StoreThenFail(FakeSource):
        def write_bytes(self, path, data, *, allow_config=False,
                        allow_core=False):
            self.files[path] = data
            raise SourceError("STOR reported failure after storing")

    src = StoreThenFail()
    probe = PhpProbe(src, FakeSession([]), ProbeSettings(), SITE)

    with pytest.raises(SourceError, match="STOR reported failure"):
        probe.ensure()

    assert src.files == {}
    assert probe._endpoint is None and probe._deployed == []
    assert ops(src, "delete")


def test_failed_write_keeps_a_refused_cleanup_tracked_for_destroy_retry():
    class StoreThenFailRefuseDelete(FakeSource):
        def __init__(self):
            super().__init__()
            self.refuse_delete = True

        def write_bytes(self, path, data, *, allow_config=False,
                        allow_core=False):
            self.files[path] = data
            raise SourceError("STOR reported failure after storing")

        def delete(self, path, *, allow_config=False):
            if self.refuse_delete:
                raise SourceError("delete refused")
            super().delete(path)

    src = StoreThenFailRefuseDelete()
    probe = PhpProbe(src, FakeSession([]), ProbeSettings(), SITE)

    with pytest.raises(SourceError, match="STOR reported failure"):
        probe.ensure()

    assert len(probe._deployed) == 1
    assert src.files
    src.refuse_delete = False
    probe.destroy()
    assert src.files == {}
    assert probe._deployed == []


class _MaskedExistsStoreThenFail(FakeSource):
    """A STOR-then-fail source whose exists() masks probe names as absent."""

    def __init__(self, refuse_delete=False):
        super().__init__()
        self.refuse_delete = refuse_delete
        self.deletes: list[str] = []

    def write_bytes(self, path, data, *, allow_config=False,
                    allow_core=False):
        self.files[path] = data
        raise SourceError("STOR reported failure after storing")

    def exists(self, path):
        if path.startswith("wpt-probe-"):
            return False
        return super().exists(path)

    def delete(self, path):
        self.deletes.append(path)
        if self.refuse_delete:
            raise SourceError("delete refused")
        super().delete(path)


def test_N1_a_masked_exists_does_not_leave_a_stored_probe_untracked():
    """N1: PhpProbe.ensure had the same shape as the bridge — trust exists()
    and clear tracking, leaving a live token probe destroy() could not see."""
    src = _MaskedExistsStoreThenFail()
    probe = PhpProbe(src, FakeSession([]), ProbeSettings(), SITE)

    with pytest.raises(SourceError, match="STOR reported failure"):
        probe.ensure()

    (endpoint,) = src.deletes
    assert endpoint not in src.files
    assert probe._endpoint is None and probe._deployed == []


def test_N1_a_masked_exists_refusal_stays_tracked_until_destroy():
    src = _MaskedExistsStoreThenFail(refuse_delete=True)
    probe = PhpProbe(src, FakeSession([]), ProbeSettings(), SITE)

    with pytest.raises(SourceError, match="STOR reported failure"):
        probe.ensure()

    assert len(probe._deployed) == 1
    assert src.files

    src.refuse_delete = False
    probe.destroy()

    assert src.files == {}
    assert probe._deployed == []


def test_N1_probe_destroy_does_not_trust_a_masked_exists():
    class MaskedExistsStore(FakeSource):
        def exists(self, path):
            if path.startswith("wpt-probe-"):
                return False
            return super().exists(path)

    src = MaskedExistsStore()
    probe = PhpProbe(src, FakeSession([]), ProbeSettings(), SITE)
    endpoint = probe.ensure()

    probe.destroy()

    assert endpoint not in src.files


def test_ensure_refuses_a_template_without_its_gate_placeholders(
        tmp_path, monkeypatch):
    template = tmp_path / "php_probe.php"
    template.write_text("<?php echo 'not a probe';\n", encoding="utf-8")
    monkeypatch.setattr(php_probe, "_PHP_TEMPLATE", template)
    probe, src, _ = make()

    with pytest.raises(WptError, match="placeholder"):
        probe.ensure()

    assert src.files == {}


# ---------------------------------------------------------------------- call


def test_call_auto_ensures_and_gets_the_exact_token_url():
    probe, src, session = make(script=[ok(php_version="7.1", php_sapi="fpm-fcgi")])

    payload = probe.call()

    (endpoint,) = src.files
    token = token_of(src, endpoint)
    assert payload == {"ok": True, "php_version": "7.1",
                       "php_sapi": "fpm-fcgi"}
    (url, kwargs), = session.gets
    assert url == f"{SITE}/{endpoint}?token={token}"
    assert kwargs["allow_redirects"] is False
    assert kwargs["stream"] is True
    # The per-read timeout is clamped to the remaining absolute budget
    # (PHP1); it can never exceed the configured timeout.
    assert 0 < kwargs["timeout"] <= 15


@pytest.mark.parametrize("status,body,fragment", [
    (500, "server exploded", "HTTP 500"),
    (302, "", "HTTP 302"),
    (200, "not json at all", "non-JSON"),
    (200, "[1, 2, 3]", "non-object"),
    (200, json.dumps({"ok": False, "error": "db down"}), "db down"),
    (200, json.dumps({"ok": 1}), "ok=true"),
])
def test_call_rejects_every_failure_shape(status, body, fragment):
    probe, _, _ = make(script=[FakeResponse(status, body)])

    with pytest.raises(WptError) as excinfo:
        probe.call()

    assert fragment in str(excinfo.value)


def test_PHP_5_token_never_reaches_logs_or_exceptions(wpt_records):
    probe, src, session = make()

    def transport_error(method, url, kwargs):
        # A real requests exception embeds the request URL — with the token.
        raise requests.ConnectionError(
            f"HTTPSConnectionPool(host='site.test', port=443): failed url: {url}"
        )

    session.script.append(transport_error)
    with pytest.raises(WptError) as excinfo:
        probe.call()
    endpoint = next(iter(src.files))
    token = token_of(src, endpoint)

    session.script.append(ok())
    assert probe.call() == {"ok": True}

    assert token not in str(excinfo.value)
    assert excinfo.value.__cause__ is None
    # The raise happens outside the except block, so the raw requests
    # exception is not even reachable as __context__.
    assert excinfo.value.__context__ is None
    assert wpt_records, "no log records captured"
    for record in wpt_records:
        assert token not in str(record.__dict__), record


# ------------------------------------------------------------------- destroy


def test_destroy_deletes_the_deployed_endpoint_and_is_idempotent():
    probe, src, _ = make()
    endpoint = probe.ensure()

    probe.destroy()

    assert endpoint not in src.files
    assert ops(src, "delete") == [endpoint]
    operations = len(src.ops)
    probe.destroy()  # no deployment left -> nothing to check or delete
    assert ops(src, "delete") == [endpoint]
    assert len(src.ops) == operations


def test_destroy_removes_every_endpoint_this_probe_deployed():
    probe, src, _ = make()
    first = probe.ensure()
    second = probe.ensure()

    probe.destroy()

    assert src.files == {}
    assert ops(src, "delete") == [first, second]


def test_destroy_after_the_probe_self_deleted_does_not_call_delete():
    probe, src, _ = make()
    endpoint = probe.ensure()
    del src.files[endpoint]  # @unlink(__FILE__) on the successful answer

    probe.destroy()

    assert ops(src, "delete") == []
    assert probe._endpoint is None and probe._deployed == []


def test_destroy_never_touches_files_it_did_not_deploy():
    probe, src, _ = make()
    foreign_probe = "wpt-probe-deadbeef.php"
    src.files[foreign_probe] = probe_body(int(time.time()) - 60)
    src.files["index.php"] = b"site entry point"
    endpoint = probe.ensure()

    probe.destroy()

    assert endpoint not in src.files
    assert foreign_probe in src.files
    assert src.files["index.php"] == b"site entry point"


def test_destroy_clears_tracking_only_after_proven_removal():
    """A successful cleanup leaves no stale endpoint/name/token behind, so
    a second destroy has nothing to check or retry."""
    probe, src, _ = make()
    endpoint = probe.ensure()
    assert probe._endpoint == endpoint

    probe.destroy()

    assert endpoint not in src.files
    assert probe._endpoint is None
    assert probe._name is None and probe._token is None
    assert probe._deployed == []


def test_destroy_keeps_tracking_after_a_refused_delete_and_retries():
    """The P3 owner rule: a refused DELE keeps the probe tracked, so a
    later destroy retries it instead of reporting a clean teardown."""
    class RefusingDelete(FakeSource):
        def __init__(self):
            super().__init__()
            self.refuse = True
            self.deletes: list[str] = []

        def delete(self, path):
            self.deletes.append(path)
            if self.refuse:
                raise SourceError("delete refused")
            super().delete(path)

    src = RefusingDelete()
    probe = PhpProbe(src, FakeSession([]), ProbeSettings(), SITE)
    endpoint = probe.ensure()

    with pytest.raises(SourceError, match="delete refused"):
        probe.destroy()

    assert src.deletes == [endpoint]
    assert probe._deployed == [endpoint]
    assert probe._endpoint == endpoint
    assert probe._name is not None and probe._token is not None

    src.refuse = False
    probe.destroy()

    assert endpoint not in src.files
    assert probe._deployed == []
    assert probe._endpoint is None
    assert probe._name is None and probe._token is None


# --------------------------------------------------------------------- sweep


def test_PHP_3_sweep_keeps_the_probe_live_at_the_exact_expiry_second(wpt_records):
    src = FakeSource()
    now = int(time.time())
    expired = "wpt-probe-00000001.php"
    boundary = "wpt-probe-00000002.php"
    live = "wpt-probe-00000003.php"
    src.files[expired] = probe_body(now - 60)
    src.files[boundary] = probe_body(now)
    src.files[live] = probe_body(now + 3600)

    removed, skipped = sweep_stale_probes(src, ProbeSettings())

    # The boundary file's literal equals now; PHP still accepts it at that
    # second (strict `>`), so the sweep leaves it exactly like a live one.
    assert (removed, skipped) == (1, 2)
    assert expired not in src.files and boundary in src.files
    assert live in src.files  # may be a concurrent sibling run's live probe
    assert ops(src, "delete") == [expired]
    messages = [record.getMessage() for record in wpt_records]
    assert any("swept 1 expired probe file(s)" in message
               for message in messages)
    assert any("left 2 probe file(s) in place" in message
               for message in messages)


def test_sweep_skips_an_oversized_probe_shaped_file(wpt_records):
    src = FakeSource()
    candidate = "wpt-probe-00000005.php"
    src.files[candidate] = b"x" * (php_probe._PROBE_READ_LIMIT + 1)

    assert sweep_stale_probes(src, ProbeSettings()) == (0, 1)

    assert candidate in src.files
    assert any("sweep bound" in record.getMessage()
               for record in wpt_records)


def test_sweep_keeps_an_unparseable_candidate_and_warns(wpt_records):
    src = FakeSource()
    candidate = "wpt-probe-00000004.php"
    src.files[candidate] = b"<?php echo 'no expiry literal here';\n"

    assert sweep_stale_probes(src, ProbeSettings()) == (0, 1)

    assert candidate in src.files
    warnings = [record.getMessage() for record in wpt_records
                if record.levelname == "WARNING"]
    assert any(candidate in message and "no expiry literal" in message
               for message in warnings)


class _FlakySweepSource(FakeSource):
    def __init__(self, unreadable=frozenset(), undeletable=frozenset()):
        super().__init__()
        self.unreadable = set(unreadable)
        self.undeletable = set(undeletable)

    def read_bytes(self, path):
        if path in self.unreadable:
            raise SourceError("read refused")
        return super().read_bytes(path)

    def delete(self, path):
        if path in self.undeletable:
            raise SourceError("delete refused")
        super().delete(path)


def test_sweep_tolerates_read_and_delete_failures(wpt_records):
    now = int(time.time())
    unreadable = "wpt-probe-00000005.php"
    undeletable = "wpt-probe-00000006.php"
    src = _FlakySweepSource(unreadable={unreadable},
                            undeletable={undeletable})
    src.files[unreadable] = probe_body(now - 60)
    src.files[undeletable] = probe_body(now - 60)

    removed, skipped = sweep_stale_probes(src, ProbeSettings())

    # A delete refusal is a warning, not a removal (and, following the
    # stale-bridge sweep, not a "skipped" verdict either).
    assert (removed, skipped) == (0, 1)
    assert unreadable in src.files and undeletable in src.files
    warnings = [record.getMessage() for record in wpt_records
                if record.levelname == "WARNING"]
    assert any(unreadable in message and "not readable" in message
               for message in warnings)
    assert any(undeletable in message and "could not be removed" in message
               for message in warnings)


def test_sweep_ignores_names_outside_the_exact_deploy_contract(wpt_records):
    src = FakeSource()
    expired = probe_body(int(time.time()) - 60)
    candidates = [
        "wpt-probe-ABCDEF12.php",       # uppercase hex is not our deploy shape
        "wpt-probe-1234567.php",        # 7 hex digits
        "wpt-probe-123456789.php",      # 9 hex digits
        "wpt-probe-12345678.php.bak",   # not .php
        "xwpt-probe-12345678.php",      # prefix must start the name
        "bridge-12345678.php",          # the OTHER wpt artifact
    ]
    for name in candidates:
        src.files[name] = expired
    src.files["wpt-probe-12345678.php/child"] = expired  # a DIRECTORY name

    assert sweep_stale_probes(src, ProbeSettings()) == (0, 0)

    assert all(name in src.files for name in candidates)
    assert ops(src, "delete") == []
    assert wpt_records == []  # nothing considered -> nothing to say


def test_sweep_skips_symlinked_probe_names():
    class LinkedSource(FakeSource):
        def list_dir(self, path):
            entries = super().list_dir(path)
            entries.append(Entry(path="wpt-probe-00000007.php",
                                 is_dir=False, size=10, is_link=True))
            return entries

    src = LinkedSource()
    src.files["wpt-probe-00000008.php"] = probe_body(int(time.time()) - 60)

    # The linked name is not a plain file (never read/deleted); the real
    # expired one is still swept.
    assert sweep_stale_probes(src, ProbeSettings()) == (1, 0)
    assert ops(src, "delete") == ["wpt-probe-00000008.php"]


# ----------------------------------------------------------------- PHP asset


@pytest.mark.skipif(PHP_CLI is None, reason="php CLI not installed")
def test_php_template_lints():
    result = subprocess.run(
        [PHP_CLI, "-l", str(PHP_TEMPLATE)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_rendered_template_carries_token_and_expiry_without_wordpress():
    probe, src, _ = make()
    endpoint = probe.ensure()
    rendered = src.files[endpoint].decode("utf-8")
    token = token_of(src, endpoint)
    expiry = expiry_of(src, endpoint)

    assert token in rendered
    assert str(expiry) in rendered
    assert "__WPT_TOKEN__" not in rendered
    assert "__WPT_EXPIRES__" not in rendered
    assert "wp-load" not in rendered
    assert "phpinfo(" not in rendered
    assert re.search(r"\$wpt_expires\s*=\s*'%d';" % expiry, rendered)


# ------------------------------------------------------- round-1 regressions


class _DripResponse:
    def __init__(self, chunks, delay=0.05):
        self.chunks = chunks
        self.delay = delay
        self.status_code = 200
        self.closed = False

    def iter_content(self, chunk_size=8192):
        for chunk in self.chunks:
            time.sleep(self.delay)
            yield chunk

    def close(self):
        self.closed = True


def test_PHP_1_body_read_has_an_absolute_deadline():
    response = _DripResponse([b"x"] * 100, delay=0.05)
    started = time.monotonic()
    with pytest.raises(WptError, match="absolute timeout"):
        php_probe._body_text(response, time.monotonic() + 0.12)
    assert time.monotonic() - started < 1.0
    assert response.closed is False  # close is the caller's finally


def test_PHP_1_call_arms_the_absolute_body_deadline(monkeypatch):
    probe, _src, _session = make()
    captured = {}

    def fake_body(response, deadline):
        captured["deadline"] = deadline
        return json.dumps({"ok": True})

    monkeypatch.setattr(php_probe, "_body_text", fake_body)
    probe._session.script.append(FakeResponse(200, ""))
    before = time.monotonic()
    assert probe.call() == {"ok": True}
    assert captured["deadline"] >= before + ProbeSettings().timeout_s - 1
    assert captured["deadline"] <= time.monotonic() + ProbeSettings().timeout_s


@pytest.mark.skipif(PHP_CLI is None, reason="php CLI not installed")
def test_PHP_2_self_delete_is_guarded_when_unlink_is_disabled(tmp_path):
    probe, src, _ = make()
    endpoint = probe.ensure()
    token = token_of(src, endpoint)
    rendered = tmp_path / "probe.php"
    rendered.write_bytes(src.files[endpoint])
    wrapper = (
        f'$_GET["token"] = "{token}"; include {str(rendered)!r};'
    )
    result = subprocess.run(
        [PHP_CLI, "-d", "disable_functions=unlink", "-r", wrapper],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "Fatal error" not in result.stdout
    payload = json.loads(result.stdout.strip().splitlines()[-1])
    assert payload["ok"] is True


def test_PHP_4_unverifiable_size_is_skipped_and_read_is_bounded(wpt_records):
    class _Unverifiable(FakeSource):
        def list_dir(self, path):
            return [Entry(path="wpt-probe-00000009.php", is_dir=False,
                          size=SIZE_UNKNOWN)]

        def read_bytes_bounded(self, path, max_bytes):
            raise AssertionError("an unverifiable size must not be read")

    src = _Unverifiable()
    src.files["wpt-probe-00000009.php"] = probe_body(int(time.time()) - 60)

    assert sweep_stale_probes(src, ProbeSettings()) == (0, 1)
    assert any("unverifiable listing size" in record.getMessage()
               for record in wpt_records)


def test_PHP_4_lying_size_still_reads_through_the_sweep_bound(wpt_records):
    class _LyingSize(FakeSource):
        def list_dir(self, path):
            return [Entry(path="wpt-probe-0000000a.php", is_dir=False,
                          size=1)]

        def read_bytes_bounded(self, path, max_bytes):
            self.bound = (path, max_bytes)
            return b"x" * (max_bytes + 1)

    src = _LyingSize()
    src.files["wpt-probe-0000000a.php"] = b"ignored"

    assert sweep_stale_probes(src, ProbeSettings()) == (0, 1)
    assert src.bound == ("wpt-probe-0000000a.php",
                         php_probe._PROBE_READ_LIMIT)
    assert any("over the" in record.getMessage() for record in wpt_records)


def test_PHP_5_non_json_body_is_not_reachable_through_the_exception_graph():
    probe, _src, session = make()
    session.script.append(FakeResponse(200, "TOKEN-BODY-IS-NOT-JSON"))
    with pytest.raises(WptError) as excinfo:
        probe.call()
    error = excinfo.value
    # The sanitized excerpt is the message; the raw JSONDecodeError (whose
    # .doc holds the whole body) must not be reachable as cause/context.
    assert error.__context__ is None
    assert error.__cause__ is None
    assert "non-JSON" in str(error)


def test_PHP_6_nested_json_raises_wpt_error_not_recursion_error():
    probe, _src, session = make()
    session.script.append(FakeResponse(200, "[" * 100000 + "]" * 100000))
    with pytest.raises(WptError, match="non-JSON"):
        probe.call()


# ------------------------------------------------------- triple-check round 2


def test_SWEEP3_a_huge_integer_expiry_is_skipped_not_raised(wpt_records):
    """SWEEP3: ``int('9'*5000)`` raises ValueError above Python's 4300-digit
    limit; it escaped the sweep and aborted every ftp command."""
    src = FakeSource()
    candidate = "wpt-probe-00000009.php"
    src.files[candidate] = (
        b"<?php $wpt_expires = '" + b"9" * 5000 + b"';\n")

    assert sweep_stale_probes(src, ProbeSettings()) == (0, 1)
    assert candidate in src.files
    assert any("unparseable expiry" in record.getMessage()
               for record in wpt_records
               if record.levelname == "WARNING")


class _StoppingProbeSource(FakeSource):
    def __init__(self, stop_on):
        super().__init__()
        self.stop_on = stop_on

    def read_bytes(self, path):
        if self.stop_on == "read":
            raise StopRequested("received SIGTERM (15)")
        return super().read_bytes(path)

    def delete(self, path):
        if self.stop_on == "delete":
            raise StopRequested("received SIGTERM (15)")
        super().delete(path)


def test_SWEEP4_probe_sweep_propagates_stop_on_read_and_delete():
    """SWEEP4: the per-candidate broad ``except Exception`` ate
    StopRequested/DeadlineExceeded, so the sweep reported (0, 1) and the
    caller continued after SIGTERM."""
    import time as _time

    candidate = "wpt-probe-0000000a.php"
    reading = _StoppingProbeSource("read")
    reading.files[candidate] = probe_body(int(_time.time()) - 60)
    with pytest.raises(StopRequested):
        sweep_stale_probes(reading, ProbeSettings())

    deleting = _StoppingProbeSource("delete")
    deleting.files[candidate] = probe_body(int(_time.time()) - 60)
    with pytest.raises(StopRequested):
        sweep_stale_probes(deleting, ProbeSettings())


def _drip_headers_server(tls_context=None):
    """A real socket server that never finishes the response headers.

    Returns ``(port, stop, listener, client_closed)``; ``client_closed`` is
    set as soon as a write fails because the probe hung up at its deadline.
    With ``tls_context`` it terminates TLS (an HTTPS origin).
    """
    import socket

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    stop = threading.Event()
    client_closed = threading.Event()

    def _serve():
        try:
            conn, _ = listener.accept()
            if tls_context is not None:
                conn = tls_context.wrap_socket(conn, server_side=True)
            conn.settimeout(0.25)
            request = b""
            while b"\r\n\r\n" not in request:
                request += conn.recv(4096)
            conn.sendall(b"HTTP/1.1 200 OK\r\n")
            for _ in range(200):
                if stop.is_set():
                    break
                try:
                    conn.sendall(b"X")
                except OSError:
                    client_closed.set()
                    break
                time.sleep(0.25)
            conn.close()
        except OSError:
            client_closed.set()
        finally:
            listener.close()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    return port, stop, listener, client_closed


def test_PHP1_header_drip_is_bounded_by_the_absolute_deadline():
    """PHP1: the timeout covered only body reads, so 20 header bytes dripped
    at 0.25 s each blocked ``call()`` for ~5 s (timeout_s=1).  The call is
    synchronous now: it returns near the deadline, closes the socket, and
    leaves no worker thread behind."""
    import requests as requests_module

    port, stop, listener, client_closed = _drip_headers_server()
    src = FakeSource()
    probe = PhpProbe(src, requests_module.Session(),
                     ProbeSettings(timeout_s=1),
                     f"http://127.0.0.1:{port}")
    probe.ensure()
    started = time.monotonic()
    try:
        with pytest.raises(WptError, match="absolute timeout"):
            probe.call()
        elapsed = time.monotonic() - started
        assert 0.9 <= elapsed < 2.0
        assert not any(thread.name == "wpt-probe-get"
                       for thread in threading.enumerate())
        assert client_closed.wait(1.0), "the server never saw the client close"
    finally:
        stop.set()
        try:
            listener.close()
        except OSError:
            pass
        probe._session.close()


def test_R16_an_expired_budget_writes_and_sends_nothing():
    """R16-P2: ensure/call connected and wrote a probe (and the request
    headers/body) before any remaining-budget check.  An already-expired
    budget deploys no file and sends no request."""
    from wpt.deadline import Deadline

    probe, src, session = make()
    with pytest.raises(DeadlineExceeded):
        probe.call(deadline=time.monotonic() - 1)
    assert src.files == {}
    assert session.gets == []

    with pytest.raises(DeadlineExceeded):
        probe.ensure(deadline=time.monotonic() - 1)
    assert src.files == {}

    probe2, src2, session2 = make()
    expired = Deadline(0.0)
    with pytest.raises(DeadlineExceeded):
        # ensure() itself receives the call's absolute budget.
        probe2.call(deadline=expired.at)
    assert src2.files == {} and session2.gets == []


def test_R17_ensure_checks_the_budget_after_a_slow_exists():
    """R17-2-P2-1: ensure checked only at entry; a slow ``exists`` let the
    write land after the call's whole budget.  The write is now refused
    after the remote lookup and the source budget is capped at the probe
    deadline."""
    class _SlowExists(FakeSource):
        def exists(self, path):
            time.sleep(0.08)
            return super().exists(path)

    src = _SlowExists()
    probe = PhpProbe(src, FakeSession([]), ProbeSettings(), SITE)
    started = time.monotonic()
    with pytest.raises(DeadlineExceeded):
        probe.ensure(deadline=started + 0.05)
    assert time.monotonic() - started < 0.5
    assert src.files == {}
    assert [path for _, op, path in src.ops if op == "write"] == []


def test_R17_destroy_removes_the_probe_after_the_run_budget_expired():
    """R17-6-P1-1: the cleanup budget must be fresh, not the expired run
    budget — otherwise the DELE raises before it is issued and the token
    probe stays live until TTL."""
    from wpt.deadline import Deadline

    class _BudgetedSource(FakeSource):
        def __init__(self):
            super().__init__()
            self.deadline = Deadline(60)
            self.cleanup_deadline_s = 5

        def _check(self):
            if self.deadline is not None:
                self.deadline.check("test probe source")

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

    src = _BudgetedSource()
    probe = PhpProbe(src, FakeSession([]), ProbeSettings(), SITE)
    endpoint = probe.ensure()
    src.deadline = Deadline(-1)
    probe.destroy()
    assert endpoint not in src.files
    assert endpoint in [path for _, op, path in src.ops if op == "delete"]


# --------------------------------------------------- proxy transport (P1)

def _pipe(source, destination):
    """Copy ``source`` to ``destination`` until EOF, then half-close."""
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            destination.sendall(data)
    except OSError:
        pass
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _relay(first, second):
    """Bidirectional byte relay (one direction on a helper thread)."""
    helper = threading.Thread(target=_pipe, args=(first, second), daemon=True)
    helper.start()
    _pipe(second, first)
    helper.join(timeout=5)


class _ProbeOriginHandler(BaseHTTPRequestHandler):
    """A real origin serving the deployed probe bytes as its JSON answer."""

    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        parsed = urlsplit(self.path)
        name = parsed.path.lstrip("/")
        token = parse_qs(parsed.query).get("token", [""])[0]
        data = self.server.files.get(name)
        match = _TOKEN_RE.search(data) if data else None
        ok = match is not None and token == match.group(1).decode()
        body = (json.dumps({"ok": True, "origin": "local"}).encode()
                if ok else b'{"ok": false}')
        self.server.requests.append((
            self.headers.get("Host"), self.path,
            self.headers.get("Proxy-Authorization")))
        self.send_response(200 if ok else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


def test_R18_bodyless_205_is_not_read_as_a_declared_body():
    """R18-P2: RFC 9110 §15.3.6 terminates 205 at the header section.  A
    keep-alive 205 without Content-Length (and one with a bogus length) was
    read as a body until the timeout and reported a transport failure."""
    class _ResetContent(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        requests = 0

        def log_message(self, *_args):
            pass

        def do_GET(self):
            type(self).requests += 1
            self.send_response(205)
            self.send_header("Content-Length", "5")
            self.end_headers()
            self.wfile.flush()
            time.sleep(1.5)      # keep the connection open

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _ResetContent)
    thread = threading.Thread(
        target=lambda: httpd.serve_forever(
            poll_interval=SERVE_POLL_INTERVAL_S),
        daemon=True)
    thread.start()
    site = f"http://127.0.0.1:{httpd.server_port}"
    probe = PhpProbe(FakeSource(), requests.Session(), ProbeSettings(), site)
    probe._session.trust_env = False
    try:
        started = time.monotonic()
        with pytest.raises(WptError, match="HTTP 205"):
            probe.call()
        assert time.monotonic() - started < 0.8
        assert _ResetContent.requests == 1
    finally:
        probe.destroy()
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def test_R18_a_reset_connection_body_read_is_a_transport_failure():
    """R18-P2: a peer that RSTs mid-body leaked a raw ``ConnectionResetError``
    out of ``read_bounded``; the documented per-fetch degrade catches
    ``requests.RequestException``, so it must be translated there."""
    import socket

    class _Reset(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.end_headers()
            self.wfile.flush()
            self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                       b"\x01\x00\x00\x00\x00\x00\x00\x00")
            self.connection.close()

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Reset)
    thread = threading.Thread(
        target=lambda: httpd.serve_forever(
            poll_interval=SERVE_POLL_INTERVAL_S),
        daemon=True)
    thread.start()
    session = requests.Session()
    session.trust_env = False
    try:
        response = get_bounded(
            session, f"http://127.0.0.1:{httpd.server_port}/",
            timeout_s=5, deadline=time.monotonic() + 5)
        with pytest.raises(requests.ConnectionError):
            response.read_bounded(1000)
        response.close()
    finally:
        session.close()
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def test_R25_dns_is_bounded_by_the_request_timeout_not_the_run_deadline(
        monkeypatch):
    """R25-P2: ``_bind_numeric_dns`` received the RUN deadline (up to an
    hour), so a stalling resolver burned the whole budget before the first
    socket existed.  The request's own ``timeout_s`` caps DNS too."""
    import socket

    class _Server(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Server)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    real = socket.getaddrinfo

    def stalling(host, port, *args, **kwargs):
        if host == "probebound.test":
            time.sleep(4)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                     ("127.0.0.1", port))]
        return real(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", stalling)
    session = requests.Session()
    session.trust_env = False
    try:
        started = time.monotonic()
        with pytest.raises((WptError, requests.RequestException)):
            get_bounded(
                session,
                f"http://probebound.test:{httpd.server_port}/",
                timeout_s=1, deadline=time.monotonic() + 3)
        assert time.monotonic() - started < 1.8
    finally:
        session.close()
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("payload", [
    b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\nConnection: close\r\n\r\nHELLO",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n"
    b"\r\n\r\nHELLO",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n"
    b"\r\n+5\r\nHELLO\r\n0\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n"
    b"\r\n0x5\r\nHELLO\r\n0\r\n\r\n",
])
def test_R25_malformed_framing_is_a_transport_error_not_an_empty_body(payload):
    """R25-P2: ``int('-1')`` made a negative Content-Length an immediate
    empty body, and a bare ``int(line, 16)`` read an EMPTY chunk-size line
    as the terminal zero chunk (plus ``+5``/``0x5`` as five).  The shared
    grammar rejects each shape with a transport error."""
    class _Malformed(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def do_GET(self):
            try:
                self.wfile.write(payload)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Malformed)
    thread = threading.Thread(
        target=lambda: httpd.serve_forever(
            poll_interval=SERVE_POLL_INTERVAL_S),
        daemon=True)
    thread.start()
    session = requests.Session()
    session.trust_env = False
    try:
        response = get_bounded(
            session, f"http://127.0.0.1:{httpd.server_port}/",
            timeout_s=2, deadline=time.monotonic() + 2)
        with pytest.raises(requests.ConnectionError):
            response.read_bounded(100)
        response.close()
    finally:
        session.close()
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def test_R16_bodyless_304_is_not_read_as_a_declared_body():
    """R16-P1: a legal 304 with Content-Length: 10 was consumed as a body,
    holding the probe until the timeout and reporting a transport failure.
    1xx/204/304 have no body; the status (304) is the answer."""
    class _NotModified(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        requests = 0

        def log_message(self, *_args):
            pass

        def do_GET(self):
            type(self).requests += 1
            self.send_response(304)
            self.send_header("Content-Length", "10")
            self.end_headers()
            self.wfile.flush()
            time.sleep(1.5)      # keep the connection open

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _NotModified)
    thread = threading.Thread(
        target=lambda: httpd.serve_forever(
            poll_interval=SERVE_POLL_INTERVAL_S),
        daemon=True)
    thread.start()
    site = f"http://127.0.0.1:{httpd.server_port}"
    probe = PhpProbe(FakeSource(), requests.Session(), ProbeSettings(),
                     site)
    probe._session.trust_env = False
    try:
        started = time.monotonic()
        with pytest.raises(WptError, match="HTTP 304"):
            probe.call()
        assert time.monotonic() - started < 0.8
        assert _NotModified.requests == 1
    finally:
        probe.destroy()
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _server_tls_context(cert_path, key_path):
    """A server-side TLS context for the local proxy/origin listeners."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    return context


@contextlib.contextmanager
def _origin_server(files, *, tls_context=None):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _ProbeOriginHandler)
    httpd.files = files
    httpd.requests = []
    if tls_context is not None:
        httpd.socket = tls_context.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(
        target=lambda: httpd.serve_forever(
            poll_interval=SERVE_POLL_INTERVAL_S),
        daemon=True)
    thread.start()
    try:
        yield httpd
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


class _ProbeProxyHandler(BaseHTTPRequestHandler):
    """A real forwarding/CONNECT proxy with optional Basic authentication."""

    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _authorized(self):
        required = self.server.auth
        return required is None or \
            self.headers.get("Proxy-Authorization") == required

    def _deny(self):
        body = b"proxy authentication required"
        self.send_response(407)
        self.send_header("Proxy-Authenticate", 'Basic realm="wpt-test"')
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_CONNECT(self):
        self.server.connects.append((
            self.path, self.headers.get("Proxy-Authorization")))
        if not self._authorized():
            self._deny()
            return
        if self.server.slow_connect:
            # Accept the tunnel request but never answer it: the probe must
            # give up at its absolute deadline, not hang on a dripping or
            # silent proxy.
            self.server.slow_seen.set()
            self.connection.settimeout(5)
            try:
                while self.connection.recv(4096):
                    pass
            except OSError:
                pass
            finally:
                self.server.slow_closed.set()
            return
        host, _, port = self.path.rpartition(":")
        upstream = socket.create_connection(
            (host.strip("[]"), int(port)), timeout=5)
        self.send_response(200, "Connection Established")
        self.end_headers()
        self.wfile.flush()
        _relay(self.connection, upstream)
        try:
            upstream.close()
        except OSError:
            pass

    def do_GET(self):
        self.server.forwards.append((
            self.path, self.headers.get("Proxy-Authorization")))
        if not self._authorized():
            self._deny()
            return
        parsed = urlsplit(self.path)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            self.send_error(400)
            return
        upstream = socket.create_connection(
            (parsed.hostname, parsed.port or 80), timeout=5)
        if parsed.scheme == "https":
            # A forwarding proxy for an HTTPS destination speaks TLS upstream.
            upstream = self.server.upstream_tls_context.wrap_socket(
                upstream, server_hostname=parsed.hostname)
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        lines = [f"GET {target} HTTP/1.1",
                 f"Host: {parsed.netloc.rpartition('@')[2]}"]
        for name, value in self.headers.items():
            if name.lower() in {"host", "proxy-authorization",
                                "proxy-connection", "connection",
                                "accept-encoding"}:
                continue
            lines.append(f"{name}: {value}")
        lines += ["Accept-Encoding: identity", "Connection: close", "", ""]
        upstream.sendall("\r\n".join(lines).encode("latin-1"))
        _pipe(upstream, self.connection)
        try:
            upstream.close()
        except OSError:
            pass


@contextlib.contextmanager
def _proxy_server(*, auth=None, slow_connect=False, tls_context=None,
                  upstream_tls_context=None):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _ProbeProxyHandler)
    if tls_context is not None:
        # An https:// proxy: the client's TLS terminates here, so CONNECT
        # (or a forwarded request) travels inside that TLS session.
        httpd.socket = tls_context.wrap_socket(httpd.socket, server_side=True)
    httpd.upstream_tls_context = upstream_tls_context
    httpd.auth = (None if auth is None else "Basic " + base64.b64encode(
        f"{auth[0]}:{auth[1]}".encode()).decode())
    httpd.slow_connect = slow_connect
    httpd.slow_seen = threading.Event()
    httpd.slow_closed = threading.Event()
    httpd.connects = []
    httpd.forwards = []
    thread = threading.Thread(
        target=lambda: httpd.serve_forever(
            poll_interval=SERVE_POLL_INTERVAL_S),
        daemon=True)
    thread.start()
    try:
        yield httpd
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _proxy_session(proxies, *, verify=True):
    session = requests.Session()
    session.trust_env = False  # environment proxies must not hijack the test
    session.proxies.update(proxies)
    session.verify = verify
    return session


def _forwarding_https_session(proxy_url, *, verify):
    """A session whose HTTPS pool FORWARDS through an HTTPS proxy.

    requests never enables urllib3's ``use_forwarding_for_https`` itself
    (``HTTPAdapter.proxy_manager_for`` builds a default proxy manager), so
    this installs the manager an embedding adapter would: no CONNECT, the
    request target goes to the proxy in absolute-form.
    """
    from urllib3.poolmanager import proxy_from_url

    session = _proxy_session({"https": proxy_url}, verify=verify)
    adapter = requests.adapters.HTTPAdapter()
    adapter.proxy_manager[proxy_url] = proxy_from_url(
        proxy_url, use_forwarding_for_https=True,
        proxy_headers=adapter.proxy_headers(proxy_url))
    session.mount("https://", adapter)
    return session


def _assert_no_probe_worker():
    assert not any(thread.name == "wpt-probe-get"
                   for thread in threading.enumerate())


def test_proxy_transport_http_target_uses_absolute_form():
    """P1: a plain-HTTP target through a forwarding proxy must travel as an
    absolute-form request (requests'/urllib3's contract); the old direct
    ``conn.connect()`` produced an origin-form GET the proxy could not
    route, surfacing as a timeout."""
    src = FakeSource()
    with _origin_server(src.files) as origin, _proxy_server() as proxy:
        proxy_url = f"http://127.0.0.1:{proxy.server_address[1]}"
        session = _proxy_session({"http": proxy_url})
        probe = PhpProbe(src, session, ProbeSettings(timeout_s=3),
                         f"http://127.0.0.1:{origin.server_address[1]}")
        probe.ensure()
        try:
            assert probe.call()["ok"] is True
        finally:
            session.close()

        assert proxy.connects == []  # HTTP targets are forwarded, not tunnelled
        (target, auth) = proxy.forwards[0]
        assert target.startswith("http://127.0.0.1:")
        assert auth is None
        assert origin.requests[0][0].startswith("127.0.0.1:")
        _assert_no_probe_worker()


def test_proxy_transport_https_target_uses_connect(tmp_path):
    """P1: an HTTPS target through a proxy must CONNECT (urllib3's tunnel),
    then speak origin-form through the tunnel."""
    from wpt.dnsoverride import ensure_cert

    cert_path, key_path = ensure_cert(tmp_path / "p1-certs")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    src = FakeSource()
    with _origin_server(src.files, tls_context=context) as origin, \
            _proxy_server() as proxy:
        target = f"127.0.0.1:{origin.server_address[1]}"
        proxy_url = f"http://127.0.0.1:{proxy.server_address[1]}"
        session = _proxy_session({"https": proxy_url}, verify=str(cert_path))
        probe = PhpProbe(src, session, ProbeSettings(timeout_s=3),
                         f"https://{target}")
        probe.ensure()
        try:
            assert probe.call()["ok"] is True
        finally:
            session.close()

        assert proxy.connects == [(target, None)]
        assert proxy.forwards == []  # the GET stayed inside the tunnel
        host, path, _auth = origin.requests[0]
        assert host == target
        assert path.startswith("/wpt-probe-")
        _assert_no_probe_worker()


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_an_authenticated_proxy_receives_the_probe_credentials(scheme,
                                                               tmp_path):
    """P1: proxy credentials belong on the CONNECT (HTTPS target) and on the
    forwarded request (HTTP target).  Without them a real proxy answers 407
    while an ordinary control request succeeds."""
    from wpt.dnsoverride import ensure_cert

    src = FakeSource()
    tls_context = None
    if scheme == "https":
        cert_path, key_path = ensure_cert(tmp_path / "auth-certs")
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.load_cert_chain(cert_path, key_path)
        verify = str(cert_path)
    else:
        verify = True
    with _origin_server(src.files, tls_context=tls_context) as origin, \
            _proxy_server(auth=("user", "secret")) as proxy:
        port = proxy.server_address[1]
        expected = "Basic " + base64.b64encode(b"user:secret").decode()
        proxy_url = f"http://user:secret@127.0.0.1:{port}"
        origin_url = f"{scheme}://127.0.0.1:{origin.server_address[1]}"
        session = _proxy_session({scheme: proxy_url}, verify=verify)
        probe = PhpProbe(src, session, ProbeSettings(timeout_s=3), origin_url)
        probe.ensure()
        try:
            assert probe.call()["ok"] is True
        finally:
            session.close()

        if scheme == "https":
            assert proxy.connects == [
                (f"127.0.0.1:{origin.server_address[1]}", expected)]
            assert proxy.forwards == []
        else:
            assert proxy.connects == []
            assert proxy.forwards[0][1] == expected
        # Credentials belong to the proxy hop only: the origin never sees
        # Proxy-Authorization, whether the request was tunnelled or forwarded.
        assert origin.requests[0][2] is None

        # The proxy really enforces auth: a control request without
        # credentials is refused, so the success above proves the header.
        control = _proxy_session({scheme: f"http://127.0.0.1:{port}"})
        try:
            if scheme == "https":
                with pytest.raises(requests.RequestException):
                    control.get(origin_url, timeout=2)
            else:
                assert control.get(origin_url, timeout=2).status_code == 407
        finally:
            control.close()
        _assert_no_probe_worker()


def test_proxy_transport_https_proxy_connect_to_https_origin(tmp_path):
    """P2: an ``https://`` proxy means TLS to the proxy FIRST; after CONNECT
    urllib3 hands the probe an ``SSLTransport`` (TLS-in-TLS).  It exposes
    ``settimeout``/``fileno``/``recv`` but no ``setblocking``, so the probe's
    unconditional ``setblocking(False)`` failed after the tunnel was up."""
    from wpt.dnsoverride import ensure_cert

    cert_path, key_path = ensure_cert(tmp_path / "tls-proxy-certs")
    tls_context = _server_tls_context(cert_path, key_path)
    src = FakeSource()
    with _origin_server(src.files, tls_context=tls_context) as origin, \
            _proxy_server(tls_context=tls_context) as proxy:
        target = f"127.0.0.1:{origin.server_address[1]}"
        proxy_url = f"https://127.0.0.1:{proxy.server_address[1]}"
        session = _proxy_session({"https": proxy_url}, verify=str(cert_path))
        probe = PhpProbe(src, session, ProbeSettings(timeout_s=3),
                         f"https://{target}")
        probe.ensure()
        try:
            assert probe.call()["ok"] is True
        finally:
            session.close()

        assert proxy.connects == [(target, None)]
        assert proxy.forwards == []  # the GET stayed inside the tunnel
        host, path, auth = origin.requests[0]
        assert host == target
        assert path.startswith("/wpt-probe-")  # origin-form in the tunnel
        assert auth is None
        _assert_no_probe_worker()


def test_an_authenticated_https_proxy_receives_the_probe_credentials(tmp_path):
    """P2: with TLS to the proxy, proxy credentials still belong on the
    CONNECT inside that TLS session and never reach the origin."""
    from wpt.dnsoverride import ensure_cert

    cert_path, key_path = ensure_cert(tmp_path / "auth-tls-proxy-certs")
    tls_context = _server_tls_context(cert_path, key_path)
    expected = "Basic " + base64.b64encode(b"user:secret").decode()
    src = FakeSource()
    with _origin_server(src.files, tls_context=tls_context) as origin, \
            _proxy_server(auth=("user", "secret"),
                          tls_context=tls_context) as proxy:
        target = f"127.0.0.1:{origin.server_address[1]}"
        origin_url = f"https://{target}"
        port = proxy.server_address[1]
        proxy_url = f"https://user:secret@127.0.0.1:{port}"
        session = _proxy_session({"https": proxy_url}, verify=str(cert_path))
        probe = PhpProbe(src, session, ProbeSettings(timeout_s=3), origin_url)
        probe.ensure()
        try:
            assert probe.call()["ok"] is True
        finally:
            session.close()

        assert proxy.connects == [(target, expected)]
        assert proxy.forwards == []
        assert origin.requests[0][2] is None

        control = _proxy_session(
            {"https": f"https://127.0.0.1:{port}"}, verify=str(cert_path))
        try:
            with pytest.raises(requests.RequestException):
                control.get(origin_url, timeout=2)
        finally:
            control.close()
        _assert_no_probe_worker()


def test_a_slow_https_proxy_connect_is_bounded_by_the_probe_deadline(
        tmp_path):
    """P2: the deadline covers the TLS-to-proxy handshake and CONNECT, not
    just the final origin read; a silent proxy leaves no live socket."""
    from wpt.dnsoverride import ensure_cert

    cert_path, key_path = ensure_cert(tmp_path / "slow-tls-proxy-certs")
    tls_context = _server_tls_context(cert_path, key_path)
    src = FakeSource()
    with _origin_server(src.files, tls_context=tls_context) as origin, \
            _proxy_server(slow_connect=True,
                          tls_context=tls_context) as proxy:
        proxy_url = f"https://127.0.0.1:{proxy.server_address[1]}"
        session = _proxy_session({"https": proxy_url}, verify=str(cert_path))
        probe = PhpProbe(src, session, ProbeSettings(timeout_s=1),
                         f"https://127.0.0.1:{origin.server_address[1]}")
        probe.ensure()
        started = time.monotonic()
        try:
            with pytest.raises(WptError, match="probe request failed"):
                probe.call()
            elapsed = time.monotonic() - started
            assert 0.9 <= elapsed < 2.5
            assert proxy.slow_seen.wait(1.0)
            assert proxy.slow_closed.wait(1.0)
        finally:
            session.close()
        _assert_no_probe_worker()


def test_an_https_proxy_tunnel_read_is_bounded_by_the_absolute_deadline(
        tmp_path):
    """P2: after TLS-to-proxy + CONNECT the socket is urllib3's
    ``SSLTransport``; its non-blocking ``recv`` must feed the same
    ``select`` deadline loop (a header drip cannot outlive the budget)."""
    from wpt.dnsoverride import ensure_cert

    cert_path, key_path = ensure_cert(tmp_path / "tunnel-drip-certs")
    proxy_tls = _server_tls_context(cert_path, key_path)
    origin_tls = _server_tls_context(cert_path, key_path)
    port, stop, listener, client_closed = _drip_headers_server(origin_tls)
    src = FakeSource()
    with _proxy_server(tls_context=proxy_tls) as proxy:
        proxy_url = f"https://127.0.0.1:{proxy.server_address[1]}"
        session = _proxy_session({"https": proxy_url}, verify=str(cert_path))
        probe = PhpProbe(src, session, ProbeSettings(timeout_s=1),
                         f"https://127.0.0.1:{port}")
        probe.ensure()
        started = time.monotonic()
        try:
            with pytest.raises(WptError, match="absolute timeout"):
                probe.call()
            elapsed = time.monotonic() - started
            assert 0.9 <= elapsed < 2.0
            assert client_closed.wait(1.0), \
                "the origin never saw the client close"
        finally:
            stop.set()
            try:
                listener.close()
            except OSError:
                pass
            session.close()
        _assert_no_probe_worker()


def test_a_forwarding_https_proxy_for_an_https_target_gets_absolute_form(
        tmp_path):
    """P3: urllib3's forwarding path (``use_forwarding_for_https=True``)
    hands the pool the ABSOLUTE url — its ``ProxyManager.urlopen`` contract
    requires one — and RFC 7230 §5.3.2 requires absolute-form to a proxy.
    requests does not enable the flag itself, so an embedding adapter owns
    it; the probe must still write absolute-form for an HTTPS destination,
    and the proxy credentials belong to that hop only."""
    from wpt.dnsoverride import ensure_cert

    cert_path, key_path = ensure_cert(tmp_path / "fwd-tls-proxy-certs")
    tls_context = _server_tls_context(cert_path, key_path)
    upstream_context = ssl.create_default_context(cafile=str(cert_path))
    expected = "Basic " + base64.b64encode(b"user:secret").decode()
    src = FakeSource()
    with _origin_server(src.files, tls_context=tls_context) as origin, \
            _proxy_server(auth=("user", "secret"), tls_context=tls_context,
                          upstream_tls_context=upstream_context) as proxy:
        target = f"127.0.0.1:{origin.server_address[1]}"
        proxy_url = f"https://user:secret@127.0.0.1:{proxy.server_address[1]}"
        session = _forwarding_https_session(proxy_url, verify=str(cert_path))
        probe = PhpProbe(src, session, ProbeSettings(timeout_s=3),
                         f"https://{target}")
        probe.ensure()
        try:
            assert probe.call()["ok"] is True
        finally:
            session.close()

        assert proxy.connects == []  # forwarding: no CONNECT
        (forwarded, auth) = proxy.forwards[0]
        assert forwarded.startswith(f"https://{target}/wpt-probe-")
        assert "token=" in forwarded
        assert auth == expected
        host, path, origin_auth = origin.requests[0]
        assert host == target
        assert path.startswith("/wpt-probe-")  # the proxy rewrote to origin
        assert origin_auth is None
        _assert_no_probe_worker()


def test_a_socks_proxy_never_gets_an_absolute_form_target():
    """SOCKS builds its own tunnel in the connection; an HTTP proxy's
    absolute-form target and Proxy-Authorization belong to a forwarding
    HTTP(S) proxy, never to SOCKS (even when PySocks is installed)."""
    class _Recorder:
        def __init__(self):
            self.target = None
            self.headers = []

        def putrequest(self, method, target, **kwargs):
            self.target = target

        def putheader(self, name, value):
            self.headers.append((name, value))

        def endheaders(self):
            pass

    prepared = requests.Request("GET", "http://site.example/a?b=1").prepare()
    conn = _Recorder()
    php_probe._write_probe_request(
        conn, prepared, "http://site.example/a?b=1",
        proxy="socks5://127.0.0.1:1080", proxied=False, tunneled=False,
        proxy_headers={"Proxy-Authorization": "Basic c2VjcmV0"})

    assert conn.target == "/a?b=1"
    assert not any(name.lower() == "proxy-authorization"
                   for name, _value in conn.headers)


def test_a_slow_connect_proxy_is_bounded_by_the_probe_deadline():
    """P1: the CONNECT/read must not outlive the absolute deadline; the
    remaining budget is fed into the connection timeout, so a proxy that
    accepts and never answers costs about ``timeout_s``, not forever."""
    src = FakeSource()
    with _origin_server(src.files) as origin, \
            _proxy_server(slow_connect=True) as proxy:
        proxy_url = f"http://127.0.0.1:{proxy.server_address[1]}"
        session = _proxy_session({"https": proxy_url})
        probe = PhpProbe(src, session, ProbeSettings(timeout_s=1),
                         f"https://127.0.0.1:{origin.server_address[1]}")
        probe.ensure()
        started = time.monotonic()
        try:
            with pytest.raises(WptError, match="probe request failed"):
                probe.call()
            elapsed = time.monotonic() - started
            assert 0.9 <= elapsed < 2.5
            assert proxy.slow_seen.wait(1.0)
            # The failed CONNECT left no live socket: the proxy sees EOF.
            assert proxy.slow_closed.wait(1.0)
        finally:
            session.close()
        _assert_no_probe_worker()


def test_a_slow_connect_proxy_uses_the_remaining_budget():
    """The CONNECT timeout is the deadline's remaining budget, not the
    caller's per-read ``timeout_s``: a 5 s setting with a 0.3 s deadline
    must still give up at about 0.3 s."""
    src = FakeSource()
    with _origin_server(src.files) as origin, \
            _proxy_server(slow_connect=True) as proxy:
        proxy_url = f"http://127.0.0.1:{proxy.server_address[1]}"
        session = _proxy_session({"https": proxy_url})
        deadline = time.monotonic() + 0.3
        started = time.monotonic()
        try:
            with pytest.raises(requests.RequestException):
                php_probe.get_bounded(
                    session, f"https://127.0.0.1:{origin.server_address[1]}",
                    timeout_s=5, deadline=deadline)
            elapsed = time.monotonic() - started
            assert 0.25 <= elapsed < 0.8
            assert proxy.slow_closed.wait(1.0)
        finally:
            session.close()
        _assert_no_probe_worker()


# ------------------------------------------------------- round-3 regressions


def test_R15_response_header_bound_is_enforced_after_every_read():
    """R15-P2: the bound was checked only while no ``\\r\\n\\r\\n`` was in
    the buffer, so one read carrying a complete 70 KiB head bypassed it
    (max accepted ~2x the limit)."""
    import socket
    import time

    from wpt.php_probe import _HEADER_LIMIT, _read_response_head, _set_nonblocking

    left, right = socket.socketpair()
    writer = None
    try:
        block = (b"HTTP/1.1 200 OK\r\nX-Junk: "
                 + b"a" * (_HEADER_LIMIT + 1) + b"\r\n\r\n")

        def _send() -> None:
            try:
                right.sendall(block)
            except OSError:
                pass  # the reader refused the head and closed its side

        # A socketpair's send buffer is much smaller than 70 KiB on macOS;
        # sendall() with no concurrent reader blocks forever there.  The
        # writer must run beside the reader (the listener's real shape).
        writer = threading.Thread(target=_send, daemon=True)
        writer.start()
        _set_nonblocking(left)
        with pytest.raises(WptError, match="headers exceeded"):
            _read_response_head(left, time.monotonic() + 2)
    finally:
        left.close()
        right.close()
        if writer is not None:
            writer.join(timeout=0.5)


def test_HTTP_1XX_interim_heads_are_skipped_until_the_final_response():
    """HTTP-1XX: _read_response_head returned the FIRST status, so a valid
    103/100 interim head became the probe's answer (HTTP 103 with the 200
    head as its body)."""
    import socket
    import time

    from wpt.php_probe import _read_response_head, _set_nonblocking

    left, right = socket.socketpair()
    try:
        right.sendall(
            b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n"
            b"HTTP/1.1 100 Continue\r\n\r\n"
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
        _set_nonblocking(left)
        status, headers, body = _read_response_head(
            left, time.monotonic() + 2)
        assert status == 200
        assert headers["content-length"] == "2"
        assert body == b"{}"
    finally:
        left.close()
        right.close()


def test_HTTP_1XX_101_is_final_not_skipped():
    """101 is a final protocol switch for this client: skip 100-199 EXCEPT
    101."""
    import socket
    import time

    from wpt.php_probe import _read_response_head, _set_nonblocking

    left, right = socket.socketpair()
    try:
        right.sendall(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
        _set_nonblocking(left)
        status, _headers, _body = _read_response_head(
            left, time.monotonic() + 2)
        assert status == 101
    finally:
        left.close()
        right.close()


def test_CONNECT_DEADLINE_a_dripping_proxy_is_bounded_and_closed():
    """CONNECT-DEADLINE: conn.timeout is PER READ, so a proxy dripping six
    bytes at 0.4 s kept the handshake alive for 3+ seconds (this test drips
    at 0.1 s, 0.6 s of bytes). The CONNECT negotiation must run on the
    absolute-deadline loop and close the socket."""
    import socket
    import threading
    import time

    from wpt.php_probe import _bounded_connect_tunnel
    from wpt.types import WptError

    left, right = socket.socketpair()
    seen = bytearray()
    closed = threading.Event()

    def _drip():
        try:
            right.settimeout(2)
            request = b""
            while b"\r\n\r\n" not in request:
                request += right.recv(4096)
            seen.extend(request)
            for byte in b"HTTP/1":
                right.sendall(bytes([byte]))
                time.sleep(0.1)
        except OSError:
            closed.set()
        finally:
            right.close()

    thread = threading.Thread(target=_drip, daemon=True)
    thread.start()

    class Conn:
        sock = left
        _tunnel_host = "site.test"
        _tunnel_port = 443
        _http_vsn_str = "HTTP/1.1"
        _tunnel_headers: dict[str, str] = {}

        @staticmethod
        def _wrap_ipv6(value):
            return value

    started = time.monotonic()
    try:
        with pytest.raises(WptError):
            _bounded_connect_tunnel(Conn(), time.monotonic() + 0.3)
        elapsed = time.monotonic() - started
        assert 0.25 <= elapsed < 0.8, elapsed
        assert seen.startswith(b"CONNECT site.test:443 HTTP/1.1\r\n")
    finally:
        left.close()
        thread.join(timeout=3)


def test_CONNECT_DEADLINE_socks_negotiation_is_closed_and_joined(
        monkeypatch):
    """CONNECT-DEADLINE SOCKS: PySocks negotiates on per-read timeouts; the
    worker must register its socket, the caller must close it at the deadline
    and join the worker (no lingering thread/socket).  PySocks is absent in
    this environment, so the same contract is exercised with a fake module."""
    import sys
    import threading
    import time
    import types

    from wpt.php_probe import _connect_socks_bounded
    from wpt.types import WptError

    fake = types.ModuleType("socks")
    instances = []

    class FakeSocksSocket:
        def __init__(self):
            self.closed = False
            self.release = threading.Event()
            instances.append(self)

        def connect(self):
            self.release.wait(5)

        def close(self):
            self.closed = True
            self.release.set()

    fake.socksocket = FakeSocksSocket
    monkeypatch.setitem(sys.modules, "socks", fake)

    class Conn:
        sock = None

        def connect(self):
            self.sock = fake.socksocket()
            self.sock.connect()

        def close(self):
            if self.sock is not None:
                self.sock.close()

    conn = Conn()
    started = time.monotonic()
    with pytest.raises(WptError):
        _connect_socks_bounded(conn, time.monotonic() + 0.2)
    assert time.monotonic() - started < 1.5
    assert instances and instances[0].closed
    assert not any(thread.name == "wpt-probe-socks"
                   for thread in threading.enumerate())


def test_REQUESTS_FALLBACK_requires_the_tls_aware_connection_api(
        monkeypatch):
    """REQUESTS-FALLBACK: requests 2.32.0/2.32.1 lack
    get_connection_with_tls_context; the old fallback silently dropped
    verify/cert, breaking DNS-override (verify=False) and custom CAs."""
    import pathlib
    import tomllib
    import requests

    from wpt.php_probe import _get_over_connection
    from wpt.types import WptError

    pyproject = tomllib.loads(
        (pathlib.Path(__file__).resolve().parents[1] / "pyproject.toml")
        .read_text(encoding="utf-8"))
    deps = pyproject["project"]["dependencies"]
    assert "requests>=2.32.2,<3" in deps
    assert hasattr(requests.adapters.HTTPAdapter,
                   "get_connection_with_tls_context")

    class LegacyAdapter:
        def get_connection(self, *args, **kwargs):
            raise AssertionError("the insecure fallback must not run")

    class LegacySession(requests.Session):
        def get_adapter(self, url):
            return LegacyAdapter()

    with pytest.raises(WptError, match="2.32.2"):
        _get_over_connection(
            LegacySession(), "http://127.0.0.1:9/probe",
            timeout_s=1, deadline=time.monotonic() + 1)


def test_CLEANUP_STOP_a_stop_during_probe_cleanup_is_not_masked():
    """P2-CLEANUP-STOP: the cleanup catch swallowed StopRequested and
    re-raised the original SourceError, so SIGTERM became a FAIL row."""
    class WriteFailDeleteStop(FakeSource):
        def write_bytes(self, path, data, *, allow_config=False,
                        allow_core=False):
            raise SourceError("upload refused")

        def delete(self, path):
            raise StopRequested("received SIGTERM (15)")

    probe = PhpProbe(WriteFailDeleteStop(), FakeSession([]),
                     ProbeSettings(), SITE)
    with pytest.raises(StopRequested):
        probe.ensure()


def test_PROBE_DNS_resolution_is_bounded_by_the_request_deadline(monkeypatch):
    """P2-PROBE-DNS: the absolute deadline started after conn.connect();
    a blocking getaddrinfo ignored it and call() outlived timeout_s."""
    real = socket.getaddrinfo
    release = threading.Event()

    def slow(*args, **kwargs):
        # Block until the bounded resolver has already refused; a fixed
        # 0.1 s sleep raced the 0.05 s budget on macOS.
        release.wait(5)
        return real("127.0.0.1", args[1], type=socket.SOCK_STREAM)

    monkeypatch.setattr(socket, "getaddrinfo", slow)
    started = time.monotonic()
    try:
        with pytest.raises(WptError, match="deadline"):
            php_probe._resolve_host_bounded(
                "slow.example", 443, time.monotonic() + 0.05)
        assert time.monotonic() - started < 0.2
    finally:
        release.set()

    calls = []
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *args, **kwargs: calls.append(args) or [])
    assert php_probe._resolve_host_bounded(
        "127.0.0.1", 443, time.monotonic() + 0.05) == ["127.0.0.1"]
    assert calls == []  # a numeric address is never resolved


def test_NEW4_dns_workers_are_bounded_and_saturation_fails_fast(monkeypatch):
    """Each timed-out getaddrinfo leaves an uncancellable daemon worker; a
    resolver that keeps stalling must not grow the thread set without bound."""
    release = threading.Event()

    def blocked(*args, **kwargs):
        release.wait(5)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 ("127.0.0.1", args[1]))]

    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    try:
        for _ in range(php_probe._DNS_WORKER_LIMIT):
            with pytest.raises(WptError, match="deadline"):
                php_probe._resolve_host_bounded(
                    "slow.example", 443, time.monotonic() + 0.05)
        with pytest.raises(WptError, match="saturat"):
            php_probe._resolve_host_bounded(
                "slow.example", 443, time.monotonic() + 0.05)
        live = [t for t in threading.enumerate()
                if t.name == "wpt-probe-dns" and t.is_alive()]
        assert len(live) <= php_probe._DNS_WORKER_LIMIT
        assert len(live) == php_probe._DNS_WORKER_LIMIT
    finally:
        release.set()
        end = time.monotonic() + 2
        while (any(t.name == "wpt-probe-dns" and t.is_alive()
                   for t in threading.enumerate())
               and time.monotonic() < end):
            time.sleep(0.01)
    assert not [t for t in threading.enumerate()
                if t.name == "wpt-probe-dns" and t.is_alive()]


# ------------------------------------------------------- round-5 regressions


def test_NEW4b_dns_resolution_returns_every_address_in_order(monkeypatch):
    """P2-PROBE-DUALSTACK: only result[0] was used, so an IPv6-first host
    never fell back to its working IPv4 address."""
    records = [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "",
         ("::1", 443, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "",
         ("192.0.2.10", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "",
         ("192.0.2.10", 443)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *args, **kwargs: records)

    addresses = php_probe._resolve_host_bounded(
        "dualstack.test", 443, time.monotonic() + 1)

    assert addresses == ["::1", "192.0.2.10"]


def test_P1_PROBE_TLS_keeps_the_hostname_for_SNI_and_certificate(
        tmp_path, monkeypatch):
    """P1-PROBE-SNI: writing the numeric address to ``_dns_host`` changed
    urllib3's ``host`` property, so a hostname certificate failed and the
    server saw SNI=None.  Only the TCP dial may be numeric."""
    from wpt.dnsoverride import ensure_cert

    cert_path, key_path = ensure_cert(tmp_path / "sni-certs")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    seen_sni: list[str | None] = []

    def sni_callback(_socket, server_name, _context):
        seen_sni.append(server_name)

    context.sni_callback = sni_callback
    src = FakeSource()

    class _V6HTTPServer(ThreadingHTTPServer):
        address_family = socket.AF_INET6

    httpd = _V6HTTPServer(("::1", 0), _ProbeOriginHandler)
    httpd.files = src.files
    httpd.requests = []
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    port = httpd.server_address[1]
    thread = threading.Thread(
        target=lambda: httpd.serve_forever(
            poll_interval=SERVE_POLL_INTERVAL_S),
        daemon=True)
    thread.start()

    real = socket.getaddrinfo

    def override(host, *args, **kwargs):
        if host == "localhost":
            return real("::1", *args, **kwargs)
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", override)
    session = requests.Session()
    session.trust_env = False
    session.verify = str(cert_path)
    probe = PhpProbe(src, session, ProbeSettings(timeout_s=3),
                     f"https://localhost:{port}")
    try:
        probe.ensure()
        assert probe.call()["ok"] is True
        assert seen_sni == ["localhost"]
    finally:
        session.close()
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def test_P1_PROBE_override_ip_never_resolves_the_url_hostname(
        tmp_path, monkeypatch):
    """P1-PROBE-OVERRIDE: the DNS binding resolved the URL hostname even
    though IPDialHTTPSConnection already owned a fixed dial address — the
    exact pre-migration case --override-ip exists for."""
    from wpt.dnsoverride import ensure_cert, resolve_session

    cert_path, key_path = ensure_cert(tmp_path / "override-certs")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    src = FakeSource()
    with _origin_server(src.files, tls_context=context) as origin:
        port = origin.server_address[1]
        session = resolve_session(
            "pre-migration.invalid", "127.0.0.1", port=port, verify=False)
        calls: list[str] = []
        real = socket.getaddrinfo

        def refusing(host, *args, **kwargs):
            if host == "pre-migration.invalid":
                calls.append(host)
                raise socket.gaierror("name does not resolve")
            return real(host, *args, **kwargs)

        monkeypatch.setattr(socket, "getaddrinfo", refusing)
        probe = PhpProbe(src, session, ProbeSettings(timeout_s=3),
                         f"https://pre-migration.invalid:{port}")
        try:
            probe.ensure()
            assert probe.call()["ok"] is True
        finally:
            session.close()
        assert calls == []


def test_P2_PROBE_SECOND_CALL_redeploys_after_a_consumed_200():
    """P2-PROBE-SECOND-CALL: PHP self-deletes on every 200, so a second
    call() must deploy a fresh probe instead of GETting the dead file."""
    probe, src, session = make([ok(php_version="8.2"), ok(php_version="8.3")])

    assert probe.call()["php_version"] == "8.2"
    first_url = session.gets[0][0]
    assert probe._endpoint is None and probe._token is None
    assert len(probe._deployed) == 1

    assert probe.call()["php_version"] == "8.3"
    second_url = session.gets[1][0]
    assert second_url != first_url
    assert len(probe._deployed) == 2

    probe.destroy()
    assert src.files == {}


def test_NEW4b_socks_workers_are_bounded_and_saturation_fails_fast(
        monkeypatch):
    """P2-PROBE-SOCKS-CAP: an uncancellable PySocks worker had no cap;
    repeated slow handshakes grew the thread set without bound."""
    import sys
    import types

    from wpt.php_probe import _connect_socks_bounded
    from wpt.types import WptError

    release = threading.Event()
    fake = types.ModuleType("socks")

    class FakeSocksSocket:
        def __init__(self):
            self.closed = False

        def connect(self):
            release.wait(5)

        def close(self):
            self.closed = True

    fake.socksocket = FakeSocksSocket
    monkeypatch.setitem(sys.modules, "socks", fake)

    class Conn:
        sock = None

        def connect(self):
            self.sock = fake.socksocket()
            self.sock.connect()

        def close(self):
            if self.sock is not None:
                self.sock.close()

    try:
        for _ in range(php_probe._SOCKS_WORKER_LIMIT):
            with pytest.raises(WptError):
                _connect_socks_bounded(Conn(), time.monotonic() + 0.01)
        with pytest.raises(WptError, match="saturat"):
            _connect_socks_bounded(Conn(), time.monotonic() + 0.01)
        live = [t for t in threading.enumerate()
                if t.name == "wpt-probe-socks" and t.is_alive()]
        assert len(live) == php_probe._SOCKS_WORKER_LIMIT
    finally:
        release.set()
        end = time.monotonic() + 2
        while (any(t.name == "wpt-probe-socks" and t.is_alive()
                   for t in threading.enumerate())
               and time.monotonic() < end):
            time.sleep(0.01)
    assert not [t for t in threading.enumerate()
                if t.name == "wpt-probe-socks" and t.is_alive()]


def test_P2_PROBE_DUALSTACK_falls_back_to_a_working_ipv4_address(
        tmp_path, monkeypatch):
    """P2-PROBE-DUALSTACK: pinning result[0] removed stdlib's family
    fallback; an IPv6-first host whose AAAA route is dead must still reach
    the working IPv4 address within the same deadline."""
    from wpt.dnsoverride import ensure_cert

    cert_path, key_path = ensure_cert(tmp_path / "dual-certs")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    src = FakeSource()
    with _origin_server(src.files, tls_context=context) as origin:
        port = origin.server_address[1]
        real = socket.getaddrinfo

        def dual(host, *args, **kwargs):
            if host == "dualstack.test":
                return [
                    (socket.AF_INET6, socket.SOCK_STREAM, 6, "",
                     ("::1", port, 0, 0)),
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "",
                     ("127.0.0.1", port)),
                ]
            return real(host, *args, **kwargs)

        monkeypatch.setattr(socket, "getaddrinfo", dual)
        session = requests.Session()
        session.trust_env = False
        session.verify = False
        probe = PhpProbe(src, session, ProbeSettings(timeout_s=3),
                         f"https://dualstack.test:{port}")
        try:
            probe.ensure()
            assert probe.call()["ok"] is True
        finally:
            session.close()


def test_P2_PROBE_BLACKHOLED_first_address_does_not_consume_the_deadline(
        tmp_path, monkeypatch):
    """P2-PROBE-BLACKHOLE: the first address (192.0.2.1, TEST-NET-1) drops
    SYNs.  It may use only its share of the remaining budget, so the working
    second address is still dialed inside the same absolute deadline."""
    src = FakeSource()
    from wpt.dnsoverride import ensure_cert

    cert_path, key_path = ensure_cert(tmp_path / "blackhole-certs")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    with _origin_server(src.files, tls_context=context) as origin:
        port = origin.server_address[1]
        real = socket.getaddrinfo

        def blackholed(host, *args, **kwargs):
            if host == "blackholed.test":
                return [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "",
                     ("192.0.2.1", port)),
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "",
                     ("127.0.0.1", port)),
                ]
            return real(host, *args, **kwargs)

        monkeypatch.setattr(socket, "getaddrinfo", blackholed)
        session = requests.Session()
        session.trust_env = False
        session.verify = False
        probe = PhpProbe(src, session, ProbeSettings(timeout_s=2),
                         f"https://blackholed.test:{port}")
        started = time.monotonic()
        try:
            probe.ensure()
            assert probe.call()["ok"] is True
        finally:
            session.close()
        assert time.monotonic() - started < 2


def test_P2_PROBE_each_address_owns_a_bounded_share(monkeypatch):
    """The per-address timeout is remaining/addresses-left, not the whole
    remaining budget, and the SNI host/timeout are restored afterwards."""
    calls: list[tuple[str, float]] = []

    class Conn:
        _dns_host = "dualstack.test"
        host = "dualstack.test"
        port = 443
        timeout = 3.0

        def _new_conn(self):
            calls.append((self._dns_host, self.timeout))
            if self._dns_host == "192.0.2.1":
                time.sleep(self.timeout)
                raise OSError("blackholed")
            return ("connected", self._dns_host)

    monkeypatch.setattr(
        php_probe, "_resolve_host_bounded",
        lambda host, port, deadline: ["192.0.2.1", "127.0.0.1"])
    conn = Conn()
    deadline = time.monotonic() + 1.0
    php_probe._bind_numeric_dns(conn, deadline)
    started = time.monotonic()
    assert conn._new_conn() == ("connected", "127.0.0.1")
    elapsed = time.monotonic() - started

    assert [address for address, _ in calls] == ["192.0.2.1", "127.0.0.1"]
    assert calls[0][1] <= 0.6  # bounded share, not the whole 1.0 s budget
    assert calls[1][1] > 0
    assert elapsed < 1.1
    assert conn._dns_host == "dualstack.test"
    assert conn.timeout == 3.0


# ------------------------------------------------------- triple-check round 6


def test_R6_08_socks_patch_lock_is_bounded_by_the_caller_deadline(monkeypatch):
    """R6-08: Lock.__enter__ has no deadline, so a second caller blocked past
    its budget and then started a worker anyway.  It must fail fast with a
    WptError, start NO worker, and leave the first call unaffected."""
    import sys
    import types

    from wpt.php_probe import _connect_socks_bounded
    from wpt.types import WptError

    release = threading.Event()
    fake = types.ModuleType("socks")

    class FakeSocksSocket:
        def __init__(self):
            self.closed = False

        def connect(self):
            release.wait(5)

        def close(self):
            self.closed = True
            release.set()

    fake.socksocket = FakeSocksSocket
    monkeypatch.setitem(sys.modules, "socks", fake)

    class Conn:
        sock = None

        def connect(self):
            self.sock = fake.socksocket()
            self.sock.connect()

        def close(self):
            if self.sock is not None:
                self.sock.close()

    first_error: list[BaseException] = []

    def _first():
        try:
            _connect_socks_bounded(Conn(), time.monotonic() + 1.5)
        except BaseException as exc:  # expected at the deadline
            first_error.append(exc)

    first = threading.Thread(target=_first, daemon=True)
    first.start()
    try:
        end = time.monotonic() + 1
        while not [t for t in threading.enumerate()
                   if t.name == "wpt-probe-socks"] \
                and time.monotonic() < end:
            time.sleep(0.005)
        time.sleep(0.1)
        started = time.monotonic()
        with pytest.raises(WptError, match="busy"):
            _connect_socks_bounded(Conn(), time.monotonic() + 0.2)
        elapsed = time.monotonic() - started
        assert elapsed < 0.6, elapsed
        # only the FIRST call owns a worker; the second never started one
        live = [t for t in threading.enumerate()
                if t.name == "wpt-probe-socks" and t.is_alive()]
        assert len(live) == 1
    finally:
        release.set()
        first.join(timeout=3)
        end = time.monotonic() + 2
        while (any(t.name == "wpt-probe-socks" and t.is_alive()
                   for t in threading.enumerate())
               and time.monotonic() < end):
            time.sleep(0.01)
    assert not [t for t in threading.enumerate()
                if t.name == "wpt-probe-socks" and t.is_alive()]


@pytest.mark.parametrize("status", [404, 410])
def test_R6_09_dead_endpoint_is_cleared_and_the_next_call_redeploys(status):
    """R6-09: a 410 (expired) or 404 (externally deleted) retained the dead
    endpoint, so every later call re-GET the same URL.  Clear the live
    endpoint state (keep _deployed for destroy) and re-ensure."""
    probe, src, session = make(
        script=[FakeResponse(status, "expired"), ok()])
    first = probe.ensure()

    with pytest.raises(WptError):
        probe.call()
    assert probe._endpoint is None and probe._name is None
    assert probe._token is None
    assert first in probe._deployed

    payload = probe.call()

    assert payload["ok"] is True
    second = [name for name in probe._deployed if name != first]
    assert len(second) == 1 and second[0] != first
    # two GETs, two DIFFERENT URLs (the second call redeployed)
    assert len(session.gets) == 2
    assert session.gets[0][0] != session.gets[1][0]
    probe.destroy()
    assert all(name not in src.files for name in (first, second[0]))


def _rst_after_partial_body_server():
    """A real HTTP server that sends 8 of 100 body bytes, then RSTs."""
    import socket
    import struct

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def _serve():
        try:
            conn, _ = listener.accept()
            request = b""
            while b"\r\n\r\n" not in request:
                request += conn.recv(4096)
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n"
                b"Connection: close\r\n\r\n" + b"x" * 8)
            conn.setsockopt(
                socket.SOL_SOCKET, socket.SO_LINGER,
                struct.pack("ii", 1, 0))
            conn.close()
        except OSError:
            pass
        finally:
            listener.close()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    return port


def test_R7_P2_05_body_read_reset_is_a_wperror_not_a_raw_oserror():
    """R7-P2-05: header resets were wrapped by the connection helper, but a
    body read after it returned leaked ``ConnectionResetError``."""
    port = _rst_after_partial_body_server()
    source = FakeSource()
    probe = PhpProbe(source, requests.Session(), ProbeSettings(timeout_s=2),
                     f"http://127.0.0.1:{port}")
    try:
        with pytest.raises(WptError) as excinfo:
            probe.call()
    finally:
        probe._session.close()
    assert not isinstance(excinfo.value, ConnectionResetError)
    assert "probe request failed" in str(excinfo.value)


# ------------------------------------------------ triple-check round 8 (P1/P2)


def test_P1_SOCKS_the_module_socksocket_class_stays_bound():
    """P1-01: rebinding ``socks.socksocket`` made PySocks' own
    ``super(socksocket, self)`` resolve to the subclass and recurse.  The
    module global must stay the REAL class; only its methods are wrapped."""
    import sys
    import types as pytypes

    from wpt.php_probe import _connect_socks_bounded

    # A module whose methods resolve ``socksocket`` from module globals —
    # exactly the real PySocks layout (exec makes that namespace real).
    fake = pytypes.ModuleType("socks")
    exec(
        "class Base:\n"
        "    def __init__(self):\n"
        "        self.connected = False\n"
        "class socksocket(Base):\n"
        "    def __init__(self):\n"
        "        super(socksocket, self).__init__()\n"
        "    def connect(self, *_args, **_kwargs):\n"
        "        self.connected = True\n"
        "    def close(self):\n"
        "        pass\n",
        fake.__dict__,
    )
    original = sys.modules.get("socks")
    sys.modules["socks"] = fake
    real_class = fake.socksocket
    try:
        class Conn:
            def __init__(self):
                self.sock = None

            def connect(self):
                self.sock = fake.socksocket()
                self.sock.connect()

            def close(self):
                if self.sock is not None:
                    self.sock.close()

        conn = Conn()
        started = time.monotonic()
        _connect_socks_bounded(conn, time.monotonic() + 2)
        assert time.monotonic() - started < 1.5
        assert fake.socksocket is real_class
        assert conn.sock is not None and conn.sock.connected
    finally:
        if original is None:
            sys.modules.pop("socks", None)
        else:
            sys.modules["socks"] = original


class _Socks5Server(threading.Thread):
    """A minimal SOCKS5 no-auth CONNECT server over 127.0.0.1."""

    def __init__(self, *, slow_reply: float = 0.0):
        super().__init__(daemon=True)
        self.slow_reply = slow_reply
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.listener.settimeout(3)
        self.port = self.listener.getsockname()[1]
        self.seen = threading.Event()
        self.closed = threading.Event()

    @staticmethod
    def _read(conn, count):
        data = b""
        while len(data) < count:
            chunk = conn.recv(count - len(data))
            if not chunk:
                raise OSError("client closed")
            data += chunk
        return data

    def run(self):
        try:
            conn, _ = self.listener.accept()
        except OSError:
            self.listener.close()
            return
        conn.settimeout(3)
        try:
            head = self._read(conn, 2)
            methods = self._read(conn, head[1])
            assert methods
            conn.sendall(b"\x05\x00")
            request = self._read(conn, 4)
            atyp = request[3]
            if atyp == 1:
                self._read(conn, 4)
            elif atyp == 3:
                self._read(conn, self._read(conn, 1)[0])
            else:
                self._read(conn, 16)
            self._read(conn, 2)
            self.seen.set()
            if self.slow_reply:
                time.sleep(self.slow_reply)
            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            # The client never sends data; wait for its close as proof the
            # tracked socket was actually closed by a deadline.
            while conn.recv(1024):
                pass
        except (OSError, AssertionError):
            pass
        finally:
            self.closed.set()
            conn.close()
            self.listener.close()


def test_P1_SOCKS_real_PySocks_negotiates_a_local_proxy():
    """P1-01 (real PySocks 1.7.1): create_connection through a real local
    SOCKS5 handshake must not raise RecursionError and must hand back the
    connected socket."""
    socks = pytest.importorskip("socks")
    from wpt.php_probe import _connect_socks_bounded

    server = _Socks5Server()
    server.start()

    class Conn:
        def __init__(self):
            self.sock = None

        def connect(self):
            self.sock = socks.create_connection(
                ("127.0.0.1", 9), timeout=2,
                proxy_type=socks.SOCKS5, proxy_addr="127.0.0.1",
                proxy_port=server.port, proxy_rdns=False)

        def close(self):
            if self.sock is not None:
                self.sock.close()

    conn = Conn()
    try:
        _connect_socks_bounded(conn, time.monotonic() + 2)
        assert server.seen.wait(1)
        assert conn.sock is not None
        assert socks.socksocket is not None
    finally:
        conn.close()
        server.join(2)


def test_P1_SOCKS_real_PySocks_deadline_closes_the_tracked_socket():
    """A SOCKS5 proxy that accepts and never answers must not outlive the
    absolute deadline, and the worker's socket is closed."""
    socks = pytest.importorskip("socks")
    from wpt.php_probe import _connect_socks_bounded

    server = _Socks5Server(slow_reply=5)
    server.start()

    class Conn:
        def __init__(self):
            self.sock = None

        def connect(self):
            self.sock = socks.create_connection(
                ("127.0.0.1", 9), timeout=1,
                proxy_type=socks.SOCKS5, proxy_addr="127.0.0.1",
                proxy_port=server.port, proxy_rdns=False)

        def close(self):
            if self.sock is not None:
                self.sock.close()

    started = time.monotonic()
    try:
        with pytest.raises(WptError, match="absolute timeout"):
            _connect_socks_bounded(Conn(), time.monotonic() + 0.2)
        assert time.monotonic() - started < 1.5
        assert server.seen.wait(1)
    finally:
        server.join(2)


def test_P2_01_ok_false_error_is_excerpted_and_single_line():
    """P2-01: an ok=false detail was unbounded and could carry newlines."""
    probe, _src, _session = make([
        FakeResponse(200, json.dumps(
            {"ok": False, "error": "A" * 200_000 + "\nFORGED"})),
    ])

    with pytest.raises(WptError) as excinfo:
        probe.call()

    message = str(excinfo.value)
    assert len(message) < 400
    assert "\n" not in message
    assert "FORGED" not in message


def test_R24_tls_failure_retries_the_next_resolved_address(monkeypatch):
    """R24-P2: the dial wrapper covered TCP only.  A peer that accepted then
    closed during the TLS handshake ended the request without trying the
    next resolved address (the working one was never dialed).  The whole
    connect (dial + TLS) now retries per address."""
    import ssl

    class Conn:
        _dns_host = "dualstack.test"
        host = "dualstack.test"
        port = 443
        timeout = 3.0

        def __init__(self):
            self.sock = None
            self._has_connected_to_proxy = False
            self.calls = []

        def _new_conn(self):
            self.calls.append(("dial", self._dns_host))
            self.sock = ("socket", self._dns_host)
            return self.sock

        def connect(self):
            self._new_conn()
            dialed = self.sock[1]
            self.calls.append(("tls", self._dns_host))
            if dialed == "127.0.0.2":
                raise ssl.SSLEOFError("peer closed during the handshake")
            self.sock = ("tls", dialed)

        def close(self):
            self.sock = None

    monkeypatch.setattr(
        php_probe, "_resolve_host_bounded",
        lambda host, port, deadline: ["127.0.0.2", "127.0.0.1"])
    conn = Conn()
    php_probe._bind_numeric_dns(conn, time.monotonic() + 2.0)
    conn.connect()
    assert conn.calls == [
        ("dial", "127.0.0.2"), ("tls", "dualstack.test"),
        ("dial", "127.0.0.1"), ("tls", "dualstack.test"),
    ]
    assert conn.sock == ("tls", "127.0.0.1")
    assert conn._dns_host == "dualstack.test"
    assert conn.timeout == 3.0
