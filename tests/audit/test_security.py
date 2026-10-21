"""Unit tests for the remote-only security checks (wpt.audit.security) — W6f.

The checks consume ``data.probe`` — a real SiteProbe wired to scripted
transport doubles — so the facade and the checks are tested together, the
way W6h will run them. Doubles:

* tests.fakes.FakeSession/FakeResponse/FakeSource (shared) back the
  facade-level tests; Resp is their header/url-capable sibling, kept local
  only because tests/fakes.py is frozen (redirect probes need Location
  headers and the final response URL).
* FakeBridge scripts bridge.call (payload or Exception).
* RouterSession routes (method, url-substring) -> response, so the
  end-to-end run needs no call ordering.
* The ``tls`` fixture stubs socket.create_connection +
  SSLContext.wrap_socket via monkeypatch — cert_mismatch NEVER opens a
  real socket in this suite.

The checks consume the shipped profile; the PHP-minimum floor is
``env.php_min_active`` (default "8.2"), exercised by the tests below.

Test -> behavior map (W6f task list):
  facade:
  test_probe_get_post_inject_timeout ......... SiteProbe.get/post add
        timeout=timeout_s + forward allow_redirects/data/headers
  test_probe_site_normalization .............. trailing slash stripped
        from site at construction
  test_probe_bridge_call ..................... real Bridge over fakes:
        payload dict passed through; {"ok": false} -> BridgeError -> None;
        no bridge -> None
  test_probe_read_file ....................... decodes text; missing file,
         binary garbage and a probe without a source all -> None
  test_probe_info_cached ..................... probe.info(): the bridge
         info payload cached after ONE round-trip (a failure's None is
         final too); no bridge -> None
  security.xmlrpc:
  test_xmlrpc_enabled_finding ................ 200 + "<methodResponse>":
        exact finding; exact POST URL, body and content-type pinned
  test_xmlrpc_silent_cases ................... 405/404 status, 200 without
        the marker (the "POST requests only" page) -> []
  test_xmlrpc_degrades ....................... ConnectionError -> [];
        probe None -> []
  security.rest_users:
  test_rest_users_finding ..................... 200 + slugged list: exact
        finding, count = users, slugs sorted in detail, allow_redirects
        False, exact URL
  test_rest_users_detail_truncated ........... 7 users -> 5 slugs
        + "(+2 more)", count still 7
  test_rest_users_silent_cases ............... 401/403/404/302, empty list,
        slug-less list, dict (non-list) body, non-JSON -> []
  test_rest_users_degrades ................... ConnectionError -> [];
        probe None -> []
  security.author_scan:
  test_author_scan_finding .................... 301 Location "/author/":
        exact finding naming the redirect target
  test_author_scan_silent_cases .............. 200, 404, 302 elsewhere,
        3xx without a Location header -> []
  test_author_scan_degrades ................... ConnectionError -> [];
        probe None -> []
  security.wp_config_perms:
  test_wp_config_perms_finding ............... "0644" -> the one high-risk
        finding; bridge receives fileperms{paths=[wp-config.php]}
  test_wp_config_perms_other_than_0600 ....... 0666/0640/0601/0604 all
        flagged; "0600" silent
  test_wp_config_perms_unknown_silent ........ None perms (absent file),
        malformed payloads, no bridge, BridgeError -> []
  test_wp_config_perms_probe_none ............ probe None -> []
  security.disallow_file_edit:
  test_disallow_file_edit_finding ............ wp-config without the
        literal: exact finding
  test_disallow_file_edit_silent ............. literal present -> []
  test_disallow_file_edit_degrades ........... unreadable file / probe
        without a source / probe None -> []
  security.https_redirect:
  test_https_redirect_mixed_pages ............ homepage+3 pages sampled
        (4th page never probed): redirect + offender + http-redirect +
        network-error aggregate into one finding (count=1)
  test_https_redirect_all_leave_silent ...... 301 https, 302 https and a
        200-with-https-Location all count as leaving http -> []
  test_https_redirect_homepage_only .......... pages None: single-sample
        finding; homepage redirect silent
  test_https_redirect_dedupes ................ homepage repeated in pages
        probed once
  test_https_redirect_degrades ............... homepage-only probe
        failure -> []; probe None -> []
  security.www_apex:
  test_www_apex_redirect_silent .............. www redirects to the apex:
        [] (redirect followed; allow_redirects=True pinned)
  test_www_apex_www_serves_finding .......... 200 final still on www:
        exact low-risk finding
  test_www_apex_already_www ................. site host starts with www.:
        [] with zero HTTP calls
  test_www_apex_unreachable_silent ........... ConnectionError / 404 on
        www: [] (www not serving is the good case)
  test_www_apex_probe_none ................... probe None -> []
  security.cert_mismatch:
  test_cert_ok_handshake_silent .............. verified handshake (stubbed
        cert) -> []; create_connection/wrap_socket args pinned (host from
        data.siteurl, port 443, timeout from probe)
  test_cert_verification_failure_finding ..... SSLCertVerificationError ->
        the informational low-risk finding
  test_cert_other_failures_silent ............ connection refused, other
        SSLError, unknown siteurl, probe None -> []
  test_cert_uses_siteurl_host_as_is .......... a www siteurl probes the
        www name (never re-hosted); siteurl paths ignored
  test_cert_override_ip_is_dialed_with_site_sni  [L13] override_ip: the
        raw socket dials the OVERRIDE address, SNI stays the site host;
        None keeps real-DNS dialing
  security.uploads_listing:
  test_uploads_listing_finding ............... 200 + "Index of": exact
        finding, exact URL, allow_redirects False
  test_uploads_listing_content_type .......... 200 + text/html ctype
        without the marker: finding (the parenthetical)
  test_uploads_listing_silent ................ 403/302/404 and a 200 JSON
        body -> []
  test_uploads_listing_degrades ............... ConnectionError -> [];
        probe None -> []
  security.debug_log:
  test_debug_log_finding ...................... file entry at exactly
         wp-content/debug.log: exact finding, bytes = size
  test_debug_log_silent ....................... directory entry, other
         paths -> []
  test_debug_log_no_probe_still_finds ......... entries-based: reports
         with probe None (documented)
  security.php_version:
  test_php_version_eol_finding ............... 7.4 below the "8.2"
         minimum: the exact medium finding — detail = the runtime facts
         line, sparse facts render "unknown"; bridge called with info{}
  test_php_version_healthy_silent ............ the live host 8.3.33, the
         minimum 8.2 itself, 8.2.1 and 9.0.0 -> [] (updates-check
         silence: healthy runtimes report nothing)
  test_php_version_missing_silent ............ absent/None/empty/int
         php_version (php_version_id is NOT a fallback) -> []
  test_php_version_unparseable_silent ........ "8", "x.y", "8.x.1",
         "8.3-beta", "PHP 8.3" -> []; _php_minor pins X.Y / X.Y.Z /
         distro-suffix shapes
  test_php_version_numeric_tuple_comparison .. minimum patched to "8.9":
         "8.10" stays SILENT (a float compare would flag it), "8.9" at
         the minimum silent, "8.8" -> the finding
  test_php_version_degrades ................... probe None, no bridge,
         BridgeError, non-dict payload -> []
  security.web_exposed_script [D2]:
  test_web_exposed_script_token_gated_probe_is_high  the LIVE shape (a
         prior session's token-gated du probe at the docroot top level):
         one HIGH finding for the FILE, detail names the matched
         signatures + the file's own date, fix is the read-only triage +
         rm, and the date is a HEAD (a GET would execute the file)
  test_web_exposed_script_plain_unknown_php_is_not_this_finding  high
         precision: an unrecognised top-level .php without a signature,
         and a signature-carrying file that is NOT at the top level, are
         both silent
  test_web_exposed_script_leaves_core_and_known_files_to_their_owners
         the official core top-level set, wp-config.php and a registered
         known_added artifact stay the owners' business (no file in two
         categories); a tampered core file is still core.integrity's
  test_web_exposed_script_reuses_the_added_classification_without_duplicating_it
         the same file is "added" evidence AND this finding, once each
  test_web_exposed_script_without_a_map_reports_unproven_not_high  an
         unavailable map (one warning) never makes the check call a file
         "not an official core file": the candidate is reported under
         security.web_exposed_script_unproven, risk MEDIUM, with a fix
         that removes nothing [D2]
  test_web_exposed_script_offline_never_calls_stock_core_a_backdoor the
         MEASURED false-positive shape: eight stock core files with wp.org
         unreachable => zero HIGH, one clearly-labelled unproven finding
         each; the same tree with the map is exempt from this check
  test_web_exposed_script_a_tampered_version_php_cannot_demote_the_verdict
         THE ATTACK [D1]: webshell + a wp-includes/version.php with its
         $wp_version stripped, wp.org reachable => the shell stays HIGH
         (the unreadable version never demotes) and the detail names the
         altered core statement
  test_web_exposed_script_an_unreadable_version_alone_never_demotes [D1]
         the version unreadable for any other reason (file absent from the
         archive) is still not the offline condition: HIGH, basis named,
         no "not an official core file" claim, no altered-core claim
  test_web_exposed_script_the_map_decides_whenever_it_applies [D1] a
         version learned from somewhere other than the (unreadable)
         version.php + an available map => the candidate is HIGH and the
         "not an official core file" claim is made again
  test_web_exposed_script_unproven_keeps_the_known_file_gates the
         degradation is about the core map only: known_artifacts and
         known_added still keep a candidate out of both classes
  test_web_exposed_script_degrades_without_evidence  no source, an
         unreadable file, no top-level .php and an expired budget (one
         warning) are all silence
  test_web_exposed_script_skips_a_file_above_the_read_bound  the read
         bound is announced, never silent
  test_web_exposed_script_runs_in_local_mode_too  a real zip answers it
         in LOCAL mode (the date is the one thing only a live site adds)
  test_web_exposed_script_catches_every_request_parameter_evasion the five
         evasions an adversarial review reproduced against the substring
         scan (POST/REQUEST/php://input/whitespace-before-the-bracket/
         COOKIE) all reach a HIGH finding, each naming the family member
         that matched
  test_web_exposed_script_scans_every_php_executable_extension .phtml /
         .phar / .PHP are candidates (case-insensitively) and name their
         own suffix; a non-executable top-level suffix is not a candidate
  test_web_exposed_script_reads_a_utf16_webshell a BOM + NUL-heavy payload
         is invisible to a UTF-8 read and is caught through the transcode
  test_web_exposed_script_reports_an_encoded_payload a predominantly
         base64/gzinflate blob earns the encoded-payload report line; an
         ordinary base64-looking block that decodes to nothing signed stays
         silent (no decoding of arbitrary content)
  test_web_exposed_script_exempts_wpts_own_bridge_artifact the REAL
         bridge.php under a bridge-<8 hex>.php name is wpt residue, not a
         backdoor
  test_web_exposed_script_exempts_only_the_bridge_hex_name [D3] the
         shipped pattern spells the eight hex characters out and the
         matcher is hex-strict: bridge-ab12cd34.php (any case) is exempt,
         bridge-shell.php / bridge-.php / bridge-shellab.php are HIGH
  test_web_exposed_script_empty_signature_list_scans_nothing an emptied
         web_script.signatures means "scan nothing" and to_diff says so
         (the old fallback scanned six while reporting none)
  test_web_script_profile_dataclass_and_module_agree the shipped profile,
         the dataclass default and the module fallback are one set
  test_publicly_served_paths_distrusts_a_soft_404 a 200 whose body IS the
         site's answer for a certainly-missing path claims nothing; a real
         200 log (body differs) still leads the fix, and a path with a
         space/# is requested percent-escaped
  test_last_modified_falls_back_to_unknown  the date enrichment degrades
         to None on an error status / absent / unparseable header /
         network failure / no probe / empty site URL
  registry:
  test_registry_thirteen_names_ftp_only ...... all thirteen registered,
         applies == ("ftp",), "security" group selects exactly them
         + security.suspicious + security.web_exposed_script
  test_local_mode_never_selects .............. select_checks("local", ...)
         yields only the two tree-based security checks
  test_run_checks_end_to_end ................. run_checks over a scripted
         probe: 9 findings in check-name order (php-eol among them), the
         two bridge round-trips pinned; same data in local mode -> [];
         probe-less ftp run -> only debug_log
"""

import json
import logging
import ssl
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest
import requests

from tests.fakes import FakeResponse, FakeSession, FakeSource
from wpt.audit import security
from wpt.audit.data import AuditData, _read_wp_version
from wpt.audit.registry import all_checks, run_checks, select_checks
from wpt.audit.security import (
    SiteProbe,
    _XMLRPC_PROBE,
    _php_const_state,
    check_security_author_scan,
    check_security_cert_mismatch,
    check_security_debug_log,
    check_security_disallow_file_edit,
    check_security_relocate,
    check_security_https_redirect,
    check_security_php_version,
    check_security_rest_users,
    check_security_uploads_listing,
    check_security_web_exposed_script,
    check_security_www_apex,
    check_security_wp_config_perms,
    check_security_xmlrpc,
)
from wpt.settings import BridgeSettings, Settings, load
from wpt.sources.zip import ZipSource
from wpt.types import BridgeError, Entry
from wpt.wpbridge.client import Bridge

#: The shipped profile — the checks consume no tunables, so every test uses
#: the defaults exactly as users get them.
DEFAULTS = load()

SITE = "https://site.test"


# ------------------------------------------------------------------ doubles


class Resp:
    """Header/url-capable sibling of tests.fakes.FakeResponse (that file is
    frozen): redirect probes need Location headers, www_apex needs the
    final response URL after following redirects."""

    def __init__(self, status_code=200, text="", headers=None, url=""):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = url
        self.history = []

    def json(self):
        return json.loads(self.text)


class FakeBridge:
    """Scriptable Bridge.call double: plays one script item per call
    (payload dict or Exception instance), recording (action, params)."""

    def __init__(self, script=()):
        self.script = list(script)
        self.calls: list[tuple[str, dict]] = []

    def call(self, action, **params):
        self.calls.append((action, params))
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class RouterSession:
    """URL-routed scripted session for the end-to-end run: routes are
    (method, url-substring, item) pairs — order-independent, unlike the
    shared FakeSession's strict queue."""

    def __init__(self, routes=()):
        self.routes = list(routes)
        self.calls: list[tuple[str, str, dict]] = []

    def get(self, url, **kwargs):
        return self._advance("GET", url, kwargs)

    def post(self, url, **kwargs):
        return self._advance("POST", url, kwargs)

    def head(self, url, **kwargs):
        # security.web_exposed_script dates a file with a HEAD (never a GET:
        # the web server would EXECUTE the file it is asking about)
        return self._advance("HEAD", url, kwargs)

    def _advance(self, method, url, kwargs):
        self.calls.append((method, url, kwargs))
        for route_method, fragment, item in self.routes:
            if route_method == method and fragment in url:
                if isinstance(item, Exception):
                    raise item
                if callable(item):
                    return item(method, url, kwargs)
                return item
        raise AssertionError(f"unexpected {method} request to {url}")


class HeadSession(FakeSession):
    """FakeSession plus ``head()`` — tests/fakes.py is frozen, and dating a
    file under investigation MUST be a HEAD (a GET would make the web
    server execute it).  Script consumption and failure-on-unexpected
    behavior are the shared double's."""

    def head(self, url, **kwargs):
        return self._advance("HEAD", url, kwargs)


class FakeRawSocket:
    def __init__(self):
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def close(self):
        self.closed = True


class FakeTLS(FakeRawSocket):
    def __init__(self, cert):
        super().__init__()
        self.cert = cert

    def getpeercert(self):
        return self.cert


@pytest.fixture
def tls(monkeypatch):
    """Stub the whole TLS layer security.cert_mismatch touches.

    create_connection and SSLContext.wrap_socket are replaced with fakes
    that record their arguments and either succeed with ``state.cert`` or
    raise ``state.conn_exc`` / ``state.wrap_exc``. No real socket opens.
    """
    state = SimpleNamespace(
        conn_calls=[], wrap_calls=[], conn_exc=None, wrap_exc=None,
        cert={"subject": (("commonName", "other.example.com"),)},
    )

    def fake_create(address, timeout=None, source_address=None):
        state.conn_calls.append((address, timeout))
        if state.conn_exc is not None:
            raise state.conn_exc
        return FakeRawSocket()

    def fake_wrap(sock_self, sock, server_hostname=None, **kw):
        state.wrap_calls.append(server_hostname)
        if state.wrap_exc is not None:
            raise state.wrap_exc
        return FakeTLS(state.cert)

    monkeypatch.setattr(security.socket, "create_connection", fake_create)
    monkeypatch.setattr(security.ssl.SSLContext, "wrap_socket", fake_wrap)
    # The probe resolves under a FINITE per-request bound even without a run
    # deadline; keep the fixture hermetic (no system DNS) by answering the
    # host itself.
    monkeypatch.setattr(
        security, "resolve_host_bounded",
        lambda host, port, deadline, **kw: [host.strip("[]")])
    return state


# ------------------------------------------------------------------ helpers


def E(path, size=0, is_dir=False):
    """One Entry, webroot-relative POSIX."""
    return Entry(path=path, is_dir=is_dir, size=size)


def sec_data(probe=None, entries=(), pages=None, siteurl=None, mode="ftp"):
    """A hand-built AuditData carrying only what security checks read."""
    return AuditData(
        mode=mode,
        entries=list(entries),
        siteurl=siteurl,
        home=None,
        template=None,
        blog_public=None,
        wp_version=None,
        mu_plugins=None,
        active_plugins=[],
        plugin_catalog={},
        uploads_basedir=None,
        posts={},
        revisions=None,
        expired_transients=None,
        orphan_meta={},
        attachments=None,
        nav_menu_items=None,
        autoload_bytes=None,
        big_autoload_options=[],
        tables={},
        probe=probe,
        pages=pages,
    )


def mkprobe(script=(), bridge=None, source=None, site=SITE, timeout_s=7):
    """A real SiteProbe over a scripted FakeSession."""
    return SiteProbe(
        session=FakeSession(script), site=site, bridge=bridge,
        source=source, timeout_s=timeout_s,
    )


def src_with(**files):
    """A FakeSource preloaded with name -> bytes files."""
    source = FakeSource()
    source.files.update(files)
    return source


def info_payload(**overrides):
    """A bridge ``info`` payload shaped like bridge.php's wpt_action_info
    (the runtime-facts keys security.php_version reads; php_version
    defaults to the LIVE host's 8.3.33)."""
    payload = {
        "php_version": "8.3.33",
        "php_version_id": 80333,
        "memory_limit": "256M",
        "max_execution_time": "120",
        "sapi": "fpm-fcgi",
        "server_software": "Apache/2.4.62",
        "mysql_version": "8.0.40",
        "wp_debug": False,
    }
    payload.update(overrides)
    return payload


def pinned(findings):
    """Every finding's full tuple, for exact-comparison asserts."""
    return [
        (f.category, f.name, f.detail, f.bytes, f.count, f.risk, f.fix)
        for f in findings
    ]


# ------------------------------------------------------------ SiteProbe API


def test_probe_get_post_inject_timeout():
    session = FakeSession([FakeResponse(200, "ok-get"), FakeResponse(200, "ok-post")])
    probe = SiteProbe(session=session, site=SITE, timeout_s=9)
    probe.get(f"{SITE}/x", allow_redirects=False)
    probe.post(f"{SITE}/xmlrpc.php", data="<x/>", headers={"Content-Type": "text/xml"})
    assert session.gets == [(f"{SITE}/x", {"allow_redirects": False, "timeout": 9})]
    assert session.posts == [
        (f"{SITE}/xmlrpc.php",
         {"data": "<x/>", "headers": {"Content-Type": "text/xml"}, "timeout": 9})
    ]


def test_probe_site_normalization():
    probe = SiteProbe(session=FakeSession(), site=f"{SITE}/", timeout_s=7)
    assert probe.site == SITE


def test_probe_bridge_call():
    # a REAL Bridge over the shared fakes: the payload dict passes through
    src = FakeSource()
    session = FakeSession([
        FakeResponse(200, json.dumps({"ok": True, "paths": {"wp-config.php": "0644"}})),
    ])
    bridge = Bridge(src, session, "", BridgeSettings(), SITE)
    probe = SiteProbe(session=FakeSession(), site=SITE, bridge=bridge, timeout_s=7)
    payload = probe.bridge_call("fileperms", paths=["wp-config.php"])
    assert payload["paths"]["wp-config.php"] == "0644"

    # {"ok": false} -> BridgeError -> silent None
    err_session = FakeSession([FakeResponse(200, json.dumps({"ok": False, "error": "boom"}))])
    err_bridge = Bridge(FakeSource(), err_session, "", BridgeSettings(), SITE)
    failing = SiteProbe(session=FakeSession(), site=SITE, bridge=err_bridge, timeout_s=7)
    assert failing.bridge_call("fileperms", paths=["wp-config.php"]) is None

    # no bridge capability -> None
    assert mkprobe().bridge_call("info") is None


def test_probe_read_file():
    source = src_with(**{"wp-config.php": b"define('DB_NAME','x');", "bin": b"\xff\xfeDISALLOW"})
    probe = mkprobe(source=source)
    assert probe.read_file("wp-config.php") == "define('DB_NAME','x');"
    assert probe.read_file("missing.php") is None          # absent
    assert probe.read_file("bin").startswith("\ufffd")     # binary: replaced, not None
    assert mkprobe().read_file("wp-config.php") is None    # no source capability


def test_probe_info_cached():
    # ONE bridge round-trip serves every caller on the probe — the payload
    # is cached, and so is a failure (None): never a second round-trip
    bridge = FakeBridge([info_payload()])
    probe = mkprobe(bridge=bridge)
    first = probe.info()
    assert probe.info() is first
    assert first["php_version"] == "8.3.33"
    assert bridge.calls == [("info", {})]

    down = FakeBridge([BridgeError("bridge down")])
    failing = mkprobe(bridge=down)
    assert failing.info() is None
    assert failing.info() is None
    assert down.calls == [("info", {})]

    # no bridge capability -> None
    assert mkprobe().info() is None


# ----------------------------------------------------------- security.xmlrpc


def test_xmlrpc_enabled_finding():
    session = FakeSession([
        FakeResponse(200, "<methodResponse><params><value>array</value></params></methodResponse>"),
    ])
    probe = SiteProbe(session=session, site=SITE, timeout_s=7)
    findings = check_security_xmlrpc(sec_data(probe=probe), DEFAULTS)
    assert pinned(findings) == [(
        "security.xmlrpc", "xmlrpc-enabled",
        "xmlrpc.php answered a system.listMethods call "
        "(brute-force and login-amplification surface)",
        0, 1, "medium", "block xmlrpc.php in .htaccess (wpt harden)",
    )]
    findings[0].validate()
    # exact request shape: URL, body, content-type, facade timeout
    assert session.posts == [(
        f"{SITE}/xmlrpc.php",
        {"data": _XMLRPC_PROBE, "headers": {"Content-Type": "text/xml"}, "timeout": 7},
    )]
    assert _XMLRPC_PROBE == (
        '<?xml version="1.0"?><methodCall>'
        "<methodName>system.listMethods</methodName><params></params></methodCall>"
    )


def test_xmlrpc_silent_cases():
    # the classic "XML-RPC server accepts POST requests only." page: 200, no marker
    assert check_security_xmlrpc(
        sec_data(probe=mkprobe([FakeResponse(200, "XML-RPC server accepts POST requests only.")])),
        DEFAULTS,
    ) == []
    # disabled (405) / missing (404) endpoints
    assert check_security_xmlrpc(sec_data(probe=mkprobe([FakeResponse(405, "no")])), DEFAULTS) == []
    assert check_security_xmlrpc(sec_data(probe=mkprobe([FakeResponse(404, "no")])), DEFAULTS) == []


def test_xmlrpc_degrades():
    assert check_security_xmlrpc(
        sec_data(probe=mkprobe([requests.ConnectionError("refused")])), DEFAULTS
    ) == []
    assert check_security_xmlrpc(sec_data(), DEFAULTS) == []  # probe None


# ------------------------------------------------------ security.rest_users


def test_rest_users_finding():
    body = json.dumps([
        {"id": 2, "slug": "editor"}, {"id": 1, "slug": "admin"}, {"id": 3, "slug": "john"},
    ])
    session = FakeSession([FakeResponse(200, body)])
    probe = SiteProbe(session=session, site=SITE, timeout_s=7)
    findings = check_security_rest_users(sec_data(probe=probe), DEFAULTS)
    assert pinned(findings) == [(
        "security.rest_users", "rest-users",
        "user enumeration via REST: /wp-json/wp/v2/users lists 3 user(s): admin, editor, john",
        0, 3, "medium",
        "block REST /wp/v2/users (pretty and ?rest_route=) in .htaccess "
        "(wpt harden)",
    )]
    findings[0].validate()
    assert session.gets == [(f"{SITE}/wp-json/wp/v2/users", {"allow_redirects": False, "timeout": 7})]


def test_rest_users_detail_truncated():
    body = json.dumps([{"slug": f"u{i}"} for i in range(1, 8)])  # 7 users
    findings = check_security_rest_users(
        sec_data(probe=mkprobe([FakeResponse(200, body)])), DEFAULTS
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.count == 7
    assert f.detail == (
        "user enumeration via REST: /wp-json/wp/v2/users lists 7 user(s): "
        "u1, u2, u3, u4, u5 (+2 more)"
    )


def test_rest_users_silent_cases():
    # 401 / 403 / 404 / redirect: status != 200.  The check probes the
    # pretty URL AND WordPress's two ?rest_route= spellings, so answer all
    # three the same way.
    for status in (401, 403, 404, 302):
        script = [FakeResponse(status, "") for _ in range(3)]
        assert check_security_rest_users(
            sec_data(probe=mkprobe(script)), DEFAULTS
        ) == []
    # 200 but no usable user list
    empty = mkprobe([FakeResponse(200, "[]") for _ in range(3)])
    slugless = mkprobe(
        [FakeResponse(200, json.dumps([{"id": 1}])) for _ in range(3)])
    empty_slug = mkprobe(
        [FakeResponse(200, json.dumps([{"slug": ""}])) for _ in range(3)])
    non_list = mkprobe(
        [FakeResponse(200, json.dumps({"code": "rest_forbidden"}))
         for _ in range(3)])
    bad_json = mkprobe(
        [FakeResponse(200, "<html>not json</html>") for _ in range(3)])
    for probe in (empty, slugless, empty_slug, non_list, bad_json):
        assert check_security_rest_users(sec_data(probe=probe), DEFAULTS) == []


def test_R25_rest_users_detects_the_query_fallback():
    """R25-P1: the pretty path is blocked (403) but WordPress still
    dispatches ``/?rest_route=/wp/v2/users``.  The audit must probe the
    fallback, including the percent-encoded spelling."""
    blocked = [FakeResponse(403, "")]
    body = json.dumps([{"slug": "admin"}, {"slug": "editor"}])
    open_fallback = blocked + [FakeResponse(200, body)]
    findings = check_security_rest_users(
        sec_data(probe=mkprobe(open_fallback)), DEFAULTS)
    assert len(findings) == 1
    assert findings[0].count == 2
    assert "/?rest_route=/wp/v2/users" in findings[0].detail
    # The encoded spelling is the same dispatch when the literal one is
    # filtered by a WAF/rule.
    encoded = blocked + [FakeResponse(404, "")] + [FakeResponse(200, body)]
    findings = check_security_rest_users(
        sec_data(probe=mkprobe(encoded)), DEFAULTS)
    assert len(findings) == 1
    assert "%2Fwp%2Fv2%2Fusers" in findings[0].detail


def test_rest_users_degrades():
    assert check_security_rest_users(
        sec_data(probe=mkprobe(
            [requests.ConnectionError("refused") for _ in range(3)])),
        DEFAULTS) == []
    assert check_security_rest_users(sec_data(), DEFAULTS) == []  # probe None


# ------------------------------------------------------ security.author_scan


def test_author_scan_finding():
    location = f"{SITE}/author/admin/"
    session = FakeSession([Resp(301, headers={"Location": location})])
    probe = SiteProbe(session=session, site=SITE, timeout_s=7)
    findings = check_security_author_scan(sec_data(probe=probe), DEFAULTS)
    assert pinned(findings) == [(
        "security.author_scan", "author-scan",
        f'user enumeration via author redirect: "?author=1" redirects to {location}',
        0, 1, "medium", "block ?author= scans in .htaccess (wpt harden)",
    )]
    findings[0].validate()
    assert session.gets == [(f"{SITE}/?author=1", {"allow_redirects": False, "timeout": 7})]


def test_author_scan_silent_cases():
    # 200 (no redirect), 404, a redirect elsewhere, a 3xx without Location
    for resp in (
        Resp(200, text="home page"),
        Resp(404),
        Resp(302, headers={"Location": f"{SITE}/"}),
        Resp(301),  # no Location header at all
    ):
        assert check_security_author_scan(
            sec_data(probe=mkprobe([resp])), DEFAULTS
        ) == []


def test_author_scan_degrades():
    assert check_security_author_scan(
        sec_data(probe=mkprobe([requests.ConnectionError("refused")])), DEFAULTS
    ) == []
    assert check_security_author_scan(sec_data(), DEFAULTS) == []  # probe None


# ---------------------------------------------------- security.wp_config_perms


def test_wp_config_perms_finding():
    bridge = FakeBridge([{"paths": {"wp-config.php": "0644"}, "context": {"abspath": "0755"}}])
    findings = check_security_wp_config_perms(
        sec_data(probe=mkprobe(bridge=bridge)), DEFAULTS
    )
    assert pinned(findings) == [(
        "security.wp_config_perms", "wp-config-perms",
        "wp-config.php permissions 0644 (readable beyond the owning account)",
        0, 1, "high", "chmod 0600 wp-config.php",
    )]
    findings[0].validate()
    assert bridge.calls == [("fileperms", {"paths": ["wp-config.php"]})]


def test_wp_config_perms_other_than_0600():
    for perms in ("0666", "0640", "0601", "0604", "0777"):
        bridge = FakeBridge([{"paths": {"wp-config.php": perms}}])
        findings = check_security_wp_config_perms(
            sec_data(probe=mkprobe(bridge=bridge)), DEFAULTS
        )
        assert len(findings) == 1 and findings[0].detail.endswith(f"{perms} (readable beyond the owning account)")
    # the single silent permission
    assert check_security_wp_config_perms(
        sec_data(probe=mkprobe(bridge=FakeBridge([{"paths": {"wp-config.php": "0600"}}]))),
        DEFAULTS,
    ) == []


def test_wp_config_perms_unknown_silent():
    # perms None (file does not resolve) / malformed payloads -> silent
    for payload in (
        {"paths": {"wp-config.php": None}},
        {"paths": "broken"},
        {},
        {"paths": {}},
    ):
        bridge = FakeBridge([payload])
        assert check_security_wp_config_perms(
            sec_data(probe=mkprobe(bridge=bridge)), DEFAULTS
        ) == []
    # BridgeError degrades inside the facade; no bridge capability likewise
    down = FakeBridge([BridgeError("bridge down")])
    assert check_security_wp_config_perms(sec_data(probe=mkprobe(bridge=down)), DEFAULTS) == []
    assert check_security_wp_config_perms(sec_data(probe=mkprobe()), DEFAULTS) == []


def test_wp_config_perms_probe_none():
    assert check_security_wp_config_perms(sec_data(), DEFAULTS) == []


# ------------------------------------------------- security.disallow_file_edit


def test_disallow_file_edit_finding():
    source = src_with(**{"wp-config.php": b"<?php\ndefine('DB_NAME','x');\nrequire_once ABSPATH.'wp-settings.php';"})
    findings = check_security_disallow_file_edit(
        sec_data(probe=mkprobe(source=source)), DEFAULTS
    )
    assert pinned(findings) == [(
        "security.disallow_file_edit", "disallow-file-edit",
        "DISALLOW_FILE_EDIT is not active in wp-config.php "
        "(admins can edit plugin and theme source in wp-admin)",
        0, 1, "medium", "add DISALLOW_FILE_EDIT to wp-config.php (wpt harden)",
    )]
    findings[0].validate()


def test_disallow_file_edit_commented_out_is_not_hardened():
    # The old raw-substring test read a commented-out define as hardened.
    source = src_with(**{
        "wp-config.php": b"<?php\n// define( 'DISALLOW_FILE_EDIT', true );\n",
    })
    findings = check_security_disallow_file_edit(
        sec_data(probe=mkprobe(source=source)), DEFAULTS
    )
    # the DEFINITIVE finding, not the indeterminate one
    assert [f.name for f in findings] == ["disallow-file-edit"]


def test_disallow_file_edit_false_is_not_hardened():
    source = src_with(**{
        "wp-config.php": b"<?php\ndefine( 'DISALLOW_FILE_EDIT', false );\n",
    })
    findings = check_security_disallow_file_edit(
        sec_data(probe=mkprobe(source=source)), DEFAULTS
    )
    assert [f.name for f in findings] == ["disallow-file-edit"]


def test_disallow_file_edit_suppressed_by_file_mods():
    # DISALLOW_FILE_MODS also disables the editor (core file_mod_allowed).
    source = src_with(**{
        "wp-config.php": b"<?php\ndefine( 'DISALLOW_FILE_MODS', true );\n",
    })
    assert check_security_disallow_file_edit(
        sec_data(probe=mkprobe(source=source)), DEFAULTS
    ) == []


def test_relocate_active_is_high_risk():
    source = src_with(**{
        "wp-config.php": b"<?php\ndefine( 'RELOCATE', true );\n",
    })
    findings = check_security_relocate(sec_data(probe=mkprobe(source=source)), DEFAULTS)
    assert pinned(findings) == [(
        "security.relocate", "relocate",
        "RELOCATE is active in wp-config.php — wp-login.php will "
        "rewrite siteurl from the incoming request",
        0, 1, "high", "remove the RELOCATE line from wp-config.php (migration-only)",
    )]
    findings[0].validate()


def test_relocate_string_false_is_still_truthy():
    # PHP: a non-empty string is truthy, so define('RELOCATE', 'false') is
    # STILL an active relocation — flag it.
    source = src_with(**{
        "wp-config.php": b"<?php\ndefine( 'RELOCATE', 'false' );\n",
    })
    assert len(check_security_relocate(
        sec_data(probe=mkprobe(source=source)), DEFAULTS
    )) == 1


def test_relocate_false_or_commented_is_silent():
    for body in (b"<?php\ndefine( 'RELOCATE', false );\n",
                 b"<?php\n// define( 'RELOCATE', true );\n",
                 b"<?php\ndefine( 'DB_NAME', 'x' );\n"):
        source = src_with(**{"wp-config.php": body})
        assert check_security_relocate(
            sec_data(probe=mkprobe(source=source)), DEFAULTS
        ) == []


# ------------------------------------------------- PHP-aware constant scanning


@pytest.mark.parametrize(("body", "constant", "expected"), [
    # A '//' inside a URL string must not eat the rest of the file: the old
    # regex comment-stripper reported this active define as absent.
    (b"<?php\ndefine('DB_HOST', 'https://example.com');\ndefine('RELOCATE', true);\n",
     "RELOCATE", "truthy"),
    (b"<?php\n$pw = 'ab#cd';\ndefine('DISALLOW_FILE_EDIT', true);\n",
     "DISALLOW_FILE_EDIT", "truthy"),
    (b"<?php\ndefine('RELOCATE', '/* not a comment */');\n", "RELOCATE", "truthy"),
    # A define written inside a string is not code.
    (b"<?php\n$x = 'define(\"RELOCATE\", true);';\n", "RELOCATE", "absent"),
    (b"<?php\n/* define('RELOCATE', true); */\n", "RELOCATE", "absent"),
    (b"<?php\n# define('RELOCATE', true);\n", "RELOCATE", "absent"),
    # PHP constant names are case-sensitive: 'relocate' is a different name.
    (b"<?php\ndefine('relocate', true);\n", "RELOCATE", "absent"),
    # Class/interface/enum members are not global constants.
    (b"<?php\nclass C { const RELOCATE = true; }\n", "RELOCATE", "absent"),
    (b"<?php\ninterface I { const RELOCATE = true; }\ndefine('RELOCATE', false);\n",
     "RELOCATE", "falsey"),
    (b"<?php\nenum E { const RELOCATE = true; }\n", "RELOCATE", "absent"),
    # A method/variable named define is not the global function.
    (b"<?php\n$obj->define('RELOCATE', true);\n", "RELOCATE", "absent"),
    # define()'s third argument still defines the constant.
    (b"<?php\ndefine('RELOCATE', true, false);\n", "RELOCATE", "truthy"),
    # The first definition wins; a later duplicate is a PHP warning, not a
    # redefinition.
    (b"<?php\ndefine('DISALLOW_FILE_EDIT', true);\ndefine('DISALLOW_FILE_EDIT', false);\n",
     "DISALLOW_FILE_EDIT", "truthy"),
    # '?>' leaves PHP mode, so trailing inline HTML is not code.
    (b"<?php\ndefine('RELOCATE', true); ?>\n<p>define('RELOCATE', true);</p>\n",
     "RELOCATE", "truthy"),
    # A heredoc body is data: its ?> and // are not PHP syntax.
    (b"<?php\n$d = <<<EOT\nline with ?> and // and RELOCATE\nEOT;\ndefine('RELOCATE', true);\n",
     "RELOCATE", "truthy"),
    # PHP truthiness, exactly: '0' is falsey, '00' is truthy, 'false' truthy.
    (b"<?php\ndefine('RELOCATE', '0');\n", "RELOCATE", "falsey"),
    (b"<?php\ndefine('RELOCATE', '00');\n", "RELOCATE", "truthy"),
    (b"<?php\ndefine('RELOCATE', 0.0);\n", "RELOCATE", "falsey"),
    (b"<?php\ndefine('RELOCATE', -1);\n", "RELOCATE", "truthy"),
    (b"<?php\ndefine('RELOCATE', array());\n", "RELOCATE", "falsey"),
    # Double quotes decode escapes: "\x30" is "0", which is falsey.
    (b'<?php\ndefine("DISALLOW_FILE_EDIT", "\\x30");\n', "DISALLOW_FILE_EDIT", "falsey"),
    # Single quotes do not: '\x30' is 4 literal characters, so truthy.
    (b"<?php\ndefine('RELOCATE', '\\x30');\n", "RELOCATE", "truthy"),
    # Runtime-decided values are UNKNOWN, never asserted either way.
    (b"<?php\ndefine('RELOCATE', !0);\n", "RELOCATE", "unknown"),
    (b"<?php\ndefine('RELOCATE', 1 && 0);\n", "RELOCATE", "unknown"),
    (b"<?php\ndefine('RELOCATE', getenv('RELOCATE'));\n", "RELOCATE", "unknown"),
    (b"<?php\nif ( ! defined('RELOCATE') ) { define('RELOCATE', true); }\n",
     "RELOCATE", "unknown"),
    (b"<?php\nconst RELOCATE = true;\n", "RELOCATE", "truthy"),
    (b"<?php\nconst RELOCATE = null;\n", "RELOCATE", "falsey"),
    # Punctuation and digits around a definition are code, not identifier
    # characters: a too-wide identifier class used to swallow '?>' and '@'.
    (b"<?php\ndefine('RELOCATE', false); ?>\n<?php\ndefine('DISALLOW_FILE_EDIT', true);\n",
     "DISALLOW_FILE_EDIT", "truthy"),
    (b"<?php\ndefine('DISALLOW_FILE_EDIT', true);\nFoo::bar();\n",
     "DISALLOW_FILE_EDIT", "truthy"),
    (b"<?php\ndefine('DISALLOW_FILE_EDIT', true); // 12345\n",
     "DISALLOW_FILE_EDIT", "truthy"),
    (b"<?php\ndefine('DISALLOW_FILE_EDIT', true);\n$obj->run();\n",
     "DISALLOW_FILE_EDIT", "truthy"),
    # PHP keywords are case-insensitive; constant names are not.
    (b"<?php\nDEFINE('DISALLOW_FILE_EDIT', false);\n", "DISALLOW_FILE_EDIT", "falsey"),
    (b"<?php\nCoNsT DISALLOW_FILE_EDIT = false;\n", "DISALLOW_FILE_EDIT", "falsey"),
    # An unrecognised escape keeps its backslash, so this defines a DIFFERENT
    # constant ('\DISALLOW_FILE_EDIT') and must not count.
    (b'<?php\ndefine("\\DISALLOW_FILE_EDIT", true);\n', "DISALLOW_FILE_EDIT", "absent"),
    # Interpolation is computed at runtime: indeterminate, never guessed.
    (b'<?php\n$x = 1;\ndefine("DISALLOW_FILE_EDIT", "$x");\n',
     "DISALLOW_FILE_EDIT", "unknown"),
    (b'<?php\ndefine("RELOCATE{$suffix}", true);\n', "RELOCATE", "unknown"),
    # A define() with a computed name could be ours: first-wins is unprovable.
    (b"<?php\ndefine('RELOCATE' . '', false);\ndefine('RELOCATE', true);\n",
     "RELOCATE", "unknown"),
    # A definition that is not an unconditional statement is not provable.
    (b"<?php\nif (false) define('DISALLOW_FILE_EDIT', false);\n",
     "DISALLOW_FILE_EDIT", "unknown"),
    (b"<?php\n$f = fn() => define('RELOCATE', true);\n", "RELOCATE", "unknown"),
    (b"<?php\n$x && define('RELOCATE', true);\n", "RELOCATE", "unknown"),
    (b"<?php\nfunction f() { define('RELOCATE', true); }\n", "RELOCATE", "unknown"),
    # PHP 8 attributes are code, not a '#' comment.
    (b"<?php\n#[MyAttribute]\nfunction f() {}\ndefine('RELOCATE', true);\n",
     "RELOCATE", "truthy"),
    # A parse error means nothing after it can be trusted.
    (b"<?php\n$x = <<<EOT\ndefine('RELOCATE', true);\n", "RELOCATE", "unknown"),
    (b"<?php\n$x = 'unterminated\ndefine('RELOCATE', true);\n", "RELOCATE", "unknown"),
    (b"<?php\n/* unterminated\ndefine('RELOCATE', true);\n", "RELOCATE", "unknown"),
    # '?>' closes PHP mode even inside a line comment, so what follows is
    # inline HTML, not a definition.
    (b"<?php\n// ?>\ndefine('DISALLOW_FILE_EDIT', true);\n",
     "DISALLOW_FILE_EDIT", "absent"),
    (b"<?php\ndefine('RELOCATE', true); ?>\ndefine('RELOCATE', true);\n",
     "RELOCATE", "truthy"),
    # Deterministic literals that are easy to read wrongly.
    (b"<?php\ndefine('RELOCATE', ((false)));\n", "RELOCATE", "falsey"),
    (b"<?php\ndefine('RELOCATE', 0x0);\n", "RELOCATE", "falsey"),
    (b"<?php\ndefine('RELOCATE', 0b0);\n", "RELOCATE", "falsey"),
    (b"<?php\ndefine('RELOCATE', (1));\n", "RELOCATE", "truthy"),
    # A method named define is not the global function.
    (b"<?php\nclass define {}\nnew define('RELOCATE', true);\n", "RELOCATE", "absent"),
    (b"<?php\nfunction define() {}\ndefine('RELOCATE', true);\n", "RELOCATE", "truthy"),
    # The open tag is case-insensitive in PHP.
    (b"<?PHP\ndefine('RELOCATE', true);\n", "RELOCATE", "truthy"),
    # Data after __halt_compiler() is never executed.
    (b"<?php\n__halt_compiler();\ndefine('RELOCATE', true);\n", "RELOCATE", "absent"),
    # A namespaced const is not the global WordPress constant: the scan keeps
    # looking for a real global definition, and reports ABSENT when there is
    # none — which is what PHP does. (Both drive the same "not hardened"
    # decision, so the write path stays fail-closed either way.)
    (b"<?php\nnamespace Vendor;\nconst DISALLOW_FILE_EDIT = false;\n",
     "DISALLOW_FILE_EDIT", "absent"),
    # ...and a global definition after a namespaced one still governs.
    (b"<?php\nnamespace Vendor;\nconst DISALLOW_FILE_EDIT = true;\n"
     b"namespace {\ndefine('DISALLOW_FILE_EDIT', false);\n}\n",
     "DISALLOW_FILE_EDIT", "falsey"),
    # `declare(ticks=1):` runs its body unconditionally: a statement boundary,
    # not a conditional block.
    (b"<?php\ndeclare(ticks=1):\ndefine('X', true);\nenddeclare;\n",
     "X", "truthy"),
    # A label is a statement, so what follows it is still top level.
    (b"<?php\ntop:\ndefine('X', true);\n", "X", "truthy"),
    # A ternary colon is not an alternative-syntax opener.
    (b"<?php\nif (false) {}\n$a = true ? 1 : 0;\ndefine('X', true);\n",
     "X", "truthy"),
    # A method/const/named-argument named `endif` is not a terminator.
    (b"<?php\nif (false):\nclass C { function endif() {} }\n"
     b"define('X', true);\nendif;\n", "X", "unknown"),
    # An identifier at EOF has no following token: a crash here once made a
    # malformed file take the whole run down.
    (b"<?php\nendif", "X", "absent"),
    (b"<?php\ntop", "X", "absent"),
    # A return-type colon is not an alternative-syntax opener.
    (b"<?php\nif (false) {}\nfunction f(): void {}\ndefine('X', true);\n",
     "X", "truthy"),
    # A ternary inside the control head: the `):` still opens the block.
    (b"<?php\nif (true ? false : true):\ndefine('X', true);\nendif;\n",
     "X", "unknown"),
    # An arrow body is its own scope: `fn() => exit` never ends the file.
    (b"<?php\n$c = fn() => exit;\ndefine('X', true);\n", "X", "truthy"),
    (b"<?php\n$c = fn() => goto end;\nend:\ndefine('X', true);\n", "X", "truthy"),
    # ...while a real file-scope exit still taints everything after it.
    (b"<?php\nexit;\ndefine('X', true);\n", "X", "unknown"),
    # `fn` has no brace body, so the next block is NOT a function body and an
    # exit inside it is a real file-scope exit.
    (b"<?php\n$c = fn() => 1;\nif (true) { exit; }\ndefine('X', false);\n",
     "X", "unknown"),
    # A nested arrow must not clobber the enclosing arrow's scope.
    (b"<?php\n$c = fn() => (fn() => 1)() ?: exit;\ndefine('X', true);\n",
     "X", "truthy"),
    # A comma ends the arrow expression, so a sibling exit is a real one.
    (b"<?php\n$x = [fn() => 1, exit];\ndefine('X', true);\n", "X", "unknown"),
    # define() takes two or three arguments. PHP raises ArgumentCountError on
    # a fourth BEFORE defining anything, so the value cannot be proven.
    (b"<?php\ndefine('X', true, false);\n", "X", "truthy"),
    (b"<?php\ndefine('X', true, false, 'extra');\n", "X", "unknown"),
    # An array's elements are evaluated before define() is called, so only a
    # literal array is a known value: `[exit]` ends the script first.
    (b"<?php\ndefine('X', []);\n", "X", "falsey"),
    (b"<?php\ndefine('X', [1, 'a']);\n", "X", "truthy"),
    (b"<?php\ndefine('X', [exit]);\n", "X", "unknown"),
    (b"<?php\ndefine('X', [foo()]);\n", "X", "unknown"),
    # A trailing comma after three arguments is legal PHP, and unpacking
    # expands at runtime, so neither may be read as a fourth argument.
    (b"<?php\ndefine('X', true, false,);\n", "X", "truthy"),
    (b"<?php\ndefine('X', true, ...[false, false]);\n", "X", "unknown"),
    # A comment inside the value is not part of the literal.
    (b"<?php\ndefine('X', /* intentionally enabled */ true);\n", "X", "truthy"),
    (b"<?php\ndefine('X', [1, /* id */ 2]);\n", "X", "truthy"),
    # The THIRD argument is evaluated before define() runs, so it must be a
    # provable literal too: `define('X', true, exit)` never defines anything.
    (b"<?php\ndefine('X', true, false);\n", "X", "truthy"),
    (b"<?php\ndefine('X', true, 1);\n", "X", "truthy"),
    (b"<?php\ndefine('X', true, [1]);\n", "X", "unknown"),
    (b"<?php\ndefine('X', true, exit);\n", "X", "unknown"),
    (b"<?php\ndefine('X', true, foo());\n", "X", "unknown"),
    (b"<?php\ndefine('X', true, [exit]);\n", "X", "unknown"),
    (b"<?php\ndefine('X', true, $flag);\n", "X", "unknown"),
    # A later name in one multi-constant declaration still counts.
    (b"<?php\nconst OTHER = 1, DISALLOW_FILE_EDIT = false;\n",
     "DISALLOW_FILE_EDIT", "falsey"),
    # An anonymous class body is still a type body.
    (b"<?php\n$x = new class { const RELOCATE = true; };\n", "RELOCATE", "absent"),
    # '?>' implies a semicolon, so the next statement still starts clean.
    (b"<?php\n$x = true ?>\n<?php\ndefine('X', true);\n", "X", "truthy"),
    # An unterminated call/declaration is a parse error, not a known value.
    (b"<?php\ndefine('X', true", "X", "unknown"),
    (b"<?php\nconst X = true", "X", "unknown"),
    # Underscores are only legal between digits.
    (b"<?php\ndefine('RELOCATE', 0b1__0);\n", "RELOCATE", "unknown"),
    (b"<?php\ndefine('RELOCATE', 1_000);\n", "RELOCATE", "truthy"),
    (b"<?php\ndefine('RELOCATE', -0x1);\n", "RELOCATE", "truthy"),
    # A statement that can end execution first makes the definition
    # unreachable, so it must not be reported as active hardening.
    (b"<?php\nif (true) return; define('DISALLOW_FILE_EDIT', true);\n",
     "DISALLOW_FILE_EDIT", "unknown"),
    (b"<?php\nexit; define('DISALLOW_FILE_EDIT', true);\n",
     "DISALLOW_FILE_EDIT", "unknown"),
    # A malformed attribute is a parse error, not a crash.
    (b"<?php\n#[Attr('unterminated)]\ndefine('X', true);\n", "X", "unknown"),
    # PHP keywords are case-insensitive, so __halt_compiler is too.
    (b"<?php\n__HALT_COMPILER();\ndefine('X', true);\n", "X", "absent"),
    # '?>' inside a line comment still implies a statement terminator.
    (b"<?php\n$x = true // ?>\n<?php\ndefine('X', true);\n", "X", "truthy"),
    (b"<?php\n$x = true # ?>\n<?php\ndefine('X', true);\n", "X", "truthy"),
    # A member named like an exit construct is not an exit statement.
    (b"<?php\n$o = new class { function return() {} }; $o->return(); define('X', true);\n",
     "X", "truthy"),
    # 'namespace' as a method or a qualified call is not a declaration.
    (b"<?php\n$o->namespace(); const X = true;\n", "X", "truthy"),
    (b"<?php\nnamespace\\strlen('x'); const X = true;\n", "X", "truthy"),
    # A bracketed namespace ends: a later global block is global again.
    (b"<?php\nnamespace Foo { const OTHER = 1; }\nnamespace { const X = true; }\n",
     "X", "truthy"),
    # A literal array with content is truthy whatever the elements are.
    (b"<?php\nconst A = array(1,2);\n", "A", "truthy"),
    (b"<?php\nconst A = [0];\n", "A", "truthy"),
    (b"<?php\nconst A = [];\n", "A", "falsey"),
    (b"<?php\nconst A = array();\n", "A", "falsey"),
    # A close tag inside a string is data, not a mode switch.
    (b"<?php $x = ' ?> '; define('X', true);", "X", "truthy"),
    # Numeric forms.
    (b"<?php\ndefine('X', 0X1F);\n", "X", "truthy"),
    (b"<?php\ndefine('X', .5);\n", "X", "truthy"),
    (b"<?php\ndefine('X', 1e3);\n", "X", "truthy"),
    (b"<?php\ndefine('X', 0o17);\n", "X", "truthy"),
    # A realistic config with a prefix table and ordinary calls stays definite.
    (b"<?php\n$table_prefix = 'wp_';\ndefine('DB_NAME', 'throw');\n"
     b"define('X', true);\n", "X", "truthy"),
    (b"<?php\nfunction cfg(): string { return 'x'; }\ndefine('X', true);\n",
     "X", "truthy"),
    # Whitespace and comments do not hide a member context.
    (b"<?php\n$o-> return(); const X = true;\n", "X", "truthy"),
    (b"<?php\n$o ?->__HALT_COMPILER(); define('X', true);\n", "X", "truthy"),
    # Emptiness ignores whitespace and comments.
    (b"<?php\ndefine('X', array( ));\n", "X", "falsey"),
    (b"<?php\ndefine('X', [ ]);\n", "X", "falsey"),
    (b"<?php\ndefine('X', [ /* nothing */ ]);\n", "X", "falsey"),
    # Unmatched delimiters are a parse error: nothing can be trusted.
    (b"<?php\nnamespace { } } define('X', true);\n", "X", "unknown"),
    (b"<?php\ndefine('X', true;\n", "X", "unknown"),
    # A jump may bypass the definition.
    (b"<?php\ngoto skip;\ndefine('X', true);\nskip:\n", "X", "unknown"),
    (b"<?php\nGoTo skip;\ndefine('X', true);\n", "X", "unknown"),
    # A multi-line constant declaration is valid PHP and must be found.
    (b"<?php\nconst OTHER = 1,\n      DISALLOW_FILE_EDIT = false;\n",
     "DISALLOW_FILE_EDIT", "falsey"),
    (b"<?php\ndefine(\n  'DISALLOW_FILE_EDIT',\n  true\n);\n",
     "DISALLOW_FILE_EDIT", "truthy"),
    # A comment inside an attribute is not a bracket.
    (b"<?php\n#[Attr(/* ] */ Foo)]\nfunction f() {}\ndefine('X', true);\n",
     "X", "truthy"),
    # In a namespace, define() may be a user function; only the global
    # built-in (reached explicitly as \define) is definitive.
    (b"<?php\nnamespace Vendor;\n"
     b"function define(string $n, mixed $v): void {}\n"
     b"define('DISALLOW_FILE_EDIT', true);\n", "DISALLOW_FILE_EDIT", "unknown"),
    (b"<?php\nnamespace Vendor;\n\\define('DISALLOW_FILE_EDIT', true);\n",
     "DISALLOW_FILE_EDIT", "truthy"),
    # `use function` is an import, not a declaration.
    (b"<?php\nnamespace Vendor;\nuse function strlen;\ndefine('X', true);\n",
     "X", "unknown"),
    # A definition inside an alternative-syntax conditional is conditional:
    # no braces, so only the opener/terminator count reveals it.
    (b"<?php\n$enabled = 0;\nif ( $enabled ):\n    echo 'x';\n"
     b"    define('DISALLOW_FILE_EDIT', false);\nendif;\n",
     "DISALLOW_FILE_EDIT", "unknown"),
    (b"<?php\nif ( $a ): echo 1;\nendif;\ndefine('X', true);\n", "X", "truthy"),
    # A braced namespace only changes name resolution, not top-level-ness.
    (b"<?php\nnamespace Vendor { \\define('DISALLOW_FILE_EDIT', true); }\n",
     "DISALLOW_FILE_EDIT", "truthy"),
    # A braced declare block runs its body unconditionally.
    (b"<?php\ndeclare(ticks=1) {\n    define('DISALLOW_FILE_EDIT', true);\n}\n",
     "DISALLOW_FILE_EDIT", "truthy"),
    # A file-scope exit inside an ordinary control block precedes the
    # definition; one inside a function body cannot end the file.
    (b"<?php\nif ( $c ) { exit; }\ndefine('DISALLOW_FILE_EDIT', true);\n",
     "DISALLOW_FILE_EDIT", "unknown"),
    (b"<?php\nfunction f() { return 1; }\ndefine('DISALLOW_FILE_EDIT', true);\n",
     "DISALLOW_FILE_EDIT", "truthy"),
    # A previous word belongs to its own statement only.
    (b"<?php\n$callback = function () {};\ndefine('X', true);\n", "X", "truthy"),
    # A VARIABLE named $endif is not the block terminator: counting it would
    # make a still-open alternative block look closed.
    (b"<?php\n$endif = 1;\nif ( $c ):\n    define('DISALLOW_FILE_EDIT', true);\n"
     b"endif;\n", "DISALLOW_FILE_EDIT", "unknown"),
    (b"<?php\n$endif = 1;\nif ( $c ): echo 1; endif;\ndefine('X', true);\n",
     "X", "truthy"),
])
def test_php_const_state_scans_php_not_text(body, constant, expected):
    assert _php_const_state(body.decode(), constant) == expected


@pytest.mark.parametrize("depth", [1024, 4096])
def test_deeply_nested_valid_literals_fail_closed_instead_of_recursing(depth):
    # PHP accepts these, but each nesting level re-lexes the value, so the
    # literal evaluator must stop rather than exhaust the interpreter stack.
    assert _php_const_state(
        "<?php\nconst X = " + "[" * depth + "]" * depth + ";", "X"
    ) == "unknown"


@pytest.mark.parametrize("body", [
    'eval("define(\'X\', true);");',
    '$c = "define(\'X\', true);"; eval($c);',
    '$eval = "x"; $eval("define(\'X\', true);");',
    'eval("define(\'X\', false);"); define(\'X\', true);',
    'create_function("define(\'X\', true);");',
    'assert("define(\'X\', true);");',
])
def test_a_runtime_definition_makes_the_state_indeterminate(body):
    # PHP executes these, so reporting "absent" was a FALSE finding for
    # DISALLOW_FILE_EDIT and a missed active state for RELOCATE.
    assert _php_const_state(f"<?php\n{body}\n", "X") == "unknown"


@pytest.mark.parametrize("body", [
    '$o->eval("x");',
    'Foo::eval("x");',
    '$eval = "strlen";',
    '// eval("x");',
    '$s = "eval(\\"x\\")";',
    'foo(eval: 1);',
    'define(\'X\', true);',
])
def test_something_that_cannot_define_at_runtime_stays_resolvable(body):
    assert _php_const_state(f"<?php\n{body}\n", "X") in ("absent", "truthy")


def _nested_interpolation(levels: int, payload: str) -> str:
    """`payload` wrapped in `levels` real `${f("...")}` interpolation layers."""
    inner = payload
    for _ in range(levels):
        inner = '${f("' + inner + '")}'
    return '<?php\n$x = "' + inner + '";\n'


def test_interpolation_past_the_structural_bound_is_indeterminate():
    # Past its recursion bound the scanner cannot model the expression, but
    # PHP still executes it: reading the body as absent text reported a
    # constant as absent (a false finding) or as the later define's value.
    from wpt.audit.security import _php_code_flags
    shallow = _nested_interpolation(3, 'eval("define(\'X\', true);");')
    deep = _nested_interpolation(40, 'eval("define(\'X\', true);");')
    assert not any(b == 2 for b in _php_code_flags(shallow)[0])
    assert any(b == 2 for b in _php_code_flags(deep)[0]), \
        "the depth bound must be reachable, or the guard is dead code"
    for source in (shallow, deep):
        assert _php_const_state(source, "X") == "unknown"
        assert _php_const_state(source + "define('X', true);\n", "X") \
            == "unknown"


def test_interpolation_within_the_bound_still_resolves():
    from wpt.audit.security import _php_code_flags
    source = _nested_interpolation(3, '1;')
    assert not any(b == 2 for b in _php_code_flags(source)[0])
    assert _php_const_state(source + "define('X', true);\n", "X") == "truthy"


def test_disallow_file_edit_indeterminate_is_reported_not_assumed():
    source = src_with(**{
        "wp-config.php": b"<?php\ndefine( 'DISALLOW_FILE_EDIT', !0 );\n",
    })
    findings = check_security_disallow_file_edit(
        sec_data(probe=mkprobe(source=source)), DEFAULTS
    )
    assert len(findings) == 1
    assert "cannot resolve" in findings[0].detail


def test_disallow_file_edit_indeterminate_when_only_file_mods_is_dynamic():
    # A runtime-computed DISALLOW_FILE_MODS might or might not close the
    # editor, so the result is unverifiable — not "definitely open".
    source = src_with(**{
        "wp-config.php": (
            b"<?php\ndefine( 'DISALLOW_FILE_EDIT', false );\n"
            b"define( 'DISALLOW_FILE_MODS', getenv('LOCK_MODS') );\n"
        ),
    })
    findings = check_security_disallow_file_edit(
        sec_data(probe=mkprobe(source=source)), DEFAULTS
    )
    assert len(findings) == 1
    assert findings[0].name == "disallow-file-edit-unverifiable"
    assert "cannot resolve" in findings[0].detail


def test_relocate_indeterminate_is_reported_not_assumed_safe():
    source = src_with(**{
        "wp-config.php": b"<?php\ndefine( 'RELOCATE', getenv('RELOCATE') );\n",
    })
    findings = check_security_relocate(
        sec_data(probe=mkprobe(source=source)), DEFAULTS
    )
    assert len(findings) == 1
    assert findings[0].risk == "medium"
    assert "cannot resolve" in findings[0].detail


def test_disallow_file_edit_silent():
    hardened = src_with(**{
        "wp-config.php": b"<?php\ndefine( 'DISALLOW_FILE_EDIT', true );\n",
    })
    assert check_security_disallow_file_edit(
        sec_data(probe=mkprobe(source=hardened)), DEFAULTS
    ) == []


def test_disallow_file_edit_degrades():
    # wp-config.php unreadable/absent (empty FakeSource) -> read_file None
    assert check_security_disallow_file_edit(
        sec_data(probe=mkprobe(source=FakeSource())), DEFAULTS
    ) == []
    # probe without a source capability
    assert check_security_disallow_file_edit(sec_data(probe=mkprobe()), DEFAULTS) == []
    # probe None
    assert check_security_disallow_file_edit(sec_data(), DEFAULTS) == []


# --------------------------------------------------- security.https_redirect


def test_https_redirect_mixed_pages():
    pages = [
        "https://site.test/about/",      # sampled: 200 -> offender
        "https://site.test/contact/",    # sampled: 301 to http://www -> leaves
        "https://site.test/pricing/",    # sampled: network error -> skipped
        "https://site.test/never-probed/",  # 4th page: beyond the sample cap
    ]
    session = FakeSession([
        Resp(301, headers={"Location": f"{SITE}/"}),   # homepage twin
        Resp(200, text="about us"),
        Resp(301, headers={"Location": "http://www.site.test/contact/"}),
        requests.ConnectionError("reset"),
    ])
    probe = SiteProbe(session=session, site=SITE, timeout_s=7)
    findings = check_security_https_redirect(sec_data(probe=probe, pages=pages), DEFAULTS)
    assert pinned(findings) == [(
        "security.https_redirect", "https-redirect",
        "https://site.test/about/", 0, 1, "medium",
        "force HTTPS in .htaccess (wpt harden)",
    )]
    findings[0].validate()
    # every sample probed over http:// without following redirects
    assert [url for url, kw in session.gets] == [
        "http://site.test", "http://site.test/about/",
        "http://site.test/contact/", "http://site.test/pricing/",
    ]
    assert all(kw == {"allow_redirects": False, "timeout": 7} for _u, kw in session.gets)


def test_https_redirect_all_leave_silent():
    session = FakeSession([
        Resp(301, headers={"Location": f"{SITE}/"}),           # 301 -> https
        Resp(302, headers={"Location": f"{SITE}/a/"}),          # 302 -> https
        Resp(200, headers={"Location": f"{SITE}/b/"}),          # 200 + https Location
    ])
    probe = SiteProbe(session=session, site=SITE, timeout_s=7)
    pages = ["https://site.test/a/", "https://site.test/b/"]
    assert check_security_https_redirect(sec_data(probe=probe, pages=pages), DEFAULTS) == []


def test_https_redirect_homepage_only():
    # pages None: the documented single-sample limitation
    finding_probe = mkprobe([Resp(200, text="plain http homepage")])
    findings = check_security_https_redirect(sec_data(probe=finding_probe, pages=None), DEFAULTS)
    assert pinned(findings) == [(
        "security.https_redirect", "https-redirect",
        SITE, 0, 1, "medium", "force HTTPS in .htaccess (wpt harden)",
    )]
    # homepage already redirecting -> silent
    assert check_security_https_redirect(
        sec_data(probe=mkprobe([Resp(301, headers={"Location": f"{SITE}/"})]), pages=None),
        DEFAULTS,
    ) == []


def test_https_redirect_dedupes():
    session = FakeSession([
        Resp(200, text="no redirect"),                      # homepage (offender)
        Resp(301, headers={"Location": f"{SITE}/about/"}),  # about leaves
    ])
    probe = SiteProbe(session=session, site=SITE, timeout_s=7)
    pages = [SITE, "https://site.test/about/"]  # homepage repeated in pages
    findings = check_security_https_redirect(sec_data(probe=probe, pages=pages), DEFAULTS)
    assert [url for url, kw in session.gets] == ["http://site.test", "http://site.test/about/"]
    assert pinned(findings) == [(
        "security.https_redirect", "https-redirect",
        SITE, 0, 1, "medium", "force HTTPS in .htaccess (wpt harden)",
    )]


def test_https_redirect_degrades():
    # homepage-only probe failure: unknown, not "secure" and not an offender
    assert check_security_https_redirect(
        sec_data(probe=mkprobe([requests.ConnectionError("refused")]), pages=None),
        DEFAULTS,
    ) == []
    assert check_security_https_redirect(sec_data(), DEFAULTS) == []  # probe None


# ------------------------------------------------------- security.www_apex


def test_www_apex_redirect_silent():
    session = FakeSession([Resp(200, url=f"{SITE}/", text="home")])  # final: apex
    probe = SiteProbe(session=session, site=SITE, timeout_s=7)
    assert check_security_www_apex(sec_data(probe=probe), DEFAULTS) == []
    # the www host is probed WITH redirect following
    assert session.gets == [("https://www.site.test/", {"allow_redirects": True, "timeout": 7})]


def test_www_apex_www_serves_finding():
    session = FakeSession([Resp(200, url="https://www.site.test/", text="mirrored content")])
    probe = SiteProbe(session=session, site=SITE, timeout_s=7)
    findings = check_security_www_apex(sec_data(probe=probe), DEFAULTS)
    assert pinned(findings) == [(
        "security.www_apex", "www-apex",
        "www.site.test serves content without redirecting to the apex host "
        "(duplicate host: SEO + stale-cert risk)",
        0, 1, "low", "redirect www to apex in the hoster's DNS or .htaccess "
        "(outside wpt harden's v1 scope)",
    )]
    findings[0].validate()


def test_www_apex_already_www():
    session = FakeSession()  # empty script: any request would raise
    probe = SiteProbe(session=session, site="https://www.site.test", timeout_s=7)
    assert check_security_www_apex(sec_data(probe=probe), DEFAULTS) == []
    assert session.gets == []  # never probed anything


def test_www_apex_unreachable_silent():
    # www not serving is the good case; a non-2xx final likewise silent
    assert check_security_www_apex(
        sec_data(probe=mkprobe([requests.ConnectionError("no such host")])), DEFAULTS
    ) == []
    assert check_security_www_apex(
        sec_data(probe=mkprobe([Resp(404, url="https://www.site.test/")])), DEFAULTS
    ) == []


def test_www_apex_probe_none():
    assert check_security_www_apex(sec_data(), DEFAULTS) == []


# ---------------------------------------------------- security.cert_mismatch


def test_cert_ok_handshake_silent(tls):
    probe = mkprobe(timeout_s=7)
    d = sec_data(probe=probe, siteurl="https://site.test/wp")  # path ignored
    assert check_security_cert_mismatch(d, DEFAULTS) == []
    assert [call[0] for call in tls.conn_calls] == [("site.test", 443)]
    # The dial carries the request's own bound (a few microseconds of
    # setup elapsed before the attempt), never the run budget.
    assert 6.5 <= tls.conn_calls[0][1] <= 7.1
    assert tls.wrap_calls == ["site.test"]  # server_hostname from data.siteurl


def test_R17_cert_probe_unencodable_sni_is_silent_not_check_failed(tls):
    """R17-3-P2: a host Python's IDNA codec refuses raised UnicodeEncodeError
    out of server_hostname and the audit reported a HIGH check_failed.  The
    unusable measured value is silent, like every other unknown TLS fact."""
    before = len(tls.conn_calls)
    findings = check_security_cert_mismatch(
        sec_data(probe=mkprobe(), siteurl="https://" + "a" * 64 + ".uk"),
        DEFAULTS,
    )
    assert findings == []
    assert len(tls.conn_calls) == before


def test_cert_verification_failure_finding(tls):
    tls.wrap_exc = ssl.SSLCertVerificationError("hostname mismatch")
    findings = check_security_cert_mismatch(
        sec_data(probe=mkprobe(), siteurl=SITE), DEFAULTS
    )
    assert pinned(findings) == [(
        "security.cert_mismatch", "cert-mismatch",
        "the TLS certificate does not verify for site.test "
        "(expected before the migration cutover)",
        0, 1, "low",
        "install a Let's Encrypt cert for the DNS name after the migration",
    )]
    findings[0].validate()


def test_cert_other_failures_silent(tls):
    tls.conn_exc = ConnectionRefusedError()  # host unreachable
    assert check_security_cert_mismatch(
        sec_data(probe=mkprobe(), siteurl=SITE), DEFAULTS
    ) == []
    tls.conn_exc = None
    tls.wrap_exc = ssl.SSLError("handshake failure")  # not a verification error
    assert check_security_cert_mismatch(
        sec_data(probe=mkprobe(), siteurl=SITE), DEFAULTS
    ) == []
    # unknown siteurl / no probe: silent without touching the TLS layer
    assert check_security_cert_mismatch(sec_data(probe=mkprobe()), DEFAULTS) == []
    assert check_security_cert_mismatch(sec_data(), DEFAULTS) == []
    # only the two reachable-host cases attempted a connection
    assert [call[0] for call in tls.conn_calls] == [("site.test", 443)] * 2
    assert all(6.5 <= call[1] <= 7.1 for call in tls.conn_calls)


def test_cert_uses_siteurl_host_as_is(tls):
    # a www siteurl probes the www name (design: siteurl's host, NOT re-hosted)
    check_security_cert_mismatch(sec_data(probe=mkprobe(), siteurl="https://www.site.test"), DEFAULTS)
    assert tls.wrap_calls == ["www.site.test"]


def test_cert_probe_dials_the_urls_explicit_port(tls):
    """C4: the cert probe hardcoded 443, so it validated a different origin
    than the :8443 URL the rest of the audit used."""
    probe = SiteProbe(
        session=FakeSession(), site=SITE, timeout_s=7, override_ip="203.0.113.10",
    )
    check_security_cert_mismatch(
        sec_data(probe=probe, siteurl="https://example.test:8443"), DEFAULTS
    )
    assert [call[0] for call in tls.conn_calls] == [
        ("203.0.113.10", 8443)]
    assert 6.5 <= tls.conn_calls[0][1] <= 7.1


def test_cert_override_ip_is_dialed_with_site_sni(tls):
    """[L13] --override-ip: the raw-socket cert probe dials the OVERRIDE
    address with server_hostname = the site host — the same override every
    session-riding probe honors.  The old probe dialed real DNS, so a
    network whose resolver answered a different server (an internal
    *.host view) turned a VALID cert into a false mismatch."""
    probe = SiteProbe(
        session=FakeSession(), site=SITE, timeout_s=7, override_ip="203.0.113.10",
    )
    check_security_cert_mismatch(
        sec_data(probe=probe, siteurl="https://example.test"), DEFAULTS
    )
    assert [call[0] for call in tls.conn_calls] == [
        ("203.0.113.10", 443)]
    assert 6.5 <= tls.conn_calls[0][1] <= 7.1
    assert tls.wrap_calls == ["example.test"]  # SNI still the site host
    # None (the default) keeps the pre-override behavior: real DNS
    check_security_cert_mismatch(
        sec_data(probe=mkprobe(timeout_s=7), siteurl="https://site.test"), DEFAULTS
    )
    assert tls.conn_calls[-1][0] == ("site.test", 443)
    assert 6.5 <= tls.conn_calls[-1][1] <= 7.1


# --------------------------------------------------- security.uploads_listing


def test_uploads_listing_finding():
    session = FakeSession([
        Resp(200, "<html><head><title>Index of /wp-content/uploads/</title></head></html>"),
    ])
    probe = SiteProbe(session=session, site=SITE, timeout_s=7)
    findings = check_security_uploads_listing(sec_data(probe=probe), DEFAULTS)
    assert pinned(findings) == [(
        "security.uploads_listing", "uploads-listing",
        "wp-content/uploads/ serves a directory listing",
        0, 1, "medium", "Options -Indexes in .htaccess (wpt harden)",
    )]
    findings[0].validate()
    assert session.gets == [
        (f"{SITE}/wp-content/uploads/", {"allow_redirects": False, "timeout": 7})
    ]


def test_uploads_listing_content_type():
    # the parenthetical: 200 + html content-type, no "Index of" marker
    resp = Resp(200, text="listing denied words absent", headers={"Content-Type": "text/html; charset=UTF-8"})
    findings = check_security_uploads_listing(
        sec_data(probe=mkprobe([resp])), DEFAULTS
    )
    assert len(findings) == 1 and findings[0].name == "uploads-listing"


def test_uploads_listing_silent():
    for resp in (
        Resp(403),                                        # Options -Indexes answer
        Resp(302, headers={"Location": f"{SITE}/"}),     # redirected
        Resp(404),                                        # nothing there
        Resp(200, text="[]", headers={"Content-Type": "application/json"}),  # non-html
    ):
        assert check_security_uploads_listing(
            sec_data(probe=mkprobe([resp])), DEFAULTS
        ) == []


def test_uploads_listing_degrades():
    assert check_security_uploads_listing(
        sec_data(probe=mkprobe([requests.ConnectionError("refused")])), DEFAULTS
    ) == []
    assert check_security_uploads_listing(sec_data(), DEFAULTS) == []  # probe None


# -------------------------------------------------------- security.debug_log


def test_debug_log_finding():
    findings = check_security_debug_log(
        sec_data(entries=[E("wp-content/debug.log", 2048)]), DEFAULTS
    )
    assert pinned(findings) == [(
        "security.debug_log", "debug-log",
        "wp-content/debug.log is exposed in the webroot (WP_DEBUG output)",
        2048, 1, "medium", "delete debug.log; disable WP_DEBUG",
    )]
    findings[0].validate()


def test_debug_log_silent():
    d = sec_data(entries=[
        E("wp-content/debug.log", 0, is_dir=True),   # a directory, not the file
        E("debug.log", 10),                          # wrong location
        E("wp-content/debug.log.bak", 10),           # different name
        E("wp-content/uploads/debug.log", 10),       # buried under uploads
    ])
    assert check_security_debug_log(d, DEFAULTS) == []
    assert check_security_debug_log(sec_data(), DEFAULTS) == []  # nothing walked


def test_debug_log_no_probe_still_finds():
    # entries-based (documented): reports even for a probe-less caller
    assert check_security_debug_log(
        sec_data(entries=[E("wp-content/debug.log", 99)]), DEFAULTS
    )[0].bytes == 99


# -------------------------------------------------- security.php_version


def test_php_version_eol_finding():
    bridge = FakeBridge([info_payload(php_version="7.4.33")])
    findings = check_security_php_version(
        sec_data(probe=mkprobe(bridge=bridge)), DEFAULTS
    )
    assert pinned(findings) == [(
        "security.php_version", "php-eol",
        "PHP 7.4.33 (sapi fpm-fcgi, mysql 8.0.40, memory_limit 256M, "
        "max_execution_time 120, server Apache/2.4.62)",
        0, 1, "medium",
        "Upgrade the host PHP runtime: 7.4 is past active support (only "
        "older minors get security fixes); the hoster (DirectAdmin/cPanel) "
        "offers selector switches",
    )]
    findings[0].validate()
    assert bridge.calls == [("info", {})]
    # a sparse payload: every absent fact renders "unknown" per field
    sparse = FakeBridge([{"php_version": "7.4.33"}])
    findings = check_security_php_version(
        sec_data(probe=mkprobe(bridge=sparse)), DEFAULTS
    )
    assert findings[0].detail == (
        "PHP 7.4.33 (sapi unknown, mysql unknown, memory_limit unknown, "
        "max_execution_time unknown, server unknown)"
    )


def test_php_version_healthy_silent():
    # at-or-above the minimum -> silence (the updates-check precedent:
    # a healthy runtime reports nothing). 8.3.33 is the LIVE host.
    for version in ("8.3.33", "8.2", "8.2.1", "9.0.0"):
        bridge = FakeBridge([info_payload(php_version=version)])
        assert check_security_php_version(
            sec_data(probe=mkprobe(bridge=bridge)), DEFAULTS
        ) == []


def test_php_version_missing_silent():
    # php_version absent/None/empty/non-string is unknown; the payload's
    # php_version_id int is deliberately NOT a fallback
    for payload in (
        {},
        {"php_version_id": 70433},
        {"php_version": None},
        {"php_version": ""},
        {"php_version": 80333},
    ):
        bridge = FakeBridge([payload])
        assert check_security_php_version(
            sec_data(probe=mkprobe(bridge=bridge)), DEFAULTS
        ) == []


def test_php_version_unparseable_silent():
    # the parser needs a decimal major.minor prefix; anything else is
    # unknown -> silence, never a guess
    for version in ("8", "x.y", "8.x.1", "8.3-beta", "PHP 8.3"):
        bridge = FakeBridge([info_payload(php_version=version)])
        assert check_security_php_version(
            sec_data(probe=mkprobe(bridge=bridge)), DEFAULTS
        ) == []
    # the shapes that DO parse: X.Y, X.Y.Z and distro-suffixed releases
    assert security._php_minor("8.3.33") == (8, 3)
    assert security._php_minor("7.4") == (7, 4)
    assert security._php_minor("8.1.2-1ubuntu2.14") == (8, 1)


def test_php_version_numeric_tuple_comparison(monkeypatch):
    # "8.10" > "8.9" numerically: with the minimum set to "8.9", a
    # float comparison ("8.10" -> 8.1 < 8.9) would flag 8.10 — the parsed
    # (major, minor) tuple keeps it silent. The floor is the SETTINGS
    # tunable env.php_min_active (dataclasses.replace on the env section).
    from dataclasses import replace as _replace

    settings = _replace(DEFAULTS, env=_replace(DEFAULTS.env,
                                               php_min_active="8.9"))
    healthy = FakeBridge([info_payload(php_version="8.10.1")])
    assert check_security_php_version(
        sec_data(probe=mkprobe(bridge=healthy)), settings
    ) == []
    at_minimum = FakeBridge([info_payload(php_version="8.9")])
    assert check_security_php_version(
        sec_data(probe=mkprobe(bridge=at_minimum)), settings
    ) == []
    below = FakeBridge([info_payload(php_version="8.8.30")])
    findings = check_security_php_version(
        sec_data(probe=mkprobe(bridge=below)), settings
    )
    assert len(findings) == 1
    assert findings[0].name == "php-eol"
    assert findings[0].risk == "medium"
    assert "8.8 is past active support" in findings[0].fix


def test_php_version_degrades():
    # probe None / no bridge capability / bridge down / non-dict payload
    assert check_security_php_version(sec_data(), DEFAULTS) == []
    assert check_security_php_version(sec_data(probe=mkprobe()), DEFAULTS) == []
    down = FakeBridge([BridgeError("bridge down")])
    assert check_security_php_version(
        sec_data(probe=mkprobe(bridge=down)), DEFAULTS
    ) == []
    malformed = FakeBridge(["not-a-dict"])
    assert check_security_php_version(
        sec_data(probe=mkprobe(bridge=malformed)), DEFAULTS
    ) == []


# ---------------------------------------------------- registry integration


FTP_ONLY = [
    "security.author_scan", "security.cert_mismatch", "security.debug_log",
    "security.disallow_file_edit", "security.https_redirect",
    "security.php_version", "security.relocate", "security.rest_users",
    "security.uploads_listing", "security.uploads_perms",
    "security.wp_config_perms", "security.www_apex", "security.xmlrpc",
]


def test_registry_thirteen_names_ftp_only():
    # security.suspicious and security.web_exposed_script (both ftp+local)
    # ride the same "security" group: the selector yields the THIRTEEN
    # ftp-only probes PLUS those three, in name order.
    checks = {rec.name: rec for rec in all_checks()}
    for name in FTP_ONLY:
        assert name in checks, name
        assert checks[name].applies == ("ftp",), name
    expected = sorted([
        *FTP_ONLY, "security.source_patterns", "security.suspicious",
        "security.web_exposed_script",
    ])
    assert [r.name for r in select_checks("ftp", ["security"], None)] == expected
    assert checks["security.web_exposed_script"].func is check_security_web_exposed_script
    # the individual functions are what the registry calls
    assert checks["security.xmlrpc"].func is check_security_xmlrpc
    assert checks["security.rest_users"].func is check_security_rest_users
    assert checks["security.author_scan"].func is check_security_author_scan
    assert checks["security.wp_config_perms"].func is check_security_wp_config_perms
    assert checks["security.disallow_file_edit"].func is check_security_disallow_file_edit
    assert checks["security.https_redirect"].func is check_security_https_redirect
    assert checks["security.www_apex"].func is check_security_www_apex
    assert checks["security.cert_mismatch"].func is check_security_cert_mismatch
    assert checks["security.uploads_listing"].func is check_security_uploads_listing
    assert checks["security.debug_log"].func is check_security_debug_log
    assert checks["security.php_version"].func is check_security_php_version
    assert checks["security.relocate"].func is check_security_relocate


def test_local_mode_never_selects():
    # The thirteen ftp-only probes never select locally; the three
    # tree-based checks (security.source_patterns, security.suspicious,
    # security.web_exposed_script) are the deliberate exceptions — all
    # read the walked file, so an offline zip can answer them.
    assert [r.name for r in select_checks("local", ["security"], None)] == [
        "security.source_patterns", "security.suspicious",
        "security.web_exposed_script",
    ]
    assert all(
        r.name in ("security.source_patterns", "security.suspicious",
                   "security.web_exposed_script")
        or not r.name.startswith("security.")
        for r in select_checks("local", None, None)
    )


def test_run_checks_end_to_end():
    # every URL shape the checks probe, routed order-independently; the
    # two bridge round-trips (cached info, then fileperms) in check order
    session = RouterSession([
        ("GET", "?author=1",
         Resp(301, headers={"Location": f"{SITE}/author/admin/"})),
        ("GET", "http://site.test", Resp(200, text="no redirect here")),
        ("GET", "/wp-json/wp/v2/users",
         FakeResponse(200, json.dumps([{"slug": "admin"}]))),
        ("GET", "wp-content/uploads/", Resp(403)),                      # silent
        ("GET", "https://www.site.test/", Resp(200, url="https://www.site.test/")),
        ("POST", "xmlrpc.php", FakeResponse(200, "<methodResponse>")),
    ])
    bridge = FakeBridge([
        info_payload(php_version="7.4.33"),       # security.php_version
        {"paths": {"wp-config.php": "0644"}},    # security.wp_config_perms
    ])
    probe = SiteProbe(
        session=session, site=SITE, bridge=bridge,
        source=src_with(**{"wp-config.php": b"<?php define('DB_NAME','x');"}),
        timeout_s=7,
    )
    d = sec_data(
        probe=probe,
        entries=[E("wp-content/debug.log", 5)],
        siteurl=None,  # cert check: unknown siteurl stays silent
    )
    findings = run_checks(d, DEFAULTS, "ftp", ["security"], None)
    assert [(f.category, f.name) for f in findings] == [
        ("security.author_scan", "author-scan"),
        ("security.debug_log", "debug-log"),
        ("security.disallow_file_edit", "disallow-file-edit"),
        ("security.https_redirect", "https-redirect"),
        ("security.php_version", "php-eol"),
        ("security.rest_users", "rest-users"),
        ("security.wp_config_perms", "wp-config-perms"),
        ("security.www_apex", "www-apex"),
        ("security.xmlrpc", "xmlrpc-enabled"),
    ]
    for f in findings:
        f.validate()
    # exactly two bridge round-trips, in check-name order (php_version's
    # cached info() runs before wp_config_perms' fileperms)
    assert bridge.calls == [
        ("info", {}),
        ("fileperms", {"paths": ["wp-config.php"]}),
    ]
    # local mode never runs a security check, probe or not
    assert run_checks(d, DEFAULTS, "local", ["security"], None) == []
    # a probe-less ftp run still reports the entries-based check only
    probeless = sec_data(entries=[E("wp-content/debug.log", 5)])
    assert [(f.category, f.name) for f in
            run_checks(probeless, DEFAULTS, "ftp", ["security"], None)] == [
        ("security.debug_log", "debug-log"),
    ]


# ------------------------------- security.web_exposed_script [D2 — the two
# web-reachable PHP probes a live production docroot carried: a prior
# session's own token-gated disk-usage scripts.  core.integrity already
# rated them HIGH as "added" files, but the fix text said nothing
# actionable and no wpt command removes a file from the webroot top level,
# so they stayed live until a human read the report.

#: The live probe shape, verbatim in substance: a token gate in front of a
#: home-directory walk.
DU_PROBE = (
    b"<?php\n"
    b"$token = $_GET['t'] ?? '';\n"
    b"if (!hash_equals('a1b2c3', (string) $token)) { http_response_code(404); exit; }\n"
    b"foreach (scandir('/home/acme/domains/site.test/public_html') as $entry) {\n"
    b"    echo $entry, \"\\n\";\n"
    b"}\n"
)

#: A live-shaped official top-level core file (the map member), carrying a
#: signature so the map exemption is what keeps it out of this check.
CRON_PHP = b"<?php\n// hash_equals( $_GET['x'] ) upstream\n"

#: The official map for the fixture site: the top-level core set only (the
#: digests are opaque — nothing here hashes them).
CORE_MAP = {
    "index.php": "1" * 32,
    "wp-cron.php": "2" * 32,
    "wp-load.php": "3" * 32,
    "wp-login.php": "4" * 32,
    "xmlrpc.php": "5" * 32,
    "wp-includes/version.php": "6" * 32,
}


def _web_script_data(files, *, version="7.1", routes=(), mode="ftp",
                     site=SITE, checksums=CORE_MAP):
    """A hand-built AuditData + the probe that answers both the wp.org map
    request and the site's own (routes are (method, url-fragment, item)).

    ``version=None`` and ``checksums=None`` model the unavailable-map
    shapes; with neither, an unscripted request FAILS the test, so every
    request the check makes is asserted by construction.
    """
    source = FakeSource()
    source.files.update(files)
    script = []
    if checksums is not None:
        script.append((
            "GET", "api.wordpress.org",
            FakeResponse(200, json.dumps({"checksums": checksums})),
        ))
    script.extend(routes)
    d = sec_data(mode=mode, siteurl=site)
    d.wp_version = version
    d.source = source
    d.probe = SiteProbe(
        session=RouterSession(script), site=site, bridge=None,
        source=source, timeout_s=7,
    )
    return d


def test_web_exposed_script_token_gated_probe_is_high():
    """The live shape: a top-level .php that is not an official core file,
    not a known plugin artifact and not any registered unit, gating on a
    request parameter and walking a home directory.  HIGH, one finding for
    the file (not one per signature), carrying the matched signatures, the
    file's own date and the read-only triage + removal commands."""
    d = _web_script_data(
        {
            "du.php": DU_PROBE,
            "wp-config.php": b"<?php // config, no probes here",
            "wp-content/plugins/real/real.php": b"<?php /* plugin */",
        },
        routes=[("HEAD", "du.php",
                 Resp(200, headers={"Last-Modified":
                                    "Sat, 20 Sep 2026 14:02:11 GMT"}))],
    )
    d.entries = [E("du.php", len(DU_PROBE)),
                 E("wp-config.php", 30),
                 E("wp-content", is_dir=True),
                 E("wp-content/plugins", is_dir=True),
                 E("wp-content/plugins/real", is_dir=True),
                 E("wp-content/plugins/real/real.php", 20)]
    (f,) = check_security_web_exposed_script(d, DEFAULTS)
    assert (f.category, f.name, f.risk, f.count, f.bytes) == (
        "security.web_exposed_script", "du.php", "high", 1, len(DU_PROBE),
    )
    assert "hash_equals( (a constant-time token compare)" in f.detail
    assert "$_GET[ (a GET request parameter)" in f.detail
    assert "scandir( (a directory listing call)" in f.detail
    assert "/home/ (an absolute home-directory path)" in f.detail
    assert f.detail.endswith("; dated 2026-09-20 14:02 UTC")
    assert f.fix == security.WEB_SCRIPT_TRIAGE
    for command in ("head -c 400", r"grep -nE 'token|hash_equals|"
                    r"\$_(GET|POST|REQUEST|COOKIE)'", "stat -c %y",
                    "rm <file>"):
        assert command in f.fix
    assert ("A file you deployed deliberately is not a finding to delete "
            "\u2014 a dated one you cannot account for is an incident") in f.fix
    f.validate()
    # the file is DATED with a HEAD, never a GET: a GET would EXECUTE the
    # very file under investigation on a production site.  The one GET is
    # the wp.org map (the exemption basis), on the integrity seam's URL.
    assert [(method, url) for method, url, _kw in d.probe.session.calls] == [
        ("GET", "https://api.wordpress.org/core/checksums/1.0/?version=7.1"
                "&locale=en_US"),
        ("HEAD", f"{SITE}/du.php"),
    ]


def test_R18_web_exposed_script_reads_under_the_web_script_byte_bound():
    """R18-P2: the candidate read had no ``max_bytes`` at the read itself,
    so a lying listing could materialize an unbounded body."""
    from wpt.audit.security import web_script_max_bytes

    class Recording(FakeSource):
        def __init__(self) -> None:
            super().__init__()
            self.bounds: list[int | None] = []

        def read_many(self, paths, *, max_bytes=None):
            self.bounds.append(max_bytes)
            return super().read_many(paths, max_bytes=max_bytes)

    d = _web_script_data({"du.php": DU_PROBE},
                         routes=[("HEAD", "du.php", Resp(404))])
    recording = Recording()
    recording.files.update(d.source.files)
    d.source = recording
    d.entries = [E("du.php", len(DU_PROBE))]
    check_security_web_exposed_script(d, DEFAULTS)
    assert recording.bounds == [web_script_max_bytes(DEFAULTS)]


def test_web_exposed_script_plain_unknown_php_is_not_this_finding():
    """High precision is the whole point: a top-level .php nobody
    recognises is NOT this finding on its own, and neither is a file with
    a signature that is NOT at the webroot top level (inside wp-content it
    is security.suspicious's / core.integrity's tree, with the plugin/theme
    context those checks need)."""
    d = _web_script_data({
        "hello.php": b"<?php\n// an operator's landing page\necho 'hi';\n",
        "wp-content/plugins/du/dropper.php": DU_PROBE,
        "tools/du.php": DU_PROBE,     # nested, not the docroot
    })
    d.entries = [
        E("hello.php", 40),
        E("tools", is_dir=True),
        E("tools/du.php", len(DU_PROBE)),
        E("wp-content", is_dir=True),
        E("wp-content/plugins", is_dir=True),
        E("wp-content/plugins/du", is_dir=True),
        E("wp-content/plugins/du/dropper.php", len(DU_PROBE)),
    ]
    assert check_security_web_exposed_script(d, DEFAULTS) == []


def test_web_exposed_script_leaves_core_and_known_files_to_their_owners():
    """The official top-level core set and a registered known-plugin
    artifact are NOT this check's business — each is already owned, and
    reporting them here would double-report one file in two categories.
    A TAMPERED core file (the dated one) stays core.integrity's finding,
    with heal-core behind it."""
    import wpt.audit.integrity as integrity

    adminer = b"<?php\n// adminer\nrequire __DIR__ . '/adminer.php';\n"
    d = _web_script_data({
        "wp-cron.php": CRON_PHP,          # map member, tampered bytes
        "index.php": b"<?php\n$_GET['x']; // official\n",
        "wp-config.php": b"<?php\n$_GET['t']; hash_equals('a', 'b');\n",
        "adminer.php": adminer,
    })
    d.entries = [E("wp-cron.php", len(CRON_PHP)),
                 E("index.php", 40),
                 E("wp-config.php", 60),
                 E("adminer.php", len(adminer))]
    settings = replace(
        DEFAULTS,
        core_integrity=replace(
            DEFAULTS.core_integrity,
            known_added=[{"name": "adminer.php", "marker": "adminer.php",
                          "max_bytes": 2048,
                          "note": "the operator's adminer drop-in"}],
        ),
    )
    assert check_security_web_exposed_script(d, settings) == []
    # ... while core.integrity still calls the tampered core file what it
    # is, from its own primitives (this check changed nothing there)
    files = {entry.path: entry for entry in d.entries}
    assert ("tampered", "wp-cron.php", len(CRON_PHP)) in \
        integrity.affected_files_local(
            d.source, files, CORE_MAP, None,
            junk_patterns=DEFAULTS.webroot_junk,
        )


def test_web_exposed_script_reuses_the_added_classification_without_duplicating_it():
    """The interaction with the "added" classification: the same file is
    evidence for BOTH findings, and each says it once — core.integrity
    owns the "this is not an official file" verdict (high, investigate),
    this check owns the actionable half (signatures, date, triage,
    removal).  Neither duplicates the other inside its own category."""
    import wpt.audit.integrity as integrity

    d = _web_script_data({"du.php": DU_PROBE},
                         routes=[("HEAD", "du.php", Resp(200))])
    d.entries = [E("du.php", len(DU_PROBE))]
    files = {entry.path: entry for entry in d.entries}
    assert integrity.added_files(files, CORE_MAP) == [
        ("added", "du.php", len(DU_PROBE)),
    ]
    (f,) = check_security_web_exposed_script(d, DEFAULTS)
    assert f.name == "du.php" and f.risk == "high"
    # one finding for the file, not one per matched signature
    assert len(check_security_web_exposed_script(d, DEFAULTS)) == 1


def test_web_exposed_script_without_a_map_reports_unproven_not_high(
    wpt_records,
):
    """[D2] A wp.org map that CANNOT BE FETCHED must never make this check
    assert something it cannot prove.  It used to warn "the official-core
    exemption cannot be applied" and then rate the candidate HIGH with the
    detail "not an official core file" and the backdoor triage text — so
    an offline run told the operator to triage stock core as an intruder
    (measured: a small share of ordinary core/plugin/theme PHP files carry one of
    these needles, and an offline run rated wp-login.php, wp-cron.php,
    wp-activate.php, xmlrpc.php and four more HIGH).  A finding that
    DISAPPEARS is not the answer either: the candidates are now reported
    under their own category at medium risk, with the basis named, and the
    fix removes nothing.  wp.org is UNREACHABLE here — no response came at
    all, which is the one condition that demotes [D1] and the only one."""
    d = _web_script_data({"du.php": DU_PROBE}, checksums=None,
                         routes=[*_WPORG_UNREACHABLE,
                                 ("HEAD", "du.php", Resp(200))])
    d.entries = [E("du.php", len(DU_PROBE))]
    (f,) = check_security_web_exposed_script(d, DEFAULTS)
    assert (f.category, f.name, f.risk) == (
        "security.web_exposed_script_unproven", "du.php", "medium",
    )
    assert f.fix == security.WEB_SCRIPT_UNPROVEN_TRIAGE
    assert "rm <file>" not in f.fix
    assert f.detail.startswith("UNPROVEN — NOT classified as a backdoor")
    assert "the official wp.org checksums for WP 7.1 (en_US) could not be " \
        "fetched" in f.detail
    assert "date unknown (no reachable site to date it)" in f.detail
    warnings = [r.getMessage() for r in wpt_records
                if r.name == "wpt.audit.security"
                and r.levelno >= logging.WARNING]
    assert any("the official-core comparison basis is UNAVAILABLE" in message
               for message in warnings)
    assert any("wp-login.php as a backdoor" in message
               for message in warnings)


#: THE ATTACK [D1]: a real request-parameter webshell (one request
#: superglobal, one constant-time token gate, one silenced exec) beside a
#: wp-includes/version.php whose ``$wp_version`` assignment the attacker
#: stripped — the ONE extra file it takes to switch the exemption off.
WEBSHELL = (
    b"<?php\n"
    b"$c = $_GET['c'] ?? '';\n"
    b"if (!hash_equals('a1b2c3', (string) $c)) { exit; }\n"
    b"@system($c);\n"
)

#: version.php with the version line removed — the file is still there and
#: still parses as PHP, so the gather reads it and finds no version.
TAMPERED_VERSION_PHP = (
    b"<?php\n"
    b"$wp_version = '';\n"
    b"$wp_db_version = 58975;\n"
    b"$required_php_version = '7.2.24';\n"
)


def _d1_data(**kwargs):
    """The attack fixture: webshell + tampered version.php, wp.org
    REACHABLE (its map route is scripted, so the demotion cannot be
    blamed on an offline run)."""
    d = _web_script_data(
        {
            "shell.php": WEBSHELL,
            "wp-includes/version.php": TAMPERED_VERSION_PHP,
        },
        routes=[("HEAD", "shell.php", Resp(404))],
        **kwargs,
    )
    d.entries = [
        E("shell.php", len(WEBSHELL)),
        E("wp-includes", is_dir=True),
        E("wp-includes/version.php", len(TAMPERED_VERSION_PHP)),
    ]
    return d


def test_web_exposed_script_a_tampered_version_php_cannot_demote_the_verdict(
    wpt_records,
):
    """[D1] A webshell must not be able to DEMOTE ITS OWN VERDICT by
    writing one more file.

    The defect: ``wp-includes/version.php`` is inside the webroot, so
    whoever wrote ``shell.php`` can strip ``$wp_version`` from it.  The
    exemption basis then came back "unavailable" and the shell moved from
    HIGH "not an official core file" + backdoor triage to MEDIUM "Do NOT
    triage or remove this file on this evidence" — a webshell whose
    removal the report talks the operator out of, bought with one extra
    write.  The two refusals are DISTINCT conditions and only one of them
    (wp.org could not be reached) is evidence that the comparison was
    impossible; an unreadable version.php is a fact about the WEBROOT,
    not about wp.org, and this run never asked wp.org anything.

    The verdict therefore stays HIGH, the fix stays the backdoor triage,
    and the detail carries the basis it actually has — including the
    positive evidence this run DOES have: the core's own statement of its
    version is present, readable and carries no version, so the core
    itself was altered."""
    d = _d1_data(version=None)
    (f,) = check_security_web_exposed_script(d, DEFAULTS)
    assert (f.category, f.name, f.risk, f.count, f.bytes) == (
        "security.web_exposed_script", "shell.php", "high", 1, len(WEBSHELL),
    )
    assert f.fix == security.WEB_SCRIPT_TRIAGE
    # the demotion is gone, and with it the "do not remove" instruction
    assert f.fix != security.WEB_SCRIPT_UNPROVEN_TRIAGE
    assert "Do NOT triage or remove" not in f.detail
    # the basis is named, and the claim the missing basis cannot support
    # ("not an official core file") is NOT made
    assert "official-core comparison was NOT completed" in f.detail
    assert "wp-includes/version.php" in f.detail
    assert "not an official core file" not in f.detail
    # the positive evidence the same run has: an altered core
    assert "carries no readable $wp_version assignment" in f.detail
    # and the file is still web-reachable, dated and fully described
    assert "hash_equals( (a constant-time token compare)" in f.detail
    assert "$_GET[ (a GET request parameter)" in f.detail
    assert f.detail.endswith(
        "before removing it; otherwise triage it as the finding says."
    )
    f.validate()
    # the core statement is read (two bounded reads of one small file),
    # the candidate is dated with a HEAD, and wp.org is never asked: there
    # is no version to ask for
    assert [(method, url) for method, url, _kw in d.probe.session.calls] == [
        ("HEAD", f"{SITE}/shell.php"),
    ]
    warnings = [r.getMessage() for r in wpt_records
                if r.name == "wpt.audit.security"
                and r.levelno >= logging.WARNING]
    assert any("the official-core comparison basis is INCOMPLETE" in message
               for message in warnings)
    assert any("carries no readable $wp_version assignment" in message
               for message in warnings)
    # ... and the report's next-step table is reachable again: the HIGH
    # category is the one it maps to a triage action
    from wpt.report import suggested_steps
    assert suggested_steps([f])


def test_web_exposed_script_an_unreadable_version_alone_never_demotes(
    wpt_records,
):
    """[D1] The other half of the rule: an unreadable version is not the
    offline condition even when NOTHING looks tampered.  A zip that simply
    does not carry ``wp-includes/version.php`` (a partial export, a
    rehearsal archive) says nothing about wp.org and nothing about the
    core, so it exempts nothing and lowers nothing: the candidate is HIGH,
    the detail names the incomplete basis, and it makes no altered-core
    claim it cannot support."""
    d = _web_script_data({"shell.php": WEBSHELL}, version=None,
                         routes=[("HEAD", "shell.php", Resp(404))])
    d.entries = [E("shell.php", len(WEBSHELL))]
    (f,) = check_security_web_exposed_script(d, DEFAULTS)
    assert (f.category, f.name, f.risk) == (
        "security.web_exposed_script", "shell.php", "high",
    )
    assert f.fix == security.WEB_SCRIPT_TRIAGE
    assert "not an official core file" not in f.detail
    assert "official-core comparison was NOT completed" in f.detail
    assert "may be an unreadable or absent file rather than an attacker's " \
        "edit" in f.detail
    assert "$wp_version assignment" not in f.detail
    # the two degraded bases are distinguishable in the report, and only
    # the wp.org one carries the "do not remove" instruction
    assert f.fix != security.WEB_SCRIPT_UNPROVEN_TRIAGE


def test_web_exposed_script_the_map_decides_whenever_it_applies(wpt_records):
    """[D1] With the map available the verdict is HIGH whatever produced
    the version — here the file is unreadable over the webroot while the
    run still learned the version, which is the state a bridge-reported
    version produces.  The map exempts the official core set, and a file
    the map does not list is HIGH: an incomplete basis never demotes, and
    a complete one never has to."""
    d = _web_script_data(
        {"shell.php": WEBSHELL, "wp-includes/version.php": b"<?php // gone"},
        version="7.1", checksums=CORE_MAP,
        routes=[("HEAD", "shell.php", Resp(404))],
    )
    d.entries = [
        E("shell.php", len(WEBSHELL)),
        E("wp-includes", is_dir=True),
        E("wp-includes/version.php", 15),
    ]
    (f,) = check_security_web_exposed_script(d, DEFAULTS)
    assert (f.category, f.name, f.risk) == (
        "security.web_exposed_script", "shell.php", "high",
    )
    # the map WAS consulted and did not list the shell: the detail can
    # therefore make the full claim again
    assert "not an official core file" in f.detail
    assert "NOT completed" not in f.detail


#: The review's fixture: EIGHT stock WordPress top-level files, each
#: carrying one signature, on a site wp.org could not be asked about.
#: Measured against a real webroot, the offline run rated every one of
#: them HIGH "not an official core file" with the backdoor triage — the
#: exact class of false positive this check could not afford.
STOCK_CORE_UNPROVEN = {
    "index.php": b"<?php\n// $_GET[ 'a' ]\n",
    "wp-activate.php": b"<?php\n// scandir( '/home/' )\n",
    "wp-blog-header.php": b"<?php\n// scandir( '/home/x' )\n",
    "wp-comments-post.php": b"<?php\n// php://input\n",
    "wp-cron.php": b"<?php\n// hash_equals( $_GET['x'] )\n",
    "wp-login.php": b"<?php\nif (isset($_POST['log'])) { $_GET['x'] = 1; }\n",
    "wp-settings.php": b"<?php\n// hash_equals( $_REQUEST['k'] )\n",
    "xmlrpc.php": b"<?php\n// phpinfo( )\n",
}

#: wp.org UNREACHABLE — the ONE condition that demotes a candidate to the
#: unproven class [D1], and it is a TRANSPORT fact: no response came at all.
#: Modelled as a raised ``requests`` exception, never as a status code,
#: because a status code is a response: a 503 (or a 500, a 302, an HTML
#: error page, an empty body) means wp.org SPOKE, and reading its answer as
#: a verdict about the site is the defect these tests pin — the request URL
#: carries the attacker-writable ``$wp_version`` verbatim, so the status is
#: something an attacker can choose (measured: 20 000 characters of version
#: string earn a live HTTP 400 from api.wordpress.org).
_WPORG_UNREACHABLE = [
    ("GET", "api.wordpress.org", requests.ConnectionError("offline")),
    ("GET", "api.wordpress.org", requests.ConnectionError("offline")),
]


def test_web_exposed_script_offline_never_calls_stock_core_a_backdoor():
    """[D2] THE MEASURED FALSE-POSITIVE SHAPE, as a regression test: the
    same eight files, the same bytes, the same signatures — and wp.org
    UNREACHABLE (the version reads fine, its answer for that version does
    not arrive: the one demoting condition [D1]).  Zero high findings,
    one clearly-labelled unproven finding per file under the unproven
    category, every one of them medium with a fix that removes nothing,
    and a detail that leads with the missing basis rather than the
    signatures.  Then the A/B half: with the official map available the
    very same tree is exempt from this check entirely (it is
    core.integrity's business) — the two verdicts are decided by the same
    basis, one fetch apart."""
    d = _web_script_data(STOCK_CORE_UNPROVEN, checksums=None,
                         routes=[*_WPORG_UNREACHABLE,
                                 ("HEAD", ".php", Resp(404))])
    d.entries = [E(name, len(blob)) for name, blob in STOCK_CORE_UNPROVEN.items()]
    findings = check_security_web_exposed_script(d, DEFAULTS)
    assert not [f for f in findings if f.risk == "high"]
    assert {f.name for f in findings} == set(STOCK_CORE_UNPROVEN)
    assert {f.category for f in findings} == {
        "security.web_exposed_script_unproven"}
    for f in findings:
        assert f.risk == "medium"
        assert f.detail.startswith("UNPROVEN — NOT classified as a backdoor")
        assert "cannot say whether" in f.detail
        # the known-core-named candidate is named as such, with the rate
        assert ("wp-login.php, wp-cron.php, wp-activate.php, xmlrpc.php"
                in f.detail)
        assert "a small share of ordinary core/plugin/theme PHP files" in f.detail
        assert f.fix == security.WEB_SCRIPT_UNPROVEN_TRIAGE
        f.validate()
    # the aggregate next-step table keys off the HIGH category only, so an
    # unproven run can never be handed the "triage, then rm it" action
    from wpt.report import suggested_steps
    assert suggested_steps(findings) == []

    # A/B: the identical tree WITH the map is not this check's business
    online = _web_script_data(STOCK_CORE_UNPROVEN, checksums=CORE_MAP
                              | {name: "0" * 32 for name in STOCK_CORE_UNPROVEN},
                              routes=[("HEAD", ".php", Resp(404))])
    online.entries = [E(name, len(blob))
                      for name, blob in STOCK_CORE_UNPROVEN.items()]
    assert check_security_web_exposed_script(online, DEFAULTS) == []


def test_R22_the_last_resort_streamed_body_is_capped_and_deadline_bound():
    """R22-P2: a streamed response with neither ``preload_prefix`` nor
    ``preload`` (a plain ``requests.Response``/embedder double) was read
    through ``.text`` whole, with no cap and no absolute deadline.  The
    shared fallback reads a bounded prefix and checks the instant."""
    import time

    class _Stream:
        def __init__(self, chunks):
            self.chunks = chunks
            self.body_truncated = False
            self._content = None
            self._content_consumed = False

        def iter_content(self, chunk_size=65536):
            yield from self.chunks

    response = _Stream([b"x" * 32])
    security._preload_bounded_text(
        response, 10, time.monotonic() + 5)
    assert response._content == b"x" * 10
    assert response.body_truncated is True

    with pytest.raises(requests.Timeout):
        security._preload_bounded_text(
            _Stream([b"x"]), 10, time.monotonic() - 1)


def test_R22_a_known_added_artifact_is_removed_by_path_not_by_identity(
        ):
    """R22-P2: the security candidate list is Entry objects while
    ``_split_known_added`` returns (kind, path, size) tuples, so
    ``entry not in unresolved`` was always true and a KNOWN artifact with a
    request gate was still reported HIGH.  The reduction is by path."""
    adminer = b"<?php\n// adminer.php\nif ($_GET['x']) { echo 1; }\n"
    d = _web_script_data({"adminer.php": adminer},
                         routes=[("HEAD", "adminer.php", Resp(404))])
    d.entries = [E("adminer.php", len(adminer))]
    settings = replace(
        DEFAULTS,
        core_integrity=replace(
            DEFAULTS.core_integrity,
            known_added=[{"name": "adminer.php", "marker": "adminer.php",
                          "max_bytes": 2048, "note": "operator drop-in"}],
        ),
    )
    assert check_security_web_exposed_script(d, settings) == []
    # the same bytes under another path are NOT covered by the signature
    other = _web_script_data(
        {"dup.php": adminer},
        routes=[("HEAD", "dup.php", Resp(404))])
    other.entries = [E("dup.php", len(adminer))]
    (finding,) = check_security_web_exposed_script(other, settings)
    assert finding.name == "dup.php" and finding.risk == "high"


def test_web_exposed_script_unproven_keeps_the_known_file_gates():
    """The degraded class is ONLY about the core map: the exemption wpt
    can still PROVE on its own — a registered known artifact, a
    known_added signature, a file below the read bound — still keeps a
    candidate out of both classes, so a degraded run is not a
    repeat of every gate."""
    d = _web_script_data(
        {
            "bridge-0a1b2c3d.php": b"<?php\nhash_equals( $_GET['t'] );\n",
            "adminer.php": (b"<?php\n// adminer.php\nrequire __DIR__ . "
                            b"'/adminer.php';\n"),
            "shell.php": b"<?php\n$_POST['c'];\n",
        },
        checksums=None,
        routes=[*_WPORG_UNREACHABLE,
                ("HEAD", "shell.php", Resp(404))],
    )
    d.entries = [E("bridge-0a1b2c3d.php", 30), E("adminer.php", 25),
                 E("shell.php", 20)]
    settings = replace(
        DEFAULTS,
        core_integrity=replace(
            DEFAULTS.core_integrity,
            known_added=[{"name": "adminer.php", "marker": "adminer.php",
                          "max_bytes": 2048, "note": "operator drop-in"}],
        ),
    )
    (f,) = check_security_web_exposed_script(d, settings)
    assert (f.name, f.risk) == ("shell.php", "medium")



def test_web_exposed_script_degrades_without_evidence(wpt_records):
    """Unknown never becomes a finding: no source (cannot read bytes), an
    unreadable file, a tree with no top-level .php at all, and an expired
    run budget (which warns instead of pretending to have scanned)."""
    d = _web_script_data({"du.php": DU_PROBE})
    d.entries = [E("du.php", len(DU_PROBE))]
    d.source = None
    assert check_security_web_exposed_script(d, DEFAULTS) == []

    d = _web_script_data({})                       # the file is unreadable
    d.entries = [E("du.php", len(DU_PROBE))]
    assert check_security_web_exposed_script(d, DEFAULTS) == []

    d = _web_script_data({"index.php": b"<?php"})
    d.entries = [E("index.php", 8), E("readme.html", 3)]
    assert check_security_web_exposed_script(d, DEFAULTS) == []

    from wpt.deadline import Deadline

    d = _web_script_data({"du.php": DU_PROBE})
    d.entries = [E("du.php", len(DU_PROBE))]
    d.deadline = Deadline(-1)
    assert check_security_web_exposed_script(d, DEFAULTS) == []
    warnings = [r.getMessage() for r in wpt_records
                if r.name == "wpt.audit.security"
                and r.levelno >= logging.WARNING]
    assert any("deadline already reached" in message for message in warnings)


def test_web_exposed_script_skips_a_file_above_the_read_bound(wpt_records):
    """The read bound is a scope limit, stated out loud: a token-gated
    probe or a dropper is a few KB, so only a pathologically large
    top-level .php is skipped — never silently."""
    d = _web_script_data({"huge.php": DU_PROBE + b"x" * 300_000})
    d.entries = [E("huge.php", 300_000 + len(DU_PROBE))]
    assert check_security_web_exposed_script(d, DEFAULTS) == []
    assert any("exceed the" in r.getMessage() for r in wpt_records
               if r.name == "wpt.audit.security")


def test_web_exposed_script_runs_in_local_mode_too(tmp_path):
    """Both modes: the evidence is a file, so an offline zip answers the
    same question (the date is the one thing only a live site can add)."""
    import zipfile

    import wpt.audit.integrity as integrity
    import wpt.audit.updates as updates

    # The local transport is a PLAIN session (the site is offline, wp.org
    # is not), so the official map is answered from a SEEDED cache entry —
    # no network in this suite.
    updates._CACHE_DIR.mkdir(parents=True, exist_ok=True)
    (updates._CACHE_DIR / (
        updates._cache_key(integrity._checksums_url("7.1"), None)
        + ".json"
    )).write_text(json.dumps({"checksums": CORE_MAP}), encoding="utf-8")

    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("wp-includes/version.php",
                    b"<?php $wp_version = '7.1';")
        zf.writestr("wp-cron.php", CRON_PHP)     # official: never this check
        zf.writestr("du.php", DU_PROBE)
    source = ZipSource(zpath)
    try:
        d = sec_data(mode="local", entries=list(source.walk()))
        d.source = source
        # the gatherer reads the version out of the zip's version.php; this
        # test builds AuditData by hand, so it does the same
        d.wp_version = _read_wp_version(source)
        findings = run_checks(
            d, DEFAULTS, "local", ["security.web_exposed_script"], None,
        )
    finally:
        source.close()
    assert [(f.category, f.name, f.risk) for f in findings] == [
        ("security.web_exposed_script", "du.php", "high"),
    ]
    # an offline zip carries no clock and there is no live site to ask
    assert "date unknown (no reachable site to date it)" in findings[0].detail


def test_last_modified_falls_back_to_unknown():
    """The date enrichment is additive: an error status, an absent or
    unparseable header, a network failure, no probe and an empty site URL
    all answer None, which the finding renders as "date unknown"."""
    probe = SiteProbe(session=HeadSession([]), site="https://site.test",
                      timeout_s=7)
    assert security.last_modified(None, "du.php") is None
    assert security.last_modified(probe, "") is None
    none_site = SiteProbe(session=HeadSession([]), site="", timeout_s=7)
    assert security.last_modified(none_site, "du.php") is None

    cases = [
        Resp(404),
        Resp(200, headers={}),
        Resp(200, headers={"Last-Modified": "not a date"}),
        requests.ConnectionError("down"),
    ]
    for item in cases:
        scripted = SiteProbe(
            session=HeadSession([item]), site="https://site.test", timeout_s=7,
        )
        assert security.last_modified(scripted, "du.php") is None

    dated = SiteProbe(
        session=HeadSession([Resp(200, headers={
            "Last-Modified": "Sat, 20 Sep 2026 14:02:11 GMT"})]),
        site="https://site.test", timeout_s=7,
    )
    assert security.last_modified(dated, "du.php") == "2026-09-20 14:02 UTC"


def test_R17_last_modified_head_is_bounded_by_the_run_deadline():
    """R17-6-P2: the date enrichment called ``probe.head`` directly, so a
    slow HEAD outlived the scan budget.  It now rides the shared bounded
    single-probe owner and answers None at the deadline."""
    from wpt.deadline import Deadline

    class _SlowHead(HeadSession):
        def head(self, url, **kwargs):
            time.sleep(0.25)
            return Resp(200, headers={
                "Last-Modified": "Sat, 20 Sep 2026 14:02:11 GMT"})

    probe = SiteProbe(session=_SlowHead([]), site="https://site.test",
                      timeout_s=7)
    started = time.monotonic()
    assert security.last_modified(
        probe, "du.php", deadline=Deadline(0.05)) is None
    assert time.monotonic() - started < 0.2


def test_R17_web_exposed_script_checks_the_deadline_every_candidate(
        monkeypatch):
    """R17-6-P2: the deadline was checked only after a signature MATCH, so
    non-matching candidates kept scanning past the budget (20 x 30 ms ran
    0.61 s under a 0.05 s deadline)."""
    import wpt.audit.security as security_mod
    from wpt.deadline import Deadline

    files = {f"p{i}.php": b"<?php echo 1;\n" for i in range(20)}
    d = _web_script_data(files)
    d.entries = [E(name, len(data)) for name, data in files.items()]
    calls = []

    def _slow_scan(blob, settings):
        calls.append(blob)
        time.sleep(0.06)
        return [], ""

    monkeypatch.setattr(security_mod, "_scan_views", _slow_scan)
    d.deadline = Deadline(0.05)
    started = time.monotonic()
    assert check_security_web_exposed_script(d, DEFAULTS) == []
    assert time.monotonic() - started < 0.5
    assert len(calls) == 1


def test_web_exposed_script_reads_its_signatures_from_the_profile():
    """[L34] the needles + read bound come from settings.web_script; a
    bare Settings() still scans through the structural fallback."""
    from wpt.audit.security import (_WEB_SCRIPT_MAX_BYTES,
                                    _WEB_SCRIPT_SIGNATURES,
                                    _matched_signatures, web_script_max_bytes,
                                    web_script_signatures)

    text = "<?php hash_equals('x', $_GET['t']); scandir('/home/u');"
    assert _matched_signatures(text, None) == [
        f"{n} ({note})" for n, note in _WEB_SCRIPT_SIGNATURES if n in text]
    base = load()
    custom = replace(base, web_script=replace(
        base.web_script,
        signatures=[{"name": "scandir(", "note": "custom needle"}],
        request_globals=[],
        max_bytes=1234))
    assert _matched_signatures(text, custom) == ["scandir( (custom needle)"]
    assert web_script_max_bytes(custom) == 1234
    assert web_script_max_bytes(None) == _WEB_SCRIPT_MAX_BYTES
    assert web_script_signatures(None) == list(_WEB_SCRIPT_SIGNATURES)


def test_web_exposed_script_empty_signature_list_scans_nothing(wpt_records):
    """D3: an EMPTY web_script.signatures means SCAN NOTHING, and the
    profile says so.  The old truthiness fallback handed an emptied list
    the six module needles while ``to_diff`` reported the section as
    empty — the effective behaviour was not describable from the profile,
    and a webshell carrying a needle was silently 'not configured'."""
    from dataclasses import replace as _replace
    from wpt.audit.security import (_matched_signatures,
                                    web_script_signatures)
    from wpt.settings import to_diff

    base = load()
    emptied = _replace(base, web_script=_replace(base.web_script,
                                                signatures=[]))
    # the report of the change is the TRUTH about what is scanned
    assert to_diff(emptied)["web_script"] == {"signatures": []}
    assert web_script_signatures(emptied) == []
    # ... and the check really scans nothing, on a real DU_PROBE candidate
    assert _matched_signatures(DU_PROBE.decode(), emptied) == []
    assert _matched_signatures(
        "<?php system($_POST['c']);", emptied) == []   # the family too
    d = _web_script_data({"du.php": DU_PROBE})
    d.entries = [E("du.php", len(DU_PROBE))]
    assert check_security_web_exposed_script(d, emptied) == []
    # a bare Settings() (no profile loaded) still scans the shipped set
    assert web_script_signatures(Settings()) == \
        list(security._WEB_SCRIPT_SIGNATURES)
    bare = _web_script_data({"du.php": DU_PROBE},
                            routes=[("HEAD", "du.php", Resp(200))])
    bare.entries = [E("du.php", len(DU_PROBE))]
    assert [f.name for f in
            check_security_web_exposed_script(bare, Settings())] == ["du.php"]


# --------------------------- the evasions the substring scan lost to [D1]
# An adversarial review reproduced five ways a webshell walks straight
# through a plain-substring, .php-only scan.  Every one of them is a real
# file in the webroot top level, so every one of them must be HIGH.


#: (label, bytes, the signature line the finding must name).  The first
#: three are "the same request-parameter gate, a different spelling"; the
#: fourth is one space between the superglobal and its subscript.
EVASIONS = [
    ("post", b"<?php\nif (isset($_POST['c'])) { system($_POST['c']); }\n",
     "$_POST[ (a POST request parameter)"),
    ("request", b"<?php\n$cmd = $_REQUEST ['cmd'] ?? '';\n",
     "$_REQUEST[ (a merged request parameter)"),
    ("php-input", b"<?php\n$c = file_get_contents('php://input');\n",
     "php://input (the raw request-body stream)"),
    ("get-space", b"<?php\n$t = $_GET ['t'] ?? '';\n",
     "$_GET[ (a GET request parameter)"),
    ("cookie", b"<?php\nif ($_COOKIE[\"x\"]) { echo 1; }\n",
     "$_COOKIE[ (a request cookie)"),
]


@pytest.mark.parametrize("label,payload,expected", EVASIONS,
                         ids=[case[0] for case in EVASIONS])
def test_web_exposed_script_catches_every_request_parameter_evasion(
        label, payload, expected):
    d = _web_script_data({"shell.php": payload},
                         routes=[("HEAD", "shell.php", Resp(200))])
    d.entries = [E("shell.php", len(payload))]
    (f,) = check_security_web_exposed_script(d, DEFAULTS)
    assert (f.name, f.risk, f.count) == ("shell.php", "high", 1)
    assert expected in f.detail, f.detail
    assert f.fix == security.WEB_SCRIPT_TRIAGE


#: The classic eval+base64 webshell body, and the gzip+base64 shape the
#: review used.  Both are plain ASCII base64, so the RAW views carry no
#: needle at all: only the decoded view can see the payload.
WEBSHELL_BODY = b"<?php @eval(base64_decode($_POST['c'])); system('id');"


def _b64_gzip(blob: bytes) -> bytes:
    import base64 as _b64
    import gzip as _gzip
    return _b64.b64encode(_gzip.compress(blob, mtime=0))


def test_web_exposed_script_scans_every_php_executable_extension():
    """``shell.phtml`` / ``shell.phar`` / ``shell.PHP`` are as
    web-reachable as ``shell.php`` on a host whose handler config maps
    them, and a candidate filter of ``endswith('.php')`` never considered
    them.  The finding names the suffix that made the file executable."""
    files = {name: DU_PROBE for name in
             ("shell.phtml", "shell.phar", "shell.PHP", "shell.inc",
              "shell.php5", "shell.php7", "shell.phps", "shell.module")}
    d = _web_script_data(files, routes=[("HEAD", "shell.", Resp(200))])
    d.entries = [E(name, len(DU_PROBE)) for name in files]
    findings = check_security_web_exposed_script(d, DEFAULTS)
    assert {f.name for f in findings} == set(files)
    assert all(f.risk == "high" for f in findings)
    for f in findings:
        suffix = f.name[f.name.index("."):].lower()
        assert f.detail.startswith(
            f"a top-level {suffix} file that is not an official core file")
    # a top-level file that is NOT in the executable set is never a
    # candidate, however web-reachable its bytes are
    d = _web_script_data({"shell.txt": DU_PROBE, "shell": DU_PROBE})
    d.entries = [E("shell.txt", len(DU_PROBE)), E("shell", len(DU_PROBE))]
    assert check_security_web_exposed_script(d, DEFAULTS) == []


def test_web_exposed_script_reads_a_utf16_webshell():
    """A webshell saved as UTF-16LE (BOM + NUL between the ASCII bytes)
    is executed by PHP exactly like a UTF-8 one, and is invisible to a
    UTF-8 read: every needle is split by a NUL.  The transcode view is
    what catches it."""
    payload = "<?php\nif (!hash_equals('k', (string) $_GET['t'])) exit;\n"
    blob = b"\xff\xfe" + payload.encode("utf-16-le")
    # the shape that would defeat a UTF-8-only scan, proven here
    assert b"hash_equals(" not in blob and b"$_GET[" not in blob
    d = _web_script_data({"shell.php": blob},
                         routes=[("HEAD", "shell.php", Resp(200))])
    d.entries = [E("shell.php", len(blob))]
    (f,) = check_security_web_exposed_script(d, DEFAULTS)
    assert f.risk == "high"
    assert "hash_equals( (a constant-time token compare)" in f.detail
    # a UTF-16 payload with no signature stays silent (the transcode view
    # proves the file is clean, it does not manufacture a finding)
    clean = b"\xff\xfe" + "<?php echo 'hi';\n".encode("utf-16-le")
    d = _web_script_data({"hello.php": clean})
    d.entries = [E("hello.php", len(clean))]
    assert check_security_web_exposed_script(d, DEFAULTS) == []


def test_web_exposed_script_reports_an_encoded_payload():
    """A payload the file only carries ENCODED earns its own report line,
    and only when decoding it finds a signature: base64-looking content
    is not itself evidence, so a file whose base64 decodes to a config
    array must stay silent (decoding arbitrary content would flag every
    encoded asset in a webroot)."""
    from wpt.audit.security import _scan_views

    blob = _b64_gzip(WEBSHELL_BODY)
    matched, note = _scan_views(blob, DEFAULTS)
    assert "$_POST[ (a POST request parameter)" in matched
    assert note is not None and note.startswith(
        "encoded-payload (base64/gzip): the decoded bytes carry ")
    d = _web_script_data({"shell.php": blob},
                         routes=[("HEAD", "shell.php", Resp(200))])
    d.entries = [E("shell.php", len(blob))]
    (f,) = check_security_web_exposed_script(d, DEFAULTS)
    assert f.risk == "high" and f.name == "shell.php"
    assert "; encoded-payload (base64/gzip): the decoded bytes carry " in \
        f.detail
    # the classic eval(base64_decode('...')) shape: the blob is the file's
    # dominant content, so it decodes too
    import base64 as _b64
    inner = _b64.b64encode(
        b"@system($_GET['c']); passthru('id');").decode()
    classic = f"<?php @eval(base64_decode('{inner}'));".encode()
    matched, note = _scan_views(classic, DEFAULTS)
    assert matched and "encoded-payload" in note
    # a file whose PLAIN view already matches still reports the hidden
    # stage: the operator is told there is a second payload behind it
    inner2 = _b64.b64encode(
        b"system($_REQUEST['c']); passthru('id');").decode()
    gated = f"<?php if ($_GET['c']) {{ eval(base64_decode('{inner2}')); }}".encode()
    matched, note = _scan_views(gated, DEFAULTS)
    assert matched == ["$_GET[ (a GET request parameter)"]
    assert note is not None and note.startswith("encoded-payload")
    # an encoded file that decodes to nothing signed: silent
    benign = _b64_gzip(b'{"theme":"Twenty Twenty","plugins":[]}')
    assert _scan_views(benign, DEFAULTS) == ([], None)
    # a short base64 run is never decoded (a hash, not a payload)
    assert _scan_views(b'<?php // ' + b"A" * 40 + b"\n", DEFAULTS) == ([], None)


def test_web_exposed_script_exempts_wpts_own_bridge_artifact():
    """wpt's own bridge is EXACTLY this check's shape — the real bridge.php
    carries the token gate, ``$_GET[`` and ``scandir(`` this check hunts —
    and ``Bridge.destroy()`` is best-effort, so a leftover copy must not
    read as a HIGH backdoor on every run that could not delete it.  The
    real file's own bytes are used, not a paraphrase."""
    import pathlib

    import wpt.wpbridge as wpbridge
    bridge = (pathlib.Path(wpbridge.__file__).parent / "bridge.php").read_bytes()
    # the premise: without the exemption this IS a finding
    assert b"hash_equals(" in bridge and b"$_GET[" in bridge
    name = "bridge-0a1b2c3d.php"
    d = _web_script_data({name: bridge})
    d.entries = [E(name, len(bridge))]
    assert check_security_web_exposed_script(d, DEFAULTS) == []
    # an artifact an operator did NOT register stays a finding (the
    # exemption is a registered list, never a name-shape guess)
    other = "shell-bridge0a1b2c3d.php"
    d = _web_script_data({other: bridge},
                         routes=[("HEAD", "shell-bridge", Resp(200))])
    d.entries = [E(other, len(bridge))]
    (f,) = check_security_web_exposed_script(d, DEFAULTS)
    assert f.name == other and f.risk == "high"


def test_web_exposed_script_exempts_only_the_bridge_hex_name():
    """[D3] The exemption must cover the tool's OWN artifact name and
    nothing else.  It shipped ``bridge-*.php`` in a public repository —
    a pattern an attacker can simply adopt, on the very check that exists
    to catch droppers: ``bridge-shell.php`` was "wpt residue" and was
    never reported.  The shipped pattern now spells the eight hex
    characters out, and the matcher is HEX-STRICT (a ``?`` is one hex
    digit, either case, never "any character"), so only the name wpt
    itself deploys is exempt."""
    import pathlib

    import wpt.wpbridge as wpbridge
    bridge = (pathlib.Path(wpbridge.__file__).parent / "bridge.php").read_bytes()
    shipped = security.web_script_known_artifacts(DEFAULTS)
    assert [name for name, _note in shipped] == [
        "bridge-????????.php", "wpt-probe-????????.php"]

    # wpt's own name shapes — every case, uppercase hex included — are exempt
    for name in ("bridge-0a1b2c3d.php", "bridge-00000000.php",
                 "bridge-abcdef01.php", "bridge-AB12CD34.php",
                 "wpt-probe-0a1b2c3d.php", "wpt-probe-00000000.php",
                 "wpt-probe-abcdef01.php", "wpt-probe-AB12CD34.php"):
        d = _web_script_data({name: bridge})
        d.entries = [E(name, len(bridge))]
        assert check_security_web_exposed_script(d, DEFAULTS) == [], name

    # an attacker's name in the same shape is NOT: no hex in those
    # positions, and every one of these files carries the real bridge
    # bytes (the token gate, $_GET[, scandir()
    for name in ("bridge-shell.php", "bridge-.php", "bridge-shellab.php",
                 "bridge-0a1b2c3.php", "bridge-0a1b2c3ddd.php",
                 "bridge-shellab1.php", "wpt-probe-shell.php",
                 "wpt-probe-.php", "wpt-probe-0a1b2c3.php",
                 "wpt-probe-0a1b2c3ddd.php"):
        d = _web_script_data(
            {name: bridge},
            routes=[
                ("HEAD", "bridge-", Resp(200, headers={
                    "Last-Modified": "Sat, 20 Sep 2026 14:02:11 GMT"})),
                ("HEAD", "wpt-probe", Resp(200, headers={
                    "Last-Modified": "Sat, 20 Sep 2026 14:02:11 GMT"})),
            ],
        )
        d.entries = [E(name, len(bridge))]
        (f,) = check_security_web_exposed_script(d, DEFAULTS)
        assert (f.name, f.risk) == (name, "high"), name
        assert f.fix == security.WEB_SCRIPT_TRIAGE

    # ... and the shipped pattern is never wider than the name wpt itself
    # deploys (wpt/bridge_name.BRIDGE_NAME_RE, the exact-name owner)
    from wpt.bridge_name import BRIDGE_NAME_RE as _BRIDGE_NAME_RE
    from wpt.audit.security import _is_known_artifact

    for name in ("bridge-0a1b2c3d.php", "bridge-ffffffff.php"):
        assert _BRIDGE_NAME_RE.match(name)
        assert _is_known_artifact(name, shipped)
    for name in ("wpt-probe-0a1b2c3d.php", "wpt-probe-ffffffff.php"):
        assert _is_known_artifact(name, shipped)
    for name in ("bridge-shell.php", "bridge-.php", "bridge-notours.php",
                 "bridge-1234567.php", "shell.php",
                 "wpt-probe-shell.php", "wpt-probe-1234567.php"):
        assert not _BRIDGE_NAME_RE.match(name)
        assert not _is_known_artifact(name, shipped)


def test_web_script_profile_dataclass_and_module_agree():
    """One owner, three views: the shipped profile file, the
    ``WebScriptSettings`` dataclass default a bare ``Settings()`` carries,
    and the module fallback a settings-less call uses must be the SAME
    values, or the effective behaviour is not describable from the profile.
    ``to_diff(load())`` being empty is the profile half of the same pin."""
    import json
    import pathlib

    import wpt.settings as st
    from wpt.audit.security import (_WEB_SCRIPT_EXTENSIONS,
                                    _WEB_SCRIPT_REQUEST_GLOBALS,
                                    _WEB_SCRIPT_SIGNATURES,
                                    web_script_extensions,
                                    web_script_request_globals)

    shipped = st.load()
    assert st.to_diff(shipped) == {}
    raw = json.loads(
        pathlib.Path(st._DEFAULT_PROFILE).read_text(encoding="utf-8"))
    section = raw["web_script"]
    assert [dict(e) for e in shipped.web_script.signatures] == \
        section["signatures"] == [
            {"name": n, "note": note} for n, note in _WEB_SCRIPT_SIGNATURES]
    assert [dict(e) for e in shipped.web_script.request_globals] == \
        section["request_globals"] == [
            {"name": n, "note": note}
            for n, note in _WEB_SCRIPT_REQUEST_GLOBALS]
    assert security.web_script_request_globals(Settings()) == \
        list(_WEB_SCRIPT_REQUEST_GLOBALS)
    assert [dict(e) for e in shipped.web_script.known_artifacts] == \
        section["known_artifacts"] == [
            {"name": n, "note": note}
            for n, note in st.WEB_SCRIPT_KNOWN_ARTIFACTS]
    assert shipped.web_script.extensions == section["extensions"] == \
        list(_WEB_SCRIPT_EXTENSIONS)
    # the shipped executable set is the documented common superset
    assert set(_WEB_SCRIPT_EXTENSIONS) == {
        ".php", ".phtml", ".php5", ".php7", ".phps", ".phar", ".inc",
        ".module"}
    # the resolvers answer the same from a profile and from nothing
    assert web_script_extensions(shipped) == web_script_extensions(None) == \
        _WEB_SCRIPT_EXTENSIONS
    assert web_script_request_globals(shipped) == \
        web_script_request_globals(None) == list(_WEB_SCRIPT_REQUEST_GLOBALS)
    # a bare Settings() carries them (not the empty-list default)
    assert web_script_extensions(Settings()) == _WEB_SCRIPT_EXTENSIONS
    assert web_script_request_globals(Settings()) == \
        list(_WEB_SCRIPT_REQUEST_GLOBALS)
    # wpt's own bridge residue is registered by default
    assert security.web_script_known_artifacts(shipped) == [
        (name, note) for name, note in st.WEB_SCRIPT_KNOWN_ARTIFACTS]


# ------------------------------------- the served-path probe's 200 trust
# D2: a host with a soft 404 answers 200 + a "not found" page for every
# missing path, and a check that trusted the status put a false
# disclosure inside a HIGH fix text.


def _served_paths_session(answers):
    session = FakeSession(list(answers))
    probe = SiteProbe(session=session, site="https://site.test", timeout_s=7)
    return session, probe


def test_publicly_served_paths_distrusts_a_soft_404():
    # A host that answers 200 + a bot-challenge / "not found" page for
    # EVERYTHING (an SEO plugin, a caching layer, a WAF): the candidate's
    # body IS the answer for a certainly-missing path, so it is not served
    # and nothing is claimed.
    CHALLENGE = "<html>Checking your browser before accessing</html>"
    session, probe = _served_paths_session([
        FakeResponse(200, CHALLENGE), FakeResponse(200, CHALLENGE),
    ])
    assert security.publicly_served_paths(probe, ["error_log"]) == []
    # ... and the baseline is asked for ONCE, under a fresh unguessable name
    assert len(session.gets) == 2
    assert session.gets[1][0].startswith("https://site.test/wpt-probe-")
    assert session.gets[1][0].endswith(".php")
    # two candidates, one baseline: the probe is never repeated.  The
    # SECOND candidate carries the not-found body, so only the first — a
    # real file behind a soft-404 host — is public.
    session, probe = _served_paths_session([
        FakeResponse(200, "log bytes"), FakeResponse(200, CHALLENGE),
        FakeResponse(200, CHALLENGE),
    ])
    assert security.publicly_served_paths(
        probe, ["error_log", "blocked.log"]) == ["error_log"]
    assert len(session.gets) == 3


def test_publicly_served_paths_claims_a_real_200():
    # a host that answers a REAL 404 for a missing path distinguishes
    # missing files, so the 200 is the file itself
    session, probe = _served_paths_session([
        FakeResponse(200, "log bytes"), FakeResponse(404),
    ])
    assert security.publicly_served_paths(probe, ["error_log"]) == \
        ["error_log"]
    # a 200 whose body DIFFERS from the not-found page is served too (the
    # comparison is the body, never the status alone)
    session, probe = _served_paths_session([
        FakeResponse(200, "the log"), FakeResponse(200, "<html>404</html>"),
    ])
    assert security.publicly_served_paths(probe, ["error_log"]) == \
        ["error_log"]
    # the baseline itself is unfetchable (network failure) => no soft-404
    # page was observed, so the 200 stands (and the site is up: the
    # candidate answered)
    session, probe = _served_paths_session([
        FakeResponse(200, "log bytes"),
        requests.ConnectionError("down"),
    ])
    assert security.publicly_served_paths(probe, ["error_log"]) == \
        ["error_log"]


def test_publicly_served_paths_quotes_the_request_path():
    """A junk name can carry a space or a ``#``: an unescaped request asks
    the server for a DIFFERENT URL than the file the tree holds, so the
    measured answer was about the wrong resource.  The path is
    percent-escaped (``safe='/'`` keeps the directory structure)."""
    session, probe = _served_paths_session([
        FakeResponse(200, "log bytes"), FakeResponse(404),
    ])
    assert security.publicly_served_paths(
        probe, ["my site/error log#1.txt"]) == ["my site/error log#1.txt"]
    assert session.gets[0][0] == \
        "https://site.test/my%20site/error%20log%231.txt"
    # the CLAIM (asserted above) keeps the tree's own spelling, never the
    # escaped URL: the fix text names the path the operator must act on


def test_publicly_served_paths_stays_silent_offline():
    """Local mode (an offline zip) has no live site: no request at all,
    so the fix text renders byte-identically to a run without a probe."""
    session = FakeSession([])
    assert security.publicly_served_paths(None, ["error_log"]) == []
    empty_site = SiteProbe(session=session, site="", timeout_s=7)
    assert security.publicly_served_paths(empty_site, ["error_log"]) == []
    assert session.gets == []
    # an expired run budget asks nothing, and the baseline is never
    # requested after it either
    from wpt.deadline import Deadline

    session, probe = _served_paths_session([FakeResponse(200, "log")])
    assert security.publicly_served_paths(
        probe, ["error_log"], Deadline(-1)) == []
    assert session.gets == []


# --------------------------------------------------------------------------
# [B] "wp.org says this build does not exist" is NOT "wp.org could not
# answer" — the webshell that demoted itself with ONE write
#
# The demotion used to be driven by "the map fetch returned None", and
# the map fetch answers None for TWO unrelated things: a transport that
# never reached wp.org, and a live API that ANSWERED that the build does
# not exist (measured: HTTP 200 ``{"checksums": false}`` for a version
# that was never released).  The second is not an outage at all — it is
# positive evidence that the version string does not correspond to a real
# release, and the version string lives in ``wp-includes/version.php``,
# the ONE file the attacker already wrote.  So one extra write beside the
# shell moved a definite HIGH webshell into the MEDIUM "Do NOT triage or
# remove this file on this evidence" class.
# --------------------------------------------------------------------------

#: version.php READABLE and carrying a version that was never released —
#: the whole attack, and the smallest possible one: the file is intact,
#: the gather reads the version from it, and the version is a lie.
GHOST_VERSION_PHP = (
    b"<?php\n"
    b"$wp_version = '9.9.9';\n"
    b"$wp_db_version = 58975;\n"
    b"$required_php_version = '7.2.24';\n"
)

#: What the live wp.org checksums API answers for a build that does not
#: exist: HTTP 200 and a payload that says so.  Not an error, not a 404.
NO_SUCH_BUILD = FakeResponse(200, json.dumps({"checksums": False}))


def test_web_exposed_script_a_version_wp_org_does_not_have_stays_high(
    wpt_records,
):
    """[B] THE ATTACK: a real webshell + ``$wp_version = '9.9.9'``.

    wp.org is REACHABLE and answers for the claimed build — with "no such
    build", which is the whole point.  Before the fix this demoted the
    shell to the unproven medium class whose fix text tells the operator
    not to triage or remove it; the demotion was bought with a single
    write to a file that is inside the webroot.

    The verdict now stays HIGH with the backdoor triage, and the fact
    that makes it high is in the detail: the version the core's own file
    names is not a release, so the core itself is altered and nothing in
    this webroot may be excused as stock core.
    """
    d = _web_script_data(
        {"shell.php": WEBSHELL,
         "wp-includes/version.php": GHOST_VERSION_PHP},
        version="9.9.9", checksums=None,
        routes=[("GET", "api.wordpress.org", NO_SUCH_BUILD),
                ("GET", "api.wordpress.org", NO_SUCH_BUILD),
                ("HEAD", "shell.php", Resp(404))],
    )
    d.entries = [
        E("shell.php", len(WEBSHELL)),
        E("wp-includes", is_dir=True),
        E("wp-includes/version.php", len(GHOST_VERSION_PHP)),
    ]
    (f,) = check_security_web_exposed_script(d, DEFAULTS)
    assert (f.category, f.name, f.risk, f.count, f.bytes) == (
        "security.web_exposed_script", "shell.php", "high", 1, len(WEBSHELL),
    )
    assert f.fix == security.WEB_SCRIPT_TRIAGE
    assert f.fix != security.WEB_SCRIPT_UNPROVEN_TRIAGE
    assert "Do NOT triage or remove" not in f.detail
    assert "UNPROVEN" not in f.detail
    # the two conditions are told apart in the operator-facing text
    assert "wp.org published no checksums" in f.detail
    assert "that build is not a release" in f.detail
    assert "could not be fetched" not in f.detail
    # ... and the ALTERED VERSION is the fact the run actually has
    assert "checksums of WP 9.9.9 and published none" in f.detail
    assert "no such WordPress build was ever released" in f.detail
    assert "$wp_version in wp-includes/version.php" in f.detail
    assert "which is positive evidence the core itself was altered" in f.detail
    f.validate()
    # the report's next-step table is reachable: it keys off the HIGH
    # category, and this finding is HIGH again
    from wpt.report import suggested_steps
    assert suggested_steps([f])
    warnings = [r.getMessage() for r in wpt_records
                if r.name == "wpt.audit.security"
                and r.levelno >= logging.WARNING]
    assert any("wp.org ANSWERED for WP 9.9.9" in m for m in warnings)
    assert any("the comparison is INCOMPLETE (not offline)" in m
               for m in warnings)
    # ... and it is never reported as the UNAVAILABLE (offline) basis
    assert not any("basis is UNAVAILABLE" in m for m in warnings)


def test_web_exposed_script_a_genuine_transport_failure_still_demotes(
    wpt_records,
):
    """The other half, pinned so the fix cannot become "never demote".

    A webshell with a SANE, readable version and a wp.org that never
    answered is the offline condition and only this is: MEDIUM, its own
    category, and a fix that removes nothing.  Every shape of "no
    response" is covered, because the demotion is what keeps an
    air-gapped run from calling wp-login.php a backdoor — a refused
    connection, a DNS failure, a TLS failure and a read timeout all raise
    a ``requests.RequestException`` and all mean the same thing here.
    """
    for exc in (requests.ConnectionError("refused"),
                requests.ConnectTimeout("no route to host"),
                requests.ReadTimeout("read timed out"),
                requests.exceptions.SSLError("handshake failed")):
        d = _web_script_data(
            {"shell.php": WEBSHELL,
             "wp-includes/version.php": b"<?php\n$wp_version = '7.1';\n"},
            version="7.1", checksums=None,
            routes=[("GET", "api.wordpress.org", exc),
                    ("GET", "api.wordpress.org", exc),
                    ("HEAD", "shell.php", Resp(404))],
        )
        d.entries = [E("shell.php", len(WEBSHELL))]
        (f,) = check_security_web_exposed_script(d, DEFAULTS)
        assert (f.category, f.risk) == (
            "security.web_exposed_script_unproven", "medium"), exc
        assert f.fix == security.WEB_SCRIPT_UNPROVEN_TRIAGE, exc
        assert "could not be fetched" in f.detail, exc
    from wpt.report import suggested_steps
    assert suggested_steps([f]) == []
    # ... and the stock-core shape is still the measured one: an offline
    # run never rates wp-login.php a backdoor
    d = _web_script_data(STOCK_CORE_UNPROVEN, checksums=None,
                         routes=[*_WPORG_UNREACHABLE,
                                 ("HEAD", ".php", Resp(404))])
    d.entries = [E(name, len(blob)) for name, blob in STOCK_CORE_UNPROVEN.items()]
    offline = check_security_web_exposed_script(d, DEFAULTS)
    assert not [f for f in offline if f.risk == "high"]


#: The 20 000-character version string of the measured attack: it is
#: interpolated into the request URL verbatim, and the LIVE API answers it
#: with HTTP 400 (URI too long) — a positive statement that the request is
#: malformed.  Before the fix that answer was read as "wp.org could not
#: answer", which demoted a real webshell to the MEDIUM "do NOT triage or
#: remove" class: twenty thousand bytes in a file the attacker already had
#: to write were enough to talk the audit out of its own verdict.
_URI_TOO_LONG_VERSION = "9" * 20000
_URI_TOO_LONG_PHP = (
    b"<?php\n$wp_version = '" + _URI_TOO_LONG_VERSION.encode() + b"';\n"
)


def _answered_run(version: str, version_php: bytes, answer):
    """The finding and the wp.org URLs of one run whose site got ``answer``.

    Every wp.org request is scripted (the map fetch AND the answer probe, so
    an extra live request fails the test by omission) and the version comes
    from a real ``wp-includes/version.php``, because the whole attack is
    that this file is the one wpt trusts.
    """
    d = _web_script_data(
        {"shell.php": WEBSHELL, "wp-includes/version.php": version_php},
        version=version, checksums=None,
        routes=[("GET", "api.wordpress.org", answer),
                ("GET", "api.wordpress.org", answer),
                ("HEAD", "shell.php", Resp(404))],
    )
    d.entries = [
        E("shell.php", len(WEBSHELL)),
        E("wp-includes", is_dir=True),
        E("wp-includes/version.php", len(version_php)),
    ]
    (f,) = check_security_web_exposed_script(d, DEFAULTS)
    assert (f.category, f.name, f.risk) == (
        "security.web_exposed_script", "shell.php", "high"), answer
    assert f.fix == security.WEB_SCRIPT_TRIAGE, answer
    asked = [url for method, url, _kw in d.probe.session.calls
             if method == "GET" and "api.wordpress.org" in url]
    return f, asked


@pytest.mark.parametrize("answer, named", [
    # THE ATTACK, measured on the live API: a version string too long for a
    # URI.  A POSITIVE answer ("this request is malformed"), not an outage.
    (FakeResponse(400, "Bad Request"), "HTTP 400"),
    # a server-side failure at wp.org's edge, a redirect to a maintenance
    # page, an HTML error body, an empty body, a JSON list where a map was
    # expected: six different answers, one rule.
    (FakeResponse(500, "boom"), "HTTP 500"),
    (FakeResponse(503, "down"), "HTTP 503"),
    (FakeResponse(302, ""), "HTTP 302"),
    (FakeResponse(200, "<html><body>maintenance</body></html>"),
     "a body that is not JSON"),
    (FakeResponse(200, ""), "a body that is not JSON"),
    (FakeResponse(200, "[]"), "a JSON list"),
    (FakeResponse(200, json.dumps({"checksums": {}})),
     "no usable path/digest entry"),
    # a 200 that says nothing about the build at all: the "no such build"
    # claim needs the `checksums` key to be THERE, or wpt would assert
    # something about the site it cannot support
    (FakeResponse(200, json.dumps({"error": "invalid version"})),
     "no `checksums` key"),
])
def test_every_wp_org_answer_keeps_the_candidate_high(answer, named, wpt_records):
    """ANY HTTP response is evidence that wp.org SPOKE, and none demotes.

    The demotion used to be decided by the STATUS of wp.org's answer,
    which is not wpt's to read: the request URL carries the ``$wp_version``
    an attacker already wrote, so the attacker chose the branch.  Each case
    here stays HIGH, and the detail names the answer's own class — an
    operator who retries needs to know WHICH answer they got — plus the one
    fact that keeps the candidate high: the build this webroot claims could
    not be confirmed, and its only statement is the file the attacker
    controls.
    """
    f, _asked = _answered_run("9.9.9", GHOST_VERSION_PHP, answer)
    assert "could not be fetched" not in f.detail
    assert "Do NOT triage or remove" not in f.detail
    assert "UNPROVEN" not in f.detail
    assert "does not establish it" in f.detail, answer
    assert named in f.detail, answer
    # ... and only the answer that really names the build claims it is not
    # a release; every other class says the build could not be CONFIRMED
    if named == 'HTTP 200 and {"checksums": false}':
        assert "no such WordPress build" in f.detail
    else:
        assert "no such WordPress build" not in f.detail
    assert "so no file in this webroot may be excused as stock core" in f.detail
    f.validate()
    from wpt.report import suggested_steps
    assert suggested_steps([f]), answer
    warnings = [r.getMessage() for r in wpt_records
                if r.name == "wpt.audit.security" and r.levelno >= logging.WARNING]
    assert any("wp.org ANSWERED for WP 9.9.9" in m for m in warnings), answer
    assert any("INCOMPLETE (not offline)" in m for m in warnings), answer
    assert not any("basis is UNAVAILABLE" in m for m in warnings), answer


def test_a_20000_character_version_cannot_demote_a_webshell(wpt_records):
    """THE ATTACK, end to end: the version file the attacker writes.

    Every other case above models the answer; this one models the WRITE.
    ``$wp_version`` is 20 000 characters long, which is what earns the live
    API its HTTP 400, and the shell beside it must still come out HIGH
    with the backdoor triage — the run names the unconfirmable build
    instead of hiding behind "offline".
    """
    f, asked = _answered_run(_URI_TOO_LONG_VERSION, _URI_TOO_LONG_PHP,
                             FakeResponse(400, "Bad Request"))
    assert "HTTP 400" in f.detail
    assert "could not be fetched" not in f.detail
    assert f.fix == security.WEB_SCRIPT_TRIAGE
    # the request really did carry the whole string: the attack IS the URL
    assert asked and all(f"version={_URI_TOO_LONG_VERSION}" in u for u in asked)


def test_a_positive_no_such_build_answer_costs_no_second_request(
    wpt_records,
):
    """The two shapes are told apart WITHOUT asking wp.org twice.

    The distinction is asked of the SAME transport, URL and 1h cache the
    map fetch used, and a 200 JSON payload is written back by that
    transport — so the second ask is a cache read with no network.  The
    request list is asserted, because a second live request per audit
    would be a cost this check must not add.
    """
    d = _web_script_data(
        {"shell.php": WEBSHELL,
         "wp-includes/version.php": GHOST_VERSION_PHP},
        version="9.9.9", checksums=None,
        routes=[("GET", "api.wordpress.org", NO_SUCH_BUILD),
                ("GET", "api.wordpress.org", NO_SUCH_BUILD),
                ("HEAD", "shell.php", Resp(404))],
    )
    d.entries = [E("shell.php", len(WEBSHELL))]
    check_security_web_exposed_script(d, DEFAULTS)
    asked = [url for method, url, _kw in d.probe.session.calls
             if method == "GET" and "api.wordpress.org" in url]
    # one request per locale the fetch asked for (en_US here), and the
    # distinguishing re-ask of the effective locale served from the cache
    assert len(asked) <= 2
    assert all("version=9.9.9" in url for url in asked)


def test_SET_PHP_MIN_stripped_two_component_value_never_crashes_the_check():
    """SET-PHP-MIN: load accepted a single component (and stored unstripped
    whitespace), then _php_minor -> None and runtime >= None raised
    TypeError inside the check."""
    from wpt.settings import SettingsError, load as load_settings

    for value in (" 8.2 ", "8.2\n"):
        settings = load_settings(overrides={"env.php_min_active": value})
        assert settings.env.php_min_active == "8.2"
        data = sec_data()
        data.probe = SimpleNamespace(info=lambda: {"php_version": "8.1.2"})
        findings = check_security_php_version(data, settings)
        assert [f.name for f in findings] == ["php-eol"]
    with pytest.raises(SettingsError):
        load_settings(overrides={"env.php_min_active": "8"})


def test_R8_P2_23_soft404_probe_name_comes_from_the_one_owner(monkeypatch):
    """R8-P2-23: security kept a second probe-name template next to
    ``bridge_name.PROBE_NAME_TEMPLATE``; the shape matched only by luck.
    The helper must call the shared owner, never re-derive the name."""
    import wpt.audit.security as security
    from wpt.bridge_name import probe_name

    calls = []

    def _recording(suffix):
        calls.append(suffix)
        return probe_name(suffix)

    monkeypatch.setattr(security, "probe_name", _recording)
    monkeypatch.setattr(security.secrets, "token_hex", lambda _n: "deadbeef")

    assert security._soft404_probe_name() == "wpt-probe-deadbeef.php"
    assert calls == ["deadbeef"]


def test_R14_cert_probe_is_bounded_by_the_run_deadline(tls, monkeypatch):
    """R14-P2: the cert probe used a blocking create_connection + TLS wrap
    with no run budget.  A stalled dial now ends at ``data.deadline`` and
    answers silent (unknown), never a guess."""
    import time

    from wpt.deadline import Deadline

    def _slow_create(address, timeout=None, source_address=None):
        tls.conn_calls.append((address, timeout))
        time.sleep(0.3)
        return FakeRawSocket()

    monkeypatch.setattr(security.socket, "create_connection", _slow_create)
    data = sec_data(probe=mkprobe(timeout_s=7),
                    siteurl="https://127.0.0.1")
    data.deadline = Deadline(0.05)
    started = time.monotonic()
    assert check_security_cert_mismatch(data, DEFAULTS) == []
    assert time.monotonic() - started < 0.25


def test_R25_cert_probe_dns_is_bounded_by_the_request_timeout(monkeypatch):
    """R25-P2: resolution used ``deadline.at`` (or libc when no deadline),
    so a stalled resolver held the audit for the run budget / forever.  The
    request's own ``probe.timeout_s`` caps resolution and every attempt."""
    import socket
    import time

    import wpt.netresolve as netresolve
    from wpt.deadline import Deadline

    real = socket.getaddrinfo

    def stalling(host, port, *args, **kwargs):
        if host == "stall.example":
            time.sleep(4)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                     ("127.0.0.1", port))]
        return real(host, port, *args, **kwargs)

    monkeypatch.setattr(netresolve.socket, "getaddrinfo", stalling)

    data = sec_data(probe=mkprobe(timeout_s=0.25),
                    siteurl="https://stall.example")
    started = time.monotonic()
    assert check_security_cert_mismatch(data, DEFAULTS) == []
    assert time.monotonic() - started < 1.2

    # A longer run budget must not win over the shorter request bound.
    data = sec_data(probe=mkprobe(timeout_s=0.25),
                    siteurl="https://stall.example")
    data.deadline = Deadline(3)
    started = time.monotonic()
    assert check_security_cert_mismatch(data, DEFAULTS) == []
    assert time.monotonic() - started < 1.2


def test_R23_cert_probe_shares_the_budget_across_addresses(tls, monkeypatch):
    """R23-P2: each address got ``min(timeout_s, remaining)``, so a
    blackholed first address spent the WHOLE run budget and a later address
    with the real certificate was never tried (a genuine mismatch became a
    silent unknown).  The share is ``remaining / addresses_left``."""
    import time

    from wpt.deadline import Deadline

    monkeypatch.setattr(security, "resolve_host_bounded",
                        lambda host, port, budget, **kw:
                        ["192.0.2.1", "127.0.0.1"])
    original = tls.conn_calls

    def fake_create(address, timeout=None, source_address=None):
        original.append((address, timeout))
        if address == ("192.0.2.1", 443):
            # A blackhole answers only at its own timeout; the OLD code gave
            # it the entire remaining run budget here.
            time.sleep(timeout)
            raise TimeoutError("blackholed address")
        return FakeRawSocket()

    monkeypatch.setattr(security.socket, "create_connection", fake_create)
    data = sec_data(probe=mkprobe(timeout_s=7), siteurl="https://site.test")
    data.deadline = Deadline(0.4)
    started = time.monotonic()
    check_security_cert_mismatch(data, DEFAULTS)
    elapsed = time.monotonic() - started
    assert [address for address, _timeout in tls.conn_calls] == [
        ("192.0.2.1", 443), ("127.0.0.1", 443)]
    assert tls.conn_calls[0][1] <= 0.3
    assert elapsed < 0.8


def test_R14_publicly_served_paths_caps_each_request_at_the_deadline():
    """R14-P2: the naive probe checked only the expiry BETWEEN requests and
    used the 7 s per-read timeout, so one 0.3 s GET outlived a 0.05 s
    budget.  The request's timeout and the caller's wait ride the
    remaining deadline."""
    import time

    from wpt.deadline import Deadline

    session = FakeSession([
        lambda method, url, kwargs: (time.sleep(0.3),
                                     FakeResponse(200, "log"))[1],
    ])
    probe = SiteProbe(session=session, site="https://site.test", timeout_s=7)
    started = time.monotonic()
    assert security.publicly_served_paths(
        probe, ["error_log"], Deadline(0.05)) == []
    assert time.monotonic() - started < 0.25
    assert session.gets
    assert session.gets[0][1]["timeout"] <= 0.05


_R16_DEADLINE_CHECKS = (
    ("xmlrpc", check_security_xmlrpc, "POST"),
    ("rest_users", check_security_rest_users, "GET"),
    ("author_scan", check_security_author_scan, "GET"),
    ("https_redirect", check_security_https_redirect, "GET"),
    ("www_apex", check_security_www_apex, "GET"),
    ("uploads_listing", check_security_uploads_listing, "GET"),
)


@pytest.mark.parametrize("name,check,verb", _R16_DEADLINE_CHECKS)
def test_R16_every_security_probe_rides_the_run_deadline(name, check, verb):
    """A drip server cannot outlive --deadline inside ANY security check:
    the GET and POST owners cap each request at the remaining budget and
    stop waiting for the worker at the absolute deadline."""
    import time

    from wpt.deadline import Deadline

    session = FakeSession([
        lambda method, url, kwargs: (time.sleep(0.3),
                                     FakeResponse(200, ""))[1],
    ])
    probe = SiteProbe(session=session, site=SITE, timeout_s=7)
    data = sec_data(probe=probe)
    data.deadline = Deadline(0.05)
    started = time.monotonic()
    assert check(data, DEFAULTS) == []
    assert time.monotonic() - started < 0.25
    calls = session.posts if verb == "POST" else session.gets
    assert calls and calls[0][1]["timeout"] <= 0.05


@pytest.mark.parametrize("name,check,verb", _R16_DEADLINE_CHECKS)
def test_R16_every_security_probe_sends_nothing_after_expiry(
        name, check, verb):
    """An already-expired budget answers unknown without opening a request
    (the expiry can never be preceded by one last wire write)."""
    from wpt.deadline import Deadline

    session = FakeSession([])
    probe = SiteProbe(session=session, site=SITE, timeout_s=7)
    data = sec_data(probe=probe)
    data.deadline = Deadline(-1)
    assert check(data, DEFAULTS) == []
    assert session.gets == [] and session.posts == []


def test_R19_deadline_probe_closes_the_socket_and_stops_the_download(
        monkeypatch, tmp_path):
    """R19-P2: ``_probe_call`` returned None at the deadline while its
    daemon worker kept downloading the dripped body (30 B at 1.5 s; the
    worker alive).  A real session now rides the in-thread absolute
    transport, preloads the body under the same budget, and closes the
    socket; no byte arrives after the call returns."""
    import http.server
    import threading

    from wpt.deadline import Deadline

    sent = {"bytes": 0, "stop": False}

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", "100000")
            self.end_headers()
            try:
                while not sent["stop"] and sent["bytes"] < 100000:
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    sent["bytes"] += 1
                    time.sleep(0.02)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    session = requests.Session()
    session.trust_env = False
    probe = SiteProbe(session=session,
                      site=f"http://127.0.0.1:{server.server_port}",
                      timeout_s=5)
    try:
        started = time.monotonic()
        response = security._get(
            probe, f"{probe.site}/x", deadline=Deadline(0.3))
        assert response is None
        # Wall-clock shape assertions run under -n 20 --dist worksteal: a
        # loaded worker can schedule the origin late.  Keep a generous
        # ceiling and prove the MECHANISM (no worker survives, the drip
        # stops) rather than measuring against the 0.3 s budget itself.
        assert time.monotonic() - started < 5.0
        assert not [t for t in threading.enumerate()
                    if t.name == "wpt-http-probe"]
        # Allow the origin's already-buffered write to hit the closed
        # socket, then prove the drip STOPPED (no post-deadline download).
        time.sleep(0.3)
        settled = sent["bytes"]
        time.sleep(0.5)
        assert sent["bytes"] == settled, (settled, sent["bytes"])
    finally:
        sent["stop"] = True
        session.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_R22_probe_transport_is_bounded_by_http_timeout_not_the_run():
    """R22-P1: the bounded transport was armed with the whole REMAINING run
    budget, so one dripped header held a single probe for the 3 s test
    deadline (and a 3600 s run in production) instead of
    ``http.timeout_s``.  The absolute bound is now
    ``min(run deadline, now + probe.timeout_s)``: the probe ends at its own
    timeout when the run is longer, and the run still wins when shorter."""
    import http.server
    import threading
    import time

    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            self.wfile.write(b"HTTP/1.1 200 OK\r\nX-Test: ")
            self.wfile.flush()
            try:
                for _ in range(40):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.25)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    session = requests.Session()
    session.trust_env = False
    probe = SiteProbe(session=session,
                      site=f"http://127.0.0.1:{server.server_port}",
                      timeout_s=1)
    try:
        started = time.monotonic()
        assert security._get(probe, f"{probe.site}/x",
                             deadline=Deadline(3)) is None
        elapsed = time.monotonic() - started
        assert elapsed < 1.6, elapsed
        # A shorter RUN budget still wins over the per-probe timeout.
        short = Deadline(0.3)
        started = time.monotonic()
        assert security._get(probe, f"{probe.site}/x", deadline=short) is None
        assert time.monotonic() - started < 0.9
        with pytest.raises(DeadlineExceeded):
            short.check("security probe")
        # A session DOUBLE that ignores its timeout kw is stopped at the
        # same minimized instant, not at the longer run deadline.
        class _SlowDouble:
            def get(self, url, **kwargs):
                time.sleep(3)
                raise AssertionError("never returned")

        slow = SiteProbe(session=_SlowDouble(), site="http://slow.test",
                         timeout_s=1)
        started = time.monotonic()
        assert security._get(slow, "http://slow.test/x",
                             deadline=Deadline(3)) is None
        assert time.monotonic() - started < 1.6
    finally:
        session.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_R19_oversized_wp_org_body_is_answered_but_unusable(
        monkeypatch, tmp_path):
    """R19-P2 residual: a 200 whose body exceeds the read bound was
    classified as the OFFLINE condition (``None``), demoting a HIGH
    finding on an answer wp.org actually sent.  The response is evidence;
    only its body is unusable, and that basis must never demote."""
    import http.server
    import threading

    from wpt.audit import integrity, updates
    from wpt.deadline import Deadline

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"x" * 1024
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    site = f"http://127.0.0.1:{server.server_port}"
    monkeypatch.setattr(integrity, "_checksums_url",
                        lambda version, locale, config=None: f"{site}/checksums")
    monkeypatch.setattr(updates, "_CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(updates, "_WPORG_JSON_MAX_BYTES", 16)
    session = requests.Session()
    session.trust_env = False
    try:
        basis = security._wp_org_answered(
            session, 5, "9.9.9", "en_US", Deadline(5))
        assert basis is not None, "a received answer was read as offline"
        assert basis.demote is False
        assert "could not be read" in basis.refusal
    finally:
        session.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_R20_a_large_body_does_not_hide_a_security_finding():
    """R20-P1: every bounded real-session GET preloaded ``.text`` through the
    bridge's 256 KiB excerpt cap, so a 307 KiB 200 made ``_get`` return None
    ("the site did not answer") and silenced https_redirect / served-junk /
    uploads-listing.  The check's own configured bound must read it."""
    import http.server
    import threading

    from wpt.deadline import Deadline

    big = b"x" * 307213

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/big.log":
                body = big
                self.send_response(200)
            else:
                body = b"not found"
                self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    session = requests.Session()
    session.trust_env = False
    site = f"http://127.0.0.1:{server.server_port}"
    probe = SiteProbe(session=session, site=site, timeout_s=5)
    try:
        data = sec_data(probe=probe)
        data.deadline = Deadline(5)
        findings = security.check_security_https_redirect(data, DEFAULTS)
        assert [f.category for f in findings] == ["security.https_redirect"]
        assert security.publicly_served_paths(
            probe, ["big.log"], Deadline(5)) == ["big.log"]
        # An UNBOUNDED run (no deadline) still uses the bounded transport
        # and the configured body cap rather than an arbitrary .text.
        unbounded = security._get(probe, f"{site}/big.log")
        assert unbounded is not None and len(unbounded.text) == len(big)
    finally:
        session.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("shape", ["truncated", "chunked"])
def test_R20_wp_org_body_failure_after_a_response_is_answered_but_unusable(
        monkeypatch, tmp_path, shape):
    """R20-P2: a truncated Content-Length or a malformed chunked body AFTER
    a 200 used the RequestException branch's "offline" answer, demoting a
    HIGH finding.  A response that arrived is evidence: demote must stay
    False."""
    import http.server
    import threading

    from wpt.audit import integrity, updates
    from wpt.deadline import Deadline

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            if shape == "truncated":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", "100")
                self.end_headers()
                self.wfile.write(b"x" * 10)
                self.close_connection = True
            else:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                self.wfile.write(b"zz\r\n")
                self.close_connection = True

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    site = f"http://127.0.0.1:{server.server_port}"
    monkeypatch.setattr(integrity, "_checksums_url",
                        lambda version, locale, config=None: f"{site}/checksums")
    monkeypatch.setattr(updates, "_CACHE_DIR", tmp_path / "cache")
    session = requests.Session()
    session.trust_env = False
    try:
        basis = security._wp_org_answered(
            session, 5, "9.9.9", "en_US", Deadline(5))
        assert basis is not None, "a received answer was read as offline"
        assert basis.demote is False
        assert "could not be read" in basis.refusal
    finally:
        session.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("shape", ["headers", "body"])
def test_R18_wp_org_answer_probe_is_bounded_for_header_and_body_drips(
        shape, monkeypatch, tmp_path):
    """R18-P1: the SECOND wp.org request used a raw ``session.get`` and an
    unbounded ``response.json()``.  A one-byte drip held it 13.2 s past a
    2 s timeout and could START after the deadline.  It now rides the one
    absolute transport and refuses when the budget is spent."""
    import http.server
    import threading

    from wpt.audit import integrity, updates
    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            try:
                if shape == "headers":
                    head = (b"HTTP/1.1 200 OK\r\nContent-Type: "
                            b"application/json\r\nContent-Length: 2\r\n\r\n{}")
                    for byte in head:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        time.sleep(0.08)
                else:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", "100")
                    self.end_headers()
                    for _ in range(100):
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        time.sleep(0.08)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    site = f"http://127.0.0.1:{server.server_port}"
    monkeypatch.setattr(integrity, "_checksums_url",
                        lambda version, locale, config=None: f"{site}/checksums")
    monkeypatch.setattr(updates, "_CACHE_DIR", tmp_path / "cache")
    session = requests.Session()
    session.trust_env = False
    try:
        started = time.monotonic()
        with pytest.raises(DeadlineExceeded):
            security._wp_org_answered(
                session, 5, "9.9.9", "en_US", Deadline(0.5))
        assert time.monotonic() - started < 1.5
    finally:
        session.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_R21_an_oversize_200_is_answered_but_too_large():
    """R21-P1: a 200 body over the configured probe cap (9 MiB > 8 MiB) was
    preloaded through the EXACT bound, raised, and became None ("the site
    did not answer") — silencing https_redirect, uploads-listing and the
    served-log disclosure.  Status/headers plus a bounded prefix are the
    answer."""
    import http.server
    import threading

    from wpt.deadline import Deadline

    big = 9 * 1024 * 1024

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/wp-content/uploads/"):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(big))
                self.end_headers()
                try:
                    self.wfile.write(
                        b"Index of /wp-content/uploads\n" + b"x" * (big - 29))
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return
            if self.path == "/big.log":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(big))
                self.end_headers()
                try:
                    self.wfile.write(b"log line\n" + b"x" * (big - 9))
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return
            if self.path == "/":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")
                return
            body = b"not found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    session = requests.Session()
    session.trust_env = False
    site = f"http://127.0.0.1:{server.server_port}"
    probe = SiteProbe(session=session, site=site, timeout_s=5)
    try:
        data = sec_data(probe=probe)
        data.deadline = Deadline(5)
        assert [f.category for f in check_security_https_redirect(
            data, DEFAULTS)] == ["security.https_redirect"]
        assert [f.category for f in check_security_uploads_listing(
            data, DEFAULTS)] == ["security.uploads_listing"]
        assert security.publicly_served_paths(
            probe, ["big.log"], Deadline(5)) == ["big.log"]
    finally:
        session.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_R24_wp_org_probe_uses_the_per_request_timeout_not_the_run_budget(
        monkeypatch, tmp_path):
    """R24-P1: the second wp.org GET used the RUN deadline, so a slow answer
    aborted the whole audit (rc 1, every finding lost) instead of reading as
    the documented offline condition.  Its transport bound is
    ``min(run, now + http.timeout_s)``; only a spent run raises."""
    import http.server
    import threading

    from wpt.audit import integrity, updates
    from wpt.deadline import Deadline

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            try:
                head = (b"HTTP/1.1 200 OK\r\nContent-Type: "
                        b"application/json\r\nContent-Length: 2\r\n\r\n{}")
                for byte in head:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.08)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    site = f"http://127.0.0.1:{server.server_port}"
    monkeypatch.setattr(integrity, "_checksums_url",
                        lambda version, locale, config=None: f"{site}/checksums")
    monkeypatch.setattr(updates, "_CACHE_DIR", tmp_path / "cache")
    session = requests.Session()
    session.trust_env = False
    try:
        started = time.monotonic()
        basis = security._wp_org_answered(
            session, 1, "9.9.9", "en_US", Deadline(3))
        elapsed = time.monotonic() - started
        assert basis is None
        assert elapsed < 2.2, elapsed
    finally:
        session.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_R24_cert_probe_attempt_deadline_covers_dial_and_handshake(
        monkeypatch):
    """R24-P2: ``_peer_cert_bounded`` gave connect ``share`` and then the
    wrapped socket inherited a FRESH share for the handshake, so one address
    could spend two shares and starve the next.  ONE absolute attempt
    deadline is computed before the dial and the handshake gets what is
    left of it."""
    clock = [1000.0]

    class Deadline:
        at = 1000.6

        @property
        def remaining(self):
            return max(0.0, self.at - clock[0])

    class FakeRaw:
        def __init__(self):
            self.timeouts = []

        def settimeout(self, value):
            self.timeouts.append(value)

        def close(self):
            pass

    class FakeTLS(FakeRaw):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def getpeercert(self):
            return {"subject": (("commonName", "site.test"),)}

    raws = []
    wrap_seen = []

    def fake_create(address, timeout=None, source_address=None):
        raw = FakeRaw()
        raws.append((address, timeout, raw))
        clock[0] += 0.2  # a slow dial consumes part of the attempt share
        return raw

    def fake_wrap(_context, sock, server_hostname=None, **kw):
        wrap_seen.append((server_hostname, list(sock.timeouts)))
        if len(wrap_seen) == 1:
            raise ssl.SSLEOFError("peer closed during the handshake")
        return FakeTLS()

    monkeypatch.setattr(security, "resolve_host_bounded",
                        lambda host, port, budget, **kw:
                        ["127.0.0.2", "127.0.0.1"])
    monkeypatch.setattr(security.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(security.socket, "create_connection", fake_create)
    monkeypatch.setattr(security.ssl.SSLContext, "wrap_socket", fake_wrap)
    security._peer_cert_bounded(
        "site.test", "site.test", 443, 5, Deadline())
    # First share 0.3: after a 0.2 s dial the handshake gets ~0.1, never a
    # fresh 0.3; the second address still has the rest of the run budget.
    assert raws[0][1] <= 0.3001
    assert wrap_seen[0][1] and wrap_seen[0][1][-1] <= 0.1001
    assert raws[1][0] == ("127.0.0.1", 443)
