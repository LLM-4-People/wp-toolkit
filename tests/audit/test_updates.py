"""Unit tests for the update audit checks (wpt.audit.updates) — W6g.

NO network: the checks ride a real SiteProbe whose ``session`` is the
scripted FakeSession (the checks use ONLY probe.session + probe.timeout_s,
never probe.get/post — so no site URL is ever requested), and the cache
directory is monkeypatched to a tmp_path via ``updates._CACHE_DIR`` — no
test ever touches the CWD's real ``.wpt-cache``.  Responses are canned
wp.org payloads matching the live-verified shapes in docs/research/R3.md
(empty buckets arrive as ``[]``, the PHP empty map).  The
fetch_core_release_zip tests script BINARY answers — a local FakeResponse
subclass carrying ``.content`` (the real requests.Response attribute the
shared JSON-only fake lacks) — with small REAL zips built in memory
(zipfile, ``wordpress/``-nested like the official releases).  All
deterministic: no sleeps — cache-age tests use os.utime.

Test -> behavior map (W6g task list):
  core:
  test_core_outdated_found .................. wp_version != offers[0].current
        => one finding "X -> Y"; GET shape pinned (R3 URL, UA wpt/,
        probe timeout)
  test_core_current_silent ................. equal versions => []
  test_core_wp_version_none_silent ......... None (local mode) => []
  test_core_probe_none_silent .............. no probe => [] (never a
        network call)
  test_core_unusable_payload_silent ........ 200 but no offers[0].current
        => [] + one warning
  plugins:
  test_plugins_request_shape ............... ONE bulk POST: R3 form
        fields (plugins map keyed FILE path, Name fallback = folder
        slug for a nameless plugin, active = the truly-active files,
        translations=[], locale=["en_US"], all=true), UA, timeout, and
        NO info/1.2 request
  test_plugins_updates_aggregate .......... updates bucket => one
        aggregate finding: sorted "slug: X -> Y (url)" lines, count,
        url falls back to package; premium (absent) + no_update silent
  test_plugins_detail_truncates_at_eight .. 10 updates => 8 lines +
        "(+2 more)", count over all 10
  test_plugins_no_update_only_silent ...... everything current => []
  test_plugins_premium_absent_silent ....... both buckets empty (the
        live premium answer) => []
  test_plugins_empty_bucket_list_shape .... "plugins": [] accepted => []
  test_plugins_empty_bucket_dict_shape ..... "plugins": {} accepted => []
  test_plugins_catalog_empty_silent ........ {} catalog (local mode) => []
        with no request
  test_plugins_versionless_mixed .......... a ""-version entry is never
        sent; the versioned one still reports
  test_plugins_all_versionless_silent ..... only ""-version entries =>
        [] with no request
  test_plugins_network_failure_silent ...... POST fails, no cache => []
        + one warning
  themes:
  test_theme_update_available .............. update bucket => finding
        "slug: installed version unknown -> new (url)"; POST shape
        pinned (themes map keyed SLUG, NO Version key — live-verified
        tolerance, no "all" field, UA, timeout)
  test_theme_no_update_silent .............. no_update bucket => []
  test_theme_premium_absent_silent ......... both buckets [] => []
  test_theme_template_none_silent .......... template None => [] with
        no request
  test_theme_entry_without_new_version ..... bucket entry missing
        new_version contributes nothing
  cache:
  test_cache_second_call_within_ttl ....... second call within TTL makes
        NO network call (scripted session counts)
  test_cache_fresh_fetch_writes_file ....... filename =
        sha256(url + canonical payload).json, content = the payload
  test_cache_stale_reused_on_failure ....... aged cache + network
        failure => stale answer reused with ONE warning
  test_cache_no_cache_failure_silent ....... no cache + failure => [] +
        ONE warning
  test_cache_corrupt_file_refetched ........ an unparsable cache file is
        a miss: refetched and rewritten
  release zip (WpOrgApi.fetch_core_release_zip — the heal-core source):
  test_release_zip_fetch_caches_bytes ..... a real in-memory zip
        downloads through the caller session (URL template, UA, timeout
        pinned), returns the exact bytes and lands at
        .wpt-cache/wp-release-<version>.zip
  test_release_zip_fresh_cache_hit_no_net .. second call within the TTL
        serves from disk: a session scripted to FAIL is never asked
  test_release_zip_stale_reused_on_failure  aged entry + failed fetch =>
        the stale bytes answer with ONE warning
  test_release_zip_no_cache_failure_none ... no cache + failure => None
        + exactly ONE warning
  test_release_zip_corrupt_payload_rejected  b"not a zip" and a
        wrong-prefix zip are failed fetches: None + one warning each,
        never cached
  test_release_zip_corrupt_cache_refetched  a torn cached entry is a
        miss: refetched and rewritten
  test_release_zip_corrupt_stale_never_served  a corrupt cache entry
        never answers, not even as the stale fallback
  test_release_zip_bad_version_raises ...... empty/whitespace/
        path-unsafe versions raise WptError, no request made
  test_release_zip_good_versions_validate .. dots/dashes/case pass the
        version gate: exact URL per version, one cache file per version
  registry:
  test_registry_integration ............... three names, both modes,
        func identity, "updates" prefix selection
  test_run_checks_end_to_end ............... run_checks(["updates"]) with
        stubs: 3 findings, 3 distinct cache files, a second run fully
        cache-served, local mode silent
"""

import io
import json
import logging
import os
import time
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest
import requests

import wpt.audit.updates as updates
from tests.fakes import FakeResponse, FakeSession
from wpt.audit.data import AuditData
from wpt.audit.registry import all_checks, run_checks, select_checks
from wpt.audit.security import SiteProbe
from wpt.audit.updates import (
    _cache_key,
    WpOrgApi,
    check_updates_core,
    check_updates_plugins,
    check_updates_themes,
)
from wpt.settings import load
from wpt.types import WptError

#: The shipped profile — the checks consume no tunables.
DEFAULTS = load()

SITE = "https://example.com"      # never requested: api.wordpress.org only
TIMEOUT = 7                       # probe.timeout_s the requests must carry

PLUGIN_FIX = "update plugins via wp-admin; back up first"
THEME_FIX = "update the active theme via wp-admin; back up first"
CORE_FIX = "update WordPress via wp-admin; back up first"


@pytest.fixture
def wpt_caplog(caplog):
    """caplog wired to the non-propagating wpt logger tree (see test_registry)."""
    parent = logging.getLogger("wpt")
    parent.addHandler(caplog.handler)
    with caplog.at_level(logging.DEBUG, logger="wpt"):
        yield caplog
    parent.removeHandler(caplog.handler)


def test_R9_P1_cooperative_stop_is_not_a_wp_org_degrade(
        cache_dir, monkeypatch):
    """P1: ``_request_json``/``_fetch_zip`` caught WptError, so a SIGTERM
    during a wp.org request became "unavailable" and the audit continued to
    a rc-0 report."""
    from wpt.types import StopRequested

    def _stop(*args, **kwargs):
        raise StopRequested("received SIGTERM (15)")

    monkeypatch.setattr(updates, "get_bounded", _stop)
    api = WpOrgApi(object(), TIMEOUT)
    with pytest.raises(StopRequested):
        api.latest_core_version()
    with pytest.raises(StopRequested):
        api.fetch_core_release_zip("6.8.3")


def test_C8_an_expired_run_budget_refuses_before_the_wp_org_request():
    """C8: the checks built WpOrgApi without the run budget, so an already
    expired --deadline still started a slow wp.org fetch.  The absolute
    budget is capped per request and checked before the network."""
    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    class _NoNetwork:
        def get(self, *_args, **_kwargs):
            raise AssertionError("wp.org must not be reached")

    deadline = Deadline(0.05)
    deadline._started -= 1.0
    api = WpOrgApi(_NoNetwork(), TIMEOUT, deadline=deadline.at)
    with pytest.raises(DeadlineExceeded):
        api.latest_core_version()


@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    """Point the module's .wpt-cache at a per-test tmp directory."""
    d = tmp_path / "cache"
    monkeypatch.setattr(updates, "_CACHE_DIR", d)
    return d


def probe(session):
    """A real SiteProbe over a scripted session (site URL never used)."""
    return SiteProbe(session=session, site=SITE, timeout_s=TIMEOUT)


def audit_data(wp_version=None, plugin_catalog=None, template=None,
               probe_obj=None, mode="ftp", theme_versions=None):
    """A hand-built AuditData with only the update-relevant fields set."""
    catalog = plugin_catalog or {}
    return AuditData(
        mode=mode,
        entries=[],
        siteurl=None,
        home=None,
        template=template,
        blog_public=None,
        wp_version=wp_version,
        mu_plugins=None,
        active_plugins=[
            f for f, m in catalog.items() if m.get("active")
        ],
        plugin_catalog=catalog,
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
        theme_versions=theme_versions or {},
        probe=probe_obj,
    )


def core_response(current="7.1"):
    """A live-shaped core/version-check payload."""
    return FakeResponse(text=json.dumps(
        {"offers": [{"current": current, "version": current}] * 26}
    ))


def plugins_response(updates_bucket, no_update):
    """A live-shaped plugins/update-check payload (buckets may be [] or {})."""
    return FakeResponse(text=json.dumps(
        {"plugins": updates_bucket, "no_update": no_update, "translations": []}
    ))


def themes_response(updates_bucket, no_update):
    """A live-shaped themes/update-check payload (buckets may be [] or {})."""
    return FakeResponse(text=json.dumps(
        {"themes": updates_bucket, "no_update": no_update, "translations": []}
    ))


def assert_sent_headers(kw):
    """Every request carries the identifying UA and the probe timeout."""
    assert kw["headers"]["User-Agent"].startswith("wpt/")
    assert kw["timeout"] == TIMEOUT


class BinaryResponse(FakeResponse):
    """FakeResponse carrying raw ``.content`` bytes — the requests.Response
    binary-body attribute the shared JSON-only fake lacks; the release-zip
    transport reads ``.content``, never ``.text``/``.json()``."""

    def __init__(self, content: bytes, status_code: int = 200) -> None:
        super().__init__(status_code=status_code)
        self.content = content


def release_zip_bytes(paths=("wordpress/wp-includes/version.php",
                             "wordpress/wp-settings.php",
                             "wordpress/wp-admin/about.php")) -> bytes:
    """A small REAL in-memory zip, ``wordpress/``-nested like the official
    releases (the nesting fetch_core_release_zip validates and the
    heal-core action strips)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for path in paths:
            zf.writestr(path, b"<?php\n// " + path.encode("utf-8") + b"\n")
    return buf.getvalue()


# ------------------------------------------------------------------- core


def test_wp_org_settings_override_reaches_the_core_check(tmp_path, monkeypatch):
    """The profile's wp_org section is the production transport owner: a
    cache dir, cache TTL, User-Agent and URL override must reach the check,
    not silently fall back to the dataclass defaults."""
    monkeypatch.setattr(updates, "_CACHE_DIR", None)
    cfg = replace(
        DEFAULTS.wp_org,
        core_version_check_url="https://updates.test/check/{locale}",
        cache_dir=str(tmp_path / "cache"),
        user_agent_template="wpt-test/{version}",
    )
    settings = replace(DEFAULTS, wp_org=cfg)
    session = FakeSession([core_response("7.1")])
    d = audit_data(wp_version="6.5", probe_obj=probe(session))

    findings = check_updates_core(d, settings)

    assert [f.detail for f in findings] == ["6.5 -> 7.1"]
    url, kw = session.gets[0]
    assert url == "https://updates.test/check/en_US"
    assert kw["headers"]["User-Agent"].startswith("wpt-test/")
    api = updates.WpOrgApi(session, TIMEOUT, config=cfg)
    assert api._cache_dir == tmp_path / "cache"
    assert api._config.cache_ttl_s == cfg.cache_ttl_s


def test_core_outdated_found(cache_dir):
    session = FakeSession([core_response("7.1")])
    d = audit_data(wp_version="6.5", probe_obj=probe(session))
    findings = check_updates_core(d, DEFAULTS)
    assert [
        (f.category, f.name, f.detail, f.bytes, f.count, f.risk, f.fix)
        for f in findings
    ] == [
        ("updates.core", "core-update", "6.5 -> 7.1", 0, 1, "medium", CORE_FIX),
    ]
    findings[0].validate()
    # R3 request shape: the version-check URL (locale per R3), UA, timeout
    assert len(session.gets) == 1 and len(session.posts) == 0
    url, kw = session.gets[0]
    assert url == updates.DEFAULT_WP_ORG.core_version_check_url.format(locale=updates.DEFAULT_WP_ORG.default_locale)
    assert_sent_headers(kw)


def test_core_current_silent(cache_dir):
    session = FakeSession([core_response("6.8.3")])
    d = audit_data(wp_version="6.8.3", probe_obj=probe(session))
    assert check_updates_core(d, DEFAULTS) == []
    assert len(session.gets) == 1  # the check DID ask wp.org


def test_core_wp_version_none_silent(cache_dir):
    session = FakeSession()
    d = audit_data(wp_version=None, probe_obj=probe(session))
    assert check_updates_core(d, DEFAULTS) == []
    assert session.gets == [] and session.posts == []  # no request at all


def test_core_probe_none_silent(cache_dir):
    session = FakeSession()
    d = audit_data(wp_version="6.5", probe_obj=None)
    assert check_updates_core(d, DEFAULTS) == []
    assert session.gets == [] and session.posts == []


def test_R13_wporg_transport_always_verifies_tls(monkeypatch, tmp_path):
    """R13-P1-6: ``WpOrgApi`` inherited the site session's verify flag
    (``http.verify_tls=false`` is the default, and ``--override-ip`` builds
    a ``verify=False`` session).  Checksums AND release zips were fetched
    unauthenticated, so a MITM could supply a matching malicious map+zip.
    WpOrgApi owns wp.org endpoints: its requests force ``verify=True``
    independently of the site session."""
    import json as json_mod
    import shutil
    import ssl
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    import requests

    import wpt.audit.updates as updates_mod
    from wpt.dnsoverride import ensure_cert

    payload = {"offers": [{"response": "upgrade", "current": "6.8.4",
                           "version": "6.8.4", "php_version": "7.4",
                           "mysql_version": "5.5.5"}]}

    # 1. The transport seam receives an explicit verify=True even though
    #    the site session was built verify=False.
    session = FakeSession([FakeResponse(200, json_mod.dumps(payload))])
    session.verify = False
    fetched = WpOrgApi(session, TIMEOUT)._request_json(
        "GET", updates_mod._CORE_CHECK_URL, None)
    assert fetched == payload
    assert session.gets and session.gets[0][1]["verify"] is True

    # 2. A self-signed local endpoint is REFUSED: verification is real, not
    #    just a kwarg on a double.
    if shutil.which("openssl") is None:
        pytest.skip("openssl is required to build the self-signed endpoint")
    cert_path, key_path = ensure_cert(tmp_path / "certs")

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 — http.server contract
            body = json_mod.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # silence the test's server
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"https://127.0.0.1:{server.server_address[1]}/version-check"
        site_session = requests.Session()
        site_session.trust_env = False
        site_session.verify = False  # exactly --override-ip / verify_tls=false
        assert WpOrgApi(site_session, 5)._request_json("GET", url, None) is None
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        site_session.close()


def test_core_unusable_payload_silent(cache_dir, wpt_caplog):
    session = FakeSession([FakeResponse(text="{}")])  # no offers key
    d = audit_data(wp_version="6.5", probe_obj=probe(session))
    assert check_updates_core(d, DEFAULTS) == []
    warns = [r for r in wpt_caplog.records
             if r.name == "wpt.audit.updates" and r.levelno == logging.WARNING]
    assert len(warns) == 1
    assert "unusable" in warns[0].getMessage()


# ---------------------------------------------------------------- plugins


def test_plugins_request_shape(cache_dir):
    session = FakeSession([plugins_response([], [])])
    catalog = {
        "akismet/akismet.php": {"name": "Akismet", "version": "5.0.0", "active": True},
        "hello.php": {"name": "", "version": "1.0", "active": False},
        "toolkit/toolkit.php": {"name": "Toolkit", "version": "2.1", "active": True},
    }
    d = audit_data(plugin_catalog=catalog, probe_obj=probe(session))
    assert check_updates_plugins(d, DEFAULTS) == []  # nothing outdated
    # ONE bulk POST, no GET, no per-slug info/1.2 request
    assert len(session.posts) == 1 and len(session.gets) == 0
    url, kw = session.posts[0]
    assert url == updates.DEFAULT_WP_ORG.plugins_update_check_url
    assert_sent_headers(kw)
    data = kw["data"]
    assert set(data) == {"plugins", "translations", "locale", "all"}
    assert json.loads(data["plugins"]) == {
        "plugins": {
            "akismet/akismet.php": {"Name": "Akismet", "Version": "5.0.0"},
            # a nameless plugin falls back to the folder slug (R3's
            # derivation); a single-file plugin IS its own slug
            "hello.php": {"Name": "hello.php", "Version": "1.0"},
            "toolkit/toolkit.php": {"Name": "Toolkit", "Version": "2.1"},
        },
        "active": ["akismet/akismet.php", "toolkit/toolkit.php"],
    }
    assert data["translations"] == "[]"
    assert data["locale"] == '["en_US"]'
    assert data["all"] == "true"


def test_plugins_updates_aggregate(cache_dir):
    session = FakeSession([plugins_response(
        {
            "akismet/akismet.php": {
                "new_version": "5.7.2",
                "url": "https://wordpress.org/plugins/akismet/",
                "package": "https://downloads.wordpress.org/plugin/akismet.5.7.2.zip",
            },
            "contact-form-7/wp-contact-form-7.php": {
                "new_version": "6.0.1",
                # no "url": the package zip is the fallback detail link
                "package": "https://downloads.wordpress.org/plugin/contact-form-7.6.0.1.zip",
            },
            # an INACTIVE plugin is still installed — its update matters
            "classic-editor/classic-editor.php": {"new_version": "1.6.4"},
        },
        [],  # live shape: an empty no_update bucket serializes as []
    )])
    catalog = {
        "contact-form-7/wp-contact-form-7.php": {"name": "CF7", "version": "5.9", "active": True},
        "akismet/akismet.php": {"name": "Akismet", "version": "5.0.0", "active": True},
        "classic-editor/classic-editor.php": {"name": "CE", "version": "1.6.3", "active": False},
        "some-premium/main.php": {"name": "Premium", "version": "2.0", "active": True},
    }
    before = {f: dict(m) for f, m in catalog.items()}
    d = audit_data(plugin_catalog=catalog, probe_obj=probe(session))
    findings = check_updates_plugins(d, DEFAULTS)
    assert [
        (f.category, f.name, f.detail, f.count, f.risk, f.fix)
        for f in findings
    ] == [
        (
            "updates.plugins", "plugin-updates",
            # slug: current -> new (url), sorted by plugin file; the
            # premium entry (absent from both buckets) is silent
            "akismet: 5.0.0 -> 5.7.2 (https://wordpress.org/plugins/akismet/)\n"
            "classic-editor: 1.6.3 -> 1.6.4\n"
            "contact-form-7: 5.9 -> 6.0.1 "
            "(https://downloads.wordpress.org/plugin/contact-form-7.6.0.1.zip)",
            3, "medium", PLUGIN_FIX,
        ),
    ]
    findings[0].validate()
    assert d.plugin_catalog == before  # the check never mutates its data


def test_plugins_detail_truncates_at_eight(cache_dir):
    catalog = {
        f"p{i:02d}/p{i:02d}.php": {"name": f"P{i:02d}", "version": "1.0", "active": True}
        for i in range(10)
    }
    bucket = {
        f"p{i:02d}/p{i:02d}.php": {"new_version": "9.9"}  # no url at all
        for i in range(10)
    }
    session = FakeSession([plugins_response(bucket, [])])
    d = audit_data(plugin_catalog=catalog, probe_obj=probe(session))
    findings = check_updates_plugins(d, DEFAULTS)
    assert len(findings) == 1
    f = findings[0]
    assert f.count == 10  # the count covers ALL updates
    assert f.detail == "\n".join(
        f"p{i:02d}: 1.0 -> 9.9" for i in range(8)
    ) + "\n(+2 more)"


def test_plugins_no_update_only_silent(cache_dir):
    session = FakeSession([plugins_response(
        [], {"akismet/akismet.php": {"new_version": "5.7.2"}},
    )])
    d = audit_data(
        plugin_catalog={"akismet/akismet.php": {"name": "Akismet", "version": "5.7.2", "active": True}},
        probe_obj=probe(session),
    )
    assert check_updates_plugins(d, DEFAULTS) == []


def test_plugins_premium_absent_silent(cache_dir):
    session = FakeSession([plugins_response([], [])])  # the live premium answer
    d = audit_data(
        plugin_catalog={"some-premium/main.php": {"name": "P", "version": "2.0", "active": True}},
        probe_obj=probe(session),
    )
    assert check_updates_plugins(d, DEFAULTS) == []


def test_plugins_empty_bucket_list_shape(cache_dir):
    # PHP's empty map serializes as [] — a bucket arriving as [] is empty
    session = FakeSession([plugins_response([], [])])
    d = audit_data(
        plugin_catalog={"a/a.php": {"name": "A", "version": "1.0", "active": True}},
        probe_obj=probe(session),
    )
    assert check_updates_plugins(d, DEFAULTS) == []


def test_plugins_empty_bucket_dict_shape(cache_dir):
    # ...and the same bucket arriving as {} is equally accepted
    session = FakeSession([plugins_response({}, {})])
    d = audit_data(
        plugin_catalog={"a/a.php": {"name": "A", "version": "1.0", "active": True}},
        probe_obj=probe(session),
    )
    assert check_updates_plugins(d, DEFAULTS) == []


def test_plugins_catalog_empty_silent(cache_dir):
    session = FakeSession()
    d = audit_data(plugin_catalog={}, probe_obj=probe(session))
    assert check_updates_plugins(d, DEFAULTS) == []
    assert session.gets == [] and session.posts == []


def test_plugins_versionless_mixed(cache_dir):
    session = FakeSession([plugins_response(
        {"akismet/akismet.php": {"new_version": "5.7.2"}}, [],
    )])
    catalog = {
        "noversion/noversion.php": {"name": "NV", "version": "", "active": True},
        "akismet/akismet.php": {"name": "Akismet", "version": "5.0.0", "active": True},
    }
    d = audit_data(plugin_catalog=catalog, probe_obj=probe(session))
    findings = check_updates_plugins(d, DEFAULTS)
    assert len(findings) == 1
    assert findings[0].count == 1
    assert findings[0].detail == "akismet: 5.0.0 -> 5.7.2"
    # the ""-version entry was never sent
    sent = json.loads(session.posts[0][1]["data"]["plugins"])
    assert set(sent["plugins"]) == {"akismet/akismet.php"}


def test_plugins_all_versionless_silent(cache_dir):
    session = FakeSession()
    d = audit_data(
        plugin_catalog={"noversion/noversion.php": {"name": "NV", "version": "", "active": True}},
        probe_obj=probe(session),
    )
    assert check_updates_plugins(d, DEFAULTS) == []
    assert session.gets == [] and session.posts == []  # nothing to ask


def test_plugins_network_failure_silent(cache_dir, wpt_caplog):
    session = FakeSession([requests.ConnectionError("boom")])
    d = audit_data(
        plugin_catalog={"a/a.php": {"name": "A", "version": "1.0", "active": True}},
        probe_obj=probe(session),
    )
    assert check_updates_plugins(d, DEFAULTS) == []
    warns = [r for r in wpt_caplog.records
             if r.name == "wpt.audit.updates" and r.levelno == logging.WARNING]
    assert len(warns) == 1
    assert "no cached response" in warns[0].getMessage()


# ----------------------------------------------------------------- themes


def test_theme_update_available(cache_dir):
    session = FakeSession([themes_response(
        {
            "twentytwentyfour": {
                "new_version": "1.6",
                "url": "https://wordpress.org/themes/twentytwentyfour/",
                "package": "https://downloads.wordpress.org/theme/twentytwentyfour.1.6.zip",
            },
        },
        [],
    )])
    d = audit_data(template="twentytwentyfour",
                   theme_versions={"twentytwentyfour": "1.4"},
                   probe_obj=probe(session))
    findings = check_updates_themes(d, DEFAULTS)
    assert [
        (f.category, f.name, f.detail, f.count, f.risk, f.fix)
        for f in findings
    ] == [
        (
            "updates.themes", "theme-updates",
            "twentytwentyfour: 1.4 -> 1.6 "
            "(https://wordpress.org/themes/twentytwentyfour/)",
            1, "medium", THEME_FIX,
        ),
    ]
    findings[0].validate()
    # ONE bulk POST, R3 themes shape: keyed by slug WITH real versions
    # (style.css header), no "all" field
    assert len(session.posts) == 1 and len(session.gets) == 0
    url, kw = session.posts[0]
    assert url == updates.DEFAULT_WP_ORG.themes_update_check_url
    assert_sent_headers(kw)
    data = kw["data"]
    assert set(data) == {"themes", "translations", "locale"}
    assert json.loads(data["themes"]) == {
        "active": "twentytwentyfour",
        "themes": {"twentytwentyfour": {"Name": "twentytwentyfour",
                                        "Version": "1.4"}},
    }
    assert data["translations"] == "[]"
    assert data["locale"] == '["en_US"]'


def test_theme_no_update_silent(cache_dir):
    session = FakeSession([themes_response(
        [], {"twentytwentyfour": {"new_version": "1.6"}},  # dict-shaped bucket
    )])
    d = audit_data(template="twentytwentyfour",
                   theme_versions={"twentytwentyfour": "1.6"},
                   probe_obj=probe(session))
    assert check_updates_themes(d, DEFAULTS) == []


def test_theme_premium_absent_silent(cache_dir):
    session = FakeSession([themes_response([], [])])
    d = audit_data(template="custom-child-theme",
                   theme_versions={"custom-child-theme": "1.0"},
                   probe_obj=probe(session))
    assert check_updates_themes(d, DEFAULTS) == []


def test_theme_no_version_silent(cache_dir):
    # style.css unreadable / header absent => version unknown => the slug is
    # neither sent nor reported (never a guess, never permanent noise)
    session = FakeSession()
    d = audit_data(template="twentytwentyfour", theme_versions={},
                   probe_obj=probe(session))
    assert check_updates_themes(d, DEFAULTS) == []
    assert session.gets == [] and session.posts == []


def test_theme_template_none_silent(cache_dir):
    session = FakeSession()
    d = audit_data(template=None, probe_obj=probe(session))
    assert check_updates_themes(d, DEFAULTS) == []
    assert session.gets == [] and session.posts == []


def test_theme_entry_without_new_version(cache_dir):
    session = FakeSession([themes_response(
        {"twentytwentyfour": {"url": "https://wordpress.org/themes/twentytwentyfour/"}},
        [],
    )])
    d = audit_data(template="twentytwentyfour",
                   theme_versions={"twentytwentyfour": "1.4"},
                   probe_obj=probe(session))
    assert check_updates_themes(d, DEFAULTS) == []


# ------------------------------------------------------------------ cache


def test_cache_second_call_within_ttl(cache_dir):
    session = FakeSession([core_response("7.1")])
    d = audit_data(wp_version="6.5", probe_obj=probe(session))
    assert check_updates_core(d, DEFAULTS)[0].detail == "6.5 -> 7.1"
    assert len(session.gets) == 1
    # within the TTL the second call is served WITHOUT any network (the
    # scripted session would raise on an unexpected extra request)
    assert check_updates_core(d, DEFAULTS)[0].detail == "6.5 -> 7.1"
    assert len(session.gets) == 1


def test_cache_fresh_fetch_writes_file(cache_dir):
    session = FakeSession([core_response("7.1")])
    d = audit_data(wp_version="6.5", probe_obj=probe(session))
    check_updates_core(d, DEFAULTS)
    path = cache_dir / (_cache_key(updates.DEFAULT_WP_ORG.core_version_check_url.format(locale=updates.DEFAULT_WP_ORG.default_locale), None) + ".json")
    assert path.is_file()
    assert json.loads(path.read_text(encoding="utf-8"))["offers"][0]["current"] == "7.1"


def test_cache_stale_reused_on_failure(cache_dir, wpt_caplog):
    session = FakeSession([core_response("7.1")])
    d = audit_data(wp_version="6.5", probe_obj=probe(session))
    check_updates_core(d, DEFAULTS)
    path = cache_dir / (_cache_key(updates.DEFAULT_WP_ORG.core_version_check_url.format(locale=updates.DEFAULT_WP_ORG.default_locale), None) + ".json")
    # age the cache file past the TTL with utime (no sleeps)
    aged = time.time() - (updates.DEFAULT_WP_ORG.cache_ttl_s + 400)
    os.utime(path, (aged, aged))
    # the network now fails — the stale entry still answers
    failing = FakeSession([requests.ConnectionError("boom")])
    d2 = audit_data(wp_version="6.5", probe_obj=probe(failing))
    findings = check_updates_core(d2, DEFAULTS)
    assert [f.detail for f in findings] == ["6.5 -> 7.1"]
    assert len(failing.gets) == 1  # one fetch was attempted
    warns = [r for r in wpt_caplog.records
             if r.name == "wpt.audit.updates" and r.levelno == logging.WARNING]
    assert len(warns) == 1
    assert "stale" in warns[0].getMessage()


def test_cache_no_cache_failure_silent(cache_dir, wpt_caplog):
    session = FakeSession([requests.ConnectionError("boom")])
    d = audit_data(wp_version="6.5", probe_obj=probe(session))
    assert check_updates_core(d, DEFAULTS) == []
    warns = [r for r in wpt_caplog.records
             if r.name == "wpt.audit.updates" and r.levelno == logging.WARNING]
    assert len(warns) == 1
    assert "no cached response" in warns[0].getMessage()


def test_cache_corrupt_file_refetched(cache_dir):
    path = cache_dir / (_cache_key(updates.DEFAULT_WP_ORG.core_version_check_url.format(locale=updates.DEFAULT_WP_ORG.default_locale), None) + ".json")
    cache_dir.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json", encoding="utf-8")
    session = FakeSession([core_response("7.1")])
    d = audit_data(wp_version="6.5", probe_obj=probe(session))
    assert check_updates_core(d, DEFAULTS)[0].detail == "6.5 -> 7.1"
    assert len(session.gets) == 1  # the corrupt file was a miss: refetched
    assert json.loads(path.read_text(encoding="utf-8"))["offers"][0]["current"] == "7.1"


# -------------------------------------------------------------- release zip


def test_release_zip_fetch_caches_bytes(cache_dir):
    payload = release_zip_bytes()
    session = FakeSession([BinaryResponse(payload)])
    assert WpOrgApi(session, TIMEOUT).fetch_core_release_zip("6.8.3") == payload
    # request shape: the live-verified URL template, UA, probe timeout
    assert len(session.gets) == 1 and len(session.posts) == 0
    url, kw = session.gets[0]
    assert url == updates.DEFAULT_WP_ORG.core_release_zip_url.format(version="6.8.3")
    assert_sent_headers(kw)
    # the raw bytes land under the (monkeypatched) .wpt-cache
    path = cache_dir / "wp-release-6.8.3.zip"
    assert path.is_file()
    assert path.read_bytes() == payload


def test_release_zip_fresh_cache_hit_no_network(cache_dir, wpt_caplog):
    payload = release_zip_bytes()
    session = FakeSession([BinaryResponse(payload)])
    api = WpOrgApi(session, TIMEOUT)
    assert api.fetch_core_release_zip("6.8.3") == payload
    assert len(session.gets) == 1
    # within the TTL a second call serves from disk: the session it
    # would ride is scripted to FAIL, proving no network happens
    failing = FakeSession([requests.ConnectionError("boom")])
    assert WpOrgApi(failing, TIMEOUT).fetch_core_release_zip("6.8.3") == payload
    assert failing.gets == []
    warns = [r for r in wpt_caplog.records
             if r.name == "wpt.audit.updates" and r.levelno == logging.WARNING]
    assert warns == []  # a fresh hit is not a failure: no warning


def test_release_zip_stale_reused_on_failure(cache_dir, wpt_caplog):
    payload = release_zip_bytes()
    session = FakeSession([BinaryResponse(payload)])
    assert WpOrgApi(session, TIMEOUT).fetch_core_release_zip("6.8.3") == payload
    path = cache_dir / "wp-release-6.8.3.zip"
    # age the cache file past the TTL with utime (no sleeps)
    aged = time.time() - (updates.DEFAULT_WP_ORG.cache_ttl_s + 400)
    os.utime(path, (aged, aged))
    # the network now fails — the stale entry still answers
    failing = FakeSession([requests.ConnectionError("boom")])
    assert WpOrgApi(failing, TIMEOUT).fetch_core_release_zip("6.8.3") == payload
    assert len(failing.gets) == 1  # one fetch was attempted
    warns = [r for r in wpt_caplog.records
             if r.name == "wpt.audit.updates" and r.levelno == logging.WARNING]
    assert len(warns) == 1
    assert "stale" in warns[0].getMessage()


def test_release_zip_no_cache_failure_none(cache_dir, wpt_caplog):
    failing = FakeSession([requests.ConnectionError("boom")])
    assert WpOrgApi(failing, TIMEOUT).fetch_core_release_zip("6.8.3") is None
    warns = [r for r in wpt_caplog.records
             if r.name == "wpt.audit.updates" and r.levelno == logging.WARNING]
    assert len(warns) == 1
    assert "no cached response" in warns[0].getMessage()


def test_release_zip_corrupt_payload_rejected(cache_dir, wpt_caplog):
    # plain non-zip garbage fails the magic + central-directory gates; a
    # real zip nested under the WRONG prefix fails the wordpress/ gate
    # — both are corrupt downloads: failed fetches, never returned lies
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("other/readme.txt", b"not the official nesting")
    wrong_prefix = buf.getvalue()
    for payload in (b"not a zip at all", wrong_prefix):
        session = FakeSession([BinaryResponse(payload)])
        assert WpOrgApi(session, TIMEOUT).fetch_core_release_zip("6.8.3") is None
        assert len(session.gets) == 1
    warns = [r for r in wpt_caplog.records
             if r.name == "wpt.audit.updates" and r.levelno == logging.WARNING]
    assert len(warns) == 2  # exactly ONE warning per corrupt download
    assert all("no cached response" in w.getMessage() for w in warns)
    # a corrupt download is never written to the cache
    assert list(cache_dir.glob("*")) == []


def test_release_zip_corrupt_cache_refetched(cache_dir):
    payload = release_zip_bytes()
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / "wp-release-6.8.3.zip"
    path.write_bytes(b"PK\x03\x04 torn mid-write garbage")  # magic, no zip
    session = FakeSession([BinaryResponse(payload)])
    assert WpOrgApi(session, TIMEOUT).fetch_core_release_zip("6.8.3") == payload
    assert len(session.gets) == 1  # the corrupt entry was a miss: refetched
    assert path.read_bytes() == payload  # and rewritten


def test_release_zip_corrupt_stale_never_served(cache_dir, wpt_caplog):
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / "wp-release-6.8.3.zip"
    path.write_bytes(b"PK\x03\x04 torn mid-write garbage")
    aged = time.time() - (updates.DEFAULT_WP_ORG.cache_ttl_s + 400)
    os.utime(path, (aged, aged))
    failing = FakeSession([requests.ConnectionError("boom")])
    # a corrupt entry is NOT a fallback: the failed fetch degrades to
    # None rather than ever returning a lie
    assert WpOrgApi(failing, TIMEOUT).fetch_core_release_zip("6.8.3") is None
    warns = [r for r in wpt_caplog.records
             if r.name == "wpt.audit.updates" and r.levelno == logging.WARNING]
    assert len(warns) == 1
    assert "no cached response" in warns[0].getMessage()


@pytest.mark.parametrize("bad", [
    "", "   ", "6.8/../../wp", "6 8", "6.8.3\n", "../6.8", "6.8;rm", None,
])
def test_release_zip_bad_version_raises(bad):
    session = FakeSession()  # empty script: any request would assert
    with pytest.raises(WptError):
        WpOrgApi(session, TIMEOUT).fetch_core_release_zip(bad)
    assert session.gets == []  # refused loudly before any request


def test_release_zip_good_versions_validate(cache_dir):
    payload = release_zip_bytes()
    asked: list[tuple[str, dict]] = []

    def respond(method, url, kwargs):
        asked.append((url, kwargs))
        return BinaryResponse(payload)

    session = FakeSession([respond, respond, respond])
    api = WpOrgApi(session, TIMEOUT)
    # dots, dashes and case all pass the [A-Za-z0-9.-] gate
    for version in ("6.8.3", "6.8-beta2", "7.1-RC1"):
        assert api.fetch_core_release_zip(version) == payload
        assert_sent_headers(asked[-1][1])
    assert [url for url, _kw in asked] == [
        updates.DEFAULT_WP_ORG.core_release_zip_url.format(version=v)
        for v in ("6.8.3", "6.8-beta2", "7.1-RC1")
    ]
    # one cache file per version, the version in the filename
    assert sorted(p.name for p in cache_dir.glob("wp-release-*")) == [
        "wp-release-6.8-beta2.zip",
        "wp-release-6.8.3.zip",
        "wp-release-7.1-RC1.zip",
    ]


# ------------------------------------------------- localized release zips
#
# [L17] the localized-migration lesson: a localized BUILD lives at its
# dash-subdomain on wordpress.org (live-verified for 6.6 across fr_CA,
# de_DE, de_DE_formal, pt_BR, zh_CN, en_CA — all HTTP 200
# application/zip, wordpress/-nested), NOT under
# downloads.wordpress.org/release (that host 404s the localized name).


def test_core_release_zip_url_resolver():
    """The locale→URL resolver (ONE authoritative owner): en_US stays
    on the downloads host; every other locale maps underscore→dash
    subdomain, whole locale in the filename.  Live-verified
    against downloads.wordpress.org (HTTP 206 on a ranged GET) for
    7.1: fr_CA, de_DE, pt_BR, zh_CN all serve their build, so a locale
    whose build does not exist is the 404 shape heal-core falls back
    from with ONE warning (the fr_CA 404 test in tests/actions/
    test_heal_core.py pins that path)."""
    assert updates.core_release_zip_url("6.8.3", "en_US") == (
        "https://downloads.wordpress.org/release/wordpress-6.8.3.zip"
    )
    assert updates.core_release_zip_url("7.1", "fr_CA") == (
        "https://fr-ca.wordpress.org/wordpress-7.1-fr_CA.zip"
    )
    assert updates.core_release_zip_url("7.1", "de_DE") == (
        "https://de-de.wordpress.org/wordpress-7.1-de_DE.zip"
    )
    assert updates.core_release_zip_url("7.1", "pt_BR") == (
        "https://pt-br.wordpress.org/wordpress-7.1-pt_BR.zip"
    )
    assert updates.core_release_zip_url("7.1", "zh_CN") == (
        "https://zh-cn.wordpress.org/wordpress-7.1-zh_CN.zip"
    )
    assert updates.core_release_zip_url("6.6", "de_DE_formal") == (
        "https://de-de-formal.wordpress.org/wordpress-6.6-de_DE_formal.zip"
    )
    assert updates.core_release_zip_url("6.6", "pt_BR") == (
        "https://pt-br.wordpress.org/wordpress-6.6-pt_BR.zip"
    )
    # invalid version / locale: refused loudly before any URL is built
    for bad in ("", "6 8", "../x", None):
        with pytest.raises(WptError):
            updates.core_release_zip_url(bad, "en_US")
    for bad in ("", "fr/CA", "fr_CA;rm", "../evil", None):
        with pytest.raises(WptError):
            updates.core_release_zip_url("6.8.3", bad)


@pytest.mark.parametrize("bad", [
    "", "fr/CA", "fr_CA;rm", "../evil", None,
])
def test_release_zip_bad_locale_raises(bad):
    session = FakeSession()  # empty script: any request would assert
    with pytest.raises(WptError):
        WpOrgApi(session, TIMEOUT).fetch_core_release_zip("6.8.3", bad)
    assert session.gets == []  # refused loudly before any request


def test_release_zip_fr_ca_fetch_caches_bytes(cache_dir):
    """[L17] fetch_core_release_zip(version, locale): the fr_CA build
    downloads from its dash-subdomain URL and caches under its own
    locale-suffixed name (one entry per distribution — an fr_CA audit +
    heal share one download; the en_US fallback never collides)."""
    payload = release_zip_bytes()
    session = FakeSession([BinaryResponse(payload)])
    assert WpOrgApi(session, TIMEOUT).fetch_core_release_zip(
        "6.8.3", "fr_CA") == payload
    assert len(session.gets) == 1 and session.posts == []
    url, kw = session.gets[0]
    assert url == updates.core_release_zip_url("6.8.3", "fr_CA")
    assert url == "https://fr-ca.wordpress.org/wordpress-6.8.3-fr_CA.zip"
    assert_sent_headers(kw)
    path = cache_dir / "wp-release-6.8.3-fr_CA.zip"
    assert path.read_bytes() == payload
    # a separate en_US entry for the same version, same cache dir
    en_payload = release_zip_bytes(("wordpress/index.php",))
    session2 = FakeSession([BinaryResponse(en_payload)])
    assert WpOrgApi(session2, TIMEOUT).fetch_core_release_zip(
        "6.8.3") == en_payload
    assert (cache_dir / "wp-release-6.8.3.zip").read_bytes() == en_payload
    assert sorted(p.name for p in cache_dir.glob("wp-release-*")) == [
        "wp-release-6.8.3-fr_CA.zip",
        "wp-release-6.8.3.zip",
    ]


# --------------------------------------------------------- registry wiring


def test_registry_integration():
    checks = {rec.name: rec for rec in all_checks()}
    for name, func in (
        ("updates.core", check_updates_core),
        ("updates.plugins", check_updates_plugins),
        ("updates.themes", check_updates_themes),
    ):
        rec = checks[name]
        assert rec.applies == ("ftp", "local")
        assert rec.func is func
    assert [r.name for r in select_checks("ftp", ["updates"], None)] == [
        "updates.core", "updates.plugins", "updates.themes",
    ]
    assert [r.name for r in select_checks("local", ["updates"], None)] == [
        "updates.core", "updates.plugins", "updates.themes",
    ]


def test_run_checks_end_to_end(cache_dir):
    catalog = {
        "akismet/akismet.php": {"name": "Akismet", "version": "5.0.0", "active": True},
        "some-premium/main.php": {"name": "Premium", "version": "2.0", "active": True},
    }
    # run order is name-sorted: core (GET), plugins (POST), themes (POST)
    session = FakeSession([
        core_response("7.1"),
        plugins_response({"akismet/akismet.php": {"new_version": "5.7.2"}}, []),
        themes_response(
            {"twentytwentyfour": {"new_version": "1.6",
                                  "url": "https://wordpress.org/themes/twentytwentyfour/"}},
            [],
        ),
    ])
    d = audit_data(
        wp_version="6.5", plugin_catalog=catalog,
        template="twentytwentyfour",
        theme_versions={"twentytwentyfour": "1.4"},
        probe_obj=probe(session),
    )
    findings = run_checks(d, DEFAULTS, "ftp", ["updates"], None)
    assert [(f.category, f.name) for f in findings] == [
        ("updates.core", "core-update"),
        ("updates.plugins", "plugin-updates"),
        ("updates.themes", "theme-updates"),
    ]
    for f in findings:
        f.validate()
    # one distinct cache file per request (core GET + two bulk POSTs)
    assert sorted(p.name for p in cache_dir.iterdir()) == sorted([
        _cache_key(updates.DEFAULT_WP_ORG.core_version_check_url.format(locale=updates.DEFAULT_WP_ORG.default_locale), None) + ".json",
        _cache_key(updates.DEFAULT_WP_ORG.plugins_update_check_url, _plugin_form(catalog)) + ".json",
        _cache_key(updates.DEFAULT_WP_ORG.themes_update_check_url,
                   _theme_form({"twentytwentyfour": "1.4"})) + ".json",
    ])
    # a second full run within the TTL is served entirely from the cache
    assert run_checks(d, DEFAULTS, "ftp", ["updates"], None) == findings
    assert len(session.gets) == 1 and len(session.posts) == 2
    # local mode stays silent (no probe, unknown versions/catalog) and
    # makes no request
    local = audit_data(
        wp_version=None, plugin_catalog={}, template=None,
        probe_obj=None, mode="local",
    )
    assert run_checks(local, DEFAULTS, "local", ["updates"], None) == []
    assert len(session.gets) == 1 and len(session.posts) == 2


def _plugin_form(catalog):
    """The canonical bulk-plugins form fields for ``catalog`` (cache key)."""
    return {
        "plugins": json.dumps(
            {
                "plugins": {
                    f: {"Name": m["name"] or f.split("/")[0], "Version": m["version"]}
                    for f, m in sorted(catalog.items())
                },
                "active": sorted(
                    f for f, m in catalog.items() if m["active"]
                ),
            },
            sort_keys=True,
        ),
        "translations": "[]",
        "locale": json.dumps([updates.DEFAULT_WP_ORG.default_locale]),
        "all": "true",
    }


def _theme_form(themes):
    """The canonical bulk-themes form fields for ``themes`` (cache key)."""
    return {
        "themes": json.dumps(
            {"active": next(iter(themes), ""),
             "themes": {slug: {"Name": slug, "Version": version}
                        for slug, version in themes.items()}}, sort_keys=True
        ),
        "translations": "[]",
        "locale": json.dumps([updates.DEFAULT_WP_ORG.default_locale]),
    }


# ---------------------------------------------------------------- theme zip


def theme_zip_bytes(slug="twentytwentyfive",
                    paths=("style.css", "readme.txt")) -> bytes:
    """A small REAL in-memory THEME release zip, ``<slug>/``-nested like
    the official theme releases (the nesting fetch_theme_zip validates
    and the integrity skew cross-check strips)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for path in paths:
            zf.writestr(f"{slug}/{path}", b"/* " + path.encode("utf-8")
                        + b" */\n")
    return buf.getvalue()


def test_theme_zip_fetch_caches_bytes(cache_dir):
    """[L12] The official theme release zip: the live-verified URL shape,
    the slug-prefixed validation, the identifying UA + probe timeout,
    and the theme-<slug>-<version>.zip cache filename."""
    payload = theme_zip_bytes()
    asked: list[tuple[str, dict]] = []

    def respond(method, url, kwargs):
        asked.append((url, kwargs))
        return BinaryResponse(payload)

    session = FakeSession([respond])
    api = WpOrgApi(session, TIMEOUT)
    assert api.fetch_theme_zip("twentytwentyfive", "1.5") == payload
    assert asked[0][0] == (
        "https://downloads.wordpress.org/theme/twentytwentyfive.1.5.zip"
    )
    assert_sent_headers(asked[0][1])
    assert sorted(p.name for p in cache_dir.glob("theme-*")) == [
        "theme-twentytwentyfive-1.5.zip",
    ]
    # the fresh cache serves the second call with no network
    assert api.fetch_theme_zip("twentytwentyfive", "1.5") == payload
    assert len(asked) == 1


@pytest.mark.parametrize("bad", ["", " ", "../evil", "a b", "theme/zip"])
def test_theme_zip_bad_slug_raises(bad):
    session = FakeSession()  # empty script: any request would assert
    with pytest.raises(WptError):
        WpOrgApi(session, TIMEOUT).fetch_theme_zip(bad, "1.5")
    assert session.gets == []  # refused loudly before any request


@pytest.mark.parametrize("bad", ["", " ", "../6.8.3", "v 1"])
def test_theme_zip_bad_version_raises(bad):
    session = FakeSession()
    with pytest.raises(WptError):
        WpOrgApi(session, TIMEOUT).fetch_theme_zip("twentytwentyfive", bad)
    assert session.gets == []


def test_theme_zip_wrong_prefix_rejected(cache_dir):
    """A zip not nested under ``<slug>/`` is a corrupt download — a
    failed fetch (None after the one warning), never a returned lie."""
    payload = release_zip_bytes()  # wordpress/-nested, NOT slug-nested
    session = FakeSession([BinaryResponse(payload)])
    assert WpOrgApi(session, TIMEOUT).fetch_theme_zip(
        "twentytwentyfive", "1.5"
    ) is None
    assert not list(cache_dir.glob("theme-*"))  # never cached


# ------------------------------------------------ round 12 (P1/P2 regressions)


class _BoundedResponse(FakeResponse):
    """A response double exposing the real transport's bounded body seam."""

    def __init__(self, payload: bytes) -> None:
        super().__init__(text=payload.decode("utf-8"))
        self.payload = payload
        self.limit: int | None = None

    def read_bounded(self, limit: int) -> bytes:
        self.limit = limit
        if len(self.payload) > limit:
            raise WptError(f"response body exceeds the {limit}-byte bound")
        return self.payload


def test_R12_P1_checksum_map_larger_than_the_probe_excerpt_is_read(
        cache_dir):
    """R12-P1-1: the real 7.1 checksum map is 327,182 bytes; the probe's
    256 KiB excerpt bound made a cold-cache audit report check_failed.
    The wp.org JSON reader carries its own structural bound and the exact
    real-map size parses."""
    from wpt.audit.integrity import _checksums_url, _fetch_checksums

    prefix = b'{"checksums":{"wp-load.php":"' + b"a" * 32 + b'","pad":"'
    suffix = b'"}}'
    payload = prefix + b"b" * (327182 - len(prefix) - len(suffix)) + suffix
    assert len(payload) == 327182
    response = _BoundedResponse(payload)
    session = FakeSession([response])
    checksums = _fetch_checksums("7.1", session, TIMEOUT)
    assert checksums is not None
    assert checksums["wp-load.php"] == "a" * 32
    assert response.limit == updates.DEFAULT_WP_ORG.json_max_bytes
    assert response.limit > 262144
    assert session.gets[0][0] == _checksums_url("7.1", "en_US")


def test_R12_P1_oversize_wp_org_body_degrades_with_one_warning(
        cache_dir, wpt_caplog):
    """R12-P1-1: an over-limit answer is ONE failed fetch, never a
    check_failed finding that hides every checksum."""
    from wpt.audit.integrity import _fetch_checksums

    class _Oversize(FakeResponse):
        def read_bounded(self, limit: int) -> bytes:
            raise WptError(f"response body exceeds the {limit}-byte bound")

    session = FakeSession([_Oversize()])
    assert _fetch_checksums("7.1", session, TIMEOUT) is None
    warns = [r for r in wpt_caplog.records
             if r.name == "wpt.audit.updates" and r.levelno == logging.WARNING]
    assert len(warns) == 1
    assert "no cached response" in warns[0].getMessage()


def _post_drip_server(payload: bytes, *, delay: float = 0.2):
    """A real TCP server: read one POST, then drip its body byte by byte."""
    import socket
    import threading

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)
    port = listener.getsockname()[1]

    def _serve():
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        try:
            conn.settimeout(5)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            head, _, body = data.partition(b"\r\n\r\n")
            length = 0
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    length = int(line.split(b":", 1)[1].strip())
            while len(body) < length:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                body += chunk
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                + f"Content-Length: {len(payload)}\r\n\r\n".encode())
            for index in range(len(payload)):
                conn.sendall(payload[index:index + 1])
                time.sleep(delay)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
            listener.close()

    worker = threading.Thread(target=_serve, daemon=True)
    worker.start()
    return port, worker, listener


def test_R12_P1_wp_org_post_body_is_bounded_by_the_absolute_deadline(
        monkeypatch, cache_dir):
    """R12-P1-2/R20-P1: a dripped POST body is bounded by the absolute
    deadline and the expiry is a STOP, not "wp.org unavailable" (which used
    to return None and let the caller finish rc 0 after its budget)."""
    from wpt.types import DeadlineExceeded

    port, worker, listener = _post_drip_server(b'{"themes":{},"no_update":{}}')
    monkeypatch.setattr(
        updates, "_THEMES_CHECK_URL",
        f"http://127.0.0.1:{port}/themes/update-check/1.1/")
    session = requests.Session()
    session.trust_env = False
    try:
        started = time.monotonic()
        with pytest.raises(DeadlineExceeded):
            WpOrgApi(
                session, 5, deadline=time.monotonic() + 0.35,
            ).bulk_theme_check({"tw": "1.2"})
        elapsed = time.monotonic() - started
    finally:
        session.close()
        try:
            listener.close()
        except OSError:
            pass
        worker.join(timeout=3)

    assert elapsed < 1.0, elapsed


def test_R12_P2_fresh_zip_cache_does_not_hide_an_expired_deadline(cache_dir):
    """R12-P2-14: a fresh cached zip returned before the deadline check, so
    an already-expired run still produced release bytes."""
    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    payload = release_zip_bytes()
    session = FakeSession([BinaryResponse(payload)])
    assert WpOrgApi(session, TIMEOUT).fetch_core_release_zip("6.8.3") == payload
    spent = Deadline(0.05)
    spent._started -= 1.0
    with pytest.raises(DeadlineExceeded):
        WpOrgApi(FakeSession(), TIMEOUT,
                 deadline=spent.at).fetch_core_release_zip("6.8.3")


def test_R12_P2_owned_session_close_never_masks_the_body_failure(
        wpt_caplog):
    """R12-P2-7: a close() RunControl overrode the body's primary WptError
    (and escaped through the action's error contract).  The primary wins;
    on a clean body the stop is re-raised."""
    from wpt.audit.updates import owned_session
    from wpt.types import StopRequested

    class _Closer:
        def close(self) -> None:
            raise StopRequested("SIGTERM during close")

    with pytest.raises(WptError, match="PRIMARY"):
        with owned_session(_Closer(), True):
            raise WptError("PRIMARY")
    assert any("primary" in r.getMessage()
               for r in wpt_caplog.records
               if r.name == "wpt.audit.updates")

    with pytest.raises(StopRequested):
        with owned_session(_Closer(), True):
            pass


def _drip_get_server(payload: bytes, *, delay: float = 0.05,
                     content_type: str = "application/json"):
    """A real HTTP server that answers one GET and drips the body."""
    import http.server
    import threading

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            try:
                for index in range(len(payload)):
                    self.wfile.write(payload[index:index + 1])
                    self.wfile.flush()
                    time.sleep(delay)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return (f"http://127.0.0.1:{server.server_port}", server, thread)


def _age_cache(path: Path) -> None:
    aged = time.time() - (updates.DEFAULT_WP_ORG.cache_ttl_s + 400)
    os.utime(path, (aged, aged))


def test_R20_stale_json_cache_never_hides_an_expired_deadline(
        cache_dir, monkeypatch):
    """A spent --deadline during a GET must be a STOP even when a stale
    cache entry exists: the old failure path served the stale dict (or
    None) and the command could finish rc 0 after its budget."""
    from wpt.types import DeadlineExceeded

    site, server, thread = _drip_get_server(b'{"offers":[]}')
    url = f"{site}/core/version-check/1.7/"
    monkeypatch.setattr(updates, "_CORE_CHECK_URL", url)
    path = cache_dir / (updates._cache_key(url, None) + ".json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"offers": [{"current": "9.9.9"}]}),
                    encoding="utf-8")
    _age_cache(path)
    session = requests.Session()
    session.trust_env = False
    try:
        with pytest.raises(DeadlineExceeded):
            WpOrgApi(session, 5,
                     deadline=time.monotonic() + 0.3,
                     ).latest_core_version()
    finally:
        session.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_R20_stale_zip_cache_never_hides_an_expired_deadline(
        cache_dir, monkeypatch):
    """The binary twin: a stale VALID release/theme zip must not answer a
    fetch whose --deadline expired mid-body."""
    from wpt.types import DeadlineExceeded

    payload = release_zip_bytes(("wordpress/wp-settings.php",))
    site, server, thread = _drip_get_server(payload, content_type="application/zip")
    monkeypatch.setattr(
        updates, "_CORE_RELEASE_ZIP_URL", site + "/wordpress-{version}.zip")
    path = cache_dir / "wp-release-9.9.9.zip"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    _age_cache(path)
    session = requests.Session()
    session.trust_env = False
    try:
        with pytest.raises(DeadlineExceeded):
            WpOrgApi(session, 5,
                     deadline=time.monotonic() + 0.3,
                     ).fetch_core_release_zip("9.9.9")
    finally:
        session.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_R20_integrity_checksums_deadline_is_a_stop(
        cache_dir, monkeypatch):
    """The integrity check's map fetch rides the same transport: an expired
    budget after a real drip raises, never a stale map/None degrade."""
    from wpt.audit import integrity
    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    site, server, thread = _drip_get_server(b'{"checksums":{"wp-load.php":"x"}}')
    url = f"{site}/core/checksums/1.0/"
    monkeypatch.setattr(integrity, "_checksums_url",
                        lambda version, locale, config=None: url)
    path = cache_dir / (updates._cache_key(url, None) + ".json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"checksums": {"wp-load.php": "x"}}),
                    encoding="utf-8")
    _age_cache(path)
    session = requests.Session()
    session.trust_env = False
    try:
        with pytest.raises(DeadlineExceeded):
            integrity._fetch_checksums(
                "9.9.9", session, 5, deadline=Deadline(0.3))
    finally:
        session.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_R14_truncated_chunked_body_is_one_failed_fetch(cache_dir, wpt_caplog):
    """R14-P2: ``read_bounded`` may raise a requests transport error
    (ChunkedEncodingError/ContentDecodingError) for a truncated body.  It
    escaped ``_request_json`` and the registry reported a spurious HIGH
    check_failed instead of the documented one-warning stale degrade."""
    class _Truncated(FakeResponse):
        def read_bounded(self, limit: int) -> bytes:
            raise requests.exceptions.ChunkedEncodingError(
                "response ended prematurely")

    session = FakeSession([_Truncated()])
    api = WpOrgApi(session, TIMEOUT)
    url = "https://api.wordpress.org/core/version-check/1.7/"
    assert api._request_json("GET", url, None) is None
    warns = [r for r in wpt_caplog.records
             if r.name == "wpt.audit.updates" and r.levelno == logging.WARNING]
    assert len(warns) == 1
    assert "no cached response" in warns[0].getMessage()


def test_R21_per_request_timeout_degrades_without_spending_the_run(
        cache_dir, monkeypatch, wpt_caplog):
    """R21-P1: a long --deadline must not turn into a long PER-REQUEST
    bound.  The transport gets min(run, now + timeout_s), so a dripping
    wp.org still degrades to None after the profile timeout."""
    site, server, thread = _drip_get_server(b'{"offers":[]}', delay=0.2)
    monkeypatch.setattr(updates, "_CORE_CHECK_URL",
                        f"{site}/core/version-check/1.7/")
    session = requests.Session()
    session.trust_env = False
    try:
        started = time.monotonic()
        answer = WpOrgApi(
            session, 0.2, deadline=time.monotonic() + 5.0,
        ).latest_core_version()
        elapsed = time.monotonic() - started
    finally:
        session.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert answer is None
    assert elapsed < 1.0, elapsed
    assert any("no cached response" in r.getMessage()
               for r in wpt_caplog.records
               if r.name == "wpt.audit.updates")


def test_R21_per_request_timeout_still_serves_a_stale_cache(
        cache_dir, monkeypatch):
    """The SAME bound on the failure path: a per-request timeout is an
    unavailable answer (stale cache), never a run stop while the run
    budget remains."""
    site, server, thread = _drip_get_server(b'{"offers":[]}', delay=0.2)
    url = f"{site}/core/version-check/1.7/"
    monkeypatch.setattr(updates, "_CORE_CHECK_URL", url)
    path = cache_dir / (updates._cache_key(url, None) + ".json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"offers": [{"current": "9.9.9"}]}),
                    encoding="utf-8")
    _age_cache(path)
    session = requests.Session()
    session.trust_env = False
    try:
        started = time.monotonic()
        answer = WpOrgApi(
            session, 0.2, deadline=time.monotonic() + 5.0,
        ).latest_core_version()
        elapsed = time.monotonic() - started
    finally:
        session.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert answer == "9.9.9"
    assert elapsed < 1.0, elapsed


def test_R21_a_spent_run_still_raises_at_the_per_request_bound(
        cache_dir, monkeypatch):
    """The other half of the two bounds: when the RUN budget is the sooner
    instant, the same transport expiry is DeadlineExceeded (rc 1), not a
    silent stale/None degrade."""
    from wpt.types import DeadlineExceeded

    site, server, thread = _drip_get_server(b'{"offers":[]}', delay=0.2)
    monkeypatch.setattr(updates, "_CORE_CHECK_URL",
                        f"{site}/core/version-check/1.7/")
    session = requests.Session()
    session.trust_env = False
    try:
        started = time.monotonic()
        with pytest.raises(DeadlineExceeded):
            WpOrgApi(
                session, 5.0, deadline=time.monotonic() + 0.3,
            ).latest_core_version()
        elapsed = time.monotonic() - started
    finally:
        session.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert elapsed < 1.5, elapsed
