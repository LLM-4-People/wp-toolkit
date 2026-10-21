"""Behavioral tests for the live site walker (wpt.walk) — W7a.

A REAL ThreadingHTTPServer on 127.0.0.1:0 (http.server in a daemon thread,
finalizer in the fixture — the test_dnsoverride / test_bridge_php
convention) plays the WordPress site: every route is fixture-built markup,
the server records every (method, path) it sees, and the walker runs over
a plain trust_env=False session with delay_s=0.  No external hosts, no
DNS, no sleeps beyond the 0 politeness delay.

Test -> behavior map (W7a task list):
  test_walkresult_field_order ............... WalkResult's pinned positional
        field order (live_refs, pages, forms, fetched)
  test_live_refs_exact_set ................... the binding media contract:
        uploads-relative, percent-decoded, query-stripped, same-host only
  test_L11_css_only_background_lands_in_refs . [L11] a background named in NO
        served HTML (only inside elementor CSS) still lands in live_refs
  test_pages_visit_order_and_dedup .......... homepage first, sitemap seed
        second, duplicate + query/fragment links collapse
  test_forms_detected_never_submitted ....... forms cataloged (absolute,
        sorted, deduped); the server saw GET ONLY — nothing was ever POSTed
  test_external_links_and_assets_ignored ..... external pages never crawled,
        external uploads-looking assets never become refs
  test_fetch_dedupe_and_count ................ fetched counts every request;
        a duplicated <link> stylesheet is fetched exactly once
  test_non_html_links_enqueue_nothing ........ an a[href] to an uploads file
        is a REF but never a page; a .pdf link neither crawls nor refs
  test_max_pages_cap ........................ max_pages caps visits
  test_max_depth_cap ........................ homepage depth 1; chain
        a->b->c with max_depth 2 stops at a
  test_sitemap_missing_degrades_one_warning .. no sitemap: homepage+links
        crawl, exactly ONE warning
  test_sitemap_index_children ............... sitemap index -> child sitemap
        pages crawled (same-host children only)
  test_broken_page_continues ................. a 404 page warns, stays in
        pages, and the crawl continues
  test_css_fetch_failure_silent ............... a 404 stylesheet is skipped
        silently; its markup href stays a ref
  test_dead_site_never_raises ................. connection-refused site:
        partial WalkResult, warnings, no exception
  test_url_normalization ...................... query/fragment dropped, dot
        segments collapsed, page paths stay percent-encoded, ref tails decode
  test_base_href_resolution .................. <base href> rewires relative
        asset resolution
  test_follows_page_redirects ................. a redirecting page is fetched
        and parsed at its final URL
  test_actionless_form_records_page_url ....... <form> with no action records
        the document URL

  The response-size bound (``walk.max_response_bytes``), a MEMORY bound
  applied while the body STREAMS — every answer the crawler takes, a page,
  a sitemap and a stylesheet alike.  The 40 MB answers below are GENERATED
  by the local server in 64 KiB chunks (never a fixture file, never a
  40 MB string in the test process), because the only way to prove the
  refused memory is bounded is to refuse a real stream:

  test_oversized_response_is_refused_not_downloaded . a 40 MB page under
        a 1 MB bound: one warning naming the URL and the bound, nothing
        parsed from it, the attempt still in ``pages``, the rest of the
        crawl intact, and no MemoryError
  test_a_normal_page_still_parses_under_a_bound . the same full-site
        fixture under the tight bound parses identically to unbounded
  test_the_shipped_default_fits_a_real_document . the shipped default
        leaves a realistic rendered page (markup + srcset + a generated
        stylesheet) completely alone
  test_an_oversized_stylesheet_is_refused_too . an over-budget ASSET is
        refused the same way, and its markup href still counts as a ref
  test_the_bound_is_read_from_the_profile_not_the_module . the same page
        above and below the bound — the knob is a profile key

The run_walk tests (the ``wpt walk`` CLI body) drive run_walk(ctx) with
real Ctx objects the way the CLI's _lazy_call invokes it.  BOTH seams are
monkeypatched — ``wpt.audit.remote_stack`` (the function-level import
seam, the tests/test_verify.py convention) and ``wpt.walk.walk_site`` (a
canned WalkResult; the real walker stays pinned by the server tests
above) — so these need no server, no network, no threads.  stdout is
captured with capsys; log assertions ride the wpt_caplog fixture (caplog
alone cannot see wpt.* records — the wpt parent does not propagate).

  test_run_walk_local_mode_refusal ... local mode: rc 1, the refusal
        error logged, both seams never called, and the shared failure
        report pair written
  test_run_walk_report_and_stdout .... happy path: rc 0; the report
        written to --report is the pinned markdown (header + summary,
        Pages in visit order, refs sorted, forms listed) and stdout is
        exactly it plus print's newline; bridge destroyed once, source
        closed once, one info summary logged
  test_run_walk_empty_sections_absent . zero refs + zero forms: those
        sections ABSENT from the report (Pages stays); without --report
        the report still prints — the pinned stdout surface
  test_run_walk_stack_failure_returns_1 . remote_stack raising WptError:
        rc 1, "walk failed" logged, walk_site never runs, the shared
        failure report pair written, never a traceback
  test_run_walk_failure_path_teardown .. a WptError from the walk (the
        unexpected path): rc 1, the shared failure report pair written,
        and the finally still destroys the bridge exactly once and
        closes the source
  test_run_walk_passes_ctx_arguments ... walk_site receives exactly the
        stack's session, ctx.wp_url, ctx.settings.walk and
        ctx.settings.http.timeout_s
  test_run_walk_writes_json_twin .......... with --report the .md AND its
        .json twin exist; the JSON parses and carries the site, the
        pages in VISIT order (not sorted), the SORTED live refs, the
        forms and the fetch count as an int
  test_run_walk_json_twin_empty_collections  zero refs + zero forms: the
        .json twin is still written and carries EMPTY lists
  test_run_walk_no_report_no_json ......... without --report NEITHER file
        is written; stdout is the markdown report only
"""

import json
import logging
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests

import wpt.audit
import wpt.walk
from wpt.cli import Ctx
from wpt.settings import WalkSettings, load
from wpt.types import StopRequested, WptError
from wpt.walk import WalkResult, walk_site

from tests.fakes import SERVE_POLL_INTERVAL_S

#: Every walk runs with zero politeness delay (pinned) and a generous cap.
FAST = WalkSettings(max_pages=200, delay_s=0.0, max_depth=5)


class _SiteHandler(BaseHTTPRequestHandler):
    """Serves ``httpd.routes[path] = (status, content_type, body[,
    headers])``; records every (method, path) in ``httpd.hits``.  POST is
    answered 405 — the walker must never send one.

    A body given as an INT is a SIZE: that many bytes of filler are
    generated and written in 64 KiB chunks, so a test can make a 40 MB
    answer without building a 40 MB string in the test process (and
    without a fixture file) — the oversized-response bound is exercised
    against a real stream, which is the only way to prove the memory it
    refuses is bounded.
    """

    protocol_version = "HTTP/1.1"

    def _respond(self, status, content_type, body, extra=()):
        if isinstance(body, int):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(body))
            for name, value in extra:
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                chunk = b"x" * 65536
                left = body
                try:
                    while left > 0:
                        self.wfile.write(chunk[:min(left, len(chunk))])
                        left -= min(left, len(chunk))
                except (BrokenPipeError, ConnectionResetError):
                    return          # the walker refused and hung up: the point
            return
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        for name, value in extra:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD" and data:
            self.wfile.write(data)

    def _dispatch(self):
        self.server.hits.append((self.command, self.path))
        route = self.server.routes.get(self.path)
        if route is None:
            self._respond(404, "text/plain; charset=utf-8", "not found")
            return
        self._respond(route[0], route[1], route[2],
                      route[3] if len(route) > 3 else ())

    def do_GET(self):
        self._dispatch()

    do_HEAD = do_GET

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or "0")
        if length:
            self.rfile.read(length)
        self.server.hits.append((self.command, self.path))
        self._respond(405, "text/plain; charset=utf-8", "method not allowed")

    def log_message(self, fmt, *args):
        pass  # quiet: the module under test logs through wpt.log


@pytest.fixture()
def serve():
    """One REAL local HTTP server per test (routes are assigned by the test
    once the port is known); the finalizer stops it."""
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _SiteHandler)
    httpd.routes = {}
    httpd.hits = []
    thread = threading.Thread(
        target=lambda: httpd.serve_forever(
            poll_interval=SERVE_POLL_INTERVAL_S),
        daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=5)


@pytest.fixture()
def session():
    """Plain trust_env=False session (env-proxy hijack guard)."""
    s = requests.Session()
    s.trust_env = False
    yield s
    s.close()


@pytest.fixture()
def wpt_caplog(caplog):
    """caplog wired to the non-propagating wpt logger tree (the wpt parent
    has propagate=False — see tests/audit/test_registry.py)."""
    parent = logging.getLogger("wpt")
    parent.addHandler(caplog.handler)
    with caplog.at_level(logging.DEBUG, logger="wpt"):
        yield caplog
    parent.removeHandler(caplog.handler)


def _base(httpd):
    return f"http://127.0.0.1:{httpd.server_address[1]}"


def _html(body, status=200):
    return (status, "text/html; charset=utf-8",
            f"<!doctype html><html><body>{body}</body></html>")


def _paths(httpd):
    return [path for _method, path in httpd.hits]


def _warnings(caplog):
    return [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]


def _full_site_routes(base):
    """Homepage + page-a + an elementor stylesheet under uploads + sitemap.

    css-only-bg.jpg [L11] appears ONLY inside the stylesheet.  Two <link>
    tags point at the SAME stylesheet (fetch-dedupe pin).  The img
    missing-but-referenced.jpg has NO route: refs come from markup, not
    fetches.  only-linked.jpg is referenced ONLY by an <a href> (a download
    link — a real media use, never a page).
    """
    css = (
        '.hero { background-image: url("/wp-content/uploads/2023/10/css-only-bg.jpg"); }\n'
        ".q { background: url(  '/wp-content/uploads/2023/10/css-quoted.png' ) no-repeat; }\n"
        '.r { background-image: url("2023/10/css-rel.jpg"); }\n'
        '.s { background-image: url("/wp-content/uploads/2023/10/bg2.jpg?ver=5"); }\n'
        '.t { background-image: url("/wp-content/uploads/2023/10/caf%C3%A9.jpg"); }\n'
        '.x { background-image: url("https://cdn.example.com/wp-content/uploads/2023/10/not-ours.jpg"); }\n'
        '.y { background-image: url("data:image/svg+xml;base64,AAAA"); }\n'
    )
    home = """<!doctype html><html><head>
<link rel="icon" href="/wp-content/uploads/2021/09/cropped-favicon-32x32.png">
<link rel="stylesheet" href="/wp-content/uploads/elementor/css/post-1.css">
<link rel="stylesheet" href="/wp-content/uploads/elementor/css/post-1.css">
<style>.inline { background: url(/wp-content/uploads/2023/10/inline-bg.jpg); }</style>
</head><body>
<img src="/wp-content/uploads/2023/10/pic-300x233.jpg" srcset="/wp-content/uploads/2023/10/pic.jpg 1024w, /wp-content/uploads/2023/10/pic-300x233.jpg 300w, /wp-content/uploads/2023/10/alt.jpg 1.5x">
<img src="/wp-content/uploads/2023/10/with%20space.jpg">
<img src="/wp-content/uploads/2023/10/missing-but-referenced.jpg">
<img src="https://cdn.example.com/wp-content/uploads/2023/10/external.jpg">
<a href="/page-a/">page a</a>
<a href="/page-a/?utm=nav#nav">page a again</a>
<a href="https://external.example/page">external</a>
<a href="/wp-content/uploads/2023/10/only-linked.jpg">download</a>
<a href="/docs/manual.pdf">pdf</a>
<form action="/contact/" method="post"></form>
<form action="submit-handler" method="get"></form>
</body></html>"""
    page_a = """<!doctype html><html><head></head><body>
<picture>
<source srcset="/wp-content/uploads/2023/10/pic-800.webp 800w, /wp-content/uploads/2023/10/pic-400.webp 400w">
<img src="/wp-content/uploads/2023/10/pic.jpg">
</picture>
<video src="/wp-content/uploads/2023/10/clip.mp4" poster="/wp-content/uploads/2023/10/poster.jpg"></video>
<audio src="/wp-content/uploads/2023/10/sound.mp3"></audio>
<script src="/wp-content/uploads/2023/10/tracked.js"></script>
<img src="../wp-content/uploads/2023/10/rel-img.jpg">
</body></html>"""
    sitemap = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        f"<url><loc>{base}/</loc></url>"
        f"<url><loc>{base}/page-a/</loc></url>"
        "</urlset>"
    )
    return {
        "/": _html(home),
        "/page-a/": _html(page_a),
        "/wp-content/uploads/elementor/css/post-1.css":
            (200, "text/css; charset=utf-8", css),
        "/sitemap.xml": (200, "application/xml; charset=utf-8", sitemap),
    }


# --------------------------------------------------------------- the contract


def test_walkresult_field_order():
    """The pinned WalkResult shape: (live_refs, pages, forms, fetched)."""
    result = WalkResult({"a.jpg"}, ["http://x/"], ["http://x/f"], 3)
    assert (result.live_refs, result.pages, result.forms, result.fetched) \
        == ({"a.jpg"}, ["http://x/"], ["http://x/f"], 3)


def test_live_refs_exact_set(serve, session):
    base = _base(serve)
    serve.routes = _full_site_routes(base)
    result = walk_site(session, base, FAST)
    assert isinstance(result.live_refs, set)
    assert result.live_refs == {
        # link hrefs (icon rel + the uploads stylesheet itself)
        "2021/09/cropped-favicon-32x32.png",
        "elementor/css/post-1.css",
        # inline <style> url()
        "2023/10/inline-bg.jpg",
        # img src + srcset (descriptors dropped; duplicate collapses)
        "2023/10/pic-300x233.jpg",
        "2023/10/pic.jpg",
        "2023/10/alt.jpg",
        # percent-DECODED tail
        "2023/10/with space.jpg",
        # a markup ref whose asset has no route (refs != fetches)
        "2023/10/missing-but-referenced.jpg",
        # a[href] to an uploads file (download link)
        "2023/10/only-linked.jpg",
        # picture/source srcset + img, video src+poster, audio src, script,
        # and a relative ../wp-content/... img on /page-a/
        "2023/10/pic-800.webp",
        "2023/10/pic-400.webp",
        "2023/10/pic.jpg",
        "2023/10/clip.mp4",
        "2023/10/poster.jpg",
        "2023/10/sound.mp3",
        "2023/10/tracked.js",
        "2023/10/rel-img.jpg",
        # url() refs from the fetched elementor stylesheet
        "2023/10/css-only-bg.jpg",
        "2023/10/css-quoted.png",
        "elementor/css/2023/10/css-rel.jpg",  # relative url() resolution
        "2023/10/bg2.jpg",                   # query stripped
        "2023/10/café.jpg",                  # percent-decoded url()
    }


def test_L11_css_only_background_lands_in_refs(serve, session):
    """[L11] the background exists ONLY inside the elementor stylesheet —
    it appears in no served HTML — and still lands in live_refs."""
    base = _base(serve)
    routes = _full_site_routes(base)
    serve.routes = routes
    result = walk_site(session, base, FAST)
    assert "2023/10/css-only-bg.jpg" in result.live_refs
    for path in ("/", "/page-a/"):  # the pin: no HTML route mentions it
        assert "css-only-bg.jpg" not in routes[path][2]


def test_pages_visit_order_and_dedup(serve, session):
    base = _base(serve)
    serve.routes = _full_site_routes(base)
    result = walk_site(session, base, FAST)
    assert isinstance(result.pages, list)
    # homepage first, sitemap seed second; the plain and the ?utm#nav link
    # to the same page collapse into one entry
    assert result.pages == [f"{base}/", f"{base}/page-a/"]


def test_forms_detected_never_submitted(serve, session):
    base = _base(serve)
    serve.routes = _full_site_routes(base)
    result = walk_site(session, base, FAST)
    assert result.forms == [f"{base}/contact/", f"{base}/submit-handler"]
    # NEVER submitted: the server saw GET only, and no action URL was even
    # fetched (form actions are cataloged, not navigated)
    assert all(method == "GET" for method, _path in serve.hits)
    paths = _paths(serve)
    assert "/contact/" not in paths and "/submit-handler" not in paths


def test_external_links_and_assets_ignored(serve, session):
    base = _base(serve)
    serve.routes = _full_site_routes(base)
    result = walk_site(session, base, FAST)
    # external pages are never crawled...
    assert all("external.example" not in page for page in result.pages)
    # ...and external hosts with uploads-looking paths are NOT this site's
    # files — neither the <img> nor the CSS url() one becomes a ref
    assert "2023/10/external.jpg" not in result.live_refs
    assert "2023/10/not-ours.jpg" not in result.live_refs
    # the external host was never even dialed (no route exists for it)
    assert all("cdn.example.com" not in path for path in _paths(serve))


def test_fetch_dedupe_and_count(serve, session):
    base = _base(serve)
    serve.routes = _full_site_routes(base)
    result = walk_site(session, base, FAST)
    # sitemap.xml + sitemap_index.xml (404) + two pages + the stylesheet
    # (the duplicate <link> is fetched exactly once); the stylesheet is
    # fetched while PROCESSING the homepage, before the next page dequeues
    assert result.fetched == 5
    assert _paths(serve) == [
        "/sitemap.xml",
        "/sitemap_index.xml",
        "/",
        "/wp-content/uploads/elementor/css/post-1.css",
        "/page-a/",
    ]


def test_non_html_links_enqueue_nothing(serve, session):
    base = _base(serve)
    serve.routes = _full_site_routes(base)
    result = walk_site(session, base, FAST)
    # an a[href] to an uploads file is a REFERENCE but never a page: it has
    # no route, so a visit would have left a 404 hit
    assert "2023/10/only-linked.jpg" in result.live_refs
    assert f"{base}/wp-content/uploads/2023/10/only-linked.jpg" not in result.pages
    assert "/wp-content/uploads/2023/10/only-linked.jpg" not in _paths(serve)
    # a .pdf link is neither crawled nor a ref
    assert all("manual.pdf" not in page for page in result.pages)
    assert all("manual.pdf" not in ref for ref in result.live_refs)


# ------------------------------------------------------------- crawl budgets


def test_max_pages_cap(serve, session):
    base = _base(serve)
    serve.routes = {
        "/": _html('<a href="/p1/"></a><a href="/p2/"></a><a href="/p3/"></a>'),
        "/p1/": _html("p1"),
        "/p2/": _html("p2"),
        "/p3/": _html("p3"),
    }
    result = walk_site(
        session, base, WalkSettings(max_pages=2, delay_s=0.0, max_depth=5)
    )
    # the homepage + exactly one more page; p2/p3 have routes but are never
    # fetched — the cap prunes visits, not just listings
    assert result.pages == [f"{base}/", f"{base}/p1/"]
    assert "/p2/" not in _paths(serve) and "/p3/" not in _paths(serve)


def test_max_depth_cap(serve, session):
    base = _base(serve)
    serve.routes = {
        "/": _html('<a href="/a/"></a>'),
        "/a/": _html('<a href="/b/"></a>'),
        "/b/": _html('<a href="/c/"></a>'),
        "/c/": _html("c"),
    }
    result = walk_site(
        session, base, WalkSettings(max_pages=200, delay_s=0.0, max_depth=2)
    )
    # homepage = depth 1, /a/ = depth 2; /b/ would be depth 3: pruned
    assert result.pages == [f"{base}/", f"{base}/a/"]
    assert "/b/" not in _paths(serve) and "/c/" not in _paths(serve)


# ------------------------------------------------------------------ sitemaps


def test_sitemap_missing_degrades_with_one_warning(serve, session, wpt_caplog):
    base = _base(serve)
    serve.routes = {
        "/": _html('<a href="/about/"></a>'),
        "/about/": _html("about"),
    }
    result = walk_site(session, base, FAST)
    # degrade: homepage + links crawl still works...
    assert result.pages == [f"{base}/", f"{base}/about/"]
    # ...with exactly ONE warning about the missing sitemap
    warnings = _warnings(wpt_caplog)
    assert len(warnings) == 1
    assert "sitemap" in warnings[0]


def test_sitemap_index_children(serve, session):
    base = _base(serve)
    serve.routes = {
        "/sitemap.xml": (200, "application/xml; charset=utf-8",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            f"<sitemap><loc>{base}/sitemap-posts.xml</loc></sitemap>"
            "<sitemap><loc>https://external.example/sitemap.xml</loc></sitemap>"
            "</sitemapindex>"),
        "/sitemap-posts.xml": (200, "application/xml; charset=utf-8",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            f"<url><loc>{base}/page-b/</loc></url>"
            "</urlset>"),
        # deliberately no links on the homepage: page-b is reachable ONLY
        # through the child sitemap
        "/": _html("home"),
        "/page-b/": _html('<img src="/wp-content/uploads/2023/10/from-sitemap.jpg">'),
    }
    result = walk_site(session, base, FAST)
    assert result.pages == [f"{base}/", f"{base}/page-b/"]
    assert "2023/10/from-sitemap.jpg" in result.live_refs
    # sitemap.xml + sitemap_index.xml (404) + child sitemap + two pages
    assert result.fetched == 5


# --------------------------------------------------------- failure semantics


def test_broken_page_continues(serve, session, wpt_caplog):
    base = _base(serve)
    serve.routes = {
        "/": _html('<a href="/broken/"></a><a href="/ok/"></a>'),
        "/ok/": _html('<img src="/wp-content/uploads/2023/10/ok-img.jpg">'),
        # /broken/ has no route: a 404 page
    }
    result = walk_site(session, base, FAST)
    # the attempt stays listed (visit order), the crawl continued, and the
    # good page's ref was still collected
    assert result.pages == [f"{base}/", f"{base}/broken/", f"{base}/ok/"]
    assert "2023/10/ok-img.jpg" in result.live_refs
    assert any("/broken/" in w for w in _warnings(wpt_caplog))


def test_css_fetch_failure_silent(serve, session, wpt_caplog):
    base = _base(serve)
    serve.routes = {
        "/": _html(
            '<link rel="stylesheet" href="/wp-content/uploads/elementor/css/gone.css">'
            '<img src="/wp-content/uploads/2023/10/still-ref.jpg">'
        ),
        "/sitemap.xml": (200, "application/xml; charset=utf-8",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            f"<url><loc>{base}/</loc></url></urlset>"),
        # gone.css has no route: the stylesheet fetch 404s — silently
    }
    result = walk_site(session, base, FAST)
    # the stylesheet href itself is a markup ref that stays; its url()
    # refs are simply lost; no warning is emitted for an asset failure
    assert result.live_refs == {"elementor/css/gone.css", "2023/10/still-ref.jpg"}
    assert _warnings(wpt_caplog) == []


def test_dead_site_never_raises(session, wpt_caplog):
    # a bound-then-closed port: nothing listens, connections are refused
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    dead_port = probe.getsockname()[1]
    probe.close()
    base = f"http://127.0.0.1:{dead_port}"
    result = walk_site(session, base, FAST)  # must not raise
    assert result.pages == [f"{base}/"]
    assert result.live_refs == set()
    assert result.forms == []
    # sitemap.xml + sitemap_index.xml + homepage: three attempts, all refused
    assert result.fetched == 3
    warnings = _warnings(wpt_caplog)
    assert len([w for w in warnings if "sitemap" in w]) == 1  # the ONE warning
    assert any(base in w for w in warnings)                   # homepage failure


# -------------------------------------------------------------- normalization


def test_url_normalization(serve, session):
    base = _base(serve)
    serve.routes = {
        "/": _html(
            '<a href="/norm/page%20two/?q=1#top"></a>'
            '<a href="/a/./b/"></a>'
            '<img src="/wp-content/uploads/2023/10/norm.jpg?v=9#frag">'
        ),
        # requests sends the %20 exactly as received, so the route key is
        # the encoded path the server actually sees
        "/norm/page%20two/": _html("encoded page"),
        "/a/b/": _html('<img src="/wp-content/uploads/2023/10/dots.jpg">'),
    }
    result = walk_site(session, base, FAST)
    # page identity: query + fragment dropped, "." collapsed, percent-
    # encoding PRESERVED (the fetched URL is the encoded one)
    assert result.pages == [
        f"{base}/",
        f"{base}/norm/page%20two/",
        f"{base}/a/b/",
    ]
    # the img ref: query/fragment stripped, tail percent-DECODED
    assert result.live_refs == {"2023/10/norm.jpg", "2023/10/dots.jpg"}


def test_base_href_resolution(serve, session):
    base = _base(serve)
    serve.routes = {
        "/": _html(f'<base href="{base}/wp-content/uploads/2023/10/">'
                   "<img src='based.jpg'>"),
    }
    result = walk_site(session, base, FAST)
    assert result.live_refs == {"2023/10/based.jpg"}


def test_follows_page_redirects(serve, session):
    base = _base(serve)
    serve.routes = {
        "/": _html('<a href="/moved/"></a>'),
        "/moved/": (302, "text/html; charset=utf-8", "",
                    (("Location", f"{base}/target/"),)),
        "/target/": _html('<img src="/wp-content/uploads/2023/10/target-img.jpg">'),
    }
    result = walk_site(session, base, FAST)
    assert f"{base}/moved/" in result.pages
    # followed to /target/ and parsed there: its asset was collected
    assert "2023/10/target-img.jpg" in result.live_refs


def test_actionless_form_records_page_url(serve, session):
    base = _base(serve)
    serve.routes = {"/": _html("<form method='post'></form>")}
    result = walk_site(session, base, FAST)
    assert result.forms == [f"{base}/"]


# ---------------------------------------------------------- run_walk (CLI)


class _RecordingBridge:
    """Lifecycle-only bridge double: counts destroy() calls."""

    def __init__(self) -> None:
        self.destroyed = 0

    def destroy(self) -> None:
        self.destroyed += 1


class _ClosableSource:
    """Source double for the finally-path getattr close guard."""

    def __init__(self) -> None:
        self.closed = 0

    def close(self) -> None:
        self.closed += 1


def _canned(pages=(), refs=(), forms=(), fetched=0):
    """A walk_site double: records every call, returns this WalkResult."""
    calls = []

    def fake(session, site, settings, timeout_s, deadline=None):
        calls.append((session, site, settings, timeout_s))
        return WalkResult(live_refs=set(refs), pages=list(pages),
                          forms=list(forms), fetched=fetched)

    return fake, calls


def _ctx(tmp_path, **overrides):
    kwargs = dict(
        source="ftp://h", settings=load(),
        wp_url="https://site.test", report_path=tmp_path / "walk.md",
    )
    kwargs.update(overrides)
    return Ctx(**kwargs)


def _errors(caplog):
    return [r.getMessage() for r in caplog.records
            if r.name == "wpt.walk" and r.levelno == logging.ERROR]


def test_run_walk_local_mode_refusal(monkeypatch, tmp_path, wpt_caplog):
    """Local mode: rc 1, the pinned refusal error logged, both seams
    never called, and the shared failure report pair written."""
    def _never_stack(ctx):
        raise AssertionError("remote_stack must not be called in local mode")

    def _never_walk(_session, _site, _settings, _timeout_s):
        raise AssertionError("walk_site must not be called in local mode")

    monkeypatch.setattr(wpt.audit, "remote_stack", _never_stack)
    monkeypatch.setattr(wpt.walk, "walk_site", _never_walk)
    ctx = _ctx(tmp_path, source="local")

    assert wpt.walk.run_walk(ctx) == 1
    written = ctx.report_path.read_text("utf-8")
    assert "## This run did not complete" in written
    twin = json.loads(
        ctx.report_path.with_suffix(".json").read_text("utf-8"))
    assert twin["run"]["status"] == "failed"
    assert _errors(wpt_caplog) == [
        "walk requires a live site: ftp mode only "
        "(local mode has no URLs to fetch)"
    ]


def test_run_walk_report_and_stdout(monkeypatch, tmp_path, capsys,
                                     wpt_caplog):
    """Happy path: rc 0; the report carries all three sections in the
    pinned order and shape, is written to --report AND printed (stdout is
    the file content plus print's newline); bridge destroyed once,
    source closed once; one info summary logged."""
    session = object()
    bridge = _RecordingBridge()
    source = _ClosableSource()
    fake, _calls = _canned(
        pages=["https://site.test/", "https://site.test/page-a/"],
        refs={"2023/a.jpg", "z.jpg"},
        forms=["https://site.test/contact"],
        fetched=7,
    )
    monkeypatch.setattr(wpt.audit, "remote_stack",
                        lambda ctx: (source, session, bridge))
    monkeypatch.setattr(wpt.walk, "walk_site", fake)
    ctx = _ctx(tmp_path)

    assert wpt.walk.run_walk(ctx) == 0

    expected = (
        "# wpt walk — https://site.test\n"
        "\n"
        "Crawled 2 pages, found 2 live media references and 1 forms "
        "(7 HTTP fetches).\n"
        "\n"
        "## Pages\n"
        "\n"
        "- https://site.test/\n"
        "- https://site.test/page-a/\n"
        "\n"
        "## Live media references\n"
        "\n"
        "- 2023/a.jpg\n"
        "- z.jpg\n"
        "\n"
        "## Forms\n"
        "\n"
        "- https://site.test/contact\n"
    )
    assert ctx.report_path.read_text(encoding="utf-8") == expected
    assert capsys.readouterr().out == expected + "\n"
    assert bridge.destroyed == 1
    assert source.closed == 1
    infos = [r.getMessage() for r in wpt_caplog.records
             if r.name == "wpt.walk" and r.levelno == logging.INFO]
    assert any("walk: 2 pages" in m for m in infos)


def test_run_walk_empty_sections_absent(monkeypatch, tmp_path, capsys):
    """Zero refs + zero forms: those sections are ABSENT from the report
    (Pages stays); without --report the report still prints — the pinned
    stdout surface.  A None source rides the getattr close guard."""
    bridge = _RecordingBridge()
    fake, _calls = _canned(pages=["https://site.test/"], refs=set(),
                           forms=[], fetched=3)
    monkeypatch.setattr(wpt.audit, "remote_stack",
                        lambda ctx: (None, None, bridge))
    monkeypatch.setattr(wpt.walk, "walk_site", fake)
    ctx = _ctx(tmp_path, report_path=None)

    assert wpt.walk.run_walk(ctx) == 0
    out = capsys.readouterr().out
    assert "## Pages" in out
    assert "- https://site.test/" in out
    assert "## Live media references" not in out
    assert "## Forms" not in out
    assert ("Crawled 1 pages, found 0 live media references and 0 forms "
            "(3 HTTP fetches).") in out
    assert bridge.destroyed == 1


def test_run_walk_stack_failure_returns_1(monkeypatch, tmp_path, wpt_caplog):
    """remote_stack raising WptError: rc 1, the error logged, walk_site
    never runs, and the shared failure report pair is written — never a
    traceback and never a silently absent report."""
    def _boom(ctx):
        raise WptError("no host")

    def _never_walk(_session, _site, _settings, _timeout_s):
        raise AssertionError("walk_site must not run when the stack fails")

    monkeypatch.setattr(wpt.audit, "remote_stack", _boom)
    monkeypatch.setattr(wpt.walk, "walk_site", _never_walk)
    ctx = _ctx(tmp_path)

    assert wpt.walk.run_walk(ctx) == 1
    assert "## This run did not complete" in ctx.report_path.read_text("utf-8")
    assert _errors(wpt_caplog) == ["walk failed: no host"]


def test_run_walk_failure_path_teardown(monkeypatch, tmp_path, wpt_caplog):
    """A WptError from the walk (the unexpected path): rc 1, the error
    logged, the shared failure report pair written — and the finally still
    destroys the bridge exactly once and closes the source."""
    session = object()
    bridge = _RecordingBridge()
    source = _ClosableSource()

    def _raising(_session, _site, _settings, _timeout_s, deadline=None):
        raise WptError("walk blew up")

    monkeypatch.setattr(wpt.audit, "remote_stack",
                        lambda ctx: (source, session, bridge))
    monkeypatch.setattr(wpt.walk, "walk_site", _raising)
    ctx = _ctx(tmp_path)

    assert wpt.walk.run_walk(ctx) == 1
    assert "## This run did not complete" in ctx.report_path.read_text("utf-8")
    assert bridge.destroyed == 1
    assert source.closed == 1
    assert _errors(wpt_caplog) == ["walk failed: walk blew up"]


def test_run_walk_passes_ctx_arguments(monkeypatch, tmp_path):
    """The walk rides the caller's stack pieces: walk_site receives
    exactly (session, wp_url, settings.walk, settings.http.timeout_s)."""
    session = object()
    fake, calls = _canned()
    monkeypatch.setattr(wpt.audit, "remote_stack",
                        lambda ctx: (_ClosableSource(), session,
                                     _RecordingBridge()))
    monkeypatch.setattr(wpt.walk, "walk_site", fake)
    ctx = _ctx(tmp_path)

    assert wpt.walk.run_walk(ctx) == 0
    assert calls == [(session, "https://site.test",
                      ctx.settings.walk, ctx.settings.http.timeout_s)]


def test_run_walk_writes_json_twin(monkeypatch, tmp_path):
    """Happy path with --report: the markdown AND its .json twin are both
    written; the JSON parses and carries the site, the pages in VISIT
    order (zeta before alpha — not sorted), the SORTED live refs, the
    walker-sorted forms and the fetch count as an int."""
    session = object()
    fake, _calls = _canned(
        pages=["https://site.test/zeta/", "https://site.test/alpha/"],
        refs={"z.jpg", "2023/a.jpg", "0.jpg"},
        forms=["https://site.test/contact", "https://site.test/search"],
        fetched=7,
    )
    monkeypatch.setattr(wpt.audit, "remote_stack",
                        lambda ctx: (_ClosableSource(), session,
                                      _RecordingBridge()))
    monkeypatch.setattr(wpt.walk, "walk_site", fake)
    ctx = _ctx(tmp_path)

    assert wpt.walk.run_walk(ctx) == 0

    json_path = ctx.report_path.with_suffix(".json")
    assert ctx.report_path.exists() and json_path.exists()
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data == {
        "site": "https://site.test",
        "pages": ["https://site.test/zeta/", "https://site.test/alpha/"],
        "live_refs": ["0.jpg", "2023/a.jpg", "z.jpg"],
        "forms": ["https://site.test/contact", "https://site.test/search"],
        "fetched": 7,
    }
    assert isinstance(data["fetched"], int)


def test_run_walk_json_twin_empty_collections(monkeypatch, tmp_path):
    """Zero refs + zero forms with --report: the .json twin is still
    written and carries EMPTY lists for both (not null, not absent)."""
    fake, _calls = _canned(pages=["https://site.test/"], refs=set(),
                           forms=[], fetched=3)
    monkeypatch.setattr(wpt.audit, "remote_stack",
                        lambda ctx: (None, None, _RecordingBridge()))
    monkeypatch.setattr(wpt.walk, "walk_site", fake)
    ctx = _ctx(tmp_path)

    assert wpt.walk.run_walk(ctx) == 0

    data = json.loads(
        ctx.report_path.with_suffix(".json").read_text(encoding="utf-8"))
    assert data == {
        "site": "https://site.test",
        "pages": ["https://site.test/"],
        "live_refs": [],
        "forms": [],
        "fetched": 3,
    }


def test_run_walk_no_report_no_json(monkeypatch, tmp_path, capsys):
    """Without --report: NEITHER the markdown file NOR its .json twin is
    written (the output dir stays empty); stdout is the markdown report
    only — the JSON twin is file-only and never leaks to the console."""
    fake, _calls = _canned(pages=["https://site.test/"], refs={"a.jpg"},
                           forms=[], fetched=1)
    monkeypatch.setattr(wpt.audit, "remote_stack",
                        lambda ctx: (None, None, _RecordingBridge()))
    monkeypatch.setattr(wpt.walk, "walk_site", fake)
    ctx = _ctx(tmp_path, report_path=None)

    assert wpt.walk.run_walk(ctx) == 0

    assert list(tmp_path.iterdir()) == []
    out = capsys.readouterr().out
    assert out.startswith("# wpt walk — https://site.test\n")
    assert "## Live media references" in out and "- a.jpg" in out
    assert '"live_refs"' not in out and not out.lstrip().startswith("{")


def test_walk_deadline_expired_returns_partial_never_raises(serve, session,
                                                            wpt_records):
    """The run deadline bounds the crawl: an already-spent budget stops the
    walk BEFORE the first visit with the partial warning (the walk's own
    never-raise contract — a crawling origin ends as a partial result, no
    external kill ever needed)."""
    from wpt.deadline import Deadline

    base = _base(serve)
    serve.routes = _full_site_routes(base)
    d = Deadline(3600)
    d._started -= 7200                     # deterministically spent
    result = walk_site(session, base, FAST, deadline=d)
    assert result.pages == [] and result.live_refs == set()
    warns = [r.getMessage() for r in wpt_records
             if r.name == "wpt.walk" and r.levelno == logging.WARNING]
    assert any("walk stopped: run deadline exceeded" in m
               and "PARTIAL" in m for m in warns), warns
    # the same walk without a deadline crawls normally
    full = walk_site(session, base, FAST)
    assert full.pages and full.live_refs


# ===========================================================================
# The response-size bound (walk.max_response_bytes) — a MEMORY bound.
#
# Measured before it existed: `session.get(url, timeout=...)` is not
# streamed and had no size check, so a 300 MB page cost ~936 MB of RSS
# (~3.1x the body) and a 3 GB page ended the run with a MemoryError
# traceback on the operator's laptop.  The body is now read against the
# profile bound while it streams, so an over-budget answer is REFUSED in
# bounded memory.
# ===========================================================================


#: 40 MB, generated by the server in 64 KiB chunks (never a fixture file,
#: never a 40 MB string in the test process).
FORTY_MB = 40 * 1024 * 1024

#: A bound small enough that a 40 MB answer is over it, large enough that
#: every real page in the fixtures is under it.
TIGHT = WalkSettings(max_pages=200, delay_s=0.0, max_depth=5,
                     max_response_bytes=1_000_000)


def test_oversized_response_is_refused_not_downloaded(serve, session,
                                                      wpt_caplog):
    """A 40 MB answer under a 1 MB bound: ONE warning naming the URL and
    the bound, no reference from that page, the attempt still recorded,
    and NO MemoryError anywhere — the run ends on its own terms."""
    base = _base(serve)
    serve.routes = {"/": (200, "text/html; charset=utf-8", FORTY_MB)}
    # a sibling page (seeded by the sitemap, since the giant page carries no
    # links) proves the crawler itself is healthy
    serve.routes["/page-a/"] = _html(
        '<img src="/wp-content/uploads/2023/10/small.jpg">')
    serve.routes["/sitemap.xml"] = (
        200, "application/xml; charset=utf-8",
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        f"<url><loc>{base}/page-a/</loc></url></urlset>")

    result = walk_site(session, base, TIGHT)

    # the giant page is refused, so it yields nothing ...
    assert result.live_refs == {"2023/10/small.jpg"}
    # ... while the attempt stays in `pages` (the visit happened) and the
    # rest of the crawl is untouched
    assert f"{base}/" in result.pages
    assert f"{base}/page-a/" in result.pages
    assert not result.partial
    warnings = [r.getMessage() for r in wpt_caplog.records
                if r.name == "wpt.walk" and r.levelno == logging.WARNING]
    over = [m for m in warnings if "over-sized response" in m]
    assert len(over) == 1, warnings
    assert f"{base}/" in over[0]          # the URL is named
    assert "16777216" not in over[0]
    assert "1000000" in over[0]           # and the bound, in bytes
    assert "not truncated" in over[0]     # never fed to the parser


def test_a_normal_page_still_parses_under_a_bound(serve, session):
    """The bound is a bound, not a new refusal: the SAME full-site fixture
    under the tight bound parses exactly as it does unbounded."""
    base = _base(serve)
    serve.routes = _full_site_routes(base)

    bounded = walk_site(session, base, TIGHT)
    unbounded = walk_site(session, base, FAST)
    assert bounded.live_refs == unbounded.live_refs
    assert bounded.forms == unbounded.forms
    assert "2023/10/pic-300x233.jpg" in bounded.live_refs


def test_the_shipped_default_fits_a_real_document(serve, session):
    """The shipped bound is sized from the DOCUMENT, not from taste: the
    fixture is a realistic rendered page (markup + srcset + a generated
    stylesheet with several url() references), and the shipped default
    must leave it alone."""
    base = _base(serve)
    serve.routes = _full_site_routes(base)

    result = walk_site(session, base, load().walk)
    assert result.live_refs
    assert "2023/10/css-only-bg.jpg" in result.live_refs  # the CSS half too


def test_an_oversized_stylesheet_is_refused_too(serve, session, wpt_caplog):
    """The same treatment for the ASSETS the walk fetches: a stylesheet
    over the bound is skipped, and its markup href still counts as a ref
    (the stylesheet is a real file of the site) — only its url()
    references are lost, and the site is told which asset was dropped."""
    base = _base(serve)
    serve.routes = {
        "/": _html(
            '<link rel="stylesheet" '
            'href="/wp-content/uploads/elementor/css/post-1.css">'),
        "/wp-content/uploads/elementor/css/post-1.css":
            (200, "text/css; charset=utf-8", FORTY_MB),
    }

    result = walk_site(session, base, TIGHT)

    assert result.live_refs == {"elementor/css/post-1.css"}
    warnings = [r.getMessage() for r in wpt_caplog.records
                if r.name == "wpt.walk" and r.levelno == logging.WARNING]
    over = [m for m in warnings if "over-sized response" in m]
    assert len(over) == 1
    assert "post-1.css" in over[0]


def test_the_bound_is_read_from_the_profile_not_the_module(serve, session):
    """The bound is a PROFILE key: the same site, the same page, a bound
    above and below the answer."""
    base = _base(serve)
    serve.routes = {"/": _html('<img src="/wp-content/uploads/a.jpg">')}

    under = walk_site(session, base,
                      WalkSettings(max_pages=5, delay_s=0.0, max_depth=1,
                                   max_response_bytes=8))
    assert under.live_refs == set()
    assert under.pages == [f"{base}/"]

    over = walk_site(session, base,
                     WalkSettings(max_pages=5, delay_s=0.0, max_depth=1,
                                  max_response_bytes=1024))
    assert over.pages == [f"{base}/"]
    assert over.live_refs == {"a.jpg"}


# ------------------------------------------------ triple-check round 8 (P1)


def test_P1_walk_report_redacts_wp_url_userinfo(monkeypatch, tmp_path,
                                                capsys):
    """P1-03: --wp-url userinfo reached the walk markdown/twin and stdout."""
    secret = "s3cr3t-pass"
    site = f"https://admin:{secret}@site.test"
    fake, _calls = _canned(
        pages=[f"https://admin:{secret}@site.test/page/"],
        refs={"a.jpg"}, forms=[], fetched=1)
    monkeypatch.setattr(
        wpt.audit, "remote_stack",
        lambda ctx: (_ClosableSource(), object(), _RecordingBridge()))
    monkeypatch.setattr(wpt.walk, "walk_site", fake)
    ctx = _ctx(tmp_path, wp_url=site)

    assert wpt.walk.run_walk(ctx) == 0

    markdown = ctx.report_path.read_text("utf-8")
    twin_text = ctx.report_path.with_suffix(".json").read_text("utf-8")
    printed = capsys.readouterr().out
    for face in (markdown, twin_text, printed):
        assert secret not in face
        assert "admin:***@site.test" in face


# ------------------------------------------------ round-8 teardown regressions


class _StopOnCloseSource(_ClosableSource):
    def close(self):
        super().close()
        raise StopRequested("SIGTERM during close")


class _CloseRecordingSession:
    def __init__(self):
        self.closed = 0

    def close(self):
        self.closed += 1


def test_R9_P1_walk_site_re_raises_a_cooperative_stop(monkeypatch):
    """P1: ``walk_site``'s broad catch turned a SIGTERM into a partial rc 0
    result.  The stop must leave the crawler instead of being packaged."""
    def _stop(self):
        raise StopRequested("received SIGTERM (15)")

    monkeypatch.setattr(wpt.walk._Crawler, "run", _stop)
    with pytest.raises(StopRequested):
        walk_site(object(), "https://site.test", FAST)


def test_R9_P1_walk_stop_returns_1_with_a_failure_report(monkeypatch, tmp_path):
    """P1: the CLI walk answered rc 1 and replaced any success pair when the
    walk raised the cooperative SIGTERM."""
    def _stop(_session, _site, _settings, _timeout_s, deadline=None):
        raise StopRequested("received SIGTERM (15)")

    monkeypatch.setattr(
        wpt.audit, "remote_stack",
        lambda ctx: (_ClosableSource(), object(), _RecordingBridge()))
    monkeypatch.setattr(wpt.walk, "walk_site", _stop)
    ctx = _ctx(tmp_path)

    assert wpt.walk.run_walk(ctx) == 1
    written = ctx.report_path.read_text(encoding="utf-8")
    assert "## This run did not complete" in written
    assert "SIGTERM" in written


def test_R8_P2_16_teardown_stop_replaces_the_success_report(
        monkeypatch, tmp_path):
    """R8-P2-16: a close-time stop after the crawl left a success report
    beside rc 1; the shared failure pair must replace it."""
    fake, _calls = _canned(pages=["https://site.test/"], refs={"a.jpg"},
                           forms=[], fetched=1)
    monkeypatch.setattr(
        wpt.audit, "remote_stack",
        lambda ctx: (_StopOnCloseSource(), _CloseRecordingSession(),
                     _RecordingBridge()))
    monkeypatch.setattr(wpt.walk, "walk_site", fake)
    ctx = _ctx(tmp_path)

    assert wpt.walk.run_walk(ctx) == 1
    markdown = ctx.report_path.read_text("utf-8")
    assert "This run did not complete" in markdown
    assert "SIGTERM" in markdown
    assert "Crawled 1 pages" not in markdown
    twin = json.loads(ctx.report_path.with_suffix(".json").read_text("utf-8"))
    assert twin["run"]["status"] == "failed"


def test_R8_P2_17_walk_closes_the_http_session(monkeypatch, tmp_path):
    """R8-P2-17: walk's finally omitted the session, leaking its pool."""
    fake, _calls = _canned(pages=["https://site.test/"], refs={"a.jpg"},
                           forms=[], fetched=1)
    session = _CloseRecordingSession()
    monkeypatch.setattr(
        wpt.audit, "remote_stack",
        lambda ctx: (_ClosableSource(), session, _RecordingBridge()))
    monkeypatch.setattr(wpt.walk, "walk_site", fake)
    ctx = _ctx(tmp_path)

    assert wpt.walk.run_walk(ctx) == 0
    assert session.closed == 1


def test_R21_a_site_wide_500_marks_the_walk_partial(serve, session,
                                                    wpt_caplog):
    """R21-P1: a 500 homepage with no sitemap left the queue EMPTY, so the
    result looked complete with zero references.  A failed homepage (or
    seed) is a site-level failure: partial=True, never "nothing is
    referenced" — the fact trim-media's apply refuses on."""
    base = _base(serve)
    serve.routes = {
        "/": _html("server error", status=500),
        "/sitemap.xml": (404, "text/plain", "no"),
        "/sitemap_index.xml": (404, "text/plain", "no"),
    }
    result = walk_site(session, base, FAST)
    assert result.partial is True
    assert result.pages == [f"{base}/"]
    assert result.live_refs == set()
    warnings = _warnings(wpt_caplog)
    assert any("HTTP 500" in w for w in warnings)


# ===========================================================================
# R22: the HTTP transport itself rides the absolute bound, and the sitemap
# worklist is bounded like pages.  A server dripping one byte below the
# per-read timeout used to hold the walk for 8.96 s (headers) / 3.68 s
# (body) under a 1 s budget.
# ===========================================================================


def _drip_server(kind: str):
    """A real origin whose HOMEPAGE drips bytes (headers or body).

    The walk always starts at ``/``; the sitemap probes answer 404 so the
    measured request is the homepage, not a 404 that would mark the walk
    partial for an unrelated reason.
    """
    import http.server
    import time

    seen: list[tuple[float, str]] = []
    started = time.monotonic()

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            seen.append((time.monotonic() - started, self.path))
            if self.path == "/" and kind == "head":
                self.wfile.write(b"HTTP/1.1 200 OK\r\nX-Test: ")
                self.wfile.flush()
                try:
                    for _ in range(40):
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        time.sleep(0.2)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return
            if self.path == "/" and kind == "body":
                body = b"x" * 100
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    for byte in body:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        time.sleep(0.2)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, seen, started


def _close_drip(server, thread, session):
    session.close()
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


@pytest.mark.parametrize("kind", ["head", "body"])
def test_R22_a_dripped_walk_fetch_is_bounded_by_the_run_budget(kind):
    """R22-P1: ``_fetch`` used requests' per-READ timeout for headers and
    body, so a drip reset it forever.  Header and body both ride
    ``min(run deadline, now + http.timeout_s)``; the walk stops PARTIAL at
    the run budget instead of treating the page as merely unhealthy."""
    import time

    from wpt.deadline import Deadline

    server, thread, seen, _started = _drip_server(kind)
    session = requests.Session()
    session.trust_env = False
    site = f"http://127.0.0.1:{server.server_port}"
    try:
        started = time.monotonic()
        result = walk_site(
            session, site, WalkSettings(max_pages=1, delay_s=0.0,
                                        max_depth=1),
            timeout_s=30, deadline=Deadline(1.0))
        elapsed = time.monotonic() - started
        assert elapsed < 2.5, elapsed
        # The homepage itself was the dripped request, and the run budget
        # stopped the walk (a 404 would be a page failure, not this signal).
        assert any(path == "/" for _at, path in seen)
        assert result.partial is True
        assert result.pages == [f"{site}/"]
    finally:
        _close_drip(server, thread, session)


def test_R22_a_huge_sitemap_worklist_is_deadline_and_max_pages_bounded():
    """R22-P2: the child-sitemap worklist appended every same-host
    ``<sitemap><loc>`` before the first page and never checked the budget
    (30 children, 3.29 s under a 0.5 s budget).  The loop checks the run
    budget at its top and caps the worklist at ``walk.max_pages``."""
    import http.server
    import time

    from wpt.deadline import Deadline

    seen: list[tuple[float, str]] = []
    started = time.monotonic()

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            seen.append((time.monotonic() - started, self.path))
            if self.path == "/sitemap.xml":
                body = (
                    '<?xml version="1.0"?><sitemapindex>'
                    + "".join(
                        f"<sitemap><loc>http://127.0.0.1:"
                        f"{self.server.server_port}/child-{index}.xml</loc>"
                        f"</sitemap>" for index in range(30))
                    + "</sitemapindex>"
                ).encode()
                status = 200
            elif self.path.startswith("/child-"):
                time.sleep(0.1)
                body = (b'<?xml version="1.0"?><urlset><url><loc>'
                        b'http://127.0.0.1:' + str(self.server.server_port).encode()
                        + b'/page/</loc></url></urlset>')
                status = 200
            else:
                body = b"<html></html>"
                status = 200
            self.send_response(status)
            self.send_header("Content-Type", "application/xml")
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
    try:
        wall = time.monotonic()
        result = walk_site(
            session, site, WalkSettings(max_pages=200, delay_s=0.0,
                                        max_depth=1),
            timeout_s=30, deadline=Deadline(0.5))
        elapsed = time.monotonic() - wall
        assert elapsed < 1.8, elapsed
        assert result.partial is True
        children = [path for _at, path in seen if path.startswith("/child-")]
        assert 0 < len(children) < 30, children
        # No child request starts after the budget (a small scheduling
        # allowance covers the request already in flight).
        assert max(at for at, _path in seen) < 1.2, seen
        assert result.pages == []  # stopped before the homepage
    finally:
        session.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
