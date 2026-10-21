"""End-to-end tests for the assembled audit entry point wpt.audit.run — W6h.

Everything goes THROUGH run(ctx) with real Ctx objects, the way the CLI's
_lazy_call invokes it. Local mode is FULLY REAL (real ZipSource over a
tmp_path zip, real analyzer over inline dump bytes — the fixture style of
tests/audit/test_data.py, helpers re-created here, never imported).  Ftp
mode fakes only the construction seam: run() is driven through a
monkeypatched wpt.audit.remote_stack returning a preloaded FakeSource, a
URL-routed scripted session and a REAL Bridge over both — so the real
gather/probe/destroy flow, the real registry and the real report rendering
all execute.  The remote_stack SWEEP tests go one level deeper: they run
the REAL remote_stack with only the module-level FtpSource name swapped
for a fake ctor, so the stale-bridge sweep and the trio wiring execute
production code.  The updates checks are made data-silent by fixture design
(unknown wp_version, versionless plugin catalog entries, a style.css
without a Version header): the wp.org request path they would take is
pinned by tests/audit/test_updates.py, and this suite then scripts every
request its checks actually make.  No network, no PHP, no sleeps — the
only socket-touching check (security.cert_mismatch) stays silent because
the fixture's info payload carries no siteurl (the documented per-check
degrade).  Deterministic.

Test -> behavior map (W6h task list):
  test_import_registers_every_landed_check .. importing wpt.audit fires
        every @register_check: the exact 29-name set is present (other
        test files' "t."-prefixed throwaway registrations excluded)
  test_local_mode_full_run .................. real zip+dump -> rc 0;
        markdown written to --report, JSON twin to .json sibling; JSON
        parses; exact PRODUCTION findings set (t.* throwaways leaked by
        test_registry into the shared process filtered out);
        media.unreferenced ABSENT (live_refs None — W7), db.ghost_tables
        absent per fixture; totals entries/mode; one info summary logged
        counting the same findings the report carries
  test_local_mode_prints_to_stdout .......... report_path None: the
        markdown goes to stdout, nothing is written
  test_local_mode_only_and_skip ............. extra["only"]/["skip"]
        flow to the registry: only=webroot -> the 3 junk findings;
        skip=webroot -> the 3 non-webroot findings
  test_local_mode_missing_inputs_return_1 .. zip None / missing zip /
        missing sql -> rc 1 (clean, no traceback) AND the refusal report
        on disk naming the failure with zero findings — a failed audit
        used to write nothing, so a caller could not tell "found nothing"
        from "never got far enough"
  test_local_mode_empty_sql_graceful ........ an empty dump parses to an
        empty model: rc 0, only tree-based findings (webroot.junk +
        plugins.inactive — [] active_plugins is "none found", not
        unknown)
  test_ftp_mode_full_run .................... faked seam, real Bridge:
        rc 0; probe attached (security findings present); every scripted
        probe consumed exactly; bridge destroyed (self-destruct GET made,
        bridge file removed from the FakeSource); report + JSON written
  test_ftp_mode_bridge_failure_returns_1 .... bridge info answers
        {"ok": false}: BridgeError caught + logged, rc 1, the REFUSAL
        REPORT written (zero findings, the failure named), the deployed
        bridge still destroyed (L6), no secret in any log record
  test_remote_stack_sweeps_stale_bridge_files ... REAL remote_stack (only
        the FtpSource name faked): the webroot-root sweep deletes exactly
        the two bridge-<8hex>.php files; decoys (bridge-notours.php,
        7-hex, UPPERCASE hex) and normal files untouched; one "swept 2"
        info log; the stack itself writes nothing (the Bridge is lazy)
  test_remote_stack_sweep_delete_failure_is_warning .... a stuck stale
        file (delete raises SourceError): one warning naming it, the
        stack still returned, the other stale file swept ("swept 1")
  test_remote_stack_sweep_quiet_without_stale_files ..... clean webroot:
        no deletes, no sweep log line at all
  test_remote_stack_sweep_list_dir_failure_is_source_error ... the
        sweep's root list_dir failing propagates SourceError — the
        normal stack contract
"""

import json
import logging
import zipfile

import pytest
import requests

import wpt.audit
from tests.fakes import FakeResponse, FakeSession, FakeSource
from wpt.audit import run
from wpt.audit.registry import all_checks
from wpt.cli import Ctx
from wpt.deadline import Deadline
from wpt.settings import BridgeSettings, load
from wpt.types import SourceError, StopRequested
from wpt.wpbridge.client import Bridge

SITE = "https://site.test"
LOCAL_SITE_URL = "https://site.example.test"
JPG = b"\xff\xd8JPGBYTES"
SECRET = "s3cret-value"


# --------------------------------------------------------------- log capture


# ----------------------------------------------------------- local fixtures

#: One small WP-shaped webroot: junk files (3 junk patterns), an active
#: and an inactive plugin dir, an uploads tree, and a theme style.css with
#: a Version header (feeds theme_versions; updates stay silent — no probe).
LOCAL_TREE = [
    ("wp-config.php", b"<?php // config"),
    ("readme.html", b"<h1>WP</h1>"),
    ("wp-config-sample.php", b"<?php // sample"),
    ("backup.sql", b"DROP TABLE x;"),
    ("wp-content/plugins/akismet/akismet.php", b"<?php /* akismet */"),
    ("wp-content/plugins/legacy-cache/legacy-cache.php", b"<?php /* legacy */"),
    ("wp-content/uploads/2023/10/a.jpg", JPG),
    ("wp-content/themes/sample-theme/style.css",
     b"/*\nTheme Name: Sample Theme\nVersion: 2.1.4\n*/\nbody{}"),
]
#: Every walked path of LOCAL_TREE (files + the dirs connectors derive).
LOCAL_TREE_PATHS = {
    "wp-config.php", "readme.html", "wp-config-sample.php", "backup.sql",
    "wp-content", "wp-content/plugins", "wp-content/plugins/akismet",
    "wp-content/plugins/akismet/akismet.php",
    "wp-content/plugins/legacy-cache",
    "wp-content/plugins/legacy-cache/legacy-cache.php",
    "wp-content/uploads", "wp-content/uploads/2023",
    "wp-content/uploads/2023/10", "wp-content/uploads/2023/10/a.jpg",
    "wp-content/themes", "wp-content/themes/sample-theme",
    "wp-content/themes/sample-theme/style.css",
}

#: The dump's posts spec: 2 posts, 3 revisions, 1 auto-draft => 4 revisions.
POSTS_SPEC = {
    ("post", "publish"): 2,
    ("revision", "inherit"): 3,
    ("post", "auto-draft"): 1,
    ("attachment", "inherit"): 1,
}

#: An autoloaded option over the packaged 102400 B threshold (131083 B).
BIG_OPTION = 's:%d:"%s";' % (131072, "y" * 131072)


def _ser_str(value: str) -> str:
    return 's:%d:"%s";' % (len(value.encode("utf-8")), value)


def _ser_int(value: int) -> str:
    return "i:%d;" % value


def _ser_list(values: list[str]) -> str:
    body = "".join("i:%d;%s" % (i, _ser_str(v)) for i, v in enumerate(values))
    return "a:%d:{%s}" % (len(values), body)


def _cell_sql(value) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, int):
        return str(value)
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _create(table: str, columns: list[str]) -> bytes:
    cols = ", ".join("`%s` text" % c for c in columns)
    return ("CREATE TABLE `%s` (%s);\n" % (table, cols)).encode()


def _insert(table: str, rows: list) -> bytes:
    tuples = ",".join("(" + ",".join(_cell_sql(c) for c in row) + ")" for row in rows)
    return ("INSERT INTO `%s` VALUES %s;\n" % (table, tuples)).encode()


def _post_rows(spec: dict[tuple[str, str], int]) -> list[tuple]:
    rows, post_id = [], 0
    for (post_type, post_status), n in spec.items():
        for _ in range(n):
            post_id += 1
            rows.append((post_id, post_type, post_status))
    return rows


def _dump_bytes() -> bytes:
    """wp_options + wp_posts + wp_postmeta, analyzer-style dump bytes."""
    options = [
        (1, "siteurl", _ser_str(LOCAL_SITE_URL), "yes"),
        (2, "home", _ser_str(LOCAL_SITE_URL), "yes"),
        (3, "template", _ser_str("sample-theme"), "yes"),
        (4, "stylesheet", _ser_str("sample-theme"), "yes"),
        (5, "blog_public", _ser_int(1), "yes"),
        (6, "active_plugins", _ser_list(["akismet/akismet.php"]), "yes"),
        (7, "big_cache_option", BIG_OPTION, "yes"),
        (8, "small_option", _ser_str("y" * 20), "no"),
    ]
    return b"".join([
        _create("wp_options", ["option_id", "option_name", "option_value", "autoload"]),
        _create("wp_posts", ["ID", "post_type", "post_status", "post_content"]),
        _create("wp_postmeta", ["meta_id", "post_id", "meta_key", "meta_value"]),
        _insert("wp_options", options),
        _insert("wp_posts", _post_rows(POSTS_SPEC)),
        _insert("wp_postmeta", [(1, 1, "_edit_last", "1")]),
    ])


def _write_zip(tmp_path, files):
    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        for name, blob in files:
            zf.writestr(name, blob)
    return zpath


@pytest.fixture
def local_site(tmp_path):
    """A real zip + real dump on disk: (zip_path, sql_path)."""
    return _write_zip(tmp_path, LOCAL_TREE), (tmp_path / "dump.sql")


def _local_ctx(tmp_path, zip_path, sql_path, **overrides):
    kwargs = dict(
        source="local", settings=load(),
        zip=zip_path, sql=sql_path,
        report_path=tmp_path / "report.md",
    )
    kwargs.update(overrides)
    return Ctx(**kwargs)


def _assert_failure_report(ctx, needle: str) -> None:
    """A FAILED audit run wrote the report it could (L44, one level up).

    Measured across 21 commands: every success wrote markdown + JSON and
    every failure wrote NOTHING, so a caller could not tell "the audit
    found nothing" from "the audit never got far enough" — one absence
    read two ways.  The report is the audit report's own shape with zero
    findings, and the one thing a success report could never say: why
    there is nothing in it.
    """
    import json as _json

    written = ctx.report_path.read_text(encoding="utf-8")
    assert "## This run did not complete" in written
    assert needle in written
    assert "- findings: 0" in written
    assert "- planned items: 0" in written
    assert "## Needs your call" not in written
    twin = _json.loads(
        ctx.report_path.with_suffix(".json").read_text(encoding="utf-8"))
    assert twin["findings"] == []
    assert twin["plan"]["items"] == []
    assert twin["run"]["status"] == "failed"
    assert needle in twin["run"]["reason"]


#: The exact findings the local fixture must produce, (category, name),
#: in the report's deterministic (category, name) order.  A webroot.junk
#: finding is named by the matched PATTERN (check contract), so the dump
#: file reports as "*.sql".
LOCAL_FINDINGS = [
    ("db.autoload", "big-autoload-options"),
    ("db.revisions", "revisions"),
    # the media check DEGRADES to the database half offline (it is no
    # longer structurally silent) — see test_local_mode_full_run
    ("media.unreferenced", "unreferenced-media"),
    ("plugins.inactive", "inactive-plugins"),
    ("webroot.junk", "*.sql"),
    ("webroot.junk", "readme.html"),
    ("webroot.junk", "wp-config-sample.php"),
]


def _read_report(report_path):
    """The parsed JSON twin of a written markdown report."""
    payload = json.loads(
        report_path.with_suffix(".json").read_text(encoding="utf-8")
    )
    return payload, [
        (f["category"], f["name"]) for f in payload["findings"]
    ]


def _production_pairs(pairs):
    """Split report findings into (production, foreign).

    test_registry.py permanently registers "t.w6a.*" throwaway checks in
    the process-global registry (by design — there is no unregister API),
    so a full-registry run inside the shared pytest process inherits them
    whenever test_registry ran first.  The production split lets the full
    runs stay unscoped (every real check executes) while asserting the
    production findings EXACTLY: everything the filter removes must be a
    "t."-prefixed throwaway, never a production surprise.
    """
    production = [p for p in pairs if not p[0].startswith("t.")]
    foreign = [p for p in pairs if p[0].startswith("t.")]
    assert all(cat.startswith("t.") for cat, _name in foreign)
    return production, foreign


# ------------------------------------------------------------ ftp fixtures


class Resp:
    """Header/url-capable canned response (redirect probes need Location)."""

    def __init__(self, status_code=200, text="", headers=None, url=""):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = url
        self.history = []

    def json(self):
        return json.loads(self.text)


class RouterSession:
    """(method, url-substring, item) routed scripted session: order-free,
    unlike the shared FakeSession's strict queue.  An item is a response,
    an Exception instance (raised), or a callable (method, url, kwargs) ->
    response.  The bridge's three POSTs pop a scripted queue in order."""

    def __init__(self, routes=()):
        self.routes = list(routes)
        self.calls: list[tuple[str, str, dict]] = []

    def get(self, url, **kwargs):
        return self._advance("GET", url, kwargs)

    def post(self, url, **kwargs):
        return self._advance("POST", url, kwargs)

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


def ok(**payload):
    """A bridge-shaped {"ok": true, ...} response."""
    return Resp(200, json.dumps({"ok": True, **payload}))


#: The ftp fixture webroot (webroot-relative files, FakeSource keys).
FTP_TREE = {
    "wp-config.php": b"<?php define('DB_NAME', 'x');",
    "readme.html": b"<h1>WP</h1>",
    "wp-content/debug.log": b"PHP Notice: something",
    "wp-content/plugins/real/real.php": b"<?php /* real */",
    "wp-content/plugins/legacy/legacy.php": b"<?php /* legacy */",
    "wp-content/uploads/2023/10/a.jpg": JPG,
    "wp-content/uploads/2023/10/orphan.jpg": JPG,  # never in live_refs
    "wp-content/themes/tt/style.css": b"/*\nTheme Name: TT\n*/\nbody{}",
}
#: Every walked path of FTP_TREE at gather time (the bridge file deploys
#: only AFTER the walk, so it is NOT part of the audit tree).
FTP_TREE_PATHS = {
    "wp-config.php", "readme.html",
    "wp-content", "wp-content/debug.log",
    "wp-content/plugins", "wp-content/plugins/real",
    "wp-content/plugins/real/real.php",
    "wp-content/plugins/legacy", "wp-content/plugins/legacy/legacy.php",
    "wp-content/uploads", "wp-content/uploads/2023",
    "wp-content/uploads/2023/10", "wp-content/uploads/2023/10/a.jpg",
    "wp-content/uploads/2023/10/orphan.jpg",
    "wp-content/themes", "wp-content/themes/tt",
    "wp-content/themes/tt/style.css",
}

#: The exact findings the ftp fixture must produce, (category, name),
#: in the report's deterministic (category, name) order.
FTP_FINDINGS = [
    ("db.orphan_meta", "postmeta"),
    ("db.revisions", "revisions"),
    ("media.unreferenced", "unreferenced-media"),
    ("plugins.inactive", "inactive-plugins"),
    ("security.author_scan", "author-scan"),
    ("security.debug_log", "debug-log"),
    ("security.disallow_file_edit", "disallow-file-edit"),
    ("security.https_redirect", "https-redirect"),
    ("security.wp_config_perms", "wp-config-perms"),
    ("webroot.junk", "readme.html"),
]


def _ftp_info_payload():
    # No siteurl (cert_mismatch degrades to silence — no socket in tests),
    # no wp_version and versionless catalog entries (updates checks stay
    # data-silent; their wp.org request path is pinned in test_updates.py).
    # php 8.3.33 keeps security.php_version silent (>= the active floor).
    return ok(
        home=SITE,
        template="tt",
        blog_public=1,
        php_version="8.3.33",
        plugins={
            "real/real.php": {"name": "Real", "version": "", "active": True},
            "hello.php": {"name": "Hello", "version": "", "active": False},
        },
        uploads_basedir="/srv/www/wp/wp-content/uploads",
    )


def _ftp_db_audit_payload():
    return ok(
        posts=[
            {"post_type": "post", "post_status": "publish", "count": 3},
            {"post_type": "revision", "post_status": "inherit", "count": 2},
        ],
        revisions=2,
        expired_transients=0,  # measured zero: db.transients stays silent
        orphan_meta={"postmeta": 3, "termmeta": 0},  # 0 kind silent too
        tables=[{"name": "wp_options", "rows": 10, "size_mb": 0.5,
                 "data_free_kb": 8.0}],
        autoload_bytes=5000,  # below the warn level: db.autoload silent
    )


def _ftp_stack(source, session, webroot="public_html"):
    """The production-shaped trio the tests monkeypatch in: preloaded
    FakeSource + scripted session + a REAL, not-yet-deployed Bridge."""
    bridge = Bridge(source, session, webroot, BridgeSettings(), SITE)
    return source, session, bridge


def _ftp_ctx(tmp_path, **overrides):
    kwargs = dict(
        source="ftp://h:2121", settings=load(),
        user="u", password=SECRET,
        webroot="public_html", wp_url=SITE,
        report_path=tmp_path / "ftp-report.md",
    )
    kwargs.update(overrides)
    return Ctx(**kwargs)


# ---------------------------------------- remote_stack sweep doubles


class _StuckDeleteSource(FakeSource):
    """FakeSource whose delete() raises SourceError for the stuck paths —
    the permission-refused stale file on a real server."""

    def __init__(self, stuck) -> None:
        super().__init__()
        self._stuck = set(stuck)

    def delete(self, path):
        if path in self._stuck:
            raise SourceError(f"delete refused: {path}")
        super().delete(path)


class _NoListingSource(FakeSource):
    """FakeSource whose list_dir() always fails — the sweep's root listing
    under the normal SourceError contract."""

    def list_dir(self, path):
        raise SourceError(f"listing failed: {path!r}")


def _real_remote_stack(monkeypatch, source):
    """Run the REAL remote_stack against ``source``: only the module-level
    FtpSource name in wpt.audit is swapped for a ctor returning it, so URL
    parsing, the settings port override, the session/Bridge wiring and the
    stale-bridge sweep all execute production code.  Returns the ctor's
    captured (host, user, password, webroot, ftp_settings) calls."""
    ctor_calls: list[tuple] = []

    def ctor(host, user, password, root, settings):
        ctor_calls.append((host, user, password, root, settings))
        return source

    monkeypatch.setattr(wpt.audit, "FtpSource", ctor)
    return ctor_calls


def _sweep_records(wpt_records):
    """The sweep's own wpt.audit log records (its info/warning lines)."""
    return [r for r in wpt_records if r.name == "wpt.audit"
            and ("swept" in r.getMessage()
                 or "could not be removed" in r.getMessage()
                 or "bridge-shaped file" in r.getMessage()
                 or "left " in r.getMessage() and "in place" in
                 r.getMessage())]


# ------------------------------------------------------------ registry side


def test_import_registers_every_landed_check():
    # The "t." filter keeps other test files' throwaway registrations
    # (test_registry registers "t.w6a.*" checks in the same process).
    names = {rec.name for rec in all_checks() if not rec.name.startswith("t.")}
    assert names == {
        "core.integrity",
        "db.active_missing",
        "db.admin_accounts", "db.autoload", "db.charset",
        "db.ghost_tables", "db.optimize", "db.orphan_meta",
        "db.revisions", "db.transients",
        "media.unreferenced",
        "plugins.duplicate", "plugins.heavy", "plugins.inactive",
        "security.author_scan", "security.cert_mismatch",
        "security.debug_log", "security.disallow_file_edit",
        "security.https_redirect", "security.php_version",
        "security.relocate",
        "security.rest_users",
        "security.source_patterns", "security.suspicious",
        "security.uploads_listing", "security.uploads_perms",
        "security.web_exposed_script",
        "security.wp_config_perms", "security.www_apex", "security.xmlrpc",
        "updates.core", "updates.plugins", "updates.themes",
        "webroot.junk", "webroot.junk_recurring",
        "webroot.migration", "webroot.mu_plugins", "webroot.stale",
    }


# ----------------------------------------------------------- local mode


def test_local_mode_full_run(local_site, tmp_path, wpt_records):
    zpath, sql_path = local_site
    sql_path.write_bytes(_dump_bytes())
    ctx = _local_ctx(tmp_path, zpath, sql_path)

    assert run(ctx) == 0

    markdown = ctx.report_path.read_text(encoding="utf-8")
    assert "# wpt audit — local:site.zip" in markdown
    assert "Source: zip:site.zip + dump.sql" in markdown
    assert "## db.revisions" in markdown
    assert "## webroot.junk" in markdown
    assert "## Needs your call" in markdown  # medium/high findings exist
    assert "**Reclaimable estimate:" in markdown

    payload, pairs = _read_report(ctx.report_path)
    # a SUCCESSFUL audit report is unchanged by the failure-report path:
    # no "run" key, and no "did not complete" section
    assert "run" not in payload
    assert "## This run did not complete" not in markdown
    production, _foreign = _production_pairs(pairs)
    assert production == LOCAL_FINDINGS
    assert payload["site"] == "local:site.zip"
    assert payload["source_summary"] == "zip:site.zip + dump.sql"
    assert payload["totals"] == {"entries": len(LOCAL_TREE_PATHS), "mode": "local"}
    assert payload["reclaimable_bytes"] > 0
    # No live walk offline — but the media check is NO LONGER structurally
    # silent: it measures the DATABASE half of the keep-set (a page renders
    # only a fraction of its attachments, so a walk-only keep-set deletes
    # what it never sees) and labels the result DEGRADED.  The fixture dump
    # has no meta_value/post_content columns, so the measured database set
    # is empty and the one uploads image is the candidate.
    media = [f for f in payload["findings"]
             if f["category"] == "media.unreferenced"]
    assert len(media) == 1
    assert media[0]["detail"] == "2023/10/a.jpg"
    assert "unreferenced by the database only (no live walk)" in media[0]["fix"]
    assert "DEGRADED" in media[0]["fix"]
    # no ghost marker matches wp_options/wp_posts/wp_postmeta
    assert ("db.ghost_tables", "ghost-tables") not in pairs

    # exactly one info summary from the runner, counting the same findings
    # the report carries (throwaways included when the suite leaked them)
    summaries = [r for r in wpt_records
                 if r.name == "wpt.audit" and r.levelno == logging.INFO
                 and "reclaimable" in r.getMessage()]
    assert len(summaries) == 1
    assert f"{len(pairs)} findings" in summaries[0].getMessage()


def test_local_mode_prints_to_stdout(local_site, tmp_path, capsys):
    zpath, sql_path = local_site
    sql_path.write_bytes(_dump_bytes())
    ctx = _local_ctx(tmp_path, zpath, sql_path, report_path=None)

    assert run(ctx) == 0
    out = capsys.readouterr().out
    assert "# wpt audit — local:site.zip" in out
    assert "## webroot.junk" in out
    assert "**Reclaimable estimate:" in out


def test_local_mode_only_and_skip(local_site, tmp_path):
    zpath, sql_path = local_site
    sql_path.write_bytes(_dump_bytes())

    only = _local_ctx(tmp_path, zpath, sql_path, extra={"only": ["webroot"]})
    assert run(only) == 0
    _payload, pairs = _read_report(only.report_path)
    assert pairs == [("webroot.junk", "*.sql"),
                     ("webroot.junk", "readme.html"),
                     ("webroot.junk", "wp-config-sample.php")]

    skip = _local_ctx(tmp_path, zpath, sql_path, extra={"skip": ["webroot"]})
    assert run(skip) == 0
    _payload, pairs = _read_report(skip.report_path)
    production, _foreign = _production_pairs(pairs)
    assert production == [("db.autoload", "big-autoload-options"),
                           ("db.revisions", "revisions"),
                           ("media.unreferenced", "unreferenced-media"),
                           ("plugins.inactive", "inactive-plugins")]


def test_local_mode_missing_inputs_return_1(local_site, tmp_path):
    zpath, sql_path = local_site
    sql_path.write_bytes(_dump_bytes())

    # zip=None: the CLI guards this before dispatch; run() re-validates
    none_zip = _local_ctx(tmp_path, None, sql_path)
    assert run(none_zip) == 1

    missing_zip = _local_ctx(tmp_path, tmp_path / "nope.zip", sql_path)
    assert run(missing_zip) == 1
    # L44: a failed run writes the report it CAN, so a caller can tell
    # "found nothing" from "never got far enough"
    _assert_failure_report(missing_zip, "zip not found")

    missing_sql = _local_ctx(tmp_path, zpath, tmp_path / "nope.sql")
    assert run(missing_sql) == 1
    _assert_failure_report(missing_sql, "nope.sql")


def test_local_mode_empty_sql_is_graceful(local_site, tmp_path):
    zpath, sql_path = local_site
    sql_path.write_bytes(b"")  # empty dump -> empty model
    ctx = _local_ctx(tmp_path, zpath, sql_path)

    assert run(ctx) == 0
    _payload, pairs = _read_report(ctx.report_path)
    production, _foreign = _production_pairs(pairs)
    # No db finding is knowable from an empty dump.  The tree still feeds
    # the webroot checks, and the active set is UNMEASURED (None, not [] —
    # a site running no plugins measures []), so the plugin check says it
    # could not ask rather than calling every unit inactive.  Each marker
    # carries its OWN category (wpt.audit.webroot
    # .DB_ACTIVE_SET_UNKNOWN_CATEGORY / .PLUGINS_ACTIVE_SET_UNKNOWN_CATEGORY),
    # never the measured category it stands in for, so no suggested-step
    # rule can fire on a run that measured nothing.
    assert production == [("db.active_set_unknown", "active-set-unknown"),
                          ("plugins.active_set_unknown", "active-set-unknown"),
                          ("webroot.junk", "*.sql"),
                          ("webroot.junk", "readme.html"),
                          ("webroot.junk", "wp-config-sample.php")]


# ------------------------------------------------------------- ftp mode


def test_ftp_mode_full_run(monkeypatch, tmp_path):
    source = FakeSource()
    source.files.update(FTP_TREE)

    bridge_payloads = [
        _ftp_info_payload(),      # gather: bridge.call("info")
        _ftp_db_audit_payload(),  # gather: bridge.call("db_audit")
        # media.unreferenced: the database half of the union keep-set, one
        # read-only media_map(mode=db) call, fetched lazily by the check
        # (checks run in name order, so it precedes the security probes)
        ok(db_refs=["2023/10/a.jpg"]),
        _ftp_info_payload(),      # security.php_version: cached probe.info()
        ok(paths={"wp-config.php": "0644"}),  # security.wp_config_perms
    ]

    def bridge_post(_method, _url, _kwargs):
        assert bridge_payloads, "unexpected bridge call"
        return bridge_payloads.pop(0)

    session = RouterSession([
        ("POST", "bridge-", bridge_post),
        ("GET", "selfdestruct", Resp(200, "gone")),  # destroy() self-destruct
        ("POST", "xmlrpc.php", Resp(404, "disabled")),         # silent
        ("GET", "wp-json/wp/v2/users", Resp(404, "none")),     # silent
        # WordPress's ?rest_route= fallback (both spellings) is probed too;
        # a blocked pretty URL must not hide an open fallback.
        ("GET", "?rest_route=/wp/v2/users", Resp(404, "none")),
        ("GET", "?rest_route=%2Fwp%2Fv2%2Fusers", Resp(404, "none")),
        ("GET", "?author=1",
         Resp(301, headers={"Location": f"{SITE}/author/admin/"})),  # finding
        ("GET", "http://site.test", Resp(200, text="plain http homepage")),  # offender
        ("GET", "https://www.", requests.ConnectionError("www not serving")),  # silent
        ("GET", "wp-content/uploads/", Resp(403)),             # silent
        # webroot.junk asks whether the matched junk is PUBLICLY served
        # (the disclosure that leads its fix); 404 = not served = silent
        ("GET", "readme.html", Resp(404)),
    ])
    monkeypatch.setattr(wpt.audit, "remote_stack",
                        lambda ctx: _ftp_stack(source, session))
    # W7i wiring: the audit runs the live walk; patched here (the real
    # walker is pinned by tests/test_walk.py). a.jpg referenced, orphan.jpg
    # not -> media.unreferenced engages; the homepage feeds https_redirect.
    from wpt.walk import WalkResult

    walk_args: list = []

    def fake_walk_site(session_, site_, settings_, timeout_s_, **kw):
        walk_args.append((site_, settings_.max_pages, timeout_s_))
        return WalkResult(live_refs={"2023/10/a.jpg"},
                          pages=[f"{SITE}/"], forms=[], fetched=7)

    monkeypatch.setattr(wpt.audit, "walk_site", fake_walk_site)

    ctx = _ftp_ctx(tmp_path)
    assert run(ctx) == 0
    assert walk_args == [(SITE, ctx.settings.walk.max_pages,
                          ctx.settings.http.timeout_s)]

    # the report landed in both formats
    markdown = ctx.report_path.read_text(encoding="utf-8")
    assert "# wpt audit — https://site.test" in markdown
    assert "Source: ftp://h:2121" in markdown
    payload, pairs = _read_report(ctx.report_path)
    production, _foreign = _production_pairs(pairs)
    assert production == FTP_FINDINGS
    assert payload["site"] == SITE
    assert payload["source_summary"] == "ftp://h:2121"
    assert payload["totals"] == {"entries": len(FTP_TREE_PATHS), "mode": "ftp"}

    # data.probe WAS attached: the security findings above are impossible
    # without it (local mode never produces a security.* finding)
    assert any(category.startswith("security.") for category, _name in pairs)

    # the bridge was destroyed: the self-destruct request happened and the
    # deployed file is gone from the source (uploads cleaned)
    assert any(method == "GET" and "selfdestruct" in url
               for method, url, _kw in session.calls)
    assert not [p for p in source.files if "bridge-" in p]


def test_ftp_mode_bridge_failure_returns_1(monkeypatch, tmp_path, wpt_records):
    source = FakeSource()
    session = FakeSession([
        FakeResponse(200, json.dumps({"ok": False, "error": "boom"})),  # info
        FakeResponse(200, "gone"),  # destroy()'s self-destruct GET
    ])
    monkeypatch.setattr(wpt.audit, "remote_stack",
                        lambda ctx: _ftp_stack(source, session))

    ctx = _ftp_ctx(tmp_path, report_path=tmp_path / "no.md")
    assert run(ctx) == 1
    # the failure is on disk, not only in the log (L44)
    _assert_failure_report(ctx, "boom")

    # the failure was caught and logged by the runner — never a traceback
    errors = [r for r in wpt_records
              if r.name == "wpt.audit" and r.levelno == logging.ERROR]
    assert len(errors) == 1
    assert "boom" in errors[0].getMessage()

    # L6 hygiene: the bridge deployed for the failed call and destroy()
    # still removed it; the password never reached any log record
    assert not [p for p in source.files if "bridge-" in p]
    for record in wpt_records:
        assert SECRET not in record.getMessage()


def test_C4_override_ip_session_dials_the_wp_url_port(monkeypatch, tmp_path):
    """C4: remote_stack dropped the URL port when building the override
    session, so every :8443 request dialed 443 and timed out while the cert
    check passed.  The adapter's dial port is the parsed URL port."""
    source = FakeSource()
    monkeypatch.setattr(
        wpt.audit, "ftp_source_for",
        lambda ctx, root=None, source_cls=None: source)
    ctx = _ftp_ctx(tmp_path, wp_url="https://site.example:8443",
                   override_ip="127.0.0.1", report_path=None)

    _source, session, _bridge = wpt.audit.remote_stack(ctx)
    try:
        adapter = session.get_adapter("https://site.example:8443/")
        assert adapter._port == 8443
        assert adapter.poolmanager._target_port == 8443
    finally:
        session.close()


def test_R15_remote_stack_arms_the_bridge_with_the_run_deadline(
        monkeypatch, tmp_path):
    """R15-P1-2: the stack seam must hand every Bridge the run's absolute
    deadline, so a convenience/action call that passes neither ``timeout``
    nor ``deadline`` cannot issue an unbounded POST."""
    source = FakeSource()
    monkeypatch.setattr(
        wpt.audit, "ftp_source_for",
        lambda ctx, root=None, source_cls=None: source)
    ctx = _ftp_ctx(tmp_path, deadline_s=60)

    _source, session, bridge = wpt.audit.remote_stack(ctx)
    try:
        deadline = Deadline.from_ctx(ctx)
        assert deadline is not None
        assert bridge._run_deadline == deadline.at
    finally:
        session.close()


def test_C5_malformed_wp_url_is_a_one_line_refusal_with_a_report(
        monkeypatch, tmp_path):
    """C5: ``https://[::1`` raised ValueError out of remote_stack; audit run
    catches only (WptError, OSError), so it escaped with no report pair."""
    source = FakeSource()
    monkeypatch.setattr(
        wpt.audit, "ftp_source_for",
        lambda ctx, root=None, source_cls=None: source)
    ctx = _ftp_ctx(tmp_path, wp_url="https://[::1")

    assert run(ctx) == 1
    written = ctx.report_path.read_text(encoding="utf-8")
    assert "malformed" in written
    assert "--wp-url" in written


# ------------------------------------------- remote_stack sweep (real seam)



#: bridge.php's deployed TTL literal, as the real client substitutes it.
_EXPIRED = b"$wpt_expires = '1000';"          # long past: provably dead
_UNEXPIRED = b"$wpt_expires = '9999999999';"  # far future: a live sibling's


def test_remote_stack_sweeps_stale_bridge_files(monkeypatch, tmp_path, wpt_records):
    source = FakeSource()
    source.files.update({
        "readme.html": b"<h1>WP</h1>",
        "bridge-12345678.php": b"<?php " + _EXPIRED + b" // dead leftover",
        "bridge-abcdef01.php": b"<?php " + _EXPIRED + b" // dead leftover",
        # EXPIRY-AWARE sweep (rule 10): a live sibling's active bridge is
        # name-shaped but its TTL has not passed — NEVER deleted
        "bridge-11223344.php": b"<?php " + _UNEXPIRED + b" // LIVE sibling",
        # unverifiable candidates are left in place, never deleted blind
        "bridge-55667788.php": b"<?php // no expiry literal: unverifiable",
        "bridge-notours.php": b"<?php // not the deployed-name contract",
        "bridge-1234567.php": b"<?php // 7 hex chars: not ours",
        "bridge-ABCDEF12.php": b"<?php // uppercase hex: not ours",
    })
    ctor_calls = _real_remote_stack(monkeypatch, source)

    source_out, session, bridge = wpt.audit.remote_stack(_ftp_ctx(tmp_path))

    # the production trio came back, wired from ctx into the fake ctor
    # (the explicit :2121 overrides the profile port through replace())
    assert source_out is source
    assert isinstance(session, requests.Session)
    assert isinstance(bridge, Bridge)
    assert len(ctor_calls) == 1
    host, user, password, webroot, ftp_settings = ctor_calls[0]
    assert (host, user, password, webroot) == ("h", "u", SECRET, "public_html")
    assert ftp_settings.port == 2121
    # exactly the two EXPIRED contract-matching names were deleted ...
    deleted = sorted(p for _t, op, p in source.ops if op == "delete")
    assert deleted == ["bridge-12345678.php", "bridge-abcdef01.php"]
    # ... the live sibling's bridge, the unverifiable file, every decoy
    # and every normal file are untouched, and the stack itself wrote
    # nothing (the Bridge is lazy: the sweep runs strictly before any
    # deployment of OUR bridge)
    assert sorted(source.files) == [
        "bridge-11223344.php", "bridge-1234567.php", "bridge-55667788.php",
        "bridge-ABCDEF12.php", "bridge-notours.php", "readme.html",
    ]
    assert not [p for _t, op, p in source.ops if op == "write"]
    # the sweep reports the removals AND what it deliberately left alone
    records = _sweep_records(wpt_records)
    infos = [r for r in records if r.levelno == logging.INFO]
    assert len(infos) == 2
    assert any("swept 2 expired bridge file(s) from the webroot "
               "(left by a killed run)" in r.getMessage() for r in infos)
    assert any("left 2 bridge file(s) in place (expiry still live or "
               "unverifiable)" in r.getMessage() for r in infos)
    # the unverifiable candidate is named in a warning
    warns = [r for r in records if r.levelno == logging.WARNING]
    assert any("bridge-55667788.php carries no expiry literal" in
               r.getMessage() for r in warns)


def test_remote_stack_sweep_delete_failure_is_warning(monkeypatch, tmp_path,
                                                      wpt_records):
    source = _StuckDeleteSource(stuck=("bridge-12345678.php",))
    source.files.update({
        "bridge-12345678.php": b"<?php " + _EXPIRED + b" // stuck but dead",
        "bridge-abcdef01.php": b"<?php " + _EXPIRED + b" // removable",
    })
    _real_remote_stack(monkeypatch, source)

    source_out, _session, _bridge = wpt.audit.remote_stack(_ftp_ctx(tmp_path))

    # a stuck stale file never blocks the stack: the trio still comes back
    assert source_out is source
    warnings = [r for r in _sweep_records(wpt_records)
                if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    message = warnings[0].getMessage()
    assert "stale bridge file bridge-12345678.php could not be removed" in message
    assert "delete refused" in message
    # the OTHER stale file was still swept; the info count is the real
    # removal count (the stuck one is still on disk, named by the warning)
    assert "bridge-abcdef01.php" not in source.files
    assert "bridge-12345678.php" in source.files
    infos = [r for r in _sweep_records(wpt_records)
             if r.levelno == logging.INFO]
    assert len(infos) == 1
    assert "swept 1 expired bridge file(s)" in infos[0].getMessage()


def test_remote_stack_sweep_quiet_without_stale_files(monkeypatch, tmp_path,
                                                       wpt_records):
    source = FakeSource()
    source.files.update({"readme.html": b"<h1>WP</h1>",
                         "wp-config.php": b"<?php // config"})
    _real_remote_stack(monkeypatch, source)

    source_out, _session, _bridge = wpt.audit.remote_stack(_ftp_ctx(tmp_path))

    # a clean webroot: the listing happened, but no deletes and no log
    assert source_out is source
    assert not [p for _t, op, p in source.ops if op == "delete"]
    assert _sweep_records(wpt_records) == []


def test_remote_stack_sweep_list_dir_failure_is_source_error(monkeypatch,
                                                             tmp_path):
    source = _NoListingSource()
    closed: list[bool] = []
    source.close = lambda: closed.append(True)
    _real_remote_stack(monkeypatch, source)

    # the sweep's root listing rides the normal stack contract: the
    # SourceError propagates out of remote_stack for the callers to catch,
    # and the source this seam built is closed before it is abandoned.
    with pytest.raises(SourceError):
        wpt.audit.remote_stack(_ftp_ctx(tmp_path))
    assert closed == [True]


def test_baseline_diff_new_and_resolved(tmp_path):
    """--baseline: findings keyed category/name; NEW = only in the current
    run, resolved = only in the baseline; the md gains the section and the
    JSON twin gains the diff key."""
    zpath = _write_zip(tmp_path, LOCAL_TREE)
    dump = tmp_path / "dump.sql"
    dump.write_bytes(_dump_bytes())
    report = tmp_path / "a.md"

    assert run(_local_ctx(tmp_path, zpath, dump, report_path=report)) == 0
    baseline_json = report.with_suffix(".json")

    # second run: readme.html + wp-config-sample.php removed (resolved), a
    # new junk pattern (license.txt) appears
    tree2 = [entry for entry in LOCAL_TREE
             if entry[0] not in ("readme.html", "wp-config-sample.php")]
    tree2.append(("license.txt", b"GPL\n"))
    run2 = tmp_path / "second"
    run2.mkdir()
    zpath2 = _write_zip(run2, tree2)
    ctx2 = _local_ctx(run2, zpath2, dump, report_path=tmp_path / "b.md",
                      extra={"baseline": baseline_json})
    assert run(ctx2) == 0
    md = (tmp_path / "b.md").read_text(encoding="utf-8")
    assert "## Changed since baseline" in md
    assert "- NEW: webroot.junk/license.txt" in md
    assert "- resolved: webroot.junk/readme.html" in md
    assert "- resolved: webroot.junk/wp-config-sample.php" in md
    payload = json.loads((tmp_path / "b.json").read_text(encoding="utf-8"))
    assert payload["diff"] == {
        "new": ["webroot.junk/license.txt"],
        "resolved": ["webroot.junk/readme.html",
                      "webroot.junk/wp-config-sample.php"],
        "changed": [],
    }


def test_baseline_diff_identical_is_explicit(tmp_path):
    zpath = _write_zip(tmp_path, LOCAL_TREE)
    dump = tmp_path / "dump.sql"
    dump.write_bytes(_dump_bytes())
    report = tmp_path / "a.md"
    assert run(_local_ctx(tmp_path, zpath, dump, report_path=report)) == 0
    ctx2 = _local_ctx(tmp_path, zpath, dump, report_path=tmp_path / "b.md",
                      extra={"baseline": report.with_suffix(".json")})
    assert run(ctx2) == 0
    md = (tmp_path / "b.md").read_text(encoding="utf-8")
    assert "No changes — the finding set is identical." in md
    payload = json.loads((tmp_path / "b.json").read_text(encoding="utf-8"))
    assert payload["diff"] == {"new": [], "resolved": [], "changed": []}


def test_baseline_diff_detail_change_is_changed(tmp_path):
    """A finding PRESENT in both runs whose DETAIL differs is CHANGED —
    not 'identical' (live lesson: deactivating litespeed-cache grew the
    plugins.inactive finding's detail and an identity-only diff answered
    'No changes' to a diff question). The second run's dump gains one
    more inactive plugin: the db.revisions-style key stays, the inactive
    list detail changes."""
    zpath = _write_zip(tmp_path, LOCAL_TREE)
    dump = tmp_path / "dump.sql"
    dump.write_bytes(_dump_bytes())
    report = tmp_path / "a.md"
    assert run(_local_ctx(tmp_path, zpath, dump, report_path=report)) == 0
    baseline_json = report.with_suffix(".json")
    first = json.loads(baseline_json.read_text(encoding="utf-8"))
    inactive = [f for f in first["findings"]
                if f["category"] == "plugins.inactive"]
    assert inactive, "fixture must produce a plugins.inactive finding"

    # same tree, same dump — identical runs — but the BASELINE is edited
    # to carry a shorter detail for the same finding key: the diff must
    # report the key as changed, never 'No changes'
    edited = json.loads(baseline_json.read_text(encoding="utf-8"))
    for f in edited["findings"]:
        if f["category"] == "plugins.inactive":
            f["detail"] = "stale-detail.txt (1 B)"
    edited_path = tmp_path / "edited-baseline.json"
    edited_path.write_text(json.dumps(edited), encoding="utf-8")
    ctx2 = _local_ctx(tmp_path, zpath, dump, report_path=tmp_path / "b.md",
                      extra={"baseline": edited_path})
    assert run(ctx2) == 0
    md = (tmp_path / "b.md").read_text(encoding="utf-8")
    assert "No changes" not in md
    assert "changed: plugins.inactive/inactive-plugins (detail changed" in md
    payload = json.loads((tmp_path / "b.json").read_text(encoding="utf-8"))
    assert payload["diff"] == {
        "new": [], "resolved": [], "changed": ["plugins.inactive/inactive-plugins"]}


def test_baseline_diff_sees_magnitude_changes(tmp_path):
    """A finding whose count/risk/bytes changed is CHANGED even when its
    detail is byte-identical. Comparing detail alone answered "No changes"
    to a run that had twice the rows and a higher risk."""
    zpath = _write_zip(tmp_path, LOCAL_TREE)
    dump = tmp_path / "dump.sql"
    dump.write_bytes(_dump_bytes())
    report = tmp_path / "a.md"
    assert run(_local_ctx(tmp_path, zpath, dump, report_path=report)) == 0
    baseline_json = report.with_suffix(".json")
    first = json.loads(baseline_json.read_text(encoding="utf-8"))
    assert first["findings"], "fixture must produce findings"

    for field, value in (("count", 999), ("risk", "high"), ("bytes", 10 ** 9)):
        edited = json.loads(baseline_json.read_text(encoding="utf-8"))
        for f in edited["findings"]:
            f[field] = value
        edited_path = tmp_path / f"edited-{field}.json"
        edited_path.write_text(json.dumps(edited), encoding="utf-8")
        ctx2 = _local_ctx(tmp_path, zpath, dump, report_path=tmp_path / f"b-{field}.md",
                          extra={"baseline": edited_path})
        assert run(ctx2) == 0
        md = (tmp_path / f"b-{field}.md").read_text(encoding="utf-8")
        assert "No changes" not in md, field
        payload = json.loads((tmp_path / f"b-{field}.json").read_text(encoding="utf-8"))
        assert payload["diff"]["changed"], field


def test_baseline_absent_optional_fields_use_the_finding_defaults(tmp_path):
    """A baseline entry may omit count/risk/bytes; those mean the Finding
    DEFAULTS (count=1, risk=low), not zero, so an omitted field is never a
    phantom change. `detail` has no dataclass default, so an omitted one is
    the empty string a finding would also compare as."""
    from wpt.audit import _baseline_diff
    from wpt.types import Finding
    for entry in (
        {"category": "c", "name": "n", "detail": "d"},
        {"category": "c", "name": "n", "detail": "d", "count": 1,
         "risk": "low"},
    ):
        baseline = tmp_path / "b.json"
        baseline.write_text(json.dumps({"findings": [entry]}), encoding="utf-8")
        new, resolved, changed = _baseline_diff([Finding("c", "n", "d")],
                                                baseline)
        assert (new, resolved, changed) == ([], [], {}), entry
    # `detail` has no dataclass default, so an omitted one compares as "",
    # which only matches a finding that also has an empty detail.
    baseline.write_text(json.dumps({"findings": [{"category": "c", "name": "n"}]}),
                        encoding="utf-8")
    assert _baseline_diff([Finding("c", "n", "")], baseline) == ([], [], {})


def test_malformed_baseline_fails_loud(tmp_path):
    """A corrupt baseline is a USAGE error, not an empty one: skipping a
    malformed entry would answer a diff question with every finding 'new'."""
    from wpt.audit import _baseline_diff
    from wpt.types import Finding, WptError
    for payload in (
        {"findings": [42]},
        {"findings": [{"name": "n", "detail": "d"}]},
        {"findings": [{"category": "c", "detail": "d"}]},
        {"findings": [{"category": "c", "name": "n", "count": "many"}]},
        {"findings": [{"category": "c", "name": "n", "risk": 3}]},
    ):
        path = tmp_path / "bad.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(WptError):
            _baseline_diff([Finding("c", "n", "d")], path)


def test_baseline_magnitude_change_names_the_field(tmp_path):
    from wpt.audit import _baseline_diff
    from wpt.types import Finding
    path = tmp_path / "b.json"
    path.write_text(json.dumps({
        "findings": [{"category": "c", "name": "n", "detail": "d",
                      "count": 1, "risk": "low", "bytes": 0}]
    }), encoding="utf-8")
    now = [Finding("c", "n", "d", count=5, risk="high", bytes=99)]
    _, _, changed = _baseline_diff(now, path)
    assert changed == {"c/n": ["bytes", "count", "risk"]}
    # a detail-only change names only detail
    path.write_text(json.dumps({
        "findings": [{"category": "c", "name": "n", "detail": "old"}]
    }), encoding="utf-8")
    _, _, changed = _baseline_diff([Finding("c", "n", "d")], path)
    assert changed == {"c/n": ["detail"]}


def test_baseline_selector_unknown_check_fails_loud(tmp_path):
    """--only with a name no registered check matches is a USAGE ERROR —
    an empty selection must never pass as a silent success (live lesson:
    a validation step filtered to a nonexistent check name and its empty
    report was mistaken for a confirmation). The verdict fires at run()
    entry, BEFORE the gather: a typo costs seconds, never a full gather.
    The refusal is still WRITTEN (a two-row file, no gather involved), so
    a caller that scripted the command and reads --report is told on disk
    as well as in the log."""
    zpath = _write_zip(tmp_path, LOCAL_TREE)
    dump = tmp_path / "dump.sql"
    dump.write_bytes(_dump_bytes())
    report = tmp_path / "r.md"
    ctx = _local_ctx(tmp_path, zpath, dump, report_path=report,
                     extra={"only": ["security.php_version"]})
    assert run(ctx) == 1   # php_version is ftp-only: no local-mode match
    ctx2 = _local_ctx(tmp_path, zpath, dump, report_path=report,
                      extra={"only": ["not.a.check"]})
    assert run(ctx2) == 1
    # the refusal is still written (cheap: no gather, no emit ran) — a
    # caller that passed a typo'd --only MUST get told on disk too
    _assert_failure_report(ctx2, "not.a.check")


def test_baseline_unreadable_fails_closed(tmp_path):
    zpath = _write_zip(tmp_path, LOCAL_TREE)
    dump = tmp_path / "dump.sql"
    dump.write_bytes(_dump_bytes())
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    ctx = _local_ctx(tmp_path, zpath, dump, report_path=tmp_path / "b.md",
                     extra={"baseline": bad})
    assert run(ctx) == 1  # WptError via the never-raises contract


def test_baseline_not_a_report_fails_closed(tmp_path):
    zpath = _write_zip(tmp_path, LOCAL_TREE)
    dump = tmp_path / "dump.sql"
    dump.write_bytes(_dump_bytes())
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"findings": "nope"}), encoding="utf-8")
    ctx = _local_ctx(tmp_path, zpath, dump, report_path=tmp_path / "b.md",
                     extra={"baseline": bad})
    assert run(ctx) == 1


# ------------------------------------------------------- triple-check round 2


def test_SWEEP1_bridge_sweep_reads_through_the_bounded_contract(
        monkeypatch, tmp_path, wpt_records):
    """SWEEP1: a 5 MiB bridge-shaped file was read whole on every ftp
    command; the sweep now skips it on the LIST size alone."""
    source = FakeSource()
    huge = "bridge-deadbeef.php"
    source.files[huge] = b"<?php " + _EXPIRED + b" " + b"x" * (5 * 1024 * 1024)
    reads = []
    real = source.read_bytes_bounded

    def recording(path, limit):
        reads.append((path, limit))
        return real(path, limit)

    source.read_bytes_bounded = recording
    _real_remote_stack(monkeypatch, source)

    source_out, _session, _bridge = wpt.audit.remote_stack(_ftp_ctx(tmp_path))

    assert source_out is source
    assert reads == []
    assert huge in source.files
    assert any("over the" in r.getMessage() and "sweep bound" in r.getMessage()
               for r in wpt_records if r.name == "wpt.audit")


def test_SWEEP2_bridge_sweep_keeps_the_endpoint_at_the_exact_expiry_second(
        monkeypatch, tmp_path, wpt_records):
    """SWEEP2: the bridge's own gate is ``time() > expiry``; at equality the
    sweep deleted a live sibling for that second."""
    source = FakeSource()
    boundary = "bridge-0000beef.php"
    source.files[boundary] = b"<?php $wpt_expires = '1000';"
    _real_remote_stack(monkeypatch, source)
    monkeypatch.setattr("wpt.endpoint.time.time", lambda: 1000)

    source_out, _session, _bridge = wpt.audit.remote_stack(_ftp_ctx(tmp_path))

    assert source_out is source
    assert boundary in source.files
    assert not [p for _t, op, p in source.ops if op == "delete"]


def test_SWEEP3_bridge_sweep_skips_a_huge_expiry_literal(
        monkeypatch, tmp_path, wpt_records):
    """SWEEP3: ``int('9'*5000)`` raised ValueError out of the seam and every
    ftp command tracebacked; it is now skipped + warned."""
    source = FakeSource()
    candidate = "bridge-0000cafe.php"
    source.files[candidate] = (
        b"<?php $wpt_expires = '" + b"9" * 5000 + b"';")
    _real_remote_stack(monkeypatch, source)

    source_out, _session, _bridge = wpt.audit.remote_stack(_ftp_ctx(tmp_path))

    assert source_out is source
    assert candidate in source.files
    assert any("unparseable expiry" in r.getMessage()
               for r in wpt_records if r.name == "wpt.audit")


class _StoppingBridgeSource(FakeSource):
    def __init__(self, stop_on):
        super().__init__()
        self.stop_on = stop_on
        self.closed = 0

    def read_bytes_bounded(self, path, limit):
        if self.stop_on == "read":
            raise StopRequested("received SIGTERM (15)")
        return super().read_bytes_bounded(path, limit)

    def delete(self, path):
        if self.stop_on == "delete":
            raise StopRequested("received SIGTERM (15)")
        super().delete(path)

    def close(self):
        self.closed += 1


def test_SWEEP4_bridge_sweep_propagates_stop_on_read_and_delete(
        monkeypatch, tmp_path):
    """SWEEP4: the broad per-candidate catches ate StopRequested, so
    ``remote_stack`` returned a trio and doctor kept running after SIGTERM."""
    candidate = "bridge-0000dead.php"
    reading = _StoppingBridgeSource("read")
    reading.files[candidate] = b"<?php " + _EXPIRED
    _real_remote_stack(monkeypatch, reading)
    with pytest.raises(StopRequested):
        wpt.audit.remote_stack(_ftp_ctx(tmp_path))
    assert reading.closed == 1  # the seam still closes what it built

    deleting = _StoppingBridgeSource("delete")
    deleting.files[candidate] = b"<?php " + _EXPIRED
    _real_remote_stack(monkeypatch, deleting)
    with pytest.raises(StopRequested):
        wpt.audit.remote_stack(_ftp_ctx(tmp_path))
    assert deleting.closed == 1


def test_R11_remote_stack_closes_the_source_when_the_sweep_stops(
        monkeypatch, tmp_path):
    """R11-P2-16: RunControl is a BaseException, so the sweep's
    ``except Exception`` never closed the source it had just built."""
    class _StoppingListSource(FakeSource):
        def __init__(self):
            super().__init__()
            self.closed = 0

        def list_dir(self, path):
            raise StopRequested("SIGTERM during the sweep")

        def close(self):
            self.closed += 1

    source = _StoppingListSource()
    _real_remote_stack(monkeypatch, source)
    with pytest.raises(StopRequested):
        wpt.audit.remote_stack(_ftp_ctx(tmp_path))
    assert source.closed == 1


def test_R11_remote_stack_closes_source_and_session_when_setup_stops(
        monkeypatch, tmp_path):
    """R11-P2-16: a stop while building the override session (or the
    Bridge) used to leak the FTP source / HTTP pool."""
    class _CloseSession:
        def __init__(self):
            self.closed = 0

        def close(self):
            self.closed += 1

    class _CloseSource(_StoppingBridgeSource):
        def __init__(self):
            super().__init__("none")

    source = _CloseSource()
    _real_remote_stack(monkeypatch, source)

    def _stop_session(**_kwargs):
        raise StopRequested("SIGTERM while resolving the override session")

    monkeypatch.setattr(wpt.audit, "resolve_session", _stop_session)
    with pytest.raises(StopRequested):
        wpt.audit.remote_stack(
            _ftp_ctx(tmp_path, override_ip="127.0.0.1"))
    assert source.closed == 1

    session = _CloseSession()

    def _session(**_kwargs):
        return session

    def _stop_bridge(*_args, **_kwargs):
        raise StopRequested("SIGTERM while constructing the bridge")

    monkeypatch.setattr(wpt.audit, "resolve_session", _session)
    monkeypatch.setattr(wpt.audit, "Bridge", _stop_bridge)
    with pytest.raises(StopRequested):
        wpt.audit.remote_stack(
            _ftp_ctx(tmp_path, override_ip="127.0.0.1"))
    assert source.closed == 2
    assert session.closed == 1


def test_AUDIT_STOP_SWALLOW_run_returns_1_after_a_stop(
        monkeypatch, local_site, tmp_path):
    """AUDIT-STOP-SWALLOW: a check raising SIGTERM/deadline was converted to
    `audit.check_failed`, so `wpt audit` returned rc 0."""
    zpath, sql_path = local_site
    sql_path.write_bytes(_dump_bytes())
    ctx = _local_ctx(tmp_path, zpath, sql_path)

    def _stopped(*_args, **_kwargs):
        raise StopRequested("received SIGTERM (15)")

    monkeypatch.setattr(wpt.audit, "run_checks", _stopped)
    assert run(ctx) == 1
    _assert_failure_report(ctx, "SIGTERM")


def test_AUDIT_CLOSE_local_and_ftp_sources_and_sessions_are_closed(
        monkeypatch, local_site, tmp_path):
    """AUDIT-CLOSE: the local ZipSource archive handle and the ftp source/
    session were never closed; each run leaked a file descriptor, an FTP
    control session and an HTTP pool."""
    import wpt.audit as audit_mod

    closed: list[str] = []

    class TrackingZip(audit_mod.ZipSource):
        def close(self):
            closed.append("zip")
            super().close()

    zpath, sql_path = local_site
    sql_path.write_bytes(_dump_bytes())
    monkeypatch.setattr(audit_mod, "ZipSource", TrackingZip)
    ctx = _local_ctx(tmp_path, zpath, sql_path)
    assert run(ctx) == 0
    assert closed == ["zip"]

    class TrackingSource(FakeSource):
        def close(self):
            closed.append("source")

    class TrackingSession(requests.Session):
        def close(self):
            closed.append("session")
            super().close()

    source = TrackingSource()
    source.files.update({
        "readme.html": b"<h1>WP</h1>",
        "wp-content/uploads/a.jpg": JPG,
    })

    class _Bridge:
        def call(self, *_args, **_kwargs):
            return {"ok": True}

        def destroy(self):
            closed.append("bridge")

    monkeypatch.setattr(
        audit_mod, "remote_stack",
        lambda _ctx: (source, TrackingSession(), _Bridge()))
    # The gatherer/probe are not what this test measures; stop after the
    # stack is built so the finally path still runs.
    def _stopped(*_args, **_kwargs):
        raise StopRequested("received SIGTERM (15)")

    monkeypatch.setattr(audit_mod, "gather_remote", _stopped)
    ctx2 = _ftp_ctx(tmp_path)
    assert run(ctx2) == 1
    assert {"bridge", "source", "session"} <= set(closed)


# ------------------------------------------------------- triple-check round 9


def test_R9_P1_live_walk_stop_returns_1_with_a_failure_report(
        monkeypatch, tmp_path):
    """P1: ``walk_site``'s StopRequested was swallowed by the live-walk
    catch, so a SIGTERMed audit finished rc 0 with a complete-looking pair."""
    from wpt.audit.data import AuditData

    data = AuditData(
        mode="ftp", entries=[], siteurl=None, home=None, template=None,
        blog_public=None, wp_version=None, mu_plugins=None,
        active_plugins=[], plugin_catalog={}, uploads_basedir=None,
        posts={}, revisions=None, expired_transients=None, orphan_meta={},
        attachments=None, nav_menu_items=None, autoload_bytes=None,
        big_autoload_options=[], tables={},
    )

    class _Bridge:
        def destroy(self):
            pass

    monkeypatch.setattr(
        wpt.audit, "remote_stack",
        lambda ctx: (FakeSource(), FakeSession(), _Bridge()))
    monkeypatch.setattr(wpt.audit, "gather_remote",
                        lambda *args, **kwargs: data)
    monkeypatch.setattr(wpt.audit, "run_checks",
                        lambda *args, **kwargs: [])
    monkeypatch.setattr(
        wpt.audit, "walk_site",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            StopRequested("received SIGTERM (15)")))
    ctx = _ftp_ctx(tmp_path, deadline_s=0)

    assert run(ctx) == 1
    _assert_failure_report(ctx, "SIGTERM")


def test_R9_P2_3_audit_teardown_stop_replaces_the_success_pair(
        monkeypatch, local_site, tmp_path):
    """P2-3: a close-time stop answered rc 1 but left the success report."""
    import wpt.audit as audit_mod

    zpath, sql_path = local_site
    sql_path.write_bytes(_dump_bytes())

    def _stopping_close(source, label):
        raise StopRequested("received SIGTERM (15)")

    monkeypatch.setattr(audit_mod, "close_source", _stopping_close)
    ctx = _local_ctx(tmp_path, zpath, sql_path)
    ctx.deadline_s = 0

    assert run(ctx) == 1
    written = ctx.report_path.read_text(encoding="utf-8")
    assert "## This run did not complete" in written
    assert "teardown stopped" in written
    twin = json.loads(
        ctx.report_path.with_suffix(".json").read_text(encoding="utf-8"))
    assert twin["run"]["status"] == "failed"


def test_R9_P2_13_deep_baseline_is_a_refusal_not_a_traceback(
        local_site, tmp_path):
    """P2-13: a 100k-deep baseline JSON raised RecursionError out of run()
    with no report."""
    zpath, sql_path = local_site
    sql_path.write_bytes(_dump_bytes())
    baseline = tmp_path / "deep.json"
    baseline.write_text("[" * 100_000 + "0" + "]" * 100_000,
                        encoding="utf-8")
    ctx = _local_ctx(tmp_path, zpath, sql_path,
                     extra={"baseline": baseline})

    assert run(ctx) == 1
    _assert_failure_report(ctx, "baseline")
    assert "RecursionError" in ctx.report_path.read_text(encoding="utf-8")


# ------------------------------------------------------- triple-check round 6


def test_R6_34_a_slow_walk_cannot_outlive_the_deadline_and_return_0(
        local_site, tmp_path, monkeypatch):
    """R6-34: the deadline was built AFTER the gather, so a slow walk/dump
    could blow the entire budget and still write a success report.  Build it
    first, thread it through the gather and fail rc 1 on expiry."""
    import time

    from wpt.sources.base import WalkMixin
    from wpt.sources.zip import ZipSource

    zpath, sql_path = local_site
    sql_path.write_bytes(_dump_bytes())
    real_walk = WalkMixin.walk

    def slow_walk(self, path=""):
        for entry in real_walk(self, path):
            time.sleep(1.2)
            yield entry

    monkeypatch.setattr(ZipSource, "walk", slow_walk)
    # 1.0s leaves ample room for the real dump analyzer even on a loaded
    # host; the first walk yield then sleeps past the budget, which the
    # threaded deadline must catch.  The floor is the BUDGET itself: a
    # budget+50ms margin is a scheduling race when workers share the host.
    ctx = _local_ctx(tmp_path, zpath, sql_path, deadline_s=1.0)

    started = time.monotonic()
    assert run(ctx) == 1
    elapsed = time.monotonic() - started
    assert elapsed >= 1.0, elapsed
    assert elapsed < 30.0, elapsed
    assert "deadline" in ctx.report_path.read_text("utf-8")


def test_R7_P2_06_audit_refuses_a_json_report_path(local_site, tmp_path,
                                                   wpt_records):
    """R7-P2-06: audit lost the markdown face when --report named a .json
    path; the one shared writer now refuses it (rc 1, no clobber)."""
    zpath, sql_path = local_site
    sql_path.write_bytes(_dump_bytes())
    report = tmp_path / "audit.json"
    ctx = _local_ctx(tmp_path, zpath, sql_path, report_path=report)
    assert run(ctx) == 1
    assert not report.exists()
    messages = [r.getMessage() for r in wpt_records
                if r.name.startswith("wpt.")]
    assert any("refusing a .json report path" in message
               for message in messages), messages


def test_R13_a_second_stop_in_the_audit_failure_writer_keeps_the_reason(
        tmp_path, monkeypatch, wpt_records):
    """R13-P2-18: the audit's failure writer caught only ``Exception``; a
    second ``StopRequested`` escaped and replaced the primary reason."""
    import wpt.actions.registry as registry_mod
    import wpt.audit as audit_mod
    from wpt.types import StopRequested

    def _stop(*args, **kwargs):
        raise StopRequested("SIGTERM during failure report")

    monkeypatch.setattr(registry_mod, "write_failure_report", _stop)
    ctx = _local_ctx(tmp_path, tmp_path / "site.zip", tmp_path / "dump.sql",
                     report_path=tmp_path / "audit.md")
    audit_mod._write_failure(ctx, "PRIMARY-FAIL")
    joined = "\n".join(r.getMessage() for r in wpt_records)
    assert "SIGTERM during failure report" in joined
