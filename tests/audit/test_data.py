"""Unit tests for the audit data layer (wpt.audit.data) — W6b.

Real collaborators only: the real Bridge client over FakeSource/FakeSession
(shared doubles in tests/fakes.py), the real ZipSource over tmp_path zips,
and the real analyzer over inline dump bytes (fixture style of
tests/test_analyzer.py). No network, no PHP, no sleeps — deterministic.

Test -> behavior map (W6b task list):
  test_gather_remote_maps_info_db_audit_and_tree ... full info+db_audit+walk
        mapping: posts list->dict conversion, active_plugins in catalog key
        order, TableFact MB/KB approximations, tree walked with dirs+files
        and no duplicates (the bridge file deployed during the walk is in
        the tree — the real ftp flow)
  test_gather_remote_tolerates_missing_wire_keys .... info without
        mu_plugins/uploads_basedir/blog_public, db_audit without
        orphan_meta; positional posts rows accepted, duplicate groups sum,
        garbage rows skipped — no exception, unknown defaults
  test_gather_remote_propagates_bridge_failures .... a failing bridge call
        raises BridgeError (a source failure is not missing data)
  test_gather_local_maps_analyzer_and_tree ........ SiteModel -> AuditData
        mapping, revisions mirror rule (revision + auto-draft rows),
        attachments / nav_menu_items derivations, TableFact mapping,
        uploads_basedir detection, local unknowns
  test_uploads_basedir_detection_rules ............. under-path match,
        dir-equals match, file-equals NO match, near-miss prefixes
  test_gather_local_measured_zero_vs_unknown ....... zero revisions -> 0
        (measured), offline unknowns -> None/{}; remote measured zeros keep
        their orphan_meta keys ({} would mean unknown)
  test_gather_local_big_autoload_threshold ......... the autoload threshold
        flows from settings.db (packaged default excludes, low setting
        includes) — no static tunable
  test_gather_remote_users_and_collation_wire_rules  users: [] vs null vs
        malformed-entry drop (one debug summary, no contents);
        collation passthrough, "" -> None, charset from the collation
        prefix, "binary" its own charset
  test_gather_local_table_charset_from_create_sql . local charset from
        the CREATE's DEFAULT CHARSET clause; absent clause -> None
        (never the SET NAMES guess); collation always None locally
  test_gather_local_admin_users_from_dump ......... model.admin_users maps
        1:1 (wire shape, login-sorted, NULL registered -> None); a dump
        without users tables -> None (unknown), never a guessed []
  test_gather_logging_contract ...................... exactly one info
        summary per gather (mode, entries count); option values, URLs and
        plugin names never reach any log record
  test_an_unmeasured_local_gather_logs_unknown_never_zero  a contested
        options identity prints plugins=unknown / post_groups=unknown, the
        same token db_media_refs already used, instead of 0 (a count nobody
        measured is not a zero); a measured dump still prints integers
"""

import io
import json
import logging
import re
import zipfile

import pytest

from tests.fakes import FakeResponse, FakeSession, FakeSource
from wpt.audit.data import AuditData, TableFact, gather_local, gather_remote
from wpt.localmode.analyzer import analyze
from wpt.settings import BridgeSettings, DbSettings, Settings
from wpt.sources.zip import ZipSource
from wpt.types import BridgeError, Entry
from wpt.wpbridge.client import Bridge

SITE = "https://site.example.test"
JPG = b"\xff\xd8JPGBYTES"
ACTIVE_PLUGINS = ["akismet/akismet.php", "zeta-cache/zeta-cache.php"]
BIG_OPTION = 's:300:"%s";' % ("y" * 300)  # 309 serialized bytes, autoloaded

#: One small realistic webroot shared by the ftp and local trees.
LOCAL_TREE = [
    ("wp-config.php", b"<?php // config"),
    ("readme.html", b"<h1>WP</h1>"),
    ("wp-content/uploads/2023/10/a.jpg", JPG),
    ("wp-content/plugins/akismet/akismet.php", b"<?php /* plugin */"),
    ("wp-content/themes/sample-theme/style.css",
     b"/*\nTheme Name: Sample Theme\nVersion: 2.1.4\n*/\nbody{}"),
    # child theme style.css without a Version header line (omitted)
    ("wp-content/themes/sample-theme-child/style.css",
     b"/*\nTheme Name: Sample Theme Child\n*/\nbody{}"),
]
#: Every walked path of LOCAL_TREE (dirs derived by the connectors + files).
LOCAL_TREE_PATHS = {
    "wp-config.php", "readme.html",
    "wp-content", "wp-content/plugins", "wp-content/plugins/akismet",
    "wp-content/plugins/akismet/akismet.php",
    "wp-content/uploads", "wp-content/uploads/2023",
    "wp-content/uploads/2023/10", "wp-content/uploads/2023/10/a.jpg",
    "wp-content/themes", "wp-content/themes/sample-theme",
    "wp-content/themes/sample-theme/style.css",
    "wp-content/themes/sample-theme-child",
    "wp-content/themes/sample-theme-child/style.css",
}


# ------------------------------------------------------------- test doubles


def ok_response(**payload):
    return FakeResponse(200, json.dumps({"ok": True, **payload}))


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def wpt_records():
    """Capture every wpt.* log record (the wpt parent does not propagate)."""
    handler = _Capture()
    parent = logging.getLogger("wpt")
    old_level = parent.level
    parent.addHandler(handler)
    parent.setLevel(logging.DEBUG)
    try:
        yield handler.records
    finally:
        parent.setLevel(old_level)
        parent.removeHandler(handler)


class _WalkStub(FakeSource):
    """FakeSource whose walk() yields a fixed entry list (edge-case trees)."""

    def __init__(self, entries) -> None:
        super().__init__()
        self._fixed = list(entries)

    def walk(self, path: str = ""):
        yield from self._fixed


# -------------------------------------------------------- remote (ftp mode)


def _info_payload():
    return ok_response(
        wp_version="6.7.1",
        siteurl=SITE,
        home=SITE,
        template="sample-theme",
        stylesheet="sample-theme-child",
        blog_public=1,
        locale="fr_CA",
        plugins={
            "zeta-cache/zeta-cache.php": {"name": "Zeta Cache", "version": "1.0.0", "active": True},
            "akismet/akismet.php": {"name": "Akismet", "version": "5.3.1", "active": True},
            "hello.php": {"name": "Hello Dolly", "version": "1.7.2", "active": False},
        },
        mu_plugins=1,
        uploads_basedir="/srv/www/site/wp-content/uploads",
        uploads_error="",
        abspath="/srv/www/site/",
    )


def _db_audit_payload():
    return ok_response(
        posts=[
            {"post_type": "post", "post_status": "publish", "count": 12},
            {"post_type": "page", "post_status": "publish", "count": 4},
            {"post_type": "revision", "post_status": "inherit", "count": 4},
            {"post_type": "post", "post_status": "auto-draft", "count": 1},
            {"post_type": "attachment", "post_status": "inherit", "count": 7},
            {"post_type": "nav_menu_item", "post_status": "publish", "count": 2},
        ],
        revisions=5,
        expired_transients=9,
        orphan_meta={"postmeta": 4, "termmeta": 1, "commentmeta": 2},
        tables=[
            {"name": "wp_options", "rows": 42, "size_mb": 0.5,
             "data_free_kb": 8.0, "collation": "utf8mb4_general_ci"},
            {"name": "wp_posts", "rows": 7, "size_mb": 1.25,
             "data_free_kb": 32.0, "collation": "latin1_swedish_ci"},
        ],
        autoload_bytes=123456,
        attachments=7,
        nav_menu_items=2,
        users=[
            {"login": "admin", "registered": "2019-05-14 09:30:00", "admin": True},
            {"login": "legacy", "registered": None, "admin": True},
        ],
    )


def _gather_remote(script):
    """Real Bridge over the shared fakes; ONE FakeSource for deploy + walk."""
    src = FakeSource()
    for name, blob in LOCAL_TREE:
        src.files[name] = blob
    session = FakeSession(script)
    bridge = Bridge(src, session, "", BridgeSettings(), SITE)
    return gather_remote(bridge, src, Settings()), src


def test_gather_remote_maps_info_db_audit_and_tree():
    data, _src = _gather_remote([_info_payload(), _db_audit_payload()])
    assert isinstance(data, AuditData)
    assert data.mode == "ftp"
    # info passthrough
    assert data.siteurl == SITE
    assert data.home == SITE
    assert data.template == "sample-theme"
    assert data.theme_versions == {"sample-theme": "2.1.4"}  # child has no header
    assert data.blog_public == 1
    assert data.wp_version == "6.7.1"
    assert data.locale == "fr_CA"  # the bridge info's get_locale() [L17]
    assert data.mu_plugins == 1
    assert data.uploads_basedir == "/srv/www/site/wp-content/uploads"
    # catalog: normalized plugin_file -> {name, version, active}
    assert data.plugin_catalog == {
        "zeta-cache/zeta-cache.php": {"name": "Zeta Cache", "version": "1.0.0", "active": True},
        "akismet/akismet.php": {"name": "Akismet", "version": "5.3.1", "active": True},
        "hello.php": {"name": "Hello Dolly", "version": "1.7.2", "active": False},
    }
    # active_plugins: only active=True entries, in CATALOG KEY order
    assert data.active_plugins == ["zeta-cache/zeta-cache.php", "akismet/akismet.php"]
    # posts: db_audit row list -> (post_type, post_status) -> count
    assert data.posts == {
        ("post", "publish"): 12,
        ("page", "publish"): 4,
        ("revision", "inherit"): 4,
        ("post", "auto-draft"): 1,
        ("attachment", "inherit"): 7,
        ("nav_menu_item", "publish"): 2,
    }
    assert data.revisions == 5
    assert data.expired_transients == 9
    assert data.orphan_meta == {"postmeta": 4, "termmeta": 1, "commentmeta": 2}
    assert data.attachments == 7
    assert data.nav_menu_items == 2
    assert data.autoload_bytes == 123456
    assert data.big_autoload_options == []  # ftp: only the byte total is known
    assert data.live_refs is None          # W7 wires it later
    # documented wire approximations: round(size_mb * 1048576),
    # data_free via round(data_free_kb * 1024); collation passes through
    # and charset is derived from the collation prefix
    assert data.tables == {
        "wp_options": TableFact(rows=42, size_bytes=524288, data_free_bytes=8192,
                                collation="utf8mb4_general_ci", charset="utf8mb4"),
        "wp_posts": TableFact(rows=7, size_bytes=1310720, data_free_bytes=32768,
                              collation="latin1_swedish_ci", charset="latin1"),
    }
    # admin users: wire-shaped maps, admins only, in bridge login order
    assert data.admin_users == [
        {"login": "admin", "registered": "2019-05-14 09:30:00", "admin": True},
        {"login": "legacy", "registered": None, "admin": True},
    ]
    # walked tree: dirs + files, no duplicates; the walk runs BEFORE any
    # bridge call, so the tree contains the SITE only — never our own
    # deployed bridge file (artifact-leak regression pin)
    paths = [e.path for e in data.entries]
    assert len(paths) == len(set(paths))
    bridge_files = [p for p in paths if re.fullmatch(r"bridge-[0-9a-f]{8}\.php", p)]
    assert bridge_files == []
    assert set(paths) == LOCAL_TREE_PATHS
    by_path = {e.path: e for e in data.entries}
    assert by_path["wp-content"].is_dir and by_path["wp-content"].size == 0
    jpg = by_path["wp-content/uploads/2023/10/a.jpg"]
    assert not jpg.is_dir and not jpg.is_link and jpg.size == len(JPG)


def test_gather_remote_tolerates_missing_wire_keys():
    info = ok_response(
        wp_version="6.7.1",
        siteurl=SITE,
        home=SITE,
        template="sample-theme",
        plugins={"akismet/akismet.php": {"name": "Akismet", "version": "5.3.1", "active": True}},
    )  # no blog_public, no mu_plugins, no uploads_basedir, no uploads_error
    db_audit = ok_response(
        posts=[
            ["post", "publish", 3],  # positional row form (accepted)
            ["junk", "row"],         # not a 3-element row: skipped
            "garbage",               # not a row at all: skipped
            None,                    # ditto: skipped
            {"post_type": "page", "post_status": "publish"},  # no count: skipped
            {"post_type": "post", "post_status": "publish", "count": 2},  # sums with the first
        ],
        tables=[{"name": "wp_posts", "rows": 7}],  # no size/free estimates
        revisions=2,
        # no orphan_meta, no expired_transients, no autoload_bytes,
        # no attachments, no nav_menu_items
    )
    data, _ = _gather_remote([info, db_audit])  # must not raise
    assert data.blog_public is None
    assert data.mu_plugins is None
    assert data.uploads_basedir is None
    assert data.wp_version == "6.7.1"
    assert data.locale is None  # no locale key on the wire: unknown
    assert data.active_plugins == ["akismet/akismet.php"]
    assert data.posts == {("post", "publish"): 5}
    assert data.tables["wp_posts"] == TableFact(rows=7, size_bytes=None,
                                                data_free_bytes=None,
                                                collation=None, charset=None)
    assert data.admin_users is None  # no users key on the wire: unknown
    assert data.revisions == 2
    assert data.orphan_meta == {}
    assert data.expired_transients is None
    assert data.autoload_bytes is None
    assert data.attachments is None
    assert data.nav_menu_items is None


def test_gather_remote_propagates_bridge_failures():
    boom = FakeResponse(200, json.dumps({"ok": False, "error": "boom"}))
    with pytest.raises(BridgeError):
        _gather_remote([boom])


def test_gather_remote_users_and_collation_wire_rules(wpt_records):
    db_audit = ok_response(
        users=[
            {"login": "admin", "registered": "2020-01-02 03:04:05", "admin": True},
            {"login": "", "registered": None, "admin": True},       # empty login: dropped
            {"login": "x", "registered": None, "admin": "yes"},      # non-bool admin: dropped
            {"login": 7, "registered": None, "admin": True},        # non-str login: dropped
            {"registered": None, "admin": True},                     # no login: dropped
            {"login": "odd", "registered": 123, "admin": True},      # bad registered: dropped
            {"login": "legacy", "registered": None, "admin": True},  # kept
            "garbage",                                                # not a dict: dropped
        ],
        tables=[
            {"name": "a", "collation": "utf8mb4_general_ci"},
            {"name": "b", "collation": ""},    # bridge NULL -> "": None/None
            {"name": "c", "collation": "binary"},  # no "_": its own charset
            {"name": "d", "collation": None},   # wrong-typed: unknown
            {"name": "e"},                      # absent: unknown
        ],
    )
    data, _ = _gather_remote([_info_payload(), db_audit])
    # malformed entries drop silently; kept entries keep the wire shape
    assert data.admin_users == [
        {"login": "admin", "registered": "2020-01-02 03:04:05", "admin": True},
        {"login": "legacy", "registered": None, "admin": True},
    ]
    no_facts = TableFact(rows=0, size_bytes=None, data_free_bytes=None,
                         collation=None, charset=None)
    assert data.tables["a"] == TableFact(rows=0, size_bytes=None, data_free_bytes=None,
                                         collation="utf8mb4_general_ci", charset="utf8mb4")
    assert data.tables["b"] == no_facts
    assert data.tables["c"] == TableFact(rows=0, size_bytes=None, data_free_bytes=None,
                                         collation="binary", charset="binary")
    assert data.tables["d"] == no_facts
    assert data.tables["e"] == no_facts
    # the drop is debug-logged as a count, never with entry contents
    drops = [r for r in wpt_records
             if r.name == "wpt.audit.data" and r.levelno == logging.DEBUG
             and "dropped" in r.getMessage()]
    assert len(drops) == 1
    assert "6 malformed entries dropped" in drops[0].getMessage()
    for record in wpt_records:
        assert "garbage" not in record.getMessage()

    # measured empty vs unknown: [] is a real measurement, null/absent is not
    data_empty, _ = _gather_remote([_info_payload(), ok_response(users=[])])
    assert data_empty.admin_users == []
    data_null, _ = _gather_remote([_info_payload(), ok_response(users=None)])
    assert data_null.admin_users is None


# ---------------------------------------------------------- local (zip mode)


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


def _create(table: str, columns: list[str], charset: str | None = None) -> bytes:
    cols = ", ".join("`%s` text" % c for c in columns)
    tail = " DEFAULT CHARSET=%s" % charset if charset else ""
    return ("CREATE TABLE `%s` (%s)%s;\n" % (table, cols, tail)).encode()


#: Per-table DEFAULT CHARSET clauses the fixture dumps carry: utf8mb4
#: options, a latin1 posts table (the migration landmine) and a CREATE
#: without the clause (charset unknown — never guessed).
DUMP_CHARSETS = {"wp_options": "utf8mb4", "wp_posts": "latin1",
                 "wp_postmeta": None}


def _insert(table: str, rows: list) -> bytes:
    tuples = ",".join("(" + ",".join(_cell_sql(c) for c in row) + ")" for row in rows)
    return ("INSERT INTO `%s` VALUES %s;\n" % (table, tuples)).encode()


def _post_rows(spec: dict[tuple[str, str], int]) -> list[tuple]:
    rows = []
    post_id = 0
    for (post_type, post_status), n in spec.items():
        for _ in range(n):
            post_id += 1
            rows.append((post_id, post_type, post_status))
    return rows


POSTS_SPEC = {
    ("post", "publish"): 2,
    ("page", "publish"): 1,
    ("revision", "inherit"): 4,
    ("post", "auto-draft"): 1,
    ("attachment", "inherit"): 7,
    ("nav_menu_item", "publish"): 1,
    ("nav_menu_item", "inherit"): 2,
}


def _options_rows() -> list[tuple]:
    return [
        (1, "siteurl", _ser_str(SITE), "yes"),
        (2, "home", _ser_str(SITE), "yes"),
        (3, "template", _ser_str("sample-theme"), "yes"),
        (4, "stylesheet", _ser_str("sample-theme"), "yes"),
        (5, "blog_public", _ser_int(0), "yes"),
        (6, "active_plugins", _ser_list(ACTIVE_PLUGINS), "yes"),
        (7, "big_cache_option", BIG_OPTION, "yes"),
        (8, "small_option", _ser_str("y" * 20), "no"),
    ]


def _dump_bytes(posts_spec=None, options_rows=None) -> bytes:
    """A small wp_options + wp_posts + wp_postmeta dump (analyzer-style bytes)."""
    parts = [
        _create("wp_options", ["option_id", "option_name", "option_value", "autoload"],
                DUMP_CHARSETS["wp_options"]),
        _create("wp_posts", ["ID", "post_type", "post_status"],
                DUMP_CHARSETS["wp_posts"]),
        _create("wp_postmeta", ["meta_id", "post_id", "meta_key"],
                DUMP_CHARSETS["wp_postmeta"]),
        _insert("wp_options", _options_rows() if options_rows is None else options_rows),
        _insert("wp_posts", _post_rows(POSTS_SPEC if posts_spec is None else posts_spec)),
        _insert("wp_postmeta", [(1, 1, "_edit_last")]),
    ]
    return b"".join(parts)


def _write_zip(tmp_path, files):
    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        for name, blob in files:
            zf.writestr(name, blob)
    return zpath


def test_gather_local_maps_analyzer_and_tree(tmp_path):
    zpath = _write_zip(tmp_path, LOCAL_TREE)
    dump_bytes = _dump_bytes()
    settings = Settings(db=DbSettings(autoload_big_bytes=100))
    data = gather_local(io.BytesIO(dump_bytes), ZipSource(zpath), settings)

    assert data.mode == "local"
    assert data.siteurl == SITE
    assert data.home == SITE
    assert data.template == "sample-theme"
    assert data.theme_versions == {"sample-theme": "2.1.4"}  # child has no header
    assert data.blog_public == 0            # measured zero (a real value)
    assert data.active_plugins == ACTIVE_PLUGINS
    assert data.plugin_catalog == {}        # a zip has no version data
    assert data.wp_version is None          # fixture zip ships no version.php
    assert data.mu_plugins is None
    assert data.uploads_basedir == "wp-content/uploads"
    assert data.posts == POSTS_SPEC
    assert data.revisions == 5             # 4 revision + 1 auto-draft rows
    assert data.attachments == 7           # posts[("attachment", "inherit")]
    assert data.nav_menu_items == 3        # ALL ("nav_menu_item", *) groups: 1 + 2
    assert data.expired_transients is None  # undeterminable offline
    assert data.autoload_bytes is None      # only big_autoload_options is known
    assert data.orphan_meta == {}           # unknown offline — NOT zero
    assert data.big_autoload_options == [("big_cache_option", len(BIG_OPTION.encode("utf-8")))]
    assert data.live_refs is None
    assert data.admin_users is None  # no users tables in the dump: unknown

    # TableFact mapping mirrors the analyzer exactly (rows, bytes, free=None),
    # collation unknown locally, charset from the CREATE's DEFAULT CHARSET
    model = analyze(io.BytesIO(dump_bytes), DbSettings(autoload_big_bytes=100))
    assert set(data.tables) == set(model.tables) == {"wp_options", "wp_posts", "wp_postmeta"}
    for name, stats in model.tables.items():
        assert data.tables[name] == TableFact(
            rows=stats.row_count, size_bytes=stats.data_bytes, data_free_bytes=None,
            collation=None, charset=DUMP_CHARSETS[name])
    assert data.tables["wp_options"].charset == "utf8mb4"
    assert data.tables["wp_posts"].charset == "latin1"   # the landmine fixture
    assert data.tables["wp_postmeta"].charset is None    # CREATE without the clause
    assert data.tables["wp_options"].rows == 8
    assert data.tables["wp_posts"].rows == 18
    assert data.tables["wp_postmeta"].rows == 1

    # walked tree from the real ZipSource: dirs + files, no duplicates
    paths = [e.path for e in data.entries]
    assert len(paths) == len(set(paths))
    assert set(paths) == LOCAL_TREE_PATHS
    by_path = {e.path: e for e in data.entries}
    assert by_path["wp-content/uploads"].is_dir
    jpg = by_path["wp-content/uploads/2023/10/a.jpg"]
    assert not jpg.is_dir and jpg.size == len(JPG)


def test_gather_local_maps_locale(tmp_path):
    """[L17] The local gather maps the analyzer's WPLANG fact into
    AuditData.locale — the SITE locale as DATA (the integrity check
    resolves the comparison basis from it itself; an absent option is
    unknown, never a guessed "en_US")."""
    zpath = _write_zip(tmp_path, [("readme.html", b"<h1>WP</h1>")])
    dump_bytes = _dump_bytes(
        options_rows=[
            (1, "siteurl", _ser_str(SITE), "yes"),
            (2, "WPLANG", "fr_CA", "yes"),
        ],
    )
    data = gather_local(io.BytesIO(dump_bytes), ZipSource(zpath), Settings())
    assert data.locale == "fr_CA"
    # absent WPLANG: unknown
    dump_no_lang = _dump_bytes(
        options_rows=[(1, "siteurl", _ser_str(SITE), "yes")],
    )
    data2 = gather_local(io.BytesIO(dump_no_lang), ZipSource(zpath),
                          Settings())
    assert data2.locale is None


def test_uploads_basedir_detection_rules():
    def gather_with(entries):
        return gather_local(io.BytesIO(b""), _WalkStub(entries), Settings())

    under = Entry(path="wp-content/uploads/2023/a.jpg", is_dir=False, size=5)
    assert gather_with([under]).uploads_basedir == "wp-content/uploads"
    explicit_dir = Entry(path="wp-content/uploads", is_dir=True, size=0)
    assert gather_with([explicit_dir]).uploads_basedir == "wp-content/uploads"
    plain_file = Entry(path="wp-content/uploads", is_dir=False, size=9)
    assert gather_with([plain_file]).uploads_basedir is None
    near_miss = Entry(path="wp-content/uploads-backup/a.jpg", is_dir=False, size=5)
    assert gather_with([near_miss]).uploads_basedir is None
    elsewhere = Entry(path="wp-content/themes/x/uploads/a.jpg", is_dir=False, size=5)
    assert gather_with([elsewhere]).uploads_basedir is None
    nothing = Entry(path="readme.html", is_dir=False, size=1)
    assert gather_with([nothing]).uploads_basedir is None


def test_gather_local_measured_zero_vs_unknown(tmp_path):
    zpath = _write_zip(tmp_path, [("readme.html", b"<h1>WP</h1>")])
    dump_bytes = _dump_bytes(
        posts_spec={("post", "publish"): 1},
        options_rows=[(1, "siteurl", _ser_str(SITE), "yes")],
    )
    data = gather_local(io.BytesIO(dump_bytes), ZipSource(zpath), Settings())
    # a real posts table measured these as ZERO — 0, never None
    assert data.posts == {("post", "publish"): 1}
    assert data.revisions == 0
    assert data.attachments == 0
    assert data.nav_menu_items == 0
    # facts a dump cannot know are unknown — None/{}, never 0
    assert data.expired_transients is None
    assert data.autoload_bytes is None
    assert data.wp_version is None
    assert data.mu_plugins is None
    assert data.orphan_meta == {}
    assert data.plugin_catalog == {}
    assert data.uploads_basedir is None
    assert data.admin_users is None  # no users tables in the dump: unknown

    # remote counterpart: measured zeros keep their orphan_meta keys —
    # {} would mean unknown, present keys with 0 mean measured zero
    data_r, _ = _gather_remote([
        ok_response(plugins={}),
        ok_response(posts=[], revisions=0, expired_transients=0,
                    orphan_meta={"postmeta": 0, "termmeta": 0, "commentmeta": 0},
                    tables=[], autoload_bytes=0, attachments=0, nav_menu_items=0),
    ])
    assert data_r.revisions == 0
    assert data_r.expired_transients == 0
    assert data_r.orphan_meta == {"postmeta": 0, "termmeta": 0, "commentmeta": 0}
    assert data_r.attachments == 0
    assert data_r.nav_menu_items == 0
    assert data_r.autoload_bytes == 0
    assert data_r.posts == {}
    assert data_r.tables == {}
    assert data_r.admin_users is None  # absent users key: unknown, not measured-empty


def test_gather_local_big_autoload_threshold(tmp_path):
    # big_cache_option autoloads at 309 serialized bytes
    zpath = _write_zip(tmp_path, [("wp-config.php", b"<?php // config")])
    dump_bytes = _dump_bytes()
    source = ZipSource(zpath)
    default = gather_local(io.BytesIO(dump_bytes), source, Settings())
    assert default.big_autoload_options == []  # 309 < the packaged 102400
    assert default.uploads_basedir is None     # tree has no uploads dir
    low = gather_local(io.BytesIO(dump_bytes), source,
                       Settings(db=DbSettings(autoload_big_bytes=100)))
    assert low.big_autoload_options == [("big_cache_option", len(BIG_OPTION.encode("utf-8")))]


def test_gather_local_table_charset_from_create_sql(tmp_path):
    """Local charset facts come from the CREATE TABLE text the analyzer
    already harvested: the DEFAULT CHARSET token passes through, a
    CREATE without the clause stays None (unknown, never guessed from
    the dump-wide SET NAMES), and collation stays None locally (a dump
    states the charset, not the full collation — analyzer round)."""
    zpath = _write_zip(tmp_path, [("readme.html", b"<h1>WP</h1>")])
    dump = b"".join([
        b"SET NAMES utf8mb4;\n",
        _create("wp_options", ["option_id", "option_name", "option_value",
                               "autoload"], charset="utf8mb4"),
        _create("wp_posts", ["ID", "post_type", "post_status"],
                charset="latin1"),
        _create("wp_postmeta", ["meta_id", "post_id", "meta_key"]),
        _insert("wp_options", [(1, "siteurl", _ser_str(SITE), "yes")]),
    ])
    data = gather_local(io.BytesIO(dump), ZipSource(zpath), Settings())
    assert data.tables["wp_options"].charset == "utf8mb4"
    assert data.tables["wp_posts"].charset == "latin1"
    assert data.tables["wp_postmeta"].charset is None  # no clause -> unknown
    assert all(f.collation is None for f in data.tables.values())
    assert data.admin_users is None  # no users tables in the dump: unknown


def test_gather_local_admin_users_from_dump(tmp_path):
    """Local admin facts map 1:1 from the model, in the SAME wire shape the
    remote db_audit users payload produces (the users check is mode-blind);
    a dump without usable wp_users/wp_usermeta stays None — unknown, never
    a guessed []."""
    zpath = _write_zip(tmp_path, [("readme.html", b"<h1>WP</h1>")])
    dump = b"".join([
        _create("wp_options", ["option_id", "option_name", "option_value",
                               "autoload"], "utf8mb4"),
        _create("wp_users", ["ID", "user_login", "user_registered"]),
        _create("wp_usermeta", ["umeta_id", "user_id", "meta_key",
                                "meta_value"]),
        _insert("wp_options", [(1, "siteurl", _ser_str(SITE), "yes")]),
        _insert("wp_users", [
            (2, "root", None),
            (1, "admin", "2019-05-14 09:30:00"),
        ]),
        _insert("wp_usermeta", [
            (10, 1, "wp_user_level", "10"),
            (11, 2, "wp_user_level", "10"),
        ]),
    ])
    data = gather_local(io.BytesIO(dump), ZipSource(zpath), Settings())
    assert data.admin_users == [
        {"login": "admin", "registered": "2019-05-14 09:30:00", "admin": True},
        {"login": "root", "registered": None, "admin": True},
    ]
    # a dump without users tables: unknown (None), never a guessed []
    data_none = gather_local(io.BytesIO(_dump_bytes()), ZipSource(zpath),
                             Settings())
    assert data_none.admin_users is None


# --------------------------------------------------------------- logging


def test_gather_logging_contract(wpt_records, tmp_path):
    data_r, _ = _gather_remote([_info_payload(), _db_audit_payload()])
    infos = [r for r in wpt_records
             if r.name == "wpt.audit.data" and r.levelno == logging.INFO]
    assert len(infos) == 1
    assert "mode=ftp" in infos[0].getMessage()
    assert "entries=%d" % len(data_r.entries) in infos[0].getMessage()

    zpath = _write_zip(tmp_path, LOCAL_TREE)
    data_l = gather_local(io.BytesIO(_dump_bytes()), ZipSource(zpath),
                          Settings(db=DbSettings(autoload_big_bytes=100)))
    infos = [r for r in wpt_records
             if r.name == "wpt.audit.data" and r.levelno == logging.INFO]
    assert len(infos) == 2
    assert "mode=local" in infos[1].getMessage()
    assert "entries=%d" % len(data_l.entries) in infos[1].getMessage()

    # option VALUES, URLs and plugin names never reach any log record
    # (option NAMES are permitted at debug — wpt.localmode.analyzer policy)
    for record in wpt_records:
        msg = record.getMessage()
        assert "site.example.test" not in msg
        assert "sample-theme" not in msg
        assert "Akismet" not in msg


def _contested_dump_bytes() -> bytes:
    """A dump whose OPTIONS identity is contested — AIOSEO 4.x's own
    ``aioseo_options`` carrying the core column pair beside ``wp_options``.
    On such a dump the analyzer never reads the options table, so it cannot
    derive the prefix the posts table is located by, and the active set is
    UNMEASURED.
    """
    return b"".join((
        _create("wp_options", ["option_id", "option_name", "option_value",
                               "autoload"], DUMP_CHARSETS["wp_options"]),
        _create("aioseo_options", ["id", "option_name", "option_value",
                                   "added"]),
        _create("wp_posts", ["ID", "post_type", "post_status"],
                DUMP_CHARSETS["wp_posts"]),
        _insert("wp_options", _options_rows()),
        _insert("aioseo_options", [(1, "aioseo_options", "a:0:{}", "1")]),
        _insert("wp_posts", _post_rows(POSTS_SPEC)),
    ))


def test_an_unmeasured_local_gather_logs_unknown_never_zero(
        wpt_records, tmp_path):
    """A count the dump cannot support prints as ``unknown``, never ``0``.

    The measured defect: on a contested-identity dump the summary line read
    ``plugins=0 post_groups=0 ... db_media_refs=unknown`` — two arguments
    on the SAME line that already admits it measured nothing, yet claimed
    zero plugins and zero post groups.  ``0`` is a positive claim, and the
    analyzer's own contract (``ActiveSet.plugins is None`` is not []; the
    posts table is located by the prefix the options table declares) is
    exactly what makes both counts unreadable.  The fix is in the LINE, not
    in the data layer: ``AuditData`` keeps its measured-or-unknown fields.
    """
    zpath = _write_zip(tmp_path, LOCAL_TREE)
    dump_bytes = _contested_dump_bytes()
    # the CONTROL: the data layer really is unmeasured, not zero
    data = gather_local(io.BytesIO(dump_bytes), ZipSource(zpath), Settings())
    assert data.active_plugins is None
    assert data.posts == {}
    assert data.db_refs is None

    (line,) = [r.getMessage() for r in wpt_records
               if r.name == "wpt.audit.data" and r.levelno == logging.INFO]
    assert "mode=local" in line
    assert "plugins=unknown" in line, line
    assert "post_groups=unknown" in line, line
    assert "db_media_refs=unknown" in line, line
    assert "plugins=0" not in line and "post_groups=0" not in line, line

    # ... and a MEASURED run still prints integers for the same fields
    wpt_records.clear()
    gather_local(io.BytesIO(_dump_bytes()), ZipSource(zpath), Settings())
    (measured,) = [r.getMessage() for r in wpt_records
                   if r.name == "wpt.audit.data" and r.levelno == logging.INFO]
    assert f"plugins={len(ACTIVE_PLUGINS)}" in measured, measured
    assert "post_groups=%d" % len(POSTS_SPEC) in measured, measured
    # the two fields under test are integers on a measured dump; this
    # fixture's own db_media_refs is separately unknown (its postmeta
    # carries no meta_value), which is the OTHER half of the same rule
    assert "plugins=unknown" not in measured, measured
    assert "post_groups=unknown" not in measured, measured


def test_gather_local_reads_wp_version_php(tmp_path):
    """wp-includes/version.php in the zip populates wp_version (None stays
    None only when the file is missing/unparseable — unknown, not guessed)."""
    import zipfile

    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("wp-includes/version.php",
                    b"<?php\n$wp_version = '7.1';\n")
        zf.writestr("wp-content/uploads/x.txt", b"y")
    settings = Settings()
    data = gather_local(io.BytesIO(_dump_bytes()), ZipSource(zpath), settings)
    assert data.wp_version == "7.1"

    zpath2 = tmp_path / "noversion.zip"
    with zipfile.ZipFile(zpath2, "w") as zf:
        zf.writestr("wp-includes/version.php", b"<?php // broken")
    data2 = gather_local(io.BytesIO(_dump_bytes()), ZipSource(zpath2), settings)
    assert data2.wp_version is None


def test_gathers_expose_the_source_for_content_checks(tmp_path):
    """Both gathers set data.source — the lazy read seam for checks that
    scan file CONTENT at check time (the suspicious-pattern scanner)."""
    zpath = _write_zip(tmp_path, LOCAL_TREE)
    src = ZipSource(zpath)
    data = gather_local(io.BytesIO(_dump_bytes()), src, Settings())
    assert data.source is src


def test_R6_42_gather_local_threads_the_deadline_into_db_refs(
        monkeypatch, tmp_path):
    """R6-42: gather_local omitted ``deadline=`` on the db-refs pass, so a
    slow dump scan ran past --deadline and failed only later."""
    import time

    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    zpath = _write_zip(tmp_path, LOCAL_TREE)
    seen = {}

    def _slow_refs(dump, extensions, dirs=None, deadline=None):
        seen["deadline"] = deadline
        time.sleep(0.25)
        deadline.check("database media references")
        return set()

    monkeypatch.setattr("wpt.audit.data.db_refs_from_dump", _slow_refs)
    budget = Deadline(0.2)
    with pytest.raises(DeadlineExceeded):
        gather_local(io.BytesIO(_dump_bytes()), ZipSource(zpath),
                     Settings(), budget)
    assert seen["deadline"] is budget
