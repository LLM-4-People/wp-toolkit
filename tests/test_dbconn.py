"""Tests for the direct-database source (wpt.localmode.dbconn).

No live database is ever contacted: :class:`FakeDb` implements the
:class:`~wpt.localmode.dbconn.DbConnection` seam (the five methods the
toolkit actually uses), so the whole offline path — connect, audit,
named-op SQL, re-dump — is exercised deterministically.

Test -> behavior map:
  test_the_one_accepted_uri_form ............ the canonical form, the
        mysql+pymysql alias, host/port/charset defaults, percent-decoded
        userinfo; every other shape refused with the accepted form named
  test_a_uri_never_renders_its_password ..... str/repr/redacted form, and a
        driver error quoting the DSN redacts too
  test_db_password_resolution ............... --db-password-env wins over an
        inline password; the env-var path IS the FTP credential path
        (unset -> the same clean refusal); no env var -> the inline one;
        neither -> None (a socket-authenticated server is legitimate)
  test_a_missing_driver_is_one_line ......... no pymysql installed -> a
        WptError naming the package and the install command, never a
        traceback, and no other command is affected
  test_escape_value ........................ every cell shape mysqldump
        renders: NULL, numbers, Decimal (no exponent), date/time types,
        UTF-8 text with quotes/backslashes/control chars, a non-UTF-8 BLOB
        as a 0x hex literal
  test_quote_ident .......................... backticks, and a backtick
        inside a name doubled (the bridge's wpt_backtick rule)
  test_scratch_table_filter .................. bridge-owned restore scratch
        names are never enumerated (audit, dump, optimize)
  test_contract_the_bridge_sql .............. TABLES_SQL, the scratch regex
        and every db_clean/db_audit statement are the bridge's OWN text,
        extracted from wpt/wpbridge/bridge.php — the mirror cannot drift
  test_schema_tables ........................ the wire rows the db_audit
        converters expect, with the bridge's reserved-name filter applied
  test_dump_round_trips_through_the_analyzer  dump -> analyze: same tables,
        same row counts, same columns, and the VALUES spot-checked
        (siteurl, a serialized option, a blob, escaped quotes)
  test_dump_batches_rows .................... extended INSERTs are flushed
        on the row cap, never merged past it
  test_the_dump_survives_a_server_without_consistent_snapshots  a refused
        snapshot is one warning; the artifact is still written and the
        read view is still closed
  test_dump_refuses_to_overwrite ............ an existing artifact is never
        clobbered (a dump IS the rollback)
  test_a_failed_dump_leaves_nothing ........ an exception (and an expired
        deadline) removes the .part: no half artifact that looks importable
  test_doctor_database_row_pass / _fail ..... --db-uri adds a connectivity
        row to the local panel; a refused login is a FAIL row, never a
        traceback, and the row never prints the password
"""

import io
import json
import re
from pathlib import Path

import pytest

from tests.fakes import FakeResponse, FakeSession
from wpt.config import CredentialError, redact_text
from wpt.localmode import dbconn
from wpt.localmode.dbconn import (DRIVER_MODULE, DRIVER_PACKAGE, DbUriError,
                                  dump_database, escape_value, is_scratch_table,
                                  parse_db_uri, quote_ident,
                                  resolve_db_password, schema_tables)
from wpt.types import WptError

REPO = Path(__file__).resolve().parents[1]
BRIDGE = REPO / "wpt" / "wpbridge" / "bridge.php"

#: A small WordPress-shaped database: real DDL, real option values, a cell
#: that needs escaping in both directions and a BLOB that does not decode.
OPTIONS_CREATE = (
    "CREATE TABLE `wp_options` (\n"
    "  `option_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,\n"
    "  `option_name` varchar(191) NOT NULL DEFAULT '',\n"
    "  `option_value` longtext NOT NULL,\n"
    "  `autoload` varchar(20) NOT NULL DEFAULT 'yes',\n"
    "  PRIMARY KEY (`option_id`),\n"
    "  UNIQUE KEY `option_name` (`option_name`)\n"
    ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
)
POSTS_CREATE = (
    "CREATE TABLE `wp_posts` (\n"
    "  `ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,\n"
    "  `post_author` bigint(20) unsigned NOT NULL DEFAULT 0,\n"
    "  `post_content` longtext NOT NULL,\n"
    "  `post_title` text NOT NULL,\n"
    "  `post_type` varchar(20) NOT NULL DEFAULT 'post',\n"
    "  `post_status` varchar(20) NOT NULL DEFAULT 'publish',\n"
    "  PRIMARY KEY (`ID`)\n"
    ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
)

WP_OPTIONS_ROWS = [
    (1, "siteurl", "https://example.test", "yes"),
    (2, "home", "https://example.test", "yes"),
    (3, "active_plugins",
     'a:1:{i:0;s:35:"litespeed-cache/litespeed-cache.php";}', "yes"),
    (4, "blog_public", "0", "yes"),
    (5, "custom_blob", b"\xff\xfe\x00binary", "no"),
]
WP_POSTS_ROWS = [
    (1, 1, "L'été — 'quoted' \\ backslash", "Bonjour", "post", "publish"),
    (2, 1, "draft body", "Draft", "post", "draft"),
]

DB_URI = "mysql://wpuser:inline-secret@db.internal:3307/wp_stage"


# --------------------------------------------------------------- the double


class FakeDb:
    """A :class:`DbConnection` double over an in-memory table set.

    Scripted at the STATEMENT level, so a test asserts the exact SQL the
    tool runs: ``schema`` is what information_schema reports, ``counts``
    and ``deletes`` map a distinctive fragment of a statement to its
    result, ``rows`` are the tuples ``SELECT *`` returns, ``create`` is the
    DDL ``SHOW CREATE TABLE`` answers, and ``failures`` makes a matching
    statement raise (the per-op catch-all the bridge has too).
    """

    def __init__(self, *, schema=None, counts=None, deletes=None, rows=None,
                 create=None, failures=None, options_tables=("wp_options",)):
        self.schema = dict(schema or {})
        self.counts = dict(counts or {})
        self.deletes = dict(deletes or {})
        self.rows = dict(rows or {})
        self.create = dict(create or {})
        self.failures = dict(failures or {})
        self.options_tables = list(options_tables)
        self.executed: list[str] = []
        self.queried: list[str] = []
        self.closed = False
        #: optional hook called with every executed statement — a test uses
        #: it to make the database actually change (a delete makes the
        #: matching count drop to zero, exactly as a server would).
        self.on_execute = None

    # -- DbConnection ----------------------------------------------------
    def query_rows(self, sql: str) -> list[tuple]:
        self.queried.append(sql)
        if sql == dbconn.TABLES_SQL:
            return [(row["name"], row.get("rows", 0), row.get("size_mb", 0.0),
                     row.get("data_free_kb", 0.0), row.get("collation", ""))
                    for row in self.schema.values()]
        if "information_schema.COLUMNS" in sql:
            return [(name, column)
                    for name in self.options_tables
                    for column in ("option_name", "option_value")]
        for needle, value in self.counts.items():
            if needle in sql:
                return [(value,)]
        return [(0,)]

    def execute(self, sql: str) -> int:
        self.executed.append(sql)
        for needle, exc in self.failures.items():
            if needle in sql:
                raise exc
        if sql.startswith("OPTIMIZE TABLE"):
            affected = 1
        else:
            affected = 0
            for needle, value in self.deletes.items():
                if needle in sql:
                    affected = value
        if self.on_execute is not None:
            self.on_execute(sql)
        return affected

    def stream_rows(self, sql: str):
        yield from self.rows.get(sql.rsplit("`", 2)[-2], [])

    def show_create_table(self, table: str) -> str:
        return self.create.get(table, f"CREATE TABLE `{table}` (`id` int)")

    def close(self) -> None:
        self.closed = True


def wp_schema(**data_free_kb) -> dict:
    """The five core tables as information_schema rows (free KiB per name)."""
    free = {"wp_commentmeta": 0.0, "wp_options": 0.0, "wp_postmeta": 0.0,
            "wp_posts": 0.0, "wp_termmeta": 0.0}
    free.update(data_free_kb)
    return {
        name: {"name": name, "rows": 10, "size_mb": 0.5, "data_free_kb": value,
               "collation": "utf8mb4_unicode_ci"}
        for name, value in sorted(free.items())
    }


def wp_dumpable() -> FakeDb:
    """A two-table database the analyzer can read back."""
    return FakeDb(
        schema={"wp_options": {"name": "wp_options", "rows": len(WP_OPTIONS_ROWS),
                               "size_mb": 0.1, "data_free_kb": 0.0,
                               "collation": "utf8mb4_unicode_ci"},
                "wp_posts": {"name": "wp_posts", "rows": len(WP_POSTS_ROWS),
                             "size_mb": 0.2, "data_free_kb": 0.0,
                             "collation": "utf8mb4_unicode_ci"}},
        rows={"wp_options": WP_OPTIONS_ROWS, "wp_posts": WP_POSTS_ROWS},
        create={"wp_options": OPTIONS_CREATE, "wp_posts": POSTS_CREATE},
    )


def _db_settings():
    from wpt.settings import load

    return load().db


# ------------------------------------------------------------------ the URI


def test_the_one_accepted_uri_form():
    uri = parse_db_uri(DB_URI)
    assert (uri.user, uri.password) == ("wpuser", "inline-secret")
    assert (uri.host, uri.port, uri.database) == ("db.internal", 3307, "wp_stage")
    assert uri.charset == "utf8mb4"
    # the alias, an explicit host, the defaults, and an explicit charset
    alias = parse_db_uri("mysql+pymysql://localhost/wp_site?charset=latin1")
    assert (alias.host, alias.port, alias.database) == ("localhost", 3306, "wp_site")
    assert alias.charset == "latin1"
    assert alias.user is None and alias.password is None
    defaulted = parse_db_uri("mysql:///wp_site")
    assert (defaulted.host, defaulted.port) == ("127.0.0.1", 3306)
    # percent-escapes: a password may contain @ : / and still parse
    tricky = parse_db_uri("mysql://u:p%40ss%3Aword@192.0.2.5/my%2Ddb")
    assert tricky.password == "p@ss:word"
    assert tricky.database == "my-db"
    assert tricky.host == "192.0.2.5"


@pytest.mark.parametrize("text, needle", [
    ("", "expected"),
    ("postgres://u:p@h/db", "not supported"),
    ("mysql://u:p@h", "names no database"),
    ("mysql://u:p@h/db?ssl=1", "does not accept"),
    ("mysql://u:p@h:notaport/db", "port is not a number"),
])
def test_every_other_uri_shape_is_refused(text, needle):
    # A silently misread DSN would connect somewhere the operator did not
    # type, so every rejection names the accepted form or the exact reason.
    with pytest.raises(DbUriError) as excinfo:
        parse_db_uri(text)
    assert needle in str(excinfo.value)


def test_a_uri_never_renders_its_password():
    uri = parse_db_uri("mysql://wpuser:sup3rs3cret@db.internal/wp_stage")
    for rendered in (str(uri), repr(uri), uri.redacted, f"{uri}"):
        assert "sup3rs3cret" not in rendered
        assert "***" in rendered
        assert "wpuser" in rendered and "wp_stage" in rendered
    # a driver message that quotes the DSN is redacted on the way out
    message = "Access denied (mysql://wpuser:sup3rs3cret@h/db)"
    assert "sup3rs3cret" not in redact_text(message)


def test_db_password_resolution(monkeypatch):
    uri = parse_db_uri(DB_URI)
    monkeypatch.setenv("WPT_DB_PASS", "from-env")
    # the env var wins: it keeps the secret out of the command line
    assert resolve_db_password(uri, "WPT_DB_PASS") == "from-env"
    # ... and it IS the FTP credential path (same refusal when unset)
    monkeypatch.delenv("WPT_DB_PASS")
    with pytest.raises(CredentialError):
        resolve_db_password(uri, "WPT_DB_PASS")
    # no env var: the URI's own password, or none at all
    assert resolve_db_password(uri, None) == "inline-secret"
    assert resolve_db_password(parse_db_uri("mysql://root@db/wp"), None) is None


def test_C3_connect_caps_the_driver_timeouts_at_the_run_budget(monkeypatch):
    """C3: the driver hardcoded connect_timeout=10 / read_timeout=300, so a
    slow --db-uri connect outlived the run budget before doctor's post-check
    could see it.  Both are capped at the remaining budget and an expired
    budget never opens a connection."""
    import sys
    import types

    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    captured: dict = {}

    class _Raw:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def close(self):
            pass

    fake = types.ModuleType("pymysql")
    fake.__version__ = "test"
    fake.connect = lambda **kwargs: _Raw(**kwargs)
    monkeypatch.setitem(sys.modules, "pymysql", fake)
    monkeypatch.setattr(
        dbconn, "resolve_host_bounded",
        lambda host, port, deadline, **_kw: ["127.0.0.1"])

    budget = Deadline(5)
    dbconn.connect(parse_db_uri(DB_URI), deadline=budget)
    assert 0 < captured["connect_timeout"] <= 5
    assert 0 < captured["read_timeout"] <= 5
    assert captured["write_timeout"] == captured["read_timeout"]

    calls: list[dict] = []
    fake.connect = lambda **kwargs: calls.append(kwargs)
    expired = Deadline(0.05)
    expired._started -= 1.0
    with pytest.raises(DeadlineExceeded):
        dbconn.connect(parse_db_uri(DB_URI), deadline=expired)
    assert calls == []


def test_a_missing_driver_is_one_line(monkeypatch):
    """No driver installed is a named, installable answer — never a traceback."""
    import sys

    monkeypatch.setitem(sys.modules, DRIVER_MODULE, None)  # import -> ImportError
    with pytest.raises(DbUriError) as excinfo:
        dbconn.connect(parse_db_uri("mysql://u@h/db"))
    message = str(excinfo.value)
    assert DRIVER_PACKAGE in message and "pip install" in message
    assert len(message.splitlines()) == 1


# ------------------------------------------------------------ value writing


@pytest.mark.parametrize("value, expected", [
    (None, "NULL"),
    (True, "1"),
    (False, "0"),
    (42, "42"),
    (-7, "-7"),
    (1.5, "1.5"),
    ("plain", "'plain'"),
    ("it's", "'it\\'s'"),
    ('say "hi"', r"'say \"hi\"'"),
    ("back\\slash", "'back\\\\slash'"),
    ("line\nbreak\r\t", "'line\\nbreak\\r\\t'"),
    ("nul\x00end", "'nul\\0end'"),
    ("sub\x1a", "'sub\\Z'"),
    (b"bytes", "'bytes'"),
    ("L'été", r"'L\'été'"),
])
def test_escape_value(value, expected):
    assert escape_value(value) == expected


def test_escape_value_edge_types():
    from datetime import date, datetime, time, timedelta
    from decimal import Decimal

    assert escape_value(datetime(2024, 5, 4, 3, 2, 1)) == "'2024-05-04 03:02:01'"
    assert escape_value(date(2024, 5, 4)) == "'2024-05-04'"
    assert escape_value(time(3, 2, 1)) == "'03:02:01'"
    assert escape_value(timedelta(hours=1, minutes=2, seconds=3)) == "'01:02:03'"
    # a Decimal never renders in exponent form (not portable across servers)
    assert escape_value(Decimal("1E+2")) == "100"
    assert escape_value(Decimal("0.50")) == "0.50"
    # a BLOB that is not valid UTF-8 round-trips as a hex literal, losslessly
    assert escape_value(b"\xff\xfe\x00") == "0xfffe00"


def test_quote_ident():
    assert quote_ident("wp_options") == "`wp_options`"
    assert quote_ident("we`ird") == "`we``ird`"  # the bridge's wpt_backtick rule


@pytest.mark.parametrize("name, scratch", [
    ("wp_posts", False),
    ("wp_posts__wpt_0123abcd__s", True),
    ("wp_posts__wpt_0123abcd__o", True),
    ("wp_posts__wpt_0123abc__s", False),   # token too short
    ("wp_posts__wpt_0123abcd__x", False),  # not a reserved suffix
])
def test_scratch_table_filter(name, scratch):
    # Bridge-owned atomic-restore scratch tables are never a legitimate
    # audit / dump / optimize target (wpt_restore_scratch_name).
    assert is_scratch_table(name) is scratch


# ------------------------------------------------- the bridge contract pins


def _php_function(source: str, name: str) -> str:
    match = re.search(rf"function {name}\s*\(.*?\n\}}\n", source, re.S)
    assert match, f"{name} not found in bridge.php"
    return match.group(0)


def _php_literals(body: str) -> list[str]:
    """Every double-quoted PHP string in ``body``, in order, unescaped.

    PHP's ``\\\\`` is one backslash and ``\\"`` one quote; a placeholder keeps
    the first replacement from eating the second.
    """
    out = []
    for raw in re.findall(r'"((?:[^"\\]|\\.)*)"', body):
        out.append(raw.replace("\\\\", "\x00").replace('\\"', '"')
                   .replace("\x00", "\\"))
    return out


def _as_template(sql: str) -> str:
    """``{$wpdb->posts}`` -> the offline ``{p}posts`` placeholder."""
    return re.sub(r"\{\$wpdb->(\w+)\}", r"{p}\1", sql)


def _one(fragments, needle):
    hits = [f for f in fragments if needle in f]
    assert len(hits) == 1, f"expected exactly one bridge statement with {needle!r}"
    return hits[0]


def test_contract_the_bridge_sql():
    """Every offline statement IS the bridge's own text.

    The mirror is what keeps the hand-ported SQL out of an operator's
    migration; this test is what keeps the mirror honest. Edit one side and
    the suite fails here.
    """
    from wpt.actions.clean_db import (EXPIRED_TRANSIENTS_SQL, optimize_sql,
                                      orphan_sql, revisions_sql, transients_sql)

    source = BRIDGE.read_text(encoding="utf-8")
    clean = _php_function(source, "wpt_action_db_clean")
    audit = _php_function(source, "wpt_action_db_audit")
    transients = _php_function(source, "wpt_expired_transients_sql")

    # -- the shared expired-transient body (the bridge builds it from $head)
    body = "".join(_as_template(f) for f in _php_literals(transients))
    assert transients_sql(count=True) == "SELECT COUNT(*)" + body
    assert transients_sql(count=False) == "DELETE t, s" + body
    assert " ".join(EXPIRED_TRANSIENTS_SQL.split()) == " ".join(body.split())

    # -- revisions: the db_clean DELETE and the db_audit COUNT, one predicate
    assert revisions_sql(count=False) == _as_template(_php_literals(clean)[0])
    assert revisions_sql(count=True) == _as_template(
        _one(_php_literals(audit), "COUNT(*) FROM {$wpdb->posts} WHERE post_type"))

    # -- orphan_meta: the DELETE (its head carries the alias) and the COUNT
    clean_sql = _php_literals(clean)
    audit_sql = _php_literals(audit)
    for kind, alias in (("postmeta", "pm"), ("termmeta", "tm"),
                        ("commentmeta", "cm")):
        assert orphan_sql(kind, head_index=0) == _as_template(
            _one(clean_sql, f"DELETE {alias} FROM"))
        assert orphan_sql(kind, head_index=1) == _as_template(
            _one(audit_sql, f"FROM {{$wpdb->{kind}}} {alias} LEFT JOIN"))

    # -- optimize_tables: one statement per whitelisted table
    assert optimize_sql("wp_posts") == "OPTIMIZE TABLE `wp_posts`"
    assert re.search(r"'OPTIMIZE TABLE `'\s*\.\s*wpt_backtick\( \$t \)"
                     r"\s*\.\s*'`'", clean)

    # -- schema introspection: the db_audit tables query, verbatim
    assert " ".join(dbconn.TABLES_SQL.split()) == " ".join(
        _as_template(_one(audit_sql, "information_schema.TABLES")).split())

    # -- the reserved-name filter the bridge applies to the same rows
    reserved = _php_function(source, "wpt_restore_scratch_name")
    # PHP's delimiters are part of the literal; the pattern itself is not
    pattern = re.search(r"'([^']*__wpt_[^']*)'", reserved).group(1)
    assert dbconn.SCRATCH_NAME_RE.pattern == pattern.strip("/")


def test_the_options_rule_is_the_analyzers():
    """Prefix discovery asks for exactly the columns the analyzer's rule names."""
    from wpt.actions.clean_db import _OPTIONS_COLUMNS_SQL
    from wpt.localmode.analyzer import analyze

    assert "'option_name', 'option_value'" in _OPTIONS_COLUMNS_SQL
    dump = (
        f"{OPTIONS_CREATE};\n"
        "INSERT INTO `wp_options` VALUES (1,'siteurl','https://x.test','yes'),"
        "(2,'home','https://x.test','yes'),(3,'template','twentytwentyfive','yes'),"
        "(4,'stylesheet','twentytwentyfive','yes'),"
        "(5,'blog_public','1','yes');\n"
    ).encode("utf-8")
    assert analyze(io.BytesIO(dump), _db_settings()).table_prefix == "wp_"


def test_schema_tables_normalizes_and_filters():
    conn = FakeDb(schema={
        "wp_options": {"name": "wp_options", "rows": 5, "size_mb": 0.125,
                       "data_free_kb": 1024.0, "collation": "utf8mb4_unicode_ci"},
        "wp_posts__wpt_0123abcd__s": {"name": "wp_posts__wpt_0123abcd__s",
                                      "rows": 0, "size_mb": 0.0,
                                      "data_free_kb": 0.0, "collation": None},
    })
    rows = schema_tables(conn)
    # the scratch table is invisible (the bridge hides it too), and the row
    # is in the exact shape wpt.audit.data._tables_from_wire consumes
    assert [row["name"] for row in rows] == ["wp_options"]
    assert rows[0]["data_free_kb"] == 1024.0
    assert rows[0]["size_mb"] == 0.125
    assert rows[0]["collation"] == "utf8mb4_unicode_ci"
    from wpt.audit.data import _tables_from_wire

    assert _tables_from_wire(rows)["wp_options"].data_free_bytes == 1048576


# ------------------------------------------------------------- the re-dump


def _analyze(path):
    from wpt.localmode.analyzer import analyze

    with path.open("rb") as handle:
        return analyze(handle, _db_settings())


def test_dump_round_trips_through_the_analyzer(tmp_path):
    from wpt.localmode.sql_dump import iter_rows

    conn = wp_dumpable()
    out = tmp_path / "fresh.sql"
    stats = dump_database(conn, out, source="mysql://u:***@h/wp")

    assert stats.path == out and stats.tables == 2
    assert stats.rows == len(WP_OPTIONS_ROWS) + len(WP_POSTS_ROWS)
    text = out.read_text(encoding="utf-8")
    # mysqldump's frame — the analyzer skips it exactly as it skips a real one
    assert "SET NAMES utf8mb4" in text
    assert "DROP TABLE IF EXISTS `wp_options`;" in text
    assert text.index("DROP TABLE IF EXISTS `wp_options`;") < text.index(
        "INSERT INTO `wp_options`")
    assert "FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS" in text
    assert "-- Dump completed" in text
    # no credential in the artifact either
    assert "p@ss" not in text

    model = _analyze(out)
    assert set(model.tables) == {"wp_options", "wp_posts"}
    assert {name: stats.row_count for name, stats in model.tables.items()} == {
        "wp_options": len(WP_OPTIONS_ROWS), "wp_posts": len(WP_POSTS_ROWS)}
    assert model.table_prefix == "wp_"
    assert "option_name" in model.tables["wp_options"].columns
    assert model.posts == {("post", "publish"): 1, ("post", "draft"): 1}
    # spot-checked VALUES: scalars, a serialized option, and the cells that
    # needed escaping on the way out
    assert model.siteurl == "https://example.test"
    assert model.blog_public == 0
    assert model.active_plugins == ["litespeed-cache/litespeed-cache.php"]
    with out.open("rb") as handle:
        by_name = {row[1]: row[2] for row in iter_rows(handle, "wp_options")}
    assert by_name["custom_blob"] == b"\xff\xfe\x00binary"   # the hex literal
    assert by_name["blog_public"] == "0"
    with out.open("rb") as handle:
        posts = list(iter_rows(handle, "wp_posts"))
    assert posts[0][2] == "L'été — 'quoted' \\ backslash"
    assert posts[0][3] == "Bonjour"


def test_dump_batches_rows(tmp_path, monkeypatch):
    conn = wp_dumpable()
    conn.rows["wp_posts"] = WP_POSTS_ROWS * 3  # 6 rows
    monkeypatch.setattr(dbconn, "_INSERT_ROW_CAP", 2)
    out = tmp_path / "batched.sql"
    assert dump_database(conn, out).rows == len(WP_OPTIONS_ROWS) + 6
    inserts = [line for line in out.read_text(encoding="utf-8").splitlines()
               if line.startswith("INSERT INTO `wp_posts`")]
    assert len(inserts) == 3  # 2 + 2 + 2, never merged past the cap
    assert all(line.count("),(") == 1 for line in inserts)
    assert _analyze(out).tables["wp_posts"].row_count == 6


def test_the_dump_survives_a_server_without_consistent_snapshots(tmp_path, caplog):
    """A refused snapshot is ONE warning, never a lost artifact."""
    import logging

    parent = logging.getLogger("wpt")
    parent.addHandler(caplog.handler)
    try:
        with caplog.at_level(logging.WARNING, logger="wpt"):
            conn = wp_dumpable()
            conn.failures = {"START TRANSACTION": RuntimeError("not supported")}
            out = tmp_path / "snap.sql"
            stats = dump_database(conn, out)
    finally:
        parent.removeHandler(caplog.handler)
    assert out.exists()
    assert stats.rows == len(WP_OPTIONS_ROWS) + len(WP_POSTS_ROWS)
    assert "refused a consistent snapshot" in caplog.text
    assert _analyze(out).tables["wp_options"].row_count == len(WP_OPTIONS_ROWS)
    # the read view is closed either way
    assert "COMMIT" in conn.executed


def test_R22_a_planted_part_symlink_or_fifo_is_never_followed(tmp_path):
    """R22-P1: the re-dump wrote a FIXED ``<target>.part`` after checking
    only ``target.exists()``.  A planted symlink redirected the dump bytes
    into a victim; a FIFO blocked the open past --deadline.  The temp is now
    an O_CREAT|O_EXCL mkstemp sibling, so neither shape is touched, and an
    existing user ``.part`` is left intact."""
    import os

    out = tmp_path / "fresh.sql"
    victim = tmp_path / "victim.txt"
    victim.write_text("KEEP", encoding="utf-8")
    planted = tmp_path / "fresh.sql.part"
    planted.symlink_to(victim)
    stats = dump_database(wp_dumpable(), out)
    assert stats.rows > 0
    assert victim.read_text(encoding="utf-8") == "KEEP"
    assert planted.is_symlink()

    fifo_target = tmp_path / "fifo.sql"
    os.mkfifo(tmp_path / "fifo.sql.part")
    fd = os.open(tmp_path / "fifo.sql.part", os.O_RDONLY | os.O_NONBLOCK)
    try:
        assert dump_database(wp_dumpable(), fifo_target).rows > 0
    finally:
        os.close(fd)
    assert fifo_target.is_file()
    assert (tmp_path / "fifo.sql.part").exists()

    user_part = tmp_path / "user.sql.part"
    user_part.write_text("USER DATA", encoding="utf-8")
    assert dump_database(wp_dumpable(), tmp_path / "user.sql").rows > 0
    assert user_part.read_text(encoding="utf-8") == "USER DATA"
    assert not [path for path in tmp_path.iterdir()
                if path.name.startswith(".fresh.sql.")
                or path.name.startswith(".fifo.sql.")
                or path.name.startswith(".user.sql.")]


def test_R22_a_deadline_expiry_before_the_dump_leaves_no_temp(tmp_path):
    """The deadline check moved BEFORE mkstemp, so a spent run creates
    nothing (the old fixed .part was also removed, but only after opening)."""
    from wpt.types import WptError

    class Spent:
        def check(self, context):
            raise WptError(f"run deadline exceeded at {context!r}")

    out = tmp_path / "spent.sql"
    with pytest.raises(WptError, match="deadline"):
        dump_database(wp_dumpable(), out, deadline=Spent())
    assert not out.exists()
    assert not [path for path in tmp_path.iterdir()
                if path.name.endswith(".part")]


def test_dump_refuses_to_overwrite(tmp_path):
    out = tmp_path / "exists.sql"
    out.write_text("-- the operator's rollback\n", encoding="utf-8")
    with pytest.raises(WptError, match="rollback artifact"):
        dump_database(wp_dumpable(), out)
    assert out.read_text(encoding="utf-8") == "-- the operator's rollback\n"
    assert not (tmp_path / "exists.sql.part").exists()


@pytest.mark.parametrize("control", ["DeadlineExceeded", "StopRequested"])
def test_R23_stop_at_commit_removes_the_part_temp(tmp_path, control):
    """R23-P2: ``_end_snapshot`` ran in a ``finally`` OUTSIDE the unlink
    guard.  A COMMIT raising DeadlineExceeded/StopRequested (SIGTERM)
    replaced the verdict and skipped the unlink, leaving a COMPLETE
    ``.part`` that looked importable.  The close is inside the guarded
    region now; target absent and no temp residue."""
    from wpt.types import DeadlineExceeded, StopRequested

    raised = {"DeadlineExceeded": DeadlineExceeded,
              "StopRequested": StopRequested}[control]
    out = tmp_path / "commit.sql"
    conn = wp_dumpable()
    conn.failures = {"COMMIT": raised("run ended at snapshot close")}
    with pytest.raises(raised):
        dump_database(conn, out)
    assert not out.exists()
    assert not [path for path in tmp_path.iterdir()
                if path.name.startswith(f".{out.name}.")]


def test_a_failed_dump_leaves_nothing(tmp_path, monkeypatch):
    out = tmp_path / "partial.sql"
    conn = wp_dumpable()

    def _boom(_sql):
        raise RuntimeError("server died mid-table")

    monkeypatch.setattr(conn, "stream_rows", _boom)
    with pytest.raises(RuntimeError, match="server died"):
        dump_database(conn, out)
    assert not out.exists()
    assert not (tmp_path / "partial.sql.part").exists()

    # an expired deadline ends the run the same way — self-bounding, and
    # still no artifact an operator could mistake for a dump
    class Spent:
        def check(self, context):
            raise WptError(f"run deadline exceeded at {context!r}")

    with pytest.raises(WptError, match="deadline"):
        dump_database(wp_dumpable(), out, deadline=Spent())
    assert not out.exists()
    assert not (tmp_path / "partial.sql.part").exists()


# ------------------------------------------------------------- doctor row


def _doctor_ctx(tmp_path, monkeypatch, db):
    """A local-mode doctor Ctx whose database row uses ``db``."""
    import wpt.doctor
    from wpt.cli import Ctx
    from wpt.settings import load

    if db is not None:
        monkeypatch.setattr(
            wpt.doctor, "connect",
            lambda uri, password=None, deadline=None, settings=None: db)
    monkeypatch.setattr(wpt.doctor.shutil, "disk_usage",
                        lambda _p: type("U", (), {"free": 3 * 1024 ** 3})())
    monkeypatch.setattr(
        wpt.doctor.requests, "Session",
        lambda: FakeSession([FakeResponse(200, json.dumps(
            {"offers": [{"current": "7.1.1"}]}))]))
    return Ctx(source="local", settings=load(), backup_dir=tmp_path / "bk",
               db_uri=DB_URI, db_password="inline-secret")


def test_C3_doctor_database_row_threads_the_budget_and_propagates_expiry(
        tmp_path, monkeypatch):
    """C3: ``_database_check`` took no deadline, so the driver's fixed 10 s
    connect could outlive the run.  The budget reaches connect and an
    expired one ends the run instead of becoming a FAIL row."""
    import wpt.doctor
    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    captured: dict = {}

    class _Conn:
        def query_rows(self, _sql):
            return []

        def close(self):
            pass

    def _connect(uri, password=None, deadline=None, settings=None):
        captured["deadline"] = deadline
        return _Conn()

    monkeypatch.setattr(wpt.doctor, "connect", _connect)
    ctx = _doctor_ctx(tmp_path, monkeypatch, None)
    budget = Deadline(5)

    row = wpt.doctor._guarded("database (--db-uri)", wpt.doctor._database_check,
                              ctx, budget, deadline=budget)
    assert row["result"] == "PASS"
    assert captured["deadline"] is budget

    spent = Deadline(0.05)
    spent._started -= 1.0
    captured.clear()
    with pytest.raises(DeadlineExceeded):
        wpt.doctor._guarded("database (--db-uri)", wpt.doctor._database_check,
                            ctx, spent, deadline=spent)
    assert captured == {}                     # refused before connect


def test_doctor_database_row_pass(tmp_path, monkeypatch, capsys):
    """--db-uri adds a connectivity row to the reduced local panel."""
    import wpt.doctor

    db = wp_dumpable()
    ctx = _doctor_ctx(tmp_path, monkeypatch, db)
    assert wpt.doctor.run(ctx) == 0
    out = capsys.readouterr().out
    assert "| database (--db-uri) | PASS |" in out
    assert "wp_stage" in out and "db.internal:3307" in out
    assert "2 base table(s)" in out
    # the row renders the URI redacted, and closes its own connection
    assert "inline-secret" not in out
    assert db.closed is True


def test_doctor_database_row_fail(tmp_path, monkeypatch, capsys, caplog):
    """A refused login is a FAIL row and rc 1 — never a traceback."""
    import wpt.doctor

    def _refused(uri, password=None, deadline=None, settings=None):
        raise DbUriError(
            f"cannot connect to {uri.redacted}: "
            f"Access denied (using password: {'YES' if password else 'NO'})")

    ctx = _doctor_ctx(tmp_path, monkeypatch, None)
    monkeypatch.setattr(wpt.doctor, "connect", _refused)
    assert wpt.doctor.run(ctx) == 1
    out = capsys.readouterr().out
    assert "| database (--db-uri) | FAIL |" in out
    assert "Access denied" in out
    assert "inline-secret" not in out and "inline-secret" not in caplog.text


# ------------------------------------------------ round 12 (P2 regressions)


def test_R12_query_timeout_is_recomputed_from_the_remaining_budget():
    """R12-P2-6: read/write timeouts were fixed at connect time, so a query
    could outlive the run.  Each query re-arms the driver socket bound from
    ``remaining`` and checks AFTER the statement (a fake cursor that sleeps
    through the socket timeout still raises)."""
    import time

    from wpt.deadline import Deadline, DeadlineExceeded
    from wpt.localmode.dbconn import _PyMySqlConnection

    class _Sock:
        def settimeout(self, timeout):
            self.timeout = timeout

    class _Cursor:
        rowcount = 0

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def execute(self, _sql):
            time.sleep(0.4)

        def fetchall(self):
            return []

    class _Raw:
        read_timeout = 300
        write_timeout = 300

        def __init__(self):
            self._sock = _Sock()

        def cursor(self, *_args):
            return _Cursor()

    raw = _Raw()
    conn = _PyMySqlConnection(raw, deadline=Deadline(0.2))
    started = time.monotonic()
    with pytest.raises(DeadlineExceeded):
        conn.query_rows("SELECT 1")
    assert time.monotonic() - started >= 0.4
    assert 0 < raw.read_timeout <= 0.2
    assert 0 < raw.write_timeout <= 0.2
    assert 0 < raw._sock.timeout <= 0.2


def test_R12_database_host_resolution_is_bounded(monkeypatch):
    """R12-P2-6: ``pymysql.connect`` resolved the host itself, outside the
    run budget.  The connection owner resolves through the shared bounded
    resolver and hands the driver the numeric address."""
    import sys
    import types

    from wpt.deadline import Deadline

    captured: dict = {}

    class _Raw:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def close(self):
            pass

    fake = types.ModuleType("pymysql")
    fake.__version__ = "test"
    fake.connect = lambda **kwargs: _Raw(**kwargs)
    monkeypatch.setitem(sys.modules, "pymysql", fake)
    seen: list[tuple] = []

    def _resolve(host, port, deadline, **kwargs):
        seen.append((host, port, deadline, kwargs))
        return ["192.0.2.44"]

    monkeypatch.setattr(dbconn, "resolve_host_bounded", _resolve)
    budget = Deadline(5)
    dbconn.connect(parse_db_uri(DB_URI), deadline=budget)
    assert seen and seen[0][0] == "db.internal"
    assert seen[0][2] == budget.at
    assert captured["host"] == "192.0.2.44"


def test_R15_connect_falls_back_across_every_resolved_address(monkeypatch):
    """R15-P2: only ``addresses[0]`` was dialed, so an unreachable ::1
    refused a host whose IPv4 listener was reachable.  Every resolved
    address is tried, each with a share of the remaining budget, and a
    connection error falls through to the next one."""
    import sys
    import types

    from wpt.deadline import Deadline
    from wpt.localmode.dbconn import DbUriError

    attempts: list[dict] = []

    class _Raw:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def close(self):
            pass

    def _connect(**kwargs):
        attempts.append(kwargs)
        if kwargs["host"] == "::1":
            raise OSError("connection refused")
        return _Raw(**kwargs)

    fake = types.ModuleType("pymysql")
    fake.__version__ = "test"
    fake.connect = _connect
    monkeypatch.setitem(sys.modules, "pymysql", fake)
    monkeypatch.setattr(
        dbconn, "resolve_host_bounded",
        lambda host, port, deadline, **_kw: ["::1", "127.0.0.1"])

    budget = Deadline(0.8)
    connection = dbconn.connect(parse_db_uri(DB_URI), deadline=budget)
    try:
        assert [call["host"] for call in attempts] == ["::1", "127.0.0.1"]
        # The first attempt gets at most HALF the remaining budget, so a
        # refused address cannot consume the next one's chance.
        assert 0 < attempts[0]["connect_timeout"] <= 0.4
        assert attempts[1]["connect_timeout"] > 0
    finally:
        connection.close()

    # Every address failing keeps the last driver error, still one line.
    attempts.clear()

    def _refuse(**kwargs):
        attempts.append(kwargs)
        raise OSError("refused")

    fake.connect = _refuse
    with pytest.raises(DbUriError, match="cannot connect"):
        dbconn.connect(parse_db_uri(DB_URI), deadline=Deadline(1.0))
    assert len(attempts) == 2

    # An AUTHENTICATION verdict is not an address problem: do not repeat a
    # wrong password against every resolved address (lockout counters).
    class _AccessDenied(Exception):
        pass

    def _deny(**kwargs):
        attempts.append(kwargs)
        raise _AccessDenied(1045, "Access denied")

    attempts.clear()
    fake.connect = _deny
    with pytest.raises(DbUriError, match="Access denied"):
        dbconn.connect(parse_db_uri(DB_URI), deadline=Deadline(1.0))
    assert len(attempts) == 1


def test_R16_a_post_connect_deadline_closes_the_live_driver(monkeypatch):
    """R16-P2: the post-connect deadline check raised AFTER pymysql.connect
    had opened a session, leaking a live connection.  The refusal now closes
    the raw driver before re-raising."""
    import sys
    import time
    import types

    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    class _Raw:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    raw = _Raw()

    def _slow_connect(**_kwargs):
        time.sleep(0.05)
        return raw

    fake = types.ModuleType("pymysql")
    fake.__version__ = "test"
    fake.connect = _slow_connect
    monkeypatch.setitem(sys.modules, "pymysql", fake)
    monkeypatch.setattr(
        dbconn, "resolve_host_bounded",
        lambda host, port, deadline, **_kw: ["127.0.0.1"])

    with pytest.raises(DeadlineExceeded):
        dbconn.connect(parse_db_uri(DB_URI), deadline=Deadline(0.01))
    assert raw.closed is True


def test_R14_connect_recomputes_both_timeouts_after_dns(monkeypatch):
    """R14-P2: both driver timeouts were frozen BEFORE bounded DNS, so
    0.35 s of resolution plus a stale 0.5 s connect outlived a 0.5 s run
    deadline.  They are recomputed from the remaining budget, and the
    budget is checked before the dial."""
    import sys
    import time
    import types

    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    captured: dict = {}

    class _Raw:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def close(self):
            pass

    fake = types.ModuleType("pymysql")
    fake.__version__ = "test"
    fake.connect = lambda **kwargs: _Raw(**kwargs)
    monkeypatch.setitem(sys.modules, "pymysql", fake)

    def _slow_resolve(host, port, deadline, **_kw):
        time.sleep(0.35)
        return ["192.0.2.44"]

    monkeypatch.setattr(dbconn, "resolve_host_bounded", _slow_resolve)
    budget = Deadline(0.5)
    started = time.monotonic()
    dbconn.connect(parse_db_uri(DB_URI), deadline=budget)
    assert time.monotonic() - started < 0.5
    assert 0 < captured["connect_timeout"] <= 0.25
    assert 0 < captured["read_timeout"] <= 0.25
    assert captured["write_timeout"] == captured["read_timeout"]

    calls: list[dict] = []
    fake.connect = lambda **kwargs: calls.append(kwargs)

    def _over_budget_resolve(host, port, deadline, **_kw):
        time.sleep(0.6)
        return ["192.0.2.44"]

    monkeypatch.setattr(dbconn, "resolve_host_bounded", _over_budget_resolve)
    expired = Deadline(0.3)
    with pytest.raises(DeadlineExceeded):
        dbconn.connect(parse_db_uri(DB_URI), deadline=expired)
    assert calls == []


def test_R25_greeting_read_does_not_consume_the_next_address_budget(
        monkeypatch):
    """R25-P2: ``read_timeout`` used the WHOLE remaining budget while
    ``connect_timeout`` was split per address.  A server that accepts TCP
    and never sends the greeting held the run, so the second resolved
    address was never dialed.  The handshake share is per-attempt and 2003
    still advances."""
    import sys
    import time
    import types

    from wpt.deadline import Deadline

    calls: list[dict] = []

    class _Raw:
        def close(self):
            pass

    def _connect(**kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            raise OSError(2003, "Can't connect (no greeting)")
        return _Raw()

    fake = types.ModuleType("pymysql")
    fake.__version__ = "test"
    fake.connect = _connect
    monkeypatch.setitem(sys.modules, "pymysql", fake)
    monkeypatch.setattr(
        dbconn, "resolve_host_bounded",
        lambda host, port, deadline, **_kw: ["192.0.2.1", "192.0.2.2"])

    started = time.monotonic()
    dbconn.connect(parse_db_uri(DB_URI), deadline=Deadline(0.6))
    assert time.monotonic() - started < 0.6
    assert len(calls) == 2
    first, second = calls
    assert first["host"] == "192.0.2.1"
    assert second["host"] == "192.0.2.2"
    # Both handshake bounds are a per-attempt share (~0.3 s), not the whole
    # remaining 0.6 s.
    assert first["read_timeout"] <= 0.31
    assert first["read_timeout"] == first["connect_timeout"]


def test_R25_dns_is_bounded_even_without_a_run_deadline(monkeypatch):
    """R25-P2: with ``--deadline 0`` the resolver call was skipped and libc
    getaddrinfo ran unbounded (measured 21.5 s against a 10 s connect
    bound).  The one resolver owner is always called with a finite bound."""
    import sys
    import time
    import types

    seen: list[float] = []

    class _Raw:
        def close(self):
            pass

    fake = types.ModuleType("pymysql")
    fake.__version__ = "test"
    fake.connect = lambda **_kwargs: _Raw()
    monkeypatch.setitem(sys.modules, "pymysql", fake)

    def _resolve(host, port, deadline, **_kw):
        seen.append(deadline - time.monotonic())
        return ["192.0.2.9"]

    monkeypatch.setattr(dbconn, "resolve_host_bounded", _resolve)
    dbconn.connect(parse_db_uri(DB_URI))
    assert len(seen) == 1
    assert 0 < seen[0] <= dbconn.DbSettings().connect_timeout_s + 0.1


def test_R24_re_dump_temp_is_registered_before_creation(tmp_path,
                                                        monkeypatch):
    """R24-P2: the temp name was known only after ``mkstemp`` returned; a
    stop on that boundary left an unreferenced ``.part``.  The name is
    journaled first, so even a stop before creation leaves nothing."""
    import wpt.localmode.dbconn as dbconn
    from wpt.types import StopRequested

    out = tmp_path / "stopped.sql"
    real_open = dbconn.os.open

    def _stopping_open(path, *args, **kwargs):
        if str(path).endswith(".part"):
            raise StopRequested("stop after temp reservation")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(dbconn.os, "open", _stopping_open)
    with pytest.raises(StopRequested):
        dump_database(wp_dumpable(), out)
    assert not out.exists()
    assert not [path for path in tmp_path.iterdir()
                if path.name.endswith(".part")]
