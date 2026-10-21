"""wpt.localmode.analyzer tests — php_unserialize subset + analyze behavior.

Test -> behavior map (binding list from the W5b task):
  php_unserialize:
    test_unserialize_string_simple_and_empty .......... s tag roundtrip + empty
    test_unserialize_string_embedded_structural_chars . payload containing ; : { } "
    test_unserialize_string_multibyte_byte_length ..... declared length counts
                                                       UTF-8 BYTES (multibyte)
    test_unserialize_length_echo_violations ........... mismatched length => error
    test_unserialize_int_bool_double_types ............ i/b/d return types
    test_unserialize_double_grammar .................... exponent/INF/NAN + malformed
    test_unserialize_array_nested ...................... recursive a, 3+ deep, a:0:{}
    test_unserialize_array_insertion_order ............ int + string keys, order kept
    test_unserialize_truncated ........................ truncated => UnserializeError
    test_unserialize_trailing_garbage .................. extra bytes => UnserializeError
    test_unserialize_unsupported_tags ................. O:/N:/R:/C:/other => error
    test_unserialize_depth_guard ....................... nesting bomb => error, sane ok
    test_unserialize_non_str_input ..................... bytes/None/int => error
  analyze:
    test_analyze_full_happy_path ....................... wp_options+wp_posts, all fields,
                                                        posts per (type,status) incl ''
    test_analyze_locale_wplang_fact .................... [L17] the WPLANG option ->
                                                        SiteModel.locale (plain +
                                                        serialized; ''/absent/
                                                        NULL = None)
    test_analyze_non_wp_prefix ........................ sample_ prefix (no wp_ hardcoding)
    test_analyze_complete_insert_reordered_columns .... by-NAME mapping via insert_columns
    test_analyze_missing_options_table ................ empty model + passthrough + warning
    test_analyze_options_only_and_unusable_posts ...... no posts table / missing columns
    test_a_partial_dump_still_measures_the_site_facts
                                                       a dump with no postmeta is
                                                       a PARTIAL export: the
                                                       media half is UNKNOWN and
                                                       says so once, while every
                                                       site fact it really
                                                       contains stays measured
                                                       (degrading them would be
                                                       fail-open for clean-files)
    test_analyze_multiple_options_tables_is_unknown_not_first_wins
                                                       ambiguity is UNKNOWN, not
                                                       first-in-dump-order; one
                                                       warning naming both, and
                                                       the keep-set agrees
    test_analyze_bad_active_plugins .................... an unreadable option is
                                                        UNKNOWN (plugins None +
                                                        cause), not an empty site;
                                                        one warning, analyze survives
    test_active_set_separates_measured_empty_from_not_measured
                                                       THREE states, told apart
                                                       without inspecting a list:
                                                       measured entries, a measured
                                                       EMPTY set (a real answer) and
                                                       not-measured (None + cause)
    test_active_set_contested_identity_names_every_candidate
                                                       a contested options identity
                                                       (aioseo_options beside
                                                       wp_options) is unmeasured,
                                                       with the cause and EVERY
                                                       candidate table
    test_active_set_absent_options_table_is_unknown_with_no_candidates
                                                       no options table: the same
                                                       unmeasured answer, no
                                                       candidate to name
    test_analyze_autoload_threshold .................... DbSettings-driven; below excluded,
                                                       at/above included, 'no' excluded,
                                                       bytes cell, sorted desc, stable ties
    test_analyze_autoload_multibyte_measured_in_bytes . multibyte cell sized in BYTES
    test_analyze_missing_autoload_column ............... check skipped + one warning
    test_analyze_rewinds_real_file_object ............... seek(0) between passes
    test_analyze_no_cell_values_in_logs ................ cell contents never reach records
    test_analyze_admin_users_level_ten_rule ............ wp_users+wp_usermeta:
                                                       only user_level=10 is admin
                                                       (INNER JOIN drop, capabilities
                                                       never grant admin),
                                                       registered passthrough
    test_analyze_admin_users_custom_prefix_null_sorted . suffix meta_key rule
                                                       (mysite_user_level),
                                                       NULL registered -> None,
                                                       sorted by login; logins
                                                       never logged
    test_analyze_admin_users_missing_tables_unknown ... users/usermeta absent,
                                                       wrong columns, or no
                                                       prefix -> None (unknown,
                                                       never [])
    test_analyze_admin_users_measured_empty ............ tables present, no
                                                       level-10 join (orphan
                                                       meta dropped) -> []

All fixtures are deterministic inline bytes through io.BytesIO on the REAL
wpt.localmode.sql_dump parser — no fakes, no network, no sleeps.
"""

import io
import logging
import math

import pytest

from wpt.localmode.analyzer import (
    SiteModel,
    UnserializeError,
    analyze,
    php_unserialize,
)
from wpt.settings import DbSettings

SITEURL = "https://sample.example.test"


def _ser_str(value: str) -> str:
    """PHP-serialize a string; the declared length is the UTF-8 byte count."""
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
    if isinstance(value, bytes):
        return "0x" + value.hex()
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _create(table: str, columns: list[str]) -> bytes:
    cols = ", ".join("`%s` text" % c for c in columns)
    return ("CREATE TABLE `%s` (%s);\n" % (table, cols)).encode()


def _insert(table: str, rows: list, columns: list[str] | None = None) -> bytes:
    tuples = ",".join(
        "(" + ",".join(_cell_sql(c) for c in row) + ")" for row in rows)
    if columns is None:
        head = "INSERT INTO `%s` VALUES " % table
    else:
        head = "INSERT INTO `%s` (%s) VALUES " % (
            table, ",".join("`%s`" % c for c in columns))
    return (head + tuples + ";\n").encode()


def _options_table(name: str, *, autoload: bool = True) -> bytes:
    cols = ["option_id", "option_name", "option_value"]
    if autoload:
        cols.append("autoload")
    return _create(name, cols)


def _posts_table(name: str) -> bytes:
    return _create(name, ["ID", "post_type", "post_status", "post_content"])


def _postmeta_table(name: str) -> bytes:
    """The postmeta CREATE a real dump carries, with no rows.

    Present (and column-complete) because the table-identity owner treats a
    dump that does not PROVE it as a PARTIAL export rather than a site
    without attachments — see ``wpt.media_refs``.  Its absence is a fact
    about the media measurement, not about any site fact below.
    """
    return _create(name, ["meta_id", "post_id", "meta_key", "meta_value"])


def _users_table(name: str) -> bytes:
    # ID is the join key (um.user_id = u.ID in the bridge's users query)
    return _create(name, ["ID", "user_login", "user_registered"])


def _usermeta_table(name: str) -> bytes:
    return _create(name, ["umeta_id", "user_id", "meta_key", "meta_value"])


def _model(dump: bytes, settings: DbSettings | None = None) -> SiteModel:
    return analyze(io.BytesIO(dump), settings or DbSettings())


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def wpt_records():
    """Capture every wpt.* log record.

    The wpt parent logger has propagate=False (see wpt.log), so pytest's
    caplog never sees wpt records — this fixture attaches a handler directly.
    """
    parent = logging.getLogger("wpt")
    handler = _Capture()
    old_level = parent.level
    parent.addHandler(handler)
    parent.setLevel(logging.DEBUG)
    try:
        yield handler.records
    finally:
        parent.setLevel(old_level)
        parent.removeHandler(handler)


# ------------------------------------------------------------ php_unserialize


def test_unserialize_string_simple_and_empty():
    assert php_unserialize('s:5:"hello";') == "hello"
    assert php_unserialize('s:1:"a";') == "a"
    assert php_unserialize('s:0:"";') == ""


def test_unserialize_string_embedded_structural_chars():
    payload = 'a";b:{c}'
    ser = 's:%d:"%s";' % (len(payload.encode()), payload)
    assert ser == 's:8:"a";b:{c}";'
    assert php_unserialize(ser) == payload
    tricky = 'wor;ld:}{"'
    ser2 = 's:%d:"%s";' % (len(tricky.encode()), tricky)
    assert ser2 == 's:10:"wor;ld:}{"";'  # payload's final " doubles with the close
    assert php_unserialize(ser2) == tricky


def test_unserialize_string_multibyte_byte_length():
    value = "héllo"
    ser = 's:%d:"%s";' % (len(value.encode("utf-8")), value)
    assert ser == 's:6:"héllo";'
    assert php_unserialize(ser) == "héllo"
    assert php_unserialize('s:6:"a\U0001F389b";') == "a\U0001F389b"
    with pytest.raises(UnserializeError):
        php_unserialize('s:5:"héllo";')  # 5 chars, but 6 bytes
    with pytest.raises(UnserializeError):
        php_unserialize('s:7:"héllo";')


def test_unserialize_length_echo_violations():
    for bad in ('s:5:"ab";', 's:2:"abc";', 's:3:"ab";', 's:11:"abc";',
                's:2:"ab"', 's::"";', 's:2:x"ab";'):
        with pytest.raises(UnserializeError):
            php_unserialize(bad)


def test_unserialize_int_bool_double_types():
    assert php_unserialize("i:42;") == 42
    assert php_unserialize("i:-7;") == -7
    assert php_unserialize("i:0;") == 0
    assert type(php_unserialize("i:42;")) is int
    assert php_unserialize("b:1;") is True
    assert php_unserialize("b:0;") is False
    assert php_unserialize("d:1.5;") == 1.5
    assert php_unserialize("d:-0.25;") == -0.25
    out = php_unserialize("d:2;")
    assert type(out) is float and out == 2.0


def test_unserialize_double_grammar():
    assert php_unserialize("d:1.0E+15;") == 1.0e15
    assert php_unserialize("d:1e-5;") == 1e-5
    assert math.isinf(php_unserialize("d:INF;"))
    assert math.isinf(php_unserialize("d:-INF;"))
    assert math.isnan(php_unserialize("d:NAN;"))
    for bad in ("d:1.2.3;", "d:;", "d:abc;", "d:1.5x;", "b:2;", "b:01;",
                "i:;", "i:+;", "b:;"):
        with pytest.raises(UnserializeError):
            php_unserialize(bad)


def test_unserialize_array_nested():
    assert php_unserialize("a:0:{}") == {}
    assert php_unserialize('a:2:{s:3:"foo";s:3:"bar";i:0;s:3:"baz";}') == {
        "foo": "bar", 0: "baz"}
    deep = 'a:1:{i:0;a:1:{s:1:"x";a:2:{i:5;s:1:"y";i:6;a:1:{i:7;b:1;}}}}'
    assert php_unserialize(deep) == {0: {"x": {5: "y", 6: {7: True}}}}


def test_unserialize_array_insertion_order():
    out = php_unserialize('a:3:{i:2;s:1:"a";i:1;s:1:"b";i:0;s:1:"c";}')
    assert list(out.keys()) == [2, 1, 0]
    mixed = php_unserialize('a:3:{s:3:"one";i:1;i:0;i:2;s:3:"two";i:3;}')
    assert list(mixed.keys()) == ["one", 0, "two"]
    assert mixed == {"one": 1, 0: 2, "two": 3}


def test_unserialize_truncated():
    for bad in ("", 's:11:"abc', "s:", "s:3:", 's:3:"a', 'a:2:{i:0;s:1:"a";',
                "a:", "a:2:{", "a:2:{i:0;}", "i:", "i:5", "b:1", "b:",
                "d:1.5", "a:1:{i:0;"):
        with pytest.raises(UnserializeError):
            php_unserialize(bad)


def test_unserialize_trailing_garbage():
    for bad in ("i:5;x", "i:5;i:6;", 's:1:"a";;', 's:1:"a"; ', "b:1;;",
                "a:1:{i:0;i:1;};", "i: 5;", 's:1 : "a";'):
        with pytest.raises(UnserializeError):
            php_unserialize(bad)


def test_unserialize_unsupported_tags():
    for bad in ('O:8:"stdClass":0:{}', "N;", "R:1;", 'C:16:"SomeClass":2:{ab}',
                "x:1;", "E:1;", 'i:5;O:1:"x";'):
        with pytest.raises(UnserializeError):
            php_unserialize(bad)


def test_unserialize_depth_guard():
    def nested(depth):
        out = "i:1;"
        for _ in range(depth):
            out = "a:1:{i:0;" + out + "}"
        return out

    value = php_unserialize(nested(10))
    for _ in range(10):
        assert isinstance(value, dict) and list(value) == [0]
        value = value[0]
    assert value == 1
    with pytest.raises(UnserializeError):
        php_unserialize(nested(100))


def test_unserialize_non_str_input():
    for bad in (b"i:5;", None, 5):
        with pytest.raises(UnserializeError):
            php_unserialize(bad)


# -------------------------------------------------------------------- analyze


def test_analyze_full_happy_path(wpt_records):
    plugins = ["akismet/akismet.php", 'we;ird "stuff"/pl\'ug.php']
    dump = (b"/*!40101 SET NAMES utf8mb4 */;\n"
            + _options_table("wp_options")
            + _posts_table("wp_posts")
            + _postmeta_table("wp_postmeta")
            + _insert("wp_options", [
                (1, "siteurl", _ser_str(SITEURL), "yes"),
                (2, "home", _ser_str(SITEURL), "yes"),
                (3, "template", _ser_str("sample-theme"), "yes"),
                (4, "stylesheet", _ser_str("sample-theme-child"), "yes"),
                (5, "blog_public", _ser_int(1), "yes"),
                (6, "active_plugins", _ser_list(plugins), "yes"),
                (7, "some_transient", _ser_str("x" * 40), "no"),
            ])
            + _insert("wp_posts", [
                (1, "post", "publish"),
                (2, "post", "draft"),
                (3, "page", "publish"),
                (4, "attachment", "inherit"),
                (5, "post", ""),
                (6, "post", None),
            ]))
    model = _model(dump)
    assert isinstance(model, SiteModel)
    assert model.siteurl == SITEURL
    assert model.home == SITEURL
    assert model.template == "sample-theme"
    assert model.stylesheet == "sample-theme-child"   # active (child) theme
    assert model.blog_public == 1
    assert model.active_plugins == plugins
    assert model.big_autoload_options == []
    assert model.posts == {
        ("post", "publish"): 1, ("post", "draft"): 1, ("page", "publish"): 1,
        ("attachment", "inherit"): 1, ("post", ""): 2,
    }
    assert model.table_prefix == "wp_"
    assert model.charset == "utf8mb4"
    assert model.admin_users is None  # no users tables in the dump: unknown
    assert model.locale is None  # no WPLANG row in the fixture: unknown
    assert set(model.tables) == {"wp_options", "wp_posts", "wp_postmeta"}
    assert model.tables["wp_options"].row_count == 7
    assert model.tables["wp_posts"].row_count == 6
    assert not [r for r in wpt_records if r.levelno >= logging.WARNING]


def test_analyze_locale_wplang_fact():
    """[L17] SiteModel.locale — the WPLANG option: plain (real dumps
    store scalars plain) or PHP-serialized both read; '' (the modern
    WordPress en_US default), an absent option, or an unreadable
    non-string value read as None (unknown — the integrity check's
    resolver floors at en_US), never a guess.  The fact is the SITE
    locale, not the core BUILD locale (an en_US build plus a fr_CA
    language pack also stores fr_CA) — the build/anything distinction
    is the consumer's semantics; the model stays data."""
    plain = (_options_table("wp_options")
            + _insert("wp_options", [
                (1, "siteurl", _ser_str(SITEURL), "yes"),
                (2, "WPLANG", "fr_CA", "yes"),
                (3, "template", _ser_str("sample-theme"), "yes"),
            ]))
    assert _model(plain).locale == "fr_CA"

    serialized = (_options_table("wp_options")
                  + _insert("wp_options", [
                      (1, "siteurl", _ser_str(SITEURL), "yes"),
                      (2, "WPLANG", _ser_str("fr_CA"), "yes"),
                  ]))
    assert _model(serialized).locale == "fr_CA"

    # '' — the modern en_US default — is unknown, not "en_US"
    empty = (_options_table("wp_options")
             + _insert("wp_options", [
                 (1, "siteurl", _ser_str(SITEURL), "yes"),
                 (2, "WPLANG", "", "yes"),
             ]))
    assert _model(empty).locale is None

    # option absent: unknown
    absent = (_options_table("wp_options")
              + _insert("wp_options", [
                  (1, "siteurl", _ser_str(SITEURL), "yes"),
              ]))
    assert _model(absent).locale is None

    # a non-string cell (NULL) is unreadable, never a guess
    unreadable = (_options_table("wp_options")
                  + _insert("wp_options", [
                      (1, "siteurl", _ser_str(SITEURL), "yes"),
                      (2, "WPLANG", None, "yes"),
                  ]))
    assert _model(unreadable).locale is None


def test_analyze_non_wp_prefix():
    dump = (_options_table("sample_options")
            + _posts_table("sample_posts")
            + _insert("sample_options", [
                (1, "siteurl", _ser_str("https://sample.example.test"), "yes"),
                (2, "blog_public", _ser_int(0), "yes"),
            ])
            + _insert("sample_posts", [(1, "page", "publish")]))
    model = _model(dump)
    assert model.table_prefix == "sample_"
    assert model.siteurl == "https://sample.example.test"
    assert model.blog_public == 0
    assert model.posts == {("page", "publish"): 1}


def test_analyze_complete_insert_reordered_columns():
    dump = (_options_table("wp_options")
            + _posts_table("wp_posts")
            + _insert("wp_options",
                      [("yes", _ser_str(SITEURL), "siteurl", 1),
                       ("yes", _ser_int(1), "blog_public", 2),
                       ("yes", _ser_str("twentytwenty"), "template", 3)],
                      columns=["autoload", "option_value", "option_name",
                               "option_id"])
            + _insert("wp_posts",
                      [("publish", "post", 1), ("draft", "post", 2)],
                      columns=["post_status", "post_type", "ID"]))
    model = _model(dump)
    assert model.siteurl == SITEURL
    assert model.blog_public == 1
    assert model.template == "twentytwenty"
    assert model.home is None
    assert model.posts == {("post", "publish"): 1, ("post", "draft"): 1}


def test_analyze_missing_options_table(wpt_records):
    dump = (_posts_table("wp_posts")
            + _insert("wp_posts", [(1, "post", "publish")]))
    for model in (_model(dump), _model(b"")):
        assert model.siteurl is None
        assert model.home is None
        assert model.template is None
        assert model.blog_public is None
        assert model.locale is None  # no options table: unknown
        assert model.active_plugins == []      # the reporting view
        assert model.active_set.plugins is None  # ... over an UNMEASURED set
        assert model.big_autoload_options == []
        assert model.posts == {}
        assert model.admin_users is None  # no prefix: users undiscoverable
        assert model.table_prefix is None
        assert model.charset is None
    model = _model(dump)
    assert set(model.tables) == {"wp_posts"}
    assert model.tables["wp_posts"].row_count == 1
    warnings = [r for r in wpt_records if r.levelno == logging.WARNING]
    assert len(warnings) == 3  # one per analyze() call (dump, b"", dump again)
    assert all("options table" in r.getMessage() for r in warnings)


def test_analyze_options_only_and_unusable_posts():
    dump = (_options_table("wp_options")
            + _create("wp_posts", ["ID", "post_title"])
            + _insert("wp_options", [
                (1, "siteurl", _ser_str("https://x.example.test"), "yes")])
            + _insert("wp_posts", [(1, "hello")]))
    model = _model(dump)
    assert model.table_prefix == "wp_"
    assert model.siteurl == "https://x.example.test"
    assert model.posts == {}  # posts table lacks post_type/post_status


def test_a_partial_dump_still_measures_the_site_facts(wpt_records):
    """WHERE THE PARTIALITY REFUSAL STOPS, and why it stops there.

    A dump with no postmeta is a per-table export: it cannot answer the
    DATABASE MEDIA question, and :mod:`wpt.media_refs` refuses that
    measurement outright.  It still PROVES its options table, and the
    options table is what carries the prefix every other table is located
    by — so the site facts below are measured facts and stay measured.

    Degrading them too would be collateral with a FAIL-OPEN edge: an
    unreadable ``active_plugins`` list makes every plugin directory look
    unused to ``clean-files``, which plans deletions.  So the analyzer's
    degradation stays exactly where the prefix becomes unknowable — an
    absent or CONTESTED options identity.
    """
    from wpt.media_refs import db_refs_from_dump

    dump = (_options_table("wp_options")
            + _posts_table("wp_posts")
            + _insert("wp_options", [
                (1, "siteurl", _ser_str(SITEURL), "yes"),
                (2, "template", _ser_str("sample-theme"), "yes"),
                (3, "active_plugins", _ser_list(["akismet/akismet.php"]), "yes"),
            ])
            + _insert("wp_posts", [(1, "post", "publish")]))
    model = _model(dump)
    assert model.table_prefix == "wp_"
    assert model.siteurl == SITEURL
    assert model.template == "sample-theme"
    assert model.active_plugins == ["akismet/akismet.php"]
    assert model.posts == {("post", "publish"): 1}
    # the media half of the same dump is UNKNOWN, and says so once
    assert db_refs_from_dump(io.BytesIO(dump)) is None
    warnings = [r.getMessage() for r in wpt_records if r.levelno == logging.WARNING]
    assert sum("postmeta" in message for message in warnings) == 1
    assert not any("options table" in message for message in warnings)


def test_analyze_multiple_options_tables_is_unknown_not_first_wins(wpt_records):
    """AMBIGUITY IS UNKNOWN, and the two halves of one run agree.

    Two tables prove the options role.  This module used to read the FIRST
    in dump order and the media measurement the first in ``sorted()`` order
    — on a dump carrying ``aioseo_options`` (a real AIOSEO 4.x table) they
    chose DIFFERENT tables inside one run, and the keep-set measured 0
    database references where the control measured the full set: a positive "this
    database references no uploads file" instead of the UNKNOWN every
    consumer refuses closed on.  Both halves now resolve nothing.
    """
    dump = (_options_table("wp_options")
            + _options_table("wp_beta_options")
            + _posts_table("wp_posts")
            + _insert("wp_options",
                      [(1, "siteurl", _ser_str("https://first.example.test"), "yes")])
            + _insert("wp_beta_options",
                      [(1, "siteurl", _ser_str("https://second.example.test"), "yes")])
            + _insert("wp_posts", [(1, "post", "publish")]))
    model = _model(dump)
    # neither table is read, and no site fact is derived from a guess
    assert model.siteurl is None and model.home is None
    assert model.template is None and model.blog_public is None
    # the active set is UNMEASURED, and says which tables made it so
    assert model.active_set.plugins is None
    assert model.active_set.candidates == ("wp_beta_options", "wp_options")
    assert model.posts == {}          # no prefix -> the posts table is unknown
    assert model.admin_users is None
    assert model.table_prefix is None
    # one warning naming BOTH candidates, from the owner
    warnings = [r.getMessage() for r in wpt_records if r.levelno == logging.WARNING]
    assert len(warnings) == 2, warnings
    assert any("wp_beta_options" in message and "wp_options" in message
               for message in warnings)
    # ... and the measurement agrees, rather than reading one of them
    from wpt.media_refs import db_refs_from_dump
    assert db_refs_from_dump(io.BytesIO(dump)) is None


def test_analyze_bad_active_plugins(wpt_records):
    """An ``active_plugins`` value that is not a readable serialized list
    is UNKNOWN, not an empty site: the model's own ``plugins`` is None
    with the cause, and only the reporting view is ``[]``."""
    dump = (_options_table("wp_options")
            + _postmeta_table("wp_postmeta")
            + _posts_table("wp_posts")
            + _insert("wp_options", [
                (1, "siteurl", _ser_str(SITEURL), "yes"),
                (2, "active_plugins",
                 'a:2:{i:0;s:9:"broken/plugin.php";i:1;s:5:"trunc', "yes"),
            ]))
    model = _model(dump)
    assert model.active_set.plugins is None
    assert "active_plugins" in model.active_set.reason
    assert model.active_set.theme_measured  # the rest of the table WAS read
    assert model.active_plugins == []       # the reporting view, still safe
    assert model.siteurl == SITEURL
    warnings = [r.getMessage() for r in wpt_records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "active_plugins" in warnings[0]
    assert "unknown" in warnings[0]


def test_active_set_separates_measured_empty_from_not_measured():
    """The ONE question a destructive consumer asks — "is this unit in
    use?" — has THREE answers, and the model must be able to tell them
    apart without a consumer inspecting an empty list.

    * measured, with entries;
    * measured EMPTY (``a:0:{}``) — a site running no plugins, a REAL
      answer, and ``reason`` stays None;
    * NOT measured — ``plugins`` is None plus the cause, which is what
      tells ``clean-files`` to refuse the unit deletion instead of
      planning it.
    """
    measured = _model(
        _options_table("wp_options")
        + _insert("wp_options", [
            (1, "active_plugins", _ser_list(["akismet/akismet.php"]), "yes"),
        ]))
    assert measured.active_set.plugins == ["akismet/akismet.php"]
    assert measured.active_set.reason is None
    assert measured.active_set.theme_measured

    empty = _model(
        _options_table("wp_options")
        + _insert("wp_options", [
            (1, "active_plugins", _ser_list([]), "yes"),
            (2, "template", _ser_str("twentytwenty"), "yes"),
        ]))
    assert empty.active_set.plugins == []
    assert empty.active_set.reason is None      # a real answer, not a gap
    assert empty.active_set.template == "twentytwenty"
    assert empty.active_set.theme_measured
    # ... and it is NOT the same value as the not-measured case:
    assert empty.active_set.plugins is not None


def test_active_set_contested_identity_names_every_candidate(wpt_records):
    """A CONTESTED options identity (AIOSEO 4.x really creates
    ``aioseo_options`` beside ``wp_options``) leaves the active set
    UNMEASURED, and the model carries the cause plus EVERY table that
    proved the role — so a consumer can refuse and say what it could not
    read instead of deleting on an empty set."""
    dump = (_options_table("wp_options")
            + _options_table("aioseo_options")
            + _insert("wp_options", [
                (1, "active_plugins", _ser_list(["akismet/akismet.php"]),
                 "yes"),
                (2, "template", _ser_str("twentytwenty"), "yes"),
            ]))
    model = _model(dump)
    active = model.active_set
    assert active.plugins is None
    assert not active.theme_measured
    assert "contested" in active.reason
    assert active.candidates == ("aioseo_options", "wp_options")
    # the reporting view stays inert for the audit consumers
    assert model.active_plugins == [] and model.template is None
    # the owner named the candidates once; the analyzer adds its own line
    # about the missing fact and never a second identity warning
    warnings = [r.getMessage() for r in wpt_records
                if r.levelno == logging.WARNING]
    assert len(warnings) == 2, warnings


def test_active_set_absent_options_table_is_unknown_with_no_candidates():
    """No options table at all: the same UNMEASURED answer, with the
    cause that names no candidate because there is none."""
    model = _model(_posts_table("wp_posts")
                   + _insert("wp_posts", [(1, "post", "publish")]))
    active = model.active_set
    assert active.plugins is None
    assert not active.theme_measured
    assert "no table" in active.reason
    assert active.candidates == ()


def test_analyze_autoload_threshold():
    settings = DbSettings(autoload_big_bytes=100)
    dump = (_options_table("wp_options")
            + _insert("wp_options", [
                (1, "siteurl", _ser_str(SITEURL), "yes"),
                (2, "big_cache_option", _ser_str("y" * 120), "yes"),
                (3, "small_option", _ser_str("y" * 20), "yes"),
                (4, "exact_threshold", _ser_str("z" * 92), "yes"),
                (5, "another_exact", _ser_str("w" * 92), "yes"),
                (6, "huge_but_not_autoloaded", _ser_str("q" * 4000), "no"),
                (7, "binary_blob_option", b"\xab" * 150, "yes"),
                (8, "null_value_option", None, "yes"),
            ]))
    model = _model(dump, settings)
    assert model.siteurl == SITEURL
    assert model.big_autoload_options == [
        ("binary_blob_option", 150),
        ("big_cache_option", 129),
        ("another_exact", 100),
        ("exact_threshold", 100),
    ]
    assert ("small_option", 28) not in model.big_autoload_options
    assert ("huge_but_not_autoloaded", 4010) not in model.big_autoload_options
    assert ("null_value_option", 0) not in model.big_autoload_options


def test_analyze_autoload_wp66_value_set():
    # WP 6.6+ autoload values: 'on'/'auto-on'/'auto' autoload, 'off'/'auto-off'
    # do not; the set is mirrored in the bridge db_audit SQL (contract test
    # in tests/test_bridge_php.py pins the mirror).
    settings = DbSettings(autoload_big_bytes=100)
    dump = (_options_table("wp_options")
            + _insert("wp_options", [
                (1, "legacy_yes", _ser_str("a" * 120), "yes"),
                (2, "wp66_on", _ser_str("b" * 120), "on"),
                (3, "wp66_auto_on", _ser_str("c" * 120), "auto-on"),
                (4, "wp66_auto", _ser_str("d" * 120), "auto"),
                (5, "wp66_off", _ser_str("e" * 120), "off"),
                (6, "wp66_auto_off", _ser_str("f" * 120), "auto-off"),
            ]))
    model = _model(dump, settings)
    # all four values serialize to 129 bytes; tiebreak is name ascending
    assert model.big_autoload_options == [
        ("legacy_yes", 129),
        ("wp66_auto", 129),
        ("wp66_auto_on", 129),
        ("wp66_on", 129),
    ]
    names = {n for n, _ in model.big_autoload_options}
    assert "wp66_off" not in names and "wp66_auto_off" not in names


def test_analyze_autoload_multibyte_measured_in_bytes():
    value = _ser_str("é" * 60)
    assert len(value) == 69          # 69 characters...
    assert len(value.encode("utf-8")) == 129   # ...but 129 UTF-8 bytes
    dump = (_options_table("wp_options")
            + _insert("wp_options", [
                (1, "multibyte_option", value, "yes"),
                (2, "ascii_option", "a" * 69, "yes"),
            ]))
    model = _model(dump, DbSettings(autoload_big_bytes=100))
    assert model.big_autoload_options == [("multibyte_option", 129)]


def test_analyze_missing_autoload_column(wpt_records):
    dump = (_options_table("wp_options", autoload=False)
            + _postmeta_table("wp_postmeta")
            + _posts_table("wp_posts")
            + _insert("wp_options", [
                (1, "siteurl", _ser_str(SITEURL)),
                (2, "huge_option", _ser_str("q" * 5000)),
            ]))
    model = _model(dump)
    assert model.big_autoload_options == []  # nothing treated as autoloaded
    assert model.siteurl == SITEURL
    warnings = [r.getMessage() for r in wpt_records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "autoload" in warnings[0]


def test_analyze_rewinds_real_file_object(tmp_path):
    dump = (_options_table("wp_options")
            + _posts_table("wp_posts")
            + _insert("wp_options", [
                (1, "siteurl", _ser_str(SITEURL), "yes"),
                (2, "blog_public", _ser_int(0), "yes"),
            ])
            + _insert("wp_posts", [(1, "post", "publish")]))
    expected = _model(dump)
    path = tmp_path / "site.sql"
    path.write_bytes(dump)
    with open(path, "rb") as fh:
        fh.read(10)  # partially consumed: analyze must rewind before each pass
        model = analyze(fh, DbSettings())
    assert model == expected


def test_analyze_no_cell_values_in_logs(wpt_records):
    marker = "S3CR3T-LEAKMARK-9999"
    dump = (_options_table("wp_options")
            + _posts_table("wp_posts")
            + _insert("wp_options", [
                (1, "siteurl", _ser_str("https://site.example.test"), "yes"),
                (2, "updraft_credentials", _ser_str(marker), "yes"),
                (3, "active_plugins", "not-serialized-at-all", "yes"),
            ])
            + _insert("wp_posts", [(1, "post", "publish")]))
    model = _model(dump)
    assert model.siteurl == "https://site.example.test"
    assert model.active_plugins == []  # raw value rejected, never guessed
    assert not [r for r in wpt_records if r.levelno >= logging.ERROR]
    for record in wpt_records:  # option NAMES may appear; cell VALUES never
        assert marker not in record.getMessage()
        assert "site.example.test" not in record.getMessage()


def test_scalar_options_accept_plain_text_real_dump_shape():
    # REAL WordPress stores scalar options PLAIN (maybe_serialize keeps
    # scalars as-is); only arrays/objects are PHP-serialized. Proven by the
    # corpus dumps: (1, 'siteurl', 'https://example.test', 'yes').
    dump = (_options_table("wp_options")
            + _insert("wp_options", [
                (1, "siteurl", "https://example.test", "yes"),
                (2, "home", "https://example.test", "yes"),
                (3, "template", "Avada", "yes"),
                (4, "stylesheet", "avada-child", "yes"),
                (5, "blog_public", "1", "yes"),
                (6, "active_plugins", _ser_list(["akismet/akismet.php"]), "yes"),
            ]))
    model = _model(dump)
    assert model.siteurl == "https://example.test"
    assert model.home == "https://example.test"
    assert model.template == "Avada"
    assert model.stylesheet == "avada-child"
    assert model.blog_public == 1
    assert model.active_plugins == ["akismet/akismet.php"]


def test_scalar_options_still_accept_serialized_shape():
    # Some migration tools re-serialize scalars; both shapes must work.
    dump = (_options_table("wp_options")
            + _insert("wp_options", [
                (1, "siteurl", _ser_str("https://example.test"), "yes"),
                (3, "template", _ser_str("Avada"), "yes"),
                (5, "blog_public", _ser_int(0), "yes"),
            ]))
    model = _model(dump)
    assert model.siteurl == "https://example.test"
    assert model.template == "Avada"
    assert model.blog_public == 0


def test_scalar_options_garbage_stays_none():
    dump = (_options_table("wp_options")
            + _insert("wp_options", [
                (1, "siteurl", "s:9:broken", "yes"),      # tagged, unreadable
                (3, "template", "", "yes"),                # empty plain
                (5, "blog_public", "not-a-number", "yes"),
            ]))
    model = _model(dump)
    assert model.siteurl is None
    assert model.template == ""            # empty plain string IS a value
    assert model.blog_public is None


def test_permalink_structure_rides_the_scalar_option_seam():
    # The harden action's pretty-permalink gate reads this field: None is
    # "absent/unreadable" (WordPress's own plain-?p=N default), "" is a REAL
    # measured empty (plain permalinks), a non-empty structure is pretty.
    # Plain first (the real dump shape), serialized accepted — exactly like
    # siteurl.
    dump = (_options_table("wp_options")
            + _insert("wp_options", [
                (1, "siteurl", "https://example.test", "yes"),
                (2, "permalink_structure",
                 "/%year%/%monthnum%/%day%/%postname%/", "yes"),
            ]))
    assert _model(dump).permalink_structure == \
        "/%year%/%monthnum%/%day%/%postname%/"

    dump = (_options_table("wp_options")
            + _insert("wp_options", [
                (1, "permalink_structure",
                 _ser_str("/blog/%postname%/"), "yes"),
            ]))
    assert _model(dump).permalink_structure == "/blog/%postname%/"

    dump = (_options_table("wp_options")
            + _insert("wp_options", [
                (1, "permalink_structure", "", "yes"),
            ]))
    assert _model(dump).permalink_structure == ""

    dump = (_options_table("wp_options")
            + _insert("wp_options", [
                (1, "siteurl", "https://example.test", "yes"),
            ]))
    assert _model(dump).permalink_structure is None


# ------------------------------------------------------------- admin users


def test_analyze_admin_users_level_ten_rule():
    # The bridge's db_audit rule: admin = a usermeta row with meta_key
    # <prefix>user_level and meta_value '10' for the user's ID.  Level 1
    # is not admin, a user with NO user_level row is not admin (INNER
    # JOIN), and capabilities rows never grant admin.
    dump = (_options_table("wp_options")
            + _users_table("wp_users")
            + _usermeta_table("wp_usermeta")
            + _insert("wp_options", [(1, "siteurl", _ser_str(SITEURL), "yes")])
            + _insert("wp_users", [
                (3, "admin2", "2021-08-01 12:00:00"),
                (1, "admin", "2019-05-14 09:30:00"),
                (2, "editor", "2020-01-02 03:04:05"),
            ])
            + _insert("wp_usermeta", [
                (10, 1, "wp_user_level", "10"),
                (11, 2, "wp_user_level", "1"),
                (12, 2, "wp_capabilities", 'a:1:{s:13:"administrator";b:1;}'),
                (13, 3, "wp_something_else", "10"),
            ]))
    model = _model(dump)
    assert model.admin_users == [
        {"login": "admin", "registered": "2019-05-14 09:30:00", "admin": True},
    ]


def test_analyze_admin_users_custom_prefix_null_registered_sorted(wpt_records):
    # The meta_key suffix rule: a custom key prefix ("mysite_user_level")
    # still matches — a usermeta prefix the options table did not reveal
    # must not hide admins.  NULL user_registered -> None; output sorted
    # by login.
    dump = (_options_table("wp_options")
            + _users_table("wp_users")
            + _usermeta_table("wp_usermeta")
            + _insert("wp_options", [(1, "siteurl", _ser_str(SITEURL), "yes")])
            + _insert("wp_users", [
                (2, "root", None),                      # NULL -> None
                (1, "boss", "2018-03-04 05:06:07"),
            ])
            + _insert("wp_usermeta", [
                (10, 1, "mysite_user_level", "10"),
                (11, 2, "mysite_user_level", "10"),
            ]))
    model = _model(dump)
    assert model.admin_users == [
        {"login": "boss", "registered": "2018-03-04 05:06:07", "admin": True},
        {"login": "root", "registered": None, "admin": True},
    ]
    for record in wpt_records:  # logins are user data — never logged
        assert "boss" not in record.getMessage()
        assert "root" not in record.getMessage()


def test_analyze_admin_users_missing_tables_unknown():
    options = (_options_table("wp_options")
               + _insert("wp_options", [(1, "siteurl", _ser_str(SITEURL), "yes")]))
    users = _users_table("wp_users") + _insert(
        "wp_users", [(1, "admin", "2019-05-14 09:30:00")])
    levels = _usermeta_table("wp_usermeta") + _insert(
        "wp_usermeta", [(10, 1, "wp_user_level", "10")])
    # usermeta absent: the admin query cannot run -> unknown, never []
    assert _model(options + users).admin_users is None
    # users absent: logins are unknowable -> unknown
    assert _model(options + levels).admin_users is None
    # no options table: no prefix, no users discovery -> unknown
    assert _model(users + levels).admin_users is None
    # usermeta with wrong columns: unmeasurable -> unknown
    bad_meta = _create("wp_usermeta", ["umeta_id", "user_id", "meta_key"])
    assert _model(options + users + bad_meta).admin_users is None
    # users with wrong columns: unmeasurable -> unknown
    bad_users = _create("wp_users", ["ID", "user_login"])
    assert _model(options + bad_users + levels).admin_users is None


def test_analyze_admin_users_measured_empty():
    # Both tables present and parsed, no level-10 join — a REAL measured
    # empty (mirror of the bridge's present-but-empty []); orphan
    # usermeta for a nonexistent user drops like the INNER JOIN.
    dump = (_options_table("wp_options")
            + _users_table("wp_users")
            + _usermeta_table("wp_usermeta")
            + _insert("wp_options", [(1, "siteurl", _ser_str(SITEURL), "yes")])
            + _insert("wp_users", [(1, "editor", "2020-01-02 03:04:05")])
            + _insert("wp_usermeta", [
                (10, 1, "wp_user_level", "1"),
                (11, 99, "wp_user_level", "10"),   # no user 99: INNER JOIN drop
            ]))
    model = _model(dump)
    assert model.admin_users == []
