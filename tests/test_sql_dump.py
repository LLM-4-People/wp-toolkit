"""wpt.localmode.sql_dump tests — every R4 §A pitfall and §C fixture.

Quick reference — test -> R4 item map (docs/research/R4.md):
  §A pitfalls:
    P1  test_p01_extended_insert_single_line
    P2  test_p02_multiline_extended_inserts
    P3  test_p03_updraftplus_space_before_newline_terminator
    P4  test_p04_chunk_independence_tiny_reads and chunk_size=1
        (jointly with test_fixture_c07_large_single_line_insert_streams)
    P5  test_p05_mysqldump_backslash_escapes_including_backtick
    P6  test_p06_quote_doubling
    P7  test_p07_backslash_parity
    P8  test_p08_unescape_table_pct_underscore_and_fallback
    P9  test_p09_adjacent_string_concatenation
    P10 test_p10_quoted_empty_string_stays_empty
    P11 test_p11_null_int_float_and_quoted_decimal
    P12 test_p12_hex_and_bit_literals
    P13 test_p13_binary_introducer_and_lazy_decode
    P14 test_p14_exec_comments_delimiter_and_double_semicolon
    P15 test_p15_dash_dash_requires_whitespace_and_hash_comments
    P16 test_p16_crlf_everywhere
    P17 test_p17_create_table_variants_and_no_double_count
    P18 test_p18_attribution_from_insert_prefix_not_lock_tables
    P19 test_p19_insert_prefix_whitespace_variants (also §C C4, jointly)
    P20 test_p20_complete_insert_column_list
    P21 test_p21_php_serialized_passthrough (also §C C1, jointly)
    P22 test_p22_eof_flush_without_trailing_newline
    P23 test_p23_set_names_harvest_other_sets_ignored
  §C naive-parser failure fixtures:
    C1  test_fixture_c01_semicolon_split_on_serialized_value
    C2  test_fixture_c02_tuple_separator_literal_inside_values
    C3  test_fixture_c03_comment_markers_inside_values
    C4  test_p19_insert_prefix_whitespace_variants (joint with P19)
    C5  test_fixture_c05_naive_quote_regex_failures
    C6  test_fixture_c06_commas_in_values_and_create_defaults
    C7  test_fixture_c07_large_single_line_insert_streams (joint with P4)
    C8  test_fixture_c08_terminator_variants
    C9  test_fixture_c09_invalid_utf8_binary_blob
    C10 test_fixture_c10_rows_vs_statement_count
  Public API / architecture:
    test_public_api_shapes, test_parse_dump_summary_api,
    test_inserts_without_create_table,
    test_iter_rows_unknown_table_and_empty_dump,
    test_parse_dump_single_info_log_line,
    test_chunk_boundary_terminator_across_chunks (real tmp file),
    test_chunk_size_kwarg_arbitrary_values
"""

import io
import logging

import wpt.log
from wpt.localmode.sql_dump import (
    DumpSummary,
    TableStats,
    iter_rows,
    parse_dump,
)


class TinyReads:
    """BinaryIO stand-in whose read() never returns more than `cap` bytes,
    proving the parser makes no chunk-size assumptions."""

    def __init__(self, data: bytes, cap: int = 7):
        self._data = data
        self._pos = 0
        self._cap = cap

    def read(self, n: int = -1) -> bytes:
        if self._pos >= len(self._data):
            return b""
        want = n if n and n > 0 else len(self._data)
        take = min(want, self._cap, len(self._data) - self._pos)
        out = self._data[self._pos : self._pos + take]
        self._pos += take
        return out


def test_p01_extended_insert_single_line():
    dump = b"INSERT INTO `wp_posts` VALUES (1,'a'),(2,'b');\n"
    s = parse_dump(io.BytesIO(dump))
    assert s.tables["wp_posts"].row_count == 2
    assert s.statement_count == 1
    assert list(iter_rows(io.BytesIO(dump), "wp_posts")) == [[1, "a"], [2, "b"]]


def test_p02_multiline_extended_inserts():
    dump = (b"INSERT INTO `t` VALUES\n(1,'a'),\n(2,'b'),\n(3,'c');\n"
            b"INSERT INTO `t` VALUES (4,'d'),\n (5,'e'),\n (6,'f');\n")
    s = parse_dump(io.BytesIO(dump))
    assert s.tables["t"].row_count == 6
    assert s.statement_count == 2
    rows = list(iter_rows(io.BytesIO(dump), "t"))
    assert rows == [[1, "a"], [2, "b"], [3, "c"], [4, "d"], [5, "e"], [6, "f"]]


def test_p03_updraftplus_space_before_newline_terminator():
    dump = b"INSERT INTO `t` VALUES (1); \nINSERT INTO `t` VALUES (2); \n"
    s = parse_dump(io.BytesIO(dump))
    assert s.statement_count == 2
    assert s.tables["t"].row_count == 2


def test_p04_chunk_independence_tiny_reads():
    tricky = (b"/*!40101 SET NAMES utf8mb4 */;\n"
              b"DELIMITER ;;\n"
              b"CREATE PROCEDURE `p`() BEGIN SET @x = 'i;;j'; END;;\n"
              b"DELIMITER ;\n"
              b"INSERT INTO `t` VALUES ('Bob''s', _binary 'a\xffb', 0x41, "
              b"'D:\\\\path\\\\'),\n (2, 'x');\n")

    def sig(summary):
        return (sorted(summary.tables),
                {n: t.row_count for n, t in summary.tables.items()},
                summary.charset, summary.statement_count)

    expected = sig(parse_dump(io.BytesIO(tricky)))
    assert sig(parse_dump(TinyReads(tricky, cap=7))) == expected
    assert sig(parse_dump(io.BytesIO(tricky), chunk_size=1)) == expected
    assert sig(parse_dump(io.BytesIO(tricky), chunk_size=65536)) == expected
    rows_bytesio = list(iter_rows(io.BytesIO(tricky), "t"))
    rows_tiny = list(iter_rows(TinyReads(tricky, cap=7), "t"))
    rows_one = list(iter_rows(io.BytesIO(tricky), "t", chunk_size=1))
    assert rows_bytesio == rows_tiny == rows_one
    assert rows_bytesio[0] == ["Bob's", b"a\xffb", b"A", "D:\\path\\"]


def test_p05_mysqldump_backslash_escapes_including_backtick():
    dump = b"INSERT INTO `t` VALUES ('\\0\\'\\\"\\n\\r\\Z\\\\');\n"
    assert list(iter_rows(io.BytesIO(dump), "t")) == [["\x00'\"\n\r\x1a\\"]]
    named = (b"CREATE TABLE `weird\\`name` (`id` int);\n"
             b"INSERT INTO `weird\\`name` VALUES (7);\n")
    s = parse_dump(io.BytesIO(named))
    assert set(s.tables) == {"weird`name"}
    assert s.tables["weird`name"].row_count == 1


def test_p06_quote_doubling():
    dump = b"INSERT INTO `t` VALUES ('Bob''s', 'a''b');\n"
    s = parse_dump(io.BytesIO(dump))
    assert s.tables["t"].row_count == 1
    assert list(iter_rows(io.BytesIO(dump), "t")) == [["Bob's", "a'b"]]


def test_p07_backslash_parity():
    dump = b"INSERT INTO `t` VALUES ('D:\\\\path\\\\','x'),('a\\'','b');\n"
    s = parse_dump(io.BytesIO(dump))
    assert s.statement_count == 1
    assert s.tables["t"].row_count == 2
    rows = list(iter_rows(io.BytesIO(dump), "t"))
    assert rows == [["D:\\path\\", "x"], ["a'", "b"]]


def test_p08_unescape_table_pct_underscore_and_fallback():
    dump = b"INSERT INTO `t` VALUES ('100\\% done\\_ ok \\q');\n"
    assert list(iter_rows(io.BytesIO(dump), "t")) == [["100\\% done\\_ ok q"]]


def test_p09_adjacent_string_concatenation():
    dump = b"INSERT INTO `t` VALUES ('a' 'b', 'c');\n"
    assert list(iter_rows(io.BytesIO(dump), "t")) == [["ab", "c"]]


def test_p10_quoted_empty_string_stays_empty():
    dump = b"INSERT INTO `t` VALUES ('', 0, '');\n"
    rows = list(iter_rows(io.BytesIO(dump), "t"))
    assert rows == [["", 0, ""]]
    assert rows[0][0] == "" and rows[0][0] is not None


def test_p11_null_int_float_and_quoted_decimal():
    dump = b"INSERT INTO `t` VALUES (NULL, null, 42, -7, +3, 3.14, '1.50', 'abc', '123');\n"
    assert list(iter_rows(io.BytesIO(dump), "t")) == [
        [None, None, 42, -7, 3, 3.14, 1.5, "abc", "123"]]


def test_p12_hex_and_bit_literals():
    dump = (b"INSERT INTO `t` VALUES (0x616263, 0x61626, X'4D7953514C', "
            b"x'4d', b'0101', b'01010101');\n")
    assert list(iter_rows(io.BytesIO(dump), "t")) == [
        [b"abc", b"\x06\x16&", b"MySQL", b"M", b"\x05", b"U"]]


def test_p13_binary_introducer_and_lazy_decode():
    dump = b"INSERT INTO `t` VALUES (_binary 'caf\xe9', 'na\xefve', _binary'tight');\n"
    s = parse_dump(io.BytesIO(dump))
    assert s.tables["t"].row_count == 1
    rows = list(iter_rows(io.BytesIO(dump), "t"))
    assert rows == [[b"caf\xe9", "na\ufffdve", b"tight"]]


def test_p14_exec_comments_delimiter_and_double_semicolon():
    dump = (b"/*!40101 SET @s='a;b' */;\n"
            b"DELIMITER ;;\n"
            b"CREATE PROCEDURE `p`() BEGIN SET @x = 'i;;j'; END;;\n"
            b"DELIMITER ;\n"
            b"INSERT INTO `t` VALUES (1);\n")
    s = parse_dump(io.BytesIO(dump))
    assert s.statement_count == 5
    assert s.tables["t"].row_count == 1
    assert s.charset is None
    assert list(iter_rows(io.BytesIO(dump), "t")) == [[1]]


def test_p15_dash_dash_requires_whitespace_and_hash_comments():
    dump = b"# UpdraftPlus-style comment\nINSERT INTO `t` VALUES ('a-- b #c');\n--x\n"
    s = parse_dump(io.BytesIO(dump))
    assert s.statement_count == 2  # `--x` is NOT a comment: it forms a statement
    assert list(iter_rows(io.BytesIO(dump), "t")) == [["a-- b #c"]]
    proper = b"-- header comment\nINSERT INTO `t` VALUES (1);\n# another comment\nINSERT INTO `t` VALUES (2);\n"
    s2 = parse_dump(io.BytesIO(proper))
    assert s2.statement_count == 2
    assert s2.tables["t"].row_count == 2


def test_p16_crlf_everywhere():
    dump = (b"-- MySQL dump\r\n"
            b"CREATE TABLE `t` (`id` int, `v` text);\r\n"
            b"INSERT INTO `t` VALUES\r\n(1,'a'),\r\n(2,'b');\r\n")
    s = parse_dump(io.BytesIO(dump))
    assert s.statement_count == 2
    assert s.tables["t"].columns == ["id", "v"]
    assert s.tables["t"].row_count == 2
    assert list(iter_rows(io.BytesIO(dump), "t")) == [[1, "a"], [2, "b"]]


def test_p17_create_table_variants_and_no_double_count():
    dump = (b"DROP TABLE IF EXISTS `wp_posts`;\n"
            b"/*!50001 DROP VIEW IF EXISTS `v`*/;\n"
            b"/*!50001 SET @x=@@y */;\n"
            b"/*!50001 CREATE TEMPORARY TABLE `v` (`id` int) */;\n"
            b"DROP TEMPORARY TABLE IF EXISTS `v`;\n"
            b"/*!50001 CREATE VIEW `v` AS select 1 AS `x`*/;\n"
            b"CREATE TABLE IF NOT EXISTS `wp_posts` (`ID` bigint(20) unsigned NOT NULL);\n"
            b"CREATE TABLE `we``ird` (`x` int);\n"
            b"CREATE TABLE plain (c int);\n"
            b"INSERT INTO wp_posts VALUES (1),(2);\n"
            b"INSERT INTO `we``ird` VALUES (5);\n")
    s = parse_dump(io.BytesIO(dump))
    assert set(s.tables) == {"wp_posts", "we`ird", "plain"}
    assert "v" not in s.tables  # 50001 view/temp sections must not double-count
    assert s.tables["wp_posts"].columns == ["ID"]
    assert s.tables["wp_posts"].row_count == 2
    assert s.tables["we`ird"].row_count == 1
    assert s.tables["plain"].columns == ["c"]
    assert s.statement_count == 11


def test_p18_attribution_from_insert_prefix_not_lock_tables():
    dump = b"LOCK TABLES `a` WRITE;\nINSERT INTO `b` VALUES (1),(2);\nUNLOCK TABLES;\n"
    s = parse_dump(io.BytesIO(dump))
    assert "a" not in s.tables
    assert s.tables["b"].row_count == 2
    assert s.statement_count == 3


def test_p19_insert_prefix_whitespace_variants():
    dump = (b"INSERT IGNORE INTO `t1` VALUES (1);\n"
            b"INSERT  IGNORE INTO t1 VALUES (2);\n"
            b"REPLACE INTO `t2` VALUES (3);\n"
            b"REPLACE  INTO t2 VALUES (4);\n")
    s = parse_dump(io.BytesIO(dump))
    assert s.tables["t1"].row_count == 2
    assert s.tables["t2"].row_count == 2
    assert s.statement_count == 4


def test_p20_complete_insert_column_list():
    create = (b"CREATE TABLE `wp_options` (`option_id` int, "
              b"`option_name` text, `option_value` longtext);\n")
    dump_a = create + (b"INSERT INTO `wp_options` (`option_id`,`option_name`,"
                       b"`option_value`) VALUES (1,'siteurl','https://x');\n")
    s = parse_dump(io.BytesIO(dump_a))
    t = s.tables["wp_options"]
    assert t.columns == ["option_id", "option_name", "option_value"]
    assert t.insert_columns == ["option_id", "option_name", "option_value"]
    assert list(iter_rows(io.BytesIO(dump_a), "wp_options")) == [
        [1, "siteurl", "https://x"]]

    dump_b = create + (b"INSERT INTO `wp_options` (`option_value`,`option_id`,"
                       b"`option_name`) VALUES ('https://y',2,'home');\n")
    s2 = parse_dump(io.BytesIO(dump_b))
    assert s2.tables["wp_options"].columns == ["option_id", "option_name", "option_value"]
    assert s2.tables["wp_options"].insert_columns == [
        "option_value", "option_id", "option_name"]
    assert list(iter_rows(io.BytesIO(dump_b), "wp_options")) == [
        ["https://y", 2, "home"]]


def test_p21_php_serialized_passthrough():
    ser = 'a:1:{s:5:"hello";s:11:"wor;ld:}{"";}'
    dump = ("INSERT INTO `wp_options` VALUES (1, 'wpt_opt', '%s');\n" % ser).encode()
    s = parse_dump(io.BytesIO(dump))
    assert s.tables["wp_options"].row_count == 1
    assert list(iter_rows(io.BytesIO(dump), "wp_options")) == [[1, "wpt_opt", ser]]


def test_p22_eof_flush_without_trailing_newline():
    s = parse_dump(io.BytesIO(b"INSERT INTO `t` VALUES (1),(2)"))
    assert s.tables["t"].row_count == 2
    assert s.statement_count == 1
    s2 = parse_dump(io.BytesIO(b"SET NAMES utf8;\nINSERT INTO `t` VALUES (3);"))
    assert s2.tables["t"].row_count == 1
    assert s2.statement_count == 2


def test_p23_set_names_harvest_other_sets_ignored():
    dump = (b"/*!40101 SET NAMES utf8mb4 */;\n"
            b"SET @@session.time_zone = '+00:00';\n"
            b"SET SQL_MODE = \"NO_AUTO_VALUE_ON_ZERO\";\n"
            b"SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT;\n")
    s = parse_dump(io.BytesIO(dump))
    assert s.charset == "utf8mb4"
    assert s.statement_count == 4
    assert s.tables == {}


def test_fixture_c01_semicolon_split_on_serialized_value():
    ser = 'a:2:{i:0;s:3:"a;b";i:1;s:3:"c;d";}'
    dump = ("INSERT INTO `wp_options` VALUES (1, 'opt', '%s');\n" % ser).encode()
    s = parse_dump(io.BytesIO(dump))
    assert s.statement_count == 1  # naive split(';') would report 7
    assert s.tables["wp_options"].row_count == 1
    assert list(iter_rows(io.BytesIO(dump), "wp_options"))[0][2] == ser


def test_fixture_c02_tuple_separator_literal_inside_values():
    dump = b"INSERT INTO `t` VALUES ('a),(b', 1),\n(2, 'x'),\n (3, 'y');\n"
    s = parse_dump(io.BytesIO(dump))
    assert s.tables["t"].row_count == 3
    assert list(iter_rows(io.BytesIO(dump), "t")) == [
        ["a),(b", 1], [2, "x"], [3, "y"]]


def test_fixture_c03_comment_markers_inside_values():
    dump = b"INSERT INTO `t` VALUES ('-- not a comment','# hash');\n"
    assert list(iter_rows(io.BytesIO(dump), "t")) == [["-- not a comment", "# hash"]]


def test_fixture_c05_naive_quote_regex_failures():
    dump = (b"INSERT INTO `t` VALUES ('Bob''s', 'a\\'b', _binary 'bin', "
            b"0x41, X'42', b'1', 'c' 'd');\n")
    s = parse_dump(io.BytesIO(dump))
    assert s.statement_count == 1
    assert list(iter_rows(io.BytesIO(dump), "t")) == [
        ["Bob's", "a'b", b"bin", b"A", b"B", b"\x01", "cd"]]


def test_fixture_c06_commas_in_values_and_create_defaults():
    dump = (b"CREATE TABLE `t` (`a` varchar(10) DEFAULT 'x,y', `b` int,"
            b" `c` varchar(10) DEFAULT ') ,(', `d` enum('p,q','r,s') NOT NULL);\n"
            b"INSERT INTO `t` VALUES ('p,q', 'r(s,t)', 0x2c, 'p,q');\n")
    s = parse_dump(io.BytesIO(dump))
    assert s.tables["t"].columns == ["a", "b", "c", "d"]
    assert list(iter_rows(io.BytesIO(dump), "t")) == [["p,q", "r(s,t)", b",", "p,q"]]


def test_fixture_c07_large_single_line_insert_streams(tmp_path):
    payload = b"x" * 290000
    data = (b"CREATE TABLE `t` (`v` longtext);\n"
            b"INSERT INTO `t` VALUES (1,'" + payload + b"',2);\n")
    p = tmp_path / "big.sql"
    p.write_bytes(data)
    with open(p, "rb") as f:
        s = parse_dump(f)
    assert s.tables["t"].row_count == 1
    assert s.tables["t"].data_bytes >= 290000
    with open(p, "rb") as f:
        rows = list(iter_rows(f, "t"))
    assert rows == [[1, "x" * 290000, 2]]
    s2 = parse_dump(TinyReads(data))
    assert s2.tables["t"].row_count == 1
    assert list(iter_rows(TinyReads(data), "t")) == rows


def test_fixture_c08_terminator_variants():
    dump = (b"INSERT INTO `t` VALUES (1); \n"
            b"INSERT INTO `t` VALUES (2);\r\n"
            b"/*!40000 SET @c=3 */;;\n"
            b"INSERT INTO `t` VALUES (3);\n"
            b"SET @d=4;")
    s = parse_dump(io.BytesIO(dump))
    assert s.statement_count == 5
    assert s.charset is None
    assert s.tables["t"].row_count == 3
    assert list(iter_rows(io.BytesIO(dump), "t")) == [[1], [2], [3]]
    again = parse_dump(TinyReads(dump, cap=3))
    assert again.statement_count == 5
    assert again.tables["t"].row_count == 3


def test_fixture_c09_invalid_utf8_binary_blob(tmp_path):
    data = (b"CREATE TABLE `t` (`v` longblob);\n"
            b"INSERT INTO `t` VALUES (_binary '\xff\xfe\x00raw'), ('bad\xffutf');\n")
    p = tmp_path / "c9.sql"
    p.write_bytes(data)
    with open(p, "rb") as f:
        s = parse_dump(f)
    assert s.tables["t"].row_count == 2
    with open(p, "rb") as f:
        rows = list(iter_rows(f, "t"))
    assert rows == [[b"\xff\xfe\x00raw"], ["bad\ufffdutf"]]


def test_fixture_c10_rows_vs_statement_count():
    tuples = b",".join(b"(%d,'v')" % i for i in range(500))
    dump = b"INSERT INTO `wp_posts` VALUES " + tuples + b";\n"
    s = parse_dump(io.BytesIO(dump))
    assert s.statement_count == 1
    assert s.tables["wp_posts"].row_count == 500
    assert len(list(iter_rows(io.BytesIO(dump), "wp_posts"))) == 500


def test_public_api_shapes():
    dump = b"CREATE TABLE `t` (`a` int);\nINSERT INTO `t` VALUES (1);\n"
    s = parse_dump(io.BytesIO(dump))
    assert isinstance(s, DumpSummary)
    t = s.tables["t"]
    assert isinstance(t, TableStats)
    assert t.name == "t"
    assert t.columns == ["a"]
    assert t.row_count == 1
    assert isinstance(t.create_sql, str) and "CREATE TABLE" in t.create_sql
    assert isinstance(t.data_bytes, int) and t.data_bytes > 0
    assert t.insert_columns is None
    assert isinstance(s.charset, (str, type(None)))
    assert isinstance(s.statement_count, int)


def test_parse_dump_summary_api():
    dump = (b"/*!40101 SET NAMES utf8mb4 */;\n"
            b"DROP TABLE IF EXISTS `wp_options`;\n"
            b"CREATE TABLE `wp_options` (\n"
            b"  `option_id` bigint(20) unsigned NOT NULL,\n"
            b"  `option_name` varchar(191) NOT NULL,\n"
            b"  PRIMARY KEY (`option_id`),\n"
            b"  UNIQUE KEY `option_name` (`option_name`)\n"
            b") ENGINE=MyISAM;\n"
            b"LOCK TABLES `wp_options` WRITE;\n"
            b"INSERT INTO `wp_options` VALUES (1,'siteurl','https://x'),(2,'home','https://x');\n"
            b"UNLOCK TABLES;\n")
    s = parse_dump(io.BytesIO(dump))
    assert s.charset == "utf8mb4"
    t = s.tables["wp_options"]
    assert t.columns == ["option_id", "option_name"]
    assert "ENGINE=MyISAM" in t.create_sql
    assert "PRIMARY KEY" in t.create_sql
    assert t.row_count == 2
    assert t.data_bytes > 0
    assert s.statement_count == 6
    assert s.statement_count != t.row_count


def test_inserts_without_create_table():
    dump = b"INSERT INTO `orphan` VALUES (1),(2);\n"
    s = parse_dump(io.BytesIO(dump))
    t = s.tables["orphan"]
    assert (t.row_count, t.create_sql, t.columns, t.insert_columns) == (2, "", [], None)
    assert list(iter_rows(io.BytesIO(dump), "orphan")) == [[1], [2]]


def test_iter_rows_unknown_table_and_empty_dump():
    assert list(iter_rows(io.BytesIO(b"INSERT INTO `other` VALUES (1);\n"), "wp_options")) == []
    s = parse_dump(io.BytesIO(b""))
    assert s == DumpSummary(tables={}, charset=None, statement_count=0)
    assert list(iter_rows(io.BytesIO(b""), "t")) == []


def test_parse_dump_single_info_log_line(tmp_path):
    logfile = tmp_path / "w.log"
    wpt.log.setup_logging(level="info", logfile=str(logfile))
    parse_dump(io.BytesIO(
        b"CREATE TABLE `t` (`id` int);\nINSERT INTO `t` VALUES (1);\n"))
    logging.getLogger("wpt").handlers[0].flush()
    lines = logfile.read_text().splitlines()
    ours = [ln for ln in lines if "sql dump parsed" in ln]
    assert len(ours) == 1
    assert "1 tables" in ours[0]
    assert "1 rows" in ours[0]
    assert "2 statements" in ours[0]


def test_chunk_boundary_terminator_across_chunks(tmp_path):
    stmt = b"INSERT INTO `t` VALUES (9);"
    chunk = 32
    pad_len = chunk - len(stmt)
    pad = b"-- " + b"a" * (pad_len - 4) + b"\n"
    assert len(pad) == pad_len
    data = pad + stmt + b"\n"
    assert data.index(b";") % chunk == chunk - 1  # ';' ends a chunk, '\n' starts the next
    p = tmp_path / "boundary.sql"
    p.write_bytes(data)
    with open(p, "rb") as f:
        s = parse_dump(f, chunk_size=chunk)
    assert s.statement_count == 1
    assert s.tables["t"].row_count == 1
    with open(p, "rb") as f:
        assert list(iter_rows(f, "t", chunk_size=chunk)) == [[9]]


def test_chunk_size_kwarg_arbitrary_values():
    dump = (b"CREATE TABLE `t` (`id` int);\n"
            b"INSERT INTO `t` VALUES (1,'a'),(2,'b');\n")
    base = parse_dump(io.BytesIO(dump))
    for size in (1, 2, 3, 5, 13, 64, 262144):
        s = parse_dump(io.BytesIO(dump), chunk_size=size)
        assert s.statement_count == base.statement_count
        assert s.tables["t"].row_count == base.tables["t"].row_count
        assert list(iter_rows(io.BytesIO(dump), "t", chunk_size=size)) == [
            [1, "a"], [2, "b"]]
