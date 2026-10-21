"""Unit tests for the DB-referenced media map (wpt.media_refs) — the
database half of the media keep-set.

The live-proven defect this module fixes (measured on an observed site): a page renders only a FRACTION of its attachment images, so
a walk-only keep-set planned most of the media files and bytes for deletion — most files the DATABASE references and the walk
never sees (featured images in menus/widgets/theme options, srcset
candidates, attachment pages, gallery templates, PDFs in post content).
The defensible measurement on that site was a small remainder.

Test -> behavior map:
  text capture:
    test_refs_in_text_html_srcset_and_links ......... img src, srcset
      candidates, <a href> to a PDF: the tail after the FIRST
      wp-content/uploads/ marker, percent-DECODED
    test_refs_in_text_css_json_and_serialized ....... CSS url(), JSON and a
      PHP-serialized value all name the same file
    test_refs_in_text_stops_at_delimiters ........... quote/angle/paren/
      whitespace/backtick cut the tail; a trailing sentence dot and
      curly quote are stripped
    test_refs_in_text_refuses_traversal_and_dirs ..... "..", "." and an
      empty segment never become refs; a directory tail is not a file
    test_refs_in_text_non_string_is_empty ........... NULL/number cells
  stored values:
    test_attached_file_relative_and_marker_bearing .. "2023/10/x.jpg" as-is;
      a full uploads URL reduced to its tail; absolute/traversing refused
    test_attached_file_keeps_spaces .................. a filename with a
      space is NOT cut (the text delimiter rule must never touch a
      stored path)
  attachment metadata — the FOUR load-bearing forms:
    test_meta_form_bare_size_basename ................ sizes[*].file as a
      bare basename, anchored to the attachment's own directory
    test_meta_form_full_path_size_entry .............. a sizes entry that is
      already uploads-relative passes through
    test_meta_form_own_file_key ...................... the map's own `file`
      key is a reference too
    test_meta_form_legacy_backup_sizes .............. the legacy
      _wp_attachment_backup_sizes key carries the same structure and is
      read identically
    test_meta_json_variant_and_broken_payload ....... a JSON-stored map
      reads; a truncated serialization names NOTHING (unknown, never "no
      other files")
  dump:
    test_dump_media_map_full_union ................... one dump carrying all
      six reference classes: attached files, the four metadata forms,
      post content PDF + gallery shortcode, a page-builder-style option, a
      termmeta path
    test_dump_metadata_row_before_its_anchor ......... post_id order is
      arbitrary: a bare size basename read BEFORE _wp_attached_file still
      lands in the attachment's directory
    test_dump_missing_options_table_is_unknown ....... None (never an empty
      keep-set)
    test_dump_prefix_is_not_assumed ................... a non-wp_ prefix is
      followed
  one table identity, one owner (a CONTESTED options/termmeta role — the
  silent 0 on a destructive gate: the keep-set read the PLUGIN's
  `aioseo_options` and measured 0 database references where the control
  measures the full set, while the analyzer read wp_options in the same run):
    test_a_contested_options_table_is_unknown_never_a_zero_keep_set
      aioseo_options / wp_aioseo_options => None (never a set), one warning
      naming both candidates; the control still measures the full set
    test_a_contested_termmeta_table_is_unknown_too  aioseo_termmeta /
      wp_edd_termmeta: a half-measured keep-set is still a lossy one, so
      the whole measurement is UNKNOWN
    test_a_role_nobody_contests_is_still_measured .. absent is NOT contested
      (no termmeta table, and a plugin table merely ENDING in a role name)
    test_a_contested_identity_makes_the_media_audit_say_nothing
      `wpt audit --only media` reports nothing it cannot justify (before the
      fix: the referenced photos + the orphan, un-degraded) and SAYS the
      keep-set was never measured; the control reports the one real orphan
    test_the_three_table_identity_consumers_agree .. AGREEMENT, not
      "each is non-None": the keep-set, the analyzer and the witness name
      the SAME table, and the analyzer's own scope is the PREFIX-defining
      role (a partial dump or a contested termmeta leaves its facts alone)
    test_a_contested_role_narrows_the_witness_to_no_table_at_all
      dump_role_tables is empty on a contested dump, so the currency check
      compares nothing rather than a table nobody read
    test_one_contested_role_is_warned_once_per_input_not_once_per_reader
      ONE resolution and ONE warning per input per run: the keep-set, the
      analyzer and the witness all ask in one run and used to log the same
      sentence 2-4 times
    test_the_table_identity_rule_has_exactly_one_owner  STRUCTURAL guard (an
      AST/data-ownership one, not a banned-name list), on USE and not on the
      presence of an import: naming the option_name+option_value pair
      requires reaching the owner through its own API, and every consumer
      USES the symbols its role needs (the three mutating actions included)
    test_the_identity_owner_resolves_a_name_only_source_fail_closed
      the wire half: db_audit carries names and no columns, so one candidate
      is used and two are already UNKNOWN, warned once per input
    test_gather_local_measures_db_refs ............... the local gatherer
      fills AuditData.db_refs (the dump handle is closed by then)
  a PARTIAL dump is not a site without attachments (the missing-PREFIX-role
  defect: `_wp_attached_file` lives in wp_postmeta, and a phpMyAdmin
  per-table export declares an options table and no postmeta, so the
  keep-set came out a POSITIVE ZERO — a large set of deletable photos, un-degraded):
    test_a_dump_without_postmeta_is_unknown_not_a_zero_keep_set
      both shapes (the table absent; its CREATE cut mid-statement) => None
      and ONE warning naming postmeta; the whole export measures the full set
    test_a_partial_dump_makes_the_media_audit_say_nothing
      the same tree: 0 justified candidates + the marker, against the
      control's one real orphan
    test_a_partial_dump_narrows_the_witness_and_the_analyzer_alike
      the witness compares nothing and the analyzer keeps the facts the
      export really contains (the options table is the prefix)
  bridge:
    test_db_refs_for_data_memoizes_one_bridge_call ... ONE media_map
      mode=db call, memoized on the data object
    test_db_refs_for_data_bridge_failure_degrades .... a failing call is
      ONE warning + None, never an exception
    test_db_refs_for_data_local_reads_the_field ...... local mode reads the
      gathered set and never touches a bridge
  the ONE rule both modes share (this file's deliverable):
    test_ref_extensions_match_the_profile_and_the_bridge ... the shipped
      family equals wpt/data/profiles/default.json AND bridge.php's mirrored
      default: neither mirror can drift
    test_the_gate_answers_with_the_callers_widened_family ... D1: a
      WIDENED profile (--set media.extensions=[..., "psd"]) is carried on
      the read, so the live gate keeps a _wp_attached_file the shipped
      default alone cannot name — and the offline half agrees, while the
      default alone drops it (the deletion the defect produced)
    test_the_widened_file_is_not_deletable_in_either_mode ... the shared
      enumeration plans no database-referenced .psd whichever half
      measured the database, and the two halves answer identically
    test_the_bridge_refuses_an_unusable_family_and_keeps_its_floor ... no
      request (empty, mistyped, dotted, non-string, path, oversized) can
      narrow the gate below the mirrored default, and each refusal is
      flagged so the client fails closed
    test_the_extension_token_rule_is_the_same_on_both_sides ... the
      client's token pattern and bound mirror bridge.php's, pinned
      against the deployed file
    test_ref_normalize_mirrors_the_php_normalizer .... the uploads-marker
      cut, NUL/backslash folding, absolute refusal, segment refusal
    test_ref_is_kept_gates_extension_then_directory ... the extension
      family, the dotfile rule, the is-a-directory belt and its skip
    test_php_decode_tolerates_the_tags_php_reads .... N;/O:/C:/R: decoded
      and consumed, R: resolved through PHP's own var_hash numbering, a
      reference past the end UNREADABLE (PHP 8.4), numeric string keys
      cast to int
    test_php_decode_agrees_with_the_analyzer_subset .... the two decoders
      return the same answer on every shape both accept
    test_dump_and_bridge_return_the_same_set .......... THE DIFFERENTIAL
      TEST: one table fixture, run through the real wpt_media_db_map out
      of bridge.php AND through db_refs_from_dump, diffed per shape
    test_dump_gates_a_directory_named_like_a_file ..... the is-a-directory
      belt is applied offline too (the enumerated dirs are the witness)
    test_uploads_dirs_reads_a_walk_and_never_guesses ... the walk's
      directories arrive UPLOADS-relative, the shape every reference is
    test_dump_reports_the_references_its_gate_dropped .. a lossy keep-set
      is reported once, never silent
    test_is_media_and_the_keep_gate_are_one_rule ....... the enumeration and
      the keep-set judge "media" through one implementation
    test_php_decode_matches_php_unserialize ........... the stored-value
      decoder measured against the PHP 8.4 CLI, shape for shape
  the PHP MIRRORS, pinned BOTH WAYS (the deployed file is the oracle; the
  comparison is over SETS, because a caller acts on a keep-set, not on a
  string):
    test_ref_normalize_matches_the_php_normalizer_set_for_set  the two
      normalizers over a corpus with a NUL at every position — the shipped
      fixture's TRAILING NUL proved nothing (PHP's own trim() removes it),
      so dropping the PHP's NUL strip was invisible with all 2286 tests
      green
    test_the_file_stem_pass_bound_matches_the_php_helper  the Python bound
      is pinned against the DEPLOYED loop bound (it was pinned against a
      literal, and the PHP side was pinned by nothing: 5 -> 6 was green),
      and both implementations answer the same corpus
"""

import contextlib
import io
import json
import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import pytest

from wpt.audit.data import gather_local
from wpt.audit.media import is_media
from wpt.media_refs import (
    REF_EXTENSIONS,
    _TEXT_DELIMITERS,  # the python/php lockstep test reads the set
    _TRAILING_PUNCTUATION,  # ... and so does the trailing-punctuation pin
    decode_php_value,
    _php_decode,
    _PhpDecodeError,
    _PhpValue,
    db_refs_for_data,
    db_refs_from_dump,
    ref_from_attached_file,
    ref_is_kept,
    ref_normalize,
    refs_from_attachment_meta,
    refs_in_text,
    uploads_dirs,
)
from wpt.settings import DbSettings, load
from wpt.types import Entry
from tests.dump_fixtures import (
    AIOSEO_OPTIONS_SCHEMA,
    AIOSEO_POSTS_SCHEMA,
    AIOSEO_TERMMETA_SCHEMA,
    CORE_SCHEMA,
    EDD_TERMMETA_SCHEMA,
    WP_AIOSEO_OPTIONS_SCHEMA,
    make_dump,
)
from tests.fakes import FakeSource

REPO = Path(__file__).resolve().parents[1]
BRIDGE_SOURCE = REPO / "wpt" / "wpbridge" / "bridge.php"
PROFILE_DEFAULT = REPO / "wpt" / "data" / "profiles" / "default.json"


# --------------------------------------------------------------- dump fixture


def _cell(value) -> str:
    if value is None:
        return "NULL"
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def _create(table: str, columns: list[str]) -> bytes:
    cols = ", ".join("`%s` text" % c for c in columns)
    return ("CREATE TABLE `%s` (%s);\n" % (table, cols)).encode()


def _insert(table: str, rows: list) -> bytes:
    tuples = ",".join("(" + ",".join(_cell(c) for c in row) + ")" for row in rows)
    return (f"INSERT INTO `{table}` VALUES " + tuples + ";\n").encode()


def _ser(value: str) -> str:
    """PHP-serialize one string (declared length = UTF-8 byte count)."""
    return 's:%d:"%s";' % (len(value.encode("utf-8")), value)


class _Raw(str):
    """A pre-serialized PHP value, embedded in a map verbatim (a nested
    array/object is a VALUE, not a serialized string)."""


def _ser_map(pairs: list[tuple[str, object]]) -> str:
    """PHP-serialize an associative array (insertion order preserved)."""
    body = "".join(
        _ser(k) + (v if isinstance(v, _Raw) else _ser(v))
        for k, v in pairs
    )
    return "a:%d:{%s}" % (len(pairs), body)


def _meta(file: str | None, sizes: list[tuple[str, str]]) -> str:
    """A PHP-serialized attachment-metadata value: the `file` key plus a
    `sizes` map of name -> {file, width, height} (core's real shape)."""
    pairs = [("file", file)] if file else []
    size_entries = [
        (name, _Raw(_ser_map([("file", value),
                              ("width", "150"), ("height", "150")])))
        for name, value in sizes
    ]
    pairs.append(("sizes", _Raw(_ser_map(size_entries))))
    return _ser_map(pairs)


def _dump(postmeta=(), posts=(), options=(), termmeta=(), prefix="wp_",
          with_options_table=True) -> bytes:
    """A minimal WordPress dump: the four tables the media map reads."""
    out = b""
    if with_options_table:
        out += _create(prefix + "options",
                       ["option_id", "option_name", "option_value", "autoload"])
        if options:
            out += _insert(prefix + "options", options)
    out += _create(prefix + "postmeta",
                   ["meta_id", "post_id", "meta_key", "meta_value"])
    if postmeta:
        out += _insert(prefix + "postmeta", postmeta)
    out += _create(prefix + "posts",
                   ["ID", "post_type", "post_status", "post_content",
                    "post_excerpt", "post_guid"])
    if posts:
        out += _insert(prefix + "posts", posts)
    out += _create(prefix + "termmeta", ["meta_id", "meta_key", "meta_value"])
    if termmeta:
        out += _insert(prefix + "termmeta", termmeta)
    return out


class _Recording(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record):
        self.records.append(record)


def _wpt_records():
    """Attach a capture handler to the non-propagating wpt logger tree."""
    parent = logging.getLogger("wpt")
    handler = _Recording()
    old = parent.level
    parent.addHandler(handler)
    parent.setLevel(logging.DEBUG)
    return handler, parent, old


def _release(handler, parent, old):
    parent.setLevel(old)
    parent.removeHandler(handler)


# ------------------------------------------------- python/php lockstep


def test_text_delimiters_match_the_php_extractor_exactly():
    """The Python and PHP tails must cut at the SAME characters.

    A path the Python side truncates and the PHP side keeps (or the
    reverse) is a keep-set that differs by mode: the same file would be
    protected offline and unprotected on the observed site, or worse the
    other way round.  The bridge's delimiter string is read straight out
    of bridge.php and evaluated, so the two cannot drift silently.
    """
    source = (Path(__file__).resolve().parents[1]
              / "wpt" / "wpbridge" / "bridge.php").read_text(encoding="utf-8")
    match = re.search(
        r"function wpt_media_ref_delims\(\) \{\s*return (.*?);\s*\}",
        source, re.S)
    assert match, "bridge.php no longer defines wpt_media_ref_delims()"
    delims = ""
    for piece in re.findall(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"",
                            match.group(1)):
        if piece.startswith("'"):
            delims += piece[1:-1].replace("\\\\", "\\").replace("\\'", "'")
        else:
            body = piece[1:-1]
            for escape, char in (("\\t", "\t"), ("\\r", "\r"), ("\\n", "\n"),
                                 ("\\f", "\f"), ("\\v", "\v"), ("\\0", "\0"),
                                 ("\\\\", "\\")):
                body = body.replace(escape, char)
            delims += body
    assert set(delims) == set(_TEXT_DELIMITERS)
    # a percent sign is the ENCODING lead, never a delimiter: cutting at
    # it would truncate every %%20 filename to its first space
    assert "%" not in _TEXT_DELIMITERS


def test_trailing_punctuation_matches_the_php_extractor_exactly():
    """THE PIN, IN BOTH DIRECTIONS: the two halves must be the same SET.

    ``wpt/media_refs.py``'s ``_TRAILING_PUNCTUATION`` and bridge.php's
    ``wpt_media_ref_trailing_punct`` implement ONE rule — the punctuation a
    captured path tail loses.  There was no test for it, and the two were
    made to diverge during the audit sweep with the whole suite GREEN.

    The direction that matters is the PHP side trimming a character the
    Python side keeps: the bridge is then a keep-set that loses a reference
    the offline half protects, and a lost keep-set reference is a DELETION.
    The other direction over-protects, which is still a mode difference.

    The PHP half is read out of the DEPLOYED FILE by name, through the same
    brace-matched ``_php_function`` helper the differential harness uses, and
    EVALUATED BY PHP ITSELF (so the byte escapes in the literal are
    interpreted by the language that will run them, not by a Python
    re-implementation of PHP string syntax that could be wrong in the same
    way twice).  The comparison is on the SET, never on the string: the two
    sides order the characters differently on purpose.
    """
    if shutil.which("php") is None:
        pytest.fail("php CLI not found on PATH (the bridge oracle is the "
                    "reference these tests measure against)")
    source = (Path(__file__).resolve().parents[1]
              / "wpt" / "wpbridge" / "bridge.php").read_text(encoding="utf-8")
    function = _php_function("wpt_media_ref_trailing_punct", source)
    # the characters, split as CHARACTERS (not bytes: the set holds two
    # multi-byte typographic quotes) and asked of PHP itself
    script = (
        function + "\n"
        'echo json_encode(preg_split(\'//u\', wpt_media_ref_trailing_punct(),'
        ' -1, PREG_SPLIT_NO_EMPTY), JSON_UNESCAPED_UNICODE), "\\n";\n'
    )
    proc = subprocess.run(["php", "-r", script], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    php_set = set(json.loads(proc.stdout))
    assert php_set == set(_TRAILING_PUNCTUATION), (
        "the trailing-punctuation rule has drifted between wpt/media_refs.py "
        f"and bridge.php: {sorted(php_set ^ set(_TRAILING_PUNCTUATION))}")


def test_the_php_extractor_uses_the_pinned_trailing_punctuation():
    """The pinned function is the ONE the extractor calls.

    Without this the pin could be satisfied by a function nothing reads: the
    literal would move back inline and the two halves would drift silently
    again, with the pin still green.
    """
    source = (Path(__file__).resolve().parents[1]
              / "wpt" / "wpbridge" / "bridge.php").read_text(encoding="utf-8")
    extractor = _php_function("wpt_media_refs_in_text", source)
    assert "wpt_media_ref_trailing_punct()" in extractor


#: The values the NORMALIZER pin below measures, chosen so that every rule
#: the two halves implement is load-bearing and every ORDERING of a NUL is
#: present: leading, embedded, trailing, doubled, and inside a filename, an
#: uploads path and a segment boundary.  A pin over a corpus that only had a
#: TRAILING NUL proves nothing here, because PHP's ``trim()`` removes a
#: trailing NUL by itself — which is exactly why dropping the PHP's own NUL
#: strip left the whole suite green.
_NORMALIZER_CORPUS = [
    "2023/10/pic.jpg",
    "  2023/10/pic.jpg  ",
    "2023/10/with space.jpg",
    "2019/02/x.jpg\x00",                  # trailing (trim() hides it)
    "\x002023/10/pic.jpg",                # leading (trim() hides it)
    "2023/10/q\x001.jpg",                 # EMBEDDED in the filename
    "img\x00name.png",                    # embedded, no directory
    "2019/02/a\x00/b.jpg",                # embedded at a segment boundary
    "a\x00b\x00c.jpg",                    # two of them
    "https://site.test/wp-content/uploads/2024/01/a\x00b.jpg",
    "/home/old/public_html/wp-content/uploads/2018/03/p\x00.jpg",
    "2019\\02\\SampleImg.jpg",             # backslashes (the other fold)
    "2019\\\\02\\\\Smpl\x00sampleimg.jpg",
    "https://site.test/wp-content/uploads/2018/03/photo.jpg",
    "/etc/passwd",                        # absolute, no marker: refused
    "",
    "   ",
    "2019//02//x.jpg",                    # collapsed, never refused
    "2019/./x.jpg",                       # refused
    "2019/02/../x.jpg",                   # refused
    "2019/02/",                           # a directory tail
]


def test_ref_normalize_matches_the_php_normalizer_set_for_set():
    """THE PIN, IN BOTH DIRECTIONS — the SETS, over the corpus above.

    ``wpt/media_refs.py``'s ``ref_normalize`` and bridge.php's
    ``wpt_media_ref_normalize`` implement ONE rule, and the two MODES of the
    keep-set (the dump read here, the bridge's own SQL there) are only the
    same keep-set while the rules are.  The direction that costs media is
    the one this test existed to catch and did not: the shipped fixture row
    was a NUL at the END of a value, which PHP's ``trim()`` already removes,
    so deleting the PHP's explicit NUL strip changed no answer and left all
    2286 tests green — while an EMBEDDED NUL then diverged (PHP keeps it,
    Python strips it), and the half that keeps it protects a path no real
    file can have: a keep-set reference lost by a mode difference.

    The PHP half is read out of the DEPLOYED FILE by name through the same
    brace-matched ``_php_function`` helper and asked of PHP itself, so the
    comparison is over what the shipped code DOES, not over a Python
    re-reading of PHP source.
    """
    if shutil.which("php") is None:
        pytest.fail("php CLI not found on PATH (the bridge oracle is the "
                    "reference these tests measure against)")
    function = _php_function(
        "wpt_media_ref_normalize", BRIDGE_SOURCE.read_text(encoding="utf-8"))
    script = ("<?php\n" + function + "\n"
              'echo json_encode(array_map("wpt_media_ref_normalize",'
              ' json_decode(file_get_contents($argv[1]))),'
              " JSON_UNESCAPED_SLASHES);\n")
    with _php_run(script, _NORMALIZER_CORPUS) as php_values:
        python_values = [ref_normalize(v) for v in _NORMALIZER_CORPUS]
    for raw, php_value, python_value in zip(
            _NORMALIZER_CORPUS, php_values, python_values):
        assert php_value == python_value, (
            f"the normalizer has drifted between wpt/media_refs.py and "
            f"bridge.php for {raw!r}: php={php_value!r} "
            f"python={python_value!r}")


def test_the_file_stem_pass_bound_matches_the_php_helper():
    """THE STEM PIN, IN BOTH DIRECTIONS — the SETS, and the bound.

    ``wpt.audit.media._file_stem`` and bridge.php's ``wpt_file_stem`` decide
    which same-directory siblings of a reference are protected, so a
    divergence is a file the offline half keeps and the live half deletes (or
    the reverse).  The Python side's bound was pinned against a LITERAL in a
    test, and the PHP side's was pinned by NOTHING: widening the deployed
    ``for ( $i = 0; $i < 5; $i++ )`` to 6 left all 2286 tests green.

    So the bound is read out of the deployed NAMED CONSTANT
    (``WPT_MEDIA_STEM_PASSES``, beside the other ``WPT_MEDIA_*`` bounds, the
    module's own convention) and compared with the Python constant that
    owns it — so the pin no longer depends on a literal it could read out of
    a loop condition, and re-introducing that literal (a bare ``5`` in the
    ``for``, which nothing would then hold in step with Python) fails here
    instead of passing silently.  Then the two implementations are asked the
    same corpus and their output SETS compared — which is what a caller acts
    on (a sibling kept, or not), so a difference in either direction fails.
    """
    if shutil.which("php") is None:
        pytest.fail("php CLI not found on PATH (the bridge oracle is the "
                    "reference these tests measure against)")
    from wpt.audit.media import _STEM_PASSES, _file_stem

    source = BRIDGE_SOURCE.read_text(encoding="utf-8")
    function = _php_function("wpt_file_stem", source)
    constant = re.search(
        r"define\(\s*'WPT_MEDIA_STEM_PASSES'\s*,\s*(\d+)\s*\)", source)
    assert constant, (
        "bridge.php no longer defines WPT_MEDIA_STEM_PASSES: the bound this "
        "test reads is a named constant on purpose, so a literal in the loop "
        "is a fact nothing holds in step with wpt/audit/media.py again")
    bound = re.search(r"for \(\s*\$i\s*=\s*0\s*;\s*\$i\s*<\s*([^;]+);", function)
    assert bound and bound.group(1).strip() == "WPT_MEDIA_STEM_PASSES", (
        "bridge.php's wpt_file_stem must compare its loop against "
        f"WPT_MEDIA_STEM_PASSES, not a literal (found {bound.group(1)!r})")
    assert int(constant.group(1)) == _STEM_PASSES, (
        "the stem strip bound has drifted between wpt/audit/media.py "
        f"({_STEM_PASSES} passes) and bridge.php "
        f"({constant.group(1)}): a "
        f"chained suffix one side strips and the other keeps is a keep-set "
        f"sibling the two modes disagree about")

    # a corpus that reaches the bound, so a widened loop cannot pass
    corpus = [
        "pic.jpg",
        "2023/10/pic-300x233.jpg",
        "img-scaled-1024x768.jpg",
        "img-1024x768-scaled.jpg",
        "a-300x233",
        ".htaccess",
        "report-2023x.pdf",
        "photo-SCALED.jpg",
        "photo-300X233.jpg",
        "a" + "-1x1" * 3 + ".jpg",         # 3 chains: inside the bound
        "a" + "-1x1" * 5 + ".jpg",         # exactly the bound
        "a" + "-1x1" * 6 + ".jpg",         # one past it: the load-bearing row
    ]
    # the oracle is asked about the DEPLOYED function, so it is given the
    # deployed constant too — the bound the loop reads is the same one the
    # pin above just compared, not a fresh 5
    with _php_run('<?php\n' + constant.group(0) + ";\n" + function
                  + '\necho json_encode(array_map("wpt_file_stem",'
                    ' json_decode(file_get_contents($argv[1]))),'
                    " JSON_UNESCAPED_SLASHES);\n", corpus) as php_stems:
        python_stems = [_file_stem(name) for name in corpus]
    for name, php_stem, python_stem in zip(corpus, php_stems, python_stems):
        assert php_stem == python_stem, (
            f"the file-stem rule has drifted between wpt/audit/media.py and "
            f"bridge.php for {name!r}: php={php_stem!r} "
            f"python={python_stem!r}")


# ------------------------------------------------------------- text capture


def test_refs_in_text_html_srcset_and_links():
    html = (
        '<img src="https://site.test/wp-content/uploads/2023/10/pic.jpg" '
        'srcset="https://site.test/wp-content/uploads/2023/10/pic-300x233.jpg 300w, '
        '/wp-content/uploads/2023/10/pic-scaled.jpg 900w">'
        '<a href="/wp-content/uploads/2023/11/brochure.pdf">download</a>'
    )
    assert refs_in_text(html) == {
        "2023/10/pic.jpg",
        "2023/10/pic-300x233.jpg",
        "2023/10/pic-scaled.jpg",
        "2023/11/brochure.pdf",
    }


def test_refs_in_text_css_json_and_serialized():
    assert refs_in_text(
        "body{background:url('/wp-content/uploads/2024/01/bg.png')}"
    ) == {"2024/01/bg.png"}
    assert refs_in_text(
        '{"bg":"https://site.test/wp-content/uploads/2024/01/bg.png"}'
    ) == {"2024/01/bg.png"}
    # the same path named inside a PHP-serialized option value
    assert refs_in_text(
        _ser_map([("image", "https://site.test/wp-content/uploads/2024/01/bg.png")])
    ) == {"2024/01/bg.png"}


def test_refs_in_text_stops_at_delimiters():
    assert refs_in_text(
        'src="wp-content/uploads/2023/10/pic.jpg?ver=2"'
    ) == {"2023/10/pic.jpg"}                     # query dropped
    assert refs_in_text(
        "url(wp-content/uploads/2023/10/pic.jpg)"
    ) == {"2023/10/pic.jpg"}                     # CSS url() token
    # a path at the end of a sentence loses the trailing punctuation
    assert refs_in_text(
        "see wp-content/uploads/2023/10/pic.jpg, then leave"
    ) == {"2023/10/pic.jpg"}
    # percent-decoded: the tail must equal the on-disk name
    assert refs_in_text(
        'src="/wp-content/uploads/2023/10/with%20space.jpg"'
    ) == {"2023/10/with space.jpg"}


def test_refs_in_text_refuses_traversal_and_dirs():
    assert refs_in_text("wp-content/uploads/../wp-config.php") == set()
    assert refs_in_text("wp-content/uploads/./x.jpg") == set()
    assert refs_in_text("wp-content/uploads//x.jpg") == set()
    assert refs_in_text("wp-content/uploads/2023/10/") == set()
    assert refs_in_text("wp-content/uploads/") == set()


def test_refs_in_text_non_string_is_empty():
    assert refs_in_text(None) == set()
    assert refs_in_text(42) == set()
    assert refs_in_text("") == set()


# ------------------------------------------------------------ stored values


def test_attached_file_relative_and_marker_bearing():
    assert ref_from_attached_file("2023/10/pic.jpg") == "2023/10/pic.jpg"
    assert ref_from_attached_file(" banner.jpg ") == "banner.jpg"
    # a value carrying the uploads marker (very old sites store the URL)
    assert ref_from_attached_file(
        "https://site.test/wp-content/uploads/2023/10/pic.jpg"
    ) == "2023/10/pic.jpg"
    # unusable shapes never become a ref
    assert ref_from_attached_file("/var/www/html/uploads/2023/x.jpg") is None
    assert ref_from_attached_file("../../etc/passwd") is None
    assert ref_from_attached_file("") is None
    assert ref_from_attached_file(None) is None


def test_attached_file_keeps_spaces():
    # the text delimiter rule must never cut a STORED path: a real
    # filename may contain a space, and cutting it would make the file
    # look unreferenced (a deletion bug, not a false positive)
    assert ref_from_attached_file("2023/10/with space.jpg") == \
        "2023/10/with space.jpg"
    assert ref_from_attached_file("2023/10/it's here.jpg") == \
        "2023/10/it's here.jpg"


# ------------------------------------------------- attachment metadata forms


def test_meta_form_bare_size_basename():
    # FORM 1: sizes[*].file stored as a bare basename, anchored to the
    # attachment's own directory (bridge wpt_media_variants' rule)
    raw = _meta("2023/11/pic.png", [("thumbnail", "pic-150x150.png")])
    assert refs_from_attachment_meta(raw, "2023/11/") == {
        "2023/11/pic.png", "2023/11/pic-150x150.png",
    }
    # no directory known -> a BARE basename lands at the uploads root,
    # while an entry that already carries its directory is untouched
    assert refs_from_attachment_meta(raw, "") == {
        "2023/11/pic.png", "pic-150x150.png",
    }


def test_meta_form_full_path_size_entry():
    # FORM 2: a sizes entry that is already uploads-relative
    raw = _meta("2023/11/pic.png", [("custom", "2023/11/pic-odd.png"),
                                    ("slashed", "/2023/11/pic-wide.png")])
    assert refs_from_attachment_meta(raw, "2023/11/") == {
        "2023/11/pic.png", "2023/11/pic-odd.png", "2023/11/pic-wide.png",
    }


def test_meta_form_own_file_key():
    # FORM 3: the map's own `file` key is a reference, sizes or not
    raw = _meta("2023/11/solo.png", [])
    assert refs_from_attachment_meta(raw, "2023/11/") == {"2023/11/solo.png"}
    # a bare `file` basename is anchored like a sizes entry
    assert refs_from_attachment_meta(_meta("solo.png", []), "2023/11/") == {
        "2023/11/solo.png",
    }


def test_meta_form_legacy_backup_sizes():
    # FORM 4: the legacy key carries the same structure — the DUMP path
    # reads both keys through this one function (see the dump test below)
    raw = _meta("2023/11/pic.png", [("thumbnail", "pic-150x150.png")])
    assert refs_from_attachment_meta(raw, "2023/11/") == \
        refs_from_attachment_meta(_meta("2023/11/pic.png",
                                        [("thumbnail", "pic-150x150.png")]),
                                  "2023/11/")


def test_meta_json_variant_and_broken_payload():
    # some plugins store the same map as JSON
    assert refs_from_attachment_meta(
        '{"file": "2023/11/pic.png", "sizes": {"thumbnail": '
        '{"file": "pic-150x150.png"}}}',
        "2023/11/",
    ) == {"2023/11/pic.png", "2023/11/pic-150x150.png"}
    # truncated / unsupported serialization: UNKNOWN, never "no other
    # files" (the fail direction that deletes live thumbnails)
    assert refs_from_attachment_meta('a:2:{s:4:"file"', "2023/11/") == set()
    assert refs_from_attachment_meta("not a map at all", "2023/11/") == set()
    assert refs_from_attachment_meta("", "2023/11/") == set()
    assert refs_from_attachment_meta(None, "2023/11/") == set()


# -------------------------------------------------------------------- dump


def test_dump_media_map_full_union():
    dump = _dump(
        postmeta=[
            (1, 10, "_wp_attached_file", "2023/11/pic.png"),
            (2, 10, "_wp_attachment_metadata",
             _meta("2023/11/pic.png", [("thumbnail", "pic-150x150.png"),
                                       ("custom", "2023/11/pic-odd.png")])),
            (3, 10, "_wp_attachment_backup_sizes",
             _meta("2023/11/pic.png", [("full", "pic-1920x1080.png")])),
            (4, 11, "_wp_attached_file", "2023/11/doc.pdf"),
            (5, 12, "_elementor_data",
             '{"bg":"https://site.test/wp-content/uploads/2024/01/bg.png"}'),
            (6, 13, "_menu_item_meta",
             "https://site.test/wp-content/uploads/2023/12/menu.png"),
        ],
        posts=[
            (20, "post", "publish",
             '<p>[gallery ids="1,2"]</p>'
             '<a href="/wp-content/uploads/2023/11/brochure.pdf">PDF</a>', None,
             "https://site.test/?p=20"),
            (21, "attachment", "inherit", None, None,
             "https://site.test/wp-content/uploads/2023/11/attachment-only.png"),
        ],
        options=[
            (1, "avada_options",
             _ser_map([("logo", "https://site.test/wp-content/uploads/"
                        "2024/02/logo.png")])),
            (2, "siteurl", "https://site.test"),
        ],
        termmeta=[(1, "_category_image", "/wp-content/uploads/2024/03/cat.jpg")],
    )
    assert db_refs_from_dump(io.BytesIO(dump)) == {
        # 1. every attachment's own path
        "2023/11/pic.png", "2023/11/doc.pdf",
        # 2. the four metadata forms
        "2023/11/pic-150x150.png",     # bare size basename, anchored
        "2023/11/pic-odd.png",         # full-path size entry
        "2023/11/pic-1920x1080.png",   # legacy backup-sizes key
        # 3. another postmeta value naming a path
        "2024/01/bg.png", "2023/12/menu.png",
        # 4. post content + guid
        "2023/11/brochure.pdf", "2023/11/attachment-only.png",
        # 5. an option value holding an uploads path
        "2024/02/logo.png",
        # 6. term meta
        "2024/03/cat.jpg",
    }


def test_dump_metadata_row_before_its_anchor():
    # post_id order in a dump is arbitrary: a bare size basename read
    # BEFORE its _wp_attached_file row must still land in that
    # attachment's directory, never at the uploads root
    dump = _dump(postmeta=[
        (1, 10, "_wp_attachment_metadata",
         _meta("2023/11/pic.png", [("thumbnail", "pic-150x150.png")])),
        (2, 10, "_wp_attached_file", "2023/11/pic.png"),
    ])
    refs = db_refs_from_dump(io.BytesIO(dump))
    assert refs == {"2023/11/pic.png", "2023/11/pic-150x150.png"}
    assert "pic-150x150.png" not in refs  # not left at the uploads root


def test_dump_missing_options_table_is_unknown():
    # no options table = no prefix = no way to find the site's tables:
    # UNKNOWN (None), never an empty keep-set that deletes everything
    handler, parent, old = _wpt_records()
    try:
        assert db_refs_from_dump(io.BytesIO(
            _create("wp_posts", ["ID", "post_content"])
        )) is None
    finally:
        _release(handler, parent, old)
    assert any("no usable options table" in r.getMessage()
               for r in handler.records)


def test_dump_prefix_is_not_assumed():
    dump = _dump(prefix="sample_", postmeta=[
        (1, 10, "_wp_attached_file", "2023/10/pic.jpg"),
    ])
    assert db_refs_from_dump(io.BytesIO(dump)) == {"2023/10/pic.jpg"}


# ------------------------------------------- one table identity, one owner
#
# THE DEFECT: "which table is the OPTIONS table" had THREE rules, and two of
# them disagreed inside ONE run.  This module picked the first name in
# ``sorted()``; the analyzer picked the first table in DUMP order; clean-db
# picked the first candidate over live columns.  On a dump that also declares
# ``aioseo_options`` (a table All in One SEO 4.x really creates, carrying
# the same option_name/option_value pair) the keep-set resolved to the
# PLUGIN's table and measured 0 database-referenced files where the control
# measures the full set — a POSITIVE "this database references no uploads file", not
# the UNKNOWN every consumer refuses closed on — while the analyzer's own
# warning sat in the same log naming a different table.  The audit then
# reported every database-attached photo as unreferenced.
#
# The fix is ONE rule in ONE place: wpt.media_refs.resolve_role, which
# answers UNKNOWN (fail-closed, one warning naming the candidates) whenever
# more than one table proves a role.

#: The control's measurement: the files the database names.
DB_REFS = {f"2023/10/photo-{index:02d}.jpg" for index in range(12)}


def _site_dump(tmp_path, name, decoys=(), refs=DB_REFS, tables=CORE_SCHEMA):
    """A real-shaped dump of this site, plus the plugin tables ``decoys``."""
    return make_dump(tmp_path, refs=refs, name=name,
                     tables=tuple(tables) + tuple(decoys))


@pytest.mark.parametrize("decoy", [AIOSEO_OPTIONS_SCHEMA,
                                   WP_AIOSEO_OPTIONS_SCHEMA])
def test_a_contested_options_table_is_unknown_never_a_zero_keep_set(
        tmp_path, decoy):
    """The measured case: a POSITIVE 0 on a dump that references the full set."""
    handler, parent, old = _wpt_records()
    try:
        with open(_site_dump(tmp_path, f"decoy-{decoy[0]}.sql", (decoy,)),
                  "rb") as dump:
            measured = db_refs_from_dump(dump)
        # the CONTROL, same dump without the plugin's table
        with open(_site_dump(tmp_path, f"control-{decoy[0]}.sql"), "rb") as f:
            assert db_refs_from_dump(f) == DB_REFS
    finally:
        _release(handler, parent, old)
    assert measured is None, "a contested identity must be UNKNOWN, never a set"
    warnings = [r.getMessage() for r in handler.records
                if r.levelno >= logging.WARNING]
    assert any(decoy[0] in message and "wp_options" in message
               for message in warnings), warnings


@pytest.mark.parametrize("decoy", [AIOSEO_TERMMETA_SCHEMA,
                                   EDD_TERMMETA_SCHEMA])
def test_a_contested_termmeta_table_is_unknown_too(tmp_path, decoy):
    """The same residual one role over — and a half-measured keep-set is
    still a lossy one.

    ``aioseo_termmeta`` sorted before ``wp_termmeta`` and displaced it, so
    every category image stored in the real table left the keep-set
    silently.  The options role here is perfectly resolvable and many postmeta
    references are readable; skipping only the contested half would be the
    same false positive one level down, so the whole measurement is
    UNKNOWN.
    """
    handler, parent, old = _wpt_records()
    try:
        with open(_site_dump(tmp_path, f"term-{decoy[0]}.sql", (decoy,)),
                  "rb") as dump:
            measured = db_refs_from_dump(dump)
    finally:
        _release(handler, parent, old)
    assert measured is None
    warnings = [r.getMessage() for r in handler.records
                if r.levelno >= logging.WARNING]
    assert any(decoy[0] in message and "wp_termmeta" in message
               for message in warnings), warnings


def test_a_role_nobody_contests_is_still_measured(tmp_path):
    """The A/B of the rule: absent is NOT contested.

    A site with no ``termmeta`` at all (WordPress before 4.4) is COMPLETELY
    measured, and a site whose plugin table merely ENDS in a role name
    (``wp_aioseo_posts``) is measured from the core tables.  Fail-closed
    must not become refuse-everything.
    """
    with open(_site_dump(tmp_path, "plain.sql", (AIOSEO_POSTS_SCHEMA,)),
              "rb") as dump:
        assert db_refs_from_dump(dump) == DB_REFS
    with open(_site_dump(tmp_path, "no-termmeta.sql",
                         tables=CORE_SCHEMA[:-1]),
              "rb") as dump:
        assert db_refs_from_dump(dump) == DB_REFS


# ------------------------------------------- a partial dump is not a site
#
# THE DEFECT: the identity owner treated a MISSING PREFIX ROLE as benign
# ("an ABSENT role ... a site that genuinely has no termmeta is completely
# measured").  That rationale is right for ``termmeta`` and wrong for
# ``postmeta``: WordPress has carried ``wp_postmeta`` since 3.0 and
# ``_wp_attached_file`` — the authoritative path of every attachment —
# lives there.  A dump that does not DECLARE it (a phpMyAdmin per-table
# export, ``mysqldump --ignore-table``, a transfer whose ``CREATE`` was cut
# mid-statement) is therefore not a site with no attachments: it is an
# export that could not answer the question, and the keep-set it produced
# was a POSITIVE ZERO.  Measured end to end on the fixture below: the audit
# reported the database-referenced photos plus the one real orphan —
# deletable files — with the ordinary local-mode caveat as the only
# disclosure.

#: The per-table export shape: everything a phpMyAdmin "quick dump" of two
#: tables produces — an options table and a posts table, no postmeta.
NO_POSTMETA = tuple(t for t in CORE_SCHEMA if t[0] != "wp_postmeta")

#: The same export with the ``CREATE`` of the postmeta table cut where a
#: truncated transfer cuts it: the statement never closes, so the parser
#: never sees a table at all.
CUT_POSTMETA = (
    b"CREATE TABLE `wp_postmeta` (`meta_id` bigint(20) unsigned NOT NULL "
    b"AUTO_INCREMENT, `post_id` bigint(20) unsigned NOT NULL DEFAULT '0', "
    b"`meta_key` varchar(255) DEFAULT NULL, `meta_value` longtext\n"
)


@pytest.mark.parametrize("shape", ["per-table", "cut-create"])
def test_a_dump_without_postmeta_is_unknown_not_a_zero_keep_set(
        tmp_path, shape):
    """The measured case: a POSITIVE 0 on a dump that references the full set.

    Both shapes that produce it are here, because they are the two ways a
    real export loses the table: it is simply not in the export, or its
    DDL was cut.  Either way the answer is UNKNOWN, and one warning names
    the role so the operator learns WHY nothing was measured.
    """
    if shape == "per-table":
        path = _site_dump(tmp_path, "partial-export.sql",
                          tables=NO_POSTMETA)
    else:
        path = _site_dump(tmp_path, "cut-create.sql")
        body = path.read_bytes().replace(
            b"CREATE TABLE `wp_postmeta` "
            b"(`meta_id` text, `post_id` text, `meta_key` text, "
            b"`meta_value` text);\n", CUT_POSTMETA)
        path.write_bytes(body)

    handler, parent, old = _wpt_records()
    try:
        with open(path, "rb") as dump:
            measured = db_refs_from_dump(dump)
    finally:
        _release(handler, parent, old)
    assert measured is None, (
        "a partial dump must measure NOTHING, never an empty keep-set: the "
        "files its missing table names are not proven unreferenced")
    warnings = [r.getMessage() for r in handler.records
                if r.levelno >= logging.WARNING]
    assert sum("postmeta" in message for message in warnings) == 1, warnings
    assert any("PARTIAL" in message for message in warnings), warnings

    # the CONTROL: the same site exported whole measures the full set — so the
    # refusal above is about the export, not about the site
    with open(_site_dump(tmp_path, f"control-{shape}.sql"), "rb") as dump:
        assert db_refs_from_dump(dump) == DB_REFS


def test_a_partial_dump_makes_the_media_audit_say_nothing(tmp_path):
    """``wpt audit --only media`` on the per-table export: the full set -> 0 candidates.

    The A/B is the whole point: the same tree, the same site, the same full set
    database-referenced photos.  Exported whole the audit reports the ONE
    real orphan; exported per table it reports NO candidate it could
    justify, and says that it measured nothing (never the full-set cost).
    """
    from wpt.audit.media import UNMEASURED_CATEGORY, check_media_unreferenced

    settings = load()
    source = FakeSource()
    for ref in DB_REFS:
        source.files[f"wp-content/uploads/{ref}"] = b"x" * 32
    source.files["wp-content/uploads/2023/10/orphan.jpg"] = b"x" * 32

    partial = _site_dump(tmp_path, "media-partial.sql", tables=NO_POSTMETA)
    with open(partial, "rb") as dump:
        data = gather_local(dump, source, settings)
    assert data.db_refs is None
    findings = check_media_unreferenced(data, settings)
    assert [f.category for f in findings] == [UNMEASURED_CATEGORY]
    assert findings[0].count == 0
    assert "wp_postmeta" in findings[0].fix   # what to export instead

    control = _site_dump(tmp_path, "media-whole.sql")
    with open(control, "rb") as dump:
        controlled = gather_local(dump, source, settings)
    assert controlled.db_refs == DB_REFS
    reported = check_media_unreferenced(controlled, settings)
    assert [f.count for f in reported] == [1]
    assert "2023/10/orphan.jpg" in reported[0].detail


def test_a_partial_dump_narrows_the_witness_and_the_analyzer_alike(tmp_path):
    """The two other consumers, and the boundary of the degradation.

    The WITNESS compares nothing: a table nobody read cannot vouch for a
    deletion.  The ANALYZER keeps measuring the site facts, because the
    options table is the one role a partial dump still PROVES and it is
    what carries the prefix — degrading facts the export really contains
    would be collateral, and fail-open besides (an unreadable
    ``active_plugins`` makes every plugin directory look unused to
    clean-files).
    """
    from wpt.localmode.analyzer import analyze
    from wpt.localmode.sql_dump import parse_dump
    from wpt.media_refs import dump_identity, dump_role_tables

    settings = load()
    path = _site_dump(tmp_path, "witness-partial.sql", tables=NO_POSTMETA)
    with open(path, "rb") as dump:
        identity = dump_identity(parse_dump(dump).tables)
    assert identity.roles == {}
    assert identity.unproven == ("postmeta",)
    assert not identity.known
    assert identity.unresolved == ("postmeta",)
    # the one fact a partial dump still proves
    assert identity.options_table.name == "wp_options"
    with open(path, "rb") as dump:
        assert dump_role_tables(parse_dump(dump).tables) == {}
    with open(path, "rb") as dump:
        model = analyze(dump, settings.db)
    assert model.table_prefix == "wp_"
    assert model.siteurl == "https://example.com"
    assert model.posts, "the posts facts the export DOES contain are measured"


def test_one_contested_role_is_warned_once_per_input_not_once_per_reader(
        tmp_path):
    """Finding 3: one resolution and one warning per input, per run.

    The owner used to warn from inside the query, and ``dump_identity`` was
    not memoized, so ONE dump in ONE local run logged the same sentence
    two to four times (the keep-set, the analyzer and the witness all ask
    the same question) — a run whose log looks like four separate problems
    where there is one.
    """
    from wpt.localmode.sql_dump import parse_dump
    from wpt.media_refs import dump_identity, resolve_role

    path = _site_dump(tmp_path, "warn-once.sql", (AIOSEO_OPTIONS_SCHEMA,))
    handler, parent, old = _wpt_records()
    try:
        with open(path, "rb") as dump:
            data = gather_local(dump, FakeSource(), load())
        assert data.db_refs is None
        # ... and the three consumers of one run ask the owner again
        with open(path, "rb") as dump:
            assert dump_identity(parse_dump(dump).tables).roles == {}
        schema = {name: stats.columns
                  for name, stats in parse_dump(open(path, "rb")).tables.items()}
        assert resolve_role("options", schema).ambiguous
    finally:
        _release(handler, parent, old)
    identity_lines = [r.getMessage() for r in handler.records
                      if "multiple options tables" in r.getMessage()]
    assert len(identity_lines) == 1, identity_lines
    assert "aioseo_options" in identity_lines[0] and "wp_options" in identity_lines[0]


def test_a_contested_identity_makes_the_media_audit_say_nothing(tmp_path):
    """``wpt audit --only media`` — the finding this identity used to cost.

    The measured run: with the keep-set resolved to the PLUGIN's options
    table the audit reported unreferenced, deletable photos that
    ``wp_postmeta`` names, and ``trim-media`` planned every one of them.
    Only the live-walk half of the cross-mode gate stood between that plan
    and the filesystem.  An UNKNOWN keep-set must make the check enumerate
    NOTHING it cannot justify (no measurement = no candidates) and must SAY
    SO — one marker finding, never silence a reader of a persisted report
    can mistake for a clean site.  The A/B proves the answer really was the
    identity, not the dump shape.
    """
    from wpt.audit.media import (
        UNMEASURED_CATEGORY,
        check_media_unreferenced,
    )

    settings = load()
    source = FakeSource()
    for ref in DB_REFS:
        source.files[f"wp-content/uploads/{ref}"] = b"x" * 32
    # one genuinely unreferenced file, so the control has something real to
    # report and every extra finding is a false positive
    source.files["wp-content/uploads/2023/10/orphan.jpg"] = b"x" * 32

    decoy = _site_dump(tmp_path, "audit-decoy.sql", (AIOSEO_OPTIONS_SCHEMA,))
    with open(decoy, "rb") as dump:
        data = gather_local(dump, source, settings)
    assert data.db_refs is None            # the measurement is UNKNOWN
    # ... so the check enumerates NOTHING: with no measurement there is no
    # candidate it could justify (before the fix this was a large finding set — the
    # the referenced photos plus the orphan — with an un-degraded evidence
    # class, i.e. a confident "the database references none of these")
    findings = check_media_unreferenced(data, settings)
    assert [f.category for f in findings] == [UNMEASURED_CATEGORY]
    assert [f.count for f in findings] == [0]        # nothing was measured
    assert "DEGRADED" in findings[0].detail

    # the A/B: the same dump without the decoy measures every reference, so
    # the ONE real orphan is reported — and nothing else
    control = _site_dump(tmp_path, "audit-control.sql")
    with open(control, "rb") as dump:
        controlled = gather_local(dump, source, settings)
    assert controlled.db_refs == DB_REFS
    findings = check_media_unreferenced(controlled, settings)
    assert [f.count for f in findings] == [1]
    assert "2023/10/orphan.jpg" in findings[0].detail
    assert "DEGRADED" in findings[0].fix      # local mode: no live walk


def test_the_three_table_identity_consumers_agree(tmp_path):
    """AGREEMENT, not merely "each is non-None".

    The three readers of the same question — the keep-set measurement, the
    analyzer (which feeds every site fact) and the witness (which decides
    whether a dump may certify a deletion) — must name the SAME table, or
    be UNKNOWN together.  Before the fix the first named ``aioseo_options``
    and the second ``wp_options`` in the same run.

    The analyzer's own scope is the PREFIX-defining role and nothing else:
    it reads the options table, then locates every other table by the
    prefix that table's name carries.  So a dump whose options identity is
    unknown leaves it with no facts at all, while a dump that is merely
    PARTIAL (no ``postmeta``) or that contests a role the analyzer never
    reads (``termmeta``) still gives it a proved options table — and a
    measurement that is degraded for a fact the analyzer does not read must
    not take the analyzer's facts with it.  Both halves are pinned here,
    because the second is exactly where a cascade stops being honesty and
    starts being collateral.
    """
    from wpt.localmode.analyzer import analyze
    from wpt.localmode.sql_dump import parse_dump
    from wpt.media_refs import dump_identity, dump_role_tables, options_prefix

    settings = load()
    cases = (
        # name, decoy tables, the options role, the ANALYZER's prefix, and
        # whether the REFERENCE SET is measurable in that dump
        ("agree-core", (), "wp_options", "wp_", True),
        ("agree-aioseo", (AIOSEO_OPTIONS_SCHEMA,), None, None, False),
        ("agree-wp-aioseo", (WP_AIOSEO_OPTIONS_SCHEMA,), None, None, False),
        ("agree-edd-term", (EDD_TERMMETA_SCHEMA,), "wp_options", "wp_", False),
        ("agree-aioseo-posts", (AIOSEO_POSTS_SCHEMA,), "wp_options", "wp_", True),
    )
    for name, decoys, options_table, prefix, measurable in cases:
        path = _site_dump(tmp_path, f"{name}.sql", decoys)
        # (1) what the MEASUREMENT reads, from its own parse of the bytes
        with open(path, "rb") as dump:
            measured = db_refs_from_dump(dump)
        with open(path, "rb") as dump:
            measurement_identity = dump_identity(parse_dump(dump).tables)
        # (2) what the ANALYZER resolves from the same dump
        with open(path, "rb") as dump:
            model = analyze(dump, settings.db)
        # (3) what the WITNESS validates the currency of
        witness_roles = dump_role_tables(model.tables)

        if not measurable:
            # half a measurement is no measurement: the reference set is
            # UNKNOWN and the witness has no table it may compare
            assert measured is None, name
            assert witness_roles == {}, name
        if options_table is None:
            # the options role is unknown => the PREFIX is unknown => the
            # analyzer has no facts at all
            assert model.table_prefix is None, name
            assert measurement_identity.contested, name
            continue
        # the same TABLE, and where the measurement ran, it really read it:
        # the references live in wp_postmeta, so a reader of any other
        # table could not have found them
        if measurable:
            assert measured == DB_REFS, name
            assert witness_roles["postmeta"].name == "wp_postmeta", name
            assert witness_roles == measurement_identity.roles, name
        assert model.table_prefix == options_prefix(options_table) == prefix, name
        assert measurement_identity.options_table.name == options_table, name
        assert witness_roles == {} or witness_roles["options"].name == options_table, name


def test_a_contested_role_narrows_the_witness_to_no_table_at_all(tmp_path):
    """Requirement: a contested identity must make the currency check
    compare NOTHING, never a table the measurement did not read.

    Before the fix ``dump_role_tables`` handed the witness a table (the
    first by name) and the check happily compared row counts against a
    table the reference set was never read from — the L-class defect this
    module already fixed for the PREFIX roles, re-entering through the
    suffix ones.
    """
    from wpt.localmode.sql_dump import parse_dump
    from wpt.media_refs import dump_identity

    with open(_site_dump(tmp_path, "contested.sql", (AIOSEO_OPTIONS_SCHEMA,)),
              "rb") as dump:
        identity = dump_identity(parse_dump(dump).tables)
    assert identity.roles == {}
    assert identity.contested == ("options",)
    assert not identity.known


def test_the_table_identity_rule_has_exactly_one_owner():
    """STRUCTURAL GUARD: the defect is a SECOND rule, so the guard is on
    where the rule may LIVE, not on any function's name.

    A guard listing identifiers no module may mention is defeatable by
    renaming, so this one is built from what a reappearing rule would
    physically need — and it is built on USE, not on the presence of an
    import:

    * RECOGNISING the options table means comparing a table's columns to
      the ``option_name`` + ``option_value`` pair, so a module may only
      name BOTH of those in executable code if it ASKS the owner for the
      rule (:func:`~wpt.media_refs.resolve_role`).  Renaming the owner's
      API, moving the check, or inlining the comparison all fail here.
      (Docstrings are excluded — they explain the rule, they are not the
      rule — and ``images_webp`` is no counterexample: its surface table
      asks for ``option_value`` ALONE, a DIFFERENT fact: which tables a
      conversion may rewrite, gated per candidate, never an answer to
      "which table is this site's ``$wpdb->options``".  Its one
      ``option_name`` reference is the same story.  The exemption list is
      the OWNER, which is where the private ``_COLUMNS`` signature table
      lives — not "anything that imported something".)
    * every consumer USES the SPECIFIC owner symbols its role needs, by
      AST: the analyzer, clean-db, the witness, and the three mutating
      actions whose plan item names a table (they used to take
      ``sorted(suffix-matches)[0]`` over the whole ``information_schema``
      base-table set, which on an AIOSEO site named ``aioseo_options``).

    Three evasions the previous version of this guard DID admit, now
    closed: an ALIASED import of the owner (``import media_refs as m``)
    used to satisfy the pair arm on its own; ``from .. import media_refs
    as m`` and ``importlib.import_module`` + ``getattr`` were invisible to
    it entirely; and a run-time-built literal (``"option_" + "name"``)
    walked straight past the literal test, because only whole constants
    were collected.  What still survives is named at the end of this
    docstring rather than pretended away.
    """
    import ast
    from pathlib import Path

    repo = Path(__file__).resolve().parents[1]
    wpt_root = repo / "wpt"
    owner_module = "media_refs.py"
    # the owner symbols each consumer's ROLE needs — a module that imports
    # the owner for something else does not satisfy its own guard
    consumers = {
        "localmode/analyzer.py": {"dump_identity", "options_prefix"},
        "actions/clean_db.py": {"resolve_role", "options_prefix"},
        "actions/dump_witness.py": {"dump_role_tables"},
        "actions/deactivate.py": {"resolve_role_by_name"},
        "actions/reconcile_plugins.py": {"resolve_role_by_name"},
        # both user-writing actions ask through this shared owner (the
        # plan item's table + the fail-closed snapshot scope), so the
        # identity USE lives here now — one consumer for two actions.
        "users.py": {"resolve_role_by_name"},
    }
    # the consumers with no honest ``getattr`` to lose: a dynamic reach in
    # one of these can only be an attempt to see past this guard (the other
    # two read settings/dataclass fields through it, which is unrelated to
    # the identity and therefore not this arm's business).
    #: the owner's identity API — the ONLY way a module may reach the
    #: answer to "which table is this role".
    IDENTITY_ENTRY_POINTS = frozenset({
        "dump_identity", "resolve_role", "resolve_role_by_name",
        "dump_role_tables", "options_prefix",
    })
    dynamic_ban = {
        "localmode/analyzer.py",
        "actions/deactivate.py",
        "actions/reconcile_plugins.py",
        "users.py",
    }

    def _docstrings(tree):
        return {id(node.body[0].value)
                for node in ast.walk(tree)
                if isinstance(node, (ast.Module, ast.ClassDef,
                                     ast.FunctionDef, ast.AsyncFunctionDef))
                and node.body and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)}

    def _literals(tree, docs):
        """Every string the module can BUILD, whole or concatenated.

        Constant folding happens at compile time, not here, so
        ``"option_" + "name"`` arrives as a BinOp of two constants; the
        pair test used to see neither half and wave the module through.
        """
        found: set[str] = set()
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and id(node) not in docs):
                found.add(node.value)
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                # ast.literal_eval refuses a Constant + Constant (it only
                # folds numbers), so the fold is spelled out: python's own
                # compiler does exactly this for adjacent literals, and a
                # rule assembled at run time from string pieces must be
                # visible to the pair test just as a literal one is.
                if (isinstance(node.left, ast.Constant)
                        and isinstance(node.right, ast.Constant)
                        and isinstance(node.left.value, str)
                        and isinstance(node.right.value, str)):
                    found.add(node.left.value + node.right.value)
        return found

    def _owner_use(tree):
        """The owner symbols this module actually USES (not merely imports).

        A direct ``from ..media_refs import resolve_role`` is satisfied by
        the bare name being loaded; ``import wpt.media_refs as m`` is
        satisfied only by ``m.resolve_role`` — an import that is never
        used satisfies nothing, and ``from .. import media_refs as m``
        (which names no owner symbol at all) does not count either, which
        is the point: the module has to reach the rule through the owner's
        own API.
        """
        direct: set[str] = set()
        modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module \
                    and node.module.endswith("media_refs"):
                direct.update(alias.asname or alias.name for alias in node.names)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.endswith("media_refs"):
                        modules.add(alias.asname or alias.name)
        used: set[str] = set()
        for node in ast.walk(tree):
            if (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
                    and node.id in direct):
                used.add(node.id)
            elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                if node.value.id in direct | modules:
                    used.add(node.attr)
        return used

    def _dynamic_reach(tree):
        """The dynamic-reach spellings a table-identity consumer may not use.

        Scoped to the CONSUMERS, not to the package: ``clean_db`` and
        ``dump_witness`` both have honest ``getattr`` uses (a settings
        field, a dataclass field), and a blanket ban would flag those while
        saying nothing about the identity.  The three mutating actions
        reach the wire and the plan and have no such use, so a dynamic
        reach there can only be an attempt to see past this guard.
        """
        banned: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                banned.update(alias.name.split(".")[0] for alias in node.names
                              if alias.name.split(".")[0] == "importlib")
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.lstrip(".").split(".")[0] == "importlib":
                    banned.add("importlib")
            elif (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
                    and node.id in ("getattr", "__import__", "eval", "exec")):
                banned.add(node.id)
        return banned

    for module in dynamic_ban:
        tree = ast.parse((wpt_root / module).read_text(encoding="utf-8"))
        assert not _dynamic_reach(tree), (
            f"{module} reaches an attribute dynamically (getattr/importlib/"
            f"eval): the table identity must be reached through "
            f"wpt.media_refs' own API, where the USE can be seen")

    asked: set[str] = set()
    for path in sorted(wpt_root.rglob("*.py")):
        if path.name == owner_module:
            continue          # the owner holds _COLUMNS; it need not ask
        tree = ast.parse(path.read_text(encoding="utf-8"))
        docs = _docstrings(tree)
        used = _owner_use(tree)
        if {"option_name", "option_value"} <= _literals(tree, docs):
            # reading a ROW out of the options table needs both column names
            # and is not a second identity rule; DECIDING which table the
            # role is would be.  The difference is whether the module asks
            # the owner for the identity, through any of its entry points —
            # and which entry point is required of it is pinned per role
            # below, so "I imported something" is not enough.
            assert used & IDENTITY_ENTRY_POINTS, (
                f"{path.relative_to(repo)} names the option_name/"
                f"option_value pair without ASKING wpt.media_refs which "
                f"table the options role is: the identity must have ONE "
                f"owner, or the keep-set and the site facts name different "
                f"tables in one run")
            asked.add(str(path.relative_to(wpt_root)))

    # the owner itself does own the pair, and every consumer ASKS it for
    # the symbols its role needs
    assert (wpt_root / owner_module).exists()
    assert "option_name" in (wpt_root / owner_module).read_text(encoding="utf-8")
    for module, needed in consumers.items():
        tree = ast.parse((wpt_root / module).read_text(encoding="utf-8"))
        assert needed <= _owner_use(tree), (
            f"{module} must USE {sorted(needed)} from wpt.media_refs to ask "
            f"it for the table identity; a rule of its own (or an unused "
            f"import) is how a plan named aioseo_options and the analyzer "
            f"named wp_options in one run")
    assert asked, ("the pair arm is vacuous — no module names the options "
                   "column pair any more, so this guard proves nothing")


def test_the_identity_owner_resolves_a_name_only_source_fail_closed():
    """The wire's half of the rule: NAMES, no columns, one answer.

    ``db_audit`` reports ``information_schema`` with names and no column
    list, so a table's name is not a schema and two names that could be the
    role are already UNKNOWN.  This is the rule the three mutating actions'
    plan targets go through (their test lives with each action); here it is
    pinned as a unit, including the direction that must not regress: a
    single candidate is used, and never a guessed prefix.
    """
    from wpt.media_refs import resolve_role_by_name

    schema = ("wp_commentmeta", "wp_options", "wp_postmeta", "wp_posts",
              "wp_termmeta", "wp_users", "wp_usermeta")
    handler, parent, old = _wpt_records()
    try:
        alone = resolve_role_by_name("options", schema)
        contested = resolve_role_by_name(
            "options", schema + ("aioseo_options",))
        empty = resolve_role_by_name("options", ())
    finally:
        _release(handler, parent, old)
    assert alone.name == "wp_options" and not alone.ambiguous
    assert contested.name is None and contested.ambiguous
    assert contested.candidates == ("aioseo_options", "wp_options")
    assert empty.candidates == () and not empty.ambiguous
    # ONE warning for the contested input, however many times it is asked
    assert sum("multiple options tables" in r.getMessage()
               for r in handler.records) == 1
    # ... and a DIFFERENT input resolves again (the generation cache never
    # turns into "the first answer sticks for the process")
    assert resolve_role_by_name("options", ("wp_2_options",)).name == "wp_2_options"


def test_gather_local_measures_db_refs():
    # the local gate is the dump, so the gatherer measures the database
    # half here (the dump handle is closed when it returns)
    dump = _dump(
        postmeta=[(1, 10, "_wp_attached_file", "2023/10/pic.jpg")],
        options=[(1, "siteurl", "https://site.test")],
    )
    source = FakeSource()
    source.files["wp-content/uploads/2023/10/pic.jpg"] = b"x" * 10
    data = gather_local(io.BytesIO(dump), source, load())
    assert data.mode == "local"
    assert data.db_refs == {"2023/10/pic.jpg"}
    assert data.live_refs is None  # no walk offline: the set is DEGRADED


# ------------------------------------------------------------------ bridge


class _FakeBridge:
    """A Bridge double recording db_media_refs() calls AND their families."""

    def __init__(self, *answers):
        self._answers = list(answers)
        self.calls = 0
        self.families: list[Any] = []

    def db_media_refs(self, extensions=None):
        self.calls += 1
        self.families.append(extensions)
        answer = self._answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return set(answer)


class _FakeProbe:
    def __init__(self, bridge):
        self.bridge = bridge


class _FakeData:
    def __init__(self, mode, bridge=None, db_refs=None):
        self.mode = mode
        self.probe = _FakeProbe(bridge) if bridge is not None else None
        self.db_refs = db_refs


def test_db_refs_for_data_memoizes_one_bridge_call():
    bridge = _FakeBridge(["2023/10/pic.jpg"], ["2023/10/other.jpg"])
    data = _FakeData("ftp", bridge=bridge)
    widened = list(REF_EXTENSIONS) + ["psd"]
    assert db_refs_for_data(data, widened) == {"2023/10/pic.jpg"}
    # memoized on the data object: a second consumer pays nothing
    assert db_refs_for_data(data, widened) == {"2023/10/pic.jpg"}
    assert bridge.calls == 1
    # ... and the run's OWN family reached the read: the check enumerates
    # with it, so a gate answering from a different list is the D1 defect
    assert bridge.families == [widened]


def test_db_refs_for_data_bridge_failure_degrades():
    handler, parent, old = _wpt_records()
    try:
        data = _FakeData("ftp", bridge=_FakeBridge(OSError("bridge down")))
        assert db_refs_for_data(data) is None
    finally:
        _release(handler, parent, old)
    warnings = [r for r in handler.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "database media map unavailable" in warnings[0].getMessage()


def test_db_refs_for_data_never_turns_a_stop_into_an_unknown():
    """C1: the broad degrade answered None for a SIGTERM, so the audit kept
    going instead of ending.  RunControl is not an operational bridge fault."""
    from wpt.types import StopRequested

    with pytest.raises(StopRequested):
        db_refs_for_data(_FakeData(
            "ftp", bridge=_FakeBridge(StopRequested("received SIGTERM (15)"))))


def test_db_refs_for_data_local_reads_the_field():
    # local mode reads the gathered set and never reaches for a bridge
    assert db_refs_for_data(_FakeData("local", db_refs={"a.jpg"})) == {"a.jpg"}
    assert db_refs_for_data(_FakeData("local")) is None
    assert db_refs_for_data(_FakeData("ftp")) is None  # no probe, no bridge


def test_db_refs_from_dump_settings_free():
    # the map needs no tunable: the same dump yields the same set whatever
    # the profile says (there is nothing to configure about a file path)
    dump = _dump(postmeta=[(1, 10, "_wp_attached_file", "2023/10/pic.jpg")])
    assert db_refs_from_dump(io.BytesIO(dump)) == db_refs_from_dump(
        io.BytesIO(dump))
    assert DbSettings()  # the analyzer's settings are the only Db knob


# ===========================================================================
# THE DIFFERENTIAL TEST — one fixture, both implementations
#
# The defect this file's second half exists for: the database half of the
# keep-set is measured in one of two places (the .sql dump here, the
# bridge's wpt_media_db_map there), and a destructive plan is built from
# ONE of them.  A regression sweep measured the two disagreeing on a real
# site — the local dump kept a multi-size "2019/02/SampleImg*" family as
# database-referenced while the live bridge kept NONE of them — so the
# same database produced two different DELETE sets and the mode decided
# whether a referenced attachment survived.
#
# The oracle below is bridge.php's OWN wpt_media_db_map, lifted out of the
# deployed file by brace-matched extraction and run over the same rows
# through a $wpdb stub, so the reference is the shipped PHP and not a
# re-implementation of it.  Thirteen stored-value shapes disagreed before
# the fix; every one of them is a row in FIXTURES below, each with the
# expected set pinned as a LITERAL as well, so a change both sides make
# together still has to survive a human's reading.
# ===========================================================================

#: The bridge functions the database media map is built from, in
#: dependency order.  Anything wpt_media_db_map calls and the stub does not
#: provide is a loud fatal, not a silent empty answer.
_PHP_FUNCTIONS = (
    "wpt_media_ref_delims",
    "wpt_media_ref_trailing_punct",
    "wpt_media_refs_in_text",
    "wpt_media_attached_ref",
    "wpt_media_meta_names",
    "wpt_media_meta_refs",
    "wpt_media_ref_extensions",
    "wpt_media_ref_normalize",
    "wpt_media_ref_is_kept",
    "wpt_media_ref_add",
    "wpt_media_db_map",
)

#: A $wpdb that answers the six read-only SELECTs wpt_media_db_map runs.
#: It understands exactly the WHERE shapes those queries use and THROWS on
#: anything else, so a changed query in bridge.php fails this harness
#: loudly instead of quietly returning the wrong rows.
_PHP_STUB = r"""
if ( ! defined( 'ARRAY_A' ) ) { define( 'ARRAY_A', 'ARRAY_A' ); }

class WPT_Media_Ref_wpdb {
	public $posts = 'wp_posts';
	public $postmeta = 'wp_postmeta';
	public $options = 'wp_options';
	public $termmeta = 'wp_termmeta';
	private $tables;

	public function __construct( array $tables ) {
		$this->tables = $tables;
	}

	public function get_results( $sql, $output = OBJECT ) {
		$rows = $this->select( $sql );
		if ( ARRAY_A === $output ) {
			return $rows;
		}
		return array_map( function ( $r ) { return (object) $r; }, $rows );
	}

	private function select( $sql ) {
		if ( ! preg_match( '/FROM\s+(\S+)/i', $sql, $m ) ) {
			throw new RuntimeException( 'unparsed table: ' . $sql );
		}
		$table = trim( $m[1], '`' );
		if ( ! isset( $this->tables[ $table ] ) ) {
			throw new RuntimeException( 'unknown table: ' . $table );
		}
		$select = trim( substr( $sql, strlen( 'SELECT' ), strpos( $sql, 'FROM' ) - 6 ) );
		$cols   = array_map( 'trim', explode( ',', $select ) );
		$where  = preg_match( '/WHERE\s+(.*)$/is', $sql, $w ) ? trim( $w[1] ) : '';
		$out    = array();
		foreach ( $this->tables[ $table ] as $row ) {
			if ( '' === $where ) {
				// every row
			} elseif ( preg_match( "/^meta_key\s*=\s*'([^']*)'$/", $where, $c ) ) {
				if ( ! isset( $row['meta_key'] ) || $row['meta_key'] !== $c[1] ) {
					continue;
				}
			} elseif ( preg_match( "/^meta_key\s+IN\s+\((.*)\)$/i", $where, $c ) ) {
				$keys = array_map(
					function ( $k ) { return trim( $k, " '" ); },
					explode( ',', $c[1] )
				);
				if ( ! isset( $row['meta_key'] ) || ! in_array( $row['meta_key'], $keys, true ) ) {
					continue;
				}
			} elseif ( preg_match(
				"/^(meta_value|option_value)\s+LIKE\s+'%(.+)%'$/i", $where, $c
			) ) {
				if ( ! isset( $row[ $c[1] ] )
					|| false === strpos( (string) $row[ $c[1] ], $c[2] ) ) {
					continue;
				}
			} else {
				throw new RuntimeException( 'unparsed WHERE: ' . $where );
			}
			$pick = array();
			foreach ( $cols as $col ) {
				$pick[ $col ] = isset( $row[ $col ] ) ? $row[ $col ] : null;
			}
			$out[] = $pick;
		}
		return $out;
	}
}
"""


def _php_function(name: str, source: str) -> str:
    """One function out of bridge.php, braces matched (never a copy)."""
    start = source.index("function %s(" % name)
    at = source.index("{", start)
    depth = 0
    for pos in range(at, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[start:pos + 1]
    raise AssertionError("unbalanced braces in " + name)


@contextlib.contextmanager
def _php_run(script: str, values: list[str]):
    """Run a PHP script over ``values`` (one json file argument) -> its list.

    The pure-function oracle behind the both-ways pins: the function is lifted
    out of the DEPLOYED file by name, PHP itself answers for the corpus, and
    the values are passed as JSON rather than embedded, so a NUL byte or a
    quote in a fixture is data the language handles the way the bridge
    handles it — never a re-implementation of PHP's own escaping in Python.
    The corpus travels through a temp file rather than argv/stdin because the
    values may contain NUL, which neither a shell argument nor a pipe
    survives intact.
    """
    if shutil.which("php") is None:
        pytest.fail("php CLI not found on PATH (the bridge oracle is the "
                    "reference these tests measure against)")
    with tempfile.TemporaryDirectory() as work:
        script_path = Path(work) / "oracle.php"
        script_path.write_text(script, encoding="utf-8")
        values_path = Path(work) / "values.json"
        values_path.write_text(json.dumps(values), encoding="utf-8")
        proc = subprocess.run(["php", str(script_path), str(values_path)],
                              capture_output=True, text=True)
    assert proc.returncode == 0, "the bridge oracle did not answer: " + proc.stderr
    yield json.loads(proc.stdout)


def _php_harness_script() -> str:
    """The oracle script: bridge.php's own functions + the $wpdb stub."""
    source = BRIDGE_SOURCE.read_text(encoding="utf-8")
    body = "\n\n".join(_php_function(name, source)
                       for name in _PHP_FUNCTIONS)
    # the structural constant the family validation reads, lifted from the
    # deployed file (never a copy, like every function above)
    bound = re.search(r"define\( 'WPT_MEDIA_REF_EXT_MAX'.*", source)
    assert bound, "bridge.php no longer bounds a requested extension family"
    return (
        "<?php\n"
        "error_reporting(E_ALL);\n"
        "ini_set('display_errors', '1');\n"
        + bound.group(0) + "\n"
        + body + "\n" + _PHP_STUB + """
$tables = json_decode(file_get_contents($argv[1]), true);
$GLOBALS['wpdb'] = new WPT_Media_Ref_wpdb($tables);
// $argv[3] is the caller's extension family, exactly as media_map mode=db
// receives it: absent = the request carries none, a JSON array = the
// requested family (an unusable one is refused by the bridge ITSELF, which
// is what a hand-written request can send).
$requested = (isset($argv[3]) && '' !== $argv[3])
    ? json_decode($argv[3]) : null;
try {
    if (isset($argv[4]) && '' !== $argv[4]) {
        // the ACTION's own resolution: the family the op answers with
        // (wpt_media_ref_extensions = default UNION request) plus the two
        // keys it reports about it.
        $refused = false;
        $family  = wpt_media_ref_extensions($requested, $refused);
        $answer  = wpt_media_db_map($argv[2], $family);
        $answer['db_refs_gate'] = count($family);
        if ($refused) {
            $answer['db_refs_gate_fallback'] = true;
        }
    } else {
        $answer = wpt_media_db_map($argv[2]);
    }
    echo json_encode($answer, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES), "\\n";
} catch (Throwable $e) {
    fwrite(STDERR, get_class($e) . ': ' . $e->getMessage() . "\\n");
    exit(3);
}
"""
    )


def _php_db_map(tmp_path: Path, tables: dict, basedir: str = "",
                extensions: Any = None, wire: bool = False) -> dict:
    """bridge.php's real wpt_media_db_map over ``tables`` -> its answer.

    ``extensions`` is the caller's media family, passed exactly as
    ``media_map`` ``mode=db`` receives it (``None`` = the request carries
    none).  ``wire=True`` runs the ACTION's own resolution — the family the
    op answers with (the mirrored default UNION the request) and the
    ``db_refs_gate`` / ``db_refs_gate_fallback`` it reports — instead of
    handing a family straight to the map, so a test measures the shipped
    REQUEST handling and not only the gate.
    """
    if shutil.which("php") is None:
        pytest.fail("php CLI not found on PATH (the bridge oracle is the "
                    "reference these tests measure against)")
    script = tmp_path / "wpt-media-ref-oracle.php"
    script.write_text(_php_harness_script(), encoding="utf-8")
    rows = tmp_path / "wpt-media-ref-rows.json"
    rows.write_text(json.dumps(tables), encoding="utf-8")
    proc = subprocess.run(
        ["php", str(script), str(rows), basedir,
         "" if extensions is None else json.dumps(extensions),
         "wire" if wire else ""],
        capture_output=True, text=True)
    assert proc.returncode == 0, (
        "bridge.php's wpt_media_db_map did not answer: " + proc.stderr)
    return json.loads(proc.stdout)


# --------------------------------------------------------------- the fixture
#
# ONE owner for the fixture: every case below declares the database ROWS
# (the source of truth) and the expected uploads-relative set (a pinned
# literal).  The dump and the bridge oracle are both run over the same rows
# and both must equal the literal.

class _Raw(str):
    """A literal PHP serialization tag, embedded in a serialized value."""


def php_ser(value) -> str:
    """A python value serialized exactly as PHP would write it."""
    if isinstance(value, _Raw):
        return str(value)
    if isinstance(value, str):
        return _ser(value)
    if value is None:
        return "N;"
    if isinstance(value, dict):
        return "a:%d:{%s}" % (
            len(value),
            "".join((php_ser(k) if isinstance(k, str) else "i:%d;" % k)
                    + php_ser(v) for k, v in value.items()))
    if isinstance(value, list):
        return "a:%d:{%s}" % (
            len(value),
            "".join("i:%d;%s" % (i, php_ser(v)) for i, v in enumerate(value)))
    raise TypeError(repr(value))


def meta_value(file=None, sizes=(), extra=()):
    """core's real attachment-metadata value: `file` + a `sizes` map whose
    entries store the size file as a BARE BASENAME (the shape the sweep
    measured), plus any extra key a test needs."""
    out: dict = {}
    if file is not None:
        out["file"] = file
    out["sizes"] = {name: {"file": value, "width": "150", "height": "150"}
                    for name, value in sizes}
    for key, value in extra:
        out[key] = value
    return php_ser(out)


ORIGINAL = "2019/02/SampleImg.jpg"
THUMB = "SampleImg-150x150.jpg"


def _nested(levels: int) -> str:
    """``levels`` nested arrays around an integer, as PHP writes them."""
    inner = "i:1;"
    for _ in range(levels):
        inner = "a:1:{i:0;%s}" % inner
    return inner


#: 200 levels: the depth a builder-shaped metadata value reaches, and far
#: past the 64 a decoder used to stop at (PHP 8.4 reads 4096).
_NESTED_200 = _nested(200)

#: name -> (postmeta, posts, options, termmeta, on-disk dirs, expected set).
#: ``on-disk dirs`` is the is-a-directory witness the walk supplies offline
#: (the bridge reads the filesystem itself).
FIXTURES: dict[str, tuple] = {
    # --- 1. _wp_attached_file, the shape every site stores -------------
    "attached-relative": (
        [(1, 10, "_wp_attached_file", ORIGINAL)], [], [], [], set(),
        {ORIGINAL},
    ),
    "attached-marker-url": (
        [(1, 10, "_wp_attached_file",
          "https://site.test/wp-content/uploads/" + ORIGINAL)], [], [], [],
        set(), {ORIGINAL},
    ),
    # a site migrated from ANOTHER host: the tail after the marker is the
    # host-independent reference
    "attached-old-host-absolute-path": (
        [(1, 10, "_wp_attached_file",
          "/home/olduser/public_html/wp-content/uploads/" + ORIGINAL)],
        [], [], [], set(), {ORIGINAL},
    ),
    # NUL bytes and backslashes: both fold, or the keep-set holds a path
    # that can never match a real file
    "attached-backslashes": (
        [(1, 10, "_wp_attached_file", "2019\\02\\SampleImg.jpg")], [], [],
        [], set(), {ORIGINAL},
    ),
    "attached-trailing-nul-byte": (
        [(1, 10, "_wp_attached_file", ORIGINAL + "\0")], [], [], [], set(),
        {ORIGINAL},
    ),
    "attached-surrounding-spaces": (
        [(1, 10, "_wp_attached_file", "  2019/02/with space.jpg ")], [], [],
        [], set(), {"2019/02/with space.jpg"},
    ),
    # refused by both sides
    "attached-empty-segment": (
        [(1, 10, "_wp_attached_file", "2019//02/SampleImg.jpg")], [], [], [],
        set(), set(),
    ),
    "attached-traversal": (
        [(1, 10, "_wp_attached_file", "2019/02/../../../etc/x.jpg")], [], [],
        [], set(), set(),
    ),
    "attached-two-paths-in-one-value": (
        [(1, 10, "_wp_attached_file",
          "wp-content/uploads/2023/10/b.jpg wp-content/uploads/2023/10/a.jpg")],
        [], [], [], set(), {"2023/10/a.jpg", "2023/10/b.jpg"},
    ),
    # --- 2. the keep-gate: no media extension, or a directory ---------
    "gate-unlisted-extension": (
        [(1, 10, "_wp_attached_file", "2019/02/data.xyz")], [], [], [], set(),
        set(),
    ),
    "gate-bare-year-directory": (
        [(1, 10, "_wp_attached_file", "2018")], [], [], [], set(), set(),
    ),
    "gate-dotfile": (
        [(1, 10, "_wp_attached_file", "2019/02/.htaccess")], [], [], [], set(),
        set(),
    ),
    "gate-directory-named-like-a-media-file": (
        [(1, 10, "_wp_attached_file", "2024/05/thumbs.jpg")], [], [], [],
        {"2024/05/thumbs.jpg"}, set(),
    ),
    "gate-directory-named-like-a-size": (
        [(1, 10, "_wp_attached_file", ORIGINAL),
         (2, 10, "_wp_attachment_metadata",
          meta_value(ORIGINAL, [("cached", "thumbs.jpg")]))],
        [], [], [], {"2019/02/thumbs.jpg"}, {ORIGINAL},
    ),
    "gate-uppercase-extension-is-media": (
        [(1, 10, "_wp_attached_file", "2019/02/x.JPG")], [], [], [], set(),
        {"2019/02/x.JPG"},
    ),
    # --- 3. attachment metadata: every stored form -------------------
    "meta-bare-size-basename": (
        [(1, 10, "_wp_attached_file", ORIGINAL),
         (2, 10, "_wp_attachment_metadata",
          meta_value(ORIGINAL, [("thumbnail", THUMB)]))],
        [], [], [], set(), {ORIGINAL, "2019/02/" + THUMB},
    ),
    # post_id order is arbitrary: a metadata row read BEFORE its anchor
    # still lands in the attachment's own directory
    "meta-row-before-its-anchor": (
        [(1, 10, "_wp_attachment_metadata",
          meta_value(ORIGINAL, [("thumbnail", THUMB)])),
         (2, 10, "_wp_attached_file", ORIGINAL)],
        [], [], [], set(), {ORIGINAL, "2019/02/" + THUMB},
    ),
    "meta-no-anchor-at-all": (
        [(1, 10, "_wp_attachment_metadata",
          meta_value(ORIGINAL, [("thumbnail", THUMB)]))],
        [], [], [], set(), {ORIGINAL, THUMB},
    ),
    "meta-legacy-backup-sizes-key": (
        [(1, 10, "_wp_attached_file", ORIGINAL),
         (2, 10, "_wp_attachment_backup_sizes",
          meta_value(None, [("full", "SampleImg-1920x1080.jpg")]))],
        [], [], [], set(), {ORIGINAL, "2019/02/SampleImg-1920x1080.jpg"},
    ),
    "meta-json-stored-map": (
        [(1, 10, "_wp_attached_file", ORIGINAL),
         (2, 10, "_wp_attachment_metadata",
          '{"file": "%s", "sizes": {"thumbnail": {"file": "%s"}}}'
          % (ORIGINAL, THUMB))],
        [], [], [], set(), {ORIGINAL, "2019/02/" + THUMB},
    ),
    "meta-full-path-size-entries": (
        [(1, 10, "_wp_attached_file", ORIGINAL),
         (2, 10, "_wp_attachment_metadata", meta_value(ORIGINAL, [
             ("odd", "2019/02/SampleImg-odd.jpg"),
             ("leading-slash", "/2019/02/SampleImg-wide.jpg")]))],
        [], [], [], set(),
        {ORIGINAL, "2019/02/SampleImg-odd.jpg", "2019/02/SampleImg-wide.jpg"},
    ),
    "meta-sizes-as-a-list": (
        [(1, 10, "_wp_attached_file", ORIGINAL),
         (2, 10, "_wp_attachment_metadata", php_ser(
             {"file": ORIGINAL, "sizes": [{"file": THUMB}]}))],
        [], [], [], set(), {ORIGINAL, "2019/02/" + THUMB},
    ),
    "meta-numeric-string-size-key-is-cast": (
        [(1, 10, "_wp_attached_file", ORIGINAL),
         (2, 10, "_wp_attachment_metadata", php_ser(
             {"file": ORIGINAL, "sizes": {"0": {"file": THUMB}}}))],
        [], [], [], set(), {ORIGINAL, "2019/02/" + THUMB},
    ),
    # --- 4. PHP's unserialize semantics, on a size map ---------------
    # ONE null / object / back-reference ANYWHERE must not cost the map:
    # PHP keeps the whole array, and a decoder that rejects it loses every
    # registered size of that attachment.  This is the multi-size family the
    # sweep measured, reproduced in the shape that lost it.
    "meta-with-a-null-value-inside": (
        [(1, 10, "_wp_attached_file", ORIGINAL),
         (2, 10, "_wp_attachment_metadata", php_ser({
             "file": ORIGINAL,
             "sizes": {"thumbnail": {"file": THUMB, "url": _Raw("N;")}},
             "image_meta": _Raw("N;")}))],
        [], [], [], set(), {ORIGINAL, "2019/02/" + THUMB},
    ),
    "meta-with-an-object-value-inside": (
        [(1, 10, "_wp_attached_file", ORIGINAL),
         (2, 10, "_wp_attachment_metadata", php_ser({
             "file": ORIGINAL,
             "sizes": {"thumbnail": {
                 "file": THUMB, "extra": _Raw('O:8:"stdClass":0:{}')}}}))],
        [], [], [], set(), {ORIGINAL, "2019/02/" + THUMB},
    ),
    "meta-with-a-back-reference-inside": (
        [(1, 10, "_wp_attached_file", ORIGINAL),
         (2, 10, "_wp_attachment_metadata", php_ser({
             "file": ORIGINAL,
             "sizes": {"thumbnail": {"file": THUMB, "same": _Raw("R:4;")}}}))],
        [], [], [], set(), {ORIGINAL, "2019/02/" + THUMB},
    ),
    # A WELL-FORMED custom serialization.  The class is not loaded on the
    # live host either, so PHP materializes an incomplete class and the MAP
    # survives — which is what makes this row able to fail: the shipped
    # fixture carried a C: whose payload declared 14 bytes and carried 20,
    # so both halves refused the map and agreed by accident, and the dead
    # C: branch underneath went unnoticed.  The sizes are the point: before
    # the fix the dump half lost every one of them.
    "meta-with-a-custom-serialization-inside": (
        [(1, 10, "_wp_attached_file", ORIGINAL),
         (2, 10, "_wp_attachment_metadata", php_ser({
             "file": ORIGINAL,
             "sizes": {"thumbnail": {"file": THUMB}},
             "obj": _Raw('C:7:"NoSuchX":2:{ab}')}))],
        [], [], [], set(), {ORIGINAL, "2019/02/" + THUMB},
    ),
    # ... and the same with an EMPTY payload, which is the shape a plugin
    # whose custom serialization carries nothing writes
    "meta-with-an-empty-custom-serialization": (
        [(1, 10, "_wp_attached_file", ORIGINAL),
         (2, 10, "_wp_attachment_metadata", php_ser({
             "file": ORIGINAL,
             "sizes": {"thumbnail": {"file": THUMB}},
             "obj": _Raw('C:7:"NoSuchX":0:{}')}))],
        [], [], [], set(), {ORIGINAL, "2019/02/" + THUMB},
    ),
    # A value nested 200 levels deep.  PHP 8.4 reads it (its own bound is
    # 4096); a decoder bounded at 64 refused the WHOLE map, so the live
    # half kept this attachment's size and the dump half lost it — one
    # stored-value shape deciding whether a thumbnail is deleted.
    "meta-nested-200-levels-deep": (
        [(1, 10, "_wp_attached_file", ORIGINAL),
         (2, 10, "_wp_attachment_metadata", php_ser({
             "file": ORIGINAL,
             "sizes": {"thumbnail": {"file": THUMB}},
             "builder": _Raw(_NESTED_200)}))],
        [], [], [], set(), {ORIGINAL, "2019/02/" + THUMB},
    ),
    # a reference past the end of PHP's var_hash is the one back-reference
    # PHP REJECTS (verified against PHP 8.4: unserialize returns false)
    "meta-back-reference-past-the-end": (
        [(1, 10, "_wp_attached_file", ORIGINAL),
         (2, 10, "_wp_attachment_metadata",
          'a:2:{s:4:"file";s:21:"%s";s:5:"sizes";R:99;}' % ORIGINAL)],
        [], [], [], set(), {ORIGINAL},
    ),
    "meta-serialized-scalar": (
        [(1, 10, "_wp_attached_file", ORIGINAL),
         (2, 10, "_wp_attachment_metadata", _ser(ORIGINAL))],
        [], [], [], set(), {ORIGINAL},
    ),
    # not a map, but it NAMES a path: the bridge scans every postmeta
    # value as text, so a serialized scalar URL is a reference
    "meta-serialized-scalar-naming-a-path": (
        [(1, 10, "_wp_attached_file", ORIGINAL),
         (2, 10, "_wp_attachment_metadata",
          _ser("https://site.test/wp-content/uploads/2019/02/other.jpg"))],
        [], [], [], set(), {ORIGINAL, "2019/02/other.jpg"},
    ),
    # the same, from another key of the size map itself
    "meta-other-key-naming-a-path": (
        [(1, 10, "_wp_attached_file", ORIGINAL),
         (2, 10, "_wp_attachment_metadata", meta_value(
             ORIGINAL, [("thumbnail", THUMB)],
             extra=[("source",
                     "https://site.test/wp-content/uploads/2019/02/sample-side.jpg")]))],
        [], [], [], set(),
        {ORIGINAL, "2019/02/" + THUMB, "2019/02/sample-side.jpg"},
    ),
    # unreadable for BOTH sides: a wrong declared length, trailing
    # garbage — the map is UNKNOWN, and the attachment's own path stands
    "meta-wrong-declared-length": (
        [(1, 10, "_wp_attached_file", ORIGINAL),
         (2, 10, "_wp_attachment_metadata",
          'a:2:{s:4:"file";s:99:"%s";s:5:"sizes";a:0:{}}' % ORIGINAL)],
        [], [], [], set(), {ORIGINAL},
    ),
    # TRAILING BYTES ARE IGNORED, because the deployed `@unserialize`
    # ignores them: it returns the map and raises only a diagnostic the `@`
    # suppresses.  The row carries a SIZE, so a decoder that treated the
    # diagnostic as a refusal loses it and the two modes disagree.
    "meta-trailing-garbage": (
        [(1, 10, "_wp_attached_file", ORIGINAL),
         (2, 10, "_wp_attachment_metadata",
          'a:2:{s:4:"file";s:21:"%s";s:5:"sizes";a:1:{s:9:"thumbnail";'
          'a:1:{s:4:"file";s:21:"%s";}}}junk' % (ORIGINAL, THUMB))],
        [], [], [], set(), {ORIGINAL, "2019/02/" + THUMB},
    ),
    "meta-not-media": (
        [(1, 10, "_wp_attached_file", "2019/02/sheet.csv"),
         (2, 10, "_wp_attachment_metadata", meta_value(
             "2019/02/sheet.csv", [("thumb", "sheet-thumb.csv")]))],
        [], [], [], set(), {"2019/02/sheet.csv", "2019/02/sheet-thumb.csv"},
    ),
    "meta-without-an-anchor-row": (
        [(1, 10, "_wp_attached_file", ""),
         (2, 10, "_wp_attachment_metadata",
          meta_value(ORIGINAL, [("thumbnail", THUMB)]))],
        [], [], [], set(), {ORIGINAL, THUMB},
    ),
    "meta-anchor-the-gate-refuses": (
        [(1, 10, "_wp_attached_file", "/var/www/html/uploads/2019/02/x.jpg"),
         (2, 10, "_wp_attachment_metadata",
          meta_value(ORIGINAL, [("thumbnail", THUMB)]))],
        [], [], [], set(), {ORIGINAL, THUMB},
    ),
    # THE SWEPT SHAPE: every registered size plus the original, one null
    # in the map.  Before the fix the dump path answered with the original
    # alone and the bridge with every size.
    "family-with-a-null-in-the-map": (
        [(1, 10, "_wp_attached_file", "2019/02/SampleImg0.jpg"),
         (2, 10, "_wp_attachment_metadata", php_ser({
             "width": "4000", "height": "3000",
             "file": "2019/02/SampleImg0.jpg",
             "sizes": {f"size{i}": {
                 "file": f"SampleImg{i}-{100 + i}.jpg",
                 "width": "100", "height": "100",
                 "mime-type": "image/jpeg"} for i in range(1, 4)},
             "image_meta": _Raw("N;")}))],
        [], [], [], set(),
        {"2019/02/SampleImg0.jpg"}
        | {f"2019/02/SampleImg{i}-{100 + i}.jpg" for i in range(1, 4)},
    ),
    # --- 5. the other three tables -----------------------------------
    "post-content-excerpt-and-guid": (
        [], [(1, "post", "publish",
              '<p>[gallery ids="1,2"]</p>'
              '<a href="/wp-content/uploads/2019/11/brochure.pdf">PDF</a>',
              "see wp-content/uploads/2019/11/excerpt.jpg.",
              "https://site.test/wp-content/uploads/2019/11/guid.png")],
        [], [], set(),
        {"2019/11/brochure.pdf", "2019/11/excerpt.jpg", "2019/11/guid.png"},
    ),
    "option-value-holding-a-path": (
        [], [], [(1, "avada_options",
                  _ser_map([("logo", "https://site.test/wp-content/uploads/"
                             "2024/02/logo.png")]), "yes")],
        [], set(), {"2024/02/logo.png"},
    ),
    "termmeta-value-holding-a-path": (
        [], [], [], [(1, "_category_image",
                      "/wp-content/uploads/2024/03/cat.jpg")],
        set(), {"2024/03/cat.jpg"},
    ),
    "other-postmeta-value-naming-a-path": (
        [(1, 10, "_wp_attached_file", ORIGINAL),
         (2, 10, "_elementor_data",
          '{"bg":"https://site.test/wp-content/uploads/2024/01/bg.png"}')],
        [], [], [], set(), {ORIGINAL, "2024/01/bg.png"},
    ),
    "postmeta-non-string-values": (
        [(1, 10, "_some_count", "42"), (2, 10, "_empty", "")], [], [], [],
        set(), set(),
    ),
    # the stale dirsize cache measured live on an observed run: absolute paths
    # to the site's previous host, several of them bare year DIRECTORIES
    "stale-dirsize-cache-option": (
        [], [], [(1, "_transient_dirsize_cache",
                  "/home/old/public_html/wp-content/uploads/2018", "no")],
        [], set(), set(),
    ),
    "several-attachments-one-directory": (
        [(1, 10, "_wp_attached_file", "2019/02/a.jpg"),
         (2, 10, "_wp_attached_file", "2019/02/b.jpg"),
         (3, 11, "_wp_attached_file", "2019/02/c.jpg"),
         (4, 11, "_wp_attachment_metadata",
          meta_value(None, [("t", "c-150.jpg")])),
         (5, 12, "_wp_attachment_metadata",
          meta_value(None, [("t", "orphan-150.jpg")]))],
        [], [], [], set(),
        {"2019/02/a.jpg", "2019/02/b.jpg", "2019/02/c.jpg",
         "2019/02/c-150.jpg", "orphan-150.jpg"},
    ),
}


def _fixture_dump(postmeta, posts, options, termmeta, prefix="wp_") -> bytes:
    """The same rows as a .sql dump (the offline half's input)."""
    out = _create(prefix + "options",
                  ["option_id", "option_name", "option_value", "autoload"])
    if options:
        out += _insert(prefix + "options", options)
    out += _create(prefix + "postmeta",
                   ["meta_id", "post_id", "meta_key", "meta_value"])
    if postmeta:
        out += _insert(prefix + "postmeta", postmeta)
    out += _create(prefix + "posts",
                   ["ID", "post_type", "post_status", "post_content",
                    "post_excerpt", "post_guid"])
    if posts:
        out += _insert(prefix + "posts", posts)
    out += _create(prefix + "termmeta", ["meta_id", "meta_key", "meta_value"])
    if termmeta:
        out += _insert(prefix + "termmeta", termmeta)
    return out


def _fixture_tables(postmeta, posts, options, termmeta, prefix="wp_") -> dict:
    """The same rows as $wpdb tables (the bridge oracle's input)."""
    def keyed(rows, columns):
        return [{name: row[i] for i, name in enumerate(columns)}
                for row in rows]
    return {
        prefix + "postmeta": keyed(
            postmeta, ["meta_id", "post_id", "meta_key", "meta_value"]),
        prefix + "posts": keyed(
            posts, ["ID", "post_type", "post_status", "post_content",
                    "post_excerpt", "post_guid"]),
        prefix + "options": keyed(
            options, ["option_id", "option_name", "option_value", "autoload"]),
        prefix + "termmeta": keyed(
            termmeta, ["meta_id", "meta_key", "meta_value"]),
    }


def test_dump_and_bridge_return_the_same_set(tmp_path):
    """THE DIFFERENTIAL TEST.

    One row fixture, two implementations: ``db_refs_from_dump`` reads the
    .sql dump, bridge.php's own ``wpt_media_db_map`` reads the same rows
    through the $wpdb stub.  Both must equal the PINNED expected set, so
    neither an offline regression nor a live-side regression can pass.

    Every shape that differed before the fix is a row here: the NUL /
    backslash / old-host normalization, the extension and is-a-directory
    gates, the ``N;``/``O:``/``C:``/``R;`` tolerance, the text scan of the
    attachment rows, and the multi-file family with a null in its map.
    """
    failures = []
    for name, case in FIXTURES.items():
        postmeta, posts, options, termmeta, dirs, expected = case
        # The on-disk half of the is-a-directory gate: the bridge asks
        # is_dir() on a real tree, so the offline half gets the same fact
        # as data (the walk's directory entries).
        basedir = tmp_path / name
        for rel in sorted(dirs):
            (basedir / rel).mkdir(parents=True, exist_ok=True)

        php = set(_php_db_map(tmp_path, _fixture_tables(
            postmeta, posts, options, termmeta), str(basedir))["db_refs"])
        py = db_refs_from_dump(
            io.BytesIO(_fixture_dump(postmeta, posts, options, termmeta)),
            dirs=set(dirs) or None,
        )
        if php != expected or py != expected:
            failures.append(
                f"{name}: expected={sorted(expected)} "
                f"php-only={sorted(php - expected)} "
                f"php-missing={sorted(expected - php)} "
                f"py-only={sorted(py - expected)} "
                f"py-missing={sorted(expected - py)}")
    assert not failures, "the two modes disagree with each other or with the "\
                         "pinned set:\n  " + "\n  ".join(failures)


# ------------------------------------------------- the ONE shared rule set

def _php_ref_extension_default() -> list[str]:
    """The MIRRORED DEFAULT literal out of bridge.php (never a copy)."""
    source = BRIDGE_SOURCE.read_text(encoding="utf-8")
    match = re.search(
        r"function wpt_media_ref_extensions\(.*?\) \{\s*\$refused = false;"
        r"\s*\$default = array\((.*?)\);", source, re.S)
    assert match, "bridge.php no longer defines wpt_media_ref_extensions()"
    return re.findall(r"'([^']+)'", match.group(1))


def test_ref_extensions_match_the_profile_and_the_bridge():
    """Three copies of ONE list, one owner: the shipped profile default.

    ``media.extensions`` decides what a media FILE is (the enumeration)
    and what a media REFERENCE may name (the keep-gate), and the live
    half of the gate runs in a file DEPLOYED on a host that cannot read
    the operator's profile — so the family is mirrored, twice, and pinned
    here against the profile that owns it.  A silent divergence is a
    mode-dependent keep-set: the exact defect class this file's
    differential test measures.

    This is the MIRROR, not the whole rule any more: a run's OWN profile
    travels with the read (the tests below), and the mirrored default is
    the FLOOR the effective family is unioned with.  The shipped default
    is still the one list all three copies must agree on, so this stays
    the drift alarm for it.
    """
    shipped = json.loads(PROFILE_DEFAULT.read_text(encoding="utf-8"))[
        "media"]["extensions"]
    assert list(REF_EXTENSIONS) == shipped
    assert _php_ref_extension_default() == list(REF_EXTENSIONS)


#: The profile knob SPEC [L20] names as set-reachable, widened by exactly
#: the one extension the shipped default does not carry.  Every reference
#: the scenario turns on ends in it.
WIDENED = ("psd",)
#: The attachment the deletion scenario destroys without the fix: a
#: ``_wp_attached_file`` row naming it, and a file of that name on disk.
WIDENED_REF = "2023/01/design.psd"


def test_the_gate_answers_with_the_callers_widened_family(tmp_path):
    """D1: a WIDENED profile must widen the LIVE gate, or the file dies.

    The defect, end to end.  ``--set media.extensions=[..., "psd"]`` made
    the ENUMERATION file uploads media by ``psd`` while the bridge's gate
    answered from its own literal, which does not carry it: the
    ``_wp_attached_file`` row below was invisible to the keep-gate, absent
    from the union, and therefore a deletion CANDIDATE — a
    database-referenced attachment removed by a compliant apply, on a
    configuration the profile documents as supported.

    So the read CARRIES the caller's family, and the real shipped PHP is
    measured here over the real rows: with the widened request the
    reference is kept, and the offline half (which always had the profile)
    keeps exactly the same set.  The third leg is the point of the whole
    exercise: the shipped default alone does NOT keep it — that answer is
    what made the file deletable, and pinning it is what would let the
    request be dropped again without a test failing.
    """
    postmeta = [(1, 10, "_wp_attached_file", WIDENED_REF),
                (2, 10, "_wp_attached_file", "2023/10/photo.jpg")]
    tables = _fixture_tables(postmeta, [], [], [])
    dump = io.BytesIO(_fixture_dump(postmeta, [], [], []))
    widened = list(REF_EXTENSIONS) + list(WIDENED)

    asked = _php_db_map(tmp_path, tables, "", widened, wire=True)
    assert set(asked["db_refs"]) == {WIDENED_REF, "2023/10/photo.jpg"}
    # the reported family CONTAINS the request (the default is the floor)
    assert asked["db_refs_gate"] >= len(widened)
    assert "db_refs_gate_fallback" not in asked

    # THE OFFLINE HALF agrees, extension for extension
    assert db_refs_from_dump(dump, widened) == set(asked["db_refs"])

    # ... and the shipped default alone is what used to lose the file
    default_only = _php_db_map(tmp_path, tables, "")
    assert set(default_only["db_refs"]) == {"2023/10/photo.jpg"}
    assert WIDENED_REF not in default_only["db_refs"]


def test_the_widened_file_is_not_deletable_in_either_mode(tmp_path):
    """The keep-set and the enumeration measure ONE family, both modes.

    The plan's delete set IS ``unreferenced_files`` (one shared
    enumeration behind the ``media.unreferenced`` finding and the
    trim-media action), so this is the deletion decision itself: with a
    widened profile the database-referenced ``.psd`` is protected
    whichever half measured the database, and the two halves answer
    IDENTICALLY — the property a mode-dependent keep-set violates.
    """
    from wpt.audit.media import unreferenced_files

    postmeta = [(1, 10, "_wp_attached_file", WIDENED_REF)]
    tables = _fixture_tables(postmeta, [], [], [])
    dump = io.BytesIO(_fixture_dump(postmeta, [], [], []))
    widened = list(REF_EXTENSIONS) + list(WIDENED)
    # the walk sees NONE of it: the database-heavy shape, where the database is the
    # only thing protecting the file
    live_refs: set[str] = set()

    offline = db_refs_from_dump(dump, widened)
    online = set(_php_db_map(
        tmp_path, tables, "", widened, wire=True)["db_refs"])
    assert offline == online == {WIDENED_REF}

    entries = [
        Entry(path=f"wp-content/uploads/{WIDENED_REF}", is_dir=False, size=99),
        Entry(path="wp-content/uploads/2023/01/orphan.jpg", is_dir=False,
              size=10),
    ]
    for db_refs in (offline, online):
        planned = [c.entry.path for c in unreferenced_files(
            entries, live_refs, db_refs, widened)]
        assert planned == ["wp-content/uploads/2023/01/orphan.jpg"]

    # and the DEFECT is the same enumeration over a gate that never heard
    # of the widening: the profile files the .psd as media, the shipped
    # default's gate cannot name it, and the database-referenced file
    # becomes a deletion candidate — pinned, so dropping the request from
    # the read fails a test again
    default_gate = set(_php_db_map(tmp_path, tables, "")["db_refs"])
    assert "wp-content/uploads/" + WIDENED_REF in [
        c.entry.path for c in unreferenced_files(
            entries, live_refs, default_gate, widened)]


def test_the_bridge_refuses_an_unusable_family_and_keeps_its_floor(tmp_path):
    """A hand-written request cannot narrow the gate below the default.

    The whole point of carrying the family on the read is that the wire can
    only WIDEN it, so a request that omits, empties or garbles the list
    leaves the mirrored default in force — a keep-set that protects at
    least everything the shipped family protects, and never the empty
    gate a smuggled empty list would buy.  Each refused shape says so in
    the answer (``db_refs_gate_fallback``), which is what the client turns
    into a fail-closed error instead of trusting the set.
    """
    postmeta = [(1, 10, "_wp_attached_file", WIDENED_REF),
                (2, 10, "_wp_attached_file", "2023/10/photo.jpg")]
    tables = _fixture_tables(postmeta, [], [], [])
    default_size = len(REF_EXTENSIONS)

    for label, request in (
        ("empty list", []),
        ("not a list", "psd"),
        ("a number", 7),
        ("a dotted suffix", [".psd"]),
        ("a non-string entry", ["psd", 7]),
        ("a path", ["../etc/passwd"]),
        ("past the bound", ["e%d" % i for i in range(513)]),
    ):
        answer = _php_db_map(tmp_path, tables, "", request, wire=True)
        assert answer.get("db_refs_gate_fallback") is True, label
        assert answer["db_refs_gate"] == default_size, label
        # the default's own references survive; nothing was narrowed away
        assert set(answer["db_refs"]) == {"2023/10/photo.jpg"}, label

    # a request that is merely NARROWER is honored as a widening of the
    # floor: the family stays the default's, the answer is the default's,
    # and nothing is flagged (a wider gate can only protect more)
    narrowed = _php_db_map(tmp_path, tables, "", ["jpg"], wire=True)
    assert "db_refs_gate_fallback" not in narrowed
    assert narrowed["db_refs_gate"] == default_size
    assert set(narrowed["db_refs"]) == {"2023/10/photo.jpg"}

    # an absent request is exactly the shipped behaviour
    absent = _php_db_map(tmp_path, tables, "", None, wire=True)
    assert absent["db_refs_gate"] == default_size
    assert "db_refs_gate_fallback" not in absent


def test_the_extension_token_rule_is_the_same_on_both_sides():
    """The wire-shape owner and the trust boundary agree on what a token is.

    The client normalizes a run's family with :data:`MEDIA_REF_TOKEN`
    before it goes on the wire; the bridge re-checks the same rule with its
    own pattern (it is the trust boundary — a hand-written request reaches
    it directly).  Two implementations of one shape, so the two
    spellings are pinned against each other here, and so is the request
    bound.
    """
    from wpt.wpbridge.client import MEDIA_REF_EXT_MAX, MEDIA_REF_TOKEN

    source = BRIDGE_SOURCE.read_text(encoding="utf-8")
    match = re.search(
        r"function wpt_media_ref_extensions\(.*?\).*?"
        r"preg_match\( '([^']+)'", source, re.S)
    assert match, "bridge.php no longer validates an extension token"
    pattern = match.group(1).replace("/", "")
    assert pattern == MEDIA_REF_TOKEN.pattern

    bound = re.search(r"define\( 'WPT_MEDIA_REF_EXT_MAX', (\d+) \)", source)
    assert bound, "bridge.php no longer bounds a requested family"
    assert int(bound.group(1)) == MEDIA_REF_EXT_MAX


def test_ref_normalize_mirrors_the_php_normalizer():
    """The offline half of the normalization, shape for shape.

    Each of these is a stored value the two implementations used to
    answer differently about: a NUL byte and a backslash used to survive
    into the offline keep-set (protecting nothing), and the marker cut is
    what makes a reference to a site migrated from ANOTHER host
    host-independent.
    """
    assert ref_normalize("2023/10/pic.jpg") == "2023/10/pic.jpg"
    assert ref_normalize(" 2023/10/pic.jpg ") == "2023/10/pic.jpg"
    assert ref_normalize("2023/10/with space.jpg") == "2023/10/with space.jpg"
    # the uploads marker wins over everything before it
    assert ref_normalize(
        "/home/old/public_html/wp-content/uploads/2018/03/photo.jpg"
    ) == "2018/03/photo.jpg"
    assert ref_normalize(
        "https://site.test/wp-content/uploads/2023/10/pic.jpg"
    ) == "2023/10/pic.jpg"
    # NUL bytes stripped, backslashes folded
    assert ref_normalize("2023/10/pic.jpg\0") == "2023/10/pic.jpg"
    assert ref_normalize("2023\\10\\pic.jpg") == "2023/10/pic.jpg"
    # an absolute value with no marker anchors to nothing
    assert ref_normalize("/var/www/html/uploads/2023/x.jpg") is None
    # refused shapes
    assert ref_normalize("") is None
    assert ref_normalize("   ") is None
    assert ref_normalize("../../etc/passwd") is None
    assert ref_normalize("2023/./x.jpg") is None
    # a repeated slash COLLAPSES (PHP's preg_replace), it is not a refusal
    assert ref_normalize("2023//10//x.jpg") == "2023/10/x.jpg"
    assert ref_normalize("2023/10/") is None
    assert ref_normalize(None) is None
    assert ref_normalize(42) is None


def test_ref_is_kept_gates_extension_then_directory():
    """The keep-gate: extension family first, is-a-directory as the belt.

    The belt's input is DATA (the enumerated directory set), because the
    bridge asks ``is_dir()`` on the live host while the offline half can
    only be told by the walk.  ``None`` skips the belt exactly as the
    bridge skips it when ``wp_upload_dir`` is unreadable — skipping can
    only over-protect, which is the safe direction for a deletion.
    """
    assert ref_is_kept("2023/10/pic.jpg") is True
    assert ref_is_kept("2023/10/pic.JPG") is True          # case-normalized
    assert ref_is_kept("2023/10/clip.mp4") is True
    assert ref_is_kept("2023/10/sheet.csv") is True
    # no usable extension at all
    assert ref_is_kept("2018") is False
    assert ref_is_kept("2023/10/README") is False
    assert ref_is_kept("2023/10/x.") is False
    assert ref_is_kept("2023/10/weird.zzz") is False
    assert ref_is_kept("2023/10/x.jpg.php") is False        # reversed double
    # a dotfile has no extension to allow (.htaccess, index.php, .user.ini)
    assert ref_is_kept("2023/10/.htaccess") is False
    assert ref_is_kept(".htaccess") is False
    assert ref_is_kept("") is False
    assert ref_is_kept(None) is False
    # the belt: a directory can carry a media-looking name
    dirs = {"2024/05/thumbs.jpg", "2023/10"}
    assert ref_is_kept("2024/05/thumbs.jpg", dirs=dirs) is False
    assert ref_is_kept("2024/05/photo.jpg", dirs=dirs) is True
    assert ref_is_kept("2024/05/thumbs.jpg") is True       # no dirs -> skipped
    # the allowlist is the caller's, so a widened profile widens both
    assert ref_is_kept("2023/10/x.svg", extensions=("jpg",)) is False
    assert ref_is_kept("2023/10/x.zzz", extensions=("zzz",)) is True


def test_php_decode_tolerates_the_tags_php_reads():
    """PHP's ``unserialize`` semantics, kept in step with the live side.

    The live half of the keep-set runs PHP's own decoder, so the offline
    half implements the same rule: the byte-exact string length, PHP's
    key CASTING, and the tags the analyzer's narrower subset rejects
    outright (``N;``, ``O:``, ``C:``, ``R:``) decoded and CONSUMED — one
    null anywhere in a size map must not cost the map.  A back-reference
    resolves through PHP's own ``var_hash`` numbering (index 0 is the
    value being decoded), and one pointing past the end is the single
    case PHP rejects (verified against PHP 8.4: ``unserialize`` returns
    false), not a silent null.
    """
    assert _php_decode('s:3:"abc";') == "abc"
    assert _php_decode("i:-5;") == -5
    assert _php_decode("i:+5;") == 5
    # an integer literal past the platform range SATURATES, as PHP does
    # (measured: i:99999999999999999999; -> PHP_INT_MAX)
    assert _php_decode("i:99999999999999999999;") == 2 ** 63 - 1
    assert _php_decode("i:-99999999999999999999;") == -(2 ** 63)
    assert _php_decode("b:1;") is True
    assert _php_decode("d:1.5;") == 1.5
    assert _php_decode("d:INF;") == float("inf")
    assert _php_decode("N;") is None
    # the byte length is PHP's, never the character count
    assert _php_decode('s:5:"caf\u00e9";') == "caf\u00e9"
    assert _php_decode('a:1:{i:0;s:1:"x";}') == {0: "x"}
    # a null INSIDE a map is decoded, and the map survives it
    assert _php_decode('a:2:{s:1:"a";N;s:1:"b";s:1:"c";}') == \
        {"a": None, "b": "c"}
    # an object member is consumed and stands in as an object (never a
    # dict — that is exactly what PHP's is_array() says about it)
    decoded = _php_decode('a:1:{s:1:"o";O:8:"stdClass":1:{s:1:"a";s:1:"b";}}')
    assert list(decoded) == ["o"] and not isinstance(decoded["o"], (dict, str))
    # a back-reference resolves to the value at PHP's index (index 0 is
    # the array being decoded, exactly as PHP's var_hash numbers it).  A
    # sequential array decodes to a dict, which is the same is_array()
    # verdict PHP gives and what the metadata reader needs.
    assert _php_decode('a:3:{i:0;s:3:"aaa";i:1;a:1:{i:0;s:3:"bbb";}i:2;R:2;}'
                       ) == {0: "aaa", 1: {0: "bbb"}, 2: "aaa"}
    assert _php_decode('a:3:{i:0;s:3:"aaa";i:1;a:1:{i:0;s:3:"bbb";}i:2;R:3;}'
                       ) == {0: "aaa", 1: {0: "bbb"}, 2: {0: "bbb"}}
    # key casting, measured against PHP 8.4: canonical decimals only
    assert _php_decode('a:1:{s:1:"0";s:1:"x";}') == {0: "x"}
    assert _php_decode('a:1:{s:2:"-5";s:1:"x";}') == {-5: "x"}
    for stays in ("007", "-0", "+12", " 1", "1.5", "1e3",
                  "9223372036854775808"):
        assert _php_decode('a:1:{s:%d:"%s";s:1:"x";}' % (len(stays), stays)
                           ) == {stays: "x"}, stays
    assert _php_decode('a:1:{s:19:"9223372036854775807";s:1:"x";}'
                       ) == {9223372036854775807: "x"}
    # a key of any OTHER type is refused, which is PHP's own verdict
    # (measured: a float, a bool, a null, an object, an array and a
    # back-reference to one each make unserialize return false).  Before
    # the rule was stated these were python TypeErrors escaping the
    # decoder — an unreadable value that crashed the dump read instead of
    # being one.
    for key in ('R:1;', 'd:1.5;', 'b:1;', 'b:0;', 'N;', 'O:8:"stdClass":0:{}',
                'a:0:{}'):
        with pytest.raises(_PhpDecodeError):
            _php_decode('a:1:{%s s:1:"x";}' % key)
    # ... and one past the end is UNREADABLE, as PHP has it
    for bad in ('a:2:{s:1:"a";s:1:"b";i:1;R:9;}',
                'a:2:{s:4:"file";s:99:"x";s:5:"sizes";a:0:{}}',
                'a:1:{s:4:"file";s:5:"x";',          # truncated
                'a:1:{s:4:"file";}',                  # count lies
                'a:1:{s:1:"a";C:7:"NoSuchX":1:{ab}}',  # C: length wrong
                'a:1:{s:1:"a";C:7:"NoSuchX":2:ab}',   # C: not braced
                'a:1:{s:1:"a";E:5:"Hearts";}',        # E: no "Class:Case"
                'not a serialized value',
                '2019/02/SampleImg.jpg'):
        with pytest.raises(_PhpDecodeError):
            _php_decode(bad)
    with pytest.raises(_PhpDecodeError):
        _php_decode(None)


def test_php_decode_reads_a_custom_serialization_and_ignores_trailing_bytes():
    """THE TWO RULES THAT DECIDED A DELETED ATTACHMENT.

    Both are the DEPLOYED expression — bridge.php's ``wpt_media_meta_names``
    asks ``is_array( @unserialize( $raw ) )`` — and both used to send the
    two halves of the keep-set different ways.

    ``C:`` was DEAD CODE.  The branch read the payload length from the
    ``:`` that PRECEDES it instead of from the first digit, so every
    ``C:`` value raised and :func:`_meta_map` returned None: every
    registered size of that attachment was lost OFFLINE while the live half
    kept all of them.  A shipped differential fixture could not see it,
    because its ``C:`` payload was itself malformed (it declared 14 bytes
    and carried 20), so both halves refused the map and agreed by accident.

    TRAILING BYTES ARE IGNORED, because the deployed ``@unserialize``
    ignores them: it returns the value and raises only a diagnostic the
    ``@`` suppresses.  A decoder that treated a diagnostic as a refusal
    dropped the size map of any attachment whose stored value carried one —
    which is exactly the failure this module's own docstring calls a
    deletion bug.
    """
    # a WELL-FORMED custom serialization: the class is not loaded here and
    # not on the live host either, so PHP materializes an incomplete class
    # and the ARRAY survives — a size map carrying one keeps its sizes
    decoded = _php_decode('a:2:{s:4:"file";s:21:"2019/02/SampleImg.jpg";'
                          's:3:"obj";C:7:"NoSuchX":2:{ab}}')
    assert list(decoded) == ["file", "obj"]
    assert decoded["file"] == "2019/02/SampleImg.jpg"
    assert isinstance(decoded["obj"], _PhpValue) and decoded["obj"].tag == "C"
    # the payload is OPAQUE and skipped by its declared byte length, exactly
    # as PHP skips it (it hands the bytes to the class and never parses
    # them) — so a payload that is itself a serialized array is fine
    assert list(_php_decode('a:1:{s:1:"a";C:7:"NoSuchX":5:{a:0:{}}}')) == ["a"]
    # ... and it takes a var_hash slot, so a later R: resolves to it
    with_ref = _php_decode('a:2:{s:1:"a";C:7:"NoSuchX":0:{}s:1:"b";R:2;}')
    assert isinstance(with_ref["b"], _PhpValue)
    assert with_ref["b"].tag == "C"
    # an empty payload is the shape a plugin that serializes nothing writes
    assert _php_decode('a:1:{s:1:"a";C:7:"NoSuchX":0:{}}')["a"].tag == "C"

    # trailing bytes: the value is the value, whatever follows it
    assert _php_decode('a:1:{s:1:"a";s:1:"x";}junk') == {"a": "x"}
    assert _php_decode('s:3:"abc";junk') == "abc"
    assert _php_decode('a:1:{s:1:"a";s:1:"x";}extra') == {"a": "x"}
    # ... and the KEEP-SET consequence, which is what the rule is for
    meta = ('a:2:{s:4:"file";s:21:"2019/02/SampleImg.jpg";s:5:"sizes";'
            'a:1:{s:9:"thumbnail";a:1:{s:4:"file";s:21:"SampleImg-150x150.jpg";'
            '}}}junk')
    assert refs_from_attachment_meta(meta, "2019/02/") == {
        "2019/02/SampleImg.jpg", "2019/02/SampleImg-150x150.jpg"}


def test_php_decode_reads_an_enum_case_the_way_that_can_only_keep_more():
    """``E:``, the last tag PHP's ``unserialize`` reads, and its one
    KNOWN one-way divergence.

    PHP 8.1 added enum cases, and a payload carrying one decodes to an
    ARRAY on the live side, so a decoder that refused the tag would lose
    every registered size of that attachment offline.  Whether PHP keeps a
    particular case depends on facts this half does not have: PHP refuses a
    case whose class it cannot load (measured: with no ``Suit`` enum
    declared, ``a:1:{s:1:"a";E:11:"Suit:Hearts";}`` returns false) and keeps
    one it can.  So the case is read as an object either way, and the two
    halves can only ever DISAGREE IN THE SAFE DIRECTION — this half keeping
    a size the live half loses, never the reverse.  Over-protection is the
    direction a keep-set is allowed to err in; losing a size is the
    deletion bug.
    """
    decoded = _php_decode('a:2:{s:4:"file";s:21:"2019/02/SampleImg.jpg";'
                          's:4:"case";E:11:"Suit:Hearts";}')
    assert decoded["file"] == "2019/02/SampleImg.jpg"
    assert isinstance(decoded["case"], _PhpValue)
    assert decoded["case"].tag == "E"
    # the declared length spans "Class:Case": a payload without a colon is
    # not a case name at all
    for bad in ('a:1:{s:1:"a";E:5:"Hearts";}',
                'a:1:{s:1:"a";E:11:"Suit:Hearts"}',   # no terminating ";"
                'a:1:{s:1:"a";E:13:"Suit:Hearts";}'):  # length wrong
        with pytest.raises(_PhpDecodeError):
            _php_decode(bad)
    # ... and the keep-set consequence
    meta = ('a:3:{s:4:"file";s:21:"2019/02/SampleImg.jpg";s:5:"sizes";'
            'a:1:{s:9:"thumbnail";a:1:{s:4:"file";s:21:"SampleImg-150x150.jpg";'
            '}}s:4:"case";E:11:"Suit:Hearts";}')
    assert refs_from_attachment_meta(meta, "2019/02/") == {
        "2019/02/SampleImg.jpg", "2019/02/SampleImg-150x150.jpg"}


def test_php_decode_nests_exactly_as_deep_as_php_reads():
    """The depth bound is PHP's, measured — not a tolerance of our own.

    A bound below PHP's is not a safety belt, it is a MODE DIFFERENCE: the
    live half reads a metadata value nested 200 deep and keeps every
    registered size, and a decoder that refuses it at 65 loses all of them
    offline.  Measured on the PHP 8.4 CLI, ``unserialize()`` accepts 4096
    nested arrays and refuses the 4097th, so the bound is 4096 and the
    boundary itself is pinned against PHP at the end of this test.

    It is NOT the deployed bridge's proof budget (1024 levels opened), and
    it must not be lowered to that number: the client sends the row either
    way — it is the SHAPE PROOF that refuses it, by name, on the per-row
    ``failed[]`` channel — while lowering this one would lose every
    reference a deep value names.  ``tests/test_bridge_php.py`` pins the
    two numbers against each other and against bridge.php's own ``define``.
    """
    # far past the old 64, and past python's own recursion limit: the
    # decoder is iterative, so it reads what PHP reads
    for levels in (65, 200, 1000, 4096):
        decoded = _php_decode(_nested(levels))
        for _ in range(levels):
            decoded = decoded[0]
        assert decoded == 1, levels
    # one level past what PHP accepts is unreadable HERE TOO (this is the
    # same verdict, not a stricter one)
    with pytest.raises(_PhpDecodeError):
        _php_decode(_nested(4097))
    # ... and the boundary is measured, not asserted from memory
    if shutil.which("php") is not None:
        script = 'echo (int) is_array(@unserialize($argv[1])), "\\n";'
        for levels in (4096, 4097):
            proc = subprocess.run(
                ["php", "-r", script, _nested(levels)],
                capture_output=True, text=True)
            assert proc.stdout.strip() == (
                "1" if levels == 4096 else "0"), (levels, proc.stdout)
    # and a size map nested 200 deep keeps its sizes offline
    meta = ('a:3:{s:4:"file";s:21:"2019/02/SampleImg.jpg";s:5:"sizes";'
            'a:1:{s:9:"thumbnail";a:1:{s:4:"file";s:21:"SampleImg-150x150.jpg";'
            '}}s:7:"builder";%s}' % _nested(200))
    assert refs_from_attachment_meta(meta, "2019/02/") == {
        "2019/02/SampleImg.jpg", "2019/02/SampleImg-150x150.jpg"}


def test_php_decode_agrees_with_the_analyzer_subset():
    """The two decoders, on every shape BOTH accept.

    ``wpt.localmode.analyzer.php_unserialize`` is the analyzer's own
    subset (it deliberately refuses to resurrect objects, so ``N;`` and
    ``O:`` are errors there).  Where the two overlap they must return the
    SAME value — an option value read and a keep-set read that disagree
    about the same bytes would be a second, invisible mode difference.
    """
    from wpt.localmode.analyzer import UnserializeError, php_unserialize

    for raw in ('s:3:"abc";', 's:0:"";', "i:42;", "i:-7;", "b:0;", "b:1;",
                "d:1.5;", "d:INF;", "d:-INF;", "a:0:{}",
                'a:1:{s:1:"a";s:1:"b";}', 'a:1:{i:0;s:1:"x";}',
                php_ser({"file": "2023/x.jpg",
                         "sizes": {0: {"file": "x-150x150.jpg"}}})):
        assert _php_decode(raw) == php_unserialize(raw), raw
    for bad in ('s:5:"abc";', "i:x;", "i: 5;", "i:1_0;", "b:2;",
                "a:1:{s:1:'a';}", 'a:2:{s:1:"a";s:1:"b";}'):
        with pytest.raises(_PhpDecodeError):
            _php_decode(bad)
        with pytest.raises(UnserializeError):
            php_unserialize(bad)
    # the two DIVERGE on exactly the tags the analyzer refuses on
    # purpose, and the keep-set must not refuse them (documented in
    # decode_php_value): PHP keeps the array either way.  R:1 is the
    # self-reference PHP resolves into a recursion, R:2 in a one-pair
    # array points PAST the table and is the one reference PHP rejects
    # (both verified against PHP 8.4).
    for tag in ("N;", 'O:8:"stdClass":0:{}', "R:1;"):
        raw = 'a:1:{s:1:"a";%s}' % tag
        assert len(_php_decode(raw)) == 1, tag
        with pytest.raises(UnserializeError):
            php_unserialize(raw)
    with pytest.raises(_PhpDecodeError):
        _php_decode('a:1:{s:1:"a";R:2;}')
    # ... and on TRAILING BYTES, where the analyzer is STRICTER than the
    # keep-set has to be.  The deployed expression is a bare
    # ``@unserialize``: it returns the value and raises only a diagnostic
    # the ``@`` suppresses (measured on PHP 8.4 —
    # ``a:1:{s:1:"a";s:1:"x";}junk`` yields the array), so a keep-set that
    # read the diagnostic as a refusal would lose every registered size of
    # an attachment whose stored value carries one.  An OPTION value is the
    # other case: it is a whole cell, so bytes after the value are part of
    # what the site stored and the analyzer refuses them.
    assert _php_decode('s:3:"abc";junk') == "abc"
    with pytest.raises(UnserializeError):
        php_unserialize('s:3:"abc";junk')
    # KEY CASTING is no longer a divergence: the analyzer is a DELEGATE to
    # this decoder, so it casts the way PHP does (verified on PHP 8.4).  A
    # size map keyed "0" is read as {0: ...} by the live side and now by
    # both offline readers.  [R29]
    assert _php_decode('a:1:{s:1:"0";s:1:"x";}') == {0: "x"}
    assert php_unserialize('a:1:{s:1:"0";s:1:"x";}') == {0: "x"}
    # ... and the analyzer keeps its own bounds, which are POLICY on top of
    # the one decoder, not a second parser: its anti-bomb depth (64, where
    # this decoder and PHP accept 4096) and its refusal of a value that is
    # its own recursion.
    assert php_unserialize(_nested(10)) == _php_decode(_nested(10))
    for deep in (_nested(100), _nested(5000)):
        with pytest.raises(UnserializeError):
            php_unserialize(deep)
    # a back-reference to an EARLIER value is not a recursion and reads as
    # that value — which is what PHP produces, and what no option read can
    # tell apart from a genuinely repeated one.
    assert php_unserialize('a:2:{i:0;s:1:"a";i:1;R:2;}') == {0: "a", 1: "a"}


def test_the_rewrite_gate_reads_a_value_through_the_one_decoder():
    """The webp local gate and the keep-set can no longer disagree.

    Both halves of ONE destructive decision read a stored PHP value, and
    they read it with the same implementation: the gate used to call
    ``wpt.localmode.analyzer.php_unserialize``, whose narrower policy
    refused shapes the live side rewrites — a ``C:`` payload, a 200-deep
    value, a value with trailing bytes — and reported "could not be parsed"
    for a value this decoder reads perfectly well.
    """
    import wpt.actions.images_webp as webp

    for raw, why in (
        ('a:2:{s:4:"file";s:3:"img";s:3:"obj";C:7:"NoSuchX":2:{ab}}',
         "a custom-serialized value"),
        ('a:2:{s:4:"deep";%ss:1:"x";s:1:"y";}' % _nested(200),
         "a value 200 levels deep"),
        ('a:1:{s:1:"a";s:1:"x";}trailing-bytes', "trailing bytes"),
    ):
        # the ONE decoder reads all three ...
        assert isinstance(decode_php_value(raw), dict), why
        # ... so the gate PLANS the value's leaves instead of refusing it
        texts, bad = webp.value_texts(raw)
        assert bad is False, why
        assert texts[0] == raw
    # a genuinely unreadable value still gates, and the reason is the honest
    # one: PHP's own unserialize returns false for it too.
    broken = 'a:1:{s:99:"short";}'
    with pytest.raises(_PhpDecodeError):
        decode_php_value(broken)
    assert webp.value_texts(broken) == ([broken], True)
    # and the action does not import the analyzer's reader at all, so the
    # two cannot drift back into a second answer for the same bytes
    assert not hasattr(webp, "php_unserialize")


def test_dump_gates_a_directory_named_like_a_file():
    """The is-a-directory belt, offline — the walk is the witness.

    The bridge asks ``is_dir()`` on the live host; the offline half is
    told by the enumeration, so the DIRECTORY set travels as data.  The
    same dump therefore answers differently once the tree is known — and
    that is the point: the offline gate used to be missing entirely, so
    the two modes planned different DELETE sets for one database.
    """
    dump = _dump(postmeta=[
        (1, 10, "_wp_attached_file", "2024/05/thumbs.jpg"),
        (2, 10, "_wp_attached_file", "2024/05/photo.jpg"),
    ])
    dirs = {"2024/05/thumbs.jpg", "2024/05"}
    assert db_refs_from_dump(io.BytesIO(dump)) == \
        {"2024/05/thumbs.jpg", "2024/05/photo.jpg"}
    assert db_refs_from_dump(io.BytesIO(dump), dirs=dirs) == \
        {"2024/05/photo.jpg"}


def test_uploads_dirs_reads_a_walk_and_never_guesses():
    from wpt.types import Entry
    entries = [
        Entry(path="wp-content/uploads", is_dir=True, size=0),
        Entry(path="wp-content/uploads/2024/05", is_dir=True, size=0),
        Entry(path="wp-content/uploads/2024/05/x.jpg", is_dir=False, size=1),
        # outside uploads: never a reference, so never in the belt's input
        Entry(path="wp-content/themes/x", is_dir=True, size=0),
    ]
    # uploads-RELATIVE, the shape every reference is: a webroot-relative
    # path here would test a path that does not exist and silently keep
    # every directory reference
    # the uploads ROOT is not in the set: its uploads-relative form is "",
    # which no reference can ever be (an empty path names nothing)
    assert uploads_dirs(entries) == {"2024/05"}
    # the caller strips the uploads prefix; the gate is uploads-relative
    assert uploads_dirs(None) is None
    assert uploads_dirs(object()) is None


def test_dump_reports_the_references_its_gate_dropped():
    """A lossy keep-set is REPORTED once, in the dump path too.

    The bridge's client reports the server's ``db_refs_dropped`` count;
    the offline gate drops the same junk (a bare year directory, a
    .htaccess) and says so the same way, because a keep-set that quietly
    lost references is the shape of the defect this module's gate fixes.
    """
    handler, parent, old = _wpt_records()
    try:
        assert db_refs_from_dump(io.BytesIO(_dump(postmeta=[
            (1, 10, "_wp_attached_file", "2023/10/pic.jpg"),
            (2, 10, "_wp_attached_file", "2018"),
            (3, 10, "_wp_attached_file", "2023/10/.htaccess"),
        ]))) == {"2023/10/pic.jpg"}
    finally:
        _release(handler, parent, old)
    warnings = [r for r in handler.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "name no media file" in warnings[0].getMessage()
    # a clean dump warns about nothing
    handler, parent, old = _wpt_records()
    try:
        db_refs_from_dump(io.BytesIO(_dump(postmeta=[
            (1, 10, "_wp_attached_file", "2023/10/pic.jpg")])))
    finally:
        _release(handler, parent, old)
    assert not [r for r in handler.records if r.levelno == logging.WARNING]


def test_is_media_and_the_keep_gate_are_one_rule():
    """The enumeration and the keep-set judge "media" the same way.

    ``wpt.audit.media.is_media`` (which files may be DELETED) delegates
    to ``ref_is_kept`` (what a database REFERENCE may name).  Two
    allowlist implementations is how the two halves of the keep-set came
    to disagree about one database, so the delegation is pinned here over
    the shapes that separate the two rules.
    """
    extensions = load().media.extensions
    for rel in ("2023/10/pic.jpg", "2023/10/pic.JPG", "2023/10/clip.mp4",
                "2023/10/pic-300x233.jpg", "2023/10/.htaccess", ".htaccess",
                "2023/10/README", "2023/10/weird.zzz", "2023/10/x.jpg.php",
                "2023/10/x.", "2018"):
        assert is_media(rel, extensions) == ref_is_kept(rel, extensions), rel


def test_php_decode_matches_the_deployed_unserialize(tmp_path):
    """The stored-value decoder, against the DEPLOYED expression itself.

    The rule is not "PHP's ``unserialize``" in the abstract: it is the
    expression bridge.php's ``wpt_media_meta_names`` actually runs —
    ``is_array( @unserialize( $raw ) )`` — so that is what the oracle asks,
    with the diagnostic IGNORED, exactly as ``@`` ignores it.  The previous
    version of this test modelled a different rule (``maybe_unserialize``
    plus ``is_serialized``: any diagnostic means refusal), which is why it
    could list ``a:1:{s:1:"a";}junk`` as "refused by PHP and here too" while
    the deployed code returns the map — the two halves of the keep-set then
    disagree about an attachment and a test says they agree.

    Every row is pinned twice: the literal this table claims PHP returns
    (compared against the real CLI, so a change in PHP is caught) and the
    answer this module must produce.  ``b:0;`` is in the list precisely to
    separate the two ways a ``false`` comes back — a real decoded false,
    which raises no diagnostic, from a refusal, which does — because the
    deployed code cannot tell them apart either and only the reader can.
    """
    if shutil.which("php") is None:
        pytest.fail("php CLI not found on PATH (the deployed unserialize is "
                    "the reference this rule is measured against)")
    # One value is deliberately absent: PHP's R:1 self-reference decodes to
    # a RECURSIVE array, which no JSON comparison can carry.  It is pinned
    # on the python side in test_php_decode_tolerates_the_tags_php_reads.
    # (raw, verdict, value) where verdict is "value" (PHP returns this) or
    # "refused" (PHP returns false, so a value here is unreadable).
    cases = [
        ('s:3:"abc";', "value", "abc"),
        ('s:5:"café";', "value", "café"),   # a BYTE length, not a char count
        ("i:-5;", "value", -5),
        # a REAL false: decoded, not refused, and no diagnostic
        ("b:0;", "value", False),
        ("b:1;", "value", True),
        ("d:1.5;", "value", 1.5),
        ("d:INF;", "value", "INF"),
        ("N;", "value", None),
        ("a:0:{}", "value", {}),
        # a key cast to int, and a list is how the oracle PRINTS a PHP array
        # whose keys are 0..n-1 (so both sides are compared in that form)
        ('a:1:{s:1:"0";s:1:"x";}', "value", ["x"]),
        ('a:1:{s:3:"007";s:1:"x";}', "value", {"007": "x"}),
        ('a:1:{s:2:"-0";s:1:"x";}', "value", {"-0": "x"}),
        ('a:1:{s:3:"1.5";s:1:"x";}', "value", {"1.5": "x"}),
        ('a:1:{s:19:"9223372036854775808";s:1:"x";}', "value",
         {"9223372036854775808": "x"}),
        ('a:2:{s:4:"file";s:5:"a.jpg";s:5:"sizes";a:1:{s:9:"thumbnail";'
         'a:1:{s:4:"file";s:5:"a.jpg";}}}}', "value",
         {"file": "a.jpg", "sizes": {"thumbnail": {"file": "a.jpg"}}}),
        ('a:1:{s:1:"a";N;}', "value", {"a": None}),   # a null value
        ('a:1:{s:1:"a";O:8:"stdClass":2:{s:1:"a";s:1:"b";s:1:"c";i:1;}}',
         "value", {"a": {"__php_object__": True}}),
        ('a:1:{s:1:"a";C:7:"NoSuchX":2:{ab}}', "value",
         {"a": {"__php_object__": True}}),            # a WELL-FORMED C:
        ('a:1:{s:1:"a";C:7:"NoSuchX":0:{}}', "value",
         {"a": {"__php_object__": True}}),            # an empty payload
        ('a:2:{s:1:"a";C:7:"NoSuchX":0:{}s:1:"b";R:2;}', "value",
         {"a": {"__php_object__": True},
          "b": {"__php_object__": True}}),            # C: takes a var_hash slot
        ('a:2:{i:0;s:1:"a";i:1;R:2;}', "value", ["a", "a"]),
        ('a:3:{i:0;s:1:"a";i:1;a:1:{i:0;s:1:"b";}i:2;R:4;}', "value",
         ["a", ["b"], "b"]),   # R:4 is the string, not the array
        # TRAILING BYTES: the deployed expression returns the value and only
        # raises a diagnostic, so the map is a MAP here
        ('a:1:{s:1:"a";s:1:"x";}junk', "value", {"a": "x"}),
        ('a:1:{s:1:"a";s:1:"x";}extra', "value", {"a": "x"}),
        # refused by PHP (unserialize returns false) and here too
        ('s:5:"abc";', "refused", None),
        ('a:2:{s:1:"a";s:1:"b";}', "refused", None),      # the count lies
        ('a:1:{s:1:"a";R:2;}', "refused", None),          # past the table
        ('a:1:{R:1;s:1:"x";}', "refused", None),          # a ref as a key
        ('a:1:{d:1.5;s:1:"x";}', "refused", None),        # a float as a key
        ('a:1:{b:1;s:1:"x";}', "refused", None),          # a bool as a key
        ('a:1:{N;s:1:"x";}', "refused", None),            # a null as a key
        ('a:1:{s:1:"a";C:7:"NoSuchX":1:{ab}}', "refused", None),
        # the fixture the shipped differential test carried: a C: whose
        # payload declares 14 bytes and carries 20, so BOTH halves refuse
        # it and agree by accident — which is why it could not catch the
        # dead C: branch (the well-formed rows above are what catches it)
        ('a:1:{s:1:"a";C:11:"ArrayObject":14:{x:i:0;a:0:{};m:a:0:{}}}',
         "refused", None),
        ('2019/02/SampleImg.jpg', "refused", None),   # not serialized at all
    ]
    script = tmp_path / "wpt-unserialize-oracle.php"
    script.write_text(
        "<?php\n"
        # INF/NAN and objects have no JSON form PHP can print, so both are
        # normalized to markers this side can produce too.
        "function wpt_norm( $v ) {\n"
        "    if ( is_float( $v ) ) {\n"
        "        if ( is_nan( $v ) ) { return 'NAN'; }\n"
        "        if ( is_infinite( $v ) ) { return $v > 0 ? 'INF' : '-INF'; }\n"
        "        return $v;\n"
        "    }\n"
        "    if ( is_object( $v ) ) { return array( '__php_object__' => true ); }\n"
        "    if ( is_array( $v ) ) {\n"
        # an EMPTY array is {} here and [] in json_encode's default list
        # form; this side decodes an array to a dict, so print {}
        "        if ( 0 === count( $v ) ) { return new stdClass(); }\n"
        "        $out = array();\n"
        "        foreach ( $v as $k => $x ) { $out[ (string) $k ] = wpt_norm( $x ); }\n"
        "        return $out;\n"
        "    }\n"
        "    return $v;\n"
        "}\n"
        "$cases = json_decode(file_get_contents($argv[1]), true);\n"
        "$out = array();\n"
        "foreach ($cases as $case) {\n"
        # THE DEPLOYED EXPRESSION, verbatim, with the diagnostic it raises
        # RECORDED and then ignored: the answer is what it returns, and a
        # raised diagnostic is not a refusal (the "refused" column below is
        # the only thing that decides that here, and the CLI check pins it).
        "    $diagnostic = false;\n"
        "    set_error_handler(function () use (&$diagnostic) {\n"
        "        $diagnostic = true; return true;\n"
        "    });\n"
        "    $value = @unserialize($case);\n"
        "    restore_error_handler();\n"
        "    $out[] = array(\n"
        "        'is_array'   => is_array($value),\n"
        "        'value'      => wpt_norm($value),\n"
        "        'diagnostic' => $diagnostic,\n"
        "    );\n"
        "}\n"
        "echo json_encode($out, JSON_PARTIAL_OUTPUT_ON_ERROR), \"\\n\";\n",
        encoding="utf-8")
    payload = tmp_path / "wpt-unserialize-cases.json"
    payload.write_text(json.dumps([case for case, _v, _x in cases]))
    proc = subprocess.run(["php", str(script), str(payload)],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    theirs = json.loads(proc.stdout)
    assert len(theirs) == len(cases)

    def comparable(value):
        """The decoded value in the shape the PHP oracle prints."""
        if isinstance(value, _PhpValue):
            return {"__php_object__": True}
        if isinstance(value, dict):
            out = {str(k): comparable(v) for k, v in value.items()}
            # a PHP array with keys 0..n-1 is a LIST, which json_encode
            # prints as a list; the same array as a dict must compare equal
            if out and list(out) == [str(i) for i in range(len(out))]:
                return [out[str(i)] for i in range(len(out))]
            return out
        if isinstance(value, float):
            if value != value:
                return "NAN"
            if value in (float("inf"), float("-inf")):
                return "INF" if value > 0 else "-INF"
        return value

    for (case, verdict, expected), answer in zip(cases, theirs):
        # 1. the PINNED FACT about the deployed expression.  A row whose
        #    expectation is a value must be the value PHP returns, and the
        #    whole row can only be a refusal when the diagnostic fired:
        #    that is the distinction the old oracle collapsed.
        if verdict == "value":
            assert answer["value"] == expected, case
        else:
            assert answer["value"] is False and answer["diagnostic"], case
        # 2. and this module answers the deployed question the same way
        try:
            mine = comparable(_php_decode(case))
            decoded = True
        except _PhpDecodeError:
            mine, decoded = None, False
        if verdict == "refused":
            assert not decoded, case
            continue
        assert decoded, case
        assert mine == expected, case
        # the MAP question, which is the one the keep-set asks
        assert isinstance(_php_decode(case), dict) is answer["is_array"], case
