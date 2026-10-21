"""Unit tests for the source-only dangerous-PHP-pattern check.

FakeSource-backed ``AuditData`` built by the real
:func:`wpt.audit.data.gather_source` (the ``wpt scan`` seam): no gatherer, no
network, no bridge, no database, no sleeps.  Every fixture is a tiny
in-memory webroot; the check reads candidate CONTENTS through
``data.source.read_many`` exactly as the command wires it.

Test -> behavior map:
  test_gather_source_is_source_only ....... mode/entries/source set, every
        DB/site fact unknown (None/{}, never a guessed zero)
  test_registered_for_both_modes_and_exact_names_risks
        .................................... registry record + one aggregate
        finding per class, exact names/risks, bytes 0, category, fix
  test_session_fixation ................... direct superglobal and a
        same-file tainted variable; a fixed literal and a member call are
        silent
  test_reflected_request .................. echo/<?= /tainted variable; an
        escaping call on the same line suppresses; a sanitizer in a comment
        does not
  test_sql_injection_and_prepare_excluded .. ->query with request data;
        ->prepare is not a sink; an untainted variable is not flagged
  test_sql_identifier ..................... FROM/describes with direct and
        tainted identifiers; an ordinary table name is silent
  test_file_include_code_execution_unserialize  the remaining three classes
  test_foreach_taint ...................... foreach ($_GET as $k => $v) taints
        both variables
  test_taint_is_assignment_based_not_name_based
        .................................... a variable merely named like data
        ($id = 5) is not tainted
  test_code_position_gating ............... commented/string/heredoc copies
        are silent; a genuine hit after them is found
  test_invalid_php_skips_the_whole_file ... lexically invalid -> no finding,
        debug line, the other file still scans
  test_ignore_prefixes_and_prefix_semantics  shipped wp-admin/wp-includes
        excluded, a near-miss prefix scanned, custom overrides honored
  test_executable_extension_set ........... .php/.PHP/.phtml scanned; .txt/
        .jpg not; directories never read
  test_size_gate_and_equal_limit ........... > max never fetched, == max
        scanned
  test_deadline_partial_results ............ second batch stops with ONE
        warning and the first batch's finding
  test_deadline_before_first_batch ......... no read at all, ONE warning
  test_breaker_and_single_read_failure ..... per-path failure debug, 25th
        consecutive aborts, later batch never fetched, partial finding kept
  test_read_many_run_level_raise_propagates  a dead transport is not a dead
        file
  test_detail_limit_and_total_count ........ detail_limit lines + (+N more),
        count is every match
  test_detail_order_is_deterministic ....... path/line/column order
  test_no_source_or_candidates_is_silent ... debug only, never a clean pass
  test_log_contract ........................ one INFO summary (scanned,
        findings); no INFO for an unmeasurable run
"""

import logging
from dataclasses import replace

import pytest

from tests.fakes import FakeSource
from wpt.audit.data import gather_source
from wpt.audit.registry import all_checks, run_checks, select_checks
from wpt.audit.source_scan import check_security_source_patterns
from wpt.settings import Settings, load
from wpt.types import DeadlineExceeded, Entry, SourceError

DEFAULTS = load()

PLUGIN = "wp-content/plugins/x/x.php"

# Wall-clock shape assertions also run under ``-n 20 --dist worksteal``.  A
# shape that must COMPLETE gets a budget and a ceiling far above its
# standalone cost; a shape that must EXPIRE keeps a tiny budget and only
# proves it STOPS within a generous ceiling.  Measuring against the deadline
# itself (deadline 0.5 s, assert < 0.5 s) made completion a scheduling race:
# a loaded worker could spend the whole budget before the scan finished.
COMPLETION_DEADLINE_S = 60.0
COMPLETION_CEILING_S = 60.0
EXPIRY_CEILING_S = 5.0


# --------------------------------------------------------------- log capture


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


def scan_records(wpt_records):
    return [r for r in wpt_records if r.name == "wpt.audit.source_scan"]


def warnings(wpt_records):
    return [r.getMessage() for r in scan_records(wpt_records)
            if r.levelno == logging.WARNING]


def infos(wpt_records):
    return [r.getMessage() for r in scan_records(wpt_records)
            if r.levelno == logging.INFO]


# ------------------------------------------------------------------ fixtures


def source_with(**files: bytes) -> FakeSource:
    source = FakeSource()
    source.files.update(files)
    return source


def data_for(source: FakeSource, mode: str = "local"):
    return gather_source(source, mode)


def scan(files: dict[str, bytes], settings: Settings = DEFAULTS):
    source = FakeSource()
    source.files.update(files)
    return check_security_source_patterns(data_for(source), settings)


def by_name(findings, name):
    return next(f for f in findings if f.name == name)


def settings_with_source_scan(**values) -> Settings:
    return replace(DEFAULTS, source_scan=replace(
        DEFAULTS.source_scan, **values))


class _ReadRecordingSource(FakeSource):
    """FakeSource recording every per-path read and read_many batch."""

    def __init__(self) -> None:
        super().__init__()
        self.reads: list[str] = []
        self.batches: list[list[str]] = []

    def read_bytes(self, path):
        self.reads.append(path)
        return super().read_bytes(path)

    def read_many(self, paths, *, max_bytes=None):
        self.batches.append(list(paths))
        return super().read_many(paths, max_bytes=max_bytes)


class _BatchedSource(FakeSource):
    """read_many double: records batches, returns failed-map entries."""

    def __init__(self, fail_paths=()) -> None:
        super().__init__()
        self.fail_paths = set(fail_paths)
        self.batches: list[list[str]] = []

    def read_many(self, paths, *, max_bytes=None):
        self.batches.append(list(paths))
        ok: dict[str, bytes] = {}
        failed: dict[str, str] = {}
        for path in paths:
            if path in self.fail_paths:
                failed[path] = f"unreadable: {path}"
            elif path in self.files:
                ok[path] = self.files[path]
            else:
                failed[path] = f"no such file: {path}"
        return ok, failed


class _RaisingReadMany(FakeSource):
    """A dead transport: read_many raises a non-per-path exception."""

    def read_many(self, paths, *, max_bytes=None):
        raise RuntimeError("transport died")


class _DeadlineAfterOneBatch:
    """Expires at the batch-boundary check after the first batch.

    The scan now checks the deadline before/after every file too; keying on
    the batch context keeps this deterministic (the first batch is scanned,
    the second is never read).
    """

    def __init__(self) -> None:
        self.batch_checks = 0

    def check(self, context) -> None:
        if context == "source scan":
            self.batch_checks += 1
            if self.batch_checks > 1:
                raise DeadlineExceeded(
                    f"run deadline exceeded at {context!r}")


# ------------------------------------------------------------------ data seam


def test_gather_source_is_source_only():
    source = source_with(**{PLUGIN: b"<?php echo 'x';"})
    data = data_for(source, "ftp")
    assert data.mode == "ftp"
    assert data.source is source
    assert [entry.path for entry in data.entries
            if not entry.is_dir] == [PLUGIN]
    # Every DB/site fact is UNKNOWN, never a guessed zero/empty measurement.
    for name in (
        "siteurl", "home", "template", "blog_public", "wp_version",
        "mu_plugins", "active_plugins", "uploads_basedir", "revisions",
        "expired_transients", "attachments", "nav_menu_items",
        "autoload_bytes", "admin_users", "locale", "deadline",
    ):
        assert getattr(data, name) is None, name
    assert data.posts == {}
    assert data.plugin_catalog == {}
    assert data.orphan_meta == {}
    assert data.tables == {}
    assert data.big_autoload_options == []
    assert data.theme_versions == {}


# ---------------------------------------------------------- registry contract


def test_registered_for_both_modes_and_exact_names_risks():
    record = next(r for r in all_checks()
                  if r.name == "security.source_patterns")
    assert record.applies == ("ftp", "local")
    assert record.func is check_security_source_patterns
    for mode in ("ftp", "local"):
        selected = select_checks(mode, ["security.source_patterns"], None)
        assert [r.name for r in selected] == ["security.source_patterns"]

    findings = scan({
        "a.php": b"<?php\nsession_id($_GET['sid']);\n",
        "b.php": b"<?php\necho $_GET['q'];\n",
        "c.php": (b"<?php\n"
                  b"$wpdb->query(\"DELETE FROM t WHERE id=\" . $_GET['id']);\n"),
        "d.php": (b"<?php\n$t = $_GET['t'];\n"
                  b"$sql = \"SELECT * FROM $t\";\n"),
        "e.php": b"<?php\ninclude $_GET['p'];\n",
        "f.php": b"<?php\nsystem($_GET['c']);\n",
        "g.php": b"<?php\nunserialize($_POST['d']);\n",
    })
    expected = {
        "session-fixation": "high",
        "reflected-request": "medium",
        "sql-injection": "high",
        "sql-identifier": "high",
        "file-include": "high",
        "code-execution": "high",
        "unserialize-request": "high",
    }
    assert {f.name: f.risk for f in findings} == expected
    assert {f.category for f in findings} == {"security.source_patterns"}
    assert {f.bytes for f in findings} == {0}
    assert all(f.count == 1 and f.fix and f.detail for f in findings)
    for finding in findings:
        finding.validate()


# ------------------------------------------------------------- each class


def test_session_fixation():
    findings = scan({"a.php": (
        b"<?php\n"
        b"session_id($_GET['sid']);\n"
        b"$sid = $_POST['sid'];\n"
        b"session_name($sid);\n"
        b"session_id('fixed');\n"
        b"$obj->session_id($_REQUEST['sid']);\n"
    )})
    assert [f.name for f in findings] == ["session-fixation"]
    finding = findings[0]
    assert finding.count == 2
    assert finding.detail.splitlines() == [
        "a.php:2 session_id()",
        "a.php:4 session_name()",
    ]


def test_reflected_request():
    findings = scan({"a.php": (
        b"<?php\n"
        b"echo $_GET['q'];\n"
        b"print $_POST['q'];\n"
        b"$q = $_REQUEST['q'];\n"
        b"printf($q);\n"
        b"die($_COOKIE['q']);\n"
        b"exit($_GET['q']);\n"
        b"echo htmlspecialchars($_GET['q']);\n"
        b"echo $_GET['q']; // esc_html()\n"
    )})
    finding = by_name(findings, "reflected-request")
    assert finding.risk == "medium"
    # echo, print, printf, die, exit, and the unsuppressed echo at the end;
    # the sanitized line is silent, the comment-only sanitizer is not.
    assert finding.count == 6
    assert finding.detail.splitlines()[0] == "a.php:2 echo"
    assert "a.php:9 echo" in finding.detail


def test_R11_an_expressionless_echo_tag_at_eof_is_not_a_crash():
    """R11-P2-8: ``<?=`` with no expression produced no statement starts;
    _statement_span indexed starts[0] and raised IndexError, which the
    registry turned into audit.check_failed and discarded every other
    source finding.  The file is simply clean."""
    assert scan({"a.php": b"<?="}) == []
    assert scan({"a.php": (
        b"<?php $x = $_GET['q']; echo $x; ?><?="
    )}) != []


def test_reflected_short_echo_tag():
    findings = scan({"a.php": b"<?= $_GET['q'] ?>\n"})
    assert [f.name for f in findings] == ["reflected-request"]
    assert findings[0].detail == "a.php:1 <?="


def test_sql_injection_and_prepare_excluded():
    findings = scan({"a.php": (
        b"<?php\n"
        b"$wpdb->query(\"DELETE FROM t WHERE id=\" . $_GET['id']);\n"
        b"$id = $_GET['id'];\n"
        b"$wpdb->get_results(\"SELECT * FROM t WHERE id=$id\");\n"
        b"$wpdb->prepare(\"SELECT * FROM t WHERE id=%s\", $_GET['id']);\n"
        b"$lang = 'fr';\n"
        b"$wpdb->query(\"DELETE FROM t WHERE lang='$lang'\");\n"
        b"mysqli_query($db, \"DELETE FROM t WHERE id=\" . $_POST['id']);\n"
    )})
    finding = by_name(findings, "sql-injection")
    assert finding.risk == "high"
    assert finding.count == 3
    assert "a.php:2 ->query()" in finding.detail
    assert "a.php:4 ->get_results()" in finding.detail
    assert "a.php:8 mysqli_query()" in finding.detail
    # ->prepare is not a sink and the untainted variable is not dataflow.
    assert "a.php:5" not in finding.detail
    assert "a.php:7" not in finding.detail


def test_sql_identifier():
    findings = scan({"a.php": (
        b"<?php\n"
        b"$sql = \"SELECT * FROM \" . $_GET['t'];\n"
        b"$table = $_GET['t'];\n"
        b"$sql = \"SELECT * FROM $table\";\n"
        b"$sql = \"SHOW COLUMNS FROM $table\";\n"
        b"$sql = \"DELETE FROM wp_users WHERE id=1\";\n"
    )})
    finding = by_name(findings, "sql-identifier")
    assert finding.risk == "high"
    assert finding.count == 3
    assert finding.detail.splitlines() == [
        "a.php:2 FROM",
        "a.php:4 FROM",
        "a.php:5 SHOW COLUMNS FROM",
    ]


def test_R25_select_aliases_and_named_windows_keep_the_sql_identifier_context():
    """R25-P2: a valid per-column alias (``a AS x, b AS y``) and the SQL
    standard's named window (``OVER w``) execute, but the SELECT grammar
    attached ``AS`` only after the whole list and accepted ``OVER`` only
    with parentheses.  A prepared query with a dynamic table was classified
    as prose and the HIGH sql-identifier finding was lost."""
    findings = scan({"a.php": (
        b"<?php\n"
        b"$t = $_GET['t'];\n"
        b"$q = \"SELECT a AS x, b AS y FROM $t\";\n"
        b"$w = \"SELECT ROW_NUMBER() OVER w FROM $t WINDOW w AS "
        b"(PARTITION BY id)\";\n"
        b"$wpdb->query($wpdb->prepare($q, 1));\n"
        b"$wpdb->query($wpdb->prepare($w, 1));\n"
    )})
    finding = by_name(findings, "sql-identifier")
    assert finding.risk == "high"
    assert finding.count == 2
    assert finding.detail.splitlines() == ["a.php:3 FROM", "a.php:4 FROM"]
    # The prose guard stays intact: an English sentence that merely starts
    # with "Select" is not a query.
    assert not any(f.name == "sql-identifier" for f in scan({"b.php": (
        b"<?php\n$d = $_GET['d'];\n"
        b"$x = \"Select a file from $d\";\n"
    )}))


def test_R25_variable_variable_read_resolves_a_static_assignment():
    """R25-P2: ``$n="t"; $t=$_GET["x"]; echo ${$n};`` prints HUNTER, but the
    alias map was populated only when ``${$n}`` was an assignment TARGET, so
    the read-only chain returned no finding.  A later non-static assignment
    removes the alias (the read is dynamic and must not inherit stale
    knowledge)."""
    findings = scan({"a.php": (
        b"<?php\n"
        b"$n = \"t\";\n"
        b"$t = $_GET[\"x\"];\n"
        b"echo ${$n};\n"
    )})
    finding = by_name(findings, "reflected-request")
    assert finding.detail.splitlines() == ["a.php:4 echo"]
    # A non-static assignment before the read means the selected variable is
    # unknowable: the read fails CLOSED on the (now tainted) indirection, so
    # the finding is kept rather than resolved to a stale ``t`` alias.
    assert by_name(scan({"b.php": (
        b"<?php\n"
        b"$n = \"t\";\n"
        b"$t = $_GET[\"x\"];\n"
        b"$n = $_GET[\"pick\"];\n"
        b"echo ${$n};\n"
    )}), "reflected-request").detail.splitlines() == ["b.php:5 echo"]


def test_file_include_code_execution_unserialize():
    findings = scan({"a.php": (
        b"<?php\n"
        b"include $_GET['p'];\n"
        b"require_once $path;\n"
        b"system($_POST['c']);\n"
        b"eval($_REQUEST['e']);\n"
        b"unserialize($_COOKIE['d']);\n"
        b"$path = $_GET['p'];\n"
    )})
    assert [f.name for f in findings] == [
        "file-include", "code-execution", "unserialize-request",
    ]
    assert by_name(findings, "file-include").detail.splitlines() == [
        "a.php:2 include", "a.php:3 require_once",
    ]
    assert by_name(findings, "code-execution").detail.splitlines() == [
        "a.php:4 system()", "a.php:5 eval()",
    ]
    assert by_name(findings, "unserialize-request").detail == (
        "a.php:6 unserialize()")


def test_foreach_taint():
    findings = scan({"a.php": (
        b"<?php\n"
        b"foreach ($_GET as $key => $value) {\n"
        b"    include $value;\n"
        b"    system($key);\n"
        b"}\n"
    )})
    assert by_name(findings, "file-include").count == 1
    assert by_name(findings, "code-execution").count == 1


def test_taint_is_assignment_based_not_name_based():
    findings = scan({"a.php": (
        b"<?php\n"
        b"$id = 5;\n"
        b"$sql = \"DELETE FROM t WHERE id=$id\";\n"
        b"mysql_query($sql);\n"
    )})
    assert findings == []


# --------------------------------------------------------- gating / scope


def test_code_position_gating():
    findings = scan({"a.php": (
        b"<?php\n"
        b"// session_id($_GET['sid']);\n"
        b"/* session_id($_GET['sid']); */\n"
        b"$x = \"session_id($_GET['sid']);\";\n"
        b"$y = <<<'EOT'\n"
        b"session_id($_GET['sid']);\n"
        b"EOT;\n"
        b"session_id($_GET['sid']);\n"
    )})
    assert [f.name for f in findings] == ["session-fixation"]
    assert findings[0].count == 1
    assert findings[0].detail == "a.php:8 session_id()"


def test_short_echo_tag_gating_and_html_context():
    # A real <?= tag inside HTML (its '#' is HTML text, not a PHP comment)
    # is found; the same bytes in a string or a PHP comment are not.
    findings = scan({"a.php": (
        b"<p>#1 <?= $_GET['q'] ?></p>\n"
        b"<?php echo '<?= $_GET[\"q\"] ?>';\n"
        b"<?php // <?= $_GET['q'] ?>\n"
    )})
    assert [f.detail for f in findings] == ["a.php:1 <?="]


def test_invalid_php_skips_the_whole_file(wpt_records):
    findings = scan({
        "bad.php": b"<?php session_id($_GET['sid']); \"unterminated\n",
        "good.php": b"<?php session_id($_GET['sid']);\n",
    })
    assert [f.name for f in findings] == ["session-fixation"]
    assert findings[0].detail == "good.php:1 session_id()"
    debug = [r.getMessage() for r in scan_records(wpt_records)
             if r.levelno == logging.DEBUG]
    assert any("bad.php" in line and "lexically valid" in line for line in debug)


def test_ignore_prefixes_and_prefix_semantics():
    findings = scan({
        "wp-admin/admin.php": b"<?php session_id($_GET['s']);\n",
        "wp-includes/core.php": b"<?php session_id($_GET['s']);\n",
        "wp-administration/plugin.php": b"<?php session_id($_GET['s']);\n",
        "wp-content/plugins/p/p.php": b"<?php session_id($_GET['s']);\n",
    })
    assert [f.detail for f in findings] == [
        "wp-administration/plugin.php:1 session_id()\n"
        "wp-content/plugins/p/p.php:1 session_id()"
    ]

    custom = settings_with_source_scan(
        ignore_prefixes=["wp-content/plugins/skip/"])
    findings = scan({
        "wp-admin/admin.php": b"<?php session_id($_GET['s']);\n",
        "wp-content/plugins/skip/s.php": b"<?php session_id($_GET['s']);\n",
        "wp-content/plugins/keep/k.php": b"<?php session_id($_GET['s']);\n",
    }, custom)
    assert [f.detail for f in findings] == [
        "wp-admin/admin.php:1 session_id()\n"
        "wp-content/plugins/keep/k.php:1 session_id()"
    ]


def test_executable_extension_set():
    findings = scan({
        "a.php": b"<?php session_id($_GET['s']);\n",
        "b.PHP": b"<?php session_id($_GET['s']);\n",
        "c.phtml": b"<?php session_id($_GET['s']);\n",
        "d.txt": b"<?php session_id($_GET['s']);\n",
        "e.jpg": b"<?php session_id($_GET['s']);\n",
    })
    assert [f.detail for f in findings] == [
        "a.php:1 session_id()\n"
        "b.PHP:1 session_id()\n"
        "c.phtml:1 session_id()"
    ]


def test_size_gate_and_equal_limit(wpt_records):
    line = b"<?php session_id($_GET['s']);\n"
    source = _ReadRecordingSource()
    source.files["exact.php"] = line
    source.files["over.php"] = b" " + line
    data = data_for(source)
    findings = check_security_source_patterns(
        data, settings_with_source_scan(max_file_bytes=len(line)))
    assert [f.detail for f in findings] == ["exact.php:1 session_id()"]
    assert source.reads == ["exact.php"]
    assert source.batches == [["exact.php"]]


# --------------------------------------------------------------- bounds


def test_static_sql_table_followed_by_value_is_not_an_identifier_sink():
    """`FROM wp_users ... = $id` is a VALUE concatenation, not a dynamic
    TABLE: the first identifier after FROM is static.  The literal-blanked
    view erased wp_users and produced a HIGH false positive."""
    findings = scan({
        "sql.php": (
            b"<?php\n$id = $_GET['id'];\n"
            b"$sql = 'SELECT * FROM wp_users WHERE id=' . $id;\n"
        ),
    })
    assert not any(finding.name == "sql-identifier"
                   for finding in findings)


def test_identifier_keywords_in_comments_or_bare_doc_strings_stay_dead():
    """A comment after a real sink and a non-SQL double-quoted string must
    not mint a HIGH sql-identifier finding; only a live SQL context counts."""
    findings = scan({
        "dead.php": (
            b"<?php\n$id = $_GET['id'];\n"
            b"mysql_query('SELECT 1'); // FROM $id\n"
            b"$x = 'FROM $id';\n"
            b"$doc = \"FROM $id\";\n"
        ),
    })
    assert not any(finding.name == "sql-identifier"
                   for finding in findings)


def test_nowdoc_is_literal_and_heredoc_interpolates():
    nowdoc = scan({
        "nowdoc.php": (
            b"<?php\n$x = <<<'TXT'\n$_GET[id]\nTXT;\necho $x;\n"
        ),
    })
    assert not any(finding.name == "reflected-request"
                   for finding in nowdoc)
    heredoc = scan({
        "heredoc.php": (
            b"<?php\n$x = <<<TXT\nsafe; $_GET[id]\nTXT;\necho $x;\n"
        ),
    })
    assert any(finding.name == "reflected-request"
               for finding in heredoc)


def test_post_read_size_cap_refuses_an_understated_listing(monkeypatch):
    class _Understated(FakeSource):
        def list_dir(self, path):
            return [Entry(path="big.php", is_dir=False, size=1)]

    source = _Understated()
    source.files["big.php"] = (
        b"<?php session_id($_GET['s']);\n" + b"x" * 100)
    findings = check_security_source_patterns(
        data_for(source),
        settings_with_source_scan(max_file_bytes=30),
    )
    # The body was materialized by this in-memory double, but it is a
    # KNOWN skip: the scan is PARTIAL, never a clean pass.
    assert [f.name for f in findings] == ["scan-partial"]
    assert "read bound" in findings[0].detail or "over the 30 B" \
        in findings[0].detail


def test_double_quoted_interpolation_does_not_truncate_session_argument():
    """A quote/parenthesis inside a `{$...}` interpolation is PHP code, not
    the end of the string or the call; the request argument after it must
    still be seen."""
    findings = scan({
        "interp.php": (
            b"<?php\n"
            b"session_id(\"safe {$a[\" ) \"]} \" . $_GET['sid']);\n"
        ),
    })
    assert any(finding.name == "session-fixation" for finding in findings)


def test_gather_source_checks_the_deadline_before_an_empty_walk():
    from wpt.audit.data import gather_source

    class _Expired:
        def check(self, context):
            raise DeadlineExceeded("run deadline exceeded")

    with pytest.raises(DeadlineExceeded):
        gather_source(FakeSource(), "local", deadline=_Expired())


def test_deadline_partial_results(monkeypatch, wpt_records):
    import wpt.audit.source_scan as mod

    monkeypatch.setattr(mod, "_READ_BATCH", 2)
    source = _ReadRecordingSource()
    source.files["a.php"] = b"<?php session_id($_GET['s']);\n"
    source.files["b.php"] = b"<?php echo 'safe';\n"
    source.files["c.php"] = b"<?php session_id($_GET['s']);\n"
    data = data_for(source)
    data.deadline = _DeadlineAfterOneBatch()
    findings = check_security_source_patterns(data, DEFAULTS)
    assert [f.name for f in findings] == ["session-fixation", "scan-partial"]
    assert findings[0].detail == "a.php:1 session_id()"
    assert "run deadline exceeded" in findings[1].detail
    assert source.batches == [
        ["a.php", "b.php"],
    ]
    assert warnings(wpt_records) == [
        "source scan stopped: run deadline exceeded; results are partial",
    ]


def test_deadline_before_first_batch(monkeypatch, wpt_records):
    source = _ReadRecordingSource()
    source.files["a.php"] = b"<?php session_id($_GET['s']);\n"
    data = data_for(source)

    class _Expired:
        def check(self, context):
            raise DeadlineExceeded(f"run deadline exceeded at {context!r}")

    data.deadline = _Expired()
    findings = check_security_source_patterns(data, DEFAULTS)
    assert [f.name for f in findings] == ["scan-partial"]
    assert "run deadline exceeded" in findings[0].detail
    assert source.batches == []
    assert warnings(wpt_records) == [
        "source scan stopped: run deadline exceeded; results are partial",
    ]


def test_breaker_and_single_read_failure(monkeypatch, wpt_records):
    import wpt.audit.source_scan as mod

    monkeypatch.setattr(mod, "_READ_BATCH", 2)
    fails = {f"wp-content/plugins/10-fail-{i:02d}.php" for i in range(25)}
    source = _BatchedSource(fails)
    source.files["wp-content/plugins/00-good.php"] = (
        b"<?php session_id($_GET['s']);\n")
    for path in fails:
        source.files[path] = b"<?php echo 'x';\n"
    source.files["wp-content/plugins/90-late.php"] = (
        b"<?php session_id($_GET['late']);\n")
    data = data_for(source)
    findings = check_security_source_patterns(data, DEFAULTS)

    assert [f.name for f in findings] == ["session-fixation", "scan-partial"]
    assert findings[0].detail == (
        "wp-content/plugins/00-good.php:1 session_id()")
    assert "25 consecutive unreadable" in findings[1].detail
    assert warnings(wpt_records) == [
        "source scan aborted after 25 consecutive unreadable files; "
        "results are partial",
    ]
    # 13 batches of 2: good + fail00, then fail01..fail24 are the 25th
    # consecutive failure; the late file's batch is never fetched.
    assert len(source.batches) == 13
    assert "wp-content/plugins/90-late.php" not in {
        path for batch in source.batches for path in batch
    }
    debug = [r.getMessage() for r in scan_records(wpt_records)
             if r.levelno == logging.DEBUG]
    assert len([line for line in debug if "unreadable, skipped" in line]) == 25


def test_read_many_run_level_raise_propagates():
    source = _RaisingReadMany()
    source.files["a.php"] = b"<?php session_id($_GET['s']);\n"
    data = data_for(source)
    with pytest.raises(RuntimeError, match="transport died"):
        check_security_source_patterns(data, DEFAULTS)


# ------------------------------------------------------------- presentation


def test_detail_limit_and_total_count():
    lines = "".join(
        f"echo $_GET['q{i}'];\n" for i in range(5)
    ).encode()
    findings = scan(
        {"a.php": b"<?php\n" + lines},
        settings_with_source_scan(detail_limit=2),
    )
    finding = by_name(findings, "reflected-request")
    assert finding.count == 5
    assert finding.detail.splitlines() == [
        "a.php:2 echo",
        "a.php:3 echo",
        "(+3 more)",
    ]


def test_detail_order_is_deterministic():
    findings = scan({
        "wp-content/plugins/z/z.php": b"<?php\necho $_GET['q'];\n",
        "wp-content/plugins/a/a.php": (b"<?php\n\n"
                                       b"echo $_GET['q'];\n"),
    })
    assert by_name(findings, "reflected-request").detail.splitlines() == [
        "wp-content/plugins/a/a.php:3 echo",
        "wp-content/plugins/z/z.php:2 echo",
    ]


def test_no_source_or_candidates_is_silent(wpt_records):
    source = source_with(**{"a.php": b"<?php session_id($_GET['s']);\n"})
    data = data_for(source)
    data.source = None
    assert check_security_source_patterns(data, DEFAULTS) == []

    no_candidates = source_with(**{"readme.txt": b"hello"})
    assert check_security_source_patterns(
        data_for(no_candidates), DEFAULTS) == []
    debug = [r.getMessage() for r in scan_records(wpt_records)
             if r.levelno == logging.DEBUG]
    assert any("no content source" in line for line in debug)
    assert any("no candidate" in line for line in debug)
    assert infos(wpt_records) == []


def test_log_contract(wpt_records):
    findings = scan({
        "a.php": b"<?php session_id($_GET['s']);\n",
        "b.php": b"<?php echo 'safe';\n",
    })
    assert len(findings) == 1
    lines = infos(wpt_records)
    assert lines == ["source scan: 2 file(s) scanned, 1 finding(s)"]


def test_run_checks_end_to_end_both_modes():
    for mode in ("ftp", "local"):
        source = source_with(**{
            "a.php": b"<?php session_id($_GET['s']);\n"})
        data = data_for(source, mode)
        findings = run_checks(
            data, DEFAULTS, mode, ["security.source_patterns"], None)
        assert [f.name for f in findings] == ["session-fixation"]


# ------------------------------------------------------- round-1 regressions


def test_SRC_1_keywords_inside_variables_and_methods_are_not_sql():
    findings = scan({"a.php": (
        b"<?php\n"
        b"$table='my_table';\n"
        b"$data=array('name'=>$_POST['name']);\n"
        b"$wpdb->update($table,$data,array('id'=>1));\n"
    )})
    assert not any(finding.name == "sql-identifier" for finding in findings)

    findings = scan({"b.php": (
        b"<?php\n"
        b"$id=$_GET['id'];\n"
        b"User::update($id);\n"
        b"$obj->describe($id);\n"
    )})
    assert not any(finding.name == "sql-identifier" for finding in findings)


def test_SRC_2_single_quoted_sql_still_exposes_a_dynamic_identifier():
    findings = scan({"a.php": (
        b"<?php\n"
        b"$pdo->prepare('SELECT * FROM ' . $_GET['t']);\n"
        b"$stmt->execute();\n"
    )})
    finding = by_name(findings, "sql-identifier")
    assert finding.detail == "a.php:2 FROM"
    assert finding.risk == "high"
    # A literal variable-looking token in single quotes is NOT request data.
    safe = scan({"safe.php": (
        b"<?php\n"
        b"$id = $_GET['id'];\n"
        b"$sql = 'SELECT * FROM wp_users WHERE id=$id';\n"
    )})
    assert not any(f.name == "sql-identifier" for f in safe)


def test_SRC_3_braced_interpolation_and_escaped_dollar():
    findings = scan({"a.php": (
        b"<?php\n"
        b"$q=$_GET['q'];\n"
        b"echo \"value ${q}\";\n"
    )})
    assert by_name(findings, "reflected-request").detail == "a.php:3 echo"

    heredoc = scan({"h.php": (
        b"<?php\n$q=$_GET['q'];\n$x = <<<TXT\n${q}\nTXT;\necho $x;\n"
    )})
    assert any(f.name == "reflected-request" for f in heredoc)

    safe = scan({"safe.php": b"<?php\necho \"literal \\$_GET\";\n"})
    assert not any(f.name == "reflected-request" for f in safe)


def test_C13_quoted_braced_name_and_files_superglobal_are_request_data():
    """C13: ``${'id'}`` is PHP's ``$id`` and ``$_FILES`` is attacker data.
    Both were invisible (the rewrite produced ``$'id'`` and the superglobal
    set omitted _FILES), so an uploaded filename or a quoted interpolation
    reached a sink with zero findings."""
    quoted = scan({"q.php": (
        b"<?php\n$id=$_GET['id'];\n$o=\"v ${'id'}\";\necho $o;\n"
    )})
    assert by_name(quoted, "reflected-request").detail == "q.php:4 echo"

    direct = scan({"f.php": b"<?php\necho $_FILES['f']['name'];\n"})
    assert by_name(direct, "reflected-request").detail == "f.php:2 echo"

    assigned = scan({"fa.php": (
        b"<?php\n$n=$_FILES['f']['name'];\necho $n;\n"
    )})
    assert by_name(assigned, "reflected-request").detail == "fa.php:3 echo"

    # PHP 8.4: in a STRING ``${'_GET'}`` interpolates the array ("Array");
    # the accessor after ``}`` is literal text, so this is static output.
    # The executable CODE spelling ``${'_GET'}['id']`` is covered below.
    quoted_super = scan({"s.php": (
        b"<?php\n$o=\"v ${'_GET'}['id']\";\necho $o;\n"
    )})
    assert not any(f.name == "reflected-request" for f in quoted_super)
    code_super = scan({"c.php": (
        b"<?php\n$o=${'_GET'}['id'];\necho $o;\n"
    )})
    assert by_name(code_super, "reflected-request").detail == "c.php:3 echo"


def test_C13_server_headers_are_request_data_but_peer_facts_are_not():
    """C13: only ``$_SERVER['HTTP_*']`` and REQUEST_URI carry attacker data;
    the masked single-quoted key used to hide the variable from the rewrite,
    so a reflected Host header was silent."""
    direct = scan({"h.php": b"<?php\necho $_SERVER['HTTP_HOST'];\n"})
    assert by_name(direct, "reflected-request").detail == "h.php:2 echo"

    assigned = scan({"ha.php": (
        b"<?php\n$h=$_SERVER['HTTP_HOST'];\necho $h;\n"
    )})
    assert by_name(assigned, "reflected-request").detail == "ha.php:3 echo"

    safe = scan({"safe.php": (
        b"<?php\n$ip=$_SERVER['REMOTE_ADDR'];\necho $ip;\n"
    )})
    assert not any(f.name == "reflected-request" for f in safe)


def test_R11_unquoted_and_commented_server_headers_are_request_data():
    """R11-P2-9: PHP accepts ``"$_SERVER[HTTP_HOST]"`` in simple
    interpolation, and comments are whitespace between the variable and
    its subscript.  Both are the same request value."""
    interpolated = scan({"i.php": (
        b'<?php\necho "H: $_SERVER[HTTP_HOST]";\n'
    )})
    assert by_name(interpolated, "reflected-request").detail == "i.php:2 echo"

    commented = scan({"c.php": (
        b"<?php\necho $_SERVER/*x*/['HTTP_HOST'];\n"
    )})
    assert by_name(commented, "reflected-request").detail == "c.php:2 echo"

    safe = scan({"s.php": (
        b"<?php\necho $_SERVER[REMOTE_ADDR];\n"
    )})
    assert not any(f.name == "reflected-request" for f in safe)


def test_R15_update_identifier_sees_heredoc_cte_and_comments():
    """R15-P2: the UPDATE prefix started at ``literal[0]+1`` (the
    ``<<<`` header for a heredoc), and a CTE/comment prefix read as prose,
    so assigned heredoc, ``WITH ... UPDATE`` and commented identifiers were
    never classified."""
    heredoc = scan({"h.php": (
        b"<?php\n$t=$_GET['t'];\n"
        b"$sql=<<<SQL\nUPDATE $t SET x=1\nSQL;\nsome_wrapper($sql);\n"
    )})
    assert by_name(heredoc, "sql-identifier").detail == "h.php:4 UPDATE"

    cte = scan({"c.php": (
        b"<?php\n$t=$_GET['t'];\n"
        b"$sql='WITH c AS (SELECT 1) UPDATE ' . $t . ' SET x=1';\n"
        b"some_wrapper($sql);\n"
    )})
    assert by_name(cte, "sql-identifier")

    commented = scan({"m.php": (
        b"<?php\n$t=$_GET['t'];\n"
        b"$sql='SELECT * FROM /*x*/ ' . $t;\nsome_wrapper($sql);\n"
    )})
    assert by_name(commented, "sql-identifier").detail == "m.php:3 FROM"


def test_R16_sql_comments_are_whitespace_and_cte_grammar_is_real():
    """R16-P2: MySQL comments are whitespace between grammar tokens, while
    a keyword inside a comment is dead.  ``WITH`` is accepted only with real
    CTE grammar, so English ``With the update ...`` stops minting a HIGH
    sql-identifier finding."""
    findings = scan({"c.php": (
        b"<?php $t=$_GET['t'];\n"
        b"$a=\"UPDATE/*x*/ $t SET a=1\";\n"
        b"some_wrapper($a);\n"
        b"$b=\"SELECT * FROM t /* FROM $t */ WHERE x=1\";\n"
        b"some_wrapper($b);\n"
        b"$c='WITH c AS (SELECT 1) UPDATE ' . $t . ' SET a=1';\n"
        b"some_wrapper($c);\n"
    )})
    identifier = by_name(findings, "sql-identifier")
    assert identifier.count == 2
    assert "c.php:2" in identifier.detail
    assert "c.php:6" in identifier.detail
    assert "c.php:4" not in identifier.detail

    prose = scan({"p.php": (
        b"<?php $n=$_GET['n'];\n"
        b"echo 'With the update ' . $n;\n"
    )})
    assert not any(f.name == "sql-identifier" for f in prose)


def test_R17_a_long_sql_comment_does_not_consume_the_grammar_window():
    """R17-5-P2: the window was sliced BEFORE comments were collapsed, so a
    comment crossing 8 KiB swallowed the real ``* FROM $t`` tokens and the
    identifier finding disappeared.  Comments are collapsed while the
    bounded view is collected."""
    for size in (8190, 8200, 20000):
        code = (b"<?php\n$t=$_GET['t'];\n$q=\"SELECT /*"
                + b"x" * size
                + b"*/ * FROM $t\";\n$pdo->prepare($q);\n")
        findings = scan({"long.php": code})
        assert by_name(findings, "sql-identifier").detail \
            == "long.php:3 FROM", size

    cte = (b"<?php\n$t=$_GET['t'];\n$q=\"WITH c /*"
           + b"x" * 20000
           + b"*/ AS (SELECT 1) UPDATE $t SET x=1\";\n"
             b"some_wrapper($q);\n")
    assert by_name(scan({"cte.php": cte}), "sql-identifier").detail \
        == "cte.php:3 UPDATE"


def test_R17_backtick_split_concatenation_completes_the_identifier():
    """R17-5-P2: inside a double-quoted literal the opening backtick is
    static text, so ``"SELECT * FROM `" . $t . "`"`` was never parsed as one
    identifier.  An unmatched (odd) trailing backtick now continues the
    expression; the complete backtick-quoted ``wp_users`` form stays
    silent."""
    from_file = scan({"from.php": (
        b"<?php\n$t=$_GET['t'];\n"
        b"$pdo->prepare(\"SELECT * FROM `\".$t.\"`\");\n")})
    assert by_name(from_file, "sql-identifier").detail == "from.php:3 FROM"

    update = scan({"update.php": (
        b"<?php\n$t=$_GET['t'];\n"
        b"$pdo->prepare(\"UPDATE `\".$t.\"` SET a=1\");\n")})
    assert by_name(update, "sql-identifier").detail == "update.php:3 UPDATE"

    complete = scan({"complete.php": (
        b"<?php\n$t=$_GET['t'];\n"
        b"$pdo->prepare(\"SELECT * FROM `wp_users`\");\n")})
    assert not any(f.name == "sql-identifier" for f in complete)


def test_R18_pdo_exec_is_a_sql_sink_and_single_quote_backtick_splits():
    """R18-P2: PDO's ``exec`` was not a sink, and the backtick-continuation
    rule only ran for interpolating literals (a single-quoted SQL prefix
    never interpolates PHP variables, but a backtick is still SQL text)."""
    exec_sink = scan({"exec.php": (
        b"<?php\n$id=$_GET['id'];\n"
        b"$pdo->exec(\"DELETE FROM wp_posts WHERE id=$id\");\n")})
    assert by_name(exec_sink, "sql-injection").detail == "exec.php:3 ->exec()"

    static = scan({"static.php": (
        b"<?php\n$id=$_GET['id'];\n"
        b"PDO::exec(\"DELETE FROM wp_posts WHERE id=$id\");\n")})
    assert by_name(static, "sql-injection").detail == "static.php:3 ::exec()"

    dynamic = scan({"table.php": (
        b"<?php\n$t=$_GET['t'];\n"
        b"$pdo->exec(\"DELETE FROM $t\");\n")})
    assert by_name(dynamic, "sql-identifier").detail == "table.php:3 FROM"

    single = scan({"single.php": (
        b"<?php\n$t=$_GET['t'];\n"
        b"$pdo->prepare('SELECT * FROM `' . $t . '` WHERE a=1');\n")})
    assert by_name(single, "sql-identifier").detail == "single.php:3 FROM"


def test_R18_sql_grammar_window_handles_long_lists_and_split_prefixes():
    """R18-P2: the fixed 8,192-byte grammar cut hid a real SELECT whose
    column list pushed FROM past the window; and ``INSERT INTO``/``DELETE
    FROM`` prefixes split across a concatenation read as prose."""
    columns = ", ".join(f"c{i}" for i in range(3000))
    long_select = scan({"long.php": (
        f"<?php\n$t=$_GET['t'];\n$q=\"SELECT {columns} FROM $t\";\n"
    ).encode()})
    assert by_name(long_select, "sql-identifier").detail == "long.php:3 FROM"

    for name, sql, keyword in (
        ("insert.php", "INSERT INTO ", "INTO"),
        ("delete.php", "DELETE FROM ", "FROM"),
    ):
        findings = scan({name: (
            f"<?php\n$t=$_GET['t'];\n$q='{sql}' . $t . ' WHERE a=1';\n"
        ).encode()})
        assert by_name(findings, "sql-identifier").detail \
            == f"{name}:3 {keyword}"

    # Newline spellings PHP renders before MySQL sees the text stay a
    # word boundary in the same SQL view.
    for escape in (r"\n", r"\r", r"\x0a", r"\x0d"):
        findings = scan({"newline.php": (
            f"<?php\n$t=$_GET['t'];\n$q=\"SELECT a{escape}FROM $t\";\n"
        ).encode()})
        assert by_name(findings, "sql-identifier").detail \
            == "newline.php:3 FROM", escape


def test_R19_php_escaped_braced_superglobals_are_request_data():
    r"""R19-P2: ``${"\x5fGET"}``, ``${"\137GET"}`` and ``${"\u{5f}GET"}``
    are all ``$_GET`` at runtime (PHP decodes the quoted NAME).  The mask
    and classifier compared raw escape text, so every spelling hid the
    superglobal from the scan."""
    for escape in (r"\x5fGET", r"\137GET", r"\u{5f}GET"):
        findings = scan({"e.php": (
            f'<?php echo ${{"{escape}"}}["x"];\n'.encode()
        )})
        assert by_name(findings, "reflected-request").detail \
            == "e.php:1 echo", escape

    # A non-request name spelled the same way stays inert.
    inert = scan({"i.php": (
        b'<?php echo ${"\\x5fSERVER"}["REMOTE_ADDR"];\n'
    )})
    assert not any(f.name == "reflected-request" for f in inert)


def test_R19_update_split_at_the_verb_detects_dynamic_target_and_set():
    """R19-P2: ``"UPDATE " . $table . " SET ..."`` splits the statement at
    the VERB; the literal alone carried no target, so the dynamic
    identifier was never classified.  Prose stays silent, and the
    INSERT/DELETE keyword-only prefixes share the same continuation rule."""
    update = scan({"u.php": (
        b"<?php\n$t=$_GET['t'];\n"
        b"$q=\"UPDATE \" . $t . \" SET a=1\";\n")})
    assert by_name(update, "sql-identifier").detail == "u.php:3 UPDATE"

    insert = scan({"i.php": (
        b"<?php\n$t=$_GET['t'];\n"
        b"$q=\"INSERT INTO \" . $t . \" VALUES (1)\";\n")})
    assert by_name(insert, "sql-identifier").detail == "i.php:3 INTO"

    delete = scan({"d.php": (
        b"<?php\n$t=$_GET['t'];\n"
        b"$q=\"DELETE FROM \" . $t . \" WHERE a=1\";\n")})
    assert by_name(delete, "sql-identifier").detail == "d.php:3 FROM"

    prose = scan({"p.php": (
        b"<?php\n$n=$_GET['n'];\n"
        b"echo \"Update \" . $n;\n"
        b"echo \"Insert into \" . $n . \" failed\";\n")})
    assert not any(f.name == "sql-identifier" for f in prose)


def test_R16_quoted_server_accessor_skips_php_whitespace_and_comments():
    """R16-P2: ``${'_SERVER'} /*c*/ ['HTTP_HOST']`` and the spaced/newline
    forms are the same request read at runtime; the accessor skip must treat
    PHP comments as whitespace on the outside of the braces too."""
    findings = scan({"s.php": (
        b"<?php\n"
        b"$a=\"SELECT * FROM \" . ${'_SERVER'} /*c*/ ['HTTP_HOST'];\n"
        b"$b=\"SELECT * FROM \" . ${'_SERVER'}\n['HTTP_HOST'];\n"
        b"$c=\"SELECT * FROM \" . ${'_SERVER'} ['HTTP_HOST'];\n"
        b"some_wrapper($a . $b . $c);\n"
    )})
    assert by_name(findings, "sql-identifier").count == 3

    safe = scan({"safe.php": (
        b"<?php $ip=${'_SERVER'} /*c*/ ['REMOTE_ADDR'];\n"
        b"$sql=\"SELECT * FROM $ip\";\n"
        b"some_wrapper($sql);\n"
    )})
    assert not any(f.name == "sql-identifier" for f in safe)


def test_R15_quoted_server_in_identifier_position_is_request_data():
    """R15-P2: the quoted braced branch returned only superglobal
    membership, never applying the ``_SERVER`` request-key rule, so
    ``${'_SERVER'}['HTTP_HOST']`` in an identifier was silent."""
    findings = scan({"s.php": (
        b"<?php\n$sql=\"SELECT * FROM \" . ${'_SERVER'}['HTTP_HOST'];\n"
        b"some_wrapper($sql);\n"
    )})
    assert by_name(findings, "sql-identifier")

    safe = scan({"safe.php": (
        b"<?php\n$sql=\"SELECT * FROM \" . ${'_SERVER'}['REMOTE_ADDR'];\n"
        b"some_wrapper($sql);\n"
    )})
    assert not any(f.name == "sql-identifier" for f in safe)


@pytest.mark.parametrize("expression", [
    "${ '_GET'}['c']",
    "${/*c*/'_GET'}['c']",
    "${\n'_GET'}['c']",
])
def test_R15_braced_php_whitespace_and_comments_keep_request_taint(
        expression):
    """R15-P2: the renderer emitted ``$ _GET`` (dollar, space, name), which
    every matcher missed; PHP 8.4 evaluates every one of these."""
    findings = scan({"a.php": (
        f"<?php system({expression});").encode()})
    assert by_name(findings, "code-execution").detail == "a.php:1 system()"


def test_R11_english_update_is_not_a_sql_identifier():
    """R11-P2-9: the word UPDATE in prose was both keyword and "SQL
    context", so a reflected request raised a HIGH sql-identifier finding
    with no query anywhere.  Real UPDATE grammar still reports."""
    prose = scan({"p.php": (
        b"<?php\n$name=$_GET['n']; echo 'Please update ' . $name;\n"
    )})
    assert [f.name for f in prose] == ["reflected-request"]

    sql = scan({"q.php": (
        b"<?php\n$t=$_GET['t'];\n$sql=\"UPDATE $t SET x=1\";\n"
    )})
    assert by_name(sql, "sql-identifier").detail == "q.php:3 UPDATE"


def test_SRC_4_output_member_and_variable_names_are_not_the_construct():
    findings = scan({"a.php": (
        b"<?php\n"
        b"$print = isset($_GET['print']) ? '1' : '';\n"
        b"$obj->print($_GET['q']);\n"
        b"print $_GET['q'];\n"
    )})
    finding = by_name(findings, "reflected-request")
    assert finding.detail == "a.php:4 print"


def test_SRC_5_multiline_sinks_are_seen():
    reflected = scan({"a.php": (
        b"<?php\n"
        b"echo sprintf(\n"
        b"    '%s',\n"
        b"    $_GET['q']\n"
        b");\n"
    )})
    assert any(f.name == "reflected-request" for f in reflected)

    sql = scan({"b.php": (
        b"<?php\n"
        b"$wpdb->query(\n"
        b"    \"DELETE FROM t WHERE id=\" . $_GET['id']\n"
        b");\n"
    )})
    assert by_name(sql, "sql-injection").detail == "b.php:2 ->query()"


def test_SRC_6_prepare_wrapped_request_data_is_not_sql_injection():
    safe = scan({"safe.php": (
        b"<?php\n"
        b"$wpdb->query($wpdb->prepare(\"SELECT * FROM t WHERE id=%d\", "
        b"$_GET['id']));\n"
    )})
    assert not any(f.name == "sql-injection" for f in safe)

    unsafe = scan({"unsafe.php": (
        b"<?php\n"
        b"$wpdb->query($wpdb->prepare(\"SELECT * FROM t WHERE id=%d\", "
        b"$id) . $_GET['x']);\n"
    )})
    assert any(f.name == "sql-injection" for f in unsafe)


# ------------------------------------------------------- triple-check round 2


def test_R6_47_first_argument_end_is_backtick_and_comment_aware():
    """R6-47: ``_first_argument_end`` stopped at the comma inside a backtick
    shell-command string and skipped line comments to the newline (not the
    shared ``?>`` stopper), so a request value interpolated in the prepare
    QUERY argument produced no finding."""
    from wpt.audit.source_scan import _first_argument_end

    text = "`a, b`, c"
    assert _first_argument_end(text, 0, len(text)) == text.index(", c")

    block = "`a, b` /* , */ , c"
    assert _first_argument_end(block, 0, len(block)) == block.rindex(",")

    line = "`a, b` // ,\n, c"
    assert _first_argument_end(line, 0, len(line)) == line.rindex(",")

    unsafe = scan({"a.php": (
        b"<?php\n"
        b"$wpdb->query($wpdb->prepare(`printf '%s', {$_GET[\"x\"]}`, 1));\n"
    )})
    assert by_name(unsafe, "sql-injection")


def test_SCAN1_prepare_first_argument_and_trailing_concat_stay_injectable():
    """SCAN1: ``_prepare_argument`` inspected only the text after the
    prepare call, so request data concatenated into the QUERY argument (or
    a tainted ``$sql`` variable) was treated as bound."""
    for name, body in {
        "literal": (b"$wpdb->query($wpdb->prepare(\"SELECT * FROM t "
                    b"WHERE id = \" . $_GET['id']));\n"),
        "variable": (b"$sql = \"SELECT * FROM t WHERE id = \" . "
                     b"$_GET['id'];\n"
                     b"$wpdb->query($wpdb->prepare($sql));\n"),
        "trailing": (b"$wpdb->query($wpdb->prepare(\"SELECT * FROM t "
                     b"WHERE id=%d\", $_GET['id']) . $_GET['x']);\n"),
    }.items():
        findings = scan({"a.php": b"<?php\n" + body})
        assert by_name(findings, "sql-injection"), name

    # parent::prepare is valid PHP and binds its second argument.
    safe = scan({"safe.php": (
        b"<?php\n$wpdb->query(parent::prepare(\"SELECT * FROM t "
        b"WHERE id=%d\", $_GET['id']));\n")})
    assert not any(f.name == "sql-injection" for f in safe)


def test_SCAN2_indexed_and_property_lvalues_taint_their_base():
    """SCAN2: ``_ASSIGN_RE`` matched only a bare ``$name``; an indexed or
    property lvalue was invisible to the taint set."""
    data = scan({"a.php": (
        b"<?php\n"
        b"$data['q'] = $_GET['q'];\n"
        b"echo $data['q'];\n"
        b"$data['sid'] = $_GET['sid'];\n"
        b"session_id($data['sid']);\n"
        b"$data['id'] = $_GET['id'];\n"
        b"$wpdb->query(\"DELETE FROM t WHERE id=$data[id]\");\n")})
    assert by_name(data, "reflected-request").detail == "a.php:3 echo"
    assert by_name(data, "session-fixation").detail == "a.php:5 session_id()"
    assert by_name(data, "sql-injection").detail == "a.php:7 ->query()"

    prop = scan({"b.php": (
        b"<?php\n$o->q = $_GET['q'];\necho $o->q;\n")})
    assert by_name(prop, "reflected-request").detail == "b.php:3 echo"


def test_SCAN3_sql_lexing_is_whole_file_and_statement_aware():
    """SCAN3: per-line masks invented findings in a multi-line comment or
    nowdoc (PHP never executes them) and hid a query whose SELECT sat on
    the line before its FROM."""
    dead = scan({"dead.php": (
        b"<?php\n$table=$_GET['t'];\n"
        b"/*\nSELECT * FROM $table\n*/\n"
        b"$x = <<<'SQL'\nSELECT * FROM $table\nSQL;\n"
        b"$doc = 'doc\nSELECT * FROM $table';\n")})
    assert not any(f.name == "sql-identifier" for f in dead)

    dynamic = scan({"dyn.php": (
        b"<?php\n$table=$_GET['t'];\n"
        b"$sql = \"SELECT *\nFROM $table\";\n"
        b"$wpdb->query($wpdb->prepare(\"SELECT *\nFROM $table WHERE "
        b"id=%d\", $_GET['id']));\n")})
    finding = by_name(dynamic, "sql-identifier")
    assert finding.count == 2
    assert finding.detail.splitlines() == ["dyn.php:4 FROM", "dyn.php:6 FROM"]


def test_SCAN4_include_variable_and_method_names_are_not_the_construct():
    """SCAN4: the gate never called ``_member_call``, so ``$include(...)``,
    ``$tpl->include(...)`` and ``Tpl::include(...)`` — all valid PHP names —
    were reported as file inclusion."""
    safe = scan({"a.php": (
        b"<?php\n"
        b"$include($_GET['p']);\n"
        b"$tpl->include($_GET['p']);\n"
        b"Tpl::include($_GET['p']);\n")})
    assert not any(f.name == "file-include" for f in safe)

    direct = scan({"b.php": b"<?php\ninclude $_GET['p'];\n"})
    assert by_name(direct, "file-include").detail == "b.php:2 include"


def test_SCAN5_static_identifier_prefixes_continue_into_interpolation():
    """SCAN5: the identifier scan returned at the first static token, so
    ``wp_$table``, ``{$wpdb->prefix}$table`` and a leading concat were
    silently clean; a static table followed by a tainted VALUE stays clean."""
    findings = scan({"a.php": (
        b"<?php\n$table=$_GET['t'];\n"
        b"$sql=\"SELECT * FROM wp_$table\";\n"
        b"$sql=\"SELECT * FROM {$wpdb->prefix}$table\";\n"
        b"$sql=\"SELECT * FROM \" . $wpdb->prefix . $table;\n"
        b"$id=$_GET['id'];\n"
        b"$sql='SELECT * FROM wp_users WHERE id=' . $id;\n")})
    finding = by_name(findings, "sql-identifier")
    assert finding.count == 3
    assert finding.detail.splitlines() == [
        "a.php:3 FROM", "a.php:4 FROM", "a.php:5 FROM"]


def test_N3_single_quoted_prefix_concat_continues_to_the_identifier():
    """N3: a static prefix in a single-quoted literal followed by PHP
    concatenation was read as a complete static table, so the request-driven
    suffix was never seen as the identifier."""
    findings = scan({"a.php": (
        b"<?php\n$t=$_GET['t'];\n"
        b"$sql='SELECT * FROM wp_' . $t;\n"
        b"$sql='SELECT * FROM ' . 'wp_' . $t;\n"
        b"$sql=\"SELECT * FROM wp_\" . $t;\n"
        b"$sql='SELECT * FROM ' . 'wp_' . $t . ' WHERE id=1';\n"
        b"$sql=\"SELECT * FROM wp_users WHERE id=$t\";\n"
        b"$sql='SELECT * FROM wp_$t';\n")})
    finding = by_name(findings, "sql-identifier")
    assert finding.count == 4
    assert finding.detail.splitlines() == [
        "a.php:3 FROM", "a.php:4 FROM", "a.php:5 FROM", "a.php:6 FROM"]


def test_SCAN5_a_tainted_value_after_a_static_table_is_not_an_identifier():
    """SCAN5 FP: the double-literal branch checked the whole remainder, so a
    tainted WHERE value was reported as the table identifier."""
    findings = scan({"a.php": (
        b"<?php\n$id=$_GET['id'];\n"
        b"$sql=\"SELECT * FROM wp_users WHERE id=$id\";\n"
        b"$sql='SELECT * FROM wp_users WHERE id=' . $id;\n"
        b"$sql=\"UPDATE wp_users SET x=$id\";\n"
        b"$sql=\"JOIN wp_users ON wp_users.id=$id\";\n")})
    assert not any(f.name == "sql-identifier" for f in findings)


def test_SCAN5_a_completed_static_table_before_a_tainted_clause_is_not_dynamic():
    """SCAN5 FP: the literal ended immediately after a COMPLETE static table,
    so the concatenated tainted WHERE fragment (or any other clause) was
    read as the table identifier.  The identifier expression ends at the
    completed name; the tainted value starts another clause."""
    findings = scan({"a.php": (
        b"<?php\n$where=$_GET['where'];\n$id=$_GET['id'];\n"
        b"$sql=\"SELECT * FROM wp_users\" . $where;\n"
        b"$sql='SELECT * FROM wp_users' . $where;\n"
        b"$sql=\"SELECT * FROM wp_users WHERE id=\" . $id;\n"
        b"$sql=\"UPDATE wp_users\" . $where;\n"
        b"$sql=\"JOIN wp_users\" . $where;\n")})
    assert not any(f.name == "sql-identifier" for f in findings)


def test_SCAN5_an_incomplete_static_prefix_still_continues_into_taint():
    """The completed-table rule must not silence a real prefix concat: a
    trailing ``_`` (or a dynamic prefix expression) leaves the identifier
    open, so the request-driven suffix is still the table name (N3)."""
    findings = scan({"a.php": (
        b"<?php\n$t=$_GET['t'];\n"
        b"$sql=\"SELECT * FROM wp_\" . $t;\n"
        b"$sql=\"SELECT * FROM \" . 'wp_' . $t;\n"
        b"$sql=\"SELECT * FROM {$wpdb->prefix}\" . $t;\n"
        b"$sql=\"UPDATE wp_\" . $t;\n")})
    finding = by_name(findings, "sql-identifier")
    assert finding.count == 4
    assert finding.detail.splitlines() == [
        "a.php:3 FROM", "a.php:4 FROM", "a.php:5 FROM", "a.php:6 UPDATE"]


def test_SCAN1_arbitrary_class_static_prepare_is_the_bound_pattern():
    """SCAN1 FP: ``_PREPARE_AT_RE`` accepted only $var/self/static/parent, so
    a normal class-static ``DB::prepare`` was reported as injection."""
    for call in (b"DB::prepare", b"\\DB::prepare", b"Helper\\DB::prepare",
                 b"self::prepare", b"parent::prepare", b"static::prepare"):
        code = (b"<?php\n$wpdb->query(" + call
                + b"(\"SELECT * FROM t WHERE id=%d\", $_GET['id']));\n")
        findings = scan({"safe.php": code})
        assert not any(f.name == "sql-injection" for f in findings), call

    unsafe = scan({"bad.php": (
        b"<?php\n$wpdb->query(DB::prepare(\"SELECT * FROM t WHERE id=\" . "
        b"$_GET['id']));\n")})
    assert by_name(unsafe, "sql-injection")


def test_SCAN6_dollar_escape_parity_is_honoured():
    """SCAN6: ``\\$`` blanking ignored the backslash run, so ``"\\\\$_GET"``
    (a real interpolation) was missed and ``"\\$table"`` (literal PHP text)
    was reported."""
    reflected = scan({"a.php": (
        b"<?php\n$q=$_GET['q'];\necho \"\\\\\\\\$_GET[x]\";\n")})
    assert by_name(reflected, "reflected-request").detail == "a.php:3 echo"

    literal = scan({"b.php": (
        b"<?php\n$table=$_GET['t'];\n"
        b"$sql=\"SELECT * FROM \\$table\";\n")})
    assert not any(f.name == "sql-identifier" for f in literal)


# ---------------------------------------------------- round-3 regressions


def test_SCAN_GETCOL_is_a_sql_sink():
    """SCAN-GETCOL: wpdb::get_col executes SQL but was absent from
    _SQL_SINKS_RE, so a direct injection returned a false clean while the
    identical get_var reported."""
    code = (
        "<?php $name=$_GET['name']; "
        "$wpdb->get_col(\"SELECT option_value FROM wp_options "
        "WHERE option_name='$name'\");"
    )
    findings = scan({"getcol.php": code.encode()})
    assert by_name(findings, "sql-injection").detail == \
        "getcol.php:1 ->get_col()"
    control = scan({"getvar.php": code.replace("get_col", "get_var").encode()})
    assert by_name(control, "sql-injection").detail == \
        "getvar.php:1 ->get_var()"


def test_SCAN_FOREACH_bindings_join_the_fixed_point():
    """SCAN-FOREACH: only a literal ``foreach ($_GET …)`` tainted its
    bindings; an assigned array and an accessor form both missed."""
    assigned = scan({"a.php": (
        b"<?php $ids=$_GET['ids']; foreach ($ids as $id) { "
        b"$wpdb->query(\"SELECT * FROM t WHERE id=$id\"); }")})
    assert by_name(assigned, "sql-injection")
    accessor = scan({"b.php": (
        b"<?php foreach ($_GET['ids'] as $id) { "
        b"$wpdb->query(\"SELECT * FROM t WHERE id=$id\"); }")})
    assert by_name(accessor, "sql-injection")
    # The iterable is still evidence-gated: a literal array is not taint.
    clean = scan({"c.php": (
        b"<?php $ids=[1,2]; foreach ($ids as $id) { "
        b"$wpdb->query(\"SELECT * FROM t WHERE id=$id\"); }")})
    assert not any(f.name == "sql-injection" for f in clean)


def test_SCAN_PREPARE_ASSIGN_a_clean_prepare_rhs_is_bound():
    """SCAN-PREPARE-ASSIGN: any RHS containing $_GET tainted the LHS, so a
    clean prepare() assigned to $sql and later queried reported injection
    while the inline identical call was silent."""
    clean = scan({"a.php": (
        b"<?php $sql=$wpdb->prepare(\"SELECT * FROM t WHERE id=%d\", "
        b"$_GET['id']); $wpdb->query($sql);")})
    assert not any(f.name == "sql-injection" for f in clean)
    # Concatenation into the query text (or after the call) still injects.
    concat = scan({"b.php": (
        b"<?php $sql=$wpdb->prepare(\"SELECT * FROM t WHERE id=\" . "
        b"$_GET['id']); $wpdb->query($sql);")})
    assert by_name(concat, "sql-injection")
    trailing = scan({"c.php": (
        b"<?php $sql=$wpdb->prepare(\"SELECT * FROM t WHERE id=%d\", "
        b"$_GET['id']) . $_GET['x']; $wpdb->query($sql);")})
    assert by_name(trailing, "sql-injection")


def test_SCAN_PREPARE_CHAIN_repeated_member_links_are_the_bound_form():
    """SCAN-PREPARE-CHAIN: _PREPARE_AT_RE allowed one member/static hop, so
    ``$this->wpdb->prepare`` and ``self::$wpdb->prepare`` were false
    positives while $wpdb->prepare was clean."""
    for name, call in {
        "member.php": "$this->wpdb->prepare",
        "static.php": "self::$wpdb->prepare",
        "nullable.php": "$this?->wpdb->prepare",
    }.items():
        findings = scan({name: (
            "<?php $this->wpdb->query(" + call
            + "(\"SELECT * FROM t WHERE id=%d\", $_GET['id']));").encode()})
        assert not any(f.name == "sql-injection" for f in findings), name
    unsafe = scan({"bad.php": (
        b"<?php $this->wpdb->query($this->wpdb->prepare("
        b"\"SELECT * FROM t WHERE id=\" . $_GET['id']));")})
    assert by_name(unsafe, "sql-injection")


def test_SCAN_DOLLAR_BRACE_interpolation_uses_the_same_variable():
    """SCAN-DOLLAR-BRACE: ``${t}`` was read as static text, so an injected
    identifier through a wrapper returned clean while ``{$t}``/``$t``
    reported."""
    findings = scan({"a.php": (
        b"<?php $t=$_GET['t']; "
        b"$sql=\"SELECT * FROM ${t}\"; some_wrapper($sql);")})
    assert by_name(findings, "sql-identifier").detail == "a.php:1 FROM"
    braced = scan({"b.php": (
        b"<?php $t=$_GET['t']; "
        b"$sql=\"SELECT * FROM {$t}\"; some_wrapper($sql);")})
    assert by_name(braced, "sql-identifier")
    escaped = scan({"c.php": (
        b"<?php $t=$_GET['t']; "
        b"$sql=\"SELECT * FROM \\${t}\"; some_wrapper($sql);")})
    assert not any(f.name == "sql-identifier" for f in escaped)


def test_SCAN_PHP_MODE_inline_html_is_not_sql_and_cannot_corrupt_the_view():
    """SCAN-PHP-MODE: SQL views scanned raw text, so a SELECT in HTML
    reported, an HTML apostrophe swallowed the next real query, and an HTML
    ``//`` blanked it.  Only PHP segments are SQL, and ``\\n`` in an
    interpolating literal is a word boundary when PHP renders it."""
    html_only = scan({"a.php": (
        b"<?php $t=$_GET['t']; ?><p>SELECT * FROM $t</p>")})
    assert not any(f.name == "sql-identifier" for f in html_only)

    for prefix in (b"<p>It's</p>", b"<p>// not php</p>",
                   b"<!-- a ' and // b -->"):
        findings = scan({"b.php": prefix + (
            b"<?php $t=$_GET['t']; "
            b"$sql='SELECT * FROM ' . $t; some_wrapper($sql);")})
        assert by_name(findings, "sql-identifier"), prefix

    newline = scan({"c.php": (
        b"<?php $t=$_GET['t']; "
        b"$sql=\"SELECT *\\nFROM $t\"; some_wrapper($sql);")})
    assert by_name(newline, "sql-identifier").detail == "c.php:1 FROM"


def test_SCAN_QUAD_many_echo_tags_are_linear_and_deadline_bounded():
    """SCAN-QUAD: every ``<?=`` re-lexed its prefix (3,200 tags ~4 s; 1 MiB
    could run for hours).  Tag offsets come from the one-pass lexer, spans
    are precomputed, and a 1 MiB file checks the run deadline per phase."""
    import time

    from wpt.deadline import Deadline
    from wpt.settings import Settings
    from wpt.types import DeadlineExceeded
    import wpt.audit.source_scan as source_scan

    tags = "<?=1?>" * 3200
    source = FakeSource()
    source.files["many.php"] = tags.encode()
    data = data_for(source)
    data.deadline = Deadline(COMPLETION_DEADLINE_S)
    started = time.monotonic()
    findings = check_security_source_patterns(data, DEFAULTS)
    elapsed = time.monotonic() - started
    assert not findings
    assert elapsed < COMPLETION_CEILING_S, elapsed

    # A tainted statement still reports once among thousands of echo tags.
    mixed = "<?=1?>" * 1600 + "<?=$_GET['x']?>" + "<?=1?>" * 1599
    source.files["mixed.php"] = mixed.encode()
    reported = check_security_source_patterns(data_for(source), DEFAULTS)
    assert by_name(reported, "reflected-request").count == 1

    # The per-file phase checks engage at the 1 MiB cap: an already-expired
    # budget must raise through the partial path, never finish "clean".
    huge = FakeSource()
    huge.files["huge.php"] = (
        "<?php $t=$_GET['t']; " + "<?=1?>" * 150000).encode()
    data = data_for(huge)
    data.deadline = Deadline(0.0001)
    with pytest.raises(DeadlineExceeded):
        source_scan._scan_file(
            huge.files["huge.php"].decode(), "huge.php", Settings(),
            {}, data.deadline)


def test_SCAN_QUAD_small_sql_dense_file_has_a_real_deadline_and_last_batch_check():
    """SCAN-QUAD residual: files below 256 KiB DROPPED the deadline, so a
    112 KB/4 000-keyword file scanned 4.71 s after a 0.5 s budget and the
    command answered rc 0.  Every file (any size) is now deadline-checked
    before/after, and the last batch check can never be skipped."""
    import time

    from wpt.deadline import Deadline
    from wpt.settings import Settings
    from wpt.types import DeadlineExceeded
    import wpt.audit.source_scan as source_scan

    dense = ('<?php $sql="'
             + "SELECT * FROM t WHERE id=1; " * 4000 + '";')
    settings = Settings()
    started = time.monotonic()
    source_scan._scan_file(
        dense, "dense.php", settings, {},
        Deadline(COMPLETION_DEADLINE_S))
    elapsed = time.monotonic() - started
    assert elapsed < COMPLETION_CEILING_S, elapsed

    # The SAME small file under an already-spent budget must raise; the old
    # size gate silently disabled this check below 256 KiB.
    with pytest.raises(DeadlineExceeded):
        source_scan._scan_file(
            dense, "dense.php", settings, {}, Deadline(0.0001))

    # End-of-batch (last file) expiry is reported as scan-partial, never a
    # clean pass: this deadline expires only at the batch completion check.
    class _ExpireAtBatchEnd:
        def check(self, context):
            if context == "source scan batch":
                raise DeadlineExceeded(f"run deadline exceeded at {context!r}")

    source = FakeSource()
    source.files["a.php"] = b"<?php session_id($_GET['s']);\n"
    data = data_for(source)
    data.deadline = _ExpireAtBatchEnd()
    findings = check_security_source_patterns(data, DEFAULTS)
    assert [finding.name for finding in findings] == [
        "session-fixation", "scan-partial"]
    assert "1 of 1" in findings[1].detail

    # THREE such 112 KB files under one 0.5 s budget: the old public probe
    # took 33.99 s.  The single sink pass plus per-file checks bound it.
    three = FakeSource()
    for index in range(3):
        three.files[f"dense{index}.php"] = dense.encode()
    data = data_for(three)
    data.deadline = Deadline(0.5)
    started = time.monotonic()
    findings = check_security_source_patterns(data, DEFAULTS)
    elapsed = time.monotonic() - started
    assert elapsed < EXPIRY_CEILING_S, elapsed
    assert not [finding for finding in findings
                if finding.name != "scan-partial"]


def test_SCAN_QUAD_540KiB_20k_keywords_is_linear_and_deadline_bounded():
    """SCAN-QUAD: 540 KB / 20 000 SQL keywords took 99.8 s because every
    keyword rescanned its whole statement.  The single sink pass makes it
    linear, and a budget it cannot meet yields scan-partial near the
    budget."""
    import time

    from wpt.deadline import Deadline

    source = FakeSource()
    source.files["dense.php"] = (
        '<?php $sql="' + "SELECT * FROM t WHERE id=1; " * 20000
        + '";').encode()
    data = data_for(source)
    data.deadline = Deadline(COMPLETION_DEADLINE_S)
    started = time.monotonic()
    findings = check_security_source_patterns(data, DEFAULTS)
    elapsed = time.monotonic() - started
    assert not findings
    assert elapsed < COMPLETION_CEILING_S, elapsed

    source = FakeSource()
    source.files["dense.php"] = (
        '<?php $sql="' + "SELECT * FROM t WHERE id=1; " * 20000
        + '";').encode()
    data = data_for(source)
    data.deadline = Deadline(0.1)
    started = time.monotonic()
    findings = check_security_source_patterns(data, DEFAULTS)
    elapsed = time.monotonic() - started
    assert [finding.name for finding in findings] == ["scan-partial"]
    assert "run deadline exceeded" in findings[0].detail
    assert elapsed < EXPIRY_CEILING_S, elapsed


def _names(findings):
    return {finding.name for finding in findings}


def test_SCAN_COMMENT_CLOSE_line_comment_ends_at_php_close_tag():
    """SCAN-COMMENT-CLOSE: `//` (and `#`) comments end at `?>`, which also
    ends PHP mode; skipping to the newline crossed into the next echo block
    and let its sanitizer suppress a real reflected sink."""
    for php in (
        b"<?= $_GET['x'] // ?> <?= htmlspecialchars('safe') ?>",
        b"<?php echo $_GET['x'] # ?> <?php echo htmlspecialchars('safe'); ?>",
    ):
        findings = scan({PLUGIN: php})
        assert "reflected-request" in _names(findings), php


def test_SCAN_COMMENT_WHITESPACE_is_php_whitespace_everywhere():
    """SCAN-COMMENT-WHITESPACE: comments are PHP whitespace, so every
    name/sink/member/sanitizer regex must see through them."""
    # A member sink split by a comment still executes.
    assert "sql-injection" in _names(scan({PLUGIN: (
        b"<?php $wpdb-> /* c */ query(\"DELETE FROM t WHERE id=\" . "
        b"$_GET['id']);")}))
    # Assignment, foreach and a function sink.
    assert "reflected-request" in _names(scan({PLUGIN: (
        b"<?php $id /* c */ = $_GET['id']; echo $id;")}))
    assert "reflected-request" in _names(scan({PLUGIN: (
        b"<?php foreach /* c */ ($_GET['ids'] as $id) { echo $id; }")}))
    assert "sql-injection" in _names(scan({PLUGIN: (
        b"<?php mysqli_query /* c */ (\"DELETE FROM t WHERE id=\" . "
        b"$_GET['id']);")}))
    # A commented sanitizer still sanitizes; a commented member include is
    # a method call, not the include construct.
    clean = scan({PLUGIN: (
        b"<?php echo htmlspecialchars /* c */ ($_GET['x']);")})
    assert "reflected-request" not in _names(clean)
    member = scan({PLUGIN: (
        b"<?php $obj-> /* c */ include($_GET['x']);")})
    assert "file-include" not in _names(member)


def test_SCAN_PREPARE_STATIC_non_request_variables_are_bound():
    """SCAN-PREPARE-STATIC: any variable in the query text rejected the
    prepare; only a REQUEST-TAINTED reference makes it unbound."""
    static = scan({PLUGIN: (
        b"<?php $t='wp_posts'; "
        b"$sql=$wpdb->prepare(\"SELECT * FROM $t WHERE id=%d\", $_GET['id']); "
        b"$wpdb->query($sql);")})
    assert "sql-injection" not in _names(static)
    prefix = scan({PLUGIN: (
        b"<?php $sql=$wpdb->prepare(\"SELECT * FROM {$wpdb->prefix}posts "
        b"WHERE id=%d\", $_GET['id']); $wpdb->query($sql);")})
    assert "sql-injection" not in _names(prefix)
    prop = scan({PLUGIN: (
        b"<?php $sql=$wpdb->prepare(\"SELECT * FROM $this->table "
        b"WHERE id=%d\", $_GET['id']); $wpdb->query($sql);")})
    assert "sql-injection" not in _names(prop)
    # A query built from request data is still injection, both assigned and
    # concatenated.
    tainted = scan({PLUGIN: (
        b"<?php $t=$_GET['t']; "
        b"$sql=$wpdb->prepare(\"SELECT * FROM $t WHERE id=%d\", $_GET['id']); "
        b"$wpdb->query($sql);")})
    assert "sql-injection" in _names(tainted)
    concat = scan({PLUGIN: (
        b"<?php $sql=$wpdb->prepare(\"SELECT * FROM \" . $_GET['t'], 1); "
        b"$wpdb->query($sql);")})
    assert "sql-injection" in _names(concat)


@pytest.mark.parametrize("escape", [b"\\x0a", b"\\x20", b"\\u{a}", b"\\n"])
def test_SCAN_HEX_WHITESPACE_escapes_still_present_a_word_boundary(escape):
    """SCAN-HEX-WHITESPACE: only \\nrtvef were normalized; \\xNN/\\u{...}
    whitespace hid the identifier keyword."""
    php = (b"<?php $t=$_GET['t']; $sql=\"SELECT *" + escape
           + b"FROM $t\"; some_wrapper($sql);")
    findings = scan({PLUGIN: php})
    assert "sql-identifier" in _names(findings), escape


def test_SCAN_EMPTY_DEADLINE_slow_empty_walk_is_not_a_clean_zero():
    """SCAN-EMPTY-DEADLINE: the deadline was checked before and per yielded
    entry, never after the walk, so a slow walk yielding NOTHING returned
    entries=0 and the security gate reported clean after its budget."""
    import time

    from wpt.deadline import Deadline

    class SlowEmpty(FakeSource):
        def walk(self, path="", *, include_links=False):
            time.sleep(0.05)
            return iter(())

    with pytest.raises(DeadlineExceeded):
        gather_source(SlowEmpty(), "local", deadline=Deadline(0.02))


# ------------------------------------------------------- triple-check round 6


def _r6_names(text, settings=DEFAULTS):
    return {finding.name for finding in scan({PLUGIN: text.encode()}, settings)}


def test_R6_14_line_comment_stops_at_the_php_close_tag():
    """R6-14: a ``//`` comment crossed ``?>`` and blanked the following
    same-line ``<?php`` block in the SQL/literal views, hiding its query."""
    text = ('<?php $t=$_GET["t"]; // c ?> '
            '<?php $sql="SELECT * FROM $t"; some($sql); ?>')
    assert "sql-identifier" in _r6_names(text)


@pytest.mark.parametrize(("text", "expected"), [
    ('<?php echo `echo hi; ` . $_GET["x"];', "reflected-request"),
    ('<?php system(`case x in x) echo hi;; esac;` . $_GET["c"]);',
     "code-execution"),
    ('<?php $x = `echo http://host $_GET[c]`; echo $x;',
     "reflected-request"),
])
def test_R6_15_backtick_strings_are_lexed_in_every_view(text, expected):
    """R6-15: backtick strings were absent from the statement/argument and
    request views, truncating the expression at a ``;``/``)`` inside them."""
    assert expected in _r6_names(text)


def test_R6_16_octal_escape_inside_an_interpolating_string_is_sql_space():
    """R6-16: PHP octal escapes were not decoded, so ``\\12`` hid the FROM
    keyword that becomes a newline before the query reaches MySQL."""
    text = '<?php $t=$_GET["t"]; $sql="SELECT *\\12FROM $t"; some($sql);'
    assert "sql-identifier" in _r6_names(text)


@pytest.mark.parametrize("verb", ["DROP", "ALTER", "TRUNCATE", "CREATE"])
def test_R6_17_ddl_verbs_provide_sql_identifier_context(verb):
    """R6-17: only DML/select verbs were SQL context, so ``DROP TABLE $t``
    reported nothing although TABLE is an advertised identifier keyword."""
    text = f'<?php $t=$_GET["t"]; $sql="{verb} TABLE $t"; some($sql);'
    assert "sql-identifier" in _r6_names(text)


def test_R6_18_prepare_gate_accepts_enclosing_parens_and_wrappers():
    """R6-18: the prepare exemption matched only at the immediate expression
    start.  A parenthesized or wrapped prepare is still the bound pattern;
    request data in the FIRST argument remains injection."""
    parenthesized = (
        '<?php $wpdb->query(($wpdb->prepare('
        '"SELECT * FROM t WHERE id=%d", $_GET["id"])));')
    wrapped = (
        '<?php $sql=apply_filters("q",$wpdb->prepare('
        '"SELECT * FROM t WHERE id=%d",$_GET["id"])); $wpdb->query($sql);')
    tainted_first = (
        '<?php $wpdb->query(($wpdb->prepare('
        '"SELECT * FROM t WHERE id=$_GET[id]")));')

    assert "sql-injection" not in _r6_names(parenthesized)
    assert "sql-injection" not in _r6_names(wrapped)
    assert "sql-injection" in _r6_names(tainted_first)


def test_R6_19_padded_extension_override_uses_the_canonical_normalizer():
    """R6-19: the candidate gate read raw extensions, so ``" .php "`` was
    accepted by the door but matched no file and a session-fixation file
    scanned clean.  The canonical normalizer is the one owner."""
    settings = replace(
        DEFAULTS,
        web_script=replace(DEFAULTS.web_script, extensions=[" .php "]))
    text = "<?php session_id($_GET['s']);"
    assert "session-fixation" in _r6_names(text, settings)


# ------------------------------------------------- triple-check round 7


def test_R7_P1_01_chained_assignment_is_linear_and_deadline_bounded():
    """R7-P1-01: ``_tainted_variables`` called ``_statement_end`` per
    assignment, rescanning the rest of the file each time (13 KB took 2.7 s;
    a 1 MiB chain extrapolated to hours).  Statement boundaries are built
    once and looked up by bisect; every assignment still checks the deadline.
    """
    import time

    from wpt.deadline import Deadline
    from wpt.settings import Settings
    import wpt.audit.source_scan as source_scan

    settings = Settings()

    def chain_text(count: int) -> str:
        return ("<?php $b=$_GET['x'];"
                + "".join("$a=$b;" for _ in range(count)))

    def scan_chain(text: str) -> float:
        cpu_started = time.process_time()
        source_scan._scan_file(
            text, "chain.php", settings, {},
            Deadline(COMPLETION_DEADLINE_S))
        return time.process_time() - cpu_started

    chain = chain_text(1600)
    assert 9_000 < len(chain) < 16_000
    # 4x the input: a linear pass costs ~4x, the old per-assignment rescan
    # cost ~16x.  CPU time (not wall time) is the ratio that survives xdist
    # scheduling; the generous floor absorbs timer resolution.
    small_cpu = scan_chain(chain)
    large_cpu = scan_chain(chain_text(6400))
    assert large_cpu < 8 * small_cpu + 0.05, (small_cpu, large_cpu)

    # A cap-sized file is bounded: 50 real assignments plus a ~1 MiB literal.
    prefix = "<?php $b=$_GET['x'];"
    assignments = "".join(f"$v{i}=$v{i-1};" for i in range(1, 50))
    filler = 1024 * 1024 - len(prefix) - len(assignments) - 8
    huge = prefix + assignments + '$q="' + "A" * filler + '";'
    assert 1_000_000 < len(huge) <= 1024 * 1024
    started = time.monotonic()
    source_scan._scan_file(
        huge, "huge.php", settings, {},
        Deadline(COMPLETION_DEADLINE_S))
    assert time.monotonic() - started < COMPLETION_CEILING_S

    # A wall-to-wall 1 MiB chain may legitimately exhaust the budget; it must
    # END at the deadline instead of running for hours.
    dense = "<?php $b=$_GET['x'];" + "".join(
        f"$v{i % 50}=$v{(i - 1) % 50};" for i in range(1, 121_000))
    assert len(dense) > 1024 * 1024
    started = time.monotonic()
    with pytest.raises(DeadlineExceeded):
        source_scan._scan_file(dense, "dense.php", settings, {}, Deadline(0.2))
    assert time.monotonic() - started < EXPIRY_CEILING_S


def test_R7_P1_01_one_statement_chain_is_linear_and_bounded():
    """R7-P1-01 residual: the separate-statement chain above was linear, but
    ONE ``$a0 = $a1 = ... = 1;`` statement still masked the whole suffix for
    every assignment (13 KB: 1.45 s; 1 MiB: hours).  Assignments now scan
    adjacent segments and reach the tail through the ordinary dependency
    edge, so bytes are scanned once per statement."""
    import time

    from wpt.deadline import Deadline
    from wpt.settings import Settings
    import wpt.audit.source_scan as source_scan

    settings = Settings()
    for count in (1600, 3200):
        chain = "<?php " + " = ".join(
            f"$a{i}" for i in range(count)) + " = 1;"
        started = time.monotonic()
        source_scan._scan_file(chain, "chain.php", settings, {},
                               Deadline(COMPLETION_DEADLINE_S))
        elapsed = time.monotonic() - started
        assert elapsed < COMPLETION_CEILING_S, (count, len(chain), elapsed)

    # The cap-sized shape must finish under a bounded budget, not converge
    # toward the run deadline for hours.
    parts = []
    size = len("<?php ")
    index = 0
    while size < 1024 * 1024 - 16:
        piece = f"$v{index} = "
        parts.append(piece)
        size += len(piece)
        index += 1
    huge_chain = "<?php " + "".join(parts) + "1;"
    assert 1_000_000 < len(huge_chain) <= 1024 * 1024
    started = time.monotonic()
    source_scan._scan_file(huge_chain, "huge-chain.php", settings, {},
                           Deadline(COMPLETION_DEADLINE_S))
    assert time.monotonic() - started < COMPLETION_CEILING_S


def test_R7_RESIDUAL_nested_prepare_chain_is_linear_and_deadline_bounded():
    """R7-P1-01 residual: a one-statement nested assignment chain with a
    ``prepare`` call per segment re-parsed every segment with the statement
    tail as its end, so each assignment copied and masked the whole suffix
    (200/400/800 assignments: 0.10/0.38/1.43 s, 4x per double; 1 MiB
    extrapolated to ~30 min).  The prepare scan is now bounded to the
    assignment segment, which the next-target dependency edge already
    completes transitively."""
    import time

    from wpt.deadline import Deadline
    from wpt.settings import Settings
    from wpt.types import DeadlineExceeded
    import wpt.audit.source_scan as source_scan

    def nested(count: int) -> str:
        parts = [f"$a{i} = f($wpdb->prepare('x',{i}), "
                 for i in range(count)]
        return ("<?php " + "".join(parts) + "$z = 1" + ")" * count + ";")

    settings = Settings()
    for count in (1600, 3200):
        chain = nested(count)
        started = time.monotonic()
        source_scan._scan_file(chain, "nested.php", settings, {},
                               Deadline(COMPLETION_DEADLINE_S))
        elapsed = time.monotonic() - started
        assert elapsed < COMPLETION_CEILING_S, (count, len(chain), elapsed)

    # A cap-sized nested chain must finish under a bounded budget, not
    # converge toward the run deadline for hours.
    cap = 1024 * 1024
    body: list[str] = []
    size = len("<?php ") + len("$z = 1") + 1  # prefix + tail + ';'
    index = 0
    while True:
        piece = f"$a{index} = f($wpdb->prepare('x',{index}), "
        # Each extra piece also adds one closing ')'.
        if size + len(piece) + 1 > cap:
            break
        body.append(piece)
        size += len(piece) + 1
        index += 1
    huge = "<?php " + "".join(body) + "$z = 1" + ")" * index + ";"
    assert 1_000_000 < len(huge) <= cap
    started = time.monotonic()
    source_scan._scan_file(huge, "nested-huge.php", settings, {},
                           Deadline(COMPLETION_DEADLINE_S))
    assert time.monotonic() - started < COMPLETION_CEILING_S

    # The same cap-sized shape must END at a small deadline instead of
    # ignoring it.
    started = time.monotonic()
    with pytest.raises(DeadlineExceeded):
        source_scan._scan_file(huge, "nested-huge.php", settings, {},
                               Deadline(0.05))
    assert time.monotonic() - started < EXPIRY_CEILING_S


def test_R7_RESIDUAL_one_statement_chain_keeps_transitive_taint():
    """The segment split must not lose the chain: request data in the last
    assignment reaches every earlier target through the next-target edge."""
    from wpt.audit.security import _php_code_flags
    import wpt.audit.source_scan as source_scan

    targets = [f"t{i}" for i in range(8)]
    text = "<?php " + " = ".join(f"${name}" for name in targets) + \
        " = $_GET['x'];"
    flags, _has_php = _php_code_flags(text)
    assert source_scan._tainted_variables(text, flags) == set(targets)


@pytest.mark.parametrize("sink, expected", [
    ('echo "${_GET[\'x\']}";', "reflected-request"),
    ('session_id("${_GET[\'s\']}");', "session-fixation"),
    ('system("${_GET[\'c\']}");', "code-execution"),
    ('$wpdb->query("SELECT * FROM ${_GET[\'t\']}");', "sql-identifier"),
    ('$t=$_GET; echo "${t[\'x\']}";', "reflected-request"),
    ('$t=$_GET["t"]; $wpdb->query("SELECT * FROM ${t}");', "sql-identifier"),
])
def test_R7_P2_17_subscripted_dollar_brace_interpolation(sink, expected):
    """R7-P2_17: ``${_GET['x']}``/``${t['x']}`` is the same runtime read as
    ``$_GET['x']``/``$t['x']``, but only the bare ``${name}`` form was
    rewritten, so every class went silent."""
    findings = scan({"a.php": f"<?php {sink}".encode()})
    assert expected in {f.name for f in findings}


@pytest.mark.parametrize("sql", [
    "CREATE TABLE IF NOT EXISTS $t (id int)",
    "DROP TABLE IF EXISTS $t",
    "UPDATE LOW_PRIORITY $t SET x=1",
    "INSERT IGNORE INTO $t (id) VALUES (1)",
])
def test_R7_P2_18_ddl_modifier_phrases_reach_the_identifier(sql):
    """R7-P2_18: the identifier parser stopped at ``IF NOT EXISTS`` /
    ``LOW_PRIORITY`` and called the first static word the table name."""
    body = f'<?php $t=$_GET["t"]; dbDelta("{sql}");'
    findings = scan({"a.php": body.encode()})
    assert by_name(findings, "sql-identifier")


def test_R8_P2_07_line_comment_scan_is_bounded_to_its_line():
    """R8-P2-07: ``_php_comment_stop`` searched ``?>`` from every ``//``
    comment to EOF, so a comment-heavy file was O(n^2) and a 48 KiB file
    overran a 50 ms deadline for 1.2 s.  The close-tag search must stop at
    the physical line end."""
    import wpt.audit.source_scan as source_scan

    class _CountingText(str):
        scanned = 0

        def find(self, needle, start=0, end=None):
            stop = len(self) if end is None else end
            position = (super().find(needle, start) if end is None
                        else super().find(needle, start, end))
            if position == -1:
                type(self).scanned += max(0, stop - start)
            else:
                type(self).scanned += max(0, position - start + len(needle))
            return position

    comments = 200
    text = _CountingText("// c\n" * comments)
    _CountingText.scanned = 0
    for offset in range(0, len(text), 5):
        source_scan._php_comment_stop(text, offset)
    # One whole-file scan per comment would be ~comments * len(text); the
    # bounded owner reads each physical line (and the newline search).
    assert _CountingText.scanned <= 4 * len(text)

    import time

    from wpt.deadline import Deadline

    dense = "<?php\n" + "// comment without any close tag\n" * 6000
    started = time.monotonic()
    source_scan._scan_file(dense, "comments.php", DEFAULTS, {},
                           Deadline(COMPLETION_DEADLINE_S))
    assert time.monotonic() - started < COMPLETION_CEILING_S

    source = FakeSource()
    source.files["comments.php"] = dense.encode()
    data = data_for(source)
    data.deadline = Deadline(0.05)
    started = time.monotonic()
    findings = check_security_source_patterns(data, DEFAULTS)
    elapsed = time.monotonic() - started
    assert elapsed < EXPIRY_CEILING_S, elapsed
    assert not [finding for finding in findings
                if finding.name not in ("source-scan-partial", "scan-partial")]


@pytest.mark.parametrize("php, expected", [
    (b"<?php // c\r echo $_GET['q'];", "reflected-request"),
    (b"<?php # c\r echo $_GET['q'];", "reflected-request"),
    (b"<?php $t=$_GET['t']; // c\r $wpdb->query('SELECT * FROM ' . $t);",
     "sql-injection"),
])
def test_R8_P2_08_bare_cr_ends_a_php_line_comment(php, expected):
    """R8-P2-08: PHP accepts a bare CR as a line end.  A CR-only file kept
    the following sink inside the comment and scanned clean."""
    findings = scan({"a.php": php})
    assert expected in _names(findings)


@pytest.mark.parametrize("php", [
    '<?php $a=1; echo "{$a /* $_GET */}";',
    '<?php $a=1; echo "{$a // $_GET\n}";',
    '<?php $a=1; echo "{$a # $_GET\n}";',
])
def test_R8_P2_09_comments_inside_interpolation_are_not_request_data(php):
    """R8-P2-09: the interpolation view kept comments inside ``{$...}``,
    so ``{$a /* $_GET */}`` reported reflected-request.  Only the executable
    expression may taint; a real interpolation still counts."""
    findings = scan({"a.php": php.encode()})
    assert "reflected-request" not in _names(findings)
    assert "reflected-request" in _names(scan({"b.php": (
        b"<?php echo \"{$_GET['x']}\";")}))


def test_R9_P2_14_interpolation_comments_are_blanked_in_both_views():
    """P2-14: the SQL view consumed an interpolating string whole and the
    comment blanker knew only ``{$``; a commented-out query minted a HIGH
    sql-identifier and ``${'a' /* $_GET */}`` minted reflected-request."""
    findings = scan({"a.php": (
        b"<?php $t=$_GET['t']; echo \"{$a /* SELECT * FROM $t */}\";\n"
        b"echo \"${'a' /* $_GET */}\";\n"
    )})
    names = _names(findings)
    assert "sql-identifier" not in names
    assert "reflected-request" not in names

    # A real interpolation in both spellings still reports.
    assert "sql-identifier" in _names(scan({"b.php": (
        b"<?php $t=$_GET['t']; $sql = \"SELECT * FROM {$t}\";")}))
    assert "reflected-request" in _names(scan({"c.php": (
        b"<?php echo \"${_GET['q']}\";")}))


# ------------------------------------------------ round 12 (P2 regressions)


def test_R12_prose_sql_words_are_not_a_non_sink_statement_context():
    """R12-P2-10: any SQL verb anywhere in a literal counted as context, so
    "Please select a file from $d" (and insert/delete/update prose) minted a
    HIGH sql-identifier.  Only a statement-initial verb counts."""
    prose = {
        "select.php": b"<?php $d=$_GET['d']; echo 'Please select a file from ' . $d;\n",
        "insert.php": b"<?php $d=$_GET['d']; echo 'Please insert into ' . $d;\n",
        "delete.php": b"<?php $d=$_GET['d']; echo 'Please delete from ' . $d;\n",
        "update.php": b"<?php $d=$_GET['d']; echo 'Please update ' . $d;\n",
    }
    findings = scan(prose)
    assert not any(f.name == "sql-identifier" for f in findings)
    assert any(f.name == "reflected-request" for f in findings)

    real = scan({"sql.php": (
        b"<?php $t=$_GET['t'];\n"
        b"$a=\"SELECT * FROM $t\";\n"
        b"$b=\"INSERT INTO $t (id) VALUES (1)\";\n"
        b"$c=\"DELETE FROM $t\";\n"
        b"$d=\"UPDATE $t SET x=1\";\n"
        b"$e=\"SELECT 1; DELETE FROM $t\";\n")})
    assert by_name(real, "sql-identifier").count == 5


def test_R12_query_string_is_request_data_quoted_or_unquoted():
    """R12-P2-11: ``$_SERVER['QUERY_STRING']`` was omitted from the C13
    request keys, so it reached a SQL sink with no finding.  Both spellings
    are request data; remote-address facts stay inert."""
    quoted = scan({"q.php": (
        b"<?php $q=$_SERVER['QUERY_STRING'];\n"
        b"$wpdb->query(\"SELECT * FROM t WHERE id=$q\");\n")})
    assert by_name(quoted, "sql-injection").detail == "q.php:2 ->query()"

    unquoted = scan({"u.php": (
        b'<?php echo "Q: $_SERVER[QUERY_STRING]";\n')})
    assert by_name(unquoted, "reflected-request").detail == "u.php:1 echo"

    safe = scan({"s.php": (
        b"<?php $ip=$_SERVER['REMOTE_ADDR']; echo $ip;\n")})
    assert not any(f.name == "reflected-request" for f in safe)


def test_R13_sql_statement_context_accepts_wrappers_and_rejects_prose():
    """R13-P2-15: the statement-start test was too broad (bare UPDATE/
    INSERT/DELETE prose) and too narrow (leading ``(``, comments, WITH,
    assigned heredoc headers).  Six shapes pin both directions."""
    findings = scan({"t.php": (
        b"<?php $t=$_GET['t'];\n"
        b"echo \"Update $t failed\";\n"
        b"$wrapped=\"(SELECT * FROM $t)\";\n"
        b"$cte=\"WITH c AS (SELECT 1) SELECT * FROM $t\";\n"
        b"$commented=\"/* hi */ SELECT * FROM $t\";\n"
        b"$assigned=<<<SQL\nSELECT * FROM $t\nSQL;\n"
        b"$wpdb->query($assigned);\n"
        b"$inline=$wpdb->query(<<<SQL\nSELECT * FROM $t\nSQL\n);\n"
    )})
    by_name = {f.name: f for f in findings}
    identifier = by_name["sql-identifier"]
    assert identifier.count == 5                 # wrapped/CTE/comment/2 heredocs
    assert "t.php:2" not in identifier.detail    # the prose UPDATE is silent
    assert "t.php:7" in identifier.detail        # assigned heredoc body
    assert by_name["sql-injection"].count == 2   # assigned + inline sinks


def test_R13_braced_server_interpolation_is_request_data():
    """R13-P2-16: ``${_SERVER[...]}`` was matched before the braced rewrite,
    so the ``$``/``{`` split hid HTTP_HOST/QUERY_STRING/REQUEST_URI.  Both
    spellings are request data; REMOTE_ADDR stays inert."""
    findings = scan({"s.php": (
        b"<?php\n"
        b"echo \"${_SERVER['HTTP_HOST']}\";\n"
        b"$q=\"${_SERVER['QUERY_STRING']}\";\n"
        b"$wpdb->query(\"SELECT * FROM t WHERE x='$q'\");\n"
        b"echo \"{$_SERVER['REQUEST_URI']}\";\n"
        b"echo \"${_SERVER['REMOTE_ADDR']}\";\n"
    )})
    names = [f.name for f in findings]
    assert by_name(findings, "reflected-request").count == 2
    assert "sql-injection" in names
    assert not any("REMOTE_ADDR" in f.detail for f in findings)


def test_R14_quoted_braced_superglobals_are_executable(tmp_path):
    """R14-P2: ``${'_GET'}`` was rewritten only AFTER its quoted name had
    been blanked, so every executable form was invisible.  PHP 8.4 runs
    these spells exactly like ``$_GET``: prove both the findings and that
    the fixture is valid PHP."""
    import shutil
    import subprocess

    code = (
        "<?php\n"
        "echo ${'_GET'}['x'];\n"
        "session_id(${'_GET'}['s']);\n"
        "system(${'_GET'}['c']);\n"
        "include ${'_GET'}['p'];\n"
    )
    findings = scan({"q.php": code.encode()})
    names = {finding.name for finding in findings}
    assert {"reflected-request", "session-fixation", "code-execution",
            "file-include"} <= names
    if shutil.which("php"):
        path = tmp_path / "q.php"
        path.write_text(code, encoding="utf-8")
        checked = subprocess.run(["php", "-l", str(path)],
                                 capture_output=True, text=True)
        assert checked.returncode == 0, checked.stdout + checked.stderr


def test_R14_sql_identifier_reads_server_request_keys():
    """R14-P2: the identifier parsers recognized only ``_SUPERGLOBALS``,
    so an identifier built from ``$_SERVER`` request keys (or its braced
    spelling) was not a finding even though the request mask knew them.
    REMOTE_ADDR remains a server fact, not request data."""
    findings = scan({"s.php": (
        b"<?php\n"
        b"$sql=\"SELECT * FROM $_SERVER[HTTP_HOST]\";\n"
        b"some_wrapper($sql);\n"
        b"$sql=\"SELECT * FROM ${_SERVER['QUERY_STRING']}\";\n"
        b"some_wrapper($sql);\n"
        b"$ip=$_SERVER['REMOTE_ADDR'];\n"
        b"$sql=\"SELECT * FROM $ip\";\n"
        b"some_wrapper($sql);\n"
    )})
    identifier = by_name(findings, "sql-identifier")
    assert identifier.count == 2
    assert "REMOTE_ADDR" not in identifier.detail


def test_R14_cr_only_sql_line_ends_and_prose_are_separated():
    """R14-P2: SQL prefix/heredoc line ends searched only ``\\n``, so a
    CR-only comment or heredoc hid the statement; conversely a prose
    string starting with SELECT/UPDATE minted an identifier finding."""
    cr = scan({"cr.php": (
        b"<?php $t=$_GET['t'];\r"
        b"$a=\"/* hi */\rSELECT * FROM $t\";\r"
        b"$b=<<<SQL\rSELECT * FROM $t\rSQL;\r"
    )})
    # one FROM in the comment-prefixed literal, one in the heredoc
    assert by_name(cr, "sql-identifier").count == 2

    prose = scan({"prose.php": (
        b"<?php $d=$_GET['d'];\n"
        b"echo \"Select a file from $d\";\n"
        b"echo \"Update $d\";\n"
    )})
    assert not any(f.name == "sql-identifier" for f in prose)
    assert by_name(prose, "reflected-request").count == 2

    real = scan({"real.php": (
        b"<?php $t=$_GET['t'];\n"
        b"$a=\"SELECT id FROM $t\";\n"
        b"$b=\"UPDATE $t SET x=1\";\n"
        b"$c=\"UPDATE wp_\" . $t;\n"
    )})
    assert by_name(real, "sql-identifier").count == 3


def test_R14_wrapped_update_is_statement_initial():
    """R-15 residual: an UPDATE preceded by an opening comment or paren
    was skipped because the pre-keyword text was non-empty.  Wrappers are
    grammar, not prose; both report, while real prose stays silent."""
    findings = scan({"u.php": (
        b"<?php $t=$_GET['t'];\n"
        b"$a=\"/* hi */ UPDATE $t SET x=1\";\n"
        b"$b=\"(UPDATE $t SET x=1)\";\n"
        b"$c=\"Please UPDATE $t failed\";\n"
    )})
    identifier = by_name(findings, "sql-identifier")
    assert identifier.count == 2
    assert "u.php:4" not in identifier.detail


def test_R20_php_escaped_server_request_keys_are_request_data():
    r"""R20-P2: PHP decodes a double-quoted key before the array lookup, so
    ``$_SERVER["HTTP\x5fHOST"]`` is the request header; the raw-key regex
    called it inert and lost the finding."""
    for spelling in (
        rb'<?php echo $_SERVER["HTTP\x5fHOST"];',
        rb'<?php echo $_SERVER["HTTP_\x48OST"];',
        rb'<?php echo $_SERVER["REQUEST\x5fURI"];',
        rb'<?php echo $_SERVER["QUERY\x5fSTRING"];',
    ):
        findings = scan({"e.php": spelling})
        assert by_name(findings, "reflected-request"), spelling

    inert = scan({"i.php": b'<?php echo $_SERVER["REMOTE_ADDR"];'})
    assert not any(f.name == "reflected-request" for f in inert)


def test_R20_insert_split_at_a_partial_target_is_a_statement():
    """R20-P2: ``"INSERT INTO wp_" . $t . " (a) VALUES (1)"`` ends at a
    PARTIAL target; without the UPDATE-style boundary branch the identifier
    class was lost.  Prose with the same prefix stays silent."""
    findings = scan({"i.php": (
        b"<?php\n$t=$_GET['t'];\n"
        b"$q='INSERT INTO wp_' . $t . ' (a) VALUES (1)';\n")})
    assert by_name(findings, "sql-identifier").detail == "i.php:3 INTO"

    prose = scan({"p.php": (
        b"<?php\n$n=$_GET['n'];\n"
        b"$q='Insert into wp_' . $n . ' failed';\n")})
    assert not any(f.name == "sql-identifier" for f in prose)


def test_R20_window_and_case_select_expressions_are_statements():
    """R20-P2: the select-list grammar accepted bare/function tokens only,
    so standard ``OVER (...)`` and ``CASE ... END`` expressions failed the
    context gate and a real query reported nothing."""
    window = scan({"w.php": (
        b"<?php\n$t=$_GET['t'];\n"
        b"$q='SELECT ROW_NUMBER() OVER (PARTITION BY id) FROM ' . $t;\n")})
    assert by_name(window, "sql-identifier").detail == "w.php:3 FROM"

    case = scan({"c.php": (
        b"<?php\n$t=$_GET['t'];\n"
        b"$q='SELECT CASE WHEN id=1 THEN name ELSE email END FROM ' . $t;\n")})
    assert by_name(case, "sql-identifier").detail == "c.php:3 FROM"

    prose = scan({"p.php": (
        b"<?php\n$d=$_GET['d'];\n"
        b"echo 'Select a file from ' . $d;\n")})
    assert not any(f.name == "sql-identifier" for f in prose)


def test_R14_a_lying_listing_size_is_bounded_and_marks_partial():
    """R14-P2: the candidate filter trusted ``entry.size`` and the batch
    read materialized the whole body before checking it.  The read now
    carries ``max_bytes``; a body over the bound is a known skip and the
    run reports scan-partial instead of a clean pass."""
    class _LyingSource(FakeSource):
        def __init__(self):
            super().__init__()
            self.path = "wp-content/plugins/x/x.php"
            self.files[self.path] = b"x" * (2 * 1024 * 1024)
            self.bounded: list[int] = []
            self.full_reads = 0

        def walk(self, path=""):
            yield Entry(path=self.path, is_dir=False, size=10)

        def read_bytes_bounded(self, path, max_bytes):
            self.bounded.append(max_bytes)
            raise SourceError(
                f"{path!r} is larger than the {max_bytes}-byte read bound")

        def read_bytes(self, path):
            self.full_reads += 1
            return super().read_bytes(path)

    source = _LyingSource()
    data = gather_source(source, "local")
    findings = check_security_source_patterns(data, DEFAULTS)
    assert source.bounded == [DEFAULTS.source_scan.max_file_bytes]
    assert source.full_reads == 0
    partial = by_name(findings, "scan-partial")
    assert "read bound" in partial.detail


def test_R21_server_keys_through_variables_and_concatenation_are_request():
    """R21-P2: PHP 8.4 reads the header through a statically assigned or
    concatenated key; the scanner only decoded a literal subscript."""
    findings = scan({"v.php": b'<?php\n$k="HTTP_HOST"; echo $_SERVER[$k];\n'})
    assert by_name(findings, "reflected-request").detail == "v.php:2 echo"
    findings = scan({
        "c.php": b'<?php\necho $_SERVER["HTTP_"."HOST"];\n'})
    assert by_name(findings, "reflected-request").detail == "c.php:2 echo"
    findings = scan({
        "s.php": b'<?php\n$q="SELECT * FROM " . $_SERVER[$k];\n'})
    assert any(f.name == "sql-identifier" for f in findings)
    # An unresolvable concatenation fails CLOSED: it may still name a header.
    dynamic = scan({
        "d.php": b'<?php\necho $_SERVER["HTTP_" . $suffix];\n'})
    assert by_name(dynamic, "reflected-request").detail == "d.php:2 echo"


def test_R21_braced_interpolation_is_context_sensitive():
    """R21-P2: ``${_SERVER [...]}`` in CODE is a constant (fatal), while the
    same spelling inside a string is the header read; ``${'_SERVER'}`` in a
    string is an array -> static text, but in code it is the variable."""
    # Code: fatal/inert.
    fatal = scan({"f.php": b'<?php\necho ${_SERVER["HTTP_HOST"]};\n'})
    assert not any(f.name == "reflected-request" for f in fatal)
    get_const = scan({"g.php": b"<?php\necho ${_GET['c']};\n"})
    assert not any(f.name == "reflected-request" for f in get_const)
    sink = scan({"x.php": b'<?php\nsystem(${_SERVER["HTTP_HOST"]});\n'})
    assert not any(f.name == "code-execution" for f in sink)
    # True positives stay.
    string = scan({"s.php": b'<?php\necho "${_SERVER[\'HTTP_HOST\']}";\n'})
    assert by_name(string, "reflected-request").detail == "s.php:2 echo"
    code_quoted = scan({"q.php": b"<?php\necho ${'_SERVER'}['HTTP_HOST'];\n"})
    assert by_name(code_quoted, "reflected-request").detail == "q.php:2 echo"
    # String form: the accessor after ``}`` is literal text.
    static = scan({"t.php": b'<?php\n$q="SELECT * FROM ${"_SERVER"}[\'HTTP_HOST\']";\n'})
    assert not any(f.name in ("reflected-request", "sql-identifier")
                   for f in static)


def test_R21_commented_partial_insert_target_is_still_sql():
    """R21-P2: SQL comments are whitespace, so ``INSERT/*c*/ INTO wp_`` and
    ``INSERT INTO/*c*/ wp_`` name the same partial dynamic table as the
    spaced spelling; prose stays silent."""
    for body in (
        b'<?php\n$t=$_GET["t"];\n$q="INSERT/*c*/ INTO wp_" . $t . " (a) VALUES(1)";\n',
        b'<?php\n$t=$_GET["t"];\n$q="INSERT INTO/*c*/ wp_" . $t . " (a) VALUES(1)";\n',
    ):
        findings = scan({"i.php": body})
        assert by_name(findings, "sql-identifier").detail == "i.php:3 INTO"
    prose = scan({
        "p.php": b'<?php\n$n=$_GET["n"];\n$q="Insert/*c*/ into wp_" . $n . " failed";\n'})
    assert not any(f.name == "sql-identifier" for f in prose)


def test_R22_braced_quoted_assignment_targets_are_tainted():
    """R22-P2: PHP's ``${'t'} = $_GET['a']`` is ``$t = ...``, but the
    assignment regex only accepted ``$name``, so later reads and a SQL
    identifier built from ``${'t'}`` were invisible."""
    findings = scan({
        "r.php": b"<?php\n${'t'} = $_GET['a'];\necho ${'t'};\n"})
    assert by_name(findings, "reflected-request").detail == "r.php:3 echo"
    findings = scan({
        "s.php": b"<?php\n${\"t\"} = $_GET['a'];\n"
                 b"$q = \"SELECT * FROM \" . ${\"t\"};\n"
                 b"$pdo->query($q);\n"})
    assert any(f.name == "sql-identifier" for f in findings)
    # ... including the interpolated SQL-text spelling
    findings = scan({
        "i.php": b"<?php\n${'t'} = $_GET['a'];\n"
                 b"$q = \"SELECT * FROM ${'t'}\";\n"
                 b"$pdo->query($q);\n"})
    assert any(f.name == "sql-identifier" for f in findings)
    # comments/spaces inside the braces are PHP whitespace
    findings = scan({
        "c.php": b"<?php\n${ /*c*/ 't' } = $_GET['a'];\necho ${'t'};\n"})
    assert by_name(findings, "reflected-request").detail == "c.php:3 echo"


def test_R23_server_interpolation_and_parenthesized_identifier():
    """R23-P2: a double-quoted ``$_SERVER`` subscript with interpolation
    (``"HTTP_$x"`` / ``"HTTP_{$x}"`` / ``"HTTP_${x}"``) was decoded as a
    STATIC key, so the header read was invisible.  A parenthesized
    concatenated identifier (``... FROM " . ($t)``) stopped at ``(``."""
    for key in ('HTTP_$x', 'HTTP_{$x}', 'HTTP_${x}'):
        body = ('<?php $x="HOST"; echo $_SERVER["' + key + '"];').encode()
        findings = scan({"h.php": body})
        assert by_name(findings, "reflected-request").detail == "h.php:1 echo"

    findings = scan({
        "p.php": b'<?php $t=$_GET["t"]; '
                 b'$wpdb->query("SELECT * FROM " . ($t));'})
    assert any(f.name == "sql-identifier" for f in findings)
    findings = scan({
        "p2.php": b'<?php $t=$_GET["t"]; '
                  b'$wpdb->query("SELECT * FROM " . (($t)));'})
    assert any(f.name == "sql-identifier" for f in findings)
    # a fully static parenthesized expression stays silent
    findings = scan({
        "s.php": b'<?php $wpdb->query("SELECT * FROM " . ("wp_users"));'})
    assert not any(f.name == "sql-identifier" for f in findings)


def test_R23_escaped_and_variable_braced_assignment_targets():
    """R23-P2: ``${"\\x74"}``/``${"\\164"}``/``${"\\u{74}"}`` and
    ``${$n}`` are PHP's ``$t`` assignment target.  The regex accepted only a
    plain quoted name and the read rewrite never tainted them."""
    for target in ('${"\\x74"}', '${"\\164"}', '${"\\u{74}"}', "${'t'}"):
        body = ('<?php ' + target + ' = $_GET["a"]; echo ' + target
                + ';').encode()
        findings = scan({"e.php": body})
        assert by_name(findings, "reflected-request").detail == "e.php:1 echo"

    findings = scan({
        "v.php": b'<?php $n="t"; ${$n}=$_GET["a"]; echo ${$n};'})
    assert by_name(findings, "reflected-request").detail == "v.php:1 echo"


def test_R22_static_server_keys_ignore_comments_and_string_bodies():
    """R22-P2: ``_static_assignment`` resolved the last assignment on RAW
    text, so a commented or string-embedded ``$k = "REMOTE_ADDR"`` shadowed
    the live ``HTTP_HOST``.  Only live-code assignments count now; the
    value is still read from the raw text (PHP escapes)."""
    from wpt.audit.source_scan import _static_assignment

    live = (
        '<?php\n$k="HTTP_HOST";\n/* $k="REMOTE_ADDR"; */\n'
        'echo $_SERVER[$k];\n')
    assert _static_assignment(live, "k", len(live)) == "HTTP_HOST"

    reverse = (
        '<?php\n$k="REMOTE_ADDR";\n/* $k="HTTP_HOST"; */\n'
        'echo $_SERVER[$k];\n')
    assert _static_assignment(reverse, "k", len(reverse)) == "REMOTE_ADDR"

    string_shadow = (
        '<?php\n$k="HTTP_HOST";\n'
        'echo "$k = \\"REMOTE_ADDR\\"";\necho $_SERVER[$k];\n')
    assert _static_assignment(string_shadow, "k", len(string_shadow)) \
        == "HTTP_HOST"

    heredoc_shadow = (
        '<?php\n$k="HTTP_HOST";\n'
        'echo <<<TXT\n$k = "REMOTE_ADDR";\nTXT;\n'
        'echo $_SERVER[$k];\n')
    assert _static_assignment(heredoc_shadow, "k", len(heredoc_shadow)) \
        == "HTTP_HOST"

    # A live reassignment after the comment still wins (the last live one).
    reassigned = (
        '<?php\n$k="HTTP_HOST";\n/* $k="REMOTE_ADDR"; */\n'
        '$k="REMOTE_ADDR";\necho $_SERVER[$k];\n')
    assert _static_assignment(reassigned, "k", len(reassigned)) \
        == "REMOTE_ADDR"

    # The end-to-end positive: the live key is still a reflected request.
    findings = scan({
        "a.php": b'<?php\n$k="HTTP_HOST";\n'
                 b'/* $k="REMOTE_ADDR"; */\necho $_SERVER[$k];\n'})
    assert by_name(findings, "reflected-request").detail == "a.php:4 echo"


def test_R22_delete_using_split_keeps_the_sql_identifier():
    """R22-P2: ``_DELETE_STATEMENT_RE`` accepts ``USING`` but the split
    continuation list did not, so the concatenated form lost the finding."""
    findings = scan({
        "u.php": b'<?php\n$t=$_GET["t"];\n'
                 b'$q="DELETE FROM " . $t . " USING x";\n'
                 b'$pdo->query($q);\n'})
    assert any(f.name == "sql-identifier" for f in findings)
    direct = scan({
        "d.php": b'<?php\n$t=$_GET["t"];\n'
                 b'$q="DELETE FROM $t USING x";\n'
                 b'$pdo->query($q);\n'})
    assert any(f.name == "sql-identifier" for f in direct)


def test_R22_sql_comment_rule_has_one_owner():
    """R22-P2: the same-length space view and the grammar view repeated the
    MySQL comment rule independently (and the prefix stripper used a looser
    ``--``).  One ``_sql_comment_end`` owns block/--/# shapes, including
    MySQL's ``--``-needs-whitespace rule."""
    from wpt.audit.source_scan import (_SQL_GRAMMAR_WINDOW,
                                       _sql_comment_end, _sql_comment_space,
                                       _sql_grammar_view,
                                       _strip_sql_statement_prefix)

    text = "a /* b */ c -- d\ne # f\n#[not] --nope"
    spaced = _sql_comment_space(text)
    assert spaced.startswith("a   ") and " b " not in spaced
    assert "-- d" not in spaced and "# f" not in spaced
    assert "--nope" in spaced          # -- without whitespace is not a comment
    assert "#[not]" in spaced          # PHP attribute marker, not SQL
    grammar = _sql_grammar_view(text, limit=None)
    assert "-- d" not in grammar and "# f" not in grammar
    assert "--nope" in grammar and "#[not]" in grammar
    assert _strip_sql_statement_prefix("--no SELECT") == "--no SELECT"
    assert _strip_sql_statement_prefix("-- yes\nSELECT") == "SELECT"
    assert _sql_comment_end(text, text.index("/*")) == text.index(" */") + 3
    assert _SQL_GRAMMAR_WINDOW > 0


def test_R23_sql_comment_identifier_consumer_uses_the_one_owner():
    """R23-P2: ``_skip_sql_comment_ws`` was a FOURTH hand-written copy of
    the MySQL comment rule and already diverged from ``_sql_comment_end``:
    it skipped ``#[x]`` (the owner treats ``#[`` as live) and did not treat
    a trailing ``--`` as a comment-to-end.  Both cases now follow the owner
    at the identifier position too."""
    from wpt.audit.source_scan import _skip_sql_comment_ws, _sql_comment_end

    trailing = "SELECT * FROM --"
    assert _sql_comment_end(trailing, 14) == len(trailing)
    assert _skip_sql_comment_ws(trailing, 14, len(trailing)) == len(trailing)
    attribute = "SELECT * FROM #[x] "
    assert _sql_comment_end(attribute, 14) is None
    assert _skip_sql_comment_ws(attribute, 14, len(attribute)) == 14
    # block comments and line comments still skip as before
    assert _skip_sql_comment_ws("/*x*/ $t", 0, 9) == 6
    assert _skip_sql_comment_ws("-- c\n$t", 0, 7) == 5
    # A normal identifier after the keyword still reports (the owner change
    # did not disable the common path).
    findings = scan({
        "n.php": b'<?php $t=$_GET["t"]; '
                 b'$wpdb->query("SELECT * FROM " . $t);'})
    assert any(f.name == "sql-identifier" for f in findings)


def test_R21_line_offsets_have_one_owner():
    """R21-P2: source_scan carried a byte-identical copy of suspicious's
    ``_line_starts``; a CR/LF fix could shift line numbers in one check
    only.  The source scanner imports the existing owner."""
    from wpt.audit import suspicious
    from wpt.audit import source_scan

    assert source_scan._line_starts is suspicious._line_starts
    text = "a\r\nb\rc\nd"
    assert source_scan._line_starts(text) == [0, 3, 5, 7]


def test_R24_bare_cr_php_comment_does_not_hide_a_server_read():
    """R24-P1: a bare CR ends a PHP ``//`` comment.  ``_PHP_WS`` only knew
    CRLF/LF, so ``$_SERVER // c\\r["HTTP_HOST"]`` scanned as a comment body
    and the request read was missed."""
    findings = scan({
        "cr.php": b'<?php echo $_SERVER // c\r["HTTP_HOST"];\n',
    })
    assert any(f.name == "reflected-request" for f in findings)


def test_R24_nested_case_and_subquery_selects_keep_the_identifier_finding():
    """R24-P2: the select-list grammar stopped at the first END and rejected
    a parenthesized subquery, so a real dynamic identifier in a NESTED CASE
    or subquery SELECT scanned clean.  Simple forms must stay detected and
    prose must stay silent."""
    nested_case = (
        b'<?php $t=$_GET["t"]; $q="SELECT CASE WHEN a THEN CASE WHEN b '
        b'THEN 1 ELSE 2 END ELSE 3 END FROM $t"; $wpdb->prepare($q,1);\n'
    )
    subquery = (
        b'<?php $t=$_GET["t"]; $q="SELECT (SELECT COUNT(*) FROM x) AS c '
        b'FROM $t"; $wpdb->prepare($q,1);\n'
    )
    simple = (
        b'<?php $t=$_GET["t"]; $q="SELECT CASE WHEN a THEN 1 ELSE 2 END '
        b'FROM $t"; $wpdb->prepare($q,1);\n'
    )
    prose = (
        b'<?php $t=$_GET["t"]; $q="Select a file ($t) from the list"; '
        b'$wpdb->prepare($q,1);\n'
    )
    for name, source in (("case", nested_case), ("sub", subquery),
                         ("simple", simple)):
        findings = scan({f"{name}.php": source})
        assert any(f.name == "sql-identifier" for f in findings), name
    assert not any(
        f.name == "sql-identifier" for f in scan({"prose.php": prose}))
