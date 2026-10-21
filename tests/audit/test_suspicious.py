"""Unit tests for the suspicious-code audit check (wpt.audit.suspicious).

FakeSource-backed AuditData with the lazy content seam set (this check
reads file CONTENTS at check time, so every fixture is a small in-memory
webroot).  Direct check calls mirroring tests/audit/test_dbcheck.py; no
gatherers, no network, no sleeps — deterministic (the breaker tests pin
read-attempt counts).  Log assertions use the
suite's ``wpt_records`` handler (as tests/audit/test_run.py): pytest's
caplog cannot see ``wpt.*`` records because the ``wpt`` parent does not
propagate.

DEFERRED CHECK IMPORT (binding): the check module imports inside
``_check()`` / ``_module()`` on first call, NOT at module level.
Collection imports every test module before the first test runs and the
registry is process-global with no unregister API, so a module-level
import would register ``security.suspicious`` BEFORE
tests/audit/test_run.py and tests/audit/test_security.py execute — and
both pin the exact PRE-SEAM landed-check sets.  The coordinator wires
this module into wpt/audit/__init__.py and updates those sets at seam
time; the deferral stays correct afterwards (module import is idempotent
via sys.modules).

Test -> behavior map:
  test_settings_defaults_wired ........... load(): max_file_bytes 1048576,
        8 shipped patterns, all valid under re.IGNORECASE
  test_override_surface .................. --set dot-paths work
        (suspicious.max_file_bytes int-coerced, suspicious.patterns list);
        wrong types raise SettingsError
  test_profile_section_deep_merges ....... a user profile overriding only
        max_file_bytes keeps the shipped pattern list (nested merge)
  test_clean_tree_silent ................. 2 benign plugin files -> []
  test_single_signature_finding .......... eval(decoder)(...): ONE
        exact finding (high, count 1, bytes = file size, fix text), detail
        "path:2 eval(decoder)", validate() ok
  test_line_number_reported .............. signature on line 3 -> ":3"
  test_patterns_reported_once_first_line . 2 distinct patterns -> 2 detail
        lines; a repeated hit of the SAME pattern -> still one line (first
        hit wins); count still 1 file
  test_two_infected_files ................ count 2, bytes = sum, details
        sorted by path
  test_benign_constructs_silent .......... the four REMOVED false-positive
        signatures (assert($superglobal), a long base64 blob,
        preg_replace /e, mail Bcc) plus "eval" in a comment and
        plain eval($x) -> []
  test_matches_inside_a_comment_or_string_are_silent
        .................................... line/block/doc comments, string
        literals and heredocs quoting a real signature -> []; a genuine
        hit AFTER a quoted one is still found
  test_scope_covers_every_php_execution_surface
        .................................... mu-plugins, uploads (incl. a
        hidden .htacces), wp-content drop-ins, languages, wp-admin and
        webroot PHP are scanned; wp-includes, sibling prefixes and
        config dotfiles are not
        file ARE scanned; a directory entry named *.php is never a hit
  test_max_file_bytes_skips_oversize ..... limit 64 B: the 139 B infected
        file skipped silently, the 39 B infected file found; an
        all-oversize tree -> []
  test_at_limit_is_scanned ............... size exactly at the limit -> hit
  test_read_failure_skips_file ........... a raising-on-read source: the
        unreadable infected file skipped (one debug log), the other
        file's finding survives, the check never raises; one failure is
        far under the breaker bound — no WARNING record
  test_breaker_aborts .................... 26 consecutive-failure
        candidates after one infected file: the scan aborts ON the 25th
        consecutive failure with ONE exact warning and returns the
        partial verified finding.  Reads are BATCH-granular: the whole
        one batch (28 candidates) is fetched up front (28 read attempts,
        the new pin) — the abort stops PROCESSING at the 25th failure
        and any further batch; the 26th failure and the also-infected
        tail were fetched but are discarded unprocessed
  test_breaker_reset_on_success .......... 24 failures then a good read:
        counter reset, scan continues to the last file (its infection
        reports and proves it); NO abort warning, every file read
  test_breaker_oversize_not_a_failure .... a size-gated skip between
        failures is policy, not health: it neither counts toward the
        bound nor breaks the chain — the next failure is still the 25th
        consecutive and aborts (the tail is fetched but discarded
        unprocessed; the read-attempt count pins the gated batch shape)
  test_batched_happy_path ................ 425 infected files over three
        read_many batches (200/200/25): every batch <= 200, chunking
        preserves the sorted candidate order losslessly, and the
        aggregate is identical to the serial expectation (count, bytes,
        8-line detail + marker)
  test_breaker_trips_across_batches ...... 24 consecutive failed-map
        entries ending batch 1 + the 25th in batch 2: abort warning +
        partial findings, and batch 3 is NEVER fetched (the counter
        spans batch boundaries)
  test_breaker_resets_on_ok_batch_entry ... the mirror: 24 consecutive
        failures ending batch 1, an ok entry at batch 2's head resets
        the counter — the scan completes to the last file (its infection
        reports), no warning, both batches fetched
  test_deadline_mid_scan_partial ......... a deadline double raising on
        its 2nd check: batch 1's findings return + ONE exact "stopped:
        run deadline" warning, batch 2 is never fetched, and the check
        NEVER raises the deadline back (deterministic — no clock race)
  test_deadline_expired_before_scan ...... a REAL Deadline(0.0001) built
        BEFORE the 1200-file fixture (the build alone spends the 0.1 ms
        budget many times over — no sleep, no race): [] + the same ONE
        warning, read_many never called, no raise
  test_deadline_none_unchanged ........... deadline None (the unbounded
        default): full findings, no warnings
  test_custom_pattern_from_profile ....... patterns=["WPTHING"] catches a
        marker file with the label "pattern[0]"
  test_invalid_regex_skipped ............. "([" + "WPTHING": one ERROR
        record from wpt.audit.suspicious, the valid pattern still applies
  test_non_string_pattern_skipped ......... patterns=[1, "WPTHING"]: the
        non-string entry skipped with an ERROR record, the valid pattern
        still applies
  test_source_none_degrades ............... source None -> [] (never
        raises; one debug line)
  test_bare_settings_silent ............... bare Settings() (no patterns)
        -> []
  test_detail_truncated_at_eight .......... 10 infected files -> 8 detail
        lines + "(+2 more)"
  test_both_modes_identical .............. ftp == local over one fixture
  test_logs ................................ findings: exactly one INFO
        (counts) + one DEBUG summary from wpt.audit.suspicious; clean: no
        INFO records at all, one DEBUG summary
  test_default_labels_mirror_profile ...... module _PATTERN_LABELS keys ==
        the shipped pattern list exactly (both directions — the cosmetic
        mirror cannot drift silently)
  test_registry_integration ............... name/applies/func registered;
        exact-name selector in both modes; run_checks end-to-end
"""

import json
import logging
import re
from dataclasses import replace

import pytest

from tests.fakes import FakeSource
from wpt.audit.data import AuditData
from wpt.audit.registry import all_checks, run_checks, select_checks
from wpt.deadline import Deadline
from wpt.settings import Settings, SettingsError, load
from wpt.types import DeadlineExceeded, SourceError

#: The shipped profile (wpt/data/profiles/default.json) — the tunables exactly
#: as users get them.
DEFAULTS = load()

PLUGIN_A = "wp-content/plugins/a/a.php"
PLUGIN_B = "wp-content/plugins/b/b.php"
THEME_T = "wp-content/themes/t/functions.php"

EVAL_B64_LINE = b"eval(base64_decode('SGVsbG8='));\n"
EVAL_POST_LINE = b"eval($_POST['c']);\n"


# --------------------------------------------------------------- log capture


# ------------------------------------------------- deferred check module seam


def _check():
    """The check under test, imported on first call — see module docstring."""
    from wpt.audit.suspicious import check_security_suspicious
    return check_security_suspicious


def _module():
    """The check module (the contract test reads its label map)."""
    from wpt.audit import suspicious
    return suspicious


# ------------------------------------------------------------------ fixtures


def src_with(**files: bytes) -> FakeSource:
    """A FakeSource preloaded with ``files`` (path -> content)."""
    source = FakeSource()
    source.files.update(files)
    return source


def sus_data(source: FakeSource, mode: str = "ftp") -> AuditData:
    """AuditData over ``source``: walk-derived entries + the content seam."""
    return AuditData(
        mode=mode,
        entries=list(source.walk()),
        siteurl=None,
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
        source=source,
    )


class _ReadFails(FakeSource):
    """FakeSource whose read_bytes raises OSError under a path prefix."""

    def __init__(self, fail_prefix: str) -> None:
        super().__init__()
        self._fail_prefix = fail_prefix

    def read_bytes(self, path):
        if path.startswith(self._fail_prefix):
            raise OSError(f"unreadable: {path}")
        return super().read_bytes(path)


class _FailingReadsSource(FakeSource):
    """FakeSource raising SourceError on the given paths, counting every
    read attempt (the breaker's abort/reset pinning)."""

    def __init__(self, fail_paths) -> None:
        super().__init__()
        self.fail_paths = set(fail_paths)
        self.read_attempts = 0

    def read_bytes(self, path):
        self.read_attempts += 1
        if path in self.fail_paths:
            raise SourceError(f"unreadable: {path}")
        return super().read_bytes(path)


class _RecordingReadMany(FakeSource):
    """FakeSource with an explicit read_many double: records every batch
    (its paths, in call order) and serves the batch contract per path —
    bytes from the store, ``fail_paths`` in the failed map (a read
    failure is a read failure: the breaker counts failed-map entries
    exactly like the read_bytes raises of _FailingReadsSource)."""

    def __init__(self, fail_paths=()) -> None:
        super().__init__()
        self.fail_paths = set(fail_paths)
        self.batches: list[list[str]] = []
        self.max_bytes: list[int | None] = []

    def read_many(self, paths, *, max_bytes=None):
        self.batches.append(list(paths))
        self.max_bytes.append(max_bytes)
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


class _DeadlineAfterOneBatch:
    """Deadline double: raises DeadlineExceeded from the SECOND check on —
    a deterministic mid-scan expiry (batch 1 completes, the budget is
    spent before batch 2; no wall-clock race, no sleep)."""

    def __init__(self) -> None:
        self.checks = 0

    def check(self, context) -> None:
        self.checks += 1
        if self.checks > 1:
            raise DeadlineExceeded(f"run deadline exceeded at {context!r}")


def check_warnings(wpt_records) -> list[str]:
    """The check's own WARNING messages."""
    return [r.getMessage() for r in wpt_records
            if r.name == "wpt.audit.suspicious" and r.levelno == logging.WARNING]


# ------------------------------------------------------------ settings seam


def test_settings_defaults_wired():
    assert DEFAULTS.suspicious.max_file_bytes == 1048576
    # Four patterns, all of which can PROVE execution. The removed ones
    # (assert on a superglobal, a long base64 blob, preg_replace /e and
    # mail-Bcc) each reported clean, documented WordPress code as malware;
    # see _PATTERN_LABELS in wpt/audit/suspicious.py for the evidence.
    assert len(DEFAULTS.suspicious.patterns) == 4
    for pattern in DEFAULTS.suspicious.patterns:
        assert isinstance(pattern, str)
        re.compile(pattern, re.IGNORECASE)  # every shipped pattern is valid


def test_override_surface():
    s = load(overrides={"suspicious.max_file_bytes": 512,
                        "suspicious.patterns": ["WPTHING"]})
    assert s.suspicious.max_file_bytes == 512
    assert s.suspicious.patterns == ["WPTHING"]
    with pytest.raises(SettingsError):  # patterns must be a list
        load(overrides={"suspicious.patterns": "WPTHING"})
    with pytest.raises(SettingsError):  # max_file_bytes must be an int
        load(overrides={"suspicious.max_file_bytes": "big"})
    # A non-positive bound would mark EVERY file oversize and report a clean
    # tree for a reason the operator never asked for. Pinned at the dataclass,
    # the same seam as ftp.parallel_reads (see the coordinator note: the
    # apply_override path mutates a constructed tree, so __post_init__ does not
    # re-run there for ANY section).
    from wpt.settings import SuspiciousSettings
    for bad in (0, -1):
        with pytest.raises(SettingsError, match="max_file_bytes.*>= 1"):
            SuspiciousSettings(max_file_bytes=bad)
    SuspiciousSettings(max_file_bytes=1)      # the smallest useful bound
    # NOTE: the override path accepts non-string list members (the profile
    # path validates them) — the check tolerates them per-entry instead;
    # pinned by test_non_string_pattern_skipped.


def test_profile_section_deep_merges(tmp_path):
    profile = tmp_path / "p.json"
    profile.write_text(json.dumps({"suspicious": {"max_file_bytes": 2048}}))
    s = load(profile_path=str(profile))
    assert s.suspicious.max_file_bytes == 2048
    # a nested-object merge keeps the shipped pattern list
    assert s.suspicious.patterns == DEFAULTS.suspicious.patterns


# ------------------------------------------------------------- scan results


def test_clean_tree_silent():
    source = src_with(
        **{
            "wp-content/plugins/good/good.php": b"<?php\necho 'hi';\n",
            "wp-content/plugins/ok/ok.php": b"<?php\nadd_action('init', 'f');\n",
        }
    )
    assert _check()(sus_data(source), DEFAULTS) == []


def test_single_signature_finding():
    content = b"<?php\n" + EVAL_B64_LINE
    source = src_with(**{PLUGIN_A: content})
    findings = _check()(sus_data(source), DEFAULTS)
    assert len(findings) == 1
    f = findings[0]
    f.validate()
    assert (f.category, f.name, f.risk) == (
        "security.suspicious", "suspicious-code", "high",
    )
    assert f.count == 1
    assert f.bytes == len(content)
    assert f.fix == (
        "Quarantine the file and investigate: executable code matched a known "
        "backdoor signature — a candidate, not a verdict. Verify the affected "
        "file against a clean copy of the same plugin/theme/drop-in, or the "
        "site itself for core files, and find the infection vector before "
        "restoring."
    )
    assert f.detail == f"{PLUGIN_A}:2 eval(decoder)"


def test_line_number_reported():
    source = src_with(**{PLUGIN_A: b"<?php\n// header\n" + EVAL_B64_LINE})
    f = _check()(sus_data(source), DEFAULTS)[0]
    assert f.detail == f"{PLUGIN_A}:3 eval(decoder)"


def test_patterns_reported_once_first_line():
    content = (
        b"<?php\n" + EVAL_B64_LINE + b"// mid\n"
        + EVAL_POST_LINE + b"eval($_POST['d']);\n"
    )
    source = src_with(**{PLUGIN_A: content})
    findings = _check()(sus_data(source), DEFAULTS)
    assert len(findings) == 1
    f = findings[0]
    assert f.count == 1                      # one affected file
    # one detail line per DISTINCT pattern, at the FIRST hit line each
    assert f.detail == (
        f"{PLUGIN_A}:2 eval(decoder)\n"
        f"{PLUGIN_A}:4 eval(superglobal)"
    )


def test_two_infected_files():
    content_a = b"<?php\n" + EVAL_B64_LINE
    content_b = b"<?php\n" + EVAL_POST_LINE
    source = src_with(**{PLUGIN_A: content_a, PLUGIN_B: content_b})
    f = _check()(sus_data(source), DEFAULTS)[0]
    f.validate()
    assert f.count == 2
    assert f.bytes == len(content_a) + len(content_b)
    assert f.detail == (
        f"{PLUGIN_A}:2 eval(decoder)\n"
        f"{PLUGIN_B}:2 eval(superglobal)"
    )


def test_benign_constructs_silent():
    source = src_with(
        **{
            # the literal word "eval" in a comment — no call shape
            "wp-content/plugins/b1/b1.php":
                b"<?php\n// we considered eval but chose not to\n",
            # a plain decode with a SHORT argument — no eval, no long blob
            "wp-content/plugins/b2/b2.php":
                b"<?php\n$x = base64_decode('SGVsbG8=');\n",
            # a superglobal assignment with no eval on the line
            "wp-content/plugins/b3/b3.php":
                b"<?php\n$x = $_POST['a'];\n",
            # plain eval of a local variable — no superglobal, no decoder
            "wp-content/plugins/b4/b4.php":
                b"<?php\neval($x);\n",
            # assert() no longer evaluates a string on PHP 8: the old
            # shipped assert($_) pattern fired on ordinary validation code
            "wp-content/plugins/b5/b5.php":
                b"<?php\nassert($_POST['id'] > 0);\n",
            # a Bcc header is documented wp_mail/WooCommerce functionality
            "wp-content/plugins/b6/b6.php":
                b"<?php\nmail($to, $s, $b, 'Bcc: audit@example.com');\n",
            # a legitimate long base64 fixture (W3TC ships these); a blob
            # alone proves no execution
            "wp-content/plugins/b7/b7.php":
                b"<?php\n$x = '"
                + b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5"
                  b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo"
                + b"';\n",
            # preg_replace /e is a fatal error on PHP 7+, not execution
            "wp-content/plugins/b8/b8.php":
                b"<?php\n$r = preg_replace('/x(.*)/e', 'return \"y\";', $in);\n",
        }
    )
    assert _check()(sus_data(source), DEFAULTS) == []


def test_matches_inside_a_comment_or_string_are_silent():
    # The scanner used to match call-shaped text wherever it appeared, so a
    # plugin that merely MENTIONS a backdoor, or quotes one in documentation,
    # was reported as compromised. Only executable PHP is a finding now.
    source = src_with(
        **{PLUGIN_A: (
            b"<?php\n"
            b"// eval(base64_decode('x'));\n"
            b"/* eval(base64_decode('x')); */\n"
            b"/** eval(base64_decode('x')) */\n"
            b"$doc = \"eval(base64_decode('x'))\";\n"
            b"$doc2 = 'eval($_POST[\"c\"])';\n"
            b"// $GLOBALS['x']($y);\n"
            b"echo 'eval(base64_decode(\"z\"))';\n"
        )}
    )
    assert _check()(sus_data(source), DEFAULTS) == []


def test_heredoc_payload_is_silent():
    # Heredoc/nowdoc bodies are data, not code: the loader never executes
    # them, so a sample payload inside one is not a finding.
    source = src_with(**{PLUGIN_A: (
        b"<?php\n"
        b"$doc = <<<EOT\n"
        b"eval(base64_decode('x'));\n"
        b"EOT;\n"
    )})
    assert _check()(sus_data(source), DEFAULTS) == []


def test_real_code_after_a_quoted_payload_still_found():
    # Guard against over-blanking: a string earlier in the file must not hide
    # a genuine hit later.
    source = src_with(**{PLUGIN_A: (
        b"<?php\n"
        b"$doc = \"eval(base64_decode('x'))\";\n"
        + EVAL_B64_LINE
    )})
    findings = _check()(sus_data(source), DEFAULTS)
    assert len(findings) == 1
    assert findings[0].detail == f"{PLUGIN_A}:3 eval(decoder)"


def test_a_file_without_php_tags_is_silent():
    # No opening tag means no executable PHP, whatever the text contains.
    source = src_with(**{PLUGIN_A: b"eval(base64_decode('x'));\n"})
    assert _check()(sus_data(source), DEFAULTS) == []


def test_a_string_before_a_real_hit_does_not_hide_it():
    # The pre-pass looks at EVERY match on the line: the first raw match can
    # sit inside a string while a real one follows, and taking only the first
    # would miss it.
    source = src_with(**{PLUGIN_A: (
        b"<?php\n"
        b"$doc = \"eval(base64_decode('x'))\"; "
        b"eval(base64_decode('real'));\n"
    )})
    findings = _check()(sus_data(source), DEFAULTS)
    assert len(findings) == 1
    assert findings[0].detail == f"{PLUGIN_A}:2 eval(decoder)"


def test_interpolated_expression_is_executable_code():
    # PHP evaluates {$...} inside a string, so a dynamic call built there is
    # code and must be found. The direct form is code too, and is found.
    direct = src_with(**{PLUGIN_A: b"<?php\n$y = 1;\n$GLOBALS['f']($y);\n"})
    assert len(_check()(sus_data(direct), DEFAULTS)) == 1
    interpolated = src_with(**{PLUGIN_A: (
        b"<?php\n"
        b"$y = 1;\n"
        b"$x = \"{$GLOBALS['f']($y)}\";\n"
    )})
    findings = _check()(sus_data(interpolated), DEFAULTS)
    assert len(findings) == 1
    assert findings[0].detail == f"{PLUGIN_A}:3 $GLOBALS-call"


def test_a_pattern_matching_spaces_inside_a_string_is_silent():
    # The code bitmap is explicit, so a run of literal spaces inside a string
    # is not mistaken for code the way a blanked-space heuristic would. The
    # pattern needs 2+ spaces so it can only match the string body here.
    settings = replace(
        DEFAULTS, suspicious=replace(DEFAULTS.suspicious, patterns=["  +"])
    )
    source = src_with(**{PLUGIN_A: b"<?php\n$x = \"     \";\n"})
    assert _check()(sus_data(source), settings) == []
    # the same pattern matches real code
    source = src_with(**{PLUGIN_A: b"<?php\nfoo(  1);\n"})
    assert len(_check()(sus_data(source), settings)) == 1


def test_superglobal_signature_requires_the_same_variable():
    # The backreference must name the ASSIGNED variable: an unrelated eval on
    # the same line is not request data reaching eval.
    settings = replace(
        DEFAULTS, suspicious=replace(DEFAULTS.suspicious,
                                     patterns=DEFAULTS.suspicious.patterns[2:3])
    )
    same = src_with(**{PLUGIN_A: b"<?php\n$x = $_POST['id']; eval($x);\n"})
    findings = _check()(sus_data(same), settings)
    assert len(findings) == 1
    assert findings[0].detail == f"{PLUGIN_A}:2 superglobal-evaluated"
    for unrelated in (
        b"<?php\n$x = $_POST['id']; eval($POST);\n",
        b"<?php\n$x = $_POST['id']; echo $x; eval($trusted);\n",
        b"<?php\n$x = $_POST['id']; eval($y);\n",
    ):
        assert _check()(sus_data(src_with(**{PLUGIN_A: unrelated})), settings) == []


def test_interpolation_only_in_interpolating_literals():
    # PHP evaluates {$...} in double quotes and heredocs, NOT in single
    # quotes or a nowdoc.
    single = src_with(**{PLUGIN_A:
                         b"<?php\n$doc = '{$GLOBALS[\"f\"]($y)}';\n"})
    assert _check()(sus_data(single), DEFAULTS) == []
    nowdoc = src_with(**{PLUGIN_A: (
        b"<?php\n$doc = <<<'EOT'\n{$GLOBALS['f']($y)}\nEOT;\n"
    )})
    assert _check()(sus_data(nowdoc), DEFAULTS) == []
    heredoc = src_with(**{PLUGIN_A: (
        b"<?php\n$x = <<<EOT\n{$GLOBALS['f']($y)}\nEOT;\n"
    )})
    findings = _check()(sus_data(heredoc), DEFAULTS)
    assert len(findings) == 1
    assert findings[0].detail == f"{PLUGIN_A}:3 $GLOBALS-call"


def test_a_brace_inside_a_nested_string_does_not_end_interpolation():
    source = src_with(**{PLUGIN_A: (
        b"<?php\n"
        b"$f = fn($v) => $v;\n"
        b"$y = 3;\n"
        b"$x = \"{$f(['}' => $GLOBALS['f']($y)])}\";\n"
    )})
    findings = _check()(sus_data(source), DEFAULTS)
    assert len(findings) == 1
    assert findings[0].detail == f"{PLUGIN_A}:4 $GLOBALS-call"


def test_a_string_inside_an_interpolation_is_still_not_code():
    settings = replace(
        DEFAULTS, suspicious=replace(DEFAULTS.suspicious, patterns=["  +"])
    )
    source = src_with(**{PLUGIN_A: (
        b"<?php\n$f = fn($v) => $v;\n$x = \"{$f('     ')}\";\n"
    )})
    assert _check()(sus_data(source), settings) == []


@pytest.mark.parametrize("eol", [b"\n", b"\r\n", b"\r"])
def test_line_numbers_survive_every_php_line_ending(eol):
    # PHP accepts all three; a wrong line number sends the operator to the
    # wrong place in the file.
    source = src_with(**{PLUGIN_A: b"<?php" + eol + b"// c" + eol
                         + b"eval(base64_decode('x'));" + eol})
    findings = _check()(sus_data(source), DEFAULTS)
    assert len(findings) == 1
    assert findings[0].detail == f"{PLUGIN_A}:3 eval(decoder)"


def test_php_case_rules_distinguish_functions_from_variables():
    # PHP function names are case-insensitive; VARIABLES are not. A global
    # IGNORECASE treated $x and $X as one variable.
    assert _check()(sus_data(
        src_with(**{PLUGIN_A: b"<?php\nEVAL(BASE64_DECODE('x'));\n"})
    ), DEFAULTS) != []
    for unrelated in (
        b"<?php\n$x = $_POST['i']; eval($X);\n",     # $X is not $x
        b"<?php\neval($_POSTfoo);\n",              # a different variable
        b"<?php\nclass C { function eval($v) {} }\n"
        b"(new C)->eval(base64_decode('x'));\n",    # a method
        b"<?php\nclass C { static function e($v) {} }\n"
        b"C::eval(base64_decode('x'));\n",          # a static call
    ):
        assert _check()(sus_data(src_with(**{PLUGIN_A: unrelated})),
                        DEFAULTS) == []


def test_open_tag_needs_a_boundary():
    # `<?phpfoo` is inline HTML, not an opener.
    assert _check()(sus_data(
        src_with(**{PLUGIN_A: b"<?phpfoo eval(base64_decode('x'));\n"})
    ), DEFAULTS) == []
    # a real tag and the short echo tag both count
    for opener in (b"<?php", b"<?PHP", b"<?="):
        assert _check()(sus_data(
            src_with(**{PLUGIN_A: opener + b" eval(base64_decode('x'));\n"})
        ), DEFAULTS) != []


def test_a_one_megabyte_single_line_file_lexes_promptly():
    # The deadline is only checked per batch, so a lex that is quadratic on a
    # long token can outlive the whole run budget.
    import time
    body = "<?php\n" + "x" * 1000000 + "eval(base64_decode('x'));"
    started = time.monotonic()
    findings = _check()(sus_data(src_with(**{PLUGIN_A: body.encode()})), DEFAULTS)
    elapsed = time.monotonic() - started
    assert len(findings) == 1
    assert elapsed < 5.0, f"scan took {elapsed:.1f}s"


def test_a_heredoc_inside_an_interpolation_is_skipped():
    source = src_with(**{PLUGIN_A: (
        b"<?php\n"
        b"function f($a, $b) {}\n"
        b"$f = 'f';\n"
        b"$y = 1;\n"
        b"$x = \"{$f(<<<EOT\n}\nEOT\n, $GLOBALS['f']($y))}\";\n"
    )})
    findings = _check()(sus_data(source), DEFAULTS)
    assert len(findings) == 1
    # the heredoc body spans lines, so the call is on line 8
    assert findings[0].detail == f"{PLUGIN_A}:8 $GLOBALS-call"


def test_a_nested_string_inside_an_interpolation_stays_data():
    # The inner eval() is a string argument, not code.
    source = src_with(**{PLUGIN_A: (
        b"<?php\n"
        b"function f($v) {}\n"
        b"$f = 'f';\n"
        b"$x = \"{$f(\"eval(base64_decode('x'));\")}\";\n"
    )})
    assert _check()(sus_data(source), DEFAULTS) == []


def test_a_symlink_entry_is_never_read_as_site_content():
    from wpt.types import Entry
    entry = Entry(path="wp-content/plugins/p/link.php", size=10,
                  is_dir=False, is_link=True)
    assert _module()._candidates([entry]) == []


def test_case_insensitive_function_names_with_case_sensitive_variables():
    # eval() is a function name (case-insensitive in PHP); $_POST and $x are
    # variables (case-sensitive). Both halves must hold at once.
    for call in (b"eval($_POST['x']);", b"EVAL($_POST['x']);",
                 b"eVaL($_POST['x']);"):
        assert _check()(sus_data(
            src_with(**{PLUGIN_A: b"<?php\n" + call + b"\n"})
        ), DEFAULTS) != []
    for bad in (b"eval($_Post['x']);", b"eval($POST['x']);"):
        assert _check()(sus_data(
            src_with(**{PLUGIN_A: b"<?php\n" + bad + b"\n"})
        ), DEFAULTS) == []


def test_member_call_detection_tolerates_whitespace():
    for call in (b"$obj->eval(base64_decode('x'));",
                 b"$obj-> eval(base64_decode('x'));",
                 b"C::eval(base64_decode('x'));",
                 b"C :: eval(base64_decode('x'));"):
        assert _check()(sus_data(
            src_with(**{PLUGIN_A: b"<?php\n" + call + b"\n"})
        ), DEFAULTS) == []


def test_a_backtick_command_string_is_not_php_code():
    # Backticks run a SHELL command; their text is data.
    source = src_with(**{PLUGIN_A: (
        b"<?php\n"
        b"$x = `echo eval(base64_decode('x'))`;\n"
        b"eval(base64_decode('real'));\n"
    )})
    findings = _check()(sus_data(source), DEFAULTS)
    assert len(findings) == 1
    assert findings[0].detail == f"{PLUGIN_A}:3 eval(decoder)"


def test_deeply_nested_interpolation_cannot_exhaust_the_stack():
    # An unbounded recursion took the whole check down with RecursionError.
    body = ('{$f("' * 500) + "1" + ('")}' * 500)
    source = src_with(**{PLUGIN_A: (
        "<?php\n$x = " + body + ";\neval(base64_decode('x'));\n"
    ).encode()})
    findings = _check()(sus_data(source), DEFAULTS)
    assert len(findings) == 1
    assert findings[0].detail == f"{PLUGIN_A}:3 eval(decoder)"


def test_dollar_brace_interpolation_is_executable_code():
    source = src_with(**{PLUGIN_A:
                         b"<?php\n$x = \"${eval(base64_decode('x'))}\";\n"})
    findings = _check()(sus_data(source), DEFAULTS)
    assert len(findings) == 1
    assert findings[0].detail == f"{PLUGIN_A}:2 eval(decoder)"


def test_a_long_many_statement_config_resolves_promptly():
    # The constant scan used to rescan the file prefix per token, which made
    # an ordinary wp-config take seconds.
    import time
    from wpt.audit.security import _php_const_state
    text = "<?php\n" + "a;\n" * 8000 + "define('RELOCATE', true);\n"
    started = time.monotonic()
    state = _php_const_state(text, "RELOCATE")
    elapsed = time.monotonic() - started
    assert state == "truthy"
    assert elapsed < 2.0, f"constant scan took {elapsed:.1f}s"


def test_backtick_strings_interpolate_like_php():
    # A backtick string is an INTERPOLATED string: ${...} inside it executes.
    source = src_with(**{PLUGIN_A: (
        b"<?php\n"
        b"$x = `printf %s ${eval(base64_decode('cmVjaG8gJ01BUiI7'))}`;\n"
    )})
    findings = _check()(sus_data(source), DEFAULTS)
    assert len(findings) == 1
    assert findings[0].detail == f"{PLUGIN_A}:2 eval(decoder)"
    # a backslash-backtick pair is an escaped delimiter, so the text after it
    # is still command data
    source = src_with(**{PLUGIN_A:
                         b"<?php\n$x = `printf '' \\` eval(base64_decode(1))'`;\n"})
    assert _check()(sus_data(source), DEFAULTS) == []


def test_an_unparseable_file_yields_no_trusted_signature():
    # The file ends inside a string: PHP would raise a parse error, so the
    # later text is not a signature we can stand behind.
    source = src_with(**{PLUGIN_A: (
        b"<?php\n$x = \"${f(`\";\neval(base64_decode('x'));\n"
    )})
    assert _check()(sus_data(source), DEFAULTS) == []


def test_a_namespace_heavy_megabyte_config_resolves_promptly():
    import time
    from wpt.audit.security import _php_const_state
    unit = "namespace N {}\n"
    text = "<?php\n" + unit * ((1024 * 1024 - 6) // len(unit))
    started = time.monotonic()
    state = _php_const_state(text, "RELOCATE")
    elapsed = time.monotonic() - started
    assert state == "absent"
    # 10s is a load ceiling, not the expectation (~1s standalone): one xdist
    # run on a loaded host measured 3.4s, while a quadratic regression here
    # still takes far longer.
    assert elapsed < 10.0, f"constant scan took {elapsed:.1f}s for 1 MiB"


@pytest.mark.parametrize("label", ["member", "brace_stack", "many_if"])
def test_the_constant_scan_stays_linear_on_adversarial_input(label):
    # Each of these grew super-linearly before: a per-token prefix copy, a
    # per-token brace-stack rescan, and an unbounded header regex.
    import time
    from wpt.audit.security import _php_const_state
    if label == "member":
        text = "<?php\n" + "$o->__halt_compiler();\n" * 8000 \
            + "eval(base64_decode('x'));"
    elif label == "brace_stack":
        text = "<?php\n" + "{a;" * 20000 + "}" * 20000
    else:
        text = "<?php\n" + "if " * 20000
    started = time.monotonic()
    _php_const_state(text, "RELOCATE")
    elapsed = time.monotonic() - started
    assert elapsed < 3.0, f"{label}: constant scan took {elapsed:.1f}s"


@pytest.mark.parametrize("unit", [b"${x}", b"{$x}"])
def test_dense_interpolation_stays_linear(unit):
    # Two separate searches for the two opener forms each rescanned the tail,
    # which was quadratic on a literal full of interpolations. Two checks keep
    # that from returning: the SCALING itself (four times the input may cost
    # at most eight times the work — linear ~4x, quadratic ~16x) and a loose
    # absolute wall-clock ceiling. The ratio is deliberately measured in CPU
    # time, not wall time: under parallel xdist load this process is scheduled
    # unpredictably, and wall-clock ratios of the LINEAR scan ranged from 1.5x
    # to 14x in a 20-worker stress run, while its CPU-time ratio stayed within
    # 3.6x-4.6x. The wall sample is retried once if it exceeds the ceiling, so
    # a loaded host must stall TWO samples before the test fails.
    import time
    from wpt.audit.security import _php_code_flags

    def timed(units: int) -> tuple[float, float]:
        text = (b'<?php\n$x = "' + unit * units + b'";\n').decode()
        cpu_started = time.process_time()
        wall_started = time.monotonic()
        _php_code_flags(text)
        elapsed = time.monotonic() - wall_started
        return elapsed, time.process_time() - cpu_started

    # 30k -> 120k units is a 4x input: linear ~4x, quadratic ~16x. The small
    # floor only absorbs timer resolution on a machine far faster than this
    # one; the 8x midpoint leaves ~2x headroom on either side.
    _, small_cpu = timed(30_000)
    large_wall, large_cpu = timed(120_000)
    assert large_cpu < 8 * small_cpu + 0.02, (
        f"super-linear interpolation scan: 30k units cost {small_cpu:.2f}s "
        f"of CPU, 120k units cost {large_cpu:.2f}s"
    )
    # Absolute safety net, not the linearity proof: 16x the standalone time,
    # well beyond the ~4.6x wall-clock slowdown seen under 20-way contention.
    if large_wall >= 10.0:
        large_wall = min(large_wall, timed(120_000)[0])
    assert large_wall < 10.0, f"lex took {large_wall:.1f}s"


def test_escaped_interpolation_opener_is_literal_text():
    # "\${...}" prints ${...}; PHP executes nothing, so neither may we.
    body = b"eval(base64_decode('ZWNobyAiSW52b2tlZCI7'))"
    literal = src_with(**{PLUGIN_A: b'<?php\n$x = "\\${' + body + b'}";\n'})
    assert _check()(sus_data(literal), DEFAULTS) == []
    # The unescaped form is still reported.
    live = src_with(**{PLUGIN_A: b'<?php\n$x = "${' + body + b'}";\n'})
    assert len(_check()(sus_data(live), DEFAULTS)) == 1


def test_superglobal_pattern_reaches_nested_request_arrays():
    settings = replace(
        DEFAULTS, suspicious=replace(DEFAULTS.suspicious,
                                     patterns=DEFAULTS.suspicious.patterns[2:3])
    )
    # $_POST['a']['b'] is request data reaching eval, not a missed signature.
    nested = src_with(**{PLUGIN_A: b"<?php\n$x = $_POST['a']['b']; eval($x);\n"})
    assert len(_check()(sus_data(nested), settings)) == 1
    # ...and a different variable is still not a match.
    other = src_with(**{PLUGIN_A: b"<?php\n$x = $_POST['a']['b']; eval($y);\n"})
    assert _check()(sus_data(other), settings) == []


def test_unterminated_declare_headers_do_not_rescan_the_file():
    import time
    from wpt.audit.security import _php_const_state
    text = "<?php\n" + "declare(ticks=1)" * 20000
    # CPU time, not wall: under a 20-worker xdist run the host can deschedule
    # this process for seconds while the scan itself is CPU-bound (measured
    # 4.5 s wall / <1 s CPU in the same round).
    cpu_started = time.process_time()
    assert _php_const_state(text, "RELOCATE") == "absent"
    elapsed = time.process_time() - cpu_started
    assert elapsed < 3.0, f"constant scan took {elapsed:.1f}s CPU"


def test_a_comment_cannot_hide_a_signature_by_splitting_its_tokens():
    # `eval(/*x*/base64_decode(...))` is a real call: the comment only hides it
    # from a raw line scan, which must not be the only pass that runs.
    split = src_with(**{
        PLUGIN_A: b'<?php\neval(/*x*/base64_decode("MTs="));\n',
        PLUGIN_B: b'<?php\neval(base64_decode("MTs="));\n',
    })
    findings = _check()(sus_data(split), DEFAULTS)
    assert len(findings) == 1
    assert findings[0].detail == (
        f"{PLUGIN_A}:2 eval(decoder)\n{PLUGIN_B}:2 eval(decoder)"
    )
    # A signature that is ONLY inside a comment or a string is still silent.
    for benign in (
        b"<?php\n// eval(base64_decode('x'))\n",
        b"<?php\n/* eval(base64_decode('x')) */\n",
        b'<?php\n$a = "eval(base64_decode(1))";\n',
    ):
        assert _check()(sus_data(src_with(**{PLUGIN_A: benign})), DEFAULTS) == []


def test_a_decoy_elsewhere_does_not_hide_a_comment_split_signature():
    # The raw pass matches the string, so the blanked-text pass must still run:
    # it used to be skipped whenever the raw pass found anything.
    source = src_with(**{
        PLUGIN_A: b'<?php\n$x = \'eval(base64_decode("x"))\';\n'
                  b'eval(/*x*/base64_decode("MTs="));\n',
    })
    findings = _check()(sus_data(source), DEFAULTS)
    assert len(findings) == 1
    assert findings[0].detail == f"{PLUGIN_A}:3 eval(decoder)"


def test_a_fully_qualified_decoder_is_still_the_signature():
    # PHP's global namespace separator does not change what is called, so
    # `eval(\base64_decode(...))` executes exactly like the bare form.
    for source in (
        b'<?php\neval(\\base64_decode("x"));\n',
        b'<?php\neval( \\ base64_decode("x"));\n',
    ):
        findings = _check()(
            sus_data(src_with(**{PLUGIN_A: source})), DEFAULTS
        )
        assert len(findings) == 1, source
        assert findings[0].detail == f"{PLUGIN_A}:2 eval(decoder)"


def test_a_signature_split_across_lines_is_still_found():
    # Splitting the call across lines is the obvious way to hide it from a
    # line scanner, so the match must not stop at a line boundary.
    for source, lineno in (
        (b'<?php\neval(\nbase64_decode("x"));\n', 2),
        (b'<?php\neval(\n  base64_decode\n  ("x"));\n', 2),
        (b'<?php\r\neval(\r\nbase64_decode("x"));\r\n', 2),
    ):
        findings = _check()(
            sus_data(src_with(**{PLUGIN_A: source})), DEFAULTS
        )
        assert len(findings) == 1, source
        assert findings[0].detail == f"{PLUGIN_A}:{lineno} eval(decoder)", source


def test_a_line_break_cannot_join_unrelated_code():
    # The patterns bridge tokens with \\s*, so only a pure-whitespace gap can
    # join them: a string, a terminator or an operator is not whitespace.
    for benign in (
        b'<?php\n$a = "eval(";\nbase64_decode("x");\n',
        b'<?php\n$a = "eval(\n";\nbase64_decode("x");\n',
        b'<?php\n// eval(\nbase64_decode("x");\n',
    ):
        assert _check()(sus_data(src_with(**{PLUGIN_A: benign})), DEFAULTS) == []


def test_unmodelled_interpolation_is_never_reported_as_code():
    # Past the lexer's structural bound a region may hold only string text.
    # Reporting it would break this check's "executable code only" contract,
    # so an UNMODELLED byte is treated as NOT code here; the constant scanner
    # still fails closed on the same byte.
    from wpt.audit.security import _CODE_UNMODELLED, _php_code_flags
    patterns = _module()._compile_patterns(DEFAULTS.suspicious.patterns)
    payload = 'eval(base64_decode("x"));'
    for levels in (3, 23, 24, 40):
        inner = payload
        for _ in range(levels):
            inner = '${f("' + inner + '")}'
        source = '<?php\n$x = "' + inner + '";\n'
        assert _module()._scan_text(source, patterns) == [], levels
    # the marker really is produced, so the guard is not vacuous
    inner = "1"
    for _ in range(40):
        inner = '${f("' + inner + '")}'
    deep = '<?php\n$x = "' + inner + '";\n'
    assert any(b == _CODE_UNMODELLED for b in _php_code_flags(deep)[0])
    # a real signature at the top level is still found
    real = '<?php\neval(base64_decode("x"));\n'
    assert _module()._scan_text(real, patterns)


def test_a_variable_callable_is_not_the_eval_construct():
    # `$eval(...)` calls a closure held in a variable; PHP tokenizes it as a
    # variable, so it is not the language construct. `${eval(...)}` is
    # different: there `eval` really is the construct.
    source = src_with(**{
        PLUGIN_A: b"<?php\n$eval = static fn($v) => $v;\n"
                  b'$eval(base64_decode("x"));\n',
    })
    assert _check()(sus_data(source), DEFAULTS) == []
    # ...but the construct itself, reached through `${...}`, is still reported,
    # and a nullsafe method call is still a method call.
    for construct, expected in (
        (b'<?php\neval(base64_decode("x"));\n', 1),
        (b'<?php\n$x = "${eval(base64_decode(1))}";\n', 1),
        (b'<?php\n$o = null; $o?->eval(base64_decode("x"));\n', 0),
    ):
        found = _check()(sus_data(src_with(**{PLUGIN_A: construct})), DEFAULTS)
        assert len(found) == expected, construct


def test_a_line_comment_is_not_cut_short_by_an_arrow():
    # `//` comments end at a newline or `?>`, never at the `>` of a `->`
    # inside them: stopping there turned comment text into executable code and
    # reported a backdoor that does not exist.
    source = src_with(**{PLUGIN_A: b'<?php\n// $o->eval(base64_decode("x"));\n'})
    assert _check()(sus_data(source), DEFAULTS) == []
    # `?>` still closes the comment, and the signature is still found.
    live = src_with(**{PLUGIN_A: b'<?php\neval(base64_decode("x")); ?>\n'})
    assert len(_check()(sus_data(live), DEFAULTS)) == 1


def test_scope_covers_every_php_execution_surface():
    infected = b"<?php\n" + EVAL_B64_LINE
    paths = {
        "wp-includes/class-x.php": infected,          # core: core.integrity's job
        "drop.php": infected,                        # webroot PHP: executes
        "wp-config.php": infected,                   # runs on every load
        "wp-content/plugins-x/x.php": infected,      # sibling prefix: no
        "wp-content/db.php": infected,                # drop-in: auto-loaded
        "wp-content/object-cache.php": infected,      # drop-in
        "wp-content/mu-plugins/loader.php": infected,  # auto-loaded
        "wp-content/uploads/2023/shell.php": infected,  # where backdoors land
        "wp-content/uploads/.htacces": infected,      # hidden payload, no suffix
        "wp-content/.htaccess": infected,             # config dotfile: not read
        "wp-content/uploads/.user.ini": infected,     # config dotfile: not read
        "wp-content/uploads/2023/photo.jpg": infected,  # not PHP
        "wp-content/languages/fr_FR.l10n.php": infected,  # locale, included
        "wp-admin/evil.php": infected,                 # entrypoint surface
        # a hidden file must NOT slip past the prefix exclusions
        "wp-includes/.evil": infected,
        "wp-content/plugins-x/.htacces": infected,
        "wp-content/uploads-old/.htacces": infected,
        "wp-content/uploads-old/other.php": infected,
        # an attacker writes wherever the web user can write, so EVERY .php
        # under wp-content/ is scanned, not just the six well-known trees
        "wp-content/cache/shell.php": infected,
        "wp-content/upgrade/stage.php": infected,
        "wp-content/custom-dir/deep/shell.php": infected,
        "wp-content/plugins-x/other.php": infected,
        THEME_T: infected,                           # themes
        "wp-content/plugins/up/UP.PHP": infected,    # suffix case-insensitive
        # a DIRECTORY named *.php is never a hit; the file inside is
        "wp-content/plugins/weird.php/inner.php": infected,
    }
    source = src_with(**paths)
    # the exact scan set, so breadth is pinned without fighting the 8-line
    # detail cap
    assert [e.path for e in
            _module()._candidates(sus_data(source).entries)] == [
        "drop.php",
        "wp-admin/evil.php",
        "wp-config.php",
        "wp-content/cache/shell.php",
        "wp-content/custom-dir/deep/shell.php",
        "wp-content/db.php",
        "wp-content/languages/fr_FR.l10n.php",
        "wp-content/mu-plugins/loader.php",
        "wp-content/object-cache.php",
        "wp-content/plugins-x/other.php",
        "wp-content/plugins-x/x.php",
        "wp-content/plugins/up/UP.PHP",
        "wp-content/plugins/weird.php/inner.php",
        "wp-content/themes/t/functions.php",
        "wp-content/upgrade/stage.php",
        "wp-content/uploads-old/other.php",
        "wp-content/uploads/.htacces",
        "wp-content/uploads/2023/shell.php",
    ]
    findings = _check()(sus_data(source), DEFAULTS)
    assert len(findings) == 1
    f = findings[0]
    f.validate()
    assert f.count == 18
    assert f.detail.splitlines()[:8] == [
        "drop.php:2 eval(decoder)",
        "wp-admin/evil.php:2 eval(decoder)",
        "wp-config.php:2 eval(decoder)",
        "wp-content/cache/shell.php:2 eval(decoder)",
        "wp-content/custom-dir/deep/shell.php:2 eval(decoder)",
        "wp-content/db.php:2 eval(decoder)",
        "wp-content/languages/fr_FR.l10n.php:2 eval(decoder)",
        "wp-content/mu-plugins/loader.php:2 eval(decoder)",
    ]
    assert f.detail.splitlines()[8] == "(+10 more)"


def test_scope_skips_a_dotfile_without_php_content():
    # .htaccess/.user.ini carry no PHP: scanning them would spend a read and
    # could only ever produce a false positive.
    source = src_with(**{
        "wp-content/.htaccess": b"<?php\neval(base64_decode('x'));\n",
        "wp-content/.user.ini": b"<?php\neval(base64_decode('x'));\n",
        "wp-content/plugins/a/a.php": b"<?php\n",
    })
    assert _check()(sus_data(source), DEFAULTS) == []


def test_max_file_bytes_skips_oversize():
    settings = replace(
        DEFAULTS, suspicious=replace(DEFAULTS.suspicious, max_file_bytes=64)
    )
    big = b"<?php\n" + EVAL_B64_LINE + b"#" * 100      # 139 B: over the limit
    small = b"<?php\n" + EVAL_B64_LINE                 # 39 B: under it
    assert len(big) == 139 and len(small) == 39
    source = src_with(**{PLUGIN_A: big, PLUGIN_B: small})
    f = _check()(sus_data(source), settings)[0]
    assert f.count == 1                                # the big file is silent
    assert f.detail == f"{PLUGIN_B}:2 eval(decoder)"
    assert f.bytes == len(small)
    # an all-oversize tree reports nothing
    assert _check()(sus_data(src_with(**{PLUGIN_A: big})), settings) == []


def test_at_limit_is_scanned():
    settings = replace(
        DEFAULTS, suspicious=replace(DEFAULTS.suspicious, max_file_bytes=39)
    )
    content = b"<?php\n" + EVAL_B64_LINE               # exactly 39 B
    assert len(content) == 39
    source = src_with(**{PLUGIN_A: content})
    assert _check()(sus_data(source), settings)[0].count == 1


def test_read_failure_skips_file(wpt_records):
    source = _ReadFails("wp-content/plugins/a/")
    source.files.update({
        PLUGIN_A: b"<?php\n" + EVAL_B64_LINE,          # read raises
        PLUGIN_B: b"<?php\n" + EVAL_B64_LINE,          # readable
    })
    findings = _check()(sus_data(source), DEFAULTS)
    assert len(findings) == 1
    f = findings[0]
    assert f.count == 1
    assert f.detail == f"{PLUGIN_B}:2 eval(decoder)"
    skips = [r for r in wpt_records
             if r.name == "wpt.audit.suspicious" and r.levelno == logging.DEBUG
             and PLUGIN_A in r.getMessage()]
    assert len(skips) == 1 and "unreadable, skipped" in skips[0].getMessage()
    # one failure is far under the breaker bound: no abort, no warning
    assert check_warnings(wpt_records) == []


# ------------------------------------------------- the circuit breaker


def test_breaker_aborts(wpt_records):
    # first file readable and INFECTED (verified), then 26 unreadable
    # candidates: the scan aborts ON the 25th consecutive failure with
    # ONE warning and returns the partial verified finding.  Reads are
    # batch-granular: the whole one batch (28 candidates) is fetched up
    # front — 28 read attempts, the batched-era pin — and the abort
    # stops PROCESSING at the 25th failure plus any further batch: the
    # 26th failure and the also-infected tail were fetched but are
    # discarded unprocessed (the finding set proves it)
    first = "wp-content/plugins/aa/first.php"
    bad = [f"wp-content/plugins/bad/bad{i:02d}.php" for i in range(26)]
    tail = "wp-content/plugins/zz/tail.php"
    infected = b"<?php\n" + EVAL_B64_LINE
    source = _FailingReadsSource(bad)
    source.files.update(
        {first: infected, **{path: b"x" for path in bad}, tail: infected}
    )
    findings = _check()(sus_data(source), DEFAULTS)
    assert [(f.detail, f.count, f.risk) for f in findings] == [
        (f"{first}:2 eval(decoder)", 1, "high"),
    ]
    # the good read + every candidate of the one fetched batch; the
    # abort contributes nothing further
    assert source.read_attempts == 28
    assert check_warnings(wpt_records) == [
        "suspicious scan aborted after 25 consecutive unreadable "
        "files; results are partial",
    ]


def test_breaker_reset_on_success(wpt_records):
    # 30 candidates, only the FIRST 24 unreadable: the 25th read
    # succeeds and resets the counter, so the scan continues to the
    # last file — whose infection reports and proves it — with NO
    # abort warning
    paths = [f"wp-content/plugins/p/p{i:02d}.php" for i in range(30)]
    infected = b"<?php\n" + EVAL_B64_LINE
    files = {path: b"<?php\necho 'clean';\n" for path in paths}
    files[paths[-1]] = infected                     # the 30th file
    source = _FailingReadsSource(paths[:24])
    source.files.update(files)
    findings = _check()(sus_data(source), DEFAULTS)
    assert [(f.detail, f.count, f.risk) for f in findings] == [
        (f"{paths[-1]}:2 eval(decoder)", 1, "high"),
    ]
    assert source.read_attempts == 30  # every candidate was read
    assert check_warnings(wpt_records) == []


def test_breaker_oversize_not_a_failure(wpt_records):
    # a size-gated skip between failures is POLICY, not health: it is
    # never read, so it neither counts toward the bound nor breaks the
    # consecutive chain — the next failure is still the 25th
    # consecutive and aborts (the also-infected tail is fetched but
    # discarded unprocessed)
    settings = replace(
        DEFAULTS, suspicious=replace(DEFAULTS.suspicious, max_file_bytes=64)
    )
    first = "wp-content/plugins/aa/first.php"
    bad = [f"wp-content/plugins/bb/b{i:02d}.php" for i in range(24)]
    huge = "wp-content/plugins/mm/huge.php"
    last = "wp-content/plugins/nn/last.php"
    tail = "wp-content/plugins/zz/tail.php"
    infected = b"<?php\n" + EVAL_B64_LINE           # 39 B: under the limit
    source = _FailingReadsSource(bad + [last])
    source.files.update({
        first: infected,
        **{path: b"x" for path in bad},
        huge: infected + b"#" * 100,                # 139 B: oversize, skipped
        last: b"x",                                 # the 25th failure
        tail: infected,                             # never read
    })
    findings = _check()(sus_data(source), settings)
    assert [(f.detail, f.count, f.risk) for f in findings] == [
        (f"{first}:2 eval(decoder)", 1, "high"),
    ]
    # the good read + 24 failures + the 25th failure — every candidate
    # of the one gated batch (27: the oversize skip is never read, the
    # tail was fetched but is discarded unprocessed after the abort)
    assert source.read_attempts == 27
    assert check_warnings(wpt_records) == [
        "suspicious scan aborted after 25 consecutive unreadable "
        "files; results are partial",
    ]


# ------------------------------------------- batched reads (the read_many seam)


def test_batched_happy_path():
    # 425 infected files -> read_many batches of 200/200/25: every batch
    # within the structural bound, chunking slices the sorted candidate
    # list losslessly, and the aggregate is exactly the serial
    # expectation (count, bytes, 8-line detail + marker)
    paths = [f"wp-content/plugins/p/p{i:03d}.php" for i in range(425)]
    content = b"<?php\n" + EVAL_B64_LINE
    source = _RecordingReadMany()
    source.files.update({path: content for path in paths})
    findings = _check()(sus_data(source), DEFAULTS)
    assert [len(batch) for batch in source.batches] == [200, 200, 25]
    assert all(len(batch) <= 200 for batch in source.batches)
    # The read itself is bounded (a lying listing cannot materialize a body).
    assert source.max_bytes == [DEFAULTS.suspicious.max_file_bytes] * 3
    # consecutive slices of the sorted list: nothing lost, reordered
    # or fetched twice
    assert [path for batch in source.batches for path in batch] == sorted(paths)
    assert len(findings) == 1
    f = findings[0]
    f.validate()
    assert (f.count, f.bytes) == (425, 425 * len(content))
    lines = f.detail.splitlines()
    assert len(lines) == 9                              # 8 hits + marker
    assert lines[0] == "wp-content/plugins/p/p000.php:2 eval(decoder)"
    assert lines[7] == "wp-content/plugins/p/p007.php:2 eval(decoder)"
    assert lines[-1] == "(+417 more)"


def test_breaker_trips_across_batches(wpt_records):
    # the counter spans batch boundaries: 24 consecutive failed-map
    # entries end batch 1, the 25th opens batch 2 -> ONE abort warning,
    # the partial verified finding, and batch 3 is NEVER fetched
    paths = [f"wp-content/plugins/p/p{i:03d}.php" for i in range(450)]
    infected = b"<?php\n" + EVAL_B64_LINE
    source = _RecordingReadMany(fail_paths=paths[176:201])
    source.files.update(
        {path: infected if path == paths[0] else b"<?php\n" for path in paths}
    )
    findings = _check()(sus_data(source), DEFAULTS)
    assert [(f.detail, f.count, f.risk) for f in findings] == [
        (f"{paths[0]}:2 eval(decoder)", 1, "high"),
    ]
    assert [len(batch) for batch in source.batches] == [200, 200]
    assert check_warnings(wpt_records) == [
        "suspicious scan aborted after 25 consecutive unreadable "
        "files; results are partial",
    ]


def test_breaker_resets_on_ok_batch_entry(wpt_records):
    # the mirror: 24 consecutive failures END batch 1, batch 2 opens
    # with an ok entry -> the counter resets and the scan runs to the
    # last file (its infection reports and proves it), no warning, both
    # batches fetched
    paths = [f"wp-content/plugins/p/p{i:03d}.php" for i in range(210)]
    infected = b"<?php\n" + EVAL_B64_LINE
    source = _RecordingReadMany(fail_paths=paths[176:200])
    source.files.update(
        {path: infected if path == paths[-1] else b"<?php\n" for path in paths}
    )
    findings = _check()(sus_data(source), DEFAULTS)
    assert [(f.detail, f.count, f.risk) for f in findings] == [
        (f"{paths[-1]}:2 eval(decoder)", 1, "high"),
    ]
    assert [len(batch) for batch in source.batches] == [200, 10]
    assert check_warnings(wpt_records) == []


# ------------------------------------------------------- the run deadline


def test_deadline_mid_scan_partial(wpt_records):
    # a budget spent after batch 1: the check returns batch 1's
    # findings with ONE exact warning and NEVER raises the
    # DeadlineExceeded back — batch 2 (whose own infection proves it
    # was never processed) is not even fetched: the budget is checked
    # BEFORE the read
    paths = [f"wp-content/plugins/p/p{i:03d}.php" for i in range(210)]
    infected = b"<?php\n" + EVAL_B64_LINE
    source = _RecordingReadMany()
    source.files.update(
        {path: infected if path in (paths[0], paths[205]) else b"<?php\n"
         for path in paths}
    )
    deadline = _DeadlineAfterOneBatch()
    findings = _check()(
        replace(sus_data(source), deadline=deadline), DEFAULTS
    )
    assert [(f.detail, f.count, f.risk) for f in findings] == [
        (f"{paths[0]}:2 eval(decoder)", 1, "high"),
    ]
    assert [len(batch) for batch in source.batches] == [200]
    assert deadline.checks == 2
    assert check_warnings(wpt_records) == [
        "suspicious scan stopped: run deadline exceeded; results are partial",
    ]


def test_deadline_expired_before_scan(wpt_records):
    # a REAL Deadline(0.0001) — it expires immediately: the deadline is
    # built BEFORE the fixture, so the 1200-file build (dict + walk +
    # the check's own candidate pass) has spent the 0.1 ms budget many
    # times over by the first batch check — no sleep, no clock race.
    # The check catches the raise: partial [] + the ONE warning, and
    # nothing is ever fetched (an all-infected tree: any determinism
    # break would surface as findings/batches, not silence)
    deadline = Deadline(0.0001)
    paths = [f"wp-content/plugins/p/p{i:04d}.php" for i in range(1200)]
    source = _RecordingReadMany()
    source.files.update(
        {path: b"<?php\n" + EVAL_B64_LINE for path in paths}
    )
    findings = _check()(
        replace(sus_data(source), deadline=deadline), DEFAULTS
    )
    assert findings == []                       # nothing scanned: partial = []
    assert source.batches == []                  # read_many never called
    assert check_warnings(wpt_records) == [
        "suspicious scan stopped: run deadline exceeded; results are partial",
    ]


def test_deadline_none_unchanged(wpt_records):
    # deadline None (the unbounded default): the full scan, unchanged
    # behavior — both files' findings, no warnings
    source = src_with(
        **{PLUGIN_A: b"<?php\n" + EVAL_B64_LINE,
           PLUGIN_B: b"<?php\n" + EVAL_POST_LINE}
    )
    findings = _check()(replace(sus_data(source), deadline=None), DEFAULTS)
    assert [(f.detail, f.count, f.risk) for f in findings] == [
        (f"{PLUGIN_A}:2 eval(decoder)\n"
         f"{PLUGIN_B}:2 eval(superglobal)", 2, "high"),
    ]
    assert check_warnings(wpt_records) == []


def test_custom_pattern_from_profile():
    settings = replace(
        DEFAULTS, suspicious=replace(DEFAULTS.suspicious, patterns=["WPTHING"])
    )
    source = src_with(
        **{PLUGIN_A: b"<?php\nWPTHING marker\n",
           PLUGIN_B: b"<?php\nnothing here\n"}
    )
    f = _check()(sus_data(source), settings)[0]
    assert f.count == 1
    assert f.detail == f"{PLUGIN_A}:2 pattern[0]"      # profile label shape


def test_invalid_regex_skipped(wpt_records):
    settings = replace(
        DEFAULTS,
        suspicious=replace(DEFAULTS.suspicious, patterns=["([", "WPTHING"]),
    )
    source = src_with(**{PLUGIN_A: b"<?php\nWPTHING marker\n"})
    findings = _check()(sus_data(source), settings)
    errors = [r for r in wpt_records
              if r.name == "wpt.audit.suspicious" and r.levelno == logging.ERROR]
    assert len(errors) == 1
    assert "pattern 0" in errors[0].getMessage()
    assert len(findings) == 1                          # the valid pattern applies
    assert findings[0].detail == f"{PLUGIN_A}:2 pattern[1]"


def test_non_string_pattern_skipped(wpt_records):
    # the override path can deliver non-string list members; the check
    # skips the malformed entry instead of dying on re.compile/search
    settings = replace(
        DEFAULTS, suspicious=replace(DEFAULTS.suspicious, patterns=[1, "WPTHING"])
    )
    source = src_with(**{PLUGIN_A: b"<?php\nWPTHING marker\n"})
    findings = _check()(sus_data(source), settings)
    errors = [r for r in wpt_records
              if r.name == "wpt.audit.suspicious" and r.levelno == logging.ERROR]
    assert len(errors) == 1
    assert "pattern 0 is not a string" in errors[0].getMessage()
    assert len(findings) == 1
    assert findings[0].detail == f"{PLUGIN_A}:2 pattern[1]"


def test_source_none_degrades(wpt_records):
    source = src_with(**{PLUGIN_A: b"<?php\n" + EVAL_B64_LINE})
    data = replace(sus_data(source), source=None)     # hand-built data shape
    assert _check()(data, DEFAULTS) == []
    assert any(
        r.name == "wpt.audit.suspicious" and "no content source" in r.getMessage()
        for r in wpt_records if r.levelno == logging.DEBUG
    )


def test_bare_settings_silent():
    source = src_with(**{PLUGIN_A: b"<?php\n" + EVAL_B64_LINE})
    assert _check()(sus_data(source), Settings()) == []  # no patterns: []


def test_detail_truncated_at_eight():
    content = b"<?php\n" + EVAL_B64_LINE
    files = {
        f"wp-content/plugins/p{i:02d}/p{i:02d}.php": content for i in range(10)
    }
    f = _check()(sus_data(src_with(**files)), DEFAULTS)[0]
    assert f.count == 10
    assert f.bytes == 10 * len(content)
    lines = f.detail.splitlines()
    assert len(lines) == 9                              # 8 hits + the marker
    assert lines[0] == "wp-content/plugins/p00/p00.php:2 eval(decoder)"
    assert lines[7] == "wp-content/plugins/p07/p07.php:2 eval(decoder)"
    assert lines[-1] == "(+2 more)"


def test_both_modes_identical():
    source = src_with(
        **{PLUGIN_A: b"<?php\n" + EVAL_B64_LINE,
           THEME_T: b"<?php\n" + EVAL_POST_LINE}
    )
    ftp = _check()(sus_data(source, mode="ftp"), DEFAULTS)
    local = _check()(sus_data(source, mode="local"), DEFAULTS)
    assert ftp == local and len(ftp) == 1


# --------------------------------------------------------------------- logs


def test_logs(wpt_records):
    infected = src_with(**{PLUGIN_A: b"<?php\n" + EVAL_B64_LINE})
    clean = src_with(**{"wp-content/plugins/g/g.php": b"<?php\n"})
    check = _check()

    assert len(check(sus_data(infected), DEFAULTS)) == 1
    infos = [r for r in wpt_records
             if r.name == "wpt.audit.suspicious" and r.levelno == logging.INFO]
    assert len(infos) == 1
    assert "1 scanned file(s) matched a backdoor signature" in infos[0].getMessage()
    assert "(1 distinct hit(s))" in infos[0].getMessage()
    debugs = [r for r in wpt_records
              if r.name == "wpt.audit.suspicious" and r.levelno == logging.DEBUG
              and "scanned" in r.getMessage()]
    assert len(debugs) == 1
    assert "scanned 1 file(s)" in debugs[0].getMessage()

    # a clean scan stays silent at info — silence IS the result
    before = len(wpt_records)
    assert check(sus_data(clean), DEFAULTS) == []
    added = wpt_records[before:]
    assert not [r for r in added
                if r.name == "wpt.audit.suspicious" and r.levelno == logging.INFO]
    assert any(
        r.name == "wpt.audit.suspicious" and "scanned 1 file(s)" in r.getMessage()
        and "0 candidate(s)" in r.getMessage()
        for r in added if r.levelno == logging.DEBUG
    )


# ------------------------------------------------- label mirror + registry


def test_default_labels_mirror_profile():
    module = _module()
    shipped = set(DEFAULTS.suspicious.patterns)
    assert shipped                                  # the profile has defaults
    assert set(module._PATTERN_LABELS) == shipped   # exact both-way mirror
    assert all(
        isinstance(label, str) and label
        for label in module._PATTERN_LABELS.values()
    )


def test_registry_integration():
    check = _check()
    checks = {rec.name: rec for rec in all_checks()}
    rec = checks["security.suspicious"]
    assert rec.applies == ("ftp", "local")
    assert rec.func is check
    assert [r.name for r in select_checks("ftp", ["security.suspicious"], None)] \
        == ["security.suspicious"]
    assert [r.name for r in select_checks("local", ["security.suspicious"], None)] \
        == ["security.suspicious"]
    source = src_with(**{PLUGIN_A: b"<?php\n" + EVAL_B64_LINE})
    findings = run_checks(
        sus_data(source), DEFAULTS, "ftp", ["security.suspicious"], None
    )
    assert [(f.category, f.name) for f in findings] == [
        ("security.suspicious", "suspicious-code")
    ]
    findings[0].validate()
    assert run_checks(
        sus_data(source), DEFAULTS, "local", ["security.suspicious"], None
    ) == findings


# --------------------------------------------------------- progress heartbeat


def test_scan_heartbeat_reports_pace(monkeypatch, wpt_records):
    """[L15] With the heartbeat spacing pinned open, ONE info pace line
    per batch head — the live lesson: an ~11-minute SILENT bulk scan is
    indistinguishable from a wedged run.  The lines carry scanned/total
    and infected-so-far (counts only, never content)."""
    module = _module()
    monkeypatch.setattr(module, "_HEARTBEAT_S", 0.0)
    paths = [f"wp-content/plugins/p/p{i:03d}.php" for i in range(425)]
    source = src_with(**{path: b"<?php\n// benign\n" for path in paths})
    assert _check()(sus_data(source), DEFAULTS) == []
    beats = [r.getMessage() for r in wpt_records
             if r.name == "wpt.audit.suspicious" and r.levelno == logging.INFO
             and r.getMessage().startswith("suspicious: scanned")]
    # one per batch head (200/200/25): scanned counts everything BEFORE
    # the batch about to run (the elapsed suffix is unpinned)
    assert [b[:b.rindex(" (")] for b in beats] == [
        "suspicious: scanned 0/425 file(s), 0 candidate(s) so far",
        "suspicious: scanned 200/425 file(s), 0 candidate(s) so far",
        "suspicious: scanned 400/425 file(s), 0 candidate(s) so far",
    ]


def test_scan_heartbeat_silent_on_fast_scan(wpt_records):
    """The shipped 10s spacing keeps a fast scan silent — test_logs' exact
    INFO-count pins stay valid because no heartbeat can fire in-session."""
    module = _module()
    assert module._HEARTBEAT_S == 10.0
    source = src_with(**{PLUGIN_A: b"<?php\n" + EVAL_B64_LINE})
    assert len(_check()(sus_data(source), DEFAULTS)) == 1
    assert not [
        r for r in wpt_records
        if r.name == "wpt.audit.suspicious" and r.levelno == logging.INFO
        and r.getMessage().startswith("suspicious: scanned")
    ]
