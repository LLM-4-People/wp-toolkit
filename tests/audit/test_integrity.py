"""Unit tests for the WP core file-integrity check (wpt.audit.integrity).

NO network: the check rides the real WpOrgApi transport over the shared
FakeSession (mirroring tests/audit/test_updates.py — the check requests
ONLY api.wordpress.org, never the site URL), and the response cache is
monkeypatched to a tmp_path via ``updates._CACHE_DIR`` — the check
reuses the SAME cache the updates checks own, so no test ever touches
the CWD's real ``.wpt-cache``.  Trees come from the shared FakeSource
(tests.fakes): the check consumes ``entries`` (walked) + ``source``
(content reads) exactly as the gathers produce them.

Two digest paths, both offline:

* ftp — the comparison goes through the bridge's bulk ``core_md5``
  action: every test wires a FakeBridge double into the SiteProbe
  (``probe.bridge`` — the seam the audit runner sets in ftp mode).  The
  double models the SERVER (it hashes its own files dict, absent paths
  land in ``missing``) or plays one scripted item per call (a payload,
  an Exception, or a callable) — mirroring wpt/wpbridge/client.py, an
  ``{"ok": false}`` envelope is RAISED as BridgeError carrying the
  payload.  ``_NoReadSource`` fails the test on any read_bytes /
  read_many call EXCEPT wp-includes/version.php — the locale
  resolver's ONE legitimate ftp-mode source read ([L17]; the digest
  surface still never takes a per-file read).
* local — no probe; the checksums come from a FRESH cache seed
  (WpOrgApi serves it without any network), so the real plain-session +
  ``http.timeout_s`` transport and the batched read_many md5 loop run
  end-to-end (the _BulkReadSource double provides the bulk primitive
  and records every call; the deadline tests script check() — the
  real wpt.deadline.Deadline is wall-clock, never sleep-tested).

Deterministic: no sleeps (cache-age tests use os.utime; the breaker
tests pin read attempt counts; the deadline tests script check()).

Test -> behavior map:
  test_clean_core_silent ................ ftp bulk happy path: matching
        server digests over a 3-path tree => []; the wp.org request
        shape pinned (live-verified URL + version + locale, UA wpt/,
        probe timeout, GET-only); ONE core_md5 call carrying the map's
        paths; no digest-surface read (the source fails the test on
        any read other than version.php)
  test_tampered_core_file_found .......... ftp: a server digest != the
        map => one exact finding (detail "tampered: <path>", walked
        size, risk high, restore fix naming the version + locale)
  test_added_php_files_flagged .......... ftp: wp-admin + top-level
        .php not in the map => both "added:" (kind then path);
        wp-config.php / .htaccess (user files) and a wp-content plugin
        NOT flagged — added detection is tree-only and identical in
        both modes
  test_added_scope_covers_unknown_top_level_php  the added scope is
        pinned as "not shipped by wp.org": an UNKNOWN top-level .php
        (the live request-gated shell shape) and a core-dir addition
        are both high-risk added, wp-content never is. A known-core-
        name allowlist would report nothing (those names are map
        members) and would drop a live-proven security signal
  test_missing_core_file_reported ....... ftp: bridge "missing" bucket
        => "missing:", risk medium, bytes 0, re-upload fix; the [L18]
        scope rule (a plugin-less hello.php and an absent TOP-LEVEL
        NON-php path stay silent; an absent TOP-LEVEL .php map path
        REPORTS)
  test_ftp_missing_scope_reads_version_php_once  the ftp soundness pins
        in one place: the version comes from info (no source read), the
        locale resolver's marker read is the ONLY per-file read and
        happens exactly once, version.php is sent to core_md5 once and
        classified from that answer (never counted twice), and the same
        tree reports exactly the one in-scope missing path
  test_missing_scope_never_names_the_user_config_files  a map listing
        wp-config.php/.htaccess (a contract violation of an external
        answer) yields no missing finding and no heal plan
  missing scope x the junk policy [L19 — the loop wp-config-sample.php
        opened: clean-files deletes it, the audit demanded it back,
        heal-core restored it, forever]:
  test_missing_scope_subtracts_junk_demanded_map_paths  ftp: a map path
        that is ALSO a webroot_junk pattern (wp-config-sample.php) is
        never demanded back, while a functional top-level php
        (wp-cron.php) and a core-dir junk member (which webroot's
        core_junk_exempt protects from deletion) still report; a
        profile that does NOT junk-match the sample file puts it back
        in scope (the subtraction is the profile's, not a filename)
  test_missing_scope_subtracts_junk_demanded_map_paths_local  the same
        answer from the LOCAL primitive — the two modes can never
        disagree about which missing core files the junk policy owns
  test_junk_demanded_subtraction_is_version_scoped  the subtraction is
        computed from the map THIS call passed (a version with no
        wp-config-sample.php is unaffected), an empty junk policy
        subtracts nothing, and the bridge primitive answers identically
  translation-pack skew [L19 — a localized build's map bundles its own
        wp-content/languages/ catalogs, which WordPress replaces from
        the wp.org translation pack]:
  test_translation_pack_skew_drops_runtime_catalogs  the four runtime
        formats are dropped with ONE info line; a planted non-catalog
        .php in the same directory and a real tampered core file still
        report
  test_resolve_translation_pack_skew_is_narrow  the pass directly: only
        the four formats under wp-content/languages/ (at any depth —
        core ships nested catalogs) and only when tampered
  test_ftp_unreadable_null_digest_skipped  a null digest (unreadable)
        and a no-bucket path => debug skips, no crash; the genuinely
        tampered path still reports
  test_ftp_unsendable_paths_dropped ..... map paths with "..", a
        leading "/", a NUL byte or empty are never SENT (the real
        bridge would refuse the whole request); the clean paths still
        compare
  test_ftp_core_md5_chunking ............ 5001 checksums paths => TWO
        core_md5 calls sized 5000 + 1 (the bridge's per-call cap)
  test_ftp_core_md5_failure_skips ....... a raised BridgeError, an
        {"ok": false} error envelope (the double raises it, mirroring
        client.py) and a malformed payload => [] + exactly ONE
        "core integrity skipped: core_md5 unavailable (...)" warning
  test_ftp_without_bridge_skips ......... a probe without .bridge / no
        probe at all in ftp mode (wiring gaps) => the same one-warning
        skip, never a per-file FTP fallback
  test_wp_version_unknown_silent ........ None / "" => [] with NO
        request and no bridge call + one debug
  test_fetch_failure_skips_silently ...... exception, HTTP 503, non-dict
        payload, missing "checksums", non-map "checksums", empty map,
        all-malformed entries => [] + exactly ONE check warning (the
        bridge is never reached)
  test_unreadable_file_skipped .......... LOCAL: a SourceError-raising
        source: the unreadable file contributes nothing (debug skip, no
        crash), the genuinely tampered file still reports
  test_local_breaker_aborts ............ LOCAL: 25 consecutive
        failed-map entries => ONE abort warning + the findings verified
        so far (the 27-path batch is ONE bulk read; everything after
        the trip is discarded — a later tampered file never reports)
  test_local_breaker_reset_on_success ... LOCAL: 24 failed-map entries
        then a good read => counter reset, scan continues to the last
        file (its tampering reports; no abort warning)
  test_local_read_many_batches ......... LOCAL happy path through the
        bulk primitive: 250 tree-present paths => 200+50 map-order
        read_many batches (sizes pinned); md5 tamper detection
        identical per batch; an absent map path classifies missing and
        is NEVER sent; deadline None (default) — the full scan, zero
        warnings
  test_local_breaker_spans_batches ...... LOCAL: a 25-failure run
        SPANNING a 200-path batch boundary trips at the 25th; the next
        batch never starts, post-trip results are discarded
  test_local_deadline_expires_mid_scan .. LOCAL: the budget expiring
        between batches NEVER raises — ONE warning + the findings
        verified so far; batch 2 never read
  test_local_deadline_spent_at_entry .... LOCAL: the REAL Deadline
        already spent at scan entry: the first check fires before any
        read — the honest early exit, additions only
  test_deterministic_grouped_ordering ... ftp mixed kinds: exact detail
        string ((kind, path) order, 5 lines + "(+1 more)"),
        count/bytes, composed high+missing fix
  test_second_call_within_ttl_no_network  the shared wp.org cache serves
        the second run without any network; core_md5 still runs per
        call (live server state, never cached)
  test_stale_cache_reused_on_fetch_failure  aged cache + network failure:
        the stale answer still serves; the TRANSPORT warns, the check
        does not
  test_transport_uses_probe_when_present .. ftp: (probe.session,
        probe.timeout_s)
  test_transport_local_plain_session ..... local: a plain requests.Session
        + the profile http.timeout_s
  test_local_mode_run_checks_end_to_end . local: clean tree => [] through
        run_checks; a tampered file => the grouped finding through the
        real registry pipeline
  test_registry_wiring ................... name/applies/func registered;
        "core" selector picks it in both modes
  test_primitives_classify_directly ...... the heal-core seam:
        affected_files_local + added_files take (source, files,
        checksums, the profile's webroot_junk) with NO AuditData and
        classify exactly what the data-shaped wrapper answers
        (delegation pinned by equality)
  test_bridge_primitive_classifies_directly  the same for
        affected_files_bridge (a fake bridge, no AuditData/probe);
        a None bridge degrades to None INSIDE the primitive
  locale resolution [L17 — observed: a localized migration healed version.php
        with en_US bytes and the site then failed
        `wp core verify-checksums --locale=fr_CA`]:
  test_resolve_core_locale_tiers ......... the resolver directly:
        readable fr_CA marker => fr_CA; readable markerless file =>
        en_US (wp-cli parity — a language-pack site never reads as a
        localized build); unreadable version.php + site locale => the
        site locale; no evidence at all => en_US; invalid marker /
        site locale characters are refused as evidence (never reach a
        URL)
  test_fr_ca_build_version_php_clean ..... the live false positive: a
        version.php carrying $wp_local_package='fr_CA' (md5 differs
        from en_US) + WPLANG=fr_CA reads CLEAN against the fr_CA map,
        with the locale=fr_CA request shape pinned
  test_en_us_build_with_language_pack_stays_en_us  WPLANG=fr_CA on an
        en_US BUILD compares against the en_US map (the fr_CA map
        would false-positive version.php and heal a mixed build)
  test_checksums_locale_fallback_warning . the fr_CA checksums fetch
        fails (503) or answers {"checksums": false} => ONE warning +
        the en_US map; the finding's fix text names the en_US basis
        AND the residual
  the locale tiers UNDER ATTACK (version.php is the file the
        compromise lives in, so its own marker is untrusted evidence —
        each case pins the documented degradation, never a guess):
  test_tampered_version_php_marker_removed_degrades_to_en_us  the
        marker DESTROYED: a readable markerless file IS the en_US build
        (wp-cli parity) => ONE en_US request, no fallback warning, and
        the file's own bytes reported tampered
  test_tampered_version_php_marker_without_a_build_degrades_once  the
        marker names a locale wp.org has no build for => the live
        {"checksums": false} answer, ONE warning, the en_US map
  test_tampered_version_php_foreign_marker_is_reported_not_guessed
        the marker names a locale that DOES have builds: the on-disk
        marker is the basis (wp-cli's own rule) and the file is
        reported tampered; the blast radius is bounded to that one file
        (live-verified across four versions x two locales)
  test_checksums_locale_fallback_both_fail_skips  both maps fail =>
        the existing "checksums unavailable" one-warning skip
  test_fr_ca_finding_fix_text_carries_locale  the fr_CA-basis finding's
        fix names the version + locale and the en_US-restore residual
  the locale fact reaching BOTH modes, and the audit trail a report
        needs (the observed localized "0 tampered / 2 added" report whose
        author concluded the wrong map had judged the core — the
        detail now names WHICH map did, so two contradictory reports
        can never sit side by side unreadable):
  test_local_fr_ca_basis_end_to_end  LOCAL, no probe: the fr_CA build's
        tree is CLEAN with the en_US map never requested (the sampleimg
        proof), the same tree with a tampered version.php reads
        tampered
  test_ftp_bridge_info_locale_drives_the_comparison  FTP, through the
        real gather_remote: the bridge info's get_locale() IS consumed
        (pre-heal shape, version.php unreadable, per-locale map
        digests) => the fr_CA map, and the basis clause says fr_CA
  test_unknown_site_locale_falls_back_to_en_us_and_says_so  no locale
        evidence at all (empty bridge locale) => the SILENT tier-3
        floor, the en_US map, and a detail naming en_US as the basis
  test_basis_clause_follows_the_fallback_and_keeps_the_residual  a
        known fr_CA build whose map failed: ONE warning, the basis
        clause names the en_US map that judged, the fix keeps the
        fr_CA residual
  test_added_known_finding_keeps_its_own_detail_shape  the low-risk
        added-known finding is a signature verdict: its detail is
        unchanged (the basis clause rides the checksum finding)
  default-theme version skew [L12 — live example.test: a pristine
        twentytwentyfive 1.5 auto-update behind the 1.4 bundled
        checksums read as 3 high-risk "tampered" files]:
  test_theme_skew_pristine_auto_update_reclassified  [] + one info
        line: the pristine official release of the declared version
        drops the tampered classification (seeded caches, offline)
  test_theme_skew_mixed_with_real_tampered_reports_only_real  a
        pristine theme update cannot silence core-dir tampering
  test_theme_skew_differs_from_own_release_stays_tampered  matches
        neither bundled nor own-release => stays high (never guesses
        benign)
  test_theme_skew_unknown_version_stays_tampered  no style.css =>
        one warning, classification survives
  test_theme_skew_zip_unavailable_stays_tampered  ftp: a scripted 404
        on downloads.wordpress.org/theme/... => warning + stays high;
        the theme-zip request shape pinned
  test_theme_skew_read_many_raise_stays_tampered  version known, zip
        available, the bulk read DIES (a channel death) => warning +
        classification survives
  test_resolve_theme_skew_source_none_and_non_theme_untouched  the
        post-pass primitive directly: identity without a source, no
        wp.org traffic for non-theme entries
  known added artifacts [L16 — live: Wordfence's wordfence-waf.php
        bootstrap flagged as high-risk "added" evidence]:
  test_known_added_wordfence_bootstrap_low_risk_finding  the REAL
        bootstrap (name+marker+size+clean) => the separate low-risk
        added-known finding, exact detail/fix
  test_known_added_malware_content_stays_high  right name + marker +
        a malware signature inside => stays high
  test_known_added_marker_absent_stays_high  an impostor name without
        the marker => stays high
  test_known_added_oversize_stays_high_without_read  over max_bytes:
        never read (_NoReadSource pins it), stays high
"""

import hashlib
import json
import logging
import os
import time
from dataclasses import replace

import pytest
import requests

import wpt.audit.integrity as integrity
import wpt.audit.updates as updates
from tests.fakes import FakeResponse, FakeSession, FakeSource
from wpt.audit.data import AuditData, gather_remote
from wpt.audit.integrity import check_core_integrity
from wpt.audit.registry import all_checks, run_checks, select_checks
from wpt.audit.security import SiteProbe
from wpt.deadline import Deadline
from wpt.settings import load
from wpt.types import (BridgeError, DeadlineExceeded, SourceError,
                       StopRequested)

#: The shipped profile — the check consumes only http.timeout_s.
DEFAULTS = load()

SITE = "https://example.com"      # never requested: api.wordpress.org only
TIMEOUT = 7                       # probe.timeout_s the request must carry

#: The fr_CA build's wp-includes/version.php (the live [L17] shape): the
#: localized build ships the $wp_local_package marker, so its md5
#: differs from the en_US build's markerless file — the ONE same-path
#: difference between the two checksums maps (live-verified for 6.6).
FR_CA_VERSION_PHP = b"<?php\n$wp_version = '7.1';\n$wp_local_package = 'fr_CA';\n"

#: Fix texts pinned verbatim (the check contract, not the implementation):
#: composed from (version, effective locale, resolved locale) — the
#: operator must know WHICH distribution the evidence names.
def restore_fix(version="7.1", locale="en_US", residual=""):
    return (
        f"Restore the file from a clean official WordPress "
        f"{version} {locale} release; a tampered core file means the "
        f"site is compromised." + residual
    )


def restore_added_fix(version="7.1", locale="en_US", residual=""):
    """[L17c/D2] the added-file fix carries the actionable triage text from
    security.WEB_SCRIPT_TRIAGE (an added top-level script is either an
    attacker's dropper or an operator's forgotten probe; both must go)."""
    from wpt.audit.security import WEB_SCRIPT_TRIAGE

    return restore_fix(version, locale, residual) + " " + WEB_SCRIPT_TRIAGE


def missing_fix(version="7.1", locale="en_US", residual=""):
    return (
        f"Re-upload the missing core file from a clean official "
        f"WordPress {version} {locale} release." + residual
    )


#: The [L17] residual clause appended to a locale-basis fix text: a
#: file restored from the en_US build (heal-core's zip-404 fallback)
#: still differs from the locale build and re-reports as tampered.
def locale_residual(locale="fr_CA"):
    return (
        f" (heal-core restores from the official {locale} build; when "
        f"that build is unavailable it restores from en_US, and such "
        f"a file still differs from the {locale} build and re-reports "
        f"here)"
    )


#: The [L17] residual clause when the COMPARISON ITSELF fell back to
#: en_US (the locale's map was unavailable).
def map_fallback_residual(locale="fr_CA"):
    return (
        f" (the wp.org {locale} checksums were unavailable — the "
        f"comparison used the official en_US checksums, and a file "
        f"restored from the en_US build can still differ from the "
        f"{locale} build)"
    )

#: The finding detail's LEADING BASIS CLAUSE — the comparison map that
#: judged this core, stated where the per-file evidence is (an incident
#: reads the detail, never the log; the en_US and fr_CA maps disagree on
#: wp-includes/version.php, so an excerpt that does not name its basis
#: cannot be read next to a contradictory one).  ``locale`` is the
#: EFFECTIVE locale — en_US after the one-warning fallback.
def basis(locale: str = "en_US", version: str = "7.1") -> str:
    return f"against the official {locale} {version} checksums"


def detail(*lines: str, locale: str = "en_US", version: str = "7.1") -> str:
    """The exact core-files detail: the basis clause + the evidence lines."""
    return basis(locale, version) + "\n" + "\n".join(lines)


#: A minimal WP-shaped webroot: one top-level core file, the version
#: marker, one shipped wp-content file.
CORE = {
    "wp-trackback.php": b"<?php // trackback\n",
    "wp-includes/version.php": b"<?php\n$wp_version = '7.1';\n",
    "wp-content/plugins/hello.php": b"<?php // hello\n",
}


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def wpt_records():
    """Capture every wpt.* log record (the wpt parent does not propagate;
    caplog never sees wpt.* records — see tests/audit/test_run.py)."""
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


@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    """Point the SHARED wp.org cache (owned by updates.py) at a tmp dir."""
    d = tmp_path / "cache"
    monkeypatch.setattr(updates, "_CACHE_DIR", d)
    return d


@pytest.fixture
def wporg_urls(monkeypatch):
    """Every wp.org URL the check requested, in order (LOCAL mode: the
    check builds its own plain session, so the request shape is pinned
    by recording the transport instead of a FakeSession)."""
    seen: list[str] = []
    real = updates.WpOrgApi._request_json

    def spy(self, method, url, form):
        seen.append(url)
        return real(self, method, url, form)

    monkeypatch.setattr(updates.WpOrgApi, "_request_json", spy)
    return seen


class FakeBridge:
    """core_md5 bridge double (the RecordingBridge pattern from
    tests/test_restore.py + the FakeSession scripting convention).

    Records every call. With no scripted items left it answers
    ``core_md5`` by hashing the SERVER files it was built with (absent
    paths land in ``missing`` — the live bridge hashes the real server
    files, never this test's client-side source).  Scripted items play
    one per call, in order: a payload dict, an Exception instance, or
    a callable ``(action, params) -> payload``.  Mirrors
    wpt/wpbridge/client.py exactly: an ``{"ok": false}`` envelope is
    RAISED as BridgeError carrying the whole payload in ``.payload``,
    so the check's failure path runs over the real client contract.
    """

    def __init__(self, files=None, script=()) -> None:
        self.files: dict[str, bytes] = dict(files or {})
        self.script = list(script)
        self.calls: list[tuple[str, dict]] = []

    def call(self, action, **params):
        self.calls.append((action, params))
        if self.script:
            item = self.script.pop(0)
            if callable(item):
                item = item(action, params)
            if isinstance(item, Exception):
                raise item
            if isinstance(item, dict) and not item.get("ok"):
                raise BridgeError(
                    f"bridge action failed: {item.get('error', 'unknown error')}",
                    payload=item,
                )
            return item
        if action != "core_md5":
            raise AssertionError(f"unexpected bridge action: {action!r}")
        digests: dict[str, str] = {}
        missing: list[str] = []
        for path in params["paths"]:
            blob = self.files.get(path)
            if blob is None:
                missing.append(path)  # nothing there — the live semantics
            else:
                digests[path] = hashlib.md5(blob).hexdigest()
        return {"ok": True, "files": digests, "missing": missing,
                "unreadable": []}


class _BulkReadSource(FakeSource):
    """FakeSource + the Source.read_many bulk-read contract: every
    requested path read through read_bytes, per-path (SourceError,
    OSError) failures collected into the failed map as str errors.
    Self-contained rather than delegating to WalkMixin.read_many so
    these tests pin the contract independently of the connector
    implementation; records every read_many call's path list
    (batch-size and order pinning)."""

    def __init__(self) -> None:
        super().__init__()
        self.read_many_calls: list[list[str]] = []
        self.read_bounds: list[int | None] = []

    def read_many(self, paths, *, max_bytes=None):
        self.read_many_calls.append(list(paths))
        self.read_bounds.append(max_bytes)
        ok: dict[str, bytes] = {}
        failed: dict[str, str] = {}
        for path in paths:
            try:
                ok[path] = self.read_bytes(path)
            except (SourceError, OSError) as exc:
                failed[path] = str(exc)
        return ok, failed


class _NoReadSource(FakeSource):
    """FakeSource whose read_bytes / read_many FAIL the test for every
    path EXCEPT wp-includes/version.php — the locale resolver's ONE
    legitimate ftp-mode source read ([L17]); the digest surface (the
    ~3780 map paths) still never takes a per-file read.  Every allowed
    read is RECORDED, so a test can pin the count (one) and not only
    the path."""

    def __init__(self) -> None:
        super().__init__()
        self.reads: list[str] = []

    def read_bytes(self, path):
        if path == "wp-includes/version.php":
            self.reads.append(path)
            return super().read_bytes(path)
        raise AssertionError(f"per-file read in ftp mode: {path}")

    def read_many(self, paths, *, max_bytes=None):
        if paths == ["wp-includes/version.php"]:
            self.reads.extend(paths)
            return super().read_many(paths)
        raise AssertionError(f"bulk read in ftp mode: {paths}")


class _UnreadableSource(_BulkReadSource):
    """A _BulkReadSource whose read_bytes raises SourceError on one path."""

    def __init__(self, fail_path: str) -> None:
        super().__init__()
        self.fail_path = fail_path

    def read_bytes(self, path):
        if path == self.fail_path:
            raise SourceError(f"unreadable: {path}")
        return super().read_bytes(path)


class _FailingReadsSource(_BulkReadSource):
    """_BulkReadSource raising SourceError on the given paths, counting
    every read attempt (the breaker's abort/reset pinning)."""

    def __init__(self, fail_paths) -> None:
        super().__init__()
        self.fail_paths = set(fail_paths)
        self.read_attempts = 0

    def read_bytes(self, path):
        self.read_attempts += 1
        if path in self.fail_paths:
            raise SourceError(f"unreadable: {path}")
        return super().read_bytes(path)


class _ExpiringDeadline:
    """Deadline double: check() passes N calls, then raises
    DeadlineExceeded — deterministic mid-scan expiry, no sleeps.  The
    real wpt.deadline.Deadline is wall-clock; this mirrors its exact
    interface, check(context) -> None | DeadlineExceeded."""

    def __init__(self, passes: int) -> None:
        self._passes = passes

    def check(self, context: str) -> None:
        if self._passes <= 0:
            raise DeadlineExceeded(
                f"run deadline of 0s exceeded at {context!r} — the run "
                "ends itself now"
            )
        self._passes -= 1


class _InfoBridge(FakeBridge):
    """FakeBridge that also answers the real ``info``/``db_audit`` ops.

    The two ops ``wpt.audit.data.gather_remote`` calls: the payload is
    whatever the test hands over, so the ftP-mode locale can only reach
    the check through the REAL gather (the bridge's ``locale`` field ->
    ``AuditData.locale`` -> ``resolve_core_locale``) — never through a
    hand-built AuditData that already carries the answer."""

    def __init__(self, files=None, info=None) -> None:
        super().__init__(files=files)
        self.info: dict = dict(info or {})

    def call(self, action, **params):
        if action in ("info", "db_audit"):
            self.calls.append((action, params))
            return {"ok": True, **self.info} if action == "info" else {"ok": True}
        return super().call(action, **params)


def probe(session, bridge=None):
    """A real SiteProbe over a scripted session; ``bridge`` = the
    FakeBridge for the ftp comparison path (never used for the wp.org
    fetch, which rides the session)."""
    return SiteProbe(session=session, site=SITE, timeout_s=TIMEOUT,
                     bridge=bridge)


def tree(files: dict[str, bytes]) -> tuple[_BulkReadSource, list]:
    """A preloaded bulk-capable FakeSource plus its walked entry list
    (the gather shape; _BulkReadSource carries read_many for the local
    comparison loop)."""
    source = _BulkReadSource()
    source.files.update(files)
    return source, list(source.walk())


def no_read_tree(files: dict[str, bytes]) -> tuple[_NoReadSource, list]:
    """tree() over _NoReadSource — the ftp-mode source double."""
    source = _NoReadSource()
    source.files.update(files)
    return source, list(source.walk())


def audit_data(entries, source, wp_version=None, probe_obj=None, mode="ftp",
               locale=None):
    """A hand-built AuditData with only the integrity-relevant fields set
    (``locale`` = the SITE locale fact: WPLANG locally, the bridge's
    get_locale() remotely)."""
    return AuditData(
        mode=mode,
        entries=entries,
        siteurl=None,
        home=None,
        template=None,
        blog_public=None,
        wp_version=wp_version,
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
        theme_versions={},
        locale=locale,
        probe=probe_obj,
        source=source,
    )


def md5(blob: bytes) -> str:
    return hashlib.md5(blob).hexdigest()


def checksums_response(checksums: dict[str, str]) -> FakeResponse:
    """A live-shaped core/checksums/1.0 payload."""
    return FakeResponse(text=json.dumps({"checksums": checksums}))


def core_checksums() -> dict[str, str]:
    """The matching checksums map for the CORE tree (a clean core)."""
    return {path: md5(blob) for path, blob in CORE.items()}


def seed_cache(cache_dir, version: str, checksums: dict[str, str],
               locale: str = "en_US"):
    """Write a FRESH cache entry for the checksums URL: WpOrgApi serves
    it without any network, so the real local-mode path (no probe, plain
    session) runs offline."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / (updates._cache_key(
        integrity._checksums_url(version, locale), None) + ".json")
    path.write_text(json.dumps({"checksums": checksums}), encoding="utf-8")
    return path


def check_warnings(wpt_records) -> list[str]:
    """The check's own WARNING messages (the transport's excluded)."""
    return [r.getMessage() for r in wpt_records
            if r.name == "wpt.audit.integrity" and r.levelno == logging.WARNING]


def check_debugs(wpt_records) -> list[str]:
    """The check's own DEBUG messages."""
    return [r.getMessage() for r in wpt_records
            if r.name == "wpt.audit.integrity" and r.levelno == logging.DEBUG]


# ----------------------------------------------------------------- clean


def test_clean_core_silent(cache_dir):
    source, entries = no_read_tree(CORE)
    session = FakeSession([checksums_response(core_checksums())])
    bridge = FakeBridge(files=CORE)
    d = audit_data(entries, source, wp_version="7.1",
                    probe_obj=probe(session, bridge))
    assert check_core_integrity(d, DEFAULTS) == []
    # the live-verified wp.org request shape: checksums URL (version +
    # locale), identifying UA, probe timeout, GET-only
    assert len(session.gets) == 1 and session.posts == []
    url, kw = session.gets[0]
    assert url == integrity._checksums_url("7.1")
    assert "core/checksums/1.0/?version=7.1&locale=en_US" in url
    assert kw["headers"]["User-Agent"].startswith("wpt/")
    assert kw["timeout"] == TIMEOUT
    # ONE bulk core_md5 call carrying the map's paths — no per-file
    # reads of the digest surface (the source fails the test on any
    # read other than the locale resolver's version.php)
    assert bridge.calls == [("core_md5", {"paths": list(core_checksums())})]


# -------------------------------------------------------------- tampered


def test_tampered_core_file_found(cache_dir):
    tampered = b"<?php // EVIL BACKDOOR\n"
    files = dict(CORE)
    files["wp-includes/version.php"] = tampered
    source, entries = no_read_tree(files)
    session = FakeSession([checksums_response(core_checksums())])
    bridge = FakeBridge(files=files)  # the SERVER holds the tampered file
    d = audit_data(entries, source, wp_version="7.1",
                    probe_obj=probe(session, bridge))
    findings = check_core_integrity(d, DEFAULTS)
    assert [
        (f.category, f.name, f.detail, f.bytes, f.count, f.risk, f.fix)
        for f in findings
    ] == [
        ("core.integrity", "core-files", detail("tampered: wp-includes/version.php"),
         len(tampered), 1, "high", restore_fix()),
    ]
    findings[0].validate()


# ----------------------------------------------------------------- added


def test_added_php_files_flagged(cache_dir):
    files = dict(CORE)
    files.update({
        "wp-admin/evil.php": b"<?php /* evil */",
        "rogue.php": b"<?php /* rogue */",
        "wp-config.php": b"<?php // user config",
        ".htaccess": b"RewriteEngine On\n",
        "wp-content/plugins/custom/custom.php": b"<?php /* user plugin */",
    })
    source, entries = no_read_tree(files)
    session = FakeSession([checksums_response(core_checksums())])
    bridge = FakeBridge(files=files)
    d = audit_data(entries, source, wp_version="7.1",
                   probe_obj=probe(session, bridge))
    findings = check_core_integrity(d, DEFAULTS)
    assert len(findings) == 1
    f = findings[0]
    f.validate()
    # wp-config.php / .htaccess (user files) and the wp-content plugin
    # are NOT flagged — count 2 proves it
    assert (f.count, f.risk) == (2, "high")
    assert f.detail == detail("added: rogue.php", "added: wp-admin/evil.php")
    assert f.bytes == (len(files["rogue.php"]) + len(files["wp-admin/evil.php"]))
    assert f.fix == restore_added_fix()


#: The live added files (example.com: duhome-x1y2.php /
#: size-t7u8.php — reported HIGH to the operator) carry a request gate:
#: they only answer a caller who supplies the right parameter, so they
#: are web EXPOSED but invisible in every page.
REQUEST_GATED_SHELL = (
    b"<?php\nif (empty($_GET['k']) || $_GET['k'] !== 's3cr3t') { exit; }\n"
    b"echo 'ok';\n"
)


def test_added_scope_covers_unknown_top_level_php(cache_dir):
    """The added scope is pinned, deliberately: a TOP-LEVEL ``.php`` that
    wp.org does not ship is ``added`` HIGH whatever its name and
    whatever its content — including a request-gated web shell, the live
    shape of the two files reported to the operator on
    example.com.  The scope is "NOT SHIPPED BY wp.org", a
    fact only the checksum map can answer; a risk classification over
    the same file (whether it is web-exposed, how it is gated) belongs
    to the content scanners, and the known plugin bootstrap is carved
    out above by signature.  Narrowing this scope to a KNOWN core-name
    allowlist is therefore a security regression, not a de-duplication:
    the canonical core names ARE map members, so an allowlist would
    report nothing at all, and heal-core/prune-core scope their plans
    on these same primitives."""
    files = dict(CORE)
    files.update({
        "size-t7u8.php": REQUEST_GATED_SHELL,
        "wp-includes/blocks/evil.php": b"<?php /* core-dir addition */",
        "wp-admin/evil.php": b"<?php /* core-dir addition */",
        "wp-content/plugins/custom/custom.php": REQUEST_GATED_SHELL,
    })
    source, entries = no_read_tree(files)
    session = FakeSession([checksums_response(core_checksums())])
    bridge = FakeBridge(files=files)
    d = audit_data(entries, source, wp_version="7.1",
                   probe_obj=probe(session, bridge))
    findings = check_core_integrity(d, DEFAULTS)
    assert [f.name for f in findings] == ["core-files"]
    assert findings[0].detail == detail(
        "added: size-t7u8.php",
        "added: wp-admin/evil.php",
        "added: wp-includes/blocks/evil.php",
    )
    assert findings[0].risk == "high"
    # wp-content is never scanned for additions (plugins are user code):
    # the request-gated plugin file is absent from the count
    assert findings[0].count == 3


# --------------------------------------------------------------- missing


def test_missing_core_file_reported(cache_dir):
    # a plugin-less site: hello.php absent though wp.org ships it.
    # [L18] the scope rule: an absent TOP-LEVEL .php map path REPORTS
    # (wp-cron.php — an observed localized migration had five such files
    # deleted and the old scope reported nothing); an absent TOP-LEVEL
    # NON-php map path stays silent (license.txt — the junk policy).
    server = {path: blob for path, blob in CORE.items()
              if path != "wp-content/plugins/hello.php"}
    source, entries = no_read_tree(server)
    checksums = core_checksums()           # still lists hello.php
    checksums["wp-includes/js/bar.js"] = "0" * 32   # absent -> missing
    checksums["wp-cron.php"] = "1" * 32    # absent, TOP-LEVEL php -> missing
    checksums["license.txt"] = "2" * 32    # absent, TOP LEVEL non-php -> silent
    session = FakeSession([checksums_response(checksums)])
    bridge = FakeBridge(files=server)  # hello/bar/cron -> missing
    d = audit_data(entries, source, wp_version="7.1",
                    probe_obj=probe(session, bridge))
    findings = check_core_integrity(d, DEFAULTS)
    assert [
        (f.category, f.name, f.detail, f.bytes, f.count, f.risk, f.fix)
        for f in findings
    ] == [
        ("core.integrity", "core-files",
         detail("missing: wp-cron.php", "missing: wp-includes/js/bar.js"),
         0, 2, "medium", missing_fix()),
    ]
    findings[0].validate()


def _junk_scope_checksums() -> dict[str, str]:
    """A map with the four scope cases side by side, all ABSENT from CORE."""
    return {
        "wp-trackback.php": md5(CORE["wp-trackback.php"]),  # present, clean
        "wp-includes/version.php": md5(CORE["wp-includes/version.php"]),
        "wp-content/plugins/hello.php": md5(CORE["wp-content/plugins/hello.php"]),
        "wp-config-sample.php": "3" * 32,    # junk-deleted  -> never missing
        "wp-cron.php": "1" * 32,             # top-level php  -> missing
        "readme.html": "4" * 32,             # top-level NON-php -> out of scope
        "license.txt": "5" * 32,             # top-level NON-php -> out of scope
        "wp-admin/ID3/license.txt": "6" * 32,  # core-dir junk member -> missing
    }


def test_ftp_missing_scope_reads_version_php_once(cache_dir):
    """The ftp-mode soundness pins in one place: the version comes from
    the bridge's info (never a source read), the locale resolver's
    marker read is the ONLY per-file read the comparison path takes and
    it happens exactly ONCE (the digest surface is the bridge's bulk
    core_md5 — the file is sent there, and classified from THAT answer,
    so it is never counted twice in the finding), and the scope rule
    itself is mode- and locale-blind: the same tree missing
    wp-cron.php, wp-config-sample.php and readme.html reports exactly
    one path."""
    files = dict(CORE)
    source, entries = no_read_tree(files)
    checksums = _junk_scope_checksums()
    session = FakeSession([checksums_response(checksums)])
    bridge = FakeBridge(files=files)
    d = audit_data(entries, source, wp_version="7.1",
                   probe_obj=probe(session, bridge))
    findings = check_core_integrity(d, DEFAULTS)
    assert [f.detail for f in findings] == [
        detail("missing: wp-admin/ID3/license.txt", "missing: wp-cron.php")
    ]
    assert findings[0].count == 2  # version.php appears once, as clean
    assert source.reads == ["wp-includes/version.php"]
    # one bulk digest call; every map path sent exactly once
    assert [c[0] for c in bridge.calls] == ["core_md5"]
    sent = bridge.calls[0][1]["paths"]
    assert sent == list(checksums)
    assert len(sent) == len(set(sent))


def test_missing_scope_never_names_the_user_config_files(cache_dir):
    """The scope's last exclusion: wp.org never ships wp-config.php or
    .htaccess (they are user files by design, the reason the added rule
    exempts them), so a map that lists one — a contract violation of an
    EXTERNAL answer — must not turn into "missing: wp-config.php" or a
    heal plan for a file the write guard refuses.  wp-config-sample.php
    (the shipped sample) is a different file and stays exempt only
    through the junk policy."""
    checksums = _junk_scope_checksums()
    checksums["wp-config.php"] = "7" * 32
    checksums[".htaccess"] = "8" * 32
    source, entries = no_read_tree(CORE)
    session = FakeSession([checksums_response(checksums)])
    bridge = FakeBridge(files=CORE)
    d = audit_data(entries, source, wp_version="7.1",
                   probe_obj=probe(session, bridge))
    findings = check_core_integrity(d, DEFAULTS)
    assert [f.detail for f in findings] == [
        detail("missing: wp-admin/ID3/license.txt", "missing: wp-cron.php")
    ]


# ------------------------------------------- missing scope x junk [L19]
#
# The loop [L18] opened one file further down the scope: with
# wp-config-sample.php in the missing scope, clean-files DELETED it (it
# is one of the profile's own webroot_junk patterns), core.integrity
# demanded it back as "missing", heal-core restored it, and the next
# clean-files run deleted it again — forever, with a finding that never
# resolves.  The scope subtracts the map paths the junk policy deletes,
# computed from the PROFILE's patterns through webroot's own predicate.


def test_missing_scope_subtracts_junk_demanded_map_paths(cache_dir):
    # ftp: wp-config-sample.php IS a checksums map path AND a
    # webroot_junk pattern the tool deletes, so it must never be
    # demanded back; wp-cron.php (functional, not junk) and the
    # core-dir license.txt (junk-matching, but webroot EXEMPTS core-dir
    # members from deletion) still report.
    checksums = _junk_scope_checksums()
    source, entries = no_read_tree(CORE)
    session = FakeSession([checksums_response(checksums)])
    bridge = FakeBridge(files=CORE)
    d = audit_data(entries, source, wp_version="7.1",
                   probe_obj=probe(session, bridge))
    findings = check_core_integrity(d, DEFAULTS)
    assert [f.detail for f in findings] == [
        detail("missing: wp-admin/ID3/license.txt", "missing: wp-cron.php")
    ]
    assert findings[0].risk == "medium" and findings[0].count == 2

    # the subtraction is the PROFILE's, not a hardcoded filename: a
    # profile that does NOT junk-match the sample file puts it back in
    # scope (a hardcoded exemption would silently ignore the operator's
    # own policy).
    keep_sample = replace(DEFAULTS, webroot_junk=["*.sql"])
    session2 = FakeSession([checksums_response(checksums)])
    d2 = audit_data(entries, source, wp_version="7.1",
                    probe_obj=probe(session2, bridge))
    assert [f.detail for f in check_core_integrity(d2, keep_sample)] == [
        detail("missing: wp-admin/ID3/license.txt",
               "missing: wp-config-sample.php", "missing: wp-cron.php")
    ]


def test_missing_scope_subtracts_junk_demanded_map_paths_local(cache_dir):
    # the SAME answer from the LOCAL primitive: the two modes must never
    # disagree about which missing core files the junk policy owns.
    source, entries = tree(CORE)
    seed_cache(cache_dir, "7.1", _junk_scope_checksums())
    d = audit_data(entries, source, wp_version="7.1", mode="local")
    assert [f.detail for f in check_core_integrity(d, DEFAULTS)] == [
        detail("missing: wp-admin/ID3/license.txt", "missing: wp-cron.php")
    ]


def test_R18_local_integrity_read_many_carries_the_expected_size_bound():
    """R18-P2: the per-batch digest read is bounded by the LARGEST expected
    size, so a listing that understates a body is a known unreadable skip
    instead of an unbounded materialization."""
    source, _entries = tree({"wp-cron.php": b"x" * 40,
                             "wp-load.php": b"y" * 90})
    files = {entry.path: entry for entry in source.walk()}
    checksums = {path: md5(source.files[path]) for path in files}
    affected = integrity.affected_files_local(
        source, files, checksums, junk_patterns=DEFAULTS.webroot_junk)
    assert affected == []
    assert source.read_bounds == [90]


def test_junk_demanded_subtraction_is_version_scoped():
    # The subtraction is computed from the map THIS call passed, so a
    # version whose map has no wp-config-sample.php is unaffected (nothing
    # to subtract, every functional top-level php still reports) — no
    # cross-version or cross-run state.
    walked = {}
    source = _BulkReadSource()
    without_sample = {"wp-cron.php": "1" * 32, "wp-mail.php": "2" * 32}
    assert integrity.affected_files_local(
        source, walked, without_sample, junk_patterns=DEFAULTS.webroot_junk
    ) == [("missing", "wp-cron.php", 0), ("missing", "wp-mail.php", 0)]
    with_sample = dict(without_sample, **{"wp-config-sample.php": "3" * 32})
    assert integrity.affected_files_local(
        source, walked, with_sample, junk_patterns=DEFAULTS.webroot_junk
    ) == [("missing", "wp-cron.php", 0), ("missing", "wp-mail.php", 0)]
    # an empty junk policy subtracts nothing at all
    assert integrity.affected_files_local(
        source, walked, with_sample, junk_patterns=[]
    ) == [("missing", "wp-cron.php", 0), ("missing", "wp-mail.php", 0),
          ("missing", "wp-config-sample.php", 0)]
    # the bridge primitive answers identically
    class _AbsentBridge:
        def call(self, action, **params):
            return {"ok": True, "files": {},
                    "missing": list(params["paths"]), "unreadable": []}
    assert integrity.affected_files_bridge(
        _AbsentBridge(), walked, with_sample,
        junk_patterns=DEFAULTS.webroot_junk,
    ) == [("missing", "wp-cron.php", 0), ("missing", "wp-mail.php", 0)]


# ------------------------------------------------------ ftp bucket edges


def test_ftp_unreadable_null_digest_skipped(cache_dir, wpt_records):
    # null digest = unreadable; hello.php lands in NO bucket (the
    # contract-drift shape) — both are debug skips, never findings; the
    # genuinely tampered path still reports
    source, entries = no_read_tree(CORE)
    session = FakeSession([checksums_response(core_checksums())])
    payload = {
        "ok": True,
        "files": {
            "wp-trackback.php": md5(b"<?php // EVIL\n"),   # tampered
            "wp-includes/version.php": None,               # unreadable
            # hello.php deliberately in no bucket
        },
        "missing": [],
        "unreadable": ["wp-includes/version.php"],
    }
    bridge = FakeBridge(script=[payload])
    d = audit_data(entries, source, wp_version="7.1",
                   probe_obj=probe(session, bridge))
    findings = check_core_integrity(d, DEFAULTS)
    assert [(f.detail, f.count, f.risk) for f in findings] == [
        (detail("tampered: wp-trackback.php"), 1, "high"),
    ]
    debugs = check_debugs(wpt_records)
    assert any("wp-includes/version.php" in m for m in debugs)
    assert any("wp-content/plugins/hello.php" in m for m in debugs)


def test_ftp_unsendable_paths_dropped(cache_dir, wpt_records):
    # defense-in-depth: a map key with "..", a leading "/", a NUL byte
    # or empty would make the REAL bridge refuse the whole request
    # (media_delete's fail-closed precedent) — it is never sent; the
    # clean paths still compare
    checksums = {
        "../escape.php": "a" * 32,
        "/absolute.php": "b" * 32,
        "bad\x00.php": "c" * 32,
        "": "d" * 32,
        "wp-trackback.php": md5(CORE["wp-trackback.php"]),
        "wp-includes/version.php": md5(CORE["wp-includes/version.php"]),
    }
    source, entries = no_read_tree(CORE)
    session = FakeSession([checksums_response(checksums)])
    bridge = FakeBridge(files=CORE)
    d = audit_data(entries, source, wp_version="7.1",
                   probe_obj=probe(session, bridge))
    assert check_core_integrity(d, DEFAULTS) == []
    sent = [p for _action, params in bridge.calls for p in params["paths"]]
    assert sent == ["wp-trackback.php", "wp-includes/version.php"]
    assert any("dropped" in m for m in check_debugs(wpt_records))


def test_ftp_core_md5_chunking(cache_dir):
    # 5001 checksums paths: the bridge's per-call cap is 5000, so the
    # comparison must split into TWO bulk calls (5000 + 1)
    files = {f"wp-includes/f{i:04d}.php": b"core" for i in range(5001)}
    checksums = {path: md5(blob) for path, blob in files.items()}
    source, entries = no_read_tree(files)
    session = FakeSession([checksums_response(checksums)])
    bridge = FakeBridge(files=files)
    d = audit_data(entries, source, wp_version="7.1",
                   probe_obj=probe(session, bridge))
    assert check_core_integrity(d, DEFAULTS) == []
    assert [len(params["paths"]) for _action, params in bridge.calls] == [5000, 1]
    sent = [p for _action, params in bridge.calls for p in params["paths"]]
    assert sent == list(checksums)


# ------------------------------------------------- ftp failure degrades


@pytest.mark.parametrize("script_item, reason", [
    pytest.param(BridgeError("bridge request failed after redeploy: ConnectionError"),
                 "bridge request failed after redeploy: ConnectionError",
                 id="raised-bridge-error"),
    pytest.param({"ok": False, "error": "refused path (traversal): ../no-such-file",
                  "type": "InvalidArgumentException", "line": 905},
                 "bridge action failed: refused path (traversal): ../no-such-file",
                 id="error-envelope"),
    pytest.param({"ok": True, "files": "not-a-map", "missing": [], "unreadable": []},
                 "malformed core_md5 payload",
                 id="malformed-payload"),
])
def test_ftp_core_md5_failure_skips(cache_dir, wpt_records, script_item, reason):
    source, entries = no_read_tree(CORE)
    session = FakeSession([checksums_response(core_checksums())])
    bridge = FakeBridge(script=[script_item])
    d = audit_data(entries, source, wp_version="7.1",
                   probe_obj=probe(session, bridge))
    assert check_core_integrity(d, DEFAULTS) == []
    # exactly ONE check warning, whatever the failure shape; the checksums
    # fetch DID succeed — the skip is purely core_md5's
    assert check_warnings(wpt_records) == [
        f"core integrity skipped: core_md5 unavailable ({reason})",
    ]
    assert len(session.gets) == 1


@pytest.mark.parametrize("with_probe", [True, False],
                         ids=["probe-no-bridge", "no-probe"])
def test_ftp_without_bridge_skips(cache_dir, wpt_records, with_probe):
    # a probe without .bridge (or no probe at all) in ftp mode cannot
    # bulk-hash: fail closed with the one-warning skip — never a silent
    # per-file FTP fallback
    seed_cache(cache_dir, "7.1", core_checksums())
    source, entries = tree(CORE)
    session = FakeSession([checksums_response(core_checksums())])
    d = audit_data(entries, source, wp_version="7.1",
                   probe_obj=probe(session) if with_probe else None)
    assert check_core_integrity(d, DEFAULTS) == []
    assert check_warnings(wpt_records) == [
        "core integrity skipped: core_md5 unavailable (probe carries no bridge)",
    ]


# ------------------------------------------------------- unknown version


@pytest.mark.parametrize("wp_version", [None, ""])
def test_wp_version_unknown_silent(cache_dir, wpt_records, wp_version):
    session = FakeSession()
    source, entries = tree(CORE)
    d = audit_data(entries, source, wp_version=wp_version,
                   probe_obj=probe(session))
    assert check_core_integrity(d, DEFAULTS) == []
    assert session.gets == [] and session.posts == []  # never a request
    debugs = [r for r in wpt_records
              if r.name == "wpt.audit.integrity" and r.levelno == logging.DEBUG]
    assert len(debugs) == 1
    assert "unknown" in debugs[0].getMessage()


# -------------------------------------------------------- failed fetches


@pytest.mark.parametrize("script_item", [
    pytest.param(requests.ConnectionError("boom"), id="network-exception"),
    pytest.param(FakeResponse(503, "unavailable"), id="http-503"),
    pytest.param(FakeResponse(text=json.dumps(["not", "a", "dict"])),
                  id="non-dict-payload"),
    pytest.param(FakeResponse(text="{}"), id="no-checksums-key"),
    pytest.param(FakeResponse(text=json.dumps({"checksums": []})),
                  id="checksums-not-a-map"),
    pytest.param(FakeResponse(text=json.dumps({"checksums": {}})),
                  id="empty-map"),
    pytest.param(FakeResponse(text=json.dumps({"checksums": {"p": 42}})),
                  id="all-entries-malformed"),
])
def test_fetch_failure_skips_silently(cache_dir, wpt_records, script_item):
    session = FakeSession([script_item])
    source, entries = tree(CORE)
    d = audit_data(entries, source, wp_version="7.1", probe_obj=probe(session))
    assert check_core_integrity(d, DEFAULTS) == []
    # exactly ONE check warning, whatever the failure shape (the
    # transport logs its own on network failures — filtered here)
    assert check_warnings(wpt_records) == [
        "core integrity skipped: checksums unavailable",
    ]


# ------------------------------------------------- local: unreadable file


def test_unreadable_file_skipped(cache_dir, wpt_records):
    # LOCAL mode: read_bytes raises SourceError on one path — the
    # unreadable file contributes nothing (debug skip, no crash), the
    # genuinely tampered file still reports
    files = dict(CORE)
    files["wp-includes/version.php"] = b"<?php // tampered but unreadable"
    files["wp-trackback.php"] = b"<?php // actually tampered"
    source = _UnreadableSource("wp-includes/version.php")
    source.files.update(files)
    entries = list(source.walk())
    seed_cache(cache_dir, "7.1", core_checksums())
    d = audit_data(entries, source, wp_version="7.1", mode="local")
    findings = check_core_integrity(d, DEFAULTS)
    # unreadable is not proof of tampering: only the readable one reports
    assert [(f.detail, f.count, f.risk) for f in findings] == [
        (detail("tampered: wp-trackback.php"), 1, "high"),
    ]
    assert any("wp-includes/version.php" in m for m in check_debugs(wpt_records))


# --------------------------------------------- local: the circuit breaker


def test_local_breaker_aborts(cache_dir, wpt_records):
    # first file readable and TAMPERED (verified), then 25 unreadable:
    # the scan aborts ON the 25th consecutive failed-map entry with ONE
    # warning and returns the partial verified findings.  All 27
    # tree-present paths fit ONE read_many batch, so the bulk read
    # fetches the whole batch — but everything after the trip point is
    # discarded and no further batch starts: the also-tampered tail
    # file never classifies, and its absence from the findings proves
    # the abort
    first = "wp-includes/first.php"
    bad = [f"wp-includes/bad{i:02d}.php" for i in range(25)]
    tail = "wp-includes/tail.php"
    files = {first: b"tampered content",
             **{p: b"x" for p in bad},
             tail: b"also tampered"}
    checksums = {first: md5(b"wp.org says otherwise"),
                 **{p: md5(b"x") for p in bad},
                 tail: md5(b"wp.org says otherwise")}
    source = _FailingReadsSource(bad)
    source.files.update(files)
    entries = list(source.walk())
    seed_cache(cache_dir, "7.1", checksums)
    d = audit_data(entries, source, wp_version="7.1", mode="local")
    findings = check_core_integrity(d, DEFAULTS)
    assert [(f.detail, f.count, f.risk) for f in findings] == [
        (detail("tampered: wp-includes/first.php"), 1, "high"),
    ]
    assert [len(c) for c in source.read_many_calls] == [27]  # ONE batch
    # 27 bulk-read paths + the locale resolver's version.php probe [L17]
    assert source.read_attempts == 28
    assert check_warnings(wpt_records) == [
        "core integrity scan aborted after 25 consecutive unreadable "
        "files; results are partial",
    ]


def test_local_breaker_reset_on_success(cache_dir, wpt_records):
    # 30 map paths, only the FIRST 24 unreadable: the 25th read
    # succeeds and resets the counter, so the scan continues to the
    # last file — whose tampering reports and proves it — with NO
    # abort warning
    paths = [f"wp-includes/f{i:02d}.php" for i in range(30)]
    files = {p: b"clean" for p in paths}
    files[paths[-1]] = b"tampered"                     # the 30th file
    checksums = {p: md5(b"clean") for p in paths}
    source = _FailingReadsSource(paths[:24])
    source.files.update(files)
    entries = list(source.walk())
    seed_cache(cache_dir, "7.1", checksums)
    d = audit_data(entries, source, wp_version="7.1", mode="local")
    findings = check_core_integrity(d, DEFAULTS)
    assert [(f.detail, f.count, f.risk) for f in findings] == [
        (detail(f"tampered: {paths[-1]}"), 1, "high"),
    ]
    # 30 map paths + the resolver's version.php probe [L17]
    assert source.read_attempts == 31
    assert check_warnings(wpt_records) == []


# ------------------------------------------------- local: read_many batching


def test_local_read_many_batches(cache_dir, wpt_records):
    # the LOCAL happy path through the bulk primitive: 250 tree-present
    # map paths stream through read_many in 200 + 50 map-order batches
    # (sizes pinned); md5 tamper detection is IDENTICAL through the
    # batch path (one tampered file per batch); the absent map path
    # classifies missing and is NEVER sent to read_many.  deadline
    # stays None (the AuditData default): the unbounded scan is
    # unchanged — every path classified, no warning of any kind
    files = {f"wp-includes/f{i:04d}.php": b"clean" for i in range(250)}
    files["wp-includes/f0000.php"] = b"tampered"        # batch 1
    files["wp-includes/f0249.php"] = b"also tampered"   # batch 2
    files["wp-admin/rogue.php"] = b"<?php /* added */"  # tree-only addition
    checksums = {f"wp-includes/f{i:04d}.php": md5(b"clean") for i in range(250)}
    checksums["wp-includes/gone.js"] = "0" * 32         # absent -> missing
    source = _BulkReadSource()
    source.files.update(files)
    entries = list(source.walk())
    seed_cache(cache_dir, "7.1", checksums)
    d = audit_data(entries, source, wp_version="7.1", mode="local")
    assert d.deadline is None
    findings = check_core_integrity(d, DEFAULTS)
    assert [
        (f.category, f.name, f.detail, f.bytes, f.count, f.risk, f.fix)
        for f in findings
    ] == [
        ("core.integrity", "core-files",
         detail("tampered: wp-includes/f0000.php",
                "tampered: wp-includes/f0249.php",
                "added: wp-admin/rogue.php",
                "missing: wp-includes/gone.js"),
         len(b"tampered") + len(b"also tampered") + len(b"<?php /* added */"),
         4, "high", f"{restore_added_fix()} {missing_fix()}"),
    ]
    findings[0].validate()
    # the batching contract: map-order batches of at most 200 paths,
    # the absent path never among them
    assert source.read_many_calls == [
        [f"wp-includes/f{i:04d}.php" for i in range(0, 200)],
        [f"wp-includes/f{i:04d}.php" for i in range(200, 250)],
    ]
    assert check_warnings(wpt_records) == []


def test_local_breaker_spans_batches(cache_dir, wpt_records):
    # the breaker survives batching: a consecutive-failure run SPANNING
    # the 200-path batch boundary (5 at batch 1's tail + 20 at batch
    # 2's head) still trips at exactly the 25th entry — batch 3 never
    # starts, and everything after the trip point is discarded (only
    # the tampered file verified BEFORE the run reports)
    files = {f"wp-includes/f{i:04d}.php": b"clean" for i in range(401)}
    files["wp-includes/f0000.php"] = b"tampered"
    fail = [f"wp-includes/f{i:04d}.php" for i in range(195, 220)]  # 25
    checksums = {f"wp-includes/f{i:04d}.php": md5(b"clean") for i in range(401)}
    source = _FailingReadsSource(fail)
    source.files.update(files)
    entries = list(source.walk())
    seed_cache(cache_dir, "7.1", checksums)
    d = audit_data(entries, source, wp_version="7.1", mode="local")
    findings = check_core_integrity(d, DEFAULTS)
    assert [(f.detail, f.count, f.risk) for f in findings] == [
        (detail("tampered: wp-includes/f0000.php"), 1, "high"),
    ]
    # batches 1 + 2 were read in full (a bulk read cannot stop mid-call);
    # batch 3 never started after the mid-batch-2 trip
    assert [len(c) for c in source.read_many_calls] == [200, 200]
    # both batches in full + the resolver's version.php probe [L17]
    assert source.read_attempts == 401
    assert check_warnings(wpt_records) == [
        "core integrity scan aborted after 25 consecutive unreadable "
        "files; results are partial",
    ]


def test_R11_an_expired_budget_never_issues_a_wporg_request(cache_dir):
    """R11-P1-1: the checksums and theme-skew transports did not receive the
    run Deadline, so an expired budget still started (and waited on) a
    wp.org request.  Both seams must refuse BEFORE any request."""
    session = FakeSession([])
    with pytest.raises(DeadlineExceeded):
        integrity._fetch_checksums(
            "9.9.9", session, TIMEOUT, "en_US", Deadline(-1))
    assert session.gets == [] and session.posts == []

    with pytest.raises(DeadlineExceeded):
        integrity._fetch_comparison_checksums(
            "9.9.9", session, TIMEOUT, "fr_CA", Deadline(-1))
    assert session.gets == [] and session.posts == []

    source = FakeSource()
    source.files["wp-content/themes/tw/style.css"] = (
        b"/*\nTheme Name: T\nVersion: 1.2\n*/")
    affected = [("tampered", "wp-content/themes/tw/style.css", 10)]
    with pytest.raises(DeadlineExceeded):
        integrity.resolve_theme_skew(
            affected, source, session, TIMEOUT, Deadline(-1))
    assert session.gets == [] and session.posts == []


def test_local_deadline_expires_mid_scan(cache_dir, wpt_records):
    # the budget expiring BETWEEN batches: DeadlineExceeded NEVER
    # escapes the check — ONE warning + the findings verified so far
    # (batch 1's tampered file plus the tree-only addition); batch 2 is
    # never read, so its tampered file never reports
    files = {f"wp-includes/f{i:04d}.php": b"clean" for i in range(250)}
    files["wp-includes/f0000.php"] = b"tampered"          # batch 1: verified
    files["wp-includes/f0249.php"] = b"never reached"      # batch 2: never
    files["wp-admin/rogue.php"] = b"<?php /* added */"
    checksums = {f"wp-includes/f{i:04d}.php": md5(b"clean") for i in range(250)}
    source = _BulkReadSource()
    source.files.update(files)
    entries = list(source.walk())
    seed_cache(cache_dir, "7.1", checksums)
    d = audit_data(entries, source, wp_version="7.1", mode="local")
    d.deadline = _ExpiringDeadline(passes=1)  # batch 1 runs; batch 2 raises
    findings = check_core_integrity(d, DEFAULTS)
    assert [(f.detail, f.count, f.risk, f.fix) for f in findings] == [
        (detail("tampered: wp-includes/f0000.php",
                "added: wp-admin/rogue.php"),
         2, "high", restore_added_fix()),
    ]
    assert [len(c) for c in source.read_many_calls] == [200]  # batch 2 unread
    assert check_warnings(wpt_records) == [
        "core integrity scan stopped: run deadline exceeded; "
        "results are partial",
    ]


def test_local_deadline_spent_at_entry(cache_dir, wpt_records):
    # the REAL Deadline class, its budget already spent at scan entry
    # (negative seconds: expired at construction — no clock-resolution
    # bet): the first batch's check raises BEFORE any bulk read, the
    # honest early exit — ONE warning and only the tree-only additions
    files = dict(CORE)
    files["wp-admin/rogue.php"] = b"<?php /* added */"
    source = _BulkReadSource()
    source.files.update(files)
    entries = list(source.walk())
    seed_cache(cache_dir, "7.1", core_checksums())
    d = audit_data(entries, source, wp_version="7.1", mode="local")
    # The checksums fetch itself is deadline-bound now (R11-P1-1), so a
    # REAL expired budget would raise before the map is even read.  This
    # case is about the scan loop: a double with no absolute instant and
    # zero passes expires at the first batch check.
    d.deadline = _ExpiringDeadline(passes=0)
    findings = check_core_integrity(d, DEFAULTS)
    assert [(f.detail, f.count, f.risk) for f in findings] == [
        (detail("added: wp-admin/rogue.php"), 1, "high"),
    ]
    assert source.read_many_calls == []  # the bulk read never happened
    assert check_warnings(wpt_records) == [
        "core integrity scan stopped: run deadline exceeded; "
        "results are partial",
    ]


# ------------------------------------------------------- grouped finding


def test_deterministic_grouped_ordering(cache_dir):
    files = {
        "wp-includes/a.php": b"AAA",            # digest differs -> tampered
        "wp-admin/z.php": b"ZZZ",               # digest differs -> tampered
        "wp-admin/x.php": b"XXX",               # not in the map -> added
        "rogue.php": b"RRR",                    # top level, not in map -> added
        "wp-includes/present.php": b"PPP",      # matches -> silent
    }
    checksums = {
        "wp-includes/a.php": md5(b"NOT-A"),
        "wp-admin/z.php": md5(b"NOT-Z"),
        "wp-includes/present.php": md5(b"PPP"),
        "wp-includes/bar.js": "f" * 32,         # absent -> missing
        "wp-admin/b.js": "e" * 32,              # absent -> missing
    }
    source, entries = no_read_tree(files)
    session = FakeSession([checksums_response(checksums)])
    payload = {
        "ok": True,
        "files": {"wp-includes/a.php": md5(b"AAA"),
                  "wp-admin/z.php": md5(b"ZZZ"),
                  "wp-includes/present.php": md5(b"PPP")},
        "missing": ["wp-includes/bar.js", "wp-admin/b.js"],
        "unreadable": [],
    }
    bridge = FakeBridge(script=[payload])
    d = audit_data(entries, source, wp_version="7.1",
                   probe_obj=probe(session, bridge))
    findings = check_core_integrity(d, DEFAULTS)
    assert len(findings) == 1
    f = findings[0]
    f.validate()
    assert (f.count, f.bytes, f.risk) == (6, 12, "high")
    # (kind, path) order with kind ranking tampered > added > missing;
    # 5 example lines then the truncation marker
    assert f.detail == detail(
        "tampered: wp-admin/z.php",
        "tampered: wp-includes/a.php",
        "added: rogue.php",
        "added: wp-admin/x.php",
        "missing: wp-admin/b.js",
        "(+1 more)",
    )
    # tampered + added + missing: the composed fix names every action
    assert f.fix == f"{restore_added_fix()} {missing_fix()}"


# -------------------------------------------------------- cache behavior


def test_second_call_within_ttl_no_network(cache_dir):
    source, entries = no_read_tree(CORE)
    session = FakeSession([checksums_response(core_checksums())])
    bridge = FakeBridge(files=CORE)
    d = audit_data(entries, source, wp_version="7.1",
                   probe_obj=probe(session, bridge))
    assert check_core_integrity(d, DEFAULTS) == []
    assert len(session.gets) == 1
    # the shared wp.org cache serves the second run: no second request —
    # but core_md5 is LIVE server state: it runs again
    assert check_core_integrity(d, DEFAULTS) == []
    assert len(session.gets) == 1
    assert len(bridge.calls) == 2


def test_stale_cache_reused_on_fetch_failure(cache_dir, wpt_records):
    source, entries = no_read_tree(CORE)
    checksums = core_checksums()
    checksums["wp-includes/js/gone.js"] = "0" * 32
    session = FakeSession([checksums_response(checksums)])
    bridge = FakeBridge(files=CORE)  # gone.js is not on the server
    d = audit_data(entries, source, wp_version="7.1",
                   probe_obj=probe(session, bridge))
    assert [f.detail for f in check_core_integrity(d, DEFAULTS)] == [
        detail("missing: wp-includes/js/gone.js")
    ]
    # age the cache entry past the TTL (no sleeps), then fail the network
    path = cache_dir / (updates._cache_key(
        integrity._checksums_url("7.1"), None) + ".json")
    aged = time.time() - (updates.DEFAULT_WP_ORG.cache_ttl_s + 400)
    os.utime(path, (aged, aged))
    failing = FakeSession([requests.ConnectionError("boom")])
    d2 = audit_data(entries, source, wp_version="7.1",
                    probe_obj=probe(failing, bridge))
    # the stale entry still answers — the check does NOT skip; the live
    # server still lacks gone.js (core_md5 runs again, never cached)
    assert [f.detail for f in check_core_integrity(d2, DEFAULTS)] == [
        detail("missing: wp-includes/js/gone.js")
    ]
    assert len(failing.gets) == 1  # one fetch was attempted
    assert len(bridge.calls) == 2
    # the TRANSPORT warns about the failure; the check stays quiet
    transport = [r.getMessage() for r in wpt_records
                  if r.name == "wpt.audit.updates" and r.levelno == logging.WARNING]
    assert len(transport) == 1 and "stale" in transport[0]
    assert check_warnings(wpt_records) == []


# ----------------------------------------------------------- transports


def test_transport_uses_probe_when_present():
    session = FakeSession()
    d = audit_data([], FakeSource(), probe_obj=probe(session))
    assert integrity._transport(d, DEFAULTS) == (session, TIMEOUT)


def test_transport_local_plain_session_and_profile_timeout():
    d = audit_data([], FakeSource(), mode="local")
    got_session, got_timeout = integrity._transport(d, DEFAULTS)
    assert isinstance(got_session, requests.Session)
    assert got_timeout == DEFAULTS.http.timeout_s


def test_R9_P2_16_local_transport_session_is_closed(
        cache_dir, monkeypatch):
    """P2-16: local mode creates a fresh plain wp.org session per check and
    never closed it; the ftp stack's session must never be closed here."""
    created = []

    class _Tracking(requests.Session):
        def __init__(self):
            super().__init__()
            self.closed = 0
            created.append(self)

        def close(self):
            self.closed += 1
            super().close()

    monkeypatch.setattr(integrity.requests, "Session", _Tracking)
    source, entries = tree(CORE)
    seed_cache(cache_dir, "7.1", core_checksums())
    d = audit_data(entries, source, wp_version="7.1", mode="local")

    assert check_core_integrity(d, DEFAULTS) == []
    assert created and all(session.closed == 1 for session in created)


def test_R9_P1_integrity_helpers_re_raise_a_cooperative_stop(monkeypatch):
    """P1: four broad catches in the integrity helpers turned SIGTERM into
    a degrade (None/[]), so the audit could finish rc 0 after the stop."""
    import io
    import zipfile as _zipfile
    from types import SimpleNamespace

    from wpt.types import Entry

    class _StopBridge:
        def call(self, *args, **kwargs):
            raise StopRequested("received SIGTERM (15)")

    with pytest.raises(StopRequested):
        integrity.affected_files_bridge(
            _StopBridge(),
            {"index.php": Entry("index.php", False, size=1)},
            {"index.php": "d41d8cd98f00b204e9800998ecf8427e"},
            junk_patterns=[])

    theme = [("tampered", "wp-content/themes/x/style.css", 1)]
    monkeypatch.setattr(
        integrity, "_theme_versions",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            StopRequested("received SIGTERM (15)")))
    with pytest.raises(StopRequested):
        integrity.resolve_theme_skew(theme, FakeSource(), object(), 5)

    class _StopRead(FakeSource):
        def read_many(self, paths, *, max_bytes=None):
            raise StopRequested("received SIGTERM (15)")

    monkeypatch.setattr(integrity, "_theme_versions",
                        lambda *args, **kwargs: {"x": "1.2.3"})
    buf = io.BytesIO()
    with _zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("x/style.css", b"body{}")

    class _ZipApi:
        def __init__(self, *args, **kwargs):
            pass

        def fetch_theme_zip(self, *args, **kwargs):
            return buf.getvalue()

    monkeypatch.setattr(integrity, "WpOrgApi", _ZipApi)
    with pytest.raises(StopRequested):
        integrity.resolve_theme_skew(theme, _StopRead(), object(), 5)

    settings = SimpleNamespace(core_integrity=SimpleNamespace(
        known_added=[{"name": "x.php", "marker": "M", "max_bytes": 10,
                      "note": "n"}]))
    with pytest.raises(StopRequested):
        integrity._split_known_added(
            [("added", "x.php", 5)], _StopRead(), settings)


def test_R22_known_added_matches_the_exact_top_level_path_only():
    """R22-P2: the split is a PATH reduction.  A signature removes only its
    exact top-level path; the same marker under another path (or a
    lookalike casing) stays an unresolved high-risk ``added`` entry."""
    from wpt.audit import integrity

    blob = b"<?php // adminer.php\n"
    source = FakeSource()
    source.files = {
        "adminer.php": blob,
        "wp-content/adminer.php": blob,
        "Adminer.php": blob,
    }
    settings = replace(
        DEFAULTS,
        core_integrity=replace(
            DEFAULTS.core_integrity,
            known_added=[{"name": "adminer.php", "marker": "adminer.php",
                          "max_bytes": 1024, "note": "operator drop-in"}],
        ),
    )
    affected = [("added", name, len(blob)) for name in source.files]
    known, remaining = integrity._split_known_added(
        affected, source, settings)
    assert [entry[1] for entry in known] == ["adminer.php"]
    assert {entry[1] for entry in remaining} == {
        "wp-content/adminer.php", "Adminer.php"}


# ------------------------------------------------- local mode, end-to-end


def test_local_mode_run_checks_end_to_end(cache_dir):
    # no probe (local mode): the plain-session transport + a fresh,
    # cache-served checksums answer — clean core => silence
    source, entries = tree(CORE)
    seed_cache(cache_dir, "7.1", core_checksums())
    d = audit_data(entries, source, wp_version="7.1", mode="local")
    assert run_checks(d, DEFAULTS, "local", ["core.integrity"], None) == []

    # a tampered file flows through the real registry pipeline
    source.files["wp-trackback.php"] = b"<?php // tampered\n"
    d2 = audit_data(list(source.walk()), source, wp_version="7.1", mode="local")
    findings = run_checks(d2, DEFAULTS, "local", ["core.integrity"], None)
    assert [(f.category, f.name, f.detail, f.count, f.risk) for f in findings] == [
        ("core.integrity", "core-files",
         detail("tampered: wp-trackback.php"), 1, "high"),
    ]
    for f in findings:
        f.validate()


# ---------------------------------------------------------- registry side


def test_registry_wiring():
    rec = {r.name: r for r in all_checks()}["core.integrity"]
    assert rec.applies == ("ftp", "local")
    assert rec.func is check_core_integrity
    # the dotted-prefix group selector: "core" matches core.integrity
    # (and never updates.core — a prefix must fall on a dot boundary)
    assert [r.name for r in select_checks("ftp", ["core"], None)] == [
        "core.integrity",
    ]
    assert [r.name for r in select_checks("local", ["core"], None)] == [
        "core.integrity",
    ]


# ------------------------------------------- heal-core reuse primitives


def test_primitives_classify_directly():
    # the heal-core seam: the classification primitives take the
    # source + the walked files map + the checksums DIRECTLY (no
    # AuditData) and classify exactly what the data-shaped wrapper
    # answers — delegation pinned by equality with that wrapper, not
    # by re-covering the semantics already pinned above
    files = {
        "wp-includes/clean.php": b"clean",
        "wp-includes/bad.php": b"tampered",
        "wp-admin/rogue.php": b"<?php /* added */",
    }
    checksums = {
        "wp-includes/clean.php": md5(b"clean"),
        "wp-includes/bad.php": md5(b"wp.org says otherwise"),
        "wp-includes/gone.js": "0" * 32,   # absent -> missing
        "wp-cron.php": "1" * 32,           # absent, TOP-LEVEL php -> missing [L18]
        "license.txt": "2" * 32,           # absent, TOP-LEVEL non-php -> silent
    }
    source = _BulkReadSource()
    source.files.update(files)
    entries = list(source.walk())
    walked = {e.path: e for e in entries if not e.is_dir}

    # the primitive's raw order: map-order digest classifications with
    # the tree-only added tail appended — the (kind, path) presentation
    # sort is the CHECK's, not the primitives' (pinned above)
    local = integrity.affected_files_local(
        source, walked, checksums, junk_patterns=DEFAULTS.webroot_junk
    )
    assert local == [
        ("tampered", "wp-includes/bad.php", len(b"tampered")),
        ("missing", "wp-includes/gone.js", 0),
        ("missing", "wp-cron.php", 0),
        ("added", "wp-admin/rogue.php", len(b"<?php /* added */")),
    ]
    # the tree-only half is its own public primitive
    assert integrity.added_files(walked, checksums) == [
        ("added", "wp-admin/rogue.php", len(b"<?php /* added */")),
    ]
    # the check path's AuditData-shaped wrapper delegates to the SAME answer
    d = audit_data(entries, source, wp_version="7.1", mode="local")
    assert integrity._affected_files_local(d, checksums, DEFAULTS) == local


def test_bridge_primitive_classifies_directly():
    # affected_files_bridge takes the bridge + the walked files map
    # with NO AuditData/probe (the never-read _NoReadSource proves it
    # takes no local reads) and classifies exactly what the
    # data-shaped wrapper answers; a None bridge degrades to None
    # INSIDE the primitive (the check's one-warning skip shape)
    server = {
        "wp-includes/bad.php": b"tampered",   # digest != map -> tampered
        "wp-admin/rogue.php": b"<?php /* added",
    }
    checksums = {
        "wp-includes/bad.php": md5(b"wp.org says otherwise"),
        "wp-includes/gone.js": "0" * 32,     # absent -> missing
    }
    source, entries = no_read_tree(server)
    walked = {e.path: e for e in entries if not e.is_dir}
    bridge = FakeBridge(files=server)        # gone.js -> missing bucket

    got = integrity.affected_files_bridge(
        bridge, walked, checksums, junk_patterns=DEFAULTS.webroot_junk
    )
    assert got == [
        ("tampered", "wp-includes/bad.php", len(b"tampered")),
        ("missing", "wp-includes/gone.js", 0),
        ("added", "wp-admin/rogue.php", len(b"<?php /* added")),
    ]
    assert integrity.affected_files_bridge(
        None, walked, checksums, junk_patterns=DEFAULTS.webroot_junk
    ) is None
    # the check path's AuditData-shaped wrapper delegates to the SAME answer
    session = FakeSession()  # never used: the wrapper makes no wp.org call
    d = audit_data(entries, source, wp_version="7.1",
                    probe_obj=probe(session, bridge))
    assert integrity._affected_files_bridge(d, checksums, DEFAULTS) == got


# ------------------------------------------- locale resolution [L17]
#
# The observed localized migration: both sites held the fr_CA BUILD (version.php
# carries $wp_local_package='fr_CA'; its md5 differs from the en_US
# build's markerless file — the only same-PATH digest difference
# between the two checksums maps, live-verified for 7.1, 7.0, 6.8.3 and
# 6.6.2 fr_CA) and WPLANG=fr_CA.  The
# locale-blind check compared them against the en_US map and the heal
# wrote en_US bytes — the site then FAILED `wp core verify-checksums
# --locale=fr_CA`.

#: The official en_US build's wp-includes/version.php (no marker).
EN_VERSION_PHP = b"<?php\n$wp_version = '7.1';\n"


def test_resolve_core_locale_tiers():
    """[L17] The resolver's tiering, directly: the version.php build
    marker first (a READABLE markerless file IS the en_US build — wp-cli
    parity, so an en_US build + fr_CA language pack never reads as a
    localized build and never gets its version.php "healed" into a
    mixed site); the site-locale fact (WPLANG) only when version.php
    cannot be read (the pre-heal shape: the marker file is the evidence
    an attacker destroys); en_US as the floor.  Invalid characters are
    refused as evidence — they would interpolate into wp.org URLs."""
    marker = _BulkReadSource()
    marker.files["wp-includes/version.php"] = FR_CA_VERSION_PHP
    assert integrity.resolve_core_locale(marker, None) == "fr_CA"
    assert integrity.resolve_core_locale(marker, "de_DE") == "fr_CA"

    # readable + markerless = the en_US build, whatever WPLANG says
    language_pack = _BulkReadSource()
    language_pack.files["wp-includes/version.php"] = EN_VERSION_PHP
    assert integrity.resolve_core_locale(language_pack, "fr_CA") == "en_US"

    # unreadable version.php: the site-locale hint answers
    gone = _BulkReadSource()  # version.php absent from the store
    assert integrity.resolve_core_locale(gone, "fr_CA") == "fr_CA"
    assert integrity.resolve_core_locale(gone, None) == "en_US"
    assert integrity.resolve_core_locale(None, "fr_CA") == "fr_CA"
    assert integrity.resolve_core_locale(None, None) == "en_US"

    # invalid characters never reach a URL (a tampered marker or a
    # corrupt dump cell is refused as evidence, not interpolated)
    evil = _BulkReadSource()
    evil.files["wp-includes/version.php"] = (
        b"<?php\n$wp_version = '7.1';\n"
        b"$wp_local_package = '../evil';\n"
    )
    assert integrity.resolve_core_locale(evil, None) == "en_US"
    assert integrity.resolve_core_locale(gone, "../evil") == "en_US"
    assert integrity.resolve_core_locale(gone, "") == "en_US"


def test_fr_ca_build_version_php_clean(cache_dir):
    """[L17] The live false positive, fixed: a version.php that IS the
    fr_CA build (marker present, md5 differs from the en_US build)
    reads CLEAN under the fr_CA map — with the request shape pinned to
    locale=fr_CA.  (The locale-blind code fetched en_US and read this
    exact tree as detail("tampered: wp-includes/version.php") high risk.)"""
    files = {
        "wp-includes/version.php": FR_CA_VERSION_PHP,
        "index.php": b"<?php // index\n",
    }
    fr_ca_map = {path: md5(blob) for path, blob in files.items()}
    source, entries = no_read_tree(files)
    session = FakeSession([checksums_response(fr_ca_map)])
    bridge = FakeBridge(files=files)
    d = audit_data(entries, source, wp_version="7.1", locale="fr_CA",
                    probe_obj=probe(session, bridge))
    assert check_core_integrity(d, DEFAULTS) == []
    url, _kw = session.gets[0]
    assert url == integrity._checksums_url("7.1", "fr_CA")
    assert "core/checksums/1.0/?version=7.1&locale=fr_CA" in url
    # the request rode the probe session with the identifying UA
    assert len(session.gets) == 1


def test_en_us_build_with_language_pack_stays_en_us(cache_dir):
    """[L17] The tier's other side: WPLANG=fr_CA on an en_US BUILD (the
    web-installer shape — language PACK, not localized build) compares
    against the en_US map — the fr_CA map would false-positive its
    version.php, and heal-core would then write fr_CA-build bytes over
    an en_US build (a mixed site that fails default
    `wp core verify-checksums` on every core file)."""
    files = {
        "wp-includes/version.php": EN_VERSION_PHP,
        "index.php": b"<?php // index\n",
    }
    en_map = {path: md5(blob) for path, blob in files.items()}
    source, entries = no_read_tree(files)
    session = FakeSession([checksums_response(en_map)])
    bridge = FakeBridge(files=files)
    d = audit_data(entries, source, wp_version="7.1", locale="fr_CA",
                    probe_obj=probe(session, bridge))
    assert check_core_integrity(d, DEFAULTS) == []
    url, _kw = session.gets[0]
    assert "locale=en_US" in url  # the BUILD locale drives the request


# --- the tiers UNDER ATTACK: version.php is the file the compromise
# lives in, so its own marker is untrusted evidence.  Each case below
# pins the documented degradation, never a guess.

#: A tampered version.php whose $wp_local_package line was REMOVED — the
#: shape an attacker leaves behind to erase the build's identity.
DE_MARKERLESS_VERSION_PHP = b"<?php\n$wp_version = '7.1';\n// wiped\n"
#: ...and one that INJECTS a foreign locale that DOES have builds on
#: wp.org (de_DE is live-verified available) alongside a payload — the
#: realistic compromise.
DE_MARKER_VERSION_PHP = (
    b"<?php\n$wp_version = '7.1';\n$wp_local_package = 'de_DE';\n"
    b"// injected backdoor\n"
)


def test_tampered_version_php_marker_removed_degrades_to_en_us(cache_dir,
                                                               wpt_records):
    """[L17] The marker DESTROYED: a readable version.php with no valid
    marker IS the en_US build (wp-cli's own verify-checksums rule), so
    the comparison uses the en_US map — one request, no fallback warning,
    and the file's own bytes are then reported tampered, which is the
    honest answer (they differ from the official en_US build)."""
    files = {
        "wp-includes/version.php": DE_MARKERLESS_VERSION_PHP,
        "index.php": b"<?php // index\n",
    }
    en_map = {
        "wp-includes/version.php": md5(EN_VERSION_PHP),
        "index.php": md5(files["index.php"]),
    }
    source, entries = no_read_tree(files)
    session = FakeSession([checksums_response(en_map)])
    bridge = FakeBridge(files=files)
    d = audit_data(entries, source, wp_version="7.1", locale="fr_CA",
                   probe_obj=probe(session, bridge))
    findings = check_core_integrity(d, DEFAULTS)
    assert [(f.detail, f.risk) for f in findings] == [
        (detail("tampered: wp-includes/version.php"), "high"),
    ]
    # ONE request only, for en_US: the site-locale tier is unreachable
    # (the file was readable) and no fallback warning fires.
    assert [u for u, _kw in session.gets] == [
        integrity._checksums_url("7.1", "en_US"),
    ]
    assert check_warnings(wpt_records) == []


def test_tampered_version_php_marker_without_a_build_degrades_once(
        cache_dir, wpt_records):
    """[L17] The marker names a locale wp.org has NO build for: the
    checksums endpoint answers the live-verified {"checksums": false},
    so ONE warning names it and the comparison falls back to en_US.
    The tampered marker is never treated as a build."""
    files = {
        "wp-includes/version.php": (
            b"<?php\n$wp_version = '7.1';\n"
            b"$wp_local_package = 'zz_ZZ';\n"
        ),
        "index.php": b"<?php // index\n",
    }
    en_map = {
        "wp-includes/version.php": md5(EN_VERSION_PHP),
        "index.php": md5(files["index.php"]),
    }
    source, entries = no_read_tree(files)
    session = FakeSession([
        FakeResponse(text=json.dumps({"checksums": False})),
        checksums_response(en_map),
    ])
    bridge = FakeBridge(files=files)
    d = audit_data(entries, source, wp_version="7.1", locale="fr_CA",
                   probe_obj=probe(session, bridge))
    findings = check_core_integrity(d, DEFAULTS)
    assert [(f.detail, f.risk) for f in findings] == [
        (detail("tampered: wp-includes/version.php"), "high"),
    ]
    assert [u for u, _kw in session.gets] == [
        integrity._checksums_url("7.1", "zz_ZZ"),
        integrity._checksums_url("7.1", "en_US"),
    ]
    assert check_warnings(wpt_records) == [
        "core integrity: wp.org checksums for WP 7.1 locale zz_ZZ are "
        "unavailable — comparing against the official en_US checksums",
    ]


def test_tampered_version_php_foreign_marker_is_reported_not_guessed(
        cache_dir, wpt_records):
    """[L17] The marker's remaining attack: it names a locale that DOES
    have builds (de_DE is live-verified).  The build marker lives in
    exactly this one file — the file an attacker tampers with — so no
    resolver can out-vote it, and the tool does not try: the on-disk
    marker is the basis (wp-cli's own rule), the file is then reported
    tampered because its bytes are not the official de_DE build's, and
    nothing is guessed silent.  The blast radius is bounded by
    construction — live-verified on wp.org across four versions x two
    locales, the only same-PATH digest difference between an en_US and
    a locale map is wp-includes/version.php, so a wrong basis can only
    ever name (and heal) that one file."""
    files = {
        "wp-includes/version.php": DE_MARKER_VERSION_PHP,
        "index.php": b"<?php // index\n",
    }
    de_map = {
        # the official de_DE build's version.php carries ITS marker
        "wp-includes/version.php": md5(
            b"<?php\n$wp_version = '7.1';\n$wp_local_package = 'de_DE';\n"
        ),
        "index.php": md5(files["index.php"]),
    }
    source, entries = no_read_tree(files)
    session = FakeSession([checksums_response(de_map)])
    bridge = FakeBridge(files=files)
    d = audit_data(entries, source, wp_version="7.1", locale="fr_CA",
                   probe_obj=probe(session, bridge))
    findings = check_core_integrity(d, DEFAULTS)
    # index.php matches the de_DE map too (identical across builds) —
    # only the marker file is named, and the basis clause names the
    # de_DE map the bytes were judged against
    assert [(f.detail, f.risk) for f in findings] == [
        (detail("tampered: wp-includes/version.php", locale="de_DE"),
         "high"),
    ]
    assert [u for u, _kw in session.gets] == [
        integrity._checksums_url("7.1", "de_DE"),
    ]
    assert check_warnings(wpt_records) == []


@pytest.mark.parametrize("fr_ca_script", [
    pytest.param(FakeResponse(503, "unavailable"), id="http-503"),
    pytest.param(FakeResponse(text=json.dumps({"checksums": False})),
                 id="no-build-false-payload"),
])
def test_checksums_locale_fallback_warning(cache_dir, wpt_records,
                                            fr_ca_script):
    """[L17] The fr_CA map unavailable (HTTP 503, or the
    live-verified no-build answer {"checksums": false}) => ONE warning
    + the en_US map; the finding then names the en_US basis it ACTUALLY
    used AND the residual (an en_US-restored file still differs from
    the fr_CA build)."""
    files = dict(CORE)
    files["wp-includes/version.php"] = FR_CA_VERSION_PHP
    source, entries = no_read_tree(files)
    en_map = core_checksums()  # describes the MARKERLESS version.php
    session = FakeSession([
        fr_ca_script,               # the fr_CA checksums GET
        checksums_response(en_map),  # the en_US fallback
    ])
    bridge = FakeBridge(files=files)
    d = audit_data(entries, source, wp_version="7.1", locale="fr_CA",
                    probe_obj=probe(session, bridge))
    findings = check_core_integrity(d, DEFAULTS)
    # honest report: the fr_CA build's version.php differs from the
    # en_US map — with the fallback residual named in the fix text
    assert [(f.detail, f.risk, f.fix) for f in findings] == [
        (detail("tampered: wp-includes/version.php"), "high",
         restore_fix(locale="en_US", residual=map_fallback_residual())),
    ]
    assert check_warnings(wpt_records) == [
        "core integrity: wp.org checksums for WP 7.1 locale fr_CA are "
        "unavailable — comparing against the official en_US checksums",
    ]
    assert [u for u, _kw in session.gets] == [
        integrity._checksums_url("7.1", "fr_CA"),
        integrity._checksums_url("7.1", "en_US"),
    ]


def test_checksums_locale_fallback_both_fail_skips(cache_dir, wpt_records):
    """[L17] Both maps unavailable => the existing one-warning skip —
    never partial guessing.  (The fallback warning fires first — the
    fr_CA map WAS unavailable — then the en_US attempt fails too.)"""
    files = dict(CORE)
    files["wp-includes/version.php"] = FR_CA_VERSION_PHP
    source, entries = no_read_tree(files)
    session = FakeSession([
        FakeResponse(503, "unavailable"),
        FakeResponse(503, "unavailable"),
    ])
    bridge = FakeBridge(files=files)
    d = audit_data(entries, source, wp_version="7.1", locale="fr_CA",
                    probe_obj=probe(session, bridge))
    assert check_core_integrity(d, DEFAULTS) == []
    assert check_warnings(wpt_records) == [
        "core integrity: wp.org checksums for WP 7.1 locale fr_CA are "
        "unavailable — comparing against the official en_US checksums",
        "core integrity skipped: checksums unavailable",
    ]


def test_fr_ca_finding_fix_text_carries_locale(cache_dir):
    """[L17] The brief's requirement: the finding's fix text names the
    locale in the detail — "against the official fr_CA 7.1 checksums"
    shape — and states heal-core's zip-404 policy truthfully: it
    restores only the files both builds ship identically and reports
    the differing ones as unrestorable (it does NOT write en_US bytes
    here, which this check would flag on every run)."""
    # tampered-but-parseable: the marker SURVIVES the tamper (the live
    # shape — the resolver must key the basis to the build, and a
    # marker-destroying tamper falls to the WPLANG tier either way)
    tampered = (b"<?php\n$wp_version = '7.1';\n"
                b"$wp_local_package = 'fr_CA';\n// injected backdoor\n")
    files = dict(CORE)
    files["wp-includes/version.php"] = tampered
    source, entries = no_read_tree(files)
    fr_ca_map = core_checksums()  # describes the markerless en_US file
    # ...under fr_CA the official build's version.php carries the marker
    fr_ca_map["wp-includes/version.php"] = md5(FR_CA_VERSION_PHP)
    session = FakeSession([checksums_response(fr_ca_map)])
    bridge = FakeBridge(files=files)
    d = audit_data(entries, source, wp_version="7.1", locale="fr_CA",
                    probe_obj=probe(session, bridge))
    findings = check_core_integrity(d, DEFAULTS)
    assert [(f.detail, f.risk) for f in findings] == [
        (detail("tampered: wp-includes/version.php", locale="fr_CA"),
         "high"),
    ]
    fix = findings[0].fix
    assert "WordPress 7.1 fr_CA release" in fix
    assert "heal-core restores from the official fr_CA build" in fix
    assert "reports the files that differ between the builds as " \
        "unrestorable" in fix


# ------------------------------- the locale fact reaches BOTH modes [L17]
#
# The live question this pins: a read-only audit of the fr_CA site
# reported "0 tampered, 0 missing, 2 added" and its author concluded
# the run had compared against the en_US map.  Two things are proven
# below, per mode and end to end:
#
#   * LOCAL: the fr_CA basis is real — the sampleimg proof shape.  The
#     final artifact's tree is CLEAN under the fr_CA map (and the
#     en_US map is never even requested), while the SAME tree with a
#     tampered fr_CA version.php reads tampered.
#   * FTP: the bridge's `info.locale` (get_locale()) is the tier-2 input
#     the REMOTE path consumes, through the real gather_remote — so the
#     remote comparison rides the same resolver as the local one.  The
#     fixture is the pre-heal shape (version.php unreadable, the file
#     the compromise destroys) with a map whose version.php digest
#     DIFFERS per locale, so the classification proves which map judged.

#: The two maps of ONE version, identical except for the build marker
#: file — the live-verified only same-path digest difference.
def _per_locale_maps(files: dict[str, bytes]) -> tuple[dict, dict]:
    fr_map = {path: md5(blob) for path, blob in files.items()}
    # the build marker is IN both maps and is the one path whose digest
    # differs between them (its $wp_local_package line)
    fr_map["wp-includes/version.php"] = md5(FR_CA_VERSION_PHP)
    en_map = dict(fr_map)
    en_map["wp-includes/version.php"] = md5(EN_VERSION_PHP)
    return fr_map, en_map


def test_local_fr_ca_basis_end_to_end(cache_dir, wporg_urls):
    """[L17] LOCAL mode, end to end, no probe: the fr_CA build's tree is
    CLEAN under the fr_CA map — the en_US map is not even requested —
    and the same tree with a tampered version.php reads tampered.  Both
    outcomes are only reachable with the fr_CA map in hand (under the
    en_US map this very tree reports the marker file), so the fixture
    IS the sampleimg proof the incident questioned."""
    files = {
        "wp-includes/version.php": FR_CA_VERSION_PHP,
        "index.php": b"<?php // index\n",
        "wp-cron.php": b"<?php // cron\n",
    }
    fr_map, en_map = _per_locale_maps(files)
    seed_cache(cache_dir, "7.1", fr_map, locale="fr_CA")
    seed_cache(cache_dir, "7.1", en_map, locale="en_US")

    source, entries = tree(files)
    d = audit_data(entries, source, wp_version="7.1", mode="local",
                   locale="fr_CA")
    assert check_core_integrity(d, DEFAULTS) == []
    assert list(wporg_urls) == [integrity._checksums_url("7.1", "fr_CA")]

    # the same tree, one injected line in the marker file: still keyed to
    # the fr_CA build (the marker survives the tamper), and the finding
    # names the fr_CA basis it used
    tampered = dict(files)
    tampered["wp-includes/version.php"] = FR_CA_VERSION_PHP + b"// injected\n"
    source2, entries2 = tree(tampered)
    d2 = audit_data(entries2, source2, wp_version="7.1", mode="local",
                    locale="fr_CA")
    findings = check_core_integrity(d2, DEFAULTS)
    assert [(f.detail, f.risk) for f in findings] == [
        (detail("tampered: wp-includes/version.php", locale="fr_CA"),
         "high"),
    ]


def test_ftp_bridge_info_locale_drives_the_comparison(cache_dir):
    """[L17] FTP mode: the REMOTE path consumes the bridge's
    ``info.locale`` — the tier-2 input — through the real gather_remote,
    so a fr_CA site with an unreadable version.php is judged against the
    fr_CA map and NOT en_US.  The map is the live shape: identical
    except for the build marker, so a request for the wrong locale would
    report a different file."""
    files = {"index.php": b"<?php // index\n", "wp-cron.php": b"<?php // cron\n"}
    fr_map, _en_map = _per_locale_maps(files)
    bridge = _InfoBridge(files=files, info={
        "wp_version": "7.1",
        "locale": "fr_CA",
        "siteurl": "https://example.net",
        "home": "https://example.net",
        "plugins": {},
    })
    source, entries = no_read_tree(files)   # NO version.php on disk
    d = gather_remote(bridge, source, DEFAULTS)
    assert d.locale == "fr_CA"            # the bridge field, gathered
    session = FakeSession([checksums_response(fr_map)])
    d.probe = probe(session, bridge)
    findings = check_core_integrity(d, DEFAULTS)
    assert [u for u, _kw in session.gets] == [
        integrity._checksums_url("7.1", "fr_CA"),
    ]
    assert [(f.detail, f.risk) for f in findings] == [
        (detail("missing: wp-includes/version.php", locale="fr_CA"),
         "medium"),
    ]


def test_unknown_site_locale_falls_back_to_en_us_and_says_so(cache_dir,
                                                             wpt_records):
    """[L17] The honest floor, pinned: with NO locale evidence at all
    (version.php unreadable AND the bridge's locale field empty — the
    field answers '' for a non-string option value, and the gather maps
    that to unknown) the resolver's tier-3 floor is SILENT and the
    comparison uses en_US.  The disclosure is the report itself: the
    basis clause and the fix both name the en_US map that judged the
    core, so an operator reading the report can tell WHICH map spoke —
    the defect the live incident was actually about.  The ONE warning
    about locale belongs to the fallback path (a known build identity
    whose map was unavailable), which is checked separately below."""
    files = {"index.php": b"<?php // index\n"}
    en_map, _fr = _per_locale_maps(files)
    bridge = _InfoBridge(files=files, info={
        "wp_version": "7.1", "locale": "", "plugins": {},
    })
    source, entries = no_read_tree(files)
    d = gather_remote(bridge, source, DEFAULTS)
    assert d.locale is None                # '' reads as unknown
    session = FakeSession([checksums_response(en_map)])
    d.probe = probe(session, bridge)
    findings = check_core_integrity(d, DEFAULTS)
    assert [u for u, _kw in session.gets] == [
        integrity._checksums_url("7.1", "en_US"),
    ]
    assert check_warnings(wpt_records) == []   # the tier-3 floor is silent
    assert [(f.detail, f.risk, f.fix) for f in findings] == [
        (detail("missing: wp-includes/version.php"), "medium",
         missing_fix()),
    ]


def test_basis_clause_follows_the_fallback_and_keeps_the_residual(
        cache_dir, wpt_records):
    """[L17] The two facts an incident needs, together: a KNOWN fr_CA
    build whose map was unavailable falls back to en_US with the ONE
    warning, and the detail's basis clause names the map that ACTUALLY
    judged (en_US — not the fr_CA build the resolver resolved), while
    the fix keeps the fr_CA residual."""
    files = dict(CORE)
    files["wp-includes/version.php"] = FR_CA_VERSION_PHP
    bridge = _InfoBridge(files=files, info={
        "wp_version": "7.1", "locale": "fr_CA", "plugins": {},
    })
    source, entries = no_read_tree(files)
    d = gather_remote(bridge, source, DEFAULTS)
    session = FakeSession([
        FakeResponse(text=json.dumps({"checksums": False})),
        checksums_response(core_checksums()),  # the en_US map
    ])
    d.probe = probe(session, bridge)
    findings = check_core_integrity(d, DEFAULTS)
    assert [(f.detail, f.risk, f.fix) for f in findings] == [
        (detail("tampered: wp-includes/version.php"), "high",
         restore_fix(locale="en_US", residual=map_fallback_residual())),
    ]
    assert check_warnings(wpt_records) == [
        "core integrity: wp.org checksums for WP 7.1 locale fr_CA are "
        "unavailable — comparing against the official en_US checksums",
    ]


def test_added_known_finding_keeps_its_own_detail_shape(cache_dir):
    """[L16] x the basis clause: the low-risk added-known finding is a
    SIGNATURE verdict (the profile's known_added note), not a checksum
    one, so its detail keeps its existing shape — the basis clause rides
    the core-files finding, which is the checksum comparison."""
    files = dict(CORE)
    files["wordfence-waf.php"] = WORDFENCE_WAF
    source, entries = tree(files)   # the signature gate reads the blob
    session = FakeSession([checksums_response(core_checksums())])
    bridge = FakeBridge(files=files)
    d = audit_data(entries, source, wp_version="7.1",
                   probe_obj=probe(session, bridge))
    findings = check_core_integrity(d, DEFAULTS)
    assert [f.name for f in findings] == ["added-known"]
    note = DEFAULTS.core_integrity.known_added[0]["note"]
    assert findings[0].detail == f"added (known): wordfence-waf.php — {note}"


# --------------------------------------- translation-pack skew [L19]
#
# Only visible on a LOCALIZED build: its checksum map bundles its own
# wp-content/languages/ catalog set (live-verified 7.1 fr_CA: 88
# entries, 226 more paths than the en_US map of the same version), and
# WordPress replaces those catalogs from the wp.org translation pack on
# demand — so an up-to-date site differs from the bundled bytes with no
# tampering at all.  A default theme is cross-checked against evidence
# (resolve_theme_skew); a catalog cannot be, and 8 of them are this
# toolkit's own webroot.junk_recurring delete candidates.

#: The four runtime formats WordPress's translation machinery owns.
CATALOGS = {
    "wp-content/languages/fr_CA.po": b"# updated translation\n",
    "wp-content/languages/fr_CA.mo": b"\x00repacked catalog",
    "wp-content/languages/admin-fr_CA.l10n.php": b"<?php return array();\n",
    "wp-content/languages/fr_CA-abc123.json": b"{}\n",
}


def test_translation_pack_skew_drops_runtime_catalogs(cache_dir,
                                                     wpt_records):
    # LOCAL end-to-end: the four runtime formats under
    # wp-content/languages/ are dropped with ONE info line; everything
    # else keeps its classification — a planted non-catalog .php in the
    # SAME directory, a real tampered core file, and a genuinely
    # tampered catalog-side file type.
    files = dict(CORE)
    files.update(CATALOGS)
    files["wp-content/languages/evil.php"] = b"<?php /* planted */"
    files["wp-trackback.php"] = b"<?php // EVIL\n"
    checksums = {path: md5(blob) for path, blob in CORE.items()}
    checksums["wp-trackback.php"] = md5(b"<?php // official\n")
    for path in CATALOGS:
        checksums[path] = md5(b"the bundled bytes\n")
    checksums["wp-content/languages/evil.php"] = md5(b"<?php /* clean */")
    source, entries = tree(files)
    seed_cache(cache_dir, "7.1", checksums)
    d = audit_data(entries, source, wp_version="7.1", mode="local")
    findings = check_core_integrity(d, DEFAULTS)
    assert [f.detail for f in findings] == [
        detail("tampered: wp-content/languages/evil.php",
               "tampered: wp-trackback.php")
    ]
    assert findings[0].risk == "high" and findings[0].count == 2
    infos = [r.getMessage() for r in wpt_records
             if r.name == "wpt.audit.integrity" and r.levelno == logging.INFO
             and "translation catalog" in r.getMessage()]
    assert len(infos) == 1
    for path in CATALOGS:
        assert path in infos[0]
    assert "evil.php" not in infos[0]
    assert check_warnings(wpt_records) == []


def test_resolve_translation_pack_skew_is_narrow():
    # The pass itself: pure, offline (no source, no session, no wp.org
    # traffic) and narrow by construction — only the four runtime
    # formats under wp-content/languages/ are exempt (at any depth: core
    # ships nested catalogs such as
    # wp-content/languages/themes/twentytwentythree-fr_CA.mo, and
    # load_textdomain() resolves those too), and only when tampered.  A
    # missing catalog, another kind, another file type, a same-named
    # file outside the languages dir and a top-level twin all keep
    # their classification.
    affected = [
        ("tampered", "wp-content/languages/fr_CA.po", 10),
        ("tampered", "wp-content/languages/admin-fr_CA.mo", 10),
        ("tampered", "wp-content/languages/fr_CA.l10n.php", 10),
        ("tampered", "wp-content/languages/fr_CA-abc.json", 10),
        ("tampered",
         "wp-content/languages/themes/twentytwentythree-fr_CA.mo", 10),
        ("tampered", "wp-content/languages/plugins/evil.php", 10),
        ("tampered", "wp-content/languages/readme.txt", 10),
        ("tampered", "wp-content/themes/twentyten/style.css", 10),
        ("missing", "wp-content/languages/fr_CA.po", 0),
        ("added", "fr_CA.po", 5),
        ("tampered", "wp-includes/version.php", 10),
    ]
    kept = integrity.resolve_translation_pack_skew(affected)
    assert kept == [
        ("tampered", "wp-content/languages/plugins/evil.php", 10),
        ("tampered", "wp-content/languages/readme.txt", 10),
        ("tampered", "wp-content/themes/twentyten/style.css", 10),
        ("missing", "wp-content/languages/fr_CA.po", 0),
        ("added", "fr_CA.po", 5),
        ("tampered", "wp-includes/version.php", 10),
    ]
    # identity when nothing matches (no log, no copy semantics relied on)
    assert integrity.resolve_translation_pack_skew([]) == []


# ------------------------------------- default-theme version skew [L12]
#
# The live example.test shape: three twentytwentyfive files whose
# bytes are the PRISTINE official 1.5 theme release, while the core
# 7.1 checksums map describes the 1.4 copy bundled with core.  The
# map-vs-tree classification reads "tampered"; resolve_theme_skew
# cross-checks against the official theme release of the version the
# site's own style.css declares and drops the pristine files.

TT5 = "twentytwentyfive"
TT5_STYLE_15 = (b"/*\nTheme Name: Twenty Twenty-Five\nVersion: 1.5\n*/\n"
                b"body { color: #111; }\n")
TT5_README_15 = b"=== Twenty Twenty-Five ===\nthe 1.5 readme\n"
#: The BUNDLED (1.4) bytes the core checksums map actually describes.
TT5_STYLE_14 = b"/*\nTheme Name: Twenty Twenty-Five\nVersion: 1.4\n*/\n"
TT5_README_14 = b"=== Twenty Twenty-Five ===\nthe 1.4 readme\n"

#: The live Wordfence WAF bootstrap shape (name + content markers of
#: settings core_integrity.known_added's shipped signature).
WORDFENCE_WAF = (
    b"<?php\n"
    b"// Before removing this file, please verify the PHP ini setting "
    b"`auto_prepend_file` does not point to this.\n\n"
    b"if (file_exists(__DIR__.'/wp-content/plugins/wordfence/waf/bootstrap.php')) {\n"
    b"\tdefine(\"WFWAF_LOG_PATH\", __DIR__.'/wp-content/wflogs/');\n"
    b"\tinclude_once __DIR__.'/wp-content/plugins/wordfence/waf/bootstrap.php';\n"
    b"}\n"
)

#: Fix text pinned verbatim from the module (the check contract).
KNOWN_ADDED_FIX = (
    "verify the file is the named plugin's own (diff against a freshly "
    "installed copy of the plugin); delete it only once the plugin is gone"
)


def theme_zip_bytes(slug: str, files: dict[str, bytes]) -> bytes:
    """A small REAL in-memory theme release zip, ``<slug>/``-nested like
    the official theme releases (the nesting fetch_theme_zip validates)."""
    import io as _io
    import zipfile as _zipfile
    buf = _io.BytesIO()
    with _zipfile.ZipFile(buf, "w") as zf:
        for rel, blob in files.items():
            zf.writestr(f"{slug}/{rel}", blob)
    return buf.getvalue()


def seed_theme_zip(cache_dir, slug: str, version: str, payload: bytes):
    """A FRESH theme-zip cache entry (raw bytes at the transport's own
    theme-<slug>-<version>.zip name) — WpOrgApi serves it with no
    network, so even the local-mode plain-session path stays offline."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / f"theme-{slug}-{version}.zip"
    path.write_bytes(payload)
    return path


def bundled_theme_checksums() -> dict[str, str]:
    """The core-bundled 1.4 checksums for the two theme paths."""
    return {
        f"wp-content/themes/{TT5}/style.css": md5(TT5_STYLE_14),
        f"wp-content/themes/{TT5}/readme.txt": md5(TT5_README_14),
    }


def test_theme_skew_pristine_auto_update_reclassified(cache_dir, wpt_records):
    """[L12] A pristine official 1.5 theme auto-update behind the 1.4
    bundled checksums is NOT tampering: the finding is [] (the live
    false positive), with one info line naming the reclassified files."""
    files = {
        f"wp-content/themes/{TT5}/style.css": TT5_STYLE_15,
        f"wp-content/themes/{TT5}/readme.txt": TT5_README_15,
    }
    source, entries = tree(files)
    seed_cache(cache_dir, "7.1", bundled_theme_checksums())
    seed_theme_zip(cache_dir, TT5, "1.5", theme_zip_bytes(TT5, {
        "style.css": TT5_STYLE_15, "readme.txt": TT5_README_15,
    }))
    d = audit_data(entries, source, wp_version="7.1", mode="local")
    assert check_core_integrity(d, DEFAULTS) == []
    infos = [r.getMessage() for r in wpt_records
             if r.name == "wpt.audit.integrity" and r.levelno == logging.INFO]
    assert any("not tampering" in m and TT5 in m
               and f"{TT5}/style.css" in m for m in infos)


def test_R19_theme_skew_size_unknown_uses_the_configured_fallback(
        cache_dir, wpt_records):
    """R19-P1: a non-Unix FTP LIST reports SIZE_UNKNOWN (-1).  ``max(...)``
    became -1, every read_many refused, and a PRISTINE official theme
    update stayed a HIGH tampered finding — the exact L12 shape heal-core
    would then "fix" by DOWNGRADING the theme.  Unknown sizes now fall
    back to files.max_file_bytes (and the official zip's own largest
    entry), so the read happens and the file resolves."""
    files = {
        f"wp-content/themes/{TT5}/style.css": TT5_STYLE_15,
        f"wp-content/themes/{TT5}/readme.txt": TT5_README_15,
    }
    source, entries = tree(files)
    # The listing knows no sizes at all (the FTP SIZE_UNKNOWN shape).
    entries = [replace(entry, size=-1) if entry.path.startswith(
        "wp-content/themes/") else entry for entry in entries]
    seed_cache(cache_dir, "7.1", bundled_theme_checksums())
    seed_theme_zip(cache_dir, TT5, "1.5", theme_zip_bytes(TT5, {
        "style.css": TT5_STYLE_15, "readme.txt": TT5_README_15,
    }))
    affected = [("tampered", f"wp-content/themes/{TT5}/style.css", -1),
                ("tampered", f"wp-content/themes/{TT5}/readme.txt", -1)]
    got = integrity.resolve_theme_skew(
        affected, source, FakeSession(), TIMEOUT,
        max_file_bytes=DEFAULTS.files.max_file_bytes)
    assert got == []
    assert any("not tampering" in r.getMessage() for r in wpt_records
               if r.name == "wpt.audit.integrity"
               and r.levelno == logging.INFO)


def test_R20_theme_skew_fallback_is_wired_from_the_check(
        cache_dir, monkeypatch):
    """The check-level wiring of R19's fallback: check_core_integrity must
    pass the configured files.max_file_bytes into the theme-skew pass (the
    direct-primitive test alone could not prove the caller)."""
    calls = []

    def fake(affected, *args, **kwargs):
        calls.append(kwargs.get("max_file_bytes"))
        return affected

    monkeypatch.setattr(integrity, "resolve_theme_skew", fake)
    settings = load(overrides={"files.max_file_bytes": 1234567})
    source, entries = tree({
        f"wp-content/themes/{TT5}/style.css": TT5_STYLE_15,
    })
    seed_cache(cache_dir, "7.1", bundled_theme_checksums())
    d = audit_data(entries, source, wp_version="7.1", mode="local")
    check_core_integrity(d, settings)
    assert calls == [1234567]


def test_theme_skew_mixed_with_real_tampered_reports_only_real(cache_dir):
    """A pristine theme update beside a GENUINELY tampered core file:
    only the real one reports (high) — the skew pass cannot silence
    core-dir tampering."""
    files = dict(CORE)
    files["wp-trackback.php"] = b"<?php // actually evil\n"
    files[f"wp-content/themes/{TT5}/style.css"] = TT5_STYLE_15
    checksums = core_checksums()
    checksums["wp-trackback.php"] = md5(CORE["wp-trackback.php"])
    checksums.update(bundled_theme_checksums())
    source, entries = tree(files)
    seed_cache(cache_dir, "7.1", checksums)
    seed_theme_zip(cache_dir, TT5, "1.5",
                   theme_zip_bytes(TT5, {"style.css": TT5_STYLE_15}))
    d = audit_data(entries, source, wp_version="7.1", mode="local")
    findings = check_core_integrity(d, DEFAULTS)
    assert [(f.category, f.name, f.detail, f.count, f.risk) for f in findings] == [
        ("core.integrity", "core-files",
         detail("tampered: wp-trackback.php"), 1, "high"),
    ]
    findings[0].validate()


def test_theme_skew_differs_from_own_release_stays_tampered(cache_dir):
    """A theme file that matches NEITHER the bundled checksums NOR the
    official release of the version it declares stays tampered — the
    cross-check never guesses benign."""
    evil_style = b"/*\nVersion: 1.5\n*/\n<?php eval($_POST['x']);\n"
    files = {f"wp-content/themes/{TT5}/style.css": evil_style,
             f"wp-content/themes/{TT5}/readme.txt": TT5_README_15}
    source, entries = tree(files)
    seed_cache(cache_dir, "7.1", bundled_theme_checksums())
    seed_theme_zip(cache_dir, TT5, "1.5", theme_zip_bytes(TT5, {
        "style.css": TT5_STYLE_15, "readme.txt": TT5_README_15,
    }))
    d = audit_data(entries, source, wp_version="7.1", mode="local")
    findings = check_core_integrity(d, DEFAULTS)
    # the pristine readme dropped; the evil style stayed
    assert [(f.category, f.name, f.detail, f.count, f.risk) for f in findings] == [
        ("core.integrity", "core-files",
         detail(f"tampered: wp-content/themes/{TT5}/style.css"), 1, "high"),
    ]


def test_theme_skew_unknown_version_stays_tampered(cache_dir, wpt_records):
    """No style.css on disk => the version is unknown => the cross-check
    cannot run: one warning, the tampered classification survives."""
    files = {f"wp-content/themes/{TT5}/readme.txt": TT5_README_15}
    source, entries = tree(files)
    seed_cache(cache_dir, "7.1", bundled_theme_checksums())
    d = audit_data(entries, source, wp_version="7.1", mode="local")
    findings = check_core_integrity(d, DEFAULTS)
    assert [(f.category, f.name, f.detail, f.count, f.risk) for f in findings] == [
        ("core.integrity", "core-files",
         detail(f"tampered: wp-content/themes/{TT5}/readme.txt"), 1, "high"),
    ]
    warnings = [r.getMessage() for r in wpt_records
                if r.name == "wpt.audit.integrity" and r.levelno == logging.WARNING]
    assert any("stay classified tampered" in m for m in warnings)


def test_theme_skew_zip_unavailable_stays_tampered(cache_dir):
    """ftp mode: the theme zip fetch fails (a scripted 404 through the
    probe session) => one warning + the high classification survives."""
    files = {
        f"wp-content/themes/{TT5}/style.css": TT5_STYLE_15,
        f"wp-content/themes/{TT5}/readme.txt": TT5_README_15,
    }
    source, entries = tree(files)
    session = FakeSession([
        checksums_response(bundled_theme_checksums()),
        FakeResponse(status_code=404),   # the theme zip GET
    ])
    bridge = FakeBridge(files=files)
    d = audit_data(entries, source, wp_version="7.1",
                    probe_obj=probe(session, bridge))
    findings = check_core_integrity(d, DEFAULTS)
    assert [(f.category, f.name, f.count, f.risk) for f in findings] == [
        ("core.integrity", "core-files", 2, "high"),
    ]
    # the theme zip went to the official downloads host with the UA
    theme_gets = [u for u, _kw in session.gets
                  if "downloads.wordpress.org/theme/" in u]
    assert theme_gets == [
        f"https://downloads.wordpress.org/theme/{TT5}.1.5.zip"
    ]


def test_theme_skew_read_many_raise_stays_tampered(cache_dir):
    """Version known + zip available, but the bulk read DIES between the
    classification pass and the skew pass (a channel death mid-run —
    read_many raises on its SECOND call): one warning, the tampered
    classification survives.  (A path unreadable at CLASSIFICATION time
    never reaches the skew pass — it is a debug skip there.)"""
    class _DyingBulkSource(_BulkReadSource):
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        def read_many(self, paths, *, max_bytes=None):
            self.calls += 1
            if self.calls >= 2:
                raise OSError("stale passive channel")
            return super().read_many(paths)

    source = _DyingBulkSource()
    source.files = {
        f"wp-content/themes/{TT5}/style.css": TT5_STYLE_15,
        f"wp-content/themes/{TT5}/readme.txt": TT5_README_15,
    }
    entries = list(source.walk())
    seed_cache(cache_dir, "7.1", bundled_theme_checksums())
    seed_theme_zip(cache_dir, TT5, "1.5", theme_zip_bytes(TT5, {
        "style.css": TT5_STYLE_15, "readme.txt": TT5_README_15,
    }))
    d = audit_data(entries, source, wp_version="7.1", mode="local")
    findings = check_core_integrity(d, DEFAULTS)
    assert [(f.category, f.name, f.detail) for f in findings] == [
        ("core.integrity", "core-files",
         detail(f"tampered: wp-content/themes/{TT5}/readme.txt",
                f"tampered: wp-content/themes/{TT5}/style.css")),
    ]


def test_resolve_theme_skew_source_none_and_non_theme_untouched():
    """The primitive post-pass, directly: no source => identity; entries
    outside wp-content/themes/ pass through without any wp.org traffic."""
    affected = [
        ("tampered", "wp-includes/version.php", 10),
        ("added", "rogue.php", 5),
        ("missing", "wp-admin/gone.php", 0),
    ]
    got = integrity.resolve_theme_skew(
        affected, None, FakeSession(), TIMEOUT
    )
    assert got == affected
    got = integrity.resolve_theme_skew(
        affected, _BulkReadSource(), FakeSession(), TIMEOUT
    )
    assert got == affected  # no theme paths => no reads, no fetches


# ------------------------------------------- known added artifacts [L16]


def test_known_added_wordfence_bootstrap_low_risk_finding(cache_dir):
    """[L16] The REAL Wordfence WAF bootstrap (name + marker + size +
    no malware signature) reports as the separate low-risk added-known
    finding — never as high-risk compromise evidence."""
    files = dict(CORE)
    files["wordfence-waf.php"] = WORDFENCE_WAF
    source, entries = tree(files)
    session = FakeSession([checksums_response(core_checksums())])
    bridge = FakeBridge(files=files)
    d = audit_data(entries, source, wp_version="7.1",
                    probe_obj=probe(session, bridge))
    findings = check_core_integrity(d, DEFAULTS)
    note = DEFAULTS.core_integrity.known_added[0]["note"]
    assert [
        (f.category, f.name, f.detail, f.bytes, f.count, f.risk, f.fix)
        for f in findings
    ] == [
        ("core.integrity", "added-known",
         f"added (known): wordfence-waf.php — {note}",
         len(WORDFENCE_WAF), 1, "low", KNOWN_ADDED_FIX),
    ]
    findings[0].validate()


def test_known_added_line_split_malware_stays_high(cache_dir):
    """A signature split across lines is still a signature. The known-artifact
    gate used per-line regexes, so a payload the suspicious check REPORTS was
    downgraded to the low-risk added-known finding."""
    evil = WORDFENCE_WAF + b'eval(\nbase64_decode("x"));\n'
    files = dict(CORE)
    files["wordfence-waf.php"] = evil
    source, entries = tree(files)
    session = FakeSession([checksums_response(core_checksums())])
    bridge = FakeBridge(files=files)
    d = audit_data(entries, source, wp_version="7.1",
                    probe_obj=probe(session, bridge))
    findings = check_core_integrity(d, DEFAULTS)
    assert [(f.name, f.detail, f.risk) for f in findings] == [
        ("core-files", detail("added: wordfence-waf.php"), "high"),
    ]


def test_known_added_malware_content_stays_high(cache_dir):
    """A file with the right NAME and MARKER but a malware signature
    inside (eval($_POST)) stays high — the marker alone never buys the
    low classification."""
    evil = (WORDFENCE_WAF + b"eval($_POST['x']);\n")
    files = dict(CORE)
    files["wordfence-waf.php"] = evil
    source, entries = tree(files)
    session = FakeSession([checksums_response(core_checksums())])
    bridge = FakeBridge(files=files)
    d = audit_data(entries, source, wp_version="7.1",
                    probe_obj=probe(session, bridge))
    findings = check_core_integrity(d, DEFAULTS)
    assert [(f.name, f.detail, f.risk) for f in findings] == [
        ("core-files", detail("added: wordfence-waf.php"), "high"),
    ]


def test_known_added_marker_absent_stays_high(cache_dir):
    """An impostor with the right name but no marker stays high."""
    files = dict(CORE)
    files["wordfence-waf.php"] = b"<?php // not wordfence at all\n"
    source, entries = tree(files)
    session = FakeSession([checksums_response(core_checksums())])
    bridge = FakeBridge(files=files)
    d = audit_data(entries, source, wp_version="7.1",
                    probe_obj=probe(session, bridge))
    findings = check_core_integrity(d, DEFAULTS)
    assert [(f.name, f.detail, f.risk) for f in findings] == [
        ("core-files", detail("added: wordfence-waf.php"), "high"),
    ]


def test_known_added_oversize_stays_high_without_read(cache_dir):
    """A candidate over the signature's max_bytes never READS (the size
    gate runs before any fetch — _NoReadSource fails the test on a
    read) and stays high."""
    files = dict(CORE)
    files["wordfence-waf.php"] = b"X" * 5000  # > the shipped 2048 gate
    source, entries = no_read_tree(files)
    session = FakeSession([checksums_response(core_checksums())])
    bridge = FakeBridge(files=files)
    d = audit_data(entries, source, wp_version="7.1",
                    probe_obj=probe(session, bridge))
    findings = check_core_integrity(d, DEFAULTS)
    assert [(f.name, f.detail, f.risk) for f in findings] == [
        ("core-files", detail("added: wordfence-waf.php"), "high"),
    ]


def test_theme_skew_style_read_never_raises(cache_dir):
    """The pass is never-raise: a source whose style.css read blows up
    with a NON-SourceError (outside _theme_versions' own catch) reads
    as an unknown version — warning + the classification survives, no
    exception escapes the check.  (style.css is unreadable at
    classification time too, so only readme.txt classifies tampered.)"""
    class _RawErrorSource(_BulkReadSource):
        def read_bytes(self, path):
            if path.endswith("style.css"):
                raise OSError("raw transport error")
            return super().read_bytes(path)

    source = _RawErrorSource()
    source.files = {
        f"wp-content/themes/{TT5}/style.css": TT5_STYLE_15,
        f"wp-content/themes/{TT5}/readme.txt": TT5_README_15,
    }
    entries = list(source.walk())
    seed_cache(cache_dir, "7.1", bundled_theme_checksums())
    d = audit_data(entries, source, wp_version="7.1", mode="local")
    findings = check_core_integrity(d, DEFAULTS)
    assert [(f.category, f.name, f.detail, f.risk) for f in findings] == [
        ("core.integrity", "core-files",
         detail(f"tampered: wp-content/themes/{TT5}/readme.txt"), "high"),
    ]
