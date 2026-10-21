"""Unit tests for the webroot + plugin audit checks (wpt.audit.webroot) — W6c.

Hand-built AuditData only: direct Entry construction, Settings from the
shipped profile (wpt.settings.load()) or dataclasses.replace with custom
lists. No gatherers, no sources, no network, no sleeps — deterministic.
The ONE wp.org-shaped exception: the official-core junk exemption rides
the REAL WpOrgApi transport over a SEEDED .wpt-cache (the integrity
suite's seeding convention — conftest pins the cache to tmp_path), so
the real fetch path runs offline; the failure shapes script the session
through a FakeSession probe (ftp mode).

Test -> behavior map (W6c task list):
  test_junk_one_finding_per_matched_pattern ... per-pattern findings with
        count/bytes/risk/excerpt detail; non-matching patterns silent;
        wp-config.php never junk; findings sorted by name
  test_junk_matches_files_only ................ a directory named like a
        junk pattern is never matched
  test_junk_risk_mapping ...................... *.sql-shaped high, .bk
        high, wp-config-sample.php medium, rest low; "schema.sql" (no
        leading wildcard) is NOT high
  test_junk_detail_truncates_at_five .......... 7 matches -> 5 paths
        + " (+2 more)"
  test_junk_silent_without_matches_or_patterns  clean tree -> []; a bare
        Settings() (empty pattern list) flags nothing — patterns live in
        the profile only, never in code
  --- the `<group>:<glob>` pattern GROUPS (the live source host's control
      files, which the shipped list named none of) ---
  test_junk_group_ships_in_the_profile ...... the three groups are
        DECLARED profile data, every shipped group name has wording in
        this module, and the observed control-panel files are all covered by
        the shipped list (a profile edit that drops one fails here)
  test_junk_groups_are_one_finding_each_with_their_own_risk_and_wording
        THREE findings named by their GROUP, not six per-glob findings;
        the placeholder family is HIGH and its WHY names the full-site
        visual outage + the 404 error-handling hijack and its fix says
        delete OR keep it out of the docroot; the quota file is a MEDIUM
        information disclosure naming WHAT it leaks; the superseded
        access config is reported WITHOUT being conflated with the live
        `.htaccess` and stated safe to delete
  test_junk_group_globs_cannot_reach_legitimate_content  [the misfire this
        design exists to prevent] `home.php`, the live `.htaccess`, a
        theme's own `home.html`/`404.shtml`, a plugin's authored
        `index.html`/`test.html`, an uploads `home.html` and a nested
        `support/.ftpquota` produce NO finding and no match at the SHARED
        PREDICATE clean-files and integrity use
  test_junk_group_glob_is_root_scoped_and_a_bare_one_is_not  the one
        behavioural difference, stated: a grouped pattern is a PATH
        pattern, a bare one is a BASENAME pattern (unchanged)
  test_junk_group_pattern_syntax_is_fail_safe  a colon, an empty side, a
        glob metacharacter or an UNKNOWN group name all leave the pattern
        BARE, so a profile can never turn a working pattern into a group
        nor invent a risk; a grouped dump pattern still gets the uploads
        attachment-data exemption
  test_a_group_glob_that_can_leave_the_root_is_refused_before_any_run  the
        MEASURED case end to end: `host_placeholder_page:*.php` reported
        WordPress's own top-level core files HIGH with the group's "no site
        content is lost" fix and planned SEVEN of them for deletion, so the
        profile DOOR now refuses the pattern and the run never starts
  test_a_bare_core_file_name_behaves_exactly_as_it_did_before_the_door  the
        counterpart that must NOT move: the door's root-``.php`` and
        never-deleted-name rules are GROUP rules, and a bare `wp-cron.php`
        still reports under its own name at its own text-derived risk and
        still plans
  test_no_clean_files_plan_can_carry_a_top_level_core_file_from_a_group  the
        other half, at a real zip and a real clean-files plan: no top-level
        core file is ever planned from a group, the root control page still
        is, and a theme's `home.html` / a plugin's `index.html` stay
        unreachable
  test_the_group_name_set_and_the_wording_table_agree  the door's group
        NAMES (settings) and this module's WORDING table are two views of
        one list, pinned to each other
  test_junk_group_never_fetches_for_a_core_exemption  the shipped groups
        perform no wp.org fetch and consume no served-path probe (the
        dump/log-shaped served lead-in would print the wrong mitigation),
        while a bare pattern in the same tree probes exactly as before
  test_junk_group_fix_never_contradicts_its_unproven_detail  [D2, for
        groups] a grouped pattern WITH a path and no version gets the
        unproven clause in the detail AND the unproven fix, never
        "Safe to delete" / "Delete it"
  test_junk_exempts_official_core_files ...... wp-version + seeded map:
        wp-includes/ID3/license.txt + wp-includes/images/crystal/
        license.txt + wp-includes/js/*/license.txt EXEMPT (license.txt
        counts only its top-level copy); top-level readme.html /
        wp-config-sample.php (also map members) STAY deletable; a
        non-map core-dir junk file (wp-includes/error_log) stays junk;
        one info line names the exempted paths
  [D1] the LIVE production deletion (a clean-files --apply removed all
  five official core wp-includes/**/license.txt members and left
  `wp core verify-checksums` failing), with one test per ruled-IN cause
  and the candidates that measurement ruled out pinned by the passing
  tests above:
  test_junk_without_version_reports_core_dir_matches_as_unproven  an
        UNKNOWN version is the branch that skipped the fetch ENTIRELY:
        the DELETE PLAN stays fail-closed (below), the CHECK now REPORTS
        the core-dir match with the unproven basis in the detail — proved
        by A/B, the old shared predicate made a served
        wp-includes/error_log disappear from the report (0 findings,
        exit 0) whenever wp.org was unreachable
  test_junk_unproven_detail_is_only_on_patterns_that_matched_a_core_path
        the clause is per finding: a top-level-only finding says nothing
        about the basis
  test_junk_an_unproven_finding_never_says_safe_to_delete [D2] the
        detail said "Do not delete these on this evidence" while the FIX
        said "Safe to delete" / "Delete now": the actionable field talked
        the operator into the hand-deletion the plan is fail-closed
        against. Both fields together: the fix is the unproven
        instruction, at every risk, and the with-map case is unchanged
  test_junk_exemption_refusal_is_one_warning_per_consumer_per_run  ONE
        line per CONSUMER per run (the old single-slot latch kept only
        the first reason, so a run that audited then planned said
        nothing on the path that deletes), carrying the SAME reason
  test_junk_checksums_failure_warns_once_and_reports_core_dir_matches
        scripted 503: unavailable map => every core-dir match reported
        as unproven, one warning naming version AND locale
  test_junk_exemption_uses_the_sites_own_build_locale_map  the basis is
        the BUILD's map through integrity's own resolver + comparison
        fetch (fr_CA), never a second locale path in this module
  test_junk_exemption_locale_falls_back_to_en_US_through_integrity  a
        locale with no build ("checksums": false) degrades to en_US
        through integrity's one-warning fallback and still exempts
  test_clean_files_plan_leaves_core_dir_junk_alone_without_a_version
        the live defect at the PLAN: a zip whose version.php is
        unreadable must not plan an official core file
  test_clean_files_rehearsal_keeps_the_core_license_and_removes_the_
        content_one  end-to-end local rehearsal: core
        wp-includes/ID3/license.txt + non-core
        wp-content/plugins/<unit>/license.txt => only the latter is
        planned, and the rehearsed twin keeps the core file
        byte-identical
  test_junk_no_fetch_without_core_dir_matches  no core-dir junk
        candidates -> NO wp.org request at all (empty-script session)
  test_junk_exemption_fetch_is_the_integrity_map_for_this_version  the
        exemption's ONE request is integrity's own URL for that version
        (version + locale in the request = in the 1h cache key): a run
        that also runs core.integrity shares the fetch
  test_po_catalogs_under_languages ............ nested languages/*.po
        counted; .mo and outside-languages .po not; recurring explanation
  test_po_catalogs_silent_without_po .......... only runtime formats -> []
  test_stale_dirs_under_wp_content ............ wp-content + uploads
        depths, subtree bytes/files, root-level same name NOT matched,
        plain files never matched
  test_stale_silent_without_dirs_or_patterns .. no stale dirs -> []; empty
        stale_content_dirs -> []
  test_migration_matches ...................... plugin dir subsumes its
        descendants (count/bytes), ai1wm* file matches, per-pattern
        findings sorted
  test_migration_silent_without_leftovers ...... clean tree -> []; empty
        migration_leftovers -> []
  test_inactive_units_and_active_semantics ..... dir + single-file units;
        active dir plugin not flagged; inactive sums correct
  test_inactive_active_single_file_not_flagged  "hello.php" active only
        when "hello.php" is in active_plugins
  test_inactive_no_plugins_dir ................ no plugins dir / empty
        plugins dir -> []
  test_inactive_detail_truncates_at_eight ...... 10 units -> 8 + " (+2 more)"
  test_duplicate_group_two_present ............ 2 of 3 group members ->
        finding naming actives/inactives; whole group in the name;
        1-member group silent
  test_duplicate_custom_groups_via_settings ... replace()-driven groups,
        single-file units participate
  test_duplicate_silent_without_groups ........ empty duplicate groups /
        single-member group -> []
  test_duplicate_detail_names_content_evidence_for_both_members  [L17]
        the live "which of these two page builders holds the content?"
        decision: per member the detail states the DISTINCT posts holding
        its content and names the postmeta prefixes it came from, and the
        fix keeps the member that HAS content + names the exact
        deactivate command for the one that has none
  test_duplicate_when_both_builders_hold_content_refuses_to_pick  two
        content holders -> no invented keeper, bytes 0, and the deferred
        figure that keeps the size visible
  test_duplicate_deferred_figure_names_the_size_a_keeper_unlocks  the
        [D1] "a number silently disappeared" fix: bytes stay 0 while the
        detail AND one INFO line state the members' total as reclaimable
        once a keeper is named
  test_duplicate_exactly_one_holder_is_unchanged_by_the_deferred_figure
        a named keeper means the reclaimable figure is the candidate set
        and no deferred clause is rendered
  test_duplicate_named_keeper_is_unchanged_by_the_deferred_figure  a
        DECLARED keeper likewise; a declared keeper that is NOT
        installed names no command, claims no bytes, and says so
  test_duplicate_content_evidence_is_never_guessed_from_a_partial_map
        an unanswered prefix stays UNKNOWN (today's detail, "confirm
        before dropping") — a partial map can never fake a zero
  test_duplicate_without_the_fact_keeps_todays_shape  no counts / None ->
        the historical detail + "Keep one, remove the rest." fix, and
        no log noise
  test_duplicate_members_without_declared_content_keys_stay_silent  the
        cache group (no content keys) is never given a content claim
  test_duplicate_preferred_key_changes_only_the_fix  the operator's
        declared keep changes the fix only — same detail/counts/risk —
        with or without evidence, both directions
  test_duplicate_preferred_key_works_without_content_evidence
  test_duplicate_preferred_slug_that_is_not_installed_names_no_command
  test_duplicate_group_with_three_present_members_lists_each_command
  test_content_meta_prefixes_are_the_shipped_plugin_facts  the
        slug -> meta-prefix map itself, and that an un-answered /
        unusable count is unknown rather than a number
  test_heavy_present ......................... present slugs with subtree
        sizes, detail slugs
  test_heavy_absent .......................... none present -> []; empty
        known_heavy -> []
  test_mu_plugins_platform_leftovers_reported  shipped prefixes flag
        automation-by-installatron.php + 0-worker.php (one low finding,
        subtree bytes for dir units); custom/non-platform mu-plugins and
        the plugins dir never match
  test_mu_plugins_directory_unit_custom_prefixes  replace()-driven
        prefixes + a DIRECTORY unit subsume its subtree
  test_mu_plugins_silent_without_platform_matches  no mu-plugins /
        non-matching names / empty prefix list -> []
  test_mu_plugin_platform_prefixes_shipped_in_profile  the Settings
        field is wired to the profile key (data-driven, overridable)
  test_active_missing_plugins_fires .......... active fusion-builder +
        litespeed-cache with only akismet present -> ONE high finding,
        sorted slugs, exact fix text (the two-site migration shape)
  test_active_missing_silent_when_tree_complete  dir + single-file units
        all present -> []
  test_active_missing_single_file_plugin ..... "hello.php" listed but
        absent -> flagged by its whole name
  test_active_missing_installed_but_unlisted_stays_silent  the inverse
        (installed, not active) is plugins.inactive's scope, never a
        db.active_missing finding
  test_active_missing_mode_agnostic ........... run_checks in BOTH modes
        (the analyzer / the bridge normalize active_plugins into
        AuditData) — identical finding
  test_active_missing_detail_truncates_at_eight  10 missing slugs -> 8
        + " (+2 more)" (the observed case had many)
  test_active_entry_missing_but_unit_present_is_reported  the LIVE shape:
        an active plugin whose unit SURVIVED (many orphan vendor/*.php,
        served and executed) with no direct .php child -> the separate
        HIGH active-plugin-entry-missing finding, naming the gone file and
        the reconcile-plugins/header-scan limit
  test_active_entry_missing_and_unit_absent_are_separate_findings  both
        shapes in one tree -> one finding each, in that order
  test_active_entry_present_stays_silent .... a unit holding a direct .php
        child (and a nested vendor/) is healthy: nothing reported
  test_active_non_php_unit_is_reported ........ a unit that survived as a
        non-PHP shell (readme.txt + assets) is not loadable either: same
        finding, same limit
  test_active_mu_plugin_entry_is_skipped_by_the_entry_rule  a
        mu-plugins/webroot-relative entry names no plugin unit: the new
        rule stays silent, exactly as the unit rule already did
  test_clean_files_plan_exempts_core_license_file  the ACTION plan
        follows the check's exemption: local-mode fixture zip with
        wp-includes/version.php + wp-includes/ID3/license.txt (seeded
        map) — the core file is NOT planned, the top-level junk is
  test_registry_contains_all_nine ............. dotted names + applies
        ("ftp", "local")
  test_select_groups_selectable .............. select_checks("ftp",
        ["webroot"]) / ("local", ["plugins"]) exact lists
  test_run_checks_end_to_end ................. run_checks pipeline over a
        rich fixture: full findings, ftp == local, every Finding validates
  test_active_plugins_entry_that_cannot_name_a_unit_is_silent  [review]
        an absolute / webroot-relative / mu-plugins / dotted / empty
        active_plugins entry yields no active slug: no bogus HIGH
        db.active_missing for a non-plugin ("wp-content") and no
        collateral "inactive" verdicts for the real plugins
  test_active_plugin_slugs_rule_shared_by_both_checks  ONE owner: the
        single-file plugin keeps its whole name; both consumers agree
  test_mu_plugins_prefixes_are_prefixes_not_globs  the profile list is
        NAME PREFIXES (a "0-*" glob matches nothing); the match is on
        the direct child's own name, never a path prefix (a nested file
        and the plugins dir never contribute)
  test_clean_files_plan_without_version_php_keeps_the_core_dir_safe  the
        ACTION's degrade path after [D1]: a zip with no version.php makes
        NO wp.org request at all, keeps the core-dir junk OUT of the
        plan, and warns once
  [D3] junk that is SERVED (the same finding; one bounded probe, one
  lead sentence — never a new category):
  test_junk_served_publicly_leads_the_fix_with_the_disclosure  HTTP 200
        for a matched large log -> the fix LEADS with "1 of these are
        served publicly at error_log (HTTP 200) ... information disclosure
        ... deny the extension in .htaccess (FilesMatch ...)", the
        measured size, then the original per-risk advice; one probe, and
        it is the SITE's URL (never wp.org)
  test_junk_not_served_changes_nothing ..... offline (no probe), 404, a
        redirect, 403, a network failure and a high-risk pattern all
        render the fix byte-identically to a run without the probe
  test_junk_served_probe_is_capped_at_three_paths  at most 3 matched
        paths are probed; the sample is stated as a sample
  test_junk_served_probe_needs_a_site_url_and_a_deadline  no --wp-url and
        an expired budget request nothing (so nothing is claimed)
  test_backup_payload_finding_also_leds_with_the_disclosure  the archive
        finding gets the same disclosure ahead of the park-backups advice
  test_the_unmeasured_active_set_markers_suggest_nothing_and_count_nothing
        the two ACTIVE-SET-UNKNOWN markers carry their own categories (so
        no suggested-step rule can name a command that refuses offline),
        count 0, and a fix scoped to the active set — never a global
        "nothing is deletable"; an observed run still reports the ordinary
        plugins.inactive finding under its own category
"""

import json
import logging
import re
import zipfile
from dataclasses import replace

import pytest
import requests

import wpt.audit.integrity as integrity
import wpt.audit.updates as updates
import wpt.audit.webroot as webroot
from tests.fakes import FakeResponse, FakeSession, FakeSource
from wpt.actions.clean_files import CleanFilesAction
from wpt.actions.registry import run_action
from wpt.audit.data import AuditData
from wpt.audit.registry import all_checks, run_checks, select_checks
from wpt.audit.security import SiteProbe
from wpt.audit.updates import WpOrgApi
from wpt.audit.webroot import (
    _active_plugin_slugs,
    check_db_active_missing,
    check_plugins_duplicate,
    check_plugins_heavy,
    check_plugins_inactive,
    check_webroot_junk,
    check_webroot_junk_recurring,
    check_webroot_migration,
    check_webroot_mu_plugins,
    check_webroot_stale,
    core_junk_basis,
    junk_file_matches,
    junk_matches_reporting,
    member_content_posts,
    split_junk_pattern,
)
from wpt.cli import Ctx
from wpt.report import AuditReport
from wpt.settings import (JUNK_GROUP_NAMES, Settings, SettingsError,
                          load)
from wpt.sources.zip import ZipSource
from wpt.types import Entry

#: The shipped profile (wpt/data/profiles/default.json) — every pattern these
#: checks consume, exactly as users get it.
DEFAULTS = load()

#: A live-shaped wp.org checksums map for "7.1" (the live two-site
#: migration's core-license shape): the top-level files the junk patterns
#: also match (which must STAY deletable) plus the official core-dir
#: license.txt copies (which must be exempted).  Digests are opaque —
#: the exemption is map membership, no hashing.
CORE_CHECKSUMS = {
    "readme.html": "1" * 32,
    "license.txt": "2" * 32,
    "wp-config-sample.php": "3" * 32,
    "wp-includes/version.php": "4" * 32,
    "wp-includes/ID3/license.txt": "5" * 32,
    "wp-includes/images/crystal/license.txt": "6" * 32,
    "wp-includes/js/jquery/license.txt": "7" * 32,
}


def _seed_checksums(version: str, checksums: dict[str, str], locale: str = "en_US"):
    """A FRESH cache entry for the checksums URL — the REAL WpOrgApi
    transport then serves it without any network (the integrity suite's
    seeding convention; tests/conftest.py pins the cache dir to tmp_path)."""
    updates._CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = updates._CACHE_DIR / (
        updates._cache_key(integrity._checksums_url(version, locale), None)
        + ".json"
    )
    path.write_text(json.dumps({"checksums": checksums}), encoding="utf-8")
    return path


def _webroot_records(wpt_records):
    """This module's own wpt.audit.webroot log records."""
    return [r for r in wpt_records if r.name == "wpt.audit.webroot"]


def _reset_exemption_latch():
    """Start the 'the exemption already refused' latch from clean.

    ``webroot._EXEMPTION_REFUSED`` is the run-scoped once-only latch
    behind the ONE warning per consumer per run (the same module-attribute
    convention as ``wpt.audit.updates._CACHE_DIR``, pinned per test by
    tests/conftest.py).  A test asserting that single line has to start
    un-latched, and the latch can only ever SUPPRESS a warning, so
    leaving it set never turns a pass into a fail elsewhere.
    """
    webroot._EXEMPTION_REFUSED = {}


def E(path, size=0, is_dir=False):
    """One Entry, webroot-relative POSIX."""
    return Entry(path=path, is_dir=is_dir, size=size)


def audit_data(entries, active=(), mode="local", wp_version=None, probe=None,
               source=None, locale=None):
    """A hand-built AuditData: walked tree + active plugin file paths."""
    return AuditData(
        mode=mode,
        entries=list(entries),
        siteurl=None,
        home=None,
        template=None,
        blog_public=None,
        wp_version=wp_version,
        mu_plugins=None,
        active_plugins=list(active),
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
        probe=probe,
        source=source,
        locale=locale,
    )


# ------------------------------------------------------------ webroot.junk


def test_junk_one_finding_per_matched_pattern():
    # A version + map are needed for the two CORE-dir entries below: the
    # exemption is map membership, and neither `wp-admin/readme.html` nor
    # `wp-includes/license.txt` is a map member, so both stay junk.
    _seed_checksums("7.1", CORE_CHECKSUMS)
    d = audit_data([
        E("readme.html", 100),
        E("wp-admin/readme.html", 20),
        E("license.txt", 50),
        E("wp-includes/license.txt", 7),   # basename match anywhere in the tree
        E("error_log", 10),
        E("wp-config-sample.php", 400),
        E(".htaccess.bk", 30),
        E("dump.sql", 500),
        E("backup.sql", 300),
        E("wp-config.php", 1000),          # the real config is never junk
    ], wp_version="7.1")
    findings = check_webroot_junk(d, DEFAULTS)
    # one finding per matched pattern, sorted by (category, name)
    assert [(f.name, f.count, f.bytes, f.risk) for f in findings] == [
        ("*.sql", 2, 800, "high"),
        (".htaccess.bk", 1, 30, "high"),
        ("error_log", 1, 10, "low"),
        ("license.txt", 2, 57, "low"),
        ("readme.html", 2, 120, "low"),
        ("wp-config-sample.php", 1, 400, "medium"),
    ]
    for f in findings:
        assert f.category == "webroot.junk"
        assert f.fix
    by_name = {f.name: f for f in findings}
    # example paths in walk order, up to 5 (fewer here: no truncation marker)
    assert by_name["readme.html"].detail == "readme.html, wp-admin/readme.html"
    assert by_name["license.txt"].detail == "license.txt, wp-includes/license.txt"
    assert by_name["*.sql"].detail == "dump.sql, backup.sql"
    assert "webroot" in by_name["*.sql"].fix     # L1: dumps out of the webroot
    assert "webroot" in by_name[".htaccess.bk"].fix


def test_junk_matches_files_only():
    d = audit_data([E("error_log", is_dir=True), E("error_log/inner.log", 5)])
    assert check_webroot_junk(d, DEFAULTS) == []


def test_junk_risk_mapping():
    settings = replace(Settings(), webroot_junk=[
        "*.sql", "schema.sql", "x.bk", "wp-config-sample.php", "readme.html",
    ])
    d = audit_data([
        E("dump.sql", 10),
        E("schema.sql", 10),   # no leading wildcard: not the dump-exposure rule
        E("x.bk", 10),
        E("wp-config-sample.php", 10),
        E("readme.html", 10),
    ])
    got = {f.name: f.risk for f in check_webroot_junk(d, settings)}
    assert got == {
        "*.sql": "high",
        "schema.sql": "low",
        "x.bk": "high",
        "wp-config-sample.php": "medium",
        "readme.html": "low",
    }


def test_junk_detail_truncates_at_five():
    settings = replace(Settings(), webroot_junk=["error_log"])
    paths = [f"wp-content/uploads/{i}/error_log" for i in range(7)]
    d = audit_data([E(p, i) for i, p in enumerate(paths)])
    findings = check_webroot_junk(d, settings)
    assert len(findings) == 1
    f = findings[0]
    assert f.count == 7
    assert f.bytes == sum(range(7))
    assert f.detail == ", ".join(paths[:5]) + " (+2 more)"


def test_junk_silent_without_matches_or_patterns():
    clean = audit_data([
        E("wp-config.php", 100), E("wp-content", is_dir=True),
        E("wp-content/index.php", 50),
    ])
    assert check_webroot_junk(clean, DEFAULTS) == []
    # bare Settings() has no junk patterns: nothing is flagged — patterns
    # come from the profile, never from code literals
    dirty = audit_data([E("readme.html", 1), E("dump.sql", 2)])
    assert check_webroot_junk(dirty, Settings()) == []


# ------------------------------------ webroot.junk pattern GROUPS (host files)


#: The live source-host webroot of the migration whose deployable artifact
#: was verified cold (an observed run): a cPanel/LiteSpeed export whose root
#: carried control-panel files beside the site's own ``index.php``.
#: ``.ftpquota`` holds the OLD ACCOUNT's real quota numbers; the two
#: ``.htaccess`` variants are pre-hardening copies of the access config.
_HOST_CONTROL_FILES = [
    ("home.html", 1963),
    ("404.shtml", 1699),
    ("test.html", 10),
    (".ftpquota", 17),
    ("old.htaccess", 301),
    (".htaccess.old", 512),
]


def test_junk_group_ships_in_the_profile():
    """The three groups are DECLARED, not hardcoded: every shipped
    ``<group>:<glob>`` entry names a group this module has wording for, and
    the observed control-panel files are all covered by the shipped list.  A
    profile edit that drops one entry, or renames a group, fails here
    instead of silently going unreported."""
    groups = {split_junk_pattern(p)[0] for p in DEFAULTS.webroot_junk}
    assert {g for g in groups if g is not None} == {
        "host_placeholder_page", "host_account_quota", "superseded_htaccess",
    }
    assert groups <= set(webroot._JUNK_GROUPS) | {None}
    matched = {
        entry.path
        for entry, _p in junk_file_matches(
            [E(path, size) for path, size in _HOST_CONTROL_FILES],
            DEFAULTS.webroot_junk,
        )
    }
    assert matched == {path for path, _size in _HOST_CONTROL_FILES}


def test_junk_groups_are_one_finding_each_with_their_own_risk_and_wording():
    """The three families are THREE findings named by their GROUP, not six
    anonymous per-glob findings: one placeholder finding covering three
    files, one quota finding, one superseded-config finding — each at the
    risk its own shape earns, and each carrying a WHY and a fix an
    operator can act on."""
    d = audit_data([E(path, size) for path, size in _HOST_CONTROL_FILES])
    findings = {f.name: f for f in check_webroot_junk(d, DEFAULTS)}
    assert set(findings) == {
        "host_placeholder_page", "host_account_quota", "superseded_htaccess",
    }
    placeholder = findings["host_placeholder_page"]
    assert placeholder.category == "webroot.junk"
    assert (placeholder.risk, placeholder.count, placeholder.bytes) == (
        "high", 3, 1963 + 1699 + 10,
    )
    assert placeholder.detail.splitlines()[0] == "home.html, 404.shtml, test.html"
    # WHY: a coming-soon page is a FULL-SITE visual outage and a 404 page
    # an error-handling hijack; the fix says delete OR keep it out of the
    # docroot and configure the host's error pages deliberately.
    why = " ".join(placeholder.detail.splitlines()[1:])
    assert "full-site visual outage" in why
    assert "error handling" in why
    assert "control-panel file, not site content" in why
    fix = placeholder.fix
    assert "index.php" in fix
    assert "OUT of the webroot" in fix
    assert "point the host at them" in fix

    quota = findings["host_account_quota"]
    assert (quota.risk, quota.count, quota.bytes) == ("medium", 1, 17)
    # an INFORMATION-DISCLOSURE finding: it names WHAT it leaks
    assert "FTP disk-quota numbers" in quota.detail
    assert "guessable name" in quota.detail
    assert "stale and misleading" in quota.detail
    assert "Safe to delete" in quota.fix

    superseded = findings["superseded_htaccess"]
    assert (superseded.risk, superseded.count, superseded.bytes) == (
        "medium", 2, 301 + 512,
    )
    # reported WITHOUT being conflated with the live .htaccess, and stated
    # safe to delete
    assert "SUPERSEDED copy" in superseded.detail
    assert "NOT the live '.htaccess'" in superseded.detail
    assert "harden action owns and the write-guard protects" in superseded.detail
    assert "Safe to delete" in superseded.fix
    assert "never a clean-files target" in superseded.fix


def test_junk_group_globs_cannot_reach_legitimate_content():
    """[the misfire this design exists to prevent] a ``home.html`` inside a
    theme, a theme's own ``404.shtml``, a plugin's legitimately authored
    ``index.html``/``test.html``, the site's ``home.php`` and the live
    ``.htaccess`` are all CONTENT or a protected config — and a group glob
    is matched on the webroot-relative PATH, so a glob carrying no ``/``
    can only ever fire at the webroot root."""
    content = [
        E("home.php", 405),                              # the site's front page
        E("index.php", 405),
        E(".htaccess", 2720),                           # harden owns this one
        E("wp-config.php", 3486),
        E("wp-content/themes/Avada/home.html", 900),     # a theme's template
        E("wp-content/themes/Avada/includes/404.shtml", 1200),
        E("wp-content/themes/Avada/test.html", 1200),
        E("wp-content/plugins/avada/index.html", 300),   # authored by the plugin
        E("wp-content/plugins/avada/test.html", 300),
        E("wp-content/plugins/avada/old.htaccess", 300),
        E("wp-content/plugins/avada/.htaccess.old", 300),
        E("wp-content/uploads/2024/05/home.html", 300),
        E("support/.ftpquota", 4),
    ]
    assert check_webroot_junk(audit_data(content), DEFAULTS) == []
    # and the same holds at the shared PREDICATE the clean-files plan and
    # integrity's junk subtraction both use — not just at the check
    assert junk_file_matches(
        [E(p, 1) for p, _ in [(e.path, 0) for e in content]],
        DEFAULTS.webroot_junk,
    ) == []


def test_junk_group_glob_is_root_scoped_and_a_bare_one_is_not():
    """The one behavioural difference, stated as its own test: a grouped
    pattern is a PATH pattern (root-only as shipped), a bare pattern is a
    BASENAME pattern (any depth, unchanged)."""
    entries = [E("home.html", 1), E("wp-content/themes/x/home.html", 1),
               E("readme.html", 1), E("wp-admin/readme.html", 1)]
    patterns = ["host_placeholder_page:home.html", "readme.html"]
    assert [(e.path, p) for e, p in junk_file_matches(entries, patterns)] == [
        ("home.html", "host_placeholder_page:home.html"),
        ("readme.html", "readme.html"),
        ("wp-admin/readme.html", "readme.html"),
    ]


def test_junk_group_pattern_syntax_is_fail_safe():
    """A group reference is only a group reference when it is one: an
    unknown name, an empty side or a glob metacharacter on the left all
    leave the pattern BARE (basename-matched, reported under its own name
    at its own text-derived risk) so a profile can never turn a working
    pattern into a group — or a group into a risk that does not exist."""
    assert split_junk_pattern("error_log") == (None, "error_log")
    assert split_junk_pattern("host_placeholder_page:home.html") == (
        "host_placeholder_page", "home.html",
    )
    # a colon in the FILE name stays bare: "weird" is not a known group, so
    # the whole string is one literal basename pattern (R6-02)
    assert split_junk_pattern("weird:12:00.html") == (
        None, "weird:12:00.html")
    for pattern in (":home.html", "host_placeholder_page:", "*.html:home.html",
                    "we?rd:home.html", "[ab]:home.html"):
        assert split_junk_pattern(pattern) == (None, pattern)
    # An unknown group name degrades to a literal bare pattern.  It no
    # longer path-matches "home.html" (or, with "*.php", every core/plugin
    # PHP file); nothing is reported or planned (R6-02).
    settings = replace(Settings(), webroot_junk=["no_such_group:home.html"])
    findings = check_webroot_junk(audit_data([E("home.html", 5)]), settings)
    assert findings == []
    assert junk_file_matches(
        [E("home.html", 5), E("wp-login.php", 5)],
        ["HOST_PLACEHOLDER_PAGE:*.php", "no_such_group:*.php"]) == []
    # ...and a grouped pattern shaped like a dump is still a bare dump
    # pattern for the uploads attachment-data exemption
    settings = replace(Settings(), webroot_junk=["no_such_group:*.sql"])
    assert check_webroot_junk(
        audit_data([E("wp-content/uploads/x/dump.sql", 5)]), settings,
    ) == []


#: WordPress's own TOP-LEVEL core files: [L18] recorded a live host that had
#: deleted all five of the .php ones, which is why the check below exists.
#: They are checksum-map members, but the core-junk exemption is scoped to
#: wp-admin/ and wp-includes/, so a junk policy that NAMED one would plan it
#: for deletion by design.
TOP_LEVEL_CORE_FILES = [
    "wp-login.php", "wp-cron.php", "xmlrpc.php", "wp-signup.php",
    "wp-mail.php", "wp-comments-post.php", "wp-trackback.php",
]


def test_a_group_glob_that_can_leave_the_root_is_refused_before_any_run():
    """THE MEASURED CASE, end to end: a profile cannot mint a HIGH finding
    and a "no site content is lost" fix over WordPress's own core files.

    ``"host_placeholder_page:*.php"`` in a profile produced a HIGH
    webroot.junk finding over every top-level core file (the group's risk,
    WHY and fix), and a clean-files plan in which SEVEN of them were
    deletable — the official-core exemption covers ``wp-admin/`` and
    ``wp-includes/`` only, which is the top-level files' deliberate
    exemption.  The fix is at the profile DOOR, so the run refuses to
    start: there is no Settings tree to plan from.
    """
    with pytest.raises(SettingsError,
                       match=r"webroot_junk\[\d+\]: the 'host_placeholder_page'"):
        load(overrides={"webroot_junk":
                        [*DEFAULTS.webroot_junk, "host_placeholder_page:*.php"]})


def test_no_clean_files_plan_can_carry_a_top_level_core_file_from_a_group(
        tmp_path):
    """...and no PLAN carries one, at the shared predicate every junk plan
    is built from.

    Two halves, and the second is the one that matters operationally: the
    door refuses the glob (above), and — for every group glob the door
    admits, which by then carries no ``/ * ? [ ]`` and can only match at the
    webroot ROOT — the plan-side matching never selects a top-level core
    file.  A real zip + a real ``clean-files`` plan, so this is the action's
    own output and not a re-derivation of it.
    """
    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("wp-includes/version.php", b"<?php\n$wp_version = '7.1';\n")
        for name in TOP_LEVEL_CORE_FILES:
            zf.writestr(name, b"<?php // core\n")
        zf.writestr("home.html", b"<h1>Coming soon</h1>")   # the real group
        zf.writestr("wp-content/themes/x/home.html", b"theme template")
        zf.writestr("wp-content/plugins/x/index.html", b"authored by the plugin")
    _seed_checksums("7.1", CORE_CHECKSUMS)
    ctx = Ctx(
        source="local", settings=DEFAULTS, command="clean-files",
        backup_dir=tmp_path / "backup", zip=zpath,
        wp_url="https://example.com",
    )
    source = ZipSource(zpath)
    try:
        plan = CleanFilesAction().plan(ctx, (source, None, None))
    finally:
        source.close()
    targets = [item.target for item in plan.items]
    assert not [t for t in targets if t in TOP_LEVEL_CORE_FILES], targets
    # the group still does its real job: the host's control page at the root
    assert "home.html" in targets
    # ... and the theme's own template and the plugin's authored index.html
    # are unreachable, at the ROOT and at any depth alike
    assert "wp-content/themes/x/home.html" not in targets
    assert "wp-content/plugins/x/index.html" not in targets


def test_a_bare_core_file_name_behaves_exactly_as_it_did_before_the_door(tmp_path):
    """THE COUNTERPART THAT MUST NOT MOVE: the door's two new rules are
    GROUP rules.  A BARE ``wp-cron.php`` is the operator naming one exact
    file on purpose, and it is basename-matched at any depth, rated by its
    own text, and planned by the plan as before — the door does not touch
    it, and neither the core-junk exemption nor the plan's guard is changed
    here.  Pinned on both halves, so a later "let the door refuse bare
    patterns too" (which would be a different decision, taken deliberately)
    cannot arrive as a side effect of a group fix.

    Deliberately built with ``replace``: the door refuses this shape when it
    arrives as ``<group>:wp-cron.php``, and the point of the test is the
    bare half."""
    settings = replace(Settings(), webroot_junk=["wp-cron.php"])
    findings = check_webroot_junk(
        audit_data([E("wp-cron.php", 12)]), settings)
    assert [(f.name, f.risk, f.count, f.bytes) for f in findings] == [
        ("wp-cron.php", "low", 1, 12),
    ]
    assert findings[0].fix == "Safe to delete; not referenced at runtime."

    # ... and the plan still carries it, exactly as it did before the door
    # grew the group rules
    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("wp-includes/version.php", b"<?php\n$wp_version = '7.1';\n")
        zf.writestr("wp-cron.php", b"<?php // core\n")
    _seed_checksums("7.1", CORE_CHECKSUMS)
    ctx = Ctx(
        source="local", settings=settings, command="clean-files",
        backup_dir=tmp_path / "backup", zip=zpath,
        wp_url="https://example.com",
    )
    source = ZipSource(zpath)
    try:
        plan = CleanFilesAction().plan(ctx, (source, None, None))
    finally:
        source.close()
    assert [item.target for item in plan.items] == ["wp-cron.php"]


def test_the_group_name_set_and_the_wording_table_agree():
    """The door asks "is this a group I have WORDING for?" before it refuses
    a glob, so the NAME set (settings, where the door lives) and the
    WORDING table (this module) are two views of one list.  A group added to
    one and not the other is a group whose patterns are either unvalidated
    or unmatched — so the two are pinned to each other here."""
    assert set(webroot._JUNK_GROUPS) == set(JUNK_GROUP_NAMES)
    assert len(webroot._JUNK_GROUPS) == 3


def test_junk_group_never_fetches_for_a_core_exemption():
    """A group match is at the webroot root, so it is structurally never a
    core-dir match: the shipped groups perform NO wp.org fetch, and they
    also consume no served-path probe (the group's wording states the
    exposure in its own words — :func:`_group_fix` says why reusing the
    dump/log-shaped served lead-in here would print the wrong mitigation).

    A bare pattern in the same tree still probes exactly as before, so
    this pins the exclusion as a group property and not a global one."""
    session = FakeSession([FakeResponse(404)])
    d = audit_data(
        [E(path, size) for path, size in _HOST_CONTROL_FILES] + [E("readme.html", 9)],
        wp_version="7.1",
        mode="ftp",
        probe=SiteProbe(session=session, site="https://example.com",
                        timeout_s=7, bridge=None),
    )
    findings = {f.name: f for f in check_webroot_junk(d, DEFAULTS)}
    assert set(findings) == {
        "host_placeholder_page", "host_account_quota",
        "superseded_htaccess", "readme.html",
    }
    assert [url for url, _kw in session.gets] == [
        "https://example.com/readme.html",
    ]


def test_junk_group_fix_never_contradicts_its_unproven_detail():
    """[D2, for groups] a profile MAY declare a grouped pattern WITH a
    path, and then the [D2] invariant has to hold for it too: the detail
    that says "Do not delete these on this evidence" can never be paired
    with a fix that says "Safe to delete".

    The pattern here carries a path, which the profile door now REFUSES for
    a known group (``_load_webroot_junk`` — the root-scoping it enforces).
    It is built with ``replace`` on purpose: the D2 pairing is the CHECK's
    invariant over whatever it is handed, and a check that only held it for
    root filenames would be one edit away from holding it for none.
    """
    settings = replace(Settings(), webroot_junk=[
        "host_placeholder_page:wp-includes/home.html",
    ])
    d = audit_data([E("wp-includes/home.html", 5)])  # no wp_version
    findings = check_webroot_junk(d, settings)
    assert len(findings) == 1
    finding = findings[0]
    assert "unproven core basis" in finding.detail
    assert "Do not delete these on this evidence" in finding.detail
    assert finding.fix == webroot._JUNK_UNPROVEN_FIX
    assert "Safe to delete" not in finding.fix
    assert "Delete it" not in finding.fix


# ------------------------------- webroot.junk official-core exemption


def test_junk_exempts_official_core_files(wpt_records):
    # The live two-site migration defect: license.txt/readme.html patterns
    # matched OFFICIAL core files, clean-files deleted them, core.integrity
    # reported them missing, heal-core restored them — the finding set
    # never resolved.  The exemption drops exactly the core-dir map paths.
    _seed_checksums("7.1", CORE_CHECKSUMS)
    d = audit_data([
        E("readme.html", 100),                      # map member, TOP LEVEL
        E("license.txt", 50),                       # map member, TOP LEVEL
        E("wp-config-sample.php", 400),             # map member, TOP LEVEL
        E("wp-content/stray.sql", 30),
        E("wp-includes/ID3/license.txt", 7),        # official: EXEMPT
        E("wp-includes/images/crystal/license.txt", 9),  # official: EXEMPT
        E("wp-includes/js/jquery/license.txt", 11),  # official: EXEMPT
        E("wp-includes/error_log", 10),  # core dir but NOT official: junk
    ], wp_version="7.1")
    findings = check_webroot_junk(d, DEFAULTS)
    got = {f.name: (f.count, f.bytes) for f in findings}
    assert got["license.txt"] == (1, 50)       # only the top-level copy
    assert got["readme.html"] == (1, 100)      # top-level stays deletable
    assert got["wp-config-sample.php"] == (1, 400)
    assert got["*.sql"] == (1, 30)
    assert got["error_log"] == (1, 10)         # not in the map: still junk
    by_name = {f.name: f for f in findings}
    assert by_name["license.txt"].detail == "license.txt"
    for f in findings:
        f.validate()
    # one info line names the exempted official files
    infos = [
        r.getMessage() for r in _webroot_records(wpt_records)
        if r.levelno == logging.INFO
    ]
    assert any(
        "wp-includes/ID3/license.txt" in m
        and "wp-includes/images/crystal/license.txt" in m
        and "wp-includes/js/jquery/license.txt" in m
        and "exempt" in m
        for m in infos
    )


def test_junk_without_version_reports_core_dir_matches_as_unproven(
    wpt_records,
):
    """[D1] UNKNOWN version = the exemption cannot be applied, and the
    live delete defect was exactly this: the version lookup came back
    empty, the refusal was a DEBUG line, and the run deleted official core
    files (``wp core verify-checksums`` failed afterwards on all five
    ``wp-includes/**/license.txt`` members).  The DELETE PLAN therefore
    stays fail-closed — and the CHECK no longer inherits that silence:
    the reporting half exempts only what the map PROVED, so a core-dir
    match is still reported, with the detail naming the unproven basis
    (proved by A/B on a real webroot: with wp.org reachable the finding
    appears; offline the same tree reported nothing at all and exited 0,
    so a large ``wp-includes/error_log`` served at HTTP 200 — the
    disclosure this check exists for — was invisible).  The non-core junk
    is untouched by any of this, and the refusal is a WARNING naming
    once."""
    _reset_exemption_latch()
    d = audit_data([
        E("license.txt", 50),
        E("wp-includes/ID3/license.txt", 7),   # core dir: unproven, REPORTED
        E("wp-includes/error_log", 19_193_018),
        E("dump.sql", 12),
    ])  # wp_version None — no exemption basis, never a guess
    findings = check_webroot_junk(d, DEFAULTS)
    got = {f.name: (f.count, f.bytes) for f in findings}
    # the top-level copy is provably junk; the core-dir one is REPORTED
    # too, because the check no longer inherits the plan's fail-closed
    # silence (the plan still refuses to delete it)
    assert got["license.txt"] == (2, 57)
    assert got["*.sql"] == (1, 12)         # outside the core dirs: unaffected
    by_name = {f.name: f for f in findings}
    core = by_name["error_log"]
    assert (core.count, core.bytes) == (1, 19_193_018)
    assert "wp-includes/ID3/license.txt" in by_name["license.txt"].detail
    # ... with the basis named as unproven, and the delete plan's refusal
    # stated so nobody acts on "Safe to delete" alone
    for f in (core, by_name["license.txt"]):
        assert "unproven core basis" in f.detail
        assert "could not be read from wp-includes/version.php" in f.detail
        assert "official wp.org checksums" in f.detail
        assert "the delete plan (wpt clean-files) will not touch" in f.detail
        f.validate()
    # a top-level-only finding has no basis in question: no clause
    assert "unproven core basis" not in by_name["*.sql"].detail
    warnings = [
        r.getMessage() for r in _webroot_records(wpt_records)
        if r.levelno == logging.WARNING
    ]
    assert len(warnings) == 1
    assert "could NOT be applied" in warnings[0]
    assert "wp-includes/version.php" in warnings[0]
    # the CHECK's warning promises the reporting, not the deletion
    assert "REPORTED with the basis named as unproven" in warnings[0]


def test_junk_unproven_detail_is_only_on_patterns_that_matched_a_core_path(
    wpt_records,
):
    """The clause is per pattern, not per run: a finding whose matches
    are all outside the core dirs says nothing about the basis, and one
    that mixes a core-dir match with top-level junk carries the clause
    for the whole pattern (the operator cannot delete half a finding)."""
    _reset_exemption_latch()
    d = audit_data([
        E("dump.sql", 12),                          # outside the core dirs
        E("readme.html", 30),                       # outside, top level
        E("wp-includes/ID3/license.txt", 7),        # inside
    ])
    by_name = {f.name: f for f in check_webroot_junk(d, DEFAULTS)}
    assert "unproven core basis" in by_name["license.txt"].detail
    assert "unproven core basis" not in by_name["*.sql"].detail
    assert "unproven core basis" not in by_name["readme.html"].detail


def test_junk_an_unproven_finding_never_says_safe_to_delete(wpt_records):
    """[D2] THE CONTRADICTION, as a regression test, asserted on BOTH
    fields together: a finding whose detail carries the unproven clause
    ("Do not delete these on this evidence") must not carry a fix that
    says "Safe to delete" or "Delete now".

    The detail is the honest half and the fix is the half an operator
    acts on, so the fix was the dangerous one: it rendered the
    reassuring per-risk text for a file the same finding says wpt cannot
    prove is not official core — and the observed incident was reproduced by
    hand exactly that way (all five official ``wp-includes/**/license.txt``
    members deleted, ``wp core verify-checksums`` failing afterwards).
    Both refusals are covered (an unreadable version and an unreachable
    wp.org), at the LOW risk (a log) and at the HIGH one (a dump), plus
    the served variant where the disclosure leads and the deny rule is the
    only action offered.  Then the A/B half: with the map available the
    reassuring text is back, byte-identically to the pre-D2 rendering.
    """
    # (1) LOW risk, unreadable version.php
    _reset_exemption_latch()
    d = audit_data([
        E("wp-includes/error_log", 19_193_018),
        E("license.txt", 50),
    ])  # wp_version None
    by_name = {f.name: f for f in check_webroot_junk(d, DEFAULTS)}
    unproven = by_name["error_log"]
    assert "unproven core basis" in unproven.detail
    assert "Do not delete these on this evidence" in unproven.detail
    # THE DEFECT, asserted first so a regression names it: the fix said
    # "Safe to delete" in the very finding whose detail says do not delete
    assert "Safe to delete" not in unproven.fix
    assert "Delete now" not in unproven.fix
    assert unproven.fix == webroot._JUNK_UNPROVEN_FIX
    # the fix states the SAME instruction as the detail, and the ONE
    # action that is available without deleting anything
    assert "Do NOT delete these on this evidence" in unproven.fix
    assert "make wp.org reachable and wp-includes/version.php readable" \
        in unproven.fix
    assert "the delete plan (wpt clean-files) will not touch" in unproven.fix
    unproven.validate()
    # a top-level-only finding is not in question: unchanged
    assert "unproven core basis" not in by_name["license.txt"].detail
    assert by_name["license.txt"].fix == (
        "Safe to delete; not referenced at runtime.")

    # (2) HIGH risk (a dump under a core dir), wp.org unreachable instead
    _reset_exemption_latch()
    session = FakeSession([FakeResponse(503, "down"), FakeResponse(404)])
    d = audit_data(
        [E("wp-includes/backup.sql", 4096)],
        wp_version="7.1", mode="ftp",
        probe=SiteProbe(session=session, site="https://example.com",
                        timeout_s=7, bridge=None),
    )
    (high,) = [f for f in check_webroot_junk(d, DEFAULTS)
               if f.name == "*.sql"]
    assert high.risk == "high"
    assert "unproven core basis" in high.detail
    assert "could not be fetched" in high.detail
    assert "Delete now" not in high.fix
    assert "Safe to delete" not in high.fix
    assert high.fix == webroot._JUNK_UNPROVEN_FIX

    # (3) the SERVED variant: the disclosure still leads, and its only
    # action is the deny rule — no delete instruction survives
    _reset_exemption_latch()
    session = FakeSession([
        FakeResponse(503, "down"),          # the wp.org map
        FakeResponse(200, "boom"),          # the site serves error_log
        FakeResponse(404),                  # soft-404 baseline
    ])
    d = audit_data(
        [E("wp-includes/error_log", 19_193_018)],
        wp_version="7.1", mode="ftp",
        probe=SiteProbe(session=session, site="https://example.com",
                        timeout_s=7, bridge=None),
    )
    (served,) = check_webroot_junk(d, DEFAULTS)
    assert "are served publicly at" in served.fix
    assert "18.3 MB" in served.fix
    assert "Delete them AND deny" not in served.fix
    assert "Safe to delete" not in served.fix
    assert "Do not delete them yet — deny the extension in .htaccess" \
        in served.fix
    assert served.fix.endswith(webroot._JUNK_UNPROVEN_FIX)

    # A/B: with the official map the reassuring per-risk text is back
    _reset_exemption_latch()
    online = audit_data([E("wp-includes/error_log", 19_193_018)],
                        wp_version="7.1")
    _seed_checksums("7.1", {
        "wp-includes/version.php": "0" * 32,
        "wp-includes/error_log": "0" * 32,   # a MAP MEMBER: not junk at all
    })
    assert check_webroot_junk(online, DEFAULTS) == []

    _reset_exemption_latch()
    online = audit_data([E("wp-admin/readme.html", 12)],
                        wp_version="7.1")
    _seed_checksums("7.1", {"wp-includes/version.php": "0" * 32})
    (kept,) = check_webroot_junk(online, DEFAULTS)
    assert kept.risk == "low"
    assert kept.fix == "Safe to delete; not referenced at runtime."
    assert "unproven core basis" not in kept.detail


def test_junk_exemption_refusal_is_one_warning_per_consumer_per_run(
    wpt_records, tmp_path,
):
    """ONE line per consumer per RUN, not one per matched file: a tree
    with a hundred core-dir junk matches would otherwise bury the single
    line that says the protection is off.  Driven through the check's own
    predicate three times — still one line.  Then the PLAN (over a real
    zip whose version.php is unreadable) announces its own refusal: the
    old single-slot latch kept only the FIRST reason, so a run that
    audited and then planned said nothing on the path that deletes.  Both
    lines carry the SAME reason for the same condition."""
    _reset_exemption_latch()
    entries = [E(f"wp-includes/dir{index}/license.txt", 7) for index in range(5)]
    for _attempt in range(3):
        pairs = junk_file_matches(entries, ["license.txt"])
        basis = core_junk_basis(pairs, None, FakeSession([]), 5)
        assert basis.unproven == {e.path for e in entries}
        assert junk_matches_reporting(pairs, basis) == pairs  # reported
    # the same tree through the deleting plan: fail-closed, its own line
    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:      # no version.php: unknown
        zf.writestr("readme.html", b"<h1>WordPress</h1>")   # a top-level file
        for entry in entries:                                # keeps it flat
            zf.writestr(entry.path, b"x" * 7)
    source = ZipSource(zpath)
    try:
        plan = CleanFilesAction().plan(
            Ctx(source="local", settings=DEFAULTS, command="clean-files",
                backup_dir=tmp_path / "backup", zip=zpath,
                wp_url="https://example.com"),
            (source, None, None),
        )
    finally:
        source.close()
    assert [item.target for item in plan.items] == ["readme.html"]
    warnings = [
        r.getMessage() for r in _webroot_records(wpt_records)
        if r.levelno == logging.WARNING
    ]
    assert len(warnings) == 2      # one per consumer, not one per match
    assert all("could NOT be applied" in message for message in warnings)
    check, plan_warning = warnings
    assert "(webroot.junk)" in check
    assert "(clean-files)" in plan_warning
    reason = ("the WordPress version could not be read from "
              "wp-includes/version.php")
    assert reason in check and reason in plan_warning   # ONE reason, both
    assert "REPORTED with the basis named as unproven" in check
    assert "left un-planned" in plan_warning


def test_junk_checksums_failure_warns_once_and_reports_core_dir_matches(
    wpt_records
):
    # ftp mode, scripted 503: the map cannot be fetched -> ONE warning and
    # every core-dir match UNPROVEN: never a partial guess from a bad map,
    # never a deletion wpt cannot justify (the plan's half), and never a
    # silent loss of the file from the report (the check's half).
    # script: the wp.org map fetch (503), then the served-path probes for
    # the two surviving junk paths (404 = not public)
    _reset_exemption_latch()
    session = FakeSession([FakeResponse(503, "service down"),
                           FakeResponse(404), FakeResponse(404)])
    d = audit_data(
        [E("license.txt", 50), E("wp-includes/ID3/license.txt", 7)],
        wp_version="7.1",
        mode="ftp",
        probe=SiteProbe(session=session, site="https://example.com",
                        timeout_s=7, bridge=None),
    )
    findings = check_webroot_junk(d, DEFAULTS)
    got = {f.name: (f.count, f.bytes) for f in findings}
    assert got["license.txt"] == (2, 57)   # the top level AND the core dir
    (finding,) = findings
    assert "unproven core basis" in finding.detail
    assert ("the official wp.org checksums for WP 7.1 (en_US) could not be "
            "fetched") in finding.detail
    warnings = [
        r.getMessage() for r in _webroot_records(wpt_records)
        if r.levelno == logging.WARNING
    ]
    assert len(warnings) == 1
    assert "could NOT be applied" in warnings[0]
    assert "7.1" in warnings[0] and "en_US" in warnings[0]
    # exactly ONE wp.org fetch attempt (the served-path probe is the
    # site's own URL, never api.wordpress.org)
    assert [url for url, _kw in session.gets
            if "api.wordpress.org" in url] == [
        integrity._checksums_url("7.1")]
    assert [url for url, _kw in session.gets
            if "example.com" in url] == [
        "https://example.com/license.txt",
        "https://example.com/wp-includes/ID3/license.txt"]



def test_junk_exemption_fetch_is_the_integrity_map_for_this_version(wpt_records):
    """The exemption rides integrity's OWN primitive, so the request (and
    therefore the 1h .wpt-cache key, which is sha256 over the URL) names
    BOTH the version and the locale.  That is what lets a run executing
    core.integrity and webroot.junk share one fetch, and what keeps a
    stale map for another version from exempting anything.  The basis is
    the site's own BUILD locale, resolved by integrity's resolver (an
    en_US build with no `$wp_local_package` marker, so the en_US URL)."""
    _reset_exemption_latch()
    session = FakeSession([
        FakeResponse(200, json.dumps({"checksums": {
            "wp-includes/ID3/license.txt": "5" * 32}})),
        FakeResponse(404),   # the surviving junk path is not served
    ])
    d = audit_data(
        [E("license.txt", 50), E("wp-includes/ID3/license.txt", 7)],
        wp_version="6.6.2",
        mode="ftp",
        probe=SiteProbe(session=session, site="https://example.com",
                        timeout_s=7, bridge=None),
    )
    findings = check_webroot_junk(d, DEFAULTS)
    assert [(f.name, f.count) for f in findings] == [("license.txt", 1)]
    wp_org = [url for url, _kw in session.gets if "api.wordpress.org" in url]
    assert len(wp_org) == 1
    url = wp_org[0]
    assert url == integrity._checksums_url("6.6.2")   # version AND locale
    assert "version=6.6.2" in url and "locale=en_US" in url


def test_junk_exemption_uses_the_sites_own_build_locale_map(wpt_records):
    """[D1] The basis is the BUILD's map, through integrity's OWN locale
    resolver + comparison fetch — never a second locale path of this
    module's own.  A localized build's ``$wp_local_package`` marker makes
    the exemption ask for ``?locale=fr_CA`` (the very URL core.integrity
    and heal-core use, so the 1h cache is shared): only the fr_CA map is
    seeded, and the en_US request is scripted to FAIL, so a regression
    back to the en_US-only basis exempts nothing and the core file is
    reported.  (Measured an observed run: en_US 7.1 and fr_CA 7.1 happen to
    ship byte-identical wp-admin//wp-includes/ members, so the OLD
    en_US-only basis worked for that one build by luck — this pins the
    contract, not the luck.)"""
    _reset_exemption_latch()
    fr_map = dict(CORE_CHECKSUMS)
    fr_map["wp-content/languages/fr_CA.po"] = "8" * 32   # a locale-only member
    _seed_checksums("7.1", fr_map, "fr_CA")
    # The fr_CA map answers from the seeded cache, so the ONLY network
    # request this run may make is the site's own served-path probe; a
    # regression to the en_US-only basis would spend the 503 here and
    # exempt nothing.
    session = FakeSession([FakeResponse(404)])
    d = audit_data(
        [E("license.txt", 50), E("wp-includes/ID3/license.txt", 7)],
        wp_version="7.1",
        mode="ftp",
        locale="fr_CA",
        source=FakeSource(),   # no version.php readable: the site locale fact
        probe=SiteProbe(session=session, site="https://example.com",
                        timeout_s=7, bridge=None),
    )
    findings = check_webroot_junk(d, DEFAULTS)
    assert [(f.name, f.count) for f in findings] == [("license.txt", 1)]
    assert not [url for url, _kw in session.gets
                if "api.wordpress.org" in url]   # served from the fr_CA cache
    assert [url for url, _kw in session.gets] == [
        "https://example.com/license.txt"]
    assert not [
        r for r in _webroot_records(wpt_records) if r.levelno == logging.WARNING
    ]


def test_junk_exemption_locale_falls_back_to_en_US_through_integrity(
    wpt_records,
):
    """The comparison fetch is integrity's, so a build with no map of its
    own degrades to en_US with integrity's ONE warning naming the
    fallback — and the exemption still applies (the en_US map answers).
    A locale the API answers with ``{"checksums": false}`` must not
    exempt nothing."""
    _reset_exemption_latch()
    _seed_checksums("7.1", CORE_CHECKSUMS)          # the en_US fallback
    session = FakeSession([
        FakeResponse(200, json.dumps({"checksums": False})),   # no fr_CA build
        FakeResponse(404),                                    # not served
    ])
    d = audit_data(
        [E("license.txt", 50), E("wp-includes/ID3/license.txt", 7)],
        wp_version="7.1",
        mode="ftp",
        locale="fr_CA",
        source=FakeSource(),
        probe=SiteProbe(session=session, site="https://example.com",
                        timeout_s=7, bridge=None),
    )
    findings = check_webroot_junk(d, DEFAULTS)
    assert [(f.name, f.count) for f in findings] == [("license.txt", 1)]
    # the fr_CA request went to the wire; the en_US fallback came from the
    # seeded cache (one fetch per URL per hour, the shared 1h contract)
    assert [url for url, _kw in session.gets
            if "api.wordpress.org" in url] == [
        integrity._checksums_url("7.1", "fr_CA")]
    messages = [
        r.getMessage() for r in _webroot_records(wpt_records)
        if r.levelno == logging.WARNING
    ]
    assert not [m for m in messages if "could NOT be applied" in m]


def test_junk_no_fetch_without_core_dir_matches():
    # The map fetch is GATED on core-dir candidates existing at all: with
    # no wp.org URL in the recorded traffic, the exemption basis was never
    # requested for this tree (FakeSession fails the test on an
    # unscripted request, so the only scripted answers are the SITE's
    # served-path probes, both 404 = not public).
    session = FakeSession([FakeResponse(404), FakeResponse(404)])
    d = audit_data(
        [E("readme.html", 100), E("wp-content/stray.sql", 30)],
        wp_version="7.1",
        mode="ftp",
        probe=SiteProbe(session=session, site="https://example.com",
                        timeout_s=7, bridge=None),
    )
    findings = check_webroot_junk(d, DEFAULTS)
    assert {f.name for f in findings} == {"readme.html", "*.sql"}
    assert not [url for url, _kw in session.gets
                if "api.wordpress.org" in url]
    assert [url for url, _kw in session.gets] == [
        "https://example.com/readme.html",
        "https://example.com/wp-content/stray.sql",
    ]


# ---------------------------------------------------- webroot.junk_recurring


def test_po_catalogs_under_languages():
    d = audit_data([
        E("wp-content/languages", is_dir=True),
        E("wp-content/languages/admin-default.po", 100),
        E("wp-content/languages/plugins", is_dir=True),
        E("wp-content/languages/plugins/x.po", 40),      # nested: counted
        E("wp-content/languages/themes/y.po", 30),       # nested: counted
        E("wp-content/languages/site.mo", 200),          # runtime format
        E("wp-content/themes/t/languages/foo.po", 10),   # not THE languages dir
        E("wp-content/plugins/languages/bar.po", 10),
        E("readme.po", 5),
    ])
    findings = check_webroot_junk_recurring(d, Settings())  # no pattern settings
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "webroot.junk_recurring"
    assert f.name == "po-catalogs"
    assert f.count == 3
    assert f.bytes == 170
    assert f.risk == "low"
    assert "re-ship" in f.detail
    assert "translation auto-update" in f.detail
    assert "Safe to delete" in f.fix


def test_po_catalogs_silent_without_po():
    d = audit_data([
        E("wp-content/languages/site.mo", 200),
        E("wp-content/languages/admin-default.l10n.php", 50),
    ])
    assert check_webroot_junk_recurring(d, Settings()) == []


# ------------------------------------------------------------ webroot.stale


def test_stale_dirs_under_wp_content():
    d = audit_data([
        E("wp-content", is_dir=True),
        E("wp-content/et_temp", is_dir=True),
        E("wp-content/et_temp/a.txt", 10),
        E("wp-content/et_temp/nested", is_dir=True),
        E("wp-content/et_temp/nested/b.txt", 5),
        E("wp-content/uploads", is_dir=True),
        E("wp-content/uploads/ao_ccss", is_dir=True),
        E("wp-content/uploads/ao_ccss/c.css", 20),
        E("et_temp", is_dir=True),               # root level: NOT under wp-content
        E("et_temp/x.txt", 99),
        E("wp-includes/et_temp", is_dir=True),   # not wp-content either
        E("wp-content/wpo", 15),                 # a FILE named wpo: not a dir
        E("wp-content/uploads/normal", is_dir=True),
    ])
    findings = check_webroot_stale(d, DEFAULTS)
    assert [(f.name, f.count, f.bytes, f.risk) for f in findings] == [
        ("wp-content/et_temp", 2, 15, "low"),           # nested dirs included
        ("wp-content/uploads/ao_ccss", 1, 20, "low"),
    ]
    for f in findings:
        assert f.category == "webroot.stale"
        assert f.fix == "Delete the stale directory."
    assert findings[0].detail == (
        "stale content directory (2 files) left by a removed plugin or theme"
    )


def test_stale_silent_without_dirs_or_patterns():
    quiet = audit_data([E("wp-content/et_temp", is_dir=True),
                        E("wp-content/et_temp/x.txt", 5)])
    assert check_webroot_stale(quiet, Settings()) == []  # empty pattern list
    clean = audit_data([E("wp-content/uploads/normal", is_dir=True)])
    assert check_webroot_stale(clean, DEFAULTS) == []


# -------------------------------------------------------- webroot.migration


def test_migration_matches():
    d = audit_data([
        E("wp-content/plugins", is_dir=True),
        E("wp-content/plugins/all-in-one-wp-migration", is_dir=True),
        E("wp-content/plugins/all-in-one-wp-migration/admin", is_dir=True),
        E("wp-content/plugins/all-in-one-wp-migration/admin/home.php", 100),
        E("wp-content/plugins/all-in-one-wp-migration/data/export.txt", 50),
        E("ai1wm-back-123.zip", 400),
        E("wp-content/uploads", is_dir=True),
        E("wp-content/uploads/ai1wm-backup.zip", 250),   # component match
        E("wp-content/plugins/all-in-one-seo", is_dir=True),  # different plugin
    ])
    findings = check_webroot_migration(d, DEFAULTS)
    # the plugin dir subsumes its descendants: count=1, bytes=whole subtree
    assert [(f.name, f.count, f.bytes, f.risk) for f in findings] == [
        ("ai1wm*", 2, 650, "medium"),
        ("all-in-one-wp-migration", 1, 150, "medium"),
    ]
    by_name = {f.name: f for f in findings}
    assert by_name["all-in-one-wp-migration"].detail == \
        "wp-content/plugins/all-in-one-wp-migration"
    assert by_name["ai1wm*"].detail == \
        "ai1wm-back-123.zip, wp-content/uploads/ai1wm-backup.zip"
    for f in findings:
        assert f.category == "webroot.migration"
        assert "migration" in f.fix


def test_migration_silent_without_leftovers():
    clean = audit_data([
        E("wp-content/plugins/akismet", is_dir=True),
        E("wp-content/uploads/2023/10/a.jpg", 100),
    ])
    assert check_webroot_migration(clean, DEFAULTS) == []
    dirty = audit_data([E("wp-content/uploads/ai1wm-backup.zip", 500)])
    assert check_webroot_migration(dirty, Settings()) == []  # empty pattern list


# ---------------------------------------------------------- plugins.inactive


def test_inactive_units_and_active_semantics():
    d = audit_data([
        E("wp-content/plugins", is_dir=True),
        E("wp-content/plugins/akismet", is_dir=True),
        E("wp-content/plugins/akismet/akismet.php", 60),
        E("wp-content/plugins/akismet/vendor", is_dir=True),
        E("wp-content/plugins/akismet/vendor/lib.php", 40),
        E("wp-content/plugins/old-cache", is_dir=True),
        E("wp-content/plugins/old-cache/old.php", 50),
        E("wp-content/plugins/old-cache/assets", is_dir=True),
        E("wp-content/plugins/old-cache/assets/style.css", 20),
        E("wp-content/plugins/hello.php", 20),
    ], active=["akismet/akismet.php"])
    findings = check_plugins_inactive(d, DEFAULTS)
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "plugins.inactive"
    assert f.name == "inactive-plugins"
    assert f.count == 2                       # old-cache subtree + hello.php
    assert f.bytes == 90                      # (50 + 20) + 20
    assert f.detail == "old-cache (70 B), hello.php (20 B)"
    assert f.risk == "medium"
    assert "inactive" in f.fix


def test_inactive_active_single_file_not_flagged():
    d = audit_data([
        E("wp-content/plugins/hello.php", 20),
        E("wp-content/plugins/akismet", is_dir=True),
        E("wp-content/plugins/akismet/akismet.php", 60),
    ], active=["hello.php", "akismet/akismet.php"])
    assert check_plugins_inactive(d, DEFAULTS) == []


def test_inactive_no_plugins_dir():
    assert check_plugins_inactive(audit_data([E("readme.html", 10)]), DEFAULTS) == []
    empty = audit_data([E("wp-content/plugins", is_dir=True)])
    assert check_plugins_inactive(empty, DEFAULTS) == []


def test_inactive_detail_truncates_at_eight():
    entries = [E("wp-content/plugins", is_dir=True)] + [
        E(f"wp-content/plugins/p{i}.php", i) for i in range(1, 11)
    ]
    findings = check_plugins_inactive(audit_data(entries), DEFAULTS)
    assert len(findings) == 1
    f = findings[0]
    assert f.count == 10
    assert f.bytes == sum(range(1, 11))
    assert f.detail == (
        ", ".join(f"p{i}.php ({i} B)" for i in range(1, 9)) + " (+2 more)"
    )


# --------------------------------------------------------- plugins.duplicate


def test_duplicate_group_two_present():
    d = audit_data([
        E("wp-content/plugins", is_dir=True),
        E("wp-content/plugins/litespeed-cache", is_dir=True),
        E("wp-content/plugins/litespeed-cache/litespeed-cache.php", 70),
        E("wp-content/plugins/wp-super-cache", is_dir=True),
        E("wp-content/plugins/wp-super-cache/wp-super-cache.php", 80),
        E("wp-content/plugins/elementor", is_dir=True),       # 1-member group
        E("wp-content/plugins/elementor/elementor.php", 90),
    ], active=["litespeed-cache/litespeed-cache.php"])
    findings = check_plugins_duplicate(d, DEFAULTS)
    assert len(findings) == 1  # the elementor group stays silent
    f = findings[0]
    assert f.category == "plugins.duplicate"
    assert f.name == "litespeed-cache/wp-super-cache/w3-total-cache"  # whole group
    assert f.count == 2
    # [D1] no evidence at all -> "Keep one" decides nothing about which,
    # so no member's bytes are claimed (the report's reclaimable total
    # must not carry a group the finding cannot act on)
    assert f.bytes == 0
    assert f.risk == "medium"
    # [D1 follow-up] refusing to CLAIM is not refusing to MENTION: the
    # members' total is still stated, as a DEFERRED figure.
    assert f.detail == (
        "litespeed-cache (active), wp-super-cache (inactive); 150 B across "
        "the present members becomes reclaimable once a keeper is named "
        "(not counted as reclaimable until then)"
    )
    assert f.fix == "Keep one, remove the rest."


def test_duplicate_custom_groups_via_settings():
    settings = replace(
        Settings(),
        duplicate_plugin_groups=[["x-cache", "y-cache"], ["hello.php", "bye.php"]],
    )
    d = audit_data([
        E("wp-content/plugins/x-cache", is_dir=True),
        E("wp-content/plugins/x-cache/x.php", 10),
        E("wp-content/plugins/y-cache", is_dir=True),
        E("wp-content/plugins/y-cache/y.php", 20),
        E("wp-content/plugins/hello.php", 5),   # single-file units count too
        E("wp-content/plugins/bye.php", 6),
    ])
    findings = check_plugins_duplicate(d, settings)
    # [D1] bytes follow the DECISION: with no evidence and no declared
    # preference these groups claim none
    assert [(f.name, f.count, f.bytes) for f in findings] == [
        ("hello.php/bye.php", 2, 0),
        ("x-cache/y-cache", 2, 0),
    ]
    assert findings[0].detail.startswith("hello.php (inactive), bye.php (inactive)")
    assert findings[0].detail.endswith(
        "11 B across the present members becomes reclaimable once a keeper "
        "is named (not counted as reclaimable until then)"
    )


def test_duplicate_silent_without_groups():
    present = audit_data([
        E("wp-content/plugins/litespeed-cache", is_dir=True),
        E("wp-content/plugins/wp-super-cache", is_dir=True),
    ])
    assert check_plugins_duplicate(present, Settings()) == []  # no groups
    single = audit_data([E("wp-content/plugins/elementor", is_dir=True)])
    assert check_plugins_duplicate(single, DEFAULTS) == []     # 1 member only


# ------------------------------- plugins.duplicate: content evidence [L17]


def _builders(content: dict[str, int]):
    """Two active page builders, both units present, with content counts.

    An observed migration's decision: both a page builder and its companion
    plugin active at once (a large measured total), and the operator had to
    query the database by hand to
    learn which one actually held the pages.  ``content`` is the gathered
    ``content_meta_posts`` fact (meta-key PREFIX -> distinct posts).
    """
    d = audit_data([
        E("wp-content/plugins", is_dir=True),
        E("wp-content/plugins/elementor", is_dir=True),
        E("wp-content/plugins/elementor/elementor.php", 90),
        E("wp-content/plugins/fusion-builder", is_dir=True),
        E("wp-content/plugins/fusion-builder/fusion-builder.php", 50),
    ], active=["elementor/elementor.php", "fusion-builder/fusion-builder.php"])
    d.content_meta_posts = dict(content)
    return d


def test_duplicate_detail_names_content_evidence_for_both_members():
    """The finding answers "which one do I keep?" for the operator
    instead of leaving it open: per present member it states how many
    DISTINCT posts hold that plugin's content, and NAMES THE SOURCE
    (the postmeta prefixes), so the claim is defensible rather than a
    bare number.  A member with zero content is a deactivation candidate;
    the member WITH content is load-bearing and is the one to keep."""
    d = _builders({"_elementor_": 12, "_fusion": 0})
    (f,) = check_plugins_duplicate(d, DEFAULTS)
    assert f.name == "elementor/fusion-builder"
    assert f.detail == (
        "elementor (active, 12 posts with its content in the database "
        "— postmeta _elementor_), fusion-builder (active, 0 posts with its "
        "content in the database — postmeta _fusion)"
    )
    # the keep is the member that holds content, and the fix names the
    # exact command for the one that does not
    assert f.fix == (
        "Keep elementor — 12 posts in the database carry its content, and "
        "none for fusion-builder (postmeta _fusion). Deactivate: wpt "
        "deactivate-plugin fusion-builder --apply. The wp_options snapshot is "
        "taken first; this is advice only — wpt never deactivates a plugin on "
        "its own."
    )
    # the finding stays ADVICE: nothing was deactivated, and the shape the
    # report/plan contract depends on is unchanged
    assert f.category == "plugins.duplicate" and f.risk == "medium"
    # [D1] bytes = the DEACTIVATION CANDIDATE (fusion-builder alone), never
    # the whole group: the fix names exactly one slug to deactivate, and
    # elementor is the member the fix says to KEEP.
    assert f.count == 2 and f.bytes == 50


def test_duplicate_when_both_builders_hold_content_refuses_to_pick():
    """Two members with content: neither can be dropped blind, so the fix
    must NOT name one as the keeper (that would be a guess the database
    does not support) — and it must not claim the group's bytes either
    [D1].  This is the observed shape: the docroot carried a page builder, its
    companion plugin, and two cache plugins (a large measured total) and
    the content evidence showed BOTH builders holding pages (a builder
    library table, rows, and templates), so the report presented the
    total as reclaimable storage for a decision it had just refused to
    make."""
    (f,) = check_plugins_duplicate(
        _builders({"_elementor_": 10, "_fusion": 4}), DEFAULTS)
    assert "10 posts" in f.detail and "4 posts" in f.detail
    assert f.fix == (
        "Both builders are in use (elementor: 10 posts, fusion-builder: 4 "
        "posts) — this is a decision, not a deletion: choose the one that "
        "keeps the site, then deactivate the other(s). wpt deactivate-plugin "
        "<slug> --apply. No bytes are counted as reclaimable: neither member "
        "can be dropped blind. The wp_options snapshot is taken first; this "
        "is advice only — wpt never deactivates a plugin on its own."
    )
    # [D1] a refusal to decide costs ZERO reclaimable bytes; count still
    # names the members the detail lists
    assert f.bytes == 0 and f.count == 2
    # ... so the report's reclaimable total cannot include this group
    assert AuditReport(
        site="s", source_summary="x", findings=[f]
    ).reclaimable_bytes() == 0
    # [D1 follow-up] ... yet refusing to CLAIM is not refusing to
    # MENTION: the 140 B the two members occupy is still stated, as a
    # DEFERRED figure that names what would make it real.
    assert f.detail.endswith(
        "; 140 B across the present members becomes reclaimable once a "
        "keeper is named (not counted as reclaimable until then)"
    ), f.detail


def test_duplicate_deferred_figure_names_the_size_a_keeper_unlocks(wpt_records):
    """[D1 follow-up] The number a zero reclaimable-bytes would hide stays
    VISIBLE for the campaign ledger, in the detail AND in exactly ONE
    info log line per group — while ``bytes`` stays 0 (the report's
    reclaimable total must not carry a group the finding refuses to act
    on).  The clause is the members' own measured total in human bytes,
    and it is only ever rendered when the decision named NO keeper."""
    (f,) = check_plugins_duplicate(
        _builders({"_elementor_": 10, "_fusion": 4}), DEFAULTS)
    assert f.bytes == 0
    deferred = (
        "140 B across the present members becomes reclaimable once a "
        "keeper is named (not counted as reclaimable until then)"
    )
    assert f.detail.endswith("; " + deferred)
    assert AuditReport(
        site="s", source_summary="x", findings=[f]
    ).reclaimable_bytes() == 0          # still not reclaimable
    infos = [
        r.getMessage() for r in _webroot_records(wpt_records)
        if r.levelno == logging.INFO and "names no keeper" in r.getMessage()
    ]
    assert len(infos) == 1
    assert "elementor/fusion-builder" in infos[0]
    assert deferred in infos[0]


def test_duplicate_exactly_one_holder_is_unchanged_by_the_deferred_figure():
    """The ONE holder is named, so the reclaimable figure IS the
    zero-content members' bytes and the deferred clause has nothing to
    add: this shape renders exactly as it did, in detail and in fix."""
    (f,) = check_plugins_duplicate(
        _builders({"_elementor_": 12, "_fusion": 0}), DEFAULTS)
    assert f.bytes == 50              # the fusion-builder unit, the keeper's not
    assert "once a keeper is named" not in f.detail
    assert "once a keeper is named" not in f.fix
    assert f.fix.startswith("Keep elementor — 12 posts in the database")


def test_duplicate_named_keeper_is_unchanged_by_the_deferred_figure():
    """A DECLARED keeper is a keeper: the finding claims the other
    members' bytes and states no deferred figure, so the two numbers can
    never both appear."""
    d = _builders({"_elementor_": 12, "_fusion": 0})
    (declared,) = check_plugins_duplicate(d, replace(
        DEFAULTS, duplicate_plugin_groups_preferred={
            "elementor/fusion-builder": "elementor"}))
    assert declared.bytes == 50
    assert "once a keeper is named" not in declared.detail
    assert "once a keeper is named" not in declared.fix
    # a declared keeper that is NOT installed leaves nothing to keep:
    # no command, no bytes, and the deferred figure says so out loud
    (missing,) = check_plugins_duplicate(d, replace(
        DEFAULTS, duplicate_plugin_groups_preferred={
            "elementor/fusion-builder": "site-editor-pro"}))
    assert missing.bytes == 0
    assert "wpt deactivate-plugin" not in missing.fix
    assert "140 B across the present members becomes reclaimable once a " \
        "keeper is named" in missing.detail


def test_duplicate_content_evidence_is_never_guessed_from_a_partial_map():
    """A gatherer that answered only SOME of the prefixes leaves the rest
    UNKNOWN: the un-answered member renders as it always did and the fix
    says "confirm before dropping" instead of claiming it holds nothing.
    A partially-answered map can never produce a false "no content"."""
    (f,) = check_plugins_duplicate(_builders({"_elementor_": 10}), DEFAULTS)
    assert "elementor (active, 10 posts" in f.detail
    assert "fusion-builder (active)" in f.detail     # unknown -> today's shape
    assert "confirm before dropping" in f.fix
    # the unknown member is never called empty
    assert "and none for fusion-builder" not in f.fix


def test_duplicate_without_the_fact_keeps_todays_shape(wpt_records):
    """A gather that carries no content counts at all (or no dump facts)
    renders the check exactly as it did before: no content claim, the
    historical one-line fix.  Unknown is never rendered as zero."""
    d = audit_data([
        E("wp-content/plugins/elementor", is_dir=True),
        E("wp-content/plugins/fusion-builder", is_dir=True),
    ], active=["elementor/elementor.php", "fusion-builder/fusion-builder.php"])
    (f,) = check_plugins_duplicate(d, DEFAULTS)
    # this fixture's units carry no measured bytes, so there is no figure
    # to defer and the detail is byte-for-byte the historical one
    assert f.detail == "elementor (active), fusion-builder (active)"
    assert f.fix == "Keep one, remove the rest."
    d.content_meta_posts = None      # the explicit "no facts" answer
    (none_fact,) = check_plugins_duplicate(d, DEFAULTS)
    assert none_fact.detail == f.detail and none_fact.fix == f.fix
    # no content claim and no warning; the ONE deferred info line is the
    # intended new line, not noise.
    assert not [
        r for r in wpt_records
        if r.name == "wpt.audit.webroot" and r.levelno >= logging.WARNING
    ]


def test_duplicate_members_without_declared_content_keys_stay_silent():
    """The cache-plugin group: neither member declares a content meta key
    (a cache plugin stores its state in options/transients), so no content
    claim is made in either direction and the fix stays the generic one."""
    d = audit_data([
        E("wp-content/plugins/litespeed-cache", is_dir=True),
        E("wp-content/plugins/wp-super-cache", is_dir=True),
    ], active=["litespeed-cache/litespeed-cache.php"])
    d.content_meta_posts = {"_elementor_": 5, "_fusion": 5}
    (f,) = check_plugins_duplicate(d, DEFAULTS)
    assert f.detail.startswith(
        "litespeed-cache (active), wp-super-cache (inactive)"
    )
    assert f.fix == "Keep one, remove the rest."


def test_duplicate_preferred_key_changes_only_the_fix():
    """The operator's declared decision turns the finding's fix into the
    exact command — and into NOTHING else: same detail, same counts,
    same risk, same category.  It is honoured with or without evidence,
    and it is still only advice (no deactivation happens)."""
    d = _builders({"_elementor_": 12, "_fusion": 0})
    evidence = check_plugins_duplicate(d, DEFAULTS)[0]
    preferred_settings = replace(
        DEFAULTS,
        duplicate_plugin_groups_preferred={"elementor/fusion-builder":
                                           "elementor"},
    )
    (preferred,) = check_plugins_duplicate(d, preferred_settings)
    assert preferred.detail == evidence.detail
    # [D1] both routes name fusion-builder as the member to drop (once as
    # the zero-content member, once as the declared drop), so they claim
    # the same bytes — and never the kept member's
    assert (preferred.count, preferred.bytes, preferred.risk,
            preferred.category, preferred.name) == (
        evidence.count, evidence.bytes, evidence.risk, evidence.category,
        evidence.name)
    assert preferred.bytes == 50 == evidence.bytes
    assert preferred.fix == (
        "duplicate_plugin_groups_preferred keeps elementor: deactivate "
        "fusion-builder — wpt deactivate-plugin fusion-builder --apply. The "
        "wp_options snapshot is taken first; this is advice only — wpt never "
        "deactivates a plugin on its own."
    )
    # the reverse decision is honoured just as literally
    (flipped,) = check_plugins_duplicate(
        d, replace(preferred_settings,
                   duplicate_plugin_groups_preferred={
                       "elementor/fusion-builder": "fusion-builder"}))
    assert "keeps fusion-builder: deactivate elementor" in flipped.fix
    assert "wpt deactivate-plugin elementor --apply" in flipped.fix
    assert flipped.detail == evidence.detail      # never the evidence's pick


def test_duplicate_preferred_key_works_without_content_evidence():
    """The preference is the operator's own answer, so it applies even
    where the database could not help (a run with no dump facts)."""
    d = audit_data([
        E("wp-content/plugins/elementor", is_dir=True),
        E("wp-content/plugins/fusion-builder", is_dir=True),
    ], active=["elementor/elementor.php", "fusion-builder/fusion-builder.php"])
    (f,) = check_plugins_duplicate(d, replace(
        DEFAULTS, duplicate_plugin_groups_preferred={
            "elementor/fusion-builder": "fusion-builder"}))
    assert f.detail == "elementor (active), fusion-builder (active)"
    assert "wpt deactivate-plugin elementor --apply" in f.fix


def test_duplicate_preferred_slug_that_is_not_installed_names_no_command():
    """A preference for a member the site does not have: there is nothing
    to deactivate, so the fix must not print a command that would fail —
    it names the mismatch and sends the operator to the profile."""
    d = _builders({"_elementor_": 5, "_fusion": 5})
    settings = replace(
        DEFAULTS,
        duplicate_plugin_groups=[*DEFAULTS.duplicate_plugin_groups,
                                 ["elementor", "fusion-builder",
                                  "site-editor-pro"]],
        duplicate_plugin_groups_preferred={
            "elementor/fusion-builder/site-editor-pro": "site-editor-pro"},
    )
    findings = check_plugins_duplicate(d, settings)
    f = next(x for x in findings
             if x.name == "elementor/fusion-builder/site-editor-pro")
    assert f.fix == (
        "duplicate_plugin_groups_preferred keeps site-editor-pro, which is "
        "not installed on this site — there is nothing to deactivate; review "
        "the group against the site."
    )
    assert "wpt deactivate-plugin" not in f.fix


def test_duplicate_group_with_three_present_members_lists_each_command():
    """A three-member group: the fix names every member that must go, and
    the command stays copyable (a placeholder, never "a and b")."""
    d = audit_data([
        E("wp-content/plugins/litespeed-cache", is_dir=True),
        E("wp-content/plugins/wp-super-cache", is_dir=True),
        E("wp-content/plugins/w3-total-cache", is_dir=True),
    ], active=["litespeed-cache/litespeed-cache.php"])
    (f,) = check_plugins_duplicate(d, replace(
        DEFAULTS, duplicate_plugin_groups_preferred={
            "litespeed-cache/wp-super-cache/w3-total-cache": "litespeed-cache"}))
    assert "wpt deactivate-plugin <slug> --apply" in f.fix
    assert "once per slug: wp-super-cache, w3-total-cache" in f.fix
    assert f.count == 3


def test_content_meta_prefixes_are_the_shipped_plugin_facts():
    """The evidence rule itself: a plugin slug -> the postmeta key prefixes
    whose rows prove it holds content.  A builder stores its document
    under its own prefix (Elementor: ``_elementor_data`` and its sibling
    ``_elementor_*`` state; a page builder: ``_fusion*``), so the
    match is on the PREFIX — the same basis the widely used
    builder-meta-cleanup plugin gates its removal on.  A slug with no
    entry is never given a content claim."""
    from wpt.audit.webroot import CONTENT_META_PREFIXES

    assert CONTENT_META_PREFIXES == {
        "elementor": ("_elementor_",),
        "fusion-builder": ("_fusion",),
    }
    # a meta key that merely CONTAINS a prefix is not the plugin's
    assert member_content_posts("elementor", {"_my_elementor_thing": 9}) is None
    # a count for a prefix the slug does not declare is not its evidence
    assert member_content_posts("elementor", {"_fusion": 9}) is None
    assert member_content_posts("elementor", {"_elementor_": 3}) == 3
    assert member_content_posts("litespeed-cache", {"_elementor_": 3}) is None
    assert member_content_posts("elementor", None) is None
    # a negative or non-integer count is not a fact
    for bogus in (-1, "3", True, None):
        assert member_content_posts("elementor", {"_elementor_": bogus}) is None


# ------------------------------------------------------------- plugins.heavy


def test_heavy_present():
    d = audit_data([
        E("wp-content/plugins", is_dir=True),
        E("wp-content/plugins/jetpack", is_dir=True),
        E("wp-content/plugins/jetpack/jetpack.php", 300),
        E("wp-content/plugins/jetpack/mod", is_dir=True),
        E("wp-content/plugins/jetpack/mod/mod.php", 100),
        E("wp-content/plugins/worker", is_dir=True),
        E("wp-content/plugins/worker/worker.php", 200),
    ])
    findings = check_plugins_heavy(d, DEFAULTS)
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "plugins.heavy"
    assert f.name == "known-heavy"
    assert f.count == 2
    assert f.bytes == 600                     # jetpack subtree 400 + worker 200
    assert f.detail == "jetpack, worker"      # settings order
    assert f.risk == "low"
    assert "heavy" in f.fix

def test_heavy_absent():
    d = audit_data([E("wp-content/plugins/akismet", is_dir=True)])
    assert check_plugins_heavy(d, DEFAULTS) == []
    present = audit_data([E("wp-content/plugins/jetpack", is_dir=True)])
    assert check_plugins_heavy(present, Settings()) == []  # empty known_heavy


# ------------------------------------------------------- webroot.mu_plugins


def test_mu_plugins_platform_leftovers_reported():
    d = audit_data([
        E("wp-content/mu-plugins", is_dir=True),
        E("wp-content/mu-plugins/automation-by-installatron.php", 120),
        E("wp-content/mu-plugins/0-worker.php", 80),
        E("wp-content/mu-plugins/custom-tool.php", 60),  # not a platform prefix
        E("wp-content/plugins/worker/worker.php", 10),    # plugins dir, not mu
        E("wp-config.php", 100),
    ])
    findings = check_webroot_mu_plugins(d, DEFAULTS)
    assert len(findings) == 1
    f = findings[0]
    f.validate()
    assert (f.category, f.name) == ("webroot.mu_plugins", "platform-mu-plugins")
    assert f.risk == "low"
    assert f.count == 2
    assert f.bytes == 200
    assert f.detail == (
        "wp-content/mu-plugins/automation-by-installatron.php, "
        "wp-content/mu-plugins/0-worker.php"
    )
    assert "review" in f.fix
    assert "platform" in f.fix


def test_mu_plugins_directory_unit_custom_prefixes():
    settings = replace(Settings(), mu_plugin_known_platform=["my-platform"])
    d = audit_data([
        E("wp-content/mu-plugins", is_dir=True),
        E("wp-content/mu-plugins/my-platform", is_dir=True),
        E("wp-content/mu-plugins/my-platform/loader.php", 40),
        E("wp-content/mu-plugins/my-platform/extra.php", 5),
        E("wp-content/mu-plugins/custom-tool.php", 60),  # other prefixes never match
    ])
    findings = check_webroot_mu_plugins(d, settings)
    assert len(findings) == 1
    f = findings[0]
    assert f.count == 1
    assert f.bytes == 45  # the directory unit subsumes its subtree
    assert f.detail == "wp-content/mu-plugins/my-platform"


def test_mu_plugins_silent_without_platform_matches():
    quiet = audit_data([
        E("wp-content/mu-plugins", is_dir=True),
        E("wp-content/mu-plugins/custom-tool.php", 60),
    ])
    assert check_webroot_mu_plugins(quiet, DEFAULTS) == []
    empty_tree = audit_data([E("wp-config.php", 10)])
    assert check_webroot_mu_plugins(empty_tree, DEFAULTS) == []
    shipped = audit_data([E("wp-content/mu-plugins/0-worker.php", 80)])
    # bare Settings() has no prefixes: nothing is flagged — the list is
    # data (the profile), never code literals
    assert check_webroot_mu_plugins(shipped, Settings()) == []


def test_mu_plugin_platform_prefixes_shipped_in_profile():
    # The settings field + the profile key are wired: the prefixes ship in
    # wpt/data/profiles/default.json, load() surfaces them, and --set can
    # replace the whole list (the _TOP_LEVEL_LISTS string-list contract).
    assert load().mu_plugin_known_platform == [
        "automation-by-installatron",
        "0-worker",
    ]
    overridden = load(overrides={"mu_plugin_known_platform": ["x-platform"]})
    assert overridden.mu_plugin_known_platform == ["x-platform"]


# -------------------------------------------------------- db.active_missing


def test_active_missing_plugins_fires():
    # The live two-site migration shape: the dump's active_plugins names
    # plugins whose directories the export zip never carried.
    d = audit_data([
        E("wp-content/plugins", is_dir=True),
        E("wp-content/plugins/akismet", is_dir=True),
        E("wp-content/plugins/akismet/akismet.php", 60),
    ], active=[
        "akismet/akismet.php",
        "fusion-builder/fusion-builder.php",
        "litespeed-cache/litespeed-cache.php",
    ])
    findings = check_db_active_missing(d, DEFAULTS)
    assert len(findings) == 1
    f = findings[0]
    f.validate()
    assert (f.category, f.name) == ("db.active_missing", "active-missing-plugins")
    assert f.risk == "high"
    assert f.count == 2
    assert f.bytes == 0  # the files are GONE — nothing is reclaimable
    assert f.detail == "fusion-builder, litespeed-cache"  # sorted slugs
    assert f.fix == (
        "restore the missing plugin directories from a complete export "
        "or reinstall them; a site with active-but-missing plugins "
        "will fatal or silently lose functionality"
    )


def test_active_missing_silent_when_tree_complete():
    d = audit_data([
        E("wp-content/plugins", is_dir=True),
        E("wp-content/plugins/akismet", is_dir=True),
        E("wp-content/plugins/akismet/akismet.php", 60),
        E("wp-content/plugins/hello.php", 20),
    ], active=["akismet/akismet.php", "hello.php"])
    assert check_db_active_missing(d, DEFAULTS) == []


def test_active_missing_single_file_plugin():
    d = audit_data(
        [E("wp-content/plugins", is_dir=True)], active=["hello.php"]
    )
    findings = check_db_active_missing(d, DEFAULTS)
    assert len(findings) == 1
    f = findings[0]
    assert f.count == 1
    assert f.detail == "hello.php"  # the unit's whole name, the slug rule


def test_active_missing_installed_but_unlisted_stays_silent():
    # The inverse (installed but not listed) is plugins.inactive's scope —
    # db.active_missing never flags it.
    d = audit_data([
        E("wp-content/plugins", is_dir=True),
        E("wp-content/plugins/ghost-dir", is_dir=True),
        E("wp-content/plugins/ghost-dir/ghost.php", 10),
    ])
    assert check_db_active_missing(d, DEFAULTS) == []


def test_active_missing_mode_agnostic():
    # Both modes normalize active_plugins into AuditData (the analyzer
    # locally, the bridge remotely) — the check is mode-blind.
    entries = [
        E("wp-content/plugins", is_dir=True),
        E("wp-content/plugins/akismet", is_dir=True),
        E("wp-content/plugins/akismet/akismet.php", 60),
    ]
    active = ["fusion-builder/fusion-builder.php", "akismet/akismet.php"]
    for mode in ("ftp", "local"):
        findings = run_checks(
            audit_data(entries, active=active, mode=mode),
            DEFAULTS, mode, ["db.active_missing"], None,
        )
        assert [
            (f.category, f.name, f.detail, f.risk) for f in findings
        ] == [
            ("db.active_missing", "active-missing-plugins",
             "fusion-builder", "high")
        ]


def test_active_missing_detail_truncates_at_eight():
    slugs = [f"p{i}" for i in range(10)]
    d = audit_data(
        [E("wp-content/plugins", is_dir=True)],
        active=[f"{slug}/{slug}.php" for slug in slugs],
    )
    f = check_db_active_missing(d, DEFAULTS)[0]
    assert f.count == 10
    assert f.detail == ", ".join(slugs[:8]) + " (+2 more)"


# --------------------------------- db.active_missing: the unit survived case


def test_active_entry_missing_but_unit_present_is_reported():
    """An observed plugin shape: the plugin's DIRECTORY survived the
    migration (many orphan ``vendor/*.php`` still served and executed) and
    its MAIN FILE did not.  The check used to be blind to it — the UNIT
    was present, so it reported nothing while ``wpt reconcile-plugins``
    (which reads get_plugins(), i.e. the main file) caught it in one item.

    ``get_plugins()`` only ever offers a loader ``wp-content/plugins/
    <slug>/*.php`` — one level into the unit, never a nested vendor/ or
    lib/ subtree — so no loadable entry file here means WordPress has no
    plugin file to load for this entry at all.
    """
    d = audit_data([
        E("wp-content/plugins", is_dir=True),
        E("wp-content/plugins/updraftplus", is_dir=True),
        E("wp-content/plugins/updraftplus/vendor/autoload.php", 40),
        E("wp-content/plugins/updraftplus/vendor/composer/x.php", 20),
        E("wp-content/plugins/akismet", is_dir=True),
        E("wp-content/plugins/akismet/akismet.php", 60),
    ], active=["updraftplus/updraftplus.php", "akismet/akismet.php"])
    findings = check_db_active_missing(d, DEFAULTS)
    assert len(findings) == 1
    f = findings[0]
    f.validate()
    assert (f.category, f.name) == ("db.active_missing",
                                    "active-plugin-entry-missing")
    assert f.risk == "high"
    assert f.count == 1
    # the detail names the webroot path whose file is GONE — the operator
    # needs the file, not the slug
    assert f.detail == "wp-content/plugins/updraftplus/updraftplus.php"
    assert "reconcile-plugins" in f.fix          # the authoritative answer
    assert "cannot confirm" in f.fix
    # the limit is stated, not hidden: a tree walk cannot judge a plugin
    # HEADER, which is the bridge's (reconcile-plugins') job
    assert "header" in f.fix


def test_active_entry_missing_and_unit_absent_are_separate_findings():
    """Both shapes in ONE tree, each its own aggregate finding: a
    directory-less unit is the migration zip, a present-but-entryless unit
    is the live one, and the operator must be able to tell them apart."""
    d = audit_data([
        E("wp-content/plugins", is_dir=True),
        E("wp-content/plugins/updraftplus", is_dir=True),
        E("wp-content/plugins/updraftplus/vendor/autoload.php", 40),
    ], active=["updraftplus/updraftplus.php", "fusion-builder/fusion-builder.php"])
    findings = check_db_active_missing(d, DEFAULTS)
    assert [(f.name, f.detail, f.count) for f in findings] == [
        ("active-missing-plugins", "fusion-builder", 1),
        ("active-plugin-entry-missing",
         "wp-content/plugins/updraftplus/updraftplus.php", 1),
    ]
    assert all(f.bytes == 0 and f.risk == "high" for f in findings)


def test_active_entry_present_stays_silent():
    """The unit present AND holding a direct .php child is a healthy
    plugin: nothing is reported (the fix must not fire on every site)."""
    d = audit_data([
        E("wp-content/plugins", is_dir=True),
        E("wp-content/plugins/akismet", is_dir=True),
        # a DIFFERENT direct .php than the one active_plugins names, plus a
        # nested vendor/: the unit is loadable, so there is nothing to say
        E("wp-content/plugins/akismet/akismet.php", 60),
        E("wp-content/plugins/akismet/vendor/lib.php", 10),
        E("wp-content/plugins/hello.php", 20),
    ], active=["akismet/akismet.php", "hello.php"])
    assert check_db_active_missing(d, DEFAULTS) == []


def test_active_non_php_unit_is_reported():
    """A unit that survived as a non-PHP shell (assets, a JSON manifest,
    a leftover ``readme.txt``) is not a plugin WordPress can load either:
    the same finding, with the same honest limit."""
    d = audit_data([
        E("wp-content/plugins", is_dir=True),
        E("wp-content/plugins/woocommerce", is_dir=True),
        E("wp-content/plugins/woocommerce/readme.txt", 900),
        E("wp-content/plugins/woocommerce/assets/app.js", 1200),
    ], active=["woocommerce/woocommerce.php"])
    findings = check_db_active_missing(d, DEFAULTS)
    assert [(f.name, f.detail) for f in findings] == [
        ("active-plugin-entry-missing",
         "wp-content/plugins/woocommerce/woocommerce.php")]


def test_active_mu_plugin_entry_is_skipped_by_the_entry_rule():
    """An entry that cannot name a plugin unit is a DB artifact, not a
    finding — the mu-plugin loader case included, in BOTH shapes."""
    d = audit_data([
        E("wp-content/plugins", is_dir=True),
        E("wp-content/plugins/akismet", is_dir=True),
        E("wp-content/plugins/akismet/akismet.php", 60),
        E("wp-content/mu-plugins", is_dir=True),
        E("wp-content/mu-plugins/loader.php", 30),
    ], active=["akismet/akismet.php", "wp-content/mu-plugins/loader.php",
               "/wp-content/plugins/akismet/akismet.php"])
    assert check_db_active_missing(d, DEFAULTS) == []


# ------------------------ clean-files plan follows the check's exemption


def test_clean_files_plan_exempts_core_license_file(tmp_path):
    """The ACTION's plan must follow the check's exemption (the live
    defect's fight: clean-files deleted official core license.txt files,
    heal-core restored them).  Local mode, a real ZipSource over a
    fixture zip carrying wp-includes/version.php plus the official
    wp-includes/ID3/license.txt: the seeded checksum map exempts the
    core file; the top-level junk stays planned."""
    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("wp-includes/version.php", b"<?php\n$wp_version = '7.1';\n")
        zf.writestr("wp-includes/ID3/license.txt", b"WordPress is free software\n")
        zf.writestr("readme.html", b"<h1>WordPress</h1>")
        zf.writestr("wp-content/stray.sql", b"DROP TABLE x;")
        zf.writestr("wp-config.php", b"<?php // config")
    _seed_checksums("7.1", CORE_CHECKSUMS)
    ctx = Ctx(
        source="local", settings=DEFAULTS, command="clean-files",
        backup_dir=tmp_path / "backup", zip=zpath,
        wp_url="https://example.com",
    )
    source = ZipSource(zpath)
    try:
        plan = CleanFilesAction().plan(ctx, (source, None, None))
    finally:
        source.close()
    targets = [item.target for item in plan.items]
    assert "wp-includes/ID3/license.txt" not in targets  # official: exempt
    assert targets == ["readme.html", "wp-content/stray.sql"]


def test_clean_files_plan_leaves_core_dir_junk_alone_without_a_version(
    tmp_path, wpt_records
):
    """[D1] THE LIVE DEFECT, as a regression test.  A ``clean-files
    --apply`` on a localized site deleted all five official
    core ``license.txt`` members and left ``wp core verify-checksums``
    failing: the plan's version lookup came back empty, the exemption
    refused, and the refusal was a DEBUG line — so the plan degraded to
    "exempt nothing" and deleted core files.  Reproduced here with a real
    zip whose version.php is unreadable: the core-dir match is NOT
    planned (wpt cannot prove it is not official core), the non-core junk
    still is, and the refusal is a WARNING naming the cause."""
    _reset_exemption_latch()
    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        # no wp-includes/version.php at all: the version is UNKNOWN
        zf.writestr("wp-includes/ID3/license.txt", b"WordPress is free\n")
        zf.writestr("wp-content/plugins/elementor/license.txt", b"vendor\n")
        zf.writestr("readme.html", b"<h1>WordPress</h1>")
    _seed_checksums("7.1", CORE_CHECKSUMS)   # the map is right there…
    ctx = Ctx(
        source="local", settings=DEFAULTS, command="clean-files",
        backup_dir=tmp_path / "backup", zip=zpath,
        wp_url="https://example.com",
    )
    source = ZipSource(zpath)
    try:
        plan = CleanFilesAction().plan(ctx, (source, None, None))
    finally:
        source.close()
    targets = [item.target for item in plan.items]
    assert "wp-includes/ID3/license.txt" not in targets      # NOT deleted
    assert "wp-content/plugins/elementor/license.txt" in targets  # not core: junk
    assert targets == ["readme.html", "wp-content/plugins/elementor/license.txt"]
    warnings = [
        r.getMessage() for r in _webroot_records(wpt_records)
        if r.levelno == logging.WARNING
    ]
    assert len(warnings) == 1
    assert "could NOT be applied" in warnings[0]


def test_clean_files_rehearsal_keeps_the_core_license_and_removes_the_content_one(
    tmp_path,
):
    """The END-TO-END rehearsal of the same requirement: over a real zip
    carrying a core ``wp-includes/ID3/license.txt`` AND a non-core
    ``wp-content/plugins/<unit>/license.txt``, the rehearsed twin keeps
    the core file byte-identical and loses only the content one — the
    local rehearsal of what a live --apply would have done."""
    _reset_exemption_latch()
    zpath = tmp_path / "site.zip"
    core = b"WordPress is free software\n"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("wp-includes/version.php", b"<?php\n$wp_version = '7.1';\n")
        zf.writestr("wp-includes/ID3/license.txt", core)
        zf.writestr("wp-content/plugins/elementor/license.txt", b"vendor\n")
        zf.writestr("wp-config.php", b"<?php // config")
    _seed_checksums("7.1", CORE_CHECKSUMS)
    rc = run_action(
        Ctx(
            source="local", settings=DEFAULTS, command="clean-files",
            apply=True, yes=True, backup_dir=tmp_path / "backup", zip=zpath,
            wp_url="https://example.com",
        ),
        "clean-files",
    )
    assert rc == 0
    rehearsed = sorted(tmp_path.glob("site-rehearsed-*.zip"))
    assert len(rehearsed) == 1
    with zipfile.ZipFile(rehearsed[0]) as zf:
        names = zf.namelist()
        assert "wp-includes/ID3/license.txt" in names        # official: kept
        assert "wp-content/plugins/elementor/license.txt" not in names
        assert zf.read("wp-includes/ID3/license.txt") == core  # byte-identical
    with zipfile.ZipFile(zpath) as zf:      # the original IS the rollback
        assert "wp-includes/ID3/license.txt" in zf.namelist()


# ------------------------------------------------------ registry integration


CHECK_NAMES = [
    "db.active_missing",
    "plugins.duplicate", "plugins.heavy", "plugins.inactive",
    "webroot.junk", "webroot.junk_recurring", "webroot.migration",
    "webroot.mu_plugins", "webroot.stale",
]


def test_registry_contains_all_nine():
    checks = {rec.name: rec for rec in all_checks()}
    for name in CHECK_NAMES:
        assert name in checks, name
        assert checks[name].applies == ("ftp", "local")


def test_select_groups_selectable():
    assert [rec.name for rec in select_checks("ftp", ["webroot"], None)] == [
        "webroot.junk", "webroot.junk_recurring", "webroot.migration",
        "webroot.mu_plugins", "webroot.stale",
    ]
    assert [rec.name for rec in select_checks("local", ["plugins"], None)] == [
        "plugins.duplicate", "plugins.heavy", "plugins.inactive",
    ]


def _rich_site():
    """One realistic site exercising every check once (or twice for junk)."""
    entries = [
        E("readme.html", 100),
        E("dump.sql", 500),
        E("wp-content", is_dir=True),
        E("wp-content/languages", is_dir=True),
        E("wp-content/languages/admin-default.po", 200),
        E("wp-content/languages/site.po", 80),
        E("wp-content/et_temp", is_dir=True),
        E("wp-content/et_temp/cache.txt", 40),
        E("wp-content/et_temp/sub", is_dir=True),
        E("wp-content/et_temp/sub/deep.txt", 10),
        E("wp-content/uploads", is_dir=True),
        E("wp-content/uploads/ai1wm-backup.zip", 900),
        E("wp-content/plugins", is_dir=True),
        E("wp-content/plugins/akismet", is_dir=True),
        E("wp-content/plugins/akismet/akismet.php", 60),
        E("wp-content/plugins/litespeed-cache", is_dir=True),
        E("wp-content/plugins/litespeed-cache/litespeed-cache.php", 70),
        E("wp-content/plugins/wp-super-cache", is_dir=True),
        E("wp-content/plugins/wp-super-cache/wp-super-cache.php", 80),
        E("wp-content/plugins/jetpack", is_dir=True),
        E("wp-content/plugins/jetpack/jetpack.php", 300),
        E("wp-content/plugins/old-cache", is_dir=True),
        E("wp-content/plugins/old-cache/old.php", 50),
        E("wp-content/plugins/hello.php", 20),
    ]
    active = ["akismet/akismet.php", "litespeed-cache/litespeed-cache.php"]
    return entries, active


def test_run_checks_end_to_end():
    entries, active = _rich_site()
    findings = run_checks(
        audit_data(entries, active=active, mode="ftp"),
        DEFAULTS, "ftp", ["webroot", "plugins"], None,
    )
    # every check contributed, in the registry's name-sorted execution order
    assert [f.category for f in findings] == [
        "plugins.duplicate", "plugins.heavy", "plugins.inactive",
        "webroot.junk", "webroot.junk",
        "webroot.junk_recurring", "webroot.migration", "webroot.stale",
    ]
    for f in findings:
        f.validate()
    assert {(f.category, f.name): (f.count, f.bytes, f.risk) for f in findings} == {
        # [D1] the group carries no bytes without a decision
        ("plugins.duplicate", "litespeed-cache/wp-super-cache/w3-total-cache"):
            (2, 0, "medium"),
        ("plugins.heavy", "known-heavy"): (1, 300, "low"),
        ("plugins.inactive", "inactive-plugins"): (4, 450, "medium"),
        ("webroot.junk", "*.sql"): (1, 500, "high"),
        ("webroot.junk", "readme.html"): (1, 100, "low"),
        ("webroot.junk_recurring", "po-catalogs"): (2, 280, "low"),
        ("webroot.migration", "ai1wm*"): (1, 900, "medium"),
        ("webroot.stale", "wp-content/et_temp"): (2, 50, "low"),
    }
    # per-slug bytes for the inactive aggregate, in unit order
    inactive = next(f for f in findings if f.category == "plugins.inactive")
    assert inactive.detail == (
        "wp-super-cache (80 B), jetpack (300 B), old-cache (50 B), hello.php (20 B)"
    )
    duplicate = next(f for f in findings if f.category == "plugins.duplicate")
    assert duplicate.detail.startswith(
        "litespeed-cache (active), wp-super-cache (inactive)"
    )
    assert "across the present members becomes reclaimable once a keeper" \
        in duplicate.detail
    # the checks are mode-agnostic: the same site audits identically offline
    local = run_checks(
        audit_data(entries, active=active, mode="local"),
        DEFAULTS, "local", ["webroot", "plugins"], None,
    )
    assert local == findings


# ------------------------------------ active_plugins entry validity gate


def test_active_plugins_entry_that_cannot_name_a_unit_is_silent():
    """A non-plugin-relative active_plugins value is a DB artifact, not a
    missing plugin.

    WordPress stores the option RELATIVE to the plugins dir and resolves
    every entry that way, so an absolute, webroot-relative or mu-plugins
    path names nothing WordPress loads.  Deriving a slug from it produced
    a HIGH ``db.active_missing`` finding for ``wp-content`` — a directory
    that is not a plugin — and, worse, poisoned the shared active set so
    EVERY real plugin read as inactive too."""
    tree = [
        E("wp-content/plugins", is_dir=True),
        E("wp-content/plugins/akismet", is_dir=True),
        E("wp-content/plugins/akismet/akismet.php", 60),
        E("wp-content/plugins/hello.php", 20),
        E("wp-content/mu-plugins/0-worker.php", 80),
    ]
    for entry in ("wp-content/mu-plugins/0-worker.php",
                  "wp-content/plugins/akismet/akismet.php",
                  "/wp-content/plugins/akismet/akismet.php",
                  "../plugins/akismet/akismet.php",
                  "", "   "):
        # the garbage entry contributes NO active slug...
        assert _active_plugin_slugs(audit_data(tree, active=[entry])) == set()
        assert check_db_active_missing(audit_data(tree, active=[entry]),
                                       DEFAULTS) == [], entry
        # ...and it never displaces a REAL entry beside it: akismet stays
        # active, so the only installed-but-unlisted unit left is
        # hello.php (the gate must not make it look inactive-by-accident).
        mixed = audit_data(tree, active=["akismet/akismet.php", entry])
        assert _active_plugin_slugs(mixed) == {"akismet"}, entry
        assert check_db_active_missing(mixed, DEFAULTS) == [], entry
        assert [f.detail for f in check_plugins_inactive(mixed, DEFAULTS)] == [
            "hello.php (20 B)"
        ], entry
    # Repeated "/" and "." segments are what WordPress's own validate_file
    # normalizes (it rejects only ".." shapes), so these entries DO load the
    # unit.  Treating them as inactive put the live plugin on clean-files'
    # deletion plan.
    for entry in ("./akismet/akismet.php", "akismet//akismet.php",
                  "./akismet//./akismet.php"):
        assert _active_plugin_slugs(audit_data(tree, active=[entry])) == {
            "akismet"}, entry
        assert [f.detail for f in check_plugins_inactive(
            audit_data(tree, active=[entry]), DEFAULTS)] == [
                "hello.php (20 B)"], entry
        assert check_db_active_missing(
            audit_data(tree, active=[entry]), DEFAULTS) == [], entry
    # a plugin-relative entry is still honored, missing or not
    assert [f.detail for f in check_db_active_missing(
        audit_data(tree, active=["akismet/akismet.php", "gone/gone.php"]),
        DEFAULTS)] == ["gone"]
    # a case-mismatched entry IS a true positive: WordPress resolves the
    # path case-sensitively, so the plugin really is not loadable
    assert [f.risk for f in check_db_active_missing(
        audit_data(tree, active=["Akismet/akismet.php"]), DEFAULTS)] == ["high"]


def test_active_plugin_slugs_rule_shared_by_both_checks():
    """ONE owner for the active set: the two checks that consume it agree
    on what an entry means, including the dirless single-file plugin."""
    d = audit_data(
        [E("wp-content/plugins/hello.php", 20)],
        active=["hello.php", "akismet/akismet.php"],
    )
    assert _active_plugin_slugs(d) == {"hello.php", "akismet"}
    assert check_plugins_inactive(d, DEFAULTS) == []  # both installed+active
    assert [f.detail for f in check_db_active_missing(d, DEFAULTS)] == [
        "akismet"  # not in the tree
    ]


# ------------------------------------------------ mu-plugins prefix contract


def test_mu_plugins_prefixes_are_prefixes_not_globs():
    """The profile key is a list of NAME PREFIXES (settings field +
    module docstring), never glob patterns: a user who writes a glob gets
    silence, never a false positive.  Pinned both ways so the semantics
    cannot drift into fnmatch without a failing test."""
    settings = replace(Settings(), mu_plugin_known_platform=["0-"])
    d = audit_data([E("wp-content/mu-plugins/0-worker.php", 80)])
    assert [f.count for f in check_webroot_mu_plugins(d, settings)] == [1]
    glob = replace(Settings(), mu_plugin_known_platform=["0-*"])
    assert check_webroot_mu_plugins(d, glob) == []
    # a prefix match is on the UNIT's own name, not a path prefix: the
    # plugins dir can never contribute, and a nested file cannot either
    nested = audit_data([
        E("wp-content/mu-plugins", is_dir=True),
        E("wp-content/mu-plugins/loader.php", 10),
        E("wp-content/mu-plugins/vendor/0-worker.php", 10),
    ])
    assert check_webroot_mu_plugins(nested, DEFAULTS) == []


# ------------------------- the exemption's degrade path: no version.php


def test_clean_files_plan_without_version_php_keeps_the_core_dir_safe(
    tmp_path, monkeypatch, wpt_records
):
    """A zip with NO wp-includes/version.php: the exemption has no basis,
    so it is never even requested (NO wp.org request at all) and the run
    must not crash on the read.  [D1] The plan is FAIL-CLOSED on that
    basis: the official core license.txt copies are NOT planned any more
    (they were the live deletion), and the refusal is a WARNING."""
    _reset_exemption_latch()
    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("wp-includes/ID3/license.txt", b"WordPress is free\n")
        zf.writestr("readme.html", b"<h1>WordPress</h1>")
    monkeypatch.setattr(
        WpOrgApi, "_request_json",
        lambda *a, **k: pytest.fail("no wp.org request without a version"),
    )
    ctx = Ctx(
        source="local", settings=DEFAULTS, command="clean-files",
        backup_dir=tmp_path / "backup", zip=zpath,
        wp_url="https://example.com",
    )
    source = ZipSource(zpath)
    try:
        plan = CleanFilesAction().plan(ctx, (source, None, None))
    finally:
        source.close()
    assert [item.target for item in plan.items] == ["readme.html"]
    warnings = [
        r.getMessage() for r in _webroot_records(wpt_records)
        if r.levelno == logging.WARNING
    ]
    assert len(warnings) == 1
    assert "could NOT be applied" in warnings[0]


def test_junk_uploads_exempt_only_for_the_dump_family_and_payloads_become_a_finding():
    """[L30] an observed migration: a Gravity Forms .sql export sits under
    uploads/ and the old advice was "Delete now"; a backup archive in the
    webroot is a HIGH exposure finding (park-backups moves it), while a
    log file stays junk UNDER uploads too."""
    from dataclasses import replace
    from wpt.audit.webroot import check_webroot_junk
    from wpt.settings import Settings

    settings = replace(
        Settings(),
        webroot_junk=["*.sql", "error_log", "*.zip"],
        backup_payloads=replace(
            settings_backup := Settings().backup_payloads,
            extensions=("*.zip", "*.tar.gz"),
            directories=("sample-backup",),
        ),
    )
    del settings_backup
    d = audit_data([
        E("wp-content/uploads/gravity_forms/export.sql", 100),   # DATA: exempt
        E("wp-content/uploads/error_log", 20),                   # junk anyway
        E("wp-content/plugins/x/some.zip", 300),                 # in a unit: junk
        E("wp-content/updraft/site.tar.gz", 400),                # PAYLOAD finding
        E("sample-backup/wp-content/plugins/a/b.php", 500),     # PAYLOAD finding
        E("wp-content/dump.sql", 600),                            # junk rule, not a payload
    ])
    got = {f.name: (f.risk, f.count) for f in check_webroot_junk(d, settings)}
    assert got["*.sql"] == ("high", 1)      # only the webroot dump, not the uploads one
    assert got["error_log"] == ("low", 1)
    assert got["*.zip"] == ("low", 1)   # in a plugin unit: still junk (low by the classifier)
    assert got["backup_payload_in_webroot"] == ("high", 2)      # no double-reporting


# --------------------------------- junk that is SERVED is a security fact
# [D3] the live case: a large error_log answered at HTTP 200
# with SQL statements and absolute server paths inside, and the only thing
# the audit said about it was "delete" — true, and silent about the fact
# that anyone could already fetch it.


def _junk_log_site(served_status=200, size=1_048_576, junk=("error_log",),
                   soft404_body=None):
    """An ftp-mode AuditData with one top-level log, plus a scripted
    session answering its served-path probe.  The soft-404 baseline is
    asked for right after the FIRST 200 (a non-200 candidate never needs
    it, so a 404/403/redirect site spends no request on it): by default
    the certainly-missing path answers a real 404, so the 200 candidate is
    still claimed; ``soft404_body`` scripts a host that answers 200 + that
    page for a missing path."""
    answers = [FakeResponse(served_status, "log bytes") for _ in junk]
    if served_status == 200:
        answers.insert(1, FakeResponse(200, soft404_body)
                       if soft404_body else FakeResponse(404))
    session = FakeSession(answers)
    d = audit_data(
        [E("error_log", size)],
        wp_version="7.1", mode="ftp",
        probe=SiteProbe(session=session, site="https://site.test",
                        timeout_s=7, bridge=None),
    )
    return d, session


def test_junk_served_publicly_leads_the_fix_with_the_disclosure():
    d, session = _junk_log_site()
    (f,) = check_webroot_junk(d, DEFAULTS)
    assert f.name == "error_log" and f.risk == "low"
    assert f.bytes == 1_048_576 and f.count == 1   # measured, not guessed
    # the disclosure LEADS (the per-risk advice follows it)
    assert f.fix.startswith(
        "1 of these are served publicly at error_log (HTTP 200) — a 1.0 MB "
        "payload in the document root (largest: error_log) is an information "
        "disclosure, not just clutter: anyone can fetch it, and a log or a "
        "dump carries SQL statements and absolute server paths. Delete them "
        "AND deny the extension in .htaccess ("
    )
    assert r"FilesMatch \.(log|sql|zip|tar\.gz)$ Require all denied" in f.fix
    # the original per-risk advice is still there, after the disclosure
    assert f.fix.endswith("Safe to delete; not referenced at runtime.")
    # exactly the candidate probe and the ONE soft-404 baseline, both
    # against the SITE (never wp.org)
    assert len(session.gets) == 2
    assert session.gets[0] == (
        "https://site.test/error_log", {"allow_redirects": False, "timeout": 7},
    )
    baseline_url, baseline_kw = session.gets[1]
    assert re.fullmatch(
        r"https://site\.test/wpt-probe-[0-9a-f]{8}\.php", baseline_url)
    assert baseline_kw == {"allow_redirects": False, "timeout": 7}


def test_junk_not_served_changes_nothing():
    """404, a redirect (a deny rule already in place), a network failure
    and a high-risk pattern all render exactly as they did before: the
    disclosure is a measured fact, never an assumption."""
    offline = audit_data([E("error_log", 20)], wp_version="7.1", mode="ftp",
                         probe=None)
    assert check_webroot_junk(offline, DEFAULTS)[0].fix == \
        "Safe to delete; not referenced at runtime."
    for status, response in ((404, FakeResponse(404)),
                             (301, FakeResponse(301, "", {"Location": "/x/"})),
                             (403, FakeResponse(403))):
        d, _session = _junk_log_site(served_status=status)
        assert check_webroot_junk(d, DEFAULTS)[0].fix == \
            "Safe to delete; not referenced at runtime."
    d = audit_data(
        [E("error_log", 20)], wp_version="7.1", mode="ftp",
        probe=SiteProbe(session=FakeSession([requests.ConnectionError("down")]),
                        site="https://site.test", timeout_s=7, bridge=None),
    )
    assert check_webroot_junk(d, DEFAULTS)[0].fix == \
        "Safe to delete; not referenced at runtime."
    # a HIGH-risk pattern (a dump) leads the fix with the disclosure and
    # keeps its own "delete now" tail
    d, _session = _junk_log_site(junk=("*.sql",))
    d.entries = [E("dump.sql", 900)]
    (f,) = check_webroot_junk(d, DEFAULTS)
    assert f.fix.startswith("1 of these are served publicly at dump.sql")
    assert f.fix.endswith("Delete now; database dumps and config backups "
                          "must never live in the webroot.")


def test_junk_served_probe_is_capped_at_three_paths():
    """At most three matched paths are probed: a junk-heavy site must not
    spend the run's budget (or the origin's patience) proving a fact the
    report states as a sample."""
    settings = replace(DEFAULTS, webroot_junk=["*.log"])
    entries = [E(f"junk{i}.log", 10) for i in range(1, 6)]
    session = FakeSession([FakeResponse(200, "log bytes"),
                           FakeResponse(404),          # the soft-404 baseline
                           FakeResponse(200, "log bytes"),
                           FakeResponse(200, "log bytes")])
    d = audit_data(entries, wp_version="7.1", mode="ftp",
                   probe=SiteProbe(session=session, site="https://site.test",
                                   timeout_s=7, bridge=None))
    (f,) = check_webroot_junk(d, settings)
    # three candidate paths + the ONE soft-404 baseline
    assert len(session.gets) == 4
    assert f.fix.startswith("3 of these are served publicly at junk1.log, "
                            "junk2.log, junk3.log (HTTP 200)")


def test_junk_served_probe_needs_a_site_url_and_a_deadline():
    """No --wp-url means the runner's probe carries an empty site: no
    request, today's fix.  An expired run budget stops the probe after the
    paths it already proved (the walk's partial-set precedent)."""
    session = FakeSession([FakeResponse(200)])
    d = audit_data([E("error_log", 20)], wp_version="7.1", mode="ftp",
                   probe=SiteProbe(session=session, site="",
                                   timeout_s=7, bridge=None))
    assert check_webroot_junk(d, DEFAULTS)[0].fix == \
        "Safe to delete; not referenced at runtime."
    assert session.gets == []

    from wpt.deadline import Deadline

    session = FakeSession([FakeResponse(200), FakeResponse(200)])
    d = audit_data([E("a.log", 20), E("b.log", 30)], wp_version="7.1",
                   mode="ftp",
                   probe=SiteProbe(session=session, site="https://site.test",
                                   timeout_s=7, bridge=None))
    d.deadline = Deadline(-1)   # already expired
    (f,) = check_webroot_junk(d, replace(DEFAULTS, webroot_junk=["*.log"]))
    assert session.gets == []    # nothing asked, so nothing claimed
    assert f.fix == "Safe to delete; not referenced at runtime."


def test_backup_payload_finding_also_leds_with_the_disclosure():
    """A backup archive in the document root gets the same served
    disclosure ahead of the park-backups advice — the exposure is the
    reachability, and the payload finding is where that is said."""
    session = FakeSession([FakeResponse(200, "archive"), FakeResponse(404)])
    d = audit_data(
        [E("wp-content/updraft/site.tar.gz", 4096)], wp_version="7.1",
        mode="ftp",
        probe=SiteProbe(session=session, site="https://site.test",
                        timeout_s=7, bridge=None),
    )
    (f,) = check_webroot_junk(d, DEFAULTS)
    assert f.name == "backup_payload_in_webroot"
    assert f.fix.startswith(
        "1 of these are served publicly at wp-content/updraft/site.tar.gz "
        "(HTTP 200)"
    )
    assert f.fix.endswith("never delete the operator's backups.")
    # the request path for the nested archive is intact, slash included
    assert session.gets[0][0] == \
        "https://site.test/wp-content/updraft/site.tar.gz"


def test_an_unmeasured_active_set_never_calls_every_plugin_inactive():
    """[L53] an options-table identity that is absent or CONTESTED (or an
    active_plugins value that is not a readable list) leaves the active set
    UNMEASURED; reporting every installed plugin as inactive is a guess in
    the dangerous direction, so both plugin findings degrade and say so."""
    from dataclasses import replace
    from wpt.audit.webroot import (check_db_active_missing,
                                   check_plugins_inactive)
    d = audit_data([
        E("wp-content/plugins", is_dir=True),
        E("wp-content/plugins/akismet", is_dir=True),
        E("wp-content/plugins/akismet/akismet.php", 60),
        E("wp-content/plugins/old-cache", is_dir=True),
        E("wp-content/plugins/old-cache/old.php", 50),
    ], active=["akismet/akismet.php"])
    d = replace(d, active_plugins=None)
    inactive = check_plugins_inactive(d, load())
    assert [f.name for f in inactive] == ["active-set-unknown"]
    assert inactive[0].risk == "low"
    missing = check_db_active_missing(d, load())
    assert [f.name for f in missing] == ["active-set-unknown"]

    # a MEASURED empty set is a real answer: the units really are inactive
    d2 = replace(audit_data([
        E("wp-content/plugins", is_dir=True),
        E("wp-content/plugins/foo", is_dir=True),
        E("wp-content/plugins/foo/foo.php", 50),
    ]), active_plugins=[])
    assert [f.name for f in check_plugins_inactive(d2, load())] == \
        ["inactive-plugins"]
    assert check_db_active_missing(d2, load()) == []


def test_the_unmeasured_active_set_markers_suggest_nothing_and_count_nothing():
    """THE PERSISTED-REPORT CONTRACT for the unmeasured active set.

    Measured on a contested-identity dump: the report carried
    ``plugins.inactive / active-set-unknown`` whose fix claimed "Nothing is
    deletable on this evidence" while the SAME run's clean-files plan held 8
    deletions, and its Suggested next steps named ``wpt deactivate-plugin
    <slug>`` and ``wpt reconcile-plugins --apply`` — both of which REFUSE
    in local mode, the only mode that produces these markers.  A reader of
    the report was sent to two refusals over a run that could act, and told
    the whole run was inert when it was not.

    Three halves, each the codebase's existing rule (``media.unmeasurable``
    in wpt/audit/media.py is the precedent): a category of its OWN, so no
    suggested-step rule can match; ``count=0``, so no total counts a
    measurement nobody made; and a fix text scoped to the ACTIVE SET.  The
    CONTROL is an observed run, which still produces the ordinary
    ``plugins.inactive`` finding under its own category.
    """
    from dataclasses import replace
    from wpt.audit.webroot import (ACTIVE_SET_UNKNOWN_NAME,
                                   DB_ACTIVE_SET_UNKNOWN_CATEGORY,
                                   PLUGINS_ACTIVE_SET_UNKNOWN_CATEGORY,
                                   check_db_active_missing,
                                   check_plugins_inactive)
    from wpt.report import suggested_step_for, suggested_steps

    d = replace(audit_data([
        E("wp-content/plugins", is_dir=True),
        E("wp-content/plugins/akismet", is_dir=True),
        E("wp-content/plugins/akismet/akismet.php", 60),
        E("wp-content/plugins/old-cache", is_dir=True),
        E("wp-content/plugins/old-cache/old.php", 50),
    ]), active_plugins=None)
    markers = check_plugins_inactive(d, load()) + check_db_active_missing(
        d, load())
    assert sorted(f.category for f in markers) == sorted([
        PLUGINS_ACTIVE_SET_UNKNOWN_CATEGORY, DB_ACTIVE_SET_UNKNOWN_CATEGORY,
    ])
    for marker in markers:
        # the category is of its own -> no rule matches, so NOTHING is
        # suggested for a finding that means "not measured"
        assert suggested_step_for(marker.category) is None, (
            f"{marker.category} matches a suggested-step rule, so a run that "
            f"measured no active set would advise a command that refuses"
        )
        # count=0 -> out of every total; a 5-unit tree is not "5 inactive"
        assert marker.count == 0
        assert marker.bytes == 0
        assert marker.name == ACTIVE_SET_UNKNOWN_NAME
        # the fix is scoped to the ACTIVE SET, never to the whole run
        assert "ACTIVE SET" in marker.fix
        assert "nothing is deletable" not in marker.fix.lower()
        assert "ftp" in marker.fix   # the route that CAN answer

    # the two rules that used to fire on these categories are reachable
    # only through a MEASURED finding — and are refused offline, which is
    # why the marker must never suggest them
    assert suggested_step_for("plugins.inactive")[0] == \
        "wpt deactivate-plugin <slug>"
    # db.active_missing's step is advice + a reconcile-plugins mention, and
    # reconcile-plugins is ftp-only: both halves are refused offline
    missing_action, missing_why = suggested_step_for("db.active_missing")
    assert "reconcile-plugins" in missing_why

    # ... and an observed run still produces the ordinary finding, under
    # ITS category, with a count
    measured = replace(audit_data([
        E("wp-content/plugins", is_dir=True),
        E("wp-content/plugins/akismet", is_dir=True),
        E("wp-content/plugins/akismet/akismet.php", 60),
        E("wp-content/plugins/old-cache", is_dir=True),
        E("wp-content/plugins/old-cache/old.php", 50),
    ]), active_plugins=["akismet/akismet.php"])
    (ordinary,) = check_plugins_inactive(measured, load())
    assert (ordinary.category, ordinary.name) == (
        "plugins.inactive", "inactive-plugins")
    assert ordinary.count == 1
    steps = suggested_steps([ordinary])
    assert [s["action"] for s in steps] == ["wpt deactivate-plugin <slug>"]


def test_wordpresss_own_directory_guard_is_not_a_plugin_unit():
    """[L56] wp-content/plugins/index.php is WordPress's own "Silence is
    golden" guard, not a plugin: offering it as an inactive plugin puts a
    core file on the operator's removal list."""
    from wpt.audit.webroot import _plugin_units
    d = audit_data([
        E("wp-content/plugins", is_dir=True),
        E("wp-content/plugins/index.php", 28),
        E("wp-content/plugins/akismet", is_dir=True),
        E("wp-content/plugins/akismet/akismet.php", 60),
    ])
    slugs = [slug for slug, _d, _s, _f in _plugin_units(d.entries)]
    assert "index.php" not in slugs
    assert "akismet" in slugs


def test_the_directory_guard_is_not_a_plugin_on_either_side():
    """[L56] ONE rule, TWO predicates: `wp-content/plugins/index.php` is
    WordPress's own "Silence is golden" guard. Round 10 exempted only the
    unit side, so `db.active_missing` then reported the guard as a HIGH
    active-but-missing plugin (an operator REINSTALL list for a core file).
    Both predicates and the active-entry filter must skip it."""
    from wpt.audit.webroot import (_is_plugin_unit_name, _loadable_plugin_entries,
                                   check_db_active_missing)
    d = audit_data([
        E("wp-content/plugins", is_dir=True),
        E("wp-content/plugins/index.php", 28),
        E("wp-content/plugins/akismet", is_dir=True),
        E("wp-content/plugins/akismet/akismet.php", 60),
    ])
    assert not _is_plugin_unit_name("index.php")
    assert _is_plugin_unit_name("hello.php")      # a real single-file plugin
    assert not _is_plugin_unit_name("README.txt")
    assert "wp-content/plugins/index.php" not in _loadable_plugin_entries(d.entries)
    # an active_plugins value naming the guard is not a missing plugin
    d2 = audit_data([
        E("wp-content/plugins", is_dir=True),
        E("wp-content/plugins/index.php", 28),
    ], active=["index.php"])
    assert check_db_active_missing(d2, load()) == []


def test_a_directory_plugin_whose_main_file_is_index_php_stays_active():
    """[L67] round 11's guard mis-fired: the owner was handed a BASENAME, so
    `responsive-menu/index.php` — a shape `get_plugins()` itself offers —
    was reported INACTIVE (with a live deactivate step) AND dropped from
    db.active_missing's reinstall list. The owner takes the whole
    plugins-relative path, and only the DIRECT CHILD `index.php` is the
    core guard."""
    d = audit_data([
        E("wp-content/plugins", is_dir=True),
        E("wp-content/plugins/responsive-menu", is_dir=True),
        E("wp-content/plugins/responsive-menu/index.php", 900),
    ], active=["responsive-menu/index.php"])
    from wpt.audit.webroot import _active_plugin_slugs
    assert _active_plugin_slugs(d) == {"responsive-menu"}
    assert check_plugins_inactive(d, load()) == []
    # the unit absent from the tree IS an active-but-missing plugin
    d2 = audit_data([
        E("wp-content/plugins", is_dir=True),
        E("wp-content/plugins/akismet", is_dir=True),
        E("wp-content/plugins/akismet/akismet.php", 60),
    ], active=["akismet/akismet.php", "responsive-menu/index.php"])
    got = check_db_active_missing(d2, load())
    assert [f.name for f in got] == ["active-missing-plugins"]
    assert "responsive-menu" in got[0].detail


def test_R15_junk_matches_for_plan_closes_its_owned_session(monkeypatch):
    """R15-P2: the local plan path created ``requests.Session()`` and never
    closed it (per-run leak in-process).  The session it CREATES is owned
    and closed on both the empty and the candidate path."""
    import wpt.audit.webroot as webroot_mod
    from wpt.audit.webroot import CoreJunkBasis
    from wpt.settings import load

    created: list["_CountingSession"] = []

    class _CountingSession(requests.Session):
        def __init__(self):
            super().__init__()
            self.closed = 0
            created.append(self)

        def close(self):
            self.closed += 1
            super().close()

    monkeypatch.setattr(webroot_mod.requests, "Session", _CountingSession)
    monkeypatch.setattr(webroot_mod, "_read_wp_version",
                        lambda source: "6.8.3")
    monkeypatch.setattr(
        webroot_mod, "core_junk_basis",
        lambda *args, **kwargs: CoreJunkBasis(frozenset(), frozenset()))
    ctx = Ctx(source="ftp://example.com", settings=load(),
              command="clean-files")

    assert webroot_mod.junk_matches_for_plan(
        ctx, (FakeSource(), None, None), [], ["error_log"]) == []
    assert webroot_mod.junk_matches_for_plan(
        ctx, (FakeSource(), None, None),
        [Entry(path="error_log", is_dir=False, size=1)], ["error_log"])
    assert len(created) == 2
    assert [session.closed for session in created] == [1, 1]


def test_R13_core_junk_basis_forwards_its_deadline(monkeypatch):
    """R13-P2-9: the webroot junk exemption fetched wp.org checksums with no
    run budget.  ``core_junk_basis`` now takes the deadline its caller owns
    (``data.deadline`` for the check, ``Deadline.from_ctx`` for the plan)."""
    import wpt.audit.webroot as webroot_mod
    from wpt.deadline import Deadline
    from wpt.types import Entry

    deadline = Deadline(0.0)
    seen = []

    def _fake(version, session, timeout_s, locale, deadline=None, config=None):
        seen.append(deadline)
        return {"wp-includes/ID3/license.txt":
                "d41d8cd98f00b204e9800998ecf8427e"}, "en_US"

    monkeypatch.setattr(webroot_mod, "_fetch_comparison_checksums", _fake)
    basis = webroot_mod.core_junk_basis(
        [(Entry(path="wp-includes/ID3/license.txt", is_dir=False, size=10),
          "license.txt")],
        "6.8.3", object(), 5, deadline=deadline,
    )
    assert len(seen) == 1 and seen[0] is deadline
    assert basis.official == frozenset({"wp-includes/ID3/license.txt"})


def test_core_junk_basis_uses_the_configured_wp_org(monkeypatch):
    """The audit check and clean-files plan must not fall back to the
    public wp.org config when the operator configured a locale/mirror."""
    import wpt.audit.webroot as webroot_mod
    from types import SimpleNamespace
    from wpt.types import Entry

    seen = {}

    def _fake(version, session, timeout_s, locale, deadline=None, config=None):
        seen["locale"] = locale
        seen["config"] = config
        return {"wp-includes/ID3/license.txt":
                "d41d8cd98f00b204e9800998ecf8427e"}, "de_DE"

    monkeypatch.setattr(webroot_mod, "_fetch_comparison_checksums", _fake)
    wp_org = SimpleNamespace(default_locale="de_DE")
    basis = webroot_mod.core_junk_basis(
        [(Entry(path="wp-includes/ID3/license.txt", is_dir=False, size=10),
          "license.txt")],
        "6.8.3", object(), 5, wp_org=wp_org,
    )
    assert seen["locale"] == "de_DE"
    assert seen["config"] is wp_org
    assert basis.official == frozenset({"wp-includes/ID3/license.txt"})
