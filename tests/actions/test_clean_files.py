"""Tests for the clean-files action (wpt.actions.clean_files) — W7d.

FakeSource-backed trees + the shipped profile (test_webroot.py
conventions): deterministic, no network, no sleeps.  The registry
end-to-end tests monkeypatch ``wpt.actions.registry._stack`` (the pinned
seam) to run the real ``run_action`` flow over a fake ftp-mode stack;
local-mode flows run the REAL ZipSource/MutableZipSource stack over a
temp zip (the rehearsal test also parses a REAL .sql dump — the local
active-plugin owner).

Test -> behavior map:
  test_plan_enumerates_all_four_groups ...... exact items for junk
        (per file, detail = pattern), .po (nested under languages/plugins
        counted, .mo not), stale dirs (subtree bytes, "N files" detail),
        migration (topmost plugin dir once, no child items; ai1wm* file);
        everything sorted by (category, target); one info summary; the
        INACTIVE plugin unit still deletes per pattern (bridge catalog
        consulted exactly once)
  test_plan_active_plugin_inner_files_never_matched  [the live
        production defect] ai1wm* VENDOR files inside the still-ACTIVE
        all-in-one-wp-migration-unlimited-extension unit: never planned;
        the UNIT becomes ONE advice item (requires_apply=False,
        done=False) with the EXACT "active plugin — deactivate first
        (wpt deactivate-plugin <slug>) or remove it in wp-admin" detail;
        a non-unit ai1wm* match (the export archive) still plans
        normally; ONE guarded log line + ONE info lookup
  test_plan_inner_files_inactive_unit_collapses  the same vendor files
        inside an INACTIVE unit: the UNIT dir is the deletion candidate
        (pattern + whole-subtree estimate), never the inner files
  test_plan_theme_inner_match_collapses_to_unit  the same unit rule
        under wp-content/themes/: an inner ai1wm* file selects the THEME
        unit dir, never the file
  test_plan_active_single_file_plugin_guarded  a directly-matched ACTIVE
        single-file plugin unit (.php): guarded advice item, no deletion
  test_plan_active_theme_unit_is_guarded  [review] the unit rule knows
        wp-content/themes/ but the guard looked at PLUGIN slugs only: the
        active theme's whole directory was planned for deletion
  test_plan_active_plugin_unit_guarded_from_the_stale_group  [review] the
        guard is a property of the DELETION, not of the migration group:
        the shipped stale pattern "wpo" is a real plugin slug, so a live
        "wpo" plugin was rmdir_recursive'd whole, with no active lookup
  test_plan_stale_dir_inside_an_active_unit_still_plans  the guard covers
        UNITS only: a stale cache dir INSIDE an active plugin still
        plans (and the guarded unit is not a subsumption parent)
  test_plan_active_set_ignores_entries_that_cannot_name_a_unit  the guard
        reads webroot's ONE active_plugins semantics: a dump row that
        cannot name a unit protects nothing and displaces nothing
  test_plan_contested_options_dump_refuses_the_unit_deletion
        [the fail-open] an UNMEASURED active set (contested options
        identity — aioseo_options beside wp_options) is never an empty
        one: the unit is refused in ONE line naming the cause and every
        candidate table, the rest of the plan is untouched, and apply
        leaves the unit's files alone
  test_plan_absent_options_table_refuses_the_unit_deletion
        a dump with NO options table: refusal, never a silent deletion
  test_plan_unreadable_active_plugins_option_refuses_the_unit_deletion
        the measured-identity twin — an unreadable active_plugins value
        is unknown, and the refusal names THAT cause
  test_plan_measured_empty_active_set_still_plans_the_unit
        a:0:{} is a REAL measured answer: the unit is a plain deletion and
        no refusal appears anywhere in the plan
  test_plan_measured_active_set_still_plans_the_inactive_unit
        unchanged behavior on the measurable path: a unit the measured set
        does not name is deleted; one it does name is still advice
  test_plan_contested_dump_refuses_the_theme_unit
        the same fail-closed rule for the active THEME (one table, one
        pass, one cause)
  test_plan_unmeasured_active_set_plans_no_geoip_legacy_data
        the legacy-GeoIP gate claims "the geoip plugin is not active", so
        it fails closed on an unmeasured set too — while a measured empty
        set still plans it
  test_registry_local_rehearsal_guards_active_theme  local rehearsal over
        a REAL zip + dump: the active theme (dump template/stylesheet)
        survives byte-identically, a non-active theme unit does not
  test_registry_apply_with_only_advice_items_is_rc0  an all-advice plan
        applies to rc 0, deletes nothing, and snapshots nothing for the
        guarded unit
  test_plan_no_plugin_unit_never_looks_up_active  no plugin-unit
        candidate -> the active lookup never fires (a bridge-less stack
        plans normally; wp-content-child migration dirs unchanged — the
        e2e fixture shape)
  test_plan_host_control_files_planned_and_the_live_htaccess_never  the
        observed source host's control-panel files (home.html, 404.shtml,
        test.html, .ftpquota, old.htaccess, .htaccess.old) are planned as
        ordinary junk ITEMS whose detail names the group they matched
        under; the LIVE `.htaccess` is never planned and the guard refuses
        it while accepting the superseded copies, and the rehearsal really
        removes them with the live one + the theme's/plugin's own html
        surviving; a theme's `home.html` and a plugin's `index.html` are
        never planned (a group glob is a PATH pattern)
  test_plan_dedup_file_items_under_dir ..... a junk file inside a planned
        stale dir is dropped (the rmdir covers it)
  test_plan_dedup_nested_dir_targets ...... a stale dir nested inside a
        planned stale dir is dropped (parent subtree already counts it)
  test_plan_duplicate_target_keeps_first .. "search-and-replace.sql" is
        junk (*.sql) AND a migration component -> one junk item only
  test_plan_guard_skip_warns_once ......... a PROTECTED root index.php
        matched by a custom junk pattern: excluded + exactly ONE warning
  test_plan_no_guard_warning_by_default ... shipped patterns never match
        a guarded target -> no warning
  test_plan_empty_tree .................... zero-item plan, zero bytes
  test_plan_unit_without_active_data_refuses  fail-closed: a plugin-unit
        candidate with NO way to learn the active set (no bridge in an
        ftp stack / no --sql locally) -> SourceError, never a deletion
        plan; a MISSING --sql file -> OSError (rc 1 through the registry)
  test_apply_marks_all_done ............... ops in plan order (delete per
        file, rmdir_recursive per dir), files really gone, same Plan obj
  test_apply_partial_failure_continues .... one injected delete failure:
        that item done=False + one warning, the rest still applied
  test_apply_local_zip_read_only .......... ZipSource: every op fails, all
        items done=False, no exception escapes apply
  test_registry_dry_run ................... run_action apply=False: plan
        printed (markdown), rc 0, nothing deleted, info looked up once,
        never purged
  test_registry_active_lookup_failure_rc1 .. the bridge's info call
        failing -> "plan failed" rc 1, nothing deleted, bridge torn down
  test_registry_apply_skips_active_unit_rc0  (c) end-to-end: an ACTIVE
        unit matched DIRECTLY by the migration pattern -> guarded advice
        item printed as "no", apply SKIPS it (the plugin file survives),
        the other deletions land, the pre-action snapshot captures only
        the deletable targets, purge fires once, rc 0
  test_registry_local_apply_rehearses ..... plain local rehearsal over a
        junk-only zip (no plugin units -> no --sql needed)
  test_registry_local_rehearsal_guards_active_unit  local rehearsal over
        a REAL zip + sql: the ACTIVE unit survives the rehearsed twin
        byte-for-byte, the INACTIVE ai1wm* unit and the junk are removed,
        the guarded item prints its deactivate-first detail, rc 0
  test_registry_ftp_apply_end_to_end ...... apply=True + yes + ftp-mode
        fake stack: backup manifest lists the planned files, files
        deleted, applied marks printed, rc 0
"""

import json
import logging
import zipfile
from dataclasses import replace

import pytest

from tests.fakes import FakeSource
from wpt.actions import registry as registry_mod
from wpt.actions.clean_files import CleanFilesAction, _PO_DETAIL
from wpt.actions.registry import run_action
from wpt.cli import Ctx
from wpt.settings import load
from wpt.sources.zip import ZipSource
from wpt.types import BridgeError, SourceError

#: The shipped profile — every pattern exactly as users get it.
DEFAULTS = load()

#: The purge_cache answer in the wire shape bridge.php's
#: wpt_action_purge_cache returns (tests/actions/test_registry.py's
#: PURGE_OK, specialized here — that file is not owned by this task).
PURGE_OK = {"ok": True, "purged": True}

#: The still-active plugin of the live production incident (its vendor
#: files carry the ai1wm prefix WITHOUT the unit being a migration tool).
ACTIVE_UNIT = "wp-content/plugins/all-in-one-wp-migration-unlimited-extension"

#: The exact deactivate-first detail the guard must emit for a slug.
def _guard_detail(slug):
    return (
        f"active plugin — deactivate first (wpt deactivate-plugin {slug}) "
        "or remove it in wp-admin"
    )


#: The official en_US checksums map of the fixture's version, seeded
#: into the per-test wp.org cache (tests/conftest.py pins the cache dir to
#: tmp_path) so the exemption's fetch is a cache hit and no test in this
#: module ever reaches the network.  It deliberately lists NO
#: wp-admin//wp-includes/ member: these tests are about WHAT the plan
#: removes, and wpt/audit/webroot's own suite owns the exemption's
#: exempt / leave-alone verdicts.
_EXEMPTION_VERSION = "7.1"
_EXEMPTION_MAP = {
    "readme.html": "1" * 32,
    "license.txt": "2" * 32,
    "wp-config-sample.php": "3" * 32,
    "wp-includes/version.php": "4" * 32,
    "wp-includes/ID3/license.txt": "5" * 32,
}


@pytest.fixture(autouse=True)
def _seed_core_checksums():
    """A fresh cache entry for the exemption's map URL (autouse).

    ``wpt.audit.webroot``'s official-core exemption is fail-closed: with
    no version and no map it leaves every wp-admin//wp-includes/ junk match
    out of the plan.  The shared tree carries a version.php, so this seeds
    the map it will ask for.
    """
    import wpt.audit.integrity as integrity
    import wpt.audit.updates as updates

    updates._CACHE_DIR.mkdir(parents=True, exist_ok=True)
    url = integrity._checksums_url(_EXEMPTION_VERSION)
    (updates._CACHE_DIR / (updates._cache_key(url, None) + ".json")).write_text(
        json.dumps({"checksums": _EXEMPTION_MAP}), encoding="utf-8"
    )


@pytest.fixture
def wpt_caplog(caplog):
    """caplog wired to the non-propagating wpt logger tree (see
    tests/audit/test_registry.py — the wpt parent never reaches root)."""
    parent = logging.getLogger("wpt")
    parent.addHandler(caplog.handler)
    with caplog.at_level(logging.DEBUG, logger="wpt"):
        yield caplog
    parent.removeHandler(caplog.handler)


class MutableFakeSource(FakeSource):
    """FakeSource whose rmdir_recursive really removes the subtree.

    The shared double only guards (its files dict never shrinks on rmdir
    and the op is not recorded); the action's apply contract needs both.
    tests/fakes.py is not owned by this task, so the fake is specialized
    here instead.
    """

    def rmdir_recursive(self, path):
        self._check_deletable(path)
        self._rec("rmdir_recursive", path)
        prefix = f"{path}/"
        for name in [k for k in self.files if k == path or k.startswith(prefix)]:
            del self.files[name]


class FailingDeleteSource(MutableFakeSource):
    """Deletes fail (SourceError) for every path in ``fail_paths``."""

    def __init__(self, fail_paths):
        super().__init__()
        self.fail_paths = set(fail_paths)

    def delete(self, path):
        if path in self.fail_paths:
            raise SourceError(f"injected delete failure: {path}")
        super().delete(path)


class InfoBridge:
    """Bridge double scripting one payload per action (the plan's lazy
    ``info`` active-plugin lookup + the registry's post-apply
    ``purge_cache``) and recording every call; ``error`` (raised) takes
    precedence.

    tests/actions/test_registry.py's FakeBridge is not owned by this
    task, so the double is specialized here (the MutableFakeSource
    precedent).  An unscripted call fails LOUDLY — a bridge roundtrip the
    test did not plan must never pass silently.
    """

    def __init__(self, payloads=None, *, error=None):
        self.payloads = dict(payloads or {})
        self.error = error
        self.calls: list[tuple[str, dict]] = []
        self.destroyed = 0

    def call(self, action, **params):
        self.calls.append((action, params))
        if self.error is not None:
            raise self.error
        try:
            return self.payloads[action]
        except KeyError:
            raise AssertionError(f"unexpected bridge action: {action}") from None

    def destroy(self):
        self.destroyed += 1


def _info(*entries):
    """An info payload whose plugin catalog is the given (file, active)
    pairs (the wire shape deactivate-plugin's tests pin)."""
    return {"plugins": {file: {"name": "Example", "version": "1.0",
                               "active": active}
                        for file, active in entries}}


def _theme_info(template, stylesheet=None, *entries):
    """An info payload naming the site's ACTIVE theme(s) plus the plugin
    catalog — bridge.php's `info` carries `template`/`stylesheet`
    alongside `plugins`, which is the fact the unit guard needs for a
    THEME unit."""
    info = _info(*entries)
    info["template"] = template
    info["stylesheet"] = template if stylesheet is None else stylesheet
    return info


#: Catalog answer for the rich tree: the migration plugin is INSTALLED
#: but NOT active — its unit stays a deletable migration item.
_INFO_INACTIVE = _info(("all-in-one-wp-migration/home.php", False))


def _ctx(tmp_path, *, settings=DEFAULTS, **overrides):
    """A clean-files Ctx; ftp-mode defaults, overridable per test."""
    fields = dict(
        source="ftp://example.com",
        settings=settings,
        command="clean-files",
        apply=False,
        yes=False,
        backup_dir=tmp_path / "backup",
        wp_url="https://example.com",
    )
    fields.update(overrides)
    return Ctx(**fields)


def _rich_tree(src):
    """One tree exercising all four groups + leaves that must survive."""
    src.files = {
        # junk (files only; .htaccess.bk is NOT protected)
        "readme.html": b"x" * 100,
        "dump.sql": b"x" * 500,
        "wp-admin/license.txt": b"x" * 20,
        # The core's own version statement: the official-core junk
        # exemption (wpt.audit.webroot, the ONE predicate this plan
        # shares with the audit check) needs a version + the official map
        # before it can rule on a wp-admin//wp-includes/ match, and it
        # FAILS CLOSED without one.  The seeded map below is the en_US
        # build of that version and lists no wp-admin/ member, so
        # wp-admin/license.txt stays the deletable junk this fixture has
        # always asserted (see the exemption's own suite for the
        # exempt/leave-alone halves).
        "wp-includes/version.php": b"<?php\n$wp_version = '7.1';\n",
        # .po catalogs (nested under languages/plugins counted; .mo not)
        "wp-content/languages/admin-default.po": b"x" * 200,
        "wp-content/languages/plugins/akismet.po": b"x" * 40,
        "wp-content/languages/site.mo": b"x" * 90,
        # stale content dir (nested subdirs included in subtree bytes)
        "wp-content/et_temp/cache.txt": b"x" * 10,
        "wp-content/et_temp/sub/deep.txt": b"x" * 5,
        # migration leftovers (plugin dir subsumes descendants)
        "wp-content/plugins/all-in-one-wp-migration/home.php": b"x" * 100,
        "wp-content/plugins/all-in-one-wp-migration/data/export.txt": b"x" * 50,
        "ai1wm-back-123.zip": b"x" * 400,
        # never planned
        "wp-config.php": b"x" * 1000,
        "wp-content/healthy/theme.php": b"x" * 30,
    }


_CLEAN_LEAVES = {
    "wp-config.php",
    "wp-content/healthy/theme.php",
    "wp-content/languages/site.mo",
    "wp-includes/version.php",
}

_EXPECTED_RICH_ITEMS = [
    ("webroot.junk", "dump.sql", "*.sql", 500),
    ("webroot.junk", "readme.html", "readme.html", 100),
    ("webroot.junk", "wp-admin/license.txt", "license.txt", 20),
    ("webroot.junk_recurring", "wp-content/languages/admin-default.po", _PO_DETAIL, 200),
    ("webroot.junk_recurring", "wp-content/languages/plugins/akismet.po", _PO_DETAIL, 40),
    ("webroot.migration", "ai1wm-back-123.zip", "ai1wm*", 400),
    (
        "webroot.migration",
        "wp-content/plugins/all-in-one-wp-migration",
        "all-in-one-wp-migration, 2 files",
        150,
    ),
    ("webroot.stale", "wp-content/et_temp", "2 files", 15),
]


def _vendor_tree(src):
    """The live production incident's shape: ai1wm-named VENDOR files
    strictly inside a plugin unit (main file + two servmask vendor
    files), plus a webroot ai1wm* export archive that IS a leftover."""
    src.files = {
        f"{ACTIVE_UNIT}/plugin.php": b"x" * 100,
        f"{ACTIVE_UNIT}/lib/vendor/servmask/command/ai1wm-wp-cli.php": b"x" * 60,
        f"{ACTIVE_UNIT}/lib/vendor/servmask/ai1wmve.php": b"x" * 40,
        "ai1wm-back-123.zip": b"x" * 400,
    }


def _active_unit_tree(src):
    """An ACTIVE plugin unit matched DIRECTLY by a migration pattern,
    plus plain junk (the guard must not disturb the rest of the plan)."""
    src.files = {
        "readme.html": b"x" * 100,
        "ai1wm-back-123.zip": b"x" * 400,
        "wp-content/plugins/all-in-one-wp-migration/home.php": b"x" * 100,
        "wp-config.php": b"x" * 1000,  # never planned
    }


def _action_records(caplog, level):
    return [
        r
        for r in caplog.records
        if r.name == "wpt.actions.clean_files" and r.levelno == level
    ]


def _ser_str(value):
    return 's:%d:"%s";' % (len(value.encode("utf-8")), value)


def _options_sql(name, rows):
    """CREATE + INSERT for ONE ``*options`` table carrying the given
    ``(option_name, raw_value)`` rows — the phpMyAdmin dump shape the
    analyzer (the local active-plugins owner) parses."""
    values = ",\n".join(
        "(%d, '%s', '%s', 'yes')" % (index, option, raw)
        for index, (option, raw) in enumerate(rows)
    )
    return b"".join([
        ("CREATE TABLE `%s` (\n"
         "  `option_id` bigint(20) UNSIGNED NOT NULL,\n"
         "  `option_name` varchar(191) NOT NULL DEFAULT '',\n"
         "  `option_value` longtext NOT NULL,\n"
         "  `autoload` varchar(20) NOT NULL DEFAULT 'yes',\n"
         "  PRIMARY KEY (`option_id`),\n"
         "  UNIQUE KEY `option_name` (`option_name`)\n"
         ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n" % name).encode("utf-8"),
        ("INSERT INTO `%s` (`option_id`, `option_name`, `option_value`, "
         "`autoload`) VALUES\n" % name).encode("utf-8")
        + values.encode("utf-8") + b";\n",
    ])


def _plugin_rows(active_plugins, extra=()):
    """The ``active_plugins`` option row (PHP-serialized, byte-accurate
    lengths) plus any ``extra`` ``(option_name, scalar_value)`` rows (the
    theme options the unit guard reads from the same pass)."""
    body = "".join("i:%d;%s" % (i, _ser_str(v))
                   for i, v in enumerate(active_plugins))
    rows = [("active_plugins", "a:%d:{%s}" % (len(active_plugins), body))]
    rows.extend(extra)
    return rows


def _dump_bytes(active_plugins, extra=(), *, rival=None):
    """A minimal dump whose wp_options carries the given active plugin
    files, plus any ``extra`` option rows.

    ``rival`` adds a SECOND table proving the options role — the real
    AIOSEO 4.x shape (``aioseo_options`` beside ``wp_options``), which
    leaves the dump's options identity CONTESTED and therefore unreadable
    (see wpt.media_refs' one fail-closed identity rule)."""
    sql = _options_sql("wp_options", _plugin_rows(active_plugins, extra))
    if rival is not None:
        rival_name, rival_plugins = rival
        sql += _options_sql(rival_name, _plugin_rows(rival_plugins))
    return sql


def _posts_only_dump_bytes():
    """A dump that declares a table and NO options table — a partial
    export (a per-table export, an --ignore-table dump, a cut CREATE).
    The prefix is unknown, so nothing about the site can be read from it."""
    return (b"CREATE TABLE `wp_posts` (\n"
            b"  `ID` bigint(20) UNSIGNED NOT NULL,\n"
            b"  `post_type` varchar(20) NOT NULL DEFAULT 'post',\n"
            b"  `post_status` varchar(20) NOT NULL DEFAULT 'publish'\n"
            b") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n"
            b"INSERT INTO `wp_posts` (`ID`, `post_type`, `post_status`) "
            b"VALUES\n(1, 'post', 'publish');\n")


def _zip_contents(path):
    """(namelist, {name: bytes}) — the tests/test_e2e_local.py helper shape."""
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        return names, {name: zf.read(name) for name in names}


# ------------------------------------------------------------------- plan


def test_plan_enumerates_all_four_groups(tmp_path, wpt_caplog):
    src = MutableFakeSource()
    _rich_tree(src)
    bridge = InfoBridge({"info": _INFO_INACTIVE})
    plan = CleanFilesAction().plan(_ctx(tmp_path), (src, None, bridge))
    assert [
        (i.category, i.target, i.detail, i.bytes_est) for i in plan.items
    ] == _EXPECTED_RICH_ITEMS
    assert plan.est_bytes() == 1425
    assert all(i.requires_apply for i in plan.items)
    assert all(not i.done for i in plan.items)
    # non-matching default patterns are absent: error_log, wp-config-sample,
    # .htaccess.bk, ao_ccss... produce no items (the exact list pins it)
    summaries = _action_records(wpt_caplog, logging.INFO)
    assert len(summaries) == 1
    assert "8 item(s)" in summaries[0].getMessage()
    # the INACTIVE unit was checked against the catalog exactly once
    assert bridge.calls == [("info", {})]


def test_C1_a_stop_mid_delete_aborts_the_remaining_items(tmp_path):
    """C1: the per-item ``except (WptError, OSError)`` logged a SIGTERM as
    "continuing" and still deleted the next file.  A RunControl is not an
    operational error: it must abort before the second delete."""
    from wpt.report import Plan, PlanItem
    from wpt.types import StopRequested

    class _StopOnDelete(FakeSource):
        def __init__(self):
            super().__init__()
            self.files = {"a.txt": b"a", "b.txt": b"b"}
            self.deleted = []

        def delete(self, path):
            self.deleted.append(path)
            if path == "a.txt":
                raise StopRequested("received SIGTERM (15)")
            super().delete(path)

    source = _StopOnDelete()
    plan = Plan(items=[
        PlanItem(category="webroot.junk", target="a.txt", detail="*.txt",
                 bytes_est=1),
        PlanItem(category="webroot.junk", target="b.txt", detail="*.txt",
                 bytes_est=1),
    ])
    with pytest.raises(StopRequested):
        CleanFilesAction().apply(_ctx(tmp_path), (source, None, None), plan)

    assert source.deleted == ["a.txt"]       # b.txt was never touched
    assert [item.done for item in plan.items] == [False, False]


def test_plan_active_plugin_inner_files_never_matched(tmp_path, wpt_caplog):
    """[the live production defect] ai1wm* vendor files INSIDE the
    still-ACTIVE all-in-one-wp-migration-unlimited-extension plugin: no
    inner file is ever a deletion candidate; the UNIT is one advice item
    with the exact deactivate-first detail; the webroot ai1wm* archive
    (not inside any unit) still plans normally."""
    src = MutableFakeSource()
    _vendor_tree(src)
    bridge = InfoBridge({"info": _info(
        ("all-in-one-wp-migration-unlimited-extension/plugin.php", True)
    )})
    plan = CleanFilesAction().plan(_ctx(tmp_path), (src, None, bridge))
    assert [
        (i.category, i.target, i.detail, i.bytes_est, i.requires_apply)
        for i in plan.items
    ] == [
        (
            "webroot.active_unit",
            ACTIVE_UNIT,
            _guard_detail("all-in-one-wp-migration-unlimited-extension"),
            200,
            False,
        ),
        ("webroot.migration", "ai1wm-back-123.zip", "ai1wm*", 400, True),
    ]
    assert all(not i.done for i in plan.items)
    # no inner-file target anywhere in the plan
    assert not [
        i.target for i in plan.items
        if i.target.startswith(ACTIVE_UNIT + "/")
    ]
    # ONE guarded log line + ONE plan summary; the catalog was asked once
    infos = _action_records(wpt_caplog, logging.INFO)
    assert len(infos) == 2
    assert any("NOT deleted" in r.getMessage() for r in infos)
    assert any("2 item(s)" in r.getMessage() for r in infos)
    assert bridge.calls == [("info", {})]


def test_plan_inner_files_inactive_unit_collapses(tmp_path, wpt_caplog):
    """The same vendor files inside an INACTIVE plugin unit: the UNIT
    directory is the one deletion candidate (pattern + whole-subtree
    estimate); inner files never appear; no guard, rc-affecting item."""
    src = MutableFakeSource()
    _vendor_tree(src)
    bridge = InfoBridge({"info": _info(
        ("all-in-one-wp-migration-unlimited-extension/plugin.php", False)
    )})
    plan = CleanFilesAction().plan(_ctx(tmp_path), (src, None, bridge))
    assert [
        (i.category, i.target, i.detail, i.bytes_est, i.requires_apply)
        for i in plan.items
    ] == [
        ("webroot.migration", "ai1wm-back-123.zip", "ai1wm*", 400, True),
        (
            "webroot.migration",
            ACTIVE_UNIT,
            "ai1wm*, 3 files",
            200,
            True,
        ),
    ]
    assert all(i.requires_apply for i in plan.items)
    assert len(_action_records(wpt_caplog, logging.INFO)) == 1  # summary only
    assert bridge.calls == [("info", {})]


def test_plan_theme_inner_match_collapses_to_unit(tmp_path):
    """The same unit rule under wp-content/themes/: an inner ai1wm*
    match selects the THEME unit dir, never the file inside it.  The
    theme is NOT the active one (the catalog's template names a
    different theme), so it stays a plain migration deletion."""
    src = MutableFakeSource()
    src.files = {"wp-content/themes/twentytwentyfour/ai1wm-leftover.php": b"x" * 50}
    bridge = InfoBridge({"info": _theme_info("twentytwentythree")})
    plan = CleanFilesAction().plan(_ctx(tmp_path), (src, None, bridge))
    assert [(i.category, i.target, i.detail, i.bytes_est, i.requires_apply)
            for i in plan.items] == [
        (
            "webroot.migration",
            "wp-content/themes/twentytwentyfour",
            "ai1wm*, 1 files",
            50,
            True,
        )
    ]


def test_plan_active_theme_unit_is_guarded(tmp_path, wpt_caplog):
    """A theme unit WordPress is USING is advice, never a deletion.

    The unit rule knows about wp-content/themes/ (the migration collapse
    targets a THEME dir), but the guard used to look at plugin slugs
    only: the active theme's whole directory went into the plan with
    requires_apply=True, and `--apply` rmdir_recursive'd the theme the
    site was rendering with — the same fatal/silent-loss the plugin guard
    exists to prevent, one function away."""
    src = MutableFakeSource()
    src.files = {
        "wp-content/themes/twentytwentyfour/style.css": b"x" * 30,
        "wp-content/themes/twentytwentyfour/ai1wm-leftover.php": b"x" * 50,
    }
    bridge = InfoBridge({"info": _theme_info("twentytwentyfour")})
    plan = CleanFilesAction().plan(_ctx(tmp_path), (src, None, bridge))
    assert [(i.category, i.target, i.detail, i.bytes_est, i.requires_apply)
            for i in plan.items] == [
        (
            "webroot.active_unit",
            "wp-content/themes/twentytwentyfour",
            "active theme — activate a different theme in wp-admin first, "
            "or remove it in wp-admin",
            80,
            False,
        )
    ]
    # apply leaves the ACTIVE theme's files byte-identical
    applied = CleanFilesAction().apply(_ctx(tmp_path), (src, None, bridge), plan)
    assert src.files == {
        "wp-content/themes/twentytwentyfour/style.css": b"x" * 30,
        "wp-content/themes/twentytwentyfour/ai1wm-leftover.php": b"x" * 50,
    }
    assert [op[1] for op in src.ops] == []
    assert [i.done for i in applied.items] == [False]


def test_plan_active_plugin_unit_guarded_from_the_stale_group(tmp_path, wpt_caplog):
    """The guard is a property of the DELETION, not of the migration group.

    ``wpo`` is a SHIPPED stale_content_dirs pattern and a real plugin
    slug: a site still running the active ``wpo`` plugin matched its own
    whole plugin directory through webroot.stale, and the plan removed it
    (rmdir_recursive over the live plugin) with no active-set lookup at
    all.  Every group that can name a unit goes through the guard."""
    src = MutableFakeSource()
    src.files = {
        "wp-content/plugins/wpo/wpo.php": b"x" * 40,
        "wp-content/plugins/wpo/lib/vendor.php": b"x" * 20,
    }
    bridge = InfoBridge({"info": _info(("wpo/wpo.php", True))})
    plan = CleanFilesAction().plan(_ctx(tmp_path), (src, None, bridge))
    assert [(i.category, i.target, i.detail, i.bytes_est, i.requires_apply)
            for i in plan.items] == [
        (
            "webroot.active_unit",
            "wp-content/plugins/wpo",
            _guard_detail("wpo"),
            60,
            False,
        )
    ]
    # ... and an INACTIVE unit of the same name is still a plain removal
    src2 = MutableFakeSource()
    _vendor = {"wp-content/plugins/wpo/wpo.php": b"x" * 40}
    src2.files = _vendor
    bridge2 = InfoBridge({"info": _info(("wpo/wpo.php", False))})
    plan2 = CleanFilesAction().plan(_ctx(tmp_path), (src2, None, bridge2))
    assert [(i.category, i.target, i.detail, i.bytes_est, i.requires_apply)
            for i in plan2.items] == [
        ("webroot.stale", "wp-content/plugins/wpo", "1 files", 40, True)
    ]


def test_plan_stale_dir_inside_an_active_unit_still_plans(tmp_path):
    """The guard covers UNITS (direct children of plugins/themes), not
    everything under one: a stale CACHE directory inside an active plugin
    is the group's designed removal and must keep planning (byte-identical
    junk/stale behavior) — and must not make the plugin unit itself a
    subsumption parent."""
    src = MutableFakeSource()
    src.files = {
        "wp-content/plugins/wpo/wpo.php": b"x" * 40,
        "wp-content/plugins/wpo/wpo/cache/tmp.txt": b"x" * 5,
    }
    bridge = InfoBridge({"info": _info(("wpo/wpo.php", True))})
    plan = CleanFilesAction().plan(_ctx(tmp_path), (src, None, bridge))
    assert [(i.category, i.target, i.bytes_est, i.requires_apply)
            for i in plan.items] == [
        ("webroot.active_unit", "wp-content/plugins/wpo", 45, False),
        ("webroot.stale", "wp-content/plugins/wpo/wpo", 5, True),
    ]


def test_plan_active_single_file_plugin_guarded(tmp_path):
    """A directly-matched ACTIVE single-file plugin unit (.php): guarded
    advice, never deleted (the file-unit twin of the dir guard)."""
    settings = replace(DEFAULTS, migration_leftovers=["ai1wm-helper.php"])
    src = MutableFakeSource()
    src.files = {"wp-content/plugins/ai1wm-helper.php": b"x" * 30}
    bridge = InfoBridge({"info": _info(("ai1wm-helper.php", True))})
    plan = CleanFilesAction().plan(
        _ctx(tmp_path, settings=settings), (src, None, bridge)
    )
    assert [
        (i.category, i.target, i.detail, i.bytes_est, i.requires_apply)
        for i in plan.items
    ] == [
        (
            "webroot.active_unit",
            "wp-content/plugins/ai1wm-helper.php",
            _guard_detail("ai1wm-helper.php"),
            30,
            False,
        )
    ]


def test_plan_active_set_ignores_entries_that_cannot_name_a_unit(tmp_path):
    """The guard reads the SAME active_plugins semantics the audit checks
    do (webroot's one `_plugin_relative_path` predicate), so a dump row
    that cannot name a plugin (webroot-relative, absolute, mu-plugins)
    neither protects an unrelated unit nor displaces a real entry."""
    settings = replace(DEFAULTS, migration_leftovers=["ai1wm*", "other"])
    src = MutableFakeSource()
    src.files = {
        "wp-content/plugins/ai1wm-vendor/vendor.php": b"x" * 10,
        "wp-content/plugins/other/other.php": b"x" * 10,
    }
    spath = tmp_path / "site.sql"
    spath.write_bytes(_dump_bytes(
        ["wp-content/plugins/ai1wm-vendor/vendor.php",   # cannot name a unit
         "other/other.php"],                              # the real entry
    ))
    plan = CleanFilesAction().plan(
        _ctx(tmp_path, source="local", settings=settings, zip=tmp_path / "z.zip",
             sql=spath),
        (src, None, None),
    )
    assert [(i.category, i.target, i.bytes_est, i.requires_apply)
            for i in plan.items] == [
        ("webroot.active_unit", "wp-content/plugins/other", 10, False),
        ("webroot.migration", "wp-content/plugins/ai1wm-vendor", 10, True),
    ]


@pytest.mark.parametrize("entry", [
    "all-in-one-wp-migration//headerless.php",
    "./all-in-one-wp-migration/headerless.php",
    "all-in-one-wp-migration/./headerless.php",
])
def test_R25_normalized_active_entry_protects_the_live_unit(
        tmp_path, entry, monkeypatch):
    """R25-P1: WordPress's own ``validate_file`` normalizes repeated ``/``
    and ``./`` segments, so these entries load the unit.  Treating them as
    inactive put the live plugin directory on a deletion plan."""
    stacks = []

    def fake_stack(ctx):
        src = MutableFakeSource()
        _active_unit_tree(src)
        bridge = InfoBridge({
            "info": _info((entry, True)),
            "purge_cache": PURGE_OK,
        })
        stacks.append((src, bridge))
        return (src, None, bridge)

    monkeypatch.setattr(registry_mod, "_stack", fake_stack)
    ctx = _ctx(tmp_path, apply=True, yes=True,
               settings=replace(DEFAULTS, migration_leftovers=["ai1wm*"]))
    assert run_action(ctx, "clean-files") == 0
    src, _bridge = stacks[-1]
    assert "wp-content/plugins/all-in-one-wp-migration/home.php" in src.files


def _local_plan(tmp_path, src, dump, *, settings=DEFAULTS):
    """A local-mode plan over ``src`` with ``dump`` as the --sql file (the
    local active-set owner)."""
    spath = tmp_path / "site.sql"
    spath.write_bytes(dump)
    return CleanFilesAction().plan(
        _ctx(tmp_path, source="local", settings=settings,
             zip=tmp_path / "site.zip", sql=spath),
        (src, None, None),
    )


def test_plan_contested_options_dump_refuses_the_unit_deletion(tmp_path):
    """[the fail-open] A CONTESTED options identity — AIOSEO 4.x really
    creates ``aioseo_options`` beside ``wp_options`` — leaves the active
    set unmeasured, and an unmeasured set must NEVER read as an empty one.

    The analyzer answered ``active_plugins=[]`` and ``template=None`` for
    such a dump, the guard read that as "no unit is in use", and the plan
    carried the DELETION of a plugin unit that may well be the live one:
    the exact fatal the active-unit guard exists to prevent, silently gone
    for a whole class of real sites.  The unit is refused instead, in ONE
    line naming the cause and every candidate table, and the rest of the
    plan is untouched."""
    src = MutableFakeSource()
    _active_unit_tree(src)
    spath = tmp_path / "site.sql"
    # wp_options claims the unit in the tree IS active; aioseo_options
    # claims something else.  Neither is read (the identity is contested),
    # which is exactly why the guard must refuse rather than delete.
    spath.write_bytes(_dump_bytes(
        ["all-in-one-wp-migration/home.php"],
        rival=("aioseo_options", ["akismet/akismet.php"]),
    ))
    ctx = _ctx(tmp_path, source="local", zip=tmp_path / "site.zip", sql=spath)
    action = CleanFilesAction()
    plan = action.plan(ctx, (src, None, None))
    units = [i for i in plan.items
             if i.target.startswith("wp-content/plugins/")]
    assert [(i.category, i.requires_apply) for i in units] == [
        ("webroot.active_unit", False),
    ]
    detail = units[0].detail
    assert "not deleted" in detail and "UNKNOWN" in detail
    assert "contested" in detail
    assert "aioseo_options" in detail and "wp_options" in detail
    # exactly ONE refusal line for the one unit, and no deletion survives
    assert len([i for i in plan.items if "not deleted" in i.detail]) == 1
    assert not [i for i in plan.items
                if i.target.startswith("wp-content/plugins/") and i.requires_apply]
    # the rest of the plan is unchanged: junk and the export archive go
    assert [(i.category, i.target) for i in plan.items
            if not i.target.startswith("wp-content/plugins/")] == [
        ("webroot.junk", "readme.html"),
        ("webroot.migration", "ai1wm-back-123.zip"),
    ]
    # ... and apply really leaves the unit's files on disk
    action.apply(ctx, (src, None, None), plan)
    assert "wp-content/plugins/all-in-one-wp-migration/home.php" in src.files


def test_plan_absent_options_table_refuses_the_unit_deletion(tmp_path):
    """A dump that declares NO options table (a per-table export, an
    --ignore-table dump, a cut CREATE) measures nothing about the site:
    refusal, never a silent deletion."""
    src = MutableFakeSource()
    _active_unit_tree(src)
    plan = _local_plan(tmp_path, src, _posts_only_dump_bytes())
    units = [i for i in plan.items
             if i.target.startswith("wp-content/plugins/")]
    assert [(i.category, i.requires_apply) for i in units] == [
        ("webroot.active_unit", False),
    ]
    detail = units[0].detail
    assert "not deleted" in detail and "UNKNOWN" in detail
    assert "no table" in detail
    assert "candidate tables" not in detail  # there is none to name
    assert not [i for i in plan.items
                if i.target.startswith("wp-content/plugins/") and i.requires_apply]


def test_plan_unreadable_active_plugins_option_refuses_the_unit_deletion(
        tmp_path):
    """The measured-identity twin: the options table WAS read, but its
    active_plugins value is not a readable list.  That is not a site
    running nothing, so the unit is refused with that cause — and the
    cause is the plugin list, NOT an options-identity contest."""
    sql = _options_sql("wp_options", [
        ("active_plugins", "a:2:{i:0;s:9:\"broken/pl"),  # truncated
    ])
    src = MutableFakeSource()
    _active_unit_tree(src)
    plan = _local_plan(tmp_path, src, sql)
    units = [i for i in plan.items
             if i.target.startswith("wp-content/plugins/")]
    assert [(i.category, i.requires_apply) for i in units] == [
        ("webroot.active_unit", False),
    ]
    detail = units[0].detail
    assert "not deleted" in detail
    assert "active_plugins" in detail
    assert "candidate tables" not in detail


def test_plan_measured_empty_active_set_still_plans_the_unit(tmp_path):
    """``active_plugins = a:0:{}`` is a REAL measured answer — a site
    running no plugins — and the guard must act on it exactly as before:
    the unit is a plain deletion, with no refusal anywhere in the plan."""
    src = MutableFakeSource()
    _active_unit_tree(src)
    plan = _local_plan(tmp_path, src, _dump_bytes([]))
    units = [i for i in plan.items
             if i.target.startswith("wp-content/plugins/")]
    assert [(i.category, i.requires_apply) for i in units] == [
        ("webroot.migration", True),
    ]
    assert units[0].detail == "all-in-one-wp-migration, 1 files"
    assert not [i for i in plan.items if "not deleted" in i.detail]


def test_plan_measured_active_set_still_plans_the_inactive_unit(tmp_path):
    """Unchanged behavior on the measurable path: a unit the measured
    active set does not name is a plain deletion (and a unit it DOES
    name is still the deactivate-first advice)."""
    src = MutableFakeSource()
    _active_unit_tree(src)
    plan = _local_plan(tmp_path, src, _dump_bytes(["other/other.php"]))
    units = [i for i in plan.items
             if i.target.startswith("wp-content/plugins/")]
    assert [(i.category, i.requires_apply) for i in units] == [
        ("webroot.migration", True),
    ]

    guarded_src = MutableFakeSource()
    _active_unit_tree(guarded_src)
    guarded = _local_plan(
        tmp_path, guarded_src,
        _dump_bytes(["all-in-one-wp-migration/home.php"]))
    guarded_units = [i for i in guarded.items
                     if i.target.startswith("wp-content/plugins/")]
    assert [(i.category, i.requires_apply) for i in guarded_units] == [
        ("webroot.active_unit", False),
    ]
    assert _guard_detail("all-in-one-wp-migration") in guarded_units[0].detail


def test_plan_contested_dump_refuses_the_theme_unit(tmp_path):
    """The same rule for the ACTIVE THEME: a theme unit is deletable only
    when the site is provably not rendering it, and on a contested dump
    the model cannot prove anything — the theme set is unmeasured too
    (one table, one pass, one cause)."""
    src = MutableFakeSource()
    src.files = {
        "wp-content/themes/twentytwentyfour/style.css": b"x" * 30,
        "wp-content/themes/twentytwentyfour/ai1wm-leftover.php": b"x" * 50,
    }
    plan = _local_plan(tmp_path, src, _dump_bytes(
        [], extra=[("template", "twentytwentyfour")],
        rival=("aioseo_options", []),
    ))
    themes = [i for i in plan.items
              if i.target.startswith("wp-content/themes/")]
    assert [(i.category, i.requires_apply) for i in themes] == [
        ("webroot.active_unit", False),
    ]
    assert "not deleted" in themes[0].detail and "contested" in themes[0].detail
    assert "aioseo_options" in themes[0].detail


def test_plan_corrupt_theme_options_refuse_theme_unit(tmp_path):
    """A corrupt ``template``/``stylesheet`` option (an array the bridge or
    analyzer renders as "") is UNMEASURED, not "no theme is active": a theme
    unit selected by a migration pattern must be refused, never deleted."""
    src = MutableFakeSource()
    src.files = {
        "wp-content/themes/twentytwentyfour/style.css": b"x" * 30,
        "wp-content/themes/twentytwentyfour/ai1wm-leftover.php": b"x" * 50,
    }
    plan = _local_plan(tmp_path, src, _dump_bytes(
        [], extra=[("template", ""), ("stylesheet", "")]))
    themes = [i for i in plan.items
              if i.target.startswith("wp-content/themes/")]
    assert [(i.category, i.requires_apply) for i in themes] == [
        ("webroot.active_unit", False),
    ]
    assert "not deleted" in themes[0].detail and "UNKNOWN" in themes[0].detail


def test_plan_unmeasured_active_set_plans_no_geoip_legacy_data(tmp_path):
    """The legacy-GeoIP gate makes the same POSITIVE claim ("the geoip
    plugin is not active, so nothing reads these bytes") off the same
    lookup, so it fails closed the same way — an unmeasured set plans
    nothing.  A MEASURED empty set still plans it: that is a real answer."""
    tree = {"GeoIP.dat": b"g" * 700, "readme.html": b"x" * 10}
    unknown_src = MutableFakeSource()
    unknown_src.files = dict(tree)
    unknown = _local_plan(tmp_path, unknown_src, _dump_bytes(
        [], rival=("aioseo_options", [])))
    assert not [i for i in unknown.items
                if i.category == "webroot.geoip_legacy"]
    assert [i.target for i in unknown.items] == ["readme.html"]

    measured_src = MutableFakeSource()
    measured_src.files = dict(tree)
    measured = _local_plan(tmp_path, measured_src, _dump_bytes(
        [], extra=[("template", "twentytwentyfour"),
                  ("stylesheet", "twentytwentyfour")]))
    geoip = [i for i in measured.items if i.category == "webroot.geoip_legacy"]
    assert [i.target for i in geoip] == ["GeoIP.dat"]
    assert geoip[0].requires_apply


def test_plan_no_plugin_unit_never_looks_up_active(tmp_path):
    """No plugin-unit candidate -> the active lookup never fires: a
    bridge-LESS stack plans normally, and wp-content-child migration
    dirs (the e2e fixture shape) are byte-identically unchanged."""
    src = MutableFakeSource()
    src.files = {
        "wp-content/ai1wm-backups/export.wpress": b"x" * 100,
        "readme.html": b"x" * 10,
    }
    plan = CleanFilesAction().plan(_ctx(tmp_path), (src, None, None))
    assert [(i.category, i.target, i.detail, i.bytes_est) for i in plan.items] == [
        ("webroot.junk", "readme.html", "readme.html", 10),
        ("webroot.migration", "wp-content/ai1wm-backups", "ai1wm*, 1 files", 100),
    ]


def test_plan_dedup_file_items_under_dir(tmp_path):
    src = MutableFakeSource()
    src.files = {
        "wp-content/et_temp/dump.sql": b"x" * 500,  # junk AND under stale dir
        "wp-content/et_temp/keep.txt": b"x" * 10,
    }
    plan = CleanFilesAction().plan(_ctx(tmp_path), (src, None, None))
    assert [(i.category, i.target, i.bytes_est) for i in plan.items] == [
        ("webroot.stale", "wp-content/et_temp", 510)
    ]


def test_plan_dedup_nested_dir_targets(tmp_path):
    settings = replace(DEFAULTS, stale_content_dirs=["et_temp", "sub"])
    src = MutableFakeSource()
    src.files = {
        "wp-content/et_temp/a.txt": b"x" * 10,
        "wp-content/et_temp/sub/b.txt": b"x" * 5,
    }
    plan = CleanFilesAction().plan(_ctx(tmp_path, settings=settings), (src, None, None))
    # the parent dir subsumes the nested stale dir (its subtree already
    # counts both files); without the drop the inner rmdir would run after
    # the outer one removed it
    assert [(i.category, i.target, i.detail, i.bytes_est) for i in plan.items] == [
        ("webroot.stale", "wp-content/et_temp", "2 files", 15)
    ]


def test_plan_duplicate_target_keeps_first(tmp_path):
    src = MutableFakeSource()
    # junk (*.sql) AND migration (component "search-and-replace")
    src.files = {"search-and-replace.sql": b"x" * 200}
    plan = CleanFilesAction().plan(_ctx(tmp_path), (src, None, None))
    assert [(i.category, i.target, i.detail) for i in plan.items] == [
        ("webroot.junk", "search-and-replace.sql", "*.sql")
    ]


def test_plan_guard_skip_warns_once(tmp_path, wpt_caplog):
    settings = replace(DEFAULTS, webroot_junk=DEFAULTS.webroot_junk + ["index.php"])
    src = MutableFakeSource()
    src.files = {
        "index.php": b"x" * 80,  # PROTECTED root file: excluded from plan
        "wp-content/index.php": b"x" * 40,  # same basename, deletable
        "readme.html": b"x" * 10,
    }
    plan = CleanFilesAction().plan(
        _ctx(tmp_path, settings=settings), (src, None, None)
    )
    assert [i.target for i in plan.items] == ["readme.html", "wp-content/index.php"]
    warnings = _action_records(wpt_caplog, logging.WARNING)
    assert len(warnings) == 1
    assert "index.php" in warnings[0].getMessage()
    assert "index.php" not in [i.target for i in plan.items]


def test_plan_no_guard_warning_by_default(tmp_path, wpt_caplog):
    src = MutableFakeSource()
    _rich_tree(src)
    bridge = InfoBridge({"info": _INFO_INACTIVE})
    CleanFilesAction().plan(_ctx(tmp_path), (src, None, bridge))
    assert not [
        r
        for r in wpt_caplog.records
        if r.name == "wpt.actions.clean_files" and r.levelno >= logging.WARNING
    ]


def test_plan_host_control_files_planned_and_the_live_htaccess_never(tmp_path,
                                                                     wpt_caplog):
    """The live source-host control files (``home.html``, ``404.shtml``,
    ``test.html``, ``.ftpquota``, ``old.htaccess``, ``.htaccess.old``) are
    planned as ordinary junk ITEMS — one per file, the item detail naming
    the group they were matched under, so the plan says which family
    authorizes the deletion.

    The LIVE ``.htaccess`` is not in the picture at all: it is
    ``Source.PROTECTED`` (harden owns it, the write-guard audits its
    writes), and its superseded copies are NOT protected, so the plan can
    delete them — which is what "reported without being conflated with the
    live one" has to mean for a DELETING plan.

    A theme's own ``home.html``/``404.shtml`` and a plugin's authored
    ``index.html``/``test.html`` are never planned: a group glob is a
    webroot-relative PATH pattern (wpt.audit.webroot.split_junk_pattern).
    """
    src = MutableFakeSource()
    src.files = {
        "home.html": b"x" * 1963,
        "404.shtml": b"x" * 1699,
        "test.html": b"x" * 10,
        ".ftpquota": b"x" * 17,
        "old.htaccess": b"x" * 301,
        ".htaccess.old": b"x" * 512,
        # never planned
        ".htaccess": b"x" * 2720,
        "home.php": b"x" * 405,
        "wp-config.php": b"x" * 3486,
        "wp-content/themes/Avada/home.html": b"x" * 900,
        "wp-content/themes/Avada/includes/404.shtml": b"x" * 1200,
        "wp-content/plugins/avada/index.html": b"x" * 300,
        "wp-content/plugins/avada/test.html": b"x" * 300,
    }
    plan = CleanFilesAction().plan(_ctx(tmp_path), (src, None, None))
    assert [(i.category, i.target, i.detail, i.bytes_est) for i in plan.items] == [
        ("webroot.junk", ".ftpquota", "host_account_quota:.ftpquota", 17),
        ("webroot.junk", ".htaccess.old", "superseded_htaccess:.htaccess.old", 512),
        ("webroot.junk", "404.shtml", "host_placeholder_page:404.shtml", 1699),
        ("webroot.junk", "home.html", "host_placeholder_page:home.html", 1963),
        ("webroot.junk", "old.htaccess", "superseded_htaccess:old.htaccess", 301),
        ("webroot.junk", "test.html", "host_placeholder_page:test.html", 10),
    ]
    assert all(i.requires_apply for i in plan.items)
    assert ".htaccess" not in [i.target for i in plan.items]
    # the guard: the LIVE file is refused, the superseded copies are not
    from wpt.types import SourceError
    src._check_deletable(".htaccess.old")
    src._check_deletable("old.htaccess")
    for protected in (".htaccess", "wp-config.php"):
        with pytest.raises(SourceError):
            src._check_deletable(protected)
    # ...and the rehearsal really removes the superseded copy while the
    # live one survives byte-identical
    action = CleanFilesAction()
    applied = action.apply(_ctx(tmp_path, apply=True, yes=True),
                           (src, None, None), plan)
    assert all(i.done for i in applied.items)
    assert ".htaccess" in src.files
    assert ".htaccess.old" not in src.files
    assert "old.htaccess" not in src.files
    assert "home.html" not in src.files
    # the theme's and the plugin's own html survived untouched
    assert "wp-content/themes/Avada/home.html" in src.files
    assert "wp-content/plugins/avada/index.html" in src.files


def test_plan_empty_tree(tmp_path):
    src = MutableFakeSource()
    plan = CleanFilesAction().plan(_ctx(tmp_path), (src, None, None))
    assert plan.items == []
    assert plan.est_bytes() == 0


def test_plan_unit_without_active_data_refuses(tmp_path):
    """Fail-closed: a plugin-unit candidate with NO way to learn the
    active set is a SourceError (never a deletion plan that might
    delete an active plugin's files); a missing --sql file raises the
    operational OSError the registry contract answers with rc 1."""
    src = MutableFakeSource()
    _active_unit_tree(src)
    # ftp-mode stack without a bridge (direct-call misuse shape)
    with pytest.raises(SourceError, match="cannot determine active plugins"):
        CleanFilesAction().plan(_ctx(tmp_path), (src, None, None))
    # local mode without --sql
    with pytest.raises(SourceError, match="cannot determine active plugins"):
        CleanFilesAction().plan(
            _ctx(tmp_path, source="local", zip=tmp_path / "site.zip"),
            (src, None, None),
        )
    # local mode with an unreadable --sql path
    with pytest.raises(OSError):
        CleanFilesAction().plan(
            _ctx(tmp_path, source="local", zip=tmp_path / "site.zip",
                 sql=tmp_path / "missing.sql"),
            (src, None, None),
        )


# ------------------------------------------------------------------ apply


def test_apply_marks_all_done(tmp_path):
    src = MutableFakeSource()
    _rich_tree(src)
    action = CleanFilesAction()
    bridge = InfoBridge({"info": _INFO_INACTIVE})
    plan = action.plan(_ctx(tmp_path), (src, None, bridge))
    applied = action.apply(_ctx(tmp_path), (src, None, bridge), plan)
    assert applied is plan  # the same Plan object, items updated in place
    assert all(i.done for i in applied.items)
    # every op in plan order: delete per file, rmdir_recursive per dir
    ops = [
        (op, path)
        for _ts, op, path in src.ops
        if op in ("delete", "rmdir_recursive")
    ]
    assert ops == [
        ("delete", "dump.sql"),
        ("delete", "readme.html"),
        ("delete", "wp-admin/license.txt"),
        ("delete", "wp-content/languages/admin-default.po"),
        ("delete", "wp-content/languages/plugins/akismet.po"),
        ("delete", "ai1wm-back-123.zip"),
        ("rmdir_recursive", "wp-content/plugins/all-in-one-wp-migration"),
        ("rmdir_recursive", "wp-content/et_temp"),
    ]
    assert set(src.files) == _CLEAN_LEAVES


def test_apply_partial_failure_continues(tmp_path, wpt_caplog):
    src = FailingDeleteSource({"dump.sql"})
    _rich_tree(src)
    action = CleanFilesAction()
    bridge = InfoBridge({"info": _INFO_INACTIVE})
    plan = action.plan(_ctx(tmp_path), (src, None, bridge))
    applied = action.apply(_ctx(tmp_path), (src, None, bridge), plan)
    by_target = {i.target: i for i in applied.items}
    assert not by_target["dump.sql"].done
    assert all(i.done for i in applied.items if i.target != "dump.sql")
    warnings = _action_records(wpt_caplog, logging.WARNING)
    assert len(warnings) == 1
    assert "dump.sql" in warnings[0].getMessage()
    assert "dump.sql" in src.files  # the failed target is untouched
    assert "readme.html" not in src.files  # the batch continued past it


def test_apply_local_zip_read_only(tmp_path, wpt_caplog):
    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.html", "junk")
        zf.writestr("dump.sql", "x" * 40)
        zf.writestr("wp-content/et_temp/cache.txt", "x" * 10)
        zf.writestr("wp-config.php", "cfg")
    ctx = _ctx(tmp_path, source="local", zip=zpath)
    zsrc = ZipSource(zpath)
    try:
        action = CleanFilesAction()
        plan = action.plan(ctx, (zsrc, None, None))
        assert [i.target for i in plan.items] == [
            "dump.sql",
            "readme.html",
            "wp-content/et_temp",
        ]
        applied = action.apply(ctx, (zsrc, None, None), plan)
        assert all(not i.done for i in applied.items)  # every op refused
        warnings = _action_records(wpt_caplog, logging.WARNING)
        assert len(warnings) == len(plan.items)  # one per item, none raised
    finally:
        zsrc.close()


# ------------------------------------------------------- registry end-to-end


def test_registry_dry_run_prints_plan_deletes_nothing(tmp_path, capsys,
                                                      monkeypatch):
    src = MutableFakeSource()
    _rich_tree(src)
    bridge = InfoBridge({"info": _INFO_INACTIVE})
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    rc = run_action(_ctx(tmp_path), "clean-files")
    assert rc == 0
    out = capsys.readouterr().out
    assert "## Plan" in out
    for target in (
        "dump.sql",
        "readme.html",
        "wp-admin/license.txt",
        "wp-content/languages/plugins/akismet.po",
        "wp-content/plugins/all-in-one-wp-migration",
        "wp-content/et_temp",
        "ai1wm-back-123.zip",
    ):
        assert target in out
    assert not [
        op for _ts, op, _p in src.ops if op in ("delete", "rmdir_recursive")
    ]
    assert "readme.html" in src.files
    # the catalog was consulted for the inactive unit; a dry run purges
    # nothing (the bridge is only ever asked info)
    assert bridge.calls == [("info", {})]


def test_registry_active_lookup_failure_rc1(tmp_path, capsys, monkeypatch,
                                            wpt_caplog):
    """Fail-closed fetch: the bridge's info call failing -> plan failed,
    rc 1, nothing deleted, teardown still runs (never a deletion plan
    over an unknowable active set)."""
    src = MutableFakeSource()
    _active_unit_tree(src)
    bridge = InfoBridge(error=BridgeError("bridge action failed: info refused"))
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "clean-files")
    assert rc == 1
    assert set(src.files) == {
        "readme.html", "ai1wm-back-123.zip",
        "wp-content/plugins/all-in-one-wp-migration/home.php", "wp-config.php",
    }
    errors = [
        r for r in wpt_caplog.records
        if r.name == "wpt.actions" and r.levelno == logging.ERROR
    ]
    assert errors and "plan failed" in errors[0].getMessage()
    assert "info refused" in errors[0].getMessage()
    assert bridge.destroyed == 1
    assert "## Plan" not in capsys.readouterr().out


def test_registry_apply_skips_active_unit_rc0(tmp_path, capsys, monkeypatch):
    """(c) end-to-end: an ACTIVE plugin unit whose dir matches a
    migration pattern DIRECTLY -> the guarded advice item prints as
    'no', apply SKIPS it (the plugin file survives), the other
    deletions land, the pre-action snapshot captures ONLY the deletable
    targets, purge fires once, rc 0 in BOTH phases."""
    stacks = []

    def fake_stack(ctx):
        src = MutableFakeSource()
        _active_unit_tree(src)
        bridge = InfoBridge({
            "info": _info(("all-in-one-wp-migration/home.php", True)),
            "purge_cache": PURGE_OK,
        })
        stacks.append((src, bridge))
        return (src, None, bridge)

    monkeypatch.setattr(registry_mod, "_stack", fake_stack)

    # dry run: the plan shows the guarded item, deletes nothing
    rc = run_action(_ctx(tmp_path), "clean-files")
    assert rc == 0
    src, bridge = stacks[-1]
    out = capsys.readouterr().out
    assert _guard_detail("all-in-one-wp-migration") in out
    assert out.count("| no |") == 3  # a dry run applies nothing: all 3 items
    assert not [op for _ts, op, _p in src.ops
                if op in ("delete", "rmdir_recursive")]
    assert bridge.calls == [("info", {})]

    # apply: the guarded unit is skipped, everything else lands, rc 0
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "clean-files")
    assert rc == 0
    src, bridge = stacks[-1]
    # the active plugin's file SURVIVES; junk and the archive are gone
    assert set(src.files) == {
        "wp-content/plugins/all-in-one-wp-migration/home.php", "wp-config.php",
    }
    out = capsys.readouterr().out
    assert out.count("| yes |") == 2   # the two deletable items applied
    assert out.count("| no |") == 1    # the guarded item, untouched
    # the pre-action snapshot captured ONLY the deletable targets (the
    # guarded unit is advice: never snapshotted, never applied)
    manifests = list((tmp_path / "backup").glob("*/*/manifest.json"))
    assert len(manifests) == 1
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    captured = sorted(e["path"] for e in manifest["files"] if not e["absent"])
    assert captured == ["ai1wm-back-123.zip", "readme.html"]
    # the bridge was asked info once, then the post-apply purge once
    assert bridge.calls == [("info", {}), ("purge_cache", {})]


def test_registry_local_apply_rehearses(tmp_path, wpt_caplog):
    """Local --apply is a REHEARSAL now: rc 0, the ORIGINAL zip untouched,
    and a materialized <stem>-rehearsed-<ts>.zip beside it carrying the
    cleanup (junk gone, config kept)."""
    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.html", "junk")
        zf.writestr("wp-config.php", "cfg")
    rc = run_action(
        _ctx(tmp_path, source="local", zip=zpath, apply=True, yes=True),
        "clean-files",
    )
    assert rc == 0
    with zipfile.ZipFile(zpath) as zf:
        assert zf.namelist() == ["readme.html", "wp-config.php"]  # original
    rehearsed = sorted(tmp_path.glob("site-rehearsed-*.zip"))
    assert len(rehearsed) == 1
    with zipfile.ZipFile(rehearsed[0]) as zf:
        assert "readme.html" not in zf.namelist()  # the cleanup happened
        assert "wp-config.php" in zf.namelist()     # the keeper stayed
    infos = [
        r
        for r in wpt_caplog.records
        if r.name == "wpt.actions" and "rehearsed" in r.getMessage()
    ]
    assert infos and str(rehearsed[0]) in infos[0].getMessage()


def test_registry_local_rehearsal_guards_active_unit(tmp_path, capsys):
    """Local rehearsal over a REAL zip + .sql dump (the local
    active-plugins owner): the ACTIVE unit's files — INCLUDING the
    ai1wm-named vendor file that caused the production fatal — survive
    the rehearsed twin byte-identically; the INACTIVE ai1wm* unit and
    the junk are removed; the guarded item prints its deactivate-first
    detail; rc 0."""
    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.html", b"junk")
        zf.writestr("wp-config.php", b"cfg")
        zf.writestr(
            "wp-content/plugins/all-in-one-wp-migration/plugin.php",
            b"<?php /* active */",
        )
        zf.writestr(
            "wp-content/plugins/all-in-one-wp-migration/lib/servmask/"
            "ai1wm-wp-cli.php",
            b"x" * 20,
        )
        zf.writestr(
            "wp-content/plugins/ai1wm-vendor-tool/vendor.php",
            b"<?php /* inactive */",
        )
    spath = tmp_path / "site.sql"
    spath.write_bytes(_dump_bytes(["all-in-one-wp-migration/plugin.php"]))
    before = _zip_contents(zpath)

    rc = run_action(
        _ctx(tmp_path, source="local", zip=zpath, sql=spath, apply=True,
             yes=True),
        "clean-files",
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert _guard_detail("all-in-one-wp-migration") in out
    assert _zip_contents(zpath) == before  # the original IS the rollback

    rehearsed = sorted(tmp_path.glob("site-rehearsed-*.zip"))
    assert len(rehearsed) == 1
    names = _zip_contents(rehearsed[0])[0]
    assert "readme.html" not in names                                   # junk gone
    assert "wp-config.php" in names                                     # keeper
    assert "wp-content/plugins/all-in-one-wp-migration/plugin.php" in names
    assert ("wp-content/plugins/all-in-one-wp-migration/lib/servmask/"
            "ai1wm-wp-cli.php") in names      # the ACTIVE unit survives INTACT
    assert "wp-content/plugins/ai1wm-vendor-tool/vendor.php" not in names
    with zipfile.ZipFile(rehearsed[0]) as zf:  # ...and byte-identically
        assert zf.read(
            "wp-content/plugins/all-in-one-wp-migration/plugin.php"
        ) == b"<?php /* active */"


def test_registry_local_rehearsal_guards_active_theme(tmp_path, capsys):
    """The ACTIVE THEME survives a local rehearsal byte-identically.

    The local active-unit owner is the dump's active_plugins option AND
    its template/stylesheet options — one analyzer pass, the same
    `--sql` gate.  A theme unit selected by the migration/stale pattern
    used to be planned as a deletion, which on --apply would leave the
    rehearsed twin (and, in ftp mode, the live site) without the theme
    WordPress is rendering with."""
    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.html", b"junk")
        zf.writestr("wp-content/themes/twentytwentyfour/style.css", b"/* theme */")
        zf.writestr("wp-content/themes/twentytwentyfour/ai1wm-leftover.php", b"x" * 9)
        zf.writestr("wp-content/themes/legacy-theme/style.css", b"/* other */")
        zf.writestr("wp-content/themes/legacy-theme/ai1wm-leftover.php", b"x" * 4)
    spath = tmp_path / "site.sql"
    spath.write_bytes(_dump_bytes(
        [], extra=[("template", "twentytwentyfour"),
                   ("stylesheet", "twentytwentyfour")],
    ))
    rc = run_action(
        _ctx(tmp_path, source="local", zip=zpath, sql=spath, apply=True,
             yes=True),
        "clean-files",
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "active theme — activate a different theme in wp-admin first" in out
    rehearsed = sorted(tmp_path.glob("site-rehearsed-*.zip"))
    assert len(rehearsed) == 1
    names, contents = _zip_contents(rehearsed[0])
    assert "readme.html" not in names                     # junk removed
    # the active theme's unit is intact...
    assert "wp-content/themes/twentytwentyfour/style.css" in names
    assert "wp-content/themes/twentytwentyfour/ai1wm-leftover.php" in names
    assert contents["wp-content/themes/twentytwentyfour/style.css"] == b"/* theme */"
    # ...and the NON-active theme unit the same pattern selected still goes
    assert "wp-content/themes/legacy-theme/style.css" not in names


def test_registry_apply_with_only_advice_items_is_rc0(tmp_path, monkeypatch,
                                                      capsys):
    """A plan whose every item is advice: rc 0, nothing deleted, an EMPTY
    snapshot scope (the guarded unit is not in the backup manifest) and
    no failure reported — 'needs your call' must never read as an
    operational failure."""
    src = MutableFakeSource()
    _vendor_tree(src)
    bridge = InfoBridge({"info": _info(
        ("all-in-one-wp-migration-unlimited-extension/plugin.php", True)
    ), "purge_cache": PURGE_OK})
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    before = dict(src.files)
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "clean-files")
    assert rc == 0
    # only the non-unit archive is deleted; the ACTIVE unit is intact
    assert "ai1wm-back-123.zip" not in src.files
    assert src.files[f"{ACTIVE_UNIT}/plugin.php"] == before[f"{ACTIVE_UNIT}/plugin.php"]
    assert src.files[
        f"{ACTIVE_UNIT}/lib/vendor/servmask/command/ai1wm-wp-cli.php"
    ] == before[f"{ACTIVE_UNIT}/lib/vendor/servmask/command/ai1wm-wp-cli.php"]
    manifests = list((tmp_path / "backup").glob("*/*/manifest.json"))
    assert len(manifests) == 1
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    # the guarded unit contributes NOTHING to the snapshot scope
    assert [e["path"] for e in manifest["files"]] == ["ai1wm-back-123.zip"]
    out = capsys.readouterr().out
    assert "webroot.active_unit" in out
    assert "not applied" not in out


def test_registry_ftp_apply_end_to_end(tmp_path, capsys, monkeypatch):
    src = MutableFakeSource()
    _rich_tree(src)
    bridge = InfoBridge({"info": _INFO_INACTIVE, "purge_cache": PURGE_OK})
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "clean-files")
    assert rc == 0
    assert set(src.files) == _CLEAN_LEAVES  # planned targets really gone
    # fail-closed pre-action backup: the manifest lists the planned FILES
    manifests = list((tmp_path / "backup").glob("*/*/manifest.json"))
    assert len(manifests) == 1
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    assert manifest["action"] == "clean-files"
    assert manifest["site"] == "example.com"
    captured = sorted(e["path"] for e in manifest["files"] if not e["absent"])
    # Dir targets expand to their contained FILES for the snapshot (registry
    # _backup_file_scope): stale + migration dir CONTENTS are captured, so a
    # restore can rebuild the deleted trees.  Sorted; absent entries excluded
    # (nothing here is absent — every captured file exists).
    assert captured == [
        "ai1wm-back-123.zip",
        "dump.sql",
        "readme.html",
        "wp-admin/license.txt",
        "wp-content/et_temp/cache.txt",
        "wp-content/et_temp/sub/deep.txt",
        "wp-content/languages/admin-default.po",
        "wp-content/languages/plugins/akismet.po",
        "wp-content/plugins/all-in-one-wp-migration/data/export.txt",
        "wp-content/plugins/all-in-one-wp-migration/home.php",
    ]
    assert manifest["totals"]["files"] == 10
    out = capsys.readouterr().out
    assert "## Plan" in out
    assert out.count("| yes |") == 8  # every applied item printed as done
    # the inactive-unit check (info) precedes the successful-apply purge
    assert bridge.calls == [("info", {}), ("purge_cache", {})]


def test_ZIP_WALK_clean_files_plan_is_run_deadline_bounded(tmp_path):
    """ZIP-WALK: clean_files.plan consumed `list(source.walk())` with no
    deadline, so a connector that relists forever ran past --deadline."""
    import time

    from wpt.types import DeadlineExceeded

    class SlowEmptyWalk(FakeSource):
        def walk(self, path="", *, include_links=False):
            time.sleep(0.05)
            return iter(())

    ctx = _ctx(tmp_path, deadline_s=0.02)
    with pytest.raises(DeadlineExceeded):
        CleanFilesAction().plan(ctx, (SlowEmptyWalk(), None, None))


# ------------------------------------------------------- triple-check round 6


def test_R6_02_unknown_or_case_variant_junk_group_plans_nothing(tmp_path):
    """R6-02: an unknown/case-variant ``<group>:pattern`` used to be treated
    as a group and path-matched, planning WordPress core, plugin and theme
    PHP for deletion.  It now degrades to a literal bare pattern, so the
    uppercase/typo forms plan NOTHING."""
    src = FakeSource()
    src.files = {
        "wp-login.php": b"<?php",
        "wp-cron.php": b"<?php",
        "xmlrpc.php": b"<?php",
        "wp-content/plugins/akismet/akismet.php": b"<?php",
        "wp-content/plugins/akismet/class.php": b"<?php",
        "wp-content/themes/twentytwentyfive/index.php": b"<?php",
    }
    settings = replace(DEFAULTS, webroot_junk=[
        "HOST_PLACEHOLDER_PAGE:*.php",
        "NO_SUCH_GROUP:*.php",
    ])
    bridge = InfoBridge({"info": _INFO_INACTIVE})

    plan = CleanFilesAction().plan(
        _ctx(tmp_path, settings=settings), (src, None, bridge))

    assert plan.items == []
    assert not any(item.requires_apply for item in plan.items)
    assert not any("*.php" in item.detail for item in plan.items)


def test_R13_geoip_only_local_plan_without_sql_is_unmeasured_rc0(
        tmp_path, monkeypatch):
    """R13-P2-23: a local GeoIP-only tree with no --sql raised
    SourceError (rc 1), contradicting SPEC's junk-only --zip rule.  No
    dump is UNMEASURED: the GeoIP group plans nothing and the run is rc 0;
    the active-unit guard still refuses any actual unit deletion."""
    import wpt.actions.registry as registry_mod

    src = MutableFakeSource()
    src.files = {"GeoIP.dat": b"g" * 700, "readme.html": b"x" * 10}
    ctx = _ctx(tmp_path, source="local", zip=tmp_path / "site.zip")
    plan = CleanFilesAction().plan(ctx, (src, None, None))
    assert [item.target for item in plan.items] == ["readme.html"]
    assert not [item for item in plan.items
                if item.category == "webroot.geoip_legacy"]

    monkeypatch.setattr(registry_mod, "_stack",
                        lambda _ctx: (src, None, None))
    assert registry_mod.run_action(ctx, "clean-files") == 0

    # The unit-deletion guard is unchanged: a plugin unit without --sql
    # still refuses (never a deletion plan).
    unit = MutableFakeSource()
    _active_unit_tree(unit)
    with pytest.raises(SourceError, match="cannot determine active plugins"):
        CleanFilesAction().plan(
            _ctx(tmp_path, source="local", zip=tmp_path / "site.zip"),
            (unit, None, None))


def test_R14_no_bridge_is_unmeasured_not_a_source_error(tmp_path):
    """R14-P2: ``_active_units`` raised for a missing bridge before
    ``required`` was considered, so the GeoIP gate's required=False call
    contradicted the documented "no bridge = not measured" contract.
    required=True still refuses the unit deletion (covered above)."""
    from wpt.actions.clean_files import _NO_BRIDGE_REASON, _active_units

    src = MutableFakeSource()
    unit = _active_units(_ctx(tmp_path), (src, None, None))
    assert unit.measured is False
    assert unit.reason == _NO_BRIDGE_REASON

    src.files = {"GeoIP.dat": b"g" * 700, "readme.html": b"x" * 10}
    plan = CleanFilesAction().plan(_ctx(tmp_path), (src, None, None))
    assert [i.target for i in plan.items] == ["readme.html"]


def test_R15_clean_files_apply_honours_the_deadline_before_any_delete(
        tmp_path):
    """R15-P2: apply's walk was unbounded and it deleted after expiry; only
    the plan had been fixed.  The walk and each delete check the SAME run
    budget and nothing is deleted once it is spent."""
    import time

    from wpt.report import Plan, PlanItem
    from wpt.types import DeadlineExceeded

    class SlowWalk(MutableFakeSource):
        def walk(self):
            for entry in super().walk():
                time.sleep(0.06)
                yield entry

    src = SlowWalk()
    src.files = {"readme.html": b"x" * 10}
    ctx = _ctx(tmp_path, deadline_s=0.02)
    plan = Plan(items=[PlanItem(category="webroot.junk",
                                target="readme.html", detail="delete",
                                bytes_est=10, requires_apply=True)])
    with pytest.raises(DeadlineExceeded):
        CleanFilesAction().apply(ctx, (src, None, None), plan)
    assert "readme.html" in src.files
    assert not plan.items[0].done



def test_R14_clean_files_bridge_info_call_is_bounded(tmp_path):
    """R14-P2: the walk-end check passed, then the ``info`` request started
    with the remaining sliver and outlived the budget.  The call checks the
    deadline and hands its remaining time to the bridge transport."""
    import time

    from wpt.types import DeadlineExceeded

    class _SlowBridge(InfoBridge):
        def call(self, action, **params):
            self.calls.append((action, params))
            time.sleep(0.25)
            return _INFO_INACTIVE

    src = MutableFakeSource()
    _active_unit_tree(src)
    bridge = _SlowBridge()
    ctx = _ctx(tmp_path, deadline_s=0.05)
    started = time.monotonic()
    with pytest.raises(DeadlineExceeded):
        CleanFilesAction().plan(ctx, (src, object(), bridge))
    assert time.monotonic() - started < 0.5
    # the ABSOLUTE run deadline rode the bridge transport, so a real
    # request cannot re-arm its 30 s per-read timeout after the remaining
    # sliver was already spent.
    absolute = bridge.calls[0][1]["deadline"]
    # The budget was built when the Ctx was made; the point is that it is
    # the SAME near-instant bound, not a fresh 30 s transport timeout.
    assert abs(absolute - started) < 0.5


def test_R21_loaded_headerless_active_plugin_is_guarded(tmp_path, capsys,
                                                        monkeypatch):
    """R21-P1: the bridge now reports a loaded-but-headerless active plugin
    as ACTIVE.  The unit guard must turn its directory into advice and the
    apply must leave every file in it untouched."""
    stacks = []

    def fake_stack(ctx):
        src = MutableFakeSource()
        _active_unit_tree(src)
        bridge = InfoBridge({
            "info": _info(("all-in-one-wp-migration/headerless.php", True)),
            "purge_cache": PURGE_OK,
        })
        stacks.append((src, bridge))
        return (src, None, bridge)

    monkeypatch.setattr(registry_mod, "_stack", fake_stack)
    ctx = _ctx(tmp_path, apply=True, yes=True)
    assert run_action(ctx, "clean-files") == 0
    src, _bridge = stacks[-1]
    out = capsys.readouterr().out
    assert _guard_detail("all-in-one-wp-migration") in out
    assert "wp-content/plugins/all-in-one-wp-migration/home.php" in src.files
    assert out.count("| no |") == 1
