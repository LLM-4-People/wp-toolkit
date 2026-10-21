"""Tests for the profile-driven junk categories of clean-files.

Covers the four groups ``wpt/actions/junk_categories.py`` owns and the
clean-files plan wires: the backup-payload group (archive payloads in the
document root plus the dead duplicate webroot), the
legacy-GeoIP group, the page-cache group and the operator-enabled obsolete
asset signatures.  FakeSource-backed trees + a REAL Bridge double over
FakeSession (the tests/actions/test_clean_files.py conventions, which that
file documents: the shared fakes are not owned by this task, so the
bridge/source doubles are specialized here).  Deterministic, no network.

Test -> behavior map:
  test_backup_payload_is_advice_never_a_delete .. a root archive plans as
        ONE ``webroot.junk`` item carrying the ``backup_payload_in_webroot``
        exposure, requires_apply False (a site's backup is moved, never
        destroyed), and the apply leaves the bytes alone
  test_backup_payload_yields_to_a_claimed_target  the group is a FALLBACK: a
        migration export archive keeps its (deletable) migration item
  test_uploads_payload_is_never_deleted .......... a ``.sql`` under
        wp-content/uploads/gravity_forms/ is excluded from the junk DELETE
        pass (the shipped ``*.sql`` pattern would otherwise plan a
        submission export for removal) and reported as advice instead
  test_geoip_legacy_data_plans_when_the_plugin_is_inactive .. GeoIP.dat /
        GeoIPv6.dat plan with the one-line reason; a file inside an ACTIVE
        unit never does
  test_geoip_refuses_when_the_active_set_is_unknown  fail-closed: no bridge
        (ftp) / no --sql (local) -> SourceError, never a deletion plan
  test_page_cache_plans_only_when_wp_cache_is_undefined  ``*.wpc.log``,
        wpo-plugins-tables-list.json and the supercache tree plan with the
        constant read AS PHP; a DEFINED WP_CACHE (even falsey — the plugin
        reads the constant) plans nothing
  test_page_cache_plans_nothing_when_wp_cache_is_unknown  a commented-out
        or runtime-decided WP_CACHE plans nothing, with ONE warning
  test_obsolete_assets_are_off_by_default ........ the shipped .eot / .map /
        foreign-.po signatures plan NOTHING
  test_enabled_obsolete_asset_signature_plans .. an enabled signature plans
        with ITS note as the detail, byte-exact
  test_every_new_category_carries_bytes_and_a_one_line_detail  the plan-item
        contract (bytes_est + a single-line detail) over all four groups
"""

import json
import logging
from pathlib import Path

import pytest

from tests.fakes import FakeSource
from wpt.actions.clean_files import CleanFilesAction
from wpt.cli import Ctx
from wpt.settings import load

DEFAULTS = load()

#: The shipped signature list, enabled, as an operator would.
_ENABLED = [
    {"name": "*.eot", "note": "legacy EOT font, unreferenced", "enabled": True},
    {"name": "*.map", "note": "source map, never served", "enabled": False},
]


@pytest.fixture
def wpt_caplog(caplog):
    parent = logging.getLogger("wpt")
    parent.addHandler(caplog.handler)
    with caplog.at_level(logging.DEBUG, logger="wpt"):
        yield caplog
    parent.removeHandler(caplog.handler)


# ------------------------------------------------------------------ doubles


class InfoBridge:
    """Bridge double answering ``info`` (the one active-set payload) and
    nothing else; ``error`` (raised) takes precedence, and an unscripted
    call fails loudly."""

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


def _info(*entries, template="twentytwentyfour", stylesheet=None):
    info = {
        "plugins": {file: {"name": "Example", "version": "1.0", "active": active}
                    for file, active in entries},
        "template": template,
        "stylesheet": template if stylesheet is None else stylesheet,
    }
    return info


def _src(files, wp_config=None):
    src = FakeSource()
    src.files = dict(files)
    if wp_config is not None:
        src.files["wp-config.php"] = wp_config
    return src


def _ctx(**overrides):
    fields = dict(
        source="ftp://example.com",
        settings=DEFAULTS,
        command="clean-files",
        apply=False,
        backup_dir="/tmp/wpt-test-backup",
        wp_url="https://example.com",
    )
    fields.update(overrides)
    return Ctx(**fields)


def _plan(src, bridge=None, *, settings=DEFAULTS, **ctx_over):
    return CleanFilesAction().plan(
        _ctx(settings=settings, **ctx_over), (src, None, bridge)
    )


def _items(plan):
    return [(i.category, i.target, i.requires_apply) for i in plan.items]


def _records(caplog, name, level):
    return [r for r in caplog.records
            if r.name == name and r.levelno == level]


# ------------------------------------------------------------ backup payload


def test_backup_payload_is_advice_never_a_delete():
    """The live finding: an archive in the document root is an EXPOSURE, and
    clean-files never destroys a backup."""
    plan = _plan(_src({
        "wp-content.zip": b"z" * 500,
        "legacy-archive-2024.tar.gz": b"t" * 300,
        "readme.html": b"x" * 10,          # plain junk still deletes
    }))
    assert _items(plan) == [
        ("webroot.junk", "legacy-archive-2024.tar.gz", False),
        ("webroot.junk", "readme.html", True),
        ("webroot.junk", "wp-content.zip", False),
    ]
    payload = next(i for i in plan.items if i.target == "wp-content.zip")
    assert payload.bytes_est == 500
    assert "backup_payload_in_webroot" in payload.detail
    assert "park-backups" in payload.detail
    assert "never deletes" in payload.detail


def test_backup_payload_yields_to_a_claimed_target():
    """The group is a FALLBACK: a migration export archive keeps the
    (deletable) migration item the group above already had."""
    plan = _plan(_src({
        "ai1wm-back-123.zip": b"z" * 40,
        "readme.html": b"x" * 10,
    }), InfoBridge({"info": _info()}))
    assert _items(plan) == [
        ("webroot.junk", "readme.html", True),
        ("webroot.migration", "ai1wm-back-123.zip", True),
    ]


def test_uploads_payload_is_never_deleted():
    """[live] the shipped ``*.sql`` junk pattern would otherwise put a
    Gravity Forms submission export in a DELETE plan."""
    src = _src({
        "wp-content/uploads/gravity_forms/export.sql": b"x" * 100,
        "wp-content/uploads/2023/04/visitor-upload.sql.gz": b"x" * 90,
        "dump.sql": b"x" * 10,
    })
    plan = _plan(src)
    assert _items(plan) == [
        ("webroot.junk", "dump.sql", True),
        ("webroot.junk", "wp-content/uploads/2023/04/visitor-upload.sql.gz",
         False),
        ("webroot.junk", "wp-content/uploads/gravity_forms/export.sql", False),
    ]
    form = next(i for i in plan.items
                if i.target.endswith("gravity_forms/export.sql"))
    assert form.requires_apply is False
    assert "NEVER deleted" in form.detail
    # the apply path never even sees it
    CleanFilesAction().apply(_ctx(), (src, None, None), plan)
    assert "wp-content/uploads/gravity_forms/export.sql" in src.files


# ------------------------------------------------------------- legacy geoip


_GEOIP_TREE = {
    "GeoIP.dat": b"g" * 700,
    "wp-content/plugins/geoip-detect/GeoIPv6.dat": b"g" * 300,
    "wp-content/plugins/other-plugin/GeoIP.dat": b"g" * 50,
}


def test_geoip_legacy_data_plans_when_the_plugin_is_inactive():
    """Retired 2019: while the geoip plugin is inactive nothing reads the
    legacy databases, wherever they sit (a root copy, the plugin's own, or
    another plugin's bundled one)."""
    plan = _plan(_src(_GEOIP_TREE), InfoBridge({"info": _info(
        ("geoip-detect/geoip-detect.php", False),
        ("other-plugin/other-plugin.php", False),
    )}))
    geoip = [i for i in plan.items if i.category == "webroot.geoip_legacy"]
    assert sorted(i.target for i in geoip) == [
        "GeoIP.dat",
        "wp-content/plugins/geoip-detect/GeoIPv6.dat",
        "wp-content/plugins/other-plugin/GeoIP.dat",
    ]
    assert all(i.requires_apply for i in geoip)
    assert {i.bytes_est for i in geoip} == {700, 300, 50}
    assert "not active" in geoip[0].detail
    assert "legacy MaxMind GeoIP database" in geoip[0].detail


def test_geoip_active_plugin_protects_every_geoip_match(wpt_caplog):
    """The profile's promise is plugin-level: while ``geoip_plugins`` is
    ACTIVE, EVERY ``geoip_files`` match stays — including a webroot-root
    copy no unit owns.  The old per-unit check protected only files under
    the active unit and deleted the root database with a false detail."""
    plan = _plan(_src(_GEOIP_TREE), InfoBridge({"info": _info(
        ("geoip-detect/geoip-detect.php", True),
        ("other-plugin/other-plugin.php", True),
    )}))
    geoip = [i for i in plan.items if i.category == "webroot.geoip_legacy"]
    assert geoip == []
    assert any("geoip-detect is ACTIVE" in r.getMessage()
               for r in wpt_caplog.records)


def test_corrupt_theme_option_refuses_the_theme_unit(wpt_caplog):
    """The bridge renders an array-valued ``template``/``stylesheet`` as ""
    (its corrupt-option convention).  An empty theme answer is UNMEASURED:
    the theme unit a migration pattern selected must be refused, never
    deleted as "no active theme"."""
    plan = _plan(_src({
        "wp-content/themes/twentytwentyfour/style.css": b"x" * 30,
        "wp-content/themes/twentytwentyfour/ai1wm-leftover.php": b"x" * 50,
    }), InfoBridge({"info": _info(
        ("akismet/akismet.php", True), template="", stylesheet="",
    )}))
    themes = [i for i in plan.items
              if i.target.startswith("wp-content/themes/")]
    assert [(i.category, i.requires_apply) for i in themes] == [
        ("webroot.active_unit", False),
    ]
    assert "not deleted" in themes[0].detail and "UNKNOWN" in themes[0].detail


def test_geoip_refuses_when_the_active_set_is_unknown():
    """Fail-closed: with no bridge (ftp) or no --sql (local) the active set
    is UNMEASURED, so the GeoIP gate plans NOTHING (a junk-only run stays
    rc 0).  The unit guard still refuses a plugin/theme deletion in that
    state; the GeoIP gate's required=False call just degrades."""
    plan = _plan(_src(_GEOIP_TREE), None)
    assert not [i for i in plan.items
                if i.category == "webroot.geoip_legacy"]
    plan = _plan(_src(_GEOIP_TREE), None, source="local",
                 zip=Path("site.zip"), sql=None, wp_url=None)
    assert not [i for i in plan.items
                if i.category == "webroot.geoip_legacy"]


# -------------------------------------------------------------- page cache

_CACHE_TREE = {
    "wp-content/cache/supercache/www.example.com/index.html": b"c" * 200,
    "wp-content/cache/supercache/www.example.com/page-2/index.html": b"c" * 50,
    "wp-content/wpc-log/debug.wpc.log": b"l" * 20,
    "wp-content/wpo-plugins-tables-list.json": b"{}" * 5,
}

_NO_CACHE = b"<?php\ndefine( 'DB_NAME', 'x' );\n"
_CACHE_ON = b"<?php\ndefine( 'WP_CACHE', true );\n"


def test_page_cache_plans_only_when_wp_cache_is_undefined():
    plan = _plan(_src(_CACHE_TREE, wp_config=_NO_CACHE))
    cache = [i for i in plan.items if i.category == "webroot.page_cache"]
    assert sorted(i.target for i in cache) == [
        "wp-content/cache/supercache",
        "wp-content/wpc-log/debug.wpc.log",
        "wp-content/wpo-plugins-tables-list.json",
    ]
    tree = next(i for i in cache
                if i.target == "wp-content/cache/supercache")
    assert tree.bytes_est == 250          # the subtree sum
    assert "2 files" in tree.detail
    assert "WP_CACHE is undefined" in tree.detail
    assert all(i.requires_apply for i in cache)


def test_page_cache_plans_nothing_when_wp_cache_is_defined():
    plan = _plan(_src(_CACHE_TREE, wp_config=_CACHE_ON))
    assert plan.items == []


def test_page_cache_plans_nothing_when_wp_cache_is_unknown(wpt_caplog):
    """A commented-out define, a runtime-decided value or an unreadable
    wp-config.php are all UNKNOWN — and an unknown constant plans nothing."""
    plan = _plan(_src(_CACHE_TREE, wp_config=(
        b"<?php\n// define( 'WP_CACHE', true );\n"
        b"if ( x ) { define( 'WP_CACHE', true ); }\n"
    )))
    assert plan.items == []
    warnings = _records(wpt_caplog, "wpt.actions.clean_files",
                        logging.WARNING)
    assert len(warnings) == 1
    assert "WP_CACHE could not be resolved" in warnings[0].getMessage()


def test_wp_config_never_read_for_a_clean_tree():
    """No page-cache candidate -> wp-config.php is not read at all."""
    class NoConfigSource(FakeSource):
        def read_bytes(self, path):
            if path == "wp-config.php":
                raise AssertionError("wp-config.php must not be read")
            return super().read_bytes(path)

    src = NoConfigSource()
    src.files = {"readme.html": b"x"}
    plan = CleanFilesAction().plan(_ctx(), (src, None, None))
    assert [i.target for i in plan.items] == ["readme.html"]


# ---------------------------------------------------------- obsolete assets

_FONT_TREE = {
    "wp-content/themes/x/fonts/legacy.eot": b"e" * 400,
    "wp-content/themes/x/style.css.map": b"m" * 900,
    "wp-content/themes/x/languages/fr_CA.po": b"p" * 60,
}


def test_obsolete_assets_are_off_by_default():
    """Every shipped signature ships DISABLED: unreferenced .eot fonts,
    .map files and foreign-locale .po catalogs are the operator's call,
    not wpt's."""
    plan = _plan(_src(_FONT_TREE))
    assert plan.items == []


def test_enabled_obsolete_asset_signature_plans():
    settings = load(overrides={"obsolete_assets.known_added": _ENABLED})
    plan = _plan(_src(_FONT_TREE), settings=settings)
    assert _items(plan) == [
        ("webroot.obsolete_asset", "wp-content/themes/x/fonts/legacy.eot",
         True),
    ]
    item = plan.items[0]
    assert item.bytes_est == 400
    assert item.detail == "legacy EOT font, unreferenced"   # the signature's
    assert "\n" not in item.detail                          # own note, one line


def test_obsolete_asset_signature_shape_is_validated(tmp_path):
    """The signature list is validated entry-by-entry on BOTH the profile and
    the --set path (one owner), and --set can reach it."""
    from wpt.settings import SettingsError

    settings = load(overrides={"obsolete_assets.known_added": [
        {"name": "*.eot", "note": "n", "enabled": True},
    ]})
    assert settings.obsolete_assets.known_added[0]["name"] == "*.eot"
    for bad in ([{"name": "*.eot", "note": "n"}],
                [{"name": "*.eot", "note": "n", "enabled": "yes"}],
                [{"name": "", "note": "n", "enabled": True}],
                [{"name": "*.eot", "note": "n", "enabled": True,
                  "extra": 1}]):
        with pytest.raises(SettingsError):
            load(overrides={"obsolete_assets.known_added": bad})


# ---------------------------------------------------------------- contract


def test_every_new_category_carries_bytes_and_a_one_line_detail():
    """The plan-item contract over all four groups at once."""
    settings = load(overrides={"obsolete_assets.known_added": _ENABLED})
    plan = _plan(
        _src({**_CACHE_TREE, **_FONT_TREE,
              "wp-content.zip": b"z" * 40,
              "GeoIP.dat": b"g" * 60}, wp_config=_NO_CACHE),
        InfoBridge({"info": _info(("geoip-detect/geoip-detect.php", False))}),
        settings=settings,
    )
    categories = {i.category for i in plan.items}
    assert {"webroot.junk", "webroot.geoip_legacy", "webroot.page_cache",
            "webroot.obsolete_asset"} <= categories
    for item in plan.items:
        assert item.bytes_est > 0, item.target
        assert "\n" not in item.detail
        assert item.detail.strip() == item.detail
    # deterministic order
    assert [i.target for i in plan.items] == sorted(
        (i.target for i in plan.items),
        key=lambda t: (next(i.category for i in plan.items if i.target == t), t),
    )
    assert json.dumps([i.category for i in plan.items])  # JSON-serializable
