"""Tests for the harden action (wpt.actions.harden) — W7h.

FakeSource-backed config pairs (tests/actions/test_clean_files.py
conventions): deterministic, no network, no sleeps.  The registry
end-to-end tests monkeypatch ``wpt.actions.registry._stack`` (the pinned
seam) to run the real ``run_action`` flow over a fake ftp-mode stack.

The appended .htaccess block and the wp-config define line are pinned by
INDEPENDENT literals here (EXPECTED_BLOCK / DEFINE_LINE) — a drift from
the coordinator-pinned design text fails these tests even though the
action's own constants stay self-consistent.

Test -> behavior map (W7h task list):
  test_registration ..................... harden registered as the
        INSTANCE under applies=("ftp", "local")
  test_plan_fresh_two_items ............. fresh .htaccess + wp-config ->
        exactly two items (category/target/detail/bytes_est pinned),
        backup_tables == [], one-line details, the proposed block AND
        define line logged at info (the diff-printed surface), one
        summary
  test_plan_marker_present_no_htaccess_ . marker in .htaccess -> NO
        htaccess item (wp-config still planned); no block proposal log
  test_plan_disallow_present_no_wpconfig DISALLOW_FILE_EDIT already in
        wp-config -> NO wp-config item (htaccess still planned)
  test_plan_missing_htaccess_new_file .. missing .htaccess -> item whose
        detail notes "new file"; the proposal is logged as a new file
  test_plan_missing_wpconfig_skips_.... missing wp-config -> NO crash,
        NO item, exactly ONE warning
  test_plan_both_hardened_empty ........ marker + define present ->
        empty plan, backup_tables == [], no warnings
  test_apply_htaccess_exact_bytes ...... appended block byte-compared
        against the independent literal for three source shapes: ends
        with newline, NO trailing newline, missing file; appended
        exactly ONCE (one marker occurrence), one write op
  test_apply_wpconfig_inserts_before_.. define inserted BEFORE the
        wp-settings require (index order pinned, count 1), result
        byte-exact, writes in plan order
  test_apply_wpconfig_no_require_...... no require line -> define
        APPENDED at the end (the source's missing trailing newline is
        added first) + exactly ONE warning; byte-exact
  test_apply_failure_continues ........ one injected write failure:
        that item done=False + one warning, the other still hardened
  test_apply_already_hardened_no_...... fresh idempotency at apply:
        both files hardened behind the plan's back -> done=True +
        ", already hardened" details, NO write
  test_apply_then_plan_is_empty ........ apply then a fresh plan ->
        zero items (the action-level idempotency pin)
  test_registry_dry_run_zero_writes .... rc 0, both items printed,
        ZERO writes, no snapshot taken
  test_registry_ftp_apply_end_to_end .. rc 0; both files written via
        allow_config=True (spy-pinned); the manifest lists BOTH config
        files captured BEFORE mutation with the ORIGINAL bytes; both
        applied rows printed
  test_registry_apply_twice_second_.... after a registry apply, a
        second registry run (dry) shows an EMPTY plan — applying twice
        plans nothing, and no further writes happen

WordPress permalink block (the live migration defect: harden once
created a root .htaccess with ONLY its own block on a pretty-permalink
site and every subpage + /wp-json 404'd):
  test_plan_pretty_permalinks_plans_ . pretty permalinks via the bridge
        info payload -> the WP item follows OUR item (category/target/
        detail pinned), the full canonical WP block logged at info
  test_local_rehearsal_materializes_ . the registry LOCAL flow end to
        end: dry run prints BOTH .htaccess items; --apply rehearses and
        materializes a zip whose fresh .htaccess carries BOTH blocks,
        OURS FIRST (the HTTPS force precedes the WP catch-all [L]);
        the original zip stays the untouched rollback
  test_plan_existing_wp_block_only_... existing canonical WP block ->
        only OUR item planned, the WP block byte-untouched, idempotent
  test_wp_block_already_hardened_no_. both blocks landed behind the
        plan's back -> both items settle, already hardened, NO write
  test_plain_or_absent_permalinks_no_  '' (measured plain) and an absent
        payload key both mean NOT pretty: no WP item (ftp + local)
  test_local_plain_permalinks_no_word '' and an absent option row in
        the dump: no WP item (the local seam, plan level)
  test_a_defaced_wp_block_is_treated_. commented-out markers, the
        no-space marker spelling, a truncated pair, a conditional
        wrapper: ALL read as MISSING (the R1 whole-line marker-pair
        discipline on WordPress's own markers)
  test_wp_block_proof_requires_the_... presence-check unit pins: exact
        canonical body only, indentation tolerated, every defacement
        rejected
  test_wp_block_write_that_does_not_.. read-back verification: a
        truncated write fails the WP item (never reported done)
  test_apply_refuses_when_permalinks_ . the fact is RE-DERIVED at apply:
        a flip to plain permalinks behind the plan's back refuses the
        item (warning, nothing written by it)
  test_anchor_analysis_matches_php_semantics .. the require anchor is
        placed exactly where PHP would execute it (a parameterised table
        over the shapes that decide it: braces, alternative syntax,
        arrow bodies, `declare`, namespaces)
  test_anchor_scan_of_repeated_declares_is_linear /
  ..._nested_declare_parens_is_bounded /
  ..._many_arrow_functions_is_linear . the anchor scan's COST, measured
        by the statements it executes per byte against a flat file of the
        same order (never by the clock: a ratio bound with a floor IS a
        wall-clock assertion whenever the floor binds, and these flaked
        under load) — a look-ahead, a re-scan or a copy that grows with
        the REST of the file instead of with the current level fails them
"""

import json
import logging

import pytest

from tests.fakes import FakeSource
from wpt.actions import registry as registry_mod
from wpt.actions.harden import HardenAction
from wpt.actions.registry import get_action, run_action
from wpt.audit.security import _php_const_state
from wpt.cli import Ctx
from wpt.settings import load
from wpt.types import SourceError

#: The shipped profile — exactly as users get it (harden consumes no
#: tunables; the block content is structural, not a profile knob).
DEFAULTS = load()

#: The exact block an apply must append — INDEPENDENT of the action's
#: own constant, so a block edit that drifts from the pinned design
#: text fails here.
EXPECTED_BLOCK = (
    "# BEGIN wpt-harden\n"
    "Options -Indexes\n"
    "\n"
    "<IfModule mod_rewrite.c>\n"
    "RewriteEngine On\n"
    "# Force HTTPS\n"
    "RewriteCond %{HTTPS} !=on\n"
    "RewriteRule ^/? https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n"
    "# Block REST user enumeration (pretty permalink)\n"
    "RewriteRule ^/?wp-json/wp/v2/users - [F]\n"
    "# Block the ?rest_route= fallback (WordPress dispatches it too)\n"
    "RewriteCond %{QUERY_STRING} (^|&)rest_route=(?:%2F|/)+wp"
    "(?:%2F|/)v2(?:%2F|/)users(?:%2F|/|&|$) [NC]\n"
    "RewriteRule ^/? - [F]\n"
    "# Block author-scan user enumeration\n"
    "RewriteCond %{QUERY_STRING} author=\\d [NC]\n"
    "RewriteRule ^/? - [F]\n"
    "</IfModule>\n"
    "\n"
    "# Block XML-RPC\n"
    "<Files xmlrpc.php>\n"
    "<IfModule mod_authz_core.c>\n"
    "Require all denied\n"
    "</IfModule>\n"
    "<IfModule !mod_authz_core.c>\n"
    "Order Deny,Allow\n"
    "Deny from all\n"
    "</IfModule>\n"
    "</Files>\n"
    "# END wpt-harden"
).encode("ascii")

#: The exact wp-config define line (binding text). Fully qualified so it still
#: defines the GLOBAL constant when wp-config.php sits in a namespace.
DEFINE_LINE = b"\\define( 'DISALLOW_FILE_EDIT', true );"

#: A realistic-but-secret-free wp-config fixture — the wp-settings
#: bootstrap require is the insertion anchor.
WP_CONFIG = (
    b"<?php\n"
    b"define( 'DB_NAME', 'example_db' );\n"
    b"define( 'DB_HOST', 'localhost' );\n"
    b"require_once( dirname( __FILE__ ) . '/wp-settings.php' );\n"
)

#: A plain pre-existing .htaccess (no wpt markers).
HTACCESS = b"RewriteEngine On\nRewriteBase /\n"

#: The one-line plan details, pinned from the design text.
HTACCESS_DETAIL = (
    "diff-printed hardening block (HTTPS redirect, Options -Indexes, "
    "xmlrpc block, REST users block, author-scan block)"
)

#: The canonical WordPress permalink block — INDEPENDENT literal pinned
#: from WP core's own ``mod_rewrite_rules()`` output
#: (wp-includes/class-wp-rewrite.php, verified against source): the exact
#: bytes WordPress itself writes between the markers for a webroot install.
#: Without its ``RewriteRule . /index.php [L]`` catch-all every pretty-
#: permalink route (subpages, /wp-json) 404s — the live migration defect.
EXPECTED_WP_BLOCK = (
    "# BEGIN WordPress\n"
    "<IfModule mod_rewrite.c>\n"
    "RewriteEngine On\n"
    "RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]\n"
    "RewriteBase /\n"
    "RewriteRule ^index\\.php$ - [L]\n"
    "RewriteCond %{REQUEST_FILENAME} !-f\n"
    "RewriteCond %{REQUEST_FILENAME} !-d\n"
    "RewriteRule . /index.php [L]\n"
    "</IfModule>\n"
    "# END WordPress"
).encode("ascii")

#: The WP-block item's one-line plan detail, pinned from the design text.
WP_PERMALINK_DETAIL = (
    "WordPress permalink block (missing; pretty permalinks active)"
)

#: A pretty permalink_structure value for the fixtures.
PRETTY_PERMALINKS = "/%year%/%monthnum%/%day%/%postname%/"


@pytest.fixture
def wpt_caplog(caplog):
    """caplog wired to the non-propagating wpt logger tree (see
    tests/actions/test_clean_files.py — the wpt parent never reaches root)."""
    parent = logging.getLogger("wpt")
    parent.addHandler(caplog.handler)
    with caplog.at_level(logging.DEBUG, logger="wpt"):
        yield caplog
    parent.removeHandler(caplog.handler)


class ConfigWriteSpySource(FakeSource):
    """FakeSource recording (path, allow_config) per write call — pins
    that the action unlocks BOTH protected config files correctly."""

    def __init__(self):
        super().__init__()
        self.config_writes: list[tuple[str, bool]] = []

    def write_bytes(self, path, data, *, allow_config=False):
        self.config_writes.append((path, allow_config))
        super().write_bytes(path, data, allow_config=allow_config)


class FailingConfigWriteSource(ConfigWriteSpySource):
    """write_bytes fails (SourceError) for every path in fail_paths."""

    def __init__(self, fail_paths):
        super().__init__()
        self.fail_paths = set(fail_paths)

    def write_bytes(self, path, data, *, allow_config=False):
        if path in self.fail_paths:
            raise SourceError(f"injected write failure: {path}")
        super().write_bytes(path, data, allow_config=allow_config)


def _ctx(tmp_path, **overrides):
    """A harden Ctx; ftp-mode defaults, overridable per test."""
    fields = dict(
        source="ftp://example.com",
        settings=DEFAULTS,
        command="harden",
        apply=False,
        yes=False,
        backup_dir=tmp_path / "backup",
        wp_url="https://example.com",
    )
    fields.update(overrides)
    return Ctx(**fields)


def _records(caplog, level):
    return [
        r
        for r in caplog.records
        if r.name == "wpt.actions.harden" and r.levelno == level
    ]


def _write_ops(src):
    return [path for _ts, op, path in src.ops if op == "write"]


class FakeBridge:
    """The stack's bridge double: ``call("info")`` answers a canned payload
    (real ftp stacks always carry a Bridge; unit stacks passed None)."""

    def __init__(self, payload):
        self.calls: list[str] = []
        self.payload = dict(payload)

    def call(self, action, **params):
        self.calls.append(action)
        return dict(self.payload)


def _bridge(pretty=PRETTY_PERMALINKS):
    """A stack bridge answering a pretty (``""`` = plain, ``None`` = the
    payload key absent, a degraded/older bridge answer)."""
    if pretty is None:
        return FakeBridge({})
    return FakeBridge({"permalink_structure": pretty})


def _dump_bytes(permalink_structure):
    """A minimal real-shape wp_options dump section (the phpMyAdmin shape
    from tests/test_e2e_local.py).  ``permalink_structure is None`` = the
    option row absent — WordPress's own plain-permalink default."""
    rows = [("1", "siteurl", "https://example.com", "yes")]
    if permalink_structure is not None:
        rows.append(("2", "permalink_structure", permalink_structure, "yes"))
    values = ",\n".join(
        "(" + ", ".join("'%s'" % cell for cell in row) + ")" for row in rows
    )
    return (
        "CREATE TABLE `wp_options` (\n"
        "  `option_id` bigint(20) UNSIGNED NOT NULL,\n"
        "  `option_name` varchar(191) NOT NULL DEFAULT '',\n"
        "  `option_value` longtext NOT NULL,\n"
        "  `autoload` varchar(20) NOT NULL DEFAULT 'yes'\n"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n"
        "INSERT INTO `wp_options` (`option_id`, `option_name`, "
        "`option_value`, `autoload`) VALUES\n" + values + ";\n"
    ).encode()


def _local_ctx(tmp_path, zip_path, sql_path, **overrides):
    """A harden Ctx in LOCAL mode — the dump is the permalink seam."""
    fields = dict(
        source="local",
        settings=DEFAULTS,
        command="harden",
        apply=False,
        yes=False,
        backup_dir=tmp_path / "backup",
        wp_url="https://example.com",
        zip=zip_path,
        sql=sql_path,
    )
    fields.update(overrides)
    return Ctx(**fields)


# ------------------------------------------------------------- registration


def test_registration():
    record = get_action("harden")
    assert record is not None
    assert record.applies == ("ftp", "local")
    assert isinstance(record.action, HardenAction)  # the instance


# ------------------------------------------------------------------- plan


def test_plan_fresh_two_items(tmp_path, wpt_caplog):
    src = FakeSource()
    src.files = {".htaccess": HTACCESS, "wp-config.php": WP_CONFIG}
    plan = HardenAction().plan(_ctx(tmp_path), (src, None, None))
    assert [
        (i.category, i.target, i.detail, i.bytes_est) for i in plan.items
    ] == [
        ("webroot.hardening", ".htaccess", HTACCESS_DETAIL, 0),
        ("webroot.hardening", "wp-config.php", "add DISALLOW_FILE_EDIT", 0),
    ]
    assert all(i.requires_apply for i in plan.items)
    assert all(not i.done for i in plan.items)
    assert plan.backup_tables == []  # deliberate: files only
    assert plan.est_bytes() == 0
    # one-line details (render_report prints one table line per item)
    assert all("\n" not in i.detail for i in plan.items)
    # the diff-printed surface: the FULL proposal logged at info
    infos = _records(wpt_caplog, logging.INFO)
    assert any(EXPECTED_BLOCK.decode("ascii") in r.getMessage() for r in infos)
    proposal = [
        r for r in infos if "wp-config.php change" in r.getMessage()
    ]
    assert len(proposal) == 1
    assert DEFINE_LINE.decode("ascii") in proposal[0].getMessage()
    assert "inserted before" in proposal[0].getMessage()
    # exactly one plan summary
    summaries = [r for r in infos if r.getMessage().startswith("plan: ")]
    assert len(summaries) == 1
    assert "2 item(s)" in summaries[0].getMessage()
    assert not _records(wpt_caplog, logging.WARNING)


def test_plan_marker_present_no_htaccess_item(tmp_path, wpt_caplog):
    from wpt.actions.harden import _HTACCESS_BLOCK_BYTES
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS + _HTACCESS_BLOCK_BYTES,
        "wp-config.php": WP_CONFIG,
    }
    plan = HardenAction().plan(_ctx(tmp_path), (src, None, None))
    assert [i.target for i in plan.items] == ["wp-config.php"]
    # no block proposal logged for the already-marked file
    assert not [
        r
        for r in _records(wpt_caplog, logging.INFO)
        if "proposed" in r.getMessage() and ".htaccess" in r.getMessage()
    ]


def test_a_bare_marker_is_not_proof_of_hardening(tmp_path):
    # A substring of the marker used to suppress the write, so a truncated
    # block, an empty marker pair or a comment mentioning it all left the
    # protections absent while the item reported done.
    from wpt.actions.harden import _HTACCESS_BLOCK_BYTES
    partials = (
        b"# BEGIN wpt-harden\n",
        b"# BEGIN wpt-harden\n# END wpt-harden\n",
        b"# a note about # BEGIN wpt-harden\n",
        b"# BEGIN wpt-harden\nOptions -Indexes\n# END wpt-harden\n",
    )
    for partial in partials:
        src = FakeSource()
        src.files = {".htaccess": HTACCESS + partial, "wp-config.php": WP_CONFIG}
        action = HardenAction()
        ctx = _ctx(tmp_path, apply=True, yes=True)
        plan = action.plan(ctx, (src, None, None))
        assert ".htaccess" in [i.target for i in plan.items], partial
        action.apply(ctx, (src, None, None), plan)
        stored = src.files[".htaccess"]
        assert b"Options -Indexes" in stored, partial
        # the complete block is now present exactly once
        assert stored.count(_HTACCESS_BLOCK_BYTES) == 1, partial
        # and a second run changes nothing
        before = bytes(stored)
        HardenAction().apply(ctx, (src, None, None), plan)
        assert src.files[".htaccess"] == before, partial


def test_a_block_inside_an_inactive_ifmodule_is_not_proof(tmp_path):
    # Apache ignores every directive inside an <IfModule> whose module is not
    # loaded, so the block is present but the protections are absent.
    from wpt.actions.harden import _HTACCESS_BLOCK_BYTES
    wrapped = (b"<IfModule definitely_not_loaded.c>\n"
               + _HTACCESS_BLOCK_BYTES
               + b"</IfModule>\n")
    src = FakeSource()
    src.files = {".htaccess": HTACCESS + wrapped, "wp-config.php": WP_CONFIG}
    plan = HardenAction().plan(_ctx(tmp_path), (src, None, None))
    assert ".htaccess" in [i.target for i in plan.items]
    action = HardenAction()
    ctx = _ctx(tmp_path, apply=True, yes=True)
    plan = action.plan(ctx, (src, None, None))
    action.apply(ctx, (src, None, None), plan)
    stored = src.files[".htaccess"]
    # the block is now present at top level, so a second run is a no-op
    assert stored.count(_HTACCESS_BLOCK_BYTES) == 2
    before = bytes(stored)
    HardenAction().apply(ctx, (src, None, None), plan)
    assert src.files[".htaccess"] == before


def test_a_closed_ifmodule_around_the_block_is_fine():
    from wpt.actions.harden import _HTACCESS_BLOCK, _htaccess_is_hardened
    assert _htaccess_is_hardened(
        f"<IfModule mod_x.c>\n</IfModule>\n{_HTACCESS_BLOCK}")


@pytest.mark.parametrize("wrap", [
    # a wrapper INSIDE the markers: the directives are inactive
    "inside",
    # a wrapper AROUND the block: the opening marker itself is conditional
    "around",
])
def test_a_wrapper_that_disables_the_block_is_not_proof(wrap):
    # Our own block wraps part of itself in <IfModule mod_rewrite.c>, so a
    # conditional-depth test would reject the very block we install. Matching
    # the canonical body, plus requiring an unconditional opening marker,
    # accepts ours and rejects every reconstruction.
    from wpt.actions.harden import (
        _HTACCESS_BLOCK,
        _HTACCESS_MARKER_BEGIN,
        _HTACCESS_MARKER_END,
        _htaccess_is_hardened,
    )
    body = "\n".join(_HTACCESS_BLOCK.splitlines()[1:-1])
    if wrap == "inside":
        text = (f"{_HTACCESS_MARKER_BEGIN}\n<IfModule absent.c>\n{body}\n"
                "</IfModule>\n" f"{_HTACCESS_MARKER_END}")
    else:
        text = f"<IfModule absent.c>\n{_HTACCESS_BLOCK}\n</IfModule>"
    assert not _htaccess_is_hardened(text)
    # indentation alone must not defeat the comparison
    assert _htaccess_is_hardened(
        f"{_HTACCESS_MARKER_BEGIN}\n"
        + "\n".join("  " + line for line in body.splitlines())
        + f"\n{_HTACCESS_MARKER_END}")


def test_plan_disallow_present_no_wpconfig_item(tmp_path):
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS,
        "wp-config.php": WP_CONFIG + DEFINE_LINE + b"\n",
    }
    plan = HardenAction().plan(_ctx(tmp_path), (src, None, None))
    assert [i.target for i in plan.items] == [".htaccess"]


def test_plan_commented_disallow_is_not_hardened(tmp_path):
    # The literal in a comment is not a definition: the item is planned.
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS + EXPECTED_BLOCK + b"\n",
        "wp-config.php": WP_CONFIG + b"// " + DEFINE_LINE + b"\n",
    }
    plan = HardenAction().plan(_ctx(tmp_path), (src, None, None))
    assert [i.target for i in plan.items] == ["wp-config.php"]


def test_plan_false_disallow_is_not_hardened(tmp_path):
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS + EXPECTED_BLOCK + b"\n",
        "wp-config.php": WP_CONFIG + b"define( 'DISALLOW_FILE_EDIT', false );\n",
    }
    plan = HardenAction().plan(_ctx(tmp_path), (src, None, None))
    assert [i.target for i in plan.items] == ["wp-config.php"]


def test_plan_file_mods_suppresses_wpconfig_item(tmp_path):
    # DISALLOW_FILE_MODS closes the editor too, so there is nothing to add.
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS + EXPECTED_BLOCK + b"\n",
        "wp-config.php": WP_CONFIG + b"define( 'DISALLOW_FILE_MODS', true );\n",
    }
    plan = HardenAction().plan(_ctx(tmp_path), (src, None, None))
    assert [i.target for i in plan.items] == []


def test_plan_indeterminate_disallow_is_left_to_a_human(tmp_path, wpt_caplog):
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS + EXPECTED_BLOCK + b"\n",
        "wp-config.php": WP_CONFIG + b"define( 'DISALLOW_FILE_EDIT', !0 );\n",
    }
    plan = HardenAction().plan(_ctx(tmp_path), (src, None, None))
    # An APPLICABLE item apply will refuse. Omitting it would make the plan
    # vacuously complete: rc 0 and a "hardened" report for an untouched file.
    assert [i.target for i in plan.items] == ["wp-config.php"]
    assert "cannot be resolved" in plan.items[0].detail
    assert any(
        "cannot be resolved statically" in r.getMessage()
        for r in _records(wpt_caplog, logging.WARNING)
    )


def test_plan_missing_htaccess_new_file_item(tmp_path, wpt_caplog):
    src = FakeSource()
    # wp-config pre-hardened: the plan isolates the .htaccess item
    src.files = {"wp-config.php": WP_CONFIG + DEFINE_LINE + b"\n"}
    plan = HardenAction().plan(_ctx(tmp_path), (src, None, None))
    assert [(i.target, i.detail) for i in plan.items] == [
        (".htaccess", HTACCESS_DETAIL + " (new file)")
    ]
    assert any(
        "proposed new .htaccess" in r.getMessage()
        for r in _records(wpt_caplog, logging.INFO)
    )


def test_plan_missing_wpconfig_skips_with_warning(tmp_path, wpt_caplog):
    src = FakeSource()
    src.files = {".htaccess": HTACCESS}
    plan = HardenAction().plan(_ctx(tmp_path), (src, None, None))
    assert [i.target for i in plan.items] == [".htaccess"]  # no crash
    warnings = _records(wpt_caplog, logging.WARNING)
    assert len(warnings) == 1
    assert "wp-config.php" in warnings[0].getMessage()


def test_plan_both_hardened_empty(tmp_path, wpt_caplog):
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS + EXPECTED_BLOCK + b"\n",
        "wp-config.php": WP_CONFIG + DEFINE_LINE + b"\n",
    }
    plan = HardenAction().plan(_ctx(tmp_path), (src, None, None))
    assert plan.items == []
    assert plan.backup_tables == []
    assert plan.est_bytes() == 0
    assert not _records(wpt_caplog, logging.WARNING)


# ------------------------------------------------------------------ apply


def test_apply_htaccess_exact_bytes(tmp_path):
    action = HardenAction()
    for current, expected in [
        # ends with newline: block follows directly
        (HTACCESS, HTACCESS + EXPECTED_BLOCK + b"\n"),
        # NO trailing newline: exactly one is added before the block
        (b"RewriteEngine On", b"RewriteEngine On\n" + EXPECTED_BLOCK + b"\n"),
        # missing file: created with the block, no leading blank line
        (None, EXPECTED_BLOCK + b"\n"),
    ]:
        src = FakeSource()
        if current is not None:
            src.files = {".htaccess": current}
        plan = action.plan(_ctx(tmp_path), (src, None, None))
        assert [i.target for i in plan.items] == [".htaccess"]
        applied = action.apply(_ctx(tmp_path), (src, None, None), plan)
        assert applied is plan  # the same Plan object, updated in place
        assert all(i.done for i in applied.items)
        assert src.files[".htaccess"] == expected  # byte-exact
        # appended exactly ONCE: one marker occurrence, one write op
        assert src.files[".htaccess"].count(b"# BEGIN wpt-harden") == 1
        assert _write_ops(src) == [".htaccess"]


def test_apply_wpconfig_inserts_before_require(tmp_path, wpt_caplog):
    src = FakeSource()
    src.files = {".htaccess": HTACCESS, "wp-config.php": WP_CONFIG}
    action = HardenAction()
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, (src, None, None))
    applied = action.apply(ctx, (src, None, None), plan)
    assert all(i.done for i in applied.items)
    hardened = src.files["wp-config.php"]
    # byte-exact: NOTHING but the define line was inserted
    assert hardened == (
        b"<?php\n"
        b"define( 'DB_NAME', 'example_db' );\n"
        b"define( 'DB_HOST', 'localhost' );\n"
        + DEFINE_LINE
        + b"\n"
        b"require_once( dirname( __FILE__ ) . '/wp-settings.php' );\n"
    )
    # ORDER: the define lands BEFORE the wp-settings require, never after
    assert hardened.count(DEFINE_LINE) == 1
    assert hardened.index(DEFINE_LINE) < hardened.index(b"wp-settings.php")
    # writes in plan order: .htaccess first, then wp-config.php
    assert _write_ops(src) == [".htaccess", "wp-config.php"]
    assert not _records(wpt_caplog, logging.WARNING)


def test_apply_wpconfig_no_require_appends_with_warning(tmp_path, wpt_caplog):
    # a config with NO wp-settings require line; also no trailing
    # newline — one is added before the appended define
    config = b"<?php\ndefine( 'DB_NAME', 'example_db' );"
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS + EXPECTED_BLOCK + b"\n",  # already hardened
        "wp-config.php": config,
    }
    action = HardenAction()
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, (src, None, None))
    assert [i.target for i in plan.items] == ["wp-config.php"]
    applied = action.apply(ctx, (src, None, None), plan)
    assert all(i.done for i in applied.items)
    assert src.files["wp-config.php"] == config + b"\n" + DEFINE_LINE + b"\n"
    warnings = _records(wpt_caplog, logging.WARNING)
    assert len(warnings) == 1
    assert "wp-settings" in warnings[0].getMessage()


def test_apply_commented_disallow_inserts_a_real_define(tmp_path):
    # The old substring idempotency test saw the literal in the comment and
    # skipped the write, leaving the site unhardened forever.
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS + EXPECTED_BLOCK + b"\n",
        "wp-config.php": WP_CONFIG + b"// " + DEFINE_LINE + b"\n",
    }
    action = HardenAction()
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, (src, None, None))
    assert [i.target for i in plan.items] == ["wp-config.php"]
    applied = action.apply(ctx, (src, None, None), plan)
    assert all(i.done for i in applied.items)
    hardened = src.files["wp-config.php"]
    assert hardened.count(DEFINE_LINE) == 2  # the comment plus the real one
    assert hardened.index(b"\n" + DEFINE_LINE) < hardened.index(b"wp-settings.php")


def test_apply_false_disallow_rewrites_the_value_in_place(tmp_path):
    # Appending a second define cannot work: PHP keeps the first definition.
    # The existing falsey value must be rewritten instead.
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS + EXPECTED_BLOCK + b"\n",
        "wp-config.php": WP_CONFIG + b"define( 'DISALLOW_FILE_EDIT', false );\n",
    }
    action = HardenAction()
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, (src, None, None))
    assert [i.target for i in plan.items] == ["wp-config.php"]
    applied = action.apply(ctx, (src, None, None), plan)
    assert all(i.done for i in applied.items)
    hardened = src.files["wp-config.php"]
    assert hardened.count(b"DISALLOW_FILE_EDIT") == 1
    assert b"false" not in hardened
    # the real invariant: one ACTIVE truthy definition, not a byte spelling
    assert _php_const_state(
        hardened.decode(), "DISALLOW_FILE_EDIT"
    ) == "truthy"
    # the write is idempotent: a second plan is empty
    assert HardenAction().plan(ctx, (src, None, None)).items == []


def test_apply_false_disallow_preserves_undecodable_bytes(tmp_path):
    # The in-place rewrite decodes to scan the PHP, so it must round-trip
    # undecodable bytes verbatim: a replace-decode would rewrite them as
    # U+FFFD and corrupt wp-config.php.
    config = (
        b"<?php\n"
        b"define( 'DB_NAME', 'example_db' );\n"
        b"// latin-1 comment: caf\xe9\n"
        b"define( 'DISALLOW_FILE_EDIT', false );\n"
    )
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS + EXPECTED_BLOCK + b"\n",
        "wp-config.php": config,
    }
    action = HardenAction()
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, (src, None, None))
    assert [i.target for i in plan.items] == ["wp-config.php"]
    applied = action.apply(ctx, (src, None, None), plan)
    assert all(i.done for i in applied.items)
    hardened = src.files["wp-config.php"]
    assert b"caf\xe9" in hardened
    assert b"\xef\xbf\xbd" not in hardened
    assert _php_const_state(
        hardened.decode("utf-8", errors="surrogateescape"), "DISALLOW_FILE_EDIT"
    ) == "truthy"


def test_apply_skips_a_commented_require_anchor(tmp_path, wpt_caplog):
    # A require inside a block comment is not the bootstrap anchor: inserting
    # before it would put the define inside the comment and harden nothing.
    config = (
        b"<?php\n"
        b"define( 'DB_NAME', 'example_db' );\n"
        b"/*\n"
        b"require_once __DIR__ . '/wp-settings.php';\n"
        b"*/\n"
    )
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS + EXPECTED_BLOCK + b"\n",
        "wp-config.php": config,
    }
    action = HardenAction()
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, (src, None, None))
    assert [i.target for i in plan.items] == ["wp-config.php"]
    applied = action.apply(ctx, (src, None, None), plan)
    assert all(i.done for i in applied.items)
    hardened = src.files["wp-config.php"]
    # the define lands AFTER the comment block, in live code
    assert hardened.index(DEFINE_LINE) > hardened.index(b"*/")
    assert _php_const_state(
        hardened.decode(), "DISALLOW_FILE_EDIT"
    ) == "truthy"
    assert any(
        "no active wp-settings require" in r.getMessage()
        or "no wp-settings require line" in r.getMessage()
        for r in _records(wpt_caplog, logging.WARNING)
    )


@pytest.mark.parametrize("require_line", [
    # same line as the open tag
    b"<?php require_once __DIR__ . '/wp-settings.php';\n",
    # split across lines
    b"<?php\nrequire_once __DIR__ .\n    '/wp-settings.php';\n",
])
def test_anchor_is_found_wherever_the_require_sits(tmp_path, require_line):
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS + EXPECTED_BLOCK + b"\n",
        "wp-config.php": require_line,
    }
    action = HardenAction()
    ctx = _ctx(tmp_path)
    applied = action.apply(ctx, (src, None, None), action.plan(ctx, (src, None, None)))
    assert all(i.done for i in applied.items)
    hardened = src.files["wp-config.php"]
    assert hardened.index(DEFINE_LINE) < hardened.index(b"wp-settings.php")
    assert _php_const_state(
        hardened.decode(), "DISALLOW_FILE_EDIT"
    ) == "truthy"


def test_conditional_alternative_syntax_require_is_not_an_anchor(tmp_path, wpt_caplog):
    # `if ($x): ... endif;` has no braces, so the require looks top-level to a
    # brace counter. Appending would place the define AFTER the bootstrap and
    # report a hardening that never happens, so the write is refused outright.
    config = (
        b"<?php\n"
        b"if ( $x ):\n"
        b"require_once __DIR__ . '/wp-settings.php';\n"
        b"endif;\n"
    )
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS + EXPECTED_BLOCK + b"\n",
        "wp-config.php": config,
    }
    action = HardenAction()
    ctx = _ctx(tmp_path)
    applied = action.apply(ctx, (src, None, None), action.plan(ctx, (src, None, None)))
    wp_config = [i for i in applied.items if i.target == "wp-config.php"][0]
    assert not wp_config.done
    assert src.files["wp-config.php"] == config  # nothing written
    assert any(
        "could not be proven top-level" in r.getMessage()
        for r in _records(wpt_caplog, logging.WARNING)
    )


def test_no_write_when_the_config_does_not_end_in_php(tmp_path, wpt_caplog):
    # Appending raw PHP after '?>' would be inline HTML: PHP would print the
    # define and the constant would never exist.
    config = (
        b"<?php\n"
        b"/* require_once __DIR__ . '/wp-settings.php'; */\n"
        b"?>\n"
    )
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS + EXPECTED_BLOCK + b"\n",
        "wp-config.php": config,
    }
    action = HardenAction()
    ctx = _ctx(tmp_path)
    applied = action.apply(ctx, (src, None, None), action.plan(ctx, (src, None, None)))
    wp_config = [i for i in applied.items if i.target == "wp-config.php"][0]
    assert not wp_config.done
    assert src.files["wp-config.php"] == config
    assert any(
        "does not end in PHP code" in r.getMessage()
        for r in _records(wpt_caplog, logging.WARNING)
    )


def test_utf8_config_anchor_is_not_split(tmp_path):
    # The insertion offset is a BYTE offset: a multi-byte character before
    # the require must not be cut in half.
    config = (
        b"<?php\n"
        b"// caf\xc3\xa9 na\xc3\xafve\n"
        b"require_once __DIR__ . '/wp-settings.php';\n"
    )
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS + EXPECTED_BLOCK + b"\n",
        "wp-config.php": config,
    }
    action = HardenAction()
    ctx = _ctx(tmp_path)
    action.apply(ctx, (src, None, None), action.plan(ctx, (src, None, None)))
    hardened = src.files["wp-config.php"]
    hardened.decode("utf-8")  # must still be valid UTF-8
    assert b"caf\xc3\xa9 na\xc3\xafve" in hardened
    assert hardened.index(DEFINE_LINE) < hardened.index(b"wp-settings.php")
    # and the second run changes nothing
    before = hardened
    action.apply(ctx, (src, None, None), action.plan(ctx, (src, None, None)))
    assert src.files["wp-config.php"] == before


def test_a_commented_path_is_not_an_anchor(tmp_path, wpt_caplog):
    # `require $other /* wp-settings.php */;` mentions the path only in a
    # comment, so it is not the bootstrap require. A LIVE require whose path
    # cannot be proven is still a require: appending would land after the
    # bootstrap and report a hardening that never happened, so the write is
    # refused.
    config = (
        b"<?php\n"
        b"require $bootstrap;\n"
        b"require $other /* wp-settings.php */;\n"
    )
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS + EXPECTED_BLOCK + b"\n",
        "wp-config.php": config,
    }
    action = HardenAction()
    ctx = _ctx(tmp_path)
    applied = action.apply(ctx, (src, None, None), action.plan(ctx, (src, None, None)))
    wp_config = [i for i in applied.items if i.target == "wp-config.php"][0]
    assert not wp_config.done
    assert src.files["wp-config.php"] == config
    assert any(
        "could not be proven top-level" in r.getMessage()
        for r in _records(wpt_caplog, logging.WARNING)
    )


def test_plan_line_number_in_the_log_is_one_based(tmp_path, wpt_caplog):
    src = FakeSource()
    src.files = {".htaccess": HTACCESS, "wp-config.php": WP_CONFIG}
    HardenAction().plan(_ctx(tmp_path), (src, None, None))
    logged = "\n".join(r.getMessage() for r in _records(wpt_caplog, logging.INFO))
    # WP_CONFIG's require is the 4th line (1-based)
    assert "line 4" in logged


def test_plan_indeterminate_file_mods_is_left_to_a_human(tmp_path, wpt_caplog):
    # DISALLOW_FILE_EDIT is falsey and writable, but a runtime-computed
    # DISALLOW_FILE_MODS makes the hardening state unprovable — the audit
    # reports it unverifiable, so harden must not claim a success it cannot
    # prove.
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS + EXPECTED_BLOCK + b"\n",
        "wp-config.php": (
            b"<?php\n"
            b"define( 'DISALLOW_FILE_EDIT', false );\n"
            b"define( 'DISALLOW_FILE_MODS', getenv('LOCK_MODS') );\n"
        ),
    }
    action = HardenAction()
    ctx = _ctx(tmp_path)
    original = src.files["wp-config.php"]
    plan = action.plan(ctx, (src, None, None))
    # An APPLICABLE item apply will refuse, so the run cannot report success.
    assert [i.target for i in plan.items] == ["wp-config.php"]
    applied = action.apply(ctx, (src, None, None), plan)
    wp_config = [i for i in applied.items if i.target == "wp-config.php"][0]
    assert not wp_config.done
    assert src.files["wp-config.php"] == original
    assert any(
        "cannot be resolved statically" in r.getMessage()
        for r in _records(wpt_caplog, logging.WARNING)
    )


def test_apply_ignores_a_php_tag_that_is_only_inside_a_string(tmp_path):
    # `'<?php'` inside a string is data, not a mode switch: the insertion must
    # not treat it as the tag boundary and must not break the file.
    config = b"<?php\n$x = '<?php'; require_once __DIR__ . '/wp-settings.php';\n"
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS + EXPECTED_BLOCK + b"\n",
        "wp-config.php": config,
    }
    action = HardenAction()
    ctx = _ctx(tmp_path)
    applied = action.apply(ctx, (src, None, None), action.plan(ctx, (src, None, None)))
    assert all(i.done for i in applied.items)
    hardened = src.files["wp-config.php"]
    assert hardened.startswith(b"<?php\n" + DEFINE_LINE + b"\n")
    assert b"$x = '<?php';" in hardened
    assert _php_const_state(hardened.decode(), "DISALLOW_FILE_EDIT") == "truthy"


def test_apply_refuses_when_the_define_would_not_activate(tmp_path, wpt_caplog):
    # Every shape here would place the define somewhere it cannot take effect
    # (inside an array literal, after a compiler halt). The write path verifies
    # the EFFECT before writing, so nothing is written.
    for config in (
        b"<?php\n$bootstrap = [\n    require_once '/wp-settings.php',\n];\n",
        b"<?php\n__halt_compiler();\n",
    ):
        src = FakeSource()
        src.files = {
            ".htaccess": HTACCESS + EXPECTED_BLOCK + b"\n",
            "wp-config.php": config,
        }
        action = HardenAction()
        ctx = _ctx(tmp_path)
        applied = action.apply(
            ctx, (src, None, None), action.plan(ctx, (src, None, None))
        )
        wp_config = [i for i in applied.items if i.target == "wp-config.php"][0]
        assert not wp_config.done, config
        assert src.files["wp-config.php"] == config


@pytest.mark.parametrize(("config", "expected"), [
    # PHP keywords are case-insensitive and include() loads wp-settings too.
    (b"<?php\nREQUIRE_ONCE ABSPATH . 'wp-settings.php';\n", "anchor"),
    (b"<?php\ninclude_once ABSPATH . 'wp-settings.php';\n", "anchor"),
    (b"<?php\nInclude ABSPATH . 'wp-settings.php';\n", "anchor"),
    # An unproven require may already have loaded wp-settings: a later anchor
    # must not erase that uncertainty.
    (b"<?php\nrequire $bootstrap;\nrequire_once ABSPATH . 'wp-settings.php';\n",
     "unsafe"),
    # A variable/property/method merely NAMED require is not the construct.
    (b"<?php\n$require = '/wp-settings.php';\n", "none"),
    (b"<?php\n$require = __DIR__;\n", "none"),
    (b"<?php\n$o->require('/wp-settings.php');\n", "none"),
    # A COMPLETED alternative-syntax block above the require is harmless.
    (b"<?php\nif ( $c ): echo 'x'; endif;\n"
     b"require_once ABSPATH . 'wp-settings.php';\n", "anchor"),
    # An OPEN one is not.
    (b"<?php\ndeclare(ticks=1):\n"
     b"require_once ABSPATH . 'wp-settings.php';\nenddeclare;\n", "anchor"),
    # A bracket inside a string is data, not structure.
    (b"<?php\ndefine('DB_PASSWORD', 'abc(def');\n"
     b"require_once ABSPATH . 'wp-settings.php';\n", "anchor"),
    # A multi-line condition still opens an alternative-syntax block: the
    # require inside it is conditional, so anchoring before it would harden
    # nothing while claiming success.
    (b"<?php\n$load = false;\nif (\n    $load\n):\n    ;\n"
     b"    require_once __DIR__ . '/wp-settings.php';\nendif;\n", "unsafe"),
    # else/elseif are branches of the block already open, not new blocks.
    (b"<?php\nif ( $a ): echo 1;\nelseif ( $b ): echo 2;\nendif;\n"
     b"require_once ABSPATH . 'wp-settings.php';\n", "anchor"),
    # A PHP 8 named argument is not the language construct.
    (b"<?php\nfunction inspect(string $require): void {}\n"
     b"inspect(require: '/wp-settings.php');\n"
     b"require_once ABSPATH . 'wp-settings.php';\n", "anchor"),
    # A nested require loads something unknown: refuse rather than guess.
    (b"<?php\nfunction ignore_arg($v) {}\nignore_arg(require '/dev/null');\n"
     b"require_once ABSPATH . 'wp-settings.php';\n", "unsafe"),
    # A variable merely NAMED __halt_compiler does not halt the compiler.
    (b"<?php\n$__halt_compiler = true;\ndefine('DISALLOW_FILE_EDIT', true);\n"
     b"require_once ABSPATH . 'wp-settings.php';\n", "anchor"),
    # An arrow body is an expression: a require after it in the same call is
    # evaluated immediately, so the anchor cannot be trusted.
    (b"<?php\nrun(fn() => 1, require_once ABSPATH . '/wp-settings.php');\n",
     "unsafe"),
    # `use function` is an import: it must not turn the next block into a
    # deferred function body and hide a conditional require.
    (b"<?php\nnamespace Vendor;\nuse function strlen;\n"
     b"if ( $x ) { require_once ABSPATH . '/wp-settings.php'; }\n", "unsafe"),
    # An arrow function inside a deferred body does not taint the anchor.
    (b"<?php\nfunction helper() { $x = fn() => 1; }\n"
     b"require_once ABSPATH . '/wp-settings.php';\n", "anchor"),
    # A variable named $fn is not the fn keyword.
    (b"<?php\n$fn = 'x';\nrequire_once ABSPATH . '/wp-settings.php';\n", "anchor"),
    # A COMPLETED arrow-function statement above the bootstrap is fine: the
    # taint covers only that statement.
    (b"<?php\n$callback = fn(int $value): int => $value + 1;\n"
     b"require_once ABSPATH . '/wp-settings.php';\n", "anchor"),
    # A nested arrow: the taint ends at the statement's own ';', which is
    # shallower than the arrow's depth.
    (b"<?php\narray_map(fn(int $v): int => $v + 1, [1]);\n"
     b"require_once ABSPATH . '/wp-settings.php';\n", "anchor"),
    # A global namespace block only scopes names; its statements still run.
    (b"<?php\nnamespace {\n    require_once ABSPATH . '/wp-settings.php';\n}\n",
     "anchor"),
    # ...but an unbracketed `namespace X;` must not claim the NEXT brace.
    (b"<?php\nnamespace Vendor;\nuse function strlen;\n"
     b"if ( $x ) { require_once ABSPATH . '/wp-settings.php'; }\n", "unsafe"),
    # An empty closure above the bootstrap must not make the require look
    # like a function name.
    (b"<?php\n$callback = function () {};\n"
     b"require_once ABSPATH . '/wp-settings.php';\n", "anchor"),
    # A braced declare block runs its body.
    (b"<?php\ndeclare(ticks=1) {\n"
     b"    require_once ABSPATH . '/wp-settings.php';\n}\n", "anchor"),
    # An abstract/interface method declaration has no body, so it must not
    # arm the deferred-body tracker and hide a later conditional require.
    (b"<?php\ninterface C { public function boot(): void; }\n"
     b"if ( $x ) { require_once ABSPATH . '/wp-settings.php'; }\n", "unsafe"),
    (b"<?php\nabstract class A { abstract function boot(): void; }\n"
     b"require_once ABSPATH . '/wp-settings.php';\n", "anchor"),
    # A variable named $endif is not the block terminator.
    (b"<?php\n$endif = 1;\nif ( $c ): echo 1; endif;\n"
     b"require_once ABSPATH . '/wp-settings.php';\n", "anchor"),
    # A LONG alternative-syntax header is still a conditional: a bounded
    # tail-scan once missed it, which let the constant be written INSIDE the
    # conditional and reported as hardened while PHP left it undefined.
    (b"<?php\n$load = false;\nif (" + b"a" * 400 + b"):\n    ;\n"
     b"    require_once ABSPATH . '/wp-settings.php';\nendif;\n", "unsafe"),
    # ...and a long braced-header comment must not be mistaken for a block end.
    (b"<?php\n$load = false;\nif (" + b"a" * 400 + b") {\n"
     b"    require_once ABSPATH . '/wp-settings.php';\n}\n", "unsafe"),
    # `elseif` continues the block; the require after `endif;` is top level.
    (b"<?php\nif ( $a ): echo 1;\nelseif ( $b ): echo 2;\nendif;\n"
     b"require_once ABSPATH . '/wp-settings.php';\n", "anchor"),
    # A method named `endif` is not a terminator: counting it let a conditional
    # require look top-level and the constant be written INSIDE the conditional
    # while the run reported success.
    (b"<?php\nif (false):\nclass C { function endif() {} }\n"
     b"require_once ABSPATH . '/wp-settings.php';\nendif;\n", "unsafe"),
    # ...and neither is a const, a named argument or a qualified name.
    (b"<?php\nif (false):\nclass C { const endif = 1; }\n"
     b"require_once ABSPATH . '/wp-settings.php';\nendif;\n", "unsafe"),
    (b"<?php\nif (false):\nfoo(endif: 1);\n"
     b"require_once ABSPATH . '/wp-settings.php';\nendif;\n", "unsafe"),
    (b"<?php\nif (false):\n$x = Vendor\\endif;\n"
     b"require_once ABSPATH . '/wp-settings.php';\nendif;\n", "unsafe"),
    # `declare(ticks=1):` is unconditional, so a require in it still anchors.
    (b"<?php\ndeclare(ticks=1):\n"
     b"require_once ABSPATH . '/wp-settings.php';\nenddeclare;\n", "anchor"),
    # A braced control head does not arm a later ternary colon.
    (b"<?php\nif (false) {}\n$a = true ? 1 : 0;\n"
     b"require_once ABSPATH . '/wp-settings.php';\n", "anchor"),
    # A label is a statement, not a block.
    (b"<?php\ntop:\nrequire_once ABSPATH . '/wp-settings.php';\n", "anchor"),
    # A top-level exit/die ENDS the script, so a require after it never runs.
    (b"<?php\ndie();\nrequire_once ABSPATH . '/wp-settings.php';\n", "unsafe"),
    (b"<?php\n$f = fn() => 1; if (true) { exit; }\n"
     b"require_once ABSPATH . '/wp-settings.php';\n", "unsafe"),
    # ...but an exit AFTER the require cannot unmake the anchor, and a method
    # named exit is not the language construct.
    (b"<?php\nrequire_once ABSPATH . '/wp-settings.php';\nexit;\n", "anchor"),
    (b"<?php\n$o->exit();\nrequire_once ABSPATH . '/wp-settings.php';\n", "anchor"),
    # A return-type colon after a braced control head is not a block opener.
    (b"<?php\nif (false) {}\nfunction f(): void {}\n"
     b"require_once ABSPATH . '/wp-settings.php';\n", "anchor"),
    # A ternary inside the control head is expression punctuation; the `):`
    # that follows still opens the block, so the require is conditional.
    (b"<?php\nif (true ? false : true):\n"
     b"require_once ABSPATH . '/wp-settings.php';\nendif;\n", "unsafe"),
    # An exit inside an arrow body, or used as a named argument, is not a
    # file-scope exit.
    (b"<?php\n$callback = fn() => exit;\n"
     b"require_once ABSPATH . '/wp-settings.php';\n", "anchor"),
    (b"<?php\nfunction foo($exit) {}\nfoo(exit: false);\n"
     b"require_once ABSPATH . '/wp-settings.php';\n", "anchor"),
    # A nested group in the control head is part of it: `array()` used to reset
    # the head, so the require looked top level and the write succeeded inside
    # a conditional that PHP never runs.
    (b"<?php\nif (array()):\n"
     b"require_once ABSPATH . '/wp-settings.php';\nendif;\n", "unsafe"),
    (b"<?php\nif ($a ? $b ? 1 : 2 : 3):\n"
     b"require_once ABSPATH . '/wp-settings.php';\nendif;\n", "unsafe"),
    (b"<?php\nif (foo(x: 1)):\n"
     b"require_once ABSPATH . '/wp-settings.php';\nendif;\n", "unsafe"),
    # An arrow body ends at ITS statement's `;`, so a closure inside it (with
    # its own `;`) does not end the scope early.
    (b"<?php\n$c = fn() => (function () { return 1; })() ?: exit;\n"
     b"require_once ABSPATH . '/wp-settings.php';\n", "anchor"),
    (b"<?php\narray_map(fn(int $v): int => $v + 1, [1]);\n"
     b"require_once ABSPATH . '/wp-settings.php';\n", "anchor"),
    # A comma ends an arrow EXPRESSION, so a sibling exit in the same statement
    # is a real file-scope exit and the anchor must be refused.
    (b"<?php\n$x = [fn() => 1, exit];\n"
     b"require_once ABSPATH . '/wp-settings.php';\n", "unsafe"),
    (b"<?php\n$x = [fn() => 1, fn() => 2];\n"
     b"require_once ABSPATH . '/wp-settings.php';\n", "anchor"),
    # `fn` has no brace body: arming the function-body tracker on it made the
    # NEXT block an `if` look like a function body, hiding a real file-scope
    # exit inside it.
    (b"<?php\n$c = fn() => 1;\nif (true) { exit; }\n"
     b"require_once ABSPATH . '/wp-settings.php';\n", "unsafe"),
    # A nested arrow must not clobber the enclosing arrow's scope.
    (b"<?php\n$c = fn() => (fn() => 1)() ?: exit;\n"
     b"require_once ABSPATH . '/wp-settings.php';\n", "anchor"),
    # A `;` inside a completed if-block is a different statement, so it must
    # not become the terminator a later top-level arrow looks for.
    (b"<?php\nif (true) { $x = 1; }\n$x = fn() => 1;\n"
     b"require_once ABSPATH . '/wp-settings.php';\n", "anchor"),
])
def test_anchor_analysis_matches_php_semantics(config, expected):
    from wpt.actions.harden import _wp_settings_require_insert
    assert _wp_settings_require_insert(config)[0] == expected


# --------------------------------------------------------------------------
# THE ANCHOR SCAN'S COST — measured by the work it does, never by the clock
#
# These three replaced wall-clock assertions that flaked under CPU load (2
# failures in 8 runs at 36x parallel load).  A ratio bound with a floor IS a
# wall-clock assertion whenever the floor binds, and a ratio without one is
# a coin flip on a shared machine, so the clock is gone: what is measured
# now is the number of Python statements the scan EXECUTES, which is a
# property of the algorithm and not of the machine.
#
# The measure is per BYTE against a FLAT input of the same length, so it
# asks the invariant the tests are actually about — "the cost is a function
# of the input's SIZE, not of its SHAPE" — and not a magic ratio between
# two arbitrary sizes.  Measured separations (this file, one core):
#
#   shape                        linear      quadratic   ratio
#   2 500 x declare(ticks=1)      92.7/byte    1 343/byte   14.5x
#   2 000 x fn() => 1             49.6/byte    3 049/byte   61x
#   1 500 x declare((((...        72.9/byte    1 387/byte   19x
#
# …against a 4x threshold, with the linear shape at 1.8x the flat one, so
# the bound has margin on both sides and no sensitivity to load at all.
# tracemalloc's PEAK was measured as the alternative and is NOT used: it is
# blind to all three (the extra work is released before the peak is sampled,
# so the peak tracks the input size alone), and only a wall clock separates
# a BULK copy, which no out-of-process measure can see (see the note on
# ``_scan_work``).
# --------------------------------------------------------------------------


def _scan_work(data: bytes) -> int:
    """The statements ``_wp_settings_require_insert`` EXECUTES on ``data``.

    One event per Python line event inside the two modules the scan lives
    in (the action and the mask builder it calls), counted through
    ``sys.settrace``: the product's own executed work, which is what a
    complexity claim is about, measured identically on a loaded and an idle
    machine.  One honest limit, stated because it is a real limit: a
    regression that is a single C-level bulk copy (a slice of the remaining
    mask per keyword) moves no line event, so this measure does not see it.
    Seeing that shape needs a counter INSIDE the product (bytes scanned /
    nodes visited) exposed by the scanning chokepoint itself; that change
    belongs to wpt/actions/harden.py + wpt/audit/security.py, and is
    reported to the coordinator rather than faked here with a clock.
    """
    import sys

    from wpt.actions import harden as harden_mod
    from wpt.audit import security as security_mod

    modules = {harden_mod.__file__, security_mod.__file__}
    count = 0

    def trace(frame, event, arg):
        nonlocal count
        if event == "line" and frame.f_code.co_filename in modules:
            count += 1
        return trace

    from wpt.actions.harden import _wp_settings_require_insert

    sys.settrace(trace)
    try:
        _wp_settings_require_insert(data)
    finally:
        sys.settrace(None)
    return count


def _assert_cost_is_per_byte(awkward: bytes, flat: bytes) -> None:
    """The awkward shape must not cost more per byte than the flat one.

    Comparable-length inputs, normalized per byte, so the only thing that
    can raise the awkward shape's per-byte cost is its SHAPE — a
    look-ahead, a re-scan or a copy that grows with what is LEFT of the
    file instead of with the level it is at.  A linear scan treats both as
    bytes, so the two land within a small factor of each other.
    """
    # comparable sizes (the per-byte normalization is what makes the
    # comparison meaningful, so the lengths need only be in the same
    # neighbourhood — within a factor of four)
    assert 0.25 <= len(flat) / len(awkward) <= 4, (len(flat), len(awkward))
    awkward_cost = _scan_work(awkward) / len(awkward)
    flat_cost = _scan_work(flat) / len(flat)
    assert awkward_cost <= 4 * flat_cost, (
        f"{awkward_cost:.1f} statements/byte for the awkward shape against "
        f"{flat_cost:.1f} for a flat file of the same order: the scan's "
        f"cost is following the input's SHAPE, not its size"
    )


def test_anchor_scan_of_repeated_declares_is_linear():
    # The look-ahead used to walk (and copy) the whole remaining mask per
    # `declare`, so N declares cost N times the file.  A per-byte measure
    # against a flat file of the same length is the invariant: the shape
    # may not make a statement more expensive.
    _assert_cost_is_per_byte(
        b"<?php\n" + b"declare(ticks=1)" * 2500,
        b"<?php\n" + b"$x = 1;" * (16 * 2500 // 7 + 1),
    )


def test_anchor_scan_of_nested_declare_parens_is_bounded():
    # The balanced-paren look-ahead scanned the whole group before any
    # budget was applied, so `declare((((...` cost the square of the
    # nesting.  This is the case tracemalloc's peak cannot see at all (the
    # extra work is released before the peak is sampled, so the peak reads
    # the same either way — measured 175 KB for both), and it is the shape
    # the statement counter separates most sharply: 34x.
    _assert_cost_is_per_byte(
        b"<?php\n" + b"declare(" * 1500 + b")" * 1500,
        b"<?php\n" + b"$x = 1;" * 3429,
    )


def test_anchor_scan_of_many_arrow_functions_is_linear():
    # Each `fn` used to rescan forward for the shared statement terminator,
    # so the arrow count was multiplied by the statement length.  Measured
    # separation: 61x.
    _assert_cost_is_per_byte(
        b"<?php\n$x = [" + b", ".join([b"fn() => 1"] * 2000) + b"];",
        b"<?php\n$x = [" + b", ".join([b"1"] * 2000) + b"];",
    )


@pytest.mark.parametrize("config", [
    b"<?php\nnamespace App;\nrequire_once ABSPATH . '/wp-settings.php';\n",
    b"<?php\nnamespace App {\nrequire_once ABSPATH . '/wp-settings.php';\n}\n",
])
def test_namespaced_config_still_hardens_the_global_constant(tmp_path, config):
    # An unqualified define() inside a namespace would create
    # App\DISALLOW_FILE_EDIT, which WordPress never reads; the emitted line is
    # fully qualified so it defines the global constant in both scopes.
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS + EXPECTED_BLOCK + b"\n",
        "wp-config.php": config,
    }
    action = HardenAction()
    ctx = _ctx(tmp_path)
    applied = action.apply(ctx, (src, None, None), action.plan(ctx, (src, None, None)))
    assert all(i.done for i in applied.items)
    assert _php_const_state(
        src.files["wp-config.php"].decode(), "DISALLOW_FILE_EDIT"
    ) == "truthy"


def test_advice_only_items_do_not_fail_the_run(tmp_path, capsys, monkeypatch):
    # PlanItem.requires_apply=False is a contract: advice items are never
    # applied and stay done=False. They must not turn a successful apply into
    # an operational failure.
    from wpt.types import PlanItem
    src = ConfigWriteSpySource()
    src.files = {".htaccess": HTACCESS + EXPECTED_BLOCK + b"\n",
                 "wp-config.php": WP_CONFIG + DEFINE_LINE + b"\n"}
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, None))
    record = get_action("harden")
    original_plan = record.action.plan

    def plan_with_advice(ctx, stack):
        plan = original_plan(ctx, stack)
        plan.items.append(
            PlanItem(category="info.advice", target="none", detail="manual",
                     requires_apply=False)
        )
        return plan

    monkeypatch.setattr(record.action, "plan", plan_with_advice)
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "harden")
    assert rc == 0


def test_registry_reports_failure_when_an_item_is_refused(
    tmp_path, capsys, monkeypatch
):
    # A refused item is an operational failure: exit 0 would tell a script the
    # site was hardened when nothing was written.
    src = ConfigWriteSpySource()
    src.files = {
        ".htaccess": HTACCESS + EXPECTED_BLOCK + b"\n",
        "wp-config.php": b"<?php\n__halt_compiler();\n",
    }
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, None))
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "harden")
    assert rc == 1
    assert src.files["wp-config.php"] == b"<?php\n__halt_compiler();\n"
    assert "| no |" in capsys.readouterr().out


def test_apply_refuses_when_a_goto_bypasses_the_define(tmp_path, wpt_caplog):
    config = (
        b"<?php\n"
        b"goto skip;\n"
        b"require_once __DIR__ . '/wp-settings.php';\n"
        b"skip:\n"
    )
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS + EXPECTED_BLOCK + b"\n",
        "wp-config.php": config,
    }
    action = HardenAction()
    ctx = _ctx(tmp_path)
    applied = action.apply(ctx, (src, None, None), action.plan(ctx, (src, None, None)))
    wp_config = [i for i in applied.items if i.target == "wp-config.php"][0]
    assert not wp_config.done
    assert src.files["wp-config.php"] == config


def test_wp_config_proposal_never_logs_config_content(tmp_path, wpt_caplog):
    # wp-config.php carries absolute paths and site-specific text; only the
    # fixed define line and a fixed phrase may reach the log.
    config = (
        b"<?php\n"
        b"define( 'DB_NAME', 'example_db' );\n"
        b"require '/srv/CUSTOMER-SECRET-PATH/wp-settings.php';\n"
    )
    src = FakeSource()
    src.files = {".htaccess": HTACCESS, "wp-config.php": config}
    HardenAction().plan(_ctx(tmp_path), (src, None, None))
    logged = "\n".join(r.getMessage() for r in _records(wpt_caplog, logging.INFO))
    assert "CUSTOMER-SECRET-PATH" not in logged
    assert "wp-settings" in logged  # the fixed phrase is still there
    assert DEFINE_LINE.decode() in logged


def test_apply_indeterminate_disallow_refuses_to_write(tmp_path, wpt_caplog):
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS + EXPECTED_BLOCK + b"\n",
        "wp-config.php": WP_CONFIG + b"define( 'DISALLOW_FILE_EDIT', !0 );\n",
    }
    action = HardenAction()
    ctx = _ctx(tmp_path)
    original = src.files["wp-config.php"]
    # plan surfaces it as an APPLICABLE item, and apply refuses it rather than
    # guessing at a value PHP decides. One item failing never aborts the batch.
    plan = action.plan(ctx, (src, None, None))
    assert [i.target for i in plan.items] == ["wp-config.php"]
    applied = action.apply(ctx, (src, None, None), plan)
    wp_config = [i for i in applied.items if i.target == "wp-config.php"][0]
    assert not wp_config.done
    assert src.files["wp-config.php"] == original
    assert any(
        "cannot resolve" in r.getMessage()
        for r in _records(wpt_caplog, logging.WARNING)
    )


def test_a_write_that_does_not_land_is_not_reported_as_done(tmp_path, wpt_caplog):
    # An FTP upload can truncate silently. The bytes are read back, so a write
    # that did not land fails the item instead of claiming the site is
    # hardened (and instead of purging caches for a change that never landed).
    class TruncatingSource(FakeSource):
        def write_bytes(self, path, data, *, allow_config=False, allow_core=False):
            super().write_bytes(
                path, data[: len(data) // 2],
                allow_config=allow_config, allow_core=allow_core,
            )

    src = TruncatingSource()
    src.files = {".htaccess": HTACCESS, "wp-config.php": WP_CONFIG}
    action = HardenAction()
    ctx = _ctx(tmp_path)
    applied = action.apply(ctx, (src, None, None), action.plan(ctx, (src, None, None)))
    assert not any(i.done for i in applied.items)
    assert any(
        "read back" in r.getMessage()
        for r in _records(wpt_caplog, logging.WARNING)
    )


def test_deferred_require_in_a_function_is_not_the_anchor(tmp_path):
    # A require inside a function body does not run at load time, so the real
    # top-level bootstrap is still a valid anchor.
    config = (
        b"<?php\n"
        b"function optional_bootstrap(): void {\n"
        b"    require_once __DIR__ . '/wp-settings.php';\n"
        b"}\n"
        b"require_once ABSPATH . '/wp-settings.php';\n"
    )
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS + EXPECTED_BLOCK + b"\n",
        "wp-config.php": config,
    }
    action = HardenAction()
    ctx = _ctx(tmp_path)
    applied = action.apply(ctx, (src, None, None), action.plan(ctx, (src, None, None)))
    assert all(i.done for i in applied.items)
    hardened = src.files["wp-config.php"]
    assert hardened.index(DEFINE_LINE) < hardened.rindex(b"require_once ABSPATH")
    assert _php_const_state(hardened.decode(), "DISALLOW_FILE_EDIT") == "truthy"


def _wpconfig_item():
    from wpt.actions.harden import _CATEGORY, _WP_CONFIG, _WP_CONFIG_DETAIL, PlanItem
    return PlanItem(category=_CATEGORY, target=_WP_CONFIG, detail=_WP_CONFIG_DETAIL)


def test_apply_failure_continues(tmp_path, wpt_caplog):
    src = FailingConfigWriteSource({".htaccess"})
    src.files = {".htaccess": HTACCESS, "wp-config.php": WP_CONFIG}
    action = HardenAction()
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, (src, None, None))
    applied = action.apply(ctx, (src, None, None), plan)
    by_target = {i.target: i for i in applied.items}
    assert not by_target[".htaccess"].done
    assert by_target["wp-config.php"].done  # the batch continued
    warnings = _records(wpt_caplog, logging.WARNING)
    assert len(warnings) == 1
    assert ".htaccess" in warnings[0].getMessage()
    # the failed target is untouched; the other item really landed
    assert src.files[".htaccess"] == HTACCESS
    assert DEFINE_LINE in src.files["wp-config.php"]


def test_apply_already_hardened_no_second_write(tmp_path, wpt_caplog):
    src = ConfigWriteSpySource()
    src.files = {".htaccess": HTACCESS, "wp-config.php": WP_CONFIG}
    action = HardenAction()
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, (src, None, None))
    assert len(plan.items) == 2
    # the site was hardened behind the plan's back (concurrent actor)
    src.files[".htaccess"] = HTACCESS + EXPECTED_BLOCK + b"\n"
    src.files["wp-config.php"] = WP_CONFIG + DEFINE_LINE + b"\n"
    applied = action.apply(ctx, (src, None, None), plan)
    by_target = {i.target: i for i in applied.items}
    assert by_target[".htaccess"].done
    assert by_target[".htaccess"].detail.endswith(", already hardened")
    assert by_target["wp-config.php"].done
    assert by_target["wp-config.php"].detail.endswith(", already hardened")
    # fresh idempotency: NO second write for either file
    assert src.config_writes == []
    assert _write_ops(src) == []
    assert not _records(wpt_caplog, logging.WARNING)


def test_apply_then_plan_is_empty(tmp_path):
    src = FakeSource()
    src.files = {".htaccess": HTACCESS, "wp-config.php": WP_CONFIG}
    action = HardenAction()
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, (src, None, None))
    assert len(plan.items) == 2
    action.apply(ctx, (src, None, None), plan)
    second = action.plan(ctx, (src, None, None))
    assert second.items == []
    assert second.backup_tables == []


# ------------------------------------------- WordPress permalink block


def test_plan_pretty_permalinks_plans_wordpress_block(tmp_path, wpt_caplog):
    # The live defect: a migrated pretty-permalink site whose .htaccess
    # lacks the WP block 404s every subpage — so the plan must carry the
    # WP item right after ours.
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS,
        "wp-config.php": WP_CONFIG + DEFINE_LINE + b"\n",
    }
    plan = HardenAction().plan(_ctx(tmp_path), (src, None, _bridge()))
    assert [(i.category, i.target, i.detail) for i in plan.items] == [
        ("webroot.hardening", ".htaccess", HTACCESS_DETAIL),
        ("webroot.hardening", ".htaccess", WP_PERMALINK_DETAIL),
    ]
    assert all(i.bytes_est == 0 for i in plan.items)
    # one-line details (render_report prints one table line per item)
    assert all("\n" not in i.detail for i in plan.items)
    # diff-printed like every config write: the FULL canonical block at info
    assert any(
        EXPECTED_WP_BLOCK.decode("ascii") in r.getMessage()
        and "WordPress permalink block" in r.getMessage()
        for r in _records(wpt_caplog, logging.INFO)
    )
    assert plan.backup_tables == []


def test_local_pretty_permalinks_plans_and_applies_wordpress_block(tmp_path):
    # The LOCAL seam: the dump's permalink_structure plans the WP item, and
    # the apply re-derives the fact FRESH from the same dump (heal-core
    # discipline) before appending both blocks in order.
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS,
        "wp-config.php": WP_CONFIG + DEFINE_LINE + b"\n",
    }
    spath = tmp_path / "site.sql"
    spath.write_bytes(_dump_bytes(PRETTY_PERMALINKS))
    ctx = _local_ctx(tmp_path, tmp_path / "site.zip", spath)
    action = HardenAction()
    plan = action.plan(ctx, (src, None, None))
    assert [i.detail for i in plan.items] == [
        HTACCESS_DETAIL, WP_PERMALINK_DETAIL,
    ]
    applied = action.apply(ctx, (src, None, None), plan)
    assert all(i.done for i in applied.items)
    assert src.files[".htaccess"] == (
        HTACCESS + EXPECTED_BLOCK + b"\n" + EXPECTED_WP_BLOCK + b"\n"
    )


def test_author_scan_rule_matches_the_path_apache_actually_sees():
    r"""R24-P1 behavioural pin: a per-directory RewriteRule sees the PATH, not
    the query string, so ``^/?\?author=\d`` can never fire.  Evaluate the
    installed block the way Apache does: the QUERY_STRING condition matches
    ``author=1`` and the rule subject has the leading slash LiteSpeed keeps.
    ``^`` alone matched only ``/`` there, leaving every subpage unblocked;
    ``^/?`` must match both the root and a subpage."""
    import re

    lines = EXPECTED_BLOCK.decode("ascii").splitlines()
    start = lines.index("# Block author-scan user enumeration")
    condition = lines[start + 1]
    rule = lines[start + 2]
    assert condition == "RewriteCond %{QUERY_STRING} author=\\d [NC]"
    assert rule == "RewriteRule ^/? - [F]"
    cond = re.search(r"%\{QUERY_STRING\}\s+(.+?)\s+\[NC\]$", condition)
    assert cond is not None
    query = "author=1"
    assert re.search(cond.group(1), query)
    pattern, flags = rule.removeprefix("RewriteRule ").split(" - ")
    for path in ("/", "/any-subpage/", "/2026/10/hello/"):
        assert re.search(pattern, path), path
    assert not re.search(r"^/?\?author=\d", "/any-subpage/")  # dead old rule


def test_R25_harden_rest_route_query_fallback_is_blocked():
    r"""R25-P1: WordPress dispatches ``/?rest_route=/wp/v2/users`` (the
    public query var), so the path-only REST rule never protected it.  The
    installed block carries a QUERY_STRING condition that matches the
    literal and percent-encoded forms, in any casing."""
    import re

    lines = EXPECTED_BLOCK.decode("ascii").splitlines()
    start = lines.index(
        "# Block REST user enumeration (pretty permalink)")
    assert lines[start + 1] == "RewriteRule ^/?wp-json/wp/v2/users - [F]"
    condition = lines[start + 3]
    assert condition.startswith("RewriteCond %{QUERY_STRING} ")
    assert condition.endswith(" [NC]")
    assert lines[start + 4] == "RewriteRule ^/? - [F]"
    cond = re.search(r"%\{QUERY_STRING\}\s+(.+?)\s+\[NC\]$", condition)
    assert cond is not None
    pattern = cond.group(1)
    for query in (
        "rest_route=/wp/v2/users",
        "rest_route=%2Fwp%2Fv2%2Fusers",
        "rest_route=%2fwp%2fv2%2fusers",
        "foo=1&rest_route=/wp/v2/users",
        "rest_route=/wp/v2/users/1",
        "rest_route=/wp/v2/users&_fields=slug",
    ):
        assert re.search(pattern, query, re.IGNORECASE), query
    for query in (
        "rest_route=/wp/v2/posts",
        "rest_route=/wp/v2/users_evil",
        "author=1",
        "not_rest_route=/wp/v2/users",
    ):
        assert not re.search(pattern, query, re.IGNORECASE), query
    pattern, _flags = lines[start + 4].removeprefix("RewriteRule ").split(" - ")
    for path in ("/", "/any-subpage/"):
        assert re.search(pattern, path), path


def test_plan_existing_wp_block_only_ours_added(tmp_path):
    # An existing canonical WP block: only OUR item is planned, the WP
    # block is byte-untouched, and the applied file is idempotent.
    src = FakeSource()
    src.files = {
        ".htaccess": EXPECTED_WP_BLOCK + b"\n",
        "wp-config.php": WP_CONFIG + DEFINE_LINE + b"\n",
    }
    action = HardenAction()
    ctx = _ctx(tmp_path, apply=True, yes=True)
    plan = action.plan(ctx, (src, None, _bridge()))
    assert [i.detail for i in plan.items] == [HTACCESS_DETAIL]
    action.apply(ctx, (src, None, _bridge()), plan)
    stored = src.files[".htaccess"]
    # the WP block: untouched and byte-identical, exactly once — but no
    # longer FIRST. Its `RewriteRule . /index.php [L]` ends the per-directory
    # rewrite round, so every rule below it is unreachable: with our block
    # appended, the HTTPS force, the REST-users block and the author-scan
    # block would never run while the plan reported them applied. Our block
    # is therefore PLACED ABOVE any existing RewriteRule.
    assert stored == (
        EXPECTED_BLOCK + b"\n" + EXPECTED_WP_BLOCK + b"\n"
    )
    assert stored.count(EXPECTED_WP_BLOCK) == 1
    assert stored.count(b"# BEGIN wpt-harden") == 1
    assert stored.index(b"# BEGIN wpt-harden") < stored.index(
        b"# BEGIN WordPress")
    assert stored.index(b"RewriteRule ^/? https://") < stored.index(
        b"RewriteRule . /index.php [L]")
    # idempotent: a fresh plan over the applied file plans NOTHING
    assert action.plan(ctx, (src, None, _bridge())).items == []


def test_R24_an_unreachable_existing_block_is_relocated_not_accepted(
        tmp_path):
    """R24-P1: a canonical wpt-harden block placed BELOW a live RewriteRule
    was reported "already hardened" while every rule in it was unreachable.
    Presence only counts when no rule precedes the marker; apply relocates
    the exact block first and removes the shadowed copy."""
    src = FakeSource()
    src.files = {
        ".htaccess": EXPECTED_WP_BLOCK + b"\n" + EXPECTED_BLOCK + b"\n",
        "wp-config.php": WP_CONFIG + DEFINE_LINE + b"\n",
    }
    action = HardenAction()
    ctx = _ctx(tmp_path, apply=True, yes=True)
    plain = _bridge("")
    plan = action.plan(ctx, (src, None, plain))
    assert [i.detail for i in plan.items] == [HTACCESS_DETAIL]
    action.apply(ctx, (src, None, plain), plan)
    stored = src.files[".htaccess"]
    assert stored == EXPECTED_BLOCK + b"\n" + EXPECTED_WP_BLOCK + b"\n"
    assert stored.count(b"# BEGIN wpt-harden") == 1
    assert stored.index(b"# BEGIN wpt-harden") < stored.index(
        b"# BEGIN WordPress")
    # idempotent AFTER the relocation
    assert action.plan(ctx, (src, None, plain)).items == []


def test_our_block_goes_above_a_file_that_already_carries_a_rewriterule(
        tmp_path):
    # The position is the protection. Apache ends a directory's rewrite
    # round at the first [L] (WP's own permalink catch-all is
    # `RewriteRule . /index.php [L]`), so every rule below it is
    # unreachable: appended there, harden would install the HTTPS force,
    # the REST-users block and the author-scan block and report them
    # applied while none of them ever runs. Any existing RewriteRule
    # therefore puts our block FIRST — with the file's own bytes carried
    # through untouched underneath.
    rewrite_rule = (
        b"# BEGIN WordPress\n"
        b"<IfModule mod_rewrite.c>\n"
        b"RewriteEngine On\n"
        b"RewriteBase /subdir/\n"
        b"RewriteRule ^index\\.php$ - [L]\n"
        b"RewriteCond %{REQUEST_FILENAME} !-f\n"
        b"RewriteCond %{REQUEST_FILENAME} !-d\n"
        b"RewriteRule . /subdir/index.php [L]\n"
        b"</IfModule>\n"
        b"# END WordPress"
    )
    src = FakeSource()
    src.files = {
        ".htaccess": rewrite_rule,
        "wp-config.php": WP_CONFIG + DEFINE_LINE + b"\n",
    }
    action = HardenAction()
    ctx = _ctx(tmp_path, apply=True, yes=True)
    # a plain-permalink bridge: only OUR item is in play here (the WP block
    # is covered by its own tests, including the subdirectory residual)
    plain = _bridge("")
    plan = action.plan(ctx, (src, None, plain))
    assert [i.detail for i in plan.items] == [HTACCESS_DETAIL]
    action.apply(ctx, (src, None, plain), plan)
    stored = src.files[".htaccess"]
    assert stored == EXPECTED_BLOCK + b"\n" + rewrite_rule + b"\n"
    # the site's own bytes are byte-identical, just moved down
    assert stored.endswith(rewrite_rule + b"\n")
    # our HTTPS force is evaluated before the rule that ends the round
    assert stored.index(b"RewriteRule ^/? https://") < stored.index(
        b"RewriteRule . /subdir/index.php [L]")
    # a second run changes nothing (idempotent over the prepended block)
    assert action.plan(ctx, (src, None, plain)).items == []


def test_subdirectory_install_block_stays_authoritative_and_inert(tmp_path):
    # The ACCEPTED residual, pinned. A subdirectory install's WP block is
    # NOT the webroot block this action installs (`RewriteBase /subdir/`,
    # `/subdir/index.php`), so the body-exact proof reads it as MISSING and
    # the canonical block is appended beside it. That must not BREAK the
    # site: the install's own catch-all comes first and ends the rewrite
    # round, so the appended block is unreachable — inert weight, never a
    # second front controller — and our own block now sits ABOVE both, so
    # the protections it carries are the ones that actually run.
    subdir_block = (
        b"# BEGIN WordPress\n"
        b"<IfModule mod_rewrite.c>\n"
        b"RewriteEngine On\n"
        b"RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]\n"
        b"RewriteBase /subdir/\n"
        b"RewriteRule ^index\\.php$ - [L]\n"
        b"RewriteCond %{REQUEST_FILENAME} !-f\n"
        b"RewriteCond %{REQUEST_FILENAME} !-d\n"
        b"RewriteRule . /subdir/index.php [L]\n"
        b"</IfModule>\n"
        b"# END WordPress\n"
    )
    src = FakeSource()
    src.files = {
        ".htaccess": subdir_block,
        "wp-config.php": WP_CONFIG + DEFINE_LINE + b"\n",
    }
    action = HardenAction()
    ctx = _ctx(tmp_path, apply=True, yes=True)
    bridge = _bridge(PRETTY_PERMALINKS)
    plan = action.plan(ctx, (src, None, bridge))
    assert [i.detail for i in plan.items] == [
        HTACCESS_DETAIL, WP_PERMALINK_DETAIL,
    ]
    action.apply(ctx, (src, None, bridge), plan)
    stored = src.files[".htaccess"]
    assert stored == (
        EXPECTED_BLOCK + b"\n" + subdir_block + EXPECTED_WP_BLOCK + b"\n"
    )
    # the install's own catch-all still ends the round BEFORE the appended
    # canonical block: the appended one is unreachable (inert)
    assert stored.index(b"RewriteRule . /subdir/index.php [L]") < \
        stored.index(b"RewriteRule . /index.php [L]")
    # and our protections run above everything
    assert stored.index(b"RewriteRule ^/? https://") < stored.index(
        b"RewriteRule . /subdir/index.php [L]")
    # idempotent: the applied file plans nothing further
    assert action.plan(ctx, (src, None, bridge)).items == []


def test_our_block_is_appended_when_nothing_can_shadow_it(tmp_path):
    # The counterpart pin: a file with no RewriteRule (RewriteEngine /
    # RewriteBase / RewriteCond on their own cannot end a rewrite round)
    # keeps the plain append — the existing content stays at the top, byte
    # for byte, and a missing trailing newline still gets exactly one.
    for current in (b"RewriteEngine On\nRewriteBase /\n",
                    b"Options +FollowSymLinks",
                    b"RewriteEngine On",
                    b"# a comment\n<IfModule mod_mime.c>\nAddType x\n</IfModule>\n"):
        src = FakeSource()
        src.files = {".htaccess": current,
                     "wp-config.php": WP_CONFIG + DEFINE_LINE + b"\n"}
        action = HardenAction()
        ctx = _ctx(tmp_path, apply=True, yes=True)
        plain = _bridge("")
        plan = action.plan(ctx, (src, None, plain))
        assert [i.detail for i in plan.items] == [HTACCESS_DETAIL]
        action.apply(ctx, (src, None, plain), plan)
        tail = current if current.endswith(b"\n") else current + b"\n"
        assert src.files[".htaccess"] == tail + EXPECTED_BLOCK + b"\n", current
        assert src.files[".htaccess"].startswith(current)


def test_apply_wp_block_already_hardened_no_second_write(tmp_path, wpt_caplog):
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS,
        "wp-config.php": WP_CONFIG + DEFINE_LINE + b"\n",
    }
    action = HardenAction()
    ctx = _ctx(tmp_path, apply=True, yes=True)
    bridge = _bridge()
    plan = action.plan(ctx, (src, None, bridge))
    assert [i.detail for i in plan.items] == [
        HTACCESS_DETAIL, WP_PERMALINK_DETAIL,
    ]
    # both .htaccess blocks landed behind the plan's back
    src.files[".htaccess"] = (
        HTACCESS + EXPECTED_BLOCK + b"\n" + EXPECTED_WP_BLOCK + b"\n"
    )
    applied = action.apply(ctx, (src, None, bridge), plan)
    assert all(i.done for i in applied.items)
    assert all(i.detail.endswith(", already hardened") for i in applied.items)
    assert _write_ops(src) == []  # fresh idempotency: NO write
    assert not _records(wpt_caplog, logging.WARNING)


@pytest.mark.parametrize("answer", ["plain", "absent"],
                         ids=["empty-string", "absent-key"])
def test_plain_or_absent_permalinks_no_wp_item(tmp_path, answer):
    # '' is a MEASURED plain (WordPress's own ?p=N default); an absent
    # payload key (a degraded bridge answer) reads the same.  No WP item
    # either way: WordPress itself writes no rewrite block for a
    # plain-permalink site, so neither do we (YAGNI).
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS,
        "wp-config.php": WP_CONFIG + DEFINE_LINE + b"\n",
    }
    fake = _bridge("" if answer == "plain" else None)
    plan = HardenAction().plan(_ctx(tmp_path), (src, None, fake))
    assert [i.detail for i in plan.items] == [HTACCESS_DETAIL]


@pytest.mark.parametrize("permalink", ["", None], ids=["empty", "absent-row"])
def test_local_plain_permalinks_no_wordpress_block(tmp_path, permalink):
    # The LOCAL seam with a plain ('') or absent option row in the dump:
    # no WP item.
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS,
        "wp-config.php": WP_CONFIG + DEFINE_LINE + b"\n",
    }
    spath = tmp_path / "site.sql"
    spath.write_bytes(_dump_bytes(permalink))
    ctx = _local_ctx(tmp_path, tmp_path / "site.zip", spath)
    plan = HardenAction().plan(ctx, (src, None, None))
    assert [i.detail for i in plan.items] == [HTACCESS_DETAIL], permalink


@pytest.mark.parametrize("shape", [
    "commented", "no-space", "truncated", "wrapped",
])
def test_a_defaced_wp_block_is_treated_as_missing(tmp_path, shape):
    # The R1 whole-line marker-pair discipline on WordPress's OWN markers:
    # a commented-out copy, the no-space marker spelling, a truncated pair
    # or a conditional wrapper is MISSING, never present.  (Our block is
    # pre-installed so the WP item is the plan's ONLY item.)
    if shape == "commented":
        defaced = b"\n".join(
            b"# " + line for line in EXPECTED_WP_BLOCK.splitlines()
        ) + b"\n"
    elif shape == "no-space":
        defaced = EXPECTED_WP_BLOCK.replace(
            b"# BEGIN WordPress", b"#BEGIN WordPress"
        ) + b"\n"
    elif shape == "truncated":
        defaced = EXPECTED_WP_BLOCK.split(b"# END WordPress")[0] + b"\n"
    else:
        defaced = (b"<IfModule definitely_not_loaded.c>\n"
                   + EXPECTED_WP_BLOCK + b"\n</IfModule>\n")
    src = FakeSource()
    src.files = {
        ".htaccess": EXPECTED_BLOCK + b"\n" + defaced,
        "wp-config.php": WP_CONFIG + DEFINE_LINE + b"\n",
    }
    action = HardenAction()
    ctx = _ctx(tmp_path, apply=True, yes=True)
    plan = action.plan(ctx, (src, None, _bridge()))
    assert [i.detail for i in plan.items] == [WP_PERMALINK_DETAIL], shape
    action.apply(ctx, (src, None, _bridge()), plan)
    stored = src.files[".htaccess"]
    # the canonical block landed at top level exactly once; the wrapped
    # defacement keeps its own (inert) copy, like the R1 test for ours
    expected_copies = 2 if shape == "wrapped" else 1
    assert stored.count(EXPECTED_WP_BLOCK + b"\n") == expected_copies, shape


def test_wp_block_proof_requires_the_exact_canonical_body():
    from wpt.actions.harden import _wp_permalink_block_present

    canonical = EXPECTED_WP_BLOCK.decode("ascii")
    assert _wp_permalink_block_present(canonical)
    # surrounded by other rules: still proof
    assert _wp_permalink_block_present("junk\n" + canonical + "\nmore\n")
    # indentation alone must not defeat the comparison
    body = "\n".join(canonical.splitlines()[1:-1])
    assert _wp_permalink_block_present(
        "# BEGIN WordPress\n"
        + "\n".join("  " + line for line in body.splitlines())
        + "\n# END WordPress"
    )
    for not_proof in (
        # commented-out markers
        "# # BEGIN WordPress\n# # END WordPress\n",
        # not the marker spelling
        "#BEGIN WordPress\n#END WordPress\n",
        # a non-canonical body: a subdirectory install's block is NOT the
        # webroot block this action installs
        canonical.replace("RewriteBase /", "RewriteBase /subdir/"),
        # a truncated catch-all
        canonical.replace("RewriteRule . /index.php [L]\n", ""),
        # the pair opened inside a conditional wrapper
        "<IfModule absent.c>\n" + canonical + "\n</IfModule>",
    ):
        assert not _wp_permalink_block_present(not_proof), not_proof


def test_wp_block_write_that_does_not_land_is_not_done(tmp_path, wpt_caplog):
    # The read-back contract: a write that lands truncated fails the WP
    # item instead of claiming the block is there.
    class TruncatingSource(FakeSource):
        def write_bytes(self, path, data, *, allow_config=False, allow_core=False):
            super().write_bytes(
                path, data[: len(data) // 2],
                allow_config=allow_config, allow_core=allow_core,
            )

    src = TruncatingSource()
    src.files = {
        ".htaccess": HTACCESS + EXPECTED_BLOCK + b"\n",  # ours present
        "wp-config.php": WP_CONFIG + DEFINE_LINE + b"\n",
    }
    action = HardenAction()
    ctx = _ctx(tmp_path, apply=True, yes=True)
    applied = action.apply(
        ctx, (src, None, _bridge()), action.plan(ctx, (src, None, _bridge()))
    )
    wp_items = [
        i for i in applied.items
        if i.target == ".htaccess" and i.detail == WP_PERMALINK_DETAIL
    ]
    assert len(wp_items) == 1
    assert not wp_items[0].done
    assert any(
        "read back" in r.getMessage()
        for r in _records(wpt_caplog, logging.WARNING)
    )


def test_apply_refuses_when_permalinks_flip_behind_the_plan(tmp_path, wpt_caplog):
    # The fact is RE-DERIVED at apply: a flip to plain permalinks behind
    # the plan's back refuses the WP item (WordPress writes no rewrite
    # block for a plain site, so neither do we) while our own block still
    # lands.
    src = FakeSource()
    src.files = {
        ".htaccess": HTACCESS,
        "wp-config.php": WP_CONFIG + DEFINE_LINE + b"\n",
    }
    bridge = _bridge()
    action = HardenAction()
    ctx = _ctx(tmp_path, apply=True, yes=True)
    plan = action.plan(ctx, (src, None, bridge))
    assert [i.detail for i in plan.items] == [
        HTACCESS_DETAIL, WP_PERMALINK_DETAIL,
    ]
    bridge.payload["permalink_structure"] = ""  # flipped behind our back
    applied = action.apply(ctx, (src, None, bridge), plan)
    wp_item = [i for i in applied.items
               if i.detail == WP_PERMALINK_DETAIL][0]
    assert not wp_item.done
    assert any(
        "no longer reports pretty permalinks" in r.getMessage()
        for r in _records(wpt_caplog, logging.WARNING)
    )
    # our own block still applied; the WP item wrote NOTHING
    assert src.files[".htaccess"] == HTACCESS + EXPECTED_BLOCK + b"\n"
    assert _write_ops(src) == [".htaccess"]


# ------------------------------------------------------- registry end-to-end


def test_registry_dry_run_zero_writes(tmp_path, capsys, monkeypatch):
    src = ConfigWriteSpySource()
    src.files = {".htaccess": HTACCESS, "wp-config.php": WP_CONFIG}
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, None))
    rc = run_action(_ctx(tmp_path), "harden")
    assert rc == 0
    out = capsys.readouterr().out
    assert "## Plan" in out
    assert ".htaccess" in out
    assert "wp-config.php" in out
    assert "add DISALLOW_FILE_EDIT" in out
    assert "diff-printed hardening block" in out
    assert out.count("| no |") == 2  # both items printed as not applied
    assert src.config_writes == []  # zero writes
    assert _write_ops(src) == []
    assert not (tmp_path / "backup").exists()  # dry run: no snapshot


def test_registry_ftp_apply_end_to_end(tmp_path, capsys, monkeypatch):
    src = ConfigWriteSpySource()
    src.files = {".htaccess": HTACCESS, "wp-config.php": WP_CONFIG}
    originals = dict(src.files)
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, None))
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "harden")
    assert rc == 0
    # both config files written, each unlocked with allow_config
    assert src.config_writes == [(".htaccess", True), ("wp-config.php", True)]
    assert src.files[".htaccess"] == HTACCESS + EXPECTED_BLOCK + b"\n"
    assert DEFINE_LINE in src.files["wp-config.php"]
    # fail-closed pre-action backup: BOTH config files snapshotted
    # BEFORE the mutation — the captured bytes are the ORIGINALS
    manifests = list((tmp_path / "backup").glob("*/*/manifest.json"))
    assert len(manifests) == 1
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    assert manifest["action"] == "harden"
    assert manifest["site"] == "example.com"
    assert manifest["tables"] == []  # file-only action: no DB side
    assert [f["path"] for f in manifest["files"]] == [
        ".htaccess",
        "wp-config.php",
    ]
    assert all(not f["absent"] for f in manifest["files"])
    snap_dir = manifests[0].parent
    assert (snap_dir / "files" / ".htaccess").read_bytes() == originals[".htaccess"]
    assert (
        snap_dir / "files" / "wp-config.php"
    ).read_bytes() == originals["wp-config.php"]
    out = capsys.readouterr().out
    assert out.count("| yes |") == 2  # both applied items printed as done


def test_registry_apply_twice_second_dry_run_empty(tmp_path, capsys, monkeypatch):
    src = ConfigWriteSpySource()
    src.files = {".htaccess": HTACCESS, "wp-config.php": WP_CONFIG}
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, None))
    assert run_action(_ctx(tmp_path, apply=True, yes=True), "harden") == 0
    first_out = capsys.readouterr().out
    assert first_out.count("| yes |") == 2
    writes_after_first = len(src.config_writes)
    assert writes_after_first == 2
    # the second run (dry) plans NOTHING: applying twice is a no-op
    rc = run_action(_ctx(tmp_path), "harden")
    assert rc == 0
    out = capsys.readouterr().out
    assert "Plan total estimate: 0 B" in out
    assert ".htaccess" not in out
    assert "wp-config.php" not in out
    assert len(src.config_writes) == writes_after_first  # no new writes


def test_registry_local_rehearsal_materializes_both_blocks_in_order(
    tmp_path, capsys, monkeypatch
):
    # The live-defect shape end to end over the registry's LOCAL flow: a
    # migrated site's export zip with NO root .htaccess + a dump whose
    # permalink_structure says pretty permalinks.  The dry run plans BOTH
    # .htaccess items; --apply REHEARSES and materializes a zip whose
    # fresh .htaccess carries both blocks, OURS FIRST.
    import zipfile

    from wpt.sources.zipwriter import MutableZipSource

    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("wp-config.php", WP_CONFIG + DEFINE_LINE + b"\n")
    spath = tmp_path / "site.sql"
    spath.write_bytes(_dump_bytes(PRETTY_PERMALINKS))
    monkeypatch.setattr(
        registry_mod, "_stack",
        lambda ctx: (MutableZipSource(zpath), None, None),
    )
    before = sorted(zipfile.ZipFile(zpath).namelist())

    # dry run: BOTH .htaccess items in the printed plan
    assert run_action(_local_ctx(tmp_path, zpath, spath), "harden") == 0
    out = capsys.readouterr().out
    assert (HTACCESS_DETAIL + " (new file)") in out
    assert out.count(WP_PERMALINK_DETAIL) == 1

    # --apply: rehearsed, rc 0, the original zip IS the untouched rollback
    assert run_action(
        _local_ctx(tmp_path, zpath, spath, apply=True, yes=True), "harden"
    ) == 0
    assert sorted(zipfile.ZipFile(zpath).namelist()) == before
    assert ".htaccess" not in before
    rehearsed = sorted(tmp_path.glob("site-rehearsed-*.zip"))
    assert len(rehearsed) == 1
    with zipfile.ZipFile(rehearsed[0]) as zf:
        assert ".htaccess" in zf.namelist()
        htaccess = zf.read(".htaccess")
    # both blocks, byte-exact, OURS FIRST
    assert htaccess == EXPECTED_BLOCK + b"\n" + EXPECTED_WP_BLOCK + b"\n"
    # ORDER: our HTTPS force PRECEDES the WP catch-all — with the WP
    # block first, its [L] catch-all would shadow the redirect on the
    # first per-directory pass
    assert (
        htaccess.index(b"RewriteCond %{HTTPS} !=on")
        < htaccess.index(b"RewriteRule . /index.php [L]")
    )
