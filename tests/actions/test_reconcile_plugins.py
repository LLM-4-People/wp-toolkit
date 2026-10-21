"""Tests for the reconcile-plugins action (wpt.actions.reconcile_plugins).

A REAL Bridge over FakeSession/FakeSource (scripted
reconcile_active_plugins / db_audit / db_dump answers —
tests/actions/test_deactivate.py conventions): deterministic, no network, no
sleeps.  The registry end-to-end tests monkeypatch
``wpt.actions.registry._stack`` (the pinned seam) to run the real
``run_action`` flow over a fake ftp-mode stack; ``bridge.destroy()`` (the
registry's finally) is scripted via a self-destruct handler.

Test -> behavior map:
  test_registration ......................... reconcile-plugins registered
        as the INSTANCE under applies=("ftp",) — local mode can never
        reach it
  test_plan_lists_active_but_absent ......... one item per missing plugin
        file: category db.active_plugins, target = the options table, the
        ``_LABEL``-owned "reconcile <file> (not installed)" label;
        backup_tables = the options table EXPLICITLY; the op called with
        NO apply flag (read-only); ONE info plan summary
  test_plan_nothing_missing ................. nothing missing -> EMPTY plan,
        backup_tables == [] deliberately, NO db_audit roundtrip
  test_plan_malformed_missing_refuses ....... a non-list / non-string
        ``missing`` -> BridgeError carrying the payload, never a guess
  test_plan_refuses_without_bridge .......... no bridge -> SourceError
  test_plan_refuses_unbacked ................ the audit lists no *options
        table -> SourceError, never an unbacked rewrite
  test_plan_backup_scope_fail_safe .......... a stray *options-suffixed
        table WIDENS the snapshot scope, never a miss; the item's target
        stays the ONE table the identity owner resolves
  test_plan_target_is_the_resolved_options_table_not_the_first_by_name
        THE MEASURED CASE: sorted()[0] over the whole
        information_schema base-table set named AIOSEO 4.x's
        aioseo_options; a contested identity is refused, both candidates
        named
  test_plan_target_is_the_options_table_on_an_uncontested_site .. the A/B
  test_apply_rewrites_and_verifies .......... ONE apply call, then the
        MANDATORY read-only re-read; every planned item done and enriched
        with the before->after counts; ONE info apply summary
  test_apply_empty_plan_no_bridge_call ...... zero planned files -> no
        bridge roundtrip
  test_apply_response_anomaly_bridge_error .. applied not True / updated not
        True / removed not a list / a planned file absent from removed / an
        UNPLANNED file removed -> BridgeError, items stay undone
  test_apply_unchanged_option_refuses ........ the re-read still reports the
        same missing entries (the write did not stick) -> BridgeError
  test_apply_lingering_entry_refuses ........ the re-read still NAMES a
        planned file as active -> BridgeError
  test_apply_verification_malformed_refuses . a re-read whose active_now is
        not a list -> BridgeError (never a half-verified success)
  test_apply_server_error_propagates ........ an ok:false answer propagates
        untouched, items stay undone
  test_registry_dry_run ...................... run_action apply=False: the
        plan printed (rc 0), read-only op + db_audit, no db_dump and no
        apply flag
  test_registry_ftp_apply_end_to_end ........ apply --yes: the pre-action
        snapshot manifest lists the options table, the op is applied then
        re-read, purge_cache once, rc 0
  test_registry_rollback_refused ............ a snapshot that cannot be
        taken (db_dump refuses) -> rc 1, "refusing to apply", the rewrite
        NEVER runs (the operator's rollback stays possible)
  test_registry_apply_anomaly_rc1 ........... a response anomaly after the
        backup -> rc 1, nothing printed as success, the backup kept
  test_registry_local_mode_refused ........... local mode: rc 1, the
        ftp-only applicability error, the stack never even built
"""

import json
import logging

import pytest

from tests.fakes import FakeResponse, FakeSession, FakeSource
from wpt.actions import registry as registry_mod
from wpt.actions.reconcile_plugins import ReconcilePluginsAction
from wpt.actions.registry import get_action, run_action
from wpt.cli import Ctx
from wpt.report import Plan
from wpt.settings import BridgeSettings, load
from wpt.types import BridgeError, PlanItem, SourceError
from wpt.wpbridge.client import Bridge

#: The shipped profile — every threshold exactly as users get it.
DEFAULTS = load()

WEBROOT = "domains/example.com/public_html"
SITE = "https://example.com"

AKISMET = "akismet/akismet.php"
HELLO = "hello.php"
MIGRATION = "all-in-one-wp-migration/all-in-one-wp-migration.php"
VELVET = "velvet-blues-update-urls/velvet.php"


@pytest.fixture
def wpt_caplog(caplog):
    """caplog wired to the non-propagating wpt logger tree (see
    tests/actions/test_deactivate.py — the wpt parent never reaches root)."""
    parent = logging.getLogger("wpt")
    parent.addHandler(caplog.handler)
    with caplog.at_level(logging.DEBUG, logger="wpt"):
        yield caplog
    parent.removeHandler(caplog.handler)


# ------------------------------------------------------------------ helpers


def _ctx(tmp_path, *, settings=DEFAULTS, **overrides):
    """A reconcile-plugins Ctx; ftp-mode defaults, overridable per test."""
    fields = dict(
        source="ftp://example.com",
        settings=settings,
        command="reconcile-plugins",
        apply=False,
        yes=False,
        backup_dir=tmp_path / "backup",
        wp_url=SITE,
    )
    fields.update(overrides)
    return Ctx(**fields)


def _tables(*names):
    """The named db_audit wire table rows (measured-zero free space)."""
    return [{"name": name, "rows": 10, "size_mb": 0.5, "data_free_kb": 0.0}
            for name in names]


def audit_payload(*table_names):
    """A db_audit payload; defaults to the five core tables."""
    if not table_names:
        table_names = (
            "wp_commentmeta", "wp_options", "wp_postmeta", "wp_posts", "wp_termmeta",
        )
    return {
        "posts": [],
        "revisions": 0,
        "expired_transients": 0,
        "orphan_meta": {},
        "tables": _tables(*table_names),
        "autoload_bytes": 123456,
        "attachments": 3,
        "nav_menu_items": 2,
    }


def ok(**payload):
    """An ok:true bridge envelope (the payload the client returns)."""
    return FakeResponse(200, json.dumps({"ok": True, **payload}))


def reconcile(*, active, missing, applied=False, updated=None, removed=None,
              installed=4):
    """A reconcile_active_plugins answer in the pinned wire shape.

    ``active`` is the option's content AFTER the call, so the apply answer
    and the verification re-read are both faithful to the persisted state.
    """
    return ok(installed=installed, active_before=len(active) + len(missing),
              missing=list(missing), applied=applied, updated=updated,
              removed=list(removed or []), active_after=len(active),
              active_now=list(active))


def read_only(*active, missing=(), installed=4):
    """The op WITHOUT its apply flag: the plan's read-only inventory."""
    return reconcile(active=active, missing=missing, installed=installed)


def applied(kept, removed, *, before):
    """The op WITH apply=True: the rewrite plus its own post-write re-read."""
    return ok(installed=4, active_before=before, missing=list(removed),
              applied=True, updated=True, removed=list(removed),
              active_after=len(kept), active_now=list(kept))


def table_lines(table, rows, create="CREATE TABLE `x` (id bigint)"):
    """Scripted db_dump NDJSON for one table: create, rows, done."""
    lines = [json.dumps({"table": table, "create": create})]
    for row in rows:
        lines.append(json.dumps({"table": table, "row": row}))
    lines.append(json.dumps({"table": table, "done": len(rows)}))
    return lines


def _selfdestruct(src):
    """Script item playing the server side of the bridge self-destruct."""

    def handler(method, url, kwargs):
        name = url.removeprefix(f"{SITE}/").partition("?")[0]
        src.files.pop(f"{WEBROOT}/{name}", None)
        return FakeResponse(200, "gone")

    return handler


def make_stack(script):
    """A fake ftp-mode stack: (FakeSource, None, Bridge over FakeSession)."""
    src = FakeSource()
    session = FakeSession(list(script) + [_selfdestruct(src)])
    bridge = Bridge(src, session, WEBROOT, BridgeSettings(), SITE)
    return src, session, bridge


def posted_actions(session):
    """Every bridge action POSTed, in order."""
    return [kwargs["json"]["action"] for _url, kwargs in session.posts]


def posted_params(session, action):
    """The ``params`` of every POST of ``action``."""
    return [kwargs["json"]["params"]
            for _url, kwargs in session.posts
            if kwargs["json"]["action"] == action]


def _records(caplog, name, level):
    return [r for r in caplog.records if r.name == name and r.levelno == level]


# ------------------------------------------------------------- registration


def test_registration():
    record = get_action("reconcile-plugins")
    assert record is not None
    assert record.applies == ("ftp",)
    assert isinstance(record.action, ReconcilePluginsAction)  # instance


# ------------------------------------------------------------------- plan


def test_plan_lists_active_but_absent(tmp_path, wpt_caplog):
    src, session, bridge = make_stack([
        read_only(AKISMET, MIGRATION, VELVET, HELLO,
                  missing=(MIGRATION, VELVET)),
        ok(**audit_payload()),
    ])
    plan = ReconcilePluginsAction().plan(_ctx(tmp_path), (src, None, bridge))
    assert [
        (i.category, i.target, i.detail, i.bytes_est) for i in plan.items
    ] == [
        ("db.active_plugins", "wp_options",
         f"reconcile {MIGRATION} (not installed)", 0),
        ("db.active_plugins", "wp_options",
         f"reconcile {VELVET} (not installed)", 0),
    ]
    assert plan.backup_tables == ["wp_options"]
    assert all(i.requires_apply for i in plan.items)
    assert all(not i.done for i in plan.items)
    # the plan's op call carried NO apply flag (read-only inventory)
    assert posted_actions(session) == ["reconcile_active_plugins", "db_audit"]
    assert posted_params(session, "reconcile_active_plugins") == [{}]
    summaries = _records(wpt_caplog, "wpt.actions.reconcile_plugins",
                         logging.INFO)
    assert len(summaries) == 1
    assert "2 item(s)" in summaries[0].getMessage()


def test_plan_nothing_missing(tmp_path, wpt_caplog):
    src, session, bridge = make_stack([read_only(AKISMET, HELLO)])
    plan = ReconcilePluginsAction().plan(_ctx(tmp_path), (src, None, bridge))
    assert plan.items == []
    assert plan.backup_tables == []  # deliberately empty, not unset
    assert posted_actions(session) == ["reconcile_active_plugins"]
    infos = _records(wpt_caplog, "wpt.actions.reconcile_plugins", logging.INFO)
    assert len(infos) == 1
    assert "every active plugin is installed" in infos[0].getMessage()


@pytest.mark.parametrize("missing", ["gone/gone.php", {}, [None], [""], 3])
def test_plan_malformed_missing_refuses(tmp_path, missing):
    src, session, bridge = make_stack([ok(installed=4, missing=missing)])
    with pytest.raises(BridgeError, match="anomaly"):
        ReconcilePluginsAction().plan(_ctx(tmp_path), (src, None, bridge))
    # refused before any second roundtrip
    assert posted_actions(session) == ["reconcile_active_plugins"]


def test_plan_refuses_without_bridge(tmp_path):
    src = FakeSource()
    with pytest.raises(SourceError, match="bridge"):
        ReconcilePluginsAction().plan(_ctx(tmp_path), (src, None, None))


def test_plan_refuses_unbacked(tmp_path):
    src, _session, bridge = make_stack([
        read_only(AKISMET, MIGRATION, missing=(MIGRATION,)),
        ok(**audit_payload("wp_posts", "wp_postmeta")),
    ])
    with pytest.raises(SourceError, match="options"):
        ReconcilePluginsAction().plan(_ctx(tmp_path), (src, None, bridge))


def test_plan_backup_scope_fail_safe(tmp_path):
    # a stray *options-suffixed table merely WIDENS the snapshot scope (it
    # is snapshotted too), never a miss — and the item's target is the ONE
    # table the identity owner resolves, not the first name.
    src, _session, bridge = make_stack([
        read_only(AKISMET, MIGRATION, missing=(MIGRATION,)),
        ok(**audit_payload("wp_myoptions", "wp_posts")),
    ])
    plan = ReconcilePluginsAction().plan(_ctx(tmp_path), (src, None, bridge))
    assert plan.backup_tables == ["wp_myoptions"]
    assert [i.target for i in plan.items] == ["wp_myoptions"]


def test_plan_target_is_the_resolved_options_table_not_the_first_by_name(
        tmp_path):
    """THE MEASURED CASE: ``sorted()``[0] named the PLUGIN's table.

    ``db_audit`` reports the whole ``information_schema`` base-table set and
    AIOSEO 4.x really creates ``aioseo_options`` (``a`` < ``w``), so the
    plan item — and every ``--report`` artifact built from it — named a
    table the rewrite never touches.  A contested identity is refused with
    both candidates named rather than resolved by name order.
    """
    src, _session, bridge = make_stack([
        read_only(AKISMET, MIGRATION, missing=(MIGRATION,)),
        ok(**audit_payload("aioseo_options", "wp_options", "wp_posts")),
    ])
    with pytest.raises(SourceError) as excinfo:
        ReconcilePluginsAction().plan(_ctx(tmp_path), (src, None, bridge))
    message = str(excinfo.value)
    assert "aioseo_options" in message and "wp_options" in message
    assert "target is unknown" in message


def test_plan_target_is_the_options_table_on_an_uncontested_site(tmp_path):
    src, _session, bridge = make_stack([
        read_only(AKISMET, MIGRATION, missing=(MIGRATION,)),
        ok(**audit_payload("wp_commentmeta", "wp_options", "wp_postmeta",
                          "wp_posts", "wp_termmeta")),
    ])
    plan = ReconcilePluginsAction().plan(_ctx(tmp_path), (src, None, bridge))
    assert [i.target for i in plan.items] == ["wp_options"]
    assert plan.backup_tables == ["wp_options"]


# ------------------------------------------------------------------ apply


def test_apply_rewrites_and_verifies(tmp_path, wpt_caplog):
    src, session, bridge = make_stack([
        read_only(AKISMET, MIGRATION, VELVET, HELLO, missing=(MIGRATION, VELVET)),
        ok(**audit_payload()),
        applied([AKISMET, HELLO], [MIGRATION, VELVET], before=4),
        # the MANDATORY verification re-read: the persisted option no
        # longer names anything absent
        read_only(AKISMET, HELLO),
    ])
    action = ReconcilePluginsAction()
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, (src, None, bridge))
    result = action.apply(ctx, (src, None, bridge), plan)
    assert result is plan
    assert posted_actions(session) == [
        "reconcile_active_plugins", "db_audit",
        "reconcile_active_plugins", "reconcile_active_plugins",
    ]
    # the apply call carries the STRICT flag; the verification re-read does
    # not (and is a separate, independent roundtrip)
    assert posted_params(session, "reconcile_active_plugins") == [
        {}, {"apply": True}, {},
    ]
    assert all(i.done for i in result.items)
    assert [i.detail for i in result.items] == [
        f"reconcile {MIGRATION} (not installed), "
        f"deactivated (4->2 active plugins)",
        f"reconcile {VELVET} (not installed), "
        f"deactivated (4->2 active plugins)",
    ]
    summaries = _records(wpt_caplog, "wpt.actions.reconcile_plugins",
                         logging.INFO)
    assert len(summaries) == 2  # one plan summary, one apply summary
    assert "2 plugin file(s) deactivated" in summaries[1].getMessage()


def test_apply_empty_plan_no_bridge_call(tmp_path):
    src, session, bridge = make_stack([])  # any POST would fail the fake
    plan = Plan(items=[], backup_tables=[])
    assert ReconcilePluginsAction().apply(
        _ctx(tmp_path), (src, None, bridge), plan) is plan
    assert session.posts == []  # nothing planned -> no bridge roundtrip


def test_apply_response_anomaly_bridge_error(tmp_path):
    plan = Plan(items=[
        PlanItem(category="db.active_plugins", target="wp_options",
                 detail=f"reconcile {MIGRATION} (not installed)"),
    ])
    # Every shape that does not PROVE the rewrite raises, items stay undone:
    # update_option refused, the op not applied, removed not a list, or a
    # planned file absent from removed.
    for answer in (
        ok(installed=4, active_before=2, missing=[MIGRATION], applied=True,
           updated=False, removed=[MIGRATION], active_after=1,
           active_now=[AKISMET]),
        ok(installed=4, active_before=2, missing=[MIGRATION], applied=False,
           updated=True, removed=[MIGRATION], active_after=1,
           active_now=[AKISMET]),
        ok(installed=4, active_before=2, missing=[MIGRATION], applied=True,
           updated=True, removed=MIGRATION, active_after=1,
           active_now=[AKISMET]),
        applied([AKISMET], [VELVET], before=2),  # planned file absent
        applied([AKISMET], [MIGRATION, VELVET], before=3),  # unplanned extra
    ):
        src, _session, bridge = make_stack([answer])
        with pytest.raises(BridgeError,
                           match="anomaly|did not remove|not in the plan"):
            ReconcilePluginsAction().apply(_ctx(tmp_path), (src, None, bridge),
                                           plan)
        assert not plan.items[0].done


def test_apply_unchanged_option_refuses(tmp_path):
    # The write reported success but the option still lists the absent
    # plugin: the apply must not report success (verify-after-mutate).
    plan = Plan(items=[
        PlanItem(category="db.active_plugins", target="wp_options",
                 detail=f"reconcile {MIGRATION} (not installed)"),
    ])
    src, _session, bridge = make_stack([
        applied([AKISMET], [MIGRATION], before=2),
        read_only(AKISMET, MIGRATION, missing=(MIGRATION,)),
    ])
    with pytest.raises(BridgeError, match="still lists"):
        ReconcilePluginsAction().apply(_ctx(tmp_path), (src, None, bridge),
                                       plan)
    assert not plan.items[0].done


def test_apply_lingering_entry_refuses(tmp_path):
    # missing is empty but the option still NAMES the planned file: a
    # half-applied rewrite, reported as a failure.
    plan = Plan(items=[
        PlanItem(category="db.active_plugins", target="wp_options",
                 detail=f"reconcile {MIGRATION} (not installed)"),
    ])
    src, _session, bridge = make_stack([
        applied([AKISMET], [MIGRATION], before=2),
        read_only(AKISMET, MIGRATION),
    ])
    with pytest.raises(BridgeError, match="still lists"):
        ReconcilePluginsAction().apply(_ctx(tmp_path), (src, None, bridge),
                                       plan)
    assert not plan.items[0].done


def test_apply_verification_malformed_refuses(tmp_path):
    plan = Plan(items=[
        PlanItem(category="db.active_plugins", target="wp_options",
                 detail=f"reconcile {MIGRATION} (not installed)"),
    ])
    src, _session, bridge = make_stack([
        applied([AKISMET], [MIGRATION], before=2),
        ok(installed=4, missing=[], active_now="akismet"),
    ])
    with pytest.raises(BridgeError, match="anomaly"):
        ReconcilePluginsAction().apply(_ctx(tmp_path), (src, None, bridge),
                                       plan)
    assert not plan.items[0].done


def test_apply_server_error_propagates(tmp_path):
    plan = Plan(items=[
        PlanItem(category="db.active_plugins", target="wp_options",
                 detail=f"reconcile {MIGRATION} (not installed)"),
    ])
    src, _session, bridge = make_stack([
        FakeResponse(200, json.dumps({"ok": False,
                                      "error": "plugin inventory unavailable"})),
    ])
    with pytest.raises(BridgeError, match="inventory unavailable"):
        ReconcilePluginsAction().apply(_ctx(tmp_path), (src, None, bridge),
                                       plan)
    assert not plan.items[0].done  # the registry reports rc 1


def test_apply_skips_non_apply_items(tmp_path):
    plan = Plan(items=[
        PlanItem(category="db.active_plugins", target="wp_options",
                 detail=f"reconcile {MIGRATION} (not installed)"),
        PlanItem(category="db.info", target="none", detail="advice",
                 requires_apply=False),
    ])
    src, _session, bridge = make_stack([
        applied([AKISMET], [MIGRATION], before=2),
        read_only(AKISMET),
    ])
    by_detail = {i.detail: i for i in plan.items}
    ReconcilePluginsAction().apply(_ctx(tmp_path), (src, None, bridge), plan)
    assert by_detail[f"reconcile {MIGRATION} (not installed)"].done
    assert not by_detail["advice"].done
    assert by_detail["advice"].detail == "advice"  # never enriched


# ------------------------------------------------------- registry end-to-end


def test_registry_dry_run(tmp_path, capsys, monkeypatch):
    src, session, bridge = make_stack([
        read_only(AKISMET, MIGRATION, missing=(MIGRATION,)),
        ok(**audit_payload()),
    ])
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    rc = run_action(_ctx(tmp_path), "reconcile-plugins")
    assert rc == 0
    out = capsys.readouterr().out
    assert "## Plan" in out
    assert "db.active_plugins" in out
    assert f"reconcile {MIGRATION} (not installed)" in out
    # read-only: the inventory + db_audit, no backup dump, no apply flag
    assert posted_actions(session) == ["reconcile_active_plugins", "db_audit"]
    assert posted_params(session, "reconcile_active_plugins") == [{}]


def test_registry_ftp_apply_end_to_end(tmp_path, capsys, monkeypatch):
    src, session, bridge = make_stack([
        read_only(AKISMET, MIGRATION, missing=(MIGRATION,)),
        ok(**audit_payload()),
        FakeResponse(200, lines=table_lines("wp_options", [])),
        applied([AKISMET], [MIGRATION], before=2),
        read_only(AKISMET),
        ok(purged=True),  # the registry's post-apply purge answer
    ])
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "reconcile-plugins")
    assert rc == 0
    assert posted_actions(session) == [
        "reconcile_active_plugins", "db_audit", "db_dump",
        "reconcile_active_plugins", "reconcile_active_plugins", "purge_cache",
    ]
    assert posted_params(session, "db_dump") == [{"tables": ["wp_options"]}]
    assert posted_params(session, "reconcile_active_plugins") == [
        {}, {"apply": True}, {},
    ]
    manifests = list((tmp_path / "backup").glob("*/*/manifest.json"))
    assert len(manifests) == 1
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    assert manifest["action"] == "reconcile-plugins"
    assert [t["name"] for t in manifest["tables"]] == ["wp_options"]
    assert manifest["files"] == []
    out = capsys.readouterr().out
    assert out.count("| yes |") == 1
    assert "deactivated (2->1 active plugins)" in out


def test_registry_rollback_refused(tmp_path, capsys, monkeypatch, wpt_caplog):
    # The snapshot cannot be taken -> the rewrite never runs: the operator's
    # rollback (the pre-action options snapshot) stays possible because the
    # mutation never happened.
    src, session, bridge = make_stack([
        read_only(AKISMET, MIGRATION, missing=(MIGRATION,)),
        ok(**audit_payload()),
        FakeResponse(200, json.dumps({"ok": False, "error": "db dump failed"})),
    ])
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "reconcile-plugins")
    assert rc == 1
    assert posted_params(session, "reconcile_active_plugins") == [{}]
    assert capsys.readouterr().out == ""
    errors = _records(wpt_caplog, "wpt.actions", logging.ERROR)
    assert errors
    assert "refusing to apply" in errors[0].getMessage()


def test_registry_apply_anomaly_rc1(tmp_path, capsys, monkeypatch, wpt_caplog):
    src, session, bridge = make_stack([
        read_only(AKISMET, MIGRATION, missing=(MIGRATION,)),
        ok(**audit_payload()),
        FakeResponse(200, lines=table_lines("wp_options", [])),
        # the write is refused
        ok(installed=4, active_before=2, missing=[MIGRATION], applied=True,
           updated=False, removed=[MIGRATION], active_after=2,
           active_now=[AKISMET, MIGRATION]),
    ])
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "reconcile-plugins")
    assert rc == 1
    out = capsys.readouterr().out
    assert out == ""  # nothing printed as success
    errors = _records(wpt_caplog, "wpt.actions", logging.ERROR)
    assert errors
    assert "apply failed after backup" in errors[0].getMessage()
    # the pre-action backup is kept for `wpt restore --table wp_options`
    assert len(list((tmp_path / "backup").glob("*/*/manifest.json"))) == 1


def test_registry_local_mode_refused(tmp_path, wpt_caplog, monkeypatch):
    built = []

    def fail_stack(ctx):
        built.append(ctx)
        raise AssertionError("_stack must not be built for an inapplicable mode")

    monkeypatch.setattr(registry_mod, "_stack", fail_stack)
    rc = run_action(
        _ctx(tmp_path, source="local", zip=tmp_path / "site.zip",
             apply=True, yes=True),
        "reconcile-plugins",
    )
    assert rc == 1  # ftp-only: local mode has no DB write path
    assert built == []
    errors = _records(wpt_caplog, "wpt.actions", logging.ERROR)
    assert errors
    message = errors[0].getMessage()
    assert "ftp" in message and "local" in message
