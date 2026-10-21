"""Tests for the deactivate-plugin action (wpt.actions.deactivate).

A REAL Bridge over FakeSession/FakeSource (scripted info / db_audit /
plugin_deactivate / db_dump responses — tests/actions/test_clean_db.py
conventions): deterministic, no network, no sleeps.  The registry
end-to-end tests monkeypatch ``wpt.actions.registry._stack`` (the pinned
seam) to run the real ``run_action`` flow over a fake ftp-mode stack;
``bridge.destroy()`` (the registry's finally) is scripted via a
self-destruct handler.

Test -> behavior map:
  test_registration .......................... deactivate-plugin registered
        as the INSTANCE under applies=("ftp",) — local mode can never
        reach it
  test_plan_matching_active_plugin .......... one item per active file:
        category db.active_plugins, target = the options table, label
        carries the plugin file; backup_tables = the options table
        explicitly; requires_apply True, done False; ONE info plan
        summary; bridge traffic info + db_audit exactly once each.
        Single-file plugins ("hello.php") and "folder/file.php" slug
        input resolve identically (the bridge's own dirname rule)
  test_plan_multiple_active_files .......... several active files under
        one slug -> one item each, catalog order, ONE plugin_deactivate
        covers them
  test_plan_slug_not_active ................. installed-but-inactive and
        unknown slugs -> the clean-db "nothing to do" precedent: EMPTY
        plan (items == [], backup_tables == [] deliberately), one info
        naming why, info queried only (no db_audit roundtrip)
  test_plan_missing_or_bad_slug ............. missing/empty/whitespace/
        non-string ctx.extra["plugin"] -> WptError before any bridge call
  test_plan_no_options_table_refuses ........ matching plugin but the
        audit lists no *options table -> SourceError, never a plan that
        would mutate unbacked
  test_plan_backup_scope_fail_safe .......... a stray *options-suffixed
        table WIDENS the snapshot scope (never a miss) while the item's
        target stays the ONE table the identity owner resolves
  test_plan_target_is_the_resolved_options_table_not_the_first_by_name
        THE MEASURED CASE: db_audit reports the whole
        information_schema base-table set and AIOSEO 4.x really creates
        aioseo_options, so sorted()[0] named the PLUGIN's table in the
        plan and in every --report artifact; a contested identity is
        refused with both candidates named
  test_plan_target_is_the_options_table_on_an_uncontested_site
        the A/B: one options table resolves and is the target
  test_apply_success_marks_and_enriches ..... ONE plugin_deactivate call
        with slugs=<planned files>; items done; details enriched with
        the reported before->after counts; requires_apply=False items
        neither sent nor marked
  test_apply_empty_plan_no_bridge_call ....... zero planned files -> no
        bridge roundtrip
  test_apply_response_anomaly_bridge_error . updated not True / removed
        missing or not a list / a planned file absent from removed ->
        BridgeError carrying the payload, items stay done=False
        (fail-closed mid-apply; the registry aborts rc 1)
  test_apply_server_error_propagates ........ an ok:false answer from the
        client propagates untouched — no partial marking
  test_registry_dry_run ...................... run_action apply=False:
        plan printed (rc 0), info + db_audit only, no db_dump, no
        plugin_deactivate
  test_registry_ftp_apply_end_to_end ........ apply --yes over the fake
        stack: pre-action snapshot manifest lists the options table
        (scripted db_dump NDJSON), plugin_deactivate called once with the
        planned files, purge_cache called once (the registry's post-apply
        hygiene step — fires after a successful apply only), applied plan
        printed done + enriched, rc 0
  test_registry_apply_anomaly_rc1 ............ plugin_deactivate response
        anomaly after the backup: rc 1, registry error "apply failed
        after backup", nothing printed as success, backup kept (the
        options table) for restore
  test_registry_local_mode_refused ........... local mode: rc 1, the
        ftp-only applicability error, the stack (and so any bridge) is
        never even built
"""

import json
import logging

import pytest

from tests.fakes import FakeResponse, FakeSession, FakeSource
from wpt.actions import registry as registry_mod
from wpt.actions.deactivate import DeactivatePluginAction
from wpt.actions.registry import get_action, run_action
from wpt.cli import Ctx
from wpt.report import Plan
from wpt.settings import BridgeSettings, load
from wpt.types import BridgeError, PlanItem, SourceError, WptError
from wpt.wpbridge.client import Bridge

#: The shipped profile — every threshold exactly as users get it.
DEFAULTS = load()

WEBROOT = "domains/example.com/public_html"
SITE = "https://example.com"

LSC = "litespeed-cache/litespeed-cache.php"


@pytest.fixture
def wpt_caplog(caplog):
    """caplog wired to the non-propagating wpt logger tree (see
    tests/actions/test_clean_db.py — the wpt parent never reaches root)."""
    parent = logging.getLogger("wpt")
    parent.addHandler(caplog.handler)
    with caplog.at_level(logging.DEBUG, logger="wpt"):
        yield caplog
    parent.removeHandler(caplog.handler)


# ------------------------------------------------------------------ helpers


def _ctx(tmp_path, *, settings=DEFAULTS, slug=LSC.rsplit("/", 1)[0], **overrides):
    """A deactivate-plugin Ctx; ftp-mode defaults, overridable per test.

    ``slug`` lands in ctx.extra["plugin"]; ``slug=None`` omits the key.
    """
    fields = dict(
        source="ftp://example.com",
        settings=settings,
        command="deactivate-plugin",
        apply=False,
        yes=False,
        backup_dir=tmp_path / "backup",
        wp_url="https://example.com",
        extra={"plugin": slug} if slug is not None else {},
    )
    fields.update(overrides)
    return Ctx(**fields)


def _plugin(file, *, active=True, name="Example", version="1.0"):
    """One info-catalog wire entry: (file, {name, version, active})."""
    return file, {"name": name, "version": version, "active": active}


def info_payload(*entries):
    """An info payload in the wire shape tests/test_bridge_php.py pins."""
    return {
        "wp_version": "6.6",
        "siteurl": SITE,
        "home": SITE,
        "template": "twentytwentyfour",
        "stylesheet": "twentytwentyfour",
        "blog_public": 1,
        "plugins": dict(entries),
        "mu_plugins": 0,
        "uploads_basedir": "/home/example/public_html/wp-content/uploads",
        "uploads_error": "",
        "abspath": "/home/example/public_html/",
    }


def _tables(*names):
    """The named db_audit wire table rows (measured-zero free space)."""
    return [
        {"name": name, "rows": 10, "size_mb": 0.5, "data_free_kb": 0.0}
        for name in names
    ]


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


def deactivate_ok(before, after, removed, *, updated=True):
    """A successful plugin_deactivate answer in the pinned wire shape."""
    return ok(before=before, after=after, removed=removed, updated=updated)


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
    """A fake ftp-mode stack: (FakeSource, None, Bridge over FakeSession).

    The self-destruct handler rides last so the registry's ``finally:
    bridge.destroy()`` GET finds a scripted answer; unit tests that never
    destroy simply leave it unconsumed.
    """
    src = FakeSource()
    session = FakeSession(list(script) + [_selfdestruct(src)])
    bridge = Bridge(src, session, WEBROOT, BridgeSettings(), SITE)
    return src, session, bridge


def posted_actions(session):
    """Every bridge action POSTed, in order."""
    return [kwargs["json"]["action"] for _url, kwargs in session.posts]


def posted_params(session, action):
    """The ``params`` of every POST of ``action`` (usually exactly one)."""
    return [
        kwargs["json"]["params"]
        for _url, kwargs in session.posts
        if kwargs["json"]["action"] == action
    ]


def _records(caplog, name, level):
    return [
        r for r in caplog.records if r.name == name and r.levelno == level
    ]


def _plan(tmp_path, script, ctx=None):
    """plan() over a fresh scripted stack -> (plan, session)."""
    src, session, bridge = make_stack(script)
    plan = DeactivatePluginAction().plan(ctx or _ctx(tmp_path), (src, None, bridge))
    return plan, session


# ------------------------------------------------------------- registration


def test_registration():
    record = get_action("deactivate-plugin")
    assert record is not None
    assert record.applies == ("ftp",)
    assert isinstance(record.action, DeactivatePluginAction)  # instance


# ------------------------------------------------------------------- plan


def test_plan_matching_active_plugin(tmp_path, wpt_caplog):
    script = [
        ok(**info_payload(
            _plugin(LSC),
            _plugin("akismet/akismet.php", active=False),
        )),
        ok(**audit_payload()),
    ]
    plan, session = _plan(tmp_path, script)
    assert [
        (i.category, i.target, i.detail, i.bytes_est) for i in plan.items
    ] == [("db.active_plugins", "wp_options", f"deactivate {LSC}", 0)]
    # the explicit pin: the snapshot scope IS the options table
    assert plan.backup_tables == ["wp_options"]
    assert all(i.requires_apply for i in plan.items)
    assert all(not i.done for i in plan.items)
    # one info plan summary; info + db_audit exactly once each
    summaries = _records(wpt_caplog, "wpt.actions.deactivate", logging.INFO)
    assert len(summaries) == 1
    assert "1 item(s)" in summaries[0].getMessage()
    assert posted_actions(session) == ["info", "db_audit"]

    # a dirless single-file plugin matches by its whole filename
    plan, _session = _plan(tmp_path, [
        ok(**info_payload(_plugin("hello.php"))),
        ok(**audit_payload()),
    ], ctx=_ctx(tmp_path, slug="hello.php"))
    assert [
        (i.category, i.target, i.detail) for i in plan.items
    ] == [("db.active_plugins", "wp_options", "deactivate hello.php")]

    # a "folder/file.php" slug is reduced to its directory (the bridge's
    # own input rule) and plans the identical item
    plan, _session = _plan(tmp_path, [
        ok(**info_payload(_plugin(LSC))),
        ok(**audit_payload()),
    ], ctx=_ctx(tmp_path, slug=LSC))
    assert [
        (i.category, i.target, i.detail) for i in plan.items
    ] == [("db.active_plugins", "wp_options", f"deactivate {LSC}")]


def test_plan_multiple_active_files(tmp_path):
    script = [
        ok(**info_payload(
            _plugin("multi/first.php"),
            _plugin("multi/second.php"),
            _plugin("other/other.php"),
        )),
        ok(**audit_payload()),
    ]
    plan, session = _plan(tmp_path, script, ctx=_ctx(tmp_path, slug="multi"))
    # one item per matching ACTIVE file, catalog order; other.php not planned
    assert [i.detail for i in plan.items] == [
        "deactivate multi/first.php",
        "deactivate multi/second.php",
    ]
    assert all(i.target == "wp_options" for i in plan.items)
    assert plan.backup_tables == ["wp_options"]
    assert posted_actions(session) == ["info", "db_audit"]


def test_plan_slug_not_active(tmp_path, wpt_caplog):
    # installed but not active: the goal already holds — EMPTY plan
    plan, session = _plan(tmp_path, [
        ok(**info_payload(_plugin(LSC, active=False))),
    ])
    assert plan.items == []
    assert plan.backup_tables == []  # deliberately empty, not unset
    assert posted_actions(session) == ["info"]  # no db_audit roundtrip
    infos = _records(wpt_caplog, "wpt.actions.deactivate", logging.INFO)
    assert len(infos) == 1
    assert "installed but not active" in infos[0].getMessage()

    # unknown slug (nothing installed under it): same empty-plan contract
    plan, session = _plan(tmp_path, [
        ok(**info_payload(_plugin(LSC))),
    ], ctx=_ctx(tmp_path, slug="not-installed"))
    assert plan.items == []
    assert plan.backup_tables == []
    assert posted_actions(session) == ["info"]
    infos = _records(wpt_caplog, "wpt.actions.deactivate", logging.INFO)
    assert len(infos) == 2  # one reason line per scenario above
    assert "matches no installed plugin" in infos[-1].getMessage()


def test_plan_missing_or_bad_slug_refuses(tmp_path):
    for extra in ({}, {"plugin": ""}, {"plugin": "   "}, {"plugin": 42}):
        src, session, bridge = make_stack([])  # any POST would fail the fake
        with pytest.raises(WptError, match="slug"):
            DeactivatePluginAction().plan(
                _ctx(tmp_path, slug=None, **{"extra": extra} if extra else {}),
                (src, None, bridge),
            )
        assert session.posts == []  # refused before any bridge roundtrip


def test_plan_no_options_table_refuses(tmp_path):
    # the plugin is active, but the audit cannot locate the table the
    # deactivation would mutate -> never a plan that runs unbacked
    script = [
        ok(**info_payload(_plugin(LSC))),
        ok(**audit_payload("wp_posts", "wp_postmeta")),
    ]
    with pytest.raises(SourceError, match="options"):
        _plan(tmp_path, script)


def test_plan_backup_scope_fail_safe(tmp_path):
    # a stray *options-suffixed table beside the real one merely WIDENS the
    # snapshot scope (both are snapshotted), never a miss (clean-db's
    # rule) — and the item's target is the ONE table the identity owner
    # resolves, which is not a name-order question.
    script = [
        ok(**info_payload(_plugin(LSC))),
        ok(**audit_payload("wp_myoptions", "wp_posts")),
    ]
    plan, _session = _plan(tmp_path, script)
    assert plan.backup_tables == ["wp_myoptions"]
    assert [i.target for i in plan.items] == ["wp_myoptions"]


def test_plan_target_is_the_resolved_options_table_not_the_first_by_name(
        tmp_path):
    """THE MEASURED CASE: the plan named a table nothing mutates.

    ``db_audit`` reports the WHOLE ``information_schema`` base-table set,
    and AIOSEO 4.x really creates its own ``aioseo_options`` carrying the
    same option_name/option_value pair — so ``sorted(matches)[0]`` picked
    the PLUGIN's table (``a`` < ``w``) and the plan, the ``--report``
    artifact and the registry's fallback scope all named it.  The write was
    safe (the bridge rewrites through ``$wpdb->options``) and the REPORT was
    wrong, which is a plan the operator cannot trust.
    """
    script = [
        ok(**info_payload(_plugin(LSC))),
        ok(**audit_payload("aioseo_options", "wp_options", "wp_posts")),
    ]
    with pytest.raises(SourceError) as excinfo:
        _plan(tmp_path, script)
    message = str(excinfo.value)
    assert "aioseo_options" in message and "wp_options" in message
    assert "target is unknown" in message


def test_plan_target_is_the_options_table_on_an_uncontested_site(tmp_path):
    # the A/B: with one options table the identity resolves and the plan
    # names it — the report is right on the site where it used to be wrong.
    script = [
        ok(**info_payload(_plugin(LSC))),
        ok(**audit_payload("wp_commentmeta", "wp_options", "wp_postmeta",
                          "wp_posts", "wp_termmeta")),
    ]
    plan, _session = _plan(tmp_path, script)
    assert [i.target for i in plan.items] == ["wp_options"]
    assert plan.backup_tables == ["wp_options"]


# ------------------------------------------------------------------ apply


def test_apply_success_marks_and_enriches(tmp_path, wpt_caplog):
    src, session, bridge = make_stack([
        ok(**info_payload(_plugin(LSC), _plugin("akismet/akismet.php"))),
        ok(**audit_payload()),
        deactivate_ok(2, 1, [LSC]),
    ])
    action = DeactivatePluginAction()
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, (src, None, bridge))
    applied = action.apply(ctx, (src, None, bridge), plan)
    assert applied is plan  # the same Plan object, items updated in place
    assert posted_actions(session) == ["info", "db_audit", "plugin_deactivate"]
    # ONE call; the planned FILES are the bridge's slugs param (the exact
    # param name bridge.php reads)
    assert posted_params(session, "plugin_deactivate") == [{"slugs": [LSC]}]
    assert all(i.done for i in applied.items)
    # the response's before/after counts surface in the enriched detail
    assert [i.detail for i in applied.items] == [
        f"deactivate {LSC}, deactivated (2->1 active plugins)"
    ]
    summaries = _records(wpt_caplog, "wpt.actions.deactivate", logging.INFO)
    assert len(summaries) == 2  # one plan summary, one apply summary
    assert "1 plugin file(s) deactivated" in summaries[1].getMessage()

    # several planned files ride ONE call; a requires_apply=False item is
    # neither sent nor marked (defensive — this plan never builds one)
    plan = Plan(items=[
        PlanItem(category="db.active_plugins", target="wp_options",
                 detail="deactivate multi/a.php"),
        PlanItem(category="db.active_plugins", target="wp_options",
                 detail="deactivate multi/b.php"),
        PlanItem(category="db.info", target="none", detail="advice",
                 requires_apply=False),
    ])
    src, session, bridge = make_stack([
        deactivate_ok(3, 1, ["multi/a.php", "multi/b.php"]),
    ])
    by_detail = {i.detail: i for i in plan.items}  # items mutate in place
    applied = DeactivatePluginAction().apply(
        _ctx(tmp_path), (src, None, bridge), plan)
    assert posted_params(session, "plugin_deactivate") == [
        {"slugs": ["multi/a.php", "multi/b.php"]}
    ]
    assert by_detail["deactivate multi/a.php"].done
    assert by_detail["deactivate multi/b.php"].done
    assert not by_detail["advice"].done
    assert by_detail["advice"].detail == "advice"  # never enriched


def test_apply_empty_plan_no_bridge_call(tmp_path):
    src, session, bridge = make_stack([])  # any POST would fail the fake
    plan = Plan(items=[], backup_tables=[])
    applied = DeactivatePluginAction().apply(_ctx(tmp_path), (src, None, bridge), plan)
    assert applied is plan
    assert session.posts == []  # nothing planned -> no bridge roundtrip


def test_apply_response_anomaly_bridge_error(tmp_path):
    # updated not True: update_option did not rewrite the option
    plan = Plan(items=[
        PlanItem(category="db.active_plugins", target="wp_options",
                 detail=f"deactivate {LSC}"),
    ])
    src, session, bridge = make_stack([
        deactivate_ok(1, 1, [LSC], updated=None),
    ])
    with pytest.raises(BridgeError, match="anomaly"):
        DeactivatePluginAction().apply(_ctx(tmp_path), (src, None, bridge), plan)
    assert not plan.items[0].done

    # removed missing / not a list: the payload proves nothing
    for payload in ({"before": 1, "after": 0, "updated": True},
                    {"before": 1, "after": 0, "updated": True,
                     "removed": "litespeed-cache"}):
        src, session, bridge = make_stack([ok(**payload)])
        with pytest.raises(BridgeError, match="anomaly"):
            DeactivatePluginAction().apply(_ctx(tmp_path), (src, None, bridge), plan)
        assert not plan.items[0].done

    # a planned file absent from removed: the deactivity is unproven
    src, session, bridge = make_stack([
        deactivate_ok(2, 2, []),
    ])
    with pytest.raises(BridgeError, match="did not remove"):
        DeactivatePluginAction().apply(_ctx(tmp_path), (src, None, bridge), plan)
    assert not plan.items[0].done


def test_apply_server_error_propagates(tmp_path):
    # an ok:false answer raises inside the client; no partial state exists
    # to mark (ONE update_option covers every file) — propagate untouched
    plan = Plan(items=[
        PlanItem(category="db.active_plugins", target="wp_options",
                 detail=f"deactivate {LSC}"),
    ])
    src, session, bridge = make_stack([
        FakeResponse(200, json.dumps({
            "ok": False, "error": "update_option failed",
        })),
    ])
    with pytest.raises(BridgeError, match="update_option failed"):
        DeactivatePluginAction().apply(_ctx(tmp_path), (src, None, bridge), plan)
    assert not plan.items[0].done  # stays undone; the registry reports rc 1


# ------------------------------------------------------- registry end-to-end


def test_registry_dry_run(tmp_path, capsys, monkeypatch):
    src, session, bridge = make_stack([
        ok(**info_payload(_plugin(LSC))),
        ok(**audit_payload()),
    ])
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    rc = run_action(_ctx(tmp_path), "deactivate-plugin")
    assert rc == 0
    out = capsys.readouterr().out
    assert "## Plan" in out
    assert "db.active_plugins" in out
    assert "wp_options" in out
    assert f"deactivate {LSC}" in out
    # read-only: info + db_audit, no db_dump (no backup), no plugin_deactivate
    assert posted_actions(session) == ["info", "db_audit"]


def test_registry_ftp_apply_end_to_end(tmp_path, capsys, monkeypatch):
    dump_lines = table_lines(
        "wp_options", [["1", "active_plugins", "a:1:{i:0;s:31:...;}", "yes"]]
    )
    src, session, bridge = make_stack([
        ok(**info_payload(_plugin(LSC))),
        ok(**audit_payload()),
        FakeResponse(200, lines=dump_lines),
        deactivate_ok(1, 0, [LSC]),
        ok(purged=True),  # the registry's post-apply purge answer
    ])
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "deactivate-plugin")
    assert rc == 0
    # bridge traffic: info, db_audit, ONE db_dump of the options table,
    # ONE plugin_deactivate with the planned file, then the registry's
    # exactly-one post-apply purge_cache (best-effort hygiene; fires
    # before the bridge is destroyed)
    assert posted_actions(session) == ["info", "db_audit", "db_dump",
                                       "plugin_deactivate", "purge_cache"]
    assert posted_params(session, "db_dump") == [{"tables": ["wp_options"]}]
    assert posted_params(session, "plugin_deactivate") == [{"slugs": [LSC]}]
    assert posted_params(session, "purge_cache") == [{}]
    # fail-closed pre-action backup: the manifest lists the options table
    manifests = list((tmp_path / "backup").glob("*/*/manifest.json"))
    assert len(manifests) == 1
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    assert manifest["action"] == "deactivate-plugin"
    assert manifest["site"] == "example.com"
    assert [t["name"] for t in manifest["tables"]] == ["wp_options"]
    assert manifest["files"] == []  # DB-only action — no file scope
    assert (manifests[0].parent / "db/wp_options.ndjson").exists()
    # the applied plan prints the item done with the enriched detail
    out = capsys.readouterr().out
    assert out.count("| yes |") == 1
    assert f"deactivate {LSC}, deactivated (1->0 active plugins)" in out


def test_registry_apply_anomaly_rc1(tmp_path, capsys, monkeypatch, wpt_caplog):
    dump_lines = table_lines("wp_options", [["1", "active_plugins", "a:1:{}", "yes"]])
    src, session, bridge = make_stack([
        ok(**info_payload(_plugin(LSC))),
        ok(**audit_payload()),
        FakeResponse(200, lines=dump_lines),
        deactivate_ok(1, 1, []),  # nothing removed: response anomaly
    ])
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "deactivate-plugin")
    assert rc == 1
    # the unapplied plan is NOT printed as success (nothing is)
    out = capsys.readouterr().out
    assert out == ""
    assert "## Plan" not in out
    # the registry reports the apply failure AFTER the backup; the action
    # raised the anomaly (fail-closed mid-apply)
    errors = _records(wpt_caplog, "wpt.actions", logging.ERROR)
    assert errors and "apply failed after backup" in errors[0].getMessage()
    # the fail-closed backup exists for the operator to restore
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
        "deactivate-plugin",
    )
    assert rc == 1  # ftp-only: local mode has no DB write path
    assert built == []  # no stack, hence no bridge, hence no bridge calls
    errors = _records(wpt_caplog, "wpt.actions", logging.ERROR)
    assert errors
    message = errors[0].getMessage()
    assert "ftp" in message and "local" in message
