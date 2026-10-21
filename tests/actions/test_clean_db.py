"""Tests for the clean-db action (wpt.actions.clean_db) — W7e.

A REAL Bridge over FakeSession/FakeSource (scripted db_audit / db_clean /
db_dump responses — tests/test_bridge_client.py + tests/test_backup.py
conventions): deterministic, no network, no sleeps.  The registry
end-to-end tests monkeypatch ``wpt.actions.registry._stack`` (the pinned
seam) to run the real ``run_action`` flow over a fake ftp-mode stack;
``bridge.destroy()`` (the registry's finally) is scripted via a
self-destruct handler.

Test -> behavior map:
  test_registration .......................... clean-db registered as the
        INSTANCE under applies=("ftp",) — local mode can never reach it
  test_plan_each_op_triggers_sorted_ ... ..... one item per triggering op
        with the exact (category, target, detail, bytes_est); sorted by
        (category, target); backup_tables = every table the three row
        ops mutate; requires_apply all True, done all False; ONE info
        plan summary; exactly one db_audit bridge call
  test_plan_unknown_never_triggers .......... None/absent/malformed audit
        fields are UNKNOWN, never zero: no items, empty backup scope
  test_plan_measured_zero_never_triggers ..... explicit zeros everywhere
        (revisions/transients/orphan kinds/data_free) -> empty plan
  test_plan_orphan_one_item_summed_detail ..... several orphan kinds ->
        ONE item (one op), kinds joined sorted + counts summed; a
        measured-zero kind never joins the sum
  test_plan_optimize_threshold_from_settings . below the shipped 1 MiB
        threshold silent, AT it triggers (>=), several tables sum; the
        threshold itself comes from settings.db.free_space_warn_bytes
  test_plan_backup_tables_per_op ............ per triggering op: revisions
        -> posts, transients -> options, orphan -> the three meta tables
        (even when only one kind is orphaned), mixed combos unioned
  test_plan_optimize_only_empty_backup ....... optimize-only plan:
        one item, backup_tables EMPTY (optimize mutates no rows)
  test_plan_refuses_unbacked_mutation ........ a triggering row-op whose
        table the audit cannot name -> SourceError, never a plan that
        would mutate unbacked
  test_apply_single_db_clean_call_ .......... ONE db_clean call, ops
        deduped in plan order; all items done; details enriched with the
        reported counts (rows removed / tables optimized)
  test_apply_dedupes_ops_and_skips_ .......... duplicate targets collapse
        preserving order; requires_apply=False items are neither applied
        nor enriched
  test_apply_empty_plan_no_bridge_call ....... zero ops -> no bridge call
  test_apply_partial_failure_marks_ .......... db_clean ok:false with
        partial results + errors: succeeded op's item done + enriched,
        failed ops not done, one warning per failed op, BridgeError
        re-raised carrying the payload
  test_registry_dry_run ...................... run_action apply=False:
        plan printed (rc 0), exactly one db_audit call, no db_dump /
        db_clean (read-only)
  test_registry_ftp_apply_end_to_end ........ apply --yes over the fake
        stack: pre-action snapshot manifest lists plan.backup_tables
        (scripted db_dump NDJSON), db_clean called with the planned ops,
        applied plan printed with counts, rc 0
  test_registry_ftp_apply_partial_ .......... db_clean ok:false after the
        backup: rc 1, registry error "apply failed after backup", the
        partial plan NOT printed as success, backup kept for restore
  test_registry_local_mode_refused ........... local mode: rc 1, the
        ftp-only applicability error, the stack (and so any bridge) is
        never even built
  test_offline_dry_run_is_the_ftp_plan ..... --db-uri: the SAME plan, the
        SAME items/details, built by the same builder; read-only
  test_offline_apply_runs_the_bridges_sql .. --apply --yes: the executed
        statements are EXACTLY the bridge's, in plan order; results
        enriched; verify-after-change re-reads the facts
  test_offline_verification_refuses_ ...... a delete that did not land
        leaves the item not-done and the run at rc 1
  test_offline_failed_op_is_rc1 ............ one op's SQL error: warning
        per failed op, no verification, nothing printed as success
  test_offline_unknown_op_is_refused ....... the op vocabulary stays the
        bridge's whitelist
  test_offline_apply_needs_confirmation .... --apply without --yes on a
        non-tty is refused and executes nothing
  test_offline_clean_database_writes_nothing  an all-zero audit: no
        statement runs
  test_offline_prefix_is_discovered ....... the prefix comes from the
        database's own options table (never guessed); an ambiguous options
        identity REFUSES the run instead of picking one
  test_offline_re_dump_round_trips ........ --re-dump writes a dump the
        analyzer reads back, and only over a verified apply
  test_offline_never_prints_the_password .. the DSN password reaches no
        log line, no stdout and no artifact; the URI still renders
"""

import json
import logging
from dataclasses import replace

import pytest

from tests.fakes import FakeResponse, FakeSession, FakeSource
from wpt.actions import registry as registry_mod
from wpt.actions.clean_db import CleanDbAction
from wpt.actions.registry import get_action, run_action
from wpt.cli import Ctx
from wpt.report import Plan
from wpt.settings import BridgeSettings, load
from wpt.types import BridgeError, PlanItem, SourceError, WptError
from wpt.wpbridge.client import Bridge

#: The shipped profile — every threshold exactly as users get it
#: (db.free_space_warn_bytes == 1048576).
DEFAULTS = load()

WEBROOT = "domains/example.com/public_html"
SITE = "https://example.com"


@pytest.fixture
def wpt_caplog(caplog):
    """caplog wired to the non-propagating wpt logger tree (see
    tests/actions/test_clean_files.py — the wpt parent never reaches root)."""
    parent = logging.getLogger("wpt")
    parent.addHandler(caplog.handler)
    with caplog.at_level(logging.DEBUG, logger="wpt"):
        yield caplog
    parent.removeHandler(caplog.handler)


# ------------------------------------------------------------------ helpers


def _ctx(tmp_path, *, settings=DEFAULTS, **overrides):
    """A clean-db Ctx; ftp-mode defaults, overridable per test."""
    fields = dict(
        source="ftp://example.com",
        settings=settings,
        command="clean-db",
        apply=False,
        yes=False,
        backup_dir=tmp_path / "backup",
        wp_url="https://example.com",
    )
    fields.update(overrides)
    return Ctx(**fields)


def _tables(**data_free_kb):
    """The five core tables as db_audit wire rows, per-name data_free_kb.

    All default to 0.0 (a measured zero -> db.optimize stays silent).
    """
    free = {
        "wp_commentmeta": 0.0,
        "wp_options": 0.0,
        "wp_postmeta": 0.0,
        "wp_posts": 0.0,
        "wp_termmeta": 0.0,
    }
    free.update(data_free_kb)
    return [
        {"name": name, "rows": 10, "size_mb": 0.5, "data_free_kb": value}
        for name, value in sorted(free.items())
    ]


def audit_payload(**over):
    """A db_audit payload in the wire shape tests/test_bridge_php.py pins."""
    payload = {
        "posts": [],
        "revisions": 0,
        "expired_transients": 0,
        "orphan_meta": {},
        "tables": _tables(),
        "autoload_bytes": 123456,
        "attachments": 3,
        "nav_menu_items": 2,
    }
    payload.update(over)
    return payload


#: One audit where every op triggers: 5 revisions, 7 expired transients,
#: 4 orphaned postmeta rows and wp_posts carrying 2048 KiB of free space.
RICH = dict(
    revisions=5,
    expired_transients=7,
    orphan_meta={"postmeta": 4},
    tables=_tables(wp_posts=2048.0),
)


def ok(**payload):
    """An ok:true bridge envelope (the payload the client returns)."""
    return FakeResponse(200, json.dumps({"ok": True, **payload}))


def db_clean_ok(**results):
    """A successful db_clean answer: per-op counts, no errors."""
    return ok(results=results, errors={})


def db_clean_partial(results, errors):
    """A failed db_clean answer (ok:false) still carrying partial results."""
    return FakeResponse(
        200,
        json.dumps(
            {
                "ok": False,
                "error": "failed ops: " + ", ".join(sorted(errors)),
                "results": results,
                "errors": errors,
            }
        ),
    )


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
    plan = CleanDbAction().plan(ctx or _ctx(tmp_path), (src, None, bridge))
    return plan, session


# ------------------------------------------------------------- registration


def test_registration():
    record = get_action("clean-db")
    assert record is not None
    assert record.applies == ("ftp",)
    assert isinstance(record.action, CleanDbAction)  # the instance, not the class


# ------------------------------------------------------------------- plan


def test_plan_each_op_triggers_sorted_with_backup_scope(tmp_path, wpt_caplog):
    plan, session = _plan(tmp_path, [ok(**audit_payload(**RICH))])
    assert [
        (i.category, i.target, i.detail, i.bytes_est) for i in plan.items
    ] == [
        ("db.optimize", "optimize_tables", "1 tables, ~2.0 MB reclaimable", 2097152),
        ("db.orphan_meta", "orphan_meta", "postmeta: 4 orphan rows", 0),
        ("db.revisions", "revisions", "5 revisions + auto-drafts", 0),
        ("db.transients", "expired_transients", "7 expired transients", 0),
    ]
    assert plan.est_bytes() == 2097152  # only the optimize item estimates bytes
    # every table the three row ops mutate, sorted; optimize adds nothing
    assert plan.backup_tables == [
        "wp_commentmeta", "wp_options", "wp_postmeta", "wp_posts", "wp_termmeta",
    ]
    assert all(i.requires_apply for i in plan.items)
    assert all(not i.done for i in plan.items)
    # exactly one info plan summary; exactly one bridge call (read-only)
    summaries = _records(wpt_caplog, "wpt.actions.clean_db", logging.INFO)
    assert len(summaries) == 1
    assert "4 item(s)" in summaries[0].getMessage()
    assert posted_actions(session) == ["db_audit"]


def test_plan_unknown_never_triggers(tmp_path):
    # explicit None + absent keys + unusable values are all UNKNOWN (the
    # dbcheck rule): unknown is not zero and must never trigger.
    payload = {
        "revisions": None,
        "expired_transients": None,  # and orphan_meta / tables absent
        "orphan_meta": {"postmeta": None},  # unusable kind stays unknown
        "tables": [{"name": "wp_posts", "rows": 5}],  # no data_free_kb
    }
    plan, _session = _plan(tmp_path, [ok(**payload)])
    assert plan.items == []
    assert plan.backup_tables == []
    # a payload with no DB facts at all is equally silent
    plan2, _s2 = _plan(tmp_path, [ok()])
    assert plan2.items == []
    assert plan2.backup_tables == []


def test_plan_measured_zero_never_triggers(tmp_path):
    payload = audit_payload(
        revisions=0,
        expired_transients=0,
        orphan_meta={"postmeta": 0, "termmeta": 0, "commentmeta": 0},
        tables=_tables(),  # every data_free_kb a measured 0.0
    )
    plan, _session = _plan(tmp_path, [ok(**payload)])
    assert plan.items == []
    assert plan.backup_tables == []


def test_plan_orphan_one_item_summed_detail(tmp_path):
    # several kinds trigger -> ONE item (ONE op), kinds sorted + counts summed
    payload = audit_payload(
        orphan_meta={"postmeta": 4, "termmeta": 1, "commentmeta": 2}
    )
    plan, _session = _plan(tmp_path, [ok(**payload)])
    assert [
        (i.category, i.target, i.detail, i.bytes_est) for i in plan.items
    ] == [
        ("db.orphan_meta", "orphan_meta",
         "commentmeta+postmeta+termmeta: 7 orphan rows", 0)
    ]
    # the op mutates all three meta tables even though one kind was orphaned
    assert plan.backup_tables == ["wp_commentmeta", "wp_postmeta", "wp_termmeta"]

    # a measured-zero kind never joins the sum
    payload = audit_payload(orphan_meta={"postmeta": 4, "termmeta": 0})
    plan, _session = _plan(tmp_path, [ok(**payload)])
    assert [i.detail for i in plan.items] == ["postmeta: 4 orphan rows"]
    assert plan.backup_tables == ["wp_commentmeta", "wp_postmeta", "wp_termmeta"]


def test_plan_optimize_threshold_from_settings(tmp_path):
    # below the shipped threshold (512 KiB < 1 MiB): silent
    plan, _session = _plan(tmp_path, [ok(**audit_payload(tables=_tables(wp_posts=512.0)))])
    assert plan.items == []

    # AT the threshold (1024.0 KiB -> 1048576 bytes): >= triggers
    plan, _session = _plan(tmp_path, [ok(**audit_payload(tables=_tables(wp_posts=1024.0)))])
    assert [(i.target, i.detail, i.bytes_est) for i in plan.items] == [
        ("optimize_tables", "1 tables, ~1.0 MB reclaimable", 1048576)
    ]

    # several qualifying tables: ONE item, counts and bytes summed
    payload = audit_payload(tables=_tables(wp_posts=2048.0, wp_options=1024.0))
    plan, _session = _plan(tmp_path, [ok(**payload)])
    assert [(i.detail, i.bytes_est) for i in plan.items] == [
        ("2 tables, ~3.0 MB reclaimable", 3145728)
    ]

    # the threshold flows from settings.db.free_space_warn_bytes, never a
    # literal: 512 KiB qualifies under a lowered threshold
    settings = replace(DEFAULTS, db=replace(DEFAULTS.db, free_space_warn_bytes=100_000))
    plan, _session = _plan(
        tmp_path,
        [ok(**audit_payload(tables=_tables(wp_posts=512.0)))],
        ctx=_ctx(tmp_path, settings=settings),
    )
    assert [i.bytes_est for i in plan.items] == [524288]


def test_plan_backup_tables_per_op(tmp_path):
    cases = [
        (dict(revisions=5), ["wp_posts"]),
        (dict(expired_transients=7), ["wp_options"]),
        # only termmeta orphans, yet all three meta tables back the op
        (dict(orphan_meta={"termmeta": 1}), ["wp_commentmeta", "wp_postmeta", "wp_termmeta"]),
        (dict(revisions=5, expired_transients=7), ["wp_options", "wp_posts"]),
        (
            dict(revisions=5, expired_transients=7, orphan_meta={"postmeta": 2}),
            ["wp_commentmeta", "wp_options", "wp_postmeta", "wp_posts", "wp_termmeta"],
        ),
    ]
    for over, expected in cases:
        plan, _session = _plan(tmp_path, [ok(**audit_payload(**over))])
        assert plan.backup_tables == expected, over


def test_plan_optimize_only_empty_backup(tmp_path):
    # optimize_tables mutates no rows: an OPTIMIZE-only plan snapshots
    # nothing (backup_tables EMPTY — see the module docstring for the
    # registry `or`-fallback hazard this case exposes).
    payload = audit_payload(tables=_tables(wp_posts=2048.0))
    plan, _session = _plan(tmp_path, [ok(**payload)])
    assert [i.target for i in plan.items] == ["optimize_tables"]
    assert plan.backup_tables == []


def test_plan_refuses_unbacked_mutation(tmp_path):
    # revisions trigger but the audit lists no posts table -> SourceError,
    # never a plan whose apply would delete from an unsnapshotted table
    payload = audit_payload(
        revisions=5, tables=[{"name": "wp_options", "rows": 1, "size_mb": 0.1, "data_free_kb": 0.0}]
    )
    with pytest.raises(SourceError, match="posts"):
        _plan(tmp_path, [ok(**payload)])

    # orphan_meta triggers but two of the three meta tables are missing
    payload = audit_payload(
        orphan_meta={"postmeta": 4},
        tables=[{"name": "wp_postmeta", "rows": 3, "size_mb": 0.1, "data_free_kb": 0.0}],
    )
    with pytest.raises(SourceError, match="termmeta"):
        _plan(tmp_path, [ok(**payload)])


# ------------------------------------------------------------------ apply


def test_apply_single_db_clean_call_marks_and_enriches(tmp_path):
    src, session, bridge = make_stack([
        ok(**audit_payload(**RICH)),
        db_clean_ok(revisions=5, expired_transients=7, orphan_meta=7, optimize_tables=3),
    ])
    action = CleanDbAction()
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, (src, None, bridge))
    applied = action.apply(ctx, (src, None, bridge), plan)
    assert applied is plan  # the same Plan object, items updated in place
    assert posted_actions(session) == ["db_audit", "db_clean"]
    # ONE db_clean call; ops deduped in plan (category-sorted) order
    assert posted_params(session, "db_clean") == [
        {"ops": ["optimize_tables", "orphan_meta", "revisions", "expired_transients"]}
    ]
    assert all(i.done for i in applied.items)
    # each item's detail enriched with its op's reported count
    assert [i.detail for i in applied.items] == [
        "1 tables, ~2.0 MB reclaimable, optimized 3 tables",
        "postmeta: 4 orphan rows, removed 7 rows",
        "5 revisions + auto-drafts, removed 5 rows",
        "7 expired transients, removed 7 rows",
    ]


def test_apply_dedupes_ops_and_skips_non_apply_items(tmp_path):
    plan = Plan(items=[
        PlanItem(category="db.revisions", target="revisions", detail="r1"),
        PlanItem(category="db.revisions", target="revisions", detail="r2"),
        PlanItem(category="db.transients", target="expired_transients", detail="t"),
        PlanItem(category="db.info", target="none", detail="advice",
                 requires_apply=False),
    ])
    src, session, bridge = make_stack([db_clean_ok(revisions=1, expired_transients=1)])
    by_detail = {i.detail: i for i in plan.items}  # items mutate in place
    applied = CleanDbAction().apply(_ctx(tmp_path), (src, None, bridge), plan)
    assert applied is plan
    # duplicates collapsed preserving first-seen order; advice op never sent
    assert posted_params(session, "db_clean") == [
        {"ops": ["revisions", "expired_transients"]}
    ]
    assert by_detail["r1"].done and by_detail["r2"].done
    assert by_detail["t"].done
    assert not by_detail["advice"].done  # never applied...
    assert by_detail["advice"].detail == "advice"  # ...so never enriched


def test_apply_empty_plan_no_bridge_call(tmp_path):
    src, session, bridge = make_stack([])  # any POST would fail the fake
    plan = Plan()
    applied = CleanDbAction().apply(_ctx(tmp_path), (src, None, bridge), plan)
    assert applied is plan
    assert session.posts == []  # nothing to clean -> no bridge roundtrip


def test_apply_partial_failure_marks_done_warns_and_reraises(tmp_path, wpt_caplog):
    src, session, bridge = make_stack([
        ok(**audit_payload(
            revisions=5, expired_transients=7, orphan_meta={"postmeta": 2}
        )),
        db_clean_partial(
            results={"expired_transients": 7},
            errors={
                "revisions": "db error: lock wait timeout",
                "orphan_meta": "db error: deadlock",
            },
        ),
    ])
    action = CleanDbAction()
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, (src, None, bridge))
    with pytest.raises(BridgeError) as excinfo:
        action.apply(ctx, (src, None, bridge), plan)
    # the re-raised error still carries the partial server payload
    assert excinfo.value.payload["results"] == {"expired_transients": 7}
    by_target = {i.target: i for i in plan.items}
    assert by_target["expired_transients"].done
    assert by_target["expired_transients"].detail == "7 expired transients, removed 7 rows"
    assert not by_target["revisions"].done
    assert by_target["revisions"].detail == "5 revisions + auto-drafts"  # untouched
    assert not by_target["orphan_meta"].done
    assert by_target["orphan_meta"].detail == "postmeta: 2 orphan rows"  # untouched
    # one warning per failed op, from this action's logger
    warnings = _records(wpt_caplog, "wpt.actions.clean_db", logging.WARNING)
    assert len(warnings) == 2
    assert "revisions" in warnings[0].getMessage() or "revisions" in warnings[1].getMessage()
    assert "orphan_meta" in warnings[0].getMessage() or "orphan_meta" in warnings[1].getMessage()
    assert "lock wait timeout" in "".join(w.getMessage() for w in warnings)


# ------------------------------------------------------- registry end-to-end


def test_registry_dry_run(tmp_path, capsys, monkeypatch):
    src, session, bridge = make_stack([ok(**audit_payload(**RICH))])
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    rc = run_action(_ctx(tmp_path), "clean-db")
    assert rc == 0
    out = capsys.readouterr().out
    assert "## Plan" in out
    for target in ("revisions", "expired_transients", "orphan_meta", "optimize_tables"):
        assert target in out
    assert "5 revisions + auto-drafts" in out
    assert "1 tables, ~2.0 MB reclaimable" in out
    # read-only: one db_audit call, no db_dump (no backup), no db_clean
    assert posted_actions(session) == ["db_audit"]


def test_registry_ftp_apply_end_to_end(tmp_path, capsys, monkeypatch):
    audit = audit_payload(revisions=5, expired_transients=7)
    dump_lines = (
        table_lines("wp_options", [["1", "siteurl", "https://example.com", "yes"]])
        + table_lines("wp_posts", [["1", "post", "publish"]])
    )
    src, session, bridge = make_stack([
        ok(**audit),
        FakeResponse(200, lines=dump_lines),
        db_clean_ok(revisions=5, expired_transients=7),
        ok(purged=True),  # the registry's post-apply cache purge
    ])
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "clean-db")
    assert rc == 0
    # bridge traffic: audit, ONE db_dump covering both backup tables, db_clean,
    # then the post-apply purge
    assert posted_actions(session) == ["db_audit", "db_dump", "db_clean",
                                        "purge_cache"]
    assert posted_params(session, "db_dump") == [{"tables": ["wp_options", "wp_posts"]}]
    assert posted_params(session, "db_clean") == [
        {"ops": ["revisions", "expired_transients"]}
    ]
    # fail-closed pre-action backup: the manifest lists plan.backup_tables
    manifests = list((tmp_path / "backup").glob("*/*/manifest.json"))
    assert len(manifests) == 1
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    assert manifest["action"] == "clean-db"
    assert manifest["site"] == "example.com"
    assert [t["name"] for t in manifest["tables"]] == ["wp_options", "wp_posts"]
    assert manifest["files"] == []  # no file targets — tables only
    assert (manifests[0].parent / "db/wp_options.ndjson").exists()
    assert (manifests[0].parent / "db/wp_posts.ndjson").exists()
    # the applied plan prints every item done, details carrying the counts
    out = capsys.readouterr().out
    assert out.count("| yes |") == 2
    assert "5 revisions + auto-drafts, removed 5 rows" in out
    assert "7 expired transients, removed 7 rows" in out


def test_registry_ftp_apply_partial_failure_rc1(tmp_path, capsys, monkeypatch, wpt_caplog):
    audit = audit_payload(revisions=5, expired_transients=7)
    dump_lines = (
        table_lines("wp_options", [["1", "siteurl", "s", "yes"]])
        + table_lines("wp_posts", [["1", "post", "publish"]])
    )
    src, session, bridge = make_stack([
        ok(**audit),
        FakeResponse(200, lines=dump_lines),
        db_clean_partial(
            results={"expired_transients": 7},
            errors={"revisions": "db error: lock wait timeout"},
        ),
    ])
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "clean-db")
    assert rc == 1
    # the partially-applied plan is NOT printed as success (nothing is)
    out = capsys.readouterr().out
    assert out == ""
    assert "## Plan" not in out
    # the registry reports the apply failure AFTER the backup; the action
    # logged the per-op warning from the partial payload
    errors = _records(wpt_caplog, "wpt.actions", logging.ERROR)
    assert errors and "apply failed after backup" in errors[0].getMessage()
    warnings = _records(wpt_caplog, "wpt.actions.clean_db", logging.WARNING)
    assert warnings and "revisions" in warnings[0].getMessage()
    # the fail-closed backup exists for the operator to restore
    assert len(list((tmp_path / "backup").glob("*/*/manifest.json"))) == 1


def test_registry_local_mode_refused(tmp_path, wpt_caplog, monkeypatch):
    built = []

    def fail_stack(ctx):
        built.append(ctx)
        raise AssertionError("_stack must not be built for an inapplicable mode")

    monkeypatch.setattr(registry_mod, "_stack", fail_stack)
    rc = run_action(
        _ctx(tmp_path, source="local", zip=tmp_path / "site.zip", apply=True, yes=True),
        "clean-db",
    )
    assert rc == 1  # ftp-only: local mode has no DB write path
    assert built == []  # no stack, hence no bridge, hence no bridge calls
    errors = _records(wpt_caplog, "wpt.actions", logging.ERROR)
    assert errors
    message = errors[0].getMessage()
    assert "ftp" in message and "local" in message


def test_registry_optimize_only_skips_db_backup(tmp_path, capsys, monkeypatch):
    # backup_tables == [] is DELIBERATE (optimize mutates no rows): the
    # registry must not fall back to deriving "optimize_tables" as a table
    # name from the db.-prefixed item target (a real bridge would refuse
    # db_dump and fail the whole apply). Registry bug pin.
    audit = audit_payload(tables=[{"name": "wp_posts", "rows": 100,
                                   "size_mb": 8.0, "data_free_kb": 4096}])
    src, session, bridge = make_stack([
        ok(**audit),
        db_clean_ok(optimize_tables=6),
        ok(purged=True),  # the registry's post-apply cache purge
    ])
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "clean-db")
    assert rc == 0
    assert posted_actions(session) == ["db_audit", "db_clean",  # NO db_dump
                                        "purge_cache"]
    manifests = list((tmp_path / "backup").glob("*/*/manifest.json"))
    assert len(manifests) == 1
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    assert manifest["tables"] == []       # nothing snapshotted
    assert manifest["files"] == []        # no file scope either


# ===========================================================================
# The OFFLINE path (--db-uri): the same plan, the same ops, the same
# results contract — spoken straight to a database instead of the bridge.
# No live DB is ever contacted: the driver seam is wpt.localmode.dbconn
# .connect, patched here (tests/test_dbconn.py owns the double).
# ===========================================================================


def _offline_db(**over):
    """A database where every op triggers, and where a delete really lands.

    The database also STATES ITS OWN IDENTITY (the ``siteurl``/``home``
    the offline wrong-database gate reads) — the double answers that
    lookup itself rather than falling through to its ``[(0,)]`` default,
    which is what a driver-less fixture can honestly say about a
    WordPress options table.  ``identities=`` overrides the answer for the
    gate's own cases (a foreign site, a half-stated identity, no identity
    at all); the lookup is recognised by its statement shape, so no other
    statement in the flow changes behaviour.
    """
    from tests.test_dbconn import wp_dumpable, wp_schema

    db = wp_dumpable()
    db.schema = wp_schema(wp_posts=2048.0)
    db.identities = {"siteurl": "https://example.com",
                     "home": "https://example.com"}
    real_query_rows = db.query_rows

    def query_rows(sql: str):
        # the identity lookup, whatever prefix the options table carries
        if sql.startswith("SELECT option_name, option_value FROM"):
            return [(name, value) for name, value in db.identities.items()]
        return real_query_rows(sql)

    db.query_rows = query_rows
    db.counts = {
        "post_type = 'revision'": 5,
        "_transient_": 7,
        "pm LEFT JOIN": 4,
        "tm LEFT JOIN": 1,
        "cm LEFT JOIN": 0,
    }
    db.deletes = {
        "DELETE FROM wp_posts": 5,
        "DELETE t, s": 7,
        "DELETE pm": 4,
        "DELETE tm": 1,
        "DELETE cm": 0,
    }
    # a real server empties what it deleted — the verification pass must see
    # the database as it is now, not as the plan found it
    def _landed(sql):
        if "post_type = 'revision'" in sql:
            db.counts["post_type = 'revision'"] = 0
        elif sql.startswith("DELETE t, s"):
            db.counts["_transient_"] = 0
        elif sql.startswith("DELETE pm"):
            db.counts["pm LEFT JOIN"] = 0
        elif sql.startswith("DELETE tm"):
            db.counts["tm LEFT JOIN"] = 0
        elif sql.startswith("DELETE cm"):
            db.counts["cm LEFT JOIN"] = 0
    db.on_execute = _landed
    for key, value in over.items():
        setattr(db, key, value)
    return db


def _offline_ctx(tmp_path, db, **over):
    """A local-mode clean-db Ctx whose driver is the double."""
    from wpt.actions import clean_db as clean_db_mod

    fields = dict(
        source="local",
        settings=DEFAULTS,
        command="clean-db",
        apply=True,
        yes=True,
        backup_dir=tmp_path / "backup",
        db_uri="mysql://wpuser:inline-secret@db.internal:3307/wp_stage",
        db_password="inline-secret",
        # the site this run is ABOUT — matched against the database's own
        # siteurl/home by the wrong-database gate
        wp_url="https://example.com",
    )
    fields.update(over)
    return clean_db_mod, Ctx(**fields)


def _patched(tmp_path, monkeypatch, db, **over):
    mod, ctx = _offline_ctx(tmp_path, db, **over)
    monkeypatch.setattr(
        mod, "connect",
        lambda uri, password=None, deadline=None, settings=None: db)
    return ctx


#: The bridge's own statements, written out: the offline apply must run
#: exactly these, in this order (plan order = category-sorted).
OFFLINE_SQL = [
    "OPTIMIZE TABLE `wp_commentmeta`",
    "OPTIMIZE TABLE `wp_options`",
    "OPTIMIZE TABLE `wp_postmeta`",
    "OPTIMIZE TABLE `wp_posts`",
    "OPTIMIZE TABLE `wp_termmeta`",
    "DELETE pm FROM wp_postmeta pm LEFT JOIN wp_posts p ON p.ID = pm.post_id"
    " WHERE p.ID IS NULL",
    "DELETE tm FROM wp_termmeta tm LEFT JOIN wp_terms t"
    " ON t.term_id = tm.term_id WHERE t.term_id IS NULL",
    "DELETE cm FROM wp_commentmeta cm LEFT JOIN wp_comments c"
    " ON c.comment_ID = cm.comment_id WHERE c.comment_ID IS NULL",
    "DELETE FROM wp_posts WHERE post_type = 'revision'"
    " OR post_status = 'auto-draft'",
    "DELETE t, s FROM wp_options t INNER JOIN wp_options s"
    " ON s.option_name = REPLACE( t.option_name, '_transient_',"
    " '_transient_timeout_' ) WHERE ( t.option_name LIKE '\\_transient\\_%'"
    " OR t.option_name LIKE '\\_site_transient\\_%' )"
    " AND t.option_name NOT LIKE '%\\_transient\\_timeout\\_%'"
    " AND s.option_value < UNIX_TIMESTAMP()",
]


def test_offline_dry_run_is_the_ftp_plan(tmp_path, monkeypatch, capsys):
    # The SAME plan the bridge produces for the same facts, built by the
    # same builder — plus the offline reads the plan was derived from.
    db = _offline_db()
    ctx = _patched(tmp_path, monkeypatch, db, apply=False)
    from wpt.actions.clean_db import run_offline

    assert run_offline(ctx) == 0
    out = capsys.readouterr().out
    assert "## Plan" in out
    for target in ("revisions", "expired_transients", "orphan_meta",
                   "optimize_tables"):
        assert target in out
    assert "5 revisions + auto-drafts" in out
    assert "7 expired transients" in out
    assert "postmeta+termmeta: 5 orphan rows" in out
    assert "1 tables, ~2.0 MB reclaimable" in out
    # read-only: no statement was executed
    assert db.executed == []
    assert db.closed is True


def test_offline_apply_runs_the_bridges_sql_in_plan_order(tmp_path, monkeypatch,
                                                         capsys, wpt_caplog):
    db = _offline_db()
    ctx = _patched(tmp_path, monkeypatch, db)
    from wpt.actions.clean_db import run_offline

    assert run_offline(ctx) == 0
    # THE point of the path: the named ops, as the bridge's own SQL, in the
    # same order the ftp apply would send them.
    assert db.executed == OFFLINE_SQL
    # the same results contract: every item done, details enriched with the
    # op's own count
    out = capsys.readouterr().out
    assert out.count("| yes |") == 4
    assert "1 tables, ~2.0 MB reclaimable, optimized 5 tables" in out
    assert "postmeta+termmeta: 5 orphan rows, removed 5 rows" in out
    assert "5 revisions + auto-drafts, removed 5 rows" in out
    assert "7 expired transients, removed 7 rows" in out
    # ... and the verify-after-change pass re-read the same facts
    infos = [r.getMessage() for r in _records(wpt_caplog, "wpt.actions.clean_db",
                                              logging.INFO)]
    assert any("is clean after the apply" in m for m in infos)
    # the honesty line: no snapshot exists in this mode
    assert any("no pre-action snapshot" in m for m in infos)
    assert db.closed is True


def test_offline_verification_refuses_an_unclean_database(tmp_path, monkeypatch,
                                                          capsys, wpt_caplog):
    # A driver whose DELETE silently does nothing: the counts are unchanged,
    # so the ops are NOT reported as done and the run fails.
    db = _offline_db()
    db.on_execute = None
    ctx = _patched(tmp_path, monkeypatch, db)
    from wpt.actions.clean_db import run_offline

    assert run_offline(ctx) == 1
    errors = [r.getMessage() for r in _records(wpt_caplog, "wpt.actions.clean_db",
                                               logging.ERROR)]
    assert any("still reports 5" in m and "revisions" in m for m in errors)
    assert any("were not applied" in m for m in errors)
    assert "removed 5 rows" in capsys.readouterr().out  # reported, not claimed


def test_offline_failed_op_is_rc1_and_never_verifies(tmp_path, monkeypatch,
                                                     capsys, wpt_caplog):
    db = _offline_db(failures={"DELETE tm": RuntimeError("db error: deadlock")})
    ctx = _patched(tmp_path, monkeypatch, db)
    from wpt.actions.clean_db import run_offline

    assert run_offline(ctx) == 1
    warnings = [r.getMessage() for r in _records(wpt_caplog, "wpt.actions.clean_db",
                                                 logging.WARNING)]
    assert any("orphan_meta" in m and "deadlock" in m for m in warnings)
    errors = [r.getMessage() for r in _records(wpt_caplog, "wpt.actions.clean_db",
                                               logging.ERROR)]
    assert any("not verifying" in m for m in errors)
    # a partially-cleaned database is never printed as a success
    assert capsys.readouterr().out == ""


def test_offline_unknown_op_is_refused(tmp_path, monkeypatch):
    from wpt.actions.clean_db import OfflineDb

    db = _offline_db()
    with pytest.raises(WptError, match="unknown db_clean op"):
        OfflineDb(db, "wp_").clean(["drop_everything"])


def test_offline_apply_needs_the_canonical_confirmation(tmp_path, monkeypatch):
    # --apply without --yes on a non-tty is refused by the SAME gate the
    # registry uses, and nothing is executed.
    db = _offline_db()
    ctx = _patched(tmp_path, monkeypatch, db, yes=False)
    from wpt.actions.clean_db import run_offline

    assert run_offline(ctx) == 1
    assert db.executed == []


def test_offline_clean_database_writes_nothing(tmp_path, monkeypatch, capsys):
    from tests.test_dbconn import wp_schema

    db = _offline_db()
    db.schema = wp_schema()
    db.counts = {key: 0 for key in db.counts}
    ctx = _patched(tmp_path, monkeypatch, db)
    from wpt.actions.clean_db import run_offline

    assert run_offline(ctx) == 0
    assert db.executed == []
    assert "## Plan" in capsys.readouterr().out


# ============================ the wrong-database gate ======================


def test_offline_wrong_database_is_refused_and_deletes_nothing(
        tmp_path, monkeypatch, capsys, wpt_caplog):
    """THE reproduced harm: ``--db-uri`` aimed at ANOTHER site's database.

    ``--wp-url https://example.org`` against a database whose own
    ``siteurl``/``home`` are ``https://other-site.example``.  Before the
    gate this run planned 3 items, the apply removed that site's
    revisions and termmeta rows, and the verification pass reported
    "revisions is clean after the apply" — a clean report over another
    site's data.  Now: refused by name, with NOTHING executed and nothing
    printed.
    """
    from wpt.actions.clean_db import run_offline

    db = _offline_db(identities={"siteurl": "https://other-site.example",
                                 "home": "https://other-site.example"})
    ctx = _patched(tmp_path, monkeypatch, db, wp_url="https://example.org")

    assert run_offline(ctx) == 1
    assert db.executed == []          # zero write calls, not a filtered plan
    assert db.closed is True
    assert capsys.readouterr().out == ""
    errors = [r.getMessage() for r in _records(wpt_caplog, "wpt.actions.clean_db",
                                               logging.ERROR)]
    assert len(errors) == 1
    message = errors[0]
    # the DATABASE is named, with its own identity, and the run's target
    assert "ANOTHER SITE's database" in message
    assert "https://other-site.example" in message
    assert "https://example.org" in message
    # the line says what an apply would have destroyed there
    assert "revisions" in message and "orphaned meta rows" in message
    # ... and the run is told to repoint, not to inspect the other site
    assert "point --db-uri at this site's database" in message


def test_offline_matching_database_proceeds(tmp_path, monkeypatch, capsys):
    """The happy path is untouched: the same site, the same plan, rc 0."""
    from wpt.actions.clean_db import run_offline

    db = _offline_db()
    ctx = _patched(tmp_path, monkeypatch, db, apply=False)

    assert run_offline(ctx) == 0
    assert db.executed == []          # a dry run stays read-only
    out = capsys.readouterr().out
    assert "## Plan" in out
    assert "5 revisions + auto-drafts" in out


def test_offline_matching_database_survives_the_insensitive_comparison(
        tmp_path, monkeypatch):
    """The comparison is dump_witness's rule, imported: scheme, port, a
    ``www.`` prefix and a trailing slash are NOT the site's identity, so
    the four real-world shapes of the SAME site all proceed."""
    from wpt.actions.clean_db import run_offline

    for siteurl, home, wp_url in (
        ("http://example.com", "http://example.com", "https://example.com"),
        ("https://example.com/", "https://example.com/", "https://example.com"),
        ("https://www.example.com", "https://www.example.com",
         "https://example.com"),
        ("https://example.com:8443", "https://example.com:8443",
         "https://example.com:8443"),
        # a subdirectory install: the PATH is part of the identity (R14)
        ("https://example.com/shop", "https://example.com/shop",
         "https://example.com/shop"),
    ):
        db = _offline_db(identities={"siteurl": siteurl, "home": home})
        ctx = _patched(tmp_path, monkeypatch, db, apply=False,
                       wp_url=wp_url)
        assert run_offline(ctx) == 0, (siteurl, wp_url)


def test_offline_stale_siteurl_with_a_current_home_proceeds(
        tmp_path, monkeypatch, wpt_caplog):
    """ONE of the two matching is enough — the case the witness's own rule
    was widened for: a site whose ``siteurl`` went stale in a migration
    while ``home`` stayed current is the same site."""
    from wpt.actions.clean_db import run_offline

    db = _offline_db(identities={"siteurl": "https://old.example",
                                 "home": "https://example.com"})
    ctx = _patched(tmp_path, monkeypatch, db, apply=False)

    assert run_offline(ctx) == 0
    assert "offline db source" in "\n".join(
        r.getMessage() for r in _records(wpt_caplog, "wpt.actions.clean_db",
                                         logging.INFO))


def test_offline_non_wordpress_database_is_refused(tmp_path, monkeypatch,
                                                   capsys, wpt_caplog):
    """A database that states NEITHER option is not this site's, and not
    another site's either: it is some other application's tables.  The
    refusal says so by name — an options table with the right columns is a
    SHAPE, never proof that WordPress wrote it."""
    from wpt.actions.clean_db import run_offline

    db = _offline_db(identities={})
    ctx = _patched(tmp_path, monkeypatch, db, wp_url="https://example.org")

    assert run_offline(ctx) == 1
    assert db.executed == []
    assert capsys.readouterr().out == ""
    errors = [r.getMessage() for r in _records(wpt_caplog, "wpt.actions.clean_db",
                                               logging.ERROR)]
    assert len(errors) == 1
    assert "not a WordPress database" in errors[0]
    assert "neither siteurl nor home" in errors[0]


def test_offline_half_stated_identity_warns_once_and_proceeds(
        tmp_path, monkeypatch, wpt_caplog):
    """Exactly one of the two options present: PROCEED with ONE warning.
    Half the evidence is not a mismatch, and a refusal here would refuse
    a real site over a missing row."""
    from wpt.actions.clean_db import run_offline

    for identities, absent in (
        ({"siteurl": "https://example.com"}, "home"),
        ({"home": "https://example.com"}, "siteurl"),
    ):
        db = _offline_db(identities=identities)
        ctx = _patched(tmp_path, monkeypatch, db, apply=False)
        wpt_caplog.clear()

        assert run_offline(ctx) == 0
        warnings = [r.getMessage()
                    for r in _records(wpt_caplog, "wpt.actions.clean_db",
                                      logging.WARNING)]
        assert len(warnings) == 1, identities
        assert absent in warnings[0]
        assert "half its evidence" in warnings[0]
        assert "https://example.com" in warnings[0]


def test_offline_no_wp_url_warns_that_the_check_could_not_run(
        tmp_path, monkeypatch, wpt_caplog):
    """No ``--wp-url`` = no second identity, so the run says so once and
    proceeds: naming a database and no site is a legitimate use of this
    path, and the warning is the honest record that nothing was checked."""
    from wpt.actions.clean_db import run_offline

    db = _offline_db(identities={"siteurl": "https://wherever.example",
                                 "home": "https://wherever.example"})
    ctx = _patched(tmp_path, monkeypatch, db, apply=False, wp_url=None)

    assert run_offline(ctx) == 0
    warnings = [r.getMessage()
                for r in _records(wpt_caplog, "wpt.actions.clean_db",
                                  logging.WARNING)]
    assert len(warnings) == 1
    assert "no --wp-url to compare this database against" in warnings[0]
    assert "https://wherever.example" in warnings[0]


def test_offline_gate_reads_a_serialized_identity_too(tmp_path, monkeypatch,
                                                       capsys):
    """A real store keeps a scalar option PLAIN, but a value that IS
    serialized is read through the analyzer's own option-value policy
    rather than compared as ``s:19:"https://…"`` (which would match
    nothing and silently degrade every run to the half-evidence warning).
    """
    from wpt.actions.clean_db import run_offline

    db = _offline_db(identities={
        "siteurl": 's:19:"https://example.com";',
        "home": 's:19:"https://example.com";',
    })
    ctx = _patched(tmp_path, monkeypatch, db, apply=False)

    assert run_offline(ctx) == 0
    assert "## Plan" in capsys.readouterr().out


def test_offline_gate_never_puts_the_password_in_the_refusal(
        tmp_path, monkeypatch, wpt_caplog):
    """The refusal is a report-bound line: it names the database's OWN
    identity and the requested URL, and it must not carry the DSN's
    password (the secrets rule applies to a message that reaches a log and
    a report like any other)."""
    from wpt.actions.clean_db import run_offline

    db = _offline_db(identities={"siteurl": "https://other-site.example",
                                 "home": "https://other-site.example"})
    ctx = _patched(tmp_path, monkeypatch, db, wp_url="https://example.org")

    assert run_offline(ctx) == 1
    logged = "\n".join(r.getMessage() for r in wpt_caplog.records)
    assert "inline-secret" not in logged
    assert "other-site.example" in logged


def test_offline_prefix_is_discovered_never_guessed(tmp_path, monkeypatch):
    """The prefix comes from the database's own options table, and an
    AMBIGUOUS identity refuses the run instead of picking one.

    The old rule warned and took the first candidate by name — on a site
    running All in One SEO 4.x, which really creates its own
    ``aioseo_options`` carrying the same column pair, that name sorts
    first, so every statement in the plan would have been aimed at the
    PLUGIN's table and the report would have read as a clean run.  The
    candidate rule is now asked of ``wpt.media_refs`` (the owner the
    analyzer and the media measurement share); only the POLICY is
    clean-db's own, and it refuses.
    """
    from wpt.actions.clean_db import discover_prefix

    # a prefixed install: the table prefix comes from the options table
    db = _offline_db(options_tables=("shop_options",))
    assert discover_prefix(db) == "shop_"
    # several candidates: REFUSED, named, never guessed
    db = _offline_db(options_tables=("shop_options", "wp_options"))
    with pytest.raises(WptError, match="multiple tables in this database "
                                       "prove the options role") as excinfo:
        discover_prefix(db)
    assert "shop_options" in str(excinfo.value)
    assert "wp_options" in str(excinfo.value)
    # the real AIOSEO 4.x shape is refused the same way (it sorts FIRST,
    # which is what the old rule silently picked)
    db = _offline_db(options_tables=("aioseo_options", "wp_options"))
    with pytest.raises(WptError, match="aioseo_options, wp_options"):
        discover_prefix(db)
    # no WordPress table at all: refused, never defaulted to wp_
    db = _offline_db(options_tables=())
    with pytest.raises(WptError, match="no WordPress options table"):
        discover_prefix(db)


def test_offline_re_dump_round_trips(tmp_path, monkeypatch):
    """--re-dump writes the operator's next artifact, readable by the analyzer."""
    from wpt.localmode.analyzer import analyze
    from wpt.settings import load

    db = _offline_db()
    out = tmp_path / "wp_stage-clean.sql"
    ctx = _patched(tmp_path, monkeypatch, db, re_dump=out)
    from wpt.actions.clean_db import run_offline

    assert run_offline(ctx) == 0
    assert out.exists()
    with out.open("rb") as handle:
        model = analyze(handle, load().db)
    assert model.siteurl == "https://example.test"
    assert set(model.tables) >= {"wp_options", "wp_posts"}
    # the dump is of the tables the plan touched, the whole database
    text = out.read_text(encoding="utf-8")
    assert "INSERT INTO `wp_posts`" in text
    # never on a run that did not complete
    db2 = _offline_db(on_execute=None)
    out2 = tmp_path / "never.sql"
    ctx2 = _patched(tmp_path, monkeypatch, db2, re_dump=out2)
    assert run_offline(ctx2) == 1
    assert not out2.exists()


def test_R22_a_failed_re_dump_writes_a_failure_pair_naming_the_cause(
        tmp_path, monkeypatch, capsys):
    """R22-P2: an existing ``--re-dump`` path made ``dump_database`` raise,
    but ``_verdict`` still emitted the SUCCESS plan pair (all four items
    ``yes``, no ``run`` object) and rc 1 only via a log line.  The plan's
    applied state stays visible, while the pair carries the shared failed
    run block naming the re-dump."""
    db = _offline_db()
    blocked = tmp_path / "already-there.sql"
    blocked.write_text("-- operator artifact\n", encoding="utf-8")
    report = tmp_path / "clean-db.md"
    ctx = _patched(tmp_path, monkeypatch, db, re_dump=blocked,
                   report_path=report)
    from wpt.actions.clean_db import run_offline

    assert run_offline(ctx) == 1
    assert blocked.read_text(encoding="utf-8") == "-- operator artifact\n"
    twin = json.loads(report.with_suffix(".json").read_text(encoding="utf-8"))
    assert twin["run"]["status"] == "failed"
    assert "re-dump" in twin["run"]["reason"]
    assert "already-there.sql" in twin["run"]["reason"]
    # the database WAS cleaned: the applied plan is still in the report,
    # never silently rolled back or replaced by a bare failure report
    done = [item for item in twin["plan"]["items"] if item["done"]]
    assert done and all(item["done"] for item in twin["plan"]["items"]
                        if item["requires_apply"])
    markdown = report.read_text(encoding="utf-8")
    assert "did not complete" in markdown
    assert "re-dump" in markdown


def test_R23_re_dump_deadline_keeps_the_applied_plan_in_the_pair(
        tmp_path, monkeypatch):
    """R23-P2: ``_verdict`` caught only (WptError, OSError), so a
    DeadlineExceeded from the re-dump escaped to run_offline's bare
    ``_fail_offline`` stub — the report lost every applied plan row even
    though the database really was cleaned.  A run-control re-dump failure
    is now the same not-complete pair with the plan preserved."""
    from wpt.actions import clean_db as clean_db_mod
    from wpt.actions.clean_db import run_offline
    from wpt.types import DeadlineExceeded

    db = _offline_db()
    out = tmp_path / "deadline.sql"
    report = tmp_path / "clean-db-deadline.md"
    ctx = _patched(tmp_path, monkeypatch, db, re_dump=out,
                   report_path=report)

    def _expire(*_args, **_kwargs):
        raise DeadlineExceeded("run deadline during the re-dump")

    monkeypatch.setattr(clean_db_mod, "dump_database", _expire)
    assert run_offline(ctx) == 1
    assert not out.exists()
    twin = json.loads(report.with_suffix(".json").read_text(encoding="utf-8"))
    assert twin["run"]["status"] == "failed"
    assert "re-dump" in twin["run"]["reason"]
    assert "deadline" in twin["run"]["reason"]
    done = [item for item in twin["plan"]["items"] if item["done"]]
    assert done and all(item["done"] for item in twin["plan"]["items"]
                        if item["requires_apply"])


def test_offline_never_prints_or_logs_the_password(tmp_path, monkeypatch, capsys,
                                                   wpt_caplog):
    from wpt.actions.clean_db import run_offline

    db = _offline_db()
    ctx = _patched(tmp_path, monkeypatch, db)
    assert run_offline(ctx) == 0
    printed = capsys.readouterr().out
    logged = "\n".join(r.getMessage() for r in wpt_caplog.records)
    for stream in (printed, logged):
        assert "inline-secret" not in stream
    # ... while the run still says WHICH database it touched (redacted)
    assert "mysql://wpuser:***@db.internal:3307/wp_stage" in logged
    # the artifact is credential-free too
    assert "inline-secret" not in (tmp_path / "x").with_name("x").as_posix()


# ------------------------------------------------ triple-check round 8 (P1)


def test_P1_offline_dry_run_honours_report_with_json_twin(tmp_path, monkeypatch,
                                                          capsys):
    """P1-05: ``--db-uri`` dry run accepted --report and wrote NOTHING."""
    db = _offline_db()
    report = tmp_path / "clean-db.md"
    ctx = _patched(tmp_path, monkeypatch, db, apply=False,
                   report_path=report)
    from wpt.actions.clean_db import run_offline

    assert run_offline(ctx) == 0
    markdown = report.read_text(encoding="utf-8")
    twin = json.loads(report.with_suffix(".json").read_text(encoding="utf-8"))
    assert "## Plan" in markdown
    assert twin["plan"]["items"]
    assert db.executed == []


def test_C8_an_expired_budget_refuses_before_the_offline_connect(
        tmp_path, monkeypatch):
    """C8: ``clean-db --db-uri`` built no deadline, so a slow audit ran past
    --deadline and still answered rc 0.  The budget must be checked before
    the first database call and end rc 1 with the failure pair."""
    from wpt.deadline import Deadline
    from wpt.actions.clean_db import run_offline

    report = tmp_path / "clean-db.md"
    mod, ctx = _offline_ctx(tmp_path, _offline_db(), report_path=report)
    calls = []
    monkeypatch.setattr(mod, "connect",
                        lambda *a, **k: calls.append(k) or _offline_db())
    deadline = Deadline(0.05)
    deadline._started -= 1.0                     # deterministically spent
    ctx._deadline = deadline

    assert run_offline(ctx) == 1
    assert calls == []
    markdown = report.read_text(encoding="utf-8")
    twin = json.loads(report.with_suffix(".json").read_text(encoding="utf-8"))
    assert "## This run did not complete" in markdown
    assert "deadline" in twin["run"]["reason"].lower()


def test_P1_offline_apply_honours_report_with_json_twin(tmp_path, monkeypatch,
                                                        capsys):
    db = _offline_db()
    report = tmp_path / "clean-db.md"
    ctx = _patched(tmp_path, monkeypatch, db, report_path=report)
    from wpt.actions.clean_db import run_offline

    assert run_offline(ctx) == 0
    assert report.exists()
    twin = json.loads(report.with_suffix(".json").read_text(encoding="utf-8"))
    assert twin["plan"]["items"]
    assert db.executed


def test_P1_offline_connect_failure_writes_the_failure_pair(
        tmp_path, monkeypatch):
    """P1-05: a connect failure exited 1 and left neither face; a stale
    report could survive the failed run."""
    report = tmp_path / "clean-db.md"
    report.write_text("STALE", encoding="utf-8")
    report.with_suffix(".json").write_text("{}", encoding="utf-8")
    ctx = _patched(tmp_path, monkeypatch, _offline_db(), report_path=report)
    from wpt.actions import clean_db as clean_db_mod
    from wpt.actions.clean_db import run_offline

    def _refuse(uri, password=None, deadline=None, settings=None):
        raise WptError("cannot connect to the database")

    monkeypatch.setattr(clean_db_mod, "connect", _refuse)
    assert run_offline(ctx) == 1
    markdown = report.read_text(encoding="utf-8")
    twin = json.loads(report.with_suffix(".json").read_text(encoding="utf-8"))
    assert "STALE" not in markdown
    assert "## This run did not complete" in markdown
    assert twin["run"]["status"] == "failed"
    assert "cannot connect" in twin["run"]["reason"]
