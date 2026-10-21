"""Tests for the cull-media action (wpt.actions.cull_media).

A REAL Bridge over FakeSession/FakeSource (scripted media_map / media_delete
/ db_audit / db_dump answers — tests/actions/test_trim_media.py
conventions) with the LIVE WALK monkeypatched in the action module's
namespace (``wpt.actions.cull_media.walk_site``).  Deterministic, no
network, no sleeps.  The registry end-to-end tests monkeypatch
``wpt.actions.registry._stack`` (the pinned seam).

Test -> behavior map (the live case: many -WxH derivatives over hundreds
of stems, a large derivative set, of which most are named in srcset and must
stay — the honest bounded cull is the DEAD stem family):
  test_registration .......................... the INSTANCE, applies
        ("ftp",) — the plan's safety proof is the site's full reference
        set, which offline does not exist
  test_dry_run_plans_exactly_the_dead_family  one dead family (original +
        two derivatives) and one live family: the plan names EXACTLY the
        dead family's derivatives, webroot-relative targets, uploads
        detail, bytes, sorted, backup_tables from db_audit, ONE info
        summary with the measured total; the live family's files and the
        dead family's ORIGINAL are never planned (trim-media's business)
  test_a_live_family_plans_nothing ........... a reference to any member
        keeps the whole family (the symmetric L5 rule)
  test_database_references_keep_a_family ..... a family no page renders but
        the DATABASE references (the database-heavy measurement) is kept
  test_walk_refused_when_partial_or_empty .... an incomplete reference set
        REFUSES the plan (rc 1) instead of calling every derivative dead
  test_unanswerable_refs_map_refuses ........ a media_map answer without a
        usable refs object is unmeasurable and refuses the plan
  test_attached_candidate_is_never_planned ... a candidate media_map maps
        to a positive attachment id is kept
  test_min_oversize_px_keeps_small_and_unmeasurable_derivatives  the floor
        keeps a 300px derivative and a -scaled name (no declared size)
  test_max_plan_files_refuses_an_unbounded_cull  a cull above the bound
        refuses, naming both numbers, with nothing planned
  test_apply_reverifies_the_reference_set .... the verification walk finds
        one planned FAMILY referenced again: it is reclassified as skipped
        (requires_apply False, the reason in its detail) and NEVER sent to
        the bridge, while the still-dead family is culled
  test_apply_deletes_and_marks_done .......... one media_map (ids) plus one
        media_delete (ids+files, uploads-relative), all items done, the
        server counts logged
  test_apply_refuses_a_failed_unlink ......... a reported unlink_failure
        fails the apply (rc 1) instead of claiming a deletion
  test_registry_dry_run ...................... run_action apply=False: plan
        printed, rc 0, no media_delete, no purge
  test_registry_ftp_apply_end_to_end ......... apply --yes: the snapshot
        manifest lists the planned files AND the DB tables, media_delete
        receives the planned paths, rc 0
  test_registry_local_mode_refused ........... local mode: rc 1 with the
        ftp-only applicability error and no stack built
  mode parity (the regression sweep's §2 discriminator):
  test_database_leg_is_the_set_the_dump_measures ... cull's database leg is
        the SAME set the offline dump path measures for the same rows, and
        never a second database half: a cull is ftp-only by registration
        (so trim_media's apply is where a --sql disagreement is refused),
        but the leg it builds its keep-set from must be the one owner
  test_the_live_family_survives_a_size_map_loss ... a size map carrying a
        null inside it (the shape that lost the family offline) still keeps
        the family a cull would otherwise call dead
  THE CROSS-MODE GATE (shared with trim_media, one owner):
  test_a_cull_without_a_dump_is_refused_before_the_snapshot ... --sql is
        optional in ftp mode, so a destructive cull with no witness is
        refused in the PLAN phase, before the pre-action snapshot exists
  test_a_cull_through_a_stale_dump_is_refused_and_nothing_is_deleted ...
        a dump cut inside the postmeta rows with `-- Dump completed on`
        APPENDED passes the trailer, the measurement and the identity, and
        is refused for being BEHIND the live row count, with both numbers
  test_a_cull_whose_dump_disagrees_with_the_live_map_is_refused ... the
        per-file dispute: the two measurements of one database disagree
        about a planned file, so nothing is deleted
  test_a_cull_dry_run_says_the_apply_will_refuse ... the dry run cannot
        refuse, so it carries the ADVICE item the apply will honour
  test_both_media_actions_refuse_with_the_OWNER_s_wording ... the two
        actions' refusals are the SAME strings (one function), and both
        hold the same gate type
"""

import json
import logging

import pytest

from tests.dump_fixtures import LIVE_ROWS, make_dump
from tests.fakes import FakeResponse, FakeSession, FakeSource
from wpt.actions import cull_media as cull_mod
from wpt.actions import registry as registry_mod
from wpt.actions.cull_media import CullMediaAction
from wpt.actions.registry import get_action, run_action
from wpt.cli import Ctx
from wpt.settings import BridgeSettings, load
from wpt.types import BridgeError, SourceError
from wpt.walk import WalkResult
from wpt.wpbridge.client import Bridge

DEFAULTS = load()
WEBROOT = "domains/example.com/public_html"
SITE = "https://example.com"

#: A dead family (nothing renders it, nothing attaches it: the left-over
#: export derivatives) and a live family (a page renders the original).
TREE = {
    "wp-content/uploads/2023/10/dead.jpg": b"d" * 100,
    "wp-content/uploads/2023/10/dead-1600x1067.jpg": b"d" * 160,
    "wp-content/uploads/2023/10/dead-scaled.jpg": b"d" * 90,
    "wp-content/uploads/2023/10/live.jpg": b"l" * 100,
    "wp-content/uploads/2023/10/live-300x200.jpg": b"l" * 30,
    "wp-content/themes/x/style.css": b"a{color:red}",
}

#: The live walk measured ONE page; it references the live family's
#: original only (srcset and generated CSS ride the same live_refs set).
LIVE_REFS = {"2023/10/live.jpg"}

#: The dead family's DERIVATIVES — exactly what the plan must name.
EXPECTED = [
    ("media.oversized", "wp-content/uploads/2023/10/dead-1600x1067.jpg", 160),
    ("media.oversized", "wp-content/uploads/2023/10/dead-scaled.jpg", 90),
]


@pytest.fixture
def wpt_caplog(caplog):
    parent = logging.getLogger("wpt")
    parent.addHandler(caplog.handler)
    with caplog.at_level(logging.DEBUG, logger="wpt"):
        yield caplog
    parent.removeHandler(caplog.handler)


# ------------------------------------------------------------------ helpers


def _ctx(tmp_path, *, settings=DEFAULTS, **overrides):
    fields = dict(
        source="ftp://example.com",
        settings=settings,
        command="cull-media",
        apply=False,
        yes=False,
        backup_dir=tmp_path / "backup",
        wp_url=SITE,
        webroot=WEBROOT,
    )
    fields.update(overrides)
    return Ctx(**fields)


#: The live row counts the db_audit fixture reports — the half of the
#: cross-mode witness' currency comparison that lives on the bridge side
#: (the other half is the dump's own parsed counts, and the shared dump
#: fixture writes exactly these numbers so an honest export is not refused).
def _tables():
    return [
        {"name": name, "rows": LIVE_ROWS[name], "size_mb": 0.5,
         "data_free_kb": 0.0}
        for name in sorted(LIVE_ROWS)
    ]


def _dump(tmp_path, refs=(), name="site.sql", **kwargs):
    """A usable --sql dump of THIS site (tests/dump_fixtures owns the
    shape): the witness is mandatory for a destructive cull, so every apply
    test needs one, and the agreeing case must apply cleanly."""
    return make_dump(tmp_path, refs=refs, name=name, **kwargs)


def audit_payload():
    return {"posts": [], "revisions": 0, "expired_transients": 0,
            "orphan_meta": {}, "tables": _tables(), "autoload_bytes": 1,
            "attachments": 2, "nav_menu_items": 0}


def ok(**payload):
    return FakeResponse(200, json.dumps({"ok": True, **payload}))


def media_map_ok(refs=None, db_refs=()):
    return ok(refs=refs or {}, db_refs=list(db_refs))


def media_delete_ok(**counts):
    return ok(deleted_posts=counts.get("deleted_posts", 0),
              deleted_meta=counts.get("deleted_meta", 0),
              deleted_termrels=counts.get("deleted_termrels", 0),
              deleted_files=counts.get("deleted_files", 0),
              skipped_missing=counts.get("skipped_missing", 0),
              unlink_failures=counts.get("unlink_failures", []))


def purge_ok():
    return FakeResponse(200, json.dumps({"ok": True, "purged": True}))


def table_lines(table, rows=(), create="CREATE TABLE `x` (id bigint)"):
    lines = [json.dumps({"table": table, "create": create})]
    for row in rows:
        lines.append(json.dumps({"table": table, "row": row}))
    lines.append(json.dumps({"table": table, "done": len(rows)}))
    return lines


def _selfdestruct(src):
    def handler(method, url, kwargs):
        src.files.pop(f"{WEBROOT}/{url.removeprefix(SITE + '/').partition('?')[0]}",
                      None)
        return FakeResponse(200, "gone")

    return handler


def _delete_handler(src, response):
    """Script item: media_delete really unlinks what it reports removed."""
    failures = set(json.loads(response.text).get("unlink_failures", []))

    def handler(method, url, kwargs):
        for rel in (kwargs.get("json") or {}).get("params", {}).get("files", []):
            if rel not in failures:
                src.files.pop(f"wp-content/uploads/{rel}", None)
        return response

    return handler


def make_stack(script, files=None):
    src = FakeSource()
    src.files = dict(TREE if files is None else files)
    wrapped = [_delete_handler(src, item[1])
               if isinstance(item, tuple) and item[0] == "delete" else item
               for item in script]
    session = FakeSession(wrapped + [_selfdestruct(src)])
    bridge = Bridge(src, session, WEBROOT, BridgeSettings(), SITE)
    return src, session, bridge


def patch_walk(monkeypatch, live_refs=LIVE_REFS, *, partial=False, refs=None):
    """Point the action's walk seam at a canned WalkResult (no HTTP).

    ``refs`` scripts a DIFFERENT answer per call (the verification pass),
    which is how the "referenced again" case is reproduced.
    """
    calls = []
    answers = list(refs) if refs is not None else None

    def fake_walk_site(session, site, settings, timeout_s=30, deadline=None):
        calls.append((session, site, settings, timeout_s))
        live = (answers or [set(live_refs)])[min(len(calls) - 1,
                                                 len(answers or [1]) - 1)]
        return WalkResult(live_refs=set(live), pages=[], forms=[], fetched=1,
                          partial=partial)

    monkeypatch.setattr(cull_mod, "walk_site", fake_walk_site)
    return calls


def posted(session):
    return [(kwargs["json"]["action"], kwargs["json"].get("params", {}))
            for _url, kwargs in session.posts]


def _plan(tmp_path, monkeypatch, script, *, ctx=None, files=None, walk=None,
          settings=DEFAULTS, sql=None):
    src, session, bridge = make_stack(script, files=files)
    patch_walk(monkeypatch, **({"live_refs": LIVE_REFS} if walk is None
                               else walk))
    # the cross-mode witness is MANDATORY for an apply, so the shared
    # fixture hands every run an honest dump unless a test wants another
    # one (``sql=False`` = none passed at all, the refusal case)
    if sql is not False and sql is None:
        sql = _dump(tmp_path)
    ctx = ctx or _ctx(tmp_path, settings=settings, sql=sql or None)
    plan = CullMediaAction().plan(ctx, (src, session, bridge))
    return plan, session, src


# The three answers a plan needs, in order: media_map in DB mode (the
# database leg of the reference set), media_map in refs mode (the
# attachment rows of the candidates), db_audit (the snapshot's table
# scope).
def _plan_script(*, db_refs=(), refs=None, audit=None):
    return [media_map_ok(db_refs=db_refs), media_map_ok(refs=refs),
            ok(**(audit_payload() if audit is None else audit))]


def _apply_script(*, db_refs=(), refs=None, delete=None):
    """A plan's three answers PLUS the apply's own: the verification walk's
    database leg, the LIVE SCHEMA the cross-mode witness measures the dump
    against (a fresh read — the apply re-measures what it relies on), the
    candidates' attachment rows again, and media_delete."""
    return _plan_script(db_refs=db_refs, refs=refs) + [
        media_map_ok(db_refs=db_refs), ok(**audit_payload()),
        media_map_ok(refs=refs),
        ("delete", delete or media_delete_ok(deleted_files=2)),
    ]


# ------------------------------------------------------------- registration


def test_registration():
    record = get_action("cull-media")
    assert record is not None
    assert record.applies == ("ftp",)
    assert isinstance(record.action, CullMediaAction)  # the instance


# --------------------------------------------------------------------- plan


def test_dry_run_plans_exactly_the_dead_family(tmp_path, monkeypatch,
                                               wpt_caplog):
    plan, session, _src_ = _plan(tmp_path, monkeypatch, _plan_script())
    assert [(i.category, i.target, i.bytes_est) for i in plan.items] \
        == EXPECTED
    assert all(i.requires_apply and not i.done for i in plan.items)
    # uploads-relative detail + the reason
    assert "2023/10/dead-1600x1067.jpg" in plan.items[0].detail
    assert "dead stem family" in plan.items[0].detail
    # the DEAD family's original and the whole live family stay
    assert "wp-content/uploads/2023/10/dead.jpg" not in [i.target
                                                         for i in plan.items]
    assert not [i for i in plan.items if "/live" in i.target]
    # the DB side of the deletion is snapshotted
    assert plan.backup_tables == ["wp_postmeta", "wp_posts",
                                  "wp_term_relationships"]
    # exactly three bridge calls: the db leg of the reference set, the
    # candidates' attachment rows, the snapshot's table scope
    assert [a for a, _ in posted(session)] == ["media_map", "media_map",
                                                "db_audit"]
    # the keep-gate is measured with the RUN's media family, so a widened
    # profile cannot make a live family look dead to a narrower gate [L39]
    first_payload = posted(session)[0][1]
    assert first_payload["mode"] == "db"
    assert set(first_payload["extensions"]) == set(DEFAULTS.media.extensions)
    infos = [r.getMessage() for r in
             _records(wpt_caplog, "wpt.actions.cull_media", logging.INFO)]
    assert any("2 derivative(s) of 1 dead stem family" in m for m in infos)


def test_a_live_family_plans_nothing(tmp_path, monkeypatch):
    """A reference to a VARIANT keeps the original and its siblings (the
    symmetric L5 rule), so the whole live family is out of scope."""
    plan, _, _ = _plan(tmp_path, monkeypatch, _plan_script(), files={
        "wp-content/uploads/2023/10/live.jpg": b"l" * 100,
        "wp-content/uploads/2023/10/live-300x200.jpg": b"l" * 30,
    }, walk={"live_refs": {"2023/10/live-300x200.jpg"}})
    assert plan.items == []
    assert plan.backup_tables == []


def test_database_references_keep_a_family(tmp_path, monkeypatch):
    """The live measurement: a page renders only a FRACTION of the media;
    the database references the rest."""
    plan, _, _ = _plan(tmp_path, monkeypatch,
                       _plan_script(db_refs=["2023/10/dead.jpg"]))
    assert plan.items == []


def test_walk_refused_when_partial_or_empty(tmp_path, monkeypatch):
    for walk in ({"live_refs": LIVE_REFS, "partial": True},
                 {"live_refs": set()}):
        with pytest.raises(SourceError, match="complete reference set"):
            _plan(tmp_path, monkeypatch, _plan_script(), walk=walk)


def test_unanswerable_refs_map_refuses(tmp_path, monkeypatch):
    with pytest.raises(SourceError, match="refs map"):
        _plan(tmp_path, monkeypatch,
              [media_map_ok(db_refs=[]), ok(db_refs=[])])


def test_attached_candidate_is_never_planned(tmp_path, monkeypatch, wpt_caplog):
    plan, _, _ = _plan(tmp_path, monkeypatch, _plan_script(refs={
        "2023/10/dead-1600x1067.jpg": {"id": 42, "file": "2023/10/dead.jpg"},
    }))
    assert [i.target for i in plan.items] == [
        "wp-content/uploads/2023/10/dead-scaled.jpg",
    ]
    infos = [r.getMessage() for r in
             _records(wpt_caplog, "wpt.actions.cull_media", logging.INFO)]
    assert any("attached media rows" in m for m in infos)


def test_min_oversize_px_keeps_small_and_unmeasurable_derivatives(
        tmp_path, monkeypatch):
    settings = load(overrides={"cull_media.min_oversize_px": 1200})
    plan, _, _ = _plan(tmp_path, monkeypatch, _plan_script(),
                       settings=settings)
    # -scaled carries no declared size -> kept under a floor
    assert [i.target for i in plan.items] == [
        "wp-content/uploads/2023/10/dead-1600x1067.jpg",
    ]


def test_max_plan_files_refuses_an_unbounded_cull(tmp_path, monkeypatch):
    settings = load(overrides={"cull_media.max_plan_files": 1})
    with pytest.raises(SourceError, match="max_plan_files"):
        _plan(tmp_path, monkeypatch, _plan_script(), settings=settings)


def test_plan_walk_wiring(tmp_path, monkeypatch):
    src, session, bridge = make_stack(_plan_script())
    calls = patch_walk(monkeypatch, LIVE_REFS)
    CullMediaAction().plan(_ctx(tmp_path), (src, session, bridge))
    assert calls == [(session, SITE, DEFAULTS.walk, DEFAULTS.http.timeout_s)]


# -------------------------------------------------------------------- apply


def test_apply_deletes_and_marks_done(tmp_path, monkeypatch):
    """One media_map (ids) plus one media_delete (ids + uploads-relative
    files), every item done, and the server's counts logged."""
    src, session, bridge = make_stack(_apply_script())
    patch_walk(monkeypatch, LIVE_REFS)
    ctx = _ctx(tmp_path, sql=_dump(tmp_path))
    plan = CullMediaAction().plan(ctx, (src, session, bridge))
    CullMediaAction().apply(ctx, (src, session, bridge), plan)
    assert all(i.done for i in plan.items)
    params = [p for a, p in posted(session) if a == "media_delete"]
    assert params == [{
        "ids": [],
        "files": ["2023/10/dead-1600x1067.jpg", "2023/10/dead-scaled.jpg"],
    }]
    assert "wp-content/uploads/2023/10/dead-1600x1067.jpg" not in src.files


def test_apply_reverifies_the_reference_set(tmp_path, monkeypatch,
                                            wpt_caplog):
    """SPEC "verify after every change": the walk is re-measured, and a
    family that is referenced AGAIN is skipped whole — never sent to the
    bridge — while the still-dead family is culled."""
    files = dict(TREE)
    files["wp-content/uploads/2023/10/other.jpg"] = b"o" * 40
    files["wp-content/uploads/2023/10/other-800x600.jpg"] = b"o" * 80
    src, session, bridge = make_stack(
        _apply_script(delete=media_delete_ok(deleted_files=1)), files=files)
    patch_walk(monkeypatch, refs=[LIVE_REFS,
                                  LIVE_REFS | {"2023/10/dead-scaled.jpg"}])
    ctx = _ctx(tmp_path, sql=_dump(tmp_path))
    plan = CullMediaAction().plan(ctx, (src, session, bridge))
    assert len(plan.items) == 3
    CullMediaAction().apply(ctx, (src, session, bridge), plan)
    skipped = [i for i in plan.items if not i.requires_apply]
    assert sorted(i.target.rsplit("/", 1)[-1] for i in skipped) == [
        "dead-1600x1067.jpg", "dead-scaled.jpg",
    ]
    assert all("SKIPPED" in i.detail and not i.done for i in skipped)
    # only the still-dead family's derivative reached the bridge
    params = [p for a, p in posted(session) if a == "media_delete"]
    assert params == [{"ids": [], "files": ["2023/10/other-800x600.jpg"]}]
    assert any("referenced again" in r.getMessage() for r in
               _records(wpt_caplog, "wpt.actions.cull_media",
                        logging.WARNING))


def test_apply_refuses_a_failed_unlink(tmp_path, monkeypatch):
    src, session, bridge = make_stack(_apply_script(
        delete=media_delete_ok(
            unlink_failures=["2023/10/dead-1600x1067.jpg"])))
    patch_walk(monkeypatch, LIVE_REFS)
    ctx = _ctx(tmp_path, sql=_dump(tmp_path))
    plan = CullMediaAction().plan(ctx, (src, session, bridge))
    with pytest.raises(SourceError, match="could not remove"):
        CullMediaAction().apply(ctx, (src, session, bridge), plan)
    # the file the server reported is NOT done; the one it did remove is
    done = {i.target.rsplit("/", 1)[-1] for i in plan.items if i.done}
    assert done == {"dead-scaled.jpg"}


def test_apply_empty_plan_never_asks_the_bridge(tmp_path, monkeypatch):
    """Nothing dead -> the plan stops after the two reference-set legs and
    the apply issues no call at all."""
    live_only = {"wp-content/uploads/2023/10/live.jpg": b"l" * 10}
    src, session, bridge = make_stack([media_map_ok(), media_map_ok()],
                                      files=live_only)
    patch_walk(monkeypatch, LIVE_REFS)
    ctx = _ctx(tmp_path)
    plan = CullMediaAction().plan(ctx, (src, session, bridge))
    assert plan.items == []
    assert [a for a, _ in posted(session)] == ["media_map"]
    before = len(session.posts)
    CullMediaAction().apply(ctx, (src, session, bridge), plan)
    assert len(session.posts) == before


def test_plan_refuses_an_unbacked_mutation(tmp_path, monkeypatch):
    thin = audit_payload()
    thin["tables"] = [{"name": "wp_options", "rows": 1, "size_mb": 0.1,
                       "data_free_kb": 0.0}]
    with pytest.raises(SourceError, match="refusing an unbacked mutation"):
        _plan(tmp_path, monkeypatch, [media_map_ok(), media_map_ok(),
                                      ok(**thin)])


# ------------------------------------------------------------ registry flow


def test_registry_dry_run(tmp_path, monkeypatch, capsys):
    _src_, session, bridge = make_stack(_plan_script())
    monkeypatch.setattr(registry_mod, "_stack",
                        lambda ctx: (_src_, session, bridge))
    patch_walk(monkeypatch, LIVE_REFS)
    ctx = _ctx(tmp_path, apply=False, yes=True)
    assert run_action(ctx, "cull-media") == 0
    out = capsys.readouterr().out
    assert "media.oversized" in out
    assert "dead-1600x1067.jpg" in out
    # read-only: the two reference-set legs + db_audit, never media_delete
    assert [a for a, _ in posted(session)] == ["media_map", "media_map",
                                                "db_audit"]


def test_registry_ftp_apply_end_to_end(tmp_path, monkeypatch, capsys):
    # plan (3 calls) -> the registry's DB snapshot (one db_dump per table)
    # -> apply (2 reference-set calls + media_delete) -> purge_cache
    dump = (table_lines("wp_postmeta") + table_lines("wp_posts")
            + table_lines("wp_term_relationships"))
    script = _plan_script() + [
        FakeResponse(200, lines=dump),          # the pre-action snapshot
        media_map_ok(),                         # the apply re-measures
        ok(**audit_payload()),                  # ... and the live schema
        media_map_ok(),                         # the candidates' ids
        ("delete", media_delete_ok(deleted_files=2)),
        purge_ok(),
    ]
    src, session, bridge = make_stack(script)
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, session,
                                                             bridge))
    patch_walk(monkeypatch, LIVE_REFS)
    ctx = _ctx(tmp_path, apply=True, yes=True, sql=_dump(tmp_path))
    assert run_action(ctx, "cull-media") == 0
    out = capsys.readouterr().out
    assert "dead-scaled.jpg" in out
    # the pre-action snapshot captured the planned files AND the DB tables
    manifest = json.loads(
        next((ctx.backup_dir).glob("example.com/*/manifest.json"))
        .read_text(encoding="utf-8")
    )
    assert [f["path"] for f in manifest["files"]] == [
        "wp-content/uploads/2023/10/dead-1600x1067.jpg",
        "wp-content/uploads/2023/10/dead-scaled.jpg",
    ]
    assert [t["name"] for t in manifest["tables"]] == [
        "wp_postmeta", "wp_posts", "wp_term_relationships",
    ]


def test_registry_local_mode_refused(tmp_path, monkeypatch):
    built = []

    def spy(ctx):
        built.append(ctx)
        return make_stack([])

    monkeypatch.setattr(registry_mod, "_stack", spy)
    ctx = _ctx(tmp_path, source="local", webroot=None, wp_url=None,
               zip=None, sql=None, apply=False)
    assert run_action(ctx, "cull-media") == 1
    assert built == []  # the stack is never even built


def test_bridge_failure_is_not_swallowed(tmp_path, monkeypatch):
    """A failing database leg propagates (the registry answers rc 1); it
    never becomes half a keep-set."""
    src = FakeSource()
    src.files = dict(TREE)
    session = FakeSession([FakeResponse(200, json.dumps(
        {"ok": False, "error": "db map unavailable", "type": "E", "line": 1}
    ))])
    bridge = Bridge(src, session, WEBROOT, BridgeSettings(), SITE)
    patch_walk(monkeypatch, LIVE_REFS)
    with pytest.raises(BridgeError):
        CullMediaAction().plan(_ctx(tmp_path), (src, session, bridge))


def _records(caplog, name, level):
    return [r for r in caplog.records
            if r.name == name and r.levelno == level]


# ===========================================================================
# MODE PARITY — the database leg is the ONE owner's set
#
# cull-media is registered ftp-only, so the local/ftp plan comparison the
# regression sweep used belongs to trim-media (tests/actions/
# test_trim_media.py::test_plan_local_and_ftp_delete_the_same_set).  What
# is cull's own share of that defect: its keep-set must be built from the
# SAME database measurement, never a second one, or a cull can be measured
# against a weaker leg than the trim it shares the union with.
# ===========================================================================

def _ser(value: str) -> str:
    return 's:%d:"%s";' % (len(value.encode("utf-8")), value)


class _SerRaw(str):
    """A literal PHP serialization tag inside a serialized map."""


def _ser_map(pairs) -> str:
    body = "".join(_ser(key) + (value if isinstance(value, _SerRaw)
                                else _ser(value)) for key, value in pairs)
    return "a:%d:{%s}" % (len(pairs), body)


def _media_dump(postmeta) -> bytes:
    out = ("CREATE TABLE `wp_options` (`option_id` text, `option_name` text,"
           " `option_value` text, `autoload` text);\n"
           "INSERT INTO `wp_options` VALUES "
           "(1,'siteurl','https://example.com','yes');\n"
           ).encode()
    out += ("CREATE TABLE `wp_postmeta` (`meta_id` text, `post_id` text,"
            " `meta_key` text, `meta_value` text);\n").encode()
    if postmeta:
        out += ("INSERT INTO `wp_postmeta` VALUES "
                + ",".join("(%d,'%d','%s','%s')" % row for row in postmeta)
                + ";\n").encode()
    out += ("CREATE TABLE `wp_posts` (`ID` text, `post_type` text,"
            " `post_status` text, `post_content` text, `post_excerpt` text,"
            " `post_guid` text);\n").encode()
    out += ("CREATE TABLE `wp_termmeta` (`meta_id` text, `meta_key` text,"
            " `meta_value` text);\n").encode()
    return out


def test_database_leg_is_the_set_the_dump_measures(tmp_path, monkeypatch):
    """One database, one measurement, whichever side asks.

    The scripted bridge answer and the .sql dump hold the SAME rows, and
    the two implementations of the database map must return the SAME set —
    so a cull's keep-set is provably the trim's keep-set, and the family
    liveness verdict cannot differ by mode.
    """
    import io

    from wpt.media_refs import db_refs_from_dump

    metadata = _ser_map([
        ("file", "2023/10/dead.jpg"),
        ("sizes", _SerRaw(_ser_map([
            ("thumbnail", _SerRaw(_ser_map([("file", "2023/10/dead-1.jpg")]))),
        ]))),
        # a null inside the size map: the shape that made the offline
        # decoder lose every registered size of a family
        ("image_meta", _SerRaw("N;")),
    ])
    measured = db_refs_from_dump(io.BytesIO(_media_dump([
        (1, 10, "_wp_attached_file", "2023/10/dead.jpg"),
        (2, 10, "_wp_attachment_metadata", metadata),
        (3, 11, "_wp_attached_file", "2023/10/live.jpg"),
    ])))
    assert measured == {"2023/10/dead.jpg", "2023/10/dead-1.jpg",
                        "2023/10/live.jpg"}
    # ... and a family the pages never render but the DATABASE holds is
    # alive: the database-heavy measurement, cull's version of it
    plan, _, _ = _plan(tmp_path, monkeypatch,
                       _plan_script(db_refs=sorted(measured)))
    assert plan.items == []


def test_the_live_family_survives_a_size_map_loss(tmp_path, monkeypatch):
    """The family-liveness verdict depends on the size map, so the map
    must be read the SAME WAY in both modes.

    The attachment row is missing here (a plugin cleaned it) and only the
    size map names the family, in full-path form so it needs no anchor.
    Read, the map keeps the family alive and nothing is culled; lost — the
    pre-fix offline decoder lost any map carrying a null — the family reads
    as dead and its derivatives are planned for deletion.  That is the
    measured defect expressed as a cull.
    """
    import io

    from wpt.media_refs import db_refs_from_dump

    tree = dict(TREE)
    tree["wp-content/uploads/2023/10/dead-1.jpg"] = b"d" * 40
    metadata = _ser_map([
        ("file", "2023/10/dead.jpg"),
        ("sizes", _SerRaw(_ser_map([
            ("thumbnail", _SerRaw(_ser_map(
                [("file", "2023/10/dead-1.jpg")]))),
        ]))),
        # a null inside the size map: PHP keeps the whole array
        ("image_meta", _SerRaw("N;")),
    ])
    measured = db_refs_from_dump(io.BytesIO(_media_dump([
        (1, 10, "_wp_attachment_metadata", metadata),
    ])))
    assert measured == {"2023/10/dead.jpg", "2023/10/dead-1.jpg"}

    # READ: the database leg keeps the family alive, nothing is culled
    plan, _, _ = _plan(tmp_path, monkeypatch,
                       _plan_script(db_refs=sorted(measured)), files=tree)
    assert plan.items == []

    # LOST: without those references the same tree culls the derivatives —
    # which is what the offline half used to do for a map with a null in it
    plan, _, _ = _plan(tmp_path, monkeypatch, _plan_script(), files=tree)
    assert [item.target for item in plan.items] == [
        "wp-content/uploads/2023/10/dead-1600x1067.jpg",
        "wp-content/uploads/2023/10/dead-scaled.jpg",
    ]


# --------------------------------------------------------------------------
# THE CROSS-MODE GATE — cull-media deleted through the SAME media_delete op
# in the SAME ftp mode with NO cross-check at all
#
# Before the fix a cull was authorized by ONE live measurement while
# trim-media, which deletes strictly more per run, refused without a second
# measurement of the same database.  These tests pin the gate here with the
# shared implementation: the same five conditions, the same three places it
# is asked, and LITERALLY the same refusal strings (the wording is asserted
# against trim_media's own builder, not a copy of it).
# --------------------------------------------------------------------------


def test_a_cull_without_a_dump_is_refused_before_the_snapshot(
        tmp_path, monkeypatch, wpt_caplog):
    """The cheapest chokepoint, first: one stat, no walk, no snapshot.

    ``--sql`` is optional in ftp mode, so the recommended live cull command
    had no way to cross-check — and this refusal happens in the PLAN phase,
    before the registry takes the pre-action backup, so a refused attempt
    cannot evict a real snapshot from ``backup.keep_last``.
    """
    src, session, bridge = make_stack(_plan_script())
    patch_walk(monkeypatch, LIVE_REFS)
    monkeypatch.setattr(registry_mod, "_stack",
                        lambda ctx: (src, session, bridge))
    ctx = _ctx(tmp_path, apply=True, yes=True)          # no --sql at all
    assert run_action(ctx, "cull-media") == 1
    errors = [r.getMessage() for r in
              _records(wpt_caplog, "wpt.actions", logging.ERROR)]
    assert any("cannot cross-check a destructive apply" in m and
               "pass --sql" in m for m in errors), errors
    assert "media_delete" not in [a for a, _ in posted(session)]
    assert list(ctx.backup_dir.rglob("manifest.json")) == []


def test_a_cull_through_a_stale_dump_is_refused_and_nothing_is_deleted(
        tmp_path, monkeypatch):
    """THE REFUTED CLASS, on the second action: a dump that is behind.

    The cut is inside the postmeta rows — the table the reference set is
    read from — with ``-- Dump completed on`` appended, so every condition
    the trailer used to be asked for is satisfied.  The dump's missing rows
    are exactly the ones that would have named the dead family's
    derivatives, so it agrees with the live union about every planned file.
    A cull must refuse it BEFORE the snapshot, naming the table and both
    counts, and delete nothing.
    """
    sql = _dump(tmp_path, rows={"wp_postmeta": 2})
    src, session, bridge = make_stack(_plan_script())
    patch_walk(monkeypatch, LIVE_REFS)
    ctx = _ctx(tmp_path, apply=True, yes=True, sql=sql)
    with pytest.raises(SourceError) as excinfo:
        CullMediaAction().plan(ctx, (src, session, bridge))
    message = str(excinfo.value)
    assert "cull-media cannot cross-check" in message
    assert "wp_postmeta" in message
    assert "2 row(s)" in message and str(LIVE_ROWS["wp_postmeta"]) in message
    assert "dead-1600x1067.jpg" in message
    assert "media_delete" not in [a for a, _ in posted(session)]
    assert "wp-content/uploads/2023/10/dead-1600x1067.jpg" in src.files


def test_a_cull_whose_dump_disagrees_with_the_live_map_is_refused(
        tmp_path, monkeypatch):
    """The per-file dispute, on the cull: the two measurements of ONE
    database disagree about a file this apply is about to delete."""
    sql = _dump(tmp_path, refs={"2023/10/dead-1600x1067.jpg"})
    src, session, bridge = make_stack(_apply_script())
    patch_walk(monkeypatch, LIVE_REFS)
    action = CullMediaAction()
    ctx = _ctx(tmp_path, sql=sql)
    plan = action.plan(ctx, (src, session, bridge))
    assert [i.target for i in plan.items] == [
        "wp-content/uploads/2023/10/dead-1600x1067.jpg",
        "wp-content/uploads/2023/10/dead-scaled.jpg",
    ]
    with pytest.raises(SourceError) as excinfo:
        action.apply(ctx, (src, session, bridge), plan)
    assert "the two measurements of the same database disagree" in \
        str(excinfo.value)
    assert "media_delete" not in [a for a, _ in posted(session)]
    assert "wp-content/uploads/2023/10/dead-1600x1067.jpg" in src.files


def test_a_cull_dry_run_says_the_apply_will_refuse(tmp_path, monkeypatch,
                                                   wpt_caplog):
    """A dry run cannot refuse (it must stay informative), so the operator
    learns from the run that RECOMMENDS the apply command that the apply
    will not proceed — the same advice form trim-media prints."""
    plan, _, _ = _plan(tmp_path, monkeypatch, _plan_script(), sql=False)
    advice = [i for i in plan.items if not i.requires_apply]
    assert len(advice) == 1
    assert advice[0].target == "cross-mode check"
    assert "--apply will refuse" in advice[0].detail
    assert "pass --sql" in advice[0].detail
    # the deletions themselves are still planned and still counted
    assert [i.target for i in plan.items if i.requires_apply] == [
        t for _c, t, _b in EXPECTED
    ]


def test_both_media_actions_refuse_with_the_OWNER_s_wording(tmp_path,
                                                            monkeypatch):
    """One function, one wording: the two actions' refusals are the SAME
    strings, because the shared module builds them.

    The point of the extraction, asserted directly: a second copy of the
    gate is a second answer to the same question, and the copy is the one
    that deletes.  So the reason clause and the sentence around it are
    compared, and both actions import the same builders.
    """
    from wpt.actions import cull_media, trim_media
    from wpt.actions.dump_witness import dispute_refusal, witness_refusal

    paths = ["2023/10/a-1600x1067.jpg"]
    for reason in ("because", "a second reason"):
        for builder in (witness_refusal, dispute_refusal):
            if builder is dispute_refusal:
                trim_line = str(builder("trim-media", paths, "site.sql"))
                cull_line = str(builder("cull-media", paths, "site.sql"))
            else:
                trim_line = str(builder("trim-media", paths, reason))
                cull_line = str(builder("cull-media", paths, reason))
            # the ONLY difference is the action name the operator typed
            assert trim_line.replace("trim-media", "X") == \
                cull_line.replace("cull-media", "X")
    # ... and both actions hold the same gate type
    assert isinstance(trim_media.TrimMediaAction()._witness,
                      cull_media.WitnessGate)
    assert isinstance(cull_media.CullMediaAction()._witness,
                      trim_media.WitnessGate)
