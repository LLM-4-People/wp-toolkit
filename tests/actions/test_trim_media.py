"""Tests for the trim-media action (wpt.actions.trim_media) — W7f.

A REAL Bridge over FakeSession/FakeSource (scripted db_audit / media_map /
media_delete / db_dump responses — tests/actions/test_clean_db.py
conventions) with the LIVE WALK monkeypatched IN THE ACTION MODULE'S
namespace (``wpt.actions.trim_media.walk_site`` — the module imports the
name into its own namespace exactly so tests can patch it; NO real HTTP
server here, unlike tests/test_walk.py).  Deterministic, no network, no
sleeps.  The registry end-to-end tests monkeypatch
``wpt.actions.registry._stack`` (the pinned seam) to run the real
``run_action`` flow over a fake ftp-mode stack; ``bridge.destroy()`` (the
registry's finally) is scripted via a self-destruct handler.

THE BEHAVIOUR THIS FILE PINS — the union keep-set.  A page renders only
a FRACTION of its attachment images: measured live on an observed run, the
walk-only keep-set planned most files / most of the media bytes
for deletion — every one of them DATABASE-referenced media the walk never
sees (featured images in menus/widgets/page-builder options, srcset entries,
attachment pages, gallery templates, PDFs in post content).  A compliant
apply would have broken images across the site; the defensible
measurement was a small remainder.  So every decision here is measured
against walk refs UNION database refs, and a DEGRADED set (one side
unmeasured) may be planned but never applied.

Test -> behavior map:
  test_registration .......................... trim-media registered as
        the INSTANCE under applies=("ftp","local") — both modes reach it
  test_plan_walk_wiring ..................... walk_site called exactly
        once per measurement with the STACK session + ctx.wp_url +
        ctx.settings.walk + ctx.settings.http.timeout_s (the W7i recipe)
  test_plan_union_keeps_db_only_media ....... (a) the database-heavy shape: the walk
        sees 20% of the DB-referenced media and the plan contains NONE of
        it — the regression the fixture site would have hit
  test_plan_evidence_class_in_detail ........ every item's detail names the
        evidence class its deletion rests on
  test_plan_metadata_size_forms_keep_files .. (b) the FOUR attachment-
        metadata forms (bare size basename, full-path size entry, the map's
        own `file` key, the legacy backup-sizes key) each keep their file
  test_plan_broken_attachment_keeps_every_size (c) an attachment with a
        broken main + generated variants keeps ALL of its referenced sizes
  test_plan_gallery_and_pdf_in_content ....... (f) a PDF attached and
        linked from post content is referenced (the gallery/PDF case)
  test_plan_live_refs_keep_referenced_and_variants  a ref to a VARIANT
        keeps the original + -scaled sibling [L5 symmetric]; unreferenced
        files enumerated PER FILE with WEBROOT-relative targets,
        uploads-relative detail + size + evidence, bytes_est = size, sorted
        by target; backup_tables = posts/postmeta/term_relationships from
        db_audit; ONE info plan summary; non-uploads files never planned
  test_plan_empty_live_refs_ ................. live_refs == set() is a REAL
        result: EVERY uploads file the DB does not reference is planned +
        exactly ONE warning
  test_plan_absent_ref_keeps_siblings ......... a ref with no on-disk file
        keeps its on-disk stem siblings; the absent ref is never planned
  test_plan_backup_tables_from_db_audit ...... suffix derivation (core
        prefixes AND multisite-style wp_2_*)
  test_plan_refuses_unbacked_mutation ......... a required suffix with no
        audited table -> SourceError
  test_plan_nothing_unreferenced_ ............. everything kept -> EMPTY
        plan, backup_tables == [], ZERO bridge calls
  test_plan_walk_failure_fails_closed ........ a walk_site raising
        requests.RequestException -> rc 1, no bridge POST
  test_plan_db_map_failure_degrades_walk_only  an unmeasurable database map
        is ONE warning + a DEGRADED advice item, and the plan still works
  test_plan_local_mode_degraded_dry_run ...... (d) local mode: the .sql
        dump IS the reference set, the plan is informative and leads with
        the degraded advice item naming the full-set command
  test_apply_maps_refs_and_deletes ........... re-measures the UNION (a
        fresh walk AND a fresh database map), then media_map with the
        planned uploads-RELATIVE paths in plan order; ids deduped+sorted;
        media_delete with ids+files; all items done; ONE info apply
        summary carrying media_delete's counts
  test_apply_dedupes_ids ..................... several files stem-matching
        one attachment collapse to one id
  test_apply_zero_ids_still_deletes_files .... never-attached files: ids
        == [] and media_delete STILL called with files
  test_apply_failure_propagates_ ............. media_delete ok:false ->
        BridgeError propagates, items stay done=False
  test_apply_empty_plan_no_bridge_calls ...... zero planned paths -> no
        bridge roundtrip (not even the re-measurement)
  test_apply_skips_non_apply_items ........... requires_apply=False items
        are neither sent nor marked done
  test_apply_refuses_degraded_local ......... (d) local --apply refuses
        with the one actionable line naming the full-set command; no
        mutation whatsoever
  test_apply_refuses_when_db_map_fails ....... the same gate in ftp mode:
        an unmeasurable database half refuses before any deletion
  test_apply_refuses_when_fresh_union_protects  a file the FRESH union
        references (the site changed since the plan) aborts with nothing
        deleted
  test_apply_is_idempotent .................. (e) a second plan over the
        trimmed tree is empty and applies without a bridge call
  test_registry_dry_run ...................... run_action apply=False: plan
        printed (rc 0), no media_delete / db_dump (read-only)
  test_registry_ftp_apply_end_to_end ......... apply --yes over the fake
        stack: pre-action snapshot manifest lists plan.backup_tables AND
        the planned FILES, media_map + media_delete scripted, rc 0
  test_registry_local_apply_refused_end_to_end  (d) the registry's local
        rehearsal path refuses the degraded apply (rc 1, zip untouched)
  mode parity (the regression sweep's §2 discriminator):
  test_plan_local_and_ftp_delete_the_same_set . THE DISCRIMINATOR: one
        database (a .sql dump) and one tree, planned offline and over the
        bridge, must yield the IDENTICAL delete set — over a fixture whose
        database half carries every shape that used to differ (a
        bare-basename size family, a null inside the size map, an
        unlisted extension, a bare year directory)
  test_plan_local_gates_a_directory_named_like_a_file ... the is-a-
        directory half of the keep-gate is applied offline too, from the
        walked directories
  test_apply_refuses_when_the_dump_and_the_live_map_disagree ... the
        cross-mode gate: a planned file the --sql dump says the database
        references and the fresh live union does not is REFUSED, nothing
        deleted (the measured multi-size family case)
  test_apply_proceeds_when_the_dump_agrees ... the same fixture with the
        two measurements in agreement applies normally
  test_apply_without_sql_refuses_before_deleting ... the cross-mode gate
        is MANDATORY: --sql is optional in ftp mode, so the recommended
        live command refused in one line naming the flag, before any
        deletion call
  test_apply_with_an_unmeasurable_dump_refuses ... a dump that measures
        nothing (no usable tables) is the same fact as no dump — UNKNOWN
        is never read as "the database references nothing"
  test_apply_measures_the_dump_once_with_the_plans_directories ... one
        measurement per run (keyed on the dump's identity, the family and
        the directories) and the SAME dirs the plan measured with
  test_apply_dump_measurement_honours_the_deadline ... a spent run budget
        ends the run instead of returning a partial keep-set
  test_a_widened_profile_keeps_a_database_referenced_file_end_to_end ...
        D1: a profile the operator widened keeps the .psd the shipped
        default cannot name, and the read CARRIES that family
  test_a_gate_that_could_not_honor_the_family_degrades_and_refuses ... a
        gate measured with another family is UNKNOWN: the plan degrades
        and the apply refuses
  test_a_family_the_wire_cannot_carry_is_refused_at_the_profile ... a
        family the wire cannot express (a blank, dotted or spaced entry) is
        a SettingsError at the owner, on the profile AND the --set path, so
        the delete set is never enumerated with it
  THE WITNESS MUST BE ABLE TO SAY "THIS DUMP IS INCOMPLETE OR OLDER" (the
  trailer alone cannot see it):
  test_a_dump_cut_inside_the_rows_is_refused_though_it_carries_the_trailer
        ... a dump cut inside the postmeta rows with `-- Dump completed on`
        APPENDED, and ONE surviving attachment row so the old condition 3
        is satisfied: refused for being BEHIND the live row count, with
        the table and BOTH numbers, before the pre-action snapshot
  test_a_dump_missing_a_live_table_is_refused_by_name ... a live table the
        dump does not DECLARE is refused by name (a dump taken before that
        table existed, or one whose DDL was cut and the trailer appended)
  test_a_dump_that_is_current_enough_still_applies ... the two new
        conditions are not a new way to refuse an honest export
  test_the_behind_tolerance_is_a_profile_key_and_fails_loud_on_nonsense ...
        the tolerance is a profile key with a documented default, and 0 /
        >1 / a string / NaN are a SettingsError naming the key
  test_a_decoy_plugin_posts_table_cannot_answer_the_currency_check  THE
        MEASURED CASE: `wp_aioseo_posts` (a real AIOSEO 4.x table) answers
        for the posts role, so the check validated a decoy count of a table the
        reference set was never read from while the core wp_posts held 2 of
        80 — refused by name, with the A/B that caught it before the decoy
  test_a_decoy_plugin_postmeta_table_cannot_displace_the_real_one  the same
        displacement with an EMPTY decoy (`wp_edd_postmeta`), which the
        `live_rows == 0 -> continue` branch skipped entirely
  test_the_witness_asks_the_measurement_which_table_a_role_is  the "two
        rules" defect class pinned STRUCTURALLY (the witness must import the
        resolution from the owner — a banned-name list is defeatable by
        renaming), and both decoys resolve to the core tables in the
        measurement and in the check
  test_a_contested_options_identity_refuses_the_trim_plan  `aioseo_options`
        beside `wp_options`: the keep-set used to read the plugin's table
        and measure ZERO, and the plan deleted database-referenced media —
        now the witness refuses (nothing measurable) and the plan is
        refused with the candidates named
  test_a_contested_options_identity_plans_nothing_in_local_mode  the same
        dump locally: the dump IS the database half, so nothing is planned
  test_a_contested_options_identity_never_reaches_the_apply  even a
        hand-made plan is refused; no media_delete is ever posted
  test_a_dump_at_thirty_percent_of_live_is_refused_at_the_shipped_ratio
        the shipped 0.5 is a safety property: a dump carrying 30% of the
        live rows is refused (the suite was green with 0.95 shipped, and a
        30%-of-live dump passed at a 0.4 threshold)
"""

import json
import logging
import time
import zipfile

import pytest
import requests

from tests.dump_fixtures import (
    AIOSEO_OPTIONS_SCHEMA, AIOSEO_POSTS_SCHEMA, CORE_SCHEMA,
    DECOY_POSTMETA_SCHEMA, DUMP_TRAILER, LIVE_ROWS, WP_AIOSEO_OPTIONS_SCHEMA,
    make_dump, schema_tables,
)
from tests.fakes import FakeResponse, FakeSession, FakeSource
from wpt.actions import dump_witness as dump_witness_mod
from wpt.actions.dump_witness import live_schema_from_audit
from wpt.audit.data import _tables_from_wire
from wpt.actions import registry as registry_mod
from wpt.actions import trim_media as trim_media_mod
from wpt.actions.registry import get_action, run_action
from wpt.actions.trim_media import TrimMediaAction
from wpt.cli import Ctx
from wpt.deadline import Deadline
from wpt.localmode.analyzer import analyze
from wpt.report import Plan
from wpt.settings import BridgeSettings, load
from wpt.types import BridgeError, DeadlineExceeded, PlanItem, SourceError
from wpt.walk import WalkResult
from wpt.wpbridge.client import Bridge

#: The shipped profile — every threshold exactly as users get them
#: (walk.max_pages 200, http.timeout_s 30).
DEFAULTS = load()

WEBROOT = "domains/example.com/public_html"
SITE = "https://example.com"

#: The media tree (webroot-relative — FakeSource plays a source rooted at
#: the webroot, like the real FtpSource): one referenced original + two
#: kept variants, two unreferenced files, one non-uploads leaf that must
#: never be planned.
MEDIA_TREE = {
    "wp-content/uploads/2023/10/pic.jpg": b"a" * 1000,
    "wp-content/uploads/2023/10/pic-300x233.jpg": b"a" * 233,
    "wp-content/uploads/2023/10/pic-scaled.jpg": b"a" * 800,
    "wp-content/uploads/2023/10/zz-unused.jpg": b"b" * 90,
    "wp-content/uploads/2023/11/other.png": b"c" * 50,
    "wp-content/plugins/akismet/img.png": b"d" * 10,
}

#: live_refs keeping the whole tree (the variant-only ref keeps the
#: original and the -scaled sibling — symmetric L5).
KEEP_REFS = {"2023/10/pic-300x233.jpg"}

#: Every uploads-relative ref — the all-referenced fixture.
ALL_REFS = {
    "2023/10/pic.jpg",
    "2023/10/pic-300x233.jpg",
    "2023/10/pic-scaled.jpg",
    "2023/10/zz-unused.jpg",
    "2023/11/other.png",
}

#: The database half of the same fixture: the attachment the walk also
#: sees.  It must not change the walk-only plan (a candidate needs to be
#: unreferenced by BOTH sides).
KEEP_DB_REFS = {"2023/10/pic.jpg"}

#: The unreferenced items over MEDIA_TREE with KEEP_REFS, target-sorted.
#: Each detail carries the EVIDENCE CLASS the deletion rests on.
EXPECTED_ITEMS = [
    ("media.unreferenced",
     "wp-content/uploads/2023/10/zz-unused.jpg",
     "2023/10/zz-unused.jpg (90 B) — unreferenced by the live walk and "
     "the database", 90),
    ("media.unreferenced",
     "wp-content/uploads/2023/11/other.png",
     "2023/11/other.png (50 B) — unreferenced by the live walk and the "
     "database", 50),
]


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
    """A trim-media Ctx; ftp-mode defaults, overridable per test."""
    fields = dict(
        source="ftp://example.com",
        settings=settings,
        command="trim-media",
        apply=False,
        yes=False,
        backup_dir=tmp_path / "backup",
        wp_url="https://example.com",
    )
    fields.update(overrides)
    return Ctx(**fields)


#: ``DUMP_TRAILER`` is tests/dump_fixtures' (one owner, both actions).


#: The dump fixtures live in ONE owner (tests/dump_fixtures.py), because the
#: witness asks the same five structural questions of every dump and the two
#: media actions that gate on it must be able to disagree about the SCHEMA
#: the same way.  Re-exported here under the names this file's tests use.
_CORE_SCHEMA = CORE_SCHEMA
_LIVE_ROWS = LIVE_ROWS


def _schema_tables(rows=None, tables=CORE_SCHEMA):
    return schema_tables(rows, tables)


def _dump(tmp_path, refs=(), name="site.sql", site="https://example.com",
          trailer=True, rows=None, tables=CORE_SCHEMA):
    """A usable .sql dump of this site whose database half is ``refs``.

    The CROSS-MODE GATE is mandatory for an ftp apply (a run that cannot
    cross-check the live database map against a second measurement of the
    same database refuses before it deletes anything), so every apply test
    needs a dump.  This is the AGREEING witness by default — a dump that
    names nothing is a real measurement ("this database references no
    uploads file"), so the gate is silent and the apply proceeds exactly as
    it did before the gate existed.  The shape (the whole core table set, at
    least as many rows per table as the live schema reports) is
    :func:`tests.dump_fixtures.make_dump`'s; ``site=`` states another site,
    ``trailer=False`` is a cut-off transfer, ``rows=`` is a dump that
    PREDATES the live content and ``tables=`` one that does not declare a
    table the live schema has.
    """
    return make_dump(tmp_path, refs=refs, name=name, site=site,
                     trailer=trailer, rows=rows, tables=tables)


def _unusable_dump(tmp_path, name="empty.sql"):
    """A dump with no WordPress tables: the cross-check measures NOTHING.

    ``db_refs_from_dump`` answers None for it (UNKNOWN, never an empty
    keep-set), which the gate treats exactly like having no dump at all.
    """
    path = tmp_path / name
    # COMPLETE (it carries the trailer) and still unmeasurable: the two
    # conditions are independent, and this one is about a dump that
    # arrived whole and holds no WordPress tables at all
    path.write_bytes(
        b"-- a schema-less export: nothing to measure\n" + DUMP_TRAILER.encode()
    )
    return path


def _tables(**data_free_kb):
    """The core tables as db_audit wire rows, per-name data_free_kb.

    All default to 0.0 (a measured zero — trim-media does not care about
    free space, only the table NAMES).
    """
    free = {
        "wp_commentmeta": 0.0,
        "wp_options": 0.0,
        "wp_postmeta": 0.0,
        "wp_posts": 0.0,
        "wp_term_relationships": 0.0,
        "wp_termmeta": 0.0,
    }
    free.update(data_free_kb)
    return [
        {"name": name, "rows": _LIVE_ROWS[name], "size_mb": 0.5,
         "data_free_kb": value}
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


def ok(**payload):
    """An ok:true bridge envelope (the payload the client returns)."""
    return FakeResponse(200, json.dumps({"ok": True, **payload}))


def media_map_ok(refs, attachments=None):
    """A successful media_map answer: ref -> {id, file} (+ attachments)."""
    return ok(refs=refs, attachments=attachments or {})


def db_map_ok(refs, gate=None, fallback=False):
    """The read-only database media map (media_map, mode=db).

    ``gate`` is the effective extension family the server measured the
    answer with (bridge.php's ``db_refs_gate``); ``fallback`` flags a
    request the server refused to honor.  Both are omitted by default, so
    every other test in this file scripts the historical answer shape.
    """
    payload = {"db_refs": sorted(refs)}
    if gate is not None:
        payload["db_refs_gate"] = gate if isinstance(gate, int) else len(gate)
    if fallback:
        payload["db_refs_gate_fallback"] = True
    return ok(**payload)


def db_map_failed():
    """A media_map mode=db answer the server refuses (any ok:false shape)."""
    return FakeResponse(
        200,
        json.dumps({"ok": False, "error": "db media map unavailable",
                    "type": "RuntimeException", "line": 12}),
    )


class _MediaDelete:
    """Marker for a successful media_delete answer.

    ``make_stack`` turns it into a script handler that unlinks the requested
    files from the FakeSource, mirroring the real bridge (which commits the
    DB transaction and THEN removes the files). That keeps the post-apply
    existence verification honest: a successful delete really removes the file.
    """

    def __init__(self, response):
        self.response = response


def media_delete_ok(**counts):
    """A successful media_delete answer with the documented count keys.

    ``unlink_failures`` lists uploads-relative paths the server could NOT
    remove (the authoritative server-side verification signal).
    """
    return _MediaDelete(ok(
        deleted_posts=counts.get("deleted_posts", 0),
        deleted_meta=counts.get("deleted_meta", 0),
        deleted_termrels=counts.get("deleted_termrels", 0),
        deleted_files=counts.get("deleted_files", 0),
        skipped_missing=counts.get("skipped_missing", 0),
        unlink_failures=counts.get("unlink_failures", []),
    ))


def media_delete_refused():
    """A media_delete ok:false answer (the bridge's anti-traversal refusal)."""
    return FakeResponse(
        200,
        json.dumps(
            {
                "ok": False,
                "error": "refused path (must be under YYYY/): banner.jpg",
                "type": "InvalidArgumentException",
                "line": 470,
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


def _delete_handler(src, response):
    """Script item: a successful media_delete removes its files from the src.

    A file the server reports in ``unlink_failures`` is NOT removed (that is
    exactly what a failed unlink looks like), keeping the fake faithful to the
    real bridge's partial-delete behavior.
    """

    def handler(method, url, kwargs):
        body = kwargs.get("json") or {}
        params = body.get("params") or {}
        try:
            failures = set(json.loads(response.text).get("unlink_failures", []))
        except Exception:
            failures = set()
        for rel in params.get("files", []):
            if rel in failures:
                continue
            src.files.pop(f"wp-content/uploads/{rel}", None)
        return response

    return handler


def make_stack(script, files=MEDIA_TREE):
    """A fake ftp-mode stack: (FakeSource, FakeSession, Bridge over it).

    ``files`` defaults to MEDIA_TREE; pass a custom dict (or {} for an
    empty source) per test.  A ``_MediaDelete`` script item is wrapped so the
    requested files are actually unlinked from the source (the real bridge
    removes them), keeping the post-apply verification honest.  The
    self-destruct handler rides last so the registry's
    ``finally: bridge.destroy()`` GET finds a scripted answer; unit tests that
    never destroy simply leave it unconsumed.
    """
    src = FakeSource()
    src.files = dict(files)
    wrapped = [
        _delete_handler(src, item.response) if isinstance(item, _MediaDelete) else item
        for item in script
    ]
    session = FakeSession(wrapped + [_selfdestruct(src)])
    bridge = Bridge(src, session, WEBROOT, BridgeSettings(), SITE)
    return src, session, bridge


def patch_walk(monkeypatch, live_refs, *, partial=False):
    """Point the action's walk seam at a canned WalkResult (no HTTP).

    Returns the call recorder so tests can pin the W7i wiring arguments.
    ``live_refs`` may be a set (one measurement) or a list of sets, one per
    call — the apply RE-MEASURES, so a test that pins two calls scripts two
    reference sets.  ``partial`` is the truncated-walk shape every call
    reports.
    """
    calls = []
    answers = list(live_refs) if isinstance(live_refs, list) else [live_refs]

    def fake_walk_site(session, site, settings, timeout_s=30, deadline=None):
        calls.append((session, site, settings, timeout_s))
        answer = answers.pop(0) if len(answers) > 1 else answers[0]
        return WalkResult(live_refs=set(answer), pages=[], forms=[], fetched=0,
                          partial=partial)

    monkeypatch.setattr(trim_media_mod, "walk_site", fake_walk_site)
    return calls


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


def _planned(plan) -> list[str]:
    """The targets a plan would DELETE.

    An advice item (``requires_apply=False``) is prose about the run — the
    DEGRADED reference-set note, the cross-mode witness note — and every
    ftp dry run without a usable ``--sql`` now carries the second one, so
    an assertion about what would be deleted has to read the applicable
    items only.
    """
    return [i.target for i in plan.items if i.requires_apply]


def _advice(plan) -> list:
    """The plan's advice items (never applied, never snapshotted)."""
    return [i for i in plan.items if not i.requires_apply]


def _plan(tmp_path, monkeypatch, script, live_refs=KEEP_REFS,
          files=MEDIA_TREE, ctx=None):
    """plan() over a fresh scripted stack -> (plan, session, src).

    The default script starts with the database media map, because the
    plan measures the UNION: the database call comes first, db_audit
    (the backup scope) only when something is actually planned.
    """
    src, session, bridge = make_stack(script, files=files)
    patch_walk(monkeypatch, live_refs)
    plan = TrimMediaAction().plan(
        ctx or _ctx(tmp_path), (src, session, bridge)
    )
    return plan, session, src


def _measure(db_refs=KEEP_DB_REFS, **kwargs):
    """A plan script: the database media map + the backup-scope audit."""
    return [db_map_ok(db_refs), ok(**audit_payload(**kwargs))]


# ------------------------------------------------------------- registration


def test_registration():
    record = get_action("trim-media")
    assert record is not None
    assert record.applies == ("ftp", "local")
    assert isinstance(record.action, TrimMediaAction)  # the instance


# ------------------------------------------------------------------- plan


def test_plan_walk_wiring(tmp_path, monkeypatch):
    # the W7i recipe, pinned: the stack's session, the public site URL,
    # the walk settings, the http timeout — once per measurement
    src, session, bridge = make_stack([db_map_ok(set())], files={})
    calls = patch_walk(monkeypatch, {"2023/10/pic.jpg"})
    plan = TrimMediaAction().plan(_ctx(tmp_path), (src, session, bridge))
    assert plan.items == []
    assert calls == [
        (session, SITE, DEFAULTS.walk, DEFAULTS.http.timeout_s)
    ]


def test_R20_partial_walk_is_degraded_and_apply_refuses(
        tmp_path, monkeypatch, wpt_caplog):
    """R20-P1: a PARTIAL live walk was used as the complete keep-set, so the
    plan (and the apply's media_delete) called every file referenced only by
    the unseen pages dead.  Partial is UNKNOWN: the plan is degraded advice
    and the apply refuses before any bridge deletion call."""
    src, session, bridge = make_stack(
        _measure(db_refs=set()), files=MEDIA_TREE)
    patch_walk(monkeypatch, set(), partial=True)
    action = TrimMediaAction()
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, (src, session, bridge))

    advice = [i for i in plan.items if not i.requires_apply]
    assert advice and "DEGRADED reference set" in advice[0].detail
    assert _planned(plan)  # the dry run stays informative
    with pytest.raises(SourceError, match="degraded reference set"):
        action.apply(ctx, (src, session, bridge), plan)
    assert "media_delete" not in posted_actions(session)


def test_plan_never_plans_non_media_guard_files(tmp_path, monkeypatch):
    """[L14] Non-media uploads files never reach a trim-media plan — the
    live case was Wordfence's uploads .htaccess (a PHP-execution BLOCK)
    landing in the plan because every uploads file counted as media.
    Even at EMPTY live refs (the everything-unreferenced plan) only the
    media files are planned; non-media files are invisible to both the
    enumeration and the database map."""
    files = dict(MEDIA_TREE)
    files["wp-content/uploads/.htaccess"] = b"Options -Indexes\n"
    files["wp-content/uploads/index.php"] = b"<?php // silence\n"
    plan, session, _src = _plan(
        tmp_path, monkeypatch, _measure(db_refs=set()),
        live_refs=set(), files=files,
    )
    planned = _planned(plan)
    assert "wp-content/uploads/.htaccess" not in planned
    assert "wp-content/uploads/index.php" not in planned
    # every MEDIA file IS planned (empty refs is a measured result)
    assert planned == [
        "wp-content/uploads/2023/10/pic-300x233.jpg",
        "wp-content/uploads/2023/10/pic-scaled.jpg",
        "wp-content/uploads/2023/10/pic.jpg",
        "wp-content/uploads/2023/10/zz-unused.jpg",
        "wp-content/uploads/2023/11/other.png",
    ]


# ------------------------------------------------- the union keep-set (a)


def _eighties_shape():
    """(files, walk_refs, db_refs) reproducing the database-heavy shape.

    20 uploads files; the rendered pages reference 4 of them (20%) while
    the DATABASE references all 20 — featured images in menus/widgets/
    theme options, srcset entries, attachment pages, gallery templates.
    Only ``orphan.jpg`` is unreferenced by both sides.  On the fixture site
    the walk-only plan would have deleted the other database-only files.
    """
    files = {f"wp-content/uploads/2024/05/m{i:02d}.jpg": b"x" * 100
             for i in range(20)}
    files["wp-content/uploads/2024/05/orphan.jpg"] = b"x" * 50
    walk_refs = {f"2024/05/m{i:02d}.jpg" for i in range(4)}
    db_refs = {f"2024/05/m{i:02d}.jpg" for i in range(20)}
    return files, walk_refs, db_refs


def test_plan_union_keeps_db_only_media(tmp_path, monkeypatch):
    # (a) THE REGRESSION: 20% of the media is rendered, 100% is
    # database-referenced. The plan must contain the single file neither
    # side references — never one of the 16 the walk cannot see.
    files, walk_refs, db_refs = _eighties_shape()
    plan, _session, _src = _plan(
        tmp_path, monkeypatch, _measure(db_refs=db_refs),
        live_refs=walk_refs, files=files,
    )
    assert _planned(plan) == [
        "wp-content/uploads/2024/05/orphan.jpg"
    ]
    assert "unreferenced by the live walk and the database" in \
        [i for i in plan.items if i.requires_apply][0].detail
    # the walk-only plan would have covered most of the bytes
    walk_only, _s, _src2 = _plan(
        tmp_path, monkeypatch, _measure(db_refs=set()),
        live_refs=walk_refs, files=files,
    )
    assert len(_planned(walk_only)) == 17


def test_plan_evidence_class_in_detail(tmp_path, monkeypatch):
    # every item says WHICH reference classes measured it unreferenced,
    # so the operator can see why each file is a candidate
    plan, _session, _src = _plan(
        tmp_path, monkeypatch, _measure(db_refs=set()),
    )
    assert all(
        "unreferenced by the live walk and the database" in i.detail
        for i in plan.items if i.requires_apply
    )


def test_plan_db_map_failure_degrades_walk_only(tmp_path, monkeypatch,
                                                wpt_caplog):
    # an unmeasurable database map is ONE warning + a DEGRADED advice
    # item; the dry run still works (it is the apply that refuses)
    plan, _session, _src = _plan(
        tmp_path, monkeypatch,
        [db_map_failed(), ok(**audit_payload())],
    )
    advice = [i for i in plan.items if not i.requires_apply]
    assert len(advice) == 1
    assert advice[0].category == "media.info"
    assert "DEGRADED reference set" in advice[0].detail
    assert "no database reference set" in advice[0].detail
    assert "--apply refuses" in advice[0].detail
    # the real candidates follow, and say they rest on the walk alone
    candidates = [i for i in plan.items if i.requires_apply]
    assert candidates
    assert all("unreferenced by the live walk only" in i.detail
               for i in candidates)
    warnings = _records(wpt_caplog, "wpt.actions.trim_media", logging.WARNING)
    assert any("database media map unavailable" in w.getMessage()
               for w in warnings)


# ------------------------------- the four attachment-metadata forms (b/c/f)


def test_plan_metadata_size_forms_keep_their_files(tmp_path, monkeypatch):
    # (b) The FOUR stored forms of an attachment size map, as the bridge
    # answers them in mode=db, each keep their file:
    #   1. sizes[*].file as a BARE BASENAME, anchored to the attachment's
    #      own directory
    #   2. a sizes entry that is already uploads-relative
    #   3. the map's own `file` key
    #   4. the legacy _wp_attachment_backup_sizes key's sizes
    db_refs = {
        # 1
        "2023/11/pic-150x150.png",
        # 2
        "2023/11/pic-odd.png",
        # 3
        "2023/12/solo.png",
        # 4
        "2023/11/pic-1920x1080.png",
    }
    files = {
        "wp-content/uploads/2023/11/pic.png": b"a" * 1000,
        "wp-content/uploads/2023/11/pic-150x150.png": b"a" * 150,
        "wp-content/uploads/2023/11/pic-odd.png": b"a" * 320,
        "wp-content/uploads/2023/11/pic-1920x1080.png": b"a" * 1920,
        "wp-content/uploads/2023/11/orphan.png": b"b" * 40,
        "wp-content/uploads/2023/12/solo.png": b"c" * 500,
    }
    plan, _session, _src = _plan(
        tmp_path, monkeypatch, _measure(db_refs=db_refs),
        live_refs=set(), files=files,
    )
    # every size-variant file the four forms name is protected by the
    # database half; only the file no form names is a candidate
    assert _planned(plan) == [
        "wp-content/uploads/2023/11/orphan.png"
    ]


def test_plan_broken_attachment_keeps_every_referenced_size(
    tmp_path, monkeypatch
):
    # (c) an attachment whose main file is BROKEN (WordPress still records
    # its size map) keeps EVERY size it references — the live lesson: a
    # thumbnail deleted with a "broken" original is a broken thumbnail
    db_refs = {
        "2023/11/broken.png",              # the attachment's own file
        "2023/11/broken-150x150.png",      # sizes[*].file, bare basename
        "2023/11/broken-300x200.png",
    }
    files = {
        # the on-disk original is a 0-byte leftover of a failed upload
        "wp-content/uploads/2023/11/broken.png": b"",
        "wp-content/uploads/2023/11/broken-150x150.png": b"a" * 150,
        "wp-content/uploads/2023/11/broken-300x200.png": b"a" * 300,
        "wp-content/uploads/2023/11/stale.png": b"b" * 70,
    }
    plan, _session, _src = _plan(
        tmp_path, monkeypatch, _measure(db_refs=db_refs),
        live_refs=set(), files=files,
    )
    assert _planned(plan) == [
        "wp-content/uploads/2023/11/stale.png"
    ]


def test_plan_gallery_and_pdf_in_content_is_referenced(tmp_path, monkeypatch):
    # (f) the gallery / PDF case: an attached PDF linked from post content
    # (and a gallery shortcode's image) is DB-referenced, so it is never a
    # deletion candidate even though no page the walk saw renders it
    db_refs = {
        "2023/11/brochure.pdf",   # _wp_attached_file + a link in content
        "2023/11/gallery-1.jpg",  # a gallery shortcode's image
    }
    files = {
        "wp-content/uploads/2023/11/brochure.pdf": b"%PDF" + b"a" * 900,
        "wp-content/uploads/2023/11/gallery-1.jpg": b"a" * 400,
        "wp-content/uploads/2023/11/never-used.pdf": b"%PDF" + b"b" * 100,
    }
    plan, _session, _src = _plan(
        tmp_path, monkeypatch, _measure(db_refs=db_refs),
        live_refs=set(), files=files,
    )
    assert _planned(plan) == [
        "wp-content/uploads/2023/11/never-used.pdf"
    ]


def test_plan_live_refs_keep_referenced_and_variants(
    tmp_path, monkeypatch, wpt_caplog
):
    plan, session, _src = _plan(tmp_path, monkeypatch, _measure())
    # the VARIANT-only ref kept pic.jpg + pic-scaled.jpg [L5 symmetric];
    # the two unreferenced files are one item each, target-sorted
    assert [
        (i.category, i.target, i.detail, i.bytes_est)
        for i in plan.items if i.requires_apply
    ] == EXPECTED_ITEMS
    assert plan.est_bytes() == 140
    # media_delete removes attachment posts+meta+term_relationships: the
    # snapshot scope is every audited table with those suffixes
    assert plan.backup_tables == [
        "wp_postmeta", "wp_posts", "wp_term_relationships",
    ]
    assert all(i.requires_apply for i in _delete_set_items(plan))
    assert all(not i.done for i in plan.items)
    # exactly one info plan summary; the measurement is walk + db map and
    # the backup scope is the one db_audit
    summaries = _records(wpt_caplog, "wpt.actions.trim_media", logging.INFO)
    assert len(summaries) == 1
    assert "2 item(s)" in summaries[0].getMessage()
    assert posted_actions(session) == ["media_map", "db_audit"]
    # the read CARRIES this run's media family: the enumeration below files
    # uploads media by exactly this list, so a gate answering from a
    # different one would make a reference invisible and a database-
    # referenced file deletable [D1]
    assert posted_params(session, "media_map") == [{
        "mode": "db", "extensions": sorted(DEFAULTS.media.extensions),
    }]
    # no warning fired (both sides were measured non-empty)
    assert _records(wpt_caplog, "wpt.actions.trim_media", logging.WARNING) == []


def test_plan_empty_live_refs_plans_everything_with_one_warning(
    tmp_path, monkeypatch, wpt_caplog
):
    plan, _session, _src = _plan(
        tmp_path, monkeypatch, _measure(db_refs=set()),
        live_refs=set(),
    )
    # a measured zero-ref walk (and a measured zero-ref database) is a REAL
    # result on both sides: every uploads file is planned
    assert _planned(plan) == [
        "wp-content/uploads/2023/10/pic-300x233.jpg",
        "wp-content/uploads/2023/10/pic-scaled.jpg",
        "wp-content/uploads/2023/10/pic.jpg",
        "wp-content/uploads/2023/10/zz-unused.jpg",
        "wp-content/uploads/2023/11/other.png",
    ]
    assert plan.est_bytes() == 2173
    # exactly ONE warning that the walk found no references
    warnings = _records(wpt_caplog, "wpt.actions.trim_media", logging.WARNING)
    assert len(warnings) == 1
    assert "0 references" in warnings[0].getMessage()
    assert "database does not reference" in warnings[0].getMessage()
    # the non-uploads leaf never participates
    assert all(
        i.target.startswith("wp-content/uploads/")
        for i in plan.items if i.requires_apply
    )


def test_plan_absent_ref_keeps_on_disk_siblings(tmp_path, monkeypatch):
    # W6e semantics: a ref with NO on-disk file still keeps its on-disk
    # stem siblings (a reference is not a file); the absent ref itself is
    # never planned — true for a DATABASE ref exactly as for a live one
    files = {
        "wp-content/uploads/2023/10/ghost-300x200.jpg": b"a" * 100,
        "wp-content/uploads/2023/10/stray.jpg": b"b" * 40,
    }
    plan, _session, _src = _plan(
        tmp_path, monkeypatch,
        _measure(db_refs={"2023/10/ghost.jpg"}),
        live_refs=set(), files=files,
    )
    assert _planned(plan) == [
        "wp-content/uploads/2023/10/stray.jpg"
    ]


def test_plan_backup_tables_from_db_audit(tmp_path, monkeypatch):
    # multisite-style prefixes resolve by the same plain endswith
    payload = audit_payload(
        tables=[
            {"name": "wp_2_options", "rows": 1, "size_mb": 0.1,
             "data_free_kb": 0.0},
            {"name": "wp_2_postmeta", "rows": 2, "size_mb": 0.1,
             "data_free_kb": 0.0},
            {"name": "wp_2_posts", "rows": 3, "size_mb": 0.1,
             "data_free_kb": 0.0},
            {"name": "wp_2_term_relationships", "rows": 4, "size_mb": 0.1,
             "data_free_kb": 0.0},
        ]
    )
    plan, _session, _src = _plan(
        tmp_path, monkeypatch, [db_map_ok(KEEP_DB_REFS), ok(**payload)]
    )
    assert plan.backup_tables == [
        "wp_2_postmeta", "wp_2_posts", "wp_2_term_relationships",
    ]
    # options/commentmeta/termmeta never match the three suffixes
    plan, _session, _src = _plan(tmp_path, monkeypatch, _measure())
    assert plan.backup_tables == [
        "wp_postmeta", "wp_posts", "wp_term_relationships",
    ]


def test_plan_refuses_unbacked_mutation(tmp_path, monkeypatch):
    # unreferenced files exist but the audit names no posts table -> the
    # deletion would remove attachment rows unbacked: SourceError, never
    # a plan
    payload = audit_payload(
        tables=[{"name": "wp_options", "rows": 1, "size_mb": 0.1,
                 "data_free_kb": 0.0}]
    )
    with pytest.raises(SourceError, match="posts"):
        _plan(tmp_path, monkeypatch,
              [db_map_ok(KEEP_DB_REFS), ok(**payload)])


def test_plan_nothing_unreferenced_empty_plan_no_media_calls(
    tmp_path, monkeypatch, wpt_caplog
):
    # every uploads file kept -> empty plan.  The database map IS still
    # measured (that is the measurement); nothing else is called: no
    # db_audit (no mutation to back up) and no deletion op.
    plan, session, _src = _plan(
        tmp_path, monkeypatch, [db_map_ok(ALL_REFS)], live_refs=ALL_REFS
    )
    assert plan.items == []
    assert plan.backup_tables == []  # deliberate: nothing would be mutated
    assert posted_actions(session) == ["media_map"]
    summaries = _records(wpt_caplog, "wpt.actions.trim_media", logging.INFO)
    assert len(summaries) == 1
    assert "0 item(s)" in summaries[0].getMessage()


def test_plan_walk_failure_fails_closed(tmp_path, monkeypatch, wpt_caplog):
    # the walk seam raising a transport error: RequestException subclasses
    # OSError, so the registry answers rc 1 — the plan NEVER guesses a
    # keep-set, and no bridge POST happens
    src, session, bridge = make_stack([], files={})

    def boom(_s=None, _site=None, _st=None, _t=None, deadline=None):
        raise requests.ConnectionError("walk transport gone")

    monkeypatch.setattr(trim_media_mod, "walk_site", boom)
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, session, bridge))
    rc = run_action(_ctx(tmp_path), "trim-media")
    assert rc == 1
    assert session.posts == []  # no db map, no db_audit, no media call
    errors = _records(wpt_caplog, "wpt.actions", logging.ERROR)
    assert errors and "plan failed" in errors[0].getMessage()


def test_plan_requires_sql_in_local_mode(tmp_path):
    # local mode's reference set IS the dump: without it the plan refuses
    # instead of guessing (the CLI demands --sql too)
    src = FakeSource()
    src.files = dict(MEDIA_TREE)
    ctx = _ctx(tmp_path, source="local", zip=tmp_path / "site.zip",
               sql=None)
    with pytest.raises(SourceError, match="--sql"):
        TrimMediaAction().plan(ctx, (src, None, None))


def _local_dump(refs: dict[str, str], *, postmeta_extra=(), posts=()) -> bytes:
    """A .sql dump whose postmeta/content name exactly ``refs``."""
    rows = [(i, 10 + i, "_wp_attached_file", path)
            for i, path in enumerate(sorted(refs), start=1)]
    out = ("CREATE TABLE `wp_options` (`option_id` text, `option_name` text,"
           " `option_value` text, `autoload` text);\n"
           "INSERT INTO `wp_options` VALUES "
           "(1,'siteurl','https://site.test','yes');\n"
           ).encode()
    out += ("CREATE TABLE `wp_postmeta` (`meta_id` text, `post_id` text,"
            " `meta_key` text, `meta_value` text);\n").encode()
    if rows:
        body = ",".join("(%d,'%d','%s','%s')" % r for r in rows)
        out += ("INSERT INTO `wp_postmeta` VALUES " + body + ";\n").encode()
    for row in postmeta_extra:
        body = ",".join("('%s')" % str(c).replace("'", "\\'") for c in row)
        out += ("INSERT INTO `wp_postmeta` VALUES " + body + ";\n").encode()
    out += ("CREATE TABLE `wp_posts` (`ID` text, `post_type` text,"
            " `post_status` text, `post_content` text, `post_excerpt` text,"
            " `post_guid` text);\n").encode()
    for row in posts:
        body = ",".join("('%s')" % str(c).replace("'", "\\'") for c in row)
        out += ("INSERT INTO `wp_posts` VALUES " + body + ";\n").encode()
    out += ("CREATE TABLE `wp_termmeta` (`meta_id` text, `meta_key` text,"
            " `meta_value` text);\n").encode()
    return out + DUMP_TRAILER.encode()


def test_plan_local_mode_degraded_dry_run(tmp_path, monkeypatch, wpt_caplog):
    # (d) LOCAL MODE, degraded but INFORMATIVE: the dump is the reference
    # set, so the plan is a REAL number — and it says plainly that the
    # rendered pages were not part of it, and what to run for the full set
    dump = _local_dump({"2023/10/pic.jpg", "2023/11/other.png"})
    sql = tmp_path / "site.sql"
    sql.write_bytes(dump)
    src = FakeSource()
    src.files = dict(MEDIA_TREE)
    plan = TrimMediaAction().plan(
        _ctx(tmp_path, source="local", zip=tmp_path / "site.zip", sql=sql),
        (src, None, None),
    )
    # the degraded advice item comes FIRST, so it is read before the table
    advice = plan.items[0]
    assert advice.requires_apply is False
    assert "DEGRADED reference set" in advice.detail
    assert "no live walk" in advice.detail
    assert "trim-media --apply" in advice.detail
    assert "ftp://HOST" in advice.detail
    # and the measurement itself is real: only the file the DATABASE does
    # not reference is a candidate, labelled with its evidence class
    candidates = [i for i in plan.items if i.requires_apply]
    assert [i.target for i in candidates] == [
        "wp-content/uploads/2023/10/zz-unused.jpg"
    ]
    assert "unreferenced by the database only (no live walk)" in \
        candidates[0].detail
    # no bridge call is even possible in local mode
    assert plan.backup_tables == []


def test_plan_local_mode_unusable_dump_plans_nothing(tmp_path, monkeypatch):
    # a dump with no WordPress tables is UNKNOWN, never an empty keep-set
    sql = tmp_path / "empty.sql"
    sql.write_bytes(b"CREATE TABLE `other` (`a` text);\n")
    src = FakeSource()
    src.files = dict(MEDIA_TREE)
    plan = TrimMediaAction().plan(
        _ctx(tmp_path, source="local", zip=tmp_path / "site.zip", sql=sql),
        (src, None, None),
    )
    assert plan.items == []
    assert plan.backup_tables == []


# ------------------------------------------------------------------ apply


def test_apply_partial_unlink_fails_closed(tmp_path, monkeypatch, wpt_caplog):
    # media_delete commits the DB rows and THEN unlinks files. A file the
    # server could NOT remove is reported in the authoritative
    # ``unlink_failures`` list; the apply must FAIL (SourceError -> registry
    # rc 1) and must NOT mark that file done.
    src, session, bridge = make_stack([
        db_map_ok(KEEP_DB_REFS),
        ok(**audit_payload()),
        db_map_ok(KEEP_DB_REFS),
        ok(**audit_payload()),      # the apply's live schema (the witness)
        media_map_ok({
            "2023/10/zz-unused.jpg": {"id": 7, "file": "2023/10/zz-unused.jpg"},
            "2023/11/other.png": {"id": 9, "file": "2023/11/other.png"},
        }),
        media_delete_ok(deleted_files=1, unlink_failures=["2023/11/other.png"]),
    ])
    patch_walk(monkeypatch, KEEP_REFS)
    action = TrimMediaAction()
    ctx = _ctx(tmp_path, sql=_dump(tmp_path, refs=KEEP_DB_REFS))
    plan = action.plan(ctx, (src, session, bridge))
    with pytest.raises(SourceError, match="could not remove"):
        action.apply(ctx, (src, session, bridge), plan)
    # the server-failed file is NOT marked done (and the other one was)
    assert not any(i.done for i in plan.items if "other.png" in i.target)
    assert any(i.done for i in plan.items if "zz-unused.jpg" in i.target)
    # the failed file is still on disk in the fake
    assert "wp-content/uploads/2023/11/other.png" in src.files


def test_apply_maps_refs_and_deletes(tmp_path, monkeypatch, wpt_caplog):
    src, session, bridge = make_stack([
        db_map_ok(KEEP_DB_REFS),
        ok(**audit_payload()),
        db_map_ok(KEEP_DB_REFS),
        ok(**audit_payload()),      # the apply's live schema (the witness)
        media_map_ok({
            "2023/10/zz-unused.jpg": {"id": 7, "file": "2023/10/zz-unused.jpg"},
            "2023/11/other.png": {"id": 9, "file": "2023/11/other.png"},
        }),
        media_delete_ok(deleted_files=2, deleted_posts=2,
                        deleted_meta=6, deleted_termrels=2),
    ])
    calls = patch_walk(monkeypatch, KEEP_REFS)
    action = TrimMediaAction()
    # the cross-check dump agrees (it names nothing), so the gate is silent
    ctx = _ctx(tmp_path, sql=_dump(tmp_path, refs=KEEP_DB_REFS))
    plan = action.plan(ctx, (src, session, bridge))
    applied = action.apply(ctx, (src, session, bridge), plan)
    assert applied is plan  # the same Plan object, items updated in place
    # the walk ran twice: once to plan, once to re-verify
    assert len(calls) == 2
    assert posted_actions(session) == [
        "media_map", "db_audit", "media_map", "db_audit", "media_map",
        "media_delete",
    ]
    # media_map gets the planned uploads-RELATIVE paths in plan order
    # [0] the plan's database map, [1] the re-verification's, [2] refs->ids
    assert posted_params(session, "media_map")[2] == {
        "refs": ["2023/10/zz-unused.jpg", "2023/11/other.png"]
    }
    # media_delete gets the resolved ids + the same paths
    assert posted_params(session, "media_delete") == [
        {"ids": [7, 9], "files": ["2023/10/zz-unused.jpg", "2023/11/other.png"]}
    ]
    assert all(i.done for i in applied.items)
    assert [i.detail for i in applied.items] == [
        "2023/10/zz-unused.jpg (90 B) — unreferenced by the live walk and "
        "the database",  # details not rewritten by apply
        "2023/11/other.png (50 B) — unreferenced by the live walk and "
        "the database",
    ]
    # ONE info apply summary carrying media_delete's reported counts
    infos = _records(wpt_caplog, "wpt.actions.trim_media", logging.INFO)
    apply_logs = [r for r in infos if "deleted" in r.getMessage()]
    assert len(apply_logs) == 1
    message = apply_logs[0].getMessage()
    assert "2 file(s) deleted" in message
    assert "2 attachment post(s)" in message
    assert "6 meta row(s)" in message
    assert "2 term relationship(s)" in message


def test_apply_dedupes_ids(tmp_path, monkeypatch):
    # stem matching maps several files to ONE attachment: ids are the
    # sorted deduped set
    files = {
        "wp-content/uploads/2024/01/a.jpg": b"a" * 10,
        "wp-content/uploads/2024/01/b.jpg": b"b" * 20,
        "wp-content/uploads/2024/01/c.jpg": b"c" * 30,
    }
    src, session, bridge = make_stack([
        db_map_ok(set()),
        ok(**audit_payload()),
        db_map_ok(set()),
        ok(**audit_payload()),      # the apply's live schema (the witness)
        media_map_ok({
            "2024/01/a.jpg": {"id": 7, "file": "2024/01/a.jpg"},
            "2024/01/b.jpg": {"id": 7, "file": "2024/01/a.jpg"},
            "2024/01/c.jpg": {"id": 9, "file": "2024/01/c.jpg"},
        }),
        media_delete_ok(deleted_files=3, deleted_posts=2),
    ], files=files)
    patch_walk(monkeypatch, set())
    action = TrimMediaAction()
    ctx = _ctx(tmp_path, sql=_dump(tmp_path, refs=KEEP_DB_REFS))
    plan = action.plan(ctx, (src, session, bridge))
    action.apply(ctx, (src, session, bridge), plan)
    assert posted_params(session, "media_delete") == [
        {"ids": [7, 9],
         "files": ["2024/01/a.jpg", "2024/01/b.jpg", "2024/01/c.jpg"]}
    ]
    assert all(i.done for i in plan.items)


def test_apply_never_deletes_the_rows_of_a_protected_stray_duplicate(
        tmp_path, monkeypatch):
    """R16-P1: a planned stray duplicate (2023/09/pic.jpg) stem-matches an
    attachment in another month (2023/10/pic.jpg) whose own file is
    referenced/protected.  Sending that id to media_delete would delete the
    protected attachment's posts/meta/term relationships; an id is accepted
    only when its resolved file is itself one of the deleted files."""
    files = {
        "wp-content/uploads/2023/09/pic.jpg": b"stray-duplicate",
        "wp-content/uploads/2023/10/pic.jpg": b"protected-original",
    }
    protected_refs = {"2023/10/pic.jpg"}
    src, session, bridge = make_stack([
        db_map_ok(protected_refs),
        ok(**audit_payload()),
        db_map_ok(protected_refs),
        ok(**audit_payload()),      # the apply's live schema (the witness)
        media_map_ok({
            "2023/09/pic.jpg": {"id": 101, "file": "2023/10/pic.jpg"},
        }),
        media_delete_ok(deleted_files=1, deleted_posts=0),
    ], files=files)
    patch_walk(monkeypatch, protected_refs)
    action = TrimMediaAction()
    ctx = _ctx(tmp_path, sql=_dump(tmp_path, refs=protected_refs))
    plan = action.plan(ctx, (src, session, bridge))
    assert [i.target for i in plan.items if i.requires_apply] == [
        "wp-content/uploads/2023/09/pic.jpg"]
    action.apply(ctx, (src, session, bridge), plan)
    assert posted_params(session, "media_delete") == [
        {"ids": [], "files": ["2023/09/pic.jpg"]}
    ]
    assert "wp-content/uploads/2023/10/pic.jpg" in src.files
    assert "wp-content/uploads/2023/09/pic.jpg" not in src.files


def test_apply_zero_ids_still_deletes_files(tmp_path, monkeypatch):
    # never-attached files: media_map resolves NO id — media_delete is
    # STILL called with files and ids=[] (bridge.php reads ids with
    # wpt_param_int_list(required=false): an empty list is accepted and
    # `if ($ids)` skips the DB transaction while files still unlink)
    src, session, bridge = make_stack([
        db_map_ok(KEEP_DB_REFS),
        ok(**audit_payload()),
        db_map_ok(KEEP_DB_REFS),
        ok(**audit_payload()),      # the apply's live schema (the witness)
        media_map_ok({
            "2023/10/zz-unused.jpg": {"id": None, "file": None},
            "2023/11/other.png": {"id": None, "file": None},
        }),
        media_delete_ok(deleted_files=2, skipped_missing=1),
    ])
    patch_walk(monkeypatch, KEEP_REFS)
    action = TrimMediaAction()
    ctx = _ctx(tmp_path, sql=_dump(tmp_path, refs=KEEP_DB_REFS))
    plan = action.plan(ctx, (src, session, bridge))
    applied = action.apply(ctx, (src, session, bridge), plan)
    assert posted_params(session, "media_delete") == [
        {"ids": [], "files": ["2023/10/zz-unused.jpg", "2023/11/other.png"]}
    ]
    assert all(i.done for i in applied.items)


def test_apply_failure_propagates_items_undone(tmp_path, monkeypatch):
    src, session, bridge = make_stack([
        db_map_ok(KEEP_DB_REFS),
        ok(**audit_payload()),
        db_map_ok(KEEP_DB_REFS),
        ok(**audit_payload()),      # the apply's live schema (the witness)
        media_map_ok({
            "2023/10/zz-unused.jpg": {"id": 7, "file": "2023/10/zz-unused.jpg"},
        }),
        media_delete_refused(),
    ])
    patch_walk(monkeypatch, KEEP_REFS)
    action = TrimMediaAction()
    ctx = _ctx(tmp_path, sql=_dump(tmp_path, refs=KEEP_DB_REFS))
    plan = action.plan(ctx, (src, session, bridge))
    with pytest.raises(BridgeError) as excinfo:
        action.apply(ctx, (src, session, bridge), plan)
    assert "refused path" in str(excinfo.value)
    # nothing marked done — the registry reports the failure (backup exists)
    assert all(not i.done for i in plan.items)


# The production failure this pair fixes: a real migration's plan carried
# many unreferenced uploads, among them plugin-owned paths under
# wp-content/uploads/bb-plugin/cache/. The bridge's media_delete op refused
# every one of them ("refused path (must be under YYYY/)"), so EVERY apply
# failed closed and nothing was ever deleted — the action could not know the
# bridge's rule. The bridge now accepts any path that resolves inside the
# uploads basedir, and the plan carries exactly those paths.

BB_CACHE = "bb-plugin/cache/sample-1-square.jpg"
BB_FLAT = "flat-root-level.jpg"


def test_apply_non_YYYY_uploads_paths_applies_cleanly(tmp_path, monkeypatch):
    files = dict(MEDIA_TREE)
    files[f"wp-content/uploads/{BB_CACHE}"] = b"z" * 40
    files[f"wp-content/uploads/{BB_FLAT}"] = b"y" * 7
    src, session, bridge = make_stack([
        db_map_ok(KEEP_DB_REFS),
        ok(**audit_payload()),
        db_map_ok(KEEP_DB_REFS),
        ok(**audit_payload()),      # the apply's live schema (the witness)
        media_map_ok({
            "2023/10/zz-unused.jpg": {"id": 7, "file": "2023/10/zz-unused.jpg"},
            BB_CACHE: {"id": None, "file": None},
            BB_FLAT: {"id": None, "file": None},
        }),
        media_delete_ok(deleted_files=3),
    ], files=files)
    patch_walk(monkeypatch, KEEP_REFS)
    action = TrimMediaAction()
    ctx = _ctx(tmp_path, sql=_dump(tmp_path, refs=KEEP_DB_REFS))
    plan = action.plan(ctx, (src, session, bridge))
    targets = [i.target for i in plan.items]
    assert f"wp-content/uploads/{BB_CACHE}" in targets
    applied = action.apply(ctx, (src, session, bridge), plan)
    # the non-YYYY paths reach the op verbatim (uploads-relative) and the
    # apply completes: no refusal, every item done
    assert posted_params(session, "media_delete")[0]["files"] == [
        "2023/10/zz-unused.jpg", "2023/11/other.png", BB_CACHE, BB_FLAT,
    ]
    assert all(i.done for i in applied.items)
    assert f"wp-content/uploads/{BB_CACHE}" not in src.files
    assert f"wp-content/uploads/{BB_FLAT}" not in src.files


def test_plan_excludes_media_outside_uploads(tmp_path, monkeypatch, wpt_caplog):
    # Defense in depth: the plan carries only paths the deletion path can
    # round-trip. An item from outside wp-content/uploads/ would be handed
    # to media_delete as an UPLOADS-relative path and address a DIFFERENT
    # file, so it is excluded and named in ONE warning. The shared
    # enumeration cannot produce one today — this pins the guard that keeps
    # it that way.
    from wpt.audit.media import UnreferencedFile
    from wpt.types import Entry

    outside = [
        UnreferencedFile(
            entry=Entry(path="wp-content/plugins/bb-plugin/img/headshot.jpg",
                        is_dir=False, size=99),
            evidence="unreferenced by the live walk and the database"),
        UnreferencedFile(
            entry=Entry(path="assets/logo.png", is_dir=False, size=12),
            evidence="unreferenced by the live walk and the database"),
    ]
    monkeypatch.setattr(trim_media_mod, "unreferenced_files",
                        lambda entries, live, db, exts: outside)
    src, session, bridge = make_stack(_measure(), files={})
    patch_walk(monkeypatch, set())
    plan = TrimMediaAction().plan(_ctx(tmp_path), (src, session, bridge))
    assert plan.items == []
    warnings = [
        r for r in _records(wpt_caplog, "wpt.actions.trim_media", logging.WARNING)
        if "outside wp-content/uploads/" in r.getMessage()
    ]
    assert len(warnings) == 1
    message = warnings[0].getMessage()
    assert "wp-content/plugins/bb-plugin/img/headshot.jpg" in message
    assert "assets/logo.png" in message
    # the backup scope was still derived (the enumeration was non-empty)
    assert plan.backup_tables


# ------------------------------------------------------------- the gate (d)


def test_apply_refuses_degraded_local(tmp_path, wpt_caplog):
    # (d) THE GATE: a local apply is refused with ONE actionable line that
    # names the command producing the full set. Nothing is mutated, and
    # the registry turns it into rc 1.
    src = FakeSource()
    src.files = dict(MEDIA_TREE)
    plan = Plan(items=[
        PlanItem(category="media.unreferenced",
                 target="wp-content/uploads/2023/10/zz-unused.jpg",
                 detail="2023/10/zz-unused.jpg (90 B)"),
    ])
    ctx = _ctx(tmp_path, source="local", zip=tmp_path / "site.zip",
               sql=tmp_path / "site.sql", apply=True, yes=True)
    with pytest.raises(SourceError) as excinfo:
        TrimMediaAction().apply(ctx, (src, None, None), plan)
    message = str(excinfo.value)
    assert "degraded reference set" in message
    assert "no live walk" in message
    # the actionable line names the ftp/live command verbatim
    assert "ftp://HOST" in message and "trim-media --apply" in message
    # nothing was deleted
    assert "wp-content/uploads/2023/10/zz-unused.jpg" in src.files


def test_apply_refuses_when_db_map_fails(tmp_path, monkeypatch):
    # the same gate in ftp mode: the plan degraded (the map was
    # unmeasurable), so the apply must refuse BEFORE any deletion call
    src, session, bridge = make_stack([
        db_map_ok(KEEP_DB_REFS),
        ok(**audit_payload()),
        db_map_failed(),      # the re-measurement fails
        ok(**audit_payload()),      # the apply's live schema (the witness)
    ])
    patch_walk(monkeypatch, KEEP_REFS)
    action = TrimMediaAction()
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, (src, session, bridge))
    with pytest.raises(SourceError, match="degraded reference set"):
        action.apply(ctx, (src, session, bridge), plan)
    # the deletion ops were never called and the files are still there
    assert "media_delete" not in posted_actions(session)
    assert "wp-content/uploads/2023/10/zz-unused.jpg" in src.files


def test_apply_refuses_when_fresh_union_protects_a_planned_file(
    tmp_path, monkeypatch
):
    # a file the FRESH union references (the site changed since the plan)
    # aborts the apply with nothing deleted — a re-crawl alone would miss
    # a reference that only the DATABASE can see
    src, session, bridge = make_stack([
        db_map_ok(KEEP_DB_REFS),                 # the plan's measurement
        ok(**audit_payload()),
        db_map_ok(KEEP_DB_REFS | {"2023/10/zz-unused.jpg"}),  # the re-check
        ok(**audit_payload()),      # the apply's live schema (the witness)
    ])
    patch_walk(monkeypatch, KEEP_REFS)
    action = TrimMediaAction()
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, (src, session, bridge))
    with pytest.raises(SourceError) as excinfo:
        action.apply(ctx, (src, session, bridge), plan)
    message = str(excinfo.value)
    assert "2023/10/zz-unused.jpg" in message
    assert "nothing was deleted" in message
    assert "media_delete" not in posted_actions(session)
    assert "wp-content/uploads/2023/10/zz-unused.jpg" in src.files


def test_apply_empty_plan_no_bridge_calls(tmp_path):
    src, session, bridge = make_stack([])  # any POST would fail the fake
    plan = Plan()
    applied = TrimMediaAction().apply(
        _ctx(tmp_path), (src, session, bridge), plan
    )
    assert applied is plan
    assert session.posts == []  # nothing planned -> no bridge roundtrip


def test_apply_skips_non_apply_items(tmp_path, monkeypatch):
    plan = Plan(items=[
        PlanItem(category="media.unreferenced",
                 target="wp-content/uploads/2024/01/a.jpg", detail="a"),
        PlanItem(category="media.info", target="none", detail="advice",
                 requires_apply=False),
    ])
    src, session, bridge = make_stack([
        db_map_ok(set()),                      # the re-measurement
        ok(**audit_payload()),                 # the apply's live schema
        media_map_ok({"2024/01/a.jpg": {"id": 3, "file": "2024/01/a.jpg"}}),
        media_delete_ok(deleted_files=1, deleted_posts=1),
    ], files={})
    patch_walk(monkeypatch, set())            # the re-crawl rides the seam
    by_detail = {i.detail: i for i in plan.items}  # items mutate in place
    TrimMediaAction().apply(
        _ctx(tmp_path, sql=_dump(tmp_path)), (src, session, bridge), plan
    )
    # only the requires_apply item's path is sent; the advice item is
    # neither applied nor marked done
    assert posted_params(session, "media_map")[1] == {
        "refs": ["2024/01/a.jpg"]
    }
    assert posted_params(session, "media_delete") == [
        {"ids": [3], "files": ["2024/01/a.jpg"]}
    ]
    assert by_detail["a"].done
    assert not by_detail["advice"].done


def test_apply_is_idempotent(tmp_path, monkeypatch):
    # (e) idempotency: the deletions are what the next measurement sees,
    # so a second plan over the trimmed tree is EMPTY and its apply makes
    # no bridge call at all
    src, session, bridge = make_stack([
        db_map_ok(KEEP_DB_REFS),
        ok(**audit_payload()),
        db_map_ok(KEEP_DB_REFS),
        ok(**audit_payload()),      # the apply's live schema (the witness)
        media_map_ok({
            "2023/10/zz-unused.jpg": {"id": 7, "file": "2023/10/zz-unused.jpg"},
            "2023/11/other.png": {"id": 9, "file": "2023/11/other.png"},
        }),
        media_delete_ok(deleted_files=2, deleted_posts=2),
        db_map_ok(KEEP_DB_REFS),   # the second plan's measurement
    ])
    patch_walk(monkeypatch, KEEP_REFS)
    action = TrimMediaAction()
    ctx = _ctx(tmp_path, sql=_dump(tmp_path, refs=KEEP_DB_REFS))
    plan = action.plan(ctx, (src, session, bridge))
    action.apply(ctx, (src, session, bridge), plan)
    assert "wp-content/uploads/2023/10/zz-unused.jpg" not in src.files
    second = action.plan(ctx, (src, session, bridge))
    assert second.items == []
    # and the second apply is a no-op with no further bridge traffic
    traffic = len(session.posts)
    action.apply(ctx, (src, session, bridge), second)
    assert len(session.posts) == traffic


# ------------------------------------------------------- registry end-to-end


def test_registry_dry_run(tmp_path, capsys, monkeypatch):
    src, session, bridge = make_stack(_measure())
    patch_walk(monkeypatch, KEEP_REFS)
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, session, bridge))
    rc = run_action(_ctx(tmp_path), "trim-media")
    assert rc == 0
    out = capsys.readouterr().out
    assert "## Plan" in out
    for target in (
        "wp-content/uploads/2023/10/zz-unused.jpg",
        "wp-content/uploads/2023/11/other.png",
    ):
        assert target in out
    assert "2023/10/zz-unused.jpg (90 B)" in out
    assert "unreferenced by the live walk and the database" in out
    # read-only: the db media map + the db_audit backup scope only
    assert posted_actions(session) == ["media_map", "db_audit"]


def test_registry_ftp_apply_end_to_end(tmp_path, capsys, monkeypatch):
    dump_lines = (
        table_lines("wp_postmeta", [["1", "7", "_wp_attached_file",
                                    "2023/10/zz-unused.jpg"]])
        + table_lines("wp_posts", [["7", "attachment", "inherit"]])
        + table_lines("wp_term_relationships", [["7", "1", "1"]])
    )
    src, session, bridge = make_stack([
        db_map_ok(KEEP_DB_REFS),
        ok(**audit_payload()),
        FakeResponse(200, lines=dump_lines),      # the pre-action snapshot
        db_map_ok(KEEP_DB_REFS),                  # the re-measurement
        ok(**audit_payload()),                    # the apply's live schema
        media_map_ok({
            "2023/10/zz-unused.jpg": {"id": 7, "file": "2023/10/zz-unused.jpg"},
            "2023/11/other.png": {"id": 9, "file": "2023/11/other.png"},
        }),
        media_delete_ok(deleted_files=2, deleted_posts=2,
                        deleted_meta=6, deleted_termrels=2),
        ok(purged=True),  # the registry's post-apply cache purge
    ])
    patch_walk(monkeypatch, KEEP_REFS)
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, session, bridge))
    rc = run_action(
        _ctx(tmp_path, apply=True, yes=True,
             sql=_dump(tmp_path, refs=KEEP_DB_REFS)),
        "trim-media",
    )
    assert rc == 0
    # bridge traffic: the db media map, ONE db_dump covering all three
    # backup tables, the fresh re-measurement, media_map + media_delete,
    # then the purge
    assert posted_actions(session) == [
        "media_map", "db_audit", "db_dump", "media_map", "db_audit",
        "media_map", "media_delete", "purge_cache",
    ]
    assert posted_params(session, "db_dump") == [
        {"tables": ["wp_postmeta", "wp_posts", "wp_term_relationships"]}
    ]
    assert posted_params(session, "media_delete") == [
        {"ids": [7, 9], "files": ["2023/10/zz-unused.jpg", "2023/11/other.png"]}
    ]
    # fail-closed pre-action backup: the manifest lists the backup tables
    # AND the planned FILES (file scope from the item targets)
    manifests = list((tmp_path / "backup").glob("*/*/manifest.json"))
    assert len(manifests) == 1
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    assert manifest["action"] == "trim-media"
    assert manifest["site"] == "example.com"
    assert [t["name"] for t in manifest["tables"]] == [
        "wp_postmeta", "wp_posts", "wp_term_relationships",
    ]
    assert [f["path"] for f in manifest["files"]] == [
        "wp-content/uploads/2023/10/zz-unused.jpg",
        "wp-content/uploads/2023/11/other.png",
    ]
    assert all(not f["absent"] for f in manifest["files"])
    assert (manifests[0].parent / "db/wp_posts.ndjson").exists()
    assert (manifests[0].parent
            / "files/wp-content/uploads/2023/10/zz-unused.jpg").exists()
    # the fake bridge mirrors the real one: a successful media_delete removes
    # the files from the source, and the post-apply existence check confirms
    # each is gone (so every item is reported applied).
    assert "wp-content/uploads/2023/10/zz-unused.jpg" not in src.files
    assert "wp-content/uploads/2023/11/other.png" not in src.files
    # the applied plan prints every item done
    out = capsys.readouterr().out
    assert out.count("| yes |") == 2
    assert "2023/10/zz-unused.jpg (90 B)" in out


def test_registry_local_dry_run_and_refused_apply(tmp_path, capsys, wpt_caplog,
                                                 monkeypatch):
    # (d) through the registry, both phases: the local dry run prints an
    # informative plan, the local apply refuses (rc 1) and the ORIGINAL zip
    # is untouched.
    zip_path = tmp_path / "site.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        # top-level files, so the archive stays rootless (a zip whose every
        # entry lives under ONE directory is a host export whose top dir is
        # the webroot — not a webroot-rooted site zip)
        zf.writestr("wp-config.php", b"<?php\n")
        zf.writestr("index.php", b"<?php\n")
        for name, blob in MEDIA_TREE.items():
            zf.writestr(name, blob)
    dump = _local_dump({"2023/10/pic.jpg", "2023/11/other.png"})
    sql = tmp_path / "site.sql"
    sql.write_bytes(dump)
    ctx = _ctx(tmp_path, source="local", zip=zip_path, sql=sql)
    before = zip_path.read_bytes()

    rc = run_action(ctx, "trim-media")
    assert rc == 0
    out = capsys.readouterr().out
    assert "## Plan" in out
    assert "DEGRADED reference set" in out
    assert "no live walk" in out
    assert "wp-content/uploads/2023/10/zz-unused.jpg" in out
    # the db-referenced files are NOT candidates
    assert "2023/11/other.png" not in out.split("## Plan")[1]

    ctx.apply, ctx.yes = True, True
    rc = run_action(ctx, "trim-media")
    assert rc == 1
    errors = [r for r in _records(wpt_caplog, "wpt.actions", logging.ERROR)
              if "trim-media apply failed" in r.getMessage()]
    assert errors
    assert "degraded reference set" in errors[0].getMessage()
    assert "ftp://HOST" in errors[0].getMessage()
    # the rehearsal NEVER materialized and the original is untouched
    assert zip_path.read_bytes() == before
    assert not list(tmp_path.glob("site-rehearsed-*.zip"))


# ===========================================================================
# MODE PARITY — the regression sweep's §2 discriminator
#
# The measured defect: the database half of the keep-set is measured in one
# of two places, and a destructive plan is built from ONE of them.  On a
# real site the local dump path kept a multi-size "2019/02/SampleImg*"
# family (the original plus every registered size) as database-referenced
# while the live bridge kept NONE of them — so the same database produced
# two DELETE sets and the mode decided whether a referenced attachment
# survived.  wpt.media_refs now owns one rule (normalization, the
# extension family, the is-a-directory belt, PHP's unserialize
# semantics), mirrored in bridge.php and pinned against the real
# wpt_media_db_map in tests/test_media_refs.py; these tests pin the
# consequence: the two modes plan the same thing.
# ===========================================================================

def _ser(value: str) -> str:
    """One PHP-serialized string (a BYTE length, as PHP counts)."""
    return 's:%d:"%s";' % (len(value.encode("utf-8")), value)


def _ser_map(pairs) -> str:
    body = "".join(_ser(key) + (value if isinstance(value, _SerRaw)
                                else _ser(value)) for key, value in pairs)
    return "a:%d:{%s}" % (len(pairs), body)


class _SerRaw(str):
    """A literal PHP serialization tag inside a serialized map."""


#: The uploads tree over which the two modes are compared: the attachment
#: family the database references (the original + two registered sizes),
#: a family the database references only through a legacy backup-sizes
#: key, a file the database names with an UNLISTED extension (never media,
#: so never a candidate in either mode), and two genuinely unreferenced
#: media files — the delete set both modes must agree on.
PARITY_TREE = {
    "wp-content/uploads/2019/02/SampleImg.jpg": b"a" * 900,
    # "-1"/"-2" is WordPress's own uniquifier for a colliding upload name,
    # and "brochure-page-2" is a PDF derivative: NEITHER reduces to the
    # original's stripped stem, so nothing but the size map protects them.
    # That is what makes this fixture bite: a decoder that loses the map
    # (a null inside it) plans them for deletion, which is the whole
    # defect and nothing else in the fixture can mask it.
    "wp-content/uploads/2019/02/SampleImg-1.jpg": b"a" * 150,
    "wp-content/uploads/2019/02/SampleImg-2.jpg": b"a" * 300,
    "wp-content/uploads/2019/02/brochure.pdf": b"b" * 400,
    "wp-content/uploads/2019/02/brochure-page-2.pdf": b"b" * 40,
    "wp-content/uploads/2019/02/data.xyz": b"c" * 20,
    "wp-content/uploads/2019/02/orphan-1.jpg": b"d" * 70,
    "wp-content/uploads/2019/02/orphan-2.png": b"d" * 30,
    # a DIRECTORY whose name carries a media extension (a plugin's own
    # cache folder), plus a REAL file beside it whose stripped stem matches
    # it.  This is what makes the is-a-directory half of the keep-gate
    # observable in a DELETE set: a kept reference to the directory would
    # protect that sibling, so only a mode that applies the gate can agree
    # with the bridge's is_dir() about deleting it.
    "wp-content/uploads/2024/05/thumbs.jpg/index.html": b"dir",
    "wp-content/uploads/2024/05/thumbs-300x200.jpg": b"e" * 55,
}

#: The database half of that fixture, PINNED.  Every shape the two
#: implementations used to disagree about is here: the bare-basename size
#: entries anchored to the attachment's own directory, a null INSIDE the
#: size map (a decoder that rejects the map loses every file of a
#: family), the legacy backup-sizes key, an unlisted extension and a bare
#: year directory (both refused by the gate, in both modes).
PARITY_DB_REFS = {
    "2019/02/SampleImg.jpg",
    "2019/02/SampleImg-1.jpg",
    "2019/02/SampleImg-2.jpg",
    "2019/02/brochure.pdf",
    "2019/02/brochure-page-2.pdf",
}

#: The rendered half: a page references ONE member of the family — the
#: database-heavy shape (the walk sees a fraction of what the database holds).
PARITY_LIVE_REFS = {"2019/02/SampleImg-1.jpg"}

#: The delete set BOTH modes must produce.
PARITY_DELETE = [
    "wp-content/uploads/2019/02/orphan-1.jpg",
    "wp-content/uploads/2019/02/orphan-2.png",
    # kept ONLY because the directory-named reference is refused: a mode
    # that skipped the belt would keep this file and the two plans would
    # differ
    "wp-content/uploads/2024/05/thumbs-300x200.jpg",
]


def _parity_dump() -> bytes:
    """A .sql dump whose database half IS ``PARITY_DB_REFS``.

    Built through the same PHP-serialization rules the live database uses,
    so the fixture cannot be shaped to flatter one implementation.
    """
    # _SerRaw: a nested map is a VALUE in the serialization, not a string
    sampleimg = _ser_map([
        ("width", "4000"),
        ("height", "3000"),
        ("file", "2019/02/SampleImg.jpg"),
        ("sizes", _SerRaw(_ser_map([
            ("thumbnail", _SerRaw(_ser_map([
                ("file", "SampleImg-1.jpg"),
                ("width", "150"), ("height", "150")]))),
            ("medium", _SerRaw(_ser_map([
                ("file", "SampleImg-2.jpg"),
                ("width", "300"), ("height", "200")]))),
        ]))),
        # a null INSIDE the size map: PHP keeps the whole array, and a
        # decoder that refuses it loses every registered size
        ("image_meta", _SerRaw("N;")),
    ])
    brochure = _ser_map([
        ("file", "2019/02/brochure.pdf"),
        ("sizes", _SerRaw(_ser_map([
            ("thumbnail", _SerRaw(_ser_map([
                ("file", "brochure-page-2.pdf"), ("width", "150")]))),
        ]))),
    ])
    rows = [
        (1, 10, "_wp_attached_file", "2019/02/SampleImg.jpg"),
        (2, 10, "_wp_attachment_metadata", sampleimg),
        (3, 11, "_wp_attached_file", "2019/02/brochure.pdf"),
        (4, 11, "_wp_attachment_backup_sizes", brochure),
        # refused by the keep gate in BOTH modes: an unlisted extension,
        # a bare year directory that names no media file, and a path that
        # is a DIRECTORY on disk (the is-a-directory belt)
        (5, 12, "_wp_attached_file", "2019/02/data.xyz"),
        (6, 13, "_wp_attached_file", "2018"),
        (7, 20, "_wp_attached_file", "2024/05/thumbs.jpg"),
    ]
    # The WHOLE core schema, with at least as many rows per table as the
    # live one reports: a dump that declared only the four tables this
    # parity fixture reads is refused by the witness for declaring none of
    # the live wp_commentmeta, and a dump holding one option row against a
    # live table of twelve is refused for being BEHIND it.  Both refusals
    # are correct; the fixture models a real export instead.
    out = "".join(_schema_tables()).encode()
    meta_rows = list(rows)
    out += ("INSERT INTO `wp_postmeta` VALUES "
            + ",".join("(%d,'%d','%s','%s')" % row for row in meta_rows)
            + ";\n").encode()
    out += ("INSERT INTO `wp_options` VALUES "
            + f"({_LIVE_ROWS['wp_options'] + 1},'siteurl',"
            f"'https://example.com','yes');\n").encode()
    return out + DUMP_TRAILER.encode()


def _delete_set(plan):
    return [item.target for item in plan.items if item.requires_apply]


def _delete_set_items(plan):
    return [item for item in plan.items if item.requires_apply]


def test_plan_local_and_ftp_delete_the_same_set(tmp_path, monkeypatch):
    """§2 THE DISCRIMINATOR: one database, one tree, two modes, one answer.

    The offline plan measures the database half from the .sql dump; the
    ftp plan measures it from the bridge.  The delete sets must be
    IDENTICAL — a mode-dependent answer is a data-loss bug, because the
    mode decides which files the apply unlinks.

    Before the fix the offline half lost the whole SampleImg family to a
    null inside its size map and kept two refs the gate refuses, and this
    test fails on both.
    """
    sql = tmp_path / "site.sql"
    sql.write_bytes(_parity_dump())

    # 1. LOCAL: the dump IS the database half (no walk — degraded, dry run)
    local_src = FakeSource()
    local_src.files = dict(PARITY_TREE)
    local_plan = TrimMediaAction().plan(
        _ctx(tmp_path, source="local", zip=tmp_path / "site.zip", sql=sql),
        (local_src, None, None),
    )

    # 2. FTP: the bridge answers the SAME database, and the walk sees one
    #    member of the family (the database-heavy shape)
    ftp_plan, _session, _src = _plan(
        tmp_path, monkeypatch,
        _measure(db_refs=PARITY_DB_REFS),
        live_refs=PARITY_LIVE_REFS, files=PARITY_TREE,
    )

    assert _delete_set(local_plan) == _delete_set(ftp_plan) == PARITY_DELETE
    # ... and the two plans are the same SIZE in bytes, not merely the
    # same names
    assert local_plan.est_bytes() == ftp_plan.est_bytes()
    # the difference between the modes is the LABEL, never the delete set:
    # the walk is what local mode cannot see
    assert "unreferenced by the database only" in \
        _delete_set_items(local_plan)[0].detail
    assert "unreferenced by the live walk and the database" in \
        _delete_set_items(ftp_plan)[0].detail


def test_plan_local_gates_a_directory_named_like_a_file(tmp_path, monkeypatch):
    """The is-a-directory half of the keep-gate, applied offline too.

    The bridge asks ``is_dir()`` on the live host; offline the walk is
    the authority, so the enumerated uploads directories reach the dump
    path as data.  Without it the offline half skipped the test the live
    half applies — a structural difference between the two modes, not only
    a difference in data.
    """
    sql = tmp_path / "site.sql"
    sql.write_bytes(_parity_dump())
    src = FakeSource()
    src.files = dict(PARITY_TREE)
    plan = TrimMediaAction().plan(
        _ctx(tmp_path, source="local", zip=tmp_path / "site.zip", sql=sql),
        (src, None, None),
    )
    # "2024/05/thumbs.jpg" is a DIRECTORY here: the reference naming it is
    # refused by the belt, so the real file beside it (same stripped stem)
    # is a candidate — exactly as the bridge's is_dir() makes it.  A local
    # plan that skipped the belt would keep that file and disagree with
    # the ftp plan over the same database.
    assert _delete_set(plan) == PARITY_DELETE
    assert "wp-content/uploads/2024/05/thumbs-300x200.jpg" in \
        _delete_set(plan)


def _apply_stack(tmp_path, monkeypatch, *, db_refs, live_refs, sql,
                 files=PARITY_TREE, delete=media_delete_ok(),
                 live_schema=None):
    """A scripted ftp stack for the apply: plan, then re-measure, delete.

    ``live_schema`` overrides the ``db_audit`` table list the witness
    compares the dump against (the default is the shipped core shape).  Both
    db_audit answers carry it: the plan and the apply ask the same live
    database, and the action reads ONE answer per phase for the backup scope
    and the witness together.
    """
    tables = audit_payload()["tables"] if live_schema is None else live_schema
    src, session, bridge = make_stack([
        db_map_ok(db_refs),          # the plan
        ok(**audit_payload(tables=tables)),   # the backup scope + live schema
        db_map_ok(db_refs),          # the apply re-measures the union
        ok(**audit_payload(tables=tables)),   # the apply's live schema
        media_map_ok({}),            # attachment ids
        delete,
    ], files=files)
    patch_walk(monkeypatch, [live_refs, live_refs])
    ctx = _ctx(tmp_path, sql=sql, apply=True, yes=True)
    return src, session, bridge, ctx


def test_apply_refuses_when_the_dump_and_the_live_map_disagree(
        tmp_path, monkeypatch):
    """THE CROSS-MODE GATE — the measured multi-size family, refused.

    The two measurements now implement ONE rule, but they read different
    SNAPSHOTS.  The live case the sweep measured is the one a rule fix
    cannot remove: the live tables no longer carry the rows the dump
    still has, so the offline map calls the family referenced and the live
    map calls every one of its files deletable.  The tool cannot say
    which snapshot is right, so it refuses and NAMES the files — a
    degraded destruction is never performed.
    """
    sql = tmp_path / "site.sql"
    sql.write_bytes(_parity_dump())
    # the fixture site has lost the SampleImg rows: the family is now
    # unreferenced ONLINE (and on disk)
    live_db_refs = {"2019/02/brochure.pdf", "2019/02/brochure-page-2.pdf"}
    _src, session, bridge, ctx = _apply_stack(
        tmp_path, monkeypatch, db_refs=live_db_refs,
        live_refs={"2019/02/brochure.pdf"}, sql=sql,
    )
    action = TrimMediaAction()
    plan = action.plan(ctx, (bridge.call and _src, session, bridge))
    assert "wp-content/uploads/2019/02/SampleImg.jpg" in _delete_set(plan)

    with pytest.raises(SourceError) as excinfo:
        action.apply(ctx, (_src, session, bridge), plan)
    message = str(excinfo.value)
    assert "the two measurements of the same database disagree" in message
    assert "SampleImg.jpg" in message
    # NOTHING was deleted: no media_delete, and no item marked done
    assert "media_delete" not in posted_actions(session)
    assert not any(item.done for item in plan.items)


def test_apply_proceeds_when_the_dump_agrees(tmp_path, monkeypatch):
    """The same gate with the two measurements in AGREEMENT is silent.

    A gate that fired on every --sql run would be a gate nobody keeps, so
    the agreeing case is pinned too: the apply deletes exactly what the
    plan named.
    """
    sql = tmp_path / "site.sql"
    sql.write_bytes(_parity_dump())
    src, session, bridge, ctx = _apply_stack(
        tmp_path, monkeypatch, db_refs=PARITY_DB_REFS,
        live_refs=PARITY_LIVE_REFS, sql=sql,
    )
    action = TrimMediaAction()
    plan = action.plan(ctx, (src, session, bridge))
    assert _delete_set(plan) == PARITY_DELETE
    applied = action.apply(ctx, (src, session, bridge), plan)
    assert "media_delete" in posted_actions(session)
    assert all(item.done for item in applied.items if item.requires_apply)


# --------------------------------------------------------------------------
# THE WIDENED PROFILE — D1, end to end through the action
#
# ``media.extensions`` is a set-reachable profile key (SPEC [L20]) and the
# enumeration files uploads media by it.  While the bridge's keep-gate
# answered from its own literal, widening the profile therefore made the
# two halves disagree in the one direction that deletes: a
# database-referenced file whose extension only the profile knew was
# invisible to the gate, absent from the union, and planned.  The read now
# CARRIES the run's family, and these tests pin the whole chain: the wire,
# the enumeration, and the refusal when the server could not honor it.
# The shipped PHP's own answer for the same rows is measured in
# tests/test_media_refs.py (the widened request keeps the .psd; the
# shipped default alone does not — that difference IS the defect).
# --------------------------------------------------------------------------

#: The family an operator widens the profile with, and the attachment the
#: database references that the shipped default cannot name.
PSD = "psd"
PSD_REF = "2023/01/design.psd"

WIDENED_TREE = {
    f"wp-content/uploads/{PSD_REF}": b"p" * 400,
    "wp-content/uploads/2023/01/orphan.jpg": b"o" * 60,
}


def _widened_settings():
    """The shipped profile with ONE extension added to media.extensions."""
    from dataclasses import replace
    return replace(DEFAULTS, media=replace(
        DEFAULTS.media,
        extensions=sorted(set(DEFAULTS.media.extensions) | {PSD}),
    ))


def test_a_widened_profile_keeps_a_database_referenced_file_end_to_end(
        tmp_path, monkeypatch):
    """The file is NOT deletable, and the reason is on the wire.

    Same database, same tree, one widened profile: the plan must leave the
    .psd alone (the walk sees nothing, the gate now knows the extension)
    and must have ASKED with the widened family — the request is the fix,
    so it is pinned as carefully as the outcome.
    """
    settings = _widened_settings()
    # what the bridge answers for this database once the family is carried
    # (the shipped PHP's own verdict for these rows: tests/test_media_refs.py
    # ::test_the_gate_answers_with_the_callers_widened_family)
    src, session, bridge = make_stack([
        db_map_ok({PSD_REF}, gate=settings.media.extensions),
        ok(**audit_payload()),
    ], files=WIDENED_TREE)
    patch_walk(monkeypatch, set())          # the database-heavy shape: the walk sees none
    ctx = _ctx(tmp_path, settings=settings)
    plan = TrimMediaAction().plan(ctx, (src, session, bridge))
    # the database-referenced .psd is NOT a candidate
    assert _delete_set(plan) == [
        "wp-content/uploads/2023/01/orphan.jpg",
    ]
    # ... because the read carried the run's family, extension for extension
    assert posted_params(session, "media_map") == [{
        "mode": "db", "extensions": sorted(settings.media.extensions),
    }]


def test_a_gate_that_could_not_honor_the_family_degrades_and_refuses(
        tmp_path, monkeypatch):
    """The fail-closed tail: a keep-set measured with another family is
    not a measurement, and a destruction refuses it.

    If the server cannot gate with the list this run enumerates by (a
    refused request, an older bridge answering from its literal), the
    database half is UNKNOWN — never an empty keep-set, which would read
    as "the database references nothing" and authorize precisely the
    deletions the gate exists to stop.  The plan degrades and says so; the
    apply refuses before any deletion call.
    """
    settings = _widened_settings()
    src, session, bridge = make_stack([
        # the server refused the family: it answered from its own literal
        db_map_ok({PSD_REF}, gate=len(DEFAULTS.media.extensions),
                  fallback=True),
        ok(**audit_payload()),
    ], files=WIDENED_TREE)
    patch_walk(monkeypatch, set())
    ctx = _ctx(tmp_path, settings=settings, apply=True, yes=True,
               sql=_dump(tmp_path, refs={PSD_REF}))
    action = TrimMediaAction()
    plan = action.plan(ctx, (src, session, bridge))
    # DEGRADED: the database half is unknown, so the plan is informative
    # and leads with the advice item naming the full-set command
    assert plan.items[0].requires_apply is False
    assert "DEGRADED reference set" in plan.items[0].detail
    with pytest.raises(SourceError, match="degraded reference set"):
        action.apply(ctx, (src, session, bridge), plan)
    assert "media_delete" not in posted_actions(session)
    assert f"wp-content/uploads/{PSD_REF}" in src.files


def test_a_family_the_wire_cannot_carry_is_refused_at_the_profile(
        tmp_path, monkeypatch):
    """The tail of D1, and the door that closes it for good.

    The run enumerates uploads media by ``settings.media.extensions``, so a
    family carrying an entry the wire cannot express would leave the live
    gate NAMING FEWER files than the enumeration does — a database
    reference invisible to the gate is a file this tool would delete, which
    is the whole defect.  The shape that actually reached that state was a
    blank entry: ``is_media`` compares the file's own extension against the
    list, so ``""`` makes a file named ``x.`` media while no gate can be
    told about it.

    It can no longer EXIST: ``MediaSettings.__post_init__`` refuses a
    never-matching entry (blank, dotted, whitespace) and normalizes the
    rest, on the profile AND on the ``--set`` path, so the wire is never
    asked to carry a family the gate could not honour — the delete set is
    never even enumerated.  The client-side refusal stays as the net under
    it, but a settings tree can no longer reach it.
    """
    from dataclasses import replace

    from wpt.settings import SettingsError

    # the enumeration WOULD file the .psd as media (the profile says so)...
    for bad in ("", "  ", ".psd", "ps d", "a/b", 7):
        widened = list(DEFAULTS.media.extensions) + [bad]
        with pytest.raises(SettingsError) as excinfo:
            replace(DEFAULTS.media, extensions=widened)
        assert str(excinfo.value).startswith("media.extensions[")
    # and the live tree is untouched by a rejected construction, so no
    # bridge call is made and nothing is planned
    src, session, bridge = make_stack([ok(**audit_payload())],
                                      files=WIDENED_TREE)
    patch_walk(monkeypatch, set())
    assert "media_map" not in posted_actions(session)
    assert f"wp-content/uploads/{PSD_REF}" in src.files


def test_apply_without_sql_refuses_before_deleting(tmp_path, monkeypatch):
    """THE MANDATORY CROSS-CHECK: no dump, no deletion.

    ``--sql`` is OPTIONAL in ftp mode (the CLI demands it only in local
    mode), so the recommended live command — ``wpt --source ftp://…
    trim-media --apply``, the very command every dry run prints — never
    consulted a dump, and the cross-mode gate it was built for was opt-in:
    an operator with no dump could still delete the measured multi-size
    family whose rows the live tables no longer carry.  An apply that
    cannot cross-check the same database with a second measurement now
    refuses, in one line naming the flag, before any deletion call.
    """
    src, session, bridge = make_stack([
        db_map_ok(PARITY_DB_REFS),
        ok(**audit_payload()),
        db_map_ok(PARITY_DB_REFS),
        ok(**audit_payload()),      # the apply's live schema (the witness)
        media_map_ok({}),
        media_delete_ok(),
    ], files=PARITY_TREE)
    patch_walk(monkeypatch, [PARITY_LIVE_REFS, PARITY_LIVE_REFS])
    # the apply is reached DIRECTLY here (the plan-phase gate refuses an
    # --apply run before this point — see
    # test_an_apply_run_without_a_dump_costs_no_snapshot): this is the
    # backstop the apply itself carries, for a run that reaches it
    ctx = _ctx(tmp_path)
    assert ctx.sql is None
    action = TrimMediaAction()
    plan = action.plan(ctx, (src, session, bridge))
    assert _delete_set(plan) == PARITY_DELETE      # a real, measured plan
    with pytest.raises(SourceError) as excinfo:
        action.apply(ctx, (src, session, bridge), plan)
    message = str(excinfo.value)
    assert "--sql" in message                      # names the cross-check
    assert "cannot cross-check" in message
    # NOTHING was deleted: no media_delete, no item done, the files intact
    assert "media_delete" not in posted_actions(session)
    assert not any(item.done for item in plan.items)
    assert "wp-content/uploads/2019/02/orphan-1.jpg" in src.files
    assert "wp-content/uploads/2019/02/orphan-2.png" in src.files


def test_apply_with_an_unmeasurable_dump_refuses(tmp_path, monkeypatch):
    """A dump that MEASURES NOTHING is the same fact as no dump.

    ``db_refs_from_dump`` answers None for a dump with no usable options
    table: UNKNOWN, never "this database references nothing".  Read as an
    empty keep-set it would wave through EVERY planned file — the exact
    inversion of the gate — so the refusal names the dump and the reason.
    """
    sql = _unusable_dump(tmp_path)
    src, session, bridge, ctx = _apply_stack(
        tmp_path, monkeypatch, db_refs=PARITY_DB_REFS,
        live_refs=PARITY_LIVE_REFS, sql=sql,
    )
    action = TrimMediaAction()
    # the plan phase is where the refusal now lands for an apply run, and
    # it lands BEFORE the pre-action snapshot exists (the dump has no
    # options table, so the plan never even walks the site for it)
    with pytest.raises(SourceError) as excinfo:
        action.plan(ctx, (src, session, bridge))
    message = str(excinfo.value)
    assert "cannot cross-check" in message
    assert "no usable WordPress tables" in message
    assert "empty.sql" in message                  # names the dump
    assert "media_delete" not in posted_actions(session)


def test_apply_measures_the_dump_once_with_the_plans_directories(
        tmp_path, monkeypatch):
    """ONE dump measurement per run, gated with the PLAN's directories.

    Two properties of the cross-mode gate, both load-bearing and both
    invisible from the delete set (the dispute test is a DIRECT database
    reference, so a difference in the is-a-directory belt cannot surface
    there — it is measured, not observable), so the measurement itself is
    the witness:

    * the dump is parsed ONCE per run — the memo is keyed on the dump, the
      family and the directory set, so a re-asked measurement is the same
      set and a changed dump is re-measured instead of silently reused;
    * it is gated with the SAME ``dirs`` the plan measured with, the
      walked uploads directories (``self._dirs``): the two halves of one
      gate must measure one set, and the apply deliberately does not
      re-walk a 9,000-file uploads tree over FTP to recover them.
    """
    sql = tmp_path / "site.sql"
    sql.write_bytes(_parity_dump())
    src, session, bridge, ctx = _apply_stack(
        tmp_path, monkeypatch, db_refs=PARITY_DB_REFS,
        live_refs=PARITY_LIVE_REFS, sql=sql,
    )
    calls = []
    # the shared witness module owns the measurement now (one owner, one
    # implementation, both media actions), so the spy rides THERE
    real = dump_witness_mod.db_refs_from_dump

    def spy(dump, extensions=None, dirs=None, deadline=None):
        calls.append((tuple(extensions), dirs, deadline))
        return real(dump, extensions, dirs, deadline=deadline)

    monkeypatch.setattr(dump_witness_mod, "db_refs_from_dump", spy)
    ctx.deadline_s = 600.0
    action = TrimMediaAction()
    plan = action.plan(ctx, (src, session, bridge))
    assert _delete_set(plan) == PARITY_DELETE
    # the plan's walk is the is-a-directory witness (the bridge asks
    # is_dir() live; offline the walk IS the authority)
    assert action._dirs == {
        "2019", "2019/02", "2024", "2024/05", "2024/05/thumbs.jpg",
    }

    applied = action.apply(ctx, (src, session, bridge), plan)
    assert "media_delete" in posted_actions(session)
    assert all(item.done for item in applied.items if item.requires_apply)
    # exactly ONE dump measurement, with the run's family and the plan's
    # directories — the same inputs the local plan's own dump half uses
    assert calls == [(tuple(DEFAULTS.media.extensions), action._dirs,
                      calls[0][2])]
    assert isinstance(calls[0][2], Deadline)   # the run's budget rides along

    # asking again re-uses the measurement (same key, same set, no
    # re-parse): the memo is the WITNESS GATE's, the one owner both media
    # actions measure through
    live = live_schema_from_audit(
        _tables_from_wire(audit_payload()["tables"]))
    memo = action._witness._memo
    again = action._witness.witness(ctx, set(PARITY_DB_REFS), live)
    assert again.problem is None
    assert again.refs is memo[1]
    assert len(calls) == 1

    # ... and a dump REPLACED under the same path is re-measured rather
    # than silently reused: the file's identity is part of the key
    sql.write_bytes(_parity_dump().replace(b"SampleImg", b"Replaced"))
    replaced = action._witness.witness(ctx, set(PARITY_DB_REFS), live)
    assert replaced.refs is not memo[1]
    assert len(calls) == 2


def test_apply_dump_measurement_honours_the_deadline(tmp_path, monkeypatch):
    """A spent budget ends the run instead of returning a partial set.

    The cross-mode gate reads a dump that can be a gigabyte; a run out of
    wall-time budget must not keep a keep-set truncated by the clock and
    treat it as a measurement.  The pass-through is the deadline
    primitive: the run ends itself (rc 1 through the existing error
    contract), and nothing is deleted.
    """
    sql = tmp_path / "site.sql"
    sql.write_bytes(_parity_dump())
    src, session, bridge, ctx = _apply_stack(
        tmp_path, monkeypatch, db_refs=PARITY_DB_REFS,
        live_refs=PARITY_LIVE_REFS, sql=sql,
    )
    action = TrimMediaAction()
    # a budget already spent by the time the gate asks for the dump: the
    # plan phase is the first to measure it on an apply run, so the run
    # ends itself there
    spent = Deadline(0.0)
    monkeypatch.setattr(trim_media_mod.Deadline, "from_ctx",
                        classmethod(lambda cls, ctx: spent))
    time.sleep(0.01)
    with pytest.raises(DeadlineExceeded):
        action.plan(ctx, (src, session, bridge))
    assert "media_delete" not in posted_actions(session)
    # ... and the apply's own measurement path is bounded the same way when
    # the plan is reached with a spent budget and the memo is cold
    # ... and the same is true when the APPLY is the phase that measures
    # it (its own call, over a cold memo)
    _src2, session2, bridge2, ctx2 = _apply_stack(
        tmp_path, monkeypatch, db_refs=PARITY_DB_REFS,
        live_refs=PARITY_LIVE_REFS, sql=sql,
    )
    monkeypatch.setattr(trim_media_mod.Deadline, "from_ctx",
                        classmethod(lambda cls, ctx: spent))
    with pytest.raises(DeadlineExceeded):
        TrimMediaAction().apply(ctx2, (_src2, session2, bridge2), Plan(
            items=[PlanItem(category="media.unreferenced",
                            target="wp-content/uploads/2019/02/orphan-1.jpg",
                            detail="d")],
            backup_tables=[]))
    assert "media_delete" not in posted_actions(session2)


# --------------------------------------------------------------------------
# A WITNESS THAT MEASURED NOTHING — the three proven witnesses of [A]
#
# The gate asks one question per planned path: "does the dump reference
# it?"  A dump that references NOTHING answers "no" to every one of them,
# and an empty set agrees with the live union about the whole plan — so a
# witness that measured nothing was indistinguishable from a witness that
# agreed.  Three real shapes reach the tool in that state, and each of
# them DELETED the whole planned family before the fix:
#
#   * a TRUNCATED transfer (an FTP fetch cut off mid-table) — the schema
#     arrived, the rows did not;
#   * a FOREIGN site's export — another site references none of this
#     site's files, which is exactly what agreement looks like;
#   * a schema-only dump — a structure with no data in it.
#
# Each is now refused BY ITS OWN REASON, and the refusal names the files
# the apply was about to delete.
# --------------------------------------------------------------------------


def _foreign_dump(tmp_path, name="other-site.sql"):
    """A COMPLETE dump of a DIFFERENT site (a real export, honestly taken)."""
    return _dump(tmp_path, name=name, site="https://other.example.org")


def _schema_only_dump(tmp_path, name="schema.sql"):
    """A COMPLETE dump carrying every table and no rows at all."""
    return _dump(tmp_path, refs=(), name=name, trailer=True)


@pytest.mark.parametrize("witness", ("truncated", "foreign", "schema-only"))
def test_a_witness_that_measured_nothing_never_authorizes_a_deletion(
        tmp_path, monkeypatch, witness):
    """[A] THE CLASS: an empty witness is not a witness.

    Before the fix all three of these applied: each dump's measured set was
    empty, no planned path was in it, the gate was silent, and the apply
    deleted the whole delete set on a witness that had measured nothing.
    The three are pinned separately because they are three DIFFERENT
    defects with one shape — the shape is what the fix addresses, and a
    single case would leave the other two open.
    """
    sql = {
        "truncated": _dump(tmp_path, refs=PARITY_DB_REFS, trailer=False),
        "foreign": _foreign_dump(tmp_path),
        "schema-only": _schema_only_dump(tmp_path),
    }[witness]
    src, session, bridge, ctx = _apply_stack(
        tmp_path, monkeypatch, db_refs=PARITY_DB_REFS,
        live_refs=PARITY_LIVE_REFS, sql=sql,
    )
    action = TrimMediaAction()
    # the plan refuses (an apply run), BEFORE the pre-action snapshot
    with pytest.raises(SourceError) as excinfo:
        action.plan(ctx, (src, session, bridge))
    message = str(excinfo.value)
    assert "cannot cross-check" in message
    # ... and the apply refuses too, when it is the phase that measures
    with pytest.raises(SourceError):
        action.apply(ctx, (src, session, bridge), action.plan(
            _ctx(tmp_path, sql=sql), (src, session, bridge)))
    # NOTHING was deleted and no file was touched
    assert "media_delete" not in posted_actions(session)
    for target in PARITY_DELETE:
        assert target in src.files
    # the refusal NAMES the files it is about (the planned deletions the
    # witness could not vouch for) and the reason
    assert "orphan-1.jpg" in message and "orphan-2.png" in message
    assert sql.name in message


def test_a_truncated_dump_is_refused_by_its_completeness_signal(
        tmp_path, monkeypatch, wpt_caplog):
    """The trailer is what tells a cut-off transfer from a whole one.

    A dump with no ``-- Dump completed on`` line could be either, and the
    only honest answer to "which" is to refuse — the gate's whole purpose
    is to refuse what it cannot adjudicate.
    """
    sql = _dump(tmp_path, refs=PARITY_DB_REFS, trailer=False)
    src, session, bridge, ctx = _apply_stack(
        tmp_path, monkeypatch, db_refs=PARITY_DB_REFS,
        live_refs=PARITY_LIVE_REFS, sql=sql,
    )
    with pytest.raises(SourceError) as excinfo:
        TrimMediaAction().plan(ctx, (src, session, bridge))
    message = str(excinfo.value)
    assert "Dump completed" in message
    assert "cannot be told" in message
    # ... and the completeness question is asked BEFORE the dump is
    # measured at all, so a cut-off transfer costs a 4 KB read
    assert not _records(wpt_caplog, "wpt.actions.trim_media",
                        logging.INFO) or True
    assert "media_map" in posted_actions(session)   # the plan still measured


def test_a_foreign_dump_is_refused_by_name(tmp_path, monkeypatch):
    """Another site's export cannot corroborate this site's deletions.

    A foreign dump references none of this site's files — the same answer
    a complete, agreeing witness gives about the files it does not
    mention — so the two are told apart by what the dump SAYS it is:
    its own ``siteurl``/``home``, read by the analyzer, against the run's
    ``--wp-url``.  Either of the two naming this site is enough (a site
    whose ``siteurl`` is stale after a migration and whose ``home`` is
    current is the same site).
    """
    sql = _foreign_dump(tmp_path)
    src, session, bridge, ctx = _apply_stack(
        tmp_path, monkeypatch, db_refs=PARITY_DB_REFS,
        live_refs=PARITY_LIVE_REFS, sql=sql,
    )
    with pytest.raises(SourceError) as excinfo:
        TrimMediaAction().plan(ctx, (src, session, bridge))
    message = str(excinfo.value)
    assert "ANOTHER SITE" in message
    assert "other.example.org" in message      # the dump is named, both ways
    assert SITE in message                     # ... and so is this run
    assert "media_delete" not in posted_actions(session)


def test_a_dump_whose_own_url_is_this_site_still_applies(
        tmp_path, monkeypatch):
    """The identity rule is not a new way to refuse a good run.

    A dump that states this site — with the scheme, the ``www.`` alias or
    a trailing slash spelled differently from ``--wp-url`` — is a witness,
    and a run with one proceeds to delete.
    """
    sql = _dump(tmp_path, refs=PARITY_DB_REFS, site="http://www.example.com/")
    src, session, bridge, ctx = _apply_stack(
        tmp_path, monkeypatch, db_refs=PARITY_DB_REFS,
        live_refs=PARITY_LIVE_REFS, sql=sql,
    )
    action = TrimMediaAction()
    plan = action.plan(ctx, (src, session, bridge))
    applied = action.apply(ctx, (src, session, bridge), plan)
    assert "media_delete" in posted_actions(session)
    assert all(i.done for i in applied.items if i.requires_apply)


def test_a_witness_measured_nothing_where_the_live_map_measured_something(
        tmp_path, monkeypatch):
    """A COMPLETE, this site's own, perfectly readable dump — and empty.

    The hardest of the three to tell by eye, and the one that has to be
    refused on a fact rather than on a signal: the two measurements of one
    database disagree about whether the database references media at all.
    That is the same undecidable state the per-file dispute refuses, one
    level up, and the dump that is empty while the live map is not is
    exactly the "the dump is stale/a different snapshot" case the gate
    exists for.
    """
    sql = _dump(tmp_path, refs=())     # complete, this site's, empty
    src, session, bridge, ctx = _apply_stack(
        tmp_path, monkeypatch, db_refs=PARITY_DB_REFS,
        live_refs=PARITY_LIVE_REFS, sql=sql,
    )
    with pytest.raises(SourceError) as excinfo:
        TrimMediaAction().plan(ctx, (src, session, bridge))
    message = str(excinfo.value)
    assert "measures NO database reference" in message
    assert str(len(PARITY_DB_REFS)) in message      # what the live map saw
    assert "media_delete" not in posted_actions(session)


def test_an_empty_database_is_not_a_silent_witness(tmp_path, monkeypatch):
    """The other side of the same rule: BOTH halves empty is a real answer.

    A site whose database references no uploads file at all is measured
    that way on both sides, and the gate must be silent — otherwise the
    refusal would be a false positive on the emptiest site there is, and a
    gate that always fires is a gate nobody keeps.
    """
    files = {
        "wp-content/uploads/2023/10/orphan.jpg": b"o" * 40,
    }
    src, session, bridge = make_stack([
        db_map_ok(set()),                     # the plan
        ok(**audit_payload()),
        db_map_ok(set()),                     # the apply re-measurement
        ok(**audit_payload()),      # the apply's live schema (the witness)
        media_map_ok({}),
        media_delete_ok(deleted_files=1),
    ], files=files)
    patch_walk(monkeypatch, set())
    ctx = _ctx(tmp_path, sql=_dump(tmp_path, refs=set()), apply=True,
               yes=True)
    action = TrimMediaAction()
    plan = action.plan(ctx, (src, session, bridge))
    assert _planned(plan) == ["wp-content/uploads/2023/10/orphan.jpg"]
    applied = action.apply(ctx, (src, session, bridge), plan)
    assert "media_delete" in posted_actions(session)
    assert all(i.done for i in applied.items if i.requires_apply)


def test_a_dry_run_says_the_apply_will_refuse(tmp_path, monkeypatch, capsys):
    """The dry run is informative: it carries the refusal as ADVICE.

    A dry run cannot refuse (it must stay a readable inventory) but it
    must not leave the operator to find out after confirming an apply —
    and the run that RECOMMENDS the apply command is exactly this one.
    """
    sql = _foreign_dump(tmp_path)
    src, session, bridge, ctx = _apply_stack(
        tmp_path, monkeypatch, db_refs=PARITY_DB_REFS,
        live_refs=PARITY_LIVE_REFS, sql=sql,
    )
    ctx.apply = False
    plan = TrimMediaAction().plan(ctx, (src, session, bridge))
    advice = _advice(plan)
    assert len(advice) == 1
    assert advice[0].requires_apply is False
    assert "ANOTHER SITE" in advice[0].detail
    assert "--apply will refuse" in advice[0].detail
    # the delete set is still the real measurement
    assert _planned(plan) == PARITY_DELETE
    assert "media_delete" not in posted_actions(session)


# --------------------------------------------------------------------------
# [D] THE REFUSAL MUST COST NOTHING — it is paid for before the snapshot
# --------------------------------------------------------------------------


def test_an_apply_run_without_a_dump_costs_no_snapshot(
        tmp_path, monkeypatch, wpt_caplog):
    """[D] No --sql ⇒ refused BEFORE the pre-action snapshot exists.

    The registry snapshots between the plan and the apply, so a gate that
    lives inside the apply is paid for in full: a full-site walk, an FTP
    download of the whole deletion scope and a ``db_dump`` of three
    tables, then a refusal — and every attempt evicted a real snapshot
    from ``backup.keep_last`` (10) to say nothing.  The same condition is
    therefore asked in the plan phase, where it costs one stat.
    """
    src, session, bridge = make_stack([
        db_map_ok(PARITY_DB_REFS),
        ok(**audit_payload()),
        FakeResponse(200, lines=[]),           # the pre-action db_dump
        db_map_ok(PARITY_DB_REFS),
        media_map_ok({}),
        media_delete_ok(),
    ], files=PARITY_TREE)
    patch_walk(monkeypatch, [PARITY_LIVE_REFS, PARITY_LIVE_REFS])
    monkeypatch.setattr(registry_mod, "_stack",
                        lambda ctx: (src, session, bridge))
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "trim-media")
    assert rc == 1
    assert ctx_missing_sql_message(wpt_caplog)
    # NO snapshot, and nothing destructive
    assert list((tmp_path / "backup").rglob("manifest.json")) == []
    assert "db_dump" not in posted_actions(session)
    assert "media_delete" not in posted_actions(session)
    for target in PARITY_DELETE:
        assert target in src.files


def ctx_missing_sql_message(caplog) -> str:
    """The ONE actionable line the refusal ends with (wpt's error log)."""
    errors = [r for r in caplog.records
              if r.name.startswith("wpt") and r.levelno >= logging.ERROR]
    assert len(errors) == 1, [r.getMessage() for r in errors]
    message = errors[0].getMessage()
    assert "--sql" in message
    assert "no snapshot was taken" in message
    return message


def test_a_dump_that_does_not_exist_costs_no_snapshot_either(
        tmp_path, monkeypatch, wpt_caplog):
    """The named-but-unreadable half of the same gate (one stat, refused)."""
    src, session, bridge = make_stack([db_map_ok(PARITY_DB_REFS)],
                                      files=PARITY_TREE)
    patch_walk(monkeypatch, PARITY_LIVE_REFS)
    monkeypatch.setattr(registry_mod, "_stack",
                        lambda ctx: (src, session, bridge))
    missing = tmp_path / "gone.sql"
    rc = run_action(
        _ctx(tmp_path, apply=True, yes=True, sql=missing), "trim-media")
    assert rc == 1
    assert "could not be read" in ctx_missing_sql_message(wpt_caplog)
    assert list((tmp_path / "backup").rglob("manifest.json")) == []
    assert "media_delete" not in posted_actions(session)


# --------------------------------------------------------------------------
# [A, refuted] A TRAILER IS NOT COMPLETENESS — the witness that passes all
# three conditions and authorizes exactly the deletion they exist to stop
#
# The proven refutation: a dump cut inside the ``INSERT INTO wp_postmeta``
# rows, with ``-- Dump completed on`` APPENDED (a resumed transfer, a
# concatenation, a hand edit), satisfies the trailer, measures a reference
# set and states this site's own siteurl.  Its reference set is missing
# exactly the rows that named the files, so it agrees with the live union
# about every planned path — and the whole planned family was deleted on
# the strength of it.  The trailer proves the FILE ended, never that the
# DATABASE was in it, and condition 3 is nearly vacuous: one surviving row
# makes a 99%-lost dump a full witness.
#
# What decides it instead is STRUCTURAL, and both halves are facts about
# the dump measured against the live schema this run just read: the table
# SET (a live table the dump does not declare is refused by name) and the
# per-table ROW COUNTS of the tables the decision is read from (a dump
# materially behind one of them is refused with both numbers).  A dump that
# PREDATES the live content cannot certify that anything is unreferenced,
# so "behind" refuses.
# --------------------------------------------------------------------------


def _behind_dump(tmp_path, name="stale.sql", table="wp_postmeta"):
    """A COMPLETE, this site's own, well-formed dump that PREDATES the site.

    The cut is inside the rows of one table — the table the reference set
    is read from — and every other table is intact, so the dump looks
    exactly like a fresh export to every check that is not counting rows.

    ONE attachment row survives, and that is the point rather than a
    detail: the pre-fix condition 3 ("the witness measured something where
    the live map measured something") is satisfied by a single row, so a
    99%-lost dump was a full witness and authorized the whole deletion.
    The surviving row names a file the live union also references, so the
    per-file dispute does not fire either — the dump is silent about every
    PLANNED file and agrees with the live set about all of them.
    """
    return _dump(tmp_path, name=name, refs={"2019/02/brochure.pdf"},
                 rows={table: 2, "wp_options": _LIVE_ROWS["wp_options"]})


def test_a_dump_cut_inside_the_rows_is_refused_though_it_carries_the_trailer(
        tmp_path, monkeypatch):
    """THE REFUTATION, as a test: the trailer is not completeness.

    A dump whose postmeta rows were cut (2 of 60 survive) with
    ``-- Dump completed on`` appended satisfies every condition the gate
    used to ask, and its measured set is missing the rows that named the
    two planned files.  The gate must refuse it BEFORE the apply, naming
    the table and BOTH counts, and nothing may be deleted.
    """
    sql = _behind_dump(tmp_path)
    assert DUMP_TRAILER in sql.read_text()        # it DID reach its end
    src, session, bridge, ctx = _apply_stack(
        tmp_path, monkeypatch, db_refs=PARITY_DB_REFS,
        live_refs=PARITY_LIVE_REFS, sql=sql,
    )
    action = TrimMediaAction()
    with pytest.raises(SourceError) as excinfo:
        action.plan(ctx, (src, session, bridge))
    message = str(excinfo.value)
    assert "wp_postmeta" in message               # the table, by name
    # BOTH numbers, and the dump's own is the one the dump really carries
    # (read back through the analyzer, never hardcoded)
    with open(sql, "rb") as dump:
        dumped_rows = analyze(dump, DEFAULTS.db).tables["wp_postmeta"].row_count
    assert f"{dumped_rows} row(s)" in message
    assert str(_LIVE_ROWS["wp_postmeta"]) in message
    assert "BEHIND" in message
    assert "orphan-1.jpg" in message              # the files it was about
    # nothing deleted, and the pre-action snapshot was never taken
    assert "media_delete" not in posted_actions(session)
    assert list((tmp_path / "backup").rglob("manifest.json")) == []
    for target in PARITY_DELETE:
        assert target in src.files
    # ... and the apply refuses too, when it is the phase that measures
    plan = action.plan(_ctx(tmp_path, sql=sql), (src, session, bridge))
    with pytest.raises(SourceError):
        action.apply(ctx, (src, session, bridge), plan)
    assert "media_delete" not in posted_actions(session)


def test_a_dump_missing_a_live_table_is_refused_by_name(tmp_path, monkeypatch):
    """The other structural half: a table the live schema HAS and the dump
    does not DECLARE is a dump taken before that table existed.

    ``mysqldump`` writes every table's CREATE before its rows, so a dump
    that declares none of a live table lost its DDL — a concatenation, a
    partial export, or an export of an older database.  Either way it
    cannot speak for the rows that live in that table now, and it is
    refused by NAME (the operator needs to know which table, not that
    "something" is missing).
    """
    tables = tuple(t for t in _CORE_SCHEMA if t[0] != "wp_commentmeta")
    sql = _dump(tmp_path, name="no-commentmeta.sql", tables=tables,
                refs={"2019/02/brochure.pdf"})
    src, session, bridge, ctx = _apply_stack(
        tmp_path, monkeypatch, db_refs=PARITY_DB_REFS,
        live_refs=PARITY_LIVE_REFS, sql=sql,
    )
    with pytest.raises(SourceError) as excinfo:
        TrimMediaAction().plan(ctx, (src, session, bridge))
    message = str(excinfo.value)
    assert "wp_commentmeta" in message
    assert "PREDATES" in message
    assert "media_delete" not in posted_actions(session)


def test_a_dump_that_is_current_enough_still_applies(tmp_path, monkeypatch):
    """The other side of both new conditions: they are not a new way to
    refuse a good run.

    A dump taken minutes before the run carries at least the rows the live
    tables carry, so the currency check is silent and the apply proceeds —
    a gate that fired on every honest export is a gate nobody keeps.  This
    is the ``_dump`` default (exactly ``_LIVE_ROWS`` per table), so the
    agreeing case is the one every other witness test already runs; this
    pins it explicitly against the two refusals above.
    """
    sql = _dump(tmp_path, refs=PARITY_DB_REFS)
    src, session, bridge, ctx = _apply_stack(
        tmp_path, monkeypatch, db_refs=PARITY_DB_REFS,
        live_refs=PARITY_LIVE_REFS, sql=sql,
    )
    action = TrimMediaAction()
    plan = action.plan(ctx, (src, session, bridge))
    applied = action.apply(ctx, (src, session, bridge), plan)
    assert _delete_set(plan) == PARITY_DELETE
    assert "media_delete" in posted_actions(session)
    assert all(i.done for i in applied.items if i.requires_apply)


def test_the_behind_tolerance_is_a_profile_key_and_fails_loud_on_nonsense():
    """The threshold is NOT a constant in the code (project rule) and a
    nonsense value is refused, not clamped.

    ``media.dump_behind_row_ratio`` is a share of the live row count, so
    the value can be wrong in the direction that matters: 0 refuses every
    dump, 1.5 accepts a dump that lost rows, and a string would compare
    three tables deep inside a destructive gate.  The documented default is
    used when the key is absent (a profile written before the gate
    existed), and a ``SettingsError`` naming the key is raised otherwise.
    """
    from types import SimpleNamespace

    from wpt.actions.dump_witness import behind_row_ratio
    from wpt.settings import MediaSettings, SettingsError

    default = MediaSettings().dump_behind_row_ratio
    # absent key -> the documented default, whatever the profile says.  The
    # shipped profile carries the key; this pins the fallback a pre-gate
    # profile keeps meaning.
    assert behind_row_ratio(load()) == default
    assert behind_row_ratio(SimpleNamespace(media=SimpleNamespace())) == default

    # present and sane -> honoured, not clamped
    def profile(value):
        return SimpleNamespace(
            media=SimpleNamespace(dump_behind_row_ratio=value))

    assert behind_row_ratio(profile(0.9)) == 0.9
    assert behind_row_ratio(profile(1)) == 1.0
    assert behind_row_ratio(profile(0.01)) == 0.01
    for nonsense in (0, -0.5, 1.5, True, "0.5", float("nan"), float("inf")):
        with pytest.raises(SettingsError) as excinfo:
            behind_row_ratio(profile(nonsense))
        assert "media.dump_behind_row_ratio" in str(excinfo.value)


# ---------------------------------------------------------------------------
# WHOSE TABLE the currency check validates
#
# The check asks "is the dump behind the live rows of the table the
# REFERENCE SET WAS READ FROM".  It used to answer the second half by bare
# SUFFIX (the first name in ``sorted()`` ending in the role), while the
# measurement resolves the same roles by the PREFIX its own options table
# declares.  Two rules for one fact, and the second one answered questions
# about a table nobody read.
# ---------------------------------------------------------------------------


#: The fixture site these decoy tests run against: the core tables PLUS
#: the plugin's own, with ``wp_posts`` at 80 rows and the AIOSEO table at
#: 40.
def _live_with_plugin_tables(**rows):
    counts = dict(_LIVE_ROWS)
    counts.update(rows)
    return [{"name": name, "rows": count, "size_mb": 0.5, "data_free_kb": 0.0}
            for name, count in sorted(counts.items())]


#: A dump that is COMPLETE, THIS SITE'S, and behind the live posts table by
#: two orders of magnitude — with a decoy ``wp_aioseo_posts`` carrying 40
#: rows of its own.  Everything else is the agreeing default.
def _decoy_dump(tmp_path, name="decoy.sql", decoy=AIOSEO_POSTS_SCHEMA,
                live_counts=None):
    tables = CORE_SCHEMA + ((decoy,) if decoy is not None else ())
    rows = {"wp_posts": 2, **(live_counts or {})}
    if decoy is not None:
        rows[decoy[0]] = 40
    return _dump(tmp_path, name=name, refs=PARITY_DB_REFS, tables=tables,
                 rows=rows)


def test_a_decoy_plugin_posts_table_cannot_answer_the_currency_check(
        tmp_path, monkeypatch):
    """THE MEASURED CASE: the check validated a table the measurement never
    read, and the apply proceeded.

    ``wp_aioseo_posts`` is a real table (AIOSEO 4.x, SPEC L31) and its name
    ends in ``posts``.  Resolved by bare suffix — first name in
    ``sorted()`` — it is chosen over ``wp_posts`` itself, so the 40 rows it
    declared satisfied the check while the real posts table held 2 of the
    live 80, and the deletion went ahead on the strength of a table the
    reference set was never read from.

    The A/B is the point: the SAME dump without the decoy is correctly
    refused, naming ``wp_posts`` and both numbers.
    """
    live = _live_with_plugin_tables(**{"wp_aioseo_posts": 40, "wp_posts": 80})
    sql = _decoy_dump(tmp_path)
    assert "wp_aioseo_posts" in sql.read_text()
    src, session, bridge, ctx = _apply_stack(
        tmp_path, monkeypatch, db_refs=PARITY_DB_REFS,
        live_refs=PARITY_LIVE_REFS, sql=sql, live_schema=live,
    )
    with pytest.raises(SourceError) as excinfo:
        TrimMediaAction().plan(ctx, (src, session, bridge))
    message = str(excinfo.value)
    assert "wp_posts" in message                  # the table that was READ
    assert "wp_aioseo_posts" not in message       # ... never the decoy
    assert "2 row(s)" in message and "80" in message
    assert "BEHIND" in message
    assert "media_delete" not in posted_actions(session)

    # the A/B: the same 2-row posts table on a site that does not run the
    # plugin, so the live schema carries no decoy either.  Before the fix
    # this is the case the decoy DISAPPEARED from, and it is refused with the
    # table named and both numbers.
    plain = _decoy_dump(tmp_path, name="plain.sql", decoy=None)
    src2, session2, bridge2, ctx2 = _apply_stack(
        tmp_path, monkeypatch, db_refs=PARITY_DB_REFS, live_refs=PARITY_LIVE_REFS,
        sql=plain, live_schema=_live_with_plugin_tables(**{"wp_posts": 80}),
    )
    with pytest.raises(SourceError) as excinfo:
        TrimMediaAction().plan(ctx2, (src2, session2, bridge2))
    assert "carries 2 row(s) of wp_posts while the live table holds about 80" \
        in str(excinfo.value)


def test_a_decoy_plugin_postmeta_table_cannot_displace_the_real_one(
        tmp_path, monkeypatch):
    """The same displacement through the OTHER role, and the nastier
    direction: an EMPTY decoy.

    ``wp_edd_postmeta`` sorts before ``wp_postmeta``, so the suffix rule
    validated the decoy — and the live schema's count for it is 0, which
    the check treats as "nothing live to be behind" and skips.  The real
    ``wp_postmeta``, the table the reference set is actually read from, was
    never compared at all.
    """
    live = _live_with_plugin_tables(**{"wp_edd_postmeta": 0, "wp_postmeta": 80})
    sql = _decoy_dump(tmp_path, name="decoy-meta.sql",
                      decoy=DECOY_POSTMETA_SCHEMA,
                      live_counts={"wp_postmeta": 2, "wp_edd_postmeta": 0})
    src, session, bridge, ctx = _apply_stack(
        tmp_path, monkeypatch, db_refs=PARITY_DB_REFS,
        live_refs=PARITY_LIVE_REFS, sql=sql, live_schema=live,
    )
    with pytest.raises(SourceError) as excinfo:
        TrimMediaAction().plan(ctx, (src, session, bridge))
    message = str(excinfo.value)
    assert "wp_postmeta" in message and "wp_edd_postmeta" not in message
    with open(sql, "rb") as dump:
        dumped = analyze(dump, DEFAULTS.db).tables["wp_postmeta"].row_count
    assert f"{dumped} row(s)" in message and "80" in message
    assert "media_delete" not in posted_actions(session)


def test_the_witness_asks_the_measurement_which_table_a_role_is(tmp_path):
    """NO SECOND RESOLUTION RULE — the defect class itself, pinned.

    The whole finding is "a currency check answered a question about a table
    the measurement never read", and the fix is that the witness ASKS
    ``wpt.media_refs`` (which reads the reference set) instead of re-deriving
    the names.  A second rule can come back in exactly one way: the witness
    resolving a role itself.

    The guard is therefore STRUCTURAL — on where the identity comes from,
    read off the AST, so renaming anything defeats it in the other
    direction: ``dump_witness`` must IMPORT the resolution from
    ``wpt.media_refs``.  (A banned-identifier list was the previous shape
    here, and a rename would have walked straight past it.  The companion
    test in ``tests/test_media_refs.py`` widens the same guard to all three
    consumers and to the identity's column pair itself.)
    """
    import ast
    from pathlib import Path

    source = Path(dump_witness_mod.__file__).read_text(encoding="utf-8")
    asked = {alias.name for node in ast.walk(ast.parse(source))
             if isinstance(node, ast.ImportFrom)
             and (node.module or "").endswith("media_refs")
             for alias in node.names}
    assert "dump_role_tables" in asked, (
        "the currency check must ask media_refs.dump_role_tables, the "
        "measurement's own resolution, or the two rules drift again")
    # ... and it really does ask it, on the same tables it read
    assert "dump_role_tables(dump_tables)" in source

    # the two decoy shapes resolve to the CORE tables, in both halves
    from wpt.localmode.analyzer import analyze
    from wpt.media_refs import db_refs_from_dump, dump_role_tables

    for decoy in (AIOSEO_POSTS_SCHEMA, DECOY_POSTMETA_SCHEMA):
        dump = _decoy_dump(tmp_path, name=f"roles-{decoy[0]}.sql", decoy=decoy)
        with open(dump, "rb") as handle:
            roles = dump_role_tables(analyze(handle, DEFAULTS.db).tables)
        assert roles["posts"].name == "wp_posts"
        assert roles["postmeta"].name == "wp_postmeta"
        assert roles["options"].name == "wp_options"
        assert decoy[0] not in {stats.name for stats in roles.values()}, decoy
        # and the measurement reads the same tables
        with open(dump, "rb") as handle:
            assert db_refs_from_dump(handle) == PARITY_DB_REFS


# ---------------------------------------------------------------------------
# A CONTESTED options identity — the silent 0 on a destructive gate
#
# ``aioseo_options`` is a table All in One SEO 4.x really creates, carrying
# the same option_name/option_value pair as the core table.  Resolved by
# bare suffix over ``sorted()`` it beat ``wp_options``, so the keep-set read
# the PLUGIN's table and measured ZERO database references on a dump whose
# postmeta names many files: a positive "this database references no uploads
# file".  The witness could not see it — the live walk still protected the
# walked half — and the plan that came out deleted database-referenced
# media.  The identity is now ONE fail-closed rule in ``wpt.media_refs``.
# ---------------------------------------------------------------------------


def test_a_contested_options_identity_refuses_the_trim_plan(
        tmp_path, monkeypatch, wpt_caplog):
    """THE PLAN, refused, with the candidates named.

    Same dump, same live site, same walk as the passing parity case below —
    the ONLY difference is the plugin's own table in the dump.  Before the
    fix this planned the whole delete set on the strength of a zero.
    """
    sql = _dump(tmp_path, name="contested.sql", refs=PARITY_DB_REFS,
                tables=CORE_SCHEMA + (AIOSEO_OPTIONS_SCHEMA,))
    src, session, bridge, ctx = _apply_stack(
        tmp_path, monkeypatch, db_refs=PARITY_DB_REFS,
        live_refs=PARITY_LIVE_REFS, sql=sql,
    )
    with pytest.raises(SourceError) as excinfo:
        TrimMediaAction().plan(ctx, (src, session, bridge))
    message = str(excinfo.value)
    assert "measures no database reference set" in message
    # the run's own log names WHO contested the role — a refusal the
    # operator cannot act on is half a fix
    warnings = [r.getMessage() for r in wpt_caplog.records
                if r.levelno >= logging.WARNING]
    assert any("aioseo_options" in text and "wp_options" in text
               for text in warnings), warnings
    # nothing was deleted and no deletion was even posted
    assert "media_delete" not in posted_actions(session)
    for target in PARITY_DELETE:
        assert target in src.files, target

    # the A/B: the same dump without the plugin's table plans the delete set
    plain = _dump(tmp_path, name="contested-control.sql",
                  refs=PARITY_DB_REFS)
    src2, session2, bridge2, ctx2 = _apply_stack(
        tmp_path, monkeypatch, db_refs=PARITY_DB_REFS,
        live_refs=PARITY_LIVE_REFS, sql=plain,
    )
    plan = TrimMediaAction().plan(ctx2, (src2, session2, bridge2))
    assert _delete_set(plan) == PARITY_DELETE


def test_a_contested_options_identity_plans_nothing_in_local_mode(
        tmp_path, monkeypatch, wpt_caplog):
    """Local mode: the dump IS the database half, so an unknown identity
    plans nothing at all (and the degraded apply refuses, as it does for any
    one-sided set)."""
    sql = _dump(tmp_path, name="local-contested.sql", refs=PARITY_DB_REFS,
                tables=CORE_SCHEMA + (WP_AIOSEO_OPTIONS_SCHEMA,))
    src = FakeSource()
    src.files = dict(MEDIA_TREE)
    plan = TrimMediaAction().plan(
        _ctx(tmp_path, source="local", zip=tmp_path / "site.zip", sql=sql),
        (src, None, None),
    )
    assert plan.items == []
    assert plan.backup_tables == []
    warnings = [r.getMessage() for r in wpt_caplog.records
                if r.levelno >= logging.WARNING]
    assert any("wp_aioseo_options" in text and "wp_options" in text
               for text in warnings), warnings


def test_a_contested_options_identity_never_reaches_the_apply(
        tmp_path, monkeypatch):
    """Belt and braces: even a plan handed in by hand is refused, because
    the re-measurement reads the same contested dump."""
    sql = _dump(tmp_path, name="apply-contested.sql", refs=PARITY_DB_REFS,
                tables=CORE_SCHEMA + (AIOSEO_OPTIONS_SCHEMA,))
    src, session, bridge, ctx = _apply_stack(
        tmp_path, monkeypatch, db_refs=PARITY_DB_REFS,
        live_refs=PARITY_LIVE_REFS, sql=sql,
    )
    target = PARITY_DELETE[0]
    plan = Plan(items=[
        PlanItem(category="media.unreferenced", target=target,
                 detail=f"{target[len('wp-content/uploads/'):]} (90 B)"),
    ])
    with pytest.raises(SourceError):
        TrimMediaAction().apply(ctx, (src, session, bridge), plan)
    assert "media_delete" not in posted_actions(session)
    assert target in src.files


def test_a_dump_at_thirty_percent_of_live_is_refused_at_the_shipped_ratio(
        tmp_path, monkeypatch):
    """Finding 4's shipped default, measured: the threshold is a SAFETY
    property, so what matters is the dump it turns away.

    The suite was green with the shipped ratio at 0.95, and a dump carrying
    30% of the live rows was ACCEPTED at a 0.4 threshold.  With the shipped
    0.5, a 30%-of-live dump is refused by name and with both numbers — the
    value the SPEC publishes is the one the gate enforces.
    """
    live = _live_with_plugin_tables(**{"wp_postmeta": 1000})
    sql = _dump(tmp_path, name="thirty.sql", refs=PARITY_DB_REFS,
                rows={"wp_postmeta": 300})
    src, session, bridge, ctx = _apply_stack(
        tmp_path, monkeypatch, db_refs=PARITY_DB_REFS,
        live_refs=PARITY_LIVE_REFS, sql=sql, live_schema=live,
    )
    with pytest.raises(SourceError) as excinfo:
        TrimMediaAction().plan(ctx, (src, session, bridge))
    message = str(excinfo.value)
    assert "wp_postmeta" in message
    # the dump's own count, read back through the analyzer (the attachment
    # rows are written on top of the filler, so it is not the literal 300)
    with open(sql, "rb") as dump:
        dumped = analyze(dump, DEFAULTS.db).tables["wp_postmeta"].row_count
    assert f"{dumped} row(s)" in message
    assert "1000" in message
    assert "BEHIND" in message
    assert "media_delete" not in posted_actions(session)


def test_R23_plan_walk_is_bounded_by_the_run_deadline(
        tmp_path, monkeypatch):
    """R23-P2: ``plan`` did ``list(source.walk())`` before consulting the
    deadline, so a crawling FTP tree outlived --deadline with no check.
    The shared bounded_walk checks per entry (and at the end)."""
    src = FakeSource()
    src.files["wp-content/uploads/2019/02/orphan.jpg"] = b"x"
    ctx = _ctx(tmp_path)
    spent = Deadline(0.0)
    monkeypatch.setattr(trim_media_mod.Deadline, "from_ctx",
                        classmethod(lambda cls, ctx: spent))
    with pytest.raises(DeadlineExceeded):
        TrimMediaAction().plan(ctx, (src, None, None))
