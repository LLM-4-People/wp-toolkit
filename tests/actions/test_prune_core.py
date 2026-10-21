"""Tests for the prune-core action (wpt/actions/prune_core).

NO network: the wp.org fetches ride the real WpOrgApi transport over the
shared FakeSession (tests/actions/test_heal_core.py conventions) with the
response cache monkeypatched to a tmp_path — or SEEDED (checksums JSON)
for the local-mode runs, whose fresh plain session cannot be scripted.

The double that matters is the ``sources`` one: a prune DELETES, so the
tree a test asserts on is the tree minus the plan — one store, walked
and read the way a live source is.

Test -> behavior map:
  test_registration .......................... prune-core registered as the
        INSTANCE under applies=("ftp", "local") — both modes reachable
  test_plan_proven_stale_files_planned ...... (a) release provenance: a
        SimplePie file, an icon-library svg and a languages catalog the
        PREVIOUS release shipped and the current one does not -> exact
        items, sorted, category core.integrity, per-file provenance in
        the detail, walked bytes_est, not done, backup_tables == []; the
        request shapes pinned (current map + the previous-release window
        at the SAME locale, identifying UA, profile timeout, GET only);
        the walk precedes the first bridge call
  test_plan_unknown_addition_is_a_note_only .. (b) a php drop-in under
        wp-includes in no release map and matching no signature: NO item,
        ONE investigate-only info naming it
  test_plan_known_stale_signature_planned .... (c) the profile's
        core_integrity.known_stale signature (fnmatch name + content
        marker) plans a file the release window cannot reach
  test_plan_scope_excludes_content_and_config  (d)+(e) a plugin file and an
        uploads file that the PREVIOUS map shipped (so the proof is
        present and only the scope can stop them) plus wp-config.php /
        .htaccess: never planned, never even named
  test_plan_unknown_version_refuses ......... no version seam -> WptError,
        zero wp.org traffic
  test_plan_checksums_unavailable_refuses .. no comparison basis -> refuse
  test_plan_previous_maps_unavailable_refuses  (f) FAIL-CLOSED: a network
        failure fetching the previous release's map refuses the WHOLE
        plan, exactly ONE warning, zero deletions, nothing reached
  test_plan_partial_window_still_prunes ..... a release that answers
        nothing contributes nothing; the others still prove their files
  test_plan_first_patch_release_has_no_provenance  no invented version: a
        6.8.0 site gets ONE warning, no provenance and signatures only
  test_plan_signature_failure_is_conservative  an unreadable candidate /
        an oversized file / a malformed signature can only ever produce
        FEWER deletions
  test_plan_nothing_to_prune_is_idempotent ... (h) a pruned tree -> EMPTY
        plan, and no release-provenance traffic at all
  test_apply_deletes_and_verifies ........... the audited core-tree warning
        line, the deletions, the post-apply re-walk: a removed file
        flips done, a survivor does not
  test_apply_surviving_file_is_incomplete .... (i) a file that fails to
        delete: ONE warning, the item NOT done, terminal "prune
        incomplete: 0 of 1 ... `wpt restore` reverts", rc 1 through the
        registry with the snapshot intact
  test_apply_refuses_config_target_even_by_hand  the write-guard's
        refuse-list is absolute: a hand-built plan naming wp-config.php
        cannot delete it, the file survives and the apply is incomplete
  test_apply_collateral_core_loss_reported .. a source that takes an
        unplanned official core file with it is named, and the apply
        fails
  test_apply_verify_basis_unavailable_refuses_before_deletes  the verify's
        map is fetched BEFORE the first delete: unavailable -> refuse
        with nothing deleted
  test_apply_empty_plan_no_work ............. zero planned files -> no
        walk-side effects, no wp.org fetch, plan returned as-is
  test_apply_local_rehearsal ................ (g) the REAL registry local
        flow: the materialized twin carries the stale files GONE and
        every other entry byte-identical; the original zip untouched
  test_apply_idempotent_second_run .......... (h) a second apply over the
        pruned tree deletes nothing and plans nothing
  test_registry_ftp_apply_end_to_end ........ the full registry contract:
        rc 0, the fail-closed pre-action snapshot capturing EXACTLY the
        plan scope, purge_cache, the report printing every item done
"""

import copy
import hashlib
import json
import logging
import zipfile

import pytest
import requests

import wpt.audit.integrity as integrity
import wpt.audit.updates as updates
from tests.fakes import FakeResponse, FakeSession, FakeSource
from wpt.actions import registry as registry_mod
from wpt.actions.prune_core import PruneCoreAction
from wpt.actions.registry import get_action, run_action
from wpt.cli import Ctx
from wpt.report import Plan, PlanItem
from wpt.settings import load
from wpt.types import SourceError, WptError

#: The shipped profile — the action consumes http.timeout_s and (when the
#: settings section carries the field) core_integrity.known_stale.
DEFAULTS = load()

SITE = "https://example.com"

VERSION = "6.8.2"
PREVIOUS = "6.8.1"
PREVIOUS_2 = "6.8.0"

INDEX = b"<?php // index\n"
VERSION_PHP = b"<?php\n$wp_version = '6.8.2';\n"
#: The legacy SimplePie tree, the icon-library svgs, the retired
#: css/dist bundles: what an incomplete upgrade leaves behind.
SIMPLEPIE = b"<?php // Simple_Pie 1.5\n"
SIMPLEPIE_COOKIE = b"<?php // Simple_Pie cookie jar\n"
ICON_SVG = b'<svg xmlns="http://www.w3.org/2000/svg"/>\n'
BLOCK_CSS = b"/*wp-block-library style.min.css 3.7.0*/\n"
#: A languages catalog of a locale the site no longer uses — the
#: scope's third tree.
OLD_PO = b'# fr_FR translation shipped by WP 6.8.1\n'
#: A possible implant: php, in the core tree, in no release map.
UNKNOWN_PHP = b"<?php // unknown drop-in\n"
PLUGIN_PHP = b"<?php // akismet\n"
UPLOAD_PNG = b"\x89PNG\r\n\x1a\n"
CONFIG_PHP = b"<?php // user config\n"
HTACCESS = b"# user rules\n"

#: The proof the previous release provides: 6.8.1 shipped all of these,
#: 6.8.0 only a subset (per-file provenance is then visible in the plan).
PREV_MAP_6_8_1 = {
    "index.php": "0" * 32,
    "wp-includes/SimplePie/class.simplepie.php": "1" * 32,
    "wp-includes/SimplePie/cookie.php": "2" * 32,
    "wp-includes/images/icon-library/admin-menu.svg": "3" * 32,
    "wp-content/languages/fr_FR.po": "4" * 32,
    "wp-includes/css/dist/block-library/style.min.css": "5" * 32,
    "wp-content/plugins/akismet/akismet.php": "6" * 32,
    "wp-content/uploads/2019/05/legacy.png": "7" * 32,
}
PREV_MAP_6_8_0 = {
    "index.php": "0" * 32,
    "wp-includes/SimplePie/class.simplepie.php": "1" * 32,
}
#: The current release ships none of the stale ones — only the two files
#: the site still legitimately has.
CURRENT_MAP = {
    "index.php": hashlib.md5(INDEX).hexdigest(),
    "wp-includes/version.php": hashlib.md5(VERSION_PHP).hexdigest(),
}

#: The tree under test: every case (a)-(e) in one walk.
TREE = {
    "index.php": INDEX,                                # in the current map
    "wp-includes/version.php": VERSION_PHP,            # in the current map
    # (a) release provenance
    "wp-includes/SimplePie/class.simplepie.php": SIMPLEPIE,
    "wp-includes/SimplePie/cookie.php": SIMPLEPIE_COOKIE,
    "wp-includes/images/icon-library/admin-menu.svg": ICON_SVG,
    "wp-content/languages/fr_FR.po": OLD_PO,
    # (b) unknown addition -> investigate note
    "wp-includes/wp-reset-fake.php": UNKNOWN_PHP,
    # (c) signature-only proof (in NEITHER previous map)
    "wp-includes/js/dist/vendor/react.js": b"/*retired bundle*/\n",
    # (d) out of scope, though the previous map shipped both
    "wp-content/plugins/akismet/akismet.php": PLUGIN_PHP,
    "wp-content/uploads/2019/05/legacy.png": UPLOAD_PNG,
    # (e) user files
    "wp-config.php": CONFIG_PHP,
    ".htaccess": HTACCESS,
}

#: (a)+(c) — the only files the plan may ever name.
EXPECTED_PLANNED = {
    "wp-content/languages/fr_FR.po": (
        f"stale core file — shipped by WP {PREVIOUS}, dropped by WP "
        f"{VERSION} en_US — delete"),
    "wp-includes/SimplePie/class.simplepie.php": (
        f"stale core file — shipped by WP {PREVIOUS_2}/{PREVIOUS}, dropped "
        f"by WP {VERSION} en_US — delete"),
    "wp-includes/SimplePie/cookie.php": (
        f"stale core file — shipped by WP {PREVIOUS}, dropped by WP "
        f"{VERSION} en_US — delete"),
    "wp-includes/images/icon-library/admin-menu.svg": (
        f"stale core file — shipped by WP {PREVIOUS}, dropped by WP "
        f"{VERSION} en_US — delete"),
}
SIGNATURE_NOTE = "a retired core bundle WordPress no longer ships"
KNOWN_STALE = [{
    "name": "wp-includes/js/dist/*.js",
    "marker": "retired bundle",
    "max_bytes": 4096,
    "note": SIGNATURE_NOTE,
}]


# ------------------------------------------------------------------ doubles


@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    """Point the SHARED wp.org cache (owned by updates.py) at a tmp dir —
    the local-mode twin of tests/actions/test_heal_core.py's fixture.  No
    test ever touches the CWD's real .wpt-cache, and a local-mode run
    (whose fresh plain session cannot be scripted) is served entirely
    from here."""
    d = tmp_path / "cache"
    monkeypatch.setattr(updates, "_CACHE_DIR", d)
    return d


class PruneSource(FakeSource):
    """FakeSource + the prune pins: every delete and every marker
    read_many batch is recorded, and a scripted path can be made to FAIL
    (an ftp DELE error model)."""

    def __init__(self, timeline=None) -> None:
        super().__init__()
        self.deletes: list[str] = []
        self.reads: list[list[str]] = []
        self.read_bounds: list[int | None] = []
        self.fail_paths: set[str] = set()
        self.timeline = timeline if timeline is not None else []

    def walk(self, path=""):
        # the walk is a real source call: recording it is what lets a
        # test pin the plan's ORDER (walk BEFORE the first bridge call,
        # which lazy-deploys wpt's own bridge-<8hex>.php into the tree).
        self.timeline.append("walk")
        return super().walk(path)

    def read_many(self, paths, *, max_bytes=None):
        self.reads.append(list(paths))
        self.read_bounds.append(max_bytes)
        self.timeline.append("read_many")
        return super().read_many(paths, max_bytes=max_bytes)

    def delete(self, path):
        if path in self.fail_paths:
            raise SourceError(f"delete failed: {path}")
        super().delete(path)
        self.deletes.append(path)


class _CollateralSource(PruneSource):
    """A source that also loses an UNPLANNED official core file with the
    first delete — the collateral-damage shape the post-apply re-walk
    must catch (independent per-file deletes should never do this; a
    source that does is a surprise the operator must hear about)."""

    def __init__(self) -> None:
        super().__init__()
        self.victim = "wp-includes/functions.php"

    def delete(self, path):
        super().delete(path)
        self.files.pop(self.victim, None)


class PruneBridge:
    """Bridge double: ``info`` answers the scripted wp_version; the
    registry's post-apply ``purge_cache`` and the teardown are recorded."""

    def __init__(self, wp_version=VERSION, timeline=None) -> None:
        self.wp_version = wp_version
        self.calls: list[tuple[str, dict]] = []
        self.destroyed = 0
        self.timeline = timeline if timeline is not None else []

    def call(self, action, **params):
        self.calls.append((action, params))
        self.timeline.append(action)
        if action == "info":
            return {"wp_version": self.wp_version}
        if action == "purge_cache":
            return {"ok": True, "purged": True}
        raise AssertionError(f"unexpected bridge action: {action!r}")

    def destroy(self):
        self.destroyed += 1


# ------------------------------------------------------------------ helpers


def _settings(known_stale=KNOWN_STALE):
    """A Settings copy carrying the profile's known_stale signatures.

    The field is attached to a deep COPY of the shipped settings so a
    test can never leak signatures into another; when the settings
    section does not carry the field yet the attribute is simply set
    here (the loader validates a profile entry of the same shape as
    known_added either way).
    """
    settings = copy.deepcopy(DEFAULTS)
    if known_stale is not None:
        settings.core_integrity.known_stale = copy.deepcopy(known_stale)
    return settings


def _ctx(tmp_path, **overrides):
    """A prune-core Ctx; ftp-mode defaults, overridable per test."""
    fields = dict(
        source="ftp://example.com",
        settings=_settings(),
        command="prune-core",
        apply=False,
        yes=False,
        backup_dir=tmp_path / "backup",
        wp_url=SITE,
    )
    fields.update(overrides)
    return Ctx(**fields)


def _ctx_local(tmp_path, zip_path, **overrides):
    return _ctx(tmp_path, source="local", zip=zip_path, **overrides)


def checksums_response(checksums: dict[str, str]) -> FakeResponse:
    """A live-shaped core/checksums/1.0 payload."""
    return FakeResponse(text=json.dumps({"checksums": checksums}))


def default_script():
    """The scripted wp.org traffic of a healthy ftp plan: the current map
    then the previous-release window (nearest first), the LAST one 404ing
    — a release that answers nothing contributes nothing and must not
    fail the plan."""
    return [
        checksums_response(CURRENT_MAP),
        checksums_response(PREV_MAP_6_8_1),
        checksums_response(PREV_MAP_6_8_0),
    ]


def make_stack(script=None, *, files=None, wp_version=VERSION, source=None):
    """A fake ftp-mode prune stack: (source, FakeSession, bridge).

    The source and the bridge share ONE timeline list, so a test can pin
    the real call ORDER across the wire and the tree."""
    timeline: list[str] = []
    if source is not None:
        source.timeline = timeline
    src = source if source is not None else PruneSource(timeline)
    src.files.update(TREE if files is None else files)
    session = FakeSession(list(default_script() if script is None else script))
    return src, session, PruneBridge(wp_version=wp_version, timeline=timeline)


def seed_checksums(cache_dir, version: str, checksums: dict[str, str],
                   locale: str = "en_US"):
    """A FRESH checksums cache entry — the local-mode transport serves it
    without any network (tests/actions/test_heal_core.py's seed)."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / (
        updates._cache_key(integrity._checksums_url(version, locale), None)
        + ".json"
    )
    path.write_text(json.dumps({"checksums": checksums}), encoding="utf-8")
    return path


def seed_all_maps(cache_dir, version=VERSION):
    """Seed the current + the whole previous-release window (local mode)."""
    seed_checksums(cache_dir, version, CURRENT_MAP)
    seed_checksums(cache_dir, PREVIOUS, PREV_MAP_6_8_1)
    seed_checksums(cache_dir, PREVIOUS_2, PREV_MAP_6_8_0)


def _records(wpt_records, level):
    return [r for r in wpt_records
            if r.name == "wpt.actions.prune_core" and r.levelno == level]


def _messages(records):
    return [r.getMessage() for r in records]


def all_warnings(wpt_records):
    return [r.getMessage() for r in wpt_records
            if r.levelno == logging.WARNING]


# ------------------------------------------------------------- registration


def test_registration():
    record = get_action("prune-core")
    assert record is not None
    assert record.applies == ("ftp", "local")
    assert isinstance(record.action, PruneCoreAction)  # the instance


# ------------------------------------------------------------------ plan


def test_plan_proven_stale_files_planned(tmp_path, wpt_records):
    src, session, bridge = make_stack()
    plan = PruneCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    # (a) + (c): exact items, path-sorted, with the walked size and the
    # per-file provenance in the detail.  The signature-only file (c)
    # names its profile signature instead of a release.
    assert {i.target: i.detail for i in plan.items} == {
        **EXPECTED_PLANNED,
        "wp-includes/js/dist/vendor/react.js": (
            f"stale core file — core_integrity.known_stale signature "
            f"\"wp-includes/js/dist/*.js\" ({SIGNATURE_NOTE}) — delete"),
    }
    assert [i.target for i in plan.items] == sorted(i.target for i in plan.items)
    assert all(i.category == "core.integrity" for i in plan.items)
    assert {i.target: i.bytes_est for i in plan.items} == {
        "wp-content/languages/fr_FR.po": len(OLD_PO),
        "wp-includes/SimplePie/class.simplepie.php": len(SIMPLEPIE),
        "wp-includes/SimplePie/cookie.php": len(SIMPLEPIE_COOKIE),
        "wp-includes/images/icon-library/admin-menu.svg": len(ICON_SVG),
        "wp-includes/js/dist/vendor/react.js": len(b"/*retired bundle*/\n"),
    }
    assert all(i.requires_apply for i in plan.items)
    assert all(not i.done for i in plan.items)
    assert plan.backup_tables == []  # files only — the deliberate pin
    # (b): the unknown addition is a NOTE, never an item
    assert "wp-includes/wp-reset-fake.php" not in {
        i.target for i in plan.items}
    # the request shapes: the current map, then the previous-release
    # window at the SAME locale, identifying UA + profile timeout
    assert [url for url, _kw in session.gets] == [
        integrity._checksums_url(VERSION, "en_US"),
        integrity._checksums_url(PREVIOUS, "en_US"),
        integrity._checksums_url(PREVIOUS_2, "en_US"),
    ]
    assert session.posts == []
    for _url, kw in session.gets:
        assert kw["headers"]["User-Agent"].startswith("wpt/")
        assert kw["timeout"] == DEFAULTS.http.timeout_s
    # the walk precedes the first bridge call (the bridge lazy-deploys
    # its own bridge-<8hex>.php on that call) and the only file read is
    # the signature marker's
    assert [a for a, _p in bridge.calls] == ["info"]
    assert src.timeline == ["walk", "info", "read_many"]
    assert src.reads == [["wp-includes/js/dist/vendor/react.js"]]
    infos = _messages(_records(wpt_records, logging.INFO))
    assert any("5 stale core file(s) to prune" in m for m in infos)


def test_plan_unknown_addition_is_a_note_only(tmp_path, wpt_records):
    """(b) An unknown php drop-in inside a core tree — the shape
    core.integrity reports as high-risk "added" — is NEVER planned by a
    prune.  It is named in ONE investigate-only line, the heal-core
    precedent."""
    src, session, bridge = make_stack()
    plan = PruneCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    assert "wp-includes/wp-reset-fake.php" not in {i.target for i in plan.items}
    infos = _messages(_records(wpt_records, logging.INFO))
    notes = [m for m in infos if "investigate-only" in m]
    assert len(notes) == 1
    assert "wp-includes/wp-reset-fake.php" in notes[0]
    assert "possible implant" in notes[0]
    assert "never auto-deleted" in notes[0]
    # the file is untouched: the plan read it, never deleted it
    assert src.deletes == []


def test_plan_known_stale_signature_planned(tmp_path, wpt_records):
    """(c) The profile signature is the second proof: a file no release
    in the window shipped, whose path matches the known_stale glob and
    whose bytes carry the marker."""
    src, session, bridge = make_stack()
    plan = PruneCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    item = next(i for i in plan.items
                if i.target == "wp-includes/js/dist/vendor/react.js")
    assert "known_stale" in item.detail and SIGNATURE_NOTE in item.detail
    # a signature whose marker the file does NOT carry proves nothing:
    # the file falls through to the investigate-only note instead
    files = dict(TREE)
    files["wp-includes/js/dist/vendor/react.js"] = b"/*not the marker*/\n"
    src2, session2, bridge2 = make_stack(files=files)
    plan2 = PruneCoreAction().plan(_ctx(tmp_path), (src2, session2, bridge2))
    assert "wp-includes/js/dist/vendor/react.js" not in {
        i.target for i in plan2.items}
    notes = [m for m in _messages(_records(wpt_records, logging.INFO))
             if "investigate-only" in m]
    assert any("wp-includes/js/dist/vendor/react.js" in m for m in notes)
    # with no signature at all the same file is likewise never planned
    src3, session3, bridge3 = make_stack(files=files)
    plan3 = PruneCoreAction().plan(
        _ctx(tmp_path, settings=_settings(known_stale=[])),
        (src3, session3, bridge3))
    assert all(i.target in EXPECTED_PLANNED for i in plan3.items)


def test_plan_scope_excludes_content_and_config(tmp_path, wpt_records):
    """(d)+(e) Scope is absolute: a plugin file and an uploads file the
    PREVIOUS map shipped (so release provenance WOULD prove them) are
    still never planned — and neither are the two user config files,
    which are not even named as unknown additions (out of scope, not
    unknown)."""
    src, session, bridge = make_stack()
    plan = PruneCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    targets = {i.target for i in plan.items}
    assert "wp-content/plugins/akismet/akismet.php" not in targets
    assert "wp-content/uploads/2019/05/legacy.png" not in targets
    assert "wp-config.php" not in targets and ".htaccess" not in targets
    notes = " ".join(m for m in _messages(_records(wpt_records, logging.INFO))
                     if "investigate-only" in m)
    for out_of_scope in ("akismet", "uploads", "wp-config.php", ".htaccess"):
        assert out_of_scope not in notes
    assert "wp-includes/wp-reset-fake.php" in notes  # the in-scope unknown
    # the previous map really did ship the two out-of-scope files, so
    # only the SCOPE can be what stopped them
    assert "wp-content/plugins/akismet/akismet.php" in PREV_MAP_6_8_1
    assert "wp-content/uploads/2019/05/legacy.png" in PREV_MAP_6_8_1


def test_plan_unknown_version_refuses(tmp_path):
    for bad in (None, ""):
        src, session, bridge = make_stack([], wp_version=bad)
        with pytest.raises(WptError, match="unknown WordPress version"):
            PruneCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
        assert session.gets == []  # refused before any wp.org traffic


def test_plan_checksums_unavailable_refuses(tmp_path):
    src, session, bridge = make_stack(
        [requests.ConnectionError("boom")])
    with pytest.raises(WptError, match="no comparison basis"):
        PruneCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    # the previous-release window is never even asked for
    assert len(session.gets) == 1
    assert src.deletes == []


def test_plan_previous_maps_unavailable_refuses(tmp_path, wpt_records):
    """(f) FAIL-CLOSED: without the "this file WAS core" proof there is
    no prune at all.  The whole plan refuses, the transport's single
    warning is the one line that names the reason, and nothing is
    deleted — through the REAL registry, so rc 1 and no snapshot."""
    src = PruneSource()
    src.files.update(TREE)
    session = FakeSession([
        checksums_response(CURRENT_MAP),     # the comparison map
        requests.ConnectionError("boom"),    # WP 6.8.1 — the proof window
        requests.ConnectionError("boom"),    # WP 6.8.0
    ])
    bridge = PruneBridge()
    with pytest.raises(WptError, match="previous release"):
        PruneCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    assert src.deletes == []
    assert src.files == TREE  # nothing touched
    # ONE warning per failed fetch, and NO second warning stacked on top
    # of the transport's own (the refusal IS the answer)
    assert len(all_warnings(wpt_records)) == 2
    assert _records(wpt_records, logging.WARNING) == []
    # the same refusal through the registry: rc 1, no snapshot at all.
    # The comparison map is served from the 1h cache the run above wrote,
    # so only the two proof-window requests are scripted.
    src2 = PruneSource()
    src2.files.update(TREE)
    session2 = FakeSession([
        requests.ConnectionError("boom"),    # WP 6.8.1 — the proof window
        requests.ConnectionError("boom"),    # WP 6.8.0
    ])
    old = registry_mod._stack
    registry_mod._stack = lambda ctx: (src2, session2, PruneBridge())
    try:
        rc = run_action(_ctx(tmp_path, apply=True, yes=True), "prune-core")
    finally:
        registry_mod._stack = old
    assert rc == 1
    assert list((tmp_path / "backup").glob("*/*/manifest.json")) == []
    assert src2.deletes == []


def test_plan_partial_window_still_prunes(tmp_path, wpt_records):
    """A release that answers nothing contributes nothing: the window is
    a union of proofs, never a requirement that EVERY release answers.
    Here WP 6.8.0 is a 404 and 6.8.1 still proves its files."""
    src, session, bridge = make_stack([
        checksums_response(CURRENT_MAP),
        checksums_response(PREV_MAP_6_8_1),
        FakeResponse(status_code=404),
    ])
    plan = PruneCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    targets = {i.target for i in plan.items}
    assert "wp-includes/SimplePie/cookie.php" in targets
    # ... and the per-file provenance drops the release that answered
    # nothing (only 6.8.1 proves it)
    detail = next(i.detail for i in plan.items
                  if i.target == "wp-includes/SimplePie/cookie.php")
    assert detail == (
        f"stale core file — shipped by WP {PREVIOUS}, dropped by WP "
        f"{VERSION} en_US — delete")


def test_plan_signature_failure_is_conservative(tmp_path, wpt_records):
    """Every signature-scan failure shape can only produce FEWER
    deletions: an unreadable candidate, an oversized file and a
    malformed signature all leave the file unproven (investigate-only)."""
    # (1) oversized: bigger than the signature's max_bytes, never read
    files = dict(TREE)
    files["wp-includes/js/dist/vendor/react.js"] = b"x" * (4096 + 1)
    src, session, bridge = make_stack(files=files)
    plan = PruneCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    assert "wp-includes/js/dist/vendor/react.js" not in {
        i.target for i in plan.items}
    # (2) unreadable: read_many fails for that one path
    class _Blind(PruneSource):
        def read_many(self, paths, *, max_bytes=None):
            ok, failed = {}, {p: "boom" for p in paths}
            return ok, failed

    files = dict(TREE)
    src, session, bridge = make_stack(
        default_script(), files=files, source=_Blind())
    plan = PruneCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    assert "wp-includes/js/dist/vendor/react.js" not in {
        i.target for i in plan.items}
    # ... while the release-proven files are unaffected
    assert "wp-includes/SimplePie/cookie.php" in {i.target for i in plan.items}
    # (3) a malformed signature is skipped with ONE error, never a crash
    src, session, bridge = make_stack()
    plan = PruneCoreAction().plan(
        _ctx(tmp_path, settings=_settings(known_stale=[
            {"name": "wp-includes/js/dist/*.js"},   # no marker
            KNOWN_STALE[0],
        ])),
        (src, session, bridge))
    assert "wp-includes/js/dist/vendor/react.js" in {i.target for i in plan.items}
    errors = [r.getMessage() for r in wpt_records
              if r.name == "wpt.actions.prune_core" and r.levelno == logging.ERROR]
    assert errors == ["core prune: known_stale signature 0 is malformed, "
                      "skipped"]


def test_plan_first_patch_release_has_no_provenance(tmp_path, wpt_records):
    """A site on ``6.8.0`` has no earlier release IN ITS OWN series, and
    this action never invents one (guessing which patch of the previous
    minor existed is exactly the invented version it refuses to build
    on).  One warning says so; the profile signatures remain available as
    the only proof, and every other candidate falls back to the
    investigate-only note."""
    files = dict(TREE)
    src, session, bridge = make_stack(
        [checksums_response(CURRENT_MAP)], files=files, wp_version="6.8.0")
    plan = PruneCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    assert [i.target for i in plan.items] == [
        "wp-includes/js/dist/vendor/react.js"]
    assert len(session.gets) == 1  # the comparison map only
    warnings = _messages(_records(wpt_records, logging.WARNING))
    assert len(warnings) == 1
    assert "first release of its patch series" in warnings[0]
    assert "only core_integrity.known_stale signatures can plan a deletion" \
        in warnings[0]
    # the release-provable files are named, never planned
    notes = [m for m in _messages(_records(wpt_records, logging.INFO))
             if "investigate-only" in m]
    assert any("wp-includes/SimplePie/cookie.php" in m for m in notes)


def test_plan_nothing_to_prune_is_idempotent(tmp_path):
    """(h) A pruned tree plans NOTHING and needs no release provenance:
    the candidate set is empty, so the window is never fetched."""
    files = {"index.php": INDEX, "wp-includes/version.php": VERSION_PHP,
             "wp-content/plugins/akismet/akismet.php": PLUGIN_PHP}
    src, session, bridge = make_stack([checksums_response(CURRENT_MAP)],
                                      files=files)
    plan = PruneCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    assert plan.items == []
    assert plan.backup_tables == []
    assert len(session.gets) == 1  # the comparison map only
    applied = PruneCoreAction().apply(
        _ctx(tmp_path), (src, session, bridge), plan)
    assert applied is plan
    assert len(session.gets) == 1  # the empty apply fetches nothing at all


# ----------------------------------------------------------------- apply


def test_apply_deletes_and_verifies(tmp_path, wpt_records):
    src, session, bridge = make_stack()
    ctx = _ctx(tmp_path)
    action = PruneCoreAction()
    stack = (src, session, bridge)
    plan = action.plan(ctx, stack)
    applied = action.apply(ctx, stack, plan)
    assert applied is plan  # the same Plan object, items updated in place
    assert all(i.done for i in applied.items)
    # the tree is exactly TREE minus the plan
    assert src.deletes == sorted(EXPECTED_PLANNED) + [
        "wp-includes/js/dist/vendor/react.js"]
    for target in src.deletes:
        assert target not in src.files
    for path in ("index.php", "wp-includes/version.php",
                 "wp-includes/wp-reset-fake.php",
                 "wp-content/plugins/akismet/akismet.php",
                 "wp-content/uploads/2019/05/legacy.png",
                 "wp-config.php", ".htaccess"):
        assert path in src.files  # untouched, byte-identical
    # every CORE-TREE delete is announced by the audited warning line
    # (never a silent deletion inside a protected core subtree); the
    # languages catalog is outside those two subtrees, so the announce
    # is the core unlock's own scope, not a per-delete trace
    warnings = _messages(_records(wpt_records, logging.WARNING))
    core_tree_deletes = [t for t in src.deletes if t.startswith(
        ("wp-admin/", "wp-includes/"))]
    assert len(warnings) == len(core_tree_deletes) == 4
    for target in core_tree_deletes:
        assert any(w.startswith(
            f"guarded core prune: deleting protected core file {target} ("
        ) for w in warnings)
    assert not any("languages" in w for w in warnings)
    # the verify re-walked the tree; the apply's own comparison map came
    # from the 1h cache the plan's fetch wrote (no second request)
    assert [url for url, _kw in session.gets] == [
        integrity._checksums_url(VERSION, "en_US"),
        integrity._checksums_url(PREVIOUS, "en_US"),
        integrity._checksums_url(PREVIOUS_2, "en_US"),
    ]
    assert [a for a, _p in bridge.calls] == ["info", "info"]
    infos = _messages(_records(wpt_records, logging.INFO))
    assert ("apply: 5 stale core file(s) removed and verified against the "
            "official WP 6.8.2 en_US checksums") in infos


def test_apply_surviving_file_is_incomplete(tmp_path, wpt_records):
    """(i) A file that fails to delete is caught by the post-apply
    re-walk: ONE warning, the item NOT done, and the terminal
    "prune incomplete" error that the registry turns into rc 1 with the
    pre-action snapshot as the rollback."""
    src, session, bridge = make_stack()
    src.fail_paths = {"wp-includes/SimplePie/cookie.php"}
    ctx = _ctx(tmp_path)
    action = PruneCoreAction()
    stack = (src, session, bridge)
    plan = action.plan(ctx, stack)
    with pytest.raises(WptError) as excinfo:
        action.apply(ctx, stack, plan)
    message = str(excinfo.value)
    assert "prune incomplete: 4 of 5 stale file(s) removed" in message
    assert "wp-includes/SimplePie/cookie.php" in message
    assert "`wpt restore` reverts" in message
    by_target = {i.target: i for i in plan.items}
    assert not by_target["wp-includes/SimplePie/cookie.php"].done
    assert by_target["wp-includes/SimplePie/class.simplepie.php"].done
    # the survivor is still on the "server" — the plan was honest
    assert "wp-includes/SimplePie/cookie.php" in src.files
    warnings = _messages(_records(wpt_records, logging.WARNING))
    assert ("apply: could not remove wp-includes/SimplePie/cookie.php "
            "(SourceError: delete failed: wp-includes/SimplePie/cookie.php); "
            "continuing") in warnings
    assert "apply: wp-includes/SimplePie/cookie.php survived the prune " \
           "— not removed" in warnings
    # ... and through the REAL registry: rc 1, the sibling items done
    src2, session2, bridge2 = make_stack()
    src2.fail_paths = {"wp-includes/SimplePie/cookie.php"}
    old = registry_mod._stack
    registry_mod._stack = lambda ctx: (src2, session2, bridge2)
    try:
        rc = run_action(_ctx(tmp_path, apply=True, yes=True), "prune-core")
    finally:
        registry_mod._stack = old
    assert rc == 1
    assert [a for a, _p in bridge2.calls] == ["info", "info"]  # no purge


def test_apply_refuses_config_target_even_by_hand(tmp_path, wpt_records):
    """The write-guard's refuse-list is absolute: a hand-built plan
    naming wp-config.php cannot delete it, the file survives and the
    apply ends incomplete — the guard, not the action, is the owner."""
    src, session, bridge = make_stack([checksums_response(CURRENT_MAP)])
    plan = Plan(items=[
        PlanItem(category="core.integrity", target="wp-config.php",
                 detail="hand-built"),
        PlanItem(category="core.integrity", target=".htaccess",
                 detail="hand-built"),
    ], backup_tables=[])
    with pytest.raises(WptError) as excinfo:
        PruneCoreAction().apply(
            _ctx(tmp_path), (src, session, bridge), plan)
    message = str(excinfo.value)
    assert "prune incomplete: 0 of 2 stale file(s) removed" in message
    assert "wp-config.php" in message and ".htaccess" in message
    assert src.files["wp-config.php"] == CONFIG_PHP
    assert src.files[".htaccess"] == HTACCESS
    assert src.deletes == []  # both refused by the source's own guard


def test_apply_collateral_core_loss_reported(tmp_path, wpt_records):
    """A core file that went missing WITHOUT being planned is
    collateral damage: named explicitly and failed, never folded into the
    "not removed" count.  The victim is an OFFICIAL core file (a path the
    current map ships) — only such a loss is collateral; a file the map
    never listed was not core to begin with."""
    official = b"<?php // official\n"
    files = dict(TREE)
    files["wp-includes/functions.php"] = official
    current_map = dict(CURRENT_MAP, **{"wp-includes/functions.php":
                                       hashlib.md5(official).hexdigest()})
    script = [checksums_response(current_map)] + default_script()[1:]
    src, session, bridge = make_stack(
        script, files=files, source=_CollateralSource())
    ctx = _ctx(tmp_path)
    action = PruneCoreAction()
    stack = (src, session, bridge)
    plan = action.plan(ctx, stack)
    assert "wp-includes/functions.php" not in {i.target for i in plan.items}
    with pytest.raises(WptError) as excinfo:
        action.apply(ctx, stack, plan)
    message = str(excinfo.value)
    assert "unplanned official core file(s) went missing" in message
    assert "wp-includes/functions.php" in message
    # every planned item did land — the failure is the collateral alone
    assert all(i.done for i in plan.items)
    errors = _messages(_records(wpt_records, logging.ERROR))
    assert len(errors) == 1
    assert "wp-includes/functions.php" in errors[0]


def test_apply_verify_basis_unavailable_refuses_before_deletes(
        tmp_path, monkeypatch, wpt_records):
    """The verify's map is fetched BEFORE the first delete: when it
    cannot be had, the prune refuses with NOTHING deleted — no
    half-pruned tree, nothing to revert."""
    src, session, bridge = make_stack(default_script())
    ctx = _ctx(tmp_path)
    action = PruneCoreAction()
    stack = (src, session, bridge)
    plan = action.plan(ctx, stack)
    # the plan's fetch warmed the 1h cache; empty it so the apply's own
    # comparison fetch really has to go to the network
    empty = tmp_path / "empty-cache"
    empty.mkdir()
    monkeypatch.setattr(updates, "_CACHE_DIR", empty)
    session.script = [requests.ConnectionError("boom")]
    with pytest.raises(WptError, match="cannot verify the prune"):
        action.apply(ctx, stack, plan)
    assert src.deletes == []
    assert src.files == TREE


def test_apply_empty_plan_no_work(tmp_path):
    src, session, bridge = make_stack([])
    plan = Plan(items=[], backup_tables=[])
    applied = PruneCoreAction().apply(
        _ctx(tmp_path), (src, session, bridge), plan)
    assert applied is plan
    assert session.gets == []  # no wp.org fetch
    assert bridge.calls == []  # no bridge roundtrip at all
    assert src.deletes == []


def test_apply_idempotent_second_run(tmp_path):
    """(h) A second apply over the pruned tree is a no-op: the plan is
    empty, nothing is deleted, and the wp.org traffic is the comparison
    map only."""
    ctx = _ctx(tmp_path)
    action = PruneCoreAction()
    src, session, bridge = make_stack()
    stack = (src, session, bridge)
    plan = action.plan(ctx, stack)
    action.apply(ctx, stack, plan)
    deleted = list(src.deletes)
    plan2 = action.plan(ctx, stack)
    assert plan2.items == []
    action.apply(ctx, stack, plan2)
    assert src.deletes == deleted  # nothing else touched the tree
    assert "wp-includes/SimplePie/class.simplepie.php" not in src.files


# --------------------------------------------------- local rehearsal (g)


def test_apply_local_rehearsal(tmp_path, cache_dir, wpt_records):
    """(g) The REAL registry local flow: the materialized twin carries
    the stale files GONE and every other entry byte-identical; the
    ORIGINAL zip is untouched (it IS the rollback)."""
    zip_path = tmp_path / "site.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for path, blob in TREE.items():
            zf.writestr(path, blob)
    before = zip_path.read_bytes()
    seed_all_maps(cache_dir)
    rc = run_action(
        _ctx_local(tmp_path, zip_path, apply=True, yes=True), "prune-core")
    assert rc == 0
    assert zip_path.read_bytes() == before
    rehearsed = sorted(tmp_path.glob("site-rehearsed-*.zip"))
    assert len(rehearsed) == 1
    with zipfile.ZipFile(rehearsed[0]) as zf:
        names = {n for n in zf.namelist() if not n.endswith("/")}
        for target in list(EXPECTED_PLANNED) + [
                "wp-includes/js/dist/vendor/react.js"]:
            assert target not in names  # the stale files are GONE
        for path, blob in TREE.items():
            if path in EXPECTED_PLANNED or path == (
                    "wp-includes/js/dist/vendor/react.js"):
                continue
            assert zf.read(path) == blob  # everything else byte-identical
    infos = [r.getMessage() for r in wpt_records
             if r.name == "wpt.actions" and "rehearsed" in r.getMessage()]
    assert infos and "rehearsed 5/5 items" in infos[0]


def test_plan_local_reads_version_from_the_tree(tmp_path, cache_dir):
    """Local mode takes its version from wp-includes/version.php
    through the source (the gather's seam) and rides the seeded caches
    for the current + previous maps — no network at all."""
    zip_path = tmp_path / "site.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for path, blob in TREE.items():
            zf.writestr(path, blob)
    seed_all_maps(cache_dir)
    src = PruneSource()
    src.files.update(TREE)
    plan = PruneCoreAction().plan(
        _ctx_local(tmp_path, zip_path), (src, None, None))
    assert {i.target for i in plan.items} == set(EXPECTED_PLANNED) | {
        "wp-includes/js/dist/vendor/react.js"}
    # a tree with no version.php refuses before any map is needed
    src2 = PruneSource()
    src2.files.update({"index.php": INDEX})
    with pytest.raises(WptError, match="unknown WordPress version"):
        PruneCoreAction().plan(
            _ctx_local(tmp_path, zip_path), (src2, None, None))


# ---------------------------------------------------- registry end-to-end


def test_registry_ftp_apply_end_to_end(tmp_path, capsys, monkeypatch):
    src, session, bridge = make_stack()
    monkeypatch.setattr(registry_mod, "_stack",
                        lambda ctx: (src, session, bridge))
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "prune-core")
    assert rc == 0
    # the registry's exactly-one post-apply purge, then the teardown
    assert [a for a, _p in bridge.calls] == ["info", "info", "purge_cache"]
    assert bridge.destroyed == 1
    # the fail-closed pre-action snapshot captured EXACTLY the plan scope
    manifests = list((tmp_path / "backup").glob("*/*/manifest.json"))
    assert len(manifests) == 1
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    assert manifest["action"] == "prune-core"
    assert manifest["tables"] == []  # files only
    captured = {e["path"]: e for e in manifest["files"]}
    assert set(captured) == set(EXPECTED_PLANNED) | {
        "wp-includes/js/dist/vendor/react.js"}
    assert captured["wp-includes/SimplePie/class.simplepie.php"]["sha256"] \
        == hashlib.sha256(SIMPLEPIE).hexdigest()
    # the report prints every planned item done
    out = capsys.readouterr().out
    assert out.count("| yes |") == 5
    assert "shipped by WP 6.8.1, dropped by WP 6.8.2 en_US" in out


def test_R13_previous_checksum_maps_receive_the_run_deadline(monkeypatch):
    """R13-P2-9: the previous-release provenance fetches omitted the run
    budget, so every fallback request re-armed a 30 s per-read timeout.
    All three checksum calls now carry ``Deadline.from_ctx(ctx)``."""
    import wpt.actions.prune_core as prune_mod
    from wpt.deadline import Deadline

    deadline = Deadline(0.0)
    seen = []

    def _fake(version, session, timeout_s, locale, deadline=None, config=None):
        seen.append((version, deadline, config))
        return {"wp-includes/x.php": "d41d8cd98f00b204e9800998ecf8427e"}

    monkeypatch.setattr(prune_mod, "_fetch_checksums", _fake)
    maps = prune_mod._previous_maps("6.8.3", object(), 5, "en_US",
                                    deadline=deadline)
    assert set(maps) == {"6.8.2", "6.8.1", "6.8.0"}
    assert len(seen) == 3
    assert all(item[1] is deadline for item in seen)
    assert all(item[2] is None for item in seen)


def test_previous_maps_forwards_the_configured_wp_org(monkeypatch):
    """A configured mirror/cache/locale owner must reach the previous-release
    provenance fetches, not silently fall back to the public default."""
    import wpt.actions.prune_core as prune_mod

    seen = []

    def _fake(version, session, timeout_s, locale, deadline=None, config=None):
        seen.append(config)
        return {"wp-includes/x.php": "d41d8cd98f00b204e9800998ecf8427e"}

    monkeypatch.setattr(prune_mod, "_fetch_checksums", _fake)
    config = object()
    prune_mod._previous_maps("6.8.3", object(), 5, "en_US", config=config)
    assert len(seen) == 3 and all(item is config for item in seen)


def test_R13_expired_marker_scan_raises_instead_of_finishing_zero():
    """R13-P2-10: ``DeadlineExceeded`` in the marker scan was logged and
    swallowed, returning partial proofs so the plan could finish rc 0.
    The deadline is a run verdict: it re-raises."""
    from wpt.actions.prune_core import _signature_proofs
    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded, Entry

    source = PruneSource()
    with pytest.raises(DeadlineExceeded):
        _signature_proofs(
            ["wp-content/plugins/x/a.php"],
            {"wp-content/plugins/x/a.php": Entry(
                path="wp-content/plugins/x/a.php", is_dir=False, size=1)},
            source,
            [{"name": "*", "max_bytes": 10, "marker": "needle"}],
            Deadline(0.0),
        )


def test_R19_marker_read_carries_the_signature_byte_bound():
    """R19-P2: the marker batch called ``read_many(batch)`` with no
    ``max_bytes``.  A non-Unix listing reports SIZE_UNKNOWN (-1), which
    passes the ``size > max_bytes`` gate, so a huge file could be buffered
    whole.  The read now carries the largest signature cap in the batch;
    the post-read check stays as the second gate."""
    from wpt.actions.prune_core import _signature_proofs
    from wpt.types import Entry

    source = PruneSource()
    source.files["wp-includes/big.php"] = b"x" * 100
    proofs = _signature_proofs(
        ["wp-includes/big.php"],
        {"wp-includes/big.php": Entry(
            path="wp-includes/big.php", is_dir=False, size=-1)},
        source,
        [{"name": "wp-includes/*.php", "max_bytes": 32,
          "marker": "x"}],
        None,
    )
    assert proofs == {}
    assert source.read_bounds == [32]


def test_R14_plan_walk_is_bounded_before_the_first_fetch(tmp_path):
    """R14-P2: the plan walked the whole tree BEFORE constructing the run
    deadline, so a slow/hostile walk outlived --deadline and reached the
    wp.org fetch.  The deadline now exists first and every entry checks."""
    import time

    from wpt.types import DeadlineExceeded, Entry

    class _SlowWalk(PruneSource):
        def walk(self, path=""):
            for index in range(1000):
                time.sleep(0.01)
                yield Entry(path=f"wp-includes/x{index}.php",
                            is_dir=False, size=1)

    class _NoFetch:
        def __init__(self):
            self.calls = []

        def call(self, action, **params):
            self.calls.append(action)
            return {"wp_version": VERSION}

        def destroy(self):
            pass

    bridge = _NoFetch()
    ctx = _ctx(tmp_path, deadline_s=0.05)
    started = time.monotonic()
    with pytest.raises(DeadlineExceeded):
        PruneCoreAction().plan(ctx, (_SlowWalk(), None, bridge))
    assert time.monotonic() - started < 1.0
    assert bridge.calls == []


def test_R14_apply_checks_the_deadline_before_each_delete(tmp_path, monkeypatch):
    """R14-P2: apply walked and deleted with no per-entry deadline check.
    The pre-apply walk is bounded and every delete is checked; an expiry at
    the delete seam stops before the source mutates anything."""
    import wpt.actions.prune_core as prune_mod
    from wpt.types import DeadlineExceeded

    class _FakeDeadline:
        def check(self, context):
            if context == "prune-core delete":
                raise DeadlineExceeded("expired before delete")

    monkeypatch.setattr(
        prune_mod.Deadline, "from_ctx",
        classmethod(lambda cls, ctx: _FakeDeadline()))
    monkeypatch.setattr(prune_mod, "_prune_basis",
                        lambda source, bridge, deadline=None: (VERSION, "en_US"))
    monkeypatch.setattr(prune_mod, "resolve_core_locale",
                        lambda source, locale, default=None: "en_US")
    monkeypatch.setattr(prune_mod, "_wporg_transport",
                        lambda ctx, stack: (None, 5))
    monkeypatch.setattr(prune_mod, "_fetch_comparison_checksums",
                        lambda *a, **k: ({"wp-includes/other.php": "x"},
                                         "en_US"))

    source = PruneSource()
    target = "wp-includes/stale.php"
    source.files[target] = b"stale"
    plan = Plan(items=[PlanItem(category="core.integrity", target=target,
                                detail="stale", bytes_est=5)])
    with pytest.raises(DeadlineExceeded):
        PruneCoreAction().apply(_ctx(tmp_path), (source, None, None), plan)
    assert source.deletes == []
