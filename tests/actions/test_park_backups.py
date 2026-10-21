"""Tests for the park-backups action (wpt.actions.park_backups).

FakeSource-backed trees + the shipped profile (tests/actions/
test_clean_files.py conventions), the LIVE WALK monkeypatched in the action
module's namespace (``wpt.actions.park_backups.walk_site`` — the module
imports the name exactly so tests can patch it; no HTTP here).  The registry
end-to-end tests monkeypatch ``wpt.actions.registry._stack`` (the pinned
seam) and run the real ``run_action`` flow over a fake ftp-mode stack with a
REAL Bridge over FakeSession.  Deterministic, no network, no sleeps.

Test -> behavior map (the live case: archive payloads in the document root
of a webroot, plus a dead duplicate webroot at a guessable path):
  test_registration .......................... registered as the INSTANCE
        under applies=("ftp", "local") — the plan works in both modes
  test_archive_at_the_webroot_root_is_parked  an archive at the root plans
        as ``webroot.backup_payload`` and the apply MOVES it (never
        deletes): the parked copy is byte-identical under
        <backup_dir>/parked/<site>-<ts>/ and only then is the webroot file
        gone; the item is done
  test_park_outside_destination_is_honoured  ``ctx.extra["park_outside"]``
        (the --park-outside flag) overrides the park root
  test_uploads_submission_data_is_never_touched  a .sql/.sql.gz under
        wp-content/uploads/ (a Gravity Forms submission export) is NEVER
        a candidate — the plan stays empty and the file survives the apply
  test_plugin_unit_payloads_are_never_candidates  a .zip inside a plugin
        unit is that plugin's own asset
  test_sample_backup_dir_without_a_provable_reference_set_is_advice
        a walk that could not prove anything (local mode, or a partial
        walk) => the whole tree is ONE advice item carrying the
        backup_payload_in_webroot exposure, requires_apply False, and the
        apply moves nothing (rc-0 advice contract)
  test_destination_inside_the_webroot_is_refused_loudly  a webroot-relative
        --park-outside raises ONE error naming both paths and degrades
        every item to advice
  test_referenced_payload_is_never_moved  a basename the live walk still
        references is KEPT (never moved out from under the page)
  test_oversized_payload_is_advice_not_a_buffer  above
        backup_payloads.max_park_file_bytes the payload is reported, not
        buffered
  test_dir_candidate_parks_the_whole_subtree  a backup DIRECTORY moves
        file by file, all verified, then one rmdir_recursive
  test_nested_candidates_collapse_into_the_directory  a payload inside a
        backup dir is ONE item
  test_apply_keeps_the_webroot_file_when_the_read_fails  fail-closed: a
        failed read leaves the file, the item not done, one warning
  test_apply_fails_the_item_when_the_parked_copy_does_not_verify  the
        sha256 re-read mismatch removes the copy and leaves the webroot
        file
  test_plan_never_walks_a_clean_tree  no candidate => no HTTP at all
  test_registry_dry_run ..................... run_action apply=False: plan
        printed, rc 0, nothing moved, no bridge call, no purge
  test_registry_ftp_apply_end_to_end ........ apply --yes over the fake
        stack: the pre-action snapshot manifest lists the payload, the file
        is moved out, the purge fires once, rc 0
"""

import json
import logging
import zipfile
from pathlib import Path

import pytest

from tests.fakes import FakeResponse, FakeSession, FakeSource
from wpt.actions import park_backups as park_mod
from wpt.actions import registry as registry_mod
from wpt.actions.park_backups import ParkBackupsAction
from wpt.actions.registry import get_action, run_action
from wpt.cli import Ctx
from wpt.settings import BridgeSettings, load
from wpt.sources.zipwriter import MutableZipSource
from wpt.types import SourceError
from wpt.walk import WalkResult
from wpt.wpbridge.client import Bridge

DEFAULTS = load()
WEBROOT = "domains/example.com/public_html"
SITE = "https://example.com"

#: The live webroot shape: archives at the root, a dead duplicate webroot in
#: a guessable directory, and the payload-extension matches that must never
#: be touched (form records, a plugin's own asset).
TREE = {
    "wp-content.zip": b"PK\x03\x04" + b"z" * 500,
    "legacy-archive-2024.tar.gz": b"\x1f\x8b" + b"t" * 300,
    "sample-backup/wp-config.php": b"<?php // dead copy" + b"d" * 400,
    "sample-backup/index.php": b"<?php // dead copy" + b"i" * 200,
    "sample-backup/wp-includes/version.php": b"<?php $wp_version='6.4';",
    # never candidates
    "wp-content/uploads/gravity_forms/export.sql": b"x" * 100,
    "wp-content/uploads/2023/04/site-backup.sql.gz": b"x" * 90,
    "wp-content/plugins/geoip-detect/GeoIP.dat": b"x" * 80,
    "wp-content/themes/twentytwentyfour/style.css": b"a{color:red}",
    "wp-config.php": b"<?php // live config",
}

#: A walk that measured the site (the gate that proves a payload
#: unreferenced).
LIVE_REFS = {"2023/10/hero-300x200.jpg", "2023/10/hero.jpg"}


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
    """A park-backups Ctx; ftp-mode defaults, overridable per test."""
    fields = dict(
        source="ftp://example.com",
        settings=settings,
        command="park-backups",
        apply=False,
        yes=False,
        backup_dir=tmp_path / "backup",
        wp_url=SITE,
        webroot=WEBROOT,
    )
    fields.update(overrides)
    return Ctx(**fields)


class MutableFakeSource(FakeSource):
    """FakeSource whose rmdir_recursive really removes the subtree.

    tests/fakes.py is not owned by this task and its shared double only
    guards the rmdir (the tests/actions/test_clean_files.py precedent).
    """

    def rmdir_recursive(self, path):
        self._check_deletable(path)
        self._rec("rmdir_recursive", path)
        prefix = f"{path}/"
        for name in [k for k in self.files
                     if k == path or k.startswith(prefix)]:
            del self.files[name]


def _src(files=None):
    src = MutableFakeSource()
    src.files = dict(TREE if files is None else files)
    return src


def patch_walk(monkeypatch, live_refs=LIVE_REFS, *, partial=False,
               pages=()):
    """Point the action's walk seam at a canned WalkResult (no HTTP).

    Returns the call recorder so tests can pin the wiring arguments.
    """
    calls = []

    def fake_walk_site(session, site, settings, timeout_s=30, deadline=None):
        calls.append((session, site, settings, timeout_s))
        return WalkResult(live_refs=set(live_refs), pages=list(pages),
                          forms=[], fetched=1, partial=partial)

    monkeypatch.setattr(park_mod, "walk_site", fake_walk_site)
    return calls


def _park_root(ctx):
    """The park directory the plan named: <base>/<label>-<ts>."""
    return sorted(ctx.backup_dir.glob("parked/*"))


def _plan(tmp_path, monkeypatch, *, ctx=None, files=None, walk=None,
          settings=DEFAULTS):
    """``(action, plan, src, ctx)`` for one run.

    The action INSTANCE is returned because the registry holds a single one
    per process: the plan and the apply of a run share it, which is what
    makes the run's park directory (it carries a timestamp) resolve once.
    """
    src = _src(files)
    ctx = ctx or _ctx(tmp_path, settings=settings)
    patch_walk(monkeypatch, **({"live_refs": LIVE_REFS} if walk is None
                               else walk))
    action = ParkBackupsAction()
    plan = action.plan(ctx, (src, FakeSession(), None))
    return action, plan, src, ctx


def _records(caplog, name, level):
    return [r for r in caplog.records
            if r.name == name and r.levelno == level]


def _zip_contents(path):
    with zipfile.ZipFile(path) as zf:
        return zf.namelist()


# ------------------------------------------------------------- registration


def test_registration():
    record = get_action("park-backups")
    assert record is not None
    assert record.applies == ("ftp", "local")
    assert isinstance(record.action, ParkBackupsAction)  # the instance


# --------------------------------------------------------------------- plan


def test_archive_at_the_webroot_root_is_parked(tmp_path, monkeypatch):
    """The live finding, parked: moved out of the webroot, never deleted."""
    action, plan, src, ctx = _plan(
        tmp_path, monkeypatch,
        files={"wp-content.zip": b"PK\x03\x04" + b"z" * 500},
    )
    assert [(i.category, i.target, i.requires_apply) for i in plan.items] == [
        ("webroot.backup_payload", "wp-content.zip", True),
    ]
    assert plan.est_bytes() == 504
    assert "*.zip" in plan.items[0].detail
    action.apply(ctx, (src, None, None), plan)
    assert plan.items[0].done is True
    # moved OUT: the webroot file is gone and the bytes are parked
    assert "wp-content.zip" not in src.files
    parked = _park_root(ctx)
    assert len(parked) == 1
    copy = parked[0] / "wp-content.zip"
    assert copy.read_bytes() == b"PK\x03\x04" + b"z" * 500
    # the park directory is the action's own dir under --backup-dir
    assert parked[0].parent == ctx.backup_dir / "parked"
    assert parked[0].name.startswith("example.com-")


def test_park_outside_destination_is_honoured(tmp_path, monkeypatch):
    outside = tmp_path / "elsewhere"
    ctx = _ctx(tmp_path, extra={"park_outside": str(outside)})
    _a, plan, src, _c = _plan(tmp_path, monkeypatch, files={"a.zip":
                                                           b"z" * 10}, ctx=ctx)
    action = _a
    assert plan.items[0].requires_apply is True
    action.apply(ctx, (src, None, None), plan)
    assert (outside).exists()
    assert len(list(outside.rglob("a.zip"))) == 1
    assert not (ctx.backup_dir / "parked").exists()


def test_uploads_submission_data_is_never_touched(tmp_path, monkeypatch,
                                                  wpt_caplog):
    """[live] a Gravity Forms submission export is inbound data, never a
    payload: the plan stays empty and nothing removes it."""
    action, plan, src, ctx = _plan(tmp_path, monkeypatch, files={
        "wp-content/uploads/gravity_forms/export.sql": b"x" * 100,
        "wp-content/uploads/2023/04/site-backup.sql.gz": b"x" * 90,
    })
    assert plan.items == []
    action.apply(ctx, (src, None, None), plan)
    assert "wp-content/uploads/gravity_forms/export.sql" in src.files
    assert "wp-content/uploads/2023/04/site-backup.sql.gz" in src.files


def test_plugin_unit_payloads_are_never_candidates(tmp_path, monkeypatch):
    _a, plan, _s, _c = _plan(tmp_path, monkeypatch, files={
        "wp-content/plugins/some-plugin/assets/bundle.zip": b"z" * 40,
    })
    assert plan.items == []


def test_sample_backup_dir_without_a_provable_reference_set_is_advice(
        tmp_path, monkeypatch, wpt_caplog):
    """A dead duplicate webroot with nothing provable about it: the
    exposure is REPORTED (the safety net the live site lacked) and
    nothing is moved."""
    # a PARTIAL walk proves nothing
    action, plan, src, ctx = _plan(
        tmp_path, monkeypatch,
        files={"sample-backup/wp-config.php": b"<?php" + b"d" * 400,
               "sample-backup/index.php": b"<?php" + b"i" * 200},
        walk={"live_refs": LIVE_REFS, "partial": True},
    )
    assert [(i.category, i.target, i.requires_apply, i.bytes_est)
            for i in plan.items] == [
        ("webroot.junk", "sample-backup", False, 610),
    ]
    detail = plan.items[0].detail
    assert "backup_payload_in_webroot" in detail
    assert "guessable URL" in detail
    assert "park-backups" in detail
    assert len(_records(wpt_caplog, "wpt.actions.park_backups",
                        logging.WARNING)) == 1
    action.apply(ctx, (src, None, None), plan)
    assert "sample-backup/index.php" in src.files
    assert not (ctx.backup_dir / "parked").exists()


def test_local_mode_plan_is_advice_only(tmp_path, monkeypatch):
    """A zip cannot represent a move out of the webroot: every local item
    is advice, and the dry run still reports the exposure."""
    ctx = _ctx(tmp_path, source="local", webroot=None,
               zip=Path("site.zip"), sql=None, wp_url=None)
    _a, plan, src, _c = _plan(tmp_path, monkeypatch,
                              files={"wp-content.zip": b"z" * 12}, ctx=ctx)
    assert [(i.category, i.requires_apply) for i in plan.items] == [
        ("webroot.junk", False),
    ]


def test_destination_inside_the_webroot_is_refused_loudly(
        tmp_path, monkeypatch, wpt_caplog):
    """An FTP-relative --park-outside (the operator's real mistake) is
    refused with ONE error naming both paths, and every item degrades."""
    ctx = _ctx(tmp_path, extra={"park_outside":
                                f"{WEBROOT}/parked"})
    action, plan, src, _c = _plan(tmp_path, monkeypatch,
                                 files={"wp-content.zip": b"z" * 12}, ctx=ctx)
    errors = _records(wpt_caplog, "wpt.actions.park_backups", logging.ERROR)
    assert len(errors) == 1
    message = errors[0].getMessage()
    assert f"{WEBROOT}/parked" in message
    assert WEBROOT in message
    assert [(i.category, i.requires_apply) for i in plan.items] == [
        ("webroot.junk", False),
    ]
    action.apply(ctx, (src, None, None), plan)
    assert "wp-content.zip" in src.files


def test_referenced_payload_is_never_moved(tmp_path, monkeypatch, wpt_caplog):
    action, plan, src, ctx = _plan(
        tmp_path, monkeypatch, files={"downloads.zip": b"z" * 10},
        walk={"live_refs": {"downloads.zip"}},
    )
    assert plan.items == []
    action.apply(ctx, (src, None, None), plan)
    assert "downloads.zip" in src.files
    infos = [r.getMessage() for r in
             _records(wpt_caplog, "wpt.actions.park_backups", logging.INFO)]
    assert any("still referenced" in m for m in infos)


def test_oversized_payload_is_advice_not_a_buffer(tmp_path, monkeypatch):
    big = 4096
    settings = load(overrides={"backup_payloads.max_park_file_bytes": big})
    action, plan, src, ctx = _plan(tmp_path, monkeypatch, settings=settings,
                                   files={"huge.tar": b"z" * (big + 1)})
    assert [(i.category, i.requires_apply) for i in plan.items] == [
        ("webroot.junk", False),
    ]
    assert "will not buffer" in plan.items[0].detail
    action.apply(ctx, (src, None, None), plan)
    assert "huge.tar" in src.files


def test_nested_candidates_collapse_into_the_directory(tmp_path, monkeypatch):
    _a, plan, _s, _c = _plan(tmp_path, monkeypatch, files={
        "sample-backup/inner.tar.gz": b"t" * 10,
        "sample-backup/deep/inner.zip": b"z" * 10,
    })
    assert [i.target for i in plan.items] == ["sample-backup"]


def test_plan_never_walks_a_clean_tree(tmp_path, monkeypatch):
    src = _src({"wp-content/themes/x/style.css": b"a{}"})
    ctx = _ctx(tmp_path)
    calls = patch_walk(monkeypatch, LIVE_REFS)
    plan = ParkBackupsAction().plan(ctx, (src, FakeSession(), None))
    assert plan.items == []
    assert calls == []  # no candidate -> no HTTP at all


def test_two_runs_never_share_a_park_directory(tmp_path, monkeypatch):
    """The registered action is a MODULE-LEVEL SINGLETON, so the run's park
    directory (it carries a timestamp and the run's own --backup-dir) is
    resolved per PLAN — a second run inheriting the first one's path would
    park into another run's backup dir and advertise a directory it never
    writes to."""
    action = get_action("park-backups").action
    patch_walk(monkeypatch, LIVE_REFS)
    seen = []
    for name in ("one", "two"):
        ctx = _ctx(tmp_path / name)
        src = _src({"wp-content.zip": b"z" * 4})
        plan = action.plan(ctx, (src, FakeSession(), None))
        seen.append(plan.items[0].detail)
        action.apply(ctx, (src, None, None), plan)
        assert plan.items[0].done is True
    assert seen[0] != seen[1], seen
    for name, detail in zip(("one", "two"), seen):
        assert f"{tmp_path}/{name}/backup/parked/" in detail, detail
    for name in ("one", "two"):
        assert len(list((tmp_path / name / "backup" / "parked").iterdir())) == 1


def test_plan_walk_wiring(tmp_path, monkeypatch):
    src = _src({"wp-content.zip": b"z" * 5})
    session = FakeSession()
    calls = patch_walk(monkeypatch, LIVE_REFS)
    ctx = _ctx(tmp_path)
    ParkBackupsAction().plan(ctx, (src, session, None))
    assert calls == [(session, SITE, DEFAULTS.walk, DEFAULTS.http.timeout_s)]


# -------------------------------------------------------------------- apply


def test_dir_candidate_parks_the_whole_subtree(tmp_path, monkeypatch):
    action, plan, src, ctx = _plan(
        tmp_path, monkeypatch,
        files={"sample-backup/a.php": b"a" * 10,
               "sample-backup/sub/b.php": b"b" * 20},
    )
    assert [(i.target, i.requires_apply, i.bytes_est) for i in plan.items] \
        == [("sample-backup", True, 30)]
    action.apply(ctx, (src, None, None), plan)
    assert plan.items[0].done is True
    parked = _park_root(ctx)[0] / "sample-backup"
    assert (parked / "a.php").read_bytes() == b"a" * 10
    assert (parked / "sub" / "b.php").read_bytes() == b"b" * 20
    assert "sample-backup/a.php" not in src.files
    assert any(op == "rmdir_recursive" and path == "sample-backup"
               for _ts, op, path in src.ops)


def test_R16_dir_is_written_batch_by_batch_not_buffered_whole(
        tmp_path, monkeypatch):
    """A backup directory is written/verified per read batch, so a 1.2 GiB
    dead webroot is never resident at once.  The second read_many call sees
    the first batch's verified copies on disk and the unread third file
    absent — the mechanical proof of streaming."""
    monkeypatch.setattr(park_mod, "_READ_BATCH", 2)
    ctx = _ctx(tmp_path)
    seen: list[list[str]] = []
    copies_at_second_read: list[str] = []

    class StreamingSource(MutableFakeSource):
        def read_many(self, paths, *, max_bytes=None):
            seen.append(list(paths))
            if len(seen) == 2:
                root = _park_root(ctx)[0] / "sample-backup"
                copies_at_second_read.extend(
                    sorted(p.name for p in root.rglob("*") if p.is_file())
                )
            return super().read_many(paths)

    src = StreamingSource()
    src.files = {"sample-backup/a.php": b"a",
                 "sample-backup/b.php": b"b",
                 "sample-backup/c.php": b"c"}
    patch_walk(monkeypatch, LIVE_REFS)
    action = ParkBackupsAction()
    plan = action.plan(ctx, (src, FakeSession(), None))
    action.apply(ctx, (src, None, None), plan)
    assert plan.items[0].done is True
    assert seen == [["sample-backup/a.php", "sample-backup/b.php"],
                    ["sample-backup/c.php"]]
    assert copies_at_second_read == ["a.php", "b.php"]
    assert "sample-backup" not in src.files


def test_R19_directory_batches_carry_the_park_byte_bound(
        tmp_path, monkeypatch, wpt_caplog):
    """R19-P2: directory members bypassed ``backup_payloads.
    max_park_file_bytes`` — ``read_many(batch)`` without ``max_bytes``
    buffered a 3 GiB member whole.  The bound now rides every batch, and
    an oversized member fails the item closed (webroot stays)."""
    settings = load(overrides={"backup_payloads.max_park_file_bytes": 4})
    ctx = _ctx(tmp_path, settings=settings)
    bounds: list[int | None] = []

    class RecordingSource(MutableFakeSource):
        def read_many(self, paths, *, max_bytes=None):
            bounds.append(max_bytes)
            return super().read_many(paths, max_bytes=max_bytes)

    src = RecordingSource()
    src.files = {"sample-backup/ok.php": b"aa",
                 "sample-backup/big.bin": b"x" * 10}
    patch_walk(monkeypatch, LIVE_REFS)
    action = ParkBackupsAction()
    plan = action.plan(ctx, (src, FakeSession(), None))
    action.apply(ctx, (src, None, None), plan)
    assert plan.items[0].done is False
    assert any(path.startswith("sample-backup/") for path in src.files)
    assert bounds == []          # refused BEFORE a read was attempted

    # A directory that fits still carries the SAME configured bound on its
    # read (never None), so the connector can refuse a lying listing.
    small = RecordingSource()
    small.files = {"sample-backup/ok.php": b"aa"}
    plan2 = action.plan(ctx, (small, FakeSession(), None))
    action.apply(ctx, (small, None, None), plan2)
    assert plan2.items[0].done is True
    assert bounds == [4]


def test_R16_dir_read_failure_discards_the_batches_already_parked(
        tmp_path, monkeypatch, wpt_caplog):
    """A later batch's read failure fails the item closed: the copies from
    earlier batches are removed and the webroot directory STAYS."""
    monkeypatch.setattr(park_mod, "_READ_BATCH", 2)
    ctx = _ctx(tmp_path)
    calls: list[list[str]] = []

    class FailingSecondBatch(MutableFakeSource):
        def read_many(self, paths, *, max_bytes=None):
            calls.append(list(paths))
            if len(calls) == 2:
                return {}, {paths[0]: "injected read failure"}
            return super().read_many(paths)

    src = FailingSecondBatch()
    src.files = {"sample-backup/a.php": b"a",
                 "sample-backup/b.php": b"b",
                 "sample-backup/c.php": b"c"}
    patch_walk(monkeypatch, LIVE_REFS)
    action = ParkBackupsAction()
    plan = action.plan(ctx, (src, FakeSession(), None))
    action.apply(ctx, (src, None, None), plan)
    assert plan.items[0].done is False
    assert "sample-backup/a.php" in src.files
    assert not any(op == "rmdir_recursive" for _ts, op, _path in src.ops)
    roots = _park_root(ctx)
    if roots:
        assert not (roots[0] / "sample-backup").exists()


def test_apply_keeps_the_webroot_file_when_the_read_fails(
        tmp_path, monkeypatch, wpt_caplog):
    class UnreadableSource(MutableFakeSource):
        def read_many(self, paths, *, max_bytes=None):
            return {}, {p: "injected read failure" for p in paths}

    src = UnreadableSource()
    src.files = {"wp-content.zip": b"z" * 10}
    patch_walk(monkeypatch, LIVE_REFS)
    ctx = _ctx(tmp_path)
    action = ParkBackupsAction()
    plan = action.plan(ctx, (src, FakeSession(), None))
    action.apply(ctx, (src, None, None), plan)
    assert plan.items[0].done is False
    assert "wp-content.zip" in src.files          # never removed unread
    assert not (ctx.backup_dir / "parked").exists()
    assert len(_records(wpt_caplog, "wpt.actions.park_backups",
                        logging.WARNING)) == 1


def test_apply_fails_the_item_when_the_parked_copy_does_not_verify(
        tmp_path, monkeypatch, wpt_caplog):
    """Verify-after-write: a sha256 mismatch on the re-read removes the copy
    and leaves the webroot file."""
    action, plan, src, ctx = _plan(tmp_path, monkeypatch,
                                   files={"wp-content.zip": b"z" * 32})

    def corrupt(out, data):
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(b"corrupted")
        raise SourceError("injected verify failure")

    monkeypatch.setattr(action, "_write_verified", corrupt)
    action.apply(ctx, (src, None, None), plan)
    assert plan.items[0].done is False
    assert "wp-content.zip" in src.files


def test_write_verified_rejects_a_mismatch(tmp_path, monkeypatch):
    """The primitive itself: a write that does not read back is refused
    (a truncated archive is never mistaken for a parked one)."""
    action = ParkBackupsAction()
    out = tmp_path / "sub" / "a.zip"
    real_replace = Path.replace

    def truncating(self, target):
        self.write_bytes(b"short")
        return real_replace(self, target)

    monkeypatch.setattr(Path, "replace", truncating)
    with pytest.raises(SourceError, match="did not verify"):
        action._write_verified(out, b"z" * 10)
    assert not out.exists()


# ------------------------------------------------------------ registry flow


def _bridge_stack(script, files=None):
    """A fake ftp-mode stack: (FakeSource, FakeSession, Bridge over it)."""
    src = _src(files)
    session = FakeSession(list(script) + [FakeResponse(200, "gone")])
    bridge = Bridge(src, session, WEBROOT, BridgeSettings(), SITE)
    return src, session, bridge


def _purge_ok():
    return FakeResponse(200, json.dumps({"ok": True, "purged": True}))


def test_R22_a_symlink_payload_is_refused_before_anything_is_moved(
        tmp_path):
    """R22-P2: a backup directory containing a symlink was read through
    (parking the target's bytes as a regular file and deleting the link),
    so the webroot no longer matched what was measured.  A link on the
    item or anywhere in its subtree refuses the whole item, before writes."""
    from wpt.types import SourceError

    class LinkSource(MutableFakeSource):
        def __init__(self, links):
            super().__init__()
            self.links = set(links)

        def list_dir(self, path):
            entries = super().list_dir(path)
            for entry in entries:
                if entry.path in self.links:
                    entry.is_link = True
            return entries

    action = ParkBackupsAction()
    file_src = LinkSource({"backup.zip"})
    file_src.files = {"backup.zip": b"PK\x03\x04"}
    dest = tmp_path / "parked" / "backup.zip"
    with pytest.raises(SourceError, match="symbolic link"):
        action._park(file_src, "backup.zip", dest, None)
    assert file_src.files == {"backup.zip": b"PK\x03\x04"}
    assert not dest.exists()

    dir_src = LinkSource({"old-site"})
    dir_src.files = {"old-site": b"", "old-site/backup.zip": b"PK\x03\x04"}
    dest_dir = tmp_path / "parked" / "old-site"
    with pytest.raises(SourceError, match="symbolic link"):
        action._park(dir_src, "old-site", dest_dir, None)
    assert set(dir_src.files) == {"old-site", "old-site/backup.zip"}
    assert not dest_dir.exists()


def test_registry_dry_run(tmp_path, monkeypatch, capsys, wpt_caplog):
    monkeypatch.setattr(registry_mod, "_stack",
                        lambda ctx: (_src({"wp-content.zip": b"z" * 8}),
                                     FakeSession(), None))
    patch_walk(monkeypatch, LIVE_REFS)
    ctx = _ctx(tmp_path, apply=False, yes=True)
    assert run_action(ctx, "park-backups") == 0
    out = capsys.readouterr().out
    assert "webroot.backup_payload" in out
    assert "wp-content.zip" in out
    # dry run: nothing moved, no bridge call, no purge
    assert not (ctx.backup_dir / "parked").exists()
    assert any("dry run" in r.getMessage()
               for r in _records(wpt_caplog, "wpt.actions", logging.INFO))


def test_registry_ftp_apply_end_to_end(tmp_path, monkeypatch, capsys):
    script = [_purge_ok()]
    monkeypatch.setattr(
        registry_mod, "_stack",
        lambda ctx: _bridge_stack(script, {"wp-content.zip": b"z" * 8}),
    )
    patch_walk(monkeypatch, LIVE_REFS)
    ctx = _ctx(tmp_path, apply=True, yes=True)
    assert run_action(ctx, "park-backups") == 0
    out = capsys.readouterr().out
    assert "wp-content.zip" in out
    # the pre-action snapshot captured the payload BEFORE it moved
    manifests = sorted((ctx.backup_dir).glob("example.com/*/manifest.json"))
    assert len(manifests) == 1
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    assert [f["path"] for f in manifest["files"]] == ["wp-content.zip"]
    # the payload is parked under the same backup dir
    parked = list((ctx.backup_dir / "parked").rglob("wp-content.zip"))
    assert len(parked) == 1
    assert parked[0].read_bytes() == b"z" * 8


def test_registry_local_mode_applies_nothing(tmp_path, monkeypatch, capsys):
    """A local rehearsal cannot represent a move out of the webroot: the
    plan is advice, the rehearsal is a no-op and rc stays 0."""
    zip_path = tmp_path / "site.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("site.test/wp-content.zip", b"z" * 8)
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (
        MutableZipSource(zip_path), None, None))
    patch_walk(monkeypatch, LIVE_REFS)
    ctx = _ctx(tmp_path, source="local", webroot=None, wp_url=None,
               zip=zip_path, sql=None, apply=True, yes=True)
    assert run_action(ctx, "park-backups") == 0
    out = capsys.readouterr().out
    assert "backup_payload_in_webroot" in out
    # the original zip is untouched and the rehearsal twin still has it
    assert "site.test/wp-content.zip" in _zip_contents(zip_path)
    twins = list(tmp_path.glob("site-rehearsed-*.zip"))
    assert len(twins) == 1
    assert "site.test/wp-content.zip" in _zip_contents(twins[0])


def test_R23_plan_walk_is_bounded_by_the_run_deadline(
        tmp_path, monkeypatch):
    """R23-P2: ``plan`` listed the whole source before any deadline check."""
    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    src = _src()
    ctx = _ctx(tmp_path)
    spent = Deadline(0.0)
    monkeypatch.setattr(park_mod.Deadline, "from_ctx",
                        classmethod(lambda cls, ctx: spent))
    with pytest.raises(DeadlineExceeded):
        ParkBackupsAction().plan(ctx, (src, FakeSession(), None))


class _RemoveSpent:
    """A deadline that expires only at the destructive remove step."""

    def check(self, context):
        if "remove" in context:
            from wpt.types import DeadlineExceeded
            raise DeadlineExceeded(f"expired at {context}")


def test_R23_no_delete_or_rmdir_after_the_budget_expires(tmp_path):
    """R23-P2: the deadline was checked before each read batch but NOT
    before ``delete``/``rmdir_recursive``, so a run whose budget expired
    during the final batch still removed the payload."""
    from wpt.types import DeadlineExceeded

    action = ParkBackupsAction()
    deadline = _RemoveSpent()
    src = MutableFakeSource()
    src.files = {"stray.zip": b"PAYLOAD"}
    with pytest.raises(DeadlineExceeded):
        action._park_file(src, "stray.zip", tmp_path / "dest" / "stray.zip",
                          deadline)
    assert src.files["stray.zip"] == b"PAYLOAD"
    assert not any(op == "delete" for _ts, op, _path in src.ops)

    src = MutableFakeSource()
    src.files = {"updraft/a.php": b"a"}
    with pytest.raises(DeadlineExceeded):
        action._park_dir(src, "updraft", tmp_path / "dest2", deadline)
    assert src.files["updraft/a.php"] == b"a"
    assert not any(op == "rmdir_recursive" for _ts, op, _path in src.ops)
