"""Tests for MutableZipSource (wpt.sources.zipwriter) — the rehearsal target.

Real zips built in tmp_path; deterministic, no network. Test -> behavior map:
  test_staged_write_shadows_original ......... read-through: staged bytes win,
        untouched siblings read from the archive, the zip FILE on disk is
        byte-identical before/after every mutation
  test_walk_reflects_overlay_exactly ......... original set - deleted +
        staged with exact (path, is_dir, size) triplets; list_dir consistent;
        exists/size follow the overlay; a staged NEW path (and its new dir)
        appears, a deleted path disappears even from walk
  test_overlay_keeps_original_metadata_and_stages_unknown  an untouched
        original keeps its zip mode/mtime; staged bytes have no zip entry
        and stay unknown
  test_delete_then_recreate_clears_tombstone .. delete a.jpg then write_bytes
        a.jpg: present again with the new bytes (tombstone cleared)
  test_emptied_dir_vanishes_even_from_walk ... deleting the last file in a
        directory removes the directory from walk/exists (dirs derive from
        surviving paths)
  test_delete_missing_path_is_idempotent ...... deleting a missing path twice
        raises nothing
  test_guard_matches_ftp_discipline ........... wp-config.php/.htaccess
        writable ONLY with allow_config=True; core PROTECTED members never
        writable even with it; delete/rmdir_recursive refuse PROTECTED paths
        with the shared guard's SourceError
  test_guard_discipline_is_exactly_the_shared_guard  no guard shadowing: the
        discipline is types.Source's, the same FtpSource applies — so nested
        core paths pass here exactly as a live ftp STOR would (PROTECTED is
        exact-membership; reported to the coordinator)
  test_rmdir_recursive_stages_subtree_removal . the whole subtree vanishes
        from the overlay; the archive on disk still carries it
  test_materialize_builds_faithful_host_export_twin  output re-read by a
        fresh ZipSource: same auto-detected root, same webroot-relative
        paths/sizes/bytes as the overlay; raw names re-prefixed with root;
        real trailing-slash dir entries; compress_type preserved for
        streamed originals
  test_materialize_refusals .................. dest == original refused;
        an existing dest refused and left untouched; no .tmp left behind on
        success
  test_materialize_normalizes_attrs_for_every_entry  live defect: staged
        entries wrote 0600 and DOS-archive-bit originals copied verbatim
        (create_system Unix -> unix mode 0o40, unreadable extracts) —
        every OUTPUT entry from the mixed-attrs fixture (DOS 0x20, 0600,
        stored JPEG, dir entry) carries EXACTLY files (0o100644<<16)|0x20 /
        dirs (0o40755<<16)|0x10 with create_system=3
  test_materialize_preserves_content_compression_timestamps  attrs change
        ONLY: bytes identical, compress_type preserved (stored JPEG stays
        STORED), date_time round-trips exactly
  test_materialized_extract_modes_readable_by_all  extract simulation
        (zipfile read + mode math): every entry extracts 0644/0755 —
        readable by all uids, never the 0600/0o40 shapes
  test_rehearsal_clean_files_runs_unchanged .. the REAL clean-files action
        plans + applies over the overlay with zero edits; the twin carries
        the cleanup; the original stays byte-identical
  test_plain_zipsource_still_refuses ......... the opt-in pin: mutating ops
        on a plain ZipSource still raise NotWritableError
"""

import zipfile
from datetime import datetime, timezone

import pytest

from wpt.actions.clean_files import CleanFilesAction
from wpt.cli import Ctx
from wpt.settings import load
from wpt.sources.zip import ZipSource
from wpt.sources.zipwriter import MutableZipSource
from wpt.types import NotWritableError, Source, SourceError

# Normalized materialized attrs (the deployability contract): regular
# files -rw-r--r-- + the DOS archive bit, dirs drwxr-xr-x + the DOS
# directory bit, Unix host system so every extractor parses the mode word.
FILE_ATTR = (0o100644 << 16) | 0x20
DIR_ATTR = (0o40755 << 16) | 0x10
DT = (2023, 1, 2, 3, 4, 4)  # even second: zip DOS time keeps 2s units


@pytest.fixture()
def zip_path(tmp_path):
    """A flat (rootless) archive with junk, a stale dir and survivors."""
    p = tmp_path / "site.zip"
    with zipfile.ZipFile(p, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.jpg", b"AAAA")
        zf.writestr("readme.html", b"JUNK")
        zf.writestr("wp-config.php", b"<?php config")
        zf.writestr("wp-content/keep.txt", b"KEEP")
        zf.writestr("wp-content/uploads/b.png", b"PNG")
        zf.writestr("wp-content/uploads/readme.txt", "hi")
        zf.writestr("wp-content/et_temp/cache.txt", b"X" * 10)
    return p


@pytest.fixture()
def nested_zip_path(tmp_path):
    """A host-export archive nesting everything under one site dir."""
    p = tmp_path / "export.zip"
    with zipfile.ZipFile(p, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("example.com/", "")  # the root dir entry
        zf.writestr("example.com/wp-config.php", b"<?php config")
        zf.writestr("example.com/readme.html", b"JUNK")
        zf.writestr("example.com/wp-content/uploads/keep.txt", b"KEEP")
        stored = zipfile.ZipInfo(
            "example.com/wp-content/uploads/2023/a.jpg"
        )
        stored.compress_type = zipfile.ZIP_STORED  # stream-preservation pin
        zf.writestr(stored, b"OLD-JPG")
    return p


@pytest.fixture()
def mixed_attrs_zip(tmp_path):
    """The input-attr shapes that broke live rehearsals: a DOS-archive-bit
    entry (external_attr 0x20 — no unix mode word), an owner-only 0600
    entry, a stored JPEG and a dir entry, each with pinned compression
    and timestamp."""
    p = tmp_path / "mixed.zip"
    with zipfile.ZipFile(p, "w") as zf:
        dos = zipfile.ZipInfo("dos-bit.txt", date_time=DT)
        dos.external_attr = 0x20  # DOS archive bit only
        dos.compress_type = zipfile.ZIP_DEFLATED
        zf.writestr(dos, b"DOS")
        locked = zipfile.ZipInfo("locked.php", date_time=DT)
        locked.external_attr = 0o100600 << 16  # -rw------- (owner-only)
        locked.compress_type = zipfile.ZIP_DEFLATED
        zf.writestr(locked, b"<?php locked")
        stored = zipfile.ZipInfo("wp-content/uploads/2023/photo.jpg",
                                 date_time=DT)
        stored.compress_type = zipfile.ZIP_STORED
        zf.writestr(stored, b"\xff\xd8JPEG-BYTES")
        dod = zipfile.ZipInfo("wp-content/uploads/2023/", date_time=DT)
        dod.external_attr = 0x10  # DOS directory bit only, no unix mode
        zf.writestr(dod, b"")
    return p


def _walk_set(src):
    return {(e.path, e.is_dir, e.size) for e in src.walk()}


# ----------------------------------------------------------------- overlay


def test_staged_write_shadows_original(zip_path):
    before = zip_path.read_bytes()
    src = MutableZipSource(zip_path)
    src.write_bytes("wp-content/uploads/b.png", b"REPLACED")
    assert src.read_bytes("wp-content/uploads/b.png") == b"REPLACED"
    assert src.size("wp-content/uploads/b.png") == len(b"REPLACED")
    # untouched siblings still read from the archive
    assert src.read_bytes("a.jpg") == b"AAAA"
    src.close()
    assert zip_path.read_bytes() == before  # the original file is immutable


def test_walk_reflects_overlay_exactly(zip_path):
    src = MutableZipSource(zip_path)
    src.write_bytes("newdir/staged.txt", b"STAGED")  # a NEW path + its dir
    src.delete("wp-content/uploads/b.png")  # a deleted original
    assert _walk_set(src) == {
        ("a.jpg", False, 4),
        ("newdir", True, 0),
        ("newdir/staged.txt", False, 6),
        ("readme.html", False, 4),
        ("wp-config.php", False, len(b"<?php config")),
        ("wp-content", True, 0),
        ("wp-content/et_temp", True, 0),
        ("wp-content/et_temp/cache.txt", False, 10),
        ("wp-content/keep.txt", False, 4),
        ("wp-content/uploads", True, 0),
        ("wp-content/uploads/readme.txt", False, 2),
    }
    # list_dir stays consistent with walk (children only, dirs derived)
    assert {e.path for e in src.list_dir("")} == {
        "a.jpg", "newdir", "readme.html", "wp-config.php", "wp-content",
    }
    assert {e.path for e in src.list_dir("wp-content/uploads")} == {
        "wp-content/uploads/readme.txt",
    }
    # exists/size reflect staging
    assert src.exists("newdir/staged.txt") is True
    assert src.size("newdir/staged.txt") == 6
    assert src.exists("wp-content/uploads/b.png") is False
    with pytest.raises(SourceError):
        src.size("wp-content/uploads/b.png")
    assert src.size("wp-content/uploads/readme.txt") == 2


def test_overlay_keeps_original_metadata_and_stages_unknown(tmp_path):
    """An untouched original file keeps the zip entry's mode/mtime; staged
    bytes have no zip entry of their own (and one they shadow no longer
    describes them), so both facts stay unknown rather than describing the
    old entry."""
    p = tmp_path / "meta.zip"
    info = zipfile.ZipInfo("wp-content/uploads/keep.txt",
                           date_time=(2021, 4, 5, 6, 7, 8))
    info.external_attr = 0o100640 << 16
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr(info, b"KEEP")
    src = MutableZipSource(p, root="")
    entries = {e.path: e for e in src.list_dir("wp-content/uploads")}
    keep = entries["wp-content/uploads/keep.txt"]
    assert keep.mode == 0o640
    assert keep.mtime == int(
        datetime(2021, 4, 5, 6, 7, 8, tzinfo=timezone.utc).timestamp())
    src.write_bytes("wp-content/uploads/new.txt", b"NEW")
    staged = {e.path: e for e in src.list_dir("wp-content/uploads")}[
        "wp-content/uploads/new.txt"]
    assert staged.mode is None and staged.mtime is None


def test_delete_then_recreate_clears_tombstone(zip_path):
    src = MutableZipSource(zip_path)
    src.delete("a.jpg")
    assert src.exists("a.jpg") is False
    src.write_bytes("a.jpg", b"REBORN")
    assert src.exists("a.jpg") is True
    assert src.read_bytes("a.jpg") == b"REBORN"
    assert ("a.jpg", False, len(b"REBORN")) in _walk_set(src)


def test_emptied_dir_vanishes_even_from_walk(zip_path):
    src = MutableZipSource(zip_path)
    src.delete("wp-content/uploads/b.png")
    src.delete("wp-content/uploads/readme.txt")
    paths = {e.path for e in src.walk()}
    assert "wp-content/uploads" not in paths  # no surviving children -> gone
    assert "wp-content/et_temp/cache.txt" in paths  # the rest of the tree stays
    assert src.exists("wp-content/uploads") is False


def test_ZIP_4_overlay_keeps_an_explicit_empty_directory(tmp_path):
    """The rehearsal twin must list and materialize an archive's explicit
    empty directory exactly as the plain ZipSource does."""
    p = tmp_path / "empty-dir.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("keep.txt", b"keep")
        zf.writestr("wp-content/uploads/", b"")
    plain = ZipSource(p, root="")
    assert {entry.path for entry in plain.list_dir("")} == {
        "keep.txt", "wp-content"}
    src = MutableZipSource(p, root="")
    assert "wp-content" in {entry.path for entry in src.list_dir("")}
    assert "wp-content/uploads" in {entry.path for entry in src.walk()}
    assert src.exists("wp-content/uploads") is True
    out = src.materialize(tmp_path / "out.zip")
    with zipfile.ZipFile(out) as zf:
        names = set(zf.namelist())
    assert "wp-content/uploads/" in names
    assert "keep.txt" in names
    src.close()
    plain.close()


def test_ZIP_4_deleting_an_explicit_empty_directory_removes_it(tmp_path):
    p = tmp_path / "empty-dir.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("keep.txt", b"keep")
        zf.writestr("wp-content/uploads/", b"")
    src = MutableZipSource(p, root="")
    src.rmdir_recursive("wp-content/uploads")
    assert src.exists("wp-content/uploads") is False
    out = src.materialize(tmp_path / "out.zip")
    with zipfile.ZipFile(out) as zf:
        assert "wp-content/uploads/" not in set(zf.namelist())
    src.close()


def test_delete_missing_path_is_idempotent(zip_path):
    src = MutableZipSource(zip_path)
    src.delete("never/existed.txt")  # no error
    src.delete("never/existed.txt")  # still no error
    assert src.exists("never/existed.txt") is False


# ------------------------------------------------------------------- guard


def test_guard_matches_ftp_discipline(zip_path):
    src = MutableZipSource(zip_path)
    # config files: writable ONLY with allow_config (the harden/restore
    # flow); the shared guard logs its own audit line for the unlocked write
    with pytest.raises(NotWritableError):
        src.write_bytes("wp-config.php", b"x")
    src.write_bytes("wp-config.php", b"hardened", allow_config=True)
    assert src.read_bytes("wp-config.php") == b"hardened"
    src.write_bytes(".htaccess", b"deny", allow_config=True)  # a new file stages
    assert src.read_bytes(".htaccess") == b"deny"
    # core paths: never writable — allow_config does not unlock them
    for core in ("index.php", "wp-admin", "wp-admin/", "wp-includes", "wp-includes/"):
        with pytest.raises(NotWritableError):
            src.write_bytes(core, b"x", allow_config=True)
    # delete/rmdir refuse protected paths identically (the shared guard's
    # SourceError — the same refusal a live ftp run gets)
    for path in ("wp-config.php", ".htaccess", "index.php", "wp-admin", "wp-includes"):
        with pytest.raises(SourceError):
            src.delete(path)
        with pytest.raises(SourceError):
            src.rmdir_recursive(path)


def test_guard_discipline_is_exactly_the_shared_guard(zip_path):
    # MutableZipSource shadows NO guard: the write/delete discipline is the
    # inherited shared guard (types.Source) — the same one FtpSource
    # applies — so a rehearsal refuses and permits exactly what the live
    # run would. Since the coordinator's prefix-recursive write-guard fix,
    # nested core paths (wp-admin/**, wp-includes/**) are refused on the
    # WRITE path in both sources alike, while deletes inside them stay
    # allowed (junk removal) — pinned here against BOTH sides of the rule.
    assert MutableZipSource._check_writable is Source._check_writable
    assert MutableZipSource._check_deletable is Source._check_deletable
    src = MutableZipSource(zip_path)
    with pytest.raises(NotWritableError):
        src.write_bytes("wp-admin/includes/x", b"x")
    with pytest.raises(NotWritableError):
        src.write_bytes("wp-includes/js/evil.js", b"x")
    with pytest.raises(NotWritableError):
        src.write_bytes("wp-admin", b"x")
    # deletes INSIDE core dirs stay allowed (junk removal) — staging only
    src.delete("wp-admin/error_log")
    with pytest.raises(SourceError):
        src.delete("wp-admin")  # the core dir itself stays undeletable


# ---------------------------------------------------------- rmdir_recursive


def test_rmdir_recursive_stages_subtree_removal(zip_path):
    src = MutableZipSource(zip_path)
    src.rmdir_recursive("wp-content/uploads")
    paths = {e.path for e in src.walk()}
    assert "wp-content/uploads" not in paths
    assert "wp-content/uploads/b.png" not in paths
    assert "wp-content/uploads/readme.txt" not in paths
    assert "wp-content/keep.txt" in paths
    assert src.exists("wp-content/uploads") is False
    # staged only — the archive on disk still carries the subtree
    with zipfile.ZipFile(zip_path) as zf:
        assert "wp-content/uploads/b.png" in zf.namelist()


# -------------------------------------------------------------- materialize


def test_materialize_builds_faithful_host_export_twin(nested_zip_path, tmp_path):
    src = MutableZipSource(nested_zip_path)
    assert src.root == "example.com"  # auto-detected, as the stack uses
    src.delete("readme.html")
    src.write_bytes("wp-content/brandnew/x.txt", b"NEWDIR")  # staged new dir
    src.write_bytes("wp-config.php", b"<?php hardened", allow_config=True)
    overlay = {e.path: e for e in src.walk()}
    dest = tmp_path / "cleaned" / "twin.zip"  # parents are created
    assert src.materialize(dest) == dest
    # raw archive names: SAME names as the original zip (re-prefixed with
    # the root) + real trailing-slash dir entries
    with zipfile.ZipFile(dest) as zf:
        infos = {i.filename: i for i in zf.infolist()}
        assert infos["example.com/"].is_dir()  # the root dir entry
        assert infos["example.com/wp-content/"].is_dir()
        assert infos["example.com/wp-content/brandnew/"].is_dir()
        assert "example.com/readme.html" not in infos  # deleted
        # streamed originals keep their compress_type; staged entries deflated
        assert infos[
            "example.com/wp-content/uploads/2023/a.jpg"
        ].compress_type == zipfile.ZIP_STORED
        assert infos[
            "example.com/wp-content/uploads/keep.txt"
        ].compress_type == zipfile.ZIP_DEFLATED
        assert infos["example.com/wp-config.php"].compress_type == (
            zipfile.ZIP_DEFLATED
        )
        assert zf.read("example.com/wp-config.php") == b"<?php hardened"
    # a fresh ZipSource over the OUTPUT auto-detects the same root and
    # resolves the same webroot-relative paths/sizes/bytes as the overlay
    twin = ZipSource(dest)
    assert twin.root == "example.com"
    twin_entries = {e.path: e for e in twin.walk()}
    assert set(twin_entries) == set(overlay)
    for path, entry in twin_entries.items():
        assert (entry.is_dir, entry.size) == (
            (overlay[path].is_dir, overlay[path].size)
        )
        if not entry.is_dir:
            assert twin.read_bytes(path) == src.read_bytes(path)


def test_materialize_refusals(tmp_path, nested_zip_path):
    src = MutableZipSource(nested_zip_path)
    # never the original path
    with pytest.raises(SourceError, match="original"):
        src.materialize(nested_zip_path)
    # dest must not already exist; the existing file is left untouched
    existing = tmp_path / "exists.zip"
    existing.write_bytes(b"precious")
    with pytest.raises(SourceError, match="exists"):
        src.materialize(existing)
    assert existing.read_bytes() == b"precious"
    # success: tmp-then-rename, nothing .tmp left behind
    dest = tmp_path / "out.zip"
    src.materialize(dest)
    assert dest.exists()
    assert not (tmp_path / "out.tmp").exists()
    assert list(tmp_path.glob("*.tmp")) == []


def test_R25_materialize_never_replaces_a_dest_that_appeared(
        tmp_path, nested_zip_path, monkeypatch):
    """R25-P2: the precheck ``dest.exists()`` followed by ``os.replace`` was
    a check-then-act race: a concurrent run (or the operator) creating the
    destination between the check and publication lost its bytes.  Publish
    with the atomic no-replace ``os.link``."""
    from wpt.sources import zipwriter as zipwriter_mod

    src = MutableZipSource(nested_zip_path)
    dest = tmp_path / "raced.zip"
    real_zipfile = zipwriter_mod.zipfile.ZipFile

    def raced(*args, **kwargs):
        # The destination appears AFTER the precheck, while the archive is
        # being assembled.
        if not dest.exists():
            dest.write_bytes(b"sentinel-bytes")
        return real_zipfile(*args, **kwargs)

    monkeypatch.setattr(zipwriter_mod.zipfile, "ZipFile", raced)
    with pytest.raises(SourceError, match="already exists"):
        src.materialize(dest)
    assert dest.read_bytes() == b"sentinel-bytes"
    assert list(tmp_path.glob("*.wip")) == []


def test_R25_materialize_wip_is_journaled_before_creation(
        tmp_path, nested_zip_path, monkeypatch):
    """R25-P2: mkstemp created the ``.wip`` before its name was assigned, so
    a stop on that boundary left a file no finally could remove.  The name is
    journaled first; a stop raised exactly at creation is cleaned up."""
    from wpt.sources import zipwriter as zipwriter_mod
    from wpt.types import StopRequested

    src = MutableZipSource(nested_zip_path)
    real_open = zipwriter_mod.os.open

    def stop_at_wip(path, flags, mode=0o777, *, dir_fd=None):
        fd = real_open(path, flags, mode, dir_fd=dir_fd)
        if str(path).endswith(".wip"):
            raise StopRequested("injected stop at .wip creation")
        return fd

    monkeypatch.setattr(zipwriter_mod.os, "open", stop_at_wip)
    with pytest.raises(StopRequested):
        src.materialize(tmp_path / "out.zip")
    assert list(tmp_path.glob("*.wip")) == []
    assert not (tmp_path / "out.zip").exists()


def test_materialize_normalizes_attrs_for_every_entry(mixed_attrs_zip,
                                                       tmp_path):
    # Live defect: staged entries were written 0600 (zipfile's writestr
    # default for a plain name) and original attrs copied VERBATIM — a
    # DOS-archive-bit 0x20 entry with create_system Unix parses as unix
    # mode 0o40, so an extracted rehearsal left files unreadable by the
    # serving uid (one live run: 27,352 owner-unreadable files). Every
    # OUTPUT entry carries the explicit deployable attrs instead.
    src = MutableZipSource(mixed_attrs_zip)
    src.write_bytes("staged.php", b"<?php new")  # the staged-NEW path
    dest = tmp_path / "rehearsed.zip"
    src.materialize(dest)
    src.close()
    with zipfile.ZipFile(dest) as zf:
        infos = zf.infolist()
        assert {i.filename for i in infos} == {
            "wp-content/", "wp-content/uploads/", "wp-content/uploads/2023/",
            "dos-bit.txt", "locked.php", "staged.php",
            "wp-content/uploads/2023/photo.jpg",
        }
        for info in infos:
            assert info.create_system == 3, info.filename  # Unix host system
            expected = DIR_ATTR if info.is_dir() else FILE_ATTR
            assert info.external_attr == expected, info.filename


def test_materialize_preserves_content_compression_timestamps(mixed_attrs_zip,
                                                               tmp_path):
    # Normalization touches ONLY the attribute word: content bytes are
    # identical, compress_type survives (a stored JPEG stays STORED) and
    # date_time round-trips exactly.
    src = MutableZipSource(mixed_attrs_zip)
    src.write_bytes("staged.php", b"<?php new")
    dest = tmp_path / "rehearsed.zip"
    src.materialize(dest)
    src.close()
    with zipfile.ZipFile(dest) as zf:
        assert zf.read("dos-bit.txt") == b"DOS"
        assert zf.read("locked.php") == b"<?php locked"
        assert zf.read("wp-content/uploads/2023/photo.jpg") == b"\xff\xd8JPEG-BYTES"
        assert zf.read("staged.php") == b"<?php new"
        assert (zf.getinfo("wp-content/uploads/2023/photo.jpg").compress_type
                == zipfile.ZIP_STORED)
        assert zf.getinfo("dos-bit.txt").compress_type == zipfile.ZIP_DEFLATED
        for name in ("dos-bit.txt", "locked.php",
                     "wp-content/uploads/2023/photo.jpg"):
            assert zf.getinfo(name).date_time == DT


def test_materialized_extract_modes_readable_by_all(mixed_attrs_zip,
                                                     tmp_path):
    # Extract simulation: a unix-mode-aware extractor (unzip, host panels,
    # zipfile) applies external_attr >> 16 when create_system is Unix.
    # Every file must extract -rw-r--r-- (readable by EVERY uid a shared
    # host serves with) and every dir drwxr-xr-x — never the 0600 or 0o40
    # shapes the input carried.
    src = MutableZipSource(mixed_attrs_zip)
    src.write_bytes("staged.php", b"<?php new")
    dest = tmp_path / "rehearsed.zip"
    src.materialize(dest)
    src.close()
    with zipfile.ZipFile(dest) as zf:
        for info in zf.infolist():
            assert info.create_system == 3, info.filename
            mode = info.external_attr >> 16
            if info.is_dir():
                assert mode == 0o40755, info.filename  # drwxr-xr-x
            else:
                assert mode == 0o100644, info.filename  # -rw-r--r--
            assert mode & 0o004, info.filename  # other-read


def test_materialize_streams_an_oversized_entry_in_zip64(mixed_attrs_zip,
                                                           tmp_path,
                                                           monkeypatch):
    # A streamed entry's size is unknown when zipfile writes its header, so
    # the 32-bit format is chosen and the copy raises "File size too large,
    # try using force_zip64" the moment it crosses the threshold — a
    # rehearsal of a webroot holding one big uploaded video would die on the
    # copy, with an operator-facing traceback for a condition nothing about
    # the site can fix. The source entry's real size IS known, so the writer
    # asks for zip64 exactly when it is needed. The threshold is lowered
    # instead of writing 2 GiB: zipfile reads the same module constant the
    # writer does, so the branch under test is the real one.
    monkeypatch.setattr(zipfile, "ZIP64_LIMIT", 8)
    src = MutableZipSource(mixed_attrs_zip)
    dest = tmp_path / "rehearsed.zip"
    src.materialize(dest)   # the pre-fix RuntimeError lands here
    src.close()
    with zipfile.ZipFile(dest) as zf:
        # every entry still reads back whole, and the normalized attrs
        # survive the wide-format write
        assert zf.read("wp-content/uploads/2023/photo.jpg") == \
            b"\xff\xd8JPEG-BYTES"
        assert zf.read("locked.php") == b"<?php locked"
        assert zf.read("dos-bit.txt") == b"DOS"
        for info in zf.infolist():
            assert info.create_system == 3
            assert info.external_attr == (
                DIR_ATTR if info.is_dir() else FILE_ATTR), info.filename
        assert zf.getinfo("wp-content/uploads/2023/photo.jpg").compress_type \
            == zipfile.ZIP_STORED  # still the source's compression


def test_materialize_does_not_force_zip64_on_ordinary_entries(mixed_attrs_zip,
                                                               tmp_path):
    # The counterpart pin: force_zip64 is driven by the ENTRY's size, never
    # applied blanket. A forced zip64 write adds a 0x0001 extra field to
    # every entry's header, so its ABSENCE on an ordinary archive proves
    # the wide format is only used when a single entry needs it — a normal
    # rehearsal zip stays byte-compatible with every extractor.
    src = MutableZipSource(mixed_attrs_zip)
    src.write_bytes("staged.php", b"<?php new")
    dest = tmp_path / "rehearsed.zip"
    src.materialize(dest)
    src.close()
    with zipfile.ZipFile(dest) as zf:
        for info in zf.infolist():
            assert not info.extra.startswith(b"\x01\x00"), info.filename


# --------------------------------------------------- the rehearsal invariant


def test_rehearsal_clean_files_runs_unchanged(zip_path, tmp_path):
    # THE point of the class: the real action plans + applies over the
    # overlay with ZERO edits (the registry's local-mode write refusal is
    # a CLI seam, bypassed here by calling the action directly), and the
    # original zip stays byte-identical.
    before = zip_path.read_bytes()
    ctx = Ctx(
        source="local", zip=zip_path, settings=load(), command="clean-files",
        apply=True, yes=True, backup_dir=tmp_path / "backup",
        wp_url="https://example.com",
    )
    src = MutableZipSource(zip_path)
    action = CleanFilesAction()
    plan = action.plan(ctx, (src, None, None))
    assert [(i.category, i.target) for i in plan.items] == [
        ("webroot.junk", "readme.html"),
        ("webroot.stale", "wp-content/et_temp"),
    ]
    applied = action.apply(ctx, (src, None, None), plan)
    assert all(i.done for i in applied.items)
    dest = src.materialize(tmp_path / "rehearsed.zip")
    src.close()
    assert zip_path.read_bytes() == before  # the original is immutable
    twin = ZipSource(dest)
    assert {e.path for e in twin.walk() if not e.is_dir} == {
        "a.jpg",
        "wp-config.php",
        "wp-content/keep.txt",
        "wp-content/uploads/b.png",
        "wp-content/uploads/readme.txt",
    }
    assert twin.read_bytes("wp-content/uploads/b.png") == b"PNG"


# ---------------------------------------------------------------- opt-in pin


def test_plain_zipsource_still_refuses(zip_path):
    # the opt-in pin: mutability exists ONLY via MutableZipSource; the
    # plain connector keeps its v1 read-only contract unchanged
    src = ZipSource(zip_path)
    with pytest.raises(NotWritableError, match="read-only"):
        src.write_bytes("wp-content/x.txt", b"x")
    with pytest.raises(NotWritableError, match="read-only"):
        src.delete("wp-content/keep.txt")
    with pytest.raises(NotWritableError, match="read-only"):
        src.rmdir_recursive("wp-content/uploads")
    src.close()


# ------------------------------------------------------------------- rename

CORE_ZIP = {
    "wp-includes/version.php": b"OLD",
    "wp-includes/js/old.js": b"OLDJS",
    "wp-admin/index.php": b"ADMIN",
    "wp-content/plugins/hello.php": b"PLUGIN",
}


@pytest.fixture()
def core_zip(tmp_path):
    p = tmp_path / "core.zip"
    with zipfile.ZipFile(p, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel, blob in CORE_ZIP.items():
            zf.writestr(rel, blob)
    return p


def test_rename_rekeys_a_whole_tree_in_the_overlay(core_zip):
    """The local twin of the FTP tree swap: staged, original and tombstoned
    paths all move with the directory, and NOTHING is rewritten (only
    materialize() turns paths back into bytes)."""
    src = MutableZipSource(core_zip)
    src.write_bytes("wp-includes.wpt-new/version.php", b"NEW", allow_core=True)
    src.write_bytes("wp-includes.wpt-new/js/new.js", b"NEWJS")
    src.delete("wp-admin/index.php")            # a tombstone inside wp-admin
    src.rename("wp-includes", "wp-includes.wpt-old", allow_core=True)
    src.rename("wp-includes.wpt-new", "wp-includes", allow_core=True)
    # the swapped tree carries the staged bytes only
    assert src.read_bytes("wp-includes/version.php") == b"NEW"
    assert src.read_bytes("wp-includes/js/new.js") == b"NEWJS"
    assert not src.exists("wp-includes/js/old.js")
    assert not src.exists("wp-includes.wpt-new")
    # the parked tree still holds the original bytes, untouched
    assert src.read_bytes("wp-includes.wpt-old/version.php") == b"OLD"
    # the tombstone MOVED with its tree: wp-admin is still deleted
    assert not src.exists("wp-admin/index.php")
    assert not src.exists("wp-admin.wpt-old/index.php")
    # and wp-content/ never moved
    assert src.read_bytes("wp-content/plugins/hello.php") == b"PLUGIN"
    src.close()


def test_rename_replaces_an_existing_destination_tree(tmp_path):
    """P2: RNTO replaces the destination; the overlay merged into it and a
    materialized rehearsal kept a stale file the live swap would remove."""
    path = tmp_path / "two.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("a/old.txt", b"OLD")
        zf.writestr("b/new.txt", b"NEW")
    src = MutableZipSource(path)
    src.rename("b", "a")

    assert not src.exists("a/old.txt")
    assert src.read_bytes("a/new.txt") == b"NEW"
    assert not src.exists("b")
    out = src.materialize(tmp_path / "clean.zip")
    src.close()
    with zipfile.ZipFile(out) as zf:
        assert "a/old.txt" not in zf.namelist()
        assert zf.read("a/new.txt") == b"NEW"


def test_rename_destination_guard(core_zip):
    """The same destination guard as the live source: the bare core tree
    names need the audited unlock, the config files never do."""
    src = MutableZipSource(core_zip)
    # a bare core tree name is exactly what a WRITE can never land on, so
    # the rename needs the same audited unlock
    with pytest.raises(NotWritableError):
        src.rename("wp-content", "wp-includes")
    # and the config files are not renameable at all
    with pytest.raises(NotWritableError):
        src.rename("wp-content/plugins", "wp-config.php")
    with pytest.raises(NotWritableError):
        src.rename("wp-content/plugins", "wp-config.php", allow_core=True)
    src.close()


# ------------------------------------------------------- triple-check round 2


def test_ZIP1_a_corrupt_member_is_a_source_error_not_a_raw_badzipfile(tmp_path):
    """ZIP1: materialize copied through ``ZipFile.open`` directly, so one
    corrupt stored byte raised ``BadZipFile: Bad CRC-32`` — neither WptError
    nor OSError — and the CLI tracebacked instead of refusing one line."""
    source = tmp_path / "corrupt.zip"
    with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("a.txt", b"hello-corrupt-me")
    raw = bytearray(source.read_bytes())
    payload = raw.find(b"hello-corrupt-me")
    assert payload != -1
    raw[payload] ^= 0xFF
    source.write_bytes(bytes(raw))

    with pytest.raises(SourceError, match="cannot read 'a.txt'"):
        MutableZipSource(source).materialize(tmp_path / "out.zip")
    assert not (tmp_path / "out.zip").exists()
    assert not (tmp_path / "out.tmp").exists()


def test_R11_directory_symlink_with_children_is_refused_at_materialize(
        tmp_path):
    """R11-P2-10: an archive cannot represent one name as both a directory
    symlink and a real directory holding children.  Materializing used to
    emit two members with the same name; it now refuses before writing."""
    from wpt.types import SourceError

    p = tmp_path / "dirlink.zip"
    with zipfile.ZipFile(p, "w") as zf:
        link = zipfile.ZipInfo("wp-content/uploads/linkdir/")
        link.external_attr = 0o120777 << 16
        zf.writestr(link, b"/etc")
        child = zipfile.ZipInfo("wp-content/uploads/linkdir/evil.php")
        child.external_attr = 0o100644 << 16
        zf.writestr(child, b"<?php evil")
    with pytest.raises(SourceError, match="directory symlink"):
        MutableZipSource(p, root="")
    assert not (tmp_path / "rehearsed.zip").exists()


def test_ZIPWRITER_SYMLINK_preserves_link_type_and_never_walks_it(tmp_path):
    """ZIPWRITER-SYMLINK: MutableZipSource built every non-directory Entry
    without is_link and materialize wrote FILE attrs, turning a symlink's
    target string into PHP content in the rehearsed archive."""
    from wpt.sources.zip import _zip_is_link

    p = tmp_path / "link.zip"
    with zipfile.ZipFile(p, "w") as zf:
        link = zipfile.ZipInfo("wp-content/uploads/link.jpg")
        link.external_attr = 0o120777 << 16
        zf.writestr(link, b"/etc/passwd")
        zf.writestr("wp-content/uploads/real.jpg", b"JPEG")
    src = MutableZipSource(p, root="")
    entries = {e.path: e for e in src.list_dir("wp-content/uploads")}
    assert entries["wp-content/uploads/link.jpg"].is_link is True
    assert "wp-content/uploads/link.jpg" not in {
        e.path for e in src.walk()}

    dest = src.materialize(tmp_path / "rehearsed.zip")
    with zipfile.ZipFile(dest) as zf:
        info = zf.getinfo("wp-content/uploads/link.jpg")
        assert _zip_is_link(info) is True
        assert (info.external_attr >> 16) & 0o777 == 0o777
    assert "wp-content/uploads/link.jpg" not in {
        e.path for e in ZipSource(dest, root="").walk()}


# ------------------------------------------------------- triple-check round 6


def test_R12_a_file_path_that_is_also_a_directory_prefix_is_refused(
        tmp_path):
    """R12-P2-8: ``site/a`` as a file and ``site/a/b`` as another member
    walked ``a`` as a file (child unreachable) and materialized BOTH a file
    and a directory named ``a``.  Refuse before writing anything."""
    import zipfile

    source = tmp_path / "collision.zip"
    with zipfile.ZipFile(source, "w") as zf:
        zf.writestr("site/a", b"file bytes")
        zf.writestr("site/a/b", b"child bytes")
    # R19: the unrepresentable shape is refused at CONSTRUCTION (the
    # shared ZipSource owner), before any overlay/materialize work.
    with pytest.raises(SourceError, match="also a directory"):
        MutableZipSource(source)
    assert not list(tmp_path.glob("*.wip"))
    assert not (tmp_path / "rehearsed.zip").exists()


def test_R17_a_tombstoned_ancestor_does_not_emit_a_file_as_a_directory(
        tmp_path):
    """R17-4-P2: ``_dir_prefixes`` emitted any ``rel in self._dirs`` even
    when a tombstoned ancestor had hidden that explicit directory, while the
    refusal used ``_live_dirs()``.  A file staged at the hidden name then
    materialized BOTH ``a/b/`` and ``a/b`` and ``extractall`` failed."""
    import zipfile

    source = tmp_path / "tombstone.zip"
    with zipfile.ZipFile(source, "w") as zf:
        zf.writestr("a/b/", b"")
        zf.writestr("a/b/keep.txt", b"old")
    src = MutableZipSource(source, root="")
    src.rmdir_recursive("a")
    src.write_bytes("a/b", b"FILE")

    dest = tmp_path / "rehearsed.zip"
    src.materialize(dest)
    with zipfile.ZipFile(dest) as zf:
        names = zf.namelist()
        assert "a/b" in names
        assert "a/b/" not in names
        zf.extractall(tmp_path / "extracted")
    assert (tmp_path / "extracted" / "a" / "b").read_bytes() == b"FILE"


def test_R6_23_materialize_temp_never_truncates_the_source_or_clobbers(tmp_path):
    """R6-23: ``dest.with_suffix(".tmp")`` could equal the source (site.tmp ->
    site.zip) and truncate it, or destroy a pre-existing user temp.  A unique
    hidden temp is used and only that path is unlinked."""
    import zipfile

    source = tmp_path / "site.tmp"
    with zipfile.ZipFile(source, "w") as zf:
        zf.writestr("index.php", b"<?php ORIGINAL")
    original = source.read_bytes()

    src = MutableZipSource(source, root="")
    dest = tmp_path / "site.zip"
    src.materialize(dest)

    assert source.read_bytes() == original
    with zipfile.ZipFile(dest) as zf:
        assert zf.read("index.php") == b"<?php ORIGINAL"

    preexisting = tmp_path / "out.tmp"
    preexisting.write_bytes(b"USER FILE")
    src.materialize(tmp_path / "out.zip")
    assert preexisting.read_bytes() == b"USER FILE"
    assert not list(tmp_path.glob("*.wip"))


def test_R13_symlink_plus_explicit_directory_is_refused_before_writing(
        tmp_path):
    """R13-P2-22: a directory symlink refuses only when LIVE children exist,
    so a zip carrying ``site/a`` (symlink) plus an explicit ``site/a/``
    directory materialized BOTH members — unrepresentable.  The explicit
    directory is now part of the refusal and nothing is written."""
    import zipfile

    source = tmp_path / "link-and-dir.zip"
    with zipfile.ZipFile(source, "w") as zf:
        link = zipfile.ZipInfo("site/a")
        link.external_attr = 0o120777 << 16
        zf.writestr(link, b"/etc")
        zf.writestr("site/a/", b"")
    dest = tmp_path / "rehearsed.zip"
    with pytest.raises(SourceError, match="directory symlink"):
        MutableZipSource(source, root="site")
    assert not dest.exists()
    assert not list(tmp_path.glob("*.wip"))


def test_R22_live_dirs_is_linear_against_a_deletion_overlay(tmp_path):
    """R22-P1: ``_live_dirs`` scanned EVERY tombstone for EVERY explicit
    directory (5,000 live + 5,000 deleted = 12.97 s) between deadline
    checks, and materialize called it twice.  The ancestor test now walks
    each name's own components; the same 5k/5k overlay materializes inside
    a short budget."""
    import time

    from wpt.deadline import Deadline

    source = tmp_path / "overlay.zip"
    with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_STORED) as zf:
        for index in range(5_000):
            zf.writestr(f"wp-content/uploads/live-{index:05d}/", b"")
            zf.writestr(f"wp-content/uploads/dead-{index:05d}/", b"")
    src = MutableZipSource(source, root="", deadline=Deadline(10.0))
    for index in range(5_000):
        src.delete(f"wp-content/uploads/dead-{index:05d}")

    started = time.monotonic()
    live = src._live_dirs()
    scan_elapsed = time.monotonic() - started
    assert len(live) == 5_000
    assert scan_elapsed < 1.0, scan_elapsed

    dest = tmp_path / "overlay-rehearsed.zip"
    started = time.monotonic()
    src.materialize(dest)
    elapsed = time.monotonic() - started
    assert elapsed < 4.0, elapsed
    with zipfile.ZipFile(dest) as zf:
        names = zf.namelist()
    assert len([name for name in names if "live-" in name]) == 5_000
    assert not [name for name in names if "dead-" in name]
    assert not list(tmp_path.glob("*.wip"))


def test_R21_materialize_is_linear_and_checks_the_run_deadline(tmp_path):
    """R21-P1: materialize scanned every surviving name per file (O(n^2):
    10k members 5.5 s, 20k 49 s) and never checked the run budget.  10k
    entries now materialize well inside a generous deadline, and an already
    spent budget refuses BEFORE writing anything."""
    import time

    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    source = tmp_path / "big.zip"
    with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_STORED) as zf:
        for index in range(10_000):
            zf.writestr(f"wp-content/uploads/2023/{index:05d}.jpg", b"x")
    dest = tmp_path / "big-rehearsed.zip"
    started = time.monotonic()
    MutableZipSource(source, root="", deadline=Deadline(5.0)).materialize(dest)
    elapsed = time.monotonic() - started
    assert elapsed < 3.0, elapsed
    with zipfile.ZipFile(dest) as zf:
        assert len(zf.namelist()) >= 10_000
    assert not list(tmp_path.glob("*.wip"))

    spent = Deadline(0.01)
    spent._started -= 1.0
    refused = tmp_path / "refused.zip"
    with pytest.raises(DeadlineExceeded):
        MutableZipSource(source, root="",
                         deadline=spent).materialize(refused)
    assert not refused.exists()
    assert not list(tmp_path.glob("*.wip"))
