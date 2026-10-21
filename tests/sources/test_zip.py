import zipfile
from datetime import datetime, timezone

import pytest

from wpt.sources.zip import ZipSource
from wpt.types import NotWritableError, SourceError


def _epoch(*parts):
    return int(datetime(*parts, tzinfo=timezone.utc).timestamp())


@pytest.fixture()
def zip_path(tmp_path):
    p = tmp_path / "site.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("wp-config.php", "<?php config")
        zf.writestr("wp-content/uploads/2018/03/a.png", b"PNGDATA")
        zf.writestr("wp-content/uploads/readme.txt", "hi")
        zf.writestr("wp-content/plugins/elementor/elementor.php", "<?php plugin")
    return p


def test_walk_posix_paths_including_month_dirs(zip_path):
    src = ZipSource(zip_path)
    paths = [e.path for e in src.walk()]
    assert "wp-content/uploads/2018/03/a.png" in paths
    assert all("\\" not in p for p in paths)


def test_root_prefix_stripping(tmp_path):
    p = tmp_path / "nested.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("domains/site/public_html/wp-config.php", "x")
        zf.writestr("domains/site/public_html/wp-content/index.php", "y")
    src = ZipSource(p, root="domains/site/public_html")
    paths = {e.path for e in src.walk()}
    assert paths == {"wp-config.php", "wp-content", "wp-content/index.php"}


def test_R20_large_archive_construction_is_linear_and_deadline_bounded(
        tmp_path):
    """R20-P1: the ancestor check re-sorted every member for every file
    (O(n² log n)); a 10k archive took ~14 s inside ``__init__`` and
    ``--deadline`` could not interrupt it.  One sorted list + bisect must
    construct it well under a second."""
    import time

    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    p = tmp_path / "big.zip"
    with zipfile.ZipFile(p, "w") as zf:
        for index in range(10_000):
            zf.writestr(f"site/wp-content/uploads/d{index % 50}/f{index}.php",
                        b"x")
    # The shipped fixture is a host export: one top-level dir is the root.
    started = time.monotonic()
    source = ZipSource(p, deadline=Deadline(30))
    elapsed = time.monotonic() - started
    try:
        assert len(source._entries) == 10_000
    finally:
        source.close()
    assert elapsed < 1.0, f"10k construction took {elapsed:.2f}s"

    spent = Deadline(0.01)
    spent._started -= 1.0
    with pytest.raises(DeadlineExceeded):
        ZipSource(p, deadline=spent)


def test_R20_refused_tree_closes_the_zip_file(tmp_path):
    """The unrepresentable-tree refusal must not leak the open ZipFile;
    library callers do not exit the process."""
    import os

    p = tmp_path / "bad.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("a", b"file")
        zf.writestr("a/b.php", b"child")
    fd_dir = "/proc/self/fd"
    if not os.path.isdir(fd_dir):
        pytest.skip("no /proc/self/fd on this platform")
    before = len(os.listdir(fd_dir))
    for _ in range(25):
        with pytest.raises(SourceError, match="not a representable tree"):
            ZipSource(p)
    after = len(os.listdir(fd_dir))
    assert after - before < 5, (before, after)


def test_read_bytes_roundtrip(zip_path):
    src = ZipSource(zip_path)
    assert src.read_bytes("wp-content/uploads/2018/03/a.png") == b"PNGDATA"
    with pytest.raises(SourceError):
        src.read_bytes("nope.txt")


def test_mutating_ops_refused_with_helpful_message(zip_path):
    src = ZipSource(zip_path)
    with pytest.raises(NotWritableError, match="read-only"):
        src.write_bytes("wp-content/x.txt", b"x")
    with pytest.raises(NotWritableError, match="read-only"):
        src.delete("wp-content/uploads/readme.txt")
    with pytest.raises(NotWritableError, match="read-only"):
        src.rmdir_recursive("wp-content/uploads")


def test_guards_still_active(zip_path):
    src = ZipSource(zip_path)
    with pytest.raises(NotWritableError):
        src.write_bytes(".htaccess", b"x", allow_config=True)
    with pytest.raises(SourceError):
        src.delete("index.php")


def test_exists_and_size(zip_path):
    src = ZipSource(zip_path)
    assert src.exists("wp-content/uploads") is True
    assert src.exists("wp-content/missing") is False
    assert src.size("wp-content/uploads/readme.txt") == 2


def test_list_dir_children_only(zip_path):
    src = ZipSource(zip_path)
    top = {e.path for e in src.list_dir("")}
    assert top == {"wp-config.php", "wp-content"}
    inner = {e.path for e in src.list_dir("wp-content/uploads")}
    assert inner == {"wp-content/uploads/2018", "wp-content/uploads/readme.txt"}


def test_list_dir_carries_posix_mode_and_mtime(tmp_path):
    """The zip entry's POSIX st_mode (high 16 bits of external_attr) and
    date_time reach the Entry; only the permission bits are kept so the
    value means what FTP's mode means.  Synthesized directory entries have
    no zip entry of their own and keep both facts unknown."""
    p = tmp_path / "meta.zip"
    with zipfile.ZipFile(p, "w") as zf:
        jpg = zipfile.ZipInfo("wp-content/uploads/a.jpg",
                              date_time=(2023, 5, 6, 7, 8, 10))
        jpg.external_attr = 0o100644 << 16
        zf.writestr(jpg, b"JPG")
        php = zipfile.ZipInfo("wp-content/uploads/b.php",
                              date_time=(2024, 1, 2, 3, 4, 6))
        php.external_attr = 0o100666 << 16
        zf.writestr(php, b"PHP")
        d = zipfile.ZipInfo("wp-content/uploads/2018/",
                            date_time=(2022, 2, 2, 2, 2, 2))
        d.external_attr = 0o40755 << 16
        zf.writestr(d, b"")
        zf.writestr("wp-content/uploads/2018/c.png", b"PNG")
    src = ZipSource(p, root="")
    entries = {e.path: e for e in src.list_dir("wp-content/uploads")}
    assert (entries["wp-content/uploads/a.jpg"].mode,
            entries["wp-content/uploads/a.jpg"].mtime) == (
        0o644, _epoch(2023, 5, 6, 7, 8, 10))
    assert entries["wp-content/uploads/b.php"].mode == 0o666
    assert entries["wp-content/uploads/b.php"].mtime == _epoch(2024, 1, 2, 3, 4, 6)
    synthesized = entries["wp-content/uploads/2018"]
    assert synthesized.is_dir is True
    # An EXPLICIT directory entry keeps its recorded metadata; a directory
    # synthesized only from child paths has none.
    assert (synthesized.mode, synthesized.mtime) == (
        0o755, _epoch(2022, 2, 2, 2, 2, 2))


def test_explicit_empty_directory_is_visible_to_list_dir_and_walk(tmp_path):
    p = tmp_path / "empty.zip"
    with zipfile.ZipFile(p, "w") as zf:
        info = zipfile.ZipInfo("wp-content/uploads/",
                               date_time=(2022, 3, 4, 5, 6, 8))
        info.external_attr = 0o40755 << 16
        zf.writestr(info, b"")
    src = ZipSource(p, root="")

    entries = {entry.path: entry for entry in src.list_dir("")}
    assert entries["wp-content"].is_dir is True
    uploads = {entry.path: entry for entry in src.list_dir("wp-content")}[
        "wp-content/uploads"]
    assert uploads.is_dir is True
    assert uploads.mode == 0o755
    assert [entry.path for entry in src.walk()] == [
        "wp-content", "wp-content/uploads"]


def test_ZIP_1_absolute_members_are_archive_relative_and_walk_terminates(
        tmp_path):
    p = tmp_path / "absolute.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("/etc/passwd", b"root")
        zf.writestr("top.txt", b"top")
    src = ZipSource(p, root="")
    assert {entry.path for entry in src.list_dir("")} == {
        "etc", "top.txt"}
    walked = {entry.path for entry in src.walk()}
    assert walked == {"etc", "etc/passwd", "top.txt"}
    assert "" not in walked


def test_ZIP_1_absolute_site_root_is_not_silently_dropped(tmp_path):
    p = tmp_path / "absolute-site.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("/site.test/x.php", b"<?php x")
        zf.writestr("site.test/y.php", b"<?php y")
    src = ZipSource(p)
    assert src.root == "site.test"
    assert sorted(src._entries) == ["x.php", "y.php"]


def test_ZIP_1_escaping_member_is_rejected(tmp_path):
    p = tmp_path / "escape.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("../evil.php", b"evil")
        zf.writestr("safe.php", b"safe")
    src = ZipSource(p, root="")
    assert sorted(src._entries) == ["safe.php"]


def test_ZIP_2_corrupt_member_read_is_a_source_error(tmp_path):
    p = tmp_path / "corrupt.zip"
    with zipfile.ZipFile(p, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("a.txt", b"secret-payload")
    raw = bytearray(p.read_bytes())
    offset = raw.index(b"secret-payload")
    raw[offset] = ord("S")
    p.write_bytes(raw)
    src = ZipSource(p, root="")
    with pytest.raises(SourceError, match="cannot read"):
        src.read_bytes("a.txt")


def test_ZIP_2_encrypted_member_read_is_a_source_error(tmp_path):
    p = tmp_path / "enc.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("a.txt", b"x")
    src = ZipSource(p, root="")

    def _encrypted(_info):
        raise RuntimeError("File a.txt is encrypted, password required")

    src._zf.read = _encrypted
    with pytest.raises(SourceError, match="cannot read"):
        src.read_bytes("a.txt")


def test_ZIP_3_explicit_directory_parent_exists_and_sizes(tmp_path):
    p = tmp_path / "dirs.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("a/b/", b"")
    src = ZipSource(p, root="")
    assert [entry.path for entry in src.list_dir("")] == ["a"]
    assert src.exists("a") is True
    assert src.size("a") == 0
    assert src.exists("a/b") is True
    assert src.size("a/b") == 0


def test_entry_without_a_posix_mode_keeps_mode_none(tmp_path):
    """external_attr's high bits are zero when the archive recorded no
    POSIX mode (the low DOS attribute bits are not a mode) — absence is
    None, never a fabricated 0."""
    p = tmp_path / "nometa.zip"
    info = zipfile.ZipInfo("plain.txt", date_time=(2022, 2, 2, 2, 2, 2))
    info.external_attr = 0x20   # DOS archive bit only, no Unix mode word
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr(info, b"x")
    entry = ZipSource(p, root="").list_dir("")[0]
    assert entry.path == "plain.txt"
    assert entry.mode is None
    assert entry.mtime == _epoch(2022, 2, 2, 2, 2, 2)


def test_missing_zip_raises(tmp_path):
    with pytest.raises(SourceError):
        ZipSource(tmp_path / "ghost.zip")


def test_root_autodetect_single_site_dir(tmp_path):
    # REAL host-export shape: every entry under one site dir, and the root
    # dir itself appears as an entry ("site.test/"). Found on the corpus.
    p = tmp_path / "site.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("site.test/", "")                      # the root dir entry
        zf.writestr("site.test/wp-config.php", "x")
        zf.writestr("site.test/wp-content/uploads/2023/a.jpg", "y")
    src = ZipSource(p)                                    # root=None -> auto
    assert src.root == "site.test"
    assert sorted(src._entries) == [
        "wp-config.php", "wp-content/uploads/2023/a.jpg",
    ]
    assert src.read_bytes("wp-config.php") == b"x"


def test_root_autodetect_flat_archive(tmp_path):
    p = tmp_path / "flat.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("wp-config.php", "x")
        zf.writestr("wp-content/index.php", "y")
    src = ZipSource(p)
    assert src.root == ""
    assert "wp-config.php" in src._entries


def test_root_autodetect_two_top_dirs(tmp_path):
    p = tmp_path / "two.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("site.test/wp-config.php", "x")
        zf.writestr("other/ca.txt", "y")
    src = ZipSource(p)
    assert src.root == ""
    assert "site.test/wp-config.php" in src._entries  # nothing stripped


def test_root_autodetect_site_dir_without_self_entry(tmp_path):
    # Some exporters omit the root dir entry itself.
    p = tmp_path / "noentry.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("site.test/wp-config.php", "x")
    src = ZipSource(p)
    assert src.root == "site.test"
    assert list(src._entries) == ["wp-config.php"]


def test_a_not_a_zip_file_is_a_one_line_refusal_not_a_traceback(tmp_path):
    """[L60] `BadZipFile` is neither WptError nor OSError, so every command
    body's error contract missed it and a plain-text file named .zip escaped
    as a raw traceback from every zip-reading command."""
    from wpt.sources.zip import ZipSource
    from wpt.types import SourceError
    bad = tmp_path / "not-really.zip"
    bad.write_text("this is not a zip")
    with pytest.raises(SourceError, match="not a zip archive"):
        ZipSource(bad)


def test_R11_directory_symlink_with_a_child_is_refused(tmp_path):
    """R11-P2-10 + R19-P1: a symlink member whose name ends in ``/`` is a
    LINK, not a walked tree — but a link that is also the ANCESTOR of
    another member cannot be represented as a tree at all.  The old code
    silently dropped the descendant from ``walk()`` (a hidden backdoor
    scanned by nothing); construction now refuses the archive and names
    both members."""
    from wpt.types import SourceError

    path = tmp_path / "dirlinks.zip"
    with zipfile.ZipFile(path, "w") as archive:
        link = zipfile.ZipInfo("wp-content/uploads/linkdir/")
        link.external_attr = 0o120777 << 16
        archive.writestr(link, b"/etc")
        child = zipfile.ZipInfo("wp-content/uploads/linkdir/evil.php")
        child.external_attr = 0o100666 << 16
        archive.writestr(child, b"<?php evil")

    with pytest.raises(SourceError) as excinfo:
        ZipSource(path, root="")
    assert "wp-content/uploads/linkdir" in str(excinfo.value)
    assert "wp-content/uploads/linkdir/evil.php" in str(excinfo.value)


def test_R19_a_file_member_that_is_an_ancestor_is_refused(tmp_path):
    """A regular file ``wp-content/uploads`` plus
    ``wp-content/uploads/backdoor.php`` used to walk as only the file:
    the descendant stayed readable by exact path but invisible to every
    scan.  Any non-directory ancestor is now a construction refusal."""
    from wpt.types import SourceError

    path = tmp_path / "collision.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("wp-content/uploads", b"not a directory")
        archive.writestr("wp-content/uploads/backdoor.php", b"<?php evil")
    with pytest.raises(SourceError) as excinfo:
        ZipSource(path, root="")
    assert "wp-content/uploads" in str(excinfo.value)
    assert "wp-content/uploads/backdoor.php" in str(excinfo.value)


def test_R19_a_symlink_member_that_is_an_ancestor_is_refused(tmp_path):
    """The symlink spelling of the same hidden-tree shape."""
    from wpt.types import SourceError

    path = tmp_path / "linkdir.zip"
    with zipfile.ZipFile(path, "w") as archive:
        link = zipfile.ZipInfo("linkdir")
        link.external_attr = 0o120777 << 16
        archive.writestr(link, b"/etc")
        archive.writestr("linkdir/evil.php", b"<?php evil")
    with pytest.raises(SourceError) as excinfo:
        ZipSource(path, root="")
    assert "linkdir" in str(excinfo.value)
    assert "linkdir/evil.php" in str(excinfo.value)


def test_ZIP_SYMLINK_type_is_preserved_and_never_walked(tmp_path):
    """ZIP-SYMLINK: _entry_meta masked S_IFLNK to 0o777, so a symlink entered
    walk as a world-writable regular file whose "content" was the target
    path, and uploads-perms advised a chmod that cannot affect a link."""
    from wpt.audit.data import gather_source
    from wpt.audit.security import check_security_uploads_perms
    from wpt.settings import Settings

    path = tmp_path / "links.zip"
    with zipfile.ZipFile(path, "w") as archive:
        link = zipfile.ZipInfo("wp-content/uploads/link.jpg")
        link.external_attr = 0o120777 << 16
        archive.writestr(link, b"/etc/passwd")
        real = zipfile.ZipInfo("wp-content/uploads/real.jpg")
        real.external_attr = 0o100644 << 16
        archive.writestr(real, b"JPEG")

    source = ZipSource(path, root="")
    entries = {entry.path: entry for entry in source.list_dir(
        "wp-content/uploads")}
    assert entries["wp-content/uploads/link.jpg"].is_link is True
    assert entries["wp-content/uploads/real.jpg"].is_link is False
    walked = {entry.path for entry in source.walk()}
    assert "wp-content/uploads/link.jpg" not in walked
    assert "wp-content/uploads/real.jpg" in walked

    data = gather_source(source, "local")
    assert check_security_uploads_perms(data, Settings()) == []


def test_ZIP_WALK_double_separator_after_the_root_terminates(tmp_path):
    """ZIP-WALK: lstrip ran BEFORE root extraction, so `site.test//x` kept a
    leading slash, list_dir("") synthesized Entry(path=""), and walk()
    relisted the root forever.  Both a bare `site.test//` and `site.test//x`
    must load as ordinary archive-relative paths."""
    for index, (member, expected) in enumerate((("site.test//", set()),
                                                ("site.test//x", {"x"}))):
        p = tmp_path / f"double-separator-{index}.zip"
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr(member, b"<?php x" if expected else b"")
        src = ZipSource(p)
        assert src.root == "site.test"
        assert [e.path for e in src.list_dir("")] == list(expected)
        walked = list(src.walk())
        assert {e.path for e in walked} == expected
        assert all(e.path for e in walked)


# ------------------------------------------------------- triple-check round 6


def test_R6_20_escaping_zip_root_is_rejected_auto_and_forced(tmp_path):
    """R6-20: an all-``../`` archive auto-detected ``..`` as its root, and a
    forced ``../evil`` was accepted; materialize then emitted ``../`` names.
    Both roots are refused through the shared path guard."""
    p = tmp_path / "evil.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("../evil/x.php", b"<?php")
    with pytest.raises(SourceError, match="unsafe zip root"):
        ZipSource(p)
    with pytest.raises(SourceError, match="unsafe zip root"):
        ZipSource(p, root="../evil")


def test_R6_21_corrupt_zip_open_answers_a_source_error(tmp_path, monkeypatch):
    """R6-21: ZipFile also raises UnicodeDecodeError/NotImplementedError;
    only BadZipFile was caught, so those escaped as raw tracebacks."""
    p = tmp_path / "site.zip"
    p.write_bytes(b"PK")

    class _Raises:
        def __init__(self, exc):
            self.exc = exc

        def __call__(self, *_args, **_kwargs):
            raise self.exc

    for exc in (UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid"),
                NotImplementedError("compression method 99"),
                ValueError("bad central directory")):
        monkeypatch.setattr("wpt.sources.zip.zipfile.ZipFile", _Raises(exc))
        with pytest.raises(SourceError, match="not a zip archive"):
            ZipSource(p)


def test_R7_P2_20_corrupt_lzma_member_body_is_a_source_error(tmp_path):
    """R7-P2-20: ``_lzma.LZMAError`` was missing from the one member-read
    tuple, so a corrupt LZMA body escaped as a raw traceback."""
    import lzma
    import struct

    p = tmp_path / "lzma.zip"
    with zipfile.ZipFile(p, "w", compression=zipfile.ZIP_LZMA) as zf:
        zf.writestr("a.txt", b"secret-payload" * 1000)
    with zipfile.ZipFile(p) as zf:
        info = zf.getinfo("a.txt")
    raw = bytearray(p.read_bytes())
    name_len, extra_len = struct.unpack_from("<HH", raw, info.header_offset + 26)
    data_start = info.header_offset + 30 + name_len + extra_len
    for offset in range(20, 25):
        raw[data_start + offset] ^= 0xFF
    p.write_bytes(raw)

    src = ZipSource(p, root="")
    with pytest.raises(SourceError, match="cannot read"):
        src.read_bytes("a.txt")
    with pytest.raises(SourceError, match="cannot read"):
        src.read_bytes_bounded("a.txt", 1024 * 1024)

    # The exception type really is the one this regression is about.
    with zipfile.ZipFile(p) as zf, pytest.raises(lzma.LZMAError):
        zf.read("a.txt")
