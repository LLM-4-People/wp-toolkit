"""Zip archive source — read-only view for offline (audit-only) mode."""

import bisect
import lzma
import posixpath
import stat
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

from ..deadline import Deadline
from ..log import get_logger
from ..types import Entry, NotWritableError, SourceError
from .base import WalkMixin

log = get_logger("sources.zip")

#: Every exception a member read can raise for a corrupt/encrypted/unsupported
#: entry.  None of them is a WptError, so the read choke point maps them to
#: SourceError — the same rule the archive OPEN already follows [L60].
_MEMBER_READ_ERRORS = (
    zipfile.BadZipFile, RuntimeError, zlib.error, lzma.LZMAError,
    NotImplementedError, OSError, EOFError, ValueError,
)


def _read_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo,
                 rel: str, limit: int | None = None) -> bytes:
    """Read one archive member, bounded when ``limit`` is given.

    The ONE member-read choke point: corrupt CRCs (BadZipFile), encrypted
    members (RuntimeError), unsupported compression (NotImplementedError)
    and zlib failures all become a one-line SourceError instead of a raw
    exception escaping the command's (WptError, OSError) contract.
    """
    try:
        if limit is None:
            return archive.read(info)
        with archive.open(info) as handle:
            data = handle.read(limit + 1)
    except _MEMBER_READ_ERRORS as exc:
        raise SourceError(
            f"cannot read {rel!r} from the zip archive: {exc}") from exc
    if limit is not None and len(data) > limit:
        raise SourceError(
            f"{rel!r} is larger than the {limit}-byte read bound")
    return data


def _zip_mode(info: zipfile.ZipInfo | None) -> int | None:
    """The POSIX st_mode recorded in the entry's Unix external-attr word."""
    if info is None:
        return None
    raw_mode = (info.external_attr >> 16) & 0xFFFF
    return raw_mode or None


def _zip_is_link(info: zipfile.ZipInfo | None) -> bool:
    """True when the archive recorded a POSIX SYMLINK for this member.

    The Unix creator stores ``S_IFLNK | perms`` in the high 16 bits; masking
    that to ``0o777`` lost the type, so a link entered walk as a regular
    file, its target string became "content", and uploads-perms reported a
    world-writable finding whose chmod cannot affect a link.
    """
    mode = _zip_mode(info)
    return mode is not None and stat.S_ISLNK(mode)


def _entry_meta(info: zipfile.ZipInfo | None) -> tuple[int | None, int | None]:
    """``(mode, mtime)`` recorded by one zip entry; None where absent.

    The high 16 bits of ``external_attr`` carry the creating system's POSIX
    ``st_mode``; zero means the archive recorded none — never a fabricated
    0.  Only the permission bits survive (0o7777), so ``Entry.mode`` means
    the same thing here as it does for FTP.  ``date_time`` is the archive's
    local wall clock with no timezone, read as UTC (deterministic; an
    entry's age can shift by the creator's UTC offset), and a malformed
    date stays None.  ``info=None`` is a path with no zip entry of its own
    (staged bytes, a synthesized directory) and keeps both facts unknown.
    """
    if info is None:
        return None, None
    raw_mode = _zip_mode(info) or 0
    mode = raw_mode & 0o7777 if raw_mode else None
    try:
        stamp = datetime(*info.date_time, tzinfo=timezone.utc)
        mtime = int(stamp.timestamp())
    except (TypeError, ValueError, OverflowError, OSError):
        mtime = None
    return mode, mtime


def _escapes_archive_root(name: str) -> bool:
    """True when an archive member name carries a ``.``/``..``/empty segment."""
    return any(segment in (".", "..")
               for segment in name.replace("\\", "/").split("/"))


class ZipSource(WalkMixin):
    """Read-only Source over a zip archive; mutating ops raise NotWritableError.

    ``root=None`` (the automatic mode used by the audit/actions stacks)
    detects a SINGLE top-level directory (a host export like
    ``example.com/...``) and treats it as the webroot; a flat
    archive stays rootless. ``root="<dir>"`` forces a prefix, ``""`` keeps
    every entry as-is (the pre-auto behavior, used by tests that build
    flat zips).
    """

    def __init__(self, zip_path: Path, root: str | None = None, *,
                 deadline: "Deadline | None" = None) -> None:
        self.zip_path = Path(zip_path)
        self._deadline = deadline
        if not self.zip_path.exists():
            raise SourceError(f"zip not found: {self.zip_path}")
        if deadline is not None:
            deadline.check("zip archive open")
        try:
            self._zf = zipfile.ZipFile(self.zip_path)
        except (zipfile.BadZipFile, NotImplementedError, UnicodeError,
                ValueError) as exc:
            # A traceback must never escape: every command body's contract
            # catches WptError/OSError.  ZipFile also raises UnicodeDecodeError
            # (UTF-8 flag with invalid filename bytes), NotImplementedError
            # (central extract_version > 6.3) and ValueError [L60/R6-21].
            raise SourceError(
                f"not a zip archive: {self.zip_path} ({exc})"
            ) from exc
        try:
            self._load_entries(root)
        except BaseException:
            # Construction owns the ZipFile it just opened: a refusal (the
            # unrepresentable-tree rule, a deadline, a path guard) must not
            # leave the descriptor to GC — library/embedder callers hold it.
            self._zf.close()
            raise

    def _load_entries(self, root: str | None) -> None:
        """Index the opened archive into ``_entries``/``_dirs``."""
        deadline = self._deadline
        if deadline is not None:
            deadline.check("zip archive index")
        if root is None:
            root = self._detect_root()
            if root:
                log.debug("zip root auto-detected: %r", root)
        root = (root or "").strip("/")
        if root:
            try:
                root = self._guard_path(root)
            except SourceError as exc:
                raise SourceError(
                    f"unsafe zip root {root!r} in {self.zip_path}: {exc}"
                ) from exc
        self.root = root
        self._entries: dict[str, zipfile.ZipInfo] = {}
        #: Explicit directory entries, kept separately so a synthesized
        #: directory can still carry the mode/mtime the archive recorded.
        self._dirs: dict[str, zipfile.ZipInfo] = {}
        for info in self._zf.infolist():
            if deadline is not None:
                deadline.check("zip archive index")
            # Absolute member names ("/etc/passwd", a common host-export
            # quirk) are treated as archive-relative, exactly as
            # _detect_root already treats them.  Keeping the slash made
            # list_dir("") synthesize Entry(path="") and walk() relist the
            # root forever.
            name = info.filename.replace("\\", "/").lstrip("/")
            if self.root and not name.startswith(self.root + "/"):
                continue
            rel = name[len(self.root) + 1:] if self.root else name
            # A double separator right after the root ("site.test//x") leaves
            # a leading "/" here; normpath preserves "//x" and list_dir("")
            # then synthesizes Entry(path="") and walk() relists forever.
            # Strip AFTER the root extraction (the old lstrip ran before it).
            rel = rel.lstrip("/")
            rel = posixpath.normpath(rel)
            if not rel or rel == ".":
                continue
            if rel == ".." or rel.startswith("../"):
                # A member that escapes the archive root is never a source
                # path: skip it (the archive is read-only; a write target
                # would already have refused it).
                log.warning("zip archive entry escapes the root; skipped: %r",
                            info.filename)
                continue
            # Symlink classification comes BEFORE ``is_dir``: a directory
            # symlink is recorded with a trailing slash, so ``is_dir()`` is
            # true even though the member is a LINK, not a tree to walk.
            # Listing it as a directory made walk() descend into the link
            # target's name-space as if it were real (R11-P2-10).
            if info.is_dir() and not _zip_is_link(info):
                self._dirs[rel] = info
            else:
                self._entries[rel] = info
        self._refuse_unrepresentable_tree()
        log.debug("zip loaded: %d files (root=%r)", len(self._entries), self.root or None)

    def _refuse_unrepresentable_tree(self) -> None:
        """A non-directory member must never be an ANCESTOR of another.

        ``_entries``/``_dirs`` are keyed by path and ``walk()`` descends by
        prefix.  A regular file (or a symlink) recorded at ``a/b`` while
        ``a/b/c.php`` also exists makes ``a/b`` a file entry AND a directory
        prefix: ``list_dir``'s ``seen`` map then emits it as a file and
        never descends, so ``walk()`` silently omits the descendant while
        ``read_bytes("a/b/c.php")`` still answers.  A backdoor under such a
        path was invisible to every audit scan.  The archive shape cannot
        be represented as a tree (``MutableZipSource.materialize`` refuses
        it too), so fail at construction and name both members.
        """
        every = set(self._entries) | set(self._dirs)
        # The descendant test is ONE bisect per file against a list sorted
        # ONCE.  The old shape re-sorted every member for every file
        # (O(n² log n)): a 20,000-member archive took 82 s to construct, so
        # --deadline could not bound a scan before it even started.  A
        # representable archive has no descendant, so the normal case is
        # n log n.
        ordered = sorted(every)
        for rel in sorted(self._entries):
            if self._deadline is not None:
                self._deadline.check("zip archive tree check")
            prefix = f"{rel}/"
            index = bisect.bisect_left(ordered, prefix)
            descendant = (ordered[index]
                          if index < len(ordered)
                          and ordered[index].startswith(prefix)
                          else None)
            if rel in self._dirs or descendant is not None:
                info = self._entries.get(rel)
                other = descendant if descendant is not None else rel
                if _zip_is_link(info):
                    raise SourceError(
                        f"zip archive is not a representable tree: {rel!r} "
                        "is a directory symlink and also has archived "
                        f"children or an explicit directory entry ({other!r}); "
                        "refusing instead of silently hiding the members "
                        "under it")
                raise SourceError(
                    f"zip archive is not a representable tree: {rel!r} is a "
                    "file and also a directory (or has archived children: "
                    f"{other!r}) — refusing the archive instead of silently "
                    "hiding members under it")

    def _detect_root(self) -> str:
        """The single top-level directory, or "" when the archive is flat.

        A root exists only when EVERY entry lives under one directory.
        Host exports list the root dir itself as an entry ("site.test/") —
        a directory entry without an internal slash is the TOP DIR, not a
        flat-archive file; only a top-level FILE disqualifies detection.
        """
        top: set[str] = set()
        saw_escaping = False
        for info in self._zf.infolist():
            name = info.filename.replace("\\", "/").strip("/")
            if not name:
                continue
            if _escapes_archive_root(name):
                # An escaping member is not evidence about the webroot's
                # shape, and must never become the auto root (R6-20).
                saw_escaping = True
                continue
            if "/" not in name:
                if not info.is_dir():
                    return ""  # a top-level FILE: flat archive
                top.add(name)  # the root directory itself ("site.test/")
            else:
                top.add(name.split("/", 1)[0])
            if len(top) > 1:
                return ""  # more than one top-level dir: not a single root
        if not top and saw_escaping:
            # Nothing BUT escaping members: there is no safe webroot here.
            # Return the unsafe sentinel so the caller's path guard refuses
            # the archive instead of opening an empty source (R6-20).
            return ".."
        return top.pop() if len(top) == 1 else ""

    # ------------------------------------------------------------------ reading

    def list_dir(self, path: str) -> list[Entry]:
        rel = self._guard_path(path) if path else ""
        prefix = f"{rel}/" if rel else ""
        seen: dict[str, Entry] = {}
        for name, info in self._entries.items():
            if not name.startswith(prefix):
                continue
            rest = name[len(prefix):]
            if "/" in rest:
                child, _, _ = rest.partition("/")
                key = self._join(rel, child)
                if key not in seen:
                    mode, mtime = _entry_meta(self._dirs.get(key))
                    seen[key] = Entry(path=key, is_dir=True, size=0,
                                      mode=mode, mtime=mtime)
            else:
                mode, mtime = _entry_meta(info)
                seen[name] = Entry(path=name, is_dir=False,
                                   size=info.file_size, mode=mode,
                                   mtime=mtime,
                                   is_link=_zip_is_link(info))
        # Explicit directory entries that have NO files of their own are
        # still real archive members (an empty wp-content/uploads/).  The
        # file-prefix loop above cannot synthesize them, so walk the
        # recorded directory paths exactly like file paths: a nested
        # ``wp-content/uploads/`` with no parent entry still yields the
        # direct child ``wp-content`` at the root, then ``uploads``.
        for name, info in self._dirs.items():
            if not name.startswith(prefix):
                continue
            rest = name[len(prefix):]
            if "/" in rest:
                child, _, _ = rest.partition("/")
                key = self._join(rel, child)
                if key not in seen:
                    mode, mtime = _entry_meta(self._dirs.get(key))
                    seen[key] = Entry(path=key, is_dir=True, size=0,
                                      mode=mode, mtime=mtime)
            elif name not in seen:
                mode, mtime = _entry_meta(info)
                seen[name] = Entry(path=name, is_dir=True, size=0,
                                   mode=mode, mtime=mtime)
        return list(seen.values())

    def read_bytes(self, path: str) -> bytes:
        rel = self._guard_path(path)
        if rel not in self._entries:
            raise SourceError(f"no such file in archive: {rel}")
        return _read_member(self._zf, self._entries[rel], rel)

    def read_bytes_bounded(self, path: str, max_bytes: int) -> bytes:
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) \
                or max_bytes < 0:
            raise SourceError(f"invalid read bound: {max_bytes!r}")
        rel = self._guard_path(path)
        info = self._entries.get(rel)
        if info is None:
            raise SourceError(f"no such file in archive: {rel}")
        if info.file_size > max_bytes:
            raise SourceError(
                f"{rel!r} is larger than the {max_bytes}-byte read bound")
        return _read_member(self._zf, info, rel, max_bytes)

    def exists(self, path: str) -> bool:
        try:
            rel = self._guard_path(path)
        except SourceError:
            return False
        if rel in self._entries or rel in self._dirs:
            return True
        prefix = f"{rel}/"
        # An explicit directory entry ("a/b/") makes its parents real even
        # when no file lives under them; the listing already yields "a".
        return any(name.startswith(prefix)
                   for name in (*self._entries, *self._dirs))

    def size(self, path: str) -> int:
        rel = self._guard_path(path)
        if rel in self._entries:
            return self._entries[rel].file_size
        if rel in self._dirs or self.exists(rel):
            return 0  # directory
        raise SourceError(f"no such file in archive: {rel}")

    # ---------------------------------------------------------------- mutations

    def _refuse(self, op: str, path: str) -> None:
        raise NotWritableError(
            f"zip source is read-only; would {op} {path!r} "
            "(v1 local mode reports a plan instead of rewriting archives)"
        )

    def write_bytes(self, path: str, data: bytes, *, allow_config: bool = False,
                    allow_core: bool = False) -> None:
        self._check_writable(path, allow_config, allow_core)
        self._refuse("write", self._guard_path(path))

    def delete(self, path: str, *, allow_config: bool = False,
               allow_core: bool = False) -> None:
        self._check_deletable(path, allow_config, allow_core)
        self._refuse("delete", self._guard_path(path))

    def rmdir(self, path: str) -> None:
        self._check_deletable(path)
        self._refuse("remove directory", self._guard_path(path))

    def rmdir_recursive(self, path: str) -> None:
        self._check_deletable(path)
        self._refuse("remove tree", self._guard_path(path))

    def close(self) -> None:
        self._zf.close()
