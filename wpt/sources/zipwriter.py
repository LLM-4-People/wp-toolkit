"""MutableZipSource — the local-REHEARSAL write target over an offline zip.

Plain ``ZipSource`` keeps its v1 read-only contract (mutating ops raise
NotWritableError); rehearsal mutability is OPT-IN via this subclass.
Mutations stage in an in-memory overlay on top of the read-only view and
``materialize()`` writes the merged tree to a NEW zip next to (never over)
the original.
"""

import os
import posixpath
import secrets
import shutil
import time
import zipfile
from bisect import bisect_left
from pathlib import Path

from ..deadline import Deadline
from ..log import get_logger
from ..types import Entry, SourceError
from .zip import (ZipSource, _MEMBER_READ_ERRORS, _entry_meta,
                  _read_member, _zip_is_link)

log = get_logger("sources.zipwriter")

# Normalized zip entry attrs: ``materialize()`` writes EVERY entry with
# these, whatever the input entries carried (live defect: staged entries
# defaulted to 0600 and DOS-archive-bit inputs copied verbatim parsed as
# garbage unix modes — an extracted rehearsal left files unreadable by
# the serving uid, 27,352 owner-unreadable files in one live run).
# Structural zip-format facts, not profile tunables.
_UNIX_CREATE_SYSTEM = 3  # zip host-system code for Unix
_FILE_EXTERNAL_ATTR = (0o100644 << 16) | 0x20  # -rw-r--r-- + DOS archive bit
_DIR_EXTERNAL_ATTR = (0o40755 << 16) | 0x10  # drwxr-xr-x + DOS directory bit


def _sweep_stale_wip(dest: Path, age_s: float) -> None:
    """Remove a killed run's hidden ``.wip`` sibling older than ``age_s``.

    The current run journals its own candidate before creating it; a
    process killed in an earlier run could not, so only AGE-distinguishable
    residue is swept (a recent file may belong to a concurrent rehearsal).
    """
    cutoff = time.time() - max(0.0, float(age_s))
    for candidate in dest.parent.glob(f".{dest.name}.*.wip"):
        try:
            info = candidate.lstat()
        except OSError:
            continue
        if candidate.is_symlink() or not candidate.is_file():
            continue
        if info.st_mtime >= cutoff:
            continue
        try:
            candidate.unlink()
        except OSError as exc:
            log.warning("stale rehearsal temp %s could not be removed: %s",
                        candidate, exc)
        else:
            log.info("swept stale rehearsal temp %s", candidate)


class MutableZipSource(ZipSource):
    """ZipSource + the Source write protocol: the local-rehearsal target.

    The rehearsal contract (user-requested local ``--apply``):

    * Actions run UNCHANGED. The actions registry and the harden/restore
      flows speak only the Source protocol (read_bytes/write_bytes/
      delete/rmdir_recursive/exists/list_dir/walk), so a Source that
      IMPLEMENTS the write protocol makes every action rehearsal-capable
      with zero edits.
    * The original archive is IMMUTABLE. ``write_bytes``/``delete``/
      ``rmdir_recursive`` stage into an in-memory overlay
      (``_staged``: path -> bytes, ``_deleted``: tombstones); the zip
      file on disk is never opened for writing, and every read
      (read_bytes/exists/size/list_dir/walk — walk is the shared
      WalkMixin over list_dir) resolves the overlay first, so consumers
      see exactly the tree a live run would see after each op:
      walk = original entries + staged - deleted, with staged bytes'
      sizes; a staged path that did not exist originally appears; a
      deleted path disappears even from walk; an explicit empty directory
      the archive carries survives unless it (or an ancestor) was deleted,
      and a directory derived only from now-deleted files vanishes; a
      deleted-then-rewritten path reappears — the write clears the
      tombstone.
    * ``materialize(dest)`` writes the merged tree to a NEW zip at dest:
      the cleaned copy. Fail-closed: dest must not exist and must never
      be the original path; parents are created; the archive is built at
      ``dest.with_suffix(".tmp")`` and renamed into place, so a failure
      leaves no half-written zip and no .tmp behind. Original entries
      stream from the source zip (compress_type and date_time preserved
      exactly) and staged entries come from memory; EVERY entry —
      original, staged or synthesized directory — carries normalized
      deployable attrs (files ``-rw-r--r--``, dirs ``drwxr-xr-x``, Unix
      create_system), whatever the input entries carried; every
      directory with surviving children
      gets a real trailing-slash dir entry, and entry names are
      re-prefixed with ``self.root`` — a fresh ``ZipSource`` over the
      output auto-detects the same root and resolves the same
      webroot-relative paths.

    Guards are the SAME shared discipline FtpSource applies
    (``types.Source._check_writable``/``_check_deletable``), including
    the ``allow_config=True`` unlock for wp-config.php/.htaccess with the
    guard's own audit log line — so a rehearsal refuses and permits
    exactly what the live run would. ``close()`` closes the underlying
    archive and discards staging (the caller materializes first when the
    cleaned copy is wanted).

    The opt-in pin: mutating ops on a PLAIN ZipSource still raise
    NotWritableError, unchanged — mutability exists only through this
    subclass.
    """

    def __init__(self, zip_path: Path, root: str | None = None, *,
                 deadline: Deadline | None = None) -> None:
        super().__init__(zip_path, root, deadline=deadline)
        self._staged: dict[str, bytes] = {}
        self._deleted: set[str] = set()

    # ------------------------------------------------------------------ overlay

    def _live_sizes(self) -> dict[str, int]:
        """The merged tree: webroot-relative path -> current size.

        Original entries minus tombstones, overlaid by staged writes (a
        staged write of an existing path shadows its original size; a
        staged path that did not exist originally appears here).
        """
        merged: dict[str, int] = {
            name: info.file_size
            for name, info in self._entries.items()
            if name not in self._deleted
        }
        for name, data in self._staged.items():
            merged[name] = len(data)
        return merged

    def _deleted_here(self, name: str) -> bool:
        """True when ``name`` or one of its ancestors was tombstoned.

        The tombstone set is a SET OF PATHS, not a set of prefixes to scan:
        every ancestor of ``name`` is a bounded lookup (one per path
        component), so this predicate is O(depth) instead of the old
        O(len(tombstones)) prefix scan.  ``rmdir_recursive`` already
        tombstones every member, but a plain delete of a directory must
        also hide its explicit child directory entries.
        """
        if name in self._deleted:
            return True
        parent = name
        while "/" in parent:
            parent = parent.rsplit("/", 1)[0]
            if parent in self._deleted:
                return True
        return False

    def _live_dirs(self) -> set[str]:
        """Explicit directory entries that survive the overlay.

        An archive's explicit empty directory (``wp-content/uploads/``) is
        a real member a plain ``ZipSource`` lists; the overlay must keep it
        unless the run deleted it (or an ancestor), otherwise the rehearsal
        tree silently differs from the source it rehearses.

        The ancestor test walks each path's OWN components (bounded by its
        depth), never every tombstone for every directory: 5,000 deleted
        directories against 5,000 live ones was a 12.97 s scan between
        deadline checks.
        """
        if not self._deleted:
            return set(self._dirs)
        return {name for name in self._dirs if not self._deleted_here(name)}

    # ------------------------------------------------------------------ reading

    def list_dir(self, path: str) -> list[Entry]:
        rel = self._guard_path(path) if path else ""
        prefix = f"{rel}/" if rel else ""
        seen: dict[str, Entry] = {}
        for name, size in self._live_sizes().items():
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
                # A staged path has no zip entry of its own, and one it
                # shadows no longer describes the staged bytes — mode and
                # mtime stay unknown rather than describing the old entry.
                info = None if name in self._staged else self._entries.get(name)
                mode, mtime = _entry_meta(info)
                seen[name] = Entry(path=name, is_dir=False, size=size,
                                   mode=mode, mtime=mtime,
                                   is_link=_zip_is_link(info))
        for name in self._live_dirs():
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
                mode, mtime = _entry_meta(self._dirs.get(name))
                seen[name] = Entry(path=name, is_dir=True, size=0,
                                   mode=mode, mtime=mtime)
        return list(seen.values())

    def read_bytes(self, path: str) -> bytes:
        rel = self._guard_path(path)
        if rel in self._staged:
            return self._staged[rel]
        if rel in self._deleted or rel not in self._entries:
            raise SourceError(f"no such file in archive: {rel}")
        return _read_member(self._zf, self._entries[rel], rel)

    def read_bytes_bounded(self, path: str, max_bytes: int) -> bytes:
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) \
                or max_bytes < 0:
            raise SourceError(f"invalid read bound: {max_bytes!r}")
        rel = self._guard_path(path)
        if rel in self._staged:
            data = self._staged[rel]
            if len(data) > max_bytes:
                raise SourceError(
                    f"{rel!r} is larger than the {max_bytes}-byte read bound")
            return data
        if rel in self._deleted or rel not in self._entries:
            raise SourceError(f"no such file in archive: {rel}")
        info = self._entries[rel]
        if info.file_size > max_bytes:
            raise SourceError(
                f"{rel!r} is larger than the {max_bytes}-byte read bound")
        return _read_member(self._zf, info, rel, max_bytes)

    def exists(self, path: str) -> bool:
        try:
            rel = self._guard_path(path)
        except SourceError:
            return False
        live = self._live_sizes()
        dirs = self._live_dirs()
        if rel in live or rel in dirs:
            return True
        prefix = f"{rel}/"
        return (any(name.startswith(prefix) for name in live)
                or any(name.startswith(prefix) for name in dirs))

    def size(self, path: str) -> int:
        rel = self._guard_path(path)
        live = self._live_sizes()
        if rel in live:
            return live[rel]
        dirs = self._live_dirs()
        prefix = f"{rel}/"
        if (rel in dirs or any(name.startswith(prefix) for name in live)
                or any(name.startswith(prefix) for name in dirs)):
            return 0  # directory (explicit or derived from surviving paths)
        raise SourceError(f"no such file in archive: {rel}")

    # ---------------------------------------------------------------- mutations

    def write_bytes(self, path: str, data: bytes, *, allow_config: bool = False,
                    allow_core: bool = False) -> None:
        # Same guard discipline as FtpSource: the shared _check_writable
        # owns the protected-file policy AND the guarded-config audit line.
        self._check_writable(path, allow_config, allow_core)
        rel = self._guard_path(path)
        self._staged[rel] = data
        self._deleted.discard(rel)  # a delete followed by a write un-deletes

    def delete(self, path: str, *, allow_config: bool = False,
               allow_core: bool = False) -> None:
        self._check_deletable(path, allow_config, allow_core)
        rel = self._guard_path(path)
        self._staged.pop(rel, None)
        # Tombstone; idempotent — a path that was never there just stays
        # absent, no error (the staging double, tests/fakes.FakeSource,
        # pops silently the same way).
        self._deleted.add(rel)

    def rmdir(self, path: str) -> None:
        self._check_deletable(path)
        rel = self._guard_path(path)
        if self.list_dir(rel):
            raise SourceError(f"directory is not empty: {rel}")
        self._deleted.add(rel)

    def rmdir_recursive(self, path: str) -> None:
        self._check_deletable(path)
        rel = self._guard_path(path)
        prefix = f"{rel}/"
        for name in [n for n in self._staged if n == rel or n.startswith(prefix)]:
            del self._staged[name]
        for name in self._entries:
            if name == rel or name.startswith(prefix):
                self._deleted.add(name)
        for name in self._dirs:
            if name == rel or name.startswith(prefix):
                self._deleted.add(name)
        self._deleted.add(rel)

    def rename(self, src: str, dst: str, *, allow_config: bool = False,
               allow_core: bool = False) -> None:
        """Re-key ``src`` (a file OR a whole directory) to ``dst`` in the
        overlay — the local twin of the FTP tree swap.

        Everything under ``src`` moves with it: the staged writes (the
        replacements), the original entries (what an untouched file
        resolves to) and the tombstones (so a deletion staged inside the
        renamed tree stays a deletion instead of reappearing at the old
        path).  Nothing is read, decompressed or rewritten, which is what
        a rename IS: a materialized rehearsal is an archive, and only
        ``materialize`` ever turns paths back into bytes.  A destination
        that already holds entries is replaced, the same outcome the FTP
        server's own rename gives.  The destination goes through
        ``_check_rename_target``, exactly as on the live source.
        """
        self._check_rename_source(src, allow_config, allow_core)
        self._check_rename_target(dst, allow_config, allow_core)
        rel_src = self._guard_path(src)
        rel_dst = self._guard_path(dst)
        if rel_src == rel_dst:
            return
        prefix = f"{rel_src}/"
        dst_prefix = f"{rel_dst}/"

        def moved(name: str) -> str:
            if name.startswith(prefix):
                return rel_dst + name[len(rel_src):]
            return rel_dst

        # FTP RNTO REPLACES the destination tree (it does not merge into
        # it).  Tombstone every destination entry first, in all three
        # stores, so a materialized rehearsal cannot keep a stale file the
        # live site's swap would have removed.
        for store in (self._staged, self._entries, self._dirs):
            for name in [n for n in store
                         if n == rel_dst or n.startswith(dst_prefix)]:
                del store[name]
        for name in [n for n in self._deleted
                     if n == rel_dst or n.startswith(dst_prefix)]:
            self._deleted.discard(name)
        for store in (self._staged, self._entries, self._dirs):
            for name in [n for n in store
                         if n == rel_src or n.startswith(prefix)]:
                store[moved(name)] = store.pop(name)
        for name in [n for n in self._deleted
                     if n == rel_src or n.startswith(prefix)]:
            self._deleted.discard(name)
            self._deleted.add(moved(name))

    # ------------------------------------------------------------- materialize

    def _arcname(self, rel: str) -> str:
        """Raw archive name for a webroot-relative path (re-prefix)."""
        return f"{self.root}/{rel}" if self.root else rel

    def _dir_prefixes(self, live: dict[str, int],
                      live_dirs: set[str]) -> set[str]:
        """Raw archive names of every directory that survives the overlay.

        Real host exports carry explicit dir entries; the twin mirrors
        that: ONE trailing-slash entry per directory prefix (the root
        itself when ``self.root`` is set and anything survives).  Explicit
        empty directories are archive members in their own right and are
        kept even when no file lives under them — deleting a directory (or
        an ancestor) removes them through the tombstone check.

        ``live_dirs`` is the caller's already-computed surviving explicit
        set: materialize must not pay the overlay scan twice.
        """
        dirs: set[str] = set()
        for rel in (*live, *live_dirs):
            parent = posixpath.dirname(rel)
            while parent:
                dirs.add(self._arcname(parent) + "/")
                parent = posixpath.dirname(parent)
            if rel in live_dirs:
                dirs.add(self._arcname(rel) + "/")
        if (live or live_dirs) and self.root:
            dirs.add(f"{self.root}/")
        return dirs

    def materialize(self, dest: Path, *,
                    stale_temp_age_s: float | None = None) -> Path:
        """Write the merged tree to a NEW zip at dest; return dest.

        Fail-closed: dest must not exist and must never be the original
        archive (the original is only ever read). Parents of dest are
        created; the archive is assembled at a hidden unique ``.wip``
        sibling and PUBLISHED with ``os.link`` (an atomic no-replace
        create), never ``os.replace``: a destination that appears between
        the precheck and publication is preserved and refused. Original
        entries stream from the source zip with compress_type and
        date_time preserved exactly;
        EVERY entry — original, staged or synthesized directory — is
        written with the normalized deployable attrs, whatever the input
        entries carried, and an original entry past zipfile's zip64
        threshold is written in the zip64 format instead of failing the
        copy mid-stream.
        """
        dest = Path(dest)
        if dest.resolve() == self.zip_path.resolve():
            raise SourceError(
                f"materialize dest must not be the original archive: {dest}"
            )
        if dest.exists():
            raise SourceError(f"materialize dest already exists: {dest}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        if stale_temp_age_s is not None:
            _sweep_stale_wip(dest, stale_temp_age_s)
        if self._deadline is not None:
            self._deadline.check("rehearsal materialize")
        live = self._live_sizes()
        live_dirs = self._live_dirs()
        if self._deadline is not None:
            self._deadline.check("rehearsal materialize")
        # ONE sorted list owns the descendant question: a path has an
        # archived descendant exactly when the first name at or after
        # ``rel + "/"`` starts with that prefix.  Scanning every surviving
        # name per file was O(n^2) (10k members: 5.5 s, 20k: 49 s) and put
        # an unbounded amount of work between the run deadline checks.
        names = sorted((*live, *live_dirs))
        # A directory symlink is a FILE member (its bytes are the target),
        # but an archive that also carries children under that name cannot
        # represent both a link and a real directory.  Refuse rather than
        # emit two members with the same name (R11-P2-10).
        for rel in live:
            if self._deadline is not None:
                self._deadline.check("rehearsal materialize")
            info = self._entries.get(rel)
            if not _zip_is_link(info):
                continue
            child_at = bisect_left(names, rel + "/")
            has_child = (child_at < len(names)
                         and names[child_at].startswith(rel + "/"))
            if rel in live_dirs or has_child:
                raise SourceError(
                    f"cannot materialize {rel!r}: it is a directory symlink "
                    "and also has archived children or an explicit directory "
                    "entry")
        # A FILE path can never also be a directory.  A zip can carry
        # ``site/a`` as a file and ``site/a/b`` as another member (or an
        # explicit ``site/a/`` directory entry); walking then yields ``a``
        # as a file and ``a/b`` is unreachable, while materialize emits
        # both a file and a directory with the same name.  Refuse the whole
        # tree rather than write an archive no extractor can represent.
        for rel in live:
            if self._deadline is not None:
                self._deadline.check("rehearsal materialize")
            if _zip_is_link(self._entries.get(rel)):
                continue  # the more specific symlink refusal above owns it
            child_at = bisect_left(names, rel + "/")
            has_child = (child_at < len(names)
                         and names[child_at].startswith(rel + "/"))
            if rel in live_dirs or has_child:
                raise SourceError(
                    f"cannot materialize {rel!r}: it is a file and also a "
                    "directory (or has archived children) — refusing a "
                    "tree that cannot be represented in a zip")
        # A UNIQUE hidden sibling: ``dest.with_suffix(".tmp")`` could equal
        # the source archive (``site.tmp`` -> ``site.zip`` truncated its own
        # input) or clobber a pre-existing user file.  The candidate is
        # JOURNALED before ``O_CREAT|O_EXCL``: mkstemp created the ``.wip``
        # first and assigned its name afterwards, so a stop on that boundary
        # left a file no finally could see (R6-23/R25).  Only OUR path is
        # ever unlinked on failure.
        tmp: Path | None = None
        try:
            for _ in range(100):
                candidate = dest.parent / (
                    f".{dest.name}.{secrets.token_hex(16)}.wip")
                tmp = candidate
                try:
                    fd = os.open(
                        candidate,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600)
                except FileExistsError:
                    tmp = None
                    continue
                os.close(fd)
                break
            if tmp is None:
                raise SourceError(
                    f"cannot reserve a rehearsal temp beside {dest}")
            if tmp.resolve() == self.zip_path.resolve():
                raise SourceError(
                    f"materialize temp must not be the source archive: {tmp}")
            with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as out:
                for dname in sorted(self._dir_prefixes(live, live_dirs)):
                    if self._deadline is not None:
                        self._deadline.check("rehearsal materialize")
                    member = zipfile.ZipInfo(dname)
                    member.external_attr = _DIR_EXTERNAL_ATTR
                    member.create_system = _UNIX_CREATE_SYSTEM
                    out.writestr(member, b"")
                for rel in sorted(live):
                    if self._deadline is not None:
                        self._deadline.check("rehearsal materialize")
                    if rel in self._staged:
                        member = zipfile.ZipInfo(
                            self._arcname(rel),
                            date_time=time.localtime(time.time())[:6],
                        )
                        member.compress_type = out.compression
                        member.external_attr = _FILE_EXTERNAL_ATTR
                        member.create_system = _UNIX_CREATE_SYSTEM
                        out.writestr(member, self._staged[rel])
                        continue
                    info = self._entries[rel]
                    member = zipfile.ZipInfo(
                        self._arcname(rel), date_time=info.date_time
                    )
                    member.compress_type = info.compress_type
                    if _zip_is_link(info):
                        # A symlink member IS its target string; rewriting
                        # the attrs as a regular file turned it into PHP
                        # content in the rehearsed archive.
                        member.external_attr = info.external_attr
                        member.create_system = (
                            info.create_system or _UNIX_CREATE_SYSTEM)
                    else:
                        member.external_attr = _FILE_EXTERNAL_ATTR
                        member.create_system = _UNIX_CREATE_SYSTEM
                    # A streamed entry's size is unknown when the header is
                    # written, so zipfile picks the 32-bit format and raises
                    # "File size too large, try using force_zip64" the moment
                    # the copy passes 2 GiB — a rehearsal of a webroot with
                    # one big uploaded video would die on the copy, not on
                    # anything the operator can act on. The source entry's
                    # real size IS known, so ask for zip64 exactly when it is
                    # needed (never unconditionally: the extra field would
                    # then be written on every entry of every rehearsal).
                    try:
                        with self._zf.open(info) as src, out.open(
                                member, "w",
                                force_zip64=info.file_size > zipfile.ZIP64_LIMIT,
                        ) as dst:
                            shutil.copyfileobj(src, dst)
                    except _MEMBER_READ_ERRORS as exc:
                        # A stored member with one corrupt byte raises
                        # ``BadZipFile: Bad CRC-32``; encrypted/unsupported
                        # members raise RuntimeError/NotImplementedError and
                        # zlib failures raise zlib.error.  None is a WptError
                        # or OSError, so the registry's error contract would
                        # miss it and the CLI would traceback (ZIP1).
                        raise SourceError(
                            f"cannot read {rel!r} from the zip archive: {exc}"
                        ) from exc
            # PUBLISH without replacing: ``os.link`` is an atomic
            # create-that-fails-if-dest-exists, so a destination that
            # appeared after the precheck is never overwritten.  Then drop
            # our temp link (the published inode remains at dest).
            try:
                os.link(tmp, dest)
            except FileExistsError:
                raise SourceError(
                    f"materialize dest already exists: {dest}") from None
            tmp.unlink()
            tmp = None
        except BaseException:
            if tmp is not None:
                tmp.unlink(missing_ok=True)
            raise
        log.debug("materialized %d surviving file(s) -> %s", len(live), dest)
        return dest

    # ------------------------------------------------------------------- close

    def close(self) -> None:
        # Staging is discarded with the handle (materialize first when
        # the cleaned copy is wanted); the original file was never written.
        self._staged.clear()
        self._deleted.clear()
        super().close()
