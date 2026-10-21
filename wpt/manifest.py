"""Transfer manifest for :mod:`wpt.deploy` — the integrity handoff for a deploy.

WHY A MANIFEST: a streamed webroot deploy is a one-way operation. The
archive leaves the operator's machine through a pipe and is unpacked by a
remote ``tar`` — there is no intermediate file anywhere to re-read (that
is the whole point: the zip plus its extraction can exceed the account
quota on a constrained host). The only way the
operator can later answer "did the site that landed match the site we
shipped?" is a record of the streamed set's hashes, written BEFORE the
run is called a success. :mod:`wpt.deploy` builds that record while the
bytes pass through (hashing in the producer costs no extra read) and
verifies it against a re-read of the target.

STYLE, NOT FORK (:mod:`wpt.backup` is the reference format owner): this
module IMPORTS the pieces it shares — :data:`wpt.backup.MANIFEST_NAME`,
:data:`wpt.backup._WPT_VERSION` (the one version lookup) and
:func:`wpt.backup.sanitize_site_label` — and follows the same shape:
UTF-8 JSON, ``indent=2``, ``ensure_ascii=False``, ``allow_nan=False``,
a trailing newline, the same identity keys first (``site``, ``action``,
``created`` ISO-8601 local, ``wpt_version``), a ``files`` list of
``{path, sha256, size}`` in webroot-relative POSIX order, and a
``totals`` object.

DELIBERATE DIVERGENCE from the backup manifest (documented so a reader
does not mistake it for a snapshot):

* ``format``/``version`` are ``wpt-deploy-manifest``/1.  A transfer
  manifest is NOT a restorable snapshot — it holds no payload, so
  ``wpt restore`` must never accept one.
* no ``tables`` key and no ``absent`` key: a deploy streams what exists
  and asserts afterwards, so "the target did not have this" is not a
  fact this record carries.
* an ``archive`` block (the SOURCE artifact's own facts: name, byte
  size, entry count, uncompressed size, the stripped root, and the
  whole-archive sha256 when it was computed) and a ``target`` block
  (where it landed).  A backup manifest describes a snapshot directory;
  this one describes an artifact and a destination.

Secrets: the target block records the ssh DESTINATION (``user@host``,
port, remote webroot) — never a password, and never the NAME of the env
var a password would come from beyond what the operator already typed on
the command line.
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import secrets
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from .backup import MANIFEST_NAME, _WPT_VERSION, sanitize_site_label
from .log import get_logger
from .types import WptError

__all__ = [
    "MANIFEST_NAME", "DEPLOY_MANIFEST_FORMAT", "DEPLOY_MANIFEST_VERSION",
    "ManifestError", "VerificationResult", "build_manifest", "write_manifest",
    "read_manifest", "verify_files", "sha256_file",
]

log = get_logger("deploy.manifest")

#: Format identity of a deploy transfer manifest. Distinct from
#: :data:`wpt.backup.MANIFEST_FORMAT` on purpose — this record has no
#: payload, so ``wpt restore`` must refuse it rather than half-restore.
DEPLOY_MANIFEST_FORMAT = "wpt-deploy-manifest"
DEPLOY_MANIFEST_VERSION = 1

#: Read chunk for hashing a payload (structural: it bounds the verifier's
#: memory, not an operator policy).
_HASH_CHUNK = 1024 * 1024


class ManifestError(WptError):
    """A transfer manifest is missing, malformed, or of a foreign format."""


@dataclass(frozen=True)
class VerificationResult:
    """The verdict of comparing a manifest against a re-read of the target.

    ``rc`` is the deploy's exit code contribution: 0 only when every
    streamed file was found on the target AND hashed identically.  A
    mismatch is a FAILED deploy, never a warning — the operator's only
    evidence that the site matches the artifact just died.
    """

    checked: int
    mismatched: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()
    unreadable: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not (self.mismatched or self.missing or self.unreadable)

    @property
    def rc(self) -> int:
        return 0 if self.ok else 1

    def message(self) -> str:
        """One actionable line naming what did not match."""
        if self.ok:
            return f"deploy verified: {self.checked} streamed file(s) match the manifest"
        parts: list[str] = []
        if self.missing:
            parts.append(f"{len(self.missing)} missing on the target "
                         f"(first: {', '.join(self.missing[:3])})")
        if self.mismatched:
            parts.append(f"{len(self.mismatched)} hash mismatch "
                         f"(first: {', '.join(self.mismatched[:3])})")
        if self.unreadable:
            parts.append(f"{len(self.unreadable)} unreadable on the target "
                         f"(first: {', '.join(self.unreadable[:3])})")
        return ("deploy verification FAILED — " + "; ".join(parts)
                + " — the target does not match the shipped artifact")


def _is_safe_rel(path: object) -> bool:
    """True for a webroot-relative POSIX path that cannot escape its root.

    Mirrors the Source path guard's shape for a DIFFERENT trust boundary:
    these paths come out of an untrusted archive, so the check is the
    manifest's own — a path that could escape the webroot is refused at
    build AND at read time.
    """
    if not isinstance(path, str) or not path:
        return False
    if "\x00" in path or "\\" in path:
        return False
    norm = posixpath.normpath(path)
    return not norm.startswith(("/", "..")) and norm not in ("", ".", "..")


def _now() -> str:
    return datetime.now().astimezone().isoformat()


def build_manifest(
    *,
    site: str,
    target: str,
    webroot: str,
    zip_name: str,
    entry_count: int,
    uncompressed_bytes: int,
    files: Mapping[str, tuple[str, int]],
    archive_bytes: int = 0,
    root: str = "",
    archive_sha256: str | None = None,
    action: str = "deploy",
    created: str | None = None,
) -> dict[str, Any]:
    """Build the transfer manifest for one streamed deploy.

    ``files`` maps a webroot-relative POSIX path to
    ``(sha256_hex, size)`` — the streamed set, hashed IN THE PRODUCER as
    the bytes passed through (so building the record costs no second read
    of a multi-gigabyte archive). Entries are emitted in sorted path
    order, deterministically, exactly like the backup manifest.

    ``archive_sha256`` is the WHOLE-ARCHIVE digest; it is optional
    (``None`` when the operator did not pay for the extra full read) and
    the block is still present so the schema never changes shape.

    Raises :class:`ManifestError` on an unsafe path, a non-hex digest or
    a negative size — the record is the deploy's only integrity claim,
    so a malformed one is refused rather than written.
    """
    entries: list[dict[str, Any]] = []
    for path in sorted(files):
        if not _is_safe_rel(path):
            raise ManifestError(f"unsafe path in deploy manifest: {path!r}")
        digest, size = files[path]
        if (not isinstance(digest, str) or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest.lower())):
            raise ManifestError(f"bad sha256 for {path!r}")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ManifestError(f"bad size for {path!r}")
        entries.append({"path": path, "sha256": digest.lower(), "size": size})
    if archive_sha256 is not None and (
            not isinstance(archive_sha256, str) or len(archive_sha256) != 64):
        raise ManifestError("bad archive sha256")
    return {
        "format": DEPLOY_MANIFEST_FORMAT,
        "version": DEPLOY_MANIFEST_VERSION,
        "site": sanitize_site_label(site),
        "action": action,
        "created": created or _now(),
        "wpt_version": _WPT_VERSION,
        "target": {"ssh_target": target, "webroot": webroot},
        "archive": {
            "name": zip_name,
            "bytes": int(archive_bytes),
            "entries": int(entry_count),
            "uncompressed_bytes": int(uncompressed_bytes),
            "root": root,
            "sha256": archive_sha256.lower() if archive_sha256 else None,
        },
        "files": entries,
        "totals": {
            "files": len(entries),
            "bytes": sum(e["size"] for e in entries),
        },
    }


def _open_manifest_directory(directory: Path, root: Path) -> int:
    """Open ``directory`` under ``root`` WITHOUT following any component.

    Returns an ``O_DIRECTORY`` fd for the final directory; missing
    components are created beneath the trusted ``root``.  ``O_NOFOLLOW``
    on every step is the owner of the R22 defect: a planted
    ``<backup>/deploy -> victim`` symlink made ``mkdir(parents=True)`` and
    the temp write land in ``victim``.  ``root`` itself is the caller's
    trust anchor and may be a symlink (the operator named it).
    """
    directory = Path(directory)
    if ".." in directory.parts:
        raise ManifestError(
            f"deploy manifest directory {directory} contains '..'")
    root = Path(root)
    root_abs = Path(os.path.abspath(root))
    dir_abs = Path(os.path.abspath(directory))
    try:
        relative = dir_abs.relative_to(root_abs)
    except ValueError as exc:
        raise ManifestError(
            f"deploy manifest directory {directory} is not under {root}") \
            from exc
    try:
        Path(root_abs).mkdir(parents=True, exist_ok=True)
        fd = os.open(root_abs, os.O_RDONLY | os.O_DIRECTORY)
    except OSError as exc:
        raise ManifestError(
            f"cannot create deploy manifest root {root}: {exc}") from exc
    try:
        for part in relative.parts:
            if part in ("", ".", ".."):
                raise ManifestError(
                    f"deploy manifest directory {directory} has an invalid "
                    f"component {part!r}")
            try:
                os.mkdir(part, dir_fd=fd)
            except FileExistsError:
                pass
            try:
                next_fd = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=fd,
                )
            except OSError as exc:
                raise ManifestError(
                    f"deploy manifest directory component {part!r} under "
                    f"{directory} is a symbolic link or not a directory") \
                    from exc
            os.close(fd)
            fd = next_fd
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    return fd


def write_manifest(manifest: Mapping[str, Any], directory: Path,
                   *, root: Path | None = None) -> Path:
    """Write ``manifest.json`` into ``directory`` (created if needed).

    LOCAL disk only — the manifest never travels to the target: a
    deploy's own purpose is that no intermediate file lands on a
    quota-bound host, and this record is the operator's copy.

    The write is atomic and never follows a planted target OR ancestor:
    every component from ``root`` (the caller's ``--backup-dir``; when
    omitted, the cwd or filesystem anchor the directory is checked
    against) to ``directory`` is opened with
    ``O_DIRECTORY|O_NOFOLLOW``, and the JSON is written to a fresh sibling
    created with ``O_CREAT|O_EXCL|O_NOFOLLOW`` via the same directory fd,
    fsynced, then replaced relative to that fd.  A symlinked
    ``<backup>/deploy`` therefore cannot redirect the record (or its
    temp) outside the backup tree.
    """
    directory = Path(directory)
    if root is not None:
        anchor = Path(root)
    else:
        # No trust anchor supplied: check every component of the ABSOLUTE
        # directory (a relative path is checked from the cwd it names).
        cwd = Path.cwd()
        try:
            directory.absolute().relative_to(cwd)
            anchor = cwd
        except ValueError:
            anchor = Path(directory.absolute().anchor or os.sep)
    fd = _open_manifest_directory(directory, anchor)
    tmp_name: str | None = None
    write_fd = -1
    try:
        try:
            info = os.stat(MANIFEST_NAME, dir_fd=fd,
                           follow_symlinks=False)
        except FileNotFoundError:
            info = None
        except OSError as exc:
            raise ManifestError(
                f"cannot inspect deploy manifest {directory / MANIFEST_NAME}: "
                f"{exc}") from exc
        if info is not None:
            if stat.S_ISLNK(info.st_mode):
                raise ManifestError(
                    f"deploy manifest target "
                    f"{directory / MANIFEST_NAME} is a symbolic link")
            if not stat.S_ISREG(info.st_mode):
                raise ManifestError(
                    f"deploy manifest target "
                    f"{directory / MANIFEST_NAME} is not a regular file")
        try:
            payload = json.dumps(manifest, indent=2, ensure_ascii=False,
                                 allow_nan=False) + "\n"
        except ValueError as exc:  # allow_nan=False
            raise ManifestError(
                f"transfer manifest is not JSON-encodable: {exc}") from exc
        for _ in range(100):
            candidate = f".{MANIFEST_NAME}.{secrets.token_hex(8)}.wip"
            # Register the candidate BEFORE creating it: a stop between a
            # successful open and the assignment of ``tmp_name`` left an
            # unreferenced ``.wip`` that no finally could remove.
            tmp_name = candidate
            try:
                write_fd = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600, dir_fd=fd)
            except FileExistsError:
                tmp_name = None
                continue
            break
        if write_fd < 0 or tmp_name is None:
            raise ManifestError(
                f"cannot reserve a temp file for deploy manifest "
                f"{directory / MANIFEST_NAME}")
        # ``backslashreplace`` is the report's safe_text policy: an argv
        # label or webroot carrying a lone surrogate (surrogateescape) is a
        # JSON-encodable string but not a strict-UTF-8 one; encoding it must
        # not escape the deploy's (DeployError, OSError) contract or lose
        # the release record.
        with os.fdopen(write_fd, "w", encoding="utf-8",
                       errors="backslashreplace") as handle:
            write_fd = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, MANIFEST_NAME,
                   src_dir_fd=fd, dst_dir_fd=fd)
        tmp_name = None
    except OSError as exc:
        raise ManifestError(
            f"cannot write deploy manifest "
            f"{directory / MANIFEST_NAME}: {exc}") from exc
    finally:
        if write_fd >= 0:
            try:
                os.close(write_fd)
            except OSError:
                pass
        if tmp_name is not None:
            try:
                os.unlink(tmp_name, dir_fd=fd)
            except OSError:
                pass
        try:
            os.close(fd)
        except OSError:
            pass
    path = directory / MANIFEST_NAME
    log.info("deploy manifest written: %s (%d file(s))", path, len(manifest["files"]))
    return path


def read_manifest(path: Path) -> dict[str, Any]:
    """Read + gate a transfer manifest. Raises :class:`ManifestError`.

    The gate is the format identity: a snapshot manifest, a truncated
    file or a hand-edited ``version`` must never be verified AS IF it
    were a deploy record.
    """
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ManifestError(f"cannot read manifest {path}: {exc}") from exc
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise ManifestError(f"manifest {path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ManifestError(f"manifest {path} is not an object")
    if data.get("format") != DEPLOY_MANIFEST_FORMAT:
        raise ManifestError(
            f"manifest {path} is not a deploy transfer manifest "
            f"(format={data.get('format')!r})")
    if data.get("version") != DEPLOY_MANIFEST_VERSION:
        raise ManifestError(
            f"manifest {path} has unsupported version {data.get('version')!r}")
    files = data.get("files")
    if not isinstance(files, list):
        raise ManifestError(f"manifest {path} has no files list")
    return data


def verify_files(manifest: Mapping[str, Any],
                 observed: Mapping[str, str]) -> VerificationResult:
    """Compare a manifest's streamed set against hashes read back on the target.

    ``observed`` maps a webroot-relative path to the sha256 read on the
    target. A path in the manifest with no observation is ``missing``; a
    path whose digest differs is ``mismatched``; a path present in
    ``observed`` but absent from the manifest is NOT a failure — the
    deploy is ADDITIVE by contract, so host-injected files
    (``wp-content/imunify-security/...`` and friends) legitimately exist
    on the target without being in the artifact, and demanding they not
    exist would make the tool delete a host's own state.

    Never raises: a malformed entry is counted as unreadable so the
    deploy answers rc 1 rather than a traceback.
    """
    mismatched: list[str] = []
    missing: list[str] = []
    unreadable: list[str] = []
    checked = 0
    entries = manifest.get("files")
    if not isinstance(entries, list):
        return VerificationResult(0, unreadable=("<no files list>",))
    for entry in entries:
        if (not isinstance(entry, dict) or not _is_safe_rel(entry.get("path"))
                or not isinstance(entry.get("sha256"), str)):
            unreadable.append(str(entry)[:80])
            continue
        path = entry["path"]
        digest = entry["sha256"].lower()
        actual = observed.get(path)
        if actual is None:
            missing.append(path)
        elif actual.lower() != digest:
            mismatched.append(path)
        else:
            checked += 1
    return VerificationResult(checked, tuple(mismatched), tuple(missing),
                              tuple(unreadable))


def sha256_file(path: Path, deadline: Any = None) -> str:
    """sha256 of a local file, chunked (never a whole multi-GB read).

    ``deadline`` is the run's absolute budget (anything with ``check``):
    a multi-GB archive on slow storage must not outlive --deadline while
    local hashing continues after the last network phase.  None keeps the
    programmatic unbounded contract.
    """
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            if deadline is not None:
                deadline.check("deploy archive hash")
            chunk = handle.read(_HASH_CHUNK)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()
