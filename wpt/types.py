"""Core types: source contract, findings, plan items, exceptions.

Every source connector (FTP, zip, ...) inherits the path guards implemented here so
safety rules live at one choke point.
"""

import posixpath
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator


class WptError(Exception):
    """Base class for OPERATIONAL errors (source, driver, validation)."""


class RunControl(BaseException):
    """A run-ending control signal, never an operational diagnosis.

    Deliberately a ``BaseException``, like ``KeyboardInterrupt``,
    ``SystemExit`` and ``asyncio.CancelledError``: a cancellation signal
    must not be swallowed by the generic containment every command uses for
    per-item/per-row recovery (108 ``except Exception`` sites and every
    ``(WptError, OSError)`` error contract).  The one place that answers it
    is the dispatch boundary (``cli.main``) and ``run_action``: they log one
    redacted line, write the shared failure markdown + JSON pair when asked,
    and return rc 1 after the command's own ``finally`` teardowns ran.

    Only the two control-flow signals inherit this class.  Ordinary
    operational failures stay :class:`WptError` / ``OSError`` so they keep
    their existing containment and diagnosis-row behavior.
    """


class StopRequested(RunControl):
    """A cooperative stop request (SIGTERM) that must unwind the run.

    Distinct from an ordinary operational failure so per-item containment
    layers (the doctor's per-check rows) can re-raise it BEFORE their generic
    catch-all: a stop request is never a diagnosis row.  Inherits
    :class:`RunControl` (a ``BaseException``), so ``except Exception`` cannot
    eat it.
    """


class SourceError(WptError):
    """A source-level failure (connection, missing path, rejected path)."""


class SourceLookupError(SourceError):
    """A path lookup could not be answered (transport failure).

    Deliberately DISTINCT from "not found": callers may treat a successful
    listing that omits a path as absence, but a lookup that failed on the
    wire proves nothing and must never be recorded as an absent file.
    """


class FtpChannelUnhealthy(SourceError):
    """The FTP session's data channel is persistently dead (the source's
    consecutive-failure breaker tripped).  NOT a not-found answer: exists()
    and size() must propagate it instead of masking it as a missing file,
    and every command body's (WptError, OSError) contract contains it."""


class NotWritableError(WptError):
    """A mutating operation is not permitted for this source/path."""


class DeadlineExceeded(RunControl):
    """A run's self-imposed wall-time bound expired (settings
    run.deadline_s / --deadline). The run ends ITSELF through the normal
    cleanup + teardown path and rc 1 — the graceful replacement for ever
    killing a wedged run from outside.  Inherits :class:`RunControl` (a
    ``BaseException``), so an ordinary ``except Exception`` handler can
    never convert the expiry into a partial success or a diagnosis row."""


class BridgeError(WptError):
    """The PHP bridge returned an error payload or could not be reached."""

    def __init__(self, message: str, payload: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.payload = payload or {}


# ---------------------------------------------------------------------------
# update-core's webroot residue: the ONE owner of the name rule.
#
# A core update stages each replaced tree BESIDE the live one
# (``wp-includes.wpt-new/``), parks the tree it replaces under a retired
# name while the new one is verified, and writes every root file under a
# temp name — so three webroot-root name shapes are wpt's own residue, and
# a run that is SIGKILLed mid-swap leaves some of them behind.  The rule
# lives HERE, not in the action that creates the names, because two
# consumers must agree on it and a second derivation is how a sweep starts
# deleting a name it does not own: the action's own sweep (which removes
# the staging/temp names and must NEVER touch a retired one) and the
# operator-facing report (which names every one of them and says who owns
# it).  Both read this table; neither re-derives a suffix.
# ---------------------------------------------------------------------------

#: A staged copy of a core tree: ``wp-admin.wpt-new/``.  Pure staging —
#: the live tree still holds the installed core, so wpt removes it.
RESIDUE_STAGED = "staged"
#: A parked copy of what the swap replaced: ``wp-includes.wpt-old/`` (a
#: tree) or ``index.php.wpt-old`` (a root file).  This is the LAST copy of
#: the installed core on the site: the operator or the pre-action snapshot
#: owns it, the sweep must never delete it, and it is REPORTED with the
#: live name it goes back to.
RESIDUE_RETIRED = "retired"
#: A root file written under its temp name before the rename: ``index.php.wpt-tmp``.
#: A partial or complete copy of a file the live tree still holds, so wpt
#: removes it.
RESIDUE_TEMP = "temp"

#: The suffixes themselves, ONE owner for the action and the residue rule.
CORE_STAGE_SUFFIX = ".wpt-new"
CORE_RETIRED_SUFFIX = ".wpt-old"
CORE_TMP_SUFFIX = ".wpt-tmp"

#: The name-shape rule, longest suffix first (``wpt-old`` before ``wpt-tmp``
#: never collides, but order is explicit rather than incidental).
_RESIDUE_SUFFIXES = (
    (CORE_RETIRED_SUFFIX, RESIDUE_RETIRED),
    (CORE_STAGE_SUFFIX, RESIDUE_STAGED),
    (CORE_TMP_SUFFIX, RESIDUE_TEMP),
)

#: What each residue role means for the sweep and for the operator-facing
#: report — ONE sentence per role, so the two surfaces cannot disagree.
RESIDUE_OWNER = {
    RESIDUE_STAGED: "wpt's own staging copy — removed by the next sweep",
    RESIDUE_TEMP: "wpt's own temp copy of a root file — removed by the "
                  "next sweep",
    RESIDUE_RETIRED: "the copy of the core the swap replaced — the "
                     "operator or `wpt restore --undo-last` owns it; wpt "
                     "never deletes it",
}


def update_core_residue(path: str) -> str | None:
    """The residue role of a webroot-relative path, or None if it is not one.

    ONLY a webroot-ROOT name can be residue, and that is by construction:
    every name the update creates is a sibling of the tree it replaces
    (``wp-includes.wpt-new``, ``wp-includes.wpt-old``) or of a root file
    (``index.php.wpt-tmp``, ``index.php.wpt-old``).  A path with a
    directory component therefore cannot be one — a site that ships
    ``wp-content/backups/index.php.wpt-tmp`` is carrying somebody else's
    file, and a sweep that removed it on a name rule would be deleting
    content this tool never wrote.
    """
    if not isinstance(path, str) or "/" in path.strip("/"):
        return None
    name = path.strip()
    for suffix, role in _RESIDUE_SUFFIXES:
        if name.endswith(suffix) and len(name) > len(suffix):
            return role
    return None


@dataclass
class Entry:
    """One item from a source tree, relative to the source root (POSIX path).

    ``mode``/``mtime``/``owner``/``group`` are the metadata a protocol can
    supply — FTP's ``LIST`` carries all four, a zip carries a POSIX mode and
    an mtime, and a synthetic source carries none.  They are OPTIONAL on
    purpose: ``None`` means "the source did not tell us", never a fabricated
    zero.  Consumers that need a permission fact (the uploads-permission
    check) stay silent when the fact is absent rather than guess.

    ``size`` is ``SIZE_UNKNOWN`` when the protocol supplied a listing line
    whose size field was not a byte count (a non-Unix LIST dialect).  A
    fabricated ``0`` would let a size gate admit any body; consumers that
    cannot verify a size must skip or read with a hard bound instead.
    """

    path: str
    is_dir: bool
    size: int
    is_link: bool = False
    mode: int | None = None
    mtime: int | None = None
    owner: str | None = None
    group: str | None = None


#: ``Entry.size`` sentinel for a protocol listing that did not carry a
#: verifiable byte count (see :class:`Entry`).
SIZE_UNKNOWN = -1


@dataclass
class Finding:
    """A single audit observation.

    category: dotted namespace, e.g. "webroot.junk", "db.revisions", "media.orphan".
    risk: low | medium | high; anything above low lands in "Needs your call".
    """

    category: str
    name: str
    detail: str
    bytes: int = 0
    count: int = 1
    risk: str = "low"
    fix: str = ""

    def validate(self) -> "Finding":
        if self.risk not in ("low", "medium", "high"):
            raise ValueError(f"invalid risk: {self.risk!r}")
        if not self.category or not self.name:
            raise ValueError("category and name are required")
        return self


@dataclass
class PlanItem:
    """One proposed (or executed) change from an action.

    ``ref`` is the action's STRUCTURAL reference for the item (e.g. the
    login a users_reset item resets).  It is never parsed back out of the
    human ``detail`` label: a legal WordPress role/login can contain the
    punctuation a label parser would split on (C11).
    """

    category: str
    target: str
    detail: str
    bytes_est: int = 0
    requires_apply: bool = True
    done: bool = False
    ref: str = ""


class Source(ABC):
    """Contract every source connector implements.

    Paths are POSIX and relative to ``root``. Guards live here so every connector
    enforces identical safety rules.
    """

    #: WordPress's webroot-ROOT core files.  They are source code, not site
    #: configuration: heal-core/update-core may replace them under the
    #: audited ``allow_core`` unlock, and a verified snapshot restore may
    #: roll them back under that same unlock; selected-file edit/restore and
    #: delete never may.  ``wp-config-sample.php`` is official core too and
    #: is NOT the live config.  ONE table: the protected set below, the
    #: write unlock and the rename guards all read it.
    CORE_ROOT_FILES = frozenset(
        {
            "wp-load.php",
            "wp-settings.php",
            "wp-blog-header.php",
            "wp-cron.php",
            "wp-login.php",
            "xmlrpc.php",
            "wp-signup.php",
            "wp-activate.php",
            "wp-trackback.php",
            "wp-comments-post.php",
            "wp-mail.php",
            "wp-links-opml.php",
            "wp-config-sample.php",
        }
    )
    CORE_ROOT_FILES_FOLDED = frozenset(
        name.casefold() for name in CORE_ROOT_FILES)

    # Paths that are never writable/deletable (config is edited via a dedicated,
    # diff-printing helper; core dirs are structural).
    PROTECTED = frozenset(
        {
            "wp-config.php",
            ".htaccess",
            "index.php",
            "wp-admin",
            "wp-admin/",
            "wp-includes",
            "wp-includes/",
        }
    ) | CORE_ROOT_FILES

    #: ``PROTECTED`` folded once — the ONE membership table the write,
    #: delete and rename guards compare against, so a case-insensitive FTP
    #: host cannot be reached through an alias (``WP-CONFIG.PHP``).
    PROTECTED_FOLDED = frozenset(item.casefold() for item in PROTECTED)

    root: str

    @contextmanager
    def deadline_suspended(self):
        """Replace an expired run budget with a FRESH finite cleanup budget.

        A rollback or residue cleanup runs BECAUSE the forward work failed,
        often because the run deadline expired.  The expiry is permanent, so
        a source that keeps honouring it can never issue the delete/read a
        rollback needs, and a half-applied site stays half-applied.  This
        owner swaps in a NEW budget for the cleanup block, then RESTORES the
        exact previous object — including on an exception, so the caller's
        normal stop contract is unchanged.

        Cleanup is NOT unbounded: a peer dripping one byte per read resets a
        per-read socket timeout forever, so detaching the budget entirely
        let cleanup (or a retry/close inside it) hang.  The fresh budget is
        ``run.cleanup_deadline_s`` (attached to the source by the ONE
        construction seam); a source built without it falls back to the
        previous budget's own configured length, still finite.
        """
        previous = getattr(self, "deadline", None)
        if previous is None:
            yield
            return
        seconds = getattr(self, "cleanup_deadline_s", None)
        if not isinstance(seconds, (int, float)) or isinstance(seconds, bool) \
                or seconds <= 0:
            seconds = max(1.0, float(getattr(previous, "_seconds", 1.0)))
        from .deadline import Deadline

        self.deadline = Deadline(float(seconds))
        try:
            yield
        finally:
            self.deadline = previous

    def _guard_path(self, path: str) -> str:
        """Normalize and validate a relative path; raise SourceError on unsafe input."""
        if not isinstance(path, str) or not path:
            raise SourceError("empty path")
        if any(ord(char) < 32 or ord(char) == 127
               or 0xD800 <= ord(char) <= 0xDFFF for char in path):
            # C0/DEL/surrogates would reach ftplib.putline as a raw
            # ValueError/UnicodeEncodeError (neither is a WptError) and can
            # smuggle a second command into an FTP line.  Reject at the one
            # path choke point every connector shares.
            raise SourceError(f"unsafe path rejected: {path!r}")
        # Windows (and a Windows-hosted FTP server) strip trailing dots and
        # spaces from a path segment, so ``wp-admin.``/``wp-config.php.``
        # reach the protected name while every casefolded comparison sees an
        # unprotected string.  Reject the alias BEFORE normpath can turn
        # ``wp-content/.. /wp-config.php`` into the protected file.  The
        # canonical POSIX ``.``/``..`` segments stay legal: normpath owns
        # them, and neither is a dot/space ALIAS of a protected name.
        for segment in path.replace("\\", "/").split("/"):
            if segment in ("", ".", ".."):
                continue
            if segment != segment.rstrip(" ."):
                raise SourceError(
                    f"unsafe path rejected: {path!r} carries a segment with "
                    f"a trailing dot/space ({segment!r}), which a Windows "
                    f"filesystem folds onto another name"
                )
        norm = posixpath.normpath(path.replace("\\", "/"))
        if norm.startswith("/") or norm.startswith("..") or "/../" in norm:
            raise SourceError(f"unsafe path rejected: {path!r}")
        if norm in (".", ".."):
            raise SourceError(f"unsafe path rejected: {path!r}")
        return norm

    def _guard_returned_path(self, path: str) -> str:
        """Validate a CONNECTOR-RETURNED name; refuse a lossy normalization.

        ``_guard_path`` normalizes ``\\`` to ``/`` because an operator may
        type a Windows-shaped path.  A connector's name is not operator
        input: on a POSIX FTP host ``wp-content\\evil.php`` is ONE legal
        file name, and rewriting it to ``wp-content/evil.php`` addresses a
        different file (usually none).  A backup then reported the real
        file ``absent`` and never captured it -- a silent hole in the
        rollback substrate.  The shared walk and the walk-to-snapshot
        boundary use THIS door, so a connector name that the guard would
        change fails closed, naming the raw name, instead of being
        silently rewritten or omitted.  Ordinary ``./a`` spellings remain
        the guard's business (a fake/test source may emit them).
        """
        if isinstance(path, str) and path.replace("\\", "/") != path:
            raise SourceError(
                f"connector returned a path containing a backslash "
                f"({path!r}); on this POSIX source it is a literal filename "
                "character, and normalizing it would address a different "
                "file -- refusing instead of omitting the entry")
        return self._guard_path(path)

    def _check_writable(self, path: str, allow_config: bool,
                        allow_core: bool = False) -> None:
        """Raise NotWritableError unless writing ``path`` is permitted.

        ``allow_config`` unlocks the two site-configuration files the harden/
        restore flows must be able to write (wp-config.php, .htaccess) and
        AUDITS the unlocked write with a warning log line.

        ``allow_core`` unlocks the WordPress CORE restore surface — the
        root ``index.php``, the other official root core files, plus
        everything under ``wp-admin/`` and ``wp-includes/`` — for the
        legitimate consumers: the heal-core action, update-core's tree
        swap, and :func:`wpt.restore.restore_snapshot` (the pre-action
        snapshot restore every core-changing action advertises as its
        rollback).  heal-core itself writes only paths PROVEN
        tampered/missing against wp.org's official checksums and extracted
        from the official release zip of the site's exact version; restore
        writes the exact bytes its verified snapshot captured.  wp-config.php
        and .htaccess are NEVER core-healable (wp.org does not ship them;
        they stay config-only behind ``allow_config``), and the bare
        directory names themselves stay refused.  The unlocked write is
        audited with a warning log line, exactly like ``allow_config``.

        Everything else in PROTECTED is never writable: the toolkit does
        not edit WordPress source outside the two audited unlocks.  The
        two core DIRECTORIES protect their whole subtree on the write
        path (wp-admin/includes/x.php is as untouchable as wp-admin
        itself); deletes inside them stay allowed — junk
        (wp-admin/error_log) is exactly what clean-files removes, and
        _check_deletable keeps its own exact-membership rule.
        """
        norm = self._guard_path(path)
        folded = norm.casefold()
        if (folded in self.PROTECTED_FOLDED
                or folded.startswith(("wp-admin/", "wp-includes/"))):
            if allow_config and folded in ("wp-config.php", ".htaccess"):
                # Lazy import: wpt.log -> wpt.config -> wpt.types would be a
                # module-level cycle; the guard fires only on config writes.
                from .log import get_logger

                get_logger("source").warning(
                    "guarded write to protected config file: %s", norm)
                return
            if (allow_core and (folded == "index.php"
                                or folded in self.CORE_ROOT_FILES_FOLDED
                                or folded.startswith(("wp-admin/",
                                                      "wp-includes/")))):
                # Same lazy-import rationale: fires only on core heals.
                from .log import get_logger

                get_logger("source").warning(
                    "guarded core heal: restoring protected core file: %s",
                    norm)
                return
            raise NotWritableError(f"refusing to write protected path: {norm}")

    def _check_deletable(self, path: str, allow_config: bool = False,
                         allow_core: bool = False) -> None:
        """Raise SourceError when ``path`` must never be deleted.

        The root CORE FILES are protected from WRITES/renames (source code
        is never edited by this toolkit), but deletion stays the junk
        policy's turf: clean-files legitimately removes
        ``wp-config-sample.php`` and an operator can name a bare core entry
        point as junk on purpose (the webroot-junk door's pinned
        counter-case).  Config files, ``index.php`` and the two core trees
        keep the delete refusal.

        The two audited unlocks mirror :meth:`_check_writable` exactly:
        ``allow_config`` covers wp-config.php/.htaccess and ``allow_core``
        covers index.php (the only protected core entry point restore's
        verified-absent plan may need to remove after harden/heal-core
        created it).  Every unlocked delete is audited with a warning, and
        the bare core directory names stay refused.
        """
        norm = self._guard_path(path)
        folded = norm.casefold()
        if (folded in self.PROTECTED_FOLDED
                and folded not in self.CORE_ROOT_FILES_FOLDED):
            if allow_config and folded in ("wp-config.php", ".htaccess"):
                from .log import get_logger  # lazy: wpt.log -> wpt.config cycle

                get_logger("source").warning(
                    "guarded delete of protected config file: %s", norm)
                return
            if allow_core and folded == "index.php":
                from .log import get_logger  # lazy: wpt.log -> wpt.config cycle

                get_logger("source").warning(
                    "guarded core heal: deleting protected core file: %s",
                    norm)
                return
            raise SourceError(f"refusing to delete protected path: {norm}")
        # The webroot IS the account root for root="" (the documented
        # mapping of --webroot /), so the structural wp-content guard must
        # not depend on root being non-empty.
        if folded.count("/") == 0 and folded == "wp-content":
            raise SourceError(f"refusing to delete structural dir: {norm}")

    def _check_rename_source(self, path: str, allow_config: bool,
                             allow_core: bool) -> None:
        """Where :meth:`rename` may take a name FROM.

        A rename MOVES bytes out of ``path`` exactly as a delete would, so
        the protected-name rule belongs to the source too: without it
        ``wp-config.php -> stolen.php`` and ``wp-admin -> moved`` walked
        past the delete guard.  The ONE legitimate mover is update-core's
        tree swap, which needs the same audited ``allow_core`` unlock the
        destination already takes; config files are never renameable (core
        updates do not replace them).
        """
        norm = self._guard_path(path)
        folded = norm.casefold()
        if folded in ("wp-config.php", ".htaccess"):
            raise NotWritableError(
                f"refusing to rename protected config path: {norm}")
        if (folded == "wp-content" or folded in self.PROTECTED_FOLDED
                or folded.startswith(("wp-admin/", "wp-includes/"))):
            if not allow_core:
                raise NotWritableError(
                    f"refusing to rename protected path: {norm}")
            from .log import get_logger  # lazy: wpt.log -> wpt.config cycle

            get_logger("source").warning(
                "guarded core heal: moving the protected path: %s", norm)
            return

    def _check_rename_target(self, path: str, allow_config: bool,
                             allow_core: bool) -> None:
        """Where :meth:`rename` may LAND — :meth:`_check_writable` plus the
        the three bare structural DIRECTORY names (``wp-admin``,
        ``wp-includes``, ``wp-content``).

        A write to ``wp-admin`` is refused for the reason it always was: no
        write lands bytes on a directory.  A RENAME does exactly that, and
        the update-core action's per-tree swap needs it: the whole point of
        staging ``wp-includes.wpt-new/`` and renaming it into place is
        that the swap is ONE filesystem operation, so a failure can never
        leave the tree holding half of two releases.

        The unlock is the SAME audited one a write to every file under
        those trees already takes (``allow_core``, plus its warning line),
        and it covers nothing more: without ``allow_core`` the bare names
        stay refused, and every other protected path is handed to
        ``_check_writable`` unchanged, so the config files never become
        renameable either.  ``wp-content`` takes the SAME locked branch: a
        rename onto the structural content tree replaces it exactly as a
        delete would (R6-22).
        """
        norm = self._guard_path(path)
        folded = norm.casefold()
        if folded in ("wp-admin", "wp-includes", "wp-content"):
            if not allow_core:
                raise NotWritableError(
                    f"refusing to rename onto protected path: {norm}"
                )
            from .log import get_logger  # lazy: wpt.log -> wpt.config cycle

            get_logger("source").warning(
                "guarded core heal: swapping the protected core tree: %s",
                norm)
            return
        self._check_writable(path, allow_config, allow_core)

    def ensure_write_dir(self, path: str) -> None:
        """Guarantee that the PARENT of ``path`` can receive a write.

        The write contract's first half, and the reason it is a method
        rather than something every caller does: a store that materializes
        an intermediate directory on its own needs nothing (a zip overlay
        derives its directory entries from the surviving file paths at
        materialize time), while a PROTOCOL that addresses a file by name
        inside an existing directory needs the directory to BE there
        first.  FTP is that protocol: ``STOR <path>`` into a directory the
        server does not have answers 553 and the file is never created, so
        a connector that speaks it must ensure the parent chain before the
        first byte moves — which is why the guarantee lives HERE, at the
        one chokepoint every writer already calls, instead of in the one
        caller that happened to trip over it (the update-core staging
        path; backup, restore, the bridge and a deploy-shaped write
        inherit it by writing at all).

        The DEFAULT is the honest no-op: a source whose storage creates
        intermediate entries implicitly has nothing to ensure, and a
        connector must not issue protocol traffic for a directory its
        store already holds.  An implementation that DOES need it
        (FtpSource) makes the directory exist, and a directory it cannot
        make exist raises :class:`SourceError` with one line naming the
        path — never lets the protocol's own 553 escape as the run's
        diagnosis, which is a bare server string outside every command
        body's ``(WptError, OSError)`` contract.
        """
        return None

    def rename(self, src: str, dst: str, *, allow_config: bool = False,
               allow_core: bool = False) -> None:
        """Rename one webroot-relative path (file OR directory subtree).

        NOT abstract, and refused by default: a connector can only honour
        it if its protocol can (FTP has RNFR/RNTO, a zip overlay remaps
        paths), and a source that cannot must say so rather than
        silently degrade into "write every file again" — which is exactly
        the half-updated tree this operation exists to avoid.

        ``dst`` goes through :meth:`_check_rename_target`, which is
        :meth:`_check_writable` plus the two bare core tree names a
        staging swap must be able to land on — for the same reason a
        rename needs the destination checked at all: it puts bytes there.
        The SOURCE goes through :meth:`_check_rename_source` for the mirror
        reason: moving a protected name away is a delete by another name.
        Both unlocks are the SAME audited ``allow_core``; config files are
        never renameable.

        The ONE consumer is the update-core action's swap, where the
        guarantee is that a failure anywhere in the write phase can be
        rolled back and never leaves the site holding half of two
        releases — over a tree, over a root file, and (through the same
        two renames in reverse) over both at once. Every connector that
        implements it keeps the guards: both paths go through
        :meth:`_guard_path`.
        """
        raise NotWritableError(
            f"this source cannot rename {src!r} -> {dst!r}"
        )

    def read_bytes_bounded(self, path: str, max_bytes: int) -> bytes:
        """Read one file with a hard byte bound (the ONE bounded-read seam).

        Connectors whose transport can stream (FTP, zip) override this to
        stop the read at ``max_bytes + 1``; the default keeps the same
        contract for in-memory/tests sources.  The bound is a post-read
        check here and a PRE-read/streaming stop in the real connectors, so
        a lying listing size can never materialize an unbounded body.
        """
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) \
                or max_bytes < 0:
            raise SourceError(f"invalid read bound: {max_bytes!r}")
        data = self.read_bytes(path)
        if len(data) > max_bytes:
            raise SourceError(
                f"{path!r} is larger than the {max_bytes}-byte read bound"
            )
        return data

    @abstractmethod
    def list_dir(self, path: str) -> list[Entry]:
        """Children of ``path`` (entries carry is_link where the protocol allows)."""

    @abstractmethod
    def walk(self, path: str = "", *,
             include_links: bool = False) -> Iterator[Entry]:
        """Yield every entry under ``path``, recursing into real subdirectories only.

        ``include_links`` yields symlink entries (never descends into them);
        the default keeps them out of backup/audit walks, while a removal
        traversal must SEE them to delete the link before RMD.
        """

    @abstractmethod
    def read_bytes(self, path: str) -> bytes:
        ...

    @abstractmethod
    def write_bytes(self, path: str, data: bytes, *, allow_config: bool = False,
                    allow_core: bool = False) -> None:
        """Write one file, after :meth:`ensure_write_dir` has made its
        parent directory exist (a connector whose protocol requires it —
        FTP's STOR — must call it before the first byte moves, so a write
        into a NEW directory is a create-then-store and not a bare 553)."""
        ...

    @abstractmethod
    def delete(self, path: str, *, allow_config: bool = False,
               allow_core: bool = False) -> None:
        """Delete one file (never a protected path unless an audited unlock)."""

    def rmdir(self, path: str) -> None:
        """Delete one EMPTY directory, non-recursively.

        The TOCTOU-safe removal primitive: the server/host must refuse when
        anything arrived in the directory after the caller's last listing.
        Connectors without it fail closed; callers must never fall back to
        ``rmdir_recursive`` after an emptiness check.
        """
        self._check_deletable(path)
        raise SourceError(
            f"cannot remove directory {path!r}: this source does not "
            "implement a non-recursive rmdir"
        )

    @abstractmethod
    def rmdir_recursive(self, path: str) -> None:
        """Delete a directory subtree (never a protected path)."""

    @abstractmethod
    def exists(self, path: str) -> bool:
        ...

    @abstractmethod
    def size(self, path: str) -> int:
        ...

    @abstractmethod
    def close(self) -> None:
        ...


# ---------------------------------------------------------------------------
# Source-level absence and delete proof.
#
# ``Source.exists`` may map a lookup failure to False (FtpSource does), so a
# False answer is NEVER proof that a file is gone.  Every caller that must
# clean up or report residue asks the parent listing instead, through these
# helpers, so the rule has one owner.
# ---------------------------------------------------------------------------


def absence_proven(source: Source, path: str) -> bool:
    """True only when a SUCCESSFUL listing proves ``path`` is absent.

    ``False`` means the parent listing contains the path.  A failed parent
    listing is not absence: walk to the grandparent, where a successful
    listing that omits the parent proves the whole chain missing (the
    new-file-in-a-new-directory case).  If the chain cannot be proven —
    transport failure, denied listing, or an existing-but-unlistable
    parent — raise: absence is unproven and the caller must fail closed.

    The ancestor walk is ITERATIVE (R7 residual): one frame per missing
    ancestor let an operator-supplied deep path raise ``RecursionError``
    instead of the command's ``WptError`` contract.  A failed listing at
    depth ``d`` is remembered with its child, so the refusal names the same
    parent/target pair the recursive form did.
    """
    # (child, failed_parent, exception) for every ancestor whose listing
    # failed, nearest first.
    failures: list[tuple[str, str, BaseException]] = []
    current = path
    while True:
        parent = posixpath.dirname(current)
        try:
            listing = source.list_dir(parent)
        except FtpChannelUnhealthy:
            raise
        except SourceLookupError:
            raise
        except (SourceError, OSError) as exc:
            if not parent:
                raise WptError(
                    f"the webroot listing failed ({exc}); absence of "
                    f"{current!r} is unproven"
                ) from exc
            failures.append((current, parent, exc))
            current = parent
            continue
        break
    folded = current.rstrip("/").casefold()
    if not any(entry.path.rstrip("/").casefold() == folded
               for entry in listing):
        return True
    if not failures:
        return False
    child, failed_parent, exc = failures[-1]
    raise WptError(
        f"parent {failed_parent!r} exists but cannot be listed ({exc}); "
        f"absence of {child!r} is unproven"
    ) from exc


def presence_proven(source: Source, path: str) -> bool:
    """True/False when the source can answer; absence only on proof.

    ``Source.exists`` may RAISE ``SourceLookupError`` when SIZE and the
    parent listing both failed — a failed lookup, not a "missing" answer.
    That lookup is resolved through :func:`absence_proven`: when a
    successful listing proves the path (or its missing parent chain) absent,
    the answer is a truthful False; otherwise the lookup error propagates so
    callers fail closed instead of guessing.  ONE helper for every presence
    decision that can face an unanswerable lookup.
    """
    try:
        return source.exists(path)
    except (StopRequested, DeadlineExceeded):
        raise
    except SourceLookupError:
        if absence_proven(source, path):
            return False
        raise


def path_may_exist(source: Source, path: str) -> bool:
    """True unless a SUCCESSFUL listing proves ``path`` absent.

    A ``True`` from ``exists`` is enough to attempt the delete; a ``False``
    answer is corroborated by the parent listing because a lookup failure
    can be masked as absence.  A failed listing proves nothing, so the path
    is treated as possibly present (fail closed: delete it).
    """
    try:
        if source.exists(path):
            return True
    except (StopRequested, DeadlineExceeded):
        raise
    except Exception:  # noqa: BLE001 — a failed lookup is not absence
        pass
    try:
        return not absence_proven(source, path)
    except (StopRequested, DeadlineExceeded):
        raise
    except Exception:  # noqa: BLE001 — an unproven listing is not absence
        return True


def delete_or_prove_absent(source: Source, path: str) -> None:
    """Delete ``path``; a failure is excused only by a proven absence.

    The delete is attempted UNCONDITIONALLY: a protocol that applies DELE
    and loses the answer must not be reported as residue.  A refused delete
    whose absence cannot be proven propagates, so the caller keeps tracking
    the file and can retry it.
    """
    try:
        source.delete(path)
    except (StopRequested, DeadlineExceeded):
        raise
    except Exception:  # noqa: BLE001 — absence proof decides
        if not absence_proven(source, path):
            raise
