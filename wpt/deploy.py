"""Streaming webroot deploy — the engine behind ``wpt deploy`` (SPEC §deploy).

THE FAILURE THIS EXISTS FOR (a real migration onto a constrained host):
uploading the prepared webroot zip AND extracting it crossed the account
quota mid-transfer, and the host answered with messages that named nothing:
``Error in the SSH layer``, ``write remote: Failure``, chunks truncated at
the protocol boundary.  The zip never needed to be on the box at all: a
pipe carries the bytes, the remote ``tar`` unpacks them as they arrive, and
the account never holds both.  That is the whole design of
:func:`deploy_stream`.

THE SECOND FAILURE — THE DOUBLE STRIP.  A first attempt shipped files one
level too deep because the archive's single top-level host
directory was stripped in BOTH the producer and the consumer.  So the
strip has exactly ONE owner here: the producer, through
:class:`wpt.sources.zip.ZipSource` — the module that already owns "a host
export nests everything under one site dir" (SPEC §FTP source).  The
remote command is ``tar -xf - -C <webroot>`` and nothing else: no
``--strip-components``, no ``cd`` into a guessed parent.
:func:`assert_target` then re-reads the target and REFUSES a deploy
showing the residue of the double strip (a ``wp-includes`` child such as
``ID3/``, or an ``about.php`` sitting at the webroot root) even when the
required files happen to be present.

THE CONTRACT, in order:

1. **Dry run first, always.** :func:`build_plan` is pure: it opens the
   zip's central directory and counts.  It touches no target and spawns
   no process.
2. **Quota preflight before a single byte moves.** :func:`preflight`
   measures the deploy account's available space through the target
   (``df -Pk`` / ``quota`` parse; a write-and-remove probe when the parse
   is ambiguous) and REFUSES with one actionable line naming both
   numbers when the streamed set cannot fit.  Unknown space is a refusal
   too: an unproven large write is the exact loss this command exists to
   prevent.
3. **Stream, ADDITIVE only.**  ``tar -x`` never deletes, so
   host-injected content (``wp-content/imunify-security/`` and friends)
   survives by construction — and :func:`verify_against_manifest` does
   not complain about files the artifact never shipped.
4. **Assert the layout, then verify the bytes.**  :func:`assert_target`
   requires ``wp-config.php`` + ``wp-load.php`` + ``wp-includes/version.php``
   and a ``wp-content`` directory AT THE WEBROOT ROOT, with no
   doubly-stripped residue — every wp-includes child the residue list
   names is probed AT THE ROOT, which is the exact place the failed
   attempt put it (``ID3/``, ``about.php``), so a doubly-stripped tree is
   refused by name instead of silently shipping.  The webroot DIRECTORY
   itself is created by the host's ``mkdir -p`` and keeps the host's own
   mode and mtime: normalizing it would rewrite the hosting panel's view
   of its own tree for no gain.  :func:`verify_against_manifest` then
   re-reads the streamed set's sha256s on the target; a mismatch is
   rc 1, never a warning.
5. **Secrets never in argv, never logged.**  The ssh password comes from
   an env var (``--ssh-password-env``) or a prompt
   (:func:`wpt.config.resolve_password`); it is handed to ssh through an
   ``SSH_ASKPASS`` helper that reads a 0600 file inside a 0700 temporary
   directory, so the secret is in neither the child's argv nor its
   environment, and the whole thing is removed in a ``finally``.  With no
   password, the target uses key/agent auth with ``BatchMode=yes`` so the
   process can never hang on a prompt.  When neither is available the
   deploy REFUSES with one line instead of hanging.

SELF-BOUNDING (SPEC rule 10): a deploy is the longest run in the toolkit,
so it never relies on an external kill.  The run
:class:`~wpt.deadline.Deadline` is checked once per archive member
(:func:`stream_archive`), the ssh channel carries
``ServerAliveInterval``/``ServerAliveCountMax`` so a dead peer is caught
in minutes rather than hanging on a half-open pipe, and
:meth:`Target.extract` bounds the child with a timeout and kills only the
child it started itself.

TESTING SEAMS: the subprocess seam is the single private :func:`_spawn`
(every target goes through it), the tar producer is a pure function of
the archive into a file-like :func:`stream_archive`, and ``local:`` is a
first-class dry target that runs the real producer through a real
``tar -x`` into a local directory.  So ``tests/test_deploy.py`` exercises
real extracted bytes end to end without a network, a key, or an ``ssh``
binary.
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import shlex
import signal
import stat
import subprocess
import tarfile
import tempfile
import threading
import time
import zipfile
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterable, Sequence

from .config import (CredentialError, redact_text, redacted_site_label,
                     resolve_password)
from .deadline import Deadline
from .log import get_logger
from .manifest import (ManifestError, VerificationResult, build_manifest,
                       sha256_file, verify_files, write_manifest)
from .ports import PORT_MIN_BINDABLE, coerce_port
from .report import Plan, PlanItem, human_bytes
from .report import write_stdout
from .settings import DeploySettings
from .sources.zip import _MEMBER_READ_ERRORS, ZipSource
from .types import (DeadlineExceeded, Entry, RunControl, SourceError,
                    StopRequested, WptError)

__all__ = [
    "DeployError", "QuotaError", "TargetLayoutError", "TransferError",
    "DeploySettings", "Preflight", "Readback",
    "StreamStats", "TransferFailure", "Target", "SshTarget", "LocalTarget",
    "make_target", "build_plan", "preflight", "deploy_stream", "assert_target",
    "stream_archive", "verify_against_manifest", "classify_transfer_error",
    "readback_script", "parse_readback", "probe_available_bytes", "run",
    "FILE_MODE", "DIR_MODE", "TAR_MTIME", "LOCAL_TARGET_PREFIX",
]

log = get_logger("deploy")

#: The ``--backup-dir`` subtree that holds VERIFIED deploy manifests
#: (``<backup-dir>/deploy/<site>-<stamp>/manifest.json``).  ONE owner for
#: the writer and the report protection scanner: a report must never replace
#: the manifest of a rollback/release record this run wrote.
DEPLOY_MANIFEST_SUBDIR = "deploy"

#: Tar normalization of the STREAMED set — structural, not a tunable.  The
#: archive's own modes and mtimes are host-export noise (a zip carries the
#: exporting user's umask and the export date); a deploy ships a
#: normalized, byte-deterministic tree, so two deploys of one artifact
#: produce the same tar bytes and the same modes on the host.
FILE_MODE = 0o644
DIR_MODE = 0o755
TAR_MTIME = 0                       # 1970-01-01, the reproducible-build epoch

#: Log cadence of the stream: one info line per this many members.
#: Structural (a 28k-file deploy is otherwise a long silence) — cadence is
#: not a behaviour an operator configures, so the no-static-configurables
#: rule stops at the logging boundary, exactly as in wpt.backup's capture
#: heartbeat.
_HEARTBEAT_EVERY = 5000

#: How long a child we started is given after its timeout before we insist
#: on the drain threads finishing.  Structural.
_REAP_GRACE_S = 5.0

#: Wait-loop poll when no stream timeout is configured: frequent enough to
#: notice the run deadline promptly, cheap enough to sleep instead of spin.
_REAP_POLL_S = 0.1

#: The askpass helper's source.  It reads the secret from a 0600 FILE, so
#: the secret appears in no argv and in no environment variable.
_ASKPASS_SOURCE = "#!/bin/sh\ncat \"$WPT_ASKPASS_FILE\"\n"

#: ``--ssh-target`` prefix selecting the local dry target.
LOCAL_TARGET_PREFIX = "local:"


# --------------------------------------------------------------------- errors


class DeployError(WptError):
    """A deploy could not proceed (refusal, bad input, unusable target)."""


class QuotaError(DeployError):
    """The deploy account cannot hold the streamed set.

    Raised by the preflight (nothing moved) AND by the mid-transfer
    classifier: a quota exhaustion is a quota failure even when the host
    reports it as ``Error in the SSH layer`` / ``write remote: Failure``,
    which is exactly what the live session saw.
    """


class TargetLayoutError(DeployError):
    """The post-extract layout check failed: something is missing, or the
    tree shows the residue of a double strip."""


class TransferError(DeployError):
    """A classified transfer failure (auth, network, remote command)."""


# ------------------------------------------------------------------- settings
#
# DeploySettings is NOT declared here: it is a SETTINGS SECTION, so its
# owner is wpt/settings.py and its values live in wpt/data/profiles/default.json
# (see that class's docstring for the knobs, and for the three that are
# structural module constants above).  Every knob is reachable with
# --set deploy.<key>=... or a profile, and the loader validates it through
# the standard SettingsError contract — the same door for a profile file, a
# --set and a bare Settings().
#
# Nothing in this module keeps a second copy of a default or reads a knob
# from anywhere but ``ctx.settings.deploy``.  ``DeploySettings`` is
# re-exported in ``__all__`` because it IS this module's settings type —
# it is imported, never redefined.


# ------------------------------------------------------------------ the data


@dataclass(frozen=True)
class Preflight:
    """What the preflight measured about the deploy account."""

    webroot: str
    required_bytes: int
    available_bytes: int | None
    source: str                 # df | quota | df+quota | write-probe | unknown
    margin_bytes: int
    require_known_space: bool = True

    @property
    def needed_bytes(self) -> int:
        return self.required_bytes + self.margin_bytes

    def refuse_reason(self) -> str | None:
        """One actionable line, or None when the deploy may proceed.

        The refusal NAMES BOTH NUMBERS: the operator's real decision is
        "free 5 GB or raise the quota", and a message without the numbers
        sends them back to the panel to guess.
        """
        if self.available_bytes is None:
            if not self.require_known_space:
                return None
            return (
                f"deploy preflight REFUSED: available space in the deploy "
                f"account is UNKNOWN, and the streamed set needs "
                f"{human_bytes(self.needed_bytes)} "
                f"({human_bytes(self.required_bytes)} of files + "
                f"{human_bytes(self.margin_bytes)} headroom) at "
                f"{self.webroot} — nothing was transferred. Check the "
                f"account quota, or set deploy.preflight_require_known_space=0 "
                f"to deploy unproven"
            )
        if self.available_bytes < self.needed_bytes:
            return (
                f"deploy preflight REFUSED: {human_bytes(self.needed_bytes)} "
                f"needed ({human_bytes(self.required_bytes)} of files + "
                f"{human_bytes(self.margin_bytes)} headroom) but only "
                f"{human_bytes(self.available_bytes)} is available in the "
                f"deploy account at {self.webroot} "
                f"(short by "
                f"{human_bytes(self.needed_bytes - self.available_bytes)}, "
                f"measured via {self.source}) — nothing was transferred. "
                f"Free space or raise the quota, then re-run"
            )
        return None


@dataclass(frozen=True)
class Readback:
    """The result of re-reading the target after the stream."""

    missing_files: tuple[str, ...] = ()
    missing_dirs: tuple[str, ...] = ()
    residue: tuple[str, ...] = ()
    top_level: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not (self.missing_files or self.missing_dirs or self.residue)

    def message(self) -> str:
        """One line naming every problem found on the target."""
        parts: list[str] = []
        if self.missing_files:
            parts.append("missing required file(s): "
                         + ", ".join(self.missing_files))
        if self.missing_dirs:
            parts.append("missing required directory: "
                         + ", ".join(self.missing_dirs))
        if self.residue:
            parts.append(
                "double-strip residue at the webroot root: "
                + ", ".join(self.residue)
                + " — the archive's top-level directory was stripped twice "
                  "(producer AND consumer); the deployed tree is one level off")
        if not parts:
            return "target layout verified"
        return "deploy layout check FAILED — " + "; ".join(parts)


@dataclass
class StreamStats:
    """What one streamed deploy actually moved."""

    files: int = 0
    dirs: int = 0
    bytes_written: int = 0
    entry_count: int = 0
    root: str = ""
    started: float = 0.0
    elapsed_s: float = 0.0
    sha256: dict[str, str] = field(default_factory=dict)
    sizes: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class TransferFailure:
    """The classification of one failed transfer."""

    kind: str                     # quota | auth | network | remote | unknown
    message: str

    def raise_for(self, context: str) -> None:
        """Raise the exception this classification deserves."""
        detail = f"{context}: {self.message}"
        if self.kind == "quota":
            raise QuotaError(
                f"{detail} — the deploy account ran out of space "
                "mid-transfer, so the streamed set was NOT fully extracted. "
                "Free space or raise the quota, then re-run (a re-run is "
                "safe: the deploy is additive)")
        if self.kind == "auth":
            raise TransferError(
                f"{detail} — ssh authentication failed. Pass "
                "--ssh-password-env VAR (or install a key for the deploy "
                "user); the password is never read from a file or argv")
        if self.kind == "network":
            raise TransferError(f"{detail} — the ssh channel failed")
        raise TransferError(f"{detail} — the remote command failed")


# ------------------------------------------------------------------- targets


def _spawn(argv: Sequence[str], *, env: dict[str, str] | None = None,
           stdin: Any = subprocess.PIPE) -> subprocess.Popen:
    """Start a child process — THE subprocess seam.

    Every target goes through this one function, so a test replaces
    ``wpt.deploy._spawn`` and no socket, no key file and no ``ssh``
    binary is needed to exercise the engine.  All three streams are
    pipes: the producer writes the tar into stdin while drain threads
    read stdout and stderr, which is what keeps a multi-GB stream from
    deadlocking on a full pipe buffer.
    """
    return subprocess.Popen(list(argv), stdin=stdin, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env, close_fds=True,
                            start_new_session=True)


def _signal_group(proc: subprocess.Popen) -> None:
    """SIGKILL the child's process GROUP when it owns an isolated one.

    ``_spawn`` starts every target command in its own session, so the
    ``/bin/sh -c`` wrapper's grandchildren (the real ``tar`` reading the
    pipe) are in that group.  Killing only the direct child left them
    holding stdin open, which made a producer blocked in ``write()``
    outlive both the stream timeout and the run deadline (R14-P1-2).

    A test double that replaced ``_spawn`` with a plain child keeps the
    caller's process group; killing that would kill pytest, so the guard
    only signals a group that is neither ours nor another group.
    """
    if not hasattr(os, "killpg"):
        return
    try:
        pgid = os.getpgid(proc.pid)
    except (OSError, ProcessLookupError):
        return
    if pgid == os.getpgrp() or pgid != proc.pid:
        return
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        pass


def _drain(stream: Any, into: list[bytes]) -> None:
    """Read a pipe to EOF into ``into`` (a drain thread's body)."""
    try:
        into.append(stream.read() or b"")
    except (OSError, ValueError):        # closed under us at teardown
        into.append(b"")


def _reap(proc: subprocess.Popen, threads: Sequence[threading.Thread],
          timeout: float, what: str, *,
          deadline: Deadline | None = None,
          timeout_at: float | None = None) -> int:
    """Wait for the child, joining the drain threads; kill on expiry.

    ``timeout <= 0`` means NO stream-time bound (the shipped default), but
    it does NOT mean unbounded when the run carries a ``Deadline``: the wait
    is polled and the child is killed the moment the run budget expires.
    ``timeout_at`` is the ABSOLUTE stream deadline the caller started the
    clock at (one limit shared by the feed watchdog and this reap — spending
    it in the feed must not restart it here).  A producer that stopped
    (SIGTERM/deadline/failure) kills the child in :meth:`Target.extract`
    itself, before this wait begins.

    The child killed here is always one this module started for this
    call — never an external process.
    """
    started = time.monotonic()
    # Both bounds apply for the WHOLE wait: a positive stream timeout and
    # the run deadline are independent, and the FIRST expiry owns the
    # verdict (timeout -> TransferError, deadline -> DeadlineExceeded).
    # The old ``elif`` let a far deadline shadow a short stream timeout.
    timeout_at = (timeout_at if timeout_at is not None
                  else started + timeout if timeout > 0 else None)
    deadline_at = deadline.at if deadline is not None else None
    limit_at = min(
        (value for value in (timeout_at, deadline_at) if value is not None),
        default=None,
    )
    while True:
        if limit_at is not None:
            remaining = limit_at - time.monotonic()
            if remaining <= 0:
                _kill(proc, threads)
                deadline_first = (
                    deadline_at is not None
                    and (timeout_at is None or deadline_at <= timeout_at)
                )
                if deadline_first:
                    raise DeadlineExceeded(
                        f"run deadline exceeded at {what!r} — the deploy "
                        "child was killed")
                raise TransferError(
                    f"{what} did not finish within {timeout:g}s and was "
                    "killed — the deploy channel is stalled")
            poll = min(_REAP_POLL_S, remaining)
        else:
            poll = _REAP_POLL_S
        try:
            rc = proc.wait(timeout=poll)
        except subprocess.TimeoutExpired:
            continue
        for thread in threads:
            thread.join(timeout=_REAP_GRACE_S)
        return rc


def _kill(proc: subprocess.Popen,
          threads: Sequence[threading.Thread]) -> None:
    """Kill the child's whole group and reap its drain threads."""
    _signal_group(proc)
    try:
        proc.kill()
    except (OSError, ProcessLookupError):
        pass
    try:
        proc.wait(timeout=_REAP_GRACE_S)
    except subprocess.TimeoutExpired:
        pass
    for thread in threads:
        if thread.ident is None:
            # A drain/watchdog thread that was never started (a stop raised
            # between the first start and this one) cannot be joined;
            # ``Thread.join`` would raise RuntimeError and mask the primary
            # failure.
            continue
        thread.join(timeout=_REAP_GRACE_S)


def _text(chunks: Sequence[bytes]) -> str:
    return b"".join(chunks).decode("utf-8", errors="replace")


class Target:
    """Where a deploy lands: the ONE place bytes are written.

    Implementations differ only in how a command is spelled; streaming,
    classification and assertion are shared, so the ``local:`` dry target
    exercises the exact code path a real deploy does.
    """

    def __init__(self, webroot: str) -> None:
        self.webroot = webroot

    @property
    def label(self) -> str:                     # pragma: no cover — abstract
        raise NotImplementedError

    def _argv(self, command: str) -> list[str]:  # pragma: no cover — abstract
        raise NotImplementedError

    def _env(self) -> dict[str, str] | None:
        return None

    def _start(self, command: str, stdin: Any, what: str) -> subprocess.Popen:
        try:
            return _spawn(self._argv(command), env=self._env(), stdin=stdin)
        except FileNotFoundError as exc:
            raise DeployError(
                f"cannot start the deploy target command ({exc.filename}) — "
                "install it, or pass a different --ssh-target"
            ) from exc

    # -- one-shot command ------------------------------------------------

    def run_command(self, command: str, *, timeout: float,
                    deadline: Deadline | None = None) -> tuple[int, str, str]:
        """Run one command; return ``(rc, stdout, stderr)``.

        ``deadline`` is the run's ONE memoized budget: it refuses BEFORE
        spawning when already spent and is forwarded to the reap loop, so a
        target that ignores its own command timeout cannot outlive the run.
        """
        if deadline is not None:
            deadline.check("deploy remote command")
        proc: subprocess.Popen | None = None
        out: list[bytes] = []
        err: list[bytes] = []
        threads: list[threading.Thread] = []
        try:
            proc = self._start(command, subprocess.DEVNULL, "remote command")
            threads = [
                threading.Thread(target=_drain, args=(proc.stdout, out),
                                 daemon=True),
                threading.Thread(target=_drain, args=(proc.stderr, err),
                                 daemon=True),
            ]
            # The guard covers ARMING too: a SIGTERM/deadline raised from a
            # thread start used to unwind with the child group alive.
            for thread in threads:
                thread.start()
            rc = _reap(proc, threads, timeout, "remote command",
                       deadline=deadline)
        except BaseException:
            # A SIGTERM/deadline (RunControl is a BaseException) during the
            # reap must not leave the one-shot child's GROUP running: this
            # is the shared kill owner the stream path already uses.
            if proc is not None:
                _kill(proc, threads)
            raise
        return rc, _text(out), _text(err)

    # -- the stream ------------------------------------------------------

    def extract(self, feed: Callable[[BinaryIO], None], *,
                timeout: float,
                deadline: Deadline | None = None) -> tuple[int, str]:
        """Pipe the tar produced by ``feed`` into ``tar -x`` at the webroot.

        ``tar -xf - -C <webroot>`` is the WHOLE consumer: it does not
        strip, and it does not delete.  A broken pipe means the remote tar
        died mid-stream; that is not raised here — the stderr says WHY,
        and :func:`classify_transfer_error` turns it into a quota / auth /
        network verdict.

        The child is ALWAYS reaped, including when the producer itself
        fails (a refused archive member): leaving a live ``tar`` behind
        would orphan a process holding the webroot open, which is
        exactly the kind of residue a self-bounding run may not leave.
        """
        command = (f"mkdir -p {shlex.quote(self.webroot)} && "
                   f"tar -xf - -C {shlex.quote(self.webroot)}")
        # ONE absolute stream limit for the whole transfer: the feed
        # watchdog and the reap share it, so time spent feeding cannot be
        # spent AGAIN by a fresh reap clock (R15-P2).
        stream_started = time.monotonic()
        stream_timeout_at = (stream_started + timeout if timeout > 0
                             else None)
        proc: subprocess.Popen | None = None
        out: list[bytes] = []
        err: list[bytes] = []
        threads: list[threading.Thread] = []
        watcher: threading.Thread | None = None
        #: The watchdog's stop flag exists BEFORE the spawn so the outer
        #: BaseException guard below always has one.
        feed_stop = threading.Event()
        try:
            proc = self._start(command, subprocess.PIPE, "deploy stream")
            threads = [
                threading.Thread(target=_drain, args=(proc.stdout, out),
                                 daemon=True),
                threading.Thread(target=_drain, args=(proc.stderr, err),
                                 daemon=True),
            ]
            # The guard covers ARMING: a stop raised from a thread start
            # used to unwind with the child group alive.
            for thread in threads:
                thread.start()
            log.info("deploy stream: writing into %s", self.webroot)
            producer_error: BaseException | None = None
            # The producer writes THROUGH a pipe: when the remote tar stops
            # draining, a blocking write (8 MiB is far past the pipe buffer)
            # never returns, so the deadline/timeout checks between archive
            # members are unreachable.  ONE watchdog owns the bound while
            # feed runs: at the first expiry it closes stdin (unblocking the
            # write) and kills the child this call started.  The verdict is
            # raised below, AFTER the child is reaped.
            feed_expiry: list[BaseException] = []

            def _watch_feed() -> None:
                limits: list[tuple[float, BaseException]] = []
                if deadline is not None:
                    limits.append((deadline.at, DeadlineExceeded(
                        "run deadline exceeded at 'deploy stream' — the deploy "
                        "child was killed while the producer was writing")))
                if stream_timeout_at is not None:
                    limits.append((stream_timeout_at, TransferError(
                        f"deploy stream did not finish within {timeout:g}s and "
                        "was killed — the deploy channel is stalled")))
                if not limits:
                    return
                expiry_at, error = min(limits, key=lambda item: item[0])
                if feed_stop.wait(max(0.0, expiry_at - time.monotonic())):
                    return
                if feed_stop.is_set():
                    return
                feed_expiry.append(error)
                # Kill the whole GROUP first: the direct child is the
                # /bin/sh wrapper, and its tar grandchild is what still holds
                # the read end of the pipe.  Only after the group is dead does
                # closing stdin stop waiting on the producer's writer lock.
                _signal_group(proc)
                try:
                    proc.kill()
                except (OSError, ProcessLookupError):
                    pass
                try:
                    proc.wait(timeout=_REAP_GRACE_S)
                except subprocess.TimeoutExpired:
                    pass
                try:
                    proc.stdin.close()
                except (OSError, ValueError):
                    pass

            watcher = threading.Thread(target=_watch_feed,
                                       name="wpt-deploy-feed", daemon=True)
            watcher.start()
            try:
                feed(proc.stdin)
            except BrokenPipeError:
                # The remote tar exited (most often: the account quota).  The
                # diagnosis is in its stderr, which the drain thread is
                # already collecting.
                log.warning(
                    "deploy stream: remote tar closed the pipe mid-stream")
            except BaseException as exc:      # noqa: BLE001 — re-raised below
                producer_error = exc
            if feed_expiry or producer_error is not None:
                # Stop the watchdog, then kill/reap the whole group FIRST.
                # Closing stdin before the readers are dead can block on the
                # producer's writer lock and never reach the reap (R14-P1-2);
                # after the group is gone the blocked write sees EPIPE and the
                # close cannot wait forever.
                feed_stop.set()
                watcher.join(timeout=_REAP_GRACE_S)
                _kill(proc, threads)
                try:
                    proc.stdin.close()
                except (OSError, ValueError):
                    pass
                if feed_expiry:
                    # The bound expired while the producer was blocked.  Raise
                    # the bound's own verdict, never the misleading broken-pipe
                    # diagnosis the group death produces.
                    raise feed_expiry[0]
                # The producer stopped (SIGTERM/deadline/refused member): its
                # verdict is the command's, and the child must not keep the
                # channel open.  Raise the ORIGINAL control/failure (never mask
                # it with a transfer diagnosis).
                raise producer_error
            # The producer finished normally: close stdin to signal EOF.  The
            # watchdog stays armed during the close, so a remote consumer that
            # stopped draining is killed at the same stream/deadline bound
            # instead of blocking here forever.  A cooperative stop (SIGTERM)
            # can arrive INSIDE this close; it must reap the child group before
            # propagating, exactly like the producer-error branches above.
            try:
                proc.stdin.close()
            except (OSError, ValueError):
                pass
            except BaseException:
                feed_stop.set()
                watcher.join(timeout=_REAP_GRACE_S)
                _kill(proc, threads)
                raise
            finally:
                feed_stop.set()
                watcher.join(timeout=_REAP_GRACE_S)
            if feed_expiry:
                _kill(proc, threads)
                raise feed_expiry[0]
            # The final wait is inside the SAME guard: a SIGTERM while the
            # last reap waits used to leave the child group alive after the
            # run reported a cooperative stop (there is no window between
            # the stdin close and this call that the guard does not cover).
            rc = _reap(proc, threads, timeout, "deploy stream",
                       deadline=deadline, timeout_at=stream_timeout_at)
            return rc, _text(err)
        except BaseException:
            # EVERY exit after the spawn is covered, including a stop raised
            # from thread arming, from the post-close gap, or inside the
            # final reap.  Kill the group this call started and reap the
            # drain/watchdog threads before preserving the verdict.
            feed_stop.set()
            if watcher is not None and watcher.ident is not None:
                watcher.join(timeout=_REAP_GRACE_S)
            if proc is not None:
                _kill(proc, threads)
                try:
                    proc.stdin.close()
                except (OSError, ValueError):
                    pass
            raise


class LocalTarget(Target):
    """Dry target: extract into a local directory through the real ``tar``.

    Selected by ``--ssh-target local:<dir>``.  This is the rehearsal
    target — a deploy rehearsed here produces exactly the bytes a real
    deploy would, with no host, no credentials and no quota.
    """

    def __init__(self, webroot: str) -> None:
        super().__init__(webroot)
        self._root = Path(webroot)

    @property
    def label(self) -> str:
        return f"local:{self.webroot}"

    def _argv(self, command: str) -> list[str]:
        return ["/bin/sh", "-c", command]


class SshTarget(Target):
    """The real target: ``ssh <target> <command>`` with stdin as the pipe.

    Auth is resolved ONCE, in :meth:`__init__`:

    * ``--ssh-password-env VAR`` (or an interactive prompt) — the secret
      is written to a 0600 file inside a 0700 temporary directory and
      read back by an ``SSH_ASKPASS`` helper.  It never enters the
      child's argv, never enters the child's environment, and both files
      are removed by :meth:`close`.  ``BatchMode`` stays off so askpass
      is consulted.
    * no password — key/agent auth with ``BatchMode=yes`` so the process
      can never block on a prompt, plus ``ServerAliveInterval`` /
      ``ServerAliveCountMax`` so a dead peer ends the run in minutes.
    * neither available — :class:`~wpt.config.CredentialError`, a clean
      refusal: never a hang, never a guess.
    """

    def __init__(self, host: str, webroot: str, settings: DeploySettings,
                 password_env: str | None = None) -> None:
        super().__init__(webroot)
        if not host or any(c.isspace() for c in host):
            raise DeployError(f"invalid ssh target: {host!r}")
        self.host = host
        self.settings = settings
        self._tmpdir: tempfile.TemporaryDirectory | None = None
        self._env_extra: dict[str, str] = {}
        self._batch_mode = True
        self.auth = self._resolve_auth(password_env)

    # -- auth ------------------------------------------------------------

    def _key_auth_available(self) -> bool:
        if os.environ.get("SSH_AUTH_SOCK"):
            return True
        ssh_dir = Path(os.path.expanduser("~")) / ".ssh"
        if not ssh_dir.is_dir():
            return False
        return any(ssh_dir.glob("id_*")) or (ssh_dir / "identity").exists()

    def _resolve_auth(self, password_env: str | None) -> str:
        """Askpass when a password is resolvable, key auth otherwise."""
        if password_env:
            secret = resolve_password(password_env, what="ssh password")
            if not secret:
                raise CredentialError("ssh password was empty")
            self._install_askpass(secret)
            return "password"
        if self._key_auth_available():
            return "key"
        # No key: a prompt is the documented secret channel, and
        # resolve_password refuses cleanly when it cannot ask.
        secret = resolve_password(None, what="ssh password")
        if not secret:
            raise CredentialError("ssh password was empty")
        self._install_askpass(secret)
        return "password"

    def _install_askpass(self, secret: str) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="wpt-deploy-")
        base = Path(self._tmpdir.name)
        os.chmod(base, 0o700)
        secret_path = base / "secret"
        handle = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(handle, secret.encode("utf-8"))
        finally:
            os.close(handle)
        script = base / "askpass.sh"
        script.write_text(_ASKPASS_SOURCE, encoding="utf-8")
        script.chmod(0o700)
        # The environment carries only PATHS; the secret lives in the
        # 0600 file, so it is in no argv and in no environ.
        self._env_extra = {
            "SSH_ASKPASS": str(script),
            "SSH_ASKPASS_REQUIRE": "force",
            "DISPLAY": os.environ.get("DISPLAY", ":0"),
            "WPT_ASKPASS_FILE": str(secret_path),
        }
        self._batch_mode = False
        log.info("ssh password resolved from the environment; it is passed "
                 "through an askpass helper and appears in no argv and no "
                 "log line")

    def close(self) -> None:
        """Remove the askpass helper and the 0600 secret file."""
        if self._tmpdir is not None:
            self._tmpdir.cleanup()
            self._tmpdir = None
        self._env_extra = {}

    # -- plumbing --------------------------------------------------------

    @property
    def label(self) -> str:
        return f"{self.host}:{self.webroot}"

    def _env(self) -> dict[str, str] | None:
        if not self._env_extra:
            return None
        env = dict(os.environ)
        env.update(self._env_extra)
        return env

    def _argv(self, command: str) -> list[str]:
        s = self.settings
        argv = ["ssh", "-p", str(s.ssh_port),
                "-o", f"ConnectTimeout={s.connect_timeout_s}",
                "-o", f"ServerAliveInterval={s.server_alive_interval_s}",
                "-o", f"ServerAliveCountMax={s.server_alive_count_max}",
                "-o", f"StrictHostKeyChecking={s.strict_host_key_checking}"]
        if self._batch_mode:
            # Never block on a password prompt: with key/agent auth there
            # is nothing to ask for, and a prompt would hang the run.
            argv += ["-o", "BatchMode=yes"]
        argv += [self.host, command]
        return argv


def _is_within(base: Path, candidate: str) -> bool:
    """True when ``candidate`` lies inside ``base`` (or IS it) after
    resolution — the prefix test both OSes agree on (path-component
    aware, symlink-resolved, and a sibling with a shared string prefix
    like ``/srv/site`` vs ``/srv/site-old`` is NOT inside)."""
    try:
        Path(candidate).resolve().relative_to(base)
        return True
    except ValueError:
        return False


def _webroot_problem(webroot: str) -> str | None:
    """Why ``webroot`` cannot name a target directory, or None.

    Empty/``~`` were the only refusals, so ``/../escaped`` was joined to a
    local rehearsal base and wrote OUTSIDE it (and the same raw string
    reached remote ``mkdir -p``/``tar -C``).  A ``..`` component is never a
    meaningful webroot: reject it before any join or shell command.  The
    returned spelling is normalized (POSIX) so ``/www//site/`` and
    ``/www/site`` are one target.
    """
    if not webroot or not webroot.strip("/"):
        return "deploy requires a non-empty target webroot"
    if webroot.startswith("~"):
        return ("the target webroot must be an absolute path on the host; "
                "'~' is expanded by the login shell, not by wpt")
    if ".." in webroot.replace("\\", "/").split("/"):
        return (f"the target webroot {webroot!r} contains '..'; a deploy "
                "must name a directory, never a path that escapes it")
    return None


def make_target(ssh_target: str, webroot: str, settings: DeploySettings,
                ssh_password_env: str | None = None) -> Target:
    """Build the target named by ``--ssh-target``.

    ``local:<dir>`` is the dry target (a real ``tar -x`` into a local
    directory); anything else is an ssh destination.  The webroot is
    validated ONCE, here: an empty path, one starting with ``~`` (the
    login shell would expand it, not wpt), or one carrying ``..`` is a
    refusal — not a surprise on the far side.  A local webroot must resolve
    INSIDE the rehearsal base after the documented join; an ssh webroot
    must be an absolute, normalized POSIX path (the remote shell's cwd is
    never part of the contract).
    """
    problem = _webroot_problem(webroot)
    if problem is not None:
        raise DeployError(problem)
    if ssh_target.startswith(LOCAL_TARGET_PREFIX):
        directory = ssh_target[len(LOCAL_TARGET_PREFIX):] or "."
        base = Path(directory).resolve()
        if Path(webroot).is_absolute() and _is_within(base, webroot):
            # The operator passed the same webroot the real ssh target uses,
            # already under the local base: that path IS the rehearsal root
            # (a live rehearsal joined it and landed the whole tree at
            # deploy-rehearsal/home/... ). Otherwise the webroot is a HOST
            # path ("/www") that the base stands in for, and the join is
            # the documented mapping.
            return LocalTarget(str(Path(webroot)))
        joined = Path(directory) / webroot.lstrip("/")
        if not _is_within(base, str(joined)):
            raise DeployError(
                f"the local target webroot {webroot!r} resolves OUTSIDE the "
                f"rehearsal base {base}; refusing to write outside the "
                "target the operator named")
        return LocalTarget(str(joined))
    if not ssh_target.strip():
        raise DeployError("deploy requires --ssh-target (user@host, or "
                          "local:<dir> to rehearse locally)")
    if not webroot.startswith("/"):
        raise DeployError(
            f"the ssh target webroot {webroot!r} must be an absolute POSIX "
            "path (the remote shell's working directory is not a target)")
    normalized = "/" + posixpath.normpath(webroot).lstrip("/")
    return SshTarget(ssh_target.strip(), normalized,
                     settings, ssh_password_env)


# --------------------------------------------------------------- error class


def classify_transfer_error(stderr: str, rc: int,
                            settings: DeploySettings) -> TransferFailure:
    """Classify one failed transfer.

    Order matters, and it is the live lesson: a QUOTA signature wins even
    when the message also smells like a broken channel.  The exhausted
    DirectAdmin account reported ``Error in the SSH layer`` + ``write
    remote: Failure`` with truncated chunks; reported as a "network error"
    that sends the operator to reboot a router while the account is
    400 bytes from full.
    """
    text = (stderr or "").strip()
    if not text:
        return TransferFailure("unknown",
                               f"remote command exited {rc} with no message")
    low = text.lower()
    if any(sig.lower() in low for sig in settings.quota_signatures):
        return TransferFailure("quota", text)
    if any(sig.lower() in low for sig in settings.auth_signatures):
        return TransferFailure("auth", text)
    if any(sig.lower() in low for sig in settings.network_signatures):
        return TransferFailure("network", text)
    return TransferFailure("remote", text)


# --------------------------------------------------------------- the readback


def readback_script(settings: DeploySettings) -> str:
    """The ONE shell script that re-reads the target after a stream.

    A single round trip answers all the questions: which required files
    are there, which required directories are there, which double-strip
    residue is there, and what the webroot root actually contains.

    Tags: ``F`` file present, ``D`` directory present, ``X`` required
    FILE missing, ``Y`` required DIRECTORY missing, ``R`` residue found,
    ``L`` = the root listing follows (untagged lines, so a real filename
    can never be confused with a tag).
    """
    def quoted(paths: Iterable[str]) -> str:
        return " ".join(shlex.quote(p) for p in paths)

    def probe(kind: str, test: str, tag: str, paths: Iterable[str]) -> list[str]:
        """One probe loop, or a no-op when the list is empty.

        ``for p in ; do`` is a shell SYNTAX ERROR, so an empty assertion
        list must emit something legal rather than a broken script that
        would make every readback fail for a reason nobody configured.
        """
        names = list(paths)
        if not names:
            return [":"]
        return [
            "for p in " + quoted(names) + "; do",
            f'  if {test}; then printf "{tag} %s\\n" "$p";'
            f' else printf "{kind} %s\\n" "$p"; fi',
            "done",
        ]

    lines = ['cd -- "$WPT_DEPLOY_WEBROOT" 2>/dev/null || exit 3']
    lines += probe("X", '[ -f "$p" ]', "F", settings.required_files)
    lines += probe("Y", '[ -d "$p" ]', "D", settings.required_dirs)
    if settings.residue_paths:
        lines += [
            "for p in " + quoted(settings.residue_paths) + "; do",
            '  if [ -e "$p" ] || [ -L "$p" ]; then printf "R %s\\n" "$p"; fi',
            "done",
        ]
    else:
        lines.append(":")
    lines += ["printf 'L\\n'", "ls -A1 2>/dev/null", ""]
    return "\n".join(lines)


def parse_readback(text: str) -> Readback:
    """Parse :func:`readback_script` output into a :class:`Readback`.

    Lines before the ``L`` marker are tagged; every line AFTER it is a
    webroot-root entry.  ``F``/``D`` are present-and-correct and record
    nothing; ``X``/``Y``/``R`` are the three refusal shapes.
    """
    missing_files: list[str] = []
    missing_dirs: list[str] = []
    residue: list[str] = []
    top_level: list[str] = []
    listing = False
    for line in text.splitlines():
        if listing:
            if line.strip():
                top_level.append(line.rstrip("/"))
            continue
        if line.strip() == "L":
            listing = True
            continue
        if len(line) < 2 or line[1] != " ":
            continue
        tag, name = line[0], line[2:].strip()
        if tag == "X":
            missing_files.append(name)
        elif tag == "Y":
            missing_dirs.append(name)
        elif tag == "R":
            residue.append(name)
    return Readback(tuple(missing_files), tuple(missing_dirs), tuple(residue),
                    tuple(top_level))


def assert_target(target: Target, settings: DeploySettings,
                  deadline: Deadline | None = None) -> Readback:
    """REQUIRE the post-extract layout on the target; raise on any absence.

    This is the deploy's own "verify after every change" obligation:
    success is only ever reported for a target that demonstrably holds a
    WordPress webroot AT ITS ROOT, with no residue of a strip that ran
    twice.  A cheap single-command readback is the honest way to do that
    — the individual files are re-read by
    :func:`verify_against_manifest`, not by a recursive listing.

    ``deadline`` is the run's memoized budget; the readback is refused
    BEFORE it starts when the budget is already spent and is reaped at the
    deadline while it runs.
    """
    if deadline is not None:
        deadline.check("deploy layout assertion")
    command = (f"WPT_DEPLOY_WEBROOT={shlex.quote(target.webroot)} "
               f"sh -c {shlex.quote(readback_script(settings))}")
    rc, out, err = target.run_command(
        command, timeout=settings.probe_timeout_s, deadline=deadline)
    if rc == 3:
        raise TargetLayoutError(
            f"deploy layout check FAILED — the target webroot "
            f"{target.webroot} does not exist or is not readable, so the "
            f"stream extracted nothing there (remote said: "
            f"{err.strip() or 'no message'})")
    if rc != 0 and not out.strip():
        classify_transfer_error(err, rc, settings).raise_for(
            f"deploy layout check on {target.label}")
    readback = parse_readback(out)
    if not readback.ok:
        raise TargetLayoutError(readback.message())
    return readback


# ----------------------------------------------------------------- preflight


def _parse_df(text: str) -> int | None:
    """Available bytes from ``df -Pk`` output (POSIX 1024-block form)."""
    best: int | None = None
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or not parts[-1].startswith("/"):
            continue
        try:
            available = int(parts[3])
        except ValueError:
            continue
        if available < 0:
            continue
        value = available * 1024
        best = value if best is None else min(best, value)
    return best


def _parse_quota(text: str) -> int | None:
    """Available bytes from ``quota``/``quota -s`` output.

    Deliberately conservative, and deliberately STRICT about the row
    shape: a data row starts with a mount point and is followed by at
    least three bare numbers (``used quota limit``, plus a grace column
    when the account is over).  Requiring that shape is what keeps a
    ``df`` line — whose fourth column is a percentage — from being read
    as a quota row, because a misread here silently INVENTS an
    allowance.  The SMALLEST remaining allowance across the rows wins: a
    multi-mount account is bounded by its tightest filesystem, not by
    its largest.
    """
    best: int | None = None
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or not parts[0].startswith("/"):
            continue
        numbers = parts[1:]
        leading = 0
        while leading < len(numbers) and numbers[leading].isdigit():
            leading += 1
        # used / quota / limit, and a grace column that is a bare number
        # when the account is over it.  A df line is rejected HERE: its
        # fourth column is a percentage ("99%"), never a number.
        if leading < 3 or (leading < len(numbers)
                           and not numbers[leading].isdigit()):
            continue
        used, soft, hard = (int(numbers[0]), int(numbers[1]), int(numbers[2]))
        limit = hard or soft
        if limit <= 0:
            continue
        remaining = max(limit - used, 0) * 1024
        best = remaining if best is None else min(best, remaining)
    return best


def probe_available_bytes(target: Target,
                          settings: DeploySettings,
                          deadline: Deadline | None = None
                          ) -> tuple[int | None, str]:
    """Measure the deploy account's available space; ``(bytes, how)``.

    ``df -Pk`` and ``quota`` are asked first (a cheap read).  When NEITHER
    parses — an account quota hidden behind a large shared filesystem,
    the DirectAdmin case — a write-and-remove probe of
    ``deploy.preflight_write_probe_bytes`` proves the account still takes
    a write, which is the fact that decides the deploy.  A probe that
    fails with a quota signature reports ZERO available, because that is
    exactly what it proved.

    ``deadline`` bounds every measurement (and refuses before the next one
    when the budget is spent), so a slow host cannot consume the whole
    deploy budget in preflight and still let the stream start.
    """
    def _check() -> None:
        if deadline is not None:
            deadline.check("deploy preflight")

    _check()
    df_bytes: int | None = None
    # Ask about the WEBROOT's filesystem, not the login directory's: a
    # DirectAdmin account can have its home and its webroot on different
    # mounts, and only the webroot's is the one the deploy fills.
    df = f"df -Pk -- {shlex.quote(target.webroot)} 2>&1 || df -Pk . 2>&1"
    try:
        rc, out, _err = target.run_command(
            df, timeout=settings.probe_timeout_s, deadline=deadline)
        if rc == 0:
            df_bytes = _parse_df(out)
    except (DeployError, TransferError) as exc:
        log.debug("df probe failed: %s", exc)

    _check()
    quota_bytes: int | None = None
    try:
        rc, out, _err = target.run_command(
            "quota -s 2>/dev/null || quota 2>/dev/null || true",
            timeout=settings.probe_timeout_s, deadline=deadline)
        if rc == 0:
            quota_bytes = _parse_quota(out)
    except (DeployError, TransferError) as exc:
        log.debug("quota probe failed: %s", exc)

    if df_bytes is not None and quota_bytes is not None:
        return min(df_bytes, quota_bytes), "df+quota"
    if df_bytes is not None:
        return df_bytes, "df"
    if quota_bytes is not None:
        return quota_bytes, "quota"
    _check()
    return _write_probe(target, settings, deadline=deadline)


def _write_probe(target: Target,
                 settings: DeploySettings,
                 deadline: Deadline | None = None) -> tuple[int | None, str]:
    """Write-and-remove probe: the fallback when parsing is ambiguous."""
    if deadline is not None:
        deadline.check("deploy preflight write probe")
    count_mb = max(settings.preflight_write_probe_bytes // (1024 * 1024), 1)
    probe_name = f".wpt-deploy-probe-{os.getpid()}"
    name = shlex.quote(probe_name)
    # The trap removes the probe on EVERY shell exit (EXIT/HUP/INT/TERM).
    # The sequential ``rm`` alone was unreachable when _reap SIGKILLed the
    # child group at the deadline, leaving a partial probe in the quota-
    # bound webroot the next run (new pid) could never clean.
    trap = shlex.quote(f"rm -f {probe_name}")
    command = (f"cd -- {shlex.quote(target.webroot)} 2>/dev/null || exit 3; "
               f"trap {trap} EXIT HUP INT TERM; "
               f"dd if=/dev/zero of={name} bs=1048576 count={count_mb} "
               f"2>/dev/null; rc=$?; rm -f {name}; exit $rc")
    cleanup_command = (f"cd -- {shlex.quote(target.webroot)} 2>/dev/null "
                       f"|| exit 3; rm -f {name}")
    pending: BaseException | None = None
    cleanup_failed = False
    rc = out = err = None
    try:
        rc, out, err = target.run_command(
            command, timeout=settings.probe_timeout_s, deadline=deadline)
    except BaseException as exc:  # noqa: BLE001 — cleanup is owed anyway
        pending = exc
    finally:
        # A FRESH finite budget (the source_cleanup_budget rule): the
        # probe usually died BECAUSE the run budget expired, and the
        # removal must not inherit it.  The same configured probe timeout
        # bounds both the forward and the cleanup command.
        cleanup = Deadline(float(settings.probe_timeout_s))
        try:
            clean_rc, _clean_out, clean_err = target.run_command(
                cleanup_command, timeout=settings.probe_timeout_s,
                deadline=cleanup)
        except BaseException as exc:  # noqa: BLE001 — name the residue
            cleanup_failed = True
            clean_rc, clean_err = None, str(exc)
        if clean_rc not in (0, None):
            cleanup_failed = True
        if cleanup_failed:
            log.warning(
                "deploy preflight: the write probe %s could not be proven "
                "removed (%s) — it may remain at %s; deploying into a "
                "webroot with this residue is refused",
                probe_name, clean_err or f"rm exited {clean_rc}",
                target.label)
    if pending is not None:
        log.debug("write probe failed: %s", pending)
        raise pending
    if cleanup_failed:
        return 0, "write-probe"
    if rc == 0:
        log.info("deploy preflight: df/quota were unparseable; the "
                 "write-and-remove probe succeeded, so the account takes "
                 "writes")
        return None, "write-probe"
    failure = classify_transfer_error(err or out, rc, settings)
    if failure.kind == "quota":
        log.warning("deploy preflight: the write probe hit the account "
                    "quota: %s", failure.message)
        return 0, "write-probe"
    return None, "unknown"


def preflight(target: Target, required_bytes: int,
              settings: DeploySettings,
              deadline: Deadline | None = None) -> Preflight:
    """Measure the target; the caller refuses on :meth:`Preflight.refuse_reason`.

    Nothing is written to the target except the write-and-remove probe
    of :func:`_write_probe`, which removes its own file.
    """
    available, how = probe_available_bytes(target, settings, deadline)
    result = Preflight(webroot=target.webroot, required_bytes=required_bytes,
                       available_bytes=available, source=how,
                       margin_bytes=settings.preflight_margin_bytes,
                       require_known_space=settings.preflight_require_known_space)
    log.info("deploy preflight: needs %s, %s available at %s (via %s)",
             human_bytes(result.needed_bytes),
             human_bytes(available) if available is not None else "unknown",
             target.webroot, how)
    return result


# ------------------------------------------------------------------ the plan


def _safe_member(path: str) -> bool:
    """True for a webroot-relative path that cannot escape its root."""
    if not path or "\x00" in path or "\\" in path:
        return False
    norm = posixpath.normpath(path)
    return not norm.startswith(("/", "..")) and norm not in ("", ".", "..")


def _parent_dirs(paths: Iterable[str]) -> list[str]:
    """Every directory implied by a set of file paths, parents first.

    The tar carries the directories explicitly: that pins a deployed tree
    to ``DIR_MODE`` regardless of the host's umask, and it is the list
    the double-strip residue check reasons about.
    """
    seen: set[str] = set()
    for path in paths:
        parent = path.rpartition("/")[0]
        while parent:
            seen.add(parent)
            parent = parent.rpartition("/")[0]
    return sorted(seen, key=lambda p: (p.count("/"), p))


def _archive_root(zip_path: Path, *,
                  deadline: Deadline | None = None) -> str:
    """The archive's single top-level host directory, or "".

    Delegated to :class:`~wpt.sources.zip.ZipSource` (constructed for its
    ``root`` and closed immediately): the "a host export nests everything
    under one site dir" rule and the strip it implies have exactly ONE
    owner in the toolkit.  The deploy strips ONCE, here in the producer.
    """
    try:
        source = ZipSource(Path(zip_path), deadline=deadline)
    except SourceError as exc:
        # ZipSource owns the "not a representable tree" refusal (a file or
        # symlink member that is also an ancestor); deploy's public error
        # contract is DeployError and every caller catches that.
        raise DeployError(f"{zip_path}: {exc}") from exc
    except _MEMBER_READ_ERRORS as exc:
        # A non-zip/swapped/truncated archive reaches ZipFile()/the central
        # directory here; the member-read owner names the same error class
        # as the stream path.
        raise DeployError(f"archive {zip_path} cannot be read: {exc}") from exc
    try:
        return source.root
    finally:
        source.close()


def zip_facts(zip_path: Path, *,
              deadline: Deadline | None = None) -> dict[str, Any]:
    """Count the streamed set WITHOUT reading any file body.

    One pass over the zip's central directory: entry count, uncompressed
    bytes, file count, directory count (explicit archive entries AND the
    parents every file implies) and the stripped root.  This is what the
    dry run and the preflight are computed from — a dry run costs one
    directory read and zero subprocesses.

    An escaping member, a member that is both a file and a directory, and
    a SYMLINK are all refused HERE — before the preflight, before the
    dry-run plan is even useful, and therefore before a single byte could
    reach a target.  The archive is untrusted input, and a webroot deploy
    that re-materialized a symlink pointing outside the webroot would
    write outside the target the operator named.
    """
    zip_path = Path(zip_path)
    root = _archive_root(zip_path, deadline=deadline)
    try:
        with zipfile.ZipFile(zip_path) as zf:
            members = _member_index(zf, root)
    except _MEMBER_READ_ERRORS as exc:
        # The archive can be corrupted or swapped between facts and stream;
        # every member-read failure class has ONE owner and deploy maps it to
        # its own error contract (DeployError), never a raw BadZipFile.
        raise DeployError(
            f"archive {zip_path} cannot be read: {exc}") from exc
    files: list[Entry] = []
    explicit_dirs: list[str] = []
    for rel, info in sorted(members.items()):
        if deadline is not None:
            deadline.check("deploy archive facts")
        if not _safe_member(rel):
            raise DeployError(
                f"archive member {rel!r} is not a webroot-relative path — "
                "refusing to deploy an archive that could write outside the "
                "target webroot")
        if _is_symlink(info):
            raise DeployError(
                f"refusing to deploy symlink member {rel!r} — a webroot "
                "deploy ships regular files and directories only; replace the "
                "link with its target first")
        if info.is_dir():
            explicit_dirs.append(rel)
        else:
            files.append(Entry(path=rel, is_dir=False, size=info.file_size))
    if not files:
        raise DeployError(f"{zip_path} holds no files — nothing to deploy")
    return {
        "root": root,
        "files": len(files),
        "entry_count": len(files) + len(explicit_dirs),
        "dirs": sorted(set(_parent_dirs([e.path for e in files]))
                       | set(explicit_dirs),
                       key=lambda p: (p.count("/"), p)),
        "bytes": sum(e.size for e in files),
        "entries": files,
    }


def _top_level_label(ssh_target: str, webroot: str) -> str:
    if ssh_target.startswith(LOCAL_TARGET_PREFIX):
        return f"{LOCAL_TARGET_PREFIX}{webroot}"
    return f"{ssh_target}:{webroot}"


def build_plan(zip_path: Path, ssh_target: str, webroot: str,
               settings: DeploySettings,
               *, deadline: Deadline | None = None) -> Plan:
    """The dry-run plan: files, bytes, duration estimate, target.

    PURE — it opens the zip's directory and counts, and spawns nothing.
    The returned :class:`wpt.report.Plan` is the toolkit's universal plan
    shape, one item per top-level entry of the streamed set, so the
    operator reads a table of a dozen rows instead of thousands.
    """
    facts = zip_facts(Path(zip_path), deadline=deadline)
    duration = (facts["bytes"] / settings.stream_bytes_per_s
                + settings.stream_overhead_s)
    label = _top_level_label(ssh_target, webroot)
    tops: dict[str, dict[str, int]] = {}
    for entry in facts["entries"]:
        row = tops.setdefault(entry.path.split("/", 1)[0],
                              {"files": 0, "dirs": 0, "bytes": 0})
        row["files"] += 1
        row["bytes"] += entry.size
    for directory in facts["dirs"]:
        row = tops.get(directory.split("/", 1)[0])
        if row is not None:
            row["dirs"] += 1
    items = [
        PlanItem(category="deploy.stream", target=name,
                 detail=(f"{row['files']} file(s), {row['dirs']} dir(s) -> "
                         f"{label} (additive: nothing is deleted)"),
                 bytes_est=row["bytes"])
        for name, row in sorted(tops.items())
    ]
    items.append(PlanItem(
        category="deploy.estimate", target="stream", bytes_est=0,
        detail=(f"{facts['files']} file(s) / {human_bytes(facts['bytes'])} from "
                f"{Path(zip_path).name} (root stripped: "
                f"{facts['root'] or '<none>'}) -> {label}; about "
                f"{duration:.0f}s at {human_bytes(settings.stream_bytes_per_s)}/s, "
                f"plus {human_bytes(settings.preflight_margin_bytes)} of "
                f"headroom demanded by the preflight"),
    ))
    log.info("deploy plan: %d file(s), %s, target=%s, estimate %.0fs",
             facts["files"], human_bytes(facts["bytes"]), label, duration)
    return Plan(items=items)


# --------------------------------------------------------------- the stream


class _HashingReader:
    """A read-through wrapper that hashes the member as it is written.

    Hashing in the producer (rather than reading each member twice) is
    what makes the transfer manifest nearly free — and it guarantees the
    recorded sha256 is the digest of the exact bytes the tar carried, so
    the record cannot drift from the artifact.
    """

    def __init__(self, handle: Any, hasher: Any) -> None:
        self._handle = handle
        self._hasher = hasher

    def read(self, size: int = -1) -> bytes:
        data = self._handle.read(size)
        if data:
            self._hasher.update(data)
        return data


def _is_symlink(zinfo: zipfile.ZipInfo) -> bool:
    """True for a zip member stored as a symlink (the unix mode lives in
    the external attributes — the only signal a zip carries)."""
    mode = zinfo.external_attr >> 16
    return bool(mode) and stat.S_ISLNK(mode)


def _member_index(zf: zipfile.ZipFile, root: str) -> dict[str, zipfile.ZipInfo]:
    """rel-path -> ZipInfo for the members under ``root``.

    Uses the SAME normalization :class:`~wpt.sources.zip.ZipSource` uses
    (backslashes folded to slashes, prefix stripped, normpath), so the
    streaming producer and the counting pass agree on identity by
    construction instead of by a second guess at the naming rules.
    """
    prefix = f"{root}/" if root else ""
    index: dict[str, zipfile.ZipInfo] = {}
    for info in zf.infolist():
        name = info.filename.replace("\\", "/")
        if prefix and not name.startswith(prefix):
            continue
        rel = posixpath.normpath(name[len(prefix):] if prefix else name)
        if rel in (".", ".."):
            continue
        # An ESCAPING member is kept, not skipped: the caller's safety
        # gate refuses the whole archive rather than deploying a silently
        # truncated version of it.
        previous = index.get(rel)
        if previous is not None and previous.is_dir() != info.is_dir():
            raise DeployError(
                f"archive names {rel!r} as both a file and a directory — "
                "refusing to deploy an archive whose members collide")
        index[rel] = info
    return index


def stream_archive(zip_path: Path, sink: BinaryIO, *, settings: DeploySettings,
                   deadline: Deadline | None = None,
                   stats: StreamStats | None = None,
                   facts: dict[str, Any] | None = None) -> StreamStats:
    """Write the normalized tar for ``zip_path`` into ``sink``.

    Normalization is fixed (SPEC §deploy): files ``0644``, directories
    ``0755``, ``mtime=0``, uid/gid 0, empty owner names, members sorted
    with parents before children.  The archive's single top-level host
    directory is stripped HERE, in the producer, exactly once — the
    consumer is ``tar -xf - -C <webroot>`` and never strips again.

    Symlinks and escaping members are REFUSED, never followed and never
    recreated: a webroot deploy that re-materialized a symlink pointing
    outside the webroot would write outside the target the operator
    named.  One clear line names the offending member.
    """
    facts = facts or zip_facts(Path(zip_path), deadline=deadline)
    out = stats or StreamStats(root=facts["root"])
    out.entry_count = facts["entry_count"]
    if not out.started:
        out.started = time.monotonic()
    try:
        zf = zipfile.ZipFile(zip_path)
    except _MEMBER_READ_ERRORS as exc:
        raise DeployError(
            f"archive {zip_path} cannot be read: {exc}") from exc
    try:
        members = _member_index(zf, facts["root"])
        with tarfile.open(fileobj=sink, mode="w|",
                          format=tarfile.PAX_FORMAT) as tar:
            for directory in facts["dirs"]:
                if deadline is not None:
                    deadline.check("deploy stream")
                info = tarfile.TarInfo(directory)
                info.type = tarfile.DIRTYPE
                info.mode = DIR_MODE
                info.mtime = TAR_MTIME
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                tar.addfile(info)
                out.dirs += 1
            for entry in facts["entries"]:
                if deadline is not None:
                    deadline.check("deploy stream")
                path = entry.path
                if not _safe_member(path):
                    raise DeployError(
                        f"refusing to deploy unsafe archive member {path!r} — "
                        "it would write outside the target webroot")
                zinfo = members.get(path)
                if zinfo is not None and _is_symlink(zinfo):
                    raise DeployError(
                        f"refusing to deploy symlink member {path!r} — a "
                        "webroot deploy ships regular files and directories "
                        "only; replace the link with its target first")
                info = tarfile.TarInfo(path)
                info.type = tarfile.REGTYPE
                info.mode = FILE_MODE
                info.mtime = TAR_MTIME
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.size = entry.size
                hasher = hashlib.sha256()
                try:
                    handle = zf.open(zinfo if zinfo is not None else path)
                    with handle:
                        # tarfile.addfile copies in blocks; the wrapper
                        # hashes exactly the bytes it copies.  The read can
                        # fail MID-COPY (corrupt CRC is checked at EOF), so
                        # the whole copy is inside the member-error boundary.
                        tar.addfile(info, _HashingReader(handle, hasher))
                except (KeyError, *_MEMBER_READ_ERRORS) as exc:
                    raise DeployError(
                        f"archive member {path!r} cannot be read: {exc}") \
                        from exc
                out.files += 1
                out.bytes_written += entry.size
                out.sha256[path] = hasher.hexdigest()
                out.sizes[path] = entry.size
                if out.files % _HEARTBEAT_EVERY == 0:
                    log.info("deploy progress: %d/%d file(s), %s streamed",
                             out.files, facts["entry_count"],
                             human_bytes(out.bytes_written))
    finally:
        zf.close()
    out.elapsed_s = time.monotonic() - out.started
    return out


def deploy_stream(zip_path: Path, target: Target, settings: DeploySettings, *,
                  deadline: Deadline | None = None,
                  preflight_result: Preflight | None = None
                  ) -> tuple[StreamStats, Preflight]:
    """Stream the webroot into ``target``: preflight, pipe, STOP.

    The order is the contract:

    1. facts (one central-directory read, no file bodies),
    2. the quota preflight — a refusal here has moved NOTHING,
    3. the tar stream into ``tar -x``,
    4. classification of any failure (a quota signature stays a quota
       failure even when the host says "SSH layer"),
    5. the post-extract layout assertion, in :func:`assert_target`.

    Returns the stream stats and the preflight measurement; the caller
    runs the manifest verification and writes the manifest.
    """
    if deadline is not None:
        deadline.check("deploy plan")
    facts = zip_facts(Path(zip_path), deadline=deadline)
    if deadline is not None:
        deadline.check("deploy preflight")
    result = preflight_result or preflight(target, facts["bytes"], settings,
                                           deadline)
    reason = result.refuse_reason()
    if reason:
        raise QuotaError(reason)
    if deadline is not None:
        # The preflight is paid for: a budget that expired DURING it must
        # stop before the stream creates the remote extraction.
        deadline.check("deploy stream")
    log.info("deploy: streaming %d file(s), %s into %s",
             facts["files"], human_bytes(facts["bytes"]), target.label)
    stats = StreamStats(root=facts["root"])
    try:
        rc, stderr = target.extract(
            lambda sink: stream_archive(Path(zip_path), sink, settings=settings,
                                        deadline=deadline, stats=stats,
                                        facts=facts),
            timeout=float(settings.stream_timeout_s),
            deadline=deadline,
        )
    except (BrokenPipeError, OSError) as exc:
        raise TransferError(
            f"deploy stream to {target.label} failed while writing: "
            f"{type(exc).__name__}: {exc}") from exc
    if rc != 0:
        classify_transfer_error(stderr, rc, settings).raise_for(
            f"deploy stream to {target.label} (exit {rc})")
    if stderr.strip():
        log.warning("deploy: remote tar reported: %s", stderr.strip()[:500])
    return stats, result


# --------------------------------------------------------------- verification


def verify_against_manifest(target: Target, manifest: dict[str, Any],
                            settings: DeploySettings,
                            deadline: Deadline | None = None
                            ) -> VerificationResult:
    """Re-read the streamed set's sha256s on the target and compare.

    One ``sha256sum``/``shasum`` invocation per batch of paths — the
    host-side bulk-work owner, the same decision the bridge's
    ``core_md5`` makes for a live core check: thousands of individual reads
    are minutes of round trips, one batched command is seconds.  Paths
    are quoted, never interpolated raw, and a batch the host cannot
    answer lands as missing in the comparison rather than being skipped.

    ``deadline`` is the run's ONE memoized budget, checked before every
    batch and forwarded into the command reap: a 28k-file deploy with
    ~140 batches used to run ~140 × ``probe_timeout_s`` past ``--deadline``.
    """
    entries = [e for e in manifest.get("files", []) if isinstance(e, dict)]
    batch = max(settings.verify_batch_paths, 1)
    observed: dict[str, str] = {}
    for start in range(0, len(entries), batch):
        if deadline is not None:
            deadline.check("deploy verify")
        chunk = entries[start:start + batch]
        if not chunk:
            continue
        quoted = " ".join(shlex.quote(e.get("path", "")) for e in chunk)
        command = (
            f"cd -- {shlex.quote(target.webroot)} 2>/dev/null || exit 3; "
            f"if command -v sha256sum >/dev/null 2>&1; then "
            f"sha256sum -- {quoted}; "
            f"elif command -v shasum >/dev/null 2>&1; then "
            f"shasum -a 256 -- {quoted}; "
            f"else echo 'no sha256 tool on host' >&2; exit 127; fi"
        )
        try:
            rc, out, err = target.run_command(
                command, timeout=settings.probe_timeout_s, deadline=deadline)
        except (DeployError, TransferError) as exc:
            log.debug("deploy verification batch failed: %s", exc)
            continue
        if rc == 127:
            raise DeployError(
                "cannot verify the deploy: the host has neither sha256sum "
                "nor shasum, so the streamed set's hashes cannot be re-read "
                "— install coreutils on the target, or deploy without "
                "verification")
        if rc not in (0, 1):
            classify_transfer_error(err, rc, settings).raise_for(
                f"deploy verification on {target.label}")
        for line in out.splitlines():
            parts = line.split(None, 1)
            if len(parts) != 2 or len(parts[0]) != 64:
                continue
            observed[parts[1].lstrip("*").strip()] = parts[0]
    return verify_files(manifest, observed)


# ------------------------------------------------------------------ rendering


def _render(target_label: str, stats: StreamStats, readback: Readback,
            result: VerificationResult | None,
            manifest_path: Path | None) -> str:
    top = readback.top_level[:12]
    lines = [
        f"# wpt deploy — {target_label}",
        "",
        f"Streamed {stats.files} file(s) / {human_bytes(stats.bytes_written)} "
        f"in {stats.elapsed_s:.0f}s (archive root stripped: "
        f"{stats.root or '<none>'}).",
        "",
        f"- Layout: {readback.message()}",
        f"- Top-level entries on target: {len(readback.top_level)}"
        + (f" ({', '.join(top)}…)" if len(readback.top_level) > len(top) else
           (f" ({', '.join(top)})" if top else "")),
        "- Additive: nothing was deleted; target content the stream did not "
        "ship is untouched.",
    ]
    if result is not None:
        lines.append(f"- Verification: {result.message()}")
    if manifest_path is not None:
        lines.append(f"- Transfer manifest: `{manifest_path}`")
    lines.append("")
    return "\n".join(lines)


def _render_json(target_label: str, stats: StreamStats, readback: Readback,
                 result: VerificationResult | None,
                 manifest_path: Path | None) -> str:
    return json.dumps(
        {
            "target": target_label,
            "files": stats.files,
            "dirs": stats.dirs,
            "bytes": stats.bytes_written,
            "elapsed_s": round(stats.elapsed_s, 1),
            "archive_root": stats.root,
            "missing_files": list(readback.missing_files),
            "missing_dirs": list(readback.missing_dirs),
            "residue": list(readback.residue),
            "verified_files": result.checked if result else 0,
            "mismatched": list(result.mismatched) if result else [],
            "missing_on_target": list(result.missing) if result else [],
            "manifest": str(manifest_path) if manifest_path else None,
        },
        ensure_ascii=False, sort_keys=True, indent=2,
    ) + "\n"


def _render_plan_json(plan: Plan, zip_path: Path, ssh_target: str,
                      webroot: str) -> str:
    """The dry run's JSON twin: the SAME facts :func:`_render_plan` puts
    in the markdown, as an object.

    Every other ``--report`` surface writes markdown AND its twin beside
    it, and this command's applied run already did (the manifest summary
    in :func:`_render_json`) — a dry run without one made the pairing half
    true, so a caller could not script "did this deploy plan anything?"
    without parsing prose.  ``applied: false`` is the field that says it:
    nothing was streamed, verified or deleted.
    """
    return json.dumps(
        {
            "applied": False,
            "target": _top_level_label(ssh_target, webroot),
            "archive": Path(zip_path).name,
            "webroot": webroot,
            "items": [
                {
                    "category": item.category,
                    "target": item.target,
                    "detail": item.detail,
                    "bytes_est": item.bytes_est,
                }
                for item in plan.items
            ],
            "total_bytes": plan.est_bytes(),
        },
        ensure_ascii=False, sort_keys=True, indent=2,
    ) + "\n"


def _render_plan(plan: Plan, zip_path: Path, ssh_target: str, webroot: str,
                 settings: DeploySettings) -> str:
    """The dry-run markdown: the plan table plus the contract in prose."""
    label = _top_level_label(ssh_target, webroot)
    lines = [
        f"# wpt deploy (dry run) — {label}",
        "",
        f"Archive `{Path(zip_path).name}`: {plan.est_bytes()} streamed into "
        f"`{webroot}`. The deploy is ADDITIVE (nothing is deleted), and the "
        f"quota preflight refuses before the first byte moves unless "
        f"{human_bytes(settings.preflight_margin_bytes)} of headroom plus "
        f"the streamed size fits the deploy account.",
        "",
        "| item | detail | bytes |",
        "|---|---|---|",
    ]
    for item in plan.items:
        shown = human_bytes(item.bytes_est) if item.bytes_est else "-"
        lines.append(f"| `{item.target}` | {item.detail} | {shown} |")
    lines.append("")
    return "\n".join(lines)


# ------------------------------------------------------------------ CLI body


def _unique_manifest_dir(parent: Path, stem: str) -> Path:
    """A release-record directory that cannot replace an earlier release.

    ``write_manifest`` atomically replaces an existing ``manifest.json`` (the
    pinned contract), so two deploys of the same site within one second
    shared a timestamped directory and the second silently replaced the
    first record.  Allocate the first free ``stem``/``stem-2``/… name by
    CREATING it with ``mkdir`` (the atomic claim): an existence check
    followed by a later write left two concurrent deploys both believing
    they owned the stem, and the second manifest replaced the first.
    """
    parent.mkdir(parents=True, exist_ok=True)
    for offset in range(1, 1000):
        candidate = parent / (stem if offset == 1 else f"{stem}-{offset}")
        try:
            candidate.mkdir(mode=0o700)
        except FileExistsError:
            continue
        return candidate
    raise ManifestError(
        f"cannot allocate a deploy manifest directory for {parent / stem}")


def run(ctx: Any) -> int:
    """Run the ``wpt deploy`` command body — 0 on success, 1 on failure.

    Reads ``ctx.zip`` (the prepared webroot archive), ``ctx.webroot`` (the
    target webroot ON THE HOST) and ``ctx.extra``: ``ssh_target``,
    ``ssh_port``, ``ssh_password_env``.  Without ``--apply`` this is the
    dry run: the plan is printed and NOTHING is spawned, not even a
    preflight probe.  With ``--apply`` the order is the contract above —
    confirm, preflight, stream, assert layout, verify hashes, write the
    manifest — and any failure answers rc 1 with one clear line.

    The markdown summary is always written through the shared report
    sink: the report IS this command's stdout surface, as in
    wpt.verify / wpt.doctor / wpt.backup.  With ``--report`` it is also
    written there, ALWAYS PAIRED with a JSON twin — the applied run's
    describes the stream, the readback and the verification
    (:func:`_render_json`), the dry run's describes the plan it printed
    (:func:`_render_plan_json`) — through
    ``wpt.actions.registry.write_report``, the one writer every
    ``--report`` surface shares, so the file cannot be accepted and
    ignored.  A report that cannot be written fails the run.
    """
    target: Target | None = None
    #: True once this run has answered with a primary failure (an exception
    #: or a failed result/report).  A teardown stop must then be logged but
    #: never replace the report that already names the real cause.
    primary_failure = False
    try:
        if getattr(ctx, "mode", "local") != "local":
            # The artifact is a LOCAL webroot zip; there is no ftp-side
            # deploy (that would be a restore, and `wpt restore` owns it).
            return _refuse(ctx, "deploy is a local-archive command: run it "
                                "with --source local --zip SITE.zip")
        extra = dict(getattr(ctx, "extra", {}) or {})
        if not getattr(ctx, "zip", None):
            return _refuse(ctx, "deploy requires --zip (the prepared "
                                "webroot archive)")
        zip_path = Path(ctx.zip)
        if not zip_path.is_file():
            return _refuse(ctx, f"no such archive: {zip_path}")
        ssh_target = str(extra.get("ssh_target") or "")
        webroot = str(getattr(ctx, "webroot", None) or "")
        if not ssh_target:
            return _refuse(ctx, "deploy requires --ssh-target (user@host, "
                                "or local:<dir> to rehearse locally)")
        if not webroot:
            return _refuse(ctx, "deploy requires --webroot (the target "
                                "webroot path on the host)")
        settings = ctx.settings.deploy
        if extra.get("ssh_port") is not None:
            # The shared port owner validates BEFORE replace: int(inf) used
            # to raise a raw OverflowError, and int(1.9)/True/"12" silently
            # became port 1/12 (R6-45).  0 is invalid, never "use 22".
            try:
                ssh_port = coerce_port(
                    extra["ssh_port"], name="deploy.ssh_port (--ssh-port)",
                    minimum=PORT_MIN_BINDABLE)
            except ValueError as exc:
                return _refuse(ctx, f"deploy: {exc}")
            settings = replace(settings, ssh_port=ssh_port)
        plan = build_plan(zip_path, ssh_target, webroot, settings,
                          deadline=Deadline.from_ctx(ctx))
        # The plan/facts phase is bounded work for BOTH paths: a spent budget
        # must never print/write a plan as success, nor proceed to a
        # confirmation/apply.
        plan_deadline = Deadline.from_ctx(ctx)
        if plan_deadline is not None:
            plan_deadline.check("deploy plan")
        # The report writer is the action registry's (ONE owner for every
        # --report surface); imported here for the same reason ``confirm``
        # is: the registry imports deploy's peers, not deploy itself.
        from .actions.registry import write_report

        if not getattr(ctx, "apply", False):
            markdown = _render_plan(plan, zip_path, ssh_target, webroot,
                                    settings)
            write_stdout(markdown)
            log.info("deploy: dry run — no bytes moved (pass --apply to deploy)")
            # --report is the tool's universal contract (the audit, verify,
            # doctor, walk, backup and restore paths all honour it, and
            # every registered action writes through this same owner): the
            # dry run's plan lands in the file too, even though it planned
            # nothing to move — WITH its JSON twin, like every other
            # surface, describing the plan this run printed (no manifest,
            # no stream and no readback exist yet; the applied run's twin
            # carries those).
            return write_report(
                ctx, "deploy", markdown,
                _render_plan_json(plan, zip_path, ssh_target, webroot),
            )
        from .actions.registry import confirm

        if not confirm(ctx):
            return _refuse(ctx, "deploy cancelled at the confirmation gate; "
                                "nothing was transferred", status="refused")
        target = make_target(ssh_target, webroot, settings,
                             extra.get("ssh_password_env"))
        deadline = Deadline.from_ctx(ctx)
        stats, _pre = deploy_stream(zip_path, target, settings,
                                    deadline=deadline)
        readback = assert_target(target, settings, deadline=deadline)
        # The manifest describes what was STREAMED, so its counters come
        # from the stream itself — no second pass over the archive.  The
        # archive hash and the manifest write are LOCAL work and were the
        # two unbounded phases left after the last network check.
        if deadline is not None:
            deadline.check("deploy manifest")
        manifest = build_manifest(
            site=redacted_site_label(
                getattr(ctx, "wp_url", None) or zip_path.stem),
            target=target.label, webroot=target.webroot,
            zip_name=zip_path.name, entry_count=stats.entry_count,
            uncompressed_bytes=stats.bytes_written,
            files={p: (d, stats.sizes.get(p, 0)) for p, d in stats.sha256.items()},
            archive_bytes=zip_path.stat().st_size, root=stats.root,
            archive_sha256=(sha256_file(zip_path, deadline=deadline)
                            if settings.manifest_archive_sha256 else None),
        )
        result = verify_against_manifest(target, manifest, settings,
                                         deadline=deadline)
        manifest_path: Path | None = None
        if result.ok:
            if deadline is not None:
                deadline.check("deploy manifest")
            manifest_dir = _unique_manifest_dir(
                Path(ctx.backup_dir) / DEPLOY_MANIFEST_SUBDIR,
                f"{manifest['site']}-{time.strftime('%Y%m%d-%H%M%S')}")
            manifest_path = write_manifest(
                manifest, manifest_dir, root=Path(ctx.backup_dir))
        else:
            log.error("%s", result.message())
        markdown = _render(target.label, stats, readback, result, manifest_path)
        write_stdout(markdown)
        if write_report(ctx, "deploy", markdown,
                        _render_json(target.label, stats, readback, result,
                                     manifest_path)):
            primary_failure = True
            return 1
        log.info("deploy complete: %d file(s), %s, %ds", stats.files,
                 human_bytes(stats.bytes_written), int(stats.elapsed_s))
        if result.rc:
            primary_failure = True
        return result.rc
    except RunControl as exc:
        primary_failure = True
        return _refuse(ctx, f"deploy stopped: {exc}")
    except (DeployError, CredentialError, ManifestError, WptError, OSError) as exc:
        primary_failure = True
        return _refuse(ctx, f"deploy failed: {exc}")
    finally:
        close = getattr(target, "close", None)
        if callable(close):
            try:
                close()
            except (StopRequested, DeadlineExceeded) as exc:
                # A teardown stop NEVER replaces a primary failure pair
                # (R6-46's rule, which deploy lacked).  On an otherwise
                # successful run it remains the run-ending event and reaches
                # the dispatch boundary for its rc-1 failure pair.
                if primary_failure:
                    log.warning(
                        "deploy: teardown stop (%s) did not mask the primary "
                        "failure", type(exc).__name__)
                else:
                    raise
            except Exception:              # cleanup never masks the verdict
                log.debug("deploy target cleanup failed", exc_info=True)


def _refuse(ctx: Any, reason: str, *, status: str = "failed") -> int:
    """A deploy run that deployed nothing: one error line, the report it
    could write, rc 1.

    The deploy dry run honours ``--report`` through
    ``wpt.actions.registry.write_report`` (L44), but a FAILED run wrote
    nothing at all — so a caller that scripted a deploy and reads its
    report could not tell "there was nothing to deploy" from "the deploy
    never got far enough", which is the one distinction a scripted caller
    cannot make any other way.  The report is deploy's own shape (its
    header and its own zeroed twin fields) plus the shared
    ``wpt.actions.registry.not_complete`` block, so the reason reaches
    disk through the same redaction chokepoint as the log.

    Written, never printed: a failed run has no transfer report to show.
    """
    from .actions.registry import not_complete, write_report

    log.error("%s", reason)
    block, payload = not_complete(reason, status=status)
    archive = getattr(ctx, "zip", None)
    webroot = str(getattr(ctx, "webroot", "") or "")
    ssh_target = str((getattr(ctx, "extra", {}) or {}).get("ssh_target") or "")
    # The archive NAME, never its path: the header says what ran, and an
    # operator's home directory is not part of that (the serve receipt's
    # own rule).
    site = redacted_site_label(
        str(getattr(ctx, "wp_url", None) or "")
        or (Path(archive).name if archive else ""),
        fallback="deploy")
    markdown = "\n".join([f"# wpt deploy — {site}", ""]) + block
    # The dry run's own twin shape (applied/target/archive/webroot/items/
    # total_bytes), so a caller parses one family of files: `applied: false`
    # says nothing was streamed, and the empty `items` says nothing was
    # planned.  `run` is the one addition, and it is the only place the
    # reason lives.
    twin = {
        "applied": False,
        "target": (_top_level_label(ssh_target, webroot)
                   if ssh_target and webroot else ""),
        "archive": Path(archive).name if archive else "",
        "webroot": webroot,
        "items": [],
        "total_bytes": 0,
        "findings": [],
        "run": payload,
    }
    def _write() -> None:
        write_report(ctx, "deploy", markdown,
                     json.dumps(twin, ensure_ascii=False, sort_keys=True,
                                indent=2) + "\n")

    # A second stop/deadline landing in the failure-report write must not
    # replace the PRIMARY reason with "deploy stopped: ..." through the
    # outer RunControl handler.  Contain it here (like the registry's
    # _safe_failure_report); one retry recovers the one-shot signal so the
    # report still names why the deploy was refused.
    try:
        _write()
    except (Exception, RunControl) as exc:  # noqa: BLE001
        log.warning("deploy: could not write the failure report: %s",
                    redact_text(str(exc)))
        try:
            _write()
        except (Exception, RunControl) as retry_exc:  # noqa: BLE001
            log.warning("deploy: failure report retry failed: %s",
                        redact_text(str(retry_exc)))
    return 1
