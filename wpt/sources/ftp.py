"""FTPS source connector — the live-site Source implementation."""

import io
import posixpath
import re
import socket
import ssl
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Callable, NoReturn

import ftplib

from ..log import get_logger
from ..netresolve import is_numeric_host, resolve_host_bounded
from ..settings import FtpSettings
from ..types import (DeadlineExceeded, Entry, FtpChannelUnhealthy,
                     SIZE_UNKNOWN, SourceError, SourceLookupError,
                     StopRequested, WptError)
from .base import WalkMixin

log = get_logger("sources.ftp")

#: English month abbreviations Unix LIST uses ("Sep").  A server that
#: localizes the name is not parsed: mtime stays None rather than guessed.
_LIST_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

#: The type characters a Unix LIST permission word may start with
#: (regular, directory, symlink, block/char device, FIFO, socket).
_LIST_TYPES = frozenset("-dlcbps")


class _ReadLimitExceeded(Exception):
    """Internal: a streamed RETR passed the caller's hard byte bound."""


def _is_list_header(line: str) -> bool:
    """True for the Unix ``total N`` header and a blank line."""
    stripped = line.strip()
    return not stripped or stripped.lower().startswith("total ")


def _parse_list_mode(perms: str) -> int | None:
    """The permission bits of a Unix LIST word, or None when malformed.

    The ten-character word is a type character plus three rwx triples.
    Setuid/setgid/sticky keep their high bits ('s'/'t' imply the matching
    execute bit, 'S'/'T' do not).  The type character itself stays OUT of
    ``Entry.mode`` so FTP and zip metadata mean the same thing — permission
    bits — and directory-ness is already carried by ``is_dir``.
    """
    if len(perms) < 10 or perms[0] not in _LIST_TYPES:
        return None
    mode = 0
    for bit, char in zip((0o400, 0o040, 0o004), perms[1::3]):
        if char == "r":
            mode |= bit
        elif char != "-":
            return None
    for bit, char in zip((0o200, 0o020, 0o002), perms[2::3]):
        if char == "w":
            mode |= bit
        elif char != "-":
            return None
    special = perms[3::3]
    for bit, char, allowed in zip((0o100, 0o010, 0o001), special,
                                  ("sS", "sS", "tT")):
        if char == "x" or char in allowed:
            if char in "xst":   # lowercase s/t also grant the execute bit
                mode |= bit
        elif char != "-":
            return None
    if special[0] in "sS":
        mode |= 0o4000
    if special[1] in "sS":
        mode |= 0o2000
    if special[2] in "tT":
        mode |= 0o1000
    return mode


def _parse_list_mtime(month: str, day: str, clock: str,
                      now: float) -> int | None:
    """Epoch seconds for a Unix LIST date, or None when it cannot be read.

    LIST carries NO timezone and, for recent files, no year ("Sep 14
    12:00" versus "Sep 14 2023"), so this conversion is explicitly
    BEST-EFFORT: a year line is taken literally at midnight UTC; a
    time-of-day line takes the UTC year of ``now`` and rolls back one year
    when that instant would be in the future (the listing's own new-year
    boundary).  The server's local clock can therefore shift ``mtime`` by
    its UTC offset — consumers may use it as an age hint, never as an
    exact timestamp.
    """
    month_number = _LIST_MONTHS.get(month)
    if month_number is None:
        return None
    try:
        day_number = int(day)
    except ValueError:
        return None
    try:
        if ":" in clock:
            parts = clock.split(":")
            if len(parts) not in (2, 3):
                return None
            hour, minute = int(parts[0]), int(parts[1])
            second = int(parts[2]) if len(parts) == 3 else 0
            reference = datetime.fromtimestamp(now, tz=timezone.utc)
            stamp = datetime(reference.year, month_number, day_number,
                             hour, minute, second, tzinfo=timezone.utc)
            if stamp.timestamp() > now:
                stamp = stamp.replace(year=reference.year - 1)
        else:
            if len(clock) != 4 or not clock.isdigit():
                return None
            stamp = datetime(int(clock), month_number, day_number,
                             tzinfo=timezone.utc)
        return int(stamp.timestamp())
    except (ValueError, OverflowError, OSError):
        return None


class FtpSource(WalkMixin):
    """Source over FTPS. Lazy-connects; one reconnect-retry on stale connections.

    All paths are POSIX-relative to ``root``; guards come from types.Source.
    Two bounds in _call() keep every bulk consumer finite on a degraded
    passive channel — the consecutive-FAILURE breaker (outright failed ops)
    and the slow-OP window (ops that merely crawl near the timeout). Bulk
    reads (read_many) go through dedicated parallel worker sessions — see
    read_many.
    """

    #: Structural constants (NOT settings tunables — the shape of the
    #: detection, not a per-site knob): how many recent op durations the
    #: slow-op window considers, and what fraction of ftp.timeout_s an op
    #: must exceed to count as "slow". Live-measured shape on the degraded
    #: production host: every data connect stalls ~30-45s then SUCCEEDS.
    _SLOW_WINDOW = 10
    _SLOW_RATIO = 0.8

    def __init__(self, host: str, user: str, password: str, root: str,
                 settings: FtpSettings | None = None,
                 deadline: "Any | None" = None,
                 cleanup_deadline_s: float | None = None) -> None:
        self.host = host
        self.user = self._validated_credential("user", user)
        self.password = self._validated_credential("password", password)
        #: The run's ONE wall-time budget (a ``wpt.deadline.Deadline`` or
        #: None), attached by ``wpt.remote.ftp_source_for``.  Every socket
        #: connect/login/control/data/list/retr op is capped at its
        #: remaining seconds and checked before each retry, so a silent FTP
        #: banner cannot outlive the run budget (C2).
        self.deadline = deadline
        #: Fresh finite budget ``Source.deadline_suspended`` installs for
        #: rollback/residue cleanup (run.cleanup_deadline_s, set by the ONE
        #: source-construction seam).
        self.cleanup_deadline_s = cleanup_deadline_s
        # ``--webroot`` reaches LIST/SIZE/RETR verbatim.  A CR/LF answers
        # ftplib's raw ValueError and a surrogate its UnicodeEncodeError —
        # neither is a WptError — so the SAME path guard every other path
        # uses validates the root at construction, before any command body.
        root = (root or "").strip("/")
        if root:
            root = self._guard_path(root)
        self.root = root
        self.settings = settings or FtpSettings()
        self._ftp: ftplib.FTP_TLS | None = None
        #: The absolute directory ``login`` left the session in.  ``root`` is
        #: relative to it; ``_remote`` joins the two so every command is
        #: addressed absolutely even after a CWD probe (R6-01).
        self._login_dir: str | None = None
        self._consecutive_failures = 0   # breaker state: outright-failed ops in a row
        # slow-op window state: wall duration of the last _SLOW_WINDOW ops
        self._op_durations: deque[float] = deque(maxlen=self._SLOW_WINDOW)
        #: Webroot-relative directories this session has PROVEN to exist,
        #: so ensure_write_dir pays for each chain component exactly once
        #: (see ensure_write_dir for why the work is memoized at all).
        self._known_dirs: set[str] = {""}

    # ---------------------------------------------------------------- connection

    @staticmethod
    def _validated_credential(field: str, value: str) -> str:
        """Refuse a credential ftplib cannot put on the wire safely.

        ``ftplib.login`` -> ``putline`` raises a raw ``ValueError`` for CR/LF
        (a trailing newline from ``$(cat secret)`` is realistic), and a lone
        surrogate raises ``UnicodeEncodeError``; neither is a WptError, so
        both escaped every command body's ``(WptError, OSError)`` contract.
        Control bytes are also a protocol-injection class, so the check is
        at the constructor (the one seam every command uses), not per call.
        """
        if not isinstance(value, str):
            raise SourceError(
                f"ftp {field} must be text, got {type(value).__name__}")
        for char in value:
            code = ord(char)
            if code < 0x20 or code == 0x7F or 0xD800 <= code <= 0xDFFF:
                raise SourceError(
                    f"ftp {field} contains a control character or lone "
                    f"surrogate (U+{code:04X}); refusing to put it on the "
                    "wire")
        return value

    def _check_budget(self, context: str) -> None:
        if self.deadline is not None:
            self.deadline.check(context)

    def _budget_timeout(self, cap: float, context: str) -> float:
        """``cap`` seconds, shrunk to the run budget still remaining.

        Zero/negative remaining raises DeadlineExceeded BEFORE a new socket
        operation starts; the tiny floor keeps a positive but sub-ms budget
        from becoming a non-blocking socket.
        """
        if self.deadline is None:
            return cap
        remaining = self.deadline.remaining
        if remaining <= 0:
            self.deadline.check(context)
        return max(0.001, min(cap, remaining))

    def _arm_socket(self, ftp: ftplib.FTP_TLS, context: str) -> float:
        """Apply the current budget to the control socket and ftplib's
        ``timeout`` (which also bounds each passive data connect)."""
        timeout = self._budget_timeout(self.settings.timeout_s, context)
        ftp.timeout = timeout
        sock = getattr(ftp, "sock", None)
        if sock is not None:
            sock.settimeout(timeout)
        return timeout

    def _tls_context(self) -> ssl.SSLContext:
        """The FTPS TLS context: verified by default, loud opt-out only.

        Python's bare ``FTP_TLS()`` uses ``_create_stdlib_context`` —
        ``CERT_NONE`` / no hostname check — so ANY MITM could present any
        certificate and capture the FTP password sent by ``login``.  The
        default is now hostname-verifying; ``ftp.verify_tls=false`` is the
        deliberate pre-migration escape hatch and says so at WARNING.
        ``ftp.ca_file`` adds a private CA without disabling verification.
        """
        if not self.settings.verify_tls:
            log.warning(
                "ftp: TLS certificate verification is DISABLED "
                "(ftp.verify_tls=false) for %s — any peer can impersonate "
                "the server and capture credentials; enable it before the "
                "pre-migration window closes", self.host)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return context
        try:
            context = ssl.create_default_context()
            # SPEC: ``ftp.ca_file`` ADDS a private CA; passing it as
            # ``cafile=`` to create_default_context REPLACED the public
            # trust store with that one file, so every public-CA server
            # failed once an operator configured a private CA.
            if self.settings.ca_file:
                context.load_verify_locations(cafile=self.settings.ca_file)
            return context
        except (OSError, ssl.SSLError) as exc:
            raise SourceError(
                f"ftp.ca_file {self.settings.ca_file!r} could not be "
                f"loaded: {exc}") from exc

    def _track_transfers(self, ftp: ftplib.FTP_TLS) -> None:
        """Track every data socket so the deadline watchdog can close it.

        ``retrbinary``/``storbinary``/``retrlines`` obtain their data
        socket through ``transfercmd``; wrapping that one seam covers
        LIST/RETR/STOR and every later caller without duplicating each
        ftplib loop.
        """
        sockets: deque[Any] = deque(maxlen=8)
        ftp._wpt_data_sockets = sockets  # type: ignore[attr-defined]
        original = getattr(ftp, "transfercmd", None)
        if not callable(original):
            # A test/embedder connection double with no ftplib transfer
            # seam: nothing to track (and no per-read blocking to bound).
            return

        def transfercmd(cmd: str, rest: Any = None) -> Any:
            data = original(cmd, rest)
            sockets.append(data)
            return data

        ftp.transfercmd = transfercmd  # type: ignore[method-assign]
        # PASV -> data CONNECT seam: ftplib's ``ntransfercmd`` runs
        # ``makepasv()`` (the PASV command/reply round trip) and only THEN
        # reads ``self.timeout`` for ``socket.create_connection``.  Arming
        # before the call measured the budget before the exchange; arm
        # AFTER it returns, at the last possible instant, so the data
        # connect gets the remaining run budget.  The transfercmd wrapper
        # only sees the socket AFTER the connect returned.
        original_pasv = getattr(ftp, "makepasv", None)
        if callable(original_pasv):
            def makepasv() -> Any:
                result = original_pasv()
                self._arm_socket(ftp, "ftp data connect")
                return result

            ftp.makepasv = makepasv  # type: ignore[method-assign]

    @staticmethod
    def _close_socket(sock: Any) -> None:
        if sock is None:
            return
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except (OSError, ValueError):
            pass
        try:
            sock.close()
        except (OSError, ValueError):
            pass

    def _close_ftp_sockets(self, ftp: Any) -> None:
        for data in list(getattr(ftp, "_wpt_data_sockets", ())):
            self._close_socket(data)
        self._close_socket(getattr(ftp, "sock", None))

    @contextmanager
    def _deadline_watch(self, ftp: Any, context: str):
        """Close control+data sockets AT the absolute run deadline.

        ``ftplib`` reads with the per-read ``timeout`` set once per op; a
        peer dripping one byte per read resets it forever.  The watchdog
        fires once at ``Deadline.at`` and shuts the sockets down, which
        unblocks banner/login/LIST/RETR/STOR and any data drip; the caller
        maps the resulting exception/expired flag to DeadlineExceeded.
        """
        if self.deadline is None:
            yield None
            return
        expired = threading.Event()
        done = threading.Event()

        def _run() -> None:
            remaining = self.deadline.at - time.monotonic()
            if remaining > 0 and done.wait(remaining):
                return
            if done.is_set():
                return
            expired.set()
            self._close_ftp_sockets(ftp)

        worker = threading.Thread(
            target=_run, name="wpt-ftp-deadline", daemon=True)
        worker.start()
        try:
            yield expired
        finally:
            done.set()
            worker.join(timeout=1.0)

    def _deadline_expired(self, context: str) -> None:
        raise DeadlineExceeded(
            f"run deadline of {self.deadline._seconds:g}s exceeded at "
            f"{context!r} — the FTP operation was aborted and its sockets "
            "closed"
        )

    def _connect(self) -> ftplib.FTP_TLS:
        ftp = ftplib.FTP_TLS()
        # Set the context AFTER construction: ftplib reads ``self.context``
        # in auth(), and the bare constructor's CERT_NONE default is never
        # used.  (A test/embedder double that constructs without keyword
        # arguments keeps working.)
        ftp.context = self._tls_context()
        self._track_transfers(ftp)
        connect_timeout = self._budget_timeout(
            self.settings.timeout_s, "ftp connect")
        with self._deadline_watch(ftp, "ftp connect") as expired:
            try:
                if self.deadline is None or is_numeric_host(self.host):
                    addresses = [self.host]
                else:
                    try:
                        addresses = resolve_host_bounded(
                            self.host, self.settings.port,
                            self.deadline.at,
                            label="ftp host DNS resolution",
                            thread_name="wpt-ftp-dns")
                    except WptError:
                        self._check_budget("ftp connect")
                        raise
                connected = False
                last_error: BaseException | None = None
                left = len(addresses)
                for address in addresses:
                    remaining = connect_timeout
                    if self.deadline is not None:
                        remaining = self.deadline.remaining
                        if remaining <= 0:
                            break
                        remaining = max(0.001, min(connect_timeout,
                                                    remaining / max(1, left)))
                    left -= 1
                    try:
                        ftp.connect(address, self.settings.port,
                                    timeout=remaining)
                    except (OSError, ftplib.Error, EOFError,
                            UnicodeError, ValueError) as exc:
                        last_error = exc
                        try:
                            ftp.close()
                        except Exception:  # noqa: BLE001 — retry next
                            pass
                        continue
                    # TCP success is not a usable FTPS endpoint: AUTH/TLS
                    # can fail on the first resolved address (a stale
                    # listener that answers 220/234 then closes).  Attempt
                    # AUTH here, under the same per-address share, so the
                    # next address gets its chance; only a CERTIFICATE
                    # verification failure is permanent (retrying another
                    # address cannot fix a name/CA verdict).
                    ftp.host = self.host
                    try:
                        ftp.timeout = remaining
                        sock = getattr(ftp, "sock", None)
                        if sock is not None:
                            sock.settimeout(remaining)
                        ftp.auth()
                    except ssl.SSLCertVerificationError:
                        raise
                    except (OSError, ftplib.Error, EOFError,
                            UnicodeError, ValueError) as exc:
                        last_error = exc
                        try:
                            ftp.close()
                        except Exception:  # noqa: BLE001 — retry next
                            pass
                        continue
                    connected = True
                    break
                if not connected:
                    if self.deadline is not None \
                            and self.deadline.remaining <= 0:
                        self._deadline_expired("ftp connect")
                    if last_error is not None:
                        raise last_error
                    raise SourceError(
                        f"ftp host {self.host!r} resolved to no address")
                self._check_budget("ftp connect")
                self._check_budget("ftp auth")
                self._arm_socket(ftp, "ftp login")
                ftp.login(self.user, self.password)
                self._check_budget("ftp login")
                self._arm_socket(ftp, "ftp prot")
                ftp.prot_p()
                self._check_budget("ftp prot")
                self._arm_socket(ftp, "ftp pwd")
                try:
                    self._login_dir = ftp.pwd() or "/"
                except (ftplib.Error, OSError) as exc:
                    # Every later path is rooted at this directory.
                    # Guessing "/" would silently address another account's
                    # tree, so fail closed.
                    self._login_dir = None
                    raise SourceError(
                        f"ftp login directory could not be read ({exc}); "
                        "refusing to address paths against an unknown "
                        "working directory") from exc
            except BaseException:
                # A connection that authenticated/partially logged in still
                # owns a real control socket (and possibly a TLS layer).
                # Re-raising without close() left it to cyclic GC: four
                # failed logins were four live client fds (R19).  Close is
                # best-effort and must never replace the primary failure.
                try:
                    self._close_ftp_sockets(ftp)
                except BaseException:  # noqa: BLE001 — preserve primary
                    pass
                try:
                    ftp.close()
                except BaseException:  # noqa: BLE001 — preserve primary
                    pass
                if expired is not None and expired.is_set():
                    self._deadline_expired("ftp connect")
                raise
            if expired is not None and expired.is_set():
                self._deadline_expired("ftp connect")
        log.debug("connected to %s as %s", self.host, self.user)
        return ftp

    @property
    def ftp(self) -> ftplib.FTP_TLS:
        if self._ftp is None:
            self._ftp = self._connect()
        return self._ftp

    def _call(self, op: Callable[[ftplib.FTP_TLS], object]) -> object:
        """Run an FTP op with exactly one reconnect-retry on stale connections (L8).

        ``op`` receives the CURRENT connection (re-resolved after any reconnect) —
        never a bound method captured earlier.

        Consecutive-failure circuit breaker (the live lesson: on a flaky
        passive-channel host, long sessions leave every data connect in
        SYN-SENT for the full 45s timeout × retries, so a 16k-file operation
        crawled for HOURS one op at a time). An op that fails OUTRIGHT —
        exhausts its reconnect-retries, or raises a non-550 error_perm (a
        permission storm is equally unhealthy; the breaker message stays
        generic) — counts toward the breaker; once ``max_consecutive_failures``
        ops fail in a row (settings ftp.max_consecutive_failures, default 5
        until that field ships), the per-op error is REPLACED by one
        actionable "ftp channel unhealthy" SourceError. The count resets ONLY
        on a successful op — never on a reconnect (a fresh control connect
        proves nothing: the passive DATA channel is what dies) and not on the
        trip itself. The bound: threshold × (retries+1) × timeout_s —
        5 × 2 × 45s = 7.5 min worst case at defaults, minutes instead of hours.

        Slow-op window — the semi-degraded twin the breaker above cannot
        see (live-measured: every data connect stalls ~30-45s and then
        SUCCEEDS, so NO failure ever counts and a 16k-file bulk read still
        crawls at ~1 op/30s). Every completed op's wall duration
        (time.monotonic around the whole retry loop) is recorded in
        _note_op_duration; when the last _SLOW_WINDOW ops ALL exceeded
        _SLOW_RATIO × timeout_s, the channel is stalled and the op raises
        FtpChannelUnhealthy ("ftp channel degraded") — EVEN IF THE OP
        ITSELF SUCCEEDED. Any op under the threshold resets the window.
        Bound at defaults: 10 near-timeout ops ≈ minutes of observation
        instead of hours of crawl.
        """
        start = time.monotonic()
        attempts = self.settings.retries + 1
        for attempt in range(attempts):
            self._check_budget("ftp operation")
            expired = None
            try:
                ftp = self.ftp
                if self._ftp is not None:
                    self._arm_socket(self._ftp, "ftp operation")
                with self._deadline_watch(ftp, "ftp operation") as expired:
                    result = op(ftp)
                if expired is not None and expired.is_set():
                    self._deadline_expired("ftp operation")
                self._check_budget("ftp operation")
                self._consecutive_failures = 0   # one success proves the channel alive
                self._note_op_duration(time.monotonic() - start)
                return result
            except (DeadlineExceeded, StopRequested):
                self._reset()
                raise
            except (ftplib.Error, OSError, EOFError) as e:
                if (expired is not None and expired.is_set()) \
                        or (self.deadline is not None
                            and self.deadline.remaining <= 0):
                    self._reset()
                    self._deadline_expired("ftp operation")
                # ftplib.all_errors: error_reply/error_proto are ftplib.Error
                # (not OSError), and EOFError is the dropped control channel.
                # Every one of them must leave this connector as a SourceError
                # — a raw ftplib exception is neither WptError nor OSError and
                # would escape every command body as a traceback.
                # non-550 permission errors won't fix themselves on reconnect
                permanent = isinstance(e, ftplib.error_perm) and "550" not in str(e)
                if permanent or attempt + 1 >= attempts:
                    self._note_op_duration(time.monotonic() - start)
                    self._fail_op(e, permanent)
                log.debug("ftp op failed (%s); reconnecting once", e)
                self._reset()
            except (UnicodeError, ValueError) as e:
                if (expired is not None and expired.is_set()) \
                        or (self.deadline is not None
                            and self.deadline.remaining <= 0):
                    self._reset()
                    self._deadline_expired("ftp operation")
                # ftplib decodes replies strictly and int()s SIZE itself; a
                # non-ASCII reply or a CR/LF credential raises a raw
                # ValueError/UnicodeError from inside the command body.  The
                # session state is unknown (a reply line may be owed), so
                # reset and answer through the source contract.  Type-only
                # message: a decode error can carry reply text.
                self._reset()
                self._note_op_duration(time.monotonic() - start)
                raise SourceError(
                    f"ftp operation failed ({type(e).__name__}); the server "
                    "reply was not decodable as text"
                ) from None
        raise SourceError("unreachable")

    def _note_op_duration(self, duration: float) -> None:
        """Record one completed op's wall duration in the rolling slow-op
        window; raise FtpChannelUnhealthy when the last _SLOW_WINDOW ops
        were ALL near-timeout slow — the crawl the consecutive-failure
        breaker cannot see (ops succeed, just slowly).

        The single recording choke point — and the test seam: tests
        synthesize durations here instead of sleeping. A fast op resets
        the window naturally: with a maxlen-sized deque the last
        _SLOW_WINDOW entries can only be all-slow if the last
        _SLOW_WINDOW ops really were all slow (a fast op stays inside the
        window for the next _SLOW_WINDOW appends and blocks any trip).
        """
        self._op_durations.append(duration)
        threshold = self._SLOW_RATIO * self.settings.timeout_s
        if len(self._op_durations) < self._SLOW_WINDOW:
            return
        if any(d <= threshold for d in self._op_durations):
            return
        slowest = max(self._op_durations)
        log.warning("ftp channel degraded on %s as %s: last %d operations each "
                    "took >%gs (slowest %gs) — the passive channel is stalled; "
                    "aborting before hours of crawl",
                    self.host, self.user, self._SLOW_WINDOW, threshold, slowest)
        raise FtpChannelUnhealthy(
            f"ftp channel degraded: last {self._SLOW_WINDOW} operations each "
            f"took >{threshold:g}s (slowest {slowest:g}s) — the passive channel "
            "is stalled; aborting before hours of crawl"
        )

    def _fail_op(self, e: BaseException, permanent: bool) -> NoReturn:
        """An op failed outright (immediate non-550 error_perm, or retries
        exhausted): count it; at the threshold trip the breaker, else raise
        today's per-op error.

        ``permanent`` marks non-550 error_perm failures: below the threshold
        they re-raise RAW — delete()/rmdir_recursive() classify error_perm
        themselves. The breaker message is generic (last error quoted, never
        a password) so any failure storm reads the same.
        """
        self._consecutive_failures += 1
        if self._consecutive_failures >= getattr(self.settings,
                                                 "max_consecutive_failures", 5):
            log.warning("ftp channel unhealthy: %d consecutive failed operations "
                        "on %s as %s (last error: %s) — stopping; reconnect the "
                        "session or retry later",
                        self._consecutive_failures, self.host, self.user, e)
            raise FtpChannelUnhealthy(
                f"ftp channel unhealthy: {self._consecutive_failures} consecutive "
                f"failed operations ({e}); the passive data channel is stale — "
                "reconnect the session or retry the command later"
            ) from e
        if permanent:
            raise e
        raise SourceError(f"ftp operation failed after retry: {e}") from e

    def _reset(self) -> None:
        ftp, self._ftp = self._ftp, None
        if ftp is not None:
            if self.deadline is not None and self.deadline.remaining <= 0:
                # A graceful QUIT on an expired budget could block on the
                # control channel; close the sockets NOW instead.
                self._close_ftp_sockets(ftp)
                try:
                    ftp.close()
                except Exception:  # noqa: BLE001 — preserve the reset
                    pass
            else:
                # QUIT is a control-channel round-trip like every other
                # operation: a peer dripping the reply resets ftplib's
                # per-read timeout and outlives --deadline.  Run it under
                # the same absolute watchdog close() uses; expiry here is
                # TEARDOWN (the caller is already resetting/discarding the
                # session), so only a cooperative stop is re-raised.
                expired = None
                try:
                    with self._deadline_watch(ftp, "ftp reset") as expired:
                        try:
                            ftp.quit()
                        except (StopRequested, DeadlineExceeded):
                            raise
                        except Exception:  # noqa: BLE001 — best-effort
                            pass
                finally:
                    # ALWAYS close the wrapper, not only when the watchdog
                    # fired: a failed/refused QUIT (or a QUIT that raised)
                    # still owns the control socket, and _track_transfers
                    # holds a bound method on it until cyclic GC (R19).
                    if expired is not None and expired.is_set():
                        self._close_ftp_sockets(ftp)
                    try:
                        ftp.close()
                    except Exception:  # noqa: BLE001 — preserve the reset
                        pass
        # A retry pause is part of the budget: never sleep past it.  The
        # next attempt's check is the authoritative abort.
        delay = 0.1
        if self.deadline is not None:
            delay = min(delay, max(0.0, self.deadline.remaining))
        if delay > 0:
            time.sleep(delay)

    def _remote(self, path: str) -> str:
        """Map a webroot-relative path to an ABSOLUTE FTP path ('' -> root).

        ``login`` leaves the session in the account's home directory, and
        ``root`` is documented relative to it.  Joining them here — rather
        than emitting ``root/path`` relative to whatever CWD a probe last
        set — is what makes a STOR land in the webroot even if a server
        left the session elsewhere (R6-01).
        """
        p = self._guard_path(path) if path else ""
        relative = f"{self.root}/{p}" if self.root and p else (self.root or p)
        if self._login_dir is not None:
            return posixpath.join(self._login_dir, relative) if relative \
                else self._login_dir
        return relative

    # ------------------------------------------------------------------ reading

    def list_dir(self, path: str) -> list[Entry]:
        rel = self._guard_path(path) if path else ""

        def collect(f: ftplib.FTP_TLS) -> list[str]:
            # The SINK lives inside the retried callable: ``_call`` may
            # replay the op on a fresh connection, and a sink captured
            # outside it made attempt 2 APPEND to attempt 1's partial
            # listing (duplicate rows, P1-FTP-PARTIAL).
            lines: list[str] = []

            def append(line: str) -> None:
                lines.append(line)

            f.retrlines(f"LIST {self._remote(rel)}".strip(), append)
            return lines

        try:
            lines = self._call(collect)
        except UnicodeError as exc:
            # ftplib decodes every LIST line with ``FTP.encoding`` strictly;
            # one Latin-1 byte in a filename raises UnicodeDecodeError (a
            # ValueError, neither WptError nor OSError).  The data/control
            # stream is mid-transfer, so drop the session rather than reuse
            # a connection that may still owe a 226, and answer through the
            # normal source error contract.
            encoding = getattr(self._ftp, "encoding", "utf-8") or "utf-8"
            self._reset()
            raise SourceError(
                f"ftp listing for {rel or '/'} is not decodable as "
                f"{encoding}; refusing to guess filenames "
                f"({type(exc).__name__})"
            ) from exc
        except ftplib.error_perm as exc:
            # _call re-raises a non-550 error_perm raw (its MKD probe needs
            # to disambiguate that code).  A public READ must never hand a
            # command body a raw ftplib exception: it is neither WptError
            # nor OSError, so every command's never-raises contract would
            # miss it and leak a traceback.
            raise SourceError(
                f"ftp listing failed for {rel or '/'}: {exc}") from exc
        now = time.time()   # one clock for the whole listing's year inference
        entries: list[Entry] = []
        unparsed: list[str] = []
        for line in lines:
            if not self._usable(line):
                continue
            entry = self._parse_line(rel, line, now)
            if entry is not None:
                entries.append(entry)
            elif not _is_list_header(line):
                unparsed.append(line)
        if not entries and unparsed:
            # A non-Unix LIST dialect (IIS/MS-DOS, VMS, a localized server)
            # used to be skipped line by line at DEBUG: the caller saw an
            # EMPTY directory and a backup happily captured zero files.
            # Empty and unparseable are different answers; fail closed.
            raise SourceError(
                f"ftp listing for {rel or '/'} carried no parseable entry "
                f"(first line: {unparsed[0].strip()!r}); refusing to treat "
                "an unparseable listing as an empty directory"
            )
        return entries

    @staticmethod
    def _list_name(line: str) -> str | None:
        """The LIST line's NAME field, exactly as :meth:`_parse_line` reads it.

        ONE owner for the name arithmetic: the dot-entry filter must never
        guess from ``line.split()[-1]`` (a legal filename may end in ``..``
        or `` ``), while the parser must not re-derive a different name.
        Returns None when the line has no Unix LIST name at all (a header,
        a non-Unix dialect, a short/garbled line); the caller decides
        whether that is an empty answer or a fail-closed unparsed line.
        """
        if not line.strip():
            return None
        spans = [(m.start(), m.end()) for m in re.finditer(r"\S+", line)]
        if len(spans) < 9 or spans[7][1] >= len(line) \
                or not line[spans[7][1]].isspace():
            return None
        name = line[spans[7][1] + 1:]
        if not name:
            return None
        perms = line[:spans[0][1]]
        if perms.startswith("l") and " -> " in name:
            name = name.split(" -> ", 1)[0]
        return name

    @staticmethod
    def _usable(line: str) -> bool:
        # Only the EXACT NAME "." / ".." is a dot entry.  Deriving it with
        # ``line.split()[-1]`` dropped legal names such as ``uploads ..``
        # (and hid their whole subtree from every walk/backup).  An
        # unparseable line stays usable so list_dir's unparsed guard can
        # fail closed instead of treating it as an empty directory.
        if not line.strip():
            return False
        name = FtpSource._list_name(line)
        if name is None:
            return True
        return name not in (".", "..")

    def _parse_line(self, parent: str, line: str,
                    now: float | None = None) -> Entry | None:
        """One Unix LIST line -> Entry, or None when the line is not one.

        The listing's "total N" header and any short/garbled line are
        skipped with a debug line, never fatal: one extra server line must
        not take an entire audit down.  ``mode``/``owner``/``group`` come
        from the permission word, ``mtime`` from the date columns through
        :func:`_parse_list_mtime` (``now`` is the listing's clock, passed
        once by list_dir and explicitly by tests).
        """
        fields = line.split(None, 8)
        if len(fields) < 9:
            log.debug("skipping unparseable LIST line: %r", line)
            return None
        # The NAME is the raw remainder after the single separator that
        # follows the date/year column.  ``split(None, 8)`` collapses runs,
        # which silently rewrote a legal leading-space name
        # (" secret.php") into a different path the audit then read.
        name = self._list_name(line)
        if name is None:
            log.debug("skipping unparseable LIST line: %r", line)
            return None
        perms = fields[0]
        mode = _parse_list_mode(perms)
        if mode is None:
            log.debug("skipping unparseable LIST line: %r", line)
            return None
        is_link = perms.startswith("l")
        is_dir = perms.startswith("d") or is_link
        try:
            size = int(fields[4])
        except ValueError:
            # A non-Unix LIST dialect can put a human size ("123M") in the
            # size column.  Fabricating 0 made every size gate believe the
            # file was empty; SIZE_UNKNOWN says "not verifiable" so gates
            # skip it and every read still goes through a hard bound.
            size = SIZE_UNKNOWN
        mtime = _parse_list_mtime(fields[5], fields[6], fields[7],
                                  time.time() if now is None else now)
        return Entry(path=self._join(parent, name), is_dir=is_dir, size=size,
                     is_link=is_link, mode=mode, mtime=mtime,
                     owner=fields[2], group=fields[3])

    def read_bytes(self, path: str) -> bytes:
        return self._read(path, None)

    def read_bytes_bounded(self, path: str, max_bytes: int) -> bytes:
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) \
                or max_bytes < 0:
            raise SourceError(f"invalid read bound: {max_bytes!r}")
        return self._read(path, max_bytes)

    def _read(self, path: str, limit: int | None) -> bytes:
        self._guard_path(path)

        def retrieve(f: ftplib.FTP_TLS) -> bytes:
            # Fresh sink per ATTEMPT: ``_call`` reconnects and replays the
            # op, and a buffer captured outside it concatenated a partial
            # first attempt with the full second one (P1-FTP-PARTIAL).
            buf = io.BytesIO()

            def write(data: bytes) -> None:
                if limit is not None and buf.tell() + len(data) > limit:
                    # Stop the transfer at the first byte past the bound; the
                    # caller never holds the unbounded body.
                    raise _ReadLimitExceeded
                buf.write(data)

            f.retrbinary(f"RETR {self._remote(path)}", write)
            return buf.getvalue()

        try:
            return self._call(retrieve)
        except _ReadLimitExceeded:
            # The data connection is mid-transfer and the control channel
            # still owes its 226; dropping the session is the only safe
            # state to continue from.
            self._reset()
            raise SourceError(
                f"{path!r} is larger than the {limit}-byte read bound"
            ) from None
        except ftplib.error_perm as exc:
            raise SourceError(
                f"ftp read failed for {path}: {exc}") from exc

    def read_many(self, paths: list[str], *, max_bytes: int | None = None
                  ) -> tuple[dict[str, bytes], dict[str, str]]:
        """Parallel bulk read through dedicated worker sessions.

        Live numbers (measured on the production host): a semi-degraded
        passive channel stalls every data connect ~30-45s before it
        SUCCEEDS, so the inherited serial default moves at ~1 op/30s — a
        16k-file backup would crawl for ~13 hours. N workers (settings
        ftp.parallel_reads, default 4; 1 = the SAME machinery with one
        worker, serial — never special-cased) read disjoint round-robin
        chunks of ``paths`` concurrently, so throughput is ≈ N×: ~4
        ops/30s. One DEDICATED session per worker because ftplib
        connections are NOT thread-safe: each worker is an FtpSource twin
        of ``self`` (same host/user/password/root/settings) whose control
        session connects lazily on first use and is closed when the batch
        ends. A stalled channel is still bounded per worker by the
        slow-op window in _call (~10 near-timeout ops, minutes).

        Per-path (SourceError, OSError) — including a worker's OWN
        FtpChannelUnhealthy (its consecutive-failure breaker or slow-op
        window tripped; the worker session is left in its breaker state,
        never reset) — land in ``failed`` exactly like the inherited
        contract. When a worker's channel dies mid-chunk, the unread
        REMAINDER of its chunk is marked failed with that same verdict:
        re-reading would burn another near-timeout op per path for the
        same answer.

        RUN-LEVEL verdict: if EVERY requested path failed AND at least one
        failure string carries the channel-unhealthy signature ("ftp
        channel unhealthy"), the batch re-raises FtpChannelUnhealthy — a
        bulk read that got nothing on a dead channel is a channel
        failure, not 5000 per-path failures. Mixed/partial results
        return normally.
        """
        ok: dict[str, bytes] = {}
        failed: dict[str, str] = {}
        workers: list[FtpSource] = []
        n = self.settings.parallel_reads
        chunks = [paths[i::n] for i in range(min(n, len(paths)))]

        def read_chunk(chunk: list[str]) -> tuple[dict[str, bytes], dict[str, str]]:
            worker = FtpSource(self.host, self.user, self.password, self.root,
                               self.settings, deadline=self.deadline,
                               cleanup_deadline_s=self.cleanup_deadline_s)
            workers.append(worker)
            ok_c: dict[str, bytes] = {}
            failed_c: dict[str, str] = {}
            for i, path in enumerate(chunk):
                try:
                    if max_bytes is None:
                        ok_c[path] = worker.read_bytes(path)
                    else:
                        # Bound BEFORE materializing: a listing that lied
                        # about the size stops at max_bytes + 1.
                        ok_c[path] = worker.read_bytes_bounded(
                            path, max_bytes)
                except FtpChannelUnhealthy as e:
                    for rest in chunk[i:]:   # the unread remainder inherits the verdict
                        failed_c[rest] = str(e)
                    break
                except (SourceError, OSError) as e:
                    failed_c[path] = str(e)
            return ok_c, failed_c

        pool = ThreadPoolExecutor(max_workers=n)
        try:
            for ok_c, failed_c in pool.map(read_chunk, chunks):
                ok.update(ok_c)
                failed.update(failed_c)
        finally:
            pool.shutdown(wait=True)
            for worker in workers:
                worker.close()
        # RUN-LEVEL verdict: if EVERY requested path failed AND at least
        # one failure string carries a CHANNEL signature, the batch
        # re-raises FtpChannelUnhealthy — a bulk read that got nothing on
        # a dead channel is a channel failure, not 5000 per-path
        # failures. BOTH trip messages count ("unhealthy" = the
        # consecutive-failure breaker, "degraded" = the slow-op window):
        # with a non-default ftp.max_consecutive_failures > _SLOW_WINDOW
        # a slow-window death could otherwise be delivered as a pile of
        # per-path failures. Mixed/partial results return normally.
        _CHANNEL_SIGNS = ("ftp channel unhealthy", "ftp channel degraded")
        if paths and not ok and any(sign in m for sign in _CHANNEL_SIGNS
                                    for m in failed.values()):
            detail = next(m for m in failed.values()
                          if any(sign in m for sign in _CHANNEL_SIGNS))
            raise FtpChannelUnhealthy(
                f"ftp channel unhealthy: bulk read of {len(paths)} paths got "
                f"nothing (every path failed; a worker session reported: {detail})"
            )
        return ok, failed

    def exists(self, path: str) -> bool:
        try:
            self.size(path)
            return True
        except FtpChannelUnhealthy:
            raise  # an unhealthy channel has no truthful exists() answer
        except SourceLookupError:
            raise  # a failed lookup proves nothing about absence
        except SourceError:
            return False

    def size(self, path: str) -> int:
        rel = self._guard_path(path)
        try:
            size = self._call(lambda f: f.size(self._remote(rel)))
            return int(size)
        except FtpChannelUnhealthy:
            raise  # never masked as "no such file"
        except (SourceError, ftplib.error_perm, ftplib.error_temp) as size_exc:
            # maybe a directory: fall back to the parent listing
            parent = rel.rpartition("/")[0]
            try:
                for entry in self.list_dir(parent):
                    if entry.path.casefold() == rel.casefold():
                        return entry.size
            except FtpChannelUnhealthy:
                raise  # the fallback channel died too — not a missing file
            except (SourceError, OSError) as list_exc:
                # SIZE failed AND the witness listing failed: absence is
                # UNPROVEN.  Saying "no such file" here is what let a backup
                # record a present file as absent and an edit overwrite it.
                raise SourceLookupError(
                    f"cannot determine whether {rel!r} exists: SIZE failed "
                    f"({size_exc}) and the parent listing failed ({list_exc})"
                ) from list_exc
            raise SourceError(f"no such file: {rel}")

    # ---------------------------------------------------------------- mutations

    def ensure_write_dir(self, path: str) -> None:
        """Make the parent chain of ``path`` exist before anything is STORed.

        WHY THIS EXISTS.  ``STOR`` addresses a file by name INSIDE a
        directory the server already has: writing into a directory that
        does not exist answers ``553 Can't open that file`` and the file
        is never created.  A local or zip-backed source creates its
        intermediate directories as a matter of course, so nothing on that
        path ever noticed — and then a live ``update-core --apply`` staged
        each replacement core tree BESIDE the installed one
        (``wp-includes.wpt-new/``), and its very first upload died on a
        directory the session had never made.  The guarantee is on the
        Source contract, not on that caller, so every remote writer
        inherits it: the bridge deployment, a restore into a re-created
        uploads directory, a backup payload parked back into the webroot.

        THE CHOICE: the work is done once per directory per SESSION, not
        once per file, and a directory this source has already proven
        exists is not re-checked.  The alternative — probe the parent
        before every single write — is what a per-file ``mkdir -p`` costs
        on a 3,000-file core tree, and on the degraded production host
        every passive DATA connect stalls 30-45s (see the module's two
        channel bounds): thousands of probes turn an apply into hours.
        The memo cannot mask a refusal, because a 550 from MKD is never
        read as "it exists": it is DISAMBIGUATED by an independent probe
        (see _remote_dir_exists) and a directory that is not there is a
        one-line SourceError.  The memo is dropped wholesale by a rename
        and per-path by a recursive remove, so a name this session moved
        or deleted is never assumed present afterwards.

        A path at the webroot ROOT has no parent to make: the webroot is
        the thing the account is already standing in, and it is never
        MKD-ed (a server that let wpt create its own webroot would be
        writing outside the site).
        """
        parent = posixpath.dirname(self._guard_path(path))
        if not parent:
            return
        parts = parent.split("/")
        for depth in range(1, len(parts) + 1):
            rel = "/".join(parts[:depth])
            if rel in self._known_dirs:
                continue
            self._mkdir(self._remote(rel), rel)
            self._known_dirs.add(rel)

    def _mkdir(self, remote: str, rel: str) -> None:
        """One MKD, then PROVE the outcome.

        A 5xx MKD is ambiguous on the wire — "already exists" and
        "permission denied" and "no such parent" are all 550 on real
        servers — so the answer is never taken from the code alone: a
        refused MKD is followed by an independent existence probe, and
        only a directory the probe cannot find is a failure.  That is
        what keeps an existing directory writable (the common case: the
        refusal is precisely the good news) without ever mistaking a real
        refusal for one.
        """
        if self._try_mkd(remote):
            return
        raise SourceError(
            f"cannot write into {rel!r}: the ftp server refused to create "
            f"the directory ({remote}) and the directory is not there — "
            f"nothing was written"
        )

    def _try_mkd(self, remote: str) -> bool:
        """MKD one directory; True when it exists afterwards.

        The probe is a CWD, not a SIZE or a LIST, and that is a measured
        choice rather than a preference: CWD is a CONTROL-channel
        operation (two round trips, no data connection), while the
        existence answer this connector already has — ``size()`` — falls
        back to a parent LIST, i.e. exactly the passive data connect that
        stalls for 30-45s on a degraded host, and it cannot tell a
        directory from a file.
        """
        try:
            self._call(lambda f: f.mkd(remote))
            return True
        except FtpChannelUnhealthy:
            raise   # a dead channel has no verdict about this directory
        except (SourceError, ftplib.error_perm) as exc:
            # everything _call does not convert to a SourceError is a
            # permanent 5xx, which it re-raises raw by design
            log.debug("ftp MKD %s refused (%s); probing the directory",
                      remote, exc)
        return self._remote_dir_exists(remote)

    def _remote_dir_exists(self, remote: str) -> bool:
        """True when the server lets the session INTO ``remote`` (CWD).

        CWD moves the SERVER's working directory even though ftplib keeps
        no state of its own.  The session's ABSOLUTE directory is captured
        before the probe and restored afterwards for EVERY root (a rooted
        source sent relative paths before R6-01, so a probe could leave the
        session inside the probed directory and the next STOR resolved the
        whole webroot prefix a second time).  A session that cannot be
        handed back is a refusal: continuing would resolve the caller's
        remaining paths against a directory this probe chose.
        """
        try:
            original = self._call(lambda f: f.pwd())
        except FtpChannelUnhealthy:
            raise
        except (SourceError, ftplib.error_perm) as exc:
            raise SourceError(
                f"the ftp session's working directory could not be read "
                f"before probing {remote} ({exc}) — refusing to write "
                "through a session whose working directory is unknown"
            ) from exc
        probed = False
        try:
            self._call(lambda f: f.cwd(remote))
            probed = True
        except FtpChannelUnhealthy:
            raise
        except (SourceError, ftplib.error_perm):
            # A failed CWD normally leaves the session where it was, but
            # not every server guarantees that; restore unconditionally.
            pass
        finally:
            try:
                self._call(lambda f: f.cwd(original))
            except (SourceError, ftplib.error_perm) as exc:
                raise SourceError(
                    f"the ftp session could not be returned to {original!r} "
                    f"after probing {remote} ({exc}) — refusing to write "
                    "through a session whose working directory is unknown"
                ) from exc
        return probed

    def write_bytes(self, path: str, data: bytes, *, allow_config: bool = False,
                    allow_core: bool = False) -> None:
        self._check_writable(path, allow_config, allow_core)
        self.ensure_write_dir(path)
        rel = self._guard_path(path)
        try:
            self._call(lambda f: f.storbinary(f"STOR {self._remote(rel)}",
                                              io.BytesIO(data)))
        except ftplib.error_perm as exc:
            # A 5xx is re-raised RAW by _call (only 550s are retried), and a
            # raw ftplib exception is not a WptError — it escapes every
            # command body's (WptError, OSError) contract as a traceback
            # whose text is a bare server string. The write path is the ONE
            # place that must never hand an operator "553 Can't open that
            # file" instead of a sentence.
            raise SourceError(
                f"cannot write {rel}: the ftp server refused the upload "
                f"({exc})"
            ) from exc

    def delete(self, path: str, *, allow_config: bool = False,
               allow_core: bool = False) -> None:
        self._check_deletable(path, allow_config, allow_core)
        try:
            self._call(lambda f: f.delete(self._remote(path)))
        except ftplib.error_perm as e:
            if "550" in str(e):
                raise SourceError(f"no such file: {path}") from e
            raise SourceError(f"delete failed on {path}: {e}") from e

    def rmdir(self, path: str) -> None:
        """RMD one empty directory; a 550 (non-empty) is a SourceError."""
        self._check_deletable(path)
        rel = self._guard_path(path)
        try:
            self._call(lambda f: f.rmd(self._remote(rel)))
        except ftplib.error_perm as e:
            raise SourceError(f"rmdir failed on {path}: {e}") from e
        self._known_dirs.discard(rel)

    def rmdir_recursive(self, path: str) -> None:
        self._check_deletable(path)
        rel = self._guard_path(path)
        # A Unix FTP ``LIST link-to-dir`` FOLLOWS the link (the L10
        # recording), so walking the caller's root descended into the
        # target and deleted its files.  The PARENT listing is the only
        # place the root's own identity is visible: delete the link name
        # itself and never descend.
        parent = posixpath.dirname(rel)
        try:
            siblings = self.list_dir(parent)
        except SourceError:
            raise
        root_entry = next((entry for entry in siblings if entry.path == rel),
                          None)
        if root_entry is None:
            raise SourceError(f"no such directory: {path}")
        if root_entry.is_link:
            self._known_dirs = {
                directory for directory in self._known_dirs
                if directory != rel and not directory.startswith(rel + "/")
            }
            self.delete(rel)
            return
        # Drop the subtree, not just the exact name: every descendant was
        # proven present by this session, and a later write into a
        # re-created descendant must MKD again instead of trusting the
        # memo (a STOR into the missing parent answers 553).
        self._known_dirs = {
            directory for directory in self._known_dirs
            if directory != rel and not directory.startswith(rel + "/")
        }
        # include_links: a symlink is a NAME in this tree and must be DELEted
        # before RMD, or the directory stays non-empty and a half-deleted
        # target is left behind.  walk never descends into a link, so this
        # sees the link itself and nothing behind it.
        entries = list(self.walk(path, include_links=True))
        files = [e for e in entries if not e.is_dir or e.is_link]
        dirs = [e for e in entries if e.is_dir and not e.is_link]
        dirs.append(Entry(path=self._guard_path(path), is_dir=True, size=0))
        for entry in files:
            self.delete(entry.path)
        # deepest-first so children vanish before their parents
        for entry in sorted(dirs, key=lambda e: e.path.count("/"), reverse=True):
            try:
                self._call(lambda f: f.rmd(self._remote(entry.path)))
            except ftplib.error_perm as e:
                raise SourceError(f"rmdir failed on {entry.path}: {e}") from e

    def rename(self, src: str, dst: str, *, allow_config: bool = False,
               allow_core: bool = False) -> None:
        """RNFR/RNTO: rename a webroot-relative file OR directory.

        The update-core tree swap's primitive: staging a whole release
        tree beside the installed one and swapping the two in place is
        exactly one FTP rename, so an interrupted update can never leave
        ``wp-includes/`` holding half of two releases.  Both paths go
        through ``_guard_path``; the DESTINATION through
        ``_check_rename_target`` (a rename lands bytes there) and the
        SOURCE through ``_check_rename_source`` (moving a protected name
        away is a delete by another name).  A 550 (no such file / no such
        directory) is reported as a :class:`SourceError` naming the path,
        the same mapping ``delete`` applies.

        The source-level ``rename`` default (wpt/types.py) is what a
        connector without RNTO inherits; this override is the real one.

        A rename MOVES names, so the session's directory memo is dropped
        wholesale: after ``wp-includes.wpt-new -> wp-includes`` every
        proven name under the staged tree describes a path that no longer
        exists, and a memo that outlived the move would let a later write
        skip the create it needs.  The cost is one extra MKD per directory
        written after a rename, which is nothing next to guessing.
        """
        self._check_rename_source(src, allow_config, allow_core)
        self._check_rename_target(dst, allow_config, allow_core)
        rel_src = self._guard_path(src)
        rel_dst = self._guard_path(dst)
        self._known_dirs = {""}
        try:
            self._call(lambda f: f.rename(self._remote(rel_src),
                                          self._remote(rel_dst)))
        except ftplib.error_perm as e:
            if "550" in str(e):
                raise SourceError(f"no such file: {rel_src}") from e
            raise SourceError(f"rename failed: {rel_src} -> {rel_dst}: "
                              f"{e}") from e

    def close(self) -> None:
        if self._ftp is not None:
            ftp = self._ftp
            # Clear the reference FIRST: a cooperative stop raised by quit()
            # must still leave this source retired, never reusable.
            self._ftp = None
            if self.deadline is not None and self.deadline.remaining <= 0:
                # The same rule _reset keeps: a graceful QUIT on an expired
                # budget could block on the control channel, so close the
                # sockets NOW instead.
                self._close_ftp_sockets(ftp)
                try:
                    ftp.close()
                except Exception:  # noqa: BLE001 — best-effort teardown
                    pass
                return
            # A dripped QUIT reply must not outlive the run budget: the
            # watchdog closes the control socket at Deadline.at, which
            # unblocks ftplib's getresp.  Expiry here is TEARDOWN, not a
            # verdict: the run's own stop/deadline was already answered by
            # the in-flight operation, so close() stays quiet.
            expired = None
            try:
                with self._deadline_watch(ftp, "ftp close") as expired:
                    try:
                        ftp.quit()
                    except (StopRequested, DeadlineExceeded):
                        raise
                    except Exception:  # noqa: BLE001 — best-effort teardown
                        pass
            finally:
                # A QUIT that failed (or raised) still owns the control
                # socket: close the wrapper unconditionally.  ftplib.close
                # is idempotent, so a successful QUIT keeps costing one
                # no-op call.
                if expired is not None and expired.is_set():
                    self._close_ftp_sockets(ftp)
                try:
                    ftp.close()
                except Exception:  # noqa: BLE001 — preserve teardown
                    pass
