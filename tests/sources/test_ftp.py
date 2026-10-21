"""FtpSource tests over a fake ftplib.FTP_TLS (in-memory FS, no network).

The fake models reality: each _connect() produces a NEW connection object sharing
the same server state; a connection that has QUIT refuses further ops (421).
retrlines can be scripted to fail N times (stale-channel storm) or to raise
non-550 permission errors (breaker counting).

The WRITE side is modelled as strictly as the read side, because that is
where a real server's rules live and where a connector's bug hides: STOR
into a directory the store does not have answers 553 (the live failure
this file's ``ensure_write_dir`` section exists for), MKD on an existing
directory answers 550, CWD into anything but a directory answers 550, and
STOR stores the bytes it was handed so a read-back is a real round trip.

Thread-ready for read_many's parallel worker sessions: the shared state's only
mutations are dict/list/set item appends and counter decrements, which are
GIL-atomic, so any number of connections may talk to one FakeFTPServer at once.
Per-path RETR failure scripting (fail_first_retr attempt counter, fail_retr_paths
set) is membership-based where tests need worker-deterministic behavior.
"""

import ftplib
import logging
import posixpath
import socket
import ssl
from datetime import datetime, timezone

import pytest

from wpt.settings import FtpSettings
from wpt.sources.base import WalkMixin
from wpt.sources.ftp import FtpSource
from wpt.types import (Entry, FtpChannelUnhealthy, NotWritableError,
                       Source, SourceError, SourceLookupError)


class FakeFTPServer:
    """Shared server state + factory: each connection is a fresh FakeFTP."""

    def __init__(self, fs=None, fail_first_retrlines=0, perm_first_retrlines=0,
                 fail_first_size=0, perm_first_delete=0, contents=None,
                 fail_first_retr=0, fail_retr_paths=(), deny_mkd=(),
                 fail_stor_paths=(), fail_rename=(), listing_extra=(),
                 partial_first_retr=b"", partial_retrlines_after=0):
        self.state = {
            "fs": dict(fs or {}),       # path -> False(file) | True(dir)
            "calls": [],
            "fail": fail_first_retrlines,
            "perm": perm_first_retrlines,
            "fail_size": fail_first_size,
            "perm_delete": perm_first_delete,
            "contents": dict(contents or {}),  # path -> bytes (default CONTENT)
            "fail_retr": fail_first_retr,      # first-N RETR attempts fail 421
            "fail_retr_paths": set(fail_retr_paths),  # these paths always 421
            "fail_mkd": set(deny_mkd),    # MKD here always answers 550
            "fail_stor_paths": set(fail_stor_paths),  # STOR here answers 553
            "fail_rename": set(fail_rename),  # RNFR/RNTO from these paths: 550
            # Raw LIST lines a test injects around the real entries (the
            # "total N" header, a malformed line, ...).
            "listing_extra": tuple(listing_extra),
            # P1-FTP-PARTIAL: deliver a prefix, then fail the transfer so
            # _call's reconnect-retry replays the op into a fresh sink.
            "partial_first_retr": partial_first_retr,
            "partial_retrlines_after": partial_retrlines_after,
        }

    def new_connection(self):
        return FakeFTP(self.state)


class FakeFTP:
    def __init__(self, state):
        self.s = state
        self.dead = False
        #: The server-side working directory this connection is standing in.
        #: A real FTP server resolves a relative command against it; the
        #: fake models that so a probe that forgets to hand the session back
        #: cannot pass (R6-01).
        self.wd = "/"

    def _live(self):
        if self.dead:
            raise ftplib.error_temp("421 connection closed")

    @staticmethod
    def _norm(path):
        return path.strip().strip("/")

    def _resolve(self, path):
        if path.startswith("/"):
            return path
        return posixpath.join(self.wd, path)

    def pwd(self):
        self._live()
        self.s["calls"].append(("pwd",))
        return self.wd

    def connect(self, host, port=21, timeout=-1):
        self.s["calls"].append(("connect", host))

    def auth(self):
        self._live()
        self.s["calls"].append(("auth",))

    def login(self, user, pwd):
        self._live()
        self.s["calls"].append(("login", user))
        assert pwd == "secret"

    def prot_p(self):
        self._live()
        self.s["calls"].append(("prot_p",))

    def quit(self):
        self.s["calls"].append(("quit",))
        self.dead = True

    def retrlines(self, cmd, callback):
        self._live()
        self.s["calls"].append(("retrlines", cmd))
        if self.s["perm"] > 0:
            self.s["perm"] -= 1
            raise ftplib.error_perm("553 permission denied")
        if self.s["fail"] > 0:
            self.s["fail"] -= 1
            raise ftplib.error_temp("421 stale control connection")
        _, _, arg = cmd.partition(" ")
        base = self._norm(arg)
        exists = (
            not base
            or self.s["fs"].get(base) is True
            or any(name.startswith(base + "/") for name in self.s["fs"])
        )
        if not exists:
            # A real FTP server answers 550 for LIST of a missing directory
            # (the webroot root itself is implicit here).  An empty listing
            # for a missing parent is what let a lookup failure look like a
            # missing file (R7-P1-03).
            raise ftplib.error_perm("550 No such file or directory")
        for name in sorted(self.s["fs"]):
            parent = name.rsplit("/", 1)[0] if "/" in name else ""
            if parent == base:
                is_dir = self.s["fs"][name]
                size = 1024 if is_dir else 500
                perms = "drwxr-xr-x" if is_dir else "-rw-r--r--"
                callback(f"{perms} 1 u g {size} Sep 14 12:00 {name.rsplit('/', 1)[-1]}")
        if self.s["partial_retrlines_after"]:
            # Deliver a prefix of a scripted listing, then fail: the retry
            # must build a FRESH line list rather than append (P1-FTP).
            callback("-rw-r--r-- 1 u g 10 Sep 14 12:00 partial-one.txt")
            self.s["partial_retrlines_after"] = 0
            raise ftplib.error_temp("421 stale control connection")
        for line in self.s["listing_extra"]:
            callback(line)

    def retrbinary(self, cmd, callback, rest=None):
        self._live()
        _, _, arg = cmd.partition(" ")
        key = self._norm(self._resolve(arg))
        if key in self.s["fail_retr_paths"]:
            raise ftplib.error_temp("421 stale control connection")
        if self.s["fail_retr"] > 0:
            self.s["fail_retr"] -= 1
            raise ftplib.error_temp("421 stale control connection")
        if key not in self.s["fs"] or self.s["fs"][key] is True:
            raise ftplib.error_perm("550 no such file")
        if self.s["partial_first_retr"]:
            prefix = self.s["partial_first_retr"]
            self.s["partial_first_retr"] = b""
            callback(prefix)
            raise ftplib.error_temp("421 stale control connection")
        callback(self.s["contents"].get(key, b"CONTENT"))

    def storbinary(self, cmd, fh):
        """STOR: the parent directory must EXIST (a real server's rule —
        the 553 a live update-core apply died on), and the bytes handed
        over are kept so a later RETR is a real round trip."""
        self._live()
        _, _, arg = cmd.partition(" ")
        key = self._norm(self._resolve(arg))
        self.s["calls"].append(("stor", key))
        if key in self.s["fail_stor_paths"]:
            raise ftplib.error_perm("553 Can't open that file: refused")
        parent = key.rsplit("/", 1)[0] if "/" in key else ""
        if parent not in self.s["fs"] or self.s["fs"][parent] is not True:
            raise ftplib.error_perm(
                "553 Can't open that file: No such file or directory")
        self.s["fs"][key] = False
        self.s["contents"][key] = fh.read()

    def mkd(self, path):
        """MKD: creates a directory; 550 when it is already there (which is
        also how most servers answer a permission problem — the connector
        must disambiguate the code with its own probe, not read it)."""
        self._live()
        key = self._norm(self._resolve(path))
        self.s["calls"].append(("mkd", key))
        if key in self.s["fail_mkd"]:
            raise ftplib.error_perm("550 Permission denied")
        if key in self.s["fs"]:
            raise ftplib.error_perm("550 Can't create directory: File exists")
        self.s["fs"][key] = True

    def cwd(self, path):
        """CWD: 250 into a directory in the store, 550 for anything else —
        the control-channel existence probe (a file answers 550 too, which
        is why it is a directory probe and not a path probe)."""
        self._live()
        key = self._norm(self._resolve(path))
        self.s["calls"].append(("cwd", key))
        if key == "":
            self.wd = "/"
            return
        if self.s["fs"].get(key) is not True:
            raise ftplib.error_perm("550 No such directory")
        self.wd = "/" + key

    def delete(self, path):
        self._live()
        key = self._norm(path)
        if self.s["perm_delete"] > 0:
            self.s["perm_delete"] -= 1
            raise ftplib.error_perm("553 permission denied")
        if key not in self.s["fs"] or self.s["fs"][key] is True:
            raise ftplib.error_perm("550 no such file")
        del self.s["fs"][key]
        self.s["calls"].append(("delete", key))

    def rmd(self, path):
        self._live()
        key = self._norm(path)
        if key not in self.s["fs"] or self.s["fs"][key] is not True:
            raise ftplib.error_perm("550 not a directory")
        del self.s["fs"][key]
        self.s["calls"].append(("rmd", key))

    def size(self, path):
        self._live()
        key = self._norm(path)
        if self.s["fail_size"] > 0:
            self.s["fail_size"] -= 1
            raise ftplib.error_temp("421 stale control connection")
        if key not in self.s["fs"] or self.s["fs"][key] is True:
            raise ftplib.error_perm("550 no such file")
        return 500

    def rename(self, src, dst):
        """RNFR/RNTO: a directory moves with its whole subtree, exactly as
        the update-core tree swap needs it to."""
        self._live()
        from_key, to_key = self._norm(src), self._norm(dst)
        if from_key in self.s["fail_rename"]:
            raise ftplib.error_perm("550 No such file or directory")
        if from_key not in self.s["fs"]:
            raise ftplib.error_perm("550 no such file or directory")
        moved = [k for k in self.s["fs"]
                 if k == from_key or k.startswith(from_key + "/")]
        is_dir = self.s["fs"][from_key]
        for key in moved:
            target = to_key + key[len(from_key):]
            self.s["fs"][target] = self.s["fs"].pop(key)
            # the bytes move with the name: a rename is not a copy, and a
            # store that kept them behind would answer every read-back of
            # a swapped tree with the pre-rename content
            if key in self.s["contents"]:
                self.s["contents"][target] = self.s["contents"].pop(key)
        self.s["fs"][to_key] = is_dir
        self.s["calls"].append(("rename", from_key, to_key))


FS = {
    # the webroot itself is a directory on the server too: a STOR at the
    # root is a write INTO it, and the fake enforces the real rule
    "site/public_html": True,
    "site/public_html/wp-config.php": False,
    "site/public_html/wp-content": True,
    "site/public_html/wp-content/uploads": True,
    "site/public_html/wp-content/uploads/2018": True,
    "site/public_html/wp-content/uploads/2018/03": True,
    "site/public_html/wp-content/uploads/2018/03/a.png": False,
    "site/public_html/private_html": True,
}


@pytest.fixture()
def server(monkeypatch):
    made = []

    def factory(fs=FS, fail_first_retrlines=0, perm_first_retrlines=0,
                fail_first_size=0, perm_first_delete=0, contents=None,
                fail_first_retr=0, fail_retr_paths=(), deny_mkd=(),
                fail_stor_paths=(), fail_rename=(), listing_extra=(),
                partial_first_retr=b"", partial_retrlines_after=0):
        srv = FakeFTPServer(fs, fail_first_retrlines, perm_first_retrlines,
                            fail_first_size, perm_first_delete, contents,
                            fail_first_retr, fail_retr_paths, deny_mkd,
                            fail_stor_paths, fail_rename, listing_extra,
                            partial_first_retr, partial_retrlines_after)
        made.append(srv)
        monkeypatch.setattr("wpt.sources.ftp.ftplib.FTP_TLS", srv.new_connection)
        return srv

    yield factory


@pytest.fixture()
def wpt_caplog(caplog):
    """caplog wired to the non-propagating wpt logger tree (caplog alone
    cannot see wpt.* records — the wpt parent does not propagate)."""
    parent = logging.getLogger("wpt")
    parent.addHandler(caplog.handler)
    with caplog.at_level(logging.DEBUG, logger="wpt"):
        yield caplog
    parent.removeHandler(caplog.handler)


def make_src():
    return FtpSource("host", "user", "secret", root="site/public_html",
                     settings=FtpSettings(timeout_s=5, retries=1))


def test_C2_connect_and_socket_timeout_are_capped_at_the_run_budget(
        monkeypatch):
    """C2: FTP used only settings.timeout_s, so a silent banner outlived
    --deadline (2.2 s at ftp.timeout_s=1, ~90 s at the default).  The connect
    must receive min(timeout_s, remaining) and an expired budget must never
    open a socket."""
    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    calls: list[float | None] = []

    class _FakeFTP:
        def __init__(self):
            self.sock = None
            self.timeout = None

        def connect(self, host, port, timeout=None):
            calls.append(timeout)

        def auth(self):
            pass

        def login(self, user, password):
            pass

        def prot_p(self):
            pass

        def pwd(self):
            return "/"

        def quit(self):
            pass

    monkeypatch.setattr("wpt.sources.ftp.ftplib.FTP_TLS", _FakeFTP)
    source = FtpSource("127.0.0.1", "user", "secret", root="",
                       settings=FtpSettings(timeout_s=30, retries=1),
                       deadline=Deadline(0.5))
    source._connect()
    assert calls and 0 < calls[0] <= 0.5

    expired = Deadline(0.05)
    expired._started -= 1.0
    source.deadline = expired
    source._ftp = None
    calls.clear()
    with pytest.raises(DeadlineExceeded):
        source._connect()
    assert calls == []


def test_R23_pasv_rearms_the_data_connect_timeout_from_remaining(
        monkeypatch):
    """R23-P2: ftplib uses ``self.timeout`` for the data CONNECT immediately
    after ``makepasv``, but the value was armed once at op start.  A slow
    PASV round trip then let a blackholed connect run past --deadline.  The
    makepasv seam re-arms from the remaining budget."""
    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    class _FakeFtp:
        def __init__(self):
            self.sock = None
            self.timeout = 30

        def transfercmd(self, cmd, rest=None):
            return None

        def makepasv(self):
            return ("127.0.0.1", 9)

    source = FtpSource("host", "u", "p", "",
                       settings=FtpSettings(timeout_s=30, retries=0),
                       deadline=Deadline(1.0))
    ftp = _FakeFtp()
    source._track_transfers(ftp)
    # Simulate 0.6 s spent inside the PASV round trip (deterministic clock
    # shift instead of a wall-clock sleep).
    source.deadline._started -= 0.6
    ftp.timeout = 30
    assert ftp.makepasv() == ("127.0.0.1", 9)
    assert 0 < ftp.timeout <= 0.5, ftp.timeout

    spent = Deadline(0.05)
    spent._started -= 1.0
    source.deadline = spent
    ftp.timeout = 30
    with pytest.raises(DeadlineExceeded):
        ftp.makepasv()


def test_R19_failed_auth_login_closes_the_control_socket(monkeypatch):
    """R19-P2: ``_connect`` re-raised after a failed auth/login/prot_p/pwd
    without ``ftp.close()``.  A real FTP_TLS owns a socket fd; four failed
    logins were four live client fds until cyclic GC.  Every post-connect
    failure now closes the wrapper."""
    import os

    if not os.path.isdir("/proc/self/fd"):  # pragma: no cover — non-Linux
        pytest.skip("fd counting needs /proc")

    class _RealSocketFTP(ftplib.FTP_TLS):
        def connect(self, host, port=21, timeout=-1, source_address=None):
            self.sock = socket.socket()
            self.host = host

        def auth(self):
            raise ftplib.error_perm("530 Login incorrect")

    monkeypatch.setattr("wpt.sources.ftp.ftplib.FTP_TLS", _RealSocketFTP)
    source = FtpSource("host", "user", "secret", root="",
                       settings=FtpSettings(timeout_s=5, retries=1))
    before = len(os.listdir("/proc/self/fd"))
    for _ in range(4):
        with pytest.raises(ftplib.error_perm):
            source._connect()
    assert len(os.listdir("/proc/self/fd")) == before


def test_R19_child_step_failure_closes_and_quit_failure_closes():
    """The same close is owed on a prot_p/pwd failure, and close()/_reset()
    must close even when QUIT itself fails."""
    class _FailingFTP:
        def __init__(self, fail_at):
            self.fail_at = fail_at
            self.closed = 0
            self.sock = None

        def connect(self, host, port=21, timeout=-1):
            pass

        def auth(self):
            if self.fail_at == "auth":
                raise ftplib.error_perm("530 auth")

        def login(self, user, password):
            if self.fail_at == "login":
                raise ftplib.error_perm("530 login")

        def prot_p(self):
            if self.fail_at == "prot_p":
                raise ftplib.error_perm("534 prot")

        def pwd(self):
            if self.fail_at == "pwd":
                raise ftplib.error_perm("550 pwd")
            return "/"

        def quit(self):
            raise ftplib.error_perm("421 quit refused")

        def close(self):
            self.closed += 1

        def transfercmd(self, cmd, rest=None):
            return None

    import wpt.sources.ftp as ftp_module

    for step in ("auth", "login", "prot_p", "pwd"):
        made = []

        def factory(step=step):
            made.append(_FailingFTP(step))
            return made[-1]

        orig = ftp_module.ftplib.FTP_TLS
        ftp_module.ftplib.FTP_TLS = factory
        try:
            source = FtpSource("host", "user", "secret", root="",
                               settings=FtpSettings(timeout_s=5, retries=1))
            with pytest.raises((ftplib.error_perm, SourceError)):
                source._connect()
        finally:
            ftp_module.ftplib.FTP_TLS = orig
        # The per-address auth attempt closes before trying the next address;
    # the outer failure guard closes the (already closed) session again.
    assert made[0].closed >= 1, step

    # A QUIT failure in _reset() and close() still closes the wrapper.
    for method in ("_reset", "close"):
        made = []

        def factory():
            made.append(_FailingFTP("none"))
            return made[-1]

        orig = ftp_module.ftplib.FTP_TLS
        ftp_module.ftplib.FTP_TLS = factory
        try:
            source = FtpSource("host", "user", "secret", root="",
                               settings=FtpSettings(timeout_s=5, retries=1))
            source._ftp = source._connect()
            getattr(source, method)()
        finally:
            ftp_module.ftplib.FTP_TLS = orig
        assert made[0].closed == 1, method


def test_login_uses_prot_p_and_never_logs_password(server, caplog):
    srv = server()
    s = make_src()
    s.list_dir("")  # force connect
    assert any(c[0] == "prot_p" for c in srv.state["calls"])
    assert "secret" not in caplog.text


def test_list_dir_root_and_nested(server):
    server()
    s = make_src()
    top = {e.path for e in s.list_dir("")}
    assert top == {"wp-config.php", "wp-content", "private_html"}
    deep = {e.path for e in s.list_dir("wp-content/uploads/2018")}
    assert deep == {"wp-content/uploads/2018/03"}


# ------------------------------------------------------------ LIST metadata

def _epoch(*parts):
    return int(datetime(*parts, tzinfo=timezone.utc).timestamp())


def test_listing_header_and_malformed_lines_are_skipped(server):
    """The "total N" header and a garbled line are not entries — and never
    an IndexError that takes an entire audit down."""
    server(listing_extra=("total 42", "this is not a LIST line"))
    entries = make_src().list_dir("")
    assert {e.path for e in entries} == {
        "wp-config.php", "wp-content", "private_html",
    }


def test_list_dir_parses_mode_owner_group(server):
    server()
    entries = {e.path: e for e in make_src().list_dir("")}
    config = entries["wp-config.php"]
    assert (config.mode, config.owner, config.group) == (0o644, "u", "g")
    assert config.is_dir is False and config.is_link is False
    content = entries["wp-content"]
    assert (content.mode, content.owner, content.group) == (0o755, "u", "g")
    assert content.is_dir is True and content.is_link is False
    # the fake always lists "Sep 14 12:00"; the year rule is tested below
    assert all(entry.mtime is not None for entry in entries.values())


@pytest.mark.parametrize(("perms", "mode"), [
    ("-rw-r--r--", 0o644),
    ("drwxr-xr-x", 0o755),
    ("-rw-rw-rw-", 0o666),
    ("-rwsr-xr-x", 0o4755),
    ("drwxrwxrwt", 0o1777),
])
def test_permission_word_maps_to_mode(perms, mode):
    entry = make_src()._parse_line(
        "", f"{perms} 1 alice staff 7 Sep 14 2023 f.txt", now=0)
    assert entry is not None and entry.mode == mode


def test_explicit_year_line_gets_its_mtime():
    entry = make_src()._parse_line(
        "", "-rw-r--r-- 1 alice staff 42 Sep 14 2023 notes.txt", now=0)
    assert entry is not None
    assert entry.mtime == _epoch(2023, 9, 14)
    assert (entry.mode, entry.owner, entry.group) == (0o644, "alice", "staff")


def test_time_of_day_line_takes_the_listing_year():
    now = _epoch(2026, 10, 19, 18, 0)
    entry = make_src()._parse_line(
        "", "-rw-r--r-- 1 alice staff 42 Sep 14 12:00 notes.txt", now=now)
    assert entry is not None
    assert entry.mtime == _epoch(2026, 9, 14, 12, 0)


def test_time_of_day_line_in_the_future_rolls_back_a_year():
    """The documented inference rule: LIST omits the year for recent files,
    so a wall-clock instant still ahead of "now" belongs to the previous
    year (the listing's new-year boundary).  Explicit ``now`` keeps the test
    deterministic."""
    now = _epoch(2026, 1, 5, 8, 0)
    entry = make_src()._parse_line(
        "", "-rw-r--r-- 1 alice staff 42 Dec 31 23:30 notes.txt", now=now)
    assert entry is not None
    assert entry.mtime == _epoch(2025, 12, 31, 23, 30)


def test_symlink_line_keeps_name_and_metadata():
    entry = make_src()._parse_line(
        "", "lrwxrwxrwx 1 root wheel 7 Sep 14 2023 current -> releases/2023",
        now=0)
    assert entry is not None
    assert entry.path == "current"
    assert entry.is_link is True and entry.is_dir is True
    assert entry.size == 7 and entry.mode == 0o777
    assert (entry.owner, entry.group) == ("root", "wheel")
    assert entry.mtime == _epoch(2023, 9, 14)


def test_malformed_lines_return_none():
    src = make_src()
    for line in (
        "total 12",                                   # the LIST header
        "garbage",                                    # far too few fields
        "-rw-r--r-- 1 u g 5 Sep 14",                  # no clock column
        "?rw-r--r-- 1 u g 5 Sep 14 2023 x",           # bad type character
        "-rwr--r-- 1 u g 5 Sep 14 2023 x",            # bad permission triple
    ):
        assert src._parse_line("", line, now=0) is None


def test_unknown_date_keeps_the_entry_with_unknown_mtime():
    """A date the parser cannot read is not an unparseable LINE: the entry
    still carries every fact the other columns state, and mtime stays None
    (unknown, never a guessed zero)."""
    entry = make_src()._parse_line(
        "", "-rw-r--r-- 1 u g 5 Foo 14 2023 x", now=0)
    assert entry is not None
    assert entry.mode == 0o644 and entry.mtime is None


def test_walk_recurses_month_subdirs(server):
    server()
    paths = [e.path for e in make_src().walk("wp-content/uploads")]
    assert "wp-content/uploads/2018/03/a.png" in paths  # L9


def test_guard_blocks_outside_webroot(server):
    server()
    with pytest.raises(SourceError):
        make_src().list_dir("../other")


@pytest.mark.parametrize("path", ["a\nb", "a\rb", "a\x00b", "a\x7fb",
                                  "a\ud800b"])
def test_FTP_1_guard_rejects_control_and_surrogate_paths(path):
    """C0/DEL/surrogates would reach ftplib.putline as a raw
    ValueError/UnicodeEncodeError (neither is a WptError) and a newline can
    smuggle a second FTP command."""
    with pytest.raises(SourceError, match="unsafe path"):
        make_src()._guard_path(path)


class _RawFtpError:
    """The smallest ftplib-shaped double: raises one chosen public read."""

    def __init__(self, error):
        self.error = error

    def retrlines(self, cmd, callback):
        raise self.error

    def retrbinary(self, cmd, callback):
        raise self.error

    def quit(self):
        pass


@pytest.mark.parametrize("error", [
    ftplib.error_reply("500 garbage"),
    ftplib.error_proto("501 malformed"),
    EOFError("control connection closed"),
])
def test_FTP_1_ftplib_all_errors_become_source_errors(error):
    """error_reply/error_proto are ftplib.Error (not OSError) and EOFError is
    the dropped control channel: all three must leave the connector as
    SourceError so every command body's (WptError, OSError) contract holds."""
    s = make_src()
    s._ftp = _RawFtpError(error)
    with pytest.raises(SourceError):
        s.list_dir("")
    s._ftp = _RawFtpError(error)
    with pytest.raises(SourceError):
        s.read_bytes("wp-config.php")


def test_FILES_5_ftp_read_is_stream_bounded_before_materializing():
    """A lying SIZE (or a growing file) cannot make read_bytes_bounded hold
    the whole body: the RETR callback aborts at the first byte past bound."""
    chunks: list[int] = []

    class _DripFtp:
        def retrbinary(self, cmd, callback):
            for chunk in (b"a" * 512, b"b" * 512, b"c" * 512):
                chunks.append(len(chunk))
                callback(chunk)

        def quit(self):
            pass

    s = make_src()
    s._ftp = _DripFtp()
    with pytest.raises(SourceError, match="read bound"):
        s.read_bytes_bounded("big.bin", 1024)
    assert sum(chunks) <= 1024 + 512
    assert s._ftp is None  # the dirty data connection was dropped


def test_protected_paths_rejected_through_public_api(server):
    server()
    s = make_src()
    with pytest.raises(NotWritableError):
        s.write_bytes("wp-config.php", b"x")
    with pytest.raises(NotWritableError):
        s.write_bytes("index.php", b"x", allow_config=True)  # core stays locked
    s.write_bytes(".htaccess", b"x", allow_config=True)      # config unlocks
    s.write_bytes("wp-config.php", b"x", allow_config=True)  # allowed with flag
    with pytest.raises(SourceError):
        s.delete("wp-config.php")
    with pytest.raises(SourceError):
        s.delete(".htaccess")


def test_stale_connection_retried_once(server):
    srv = server(fail_first_retrlines=1)
    s = make_src()
    names = {e.path for e in s.list_dir("")}
    assert "wp-config.php" in names
    # proof of a REAL reconnect: login ran on a fresh connection object
    assert srv.state["calls"].count(("login", "user")) >= 2


def test_persistent_failure_raises_after_retry(server):
    server(fail_first_retrlines=999)
    with pytest.raises(SourceError):
        make_src().list_dir("")


def test_rmdir_recursive_deletes_deepest_first(server):
    srv = server({
        "site/public_html/wp-content/plugins/old": True,
        "site/public_html/wp-content/plugins/old/nested": True,
        "site/public_html/wp-content/plugins/old/nested/file.php": False,
    })
    s = make_src()
    s.rmdir_recursive("wp-content/plugins/old")
    calls = srv.state["calls"]
    rmd = [c[1] for c in calls if c[0] == "rmd"]
    assert rmd.index("site/public_html/wp-content/plugins/old/nested") \
        < rmd.index("site/public_html/wp-content/plugins/old")
    assert ("delete", "site/public_html/wp-content/plugins/old/nested/file.php") in calls


def test_exists_and_size(server):
    server()
    s = make_src()
    assert s.exists("wp-config.php") is True
    assert s.size("wp-config.php") == 500
    assert s.exists("wp-content/missing.txt") is False


def test_read_bytes_roundtrip(server):
    server()
    assert make_src().read_bytes("wp-config.php") == b"CONTENT"


# --------------------------------------------- consecutive-failure breaker

def test_breaker_no_trip_on_four_failures_then_success(server):
    server(fail_first_retrlines=8)  # 4 failed ops x 2 attempts (threshold 5)
    s = make_src()
    for _ in range(4):
        with pytest.raises(SourceError, match="ftp operation failed after retry"):
            s.list_dir("")
    names = {e.path for e in s.list_dir("")}  # 5th op recovers: no trip
    assert "wp-config.php" in names


def test_breaker_trips_on_fifth_consecutive_failure(server):
    server(fail_first_retrlines=999)
    s = make_src()
    for _ in range(4):
        with pytest.raises(SourceError, match="ftp operation failed after retry"):
            s.list_dir("")
    with pytest.raises(SourceError) as ei:
        s.list_dir("")
    assert str(ei.value) == (
        "ftp channel unhealthy: 5 consecutive failed operations "
        "(421 stale control connection); the passive data channel is stale — "
        "reconnect the session or retry the command later"
    )


def test_breaker_counter_resets_on_success(server):
    srv = server(fail_first_retrlines=4)
    s = make_src()
    for _ in range(2):
        with pytest.raises(SourceError, match="ftp operation failed after retry"):
            s.list_dir("")
    assert s.list_dir("")          # success: the breaker re-arms
    srv.state["fail"] = 10         # the channel breaks again
    for _ in range(4):
        with pytest.raises(SourceError, match="ftp operation failed after retry"):
            s.list_dir("")         # 4 consecutive since the success: no trip yet
    with pytest.raises(SourceError, match="ftp channel unhealthy: 5 consecutive"):
        s.list_dir("")             # the 5th AFTER the success trips — reset proven


def test_non_550_perm_failure_raises_immediately_and_counts(server):
    srv = server(perm_first_retrlines=2)
    s = make_src()
    s.settings.max_consecutive_failures = 2
    with pytest.raises(SourceError):  # public read maps the raw 553
        s.list_dir("")
    assert len([c for c in srv.state["calls"] if c[0] == "retrlines"]) == 1
    assert srv.state["calls"].count(("login", "user")) == 1
    with pytest.raises(SourceError, match="ftp channel unhealthy: 2 consecutive"):
        s.list_dir("")             # the perm failure counted: trip at 2


def test_breaker_threshold_honored_from_settings(server):
    server(fail_first_retrlines=999)
    s = make_src()
    s.settings.max_consecutive_failures = 2  # ftp.max_consecutive_failures once promoted
    with pytest.raises(SourceError, match="ftp operation failed after retry"):
        s.list_dir("")
    with pytest.raises(SourceError, match="ftp channel unhealthy: 2 consecutive"):
        s.list_dir("")


def test_breaker_trip_warns_once_without_secrets(server, wpt_caplog):
    server(fail_first_retrlines=999)
    s = make_src()
    for _ in range(4):
        with pytest.raises(SourceError):
            s.list_dir("")
    with pytest.raises(SourceError, match="ftp channel unhealthy"):
        s.list_dir("")
    warns = [r for r in wpt_caplog.records
             if r.name == "wpt.sources.ftp" and r.levelno == logging.WARNING]
    assert len(warns) == 1          # ONE health line, at the trip
    msg = warns[0].getMessage()
    assert "ftp channel unhealthy" in msg
    assert "host" in msg and "user" in msg
    assert "secret" not in wpt_caplog.text  # the password never reaches logs


def test_breaker_trip_propagates_through_size_not_masked_as_missing(server):
    """A dead data channel has no truthful exists() answer: the breaker
    trip (FtpChannelUnhealthy) propagates out of size()/exists() instead
    of being masked as "no such file" — a false missing would make
    destroy/restore skip live work. Both the SIZE op AND the parent-
    listing fallback must die (a healthy fallback listing rescues size)."""
    server(fail_first_size=999, fail_first_retrlines=999)
    s = make_src()
    # each size() burns 2 ops (SIZE + fallback listing): ops 1-4 fail as
    # per-op SourceError; the 5th consecutive op trips the breaker.  A
    # failed SIZE plus a failed witness listing is UNPROVEN absence, not
    # "no such file" (FILES-1).
    with pytest.raises(SourceLookupError, match="cannot determine"):
        s.size("site/public_html/wp-config.php")
    with pytest.raises(SourceLookupError, match="cannot determine"):
        s.size("site/public_html/wp-config.php")
    with pytest.raises(FtpChannelUnhealthy, match="ftp channel unhealthy"):
        s.size("site/public_html/wp-config.php")  # the 5th op is the trip
    s2 = make_src()  # fresh session, same dead server
    for _ in range(2):
        with pytest.raises(SourceLookupError, match="cannot determine"):
            s2.exists("site/public_html/wp-config.php")
    with pytest.raises(FtpChannelUnhealthy, match="ftp channel unhealthy"):
        s2.exists("site/public_html/wp-config.php")  # the 5th op is the trip
    # a healthy channel still answers not-found truthfully
    server()
    s3 = make_src()
    assert s3.exists("nope.php") is False


def test_delete_non_550_perm_is_sourceerror_never_raw(server):
    """A permission-refused delete surfaces as SourceError (wrapped) —
    a raw ftplib.error_perm would escape every command body's
    (WptError, OSError) contract as a traceback."""
    srv = server(fs={**FS, "site/public_html/readme.html": False},
                 perm_first_delete=1)
    s = make_src()
    with pytest.raises(SourceError, match="delete failed on"):
        s.delete("readme.html")
    assert s.delete("readme.html") is None  # the refusal was transient
    assert ("delete", "site/public_html/readme.html") in srv.state["calls"]


# ------------------------------------------------------ read_many bulk contract

class SerialBulkSource(WalkMixin):
    """Minimal Source exercising the INHERITED default read_many (the base
    contract every connector falls back to): scripted ok/raise per path."""

    root = ""

    def __init__(self, files: dict[str, bytes], raises: dict[str, Exception]) -> None:
        self.files = files
        self.raises = raises

    def read_bytes(self, path: str) -> bytes:
        if path in self.raises:
            raise self.raises[path]
        return self.files[path]

    def list_dir(self, path):
        return []

    def write_bytes(self, path, data, *, allow_config=False, allow_core=False):
        pass

    def delete(self, path):
        pass

    def rmdir_recursive(self, path):
        pass

    def exists(self, path):
        return True

    def size(self, path):
        return 0

    def close(self):
        pass


def test_read_many_serial_default_mixed_ok_and_failed():
    """The default read_many: per-path (SourceError, OSError) land in
    ``failed`` carrying the exception TEXT; the rest keep going."""
    src = SerialBulkSource({"a.php": b"AAA", "b.php": b"BBB"},
                           {"c.php": SourceError("no such file: c.php"),
                            "d.php": OSError("socket hung up")})
    ok, failed = src.read_many(["a.php", "c.php", "b.php", "d.php"])
    assert ok == {"a.php": b"AAA", "b.php": b"BBB"}
    assert failed == {"c.php": "no such file: c.php",
                      "d.php": "socket hung up"}


def test_read_many_serial_default_unexpected_exception_is_run_level():
    """Anything outside (SourceError, OSError) propagates: a RAISE is a
    run-level verdict, never a per-path answer."""
    src = SerialBulkSource({}, {"x.php": ValueError("boom")})
    with pytest.raises(ValueError, match="boom"):
        src.read_many(["x.php"])


def _bulk_fs(n=8):
    return {f"site/public_html/f{i}.php": False for i in range(n)}


def _bulk_contents(n=8):
    return {f"site/public_html/f{i}.php": f"DATA{i}".encode() for i in range(n)}


def test_read_many_parallel_reads_all_ok_four_worker_logins(server):
    """parallel_reads=4 over 8 paths: every worker session is DEDICATED —
    the fake must record 4 distinct logins (one per worker), not 1 or 8."""
    srv = server(fs=_bulk_fs(), contents=_bulk_contents())
    s = make_src()   # FtpSettings default parallel_reads=4
    ok, failed = s.read_many([f"f{i}.php" for i in range(8)])
    assert failed == {}
    assert ok == {f"f{i}.php": f"DATA{i}".encode() for i in range(8)}
    assert srv.state["calls"].count(("login", "user")) == 4


def test_read_many_parallel_one_is_serial_through_same_machinery(server):
    """parallel_reads=1: the SAME worker machinery with one worker — same
    bytes, exactly one login."""
    srv = server(fs=_bulk_fs(), contents=_bulk_contents())
    s = make_src()
    s.settings.parallel_reads = 1
    ok, failed = s.read_many([f"f{i}.php" for i in range(8)])
    assert failed == {}
    assert ok == {f"f{i}.php": f"DATA{i}".encode() for i in range(8)}
    assert srv.state["calls"].count(("login", "user")) == 1


def test_read_many_one_missing_path_fails_alone(server):
    """A 550-missing path is a per-path failure: it lands in ``failed``;
    every readable path still returns its bytes."""
    server(fs=_bulk_fs(), contents=_bulk_contents())
    s = make_src()
    paths = [f"f{i}.php" for i in range(8)] + ["missing.php"]
    ok, failed = s.read_many(paths)
    assert ok == {f"f{i}.php": f"DATA{i}".encode() for i in range(8)}
    assert list(failed) == ["missing.php"]
    assert "no such file" in failed["missing.php"]


def test_read_many_dead_channel_every_path_failed_raises(server):
    """Every path failing with the channel-unhealthy verdict is a RUN-LEVEL
    failure: read_many re-raises FtpChannelUnhealthy instead of returning
    thousands of per-path failures."""
    server(fs=_bulk_fs(), fail_first_retr=999)
    s = make_src()
    s.settings.max_consecutive_failures = 1  # every read trips its worker
    with pytest.raises(FtpChannelUnhealthy, match="ftp channel unhealthy"):
        s.read_many([f"f{i}.php" for i in range(8)])


def test_read_many_dead_worker_marks_rest_of_chunk_partial_ok(server):
    """A worker whose channel dies mid-chunk marks the unread remainder of
    its chunk failed with the SAME channel verdict (no per-path re-reads on
    a dead session); the healthy workers' paths still succeed — a mixed
    batch returns normally, no run-level raise."""
    server(fs=_bulk_fs(4), contents=_bulk_contents(4),
           fail_retr_paths=("site/public_html/f0.php",))
    s = make_src()
    s.settings.parallel_reads = 2       # chunks [f0, f2] and [f1, f3]
    s.settings.max_consecutive_failures = 1
    ok, failed = s.read_many([f"f{i}.php" for i in range(4)])
    assert ok == {f"f{i}.php": f"DATA{i}".encode() for i in (1, 3)}
    assert set(failed) == {"f0.php", "f2.php"}  # f2 = unread remainder
    assert all("ftp channel unhealthy" in m for m in failed.values())


# ------------------------------------------------------------- slow-op window

def test_slow_window_trips_on_ten_consecutive_slow_ops(server):
    """10 consecutive near-timeout ops (synthesized durations — no sleeps)
    trip the window: FtpChannelUnhealthy even though nothing failed."""
    server()
    s = make_src()   # timeout_s=5 -> slow threshold 0.8 x 5 = 4s
    for _ in range(9):
        s._note_op_duration(5.0)
    with pytest.raises(FtpChannelUnhealthy,
                       match="ftp channel degraded: last 10 operations each "
                             "took >4s"):
        s._note_op_duration(5.0)


def test_slow_window_resets_on_any_fast_op(server):
    """One fast op resets the window: 9 slow + 1 fast + 9 slow does NOT
    trip; the 10th slow op after the fast one completes the refill and
    does."""
    server()
    s = make_src()
    for _ in range(9):
        s._note_op_duration(5.0)
    s._note_op_duration(0.1)             # fast: resets the window
    for _ in range(9):
        s._note_op_duration(5.0)         # only 9 slow since: no trip
    with pytest.raises(FtpChannelUnhealthy, match="ftp channel degraded"):
        s._note_op_duration(5.0)        # the 10th slow completes the window


def test_slow_window_measures_real_op_durations(server, monkeypatch):
    """Integration: _call records REAL wall durations via time.monotonic —
    a synthesized clock (no sleeps) makes 10 SUCCESSFUL ops trip the
    window, proving the recording path and the even-on-success abort."""

    class FakeClock:
        """time-module shim for wpt.sources.ftp: monotonic jumps 5s per
        call (each op measures start + end = 5s > the 4s threshold)."""

        def __init__(self):
            self.now = 0.0

        def monotonic(self):
            self.now += 5.0
            return self.now

        def time(self):
            return self.now

        def sleep(self, seconds):
            pass

    server()
    s = make_src()
    monkeypatch.setattr("wpt.sources.ftp.time", FakeClock())
    with pytest.raises(FtpChannelUnhealthy, match="ftp channel degraded"):
        for _ in range(10):
            s.list_dir("")              # ops SUCCEED — only their pace trips
    assert list(s._op_durations) == [5.0] * 10

def test_read_many_all_failed_via_slow_window_also_raises(server, monkeypatch):
    """The run-level verdict counts BOTH channel signatures: a batch whose
    every path failed via the slow-op window ("degraded", not "unhealthy")
    re-raises too — with a non-default max_consecutive_failures above the
    window size, a slow-window death must not be delivered as a pile of
    per-path failures (the pre-fix bug). Reads fail AND crawl (FakeClock:
    every op measures 5s > the 4s threshold, no sleeps); the window trips
    on the 10th op, the chunk remainder inherits the degraded verdict,
    the earlier paths carry plain read-failure messages — every bucket
    entry failed, a channel signature is present -> RUN-LEVEL raise."""

    class FakeClock:
        def __init__(self):
            self.now = 0.0

        def monotonic(self):
            self.now += 5.0
            return self.now

        def time(self):
            return self.now

        def sleep(self, seconds):
            pass

    server(fs=_bulk_fs(), fail_first_retr=999)
    s = make_src()               # timeout_s=5 -> slow threshold 4s
    s.settings.max_consecutive_failures = 50   # the FAILURE breaker stays mute
    s.settings.parallel_reads = 1               # one worker, one chunk
    monkeypatch.setattr("wpt.sources.ftp.time", FakeClock())
    with pytest.raises(FtpChannelUnhealthy, match="ftp channel unhealthy"):
        s.read_many([f"f{i}.php" for i in range(12)])


# --------------------------------------------------------------- rename

TREE_FS = {
    "site/public_html/wp-includes": True,
    "site/public_html/wp-includes/version.php": False,
    "site/public_html/wp-includes/js": True,
    "site/public_html/wp-includes/js/old.js": False,
    "site/public_html/wp-includes.wpt-new": True,
    "site/public_html/wp-includes.wpt-new/version.php": False,
    "site/public_html/wp-content": True,
    "site/public_html/wp-content/plugins": True,
}


@pytest.fixture()
def tree(server):
    """(FtpSource, FakeFTPServer) over a webroot with a core tree and its
    staged replacement — the update-core swap, on the wire."""
    srv = server(TREE_FS)
    return FtpSource("host", "u", "secret", "site/public_html"), srv


def test_rename_moves_a_whole_tree(tree):
    """RNFR/RNTO on a directory: the swap the update-core action depends on
    is ONE ftp operation carrying the whole subtree, which is the property
    a per-file rewrite of three thousand files cannot have."""
    src, srv = tree
    src.rename("wp-includes.wpt-new", "wp-includes", allow_core=True)
    assert ("rename", "site/public_html/wp-includes.wpt-new",
            "site/public_html/wp-includes") in srv.state["calls"]
    fs = srv.state["fs"]
    assert fs["site/public_html/wp-includes/version.php"] is False
    assert not any("wpt-new" in key for key in fs)


def test_rename_refuses_a_protected_destination_without_the_unlock(tree):
    """The destination guard is the WRITE guard plus the two bare tree
    names: without the audited core unlock the swap cannot land."""
    src, _srv = tree
    with pytest.raises(NotWritableError):
        src.rename("wp-includes.wpt-new", "wp-includes")
    with pytest.raises(NotWritableError):
        src.rename("wp-content/plugins", "wp-config.php")


def test_rename_550_is_a_source_error(tree):
    """A 550 from RNTO names the path as a missing file, the same mapping
    delete() applies — never a raw ftplib error escaping the connector."""
    src, _srv = tree
    # a user-content destination (so the guard is not what refuses it) and
    # a path the server has never heard of
    with pytest.raises(SourceError, match="no such file"):
        src.rename("wp-content/gone", "wp-content/plugins")


# ------------------------------------------------- ensure_write_dir (MKD)

STAGE_FS = {
    "site/public_html": True,
    "site/public_html/index.php": False,
    "site/public_html/wp-content": True,
    "site/public_html/wp-content/uploads": True,
    "site/public_html/wp-content/uploads/2018": True,
    "site/public_html/wp-content/uploads/2018/03": True,
    "site/public_html/wp-content/uploads/2018/03/a.png": False,
}


def _mkds(srv, *, collapse_retry=True):
    """The MKD targets in wire order.

    A 550 is retried once by ``_call`` (the stale-connection discipline
    every op shares), so a REFUSED MKD appears twice on the wire — real
    traffic, pinned by its own test below.  Every other assertion reads
    the collapsed list: the directory the connector worked on, in order.
    """
    out = [c[1] for c in srv.state["calls"] if c[0] == "mkd"]
    if not collapse_retry:
        return out
    return [k for i, k in enumerate(out) if i == 0 or out[i - 1] != k]


def _stors(srv):
    return [c[1] for c in srv.state["calls"] if c[0] == "stor"]


def test_a_550_mkd_is_retried_once_like_every_other_op(server):
    """The 550 that says "already there" is indistinguishable on the wire
    from a stale-channel 550, so it gets the same single reconnect-retry
    every op gets — pinned here so the collapse every other test in this
    section relies on is a fact and not a convenience."""
    srv = server(STAGE_FS)
    make_src().write_bytes("wp-content/uploads/one.txt", b"1")
    assert _mkds(srv, collapse_retry=False) == [
        "site/public_html/wp-content",           # refused, retried
        "site/public_html/wp-content",
        "site/public_html/wp-content/uploads",  # refused, retried
        "site/public_html/wp-content/uploads",
    ]


def test_write_into_a_new_directory_creates_the_whole_chain(server):
    """STOR into a directory the server has never had is a 553, so the
    write path makes the parent chain first: MKD every component, from the
    webroot-relative path and the webroot prefix on EACH one (never a
    working-directory assumption), shallowest first, and only then store.

    The live shape: update-core stages each replacement tree BESIDE the
    installed one, so the very first upload of a core update is a write
    into a directory no site has ever had.
    """
    srv = server(STAGE_FS)
    src = make_src()
    src.write_bytes("wp-admin.wpt-new/js/new.js", b"<?php\n")
    assert _mkds(srv) == [
        "site/public_html/wp-admin.wpt-new",
        "site/public_html/wp-admin.wpt-new/js",
    ]
    assert _stors(srv) == ["site/public_html/wp-admin.wpt-new/js/new.js"]
    assert srv.state["fs"]["site/public_html/wp-admin.wpt-new/js/new.js"] is False
    assert srv.state["contents"]["site/public_html/wp-admin.wpt-new/js/new.js"] \
        == b"<?php\n"
    # the staging directories are real to the connector afterwards
    assert {e.path for e in src.list_dir("wp-admin.wpt-new")} == {"wp-admin.wpt-new/js"}
    assert src.read_bytes("wp-admin.wpt-new/js/new.js") == b"<?php\n"


def test_an_existing_directory_survives_the_550_mkd_and_the_write_lands(server):
    """MKD on a directory that is already there answers 550 — the common
    case, and the one that must NOT be read as a failure.  The refusal is
    disambiguated by an independent probe, so the write proceeds and the
    file lands.

    The whole chain is walked, ``mkdir -p`` style: a directory whose own
    parent is missing cannot be created, so every level is proven once
    rather than only the leaf.
    """
    srv = server(STAGE_FS)
    src = make_src()
    src.write_bytes("wp-content/uploads/2018/03/b.png", b"PNG")
    assert _mkds(srv) == [
        "site/public_html/wp-content",
        "site/public_html/wp-content/uploads",
        "site/public_html/wp-content/uploads/2018",
        "site/public_html/wp-content/uploads/2018/03",
    ]
    # the probe: a CWD per refused MKD, answered by the server itself
    assert [c for c in srv.state["calls"] if c[0] == "cwd"] == [
        ("cwd", "site/public_html/wp-content"), ("cwd", ""),
        ("cwd", "site/public_html/wp-content/uploads"), ("cwd", ""),
        ("cwd", "site/public_html/wp-content/uploads/2018"), ("cwd", ""),
        ("cwd", "site/public_html/wp-content/uploads/2018/03"), ("cwd", ""),
    ]
    assert _stors(srv) == ["site/public_html/wp-content/uploads/2018/03/b.png"]
    assert src.read_bytes("wp-content/uploads/2018/03/b.png") == b"PNG"


def test_a_refused_mkd_surfaces_one_line_and_stores_nothing(server):
    """A directory that cannot be created is a REFUSAL with one line
    naming it: the operator gets a sentence and the site is untouched,
    never a bare 553 from the STOR that would have followed."""
    srv = server(STAGE_FS, deny_mkd=("site/public_html/wp-admin.wpt-new",))
    src = make_src()
    with pytest.raises(SourceError) as excinfo:
        src.write_bytes("wp-admin.wpt-new/index.php", b"<?php\n")
    message = str(excinfo.value)
    assert "cannot write into 'wp-admin.wpt-new'" in message
    assert "refused to create the directory" in message
    assert "nothing was written" in message
    # the probe ran and found nothing: MKD's 550 was not taken as "exists"
    assert ("cwd", "site/public_html/wp-admin.wpt-new") in srv.state["calls"]
    assert _stors(srv) == []
    assert "site/public_html/wp-admin.wpt-new" not in srv.state["fs"]
    # the chain is not walked past its first failure: a parent that cannot
    # be made means nothing under it is attempted either
    assert ("mkd", "site/public_html/wp-admin.wpt-new/js") not in srv.state["calls"]


def test_a_refused_write_creates_no_directory(server):
    """The guard runs first: a write the write-guard refuses (a protected
    path without the unlock) must not leave a directory behind on the
    server.  Creating one would be a mutation of a site the run was told
    it may not touch."""
    srv = server(STAGE_FS)
    with pytest.raises(NotWritableError):
        make_src().write_bytes("wp-admin/index.php", b"x")
    assert _mkds(srv) == [] and _stors(srv) == []
    assert "site/public_html/wp-admin" not in srv.state["fs"]


def test_a_refused_upload_is_a_source_error_never_a_raw_ftplib_error(server):
    """A 5xx STOR is re-raised raw by _call (only 550s are retried), and a
    raw ftplib exception is not a WptError: it escapes every command
    body's (WptError, OSError) contract as a traceback whose text is the
    server's own words.  The write path is where that must never happen."""
    server(STAGE_FS, fail_stor_paths=("site/public_html/readme.html",))
    with pytest.raises(SourceError) as excinfo:
        make_src().write_bytes("readme.html", b"x")
    message = str(excinfo.value)
    assert "cannot write readme.html" in message
    assert "refused the upload" in message
    assert "553" in message          # the server's own words are kept


def test_a_root_level_write_never_creates_a_directory(server):
    """The webroot is where the account already stands: a root-level write
    (the bridge deployment, .maintenance, every root core file's temp
    name) issues no MKD and no probe at all."""
    srv = server(STAGE_FS)
    src = make_src()
    src.write_bytes(".maintenance", b"<?php $upgrading = 1; ?>")
    src.write_bytes("readme.html", b"<h1>WordPress</h1>")
    assert _mkds(srv) == [] and _stors(srv) == [
        "site/public_html/.maintenance", "site/public_html/readme.html"]


def test_the_chain_is_created_once_per_directory_not_once_per_file(server):
    """The memo, and why it is safe: 3,000 core files in 400 directories
    cost 400 MKDs, not 3,000 — and each component is still proven, not
    assumed, the first time."""
    srv = server(STAGE_FS)
    src = make_src()
    for name in ("a.php", "b.php", "c.php"):
        src.write_bytes(f"wp-admin.wpt-new/js/{name}", b"x")
    assert _mkds(srv) == [
        "site/public_html/wp-admin.wpt-new",
        "site/public_html/wp-admin.wpt-new/js",
    ]
    assert len(_stors(srv)) == 3


def test_a_renamed_or_removed_directory_is_never_assumed_present(server):
    """The memo is dropped by anything that MOVES or REMOVES names, so a
    write after a swap re-proves what it writes into instead of trusting a
    path this session already deleted."""
    srv = server({**STAGE_FS,
                  "site/public_html/wp-content/uploads/keep": True})
    src = make_src()
    src.write_bytes("wp-content/uploads/keep/one.txt", b"1")
    first = ["site/public_html/wp-content",
             "site/public_html/wp-content/uploads",
             "site/public_html/wp-content/uploads/keep"]
    assert _mkds(srv) == first
    src.rename("wp-content/uploads/keep", "wp-content/uploads/kept")
    srv.state["calls"].clear()
    src.write_bytes("wp-content/uploads/kept/two.txt", b"2")
    # every level is proven AGAIN after the rename: a memo that outlived
    # the move would be a path this session no longer controls
    assert _mkds(srv) == [first[0], first[1],
                          "site/public_html/wp-content/uploads/kept"]
    src.rmdir_recursive("wp-content/uploads/kept")
    srv.state["calls"].clear()
    src.write_bytes("wp-content/uploads/kept/three.txt", b"3")
    # the recursive remove forgets exactly the subtree it took away; the
    # ancestors it did not touch stay proven
    assert _mkds(srv) == ["site/public_html/wp-content/uploads/kept"]


def test_the_probe_hands_the_session_back_when_the_webroot_is_the_root(server):
    """CWD moves the SERVER's working directory.  A source whose webroot IS
    the account root (root="", so every path it sends is relative) must
    therefore put the session back at "/" after a probe — otherwise the
    rest of the run would resolve against a directory the probe chose.
    A rooted source sends absolute paths and has nothing to undo."""
    # an account whose root IS the webroot: "/" is a real directory there
    srv = server({**{k.removeprefix("site/public_html/"): v
                     for k, v in STAGE_FS.items()}, "": True})
    rootless = FtpSource("host", "user", "secret", root="",
                         settings=FtpSettings(timeout_s=5, retries=1))
    rootless.write_bytes("wp-content/uploads/2018/03/c.png", b"PNG")
    cwds = [c[1] for c in srv.state["calls"] if c[0] == "cwd"]
    # every refused MKD is probed, and every probe is handed back: the
    # session ends up exactly where it started
    assert cwds == [
        "wp-content", "", "wp-content/uploads", "",
        "wp-content/uploads/2018", "", "wp-content/uploads/2018/03", "",
    ]
    assert _stors(srv) == ["wp-content/uploads/2018/03/c.png"]


def test_the_contract_default_is_a_no_op_and_ftp_is_the_one_that_creates(tmp_path):
    """The guarantee is on the Source contract, so it is stated there — and
    the DEFAULT is the honest no-op, because a store that materializes
    intermediate entries implicitly (the zip overlay derives its directory
    entries from the surviving file paths at materialize time) has nothing
    to create and must not spend protocol traffic proving it.

    Proven on a real writable source: a two-level staged write lands with
    no directory of its own anywhere in the archive, and the connector
    that speaks a name-inside-an-existing-directory protocol is the one
    that overrides the no-op.
    """
    import zipfile

    from wpt.sources.zipwriter import MutableZipSource

    archive = tmp_path / "site.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("index.php", b"<?php\n")
    src = MutableZipSource(archive, root=None)
    assert src.write_bytes("wp-admin.wpt-new/js/new.js", b"<?php\n") is None
    src.materialize(tmp_path / "out.zip")
    with zipfile.ZipFile(tmp_path / "out.zip") as zf:
        assert "wp-admin.wpt-new/js/new.js" in zf.namelist()
        assert "wp-admin.wpt-new/js/" in zf.namelist()   # derived, not created
    assert MutableZipSource.ensure_write_dir is Source.ensure_write_dir
    assert FtpSource.ensure_write_dir is not Source.ensure_write_dir


# ------------------------------------------------------- triple-check round 2


def test_FTP1_rmdir_recursive_drops_the_whole_subtree_from_the_dir_memo(server):
    """FTP1: only the exact directory was dropped from ``_known_dirs``; a
    later write into the re-created descendant skipped MKD and STOR 553'd."""
    srv = server({
        "site/public_html/wp-content": True,
        "site/public_html/wp-content/uploads": True,
        "site/public_html/wp-content/uploads/keep": True,
        "site/public_html/wp-content/uploads/keep/sub": True,
        "site/public_html/wp-content/uploads/keep/sub/a.txt": False,
    })
    s = make_src()
    s.write_bytes("wp-content/uploads/keep/sub/a.txt", b"a")
    s.rmdir_recursive("wp-content/uploads/keep")

    s.write_bytes("wp-content/uploads/keep/sub/b.txt", b"b")

    assert srv.state["contents"][
        "site/public_html/wp-content/uploads/keep/sub/b.txt"] == b"b"
    mkd = [c[1] for c in srv.state["calls"] if c[0] == "mkd"]
    assert "site/public_html/wp-content/uploads/keep/sub" in mkd


def test_FILE3_size_witness_listing_is_casefolded(server):
    """FILE3's interface half: SIZE fails, the witness LIST returns the
    lower-case spelling, and the requested name is differently cased."""
    server({
        "site/public_html/wp-content": True,
        "site/public_html/wp-content/a.txt": False,
    }, fail_first_size=1)
    s = make_src()
    assert s.size("wp-content/A.TXT") == 500
    assert s.exists("wp-content/A.TXT") is True


def test_LOGS4_ftp_root_and_host_are_validated_at_the_owner():
    """LOGS4: a CR/LF root reached ``putline`` as a raw ValueError and a
    surrogate host reached ``getaddrinfo`` as UnicodeEncodeError."""
    from wpt.cli import Ctx
    from wpt.remote import _validated_host, ftp_source_for
    from wpt.settings import load

    for root in ("a\nb", "a\rb", "a\ud800b", "../outside"):
        with pytest.raises(SourceError):
            FtpSource("host", "u", "p", root=root)
    for host in ("a\ud800b", "a\nb", "a..b"):
        with pytest.raises(SourceError):
            _validated_host(host)
    ctx = Ctx(source="ftp://a\ud800b", settings=load(), command="logs",
              webroot="public_html")
    with pytest.raises(SourceError):
        ftp_source_for(ctx)


class _Utf8ListServer:
    """A real TCP FTP control+data server for one LIST; non-UTF-8 bytes."""

    def __init__(self, line: bytes) -> None:
        import socket
        import threading

        self.line = line
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        import socket

        control, _addr = self.listener.accept()
        control_file = control.makefile("rb")
        control.sendall(b"220 fake ftp ready\r\n")
        data_listener = None
        try:
            while True:
                line = control_file.readline()
                if not line:
                    return
                verb = line.split(None, 1)[0].upper()
                if verb in (b"USER", b"PASS", b"TYPE", b"SYST"):
                    control.sendall(b"200 ok\r\n")
                elif verb == b"PASV":
                    data_listener = socket.socket(socket.AF_INET,
                                                  socket.SOCK_STREAM)
                    data_listener.bind(("127.0.0.1", 0))
                    data_listener.listen(1)
                    port = data_listener.getsockname()[1]
                    control.sendall(
                        f"227 Entering Passive Mode (127,0,0,1,"
                        f"{port >> 8},{port & 0xFF})\r\n".encode())
                elif verb == b"LIST":
                    control.sendall(b"150 here it comes\r\n")
                    data, _ = data_listener.accept()
                    data.sendall(
                        b"-rw-r--r-- 1 u g 10 Jan 1 2020 " + self.line + b"\r\n")
                    data.close()
                    data_listener.close()
                    control.sendall(b"226 transfer complete\r\n")
                elif verb == b"QUIT":
                    control.sendall(b"221 bye\r\n")
                    return
                else:
                    control.sendall(b"200 ok\r\n")
        finally:
            control.close()
            self.listener.close()

    def close(self) -> None:
        self.thread.join(timeout=5)
        self.listener.close()


class _RealFtpListSource(FtpSource):
    """FtpSource whose connection is a REAL ftplib.FTP (plain, not TLS)."""

    def __init__(self, port: int) -> None:
        super().__init__("127.0.0.1", "u", "p", "",
                         FtpSettings(port=port, timeout_s=5))

    def _connect(self):
        ftp = ftplib.FTP()
        ftp.connect("127.0.0.1", self.settings.port, timeout=5)
        ftp.login("u", "p")
        ftp.encoding = "utf-8"
        return ftp


def test_LOGS1_real_ftplib_list_decode_error_is_a_source_error_and_resets():
    """LOGS1: ``retrlines`` decodes LIST strictly UTF-8; one Latin-1 byte
    escaped as UnicodeDecodeError (not WptError/OSError) and crashed logs.
    The real ftplib + socket path must answer SourceError and drop the
    session (the transfer may still owe a 226)."""
    srv = _Utf8ListServer(b"caf\xe9.log")
    source = _RealFtpListSource(srv.port)
    try:
        with pytest.raises(SourceError, match="not decodable"):
            source.list_dir("")
        assert source._ftp is None
    finally:
        srv.close()


# ------------------------------------------------------- round-3 regressions


def test_FTP_LIST_DIALECT_unparseable_listing_is_not_an_empty_directory(
        server):
    """FTP-LIST-DIALECT: every non-Unix LIST line was skipped, so list_dir
    returned [] exactly like an empty directory and a backup captured
    zero files with rc 0."""
    server(fs={"site/public_html": True}, listing_extra=(
        "04-08-15  02:06PM       <DIR>          wp-content",
        "04-08-15  02:06PM                  412 wp-config.php",
    ))
    with pytest.raises(SourceError, match=r"first line: .*wp-content"):
        make_src().list_dir("")

    # A genuinely empty Unix directory (the total header only) stays [].
    server(fs={"site/public_html": True}, listing_extra=("total 0",))
    assert make_src().list_dir("") == []


class _FakeConn:
    def __init__(self, source):
        self.source = source

    def delete(self, path):
        if path in self.source.links:
            del self.source.links[path]
            return
        assert path in self.source.tree and not self.source.tree[path]
        del self.source.tree[path]

    def rmd(self, path):
        assert self.source.tree.get(path) is True
        del self.source.tree[path]


class _LinkTree(FtpSource):
    """A tiny FTP tree with a symlink, a file, a subdir and their RMDs."""

    def __init__(self):
        super().__init__("host", "u", "p", "")
        self.tree = {"upgrade": True, "upgrade/keep.txt": False,
                     "upgrade/sub": True}
        self.links = {"upgrade/current": "/shared/x"}
        self.conn = _FakeConn(self)

    def _call(self, op):
        return op(self.conn)

    def list_dir(self, path):
        rel = path if path else ""
        entries = []
        for name, is_dir in self.tree.items():
            parent = name.rpartition("/")[0]
            child = name.rsplit("/", 1)[-1]
            if parent == rel:
                entries.append(Entry(self._join(rel, child), is_dir,
                                     size=0))
        for name in self.links:
            parent = name.rpartition("/")[0]
            child = name.rsplit("/", 1)[-1]
            if parent == rel:
                # FTP models a link as is_dir=True + is_link=True.
                entries.append(Entry(self._join(rel, child), True, size=0,
                                     is_link=True))
        return entries


def test_FTP_RMDIR_LINK_deletes_links_and_the_tree():
    """FTP-RMDIR-LINK: walk() omitted is_link entries, so rmdir_recursive
    never DELEted a symlink, the final RMD answered 550, and a half-deleted
    tree was left behind."""
    source = _LinkTree()
    walked = [entry.path for entry in source.walk("upgrade", include_links=True)]
    assert "upgrade/current" in walked
    source.rmdir_recursive("upgrade")
    assert source.tree == {}
    assert source.links == {}
    # A link whose target is exactly "." is still the named entry.
    assert FtpSource._usable(
        "lrwxrwxrwx 1 u g 0 Jan 1 2020 current -> .")


def test_FTP_RAW_EXC_credentials_and_raw_value_errors_are_source_errors(
        monkeypatch):
    """FTP-RAW-EXC: ftplib.login raises ValueError for CR/LF and
    UnicodeEncodeError for a surrogate; size() raises ValueError for an
    unparseable reply.  None is WptError/OSError."""
    for value in ("p\nx", "p\rx", "p\x00x", "p\ud800x"):
        with pytest.raises(SourceError):
            FtpSource("host", "u", value, "")
    source = make_src()
    calls = []

    class Channel:
        pass

    source._ftp = Channel()
    monkeypatch.setattr(source, "_reset", lambda: calls.append("reset"))

    def _raise(exc):
        def _op(_ftp):
            raise exc
        return _op

    for exc in (ValueError("213 not-a-size"), UnicodeError("bad \udcff")):
        with pytest.raises(SourceError) as info:
            source._call(_raise(exc))
        message = str(info.value)
        assert "not-a-size" not in message
        assert "\udcff" not in message
    assert calls == ["reset", "reset"]


def test_FTP_RAW_EXC_real_ftplib_size_value_error_is_a_source_error():
    """Real ftplib.FTP.size parses the reply with int() itself; a malformed
    server answer raised ValueError through every command body."""
    import socket
    import threading

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def _serve():
        control, _ = listener.accept()
        stream = control.makefile("rb")
        control.sendall(b"220 fake ftp ready\r\n")
        try:
            while True:
                line = stream.readline()
                if not line:
                    return
                verb = line.split(None, 1)[0].upper()
                if verb in (b"USER", b"PASS", b"TYPE", b"SYST"):
                    control.sendall(b"200 ok\r\n")
                elif verb == b"SIZE":
                    control.sendall(b"213 not-a-size\r\n")
                elif verb == b"QUIT":
                    control.sendall(b"221 bye\r\n")
                    return
                else:
                    control.sendall(b"200 ok\r\n")
        finally:
            control.close()
            listener.close()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    source = _RealFtpListSource(port)
    try:
        with pytest.raises(SourceError, match="ValueError"):
            source.size("x")
        assert source._ftp is None
    finally:
        source.close()
        thread.join(timeout=5)


def test_FTP_LEADING_SPACE_preserves_the_raw_name_remainder():
    """FTP-LEADING-SPACE: split(None, 8) collapsed the separator run, so a
    legal `" secret.php"` became `secret.php` and the wrong path was read."""
    entry = make_src()._parse_line(
        "", "-rw-r--r-- 1 u g 5 Sep 14 2023  secret.php", now=0)
    assert entry is not None
    assert entry.path == " secret.php"
    # Ordinary names and internal spaces are unchanged.
    assert make_src()._parse_line(
        "", "-rw-r--r-- 1 u g 5 Sep 14 2023 notes.txt", now=0).path == "notes.txt"
    assert make_src()._parse_line(
        "", "-rw-r--r-- 1 u g 5 Sep 14 2023 a b.txt", now=0).path == "a b.txt"


# ------------------------------------------------ round 12 (P1 regressions)


class _DripRetrServer:
    """A real plain-FTP control+data server whose RETR drips 1 B / 0.2 s."""

    def __init__(self, payload: bytes = b"x" * 20, *, delay: float = 0.2):
        import socket
        import threading

        self.payload = payload
        self.delay = delay
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(5)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        import socket
        import time

        try:
            control, _ = self.listener.accept()
        except OSError:
            return
        stream = control.makefile("rb")
        data_listener = None
        try:
            control.sendall(b"220 fake ftp ready\r\n")
            while True:
                line = stream.readline()
                if not line:
                    return
                verb = line.split(None, 1)[0].upper()
                if verb in (b"USER", b"PASS", b"TYPE", b"SYST"):
                    control.sendall(b"200 ok\r\n")
                elif verb == b"PWD":
                    control.sendall(b'257 "/"\r\n')
                elif verb == b"PASV":
                    data_listener = socket.socket(socket.AF_INET,
                                                  socket.SOCK_STREAM)
                    data_listener.bind(("127.0.0.1", 0))
                    data_listener.listen(1)
                    port = data_listener.getsockname()[1]
                    control.sendall(
                        f"227 Entering Passive Mode (127,0,0,1,"
                        f"{port >> 8},{port & 0xFF})\r\n".encode())
                elif verb == b"RETR":
                    control.sendall(b"150 here it comes\r\n")
                    data, _ = data_listener.accept()
                    try:
                        for byte in self.payload:
                            data.sendall(bytes([byte]))
                            time.sleep(self.delay)
                    except OSError:
                        pass
                    finally:
                        data.close()
                        data_listener.close()
                    try:
                        control.sendall(b"226 transfer complete\r\n")
                    except OSError:
                        pass
                elif verb == b"QUIT":
                    control.sendall(b"221 bye\r\n")
                    return
                else:
                    control.sendall(b"200 ok\r\n")
        except (OSError, ValueError):
            pass
        finally:
            try:
                control.close()
            except OSError:
                pass
            self.listener.close()

    def close(self) -> None:
        self.thread.join(timeout=5)
        try:
            self.listener.close()
        except OSError:
            pass


class _RealFtpDripSource(FtpSource):
    def __init__(self, port: int, deadline,
                 cleanup_deadline_s: float | None = None) -> None:
        super().__init__("127.0.0.1", "u", "p", "",
                         FtpSettings(port=port, timeout_s=1, retries=0),
                         deadline=deadline,
                         cleanup_deadline_s=cleanup_deadline_s)

    def _connect(self):
        ftp = ftplib.FTP()
        ftp.connect("127.0.0.1", self.settings.port, timeout=1)
        ftp.login("u", "p")
        self._track_transfers(ftp)
        return ftp


def test_R12_ftp_data_drip_is_bounded_by_the_absolute_deadline():
    """R12-P1-6: ``retrbinary`` used the per-read timeout set once at op
    start; 20 bytes at 1 B/0.2 s returned after 4 s under a 0.5 s budget.
    The watchdog closes the data/control sockets at Deadline.at and the
    expiry maps to DeadlineExceeded."""
    import time

    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    server = _DripRetrServer()
    source = _RealFtpDripSource(server.port, Deadline(0.5))
    try:
        started = time.monotonic()
        with pytest.raises(DeadlineExceeded):
            source.read_bytes("f.bin")
        elapsed = time.monotonic() - started
        assert elapsed < 1.5, elapsed
        assert source._ftp is None
    finally:
        source.close()
        server.close()


@pytest.mark.parametrize("failure", [
    OSError("network unreachable"),
    ftplib.error_temp("421 service unavailable"),
    ftplib.error_proto("500 bad banner"),
    EOFError(),
    UnicodeError("bad reply"),
    ValueError("bad reply"),
])
def test_R16_address_fallback_catches_every_per_address_failure(
        monkeypatch, failure):
    """R16-P1: the connect loop caught only OSError, so an FTP-level banner
    refusal (ftplib.Error) aborted before the next resolved address.  Every
    per-address failure closes that connection, records it, and continues."""
    from wpt.sources import ftp as ftp_module

    class _FakeFTP:
        def __init__(self):
            self.addresses: list[str] = []
            self.closed = 0
            self.context = None

        def connect(self, address, port, timeout=None):
            self.addresses.append(address)
            if address == "127.0.0.1":
                raise failure
            self.connected = address

        def close(self):
            self.closed += 1

        def auth(self):
            pass

        def login(self, user, password):
            self.user = user

        def prot_p(self):
            pass

        def pwd(self):
            return "/"

    monkeypatch.setattr(ftp_module.ftplib, "FTP_TLS", _FakeFTP)
    monkeypatch.setattr(ftp_module, "is_numeric_host", lambda host: False)
    monkeypatch.setattr(
        ftp_module, "resolve_host_bounded",
        lambda host, port, deadline, **kwargs:
        ["127.0.0.1", "127.0.0.2"])
    from wpt.deadline import Deadline

    source = FtpSource("ftp.example", "u", "p", "", deadline=Deadline(10))
    ftp = source.ftp
    assert ftp.addresses == ["127.0.0.1", "127.0.0.2"]
    assert ftp.connected == "127.0.0.2"
    assert ftp.closed == 1


def test_R25_auth_failure_on_the_first_address_falls_back_to_the_next(
        monkeypatch):
    """R25-P2: the address loop wrapped only ``connect``; ``auth()`` ran
    after one address was chosen, so a listener that accepts TCP and answers
    AUTH with 234 then closes aborted the whole operation instead of trying
    the next resolved address.  A certificate verification failure stays
    permanent (another address cannot fix a name/CA verdict)."""
    from wpt.sources import ftp as ftp_module

    class _FakeFTP:
        def __init__(self):
            self.addresses: list[str] = []
            self.auths: list[str] = []
            self.closed = 0
            self.context = None
            self.logged_in = False

        def connect(self, address, port, timeout=None):
            self.addresses.append(address)
            self.current = address

        def close(self):
            self.closed += 1

        def auth(self):
            self.auths.append(self.current)
            if self.current == "127.0.0.1":
                raise ssl.SSLEOFError("banner 234 then EOF")

        def login(self, user, password):
            self.logged_in = True

        def prot_p(self):
            pass

        def pwd(self):
            return "/"

    monkeypatch.setattr(ftp_module.ftplib, "FTP_TLS", _FakeFTP)
    monkeypatch.setattr(ftp_module, "is_numeric_host", lambda host: False)
    monkeypatch.setattr(
        ftp_module, "resolve_host_bounded",
        lambda host, port, deadline, **kwargs:
        ["127.0.0.1", "127.0.0.2"])
    from wpt.deadline import Deadline

    source = FtpSource("ftp.example", "u", "p", "", deadline=Deadline(10))
    ftp = source.ftp
    assert ftp.addresses == ["127.0.0.1", "127.0.0.2"]
    assert ftp.auths == ["127.0.0.1", "127.0.0.2"]
    assert ftp.logged_in is True


def test_R25_certificate_verification_failure_is_not_retried_on_another_address(
        monkeypatch):
    from wpt.sources import ftp as ftp_module

    class _FakeFTP:
        def __init__(self):
            self.addresses: list[str] = []
            self.context = None

        def connect(self, address, port, timeout=None):
            self.addresses.append(address)
            self.host = address

        def close(self):
            pass

        def auth(self):
            raise ssl.SSLCertVerificationError("hostname mismatch")

        def login(self, user, password):
            raise AssertionError("a cert failure must not log in")

        def prot_p(self):
            raise AssertionError

        def pwd(self):
            raise AssertionError

    monkeypatch.setattr(ftp_module.ftplib, "FTP_TLS", _FakeFTP)
    monkeypatch.setattr(ftp_module, "is_numeric_host", lambda host: False)
    monkeypatch.setattr(
        ftp_module, "resolve_host_bounded",
        lambda host, port, deadline, **kwargs:
        ["127.0.0.1", "127.0.0.2"])
    from wpt.deadline import Deadline

    source = FtpSource("ftp.example", "u", "p", "", deadline=Deadline(10))
    with pytest.raises(ssl.SSLCertVerificationError):
        _ = source.ftp


def test_R16_cleanup_suspends_to_a_fresh_finite_budget_not_none():
    """R16-P1: ``deadline_suspended`` detached the budget to None, so cleanup
    read/retry/close had no watchdog and a 1-byte/0.2 s drip held it forever.
    It now installs run.cleanup_deadline_s (a fresh finite budget), so the
    same watchdog aborts the cleanup read inside the cleanup budget."""
    import time

    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    server = _DripRetrServer(payload=b"x" * 200, delay=0.2)
    source = _RealFtpDripSource(
        server.port, Deadline(0.05), cleanup_deadline_s=0.5)
    try:
        with source.deadline_suspended():
            assert source.deadline is not None
            assert source.deadline.remaining > 0
            started = time.monotonic()
            with pytest.raises(DeadlineExceeded):
                source.read_bytes("f.bin")
            elapsed = time.monotonic() - started
            assert elapsed < 1.5, elapsed
        # The exact previous budget is restored for the caller.
        assert source.deadline is not None
        assert source.deadline.remaining <= 0.05
    finally:
        source.close()
        server.close()


def test_R12_ftps_verifies_the_server_certificate_by_default(
        monkeypatch, wpt_caplog, tmp_path):
    """R12-P1-7: bare FTP_TLS() was CERT_NONE with no hostname check, so a
    MITM captured the FTP password.  The default context verifies; the
    explicit opt-out is unverified AND logs a loud warning; a CA file is
    passed to the verifying context."""
    import ssl

    source = FtpSource("ftp.example", "u", "p", "", FtpSettings())
    context = source._tls_context()
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True

    unverified = FtpSource(
        "ftp.example", "u", "p", "",
        FtpSettings(verify_tls=False))
    with wpt_caplog.at_level(logging.WARNING, logger="wpt.sources.ftp"):
        ctx = unverified._tls_context()
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False
    assert any("verification is DISABLED" in r.getMessage()
               for r in wpt_caplog.records)

    # ftp.ca_file ADDS the private CA to the default trust store.  The old
    # ``create_default_context(cafile=...)`` REPLACED it with one cert, so a
    # public-CA server failed the moment a private CA was configured.
    from wpt.dnsoverride import ensure_cert

    ca_path, _key = ensure_cert(tmp_path / "private-ca")
    public = ssl.create_default_context()
    configured = FtpSource(
        "ftp.example", "u", "p", "",
        FtpSettings(ca_file=str(ca_path)))
    context = configured._tls_context()
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert len(context.get_ca_certs()) > len(public.get_ca_certs())

    missing = FtpSource(
        "ftp.example", "u", "p", "",
        FtpSettings(ca_file=str(tmp_path / "no-such-ca.pem")))
    with pytest.raises(SourceError, match="could not be loaded"):
        missing._tls_context()


class _DripControlServer:
    """A real control-only FTP server that drips the banner or the login
    reply one byte / 0.2 s and never finishes."""

    def __init__(self, mode: str) -> None:
        import socket
        import threading

        self.mode = mode
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(5)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        import time

        try:
            control, _ = self.listener.accept()
        except OSError:
            return
        stream = control.makefile("rb")
        try:
            if self.mode == "banner":
                text = b"2" + b"20 fake ftp ready\r\n"
            else:
                control.sendall(b"220 fake ftp ready\r\n")
                stream.readline()  # USER
                control.sendall(b"331 password required\r\n")
                stream.readline()  # PASS
                text = b"2" + b"30 logged in\r\n"
            for byte in text:
                control.sendall(bytes([byte]))
                time.sleep(0.2)
        except OSError:
            pass
        finally:
            try:
                control.close()
            except OSError:
                pass
            self.listener.close()

    def close(self) -> None:
        self.thread.join(timeout=5)
        try:
            self.listener.close()
        except OSError:
            pass


class _PlainLoginFTP(ftplib.FTP):
    """Plain FTP with the two FTPS calls _connect makes (no TLS server)."""

    def auth(self):
        pass

    def prot_p(self):
        pass


@pytest.mark.parametrize("mode", ["banner", "login"])
def test_R12_ftp_banner_and_login_drips_are_bounded(monkeypatch, mode):
    """R12-P1-6: connect/auth/login read via per-read socket timeouts; a
    dripped banner or login reply could hold the run indefinitely.  The
    watchdog closes the control socket at Deadline.at."""
    import time

    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded
    from wpt.sources import ftp as ftp_module

    server = _DripControlServer(mode)
    monkeypatch.setattr(ftp_module.ftplib, "FTP_TLS", _PlainLoginFTP)
    source = FtpSource("127.0.0.1", "u", "p", "",
                       FtpSettings(port=server.port, timeout_s=1),
                       deadline=Deadline(0.5))
    try:
        started = time.monotonic()
        with pytest.raises(DeadlineExceeded):
            source.ftp
        assert time.monotonic() - started < 1.5
    finally:
        source.close()
        server.close()


class _DripListServer:
    """A real FTP server whose LIST data connection drips one byte/0.2 s."""

    def __init__(self) -> None:
        import socket
        import threading

        self.line = b"-rw-r--r-- 1 u g 5 Sep 14 2023 a.txt\r\n"
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(5)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        import socket
        import time

        try:
            control, _ = self.listener.accept()
        except OSError:
            return
        stream = control.makefile("rb")
        data_listener = None
        try:
            control.sendall(b"220 fake ftp ready\r\n")
            while True:
                line = stream.readline()
                if not line:
                    return
                verb = line.split(None, 1)[0].upper()
                if verb in (b"USER", b"PASS", b"TYPE", b"PWD"):
                    control.sendall(b'257 "/"\r\n' if verb == b"PWD"
                                    else b"200 ok\r\n")
                elif verb == b"PASV":
                    data_listener = socket.socket(socket.AF_INET,
                                                  socket.SOCK_STREAM)
                    data_listener.bind(("127.0.0.1", 0))
                    data_listener.listen(1)
                    port = data_listener.getsockname()[1]
                    control.sendall(
                        f"227 Entering Passive Mode (127,0,0,1,"
                        f"{port >> 8},{port & 0xFF})\r\n".encode())
                elif verb == b"LIST":
                    control.sendall(b"150 here it comes\r\n")
                    data, _ = data_listener.accept()
                    for byte in self.line:
                        data.sendall(bytes([byte]))
                        time.sleep(0.2)
                    data.close()
                    data_listener.close()
                    control.sendall(b"226 transfer complete\r\n")
                elif verb == b"QUIT":
                    control.sendall(b"221 bye\r\n")
                    return
                else:
                    control.sendall(b"200 ok\r\n")
        except (OSError, ValueError):
            pass
        finally:
            try:
                control.close()
            except OSError:
                pass
            self.listener.close()

    def close(self) -> None:
        self.thread.join(timeout=5)
        try:
            self.listener.close()
        except OSError:
            pass


def test_R13_ftp_close_is_bounded_and_skips_quit_on_an_expired_budget():
    """R13-P1-2: ``close()`` called ``ftp.quit()`` with no budget check and
    no watchdog, so a peer dripping the QUIT reply held shutdown forever.
    Mirror ``_reset``: an expired budget closes the sockets without QUIT;
    a live budget runs QUIT under the same deadline watchdog."""
    import socket
    import time

    from wpt.deadline import Deadline
    from wpt.types import StopRequested

    class _DrippingQuitFtp:
        def __init__(self):
            self.left, self.right = socket.socketpair()
            self.sock = self.left
            self.quit_called = False

        def quit(self):
            self.quit_called = True
            # A peer that drips no terminator: only the watchdog's socket
            # close ends this read.
            try:
                self.right.settimeout(3.0)
                while self.right.recv(1):
                    pass
            except OSError:
                pass

        def close(self):
            self.left.close()

    source = FtpSource("ftp.example", "u", "p", "", FtpSettings(),
                       deadline=Deadline(0.4))
    ftp = _DrippingQuitFtp()
    source._ftp = ftp
    started = time.monotonic()
    source.close()
    elapsed = time.monotonic() - started
    assert elapsed < 1.5, elapsed
    assert ftp.quit_called is True
    assert source._ftp is None
    assert ftp.sock.fileno() == -1  # sockets closed by the watchdog
    ftp.right.close()

    class _NeverQuit:
        sock = None
        called = False

        def quit(self):  # pragma: no cover - must not run on an expired budget
            self.called = True

        def close(self):
            pass

    expired = FtpSource("ftp.example", "u", "p", "", FtpSettings(),
                        deadline=Deadline(0.0))
    fake = _NeverQuit()
    expired._ftp = fake
    expired.close()
    assert fake.called is False

    class _StopOnQuit:
        sock = None

        def quit(self):
            raise StopRequested("SIGTERM during ftp close")

    stopping = FtpSource("ftp.example", "u", "p", "", FtpSettings())
    stopping._ftp = _StopOnQuit()
    with pytest.raises(StopRequested, match="ftp close"):
        stopping.close()
    assert stopping._ftp is None


def test_R14_ftp_reset_quit_is_bounded_and_preserves_stop():
    """R14-P1-4: ``_reset()`` called ``ftp.quit()`` outside the deadline
    watchdog (the sibling ``close()`` already fixed).  A peer dripping the
    QUIT reply reset ftplib's per-read timeout and outlived the run.  The
    reset now runs QUIT under the absolute deadline, closes the sockets on
    expiry, and still re-raises a cooperative stop."""
    import socket
    import time

    from wpt.deadline import Deadline
    from wpt.types import StopRequested

    class _DrippingQuit:
        def __init__(self):
            self.left, self.right = socket.socketpair()
            self.sock = self.left
            self.quit_called = False

        def quit(self):
            self.quit_called = True
            try:
                self.right.settimeout(3.0)
                while self.right.recv(1):
                    pass
            except OSError:
                pass

        def close(self):
            self.left.close()

    source = FtpSource("ftp.example", "u", "p", "", FtpSettings(),
                       deadline=Deadline(0.2))
    ftp = _DrippingQuit()
    source._ftp = ftp
    started = time.monotonic()
    source._reset()
    elapsed = time.monotonic() - started
    assert elapsed < 1.5, elapsed
    assert ftp.quit_called is True
    assert source._ftp is None
    assert ftp.sock.fileno() == -1       # the watchdog closed the socket
    ftp.right.close()

    class _Expired:
        sock = None
        called = False

        def quit(self):  # pragma: no cover - must not run when expired
            self.called = True

        def close(self):
            pass

    expired = FtpSource("ftp.example", "u", "p", "", FtpSettings(),
                        deadline=Deadline(0.0))
    fake = _Expired()
    expired._ftp = fake
    expired._reset()
    assert fake.called is False

    class _StopOnQuit:
        sock = None

        def quit(self):
            raise StopRequested("SIGTERM during ftp reset")

    stopping = FtpSource("ftp.example", "u", "p", "", FtpSettings())
    stopping._ftp = _StopOnQuit()
    with pytest.raises(StopRequested, match="ftp reset"):
        stopping._reset()
    assert stopping._ftp is None


def test_R12_ftp_list_data_drip_is_bounded():
    """R12-P1-6: LIST is the same transfercmd data path; a dripped listing
    must end at the run deadline too."""
    import time

    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    server = _DripListServer()
    source = _RealFtpDripSource(server.port, Deadline(0.5))
    try:
        started = time.monotonic()
        with pytest.raises(DeadlineExceeded):
            source.list_dir("")
        assert time.monotonic() - started < 1.5
    finally:
        source.close()
        server.close()


class _LinkRootTree(_LinkTree):
    """A root that IS a link: the parent shows the link, its target lists
    files (Unix FTP follows `LIST link-to-dir`)."""

    def __init__(self):
        super().__init__()
        self.tree = {
            "upgrade": True,
            "upgrade/current/keep.jpg": False,
            "wp-content/uploads/keep.jpg": False,
        }
        self.links = {"upgrade/current": "wp-content/uploads"}

    def list_dir(self, path):
        if path == "upgrade/current":
            return [Entry("upgrade/current/keep.jpg", False, size=5)]
        return super().list_dir(path)


def test_FTP_RMDIR_SYMLINK_root_link_is_deleted_never_descended():
    """FTP-RMDIR-SYMLINK: walking the caller's root followed a link-to-dir
    and deleted the TARGET's files."""
    source = _LinkRootTree()
    source.rmdir_recursive("upgrade/current")
    assert source.links == {}
    assert source.tree["wp-content/uploads/keep.jpg"] is False
    assert source.tree["upgrade/current/keep.jpg"] is False
    assert source.tree["upgrade"] is True


# ------------------------------------------------------- triple-check round 6


def test_R6_01_probe_restores_the_captured_cwd_for_a_non_empty_root(server):
    """R6-01: with a non-empty root the probe left the FTP session INSIDE the
    probed directory, so the next relative STOR re-prefixed the whole
    webroot.  A write whose parent already exists must land at the webroot
    path and the session must end where it started."""
    srv = server({
        "site/public_html": True,
        "site/public_html/wp-content": True,
    })
    src = make_src()

    src.write_bytes("wp-content/advanced-cache.php", b"<?php\n")

    assert srv.state["contents"][
        "site/public_html/wp-content/advanced-cache.php"] == b"<?php\n"
    # no double-prefixed path was ever created
    assert not any(path.startswith("site/public_html/site/public_html")
                   for path in srv.state["fs"])
    cwds = [call[1] for call in srv.state["calls"] if call[0] == "cwd"]
    # one probe into the existing parent, then the captured CWD restored
    assert cwds == ["site/public_html/wp-content", ""]


def test_R7_P1_03_missing_directory_lookup_is_resolved_by_absence_proof(server):
    """R7-P1-03: a missing directory answers 550 for both SIZE and LIST, so
    ``exists`` raises ``SourceLookupError``; the grandparent listing proves
    the whole chain absent and callers can answer False truthfully."""
    from wpt.types import SourceLookupError, absence_proven

    server(fs={"site/public_html": True,
               "site/public_html/readme.html": False})
    source = make_src()
    with pytest.raises(SourceLookupError, match="cannot determine"):
        source.exists("newdir/a.txt")
    assert absence_proven(source, "newdir/a.txt") is True


# ------------------------------------------------ triple-check round 8 (P1)


def test_P1_ftp_read_retry_uses_a_fresh_buffer(server):
    """P1-02: a partial first RETR followed by a successful retry used to
    concatenate the two attempts into one body."""
    path = "wp-content/uploads/2018/03/a.png"
    srv = server(contents={"site/public_html/" + path: b"FULL-CONTENT"},
                 partial_first_retr=b"PARTIAL-")
    src = make_src()

    assert src.read_bytes(path) == b"FULL-CONTENT"
    # exactly one successful replay after the 421
    assert len([c for c in srv.state["calls"] if c[0] == "retrlines"]) == 0


def test_P1_ftp_listing_retry_uses_a_fresh_sink(server):
    """P1-02: the LIST sink lived across the reconnect-retry, so every row
    from the first attempt appeared twice."""
    srv = server(partial_retrlines_after=1)
    src = make_src()

    entries = src.list_dir("")
    names = [entry.path for entry in entries]

    assert len(names) == len(set(names)), names
    assert "partial-one.txt" not in names
    assert names.count("wp-config.php") == 1
    assert srv.state["partial_retrlines_after"] == 0


def test_P1_ftp_partial_snapshot_is_restorable_and_contains_no_duplicates(
        server, tmp_path):
    """P1-02 end to end: a partial RETR during create_snapshot must capture
    the FULL body, verify, and restore byte-exactly — no concatenation and
    no duplicate manifest rows."""
    from tests.fakes import FakeSource
    from wpt import backup, restore
    from wpt.settings import BackupSettings

    first = "wp-content/uploads/2018/03/a.png"
    second = "wp-config.php"
    srv = server(contents={"site/public_html/" + first: b"FULL-CONTENT",
                           "site/public_html/" + second: b"SECOND"},
                 partial_first_retr=b"PARTIAL-")
    src = make_src()

    meta = backup.create_snapshot(
        src, None, "example.com", [first, second], [],
        tmp_path / "bck", BackupSettings(), "backup",
        site_raw="example.com", webroot="site/public_html")

    assert backup.verify_snapshot(meta.path) is True
    import json
    manifest = json.loads(
        (meta.path / "manifest.json").read_text(encoding="utf-8"))
    paths = [entry["path"] for entry in manifest["files"]]
    assert paths == [first, second]
    assert (meta.path / "files" / first).read_bytes() == b"FULL-CONTENT"

    live = FakeSource()
    report = restore.restore_snapshot(
        meta.path, live, None, expected_site="example.com",
        expected_webroot="site/public_html")
    assert report.files_restored == 2
    assert live.files[first] == b"FULL-CONTENT"
    assert live.files[second] == b"SECOND"
    assert srv.state["partial_first_retr"] == b""


def test_R24_legal_names_ending_in_dot_tokens_are_not_dot_entries():
    """R24-P1: ``_usable`` read the LAST whitespace token as the name, so a
    legal file/directory named ``evil.php ..`` or ``uploads ..`` was filtered
    before parsing — its subtree silently vanished from list/walk/backup.
    The exact NAME field decides; synthetic exact ``.``/``..`` rows still are
    dot entries and ``current -> .`` stays a usable symlink."""
    srv = FakeFTPServer(fs={
        "uploads ..": True,
        "uploads ../shell.php": False,
        "evil.php ..": False,
        "foo .": False,
        "normal.txt": False,
        "current": False,
    })
    src = FtpSource("h", "u", "secret", "", FtpSettings())
    src._ftp = srv.new_connection()
    src._login_dir = "/"
    names = {entry.path for entry in src.list_dir("")}
    assert {"uploads ..", "evil.php ..", "foo .", "normal.txt",
            "current"} <= names
    # A retained name that the shared path guard refuses (trailing dot/
    # space is a Windows alias) must FAIL THE WALK CLOSED, never be silently
    # omitted from an audit/backup subtree.
    with pytest.raises(SourceError, match="trailing dot/space"):
        list(src.walk())

    parsed = src._parse_line(
        "", "-rw-r--r-- 1 u g 500 Sep 14 12:00 evil.php ..")
    assert parsed is not None and parsed.path == "evil.php .."

    exact_dir = "drwxr-xr-x 1 u g 1024 Sep 14 12:00 .."
    exact_file = "-rw-r--r-- 1 u g 10 Sep 14 12:00 ."
    assert FtpSource._usable(exact_dir) is False
    assert FtpSource._usable(exact_file) is False
    assert FtpSource._usable(
        "lrwxrwxrwx 1 u g 1 Sep 14 12:00 current -> .") is True


def test_R24_pasv_rearms_after_the_pasv_round_trip(monkeypatch):
    """R24-P2: arming BEFORE ``original_pasv`` measured the budget before
    the PASV command/reply, so a slow exchange left the data connect with a
    stale (too large) timeout.  Time spent INSIDE makepasv must be deducted."""
    from wpt.deadline import Deadline

    class _FakeFtp:
        def __init__(self):
            self.sock = None
            self.timeout = 30

        def transfercmd(self, cmd, rest=None):
            return None

        def makepasv(self):
            # Simulate 0.8 s spent inside PASV itself.
            source.deadline._started -= 0.8
            return ("127.0.0.1", 9)

    source = FtpSource("host", "u", "p", "",
                       settings=FtpSettings(timeout_s=30, retries=0),
                       deadline=Deadline(1.0))
    ftp = _FakeFtp()
    source._track_transfers(ftp)
    assert ftp.makepasv() == ("127.0.0.1", 9)
    assert 0 < ftp.timeout <= 0.25, ftp.timeout
