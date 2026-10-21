"""Direct database access for local mode — the ``--db-uri`` source.

WHY (binding): ``clean-db`` is ftp-only because the bridge is the toolkit's
only DB *write* path, so an operator who wants "clean -> optimize -> TEST ->
only then publish" had to publish first, or hand-port the bridge's own SQL
against a local MariaDB (what a real migration session did — the same four
named ops, duplicated by hand, with all the drift that implies). This module
is the offline counterpart of the bridge's DB surface: a parsed ``--db-uri``,
one driver connection, the schema introspection both the audit mirror and the
re-dump read, and a pure-Python mysqldump writer.

Three owners live here, and nothing else owns them:

* :class:`DbUri` — the ONLY accepted connection-string form, parsed with the
  stdlib. ``__str__``/``__repr__`` return the REDACTED form, so an accidental
  ``log.info("%s", uri)`` cannot print a password; the password itself is
  only ever read out of :attr:`DbUri.password` by the driver call.
* :func:`schema_tables` — the schema introspection, ONE query shared by the
  offline db_audit mirror and the re-dump's table list. Its SQL and its
  scratch-table filter are a MIRROR of the bridge's ``wpt_table_whitelist()``
  + ``wpt_restore_scratch_name()``, contract-pinned against the PHP by
  ``tests/test_dbconn.py`` (the mirror convention the autoload set already
  uses). Editing one side without the other fails the suite, never a run.
* :func:`dump_database` — the mysqldump-style WRITER. No ``mysqldump``
  binary is shelled out to: an operator machine has no MySQL client
  installed (that is the whole premise of this path), and a dump produced by
  an unavailable binary is not an artifact. The output is the same shape
  ``mysqldump`` emits — ``SET`` preamble, ``DROP TABLE``/``CREATE TABLE``
  from the server's own ``SHOW CREATE TABLE``, batched extended ``INSERT``s,
  trailing comment — and is re-importable by phpMyAdmin/MariaDB. It is also
  what ``wpt.localmode.analyzer`` can read back, which is the round-trip the
  test suite pins (same tables, same row counts, spot-checked cells).

DEPENDENCY STANCE (deliberate, documented): the stdlib cannot speak the
MySQL wire protocol and this toolkit ships no binaries, so the connection
itself needs one third-party package. :data:`DRIVER_PACKAGE` (PyMySQL — pure
Python, MIT, no compiler, MySQL *and* MariaDB) is imported lazily and ONLY
when a ``--db-uri`` run actually connects: a missing driver is a one-line
error naming the package, never an ImportError traceback, and it never
affects any other command. The ``[rsa]`` extra is part of the documented
install because MySQL 8's default ``caching_sha2_password`` needs it; MariaDB
works without it.

Secrets: the password reaches this module from the CLI choke point (the same
``resolve_password`` convention as the FTP password, via
:func:`resolve_db_password`) and goes straight into the driver call. It is
never logged, never put in an exception message, and every message this
module emits routes through :func:`wpt.config.redact_text` so a DSN echoed
back by a driver error is redacted (``mysql://user:***@host``).

Logging: ``get_logger("localmode.dbconn")`` — connection facts (host, port,
database, table and row counts), never a credential and never a cell value.
"""

from __future__ import annotations

import os
import re
import secrets
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from pathlib import Path
from time import monotonic
from typing import TYPE_CHECKING, Any, Iterator, Protocol
from urllib.parse import parse_qsl, unquote, urlsplit

from ..config import redact_text
from ..log import get_logger
from ..netresolve import is_numeric_host, resolve_host_bounded
from ..settings import DbSettings
from ..types import RunControl, WptError

if TYPE_CHECKING:
    from ..deadline import Deadline

__all__ = [
    "DRIVER_MODULE", "DRIVER_PACKAGE", "DbConnection", "DbUri", "DbUriError",
    "DumpStats", "connect", "dump_database", "escape_value", "quote_ident",
    "resolve_db_password", "schema_tables",
]

log = get_logger("localmode.dbconn")

#: The one importable driver, and the one install line we print. Kept as data
#: so the message, the docs and the tests cannot disagree.
DRIVER_MODULE = "pymysql"
DRIVER_PACKAGE = 'PyMySQL[rsa]'

#: Accepted schemes. ``mysql+pymysql`` is the SQLAlchemy-flavoured spelling of
#: the same thing and is accepted as an alias; anything else is refused with
#: the accepted forms named in the error (never silently coerced).
_SCHEMES = ("mysql", "mysql+pymysql")
_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 3306
_DEFAULT_CHARSET = "utf8mb4"

#: Schema introspection — the OFFLINE MIRROR of the bridge's db_audit tables
#: query (bridge.php ``wpt_action_db_audit``). ``ORDER BY TABLE_NAME`` is the
#: bridge's own ordering, and it is what makes both the plan and the dump
#: deterministic. Contract-pinned by tests/test_dbconn.py.
TABLES_SQL = (
    "SELECT TABLE_NAME AS name, TABLE_ROWS AS row_count,"
    " ( DATA_LENGTH + INDEX_LENGTH ) / 1024 / 1024 AS size_mb,"
    " DATA_FREE / 1024 AS data_free_kb, TABLE_COLLATION AS collation"
    " FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()"
    " AND TABLE_TYPE = 'BASE TABLE' ORDER BY TABLE_NAME"
)

#: The bridge's RESERVED atomic-restore scratch-table names
#: (``wpt_restore_scratch_name``): only the bridge generates a name matching
#: this exact token pattern, and they are never a legitimate dump / audit /
#: optimize target. Mirrored here (same regex) so an offline run cannot
#: OPTIMIZE, report or re-dump bridge plumbing. Contract-pinned.
SCRATCH_NAME_RE = re.compile(r"__wpt_[0-9a-f]{8,16}__[so]$")

#: Structural dump bounds (documented facts about a MySQL server, NOT operator
#: tunables — the same kind of constant as the deadline/heartbeat bounds):
#: an extended INSERT is flushed once it would exceed the packet size every
#: server accepts comfortably, or once it holds more rows than mysqldump's
#: own default extended-insert batch.
_INSERT_BYTE_CAP = 1 << 20
_INSERT_ROW_CAP = 1000

#: Driver socket bounds are profile policy (``db.connect_timeout_s`` /
#: ``db.read_timeout_s``); a run deadline still caps both at what is left.

#: MySQL client error codes that mean the TCP/handshake attempt did not
#: reach an authenticating server (CR_CONNECTION_ERROR, CR_CONN_HOST_ERROR,
#: CR_UNKNOWN_HOST).  A wrong password/unknown database is NOT retried on
#: the next resolved address: repeating an authentication failure can trip
#: the site's lockout policy and only repeats the same verdict.
_CONNECT_ERROR_CODES = frozenset({2002, 2003, 2005})


def _is_connection_error(exc: BaseException) -> bool:
    """Would another ADDRESS plausibly succeed after ``exc``?"""
    if isinstance(exc, (ConnectionError, TimeoutError, OSError)):
        return True
    code = exc.args[0] if exc.args else None
    return isinstance(code, int) and code in _CONNECT_ERROR_CODES


class DbUriError(WptError):
    """A --db-uri (or its password) is unusable; reported as one clean line."""


# ------------------------------------------------------------------- the URI


@dataclass(frozen=True)
class DbUri:
    """A parsed ``--db-uri``. Printing one is always safe (redacted)."""

    host: str
    database: str
    user: str | None = None
    password: str | None = field(default=None, repr=False)
    port: int = _DEFAULT_PORT
    charset: str = _DEFAULT_CHARSET

    @property
    def redacted(self) -> str:
        """``mysql://user:***@host:port/db`` — the only printable form."""
        userinfo = ""
        if self.user:
            userinfo = self.user + (":***@" if self.password is not None else "@")
        return (f"mysql://{userinfo}{self.host}:{self.port}/{self.database}")

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.redacted

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"DbUri({self.redacted!r})"


def parse_db_uri(text: str) -> DbUri:
    """Parse the ONE accepted ``--db-uri`` form.

    ``mysql://[user[:password]@]host[:port]/database[?charset=utf8mb4]``
    (the ``mysql+pymysql://`` scheme is accepted as an alias; host defaults to
    127.0.0.1, port to 3306, charset to utf8mb4). The database name is
    REQUIRED: this URI names the source of DB data, so a DSN without a
    database has nothing to say. Percent-escapes in the userinfo and the
    database are decoded (a password may contain ``@``/``:``/``/``). Every
    rejection names the accepted form, because a silently misread DSN would
    connect somewhere the operator did not type.
    """
    raw = (text or "").strip()
    if not raw:
        raise DbUriError(
            "--db-uri is empty; expected "
            "mysql://[user[:password]@]host[:port]/database")
    try:
        parts = urlsplit(raw)
    except ValueError as exc:
        raise DbUriError(f"--db-uri is not a valid URL: {redact_text(str(exc))}") from None
    if parts.scheme.lower() not in _SCHEMES:
        raise DbUriError(
            f"--db-uri scheme {parts.scheme or '(none)'!r} is not supported; "
            "expected mysql://[user[:password]@]host[:port]/database")
    try:
        port = parts.port or _DEFAULT_PORT
    except ValueError:
        raise DbUriError(
            f"--db-uri port is not a number in {parts.netloc.rsplit('@', 1)[-1]!r}") from None
    try:
        host = parts.hostname or _DEFAULT_HOST
    except ValueError:
        raise DbUriError(
            f"--db-uri host is not a valid host or IPv6 literal in "
            f"{parts.netloc.rsplit('@', 1)[-1]!r}") from None
    # .hostname is the host WITHOUT the port (and lowercased, which DNS
    # makes free); the port came from .port above.
    database = unquote(parts.path.lstrip("/"))
    if not database:
        raise DbUriError(
            "--db-uri names no database; expected "
            "mysql://[user[:password]@]host[:port]/database")
    if parts.query:
        unknown = [k for k, _v in parse_qsl(parts.query) if k != "charset"]
        if unknown:
            raise DbUriError(
                f"--db-uri does not accept the parameter(s) {', '.join(sorted(unknown))};"
                " only charset= is understood")
    params = dict(parse_qsl(parts.query))
    userinfo, _at, _hostport = parts.netloc.rpartition("@")
    user = password = None
    if _at:
        user, _, password = userinfo.partition(":")
        user = unquote(user) or None
        password = unquote(password) if password else None
    return DbUri(
        host=host,
        database=database,
        user=user,
        password=password,
        port=port,
        charset=params.get("charset") or _DEFAULT_CHARSET,
    )


def resolve_db_password(uri: DbUri, env_var: str | None) -> str | None:
    """The database password: ``--db-password-env`` first, then the URI's.

    The env-var form is the SAME credential path the FTP password uses
    (:func:`wpt.config.resolve_password`, including its unset/empty refusal),
    so an operator has one convention to learn. When both are present the env
    var wins — it keeps the secret out of the command line, in the shell
    history and in the process table. ``None`` means "no password": a
    staging server may authenticate by socket or allowlist, and prompting for
    one it does not want would be a hang, not a convenience.
    """
    if env_var:
        from ..config import resolve_password

        return resolve_password(env_var, what="database password")
    return uri.password


# ------------------------------------------------------------ the connection


class DbConnection(Protocol):
    """The narrow DB surface the toolkit needs (the driver seam).

    Deliberately tiny and driver-agnostic so the whole offline path is
    testable without a server: every caller in wpt goes through these five
    methods, and a test double implements exactly them.
    """

    def query_rows(self, sql: str) -> list[tuple]: ...

    def stream_rows(self, sql: str) -> Iterator[tuple]: ...

    def execute(self, sql: str) -> int:
        """Run one mutating statement; return the affected row count."""

    def show_create_table(self, table: str) -> str: ...

    def close(self) -> None: ...


def connect(uri: DbUri, *, password: str | None = None,
            deadline: "Deadline | None" = None,
            settings: DbSettings | None = None) -> DbConnection:
    """Open a connection to ``uri`` (the ONE driver import site).

    A missing driver is a one-line WptError naming the package and the
    install command — an operator must never be shown an ImportError
    traceback for a feature that is one ``pip install`` away.

    ``deadline`` caps BOTH driver timeouts at the remaining run budget and
    is stored on the connection so every later query checks it first.  The
    undeadlined bounds are ``db.connect_timeout_s`` / ``db.read_timeout_s``.
    """
    cfg = settings or DbSettings()
    try:
        import pymysql  # noqa: PLC0415 — the deliberate lazy import point
    except ImportError:
        raise DbUriError(
            f"--db-uri needs the {DRIVER_PACKAGE} driver "
            f'(install: python3 -m pip install "{DRIVER_PACKAGE}")'
        ) from None
    remaining = deadline.remaining if deadline is not None else None
    if remaining is not None:
        deadline.check("database connect")
    host = uri.host
    addresses: list[str] | None = None
    # Resolve under a FINITE request bound even on an unbounded run: a libc
    # getaddrinfo stall otherwise held the connect for minutes (measured
    # 21.5 s against a 10 s connect bound).  A run deadline still wins when
    # it is earlier.
    resolve_at = monotonic() + cfg.connect_timeout_s
    if deadline is not None:
        resolve_at = min(resolve_at, deadline.at)
    if not is_numeric_host(host):
        try:
            addresses = resolve_host_bounded(
                host, uri.port, resolve_at,
                label="database host DNS resolution",
                thread_name="wpt-db-dns")
        except WptError:
            if deadline is not None:
                deadline.check("database connect")
            raise
        # DNS consumed budget: every driver timeout must be recomputed from
        # what is LEFT, and the budget checked before each dial.
        if deadline is not None:
            deadline.check("database connect")
    candidates: list[str] = addresses if addresses else [host]
    last_error: Exception | None = None
    raw = None
    for attempt, address in enumerate(candidates):
        if deadline is not None:
            deadline.check("database connect")
            remaining = deadline.remaining
            if remaining <= 0:
                deadline.check("database connect")
            # PER-ATTEMPT SHARE of the remaining budget: a refused first
            # address must leave the later ones a real chance to connect
            # instead of one attempt eating the whole run budget.
            attempts_left = len(candidates) - attempt
            connect_timeout = max(
                0.001, min(cfg.connect_timeout_s, remaining / attempts_left))
            # The GREETING is part of the CONNECT, not a query: giving it
            # the whole remaining budget let an address that accepts TCP
            # and never sends a handshake consume the run, so the later
            # resolved address was never dialed (measured: 0.6 s budget,
            # first address read_timeout=0.6, second never tried).  Share
            # the per-attempt bound with the dial.
            io_timeout = connect_timeout
        else:
            connect_timeout = cfg.connect_timeout_s
            # An unbounded run still must not wait 300 s for a greeting.
            # The post-connect query owner restores its own read bound.
            io_timeout = cfg.connect_timeout_s
        try:
            raw = pymysql.connect(
                host=address,
                port=uri.port,
                user=uri.user or None,
                password=password or "",
                database=uri.database,
                charset=uri.charset,
                autocommit=True,   # one statement = one commit, like wpdb
                connect_timeout=connect_timeout,
                read_timeout=io_timeout,
                write_timeout=io_timeout,
            )
        except RunControl:
            raise
        except Exception as exc:
            last_error = exc
            if attempt + 1 < len(candidates) and _is_connection_error(exc):
                log.debug(
                    "database connect to %s failed (%s); trying the next "
                    "resolved address", address, type(exc).__name__)
                continue
            break
        break
    if raw is None:
        assert last_error is not None
        # The driver's own message can quote the DSN; redact unconditionally.
        raise DbUriError(
            f"cannot connect to {uri.redacted}: "
            f"{redact_text(str(last_error))}") from None
    if deadline is not None:
        try:
            deadline.check("database connect")
        except BaseException:
            # The connection was OPENED, then the post-connect budget
            # check refused the run.  Leaving it open leaks a live server
            # session (and its socket) for the rest of the process.
            try:
                raw.close()
            except Exception:  # noqa: BLE001 — preserve the deadline stop
                pass
            raise
    log.info("connected to %s (driver %s)", uri.redacted,
             getattr(pymysql, "__version__", "?"))
    return _PyMySqlConnection(
        raw, deadline=deadline, read_timeout_s=cfg.read_timeout_s)


class _PyMySqlConnection:
    """:class:`DbConnection` over a PyMySQL connection.

    The DRIVER BOUNDARY: every driver exception becomes a
    :class:`~wpt.types.WptError` here, so the command bodies' existing
    "WptError/OSError -> log.error + rc 1" contract holds without any of
    them knowing a database driver exists (and no run ever ends in a
    traceback because a server answered oddly).
    """

    def __init__(self, raw, deadline: "Deadline | None" = None,
                 read_timeout_s: float | None = None) -> None:
        self._raw = raw
        self._deadline = deadline
        self._read_timeout_s = (
            read_timeout_s if read_timeout_s is not None
            else DbSettings().read_timeout_s
        )
    def _check(self, context: str) -> None:
        if self._deadline is not None:
            self._deadline.check(context)

    def _refresh_timeouts(self, context: str) -> None:
        """Re-arm the driver's read/write bound from what is LEFT.

        ``connect()`` used to fix read_timeout at the remaining budget once;
        a long run then kept a 300 s (or original) per-read timeout for
        every later query, and a single statement could outlive the whole
        budget.  The driver's socket timeout is lowered to the remaining
        budget before each query; the post-query check turns a fake/driver
        that ignored it into the same DeadlineExceeded.
        """
        if self._deadline is None:
            # The CONNECT deliberately uses a short handshake bound; a
            # normal query keeps the driver's historical read bound.
            timeout = self._read_timeout_s
        else:
            remaining = self._deadline.remaining
            if remaining <= 0:
                self._deadline.check(context)
            timeout = max(0.001, min(self._read_timeout_s, remaining))
        raw = self._raw
        for attr in ("read_timeout", "write_timeout",
                     "_read_timeout", "_write_timeout"):
            if hasattr(raw, attr):
                try:
                    setattr(raw, attr, timeout)
                except (AttributeError, TypeError):
                    pass
        sock = getattr(raw, "_sock", None)
        if sock is not None:
            try:
                sock.settimeout(timeout)
            except (OSError, ValueError):
                pass

    @contextmanager
    def _driver_errors(self, sql: str):
        try:
            yield
        except RunControl:
            # The run budget expiry is not a database fault: never convert
            # it into the operational WptError contract.
            raise
        except WptError:
            raise
        except Exception as exc:
            raise WptError(f"database error: {redact_text(str(exc))}") from None

    def query_rows(self, sql: str) -> list[tuple]:
        self._refresh_timeouts("database query")
        with self._driver_errors(sql):
            with self._raw.cursor() as cursor:
                cursor.execute(sql)
                rows = list(cursor.fetchall())
        self._check("database query")
        return rows

    def stream_rows(self, sql: str) -> Iterator[tuple]:
        """Unbuffered rows (the dump must never buffer a whole table)."""
        from pymysql.cursors import SSCursor  # noqa: PLC0415

        self._refresh_timeouts("database query")
        cursor = self._raw.cursor(SSCursor)
        try:
            with self._driver_errors(sql):
                cursor.execute(sql)
                self._check("database query")
                while True:
                    self._refresh_timeouts("database query")
                    row = cursor.fetchone()
                    if row is None:
                        return
                    yield row
        finally:
            cursor.close()

    def execute(self, sql: str) -> int:
        self._refresh_timeouts("database query")
        with self._driver_errors(sql):
            with self._raw.cursor() as cursor:
                cursor.execute(sql)
                affected = max(0, int(cursor.rowcount or 0))
        self._check("database query")
        return affected

    def show_create_table(self, table: str) -> str:
        rows = self.query_rows(f"SHOW CREATE TABLE {quote_ident(table)}")
        if not rows or len(rows[0]) < 2:
            raise WptError(f"SHOW CREATE TABLE {table!r} returned no DDL")
        return str(rows[0][1])

    def close(self) -> None:
        try:
            self._raw.close()
        except Exception as exc:  # pragma: no cover - driver-specific
            log.warning("db connection close failed: %s", redact_text(str(exc)))


# --------------------------------------------------------------- identifiers


def quote_ident(name: str) -> str:
    """A backtick-quoted identifier (a backtick inside it is doubled).

    The bridge's ``wpt_backtick`` rule, verbatim — the identifiers here come
    from information_schema, so quoting is total, not hopeful.
    """
    return "`" + str(name).replace("`", "``") + "`"


def is_scratch_table(name: str) -> bool:
    """True for a bridge-owned atomic-restore scratch table (never dumped)."""
    return bool(SCRATCH_NAME_RE.search(str(name)))


def schema_tables(conn: DbConnection) -> list[dict[str, Any]]:
    """The schema's base tables in the bridge's db_audit row shape.

    ONE query (:data:`TABLES_SQL`, the bridge's own) with the bridge's own
    reserved-name filter applied here in Python, so the offline audit and the
    re-dump can never enumerate a table the bridge would have hidden.
    """
    rows: list[dict[str, Any]] = []
    for row in conn.query_rows(TABLES_SQL):
        if not row:
            continue
        name = str(row[0] or "")
        if not name or is_scratch_table(name):
            continue
        rows.append({
            "name": name,
            "rows": int(row[1] or 0) if _is_number(row[1]) else 0,
            "size_mb": round(float(row[2] or 0.0), 3) if _is_number(row[2]) else 0.0,
            "data_free_kb": round(float(row[3] or 0.0), 1) if _is_number(row[3]) else 0.0,
            "collation": str(row[4] or "") if len(row) > 4 and row[4] is not None else "",
        })
    return rows


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float, Decimal)) and not isinstance(value, bool)


# --------------------------------------------------------------- dump writer

#: MySQL string-literal escapes (the set mysqldump itself emits).
_ESCAPES = {
    0x00: "\\0", 0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0D: "\\r",
    0x1A: "\\Z", 0x22: '\\"', 0x27: "\\'", 0x5C: "\\\\",
}

#: The dump preamble/restorer, the standard mysqldump frame. Version-gated
#: comments (/*!40101 ... */) are what a real mysqldump writes and every
#: server from 4.1 on understands them; the analyzer skips them.
_PREAMBLE = (
    "/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;\n"
    "/*!40101 SET NAMES utf8mb4 */;\n"
    "/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS,"
    " FOREIGN_KEY_CHECKS=0 */;\n"
    "/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;\n"
)
_RESTORE = (
    "/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;\n"
    "/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;\n"
    "/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;\n"
)


@dataclass
class DumpStats:
    """What a re-dump actually wrote (logged; never a claim without proof)."""

    path: Path
    tables: int
    rows: int
    bytes: int


def escape_value(value: Any) -> str:
    """One cell as a MySQL literal (the writer's only value rendering).

    * ``None`` -> ``NULL``; numbers and ``Decimal`` unquoted (Decimal
      formatted fixed-point: an exponent form is not portable across
      servers).
    * ``datetime``/``date``/``time``/``timedelta`` -> the quoted canonical
      text mysqldump writes.
    * ``bytes`` that are not valid UTF-8 -> a ``0x...`` hex literal, the
      lossless form for a BLOB; valid UTF-8 is treated as text.
    * everything else -> a quoted, escaped string.
    """
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, datetime):
        return "'" + value.strftime("%Y-%m-%d %H:%M:%S") + "'"
    if isinstance(value, date):
        return "'" + value.strftime("%Y-%m-%d") + "'"
    if isinstance(value, time):
        return "'" + value.strftime("%H:%M:%S") + "'"
    if isinstance(value, timedelta):
        total = int(value.total_seconds())
        sign = "-" if total < 0 else ""
        total = abs(total)
        return f"'{sign}{total // 3600:02d}:{total % 3600 // 60:02d}:{total % 60:02d}'"
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        try:
            return _quote_text(raw.decode("utf-8"))
        except UnicodeDecodeError:
            return "0x" + raw.hex()
    return _quote_text(str(value))


def _quote_text(text: str) -> str:
    out = ["'"]
    for char in text:
        code = ord(char)
        escape = _ESCAPES.get(code)
        out.append(escape if escape is not None else char)
    out.append("'")
    return "".join(out)


def dump_database(conn: DbConnection, path: Path, *,
                  source: str = "", deadline: "Deadline | None" = None) -> DumpStats:
    """Write a mysqldump-style dump of the connected database to ``path``.

    Structure (what a real mysqldump produces, and what
    ``wpt.localmode.analyzer`` parses back): the standard ``SET`` preamble,
    then per base table — ``DROP TABLE IF EXISTS``, the server's own
    ``SHOW CREATE TABLE`` DDL, and batched extended ``INSERT``s — then the
    restoring preamble and a completion marker. Rows stream one at a time
    (never a whole table in memory) and there is no ``LOCK TABLES``: a
    WordPress database is InnoDB, where the snapshot below already gives a
    consistent read.

    Three safety properties, all structural:

    * **consistent snapshot.** The dump opens
      ``START TRANSACTION WITH CONSISTENT SNAPSHOT`` (a non-locking read
      view — no row locks, nothing blocked) and closes it in a ``finally``,
      so every table in the artifact is as of one instant. A server that
      refuses the statement is ONE warning, not a failed dump: the artifact
      is still written, and the operator is told it may mix concurrent
      changes.
    * **tmp-then-rename.** The bytes land in a UNIQUE sibling temp created
      with ``os.open(O_CREAT|O_EXCL|O_NOFOLLOW)`` — never a fixed
      ``<path>.part`` that an earlier run or an attacker could have planted
      as a symlink, FIFO or read-only file — and are installed only after
      the whole dump succeeded, so a failed or deadline-expired dump never
      leaves an artifact that looks importable.  The temp name is recorded
      BEFORE creation and is removed on every failure (fail-closed cleanup,
      the snapshot rule).
    * **no silent overwrite.** An existing ``path`` is refused: a dump IS a
      rollback artifact, and clobbering the previous one with a half-derived
      successor is exactly the kind of quiet loss this toolkit refuses.  The
      install is a hard link, which fails atomically if the path appeared
      while the dump was running.

    The per-table loop checks ``deadline`` between tables and INSERT flushes,
    so a re-dump of a huge database ends the run itself rather than running
    past ``--deadline``.
    """
    target = Path(path)
    if target.exists():
        raise WptError(
            f"refusing to overwrite the existing {target} — a dump is a "
            "rollback artifact; choose another --re-dump path")
    tables = [row["name"] for row in schema_tables(conn)]
    log.info("re-dump: %d table(s) from the database to %s", len(tables), target)
    rows_written = 0
    tmp: Path | None = None
    fd = -1
    try:
        if deadline is not None:
            # Check BEFORE creating/reserving anything: a spent run must not
            # leave a temp behind, and reserving a name is work.
            deadline.check("re-dump setup")
        for _ in range(100):
            candidate = target.parent / (
                f".{target.name}.{secrets.token_hex(8)}.part")
            # Register the name BEFORE creating it: a stop between the
            # successful open and the assignment used to leave an
            # unreferenced ``.part`` that no cleanup could remove.
            tmp = candidate
            try:
                fd = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600)
            except FileExistsError:
                tmp = None
                continue
            break
        if fd < 0 or tmp is None:
            raise WptError(
                f"cannot reserve a temp file beside re-dump target {target}")
        try:
            _begin_snapshot(conn)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                fd = -1
                handle.write(f"-- wpt re-dump (mysqldump-compatible) — {target.name}\n")
                handle.write(f"-- source: {redact_text(source)}\n")
                handle.write(_PREAMBLE)
                for name in tables:
                    if deadline is not None:
                        deadline.check(f"re-dump of {name}")
                    handle.write(f"\n--\n-- Table structure for {quote_ident(name)}\n--\n\n")
                    handle.write(f"DROP TABLE IF EXISTS {quote_ident(name)};\n")
                    ddl = conn.show_create_table(name).rstrip().rstrip(";")
                    handle.write(f"{ddl};\n\n")
                    handle.write(f"--\n-- Dumping data for table {quote_ident(name)}\n--\n\n")
                    rows_written += _dump_table(conn, handle, name, deadline=deadline)
                handle.write(_RESTORE)
                handle.write("\n-- Dump completed\n")
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            # The snapshot close is INSIDE the guarded region: a
            # DeadlineExceeded/StopRequested raised by COMMIT used to escape
            # from the outer finally, replacing the verdict and skipping the
            # temp unlink (a complete `.part` remained).
            _end_snapshot(conn)
    except BaseException:
        # Includes DeadlineExceeded and KeyboardInterrupt from the body OR
        # from the COMMIT: a partial dump is never left behind for an
        # operator to mistake for an artifact.
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp is not None:
            tmp.unlink(missing_ok=True)
        raise
    try:
        # A hard link installs the temp ONLY when the target name is still
        # absent: os.replace would silently clobber a file created while
        # the dump ran.  The temp is in the target's own directory, so the
        # link cannot cross a filesystem boundary.
        os.link(tmp, target)
    except FileExistsError:
        tmp.unlink(missing_ok=True)
        raise WptError(
            f"refusing to overwrite the existing {target} — it appeared "
            "while the re-dump was running; the dump was discarded")
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    else:
        tmp.unlink(missing_ok=True)
    size = target.stat().st_size
    log.info("re-dump written: %s (%d table(s), %d row(s), %d bytes)",
             target, len(tables), rows_written, size)
    return DumpStats(path=target, tables=len(tables), rows=rows_written, bytes=size)


def _begin_snapshot(conn: DbConnection) -> None:
    """Open a consistent read view; a server that refuses it warns only."""
    try:
        conn.execute("START TRANSACTION WITH CONSISTENT SNAPSHOT")
    except Exception as exc:
        log.warning("re-dump: this server refused a consistent snapshot (%s); "
                    "the dump may mix concurrent changes",
                    redact_text(str(exc)))


def _end_snapshot(conn: DbConnection) -> None:
    """Close the read view (a COMMIT with no open transaction is a no-op)."""
    try:
        conn.execute("COMMIT")
    except Exception as exc:  # pragma: no cover - server-specific
        log.warning("re-dump: could not close the read view: %s",
                    redact_text(str(exc)))


def _dump_table(conn: DbConnection, handle, table: str, *,
                deadline: "Deadline | None" = None) -> int:
    """One table's rows as batched extended INSERTs; returns the row count."""
    ident = quote_ident(table)
    pending: list[str] = []
    pending_bytes = 0
    total = 0
    for row in conn.stream_rows(f"SELECT * FROM {ident}"):
        rendered = "(" + ",".join(escape_value(cell) for cell in row) + ")"
        pending.append(rendered)
        pending_bytes += len(rendered) + 1
        total += 1
        if pending_bytes >= _INSERT_BYTE_CAP or len(pending) >= _INSERT_ROW_CAP:
            handle.write(f"INSERT INTO {ident} VALUES "
                         + ",".join(pending) + ";\n")
            pending, pending_bytes = [], 0
            if deadline is not None:
                deadline.check(f"re-dump of {table}")
    if pending:
        handle.write(f"INSERT INTO {ident} VALUES " + ",".join(pending) + ";\n")
    return total
