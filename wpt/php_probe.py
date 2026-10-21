"""Standalone, token-gated PHP runtime probe (SPEC ``probe`` settings).

The diagnostic that still answers when ``wp-load.php``, the database or PDO
are broken — the exact state the WordPress bridge can never report.  This
module is deliberately NOT the bridge: the PHP template (``php_probe.php``,
packaged beside this file) loads no WordPress and includes nothing, so a
deployment needs only the webroot and a public URL.

Lifecycle: :meth:`PhpProbe.ensure` deploys one ``wpt-probe-<8hex>.php`` at the
webroot root with a fresh 32-hex token and a ``$wpt_expires = '<unix-ts>';``
literal; :meth:`PhpProbe.call` GETs it with that token; :meth:`destroy`
removes it.  The template also ``@unlink(__FILE__)``s after a successful
answer, so a normal run leaves nothing behind even if teardown is skipped.
:func:`sweep_stale_probes` removes an EXPIRED file a killed run left; a file
whose embedded expiry is still in the future may be a concurrent sibling
run's live probe and is never touched (the bridge sweep's rule).

Security: the token never reaches a log line or an exception (requests'
exceptions embed the request URL, so transport failures are sanitized and
re-raised without their chain), and a name collision is retried under a
fresh name AND token rather than overwriting whatever is already there.
"""

from __future__ import annotations

import re
import secrets
import select
import socket
import ssl
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import requests
from requests.structures import CaseInsensitiveDict
from requests.utils import select_proxy, urldefragauth
from urllib3.util.proxy import connection_requires_http_tunnel

from .bridge_name import (PROBE_NAME_RE, probe_name,
                          render_endpoint_template)
from .endpoint import sweep_expired_endpoints
from .config import redact_text
from .jsonutil import loads_bounded
from .log import get_logger
from .netresolve import (DNS_WORKER_LIMIT, DNS_WORKERS, is_numeric_host,
                         resolve_host_bounded)
from .settings import ProbeSettings
from .teardown import source_cleanup_budget
from .types import (DeadlineExceeded, Source, StopRequested,
                    WptError, delete_or_prove_absent, path_may_exist)

log = get_logger("php_probe")

#: The packaged PHP template.  Read once per deployment (a profile switch or
#: an operator edit is picked up without a restart), never cached.
_PHP_TEMPLATE = Path(__file__).resolve().parent / "php_probe.php"

#: The deployed-name contract.  It is exactly the profile's
#: ``web_script.known_artifacts`` entry ``wpt-probe-????????.php`` (a '?' is
#: ONE HEX DIGIT there), LOWERCASE because ``secrets.token_hex`` emits
#: lowercase; the sweep matches this full name and nothing wider.
# (PROBE_NAME_RE is imported from wpt.bridge_name — the ONE owner shared
# with backup/restore's endpoint predicate.)

#: The embedded expiry literal — the SAME shape the stale-bridge sweep reads,
#: so one ``$wpt_expires = '<unix-ts>';`` convention describes both wpt
#: endpoints.  The sweep deletes on the FILE's own literal, never on this
#: run's TTL: a sibling run's file carries its own deployment clock.  Parsed
#: by ``bridge_name.endpoint_expiry`` (shared with the bridge sweep).

#: 16 random bytes = the 32 hex chars the wire contract names; 4 bytes = the
#: 8-hex-name suffix.  Structural, not tunables.
_TOKEN_BYTES = 16
_SUFFIX_BYTES = 4

#: Body excerpt bound for an unreadable answer (the bridge's own bound).
_EXCERPT_LIMIT = 200

#: The largest probe-shaped file the stale sweep will read.  A real probe is
#: a few KB; a matching name carrying megabytes is not ours to parse.
_PROBE_READ_LIMIT = 64 * 1024

#: The largest HTTP answer body the probe call will hold.  The runtime
#: payload is a few KB; a challenge/error page must not be buffered whole.
_BODY_LIMIT = 256 * 1024

#: Final HTTP statuses whose semantics terminate the message at the end of
#: the header section (RFC 9110 §15.3.6 / §15.4.6): an absent body is not a
#: transport timeout even when the peer keeps the connection alive without
#: a Content-Length.  1xx is handled separately (interim vs 101).
BODYLESS_STATUSES = frozenset({204, 205, 304})


#: Header/chunk-line bounds for the bounded socket reader.  A hostile peer
#: must not make the probe hold an unbounded header block or chunk line.
_HEADER_LIMIT = 64 * 1024
_CHUNK_LINE_LIMIT = 8 * 1024
_READ_SIZE = 64 * 1024

#: The ONE chunk-size grammar shared with the proxy's upstream reader
#: (``wpt.dnsoverride`` imports this).  A bare ``int(line, 16)`` accepted
#: ``+5`` and ``0x5`` and read an EMPTY size line as the terminal zero chunk,
#: so a malformed peer produced a complete empty body instead of a transport
#: error.  Hex only, at least one digit, no sign/prefix.
CHUNK_SIZE_RE = re.compile(rb"[0-9A-Fa-f]{1,16}")
#: ``Content-Length`` is decimal digits only: ``int()`` accepted ``-1`` (and
#: ``+5``), turning a malformed declaration into an immediate empty body.
CONTENT_LENGTH_RE = re.compile(r"[0-9]+")

_HEADER_TIMEOUT = (
    "probe request exceeded the absolute timeout before the response "
    "headers arrived"
)
_BODY_TIMEOUT = (
    "probe body read exceeded the absolute timeout; the answer arrived too "
    "slowly to trust"
)


def _body_text(response: Any, deadline: float | None = None) -> str:
    """Read at most ``_BODY_LIMIT`` bytes of a streamed answer as text.

    ``stream=True`` stops the transport from buffering an arbitrary error or
    challenge page; this helper stops the client from holding one either.
    ``deadline`` is an ABSOLUTE ``time.monotonic()`` bound: requests'
    ``timeout`` resets on every socket read, so a server dripping one byte
    per read could otherwise keep the loop alive for hours.
    A response double without ``iter_content`` (the test fake) falls back to
    its own ``text``, already bounded by the caller's excerpt.
    """
    iterator = getattr(response, "iter_content", None)
    if not callable(iterator):
        text = getattr(response, "text", "")
        return text if isinstance(text, str) else str(text)
    chunks: list[bytes] = []
    total = 0
    for chunk in iterator(chunk_size=8192):
        if deadline is not None and time.monotonic() > deadline:
            raise WptError(
                "probe body read exceeded the absolute timeout; the answer "
                "arrived too slowly to trust")
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8", "replace")
        chunks.append(chunk)
        total += len(chunk)
        if total >= _BODY_LIMIT:
            break
    return b"".join(chunks)[:_BODY_LIMIT].decode("utf-8", "replace")


def _wait_readable(sock: Any, deadline: float) -> bool:
    """Wait until ``sock`` is readable or the absolute deadline expires."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return False
    try:
        readable, _, _ = select.select([sock], [], [], remaining)
    except (OSError, ValueError):
        return False
    return bool(readable)


def _set_nonblocking(sock: Any) -> None:
    """Switch a transport socket to non-blocking reads.

    ``socket.socket`` and ``ssl.SSLSocket`` expose ``setblocking``;
    urllib3's ``SSLTransport`` (TLS-in-TLS, used when the proxy itself is
    ``https://``) implements the socket-API subset urllib3 needs but only
    offers ``settimeout``.  ``settimeout(0)`` is its non-blocking mode: the
    same ``BlockingIOError``/``SSLWant*Error`` contract the ``select`` loop
    below already handles for the plain and TLS-to-origin sockets.
    """
    setblocking = getattr(sock, "setblocking", None)
    if callable(setblocking):
        setblocking(False)
    else:
        sock.settimeout(0)


def _recv_bounded(sock: Any, deadline: float, *,
                  body: bool) -> bytes:
    """One non-blocking socket read bounded by the absolute deadline.

    The socket is in non-blocking mode, so no single ``recv`` can outlive a
    peer that drips bytes below a per-read timeout (PHP1).  ``select`` waits
    only for the remaining budget, and a timeout closes the caller's socket.
    """
    error = _BODY_TIMEOUT if body else _HEADER_TIMEOUT
    while True:
        try:
            return sock.recv(_READ_SIZE)
        except (BlockingIOError, InterruptedError):
            pass
        except ssl.SSLWantReadError:
            pass
        except ssl.SSLWantWriteError:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise WptError(error) from None
            try:
                _, writable, _ = select.select([], [sock], [], remaining)
            except (OSError, ValueError):
                raise WptError(error) from None
            if not writable:
                raise WptError(error) from None
            continue
        except (socket.timeout, TimeoutError):
            raise WptError(error) from None
        except ssl.SSLError as exc:
            # A TLS protocol failure is a TRANSPORT failure, not a bare
            # OSError escaping the reader's contract (the chunked/closed
            # paths already raise requests.ConnectionError).
            raise requests.ConnectionError(
                f"probe body read failed ({type(exc).__name__})") from exc
        except OSError as exc:
            # A reset/aborted connection is the documented per-fetch
            # transport failure.  Letting the raw OSError escape bypassed
            # WpOrgApi's one-warning/stale-cache degrade and aborted the
            # whole audit.
            raise requests.ConnectionError(
                f"probe body read failed ({type(exc).__name__})") from exc
        if not _wait_readable(sock, deadline):
            raise WptError(error) from None


def _read_response_head(
    sock: Any, deadline: float
) -> tuple[int, dict[str, str], bytes]:
    """Read and parse FINAL response headers under the absolute deadline.

    Intermediates are not answers: RFC 9110 permits any number of 1xx
    interim responses (100 Continue, 103 Early Hints) before the final
    status, each with its own header block.  Returning the first status made
    a valid 103-then-200 answer fail as ``HTTP 103``.  ``101 Switching
    Protocols`` is final for this client (it is not an HTTP body answer), so
    it is returned, not skipped.
    """
    buffer = bytearray()
    while True:
        marker = buffer.find(b"\r\n\r\n")
        if marker == -1:
            if len(buffer) > _HEADER_LIMIT:
                raise WptError(
                    f"probe response headers exceeded the {_HEADER_LIMIT}-byte "
                    "bound")
            chunk = _recv_bounded(sock, deadline, body=False)
            if not chunk:
                raise requests.ConnectionError(
                    "probe connection closed before the response headers "
                    "arrived")
            buffer.extend(chunk)
            # The bound is enforced AFTER every extension too: a peer that
            # sends a whole over-limit block (terminator included) in one
            # read never hit the pre-read check, so ~2x the limit was
            # accepted (R15-P2).
            if len(buffer) > _HEADER_LIMIT:
                raise WptError(
                    f"probe response headers exceeded the {_HEADER_LIMIT}-byte "
                    "bound")
            continue
        if marker > _HEADER_LIMIT:
            raise WptError(
                f"probe response headers exceeded the {_HEADER_LIMIT}-byte "
                "bound")
        head = bytes(buffer[:marker])
        del buffer[:marker + 4]
        status, headers = _parse_response_head(head)
        if 100 <= status < 200 and status != 101:
            # Another head follows on the SAME stream.  It may already be in
            # `buffer`; the loop parses it before another recv.
            continue
        return status, headers, bytes(buffer)


def _parse_response_head(
        head: bytes) -> tuple[int, CaseInsensitiveDict[str]]:
    """Parse one status line + header block (no body bytes).

    The header map is CASE-INSENSITIVE: wire headers are lowercased here,
    while doctor's policy row (and every other requests-shaped consumer)
    looks up ``Location``/``Strict-Transport-Security`` with their canonical
    spelling.  A plain lowercased dict made a correctly forced site read as
    unforced in the real transport while the capitalized test doubles passed.
    """
    lines = head.split(b"\r\n")
    parts = lines[0].decode("latin-1").split(None, 2)
    if len(parts) < 2 or not parts[0].upper().startswith("HTTP/"):
        raise requests.ConnectionError(
            "probe answered with a malformed HTTP status line")
    try:
        status = int(parts[1])
    except ValueError:
        raise requests.ConnectionError(
            "probe answered with a non-numeric HTTP status") from None
    headers: CaseInsensitiveDict[str] = CaseInsensitiveDict()
    for line in lines[1:]:
        name, sep, value = line.decode("latin-1").partition(":")
        if not sep:
            continue
        key = name.strip().lower()
        text = value.strip()
        # Repeated fields are a comma-joined list (RFC 9110 §5.3).  The old
        # assignment kept only the LAST value: ``max-age=0`` followed by
        # ``max-age=31536000`` read as a forced site, so duplicate HSTS
        # turned a non-conforming (ignored) header into a false PASS.
        if key in headers:
            headers[key] = f"{headers[key]}, {text}"
        else:
            headers[key] = text
    return status, headers


class _RawBodyReader:
    """Bounded ``raw.read1`` adapter over one :class:`_SocketResponse`.

    ``requests``/urllib3 call ``read1(amt, decode_content=True)`` and expect
    "whatever is available, never more than ``amt``".  The underlying
    ``iter_content`` generator already reads under the response's absolute
    deadline and framing; this adapter keeps ONE generator so repeated
    ``read1`` calls never restart the body.
    """

    def __init__(self, owner: _SocketResponse) -> None:
        self._owner = owner
        self._iterator: Any = None

    def read1(self, amount: int = 65536,
              decode_content: bool | None = None) -> bytes:
        # ``decode_content`` is urllib3's gzip hook; the bounded transport
        # does not advertise Content-Encoding decoding, so it is irrelevant.
        # The parameter is part of urllib3's read1 interface, not an input
        # this adapter consumes.
        del decode_content
        if self._owner._content is not None:
            return b""
        if self._iterator is None:
            size = 65536 if amount is None else max(1, int(amount))
            self._iterator = self._owner.iter_content(chunk_size=size)
        try:
            return next(self._iterator)
        except StopIteration:
            return b""


class _SocketResponse:
    """Minimal streamed HTTP response over the session's own connection.

    ``iter_content`` mirrors requests' contract for the one consumer
    (:func:`_body_text`): byte chunks, bounded by the absolute deadline.
    """

    def __init__(self, conn: Any, sock: Any, status_code: int,
                 headers: CaseInsensitiveDict[str], buffered: bytes,
                 deadline: float, url: str = "") -> None:
        self._conn = conn
        self._sock = sock
        self.status_code = status_code
        self.headers = headers
        self.url = url
        self._buffered = buffered
        self._deadline = deadline
        self._closed = False
        #: Fully-read body bytes.  requests' ``Response`` exposes the same
        #: attribute after ``_read_body_bounded``; keeping it here means
        #: ``text``/``json``/``iter_lines`` still answer after the socket was
        #: closed by that bounded read.
        self._content: bytes | None = None
        #: True when :meth:`preload_prefix` stopped at the caller's bound
        #: before the body ended.  Consumers that only need status/headers
        #: or a bounded prefix (the security probes) must still treat the
        #: response as an ANSWER, never as "the site did not answer".
        self.body_truncated = False

    def _recv_body(self, limit: int) -> bytes:
        if self._buffered:
            chunk = self._buffered[:limit]
            self._buffered = self._buffered[len(chunk):]
            return chunk
        chunk = _recv_bounded(self._sock, self._deadline, body=True)
        if len(chunk) > limit:
            self._buffered = chunk[limit:]
            chunk = chunk[:limit]
        return chunk

    def _read_exact(self, count: int) -> bytes:
        out = bytearray()
        while len(out) < count:
            chunk = self._recv_body(count - len(out))
            if not chunk:
                raise requests.ConnectionError(
                    "probe connection closed before the response body "
                    "completed")
            out.extend(chunk)
        return bytes(out)

    def _read_line(self) -> bytes:
        while b"\r\n" not in self._buffered:
            if len(self._buffered) > _CHUNK_LINE_LIMIT:
                raise requests.ConnectionError(
                    "probe returned an oversized chunked-body line")
            chunk = _recv_bounded(self._sock, self._deadline, body=True)
            if not chunk:
                raise requests.ConnectionError(
                    "probe connection closed in a chunked response body")
            self._buffered += chunk
        line, _, self._buffered = self._buffered.partition(b"\r\n")
        return line

    def iter_content(self, chunk_size: int = 8192) -> Any:
        chunk_size = max(1, int(chunk_size))
        if self._content is not None:
            for offset in range(0, len(self._content), chunk_size):
                yield self._content[offset:offset + chunk_size]
            return
        # RFC 9110: 1xx/204/205/304 responses have no body, regardless of
        # any Content-Length header the peer sent.  Treating the declared
        # length as payload made a legal 304/205 hold the call until the
        # body timeout (then report a transport failure instead of HTTP 304).
        if 100 <= self.status_code < 200 \
                or self.status_code in BODYLESS_STATUSES:
            self._buffered = b""
            return
        if "chunked" in self.headers.get("transfer-encoding", "").lower():
            yield from self._iter_chunked(chunk_size)
            return
        length = self.headers.get("content-length")
        if length is not None:
            stripped = length.strip()
            if CONTENT_LENGTH_RE.fullmatch(stripped) is None:
                raise requests.ConnectionError(
                    "probe answered with a malformed Content-Length")
            remaining = int(stripped)
            while remaining > 0:
                chunk = self._recv_body(min(chunk_size, remaining))
                if not chunk:
                    raise requests.ConnectionError(
                        "probe connection closed before the response body "
                        "completed")
                remaining -= len(chunk)
                yield chunk
            return
        while True:
            chunk = self._recv_body(chunk_size)
            if not chunk:
                return
            yield chunk

    def _iter_chunked(self, chunk_size: int) -> Any:
        while True:
            line = self._read_line()
            size_text = line.split(b";", 1)[0].strip()
            if CHUNK_SIZE_RE.fullmatch(size_text) is None:
                raise requests.ConnectionError(
                    "probe returned a malformed chunked response body")
            size = int(size_text, 16)
            if size == 0:
                # Consume the trailer section up to its blank line.
                while self._read_line() != b"":
                    pass
                return
            remaining = size
            while remaining:
                chunk = self._recv_body(min(chunk_size, remaining))
                if not chunk:
                    raise requests.ConnectionError(
                        "probe connection closed in a chunked response body")
                remaining -= len(chunk)
                yield chunk
            if self._read_exact(2) != b"\r\n":
                raise requests.ConnectionError(
                    "probe returned a malformed chunked response body")

    @property
    def raw(self) -> "_RawBodyReader":
        """The urllib3-style ``read1`` seam requests responses expose.

        The bridge's bounded body/stream readers prefer ``raw.read1`` so
        they check the absolute budget at the socket's own pace instead of
        falling back to ``iter_content(chunk_size=1)``.  Without this
        property every non-stream bridge answer under a run deadline was
        read one byte at a time (O(n²)).
        """
        return _RawBodyReader(self)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._conn.close()
        except Exception:  # noqa: BLE001 — close is best-effort
            pass

    def read_bounded(self, limit: int) -> bytes:
        """Read the response body, never more than ``limit`` bytes.

        The ONE bounded body reader for non-probe consumers (wp.org JSON
        and release zips): ``requests.Response.content`` has no absolute
        deadline, while this rides the same non-blocking socket loop.
        """
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
            raise WptError(f"invalid body bound: {limit!r}")
        chunks: list[bytes] = []
        total = 0
        for chunk in self.iter_content(chunk_size=64 * 1024):
            total += len(chunk)
            if total > limit:
                raise WptError(
                    f"response body exceeds the {limit}-byte bound")
            chunks.append(chunk)
        return b"".join(chunks)

    def preload(self, limit: int) -> bytes:
        """Read the whole body once at the CALLER's bound and cache it.

        The security checks read ``.text``/``.json`` after the bounded
        transport returns; without this cache the second read hit an
        exhausted socket.  Unlike ``.text`` (the bridge's 256 KiB
        excerpt), a check that needs the body declares its own configured
        bound, so a large homepage is not misread as an offline site.
        """
        if self._content is None:
            self._content = self.read_bounded(limit)
        return self._content

    def preload_prefix(self, limit: int) -> bytes:
        """Read at most ``limit`` bytes and KEEP the answer.

        Unlike :meth:`read_bounded` (which refuses an over-limit body for
        the wp.org JSON/zip consumers), a security probe's question is
        often answerable from the status/headers or a bounded prefix.  A
        9 MiB ``error_log`` at HTTP 200 is a real disclosure, not "the
        site did not answer": stop at the bound, mark
        :attr:`body_truncated`, and let the caller classify the answer.
        """
        if self._content is not None:
            return self._content
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
            raise WptError(f"invalid body bound: {limit!r}")
        chunks: list[bytes] = []
        total = 0
        for chunk in self.iter_content(chunk_size=64 * 1024):
            remaining = limit - total
            if len(chunk) > remaining:
                chunks.append(chunk[:remaining])
                total = limit
                self.body_truncated = True
                break
            chunks.append(chunk)
            total += len(chunk)
            if total >= limit:
                self.body_truncated = True
                break
        self._content = b"".join(chunks)
        return self._content

    @property
    def content(self) -> bytes:
        if self._content is None:
            self._content = self.read_bounded(_BODY_LIMIT)
        return self._content

    @property
    def text(self) -> str:
        if self._content is None:
            # requests caches ``.text``/``.content``; the bridge reads
            # ``response.text`` for the excerpt and then ``response.json()``.
            # Without this cache the second read saw an exhausted socket and
            # every real answer became "non-JSON".
            self._content = self.read_bounded(_BODY_LIMIT)
        return self._content.decode("utf-8", "replace")

    def iter_lines(self, chunk_size: int = 512, decode_unicode: bool = False,
                   delimiter: bytes | None = None) -> Any:
        """requests' newline contract over the bounded body reader.

        The bridge's streaming op (``db_dump``) consumes NDJSON through
        ``iter_lines``; the absolute-deadline transport must expose the same
        seam as ``requests.Response`` or streaming would silently lose its
        reader.  Lines are split on CR/LF (and a caller's delimiter).
        """
        pending = b""
        for chunk in self.iter_content(chunk_size=chunk_size):
            pending += chunk
            if delimiter is not None:
                parts = pending.split(delimiter)
                pending = parts.pop()
                yield from parts
                continue
            while True:
                break_at = -1
                for index, byte in enumerate(pending):
                    if byte in (0x0A, 0x0D):
                        break_at = index
                        break
                if break_at < 0:
                    break
                line = pending[:break_at]
                after = break_at + 1
                if pending[break_at:break_at + 2] == b"\r\n":
                    after += 1
                pending = pending[after:]
                yield line.decode("utf-8", "replace") if decode_unicode else line
        if pending:
            yield pending.decode("utf-8", "replace") if decode_unicode else pending

    def json(self) -> Any:
        return loads_bounded(self.text)


def _proxy_is_socks(proxy: str | None) -> bool:
    """Is ``proxy`` a SOCKS URL (whose tunnel is built by the connection)?"""
    return bool(proxy) and urlsplit(proxy).scheme.lower().startswith("socks")


def _send_bounded(sock: Any, data: bytes, deadline: float) -> None:
    """Send ALL of ``data``, bounded by the absolute deadline.

    A non-blocking send loop: a peer that accepts a few bytes and then stops
    reading cannot reset a per-write timeout forever.
    """
    view = memoryview(data)
    while view:
        try:
            sent = sock.send(view)
        except (BlockingIOError, InterruptedError):
            sent = 0
        except ssl.SSLWantWriteError:
            sent = 0
        except ssl.SSLWantReadError:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise WptError(_HEADER_TIMEOUT) from None
            try:
                readable, _, _ = select.select([sock], [], [], remaining)
            except (OSError, ValueError):
                raise WptError(_HEADER_TIMEOUT) from None
            if not readable:
                raise WptError(_HEADER_TIMEOUT) from None
            continue
        except (socket.timeout, TimeoutError):
            raise WptError(_HEADER_TIMEOUT) from None
        if sent:
            view = view[sent:]
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise WptError(_HEADER_TIMEOUT) from None
        try:
            _, writable, _ = select.select([], [sock], [], remaining)
        except (OSError, ValueError):
            raise WptError(_HEADER_TIMEOUT) from None
        if not writable:
            raise WptError(_HEADER_TIMEOUT) from None


def _bounded_connect_tunnel(conn: Any, deadline: float) -> None:
    """The CONNECT handshake on the bounded non-blocking loop.

    `http.client._tunnel` reads through a blocking file object whose
    ``timeout`` is PER READ: a proxy dripping one byte below each timeout
    kept the handshake alive for seconds and could drip forever.  This
    speaks the same wire shape (CONNECT target, tunnel headers, HTTP/1.1)
    but sends and receives under the caller's absolute deadline.
    """
    host = conn._wrap_ipv6(conn._tunnel_host.encode("idna"))
    request = b"CONNECT %s:%d %s\r\n" % (
        host, conn._tunnel_port, conn._http_vsn_str.encode("ascii"))
    for name, value in conn._tunnel_headers.items():
        request += f"{name}: {value}\r\n".encode("latin-1")
    request += b"\r\n"
    _set_nonblocking(conn.sock)
    _send_bounded(conn.sock, request, deadline)
    status, _headers, _buffered = _read_response_head(conn.sock, deadline)
    if status != 200:
        raise OSError(f"Tunnel connection failed: {status}")
    # The socket enters the origin-TLS wrap next; ssl.wrap_socket refuses a
    # non-blocking socket when handshake_on_connect is set.  Restore a
    # blocking mode with the REMAINING budget.
    conn.sock.settimeout(max(0.001, deadline - time.monotonic()))


#: One SOCKS negotiation at a time: the tracker below temporarily replaces
#: PySocks' socket class, so two concurrent probes must not race it.
_SOCKS_PATCH_LOCK = threading.Lock()

#: Structural resource ceiling, not an operator tunable: PySocks resolves
#: through libc getaddrinfo, which cannot be cancelled.  A timed-out
#: negotiation may therefore leave one daemon worker behind until the
#: resolver answers; at most this many may coexist, and the next caller
#: fails fast instead of growing the thread set without bound.
_SOCKS_WORKER_LIMIT = 4
_SOCKS_WORKERS = threading.BoundedSemaphore(_SOCKS_WORKER_LIMIT)


def _connect_socks_bounded(conn: Any, deadline: float) -> None:
    """Run PySocks' negotiation in a worker that CAN be cancelled.

    PySocks negotiates on per-read socket timeouts, so one byte per 0.4 s
    stays under every timeout forever.  The worker registers its socket; the
    caller joins only until the absolute deadline, then CLOSES the socket
    (which unblocks the negotiation) and joins the worker before raising.
    A process-wide semaphore bounds the workers at ``_SOCKS_WORKER_LIMIT``:
    once saturated a caller fails fast instead of spawning another thread.
    LIMITATION (stated): a libc getaddrinfo inside PySocks that never returns
    cannot be cancelled — up to ``_SOCKS_WORKER_LIMIT`` daemon workers may
    linger until the resolver answers, but each owns only its registered
    socket (closed here) and never blocks process exit.
    """
    try:
        import socks  # type: ignore[import-not-found]
    except ImportError:  # pragma: no cover — a Socks pool cannot exist
        conn.connect()
        return
    outcome: dict[str, Any] = {}
    tracked: list[Any] = []
    original = socks.socksocket
    # NEVER rebind the module's class: PySocks' own methods call
    # ``super(socksocket, self)`` against that global, so a subclass bound
    # there makes the original __init__ resolve to itself and recurse
    # (confirmed with PySocks 1.7.1, socks.py:258).  Patch the class's
    # __init__/connect instead and leave ``socks.socksocket`` bound to the
    # real class.
    original_init = original.__init__
    original_connect = original.connect

    def _track(sock: Any) -> None:
        if not any(item is sock for item in tracked):
            tracked.append(sock)

    def _tracked_init(self: Any, *args: Any, **kwargs: Any) -> Any:
        _track(self)
        return original_init(self, *args, **kwargs)

    def _tracked_connect(self: Any, *args: Any, **kwargs: Any) -> Any:
        _track(self)
        return original_connect(self, *args, **kwargs)

    def _run() -> None:
        try:
            conn.connect()
        except BaseException as exc:  # noqa: BLE001 — handed to the caller
            outcome["error"] = exc
        finally:
            outcome["done"] = True
            _SOCKS_WORKERS.release()

    if not _SOCKS_WORKERS.acquire(blocking=False):
        raise WptError(
            f"probe SOCKS negotiation is saturated: {_SOCKS_WORKER_LIMIT} "
            "worker(s) are still blocked in name resolution; refusing to "
            "start another (wait for the resolver or retry)")
    worker_started = False
    try:
        # The patch lock is GLOBAL and held through the worker's whole
        # lifetime.  ``Lock.__enter__`` has no deadline, so a second caller
        # used to block past its own absolute deadline and then start a
        # worker anyway.  Acquire only for the REMAINING budget and fail
        # fast without starting anything (R6-08).
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise WptError(_HEADER_TIMEOUT)
        if not _SOCKS_PATCH_LOCK.acquire(timeout=remaining):
            raise WptError(
                "probe SOCKS negotiation is busy: another probe held the "
                "PySocks patch for the whole remaining budget; refusing to "
                "start a worker past the deadline")
        try:
            if deadline - time.monotonic() <= 0:
                raise WptError(_HEADER_TIMEOUT)
            original.__init__ = _tracked_init
            original.connect = _tracked_connect
            try:
                worker = threading.Thread(
                    target=_run, name="wpt-probe-socks", daemon=True)
                worker.start()
                worker_started = True
                while worker.is_alive():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    worker.join(min(0.02, remaining))
                if worker.is_alive():
                    for sock in tracked:
                        try:
                            sock.close()
                        except Exception:  # noqa: BLE001 — best effort
                            pass
                    try:
                        conn.close()
                    except Exception:  # noqa: BLE001 — best effort
                        pass
                    # CLOSE then JOIN: the closed fd makes the negotiation
                    # fail promptly; give the worker a bounded moment to
                    # unwind.
                    worker.join(0.5)
                    raise WptError(_HEADER_TIMEOUT)
            finally:
                original.__init__ = original_init
                original.connect = original_connect
        finally:
            _SOCKS_PATCH_LOCK.release()
    finally:
        if not worker_started:
            _SOCKS_WORKERS.release()
    error = outcome.get("error")
    if error is not None:
        raise error


def _proxy_headers(adapter: Any, pool: Any, proxy: str | None) -> dict[str, str]:
    """The headers a forwarding proxy or CONNECT must receive.

    ``pool.proxy_headers`` is what urllib3 itself merges (requests builds
    the pool with ``adapter.proxy_headers(proxy)``); the adapter call is the
    owner's fallback for a pool built by another stack.  A SOCKS proxy
    authenticates inside its own handshake, so no HTTP header belongs there.
    """
    headers = dict(getattr(pool, "proxy_headers", None) or {})
    if proxy and getattr(pool, "proxy", None) \
            and not _proxy_is_socks(proxy):
        adapter_headers = getattr(adapter, "proxy_headers", None)
        if callable(adapter_headers):
            headers.update(adapter_headers(proxy))
    return headers


def _write_probe_request(conn: Any, prepared: requests.PreparedRequest,
                         url: str, *, proxy: str | None, proxied: bool,
                         tunneled: bool, proxy_headers: dict[str, str],
                         method: str = "GET", body: bytes | None = None,
                         deadline: float | None = None) -> None:
    """Write one request on an already-connected urllib3 connection.

    A forwarding HTTP(S) proxy takes an absolute-form target plus its
    ``Proxy-Authorization`` header (the same merge urllib3 performs); a
    CONNECT tunnel and a SOCKS proxy take the origin-form path only — their
    auth travels in the tunnel handshake, and ``Host`` stays the target.

    ``body`` (a POST form) is sent through the SAME non-blocking absolute-
    deadline loop as the response read: a peer that accepts a few bytes and
    then stops reading must not reset a per-write timeout forever.
    """
    parsed = urlsplit(prepared.url or url)
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    if proxied and not tunneled and proxy and not _proxy_is_socks(proxy):
        # RFC 7230 §5.3.2: a proxy expects absolute-form.  urllib3's own
        # forwarding path (``ProxyManager.urlopen``) requires an absolute
        # url and writes it unchanged for an HTTPS destination too;
        # requests never enables ``use_forwarding_for_https`` itself, so its
        # path-only HTTPS form is not the forwarding contract to inherit.
        target = urldefragauth(prepared.url or url)
    if deadline is not None and time.monotonic() >= deadline:
        raise requests.Timeout(
            "probe deadline expired before the request headers were written")
    conn.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
    conn.putheader("Host", parsed.netloc.rsplit("@", 1)[-1])
    skip = {"host", "content-length", "connection", "accept-encoding"}
    if proxied and proxy_headers:
        # The proxy's header wins, exactly like urllib3's forwarding merge,
        # and a tunnelled request never carries it to the origin.
        skip.add("proxy-authorization")
    for name, value in prepared.headers.items():
        if name.lower() in skip:
            continue
        conn.putheader(name, value)
    if body is not None:
        conn.putheader("Content-Length", str(len(body)))
    if proxied and not tunneled:
        for name, value in proxy_headers.items():
            if name.lower() in {"host", "content-length", "connection",
                                "accept-encoding"}:
                continue
            conn.putheader(name, value)
    # The probe answer is JSON: never negotiate compression the bounded
    # reader would have to decode.
    conn.putheader("Accept-Encoding", "identity")
    conn.putheader("Connection", "close")
    if deadline is not None and time.monotonic() >= deadline:
        raise requests.Timeout(
            "probe deadline expired before the request was sent")
    conn.endheaders()
    if body:
        if deadline is None:
            conn.send(body)
        else:
            _send_bounded(conn.sock, body, deadline)


#: ONE bounded resolver owner shared with the database and FTP transports.
#: The aliases keep the probe's public seam (doctor and its tests import
#: ``_resolve_host_bounded`` / ``_DNS_WORKERS`` from this module).
_is_numeric_host = is_numeric_host
_DNS_WORKER_LIMIT = DNS_WORKER_LIMIT
_DNS_WORKERS = DNS_WORKERS


def _resolve_host_bounded(host: str, port: int, deadline: float) -> list[str]:
    """Probe-labelled view of the shared bounded resolver."""
    return resolve_host_bounded(
        host, port, deadline,
        label="probe DNS resolution", thread_name="wpt-probe-dns")


def _bind_numeric_dns(conn: Any, deadline: float) -> None:
    """Dial a deadline-bounded numeric address, never a numeric TLS name.

    urllib3's ``_new_conn`` resolves ``_dns_host`` synchronously and
    ``HTTPConnection.host`` is a PROPERTY over ``_dns_host`` — assigning the
    numeric address to ``_dns_host`` made it the TLS SNI/certificate target
    (a hostname certificate then fails and the server sees SNI=None).  This
    wraps BOTH the dial (``_new_conn``) and the whole ``connect`` (dial +
    TLS): each resolved address is installed for the socket creation attempt
    and the ORIGINAL raw host is restored before the TLS/Host phase.  Every
    address is tried in resolver order under the absolute deadline, and each
    attempt owns a bounded share of the remaining budget so one blackholed
    address cannot starve the rest.  A TLS failure after a successful TCP
    dial resumes at the NEXT address instead of ending the request.

    The caller skips this for connections that already own a fixed dial
    address (``dial_ip``, e.g. ``--override-ip``) and for SOCKS, where
    PySocks/the proxy performs name resolution.
    """
    host = getattr(conn, "_dns_host", None) or getattr(conn, "host", "")
    if not isinstance(host, str) or not host:
        return
    port = getattr(conn, "port", None)
    if not isinstance(port, int):
        return
    if _is_numeric_host(host):
        return
    addresses = _resolve_host_bounded(host, port, deadline)
    original_new_conn = conn._new_conn
    original_connect = getattr(conn, "connect", None)
    original_dns_host = getattr(conn, "_dns_host", host)
    original_timeout = getattr(conn, "timeout", None)
    #: Next resolved address to dial.  A TLS failure happens AFTER
    #: ``_new_conn`` returned, so the connection-level retry below resumes
    #: at the address after the one whose handshake failed instead of
    #: restarting at the first (which would retry a broken peer forever).
    state = {"next": 0}

    def _set_timeout(share: float) -> float:
        if isinstance(original_timeout, (int, float)) \
                and not isinstance(original_timeout, bool):
            return max(0.001, min(original_timeout, share))
        return max(0.001, share)

    def _dial_first_working() -> Any:
        last_error: BaseException | None = None
        addresses_left = len(addresses) - state["next"]
        try:
            for index in range(state["next"], len(addresses)):
                address = addresses[index]
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise requests.ConnectionError(
                        "probe connection exceeded the absolute timeout "
                        "before a dial address answered")
                # A blackholed address must not consume the whole budget:
                # each attempt owns a bounded SHARE of what remains, so a
                # later address (e.g. the working IPv4 after a dead AAAA)
                # still gets a dial within the same absolute deadline.
                share = remaining / max(1, addresses_left)
                addresses_left -= 1
                state["next"] = index + 1
                conn._dns_host = address
                conn.timeout = _set_timeout(share)
                try:
                    return original_new_conn()
                except Exception as exc:  # noqa: BLE001 — try next address
                    last_error = exc
            if last_error is not None:
                raise last_error
            raise requests.ConnectionError(
                "probe DNS resolution returned no dial address")
        finally:
            conn._dns_host = original_dns_host
            conn.timeout = original_timeout

    conn._new_conn = _dial_first_working

    def _connect_first_working() -> None:
        """Run the WHOLE connect (dial + TLS) once per address.

        urllib3's ``connect`` performs the TLS handshake after ``_new_conn``
        returns, so wrapping only the dial left a TLS failure (a peer that
        accepts TCP then closes, a torn handshake) as the final answer and
        never tried the next resolved address.  Each retry resumes at the
        next address and reuses the same absolute run deadline.
        """
        try:
            while True:
                try:
                    return original_connect()
                except (OSError, ssl.SSLError) as exc:
                    if state["next"] >= len(addresses):
                        raise
                    last_error = exc
                    try:
                        conn.close()
                    except Exception:  # noqa: BLE001 — retry owns cleanup
                        pass
                    conn.sock = None
                    conn._has_connected_to_proxy = False
                    if time.monotonic() >= deadline:
                        raise last_error
        finally:
            conn._dns_host = original_dns_host
            conn.timeout = original_timeout

    if callable(original_connect):
        conn.connect = _connect_first_working


def _get_over_connection(session: requests.Session, url: str, *,
                         timeout_s: float, deadline: float,
                         headers: dict[str, str] | None = None,
                         verify: Any = None, method: str = "GET",
                         data: Any = None, json_body: Any = None) -> Any:
    """Run one request over the session's own urllib3 connection.

    Using the adapter's connection keeps DNS override, proxy and certificate
    configuration intact; only the header/body READ path changes from
    requests' per-read timeout to the non-blocking absolute-deadline loop.
    ``data`` is requests' own form payload (POST); ``json_body`` is its JSON
    payload.  Both are serialized by ``prepare_request`` and written on the
    same deadline loop.
    """
    prepared = session.prepare_request(
        requests.Request(method, url, headers=headers, data=data,
                         json=json_body))
    settings = session.merge_environment_settings(
        url, {}, None, verify, None)
    proxies = settings.get("proxies") or {}
    adapter = session.get_adapter(url)
    getter = getattr(adapter, "get_connection_with_tls_context", None)
    if callable(getter):
        pool = getter(prepared, settings.get("verify", True),
                      proxies=proxies, cert=settings.get("cert"))
    else:  # pragma: no cover — requests < 2.32.2
        # The old fallback called adapter.get_connection(url, proxies=...),
        # which accepts no verify/cert: DNS-override mode (verify=False) and
        # custom CA/client certs then failed TLS.  Dropping security options
        # silently is worse than naming the supported floor.
        raise WptError(
            "probe transport requires requests >= 2.32.2 "
            "(get_connection_with_tls_context); upgrade requests")
    proxy = select_proxy(prepared.url or url, proxies)
    proxy_headers = _proxy_headers(adapter, pool, proxy)
    parsed = urlsplit(prepared.url or url)
    # urllib3 owns the decision: an HTTPS destination (or an HTTPS proxy
    # without forwarding) needs a CONNECT tunnel; a forwarded destination —
    # plain HTTP, or HTTPS with ``use_forwarding_for_https`` — takes an
    # absolute-form target.  SOCKS pools carry no ``proxy`` here and build
    # their own tunnel in ``connect()``.
    tunneled = bool(getattr(pool, "proxy", None)) \
        and connection_requires_http_tunnel(
            pool.proxy, getattr(pool, "proxy_config", None), parsed.scheme)
    if time.monotonic() >= deadline:
        raise requests.Timeout(
            "probe deadline expired before the connection was opened")
    remaining = max(0.001, deadline - time.monotonic())
    conn = pool._get_conn(timeout=min(timeout_s, remaining))
    try:
        if getattr(conn, "sock", None) is not None:
            conn.close()
        conn.timeout = min(timeout_s,
                           max(0.001, deadline - time.monotonic()))
        # Resolve BEFORE the blocking connect phase, under the same absolute
        # deadline the socket loop uses.  A connection with its own fixed dial
        # address (--override-ip's dial_ip) must NEVER resolve the URL host:
        # that is the exact pre-migration case the override exists for.  A
        # SOCKS pool owns name resolution inside PySocks/the proxy, so the
        # origin hostname is left untouched there too.
        if getattr(conn, "dial_ip", None) is None \
                and not _proxy_is_socks(proxy):
            # DNS is bounded by the REQUEST's own timeout too, not only by
            # the run deadline.  A bridge request carries the run deadline
            # (up to an hour) while ``timeout_s`` is its per-request bound;
            # a stalling resolver otherwise burned the whole run budget
            # before the first socket existed.
            _bind_numeric_dns(
                conn, min(deadline, time.monotonic() + max(0.001, timeout_s)))
        if time.monotonic() >= deadline:
            raise requests.Timeout(
                "probe deadline expired before the connection was used")
        if tunneled:
            # The exact CONNECT ``HTTPSConnectionPool._prepare_proxy``
            # builds: URL-derived tunnel host/port plus the adapter's proxy
            # auth.  The handshake itself runs on the absolute-deadline loop
            # (per-read socket timeouts reset on every dripped byte).
            conn.set_tunnel(
                scheme="https"
                if getattr(pool.proxy, "scheme", "") == "https" else "http",
                host=getattr(pool, "_tunnel_host", None) or parsed.hostname,
                port=getattr(pool, "port", None) or parsed.port or 443,
                headers=proxy_headers,
            )
            original_tunnel = conn._tunnel
            conn._tunnel = lambda: _bounded_connect_tunnel(conn, deadline)
            try:
                conn.connect()
            except WptError as exc:
                # A tunnel timeout is a TRANSPORT failure to PhpProbe.call's
                # contract (requests.ConnectionError), not a probe-answer
                # failure; keep the one message shape every proxy timeout
                # already had.
                raise requests.ConnectionError(str(exc)) from exc
            finally:
                conn._tunnel = original_tunnel
        elif _proxy_is_socks(proxy):
            _connect_socks_bounded(conn, deadline)
        else:
            conn.connect()
        sock = conn.sock
        if sock is None:
            raise requests.ConnectionError("probe connection was not opened")
        sock.settimeout(max(0.001, deadline - time.monotonic()))
        body = prepared.body
        if isinstance(body, str):
            body = body.encode("utf-8")
        if time.monotonic() >= deadline:
            raise requests.Timeout(
                "probe deadline expired before the request was written")
        _write_probe_request(
            conn, prepared, url, proxy=proxy,
            proxied=bool(getattr(pool, "proxy", None)),
            tunneled=tunneled, proxy_headers=proxy_headers,
            method=method, body=body, deadline=deadline)
        _set_nonblocking(sock)
        status, headers, buffered = _read_response_head(sock, deadline)
        return _SocketResponse(conn, sock, status, headers, buffered,
                               deadline, url=url)
    except BaseException:
        # The caller's deadline (or transport failure) closes the socket
        # NOW: a late complete answer can never outlive the probe call.
        try:
            conn.close()
        except Exception:  # noqa: BLE001 — preserve the primary failure
            pass
        raise


#: Requests' own redirect ceiling (structural): a redirect loop must end.
_MAX_REDIRECTS = 30
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


def get_bounded(session: Any, url: str, *,
                timeout_s: float, deadline: float | None = None,
                allow_redirects: bool = False,
                headers: dict[str, str] | None = None,
                verify: Any = None) -> Any:
    """GET bounded by an ABSOLUTE wall-clock deadline — the ONE HTTP owner.

    requests/urllib3's ``timeout`` is a PER-READ bound: a server dripping
    one header byte every 0.25 s keeps every individual read under a 1 s
    timeout and the call blocked for seconds (PHP1, doctor P1).  A real
    requests session is driven over its own adapter connection with a
    non-blocking socket + ``select`` loop in THIS thread; no worker thread
    or socket can outlive the call.  Redirects are followed here under the
    SAME absolute budget (requests' default would re-arm a fresh per-read
    timeout on every hop).  Session doubles (tests and embedders that only
    expose ``get``) keep their synchronous contract.

    ``deadline`` is an absolute ``time.monotonic()`` instant; ``None``
    means ``timeout_s`` from now.  The response exposes ``status_code``,
    ``headers``, ``url`` (the FINAL URL), ``iter_content`` and — for the
    probe's real socket response — ``read_bounded``.
    """
    absolute = time.monotonic() + timeout_s if deadline is None else deadline
    # Duck-typing, not isinstance: tests monkeypatch ``requests.Session`` (a
    # shared module attribute) and that must not turn this check into
    # ``isinstance(x, function)``.  A real session exposes the three
    # adapter-level seams the bounded reader drives.
    real_session = all(
        callable(getattr(session, name, None))
        for name in ("prepare_request", "get_adapter",
                     "merge_environment_settings"))
    if not real_session:
        kwargs: dict[str, Any] = {
            "timeout": timeout_s,
            "stream": True,
            "allow_redirects": allow_redirects,
        }
        if headers is not None:
            kwargs["headers"] = headers
        if verify is not None:
            kwargs["verify"] = verify
        return session.get(url, **kwargs)
    current = url
    for hop in range(_MAX_REDIRECTS + 1):
        try:
            response = _get_over_connection(
                session, current, timeout_s=timeout_s, deadline=absolute,
                headers=headers, verify=verify)
        except (requests.RequestException, WptError):
            raise
        except Exception as exc:  # noqa: BLE001 — one sanitized contract
            raise requests.ConnectionError(
                f"bounded GET transport failed ({type(exc).__name__})") from exc
        if not allow_redirects or response.status_code not in _REDIRECT_STATUSES:
            return response
        location = response.headers.get("location")
        if not isinstance(location, str) or not location.strip():
            # A 3xx without a usable Location is the server's final answer.
            return response
        if hop >= _MAX_REDIRECTS:
            # The ceiling is reached WITH another hop requested: that is a
            # redirect LOOP, not a successful final 3xx.  Returning the last
            # redirect made doctor read a looping site as PASS "HTTP 302".
            response.close()
            raise requests.TooManyRedirects(
                f"bounded GET exceeded {_MAX_REDIRECTS} redirects",
                response=response)
        response.close()
        current = urljoin(current, location.strip())


def head_bounded(session: Any, url: str, *, timeout_s: float,
                 deadline: float | None = None,
                 allow_redirects: bool = True,
                 headers: dict[str, str] | None = None,
                 verify: Any = None) -> Any:
    """HEAD bounded by an ABSOLUTE wall-clock deadline.

    The metadata-only twin of :func:`get_bounded`: a header drip re-arms a
    per-read timeout forever, and the security checks use HEAD to date an
    unknown PHP file.  A real session rides the same adapter connection
    and deadline loop; a session double keeps its synchronous contract.
    """
    absolute = time.monotonic() + timeout_s if deadline is None else deadline
    real_session = all(
        callable(getattr(session, name, None))
        for name in ("prepare_request", "get_adapter",
                     "merge_environment_settings"))
    if not real_session:
        kwargs: dict[str, Any] = {
            "timeout": timeout_s,
            "allow_redirects": allow_redirects,
        }
        if headers is not None:
            kwargs["headers"] = headers
        if verify is not None:
            kwargs["verify"] = verify
        return session.head(url, **kwargs)
    current = url
    for hop in range(_MAX_REDIRECTS + 1):
        try:
            response = _get_over_connection(
                session, current, timeout_s=timeout_s, deadline=absolute,
                headers=headers, verify=verify, method="HEAD")
        except (requests.RequestException, WptError):
            raise
        except Exception as exc:  # noqa: BLE001 — one sanitized contract
            raise requests.ConnectionError(
                f"bounded HEAD transport failed ({type(exc).__name__})") \
                from exc
        if not allow_redirects or response.status_code not in _REDIRECT_STATUSES:
            return response
        location = response.headers.get("location")
        if not isinstance(location, str) or not location.strip():
            return response
        if hop >= _MAX_REDIRECTS:
            response.close()
            raise requests.TooManyRedirects(
                f"bounded HEAD exceeded {_MAX_REDIRECTS} redirects",
                response=response)
        response.close()
        current = urljoin(current, location.strip())


def post_bounded(session: Any, url: str, *, form: dict[str, str] | None = None,
                 json_body: Any = None,
                 timeout_s: float, deadline: float | None = None,
                 headers: dict[str, str] | None = None,
                 verify: Any = None) -> Any:
    """POST bounded by an ABSOLUTE wall-clock deadline — the ONE POST owner.

    The GET twin is :func:`get_bounded`; a wp.org bulk check is a POST whose
    form body and response body must both ride the non-blocking deadline
    loop, because requests' ``timeout`` resets on every read and
    ``response.json()`` has no absolute bound at all.  A real session is
    driven over its own adapter connection; a session double keeps its
    synchronous contract (tests/embedders that only expose ``post``).

    ``form`` is the urlencoded body the wp.org API takes; ``json_body`` is
    the JSON object the bridge wire protocol takes.  Exactly one of the two
    is supplied by every caller.
    """
    if (form is None) == (json_body is None):
        raise WptError("post_bounded needs exactly one of form/json_body")
    absolute = time.monotonic() + timeout_s if deadline is None else deadline
    real_session = all(
        callable(getattr(session, name, None))
        for name in ("prepare_request", "get_adapter",
                     "merge_environment_settings"))
    if not real_session:
        kwargs: dict[str, Any] = {
            "timeout": timeout_s,
            "stream": True,
        }
        if form is not None:
            kwargs["data"] = form
        else:
            kwargs["json"] = json_body
        if headers is not None:
            kwargs["headers"] = headers
        if verify is not None:
            kwargs["verify"] = verify
        return session.post(url, **kwargs)
    try:
        return _get_over_connection(
            session, url, timeout_s=timeout_s, deadline=absolute,
            headers=headers, verify=verify, method="POST",
            data=form, json_body=json_body)
    except (requests.RequestException, WptError):
        raise
    except Exception as exc:  # noqa: BLE001 — one sanitized contract
        raise requests.ConnectionError(
            f"bounded POST transport failed ({type(exc).__name__})") from exc


@contextmanager
def _capped_source_budget(source: Source, deadline: float | None):
    """Cap a source's budget at the probe deadline for one deployment block.

    The source's own run deadline is usually much LONGER than the probe's
    ``timeout_s`` (FTP 45 s vs probe 15 s), so a slow ``exists``/write could
    spend the probe's whole budget and still issue the write afterwards.
    The temporary budget is the EARLIER of the source's remaining time and
    the probe deadline; the exact previous object is restored in ``finally``.
    """
    if deadline is None:
        yield
        return
    current = getattr(source, "deadline", None)
    if current is None:
        # A double/source with no budget cannot be capped; the caller's own
        # explicit deadline checks before every write still hold.
        yield
        return
    from .deadline import Deadline

    remaining = deadline - time.monotonic()
    source_remaining = getattr(current, "remaining", None)
    if isinstance(source_remaining, (int, float)) \
            and not isinstance(source_remaining, bool):
        remaining = min(remaining, source_remaining)
    if remaining <= 0:
        raise DeadlineExceeded(
            "probe deadline expired before deployment; no file was written")
    source.deadline = Deadline(max(0.001, remaining))
    try:
        yield
    finally:
        source.deadline = current


class PhpProbe:
    """One deploy -> GET -> destroy lifecycle for the standalone probe.

    ``source`` is rooted at the webroot (every ``Source`` prefixes its own
    root, so the deployed path is the BARE filename).  ``session`` is the
    already-prepared ``requests.Session`` the caller owns — a DNS-override
    session works unchanged — and ``site`` is the public site URL whose
    document root is that webroot.  ``settings`` is the ``probe`` section:
    its TTL, collision-retry budget and transport timeout.
    """

    def __init__(self, source: Source, session: requests.Session,
                 settings: ProbeSettings, site: str) -> None:
        self._source = source
        self._session = session
        self._settings = settings
        self._site = site.rstrip("/")
        self._endpoint: str | None = None   # webroot-relative deployed path
        self._name: str | None = None       # deployed filename
        self._token: str | None = None
        # Every endpoint THIS instance wrote.  destroy() removes these and
        # nothing else — a probe-shaped file this instance did not deploy may
        # belong to another run (or be a third party's), so it is the sweep's
        # expiry-aware job, never destroy()'s.
        self._deployed: list[str] = []

    # ------------------------------------------------------------- lifecycle

    def ensure(self, *, deadline: float | None = None) -> str:
        """Deploy a fresh probe; return its webroot-relative endpoint.

        Each attempt generates a NEW name and a NEW token.  A name already
        present at the root is a collision (the site's own file, or a live
        sibling probe) and is never overwritten: retry at most
        ``settings.name_retries`` times, then fail with one clear error.  A
        write failure propagates from the source (``SourceError`` is the
        caller's contract) and leaves no partial endpoint recorded — the
        instance either has a deployed file it can call and destroy, or it
        has nothing.
        """
        if deadline is not None and time.monotonic() >= deadline:
            raise DeadlineExceeded(
                "probe deadline expired before deployment; no file was written")
        template = _PHP_TEMPLATE.read_text(encoding="utf-8")
        attempts = self._settings.name_retries + 1
        with _capped_source_budget(self._source, deadline):
            for _attempt in range(attempts):
                token = secrets.token_hex(_TOKEN_BYTES)
                name = probe_name(secrets.token_hex(_SUFFIX_BYTES))
                endpoint = name
                if self._source.exists(endpoint):
                    log.debug("probe name %s is already present; retrying",
                              endpoint)
                    continue
                # The exists() above is a REMOTE operation: a slow listing
                # can consume the whole probe budget.  Never write after it.
                if deadline is not None and time.monotonic() >= deadline:
                    raise DeadlineExceeded(
                        "probe deadline expired during deployment; no file "
                        "was written")
                expiry = int(time.time()) + self._settings.ttl_minutes * 60
                try:
                    text = render_endpoint_template(
                        template, token=token, expiry=expiry)
                except ValueError as exc:
                    raise WptError(
                        "probe template is unusable: "
                        f"{exc}; refusing to deploy {_PHP_TEMPLATE}"
                    ) from None
                # Record the attempted endpoint BEFORE the write so a protocol
                # that stores bytes and then reports a failure is still
                # destroyable: the best-effort cleanup below removes it, and a
                # failed ensure never leaves an untracked live probe.
                self._endpoint = endpoint
                self._name = endpoint
                self._token = token
                self._deployed.append(endpoint)
                try:
                    if deadline is not None and time.monotonic() >= deadline:
                        raise DeadlineExceeded(
                            "probe deadline expired before the write; no file "
                            "was written")
                    self._source.write_bytes(endpoint, text.encode("utf-8"))
                except Exception:
                    cleaned = False
                    try:
                        # FILE2 rule: never trust exists() here.  Attempt the
                        # delete unconditionally; a masked "absent" answer would
                        # leave a live token probe untracked and destroy() would
                        # skip it.
                        delete_or_prove_absent(self._source, endpoint)
                        cleaned = True
                    except (StopRequested, DeadlineExceeded):
                        # SIGTERM/the run deadline during cleanup ends the RUN;
                        # re-raising the original write failure here lost it.
                        raise
                    except Exception as cleanup_exc:  # noqa: BLE001
                        log.warning(
                            "probe cleanup after a failed write failed for %s: %s",
                            endpoint, redact_text(str(cleanup_exc)))
                    if cleaned:
                        self._deployed.remove(endpoint)
                        self._endpoint = None
                        self._name = None
                        self._token = None
                    # On a cleanup refusal the endpoint STAYS tracked: the
                    # caller's finally-destroy() retries it, and the expiry
                    # sweep backstops a later killed run.
                    raise
                log.debug("probe deployed at %s (ttl %d min)", endpoint,
                          self._settings.ttl_minutes)
                return endpoint
        raise WptError(
            f"could not deploy a PHP probe: all {attempts} fresh "
            f"wpt-probe-<hex>.php name(s) already existed at the webroot root "
            f"(probe.name_retries={self._settings.name_retries}); nothing was "
            f"overwritten",
        )

    def call(self, *, deadline: float | None = None) -> dict[str, Any]:
        """GET the probe with its token; return the decoded JSON object.

        Ensures first when nothing is deployed.  The PHP template
        ``@unlink(__FILE__)``s after every authenticated HTTP 200, so the
        endpoint is CONSUMED by that answer: the status is captured before
        the body is read and a 200 clears ``_endpoint``/``_name``/``_token``
        (``_deployed`` keeps the name so ``destroy`` still covers it), which
        makes a second :meth:`call` deploy a fresh probe instead of GETting
        the self-deleted file and failing with a 404.  The request never
        follows a redirect (a host's redirect to a login/challenge page is
        not the probe's answer) and is bounded by ``settings.timeout_s``
        AND the caller's optional absolute ``deadline`` (``time.monotonic``
        instant): a doctor row must never restart a fresh probe timeout after
        the run budget has already expired.
        Every failure shape — transport, non-200, non-JSON, non-object, or
        anything but a literal ``"ok": true`` — raises :class:`WptError`
        with a REDACTED excerpt; the token itself never enters a message or
        a log.
        """
        started = time.monotonic()
        budget = started + self._settings.timeout_s
        if deadline is not None:
            budget = min(budget, deadline)
        if budget <= time.monotonic():
            raise DeadlineExceeded(
                "probe deadline expired before the call could start")
        if self._endpoint is None:
            self.ensure(deadline=budget)
        assert self._name is not None and self._token is not None
        token = self._token
        url = f"{self._site}/{self._name}?token={self._token}"
        response = None
        request_error: tuple[str, str] | None = None
        try:
            response = get_bounded(
                self._session, url,
                timeout_s=self._settings.timeout_s, deadline=budget,
            )
            # Capture the status BEFORE reading the body: a 200 proves the
            # token-gated script ran, and its self-unlink runs after its
            # answer enters the SAPI buffer.  The endpoint is consumed even
            # if the body subsequently times out or fails to decode.
            status = response.status_code
            if status in (200, 404, 410):
                # 200 consumed the self-deleting script; 404/410 prove the
                # deployed URL can NEVER answer again (deleted externally,
                # or expired — PHP's gate is monotonic).  Clear the live
                # endpoint state in all three so the next call() re-ensures
                # a fresh probe instead of re-GETting a dead URL (R6-09).
                # _deployed keeps the name for destroy().
                self._endpoint = None
                self._name = None
                self._token = None
            text = _body_text(response, budget)
        except (requests.RequestException, OSError) as exc:
            # requests embeds the token-bearing URL in its own text.  Keep
            # the class and a sanitized detail only; the raise happens
            # OUTSIDE this block so Python does not attach the raw
            # exception as __context__ (which would carry the token).
            request_error = (type(exc).__name__,
                             self._sanitize(str(exc), token=token))
        finally:
            close = getattr(response, "close", None)
            if callable(close):
                close()
        if request_error is not None:
            msg = (f"probe request failed ({request_error[0]}: "
                   f"{request_error[1]})")
            log.error("probe call failed: %s", msg)
            raise WptError(msg)
        excerpt = self._excerpt(text, token=token)
        if status != 200:
            msg = f"probe answered HTTP {status}: {excerpt}"
            log.error("probe call failed: %s", msg)
            raise WptError(msg)
        decode_failed = False
        data: Any = None
        try:
            data = loads_bounded(text)
        except (TypeError, ValueError, RecursionError):
            # Nested arrays can exhaust the decoder's recursion limit; a
            # hostile body must still answer a WptError, never a traceback.
            # The exception object is dropped here so its .doc (the raw,
            # possibly token-bearing body) is not reachable as __context__.
            decode_failed = True
        if decode_failed:
            msg = f"probe returned non-JSON (HTTP 200): {excerpt}"
            log.error("probe call failed: %s", msg)
            raise WptError(msg)
        if not isinstance(data, dict):
            msg = (f"probe returned a non-object JSON body (HTTP 200): "
                   f"{excerpt}")
            log.error("probe call failed: %s", msg)
            raise WptError(msg)
        if data.get("ok") is not True:
            # Deliberately strict: the probe's own PHP emits a JSON boolean,
            # and a truthy 1/string is not the success shape this tool wrote.
            error = data.get("error")
            detail = (f": {self._excerpt(error, token=token)}"
                      if isinstance(error, str) and error else "")
            msg = self._sanitize(
                f"probe answered without ok=true (HTTP 200){detail}",
                token=token)
            log.warning("probe call failed: %s", msg)
            raise WptError(msg)
        log.debug("probe call ok in %d ms",
                  int((time.monotonic() - started) * 1000))
        return data

    def destroy(self) -> None:
        """Remove every endpoint THIS instance deployed; idempotent.

        The PHP self-deletes after a successful answer, so a missing file is
        the normal case here and is not an error.  A source that refuses a
        delete raises ``SourceError`` (the caller's contract); the failed
        endpoint stays tracked so a later destroy can retry it.  Files this
        instance did not deploy are never considered.
        """
        for endpoint in list(self._deployed):
            # Cleanup runs BECAUSE the forward work failed, often because the
            # run deadline expired: a source that keeps honouring it can never
            # issue the DELE, leaving a live token probe until TTL.  The
            # source owner installs a fresh finite cleanup budget.
            with source_cleanup_budget(self._source):
                # A masked exists()=False is not proof: delete only when a
                # successful listing confirms the file may still be there.
                if path_may_exist(self._source, endpoint):
                    delete_or_prove_absent(self._source, endpoint)
                    log.debug("probe removed from %s", endpoint)
                else:
                    log.debug("probe already gone from %s", endpoint)
            self._deployed.remove(endpoint)
        self._endpoint = None
        self._name = None
        self._token = None

    # --------------------------------------------------------------- helpers

    def _sanitize(self, text: str, *, token: str | None = None) -> str:
        """Replace this deployment's token exactly, then redact secrets.

        ``token`` lets a caller sanitize with the token of an endpoint it has
        just marked consumed (a 200 clears ``_token`` before the body and
        subsequent error excerpts are processed).
        """
        token = self._token if token is None else token
        if token:
            text = text.replace(token, "***")
        return redact_text(text)

    def _excerpt(self, text: str | None, *, token: str | None = None) -> str:
        """Bounded, single-line, token-redacted body excerpt."""
        text = self._sanitize(text or "", token=token)
        # A hostile body must not inject newlines (or forge a second report
        # line) through an error detail.
        text = " ".join(text.split())
        if len(text) <= _EXCERPT_LIMIT:
            return text
        return text[:_EXCERPT_LIMIT] + "..."


def sweep_stale_probes(source: Source,
                       settings: ProbeSettings) -> tuple[int, int]:
    """Delete EXPIRED ``wpt-probe-<8hex>.php`` files from the webroot root.

    Only a plain root file whose name matches the exact deployed shape is a
    candidate.  Each candidate is read and its OWN embedded expiry literal is
    compared with the current clock: a file still inside its TTL may be a
    CONCURRENT sibling run's live probe, and deleting it would terminate that
    run's diagnostic (the bridge sweep's rule).  An unreadable or unparseable
    candidate is left in place with one warning — never delete what cannot be
    verified — and a delete refusal is a warning, never a sweep failure.

    ``settings`` is part of the lifecycle contract (the probe section owns the
    TTL policy that produced each literal); the deletion decision itself is
    the file's literal, not this run's TTL.  Returns ``(removed, skipped)``
    and logs one info line for each non-zero count.
    """
    return sweep_expired_endpoints(
        source, source.list_dir(""),
        kind="probe",
        matches=lambda path: PROBE_NAME_RE.fullmatch(
            path.rsplit("/", 1)[-1]) is not None,
        read_limit=_PROBE_READ_LIMIT,
        logger=log,
    )
