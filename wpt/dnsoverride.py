"""DNS override — reach a WordPress site by IP while it still believes it is
the hostname it presents (pre-migration sites whose DNS points elsewhere).

Two surfaces, per SPEC §"DNS override (W3)" and the empirically verified
recipe in docs/research/R1.md (38/38 checks, requests 2.34.2 + urllib3 2.7.0):

- resolve_session(): a requests.Session whose HTTPS pool for exactly ONE
  configured hostname dials a fixed ``ip:port`` instead of resolving DNS.
  The urllib3 pool stays keyed by the URL hostname, so the Host header, TLS
  SNI and certificate target all derive from the hostname automatically;
  only the TCP dial (connection ``_new_conn``) is overridden. No global
  monkeypatching; every other hostname keeps stock DNS semantics.
- ProxyServer / run_proxy(): a threaded TLS-terminating proxy so a real
  browser can browse through the override. The browser talks TLS to
  https://localhost:<port> (the SAME origin bodies, Location and cookie
  Domain are rewritten to; a self-signed certificate, Chrome shows the
  standard interstitial — typing "thisisunsafe" proceeds, see README), each
  request is re-issued upstream to ``ip:<upstream_port>`` with SNI and Host =
  ``hostname`` under a CERT_NONE client context, and the response is served
  back with absolute site URLs rewritten to the proxy origin.

Upstream bodies are buffered before being written to the browser (this is a
manual testing tool, not a streaming production edge), but the buffer is
bounded by ``ProxyServer(max_body_bytes=...)`` — production passes
``walk.max_response_bytes`` — and every head/body read shares ONE absolute
deadline, so a dripped or over-cap answer becomes the documented 502 instead
of an unbounded download.

Deviations from the R1 recipe, both for testability (required by the W3
test plan; the production paths keep R1's defaults):

- resolve_session() takes ``port`` (default 443): the TCP dial port for the
  overridden hostname is pinned by the caller instead of flowing from the
  request URL. Host header and SNI are unaffected.
- ProxyServer takes ``upstream_port`` (default 443): dial-only knob so tests
  can point the proxy at a local TLS server. The upstream request always
  presents the canonical ``https://hostname`` origin (Host/SNI = hostname).
"""

import http.client
import os
import re
import secrets
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
import unicodedata
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import requests
import urllib3
import urllib3.connection
import urllib3.connectionpool
from requests.adapters import HTTPAdapter
from urllib3.exceptions import (
    ConnectTimeoutError,
    NameResolutionError,
    NewConnectionError,
)
from urllib3.poolmanager import PoolManager
from urllib3.util.connection import create_connection

from .log import get_logger
from .php_probe import BODYLESS_STATUSES, CHUNK_SIZE_RE
from .ports import DEFAULT_PROXY_PORT
from .settings import ProxySettings
from .types import WptError

log = get_logger("dnsoverride")

# R1 pitfall: InsecureRequestWarning is emitted PER REQUEST (urllib3
# connectionpool._validate_conn) and cannot be scoped to one session, so it
# is disabled exactly once, here, at module init (process-global).
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_CERT_FILE = "cert.pem"
_KEY_FILE = "key.pem"
#: ONE default certificate directory for the CLI, command body and engine.
DEFAULT_CERT_DIR = Path(".wpt-cert")
#: The ONE advertised rewrite origin host.  The certificate is minted for
#: ``localhost`` (SAN localhost/127.0.0.1/::1), cookies are rewritten to it
#: and absolute URLs in bodies/Location point at it: one owner so the URL
#: the operator is told to open is the origin every rewrite targets.
_ORIGIN_HOST = "localhost"
# SPEC sets the shipped default (7 days); both values are profile policy
# (``proxy.cert_validity_days`` / ``proxy.cert_renew_before_s``).

# Response headers the proxy must not pass through to the browser: hop-by-hop
# headers it re-derives itself, plus headers that would re-pin the browser to
# the real origin (HSTS, CSP, Alt-Svc). content-encoding is dropped whenever we
# could decode/rewrite the body; server/date are ours (send_response emits them).
_RESPONSE_DROP_HEADERS = frozenset(
    {
        "transfer-encoding",
        "content-length",
        "connection",
        "keep-alive",
        "strict-transport-security",
        "content-security-policy",
        "alt-svc",
        "content-encoding",
        "server",
        "date",
    }
)
# Request headers never forwarded upstream: hop-by-hop headers, Host (the
# upstream Host is always the real site hostname, set by http.client),
# Content-Length (recomputed from the buffered body) and Accept-Encoding —
# we request identity so upstream bodies are plaintext and rewriting them
# is byte-safe.
_REQUEST_DROP_HEADERS = frozenset(
    {
        "host",
        "connection",
        "keep-alive",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "content-length",
        "accept-encoding",
    }
)

#: Structural bounds for ONE upstream response head.  The proxy is a manual
#: testing tool, not a general edge, so a peer that grows headers without
#: bound must end in the documented 502 instead of holding a worker forever.
#: Values are protocol ceilings (what a real HTTP/1.1 answer needs), not
#: operator policy.
_MAX_UPSTREAM_HEAD_BYTES = 64 * 1024
_MAX_UPSTREAM_HEADERS = 200
_MAX_UPSTREAM_INTERIM_HEADS = 10


# --------------------------------------------------------------------------
# resolve_session: host-keyed pool + _new_conn dial override (R1, verbatim)
# --------------------------------------------------------------------------


class _IPDialConnectionMixin:
    """TCP-dial override shared by the HTTP and HTTPS urllib3 connections."""

    def _new_conn(self) -> socket.socket:
        if self.dial_ip is None:
            return super()._new_conn()
        dial_port = self.dial_port if self.dial_port is not None else self.port
        try:
            sock = create_connection(
                (self.dial_ip, dial_port),
                self.timeout,
                source_address=self.source_address,
                socket_options=self.socket_options,
            )
        except socket.gaierror as e:
            raise NameResolutionError(self.host, self, e) from e
        except socket.timeout as e:
            raise ConnectTimeoutError(
                self,
                f"Connection to {self.host} timed out. (connect timeout={self.timeout})",
            ) from e
        except OSError as e:
            raise NewConnectionError(
                self, f"Failed to establish a new connection: {e}"
            ) from e
        sys.audit("http.client.connect", self, self.dial_ip, dial_port)
        return sock


class IPDialHTTPSConnection(_IPDialConnectionMixin,
                            urllib3.connection.HTTPSConnection):
    """HTTPS connection that TCP-dials ``dial_ip:dial_port`` while every
    hostname-derived behavior (Host header, SNI, cert target) keeps using
    the URL hostname, exactly as if DNS had resolved to the dial address.

    ``dial_port=None`` preserves urllib3 semantics: the port from the request
    URL flows to the dial.
    """

    def __init__(self, *args, dial_ip: str | None = None,
                 dial_port: int | None = None, **kwargs) -> None:
        self.dial_ip = dial_ip
        self.dial_port = dial_port
        super().__init__(*args, **kwargs)


class IPDialHTTPConnection(_IPDialConnectionMixin,
                           urllib3.connection.HTTPConnection):
    """The plain-HTTP twin (an ``http://`` site under ``--override-ip``)."""

    def __init__(self, *args, dial_ip: str | None = None,
                 dial_port: int | None = None, **kwargs) -> None:
        self.dial_ip = dial_ip
        self.dial_port = dial_port
        super().__init__(*args, **kwargs)


class IPDialHTTPSConnectionPool(urllib3.connectionpool.HTTPSConnectionPool):
    """HTTPS pool whose connections are IPDialHTTPSConnection (dial_ip and
    dial_port reach it through the pool's conn_kw)."""

    ConnectionCls = IPDialHTTPSConnection


class IPDialHTTPConnectionPool(urllib3.connectionpool.HTTPConnectionPool):
    """Plain-HTTP pool over :class:`IPDialHTTPConnection`."""

    ConnectionCls = IPDialHTTPConnection


class IPDialPoolManager(PoolManager):
    """PoolManager routing the HTTPS pool of exactly one hostname through a
    fixed dial address (host-gated: same-host redirects keep the override,
    any other host falls back to normal DNS)."""

    def __init__(self, target_host: str, target_ip: str,
                 target_port: int | None = None, **kwargs) -> None:
        # urllib3 keys HTTPS pools by the URL host, which requests has
        # already IDNA-encoded (punycode).  A raw Unicode hostname here
        # never matched, so --override-ip silently dialed real DNS for an
        # IDN site.  Normalize the GATE owner to the same wire form.
        normalized = target_host.rstrip(".").lower()
        try:
            normalized = normalized.encode("idna").decode("ascii")
        except UnicodeError:
            # Leave an invalid name as-is: the pool simply never matches,
            # exactly like an unrelated host (and the proxy/server path
            # reports the IDNA refusal at its own boundary).
            pass
        self._target_host = normalized
        self._target_ip = target_ip
        self._target_port = target_port
        super().__init__(**kwargs)
        # R1 pitfall: PoolManager.__init__ assigns the module-level
        # pool_classes_by_scheme dict BY REFERENCE — mutating it in place would
        # globally patch every other PoolManager. Copy before mutating.
        self.pool_classes_by_scheme = dict(self.pool_classes_by_scheme)
        self.pool_classes_by_scheme["https"] = IPDialHTTPSConnectionPool
        self.pool_classes_by_scheme["http"] = IPDialHTTPConnectionPool

    def _new_pool(self, scheme: str, host: str, port: int,
                  request_context: dict | None = None):
        if scheme in ("https", "http") and host \
                and host.rstrip(".").lower() == self._target_host:
            # The base implementation pops keys from request_context, and the
            # caller's dict may be reused — always hand it a private copy so
            # repeated (re)builds re-inject dial_ip/dial_port idempotently.
            if request_context is None:
                ctx = dict(self.connection_pool_kw)
            else:
                ctx = dict(request_context)
            ctx["dial_ip"] = self._target_ip
            if self._target_port is not None:
                ctx["dial_port"] = self._target_port
            return super()._new_pool(scheme, host, port, ctx)
        return super()._new_pool(scheme, host, port, request_context)


class IPDialHTTPAdapter(HTTPAdapter):
    """requests adapter mounting an IPDialPoolManager for one hostname:ip[:port]."""

    def __init__(self, hostname: str, ip: str, port: int = 443, **kwargs) -> None:
        self._hostname = hostname
        self._ip = ip
        self._port = port
        super().__init__(**kwargs)

    def init_poolmanager(self, connections: int, maxsize: int,
                         block: bool = False, **pool_kwargs) -> None:
        # Mirror requests' contract: stored for pickling (adapter state rebuilds
        # re-run init_poolmanager, re-injecting the dial override idempotently).
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block
        self.poolmanager = IPDialPoolManager(
            self._hostname,
            self._ip,
            target_port=self._port,
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            **pool_kwargs,
        )


class _DefaultTimeoutSession(requests.Session):
    """Session enforcing a default timeout on every request (requests has none)."""

    def __init__(self, default_timeout: float) -> None:
        super().__init__()
        self._default_timeout = default_timeout

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self._default_timeout)
        return super().request(method, url, **kwargs)


def resolve_session(hostname: str, ip: str, *, verify: bool = False,
                    timeout: float = 30.0, port: int = 443,
                    pool_maxsize: int = 10, pool_connections: int = 4,
                    max_retries: int = 0) -> requests.Session:
    """Build a Session that reaches ``hostname`` at ``ip:port`` without DNS.

    Both HTTPS and plain-HTTP requests to exactly ``hostname`` are
    overridden (host-gated: redirects to any other host fall back to normal
    DNS resolution).  TLS verification defaults to off — this mode exists for
    pre-migration sites whose certificate does not (yet) match; pass
    verify=True (or a CA bundle path) when it does. The default timeout
    applies to every request that does not pass its own.
    """
    session = _DefaultTimeoutSession(timeout)
    session.verify = verify
    # R1 pitfall: hostile HTTPS_PROXY/ALL_PROXY/netrc must not hijack the
    # session or leak credentials.
    session.trust_env = False
    session.mount(
        "https://",
        IPDialHTTPAdapter(
            hostname,
            ip,
            port=port,
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            max_retries=max_retries,
        ),
    )
    session.mount(
        "http://",
        IPDialHTTPAdapter(
            hostname,
            ip,
            port=port,
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            max_retries=max_retries,
        ),
    )
    return session


# --------------------------------------------------------------------------
# Browser proxy: TLS-terminating, URL-rewriting, single hostname
# --------------------------------------------------------------------------


def cert_paths(cert_dir: Path) -> tuple[Path, Path]:
    """The resolved certificate/key pair the proxy listener reads.

    ONE owner for the filenames: ``ensure_cert`` generates them and the
    command body protects them from a ``--report`` collision, so neither
    can drift to a different name.  ``ensure_cert`` itself uses
    :func:`cert_file_paths` (UNRESOLVED): resolving a symlink before
    generation handed openssl the link TARGET, an arbitrary-file overwrite.
    """
    directory = Path(cert_dir)
    return (directory / _CERT_FILE).resolve(), (directory / _KEY_FILE).resolve()


def cert_file_paths(cert_dir: Path) -> tuple[Path, Path]:
    """The pair's own directory entries, never followed (generation owner)."""
    directory = Path(cert_dir)
    return directory / _CERT_FILE, directory / _KEY_FILE


def _cert_target_problem(path: Path) -> str | None:
    """Why an existing cert/key target cannot be replaced, or None.

    A symlink is refused even when it points at a regular file: openssl
    would write THROUGH it and replace the target (the R20 arbitrary-file
    primitive).  A FIFO/device/socket/directory is refused too — openssl
    writing a FIFO blocked forever.  Generation then writes fresh temp
    names and ``os.replace``s them over the directory entries, so a link
    that appears after this check is replaced itself, never followed.
    """
    try:
        if path.is_symlink():
            return f"{path} is a symbolic link (refusing to follow it)"
        if path.exists() and not path.is_file():
            return f"{path} is not a regular file"
    except OSError as exc:
        return f"cannot inspect {path}: {exc}"
    return None


def _cert_pair_usable(cert_path: Path, key_path: Path,
                      timeout_s: float | None = None,
                      renew_before_s: int | None = None) -> bool:
    """Is the existing pair unexpired, key-matched AND localhost-identified?

    The proxy is a browser-testing listener, but serving an expired (or
    mismatched) certificate is never useful: every client refuses it, and
    the failure looks like a proxy bug.  A pair is reused only when openssl
    proves expiry, the key match, and the exact subject/SAN identity
    (localhost + 127.0.0.1 + ::1); anything else is regenerated by the
    caller.  Every openssl call is bounded: a wedged one must not outlive
    the run.
    """
    renew_before_s = (renew_before_s if renew_before_s is not None
                      else ProxySettings().cert_renew_before_s)
    checks = (
        ["openssl", "x509", "-in", str(cert_path), "-noout", "-checkend",
         str(renew_before_s)],
        ["openssl", "x509", "-in", str(cert_path), "-noout", "-pubkey"],
        ["openssl", "pkey", "-in", str(key_path), "-pubout"],
        # Text identity, not only ``-checkhost``/``-checkip``: those flags
        # answered differently on the shipped OpenSSL 3.0 build and reused a
        # wrong-host pair.  The generated pair's own subject and SAN text is
        # the portable proof.
        ["openssl", "x509", "-in", str(cert_path), "-noout",
         "-subject", "-ext", "subjectAltName"],
    )
    outputs: list[str] = []
    for command in checks:
        try:
            proc = subprocess.run(command, capture_output=True, text=True,
                                  check=False, timeout=timeout_s)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return False
        if proc.returncode != 0:
            return False
        outputs.append(proc.stdout.strip())
    if outputs[1] != outputs[2]:
        return False
    # Expiry and key-match alone are not identity: a key-matched pair for a
    # DIFFERENT host was reused and every browser refused the handshake.
    # ``ensure_cert`` promises CN=localhost + SAN localhost/127.0.0.1/::1,
    # so prove all three names on the very certificate we are about to serve.
    identity = " ".join(outputs[3].replace("\n", " ").split())
    subject_ok = "CN = localhost" in identity or "CN=localhost" in identity
    san_ok = ("DNS:localhost" in identity
              and "IP Address:127.0.0.1" in identity
              and ("IP Address:0:0:0:0:0:0:0:1" in identity
                   or "IP Address:::1" in identity))
    return subject_ok and san_ok


def _reserve_temp(directory: Path, stem: str,
                  journal: list[Path]) -> Path:
    """A unique, never-pre-existing temp path in ``directory``.

    The candidate enters ``journal`` BEFORE ``O_CREAT|O_EXCL``: mkstemp
    created the file first and returned its name afterwards, so a stop on
    that boundary left a ``.cert.pem.tmp-*`` no finally could see.  The
    placeholder is removed immediately so openssl creates its own
    (mode-controlled) output; the caller's finally unlinks every journal
    entry, which also covers a stop between this return and the caller's
    assignment.  The random name makes a concurrent symlink swap
    impractical, and ``os.replace`` below never follows a link.
    """
    for _ in range(100):
        path = directory / f".{stem}.tmp-{secrets.token_hex(16)}"
        journal.append(path)
        try:
            fd = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600)
        except FileExistsError:
            journal.remove(path)
            continue
        try:
            os.close(fd)
        finally:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        return path
    raise WptError(
        f"cannot reserve a certificate temp file in {directory}")


def _sweep_stale_cert_temps(cert_dir: Path, timeout_s: float) -> None:
    """Remove a killed run's ``.{key,cert}.pem.tmp-*`` older than the
    openssl hard bound.

    A live generation cannot outlive ``timeout_s`` (subprocess.run is
    bounded), so an older temp has no owner.  A shorter age is never swept:
    a concurrent proxy could be writing it.
    """
    cutoff = time.time() - max(1.0, float(timeout_s))
    for stem in (_KEY_FILE, _CERT_FILE):
        for candidate in cert_dir.glob(f".{stem}.tmp-*"):
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
            except OSError:
                pass


def ensure_cert(cert_dir: Path, *,
                timeout_s: float | None = None,
                validity_days: int | None = None,
                renew_before_s: int | None = None) -> tuple[Path, Path]:
    """Generate (or reuse) the self-signed localhost certificate used by the
    proxy listener: CN=localhost, SAN localhost + 127.0.0.1 + ::1, with the
    configured validity period (default 7 days).

    An existing cert.pem/key.pem pair is reused only while it is
    unexpired (and not inside the renewal horizon), its key matches the
    certificate, and its subject/SAN still name localhost + 127.0.0.1 +
    ::1.  An expired, mismatched or wrong-host pair is regenerated, never
    served: a shipped certificate from an earlier session outlived its
    seven days and every browser refused the proxy.

    The pair is generated into fresh temp files and atomically replaced
    onto the directory entries, so a symlink/FIFO never receives bytes and
    a wedged openssl is bounded by ``timeout_s``.
    """
    cert_dir = Path(cert_dir)
    cfg = ProxySettings()
    validity_days = (validity_days if validity_days is not None
                     else cfg.cert_validity_days)
    renew_before_s = (renew_before_s if renew_before_s is not None
                      else cfg.cert_renew_before_s)
    cert_path, key_path = cert_file_paths(cert_dir)
    for target in (cert_path, key_path):
        problem = _cert_target_problem(target)
        if problem is not None:
            raise WptError(f"refusing the proxy certificate files: {problem}")
    if cert_path.is_file() and key_path.is_file() \
            and _cert_pair_usable(cert_path, key_path, timeout_s,
                                  renew_before_s):
        return cert_path, key_path
    cert_dir.mkdir(parents=True, exist_ok=True)
    if timeout_s is not None:
        _sweep_stale_cert_temps(cert_dir, timeout_s)
    reserved: list[Path] = []
    tmp_key = tmp_cert = None
    try:
        tmp_key = _reserve_temp(cert_dir, _KEY_FILE, reserved)
        tmp_cert = _reserve_temp(cert_dir, _CERT_FILE, reserved)
        command = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256",
            "-days", str(validity_days), "-nodes",
            "-keyout", str(tmp_key), "-out", str(tmp_cert),
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1",
        ]
        try:
            proc = subprocess.run(command, capture_output=True, text=True,
                                  check=False, timeout=timeout_s)
        except FileNotFoundError as e:
            raise WptError(
                "openssl executable not found; it is required to generate "
                "the proxy certificate"
            ) from e
        except subprocess.TimeoutExpired as e:
            raise WptError(
                "openssl did not finish generating the proxy certificate "
                f"within {timeout_s:g}s; nothing was installed"
                if timeout_s is not None else
                "openssl did not finish generating the proxy certificate"
            ) from e
        if proc.returncode != 0:
            raise WptError(
                f"openssl failed (exit {proc.returncode}): "
                f"{proc.stderr.strip()}")
        for generated in (tmp_cert, tmp_key):
            problem = _cert_target_problem(generated)
            if problem is not None:
                raise WptError(
                    f"openssl did not produce a regular {generated.name}: "
                    f"{problem}")
        tmp_key.chmod(0o600)
        os.replace(tmp_key, key_path)
        tmp_key = None
        os.replace(tmp_cert, cert_path)
        tmp_cert = None
    finally:
        # Every journaled candidate, even one whose caller assignment never
        # happened (a stop inside ``_reserve_temp`` or on its return).
        for leftover in (*reserved, tmp_cert, tmp_key):
            if leftover is not None:
                try:
                    leftover.unlink()
                except OSError:
                    pass
    log.info("generated self-signed proxy certificate in %s", cert_dir)
    return cert_path, key_path


def _decode_content(encoding: str, data: bytes,
                    limit: int | None = None) -> bytes | None:
    """Decode a compressed upstream body so URL rewriting stays byte-safe.

    Returns None when the encoding is unknown or undecodable — the caller
    then forwards the body untouched and keeps its Content-Encoding header.
    ``limit`` bounds the DECODED size before the whole payload is buffered:
    a 20 KiB gzip bomb expands to 20 MiB (and a shipped-cap 8 MiB body to
    terabytes), so an over-limit output raises :class:`LineTooLong` instead
    of being decompressed into memory and then served as a 200.
    """
    if not encoding or encoding == "identity":
        return data

    def _bounded(decomp):
        # max_length stops zlib from materializing more than one byte past
        # the configured ceiling.  ``unconsumed_tail``/a full-length result
        # then proves the payload is over the bound.
        cap = 0 if limit is None else max(1, int(limit))
        out = decomp.decompress(data, cap + 1 if cap else 0)
        if cap and (len(out) > cap or decomp.unconsumed_tail):
            raise http.client.LineTooLong(
                f"upstream response body exceeds {cap} bytes after "
                f"{encoding} decoding")
        tail = decomp.flush()
        if cap and len(out) + len(tail) > cap:
            raise http.client.LineTooLong(
                f"upstream response body exceeds {cap} bytes after "
                f"{encoding} decoding")
        # A complete single-member stream ends at eof with no bytes left
        # over.  A TRUNCATED member (``eof`` false) or a CONCATENATED
        # multi-member stream (``unused_data``) must not be served as a
        # decoded 200: the first case would expose a partial plaintext
        # body, the second would silently drop every member after the
        # first.  Returning None forwards the original bytes untouched
        # with the original Content-Encoding, so the browser decodes it.
        if not decomp.eof or decomp.unused_data:
            return None
        return out + tail

    try:
        if encoding in ("gzip", "x-gzip"):
            return _bounded(zlib.decompressobj(16 + zlib.MAX_WBITS))
        if encoding == "deflate":
            try:
                return _bounded(zlib.decompressobj())
            except zlib.error:
                return _bounded(zlib.decompressobj(-zlib.MAX_WBITS))
    except (OSError, EOFError, zlib.error):
        return None
    return None


class _ProxyHTTPServer(ThreadingHTTPServer):
    """Listener that terminates TLS in the worker thread, not in the accept
    loop: a client that connects but never handshakes must not stall the
    listener for everyone else."""

    daemon_threads = True

    def server_bind(self):
        """Bind without ``HTTPServer``'s blocking ``getfqdn`` lookup.

        ``http.server.HTTPServer.server_bind`` calls ``socket.getfqdn(host)``
        to fill ``server_name``.  That is a libc DNS lookup with no budget;
        on macOS the localhost reverse lookup can stall the entire proxy
        startup before the receipt is written.  The listener only needs the
        address it actually bound, never a canonical hostname.
        """
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = host
        self.server_port = port

    def finish_request(self, request, client_address):
        tls = self.proxy._tls_server_context.wrap_socket(request, server_side=True)
        super().finish_request(tls, client_address)

    def handle_error(self, request, client_address):
        # Default prints a traceback to stderr; route through wpt logging.
        log.debug("proxy connection error from %s", client_address, exc_info=True)


class _ProxyHandler(BaseHTTPRequestHandler):
    """HTTP plumbing for the browser side; upstream policy lives in ProxyServer."""

    protocol_version = "HTTP/1.1"

    @property
    def _proxy(self) -> "ProxyServer":
        return self.server.proxy  # type: ignore[attr-defined]

    def setup(self):
        self.timeout = self._proxy._timeout
        super().setup()

    def do_GET(self):
        self._forward()

    do_POST = do_GET
    do_HEAD = do_GET

    def log_message(self, fmt, *args):
        log.debug(fmt, *args)

    def log_error(self, fmt, *args):
        log.warning(fmt, *args)

    def _read_request_body(self) -> bytes | None:
        """Buffer the request body; None means an error response was sent.

        ONE absolute deadline from request start (a byte-drip resets the
        per-read socket timeout forever), an EXACT Content-Length check (a
        half-closed short upload was forwarded as a complete POST) and the
        configured request ceiling answered as 413 BEFORE buffering.
        """
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            self.send_error(411, "Length Required")
            return None
        raw_length = self.headers.get("Content-Length")
        if not raw_length:
            return b""
        try:
            length = int(raw_length)
        except ValueError:
            self.send_error(400, "Bad Request")
            return None
        if length < 0:
            self.send_error(400, "Bad Request")
            return None
        cap = self._proxy._max_request_bytes
        if cap is not None and length > cap:
            log.warning(
                "proxy rejected a %d-byte request body above the %d-byte "
                "ceiling", length, cap)
            self.send_error(413, "Payload Too Large")
            return None
        if not length:
            return b""
        absolute = time.monotonic() + max(0.001, self._proxy._timeout)
        try:
            return _read_exact(self.rfile, length, deadline=absolute,
                               sock=self.connection)
        except TimeoutError:
            log.warning(
                "proxy request body did not complete within %.3fs",
                max(0.001, self._proxy._timeout))
            self.send_error(408, "Request Timeout")
        except (http.client.IncompleteRead, OSError, ValueError):
            log.warning(
                "proxy request body ended before its declared %d bytes",
                length)
            self.send_error(400, "Bad Request")
        return None

    def _forward(self):
        proxy = self._proxy
        log.debug("proxy request %s %s", self.command, self.path.split("?", 1)[0])
        body = self._read_request_body()
        if body is None:
            return
        try:
            status, headers_out, payload, upstream_length = proxy._upstream_exchange(
                self.command, self.path, body,
                proxy._forward_request_headers(self.headers),
            )
        except http.client.InvalidURL as exc:
            log.warning("rejected malformed request line %s %s: %s",
                        self.command, self.path.split("?", 1)[0], exc)
            self.send_error(400, "Bad Request")
            return
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            log.warning("upstream %s:%s unreachable for %s %s: %s",
                        proxy.ip, proxy._upstream_port, self.command,
                        self.path.split("?", 1)[0], exc)
            self.send_error(502, "upstream unreachable")
            return
        self._send_upstream_response(status, headers_out, payload, upstream_length)

    def _send_upstream_response(self, status: int,
                                upstream_headers: list[tuple[str, str]],
                                payload: bytes, upstream_length: str | None):
        proxy = self._proxy
        keep_encoding = False
        encoding = ",".join(
            value for name, value in upstream_headers
            if name.lower() == "content-encoding"
        ).strip().lower()
        if encoding:
            try:
                decoded = _decode_content(
                    encoding, payload, proxy._max_body_bytes)
            except http.client.HTTPException as exc:
                # A compressed answer that expands past the configured body
                # cap is a REFUSED answer (502), never a 200 carrying a
                # multi-megabyte/terabyte payload the cap exists to stop.
                log.warning(
                    "upstream %s:%s response refused after %s decoding: %s",
                    proxy.ip, proxy._upstream_port, encoding, exc)
                self.send_error(502, "upstream response body too large")
                return
            if decoded is None:
                # Unknown/corrupt compression: forward the bytes untouched and
                # keep Content-Encoding so the browser can still decode;
                # rewriting compressed bytes would corrupt them.
                keep_encoding = True
                log.debug("proxy passthrough for content-encoding %r (%s)",
                          encoding, self.path.split("?", 1)[0])
            else:
                payload = decoded
        if not keep_encoding:
            payload = proxy._rewrite_body(payload)
        self.send_response(status)
        for name, value in upstream_headers:
            lname = name.lower()
            if lname in _RESPONSE_DROP_HEADERS \
                    and not (lname == "content-encoding" and keep_encoding):
                continue
            if lname == "location":
                value = proxy._rewrite_location(value)
            elif lname == "set-cookie":
                value = proxy._rewrite_set_cookie(value)
            self.send_header(name, value)
        # HEAD mirrors the upstream's declared length; otherwise ours reflects
        # the (possibly rewritten) body.
        length = upstream_length if (self.command == "HEAD" and upstream_length) \
            else str(len(payload))
        self.send_header("Content-Length", length)
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD" and payload:
            self.wfile.write(payload)


def _read_upstream_head(fp, *, deadline: float | None = None,
                        sock: socket.socket | None = None
                        ) -> tuple[int, list[tuple[str, str]]]:
    """Read ONE status line + header block (1xx interim or final).

    ``http.client.getresponse()`` cannot parse a second answer on the same
    request (it raises ``ResponseNotReady`` after any status), so a 103
    Early Hints head made every real response a 502.  This reader owns the
    multi-head loop at the socket's single buffered reader (no read-ahead
    is lost between heads).

    Every read is bounded by the SAME absolute ``deadline`` (socket timeout
    re-armed to the remaining budget) and the block itself by a total-byte
    and header-count ceiling: a peer dripping headers resets a per-read
    timeout forever, and an endless list of header lines grows memory
    without bound.  An over-limit answer raises an ``http.client`` exception,
    which the proxy's existing handler answers with 502.
    """
    total = 0

    def _remaining() -> float | None:
        if deadline is None:
            return None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("upstream response head exceeded its deadline")
        return max(0.001, remaining)

    def _readline() -> bytes:
        nonlocal total
        _remaining()  # fast, explicit expiry before the byte loop
        # ``BufferedReader.readline`` loops on recv; a peer dripping one
        # byte just under the socket timeout kept it alive far past the
        # absolute deadline.  The same re-armed byte loop the body uses
        # bounds EVERY status/header line.
        raw = _read_line_bounded(
            fp, deadline, sock, limit=_CHUNK_LINE_LIMIT)
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("upstream response head exceeded its deadline")
        total += len(raw)
        if total > _MAX_UPSTREAM_HEAD_BYTES:
            raise http.client.LineTooLong(
                f"upstream response headers exceed "
                f"{_MAX_UPSTREAM_HEAD_BYTES} bytes")
        if len(raw) >= _CHUNK_LINE_LIMIT and not raw.endswith((b"\r\n", b"\n")):
            raise http.client.LineTooLong("upstream response header line")
        return raw

    line = _readline()
    if not line:
        raise http.client.RemoteDisconnected(
            "remote end closed connection without a response")
    try:
        version, status, *_rest = line.decode("iso-8859-1").strip().split()
        code = int(status)
    except (UnicodeDecodeError, ValueError) as exc:
        raise http.client.BadStatusLine(line) from exc
    if not version.startswith("HTTP/"):
        raise http.client.BadStatusLine(line)
    headers: list[tuple[str, str]] = []
    while True:
        raw = _readline()
        if not raw:
            raise http.client.IncompleteRead(b"".join(
                name.encode() + b": " + value.encode() + b"\r\n"
                for name, value in headers))
        if raw in (b"\r\n", b"\n"):
            return code, headers
        if len(headers) >= _MAX_UPSTREAM_HEADERS:
            raise http.client.LineTooLong(
                f"upstream response carries more than "
                f"{_MAX_UPSTREAM_HEADERS} headers")
        text = raw.decode("iso-8859-1").rstrip("\r\n")
        name, sep, value = text.partition(":")
        if not sep:
            raise http.client.LineTooLong(text)
        headers.append((name.strip(), value.strip()))


def _read_final_upstream_head(fp, *, deadline: float | None = None,
                              sock: socket.socket | None = None
                              ) -> tuple[int, list[tuple[str, str]]]:
    """Read past interim 1xx answers to the FINAL head; cap the interim count.

    RFC 9110 permits any number of 1xx heads, but an endless 100-Continue
    stream is a peer that never answers.  The cap is structural and mapped
    to the proxy's existing 502 path by the caller.
    """
    interim = 0
    while True:
        status, headers = _read_upstream_head(
            fp, deadline=deadline, sock=sock)
        if 100 <= status < 200 and status != 101:
            interim += 1
            if interim > _MAX_UPSTREAM_INTERIM_HEADS:
                raise http.client.LineTooLong(
                    "upstream sent more than "
                    f"{_MAX_UPSTREAM_INTERIM_HEADS} interim heads")
            continue
        return status, headers


#: Structural ceiling for one chunk-size/trailer LINE (not the body size).
_CHUNK_LINE_LIMIT = 65537
#: Hex digits in a chunk size (64-bit count is already absurd; reject junk).



def _arm_read(sock: socket.socket | None, deadline: float | None) -> None:
    """Re-arm ``sock`` to the remaining absolute budget before one read."""
    if deadline is None:
        return
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("upstream response body exceeded its deadline")
    if sock is not None:
        try:
            sock.settimeout(max(0.001, remaining))
        except OSError:
            pass


def _read_some(fp, count: int) -> bytes:
    """One bounded read that returns AS SOON AS bytes are available.

    ``BufferedReader.read(n)`` loops on ``recv`` until n bytes arrive; a
    peer dripping one byte every 0.4 s reset the per-recv timeout forever
    and outlived the absolute deadline.  ``read1`` returns what the next
    recv produced, so ``_arm_read`` is re-evaluated for every byte.  A
    BytesIO double has no ``read1`` and keeps its synchronous contract.
    """
    reader = getattr(fp, "read1", None)
    if callable(reader):
        return reader(count)
    reader = getattr(fp, "read", None)
    if callable(reader):
        return reader(count)
    # A read-only test double exposing just ``readline`` (the old head
    # reader's contract) still works; BufferedReader always has read1.
    return fp.readline(count)


def _read_exact(fp, count: int, *, deadline: float | None = None,
                sock: socket.socket | None = None) -> bytes:
    """Read exactly ``count`` bytes under the absolute body deadline."""
    chunks: list[bytes] = []
    remaining = count
    while remaining > 0:
        _arm_read(sock, deadline)
        chunk = _read_some(fp, min(remaining, 65536))
        if not chunk:
            raise http.client.IncompleteRead(b"".join(chunks), remaining)
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_line_bounded(fp, deadline: float | None,
                       sock: socket.socket | None,
                       limit: int = _CHUNK_LINE_LIMIT) -> bytes:
    """Read one CRLF/LF-terminated line, re-arming the deadline per byte.

    ``BufferedReader.readline`` can spend many per-recv timeouts inside one
    call, so a peer dripping a chunk-size line could outlive the absolute
    budget.  This reads ONE byte per armed call.
    """
    out = bytearray()
    while len(out) <= limit:
        _arm_read(sock, deadline)
        chunk = _read_some(fp, 1)
        if not chunk:
            return bytes(out)
        out += chunk
        if chunk == b"\n":
            return bytes(out)
    raise http.client.LineTooLong("upstream response body line")


def _read_upstream_body(fp, method: str, status: int,
                        headers: list[tuple[str, str]], *,
                        deadline: float | None = None,
                        sock: socket.socket | None = None,
                        max_bytes: int | None = None) -> bytes:
    """Read one FINAL response body (length, chunked, or close-delimited).

    Every read is armed to the SAME absolute ``deadline`` the head used:
    requests' per-read socket timeout resets on every dripped byte, so a
    body without this bound answered 4x its configured timeout.  A
    malformed chunk (negative/non-hex size, missing CRLF) is rejected
    instead of being read as an endless stream, and ``max_bytes`` bounds
    the buffer (the proxy doc's historical "buffered" note is now a
    configured ceiling, not an unbounded read).
    """
    if method.upper() == "HEAD" or status == 101 \
            or status in BODYLESS_STATUSES:
        return b""

    def _cap() -> None:
        if max_bytes is not None and total > max_bytes:
            raise http.client.LineTooLong(
                f"upstream response body exceeds {max_bytes} bytes")

    lower = {name.lower(): value for name, value in headers}
    total = 0
    if "chunked" in lower.get("transfer-encoding", "").lower():
        chunks: list[bytes] = []
        while True:
            size_line = _read_line_bounded(fp, deadline, sock)
            if not size_line:
                raise http.client.IncompleteRead(b"".join(chunks))
            if not size_line.endswith(b"\n"):
                raise http.client.IncompleteRead(b"".join(chunks))
            size_text = size_line.split(b";", 1)[0].strip()
            if CHUNK_SIZE_RE.fullmatch(size_text) is None:
                raise http.client.IncompleteRead(b"".join(chunks))
            size = int(size_text, 16)
            if size == 0:
                # Trailer section (possibly empty), bounded like a head.
                trailer_bytes = 0
                while True:
                    trailer = _read_line_bounded(fp, deadline, sock)
                    if not trailer:
                        # RFC 9112: the trailer section (and the message)
                        # ends only at a real empty LINE.  EOF after
                        # ``0\r\n`` was read as the terminator, so an
                        # origin that closed mid-message was presented as
                        # a complete 200 body.
                        raise http.client.IncompleteRead(b"".join(chunks))
                    trailer_bytes += len(trailer)
                    if trailer_bytes > _MAX_UPSTREAM_HEAD_BYTES:
                        raise http.client.LineTooLong(
                            "upstream response trailer section")
                    if trailer in (b"\r\n", b"\n"):
                        break
                break
            total += size
            _cap()
            chunks.append(_read_exact(fp, size, deadline=deadline, sock=sock))
            if _read_exact(fp, 2, deadline=deadline, sock=sock) != b"\r\n":
                raise http.client.IncompleteRead(b"".join(chunks))
        return b"".join(chunks)
    length = lower.get("content-length")
    if length is not None:
        try:
            declared = int(length)
        except ValueError as exc:
            raise http.client.IncompleteRead(b"") from exc
        if declared < 0:
            raise http.client.IncompleteRead(b"")
        total = declared
        _cap()
        return _read_exact(fp, declared, deadline=deadline, sock=sock)
    chunks = []
    while True:
        _arm_read(sock, deadline)
        chunk = _read_some(fp, 65536)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        _cap()
        chunks.append(chunk)


class ProxyServer:
    """Threaded TLS-terminating browser proxy for one hostname/ip pair.

    start() is non-blocking and returns the bound port (useful with port=0);
    serve() blocks with SIGINT/SIGTERM handling for CLI use; stop() is
    idempotent. The listener only ever binds 127.0.0.1.
    """

    def __init__(self, hostname: str, ip: str, *,
                 port: int = DEFAULT_PROXY_PORT,
                 upstream_port: int = 443, cert_dir: Path = DEFAULT_CERT_DIR,
                 timeout: float = 30.0,
                 max_body_bytes: int | None = None,
                 max_request_bytes: int | None = None,
                 cert_timeout_s: float | None = None,
                 cert_validity_days: int | None = None,
                 cert_renew_before_s: int | None = None) -> None:
        if max_body_bytes is not None and (
                isinstance(max_body_bytes, bool)
                or not isinstance(max_body_bytes, int)
                or max_body_bytes < 1):
            raise ValueError(
                f"proxy max_body_bytes must be an integer >= 1, got "
                f"{max_body_bytes!r}")
        if max_request_bytes is not None and (
                isinstance(max_request_bytes, bool)
                or not isinstance(max_request_bytes, int)
                or max_request_bytes < 1):
            raise ValueError(
                f"proxy max_request_bytes must be an integer >= 1, got "
                f"{max_request_bytes!r}")
        # Normalize once: a trailing-dot FQDN form must not leak into Host,
        # SNI or the rewrite patterns (URLs never carry the trailing dot).
        # Unicode normalization/case is part of the SAME normalization: the
        # body regex is compiled over BYTES, where ``re.IGNORECASE`` is
        # ASCII-only, so a configured ``TÄST.EXAMPLE`` left a page's lowercase
        # ``täst.example`` rewrite untouched and the browser left the override.
        # Keep BOTH the normalized and the original spelling in host_forms.
        raw_hostname = hostname.rstrip(".")
        normalized = unicodedata.normalize("NFC", raw_hostname).lower()
        if not normalized:
            raise ValueError("proxy --hostname must not be empty")
        hostname = normalized
        # IDNA validation belongs HERE, at the engine boundary: the body
        # rewrite pattern needs the encoded form, and an invalid label used
        # to raise UnicodeEncodeError outside run_proxy's try (a traceback).
        try:
            encoded_host = hostname.encode("idna")
        except UnicodeError as exc:
            raise ValueError(
                f"proxy --hostname {raw_hostname!r} is not a valid IDNA name"
            ) from exc
        self.hostname = hostname
        self.ip = ip
        self._listen_port = port
        self._upstream_port = upstream_port
        self._cert_dir = Path(cert_dir)
        self._timeout = timeout
        self._max_body_bytes = max_body_bytes
        self._max_request_bytes = max_request_bytes
        self._cert_timeout_s = cert_timeout_s
        self._cert_validity_days = cert_validity_days
        self._cert_renew_before_s = cert_renew_before_s
        self._httpd: _ProxyHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._bound_port: int | None = None
        self._tls_server_context: ssl.SSLContext | None = None
        self._tls_client_context: ssl.SSLContext | None = None
        # Rewriting target origin, built in start() once the real port is known.
        self._origin_prefix: str | None = None
        # Absolute https://hostname (and http://hostname) URLs with an optional
        # explicit port, never a longer hostname sharing the prefix. The body
        # pattern also matches the JSON-escaped "\/" slash form common in
        # WordPress config payloads, and operates on bytes so non-ASCII
        # content is never corrupted.
        # Location/Set-Cookie/body arrive in EITHER the original Unicode
        # spelling an application wrote or the punycode form a browser/
        # server emitted.  ONE host_forms owner feeds all three patterns;
        # the body regex is compiled from its UTF-8 BYTES so a raw Unicode
        # URL inside a page is rewritten too (the punycode-only pattern
        # left it byte-identical and bypassed the override).
        host_forms = [encoded_host.decode("ascii")]
        # The bytes regex is ASCII-only under IGNORECASE, so BOTH directions
        # of the Unicode spelling matter: a lowercase configuration must
        # rewrite an UPPERCASE body, and decomposed (NFD) input from a
        # filesystem/editor must rewrite composed (NFC) output.  ONE
        # host_forms owner builds every spelling for all three patterns.
        for base in (normalized, raw_hostname):
            if not base:
                continue
            for composed in (unicodedata.normalize("NFC", base),
                             unicodedata.normalize("NFD", base)):
                for form in (composed, composed.upper()):
                    if form and form not in host_forms:
                        host_forms.append(form)
        # ONE Unicode pattern for all three surfaces.  The body used a
        # BYTES regex with IGNORECASE, which is ASCII-only: a page link
        # spelling ``mÄrchenbücher.example`` (mixed case on non-ASCII letters)
        # passed through byte-identical while ``MÄRCHENBÜCHER.EXAMPLE`` and the
        # lowercase form were rewritten.  The body rewrite decodes with
        # ``surrogateescape`` so arbitrary bytes survive, then applies the
        # same Unicode-aware host alternation the Location/cookie regexes
        # already used.
        host = "(?:" + "|".join(re.escape(form) for form in host_forms) + ")"
        self._body_url_re = re.compile(
            r"(?<![\w:/.\\-])(?:https?:)?(?:\\/|/){2}" + host
            + r"(?::\d+)?(?![\w.-])",
            re.IGNORECASE,
        )
        self._location_re = re.compile(
            r"(?<![\w:/.\\-])(?:https?:)?//" + host + r"(?::\d+)?(?![\w.-])",
            re.IGNORECASE
        )
        self._cookie_domain_re = re.compile(
            r"(\bdomain\s*=\s*\.?)" + host + r"(?![\w.-])", re.IGNORECASE
        )

    @property
    def port(self) -> int:
        """The listen port: the bound one once started, else the configured one."""
        return self._bound_port if self._bound_port is not None else self._listen_port

    @property
    def origin(self) -> str:
        """The rewrite origin (``https://localhost:<port>``) — ONE owner.

        The receipt, the start log, body/Location rewrites and the cookie
        Domain must all name THIS origin: advertising 127.0.0.1 while
        rewriting to localhost split a host-only cookie across two origins
        and broke WordPress's absolute login redirect.
        """
        if self._origin_prefix is None:
            raise RuntimeError("proxy origin is only known after start()")
        return self._origin_prefix

    def browser_url(self) -> str:
        """The URL the operator opens; always ``<origin>/``."""
        return f"{self.origin}/"

    def start(self) -> int:
        """Bind 127.0.0.1 and start serving in a daemon thread; returns the port."""
        if self._httpd is not None:
            assert self._bound_port is not None
            return self._bound_port
        cert_path, key_path = ensure_cert(
            self._cert_dir, timeout_s=self._cert_timeout_s,
            validity_days=self._cert_validity_days,
            renew_before_s=self._cert_renew_before_s)
        self._tls_server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._tls_server_context.load_cert_chain(cert_path, key_path)
        client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client.check_hostname = False
        client.verify_mode = ssl.CERT_NONE
        self._tls_client_context = client
        httpd = _ProxyHTTPServer(("127.0.0.1", self._listen_port), _ProxyHandler)
        httpd.proxy = self
        bound_port = httpd.server_address[1]
        thread = threading.Thread(
            target=httpd.serve_forever, name="wpt-proxy", daemon=True
        )
        # ALL-OR-NOTHING: publish the listener only once its serving thread
        # actually started.  A failed start leaves no half-built state for a
        # later stop() to trip over (R6-07).
        try:
            thread.start()
        except BaseException:
            try:
                httpd.server_close()
            except Exception:  # noqa: BLE001 — preserve the start failure
                pass
            raise
        self._bound_port = bound_port
        self._origin_prefix = f"https://{_ORIGIN_HOST}:{bound_port}"
        self._httpd = httpd
        self._thread = thread
        log.debug("proxy bound on 127.0.0.1:%s", bound_port)
        return bound_port

    def stop(self) -> None:
        """Close the listener and stop accepting. Idempotent."""
        httpd, self._httpd = self._httpd, None
        if httpd is None:
            return
        httpd.shutdown()
        httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            if self._thread.is_alive():
                log.warning("proxy accept thread did not exit within 2s")
            self._thread = None
        log.info("proxy stopped")

    def serve(self) -> None:
        """Start, then block until SIGINT, KeyboardInterrupt, or an
        external stop(); always stops the listener before returning.

        SIGTERM is deliberately NOT shadowed here: the CLI owns it
        (``cli._install_sigterm_self_shutdown``) and raises StopRequested so
        the run ends rc 1 with a failure pair.  A local handler that merely
        set this event made a real SIGTERM look like Ctrl-C (rc 0 and a
        success receipt).
        """
        self.start()
        log.info("proxy listening on %s (site %s at %s:%s)",
                 self.browser_url(), self.hostname, self.ip,
                 self._upstream_port)
        stop_signal = threading.Event()
        installed: list[tuple[int, object]] = []

        def _request_stop(signum, frame):  # noqa: ARG001 (signal handler signature)
            stop_signal.set()

        if threading.current_thread() is threading.main_thread():
            try:
                installed.append((signal.SIGINT,
                                  signal.signal(signal.SIGINT,
                                                _request_stop)))
            except (ValueError, OSError):
                pass  # restricted environment; KeyboardInterrupt still works
        try:
            while not stop_signal.wait(0.5):
                if self._httpd is None:
                    break  # stop() called externally
        except KeyboardInterrupt:
            pass
        finally:
            for sig, previous in installed:
                signal.signal(sig, previous)  # type: ignore[arg-type]
            self.stop()

    # -- upstream side -----------------------------------------------------

    def _forward_request_headers(self, browser_headers) -> dict[str, str]:
        out: dict[str, str] = {}
        for name, value in browser_headers.items():
            if name.lower() not in _REQUEST_DROP_HEADERS:
                out[name.lower()] = value
        return out

    def _upstream_exchange(self, method: str, path: str, body: bytes,
                           headers: dict[str, str]
                           ) -> tuple[int, list[tuple[str, str]], bytes, str | None]:
        """Send one request upstream (dial ip:upstream_port, SNI/Host = hostname)
        and buffer the response. Returns (status, headers, body, upstream
        Content-Length for HEAD mirroring)."""
        # ONE absolute budget covers dial + TLS + head + body.  Starting it
        # after the head let a dripped body answer 4x --timeout.
        absolute = time.monotonic() + self._timeout
        conn_sock = socket.create_connection(
            (self.ip, self._upstream_port),
            timeout=max(0.001, min(self._timeout,
                                   absolute - time.monotonic())),
        )
        try:
            conn_sock.settimeout(max(0.001, absolute - time.monotonic()))
            tls = self._tls_client_context.wrap_socket(
                conn_sock, server_hostname=self.hostname
            )
        except BaseException:
            conn_sock.close()
            raise
        # The dial is already done; the connection object exists to present the
        # canonical site origin: http.client derives Host from (hostname, 443)
        # and would attempt its own connect only if sock were still None.
        conn = http.client.HTTPSConnection(
            self.hostname, 443, timeout=self._timeout,
            context=self._tls_client_context,
        )
        conn.sock = tls
        fp = None
        try:
            conn.request(method, path, body=body if body else None,
                         headers=headers)
            # ONE buffered reader parses EVERY head on this request: RFC
            # 9110 permits any number of 1xx interim answers before the
            # final one, and 101 stays final (a protocol switch this plain
            # reverse proxy does not forward).
            fp = tls.makefile("rb")
            status, headers_out = _read_final_upstream_head(
                fp, deadline=absolute, sock=tls)
            payload = _read_upstream_body(
                fp, method, status, headers_out, deadline=absolute,
                sock=tls, max_bytes=self._max_body_bytes)
            upstream_length = next(
                (value for name, value in headers_out
                 if name.lower() == "content-length"), None)
        finally:
            if fp is not None:
                fp.close()
            conn.close()
        return status, headers_out, payload, upstream_length

    # -- rewriting ---------------------------------------------------------

    def _rewrite_body(self, data: bytes) -> bytes:
        # ``surrogateescape`` round-trips every byte exactly; only matched
        # URL spans are replaced, with ASCII origin bytes.
        text = data.decode("utf-8", "surrogateescape")
        if self._body_url_re.search(text):
            assert self._origin_prefix is not None
            return self._body_url_re.sub(self._origin_prefix, text) \
                .encode("utf-8", "surrogateescape")
        return data

    def _rewrite_location(self, value: str) -> str:
        assert self._origin_prefix is not None
        return self._location_re.sub(self._origin_prefix, value)

    def _rewrite_set_cookie(self, value: str) -> str:
        return self._cookie_domain_re.sub(rf"\g<1>{_ORIGIN_HOST}", value)


def run_proxy(hostname: str, ip: str, port: int = DEFAULT_PROXY_PORT,
              cert_dir: Path = DEFAULT_CERT_DIR) -> None:
    """CLI entry (`wpt proxy`): serve the browser proxy until Ctrl-C/SIGTERM."""
    ProxyServer(hostname, ip, port=port, cert_dir=cert_dir).serve()
