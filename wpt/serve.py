r"""wpt serve — the offline rehearsal HTTP server.

This module is the LOCAL-MODE-ONLY engine behind the ``wpt serve``
command: it puts the rehearsal zip behind plain HTTP on localhost so
``wpt verify --wp-url http://127.0.0.1:<port>`` re-checks every live
media reference WITHOUT the live site, and ``wpt walk`` can crawl the
same origin in a degraded, static-only mode.  The use case
(live-validated): after a local rehearsal (clean-files etc. over a
materialized zip twin), the operator serves the cleaned zip on
localhost and verifies the result offline BEFORE uploading anything
to the host.

What this is — deliberately:

* A READ-ONLY STATIC server over a :class:`~wpt.sources.zip.ZipSource`
  with root AUTO-DETECTED (the host-export twin nested under
  ``"<site>/"`` is stripped, so URLs are webroot-relative exactly like
  the live webroot).  Files are served as static bytes.
* PHP IS NOT EXECUTED.  A ``.php`` request answers the RAW SOURCE as
  ``text/plain`` — debuggable and harmless on localhost.  A rehearsal
  therefore walks media/uploads fine (verify only reads statuses, and
  every uploads URL maps 1:1 to a zip member), but RENDERED-PAGE
  crawling needs the real site: no WordPress ever runs here.  That limit
  is stated in the run's own receipt, because the pair's honest failure
  mode matters: the walker needs a ``text/html`` document, the only
  servable root here is ``index.php`` as ``text/plain``, so a ``verify``
  against this origin finds ZERO live references — which is why
  ``wpt verify`` answers "this is not a pass" there instead of the rc 0 a
  run that verified nothing used to report.  The server was NOT taught
  to fake a rendering for this: a static server cannot render WordPress,
  and anything it produced would be a pretence with a URL on it.
* LOCALHOST-ONLY BY DESIGN: the server binds ``127.0.0.1``, never
  ``0.0.0.0`` — a rehearsal twin (wp-config source included) must never
  be exposed.  This is structural, not a profile tunable.

URL -> zip-member mapping (the decode rule matches ``wpt.walk``'s ref
rule — the tail must equal the on-disk name — so verify's re-encode
round-trip holds):

* the path is percent-DECODED first, then ``.``/``..`` segments are
  collapsed.  Decode-before-collapse is the secure order: an encoded
  escape like ``/..%2Fx`` decodes to a traversal and resolves to
  NOTHING -> 404, so bytes outside the webroot can never leak.
* query and fragment are dropped (``/a.jpg?ver=5`` serves ``a.jpg``).
* ``/`` maps to ``index.php`` when present (served raw, like any other
  member); an absent index answers 404.  Every OTHER directory path
  answers 404 — KISS (v1 deliberately does NOT 301 to ``path + "/"``):
  ``wpt walk`` probes only ``/`` and verify never touches directories,
  and a static rehearsal has no use for index resolution.
* a missing member answers 404; a directory answers 404 (one code
  path: ``read_bytes`` raises SourceError for either).

HTTP surface: GET and HEAD only, on ONE shared code path (HEAD sends
the same headers with an empty body — correct for a static server and
cheap).  EVERY other method — including ones stdlib would answer 501 —
answers ``405`` with an ``Allow: GET, HEAD`` header, via a handler
``__getattr__`` catch-all on ``do_*`` (BaseHTTPRequestHandler dispatches
through ``getattr(self, "do_" + command)``).  Content-Type is sniffed by
extension (html/htm, css, js, php-as-text, txt, images, json, xml, pdf,
zip); everything unknown is ``application/octet-stream``.

Lifecycle: ``run_serve`` is a BLOCKING command body — no daemon, no
background thread (the CLI command blocks; that is the contract).  It
blocks in ``serve_forever`` until Ctrl-C, then shuts down cleanly
(rc 0, wherever the interrupt landed).  A bind failure (port in use)
is logged at error and answers rc 1.  The ZipSource is built ONCE by
:func:`build_server` — the single construction seam shared by
``run_serve`` and the tests — and closed by ``server_close``.  Every
member read rides a lock: ``zipfile.ZipFile`` is not thread-safe and
``ThreadingHTTPServer`` serves concurrently.

Logging: everything flows through ``wpt.log`` — the stdlib handler's
stderr ``log_message`` is silenced, one access line per request is
logged at DEBUG (method, path, status), and the command announces
itself with ONE info line:
``serving <zip> at http://127.0.0.1:<port>/ — Ctrl-C to stop``.
``handle_error`` is overridden for the same reason: a client dropping
mid-download (verify's streamed, body-less close) answers one DEBUG
line, never socketserver's stderr traceback.

Port: ``ctx.extra["port"]`` — the CLI's ``--port`` flag, whose default
(8080) is chosen AT the CLI (no new settings tunables); the 8080 here
is only the defensive fallback for a Ctx built without one.

``--report``: this module also owns :func:`run_receipt`, the ONE
rendering of a planless run's report (the command, the URL/host/port it
ran on, and its JSON twin) — ``serve`` writes it and ``wpt.proxy`` (the
sibling command body for ``wpt proxy``) imports it, so a run with no
plan has one report shape instead of one per command.  The writer is
``wpt.actions.registry.write_report``, the same one every other
``--report`` surface uses.

Error contract (binding, same as every command body): every
:class:`~wpt.types.WptError` and ``OSError`` — missing zip, bind
failure — is logged at error and answered rc 1; ``run_serve`` NEVER
raises and never lets a traceback reach the CLI.  Ctrl-C
(KeyboardInterrupt) is the operator's normal stop: rc 0.
"""

from __future__ import annotations

import json
import sys
import threading
from collections.abc import Sequence
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import unquote

from . import __version__
from .config import redact_text
from .log import get_logger
from .ports import DEFAULT_SERVE_PORT, coerce_port
from .sources.zip import ZipSource
from .types import RunControl, SourceError, WptError

if TYPE_CHECKING:
    # Annotation-only (same pattern as wpt/walk.py): the CLI lazy-calls
    # this module, so there is no import cycle at runtime.
    from .cli import Ctx

__all__ = ["build_server", "run_serve", "run_receipt"]

log = get_logger("serve")

# Structural facts, NOT profile tunables (SPEC hard rule; same convention
# as wpt/walk.py's crawler facts): the bind address is localhost-only by
# design (see module docstring), the webroot index is WordPress' own, and
# the fallback is the SAME exported default the CLI's --port reads.
_BIND_HOST = "127.0.0.1"
_ROOT_INDEX = "index.php"
_FALLBACK_PORT = DEFAULT_SERVE_PORT

# Extension -> Content-Type.  ".php" is text/plain: PHP is never executed,
# the raw source IS the answer (see module docstring).  Everything not
# listed answers application/octet-stream.
_CONTENT_TYPES = {
    "html": "text/html; charset=utf-8",
    "htm": "text/html; charset=utf-8",
    "css": "text/css; charset=utf-8",
    "js": "text/javascript; charset=utf-8",
    "txt": "text/plain; charset=utf-8",
    "php": "text/plain; charset=utf-8",
    "json": "application/json",
    "xml": "application/xml",
    "pdf": "application/pdf",
    "zip": "application/zip",
    "gif": "image/gif",
    "ico": "image/x-icon",
    "jpeg": "image/jpeg",
    "jpg": "image/jpeg",
    "png": "image/png",
    "svg": "image/svg+xml",
    "webp": "image/webp",
    "avif": "image/avif",
}


def _content_type(member: str) -> str:
    """Content-Type sniffed from the zip member's extension."""
    if "." not in member:
        return "application/octet-stream"
    ext = member.rsplit(".", 1)[-1].lower()
    return _CONTENT_TYPES.get(ext, "application/octet-stream")


def _map_path(raw: str) -> str | None:
    """One request path -> one webroot-relative zip member, or None.

    Server-side resolution order: query/fragment dropped, path
    percent-DECODED, then ``.``/``..`` segments collapsed (decode first,
    so an encoded escape can never sneak above the root).  A traversal
    that pops above the webroot resolves to NOTHING -> the caller
    answers 404 (bytes outside the zip can never leak).  The empty root
    (``/``, or anything collapsing to it) maps to ``index.php`` — an
    absent index 404s through the same read path as any missing file.
    """
    path = raw.split("?", 1)[0].split("#", 1)[0]
    segments: list[str] = []
    for segment in unquote(path).split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if not segments:
                return None  # escape above the webroot
            segments.pop()
        else:
            segments.append(segment)
    return "/".join(segments) if segments else _ROOT_INDEX


class _ZipHandler(BaseHTTPRequestHandler):
    """One request against the rehearsal zip: GET/HEAD only, everything
    else 405 — every byte comes from ONE ZipSource, never from disk."""

    protocol_version = "HTTP/1.1"
    server_version = f"wpt-serve/{__version__}"

    # -- dispatch ---------------------------------------------------------

    def do_GET(self) -> None:
        self._serve()

    do_HEAD = do_GET  # same code path; _reply suppresses the body

    def __getattr__(self, name: str):
        """The 405 catch-all: any method without a ``do_*`` here answers
        405 instead of stdlib's 501 — GET and HEAD are the whole surface."""
        if name.startswith("do_"):
            return self._not_allowed
        raise AttributeError(name)

    # -- serving ------------------------------------------------------------

    def _serve(self) -> None:
        member = _map_path(self.path)
        if member is None:
            self._reply(404, b"not found\n")
            return
        try:
            # zipfile is not thread-safe; ThreadingHTTPServer serves
            # concurrently — every member read rides the server's lock.
            with self.server.zip_lock:
                data = self.server.zip_source.read_bytes(member)
        except (WptError, OSError):
            # missing member or a directory path: both answer 404
            # (read_bytes raises SourceError for either — one code path).
            self._reply(404, b"not found\n")
            return
        self._reply(200, data, _content_type(member))

    def _not_allowed(self) -> None:
        # Answer 405 IMMEDIATELY and close the connection.  Draining a
        # declared Content-Length before answering made a client that sends
        # ``Content-Length: 100000000`` and no body pin this handler in
        # ``rfile.read`` forever (one thread per request).  The unread body
        # dies with the socket; no server-side drain is needed for a
        # connection this server is about to close.
        self.close_connection = True
        self._reply(405, b"method not allowed\n", allow="GET, HEAD",
                    close=True)

    def _reply(self, status: int, body: bytes,
               content_type: str = "text/plain; charset=utf-8",
               allow: str | None = None, *, close: bool = False) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if allow:
            self.send_header("Allow", allow)
        if close:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def version_string(self) -> str:
        return self.server_version  # no Python-version advertisement

    # -- logging ------------------------------------------------------------

    def log_request(self, code: str | int = "-", size: str | int = "-") -> None:
        """The one access line per request, at DEBUG (method, path, status)."""
        log.debug("%s %s -> %s", self.command, self.path, code)

    def log_message(self, fmt: str, *args: object) -> None:
        pass  # stderr writes are forbidden: wpt.log is the only log path


class _ZipHTTPServer(ThreadingHTTPServer):
    """The shared server core: owns ONE ZipSource (auto-detected root)
    and closes it in ``server_close`` — the single lifecycle owner for
    both ``run_serve`` and the tests."""

    def __init__(self, zip_path: Path, port: int) -> None:
        # The source opens BEFORE the socket binds: a missing/corrupt
        # zip raises SourceError/OSError with nothing to clean up.
        self.zip_source = ZipSource(zip_path)
        self.zip_lock = threading.Lock()
        super().__init__((_BIND_HOST, port), _ZipHandler)

    def server_close(self) -> None:
        super().server_close()
        self.zip_source.close()

    def handle_error(self, request, client_address) -> None:
        """socketserver's default prints a traceback to stderr —
        forbidden: wpt.log is the only log path.  A disconnect
        mid-download is transport noise (``wpt verify`` streams and
        closes WITHOUT reading the body, on purpose), so it answers one
        debug line; anything else is a real server bug and is logged at
        error."""
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionError, TimeoutError)):
            log.debug("serve: client %s disconnected: %s",
                      client_address[0], exc)
            return
        log.error("serve: request from %s failed: %s",
                  client_address[0], exc, exc_info=True)


def build_server(zip_path: Path | str, port: int) -> ThreadingHTTPServer:
    """Build the rehearsal server — the ONE construction seam shared by
    ``run_serve`` and the tests.

    ``zip_path`` opens as a :class:`ZipSource` with root AUTO-DETECTED
    (the host-export twin nested under ``"<site>/"`` is stripped: URLs
    serve webroot-relative).  Binds ``127.0.0.1:port`` — ``port=0`` asks
    the kernel for an ephemeral port (``server.server_address[1]``
    carries the chosen one).  A missing zip raises
    :class:`~wpt.types.SourceError`, a taken port raises ``OSError`` —
    ``run_serve`` maps both to rc 1; the tests treat both as fixtures.
    """
    return _ZipHTTPServer(Path(zip_path), port)


def run_receipt(
    name: str, rows: Sequence[tuple[str, str]],
) -> tuple[str, str]:
    """``(markdown, json twin)`` for a command that produced no plan.

    THE one rendering for a planless run's ``--report`` — ``serve`` and
    ``proxy`` have nothing to plan, so what their report can honestly
    carry is WHAT RAN: the command, the URL/host/port it runs on, and
    nothing else.  A receipt is not a summary, so it must not grow into
    one: the caller passes its rows and this owns the shape — the
    ``command`` row (always, from ``name`` itself, so the twin's
    ``command`` key cannot disagree with the title), one
    ``- key: value`` line per row, then a blank line.

    The JSON twin is the same facts as an object, because ``--report``
    writes markdown AND its twin everywhere else (the audit, the actions
    registry, deploy, doctor, walk) and a command that wrote markdown
    alone would make that property false for itself.

    Never a credential: the rows are the caller's own public facts (a
    URL, a port, an archive NAME), and nothing here reads ``ctx``.
    """
    lines = [f"# wpt {name}", "", f"- command: {name}"]
    lines += [f"- {key}: {value}" for key, value in rows]
    lines.append("")
    markdown = "\n".join(lines)
    twin = json.dumps(
        {"command": name,
         **{key.replace(" ", "_").lower(): value for key, value in rows}},
        ensure_ascii=False, sort_keys=True, indent=2,
    ) + "\n"
    return markdown, twin


def run_serve(ctx: Ctx) -> int:
    """Run the ``wpt serve`` command body; 0 after a clean Ctrl-C stop,
    1 on refusal or operational failure — never raises, never a traceback.

    Local mode ONLY: against a live ftp source serving makes no sense —
    the live site already has URLs; what ``serve`` adds is an OFFLINE
    URL surface for the rehearsal zip.  The port comes from
    ``ctx.extra["port"]`` (the CLI's ``--port`` flag; the default 8080
    is chosen at the CLI).  The command BLOCKS in ``serve_forever``
    until Ctrl-C — no daemon, no background thread — and the server
    (and its ZipSource) is closed in the ``finally``.

    ``--report`` is honoured (:func:`run_receipt`, written through
    ``wpt.actions.registry.write_report`` — the one owner every
    ``--report`` surface shares): the receipt is written once the server
    is BOUND, so it names the real port and exists even though the run
    only ends at Ctrl-C.  A path that cannot be written fails the run
    (rc 1), like every other command.  Without a path the run prints
    only and this is a no-op.
    """
    if ctx.mode != "local":
        reason = ("serve requires local mode: the live site already has "
                  "URLs (serve the rehearsal zip offline instead)")
        return _write_failure(ctx, reason)
    try:
        raw_port = ctx.extra.get("port", _FALLBACK_PORT)
        port = coerce_port(raw_port, name="--port")
    except ValueError as exc:
        # One port owner: bool/non-finite/non-integral/out-of-range values
        # are refused here with one line, before socket.bind (R6-30/R6-44).
        return _write_failure(ctx, f"serve: {exc}")
    server: ThreadingHTTPServer | None = None
    try:
        if ctx.zip is None:  # cli validates; guarded so never-raises holds
            raise SourceError("local mode requires --zip")
        server = build_server(ctx.zip, port)
        bound = server.server_address[1]
        log.info("serving %s at http://127.0.0.1:%d/ — Ctrl-C to stop",
                 ctx.zip, bound)
        rc = _write_receipt(ctx, ctx.zip, bound)
        if rc:
            return rc
        server.serve_forever()  # blocks until Ctrl-C (the operator's stop)
    except KeyboardInterrupt:
        pass  # clean shutdown: rc 0, wherever the interrupt landed
    except RunControl as exc:
        return _write_failure(ctx, f"serve stopped: {exc}")
    except (WptError, OSError) as exc:
        return _write_failure(ctx, f"serve failed: {exc}")
    finally:
        if server is not None:
            # server_close ALSO closes the ZipSource; a teardown failure
            # must never replace the run's verdict/rc with a traceback
            # (the same best-effort rule proxy's stop follows).
            try:
                server.server_close()
            except (Exception, RunControl, KeyboardInterrupt) as exc:
                log.warning("serve: server close failed: %s",
                            redact_text(str(exc)))
    return 0


def _write_failure(ctx: Ctx, reason: str) -> int:
    """Log one listener-startup refusal AND write the shared failure pair.

    A listener that never bound is a run that did not complete: ``--report``
    must still explain why (the receipt exists only for a bound server).
    """
    log.error("%s", reason)
    from .actions.registry import write_failure_report

    try:
        write_failure_report(ctx, "serve", reason, title="wpt serve")
    except (Exception, RunControl) as exc:  # noqa: BLE001 — reporting must not mask rc 1
        log.warning("serve: could not write the failure report: %s",
                    redact_text(str(exc)))
    return 1


def _write_receipt(ctx: Ctx, zip_path: Path, port: int) -> int:
    """Write the serve run receipt to ``ctx.report_path``; 0 written, 1
    refused (no path is a no-op, never an error).

    The archive is named by its FILE NAME, never its full path: the
    receipt says what ran, and an operator's home directory is not part
    of that.  Everything else is what the command's own info line
    already states.
    """
    # The report writer is the action registry's (ONE owner for every
    # --report surface), imported here so a command with no plan cannot
    # grow a second one — the same reason deploy imports it.
    from .actions.registry import write_report

    markdown, twin = run_receipt("serve", (
        ("mode", "local — read-only static server; PHP is NOT executed "
                 "(a .php request answers its raw source as text/plain)"),
        ("archive", zip_path.name),
        ("url", f"http://127.0.0.1:{port}/"),
        ("bind", f"{_BIND_HOST}:{port} (localhost only by design)"),
        ("verify", "the walker reads RENDERED HTML, which this server cannot "
                   "produce (static PHP is not parsed), so `wpt verify` "
                   "against this origin finds no live references and reports "
                   "NOT a pass — an honest 'could not verify', never a green "
                   "run over nothing"),
        ("stop", "Ctrl-C; nothing is ever written to the archive"),
    ))
    return write_report(ctx, "serve", markdown, twin)
