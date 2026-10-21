r"""wpt proxy — the command body behind the local TLS proxy.

The engine is :mod:`wpt.dnsoverride` (``ProxyServer``: a threaded
TLS-terminating, URL-rewriting listener for ONE hostname/ip pair, so a
real browser can reach a pre-migration site by IP while it still
believes it is serving the hostname it presents).  This module is the
COMMAND BODY — the seam the CLI dispatches into, exactly as
:mod:`wpt.serve` is for ``wpt serve`` — and it owns two things the engine
has no business owning:

* the CLI's ``ImportError`` fallback moves here with the call, so the
  dispatcher stays a dispatcher;
* ``--report``, which the engine knows nothing about (it is a blocking
  listener, not a run with a plan).

``--report`` on this command is a RUN RECEIPT, not a summary: the proxy
plans nothing, so what it can honestly record is what ran — the site
hostname, the upstream it dials, and the loopback URL the browser talks
to (:func:`wpt.serve.run_receipt`, the one rendering shared with
``serve``; the writer is ``wpt.actions.registry.write_report``, the one
owner every ``--report`` surface shares).  The receipt is written AFTER
the listener is bound, so it names the real port and a run that is later
stopped with Ctrl-C still leaves the file behind; a path that cannot be
written fails the run (rc 1), like every other command.  Nothing in it
is credential-shaped: the hostname, the IP and the port are the three
things the operator typed, and no password, key or certificate path is
recorded.

Ordering: ``ProxyServer.start()`` binds and serves in a daemon thread,
so the receipt can be written before the blocking wait; ``serve()`` then
starts idempotently and blocks until SIGINT/SIGTERM, a
``KeyboardInterrupt`` or an external ``stop()``, always stopping the
listener in its ``finally``.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from .config import redact_text
from .dnsoverride import DEFAULT_CERT_DIR
from .log import get_logger
from .ports import DEFAULT_PROXY_PORT, coerce_port
from .serve import run_receipt
from .types import RunControl, WptError

if TYPE_CHECKING:
    # Annotation-only (same pattern as wpt/serve.py): the dispatcher
    # imports this module, so there is no import cycle at runtime.
    from .cli import Ctx

__all__ = ["protect_cert_inputs", "run_proxy"]

log = get_logger("proxy")


def protect_cert_inputs(ctx: Ctx, cert_dir: Path) -> None:
    """Resolve the proxy's certificate/key pair into ``ctx.extra``.

    ONE helper for BOTH Ctx builders (the full post-settings builder and the
    minimal pre-dispatch refusal builder): the pair is a local INPUT of every
    proxy run, so a ``--report`` naming either must be refused before any
    failure pair is written — including refusals that happen before the
    command body (a bad ``--deadline``/``--set``/SIGTERM).  ``run_proxy``
    consumes the stored paths; nothing else resolves them.

    A missing engine (the CLI's deferred-import fallback) leaves the extra
    unset: the command body answers rc 2 and has no TLS material to protect.
    """
    if getattr(ctx, "command", None) != "proxy":
        return
    try:
        from . import dnsoverride
    except ImportError:
        return
    cert_path, key_path = dnsoverride.cert_paths(Path(cert_dir))
    extra = getattr(ctx, "extra", None)
    if not isinstance(extra, dict):
        extra = {}
        try:
            ctx.extra = extra
        except (AttributeError, TypeError):
            return
    extra["cert_path"] = cert_path
    extra["key_path"] = key_path

#: The loopback the browser talks to, and the site's real HTTPS port.
#: Structural, not profile tunables: the proxy exists so a browser on
#: THIS machine can reach a site whose DNS points elsewhere, a rehearsal
#: twin must never be exposed, and the upstream presents the canonical
#: ``https://hostname`` origin (Host/SNI), which is port 443 by
#: definition.  The CLI exposes neither.
_BIND_HOST = "127.0.0.1"
_UPSTREAM_PORT = 443


def run_proxy(ctx: Ctx, *, hostname: str, ip: str,
              port: int = DEFAULT_PROXY_PORT,
              cert_dir: Path = DEFAULT_CERT_DIR,
              upstream_port: int = _UPSTREAM_PORT) -> int:
    """Run the ``wpt proxy`` command body; 0 after a clean Ctrl-C, 1 when a
    SIGTERM cooperative stop/any listener failure occurred or the report
    could not be written, 2 when the engine is not wired.

    SIGTERM is owned by the CLI's ``_install_sigterm_self_shutdown``: it
    raises StopRequested and the shared dispatch boundary answers rc 1 with
    a failure pair (Ctrl-C remains rc 0 through the engine's own handler).

    ``ctx`` carries ``report_path`` (and nothing else this command
    reads): the four arguments are the CLI's own flags, passed through
    untouched so the engine's signature — and every other caller of it —
    is unchanged.  A report that cannot be written is a FAILED run, never
    a silent success: the contract that makes ``--report`` worth passing
    is that the file is there afterwards.  Every failure the listener can
    raise (no openssl, a refused cert generation, a taken port) is logged
    at error and answered rc 1 — the same never-raises contract
    :mod:`wpt.serve` keeps, so a bad port is a message and not a
    traceback.
    """
    # Deferred, like every other command body's import of its engine: the
    # dispatcher imports this module eagerly, so a missing/incomplete
    # engine must surface as this command's refusal, not as an import
    # error anywhere up the stack.
    try:
        from . import dnsoverride
    except ImportError:
        log.error("wpt.dnsoverride not wired yet (W3 pending)")
        return 2
    # The certificate/key are local INPUTS of every proxy run: a --report
    # naming either would replace the TLS material the listener reads.  Add
    # their resolved paths to the ONE protected-set owner and refuse BEFORE
    # the port gate (an invalid port once overwrote the pair) and WITHOUT
    # writing a failure pair on that path, which would itself overwrite the
    # input.  The CLI builders already stored the same pair; consuming it
    # here keeps ONE resolution point for the real command and a fallback
    # for programmatic callers.
    extra = getattr(ctx, "extra", None)
    if not isinstance(extra, dict):
        extra = {}
        try:
            ctx.extra = extra
        except (AttributeError, TypeError):
            extra = None
    cert_path = extra.get("cert_path") if extra is not None else None
    key_path = extra.get("key_path") if extra is not None else None
    if cert_path is None or key_path is None:
        cert_path, key_path = dnsoverride.cert_paths(cert_dir)
        if extra is not None:
            extra["cert_path"] = cert_path
            extra["key_path"] = key_path
    report_path = getattr(ctx, "report_path", None)
    if report_path is not None:
        from .report import (report_input_collision,
                             report_protected_inputs,
                             report_protected_subtrees)

        collision = report_input_collision(
            report_path, report_protected_inputs(ctx),
            subtrees=report_protected_subtrees(ctx))
        if collision is not None:
            reason = (f"--report {report_path} resolves to this run's input "
                      f"{collision}; refusing to overwrite the certificate/"
                      "key it reads")
            log.error("%s", reason)
            from .report import write_stderr
            write_stderr(f"wpt: {reason}")
            return 1
    try:
        port = coerce_port(port, name="--port")
    except ValueError as exc:
        # A port outside the kernel's 0..65535 range reached socket.bind and
        # escaped as OverflowError (not an OSError) after the listener object
        # was built.  Refuse it at the flag boundary: one line, rc 1.  The
        # shared owner also refuses bool/non-integral values (R6-44).
        return _write_failure(ctx, f"proxy failed: {exc}")
    server = None
    serving = False
    # ONE lifetime: construction, start, receipt and serve all share the
    # finally, so every exit (including KeyboardInterrupt from
    # ``ensure_cert`` or a RunControl from the receipt) stops a listener
    # that may already be bound.  A start failure still fails BEFORE a
    # receipt exists.
    try:
        try:
            server = dnsoverride.ProxyServer(
                hostname, ip, port=port, upstream_port=upstream_port,
                cert_dir=cert_dir,
                timeout=ctx.settings.http.timeout_s,
                max_body_bytes=ctx.settings.walk.max_response_bytes,
                max_request_bytes=ctx.settings.proxy.max_request_bytes,
                cert_timeout_s=ctx.settings.proxy.cert_timeout_s,
                cert_validity_days=ctx.settings.proxy.cert_validity_days,
                cert_renew_before_s=ctx.settings.proxy.cert_renew_before_s)
            bound = server.start()
        except RunControl as exc:
            return _write_failure(ctx, f"proxy stopped: {exc}")
        except (WptError, OSError, UnicodeError, ValueError, OverflowError) as exc:
            return _write_failure(ctx, f"proxy failed: {exc}")
        rc = _write_receipt(ctx, hostname, ip, upstream_port, bound,
                              server.browser_url())
        if rc:
            return rc
        serving = True
        server.serve()   # blocks until Ctrl-C / SIGTERM, then stops it
        return 0
    except KeyboardInterrupt:
        if serving:
            return 0       # the engine's own serve() normally handles it
        return _write_failure(ctx, "proxy stopped: interrupted before serving")
    except RunControl as exc:
        return _write_failure(ctx, f"proxy stopped: {exc}")
    except (WptError, OSError) as exc:
        return _write_failure(ctx, f"proxy failed: {exc}")
    finally:
        # A teardown failure is ONE warning; it must never replace the
        # in-flight exception or turn a clean run into a traceback (R6-07).
        if server is not None:
            _stop_best_effort(server, "during shutdown")


def _write_failure(ctx: Ctx, reason: str) -> int:
    """Log one listener-startup refusal AND write the shared failure pair.

    A proxy that never bound is a run that did not complete: ``--report``
    must still explain why (the receipt exists only for a bound listener).
    """
    log.error("%s", reason)
    from .actions.registry import write_failure_report

    try:
        write_failure_report(ctx, "proxy", reason, title="wpt proxy")
    except (Exception, RunControl) as exc:  # noqa: BLE001 — reporting must not mask rc 1
        log.warning("proxy: could not write the failure report: %s",
                    redact_text(str(exc)))
    return 1


def _stop_best_effort(server, context: str) -> None:
    """Stop the listener without letting a teardown error escape.

    ``ProxyServer.stop`` performs shutdown/server_close/join and is not
    documented as infallible; ``run_proxy``'s contract is that every
    listener failure is logged and answered rc 1, never raised.  A stop
    that fails leaves the original error/rc intact and says so in one line.
    """
    try:
        server.stop()
    except (Exception, RunControl, KeyboardInterrupt) as exc:  # noqa: BLE001
        log.warning("proxy: listener stop failed %s: %s", context,
                    redact_text(str(exc)))


def _write_receipt(ctx: Ctx, hostname: str, ip: str, upstream_port: int,
                   port: int, browser_url: str) -> int:
    """Write the proxy run receipt to ``ctx.report_path``; 0 written, 1
    refused (no path is a no-op, never an error).

    The upstream port is the value handed to the engine, not a constant
    restated here, so the receipt can never claim an upstream the run is
    not dialling.  ``browser_url`` comes from the engine's ONE origin owner
    (``ProxyServer.browser_url``), so the advertised URL can never drift
    from the body/cookie rewrite target.
    """
    from .actions.registry import write_report

    markdown, twin = run_receipt("proxy", (
        ("site hostname", f"{hostname} (SNI and Host presented upstream)"),
        ("upstream", f"{ip}:{upstream_port}"),
        ("url", browser_url),
        ("bind", f"{_BIND_HOST}:{port} (localhost only by design)"),
        ("certificate", "self-signed, generated on first run; Chrome shows "
                        "the standard interstitial"),
        ("stop", "Ctrl-C (or SIGTERM); the listener is always stopped"),
    ))
    return write_report(ctx, "proxy", markdown, twin)
