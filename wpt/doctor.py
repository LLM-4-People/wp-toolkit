r"""wpt doctor — the preflight self-check behind ``wpt doctor``.

One command answering "can I actually work on this site right now?" —
the check an operator (human or AI) runs BEFORE a long session, in
seconds, instead of discovering a broken FTP login, a dead bridge or a
full disk an hour into a backup.

Panels (``run(ctx)`` branches on ``ctx.mode``, exactly like the audit
runner and ``wpt verify``):

* ftp — the FULL panel, eleven checks, each one table row, PLUS a
  conditional ``wpt residue`` row when a prior update left staging names:

  1. ``ftp + webroot`` — the remote stack builds through the ONE
     construction seam ``wpt.audit.remote_stack`` (FTP login, TLS, and
     the stale-bridge sweep the seam carries when present), then ONE
     ``list_dir("")`` of the webroot: PASS "N entries in webroot"; any
     exception => FAIL with the message.  The SAME root listing feeds
     the layout row (never a second listing) and the conditional
     ``wpt residue`` row (update-core staging/retired names).
  2. ``wordpress layout`` — the exact webroot markers
     ``wp-config.php`` (file), ``wp-content`` and ``wp-includes``
     (directories) from that root listing: PASS names them; FAIL
     "not a WordPress webroot — missing ..." and the bridge/write-gated
     rows stand down, but the generic PHP probe still measures.  When
     the root listing failed the row answers "not checked".
  3. ``write access`` — ONE unique per-run ``.wpt-write-probe-<16hex>``
     at the webroot root (write, verify ``exists``, delete in ``finally``):
     PASS "webroot is writable (probe written and removed)"; a failed
     write names the FTP reason and the operator's fix; a write that
     reported success but left no probe, or a probe that could not be
     removed, is a FAIL.
  4. ``php runtime`` — the standalone no-WordPress probe
     (:class:`wpt.php_probe.PhpProbe`): sweep stale probe files first,
     deploy once, call once, destroy in ``finally`` (even when the call
     failed).  The detail carries PHP/SAPI, the MySQL extension(s) and
     the session-cookie flags; no MySQL extension, lax session flags or
     ``display_errors=1`` => WARN.  It runs even on a non-WordPress or
     DB-broken root — the one diagnostic that must.
  5. ``bridge round-trip`` — runs only on a WordPress layout with a
     writable webroot: ``bridge.call("info")``; an ok payload carrying
     ``wp_version`` => PASS; ok without it => WARN; any bridge failure
     => FAIL.  The bridge lazy-deploys on this call and
     ``bridge.destroy()`` runs EXACTLY once, in the panel's ``finally``.
  6. ``site reachability`` — ONE streamed GET of ``{wp_url}/`` through
     the SAME session the stack built (DNS-override aware): 2xx/3xx =>
     PASS; 4xx => WARN (an odd homepage); 5xx => FAIL (a server error
     is not a healthy site); transport error => FAIL.
  7. ``tls certificate`` — a verified TLS handshake against
     ``ctx.wp_url``'s host (or the ``--override-ip`` dial target): a
     verified certificate beyond ``tls.warn_days`` => PASS, inside the
     renewal window => WARN, expired or not verifying => FAIL (the
     failing certificate is retried once unverified, only to read its
     facts).  A transport failure => WARN "TLS unreachable".
  8. ``https policy`` — HTTP and HTTPS GETs of the site root through
     the same session: PASS only when HTTP redirects to HTTPS AND the
     HTTPS answer carries ``Strict-Transport-Security``; every other
     shape (HTTP serves content, HSTS absent, HTTPS unreachable) =>
     WARN.  The certificate verdict belongs to row 7.
  9. ``host error log`` — one :func:`wpt.logs.collect` pass (it owns and
     closes its account-root source; the webroot source is passed in):
     no files => WARN, no matches => PASS, matches => WARN with the
     total and the latest line, unreadable => WARN.  It never fails the
     panel solely because logs are unreadable; a dead stack is FAIL
     "not checked".
  10. ``wp.org API`` — through the SAME transport the session's
      updates/integrity checks ride (:class:`WpOrgApi` from
      wpt.audit.updates: its identifying ``wpt/<version>`` User-Agent,
      its ``settings.http.timeout_s`` bound, its 1h ``.wpt-cache/``):
      ``latest_core_version()`` answers a core offer => PASS; no answer
      (unreachable, non-200, unusable payload) => WARN — updates and
      integrity checks degrade without wp.org but never crash.  When
      the stack failed, this row still measures through a plain
      session — api.wordpress.org is public and the DNS override is
      host-gated to the site.
  11. ``disk`` — ``shutil.disk_usage`` of the NEAREST EXISTING ancestor of
      ``ctx.backup_dir`` (the doctor runs BEFORE the session, so the backup
      dir — and a nested path's immediate parent — usually does not exist
      yet; walking ancestors keeps a not-yet-created nested target from
      becoming a false FAIL): PASS above ``backup.free_pass_bytes``, WARN
      above ``backup.free_warn_bytes``, FAIL at or below the warn floor
      ("snapshots cannot land").  Space that cannot be measured
      at all (no existing ancestor, or a failed ``disk_usage``) is the
      documented free-space-unavailable state: WARN, never a false FAIL.
      The thresholds are profile policy (``backup.free_pass_bytes`` /
      ``backup.free_warn_bytes``), so a small host can tune them.

* local — the REDUCED panel (``disk`` then ``wp.org API``): offline mode
  has no site, no FTP, no bridge — the zip+sql inputs are validated by the
  audit itself.  ftp mode runs the full panel above.  With ``--db-uri`` the
  local panel gains ONE extra row, ``database``: the direct-database source
  ``clean-db --apply`` would use is reachable (a connection plus its table
  count), so a run that would otherwise fail minutes in at the first DELETE
  is caught here in seconds.  It is a diagnostic row like every other one:
  a driver that is not installed, a refused login or an unreachable host
  all answer as a FAIL row, never a traceback.

Per-check contract (binding): every check runs inside its own
``except Exception`` and any exception becomes a FAIL row carrying
``str(exc)`` — a diagnostic command answers with facts, never a
traceback.  Timeout bounds are the settings' own transports': the site,
HTTPS-policy and TLS checks carry ``settings.http.timeout_s``, the
bridge call the bridge settings' timeout, the PHP probe the probe
settings' timeout, and the FTP source the ftp settings' — no check can
hang past its transport's bound.

Output: a small markdown table (``| check | result | detail |``) that
is ALWAYS written to stdout through the shared report sink, exactly like
``wpt verify`` — the table IS the command's stdout surface; with
``ctx.report_path`` set the markdown is ALSO written
there and the machine-readable JSON twin — exactly
``{"checks": [{"name", "result", "detail"}]}``, nothing else — to
``report_path.with_suffix(".json")``.  One info summary
("doctor: N pass, M warn, K fail") is always logged.

rc: 0 when zero rows are FAIL; 1 when any row is (WARNs never fail —
an odd homepage, a cold wp.org or an expiring certificate must not
block a session; an HTTP 5xx homepage does).

Error contract (like verify): every :class:`~wpt.types.WptError` /
``OSError`` escaping the per-check containment is logged at error and
answered with rc 1 — ``run`` never raises.  The per-check catches
already contain the stack seams; the run-level clause is the backstop
for operational failures around the report write itself.

Logging: everything through ``get_logger("doctor")`` — the one info
summary plus at most one warning per lifecycle hiccup (bridge/probe
destroy, stale-probe sweep); rows carry counts, versions and exception
messages only.  The FTP password never flows near this module
(remote_stack owns credentials).
"""

from __future__ import annotations

import json
import os
import re
import secrets
import select
import shutil
import socket
import ssl
import tempfile
import time
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import requests

# The ONE stack construction seam, imported into THIS namespace so
# tests can monkeypatch wpt.doctor.remote_stack (verify's contract).
from .audit import remote_stack
from .audit.updates import WpOrgApi
from .config import redact_text
from .deadline import Deadline, transport_kwargs
# Imported into THIS namespace: tests monkeypatch wpt.doctor.collect_logs.
from .logs import collect as collect_logs
from .localmode.dbconn import connect, parse_db_uri, schema_tables
from .log import get_logger
# Imported into THIS namespace: tests monkeypatch wpt.doctor.PhpProbe.
from .php_probe import (PhpProbe, _resolve_host_bounded, get_bounded,
                        sweep_stale_probes)
from .report import human_bytes, md_escape
from .report import write_stdout
from .teardown import source_cleanup_budget
from .types import (DeadlineExceeded, RunControl, StopRequested, WptError,
                    update_core_residue)

if TYPE_CHECKING:
    # Ctx is annotation-only (same pattern as wpt/audit/__init__.py and
    # wpt/verify.py): cli lazy-calls this module, so there is no import
    # cycle at runtime.
    from .cli import Ctx

__all__ = ["run"]

log = get_logger("doctor")

#: The panel's result vocabulary — the table and JSON twin carry these.
PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"

#: Free-space policy lives in ``backup.free_pass_bytes`` /
#: ``backup.free_warn_bytes``; the doctor reads the loaded profile.

#: The webroot-root write probe (row 3).  The name is UNIQUE per run, as
#: the PHP probe's is: a fixed name overwrote and then deleted a site file
#: that happened to carry it, and two concurrent doctors deleted each
#: other's probe (R6-05).  ``_WRITE_PROBE_RE`` is the exact owned shape the
#: stale sweep may consider, and it matches the name ``_write_check``
#: actually generates (``secrets.token_hex(8)`` = 16 hex; an 8-hex pattern
#: could never sweep a real leftover — R6-41).  A bare/legacy
#: ``.wpt-write-probe`` is never ours to delete.
_WRITE_PROBE_PREFIX = ".wpt-write-probe-"
_WRITE_PROBE_RE = re.compile(r"^\.wpt-write-probe-[0-9a-f]{16}$")

#: The host-log row's own excerpt bound (the log report's line ceiling is
#: the report's; the table cell is smaller).
_LOG_EXCERPT = 160

#: Detail for stack-dependent rows when the stack never built — the
#: root cause lives in the ftp + webroot row.
_STACK_DOWN = ("not checked — the remote stack failed "
               "(see the ftp + webroot row)")


def run(ctx: Ctx) -> int:
    """Run the doctor panel for ``ctx``'s mode; 0 when no row is FAIL.

    Builds the panel (full in ftp mode, reduced in local mode), prints
    the markdown table to stdout ALWAYS, writes the markdown + JSON
    twin to ``ctx.report_path`` when set, logs the one info summary and
    answers 1 when any row is FAIL.  Never raises.
    """
    try:
        deadline = Deadline.from_ctx(ctx)
        if ctx.mode == "local":
            checks = _local_panel(ctx, deadline)
            note = ("Local mode — reduced panel "
                    "(ftp mode runs the full 11-check panel).")
        else:
            checks = _ftp_panel(ctx, deadline)
            note = ""
        # A check can overrun its budget INSIDE the final row (the wp.org
        # roundtrip); the pre-check in _guarded/the panels cannot see that.
        # Never render a PASS table after the run budget expired.
        _check(deadline, "doctor panel")
        markdown = _render(_site_label(ctx), checks, note)
        # ALWAYS printed first — the table is the command's stdout
        # surface; --report adds the files, never replaces stdout.
        write_stdout(markdown)
        if ctx.report_path is not None:
            from .actions.registry import write_report

            if write_report(ctx, "doctor", markdown, _render_json(checks)):
                return 1
        passes = sum(1 for c in checks if c["result"] == PASS)
        warns = sum(1 for c in checks if c["result"] == WARN)
        fails = sum(1 for c in checks if c["result"] == FAIL)
        log.info("doctor: %d pass, %d warn, %d fail", passes, warns, fails)
        return 1 if fails else 0
    except RunControl as exc:
        # A run-level stop/deadline is still a run that did not complete:
        # --report promised an artifact, and "no file" was indistinguishable
        # from "no findings" (DOC2).  Same shared contract as logs/discover.
        log.error("doctor stopped: %s", redact_text(str(exc)))
        _write_failure(ctx, exc)
        return 1
    except (WptError, OSError) as exc:
        log.error("doctor failed: %s", exc)
        # A run-level stop/deadline is still a run that did not complete:
        # --report promised an artifact, and "no file" was indistinguishable
        # from "no findings" (DOC2).  Same shared contract as logs/discover.
        _write_failure(ctx, exc)
        return 1


def _write_failure(ctx: Ctx, exc: BaseException) -> None:
    """Write doctor's ``not_complete`` markdown + JSON twin when asked."""
    if getattr(ctx, "report_path", None) is None:
        return
    from .actions.registry import not_complete, write_report

    block, run_payload = not_complete(str(exc), status="failed")
    markdown = f"# wpt doctor — {_site_label(ctx)}\n" + block
    json_text = json.dumps(
        {"checks": [], "run": run_payload},
        ensure_ascii=False, sort_keys=True, indent=2,
    ) + "\n"
    try:
        write_report(ctx, "doctor", markdown, json_text)
    except (Exception, RunControl) as report_exc:  # noqa: BLE001
        # A second stop during the failure write must not escape and mask
        # the primary reason (the same contract every other writer keeps).
        log.warning("doctor: could not write the failure report: %s",
                    redact_text(str(report_exc)))


# --------------------------------------------------------------- the panels


def _close_session_best_effort(session, label: str) -> BaseException | None:
    """Close one HTTP session; return a cooperative stop, warn other errors.

    ONE helper for doctor's independently-owned sessions: a session that
    cannot close is a warning, never a traceback, but SIGTERM/deadline is
    returned to the caller so the run still ends through the stop contract.
    """
    close = getattr(session, "close", None)
    if not callable(close):
        return None
    try:
        close()
    except (StopRequested, DeadlineExceeded) as exc:
        return exc
    except Exception as exc:  # noqa: BLE001 — close is best-effort
        log.warning("doctor: %s session close failed: %s", label,
                    redact_text(str(exc)))
    return None


def _ftp_panel(ctx: Ctx,
               deadline: Deadline | None = None) -> list[dict[str, str]]:
    """The full 11-check panel (see module docstring for row semantics)."""
    checks: list[dict[str, str]] = []
    session = None
    bridge = None
    source = None
    root_entries = None
    layout_ok = False
    write_ok = False
    primary: BaseException | None = None
    try:
        _check(deadline, "doctor ftp")
        # 1. ftp + webroot — stack construction, then ONE root listing.
        try:
            source, session, bridge = remote_stack(ctx)
        except Exception as exc:
            _raise_stop(exc)
            checks.append(
                _row("ftp + webroot", FAIL, f"remote stack failed: {exc}"))
        else:
            try:
                _check(deadline, "doctor webroot listing")
                root_entries = source.list_dir("")
            except Exception as exc:
                _raise_stop(exc)
                checks.append(
                    _row("ftp + webroot", FAIL,
                         f"webroot listing failed: {exc}"))
            else:
                checks.append(_row(
                    "ftp + webroot", PASS,
                    f"{len(root_entries)} entries in webroot"))
                # A killed/failed update-core leaves staging names the
                # operator must know about before the next run [L69].  This
                # row is CONDITIONAL (only when residue exists); the rest of
                # the panel's order is stable.
                residue = [
                    (entry.path,
                     "retired core" if entry.path.endswith(".wpt-old")
                     else "staged")
                    for entry in root_entries
                    if update_core_residue(entry.path)
                ]
                try:
                    _check(deadline, "doctor residue")
                    # WordPress's updater leaves a DIRECTORY named
                    # wp-content/upgrade; a regular file with that name is
                    # ordinary site content and must not be labelled core
                    # staging (DOC3).
                    if any(entry.path.rstrip("/") == "wp-content/upgrade"
                           and entry.is_dir
                           for entry in source.list_dir("wp-content")):
                        residue.append(
                            ("wp-content/upgrade/",
                             "WordPress's own updater staging"))
                except Exception as exc:
                    _raise_stop(exc)
                if residue:
                    checks.append(_row(
                        "wpt residue", WARN,
                        "; ".join(
                            f"{path} ({label})"
                            for path, label in sorted(residue)[:5])
                        + " — a failed or killed run left staging files; "
                          "wpt update-core sweeps them and `restore "
                          "--undo-last` brings a retired core back"))

        # 2. wordpress layout — from the SAME root listing (never re-list).
        layout = _guarded("wordpress layout", _layout_check, root_entries,
                          deadline=deadline)
        checks.append(layout)
        layout_ok = layout["result"] == PASS

        # 3. write access — unique per-run root probe, removed in finally.
        write = _guarded("write access", _write_check, source,
                         ctx.settings.probe.ttl_minutes, deadline,
                         deadline=deadline)
        checks.append(write)
        write_ok = write["result"] == PASS

        # 4. php runtime — generic: runs even when layout is not WordPress.
        checks.append(_guarded(
            "php runtime", _php_runtime_check, ctx, source, session, write_ok,
            deadline, deadline=deadline))

        # 5. bridge round-trip — deploys on the call; destroy in finally.
        checks.append(_guarded(
            "bridge round-trip", _bridge_row,
            source, bridge, layout_ok, write_ok, deadline, deadline=deadline))

        # 6. site reachability — the stack session (DNS-override aware).
        if session is None:
            checks.append(_row("site reachability", FAIL, _STACK_DOWN))
        else:
            checks.append(_guarded(
                "site reachability", _site_check, session, ctx,
                deadline, deadline=deadline))

        # 7. tls certificate — independent of the remote stack.
        checks.append(_guarded("tls certificate", _tls_check, ctx, deadline,
                               deadline=deadline))

        # 8. https policy — same stack session (no session => not checked).
        if session is None:
            checks.append(_row("https policy", FAIL, _STACK_DOWN))
        else:
            checks.append(_guarded(
                "https policy", _https_policy_check, session, ctx,
                deadline, deadline=deadline))

        # 9. host error log — the webroot source is passed in; collect()
        #    creates and closes its own account-root source, and receives
        #    THIS panel's deadline so the row cannot restart the budget.
        checks.append(_guarded(
            "host error log", _host_log_check, ctx, source, deadline,
            deadline=deadline))

        # 10. wp.org API — the stack session when one exists (the
        # transport the session's own checks ride); a plain session
        # otherwise: the row is independent of the site's FTP.
        fallback = None
        if session is None:
            fallback = requests.Session()
        try:
            checks.append(_guarded(
                "wp.org API", partial(
                    _wporg_check, config=ctx.settings.wp_org),
                session if session is not None else fallback,
                ctx.settings.http.timeout_s, deadline,
                deadline=deadline))
        except BaseException:
            stop = _close_session_best_effort(fallback, "fallback")
            if stop is not None:
                log.error("doctor: fallback session close stopped: %s; the "
                          "primary failure above stays the run's reason", stop)
            raise
        else:
            stop = _close_session_best_effort(fallback, "fallback")
            if stop is not None:
                raise stop

        # 11. disk — local fact, never needs the remote side.
        checks.append(_guarded("disk", _disk_check, ctx, deadline=deadline))
    except BaseException as exc:
        primary = exc
        raise
    finally:
        # Cleanup is ALL-OR-NOTHING in coverage, not in failure: a stop
        # raised by one step must not skip the rest (DOC5).  Remember the
        # FIRST stop, run every source/session/bridge cleanup, then re-raise
        # it so the run still ends through the cooperative-stop contract.
        first_stop: BaseException | None = None

        def _remember_stop(exc: BaseException) -> None:
            nonlocal first_stop
            if first_stop is None and _is_stop(exc):
                first_stop = exc

        if bridge is not None:
            try:
                bridge.destroy()
            except (Exception, RunControl) as exc:
                _remember_stop(exc)
                log.warning(
                    "doctor: bridge destroy failed (the token TTL gate "
                    "backstops a leftover file): %s", exc)
        # The panel OWNS the stack it built: the bridge is gone, then the
        # FTP control session and the HTTP pool are closed.  A source that
        # cannot close is one warning, never a masking failure.
        if source is not None:
            try:
                source.close()
            except (Exception, RunControl) as exc:  # noqa: BLE001
                _remember_stop(exc)
                log.warning("doctor: source close failed: %s",
                            redact_text(str(exc)))
        if session is not None:
            _remember_stop(_close_session_best_effort(session, "doctor"))
        if first_stop is not None:
            if primary is None:
                raise first_stop
            # A teardown stop must never REPLACE the panel's primary failure
            # (a deadline/stop already propagating): log it beside the
            # reason the run actually ended for.
            log.error("doctor: teardown stopped: %s; the primary failure "
                      "above stays the run's reason", first_stop)
    return checks


def _local_panel(ctx: Ctx,
                 deadline: Deadline | None = None) -> list[dict[str, str]]:
    """The reduced offline panel: disk, then wp.org (module docstring)."""
    checks = [_guarded("disk", _disk_check, ctx, deadline=deadline)]
    if ctx.db_uri:
        # The extra --db-uri row goes FIRST: a database that cannot be
        # reached is the finding that matters, and the operator reading the
        # table top-down should not have to wait for the wp.org roundtrip.
        checks.append(_guarded(
            "database (--db-uri)", _database_check, ctx, deadline,
            deadline=deadline))
    session = requests.Session()
    primary: BaseException | None = None
    try:
        checks.append(_guarded(
            "wp.org API", partial(
                _wporg_check, config=ctx.settings.wp_org), session,
            ctx.settings.http.timeout_s, deadline, deadline=deadline))
    except BaseException as exc:
        primary = exc
        raise
    finally:
        # The getattr guard keeps simpler test doubles usable (verify's);
        # generic close errors warn, a cooperative stop propagates — unless
        # a primary failure is already in flight, which keeps its reason.
        stop = _close_session_best_effort(session, "local")
        if stop is not None:
            if primary is None:
                raise stop
            log.error("doctor: local session close stopped: %s; the primary "
                      "failure above stays the run's reason", stop)
    return checks


def _check(deadline: Deadline | None, context: str) -> None:
    if deadline is not None:
        deadline.check(context)


def _http_deadline(deadline: Deadline | None, timeout_s: float) -> float:
    """The absolute instant one HTTP GET may run until.

    ``min(run budget, now + per-request timeout)``: a request never outlives
    the run, and never gets a longer bound than the profile allows.
    """
    per_request = time.monotonic() + timeout_s
    if deadline is None:
        return per_request
    return min(deadline.at, per_request)


def _raise_stop(exc: BaseException) -> None:
    """Re-raise a cooperative stop/deadline before any per-row containment."""
    if _is_stop(exc):
        raise exc


def _is_stop(exc: BaseException) -> bool:
    """True for the run-level stop/deadline signal (not a diagnosis row)."""
    return isinstance(exc, (StopRequested, DeadlineExceeded))


# ------------------------------------------------------------ single checks


def _guarded(name: str, check, *args,
             deadline: Deadline | None = None) -> dict[str, str]:
    """Run one check; any unexpected exception becomes its FAIL row.

    The check functions catch their own expected failures and answer with
    the specific wording; this is the per-row backstop that keeps a
    diagnostic command from ever answering with a traceback.  A cooperative
    stop (SIGTERM) or the run deadline is re-raised BEFORE the catch-all:
    those end the whole run, they are not a diagnosis row.
    """
    _check(deadline, name)
    try:
        result = check(*args)
    except Exception as exc:  # noqa: BLE001 — the panel's binding contract
        _raise_stop(exc)
        return _row(name, FAIL, str(exc))
    # The check itself may have consumed the remaining budget; a row that
    # answers after expiry must end the run, not become a PASS.
    _check(deadline, name)
    return result


def _layout_check(entries) -> dict[str, str]:
    """WordPress's three exact webroot markers, from the root listing."""
    if entries is None:
        return _row("wordpress layout", FAIL,
                    "not checked — webroot listing failed")
    files = {entry.path.rstrip("/") for entry in entries
             if not entry.is_dir or entry.is_link}
    dirs = {entry.path.rstrip("/") for entry in entries if entry.is_dir}
    markers = (
        ("wp-config.php", False),
        ("wp-content", True),
        ("wp-includes", True),
    )
    missing = [name for name, is_dir in markers
               if not (name in dirs if is_dir else name in files)]
    if missing:
        return _row("wordpress layout", FAIL,
                    "not a WordPress webroot — missing " + ", ".join(missing))
    return _row("wordpress layout", PASS,
                "wp-config.php, wp-content, wp-includes")


def _sweep_write_probes(source, ttl_minutes: int,
                        deadline: Deadline | None = None) -> None:
    """Best-effort removal of an EARLIER run's owned write-probe leftovers.

    Only the exact ``.wpt-write-probe-<16hex>`` shape is considered, and only
    when its listing carries a KNOWN mtime older than the probe TTL: an
    unknown mtime or a young file may belong to a concurrent doctor and is
    never touched.  A listing/delete failure is one warning, never a row
    failure — the sweep is hygiene, not the write check.
    """
    try:
        entries = source.list_dir("")
    except Exception as exc:  # noqa: BLE001 — hygiene only
        _raise_stop(exc)
        log.warning("doctor: write-probe sweep listing failed: %s",
                    redact_text(str(exc)))
        return
    cutoff = time.time() - ttl_minutes * 60
    for entry in entries:
        _check(deadline, "doctor write probe sweep")
        if entry.is_dir or entry.is_link:
            continue
        name = entry.path.rsplit("/", 1)[-1]
        if entry.path != name or _WRITE_PROBE_RE.match(name) is None:
            continue
        if entry.mtime is None or entry.mtime > cutoff:
            continue
        try:
            source.delete(name)
        except (StopRequested, DeadlineExceeded):
            raise
        except Exception as exc:  # noqa: BLE001 — hygiene only
            log.warning("doctor: stale write-probe delete failed for %s: %s",
                        name, redact_text(str(exc)))
        else:
            log.debug("doctor: swept stale write probe %s", name)


def _write_check(source, ttl_minutes: int | None = None,
                 deadline: Deadline | None = None) -> dict[str, str]:
    """Write, verify and remove ONE unique probe at the root.

    The path is generated per invocation and only that path is ever
    deleted: a pre-existing file (even one carrying the old fixed name) is
    never overwritten or removed.  With ``ttl_minutes``, leftovers from an
    EARLIER killed run are swept first — only names matching the exact
    owned shape AND carrying a known mtime older than the probe TTL; a
    concurrent doctor's live probe is younger, and an unknown mtime is
    left alone (R6-05).
    """
    if source is None:
        return _row("write access", FAIL, _STACK_DOWN)
    _check(deadline, "doctor write probe")
    name = f"{_WRITE_PROBE_PREFIX}{secrets.token_hex(8)}"
    if ttl_minutes is not None:
        _sweep_write_probes(source, ttl_minutes, deadline)
    _check(deadline, "doctor write probe")
    try:
        source.write_bytes(name, b"wpt write probe\n")
    except (Exception, RunControl) as exc:
        # A protocol can fail after creating a partial file (a dropped STOR).
        # Only THIS run's unique name is removed before answering; the
        # delete is attempted UNCONDITIONALLY —
        # an exists() probe that itself failed must not suppress the cleanup,
        # and a cooperative stop must not skip it either (DOC4).  A cleanup
        # refusal is logged, never allowed to mask the write failure.
        try:
            with source_cleanup_budget(source):
                source.delete(name)
        except (Exception, RunControl) as cleanup_exc:
            _raise_stop(cleanup_exc)
            log.warning("doctor: write-probe cleanup failed: %s",
                        redact_text(str(cleanup_exc)))
        _raise_stop(exc)
        return _row(
            "write access", FAIL,
            "webroot is not writable over FTP: "
            f"{redact_text(str(exc))}; use the host file manager or fix "
            "ownership")
    present = False
    verify_error = None
    delete_error = None
    try:
        try:
            present = source.exists(name)
        except (Exception, RunControl) as exc:  # verification failure still
            _raise_stop(exc)                    # cleans up
            verify_error = exc
    finally:
        try:
            with source_cleanup_budget(source):
                source.delete(name)
        except (Exception, RunControl) as exc:
            _raise_stop(exc)
            delete_error = exc
    if delete_error is not None:
        return _row(
            "write access", FAIL,
            "write succeeded but the probe could not be removed: "
            f"{name}: {redact_text(str(delete_error))}")
    if verify_error is not None:
        return _row(
            "write access", FAIL,
            "write reported success but the probe could not be verified: "
            f"{redact_text(str(verify_error))}")
    if not present:
        return _row("write access", FAIL,
                    "write reported success but the probe is absent")
    return _row("write access", PASS,
                "webroot is writable (probe written and removed)")


def _php_runtime_check(ctx: Ctx, source, session, write_ok: bool,
                       deadline: Deadline | None = None) -> dict[str, str]:
    """The standalone no-WordPress PHP runtime diagnostic.

    ``deadline`` is the run's absolute budget: the probe GET may never
    outlive it with a fresh ``probe.timeout_s``.
    """
    if source is None or session is None:
        return _row("php runtime", FAIL, _STACK_DOWN)
    if not write_ok:
        return _row("php runtime", FAIL, "not checked — write access failed")
    try:
        sweep_stale_probes(source, ctx.settings.probe)
    except Exception as exc:  # sweep alone never fails the row
        _raise_stop(exc)
        log.warning("doctor: stale probe sweep failed: %s",
                    redact_text(str(exc)))
    probe = PhpProbe(source, session, ctx.settings.probe, ctx.wp_url or "")
    payload = None
    call_error = None
    try:
        payload = probe.call(deadline=deadline.at if deadline is not None
                             else None)
    except Exception as exc:
        _raise_stop(exc)
        call_error = exc
    finally:
        try:
            probe.destroy()
        except Exception as exc:  # never masks the call result
            _raise_stop(exc)
            log.warning("doctor: PHP probe destroy failed: %s",
                        redact_text(str(exc)))
    if call_error is not None:
        return _row("php runtime", FAIL,
                    f"PHP runtime probe failed: "
                    f"{redact_text(str(call_error))}")
    if not isinstance(payload, dict) or not payload.get("php_version"):
        return _row("php runtime", WARN,
                    "probe answered ok but carried no php_version")
    session_facts = payload.get("session")
    if not isinstance(session_facts, dict):
        session_facts = {}
    ini = payload.get("ini")
    if not isinstance(ini, dict):
        ini = {}
    pdo_mysql = payload.get("pdo_mysql") is True
    mysqli = payload.get("mysqli") is True
    mysql = ",".join(
        name for name, loaded in (("pdo_mysql", pdo_mysql),
                                  ("mysqli", mysqli)) if loaded) or "none"
    strict = _ini_flag(session_facts.get("use_strict_mode"))
    httponly = _ini_flag(session_facts.get("cookie_httponly"))
    samesite_value = session_facts.get("cookie_samesite")
    samesite = ("unset" if samesite_value in (None, "", False)
                else str(samesite_value))
    # The probe reports these two doubles deliberately: ``use_only_cookies``
    # 0 accepts a session id from GET/POST, and ``use_trans_sid`` 1 emits it
    # in URLs.  A present value is measured; an absent one (an older runtime
    # answers false) stays not-measured instead of fabricating "0" (R6-10).
    only_cookies = _measured_ini_flag(session_facts.get("use_only_cookies"))
    trans_sid = _measured_ini_flag(session_facts.get("use_trans_sid"))
    sapi = payload.get("php_sapi") or "unknown"
    detail = (f"PHP {payload['php_version']} ({sapi}); mysql {mysql}; "
              f"session strict={strict} httponly={httponly} "
              f"samesite={samesite}")
    if only_cookies is not None:
        detail += f" only_cookies={only_cookies}"
    if trans_sid is not None:
        detail += f" trans_sid={trans_sid}"
    insecure = (
        not (pdo_mysql or mysqli)
        or strict != "1"
        or httponly != "1"
        or samesite == "unset"
        or only_cookies == "0"
        or trans_sid == "1"
        or ini.get("display_errors") == "1"
    )
    return _row("php runtime", WARN if insecure else PASS, detail)


def _bridge_row(source, bridge, layout_ok: bool,
                write_ok: bool, deadline: Deadline | None = None
                ) -> dict[str, str]:
    """The bridge gate: layout + write access decide whether it runs."""
    if source is None:
        return _row("bridge round-trip", FAIL, _STACK_DOWN)
    if not layout_ok:
        return _row("bridge round-trip", FAIL,
                    "not checked — not a WordPress webroot")
    if not write_ok:
        return _row("bridge round-trip", FAIL,
                    "not checked — write access failed")
    if bridge is None:
        return _row("bridge round-trip", FAIL, _STACK_DOWN)
    return _bridge_check(bridge, deadline)


def _bridge_check(bridge, deadline: Deadline | None = None) -> dict[str, str]:
    """One bridge ``info`` round-trip: the WP/PHP facts a session needs."""
    try:
        payload = bridge.call("info", **transport_kwargs(deadline))
    except Exception as exc:
        _raise_stop(exc)
        return _row("bridge round-trip", FAIL, str(exc))
    if not isinstance(payload, dict):
        payload = {}
    version = payload.get("wp_version")
    if not (isinstance(version, str) and version):
        return _row("bridge round-trip", WARN,
                    "bridge answered ok but carried no wp_version")
    detail = f"WP {version}"
    php = payload.get("php_version")
    if isinstance(php, str) and php:
        detail += f", PHP {php}"
    return _row("bridge round-trip", PASS, detail)


def _site_check(session, ctx: Ctx,
                deadline: Deadline | None = None) -> dict[str, str]:
    """One streamed GET of ``{wp_url}/``: up / odd / broken.

    The GET rides the ONE absolute-deadline transport (php_probe's bounded
    reader): requests' per-read ``timeout`` let a header drip keep this row
    alive for seconds past the run budget.
    """
    base = (ctx.wp_url or "").strip()
    if not base:
        return _row("site reachability", FAIL, "no --wp-url to check")
    url = base.rstrip("/") + "/"
    try:
        response = get_bounded(
            session, url, timeout_s=ctx.settings.http.timeout_s,
            deadline=_http_deadline(deadline, ctx.settings.http.timeout_s),
            allow_redirects=True)
        status = response.status_code
        close = getattr(response, "close", None)
        if callable(close):
            close()
    except Exception as exc:
        _raise_stop(exc)
        return _row("site reachability", FAIL, str(exc))
    if 200 <= status < 400:
        return _row("site reachability", PASS, f"HTTP {status} at {url}")
    if 400 <= status < 500:
        return _row("site reachability", WARN, f"HTTP {status} at {url}")
    if 500 <= status < 600:
        return _row("site reachability", FAIL, f"HTTP {status} at {url}")
    return _row("site reachability", WARN, f"HTTP {status} at {url}")


# ------------------------------------------------------------------- tls


def _wp_target(wp_url: str | None) -> tuple[str, int | None] | None:
    """``(host, explicit port or None)`` for ``--wp-url``, or None.

    A URL typed without a scheme is still read as a host (the logs
    module's rule); the port is only the one the operator typed, so the
    caller can apply its own default.
    """
    value = (wp_url or "").strip()
    if not value:
        return None
    try:
        parsed = urlparse(value if "://" in value else f"//{value}")
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if not host:
        return None
    return host, port


def _authority(host: str, port: int, default_port: int) -> str:
    """``host[:port]`` for a URL, omitting the default port."""
    name = f"[{host}]" if ":" in host else host
    return name if port == default_port else f"{name}:{port}"


def _tls_check(ctx: Ctx,
               deadline: Deadline | None = None) -> dict[str, str]:
    """Dial the site host, verify its certificate and answer the row.

    ``deadline`` is the run budget.  DNS resolution and the dial/handshake
    ride it through the SAME bounded resolver the PHP probe uses: libc
    ``getaddrinfo`` ignores socket timeouts, so a stalled resolver used to
    keep this row alive for as long as the OS took, past ``--deadline``.
    """
    target = _wp_target(ctx.wp_url)
    if target is None:
        return _row("tls certificate", FAIL, "no --wp-url to check")
    host, explicit_port = target
    port = explicit_port or 443
    dial_host = ctx.override_ip or host
    timeout_s = ctx.settings.http.timeout_s
    warn_days = ctx.settings.tls.warn_days
    budget = _http_deadline(deadline, timeout_s)
    try:
        cert = _tls_peer_cert(
            dial_host, host, port, timeout_s, verify=True, deadline=budget)
    except ssl.SSLCertVerificationError as exc:
        error = redact_text(" ".join(str(exc).split()))
        try:
            # Retry ONCE, unverified, only to read the certificate's facts.
            cert = _tls_peer_cert(
                dial_host, host, port, timeout_s, verify=False,
                deadline=budget)
        except (OSError, ssl.SSLError, WptError) as retry_exc:
            _raise_stop(retry_exc)
            cert = None
        return _certificate_row(
            host, cert, False, error, warn_days, time.time())
    except (OSError, ssl.SSLError, WptError) as exc:
        _raise_stop(exc)
        return _row(
            "tls certificate", WARN,
            f"TLS unreachable for {host}: "
            f"{redact_text(' '.join(str(exc).split()))}")
    return _certificate_row(
        host, cert, True, None, warn_days, time.time())


def _tls_peer_cert(dial_host: str, host: str, port: int, timeout_s: int,
                   *, verify: bool, deadline: float | None = None):
    """One TLS handshake; returns the peer certificate dict.

    Resolution, every dial attempt and the handshake share ONE absolute
    ``deadline`` (``time.monotonic``): the resolver runs in php_probe's
    bounded worker, each resolved numeric address gets a bounded share of
    the remaining budget (so a dead AAAA cannot starve the working IPv4),
    and the TLS handshake is driven by ``select`` against the remainder.
    ``None`` means a fresh ``timeout_s`` bound.

    The verified context is the default trust store with hostname
    checking.  The single unverified retry exists only to read facts from a
    certificate that already failed verification; with ``CERT_NONE``
    ``getpeercert()`` returns ``{}``, so the DER form is decoded here
    instead of returning an empty dict the row cannot describe.
    """
    now = time.monotonic()
    budget = now + timeout_s if deadline is None else deadline
    addresses = _resolve_host_bounded(dial_host, port, budget)
    last_error: BaseException | None = None
    for index, address in enumerate(addresses):
        remaining = budget - time.monotonic()
        if remaining <= 0:
            raise socket.timeout(
                f"TLS dial for {host} exceeded the absolute deadline")
        # ONE share per remaining address covers BOTH the dial and the
        # handshake: a stale/blackholed first address used to consume the
        # whole budget in one handshake, so a later address with a valid
        # certificate was never tried (and a non-TLS service made the row
        # WARN "unreachable" although the next address was healthy).  The
        # absolute attempt deadline is computed BEFORE the dial and reused
        # for the handshake — computing a fresh ``now + share`` after the
        # dial spent the share twice and overran the run budget.
        share = remaining / (len(addresses) - index)
        attempt_budget = time.monotonic() + max(
            0.001, min(timeout_s, share))
        try:
            sock = _dial_numeric(
                address, port, max(0.001, attempt_budget - time.monotonic()))
        except OSError as exc:
            last_error = exc
            continue
        try:
            context = ssl.create_default_context()
            if not verify:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            tls = _tls_wrap_bounded(sock, host, context, attempt_budget)
            sock = None
            try:
                if verify:
                    return tls.getpeercert()
                der = tls.getpeercert(binary_form=True)
                decoded = _decode_der_cert(der)
                # Keep the "a certificate was presented" fact even when this
                # build cannot decode DER: the row can then say so.
                return decoded if decoded is not None else {"binary": True}
            finally:
                tls.close()
        except ssl.SSLCertVerificationError:
            # A VERIFIED handshake reached a certificate and rejected it:
            # the unverified retry in the caller is the one reader of its
            # facts.  Never treat it as an unreachable address.
            raise
        except (OSError, ssl.SSLError) as exc:
            last_error = exc
            continue
        finally:
            if sock is not None:
                sock.close()
    if last_error is not None:
        raise last_error
    raise OSError(f"TLS dial for {host} found no usable address")


def _tls_wrap_bounded(sock: socket.socket, host: str,
                      context: ssl.SSLContext,
                      deadline: float) -> ssl.SSLSocket:
    """Complete the TLS handshake under ONE absolute deadline.

    ``SSLSocket``'s own timeout is per read/write: a peer dripping one
    handshake record at a time can keep resetting it.  The socket is
    non-blocking and the handshake is driven by ``select`` against the
    remaining budget, so no drip can outlive ``deadline``.
    """
    sock.setblocking(False)
    tls = context.wrap_socket(
        sock, server_hostname=host, do_handshake_on_connect=False)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout(
                f"TLS handshake for {host} exceeded the absolute deadline")
        readable = writable = []
        try:
            tls.do_handshake()
            return tls
        except ssl.SSLWantReadError:
            readable, _writable, _errors = select.select(
                [tls], [], [], remaining)
        except ssl.SSLWantWriteError:
            _readable, writable, _errors = select.select(
                [], [tls], [], remaining)
        if not readable and not writable:
            tls.close()
            raise socket.timeout(
                f"TLS handshake for {host} exceeded the absolute deadline")


def _dial_numeric(address: str, port: int, timeout_s: float) -> socket.socket:
    """Connect to an already-resolved numeric address under a timeout.

    ``socket.create_connection`` would resolve AGAIN (through libc
    ``getaddrinfo``) and could re-enter the very stall the bounded resolver
    just escaped; the address here is numeric by construction.
    """
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(max(0.001, timeout_s))
        sock.connect((address, port))
        return sock
    except BaseException:
        sock.close()
        raise


def _decode_der_cert(der: bytes | None) -> dict | None:
    """Decode a DER certificate into ssl's dict shape, or None.

    CPython exposes the PEM decoder used by ``getpeercert`` as the private
    ``ssl._ssl._test_decode_cert``; it takes a FILE path, so the DER bytes
    are wrapped in PEM and written to a short-lived temp file.  Absent on a
    non-CPython/partial build -> None (the caller reports that facts were
    unavailable rather than fabricating them).
    """
    if not der:
        return None
    decoder = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if decoder is None:
        return None
    path = None
    try:
        with tempfile.NamedTemporaryFile(
                "w", suffix=".pem", prefix="wpt-cert-", delete=False,
                encoding="ascii") as handle:
            path = handle.name
            handle.write(ssl.DER_cert_to_PEM_cert(der))
        decoded = decoder(path)
        return decoded if isinstance(decoded, dict) else None
    except (OSError, ValueError, ssl.SSLError):
        return None
    finally:
        if path is not None:
            try:
                os.unlink(path)
            except OSError:
                log.debug("doctor: could not remove the decoded-cert temp file")


def _certificate_deadline(cert) -> float | None:
    """The certificate's ``notAfter`` as a unix timestamp, or None."""
    value = cert.get("notAfter") if isinstance(cert, dict) else None
    if not isinstance(value, str) or not value:
        return None
    try:
        return ssl.cert_time_to_seconds(value)
    except (TypeError, ValueError):
        return None


def _common_name(rdns) -> str:
    """The first ``commonName`` in an ssl certificate RDN sequence."""
    try:
        for rdn in rdns or ():
            for key, value in rdn:
                if str(key).lower() == "commonname" and value:
                    return str(value)
    except (TypeError, ValueError):
        return ""
    return ""


def _certificate_facts(cert, now: float) -> str:
    """The bounded certificate facts a row may carry (never a full subject)."""
    if not isinstance(cert, dict) or not cert:
        return "no certificate facts"
    names: list[str] = []
    for pair in cert.get("subjectAltName") or ():
        try:
            kind, value = pair
        except (TypeError, ValueError):
            continue
        if kind == "DNS" and value and str(value) not in names:
            names.append(str(value))
    if names:
        subject = "SAN " + ", ".join(names[:4])
        if len(names) > 4:
            subject += ", ..."
    else:
        cn = _common_name(cert.get("subject"))
        subject = f"CN {cn}" if cn else "no subject name"
    issuer = _common_name(cert.get("issuer")) or "unknown"
    deadline = _certificate_deadline(cert)
    if deadline is None:
        expiry = "expiry unknown"
    else:
        date = time.strftime("%Y-%m-%d", time.gmtime(deadline))
        if deadline <= now:
            days = int((now - deadline) / 86400)
            expiry = f"expired {date} ({days} day(s) ago)"
        else:
            days = int((deadline - now) / 86400)
            expiry = f"expires {date} ({days} day(s) left)"
    return f"{subject}; issuer {issuer}; {expiry}"


def _certificate_row(host: str, cert, verified: bool, error: str | None,
                     warn_days: int, now: float) -> dict[str, str]:
    """The pure certificate verdict; tests inject synthetic cert dicts."""
    facts = _certificate_facts(cert, now)
    if error:
        return _row(
            "tls certificate", FAIL,
            f"certificate does not verify for {host}: {error}; {facts}")
    if not isinstance(cert, dict) or not cert:
        return _row("tls certificate", FAIL,
                    f"no certificate presented for {host}")
    deadline = _certificate_deadline(cert)
    if deadline is not None and deadline <= now:
        return _row("tls certificate", FAIL,
                    f"certificate expired for {host}: {facts}")
    if not verified:
        return _row("tls certificate", FAIL,
                    f"certificate does not verify for {host}; {facts}")
    if deadline is None:
        return _row("tls certificate", WARN,
                    f"certificate verified but its expiry is unreadable; "
                    f"{facts}")
    if deadline - now <= warn_days * 86400:
        days = max(0, int((deadline - now) / 86400))
        return _row("tls certificate", WARN,
                    f"certificate expires in {days} day(s); {facts}")
    return _row("tls certificate", PASS,
                f"certificate verifies for {host}; {facts}")


# ---------------------------------------------------------- https policy


#: RFC 7230 ``tchar``: the token production every directive name and every
#: unquoted directive value must satisfy.
_HSTS_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
#: RFC 6797 delta-seconds: one or more DIGIT, nothing else.
_HSTS_DELTA_SECONDS_RE = re.compile(r"^[0-9]+$")


def _hsts_split_directives(value: str) -> list[str] | None:
    """Split a header on ``;`` while respecting quoted strings.

    A semicolon inside ``x="a;b"`` is qdtext, not a directive separator.
    Returns ``None`` when a quoted string is unterminated: a user agent MUST
    ignore such a header, so the caller renders WARN instead of guessing.
    """
    directives: list[str] = []
    current: list[str] = []
    quoted = False
    escaped = False
    for char in value:
        if quoted:
            current.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
            continue
        if char == '"':
            quoted = True
            current.append(char)
        elif char == ";":
            directives.append("".join(current))
            current = []
        else:
            current.append(char)
    if quoted:
        return None
    directives.append("".join(current))
    return directives


def _hsts_quoted_string_valid(raw: str) -> bool:
    """RFC 7230 quoted-string: quoted-pair or qdtext, closing quote last."""
    if len(raw) < 2 or raw[0] != '"' or raw[-1] != '"':
        return False
    inner = raw[1:-1]
    index = 0
    while index < len(inner):
        char = inner[index]
        if char == "\\":
            # quoted-pair must be followed by HTAB / SP / VCHAR / obs-text.
            index += 1
            if index >= len(inner):
                return False
            escaped = inner[index]
            if not (escaped == "\t" or " " <= escaped <= "\x7e"
                    or "\x80" <= escaped <= "\xff"):
                return False
        elif char == '"':
            return False
        elif not (char == "\t" or " " <= char <= "\x7e"
                  or "\x80" <= char <= "\xff"):
            # Control characters are not qdtext.
            return False
        index += 1
    return True


def _hsts_directive_value_valid(raw: str) -> bool:
    """RFC 7230 ``directive-value = token | quoted-string``."""
    return bool(_HSTS_TOKEN_RE.match(raw)) or _hsts_quoted_string_valid(raw)


def _hsts_policy(value: str) -> tuple[int | None, str | None]:
    """``(max-age, why the header is ignored)`` parsed per RFC 6797.

    RFC 6797 §6.1 makes the whole header conforming only when every
    directive name appears once and carries a valid value: ``max-age`` is a
    decimal ``delta-seconds``, ``includeSubDomains`` is valueless, and every
    unknown extension value is a token or a quoted-string.  A user agent
    MUST ignore a non-conforming STS header, so ``max-age=abc;
    max-age=31536000``, a duplicate ``includeSubDomains`` or ``x=@`` is not a
    security assurance: return the reason instead of searching for any
    valid-looking occurrence.

    ``max-age=0`` is conforming but disables HSTS; it is returned as ``0``
    so the caller can render its distinct warning.  Unknown extension
    directives are allowed (and must still be unique).

    The header is split quote-aware: a semicolon inside ``x="a;b"`` is
    part of the quoted value, not a directive boundary.
    """
    directives = _hsts_split_directives(value)
    if directives is None:
        return None, "unterminated quoted string"
    seen: set[str] = set()
    max_age: int | None = None
    for raw in directives:
        directive = raw.strip()
        if not directive:
            # A trailing/duplicated separator is empty field syntax, not a
            # directive; tolerate it rather than rejecting a common header.
            continue
        name, separator, raw_value = directive.partition("=")
        name = name.strip().lower()
        if not _HSTS_TOKEN_RE.match(name):
            return None, f"malformed directive {directive!r}"
        if name in seen:
            return None, f"duplicate {name} directive"
        seen.add(name)
        if name == "max-age":
            if not separator:
                return None, "max-age has no value"
            number = raw_value.strip()
            if len(number) >= 2 and number[0] == number[-1] == '"':
                if not _hsts_quoted_string_valid(number):
                    return None, f"max-age={number} is not a quoted-string"
                number = number[1:-1]
            if not _HSTS_DELTA_SECONDS_RE.match(number):
                return None, f"max-age={raw_value.strip()} is not delta-seconds"
            try:
                max_age = int(number)
            except ValueError:
                # ``int`` refuses very long digit strings (sys.int_max_str_
                # digits); that value is still a syntactically valid but
                # unusable delta-seconds, never a traceback.
                return None, "max-age is too large to evaluate"
        elif name == "includesubdomains":
            if separator:
                return None, "includeSubDomains must not carry a value"
        elif separator and not _hsts_directive_value_valid(raw_value.strip()):
            return None, (
                f"directive {name} has an invalid value "
                f"{raw_value.strip()!r}")
    if "max-age" not in seen:
        return None, "max-age is required"
    return max_age, None


def _normalized_origin_host(host: str | None) -> str:
    """The same host spelling for a URL answer and the configured site."""
    return (host or "").strip().rstrip(".").lower()


def _same_https_origin(url: str, host: str, https_port: int) -> bool:
    """True when ``url`` is https on the configured host AND effective port.

    HSTS belongs to an ORIGIN, not a header.  Following a redirect to a
    foreign host (or a subdomain, whose cookies/HSTS are a different
    origin) and reading that answer's HSTS reported a PASS for a policy
    this site never set (R11-P2-5).  Default-port normalization means an
    explicit ``:443`` and an omitted port are the same origin.
    """
    try:
        parsed = urlparse(url)
        port = parsed.port or 443
    except (TypeError, ValueError):
        return False
    return (
        parsed.scheme.lower() == "https"
        and bool(parsed.hostname)
        and _normalized_origin_host(parsed.hostname)
        == _normalized_origin_host(host)
        and port == https_port
    )


def _https_policy_check(session, ctx: Ctx,
                        deadline: Deadline | None = None) -> dict[str, str]:
    """HTTP must redirect to HTTPS and the HTTPS answer must carry HSTS."""
    target = _wp_target(ctx.wp_url)
    if target is None:
        return _row("https policy", FAIL, "no --wp-url to check")
    host, explicit_port = target
    http_port = explicit_port or 80
    https_port = explicit_port or 443
    http_url = f"http://{_authority(host, http_port, 80)}/"
    https_url = f"https://{_authority(host, https_port, 443)}/"
    timeout_s = ctx.settings.http.timeout_s
    verify = ctx.settings.http.verify_tls
    budget = _http_deadline(deadline, timeout_s)
    forced = False
    try:
        response = get_bounded(
            session, http_url, timeout_s=timeout_s, deadline=budget,
            allow_redirects=False, verify=verify,
        )
        status = response.status_code
        headers = getattr(response, "headers", {}) or {}
        location = headers.get("Location") if hasattr(headers, "get") else None
        close = getattr(response, "close", None)
        if callable(close):
            close()
    except Exception as exc:
        _raise_stop(exc)
        http_fact = (f"HTTP request failed: "
                     f"{redact_text(' '.join(str(exc).split()))}")
    else:
        if 200 <= status < 300:
            http_fact = "HTTP serves content; HTTPS is not forced"
        elif 300 <= status < 400:
            if (isinstance(location, str)
                    and _same_https_origin(location, host, https_port)):
                forced = True
                http_fact = f"HTTP redirects to {location}"
            else:
                suffix = (f" (redirects to {location})" if location
                          else f" (HTTP {status})")
                if (isinstance(location, str)
                        and location.lower().startswith("https://")):
                    suffix = (f" (redirects to a different origin: "
                              f"{location})")
                http_fact = ("HTTP serves content; HTTPS is not forced"
                             + suffix)
        else:
            http_fact = (f"HTTP {status} at {http_url}; "
                         "HTTPS is not forced")

    try:
        response = get_bounded(
            session, https_url, timeout_s=timeout_s,
            deadline=_http_deadline(deadline, timeout_s),
            allow_redirects=True, verify=verify,
        )
        status = response.status_code
        raw_final_url = getattr(response, "url", None)
        headers = getattr(response, "headers", {}) or {}
        hsts = headers.get("Strict-Transport-Security") if hasattr(
            headers, "get") else None
        close = getattr(response, "close", None)
        if callable(close):
            close()
    except Exception as exc:
        _raise_stop(exc)
        return _row(
            "https policy", WARN,
            f"HTTPS request failed: "
            f"{redact_text(' '.join(str(exc).split()))}")
    if not isinstance(raw_final_url, str) or not raw_final_url:
        # Without a final URL the transport cannot prove the answer came
        # over HTTPS.  A session double (or a third-party session) may not
        # carry one; never fall back to the REQUESTED https URL, and never
        # accept HSTS from an unverified answer.
        return _row(
            "https policy", WARN,
            "HTTPS final URL could not be verified (the response records "
            "no URL); HSTS is not trusted")
    final_url = raw_final_url
    if not final_url.lower().startswith("https://"):
        # requests follows Location: http://...; HSTS on that answer is
        # meaningless (browsers ignore it over plain HTTP), so a site that
        # downgrades must never be reported as forcing HTTPS.
        return _row(
            "https policy", WARN,
            f"HTTPS redirects DOWNGRADE to plain HTTP: "
            f"{redact_text(final_url)}")
    if not _same_https_origin(final_url, host, https_port):
        # The answer's HSTS belongs to whatever origin answered; a foreign
        # host or subdomain is not this site's policy (R11-P2-5).
        return _row(
            "https policy", WARN,
            f"HTTPS redirects to a different origin: "
            f"{redact_text(final_url)}; HSTS is not trusted")
    if not 200 <= status < 400:
        return _row("https policy", WARN,
                    f"HTTPS request failed: HTTP {status} at {https_url}")
    hsts = str(hsts or "").strip()
    if hsts:
        max_age, problem = _hsts_policy(hsts)
        if problem is not None:
            return _row("https policy", WARN,
                        f"{http_fact}; HSTS header is non-conforming "
                        f"({problem}) ({hsts})")
        if max_age is None:
            return _row("https policy", WARN,
                        f"{http_fact}; HSTS has no valid max-age ({hsts})")
        if max_age <= 0:
            # max-age=0 disables HSTS (RFC 6797) — never a PASS.
            return _row("https policy", WARN,
                        f"{http_fact}; HSTS max-age={max_age} disables HSTS "
                        f"({hsts})")
        if forced:
            return _row("https policy", PASS,
                        f"{http_fact}; HSTS {hsts}")
        return _row("https policy", WARN,
                    f"{http_fact}; HSTS {hsts}")
    return _row("https policy", WARN,
                f"{http_fact}; HTTPS works but HSTS is absent")


# ------------------------------------------------------------- host logs


def _host_log_check(ctx: Ctx, source, deadline=None) -> dict[str, str]:
    """One bounded host/webroot error-log triage pass."""
    if source is None:
        return _row("host error log", FAIL, _STACK_DOWN)
    try:
        scan = collect_logs(ctx, webroot_source=source, deadline=deadline)
    except Exception as exc:
        _raise_stop(exc)
        return _row(
            "host error log", WARN,
            f"could not read host logs: "
            f"{redact_text(' '.join(str(exc).split()))}")
    skipped = len(getattr(scan, "skipped", None) or [])
    if scan.scanned == 0:
        detail = "no host/webroot log files found"
        if skipped:
            detail += f" ({skipped} skipped)"
        return _row("host error log", WARN, detail)
    if not scan.total_matches:
        if skipped:
            return _row(
                "host error log", WARN,
                f"{scan.scanned} file(s); no fatal/error patterns; "
                f"{skipped} skipped (unreadable or over a bound)")
        return _row("host error log", PASS,
                    f"{scan.scanned} file(s); no fatal/error patterns")
    skipped_note = f"; {skipped} skipped" if skipped else ""
    if not scan.matches:
        return _row("host error log", WARN,
                    f"{scan.total_matches} matching line(s) in "
                    f"{scan.scanned} file(s){skipped_note}")
    # The newest matching FILE is the one with the best candidate rank
    # (mtime), recorded while scanning; ``matches[0]`` is merely the first
    # scanned candidate and can be an older, undated webroot log.
    newest_file = (getattr(scan, "latest_file", None)
                   or scan.matches[0].get("file"))
    latest_by_file = getattr(scan, "latest_matches", None) or {}
    latest = latest_by_file.get(newest_file)
    if latest is None:
        latest = next(
            (match for match in reversed(scan.matches)
             if match.get("file") == newest_file),
            scan.matches[-1],
        )
    excerpt = str(latest.get("match") or "")[:_LOG_EXCERPT]
    return _row(
        "host error log", WARN,
        f"{scan.total_matches} matching line(s) in {scan.scanned} file(s)"
        f"{skipped_note}; latest {latest.get('file')}:{latest.get('line')} "
        f"{latest.get('pattern')} — {excerpt}")


# ---------------------------------------------------------------- wp.org


def _wporg_check(session, timeout_s: int,
                 deadline: Deadline | None = None,
                 config=None) -> dict[str, str]:
    """The wp.org reachability row through the real updates transport."""
    try:
        latest = WpOrgApi(
            session, timeout_s,
            # The RUN budget, not a pre-minimized transport instant:
            # WpOrgApi owns the min(run, now + timeout_s) transport bound
            # and distinguishes a per-request timeout (WARN/None) from a
            # spent run (the row ends the run).
            deadline=None if deadline is None else deadline.at,
            config=config,
        ).latest_core_version()
    except Exception as exc:
        _raise_stop(exc)
        return _row("wp.org API", FAIL, str(exc))
    if latest is not None:
        return _row("wp.org API", PASS,
                    f"reachable — latest core offer {latest}")
    return _row("wp.org API", WARN,
                "no answer from api.wordpress.org — updates/integrity "
                "checks degrade without it")


def _database_check(ctx: Ctx, deadline: Deadline | None = None) -> dict[str, str]:
    """One connection to the ``--db-uri`` database: reachable or not.

    A connection plus a table listing is the smallest fact that answers
    "can this run work", and it is the exact seam ``clean-db --apply`` uses
    (a refused login or a missing driver surfaces here, in seconds, instead
    of at the first DELETE). The detail never carries a credential: the URI
    renders redacted and any driver text is redacted too.

    ``deadline`` is threaded into BOTH the connection and every query: the
    driver's fixed 10s/300s timeouts used to let one slow connect outlive
    the whole run budget before the row's post-check could see it (C3).
    """
    conn = None
    try:
        uri = parse_db_uri(ctx.db_uri or "")
        if deadline is not None:
            deadline.check("doctor database connect")
        conn = connect(uri, password=ctx.db_password, deadline=deadline,
                       settings=ctx.settings.db)
        # The SAME introspection the offline audit and the re-dump read, so
        # the count this row reports is the count those would enumerate.
        tables = schema_tables(conn)
        if deadline is not None:
            deadline.check("doctor database")
    except Exception as exc:
        _raise_stop(exc)
        return _row("database (--db-uri)", FAIL, redact_text(str(exc)))
    finally:
        if conn is not None:
            close = getattr(conn, "close", None)
            if callable(close):
                try:
                    close()
                except Exception as exc:
                    _raise_stop(exc)
                    log.warning("doctor: database close failed: %s", exc)
    return _row("database (--db-uri)", PASS,
                f"connected to {uri.redacted} — {len(tables)} base table(s)")


def _disk_check(ctx: Ctx) -> dict[str, str]:
    """Free space at the nearest EXISTING ancestor of the backup target.

    The doctor runs before the session (and before a nested ``--backup-dir``
    is created), so neither the backup dir nor its immediate parent may
    exist yet.  Walk up to the first existing ancestor; when nothing can be
    measured the row is the documented free-space-unavailable state (WARN,
    never a false FAIL/rc 1).
    """
    target = _existing_ancestor(ctx.backup_dir)
    if target is None:
        return _row("disk", WARN,
                    f"free space unavailable — no existing ancestor of "
                    f"{ctx.backup_dir}")
    try:
        free = shutil.disk_usage(target).free
    except Exception as exc:
        _raise_stop(exc)
        return _row("disk", WARN,
                    f"free space unavailable at {target}: {exc}")
    if free > ctx.settings.backup.free_pass_bytes:
        return _row("disk", PASS, f"{human_bytes(free)} free at {target}")
    if free > ctx.settings.backup.free_warn_bytes:
        return _row(
            "disk", WARN,
            f"{human_bytes(free)} free at {target} "
            f"(under {human_bytes(ctx.settings.backup.free_pass_bytes)})")
    return _row(
        "disk", FAIL,
        f"{human_bytes(free)} free at {target} "
        f"(under {human_bytes(ctx.settings.backup.free_warn_bytes)} — "
        "snapshots cannot land)")


def _existing_ancestor(path: Path) -> Path | None:
    """The first existing directory at or above ``path`` (None if none)."""
    candidate = path.resolve()
    while True:
        if candidate.exists():
            return candidate
        parent = candidate.parent
        if parent == candidate:
            return None
        candidate = parent


def _ini_flag(value) -> str:
    """``1`` only for PHP's own string ``"1"``; every other answer is ``0``."""
    return "1" if value == "1" else "0"


def _measured_ini_flag(value) -> str | None:
    """``1``/``0`` for a PRESENT ini value; None when the probe didn't answer.

    ``ini_get`` returns boolean false for a directive the runtime does not
    know (cookie_samesite before 7.3, an older probe), and that is absence,
    not a lax setting.  A PRESENT value — including PHP's empty string for a
    directive set with no value (``session.use_only_cookies=``) — is measured:
    PHP reads that empty value as boolean false, i.e. lax ``"0"``
    (R6-40).
    """
    if value is None or value is False:
        return None
    return "1" if value in (1, "1", True) else "0"


# ---------------------------------------------------------------- rendering


def _row(name: str, result: str, detail: str) -> dict[str, str]:
    """One panel row — the exact JSON-twin shape, in panel order.

    Redaction is here, at the ONE row constructor, so a detail assembled
    from an exception, a redirect Location or a host answer cannot leak a
    token/credential into the table, the markdown report or the JSON twin.
    """
    return {"name": name, "result": result, "detail": redact_text(detail)}


def _site_label(ctx: Ctx) -> str:
    """The panel title's site: the public URL when known, else the source."""
    return redact_text(ctx.wp_url or ctx.source)


def _render(site: str, checks: list[dict[str, str]], note: str) -> str:
    """The doctor markdown table (the JSON twin is :func:`_render_json`)."""
    lines = [f"# wpt doctor — {site}", ""]
    if note:
        lines.append(note)
        lines.append("")
    lines.append("| check | result | detail |")
    lines.append("|---|---|---|")
    for check in checks:
        lines.append(f"| {md_escape(check['name'])} | {check['result']} "
                     f"| {md_escape(check['detail'])} |")
    lines.append("")
    return "\n".join(lines)


def _render_json(checks: list[dict[str, str]]) -> str:
    """The machine-readable twin: exactly ``{"checks": [{name, result,
    detail}]}`` — doctor's own small schema, deliberately minimal —
    formatted like every other JSON twin in the toolkit."""
    return json.dumps(
        {"checks": [dict(check) for check in checks]},
        ensure_ascii=False, sort_keys=True, indent=2,
    ) + "\n"
