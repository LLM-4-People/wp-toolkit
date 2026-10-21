"""``wpt scan`` — a source-only dangerous-PHP-pattern scan.

The command answers the audit's security question from the WEBROOT ALONE:
no WordPress, no bridge, no database, no live session.  It walks the chosen
source (an FTP webroot or an offline zip), gathers the source-only
``AuditData``, attaches the run deadline, and executes exactly ONE registered
check — ``security.source_patterns`` (see
:mod:`wpt.audit.source_scan`) — through the normal audit registry.  The
report uses the audit renderer, so ``--report`` keeps the same markdown +
JSON-twin contract every other command honors.

Mode inputs:
    * local — ``ctx.zip`` only; ``--sql`` is deliberately NOT read or
      required (a source scan needs no dump).
    * ftp — ``ftp_source_for(ctx)`` rooted at ``ctx.webroot``; no bridge is
      built or deployed, so ``--wp-url`` is not part of this command's
      input contract.

Error contract (mirrors ``wpt.audit.run``): every WptError/OSError is logged
at error, answered with a failure report (when ``--report`` was given) and
exit 1 — a traceback never escapes :func:`run`.  The source is closed in a
``finally`` on every path.  Read-only by construction: there is no
``--apply`` and no mutation path here.
"""

from __future__ import annotations

from urllib.parse import urlparse

from .actions.registry import write_failure_report, write_report
from .audit.data import gather_source
from .config import redact_text
from .audit.registry import run_checks
from .deadline import Deadline
from .log import get_logger
from .remote import ftp_source_for
from .report import AuditReport, render_json, render_report, safe_text
from .report import write_stdout
from .sources.base import close_source
from .sources.zip import ZipSource
from .types import (DeadlineExceeded, RunControl, SourceError, StopRequested,
                    WptError)

log = get_logger("scan")

__all__ = ["run"]

#: The one check this command runs; the audit's registry owns selection and
#: execution, so this command adds no parallel dispatch path.
_SELECTION = ["security.source_patterns"]


def _ftp_label(ctx) -> str:
    """``host[:port]`` from ``ctx.source`` — never a userinfo component."""
    try:
        parsed = urlparse(ctx.source or "")
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return "unknown"
    if not host:
        return "unknown"
    return host if port is None else f"{host}:{port}"


def _site(ctx) -> str:
    """The report header's site: the explicit URL, the zip name, or the host."""
    if ctx.mode == "local":
        if ctx.wp_url:
            return safe_text(redact_text(ctx.wp_url))
        return f"local:{ctx.zip.name}" if ctx.zip is not None else "local:unknown"
    return safe_text(redact_text(ctx.wp_url)) if ctx.wp_url else _ftp_label(ctx)


def _source_summary(ctx) -> str:
    """What was scanned, in the audit report's one-line source form."""
    if ctx.mode == "local":
        return f"zip:{ctx.zip.name}" if ctx.zip is not None else "zip:(missing)"
    return f"ftp://{_ftp_label(ctx)}"


def _write_failure(ctx, reason: str) -> None:
    """Write the report of a scan that measured nothing (best effort).

    Runs on the way out of a failed run, so it must never raise over the
    failure it reports — exactly the audit's failure-report contract, with
    the same site/source header the successful report would have carried.
    """
    try:
        write_failure_report(
            ctx, "scan", reason,
            audit=AuditReport(
                site=_site(ctx),
                source_summary=_source_summary(ctx),
            ),
            title="wpt scan",
        )
    except (Exception, RunControl) as exc:  # noqa: BLE001 — reporting must not raise
        log.warning("scan: could not write the failure report: %s", exc)


def run(ctx) -> int:
    """Run the source-only scan for ``ctx``; 0 on success, 1 on failure."""
    source = None
    rc = 1
    close_stop: BaseException | None = None
    primary: BaseException | None = None
    try:
        deadline = Deadline.from_ctx(ctx)
        if deadline is not None:
            deadline.check("scan setup")
        if ctx.mode == "local":
            if ctx.zip is None:
                raise SourceError("local mode requires --zip")
            source = ZipSource(ctx.zip, deadline=deadline)
        else:
            source = ftp_source_for(ctx)
        data = gather_source(source, ctx.mode, deadline=deadline)
        data.deadline = deadline
        findings = run_checks(
            data, ctx.settings, ctx.mode, _SELECTION, None,
        )
        report = AuditReport(
            site=_site(ctx),
            source_summary=_source_summary(ctx),
            findings=findings,
            totals={"entries": len(data.entries), "mode": data.mode},
        )
        markdown = render_report(report, title="wpt scan")
        if ctx.report_path is not None:
            rc = write_report(ctx, "scan", markdown, render_json(report))
            if rc:
                return rc
        else:
            # The report is this command's stdout surface; only the shared
            # report sink may write it.
            write_stdout(markdown)
        partial = any(
            finding.category == "security.source_patterns"
            and finding.name == "scan-partial"
            for finding in findings
        )
        # A check that crashed is a COVERAGE GAP (audit.check_failed), not a
        # clean tree.  The runner catches it so one bad check cannot take
        # the run down; a security gate still must not answer success.
        check_failed = any(
            finding.category == "audit.check_failed"
            for finding in findings
        )
        log.info(
            "scan: %d finding(s), %d entries%s%s",
            len(findings), len(data.entries),
            " — PARTIAL (rc 1)" if partial else "",
            " — CHECK FAILED (rc 1)" if check_failed else "",
        )
        rc = 1 if partial or check_failed else 0
    except RunControl as exc:
        primary = exc
        reason = redact_text(f"scan stopped: {exc}")
        log.error("%s", reason)
        _write_failure(ctx, reason)
        rc = 1
    except (WptError, OSError) as exc:
        primary = exc
        log.error("scan failed: %s", exc)
        _write_failure(ctx, str(exc))
        rc = 1
    finally:
        if source is not None:
            try:
                close_source(source, "scan")
            except (StopRequested, DeadlineExceeded) as exc:
                # Teardown was ATTEMPTED; the cooperative stop must still end
                # the run with rc 1 (SIGTERM never reports success).
                close_stop = exc
            except Exception as exc:  # noqa: BLE001 — never mask data
                log.warning("scan: could not close the source: %s", exc)
    if close_stop is not None:
        reason = redact_text(str(close_stop))
        log.error("scan: %s", reason)
        if primary is None:
            _write_failure(ctx, reason)
        else:
            log.error("scan: the primary failure above stays the run's "
                      "reason (rc %d); the failure report was not replaced",
                      rc)
        return 1
    return rc
