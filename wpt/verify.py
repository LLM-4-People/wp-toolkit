r"""wpt verify — the post-change live reference re-check (W7, SPEC [L2]).

``wpt verify`` re-checks every live reference the site currently uses:
the verification pass SPEC makes mandatory after a mutating action
("verify after every change … refuse to report success without it").
A media trim once looked successful while it had broken 36 srcset
variants, and only URL re-verification caught it [L2] — so this command
asserts 2xx on the FULL live reference set, never a sample.

Design (mirrors the assembled audit runner, ``wpt/audit/__init__.py``):

* local mode WITHOUT ``--wp-url`` refuses with rc 1 (nothing to
  check); local mode WITH a wp_url runs against a ``wpt serve``
  rehearsal — a plain Session, no bridge, no source (the served zip IS
  the site; verify never reads it).
* ftp mode builds the remote stack through the ONE construction seam
  ``wpt.audit.remote_stack`` (imported into THIS namespace so tests can
  monkeypatch ``wpt.verify.remote_stack``); the bridge is destroyed in a
  ``finally`` spanning the whole pass (``Bridge.destroy`` is idempotent
  and a no-op when the bridge was never deployed).
* a FRESH ``walk_site`` produces the reference set (imported into this
  namespace for the same patchability).  A failed walk DEGRADES the whole
  command to rc 1: the re-check could not happen, so success cannot be
  reported — exactly like the audit runner's degrade, but fatal here.
* every ref in ``sorted(live_refs)`` (deterministic order) is re-fetched
  at ``{wp_url}/wp-content/uploads/{ref}`` — the tail percent-RE-ENCODED
  with ``quote(ref, safe="/")`` because refs are stored DECODED (the
  walker's conversion rule: the tail must equal the on-disk name).  The
  fetch is streamed (``stream=True``): the status comes from the headers,
  the body is never downloaded (media files can be huge) and the
  response is closed without reading (a ``getattr`` close guard keeps
  real ``requests.Response`` and simpler test doubles both usable).
  Classification per ref: ``ok`` = 2xx, ``broken`` = any other HTTP
  status (``"HTTP <status>"``), ``failed`` = transport error (the
  exception text).
* rc 0 requires every ref ok; any broken or failed ref answers 1.  A
  walk finding ZERO refs is NOT a pass: the run could not see a single
  reference, which is a statement about the crawl, never about the site.
  Every inconclusive arm — a partial walk, a homepage that is not
  answering, a degraded walk, a stack failure, an exhausted deadline —
  answers 1 with a named reason.
* the run is SELF-BOUNDING in its dominant loop, not only in the walk:
  ``_recheck_refs`` takes the same ``Deadline`` and checks it once per
  ref, because the re-check (one round-trip per reference, 10,000 of them
  on a big page) is where the wall time actually goes.  An exhausted
  budget ends the run through the ordinary error contract — fail-closed
  teardown, rc 1, one clear line — never as a pass over the references
  that happened to be reachable.

Output: a small markdown report PLUS its machine-readable JSON twin
(scripted/CI consumers).  The audit's AuditReport/Finding shape does
not fit a verification pass, so the twin carries verify's OWN small
schema — site, total, ok, and every broken/failed ref as a
``{"label", "url"}`` pair.  With ``ctx.report_path`` set BOTH files
are written: the markdown there and the JSON twin to
``report_path.with_suffix(".json")`` — exactly the audit ``_emit``
md+json pair; without it neither file is written.  The markdown is
ALSO always written to stdout through the shared
``wpt.report.write_stdout`` sink (the report IS the command's stdout
surface; stdout stays markdown-only).  One info summary (ok/broken/failed counts) is always
logged.

A run that FAILED also writes a report, in verify's own twin shape with
every count zero plus a ``run`` object naming the refusal
(``wpt.actions.registry.not_complete`` builds the block, so no command
grows a second "this did not complete" shape).  It is written and not
printed: a failed run has no report to show, and the point is that a
caller reading ``--report`` can tell "nothing to verify" from "never got
far enough".

Error contract (binding, same as the audit runner): every WptError and
OSError from the stack is logged at error and answered with rc 1 — a
traceback NEVER escapes ``run``.  Per-URL transport failures are
``requests.RequestException`` (an OSError subclass) but are caught
FIRST, inside the re-check, and classified as ``failed`` refs — a dead
reference is the finding, not a command error.
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING
from urllib.parse import quote

import requests

from .audit import remote_stack
from .config import redacted_site_label, redact_text
from .deadline import Deadline
from .log import get_logger
from .php_probe import get_bounded
from .report import (report_protected_inputs,
                     report_protected_subtrees, write_report_files)
from .report import write_stdout
from .types import RunControl, WptError
from .walk import walk_site

if TYPE_CHECKING:
    # Ctx is annotation-only (same pattern as wpt/audit/__init__.py):
    # cli lazy-calls this module, so there is no import cycle at runtime.
    from .cli import Ctx

__all__ = ["run"]

log = get_logger("verify")


def run(ctx: Ctx) -> int:
    """Re-check the full live reference set; 0 only when every ref answers 2xx.

    A fresh walk produces the references, each one is re-fetched
    streamed, and the markdown report goes to ``ctx.report_path`` and
    always to stdout; with ``ctx.report_path`` set the JSON twin is
    written alongside it (``report_path.with_suffix(".json")``).
    Never raises: stack failures are logged at error and answered
    with 1.

    The session contract: ftp mode rides the remote_stack seam (bridge
    deployed/destroyed as usual); LOCAL mode with a ``--wp-url`` runs
    against ``wpt serve`` — a plain Session, no bridge, no source (the
    served rehearsal IS the site; verify never reads the zip). Local
    mode WITHOUT a wp_url is the one refusal left (no URL to check).

    A run that does NOT verify anything is never a pass: a zero-reference
    walk, a degraded walk, a stack failure and an exhausted ``--deadline``
    all answer 1 (see :func:`_pass` and :func:`_recheck_refs`), and each
    of them leaves the report it could write behind — a caller can then
    tell "planned nothing / verified nothing" from "never got far enough",
    which is the difference the missing report made invisible.
    """
    if ctx.mode == "local" and not (ctx.wp_url or "").strip():
        return _write_failure(
            ctx, "verify requires a live site: ftp mode, or local mode with "
                 "--wp-url (e.g. a wpt serve rehearsal)")
    source = None
    session = None
    bridge = None
    rc = 1
    try:
        if ctx.mode == "local":
            session = requests.Session()
            rc = _pass(ctx, session)
        else:
            source, session, bridge = remote_stack(ctx)
            rc = _pass(ctx, session)
    except RunControl as exc:
        # One redacted line + the failure pair, after the finally teardowns.
        rc = _write_failure(ctx, f"verify stopped: {exc}")
    except (WptError, OSError) as exc:
        # _write_failure logs the ONE error line and writes the report;
        # logging here as well would say the same thing twice.
        rc = _write_failure(ctx, str(exc))
    finally:
        # Every piece of the trio is closed by the ONE teardown owner:
        # verify owns the HTTP session and (ftp) the source, and the bridge.
        from .teardown import teardown_stack

        first_stop = teardown_stack((source, session, bridge), "verify")
    if first_stop is not None:
        reason = f"verify: teardown stopped: {first_stop}"
        log.error("%s", reason)
        if rc == 0:
            # The pass wrote a success report; rc 1 beside it would be a
            # lie.  Replace it with the shared failure pair.
            rc = _write_failure(ctx, reason)
        else:
            rc = 1
    return rc


def _http_budget(deadline: Deadline | None, timeout_s: float) -> float:
    """The absolute instant ONE verify request may run until.

    ``min(run budget, now + http.timeout_s)``: a per-request timeout stays
    a per-request timeout (the probe degrades/fails that ref), while a
    spent run budget is still the run's stop — checked by the caller when
    the bounded transport reports a timeout.
    """
    per_request = time.monotonic() + max(0.001, float(timeout_s))
    return per_request if deadline is None else min(deadline.at, per_request)


def _write_failure(ctx: Ctx, reason: str) -> int:
    """A run that could not verify: one error line, rc 1, and the report
    the caller asked for.

    The report exists for the same reason the rc is 1: a caller reading
    ``--report`` after a failed run must be able to see WHY, and must be
    able to tell "verified nothing" from "never got far enough" — the
    difference a missing file made invisible (L44, one level up).  It
    keeps verify's OWN twin shape (``total``/``ok``/``broken``/``failed``,
    all zero) so a caller parses one family whatever the outcome, plus
    the shared ``run`` object naming the refusal.  It is NOT printed: a
    failed run has no report to show, and stdout stays the surface of a
    report that exists.
    """
    from .actions.registry import not_complete, write_report

    site = redacted_site_label(ctx.wp_url or ctx.source, fallback="unknown")
    block, payload = not_complete(reason, status="failed")
    markdown = _render(site, 0, 0, [], []) + block
    twin = json.loads(_render_json(site, 0, 0, [], []))
    twin["run"] = payload
    # ONE error line for the whole failure: the caller's reason IS the
    # message, so a failed run never says the same thing twice.
    log.error("verify did not verify: %s", redact_text(reason))
    write_report(ctx, "verify", markdown,
                 json.dumps(twin, ensure_ascii=False, sort_keys=True,
                            indent=2))
    return 1


def _pass(ctx: Ctx, session) -> int:
    """One verification pass over ``session``: fresh walk + streamed
    re-fetch of every live reference + the report. Returns the rc."""
    deadline = Deadline.from_ctx(ctx)
    try:
        walked = walk_site(session, ctx.wp_url or "",
                           ctx.settings.walk,
                           ctx.settings.http.timeout_s,
                           deadline=deadline)
    except (WptError, OSError) as exc:
        log.warning("live walk failed; verification degraded: %s", exc)
        return _write_failure(ctx, f"live walk failed: {exc}")
    if walked.partial:
        # ANY partial walk is INCONCLUSIVE, even when it found references:
        # the pages it could not fetch may reference media the measured set
        # does not contain.  A green verify over a partial set is the same
        # false all-clear as a green verify over an empty one.
        return _write_failure(
            ctx, "the live walk was PARTIAL (stopped early); verification "
                 "is INCONCLUSIVE")
    refs = sorted(walked.live_refs)
    if not refs:
        # A zero-ref walk is INCONCLUSIVE, and a green run that verified
        # NOTHING is the defect this branch used to ship: a site that
        # renders no reference the crawler can see (a bot-challenged
        # origin, a page-builder page whose images load from a CDN, a
        # rehearsal served as static PHP) answers rc 0 with "nothing to
        # re-check" and reads as a clean verification.  The partial signal
        # is consumed above; the probe stays because it distinguishes "the
        # site is not serving content" from "the site is serving content
        # this crawler cannot read" — two different faults an operator
        # acts on differently.  Every arm answers non-zero: there is no
        # walk that proves "nothing to check" here, only a walk that could
        # not see.
        base = (ctx.wp_url or "").rstrip("/")
        if deadline is not None:
            deadline.check("verify homepage")
        try:
            probe = get_bounded(
                session, base + "/",
                timeout_s=ctx.settings.http.timeout_s,
                deadline=_http_budget(deadline,
                                      ctx.settings.http.timeout_s),
                allow_redirects=True,
            )
        except (requests.RequestException, WptError) as exc:
            # A transport timeout is only inconclusive while the RUN still
            # has budget; once the run budget itself is spent this is the
            # run's stop, not a site diagnosis.
            if deadline is not None:
                deadline.check("verify homepage")
            return _write_failure(
                ctx, f"homepage probe failed ({redact_text(str(exc))}); the "
                     "site may be down; verification is INCONCLUSIVE")
        status = probe.status_code
        pclose = getattr(probe, "close", None)
        if callable(pclose):
            pclose()
        if not (200 <= status < 300):
            return _write_failure(
                ctx, f"homepage returned HTTP {status}; the site is not "
                     "serving content; verification is INCONCLUSIVE")
        return _write_failure(
            ctx, "the walk found NO live references, so nothing could be "
                 "verified — this is not a pass")
    # A budget that expires inside the re-check RAISES (DeadlineExceeded is
    # a RunControl BaseException, not a WptError): the run-level handler
    # logs the one line and writes the failure report, after the finally
    # teardowns have run.  A re-check that stopped early is a FAILURE, never
    # a pass over the references that happened to be reachable.
    ok_count, broken, failed = _recheck_refs(
        session, (ctx.wp_url or "").rstrip("/"), refs,
        ctx.settings.http.timeout_s, deadline=deadline,
    )
    site = redacted_site_label(ctx.wp_url or ctx.source)
    markdown = _render(site, len(refs), ok_count, broken, failed)
    if ctx.report_path is not None:
        write_report_files(
            ctx.report_path, markdown,
            _render_json(site, len(refs), ok_count, broken, failed),
            protected_paths=report_protected_inputs(ctx),
            protected_subtrees=report_protected_subtrees(ctx),
        )
    write_stdout(markdown)
    log.info("verify: %d refs ok, %d broken, %d failed",
             ok_count, len(broken), len(failed))
    return 0 if not broken and not failed else 1


def _recheck_refs(
    session: requests.Session, site: str, refs: list[str], timeout_s: int,
    deadline: Deadline | None = None,
) -> tuple[int, list[tuple[str, str]], list[tuple[str, str]]]:
    """Fetch every ref's uploads URL; return ``(ok count, broken, failed)``.

    Each entry in ``broken``/``failed`` is a ``(label, url)`` pair — the
    label is ``"HTTP <status>"`` for a non-2xx answer or the exception
    text for a transport failure; ``url`` is the FULL fetched URL (the
    ref tail is percent-encoded back into it, ``safe="/"`` keeping the
    POSIX directory separators).  ``refs`` arrives sorted; the fetches
    happen in that order.

    ``deadline`` is the run's own budget, checked ONCE PER REF, because
    this loop dominates the command's wall time (a page with 10,000
    images is 10,000 round-trips, and the walk that found them is over in
    seconds).  An exhausted budget raises :class:`DeadlineExceeded` — a
    WptError — so the run ends through the same error contract as every
    other deadline: fail-closed teardown, rc 1, one clear line.  It is a
    FAILURE and never a "checked what was reachable so far" pass, because
    a re-check that stopped early is a set nobody verified.
    """
    ok_count = 0
    broken: list[tuple[str, str]] = []
    failed: list[tuple[str, str]] = []
    for ref in refs:
        if deadline is not None:
            deadline.check("verify re-check")
        url = f"{site}/wp-content/uploads/{quote(ref, safe='/')}"
        try:
            response = get_bounded(
                session, url, timeout_s=timeout_s,
                deadline=_http_budget(deadline, timeout_s),
                allow_redirects=False,
            )
        except (requests.RequestException, WptError) as exc:
            # A per-request transport timeout is a FAILED ref while the run
            # still has budget; a spent run budget raises DeadlineExceeded
            # through the same check (never a success report over refs the
            # loop stopped checking).
            if deadline is not None:
                deadline.check("verify re-check")
            failed.append((str(exc), url))
            continue
        status = response.status_code
        close = getattr(response, "close", None)
        if callable(close):
            close()
        if 200 <= status < 300:
            ok_count += 1
        else:
            broken.append((f"HTTP {status}", url))
    return ok_count, broken, failed


def _render(site: str, total: int, ok_count: int,
            broken: list[tuple[str, str]],
            failed: list[tuple[str, str]]) -> str:
    """The verification markdown report (its JSON twin is
    :func:`_render_json`).  The ``Broken references`` and
    ``Failed fetches`` sections appear only when non-empty."""
    lines = [
        f"# wpt verify — {site}",
        "",
        f"Re-checked {total} live references from a fresh walk of {site}.",
        "",
        "| result | count |",
        "|---|---|",
        f"| ok | {ok_count} |",
        f"| broken | {len(broken)} |",
        f"| failed | {len(failed)} |",
        "",
    ]
    if broken:
        lines.append("## Broken references")
        lines.append("")
        lines.extend(f"- {redact_text(label)} — {redact_text(url)}"
                     for label, url in broken)
        lines.append("")
    if failed:
        lines.append("## Failed fetches")
        lines.append("")
        lines.extend(f"- {redact_text(label)} — {redact_text(url)}"
                     for label, url in failed)
        lines.append("")
    return "\n".join(lines)


def _render_json(site: str, total: int, ok_count: int,
                 broken: list[tuple[str, str]],
                 failed: list[tuple[str, str]]) -> str:
    """The machine-readable twin of :func:`_render`: the site, the ref
    totals, and EVERY broken/failed ref as a ``{"label", "url"}`` pair
    — verify's OWN schema, not the audit's AuditReport shape.
    Formatted exactly like :func:`wpt.report.render_json` (utf-8,
    sorted keys, indent 2) so the report surfaces stay consistent."""
    return json.dumps(
        {
            "site": site,
            "total": total,
            "ok": ok_count,
            "broken": [{"label": redact_text(label), "url": redact_text(url)}
                       for label, url in broken],
            "failed": [{"label": redact_text(label), "url": redact_text(url)}
                       for label, url in failed],
        },
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    )
