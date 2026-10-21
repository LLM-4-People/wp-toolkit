"""wpt audit — the assembled entry point for the ``wpt audit`` command (W6h).

``wpt.cli`` dispatches the ``audit`` subcommand here via ``_lazy_call(ctx,
"wpt.audit", "run")``; :func:`run` is the ONE mode-agnostic entry point and
branches on ``ctx.mode``:

* local — :class:`~wpt.sources.zip.ZipSource` over ``ctx.zip`` plus the
  SQL dump at ``ctx.sql`` feed :func:`~wpt.audit.data.gather_local`.
* ftp  — :func:`remote_stack` builds the (source, session, bridge) trio
  (first sweeping any stale ``bridge-<8hex>.php`` a killed run left in
  the webroot — the sweep is part of the stack seam and its contract is
  documented on :func:`remote_stack`); an UNDEPLOYED bridge (it
  lazy-deploys on its first call, and
  ``gather_remote`` walks the tree BEFORE any bridge call, so the audit
  tree never contains our own bridge file) feeds
  :func:`~wpt.audit.data.gather_remote`, then the SiteProbe is attached
  (ftp mode only — local mode has no live site to probe).  The bridge is
  destroyed in a ``finally`` that spans gather, probe attach AND
  :func:`_emit`: the security checks run inside ``_emit`` and need the
  LIVE bridge (``fileperms``) and the source (wp-config.php read); a
  destroy before emit would systematically silence
  ``security.wp_config_perms``.  L6 hygiene holds either way: the bridge
  never outlives the run, and ``destroy()`` is idempotent / a no-op when
  the bridge was never deployed (a gather failure on the very first
  call).

The check modules (W6c–g) self-register through ``@register_check`` at
import time and the registry is importer-agnostic, so THIS package
imports them in one block: ``import wpt.audit`` alone leaves every landed
check registered — :func:`run` (which lives in this module and therefore
always runs after that block) can never see a half-empty registry.

Error contract (binding): every :class:`~wpt.types.WptError`
(SourceError / BridgeError / SettingsError / ...) plus ``OSError``
(a missing/unreadable ``--sql`` file; requests' RequestException
subclasses IOError == OSError, so even an unwrapped transport failure is
operational) is logged at error and answered with exit 1 — a traceback
NEVER escapes :func:`run`.

Logging: everything goes through ``get_logger("audit")`` and carries no
secrets — the FTP password flows ONLY into FtpSource; log lines carry
counts, byte totals and exception messages (redacted at handler level by
wpt.log), never report bodies.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import requests

from ..config import redact_text
from ..deadline import Deadline
from ..dnsoverride import resolve_session
from ..jsonutil import loads_bounded
from ..log import get_logger
from ..remote import ftp_source_for
from ..report import (AuditReport, human_bytes, render_json, render_report,
                      report_protected_inputs, report_protected_subtrees,
                      report_refreshable_inputs, safe_text,
                      site_facts, write_report_files)
from ..report import write_stdout
from ..sources.base import close_source
from ..sources.ftp import FtpSource
from ..sources.zip import ZipSource
from ..teardown import source_cleanup_budget
from ..types import (DeadlineExceeded, RunControl, Source, SourceError,
                     StopRequested, WptError)
from ..walk import walk_site
from ..wpbridge.client import Bridge
from ..bridge_name import is_bridge_file
from ..endpoint import sweep_expired_endpoints
from .data import AuditData, gather_local, gather_remote
from .registry import run_checks, validate_selectors
from .security import SiteProbe

# The check modules register via @register_check at import time; importing
# them here (one block) is the registration seam — see module docstring.
from . import dbcheck, integrity, media, security, source_scan, suspicious, updates, webroot  # noqa: F401

if TYPE_CHECKING:
    # Ctx is annotation-only. A top-level runtime `from ..cli import Ctx`
    # would also work (cli lazy-calls this module, so there is no import
    # cycle — verified: `python -c "import wpt.audit"` standalone), but the
    # lazy call contract means cli is always fully imported before run()
    # executes, so the annotation-only import is the clean choice.
    from ..cli import Ctx

__all__ = [
    "run",
    "AuditData",
    "SiteProbe",
    "gather_local",
    "gather_remote",
    "run_checks",
]

log = get_logger("audit")

# The deployed bridge filename contract, mirrored from wpt/wpbridge/
# client.py's Bridge.ensure: "bridge-" + 8 LOWERCASE hex chars + ".php",
# written at the TOP of the webroot (Bridge._endpoint is webroot-relative,
# so the deployed name is a bare root-level filename). remote_stack's
# stale-file sweep matches this EXACT shape and nothing else — any other
# "bridge-*.php" (bridge-notours.php, a 7-hex bridge-1234567.php, an
# uppercase name) is NOT ours and is never touched.
#: The embedded TTL literal every deployed bridge carries (bridge.php's
#: ``$wpt_expires = '<unix-ts>';``): the ONE authoritative signal that
#: distinguishes a dead leftover (expiry passed — the bridge's own token
#: gate already refuses EVERYTHING, including selfdestruct) from the
#: ACTIVE bridge of a concurrently running sibling wpt process (expiry
#: still in the future). A sibling run may NEVER delete a live run's
#: substrate (rule 10) — the sweep is expiry-aware, not name-blind.
#: The literal is parsed by ``bridge_name.endpoint_expiry`` (shared with
#: the probe sweep).

#: The stale-bridge sweep's read bound.  The packaged bridge.php is roughly
#: 215 KiB; a matching name carrying more than 1 MiB is not ours to parse,
#: and the old unbounded ``read_bytes`` held a 5 MiB file whole on every ftp
#: command.
_BRIDGE_READ_LIMIT = 1024 * 1024


def run(ctx: Ctx) -> int:
    """Run the full audit for ``ctx``'s source mode; 0 on success, 1 on failure.

    Both modes end in :func:`_emit` (checks + report).  Any WptError or
    OSError from the stack is logged at error and answered with 1 — run()
    never raises and never lets a traceback reach the CLI.

    A FAILED run writes the report it could: the audit report's own shape
    with zero findings and one line naming the failure, through
    ``wpt.actions.registry.write_failure_report`` (the same writer every
    other ``--report`` surface shares, reached by a function-level import
    because this module sits UPSTREAM of the actions registry in the
    import graph).  Measured across 21 commands before this: every success
    wrote markdown + JSON and every failure wrote nothing, so a caller
    could not tell "the audit found nothing" from "the audit never got far
    enough" — the same absence, read two ways.
    """
    source = None
    session = None
    bridge = None
    first_stop: BaseException | None = None
    rc = 1
    try:
        # a typo'd / mode-inapplicable --only/--skip selector fails HERE,
        # in seconds — never after the (expensive) gather
        validate_selectors(ctx.mode,
                           ctx.extra.get("only"), ctx.extra.get("skip"))
        # Build the budget BEFORE the gather, so a slow walk/dump/bridge call
        # cannot outlive --deadline and still return rc 0 (R6-34).
        deadline = Deadline.from_ctx(ctx)
        if ctx.mode == "local":
            if ctx.zip is None or ctx.sql is None:
                raise SourceError("local mode requires both --zip and --sql")
            source = ZipSource(ctx.zip, deadline=deadline)
            with open(ctx.sql, "rb") as dump:
                data = gather_local(dump, source, ctx.settings,
                                    deadline=deadline)
            data.deadline = deadline
            _emit(ctx, data, deadline)
        else:
            source, session, bridge = remote_stack(ctx)
            data = gather_remote(bridge, source, ctx.settings,
                                 deadline=deadline)
            data.deadline = deadline
            data.probe = SiteProbe(
                session=session,
                site=ctx.wp_url or "",
                bridge=bridge,
                source=source,
                timeout_s=ctx.settings.http.timeout_s,
                max_response_bytes=ctx.settings.http.max_response_bytes,
                override_ip=ctx.override_ip,
            )
            # The live walk feeds the media + https-redirect checks.
            # Imported into THIS namespace so tests can patch
            # wpt.audit.walk_site. A failed walk degrades the audit
            # (live_refs stays None — media checks go silent, never
            # guess); a walk finding ZERO refs is a real result.  A
            # SIGTERM/run-deadline is a RunControl BaseException, so the
            # (WptError, OSError) handler below cannot swallow it.
            try:
                walked = walk_site(session, ctx.wp_url or "",
                                   ctx.settings.walk,
                                   ctx.settings.http.timeout_s,
                                   deadline=deadline)
                data.live_refs = walked.live_refs
                data.pages = walked.pages
            except (WptError, OSError) as exc:
                log.warning("live walk failed; media/https findings "
                            "degraded: %s", exc)
            _emit(ctx, data, deadline)
        rc = 0
    except RunControl as exc:
        # The audit owns its report family: answer a stop/deadline with the
        # SAME shared failure pair every operational failure writes.
        log.error("audit stopped: %s", redact_text(str(exc)))
        _write_failure(ctx, f"audit stopped: {exc}")
        rc = 1
    except (WptError, OSError) as exc:
        log.error("audit failed: %s", exc)
        _write_failure(ctx, str(exc))
        rc = 1
    finally:
        # The command OWNS the stack it built: destroy the bridge, close
        # the source (local ZipSource included — its archive handle stayed
        # open) and the HTTP pool.  A cooperative stop during teardown is a
        # run-ending event, never a swallowed warning.
        with source_cleanup_budget(source):
            if bridge is not None:
                try:
                    bridge.destroy()
                except (StopRequested, DeadlineExceeded) as exc:
                    first_stop = first_stop or exc
                except Exception as exc:  # noqa: BLE001 — teardown is best-effort
                    log.warning("audit: bridge destroy failed: %s", exc)
            if source is not None:
                try:
                    close_source(source, "audit")
                except (StopRequested, DeadlineExceeded) as exc:
                    first_stop = first_stop or exc
        if session is not None:
            close = getattr(session, "close", None)
            if callable(close):
                try:
                    close()
                except (StopRequested, DeadlineExceeded) as exc:
                    first_stop = first_stop or exc
                except Exception as exc:  # noqa: BLE001
                    log.warning("audit: session close failed: %s", exc)
    if first_stop is not None:
        reason = f"audit: teardown stopped: {first_stop}"
        log.error("%s", reason)
        if rc == 0:
            # A success pair is already on disk; rc 1 must not sit beside a
            # report that claims the audit completed.  Replace it exactly
            # like restore/walk/verify's teardown-stop contract.
            _write_failure(ctx, reason)
        rc = 1
    return rc


def _write_failure(ctx: Ctx, reason: str) -> None:
    """The report of an audit run that measured nothing, through the ONE
    ``--report`` writer every command shares.

    Best-effort by construction (a report that cannot be written is the
    caller's own filesystem problem, and the run's verdict is already
    logged): this runs on the way out of a FAILED run, so it must never
    raise over the failure it is reporting.
    """
    from ..actions.registry import write_failure_report

    try:
        # The same site the audit's own header names (netloc, so no
        # userinfo can ride into a file).
        site = (ctx.wp_url or urlparse(ctx.source or "").netloc
                or "unknown")
        write_failure_report(ctx, "audit", reason,
                             audit=AuditReport(
                                 site=site,
                                 source_summary=f"audit ({ctx.mode}) — "
                                                "the run did not complete"))
    except (Exception, RunControl) as exc:  # noqa: BLE001 — reporting must not raise
        log.warning("audit: could not write the failure report: %s", exc)


def remote_stack(ctx: Ctx) -> tuple[Source, requests.Session, Bridge]:
    """Build the ftp-mode trio ``(source, session, bridge)`` — the ONE
    construction seam (tests monkeypatch this function to fake the remote
    side end-to-end).

    * source — ``FtpSource`` for the ``ftp://host[:port]`` in
      ``ctx.source``; an explicit ``:port`` overrides ``settings.ftp.port``
      via ``replace()`` (the profile's timeout/retries are kept), no port
      keeps the profile value.  Credentials flow from ctx straight into
      FtpSource and nowhere else.
    * session — ``resolve_session`` output when ``ctx.override_ip`` is set
      (the DNS-override transport; ``settings.http.verify_tls`` and
      ``timeout_s`` apply HERE), else a plain ``requests.Session`` with
      nothing mounted.  Note: the plain session keeps requests' own
      defaults — ``verify_tls`` is NOT applied to it (coordinator-pinned;
      a deviation from wpt.audit.security's docstring, reported there) —
      which is acceptable because every bridge / SiteProbe / wp.org call
      passes an explicit timeout, and requests verifies TLS by default
      anyway.
    * bridge — built but NOT deployed: the Bridge lazy-deploys on its
      first call and ``gather_remote`` walks the tree before that call.

    Stale-bridge sweep (ftp-mode only — local stacks are zips, nothing
    to sweep, and the local branch never builds through this seam):
    right after the source is built, ONE ``list_dir("")`` of the webroot
    root; every plain FILE whose path matches the deployed-BRIDGE name
    contract ``bridge-<8hex>.php`` (``bridge_name.BRIDGE_NAME_RE``, the exact
    name shape ``Bridge.ensure`` deploys — ``Bridge._endpoint`` is
    webroot-relative, so our bridge files sit at the root) is EXAMINED and
    deleted ONLY
    once its own embedded expiry literal (``$wpt_expires =
    '<unix-ts>';``) has passed: a SIGKILL'd or crashed run leaves its
    deployed bridge file behind — dead once the TTL gate refuses
    everything, but persistent — while a file whose expiry is still in
    the future may be the ACTIVE bridge of a CONCURRENT sibling wpt run
    and is never touched (rule 10: a sibling may not terminate a live
    run's substrate; an unreadable/unparseable candidate is likewise
    left in place, never deleted unverified). Every ftp command builds
    its stack through THIS seam, so every ftp command inherits the
    sweep. The sweep runs BEFORE any deployment of OUR
    bridge (the Bridge above is lazy and first deploys on a call made
    after this function returns), so it can never remove our own file —
    the audit's walk-before-deploy guarantee is untouched. A non-matching
    ``bridge-*.php`` is NOT ours and is never touched. The ``list_dir``
    failure contract is the normal stack contract (a SourceError
    propagates, same as any stack failure); a DELETE failure is a
    WARNING only, never a stack failure — a stuck stale file must not
    block the command, and the TTL gate already neutralized it.
    """
    source = ftp_source_for(ctx, source_cls=FtpSource)

    def close_on_failure() -> None:
        """Close a source this seam built but is about to abandon."""
        try:
            source.close()
        except (Exception, RunControl):
            pass

    # The stale-bridge sweep — see the docstring paragraph. It sits here,
    # in the ONE construction seam, so every ftp command inherits it, and
    # before the return, i.e. strictly before the lazy Bridge can deploy
    # OUR file. The delete wrap must be Exception-wide, not (WptError,
    # OSError): FtpSource.delete can re-raise a raw ftplib.error_perm
    # (a non-550 permission refusal — exactly the stuck-file case), which
    # run()'s contract would let escape as a traceback.
    try:
        stale = [entry for entry in source.list_dir("")
                 if not entry.is_dir and not entry.is_link
                 and is_bridge_file(entry.path)]
    except (Exception, RunControl):
        # A source constructed here is OWNED here until the trio is
        # returned.  A failure — including a stop/deadline (RunControl is
        # a BaseException, so a plain ``except Exception`` would leak it) —
        # must not leak the FTP control session: doctor's `source` stays
        # None on this raise, so it cannot close what it never received.
        close_on_failure()
        raise
    sweep_expired_endpoints(
        source, stale, kind="bridge",
        matches=is_bridge_file,
        read_limit=_BRIDGE_READ_LIMIT,
        on_stop=close_on_failure,
        logger=log,
        delete_label="stale",
    )
    try:
        try:
            site_url = urlparse(ctx.wp_url or "")
            hostname = site_url.hostname
            # The dial port follows the URL SCHEME: https defaults to 443,
            # http to 80.  Hard-coding 443 sent an http:// override to the
            # TLS port and silently ignored the override (R15-P2).
            port = site_url.port or (
                443 if site_url.scheme == "https" else 80)
        except (TypeError, ValueError) as exc:
            # urlparse raises ValueError for an invalid IPv6 literal
            # (``https://[::1``) and for an out-of-range port; it is an
            # operator input refusal, never a traceback out of remote_stack
            # with no report pair (C5).
            raise SourceError(
                "--wp-url is malformed (expected https://host[:port])"
            ) from exc
        if ctx.override_ip:
            if not hostname:
                raise SourceError(
                    "--override-ip requires --wp-url with a hostname")
            session: requests.Session = resolve_session(
                hostname=hostname,
                ip=ctx.override_ip,
                port=port,
                verify=ctx.settings.http.verify_tls,
                timeout=ctx.settings.http.timeout_s,
            )
        else:
            session = requests.Session()
    except (Exception, RunControl):
        close_on_failure()
        raise
    try:
        deadline = Deadline.from_ctx(ctx)
        bridge = Bridge(source, session, ctx.webroot or "",
                        ctx.settings.bridge, ctx.wp_url or "",
                        deadline=deadline.at if deadline is not None else None)
    except (Exception, RunControl):
        close_on_failure()
        try:
            session.close()
        except (Exception, RunControl):
            pass
        raise
    # Ownership hands off ONLY on a completed return.  A stop landing at the
    # return itself (the handler runs between bytecodes) still unwinds
    # through this finally, which closes everything the seam built.
    try:
        return source, session, bridge
    finally:
        if sys.exc_info()[0] is not None:
            close_on_failure()
            try:
                session.close()
            except (Exception, RunControl):
                pass
            destroy = getattr(bridge, "destroy", None)
            if callable(destroy):
                try:
                    destroy()
                except (Exception, RunControl):
                    pass


#: The compared fields, in the order the shape tuple stores them. The labels
#: are the ONLY way the markdown can say what actually changed.
_DIFF_FIELDS = ("detail", "count", "risk", "bytes")


def _baseline_diff(findings, baseline_path) -> tuple[list[str], list[str],
                                                       dict[str, list[str]]]:
    """(new, resolved, changed-fields-per-key) vs a previous report's JSON
    twin.

    The baseline is the .json artifact of an earlier ``wpt audit
    --report`` run. A finding's PRESENCE identity is its ``category/name``
    pair; its DETAIL is compared too: a key present in both runs with a
    different detail is CHANGED (live lesson: deactivating litespeed-cache
    grew the ``plugins.inactive`` finding's detail — an identity-only diff
    answered "No changes" to a diff question). An unreadable/malformed
    baseline is an OPERATIONAL error (WptError — a wrong comparison basis
    must never pass silently as "no changes").
    """
    try:
        payload = loads_bounded(
            Path(baseline_path).read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError, MemoryError) as exc:
        # A deeply nested baseline exhausts the C decoder's recursion limit
        # (RecursionError is not a ValueError) and escaped run() as a
        # traceback with no report; it is the same malformed-baseline
        # operational refusal.
        raise WptError(
            f"--baseline report unreadable: {baseline_path}: "
            f"{type(exc).__name__}") from exc
    base_entries = payload.get("findings") if isinstance(payload, dict) else None
    if not isinstance(base_entries, list):
        raise WptError(
            f"--baseline is not a wpt audit JSON report: {baseline_path}")

    def _key(cat, name):
        return f"{cat}/{name}"

    def _by_key(items, cat_get, name_get, shape_get):
        maps: dict[str, list[tuple]] = {}
        for index, item in enumerate(items):
            try:
                cat, name, shape = cat_get(item), name_get(item), shape_get(item)
            except (KeyError, TypeError) as exc:
                # A baseline entry that is not a finding object is a CORRUPT
                # baseline, not an absent one: skipping it would report every
                # current finding as new and answer a diff question wrongly.
                raise WptError(
                    f"--baseline finding #{index} is malformed: {exc}"
                ) from exc
            if not isinstance(cat, str) or not isinstance(name, str):
                raise WptError(
                    f"--baseline finding #{index} needs string category/name")
            maps.setdefault(_key(cat, name), []).append(shape)
        return {key: sorted(shapes) for key, shapes in maps.items()}

    def _finding_shape(finding):
        """Everything a reader would act on: identity plus magnitude.

        Comparing DETAIL alone hid a finding that got worse: a doubled row
        count, a risk that rose from medium to high, or reclaimable bytes that
        grew all reported "no changes". `fix` is prose and is deliberately not
        part of the shape.
        """
        return (
            finding.detail,
            finding.count,
            finding.risk,
            finding.bytes,
        )

    def _entry_shape(entry):
        # A baseline entry that omits an optional field means the Finding
        # DEFAULT, not a zero: `{"category","name","detail"}` describes the
        # same finding as Finding(cat, name, detail) with count=1, risk=low.
        detail = entry.get("detail", "")
        risk = entry.get("risk", "low")
        count = entry.get("count", 1)
        size = entry.get("bytes", 0)
        for label, value, expected in (("detail", detail, str),
                                       ("count", count, int),
                                       ("risk", risk, str),
                                       ("bytes", size, int)):
            if not isinstance(value, expected) or isinstance(value, bool) \
                    and expected is not bool:
                raise WptError(
                    f"--baseline finding field {label!r} must be "
                    f"{expected.__name__}, got {type(value).__name__}")
        return (detail, count, risk, size)

    current = _by_key(findings,
                      lambda f: f.category, lambda f: f.name, _finding_shape)
    base = _by_key(base_entries,
                   lambda e: e["category"], lambda e: e["name"], _entry_shape)
    new_keys = sorted(set(current) - set(base))
    resolved_keys = sorted(set(base) - set(current))
    changed: dict[str, list[str]] = {}
    for key in sorted(set(current) & set(base)):
        now, before = current[key], base[key]
        if now == before:
            continue
        labels: set[str] = set()
        if len(now) != len(before):
            labels.add("finding set")
        for shape_now, shape_before in zip(now, before):
            labels.update(
                name for name, a, b in zip(_DIFF_FIELDS, shape_now, shape_before)
                if a != b
            )
        changed[key] = sorted(labels) or ["finding set"]
    return new_keys, resolved_keys, changed


def _emit(ctx: Ctx, data: AuditData,
          deadline: Deadline | None = None) -> str:
    """Run the selected checks over ``data`` and emit the report.

    ``ctx.extra["only"]`` / ``["skip"]`` (the audit subcommand's
    ``--only`` / ``--skip``) flow to ``run_checks`` unchanged.  Output:
    with ``ctx.report_path`` the markdown is written there and the JSON
    twin to ``report_path.with_suffix(".json")``; without it the markdown
    is written to stdout through the shared ``wpt.report.write_stdout``
    sink (the report IS the command's stdout surface).
    One info summary (findings count + reclaimable bytes) is ALWAYS
    logged.  Returns the markdown string.
    """
    if deadline is not None:
        deadline.check("audit emit")
    findings = run_checks(
        data, ctx.settings, ctx.mode, ctx.extra.get("only"),
        ctx.extra.get("skip"), deadline=deadline
    )
    if deadline is not None:
        deadline.check("audit report")
    if ctx.mode == "local":
        # ctx.zip / ctx.sql are validated non-None before the gather (run).
        site = safe_text(ctx.wp_url or f"local:{ctx.zip.name}")
        source_summary = safe_text(f"zip:{ctx.zip.name} + {ctx.sql.name}")
    else:
        netloc = urlparse(ctx.source).netloc
        site = safe_text(ctx.wp_url or netloc)
        source_summary = safe_text(f"ftp://{netloc}")
    report = AuditReport(
        site=site,
        source_summary=source_summary,
        findings=findings,
        totals={"entries": len(data.entries), "mode": data.mode},
        site_facts=site_facts(data),
    )
    markdown = render_report(report)
    diff = None
    baseline = ctx.extra.get("baseline")
    if baseline is not None:
        new_keys, resolved_keys, changed = _baseline_diff(findings, baseline)
        changed_keys = sorted(changed)
        diff = {"new": new_keys, "resolved": resolved_keys,
                "changed": changed_keys}
        if new_keys or resolved_keys or changed_keys:
            markdown += "\n## Changed since baseline\n\n"
            markdown += "".join(f"- NEW: {k}\n" for k in new_keys)
            markdown += "".join(f"- resolved: {k}\n" for k in resolved_keys)
            markdown += "".join(
                f"- changed: {k} ("
                + (f"{changed[k][0]} changed" if len(changed[k]) == 1
                   else f"{', '.join(changed[k])} changed")
                + " since the baseline)\n"
                for k in changed_keys
            )
        else:
            markdown += "\n## Changed since baseline\n\nNo changes — the " \
                        "finding set is identical.\n"
        log.info("audit vs baseline: %d new, %d resolved, %d changed",
                 len(new_keys), len(resolved_keys), len(changed_keys))
    if ctx.report_path is not None:
        json_payload = json.loads(render_json(report))
        if diff is not None:
            json_payload["diff"] = diff
        write_report_files(
            ctx.report_path, markdown,
            json.dumps(json_payload, ensure_ascii=False, sort_keys=True,
                       indent=2) + "\n",
            protected_paths=report_protected_inputs(ctx),
            refreshable_paths=report_refreshable_inputs(ctx),
            protected_subtrees=report_protected_subtrees(ctx),
        )
    else:
        write_stdout(markdown)
    log.info(
        "audit: %d findings, %s reclaimable",
        len(findings), human_bytes(report.reclaimable_bytes()),
    )
    return markdown
