"""Action registry — the extension surface for every mutating command.

SPEC §Framework registries: actions are ``@register_action("clean-files",
applies=[...])`` decorated objects; the CLI dispatches through this
registry, not a hardcoded map. An action implements two phases:

* ``plan(ctx) -> Plan`` — the dry-run inventory (read-only; what WOULD be
  removed/changed, with per-target PlanItems).
* ``apply(ctx, plan) -> Plan`` — execute the plan's items, marking each
  PlanItem ``done`` as it lands.

:func:`run_action` owns EVERYTHING the phases share, so an action body is
pure domain logic:

1. mode applicability (registered ``applies``),
2. plan phase (errors -> exit 1, no traceback),
3. dry-run boundary (``--apply`` absent -> print the plan, exit 0),
4. local-mode write refusal (D5: local v1 is audit-only; zip rewriting is
   v2 — --apply on a zip exits 1 with a clear message),
5. confirmation (``--yes`` skips it; otherwise an interactive tty prompt;
   a non-tty without --yes refuses),
6. the fail-closed pre-action backup (scope derived from the plan: file
   targets vs ``db.``-prefixed table targets; any snapshot failure aborts
   the apply — never mutate unbacked),
7. apply phase,
8. the post-apply cache purge (ftp mode only, best-effort hygiene: the
   still-deployed bridge is asked exactly once to ``purge_cache`` —
   without it LiteSpeed/W3TC/WP Super Cache keep serving stale pages
   and the operator sees "no change"; a purge failure is ONE warning,
   never an rc change),
9. result printing.

The run's plan is rendered in ONE place (:func:`_emit`), so
``--report out.md`` — the universal contract the audit, verify, doctor,
walk, backup and restore paths honour — can never be accepted and
silently ignored by an action or by the deploy dry run: whatever this
registry prints is also written there, in the same markdown shape (plan
table, totals) the audit report uses, and the file is created even for an
empty plan so a caller can trust its presence [D2].  The written report
carries the plan ONLY: a credential an action prints on stdout (users
_reset's generated passwords) is never part of a PlanItem and can never
reach the file.

A run that produced NO plan still writes a report (:func:`_refuse` →
:func:`write_failure_report`): the audit report's own shape with zero
findings, zero planned items, and one line naming the refusal.  That is
what makes the file's PRESENCE informative — before it, every failure
wrote nothing, so "the run planned nothing" and "the run never got far
enough" were the same absence on disk, and the refusal a caller most
wants to read was the one never written.  The reason crosses the same
redaction chokepoint every log line does, so a ``users_reset`` credential
can reach neither.

Error contract mirrors wpt.audit.run: WptError/OSError -> log.error +
exit 1, never a traceback.
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TYPE_CHECKING, Protocol

from ..backup import (create_snapshot, require_distinct_snapshot_names,
                     require_snapshot_tables, site_label)
from ..bridge_name import is_wpt_endpoint_file
from ..config import redact_text
from ..deadline import Deadline, transport_kwargs
from ..log import get_logger
from ..report import (Plan, render_json, render_report,
                      record_snapshot_root, report_protected_inputs,
                      report_protected_subtrees, write_report_files)
from ..report import write_stdout
from ..types import DeadlineExceeded, RunControl, StopRequested, WptError

if TYPE_CHECKING:
    from ..cli import Ctx

__all__ = ["Action", "ActionRecord", "register_action", "get_action",
           "run_action", "all_actions", "failure_report", "not_complete",
           "write_report", "write_failure_report"]

log = get_logger("actions")

MODES = ("ftp", "local")


class Action(Protocol):
    """The two-phase contract every action implements.

    ``stack`` is the command's ONE ``(source, session, bridge)`` trio,
    built by the registry before the plan phase and destroyed after the
    apply phase — actions never build their own.  Local mode's stack is
    ``(ZipSource, None, None)``; ftp mode's is audit's ``remote_stack``.
    """

    def plan(self, ctx: "Ctx", stack: tuple) -> Plan: ...

    def apply(self, ctx: "Ctx", stack: tuple, plan: Plan) -> Plan: ...


@dataclass(frozen=True)
class ActionRecord:
    name: str
    applies: tuple[str, ...]
    action: Action


_ACTIONS: dict[str, ActionRecord] = {}


def register_action(name: str, applies: tuple[str, ...] | list[str]):
    """Decorate an action class/module under its CLI command name.

    Duplicate names fail at import time (RuntimeError); unknown modes and
    empty names fail at decoration (ValueError).
    """
    if not isinstance(name, str) or not name:
        raise ValueError(f"invalid action name: {name!r}")
    if name in _ACTIONS:
        raise RuntimeError(f"duplicate action name: {name!r}")
    applies = tuple(applies)
    if not applies or any(mode not in MODES for mode in applies):
        raise ValueError(f"invalid applies for {name!r}: {applies!r}")

    def decorate(action: Action) -> Action:
        _ACTIONS[name] = ActionRecord(name=name, applies=applies, action=action)
        return action

    return decorate


def all_actions() -> list[ActionRecord]:
    """Every registered action, registration order (deterministic)."""
    return list(_ACTIONS.values())


def get_action(name: str) -> ActionRecord | None:
    return _ACTIONS.get(name)


def confirm(ctx: "Ctx") -> bool:
    """Interactive confirmation unless --yes; non-tty without it refuses.

    The canonical mutating-command gate (actions AND the restore CLI
    body share it): ``--yes`` answers yes; without a tty an ``--apply``
    run REFUSES (no silent blind approvals); on a tty the operator must
    answer y/yes to proceed.
    """
    if ctx.yes:
        return True
    if not sys.stdin.isatty():
        log.error("--apply requires --yes when stdin is not a terminal")
        return False
    try:
        answer = input("Proceed? [y/N] ")
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")


def run_action(ctx: "Ctx", name: str) -> int:
    """The shared command flow; 0 success, 1 operational failure, 2 unknown.

    The action body runs in :func:`_execute_action`; THIS function owns the
    stack teardown so EVERY exit path (dry run, refusal, apply success or
    failure) observes a teardown stop.  A ``StopRequested``/``DeadlineExceeded``
    raised by ``bridge.destroy()`` or ``source.close()`` is remembered,
    BOTH cleanups still run, and the run ends rc 1 with the failure report —
    the old ``except Exception`` only warned and returned 0 after SIGTERM
    (R6-35).  Generic teardown errors stay warnings.
    """
    record = get_action(name)
    if record is None:
        log.error("no such action: %s", name)
        return 2
    if ctx.mode not in record.applies:
        return _refuse(
            ctx, name,
            f"{name} applies to {'/'.join(record.applies)} mode(s) only "
            f"(source is {ctx.mode})", status="refused")
    # ONE budget for the action, built BEFORE the stack/plan/scope pre-work.
    # Every later Deadline.from_ctx(ctx) returns this same instance.
    deadline = Deadline.from_ctx(ctx)
    try:
        if deadline is not None:
            deadline.check(f"{name} setup")
        # Stack construction INSIDE the error contract: a bad --zip or an
        # unparseable ftp:// URL must exit 1 cleanly, never traceback.
        stack = _stack(ctx)
    except RunControl as exc:
        return _run_control(ctx, name, exc)
    except (WptError, OSError) as exc:
        return _refuse(ctx, name, f"{name}: source setup failed: {exc}")
    stop: BaseException | None = None
    try:
        rc = _execute_action(ctx, name, record, stack, deadline)
    except RunControl as exc:
        # The action body (plan/apply/snapshot/emit) hit SIGTERM or the run
        # deadline.  The finally teardown still runs, then rc 1 with the
        # shared failure pair.  No per-site re-raise is needed: RunControl is
        # a BaseException, so no (WptError, OSError) branch can have eaten it.
        stop = exc
        rc = None
    finally:
        teardown_stop = _teardown_action(name, stack)
        if stop is None:
            stop = teardown_stop
    if rc is None:
        return _run_control(ctx, name, stop)
    if stop is not None:
        # Remember the stop and end rc 1 — but never OVERWRITE the reason of
        # a primary failure that already answered: the report on disk (and
        # the operator's diagnosis) must name the plan/apply failure, with
        # the teardown stop logged beside it (R6-46).  On an otherwise
        # successful run the teardown stop IS the failure, so it writes the
        # report itself (R6-35).
        teardown_reason = f"{name}: teardown stopped: {stop}"
        log.error("%s", redact_text(teardown_reason))
        if rc == 0:
            _safe_failure_report(ctx, name, teardown_reason)
        else:
            log.error("%s: the primary failure above stays the run's reason "
                      "(rc %d); the failure report was not replaced",
                      name, rc)
        return 1
    return rc


def _teardown_action(name: str, stack: tuple) -> BaseException | None:
    """Run bridge/source/session cleanups through the ONE teardown owner."""
    from ..teardown import teardown_stack

    return teardown_stack(stack, name)


def _execute_action(ctx: "Ctx", name: str, record: ActionRecord,
                    stack: tuple, deadline: Deadline | None = None) -> int:
    """The action's plan/apply/report body once the stack exists."""
    source = stack[0]
    bridge = stack[2]
    try:
        plan = record.action.plan(ctx, stack)
    except (WptError, OSError) as exc:
        return _refuse(ctx, name, f"{name} plan failed: {exc}")
    # The plan phase may have swallowed a DeadlineExceeded itself (integrity's
    # partial classification does) and returned a partial plan.  Re-check the
    # SAME memoized budget here: an expired run must never proceed to a plan
    # report, a confirmation or an apply.
    if deadline is not None:
        deadline.check(f"{name} plan")
    if not ctx.apply:
        rc = _emit(ctx, name, plan)
        if rc:
            return rc
        log.info("%s: dry run — %d items, %s estimated (pass --apply to execute)",
                 name, len(plan.items), _plan_bytes(plan))
        return 0
    if not confirm(ctx):
        return _refuse(ctx, name, f"{name}: aborted by the operator",
                       status="refused", level=logging.INFO)
    if ctx.mode == "local":
        # LOCAL REHEARSAL: the stack is a MutableZipSource — the apply
        # stages in memory over the read-only view and the ORIGINAL zip
        # is never touched, so it IS the rollback (no snapshot needed).
        # After a successful apply the overlay materializes as a NEW
        # zip beside the original: <stem>-rehearsed-<YYYYmmdd-HHMMSS>.
        try:
            applied = record.action.apply(ctx, stack, plan)
        except (WptError, OSError) as exc:
            return _refuse(ctx, name, f"{name} apply failed: {exc}")
        # Completion is decided BEFORE materialization: an incomplete
        # rehearsal must not produce an archive the operator could mistake
        # for a clean dry run.
        pending = [i for i in applied.items if i.requires_apply]
        if not all(i.done for i in pending):
            rc = _emit(ctx, name, applied)
            done = sum(1 for i in pending if i.done)
            log.error("%s: %d/%d applicable item(s) were not applied",
                      name, done, len(pending))
            return rc or 1
        try:
            rehearsal = _rehearsal_path(ctx)
            # The archive is this run's deliverable.  Record the EXACT path
            # before it exists so the shared report writer refuses to replace
            # it (the path is timestamp-derived and cannot be known at the
            # CLI's pre-dispatch gate).
            _record_protected_output(ctx, rehearsal)
            materialized = source.materialize(
                rehearsal,
                stale_temp_age_s=ctx.settings.backup.stale_temp_age_s)
        except (WptError, OSError) as exc:
            return _refuse(
                ctx, name,
                f"{name}: rehearsal materialization failed (the original "
                f"zip is untouched): {exc}")
        rc = _emit(ctx, name, applied)
        pending = [i for i in applied.items if i.requires_apply]
        done = sum(1 for i in pending if i.done)
        log.info("%s: rehearsed %d/%d items; cleaned copy at %s",
                 name, done, len(pending), materialized)
        # Same contract as the real apply: a refused item is a failure, and
        # a "rehearsal succeeded" report over an incomplete plan is a lie
        # the operator will act on.
        return rc or (0 if all(i.done for i in pending) else 1)
    # None = action did not scope (derive from db.-prefixed item targets);
    # [] = deliberately no tables (e.g. optimize-only mutates no rows).
    if plan.backup_tables is not None:
        table_targets = plan.backup_tables
    else:
        table_targets = [i.target for i in plan.items
                         if i.requires_apply
                         and i.category.startswith("db.")]
    inspected_roots: list[Path] = []
    try:
        snapshot = create_snapshot(
            source=source,
            bridge=bridge if table_targets else None,
            site_label=site_label(ctx),
            targets=_backup_file_scope(source, plan, deadline),
            tables=require_snapshot_tables(table_targets),
            backup_dir=ctx.backup_dir,
            settings=ctx.settings.backup,
            action=name,
            site_raw=site_label(ctx),
            webroot=ctx.webroot or "",
            deadline=deadline,
            snapshot_roots=inspected_roots,
        )
    except RunControl as exc:
        # A stop/deadline during the pre-action capture still ends rc 1
        # with the failure pair; the phase name stays in the operator's
        # diagnosis exactly like the operational-failure branch below.
        for root in inspected_roots:
            record_snapshot_root(ctx, root)
        return _refuse(ctx, name,
                       f"{name}: pre-action backup failed ({exc}); "
                       f"refusing to apply")
    except (WptError, OSError) as exc:
        for root in inspected_roots:
            record_snapshot_root(ctx, root)
        return _refuse(ctx, name,
                       f"{name}: pre-action backup failed ({exc}); "
                       f"refusing to apply")
    # The action's own pre-action snapshot is a protected INPUT of the rest
    # of this run: the apply report (or a failure writer) must never replace
    # a manifest/payload beneath the rollback basis it just created.
    ctx.extra.setdefault("snapshot_dir", str(snapshot.path))
    for root in inspected_roots:
        record_snapshot_root(ctx, root)
    record_snapshot_root(ctx, snapshot.path)
    try:
        applied = record.action.apply(ctx, stack, plan)
    except (WptError, OSError) as exc:
        return _refuse(ctx, name, f"{name} apply failed after backup "
                                  f"{snapshot.path}: {exc}")
    # An item the action refused (done=False after its own recovery) is an
    # operational failure: nothing was hardened for it, so the post-apply
    # cache purge (which exists to make a SUCCESSFUL change visible) must
    # not fire and rc must not report success.  Only requires_apply items
    # count: advice items are never applied and stay done=False by design.
    pending = [i for i in applied.items if i.requires_apply]
    complete = all(i.done for i in pending)
    if not complete:
        log.error("%s: %d/%d applicable item(s) were not applied; "
                  "not purging cache",
                  name, sum(1 for i in pending if i.done), len(pending))
    # Post-apply hygiene: ask the still-deployed bridge to purge the
    # site's page cache (exactly once per successful apply) — the
    # operator would otherwise see "no change" until it expires.
    # Best-effort by contract: ANY failure is one warning; the
    # changes ARE applied, so rc and report must not move.  The
    # except stays tight around the call — a purge bug must never
    # mask a successful apply.
    if bridge is not None and complete:
        try:
            purged = bridge.call(
                "purge_cache", **transport_kwargs(deadline))
        except (StopRequested, DeadlineExceeded) as exc:
            # A cooperative stop during post-apply hygiene is a run-ending
            # event, not a warning: the changes are already applied, but
            # SIGTERM/deadline must end rc 1 with its own failure report.
            return _refuse(
                ctx, name,
                f"{name}: stopped during the post-apply cache purge: {exc}")
        except Exception as exc:
            log.warning("%s: cache purge failed (changes ARE applied; "
                        "stale pages may persist until the cache "
                        "expires): %s", name, exc)
        else:
            log.debug("%s: post-apply cache purge: %s", name, purged)
    rc = _emit(ctx, name, applied)
    pending = [i for i in applied.items if i.requires_apply]
    done = sum(1 for i in pending if i.done)
    log.info("%s: applied %d/%d items; backup at %s",
             name, done, len(pending), snapshot.path)
    return rc or (0 if all(i.done for i in pending) else 1)


def write_report(ctx: "Ctx", name: str, markdown: str,
                 json_text: str | None = None) -> int:
    """Write ``markdown`` to ``ctx.report_path`` — 0 written, 1 refused.

    THE one place a run's report file is written, so ``--report`` means
    the same thing on every command [D2].  With no path given the run
    prints only and this is a no-op (0).  The JSON twin, when the caller
    has one (the audit's own ``render_json`` for an action plan, deploy's
    manifest summary), lands beside it as ``<stem>.json`` — the pairing
    every other report surface already writes.

    A path the operator named that CANNOT be written is a FAILED run (1),
    never a silent success: the contract that makes ``--report`` worth
    passing is that the file is there afterwards, so a caller can trust
    its absence as well as its presence.

    The baseline ``.json`` twin is NEVER refreshed here: only the audit's
    SUCCESS emitter owns that advance.  A failure report written beside a
    valid baseline must leave the baseline bytes untouched (otherwise a
    failed run destroys the very comparison basis it reports against).
    """
    report_path = getattr(ctx, "report_path", None)
    if report_path is None:
        return 0
    try:
        write_report_files(report_path, markdown, json_text,
                           protected_paths=report_protected_inputs(ctx),
                           protected_subtrees=report_protected_subtrees(ctx))
    except (WptError, OSError, UnicodeError) as exc:
        log.error("%s: could not write the report %s: %s", name,
                  report_path, redact_text(str(exc)))
        return 1
    log.info("%s: report written to %s", name, report_path)
    return 0


# ---------------------------------------------------------------------------
# The report of a run that did NOT produce one.
# ---------------------------------------------------------------------------

#: The one heading every failed or refusing run's report ends with, so no
#: writer grows its own shape for "this run did not complete".
_NOT_COMPLETE_HEADING = "## This run did not complete"


def not_complete(reason: str, *,
                 status: str = "failed") -> tuple[str, dict[str, Any]]:
    """``(markdown block, JSON object)`` — the ONE way a run says it did
    not complete.

    A command with its own report family (``verify``, ``deploy``) composes
    its envelope from this; the audit-shaped renderer below composes the
    same two pieces into the audit report.  The reason is REDACTED on the
    way in (``wpt.config.redact_text``), the chokepoint every log line
    passes: this text reaches a file an operator keeps and shares, so a
    password that reached an exception message must not reach the report
    either (the users_reset rule, stated for every report this project
    writes).  The count fields are structural, never a measurement: this
    run measured nothing.
    """
    safe = redact_text(reason).replace("\n", " ").strip() or "no reason given"
    # the leading blank line: every renderer ends its own body on a table
    # or a bullet, and a heading glued to the last line is not a section
    block = "\n" + "\n".join([
        _NOT_COMPLETE_HEADING,
        "",
        f"- status: {status}",
        f"- reason: {safe}",
        "- findings: 0 (the run ended before it measured anything)",
        "- planned items: 0",
        "",
    ])
    payload = {"status": status, "reason": safe,
               "findings": 0, "planned_items": 0}
    return block, payload


def failure_report(audit: Any, reason: str, *,
                   status: str = "failed",
                   title: str = "wpt audit") -> tuple[str, str]:
    """``(markdown, json twin)`` for a run that produced no findings.

    THE report a FAILED or REFUSING run writes, in the audit report's own
    shape so a caller can keep parsing one family: the same header, the
    same ``**Reclaimable estimate**`` line, ``findings: []`` and an empty
    ``plan.items`` — and the ONE thing a success report could not say, why
    there is nothing there.  Before this, a caller reading ``--report``
    after a failed run found no file at all and could not tell "the run
    planned nothing" from "the run never got far enough"; both looked
    identical, and the L44 complaint was one level up.

    It is written, never printed: a failed run has no report to show, and
    stdout stays the surface of a report that exists.
    """
    from ..report import Plan

    block, payload = not_complete(reason, status=status)
    markdown = render_report(audit, Plan(items=[]), title=title) + block
    twin = json.loads(render_json(audit, Plan(items=[])))
    twin["run"] = payload
    return markdown, json.dumps(twin, ensure_ascii=False, sort_keys=True,
                                indent=2)


def write_failure_report(ctx: "Ctx", name: str, reason: str, *,
                         status: str = "failed", audit: Any = None,
                         title: str = "wpt audit") -> int:
    """Write :func:`failure_report` to ``ctx.report_path``; 0 written,
    1 refused — the same contract :func:`write_report` has, for the runs
    that had nothing to report until now.

    ``audit`` is the caller's own header (a command with its own report
    family passes the AuditReport it would have rendered); the default is
    the SAME stub :func:`_emit` renders, so a caller reading the two files
    of one command sees one ``site`` and one ``source_summary`` whichever
    way the run ended.
    """
    header = audit if audit is not None else _audit_stub(ctx)
    markdown, twin = failure_report(header, reason, status=status, title=title)
    report_path = getattr(ctx, "report_path", None)
    extra = getattr(ctx, "extra", None) or {}
    baseline = extra.get("baseline") if isinstance(extra, dict) else None
    # A failure report never refreshes the baseline.  When --report names
    # the baseline's own markdown face, writing the twin would overwrite
    # the comparison basis; emit MARKDOWN ONLY and leave prev.json intact.
    if report_path is not None and baseline is not None:
        try:
            json_face = Path(report_path).with_suffix(".json").resolve()
            baseline_face = Path(baseline).resolve()
        except (OSError, RuntimeError, ValueError, TypeError):
            json_face = baseline_face = None
        if json_face is not None and json_face == baseline_face:
            return write_report(ctx, name, markdown)
    return write_report(ctx, name, markdown, twin)


def _safe_failure_report(ctx: "Ctx", name: str, reason: str, *,
                         status: str = "failed",
                         title: str | None = None) -> None:
    """Write a failure pair without letting a SECOND stop escape.

    The first stop/deadline is already the run's verdict; a signal landing
    during the failure-report write must not turn rc 1 into a traceback (or
    replace the reason with the reporting failure).  Every failure-report
    writer in this module goes through here (R11-P2-17).
    """
    try:
        write_failure_report(ctx, name, reason, status=status,
                             title=title or f"wpt {name}")
    except (Exception, RunControl) as report_exc:  # noqa: BLE001
        log.warning(
            "%s: could not write the failure report: %s",
            name, redact_text(str(report_exc)))


def _run_control(ctx: "Ctx", name: str, exc: BaseException) -> int:
    """The shared action boundary for a stop/deadline.

    Logs ONE redacted line, writes the shared failure markdown + JSON pair,
    and returns rc 1 — never a traceback.  ``run_action``'s ``finally`` has
    already torn the stack down.
    """
    reason = f"{name} stopped: {exc}"
    log.error("%s", redact_text(reason))
    _safe_failure_report(ctx, name, reason, title=f"wpt {name}")
    return 1


def _refuse(ctx: "Ctx", name: str, reason: str, *, status: str = "failed",
            level: int = logging.ERROR) -> int:
    """A run that did NOT produce a report: one log line, the report it
    could write, and the non-zero exit.

    Every refusal and failure path of :func:`run_action` goes through
    here, so "a failed run leaves a caller nothing on disk" cannot be true
    of one branch and false of the next.  Before this, a caller reading
    ``--report`` after a failed run found NO file and could not tell "the
    run planned nothing" from "the run never got far enough" — the L44
    defect one level up (L44 gave every dry run a report; the failed run
    still had none, which is where a caller most wants one).

    ``reason`` is the WHOLE line the log used to carry, so the failure
    messages operators and scripts already match on are unchanged; the
    level is explicit because an operator aborting at the confirmation is
    a refusal, not an error.
    """
    log.log(level, "%s", redact_text(reason))
    _safe_failure_report(ctx, name, reason, status=status,
                         title=f"wpt {name}")
    return 1


def _emit(ctx: "Ctx", name: str, plan: Plan) -> int:
    """Render the run's plan, print it, and write it to ``--report``.

    Every dry run, every local rehearsal and every ftp apply reports
    through here, so the printed surface and the file can never disagree
    and a registry-owned command can never ignore ``--report``.  The
    report is the audit report's own shape (site header, plan table,
    totals) around the action's plan — a stub AuditReport supplies the
    header; the plan is the run's own, so the written file is exactly what
    the operator read on stdout, and it is written even when the plan is
    EMPTY.
    """
    # Rendering and writing the run's plan is work after the action body:
    # an action that swallowed its own deadline (or a spent budget during a
    # long apply) must end rc 1 here, never publish a partial plan as the
    # run's success.  RunControl propagates to run_action's failure pair.
    deadline = Deadline.from_ctx(ctx)
    if deadline is not None:
        deadline.check(f"{name} report")
    audit = _audit_stub(ctx)
    # The command's own title, not the audit report's default: every action
    # success report was headed "# wpt audit" while its failure pair was
    # "# wpt <command>" -- two different documents for one command.
    markdown = render_report(audit, plan, title=f"wpt {name}")
    write_stdout(markdown)
    return write_report(ctx, name, markdown, render_json(audit, plan))


def _record_protected_output(ctx: "Ctx", path: Any) -> None:
    """Record one of the run's own OUTPUT files as report-writer protected.

    A local rehearsal archive (and clean-db's --re-dump) is a deliverable
    the run just produced; ``--report`` naming it would replace those bytes
    with Markdown on a green run.  The shared protected-set owner reads
    ``ctx.extra["protected_outputs"]``; this is the ONE recorder.
    """
    if path is None:
        return
    extra = getattr(ctx, "extra", None)
    if not isinstance(extra, dict):
        extra = {}
        try:
            ctx.extra = extra
        except (AttributeError, TypeError):
            return
    outputs = extra.setdefault("protected_outputs", [])
    if isinstance(outputs, list):
        outputs.append(str(path))


def _rehearsal_path(ctx: "Ctx"):
    """The materialized rehearsal zip's path: <stem>-rehearsed-<ts>.zip
    beside the original — convention-derived, never over the original.

    A same-second second apply used to collide with the first artifact's
    name and fail closed ("dest already exists").  Allocate the first free
    ``-2``/``-3``… suffix instead; the materializer still refuses any path
    that appears between this check and its own exclusive create.
    """
    from datetime import datetime

    from ..types import SourceError

    if ctx.zip is None:
        raise SourceError("local mode requires --zip")
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    stem = f"{ctx.zip.stem}-rehearsed-{stamp}"
    for offset in range(1, 1000):
        suffix = "" if offset == 1 else f"-{offset}"
        candidate = ctx.zip.with_name(f"{stem}{suffix}.zip")
        if not candidate.exists():
            return candidate
    raise SourceError(
        f"cannot allocate a rehearsal archive beside {ctx.zip}")


def _backup_file_scope(source, plan: Plan,
                       deadline: Deadline | None = None) -> list[str]:
    """File paths the pre-action snapshot must capture.

    A plan item may target a DIRECTORY (stale/migration dirs): snapshotting
    a dir target as a file would fail closed on a real source (dirs are not
    readable as bytes). Instead, every dir target expands to the FILES it
    contains (one walk); restoring those files recreates the tree. Empty
    dirs are not recoverable from a file snapshot — documented limitation.

    ``deadline`` is checked per walked entry: this scope walk runs BEFORE
    the snapshot, so an expired budget must end the run here rather than
    after a crawl (C8).
    """
    targets = [source._guard_path(i.target) for i in plan.items
               if i.requires_apply and not i.category.startswith("db.")]
    if not targets:
        return []
    dirs = set()
    for entry in source.walk():
        if deadline is not None:
            deadline.check("action scope walk")
        if entry.is_dir:
            dirs.add(source._guard_path(entry.path))
    files: set[str] = set()
    for target in targets:
        if target in dirs:
            prefix = target.rstrip("/") + "/"
            for entry in source.walk(target):
                if deadline is not None:
                    deadline.check("action scope walk")
                path = source._guard_path(entry.path)
                if not entry.is_dir and path.startswith(prefix):
                    files.add(path)
        else:
            files.add(target)
    # A live bridge/probe is a token-authenticated endpoint, never site
    # content; a custom plan pattern could otherwise name one.  The writer
    # refuses such a target too (one predicate, both doors).
    return require_distinct_snapshot_names(
        (path for path in files if not is_wpt_endpoint_file(path)), "target")


def _stack(ctx: "Ctx") -> tuple:
    """The command's ONE (source, session, bridge) trio.

    ftp mode: audit's remote_stack (FtpSource + override/plain session +
    undeployed Bridge).  local mode: (ZipSource(ctx.zip), None, None) —
    plan enumerates over the zip; apply is refused before any mutation.
    """
    from ..sources.zipwriter import MutableZipSource

    if ctx.mode == "local":
        if ctx.zip is None:
            from ..types import SourceError

            raise SourceError("local mode requires --zip")
        # MutableZipSource: reads are the ZipSource view; --apply STAGES in
        # memory and materializes a NEW zip (the rehearsal contract).
        return (MutableZipSource(ctx.zip, deadline=Deadline.from_ctx(ctx)),
                None, None)
    from ..audit import remote_stack

    return remote_stack(ctx)


def _plan_bytes(plan: Plan) -> str:
    from ..report import human_bytes

    return human_bytes(plan.est_bytes())


def _audit_stub(ctx: "Ctx"):
    """A minimal AuditReport header so the plan renders with site context."""
    from ..report import AuditReport

    return AuditReport(site=site_label(ctx),
                        source_summary=f"action plan ({ctx.mode})")
