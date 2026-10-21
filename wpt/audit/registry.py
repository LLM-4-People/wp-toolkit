"""Audit check registry: check registration, selection, and the run pipeline.

Checks attach by import. Each check module in ``wpt.audit`` (for example
``webroot``, ``security``, ``media``, and ``updates``) decorates its functions with ``@register_check("webroot.junk", applies=[...])``;
the decorator appends to the single authoritative store in this module at
import time. The registry is deliberately importer-agnostic: the ``wpt audit``
run() wiring (W6h) imports the check modules so their decorators fire — this
module never imports them, and never imports ``wpt.audit.data`` (W6b) either:
the gathered audit data crosses the pipeline opaquely as ``Any``.

Selection mirrors the CLI surface: ``wpt audit --only x --skip y`` lands in
``Ctx.extra`` as ``{"only": [...], "skip": [...]}`` and is passed to
``select_checks`` / ``run_checks`` unchanged.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from time import perf_counter
from typing import Any

from ..config import redact_text
from ..log import get_logger
from ..settings import Settings
from ..types import DeadlineExceeded, Finding, StopRequested, WptError

log = get_logger("audit")

#: Source modes a check can apply to (the Ctx.mode values, owned here so the
#: registry's boundary validation has one authoritative list).
MODES: tuple[str, ...] = ("ftp", "local")

#: A check is called as ``func(data, settings)`` and returns list[Finding].
#: ``data`` is the AuditData object from wpt.audit.data (W6b) — opaque here.
CheckFunc = Callable[..., list[Finding]]


@dataclass(frozen=True)
class CheckRecord:
    """One registered check: dotted name, applicable source modes, function."""

    name: str
    applies: tuple[str, ...]
    func: CheckFunc


# The single authoritative registration store, keyed by dotted check name in
# registration (import) order. Decorators append at import of the check
# modules; there is intentionally no unregister API.
_CHECKS: dict[str, CheckRecord] = {}


def register_check(
    name: str, applies: tuple[str, ...] | list[str]
) -> Callable[[CheckFunc], CheckFunc]:
    """Decorator registering an audit check under a dotted name.

    ``name`` is a dotted check name matching Finding.category conventions
    ("webroot.junk", "db.revisions", ...) so ``--only webroot`` selects the
    whole ``webroot.*`` group. ``applies`` is the subset of MODES the check
    runs for; a check registered for one mode never runs in the other.

    Raises at decoration (import) time:
      ValueError    — empty name, applies not a list/tuple (a bare string is
                      rejected: it would iterate per character), or a mode
                      outside MODES;
      RuntimeError  — duplicate name (fail loud, never last-wins).
    """
    if not isinstance(name, str) or not name:
        raise ValueError(f"check name must be a non-empty string, got {name!r}")
    if isinstance(applies, str) or not isinstance(applies, (list, tuple)):
        raise ValueError(
            f"check {name!r}: applies must be a list/tuple of modes, got {applies!r}"
        )
    normalized = tuple(applies)
    invalid = [mode for mode in normalized if mode not in MODES]
    if invalid:
        raise ValueError(
            f"check {name!r}: invalid applies {invalid!r}; expected a subset of {list(MODES)!r}"
        )
    if name in _CHECKS:
        raise RuntimeError(f"duplicate check registration: {name!r} is already registered")

    def decorator(func: CheckFunc) -> CheckFunc:
        _CHECKS[name] = CheckRecord(name=name, applies=normalized, func=func)
        return func

    return decorator


def all_checks() -> list[CheckRecord]:
    """Every registered check, in registration (import) order."""
    return list(_CHECKS.values())


def _selector_matches(selector: str, check_name: str) -> bool:
    """Selector equality or a dotted-prefix match ("webroot" ~ "webroot.junk")."""
    return check_name == selector or check_name.startswith(f"{selector}.")


def validate_selectors(mode, only, skip) -> None:
    """Fail LOUD on any selector matching no applicable check — BEFORE any
    expensive work (the gather). A typo'd or mode-inapplicable ``--only`` /
    ``--skip`` name must die in seconds, not after a 15-minute gather; an
    empty selection would otherwise read as 'that check passed'. THE single
    owner of the unknown-selector verdict: select_checks calls this too,
    so the two paths can never drift."""
    if mode not in MODES:
        raise ValueError(f"unknown audit mode {mode!r}; expected one of {list(MODES)!r}")
    applicable = [rec for rec in _CHECKS.values() if mode in rec.applies]
    for selector in dict.fromkeys(list(only or ()) + list(skip or ())):
        if not any(_selector_matches(selector, rec.name) for rec in applicable):
            raise WptError(
                f"audit: selector {selector!r} matched no {mode}-mode "
                "check (typo, or the check does not apply to this mode); "
                "refusing to run a selection that would silently skip it"
            )


def select_checks(
    mode: str,
    only: Sequence[str] | None,
    skip: Sequence[str] | None,
) -> list[CheckRecord]:
    """Select the checks to run in ``mode`` under ``--only`` / ``--skip``.

    Semantics (binding):
      * start from the checks whose ``applies`` contains ``mode``;
      * a selector matches a check when it equals the check name or is a
        dotted prefix of it ("webroot" matches "webroot.junk" and
        "webroot.stale"; "webroot.junk" matches exactly that check);
      * ``only=None`` or empty keeps every applicable check; otherwise the
        result is the union of the selectors' matches;
      * ``skip`` subtracts from that set and wins over ``only``;
      * a selector matching NO check applicable to this mode is a USAGE
        ERROR (WptError): a typo'd or mode-inapplicable name must never
        pass silently — the operator asked for a specific check and an
        empty report would read as "that check passed" (live lesson: a
        validation step filtered to a nonexistent name and produced an
        empty report that looked like a confirmation);
      * the result is sorted by check name (deterministic ordering).
    """
    validate_selectors(mode, only, skip)
    applicable = [rec for rec in _CHECKS.values() if mode in rec.applies]
    if only:
        selected = [
            rec for rec in applicable
            if any(_selector_matches(sel, rec.name) for sel in only)
        ]
    else:
        selected = applicable
    if skip:
        selected = [
            rec for rec in selected
            if not any(_selector_matches(sel, rec.name) for sel in skip)
        ]
    return sorted(selected, key=lambda rec: rec.name)


def run_checks(
    data: Any,
    settings: Settings,
    mode: str,
    only: Sequence[str] | None,
    skip: Sequence[str] | None,
    *,
    deadline: Any = None,
) -> list[Finding]:
    """Select and execute the audit checks for ``mode`` over ``data``.

    Each selected check is called as ``func(data, settings)`` (positionally)
    and its findings accumulate in execution order. A check that raises is
    logged at error with its name and the exception message, then skipped —
    one bad check never kills the audit; the remaining checks still run. A
    skipped check contributed NO findings, so it is surfaced as a
    ``<check>/check-failed`` high-risk finding: a silent skip would otherwise
    read as a clean pass. Per-check durations are logged at debug; one summary
    line (checks run, failed, findings count) is logged at info. ``data`` is
    opaque to the registry (the AuditData gatherers land in W6b) and is passed
    through untouched.
    """
    checks = select_checks(mode, only, skip)
    findings: list[Finding] = []
    failed = 0
    for rec in checks:
        # The run budget is checked BEFORE each check and once before the
        # caller emits; otherwise a slow walk/check could outlive --deadline
        # and still produce a success report (R6-34).
        if deadline is not None:
            deadline.check("audit check")
        started = perf_counter()
        try:
            results = list(rec.func(data, settings))
        except (StopRequested, DeadlineExceeded):
            # A cooperative stop or the run deadline ends the whole run; it
            # is not a "this check errored" coverage row.  Swallowing it made
            # audit/updates return rc 0 after SIGTERM.
            raise
        except Exception as exc:
            failed += 1
            # The exception message can carry secrets, and the redacting log
            # filter only scrubs record.msg (not record.args), so redact it
            # BEFORE it becomes a log argument.
            log.error("audit check %s failed: %s", rec.name, redact_text(str(exc)))
            # Surface the coverage gap. The category is a reserved "audit.*"
            # runner category that matches NO suggested-step rule, so a failed
            # check can never be mistaken for a real finding and routed to a
            # destructive action (a failed core.integrity must not suggest
            # heal-core, a failed media.unreferenced must not suggest trim).
            # The raw exception stays out of the report; only its type does.
            findings.append(Finding(
                category="audit.check_failed",
                name=rec.name,
                detail=(f"check {rec.name!r} errored and was skipped "
                        f"({type(exc).__name__}); see the audit log"),
                count=0,
                risk="high",
                fix="this check ran no logic; re-run it (narrow with --only) or report as a bug",
            ))
            log.debug(
                "check %s failed after %.2f ms", rec.name,
                (perf_counter() - started) * 1000.0,
            )
            continue
        log.debug(
            "check %s finished in %.2f ms (%d findings)", rec.name,
            (perf_counter() - started) * 1000.0, len(results),
        )
        findings.extend(results)
    if deadline is not None:
        deadline.check("audit checks end")
    log.info("audit: %d checks run (%d failed), %d findings",
             len(checks), failed, len(findings))
    return findings
