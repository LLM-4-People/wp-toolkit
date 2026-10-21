"""Read-only FTP account-root scan for WordPress webroot candidates.

``wpt discover`` exists because the operator often knows the FTP login but
not the docroot: a host may serve ``public_html``, ``httpdocs``, ``www``, a
cPanel-style ``<domain>/public_html`` or a DirectAdmin-style
``domains/<domain>/public_html``.  The command builds the ONE account-root
source (``wpt.remote.ftp_source_for(ctx, root="")``) and lists a bounded set
of candidate directories.  It NEVER reads a file, writes a file, opens HTTP
or deploys the bridge: a candidate is identified by the exact top-level
entries ``wp-config.php`` (file), ``wp-content`` (dir) and ``wp-includes``
(dir) in ONE ``list_dir``.

A directory that cannot be listed is a debug-level skip — one missing
subdirectory must not kill a scan that has other candidates.  The account
root listing is different: it feeds the cPanel-style child candidates, so a
failure there makes the whole scan impossible and propagates to :func:`run`.
``FtpChannelUnhealthy`` is never masked as "not found": a dead data channel
is a run-level failure.

The result is deterministic: complete candidates first, then partial ones
(most markers first), and a known domain ranks first inside each group.
``run`` renders that list as a markdown table plus a JSON twin through the
shared report writer and exits 1 when no complete webroot was found — a
discovery that found nothing is a failed answer, not a success.
"""

from __future__ import annotations

import json
import posixpath
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from .config import redact_text
from .deadline import Deadline
from .log import get_logger
from .remote import DOCROOT_NAMES, ftp_source_for, normalize_domain
from .sources.base import close_source
from .report import md_escape, safe_source_label, safe_text
from .report import write_stdout
from .settings import DiscoverSettings
from .types import (DeadlineExceeded, Entry, FtpChannelUnhealthy, RunControl,
                    Source, SourceError, StopRequested, WptError)

if TYPE_CHECKING:  # annotation-only (cli lazy-calls every command)
    from .cli import Ctx

__all__ = ["WebrootCandidate", "scan", "run"]

log = get_logger("discover")

#: Exact top-level entries that identify a WordPress webroot, in the order
#: every report renders them, mapped to whether the entry is a DIRECTORY.
#: Structurally fixed by WordPress, not a knob.
_MARKER_DIRS = {
    "wp-config.php": False,
    "wp-content": True,
    "wp-includes": True,
}
_MARKERS = tuple(_MARKER_DIRS)

#: Nested tree candidates.  BOTH families read the ONE docroot tuple:
#: a docroot a host serves at the account root is equally plausible under
#: ``domains/<domain>/`` (DirectAdmin) and ``<domain>/`` (cPanel), and
#: keeping two hand-maintained tuples let ``wwwroot``/``web``/``htdocs``
#: drift out of the nested scan.
_DOMAIN_WEBROOTS = DOCROOT_NAMES
_CHILD_WEBROOTS = DOCROOT_NAMES


@dataclass(frozen=True)
class WebrootCandidate:
    """One directory carrying at least one WordPress marker."""

    path: str
    markers: tuple[str, ...]
    missing: tuple[str, ...]

    @property
    def full(self) -> bool:
        """True when every WordPress marker is present."""
        return not self.missing

    @property
    def partial(self) -> bool:
        """True when some, but not all, WordPress markers are present."""
        return bool(self.markers) and not self.full


def scan(source: Source, settings: DiscoverSettings,
         domain: str | None = None,
         deadline: Deadline | None = None) -> list[WebrootCandidate]:
    """List candidate webroots under ``source``'s root; never mutates.

    ``settings`` is ``ctx.settings.discover``.  ``domain`` (already the bare
    hostname, but tolerant of ``www.``) ranks matching paths first inside
    each report group and seeds the two known DirectAdmin candidates.
    ``deadline`` is the run budget: checked before each listing so a crawl
    ends itself instead of outliving ``--deadline``.
    """
    known = _clean_domain(domain)
    cap = settings.max_candidates
    candidates: list[str] = []
    seen: set[str] = set()
    root_listing: list[Entry] | None = None

    def add(path: str) -> None:
        if path not in seen:
            seen.add(path)
            candidates.append(path)

    def root_entries() -> list[Entry]:
        """The login directory listing, fetched at most once.

        The root is both candidate ``""`` and the source of the cPanel-style
        child candidates; a failure here is run-level (never a skip).
        """
        nonlocal root_listing
        if root_listing is None:
            _check(deadline, "discover account root")
            root_listing = source.list_dir("")
            # A slow LIST can outlive the budget; check AFTER it, not only
            # before the next candidate (R6-12).
            _check(deadline, "discover account root end")
        return root_listing

    # Fixed, highest-value candidates: a known domain's DirectAdmin docroots
    # first, then the login root and the common shared-host docroot names.
    if known:
        add(f"domains/{known}/public_html")
        add(f"domains/{known}/httpdocs")
    add("")
    for name in DOCROOT_NAMES:
        add(name)

    # Expand the account-root children only when the fixed list left room.
    # The root listing also feeds candidate "" below, so it is fetched once.
    if len(candidates) < cap:
        root_children = _child_dirs_from(root_entries(), "")
        # DirectAdmin wildcard candidates: one listing of ``domains``
        # discovers the account's domain directories; no deeper recursion.
        if "domains" in root_children:
            domain_children = _child_dirs(source, "domains", deadline)
            for suffix in _DOMAIN_WEBROOTS:
                for child in domain_children:
                    add(f"domains/{child}/{suffix}")
                    if len(candidates) >= cap:
                        break
                if len(candidates) >= cap:
                    break
        # cPanel-style immediate children of the login root.
        if len(candidates) < cap:
            for child in root_children:
                for suffix in _CHILD_WEBROOTS:
                    add(f"{child}/{suffix}")
                    if len(candidates) >= cap:
                        break
                if len(candidates) >= cap:
                    break

    results: list[WebrootCandidate] = []
    for path in candidates[:cap]:
        _check(deadline, "discover candidate")
        if path == "":
            listing = root_entries()
        else:
            try:
                listing = source.list_dir(path)
            except FtpChannelUnhealthy:
                raise
            except (SourceError, OSError) as exc:
                log.debug("discover: no webroot at %s (%s)", _display(path),
                          redact_text(str(exc)))
                continue
            _check(deadline, "discover candidate listing end")
        markers = _markers(listing, path)
        if not markers:
            log.debug("discover: no WordPress markers at %s", _display(path))
            continue
        results.append(WebrootCandidate(
            path=path,
            markers=markers,
            missing=tuple(marker for marker in _MARKERS
                          if marker not in markers),
        ))

    results.sort(key=lambda candidate: _rank(candidate, known))
    _check(deadline, "discover report")
    return results


def run(ctx: "Ctx") -> int:
    """Run ``wpt discover``; never raises for an operational failure."""
    if ctx.mode != "ftp":
        reason = ("wpt discover is ftp-only: a local zip already names its "
                  "own webroot")
        log.error("discover: %s", reason)
        _write_failure(ctx, reason)
        return 1

    source = None
    rc = 1
    close_stop: BaseException | None = None
    primary: BaseException | None = None
    try:
        deadline = Deadline.from_ctx(ctx)
        source = ftp_source_for(ctx, root="")
        domain = _domain_from_url(ctx.wp_url)
        candidates = scan(source, ctx.settings.discover, domain,
                          deadline=deadline)
        # Even a scan that returned candidates can have spent the budget on
        # its final listing; never emit a success report after expiry.
        _check(deadline, "discover report")
        markdown = _markdown(ctx, candidates)
        write_stdout(markdown, end="")

        complete = [candidate for candidate in candidates if candidate.full]
        partial = [candidate for candidate in candidates
                   if candidate.partial]
        log.info("discover: %d candidate(s), %d complete, %d partial",
                 len(candidates), len(complete), len(partial))
        if len(complete) > 1:
            log.warning(
                "discover: %d complete WordPress webroots found (%s); "
                "the operator must choose one with --webroot",
                len(complete),
                ", ".join(_display(candidate.path)
                          for candidate in complete))

        if ctx.report_path is not None:
            from .actions.registry import write_report

            if write_report(ctx, "discover", markdown,
                            _json_text(ctx, domain, candidates)):
                return 1
        rc = 0 if complete else 1
    except RunControl as exc:
        primary = exc
        reason = redact_text(f"discover stopped: {exc}")
        log.error("%s", reason)
        _write_failure(ctx, reason)
        rc = 1
    except (WptError, OSError) as exc:
        primary = exc
        reason = redact_text(str(exc))
        log.error("discover failed: %s", reason)
        _write_failure(ctx, reason)
        rc = 1
    finally:
        if source is not None:
            try:
                close_source(source, "discover")
            except (StopRequested, DeadlineExceeded) as exc:
                close_stop = exc
            except Exception as exc:  # noqa: BLE001 — never mask data
                log.warning("discover: source close failed: %s",
                            redact_text(str(exc)))
    if close_stop is not None:
        reason = redact_text(str(close_stop))
        log.error("discover: %s", reason)
        if primary is None:
            _write_failure(ctx, reason)
        else:
            log.error("discover: the primary failure above stays the run's "
                      "reason (rc %d); the failure report was not replaced",
                      rc)
        return 1
    return rc


# ------------------------------------------------------------------ helpers


def _markers(entries: list[Entry], path: str) -> tuple[str, ...]:
    """The WordPress markers among ONE top-level listing, canonical order."""
    found: set[str] = set()
    for entry in entries:
        entry_path = entry.path.rstrip("/")
        if posixpath.dirname(entry_path) != path:
            continue
        name = posixpath.basename(entry_path)
        expected_dir = _MARKER_DIRS.get(name)
        if expected_dir is None:
            continue
        if expected_dir:
            found_here = entry.is_dir
        else:
            # A symlinked file marker is still the file: FTP models a link
            # as is_dir=True plus is_link=True (the target may be a file or
            # a directory), so the exact (name, is_dir) pair rejected it.
            found_here = not entry.is_dir or entry.is_link
        if found_here:
            found.add(name)
    return tuple(marker for marker in _MARKERS if marker in found)


def _child_dirs(source: Source, path: str,
                deadline: Deadline | None = None) -> list[str]:
    """Immediate directory children of ``path``; a missing tree is a skip."""
    _check(deadline, "discover child directory")
    try:
        listing = source.list_dir(path)
    except FtpChannelUnhealthy:
        raise
    except (SourceError, OSError) as exc:
        log.debug("discover: cannot list %s (%s)", _display(path),
                  redact_text(str(exc)))
        return []
    _check(deadline, "discover child directory end")
    return _child_dirs_from(listing, path)


def _child_dirs_from(entries: list[Entry], path: str) -> list[str]:
    """Sorted immediate directory basenames in ``entries`` (links skipped)."""
    children: set[str] = set()
    for entry in entries:
        entry_path = entry.path.rstrip("/")
        if posixpath.dirname(entry_path) != path:
            continue
        if entry.is_dir and not entry.is_link:
            children.add(posixpath.basename(entry_path))
    return sorted(children)


def _check(deadline: Deadline | None, context: str) -> None:
    if deadline is not None:
        deadline.check(context)


def _rank(candidate: WebrootCandidate, domain: str | None) -> tuple:
    """Complete first, known-domain first inside a group, markers, path."""
    group = 0 if candidate.full else 1
    segments = tuple(segment.casefold() for segment in candidate.path.split("/")
                     if segment)
    domain_rank = 0 if domain and any(
        normalize_domain(segment) == normalize_domain(domain)
        for segment in segments
    ) else 1
    marker_rank = 0 if candidate.full else -len(candidate.markers)
    return (group, domain_rank, marker_rank, candidate.path)


def _clean_domain(domain: str | None) -> str | None:
    """The bare hostname: lowercase, no trailing dot, no leading ``www.``."""
    value = normalize_domain(domain)
    return value or None


def _domain_from_url(wp_url: str | None) -> str | None:
    """The hostname of ``--wp-url`` with ``www.`` stripped, or None."""
    value = (wp_url or "").strip()
    if not value:
        return None
    try:
        host = urlparse(value).hostname
        if host is None and "://" not in value:
            host = urlparse(f"//{value}").hostname
    except ValueError:
        # A malformed URL carries no usable hostname; the scan still runs
        # (the domain is only a ranking hint and a candidate seed).
        return None
    return _clean_domain(host)


def _display(path: str) -> str:
    """Render the login root as ``.`` in tables and log lines.

    The candidate path is filesystem text but still untrusted input: an
    account can name a directory ``password=HUNTER2``.  Every rendered
    surface crosses the shared redaction owner.
    """
    return safe_text(redact_text(path)) if path else "."


# ---------------------------------------------------------------- rendering


def _markdown(ctx: "Ctx", candidates: list[WebrootCandidate]) -> str:
    """The operator-facing discovery table (always ends with a newline)."""
    complete = sum(1 for candidate in candidates if candidate.full)
    lines = [
        f"# wpt discover — {safe_source_label(ctx.source or "unknown")}",
        (f"Found {len(candidates)} candidate(s); {complete} complete "
         f"WordPress webroot(s)."),
    ]
    if candidates:
        lines.append("| webroot | wordpress | evidence |")
        lines.append("|---|---|---|")
        for candidate in candidates:
            evidence = ", ".join(candidate.markers)
            if candidate.partial:
                evidence += f"; missing: {', '.join(candidate.missing)}"
            lines.append(
                "| {} | {} | {} |".format(
                    md_escape(_display(candidate.path)),
                    "complete" if candidate.full else "partial",
                    md_escape(evidence),
                )
            )
    if not complete:
        lines.append("")
        if candidates:
            lines.append(
                "No complete WordPress webroot was found; pass --webroot "
                "explicitly (for example --webroot domains/site/public_html).")
        else:
            lines.append(
                "No WordPress webroot was found from the account root; pass "
                "--webroot explicitly (for example --webroot "
                "domains/site/public_html).")
    return "\n".join(lines).rstrip("\n") + "\n"


def _json_text(ctx: "Ctx", domain: str | None,
               candidates: list[WebrootCandidate]) -> str:
    """The machine-readable twin (sorted keys, indent 2, trailing newline)."""
    payload = {
        "source": safe_source_label(ctx.source or "unknown"),
        "domain": domain,
        "candidates": [
            {
                "path": safe_text(redact_text(candidate.path)),
                "wordpress": "complete" if candidate.full else "partial",
                "markers": list(candidate.markers),
                "missing": list(candidate.missing),
            }
            for candidate in candidates
        ],
        "totals": {
            "candidates": len(candidates),
            "complete": sum(1 for candidate in candidates if candidate.full),
            "partial": sum(1 for candidate in candidates
                           if candidate.partial),
        },
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      indent=2) + "\n"


def _write_failure(ctx: "Ctx", reason: str) -> None:
    """Write the small failure report when ``--report`` was asked for."""
    if getattr(ctx, "report_path", None) is None:
        return
    from .actions.registry import not_complete, write_report

    block, run_payload = not_complete(reason, status="failed")
    markdown = f"# wpt discover — {safe_source_label(ctx.source or "unknown")}\n" + block
    payload = {
        "source": safe_source_label(ctx.source or "unknown"),
        "domain": _domain_from_url(ctx.wp_url),
        "candidates": [],
        "totals": {"candidates": 0, "complete": 0, "partial": 0},
        "run": run_payload,
    }
    json_text = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                           indent=2) + "\n"
    try:
        write_report(ctx, "discover", markdown, json_text)
    except (Exception, RunControl) as exc:  # noqa: BLE001 — never replace the reason
        log.warning("discover: could not write the failure report: %s",
                    redact_text(str(exc)))
