"""Audit report + plan rendering (markdown and JSON), deterministic and secret-free.

Suggested next steps — single owner: ``SUGGESTED_STEPS`` below is the ONE
ordered mapping from an audit-check category prefix to the operator's next
move (a ``wpt`` command to run verbatim, or advice text where no command
safely applies). Rendering contract:

* first-match-wins per finding over DOTTED prefixes ("webroot.junk" never
  matches "webroot.junk_recurring" — the separator is a dot);
* one line per matched rule, in MAPPING order (priority order: compromise
  investigation first, then cleanup commands, reversible actions, advice,
  manual/hoster territory, updates) — never in finding order;
* rules sharing an identical (action, why) — the webroot, db-cleanup,
  harden and updates families — collapse to a single line;
* severity never changes the suggestion;
* a category no rule matches renders NOTHING: future checks stay silent
  rather than suggest a wrong command. Every category registered by the
  ``wpt.audit`` check registry is covered (tests enforce this); extend the
  mapping in the same change as any new check. Command mappings track what
  the actions truly implement — clean-db's named ops (revisions, expired
  transients, orphan meta, optimize) and harden's .htaccess/wp-config
  lines — never a wish.

Site facts — the ``Site`` section (markdown) / ``site_facts`` key (JSON
twin) carry the site's own identity and inventory, so the operator can
answer "which theme, which builder, whose account, which locale?" from
the report instead of querying the database by hand.  They are FACTS, not
findings: they add no category, no risk and no reclaimable bytes, and
they are never a check's output.  :func:`site_facts` is the ONE builder
from the audit's ``AuditData``; the section is omitted entirely when no
fact is known (a gather that carried none), never rendered empty.

The section passes through the same redaction choke point as the
findings (:func:`_scrub`): a fact whose NAME looks like a secret slot is
rendered ``***`` and a value that reads like a credential assignment is
masked, in BOTH twins.  A user email is NOT such a case — the report is
the operator's own data, written to a path they choose, and a password
reset needs the roster.
"""

import dataclasses
import json
import os
import secrets
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .config import redact, redact_text
from .log import get_logger
from .types import Finding, PlanItem, RunControl, WptError

if TYPE_CHECKING:  # the audit's site model — read structurally, never imported
    from .audit.data import AuditData

log = get_logger("report")

#: The scalar facts of the report's "Site" section, in render order, with
#: the label each one carries.  ONE owner: the markdown table, the JSON
#: twin and the presence rule all read this tuple, so a fact can never be
#: rendered in one twin and forgotten in the other.
#:
#: A fact is rendered only when it is KNOWN; an unknown one is omitted
#: from both twins (the "unknown = silent" discipline the audit data
#: layer uses) — never a row of placeholders.
SITE_SCALAR_FACTS: tuple[tuple[str, str], ...] = (
    ("blogname", "blog name"),
    ("siteurl", "siteurl"),
    ("home", "home"),
    ("wp_version", "WordPress version"),
    ("db_version", "DB version"),
    ("locale", "locale"),
)

#: The header line of the site section's theme row, its title, and its
#: sub-tables: ``(fact key, title, columns)``.  The columns ARE the fact
#: entry's own field names, in render order, so the markdown header, the
#: cells and the JSON keys are one list read in one order — a sub-table
#: can never exist in one twin and not the other.  Kept beside
#: SITE_SCALAR_FACTS so the whole section shape is readable in one place.
SITE_THEME_LABEL = "active theme"
SITE_SECTION_TITLE = "Site"
SITE_TABLES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("plugins", "Active plugins", ("slug", "version")),
    ("users", "Users", ("login", "email", "role")),
    ("posts", "Posts by type", ("type", "status", "count")),
    ("tables", "Database tables", ("table", "rows", "size")),
)

#: fact key -> the entry fields the sub-table renders, in order.
_SITE_COLUMNS: dict[str, tuple[str, ...]] = {
    key: columns for key, _title, columns in SITE_TABLES
}


def human_bytes(n: float) -> str:
    """Deterministic human byte formatting (the single shared impl)."""
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(n)} {unit}"
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def safe_text(value: Any) -> str:
    """Text every UTF-8 sink can encode (the ONE stdout/report policy).

    A site label or source line can carry a lone surrogate from argv decoded
    with ``surrogateescape`` or from bridge/probe JSON.  ``redact_text``
    preserves it, and a strict ``sys.stdout.write`` then raises
    UnicodeEncodeError after the run already did work.  ``backslashreplace``
    keeps the bytes identifiable (``\\udcff``) instead of crashing.
    """
    if not isinstance(value, str):
        value = "" if value is None else str(value)
    return value.encode("utf-8", "backslashreplace").decode("utf-8")


def write_stdout(text: str, *, end: str = "\n") -> None:
    """The ONE report/stdout sink outside the CLI.

    Command report surfaces write through here so the output policy (UTF-8
    safety, exact newline) cannot drift module by module.  Diagnostics never
    use this sink; they go through :func:`wpt.log.get_logger`.
    """
    sys.stdout.write(safe_text(text) + end)


def write_stderr(text: str, *, end: str = "\n") -> None:
    """The ONE non-log stderr sink for a command body's pre-dispatch refusal.

    CLI argument/usage errors still print through ``wpt.cli``; this is for a
    command body (the proxy listener) that must answer the same line without
    importing the dispatcher.
    """
    sys.stderr.write(safe_text(text) + end)


def safe_source_label(value: Any) -> str:
    """A report title's source line: redacted AND UTF-8-encodable text.

    ONE owner for the ``# wpt <cmd> — <source>`` label every command builds.
    ``redact_text`` preserves a lone surrogate from argv (surrogateescape)
    or bridge JSON; ``safe_text`` turns it into ``\\udcff`` so a strict
    stdout/report sink cannot raise after the work already ran.
    """
    text = "" if value is None else str(value)
    return safe_text(redact_text(text or "unknown"))


def _scrub(obj):
    """Sanitize any report payload: structured keys + free text, one choke point."""
    return _safe_text_walk(redact_text_walk(redact(obj)))


def _safe_text_walk(obj):
    """Apply :func:`safe_text` to every string in a redacted report payload.

    The renderers (markdown AND JSON) must be encodable by a strict UTF-8
    sink: a surrogate from bridge/probe JSON or argv must render as
    ``\\udcff``, never raise after the run already did work.
    """
    if isinstance(obj, str):
        return safe_text(obj)
    if isinstance(obj, dict):
        return {key: _safe_text_walk(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [_safe_text_walk(value) for value in obj]
    if isinstance(obj, tuple):
        return tuple(_safe_text_walk(value) for value in obj)
    return obj


_WALK_MAX_DEPTH = 32
_WALK_CYCLE = "<circular>"
_WALK_DEPTH = "<max-depth>"


def redact_text_walk(obj, *, _depth: int = 0, _seen: set[int] | None = None):
    """Apply redact_text to every string in a nested structure (list/dict/scalar).

    Bounded and cycle-safe: an untrusted payload that reached a report must
    not raise RecursionError out of the shared writer.  A repeated ancestor
    renders ``<circular>``; depth 32 renders ``<max-depth>``.
    """
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict) or isinstance(obj, (list, tuple)):
        if _depth >= _WALK_MAX_DEPTH:
            return _WALK_DEPTH
        if _seen is None:
            _seen = set()
        token = id(obj)
        if token in _seen:
            return _WALK_CYCLE
        _seen.add(token)
        try:
            if isinstance(obj, dict):
                return {k: redact_text_walk(v, _depth=_depth + 1,
                                            _seen=_seen)
                        for k, v in obj.items()}
            maker = list if isinstance(obj, list) else tuple
            return maker(redact_text_walk(v, _depth=_depth + 1, _seen=_seen)
                         for v in obj)
        finally:
            _seen.discard(token)
    return obj


def _redact_json_text(json_text: str) -> str:
    """Redact a report twin without changing valid ``json_text`` bytes when
    nothing matched.

    Markdown gets ``redact_text`` directly, but a JSON body must stay valid
    JSON: a bare free-text rewrite would corrupt keys/numbers.  Parse,
    redact every value, and only re-serialize when the payload actually
    changed — the exact-output surrogate contract for secret-free reports
    stays byte-identical.
    """
    try:
        payload = json.loads(json_text)
    except (ValueError, RecursionError):
        # The caller handed us invalid JSON; the report is already broken.
        # Redacting free text keeps the credential out even then.
        return redact_text(json_text)
    # KEY-AWARE first (``config.redact`` blanks the VALUE of a secret-named
    # key such as ``password``/``db_password``), then free text.  The
    # value-only walk alone left a secret-keyed map untouched in the twin
    # while the markdown face was redacted.
    safe = redact_text_walk(redact(payload))
    if safe == payload:
        return json_text
    newline = "\n" if json_text.endswith("\n") else ""
    return json.dumps(safe, ensure_ascii=False, sort_keys=True,
                      indent=2) + newline


@dataclass
class AuditReport:
    site: str
    source_summary: str
    findings: list[Finding] = field(default_factory=list)
    totals: dict[str, Any] = field(default_factory=dict)
    # The site's own facts for the "Site" section (see :func:`site_facts`
    # for the shape).  None = none gathered = the section is omitted from
    # both twins.  Facts, never findings: they add no category and no
    # reclaimable bytes.
    site_facts: dict[str, Any] | None = None

    def findings_by_category(self) -> dict[str, list[Finding]]:
        """Findings grouped by category, deterministically ordered."""
        groups: dict[str, list[Finding]] = {}
        for f in sorted(self.findings, key=lambda f: (f.category, f.name)):
            groups.setdefault(f.category, []).append(f)
        return groups

    def reclaimable_bytes(self) -> int:
        return sum(f.bytes for f in self.findings)


@dataclass
class Plan:
    items: list[PlanItem] = field(default_factory=list)
    # Explicit pre-action snapshot scope for DB-touching plans: the table
    # names the action will mutate. None = unset (the registry derives from
    # db.-prefixed item targets); [] = deliberately NOTHING (e.g. an
    # optimize-only plan mutates no rows) — distinct from unset.
    backup_tables: list[str] | None = None

    def est_bytes(self) -> int:
        """Bytes the plan's APPLY will actually reclaim.

        ADVICE items (``requires_apply=False`` — the clean-files
        active-unit guard) carry a size the operator would reclaim only
        after deactivating/switching, and their apply never runs, so
        they are excluded: the plan total is the number the apply
        delivers, not the number the tree contains.  The per-row
        estimate in the plan table is unchanged, so the guarded size
        stays visible where the advice item explains it.
        """
        return sum(i.bytes_est for i in self.items if i.requires_apply)


def md_escape(text: str) -> str:
    """Markdown table-cell escaping: pipes escaped, CR/LF flattened.

    The ONE owner of the rule — every report renderer (audit, doctor,
    future commands) imports it; no local twins.  A bare ``\\r`` is a line
    break for a Markdown table exactly like ``\\n``, so both (and CRLF as
    one break) become a space.
    """
    return (text.replace("|", "\\|")
            .replace("\r\n", " ")
            .replace("\r", " ")
            .replace("\n", " "))


def record_snapshot_root(ctx: Any, root: Any) -> None:
    """Record one snapshot root this run has INSPECTED or selected.

    THE single registration door for the report-protection owner.  A
    snapshot reader (selection, retention, undo/list, a freshly created
    rollback basis) records every root it opens BEFORE it reads a manifest;
    the shared writer then treats each recorded root as a subtree, so no
    report face can replace its manifest or a payload — even for a
    manifest-less/corrupt root whose marker is absent.
    """
    if root is None:
        return
    try:
        raw = str(Path(root))
    except (TypeError, ValueError, OSError):
        return
    extra = getattr(ctx, "extra", None)
    if not isinstance(extra, dict):
        return
    roots = extra.setdefault("snapshot_roots", [])
    if isinstance(roots, list) and raw not in roots:
        roots.append(raw)


def report_protected_subtrees(ctx: Any) -> tuple[Path, ...]:
    """Every snapshot root this run selects or records (collision SUBTREES).

    Includes the PRE-DISPATCH selection (a managed name, ``last``,
    ``--undo-last``, list mode, a files restore) as well as roots recorded by
    a command body while it reads retention/selection candidates.  Recording
    is not required for the former: the selected root is an input even when
    its manifest was already gone.

    Snapshot-shaped directories under ``--backup-dir`` are included even when
    this run selects none of them: a report must never replace the manifest
    or payload of a rollback basis the operator keeps for a later restore
    (both naming families — ``wpt backup``'s ``YYYYmmdd-HHMMSS`` and
    ``wpt files``' ``files-<UTC>-<hex>``).
    """
    extra = getattr(ctx, "extra", None) or {}
    if not isinstance(extra, dict):
        return ()
    roots: list[Path] = []
    for raw in _selected_snapshot_roots(ctx, extra):
        try:
            path = Path(raw)
        except (TypeError, ValueError, OSError):
            continue
        if path not in roots:
            roots.append(path)
    for raw in extra.get("snapshot_roots") or ():
        try:
            path = Path(raw)
        except (TypeError, ValueError, OSError):
            continue
        if path not in roots:
            roots.append(path)
    for path in _snapshot_roots_under_backup_dir(ctx):
        if path not in roots:
            roots.append(path)
    # A ``deploy --ssh-target local:<dir>`` writes the verified tree under
    # that directory.  A report (or --log-file) inside it replaced a file
    # AFTER the manifest proved every target byte, turning a rc-0 deploy
    # into a corrupted webroot — and a dry run could replace a pre-existing
    # target file before any rehearsal.  Protect the local target root (and
    # the joined webroot spelling) as a subtree before dispatch.
    ssh_target = extra.get("ssh_target")
    if isinstance(ssh_target, str) and ssh_target.startswith("local:"):
        try:
            from .deploy import LOCAL_TARGET_PREFIX
        except ImportError:  # pragma: no cover — circular-import guard
            LOCAL_TARGET_PREFIX = "local:"
        directory = ssh_target[len(LOCAL_TARGET_PREFIX):] or "."
        try:
            base = Path(directory).resolve()
            targets = [base]
            webroot = getattr(ctx, "webroot", None)
            if isinstance(webroot, str) and webroot:
                if Path(webroot).is_absolute():
                    targets.append(Path(webroot))
                targets.append(base / webroot.lstrip("/"))
            for target in targets:
                if target not in roots:
                    roots.append(target)
        except (OSError, ValueError, TypeError):
            pass
    return tuple(roots)


def _snapshot_roots_under_backup_dir(ctx: Any) -> list[Path]:
    """Every snapshot-shaped directory under ``ctx.backup_dir``.

    Name-only, no manifest read: this is the PROTECTIVE superset, so an
    unselected files snapshot or a retention candidate is protected exactly
    like the selected one.  Both naming families come from their owners
    (``backup.SNAPSHOT_NAME_RE`` and ``files._SNAPSHOT_RE``); nothing here
    re-spells the patterns.
    """
    backup_dir = getattr(ctx, "backup_dir", None)
    if backup_dir is None:
        return []
    try:
        from .backup import SNAPSHOT_NAME_RE
        from .deploy import DEPLOY_MANIFEST_SUBDIR
        from .files import _SNAPSHOT_RE
    except ImportError:  # pragma: no cover — circular-import guard
        return []
    found: list[Path] = []

    def _scan(parent: Path) -> None:
        try:
            entries = list(parent.iterdir())
        except OSError:
            return
        for entry in entries:
            try:
                if not entry.is_dir():
                    continue
            except OSError:
                continue
            if SNAPSHOT_NAME_RE.match(entry.name) \
                    or _SNAPSHOT_RE.match(entry.name):
                found.append(entry)

    try:
        root = Path(backup_dir)
        _scan(root)
        for site_dir in root.iterdir():
            if site_dir.is_dir():
                _scan(site_dir)
        # Verified deploy manifests are rollback/release records too:
        # ``<backup-dir>/deploy/<site>-<stamp>/manifest.json`` has no
        # snapshot-shaped NAME, so the name-only scan above never saw it.
        deploy_root = root / DEPLOY_MANIFEST_SUBDIR
        if deploy_root.is_dir() and deploy_root != root:
            for entry in deploy_root.iterdir():
                if entry.is_dir():
                    found.append(entry)
    except OSError:
        return found
    return found


def report_protected_inputs(ctx: Any) -> tuple[Any, ...]:
    """Every local INPUT a report face must never overwrite for this run.

    THE owner of the complete protected set — ``--zip``, ``--sql``, the
    ``files --from`` local source paths, the effective profile (always,
    including the packaged default), the audit ``--baseline``, and the
    proxy's resolved certificate/key paths.  A report's markdown/twin could
    otherwise replace a file the run reads (R11-P2-15) or the settings/
    profile it loaded or the TLS material proxy needs; the
    CLI pre-dispatch gate, the shared writer and every command emitter all
    read THIS function, so no surface can enumerate a narrower set.

    Baseline exception: ``--baseline prev.json`` may legally be refreshed by
    its own run's new twin (``--report prev.md`` writes prev.md + prev.json);
    only a DIRECT markdown collision with the baseline is refused.  That is
    expressed by :func:`report_refreshable_inputs`.
    """
    extra = getattr(ctx, "extra", None) or {}
    from_paths = extra.get("from_paths") if isinstance(extra, dict) else None
    protected: list[Any] = [getattr(ctx, "zip", None),
                            getattr(ctx, "sql", None)]
    if isinstance(from_paths, (list, tuple)):
        protected.extend(from_paths)
    profile = extra.get("profile") if isinstance(extra, dict) else None
    from .settings import effective_profile_path

    # load() ALWAYS reads the packaged default as its base, even when an
    # explicit --profile overlay is merged over it; both are local inputs.
    profiles: list[Any] = [effective_profile_path(None)]
    if profile is not None:
        profiles.append(profile)
    if isinstance(extra, dict):
        protected.extend(profiles)
        protected.extend((extra.get("baseline"),
                          extra.get("cert_path"), extra.get("key_path")))
        # OUTPUTS the run itself materializes and then reports: a local
        # rehearsal archive and a --re-dump file.  They are not INPUTS, but
        # a --report naming one would replace the run's own deliverable
        # with Markdown after the green log line (R20).  The command body
        # records the actual path before the writer runs.
        outputs = extra.get("protected_outputs")
        if isinstance(outputs, (list, tuple)):
            protected.extend(outputs)
        protected.append(getattr(ctx, "re_dump", None))
        # A restore/files-restore reads its SELECTED snapshot: the manifest
        # is the rollback's integrity record, and a --report naming it (or
        # a payload BENEATH the snapshot root) would invalidate the snapshot
        # the run is restoring from.  The ROOT is the protected unit —
        # report_input_collision treats it as a subtree.  Commands resolve
        # the actual snapshot directory into extra["snapshot_dir"] BEFORE
        # they write their report; a pre-dispatch refusal (a bad --deadline,
        # a malformed input) must resolve the same selection from the
        # arguments, and LIST mode protects every snapshot it will read.
        for root in _selected_snapshot_roots(ctx, extra):
            protected.extend((root, root / "manifest.json"))
        for root in report_protected_subtrees(ctx):
            protected.extend((root, root / "manifest.json"))
    return tuple(protected)


def _snapshot_name_candidate(ctx: Any, value: Any) -> Path | None:
    """The managed/explicit snapshot DIRECTORY named by one CLI reference.

    A bare snapshot name resolves under ``<backup_dir>/<site label>``; an
    explicit path is its own location.  Selection failures (no snapshot,
    an unreadable backup dir) answer ``None``: a refusal writer must never
    turn a missing input into a traceback, and the command body repeats the
    same selection with its own error contract.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        candidate = Path(value)
        if candidate.is_absolute() or "/" in value or "\\" in value:
            return candidate
        from .backup import SNAPSHOT_NAME_RE, sanitize_site_label
        from .backup import site_label as _site_label

        if not SNAPSHOT_NAME_RE.match(value) \
                or not getattr(ctx, "backup_dir", None):
            return None
        return (Path(ctx.backup_dir)
                / sanitize_site_label(_site_label(ctx)) / value)
    except (ImportError, OSError, ValueError, TypeError, AttributeError):
        return None


def _selected_snapshot_roots(ctx: Any, extra: dict[str, Any]) -> list[Path]:
    """Every snapshot root this run READS, resolved without writing anything.

    THE protected-set owner for ``restore``/``files --restore``.  It runs
    both at the CLI's pre-dispatch gate (before any command body exists) and
    in the shared writer after the body has recorded the real directory, so
    every refusal/failure face sees the same roots:

    * an already-recorded ``snapshot_dir`` (the command's own resolution);
    * the ``--snapshot`` / ``files --restore`` argument (managed name,
      ``last``, or an explicit location);
    * ``--undo-last`` — the newest snapshot selection, which the command
      would read and restore;
    * ``restore`` LIST mode (no name, no undo) — every candidate directory
      the listing iterates, including ones it skips after reading their
      manifest.
    """
    roots: list[Path] = []

    def _add(root: Any) -> None:
        if root is None:
            return
        try:
            candidate = Path(root)
        except (TypeError, ValueError, OSError):
            return
        if candidate not in roots:
            roots.append(candidate)

    _add(extra.get("snapshot_dir"))
    for recorded in extra.get("snapshot_roots") or ():
        _add(recorded)
    _add(_snapshot_name_candidate(ctx, extra.get("snapshot")))
    _add(_snapshot_name_candidate(ctx, extra.get("restore")))

    command = getattr(ctx, "command", "")
    if command == "restore":
        try:
            # Directory-name selection only, never a manifest read: the
            # protected set must be resolvable at a PRE-DISPATCH refusal
            # (before the command's own selection runs), and over-protecting
            # a candidate is safe while invoking the command's selection
            # seam here could re-raise its stop/deadline.
            from .restore import _snapshot_dirs

            candidates = _snapshot_dirs(
                Path(ctx.backup_dir), _raw_site_label(ctx))
            if extra.get("undo_last") or not extra.get("snapshot"):
                # --undo-last reads the newest candidate; LIST mode reads
                # every candidate's manifest.  Either way every root the
                # command may read is an input of this run.
                for path in candidates:
                    _add(path)
        except (ImportError, OSError, ValueError, TypeError, AttributeError,
                WptError):
            pass
    elif command == "files" and extra.get("restore") is not None:
        try:
            from .files import _resolve_snapshot

            _add(_resolve_snapshot(ctx, extra.get("restore")))
        except (ImportError, OSError, ValueError, TypeError, AttributeError,
                WptError):
            pass
    return roots


def _raw_site_label(ctx: Any) -> str:
    """The snapshot directory label for one ctx (backup's owner)."""
    from .backup import site_label

    return site_label(ctx)


def report_refreshable_inputs(ctx: Any) -> tuple[Any, ...]:
    """Protected inputs whose ``.json`` twin face may be REFRESHED.

    Only the audit baseline: writing ``prev.json`` from the new run is the
    documented way to advance a baseline, while naming ``prev.json`` itself
    as the report markdown stays refused by
    :func:`report_input_collision`.
    """
    extra = getattr(ctx, "extra", None) or {}
    baseline = extra.get("baseline") if isinstance(extra, dict) else None
    return (baseline,) if baseline is not None else ()


def report_input_collision(report_path: Path | str | None,
                           inputs,
                           *, refreshable=(),
                           json_twin: bool = True,
                           subtrees=()) -> Path | None:
    """The run INPUT a report face would overwrite, or ``None``.

    ``--report`` names an OUTPUT; the protected set is owned by
    :func:`report_protected_inputs`.  A report path that resolves to any of
    them (or to the JSON twin's path) would destroy a file the run is
    reading — including the one case where the damage is silent because the
    read already happened.  ONE predicate for the CLI pre-dispatch gate and
    the shared writer, so a programmatic caller cannot bypass what the CLI
    refuses.

    ``json_twin=False`` says this write produces NO JSON face (a
    markdown-only failure report): the twin cannot overwrite anything it
    never writes.

    ``refreshable`` paths (the audit baseline) are compared only as the
    DIRECT markdown face: their JSON twin is the next baseline the run is
    legitimately producing.

    Returns the PROTECTED input path, not the report alias: the diagnostic
    must name what would be destroyed (a symlinked ``--report`` otherwise
    read "resolves to this run's input <the alias itself>").
    """
    if report_path is None:
        return None
    try:
        faces = [Path(report_path)]
        if json_twin:
            faces.append(faces[0].with_suffix(".json"))
    except (ValueError, OSError):
        return None
    resolved: list[tuple[Path, Path, Path]] = []
    for candidate in faces:
        try:
            # ``resolve()`` catches a symlink whose TARGET is an input (the
            # historical check).  ``landing`` catches the opposite shape:
            # BOTH report faces are symlinks to outside files, so neither
            # resolves under a protected snapshot/deploy target even though
            # the directory entries themselves live INSIDE it.  Writing the
            # pair replaced the links and put the report into the target.
            landing = candidate.parent.resolve() / candidate.name
            resolved.append((candidate, candidate.resolve(), landing))
        except (OSError, RuntimeError):
            continue
    subtree_resolved: set[Path] = set()
    for raw in subtrees:
        if raw is None:
            continue
        try:
            subtree_resolved.add(Path(raw).resolve())
        except (OSError, RuntimeError):
            continue
    refreshable_resolved: set[Path] = set()
    for raw in refreshable:
        if raw is None:
            continue
        try:
            refreshable_resolved.add(Path(raw).resolve())
        except (OSError, RuntimeError):
            continue
    best: Path | None = None
    best_depth = -1
    for raw in inputs:
        if raw is None:
            continue
        try:
            protected = Path(raw).resolve()
        except (OSError, RuntimeError):
            continue
        for index, (_candidate, target, landing) in enumerate(resolved):
            # A protected SNAPSHOT ROOT is a subtree: replacing any face at
            # or beneath it (manifest.json, a files/ payload) destroys the
            # rollback basis exactly like replacing the root itself.  The
            # manifest is the marker that makes a directory a snapshot — a
            # zip path that happens to be a directory is still a FILE input
            # (exact only).
            # A RECORDED root is a subtree unconditionally: a selected
            # corrupt/manifest-less snapshot still has payloads and a path
            # identity the run is reading.  The manifest marker remains the
            # fallback for callers that pass only plain inputs.
            is_snapshot_root = (
                protected in subtree_resolved
                or (protected.is_dir()
                    and (protected / "manifest.json").is_file()))
            # Check the symlink TARGET and the directory entry's landing
            # path: a pair of links pointing outside still lands INSIDE the
            # protected tree when the writer replaces them.
            if not any(
                face == protected
                or (is_snapshot_root and face.is_relative_to(protected))
                for face in (target, landing)
            ):
                continue
            if index == 1 and protected in refreshable_resolved:
                # prev.json + prev.md refresh: the new twin IS the baseline.
                continue
            # Name the DEEPEST protected path: an exact manifest hit is the
            # diagnostic, while a payload beneath an otherwise-unknown root
            # names the snapshot directory.
            if len(protected.parts) > best_depth:
                best = Path(raw)
                best_depth = len(protected.parts)
    return best


def non_regular_target_problem(path: Path) -> str | None:
    """Why an existing output target is not a REGULAR file, or None.

    A report (or its JSON twin) must never rename away a FIFO, device node
    or directory: ``os.replace`` moved a FIFO to the backup name and then
    deleted it, so the operator's special file vanished and the report
    landed in its place.  A nonexistent path and a symlink TO a regular file
    stay allowed; a symlink to a directory is a directory for this rule.
    """
    try:
        if (path.exists() or path.is_symlink()) and not path.is_file():
            return f"output target {path} is not a regular file"
    except OSError as exc:
        return f"cannot inspect output target {path}: {exc}"
    return None


def report_hardlink_problem(target: Path | str | None,
                            protected_paths=()) -> str | None:
    """Why an output path is a HARDLINK alias of a protected input, or None.

    Path resolution is not inode identity: ``os.link(zip, "looks.log")`` is
    a different path, so the ``--log-file`` gate accepted it and appended
    log bytes INTO the zip.  Compare ``(st_dev, st_ino)`` against every
    protected input and refuse a pre-existing target whose ``st_nlink`` is
    greater than one: with several names for one inode this process cannot
    prove the other name is not a snapshot payload it must not modify.
    The test is on the RESOLVED inode (``stat`` follows a symlink), never
    skipped for a symlink: a link to a hardlinked payload is the same
    corruption as the direct spelling.  A nonexistent target has no link to
    prove and stays allowed (a created log file has one name).
    """
    if target is None:
        return None
    try:
        path = Path(target)
        info = path.stat()
    except FileNotFoundError:
        return None
    except (TypeError, ValueError, OSError) as exc:
        return f"cannot inspect output target {target!r}: {exc}"
    for protected in protected_paths:
        try:
            other = Path(protected).stat()
        except (TypeError, ValueError, OSError):
            continue
        if (info.st_dev, info.st_ino) == (other.st_dev, other.st_ino):
            return (f"output target {path} is the same inode as this run's "
                    f"input {protected}; a hardlink alias would overwrite "
                    "the input it reads")
    if info.st_nlink > 1:
        return (f"output target {path} has {info.st_nlink} hardlinks; this "
                "run cannot prove it is not a protected input or snapshot "
                "payload")
    return None


def report_output_problem(report_path: Path | str | None) -> str | None:
    """Why ``report_path`` cannot be a report OUTPUT, or None.

    ONE owner for the output-shape refusal shared by the CLI's pre-dispatch
    gate and :func:`write_report_files`.  Checking it BEFORE dispatch is
    what keeps a mutating apply from running and then discovering that the
    report it promised can never be written (``clean-files --apply`` used to
    materialize a rehearsal zip and only then refuse ``out.json``).

    BOTH faces are inspected: the markdown target and its derived ``.json``
    twin.  A twin that exists as a directory made the pre-dispatch gate
    accept a report the writer could never publish, after a local apply had
    already materialized its rehearsal zip.
    """
    if report_path is None:
        return None
    try:
        path = Path(report_path)
    except (TypeError, ValueError, OSError) as exc:
        return f"invalid report path {report_path!r}: {exc}"
    if path.suffix.lower() == ".json":
        return (f"refusing a .json report path ({path}): the JSON twin would "
                "overwrite the markdown report; name the markdown path instead")
    try:
        faces = (path, path.with_suffix(".json"))
    except (ValueError, OSError) as exc:
        return f"cannot derive the JSON twin path for {path}: {exc}"
    for face in faces:
        problem = non_regular_target_problem(face)
        if problem is not None:
            return problem
    return None


def report_output_alias_problem(
    target: Path | str | None, report_path: Path | str | None
) -> str | None:
    """Why ``target`` is the report's markdown face or JSON twin, or None.

    ``--log-file run.md --report run.md`` opened the log first and then the
    report writer put the markdown over it (the run-start line vanished);
    ``--log-file run.json`` did the same to the twin.  Path resolution and,
    when both exist, ``(st_dev, st_ino)`` identity cover symlink and
    hardlink spellings that plain string comparison misses.
    """
    if target is None or report_path is None:
        return None
    try:
        path = Path(target)
        report = Path(report_path)
        faces = (report, report.with_suffix(".json"))
    except (TypeError, ValueError, OSError) as exc:
        return f"cannot compare output paths: {exc}"
    try:
        info = path.stat()
    except OSError:
        info = None
    for face in faces:
        try:
            same = path.resolve() == face.resolve()
        except (OSError, RuntimeError):
            same = False
        if not same:
            try:
                other = face.stat()
            except OSError:
                other = None
            same = (info is not None and other is not None
                    and (info.st_dev, info.st_ino)
                    == (other.st_dev, other.st_ino))
        if same:
            return (f"output target {path} is the report face {face}; the "
                    "log and the report cannot share one file")
    return None


def report_parent_problem(report_path: Path | str | None) -> str | None:
    """Why ``report_path``'s parent cannot receive a report file, or None.

    The writer's historical contract answers a missing parent with
    ``OSError`` (the temp-file open fails); the CLI uses this before dispatch
    so a mutating apply never runs only to discover the report is unwritable.
    """
    if report_path is None:
        return None
    staged: list[tuple[Path, Path]] = []
    handle: Any = None
    try:
        path = Path(report_path)
        parent = path.parent
        if not parent.is_dir():
            return f"report target {path} has no existing parent directory"
        # ``is_dir`` says nothing about WRITE access: an apply used to run
        # (and materialize its rehearsal archive) before the writer failed
        # on a 0555 parent.  A same-prefix temp create+unlink proves the
        # exact operation the writer will perform, including NAME_MAX for
        # this report's basename.  One probe covers BOTH faces: the twin
        # shares the stem and suffix length.  The helper journals the name
        # before creating it, so a stop on the creation boundary cannot
        # leave an unreferenced probe temp behind.
        probe, handle = _stage_report_temp(path, ".tmp", staged)
        handle.close()
        handle = None
        probe.unlink()
        staged.clear()
    except (TypeError, ValueError, OSError) as exc:
        return f"report target {report_path!r} cannot be written: {exc}"
    finally:
        if handle is not None:
            try:
                handle.close()
            except OSError:
                pass
        for probe, _target in staged:
            try:
                probe.unlink()
            except OSError:
                pass
    return None


def _stage_report_temp(target: Path, suffix: str,
                       staged: list[tuple[Path, Path]], *,
                       journal_entry: dict[str, Any] | None = None):
    """Journal a temp name BEFORE creating it, then open it exclusively.

    ``NamedTemporaryFile`` returned a name that only entered the journal
    afterwards: a stop on that boundary left an unreferenced ``.tmp``/``.bak``
    no finally could remove.  The candidate is recorded first (``staged``
    for the writer's finally; ``journal_entry['backup']`` for the rollback
    journal), then created with ``O_CREAT|O_EXCL|O_NOFOLLOW``.  A stop
    anywhere from the name choice through the open therefore leaves a
    record that cleanup can unlink; a populated backup is preserved by the
    rollback/success logic, never by this helper.
    """
    for _ in range(100):
        candidate = target.parent / (
            f".{target.name}.{secrets.token_hex(16)}{suffix}")
        staged.append((candidate, target))
        if journal_entry is not None:
            journal_entry["backup"] = candidate
        try:
            fd = os.open(
                candidate,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600)
        except FileExistsError:
            staged.remove((candidate, target))
            if journal_entry is not None:
                journal_entry["backup"] = None
            continue
        return candidate, os.fdopen(
            fd, "w", encoding="utf-8", errors="backslashreplace")
    raise OSError(
        f"cannot reserve a temp file beside report target {target}")


def write_report_files(report_path: Path | str, markdown: str,
                       json_text: str | None = None, *,
                       protected_paths=(),
                       refreshable_paths=(),
                       protected_subtrees=()) -> None:
    """Write a report's markdown face and optional JSON twin to disk.

    ONE owner for the report-write contract every command shares:

    * a report path (or its JSON twin) that resolves to one of
      ``protected_paths`` — the run's local INPUTS, owned by
      :func:`report_protected_inputs` — is REFUSED before any bytes move: a
      report must never replace the archive/dump/files-source/profile it
      read, and a baseline's direct markdown face is refused while its twin
      refresh is legal (``refreshable_paths``);
    * a ``.json`` report path is REFUSED: the JSON twin is
      ``<stem>.json``, so naming the markdown path with that suffix would
      silently replace the table with the twin.  Every emitter (audit,
      backup, restore, walk, actions) goes through this one door, so none
      can accept the path and lose the markdown face;
    * UTF-8 with ``backslashreplace``: a site-controlled lone surrogate
      (bridge/probe JSON, argv decoded with surrogateescape, a tar member
      name) must become the visible text ``\\udcff``, never a
      ``UnicodeEncodeError`` after the run already mutated the site;
    * each face is fully written to a sibling TEMP file and only then
      ``os.replace``d into place.  A strict encoder used to truncate the
      target to zero bytes before raising; a failed write now leaves the
      previous report intact instead of a 0-byte or half-written twin.

    WptError (the ``.json`` refusal), OSError and UnicodeError propagate;
    the command's normal error contract answers rc 1.  The temp names are
    removed on every failure path.
    """
    path = Path(report_path)
    collision = report_input_collision(
        path, protected_paths, refreshable=refreshable_paths,
        json_twin=json_text is not None, subtrees=protected_subtrees)
    if collision is not None:
        raise WptError(
            f"refusing report path {collision}: it is an input of this run "
            "(the report would overwrite an input being read)")
    # THE report bytes cross the redaction owner before they touch disk:
    # every command's `--report` surface (audit, walk, verify, restore,
    # backup, doctor, deploy, actions) writes through this ONE function, so
    # a URL userinfo or a secret that reached a renderer can never survive
    # into the file an operator keeps and shares.
    markdown = redact_text(markdown)
    if json_text is not None:
        json_text = _redact_json_text(json_text)
    try:
        targets = [(path, markdown)]
        if json_text is not None:
            targets.append((path.with_suffix(".json"), json_text))
    except (ValueError, OSError) as exc:
        # ``Path(".").with_suffix`` / ``Path("/")`` raise ValueError; a
        # caller's bad --report must be the shared writer's one-line
        # refusal (rc 1), never a traceback.
        raise WptError(
            f"cannot derive the JSON twin path for {path}: {exc}") from exc
    problem = report_output_problem(path)
    if problem is not None:
        raise WptError(problem)
    parent_problem = report_parent_problem(path)
    if parent_problem is not None:
        raise OSError(parent_problem)
    staged: list[tuple[Path, Path]] = []
    #: Every in-flight publish, appended BEFORE the first move of either
    #: face.  A stop injected at temp creation, at the backup rename or at
    #: the publish itself must still leave no mixed pair/.tmp/.bak behind.
    journal: list[dict[str, Any]] = []
    #: The first cooperative stop raised by a CLEANUP unlink.  Every
    #: removal is still attempted; it is re-raised after the finally when
    #: no primary failure is already unwinding.
    cleanup_stop: BaseException | None = None
    primary = False
    try:
        for target, text in targets:
            temp, handle = _stage_report_temp(target, ".tmp", staged)
            # Registered BEFORE writing (inside the helper): a stop inside
            # write/fsync used to leave it behind because registration
            # happened after creation.
            try:
                with handle:
                    handle.write(text)
                    handle.flush()
                    os.fsync(handle.fileno())
            except BaseException:
                _unlink_quietly(temp)
                staged.remove((temp, target))
                raise
        # Preflight BOTH faces before publishing anything: a directory (or
        # any non-regular target: FIFO, device) must fail the run while the
        # previous pair is still intact, never after the markdown has
        # already landed.
        for _temp, target in staged:
            problem = non_regular_target_problem(target)
            if problem is not None:
                raise WptError(problem)
        # JSON TWIN FIRST, markdown last: a failure publishing the twin
        # cannot leave a NEW success markdown beside rc 1.  Each replaced
        # face keeps its previous bytes in a sibling backup until BOTH
        # faces are in place, so a later failure restores the old pair.
        for temp, target in reversed(staged):
            entry: dict[str, Any] = {
                "target": target,
                "temp": temp,
                "backup": None,
                "old_moved": False,
                "new_moved": False,
            }
            journal.append(entry)
            backup: Path | None = None
            if target.exists() or target.is_symlink():
                # The candidate name enters the journal BEFORE the file is
                # created, so a stop at (or inside) the creation boundary is
                # rollback-owned.  The throwaway staging list is deliberate:
                # once old bytes move here the backup's keeper is the
                # rollback/success logic, never a blanket cleanup.
                backup, handle = _stage_report_temp(
                    target, ".bak", [], journal_entry=entry)
                try:
                    handle.close()
                except BaseException:
                    # The journal already names the (empty) backup; rollback
                    # removes it when neither face moved.  The target is
                    # intact.
                    raise
                try:
                    os.replace(target, backup)
                except BaseException:
                    # A stop can arrive AFTER the move completed.  The old
                    # bytes are then in ``backup`` and the target is gone;
                    # unlinking the backup would destroy the only copy.
                    if backup.exists() and not target.exists():
                        entry["old_moved"] = True
                    else:
                        _unlink_quietly(backup)
                        entry["backup"] = None
                    raise
                entry["old_moved"] = True
            os.replace(temp, target)
            entry["new_moved"] = True
    except BaseException:
        primary = True
        # A StopRequested can arrive AFTER ``os.replace`` completed but
        # BEFORE the flag assignment (the move is no longer undoable by
        # re-reading the flags).  Infer the move from the filesystem:
        # the target is absent => the old face went to ``backup``; the
        # temp is absent => the new face is published.  Compositional
        # flags without this inference deleted the only copy of the old
        # bytes or left a mixed pair after a post-move signal.
        for entry in journal:
            target = entry["target"]
            backup = entry["backup"]
            temp = entry.get("temp")
            try:
                if not entry["old_moved"] and backup is not None \
                        and not target.exists() and backup.exists():
                    entry["old_moved"] = True
                if not entry["new_moved"] and temp is not None \
                        and not Path(temp).exists():
                    entry["new_moved"] = True
            except OSError:
                pass
        # Restore every face already touched, newest first.  Each step is
        # attempted independently (a second stop during rollback must not
        # leave an earlier face mixed); the ORIGINAL exception then
        # propagates unchanged.
        _rollback_report_journal(journal)
        raise
    else:
        for entry in journal:
            backup = entry["backup"]
            if backup is not None:
                stop = _unlink_quietly(backup)
                cleanup_stop = cleanup_stop or stop
    finally:
        for temp, _target in staged:
            stop = _unlink_quietly(temp)
            cleanup_stop = cleanup_stop or stop
        if not primary and cleanup_stop is not None:
            # Cleanup is complete; the stop is the run's verdict.  Raise it
            # HERE so the dispatch boundary writes the failure pair and
            # returns rc 1 (the pair on disk is already fully published).
            raise cleanup_stop


def _unlink_quietly(path: Path) -> BaseException | None:
    """Remove one temp/backup/residue path; return a RunControl, never raise.

    Cleanup must attempt EVERY removal (one stop cannot skip the next), but
    a ``StopRequested``/``DeadlineExceeded`` raised inside ``unlink`` is the
    run's verdict: swallowing it here let a post-receipt SIGTERM vanish
    while the listener kept serving.  The caller finishes all removals and
    re-raises the first RunControl AFTER cleanup (and never in place of a
    primary failure).
    """
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except RunControl as exc:
        # The stop interrupted THIS removal: retry it once so cleanup is
        # finished (the signal is already captured as the verdict).  A
        # second stop leaves the residue named, never a crash.
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except BaseException as retry:  # noqa: BLE001 — preserve the stop
            log.warning("report residue %s could not be removed: %s",
                        path, retry)
        log.warning("report residue %s cleanup was interrupted: %s", path, exc)
        return exc
    except BaseException as exc:  # noqa: BLE001 — cleanup must finish
        log.warning("report residue %s could not be removed: %s", path, exc)
    return None


def _rollback_report_journal(journal: list[dict[str, Any]]) -> None:
    """Undo every recorded publish attempt, never stopping at a second stop.

    The journal is written BEFORE each move, so an entry may describe a
    backup that was created but never moved, a target whose old bytes are
    in ``backup``, or a face already published.  Each face is restored
    independently: a ``RunControl`` raised by the first restore must not
    abandon the rest, and the caller re-raises the PRIMARY failure.
    """
    for entry in reversed(journal):
        target: Path = entry["target"]
        backup: Path | None = entry["backup"]
        try:
            if entry["new_moved"]:
                if backup is not None and entry["old_moved"]:
                    os.replace(backup, target)
                    backup = None
                else:
                    target.unlink(missing_ok=True)
            elif entry["old_moved"] and backup is not None:
                os.replace(backup, target)
                backup = None
        except BaseException as exc:  # noqa: BLE001 — finish every face
            log.warning("report rollback failed for %s: %s", target,
                        redact_text(str(exc)))
        if backup is not None and not entry["old_moved"]:
            # The backup was RESERVED (journaled before creation) but the
            # old face was never moved into it: the file is empty/missing,
            # not "previous bytes".  A stop between the reservation and the
            # move used to leave that empty .bak behind while logging that
            # it held the old report.
            _unlink_quietly(backup)
            backup = None
        if backup is not None:
            # The restore move did NOT happen.  Keeping the .bak is better
            # than deleting the only copy of the previous bytes: a second
            # stop during this rollback used to unlink it unconditionally
            # and lose the old report (R15-P2).  A .bak residue is named in
            # the warning above and is recoverable by hand.
            log.warning("report rollback kept the previous bytes at %s "
                        "(the original face could not be restored)",
                        backup)


#: Ordered category-prefix -> (action, why) suggestions, evaluated
#: first-match-wins (dotted prefix) over each finding's category. ``action``
#: is a ``wpt`` command the operator can run verbatim, or advice text when
#: no command safely applies. Families (webroot / db-cleanup / harden /
#: updates) repeat one (action, why) across their categories so they render
#: as ONE line whenever any member matched.
SUGGESTED_STEPS: tuple[tuple[str, str, str], ...] = (
    # Compromise first: heal the PROVEN core changes (checksum-verified,
    # official-release restore, snapshot first) — but healing core does
    # NOT clean a compromise (backdoors in plugins/uploads survive it);
    # the step keeps the investigate caveat in its why.
    ("core.integrity", "wpt heal-core --apply",
     "restores checksum-proven tampered/missing core files from the "
     "official WP release (snapshot first; still INVESTIGATE — healing "
     "core does not remove backdoors elsewhere), and never touches the "
     "'added' files it lists"),
    ("security.suspicious", "investigate/quarantine",
     "executable code matched a backdoor signature — a candidate, not a "
     "verdict; compare the affected file with a clean copy, or the site "
     "itself for core files, before restoring"),
    # One command per cleanup family.
    ("webroot.junk", "wpt clean-files --apply",
     "removes the junk/backup/stale/migration leftovers the audit found"),
    ("webroot.junk_recurring", "wpt clean-files --apply",
     "removes the junk/backup/stale/migration leftovers the audit found"),
    ("webroot.stale", "wpt clean-files --apply",
     "removes the junk/backup/stale/migration leftovers the audit found"),
    ("webroot.migration", "wpt clean-files --apply",
     "removes the junk/backup/stale/migration leftovers the audit found"),
    # Informational only — clean-files never touches mu-plugins (no junk
    # pattern matches them); the operator decides against the platform.
    ("webroot.mu_plugins",
     "review the hosting-platform must-use plugins; remove them if the "
     "site left that platform",
     "platform mu-plugins run on every request and are invisible to "
     "normal plugin management"),
    ("db.revisions", "wpt clean-db --apply",
     "plans only the ops these same findings trigger: revisions, expired "
     "transients, orphan meta, optimize"),
    ("db.transients", "wpt clean-db --apply",
     "plans only the ops these same findings trigger: revisions, expired "
     "transients, orphan meta, optimize"),
    ("db.orphan_meta", "wpt clean-db --apply",
     "plans only the ops these same findings trigger: revisions, expired "
     "transients, orphan meta, optimize"),
    ("db.optimize", "wpt clean-db --apply",
     "plans only the ops these same findings trigger: revisions, expired "
     "transients, orphan meta, optimize"),
    ("media.unreferenced", "wpt trim-media --apply",
     "deletes only walk-verified unreferenced files; run `wpt verify` "
     "afterwards to re-check every live reference"),
    # Reversible plugin decisions — review first, never a blind delete.
    ("plugins.inactive", "wpt deactivate-plugin <slug>",
     "deactivates with an options-table snapshot first — review, then "
     "reactivate or remove in wp-admin"),
    ("plugins.duplicate", "wpt deactivate-plugin <slug>",
     "keep one of the duplicates, deactivate the rest (snapshot first)"),
    ("plugins.heavy", "review whether each heavy plugin is still needed",
     "heavy plugins run on every request — deactivate what you do not need"),
    # Findings with no automated action: advice only.
    ("db.ghost_tables", "review, then `wpt backup` before any manual DROP",
     "ghost tables may belong to something still installed — verify "
     "ownership before dropping"),
    ("db.autoload", "review; de-autoload or delete unused options",
     "clean-db has no autoload op — wp_options needs a manual pass"),
    ("db.charset",
     "ALTER TABLE ... CONVERT TO CHARACTER SET utf8mb4 (back up first)",
     "a non-utf8mb4 table corrupts accents/emoji and blocks clean migrations"),
    ("db.admin_accounts",
     "rename the default 'admin' account (new admin, reassign, delete old)",
     "the default login is the single biggest brute-force magnet"),
    # Active-but-missing plugins: no wpt command reinstalls plugin code —
    # the operator restores the files (complete export / reinstall), or
    # resolves the DB side of it when the plugin is gone for good.
    ("db.active_missing",
     "restore the missing plugin directories from a complete export or "
     "reinstall them",
     "a site with active-but-missing plugins fatals or silently loses "
     "functionality — no wpt command can reinstall plugin code; if the "
     "plugin is gone for good, `wpt reconcile-plugins --apply` drops the "
     "dead entries from active_plugins (options snapshot first), which "
     "stops the fatals but does not bring the functionality back"),
    # harden-able security findings — exactly what wpt/actions/harden.py
    # implements (its docstring is the scope owner).
    ("security.disallow_file_edit", "wpt harden --apply",
     "writes the missing .htaccess/wp-config hardening lines "
     "(diff-printed, idempotent)"),
    ("security.https_redirect", "wpt harden --apply",
     "writes the missing .htaccess/wp-config hardening lines "
     "(diff-printed, idempotent)"),
    ("security.xmlrpc", "wpt harden --apply",
     "writes the missing .htaccess/wp-config hardening lines "
     "(diff-printed, idempotent)"),
    ("security.rest_users", "wpt harden --apply",
     "writes the missing .htaccess/wp-config hardening lines "
     "(diff-printed, idempotent)"),
    ("security.author_scan", "wpt harden --apply",
     "writes the missing .htaccess/wp-config hardening lines "
     "(diff-printed, idempotent)"),
    ("security.uploads_listing", "wpt harden --apply",
     "writes the missing .htaccess/wp-config hardening lines "
     "(diff-printed, idempotent)"),
    # Manual / hoster territory (documented out of harden's v1 scope).
    ("security.source_patterns",
     "review each named sink; parameterize SQL, allowlist request-driven "
     "session IDs/includes, and escape reflected request data",
     "the source-only scan names dangerous data flows (a heuristic, not a "
     "parser verdict) — fix the sink in the application, then re-run "
     "`wpt scan`"),
    ("security.uploads_perms",
     "chmod 755 directories / 644 files under wp-content/uploads "
     "(or ask the host to fix the account umask)",
     "world-writable upload paths let any local account replace media or "
     "drop executable content; wpt does not change file modes"),
    ("security.wp_config_perms",
     "chmod 0600 wp-config.php (by hand or panel)",
     "file permissions are outside wpt's write path"),
    ("security.debug_log",
     "delete wp-content/debug.log and disable WP_DEBUG",
     "exposed debug output can leak paths and credentials"),
    ("security.www_apex",
     "redirect www to the apex host (panel or manual .htaccess)",
     "a duplicate host is an SEO and stale-cert risk"),
    ("security.cert_mismatch",
     "install a matching certificate (e.g. Let's Encrypt) once DNS points here",
     "certificate issuance is a hoster/DNS action, not a webroot edit"),
    ("security.php_version",
     "switch the hoster's PHP selector to a supported version",
     "an EOL runtime only receives security fixes on newer minors"),
    ("security.relocate",
     "delete the RELOCATE line from wp-config.php (by hand)",
     "RELOCATE lets wp-login.php rewrite siteurl; it is migration-only"),
    # An unexplained top-level PHP file: no wpt command removes it (prune-core
    # works only inside the core dirs, clean-files only its own junk
    # patterns), so the operator triages and deletes it by hand [D2].
    ("security.web_exposed_script",
     "triage the file read-only (head -c 400, grep -nE 'token|hash_equals|"
     "$_(GET|POST|REQUEST)', stat -c %y), then rm it",
     "an unknown top-level PHP file carrying a token gate or a home-directory "
     "walk is served to anyone and is either an attacker's dropper or a "
     "forgotten operator probe — both must leave the docroot, and wpt has "
     "no action that removes a webroot-top-level file"),
    # Updates: wp-admin is the v1 path (apply-updates is roadmap).
    ("updates.core", "wpt backup, then update via wp-admin",
     "wpt does not apply updates in v1 — snapshot first, update in wp-admin"),
    ("updates.plugins", "wpt backup, then update via wp-admin",
     "wpt does not apply updates in v1 — snapshot first, update in wp-admin"),
    ("updates.themes", "wpt backup, then update via wp-admin",
     "wpt does not apply updates in v1 — snapshot first, update in wp-admin"),
)

#: Per-NAME overrides inside a category whose findings mean very
#: different operator actions [L16: the new low-risk "added-known"
#: finding shares core.integrity with the high-risk "core-files" proof
#: — suggesting heal-core for a known plugin artifact is noise, and
#: suggesting nothing for tampered core files is dangerous].  A pinned
#: (category, name) renders ITS (action, why) at the matched rule's
#: priority instead of the rule's own; findings of the same category
#: without a pin keep the rule verbatim.  Keyed on the exact dotted
#: category + finding name — never a prefix.
_NAME_PINS: dict[tuple[str, str], tuple[str, str]] = {
    ("security.source_patterns", "scan-partial"): (
        "re-run wpt scan with a larger --deadline or after restoring "
        "the FTP channel",
        "the scan was truncated; its findings cover only the files it "
        "actually read, not a clean tree",
    ),
    ("core.integrity", "added-known"): (
        "verify the file against a freshly installed copy of the named plugin",
        "the finding is a known plugin-deployed artifact (low risk) — no "
        "tampered or missing core file exists, so heal-core has nothing "
        "to restore here",
    ),
    # An unverifiable wp-config constant is deliberately NOT harden-able:
    # when either constant is decided at runtime, harden refuses rather than
    # rewrite one and report a hardening it cannot prove, so advising
    # `wpt harden --apply` here would send the operator to a no-op.
    ("security.disallow_file_edit", "disallow-file-edit-unverifiable"): (
        "set DISALLOW_FILE_EDIT unconditionally in wp-config.php (by hand)",
        "the value is computed at runtime, so wpt harden will not rewrite it",
    ),
}


def _step_matches(prefix: str, category: str) -> bool:
    """Dotted-prefix rule match: exact or a ``prefix.`` continuation.

    "webroot.junk" therefore never matches "webroot.junk_recurring" — the
    same semantics as the audit registry's selectors.
    """
    return category == prefix or category.startswith(f"{prefix}.")


def suggested_step_for(category: str) -> tuple[str, str] | None:
    """First-match-wins (action, why) for a finding category.

    None when no rule matches — that category renders nothing by design.
    """
    for prefix, action, why in SUGGESTED_STEPS:
        if _step_matches(prefix, category):
            return action, why
    return None


def suggested_steps(findings: list[Finding]) -> list[dict[str, str]]:
    """The deduplicated next-step plan for a finding set.

    One ``{"action", "why"}`` entry per matched rule in MAPPING (priority)
    order — never in finding order — with rules sharing an identical
    (action, why) collapsed to one entry. Severity never changes the
    suggestion; a ``_NAME_PINS`` override swaps in its own (action, why)
    at the matched rule's priority [L16]. Returns [] when no finding's
    category matches a rule.
    """
    matched: set[tuple[int, int, str, str]] = set()
    for finding in findings:
        pin = _NAME_PINS.get((finding.category, finding.name))
        for index, (prefix, action, why) in enumerate(SUGGESTED_STEPS):
            if _step_matches(prefix, finding.category):
                if pin is not None:
                    # pinned advice renders at the rule's priority but
                    # AFTER the rule itself (is_pin sort flag)
                    matched.add((index, 1, pin[0], pin[1]))
                else:
                    matched.add((index, 0, action, why))
                break
    steps: list[dict[str, str]] = []
    emitted: set[tuple[str, str]] = set()
    for _index, _is_pin, action, why in sorted(matched):
        if (action, why) in emitted:
            continue
        emitted.add((action, why))
        steps.append({"action": action, "why": why})
    return steps


# ---------------------------------------------------------------- site facts


def _optional_fact(data: Any, name: str) -> str | None:
    """One OPTIONAL AuditData fact, or None when the gather lacks it.

    ``siteurl``/``home``/``wp_version``/``locale``/``template`` and the
    rest are AuditData fields today; ``blogname`` and ``db_version`` are
    the two the data layer does not map yet (the option / ``$wpdb``
    value), so they are read defensively and simply omitted while the
    gather carries nothing.  A value that is not a usable non-empty
    string is unknown, never rendered as-is.
    """
    value = getattr(data, name, None)
    return value if isinstance(value, str) and value else None


def site_facts_present(facts: Any) -> bool:
    """True when the fact set carries at least one RENDERABLE fact.

    The ONE presence rule, shared by the markdown section, the JSON twin
    and the builder: an absent/None/empty set, a set of empty lists, or a
    set whose every value is unknown renders NOTHING — a run that
    gathered no facts gets a report byte-identical to the one that never
    heard of the section, never a header over an empty table.
    """
    if not isinstance(facts, dict) or not facts:
        return False
    if any(facts.get(name) is not None for name, _label in SITE_SCALAR_FACTS):
        return True
    theme = facts.get("theme")
    if isinstance(theme, dict) and theme.get("slug"):
        return True
    return any(facts.get(key) for key in
               ("plugins", "users", "posts", "tables"))


def site_facts(data: "AuditData") -> dict[str, Any] | None:
    """The report's site facts from a gathered ``AuditData``, or None.

    The ONE builder: the markdown section and the JSON twin both render
    what it returns, so neither can show a fact the other lacks.  Shape::

        {"blogname": str, "siteurl": str, "home": str,
         "wp_version": str, "db_version": str, "locale": str,
         "theme": {"slug": str, "version": str | None},
         "plugins": [{"slug", "version"}],      # ACTIVE plugins
         "users": [{"login", "email", "role"}],  # admin/author roster
         "posts": [{"type", "status", "count"}],
         "tables": [{"name", "rows", "size_bytes"}]}

    Unknown scalars are ABSENT keys (never a placeholder), an unknown
    list element field is None, and an empty list is omitted — so
    "omitted everywhere" is the single shape for "not gathered".  Every
    list is sorted, so the same site always renders the same bytes.

    Source mapping (the audit data layer is the owner; this reads it
    structurally and imports nothing, so the report stays independent of
    the audit's gatherers):

    * scalars — the WP options / bridge ``info`` facts.  ``db_version``
      is the WordPress DB schema version, not the engine version;
    * theme — the ACTIVE theme.  ``stylesheet`` when the gather carries
      it (the option whose value is the theme actually rendering; WP
      stores the PARENT in ``template``), else ``template``, with the
      version from the gather's style.css header read
      (``theme_versions``) when known;
    * plugins — the ACTIVE plugins, one row each, version from the
      remote plugin catalog when it carries one (a local dump cannot:
      its version is None, never a guess);
    * users — the gathered privileged-account roster, each entry's
      ``email``/``role`` when the entry carries them (the data layer's
      entries are ``{login, registered, admin}`` today, so both render
      as unknown rather than being invented);
    * posts — the audit's own posts-by-(type, status) counts;
    * tables — the gathered table inventory, largest first (ties by
      name), so the DB summary answers "where did the measured bytes go?".
    """
    facts: dict[str, Any] = {}
    for name, _label in SITE_SCALAR_FACTS:
        value = _optional_fact(data, name)
        if value is not None:
            facts[name] = value
    slug = _optional_fact(data, "stylesheet") or _optional_fact(data, "template")
    if slug is not None:
        versions = getattr(data, "theme_versions", None) or {}
        facts["theme"] = {
            "slug": slug,
            "version": versions.get(slug) or None,
        }
    catalog = getattr(data, "plugin_catalog", None) or {}
    active = [path for path in (getattr(data, "active_plugins", None) or [])
              if isinstance(path, str) and path]
    plugins = [
        {
            "slug": path.split("/")[0],
            "version": _catalog_version(catalog, path),
        }
        for path in sorted(set(active))
    ]
    if plugins:
        facts["plugins"] = plugins
    users = [
        {
            "login": entry.get("login", ""),
            "email": entry.get("email") or None,
            "role": entry.get("role") or None,
        }
        for entry in (getattr(data, "admin_users", None) or [])
        if isinstance(entry, dict) and entry.get("login")
    ]
    if users:
        facts["users"] = sorted(users, key=lambda u: str(u["login"]))
    posts = [
        {"type": post_type, "status": status, "count": count}
        for (post_type, status), count in (getattr(data, "posts", None) or {}).items()
    ]
    if posts:
        facts["posts"] = sorted(posts, key=lambda p: (p["type"], p["status"]))
    tables = [
        {
            "name": name,
            "rows": getattr(fact, "rows", 0),
            "size_bytes": getattr(fact, "size_bytes", None),
        }
        for name, fact in (getattr(data, "tables", None) or {}).items()
    ]
    if tables:
        facts["tables"] = sorted(
            tables,
            key=lambda t: (-(t["size_bytes"] or 0), str(t["name"])),
        )
    if not site_facts_present(facts):
        return None
    log.info(
        "report site facts: scalars=%d plugins=%d users=%d posts=%d tables=%d",
        len([k for k, _l in SITE_SCALAR_FACTS if k in facts]),
        len(facts.get("plugins", [])), len(facts.get("users", [])),
        len(facts.get("posts", [])), len(facts.get("tables", [])),
    )
    return facts


def _catalog_version(catalog: Any, path: str) -> str | None:
    """The plugin file's version from the remote catalog, or None.

    The catalog is keyed by plugin FILE ("akismet/akismet.php"), which is
    exactly the active_plugins entry — no slug matching, so a plugin
    whose file path is unusual still resolves.
    """
    entry = catalog.get(path) if isinstance(catalog, dict) else None
    if not isinstance(entry, dict):
        return None
    version = entry.get("version")
    return version if isinstance(version, str) and version else None


def site_cell(value: Any) -> str:
    """One site-table cell: the value, or the em dash for an unknown one.

    The ONE markdown projection of a site fact, shared with the parity
    contract test so the two renderings cannot disagree about what a None
    renders.  A byte count reaches here already rendered through
    :func:`human_bytes` (the same reader as the findings table), so a
    number and its cell can never drift.
    """
    if value is None:
        return "—"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return md_escape(str(value)) or "—"


def _site_rows(facts: dict[str, Any]) -> list[tuple[str, str]]:
    """``(label, value)`` for the fact table, in SITE_SCALAR_FACTS order.

    Only KNOWN facts produce a row (an absent key is unknown), and the
    theme row comes last: it is the one fact that can carry a sub-value
    (its version), rendered as "slug (version)" / "slug" when unknown.
    """
    rows = [
        (label, site_cell(facts[name]))
        for name, label in SITE_SCALAR_FACTS
        if facts.get(name) is not None
    ]
    theme = facts.get("theme")
    if isinstance(theme, dict) and theme.get("slug"):
        version = theme.get("version")
        rows.append((
            SITE_THEME_LABEL,
            f"{site_cell(theme['slug'])}"
            f"{f' ({site_cell(version)})' if version else ''}",
        ))
    return rows


def _site_entry_rows(key: str, facts: dict[str, Any]) -> list[list[Any]]:
    """The cell values of one sub-table's rows, in the fact list's order.

    One projection per sub-table so the markdown and the JSON twin read
    the same list: the JSON carries the raw value (a byte count, a None
    for an unknown) and :func:`site_cell` renders it, which is why a
    size column is pre-rendered through :func:`human_bytes` here.
    """
    entries = facts.get(key) or []
    if key == "tables":
        # the one column whose value is a byte count, not a fact key:
        # rendered through the same human_bytes the findings table uses
        return [[t["name"], t["rows"],
                 human_bytes(t["size_bytes"]) if t["size_bytes"] is not None
                 else None]
                for t in entries]
    return [[entry.get(field) for field in _SITE_COLUMNS[key]] for entry in entries]


def _site_table(title: str, columns: tuple[str, ...],
                rows: list[list[Any]]) -> list[str]:
    """Markdown lines for one site sub-table, or [] when it has no rows."""
    if not rows:
        return []
    lines = [f"### {title}", "", f"| {' | '.join(columns)} |",
             f"|{'---|' * len(columns)}"]
    for row in rows:
        lines.append("| " + " | ".join(site_cell(cell) for cell in row) + " |")
    lines.append("")
    return lines


def _site_markdown(facts: dict[str, Any] | None) -> list[str]:
    """The whole ``## Site`` section as markdown lines; [] when empty."""
    if not site_facts_present(facts):
        return []
    lines = [f"## {SITE_SECTION_TITLE}", "", "| fact | value |", "|---|---|"]
    for label, value in _site_rows(facts):
        lines.append(f"| {label} | {value} |")
    lines.append("")
    for key, title, _columns in SITE_TABLES:
        lines.extend(_site_table(title, _SITE_COLUMNS[key],
                                 _site_entry_rows(key, facts)))
    return lines


def render_report(audit: AuditReport, plan: Plan | None = None, *,
                  title: str = "wpt audit") -> str:
    """Deterministic markdown report; identical input -> identical output.

    ``title`` is the one header word a command with the audit report's
    shape but a different name (``wpt scan``) supplies; the default keeps
    every existing audit render byte-identical.
    """
    audit, plan = _sanitize(audit, plan)
    lines: list[str] = []
    lines.append(f"# {title} — {audit.site}")
    lines.append("")
    lines.append(f"Source: {audit.source_summary}")
    lines.append("")

    # Site facts first: the inventory the findings below are read against
    # (which theme, which builder, whose account).  Omitted when none was
    # gathered — a run without the facts renders exactly as it did before.
    lines.extend(_site_markdown(audit.site_facts))

    for category, findings in sorted(audit.findings_by_category().items()):
        lines.append(f"## {category}")
        lines.append("")
        lines.append("| name | detail | bytes | count | risk | fix |")
        lines.append("|---|---|---|---|---|---|")
        for f in findings:
            lines.append(
                "| {} | {} | {} | {} | {} | {} |".format(
                    md_escape(f.name),
                    md_escape(f.detail),
                    human_bytes(f.bytes) if f.bytes else "—",
                    f.count,
                    f.risk,
                    md_escape(f.fix) or "—",
                )
            )
        lines.append("")

    lines.append(f"**Reclaimable estimate: {human_bytes(audit.reclaimable_bytes())}**")
    lines.append("")

    attention = sorted(
        (f for f in audit.findings if f.risk != "low"),
        key=lambda f: ({"high": 0, "medium": 1}[f.risk], f.category, f.name),
    )
    if attention:
        lines.append("## Needs your call")
        lines.append("")
        for f in attention:
            lines.append(f"- **[{f.risk.upper()}]** {f.category} / {f.name} — {f.detail}")
            if f.fix:
                lines.append(f"  - fix: {f.fix}")
        lines.append("")

    steps = suggested_steps(audit.findings)
    if steps:
        lines.append("## Suggested next steps")
        lines.append("")
        for step in steps:
            lines.append(f"- `{step['action']}` — {step['why']}")
        lines.append("")

    if plan is not None:
        lines.append("## Plan")
        lines.append("")
        lines.append("| action | target | detail | est. bytes | applied |")
        lines.append("|---|---|---|---|---|")
        for item in sorted(plan.items, key=lambda i: (i.category, i.target)):
            lines.append(
                "| {} | {} | {} | {} | {} |".format(
                    md_escape(item.category),
                    md_escape(item.target),
                    md_escape(item.detail),
                    human_bytes(item.bytes_est) if item.bytes_est else "—",
                    "yes" if item.done else "no",
                )
            )
        lines.append("")
        lines.append(f"**Plan total estimate: {human_bytes(plan.est_bytes())}**")
        lines.append("")

    return "\n".join(lines)


def to_json(audit: AuditReport, plan: Plan | None = None) -> dict[str, Any]:
    """Machine-readable twin of render_report; secrets redacted."""
    clean_audit, clean_plan = _sanitize(audit, plan)
    payload: dict[str, Any] = {
        "site": clean_audit.site,
        "source_summary": clean_audit.source_summary,
        "findings": [dataclasses.asdict(f) for f in clean_audit.findings],
        "totals": clean_audit.totals,
        "reclaimable_bytes": clean_audit.reclaimable_bytes(),
    }
    if site_facts_present(clean_audit.site_facts):
        # "site_facts", not "site": the top-level "site" key is the audited
        # URL every consumer already reads.
        payload["site_facts"] = clean_audit.site_facts
    steps = suggested_steps(clean_audit.findings)
    if steps:
        payload["suggested_steps"] = steps
    if clean_plan is not None:
        payload["plan"] = {
            "items": [dataclasses.asdict(i) for i in clean_plan.items],
            "est_bytes": clean_plan.est_bytes(),
        }
    return payload


def _sanitize(audit: AuditReport, plan: Plan | None) -> tuple[AuditReport, Plan | None]:
    """Redact structured keys + scrub free text; rebuild dataclasses."""
    safe = _scrub(dataclasses.asdict(audit))
    clean_audit = AuditReport(
        site=safe["site"],
        source_summary=safe["source_summary"],
        findings=[Finding.validate(Finding(**f)) for f in safe["findings"]],
        totals=safe["totals"],
        # the facts ride the SAME scrub (redact by key name + redact_text
        # by value), so a fact that ever carries a secret renders "***" in
        # the markdown AND the JSON twin, or nothing at all
        site_facts=safe["site_facts"],
    )
    clean_plan = None
    if plan is not None:
        clean_plan = Plan(items=[PlanItem(**i) for i in _scrub(dataclasses.asdict(plan))["items"]])
    return clean_audit, clean_plan


def render_json(audit: AuditReport, plan: Plan | None = None) -> str:
    """Deterministic JSON rendering (sorted keys, stable ordering)."""
    payload = to_json(audit, plan)
    payload["findings"].sort(key=lambda f: (f["category"], f["name"]))
    if "plan" in payload:
        payload["plan"]["items"].sort(key=lambda i: (i["category"], i["target"]))
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2)
