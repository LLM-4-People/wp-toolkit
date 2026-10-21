"""Snapshot restore — the inverse of wpt.backup (SPEC §restore).

Consumes exactly the layout :func:`wpt.backup.create_snapshot` writes (that
module's docstring is the authoritative manifest/NDJSON schema)::

    <snapshot_dir>/
        manifest.json          format "wpt-backup-manifest", version 1
        files/<path>           captured file bytes, webroot hierarchy preserved
        db/<table>.ndjson      per-table dump stream (one JSON object per line)

Pre-pass order — NOTHING is mutated before every step below has passed:

1. :func:`wpt.backup.verify_snapshot` recomputes every manifest hash over the
   whole snapshot; a snapshot that fails verification is never restored from.
   The EXACT parsed manifest it verified is retained and used for selection
   and every write hash — ``manifest.json`` is never re-read after
   verification, so a swapped manifest cannot select unverified entries.
2. The manifest must declare format ``wpt-backup-manifest`` version 1
   (``verify_snapshot`` checks hashes, not the format) and the CURRENT
   identity format: both ``site_raw`` and ``webroot``.  A pre-identity
   manifest is unsupported and refused for managed AND explicit-path
   restores — there is no legacy/migration/trusted-import path.  Every
   caller MUST pass the run's expected identity as the required keyword-only
   ``expected_site``/``expected_webroot`` arguments; there is no shape-only
   default.  The VERIFIED manifest must match them EXACTLY — raw ``site_raw``
   and raw ``webroot``, no normalization — before any file/table work.  The
   CLI's pre-stack gate only SELECTS the snapshot; it cannot bind a later
   manifest read, so the identity it checked is passed here and re-applied
   to the one object verification retained (N-G3, N-G4).
3. Targeting is validated and resolved; unknown ``only_files`` /
   ``only_tables`` entries raise (typo protection) and unsafe paths raise
   through the source's own path guard.
4. Capability check: selected file entries require ``source``, selected
   table entries require ``bridge``.
5. File plan (pure classification, no mutation): each selected entry becomes
   a write, a delete, an absent-keep or an identical-skip. The source's own
   writability/deletability guards run HERE so a refused restore fails
   before the first mutation, not halfway through it.
6. Table pre-pass: every selected table's NDJSON is fully parsed and
   validated — stream shape, cell well-formedness, and the row-line count
   against BOTH the stream's ``done`` line and the manifest's ``rows`` field.

Only then the mutation phase runs: files first (deletes, then writes, each
write re-read and sha256-verified — SPEC §restore "verify-after-write"), then
tables (manifest order, chunked bridge calls).

Targeting semantics: with NO targeting arguments the whole snapshot is
restored. ANY of ``only_files`` / ``file_prefix`` / ``only_tables`` makes the
restore targeted — only the targeted scope is selected and every untargeted
scope restores nothing (a ``--table`` restore must never rewrite files).
Within the file scope, ``only_files`` (exact paths, normalized through the
source path guard) and ``file_prefix`` (a directory boundary:
``path == prefix or path.startswith(prefix + "/")``; ``wp-content/uploads``
never selects ``wp-content/uploads-old/``) select the UNION of their matches.

File semantics:

- present entry: the captured bytes are written back through
  ``source.write_bytes``. A live file already byte-identical to the snapshot
  is skipped with a debug log and counted NOWHERE. After every write the
  file is re-read and its sha256 re-checked — a mismatch raises and the
  restore aborts.
- absent entry: the snapshot recorded "this target did not exist"; a live
  file at that path is DELETED to honor the reversible delete (a ``wpt``
  action must be undoable both ways). A live file that is already gone is
  just counted as absent-kept.
- protected config: ``allow_config=True`` is passed exactly for paths in
  ``Source.PROTECTED`` (the types module owns that set — restore never
  hardcodes path lists). ``wp-config.php`` restores go through and are
  logged at WARNING; core paths (root core files, ``index.php``,
  ``wp-admin/**``, ``wp-includes/**``) unlock through the same audited
  ``allow_core`` the actions that snapshot them use, because the snapshot
  IS the rollback those actions advertise. The types guard itself still
  refuses writes it does not permit and restore does not bypass it.

Table semantics: restore REPLACES each table's rows via the bridge's STAGED
ATOMIC SWAP — rows are loaded into a token-owned ``<table>__wpt_<id>__s``
shadow and the live table is replaced by a single atomic multi-table RENAME
only on the last chunk (the first call passes ``truncate_first=True``, the
last ``finalize=True``), so a mid-restore failure leaves the live table
untouched. The bridge proves completeness (staged row count == the snapshot's
row count) before swapping, and a per-table random ``restore_id`` owns the
scratch names. Rows are batched at ``ROWS_PER_CALL`` per ``db_restore_table``
call; a zero-row table still sends one empty begin+finalize call so the live
table ends up empty, exactly like the snapshot. Cells travel UNCHANGED: bytes
stay in their ``["__wpt_b64__", "<base64>"]`` wire form straight off the NDJSON
disk format (the disk form IS the wire form; the bridge decodes the marker —
only well-formedness is checked here, in the pre-pass). The ``create`` line is
schema reference only: ``db_restore_table`` stages into the shadow table and
the bridge enforces row width against the live columns.

Accepted limits of the atomic swap (a maintenance CLI, not a concurrent
replication tool): concurrent schema changes (adding a FK/trigger) on the live
table *during* a restore are not locked against; and a crashed restore can
leave a token-owned scratch table behind (inert, hidden from audit — the
operator can drop it). Neither can empty or corrupt the live table for a
single honest restore run.

``dry_run=True`` runs the entire pre-pass and reports the counters as-if,
with zero writes and zero bridge calls.

Fail-closed: any validation failure raises before the first mutation; a
failure DURING the mutation phase (source/bridge error) propagates and
leaves the already-restored prefix in place — the snapshot itself is the
recovery path. No secrets are logged.
"""

import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from typing import TYPE_CHECKING

from .backup import (DB_DIR, FILES_DIR, MANIFEST_FORMAT, MANIFEST_VERSION,
                     SNAPSHOT_NAME_RE, read_regular_bounded,
                     read_snapshot_manifest, sanitize_site_label,
                     verify_snapshot)
from .dbstream import TableStream, loads_ndjson
from .deadline import Deadline
from .log import get_logger
from .config import redact_text
from .bridge_name import is_wpt_endpoint_file
from .types import (BridgeError, DeadlineExceeded, RunControl, Source,
                    SourceError, StopRequested, WptError, presence_proven)
from .wpbridge.client import Bridge

from .actions.registry import confirm
from .audit import remote_stack
from .backup import site_label
from .report import (record_snapshot_root, report_protected_inputs,
                     report_protected_subtrees, write_report_files)
from .report import write_stdout

if TYPE_CHECKING:
    from .cli import Ctx

log = get_logger("restore")

__all__ = ["RestoreReport", "list_snapshots", "restore_snapshot",
           "run_restore"]

#: Rows per ``db_restore_table`` call. The bridge refuses more than 5000 rows
#: per call (wpt_action_db_restore_table in wpt/wpbridge/bridge.php); 1000
#: matches the bridge's own INSERT chunk size and keeps 5x headroom under
#: that wire cap. A wire-protocol bound, not a profile tunable.
ROWS_PER_CALL = 1000


@dataclass
class RestoreReport:
    """Outcome of one :func:`restore_snapshot` run.

    With ``dry_run=True`` the same counters are reported as-if the restore
    had run — but zero writes and zero bridge calls were made. Exact
    semantics:

    - ``files_restored``: present manifest entries whose live bytes were
      missing or different and were (re)written. A live file already
      byte-identical to the snapshot is skipped with a debug log and counted
      NOWHERE (not restored, not deleted, not absent-kept).
    - ``files_absent_kept``: absent entries whose live file does not exist
      (the "still absent" invariant already holds — nothing to do).
    - ``files_deleted``: absent entries whose live file existed and was (or,
      in dry-run, would be) deleted to honor the snapshot's reversible
      delete.
    - ``tables_restored``: restored table names, in manifest order.
    - ``rows_inserted``: rows the bridge reports inserted across all calls
      (dry-run: the pre-pass row total).
    """

    files_restored: int
    files_absent_kept: int
    files_deleted: int
    tables_restored: list[str]
    rows_inserted: int


def _snapshot_dirs(backup_dir: Path, site_label: str) -> list[Path]:
    """Every snapshot-named directory for one site, NEWEST first.

    Name/order only — no manifest read.  Sorted by (name timestamp,
    collision suffix) DESCENDING, the exact reverse of creation order, so
    ``[0]`` is the latest snapshot and same-second collisions order
    highest-suffix-first.  Anything else in the site dir is ignored; a
    missing site directory lists nothing.
    """
    site_dir = Path(backup_dir) / sanitize_site_label(site_label)
    if not site_dir.is_dir():
        return []
    snaps: list[tuple[tuple[datetime, int], Path]] = []
    for entry in site_dir.iterdir():
        if not entry.is_dir():
            continue
        match = SNAPSHOT_NAME_RE.match(entry.name)
        if not match:
            continue
        try:
            ts = datetime.strptime(match.group(1), "%Y%m%d-%H%M%S")
        except ValueError:
            continue
        snaps.append(((ts, int(match.group(2) or 0)), entry))
    snaps.sort(key=lambda item: item[0])
    snaps.reverse()
    return [path for _, path in snaps]


def list_snapshots(backup_dir: Path, site_label: str, *,
                   webroot: str | None = None,
                   inspected: list[Path] | None = None) -> list[Path]:
    """Snapshot directories for one site, NEWEST first.

    Selection is IDENTITY-AWARE only in the NEGATIVE: a directory is one
    sanitized label, which two installations can share (two docroots on one
    host; ``bücher`` and ``b-cher``).  A manifest that records BOTH the raw
    ``site_raw`` and the ``webroot`` and differs from this site/webroot is
    excluded.  A manifest that cannot prove a DIFFERENT identity — unreadable
    JSON, a non-object, or a pre-identity manifest missing either key — is
    kept as a candidate (newest-first ordering must never hide a newer
    invalid snapshot behind an older valid one) and refused by the caller's
    identity gate.  There is no migration/trusted-import path: regenerate
    the snapshot with the current format.
    """
    candidates = _snapshot_dirs(backup_dir, site_label)
    if inspected is not None:
        inspected.extend(candidates)
    return [path for path in candidates
            if not _empty_manifestless_snapshot(path)
            and _snapshot_matches_identity(path, site_label, webroot)]


def _empty_manifestless_snapshot(path: Path) -> bool:
    """A timestamped directory with neither a manifest nor any content.

    Pre-fix versions could leave one after a stop between mkdir and the
    manifest write.  It is not a snapshot (nothing to restore), and letting
    it win ``--undo-last`` made the command fail instead of using the valid
    older snapshot beside it.  A non-empty manifest-less directory is still
    KEPT (fail closed: it may be a corrupt capture worth refusing on).
    """
    try:
        if (path / "manifest.json").exists():
            return False
        if next(path.iterdir(), None) is not None:
            return False
    except OSError:
        return False
    return True


def _identity_problem(manifest: dict[str, Any], site: str,
                      webroot: str | None) -> str | None:
    """Why one manifest is not this site/webroot, or None when it is.

    BOTH current identity keys are required, on managed AND explicit-path
    restores.  A sanitized-only ``site`` and a missing ``webroot`` are never
    proof: pre-identity manifests for ``bücher.example`` and
    ``b-cher.example`` share one directory name, and omitting the webroot
    used to make every docroot match.  The raw site AND webroot compares are
    EXACT — ``www.example.com``/``example.com`` and ``public_html``/
    ``/public_html/`` are distinct identities — and there is no
    legacy/migration/trusted-import path: an old manifest must be
    regenerated.
    """
    raw = manifest.get("site_raw")
    recorded = manifest.get("webroot")
    missing = []
    if not isinstance(raw, str) or not raw:
        missing.append("site_raw")
    if not isinstance(recorded, str):
        missing.append("webroot")
    if missing:
        return (
            "is not in the current snapshot format (missing "
            + " and ".join(missing)
            + "); snapshots require both site_raw and webroot — regenerate "
            "the snapshot with the current format"
        )
    if raw != site:
        return f"belongs to site {raw!r}, not {site!r}"
    expected = "" if webroot is None else webroot
    if recorded != expected:
        # EXACT, never normalized: selection and the verified-manifest gate
        # must agree.  A normalized-only newer snapshot used to be SELECTED
        # by --undo-last/list and then refused by the exact gate, hiding the
        # older exact snapshot that could actually restore.  ``None`` keeps
        # the historical site-only listing shape (only an empty recorded
        # webroot qualifies), never a wildcard.
        return f"was taken for webroot {recorded!r}, not {webroot!r}"
    return None


def _expected_identity_problem(manifest: dict[str, Any], site: str,
                               webroot: str) -> str | None:
    """Why a VERIFIED manifest is not the caller's expected identity.

    Selection and the pre-stack gate compare a manifest read at that moment;
    this owner binds the manifest verification actually retained to the
    values the caller resolved before remote setup.  Both fields compare
    EXACTLY (no webroot normalization): a normalized or legacy match is a
    different identity and must never authorize a write.
    """
    raw = manifest.get("site_raw")
    recorded = manifest.get("webroot")
    if raw != site:
        return f"belongs to site {raw!r}, not {site!r}"
    if recorded != webroot:
        return f"was taken for webroot {recorded!r}, not {webroot!r}"
    return None


def _manifest_matches_identity(manifest: dict[str, Any], site: str,
                               webroot: str | None) -> bool:
    """Does one managed-eligible manifest belong to ``site``/``webroot``?"""
    return _identity_problem(manifest, site, webroot) is None


def _snapshot_matches_identity(snapshot_dir: Path, site: str,
                               webroot: str | None) -> bool:
    """Identity filter for selection/listing; only a PROVEN mismatch drops.

    A manifest that cannot prove a DIFFERENT identity — unreadable, not an
    object, or missing either current identity key — is ALWAYS kept as a
    candidate: selection must never skip a newer invalid snapshot and
    restore an older state the operator did not ask for.  The selected
    candidate is then refused by _managed_identity_problem /
    verify_snapshot (fail closed).  The old sanitizer-ambiguity gate and
    the schema-invalid skip both silently dropped exactly those labels
    (R6-27, R6-36).
    """
    try:
        manifest = read_snapshot_manifest(snapshot_dir)
    except (StopRequested, DeadlineExceeded):
        raise
    except (WptError, OSError, ValueError, UnicodeError):
        return True
    if not isinstance(manifest, dict):
        return True
    raw = manifest.get("site_raw")
    recorded = manifest.get("webroot")
    if not isinstance(raw, str) or not raw or not isinstance(recorded, str):
        # Missing/invalid identity keys cannot prove a different site, so
        # the manifest stays a candidate and the explicit identity gate
        # refuses it with the regenerate-the-snapshot message.
        return True
    return _manifest_matches_identity(manifest, site, webroot)


def _managed_identity_problem(snapshot_dir: Path, site: str,
                              webroot: str | None) -> str | None:
    """Reason a managed snapshot is not this site/webroot, or None."""
    try:
        manifest = read_snapshot_manifest(snapshot_dir)
    except (StopRequested, DeadlineExceeded):
        raise
    except (WptError, OSError, ValueError, UnicodeError) as exc:
        return f"snapshot {snapshot_dir.name} has no readable manifest ({exc})"
    if not isinstance(manifest, dict):
        return f"snapshot {snapshot_dir.name} manifest is not an object"
    problem = _identity_problem(manifest, site, webroot)
    if problem is not None:
        return f"snapshot {snapshot_dir.name} {problem}"
    return None


def _validate_prefix(prefix: str) -> str:
    """Normalize and validate a ``file_prefix``; reject a never-matching shape.

    Manifest paths are normalized webroot-relative POSIX paths (checked by
    ``verify_snapshot``): no leading ``/``, no ``.``/``..`` segments, no
    backslashes. A prefix violating that shape would silently select
    nothing — fail closed on it instead.  Backslashes are separators and are
    normalized before validation/matching; C0 controls, DEL, NUL and lone
    surrogates are refused because no manifest path can carry them.  One
    TRAILING slash is
    accepted (directory scoping: ``wp-content/uploads/``) and stripped: a
    prefix selects a DIRECTORY SUBTREE, never a plain string prefix, so
    ``wp-content/uploads`` must not restore ``wp-content/uploads-old/``.
    """
    normalized = prefix.replace("\\", "/")
    if any(ord(char) < 0x20 or ord(char) == 0x7F
           or 0xD800 <= ord(char) <= 0xDFFF for char in normalized):
        # C0/DEL and lone surrogates cannot appear in a manifest path
        # (Source._guard_path refuses them), so such a prefix can only match
        # zero files.  Accepting it made the CLI exit 0 with an all-zero
        # restore report instead of naming the bad selector.
        raise ValueError(f"invalid file_prefix: {prefix!r}")
    segments = normalized.split("/")
    if segments and segments[-1] == "":
        segments = segments[:-1]
    if not segments or any(seg in ("", ".", "..") for seg in segments):
        raise ValueError(f"invalid file_prefix: {prefix!r}")
    # A trailing dot/space is a Windows filename alias and is never a
    # manifest segment (Source._guard_path refuses it), so a prefix carrying
    # one matches nothing and would silently restore zero files.  Leading
    # spaces stay legal: they are ordinary characters in a POSIX segment.
    if any(seg != seg.rstrip(" .") for seg in segments):
        raise ValueError(f"invalid file_prefix: {prefix!r}")
    return "/".join(segments)


def _under_prefix(path: str, prefix: str) -> bool:
    """Is ``path`` inside the directory subtree ``prefix``?

    One owner for the restore selector's boundary: the prefix itself and
    every descendant, never a sibling that merely shares the string prefix
    (``wp-content/uploads-old`` is not under ``wp-content/uploads``).
    """
    return path == prefix or path.startswith(prefix + "/")


def _load_table_rows(snapshot_dir: Path, entry: dict[str, Any],
                     deadline: Deadline | None = None, *,
                     raw: bytes | None = None) -> list[list[Any]]:
    """Fully parse + validate one table's NDJSON stream; return its rows.

    Fail-closed on: malformed JSON, non-object lines, lines for another
    table, unknown line shapes, lines after ``done``, a missing ``done``
    line, unsupported or malformed cells, and any disagreement between the
    row-line count, the stream's ``done`` count and the manifest's ``rows``
    field. Called for every selected table BEFORE any bridge call. The
    ``create`` line is schema reference only — ``db_restore_table`` stages
    into a shadow table and swaps it in atomically.

    ``raw`` is the EXACT byte stream ``verify_snapshot`` hashed; the rows
    handed to the bridge are parsed from it, never from a second read of
    the name (an equal-length row swap after verification would otherwise
    reach the bridge — N-F2).  The bytes are re-hashed here as well, so the
    one-read path fails closed if a caller passes anything else.
    """
    table = entry["name"]
    path = snapshot_dir / DB_DIR / f"{table}.ndjson"
    expected = entry.get("rows")
    if isinstance(expected, bool) or not isinstance(expected, int):
        raise ValueError(f"manifest entry for table {table!r}: bad rows count")
    size = entry.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ValueError(f"manifest entry for table {table!r}: bad size")
    if raw is None:
        try:
            raw = read_regular_bounded(
                Path(DB_DIR) / f"{table}.ndjson", size, f"table {table!r}",
                root=snapshot_dir)
        except WptError as exc:
            raise ValueError(str(exc)) from exc
    if len(raw) != size:
        raise ValueError(
            f"{path.name}: stream is {len(raw)} bytes, manifest says {size}")
    if hashlib.sha256(raw).hexdigest() != entry.get("sha256"):
        raise ValueError(
            f"{path.name}: SHA-256 mismatch — the stream changed after "
            "verification")
    rows: list[list[Any]] = []
    # ONE grammar owner with the capture side (wpt/dbstream.py): the exact
    # key sets, cell rule, done count and line-after-done rule are not
    # re-implemented here.
    stream = TableStream(table)
    # Physical NDJSON is newline-delimited ONLY: ``str.splitlines`` also
    # splits on U+2028/U+0085/vertical-tab/FF, so a legal JSON string cell
    # containing one of those characters turned one valid line into two
    # malformed ones and made a VERIFIED table unrestorable (P2-RESTORE-
    # SPLITLINES).
    lines = raw.decode("utf-8").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    for lineno, line in enumerate(lines, 1):
        _check(deadline, "restore table row")
        try:
            obj = loads_ndjson(line)
        except (ValueError, RecursionError, MemoryError) as e:
            # Deeply nested JSON exhausts the decoder's recursion limit (a
            # RecursionError is not a ValueError); a failed decode is the
            # same malformed-stream verdict, never a traceback escaping
            # run_restore.
            raise ValueError(f"{path.name}:{lineno}: malformed JSON") from e
        row = stream.accept(obj, f"{path.name}:{lineno}")
        if row is not None:
            rows.append(row)
    if stream.done is None:
        raise ValueError(f"{path.name}: missing done line")
    if expected != len(rows):
        raise ValueError(f"{path.name}: manifest rows {expected} != {len(rows)} row line(s)")
    return rows


def _check_restore_response(
    name: str, payload: dict[str, Any], expected: int, final: bool
) -> int:
    """Validate one db_restore_table response; return the inserted count.

    The live table is only safe once the bridge CONFIRMS the atomic swap, so
    the finalize call must report ``swapped: true`` and every earlier chunk
    must report ``swapped: false`` (a bridge that swaps early would otherwise
    leave the live table holding a partial restore).
    """
    inserted = payload.get("inserted")
    if payload.get("table") != name or type(inserted) is not int or inserted != expected:
        raise BridgeError(
            f"db_restore_table for {name!r} reported table="
            f"{payload.get('table')!r}, inserted={inserted!r} "
            f"(expected {expected} row(s))",
            payload=payload,
        )
    swapped = payload.get("swapped")
    if final and swapped is not True:
        raise BridgeError(
            f"db_restore_table for {name!r} did not confirm the atomic "
            f"swap (swapped={swapped!r})",
            payload=payload,
        )
    if not final and swapped is not False:
        raise BridgeError(
            f"db_restore_table for {name!r} reported swapped={swapped!r} on a "
            f"non-final chunk (expected False)",
            payload=payload,
        )
    if payload.get("old_left"):
        log.warning(
            "restore: %s left an inert pre-restore backup table behind "
            "(harmless; it can be dropped manually)", name,
        )
    return inserted


def restore_snapshot(
    snapshot_dir: Path,
    source: Source | None,
    bridge: Bridge | None,
    *,
    only_files: list[str] | None = None,
    file_prefix: str | None = None,
    only_tables: list[str] | None = None,
    dry_run: bool = False,
    deadline: Deadline | None = None,
    expected_site: str,
    expected_webroot: str,
) -> RestoreReport:
    """Restore all or part of one snapshot into the live site.

    Targeting: ``only_files`` (exact webroot-relative paths), ``file_prefix``
    (subtree prefix) and ``only_tables`` (exact table names) each narrow the
    restore to their own scope; ANY of them makes the restore targeted and
    every untargeted scope is left untouched. No targeting arguments at all
    = full restore. ``dry_run=True`` validates everything and reports the
    counters as-if without a single write or bridge call.

    ``expected_site``/``expected_webroot`` are REQUIRED keyword-only
    arguments: the CURRENT identity resolved by the caller before remote
    setup.  There is no default and no shape-only self-comparison path, so a
    direct caller cannot invoke a restore without naming the identity it
    intends to write.  The VERIFIED manifest must match BOTH exactly — no
    normalization and no legacy spelling — before the file/table plan runs.
    This binds the pre-stack gate's decision (or a direct caller's intent) to
    the one manifest object verification retained, so a snapshot swapped
    before or during verification cannot write another site's bytes
    (N-G3, N-G4).

    Raises ValueError for a snapshot that fails verification, a wrong
    manifest format/version, or a bad/unknown selection; SourceError /
    NotWritableError from the source path guards; BridgeError from bridge
    failures or anomalous db_restore_table payloads. Nothing is mutated
    until every validation step has passed — see the module docstring for
    the exact pre-pass order and counter semantics.
    """
    snapshot_dir = Path(snapshot_dir)

    _check(deadline, "restore verification")
    # 1. Integrity first: never restore from a corrupt snapshot.  The
    #    verification reads through the SAME budget as the restore.  The
    #    EXACT manifest object and table bytes it verifies are retained and
    #    used below; a manifest or stream swapped after verification is
    #    never selected, parsed or sent (N-G1, N-F2).
    verified_tables: dict[str, bytes] = {}
    verified_manifest: dict[str, Any] = {}
    if not verify_snapshot(snapshot_dir, deadline=deadline,
                           table_bytes=verified_tables,
                           manifest_out=verified_manifest):
        raise ValueError(f"snapshot failed verification, refusing to restore: {snapshot_dir}")
    _check(deadline, "restore manifest")

    # 2. Manifest format gate on the VERIFIED manifest (verify checks
    #    hashes, not the format).  NEVER re-read manifest.json here: a
    #    second read is a different object that verification never saw.
    manifest = verified_manifest
    if manifest.get("format") != MANIFEST_FORMAT:
        raise ValueError(f"not a wpt backup manifest: {manifest.get('format')!r}")
    if manifest.get("version") != MANIFEST_VERSION:
        raise ValueError(f"unsupported manifest version: {manifest.get('version')!r}")
    # 2b. Current identity format is mandatory for EVERY restore (managed or
    # explicit path): a pre-identity manifest is unsupported, not imported.
    identity_problem = _identity_problem(
        manifest, manifest.get("site_raw"), manifest.get("webroot"))
    if identity_problem is not None:
        raise ValueError(
            f"snapshot {snapshot_dir.name} {identity_problem}")
    if not isinstance(expected_site, str) or not expected_site \
            or not isinstance(expected_webroot, str):
        raise ValueError(
            "expected_site must be a non-empty string and expected_webroot "
            "a string (the identity this restore intends to write)")
    expected_problem = _expected_identity_problem(
        manifest, expected_site, expected_webroot)
    if expected_problem is not None:
        raise ValueError(
            f"snapshot {snapshot_dir.name} {expected_problem} — the "
            "verified manifest does not match the identity selected "
            "for this restore")
    manifest_files = manifest.get("files") or []
    manifest_tables = manifest.get("tables") or []

    # 3. Targeting validation + selection.
    if only_files is None:
        only_files = []
    if not isinstance(only_files, list) or any(
        not isinstance(p, str) or not p for p in only_files
    ):
        raise ValueError("only_files must be a list of non-empty strings")
    if file_prefix is not None:
        if not isinstance(file_prefix, str):
            raise ValueError("file_prefix must be a string")
        file_prefix = _validate_prefix(file_prefix)
    wanted_files: set[str] = set()
    if only_files:
        for raw in only_files:
            if is_wpt_endpoint_file(raw):
                raise ValueError(
                    f"refusing to restore {raw!r}: it is a wpt token "
                    f"endpoint (bridge or probe), not site content — a "
                    f"snapshot never holds one [L59]"
                )
        if source is None:
            raise ValueError("only_files targeting requires a source")
        for raw in only_files:
            norm = source._guard_path(raw)  # SourceError on unsafe input
            if norm in wanted_files:
                raise ValueError(f"duplicate only_files entry: {raw!r}")
            wanted_files.add(norm)
    if only_tables is None:
        only_tables = []
    if not isinstance(only_tables, list) or any(
        not isinstance(t, str) or not t for t in only_tables
    ):
        raise ValueError("only_tables must be a list of non-empty strings")
    wanted_tables: set[str] = set()
    for name in only_tables:
        if name in wanted_tables:
            raise ValueError(f"duplicate only_tables entry: {name!r}")
        wanted_tables.add(name)

    targeting = bool(wanted_files) or file_prefix is not None or bool(wanted_tables)
    stray = [
        (f.get("path") if isinstance(f, dict) else f)
        for f in manifest_files
        if is_wpt_endpoint_file(f.get("path") if isinstance(f, dict) else f)
    ]
    if stray:
        raise ValueError(
            f"snapshot {snapshot_dir.name} holds {len(stray)} wpt token "
            f"endpoint(s) ({stray[0]}) — refusing to restore them: they are "
            f"token-authenticated scripts, never site content [L59]"
        )
    if not targeting:
        # No filters at all: restore everything the snapshot holds.
        selected_files = list(manifest_files)
        selected_tables = list(manifest_tables)
    else:
        # Targeted restore: ONLY the targeted scope is selected.
        if wanted_files or file_prefix is not None:
            unknown = wanted_files - {e["path"] for e in manifest_files}
            if unknown:
                raise ValueError(f"only_files not in snapshot: {sorted(unknown)}")
            selected_files = [
                e for e in manifest_files
                if e["path"] in wanted_files
                or (file_prefix is not None
                    and _under_prefix(e["path"], file_prefix))
            ]
        else:
            selected_files = []
        if wanted_tables:
            unknown = wanted_tables - {e["name"] for e in manifest_tables}
            if unknown:
                raise ValueError(f"only_tables not in snapshot: {sorted(unknown)}")
            selected_tables = [e for e in manifest_tables if e["name"] in wanted_tables]
        else:
            selected_tables = []

    # 4. Capability check.
    if selected_files and source is None:
        raise ValueError("restoring files requires a source")
    if selected_tables and bridge is None:
        raise ValueError("restoring tables requires a bridge")

    # 5. File plan — pure classification; the source's own guards run here
    #    so a refused restore fails before the first mutation.
    writes: list[dict[str, Any]] = []
    deletes: list[str] = []
    files_absent_kept = 0
    for entry in selected_files:
        _check(deadline, "restore file plan")
        path = entry["path"]
        absent = entry.get("absent")
        if not isinstance(absent, bool):
            # Defence in depth behind verify_snapshot: a direct caller must
            # never turn ``"yes"``/``1`` (truthy non-booleans) into a live
            # delete because the manifest was hand-edited after creation.
            raise ValueError(
                f"manifest entry for {path!r}: absent must be a boolean")
        if absent and ("size" in entry or "sha256" in entry):
            raise ValueError(
                f"manifest entry for {path!r}: an absent entry must not "
                "carry size/sha256")
        present = presence_proven(source, path)
        if absent:
            if present:
                source._check_deletable(
                    path, allow_config=_config_unlock(path), allow_core=True)
                deletes.append(path)
            else:
                files_absent_kept += 1
            continue
        sha = entry.get("sha256")
        expected_size = entry.get("size")
        identical = False
        if present:
            live_size = None
            try:
                live_size = source.size(path)
            except (StopRequested, DeadlineExceeded):
                raise
            except (WptError, OSError):
                live_size = None
            # Read the live bytes ONLY when its size already equals the
            # manifest entry: a grown live file is planned as a write
            # without materializing it (the old check read the whole file
            # before hashing).
            if (not isinstance(expected_size, bool)
                    and isinstance(expected_size, int)
                    and live_size == expected_size):
                try:
                    live = source.read_bytes_bounded(path, expected_size)
                except (StopRequested, DeadlineExceeded):
                    raise
                except (WptError, OSError):
                    live = None
                identical = (
                    live is not None
                    and hashlib.sha256(live).hexdigest() == sha
                )
        if identical:
            log.debug("restore: %s already byte-identical, skipping write", path)
            continue
        source._check_writable(path, _config_unlock(path), allow_core=True)
        writes.append(entry)
        _check(deadline, "restore file plan end")

    # 6. Table pre-pass: parse + validate every selected stream fully.
    table_rows = []
    for e in selected_tables:
        _check(deadline, "restore table plan")
        table_rows.append((e["name"], _load_table_rows(
            snapshot_dir, e, deadline, raw=verified_tables.get(e["name"]))))

    # ---------------------------------------------- all validation has passed
    files_restored = len(writes)
    files_deleted = len(deletes)
    tables_restored: list[str] = []
    rows_inserted = 0

    if not dry_run:
        for path in deletes:
            _check(deadline, "restore delete")
            source.delete(path, allow_config=_config_unlock(path),
                          allow_core=True)
            log.debug("restore: deleted %s (absent in snapshot)", path)
        for entry in writes:
            _check(deadline, "restore file write")
            path = entry["path"]
            size = entry.get("size")
            if isinstance(size, bool) or not isinstance(size, int) or size < 0:
                raise ValueError(f"manifest entry for {path!r}: bad size")
            data = read_regular_bounded(
                Path(FILES_DIR) / path, size, f"stored bytes for {path!r}",
                root=snapshot_dir)
            # Hash the EXACT bytes read from the snapshot — the old
            # post-write re-read could observe a concurrently swapped file
            # and "verify" bytes that were never captured (R6-24).
            if len(data) != size \
                    or hashlib.sha256(data).hexdigest() != entry["sha256"]:
                raise SourceError(
                    f"restore verify failed for {path}: snapshot bytes "
                    "changed after verification")
            # PROTECTED config paths (wp-config.php/.htaccess) unlock with
            # allow_config; CORE paths (root core files, index.php,
            # wp-admin/**, wp-includes/**) unlock with the audited
            # allow_core the same way — a snapshot of a core update/heal/
            # prune is the documented rollback, so restore MUST be able to
            # write the bytes it captured.  The guard itself owns the
            # guarded-write audit log line.
            allow_config = _config_unlock(path)
            source.write_bytes(path, data, allow_config=allow_config,
                               allow_core=True)
            # SPEC: every restore is verify-after-write.  Re-read the LIVE
            # bytes through the bounded seam and match length + sha256;
            # a store that corrupts or truncates a write must fail the run,
            # never report files_restored for bytes that did not land.
            try:
                written = source.read_bytes_bounded(path, size)
            except (StopRequested, DeadlineExceeded):
                raise
            except (WptError, OSError) as exc:
                raise SourceError(
                    f"restore verify failed for {path}: the written bytes "
                    f"could not be re-read ({exc})") from exc
            if len(written) != size \
                    or hashlib.sha256(written).hexdigest() != entry["sha256"]:
                raise SourceError(
                    f"restore verify failed for {path}: the live bytes do "
                    "not match the snapshot after the write")

    for name, rows in table_rows:
        _check(deadline, "restore table")
        if dry_run:
            tables_restored.append(name)
            rows_inserted += len(rows)
            continue
        # Staged atomic restore: each table gets its OWN restore_id so the
        # bridge's token-scoped staging table cannot collide with a user table
        # or a concurrent restore. The first call creates staging
        # (truncate_first), the last performs the completeness check + atomic
        # RENAME swap (finalize). A zero-row table restores as one empty
        # begin+finalize call (the live table becomes empty).
        restore_id = secrets.token_hex(8)
        if not rows:
            _check_restore_response(name, bridge.call(
                "db_restore_table", table=name, rows=[], restore_id=restore_id,
                total_rows=0, truncate_first=True, finalize=True,
            ), 0, True)
            tables_restored.append(name)
            continue
        first = True
        offset = 0
        while offset < len(rows):
            _check(deadline, "restore table batch")
            batch = rows[offset:offset + ROWS_PER_CALL]
            offset += len(batch)
            last = offset >= len(rows)
            payload = bridge.call(
                "db_restore_table", table=name, rows=batch,
                restore_id=restore_id, total_rows=len(rows),
                truncate_first=first, finalize=last,
            )
            rows_inserted += _check_restore_response(name, payload, len(batch), last)
            first = False
        tables_restored.append(name)

    _check(deadline, "restore report")
    report = RestoreReport(
        files_restored=files_restored,
        files_absent_kept=files_absent_kept,
        files_deleted=files_deleted,
        tables_restored=tables_restored,
        rows_inserted=rows_inserted,
    )
    log.info(
        "restore%s of %s: %d file(s) restored, %d deleted, %d absent kept, "
        "%d table(s), %d row(s) inserted",
        " (dry-run)" if dry_run else "", snapshot_dir, files_restored,
        files_deleted, files_absent_kept, len(tables_restored), rows_inserted,
    )
    return report


def run_restore(ctx: "Ctx") -> int:
    """Run the ``wpt restore`` command; 0 on success, 1 on failure.

    ``wpt.cli`` dispatches here via ``_lazy_call(ctx, "wpt.restore",
    "run_restore")`` with the subcommand's flags in ``ctx.extra``:
    ``snapshot`` (the snapshot directory name; absent/None = list mode
    unless ``undo_last``), ``undo_last`` (bool, ``--undo-last`` — see
    below), ``file`` (exact webroot-relative paths), ``path_prefix``
    (a subtree), ``table`` (table names), ``config`` (``"wp-config"``
    or ``".htaccess"`` — restored through the SAME restore_snapshot path
    as a file target, so the write hits the source's config guard and
    its audit log line), ``media`` (the bridge-reported uploads
    subtree).  Every key may be absent; all reads go through ``.get()``.

    LIST mode: the site's snapshot directories NEWEST first
    (:func:`list_snapshots`), one per line — the directory name plus
    the manifest's ``action`` and ``created`` fields when cheaply
    readable (a snapshot whose manifest does not parse skips its line
    with a warning) — under a ``# wpt restore — <site>`` heading, or
    ``No snapshots for <site>.`` when the site's directory holds no
    current-format snapshot.  A pre-identity manifest is never listed:
    snapshots require the current identity format and are refused, not
    migrated.  rc 0 either way; listing reads local disk only, so it
    works in BOTH source modes and never builds a stack.

    ``--undo-last`` (``ctx.extra["undo_last"]`` truthy): the ergonomic
    one-flag rollback — "that apply made it worse, undo it" without
    hunting timestamps.  Resolves the NEWEST snapshot for the site
    (:func:`list_snapshots` over ``site_label(ctx)`` — ``[0]`` is the
    latest) and restores EXACTLY as if its name had been passed: the
    same name gate, local refusal, stack build, targeting, dry-run and
    confirm path.  It is checked BEFORE the snapshot-name logic and
    takes precedence over the no-name LIST mode (``--undo-last`` with
    no explicit name is NOT list mode).  An explicit snapshot name
    alongside it is a usage error (rc 1, no stack built), and a site
    with no snapshots fails with rc 1.  The targeting flags
    (``--file`` / ``--path-prefix`` / ``--table`` / ``--config`` /
    ``--media``) still compose with it BY DESIGN —
    ``--undo-last --config wp-config`` rolls back only the newest
    snapshot's wp-config.php.  One info log names the resolved
    snapshot.

    RESTORE mode: the name — passed explicitly or resolved by
    ``--undo-last`` — must match ``SNAPSHOT_NAME_RE`` (only
    snapshot directories are addressable) and resolve to an existing
    directory under ``<backup_dir>/<sanitized site label>/``.  A value
    containing a path separator and naming an existing directory is an
    explicit snapshot LOCATION, not a trust bypass: it must record the
    same current ``site_raw`` and ``webroot`` and pass the same
    ``verify_snapshot`` and path/endpoint guards.  A pre-identity
    manifest is unsupported on either route and is refused with a
    regenerate-the-snapshot message.  Local mode refuses (v1 restore is
    ftp-only — the zip + dump ARE the offline source).  Ftp mode builds
    the remote stack through the module-top ``remote_stack`` seam
    (patchable as ``wpt.restore.remote_stack``), then runs
    :func:`restore_snapshot`
    with ``dry_run = not ctx.apply``: without ``--apply`` the as-if
    report is printed with rc 0 and nothing is written; with
    ``--apply`` the run is gated on
    :func:`~wpt.actions.registry.confirm` (the canonical
    mutating-command gate) and a refusal aborts with rc 1 before
    anything is restored.  ``--media`` asks the bridge's ``info``
    action for ``uploads_basedir`` and scopes the restore to that
    subtree; a bridge that reports no usable basedir is an error.

    Output: a small markdown report of every :class:`RestoreReport`
    counter, written to ``ctx.report_path`` when set and ALWAYS
    written to stdout through the shared ``wpt.report.write_stdout``
    sink, exactly like ``wpt.verify`` (the report IS the command's
    stdout surface).  With ``ctx.report_path`` set, a JSON twin of the
    same run — ``site`` / ``snapshot`` / ``dry_run`` plus EVERY
    RestoreReport counter, its own small schema (not the audit's
    AuditReport shape) — is ALSO written to
    ``report_path.with_suffix(".json")``, mirroring the audit
    ``_emit`` md+json pair; the stdout print stays markdown-only,
    unchanged.  The engine's own info line inside
    :func:`restore_snapshot` carries the counters summary.

    Error contract: ``WptError`` / ``OSError`` / ``ValueError``
    (restore_snapshot raises ValueError for the failed
    verification/format gates) are logged at error as
    ``restore failed: ...`` and answered with rc 1 — run_restore never
    raises and never lets a traceback reach the CLI.  The stack is
    torn down in a ``finally`` exactly like ``registry.run_action``:
    bridge destroy + source close.
    """
    deadline = Deadline.from_ctx(ctx)
    try:
        if deadline is not None:
            deadline.check("restore selection")
        name = ctx.extra.get("snapshot")
        if isinstance(name, Path):
            name = str(name)
        site = site_label(ctx)
        if ctx.extra.get("undo_last"):
            # --undo-last BEFORE the snapshot-name logic; it takes
            # precedence over the no-name list mode.  The targeting flags
            # below still compose with the resolved snapshot BY DESIGN.
            if name:
                return _fail(
                    ctx, "restore: --undo-last and a snapshot name are "
                         "mutually exclusive")
            inspected: list[Path] = []
            try:
                newest = list_snapshots(Path(ctx.backup_dir), site,
                                        webroot=ctx.webroot,
                                        inspected=inspected)
            finally:
                for root in inspected:
                    record_snapshot_root(ctx, root)
            if not newest:
                site_dir = Path(ctx.backup_dir) / sanitize_site_label(site)
                try:
                    others = sum(
                        1 for entry in site_dir.iterdir()
                        if entry.is_dir() and SNAPSHOT_NAME_RE.match(entry.name))
                except OSError:
                    others = 0
                if others:
                    return _fail(
                        ctx, "restore: no snapshots to undo for this site and "
                             f"webroot ({others} snapshot(s) belong to another "
                             "site or webroot, or are not in the current snapshot "
                             "format; regenerate them with the current format)")
                return _fail(ctx, "restore: no snapshots to undo")
            name = newest[0].name
            log.info("restore: undoing with the newest snapshot %s", name)
        if not name:
            return _list(ctx)
        explicit_path = None
        if isinstance(name, str) and ("/" in name or "\\" in name):
            # An explicit snapshot directory is still subject to the CURRENT
            # manifest identity: it is a location, not a trust bypass.  A
            # pre-identity manifest is refused here exactly like a managed one.
            candidate = Path(name)
            if not candidate.is_dir():
                return _fail(ctx, f"restore: no snapshot directory {name!r}")
            explicit_path = candidate
            name = candidate.name
        if explicit_path is None:
            if not isinstance(name, str) or not SNAPSHOT_NAME_RE.match(name):
                return _fail(
                    ctx, f"restore: {name!r} is not a snapshot name (only "
                         "snapshot directories are addressable)")
            snapshot_dir = (Path(ctx.backup_dir) / sanitize_site_label(site)
                            / name)
            if not snapshot_dir.is_dir():
                return _fail(ctx, f"restore: no snapshot {name} under "
                                  f"{snapshot_dir.parent}")
        else:
            snapshot_dir = explicit_path
    except (StopRequested, DeadlineExceeded) as exc:
        # A listing stop is still a run that did not complete: answer rc 1
        # with the shared failure pair, never a traceback out of run_restore.
        return _fail(ctx, f"restore failed: {exc}")
    except (WptError, OSError, ValueError) as exc:
        # Selection/listing reads the local backup directory: an unreadable
        # directory is an operational failure like any other, answered with
        # the one-line/rc-1 contract instead of a traceback.
        return _fail(ctx, f"restore failed: {exc}")
    # Both managed and explicit-path restores require the current identity;
    # no migration/trusted-import path exists.  The SELECTED snapshot is a
    # local input from here on: record it before any failure report so a
    # --report naming its manifest can never invalidate the rollback.
    ctx.extra["snapshot_dir"] = str(snapshot_dir)
    record_snapshot_root(ctx, snapshot_dir)
    try:
        problem = _managed_identity_problem(snapshot_dir, site, ctx.webroot)
    except (StopRequested, DeadlineExceeded) as exc:
        return _fail(ctx, f"restore failed: {exc}")
    if deadline is not None:
        try:
            deadline.check("restore identity")
        except RunControl as exc:
            return _fail(ctx, f"restore stopped: {exc}")
    if problem is not None:
        return _fail(ctx, f"restore: {problem}")
    if ctx.mode == "local":
        return _fail(
            ctx, "restore is ftp-only in v1 (zip rewriting is v2); "
                 "the zip + dump are the offline source")
    source = None
    bridge = None
    session = None
    rc = 1
    try:
        _check(deadline, "restore setup")
        source, session, bridge = remote_stack(ctx)
        rc = _restore_with_stack(ctx, source, bridge, snapshot_dir, site, name,
                                 deadline)
    except RunControl as exc:
        rc = _fail(ctx, f"restore stopped: {exc}")
    except (WptError, OSError, ValueError) as exc:
        rc = _fail(ctx, f"restore failed: {exc}")
    finally:
        # Teardown is part of the command contract, not a place a traceback
        # may escape: the shared owner attempts bridge/source/session
        # independently and returns the first cooperative stop.
        from .teardown import teardown_stack

        first_stop = teardown_stack((source, session, bridge), "restore")
    if first_stop is not None:
        reason = f"restore: teardown stopped: {first_stop}"
        log.error("%s", reason)
        if rc == 0:
            # The success report is on disk; rc 1 must not leave it saying
            # "restored".  Replace it with the shared failure pair.
            rc = _fail(ctx, reason)
        else:
            rc = 1
    return rc


def _restore_with_stack(ctx: "Ctx", source, bridge, snapshot_dir: Path,
                        site: str, name: str,
                        deadline: Deadline | None = None) -> int:
    """The restore body once the remote stack exists (no teardown here).

    ``site`` and ``ctx.webroot`` are the identity resolved BEFORE the stack
    was built; they are passed through as :func:`restore_snapshot`'s REQUIRED
    expected identity so the verified manifest is bound to that selection,
    not merely to its own fields (N-G3, N-G4).
    """
    # The identity owner shared with backup/files snapshot creation: the raw
    # site label and ``ctx.webroot or ""`` are the exact values a manifest
    # records, so they are also the exact values verification must match.
    expected_webroot = ctx.webroot or ""
    only_files = list(ctx.extra.get("file") or [])
    only_tables = list(ctx.extra.get("table") or [])
    file_prefix = ctx.extra.get("path_prefix")
    config = ctx.extra.get("config")
    if config is not None:
        if config == "wp-config":
            only_files.append("wp-config.php")
        elif config == ".htaccess":
            only_files.append(".htaccess")
        else:
            return _fail(
                ctx, f"restore: --config must be wp-config or .htaccess, "
                     f"not {config!r}")
    if ctx.extra.get("media"):
        # The bridge reports uploads_basedir SERVER-ABSOLUTE
        # (wp_upload_dir()['basedir'], e.g. "/home/u/public_html/
        # wp-content/uploads") while manifest paths are webroot-
        # relative — relativize against the bridge's own abspath
        # (the WP install root == the source's webroot).  The audit
        # never consumes the absolute form (wpt/audit/media.py:58);
        # neither does this.  An uploads dir OUTSIDE the webroot is
        # fail-closed: it can never match manifest paths.
        info = bridge.call("info")
        basedir = info.get("uploads_basedir")
        abspath = info.get("abspath")
        if (not isinstance(basedir, str) or not basedir.strip("/")
                or not isinstance(abspath, str) or not abspath.strip("/")):
            return _fail(
                ctx, "restore: --media needs the bridge's uploads "
                     "basedir; none was reported")
        base = basedir.rstrip("/")
        root = abspath.rstrip("/")
        if not base.startswith(root + "/"):
            return _fail(
                ctx, f"restore: uploads dir {basedir} is not under the "
                     f"webroot {abspath}; --media cannot scope it")
        file_prefix = base[len(root) + 1:] + "/"
    if not ctx.apply:
        report = restore_snapshot(
            snapshot_dir, source, bridge,
            only_files=only_files, file_prefix=file_prefix,
            only_tables=only_tables, dry_run=True, deadline=deadline,
            expected_site=site, expected_webroot=expected_webroot,
        )
        _check(deadline, "restore dry-run report")
        _emit(ctx, site, name, report, dry_run=True)
        log.info("restore: dry run (pass --apply to execute)")
        return 0
    if not confirm(ctx):
        return _fail(ctx, "restore: aborted by the operator",
                     status="refused", info=True)
    report = restore_snapshot(
        snapshot_dir, source, bridge,
        only_files=only_files, file_prefix=file_prefix,
        only_tables=only_tables, dry_run=False, deadline=deadline,
        expected_site=site, expected_webroot=expected_webroot,
    )
    _check(deadline, "restore report")
    _emit(ctx, site, name, report, dry_run=False)
    return 0


def _check(deadline: Deadline | None, context: str) -> None:
    if deadline is not None:
        deadline.check(context)


def _config_unlock(path: str) -> bool:
    """Is ``path`` one of the protected config names, case-insensitively?

    The write/delete guards compare through ``Source.PROTECTED_FOLDED``, so
    a snapshot taken on a case-insensitive host may hold ``.HTACCESS`` or
    ``WP-CONFIG.PHP``.  A case-sensitive membership test refused exactly the
    restore the guard would have allowed (R14-P2 restore casefold).
    """
    return path.casefold() in Source.PROTECTED_FOLDED


def _fail(ctx: "Ctx", message: str, *, status: str = "failed",
          info: bool = False) -> int:
    """Log one refusal/failure AND write the shared failure artifact.

    Every rc-1 path of ``run_restore`` uses this: before, a failed restore
    left neither a file nor (on some paths) any stdout, so a caller could
    not tell "restored nothing" from "never got far enough".
    """
    (log.info if info else log.error)(message)
    from .actions.registry import write_failure_report

    try:
        write_failure_report(ctx, "restore", message, status=status,
                             title="wpt restore")
    except (Exception, RunControl) as exc:  # noqa: BLE001 — never mask the failure
        log.warning("restore: could not write the failure report: %s",
                    redact_text(str(exc)))
    return 1


def _list(ctx: "Ctx") -> int:
    """Print the site's snapshots newest-first (the interactive picker).

    Pure local disk — :func:`list_snapshots` plus one manifest read
    per line — so no stack is built and both source modes work.  A
    snapshot whose manifest does not parse (or lacks the fields) skips
    its line with a warning instead of failing the whole listing.  Only
    CURRENT-format snapshots (both identity keys) are listed; a
    pre-identity manifest is unsupported and never discovered/migrated.

    ``--report`` is honoured here exactly like every other command: the
    printed listing becomes the markdown file plus its JSON twin.  List
    mode is a pure local read, so it is also the one restore path that
    works offline — and it was the one restore path that ignored the
    universal ``--report`` contract.
    """
    site = site_label(ctx)
    lines = [f"# wpt restore — {site}"]
    deadline = Deadline.from_ctx(ctx)
    _check(deadline, "restore list")
    inspected: list[Path] = []
    try:
        snapshots = list_snapshots(Path(ctx.backup_dir), site,
                                   webroot=ctx.webroot,
                                   inspected=inspected)
    finally:
        for root in inspected:
            record_snapshot_root(ctx, root)
    _check(deadline, "restore list")
    rows: list[dict[str, str]] = []
    if not snapshots:
        lines.append(f"No snapshots for {site}.")
    for path in snapshots:
        _check(deadline, "restore list identity")
        # Listing ADVERTISES only a snapshot that proves the CURRENT
        # identity: a candidate kept for selection (unreadable, non-object,
        # or pre-identity) is refused by the restore gate and is never
        # shown as a restorable line.  Selection itself must keep it (a
        # newer invalid snapshot may not be skipped, R6-36); display is
        # the other half of that rule.
        problem = _managed_identity_problem(path, site, ctx.webroot)
        if problem is not None:
            log.warning("restore: skipping %s (%s)", path.name, problem)
            continue
        try:
            manifest = read_snapshot_manifest(path)
            if not isinstance(manifest, dict):
                raise ValueError("manifest is not an object")
            lines.append(f"{path.name}  action={manifest['action']}  "
                         f"created={manifest['created']}")
            rows.append({
                "name": path.name,
                "action": str(manifest["action"]),
                "created": str(manifest["created"]),
            })
        except (StopRequested, DeadlineExceeded):
            raise
        except (WptError, OSError, ValueError, KeyError):
            log.warning("restore: skipping %s (unparseable manifest)", path.name)
        _check(deadline, "restore list identity")
    markdown = "\n".join(lines) + "\n"
    write_stdout(markdown, end="")
    if ctx.report_path is not None:
        from .actions.registry import write_report

        twin = json.dumps(
            {"site": site, "snapshots": rows, "total": len(rows)},
            ensure_ascii=False, sort_keys=True, indent=2)
        return write_report(ctx, "restore", markdown, twin)
    return 0


def _emit(ctx: "Ctx", site: str, snapshot: str, report: RestoreReport,
          *, dry_run: bool) -> None:
    """Write the restore report to ``ctx.report_path`` (when set) — the
    markdown PLUS its JSON twin at ``report_path.with_suffix(".json")``,
    exactly the audit ``_emit`` md+json pair — and ALWAYS print the
    markdown; the stdout surface is unchanged (see run_restore)."""
    markdown = _render(site, snapshot, report, dry_run=dry_run)
    # stdout FIRST: a report path that cannot be written fails the run, and
    # the dry-run pass (the thing the operator asked to see) must still have
    # been printed before that failure.
    write_stdout(markdown)
    if ctx.report_path is not None:
        write_report_files(
            ctx.report_path, markdown,
            _render_json(site, snapshot, report, dry_run=dry_run),
            protected_paths=report_protected_inputs(ctx),
            protected_subtrees=report_protected_subtrees(ctx),
        )


def _render(site: str, snapshot: str, report: RestoreReport,
            *, dry_run: bool) -> str:
    """The restore markdown report: every :class:`RestoreReport` counter
    renders into the table; the restored table names list below it when
    any.  The headline states the dry-run boundary explicitly."""
    headline = (
        f"Dry-run restore of snapshot `{snapshot}` — nothing was written "
        "(pass --apply to execute)."
        if dry_run
        else f"Restored snapshot `{snapshot}`."
    )
    lines = [
        f"# wpt restore — {site}",
        "",
        headline,
        "",
        "| counter | count |",
        "|---|---|",
        f"| files restored | {report.files_restored} |",
        f"| files deleted | {report.files_deleted} |",
        f"| files absent kept | {report.files_absent_kept} |",
        f"| tables restored | {len(report.tables_restored)} |",
        f"| rows inserted | {report.rows_inserted} |",
        "",
    ]
    if report.tables_restored:
        lines.append("Tables restored: "
                     + ", ".join(f"`{t}`" for t in report.tables_restored))
        lines.append("")
    return "\n".join(lines)


def _render_json(site: str, snapshot: str, report: RestoreReport,
                 *, dry_run: bool) -> str:
    """The machine-readable twin of :func:`_render`: the site, the
    snapshot name, the dry-run boundary and EVERY :class:`RestoreReport`
    counter as one small snake_case dict — restore's OWN schema, not
    the audit's AuditReport shape.  Formatted exactly like
    :func:`wpt.report.render_json` (utf-8, sorted keys, indent 2) so
    the two report surfaces stay consistent."""
    return json.dumps(
        {
            "site": site,
            "snapshot": snapshot,
            "dry_run": dry_run,
            "files_restored": report.files_restored,
            "files_deleted": report.files_deleted,
            "files_absent_kept": report.files_absent_kept,
            "tables_restored": list(report.tables_restored),
            "rows_inserted": report.rows_inserted,
        },
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    )
