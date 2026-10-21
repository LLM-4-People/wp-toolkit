"""Profile-driven junk categories shared by the actions (junk_categories).

Matching + detail-line ownership for the webroot categories whose GATE is a
measured site fact rather than a bare pattern: the backup-payload group, the
legacy-GeoIP group, the page-cache group and the operator-enabled obsolete
asset signatures.  ``wpt.actions.clean_files`` imports these; nothing here
registers an action, walks a source or writes anything.

WHY A SEPARATE MODULE: the category rules are pure predicates over walked
entries plus one read of wp-config.php, and the action's plan is already the
largest in the toolkit.  Keeping the predicates here means the plan reads as
"which groups fire, and under which measured gate" and the rules read as
rules.

STRUCTURAL WORDPRESS CONSTANTS (fixed layout facts, NOT tunables — the same
rule ``wpt/audit/webroot.py`` documents for its own constants):

* ``wp-content/uploads/`` — the attachment DATA tree.  Everything under it
  is an inbound record, not a build artifact: a ``.sql`` there is a form
  submission export (Gravity Forms keeps form records under
  ``wp-content/uploads/gravity_forms/``), a ``.zip`` is somebody's uploaded
  document.  No payload/legacy/cache group ever names a path under it.
* ``wp-content/plugins/`` + ``wp-content/themes/`` — a UNIT (a direct child)
  and its subtree.  A unit is a self-contained install: a ``.zip`` inside a
  plugin is that plugin's own asset, and a directory directly under
  ``plugins/`` is a unit, not a backup store.  Both are excluded a fortiori
  from the payload rule, which requires only "not an active plugin/theme
  path": excluding every unit needs no bridge/dump active-set lookup, and it
  cannot mis-fire on a unit WordPress is not using either.
* ``wp-config.php`` — the only file the WP_CACHE gate reads.

MEASURED GATES (fail-closed, one per group):

* rendered pages — the walker's live reference set (rendered HTML refs,
  srcset attributes and generated-CSS ``url()`` refs).  A payload whose
  basename is a reference is KEPT: the gate is a keep-set, and a name the
  live site still points at is never moved out from under it.
* the active plugin set — bridge ``info`` (ftp) / the dump's
  ``active_plugins`` (local), read through ``wpt.actions.clean_files``'s one
  owner.  UNKNOWABLE is a refusal, never a guess: legacy GeoIP databases are
  megabytes of data a still-active plugin reads.
* ``WP_CACHE`` in wp-config.php — read AS PHP through
  ``wpt.audit.security._php_const_state`` (the one owner of "is this
  constant active"), never grepped: a commented-out define, a string, a
  conditional define or a value PHP decides at runtime all mean UNKNOWN, and
  an unknown constant plans NOTHING.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase

from ..audit.security import _php_const_state
from ..audit.webroot import _dir_subtree_file_counts, _dir_subtree_sizes
from ..log import get_logger
from ..types import Entry, Source, WptError

__all__ = [
    "GEOIP_CATEGORY", "OBSOLETE_CATEGORY", "PAGE_CACHE_CATEGORY",
    "PAYLOAD_CATEGORY", "PAYLOAD_EXPOSURE", "PayloadCandidate",
    "geoip_file_matches", "obsolete_asset_matches", "page_cache_dir_matches",
    "page_cache_file_matches", "payload_candidates", "unit_name_of",
    "wp_cache_state",
]

log = get_logger("actions.junk_categories")

#: The uploads tree every payload/legacy/cache group is scoped AROUND (never
#: inside): attachment data and inbound form records live here.
_UPLOADS_PREFIX = "wp-content/uploads/"

#: The two unit roots (direct children are plugin/theme UNITS).
_UNIT_ROOTS = ("wp-content/plugins/", "wp-content/themes/")

#: The plan categories these groups own.  ``webroot.junk`` is the audit's own
#: "junk in the webroot" category and is reused for the backup-payload
#: EXPOSURE, under the shared name :data:`PAYLOAD_EXPOSURE`, so a plan item
#: and the audit's finding speak one vocabulary.
PAYLOAD_CATEGORY = "webroot.junk"
GEOIP_CATEGORY = "webroot.geoip_legacy"
PAGE_CACHE_CATEGORY = "webroot.page_cache"
OBSOLETE_CATEGORY = "webroot.obsolete_asset"

#: The shared name of the backup-payload exposure.  A finding/plan detail
#: carrying it says: a full-site backup payload is being served from the
#: document root, which is an exposure (an archive in the webroot is
#: downloadable at a guessable URL) as well as wasted bytes.
PAYLOAD_EXPOSURE = "backup_payload_in_webroot"


@dataclass
class PayloadCandidate:
    """One backup payload: its webroot-relative path, the pattern that
    matched it, its measured bytes and its file count (a subtree sum for a
    directory)."""

    path: str
    is_dir: bool
    pattern: str
    size: int
    files: int


def is_attachment_data(path: str) -> bool:
    """True for a path under ``wp-content/uploads/`` — inbound data, never
    junk.  A ``.sql`` there is a form-submission export; an archive there is
    a visitor's upload."""
    return path.startswith(_UPLOADS_PREFIX)


def in_unit_subtree(path: str) -> bool:
    """True for a path strictly inside a plugin or theme UNIT (or for a
    directory that IS one).  Nothing under ``wp-content/plugins/<unit>/`` or
    ``wp-content/themes/<unit>/`` is a build artifact: a unit is a
    self-contained install.  This is STRICTLY STRONGER than "not an active
    plugin/theme path" and needs no active-set lookup, so it holds in a
    bridge-less stack too."""
    return unit_name_of(path) is not None


def unit_name_of(path: str) -> str | None:
    """The plugin/theme UNIT a path belongs to — the unit's own name when
    the path IS a unit, its unit name when it sits strictly inside one, and
    None for anything else.  One owner, shared with the clean-files unit
    rule's two roots."""
    for root in _UNIT_ROOTS:
        if not path.startswith(root):
            continue
        rest = path[len(root):]
        if not rest:
            return None
        return rest.split("/", 1)[0]
    return None


def _base(path: str) -> str:
    """The basename of a webroot-relative POSIX path."""
    return path.rsplit("/", 1)[-1]


def payload_file_matches(entry: Entry, patterns: list[str]) -> str | None:
    """The first backup-payload extension pattern matching this file, or None."""
    if entry.is_dir:
        return None
    base = _base(entry.path)
    for pattern in patterns:
        if fnmatchcase(base, pattern):
            return pattern
    return None


def payload_dir_matches(entry: Entry, patterns: list[str]) -> str | None:
    """The first backup-payload directory pattern matching this dir, or None."""
    if not entry.is_dir:
        return None
    base = _base(entry.path)
    for pattern in patterns:
        if fnmatchcase(base, pattern):
            return pattern
    return None


def payload_candidates(entries: list[Entry], settings) -> list[PayloadCandidate]:
    """EVERY backup payload in the tree, topmost only, with its measured
    bytes — the ONE owner of the enumeration, shared by the ``park-backups``
    action (which MOVES them) and the clean-files backup-payload group
    (which reports them as advice), so the two can never disagree on what a
    payload is.

    A FILE matches a ``backup_payloads.extensions`` pattern, a DIRECTORY a
    ``backup_payloads.directories`` one; a candidate nested inside a
    candidate directory is dropped (the directory covers it).  Two
    structural exclusions apply here, so both consumers get them: nothing
    under ``wp-content/uploads/`` (attachment data) and nothing under a
    plugin or theme unit (a unit is a self-contained install).  Order
    follows the walk, so plans stay deterministic.
    """
    extensions = settings.backup_payloads.extensions
    directories = settings.backup_payloads.directories
    sizes = _dir_subtree_sizes(entries)
    counts = _dir_subtree_file_counts(entries)
    out: list[PayloadCandidate] = []
    for entry in entries:
        pattern = (payload_dir_matches(entry, directories)
                   or payload_file_matches(entry, extensions))
        if pattern is None:
            continue
        if is_attachment_data(entry.path) or in_unit_subtree(entry.path):
            continue
        if entry.is_dir:
            out.append(PayloadCandidate(
                entry.path, True, pattern,
                sizes.get(entry.path, 0), counts.get(entry.path, 0),
            ))
        else:
            out.append(PayloadCandidate(
                entry.path, False, pattern, entry.size, 1,
            ))
    dirs = [c.path for c in out if c.is_dir]
    return [c for c in out
            if not any(c.path.startswith(d + "/") for d in dirs)]


def geoip_file_matches(entry: Entry, patterns: list[str]) -> str | None:
    """The first legacy-GeoIP pattern matching this file, or None."""
    if entry.is_dir:
        return None
    base = _base(entry.path)
    for pattern in patterns:
        if fnmatchcase(base, pattern):
            return pattern
    return None


def page_cache_file_matches(entry: Entry, patterns: list[str]) -> str | None:
    """The first page-cache byproduct pattern matching this file, or None."""
    if entry.is_dir:
        return None
    base = _base(entry.path)
    for pattern in patterns:
        if fnmatchcase(base, pattern):
            return pattern
    return None


def page_cache_dir_matches(entry: Entry, prefixes: list[str]) -> str | None:
    """The page-cache path prefix this directory is (or is inside), or None.

    ``page_cache_dirs`` entries are webroot-relative path PREFIXES: a
    directory prefix ends in ``/`` and covers its whole subtree, a bare
    directory name matches that directory only.  The same literal-prefix
    rule ``media_optimize.exclude_prefixes`` documents.
    """
    if not entry.is_dir:
        return None
    for prefix in prefixes:
        if prefix.endswith("/"):
            if entry.path == prefix.rstrip("/") or entry.path.startswith(prefix):
                return prefix
        elif entry.path == prefix:
            return prefix
    return None


def obsolete_asset_matches(
    entry: Entry, signatures: list[dict]
) -> dict | None:
    """The ENABLED obsolete-asset signature matching this file, or None.

    A signature whose ``enabled`` is false is inert: the shipped default
    ships every signature disabled, because ".eot fonts nobody references"
    and "these .po catalogs are not the site locale" are per-site judgements
    the operator makes, not facts wpt can prove from a walk.
    """
    if entry.is_dir:
        return None
    base = _base(entry.path)
    for signature in signatures:
        if not signature.get("enabled"):
            continue
        if fnmatchcase(base, str(signature.get("name", ""))):
            return signature
    return None


def wp_cache_state(source: Source) -> str:
    """``"absent"`` | ``"defined"`` | ``"unknown"`` for wp-config.php's
    ``WP_CACHE``.

    Read AS PHP through ``wpt.audit.security._php_const_state`` (the one
    owner of "is this wp-config constant active"): a commented-out define, a
    string/comment occurrence, a define PHP decides at runtime, an
    unparseable file or an unreadable wp-config.php are all ``"unknown"`` —
    and an unknown constant plans nothing, because a page cache the site
    still serves must never be deleted on a guess.
    """
    try:
        raw = source.read_bytes("wp-config.php")
    except (WptError, OSError) as exc:
        log.warning(
            "wp-config.php could not be read (%s): WP_CACHE is unknown, so "
            "no page-cache junk is planned", exc,
        )
        return "unknown"
    try:
        text = raw.decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001 — decode never raises with replace
        log.warning("wp-config.php could not be decoded (%s): WP_CACHE is "
                    "unknown, so no page-cache junk is planned", exc)
        return "unknown"
    state = _php_const_state(text, "WP_CACHE")
    if state == "absent":
        return "absent"
    if state in ("truthy", "falsey"):
        return "defined"
    return "unknown"
