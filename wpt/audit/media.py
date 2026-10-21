r"""Media audit check (W6e): pure functions over AuditData + Settings.

``media.unreferenced`` flags uploaded media files neither the live site
nor the database references.  The check registers through
``wpt.audit.registry.register_check`` with ``applies=("ftp", "local")``
(the AuditData contract is mode-agnostic) and has the uniform signature
``func(data: AuditData, settings: Settings) -> list[Finding]``.  It
consumes ONE settings tunable — ``settings.media.extensions``, the
extension allowlist deciding which uploads files count as MEDIA at all
(see :func:`unreferenced_files`); everything else about the uploads
tree location is a structural WordPress path, not a profile knob.
Nothing here mutates ``data`` except the memoized database reference set
(``data.db_refs``, see :mod:`wpt.media_refs`); detail lines are sorted;
there is no per-file (or any) logging — the registry already logs
durations and outcomes.

THE KEEP-SET IS A UNION (the live-proven defect): a WordPress page renders
only a FRACTION of its attachment images.  On an observed site, a walk-only
keep-set covered most of the media files and bytes only through database
references the walk never sees (featured images in menus/widgets/theme
options, srcset candidates, attachment pages, gallery templates, PDFs linked
from post content) — a compliant apply would have deleted them all.  The
defensible remainder was small.  So the keep-set is
``live_refs`` (rendered) ∪ ``db_refs`` (database), and this module is
the ONE place the two are unioned, so the check's aggregate Finding and
the trim-media action's per-file items can never disagree.

The two sides (binding contract for the W7 walker and for
:mod:`wpt.media_refs`):
    * ``data.live_refs`` — uploads-RELATIVE POSIX paths
      ("2023/10/pic-300x233.jpg") of the RENDERED references: the same
      shape the bridge's media_map action resolves.  The walker converts
      every asset URL it collects (rendered HTML refs, srcset
      attributes, url() refs inside generated CSS under
      wp-content/uploads [L11]) to this form before storing: strip
      scheme/host, keep the wp-content/uploads/ tail, URL-decode.
    * ``data.db_refs`` — the same path shape for everything the DATABASE
      references (attachment paths + metadata sizes, post content,
      theme/widget/menu options, term meta).  ``wpt.media_refs`` owns how
      each mode measures it (the bridge in ftp mode, the .sql dump in
      local mode); this module only consumes it.
    * ``None`` on either side means that side is MISSING/unknown — the
      set it feeds is DEGRADED, and the finding says so.  An EMPTY set is
      a measured result ("nothing references any uploads file") and is
      reported as such.  When BOTH sides are None nothing is enumerated
      at all: an audit that measured neither reference class must never
      guess a keep-set — and it must never read as a CLEAN one either, so
      the check emits the zero-count ``media.unmeasurable`` marker
      (:func:`unmeasured_note`) rather than silence.

Keep-set (SPEC §Audit modules W6, lesson L5 — symmetric stem matching):
    an uploads file is KEPT when its uploads-relative path IS a ref (from
    EITHER side), or when it sits in the SAME directory as some ref and
    its stripped stem equals that ref's stripped stem.  Stripping
    removes WordPress's generated suffixes ``-<digits>x<digits>`` (size
    variants) and ``-scaled`` from the basename REPEATEDLY, so chained
    names like ``img-scaled-1024x768`` reduce to ``img``: a referenced
    original keeps its ``-300x233``/``-scaled`` variants, and a
    referenced VARIANT equally keeps the original and its siblings —
    stem matching is symmetric.  It never crosses a directory boundary.
    A ref with no on-disk file is a reference, not a file: it keeps its
    on-disk stem siblings and can never be flagged itself.

EVIDENCE CLASSES — what a candidate deletion is actually based on, so an
operator can see WHY a file is in the list (the plan's per-item detail
and the finding's fix text both carry it):

    * :data:`EVIDENCE_WALK_AND_DB` — unreferenced by the rendered pages
      AND by the database.  The strong class: the only candidates an
      apply may delete.
    * :data:`EVIDENCE_WALK_ONLY` — the database side was unavailable, so
      a database-only reference (a menu featured image, a theme option)
      would be invisible.  DEGRADED; the trim-media apply refuses.
    * :data:`EVIDENCE_DB_ONLY` — no live walk (local mode renders
      nothing), so a rendered-only reference is invisible.  DEGRADED;
      still a real measurement, and the trim-media apply refuses it too.

Stem semantics are the exact mirror of ``wpt_file_stem`` in
wpt/wpbridge/bridge.php (the canonical L5 helper): take the basename,
drop the extension at its last dot, then strip one trailing
``-<digits>x<digits>`` or ``-scaled`` per pass for at most 5 passes
(the PHP loop bound, mirrored — not chosen).  ``[0-9]`` matches what
PCRE's ``\d`` does without modifiers: ASCII digits only, never the
Unicode digits Python's ``\d`` would also strip.  The two language
implementations MUST stay in lockstep — migrated sites lack attachment
metadata, so keep-set resolution is purely name-based [L5].

Structural WordPress constants (fixed layout facts, NOT tunables —
documented here per the settings rule):
    * ``wp-content/uploads/`` — the uploads tree prefix.  Entry paths
      are webroot-relative and carry exactly this prefix in BOTH source
      modes (the CLI roots the source at the webroot); the check
      matches that prefix and never reads ``uploads_basedir`` (a
      server-absolute ftp fact that is useless for tree-relative
      matching).  Detail lines drop the prefix for display, so they are
      uploads-relative.
    * 10 — presentation limit for detail lines fixed by this check's
      contract (not a tunable), with a "(+N more)" truncation marker.

Only MEDIA files under wp-content/uploads/ participate — an extension
allowlist decides (``settings.media.extensions``), because a live
reference walk can never "reference" a config or guard file: Wordfence's
uploads .htaccess is a PHP-execution BLOCK [L14: it landed in a live
trim-media plan when every uploads file counted as media], core's
index.php guards and .user.ini/CageFS shim files are the same shape.
Non-media files are invisible to the finding AND to trim-media (the
shared enumeration), and unlisted extensions are merely never flagged
— false negatives are the safe direction for a destructive action.
Deletion is destructive and the verify pass must succeed afterwards
[L2], so the finding is risk "medium".

THE TWO MODES MUST AGREE ON THE DELETE SET (the mode-dependent-keep-set
defect).  The database half of the keep-set is measured offline from the
.sql dump and on the live site by the bridge, and the rules deciding it
are stated once, in :mod:`wpt.media_refs` (normalize, the extension
family, the is-a-directory belt, PHP's ``unserialize`` semantics), each
mirrored in bridge.php and pinned by a differential test that runs the
real ``wpt_media_db_map`` over the same rows and diffs the two answers.
THIS MODULE is part of that chain and adds no rule of its own: the
allowlist verdict below delegates to ``wpt.media_refs.ref_is_kept``, the
very rule the database references are gated with, so "what counts as a
media file" and "what counts as a media reference" can never drift into
two different keep-sets for one database.  For the same reason the run's
OWN family is CARRIED into the live measurement
(``db_refs_for_data(data, settings.media.extensions)``): this check
enumerates with ``settings.media.extensions`` and the bridge gates with
the family the read carries, whose floor is the mirrored default — so a
WIDENED profile widens both halves together instead of leaving the
reference set narrower than the files it is compared against.
"""

import re
from dataclasses import dataclass

from .data import AuditData
from .registry import register_check
from ..media_refs import (
    UPLOADS_PREFIX as _UPLOADS_PREFIX,
    db_refs_for_data,
    ref_is_kept,
)
from ..settings import Settings
from ..types import Entry, Finding

# The structural uploads tree prefix every webroot-relative Entry path
# carries in both source modes (see the module docstring).  OWNED by
# wpt.media_refs beside the marker and the keep-gate that speak the same
# paths, and bound here under the names this module and its callers have
# always used — one fact, one owner.

# Presentation limit fixed by this check's contract (not a tunable):
# max detail lines before the "(+N more)" truncation marker.
_DETAIL_PATHS = 10

# wpt_file_stem's loop bound in bridge.php (at most 5 strip passes) —
# mirrored, not chosen.
_STEM_PASSES = 5

# A trailing "-WxH" ("-" + ASCII digits + "x" + ASCII digits) or
# "-scaled".  [0-9] rather than \d: PCRE's \d is ASCII-only without
# modifiers while Python's \d would also strip Unicode digits and drift
# from the PHP helper.
_STEM_SUFFIX = re.compile(r"-(?:[0-9]+x[0-9]+|scaled)$")

#: The three evidence classes a candidate deletion can carry (module
#: docstring): what the candidate is UNREFERENCED BY, spelled out for the
#: operator.  The trim-media plan's per-item detail and this check's fix
#: text both render them.
EVIDENCE_WALK_AND_DB = "unreferenced by the live walk and the database"
EVIDENCE_WALK_ONLY = (
    "unreferenced by the live walk only (no database reference set)"
)
EVIDENCE_DB_ONLY = "unreferenced by the database only (no live walk)"

#: Why a missing side makes the set degraded — the marker rendered in the
#: finding's fix text, in the plan's advice item and in the apply refusal.
DEGRADED_NO_WALK = (
    "no live walk: rendered pages, srcset candidates and CSS url() "
    "references are NOT part of this set"
)
DEGRADED_NO_DB = (
    "no database reference set: attachment metadata, theme options, "
    "widgets, menus and post content are NOT part of this set"
)

#: The category and name of the finding that says NOTHING WAS MEASURED.
#: Deliberately NOT ``media.unreferenced``: that category's suggested step
#: is ``wpt trim-media --apply`` (report.SUGGESTED_STEPS), and advising a
#: deletion for a run that measured no keep-set at all is the exact
#: misreading this marker exists to prevent.  No suggested-step rule
#: matches this category, and ``count=0`` keeps it out of every total, so
#: a persisted report carries the degradation and nothing else — the shape
#: the registry already uses for ``audit.check_failed``.
UNMEASURED_CATEGORY = "media.unmeasurable"
UNMEASURED_NAME = "unmeasured-keep-set"


def _file_stem(name: str) -> str:
    """Stripped basename stem — the exact mirror of bridge.php wpt_file_stem.

    "2023/10/pic-300x233.jpg" -> "pic"; "pic.jpg" -> "pic";
    "img-scaled-1024x768.jpg" -> "img" (chained suffixes strip one
    per pass, at most _STEM_PASSES passes).  A dotfile keeps PHP's
    behavior: the dot at position 0 leaves an empty stem.
    """
    base = name.rsplit("/", 1)[-1]  # basename() over a POSIX path
    dot = base.rfind(".")
    stem = base if dot < 0 else base[:dot]
    for _ in range(_STEM_PASSES):
        stripped = _STEM_SUFFIX.sub("", stem)
        if stripped == stem:
            break
        stem = stripped
    return stem


def _dir_of(rel: str) -> str:
    """Containing directory of an uploads-relative path ("" at the top)."""
    return rel.rsplit("/", 1)[0] if "/" in rel else ""


@dataclass(frozen=True)
class UnreferencedFile:
    """One deletion candidate: the file plus the evidence class it rests on.

    ``entry`` is the walked :class:`~wpt.types.Entry` (webroot-relative
    path, size); ``evidence`` is one of the ``EVIDENCE_*`` classes, i.e.
    WHICH reference classes measured it as unreferenced.  Kept together so
    no consumer can render a candidate without saying why it is one.
    """

    entry: Entry
    evidence: str


def is_media(rel: str, extensions: list[str] | tuple[str, ...]) -> bool:
    """True when an uploads-relative path is a MEDIA file per the
    extension allowlist [L14].

    A DELEGATION, not a second rule: the verdict is
    :func:`wpt.media_refs.ref_is_kept`'s — the ONE keep-gate, whose
    mirror in bridge.php (``wpt_media_ref_is_kept``) decides what a
    database REFERENCE may name.  That is deliberate.  The enumeration
    (which files may be deleted) and the keep-set (which references
    protect a file) must agree about what a media file is: two
    implementations of one allowlist is how the offline and live halves
    of the keep-set came to disagree about the same database, and a
    disagreement here is a deletion bug in one mode only.

    A dotfile (".htaccess") is never media — its name's only dot is the
    leading one, so it has no extension to allow.  A file without a dot
    ("README"), one with a reversed double extension ("x.jpg.php") and
    one with an unlisted extension ("weird.zzz") all read as non-media:
    invisible to the finding and to trim-media.  Case is normalized (the
    allowlist ships lowercase).  The is-a-directory belt is not applied
    here: a walk entry is already known to be a file.
    """
    return ref_is_kept(rel, extensions)


def _detail_lines(items: list[str]) -> str:
    """Up to _DETAIL_PATHS newline-joined lines; "(+N more)" if truncated."""
    if len(items) <= _DETAIL_PATHS:
        return "\n".join(items)
    return "\n".join(items[:_DETAIL_PATHS]) + f"\n(+{len(items) - _DETAIL_PATHS} more)"


def protected_by(refs: set[str], candidate: str) -> bool:
    """True when ``refs`` (EITHER side, already unioned) protects ``candidate``.

    The keep rule restricted to one uploads-relative path: the candidate is
    protected when it IS a ref, or when some ref sits in the same
    directory with the same stripped stem (L5, symmetric).  Used by the
    trim-media apply, which must re-verify a fresh reference set against
    the planned paths WITHOUT re-walking the whole tree (a 9,000-file
    uploads walk over FTP is not an acceptable price for a guard).
    """
    if candidate in refs:
        return True
    directory, stem = _dir_of(candidate), _file_stem(candidate)
    return any(_dir_of(ref) == directory and _file_stem(ref) == stem
               for ref in refs)


def unreferenced_files(
    entries: list[Entry],
    live_refs: set[str] | None,
    db_refs: set[str] | None,
    extensions: list[str],
) -> list[UnreferencedFile]:
    """Unreferenced uploads MEDIA file entries with their evidence class,
    sorted by path — the shared per-file enumeration behind
    ``media.unreferenced`` AND the trim-media plan (one implementation, so
    the check's aggregate Finding and the action's per-file PlanItems can
    never disagree).

    ``entries`` are webroot-relative walk entries; only MEDIA files
    under wp-content/uploads/ participate — the ``extensions``
    allowlist (``settings.media.extensions``) decides which files count
    as media at all; directories, non-uploads entries and non-media
    uploads files (.htaccess, index.php, stray logs — the L14 rule) are
    invisible.

    ``live_refs`` (rendered pages) and ``db_refs`` (the database, see
    :mod:`wpt.media_refs`) are the TWO halves of the keep-set, and each
    carries the tool-wide None-vs-empty contract: ``None`` = that side is
    unknown, so the set is DEGRADED (the returned candidates say so in
    their evidence class) and an EMPTY set = a measured "nothing
    references any uploads file".  Both sides ``None`` enumerates nothing
    at all: a run that measured neither reference class must never guess
    a keep-set (the degrade the module documents).

    Keep-set semantics are the L5 rule applied to the UNION (refs ∪
    same-directory stem siblings, symmetric, from either side).
    """
    if live_refs is None and db_refs is None:
        return []

    # Uploads MEDIA files; by_stem groups their uploads-relative paths
    # by (directory, stripped stem) for same-directory lookups.
    by_stem: dict[tuple[str, str], list[str]] = {}
    files: list[Entry] = []
    for entry in entries:
        if entry.is_dir or not entry.path.startswith(_UPLOADS_PREFIX):
            continue
        rel = entry.path[len(_UPLOADS_PREFIX):]
        if not is_media(rel, extensions):
            continue
        by_stem.setdefault((_dir_of(rel), _file_stem(rel)), []).append(rel)
        files.append(entry)

    # Keep-set: every ref (on disk or not) plus each ref's on-disk
    # same-directory stem siblings (symmetric — see module docstring).
    # Both sides contribute identically: a database reference keeps
    # exactly what a rendered reference keeps.
    keep: set[str] = set()
    for refs in (live_refs, db_refs):
        if refs is None:
            continue
        for ref in refs:
            keep.add(ref)
            keep.update(by_stem.get((_dir_of(ref), _file_stem(ref)), ()))

    # The evidence class names every side that MEASURED the candidate as
    # unreferenced; a one-sided set therefore degrades its own wording.
    if live_refs is not None and db_refs is not None:
        evidence = EVIDENCE_WALK_AND_DB
    elif live_refs is not None:
        evidence = EVIDENCE_WALK_ONLY
    else:
        evidence = EVIDENCE_DB_ONLY

    # Sorted by entry path == uploads-relative path (the prefix is a
    # constant), the same order the check's detail lines always had.
    flagged = sorted(
        (entry for entry in files
         if entry.path[len(_UPLOADS_PREFIX):] not in keep),
        key=lambda entry: entry.path,
    )
    return [UnreferencedFile(entry=entry, evidence=evidence)
            for entry in flagged]


def degraded_note(live_refs: set[str] | None, db_refs: set[str] | None) -> str:
    """The DEGRADED-MODE marker for a one-sided reference set ("" when the
    set is the full union).

    Names every missing side in the operator's words — the finding's fix
    text, the plan's advice item and the apply refusal all render it, so a
    degraded run can never read like a complete one.
    """
    missing: list[str] = []
    if live_refs is None:
        missing.append(DEGRADED_NO_WALK)
    if db_refs is None:
        missing.append(DEGRADED_NO_DB)
    return "; ".join(missing)


def unmeasured_note(data: AuditData, db_refs: set[str] | None) -> str:
    """The marker for a keep-set that was NEVER MEASURED ("" otherwise).

    A dump whose database half is UNKNOWN (a contested table identity, a
    partial export, a bridge that could not be reached) together with no
    live walk leaves the check with no reference class at all.  It then
    finds nothing — correctly, it has nothing to compare — and used to
    return that silence as a clean report, which contradicts this check's
    own "never a guess, always labelled" contract and is indistinguishable
    in a persisted ``--report`` from a site with no unreferenced media.

    One condition, and the reason it is not "both sides unknown" bare: the
    run must have measured a DATABASE at all.  An input that declares no
    table (an empty or foreign ``--sql``) is a degradation of the whole
    database half of the audit, of which the media check is one voice: it
    has nothing to add to the other database checks' silence, and a marker
    per check would say the same thing once per category.
    """
    if data.live_refs is not None or db_refs is not None:
        return ""            # at least one side measured: not this marker
    if not data.tables:
        return ""            # no database was measured at all
    return (
        "neither reference class could be measured, so NOT ONE uploads file "
        "was tested: this is an unmeasured site, not a clean one"
    )


@register_check("media.unreferenced", applies=("ftp", "local"))
def check_media_unreferenced(data: AuditData, settings: Settings) -> list[Finding]:
    """Uploads media neither the live site nor the database references: one
    aggregate finding over the UNION keep-set.

    Only MEDIA files under wp-content/uploads/ participate (the
    ``settings.media.extensions`` allowlist — directories, non-uploads
    entries and non-media uploads files like .htaccess are invisible,
    the L14 rule).  A file is unreferenced when its uploads-relative path
    is neither a live ref, nor a database ref, nor a same-directory stem
    sibling of one (L5, applied to the union).

    Degrade (never a guess, ALWAYS labelled):
      * neither reference class measurable (:func:`unmeasured_note`) — one
        zero-count INFO marker under :data:`UNMEASURED_CATEGORY`, so a
        persisted report can never read as a clean site;
      * one side unknown — a REAL measurement over the other half, marked
        DEGRADED in the fix text with the missing side named;
      * a local run, where there is no live walk — a REAL measurement over
        the database side alone, marked DEGRADED;
      * an ftp run with an unreachable/unanalyzable database map — the
        walk-only measurement, marked DEGRADED.

    Detail lines are uploads-relative, sorted, capped at 10 with a
    "(+N more)" marker.  Deletion is destructive and verify must pass
    after — risk "medium"; the fix text names the evidence class(es) the
    candidates rest on, so the operator sees WHY each file is a candidate.
    """
    db_refs = db_refs_for_data(data, settings.media.extensions)
    unreferenced = unreferenced_files(
        data.entries, data.live_refs, db_refs, settings.media.extensions
    )
    if not unreferenced:
        unmeasured = unmeasured_note(data, db_refs)
        if not unmeasured:
            return []
        return [
            Finding(
                category=UNMEASURED_CATEGORY,
                name=UNMEASURED_NAME,
                detail=f"DEGRADED — {unmeasured} (no media candidate is "
                       f"reported, and none can be justified)",
                count=0,
                risk="low",
                fix="pass a COMPLETE database export (--sql must include "
                    "wp_postmeta and wp_posts) and re-run, or measure the "
                    "live site with an ftp source",
            )
        ]

    classes = sorted({candidate.evidence for candidate in unreferenced})
    fix = ("trim-media after reviewing; verify all references afterwards "
           "(evidence: " + ", ".join(classes) + ")")
    degraded = degraded_note(data.live_refs, db_refs)
    if degraded:
        fix += f". DEGRADED — {degraded}; run it against the live site "\
               "(ftp source) for the full reference set"
    return [
        Finding(
            category="media.unreferenced",
            name="unreferenced-media",
            detail=_detail_lines(
                [candidate.entry.path[len(_UPLOADS_PREFIX):]
                 for candidate in unreferenced]
            ),
            bytes=sum(candidate.entry.size for candidate in unreferenced),
            count=len(unreferenced),
            risk="medium",
            fix=fix,
        )
    ]
