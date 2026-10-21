"""optimize-media action (W7g): recompress oversized uploads images in place.

Two-phase action over the shared registry flow (``wpt.actions.registry`` —
the registry owns dry-run, confirmation, the fail-closed pre-action backup
and the local-mode write refusal; this module is pure domain logic).
Registered ``applies=("ftp", "local")``: the plan needs only the Source
(ONE walk + per-candidate reads), so it runs over the live site AND over
an offline zip; the apply mutates the webroot, so local mode never
reaches it through the registry (v1 write refusal, rc 1).  The action
body itself works on any Source — called directly against a read-only
zip, every item fails without raising (clean-files semantics).

Local backups: the registry's pre-action snapshot IS the backup.  Every
planned item targets the file it recompresses, so the snapshot captures
every original before the first upload — this module never writes backup
copies itself (and never leaves any artifact in the webroot).

``plan`` (read-only):

* Candidates: FILES under ``wp-content/uploads/`` (the shared
  ``_UPLOADS_PREFIX`` owner, ``wpt.audit.media``) whose suffix is
  ``.jpg``/``.jpeg``/``.png`` (case-insensitive) and whose on-disk size
  is >= ``settings.media_optimize.skip_below_bytes`` — the size gate
  runs on the walk entry, before any download, so small files cost one
  comparison.  All thresholds come from the settings object; none live
  here.
* A file under any ``settings.media_optimize.exclude_prefixes`` subtree
  leaves the candidate set BEFORE the suffix and size gates (:func:`_excluded`):
  it is never downloaded, never planned, and never applied to — the plan
  is SILENT about it (this action is not a check; an out-of-scope file is
  not a finding), while the summary log reports HOW MANY files were
  skipped, so an operator can see the subtree was honoured without the
  plan listing the records it protects.  The shipped default excludes the
  Gravity Forms submission-record subtree — those are people-uploaded
  photos, and a live migration recompressed them.
* Each candidate is downloaded (``source.read_bytes``) and recompressed
  IN MEMORY (:func:`_recompress` — BytesIO only, never a tmp file).
* A candidate whose recompressed bytes are smaller than the original by
  at least ``media_optimize.min_savings_ratio`` becomes ONE PlanItem:
  category ``media.oversized``, ``target`` = the WEBROOT-relative path
  (what the registry's pre-action backup captures), ``bytes_est`` =
  original - recompressed, detail =
  ``"{uploads-relative path} ({orig} -> {new})"`` (human_bytes, same
  display-path convention as trim-media).  Items are sorted by target.
* A candidate Pillow cannot decode returns ``None`` from
  :func:`_recompress` and is skipped with ONE debug log — corrupt files
  are not this action's business.  A source-level READ failure is not
  per-file noise: it propagates and the registry answers rc 1
  (fail-closed — a plan over a half-readable tree would be a guess).
* ``plan.backup_tables = []`` deliberately: no DB rows mutate (the
  attachment posts are untouched), so the pre-action snapshot has no
  table side.  Distinct from ``None``: the registry then snapshots
  exactly the planned files with no bridge roundtrip.

``apply`` (the plan's measurements may be stale — the file may have
changed since): every ``requires_apply`` item is re-downloaded and
recompressed FRESH, and uploaded via ``source.write_bytes`` ONLY when
the fresh savings still clear ``min_savings_ratio``.  Per-item
outcomes:

* upload lands -> ``done=True`` + one info log (path, old -> new bytes);
* fresh pass finds no savings -> ``done=True``, detail enriched
  ``", already optimal"``, NO upload (the file changed since the plan —
  a settled truth, not a failure; uploading a byte-identical or larger
  file would be noise);
* fresh bytes no longer decode -> ONE warning, ``done=False`` (the
  skip semantics of the plan phase — the item is genuinely not done);
* :class:`WptError` / ``OSError`` on read or write -> ONE warning,
  ``done=False``, the batch continues (items are independent).

Logging: ``get_logger("actions.optimize_media")`` — one info plan
summary (candidates scanned / optimizable count / estimated savings /
files skipped by ``exclude_prefixes``), per-upload info lines and
per-failure warnings.  Paths and byte counts only, never image content.
"""

from __future__ import annotations

import io
from typing import TYPE_CHECKING

import PIL.Image
import PIL.ImageOps

from ..audit.media import _UPLOADS_PREFIX
from ..deadline import Deadline, bounded_walk
from ..log import get_logger
from ..report import Plan, human_bytes
from ..settings import MediaOptimizeSettings
from ..types import PlanItem, WptError
from .registry import register_action

if TYPE_CHECKING:
    from ..cli import Ctx

__all__ = ["OptimizeMediaAction"]

log = get_logger("actions.optimize_media")

#: Uploads file suffixes this action recompresses — exactly the encoders
#: :func:`_recompress` implements (JPEG + PNG; webp/gif are v2 scope).
#: Structural capability set, not a tunable: the uploads tree location
#: is likewise structural (see wpt.audit.media).
_SUFFIXES = frozenset({"jpg", "jpeg", "png"})

#: The JPEG side of _SUFFIXES (chooses the encoder + jpeg_max_dim).
_JPEG_SUFFIXES = frozenset({"jpg", "jpeg"})


def _suffix_of(path: str) -> str:
    """Lowercase extension without the dot ("" when the name has none)."""
    head, dot, ext = path.rpartition(".")
    return ext.lower() if dot else ""


def _worth(original: int, optimized: int, settings: MediaOptimizeSettings) -> bool:
    """True when ``optimized`` is smaller than ``original`` by at least
    ``min_savings_ratio`` (a bigger result fails — negative savings)."""
    return original - optimized >= settings.min_savings_ratio * original


def _excluded(path: str, settings: MediaOptimizeSettings) -> bool:
    """True when ``path`` falls under an ``exclude_prefixes`` subtree.

    A literal webroot-relative prefix match, the shape the shipped values
    use: a directory prefix ends in "/" and therefore covers its whole
    subtree, and a file prefix covers that one file.  An empty list (the
    structural code default) excludes nothing.  Validated at the settings
    owner, so no entry here is blank or root-absolute.
    """
    return any(path.startswith(prefix)
               for prefix in settings.exclude_prefixes)


def _recompress(data: bytes, suffix: str,
                settings: MediaOptimizeSettings) -> bytes | None:
    """Re-encode one image in memory; ``None`` when Pillow cannot decode it.

    Rules (coordinator-pinned):

    * EXIF orientation is honored FIRST (``ImageOps.exif_transpose``) so
      every dimension decision and resample sees the DISPLAY orientation;
      the transposed pixels are saved without an orientation tag.
    * JPEG (``.jpg``/``.jpeg``): downscaled to fit ``jpeg_max_dim`` when
      width OR height exceeds it (``thumbnail``, LANCZOS, aspect
      preserved, never upscaled), then saved at
      ``quality=settings.jpeg_quality`` with ``optimize=True`` and
      ``progressive=True``.  A JPEG has no alpha, so ``RGBA``/``P``/``LA``
      sources are flattened with ``convert("RGB")``; CMYK JPEGs save
      fine and stay CMYK.
    * PNG: downscaled to fit ``png_max_dim``, saved with
      ``optimize=True``.  NEVER converted to JPEG (alpha/transparency
      loss is a no) — so a same-size PNG re-save is roughly size-neutral
      and only a downscaled PNG can plan.
    * Never writes to disk: everything happens in BytesIO.

    Returns ``None`` for anything Pillow refuses to decode or re-encode
    (``UnidentifiedImageError``, ``OSError`` — truncated data,
    ``ValueError`` — e.g. a mode the target format cannot store, and
    Pillow's ``DecompressionBombError`` decode refusal): corrupt files
    are not this action's business, and a bomb refusal must NOT escape
    as a traceback through the registry's error contract.
    """
    if suffix not in _SUFFIXES:
        return None
    try:
        with PIL.Image.open(io.BytesIO(data)) as opened:
            image = PIL.ImageOps.exif_transpose(opened)
            max_dim = (settings.jpeg_max_dim if suffix in _JPEG_SUFFIXES
                       else settings.png_max_dim)
            if image.width > max_dim or image.height > max_dim:
                image.thumbnail((max_dim, max_dim), PIL.Image.Resampling.LANCZOS)
            out = io.BytesIO()
            if suffix in _JPEG_SUFFIXES:
                if image.mode in ("RGBA", "P", "LA"):
                    image = image.convert("RGB")
                image.save(out, format="JPEG", quality=settings.jpeg_quality,
                           optimize=True, progressive=True)
            else:
                image.save(out, format="PNG", optimize=True)
            return out.getvalue()
    except (PIL.Image.UnidentifiedImageError,
            PIL.Image.DecompressionBombError,
            OSError,
            ValueError):
        return None


class OptimizeMediaAction:
    """The plan/apply pair; ``stack`` is the registry-built source trio."""

    def plan(self, ctx: "Ctx", stack: tuple) -> Plan:
        source = stack[0]
        media = ctx.settings.media_optimize
        deadline = Deadline.from_ctx(ctx)
        scanned = 0
        excluded = 0
        items: list[PlanItem] = []
        for entry in bounded_walk(source, deadline, "optimize-media plan"):
            if entry.is_dir or not entry.path.startswith(_UPLOADS_PREFIX):
                continue
            if _excluded(entry.path, media):
                # out of scope, NOT a finding: counted, never downloaded,
                # never planned, never applied to
                excluded += 1
                continue
            suffix = _suffix_of(entry.path)
            if suffix not in _SUFFIXES:
                continue
            if entry.size < media.skip_below_bytes:
                continue  # size gate before any download
            scanned += 1
            if deadline is not None:
                deadline.check("optimize-media plan read")
            original = source.read_bytes(entry.path)
            if deadline is not None:
                deadline.check("optimize-media plan recompress")
            optimized = _recompress(original, suffix, media)
            if optimized is None:
                log.debug("skipping %s: not a decodable image", entry.path)
                continue
            if not _worth(len(original), len(optimized), media):
                continue
            items.append(
                PlanItem(
                    category="media.oversized",
                    target=entry.path,
                    detail=(
                        f"{entry.path[len(_UPLOADS_PREFIX):]} "
                        f"({human_bytes(len(original))} -> "
                        f"{human_bytes(len(optimized))})"
                    ),
                    bytes_est=len(original) - len(optimized),
                )
            )
        items.sort(key=lambda item: item.target)
        plan = Plan(items=items, backup_tables=[])
        log.info(
            "plan: %d candidate(s) scanned, %d optimizable, %s estimated, "
            "%d file(s) skipped by exclude_prefixes",
            scanned, len(items), human_bytes(plan.est_bytes()), excluded,
        )
        return plan

    def apply(self, ctx: "Ctx", stack: tuple, plan: Plan) -> Plan:
        source = stack[0]
        media = ctx.settings.media_optimize
        deadline = Deadline.from_ctx(ctx)
        for item in plan.items:
            if not item.requires_apply:
                continue
            if deadline is not None:
                deadline.check("optimize-media apply")
            try:
                original = source.read_bytes(item.target)
                if deadline is not None:
                    deadline.check("optimize-media apply recompress")
                optimized = _recompress(original, _suffix_of(item.target), media)
                if optimized is None:
                    log.warning(
                        "could not optimize %s (no longer a decodable image); "
                        "continuing", item.target)
                    continue
                if not _worth(len(original), len(optimized), media):
                    # The file changed since the plan and is now optimal
                    # enough: settled WITHOUT an upload — done, not failed.
                    item.done = True
                    item.detail = f"{item.detail}, already optimal"
                    log.info("apply: %s already optimal", item.target)
                    continue
                if deadline is not None:
                    deadline.check("optimize-media apply write")
                source.write_bytes(item.target, optimized)
            except (WptError, OSError) as exc:
                log.warning("could not optimize %s (%s: %s); continuing",
                            item.target, type(exc).__name__, exc)
                continue
            item.done = True
            log.info("apply: %s (%s -> %s)", item.target,
                     human_bytes(len(original)), human_bytes(len(optimized)))
        if deadline is not None:
            deadline.check("optimize-media apply end")
        return plan


# The registry stores the decorated OBJECT and calls .plan/.apply on it,
# so the registered action is the instance (same as clean_files/clean_db/
# trim_media: a bare class would be invoked with plan(ctx, stack) unbound
# and crash in run_action).
register_action("optimize-media", applies=("ftp", "local"))(OptimizeMediaAction())
