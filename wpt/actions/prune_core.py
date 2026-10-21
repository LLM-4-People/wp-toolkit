"""prune-core action: delete the STALE core files — the ones WordPress
no longer ships.

Live motivation (a masked ``wp-includes/version.php``, so years of
incomplete WordPress upgrades went unnoticed): an observed host's tree held
many files wp.org no longer ships — a legacy bundled library, the generated
icon set, old block ``view.js`` / ``editor.css`` pairs, the retired
``css/dist`` + ``js/dist`` bundles, legacy header images and a handful of
``wp-content/languages`` catalogs.  ``wp-cli core verify-checksums`` listed
every one of them as "should
not exist".  The toolkit's own ``core.integrity`` check saw only 62 of
them: its ``added`` scope is a ``.php`` under wp-admin/wp-includes or at
the webroot top level, so an ``.svg``/``.webp``/``.po``/``.js`` orphan
is invisible to it — and by DESIGN it never deletes an ``added`` file
("investigate only").  The operator was left hand-deleting files over
SSH: an hour of surgery, and a risk.  This action is that hour, done
safely and reversibly.

The two-proof rule (binding — this is the whole safety argument):

A webroot file is planned for deletion ONLY when ALL THREE hold.

1. **Absent from the official checksum map** of the site's EXACT
   version + BUILD locale — the SAME map
   ``core.integrity`` compares against (``_fetch_comparison_checksums``,
   the ONE-warning en_US fallback, over the SAME
   :func:`~wpt.audit.integrity.resolve_core_locale` basis, the SAME
   version seam).  A file the current release still ships is never a
   candidate whatever else it looks like.
2. **In prune scope** — under ``wp-admin/`` or ``wp-includes/``, or a
   ``wp-content/languages/`` runtime catalog path.  Those are exactly
   the trees ``core.integrity`` owns (its ``added`` scope, its
   translation-pack exemption, its missing scope); a plugin, a theme, an
   upload, a webroot-top-level drop-in and anything else is
   out of scope, forever, whatever it looks like.  The catalog half of
   the scope reuses the integrity module's OWN predicate
   (:func:`~wpt.audit.integrity._is_translation_catalog`, the four
   runtime formats WordPress's translation machinery owns) so the two
   can never drift on what a language catalog is.
3. **A content marker proving it is a STALE CORE FILE, never an
   unknown drop-in** — it must carry at least ONE of the two proofs:

   * **Release provenance** — the path appears in the checksum map of a
     PREVIOUS release of the SAME build (``_fetch_checksums`` over the
     same :class:`~wpt.audit.updates.WpOrgApi` transport, at the same
     locale the comparison resolved to).  "This file WAS core; the
     current release dropped it."  Provenance, not a guess: a path in
     no earlier release's map was never core, whatever its name
     suggests.
   * **A profile signature** — the path matches a
     ``core_integrity.known_stale`` entry (glob ``name`` + content
     ``marker`` + ``max_bytes`` + ``note``; the known_added precedent,
     same key set, so the settings loader's existing list-of-objects
     validator covers it unchanged) — the escape hatch for a stale
     artifact older than the proof window, which the operator must
     declare, never the tool.

   A file matching NEITHER is a truly unknown addition — a potential
   implant — and is NEVER planned.  It is named in ONE
   investigate-only info line, exactly the way heal-core names its
   ``added`` files (``Plan`` carries items + backup_tables only, so that
   log line IS the note).

Fail-closed everywhere it matters:

* an unknown version (the maps are version-pinned) or an unavailable
  comparison map -> refuse, nothing planned;
* an available window of previous releases whose maps ALL fail to fetch
  -> the WHOLE plan refuses: a prune without the "was core" proof is not
  a prune, and the transport's own single warning already named the
  reason (no second warning is stacked on top of it);
* an unparseable installed version, or a version whose patch is ``.0``
  (no earlier release of that series exists) -> NO provenance proof is
  available; only profile signatures can plan a deletion, and the plan
  says so in one warning.  Never a guessed version;
* ``wp-config.php`` / ``.htaccess`` are out of scope by rule 2 and, if
  a hand-built plan ever named one, refused by the source's own delete
  guard — the refuse-list is absolute, in the guard and nowhere else;
* the signature scan is a *bonus* proof, so a failed read, an oversized
  file, a deadline stop or a transport hiccup can only ever produce
  FEWER deletions, never more.

``plan`` (read-only inventory):

1. ONE walk of the source tree — BEFORE the first bridge call (the
   gather's discipline: the bridge lazy-deploys on its first call and a
   later walk would flag wpt's own bridge-<8hex>.php).
2. The version + locale (heal-core's own re-derivable basis seam, read
   — never re-implemented), then the comparison map through the audit's
   fallback-aware fetch seam, on the stack's session in ftp mode (the
   audit's DNS-override-aware wp.org transport) and a fresh plain
   session locally (the site is offline, wp.org is not).
3. The candidate set = walked files, in scope, absent from the map.
   NO digest sweep: unlike heal-core this action never compares file
   contents against the map, so the ~3800-path ``core_md5`` round trip
   is not needed — a plan is one walk and a few wp.org maps.
4. The proofs: the previous-release maps (above) and the
   ``known_stale`` signatures (one ``read_many`` per bounded batch,
   deadline-checked, content-marked).
5. Every proven path becomes ONE PlanItem: category ``core.integrity``
   (the audit's own category — the operator reads the prune as the
   integrity finding's fix), ``target`` = the webroot-relative path,
   ``detail`` = the provenance ("shipped by WP 6.8.1/6.8.0, dropped by
   WP 6.8.3 — delete") or the signature ("known_stale signature .. —
   delete"), ``bytes_est`` = the walked size.  ``backup_tables = []``
   deliberately (files only — the registry derives the pre-action
   snapshot's file scope from the item targets).
6. Zero items -> an EMPTY plan (rc 0 in both phases), with one info
   naming the case: "nothing to prune", or — when only unknown files
   exist — the investigate-only line.

``apply`` (the mutation; the plan is executed AS-IS, never
re-classified — the state can change between plan and apply and that is
fine and honest, like every other action):

* The pre-apply tree is walked FIRST and the comparison map re-fetched
  through the audit's own seam (1h cache: free) BEFORE the first
  delete, because both are the verify's inputs and a verify whose basis
  is missing must refuse with NOTHING deleted — never skip a
  verification because the network blinked mid-run.
* Per item, in plan order: a target already absent from the pre-apply
  tree is the goal state (nothing to delete — the idempotent no-op).
  Otherwise ``source.delete(target)`` through the SOURCE, whose
  ``_check_deletable`` guard is the same audited choke point every
  delete in this toolkit passes: it refuses ``wp-config.php``,
  ``.htaccess``, ``index.php`` and the bare ``wp-admin`` /
  ``wp-includes`` directory names, and allows deletes INSIDE the core
  subtrees (the design clean-files already relies on for
  ``wp-admin/error_log``).  A delete inside a protected core tree is
  announced with the guard's own audited warning line before it runs,
  naming the file and the proof — a core-tree deletion is never silent.
  A delete failure (a refused path, an ftp DELE error) is ONE warning
  + continue: items are independent.
* MANDATORY verification (the SPEC's verify-after-mutate rule; never
  skipped, never assumed): the tree is re-walked and the SURVIVING set
  re-checked — a planned path still present after the deletes is an
  item NOT done (ONE warning naming it), and a path the current
  checksum map ships which was present BEFORE the apply and gone AFTER
  it — and was not a planned target — is COLLATERAL DAMAGE (named
  explicitly; the deletes are independent and per-file, so this is a
  source-level surprise, not an expected shape).
* Any item not done, or any collateral loss -> ONE terminal WptError:
  "prune incomplete: N of M stale file(s) removed; not removed: <paths>"
  (+ the collateral clause when it fired).  The registry turns that
  into rc 1 with the pre-action snapshot INTACT — that snapshot holds
  the exact plan scope, so ``wpt restore`` writes back every removed
  stale file (and, for a target the snapshot recorded as ABSENT,
  deletes it again: the same revert contract heal-core relies on).
  All done -> the plan returns (rc 0; the registry purges caches and
  prints).

Idempotent by construction: the plan's candidate set is "in the tree and
absent from the map", so a second run over a pruned tree plans nothing,
and an apply over an empty plan does no walk, no fetch and no delete.

Local mode: registered ``applies=("ftp", "local")``; the registry's
local ``--apply`` is the REHEARSAL (MutableZipSource overlay, the
materialized twin, the original zip is the rollback).  The module is
mode-agnostic given the stack: a ``None`` bridge IS the local shape
every branch keys on (version.php for the version, ``read_many`` for the
signature markers, ``walk`` for both verifies).

Logging: ``get_logger("actions.prune_core")`` — one info per phase,
one warning per failure, one warning per audited core-tree delete; paths,
counts, versions and locales only, never file contents.
"""

from __future__ import annotations

from fnmatch import fnmatchcase
from typing import TYPE_CHECKING

from ..audit.integrity import (
    _fetch_checksums,
    _fetch_comparison_checksums,
    _is_translation_catalog,
    resolve_core_locale,
)
from ..deadline import Deadline, bounded_walk
from ..log import get_logger
from ..report import Plan, human_bytes
from ..types import DeadlineExceeded, Entry, PlanItem, WptError
from ..audit.updates import owned_session
from .heal_core import _wp_basis, _wporg_transport
from .registry import register_action

if TYPE_CHECKING:
    from ..cli import Ctx
    from ..types import Source

__all__ = ["PruneCoreAction"]

log = get_logger("actions.prune_core")

#: The core subtrees prune-core may touch — EXACTLY the trees
#: wpt.audit.integrity owns (its ``added`` scope, its ``missing`` scope,
#: its translation-pack exemption).  Structural WordPress facts, NOT
#: tunables: pruning outside them is the "never delete an unknown file"
#: rule, not a policy an operator relaxes.
_CORE_TREES = ("wp-admin/", "wp-includes/")

#: The proof window: how many patch releases older than the installed
#: one this action asks wp.org about ("N-1/N-2" in the common case).
#: Structural bound of THIS action's contract, NOT a tunable: the window
#: only ever ADDS provenance (a path proven by ANY fetched release is
#: proven; a release that answers nothing contributes nothing), so a
#: deeper window prunes more and never deletes more without proof.
_PREVIOUS_RELEASE_DEPTH = 4

#: read_many batching for the signature-marker scan.  Structural, not a
#: tunable — the local twin of the integrity comparison's own batch
#: bound: it caps the batch's in-memory bytes and gives the run deadline
#: a checkpoint at least every _READ_MANY_BATCH candidate files.
_READ_MANY_BATCH = 200


def _in_prune_scope(path: str) -> bool:
    """True for a path inside one of the trees prune-core owns.

    The wp-admin//wp-includes/ subtrees plus the ``wp-content/languages/``
    runtime catalogs — the last half delegated to the integrity module's
    OWN predicate (:func:`~wpt.audit.integrity._is_translation_catalog`,
    the four formats WordPress's translation machinery owns and
    reloads) so the prune and the audit can never disagree about what a
    language catalog is.  Nothing else is ever in scope: no plugins, no
    themes, no uploads, no webroot top level, no config files.
    """
    return path.startswith(_CORE_TREES) or _is_translation_catalog(path)


def _prune_basis(source: "Source", bridge,
                 deadline: "Deadline | None" = None) -> tuple[str, str | None]:
    """(wp_version, site_locale) — prune's version/locale basis.

    heal-core's own re-derivable seam (its info call over the bridge,
    its wp-includes/version.php read through the source) — read, never
    re-implemented, so the two actions can never disagree about the
    site's version.  The refusal is re-worded for this action: the pin
    is the same (both maps are version-pinned), the message must not
    tell a prune operator about a heal.
    """
    try:
        return _wp_basis(source, bridge, deadline=deadline)
    except WptError as exc:
        raise WptError(
            "unknown WordPress version — cannot prune (the checksums basis "
            "is version- and locale-pinned); refusing to guess"
        ) from exc


def _previous_versions(version: str) -> list[str]:
    """The proof window: patch releases older than ``version``, nearest first.

    ``6.8.3`` -> ``["6.8.2", "6.8.1", "6.8.0"]`` (the walk stops at
    patch 1 — a ``6.8.0`` has no older release IN ITS OWN series, and
    guessing which patch of the previous minor existed would be exactly
    the kind of invented version this action refuses to build on).  An
    unparseable version, or a version that is not ``major.minor.patch``
    with numeric parts, yields NO window — never a guess.
    """
    parts = version.split(".")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        return []
    major, minor, patch = (int(part) for part in parts)
    window: list[str] = []
    for _ in range(_PREVIOUS_RELEASE_DEPTH):
        if patch < 1:
            break
        patch -= 1
        window.append(f"{major}.{minor}.{patch}")
    return window


def _previous_maps(
    version: str, session, timeout_s: int, locale: str,
    deadline: Deadline | None = None, config=None,
) -> dict[str, set[str]]:
    """{previous_version: its path set} — the release-provenance proofs.

    Each candidate rides the SAME :class:`~wpt.audit.updates.WpOrgApi`
    transport and the SAME ``_fetch_checksums`` seam the current
    comparison used, at the SAME locale the comparison resolved to —
    deliberately WITHOUT the en_US fallback that comparison seam offers.
    The proof must be apples-to-apples: "the current <locale> build does
    not ship it, an earlier <locale> build did" is a fact, while
    "the current en_US map does not list it and the earlier fr_CA map
    does" is exactly how a localized build's own file gets deleted
    (the [L17] class of bug, inverted).  A fallback would only ever make
    the window WEAKER here, never stronger.

    An EMPTY window (the installed patch is ``.0``) is not a failure: it
    is one warning saying that no provenance exists, leaving the
    profile signatures as the only possible proof.

    A window that EXISTS but yields no map at all REFUSES the plan
    (WptError).  Every failed fetch already logged exactly one transport
    warning naming its reason; this action stacks no second warning on
    top — it simply refuses, because a prune without the "this file WAS
    core" proof is not a prune.
    """
    window = _previous_versions(version)
    if not window:
        log.warning(
            "plan: WP %s is the first release of its patch series — no "
            "earlier release of this build exists to prove staleness "
            "against; only core_integrity.known_stale signatures can "
            "plan a deletion on this site", version,
        )
        return {}
    maps: dict[str, set[str]] = {}
    for previous in window:
        previous_map = _fetch_checksums(previous, session, timeout_s, locale,
                                        deadline=deadline, config=config)
        if previous_map:
            maps[previous] = set(previous_map)
    if not maps:
        raise WptError(
            f"cannot prune: the official WP checksums for the previous "
            f"release(s) of {version} ({', '.join(window)} at {locale}) "
            f"are unavailable — a prune without the \"this file WAS core\" "
            f"proof is not a prune; refusing (the transport's own warnings "
            f"name the reason)"
        )
    return maps


def _known_stale_signatures(ctx: "Ctx") -> list[dict]:
    """The profile's ``core_integrity.known_stale`` signatures, validated.

    Same key set as ``known_added`` (name / marker / max_bytes / note),
    so the settings loader's list-of-objects validator accepts a profile
    entry unchanged; ``name`` is an fnmatch pattern over the
    webroot-relative path here (a stale artifact is a TREE — the live
    case is the icon-library svg tree, which no exact-name list could
    name), ``marker`` a content substring the file must carry.

    The one wiring caveat: this action reads the field when the
    settings section carries it.  A build whose
    ``CoreIntegritySettings`` has no ``known_stale`` field yet simply has
    no signature proof (an empty list) — the release-provenance proof
    stands alone, and the plan says which proofs it used.
    """
    raw = getattr(ctx.settings.core_integrity, "known_stale", ())
    signatures: list[dict] = []
    for index, sig in enumerate(raw):
        if (isinstance(sig, dict)
                and isinstance(sig.get("name"), str) and sig["name"]
                and isinstance(sig.get("marker"), str) and sig["marker"]
                and isinstance(sig.get("max_bytes"), int)
                and not isinstance(sig.get("max_bytes"), bool)
                and isinstance(sig.get("note"), str)):
            signatures.append(sig)
        else:
            log.error(
                "core prune: known_stale signature %d is malformed, skipped",
                index,
            )
    return signatures


def _signature_proofs(
    candidates: list[str],
    files: dict[str, Entry],
    source: "Source",
    signatures: list[dict],
    deadline: Deadline | None,
) -> dict[str, dict]:
    """{path: signature} for candidates PROVEN stale by a profile marker.

    A candidate is a signature candidate when its path fnmatches a
    signature's ``name`` AND its walked size is within that signature's
    ``max_bytes`` — an oversized file is never read for a marker it
    could not carry, so a huge drop-in can never match a small
    signature's cap by accident.  Markers are read in bounded
    ``read_many`` batches (deadline-checked) and a file is proven only
    when its bytes carry the signature's ``marker``.

    Every failure keeps the return CONSERVATIVE (fewer deletions, never
    more): an unreadable file, a failed batch, a size above the cap and
    an absent marker all simply do not prove anything, so the file falls
    through to the investigate-only note where the operator sees it.  One
    debug per unreadable file, one warning per failed batch or deadline
    stop, and never a raise.
    """
    proofs: dict[str, dict] = {}
    if not signatures:
        return proofs
    candidates_by_path: dict[str, dict] = {}
    for path in candidates:
        size = files[path].size
        for sig in signatures:
            if size > sig["max_bytes"]:
                continue
            if fnmatchcase(path, sig["name"]):
                # First matching profile entry wins, in settings order
                # (the clean-files known_added precedent).
                candidates_by_path[path] = sig
                break
    ordered = sorted(candidates_by_path)
    for start in range(0, len(ordered), _READ_MANY_BATCH):
        batch = ordered[start:start + _READ_MANY_BATCH]
        if deadline is not None:
            try:
                deadline.check("core prune marker scan")
            except DeadlineExceeded:
                log.warning(
                    "core prune: marker scan stopped: run deadline "
                    "exceeded; the signatures proved so far stand, the "
                    "rest stay investigate-only"
                )
                # A deadline is the run's verdict, never a partial rc 0.
                raise
        # Bound EVERY read by the largest signature cap in this batch: a
        # listing can report SIZE_UNKNOWN (-1), which passes the plan's
        # ``size > max_bytes`` gate and previously buffered the whole file.
        batch_cap = max(candidates_by_path[path]["max_bytes"]
                        for path in batch)
        try:
            ok, failed = source.read_many(batch, max_bytes=batch_cap)
        except DeadlineExceeded:
            log.warning(
                "core prune: marker scan stopped: run deadline exceeded; "
                "the signatures proved so far stand, the rest stay "
                "investigate-only"
            )
            raise
        except Exception as exc:  # a source fault must never widen a prune
            log.warning(
                "core prune: reading %d candidate file(s) for the "
                "known_stale marker check failed (%s); they stay "
                "investigate-only", len(batch), exc,
            )
            return proofs
        for path in batch:
            blob = ok.get(path)
            if blob is None:
                log.debug("core prune: skipping unreadable candidate %s: %s",
                          path, failed.get(path, "no read_many answer"))
                continue
            sig = candidates_by_path[path]
            if len(blob) > sig["max_bytes"]:
                continue
            if sig["marker"] in blob.decode("utf-8", errors="replace"):
                proofs[path] = sig
    return proofs


class PruneCoreAction:
    """The plan/apply pair; ``stack`` is the registry-built source trio
    (ftp: ``(source, session, bridge)``; local: ``(source, None, None)``
    — a None bridge IS the local shape every branch keys on)."""

    def plan(self, ctx: "Ctx", stack: tuple) -> Plan:
        source = stack[0]
        bridge = stack[2]
        # The budget exists BEFORE the first walk: a hostile/broken source
        # cannot make the plan's own listing outlive --deadline (R14-P2).
        deadline = Deadline.from_ctx(ctx)
        # The walk runs BEFORE the first bridge call (the gather's
        # discipline): the bridge lazy-deploys on its first call, and a
        # walk after it would flag wpt's own bridge-<8hex>.php.
        files = {entry.path: entry
                 for entry in bounded_walk(source, deadline,
                                            "prune-core walk")
                 if not entry.is_dir}
        version, site_locale = _prune_basis(source, bridge, deadline=deadline)
        # [L17] keyed to the BUILD the installed files came from — the
        # SAME resolver the audit check and heal-core use.
        wp_org = ctx.settings.wp_org
        locale = resolve_core_locale(source, site_locale, wp_org.default_locale)
        session, timeout_s = _wporg_transport(ctx, stack)
        with owned_session(session, stack[2] is None):
            checksums, effective_locale = _fetch_comparison_checksums(
                version, session, timeout_s, locale, deadline=deadline,
                config=wp_org,
            )
            if checksums is None:
                raise WptError(
                    f"cannot prune: wp.org checksums for WP {version} are "
                    "unavailable — no comparison basis; refusing to prune"
                )
            # Absent from the CURRENT release, inside a tree this action
            # owns.  No digest pass: this action never compares file
            # contents against the map, so the ~3800-path core_md5 sweep
            # heal-core needs is not needed here.
            candidates = sorted(
                path for path in files
                if _in_prune_scope(path) and path not in checksums
            )
            if not candidates:
                # Nothing to prove and nothing to fetch: a pruned (or clean)
                # tree plans nothing and needs no release provenance at all
                # — the idempotence case, and a site whose previous-release
                # maps are unreachable must still report its own clean state.
                log.info("plan: nothing to prune; no stale core file under "
                         "wp-admin/, wp-includes/ or wp-content/languages/")
                return Plan(items=[], backup_tables=[])
            previous = _previous_maps(
                version, session, timeout_s, effective_locale,
                deadline=deadline, config=wp_org,
            )
        signature_proofs = _signature_proofs(
            candidates, files, source, _known_stale_signatures(ctx),
            Deadline.from_ctx(ctx),
        )
        items: list[PlanItem] = []
        unknown: list[str] = []
        for path in candidates:
            shipped_by = sorted(prev for prev, paths in previous.items()
                                if path in paths)
            if shipped_by:
                items.append(PlanItem(
                    category="core.integrity",
                    target=path,
                    detail=f"stale core file — shipped by WP "
                           f"{'/'.join(shipped_by)}, dropped by WP "
                           f"{version} {effective_locale} — delete",
                    bytes_est=files[path].size,
                ))
                continue
            sig = signature_proofs.get(path)
            if sig is not None:
                items.append(PlanItem(
                    category="core.integrity",
                    target=path,
                    detail=f"stale core file — core_integrity.known_stale "
                           f"signature \"{sig['name']}\" ({sig['note']}) "
                           f"— delete",
                    bytes_est=files[path].size,
                ))
                continue
            unknown.append(path)
        # Files only: backup_tables=[] deliberately (the heal /
        # optimize-media precedent) — the registry derives the
        # pre-action snapshot's file scope from the item targets.
        plan = Plan(items=items, backup_tables=[])
        if unknown:
            log.info(
                "plan: %d file(s) in the core trees are in no WP %s "
                "release map and match no core_integrity.known_stale "
                "signature — unknown additions (a possible implant), "
                "investigate-only, never auto-deleted: %s",
                len(unknown), version, ", ".join(unknown),
            )
        if items:
            log.info("plan: %d stale core file(s) to prune, %s estimated",
                     len(items), human_bytes(plan.est_bytes()))
        elif not unknown:
            log.info("plan: nothing to prune; no stale core file under "
                     "wp-admin/, wp-includes/ or wp-content/languages/")
        else:
            log.info("plan: nothing to prune; %d unknown file(s) remain "
                     "investigate-only", len(unknown))
        return plan

    def apply(self, ctx: "Ctx", stack: tuple, plan: Plan) -> Plan:
        source = stack[0]
        bridge = stack[2]
        prune_items = [item for item in plan.items if item.requires_apply]
        if not prune_items:
            return plan  # nothing planned — no walk, no fetch, no delete
        # The pre-apply tree IS the verify's baseline: it is what makes
        # "a core file that went missing" a fact rather than a guess.
        deadline = Deadline.from_ctx(ctx)
        before = {entry.path
                  for entry in bounded_walk(source, deadline,
                                             "prune-core verify walk")
                  if not entry.is_dir}
        version, site_locale = _prune_basis(source, bridge, deadline=deadline)
        wp_org = ctx.settings.wp_org
        locale = resolve_core_locale(source, site_locale, wp_org.default_locale)
        session, timeout_s = _wporg_transport(ctx, stack)
        # The comparison map is the verify's other input, so it is
        # re-derived through the AUDIT's own seam BEFORE the first
        # delete: a verify whose basis cannot be had refuses with
        # NOTHING deleted rather than claiming an unproven prune.
        with owned_session(session, stack[2] is None):
            checksums, effective_locale = _fetch_comparison_checksums(
                version, session, timeout_s, locale, deadline=deadline,
                config=wp_org,
            )
        if checksums is None:
            raise WptError(
                f"cannot verify the prune: wp.org checksums for WP "
                f"{version} are unavailable — verification is mandatory, "
                f"never skipped"
            )
        targets = [item.target for item in prune_items]
        for item in prune_items:
            if deadline is not None:
                deadline.check("prune-core delete")
            target = item.target
            if target not in before:
                # Already gone: the goal state holds and the plan is
                # idempotent — nothing to delete (an ftp DELE on a
                # vanished file would only produce a 550 warning).
                continue
            if target.startswith(_CORE_TREES):
                # The audited core-tree unlock, announced exactly like
                # the write guard announces its own: a deletion inside a
                # protected core subtree is never silent.
                log.warning(
                    "guarded core prune: deleting protected core file %s "
                    "(proven stale against the official WP %s %s release "
                    "maps: shipped by an earlier release, or by a "
                    "known_stale signature)", target, version,
                    effective_locale,
                )
            try:
                source.delete(target)
            except (WptError, OSError) as exc:
                log.warning(
                    "apply: could not remove %s (%s: %s); continuing",
                    target, type(exc).__name__, exc,
                )
        # MANDATORY verification (the SPEC's verify-after-mutate rule):
        # the tree is re-walked and the surviving set re-checked against
        # the current map — a planned file that survived is an item NOT
        # done, and a map path that was present before and is gone after
        # without being planned is collateral damage.
        after = {entry.path
                 for entry in bounded_walk(source, deadline,
                                            "prune-core verification walk")
                 if not entry.is_dir}
        for item in prune_items:
            if item.target not in after:
                item.done = True
            else:
                log.warning("apply: %s survived the prune — not removed",
                            item.target)
        collateral = sorted(
            (before & set(checksums)) - after - set(targets)
        )
        failed = [item for item in prune_items if not item.done]
        if not failed and not collateral:
            log.info("apply: %d stale core file(s) removed and verified "
                     "against the official WP %s %s checksums",
                     len(prune_items), version, effective_locale)
            return plan
        parts = []
        if failed:
            parts.append(
                f"prune incomplete: {len(prune_items) - len(failed)} of "
                f"{len(prune_items)} stale file(s) removed; not removed: "
                f"{', '.join(sorted(item.target for item in failed))}"
            )
        if collateral:
            log.error(
                "apply: %d official core file(s) disappeared during the "
                "prune without being planned: %s", len(collateral),
                ", ".join(collateral),
            )
            parts.append(
                f"{len(collateral)} unplanned official core file(s) went "
                f"missing: {', '.join(collateral)}"
            )
        if bridge is not None:
            revert = ("the pre-action snapshot holds the originals "
                      "— `wpt restore` reverts")
        else:
            revert = ("the original zip is untouched (the rehearsal "
                      "never materialized)")
        raise WptError("; ".join(parts) + f"; {revert}")


# The registry stores the decorated OBJECT and calls .plan/.apply on it
# (the deactivate/clean_files precedent: a bare class would be invoked
# with plan(ctx, stack) unbound and crash in run_action).
register_action("prune-core", applies=("ftp", "local"))(PruneCoreAction())
