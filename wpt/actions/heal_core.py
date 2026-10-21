"""heal-core action: restore checksum-PROVEN tampered/missing WordPress
core files from the official wp.org release zip of the site's exact
version.

Live motivation (an observed migration): the
audit's first live ``core.integrity`` run PROVED wp-includes/version.php
plus three twentytwentyfive files tampered against wp.org's official
checksums (md5 evidence, not pattern hints) — and the operator asked for
the fix path.  This action is that fix: the SAME classification the
audit produced, driven to restoration.

Scope (binding — RESTORE only):

* Heal items are the ``tampered`` and ``missing`` classifications of
  wpt.audit.integrity — the ONE owner of the semantics; this module
  consumes the public classification primitives
  (``affected_files_bridge`` / ``affected_files_local``, whose returns
  already carry the tree-only ``added`` tail) and never re-derives them.
  A tampered file gets its official bytes back; a missing one is
  re-created from the release.
* "added" files — a ``.php`` under wp-admin/, under wp-includes/ or at
  the webroot top level that the checksums map does not list — are
  INVESTIGATION FINDINGS, never heal targets, never deleted:
  auto-deleting custom top-level php is exactly the destructive guess
  this toolkit refuses to make (a hoster shim, a parked-page stub, an
  operator hack all look like "added").  The plan NAMES them in ONE
  investigate-only info line ("investigate-only, not healed: ...") and
  touches nothing; ``Plan`` has no free-text note field (report.py
  ships items + backup_tables only), so that log line is the note.
* ``wp-config.php`` / ``.htaccess`` are NEVER healable: wp.org does not
  ship them (they are user configuration), the checksums map never
  lists them, and the write guard keeps them config-only.

Version- AND locale-pinned basis (never a guess): the heal restores
from the official release zip of the site's EXACT version at the
BUILD locale the files came from — ``WpOrgApi.fetch_core_release_zip``
(``downloads.wordpress.org/release/wordpress-<V>.zip`` for en_US,
``https://<dash-subdomain>.wordpress.org/wordpress-<V>-<locale>.zip``
for a localized build, PK-magic + wordpress/-prefix validated before
caching), which is the SAME distribution the ``core/checksums/1.0``
map at that locale describes (live-verified for en_US AND fr_CA: file
md5s taken from the zip match the map exactly), so a restored file
satisfies the checksums EXACTLY.  The version comes from the audit's
own seams — ``info.wp_version`` over the bridge (ftp),
wp-includes/version.php through the source (local) — and the locale
from the integrity check's own ``resolve_core_locale`` (the SAME
resolver the audit check uses, so plan and audit can never disagree;
the localized-migration lesson [L17]: an en_US heal of a localized build's
wp-includes/version.php loses ``$wp_local_package`` and the site then
fails ``wp core verify-checksums --locale=<locale>``).  An unknown
version is a REFUSAL: both the checksums and the zip are version-
pinned, and guessing either would heal the wrong bytes over a
compromised site.

``plan`` (read-only inventory):

1. ONE walk of the source tree — BEFORE the first bridge call (the
   gather's discipline: the bridge lazy-deploys on its first call, and
   the tree must reflect the site, not wpt's own bridge-<8hex>.php —
   a later walk would flag our own file as an "added" note on every
   ftp run).  Walked non-dir entries become the ``files`` map the
   classification primitives take.
2. The version + locale (the refusal above fires before any wp.org
   traffic; the locale via ``resolve_core_locale`` over the same
   version.php / info payload).
3. The checksums map via ``_fetch_comparison_checksums`` — the
   integrity check's own fallback-aware seam (the locale's map, the
   ONE-warning en_US fallback when it is unavailable), riding the
   WpOrgApi transport (identifying UA, 1h
   .wpt-cache with stale-reuse-on-failure).  ftp: the STACK session
   (the audit's wp.org transport — DNS-override-aware when
   --override-ip is set; only wp.org hosts are ever requested); local:
   a fresh plain session — the SITE is offline, wp.org is not.  None
   → WptError: the check degrades to silence, an action must refuse —
   no comparison basis, no heal.
4. Classification through the primitives.  ftp:
   ``affected_files_bridge`` — its None (after its own ONE degrade
   warning naming the reason) is a WptError naming it; a heal never
   runs on an unclassifiable tree.  local: ``affected_files_local``
   with ``Deadline.from_ctx(ctx)`` — a breaker/deadline stop returns
   the VERIFIED subset, which is safe to heal (partial never INVENTS a
   tampered/missing file, it only misses some); the abort warning
   carries the caveat and a re-run picks up the rest.  BOTH primitives
   are handed ``ctx.settings.webroot_junk`` ([L19]): the missing scope
   must subtract the map paths the tool's own junk policy DELETES (the
   shipped profile's ``wp-config-sample.php``) in both modes and in both
   phases, or clean-files deletes it, the audit demands it back, the
   heal restores it — forever.  Both modes then run the integrity
   check's default-theme version-skew pass (``resolve_theme_skew``
   [L12]): a tampered-flagged wp-content/ themes/<slug>/ path whose
   bytes match the OFFICIAL theme release of the version the site's own
   style.css declares is a pristine auto-update past the core-bundled
   copy — dropped from the healable set, because restoring the bundled
   bytes would DOWNGRADE the theme (and it is not compromise evidence;
   the audit's finding drops it too, so plan and audit can never
   disagree) — and its translation-catalog twin
   (``resolve_translation_pack_skew`` [L19]), for the same reason about
   wp.org language packs.
5. Every (kind, path, size) with kind tampered/missing becomes ONE
   PlanItem: category ``core.integrity`` (the audit's own category —
   the operator reads the heal as the integrity finding's fix),
   ``target`` = the webroot-relative path, ``detail`` = "<kind> —
   restore the official WP <version> <locale> file", ``bytes_est`` =
   the walked size (0 for missing).  Items sort by (kind, path).  The
   locale in the detail is the EFFECTIVE COMPARISON LOCALE — the same
   basis clause the audit finding's detail carries, for the same
   reason: a plan that says "the official WP 7.1 file" without naming
   the build is what made an observed localized heal and its re-audit look like
   two contradictory accounts of one core (the en_US and fr_CA maps
   disagree on wp-includes/version.php).
   ``backup_tables = []`` deliberately (files only — the harden /
   optimize-media precedent; the registry derives the pre-action
   snapshot's file scope from the item targets).
6. Zero healable items → an EMPTY plan (rc 0 in both phases): ONE info
   names the case — "nothing to heal; the core matches the official
   <locale> <version> checksums" (the basis that judged it), or, when
   only added files exist, the investigate-only line above.

``apply`` (the mutation; the plan is executed AS-IS — no
re-classification: the state can change between plan and apply, and
that is fine and honest, like every other action):

* The version + locale are RE-DERIVED exactly as plan derived them
  (info / version.php + resolve_core_locale) — chosen over stashing
  them on the plan because a Plan is
  a printed, rebuildable artifact (render_report/to_json reconstruct
  it from items + backup_tables; a stashed private attribute would be
  invisible state only the in-memory twin ever sees); the
  re-derivation is one cheap bridge call / one source read while the
  stack is still live, and the mandatory verification below
  arbitrates any drift.  The COMPARISON basis is re-derived through the
  audit's own fallback-aware seam (``_fetch_comparison_checksums``, the
  1h cache making it free), so the restore basis is always a basis the
  audit itself would compare against — a heal that picked its own
  locale could write bytes the next audit run flags forever.
* The release zip is re-FETCHED via ``fetch_core_release_zip`` at the
  comparison's build (the 1h cache makes the plan→apply second fetch
  free).  An UNAVAILABLE build (a 404) falls back to the en_US release
  with ONE warning.  Both unavailable → WptError: refuse to heal from
  no/wrong basis; a malformed version or locale string raises the
  fetch's own loud WptError.
* [L19] The en_US fallback can only supply what the two builds ship
  IDENTICALLY.  The restore-basis map is therefore fetched BEFORE the
  writes and used for one more decision: a planned path whose official
  digests DIFFER between the comparison's build and the restore basis
  (live-verified across four versions x two locales: the only
  same-PATH difference between an en_US and a locale map is
  ``wp-includes/version.php`` — hence derived from the maps at runtime,
  never from a filename list) is reported
  unrestorable — ONE warning naming it — and never written.  Writing
  en_US bytes there would leave a file the audit flags as tampered on
  every subsequent run: a heal/audit loop with no fixed point, traded
  for a heal that reports success.  Paths absent from either map (a
  localized build's extra ``wp-content/languages/`` entries) are not
  unrestorable — en_US has no bytes for them at all, so there is no
  basis to disagree with.
* Per item, in plan order: ``wordpress/<target>`` is read from the
  in-memory zip; a name the zip does not ship (wp.org checksums/zip
  map drift) is ONE warning + a skip (done stays False, apply
  continues).  The write is ``source.write_bytes(target, data,
  allow_core=True)`` — types.Source's audited surgical unlock (one
  warning log line per write), unlocking EXACTLY the protected core
  surface: index.php and the wp-admin//wp-includes/ subtrees.  The
  map's other paths (a root-level file like wp-trackback.php, the one
  wp-content entry wp-content/plugins/hello.php) sit outside PROTECTED
  and need no unlock — the guard's own design; wp-config.php and
  .htaccess stay refused (config-only, never core-healable).  A write
  failure — a refused path on a hand-built plan, an ftp STOR error —
  is ONE warning + continue: items are independent.
* MANDATORY verification (the SPEC's verify-after-mutate rule; never
  skipped, never assumed): after all writes, ONE bulk digest pass over
  the healed paths — ftp: ``bridge.call("core_md5", paths=...)`` (the
  heal set is bounded by the checksums map, under the bridge's own
  5000-path per-call cap); local: ``source.read_many`` (the overlay
  serves the staged bytes) + md5 — compared against the checksums OF
  THE RESTORE BASIS (the distribution the bytes came from), the map
  already fetched for the unrestorable decision.  None → WptError
  "cannot verify the heal: checksums unavailable": a heal is never
  REPORTED without its proof, and the pre-action snapshot is the
  operator's revert.  A matching digest flips the item ``done``; a
  mismatching or missing answer keeps it not-done with ONE warning
  per path (heal sets are small — every failed path is named).
* Any item still not done at the end (zip-missing, write failure,
  verify mismatch) → ONE terminal WptError: "heal incomplete: N of M
  files restored; not restored: <paths>; the pre-action snapshot holds
  the originals — `wpt restore` reverts" (local mode: "...the
  original zip is untouched").  The registry turns it into rc 1 with
  the pre-action snapshot INTACT — restoring it reverts the whole
  heal: the tampered originals come back, and a file healed into a
  snapshot-ABSENT target is deleted (absent entries restore to
  absence).  All done → the plan returns (rc 0; the registry purges
  caches and prints).

Local mode: registered ``applies=("ftp", "local")``; the registry's
local ``--apply`` is the REHEARSAL (MutableZipSource overlay,
materialized twin, the original zip is the rollback).  This module is
mode-agnostic given the stack: a ``None`` bridge IS the local shape
every branch keys on (version.php for the version, read_many for the
verify).

Logging: ``get_logger("actions.heal_core")`` — one info per phase plus
one warning per failure; paths, counts and versions only, never file
contents.
"""

from __future__ import annotations

import hashlib
import io
import zipfile
from typing import TYPE_CHECKING

import requests

from ..audit.data import _opt_str, _read_wp_version
from ..audit.integrity import (
    _api_deadline,
    _fetch_checksums,
    _fetch_comparison_checksums,
    affected_files_bridge,
    affected_files_local,
    resolve_core_locale,
    resolve_theme_skew,
    resolve_translation_pack_skew,
)
from ..audit.updates import WpOrgApi, owned_session
from ..deadline import Deadline, bounded_walk, transport_kwargs
from ..log import get_logger
from ..report import Plan, human_bytes
from ..types import PlanItem, SourceError, WptError
from .registry import register_action

if TYPE_CHECKING:
    from ..cli import Ctx
    from ..types import Source
    from ..wpbridge.client import Bridge

__all__ = ["HealCoreAction"]

log = get_logger("actions.heal_core")

#: The healable classification kinds — everything the integrity
#: primitives report for a core file EXCEPT "added" (the restore-only
#: scope; see the module docstring).  Structural, NOT a tunable.
_HEAL_KINDS = ("missing", "tampered")


def _wp_basis(source: "Source", bridge: "Bridge | None",
              deadline: "Deadline | None" = None) -> tuple[str, str | None]:
    """(wp_version, site_locale) — the heal's re-derivable basis.

    The version is the heal's ONLY pin (both the checksums map and the
    release zip are version-pinned); refused, never guessed.  The site
    locale (the ``resolve_core_locale`` fallback tier's input) rides
    the SAME single info call remotely — WP's own get_locale(); local
    mode has no dump in the heal stack, so it stays None (the tier is
    unreachable there anyway: an unreadable version.php already
    refused above).

    ftp (``bridge`` not None): ``info``'s ``wp_version`` + ``locale``
    through the audit's wire-tolerance helper ``_opt_str`` (None for
    missing/empty/non-string).  local (``bridge`` None):
    wp-includes/version.php through the source — the gather's own
    seam (a missing/unparseable file stays None).
    """
    if bridge is not None:
        info = bridge.call("info", **transport_kwargs(deadline))
        version = _opt_str(info.get("wp_version"))
        site_locale = _opt_str(info.get("locale"))
    else:
        version = _read_wp_version(source)
        site_locale = None
    if version is None:
        raise WptError(
            "unknown WordPress version — cannot heal (the checksums/"
            "release basis is the version); refusing to guess"
        )
    return version, site_locale


def _wporg_transport(ctx: "Ctx", stack: tuple) -> tuple[requests.Session, int]:
    """(session, timeout_s) for the wp.org fetches (checksums + zip).

    ftp: the stack's session — the audit's own wp.org transport
    (DNS-override-aware when --override-ip is set; only
    api.wordpress.org / downloads.wordpress.org are ever requested).
    local: a fresh plain session — the SITE is offline, the wp.org
    reference data is not.  The timeout is the profile's
    ``http.timeout_s`` in both modes (the audit's own pairing).
    """
    if stack[2] is None:
        return requests.Session(), ctx.settings.http.timeout_s
    return stack[1], ctx.settings.http.timeout_s


class HealCoreAction:
    """The plan/apply pair; ``stack`` is the registry-built source trio
    (ftp: ``(source, session, bridge)``; local: ``(source, None,
    None)`` — a None bridge IS the local shape every branch keys on)."""

    def plan(self, ctx: "Ctx", stack: tuple) -> Plan:
        source = stack[0]
        bridge = stack[2]
        # The walk runs BEFORE the first bridge call (the gather's
        # discipline): the bridge lazy-deploys on its first call, and a
        # walk after it would flag wpt's own bridge-<8hex>.php as an
        # "added" file on every ftp run.
        deadline = Deadline.from_ctx(ctx)
        files = {entry.path: entry
                 for entry in bounded_walk(
                     source, deadline, "heal-core walk")
                 if not entry.is_dir}
        version, site_locale = _wp_basis(source, bridge, deadline=deadline)
        # [L17] the comparison is keyed to the BUILD the files came
        # from — the SAME resolver the audit check uses, so plan and
        # audit can never disagree.
        wp_org = ctx.settings.wp_org
        locale = resolve_core_locale(
            source, site_locale, wp_org.default_locale)
        session, timeout_s = _wporg_transport(ctx, stack)
        with owned_session(session, stack[2] is None):
            checksums, effective_locale = _fetch_comparison_checksums(
                version, session, timeout_s, locale, deadline,
                config=wp_org,
            )
            if checksums is None:
                raise WptError(
                    f"cannot heal: wp.org checksums for WP {version} are "
                    "unavailable — no comparison basis; refusing to heal"
                )
            if bridge is not None:
                affected = affected_files_bridge(
                    bridge, files, checksums,
                    junk_patterns=ctx.settings.webroot_junk,
                    deadline=deadline.at if deadline is not None else None,
                )
                if affected is None:
                    # The primitive already logged its ONE degrade warning
                    # naming the reason; the heal refuses on top of it.
                    raise WptError(
                        "cannot heal: core_md5 unavailable (the preceding "
                        "degrade warning names the reason) — no "
                        "classification, no heal"
                    )
            else:
                affected = affected_files_local(
                    source, files, checksums,
                    deadline=deadline,
                    junk_patterns=ctx.settings.webroot_junk,
                    max_file_bytes=ctx.settings.files.max_file_bytes,
                )
            # [L12] the default-theme version-skew pass — the SAME one the
            # audit check runs: a pristine official theme release newer
            # than the core-bundled copy is NOT tampering, and restoring
            # the bundled bytes over it would DOWNGRADE the theme.  Every
            # failure shape keeps the tampered classification (conservative:
            # the heal restores the bundled official bytes, the snapshot
            # reverts).
            affected = resolve_theme_skew(
                affected, source, session, timeout_s, deadline,
                max_file_bytes=ctx.settings.files.max_file_bytes)
        # [L19] translation catalogs — the SAME pass the audit check runs:
        # a pristine wp.org language pack is not tampering, and restoring
        # the BUNDLED catalogs would DOWNGRADE the site's translations.
        affected = resolve_translation_pack_skew(affected)
        healable = sorted(
            (kind, path, size) for kind, path, size in affected
            if kind in _HEAL_KINDS
        )
        added = sorted(path for kind, path, _size in affected
                       if kind == "added")
        items = [
            PlanItem(
                category="core.integrity",
                target=path,
                detail=(f"{kind} — restore the official WP {version} "
                        f"{effective_locale} file"),
                bytes_est=size,
            )
            for kind, path, size in healable
        ]
        # Files only: backup_tables=[] deliberately (the harden /
        # optimize-media precedent) — the registry derives the
        # pre-action snapshot's file scope from the item targets.
        plan = Plan(items=items, backup_tables=[])
        if items:
            if added:
                log.info(
                    "plan: %d added file(s) are out of heal-core's "
                    "scope (restore-only; added files are "
                    "investigation findings, never auto-deleted) — "
                    "investigate-only, not healed: %s",
                    len(added), ", ".join(added),
                )
            log.info("plan: %d core file(s) to heal, %s estimated",
                     len(items), human_bytes(plan.est_bytes()))
        elif added:
            log.info(
                "plan: nothing to heal; %d added file(s) remain — "
                "investigate-only, not healed: %s",
                len(added), ", ".join(added),
            )
        else:
            log.info("plan: nothing to heal; the core matches the "
                     "official %s %s checksums",
                     effective_locale, version)
        return plan

    def apply(self, ctx: "Ctx", stack: tuple, plan: Plan) -> Plan:
        source = stack[0]
        bridge = stack[2]
        heal_items = [item for item in plan.items if item.requires_apply]
        if not heal_items:
            return plan  # nothing planned — no fetch, no bridge roundtrip
        # The version + locale re-derived EXACTLY as plan derived them:
        # a Plan is a printed artifact (items + backup_tables only) and
        # cannot carry either; one cheap info/read while the stack is
        # still live, and the mandatory verification below arbitrates
        # any drift.
        deadline = Deadline.from_ctx(ctx)
        version, site_locale = _wp_basis(source, bridge, deadline=deadline)
        wp_org = ctx.settings.wp_org
        locale = resolve_core_locale(
            source, site_locale, wp_org.default_locale)
        session, timeout_s = _wporg_transport(ctx, stack)
        with owned_session(session, stack[2] is None):
            # The comparison basis is re-derived through the AUDIT's own
            # fallback-aware seam (the same one plan used): a restore basis
            # that could disagree with the audit's comparison is exactly how
            # a heal writes bytes the next audit run flags forever, so the
            # apply never picks its own locale.
            comparison, comparison_locale = _fetch_comparison_checksums(
                version, session, timeout_s, locale, deadline,
                config=wp_org,
            )
            if comparison is None:
                raise WptError(
                    f"cannot heal: wp.org checksums for WP {version} are "
                    "unavailable — no comparison basis; refusing to heal"
                )
            # [L17] restore from the COMPARISON's build (the fr_CA build's
            # wp-includes/version.php carries $wp_local_package — the file
            # the en_US zip cannot supply).  A 404/unavailable build falls
            # back to the configured default release with ONE warning; the
            # restore basis then IS that build, so verification below uses
            # its map.
            restore_locale = comparison_locale
            zip_bytes = WpOrgApi(
                session, timeout_s, deadline=_api_deadline(deadline),
                config=wp_org,
            ).fetch_core_release_zip(version, restore_locale)
            if zip_bytes is None and restore_locale != wp_org.default_locale:
                log.warning(
                    "apply: the official WordPress %s %s release zip is "
                    "unavailable — falling back to the %s release for "
                    "the files both builds ship identically",
                    version, restore_locale, wp_org.default_locale,
                )
                restore_locale = wp_org.default_locale
                zip_bytes = WpOrgApi(
                    session, timeout_s, deadline=_api_deadline(deadline),
                    config=wp_org,
                ).fetch_core_release_zip(version, wp_org.default_locale)
            if zip_bytes is None:
                raise WptError(
                    f"cannot heal: the official WordPress {version} "
                    f"{restore_locale} release zip is unavailable — "
                    "refusing to restore from any other source"
                )
            # The restore-basis map is BOTH the verification map and the
            # decision map below; fetched ONCE (the configured cache: the
            # plan's fetch of the same map, or the first call here, serves
            # the rest).
            basis = _fetch_checksums(
                version, session, timeout_s, restore_locale, deadline,
                config=wp_org)
            if basis is None:
                raise WptError(
                    "cannot verify the heal: checksums unavailable — "
                    "verification is mandatory, never skipped"
                )
        # [L19] The en_US fallback can only supply files the two builds
        # ship IDENTICALLY.  A path whose official digests DIFFER between
        # the comparison's build and the restore basis (live-verified
        # across four versions x two locales: the only same-PATH
        # difference between an en_US and a locale map is
        # wp-includes/version.php) would be written with bytes this audit
        # will flag as tampered on EVERY subsequent run — a heal/audit
        # loop with no fixed point.  Such paths are reported unrestorable
        # instead: the operator gets the truth (wp.org has no
        # <locale> build for this version) rather than a file the tool
        # keeps fighting.  Same rule in both modes; the decision is
        # derived from the two maps at runtime, never from a filename
        # list and never guessed.
        unrestorable: set[str] = set()
        if restore_locale != comparison_locale:
            unrestorable = {
                target for target in (item.target for item in heal_items)
                if comparison.get(target) and basis.get(target)
                and comparison[target] != basis[target]
            }
        by_target = {item.target: item for item in heal_items}
        healed: list[str] = []
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            names = set(zf.namelist())
            for item in heal_items:
                if deadline is not None:
                    deadline.check("heal-core write")
                target = item.target
                if target in unrestorable:
                    log.warning(
                        "apply: %s is not shipped identically by the "
                        "official WP %s %s and en_US builds (and the %s "
                        "build's release zip is unavailable) — not "
                        "restored, unrestorable from here",
                        target, version, comparison_locale,
                        comparison_locale,
                    )
                    continue
                name = ctx.settings.wp_org.release_zip_prefix + target
                if name not in names:
                    log.warning(
                        "apply: %s is absent from the official WP %s "
                        "%s release zip (wp.org checksums/zip map "
                        "drift) — not restored",
                        target, version, restore_locale,
                    )
                    continue
                try:
                    data = zf.read(name)
                except (OSError, ValueError, EOFError, RuntimeError,
                        zipfile.BadZipFile) as exc:
                    log.warning(
                        "apply: reading %s from the release zip failed "
                        "(%s) — not restored", target, exc,
                    )
                    continue
                try:
                    # The audited surgical unlock: exactly index.php +
                    # the wp-admin//wp-includes/ subtrees, never the
                    # config files.
                    source.write_bytes(target, data, allow_core=True)
                except (SourceError, OSError) as exc:
                    log.warning(
                        "apply: restoring %s failed (%s) — not restored",
                        target, exc,
                    )
                    continue
                healed.append(target)
        if healed:
            if deadline is not None:
                deadline.check("heal-core verify")
            # MANDATORY verification (the SPEC's verify-after-mutate
            # rule): the heal is proven, never assumed — against the
            # map of the distribution the bytes CAME from (the restore
            # basis), the SAME map the unrestorable decision used and
            # already fetched above.
            if bridge is not None:
                # ONE bulk server-side digest call; the heal set is
                # bounded by the checksums map, under the bridge's own
                # 5000-path per-call cap.
                try:
                    payload = bridge.call(
                        "core_md5", paths=healed,
                        **transport_kwargs(deadline))
                except Exception as exc:
                    raise WptError(
                        f"cannot verify the heal: core_md5 unavailable "
                        f"({exc})"
                    ) from exc
                if not isinstance(payload, dict):
                    raise WptError(
                        "cannot verify the heal: core_md5 unavailable "
                        "(malformed core_md5 payload)"
                    )
                digests = payload.get("files")
                missing = payload.get("missing")
                unreadable = payload.get("unreadable")
                if (not isinstance(digests, dict)
                        or not isinstance(missing, list)
                        or not isinstance(unreadable, list)):
                    raise WptError(
                        "cannot verify the heal: core_md5 unavailable "
                        "(malformed core_md5 payload)"
                    )
                digest_of = {path: digests.get(path) for path in healed}
            else:
                ok, _failed = source.read_many(healed)
                digest_of = {
                    path: hashlib.md5(ok[path]).hexdigest()
                    if path in ok else None
                    for path in healed
                }
            for path in healed:
                expected = basis.get(path)
                if expected is not None and digest_of[path] == expected:
                    by_target[path].done = True
                else:
                    log.warning(
                        "apply: %s did not verify against the official "
                        "WP %s %s checksums after the heal — not marked "
                        "done", path, version, restore_locale,
                    )
        failed = [item for item in heal_items if not item.done]
        if failed:
            failed_paths = ", ".join(
                sorted(item.target for item in failed)
            )
            if bridge is not None:
                revert = ("the pre-action snapshot holds the originals "
                          "— `wpt restore` reverts")
            else:
                revert = ("the original zip is untouched (the "
                          "rehearsal never materialized)")
            raise WptError(
                f"heal incomplete: {len(heal_items) - len(failed)} of "
                f"{len(heal_items)} files restored; not restored: "
                f"{failed_paths}; {revert}"
            )
        log.info("apply: %d core file(s) restored from the official "
                 "WP %s %s release and verified",
                 len(healed), version, restore_locale)
        return plan


# The registry stores the decorated OBJECT and calls .plan/.apply on it
# (the deactivate/clean_files precedent: a bare class would be invoked
# with plan(ctx, stack) unbound and crash in run_action).
register_action("heal-core", applies=("ftp", "local"))(HealCoreAction())
