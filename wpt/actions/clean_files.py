"""clean-files action (W7d): delete junk/backup/stale files from the webroot.

Two-phase action over the shared registry flow (``wpt.actions.registry`` —
the registry owns dry-run, confirmation, the fail-closed pre-action backup
and the local-mode write refusal; this module is pure domain logic).
``plan`` walks the source ONCE and enumerates four removal groups (v1
scope, binding — inactive plugins are a later, separate action):

* ``webroot.junk``           — junk FILES whose basename fnmatches a
  ``settings.webroot_junk`` pattern; one item per file, detail = the
  matched pattern.  Official core files under wp-admin//wp-includes/
  (the wp.org checksum map — e.g. wp-includes/ID3/license.txt) are
  EXEMPT by the same shared rule the audit check applies
  (``junk_matches_for_plan``), so the plan never deletes a file
  heal-core would restore.  ``.htaccess.bk`` is NOT in
  ``Source.PROTECTED``, so config backups in the webroot really are
  deletable.
* ``webroot.junk_recurring`` — ``.po`` catalogs under
  ``wp-content/languages`` (recursive), one item per file; runtime-safe
  but recurring (wp.org language packs re-ship them on every translation
  auto-update, which is on by default).
* ``webroot.stale``          — stale content DIRECTORIES under
  ``wp-content/`` whose basename matches a ``settings.stale_content_dirs``
  pattern; one item per directory, bytes = subtree sum, detail = file
  count.  A stale directory that IS a plugin/theme unit faces the
  active-unit guard like every other unit (one of the shipped patterns
  is a real plugin slug), and a stale directory NESTED inside a unit
  still plans: it is not a unit and its own subtree is what goes.
* ``webroot.migration``      — migration leftovers: an entry (file OR
  directory) matches a ``settings.migration_leftovers`` pattern when ANY
  path component fnmatches it; per-pattern topmost-match subsumption (a
  matched plugin directory subsumes its descendants), one item per
  topmost target.  THE UNIT RULE (live production defect: the ``ai1wm*``
  pattern matched ``lib/vendor/servmask/command/ai1wm-wp-cli.php`` and
  ``ai1wmve.php`` — two vendor files INSIDE the still-active
  ``all-in-one-wp-migration-unlimited-extension`` plugin; deleting them
  left the plugin's main file requiring code that was gone, so WordPress
  fataled the site on every request): a match strictly inside
  ``wp-content/plugins/<unit>/`` or ``wp-content/themes/<unit>/`` selects
  the UNIT directory — the top-level child of the plugins/themes dir —
  and NEVER the inner file.  Deleting a whole unit is not "safe by
  accident" either (WordPress merely auto-skips a missing main file),
  so the unit then faces the active-unit guard below.
* ``webroot.active_unit`` — the ACTIVE-unit guard, a property of the
  DELETION and not of the group that selected it: any planned target
  that IS a unit (a direct child directory of ``wp-content/plugins`` or
  ``wp-content/themes``, or a single-file ``.php`` plugin) and that
  WordPress is currently using becomes an ADVICE item
  (``requires_apply=False``) — ``active plugin — deactivate first
  (wpt deactivate-plugin <slug>) or remove it in wp-admin`` /
  ``active theme — activate a different theme in wp-admin first, or
  remove it in wp-admin``.  It fires for EVERY group, not only for
  migration matches: a unit directory is only ever deletable in whole,
  so any pattern that names one (the shipped ``stale_content_dirs``
  entry ``wpo`` is a real plugin slug, and a profile may add any
  pattern) removes a directory WordPress is loading from.  The run
  stays rc 0 with advice items (they are "needs your call"): apply
  skips them, the registry's snapshot scope ignores them, and the local
  rehearsal materializes with the unit intact.  The active facts come
  from each mode's own owner — the bridge's ``info`` plugin catalog
  plus its ``template``/``stylesheet`` remotely
  (deactivate-plugin's established pattern,
  ``wpt.audit.data._plugin_catalog`` being the wire->fact owner), the
  dump's ``active_plugins`` option plus ``template``/``stylesheet``
  locally (``wpt.localmode.analyzer``, the same owner
  ``gather_local`` reads) — from ONE payload, fetched LAZILY (only when
  a unit candidate exists at all), and FAIL-CLOSED in both shapes the
  question can be in: a stack with no bridge (ftp) or no ``--sql``
  (local) cannot know the active set at all, so the plan raises
  ``SourceError`` (the registry answers rc 1); a payload that answered
  but could not MEASURE the set — a dump whose options identity is
  absent or contested (AIOSEO 4.x really creates ``aioseo_options``
  beside ``wp_options``), or whose ``active_plugins`` value is
  unreadable — turns the affected unit into advice with ONE line naming
  the cause and the candidate tables.  "Not in the active set" is a
  DELETION verdict, so it is only ever drawn from a set somebody
  measured: an empty measured set is a site running nothing, and that
  is a real answer this module still acts on.

Matching semantics and subtree aggregation are owned by
``wpt.audit.webroot``; this module imports its private helpers and
constants (``_dir_subtree_sizes``, ``_dir_subtree_file_counts``,
``_topmost``, ``_PLUGINS_DIR``, ``_PLUGIN_FILE_SUFFIX``) so the audit and
the action can never disagree on WHAT matches.  The unit rule
and the active-unit guard are deliberately ACTION-only safety on top of
that shared matching: the audit's ``webroot.migration`` finding stays
informational (it names matched paths, deleting nothing), while this
module — the only side that deletes — additionally collapses matches to
units and refuses the ones WordPress is using.  The slug rule is
``wpt.audit.webroot``'s — the FIRST component of each active plugin
FILE path (a dirless single-file plugin keeps its whole name), filtered
through its ``_plugin_relative_path`` so a value that cannot name a unit
names none: ONE owner with the audit checks, which read the same
predicate on the same facts.

Plan safety rules:

* Guarded targets — anything ``source._check_deletable`` refuses
  (``Source.PROTECTED``: wp-config.php, root ``.htaccess``/``index.php``,
  wp-admin, wp-includes; plus root wp-content) — are EXCLUDED from the
  plan and named in ONE warning; the apply phase never attempts them.
* Subsumption — a planned directory removal already covers everything
  beneath it: file items under a planned directory, and directory items
  nested inside one, are dropped.  An advice item is never a subsumption
  parent (its subtree is NOT being removed — e.g. a junk ``*.sql`` file
  inside a guarded active unit still plans normally, junk behavior
  being byte-identical).  An exact duplicate target (a file can match
  two groups, e.g. ``search-and-replace.sql`` is junk ``*.sql`` and a
  migration component) keeps only its first item in
  ``(category, target)`` order.  The guard needs no such tie-break: it
  REPLACES the deletion item in place (one item per target, carrying
  the advice category), so a unit can never carry both.
* Items are sorted by ``(category, target)`` — deterministic plans and a
  deterministic apply order.

``apply`` executes items in plan order: files via ``source.delete``,
directories via ``source.rmdir_recursive`` (dir-ness re-derived from one
fresh walk — ``PlanItem`` carries no is_dir field, and the plan needs no
extra state).  Advice items (``requires_apply=False`` — the active-unit
guard) are SKIPPED, staying ``done=False`` by design.  Items are
independent: a failed removal logs one warning, leaves the item
``done=False`` and the batch continues.  Local mode never reaches
``apply`` through the registry with a read-only source; the rehearsal
path (MutableZipSource) stages the deletions and the guarded unit simply
survives into the materialized twin.

THE PROFILE-DRIVEN JUNK GROUPS (``wpt.actions.junk_categories`` owns
their matching and their detail lines; the live case each one answers is
named here).  What sets them apart from the four groups above is that a
bare pattern is not enough to DELETE: each carries a MEASURED gate, and
an unmeasurable gate plans nothing.

* ``webroot.junk`` / ``backup_payload_in_webroot`` (ADVICE, never a
  delete) — a full-site backup payload in the document root: archives plus
  a dead duplicate webroot at a guessable path.  An archive in
  the webroot is an EXPOSURE (downloadable at a guessable URL), and a
  site's backup is MOVED, never destroyed — ``wpt park-backups --apply``
  moves it out.  The group is a FALLBACK: it claims only a payload no
  other group claimed, so an existing (deletable) migration item is never
  downgraded to advice.  Its structural exclusions are the same ones the
  park action uses: nothing under ``wp-content/uploads/`` (a ``.sql``
  there is a Gravity Forms submission export — the attachment-data
  matches are pulled OUT of the junk delete pass above and reported
  instead) and nothing under a plugin or theme unit.
* ``webroot.geoip_legacy`` — ``GeoIP.dat`` / ``GeoIPv6.dat``, the MaxMind
  legacy databases RETIRED in 2019, deleted only while the geoip plugin
  is inactive AND the file is not inside a unit WordPress is using.  The
  active set is the same fail-closed lookup the unit guard uses.
* ``webroot.page_cache`` — ``*.wpc.log``,
  ``wpo-plugins-tables-list.json`` and the ``wp-content/cache/supercache``
  tree, gated on ``WP_CACHE`` being UNDEFINED in wp-config.php (read as
  PHP through ``wpt.audit.security``, never grepped: a commented-out or
  runtime-decided define is UNKNOWN, and an unknown constant plans
  nothing).
* ``webroot.obsolete_asset`` — the operator's own decision as DATA: the
  profile's ``obsolete_assets.known_added`` signatures (``.eot``,
  ``.map``, foreign-locale ``.po`` — the measured 56/32/12 on one live
  site) ship DISABLED, so the shipped profile plans nothing here and the
  signature's own note becomes the item's detail once enabled.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, NamedTuple

from ..audit.data import _plugin_catalog
from ..audit.webroot import (
    _PLUGINS_DIR,
    _PLUGIN_FILE_SUFFIX,
    _dir_subtree_file_counts,
    _dir_subtree_sizes,
    _plugin_relative_path,
    _topmost,
    junk_matches_for_plan,
    migration_pattern_matches,
    po_files,
    stale_content_dir_matches,
)
from ..deadline import Deadline, transport_kwargs
from ..localmode.analyzer import analyze
from ..log import get_logger
from ..report import Plan, human_bytes
from ..types import Entry, PlanItem, Source, SourceError, WptError
from .junk_categories import (
    GEOIP_CATEGORY,
    OBSOLETE_CATEGORY,
    PAGE_CACHE_CATEGORY,
    PAYLOAD_CATEGORY,
    PAYLOAD_EXPOSURE,
    geoip_file_matches,
    is_attachment_data,
    obsolete_asset_matches,
    page_cache_dir_matches,
    page_cache_file_matches,
    payload_candidates,
    payload_file_matches,
    unit_name_of,
    wp_cache_state,
)
from .registry import register_action

if TYPE_CHECKING:
    from ..cli import Ctx

__all__ = ["CleanFilesAction"]

log = get_logger("actions.clean_files")

#: Detail line for every .po item — matches check_webroot_junk_recurring's
#: explanation of why the group is separate: the files recur.
_PO_DETAIL = (
    "recurring: wp.org language packs re-ship .po catalogs on every "
    "translation auto-update; .mo/.l10n.php are the runtime formats"
)

#: Structural WordPress constant mirroring webroot.py's ``_PLUGINS_DIR``
#: (which owns the plugins one; the themes dir has no constant there).
#: The two roots whose DIRECT CHILDREN are plugin/theme UNITS for the
#: migration unit rule — fixed layout facts, NOT tunables.
_THEMES_DIR = "wp-content/themes"

#: Plan category of the active-unit guard's advice items.  It names the
#: GUARD, not the group that selected the target: the guard is a property
#: of the deletion (a unit directory is only ever deletable in whole), so
#: it fires for the migration, stale and junk groups alike and the
#: category must stay honest for all of them.
_GUARD_CATEGORY = "webroot.active_unit"

#: The EXACT detail line of every guarded item, per unit kind.  The
#: plugin line names the reversible command (``wpt deactivate-plugin
#: <slug>`` — the same token the audit's suggested step uses); a theme
#: has no such command (the active theme is the `template`/
#: `stylesheet` options), so its line is the manual one.
_GUARD_DETAILS = {
    "plugin": (
        "active plugin — deactivate first (wpt deactivate-plugin {slug}) "
        "or remove it in wp-admin"
    ),
    "theme": (
        "active theme — activate a different theme in wp-admin first, "
        "or remove it in wp-admin"
    ),
}


def _deletable(source: Source, path: str) -> bool:
    """True unless the source guard refuses to delete ``path``."""
    try:
        source._check_deletable(path)
    except SourceError:
        return False
    return True


def _unit_dir_of(path: str) -> str | None:
    """The plugin/theme UNIT directory governing ``path``, when ``path``
    sits STRICTLY inside one (a top-level child of ``wp-content/plugins/``
    or ``wp-content/themes/`` whose subtree contains the path).

    A path that IS a unit, or a direct child of the unit roots, returns
    None — it is already unit-level and needs no collapse.
    """
    for parent in (_PLUGINS_DIR, _THEMES_DIR):
        prefix = parent + "/"
        if path.startswith(prefix):
            rest = path[len(prefix):]
            if "/" in rest:
                return prefix + rest.split("/", 1)[0]
    return None


def _unit_slug(path: str, is_dir: bool) -> tuple[str, str] | None:
    """``(kind, slug)`` when ``path`` IS a plugin or theme unit.

    A plugin unit is a direct child DIRECTORY of ``wp-content/plugins``
    or a direct child ``.php`` FILE (webroot.py's ``_plugin_units``
    rule); a theme unit is a direct child directory of
    ``wp-content/themes`` — a theme is never a bare ``.php`` file, so
    the file rule stays plugin-only.  None otherwise: deeper paths are
    pre-collapsed by the unit rule and non-unit direct children (a
    stray ``readme.txt`` in the plugins dir) are not units.

    The guard consults this for EVERY planned target, so a unit
    selected by any group is recognized as one — the deletion
    candidates were never plugin-only.
    """
    prefix = _PLUGINS_DIR + "/"
    if path.startswith(prefix):
        slug = path[len(prefix):]
        if slug and "/" not in slug and (is_dir or slug.endswith(_PLUGIN_FILE_SUFFIX)):
            return "plugin", slug
    prefix = _THEMES_DIR + "/"
    if path.startswith(prefix):
        slug = path[len(prefix):]
        if slug and "/" not in slug and is_dir:
            return "theme", slug
    return None


def _plugin_slugs(files: Any) -> set[str]:
    """The FIRST component of each active plugin FILE path, filtered and
    normalized through webroot's ``_plugin_relative_path`` — the audit
    checks' ONE owner of what an active_plugins entry means, so a value
    that cannot name a unit (a webroot-relative dump row, a rogue wire key)
    can neither make a real unit look unused here nor contradict
    ``plugins.inactive`` / ``db.active_missing``.  Repeated ``/`` and ``./``
    segments are loads WordPress really performs, so they normalize to the
    same slug rather than dropping the unit from the protected set."""
    normalized = (_plugin_relative_path(file) for file in files)
    return {path.split("/")[0] for path in normalized if path is not None}


def _theme_slugs(options: tuple[Any, Any]) -> set[str] | None:
    """The active theme's two slugs — or None when the options are unusable.

    BOTH options are collected on purpose: ``template`` is the PARENT of a
    child theme and the child cannot render without it, so a parent unit is
    in use too.  A value that is not a non-empty string is UNMEASURED, never
    "no theme": the bridge renders an array-valued (corrupt) option as ``""``
    and an absent one the same way, so accepting the empty string as a real
    measurement made the active theme look unused and a migration/stale
    pattern could delete its whole directory.  Fail closed instead: the
    caller turns None into "themes unknown" and refuses every theme-unit
    deletion.
    """
    values = set()
    for value in options:
        if not isinstance(value, str) or not value:
            return None
        values.add(value)
    return values


_NO_LOCAL_DUMP_REASON = (
    "local mode has no --sql dump, so the active set was not measured"
)
_NO_BRIDGE_REASON = (
    "the stack has no bridge, so the active set was not measured"
)


class ActiveUnits(NamedTuple):
    """The active set ONE payload proved — or the reason it proved none.

    A ``set`` for each kind, or ``None`` when that kind could not be
    MEASURED, because the guard below DELETES what the set does not name:
    reading "not measured" as an empty set is what turned a contested
    options identity into a plan that removed a live plugin's whole
    directory.  ``[]`` is still a real measured answer (a site running no
    plugins), so the two are told apart HERE, once, instead of by each
    consumer inspecting a list that looks the same either way.

    ``reason`` and ``candidates`` exist so the refusal can name what could
    not be read: the cause, and (for a contested options identity) every
    table that proved the role.
    """

    plugins: set[str] | None
    themes: set[str] | None
    reason: str | None = None
    candidates: tuple[str, ...] = ()

    @property
    def measured(self) -> bool:
        return self.plugins is not None and self.themes is not None


def _active_units(ctx: "Ctx", stack: tuple,
                  deadline: "Deadline | None" = None) -> ActiveUnits:
    """The active plugin/theme units WordPress is using, from ONE payload.

    ftp: the bridge's ``info`` — the plugin catalog (deactivate-plugin's
    pattern; ``_plugin_catalog`` owns the wire->active-flag semantics)
    plus its ``template``/``stylesheet`` options, the site theme's two
    slugs.  local: the SQL dump's ``active_plugins`` option plus the
    same two options via ``wpt.localmode.analyzer.analyze`` — the owner
    ``gather_local`` reads, ONE pass over the dump.

    Fail-closed, in two different shapes because there are two different
    questions.  NOT MEASURED AT ALL — no bridge (ftp) or no ``--sql``
    (local) — is an unmeasured answer: the GeoIP gate plans nothing, while
    the unit guard (``active_units(required=True)``) raises ``SourceError``
    (the registry's error contract answers rc 1) because no unit deletion
    may be planned at all.  MEASURED BUT INCOMPLETE — a dump whose options
    identity is absent or contested, or whose ``active_plugins`` value is
    unreadable — returns ``None`` for the kinds it could not read, with
    the cause and the candidate tables, and every consumer of this answer
    REFUSES to act on the affected kind instead of deleting it.  A unit
    deletion that might fatal or silently disable the live site must never
    be planned on a fact nobody measured.
    """
    if ctx.mode == "local":
        if ctx.sql is None:
            # No dump is "not measured", not "nothing active": the GeoIP
            # gate plans nothing (rc 0) and the unit guard below still
            # refuses every unit deletion.  Raising here made a junk-only
            # local tree with a retired GeoIP file exit 1, contradicting
            # SPEC's junk-only --zip rule.
            return ActiveUnits(None, None, reason=_NO_LOCAL_DUMP_REASON)
        with open(ctx.sql, "rb") as dump:
            model = analyze(dump, ctx.settings.db)
        active = model.active_set
        log.debug(
            "active units from --sql: %s plugin file(s), template=%r, "
            "theme measured=%s",
            "unknown" if active.plugins is None else len(active.plugins),
            active.template, active.theme_measured,
        )
        return ActiveUnits(
            None if active.plugins is None else _plugin_slugs(active.plugins),
            None if not active.theme_measured else _theme_slugs(
                (active.template, active.stylesheet)),
            reason=active.reason,
            candidates=active.candidates,
        )
    bridge = stack[2]
    if bridge is None:
        # NO bridge is "not measured", exactly like a local run without
        # --sql: the GeoIP gate (required=False) plans nothing, while the
        # unit guard (required=True) still refuses every unit deletion in
        # the closure below.  Raising HERE made a direct/embedder call
        # contradict the documented contract (R14-P2).
        return ActiveUnits(None, None, reason=_NO_BRIDGE_REASON)
    if deadline is not None:
        deadline.check("clean-files bridge info")
    info = bridge.call("info", **transport_kwargs(deadline))
    if deadline is not None:
        deadline.check("clean-files bridge info end")
    catalog = _plugin_catalog(info.get("plugins"))
    files = [file for file, meta in catalog.items() if meta["active"]]
    log.debug("active units from bridge info: %d plugin file(s)", len(files))
    # A bridge payload that answered normally proves the theme options; an
    # empty/non-string value is NOT that convention: the bridge renders a
    # corrupt array option as "", indistinguishable from an absent one, so
    # _theme_slugs answers None (UNMEASURED) and the unit guard refuses theme
    # deletions rather than deleting the live theme.
    return ActiveUnits(
        _plugin_slugs(files), _theme_slugs((info.get("template"),
                                            info.get("stylesheet"))))


def _unmeasured_detail(active: ActiveUnits) -> str:
    """The ONE refusal line a unit carries when the active set is unknown.

    It names the cause and — for a contested options identity — every
    table that proved the role, because "clean-files did not delete this"
    is only actionable if it says what it could not read and which tables
    to look at.
    """
    cause = active.reason or "the active set was not measured"
    candidates = (f"; candidate tables: {', '.join(active.candidates)}"
                  if active.candidates else "")
    return (
        f"not deleted — the site's active set is UNKNOWN ({cause}"
        f"{candidates}), so no unit can be proven unused: this one stays "
        f"until the active set can be read, or until you have confirmed by "
        f"hand that nothing on the site is using it"
    )


class CleanFilesAction:
    """The plan/apply pair; ``stack`` is the registry-built source trio."""

    def plan(self, ctx: "Ctx", stack: tuple) -> Plan:
        source = stack[0]
        # The walk is the first unbounded phase: a hostile/broken archive
        # that relists a directory forever must end at the run budget, not
        # in `list(source.walk())` holding the process.
        deadline = Deadline.from_ctx(ctx)
        entries: list[Entry] = []
        for entry in source.walk():
            if deadline is not None:
                deadline.check("clean-files walk")
            entries.append(entry)
        if deadline is not None:
            deadline.check("clean-files walk end")
        settings = ctx.settings
        # (category, target, detail, bytes_est, is_dir, requires_apply)
        candidates: list[tuple[str, str, str, int, bool, bool]] = []

        # ONE active-set lookup per plan, shared by the legacy-GeoIP gate
        # (pass 2b) and the active-unit guard (pass 5): both ask the same
        # question of the same payload, and a second identical bridge call
        # would be a second chance to fail.  Lazy — a junk-only tree never
        # asks at all.
        active_cache: list[ActiveUnits] = []

        def active_units(required: bool = True) -> ActiveUnits:
            if not active_cache:
                active_cache.append(_active_units(ctx, stack, deadline))
            active = active_cache[0]
            if required and not active.measured:
                if active.reason == _NO_LOCAL_DUMP_REASON:
                    # The UNIT guard keeps its documented refusal: deleting a
                    # plugin/theme unit without --sql is not knowable.  The
                    # GeoIP gate calls with required=False and plans nothing.
                    raise SourceError(
                        "cannot determine active plugins (local mode requires "
                        "--sql); refusing to plan a plugin/theme unit deletion"
                    )
                if active.reason == _NO_BRIDGE_REASON:
                    raise SourceError(
                        "cannot determine active plugins (no bridge in the "
                        "stack); refusing to plan a plugin/theme unit deletion"
                    )
            return active

        # 0. ATTACHMENT-DATA GUARD for the payload extensions — the live
        #    case was a Gravity Forms submission record: the shipped
        #    ``*.sql`` junk pattern would otherwise put it in a DELETE
        #    plan.  A payload-extension match under wp-content/uploads/ is
        #    excluded from the junk pass below and reported as advice in
        #    pass 4a instead: there it is inbound data (a form-submission
        #    export, a visitor's upload), and clean-files deleting
        #    somebody's form records is the one outcome this exists to
        #    prevent.
        upload_payloads = {
            entry.path: entry for entry in entries
            if not entry.is_dir
            and is_attachment_data(entry.path)
            and payload_file_matches(entry, settings.backup_payloads.extensions)
        }
        # 1. junk FILES — shared predicate; first settings pattern per file
        #    wins (a file matching two patterns is ONE item).  Official
        #    core files under wp-admin//wp-includes/ are exempted by the
        #    SAME rule the audit check applies (junk_matches_for_plan ->
        #    the check's junk_matches_excluding), so the plan never
        #    deletes a file heal-core would restore.  The attachment-data
        #    payload matches of pass 0 are excluded here: the shipped
        #    ``*.sql`` pattern would otherwise put a form-submission
        #    export in a delete plan.
        seen_junk: set[str] = set()
        for entry, pattern in junk_matches_for_plan(
            ctx, stack, entries, settings.webroot_junk
        ):
            if entry.path in seen_junk or entry.path in upload_payloads:
                continue
            seen_junk.add(entry.path)
            candidates.append(
                ("webroot.junk", entry.path, pattern, entry.size, False, True)
            )

        # 2. recurring .po catalogs — shared predicate.
        for entry in po_files(entries):
            candidates.append(
                ("webroot.junk_recurring", entry.path, _PO_DETAIL, entry.size,
                 False, True)
            )

        # 2a. LEGACY GEOLOCATION DATA — gated on the ACTIVE SET, read from
        #     the same lazy lookup the unit guard uses (one bridge `info`
        #     call / one analyzer pass; no bridge/no --sql is UNMEASURED,
        #     so this gate plans nothing and the run stays rc 0.
        #     GeoIP databases were RETIRED in 2019: while the geoip plugin
        #     is inactive nothing reads the megabytes, and a file inside
        #     some OTHER active unit is that plugin's business, not ours.
        geoip: list[tuple[Entry, str]] = []
        for entry in entries:
            if is_attachment_data(entry.path):
                continue
            pattern = geoip_file_matches(
                entry, settings.conditional_junk.geoip_files
            )
            if pattern is not None:
                geoip.append((entry, pattern))
        if geoip:
            active = active_units(required=False)
            if not active.measured:
                # The group's whole premise is "the geoip plugin is NOT
                # active, so nothing reads these bytes" — a POSITIVE claim
                # about the active set, so an unmeasured one plans nothing
                # (the same rule the WP_CACHE gate below follows).
                log.info(
                    "legacy geo data left alone: the active set is unknown "
                    "(%s), so wpt cannot prove the geoip plugin is inactive",
                    active.reason or "not measured",
                )
            else:
                plugins = "/".join(settings.conditional_junk.geoip_plugins) \
                    or "the geoip plugin"
                geoip_plugins = set(settings.conditional_junk.geoip_plugins)
                active_plugins = set(active.plugins or ())
                if geoip_plugins & active_plugins:
                    # The profile's promise: geoip_files are deleted ONLY
                    # while geoip_plugins is INACTIVE.  A match at the
                    # webroot root has no unit owner, so the per-unit check
                    # below cannot protect it; the plugin-level premise is
                    # the gate for EVERY match.
                    log.info(
                        "legacy geo data left alone: %s is ACTIVE, so this "
                        "site still reads %s",
                        "/".join(sorted(geoip_plugins & active_plugins)),
                        ", ".join(entry.path for entry, _pattern in geoip),
                    )
                    geoip = []
                for entry, pattern in geoip:
                    unit = unit_name_of(entry.path)
                    if unit and (unit in active.plugins
                                 or unit in active.themes):
                        log.info(
                            "legacy geo data %s stays: it belongs to the "
                            "ACTIVE unit %r", entry.path, unit,
                        )
                        continue
                    candidates.append(
                        (GEOIP_CATEGORY, entry.path,
                         f"legacy MaxMind GeoIP database ({pattern}) — "
                         f"{plugins} is not active, so nothing on this site "
                         f"reads it",
                         entry.size, False, True)
                    )

        # 2b. PAGE-CACHE BYPRODUCTS — gated on WP_CACHE in wp-config.php,
        #     read AS PHP through wpt.audit.security (a commented-out or
        #     runtime-decided define is UNKNOWN, and an unknown constant
        #     plans nothing: a served cache must never be deleted on a
        #     guess).  wp-config.php is read only when a candidate exists.
        cache_files: list[tuple[Entry, str]] = []
        cache_dirs: list[tuple[Entry, str]] = []
        for entry in entries:
            if not is_attachment_data(entry.path):
                pattern = page_cache_file_matches(
                    entry, settings.conditional_junk.page_cache_files
                )
                if pattern is not None:
                    cache_files.append((entry, pattern))
                    continue
            pattern = page_cache_dir_matches(
                entry, settings.conditional_junk.page_cache_dirs
            )
            if pattern is not None:
                cache_dirs.append((entry, pattern))
        if cache_files or cache_dirs:
            state = wp_cache_state(source)
            plugin = settings.conditional_junk.page_cache_plugin
            if state == "absent":
                sizes = _dir_subtree_sizes(entries)
                counts = _dir_subtree_file_counts(entries)
                for entry, pattern in cache_files:
                    candidates.append(
                        (PAGE_CACHE_CATEGORY, entry.path,
                         f"{plugin} byproduct ({pattern}) — WP_CACHE is "
                         f"undefined in wp-config.php, so this cache is never "
                         f"served again",
                         entry.size, False, True)
                    )
                for entry, pattern in cache_dirs:
                    candidates.append(
                        (PAGE_CACHE_CATEGORY, entry.path,
                         f"{plugin} page cache ({pattern}, "
                         f"{counts.get(entry.path, 0)} files) — WP_CACHE is "
                         f"undefined in wp-config.php, so this tree is never "
                         f"served again",
                         sizes.get(entry.path, 0), True, True)
                    )
            elif state == "defined":
                log.debug(
                    "page cache is in use (WP_CACHE is defined in "
                    "wp-config.php): no page-cache junk planned"
                )
            else:
                log.warning(
                    "WP_CACHE could not be resolved in wp-config.php: no "
                    "page-cache junk is planned (a served cache is never "
                    "deleted on a guess)"
                )

        # 3. stale content DIRECTORIES — shared predicate.  No unit rule
        #    and no guard of their own here: a stale DIRECTORY that IS a
        #    plugin/theme unit is deletable only in whole, so pass 5
        #    guards every unit target no matter which group chose it.
        stale = stale_content_dir_matches(entries, settings.stale_content_dirs)

        # 4. migration leftovers — shared predicate, then the UNIT rule:
        #    a match strictly inside wp-content/plugins/<unit>/ (or the
        #    themes twin) selects the UNIT, never the inner file.  The
        #    active-unit guard is pass 5, not this loop.
        migration_groups = migration_pattern_matches(
            entries, settings.migration_leftovers
        )

        sizes: dict[str, int] | None = None
        counts: dict[str, int] | None = None
        if stale or migration_groups:
            sizes = _dir_subtree_sizes(entries)
            counts = _dir_subtree_file_counts(entries)

        for entry in stale:
            candidates.append(
                (
                    "webroot.stale",
                    entry.path,
                    f"{counts.get(entry.path, 0)} files",
                    sizes.get(entry.path, 0),
                    True,
                    True,
                )
            )

        dir_entries = {entry.path: entry for entry in entries if entry.is_dir}
        for pattern, matched in migration_groups:
            collapsed: dict[str, Entry] = {}
            for entry in matched:
                unit = _unit_dir_of(entry.path)
                if unit is None:
                    collapsed[entry.path] = entry
                else:
                    # A missing unit dir entry (an inconsistent tree)
                    # still collapses — the "never an inner file"
                    # invariant holds unconditionally; its sizes/counts
                    # degrade to 0 via .get().
                    collapsed[unit] = dir_entries.get(
                        unit, Entry(path=unit, is_dir=True, size=0)
                    )
            for entry in _topmost(list(collapsed.values())):
                nbytes = sizes.get(entry.path, 0) if entry.is_dir else entry.size
                if entry.is_dir:
                    candidates.append(
                        (
                            "webroot.migration",
                            entry.path,
                            f"{pattern}, {counts.get(entry.path, 0)} files",
                            nbytes,
                            True,
                            True,
                        )
                    )
                else:
                    candidates.append(
                        ("webroot.migration", entry.path, pattern, nbytes,
                         False, True)
                    )

        # 4a. BACKUP PAYLOADS — a webroot can contain full-site
        #     archives IN the document root beside a dead duplicate
        #     webroot: an exposure at a guessable URL, and nothing
        #     clean-files may delete (a site's backup is MOVED, never
        #     destroyed).  The group is a FALLBACK: it claims only a
        #     payload no other group claimed, so a migration export
        #     archive keeps its (deletable) migration item and this one
        #     never downgrades an existing delete into advice.  Items are
        #     advice (requires_apply=False) under the shared exposure name
        #     ``backup_payload_in_webroot``, and the detail names the
        #     command that moves the payload out.
        claimed = {cand[1] for cand in candidates}
        for cand in payload_candidates(entries, settings):
            if cand.path in claimed:
                continue
            candidates.append(
                (PAYLOAD_CATEGORY, cand.path,
                 f"{PAYLOAD_EXPOSURE}: {cand.pattern}"
                 + (f" backup directory ({cand.files} files)"
                    if cand.is_dir else " backup payload")
                 + " in the document root — an exposure at a guessable URL, "
                   "not only wasted bytes; clean-files never deletes it. Run "
                   "`wpt park-backups --apply` to move it out of the webroot",
                 cand.size, cand.is_dir, False)
            )
        for path, entry in sorted(upload_payloads.items()):
            if path in claimed:
                continue
            candidates.append(
                (PAYLOAD_CATEGORY, path,
                 "backup-extension match inside wp-content/uploads/ "
                 "(attachment data) — NEVER deleted: that path holds inbound "
                 "records (a Gravity Forms submission export, a visitor's "
                 "upload). If it really is a dump, move it out of the "
                 "webroot by hand",
                 entry.size, False, False)
            )

        # 4b. OBSOLETE ASSETS — the operator's own decision, as DATA: the
        #     profile's ``obsolete_assets.known_added`` signatures ship
        #     DISABLED, so with the shipped profile NOTHING here is planned
        #     and the observed cases (unreferenced .eot fonts, .map
        #     source maps, foreign-locale .po catalogs on a localized site)
        #     stay the operator's call.  A file matching an ENABLED
        #     signature plans with the signature's own note as its
        #     one-line detail.  Attachment data is exempt (an upload is
        #     somebody's file), and a file the recurring-.po group already
        #     claims is deduped by the (category, target) order below.
        for entry in entries:
            if is_attachment_data(entry.path):
                continue
            signature = obsolete_asset_matches(
                entry, settings.obsolete_assets.known_added
            )
            if signature is None:
                continue
            candidates.append(
                (OBSOLETE_CATEGORY, entry.path, signature["note"],
                 entry.size, False, True)
            )

        # 5. THE ACTIVE-UNIT GUARD — one pass over the WHOLE plan, after
        #    every group has spoken: a planned target that IS a unit
        #    (plugin or theme, dir or single-file plugin) WordPress is
        #    using is REPLACED by an advice item, never deleted.  The
        #    active facts are fetched from ONE payload and only when a
        #    unit target exists at all (never for a junk/po-only tree),
        #    and are unknowable → fail-closed (SourceError for no payload at
        #    all, an advice refusal per unit for a payload that could not
        #    measure the set).  Replacing the candidate in place (instead of
        #    adding a second item) keeps one item per target, so the guarded
        #    unit can never also sit in ``dir_targets`` as a subsumption
        #    parent.
        guarded: list[str] = []
        unit_targets = [
            (index, _unit_slug(cand[1], cand[4]))
            for index, cand in enumerate(candidates)
            if cand[5]  # a non-applicable candidate is never a deletion
        ]
        unit_targets = [(index, unit) for index, unit in unit_targets
                        if unit is not None]
        if unit_targets:
            active = active_units()
            for index, (kind, slug) in unit_targets:
                in_use_set = active.plugins if kind == "plugin" \
                    else active.themes
                if in_use_set is None:
                    # NOT MEASURED (a contested or absent options identity,
                    # an unreadable active_plugins option): a unit can only
                    # ever be deleted in whole, and nothing proves this one
                    # is unused, so it is refused — the same item shape as a
                    # measured ACTIVE unit (advice, never a deletion), with
                    # the cause and the candidate tables in its detail.
                    cand = candidates[index]
                    guarded.append(cand[1])
                    candidates[index] = (
                        _GUARD_CATEGORY,
                        cand[1],
                        _unmeasured_detail(active),
                        cand[3],
                        cand[4],
                        False,
                    )
                    continue
                if slug not in in_use_set:
                    continue
                cand = candidates[index]
                guarded.append(cand[1])
                candidates[index] = (
                    _GUARD_CATEGORY,
                    cand[1],
                    _GUARD_DETAILS[kind].format(slug=slug),
                    cand[3],
                    cand[4],
                    False,
                )

        # Guarded-by-source targets never enter the plan (one warning
        # names them).  Guarded ACTIVE units are advice: never
        # delete-checked, never subsumption parents (their subtree is NOT
        # being removed).
        kept: list[tuple[str, str, str, int, bool, bool]] = []
        dir_targets: set[str] = set()
        skipped: set[str] = set()
        for cand in candidates:
            if cand[5] and not _deletable(source, cand[1]):
                skipped.add(cand[1])
                continue
            kept.append(cand)
            if cand[4] and cand[5]:
                dir_targets.add(cand[1])

        # A planned directory removal already covers everything beneath it
        # (never the directory itself: the startswith test is strict); a
        # duplicate target keeps only its first (category, target) item.
        items: list[PlanItem] = []
        seen: set[str] = set()
        for category, target, detail, nbytes, _is_dir, requires in sorted(
            kept, key=lambda c: (c[0], c[1])
        ):
            if any(target.startswith(d + "/") for d in dir_targets):
                continue
            if target in seen:
                continue
            seen.add(target)
            items.append(
                PlanItem(
                    category=category, target=target, detail=detail,
                    bytes_est=nbytes, requires_apply=requires,
                )
            )

        if skipped:
            log.warning(
                "excluding %d guarded target(s) the source refuses to delete: %s",
                len(skipped),
                ", ".join(sorted(skipped)),
            )
        if guarded:
            log.info(
                "plan: %d active unit(s) WordPress is using are NOT deleted "
                "(deactivate/switch first): %s",
                len(guarded),
                ", ".join(sorted(set(guarded))),
            )
        plan = Plan(items=items)
        log.info(
            "plan: %d item(s), %s estimated", len(items), human_bytes(plan.est_bytes())
        )
        return plan

    def apply(self, ctx: "Ctx", stack: tuple, plan: Plan) -> Plan:
        source = stack[0]
        deadline = Deadline.from_ctx(ctx)
        if deadline is not None:
            deadline.check("clean-files apply walk")
        dirs: set[str] = set()
        for entry in source.walk():
            if deadline is not None:
                deadline.check("clean-files apply walk")
            if entry.is_dir:
                dirs.add(entry.path)
        if deadline is not None:
            deadline.check("clean-files apply walk end")
        for item in plan.items:
            if not item.requires_apply:
                # advice item (the active-unit guard): never touched.
                continue
            if deadline is not None:
                deadline.check("clean-files apply delete")
            try:
                if item.target in dirs:
                    source.rmdir_recursive(item.target)
                else:
                    source.delete(item.target)
            except (WptError, OSError) as exc:
                log.warning(
                    "could not remove %s (%s: %s); continuing",
                    item.target,
                    type(exc).__name__,
                    exc,
                )
                continue
            item.done = True
        return plan


# The registry stores the decorated OBJECT and calls .plan/.apply on it,
# so the registered action is the instance (a bare class would be invoked
# with plan(ctx, stack) unbound and crash in run_action).
register_action("clean-files", applies=("ftp", "local"))(CleanFilesAction())
