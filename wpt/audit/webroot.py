"""Webroot + plugin audit checks (W6c): pure functions over AuditData + Settings.

Every check registers through ``wpt.audit.registry.register_check`` under a
dotted name with ``applies=("ftp", "local")`` — both source modes walk the
same tree, so every check here is mode-agnostic — and has the uniform
signature ``func(data: AuditData, settings: Settings) -> list[Finding]``.
All pattern lists come from ``Settings`` (wpt/data/profiles/default.json),
never from literals; nothing here mutates ``data``; findings are returned
sorted by ``(category, name)``.

Structural WordPress constants (fixed layout facts, NOT tunables —
documented here per the settings rule):

* ``wp-content``            — content root; stale content directories
                              match only somewhere under this directory.
* ``wp-content/plugins``    — plugin directory; its direct children are the
                              plugin units (directory subtrees plus
                              single-file ``.php`` plugins).
* ``wp-content/languages``  — language-pack directory whose ``.po``
                              catalogs are recurring junk (wp.org re-ships
                              them on every translation auto-update;
                              ``.mo``/``.l10n.php`` are the runtime formats).
* ``.php``                  — single-file plugin extension ("hello.php").
* ``wp-config-sample.php``  — the install-time sample config WordPress
                              ships (medium-risk junk).

Structural WordPress PLUGIN facts (fixed facts about what a plugin
writes, NOT tunables — same rule):

* :data:`CONTENT_META_PREFIXES` — plugin slug -> the postmeta key PREFIXES
  whose rows carry that plugin's stored page-builder content.  Used only
  by plugins.duplicate to answer "which of these two page builders
  actually holds content?", which an operator otherwise has to answer by
  querying the database by hand (an observed migration's page-builder
  decision).  A plugin with no entry here gets NO content
  claim at all — a cache plugin stores its state in options/transients,
  and saying "no content" about it would be a guess, not evidence.

Junk risk classification (derived from each settings pattern's own text):
a pattern shaped ``*.sql`` (leading wildcard + ``.sql`` suffix) flags a
database dump exposure and a pattern containing ``.bk`` flags a config
backup exposure — both L1, risk "high"; ``wp-config-sample.php`` is
"medium"; every other pattern is "low".

Junk pattern GROUPS — a ``<group>:<glob>`` pattern (the same
``{name, note}`` pairing ``core_integrity.known_added`` and
``obsolete_assets.signatures`` use, spelled for a list-of-strings key):

* a BARE pattern (``error_log``, ``*.sql``) is matched against the file's
  BASENAME at any depth, is reported under its own name, and is rated by
  the text rules above — the pre-existing contract, unchanged;
* a GROUPED pattern is matched against the webroot-relative PATH and is
  reported as ONE finding for the GROUP, named by the group, carrying
  that group's risk, its WHY and its fix (:data:`_JUNK_GROUPS`).

Both halves exist because the two families are different in kind, not in
degree. A bare pattern names a file whose NAME is the problem
(``error_log``, ``*.sql``) — the same name is junk wherever it sits. The
grouped family names files that are junk only because of WHERE they are:
they are the SOURCE HOST's control files, and a control file belongs to
the account, not to the site. Scoping the glob to the whole PATH is what
makes that structural instead of a convention — and the scoping is
ENFORCED AT THE PROFILE DOOR (:func:`wpt.settings._load_webroot_junk`), not
merely intended here: a group glob that carries any of ``/ * ? [ ]`` is
refused at load, because ``fnmatch``'s ``*`` crosses ``/`` and a globbed
group reached WordPress's own top-level core files (``*.php`` → wp-login.php,
wp-cron.php, xmlrpc.php …) at the group's HIGH risk with its "no site
content is lost" fix, which the plan then carried out for seven of them
(the core-junk exemption covers ``wp-admin``/``wp-includes`` only), and a
theme's own template and a plugin's authored ``index.html`` through
``*.html``. A group's glob is a webroot-ROOT FILENAME, and the door also
refuses a root ``.php`` — the literal spelling of the same bypass
(``host_placeholder_page:wp-cron.php``, measured: a HIGH finding over one of
WordPress's own core files and a plan that deleted it) — and any name in
the write-guard's refuse set (``Source.PROTECTED``, e.g. the live
``.htaccess``). So a theme's ``home.html``, ``home.php`` and a plugin's
``index.html`` are unreachable BY THE DOOR, for every value a profile file
or a ``--set`` can carry. A BARE pattern is untouched by all of it: it is
basename-matched at any depth by design. The shipped groups:
:data:`_JUNK_GROUPS`.

The group NAME is profile data (the operator can rename it, drop the
group, or add their own files to it) while the wording of a WHY is this
module's, as every other finding's wording is; a group name with no
entry here is not an error, it degrades to the bare-pattern shape, so a
profile can never reference a risk that does not exist.

Check semantics:
* webroot.junk — files only; a BARE settings.webroot_junk pattern is
  matched on the BASENAME and is one finding under its own name; a
  ``<group>:<glob>`` pattern is matched on the webroot-relative PATH and
  is ONE finding for the group, named by the group, carrying that
  group's risk/WHY/fix (:data:`_JUNK_GROUPS`, :func:`split_junk_pattern`);
  a pattern with zero matches yields no finding.  OFFICIAL-CORE
  EXEMPTION: a matched path
  the wp.org checksum map for the site's version lists under
  wp-admin/ or wp-includes/ (wp-includes/ID3/license.txt,
  wp-includes/images/crystal/license.txt, wp-includes/js/*/license.txt,
  ...) is EXEMPT — the patterns otherwise flag official core files,
  clean-files deletes them, core.integrity reports them missing and
  heal-core restores them: a finding set that never resolves (live
  two-site migration).  Live-verified for 7.1, the junk-matching core
  members are the five ``license.txt`` copies only (ID3, images/crystal
  and js/{plupload,swfupload,tinymce}, all under wp-includes/; measured
  across every release 6.5 -> 7.1.2).  Top-level
  license.txt / readme.html / wp-config-sample.php are ALSO map
  members but stay deletable — their removal is the tool's designed
  behavior; the exemption is core-dir-only.  The map is the site's own
  version AND build locale, fetched through integrity.py's OWN
  primitives, and the TWO CONSUMERS SPLIT on what an unproven basis
  means (:func:`CoreJunkBasis`):
  the DELETE PLAN (clean-files) stays FAIL-CLOSED — a core-dir match
  the map could not judge is left un-planned, because deleting a file
  wpt cannot prove is not official core is the worse error; the CHECK
  reports it — an unknown version or an unavailable map must not make a
  real ``wp-includes/error_log`` (a served-at-200 disclosure
  this check exists for) vanish from the report, so every match is
  reported and the finding's detail says the basis is unproven.  Each
  consumer announces the ONE shared refusal reason once per run.
  SERVED DISCLOSURE: when the live site answers HTTP 200 for a matched
  path, the fix text LEADS with "N of these are served publicly at ..."
  plus the deny rule (:func:`_junk_fix_with_served`) — junk in the
  document root is public by default, and "delete" alone never said so
  (live: a large ``error_log`` served at 200 with SQL and absolute
  paths in it).  At most three matched paths are probed, the run deadline
  is checked before each, and LOCAL mode (no live site) renders
  byte-identically to a run without a probe.
* webroot.junk_recurring — one aggregate finding over the ``.po`` files
  under wp-content/languages (recursive); runtime-safe to delete but
  recurring.
* webroot.stale — directories only, anywhere under wp-content/, whose
  basename matches a settings.stale_content_dirs pattern; one finding per
  matched directory with its subtree file-byte sum / file count.
* webroot.migration — an entry (file OR directory) matches a
  settings.migration_leftovers pattern when ANY path component fnmatches
  it; a matched directory subsumes its descendants, so a plugin subtree
  is reported once (count = topmost matches; bytes = subtree sums for
  matched dirs + sizes for matched files).
* webroot.mu_plugins — must-use plugin units (direct children of
  wp-content/mu-plugins) whose name starts with one of the
  settings.mu_plugin_known_platform prefixes — the markers hosting
  platforms deploy (automation-by-installatron, 0-worker); one
  aggregate low-risk informational finding suggesting operator review.
* plugins.inactive — plugin units not active; a plugin unit is a direct
  child directory of wp-content/plugins (slug = dir name, extent = its
  subtree) or a direct child file ending ``.php`` (slug = file name).
  Active slugs are the first component of each active_plugins path
  ("akismet/akismet.php" -> "akismet"; a single-file plugin is active
  only when its own path, e.g. "hello.php", is listed).  An entry that
  cannot name a unit at all (empty, absolute, webroot-relative — see
  ``_plugin_relative_path``) is skipped: the option is a DB string list
  and a slug derived from such a value names a non-plugin.  UNMEASURED
  active set (``AuditData.active_plugins is None`` — an absent or
  contested options-table identity, or an unreadable active_plugins
  value): one low-risk marker, ``count=0``, under
  :data:`PLUGINS_ACTIVE_SET_UNKNOWN_CATEGORY` — a category of its own so
  no suggested-step rule fires (``plugins.inactive``'s is
  ``wpt deactivate-plugin <slug>``, which REFUSES in the only mode that
  produces the marker) and no total counts it.  Its fix text scopes the
  refusal to the ACTIVE SET; it never claims the run holds no deletion.
* plugins.duplicate — per settings.duplicate_plugin_groups group, one
  finding when more than one member is present, naming present members
  and their active/inactive status.  Per present member it also states
  the DB CONTENT EVIDENCE when the gathered facts carry it
  (:data:`CONTENT_META_PREFIXES` + the ``content_meta_posts`` fact), and
  its fix names the member to keep plus the exact deactivate command —
  the operator's real question is "which one do I keep?", which
  :data:`CONTENT_META_PREFIXES` answers from the database instead of
  leaving the decision entirely open.  Its BYTES are the members the fix
  itself names for deactivation and NOTHING else: a finding that refuses
  to decide (two content holders, an unusable map) claims zero
  reclaimable bytes [D1] — but refusing to CLAIM is not refusing to
  MENTION, so a decision that names NO keeper also states the deferred
  figure ("N MB across the present members becomes reclaimable once a
  keeper is named") in the detail plus one INFO line, keeping the
  number visible for the campaign ledger without putting it in the
  reclaimable total.
* plugins.heavy — one aggregate finding over present known_heavy units.
* db.active_missing — active_plugins entries (the DB's truth; both
  modes normalize the fact into AuditData) the walked tree cannot account
  for, in TWO shapes, each its own aggregate HIGH finding:
  ``active-missing-plugins`` (the plugin UNIT is ABSENT — the two-site
  migration shape: an export zip missing several active plugin directories
  (page builder, cache, SEO, form export, and others); no other check
  catches it; the files are GONE, so bytes=0) and ``active-plugin-entry-missing``
  (the unit SURVIVED but holds no PHP file the loader would use as its
  entry point — an observed plugin shape: many orphan vendor/*.php still
  served and executed, main file gone, reported as NOTHING because the
  unit was present).  The second finding names the entry paths and says
  the plugin cannot be CONFIRMED: a tree walk sees whether an entry file
  is THERE, never whether it is a valid plugin — WordPress's own
  plugin-header scan is the bridge's job, and ``reconcile-plugins`` runs
  it live, which is where the authoritative answer comes from.  The
  inverse (installed but not listed) stays out of scope —
  plugins.inactive owns it.  An UNMEASURED active set yields the same
  fail-closed shape as the media check's unmeasured marker: one low-risk
  ``count=0`` finding under :data:`DB_ACTIVE_SET_UNKNOWN_CATEGORY` (its
  own category, so ``db.active_missing``'s restore/reconcile-plugins
  advice — both of which refuse offline — can never fire on a marker that
  means "not measured").  Registered here because it consumes this
  module's plugin-unit semantics (_plugin_units / _active_plugin_paths /
  _loadable_plugin_entries); both checks share ONE active set, so neither
  can call a real plugin inactive while the other calls it missing.
"""

from collections.abc import Callable
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import TYPE_CHECKING

import requests

from .data import AuditData, _read_wp_version
# The checksum-map seam is integrity's (ONE locale path, ONE 1h cache,
# ONE fallback): the exemption rides the same primitives the core.integrity
# check and heal-core use, never a fetch of its own.
from .integrity import _fetch_comparison_checksums, _transport, resolve_core_locale
from .updates import DEFAULT_WP_ORG, owned_session
from ..media_refs import UPLOADS_MARKER
from .registry import register_check
# The served-path probe (security.py owns every HTTP fact probe) and the
# ONE human-byte formatter (report.py).
from .security import publicly_served_paths
from ..log import get_logger
from ..deadline import Deadline
from ..report import human_bytes
from ..settings import Settings, WpOrgSettings, junk_pattern_parts
from ..types import Entry, Finding, Source

if TYPE_CHECKING:
    from ..cli import Ctx

log = get_logger("audit.webroot")

# Structural WordPress constants (see module docstring).
_WP_CONTENT = "wp-content"
_PLUGINS_DIR = "wp-content/plugins"
_LANGUAGES_DIR = "wp-content/languages"
_MU_PLUGINS_DIR = "wp-content/mu-plugins"
_THEMES_DIR = "wp-content/themes"
_PO_SUFFIX = ".po"
_PLUGIN_FILE_SUFFIX = ".php"
_WP_CONFIG_SAMPLE = "wp-config-sample.php"
# The official-core subtrees the junk exemption is scoped to (see
# core_junk_exempt): wp.org ships license.txt copies under these dirs,
# and their deletion would fight heal-core.  Structural, NOT tunables.
_WP_ADMIN = "wp-admin/"
_WP_INCLUDES = "wp-includes/"

#: Plugin slug -> the postmeta key PREFIXES whose rows carry that plugin's
#: page-builder CONTENT (structural WordPress/plugin facts, NOT tunables —
#: see the module docstring).
#:
#: Elementor stores each document's element tree under
#: ``_elementor_data`` (``Document::ELEMENTOR_DATA_META_KEY`` in the
#: plugin's own source) and its remaining editor state under sibling
#: ``_elementor_*`` keys; a page builder writes its per-post state
#: under ``_fusion*``.  Matching on the PREFIX (not one exact key) is the
#: industry-standard way to see a builder's footprint — the widely used
#: builder-meta-cleanup plugin gates its removal on
#: ``meta_key LIKE '_elementor_%'`` and ``LIKE '_fusion%'`` for exactly
#: this reason, because the key set differs between plugin versions.
#:
#: The HEURISTIC and its limit, named because the finding is advice: a
#: member with rows under these keys HOLDS CONTENT (deactivating it
#: leaves content that only it can render); a member with zero rows is a
#: DEACTIVATION CANDIDATE.  A page a builder never touched (a classic
#: editor post) holds content for NEITHER builder, and a builder whose
#: content lives only in ``post_content`` shortcodes (Fusion Builder
#: stores its layout as ``[fusion_builder_*]`` shortcodes) can read zero
#: — the finding therefore names the source of the evidence and never
#: claims the deactivation is safe, only that the database shows no
#: content behind the member.  A slug with NO entry here is never given a
#: content claim in either direction.
CONTENT_META_PREFIXES: dict[str, tuple[str, ...]] = {
    "elementor": ("_elementor_",),
    "fusion-builder": ("_fusion",),
}

#: The category + name of the finding that says the ACTIVE SET could not
#: be measured, and why those are the two consumers' own constants.
#:
#: Deliberately NOT ``plugins.inactive`` / ``db.active_missing``: those
#: categories' suggested steps are ``wpt deactivate-plugin <slug>`` and
#: ``wpt reconcile-plugins --apply`` (report.SUGGESTED_STEPS), and BOTH
#: REFUSE in the only mode that produces this marker — local, where there
#: is no bridge to read WordPress's own ``active_plugins`` and the dump's
#: options-table identity is absent or contested.  Measured on a
#: contested-identity dump: the marker named both commands while the SAME
#: report's clean-files plan held 8 deletions, so the report advised two
#: refusals over a run that could act.  No suggested-step rule matches
#: these categories and ``count=0`` keeps each marker out of every
#: total — the same two halves ``media.unmeasurable`` uses
#: (wpt/audit/media.py:UNMEASURED_CATEGORY).
#:
#: The fix text therefore says the ACTIVE SET is what could not be
#: measured — never that "nothing is deletable", which this run's own
#: other plans contradict — and names the ftp route that can answer.
#: The names are per-category and both are the same shape
#: (``<check>_active_set_unknown``), so the two markers stay
#: distinguishable in a report while sharing one rule.
PLUGINS_ACTIVE_SET_UNKNOWN_CATEGORY = "plugins.active_set_unknown"
DB_ACTIVE_SET_UNKNOWN_CATEGORY = "db.active_set_unknown"
ACTIVE_SET_UNKNOWN_NAME = "active-set-unknown"

#: The AuditData attribute plugins.duplicate reads the per-prefix post
#: counts from: ``content_meta_posts: dict[str, int] | None`` — meta_key
#: PREFIX -> the number of DISTINCT posts holding a postmeta row whose
#: meta_key starts with that prefix.  None = unknown (the gatherers do
#: not carry it — a remote run whose db_audit did not answer, or a dump
#: without a usable postmeta table), which renders the finding exactly as
#: it reads today.  A producer MUST answer EVERY prefix in
#: :data:`CONTENT_META_PREFIXES` (0 for a prefix with no rows): a member
#: with a prefix missing from the map is treated as UNKNOWN, so a
#: partially-answered map can never turn into a false "no content".
_CONTENT_POSTS_ATTR = "content_meta_posts"


def content_posts(data: AuditData) -> dict[str, int] | None:
    """The gathered meta-key-prefix -> distinct-post-count map, or None.

    Read defensively because the gatherers do not populate the field yet
    (it is the data layer's contract, not this check's): an AuditData
    without the attribute, or with None, means UNKNOWN and every
    consumer degrades to its no-evidence shape.  A present map is
    returned as-is; this module never mutates it.
    """
    counts = getattr(data, _CONTENT_POSTS_ATTR, None)
    if not isinstance(counts, dict):
        return None
    return {str(k): v for k, v in counts.items() if isinstance(v, int)
            and not isinstance(v, bool) and v >= 0}


def member_content_posts(
    slug: str, counts: dict[str, int] | None
) -> int | None:
    """Posts holding THIS member's content, or None when unknown.

    The sum over the slug's :data:`CONTENT_META_PREFIXES` keys — but only
    when every one of them is answered by the gathered map with a
    non-negative integer, so a missing or unusable count degrades to
    "unknown" instead of a confident zero.  A slug with no declared
    prefixes is always None: the tool has no evidence to offer about it,
    and never substitutes a guess.
    """
    prefixes = CONTENT_META_PREFIXES.get(slug)
    if not prefixes or counts is None:
        return None
    if any(prefix not in counts for prefix in prefixes):
        return None
    values = [counts[prefix] for prefix in prefixes]
    if any(isinstance(v, bool) or not isinstance(v, int) or v < 0
           for v in values):
        return None
    return sum(values)


# ------------------------------------------------- shared matching predicates
# One owner for every pattern-matching semantic: the checks below AND the
# clean-files action (wpt/actions/clean_files.py) import THESE — never
# reimplement the expressions.


#: The separator a GROUPED ``webroot_junk`` pattern uses (``<group>:<glob>``)
#: and the metacharacters that make a group glob a GLOB, both live in
#: ``wpt.settings`` (``JUNK_GROUP_SEPARATOR`` / ``_JUNK_GLOB_META``): the
#: settings DOOR validates a grouped pattern's shape before this module ever
#: sees one, so the grammar is asked in exactly one place and there is no
#: local copy of it here to fall out of step.
def split_junk_pattern(pattern: str) -> tuple[str | None, str]:
    """``(group, glob)`` for one ``settings.webroot_junk`` pattern.

    ``(None, pattern)`` for a BARE pattern — unchanged behavior: matched on
    the basename, reported under its own name.  ``(group, glob)`` for a
    ``<group>:<glob>`` pattern: ``glob`` is matched on the webroot-relative
    PATH (so a glob carrying no ``/`` can only match at the webroot root)
    and the whole pattern is attributed to ``group``.

    The SPLIT is :func:`wpt.settings.junk_pattern_parts` — one implementation,
    because the profile door validates a grouped pattern's GLOB with it
    before a pattern ever reaches this module, and two splits would let a
    pattern pass one door under one reading and be matched under another.
    Only the FIRST colon splits, so every further colon belongs to the glob
    and a colon-bearing filename still matches (``weird:12:00.html``); a
    colon with an empty side, or a left side holding a glob metacharacter
    (``*?[]``), is not a group reference and the pattern stays bare.

    THE ROOT-SCOPING IS ENFORCED, NOT ASSUMED: ``_load_webroot_junk`` refuses
    a KNOWN group's glob outright when it carries any of ``/ * ? [ ]``, when
    it names a member of the write-guard's refuse set
    (``wpt.types.Source.PROTECTED`` — the live ``.htaccess``,
    ``wp-config.php``, ``index.php``, ``wp-admin``, ``wp-includes``) and
    when it is a root ``.php`` (core's own executable surface — the literal
    spelling of the same bypass the metacharacter rule closes, which a
    profile reached as ``host_placeholder_page:wp-cron.php`` and the plan
    then deleted), so the invariant this module's docstring claims — a
    theme's ``home.html``, a plugin's authored ``index.html`` and
    WordPress's own top-level core files are unreachable — is true by the
    profile DOOR, for every value a profile or a ``--set`` can carry.  An
    unknown group name still degrades to the bare shape, where a
    metacharacter is matched on the basename at any depth by design.
    """
    return junk_pattern_parts(pattern)


@dataclass(frozen=True)
class JunkGroup:
    """One named junk GROUP's reportable verdict.

    :attr:`risk` replaces the text-derived :func:`_junk_risk` for every
    pattern in the group; :attr:`why` is the detail clause that says what
    the file IS and what it costs (the one sentence the per-pattern
    "safe to delete" text could never say about a host control file);
    :attr:`fix` is the operator action.

    The group is rated by its WORST member and says so — a group holding a
    full-site-outage page and an inert test page is one finding at the
    higher risk, and a reader who wants the per-file severity reads the
    WHY, which names what each shape is.
    """

    risk: str
    why: str
    fix: str


#: The shipped junk groups, keyed by the group name a profile pattern
#: declares.  Observed on a live migration's source-host webroot (a
#: control-panel export: a "Coming Soon" page, a custom 404 page, a tiny
#: test page, a quota file, and two superseded pre-hardening copies of the
#: access config beside the live ``.htaccess`` the hardening action owns).
#: All of them survived the migration because a control-panel file is
#: invisible to anyone looking for site content, and the shipped junk list
#: named none of them.
#:
#: A group name absent from this table is not an error: the pattern falls
#: back to the bare shape, so a profile can never reference a risk that
#: does not exist.  The wording is here, the MEMBERSHIP is in the profile.
#: The KEYS are pinned to ``wpt.settings.JUNK_GROUP_NAMES`` — the name set
#: the profile door asks before it refuses a group's glob — by
#: ``tests/audit/test_webroot.py``, so a group can never be added to one
#: view and not the other (a name only the door knew would be matched with
#: no wording, and one only this table knew would be unvalidated).
_JUNK_GROUPS: dict[str, JunkGroup] = {
    "host_placeholder_page": JunkGroup(
        risk="high",
        why=(
            "a HOST placeholder page in the document root is a control-panel "
            "file, not site content. A 'coming soon' page here is what every "
            "visitor gets at the site URL — a full-site visual outage, and "
            "one that survives a migration because nobody thinks of it as "
            "content; a custom 404/error page can take over the host's "
            "error handling (LiteSpeed serves the error document it finds "
            "in the docroot) and replace the site's own 404; a host test "
            "page is inert clutter that only records the old account being "
            "probed and served. A WordPress webroot's root belongs to "
            "index.php."
        ),
        fix=(
            "Delete it: the site is rendered by index.php, so nothing reads "
            "these and no site content is lost. If the operator wants a "
            "maintenance page or custom error pages, keep the files OUT of "
            "the webroot (above the docroot) and point the host at them "
            "deliberately — a page left in the docroot root is a page the "
            "public gets by default."
        ),
    ),
    "host_account_quota": JunkGroup(
        risk="medium",
        why=(
            "a hosting-ACCOUNT control file: it holds the account's real "
            "FTP disk-quota numbers (the live source-host value is a "
            "soft/hard pair) and is fetched from a guessable name by "
            "anyone who asks, which is a small but real disclosure of the "
            "old account's host configuration — and in the new account the "
            "numbers are stale and misleading, describing limits that "
            "account does not have. Medium, not high: it is host metadata, "
            "not site data — no credential, no database row, no executable "
            "content and no request it can serve. Matched at the webroot "
            "root, which is where the account's quota is actually declared "
            "(a nested .ftpquota holding 0 0 sets no quota and discloses "
            "nothing, so it is not a finding)."
        ),
        fix=(
            "Safe to delete: the quota is the control panel's, not the "
            "site's — the panel owns the limit and re-writes the file if "
            "the account ever needs one. Nothing in WordPress reads it."
        ),
    ),
    "superseded_htaccess": JunkGroup(
        risk="medium",
        why=(
            "a SUPERSEDED copy of the site's access configuration. The web "
            "server only ever reads '.htaccess' — the live file, which the "
            "harden action owns and the write-guard protects — so this one "
            "is inert. Medium, not low, because it is inert WITH THE OLD "
            "RULES IN IT and it is a complete, plausible-looking config: "
            "re-applying it, restoring over the live one, or editing the "
            "wrong copy silently drops the cache block, the HTTPS "
            "redirect and the hardening rules. This is NOT the live "
            "'.htaccess' and no web server reads it."
        ),
        fix=(
            "Safe to delete: no web server reads a name other than "
            "'.htaccess', and the live '.htaccess' is the file that is "
            "served. Move it out of the webroot instead if its rules are "
            "worth reading — but never edit or re-apply it in place, and "
            "never let a restore write over the live '.htaccess' with it. "
            "('.htaccess' itself is never a clean-files target.)"
        ),
    ),
}


def junk_file_matches(entries: list[Entry], patterns: list[str]) -> list[tuple[Entry, str]]:
    """EVERY (file entry, matching pattern) pair for junk patterns.

    Files only; entry-major in `entries` order, patterns in settings order
    within a file. The check groups these by pattern (a file matching two
    patterns counts under both); the clean-files action keeps only the
    first pair per file (first settings pattern wins as the item detail).

    WHICH text a pattern is matched against is the ONE decision
    (:func:`split_junk_pattern`, shared with the check and therefore with
    clean-files and with integrity's junk-deletion subtraction, so the
    three can never disagree on what "junk" means): a bare pattern on the
    BASENAME, a grouped one on the webroot-relative PATH.

    The returned pattern is always the FULL settings string, group prefix
    included, so the group travels with the pair — the check needs it to
    aggregate without a second pass over the settings list, and the plan
    item's detail names the group the file was matched under.
    """
    out: list[tuple[Entry, str]] = []
    for entry in entries:
        if entry.is_dir:
            continue
        for pattern in patterns:
            group, glob = split_junk_pattern(pattern)
            subject = entry.path if group else entry.path.rsplit("/", 1)[-1]
            if fnmatchcase(subject, glob):
                out.append((entry, pattern))
    return out


def _under_core_dirs(path: str) -> bool:
    """True for paths inside the wp-admin/ or wp-includes/ subtrees."""
    return path.startswith(_WP_ADMIN) or path.startswith(_WP_INCLUDES)


#: The consumers of the official-core junk exemption, named so the ONE
#: refusal announcement can be made once PER CONSUMER: the audit check
#: (which REPORTS the unproven matches) and the clean-files plan (which
#: refuses to delete them).
_JUNK_CHECK_CONSUMER = "webroot.junk"
_JUNK_PLAN_CONSUMER = "clean-files"


@dataclass(frozen=True)
class CoreJunkBasis:
    """What the wp.org checksum map PROVED about the core-dir junk matches.

    The two consumers of the exemption need DIFFERENT things from the
    same fetch, which is why one shared predicate could not serve both
    (it silently removed the check's whole reason to exist when the
    basis was unavailable):

    * :attr:`official` — core-dir matches the map LISTS.  Exempt from the
      finding AND from the plan, by both consumers, always.
    * :attr:`unproven` — core-dir matches the map could NOT judge
      (unknown version, unavailable map).  The PLAN drops them (a
      deletion wpt cannot justify); the CHECK reports them with
      :data:`_UNPROVEN_NOTE` naming the reason.  Empty when the map
      applied.
    * :attr:`refusal` — the ONE reason the basis was unavailable, or
      None.  Announced once per consumer
      (:func:`_warn_exemption_refused`).
    """

    official: frozenset[str]
    unproven: frozenset[str]
    refusal: str | None = None


#: The detail clause a webroot.junk finding carries when it matched a
#: core-dir path the map could NOT judge.  It states what is missing, what
#: it may mean, and what the delete plan will do — the finding is still
#: a real file in the document root (a served ``wp-includes/error_log`` is
#: an information disclosure whatever its name), so it is reported; it
#: is not a proven-junk file, so nothing may be deleted on this evidence.
_UNPROVEN_NOTE = (
    "unproven core basis: {reason}. This site could not be compared with "
    "the official wp.org checksums, so an official core file may appear in "
    "this list — and the delete plan (wpt clean-files) will not touch a "
    "core-dir match until the basis is available. Do not delete these on "
    "this evidence: make wp.org reachable and wp-includes/version.php "
    "readable, then re-run, and the official ones are exempted."
)


#: The run-scoped latch behind :func:`_warn_exemption_refused` — CONSUMER
#: -> the reason its exemption was already announced (absent = it was
#: not).  A process IS a run, so this is what makes the refusal ONE
#: warning per run per consumer instead of one per matched file (a tree
#: with a hundred ``wp-includes/**/license.txt`` copies must not bury the
#: one line that says the protection is off) — and, being keyed by
#: consumer, the audit's announcement can no longer swallow the plan's
#: (or the reverse): each consumer learns that its own basis is missing.
#: Tests reset it the same way they reset ``wpt.audit.updates._CACHE_DIR``.
_EXEMPTION_REFUSED: dict[str, str] = {}


#: What each consumer DOES with a core-dir match it cannot prove, said in
#: its own warning.  Kept beside the latch: the refusal is only useful
#: next to its consequence.  A consumer missing from this map is
#: announced with the reporting effect — the one that names no deletion.
_JUNK_REFUSAL_EFFECT: dict[str, str] = {
    _JUNK_PLAN_CONSUMER: (
        "Every junk match under wp-admin/ and wp-includes/ is therefore "
        "left un-planned: wpt cannot prove such a file is not official "
        "core, and clean-files would delete a file heal-core then has to "
        "restore."
    ),
    _JUNK_CHECK_CONSUMER: (
        "Every junk match under wp-admin/ and wp-includes/ is therefore "
        "REPORTED with the basis named as unproven: a core-dir match the "
        "map could not judge is still a file in the document root (a "
        "served error_log is an information disclosure whatever its name), "
        "and a finding that disappears because wp.org was unreachable is "
        "the silence this project treats as the dangerous outcome. Nothing "
        "is deleted on this evidence: the clean-files plan keeps its own "
        "fail-closed refusal."
    ),
}
_JUNK_CHECK_REFUSAL_EFFECT = _JUNK_REFUSAL_EFFECT[_JUNK_CHECK_CONSUMER]


def _warn_exemption_refused(consumer: str, reason: str) -> None:
    """Announce ONCE per consumer that the official-core exemption is off.

    The exemption is the only thing standing between a junk pattern and
    an OFFICIAL core file, so its refusal must be loud and must say what
    it costs — in the words of the consumer that refuses, from
    :data:`_JUNK_REFUSAL_EFFECT`: the PLAN says it will not touch what
    it cannot prove, the CHECK says it reports it and names the basis as
    unproven.  ``reason`` is the ONE shared reason (:func:`core_junk_basis`
    builds it and both consumers pass it through verbatim, so the same
    condition cannot be described two ways).  One line per consumer per
    run, not per file — a site with a hundred core-dir junk matches would
    otherwise bury it.
    """
    if consumer in _EXEMPTION_REFUSED:
        return
    _EXEMPTION_REFUSED[consumer] = reason
    log.warning(
        "webroot junk (%s): the official-core exemption could NOT be "
        "applied — %s. %s Make wp.org reachable and "
        "wp-includes/version.php readable, then re-run; nothing else about "
        "this run is affected.",
        consumer, reason,
        _JUNK_REFUSAL_EFFECT.get(consumer, _JUNK_CHECK_REFUSAL_EFFECT),
    )


def _unproven_basis(
    consumer: str, reason: str, core_paths: set[str]
) -> CoreJunkBasis:
    """The refusal result: nothing proven official, every core-dir match
    unproven, the ONE reason — announced once for ``consumer``."""
    _warn_exemption_refused(consumer, reason)
    return CoreJunkBasis(frozenset(), frozenset(core_paths), reason)


def core_junk_basis(
    pairs: list[tuple[Entry, str]],
    version: str | None,
    session: requests.Session,
    timeout_s: int,
    source: Source | None = None,
    site_locale: str | None = None,
    consumer: str = _JUNK_CHECK_CONSUMER,
    deadline: Deadline | None = None,
    wp_org: WpOrgSettings | None = None,
) -> CoreJunkBasis:
    """The wp.org checksum map's VERDICT on this run's core-dir junk
    matches: what it proved official, what it could not judge, and the
    one reason it could not.

    The map is the wp-admin//wp-includes/ subset of the wp.org checksum
    map of the site's exact version AND build locale: the junk patterns
    (``license.txt``, ``readme.html``, ``wp-config-sample.php``, ...)
    also match OFFICIAL core files (measured live on a real site: every
    release 6.5 -> 7.1.2 ships exactly five such members —
    ``wp-includes/ID3/license.txt``,
    ``wp-includes/images/crystal/license.txt`` and
    ``wp-includes/js/{plupload,swfupload,tinymce}/license.txt``), and
    deleting those makes core.integrity report them missing and
    heal-core restore them — a finding set that never resolves, and
    ``wp core verify-checksums`` failing on the site afterwards.

    THE BASIS, resolved once and by the owners that already have it:
    the build locale comes from :func:`resolve_core_locale` and the map
    from :func:`_fetch_comparison_checksums` — integrity.py's OWN
    primitives, the ones core.integrity and heal-core use, so there is
    ONE locale path, ONE 1h ``.wpt-cache`` (its key is the request URL,
    so the version AND the locale are in it and a run that also executes
    core.integrity fetches each map once) and ONE en_US fallback with
    its one warning.  A previous version of this function asked for the
    en_US map and asserted the exemption "needs no locale resolution of
    its own" because en_US/fr_CA/de_DE happened to ship byte-identical
    core-dir members for 7.1 — an unproven basis (a build that ships a
    core-dir file only in its own locale, or a version whose en_US build
    is a plain `{"checksums": false}`, silently exempts nothing) for a
    decision that deletes files.

    THE TWO REFUSALS, one reason each, both announced once per consumer
    (:func:`_warn_exemption_refused`): an UNKNOWN version, and an
    UNAVAILABLE map for a known version.  What a refusal MEANS is the
    consumer's own decision — :attr:`CoreJunkBasis.unproven` is the raw
    fact, and the plan (:func:`junk_matches_for_plan`) drops those paths
    while the check reports them.  A junk match OUTSIDE the core dirs is
    untouched by any of this, and a tree with no core-dir junk candidate
    performs NO fetch at all (the common case).  Top-level map members
    (license.txt, readme.html, wp-config-sample.php) are never returned:
    their removal is the tool's designed behavior.

    This function also OWNS the line that explains a changed junk count,
    because it is the only place that knows WHY a match was dropped: the
    MAP lists it (one info line naming the files and the basis they came
    from) or the basis was REFUSED (the warning above, which never claims
    a map membership it does not have).
    """
    core_paths = {
        entry.path for entry, _pattern in pairs if _under_core_dirs(entry.path)
    }
    if not core_paths:
        return CoreJunkBasis(frozenset(), frozenset())
    # The TWO refusal wordings, mirrored from security.py's
    # ``_VERSION_UNREADABLE`` / ``_CHECKSUMS_UNFETCHABLE`` (the two checks
    # that share this fetch seam, each owning the sentence its own report
    # renders) and pinned verbatim by this suite and the security suite,
    # so one condition cannot read two ways across the report.  For
    # security.web_exposed_script the SAME two strings are the
    # discriminator that decides whether a candidate is demoted at all: an
    # unreadable version.php is a fact about the webroot, not about wp.org
    # [D1], and this check's plan-side refusal is the correct
    # fail-closed answer to it.
    if not version:
        return _unproven_basis(
            consumer,
            "the WordPress version could not be read from "
            "wp-includes/version.php",
            core_paths,
        )
    cfg = wp_org or DEFAULT_WP_ORG
    locale = resolve_core_locale(source, site_locale, cfg.default_locale)
    checksums, effective = _fetch_comparison_checksums(
        version, session, timeout_s, locale, deadline=deadline, config=cfg,
    )
    if checksums is None:
        return _unproven_basis(
            consumer,
            f"the official wp.org checksums for WP {version} ({locale}) "
            "could not be fetched",
            core_paths,
        )

    exempt = frozenset(path for path in checksums if _under_core_dirs(path))
    official = sorted(core_paths & exempt)
    if official:
        log.info(
            "webroot junk: %d matched file(s) are official WP core files "
            "(wp.org checksum map, WP %s %s) — exempt from junk "
            "findings and the clean-files plan: %s",
            len(official), version, effective, ", ".join(official),
        )
    return CoreJunkBasis(exempt, frozenset())


def junk_matches_reporting(
    pairs: list[tuple[Entry, str]],
    basis: CoreJunkBasis,
) -> list[tuple[Entry, str]]:
    """The CHECK's junk pairs (:func:`junk_file_matches` output) MINUS the
    core-dir paths the map PROVED official.

    This is the REPORTING half of the split, and it exempts strictly
    less than the plan does (:func:`junk_matches_for_plan`): a core-dir
    match the map could not judge (:attr:`CoreJunkBasis.unproven`) is
    KEPT and reported, because a real ``wp-includes/error_log`` served at
    HTTP 200 is an information disclosure whatever its name — and the
    sharing defect this replaces made that file disappear from the report
    entirely on an offline run (proved by A/B: with wp.org reachable the
    finding appears, offline the same tree reported none, exit 0).  The
    finding names the unproven basis in its detail
    (:data:`_UNPROVEN_NOTE`) so a reader never mistakes an unjudged
    match for a proven-junk one, and :func:`_junk_detail` is where that
    clause is added.
    """
    if not basis.official:
        return pairs
    return [
        (entry, pattern)
        for entry, pattern in pairs
        if entry.path not in basis.official
    ]


def junk_matches_for_plan(
    ctx: "Ctx", stack: tuple, entries: list[Entry], patterns: list[str]
) -> list[tuple[Entry, str]]:
    """The clean-files ACTION plan's junk matching: the CHECK's own
    matching, minus the official core files, AND minus the ones whose
    basis is unproven.

    FAIL-CLOSED, and it is the only place that is: an UNPROVEN core-dir
    match is a file this plan cannot prove is not official core, and a
    deleting plan must never guess in the direction of deletion (live:
    a clean-files --apply on a localized site deleted all
    five official core ``license.txt`` members — ``wp core
    verify-checksums`` failed afterwards — because the version lookup
    came back empty and the refusal was a debug line nobody could see).
    The same fact is a REPORTED finding in the audit
    (:func:`junk_matches_reporting`): the two consumers are not in
    conflict, they answer different questions.

    Version: wp-includes/version.php through the source in BOTH modes
    (:func:`_read_wp_version`, the gather's own seam — the core's own
    statement of its version, the most exact basis for a CORE-file
    exemption; one small bounded read, and the plan stays free of
    bridge roundtrips: a dry run never deploys the bridge just to
    match junk).  That read is BEST-EFFORT and this is a DELETING plan,
    so an answer of None is not a shrug: :func:`core_junk_basis` refuses
    to apply the exemption, announces it once for this consumer, and the
    plan then leaves every core-dir junk match alone.  The SOURCE is
    handed down as well, so the exemption resolves the build locale
    through integrity's own resolver on the FTP path exactly as the audit
    check does.  Transport: the stack session (ftp) or a fresh plain
    session (local — the site is offline, wp.org is not), the profile's
    ``http.timeout_s``.
    """
    source, session, _bridge = stack
    version = _read_wp_version(source)
    owned = session is None
    if owned:
        session = requests.Session()
    pairs = junk_file_matches(entries, patterns)
    with owned_session(session, owned):
        basis = core_junk_basis(
            pairs, version, session, ctx.settings.http.timeout_s,
            source=source, consumer=_JUNK_PLAN_CONSUMER,
            deadline=Deadline.from_ctx(ctx), wp_org=ctx.settings.wp_org,
        )
    if not basis.official and not basis.unproven:
        return pairs
    return [
        (entry, pattern)
        for entry, pattern in pairs
        if entry.path not in basis.official
        and entry.path not in basis.unproven
    ]


def po_files(entries: list[Entry]) -> list[Entry]:
    """.po catalog FILES under wp-content/languages/ (recursive)."""
    prefix = _LANGUAGES_DIR + "/"
    return [
        entry
        for entry in entries
        if not entry.is_dir
        and entry.path.startswith(prefix)
        and entry.path.rsplit("/", 1)[-1].endswith(_PO_SUFFIX)
    ]


def stale_content_dir_matches(
    entries: list[Entry], patterns: list[str]
) -> list[Entry]:
    """Directories under wp-content/ whose basename matches a stale pattern."""
    prefix = _WP_CONTENT + "/"
    return [
        entry
        for entry in entries
        if entry.is_dir
        and entry.path.startswith(prefix)
        and any(
            fnmatchcase(entry.path.rsplit("/", 1)[-1], pattern)
            for pattern in patterns
        )
    ]


def migration_pattern_matches(
    entries: list[Entry], patterns: list[str]
) -> list[tuple[str, list[Entry]]]:
    """(pattern, matched entries) per migration-leftovers pattern.

    An entry matches when ANY path component fnmatches the pattern;
    pattern-major, settings order, empty patterns skipped.
    """
    out: list[tuple[str, list[Entry]]] = []
    for pattern in patterns:
        matched = [
            entry
            for entry in entries
            if any(fnmatchcase(component, pattern) for component in entry.path.split("/"))
        ]
        if matched:
            out.append((pattern, matched))
    return out

# Presentation limits fixed by the W6c check contract (not tunables):
# example paths per junk/migration detail, plugin slugs per inactive detail.
_DETAIL_PATHS = 5
_DETAIL_SLUGS = 8

# ----------------------------------------------------------- shared internals


def _dir_subtree_agg(
    entries: list[Entry], value: Callable[[Entry], int]
) -> dict[str, int]:
    """path -> accumulated ``value(entry)`` over every file beneath it.

    Each file contributes ``value(entry)`` to all of its ancestor
    directories (every directory implied by a file path gets a key); a
    directory entry contributes 0 directly, so an empty directory still
    appears at 0. Entry order does not matter.
    """
    agg: dict[str, int] = {}
    for entry in entries:
        if entry.is_dir:
            agg.setdefault(entry.path, 0)
            continue
        parts = entry.path.split("/")
        for depth in range(1, len(parts)):
            ancestor = "/".join(parts[:depth])
            agg[ancestor] = agg.get(ancestor, 0) + value(entry)
    return agg


def _dir_subtree_sizes(entries: list[Entry]) -> dict[str, int]:
    """path -> subtree file-byte sum for every directory in the tree."""
    return _dir_subtree_agg(entries, lambda entry: entry.size)


def _dir_subtree_file_counts(entries: list[Entry]) -> dict[str, int]:
    """path -> subtree file count for every directory in the tree."""
    return _dir_subtree_agg(entries, lambda _entry: 1)


def _is_plugin_unit_name(name: str) -> bool:
    """Is this direct child of ``wp-content/plugins`` a PLUGIN?

    ``name`` is a path RELATIVE to ``wp-content/plugins`` ("akismet",
    "hello.php", "responsive-menu/index.php") — the shape
    ``get_plugins()`` uses, which is the whole point: every caller passes
    the SAME thing, so the predicates cannot disagree.

    A DIRECT CHILD FILE is a plugin when it ends in ``.php`` (a direct
    child that is a directory is a unit — the caller knows it is one).
    WordPress's own ``index.php`` directory guard (the direct child
    ``index.php``) is the one named exception — a core file, never a unit,
    and it must not appear on an operator's removal list OR their reinstall
    list [L56]. (The exception is a NAME at the DIRECT-CHILD depth: a
    directory plugin whose own main file happens to be called
    ``index.php`` — ``responsive-menu/index.php`` — is a perfectly legal
    WordPress shape and MUST stay a plugin, which is why a basename test
    is wrong here.) [L67]
    """
    if not name:
        return False
    if "/" in name:
        # deeper than a unit's main file: the loader's shape, a plugin file
        return name.endswith(_PLUGIN_FILE_SUFFIX)
    if name == "index.php":
        return False
    # a direct child is a plugin when it is a DIRECTORY (any name) or a
    # .php file; a direct child FILE of any other type (README.txt) is not
    return name.endswith(_PLUGIN_FILE_SUFFIX)


def _plugin_units(entries: list[Entry]) -> list[tuple[str, bool, int, int]]:
    """Ordered ``(slug, is_dir, size_sum, file_count)`` plugin units.

    A unit is a direct child of ``wp-content/plugins``: a directory (slug
    = dir name; size_sum/file_count over its whole subtree) or a file
    ending ``.php`` (slug = file name; size_sum = its size, file_count
    1). Deeper paths and non-.php direct files are not units. Order
    follows the walked entries. ONE implementation, shared by the
    plugins.* checks.
    """
    sizes = _dir_subtree_sizes(entries)
    counts = _dir_subtree_file_counts(entries)
    units: list[tuple[str, bool, int, int]] = []
    prefix = _PLUGINS_DIR + "/"
    for entry in entries:
        if not entry.path.startswith(prefix):
            continue
        slug = entry.path[len(prefix):]
        if "/" in slug:  # not a direct child of the plugins dir
            continue
        if entry.is_dir:
            units.append(
                (slug, True, sizes.get(entry.path, 0), counts.get(entry.path, 0))
            )
        elif _is_plugin_unit_name(slug):
            units.append((slug, False, entry.size, 1))
    return units


def _loadable_plugin_entries(entries: list[Entry]) -> set[str]:
    """Every webroot path WordPress could load AS a plugin.

    ``get_plugins()`` and the plugin API behind it only ever offer the
    loader two shapes: ``wp-content/plugins/*.php`` (a single-file plugin)
    and ``wp-content/plugins/<slug>/*.php`` (a directory unit's DIRECT
    children) — one level into a unit, never deeper.  A ``vendor/`` or
    ``lib/`` subtree is invisible to them, which is exactly why a unit can
    survive a migration with hundreds of PHP files under it and no entry
    point (an observed plugin shape).  ONE definition of "a plugin
    file the loader could use", so the check can never disagree with
    WordPress about which paths exist as plugin entries.
    """
    prefix = _PLUGINS_DIR + "/"
    return {
        entry.path for entry in entries
        if not entry.is_dir
        and entry.path.startswith(prefix)
        and entry.path[len(prefix):].count("/") <= 1
        and _is_plugin_unit_name(entry.path[len(prefix):])
    }


def _plugin_relative_path(path: str) -> str | None:
    """The normalized plugins-relative path an entry names, or None.

    WordPress stores ``active_plugins`` RELATIVE to the plugins dir
    ("akismet/akismet.php", "hello.php") and resolves every entry that
    way (``validate_plugin()`` file_exists's ``WP_PLUGIN_DIR . '/' .
    $plugin``).  Its own ``validate_file()`` normalizes separators and
    allows repeated ``/`` and ``./`` segments, so
    ``headerless//headerless.php`` and ``headerless/./headerless.php``
    ARE loaded units (proven against WordPress 5.9/6.5/6.8/master).  The
    option is a DB string list though: a hand-edited, migrated or botched
    value can hold anything, and the shapes that cannot name a plugin are
    not "missing plugins" — they are DB artifacts:

    * empty / whitespace-only,
    * absolute or webroot-relative ("/wp-content/plugins/x/x.php",
      "wp-content/mu-plugins/loader.php"),
    * a ``..`` segment (an escape attempt, never a plugin path).

    Repeated ``/`` and ``.`` segments are COLLAPSED (not rejected): the
    runtime loads them, and treating them as inactive put the live unit
    on clean-files' deletion plan.  Such an entry is skipped silently only
    when it cannot name a plugin; never a guess in either direction.
    """
    if not path or path != path.strip():
        return None
    parts = path.split("/")
    # wp_normalize_path collapses repeated separators; ``.`` segments are
    # resolved by the filesystem.  Keep the FIRST component meaningful:
    # an empty first component is absolute, and a leading wp-content is
    # webroot-relative.  ``..`` anywhere is an escape, not a plugin.
    normalized: list[str] = []
    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            return None
        normalized.append(part)
    if not normalized:
        return None
    if path.startswith("/") or normalized[0] == "wp-content":
        return None
    return "/".join(normalized)


def _active_plugin_paths(data: AuditData) -> list[str]:
    """Every active_plugins entry that can name a plugin unit, sorted.

    The plugin-RELATIVE paths the option actually holds
    ("akismet/akismet.php", "hello.php"), deduplicated.  ONE owner:
    plugins.inactive and db.active_missing both read what counts as an
    active entry from here (and :func:`_active_plugin_slugs` from the
    same list), so neither can disagree about what "active" means.
    """
    normalized = (_plugin_relative_path(path)
                  for path in data.active_plugins)
    return sorted({path for path in normalized if path is not None})


def _active_plugin_slugs(data: AuditData) -> set[str]:
    """Installed-unit slugs that are active.

    The first component of each active plugin FILE path
    ("akismet/akismet.php" -> "akismet"); a single-file plugin with no
    "/" keeps its whole name ("hello.php" -> "hello.php").  Entries
    that cannot name a plugin unit at all (see :func:`_plugin_relative_path`)
    are skipped — the option is a DB string list, and a derived slug for
    a webroot-relative or absolute path names a directory that is not a
    plugin.  ONE owner: plugins.inactive and db.active_missing both read
    the set from here, so they can never disagree about what "active"
    means.
    """
    return {
        path.split("/")[0]
        for path in _active_plugin_paths(data)
        if _is_plugin_unit_name(path)          # the whole relative entry
    }


def _active_plugin_slugs_measured(data: AuditData) -> set[str] | None:
    """The active-unit slugs, or None when the active set was NOT
    measured (an options-table identity that is absent or contested, or an
    unreadable active_plugins value). One owner: every check that needs to
    know "is this unit active?" asks here, so none of them can mistake
    UNKNOWN for "nothing is active"."""
    if data.active_plugins is None:
        return None
    return _active_plugin_slugs(data)


def _excerpt(items: list[str], limit: int) -> str:
    """Up to ``limit`` items, comma-joined; " (+N more)" when truncated."""
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f" (+{len(items) - limit} more)"


def _topmost(matched: list[Entry]) -> list[Entry]:
    """Matched entries none of whose ancestors also matched."""
    paths = {entry.path for entry in matched}
    kept: list[Entry] = []
    for entry in matched:
        parts = entry.path.split("/")
        if any("/".join(parts[:depth]) in paths for depth in range(1, len(parts))):
            continue
        kept.append(entry)
    return kept


def _junk_risk(pattern: str) -> str:
    """Risk for one BARE settings.junk pattern, classified from its own text.

    ``*.sql``-shaped (leading wildcard + .sql suffix) = database dump
    exposure, contains ``.bk`` = config backup exposure — both L1, high;
    the shipped sample config = medium; everything else = low.  A GROUPED
    pattern never reaches here: its risk is its group's
    (:data:`_JUNK_GROUPS`), and the check resolves the group before it
    resolves a risk.
    """
    if pattern.startswith("*") and pattern.endswith(".sql"):
        return "high"
    if ".bk" in pattern:
        return "high"
    if pattern == _WP_CONFIG_SAMPLE:
        return "medium"
    return "low"


def _junk_fix(risk: str) -> str:
    if risk == "high":
        return (
            "Delete now; database dumps and config backups must never "
            "live in the webroot."
        )
    if risk == "medium":
        return "Safe to delete; WordPress ships it only as an install-time sample."
    return "Safe to delete; not referenced at runtime."


#: The FIX for a finding whose detail carries :data:`_UNPROVEN_NOTE` — the
#: one actionable field an operator reads before touching a file, so it may
#: never contradict the detail.  It replaced the reassuring per-risk text,
#: which said "Safe to delete" (or "Delete now") in the very finding whose
#: detail said "Do not delete these on this evidence": the actionable field
#: talked the operator into the hand-deletion the plan is fail-closed
#: against, and the observed incident was reproduced by hand exactly that way
#: (all five official ``wp-includes/**/license.txt`` members gone, ``wp core
#: verify-checksums`` failing afterwards).  So the fix states the same
#: instruction as the detail, plus the one action that IS available: make
#: wp.org reachable and version.php readable and re-run — the plan will
#: not touch these until then, and nothing needs deleting by hand to be
#: safe in the meantime.  With the basis available the reassuring text
#: returns unchanged: the two are decided by the SAME basis, one fetch
#: apart.  A GROUPED pattern's fix is decided by the same clause
#: (:func:`_group_fix`) for exactly this reason.
_JUNK_UNPROVEN_FIX = (
    "Do NOT delete these on this evidence: an official core file may be "
    "among them, and the delete plan (wpt clean-files) will not touch a "
    "core-dir match until the basis is available. Restore the basis and "
    "re-run instead: make wp.org reachable and wp-includes/version.php "
    "readable, then re-run — the official members are exempted from the "
    "finding and from the plan, and only what is really there is left to "
    "delete. Nothing needs removing by hand to be safe in the meantime."
)


#: The Apache deny line the disclosure fix names.  Structural: it is the
#: extension set the shipped junk/backup policy exists for (a log, a dump,
#: an archive) and Apache 2.4 syntax — the two directives a shared host
#: needs together (``Require all denied`` is 2.4; on 2.2 the hoster's
#: panel rule serves the same purpose).
_JUNK_DENY_LINE = r"FilesMatch \.(log|sql|zip|tar\.gz)$ Require all denied"


def _served_junk_fix(base: str, served: list[str], matched: list[Entry],
                     may_delete: bool = True) -> str:
    """The fix text for junk a matched file of which the LIVE site SERVES.

    Junk in the document root is not only clutter: the web server hands
    the bytes to anyone who asks for the name (live: a large
    ``error_log`` answered at HTTP 200 carrying SQL statements and
    absolute server paths, and nothing in the audit said so — the finding
    said "delete", which is true and does not mention that the file is
    already public).  The disclosure therefore LEADS the fix, with the
    served paths, their measured size and the deny rule, and the original
    per-risk advice follows it.

    Only reachability is measured (any HTTP 200), never the body: the
    check does not read what the server returns, so the sentence states
    the generic hazard of the format (a log or a dump carries SQL and
    server paths) rather than claiming what this file happens to contain.

    ``may_delete=False`` when the finding's basis is unproven: the
    disclosure is a fact whatever the basis question is, but a delete
    instruction would contradict the very clause the fix carries, so the
    served mitigation is the .htaccess deny rule ALONE — the action that
    removes the exposure without removing a file wpt cannot prove is not
    official core.
    """
    sizes = {entry.path: entry.size for entry in matched}
    total = sum(sizes.get(path, 0) for path in served)
    largest = max(served, key=lambda path: sizes.get(path, 0))
    action = ("Delete them AND deny" if may_delete
              else "Do not delete them yet — deny")
    return (
        f"{len(served)} of these are served publicly at "
        f"{_excerpt(served, _DETAIL_PATHS)} (HTTP 200) — a "
        f"{human_bytes(total)} payload in the document root (largest: "
        f"{largest}) is an information disclosure, not just clutter: anyone "
        f"can fetch it, and a log or a dump carries SQL statements and "
        f"absolute server paths. {action} the extension in "
        f".htaccess ({_JUNK_DENY_LINE}). {base}"
    )


def _junk_fix_with_served(
    data: AuditData, base: str, matched: list[Entry],
    may_delete: bool = True,
) -> str:
    """``base``, led by the SERVED disclosure when the live site hands the
    matched file to anyone [D3].

    The webroot is served verbatim, so junk in it is a security fact, not
    only a housekeeping one: a large ``error_log`` at HTTP 200 with SQL
    statements and absolute server paths inside was reported as "delete"
    and nothing in the audit said it was already public.  At most three
    matched paths are probed (deadline-bounded, and skipped entirely when
    there is no live site), so:

    * a site the audit cannot reach (LOCAL mode: an offline zip has no
      probe) renders the fix byte-identically to a run without this
      probe;
    * a 404 or a redirect (a deny rule already in place) is silence — the
      file is not public, so the disclosure would be a lie;
    * any 200 leads the fix with the served paths.
    """
    served = publicly_served_paths(
        data.probe, [entry.path for entry in matched], data.deadline,
    )
    if not served:
        return base
    return _served_junk_fix(base, served, matched, may_delete)


# ------------------------------------------------------------------- checks


def _unproven_clause(matched: list[Entry], basis: CoreJunkBasis) -> str | None:
    """The :data:`_UNPROVEN_NOTE` clause this finding carries, or None.

    ONE predicate for BOTH fields, because the detail and the fix are two
    renderings of the same verdict and must not be able to disagree: the
    detail said "Do not delete these on this evidence" while the fix said
    "Safe to delete", and the actionable field is the one an operator acts
    on (:data:`_JUNK_UNPROVEN_FIX`).
    """
    if not basis.refusal:
        return None
    if not any(entry.path in basis.unproven for entry in matched):
        return None
    return _UNPROVEN_NOTE.format(reason=basis.refusal)


def _junk_detail(
    matched: list[Entry], basis: CoreJunkBasis
) -> str:
    """The finding's example paths, plus the UNPROVEN-CORE clause when
    this pattern matched a core-dir path the map could not judge.

    The clause is what keeps a reported unjudged match honest: without
    it a ``wp-includes/**/license.txt`` (an official core file the
    exemption could not prove) would read exactly like the
    ``wp-includes/error_log`` beside it, and the operator would have no
    way to tell which one the delete plan will refuse.  Attached only to
    the patterns that actually matched such a path — a top-level-only
    finding's basis is not in question.
    """
    detail = _excerpt([e.path for e in matched], _DETAIL_PATHS)
    clause = _unproven_clause(matched, basis)
    if clause is None:
        return detail
    return detail + "\n" + clause


def _group_detail(
    group: JunkGroup, matched: list[Entry], basis: CoreJunkBasis
) -> str:
    """A GROUPED pattern's detail: its example paths, the group's WHY, and
    the UNPROVEN-CORE clause when the basis is in question.

    Same clause, same place, same reason as :func:`_junk_detail` — the two
    are renderings of one verdict and the actionable field must never
    contradict the detail.  (For every SHIPPED group the clause is
    structurally unreachable: a group glob carries no ``/``, so a group
    match is at the webroot root and can never sit under wp-admin/ or
    wp-includes/.  It is routed through the same guard anyway, because a
    profile MAY declare a grouped pattern with a path and then the two
    fields must not be able to disagree.)
    """
    parts = [_excerpt([e.path for e in matched], _DETAIL_PATHS), group.why]
    clause = _unproven_clause(matched, basis)
    if clause is not None:
        parts.append(clause)
    return "\n".join(parts)


def _group_fix(group: JunkGroup, matched: list[Entry], basis: CoreJunkBasis) -> str:
    """A GROUPED pattern's fix, or the UNPROVEN instruction when the basis
    is in question — the one condition under which it differs.

    :data:`_JUNK_UNPROVEN_FIX` replaces the group's own wording for the
    same reason it replaces the per-risk wording on a bare pattern: the
    clause is attached to the whole finding, so a fix that says "safe to
    delete" for a member the plan refuses to touch is the same [D2] defect.

    The group's wording is NOT led by the served-disclosure probe
    (:func:`_junk_fix_with_served`), and that is deliberate.  That
    helper's sentence is shaped for a DUMP OR A LOG: its hazard clause is
    "a log or a dump carries SQL statements and absolute server paths" and
    its mitigation is an extension deny rule in ``.htaccess``
    (:data:`_JUNK_DENY_LINE`).  Both are wrong for these files — a
    dotless control file has no extension to deny, a page is not a payload,
    and the mitigation for a placeholder page is to take the file out of
    the docroot, not to hide a name.  A correct-sounding lead-in with the
    wrong mitigation is worse than none, and the group's own WHY already
    states the exposure in the words the operator needs.
    """
    if _unproven_clause(matched, basis) is not None:
        return _JUNK_UNPROVEN_FIX
    return group.fix


def _junk_fix_for(
    data: AuditData, matched: list[Entry], basis: CoreJunkBasis, risk: str,
) -> str:
    """The finding's FIX, led by the served disclosure — and NEVER
    contradicting its own detail.

    A finding that carries the unproven clause gets
    :data:`_JUNK_UNPROVEN_FIX` (the same instruction as the detail) and
    loses the reassuring per-risk text entirely, at every risk including
    the high dump/backup one: the clause is attached to the whole pattern
    because the operator cannot delete half a finding, so a fix that says
    "Delete now" for the unjudged member is the same defect as "Safe to
    delete" for it.  With the basis available the per-risk text is
    unchanged — the two are decided by the SAME basis, one fetch apart.
    """
    clause = _unproven_clause(matched, basis)
    base = _JUNK_UNPROVEN_FIX if clause is not None else _junk_fix(risk)
    return _junk_fix_with_served(data, base, matched,
                                 may_delete=clause is None)


@register_check("webroot.junk", applies=("ftp", "local"))
def check_webroot_junk(data: AuditData, settings: Settings) -> list[Finding]:
    """Junk files: one finding per matched BARE settings.webroot_junk
    pattern, one per matched GROUP (:func:`split_junk_pattern`).

    A BARE pattern is matched on the file's BASENAME (case-sensitive,
    anywhere in the tree) and is reported under its own name at its
    text-derived risk; a ``<group>:<glob>`` pattern is matched on the
    webroot-relative PATH, is reported ONCE for the group under the
    GROUP's name at the GROUP's risk, and carries the group's WHY and fix
    (:data:`_JUNK_GROUPS`).  Directories never match.  Matched paths the
    official wp.org checksum map of the site's version AND build locale
    lists under wp-admin/ or wp-includes/ are EXEMPT
    (:func:`junk_matches_reporting`); top-level map members stay
    deletable by design.

    WHEN THAT BASIS CANNOT BE ESTABLISHED (unknown version, unreachable
    wp.org) this check still REPORTS every core-dir match and says the
    basis is unproven in the detail (:func:`_junk_detail`) — the delete
    plan keeps its own fail-closed refusal
    (:func:`junk_matches_for_plan`), so a real large ``error_log`` served
    at HTTP 200 can never leave the report because wp.org was
    unreachable, and one warning per run says why the protection is off.
    A finding carrying that clause also carries the UNPROVEN FIX
    (:func:`_junk_fix_for`, :data:`_JUNK_UNPROVEN_FIX`) instead of the
    reassuring per-risk text: the two fields are two renderings of one
    verdict, and the actionable one must not talk the operator into the
    hand-deletion the plan refuses to perform (the observed incident was
    reproduced exactly that way).  Each finding carries count/bytes over
    the matched files, up to 5 example paths in the detail, and the
    pattern-derived risk.

    Two structural exemptions, both from live migrations: a match under
    ``wp-content/uploads/`` is ATTACHMENT DATA (a Gravity Forms export
    arrives as a ``.sql`` the site needs — "Delete now" was wrong advice,
    [L30]), and a backup-payload match (``.zip``/``.tar.gz``/``.sql.gz``
    per ``backup_payloads.extensions``, or a ``backup_payloads.directories``
    entry) is reported as its own HIGH exposure finding instead of junk —
    an archive in the document root is fetchable at a guessable URL
    [L30], and ``wpt park-backups`` moves it.
    """
    findings: list[Finding] = []
    session, timeout_s = _transport(data, settings)
    by_pattern: dict[str, list[Entry]] = {}
    by_group: dict[str, list[Entry]] = {}
    payload_dirs = tuple(settings.backup_payloads.directories)
    data_patterns = tuple(settings.backup_payloads.extensions) + ("*.sql",)
    pairs = junk_file_matches(data.entries, settings.webroot_junk)
    with owned_session(session, data.probe is None):
        basis = core_junk_basis(
            pairs, data.wp_version, session, timeout_s, source=data.source,
            site_locale=data.locale, consumer=_JUNK_CHECK_CONSUMER,
            deadline=data.deadline, wp_org=settings.wp_org,
        )
    for entry, pattern in junk_matches_reporting(pairs, basis):
        if entry.path.startswith(UPLOADS_MARKER) and any(
            fnmatchcase(split_junk_pattern(pattern)[1], p)
            for p in data_patterns
        ):
            # ATTACHMENT DATA: a Gravity Forms export arrives as a .sql the
            # site needs; only the DUMP/ARCHIVE family is exempt under
            # uploads (a log file is junk everywhere).  The test is on the
            # pattern's GLOB, so a grouped pattern shaped like a dump is
            # judged by the same rule as a bare one.
            continue
        # A group name this module has no wording for degrades to the bare
        # shape (:data:`_JUNK_GROUPS`), so an unknown group can never
        # invent a risk — and the finding is then named after the full
        # pattern, exactly as before.
        name, _glob = split_junk_pattern(pattern)
        if name is not None and name in _JUNK_GROUPS:
            by_group.setdefault(name, []).append(entry)
        else:
            by_pattern.setdefault(pattern, []).append(entry)
    for pattern, matched in by_pattern.items():
        risk = _junk_risk(pattern)
        findings.append(
            Finding(
                category="webroot.junk",
                name=pattern,
                detail=_junk_detail(matched, basis),
                bytes=sum(e.size for e in matched),
                count=len(matched),
                risk=risk,
                fix=_junk_fix_for(data, matched, basis, risk),
            )
        )
    for name, matched in by_group.items():
        group = _JUNK_GROUPS[name]
        findings.append(
            Finding(
                category="webroot.junk",
                name=name,
                detail=_group_detail(group, matched, basis),
                bytes=sum(e.size for e in matched),
                count=len(matched),
                risk=group.risk,
                fix=_group_fix(group, matched, basis),
            )
        )
    # Backup payloads are scanned INDEPENDENTLY of the junk patterns (a
    # .tar.gz is not junk by default — it is a full-site backup, and it is
    # an exposure in the document root): profile extensions + directories,
    # minus attachment data, minus plugin/theme units, and minus anything
    # the junk pass ALREADY reported (a .sql the dump rule matched is one
    # finding, not two).
    reported = {
        e.path
        for matched in list(by_pattern.values()) + list(by_group.values())
        for e in matched
    }
    payload_entries = [
        e
        for e in data.entries
        if not e.is_dir
        and not e.path.startswith(UPLOADS_MARKER)
        and not e.path.startswith(_PLUGINS_DIR + "/")
        and not e.path.startswith(_THEMES_DIR + "/")
        and e.path not in reported
        and (
            any(
                fnmatchcase(e.path.rsplit("/", 1)[-1], p)
                for p in settings.backup_payloads.extensions
            )
            or any(part in payload_dirs for part in e.path.split("/"))
        )
    ]
    if payload_entries:
        findings.append(
            Finding(
                category="webroot.junk",
                name="backup_payload_in_webroot",
                detail=_excerpt([e.path for e in payload_entries], _DETAIL_PATHS),
                bytes=sum(e.size for e in payload_entries),
                count=len(payload_entries),
                risk="high",
                fix=_junk_fix_with_served(data, (
                    "A backup payload in the document root is served at a "
                    "guessable URL and can hold the whole site (a live "
                    "migration carried archives plus a dead duplicate "
                    "webroot with executable PHP files). Move it out — "
                    "wpt park-backups --apply — never delete the operator's "
                    "backups."
                ), payload_entries),
            )
        )
    findings.sort(key=lambda f: (f.category, f.name))
    return findings


@register_check("webroot.junk_recurring", applies=("ftp", "local"))
def check_webroot_junk_recurring(
    data: AuditData, settings: Settings
) -> list[Finding]:
    """.po catalogs under wp-content/languages (recursive): recurring junk.

    Runtime-safe to delete (the runtime formats are .mo/.l10n.php) but
    wp.org language packs re-ship .po on every translation auto-update,
    which is on by default — hence a dedicated recurring category instead
    of webroot.junk. One aggregate finding; nothing when no .po exists.
    """
    matched = po_files(data.entries)
    if not matched:
        return []
    return [
        Finding(
            category="webroot.junk_recurring",
            name="po-catalogs",
            detail=(
                "wp.org language packs re-ship .po catalogs under "
                "wp-content/languages on every translation auto-update "
                "(on by default); .mo/.l10n.php are the runtime formats, "
                "so deleting is safe but the files recur"
            ),
            bytes=sum(e.size for e in matched),
            count=len(matched),
            risk="low",
            fix="Safe to delete; they return with the next translation auto-update.",
        )
    ]


@register_check("webroot.stale", applies=("ftp", "local"))
def check_webroot_stale(data: AuditData, settings: Settings) -> list[Finding]:
    """Stale content directories: one finding per matched directory.

    A directory matches when it sits anywhere under wp-content/ and its
    basename fnmatches a settings.stale_content_dirs pattern; bytes/count
    are its subtree file-byte sum / file count.
    """
    matched = stale_content_dir_matches(data.entries, settings.stale_content_dirs)
    if not matched:
        return []
    sizes = _dir_subtree_sizes(data.entries)
    counts = _dir_subtree_file_counts(data.entries)
    findings = [
        Finding(
            category="webroot.stale",
            name=entry.path,
            detail=(
                f"stale content directory ({counts.get(entry.path, 0)} files) "
                "left by a removed plugin or theme"
            ),
            bytes=sizes.get(entry.path, 0),
            count=counts.get(entry.path, 0),
            risk="low",
            fix="Delete the stale directory.",
        )
        for entry in matched
    ]
    findings.sort(key=lambda f: (f.category, f.name))
    return findings


@register_check("webroot.migration", applies=("ftp", "local"))
def check_webroot_migration(data: AuditData, settings: Settings) -> list[Finding]:
    """Migration tool leftovers: one finding per matched pattern.

    An entry (file or directory) matches a settings.migration_leftovers
    pattern when ANY component of its path fnmatches it — so the
    all-in-one-wp-migration plugin dir, an ai1wm* export archive, or a
    file buried inside either all match. A matched directory subsumes its
    descendants: count is the number of topmost matches and bytes sums
    subtree sizes for matched dirs plus file sizes for matched files, so
    a plugin subtree is reported exactly once.
    """
    findings: list[Finding] = []
    sizes: dict[str, int] | None = None
    for pattern, matched in migration_pattern_matches(
        data.entries, settings.migration_leftovers
    ):
        if sizes is None:
            sizes = _dir_subtree_sizes(data.entries)
        topmost = _topmost(matched)
        findings.append(
            Finding(
                category="webroot.migration",
                name=pattern,
                detail=_excerpt([e.path for e in topmost], _DETAIL_PATHS),
                bytes=sum(
                    sizes.get(e.path, 0) if e.is_dir else e.size for e in topmost
                ),
                count=len(topmost),
                risk="medium",
                fix=(
                    "Remove the migration tool and its leftover files; its "
                    "export archives can contain a full site backup."
                ),
            )
        )
    findings.sort(key=lambda f: (f.category, f.name))
    return findings


@register_check("plugins.inactive", applies=("ftp", "local"))
def check_plugins_inactive(data: AuditData, settings: Settings) -> list[Finding]:
    """Inactive plugin units: one aggregate finding.

    Units come from :func:`_plugin_units`; a unit is inactive when its
    slug is not in the active set derived from ``data.active_plugins``.
    Nothing is reported when no plugin units exist at all or every unit
    is active.
    """
    if data.active_plugins is None:
        # The database could not MEASURE the active set (an options-table
        # identity that is absent or contested, or an unreadable
        # active_plugins value). Reporting every installed plugin as
        # inactive is a guess in the dangerous direction — say so instead,
        # under a category of its own (see
        # :data:`PLUGINS_ACTIVE_SET_UNKNOWN_CATEGORY`): the run's other
        # plans still stand, and nothing here is a deletion.
        units = [slug for slug, _d, _s, _f in _plugin_units(data.entries)]
        if not units:
            return []
        return [
            Finding(
                category=PLUGINS_ACTIVE_SET_UNKNOWN_CATEGORY,
                name=ACTIVE_SET_UNKNOWN_NAME,
                detail=(
                    "the database could not be asked which plugins are "
                    f"active, so none of the {len(units)} installed unit(s) "
                    "can be called inactive"
                ),
                count=0,
                risk="low",
                fix=(
                    "The ACTIVE SET is what could not be measured here, so no "
                    "plugin can be called inactive — this says nothing about "
                    "the rest of the run's plans. Re-run against a dump whose "
                    "options table is unambiguous, or ask the question over "
                    "ftp (the bridge reads WordPress's own active_plugins)."
                ),
            )
        ]
    active = _active_plugin_slugs(data)
    inactive = [
        (slug, size_sum)
        for slug, _is_dir, size_sum, _files in _plugin_units(data.entries)
        if slug not in active
    ]
    if not inactive:
        return []
    return [
        Finding(
            category="plugins.inactive",
            name="inactive-plugins",
            detail=_excerpt(
                [f"{slug} ({size_sum} B)" for slug, size_sum in inactive],
                _DETAIL_SLUGS,
            ),
            bytes=sum(size_sum for _slug, size_sum in inactive),
            count=len(inactive),
            risk="medium",
            # [L35] measured on an observed site: on a live site several units
            # owned active database feeds — an inactive plugin's DATA keeps
            # running. Deleting its files is usually right, but the data
            # check comes first.
            fix=(
                "Review and remove inactive plugins. An inactive plugin's "
                "DATA can still be in use — inactive units can own active feeds, "
                "cron events, options, and tables — so check the database "
                "before deleting files, and delete through wp-admin so its "
                "cleanup runs."
            ),
        )
    ]


@register_check("plugins.duplicate", applies=("ftp", "local"))
def check_plugins_duplicate(data: AuditData, settings: Settings) -> list[Finding]:
    """Duplicate plugin groups: one finding per group with >1 member present.

    A group member is present when a plugin unit with its slug exists
    (directory or file, active or not). The finding names the whole group
    (members joined by "/") and lists each present member with its
    active/inactive status.

    CONTENT EVIDENCE (the operator's actual question — "which of these two
    page builders holds the content?"): when the gathered facts carry the
    ``content_meta_posts`` map, every present member that declares content
    meta keys (see :data:`CONTENT_META_PREFIXES`) also states how many
    DISTINCT posts hold its content, and the fix names the member to keep
    and the exact command that deactivates the others.  A member with zero
    content is a deactivation candidate; a member with content is
    load-bearing and is never the one to drop.  The evidence is a
    heuristic (the prefix match, and the shortcode caveat documented on
    :data:`CONTENT_META_PREFIXES`), so the finding names its source and
    the fix stays advice — wpt never deactivates a plugin on its own.

    ``settings.duplicate_plugin_groups_preferred`` (group name -> slug to
    keep) turns the fix into the operator's declared decision: it changes
    ONLY the fix text, never the detail or the counts, and it is honoured
    whether or not content evidence was gathered.  Nothing is applied.

    BYTES = the deactivation-candidate set, never the whole group [D1]:
    :func:`_duplicate_decision` returns the members its own fix text
    names for deactivation, and only those bytes are claimed.  A finding
    that refuses to decide (two content holders, an unusable evidence map,
    or a preference for a member the site does not carry) costs ZERO
    reclaimable bytes — the report's reclaimable total used to present the
    WHOLE group (a measured total across every member, including page
    builders and cache plugins) while the finding's own evidence text
    refused to name a keeper, which is a claim the finding cannot support.
    But refusing to CLAIM is not refusing to MENTION [D1 follow-up]: when the decision
    names NO keeper at all, the detail and one INFO line still carry the
    DEFERRED figure — the present members' total, as the amount that
    "becomes reclaimable once a keeper is named" — so a campaign ledger
    reading the report never loses the number the zero hides.  The
    sentence is deliberately in the DETAIL, not the fix, and the bytes
    field stays 0: one number, one place.
    """
    units = {slug: size_sum for slug, _is_dir, size_sum, _files in _plugin_units(data.entries)}
    measured = _active_plugin_slugs_measured(data)
    if measured is None:
        # The duplicate CONTENT evidence needs the active set; without it the
        # check cannot tell a keep-both decision from a keep-one, so it
        # reports nothing rather than guessing.
        return []
    active = measured
    counts = content_posts(data)
    findings: list[Finding] = []
    for group in settings.duplicate_plugin_groups:
        present = [slug for slug in group if slug in units]
        if len(present) < 2:
            continue
        content = {
            slug: member_content_posts(slug, counts) for slug in present
        }
        fix, candidates, deferred = _duplicate_decision(
            group, present, content, settings, units,
        )
        detail = ", ".join(
            _duplicate_member_detail(slug, slug in active, content[slug])
            for slug in present
        )
        if deferred:
            detail = f"{detail}; {deferred}"
            # ONE line per group, so a report read without the finding
            # table (a campaign ledger, a log tail) still carries the
            # number the zero reclaimable bytes deliberately hides.
            log.info(
                "plugins.duplicate: %s names no keeper — %s",
                "/".join(group), deferred,
            )
        findings.append(
            Finding(
                category="plugins.duplicate",
                name="/".join(group),
                detail=detail,
                bytes=sum(units[slug] for slug in candidates),
                count=len(present),
                risk="medium",
                fix=fix,
            )
        )
    findings.sort(key=lambda f: (f.category, f.name))
    return findings


def _duplicate_member_detail(slug: str, is_active: bool, posts: int | None) -> str:
    """One member of the detail: its state, and its content evidence.

    ``posts is None`` (no content keys declared for the member, or the
    facts carry no counts) renders exactly the state part this check
    always rendered, so a site without the fact keeps today's detail.
    """
    state = "active" if is_active else "inactive"
    if posts is None:
        return f"{slug} ({state})"
    return (
        f"{slug} ({state}, {posts} posts with its content in the database"
        f" — postmeta {_duplicate_meta_keys(slug)})"
    )


def _duplicate_meta_keys(slug: str) -> str:
    """The member's content meta keys, named in the detail (the source)."""
    return ", ".join(CONTENT_META_PREFIXES.get(slug, ()))


#: The one advisory sentence every evidence/preference-driven duplicate
#: fix ends with: the finding is ADVICE, and the deactivate command is the
#: one the operator runs (wpt never touches active_plugins on its own).
_DUPLICATE_ADVICE = (
    "The wp_options snapshot is taken first; this is advice only — wpt never "
    "deactivates a plugin on its own."
)


#: The DEFERRED-reclaimable clause appended to the DETAIL of a duplicate
#: finding whose decision names no keeper [D1 follow-up].  Claiming zero
#: reclaimable bytes and saying nothing about the size are different
#: things: the report's total must not carry a group the finding refuses
#: to act on, but a campaign ledger still has to see how much is riding
#: on the operator's answer.  Rendered only when the decision named no
#: keeper, so it can never contradict a fix that already names one.
_DUPLICATE_DEFERRED = (
    "{total} across the present members becomes reclaimable once a keeper "
    "is named (not counted as reclaimable until then)"
)


def _deferred_reclaimable(units: dict[str, int], present: list[str]) -> str:
    """The deferred-reclaimable clause for a group with no named keeper.

    ``{total}`` is the present members' measured subtree total in
    human bytes, so the operator reads the measured total across the
    present members as reclaimable once a keeper is named, rather than a
    byte count.  A group of zero-byte members states nothing (there is
    no figure to keep visible).
    """
    total = sum(units.get(slug, 0) for slug in present)
    if total <= 0:
        return ""
    return _DUPLICATE_DEFERRED.format(total=human_bytes(total))


def _deactivate_command(slugs: list[str]) -> str:
    """The exact ``wpt deactivate-plugin`` command(s) for these slugs.

    One slug = the runnable command verbatim; several = the same command
    with a ``<slug>`` placeholder plus the explicit list, so the rendered
    advice is never a command that cannot be copied.
    """
    if len(slugs) == 1:
        return f"wpt deactivate-plugin {slugs[0]} --apply"
    return (f"wpt deactivate-plugin <slug> --apply (once per slug: "
            f"{', '.join(slugs)})")


def _slugs(slugs: list[str]) -> str:
    """One or more slugs, readable in a sentence ("a" / "a and b")."""
    if len(slugs) <= 1:
        return "".join(slugs)
    return f"{', '.join(slugs[:-1])} and {slugs[-1]}"


def _duplicate_decision(
    group: list[str],
    present: list[str],
    content: dict[str, int | None],
    settings: Settings,
    units: dict[str, int],
) -> tuple[str, list[str], str]:
    """(fix text, deactivation candidates, deferred-reclaimable clause).

    The second element is the SET the fix text itself names for
    deactivation — the only members whose bytes the finding may claim as
    reclaimable [D1].  It is empty whenever the advice refuses to decide,
    so the report can never present a group as reclaimable storage while
    the text says "decide which one keeps the site".  All three come from
    ONE decision, so the number and the prose cannot disagree.

    The third is the DEFERRED clause: non-empty exactly when the fix
    names NO member to keep, which is the one situation where "zero
    reclaimable bytes" would otherwise swallow a number the operator
    needs (refusing to CLAIM is not refusing to MENTION).  It is a clause
    of prose for the DETAIL plus one INFO line — never a ``bytes``
    contribution, and never rendered beside a fix that already names a
    keeper (there the reclaimable figure is the candidate set itself).

    Shapes, in priority order:

    * the operator's declared preference
      (``settings.duplicate_plugin_groups_preferred``, keyed on the
      group name) names the slug to keep, and the fix becomes the exact
      command for every OTHER present member — an operator who already
      decided never gets argued with, and those members ARE the
      candidates.  A preference naming a member that is not installed
      names no command and claims no bytes: there is nothing to
      deactivate, and the profile is what needs review;
    * otherwise, when the gathered content evidence names EXACTLY ONE
      member holding content AND at least one member holds none, that
      member is the one to keep and the zero-content members are the
      candidates (the one shape that carries bytes);
    * otherwise the generic advice — no single member is provably the
      one to keep, so nothing is claimed.

    No evidence at all (no member declares content keys, or the gather
    carries no counts) and no preference keeps the historical one-liner
    (and claims no bytes), so a run without the fact renders exactly as
    it did before — plus the deferred clause, which is the point.
    """
    preferred = settings.duplicate_plugin_groups_preferred.get("/".join(group))
    if preferred is not None:
        if preferred not in present:
            return (
                f"duplicate_plugin_groups_preferred keeps {preferred}, which is "
                f"not installed on this site — there is nothing to deactivate; "
                f"review the group against the site."
            ), [], _deferred_reclaimable(units, present)
        others = [slug for slug in present if slug != preferred]
        return (
            f"duplicate_plugin_groups_preferred keeps {preferred}: deactivate "
            f"{_slugs(others)} — {_deactivate_command(others)}. "
            f"{_DUPLICATE_ADVICE}"
        ), others, ""
    holders = [slug for slug in present if content.get(slug)]
    empties = [slug for slug in present if content.get(slug) == 0]
    if not holders and not empties:
        # No member declares content keys, or nothing was gathered: the
        # historical one-liner, byte for byte — and no bytes, because
        # "keep one" decides nothing about which.  The deferred clause
        # still states how much is riding on that "one".
        return (
            "Keep one, remove the rest.", [],
            _deferred_reclaimable(units, present),
        )
    if len(holders) == 1 and empties:
        keep = holders[0]
        return (
            f"Keep {keep} — {content[keep]} posts in the database carry its "
            f"content, and none for {_slugs(empties)} (postmeta "
            f"{_duplicate_meta_keys(empties[0])}). Deactivate: "
            f"{_deactivate_command(empties)}. {_DUPLICATE_ADVICE}"
        ), empties, ""
    if len(holders) == 1:
        keep = holders[0]
        return (
            f"Keep {keep} — {content[keep]} posts in the database carry its "
            f"content; the remaining member(s) have no content evidence "
            f"either way, so confirm before dropping them. Deactivate: "
            f"wpt deactivate-plugin <slug> --apply. {_DUPLICATE_ADVICE}"
        ), [], ""
    if len(holders) > 1:
        # [D1] the observed shape: two page builders both hold pages (a
        # builder library table plus its per-post rows).
        # The evidence REFUSES to pick, so no member's bytes are claimed —
        # and the deferred clause keeps the group's size visible anyway,
        # because a zero that says nothing reads as "nothing at stake".
        held = ", ".join(f"{slug}: {content[slug]} posts" for slug in holders)
        return (
            f"Both builders are in use ({held}) — this is a decision, not a "
            f"deletion: choose the one that keeps the site, then deactivate "
            f"the other(s). wpt deactivate-plugin <slug> --apply. No bytes "
            f"are counted as reclaimable: neither member can be dropped "
            f"blind. {_DUPLICATE_ADVICE}"
        ), [], _deferred_reclaimable(units, present)
    return (
        f"No member holds content in the database ({_slugs(empties)}), so any "
        f"of them can go. {_deactivate_command(empties)}. "
        f"{_DUPLICATE_ADVICE}"
    ), [], _deferred_reclaimable(units, present)


@register_check("plugins.heavy", applies=("ftp", "local"))
def check_plugins_heavy(data: AuditData, settings: Settings) -> list[Finding]:
    """Known heavy plugins present as units: one aggregate finding."""
    units = {slug: size_sum for slug, _is_dir, size_sum, _files in _plugin_units(data.entries)}
    present = [slug for slug in settings.known_heavy if slug in units]
    if not present:
        return []
    return [
        Finding(
            category="plugins.heavy",
            name="known-heavy",
            detail=", ".join(present),
            bytes=sum(units[slug] for slug in present),
            count=len(present),
            risk="low",
            fix="Review whether these heavy plugins are needed.",
        )
    ]


@register_check("webroot.mu_plugins", applies=("ftp", "local"))
def check_webroot_mu_plugins(
    data: AuditData, settings: Settings
) -> list[Finding]:
    """Hosting-platform must-use plugins: one informational finding.

    A must-use plugin unit is a DIRECT child of wp-content/mu-plugins
    (a file or a directory — mu-plugin loaders never nest).  A unit
    matches when its name starts with one of the
    settings.mu_plugin_known_platform prefixes — the markers hosting
    panels deploy (Installatron's automation-by-installatron, the
    0-worker bootstrap): platform leftovers that run on EVERY request
    and are invisible to normal plugin management.  One aggregate
    low-risk finding suggesting operator review; a tree without
    mu-plugins or without a known platform prefix is silent.  The
    prefix list is data (the profile), never literals.
    """
    prefix = _MU_PLUGINS_DIR + "/"
    matched: list[Entry] = []
    for entry in data.entries:
        if not entry.path.startswith(prefix):
            continue
        name = entry.path[len(prefix):]
        if not name or "/" in name:  # not a direct child of the dir
            continue
        if any(
            name.startswith(known)
            for known in settings.mu_plugin_known_platform
        ):
            matched.append(entry)
    if not matched:
        return []
    sizes = _dir_subtree_sizes(data.entries)
    return [
        Finding(
            category="webroot.mu_plugins",
            name="platform-mu-plugins",
            detail=_excerpt([entry.path for entry in matched], _DETAIL_PATHS),
            bytes=sum(
                sizes.get(entry.path, 0) if entry.is_dir else entry.size
                for entry in matched
            ),
            count=len(matched),
            risk="low",
            fix=(
                "review these hosting-platform must-use plugins and "
                "remove them if the site no longer runs on that "
                "platform; they run on every request and are invisible "
                "to normal plugin management."
            ),
        )
    ]


@register_check("db.active_missing", applies=("ftp", "local"))
def check_db_active_missing(data: AuditData, settings: Settings) -> list[Finding]:
    """Active plugins the tree cannot account for: up to two HIGH findings.

    ``active_plugins`` names a plugin FILE; WordPress loads exactly the
    path the option holds (``include_once(WP_PLUGIN_DIR . '/' . $plugin)``)
    and ``get_plugins()`` only ever offers the loader a plugin's DIRECT
    ``*.php`` children (``wp-content/plugins/*.php`` for a single-file
    plugin, ``wp-content/plugins/<slug>/*.php`` for a directory unit —
    never a nested ``vendor/`` or ``lib/`` subtree).  So an active entry is
    unaccounted for in two ways, and they are NOT the same risk:

    * ``active-missing-plugins`` — the UNIT is absent from the tree: the
      two-site migration shape (an export zip missing several active plugin
      directories: page builder, cache, SEO, and others).  The
      files are GONE, so bytes=0.
    * ``active-plugin-entry-missing`` — the unit SURVIVED but holds no
      PHP file the loader would use as its entry point.  The live case:
      an active plugin was named in active_plugins, its directory had
      survived a migration (many orphan ``vendor/*.php`` still web-reachable
      and PHP-executing) and its main file was gone — reported as nothing
      because the UNIT was present, while ``wpt reconcile-plugins``, which
      reads ``get_plugins()`` (the MAIN FILE), caught it in one item.  The
      orphaned subtree is live attack surface the operator does not know
      they are serving, which is why this finding is not a variant of the
      first one.

    The offline limit is stated in the fix rather than papered over: a
    tree walk can see that no entry file is THERE, never that the file is
    a valid plugin (that is WordPress's own plugin-header scan, the
    bridge's job — ``reconcile-plugins`` runs it live), so the finding
    says the plugin cannot be CONFIRMED and names the authoritative
    answer.  Entries that cannot name a unit at all (see
    :func:`_plugin_relative_path`) are skipped, and the inverse (installed
    but not listed) stays out of scope — plugins.inactive owns it.

    Installed slugs come from :func:`_plugin_units`, active entries from
    :func:`_active_plugin_paths` (both modes normalize active_plugins into
    AuditData — the analyzer locally, the bridge remotely).  Both findings
    are aggregate and sorted.
    """
    if data.active_plugins is None:
        # The active set is UNMEASURED (absent or contested options-table
        # identity, or an unreadable active_plugins value). "No active
        # plugin is missing" would be a guess in the SAFE direction and
        # hides a gap we cannot see — say the question could not be asked.
        installed_units = [
            slug for slug, _d, _s, _f in _plugin_units(data.entries)
        ]
        if not installed_units:
            return []
        return [Finding(
            # Its own category (see
            # :data:`DB_ACTIVE_SET_UNKNOWN_CATEGORY`): no suggested-step
            # rule may fire on a marker that means "not measured", and
            # count=0 keeps it out of every total.
            category=DB_ACTIVE_SET_UNKNOWN_CATEGORY,
            name=ACTIVE_SET_UNKNOWN_NAME,
            detail=(
                "the database could not be asked which plugins are active, "
                f"so no active-but-missing plugin can be named across the "
                f"{len(installed_units)} installed unit(s)"
            ),
            count=0,
            risk="low",
            fix=(
                "The ACTIVE SET is what could not be measured here, so no "
                "plugin can be called active-but-missing — this says nothing "
                "about the rest of the run's plans. Re-run against a dump "
                "whose options table is unambiguous, or over ftp (the bridge "
                "reads WordPress's own active_plugins)."
            ),
        )]
    installed = {
        slug for slug, _is_dir, _size, _files in _plugin_units(data.entries)
    }
    loadable = _loadable_plugin_entries(data.entries)
    paths = _active_plugin_paths(data)
    findings: list[Finding] = []
    # the same owner decides what an active entry can name (the directory
    # guard is a core file, not a plugin [L56])
    missing = sorted(
        slug for path in paths
        if (slug := path.split("/")[0]) not in installed
        and _is_plugin_unit_name(path)          # the whole relative entry
    )
    if missing:
        findings.append(Finding(
            category="db.active_missing",
            name="active-missing-plugins",
            detail=_excerpt(missing, _DETAIL_SLUGS),
            bytes=0,
            count=len(missing),
            risk="high",
            fix=(
                "restore the missing plugin directories from a complete "
                "export or reinstall them; a site with "
                "active-but-missing plugins will fatal or silently "
                "lose functionality"
            ),
        ))
    no_entry = sorted(
        f"{_PLUGINS_DIR}/{path}" for path in paths
        if f"{_PLUGINS_DIR}/{path}" not in loadable
        and path.split("/")[0] in installed
    )
    if no_entry:
        findings.append(Finding(
            category="db.active_missing",
            name="active-plugin-entry-missing",
            detail=_excerpt(no_entry, _DETAIL_SLUGS),
            bytes=0,
            count=len(no_entry),
            risk="high",
            fix=(
                "the plugin directory survived but holds no top-level PHP "
                "file WordPress would load as its entry point (the file "
                "active_plugins names is not among them), so wpt cannot "
                "confirm this plugin is installed — and the files the unit "
                "does hold are still served and executed, so review them "
                "before anything else. Restore the main plugin file from a "
                "complete export, or run wpt reconcile-plugins (ftp) for "
                "the authoritative answer: only WordPress's own plugin-"
                "header scan (which reconcile-plugins runs through the "
                "bridge) can say whether what is there is a working plugin"
            ),
        ))
    return findings
