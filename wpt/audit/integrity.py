"""WP core file-integrity audit check: wp.org's official checksums.

Hacked-site triage: a core file whose md5 differs from wp.org's official
checksums for the installed version is PROOF of compromise (or of a
botched manual patch — either way it must be restored from a clean
release); junk-pattern scans can only hint.  One check registered as
``core.integrity`` with ``applies=("ftp", "local")`` and the uniform
signature ``func(data: AuditData, settings: Settings) -> list[Finding]``.

wp.org wire (live-verified for WP 7.1 en_US and WP 6.6 fr_CA; trusted,
never re-derived here):

* GET ``core/checksums/1.0/?version=<V>&locale=<locale>`` answers
  ``{"checksums": {"<webroot-relative-posix-path>": "<md5hex>", ...}}``
  — 3782 entries for 7.1 en_US, including the shipped DEFAULT THEME
  (wp-content/themes/twentytwentyfive: 235 entries live-verified —
  default-theme files ARE core-checksummed, so a tampered theme file is
  the same compromise evidence as a tampered wp-includes file).
  ``wp-config.php`` is never listed (the installer creates it,
  WordPress does not ship it).  A locale with no such build answers
  HTTP 200 ``{"checksums": false}`` (live-verified) — the same
  "unusable answer" shape as a transport failure, so the en_US
  fallback below covers it.

Locale resolution (the localized-migration lesson — [L17]: a live
French-Canadian migration healed wp-includes/version.php with en_US
bytes and the site then FAILED ``wp core verify-checksums
--locale=fr_CA``, because the fr_CA distribution's version.php carries
``$wp_local_package = 'fr_CA'``): the comparison map and the heal-core
restore zip are BOTH keyed to the BUILD the installed core files came
from.  :func:`resolve_core_locale` — the ONE owner of the semantics,
consumed by this check AND heal-core so plan and audit can never
disagree — resolves it as:

1. ``$wp_local_package`` parsed from a READABLE wp-includes/version.php
   (the localized-build marker; its absence in a readable file means
   the en_US build — wp-cli's own ``verify-checksums`` default resolves
   exactly this way, and WordPress's ``get_locale()`` consults the
   marker first).  This tier keeps an en_US build plus a fr_CA
   language pack (WPLANG=fr_CA, the COMMON French-site shape — the
   web installer ships language PACKS, not localized builds) reading
   CLEAN: the fr_CA map would false-positive its version.php, and
   heal-core would then write fr_CA-build bytes over an en_US build.
2. When wp-includes/version.php cannot be read (deleted/tampered
   beyond parsing — the pre-heal shape, where the build's own marker
   file is the evidence an attacker destroys): the SITE locale fact
   (AuditData.locale — the analyzer's WPLANG option locally, the
   bridge's get_locale() remotely), which on a properly-installed
   localized site equals the build locale.
3. Else ``en_US``.

The checksums fetch RIDES that locale with an en_US fallback: the
locale map first; when it fails or answers an unusable/empty shape —
``{"checksums": false}`` included — ONE warning, then the en_US map.
heal-core's plan AND apply ride the SAME fallback-aware seam, so a
restore basis can never disagree with this comparison; the only residual
is the RELEASE ZIP: when the comparison's own locale build has no zip on
wp.org, heal-core falls back to the en_US release but restores only the
files the two builds ship IDENTICALLY, reporting the ones that DIFFER
(live-verified: the only same-PATH digest difference between an en_US
and a locale map is ``wp-includes/version.php``) as unrestorable rather
than writing bytes this check would flag on every subsequent run.
The finding's fix text names that policy.

Live-verified on wp.org while reviewing the locale tiers (an observed run,
four versions x two locales): between the en_US map and a locale map of
the SAME version the only same-PATH digest difference is
``wp-includes/version.php`` — the build's identity — while the locale
map additionally LISTS paths the en_US map omits (the localized
default theme and the ``wp-content/languages/`` catalogs; 6.6.2 de_DE
also differs on ``wp-content/plugins/akismet/readme.txt``).  Nothing
else about a build is knowable from the maps, which is why heal-core
derives its unrestorable set by comparing the two maps at runtime
instead of assuming a file list.

Reuse (DRY — no duplicated machinery): the fetch rides the
:class:`~wpt.audit.updates.WpOrgApi` transport from wpt.audit.updates,
which owns the identifying User-Agent (``wpt/<version>``), the 1h
``.wpt-cache/`` with stale-reuse-on-failure, the caller-supplied timeout
and the one-warning-per-failed-request discipline.  This module adds
only the endpoint URL and the payload validation.  The only settings
tunable consumed is the shared ``http.timeout_s`` (the local-mode
transport); the presentation limit, the kind ranking, the core_md5
chunk size (the bridge's own per-call cap), the local read_many batch
size and the local abort bound are structural facts of this check
contract (NOT tunables).

Reuse (heal-core — the classification's public surface): the comparison
primitives are mode-shaped, not AuditData-shaped, so the upcoming
heal-core action (which has a source/bridge/files but no AuditData)
consumes the SAME tampered/added/missing semantics without rebuilding
them — this module stays their ONE owner.  Fetch the reference map via
``_fetch_checksums(version, session, timeout_s, locale)`` (or the
fallback-aware :func:`_fetch_comparison_checksums`); resolve the locale
via :func:`resolve_core_locale`; classify via
:func:`affected_files_local` (a Source, the walked ``files`` map
``{path: Entry}``, the checksums, an optional run deadline) or
:func:`affected_files_bridge` (a Bridge or None, the files map, the
checksums), plus :func:`added_files` for the tree-only additions.
The check path rides the thin AuditData-shaped wrappers
``_affected_files_local`` / ``_affected_files_bridge`` over the same
primitives.  The action itself lives elsewhere — nothing here imports
or registers actions.

Comparison semantics — mode-split at the DIGEST source; the wp.org map
and the walked tree are the shared inputs:

* tampered — the digest of a checksums path's on-disk file differs
  from the map → risk high.  LOCAL: the tree-present map paths stream
  in map order through the source's bulk ``read_many`` primitive
  (``read_many(paths) -> (ok: {path: bytes}, failed: {path: error})``)
  in batches of at most ``_READ_MANY_BATCH`` paths — one bulk read per
  batch, then ``hashlib.md5`` over each ok entry: the wp-cli digest
  comparison over the walked tree, batched so a slow source moves in
  bounded bulk steps instead of one lazy read per file.  FTP: per-file
  FTP reads measured MINUTES PER FILE on a stale passive channel in a
  live run (~3780 core files: non-viable), so the digests come from
  the bridge's bulk ``core_md5`` action instead — every md5 computed
  server-side in ONE call per at most 5000 paths (the bridge's own
  cap, mirrored here), through the ``data.probe.bridge`` seam (the
  SiteProbe carries the live Bridge; the audit runner wires it in ftp
  mode).  Only clean webroot-relative paths are sent — the bridge
  refuses the WHOLE request for any ``..``/out-of-webroot path
  (media_delete's fail-closed precedent) — so a map path that is
  empty or carries a leading ``"/"``, a ``..`` segment or a NUL byte
  is never sent (wp.org publishes only clean paths; one debug when
  this defense drops any).  A batch answer classifies each sent path:
  ``files[path]`` equal to the expected md5 → clean, different →
  tampered (the server-side digest IS the evidence — tree presence is
  not consulted); ``missing`` → the missing kind below; a ``null``
  digest / ``unreadable`` entry → the same debug skip as an
  unreadable local read; a path in no bucket (contract drift) → a
  debug skip.
* added — a ``.php`` file under ``wp-admin/``, under ``wp-includes/``,
  or at the webroot TOP LEVEL (no ``"/"``) that the checksums map does
  not list → risk high.  Tree-only (``entries``), identical in both
  modes and independent of the digest source.  ``wp-config.php`` and
  ``.htaccess`` are USER files by design and never flagged
  (``.htaccess`` is additionally excluded by the ``.php`` filter);
  ``wp-content`` is never scanned for additions — plugins/themes are
  user code.  The scope is deliberately "NOT SHIPPED BY wp.org", not a
  known-core-name allowlist: the canonical core names ARE map members
  (so an allowlist would report nothing at all) and the live high-risk
  evidence this check exists for is precisely the UNKNOWN name (the two
  web-exposed files reported on example.com).  A top-level
  unknown ``.php`` that also carries a request-gate or home-directory
  signature is reported by ``security.web_exposed_script`` as well —
  deliberately complementary, not duplicated: that check is the
  actionable half (the signature, the file's date, the triage and
  removal commands), this one the fact the map states.  Both consume
  this module's :func:`added_files` / ``known_added`` primitives, so
  the plugin-artifact carve-out below applies identically in both.
* missing — a checksums path with nothing on disk, reported ONLY for
  ``wp-admin/``/``wp-includes/`` paths and for TOP-LEVEL ``.php`` map
  paths ([L18] — an observed localized migration: the old host had DELETED
  wp-comments-post.php, wp-cron.php, wp-mail.php, wp-signup.php and
  wp-trackback.php, silently breaking comments and WP-Cron, and the
  old wp-admin/wp-includes-only scope reported NOTHING).  A missing
  top-level NON-php map path (license.txt, readme.html) stays OUT of
  scope — that is the junk policy (webroot junk's own finding treats
  those files as deletable; integrity must not fight it) → risk
  medium.  The junk policy's reach is NOT a hardcoded filename list
  ([L19] — the EXACT loop [L18] opened one file further down the
  scope): it is the profile's own ``webroot_junk`` patterns through
  webroot's ONE matching predicate (:func:`junk_file_matches`,
  imported — the SAME patterns the webroot.junk check and the
  clean-files plan match with), so a profile that junk-matches another
  top-level core file is honored at the same instant.  The exemption is
  scope-shaped (absence only) and top-level-shaped: the core-dir
  members of the map are exempt from junk DELETION by
  :func:`core_junk_exempt` and therefore still demand restoration, and
  ``wp-config.php``/``.htaccess`` are user files the map never lists.
  See the ``junk_patterns`` argument on the primitives.

Consecutive-failure circuit breaker (the live-run lesson, LOCAL read
loop): after 25 consecutive unreadable reads the scan ABORTS with ONE
warning ("core integrity scan aborted after 25 consecutive unreadable
files; results are partial") and returns the findings verified so far —
partial verified results are real, the warning carries the caveat, and
a stale-FTP worst case is bounded to ~25 stalled reads instead of
days.  Any successful read resets the counter (a missing path reads
nothing and leaves it); the tree-only additions still return.  The
batching keeps the semantics: a failed-map entry IS one unreadable
read (the same per-file debug skip plus one counter tick), an ok entry
resets, consecutive runs carry ACROSS batch boundaries, and a trip
discards the rest of the tripped batch's results and reads NO further
batch — the partial return still carries exactly the findings verified
so far.

Run-deadline bound (LOCAL batches — the never-killed-from-outside
rule): the committed ``AuditData.deadline`` (the run budget the audit
runner builds from ctx; None = unbounded) is
``check("core integrity scan")``-ed before every read_many batch.  A
:class:`~wpt.types.DeadlineExceeded` — from that check or raised
inside the bulk read itself — does not escape the LOCAL scan loop: ONE
warning ("core integrity scan stopped: run deadline exceeded; results
are partial") and the same partial return as the breaker abort (findings
verified so far plus the tree-only additions).  A wedged local scan
ends ITSELF at the next batch boundary.  The POST-SCAN theme-skew and
known-artifact reads are outside that degrade: they re-raise
StopRequested/DeadlineExceeded so an expired budget or cooperative
stop ends the command through its shared failure report instead of
being disguised as a completed partial scan.

One grouped Finding (category ``core.integrity``, name ``core-files``):
``count`` = affected files, ``bytes`` = their size sum (missing files
contribute 0, and so does a tampered ftp path the walked tree never
saw), ``detail`` = ONE basis clause naming the comparison that judged
this core ("against the official fr_CA 7.1 checksums" — the EFFECTIVE
locale, en_US after the one-warning fallback), then up to 5
``"kind: path"`` lines then ``"(+N more)"``, sorted by (kind, path)
with the kind order tampered, added, missing.  The clause is the audit
trail an incident needs: the per-file lines alone say nothing about
WHICH distribution judged them, and the en_US and fr_CA maps disagree
on ``wp-includes/version.php``, so a report excerpt carried into a
ticket would otherwise be unreadable next to a contradictory one from a
run that used the other map.  ``risk`` is high whenever a tampered or
added file exists, else medium.  ``fix`` is composed from the kinds
present (the restore / investigate-the-added-file / re-upload texts,
pinned per kind in the constants below).  A clean core is silence
(``[]``), never a "0 findings" row.  The separate low-risk
``added-known`` finding keeps its own detail shape (the signature
notes) — it is a signature verdict, not a checksum verdict.

Default-theme version skew [L12 — the live example.test run: three
twentytwentyfive files read as "tampered" high-risk compromise
evidence and were a pristine official theme AUTO-UPDATE]: wp.org's
core checksums describe the default theme version BUNDLED with the
core release, but WordPress ships default-theme updates independent
of core — a site whose bundled theme auto-updated holds PRISTINE
official files that no longer match those bundled checksums.  The
map-vs-tree classification therefore over-reports "tampered" for
wp-content/themes/<slug>/ paths.  :func:`resolve_theme_skew` — the
post-classification pass BOTH this check and the heal-core action
run (the classification primitives stay pure map-vs-tree comparers)
— cross-checks every tampered path under wp-content/themes/<slug>/
against the OFFICIAL theme release zip of the version the site's own
``wp-content/themes/<slug>/style.css`` ``Version:`` header declares
(``WpOrgApi.fetch_theme_zip``, the same validated-zip 1h-cache
discipline as the core release): a path whose on-disk md5 equals the
official zip entry is DROPPED from the classification with one info
line (an auto-update past the bundled copy, not tampering — and for
heal-core: never "healed" back into the bundled version, which would
DOWNGRADE the theme).  Every failure shape — unreadable style.css, an
unknown version, an unavailable zip, an unreadable path — KEEPS the
tampered classification (the check never guesses benign; one warning
per slug names the unresolved count).  Only paths the checksums map
itself lists can reach this pass, so <slug> is always a core-bundled
default theme, never a guess.

Translation-pack drift [L19 — the same defect one tree over, only
visible on a LOCALIZED build]: a localized build's checksum map
bundles its own ``wp-content/languages/`` catalog set (live-verified:
7.1 fr_CA — 88 entries, 8 ``.po`` + 8 ``.mo`` + 4 ``.l10n.php`` + 68
``<locale>-<md5>.json`` script-translation files; 226 paths more than
the en_US map of the same version), but WordPress replaces those
catalogs from the wp.org TRANSLATION PACK on demand — a live artifact
translated independently of the core build — so an up-to-date site can
differ from the bundled bytes without any tampering.  (Honest measure of
that risk as of this review: across 18 live version x locale pairs
(fr_CA/de_DE/ru_RU/es_ES/ja/it_IT) the pack currently matches the
bundled catalogs byte for byte, so no site is being misreported TODAY;
the exemption is the cheap insurance against the first pack update that
lands after a build, and it is what keeps heal-core from DOWNGRADING a
site's translations to the bundled copies.)  A tampered default theme is
cross-checked against evidence (:func:`resolve_theme_skew`); a
translation catalog cannot be — the runtime formats are
generated/repacked by the translation system, and 8 of them are this
toolkit's OWN ``webroot.junk_recurring`` delete candidates.
:func:`resolve_translation_pack_skew` — the same post-classification
pass position, run by the check AND heal-core — therefore EXEMPTS the
runtime translation formats under ``wp-content/languages/`` from the
tampered classification with one info line.  Narrow by construction:
only the four formats WordPress's translation machinery owns and
reloads (``.po``, ``.mo``, ``.l10n.php``, ``.json``) are exempt, so any
other file type planted in that directory still reads as evidence.  No
security coverage is lost — ``security.suspicious`` scans EVERY
``.php`` under ``wp-content/`` at any depth (its scan roots include
``wp-content/languages/``, so a planted ``.l10n.php`` — the one exempt
format that is PHP — is content-scanned) for executable backdoors,
which is what owns that tree's code, while the checksum comparison only
ever claimed its bundled catalog bytes.

Known plugin-deployed artifacts [L16 — the same live run: Wordfence's
``wordfence-waf.php`` bootstrap read as "added" high-risk compromise
evidence on every Wordfence site]: security plugins deploy small PHP
bootstraps at the webroot top level; the tree-only added detection
cannot know them.  The check splits ``added`` entries against the
settings ``core_integrity.known_added`` signature list: a TOP-LEVEL
file whose name, size and content marker match a signature AND whose
content carries none of the ``suspicious.patterns`` malware
signatures moves to the separate low-risk finding "added-known"
(category ``core.integrity``, name ``added-known``, detail lines
``"added (known): <path> — <note>"``); ANY mismatch — wrong name,
oversized, marker absent, a malware signature hit, an unreadable
file, no source — keeps the high classification.  Benign is matched
on evidence, never guessed; the signature list lives in the profile
(the shipped default carries Wordfence's), not in code.

Degrade contract (never a crash, never a finding from partial data):

* ``wp_version`` None/empty → ``[]`` + one debug (unknown version,
  never guessed — AuditData gathers it in BOTH modes: the bridge
  remotely, wp-includes/version.php locally).
* checksums unavailable — the transport failed with nothing cached, or
  the payload is not a dict, or its ``checksums`` value is not a dict,
  or the normalized map is empty (all-malformed entries count as
  empty) → ``[]`` + ONE warning ("core integrity skipped: checksums
  unavailable").  A present-but-stale cache entry still answers (the
  transport's own discipline — availability over freshness, its warning
  included); individual malformed map entries are dropped silently,
  never raised over.
* an unreadable core file — LOCAL: a ``failed`` read_many entry (the
  primitive funnels the per-path read failure into the map);
  ftp: a ``null`` digest / ``unreadable`` bucket entry — is skipped
  with one debug: unreadable is not proof of tampering.
* core_md5 unavailable (ftp) — the probe carries no bridge (a wiring
  gap — fail-closed, never a silent fallback to the non-viable
  per-file FTP path), a call raised (the client funnels transport,
  protocol and ``{"ok": false}`` envelope failures into BridgeError;
  anything else is still never a crash mid-scan), or the payload is
  malformed → ``[]`` + ONE warning ("core integrity skipped: core_md5
  unavailable (...)") — the same degrade shape as a checksums fetch
  failure.
* no locale evidence at all (version.php unreadable AND the site
  locale unknown — the bridge answered ``info`` without a usable
  locale, or the dump carries no WPLANG) — the resolver's tier-3 floor
  is SILENT (en_US is the documented default, not a finding) and the
  report says so instead: the finding's basis clause and its fix name
  the en_US build it actually used.  The ONE warning this check emits
  about locale belongs to the FALLBACK path (the locale's MAP was
  unavailable), which is the case where a real build identity was
  known and lost.

Modes: the comparison follows ``data.mode`` — which source holds the
files is a property of the mode, not of the transport — while the wp.org
fetch keeps following the probe seam (landed behavior): ftp rides the
probe's DNS-override-aware session (only api.wordpress.org is ever
requested there) and the probe's bridge for the digests; local builds a
plain ``requests.Session`` with the profile's ``http.timeout_s`` — the
SITE is offline, the wp.org reference data is not.  Nothing mutates
``data``; no secrets exist on this path (a public endpoint plus a
token-guarded bridge; logs carry file paths and counts only).
"""

from __future__ import annotations

import hashlib
import io
import re
import zipfile
from urllib.parse import urlencode

import requests

from .data import AuditData, _theme_versions
from .registry import register_check
from .suspicious import _compile_patterns, _scan_text
from .updates import (
    DEFAULT_WP_ORG,
    WpOrgApi,
    owned_session,
)
from ..deadline import Deadline
from ..log import get_logger
from ..settings import (
    Settings,
    WpOrgSettings,
    WP_LOCALE_RE,
    WP_RELEASE_VERSION_RE,
    WP_THEME_SLUG_RE,
)
from ..types import (DeadlineExceeded, Entry, Finding, Source, SourceError,
                     StopRequested)
from ..wpbridge.client import Bridge

log = get_logger("audit.integrity")

#: The classification's public surface (see "Reuse (heal-core)" in the
#: module docstring): the heal-core action consumes these primitives
#: without an AuditData; every other name here is check-internal.
__all__ = [
    "added_files",
    "affected_files_bridge",
    "affected_files_local",
    "check_core_integrity",
    "resolve_core_locale",
    "resolve_theme_skew",
    "resolve_translation_pack_skew",
]

#: The live-verified checksums endpoint base URL lives in
#: ``WpOrgSettings.core_checksums_url`` (one authoritative owner).

# Structural WordPress facts (see module docstring) — NOT tunables.
_WP_ADMIN = "wp-admin/"
_WP_INCLUDES = "wp-includes/"
_PHP_SUFFIX = ".php"
#: Webroot files that are USER files by design: wp.org never lists them,
#: so they are never "suspicious additions".
_USER_FILES = frozenset({".htaccess", "wp-config.php"})
#: The core-build marker file — the ONE file whose bytes differ between
#: the en_US release and a localized build of the same version (its
#: ``$wp_local_package`` line; live-verified for fr_CA 6.6: that is the
#: single same-path difference between the two checksums maps).
_VERSION_PHP = "wp-includes/version.php"
#: The localized-build marker assignment inside wp-includes/version.php
#: (``$wp_local_package = 'fr_CA';`` — a simple single-quoted string, the
#: only shape WordPress ships).
_WP_LOCAL_PACKAGE_RE = re.compile(r"\$wp_local_package\s*=\s*'([^']*)'")

#: Kind ranking for the grouped finding's deterministic (kind, path)
#: order and its severity-derived risk: tampered and added are
#: compromise evidence, missing is an incomplete core.
_KIND_ORDER = {"tampered": 0, "added": 1, "missing": 2}

#: Presentation limit fixed by this check contract (not a tunable):
#: max detail lines before the "(+N more)" truncation marker.
_DETAIL_PATHS = 5

#: core_md5's per-call path cap, mirrored from wpt_action_core_md5 in
#: wpt/wpbridge/bridge.php (which refuses more per call with an error
#: envelope).  A structural protocol constant of the wire contract,
#: NOT a tunable.
_CORE_MD5_BATCH = 5000

#: read_many batching for the LOCAL comparison loop.  Structural, not
#: a tunable: 200 tree-present paths per bulk read bound the batch's
#: in-memory bytes and give the run deadline (AuditData.deadline) a
#: checkpoint at least every 200 files — the local twin of
#: _CORE_MD5_BATCH's wire cap on the ftp side.
_READ_MANY_BATCH = 200

#: Consecutive unreadable reads that abort the LOCAL comparison loop.
#: Structural, not a tunable: a stale FTP passive channel measured
#: minutes PER FILE on a live run, so the scan gives up after this many
#: consecutive failures and returns what it verified — the abort
#: warning carries the partial-results caveat.
_CONSECUTIVE_UNREADABLE = 25

#: The default-theme subtree of the checksums map [L12] — the paths the
#: theme-skew post-pass (resolve_theme_skew) cross-checks against the
#: official theme release.  Structural WordPress fact, NOT a tunable.
_THEMES_PREFIX = "wp-content/themes/"

#: The runtime translation catalogs of a LOCALIZED build's checksum map
#: [L19] — the drift the translation-pack post-pass exempts.  Structural
#: WordPress facts (WP_LANG_DIR's own contents: the source catalogs
#: ``.po``, the compiled ``.mo``, the generated ``.l10n.php`` and the
#: ``<locale>-<md5>.json`` script translations ``load_script_textdomain``
#: reads), NOT a tunable: adding one would widen a security-relevant
#: exemption on a guess.
_LANGUAGES_PREFIX = "wp-content/languages/"
_TRANSLATION_SUFFIXES = (".po", ".mo", ".l10n.php", ".json")

#: Fix text for the low-risk added-known finding [L16].
_KNOWN_ADDED_FIX = (
    "verify the file is the named plugin's own (diff against a freshly "
    "installed copy of the plugin); delete it only once the plugin is gone"
)

# Fix texts are composed per finding from the version and the
# comparison locale (see the check docstring): the operator must know
# WHICH distribution the evidence names — the en_US map and the fr_CA
# map disagree on wp-includes/version.php, so a basis-less "restore
# from a clean release" can heal the wrong build onto the site.


def _locale_residual_note(effective_locale: str, locale: str) -> str:
    """The honest residual clause for a locale-aware fix text.

    Two distinct residuals (see the module docstring): the comparison
    itself fell back to en_US (the locale's map was unavailable — heal
    -core's plan rides the SAME fallback-aware seam, so its restore
    basis matches this comparison and the two cannot disagree), or the
    locale's RELEASE ZIP is unavailable — heal-core then restores only
    the files both builds ship identically and reports the ones that
    DIFFER between the builds as unrestorable, rather than writing
    en_US bytes this check would flag as tampered on every run.
    """
    if effective_locale != locale:
        return (
            f" (the wp.org {locale} checksums were unavailable — the "
            f"comparison used the official en_US checksums, and a file "
            f"restored from the en_US build can still differ from the "
            f"{locale} build)"
        )
    if locale != DEFAULT_WP_ORG.default_locale:
        return (
            f" (heal-core restores from the official {locale} build; when "
            f"wp.org has no {locale} build for this version it restores "
            f"from en_US only the files both builds ship identically, and "
            f"reports the files that differ between the builds as "
            f"unrestorable rather than writing bytes this check would "
            f"always flag)"
        )
    return ""


def _restore_fix(version: str, effective_locale: str, locale: str,
                 added: bool) -> str:
    fix = (
        f"Restore the file from a clean official WordPress "
        f"{version} {effective_locale} release; a tampered core file "
        f"means the site is compromised."
    )
    if added:
        from .security import WEB_SCRIPT_TRIAGE  # deferred: integrity -> security

        fix += " " + WEB_SCRIPT_TRIAGE
    return fix + _locale_residual_note(effective_locale, locale)


def _missing_fix(version: str, effective_locale: str, locale: str) -> str:
    return (
        f"Re-upload the missing core file from a clean official "
        f"WordPress {version} {effective_locale} release."
        + _locale_residual_note(effective_locale, locale)
    )


def _basis_clause(effective_locale: str, version: str) -> str:
    """The detail clause naming WHICH map judged this core.

    The audit trail an incident needs [the observed localized contradiction]: the
    per-file evidence lines say "tampered: wp-includes/version.php"
    and nothing about the distribution those bytes were compared
    against, so a report excerpt pasted into a ticket cannot say which
    build the verdict names — and a reader who saw one run judge the
    core as clean and another report two findings on the same site had
    no way to tell the two runs used DIFFERENT maps.  The clause is
    the EFFECTIVE basis (the locale that answered, which is en_US
    after the one-warning fallback), the same fact the info log line
    and the fix text already carry, stated where the evidence is.
    """
    return f"against the official {effective_locale} {version} checksums"


def _checksums_url(version: str, locale: str | None = None,
                   config: WpOrgSettings | None = None) -> str:
    """The live-verified checksums request for ``version``@``locale``.

    The locale comes from :func:`resolve_core_locale` (the BUILD the
    files came from); the configured default locale is both the default
    and the fallback basis.
    """
    cfg = config or DEFAULT_WP_ORG
    locale = locale if locale is not None else cfg.default_locale
    return f"{cfg.core_checksums_url}?{urlencode({'version': version, 'locale': locale})}"


def resolve_core_locale(source: Source | None,
                        site_locale: str | None,
                        default_locale: str | None = None) -> str:
    """The locale whose BUILD the installed core files came from — the
    ONE owner of the comparison/heal locale semantics, consumed by this
    check AND heal-core (plan and audit can never disagree).

    Tiers (see the module docstring): the ``$wp_local_package`` marker
    parsed from a READABLE wp-includes/version.php (its absence in a
    readable file IS the unlocalized build — wp-cli's own verify-checksums
    default; an unlocalized build plus a language pack must not read as a
    localized build), else the site-locale fact (``AuditData.locale``:
    WPLANG from the analyzer / get_locale() from the bridge — the
    pre-heal shape where version.php was destroyed), else the configured
    default locale.  A marker or site locale outside ``[A-Za-z0-9_]+``
    (real WP locales are fr_CA, de_DE_formal, bel) is refused as
    evidence — it would interpolate into a wp.org URL and a cache
    filename, and tampered bytes never reach either.  Never raises.
    """
    fallback = default_locale or DEFAULT_WP_ORG.default_locale
    if source is not None:
        try:
            raw = source.read_bytes(_VERSION_PHP)
        except (SourceError, OSError):
            raw = None
        if raw is not None:
            match = _WP_LOCAL_PACKAGE_RE.search(
                raw.decode("utf-8", errors="replace"))
            if match is not None and WP_LOCALE_RE.fullmatch(match.group(1)):
                return match.group(1)
            return fallback  # readable file without a valid marker
    if site_locale is not None and WP_LOCALE_RE.fullmatch(site_locale):
        return site_locale
    return fallback


def _transport(
    data: AuditData, settings: Settings
) -> tuple[requests.Session, int]:
    """(session, timeout_s) for the wp.org checksums fetch.

    ftp: the probe's transport — exactly like the updates checks, only
    api.wordpress.org is ever requested.  local (``probe is None``):
    a plain session with the profile's ``http.timeout_s`` — the site is
    offline, but the wp.org reference data is still the comparison's
    source of truth and ``wp_version`` is gathered in both modes.
    """
    if data.probe is not None:
        return data.probe.session, data.probe.timeout_s
    return requests.Session(), settings.http.timeout_s


def _api_deadline(deadline: Deadline | None) -> float | None:
    """The absolute monotonic bound a wp.org transport must honour.

    A test double may implement only ``check()`` (the integrity suite's
    deterministic batch-expiry double); it has no absolute instant, so the
    transport keeps its per-request timeout and the double still ends the
    read loop at the next check.
    """
    return getattr(deadline, "at", None) if deadline is not None else None


def _fetch_checksums(
    version: str, session: requests.Session, timeout_s: int,
    locale: str | None = None, deadline: Deadline | None = None,
    config: WpOrgSettings | None = None,
) -> dict[str, str] | None:
    """The validated ``path -> md5`` map for ``version``@``locale``, or None.

    Rides the WpOrgApi transport (updates.py): identifying UA, configured
    cache with stale-reuse-on-failure, one transport warning
    per failed request.  None means NO usable answer — the transport
    failed with nothing cached, the payload is not a dict, its
    ``checksums`` value is not a dict (a locale with no such build
    answers HTTP 200 ``{"checksums": false}`` — live-verified), or the
    normalized map is empty (all-malformed entries count as empty); the
    CALLER logs the single skip warning.  Partial data is never
    returned: a map that survives validation is complete for the paths
    it lists.  ``deadline`` is the run budget: an already-expired budget
    raises BEFORE any request (and a cache hit does not hide the expiry).
    """
    cfg = config or DEFAULT_WP_ORG
    locale = locale if locale is not None else cfg.default_locale
    payload = WpOrgApi(
        session, timeout_s, deadline=_api_deadline(deadline), config=cfg,
    )._request_json("GET", _checksums_url(version, locale, cfg), None)
    if not isinstance(payload, dict):
        return None
    raw = payload.get("checksums")
    if not isinstance(raw, dict):
        return None
    checksums = {
        path: digest
        for path, digest in raw.items()
        if isinstance(path, str) and isinstance(digest, str)
    }
    return checksums or None


def _fetch_comparison_checksums(
    version: str, session: requests.Session, timeout_s: int, locale: str,
    deadline: Deadline | None = None,
    config: WpOrgSettings | None = None,
) -> tuple[dict[str, str] | None, str]:
    """(map, effective_locale) — the locale's map with the default fallback.

    The shared fetch seam for the check AND heal-core's plan: the
    ``locale`` map first; when it is unavailable (transport failure
    with nothing cached, or an unusable/empty answer — a locale with
    no build answers ``{"checksums": false}``) ONE warning, then the
    default-locale map, and the effective locale says that fallback so the
    finding's fix text can name the basis it ACTUALLY used.  A
    requested-default failure returns (None, default-locale) — the caller's
    existing skip path; the fallback never retries the same locale.
    """
    cfg = config or DEFAULT_WP_ORG
    checksums = _fetch_checksums(
        version, session, timeout_s, locale, deadline, config=cfg)
    if checksums is not None or locale == cfg.default_locale:
        return checksums, locale
    log.warning(
        "core integrity: wp.org checksums for WP %s locale %s are "
        "unavailable — comparing against the official %s checksums",
        version, locale, cfg.default_locale,
    )
    return _fetch_checksums(
        version, session, timeout_s, cfg.default_locale, deadline,
        config=cfg), cfg.default_locale


def _sendable(path: str) -> bool:
    """True when a checksums path may be sent to the bridge's core_md5.

    The bridge refuses the WHOLE request for any path with a ``..``
    segment or one whose realpath leaves the webroot (media_delete's
    fail-closed precedent), and a leading ``"/"`` or NUL byte never
    names a webroot-relative file.  wp.org publishes only clean
    webroot-relative POSIX paths, so this is defense-in-depth around
    the map, never an expectation.
    """
    return (
        bool(path)
        and not path.startswith("/")
        and "\x00" not in path
        and ".." not in path.split("/")
    )


def _walked_files(data: AuditData) -> dict[str, Entry]:
    """The walked tree as the classification primitives' ``files`` map.

    ``{path: Entry}`` over the non-directory entries — the shape both
    AuditData-shaped wrappers hand to the primitives (heal-core builds
    the same map from its own walk).
    """
    return {entry.path: entry for entry in data.entries if not entry.is_dir}


def _junk_demanded(
    checksums: dict[str, str], junk_patterns: list[str] | tuple[str, ...]
) -> set[str]:
    """The map paths this tool's OWN junk policy DELETES [L19].

    A map path whose basename matches one of the profile's
    ``webroot_junk`` patterns is a file ``webroot.junk`` reports and
    clean-files deletes — the tool's DESIGNED behavior at the webroot
    top level (wp-config-sample.php, license.txt, readme.html, a
    ``*.sql`` dump, an ``error_log``).  Such a path must never be
    demanded back by this module or the three tools have no fixed
    point: clean-files deletes it, core.integrity reports it missing,
    heal-core restores it, and the next clean-files run deletes it
    again — forever, with an audit finding that never resolves
    (reproduced with the shipped profile: wp-config-sample.php, every
    round).

    The patterns are the profile's, never a hardcoded filename list
    (a profile that junk-matches another top-level core file is
    honored at the same instant), and the match is webroot's OWN
    predicate — imported, not reimplemented, so this module and
    ``wpt.audit.webroot`` can never drift on what "junk" means.  The
    import is deferred because webroot imports THIS module (the
    checksum-fetch seam), so a module-level import would be a cycle
    (walk.py's deferred audit import is the same precedent).
    """
    from .webroot import junk_file_matches

    if not junk_patterns:
        return set()
    return {
        entry.path
        for entry, _pattern in junk_file_matches(
            [Entry(path=path, is_dir=False, size=0) for path in checksums],
            list(junk_patterns),
        )
    }


def _missing_in_scope(path: str, junk_demanded: set[str]) -> bool:
    """A checksums path whose ABSENCE is a finding [L18] + [L19].

    ``wp-admin/`` and ``wp-includes/`` paths (the original rule) plus
    TOP-LEVEL ``.php`` map paths: those are functional core files — a
    deleted wp-cron.php silently breaks WP-Cron, a deleted
    wp-comments-post.php breaks commenting (an observed localized migration
    had five of them deleted and the old scope reported nothing).  Three
    exclusions, all of them the tool's own policy or a structural fact
    about the map, never a filename list:

    * a top-level NON-php map path (license.txt, readme.html),
    * a top-level path the junk policy DELETES (:func:`_junk_demanded`
      — wp-config-sample.php, the file [L18] itself opened the loop
      on; the exclusion is scope-shaped so the core-dir junk members
      webroot's ``core_junk_exempt`` protects from deletion still
      demand restoration), and
    * ``wp-config.php`` / ``.htaccess`` — wp.org never ships them (they
      are user files by design, the same reason the added rule exempts
      them), so a map listing one is a contract violation of an EXTERNAL
      answer; refusing it here keeps the "re-upload the missing core
      file" advice off the configuration files and keeps the heal from
      ever planning a write the guard would refuse anyway.
    """
    if path in _USER_FILES:
        return False
    if path.startswith(_WP_ADMIN) or path.startswith(_WP_INCLUDES):
        return True
    if "/" in path or not path.endswith(_PHP_SUFFIX):
        return False
    return path not in junk_demanded


def added_files(
    files: dict[str, Entry], checksums: dict[str, str]
) -> list[tuple[str, str, int]]:
    """(added, path, size) for suspicious .php additions — TREE-ONLY.

    The walked tree against the checksums map; needs no file reads, so
    it is identical in both modes and independent of the digest source
    (it also still runs after a local breaker abort).
    """
    affected: list[tuple[str, str, int]] = []
    for path, entry in files.items():
        if path in checksums or path in _USER_FILES:
            continue
        if not path.endswith(_PHP_SUFFIX):
            continue
        under_core = path.startswith(_WP_ADMIN) or path.startswith(_WP_INCLUDES)
        if under_core or "/" not in path:  # core dirs or webroot top level
            affected.append(("added", path, entry.size))
    return affected


def affected_files_local(
    source: Source,
    files: dict[str, Entry],
    checksums: dict[str, str],
    deadline: Deadline | None = None,
    *,
    junk_patterns: list[str] | tuple[str, ...],
    max_file_bytes: int | None = None,
) -> list[tuple[str, str, int]]:
    """LOCAL comparison: bulk read_many md5 batches + the breaker.

    The classification primitive (heal-core's seam): the Source, the
    walked ``files`` map, the optional run deadline and the profile's
    ``webroot_junk`` patterns come in directly — no AuditData.
    ``junk_patterns`` is a REQUIRED keyword argument, not an optional
    refinement: it is the tool's own junk policy, and a caller that
    forgot it would demand back every top-level core file clean-files
    deletes — the [L19] loop.  The tree-present checksums paths stream
    in map order through ``source.read_many`` in batches of
    _READ_MANY_BATCH; the missing map paths classify inline (the
    [L18]/[L19] scope rule) exactly where the per-file loop met them,
    so a breaker or deadline stop still returns the findings verified
    so far — never
    ones from beyond the stop point; every return carries the
    tree-only additions from :func:`added_files` as its tail.  Per
    batch: ``deadline.check("core integrity scan")`` when a deadline
    is given (None = unbounded, no check) then the bulk read.  A
    DeadlineExceeded — from the check or raised inside read_many —
    never escapes: ONE warning, then the same partial return as the
    breaker abort.  A failed-map entry is the per-file unreadable
    debug skip AND one consecutive-failure tick: 25 in a row aborts
    with the warning, an ok entry resets, the run carries across
    batch boundaries, and a trip discards the rest of the tripped
    batch's results and reads no further batch.  A path in neither
    answer map (contract drift) is a debug skip that touches nothing.
    Nothing here raises.
    """
    affected: list[tuple[str, str, int]] = []
    unreadable = 0
    junk = _junk_demanded(checksums, junk_patterns)
    # The batch stream: tree-present map paths in map order.  A missing
    # path reads nothing and leaves the counter — it classifies inline.
    present = [path for path in checksums if path in files]
    stream_pos = 0
    ok: dict[str, bytes] = {}
    failed: dict[str, str] = {}
    try:
        for path, expected in checksums.items():
            entry = files.get(path)
            if entry is None:
                # Missing follows the scope rule [L18]/[L19]: core dirs
                # plus top-level .php map paths the junk policy does not
                # delete; a missing license.txt / readme.html /
                # wp-config-sample.php is the junk policy's turf.
                if _missing_in_scope(path, junk):
                    affected.append(("missing", path, 0))
                continue
            if stream_pos % _READ_MANY_BATCH == 0:
                # One deadline check + one bulk read per batch, at the
                # batch's first path in map order.  The read is bounded by
                # the LARGEST expected size in the batch: a listing that
                # understates a core file's body is refused by the
                # connector and lands as a known per-path failure (below),
                # never materialized whole.
                if deadline is not None:
                    deadline.check("core integrity scan")
                batch_paths = present[stream_pos:stream_pos + _READ_MANY_BATCH]
                # SIZE_UNKNOWN (-1: a non-Unix FTP LIST) is not a bound.
                # When any member's size is unknown the configured
                # files.max_file_bytes (the caller's) is the fallback; a
                # known-largest cap alone would refuse every read with -1.
                sizes = [files[path].size for path in batch_paths]
                known = [size for size in sizes
                         if isinstance(size, int) and size >= 0]
                batch_cap = max(known, default=0)
                if len(known) != len(sizes) and max_file_bytes is not None:
                    batch_cap = max(batch_cap, max_file_bytes)
                ok, failed = source.read_many(
                    batch_paths, max_bytes=batch_cap
                )
            stream_pos += 1
            if path in ok:
                unreadable = 0
                if hashlib.md5(ok[path]).hexdigest() != expected:
                    affected.append(("tampered", path, entry.size))
                continue
            if path in failed:
                log.debug("core integrity: skipping unreadable core file %s: %s",
                          path, failed[path])
                unreadable += 1
                if unreadable >= _CONSECUTIVE_UNREADABLE:
                    log.warning(
                        "core integrity scan aborted after %d consecutive "
                        "unreadable files; results are partial",
                        _CONSECUTIVE_UNREADABLE,
                    )
                    return affected + added_files(files, checksums)
                continue
            log.debug("core integrity: no read_many answer for %s", path)
    except DeadlineExceeded:
        log.warning(
            "core integrity scan stopped: run deadline exceeded; "
            "results are partial"
        )
        return affected + added_files(files, checksums)
    return affected + added_files(files, checksums)


def _affected_files_local(
    data: AuditData, checksums: dict[str, str], settings: Settings
) -> list[tuple[str, str, int]]:
    """The check path over :func:`affected_files_local`: the walked
    files map + ``data.source`` + ``data.deadline`` handed to the
    primitive — a thin AuditData-shaped adapter, nothing of its own.
    ``settings`` hands over the profile's ``webroot_junk`` patterns: the
    missing scope reads the SAME junk policy the webroot check and the
    clean-files plan read, so the [L19] loop closes in the check exactly
    as it does for the two tools that delete.
    """
    return affected_files_local(
        data.source, _walked_files(data), checksums, data.deadline,
        junk_patterns=settings.webroot_junk,
        max_file_bytes=settings.files.max_file_bytes,
    )


def affected_files_bridge(
    bridge: Bridge | None,
    files: dict[str, Entry],
    checksums: dict[str, str],
    *,
    junk_patterns: list[str] | tuple[str, ...],
    deadline: float | None = None,
) -> list[tuple[str, str, int]] | None:
    """FTP comparison over the bridge's bulk core_md5 action, or None.

    The classification primitive (heal-core's seam): the Bridge (or
    None — the degrade below), the walked ``files`` map and the
    profile's ``webroot_junk`` patterns (a REQUIRED keyword argument
    with the same [L19] reason as on :func:`affected_files_local` — the
    missing scope must honor the junk policy in BOTH modes, or the two
    modes disagree about the same tree) come in directly — no
    AuditData.  All digests in one server-side call per
    at most _CORE_MD5_BATCH paths.  None — after exactly ONE skip
    warning — on every data/site failure shape: ``bridge`` is None, a
    raised error (the client funnels transport, protocol and
    ``{"ok": false}`` envelope failures into BridgeError; any other
    non-stop error is still never a crash mid-scan), or a malformed
    payload.  ``StopRequested``/``DeadlineExceeded`` re-raise: a
    cooperative stop is not a skip.  Unlike
    ``_fetch_checksums`` (whose caller logs), this primitive logs its
    own warning so the one line can carry the failure reason; the
    caller then degrades to ``[]`` exactly like a checksums fetch
    failure.
    """
    if bridge is None:
        log.warning("core integrity skipped: core_md5 unavailable "
                    "(probe carries no bridge)")
        return None
    junk = _junk_demanded(checksums, junk_patterns)
    paths = [path for path in checksums if _sendable(path)]
    if len(paths) < len(checksums):
        log.debug("core integrity: %d checksums paths not sendable to "
                  "core_md5 (dropped)", len(checksums) - len(paths))
    affected: list[tuple[str, str, int]] = []
    for start in range(0, len(paths), _CORE_MD5_BATCH):
        batch = paths[start:start + _CORE_MD5_BATCH]
        try:
            # ``deadline`` is already the ABSOLUTE instant (both callers
            # pass ``Deadline.at``); hand it straight to the bridge.  Passing
            # it through transport_kwargs read ``.at`` on a float and refused
            # every heal/audit classification after a bounded run.
            payload = bridge.call(
                "core_md5", paths=batch,
                **({"deadline": deadline} if deadline is not None else {}))
        except (StopRequested, DeadlineExceeded):
            raise
        except Exception as exc:
            log.warning("core integrity skipped: core_md5 unavailable (%s)",
                        exc)
            return None
        if not isinstance(payload, dict):
            log.warning("core integrity skipped: core_md5 unavailable "
                        "(malformed core_md5 payload)")
            return None
        got_files = payload.get("files")
        missing = payload.get("missing")
        unreadable = payload.get("unreadable")
        if (not isinstance(got_files, dict)
                or not isinstance(missing, list)
                or not isinstance(unreadable, list)):
            log.warning("core integrity skipped: core_md5 unavailable "
                        "(malformed core_md5 payload)")
            return None
        missing_set = {p for p in missing if isinstance(p, str)}
        unreadable_set = {p for p in unreadable if isinstance(p, str)}
        for path in batch:
            expected = checksums[path]
            if path in got_files:
                digest = got_files[path]
                if digest is None or path in unreadable_set:
                    log.debug("core integrity: skipping unreadable core "
                              "file %s", path)
                    continue
                if not isinstance(digest, str):
                    log.debug("core integrity: skipping core file %s with a "
                              "malformed digest", path)
                    continue
                if digest != expected:
                    # The server-side digest is the evidence; the size is
                    # the walked entry's, 0 when the tree never saw it.
                    entry = files.get(path)
                    affected.append(("tampered", path,
                                     entry.size if entry is not None else 0))
            elif path in missing_set:
                # The same scope rule as the local path [L18]/[L19].
                if _missing_in_scope(path, junk):
                    affected.append(("missing", path, 0))
            elif path in unreadable_set:
                log.debug("core integrity: skipping unreadable core file %s",
                          path)
            else:
                log.debug("core integrity: no core_md5 answer for %s", path)
    return affected + added_files(files, checksums)


def _affected_files_bridge(
    data: AuditData, checksums: dict[str, str], settings: Settings
) -> list[tuple[str, str, int]] | None:
    """The check path over :func:`affected_files_bridge`: the walked
    files map + the probe's bridge (None without a probe) handed to the
    primitive — a thin AuditData-shaped adapter, nothing of its
    own.  ``settings`` hands over the same profile ``webroot_junk``
    patterns the local wrapper reads, so the two MODES can never
    disagree about which missing core files the junk policy owns.
    """
    bridge = data.probe.bridge if data.probe is not None else None
    return affected_files_bridge(
        bridge, _walked_files(data), checksums,
        junk_patterns=settings.webroot_junk,
        deadline=data.deadline.at if data.deadline is not None else None,
    )


# --------------------------------------------- default-theme skew [L12]


def _theme_slug(path: str) -> str | None:
    """The slug of a wp-content/themes/<slug>/... path; None otherwise."""
    parts = path.split("/")
    if len(parts) > 3 and parts[:2] == ["wp-content", "themes"] and parts[2]:
        return parts[2]
    return None


def _zip_md5_map(
    zip_bytes: bytes, prefix: str
) -> tuple[dict[str, str], int] | None:
    """``({zip inner name: md5hex}, largest entry size)``, or None.

    Directory entries are skipped.  A zip zipfile cannot open (torn,
    corrupt) is a failed cross-check basis, never a raise and never a
    guessed empty map.  The largest entry is the read bound the EXACT
    official bytes themselves prove: it is data, not a hard-coded cap.
    """
    out: dict[str, str] = {}
    largest = 0
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            for info in zf.infolist():
                if info.filename.startswith(prefix) and not info.is_dir():
                    out[info.filename] = hashlib.md5(
                        zf.read(info)).hexdigest()
                    largest = max(largest, info.file_size)
    except (OSError, ValueError, EOFError, RuntimeError, zipfile.BadZipFile):
        return None
    return (out, largest) if out else None


def resolve_theme_skew(
    affected: list[tuple[str, str, int]],
    source: Source | None,
    session: requests.Session,
    timeout_s: int,
    deadline: Deadline | None = None,
    *,
    max_file_bytes: int | None = None,
    config: WpOrgSettings | None = None,
) -> list[tuple[str, str, int]]:
    """Drop tampered default-theme paths that match the OFFICIAL theme
    release of the site's installed version [L12] — the post-pass the
    check AND heal-core run after the classification primitives.

    Every ``tampered`` path under wp-content/themes/<slug>/ is grouped
    by slug; per slug, the version comes from the site's own style.css
    header (``_theme_versions`` through ``source``) and the official
    theme release zip from ``WpOrgApi.fetch_theme_zip`` (the same
    validated, 1h-cached wp.org transport as the core release zip).  A
    path whose on-disk md5 (one small ``source.read_many`` over the
    whole slug's candidates) equals the zip entry's is a pristine
    auto-update past the core-bundled copy: DROPPED from the return
    with one info line — and, for heal-core, never "healed" back into
    the bundled version (which would DOWNGRADE the theme).

    Conservative on EVERY failure shape — the tampered classification
    survives: no source, no theme candidates, an unreadable style.css
    (unknown version), an invalid-looking slug/version (validated
    before the fetch; fetch_theme_zip would raise), an unavailable or
    unparseable zip, an unreadable candidate path, or a digest that
    still differs.  One warning per slug names the unresolved count;
    a genuinely tampered theme file (differs from its own declared
    version's release) stays silently — the finding covers it.  Never
    raises for data/site failures; ``StopRequested``/``DeadlineExceeded``
    re-raise so a cooperative stop or expired budget is never disguised as
    a resolved skew.
    """
    if source is None:
        return affected
    by_slug: dict[str, list[tuple[str, int]]] = {}
    kept: list[tuple[str, str, int]] = []
    for kind, path, size in affected:
        slug = _theme_slug(path) if kind == "tampered" else None
        if slug is None:
            kept.append((kind, path, size))
        else:
            by_slug.setdefault(slug, []).append((path, size))
    if not by_slug:
        return affected

    resolved: list[str] = []
    for slug in sorted(by_slug):
        paths = [path for path, _size in by_slug[slug]]
        try:
            version = _theme_versions(source, {slug}).get(slug)
        except (StopRequested, DeadlineExceeded):
            raise
        except Exception:
            # _theme_versions catches SourceError itself; anything else
            # (a raw OSError from an exotic source) is an unknown
            # version, never a raise out of the never-raise pass.
            version = None
        digests: dict[str, str] | None = None
        official_largest = 0
        if (version is not None
                and WP_THEME_SLUG_RE.fullmatch(slug)
                and WP_RELEASE_VERSION_RE.fullmatch(version)):
            zip_bytes = WpOrgApi(
                session, timeout_s, deadline=_api_deadline(deadline),
                config=config or DEFAULT_WP_ORG,
            ).fetch_theme_zip(slug, version)
            if zip_bytes is not None:
                mapped = _zip_md5_map(zip_bytes, f"{slug}/")
                if mapped is not None:
                    digests, official_largest = mapped
        if digests is None:
            log.warning(
                "core integrity: cannot cross-check %d default-theme "
                "file(s) under wp-content/themes/%s/ against the "
                "official theme release (unknown version or "
                "unavailable zip); they stay classified tampered",
                len(paths), slug,
            )
            kept.extend(
                ("tampered", path, size) for path, size in by_slug[slug]
            )
            continue
        # SIZE_UNKNOWN (-1, a non-Unix FTP LIST) must never become a
        # bound: read_many would refuse every path and a pristine theme
        # auto-update stayed a HIGH tampered finding (and heal-core then
        # planned the DOWNGRADE it exists to prevent).  The exact official
        # zip's largest entry is data-driven; the configured
        # files.max_file_bytes is the fallback for an unknown listing size.
        sizes = [size for _path, size in by_slug[slug]]
        known = [size for size in sizes
                 if isinstance(size, int) and size >= 0]
        cap = max(known, default=0)
        cap = max(cap, official_largest)
        if len(known) != len(sizes) and max_file_bytes is not None:
            cap = max(cap, max_file_bytes)
        try:
            ok, failed = source.read_many(paths, max_bytes=cap)
        except (StopRequested, DeadlineExceeded):
            raise
        except Exception as exc:
            log.warning(
                "core integrity: reading %d default-theme file(s) under "
                "wp-content/themes/%s/ failed (%s); they stay classified "
                "tampered", len(paths), slug, exc,
            )
            ok, failed = {}, {}
        if failed:
            log.warning(
                "core integrity: %d default-theme file(s) under "
                "wp-content/themes/%s/ could not be read within the "
                "%d-byte bound; they stay classified tampered",
                len(failed), slug, cap)
        for path, size in by_slug[slug]:
            blob = ok.get(path)
            # path already carries the slug past the themes prefix:
            # "wp-content/themes/<slug>/x" -> zip inner name "<slug>/x"
            inner = path[len(_THEMES_PREFIX):]
            if (blob is not None
                    and digests.get(inner) == hashlib.md5(blob).hexdigest()):
                resolved.append(path)
            else:
                kept.append(("tampered", path, size))
    if resolved:
        log.info(
            "core integrity: %d default-theme file(s) match the "
            "official theme release of the installed version — a theme "
            "auto-update past the core-bundled copy, not tampering: %s",
            len(resolved), ", ".join(sorted(resolved)),
        )
    return kept


# ------------------------------------------ translation-pack skew [L19]


def _is_translation_catalog(path: str) -> bool:
    """True for a runtime translation catalog under wp-content/languages/.

    The four formats WordPress's translation machinery owns and reloads
    (see the module docstring).  Narrow by construction: any OTHER file
    type planted in that directory (a .php payload, a stray archive)
    does not match and keeps the tampered classification.
    """
    return (path.startswith(_LANGUAGES_PREFIX)
            and path.endswith(_TRANSLATION_SUFFIXES))


def resolve_translation_pack_skew(
    affected: list[tuple[str, str, int]],
) -> list[tuple[str, str, int]]:
    """Drop tampered translation-catalog paths [L19] — the second
    post-classification pass, run by the check AND heal-core.

    A LOCALIZED build's checksum map bundles its own
    ``wp-content/languages/`` catalog set (live-verified 7.1 fr_CA: 88
    entries — 8 ``.po`` + 8 ``.mo`` + 4 ``.l10n.php`` + 68 script
    ``<locale>-<md5>.json`` translations; 226 paths more than the en_US
    map of the same version), and WordPress replaces those catalogs from
    the wp.org TRANSLATION PACK, so an up-to-date site can differ from
    the bundled bytes without any tampering (the pack is a live artifact
    translated independently of the core build).  Unlike a default theme
    (which :func:`resolve_theme_skew` can cross-check against the
    official theme release) a catalog cannot be cross-checked: the
    runtime formats are generated and repacked by the translation system,
    and 8 of them are this toolkit's OWN ``webroot.junk_recurring``
    delete candidates — so "healing" them would restore the BUNDLED
    translations and DOWNGRADE the site's language, the exact
    [L12]-for-translations failure.

    Every ``tampered`` path under ``wp-content/languages/`` with one of
    the four runtime suffixes is therefore dropped with ONE info line
    naming them.  Nothing else is touched: a ``missing`` entry (never in
    scope — wp-content is out of the missing rule), a non-catalog file
    type, and every other kind keep their classification.  Pure and
    offline (no source, no session, no wp.org traffic): there is no
    evidence to fetch, and the one evidence-free case — the four formats
    WordPress itself owns — is exactly what the exemption is scoped to.
    """
    kept: list[tuple[str, str, int]] = []
    resolved: list[str] = []
    for kind, path, size in affected:
        if kind == "tampered" and _is_translation_catalog(path):
            resolved.append(path)
        else:
            kept.append((kind, path, size))
    if resolved:
        log.info(
            "core integrity: %d translation catalog file(s) under "
            "wp-content/languages/ differ from the bytes bundled with the "
            "core build — translation packs are replaced on demand by "
            "wp.org, so this is not tampering: %s",
            len(resolved), ", ".join(sorted(resolved)),
        )
    return kept


# ------------------------------------------ known added artifacts [L16]


def _split_known_added(
    affected: list[tuple[str, str, int]],
    source: Source | None,
    settings: Settings,
) -> tuple[list[tuple[str, str, int, str]], list[tuple[str, str, int]]]:
    """(known, remaining) over the ``added`` entries [L16].

    ``known`` entries carry the signature's note as a fourth tuple
    element.  A candidate qualifies ONLY on every gate: an exact
    TOP-LEVEL path match with a known_added signature (malformed
    profile entries are skipped with one error — a bad ``--set`` must
    not crash the check), a walked size within the signature's
    max_bytes, a readable content blob within max_bytes carrying the
    signature's marker, and NO suspicious-patterns match anywhere in
    its lines (the same high-precision malware signatures the
    security.suspicious scan uses — a planted lookalike with a
    backdoor inside stays high).  Everything else — wrong name,
    oversized, marker absent, malware hit, unreadable, no source —
    stays in ``remaining`` with the high classification.  Never raises for
    data/site failures; ``StopRequested``/``DeadlineExceeded`` re-raise so a
    cooperative stop or expired budget is never disguised as a partial scan.
    """
    remaining = list(affected)
    if source is None:
        return [], remaining
    signatures: list[dict] = []
    for index, sig in enumerate(settings.core_integrity.known_added):
        if (isinstance(sig, dict)
                and isinstance(sig.get("name"), str) and sig["name"]
                and "/" not in sig["name"]
                and isinstance(sig.get("marker"), str) and sig["marker"]
                and isinstance(sig.get("max_bytes"), int)
                and not isinstance(sig.get("max_bytes"), bool)
                and isinstance(sig.get("note"), str)):
            signatures.append(sig)
        else:
            log.error(
                "core integrity: known_added signature %d is malformed, "
                "skipped", index,
            )
    if not signatures:
        return [], remaining
    by_name = {sig["name"]: sig for sig in signatures}
    candidates: dict[str, tuple[int, dict]] = {}
    for kind, path, size in affected:
        if kind == "added" and path in by_name and 0 <= size <= by_name[path]["max_bytes"]:
            candidates[path] = (size, by_name[path])
    if not candidates:
        return [], remaining
    try:
        ok, _failed = source.read_many(
            list(candidates),
            max_bytes=max((sig["max_bytes"]
                           for _size, sig in candidates.values()), default=0))
    except (StopRequested, DeadlineExceeded):
        raise
    except Exception as exc:
        log.warning(
            "core integrity: reading %d added file(s) for the known-artifact "
            "check failed (%s); they stay classified added", len(candidates), exc,
        )
        return [], remaining
    patterns = _compile_patterns(settings.suspicious.patterns)
    known: list[tuple[str, str, int, str]] = []
    resolved_paths: set[str] = set()
    for path, (size, sig) in candidates.items():
        blob = ok.get(path)
        if blob is None or len(blob) > sig["max_bytes"]:
            continue
        text = blob.decode("utf-8", errors="replace")
        if sig["marker"] not in text:
            continue
        # The SAME PHP-aware scan the suspicious check uses, so a signature
        # split across lines (or by a comment) cannot be downgraded to a
        # low-risk "known artifact" by a per-line regex.
        if _scan_text(text, patterns):
            continue
        known.append(("added", path, size, sig["note"]))
        resolved_paths.add(path)
    remaining = [entry for entry in remaining
                 if not (entry[0] == "added" and entry[1] in resolved_paths)]
    if known:
        log.info(
            "core integrity: %d added file(s) match a known plugin "
            "artifact signature — reported as the low-risk added-known "
            "finding: %s",
            len(known), ", ".join(sorted(entry[1] for entry in known)),
        )
    return known, remaining


def _detail_lines(items: list[str]) -> str:
    """Up to _DETAIL_PATHS newline-joined lines; "(+N more)" if truncated."""
    if len(items) <= _DETAIL_PATHS:
        return "\n".join(items)
    return "\n".join(items[:_DETAIL_PATHS]) + f"\n(+{len(items) - _DETAIL_PATHS} more)"


@register_check("core.integrity", applies=("ftp", "local"))
def check_core_integrity(data: AuditData, settings: Settings) -> list[Finding]:
    """Verify WP core files against wp.org's official checksums.

    Unknown version → silent; unavailable checksums, or (ftp) an
    unavailable core_md5 → silent after one warning; a clean core →
    silent.  The comparison is keyed to the core BUILD locale
    (:func:`resolve_core_locale` over the version.php marker read
    through the source — the ONE per-file read ftp mode ever makes —
    and ``data.locale``, which in ftp mode is the bridge ``info``'s
    ``get_locale()`` and locally the analyzer's WPLANG; the locale's
    map, with the ONE-warning en_US fallback when it is unavailable)
    — the localized-migration lesson
    [L17].  Otherwise ONE grouped finding covering every tampered,
    added and missing core file (see the module docstring for the
    mode-split digest sources, the per-kind semantics, the
    deterministic ordering, the BASIS CLAUSE that names the comparison
    map in the detail, the locale-aware fix composition and the
    local consecutive-failure abort), plus — when they exist — the
    separate low-risk "added-known" finding for added files matching a
    known plugin-artifact signature [L16].  Default-theme tampered
    paths matching the official theme release of the installed version
    are reclassified by :func:`resolve_theme_skew` BEFORE the findings
    are built [L12].  Per-file failures are debug skips, fetch/bulk
    failures are the one-warning skip, and the local batched read loop
    aborts partial after 25 consecutive unreadable files.  A run-deadline
    expiry in that loop stops the scan partial the same way (the verified
    findings return with the one warning).  ``StopRequested`` and
    ``DeadlineExceeded`` raised by the post-scan theme-skew or
    known-artifact reads DO re-raise: a cooperative stop or an expired
    budget must end the command through its shared failure report, never
    look like a completed scan.
    """
    if not data.wp_version:
        log.debug("core integrity skipped: WP core version unknown")
        return []
    locale = resolve_core_locale(
        data.source, data.locale, settings.wp_org.default_locale)
    session, timeout_s = _transport(data, settings)
    with owned_session(session, data.probe is None):
        checksums, effective_locale = _fetch_comparison_checksums(
            data.wp_version, session, timeout_s, locale, data.deadline,
            config=settings.wp_org,
        )
        if checksums is None:
            log.warning("core integrity skipped: checksums unavailable")
            return []
        if data.mode == "ftp":
            affected = _affected_files_bridge(data, checksums, settings)
            if affected is None:
                return []  # the helper already logged its one skip warning
        else:
            affected = _affected_files_local(data, checksums, settings)
        # [L12] pristine official theme auto-updates are not tampering —
        # and heal-core (the same pass) must not "heal" them back into the
        # bundled version.
        affected = resolve_theme_skew(
            affected, data.source, session, timeout_s, data.deadline,
            max_file_bytes=settings.files.max_file_bytes,
            config=settings.wp_org)
    # [L19] translation catalogs are repacked on demand by wp.org — a
    # pristine updated language pack is not tampering either.
    affected = resolve_translation_pack_skew(affected)
    # [L16] known plugin-deployed bootstraps are reported separately,
    # never as high-risk compromise evidence.
    known, affected = _split_known_added(affected, data.source, settings)
    if not affected and not known:
        return []
    findings: list[Finding] = []
    if affected:
        affected.sort(key=lambda item: (_KIND_ORDER[item[0]], item[1]))
        tampered = sum(1 for kind, _p, _s in affected if kind == "tampered")
        added = sum(1 for kind, _p, _s in affected if kind == "added")
        missing = sum(1 for kind, _p, _s in affected if kind == "missing")
        log.info(
            "core integrity: %d tampered, %d added, %d missing core files "
            "(against the official %s %s checksums)",
            tampered, added, missing, effective_locale, data.wp_version,
        )
        # Risk + fix composition: tampered/added are compromise evidence
        # (high); a missing-only finding is an incomplete core (medium).
        # The fix names the DISTRIBUTION the evidence is keyed to —
        # version + the comparison locale actually used.
        version = data.wp_version
        if tampered or added:
            risk = "high"
            fix = _restore_fix(version, effective_locale, locale,
                               added=bool(added))
            if missing:
                fix = f"{fix} {_missing_fix(version, effective_locale, locale)}"
        else:
            risk = "medium"
            fix = _missing_fix(version, effective_locale, locale)
        findings.append(
            Finding(
                category="core.integrity",
                name="core-files",
                detail=(
                    _basis_clause(effective_locale, version) + "\n"
                    + _detail_lines(
                        [f"{kind}: {path}" for kind, path, _s in affected]
                    )
                ),
                bytes=sum(size for _k, _p, size in affected),
                count=len(affected),
                risk=risk,
                fix=fix,
            )
        )
    if known:
        known.sort(key=lambda item: item[1])
        findings.append(
            Finding(
                category="core.integrity",
                name="added-known",
                detail=_detail_lines(
                    [f"added (known): {path} — {note}"
                     for _kind, path, _s, note in known]
                ),
                bytes=sum(size for _k, _p, size, _n in known),
                count=len(known),
                risk="low",
                fix=_KNOWN_ADDED_FIX,
            )
        )
    return findings
