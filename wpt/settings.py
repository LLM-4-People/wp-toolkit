"""Settings: every tunable in wpt flows from wpt/data/profiles/default.json.

No module reads environment variables or hardcodes numbers; they receive a Settings
object via Ctx. Overrides arrive as dot-paths ("media_optimize.jpeg_quality=75").
"""

import json
import math
from dataclasses import asdict, dataclass, field, fields, replace
import re
from pathlib import Path
from typing import Any

from .jsonutil import loads_bounded
from .ports import PORT_MAX, PORT_MIN_BINDABLE
from .types import Source, WptError

_DEFAULT_PROFILE = Path(__file__).resolve().parent / "data" / "profiles" / "default.json"


class SettingsError(WptError):
    """Invalid profile content or override."""


# ---------------------------------------------------------------------------
# The ``webroot_junk`` GROUPED-pattern grammar
#
# This is the PROFILE DOOR, so it sits here with the other shape validators
# rather than in the audit module that reads the patterns: the two
# properties a grouped pattern must have are properties of the SHAPE, and
# the shape is what a profile file and a ``--set`` both hand us.
#
# Two families, different in kind (wpt.audit.webroot's module docstring is
# the prose): a BARE pattern (``error_log``, ``*.sql``) names a file whose
# NAME is the problem and is matched on the basename at any depth, while a
# GROUPED pattern (``<group>:<glob>``) names the source host's control
# files, which are junk because of WHERE they are, and is matched on the
# webroot-relative PATH so it can only fire at the webroot ROOT.
#
# THE DOOR: a group glob must be a webroot-ROOT FILENAME it can honestly
# own.  Three shape rules, one per way a group could claim a file that is
# not the SOURCE HOST's:
#
# 1. It may not be a GLOB.  ``fnmatch``'s ``*`` crosses ``/``, so
#    ``host_placeholder_page:*.php`` reached WordPress's own top-level core
#    files (wp-login.php, wp-cron.php, xmlrpc.php, …) and rendered them at
#    the group's HIGH risk with the group's "no site content is lost —
#    delete it" fix; the core-junk exemption only covers
#    ``wp-admin/``/``wp-includes/``, so 7 of those files were PLANNED for
#    deletion.  ``*.html`` reached a theme's ``home.html`` and a plugin's
#    authored ``index.html`` — the exact files the root-scoping was
#    designed to make unreachable.  Only the CLASSIFICATION lists may be
#    globbed (which files the group NAMES).
# 2. It may not name a path wpt must NEVER delete
#    (:attr:`wpt.types.Source.PROTECTED_FOLDED`) — the write-guard's own
#    refuse list, which
#    ``.htaccess`` (the live access config, which the harden action owns),
#    ``index.php``, ``wp-config.php``, ``wp-admin`` and ``wp-includes``
#    are members of.
# 3. It may not be a ``.php`` file (:data:`_JUNK_ROOT_EXECUTABLE`).  The
#    metacharacter rule closed the GLOB, not the LITERAL: a profile
#    spelling one file out — ``host_placeholder_page:wp-cron.php`` — walked
#    straight past it, minted the same HIGH finding over one of
#    WordPress's own top-level core files, and the clean-files plan deleted
#    it (the write-guard does not refuse it: it is not in
#    :attr:`wpt.types.Source.PROTECTED_FOLDED`).  The rule is the SUFFIX, not a filename list,
#    and that is the whole point: at a WordPress webroot ROOT a ``.php``
#    file IS the core's executable surface (the loader resolves index.php;
#    every entry point — wp-cron.php, xmlrpc.php, wp-signup.php, … — is
#    one), so no list of names could keep up with the next core release.
#    ``wpt/audit/integrity.py`` states the same structural fact from the
#    other side: a top-level ``.php`` is core-shaped, never a host's.
#
# A BARE pattern is untouched by all three: basename-matching at any depth is
# its documented behavior, and a bare ``wp-cron.php`` or ``.htaccess`` is the
# operator's own explicit naming — unchanged here, refused where it deletes
# (Source._check_deletable) and reported where it does not.
# ---------------------------------------------------------------------------

#: The separator a GROUPED ``webroot_junk`` pattern uses: ``<group>:<glob>``.
JUNK_GROUP_SEPARATOR = ":"

#: The fnmatch metacharacters.  Any one of them in a group's glob can match
#: a character a webroot-ROOT FILENAME cannot contain, or reach across a
#: ``/`` — which is the whole invariant this door exists to hold.
_JUNK_GLOB_META = "*/?[]"

#: The paths a GROUPED pattern may not name at all, named by the ONE owner
#: of "wpt must never delete this": ``Source.PROTECTED`` (wpt/types.py), the
#: set ``Source._check_deletable`` raises on and the clean-files plan
#: excludes in one warning.  IMPORTED, never copied: a second list of
#: protected paths is a list that drifts, and the whole safety of both
#: consumers is that they read the guard's own set.  The door compares its
#: casefolded membership set, the same fold the delete guard uses.
_NEVER_DELETED = Source.PROTECTED

#: The suffix that makes a webroot-ROOT file WordPress's own EXECUTABLE
#: surface rather than a host control file — see rule 3 in the section
#: comment above.  Structural WordPress fact (a loader resolves index.php;
#: every top-level core entry point is a ``.php``), not a policy an operator
#: relaxes and not a list of core filenames to keep in step with releases.
_JUNK_ROOT_EXECUTABLE = ".php"

#: The shipped junk GROUP names — the ones wpt.audit.webroot has risk/WHY/
#: fix wording for, so a pattern naming one of them renders THAT group's
#: verdict.  The NAMES are this module's because the door asks "is this a
#: known group?" before it may refuse its glob; the WORDING is the audit
#: module's, and ``tests/audit/test_webroot.py`` pins the two views to each
#: other so a group can never be added to one and not the other.  (The same
#: arrangement ``WEB_SCRIPT_*`` below uses.)  A name absent here is not an
#: error: the pattern degrades to the bare shape, so a profile can never
#: reference a risk that does not exist.
JUNK_GROUP_NAMES: frozenset[str] = frozenset({
    "host_placeholder_page",   # HIGH: a host's "coming soon"/404/test page
    "host_account_quota",      # MEDIUM: the account's real FTP quota numbers
    "superseded_htaccess",     # MEDIUM: a pre-hardening copy of the config
})

#: The ``update.driver`` values — the ONE owner of the accepted set, read by
#: :meth:`UpdateSettings.__post_init__` (the load/override door) and by
#: ``wpt.actions.update_core`` (which names a driver's driver in the plan).
#: ``auto`` is the shipped default and means "ask the site, then choose"; the
#: other two name a driver outright, so a host whose filesystem core cannot
#: write is still updatable through the tool's own swap.
UPDATE_DRIVERS: frozenset[str] = frozenset({"auto", "swap", "wordpress"})

#: WordPress version/locale/slug shapes used by the wp.org URL resolver and
#: the settings validator.  These are protocol invariants, not tunables:
#: values that interpolate into a URL or a cache filename must match them.
WP_LOCALE_RE = re.compile(r"[A-Za-z0-9_]+")
WP_RELEASE_VERSION_RE = re.compile(r"[A-Za-z0-9.\-]+")
WP_THEME_SLUG_RE = re.compile(r"[A-Za-z0-9_\-]+")


def junk_pattern_parts(pattern: str) -> tuple[str | None, str]:
    """``(group, glob)`` for one ``webroot_junk`` pattern — THE SPLIT.

    ``(None, pattern)`` for a BARE pattern; ``(group, glob)`` for a
    ``<group>:<glob>`` pattern.  Only the FIRST colon splits (a
    colon-bearing filename still matches), and a left side that is empty or
    carries a glob metacharacter is not a group reference at all, so the
    pattern stays bare: a profile cannot turn a working pattern into a
    group by accident.  :func:`_load_webroot_junk` validates the RESULT at
    the door; this is only the grammar, shared by the door and by
    ``wpt.audit.webroot.split_junk_pattern`` so the two can never disagree
    about what a pattern is.
    """
    group, sep, glob = pattern.partition(JUNK_GROUP_SEPARATOR)
    if not sep or not group or not glob:
        return None, pattern
    if any(char in group for char in _JUNK_GLOB_META):
        return None, pattern
    if group not in JUNK_GROUP_NAMES:
        # An UNKNOWN group is not a group reference: it degrades to the
        # bare shape, matched on the basename and reported under its own
        # text.  Returning it as a group made a typo or case variant
        # (``HOST_PLACEHOLDER_PAGE:*.php``) path-match core/plugin PHP and
        # plan its deletion (R6-02).
        return None, pattern
    return group, glob


def _load_webroot_junk(key: str, raw: Any) -> list[str]:
    """The ``webroot_junk`` door: a list of patterns, each one well shaped.

    Shared by the profile loader and the ``--set`` path (``apply_override``
    validates a list value through this one function), so a hostile glob can
    arrive from neither.  A grouped pattern naming a group this tool has
    wording for must name a webroot-ROOT FILENAME the group can honestly
    own — see the section comment above for the two deletions that keeps
    out, and for the bare pattern this leaves exactly as it was.
    """
    patterns = _load_str_list(key, raw)
    for index, pattern in enumerate(patterns):
        group, glob = junk_pattern_parts(pattern)
        if group not in JUNK_GROUP_NAMES:
            continue
        if any(char in glob for char in _JUNK_GLOB_META):
            raise SettingsError(
                f"{key}[{index}]: the {group!r} group names the SOURCE HOST's "
                f"control files, which live at the webroot ROOT, so its glob "
                f"may not contain {sorted(_JUNK_GLOB_META)} (got {glob!r}) — "
                f"fnmatch's '*' crosses '/', so a globbed group would report "
                f"WordPress's own top-level core files at that group's risk "
                f"and plan them for deletion, and a theme's home.html or a "
                f"plugin's index.html would stop being unreachable. List the "
                f"root filenames the group covers, one pattern each (a BARE "
                f"pattern is still basename-matched at any depth)"
            )
        folded_glob = glob.casefold()
        if folded_glob in Source.PROTECTED_FOLDED:
            raise SettingsError(
                f"{key}[{index}]: the {group!r} group may not name {glob!r} — "
                f"it is a path wpt must never delete (the write-guard's own "
                f"refuse list, which the clean-files plan excludes too), and a "
                f"group reports its members at the group's risk with a fix "
                f"that says no site content is lost. The live .htaccess "
                f"belongs to the harden action; wp-config.php holds the "
                f"credentials and index.php renders the site. Name the host's "
                f"OWN files instead (superseded_htaccess:.htaccess.old)"
            )
        if folded_glob.endswith(_JUNK_ROOT_EXECUTABLE):
            raise SettingsError(
                f"{key}[{index}]: the {group!r} group may not name {glob!r} — "
                f"a .php file at a WordPress webroot ROOT is core's own "
                f"executable surface (the loader resolves index.php, and "
                f"wp-cron.php / xmlrpc.php / wp-signup.php are entry points "
                f"beside it), never a host control file, so a group naming "
                f"one would report it at the group's risk with a fix saying "
                f"no site content is lost, and the plan would delete a file "
                f"the write-guard does not refuse. If you really mean one "
                f"exact name, write it as a BARE pattern: that keeps its own "
                f"text-derived risk and its own wording"
            )
    return patterns


@dataclass
class FtpSettings:
    port: int = 21
    timeout_s: int = 45
    retries: int = 1
    #: Verify the FTPS server certificate and hostname.  The bare stdlib
    #: ``FTP_TLS()`` used CERT_NONE, so any MITM could capture the FTP
    #: password; verification is ON by default.  ``false`` is the explicit
    #: pre-migration opt-out and logs a loud warning on every connect.
    verify_tls: bool = True
    #: Optional CA bundle for a private/self-signed certificate.  Requires
    #: verification to remain enabled (an unverified context ignores it).
    ca_file: str = ""
    #: The source-level consecutive-failure breaker: after this many
    #: consecutive failed ops the session raises FtpChannelUnhealthy
    #: instead of grinding (live lesson: stale passive channels leave
    #: data connects in SYN-SENT for the full timeout; 5 x 2 x 45s
    #: bounds a dead channel to minutes, not hours).
    max_consecutive_failures: int = 5
    #: Bulk-read parallelism (Source.read_many): how many dedicated FTP
    #: sessions read concurrently. 1 = serial. A passive channel that
    #: stalls ~45s/op serially still moves at N x pace with N workers
    #: (live-measured on a degraded host: ~1 op/30s serial).
    parallel_reads: int = 4

    def __post_init__(self) -> None:
        # semantic validation at the owner: the pool constructs from this
        # value, and an out-of-range profile must fail through the
        # standard error contract (SettingsError), not as a raw
        # ValueError out of ThreadPoolExecutor at bulk-read time.
        if self.parallel_reads < 1:
            raise SettingsError(
                f"ftp.parallel_reads: expected >= 1, got {self.parallel_reads}"
            )
        if not isinstance(self.verify_tls, bool):
            raise SettingsError(
                f"ftp.verify_tls: expected bool, got "
                f"{type(self.verify_tls).__name__}")
        if not isinstance(self.ca_file, str):
            raise SettingsError(
                f"ftp.ca_file: expected str, got "
                f"{type(self.ca_file).__name__}")
        if self.ca_file and not self.verify_tls:
            raise SettingsError(
                "ftp.ca_file: requires ftp.verify_tls=true (an unverified "
                "context ignores the CA bundle)")
        # A port outside 1-65535 is refused by the socket layer with a raw
        # ValueError (neither WptError nor OSError) long after the load
        # door; a negative timeout/retry count turns the transport's own
        # bounds into nonsense or an immediate failure.
        for name, low, high in (
                ("port", PORT_MIN_BINDABLE, PORT_MAX),
                ("timeout_s", 1, None),
                ("retries", 0, None),
                ("max_consecutive_failures", 1, None)):
            value = getattr(self, name)
            if (isinstance(value, bool) or not isinstance(value, int)
                    or value < low or (high is not None and value > high)):
                bound = f">= {low}" if high is None else f"{low}-{high}"
                raise SettingsError(
                    f"ftp.{name}: expected an integer {bound}, got {value!r}"
                )


@dataclass
class BridgeSettings:
    ttl_minutes: int = 15
    name_retries: int = 3
    timeout_s: int = 30
    #: The row count at which the ``media_rewrite_refs`` READ mode (the
    #: webp-media rewrite's reference scan) truncates — the OPERATOR LEVER
    #: for a site that really does carry more image-bearing rows than the
    #: bridge's own default (bridge.php's ``WPT_MEDIA_REWRITE_SCAN_CAP``,
    #: 100000).  The shipped value equals that default, so a default run
    #: is byte-identical to one that never mentioned a cap; raising it is
    #: what makes an oversized site measurable instead of permanently
    #: unmeasurable.
    #:
    #: 0 = ASK FOR NOTHING, and the op applies its own default.  That is
    #: the honest way to spell "the bridge's own bound", because the
    #: default is the BRIDGE's constant (mirrored, never owned, by
    #: ``wpt.wpbridge.client.REWRITE_REF_SCAN_CAP``) and restating the
    #: number here would put a third copy of it in the tree — the mirror
    #: failure the media extension family already documents.
    #:
    #: Deliberately NOT bounded here by the op's ceiling: a value above it
    #: is passed through as asked, the op CLAMPS to the ceiling and says
    #: so on its answer, and the client turns that into a WARNING.  A
    #: cap the caller believes in and the server did not honour is
    #: exactly what that warning exists to make visible, so refusing it
    #: at load time would replace a visible clamp with a silent one.
    scan_cap: int = 0
    #: The largest NON-STREAM bridge answer body the client will hold:
    #: one read bound for both the deadline and no-deadline transports.
    #: A live official-checksums answer for a 4,008-path core map is
    #: 339,095 bytes, so 16 MiB leaves a wide margin over every real
    #: ``info``/``core_md5``/``media_map`` answer while refusing a runaway
    #: body before it can exhaust the operator's memory.  ``db_dump`` is
    #: NDJSON and streams line-by-line under ``call_stream``; it never
    #: rides this one-shot bound.
    max_response_bytes: int = 16777216

    def __post_init__(self) -> None:
        for name in ("ttl_minutes", "name_retries", "timeout_s",
                     "max_response_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise SettingsError(
                    f"bridge.{name}: expected an integer >= 1, got {value!r}; "
                    f"a non-positive bound makes the deploy/expiry/transport "
                    f"arithmetic meaningless or raises a raw ValueError later"
                )
        if self.scan_cap < 0:
            raise SettingsError(
                f"bridge.scan_cap: expected >= 0 (0 = ask for nothing and let "
                f"the bridge apply its own default), got {self.scan_cap}"
            )


@dataclass
class DbSettings:
    autoload_big_bytes: int = 102400
    autoload_total_warn_bytes: int = 1048576   # total autoloaded options warn level
    free_space_warn_bytes: int = 1048576      # per-table data_free optimize threshold
    #: Driver socket bounds used when the run has no deadline (a run
    #: deadline still caps both at the remaining budget).
    connect_timeout_s: float = 10.0
    read_timeout_s: float = 300.0

    def __post_init__(self) -> None:
        for name in ("autoload_big_bytes", "autoload_total_warn_bytes",
                     "free_space_warn_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise SettingsError(
                    f"db.{name}: expected an integer >= 0, got {value!r}"
                )
        for name in ("connect_timeout_s", "read_timeout_s"):
            value = getattr(self, name)
            if (isinstance(value, bool)
                    or not isinstance(value, (int, float))
                    or value <= 0):
                raise SettingsError(
                    f"db.{name}: expected a number > 0, got {value!r}"
                )


@dataclass
class MediaOptimizeSettings:
    """Tunables for the optimize-media action (wpt.actions.optimize_media).

    exclude_prefixes: webroot-relative path PREFIXES whose files are never
        optimized — and never even PLANNED (the plan stays silent about
        them: the action is not a check, so an excluded file is not a
        finding, just something out of scope).  Each entry is matched
        literally against a walk path, so a DIRECTORY prefix ends in "/"
        and covers its whole subtree; an empty list means "no exclusions".

        The shipped value protects the Gravity Forms submission-record
        subtree (``wp-content/uploads/gravity_forms/``): those inbound
        files are PEOPLE'S UPLOADED PHOTOS — quasi-records of a form
        submission, not site content an operator wants recompressed.  A
        live migration recompressed them under a profile with no such
        key, which is the whole reason the default exists.  Operators
        extend the list via ``--profile`` or ``--set`` with a JSON array
        literal:
        ``--set media_optimize.exclude_prefixes=["wp-content/uploads/2023/"]``.
    """

    jpeg_quality: int = 82
    jpeg_max_dim: int = 2560
    png_max_dim: int = 1200
    min_savings_ratio: float = 0.2
    skip_below_bytes: int = 30720
    exclude_prefixes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        quality = self.jpeg_quality
        if (isinstance(quality, bool) or not isinstance(quality, int)
                or not 0 <= quality <= 100):
            raise SettingsError(
                f"media_optimize.jpeg_quality: expected an integer 0-100, "
                f"got {quality!r}"
            )
        skip = self.skip_below_bytes
        if (isinstance(skip, bool) or not isinstance(skip, int) or skip < 0):
            raise SettingsError(
                f"media_optimize.skip_below_bytes: expected an integer >= 0, "
                f"got {skip!r}"
            )
        ratio = self.min_savings_ratio
        try:
            ratio_value = float(ratio)
        except (TypeError, ValueError, OverflowError):
            ratio_value = None
        if (isinstance(ratio, bool)
                or not isinstance(ratio, (int, float))
                or ratio_value is None
                or not math.isfinite(ratio_value)
                or not 0.0 <= ratio_value <= 1.0):
            raise SettingsError(
                f"media_optimize.min_savings_ratio: expected a finite number "
                f"between 0 and 1, got {ratio!r}"
            )
        for name in ("jpeg_max_dim", "png_max_dim"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise SettingsError(
                    f"media_optimize.{name}: expected an integer >= 1, got "
                    f"{value!r} — a 0/negative longest side makes "
                    f"PIL's thumbnail((0, 0)) raise ZeroDivisionError inside "
                    f"the action instead of naming the setting"
                )
        # ONE door for both the profile and the ``--set`` path (an override
        # REPLACES the section, so this runs there too), shared with
        # ``webp.data_prefixes`` — two keys, one meaning, one validator.
        self.exclude_prefixes = _load_prefix_list(
            "media_optimize.exclude_prefixes", self.exclude_prefixes)


@dataclass
class HttpSettings:
    timeout_s: int = 30
    verify_tls: bool = False
    #: Largest response body a bounded security probe preloads for a check
    #: that needs the BODY (homepage redirect/www, served junk, REST users).
    #: Bounded per response; the bridge's 256 KiB excerpt cap stays its own
    #: (much smaller) contract.
    max_response_bytes: int = 8388608

    def __post_init__(self) -> None:
        if (isinstance(self.timeout_s, bool) or not isinstance(self.timeout_s, int)
                or self.timeout_s < 1):
            raise SettingsError(
                f"http.timeout_s: expected an integer >= 1, got "
                f"{self.timeout_s!r}"
            )
        if not isinstance(self.verify_tls, bool):
            raise SettingsError(
                f"http.verify_tls: expected a boolean, got "
                f"{self.verify_tls!r}"
            )
        if (isinstance(self.max_response_bytes, bool)
                or not isinstance(self.max_response_bytes, int)
                or self.max_response_bytes < 1):
            raise SettingsError(
                f"http.max_response_bytes: expected an integer >= 1, got "
                f"{self.max_response_bytes!r}"
            )


@dataclass
class WpOrgSettings:
    """The wp.org endpoints, cache and transport identity — one owner.

    ``WpOrgApi`` used to hold these as module constants because they were
    considered structural protocol facts.  They are still protocol-shaped,
    but they are operator-visible behavior (a mirror, a cache location, a
    stricter body bound, a different User-Agent), so they belong here.  The
    payload shapes, validation patterns and release-zip prefix are policy
    defaults in this section; the resolver still validates every version,
    locale and theme slug before interpolation.
    """

    core_version_check_url: str = (
        "https://api.wordpress.org/core/version-check/1.7/?locale={locale}"
    )
    core_checksums_url: str = (
        "https://api.wordpress.org/core/checksums/1.0/"
    )
    plugins_update_check_url: str = (
        "https://api.wordpress.org/plugins/update-check/1.1/"
    )
    themes_update_check_url: str = (
        "https://api.wordpress.org/themes/update-check/1.1/"
    )
    core_release_zip_url: str = (
        "https://downloads.wordpress.org/release/wordpress-{version}.zip"
    )
    localized_release_zip_url: str = (
        "https://{subdomain}.wordpress.org/wordpress-{version}-{locale}.zip"
    )
    theme_release_zip_url: str = (
        "https://downloads.wordpress.org/theme/{slug}.{version}.zip"
    )
    default_locale: str = "en_US"
    release_zip_prefix: str = "wordpress/"
    cache_dir: str = ".wpt-cache"
    cache_ttl_s: int = 3600
    json_max_bytes: int = 8 * 1024 * 1024
    release_zip_max_bytes: int = 256 * 1024 * 1024
    user_agent_template: str = "wpt/{version}"

    def __post_init__(self) -> None:
        url_placeholders = {
            "core_version_check_url": ("locale",),
            "core_checksums_url": (),
            "plugins_update_check_url": (),
            "themes_update_check_url": (),
            "core_release_zip_url": ("version",),
            "localized_release_zip_url": ("subdomain", "version", "locale"),
            "theme_release_zip_url": ("slug", "version"),
        }
        for name, placeholders in url_placeholders.items():
            value = getattr(self, name)
            if not isinstance(value, str) or not value.startswith("https://"):
                raise SettingsError(
                    f"wp_org.{name}: expected an https:// URL, got {value!r}"
                )
            for placeholder in placeholders:
                token = "{" + placeholder + "}"
                if token not in value:
                    raise SettingsError(
                        f"wp_org.{name}: missing required placeholder "
                        f"{token!r}"
                    )
        for name in ("default_locale", "release_zip_prefix", "cache_dir",
                     "user_agent_template"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise SettingsError(
                    f"wp_org.{name}: expected a non-empty string, got "
                    f"{value!r}"
                )
        if not WP_LOCALE_RE.fullmatch(self.default_locale):
            raise SettingsError(
                f"wp_org.default_locale: expected [A-Za-z0-9_]+, got "
                f"{self.default_locale!r}"
            )
        if not self.release_zip_prefix.endswith("/"):
            raise SettingsError(
                f"wp_org.release_zip_prefix: expected a prefix ending in '/', "
                f"got {self.release_zip_prefix!r}"
            )
        for name in ("cache_ttl_s", "json_max_bytes", "release_zip_max_bytes"):
            value = getattr(self, name)
            if (isinstance(value, bool) or not isinstance(value, int)
                    or value < 1):
                raise SettingsError(
                    f"wp_org.{name}: expected an integer >= 1, got {value!r}"
                )
        try:
            self.user_agent_template.format(version="0.0.0")
        except (KeyError, IndexError, ValueError) as exc:
            raise SettingsError(
                "wp_org.user_agent_template: invalid format string "
                f"{self.user_agent_template!r}"
            ) from exc


@dataclass
class ProxySettings:
    """Tunables for the local TLS proxy command/engine.

    ``cert_timeout_s``: the HARD bound on every openssl invocation that
        reuses or generates the throwaway pair.  openssl is a subprocess;
        without a timeout a wedged one blocked the command past --deadline
        with no way for the tool to end its own run.
    ``max_request_bytes``: the request-body ceiling the browser side
        buffers.  A larger declared Content-Length is answered 413 BEFORE
        any read; the upstream response cap stays ``walk.max_response_bytes``
        (the historical engine setting).
    """

    cert_timeout_s: int = 30
    max_request_bytes: int = 67108864
    cert_validity_days: int = 7
    cert_renew_before_s: int = 86400

    def __post_init__(self) -> None:
        for name in ("cert_timeout_s", "max_request_bytes",
                     "cert_validity_days"):
            value = getattr(self, name)
            if (isinstance(value, bool) or not isinstance(value, int)
                    or value < 1):
                raise SettingsError(
                    f"proxy.{name}: expected an integer >= 1, got {value!r}")
        value = self.cert_renew_before_s
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise SettingsError(
                "proxy.cert_renew_before_s: expected an integer >= 0, got "
                f"{value!r}")


#: The accepted ``log.level`` names — the ONE owner read by the load door,
#: ``--log-level`` and the ``WPT_LOG_LEVEL`` fallback.  The stdlib's aliases
#: (``warn``/``fatal``) are deliberately absent: one spelling per level.
LOG_LEVELS = frozenset({"debug", "info", "warning", "error", "critical"})


@dataclass
class LogSettings:
    level: str = "info"

    def __post_init__(self) -> None:
        # ``setup_logging`` silently falls back to INFO for an unknown name,
        # so a typo would hide every DEBUG line without saying so.
        value = self.level.strip().lower() if isinstance(self.level, str) else ""
        if value not in LOG_LEVELS:
            raise SettingsError(
                f"log.level: expected one of {sorted(LOG_LEVELS)}, got "
                f"{self.level!r}"
            )
        self.level = value


@dataclass
class BackupSettings:
    keep_last: int = 10
    keep_days: int = 90
    #: Age after which a hidden snapshot capture directory left by a killed
    #: run (``.<stamp>-N.tmp`` / ``.files-*``) is residue and may be swept.
    #: Recent temps are never touched: they may belong to a LIVE concurrent
    #: run, and deleting one would abort that run's capture.
    stale_temp_age_s: int = 86400
    #: Free-space policy for the doctor's disk row: PASS above
    #: ``free_pass_bytes``, WARN above ``free_warn_bytes``, FAIL at or below
    #: it.  The row measures where the next snapshot will land.
    free_pass_bytes: int = 2 * 1024 ** 3
    free_warn_bytes: int = 500 * 1024 ** 2

    def __post_init__(self) -> None:
        for name in ("keep_last", "keep_days", "stale_temp_age_s",
                     "free_pass_bytes", "free_warn_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise SettingsError(
                    f"backup.{name}: expected an integer >= 0, got {value!r}"
                )
        if self.free_warn_bytes > self.free_pass_bytes:
            raise SettingsError(
                "backup.free_warn_bytes must not exceed "
                "backup.free_pass_bytes"
            )


@dataclass
class FilesSettings:
    """Bounds for the generic selected-file backup/edit/rollback command.

    ``wpt files`` is deliberately NOT a directory-sync tool: the operator
    names each file, the command snapshots/heals exactly those paths, and
    every read is bounded before it happens.  The cap keeps one run's local
    snapshot and its in-memory plan finite.
    """

    max_files: int = 20
    max_file_bytes: int = 8 * 1024 * 1024

    def __post_init__(self) -> None:
        for name in ("max_files", "max_file_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise SettingsError(
                    f"files.{name}: expected an integer >= 1, got {value!r}"
                )


@dataclass
class RunSettings:
    """Per-run self-bounding policy — the graceful replacement for ever
    killing a wedged run from outside: when a command's hot loops exceed
    ``deadline_s`` of elapsed wall time, the run ends ITSELF through the
    normal error contract (fail-closed cleanup, bridge destroy, rc 1
    with a clear log). 0 disables the bound."""
    deadline_s: int = 3600
    #: A FRESH finite budget for cleanup work a failed run still owes
    #: (rollback, temp/residue deletion).  Cleanup must not inherit an
    #: already-spent run budget, and must not be unbounded either: the
    #: source's ``deadline_suspended`` detachment installs this budget so
    #: the transport watchdog still fires on a dripping peer.
    cleanup_deadline_s: int = 120

    def __post_init__(self) -> None:
        # 0 is the documented explicit "off"; a negative value must not
        # silently mean the same thing (Deadline.from_ctx treats <=0 as
        # unbounded), because that would disable self-bounding by typo.
        value = self.deadline_s
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise SettingsError(
                f"run.deadline_s: expected an integer >= 0 (0 = the explicit "
                f"off switch), got {value!r}"
            )
        value = self.cleanup_deadline_s
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise SettingsError(
                f"run.cleanup_deadline_s: expected an integer >= 1, got "
                f"{value!r}"
            )


PHASE_RE = re.compile(r"\d+\.\d+")


@dataclass
class EnvSettings:
    """Runtime-environment policy (the security.php_version check).

    ``php_min_active`` is the minimum actively-supported PHP minor as a
    two-component "X.Y" string (numeric-aware tuple comparison, never a
    float); a site below it earns the php-eol finding.
    """
    php_min_active: str = "8.2"

    def __post_init__(self) -> None:
        value = self.php_min_active
        # Every settings section validates its own shape at the load door
        # (see each ``__post_init__``); this one did not, and
        # `runtime >= <the string>` then fabricated a HIGH "check errored"
        # finding that blamed the tool [L61].  The consumer compares a
        # (major, minor) tuple, so a single component ("8") has no minor and
        # crashes the comparison exactly like a non-version string; require
        # BOTH components and store the stripped form the validator saw.
        if not isinstance(value, str):
            raise SettingsError(
                "env.php_min_active: expected a version-shaped string like "
                f"'8.2' (got {value!r}); a non-version here compares against "
                "None and fabricates a HIGH check error"
            )
        value = value.strip()
        if not PHASE_RE.fullmatch(value):
            raise SettingsError(
                "env.php_min_active: expected a version-shaped string with "
                f"TWO components like '8.2' (got {self.php_min_active!r}); a "
                "non-version or a missing minor compares against None and "
                "fabricates a HIGH check error"
            )
        self.php_min_active = value


@dataclass
class WalkSettings:
    """Tunables for the live site crawler (wpt.walk) — politeness, the
    frontier's size and the size of an ANSWER.

    ``max_pages`` caps PAGES (navigations, homepage included), ``delay_s``
    sleeps between navigations only, ``max_depth`` bounds the BFS.  The
    fourth knob bounds a single RESPONSE, and it is a memory bound, not a
    politeness one: the crawler used to ``session.get()`` a page whole, so
    a 300 MB answer cost ~936 MB of RSS and a 3 GB one ended the run with a
    ``MemoryError`` traceback on the operator's laptop.  The bound is
    enforced while the body streams (wpt.walk's ``_fetch``), so an
    over-budget answer is REFUSED in bounded memory — never truncated into
    a parser.

    ``max_response_bytes`` therefore has a floor of 1: 0 would refuse every
    page, and the run would report a site with no reachable pages rather
    than the real cause.
    """

    max_pages: int = 200
    delay_s: float = 0.5
    max_depth: int = 5
    #: The largest response body the crawler will hold.  The shipped value
    #: is ~10x the largest real document this crawler parses (an Avada /
    #: page-builder front page measures 0.3-1.5 MB of HTML, the biggest
    #: generated stylesheet on such a site well under 1 MB), so no real
    #: page is ever refused, while a runaway answer is bounded at a
    #: sixteenth of what killed the process.
    max_response_bytes: int = 16777216

    def __post_init__(self) -> None:
        bound = self.max_response_bytes
        if isinstance(bound, bool) or not isinstance(bound, int) or bound < 1:
            raise SettingsError(
                f"walk.max_response_bytes: expected an integer >= 1 (got "
                f"{bound!r}) — 0 would refuse every response and report a "
                f"site with no reachable pages instead of the real cause"
            )
        for name, low in (("max_pages", 1), ("max_depth", 0)):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) \
                    or value < low:
                raise SettingsError(
                    f"walk.{name}: expected an integer >= {low}, got "
                    f"{value!r}"
                )
        delay = self.delay_s
        if (isinstance(delay, bool) or not isinstance(delay, (int, float))
                or not math.isfinite(delay) or delay < 0):
            raise SettingsError(
                f"walk.delay_s: expected a finite number >= 0, got {delay!r}"
            )


@dataclass
class MediaSettings:
    """Which uploads file types count as MEDIA for unreferenced-media
    flagging and trim-media deletion (wpt.audit.media + the trim-media
    action).

    extensions: lowercase extensions WITHOUT the dot.  Only files under
        wp-content/uploads/ whose extension is listed ever participate in
        the media.unreferenced finding or a trim-media plan — everything
        else under uploads (.htaccess, index.php, .user.ini, stray logs)
        is invisible to both [L14: a live Wordfence PHP-execution block
        in .htaccess landed in a trim-media plan because every uploads
        file counted as media; a content walk can never "reference" a
        config file].  False negatives are the safe direction for a
        destructive action: an unlisted extension is merely never
        flagged, never deleted.
    """

    extensions: list[str] = field(default_factory=list)
    #: How far BEHIND the live row count a --sql dump may be for a table
    #: that matters to the media reference decision, as a share of the live
    #: count (0 < value <= 1).  Owner of the meaning:
    #: wpt.actions.dump_witness.behind_row_ratio (which re-validates it).
    #: A dump that predates the live content cannot certify that anything
    #: is unreferenced, so "behind" is a refusal, not a discount.  The
    #: shipped default (0.5) is pinned by ``tests/test_settings.py``: it is
    #: a SAFETY property, not a preference — a dump retaining under half the
    #: live rows cannot certify an unreferenced file.
    dump_behind_row_ratio: float = 0.5

    def __post_init__(self) -> None:
        # ONE door, on BOTH the profile and the ``--set`` path (an
        # override REPLACES the section, so this runs there too), and it
        # exists because the two halves of this key read it in OPPOSITE
        # DIRECTIONS.  The enumeration files a file by its own extension
        # and the keep-gate lowercases the extension before looking it up
        # in this list, so an entry that is not already the exact
        # lowercase token matches NOTHING in one half: "JPG" plans every
        # .jpg for deletion while the database map cannot protect one,
        # and a dotted ".jpg" is the same hole wearing a disguise.  That
        # is a deletion bug reachable through a documented, set-reachable
        # profile key [L20], and a gate that silently measures an EMPTY
        # keep-set is the worst possible shape for it.
        #
        # The entries are therefore normalized (lowercased) and the
        # never-matching shapes are refused loudly, naming the key and
        # the index: a blank entry, a dotted one (this list is stored
        # without dots — the bridge's mirrored family and the wire that
        # carries it are too), and any entry carrying whitespace or a
        # path separator, which no file's extension can ever be.  An
        # extension that is merely unusual but real (a numeric one like
        # "3gp", a vendor one) is left alone: the key must not refuse a
        # family it cannot foresee.
        normalized: list[str] = []
        for index, value in enumerate(self.extensions):
            if not isinstance(value, str) or not value.strip():
                raise SettingsError(
                    f"media.extensions[{index}]: expected a non-empty "
                    f"extension string (a blank entry matches no file)"
                )
            if "." in value:
                raise SettingsError(
                    f"media.extensions[{index}]: extensions are stored "
                    f"WITHOUT the dot (got {value!r}) — '.jpg' matches no "
                    f"file, so the keep-gate would measure an empty set"
                )
            if any(char.isspace() or char in "/\\" for char in value):
                raise SettingsError(
                    f"media.extensions[{index}]: expected an extension with "
                    f"no whitespace and no path separator (got {value!r}) — "
                    f"no file's extension can be that"
                )
            normalized.append(value.lower())
        self.extensions = normalized
        # THE TOLERANCE, validated HERE and not only at the gate that reads
        # it.  ``wpt.actions.dump_witness.behind_row_ratio`` re-validates at
        # the chokepoint because that is the last moment before a deletion,
        # but a value that only fails there is caught AFTER the whole plan
        # phase has run — the one-validator-per-shape-on-the-override-path
        # hole this project keeps closing.  A ratio of 0 refuses every dump,
        # one above 1 accepts a dump that lost every row, and a string (or a
        # bool, which is an int in Python) would compare as a TypeError deep
        # inside a destructive gate.  The shape is refused on BOTH doors
        # (a ``--set`` replaces the section, so this runs there too).
        ratio = self.dump_behind_row_ratio
        if (isinstance(ratio, bool) or not isinstance(ratio, (int, float))
                or not math.isfinite(ratio) or not 0 < ratio <= 1):
            raise SettingsError(
                f"media.dump_behind_row_ratio: expected a share of the live "
                f"row count strictly above 0 and at most 1 (got {ratio!r}) — "
                f"0 would refuse every dump and a value above 1 would accept "
                f"a dump that lost rows, and a dump that predates the live "
                f"content cannot certify that anything is unreferenced"
            )
        self.dump_behind_row_ratio = float(ratio)


@dataclass
class CoreIntegritySettings:
    """Tunables for the core.integrity check (wpt.audit.integrity).

    known_stale: signatures of STALE core files — files a PREVIOUS
        WordPoint release shipped under wp-admin/wp-includes (or
        wp-content/languages catalogs) and the current release dropped.
        prune-core deletes a stale file on release provenance (its path
        in an earlier release's checksum map) OR on one of these
        signatures (same shape as known_added: ``name`` fnmatch,
        content ``marker``, ``max_bytes``, ``note``).  An empty list is
        valid: the release-provenance proof then stands alone.

    known_added: signatures of well-known BENIGN top-level PHP files
        other tools deploy into the webroot (the live case [L16]:
        Wordfence's WAF bootstrap, "wordfence-waf.php", flagged as a
        high-risk "added core file" on every Wordfence site).  Each
        entry: ``name`` (the exact webroot TOP-LEVEL filename), a
        content ``marker`` the file must carry, ``max_bytes`` (a
        content size ceiling), and a human ``note`` for the finding.
        A candidate matching name + size + marker AND carrying none of
        the ``suspicious.patterns`` malware signatures is reported as
        the separate low-risk "added-known" finding instead of the
        high-risk compromise evidence; ANY mismatch keeps the high
        classification — benign is never guessed.
    """

    known_added: list[dict] = field(default_factory=list)
    known_stale: list[dict] = field(default_factory=list)


@dataclass
class SuspiciousSettings:
    """Tunables for the security.suspicious malware-signature scan.

    max_file_bytes: PHP candidates above this size are skipped (obfuscated
        droppers are small; core-sized files are noise). The shipped default
        lives in wpt/data/profiles/default.json.
    patterns: high-precision regexes, matched CASE-SENSITIVELY (PHP function
        names are case-insensitive and variables are not, so a shipped
        pattern that needs case-insensitivity carries its own inline
        ``(?i)``); the shipped default list lives in
        wpt/data/profiles/default.json (mirrored ONLY for detail-line labels by
        wpt.audit.suspicious, never for matching).
    """

    max_file_bytes: int = 1048576
    patterns: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # A non-positive bound silently marks EVERY file oversize, so the scan
        # reports a clean tree for a reason the operator never asked for. That
        # must fail through the standard error contract, not hide.
        if self.max_file_bytes < 1:
            raise SettingsError(
                f"suspicious.max_file_bytes: expected >= 1, got "
                f"{self.max_file_bytes}"
            )


@dataclass
class BackupPayloadSettings:
    """What counts as a FULL-SITE BACKUP PAYLOAD — the shared owner for the
    ``park-backups`` action and the ``webroot.junk`` backup-payload group of
    ``clean-files`` (archive payloads sitting in the document root of a
    webroot, plus a dead duplicate webroot in a guessable directory).

    extensions: fnmatch patterns on the file's BASENAME, at any depth
        (``*.zip``, ``*.tar.gz``, ``*.tgz``, ``*.sql``, ``*.sql.gz``,
        ``*.tar``).  ``.sql``/``.sql.gz`` are shipped because a dump is the
        other shape of the same exposure; the shipped ``webroot_junk``
        ``*.sql`` entry is the pre-existing half of that rule and stays
        where it is.
    directories: fnmatch patterns on a DIRECTORY's basename, at any depth
        (``sample-backup``, ``updraft``, ``fm_backup``) — a backup plugin's
        store is a directory, and parking it moves the whole subtree.

    max_park_file_bytes: the in-memory read bound for ONE payload file
        (park-backups copies a payload out of the webroot before removing
        it).  A payload LARGER than this is reported as advice instead of
        being buffered: the action moves files it can hold, and an operator
        moves a multi-gigabyte archive by hand.  0 = unbounded (never
        ship that on a small host).
    """

    extensions: list[str] = field(default_factory=list)
    directories: list[str] = field(default_factory=list)
    max_park_file_bytes: int = 268435456

    def __post_init__(self) -> None:
        if self.max_park_file_bytes < 0:
            raise SettingsError(
                f"backup_payloads.max_park_file_bytes: expected >= 0, got "
                f"{self.max_park_file_bytes}"
            )


@dataclass
class ConditionalJunkSettings:
    """Junk whose DELETION is conditional on a plugin / constant state the
    tool must measure, never assumed (both are clean-files groups).

    Each group's gate is fail-closed: an unmeasurable gate plans NOTHING.

    geoip_files: fnmatch patterns on the basename of a legacy MaxMind
        GeoIP database, at any depth.  Legacy GeoIP was RETIRED in 2019:
        ``GeoIP.dat``/``GeoIPv6.dat`` are megabytes of data only the legacy
        ``geoip-detect`` plugin family reads.  They are deleted only while
        geoip_plugins is INACTIVE — the check reads the live active set
        (bridge ``info`` remotely, the dump's ``active_plugins`` locally) and
        REFUSES the plan when that set cannot be learned.
    geoip_plugins: plugin slugs whose ACTIVE presence keeps every
        geoip_files match in place.
    page_cache_files / page_cache_dirs: WP Super Cache's own byproducts
        (``*.wpc.log``, its ``wpo-plugins-tables-list.json`` index) and its
        cache tree (``wp-content/cache/supercache``).  They are stale the
        moment ``WP_CACHE`` is undefined in wp-config.php — the plugin
        cannot serve a page without it — so that constant (read as PHP,
        never grepped) is the gate.  page_cache_dirs entries are
        webroot-relative path PREFIXES, a directory prefix ending in ``/``.
    page_cache_plugin: the plugin the detail line names (the gate is
        WP_CACHE, not the active set: an undefined WP_CACHE already proves
        the cache is not served).
    """

    geoip_files: list[str] = field(default_factory=list)
    geoip_plugins: list[str] = field(default_factory=list)
    page_cache_files: list[str] = field(default_factory=list)
    page_cache_dirs: list[str] = field(default_factory=list)
    page_cache_plugin: str = "wp-super-cache"

    def __post_init__(self) -> None:
        # The same prefix contract every other path-prefix list uses, so a
        # direct construction cannot accept "" / "." / "a//b" that the
        # profile and --set doors refuse.
        self.page_cache_dirs = _load_prefix_list(
            "conditional_junk.page_cache_dirs", self.page_cache_dirs)


@dataclass
class ObsoleteAssetSettings:
    """Delete-candidate signatures for assets a modern site never serves.

    ``known_added`` is the ``core_integrity.known_added`` SHAPE (a list of
    signature objects validated entry-by-entry at load, unknown/missing keys
    failing loud) with the keys the decision actually needs:

    * ``name``   — fnmatch pattern on the file's basename
    * ``note``   — the one-line reason rendered as the plan item's detail
    * ``enabled``— the operator's switch.  EVERY entry ships DISABLED: these
      are per-site judgement calls, not facts, and wpt must never delete a
      font or a translation catalog on its own authority.  ``--set
      obsolete_assets.known_added=[{"name":"*.eot","note":"...","enabled":true}]``
      or a profile file turns one on.
    """

    known_added: list[dict] = field(default_factory=list)


@dataclass
class CullMediaSettings:
    """Bounds for the cull-media action (wpt.actions.cull_media).

    min_oversize_px: the smallest DECLARED dimension (the largest of a
        derivative's ``-WxH``) a cull may remove; 0 = no floor.  A derivative
        whose name carries no dimensions (``-scaled``) is measurable only
        under a 0 floor — with a floor set it is kept, because wpt cannot
        prove its size from the name.
    max_plan_files: self-bound on one plan — a cull above this many files
        REFUSES (naming both numbers) instead of emitting a huge destructive
        plan; 0 = unbounded.
    """

    min_oversize_px: int = 0
    max_plan_files: int = 0

    def __post_init__(self) -> None:
        for name in ("min_oversize_px", "max_plan_files"):
            value = getattr(self, name)
            if value < 0:
                raise SettingsError(
                    f"cull_media.{name}: expected >= 0, got {value}"
                )


#: The SHIPPED values of the web_script section, as ``(name, note)`` pairs
#: (or bare strings for the extension list) — ONE owner in code, restated
#: in wpt/data/profiles/default.json and pinned to it by
#: ``tests/audit/test_security.py::test_web_script_profile_dataclass_and_module_agree``,
#: so the three views (dataclass default, shipped profile, no-settings
#: module fallback) can never drift apart.  wpt.audit.security imports
#: these as its structural fallback for a call that carries no settings.
WEB_SCRIPT_EXTENSIONS: tuple[str, ...] = (
    ".php", ".phtml", ".php5", ".php7", ".phps", ".phar", ".inc", ".module",
)
#: The read bound for the content gate; one owner for the dataclass default
#: and the module's no-settings fallback.
WEB_SCRIPT_MAX_BYTES = 262144
WEB_SCRIPT_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("hash_equals(", "a constant-time token compare"),
    ("$_GET[", "a GET request parameter"),
    ("scandir(", "a directory listing call"),
    ("/home/", "an absolute home-directory path"),
    ("phpinfo(", "a PHP configuration dump"),
    ("php://input", "the raw request-body stream"),
)
WEB_SCRIPT_REQUEST_GLOBALS: tuple[tuple[str, str], ...] = (
    ("$_GET", "a GET request parameter"),
    ("$_POST", "a POST request parameter"),
    ("$_REQUEST", "a merged request parameter"),
    ("$_COOKIE", "a request cookie"),
)
#: wpt's OWN webroot artifacts.  A pattern rather than an exact name,
#: because the bridge name carries a random hex suffix that an exact-name
#: signature (core_integrity.known_added) cannot express — and HEX-STRICT
#: (a '?' is one hex digit), because an exemption wider than the name it
#: covers is a hole in the check that ships it.
WEB_SCRIPT_KNOWN_ARTIFACTS: tuple[tuple[str, str], ...] = (
    ("bridge-????????.php",
     "wpt's own token-guarded bridge endpoint, deployed by wpt itself "
     "(Bridge.ensure); destroy() is best-effort, so a leftover copy is wpt "
     "residue to remove, not a third-party backdoor. A '?' is ONE HEX "
     "DIGIT (case-insensitive), never 'any character': the shipped name is "
     "bridge-<8 hex>.php, and a wider pattern would exempt an attacker's "
     "bridge-shell.php"),
    ("wpt-probe-????????.php",
     "wpt's own short-lived PHP runtime probe (PhpProbe); it self-deletes "
     "after the token-gated answer and the stale sweep removes an expired "
     "copy, so a leftover is wpt residue, not a third-party backdoor. A '?' "
     "is ONE HEX DIGIT (case-insensitive)"),
)


def _signature_entries(pairs: tuple[tuple[str, str], ...]) -> list[dict]:
    """The profile's ``{name, note}`` entry shape from the shipped tuples
    (one converter for the three lists — a section default that built its
    dicts inline three times is three places to keep in step)."""
    return [{"name": name, "note": note} for name, note in pairs]


@dataclass
class DeploySettings:
    """Every deploy policy knob, in ONE place (the ``deploy`` section).

    This dataclass is the OWNER: ``wpt.deploy`` reads ``ctx.settings.deploy``
    and nothing else, so a knob is reachable by ``--set deploy.<key>=`` or a
    profile exactly like every other section.  The values below restate the
    shipped profile, and ``tests/test_settings.py`` pins the two against each
    other, so a bare ``Settings()`` and a loaded profile cannot disagree.

    NOT here, because they are STRUCTURAL rather than policy and are module
    constants in ``wpt.deploy`` with their own comments: ``FILE_MODE`` /
    ``DIR_MODE`` / ``TAR_MTIME`` (tar normalization — a byte-deterministic
    stream is a property of the format, not an operator choice), and the log
    heartbeat cadence.
    """

    # --- transport -----------------------------------------------------
    ssh_port: int = 22
    connect_timeout_s: int = 30
    #: ssh keepalive: a dead peer is detected after interval x count
    #: seconds instead of hanging on a half-open pipe (SPEC rule 10).
    server_alive_interval_s: int = 15
    server_alive_count_max: int = 4
    #: ``accept-new`` is the shipped value and it is a SECURITY default, not
    #: a convenience: a host seen for the first time is trusted, a host whose
    #: key CHANGED is refused (that is a man-in-the-middle, and the deploy
    #: writes to the target).  ``yes`` (refuse an unknown host) and ``no``
    #: (trust any key, including a changed one — never ship this) are the
    #: operator's calls, and ``tests/test_settings.py`` pins the default so
    #: the mutation "accept-new -> no" fails the suite.
    strict_host_key_checking: str = "accept-new"
    #: Hard bound on a PROBE command (df / quota / readback / sha256sum).
    probe_timeout_s: int = 120
    #: Hard bound on the streaming extract.  0 = no transport bound; the
    #: run Deadline is the bound (a multi-GB deploy is legitimately slow).
    stream_timeout_s: int = 0
    # --- plan ----------------------------------------------------------
    #: Throughput the dry-run duration estimate is computed from.
    stream_bytes_per_s: int = 20 * 1024 * 1024
    #: Fixed overhead added to the estimate (connect + readback + verify).
    stream_overhead_s: int = 60
    #: Paths hashed per remote command in the post-deploy verification.
    #: One batched command is seconds; thousands of individual reads are minutes.
    verify_batch_paths: int = 200
    #: Also record the WHOLE-ARCHIVE sha256 in the transfer manifest, so
    #: the artifact itself is identifiable independently of the streamed
    #: set.  Costs one extra sequential read of the archive, so it is the
    #: operator's call.
    manifest_archive_sha256: bool = True

    # --- preflight -----------------------------------------------------
    #: Headroom demanded ON TOP of the streamed size: the host writes logs,
    #: mail spools and databases while the deploy runs.
    preflight_margin_bytes: int = 256 * 1024 * 1024
    #: Size of the write-and-remove probe used when df/quota cannot be
    #: parsed (an account quota hidden behind a large shared filesystem —
    #: the DirectAdmin case).
    preflight_write_probe_bytes: int = 8 * 1024 * 1024
    #: When space cannot be measured at all, refuse (fail closed) instead
    #: of streaming an unproven multi-GB write.
    preflight_require_known_space: bool = True

    # --- post-extract assertions --------------------------------------
    required_files: list[str] = field(default_factory=lambda: [
        "wp-config.php", "wp-load.php", "wp-includes/version.php",
    ])
    required_dirs: list[str] = field(default_factory=lambda: ["wp-content"])
    #: Paths that must NOT exist at the webroot root.  Each is a CHILD of
    #: wp-includes/ (or wp-admin/), so finding one there is the signature
    #: of a strip that ran twice — ``ID3/``, ``about.php`` and
    #: ``version.php`` are exactly the names the failed attempt landed at
    #: the root.  A correct tree keeps them UNDER wp-includes/.
    residue_paths: list[str] = field(default_factory=lambda: [
        "ID3", "about.php", "version.php", "class-wp-error.php",
        "class-wp-query.php", "rest-api", "blocks", "SimplePie", "pomo",
        "sodium_compat", "Text", "Requests",
    ])

    # --- error classification -----------------------------------------
    quota_signatures: list[str] = field(default_factory=lambda: [
        "no space left on device", "disk quota", "quota exceeded",
        "over quota", "edquot", "not enough space", "no room left",
        "filesystem full", "out of disk space", "quota violation",
        # The live pair.  On a quota-exhausted DirectAdmin account these
        # two replace every useful message and the accompanying truncation
        # chunk truncation is the write that could not complete — so the
        # transfer is reported as the quota failure it is, never as a
        # generic network error.
        "write remote: failure", "error in the ssh layer",
    ])
    auth_signatures: list[str] = field(default_factory=lambda: [
        # ssh-AUTH shapes only.  A bare "permission denied" is deliberately
        # absent: `tar: ...: Cannot open: Permission denied` is a REMOTE
        # filesystem problem, and reading it as an auth failure sends the
        # operator to rotate a credential that was never the problem.
        "permission denied (publickey", "permission denied, please try again",
        "authentication failed", "too many authentication failures",
        "no supported authentication methods", "host key verification failed",
        "host key has changed", "no mutual signature algorithm",
    ])
    network_signatures: list[str] = field(default_factory=lambda: [
        "connection refused", "connection reset", "connection timed out",
        "operation timed out", "network is unreachable", "no route to host",
        "could not resolve hostname", "broken pipe", "connection closed",
        "kex_exchange_identification", "connection lost",
    ])

    def __post_init__(self) -> None:
        # ONE loud door, on BOTH the profile and the ``--set`` path (an
        # override REPLACES the section, so this runs there too), through
        # the standard error contract — never a raw TypeError from deep
        # inside a deploy, which would surface as a traceback.  The type
        # asked of each field is its DECLARED one, the same table the
        # profile loader and the ``--set`` path read, so a value is
        # refused identically however it arrived.
        for spec in fields(self):
            key = f"deploy.{spec.name}"
            expected = getattr(spec.type, "__name__", "")
            if expected == "list":
                values = getattr(self, spec.name)
                _load_str_list(key, values)
                if not all(values):
                    raise SettingsError(
                        f"{key}: entries must be non-empty — an empty entry "
                        f"is a substring of every message, so it would "
                        f"classify every failure this list exists to name"
                    )
            else:
                value = getattr(self, spec.name)
                _coerce(_DEPLOY_TYPES[expected], key, value)
                if expected == "str" and not value:
                    # an empty policy reaches the ssh command line as an
                    # empty option, which configures nothing and reads as
                    # "the operator asked for this"
                    raise SettingsError(
                        f"{key}: expected a non-empty str (an empty value "
                        f"would be passed to ssh as an empty option)"
                    )
        for name in ("ssh_port", "connect_timeout_s", "probe_timeout_s",
                     "stream_bytes_per_s", "verify_batch_paths",
                     "preflight_write_probe_bytes"):
            if getattr(self, name) <= 0:
                raise SettingsError(f"deploy.{name}: expected > 0")
        if self.ssh_port > PORT_MAX:
            raise SettingsError(
                f"deploy.ssh_port: expected {PORT_MIN_BINDABLE}..{PORT_MAX}, "
                f"got {self.ssh_port!r}")
        for name in ("server_alive_interval_s", "server_alive_count_max",
                     "preflight_margin_bytes", "stream_overhead_s",
                     "stream_timeout_s"):
            if getattr(self, name) < 0:
                raise SettingsError(f"deploy.{name}: expected >= 0")
        for name in ("required_files", "required_dirs", "residue_paths"):
            for path in getattr(self, name):
                if path.startswith("/") or ".." in path.split("/"):
                    raise SettingsError(
                        f"deploy.{name}: assertion path must be "
                        f"webroot-relative: {path!r}")
        for name, stopped in _DEPLOY_ASSERTIONS.items():
            # NOT `if not all(...)`: that test is vacuously TRUE for an
            # empty list, so an empty assertion list was accepted here and
            # the engine's no-op branch answered it — the documented
            # "REQUIRES wp-config.php + wp-load.php + wp-includes/version.php"
            # switched off by a profile key, silently.
            if not getattr(self, name):
                raise SettingsError(
                    f"deploy.{name}: expected a non-empty list — {stopped}"
                )


#: The declared scalar type of each ``deploy`` field, the one table
#: ``__post_init__`` and ``_coerce`` share.  ``list`` is handled by the
#: list validator before this table is consulted.
_DEPLOY_TYPES: dict[str, type] = {"int": int, "str": str, "bool": bool}

#: The deploy lists that ARE assertions, and what each one stops proving
#: when it is emptied.  The other three list fields (quota / auth / network
#: signatures) are CLASSIFICATION lists: an empty one is a coherent policy
#: (this operator's hosts never produce that message), so they stay
#: optional.  An emptied ASSERTION is not — ``readback_script`` answers an
#: empty one with the legal shell no-op ``:`` (an empty ``for p in ; do`` is
#: a syntax error), and the post-extract layout proof is then switched off
#: by a profile key with no finding anywhere: success is reported for a
#: target that is missing wp-config.php entirely.  The three refusals name
#: the fact, because "expected a non-empty list" does not tell an operator
#: what they just stopped verifying.
_DEPLOY_ASSERTIONS: dict[str, str] = {
    "required_files": (
        "the post-extract layout assertion would stop proving the site's own "
        "load files (wp-config.php, wp-load.php, wp-includes/version.php) "
        "are on the target at all, and a deploy to a target missing them "
        "would report success"
    ),
    "required_dirs": (
        "the post-extract layout assertion would stop proving wp-content/ "
        "reached the target, so a webroot with no content tree at all would "
        "verify"
    ),
    "residue_paths": (
        "the post-extract layout assertion would stop refusing a "
        "double-strip RESIDUE (ID3/, about.php at the webroot root), which is "
        "the one shape the layout assertion exists to catch"
    ),
}


@dataclass
class WebpSettings:
    """Tunables for the webp-media action (wpt.actions.images_webp).

    quality: libwebp's quality for the twin (0-100, the codec's own
        range).  A lossy re-encode, so it is the operator's call per
        site; the shipped 80 is libwebp's own default and the point where
        the saving stays worth the second generation.
    skip_below_bytes: files smaller than this are not converted at all
        (a 4 KB icon is noise, and its twin is not worth a row in the
        plan).  NOT the same bound as ``media_optimize.skip_below_bytes``
        only by name: that one measures a RE-ENCODE, this one measures
        whether converting is worth doing.
    max_dim: the longest side a twin may carry; 0 = never resize (the
        shipped default, because downscaling loses resolution a theme
        may be relying on and the operator has to ask for it).
    purge_originals: whether the originals are deleted once every
        reference has been rewritten (see the action's ``_require_purge_ack``:
        whichever door asks for it, the acknowledgement is still required).
        TRI-STATE at the CLI: the ``--purge-originals`` FLAG wins when
        typed, and this key decides only in the "not typed" state.
    data_prefixes: webroot-relative PREFIXES whose files are never
        converted — the Gravity Forms submission photos
        (``wp-content/uploads/gravity_forms/``) are PEOPLE'S uploads,
        quasi-records of a form submission, not site content.  Same
        meaning and same validator as
        ``media_optimize.exclude_prefixes``.
    verify_pages: how many rendered pages the post-apply verification
        fetches (the reference-set re-read on live HTML); 0 disables the
        rendered-page pass.
    verify_retries / verify_retry_delay_s: the retry policy of that pass
        (a page that 503s once must not fail a verified apply).
    challenge_max_bytes: the largest body still inspected for a
        bot-challenge page — above it the body is far too large to be a
        challenge interstitial, so it is content (see the action's
        ``challenge_reason``).
    """

    quality: int = 80
    skip_below_bytes: int = 30720
    max_dim: int = 0
    purge_originals: bool = False
    data_prefixes: list[str] = field(
        default_factory=lambda: ["wp-content/uploads/gravity_forms/"])
    verify_pages: int = 20
    verify_retries: int = 2
    verify_retry_delay_s: float = 1.0
    challenge_max_bytes: int = 32768

    def __post_init__(self) -> None:
        if (isinstance(self.quality, bool) or not isinstance(self.quality, int)
                or not 0 <= self.quality <= 100):
            raise SettingsError(
                f"webp.quality: expected 0-100 (libwebp's own range), got "
                f"{self.quality}"
            )
        for name in ("skip_below_bytes", "max_dim", "verify_pages",
                     "verify_retries"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise SettingsError(
                    f"webp.{name}: expected an integer >= 0, got {value}")
        if not isinstance(self.purge_originals, bool):
            raise SettingsError(
                f"webp.purge_originals: expected a boolean, got "
                f"{self.purge_originals!r}"
            )
        if (isinstance(self.challenge_max_bytes, bool)
                or not isinstance(self.challenge_max_bytes, int)
                or self.challenge_max_bytes < 1):
            # 0 would be "never inspect a body", which silently turns the
            # bot-challenge detection OFF — a challenge page would then read
            # as content.  The verification would still pass, on a fetch that
            # proved nothing, so this is the weaker door the rule refuses.
            raise SettingsError(
                f"webp.challenge_max_bytes: expected an integer >= 1 (0 "
                f"would disable challenge detection, so a challenge page "
                f"would read as content), got {self.challenge_max_bytes!r}"
            )
        delay = self.verify_retry_delay_s
        # ``time.sleep`` converts to a 64-bit nanosecond PyTime_t; inf/nan
        # never expire and a value past that platform bound raises a raw
        # OverflowError inside the action.  Refuse both at the door.
        max_sleep = (1 << 63) / 1_000_000_000
        try:
            delay_value = float(delay)
        except (TypeError, ValueError, OverflowError):
            delay_value = None
        if (isinstance(delay, bool)
                or not isinstance(delay, (int, float))
                or delay_value is None
                or not math.isfinite(delay_value)
                or not 0 <= delay_value <= max_sleep):
            raise SettingsError(
                f"webp.verify_retry_delay_s: expected a finite number of "
                f"seconds between 0 and {max_sleep:g}, got {delay!r}"
            )
        self.data_prefixes = _load_prefix_list(
            "webp.data_prefixes", self.data_prefixes)


@dataclass
class UpdateSettings:
    """Policy knobs for the update-core action (wpt.actions.update_core).

    Three, because exactly three of that action's decisions are the
    OPERATOR's and not structural WordPress facts. Everything else in the
    action is derived from wp.org (the target version, its file set, its
    PHP/MySQL floors) or is a structural fact of the format (the
    ``.maintenance`` file WordPress itself honours, the release zip's
    ``wordpress/`` prefix, the staging suffix beside the tree being
    replaced) and belongs in the module, not in a profile.

    ``pre_release_allowed``: the DEFAULT answer to "may this run install a
        pre-release (RC / beta / alpha) target?". TRI-STATE at the CLI,
        exactly like ``webp.purge_originals``: ``--allow-pre-release``
        wins when typed, and this key decides only in the "not typed"
        state. Shipped FALSE — a release candidate is not a version an
        operator should reach for by omission.
    ``maintenance``: whether the update engages the webroot-root
        ``.maintenance`` file for the duration of the swap. Shipped TRUE:
        WordPress honours the file, so it is the cheapest possible
        "do not touch the site for a moment" and it is removed in the
        action's ``finally``, so a crash cannot leave the site down. Set
        it FALSE only for an operator who answers for the maintenance
        window out of band (a host-level block page, a closed lobby) and
        accepts the partial tree a visitor can see mid-swap.
    ``driver``: WHICH of the action's two file drivers installs the
        release. ``"wordpress"`` drives WordPress's OWN updater through
        the ``core_upgrade_files`` bridge op (core's ``unzip_file()`` /
        ``copy_dir()`` / version-last ordering / bundled re-add), ``"swap"``
        is the tool's park-and-land rename, and ``"auto"`` — SHIPPED —
        picks ``wordpress`` when the site reports a ``direct`` filesystem
        method AND a zip library (the two preconditions core's own
        extractor has, and the reason it cannot be automated anywhere
        else), and ``swap`` everywhere else, because the swap needs
        neither. The driver is a POLICY choice, not a capability: both
        drivers are verified the same way, so the setting only decides
        which well-tested mechanism lays the bytes down.

    NOT here, deliberately: the replacement SCOPE. Which trees a core
    update replaces (``wp-admin/``, ``wp-includes/`` and the webroot-root
    core files) is a structural fact of what a WordPress release ships,
    and both directions of a knob for it are wrong — widening it would
    let an update write ``wp-content/`` (plugins, themes, uploads: never
    core's business) and narrowing it produces a core that no longer
    matches its own release. The file set is derived from the target
    release zip and the checksum map on every run, so a knob could not
    make it more correct.
    """

    pre_release_allowed: bool = False
    maintenance: bool = True
    driver: str = "auto"

    def __post_init__(self) -> None:
        for name in ("pre_release_allowed", "maintenance"):
            value = getattr(self, name)
            if not isinstance(value, bool):
                raise SettingsError(
                    f"update.{name}: expected a boolean, got {value!r}")
        # ONE door for both the profile and the ``--set`` path (an override
        # REPLACES the section, so this runs there too): a driver name the
        # action does not know is a typo, and it must fail loud at load
        # rather than silently reading as "not wordpress" and running the
        # other driver.
        if self.driver not in UPDATE_DRIVERS:
            raise SettingsError(
                f"update.driver: expected one of "
                f"{', '.join(sorted(UPDATE_DRIVERS))}, got {self.driver!r}"
            )


@dataclass
class WebScriptSettings:
    """Tunables for the security.web_exposed_script check.

    ``extensions``: the webroot path SUFFIXES the check treats as
    PHP-EXECUTABLE (leading dot included; a value without one is
        normalized).  WHICH suffixes execute is the HOST's handler
        configuration (``AddHandler``/mod_php routinely map ``.phtml``,
        ``.phar``, ``.php5`` and ``.module`` to the interpreter on shared
        hosting), so this is the common superset an operator can narrow
        for a host that runs less — and the check's candidate filter is
        case-insensitive, so ``shell.PHP`` is a candidate.
    ``signatures``: the needles an unknown top-level webroot script must
        carry for the check to call it out (each ``{name, note}``: the
        literal and what it is), in the fixed order the detail renders
        them.  The cheap first pass; ``request_globals`` is the
        structured second pass that survives the whitespace/quoting a
        substring loses to.
    ``request_globals``: the request-superglobal family as ``{name, note}``,
        matched as NAME + optional whitespace/quote + subscript, so
        ``$_GET ['t']`` and every sibling superglobal are as visible as
        the literal ``$_GET[``.  An empty list disables that pass alone.
    ``known_artifacts``: ``{name, note}`` patterns on a
        TOP-LEVEL basename for the files WPT ITSELF leaves in a docroot
        (the shipped default is its own ``bridge-<hex>.php``: the real
        bridge.php carries the request-parameter gate and ``scandir(``
        this check looks for, and ``Bridge.destroy()`` is best-effort, so
        wpt's own residue must never read as a HIGH backdoor).  It lives
        here and not in ``core_integrity.known_added`` because that
        mechanism matches an EXACT filename, which a random hex suffix
        cannot express.  ``*`` is any run of characters and ``?`` is ONE
        HEX DIGIT (either case) — the matcher is hex-strict, not plain
        fnmatch, because the exemption is a security hole as soon as it
        is wider than the name it covers: ``bridge-*.php`` also exempts
        an attacker's ``bridge-shell.php`` (wpt/audit/security.py owns the
        matching).
    ``max_bytes``: a candidate larger than this is not read (a scope
        bound, not a verdict — a token-gated probe or a dropper is a few
        KB).

    An EMPTY ``signatures`` list means SCAN NOTHING, not "fall back to the
    built-in list": the old fallback reported a section as empty while the
    check still scanned six needles, so the effective behaviour could not
    be described from the profile.  It is the master switch for the whole
    content gate (the request-superglobal family is part of the same
    scan); the dataclass default below restates the shipped values so a
    bare ``Settings()`` still scans.
    """

    extensions: list[str] = field(default_factory=lambda: list(
        WEB_SCRIPT_EXTENSIONS))
    signatures: list[dict] = field(
        default_factory=lambda: _signature_entries(WEB_SCRIPT_SIGNATURES))
    request_globals: list[dict] = field(
        default_factory=lambda: _signature_entries(WEB_SCRIPT_REQUEST_GLOBALS))
    known_artifacts: list[dict] = field(
        default_factory=lambda: _signature_entries(WEB_SCRIPT_KNOWN_ARTIFACTS))
    max_bytes: int = WEB_SCRIPT_MAX_BYTES

    def __post_init__(self) -> None:
        # One loud door for the suffix list, on BOTH the profile and the
        # --set path (apply_override replaces the section, so this runs
        # there too): a blank or non-string entry is a typo that would
        # make the check scan an empty candidate set and report a clean
        # webroot for a reason nobody asked for.  An EMPTY list is refused
        # for the same reason: ``signatures: []`` is the documented master
        # switch, while an empty extension list silently disables the gate.
        if not self.extensions:
            raise SettingsError(
                "web_script.extensions: expected at least one suffix — an "
                "empty list would read no candidate and report the webroot "
                "clean; use web_script.signatures=[] to disable the check"
            )
        for index, value in enumerate(self.extensions):
            if not isinstance(value, str) or not value.strip():
                raise SettingsError(
                    f"web_script.extensions[{index}]: expected a non-empty "
                    f"string suffix (a blank pattern matches nothing)"
                )
        # A non-positive read bound silently filters EVERY candidate
        # (``size <= max_bytes``), so the whole content gate reports clean
        # without reading a byte — the same false-negative class
        # ``suspicious.max_file_bytes`` already refuses.
        if (isinstance(self.max_bytes, bool)
                or not isinstance(self.max_bytes, int) or self.max_bytes < 1):
            raise SettingsError(
                f"web_script.max_bytes: expected an integer >= 1, got "
                f"{self.max_bytes!r} — a non-positive bound would skip every "
                f"candidate and report the webroot clean"
            )


@dataclass
class ProbeSettings:
    """Lifecycle bounds for the standalone, no-WordPress PHP runtime probe.

    The probe is the diagnostic that still works when ``wp-load.php``/PDO/DB
    are broken (the exact state a bridge cannot report).  It is a short-lived
    executable PHP file at the webroot root, so it carries the same three
    bounds as the bridge: a token TTL, a collision-retry count and a transport
    timeout.  ``ttl_minutes`` also gates the stale-probe sweep.
    """

    ttl_minutes: int = 15
    name_retries: int = 3
    timeout_s: int = 15

    def __post_init__(self) -> None:
        for name in ("ttl_minutes", "name_retries", "timeout_s"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise SettingsError(
                    f"probe.{name}: expected an integer >= 1, got {value!r}"
                )


@dataclass
class LogsSettings:
    """Bounds for host/webroot error-log triage (``wpt logs`` + doctor).

    Log files are the one diagnostic source that can be arbitrarily large and
    can live outside the webroot.  Every read is bounded before it happens:
    the number of files considered, the bytes of a plain file, and the bytes
    of an archive (a DirectAdmin monthly ``.tar.gz``).  ``detail_limit`` bounds
    the rows rendered for one report.
    """

    max_files: int = 20
    max_file_bytes: int = 4 * 1024 * 1024
    max_archive_bytes: int = 32 * 1024 * 1024
    #: Hard ceiling on the bytes a compressed archive may make us DECOMPRESS
    #: (selected and skipped members alike).  The archive byte bound alone
    #: says nothing about its expansion: a 32 MiB gzip stream can encode tens
    #: of GiB, and tarfile walks every member — including non-log members it
    #: never reads — by decompressing the stream.  One aggregate ceiling turns
    #: that into a skip instead of unbounded work/deadline overrun.
    max_decompressed_bytes: int = 256 * 1024 * 1024
    detail_limit: int = 20

    def __post_init__(self) -> None:
        for name in ("max_files", "max_file_bytes", "max_archive_bytes",
                     "max_decompressed_bytes", "detail_limit"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise SettingsError(
                    f"logs.{name}: expected an integer >= 1, got {value!r}"
                )


@dataclass
class TlsSettings:
    """TLS health policy for the doctor's certificate row.

    ``warn_days`` is the renewal horizon: a certificate that verifies but
    expires inside this window is a WARN, not a PASS.  The URL's own port (or
    443) is the dial target; there is deliberately no separate port knob.
    """

    warn_days: int = 14

    def __post_init__(self) -> None:
        if isinstance(self.warn_days, bool) or not isinstance(self.warn_days, int) \
                or self.warn_days < 0:
            raise SettingsError(
                f"tls.warn_days: expected an integer >= 0, got "
                f"{self.warn_days!r}"
            )


@dataclass
class SourceScanSettings:
    """Bounds and exclusions for ``security.source_patterns`` / ``wpt scan``.

    The scan is a source-only heuristic for the dangerous PHP patterns a
    legacy application carries (request-driven ``session_id``, reflected
    request data, request data in SQL sinks and file includes).  Core
    directories are excluded by default because their code is WordPress's, not
    the application's; plugins/themes stay in scope because they are executed
    application code.
    """

    max_file_bytes: int = 1024 * 1024
    detail_limit: int = 20
    ignore_prefixes: list[str] = field(
        default_factory=lambda: ["wp-admin/", "wp-includes/"])

    def __post_init__(self) -> None:
        for name in ("max_file_bytes", "detail_limit"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise SettingsError(
                    f"source_scan.{name}: expected an integer >= 1, got "
                    f"{value!r}"
                )
        self.ignore_prefixes = _load_prefix_list(
            "source_scan.ignore_prefixes", self.ignore_prefixes)


@dataclass
class DiscoverSettings:
    """Bound on the read-only webroot discovery walk (``wpt discover``)."""

    max_candidates: int = 50

    def __post_init__(self) -> None:
        if isinstance(self.max_candidates, bool) \
                or not isinstance(self.max_candidates, int) \
                or self.max_candidates < 1:
            raise SettingsError(
                f"discover.max_candidates: expected an integer >= 1, got "
                f"{self.max_candidates!r}"
            )


@dataclass
class Settings:
    ftp: FtpSettings = field(default_factory=FtpSettings)
    bridge: BridgeSettings = field(default_factory=BridgeSettings)
    probe: ProbeSettings = field(default_factory=ProbeSettings)
    db: DbSettings = field(default_factory=DbSettings)
    media_optimize: MediaOptimizeSettings = field(default_factory=MediaOptimizeSettings)
    media: MediaSettings = field(default_factory=MediaSettings)
    core_integrity: CoreIntegritySettings = field(default_factory=CoreIntegritySettings)
    http: HttpSettings = field(default_factory=HttpSettings)
    wp_org: WpOrgSettings = field(default_factory=WpOrgSettings)
    proxy: ProxySettings = field(default_factory=ProxySettings)
    tls: TlsSettings = field(default_factory=TlsSettings)
    log: LogSettings = field(default_factory=LogSettings)
    logs: LogsSettings = field(default_factory=LogsSettings)
    backup: BackupSettings = field(default_factory=BackupSettings)
    files: FilesSettings = field(default_factory=FilesSettings)
    walk: WalkSettings = field(default_factory=WalkSettings)
    discover: DiscoverSettings = field(default_factory=DiscoverSettings)
    suspicious: SuspiciousSettings = field(default_factory=SuspiciousSettings)
    source_scan: SourceScanSettings = field(default_factory=SourceScanSettings)
    backup_payloads: BackupPayloadSettings = field(
        default_factory=BackupPayloadSettings)
    conditional_junk: ConditionalJunkSettings = field(
        default_factory=ConditionalJunkSettings)
    obsolete_assets: ObsoleteAssetSettings = field(
        default_factory=ObsoleteAssetSettings)
    cull_media: CullMediaSettings = field(default_factory=CullMediaSettings)
    env: EnvSettings = field(default_factory=EnvSettings)
    web_script: WebScriptSettings = field(default_factory=WebScriptSettings)
    webp: WebpSettings = field(default_factory=WebpSettings)
    deploy: DeploySettings = field(default_factory=DeploySettings)
    update: UpdateSettings = field(default_factory=UpdateSettings)
    run: RunSettings = field(default_factory=RunSettings)
    webroot_junk: list[str] = field(default_factory=list)
    stale_content_dirs: list[str] = field(default_factory=list)
    ghost_table_prefixes: list[str] = field(default_factory=list)
    # ghost marker -> the plugin slug whose ACTIVE presence excludes the
    # marker (markers are table-name tokens, not plugin slugs: "nf3" tables
    # belong to "ninja-forms", "statistics" tables to "wp-statistics").
    ghost_marker_plugins: dict[str, str] = field(default_factory=dict)
    duplicate_plugin_groups: list[list[str]] = field(default_factory=list)
    #: The operator's OWN decision for the plugins.duplicate check:
    #: group name (the members joined with "/", byte-identical to the
    #: finding's ``name``) -> the slug to KEEP.  Empty/unset = today's
    #: behavior (the check's own evidence-based advice, no command).
    #: Setting it turns the finding's ``fix`` into the exact
    #: ``wpt deactivate-plugin <slug> --apply`` command for every OTHER
    #: present member of that group.  It is ADVICE, never an action:
    #: nothing is deactivated without the operator running the command
    #: (or a follow-up run) with --apply.  Both the key and its value are
    #: validated against ``duplicate_plugin_groups`` by
    #: :func:`_check_duplicate_preferences` — an unknown group or a slug
    #: outside it is a typo, and it fails loud (SettingsError) instead of
    #: silently doing nothing.  ORDER: a `--set` list that overrides BOTH
    #: keys must set ``duplicate_plugin_groups`` first (a single profile
    #: file is order-free).
    duplicate_plugin_groups_preferred: dict[str, str] = field(default_factory=dict)
    migration_leftovers: list[str] = field(default_factory=list)
    known_heavy: list[str] = field(default_factory=list)
    #: Name PREFIXES of must-use plugin units (direct children of
    #: wp-content/mu-plugins) that hosting platforms deploy — the
    #: webroot.mu_plugins informational check reads them; the shipped
    #: list lives in wpt/data/profiles/default.json.
    mu_plugin_known_platform: list[str] = field(default_factory=list)


def _coerce(typ: type, key: str, value: Any) -> Any:
    """Validate a scalar against its declared type (bool must be a JSON bool)."""
    if typ is bool:
        if not isinstance(value, bool):
            raise SettingsError(f"{key}: expected bool, got {type(value).__name__}")
        return value
    if typ is float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise SettingsError(f"{key}: expected number, got {type(value).__name__}")
        try:
            return float(value)
        except OverflowError as exc:
            raise SettingsError(
                f"{key}: number {value!r} is too large for a float") from exc
    if typ is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise SettingsError(f"{key}: expected int, got {type(value).__name__}")
        return value
    if typ is str:
        if not isinstance(value, str):
            raise SettingsError(f"{key}: expected str, got {type(value).__name__}")
        return value
    raise SettingsError(f"{key}: unsupported setting type {typ!r}")


def apply_override(target: Any, dotted_key: str, value: Any) -> None:
    """Apply one dot-path override onto a Settings tree (shared, single impl).

    The value is validated with the SAME rules the profile loader applies, and
    the owning section's ``__post_init__`` runs afterwards, so an override can
    never be a weaker door than a value read from a profile file.
    """
    parts = dotted_key.split(".")
    if not dotted_key or not all(parts):
        raise SettingsError(f"malformed override key: {dotted_key!r}")
    obj: Any = target
    for part in parts[:-1]:
        if not hasattr(obj, part):
            raise SettingsError(f"unknown settings section: {'.'.join(parts[:-1])!r}")
        obj = getattr(obj, part)
        if not hasattr(obj, "__dataclass_fields__"):
            raise SettingsError(f"{'.'.join(parts[:-1])!r} is not a settings section")
    leaf = parts[-1]
    if not hasattr(obj, "__dataclass_fields__") or leaf not in obj.__dataclass_fields__:
        raise SettingsError(f"unknown setting: {dotted_key!r}")
    candidate = _override_value(dotted_key, obj, leaf, value)
    # Cross-field validation (the duplicate-group preferences) runs on the
    # PROSPECTIVE pair before the live tree is touched, for the same reason
    # the replacement below does: a rejected override must leave a tree the
    # loader would never have produced.
    if dotted_key in _DUPLICATE_PREFERENCE_KEYS:
        _check_duplicate_preferences(
            candidate if dotted_key == "duplicate_plugin_groups"
            else target.duplicate_plugin_groups,
            candidate if dotted_key == "duplicate_plugin_groups_preferred"
            else target.duplicate_plugin_groups_preferred,
        )
    # Validate on a REPLACEMENT before the live object is touched: assigning
    # first left a rejected override in place, so a caller that caught the
    # SettingsError kept a tree the loader would never have produced.
    validated = replace(obj, **{leaf: candidate})
    setattr(obj, leaf, getattr(validated, leaf))


def _override_value(dotted_key: str, owner: Any, leaf: str, value: Any) -> Any:
    """The coerced override value, checked with the loader's own contracts.

    Every shape the loader accepts is accepted here and nothing else: a
    section's scalars, its list-of-strings fields, the list-of-objects
    fields, and the three top-level collection shapes.  The list-of-objects
    validator is looked up by (owning dataclass, field) exactly as the
    profile loader does, so ``--set`` can never be a weaker door.
    """
    field = owner.__dataclass_fields__[leaf]
    declared = field.type
    validator = _LIST_OF_OBJECT_VALIDATORS.get(
        (type(owner).__name__, leaf)
    )
    if validator is not None:
        return validator(dotted_key, value)
    list_validator = _SECTION_STRING_LIST_VALIDATORS.get(
        (type(owner).__name__, leaf))
    if list_validator is not None:
        return list_validator(dotted_key, value)
    if leaf in _TOP_LEVEL_LISTS:
        return _top_level_list(dotted_key, value)
    if leaf in _TOP_LEVEL_MAPS:
        return _load_str_map(dotted_key, value)
    if leaf in _TOP_LEVEL_NESTED_LISTS:
        return _load_str_lists(dotted_key, value)
    expected = declared if isinstance(declared, str) \
        else getattr(declared, "__name__", "")
    if expected == "list":
        return _load_str_list(dotted_key, value)
    typemap = {"int": int, "float": float, "str": str, "bool": bool}
    typ = typemap.get(expected)
    if typ is None:
        raise SettingsError(f"{dotted_key}: unsupported setting type {declared!r}")
    return _coerce(typ, dotted_key, value)


#: The three top-level collection shapes (one owner each, shared by the
#: profile loader and the override path).  A key with its own shape rules
#: names its validator here, so the loader and ``--set`` reach the SAME
#: function for it (never the generic one) — the table is what keeps the two
#: doors from drifting, the same arrangement
#: :data:`_LIST_OF_OBJECT_VALIDATORS` makes for the section-level lists.
_TOP_LEVEL_LIST_VALIDATORS: dict[str, Any] = {
    "webroot_junk": _load_webroot_junk,
}
_TOP_LEVEL_LISTS = ("webroot_junk", "stale_content_dirs", "ghost_table_prefixes",
                    "migration_leftovers", "known_heavy",
                    "mu_plugin_known_platform")
_TOP_LEVEL_MAPS = ("ghost_marker_plugins", "duplicate_plugin_groups_preferred")
_TOP_LEVEL_NESTED_LISTS = ("duplicate_plugin_groups",)

#: The two keys the cross-field preference check couples (see
#: ``_check_duplicate_preferences``).
_DUPLICATE_PREFERENCE_KEYS = (
    "duplicate_plugin_groups", "duplicate_plugin_groups_preferred",
)


def _check_duplicate_preferences(
    groups: list[list[str]], preferred: dict[str, str]
) -> None:
    """Every preference must name a real group AND one of its slugs.

    A preference that names an unknown group, or a slug outside the group
    it names, is a TYPO — the plugins.duplicate check could never honour
    it, and silently ignoring it would leave the operator believing a
    decision is in force when the finding still renders its generic
    advice.  Failing loud here (the standard error contract, on both the
    profile and the ``--set`` path) is the only way that mistake is
    visible.  A pure function of the two values, so both callers can run
    it on a PROSPECTIVE pair without mutating a live tree.
    """
    if not preferred:
        return
    by_name = {"/".join(group): group for group in groups}
    for name, keep in sorted(preferred.items()):
        group = by_name.get(name)
        if group is None:
            raise SettingsError(
                f"duplicate_plugin_groups_preferred: {name!r} names no group "
                f"in duplicate_plugin_groups (known groups: {sorted(by_name)}) "
                f"— set duplicate_plugin_groups first"
            )
        if keep not in group:
            raise SettingsError(
                f"duplicate_plugin_groups_preferred[{name!r}]: {keep!r} is not "
                f"a member of that group ({group})"
            )


def _load_str_list(key: str, raw: Any) -> list[str]:
    """A list of strings, or a loud SettingsError."""
    if not isinstance(raw, list) or not all(isinstance(v, str) for v in raw):
        raise SettingsError(f"{key}: expected list of strings")
    return list(raw)


def _top_level_list(key: str, raw: Any) -> list[str]:
    """One top-level list key through ITS validator (see the table).

    The generic contract is the floor, so a key with no entry here is
    exactly a list of strings — the shared path, called from one place, so
    adding a validator is a one-line change and can never be applied to only
    one of the two doors.
    """
    return _TOP_LEVEL_LIST_VALIDATORS.get(key, _load_str_list)(key, raw)


def _load_prefix_list(key: str, raw: list[str]) -> list[str]:
    """Webroot-relative path PREFIXES, or a loud SettingsError.

    ONE validator for every key that carries that meaning —
    ``media_optimize.exclude_prefixes`` (never optimize these),
    ``webp.data_prefixes`` (never convert these; the Gravity Forms
    submission photos the operator's uploads tree is full of),
    ``source_scan.ignore_prefixes`` (never scan these) and
    ``conditional_junk.page_cache_dirs`` (page-cache subtrees).

    Every entry must be a prefix a webroot-relative walk path can
    actually match.  A blank entry matches EVERY file (the action
    silently stops doing anything) and a root-absolute one matches
    NOTHING (the operator believes a subtree is protected while it is
    still processed) — both are the exact live failure these keys exist
    to prevent, so they fail here, at the owner, through the standard
    error contract.  This runs on the override path too
    (``apply_override`` validates on a replacement), so ``--set`` is
    never the weaker door.

    The blank test is on the STRIPPED entry, so a padded absolute path
    ("   /wp-content/") is rejected like the bare one; and a
    separator-shaped entry is refused for the same "matches nothing while
    looking deliberate" reason: a backslash (a Windows path where walk
    paths are POSIX), a drive-letter prefix (``C:/...``), a
    home-relative ``~`` shape, or a ".." segment (no webroot-relative
    walk path can contain one — the Source guard refuses them).  A
    padded entry is rejected rather than silently stripped: consumers
    compare the stored string with ``startswith``, so returning the raw
    padded value would claim to protect a subtree while matching none
    of it.  An entry that is merely unusual but matchable (a space in a
    directory name) is left alone.
    """
    if not isinstance(raw, list) or not all(isinstance(v, str) for v in raw):
        raise SettingsError(f"{key}: expected list of strings")
    for prefix in raw:
        stripped = prefix.strip()
        segments = stripped.split("/")
        # A trailing separator is the documented directory-prefix shape;
        # any OTHER empty segment ("a//b") and a "." segment ("./x", ".",
        # "a/./b") matches nothing (or, for ".", the whole tree) while
        # looking deliberate — reject at the one owner both doors use.
        if segments and segments[-1] == "":
            segments = segments[:-1]
        drive_letter = (len(stripped) >= 2 and stripped[1] == ":"
                        and stripped[0].isalpha())
        if (not stripped
                or stripped != prefix
                or stripped.startswith("/")
                or stripped.startswith("~")
                or drive_letter
                or "\\" in prefix
                or ".." in prefix.split("/")
                or not segments
                or any(segment in ("", ".") for segment in segments)):
            raise SettingsError(
                f"{key}: entries must be non-padded webroot-relative "
                f"prefixes (no leading '/', no drive letter or '~', no "
                f"backslash, no '..'/'.'/empty segment), got {prefix!r}"
            )
    return list(raw)


def _load_str_map(key: str, raw: Any) -> dict[str, str]:
    """A string -> string object, or a loud SettingsError."""
    if not isinstance(raw, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in raw.items()
    ):
        raise SettingsError(f"{key}: expected object of string -> string")
    return dict(raw)


def _load_str_lists(key: str, raw: Any) -> list[list[str]]:
    """A list of lists of strings, or a loud SettingsError."""
    if not isinstance(raw, list) or not all(
        isinstance(g, list) and all(isinstance(v, str) for v in g) for g in raw
    ):
        raise SettingsError(f"{key}: expected list of lists of strings")
    return [list(g) for g in raw]


#: The fixed per-signature key set + types of core_integrity.known_added
#: entries (the one list-of-objects shape in the profile — validated
#: entry-by-entry at load; unknown/missing keys fail loud).
_KNOWN_ADDED_KEYS: dict[str, type] = {
    "name": str, "marker": str, "max_bytes": int, "note": str,
}


_WEB_SCRIPT_KEYS: dict[str, type] = {"name": str, "note": str}


def _load_web_script_signatures(key: str, raw: Any) -> list[dict]:
    """Validate a web_script ``{name, note}`` list (the signature family and
    the request-superglobal family share the shape): a list of objects with
    exactly the two keys, both non-empty strings.  A malformed profile
    fails loud, never silently scans nothing."""
    return _load_web_script_entry_list(key, raw)


def _load_web_script_artifacts(key: str, raw: Any) -> list[dict]:
    """Validate ``web_script.known_artifacts``: the same ``{name, note}``
    shape, with the extra rule that a name is a pattern on a TOP-LEVEL
    basename, so it may not carry a path separator (a name with one could
    never match the basename — the matcher is hex-strict on ``?``, see
    ``wpt/audit/security.py``)."""
    return _load_web_script_entry_list(key, raw, basename=True)


def _load_web_script_entry_list(
    key: str, raw: Any, *, basename: bool = False
) -> list[dict]:
    """The one validator behind both web_script ``{name, note}`` lists."""
    if not isinstance(raw, list):
        raise SettingsError(f"{key}: expected a list of signatures")
    out: list[dict] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise SettingsError(f"{key}[{i}]: expected an object")
        if set(entry) != set(_WEB_SCRIPT_KEYS):
            raise SettingsError(
                f"{key}[{i}]: expected exactly {sorted(_WEB_SCRIPT_KEYS)}")
        for k, t in _WEB_SCRIPT_KEYS.items():
            if not isinstance(entry[k], t) or not entry[k]:
                raise SettingsError(f"{key}[{i}].{k}: expected a non-empty string")
        if basename and "/" in entry["name"]:
            raise SettingsError(
                f"{key}[{i}].name: a top-level basename pattern carries no "
                f"path separator"
            )
        out.append(dict(entry))
    return out


def _load_known_added(key: str, raw: Any) -> list[dict]:
    """Validate one known_added signatures list (see _KNOWN_ADDED_KEYS).

    Every entry must carry exactly the fixed keys with the right types;
    a malformed profile fails as SettingsError instead of surprising the
    check at runtime.
    """
    if not isinstance(raw, list):
        raise SettingsError(f"{key}: expected a list of known-added signatures")
    out: list[dict] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise SettingsError(f"{key}[{i}]: expected an object")
        unknown = set(entry) - set(_KNOWN_ADDED_KEYS)
        if unknown:
            raise SettingsError(f"{key}[{i}]: unknown keys {sorted(unknown)}")
        missing = set(_KNOWN_ADDED_KEYS) - set(entry)
        if missing:
            raise SettingsError(f"{key}[{i}]: missing keys {sorted(missing)}")
        sig = {}
        for field_name, field_type in _KNOWN_ADDED_KEYS.items():
            sig[field_name] = _coerce(field_type, f"{key}[{i}].{field_name}",
                                      entry[field_name])
        out.append(sig)
    return out


#: The fixed per-signature key set + types of obsolete_assets.known_added
#: entries: the known_added SHAPE (a marker/suffix + a note) plus the
#: operator's ``enabled`` switch, which is why these decisions ship in the
#: profile as DATA and default to off.  Same entry-by-entry validation as
#: core_integrity's list — unknown/missing keys fail loud at load.
_OBSOLETE_ASSET_KEYS: dict[str, type] = {
    "name": str, "note": str, "enabled": bool,
}


def _load_obsolete_assets(key: str, raw: Any) -> list[dict]:
    """Validate one obsolete_assets signatures list (see
    :data:`_OBSOLETE_ASSET_KEYS`).  An empty list is valid and is the
    shipped default: nothing is planned until the operator enables a
    signature."""
    if not isinstance(raw, list):
        raise SettingsError(f"{key}: expected a list of signatures")
    out: list[dict] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise SettingsError(f"{key}[{i}]: expected an object")
        unknown = set(entry) - set(_OBSOLETE_ASSET_KEYS)
        if unknown:
            raise SettingsError(f"{key}[{i}]: unknown keys {sorted(unknown)}")
        missing = set(_OBSOLETE_ASSET_KEYS) - set(entry)
        if missing:
            raise SettingsError(f"{key}[{i}]: missing keys {sorted(missing)}")
        sig = {}
        for field_name, field_type in _OBSOLETE_ASSET_KEYS.items():
            sig[field_name] = _coerce(field_type, f"{key}[{i}].{field_name}",
                                      entry[field_name])
        if not sig["name"].strip():
            raise SettingsError(
                f"{key}[{i}].name: a blank pattern matches every file — the "
                f"signature would name the whole webroot"
            )
        out.append(sig)
    return out


#: The list-of-objects validators, ONE per (owning dataclass, field) — the
#: single table both the profile loader (``_load_section``) and the ``--set``
#: path (``_override_value``) dispatch through, so a signature list can
#: never be validated by one path and accepted raw by the other.
_LIST_OF_OBJECT_VALIDATORS: dict[tuple[str, str], Any] = {
    ("CoreIntegritySettings", "known_added"): _load_known_added,
    ("CoreIntegritySettings", "known_stale"): _load_known_added,
    ("ObsoleteAssetSettings", "known_added"): _load_obsolete_assets,
    ("WebScriptSettings", "signatures"): _load_web_script_signatures,
    ("WebScriptSettings", "request_globals"): _load_web_script_signatures,
    ("WebScriptSettings", "known_artifacts"): _load_web_script_artifacts,
}

#: Section list fields with a SHAPE of their own.  The same table serves the
#: profile loader and ``--set``, so a value the file door refuses is never
#: accepted by the override door (or vice versa).
_SECTION_STRING_LIST_VALIDATORS: dict[tuple[str, str], Any] = {
    ("ConditionalJunkSettings", "page_cache_dirs"): _load_prefix_list,
}


#: The sections whose EVERY key the profile must spell out (see
#: :func:`_load_section`).  These are the sections an operator is expected
#: to read, change and be shown: deploy, webp, update, http, proxy plus the
#: newer probe, logs, tls, source_scan, discover and files sections.
#: (core_integrity/suspicious deliberately keep their omitted-list default.)
_COMPLETE_SECTIONS = frozenset({"DeploySettings", "WebpSettings",
                                "UpdateSettings", "HttpSettings",
                                "WpOrgSettings", "ProxySettings", "ProbeSettings",
                                "LogsSettings", "TlsSettings",
                                "SourceScanSettings", "DiscoverSettings",
                                "FilesSettings"})


def _load_section(section_dc: type, key: str, raw: dict[str, Any]) -> Any:
    fields = {f.name: f for f in section_dc.__dataclass_fields__.values()}
    unknown = set(raw) - set(fields)
    if unknown:
        raise SettingsError(f"{key}: unknown keys {sorted(unknown)}")
    if section_dc.__name__ in _COMPLETE_SECTIONS:
        # EVERY key of these sections must be present in the profile.  A
        # missing one used to fall back to the dataclass default silently,
        # which is the shape of the defect this closes from the other side:
        # a knob deleted from wpt/data/profiles/default.json (or a key added to
        # a dataclass and forgotten in the profile) left the section loading
        # with a value nobody wrote down, and `to_diff` — which compares
        # against the profile — reported nothing, because the fallback and
        # the profile agreed by construction.
        #
        # These sections and not the older ones: the older ones deliberately
        # read an OMITTED list as the empty list (``core_integrity.known_
        # stale`` ships that way), so requiring a key there would refuse the
        # shipped profile itself.  A user profile cannot reach this at all:
        # it is deep-merged over the shipped one, so a partial section is
        # only ever a hand-edited default.
        missing = set(fields) - set(raw)
        if missing:
            raise SettingsError(f"{key}: missing keys {sorted(missing)}")
    kwargs = {}
    for name, f in fields.items():
        if name in raw:
            # A list[dict] section field is detected by its OWNING validator
            # (both a live GenericAlias and a postponed-annotation string
            # are normalized by the dataclass's field name), never by its
            # rendered type name: two sections now carry signature lists
            # with DIFFERENT key sets, and a type-based dispatch would send
            # obsolete_assets through core_integrity's validator.
            validator = _LIST_OF_OBJECT_VALIDATORS.get(
                (section_dc.__name__, name)
            )
            if validator is not None:
                kwargs[name] = validator(f"{key}.{name}", raw[name])
                continue
            list_validator = _SECTION_STRING_LIST_VALIDATORS.get(
                (section_dc.__name__, name))
            if list_validator is not None:
                kwargs[name] = list_validator(f"{key}.{name}", raw[name])
                continue
            expected = f.type if isinstance(f.type, str) else getattr(f.type, "__name__", "")
            typemap = {"int": int, "float": float, "str": str, "bool": bool}
            typ = typemap.get(expected)
            if typ is None and expected == "list":
                # list-of-strings section fields (suspicious.patterns) take
                # the same contract as the top-level pattern lists — the ONE
                # validator, shared with the override path
                kwargs[name] = _load_str_list(f"{key}.{name}", raw[name])
            else:
                kwargs[name] = _coerce(typ, f"{key}.{name}", raw[name])
    return section_dc(**kwargs)


#: Every settings section: the ONE table the loader (``_load``) and the
#: diff (``to_diff``) both read, so a section can never be loaded and then
#: silently missing from a report.  This is the loader's own grouping
#: order; it intentionally does not mirror the profile JSON's key order
#: (the profile's newer sections sit at the end, while dataclass grouping
#: keeps probe/logs/tls next to their relatives here).
_SECTIONS: dict[str, type] = {
    "ftp": FtpSettings,
    "bridge": BridgeSettings,
    "probe": ProbeSettings,
    "db": DbSettings,
    "media_optimize": MediaOptimizeSettings,
    "media": MediaSettings,
    "core_integrity": CoreIntegritySettings,
    "http": HttpSettings,
    "wp_org": WpOrgSettings,
    "proxy": ProxySettings,
    "tls": TlsSettings,
    "log": LogSettings,
    "logs": LogsSettings,
    "backup": BackupSettings,
    "files": FilesSettings,
    "walk": WalkSettings,
    "discover": DiscoverSettings,
    "suspicious": SuspiciousSettings,
    "source_scan": SourceScanSettings,
    "backup_payloads": BackupPayloadSettings,
    "conditional_junk": ConditionalJunkSettings,
    "obsolete_assets": ObsoleteAssetSettings,
    "cull_media": CullMediaSettings,
    "env": EnvSettings,
    "run": RunSettings,
    "web_script": WebScriptSettings,
    "webp": WebpSettings,
    "deploy": DeploySettings,
    "update": UpdateSettings,
}


def _load(raw: dict[str, Any]) -> Settings:
    sections = _SECTIONS
    lists = _TOP_LEVEL_LISTS
    maps = _TOP_LEVEL_MAPS
    nested_lists = _TOP_LEVEL_NESTED_LISTS
    unknown = set(raw) - set(sections) - set(lists) - set(maps) - set(nested_lists)
    if unknown:
        raise SettingsError(f"unknown top-level keys: {sorted(unknown)}")

    s = Settings()
    for key, dc in sections.items():
        if key in raw:
            if not isinstance(raw[key], dict):
                raise SettingsError(f"{key}: expected object")
            setattr(s, key, _load_section(dc, key, raw[key]))
    for key in lists:
        if key in raw:
            setattr(s, key, _top_level_list(key, raw[key]))
    for key in maps:
        if key in raw:
            setattr(s, key, _load_str_map(key, raw[key]))
    for key in nested_lists:
        if key in raw:
            setattr(s, key, _load_str_lists(key, raw[key]))
    _check_duplicate_preferences(
        s.duplicate_plugin_groups, s.duplicate_plugin_groups_preferred
    )
    return s


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Deep-merge a user profile over defaults; nested objects merge, lists replace."""
    out = json.loads(json.dumps(base))
    for key, value in overlay.items():
        if key in out and isinstance(out[key], dict) and isinstance(value, dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def effective_profile_path(profile_path: str | Path | None) -> Path:
    """The profile file THIS run reads: the explicit one or the packaged default.

    ``load`` always reads ``_DEFAULT_PROFILE`` as its base, so a run without
    ``--profile`` still has a local input.  The report-collision owner must
    protect that file exactly like an explicit profile; returning the
    effective path from ONE function keeps the CLI and every programmatic
    caller from having to remember the default.
    """
    return Path(profile_path) if profile_path is not None else _DEFAULT_PROFILE


def load(profile_path: str | None = None,
         overrides: dict[str, Any] | None = None) -> Settings:
    """Load Settings from default.json (+ optional user profile) + dot-path overrides."""
    defaults = json.loads(_DEFAULT_PROFILE.read_text(encoding="utf-8"))
    raw: dict[str, Any] = defaults
    if profile_path is not None:
        try:
            user = loads_bounded(Path(profile_path).read_text(encoding="utf-8"))
            if not isinstance(user, dict):
                raise SettingsError(
                    f"{profile_path}: profile must be a JSON object")
            raw = _deep_merge(defaults, user)
        except SettingsError:
            raise
        except (RecursionError, MemoryError) as exc:
            # A deeply nested profile exhausts the decoder/merge recursion;
            # an operator input must be the one-line settings refusal, never
            # a traceback out of main() with no report pair.
            raise SettingsError(
                f"{profile_path}: profile JSON is too deeply nested or too "
                "large to decode") from exc
    settings = _load(raw)
    for dotted, value in (overrides or {}).items():
        apply_override(settings, dotted, value)
    return settings


def to_diff(settings: Settings) -> dict[str, Any]:
    """Return only the values that differ from the packaged defaults."""
    defaults = _load(json.loads(_DEFAULT_PROFILE.read_text(encoding="utf-8")))
    diff: dict[str, Any] = {}
    for section_name in _SECTIONS:
        cur, dflt = asdict(getattr(settings, section_name)), asdict(getattr(defaults, section_name))
        sub = {k: v for k, v in cur.items() if v != dflt.get(k)}
        if sub:
            diff[section_name] = sub
    for key in ("webroot_junk", "stale_content_dirs", "ghost_table_prefixes",
                "migration_leftovers", "known_heavy", "duplicate_plugin_groups",
                "duplicate_plugin_groups_preferred",
                "ghost_marker_plugins", "mu_plugin_known_platform"):
        cur = getattr(settings, key)
        if cur != getattr(defaults, key):
            diff[key] = cur
    return diff
