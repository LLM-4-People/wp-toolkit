"""Database audit checks (W6d): pure functions over AuditData + Settings.

Module named ``dbcheck`` (not ``db``) so it cannot collide conceptually
with the wpt.localmode data layer; the CHECK names still use the ``db.``
dotted prefix. Every check registers through
``wpt.audit.registry.register_check`` with ``applies=("ftp", "local")``
(the AuditData contract is mode-agnostic) and has the uniform signature
``func(data: AuditData, settings: Settings) -> list[Finding]``. All
thresholds and marker lists come from ``Settings``
(wpt/data/profiles/default.json), never from literals; nothing here mutates
``data``; multi-finding results are sorted by ``(category, name)``; no
per-check logging (the registry already logs durations and outcomes).

Unknown vs measured zero (the AuditData contract, binding for every
check here): None on a scalar field is UNKNOWN for the mode and always
silent; 0 is a real measured zero; an empty dict/list means the mode
cannot know that fact. Never conflate the two.

Check semantics:

* db.revisions / db.transients — report only a measured count > 0
  (None unknown and measured 0 are both silent). Reclaimed bytes of
  revision/transient ROWS are unknowable from the gathered facts, so
  those findings carry bytes=0 and only counts.
* db.orphan_meta — {} is UNKNOWN (never "zero orphans"); a kind key
  PRESENT at 0 is a measured zero; only kinds PRESENT with count > 0
  are reported, one finding per kind (key presence is tested, never a
  default-0 lookup).
* db.ghost_tables — a table is ghost when a
  settings.ghost_table_prefixes marker matches its name AND the marker's
  plugin slug is not active. Marker-to-slug: settings.ghost_marker_plugins
  maps a marker to the plugin slug that owns its tables when they differ
  (markers are table-name tokens, not slugs: "nf3" tables belong to the
  "ninja-forms" plugin, "statistics" to "wp-statistics"); an unmapped
  marker is its own slug (an active "woocommerce/woocommerce.php" keeps
  wp_woocommerce_* out of the finding). Active slugs are the first path
  component of each data.active_plugins entry, via the shared
  wpt.audit.webroot helper. Matching semantics (structural, NOT tunable): WordPress
  joins table-name segments with "_", so a "_"-free marker matches
  only a WHOLE "_"-split component ("woocommerce" matches
  "wp_woocommerce_orders" but not "wp_xwoocommerce"); a marker that
  itself contains "_" (e.g. "actionscheduler_actions") can never be a
  "_"-split component and matches by SUBSTRING instead (real names
  like "wp_actionscheduler_actions"). An empty marker matches nothing
  (malformed profile data must not flag tables). One aggregate
  finding: count = ghost tables, bytes = sum of known sizes (unknown
  size_bytes contributes nothing, never a fake 0), detail =
  name-sorted "table (rows, size)" lines with the size omitted when
  unknown, risk medium (user data — deletion is the operator's call).
  tables == {} (no table facts) is silent.
* db.autoload — two signals in priority order: a non-empty
  big_autoload_options list (gathered at or above
  settings.db.autoload_big_bytes; the check consumes it as-is) yields
  the per-option finding; otherwise autoload_bytes, when known (not
  None), at or above settings.db.autoload_total_warn_bytes yields the
  total finding. [] in ftp mode means "only the byte total is known",
  NOT "no big options" — exactly why the total signal exists.
* db.optimize — tables whose data_free_bytes is known (not None) and
  at or above settings.db.free_space_warn_bytes; detail lines sorted
  free-bytes descending.
* db.charset — utf8mb4 is the modern WordPress default charset (a
  STRUCTURAL fact, not a tunable: WP has required utf8mb4 for new
  installs since 4.2). A charset present on SOME tables means the
  fact was measured: a table whose charset is KNOWN (not None —
  unknown never counts) and not utf8mb4 is reported; a measured
  all-utf8mb4 set, all-unknown charsets and {} tables are all
  silent. One aggregate finding: count = affected tables, detail =
  name-sorted "table (charset)" lines.
* db.admin_accounts — admin_users None is UNKNOWN for the mode
  (silent — no users facts could be gathered) and [] is a measured
  empty (a site with no admins is not actionable noise): both silent.
  Both modes gather the roster (remote: the bridge's admins query;
  local: the analyzer's wp_users/wp_usermeta user_level=10 join), and
  the finding fires
  only when a privileged account's login is exactly "admin"
  (case-insensitive) — the default login is the single biggest
  brute-force magnet (structural fact); the detail carries the FULL
  login-sorted admin roster ("*" on offenders; a None/empty
  registered renders "unknown"), so the roster rides along only
  when there is an offender. Entries carry an "admin" flag and only
  privileged ones are read (the wire list may widen beyond admins
  in a later revision).

Risk classification: revisions/transients/orphan-meta/optimize are
routine, reversible cleanup — "low"; ghost tables, autoload and
charset conversion touch user data or live site behavior, so they
need the operator's call — "medium"; the default 'admin' login is
actively exploited by every botnet — "high".

Presentation limits fixed by the W6d check contract (not tunables):
max detail lines per finding before the "(+N more)" truncation marker.
Structural WordPress facts consumed as constants (not tunables):
utf8mb4 (the default charset WP has required for new installs
since 4.2) and the classic default "admin" login.
"""

from .data import AuditData
from .registry import register_check
from ..settings import Settings
from ..types import Finding

# Presentation limit fixed by the W6d check contract (not a tunable):
# example table/option/admin lines per detail before the "(+N more)" marker.
_DETAIL_TABLES = 8

# The modern WordPress default charset (structural fact, not a tunable):
# WP has required utf8mb4 for new installs since 4.2 — any other charset
# corrupts accents/emoji on import and blocks clean migrations.
_UTF8MB4 = "utf8mb4"

# The classic default administrator login (structural fact, not a
# tunable): "admin" is the single login every brute-force botnet tries
# first on wp-login.
_DEFAULT_ADMIN_LOGIN = "admin"


# ----------------------------------------------------------- shared internals


def _detail_lines(items: list[str]) -> str:
    """Up to _DETAIL_TABLES newline-joined lines; "(+N more)" if truncated."""
    if len(items) <= _DETAIL_TABLES:
        return "\n".join(items)
    return "\n".join(items[:_DETAIL_TABLES]) + f"\n(+{len(items) - _DETAIL_TABLES} more)"


def _ghost_marker_matches(marker: str, table: str) -> bool:
    """Does one ghost marker match one table name? (see module docstring)

    "_"-free markers align on whole "_"-split components; markers that
    contain "_" match by substring (a "_"-split component can never
    contain the separator). An empty marker matches nothing.
    """
    if not marker:
        return False
    if "_" in marker:
        return marker in table
    return marker in table.split("_")


def _admin_roster_line(entry: dict, offender: bool) -> str:
    """One admin roster line: "login (registered ...)"; "*" marks offenders.

    The registered timestamp renders verbatim as gathered; a None or
    empty one renders "unknown" — the fact was not gathered, never a
    guessed date.
    """
    registered = entry.get("registered")
    mark = "*" if offender else ""
    when = registered if registered else "unknown"
    return f"{entry['login']}{mark} (registered {when})"


# ------------------------------------------------------------------- checks


@register_check("db.revisions", applies=("ftp", "local"))
def check_db_revisions(data: AuditData, settings: Settings) -> list[Finding]:
    """Revision + auto-draft posts: one finding when measured > 0.

    None (unknown for the mode) and a measured 0 are both silent; the
    bytes reclaimed per revision row are unknowable from the gathered
    facts, so the finding carries bytes=0 and only the count.
    """
    if data.revisions is None or data.revisions <= 0:
        return []
    return [
        Finding(
            category="db.revisions",
            name="revisions",
            detail="revision and auto-draft posts",
            bytes=0,
            count=data.revisions,
            risk="low",
            fix="remove via clean-db revisions",
        )
    ]


@register_check("db.transients", applies=("ftp", "local"))
def check_db_transients(data: AuditData, settings: Settings) -> list[Finding]:
    """Expired transients: one finding when measured > 0 (None/0 silent)."""
    if data.expired_transients is None or data.expired_transients <= 0:
        return []
    return [
        Finding(
            category="db.transients",
            name="expired-transients",
            detail="expired transient options",
            bytes=0,
            count=data.expired_transients,
            risk="low",
            fix="remove via clean-db expired_transients",
        )
    ]


@register_check("db.orphan_meta", applies=("ftp", "local"))
def check_db_orphan_meta(data: AuditData, settings: Settings) -> list[Finding]:
    """Orphaned meta rows: one finding per kind PRESENT with count > 0.

    {} means UNKNOWN (never "zero orphans") and a kind key present at 0
    is a measured zero — both silent. Key presence is tested, never a
    default-0 lookup. Row bytes are unknowable; findings carry counts.
    """
    findings = [
        Finding(
            category="db.orphan_meta",
            name=kind,
            detail=f"orphaned {kind} rows (owner object gone)",
            bytes=0,
            count=count,
            risk="low",
            fix="remove via clean-db orphan_meta",
        )
        for kind, count in data.orphan_meta.items()
        if count > 0
    ]
    findings.sort(key=lambda f: (f.category, f.name))
    return findings


@register_check("db.ghost_tables", applies=("ftp", "local"))
def check_db_ghost_tables(data: AuditData, settings: Settings) -> list[Finding]:
    """Tables left behind by inactive/removed plugins: one aggregate finding.

    Ghost when a settings.ghost_table_prefixes marker matches the table
    name (component / substring — see _ghost_marker_matches) and the
    marker's plugin slug (settings.ghost_marker_plugins[marker] when the
    marker is mapped, else the marker itself) is not an active plugin slug.
    An UNMEASURED active set (an options-table identity that is absent
    or contested, or an ``active_plugins`` value that is not a readable
    serialized list) reports nothing at all: "no marker matches an ACTIVE
    plugin" is unknowable without one, and a ghost table a removed plugin
    still owns is exactly what this check exists to surface.  The same
    three-state rule governs db.active_missing.
    An unknown size_bytes contributes nothing to the byte sum and the size
    is omitted from its detail line; detail lines are name-sorted. User
    data — the fix asks for review + backup, never an auto-drop.
    """
    if not data.tables:
        return []
    from .webroot import _active_plugin_slugs_measured
    measured = _active_plugin_slugs_measured(data)
    if measured is None:
        # The active set was not MEASURED: "no marker matches an ACTIVE
        # plugin" is unknowable, and a ghost table that a removed plugin
        # still owns is exactly what this check exists to surface. Report
        # nothing rather than crash or guess.
        return []
    active = measured
    ghost = sorted(
        (
            (name, fact)
            for name, fact in data.tables.items()
            if any(
                _ghost_marker_matches(marker, name)
                for marker in settings.ghost_table_prefixes
                if settings.ghost_marker_plugins.get(marker, marker) not in active
            )
        ),
        key=lambda pair: pair[0],
    )
    if not ghost:
        return []
    lines = [
        f"{name} ({fact.rows} rows, {fact.size_bytes} B)"
        if fact.size_bytes is not None
        else f"{name} ({fact.rows} rows)"
        for name, fact in ghost
    ]
    return [
        Finding(
            category="db.ghost_tables",
            name="ghost-tables",
            detail=_detail_lines(lines),
            bytes=sum(fact.size_bytes for _name, fact in ghost
                      if fact.size_bytes is not None),
            count=len(ghost),
            risk="medium",
            fix="review with the operator; back up before dropping",
        )
    ]


@register_check("db.autoload", applies=("ftp", "local"))
def check_db_autoload(data: AuditData, settings: Settings) -> list[Finding]:
    """Autoloaded options: per-option list first, else the byte total.

    Priority order (binding): a non-empty big_autoload_options list
    yields the per-option finding (size-descending detail); otherwise
    the known autoload_bytes total at or above
    settings.db.autoload_total_warn_bytes yields the total finding.
    Both signals unknown/quiet -> [].
    """
    if data.big_autoload_options:
        options = sorted(
            data.big_autoload_options, key=lambda item: (-item[1], item[0])
        )
        return [
            Finding(
                category="db.autoload",
                name="big-autoload-options",
                detail=_detail_lines(
                    [f"{name} ({size} B)" for name, size in options]
                ),
                bytes=sum(size for _name, size in options),
                count=len(options),
                risk="medium",
                fix="review; de-autoload or delete unused options",
            )
        ]
    total = data.autoload_bytes
    if total is not None and total >= settings.db.autoload_total_warn_bytes:
        return [
            Finding(
                category="db.autoload",
                name="autoload-total",
                detail="total autoloaded options exceed the warn level",
                bytes=total,
                count=1,
                risk="medium",
                fix="review; de-autoload or delete unused options",
            )
        ]
    return []


@register_check("db.optimize", applies=("ftp", "local"))
def check_db_optimize(data: AuditData, settings: Settings) -> list[Finding]:
    """Tables with reclaimable free space: one aggregate finding.

    A table qualifies when data_free_bytes is known (not None) and at
    or above settings.db.free_space_warn_bytes; detail lines are
    free-bytes descending. Routine maintenance, risk low.
    """
    candidates = sorted(
        (
            (name, fact.data_free_bytes)
            for name, fact in data.tables.items()
            if fact.data_free_bytes is not None
            and fact.data_free_bytes >= settings.db.free_space_warn_bytes
        ),
        key=lambda item: (-item[1], item[0]),
    )
    if not candidates:
        return []
    return [
        Finding(
            category="db.optimize",
            name="optimize-candidates",
            detail=_detail_lines(
                [f"{name} ({free} B)" for name, free in candidates]
            ),
            bytes=sum(free for _name, free in candidates),
            count=len(candidates),
            risk="low",
            fix="optimize via clean-db optimize_tables",
        )
    ]


@register_check("db.charset", applies=("ftp", "local"))
def check_db_charset(data: AuditData, settings: Settings) -> list[Finding]:
    """Tables not on the modern WP default charset: one aggregate finding.

    utf8mb4 is a STRUCTURAL fact, not a tunable: WordPress has
    required utf8mb4 for new installs since 4.2, and any other
    charset corrupts accents/emoji on import and blocks clean
    migrations. A charset present on SOME tables means the fact was
    measured: every table whose charset is KNOWN (not None — unknown
    for the mode never counts) and not utf8mb4 is reported; a
    measured all-utf8mb4 set, an all-unknown set and {} tables are
    all silent. Detail lines are name-sorted "table (charset)".
    The conversion rewrites user data but reclaims no bytes —
    risk medium, bytes 0.
    """
    if not data.tables:
        return []
    offenders = sorted(
        (name, fact.charset)
        for name, fact in data.tables.items()
        if fact.charset is not None and fact.charset != _UTF8MB4
    )
    if not offenders:
        return []
    return [
        Finding(
            category="db.charset",
            name="non-utf8mb4-tables",
            detail=_detail_lines(
                [f"{name} ({charset})" for name, charset in offenders]
            ),
            bytes=0,
            count=len(offenders),
            risk="medium",
            fix="Convert the table to utf8mb4 (a latin1 table corrupts "
                "accents/emoji on import and blocks clean migrations): "
                "ALTER TABLE ... CONVERT TO CHARACTER SET utf8mb4 "
                "COLLATE utf8mb4_unicode_ci; back up first.",
        )
    ]


@register_check("db.admin_accounts", applies=("ftp", "local"))
def check_db_admin_accounts(data: AuditData, settings: Settings) -> list[Finding]:
    """The default 'admin' login exists: one finding, roster in the detail.

    admin_users None is UNKNOWN for the mode — silent (local mode
    stays quiet until the analyzer round surfaces wp_users); [] is a
    real measured empty — a site with no admins is not actionable
    noise. The finding fires only when a privileged account's login
    is exactly "admin" (case-insensitive): the default login is the
    single biggest brute-force magnet (structural fact, not a
    tunable). The detail then carries the FULL admin roster,
    login-sorted, "*" marking offenders and an unknown registered
    date rendered "unknown" — the roster rides along only when
    there is an offender. Only entries with a true "admin" flag are
    read (the wire list may widen beyond admins in a later
    revision). Actively exploited by every botnet — risk high,
    bytes 0.
    """
    if not data.admin_users:
        return []
    roster = sorted(
        (entry for entry in data.admin_users if entry.get("admin")),
        key=lambda entry: entry["login"],
    )
    default = [
        entry for entry in roster
        if entry["login"].lower() == _DEFAULT_ADMIN_LOGIN
    ]
    if not default:
        return []
    lines = [
        _admin_roster_line(
            entry, entry["login"].lower() == _DEFAULT_ADMIN_LOGIN
        )
        for entry in roster
    ]
    return [
        Finding(
            category="db.admin_accounts",
            name="default-admin-login",
            detail=_detail_lines(lines),
            bytes=0,
            count=len(default),
            risk="high",
            fix="Rename the default 'admin' account (create a new admin, "
                "log in as it, delete/reassign the old one): every botnet "
                "hammers wp-login with 'admin'.",
        )
    ]
