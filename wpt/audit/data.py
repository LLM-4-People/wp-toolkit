"""Audit data layer (W6b): one mode-agnostic site model for every check.

SPEC §Audit modules (W6): the same data shape feeds checks from both
sources.  :func:`gather_remote` (ftp mode) builds it from the PHP bridge
(``info`` + ``db_audit``) plus one source walk; :func:`gather_local`
(local mode) builds it from the SQL-dump analyzer plus one source walk.
Checks (W6c+) are pure functions over ``AuditData`` + ``Settings``; the
registry passes the gathered object through opaquely, so this module is
imported only by the CLI wiring (W6h) and by callers of the gatherers —
never by ``wpt.audit.registry``.

Unknown vs measured zero (the contract every check relies on):
    * a scalar Optional field is None when the value is UNKNOWN for the
      mode; 0 is always a real measured zero.  Never substitute one for
      the other in a check.
    * dict/list fields use emptiness for "no data":
        ``posts == {}``                 — no post facts available at all;
        ``orphan_meta == {}``           — unknown (see AuditData);
        ``plugin_catalog == {}``        — local mode (a zip carries no
                                           reliable plugin version data);
        ``big_autoload_options == []``  — ftp mode (only the byte total
                                           is known, not per-option sizes);
        ``admin_users == []``           — a REAL measured empty (the users
                                           query ran — bridge SQL remotely,
                                           the dump's wp_users/wp_usermeta
                                           locally — and matched no
                                           user_level=10 account); None
                                           means no users facts at all.

Wire tolerance (gather_remote): the bridge contract
(tests/test_bridge_php.py) pins ``db_audit.posts`` rows as objects
``{"post_type", "post_status", "count"}``; the positional
``[post_type, post_status, count]`` row form is accepted as well.  A
missing key, a None value or a wrong-typed value degrades to that field's
unknown value — gathering never raises on a malformed payload FIELD; a
failing bridge CALL (transport/protocol error) still raises
:class:`~wpt.types.BridgeError`: that is a source failure, not missing
data.  ``db_audit.users`` gets per-entry validation (see
:func:`_admin_users_from_wire`): malformed entries are dropped with one
debug summary, never raised over and never logged with their contents.

Logging discipline (mirrors wpt.localmode.analyzer): one info summary per
gather carrying structural counts only (mode, walked entries, plugin and
table counts) — never option values, URLs, plugin names or cell contents.
"""

from __future__ import annotations

import re
from collections.abc import Sized
from dataclasses import dataclass, field
from typing import Any, BinaryIO

from ..localmode.analyzer import SiteModel, analyze
from ..log import get_logger
from ..media_refs import db_refs_from_dump
from ..settings import Settings
from ..types import Entry, Source, SourceError
from ..wpbridge.client import Bridge

log = get_logger("audit.data")

__all__ = ["AuditData", "TableFact", "gather_local", "gather_remote",
           "gather_source"]

#: The uploads directory relative to the webroot — the only offline-known
#: form of :attr:`AuditData.uploads_basedir` (structural WP path, not a
#: tunable).
_UPLOADS_RELPATH = "wp-content/uploads"


@dataclass
class TableFact:
    """Row/size facts about one DB table (estimates; mode-dependent source).

    rows: row count (bridge: an information_schema estimate; analyzer:
        the INSERT tuple count).
    size_bytes: approximate table size in bytes; None when unknown.  The
        bridge reports megabytes — stored as round(size_mb * 1048576);
        the analyzer's value is its scanned INSERT-tuple byte total.
    data_free_bytes: reclaimable-space estimate; None when unknown —
        always None in local mode (a dump cannot know engine internals).
        The bridge reports kilobytes — stored as round(data_free_kb * 1024).
    collation: the table's full collation name ("utf8mb4_general_ci");
        None when unknown.  The wire sends "" for a NULL TABLE_COLLATION —
        mapped to None (the None = unknown discipline), while a real
        collation passes through.  Remote only for now: always None in
        local mode (a dump's CREATE TABLE text states the charset but not
        the full collation; richer local collation facts land with the
        analyzer round).
    charset: the table's CHARACTER SET name ("utf8mb4") — the fact the
        charset check reads.  None when unknown.  Remote: derived from
        the collation prefix (MySQL names collations "<charset>_<rules>";
        a collation with no underscore, like "binary", is its own
        charset).  Local: the ``DEFAULT CHARSET=X`` token parsed from the
        CREATE TABLE text the analyzer already harvested — never guessed
        from the dump-wide SET NAMES when the clause is absent.
    """

    rows: int
    size_bytes: int | None
    data_free_bytes: int | None
    collation: str | None = None
    charset: str | None = None


@dataclass
class AuditData:
    """One site's gathered facts — the single input every audit check reads.

    Built by :func:`gather_remote` (ftp mode) or :func:`gather_local`
    (local mode) and handed to checks as ``func(data, settings)`` by
    ``wpt.audit.registry.run_checks`` (which treats it as opaque).

    Field semantics (binding for W6c+ check writers):

    mode
        "ftp" or "local" — matches ``wpt.audit.registry.MODES``.
    entries
        The walked source tree (dirs + files, symlinked dirs skipped) in
        walk order; paths relative to the source root (the CLI roots the
        source at the webroot, so paths are webroot-relative).  In ftp
        mode the deployed bridge file ("bridge-<8hex>.php") is part of
        the tree: the bridge calls happen before the walk and the file is
        destroyed afterwards.
    siteurl / home / template
        The WP options.  None when unknown (remote: absent from the info
        payload; local: option absent or unreadable in the dump).
    blog_public
        The option as an int; None when unknown.
    wp_version
        WP core version.  Remote: ``get_bloginfo``; local: read from
        wp-includes/version.php through the source (best effort; a
        missing/unparseable file stays None — unknown, never guessed).
    locale
        The SITE locale — WordPress's content language, NOT necessarily
        the core build's locale (an en_US build plus a fr_CA language
        pack also stores fr_CA).  Remote: the bridge ``info``'s
        ``locale`` (WP's own get_locale()); local: the analyzer's
        WPLANG option fact.  None when unknown; the integrity check
        resolves the COMPARISON locale from this (its own semantics —
        the data layer stays facts).
    mu_plugins
        Remote only (must-use plugin count; 0 is a real measured zero);
        always None in local mode.
    active_plugins
        Active plugin FILE paths ("akismet/akismet.php"), or None when the
        active set was NOT MEASURED — never an empty list for a gap, and
        [] is a real answer (a site running no plugins measures []).
        Remote: catalog entries with ``active`` true, in catalog key order
        (the bridge reads WordPress's own answer, so it is always
        measured).  Local: ``SiteModel.active_set.plugins`` — None when the
        dump's options-table identity is absent or contested, or the
        ``active_plugins`` option is not a readable serialized list.
    plugin_catalog
        plugin_file -> {"name", "version", "active"} (remote).  Always {}
        in local mode — a zip carries no reliable plugin version data;
        checks that only need file paths must use active_plugins instead.
    uploads_basedir
        Where uploaded media lives.  Remote: the server-absolute
        ``wp_upload_dir()`` basedir.  Local: the literal
        "wp-content/uploads" when the walked tree contains that path
        (an empty/absent uploads directory is undetectable offline —
        None, correct, since there is no media inside it to audit).
    posts
        (post_type, post_status) -> row count; a ("", "") group is
        possible (NULL/empty cells).  {} means no post facts were
        available (remote: no usable db_audit posts rows; local: no
        usable posts table).
    revisions
        Count of revision + auto-draft posts.  Remote: the bridge's
        db_audit rule (post_type = 'revision' OR post_status =
        'auto-draft').  Local: the exact mirror, derived from posts — so
        it reads 0 when posts is {}; treat it as known only when posts
        is non-empty.  None when unknown (remote only).
    expired_transients
        Expired transient count; None when unknown — always None in local
        mode (undeterminable offline).
    orphan_meta
        postmeta/termmeta/commentmeta -> orphan row counts.  {} means
        UNKNOWN — the local mode cannot know, or the remote key was
        absent — NOT "zero orphans": the bridge reports measured zeros as
        explicit keys with value 0.  Trust present keys (even at 0) and
        treat absent ones as unknown.
    attachments
        Attachment post count.  Remote: all attachment posts; local:
        ``posts.get(("attachment", "inherit"), 0)`` — inherit is the
        standard attachment status.  None when unknown (remote only).
    nav_menu_items
        Nav-menu item count over ALL statuses (never guess a status
        subset).  None when unknown (remote only).
    autoload_bytes
        Total bytes of autoloaded options; None when unknown — always
        None in local mode (only big_autoload_options is known there).
    big_autoload_options
        (option_name, size_bytes) for autoloaded options at or above
        settings.db.autoload_big_bytes, size-descending (local mode
        only).  [] in ftp mode means UNKNOWN (the bridge reports only
        the autoload_bytes total), never "no big options".
    tables
        table name -> :class:`TableFact`; {} means no table facts at all.
        TableFact additionally carries per-table collation (remote only
        for now) and charset (both modes) for the charset check — see
        TableFact.
    admin_users
        The site's administrator accounts as wire-shaped maps:
        ``{"login": str, "registered": str | None, "admin": True}`` —
        ADMINS ONLY, sorted by login.  The check reads privileged
        accounts (default 'admin' login, dormant accounts); a future
        revision may widen the list without reshaping entries.
        Remote: the db_audit users payload.  Local: parsed from the
        dump's wp_users/wp_usermeta (user_level=10) — the same rule and
        entry shape, so the check never depends on the mode.  [] is a
        REAL measured empty (the users query ran — remotely in SQL,
        locally over the parsed tables — and no user_level=10 account
        matched), while None means unknown — the bridge could not
        discover the users/usermeta tables or the prefix, or the key
        was absent; locally, wp_users or wp_usermeta is missing from
        the dump or lacks its required columns.
    live_refs
        The live media reference set from ``wpt walk`` (W7 wires it);
        None until then — media checks MUST degrade when it is None.
    db_refs
        The DATABASE-referenced media half of the media keep-set
        (``wpt.media_refs`` — the union of the two is what the
        ``media.unreferenced`` finding and the trim-media plan delete
        against; a page renders only a fraction of its attachments, and a
        walk-only trim deletes what it never sees).  Uploads-relative
        POSIX paths, the same shape as ``live_refs``.  Local mode:
        measured from the .sql dump by :func:`gather_local` (the only
        offline source).  Ftp mode: None here, because the measurement is
        a full postmeta/options scan — the media check fetches it lazily
        through the bridge once and memoizes it on this field
        (``wpt.media_refs.db_refs_for_data``), so an audit that skips the
        media checks never pays for it.  None always means UNKNOWN (no
        bridge, an unreadable dump, a failed call), never an empty set.
    probe
        Transport facade for remote-only probes (the security checks);
        a ``wpt.audit.security.SiteProbe`` assembled by the audit runner
        (session + site + bridge + source).  None in local mode — remote
        checks registered for ftp only must stay silent on None anyway.
    pages
        Walked page URLs (W7 wires it); None until then.  Sampled by the
        HTTPS-redirect check; a None means "homepage only" — documented
        limitation, never a guess.
    """

    mode: str
    entries: list[Entry]
    # site facts — None when unknown for the mode
    siteurl: str | None
    home: str | None
    template: str | None
    blog_public: int | None
    wp_version: str | None
    mu_plugins: int | None
    #: The site's active plugin slugs, or None when the database could not
    #: measure them (an options-table identity that is absent or contested, or
    #: an active_plugins value that is not a readable serialized list). None
    #: is "unknown", which is NOT [] — a site running no plugins measures [].
    #: A destructive consumer must refuse on None; a reporting check must
    #: say it could not measure rather than report every plugin as inactive.
    active_plugins: list[str] | None
    plugin_catalog: dict[str, dict]
    uploads_basedir: str | None
    # DB facts — None when unknown for the mode
    posts: dict[tuple[str, str], int]
    revisions: int | None
    expired_transients: int | None
    orphan_meta: dict[str, int]
    attachments: int | None
    nav_menu_items: int | None
    autoload_bytes: int | None
    big_autoload_options: list[tuple[str, int]]
    tables: dict[str, TableFact]
    # admin accounts (users check): wire-shaped maps; None when unknown —
    # remote: discovery failed; local: wp_users/wp_usermeta absent from
    # the dump or unusable
    admin_users: list[dict] | None = None
    # the SITE locale (None when unknown; see the field docs above) —
    # remote: the bridge info's get_locale(); local: the analyzer's
    # WPLANG option fact
    locale: str | None = None
    # active theme dir (slug) -> style.css header Version (both modes,
    # best-effort read via the source; a slug absent = version unknown)
    theme_versions: dict[str, str] = field(default_factory=dict)
    # later inputs (W7 wires them); checks must degrade when None
    live_refs: set[str] | None = None
    # the DATABASE-referenced media set (see the field docs): measured here
    # in local mode (the dump is the only offline source), fetched lazily
    # over the bridge by the media check in ftp mode.  None = unknown
    db_refs: set[str] | None = None
    probe: Any = None
    pages: list[str] | None = None
    # the gather's Source (both modes) — for checks that read file CONTENT
    # lazily at check time (the suspicious-pattern scanner); never None
    # when a check runs, because every gather sets it
    source: Any = None
    # the run's self-bounding budget (wpt.deadline.Deadline built by the
    # audit runner from ctx — None = unbounded); bulk-scan checks check()
    # it between batches so a crawling run ends itself
    deadline: Any = None


# ---------------------------------------------------------- wire extraction


def _opt_str(raw: Any) -> str | None:
    """A non-empty str from the wire; None for missing/None/other types."""
    return raw if isinstance(raw, str) and raw else None


def _opt_int(raw: Any) -> int | None:
    """An int from the wire (bools rejected); None when unusable."""
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return None
    return int(raw)


def _approx_bytes(raw: Any, unit: int) -> int | None:
    """round(raw * unit) for a numeric wire value; None when absent."""
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return None
    return round(raw * unit)


def _plugin_catalog(raw: Any) -> dict[str, dict[str, Any]]:
    """Normalize the info plugins map into file -> {"name","version","active"}.

    A missing map yields {}; malformed entries are skipped, never raised;
    kept entries get structural defaults for absent subkeys.  Key order
    (the bridge's ``get_plugins()`` order) is preserved.
    """
    if not isinstance(raw, dict):
        return {}
    catalog: dict[str, dict[str, Any]] = {}
    for file, entry in raw.items():
        if not isinstance(file, str) or not file or not isinstance(entry, dict):
            continue
        name = entry.get("name")
        version = entry.get("version")
        catalog[file] = {
            "name": name if isinstance(name, str) else "",
            "version": version if isinstance(version, str) else "",
            "active": bool(entry.get("active")),
        }
    return catalog


def _posts_from_wire(raw: Any) -> dict[tuple[str, str], int]:
    """Convert db_audit's posts rows into (post_type, post_status) -> count.

    The bridge contract sends objects {"post_type", "post_status",
    "count"}; the positional [post_type, post_status, count] row form is
    accepted too.  Rows repeating a group SUM (mirroring COUNT(*) over
    the same grouping); rows with a non-str type/status or without a
    usable count are skipped, never raised.
    """
    if not isinstance(raw, list):
        return {}
    posts: dict[tuple[str, str], int] = {}
    for row in raw:
        if isinstance(row, dict):
            post_type = row.get("post_type")
            post_status = row.get("post_status")
            count = row.get("count")
        elif isinstance(row, (list, tuple)) and len(row) == 3:
            post_type, post_status, count = row
        else:
            continue
        if not isinstance(post_type, str) or not isinstance(post_status, str):
            continue
        n = _opt_int(count)
        if n is None:
            continue
        key = (post_type, post_status)
        posts[key] = posts.get(key, 0) + n
    return posts


def _tables_from_wire(raw: Any) -> dict[str, TableFact]:
    """Convert db_audit's table rows into name -> TableFact.

    Documented approximations (the bridge reports information_schema
    estimates): size_bytes = round(size_mb * 1048576) and
    data_free_bytes = round(data_free_kb * 1024); either is None when the
    wire omitted it.  rows defaults to 0 when omitted.  collation is the
    wire string (the bridge's NULL TABLE_COLLATION arrives as "" — mapped
    to None, unknown); charset is derived from the collation prefix.
    Rows without a usable name are skipped, never raised.
    """
    if not isinstance(raw, list):
        return {}
    tables: dict[str, TableFact] = {}
    for row in raw:
        if not isinstance(row, dict):
            continue
        name = row.get("name")
        if not isinstance(name, str) or not name:
            continue
        rows = _opt_int(row.get("rows"))
        collation = _opt_str(row.get("collation"))
        tables[name] = TableFact(
            rows=rows if rows is not None else 0,
            size_bytes=_approx_bytes(row.get("size_mb"), 1048576),
            data_free_bytes=_approx_bytes(row.get("data_free_kb"), 1024),
            collation=collation,
            charset=_charset_from_collation(collation),
        )
    return tables


def _charset_from_collation(collation: str | None) -> str | None:
    """The collation's charset prefix ("utf8mb4_general_ci" -> "utf8mb4").

    MySQL names collations ``<charset>_<rules>``; a collation with no
    underscore IS a charset name ("binary").  None passes through.
    """
    if collation is None:
        return None
    return collation.split("_", 1)[0]


#: The ``DEFAULT CHARSET=X`` token inside a CREATE TABLE statement
#: (MySQL emits it in the table options tail; matched case-insensitively).
_CREATE_CHARSET_RE = re.compile(r"DEFAULT[ \t]+CHARSET[ \t]*=[ \t]*(\w+)",
                                re.IGNORECASE)


def _charset_from_create(create_sql: str) -> str | None:
    """The CREATE TABLE ``DEFAULT CHARSET=X`` token; None when absent.

    Real dumps state the charset per table (``) ENGINE=InnoDB DEFAULT
    CHARSET=utf8mb4``); a CREATE without the clause (hand-written dumps,
    or a table the analyzer only saw INSERTs for, where create_sql is
    empty) keeps None — unknown, never guessed from the dump-wide
    SET NAMES token.
    """
    match = _CREATE_CHARSET_RE.search(create_sql)
    return match.group(1) if match else None


def _orphan_meta_from_wire(raw: Any) -> dict[str, int]:
    """Keep the usable orphan_meta counts; {} when the map is absent.

    A kind with a missing/unusable count stays ABSENT — an absent key means
    unknown, never zero (the bridge reports measured zeros explicitly).
    """
    if not isinstance(raw, dict):
        return {}
    out: dict[str, int] = {}
    for kind, value in raw.items():
        if not isinstance(kind, str) or not kind:
            continue
        count = _opt_int(value)
        if count is not None:
            out[kind] = count
    return out


def _admin_users_from_wire(raw: Any) -> list[dict] | None:
    """Convert db_audit's users list into validated admin-account maps.

    None (unknown — no users facts) when the wire key is absent or null;
    the bridge sends null when its users/usermeta discovery fails.  []
    is a REAL measured empty and survives: per-entry validation keeps
    {"login": non-empty str, "registered": str | None, "admin": bool};
    malformed entries are dropped — one debug summary with the count,
    never raised over and never logged with their contents (logins are
    user data).
    """
    if not isinstance(raw, list):
        return None
    users: list[dict] = []
    dropped = 0
    for entry in raw:
        if (
            isinstance(entry, dict)
            and isinstance(entry.get("login"), str) and entry["login"]
            and (entry.get("registered") is None
                 or isinstance(entry.get("registered"), str))
            and isinstance(entry.get("admin"), bool)
        ):
            users.append({
                "login": entry["login"],
                "registered": entry["registered"],
                "admin": entry["admin"],
            })
        else:
            dropped += 1
    if dropped:
        log.debug("db_audit users: %d malformed entries dropped", dropped)
    return users


def _read_wp_version(source: Source) -> str | None:
    """WP core version from wp-includes/version.php (best effort; a
    missing/unparseable file stays None — unknown, never guessed)."""
    try:
        raw = source.read_bytes("wp-includes/version.php")
    except (SourceError, OSError):
        return None
    text = raw.decode("utf-8", errors="replace")
    match = re.search(r"\$wp_version\s*=\s*'([^']+)'", text)
    return match.group(1) if match else None


def _detect_uploads_dir(entries: list[Entry]) -> str | None:
    """"wp-content/uploads" when the walked tree shows it; else None.

    Offline the uploads directory is known only from the tree: either a
    path under "wp-content/uploads/" or that directory entry itself (a
    plain FILE named "wp-content/uploads" is not the directory).
    """
    for entry in entries:
        if entry.path.startswith(_UPLOADS_RELPATH + "/"):
            return _UPLOADS_RELPATH
        if entry.path == _UPLOADS_RELPATH and entry.is_dir:
            return _UPLOADS_RELPATH
    return None


def _theme_versions(source: Source, slugs: set[str]) -> dict[str, str]:
    """Active theme dir -> style.css header Version (best effort, both modes).

    A theme's version lives in its style.css file header — readable through
    the source in BOTH modes (ftp or zip), so the updates check can compare
    against wp.org without guessing.  A missing/unreadable style.css or a
    header without a Version line simply omits the slug (unknown).
    """
    versions: dict[str, str] = {}
    for slug in sorted(slugs):
        try:
            raw = source.read_bytes(f"wp-content/themes/{slug}/style.css")
        except SourceError:
            continue
        text = raw.decode("utf-8", errors="replace")
        # WordPress theme headers: "Version: 1.2.3" on its own line in the
        # top-of-file comment block.
        match = re.search(r"^[ \t]*[Vv]ersion[ \t]*:[ \t]*(.+?)[ \t]*$",
                          text, re.MULTILINE)
        if match:
            versions[slug] = match.group(1)
    return versions


# ---------------------------------------------------------------- gatherers


def _walk_bounded(source: Source, deadline: Any = None) -> list[Entry]:
    """Walk the tree, checking the run budget before every entry."""
    entries: list[Entry] = []
    for entry in source.walk():
        if deadline is not None:
            deadline.check("audit walk")
        entries.append(entry)
    if deadline is not None:
        deadline.check("audit walk end")
    return entries


def gather_remote(bridge: Bridge, source: Source, settings: Settings,
                  deadline: Any = None) -> AuditData:
    """Gather ftp-mode AuditData: one walk, then bridge ``info`` + ``db_audit``.

    The walk runs BEFORE any bridge call: the audit tree must reflect the
    site, not our own deployed bridge file (the Bridge lazy-deploys on its
    first call, so a not-yet-called bridge leaves the webroot untouched).
    Absent/None/wrong-typed payload fields degrade to each AuditData field's
    unknown value — this never raises on payload gaps; a failing bridge call
    still raises BridgeError (a source failure, not missing data).
    ``settings`` is part of the uniform gatherer signature (the bridge
    carries its own).
    """
    entries = _walk_bounded(source, deadline)
    if deadline is not None:
        deadline.check("audit bridge info")
    info = bridge.call("info")
    if deadline is not None:
        deadline.check("audit bridge db_audit")
    db_audit = bridge.call("db_audit")

    plugin_catalog = _plugin_catalog(info.get("plugins"))
    theme_slugs = {slug for slug in
                   (_opt_str(info.get("template")), _opt_str(info.get("stylesheet")))
                   if slug}
    data = AuditData(
        mode="ftp",
        entries=entries,
        siteurl=_opt_str(info.get("siteurl")),
        home=_opt_str(info.get("home")),
        template=_opt_str(info.get("template")),
        blog_public=_opt_int(info.get("blog_public")),
        wp_version=_opt_str(info.get("wp_version")),
        mu_plugins=_opt_int(info.get("mu_plugins")),
        active_plugins=[file for file, meta in plugin_catalog.items() if meta["active"]],
        plugin_catalog=plugin_catalog,
        uploads_basedir=_opt_str(info.get("uploads_basedir")),
        posts=_posts_from_wire(db_audit.get("posts")),
        revisions=_opt_int(db_audit.get("revisions")),
        expired_transients=_opt_int(db_audit.get("expired_transients")),
        orphan_meta=_orphan_meta_from_wire(db_audit.get("orphan_meta")),
        attachments=_opt_int(db_audit.get("attachments")),
        nav_menu_items=_opt_int(db_audit.get("nav_menu_items")),
        autoload_bytes=_opt_int(db_audit.get("autoload_bytes")),
        big_autoload_options=[],  # ftp: only the byte total is known
        tables=_tables_from_wire(db_audit.get("tables")),
        admin_users=_admin_users_from_wire(db_audit.get("users")),
        theme_versions=_theme_versions(source, theme_slugs),
        locale=_opt_str(info.get("locale")),
        # db_refs stays None in ftp mode on purpose: the database media map
        # is a full postmeta/options scan, and only the media check needs
        # it.  It fetches the set from the bridge once and memoizes it on
        # this field (wpt.media_refs.db_refs_for_data), so an audit that
        # skips media.unreferenced never pays for the scan.
        source=source,
    )
    log.info(
        "audit data gathered: mode=ftp entries=%d plugins=%d active=%d "
        "post_groups=%d revisions=%r tables=%d",
        len(data.entries), len(plugin_catalog), len(data.active_plugins),
        len(data.posts), data.revisions, len(data.tables),
    )
    return data


def _count_or_unknown(value: Sized | None) -> str:
    """A log-line count: the integer, or ``"unknown"`` when unmeasured.

    The ONE renderer for the gather summary's counted fields.  ``None``
    renders ``unknown`` — never ``0``, because a count nobody measured is
    not a zero and a reader scanning the line cannot tell the two apart.
    """
    return "unknown" if value is None else str(len(value))


def gather_local(dump: BinaryIO, source: Source, settings: Settings,
                 deadline: Any = None) -> AuditData:
    """Gather local-mode AuditData: ``analyze(dump, settings.db)`` + one walk.

    Everything a dump cannot know keeps its field's unknown value:
    wp_version, mu_plugins, expired_transients, autoload_bytes and
    orphan_meta (see AuditData).  Derived counts mirror the bridge's
    db_audit rules exactly:

    * revisions — sum of posts counts where post_type == "revision" OR
      post_status == "auto-draft" (the bridge's revision SQL);
    * attachments — posts.get(("attachment", "inherit"), 0);
    * nav_menu_items — the sum over ALL ("nav_menu_item", *) groups
      (never a guessed status subset);
    * tables — SiteModel row/byte estimates with data_free unknown,
      collation unknown (a dump's CREATE text states only the charset;
      richer local collation facts land with the analyzer round) and
      charset parsed from each CREATE's DEFAULT CHARSET clause;
    * admin_users — the model's parsed admin facts (wp_users joined to
      wp_usermeta user_level=10 rows, wire-shaped, sorted by login);
      None passes through when the dump lacks usable users tables —
      unknown, never a guessed [];
    * uploads_basedir — "wp-content/uploads" only when the walked tree
       contains that path;
    * plugin_catalog — {} (a zip carries no reliable version data);
    * theme_versions — style.css header reads for the model's template
       and stylesheet slugs (best effort; a failed read omits the slug);
    * db_refs — the DATABASE-referenced media set, measured here from the
       same dump with the W5a streaming parser (``wpt.media_refs``; the
       local gate is the dump, so this is the only offline source of that
       half of the media keep-set).  None when the dump carries no usable
       WordPress tables (unknown — never an empty set).

    The one INFO summary line states each count, and a count the dump
    cannot support prints as ``unknown`` rather than 0 (see
    :func:`_count_or_unknown`) — on an absent or contested options-table
    identity the active set and the posts table were both never read.
    """
    if deadline is not None:
        deadline.check("audit dump analyze")
    model: SiteModel = analyze(dump, settings.db)
    if deadline is not None:
        deadline.check("audit dump analyze end")
    entries = _walk_bounded(source, deadline)
    # The database half of the media keep-set, from the same dump (the
    # offline gate).  Measured HERE, not lazily: the dump handle is closed
    # when the gather returns, and a page renders only a fraction of its
    # attachment images, so this is what keeps an offline audit from
    # reporting database-referenced media as unreferenced.
    db_media_refs = db_refs_from_dump(
        dump, settings.media.extensions, deadline=deadline)

    posts = model.posts
    revisions = sum(
        count
        for (post_type, post_status), count in posts.items()
        if post_type == "revision" or post_status == "auto-draft"
    )
    nav_menu_items = sum(
        count for (post_type, _status), count in posts.items()
        if post_type == "nav_menu_item"
    )
    theme_slugs = {slug for slug in (model.template, model.stylesheet) if slug}
    data = AuditData(
        mode="local",
        entries=entries,
        siteurl=model.siteurl,
        home=model.home,
        template=model.template,
        blog_public=model.blog_public,
        wp_version=_read_wp_version(source),
        mu_plugins=None,
        active_plugins=model.active_set.plugins,
        plugin_catalog={},
        uploads_basedir=_detect_uploads_dir(entries),
        posts=posts,
        revisions=revisions,
        expired_transients=None,
        orphan_meta={},
        attachments=posts.get(("attachment", "inherit"), 0),
        nav_menu_items=nav_menu_items,
        autoload_bytes=None,
        big_autoload_options=model.big_autoload_options,
        tables={
            name: TableFact(
                rows=stats.row_count, size_bytes=stats.data_bytes,
                data_free_bytes=None, collation=None,
                charset=_charset_from_create(stats.create_sql),
            )
            for name, stats in model.tables.items()
        },
        admin_users=model.admin_users,
        theme_versions=_theme_versions(source, theme_slugs),
        locale=model.locale,
        db_refs=db_media_refs,
        source=source,
    )
    # The counts are DERIVED FROM AN UNMEASURED keep-set when the dump's
    # options-table identity is absent or contested: the analyzer could not
    # locate the posts table (it is located by the prefix the options table
    # declares), and ``SiteModel.active_plugins`` is the collapsing
    # ``active_set.plugins or []`` view, so both read 0 for a measurement
    # nobody made.  ``0`` is a claim, and here the same line already says
    # ``db_media_refs=unknown`` — so a count the dump cannot support
    # prints as ``unknown``, the same token the line already uses, and a
    # measured run keeps printing integers.
    log.info(
        "audit data gathered: mode=local entries=%d plugins=%s "
        "post_groups=%s tables=%d big_autoload=%d db_media_refs=%s",
        len(data.entries),
        _count_or_unknown(model.active_set.plugins),
        _count_or_unknown(posts if model.table_prefix is not None else None),
        len(model.tables), len(model.big_autoload_options),
        _count_or_unknown(db_media_refs),
    )
    return data


def gather_source(source: Source, mode: str, *, deadline=None) -> AuditData:
    """Gather source-only AuditData: one walk, every DB/site fact unknown.

    The ``wpt scan`` path reads a webroot and nothing else: no bridge, no
    SQL dump, no live session.  Every scalar fact is therefore None (the
    data layer's "not measured" value), every dict is empty, and
    ``active_plugins``/``admin_users`` stay None rather than a guessed ``[]``
    — a source-only run must never read as a measured clean database.

    ``source`` is the webroot-rooted connector (FTP or zip) and ``mode`` is
    the Ctx mode ("ftp" or "local"); both are stored so the check and the
    report header can name what was scanned.  ``deadline`` (a
    ``wpt.deadline.Deadline`` or None) bounds the WALK itself, not only the
    later check batches: the walk is the first unbounded phase of a
    source-only run, so a large tree cannot outlive ``--deadline`` before
    the scanner even starts.  The deadline is also stored on the returned
    data for the check's own batch loop.
    """
    entries: list[Entry] = []
    if deadline is not None:
        # An already-expired deadline must fail even when the tree yields
        # ZERO entries; checking only after a yield made an empty scan a
        # clean-looking success.
        deadline.check("source scan walk")
    for entry in source.walk():
        if deadline is not None:
            deadline.check("source scan walk")
        entries.append(entry)
    if deadline is not None:
        # The walk can spend the budget and still yield NOTHING (an empty
        # tree, a slow directory listing).  Without this check a security
        # gate returned a clean rc 0 after its deadline had expired.
        deadline.check("source scan walk end")
    data = AuditData(
        mode=mode,
        entries=entries,
        siteurl=None,
        home=None,
        template=None,
        blog_public=None,
        wp_version=None,
        mu_plugins=None,
        active_plugins=None,
        plugin_catalog={},
        uploads_basedir=None,
        posts={},
        revisions=None,
        expired_transients=None,
        orphan_meta={},
        attachments=None,
        nav_menu_items=None,
        autoload_bytes=None,
        big_autoload_options=[],
        tables={},
        admin_users=None,
        source=source,
        deadline=deadline,
    )
    log.info(
        "audit data gathered: mode=%s entries=%d (source only)",
        mode, len(entries),
    )
    return data
