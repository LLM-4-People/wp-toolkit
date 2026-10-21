"""Analyzer layer for local mode (W5b): parsed .sql dump -> SiteModel.

Builds on the W5a streaming parser (``wpt.localmode.sql_dump``): exactly one
``parse_dump`` pass for the table summary, then one ``iter_rows`` pass each
for the options, posts, usermeta and users tables.  Rows are aggregated
incrementally — nothing ever buffers a whole table.  The stream is rewound
(``seek(0)``) before each pass, so callers may hand over the file object in
any state.

The result is DATA, never verdicts: audit Findings are W6's job.  A field is
None/empty when the dump does not contain the corresponding fact.

Table detection never guesses, and it never RE-DERIVES: the options table
is resolved by :func:`wpt.media_refs.dump_identity` (the ONE fail-closed
identity rule, whose candidate test is
:func:`wpt.media_refs.resolve_role` — the media measurement that reads the
destructive keep-set asks the same one), so a dump that declares two tables
carrying the ``option_name``/``option_value`` pair (AIOSEO 4.x really
creates ``aioseo_options``) resolves to NOTHING here and in the keep-set
alike, instead of this module reading one and the measurement another.
An absent or ambiguous options identity therefore means no prefix, hence
no posts or users facts — ``wp_`` is never assumed, and the ambiguous case
degrades exactly like the absent one after ONE warning from the owner
naming the candidates.

PARTIAL IS NOT THIS MODULE'S BUSINESS, and it must not be reported as an
absent options table.  A dump that declares no table every WordPress
database has (``postmeta`` above all — a phpMyAdmin per-table export, a
``mysqldump --ignore-table``, a transfer whose ``CREATE`` was cut) cannot
answer the DATABASE MEDIA question, and :mod:`wpt.media_refs` refuses that
measurement (see :data:`wpt.media_refs._REQUIRED_PREFIX_ROLES`).  What
such a dump still PROVES is its options table — and the options table is
the one thing that carries the prefix every other table is located by — so
the site facts below are still measured here, and a dump whose options
identity is absent or contested is still the never-guess degradation below.

The posts table is prefix + ``posts`` when it exists and its columns
include ``post_type`` and ``post_status``; the users tables are prefix +
``users`` (columns ``ID`` — the join key — ``user_login`` and
``user_registered``) and prefix + ``usermeta`` (columns ``user_id``,
``meta_key`` and ``meta_value``).  The prefix itself is the owner's
:func:`wpt.media_refs.options_prefix`.  A table with INSERTs but no CREATE
has no columns and can never satisfy any of the column checks (guard).

The admin rule mirrors the bridge's db_audit users query
(wpt/wpbridge/bridge.php) exactly: an account is an admin when a usermeta
row with meta_key ending in ``user_level`` holds meta_value ``10`` for its
users-table ID (the suffix match tolerates a usermeta key prefix the
options table did not reveal).  ``admin_users`` follows the remote wire's
None-vs-measured contract: None when either table is absent or lacks its
columns (the admin query could not run — unknown, the bridge's users
null), [] when both parsed and no account matched (a REAL measured
empty), else the admins in the bridge's entry shape, sorted by login.

``active_set`` follows that same None-vs-measured contract, and for the
same reason one of its consumers deletes files: it holds the active plugin
FILE paths and the active theme, ``plugins`` being None when the set could
not be MEASURED (an absent or contested options identity, or an
``active_plugins`` value that is not a readable serialized list) and ``[]``
when the site genuinely runs no plugins.  Reporting the unknown as an
empty list is a POSITIVE answer — the shape of a site running nothing —
and the consumer that deletes a plugin/theme UNIT directory in whole
(``clean-files``, whose active-unit guard stops a live plugin from being
removed out from under a running site) read it as "this unit is not in
use" and planned the deletion.  The model therefore carries the cause
(``reason``) and, for a contested identity, every table that proved the
role (``candidates``), so a consumer can refuse and say what it could not
read.  ``SiteModel.active_plugins`` / ``template`` / ``stylesheet`` remain
as derived read-only views for the consumers that only report the fact.

Logging discipline: dumps contain secrets.  This module logs table names,
option names and structural counts only — never cell contents — with one
info summary line and at most one warning per anomaly class.  There is no
per-row logging.

``php_unserialize`` is a DELEGATE to the ONE PHP decoder
(``wpt.media_refs.decode_php_value``, whose reference is the
``@unserialize`` bridge.php deploys) — the bytes are parsed there, once, and
this module applies its own narrower POLICY to the result: objects are
rejected outright (the analyzer never resurrects an object, and nothing
here ever evaluates anything), trailing bytes are a refusal, and
``_MAX_DEPTH`` is a structural anti-bomb guard (not an operator tunable) so
a nesting bomb raises ``UnserializeError`` instead of exhausting the
interpreter stack; ``analyze`` then degrades the affected option to
None/empty rather than failing the whole dump.  The decoder is imported
inside the function because this package's ``sql_dump`` is imported by
``wpt.media_refs``, so a module-level import would be a cycle.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, BinaryIO

from ..log import get_logger
from ..settings import DbSettings
from .sql_dump import TableStats, iter_rows, parse_dump

log = get_logger("localmode.analyzer")

__all__ = ["ActiveSet", "SiteModel", "UnserializeError", "analyze",
           "php_unserialize"]

_MAX_DEPTH = 64
# Scalar string options harvested from the options table.  WPLANG feeds
# SiteModel.locale (the SITE locale — the fallback tier of the
# integrity check's core-build locale resolution); the rest feed their
# own model fields.
_STRING_OPTIONS = frozenset((
    "siteurl", "home", "template", "stylesheet", "permalink_structure",
    "WPLANG",
))
# Autoloading autoload-column values across WP versions: pre-6.6 'yes'; 6.6+
# 'on' / 'auto-on' / 'auto' (wp_determine_option_autoload_value).  NOT autoloaded:
# 'no' / 'off' / 'auto-off'.  The bridge's db_audit SQL (wpt/wpbridge/bridge.php)
# mirrors this set — tests/test_bridge_php.py contract-pins the mirror.
AUTOLOAD_ON = frozenset(("yes", "on", "auto-on", "auto"))


class UnserializeError(ValueError):
    """Malformed, truncated or unsupported php-serialized input."""


#: The shapes an option value may have: PHP's scalars and containers.
#: Anything else the decoder can produce — an OBJECT stand-in (``O:``/
#: ``C:``/``E:``) or a NULL (``N;``) — is refused, so an option read can
#: never introduce an object into the model and never has to tell a null
#: apart from an unreadable value.  An ALLOW-list rather than a deny-list
#: of the decoder's internals, so a stand-in type this module has never
#: heard of is refused rather than mistaken for data.
_OPTION_SHAPES = (str, int, float, bool, dict, list)


def _refuse_unsupported(value: Any, depth: int = 0,
                         _ancestors: set[int] | None = None) -> None:
    """This module's extra refusals, in ONE walk over the decoded value.

    An OBJECT or a NULL — shapes the ONE decoder reads because the live
    side does, and this module does not accept (see :data:`_OPTION_SHAPES`)
    — a nesting DEEPER than :data:`_MAX_DEPTH` (its own anti-bomb bound,
    deliberately stricter than the decoder's 4096, which is what PHP
    accepts), and a value that is its own ANCESTOR (a ``R:1;`` recursion).
    Three refusals in one traversal, because a second traversal would be a
    second thing to keep in step with the first.

    The walk tracks the ANCESTOR path, not every node it has seen: a node
    that is an ancestor is a recursion and is refused, while the same node
    reached through two branches is a shared sub-value (what a
    back-reference produces) and is legitimate, exactly as it is in PHP.
    """
    if depth > _MAX_DEPTH:
        raise UnserializeError("serialized value nested too deeply")
    if not isinstance(value, _OPTION_SHAPES):
        raise UnserializeError(
            "unsupported serialization: an option value must not carry an "
            "object or a null")
    if not isinstance(value, (dict, list)):
        return
    if _ancestors is None:
        _ancestors = set()
    if id(value) in _ancestors:
        raise UnserializeError("serialized value is its own recursion")
    _ancestors.add(id(value))
    try:
        for member in (value.values() if isinstance(value, dict) else value):
            _refuse_unsupported(member, depth + 1, _ancestors)
    finally:
        _ancestors.discard(id(value))


def php_unserialize(data: str) -> Any:
    """Read a stored ``wp_options`` value with the ONE PHP decoder.

    DELEGATE, not a second implementation: the rule is
    :func:`wpt.media_refs.decode_php_value` (PHP's own ``unserialize``
    semantics — the reference being the ``@unserialize`` bridge.php deploys),
    and the bytes are parsed by that ONE implementation.  The import is
    deferred inside the function because ``wpt.media_refs`` imports this
    package's ``sql_dump``, so a module-level import here is a cycle.

    What this function adds is a POLICY, not a parser: the analyzer's own
    consumers read scalar and simple-list OPTION values, and they want the
    two things a *narrower* reader gives them.

    * OBJECTS AND NULLS ARE NEVER ACCEPTED — ``O:``/``C:``/``E:`` and ``N;``
      are refused outright, so no option value can introduce an object into
      the model.  The one decoder cannot resurrect anything either (it
      stands an object in as an inert marker), but refusing is the stronger
      statement for a value this module only needs to be a string.
    * TRAILING BYTES are a refusal, not something to ignore: an option
      value is a whole cell, so bytes after the value are part of what the
      site stored, and a reader that silently dropped them would report a
      fact the dump does not contain.  That is the decoder's ``require_eof``
      POLICY switch, not a second parser.
    * NESTING is bounded at :data:`_MAX_DEPTH` rather than the decoder's
      own 4096 (what PHP accepts) — a structural anti-bomb guard for a
      dump this module streams, and a bomb has to raise rather than
      exhaust the interpreter.
    * A value that is its own ANCESTOR (``R:1;``, which PHP resolves into a
      recursion) is refused.  A back-reference to an earlier value is NOT
      separately refused: after the one decode it is that value, which is
      what PHP produces too, and no option read can tell the two apart.  No
      option value is a recursion, and one that reached :class:`SiteModel`
      would be a shape nothing downstream can read.

    On every shape both readers accept, the value is identical: the
    difference is only ever which inputs are refused.  ``tests/
    test_media_refs.py::test_php_decode_agrees_with_the_analyzer_subset``
    pins that agreement, and the local rewrite gate's own direct use of the
    decoder (``wpt/actions/images_webp.py``) pins that the two halves of one
    destructive decision can no longer be read by different rules.
    """
    from ..media_refs import decode_php_value   # cycle: deferred, see above

    if not isinstance(data, str):
        raise UnserializeError("php_unserialize expects a str value")
    try:
        value = decode_php_value(data, require_eof=True)
    except ValueError as exc:      # the one decoder's PhpDecodeError
        raise UnserializeError(str(exc)) from None
    _refuse_unsupported(value, 0)
    return value



# ------------------------------------------------------------------ analyze


@dataclass(frozen=True)
class ActiveSet:
    """The site's ACTIVE set as the options table proves it, or why it cannot.

    The ONE answer to "which plugins is WordPress running, and which theme
    is it rendering", and it distinguishes THREE states instead of two,
    because a destructive consumer acts on the difference:

    * MEASURED — ``plugins`` holds the ``active_plugins`` option's plugin
      FILE paths in stored order.  ``[]`` is a REAL measured answer (a
      site running no plugins), not an absence of one.
    * NOT MEASURED — ``plugins`` is ``None``.  There are two causes and
      they differ in what they invalidate: the options table itself was
      never read (an absent or CONTESTED identity — ``theme_measured`` is
      False as well, and ``candidates`` names every table that proved the
      role), or the table was read and the option's value is not a readable
      serialized list.  ``reason`` is the one clause that says which.
      A table that WAS read and carries no ``active_plugins`` row at all is
      NOT one of them: that is a measured empty, because it is what
      ``get_option('active_plugins')`` itself answers on such a site
      (false ⇒ WordPress loads nothing), and a measured fact of the site
      is what this model reports.

    The distinction is the whole point.  A consumer that deletes what the
    active set does not name (a plugin/theme UNIT directory can only ever
    be removed in whole) read the not-measured case as an EMPTY set, which
    is the shape of a site running nothing: on a dump whose options
    identity is contested — AIOSEO 4.x really creates its own
    ``aioseo_options`` beside ``wp_options`` — the ACTIVE-UNIT GUARD
    silently disappeared and ``clean-files`` planned the deletion of a live
    plugin's whole directory, the fatal the guard exists to prevent.  The
    model therefore never reports "unknown" as an empty list: it reports it
    as ``None`` plus the cause, and a destructive consumer refuses.

    template / stylesheet: the active theme's PARENT and ACTIVE (child)
        directory, None when the site names no such theme.
    theme_measured: False when the options table was never read, so a None
        template/stylesheet is UNKNOWN; True when it was read, where None
        is the site's own answer.  Same rule as ``plugins`` is None, one
        table and one pass away.
    """

    plugins: list[str] | None
    template: str | None
    stylesheet: str | None
    theme_measured: bool
    reason: str | None = None
    candidates: tuple[str, ...] = ()


@dataclass
class SiteModel:
    """Structured facts about the WordPress site contained in one .sql dump.

    The model is data, not verdicts — W6 decides what the values mean.

    active_set: the site's active plugins and active theme, or the reason
        that could not be measured (:class:`ActiveSet`, the ONE owner of
        that question).  ``active_plugins`` / ``template`` / ``stylesheet``
        below are derived read-only views of it, kept for the consumers
        that only ever REPORT the fact: a destructive consumer must ask
        ``active_set`` itself, because the view collapses "not measured"
        into the same empty value a site running nothing produces.
    siteurl / home: value of the option, None when the option is absent
        or its value is not a readable serialized string.
    blog_public: the option as an int (``i:0;/i:1;``), None otherwise.
    permalink_structure: the permalink_structure option — None when the
        option is absent or unreadable, ``""`` when the site uses PLAIN
        (``?p=N``) permalinks (a REAL measured empty — WordPress's own
        default), a non-empty structure (``/%year%/%monthnum%/%postname%/``)
        when the site uses pretty permalinks.  The harden action's
        pretty-permalink gate reads it.
    locale: the site's locale from the WPLANG option — ``"fr_CA"`` on a
        French-Canadian site, None when the option is absent, empty
        (the modern WordPress en_US default), unreadable, or not a
        readable string.  This is the SITE locale (the content
        language), NOT necessarily the core BUILD locale: an en_US
        build plus a fr_CA language pack also stores WPLANG=fr_CA.
        The integrity check consumes it as the fallback tier of its
        core-build locale resolution (its own semantics — the model
        stays data, never verdicts).
    big_autoload_options: (option_name, byte size) for every autoloaded option
        (autoload in AUTOLOAD_ON: 'yes' and the WP 6.6+ 'on'/'auto-on'/'auto')
        whose value is at least settings.db.autoload_big_bytes bytes,
        sorted by size descending (option_name is the tiebreak).  Empty means
        nothing crossed the threshold, or the table has no autoload column
        (warned).
    posts: (post_type, post_status) -> row count.  A post_status cell that is
        empty or NULL counts under ("").  Empty means no usable posts table.
    admin_users: administrator accounts in the remote wire's exact entry
        shape — {"login": str, "registered": str | None, "admin": True} —
        so the users check never depends on the mode.  An account is an
        admin when a wp_usermeta row with meta_key ending in "user_level"
        holds meta_value "10" for its wp_users ID (the bridge's db_audit
        rule; the suffix match tolerates a usermeta key prefix the
        options table did not reveal).  registered is the user row's
        user_registered string, None on NULL.  Sorted by login (the
        bridge sorts by user_login in SQL).  None when wp_users or
        wp_usermeta is absent or lacks its required columns (the admin
        query could not run — unknown); [] when both parsed and no
        account matched (a REAL measured empty — never confused with
        unknown).
    tables / charset: passthrough from parse_dump.
    table_prefix: options-table name minus the trailing "options"; None when
        no UNIQUE options table was found (absent, or two tables prove the
        role — the owner's one fail-closed rule; never guessed).
    """

    siteurl: str | None
    home: str | None
    blog_public: int | None
    permalink_structure: str | None
    locale: str | None
    active_set: ActiveSet
    big_autoload_options: list[tuple[str, int]]
    posts: dict[tuple[str, str], int]
    admin_users: list[dict] | None
    tables: dict[str, TableStats]
    charset: str | None
    table_prefix: str | None

    # -- derived read-only views of ``active_set`` (see the class docstring)

    @property
    def active_plugins(self) -> list[str]:
        """The measured active plugin FILE paths; ``[]`` when the set was
        NOT measured — which is why a destructive consumer asks
        ``active_set.plugins`` (None) instead of this view."""
        return self.active_set.plugins or []

    @property
    def template(self) -> str | None:
        """The active theme's PARENT directory (None when the site names
        none, or when the options table was never read)."""
        return self.active_set.template

    @property
    def stylesheet(self) -> str | None:
        """The active (child) theme directory — the ACTIVE theme, as
        opposed to ``template``, its parent.  None when the site names
        none, or when the options table was never read."""
        return self.active_set.stylesheet


def _effective_columns(stats: TableStats) -> list[str]:
    if stats.insert_columns is not None:
        return stats.insert_columns
    return stats.columns


def _cell_bytes(value: Any) -> int | None:
    """Byte size of a cell's str/bytes form; None when it has neither."""
    if isinstance(value, bytes):
        return len(value)
    if isinstance(value, str):
        return len(value.encode("utf-8"))
    return None


# Real WordPress stores SCALAR options (siteurl, template, blog_public, ...)
# as PLAIN text and only ARRAYS/objects PHP-serialized (maybe_serialize).
# Real dumps prove both shapes exist (phpMyAdmin: 'siteurl',
# 'https://example.test'); accept plain first, unwrap only when the value
# carries a serialize tag.
_SERIALIZE_TAG = ("s:", "a:", "i:", "b:", "d:")


def _str_option(name: str, raw: Any) -> str | None:
    if not isinstance(raw, str):
        log.debug("option %s is not a string cell; left unset", name)
        return None
    if raw.startswith(_SERIALIZE_TAG):
        try:
            value = php_unserialize(raw)
        except UnserializeError:
            value = None
        if isinstance(value, str):
            return value
        log.debug("option %s is tagged but not a readable serialized "
                  "string; left unset", name)
        return None
    return raw


def _int_option(name: str, raw: Any) -> int | None:
    if isinstance(raw, int):
        return raw
    if not isinstance(raw, str):
        log.debug("option %s is not a string/int cell; left unset", name)
        return None
    text = raw.strip()
    if text.startswith(_SERIALIZE_TAG):
        try:
            value = php_unserialize(text)
        except UnserializeError:
            value = None
        if type(value) is int:
            return value
        log.debug("option %s is tagged but not a readable serialized int; "
                  "left unset", name)
        return None
    try:
        return int(text)
    except ValueError:
        log.debug("option %s is not a readable int; left unset", name)
        return None


def _plugins_option(raw: Any) -> list[str] | None:
    """The active_plugins option as a list of plugin file paths (None = unreadable)."""
    try:
        value = php_unserialize(raw)
    except UnserializeError:
        return None
    if not isinstance(value, dict):
        return None
    return [v for v in value.values() if isinstance(v, str)]


def analyze(dump: BinaryIO, settings: DbSettings) -> SiteModel:
    """Analyze one open binary .sql dump into a SiteModel (streaming).

    One ``parse_dump`` pass builds the table summary; then one ``iter_rows``
    pass each for the options, posts, usermeta and users tables, aggregating
    rows incrementally.  The stream is rewound before each pass.
    """
    dump.seek(0)
    summary = parse_dump(dump)
    tables = summary.tables

    # WHOSE OPTIONS TABLE: :mod:`wpt.media_refs` — the module that owns
    # table identity and reads the media keep-set — asked through the SAME
    # resolution, never re-derived.  The import is deferred for the reason
    # ``php_unserialize`` defers the same module's decoder: ``wpt.media_refs``
    # imports this package, so a module-level import here is a cycle.
    from ..media_refs import dump_identity, options_prefix, resolve_role

    identity = dump_identity(tables)
    # THE OPTIONS TABLE, and nothing else from the identity: a partially
    # exported dump (no postmeta — see wpt.media_refs' partiality rule)
    # still PROVES its options table, and the options table is the only
    # thing that carries the prefix every other table is located by.  The
    # reference set and the witness ask the whole identity and get nothing
    # from such a dump; the site facts below are still measured facts, and
    # degrading them too would be collateral.
    options_stats = identity.options_table
    if options_stats is None:
        # ABSENT or CONTESTED options identity: the never-guess degradation,
        # and on a contested dump the owner has already named the candidates
        # (so this module can never warn about a different table than the
        # one the keep-set read).
        log.warning("no unique WordPress options table in dump (tables=%d); "
                    "the site's table prefix and every fact derived from it "
                    "are unknown", len(tables))
        # WHY, in the model's own terms, plus WHICH tables — a consumer
        # that must refuse the unit deletions this fact protects has to be
        # able to say what it could not read.  The candidates come from the
        # ONE candidate rule, asked with the owner's own input (the CREATE
        # columns of every table), which is the memoized resolution
        # ``dump_identity`` just made: a cache hit, never a second
        # resolution and never a second warning.
        options_role = resolve_role(
            "options", {name: stats.columns for name, stats in tables.items()})
        contested = options_role.ambiguous
        return SiteModel(
            siteurl=None, home=None,
            blog_public=None, permalink_structure=None, locale=None,
            active_set=ActiveSet(
                plugins=None, template=None, stylesheet=None,
                theme_measured=False,
                reason=("the options-table identity is contested"
                        if contested
                        else "the dump declares no table that proves the "
                             "options role"),
                candidates=options_role.candidates if contested else (),
            ),
            big_autoload_options=[], posts={},
            admin_users=None,
            tables=tables, charset=summary.charset, table_prefix=None,
        )
    prefix = options_prefix(options_stats.name)

    siteurl: str | None = None
    home: str | None = None
    template: str | None = None
    stylesheet: str | None = None
    blog_public: int | None = None
    permalink_structure: str | None = None
    locale: str | None = None
    active_plugins: list[str] | None = []
    plugins_reason: str | None = None
    big: list[tuple[str, int]] = []
    plugins_warned = False
    option_columns = _effective_columns(options_stats)
    has_autoload = "autoload" in option_columns
    if not has_autoload:
        log.warning("options table %s has no autoload column; big-autoload "
                    "detection skipped", options_stats.name)

    option_rows = 0
    dump.seek(0)
    for row in iter_rows(dump, options_stats.name):
        option_rows += 1
        record = dict(zip(option_columns, row))
        name = record.get("option_name")
        if not isinstance(name, str):
            continue
        if name in _STRING_OPTIONS:
            value = _str_option(name, record.get("option_value"))
            if name == "siteurl":
                siteurl = value
            elif name == "home":
                home = value
            elif name == "stylesheet":
                stylesheet = value
            elif name == "permalink_structure":
                permalink_structure = value
            elif name == "WPLANG":
                # '' (the modern en_US default) reads as unknown — the
                # consumer floors at en_US; a non-empty locale is the fact.
                locale = value or None
            else:
                template = value
        elif name == "blog_public":
            blog_public = _int_option(name, record.get("option_value"))
        elif name == "active_plugins":
            plugins = _plugins_option(record.get("option_value"))
            if plugins is None:
                # An option the dump carries but that cannot be READ is not
                # a site running no plugins: it is the answer nobody has.
                # None says so, and a destructive consumer refuses where an
                # empty list would have let it act.
                active_plugins = None
                plugins_reason = ("the active_plugins option is not a "
                                  "readable serialized plugin list")
                if not plugins_warned:
                    plugins_warned = True
                    log.warning("option active_plugins is not a readable "
                                "serialized plugin list; the site's active "
                                "plugin set is unknown, not empty")
            else:
                active_plugins = plugins
        if has_autoload and record.get("autoload") in AUTOLOAD_ON:
            size = _cell_bytes(record.get("option_value"))
            if size is not None and size >= settings.autoload_big_bytes:
                big.append((name, size))
    big.sort(key=lambda item: (-item[1], item[0]))

    posts: dict[tuple[str, str], int] = {}
    post_rows = 0
    posts_stats: TableStats | None = None
    posts_candidate = tables.get(prefix + "posts")
    if (posts_candidate is not None
            and {"post_type", "post_status"} <= set(posts_candidate.columns)):
        posts_stats = posts_candidate
    if posts_stats is not None:
        post_columns = _effective_columns(posts_stats)
        dump.seek(0)
        for row in iter_rows(dump, posts_stats.name):
            post_rows += 1
            record = dict(zip(post_columns, row))
            post_type = record.get("post_type")
            post_status = record.get("post_status")
            key = (
                post_type if isinstance(post_type, str) else "",
                post_status if isinstance(post_status, str) else "",
            )
            posts[key] = posts.get(key, 0) + 1

    users_stats: TableStats | None = None
    users_candidate = tables.get(prefix + "users")
    if (users_candidate is not None
            and {"ID", "user_login", "user_registered"}
            <= set(users_candidate.columns)):
        users_stats = users_candidate
    usermeta_stats: TableStats | None = None
    usermeta_candidate = tables.get(prefix + "usermeta")
    if (usermeta_candidate is not None
            and {"user_id", "meta_key", "meta_value"}
            <= set(usermeta_candidate.columns)):
        usermeta_stats = usermeta_candidate

    admin_users: list[dict] | None = None
    if users_stats is not None and usermeta_stats is not None:
        admin_ids: set[str] = set()
        usermeta_columns = _effective_columns(usermeta_stats)
        dump.seek(0)
        for row in iter_rows(dump, usermeta_stats.name):
            record = dict(zip(usermeta_columns, row))
            key = record.get("meta_key")
            # meta_value '10' parses as str in quoted dumps; a bare 10
            # token is the same stored string either way.
            if (isinstance(key, str) and key.endswith("user_level")
                    and record.get("meta_value") in ("10", 10)):
                user_id = record.get("user_id")
                # IDs join by string form: quoted ('1') and bare (1)
                # cells mean the same SQL value.
                if isinstance(user_id, (int, str)):
                    admin_ids.add(str(user_id))
        admins: list[dict] = []
        users_columns = _effective_columns(users_stats)
        dump.seek(0)
        for row in iter_rows(dump, users_stats.name):
            record = dict(zip(users_columns, row))
            user_id = record.get("ID")
            if (not isinstance(user_id, (int, str))
                    or str(user_id) not in admin_ids):
                continue
            login = record.get("user_login")
            if not isinstance(login, str) or not login:
                continue
            registered = record.get("user_registered")
            admins.append({
                "login": login,
                "registered": registered if isinstance(registered, str)
                              else None,
                "admin": True,
            })
        admins.sort(key=lambda entry: entry["login"])
        admin_users = admins

    log.info("dump analyzed: prefix=%s options=%s posts=%s option_rows=%d "
             "post_rows=%d big_autoload=%d users=%s usermeta=%s admins=%s",
             prefix, options_stats.name,
             posts_stats.name if posts_stats is not None else "-",
             option_rows, post_rows, len(big),
             users_stats.name if users_stats is not None else "-",
             usermeta_stats.name if usermeta_stats is not None else "-",
             len(admin_users) if admin_users is not None else "-")
    if big:
        log.debug("big autoload options: %s",
                  ", ".join("%s=%d" % item for item in big))

    return SiteModel(
        siteurl=siteurl, home=home,
        blog_public=blog_public, permalink_structure=permalink_structure,
        locale=locale,
        active_set=ActiveSet(
            plugins=active_plugins, template=template, stylesheet=stylesheet,
            theme_measured=True, reason=plugins_reason,
        ),
        big_autoload_options=big, posts=posts,
        admin_users=admin_users,
        tables=tables, charset=summary.charset, table_prefix=prefix,
    )
