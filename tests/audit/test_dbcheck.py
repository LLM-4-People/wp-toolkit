"""Unit tests for the database audit checks (wpt.audit.dbcheck) — W6d.

Hand-built AuditData only: direct TableFact construction, Settings from
the shipped profile (wpt.settings.load()) or dataclasses.replace with
custom thresholds/marker lists. No gatherers, no sources, no network,
no sleeps — deterministic. The three-state discipline (None unknown /
0 measured zero / >0 reported) is pinned for every count signal.

Test -> behavior map (W6d task list):
  test_revisions_three_states ............... 42 -> one exact finding
        (bytes=0, low, clean-db revisions fix); 0 measured silent;
        None unknown silent
  test_transients_three_states .............. same shape for
        expired-transients / clean-db expired_transients
  test_orphan_meta_present_kinds_only ....... {} unknown silent;
        {kind: 0} measured-zero silent; {kind: N} one finding;
        two kinds -> two findings sorted by name
  test_ghost_component_and_substring_markers  "_" component match
        (wp_woocommerce_orders), "_"-bearing substring match
        (wp_actionscheduler_actions via "actionscheduler_actions"),
        partial-segment "wp_xwoocommerce" NOT matched, unmarked table
        not flagged; name-sorted detail; count/bytes exact
  test_ghost_active_plugin_excludes ......... active woocommerce keeps
        its tables out; all markers active -> []
  test_ghost_unknown_size_tolerated ......... None size_bytes: no byte
        contribution, size omitted from its detail line
  test_ghost_silent_without_tables_or_markers  {} tables silent; bare
        Settings() (no markers) silent; empty marker matches nothing
        (even a table with an empty "_"-split component)
  test_autoload_big_options_prioritized ...... per-option finding
        (detail size-desc, count/bytes summed); big list wins even when
        the total is also over threshold
  test_autoload_big_detail_truncated ........ 10 options -> 8 lines
        + "(+2 more)"
  test_autoload_total_at_threshold_only ...... at 1048576 -> exact
        autoload-total finding; below silent; None silent
  test_autoload_total_threshold_from_settings  replace()-driven
        threshold honored (below/at)
  test_optimize_free_space_thresholds ....... above + at -> one
        finding (free desc); below/None/{} silent
  test_optimize_detail_sorted_truncated ...... 10 tables -> free-desc
        8 lines + "(+2 more)", exact bytes
  test_optimize_threshold_from_settings ...... replace()-driven
        threshold honored (below/at)
  test_charset_mixed_reports_only_offenders .. utf8mb4 + latin1 +
        charset-None tables -> one finding naming ONLY the latin1
        table (count 1, bytes 0, medium, exact fix); all-None,
        all-utf8mb4 and {} tables silent
  test_charset_detail_sorted_truncated ........ 10 latin1 tables ->
        name-sorted 8 lines + "(+2 more)"
  test_admin_accounts_none_and_measured_empty_silent
                                        admin_users None (unknown —
        local mode until the analyzer round) and [] (measured
        empty) both silent
  test_admin_default_login_case_insensitive  "admin" + "Admin" ->
        count 2, high, exact fix; full login-sorted roster in the
        detail with "*" on offenders, "(registered ...)" on dated
        entries and "unknown" for a None registered (pinned)
  test_admin_roster_without_default_login .... no exact-match admin
        (incl. "admin2") -> []; a non-privileged "admin" entry
        never triggers
  test_registry_contains_all_nine ........... dotted names + applies
        ("ftp", "local")
  test_select_db_group_selectable ........... select_checks(["db"]) ==
        exactly the nine, both modes
  test_run_checks_end_to_end ................ run_checks pipeline over a
        rich fixture: exact finding set in execution order, every
        Finding validates, ftp == local
"""

from dataclasses import replace

from wpt.audit.data import AuditData, TableFact
from wpt.audit.dbcheck import (
    check_db_admin_accounts,
    check_db_autoload,
    check_db_charset,
    check_db_ghost_tables,
    check_db_optimize,
    check_db_orphan_meta,
    check_db_revisions,
    check_db_transients,
)
from wpt.audit.registry import all_checks, run_checks, select_checks
from wpt.settings import Settings, load

#: The shipped profile (wpt/data/profiles/default.json) — every threshold and
#: marker list these checks consume, exactly as users get it.
DEFAULTS = load()


def T(rows=0, size=None, free=None, charset=None):
    """One TableFact; size/data_free/charset default to unknown (None)."""
    return TableFact(rows=rows, size_bytes=size, data_free_bytes=free,
                     charset=charset)


def db_data(revisions=None, transients=None, orphan_meta=None,
            autoload_bytes=None, big_autoload=None, tables=None,
            admin_users=None, active=(), mode="ftp"):
    """A hand-built AuditData carrying DB facts only (rest unknown/empty)."""
    return AuditData(
        mode=mode,
        entries=[],
        siteurl=None,
        home=None,
        template=None,
        blog_public=None,
        wp_version=None,
        mu_plugins=None,
        active_plugins=list(active),
        plugin_catalog={},
        uploads_basedir=None,
        posts={},
        revisions=revisions,
        expired_transients=transients,
        orphan_meta=orphan_meta if orphan_meta is not None else {},
        attachments=None,
        nav_menu_items=None,
        autoload_bytes=autoload_bytes,
        big_autoload_options=big_autoload if big_autoload is not None else [],
        tables=tables if tables is not None else {},
        admin_users=admin_users,
    )


# ------------------------------------------------------------- db.revisions


def test_revisions_three_states():
    findings = check_db_revisions(db_data(revisions=42), DEFAULTS)
    assert [
        (f.category, f.name, f.detail, f.bytes, f.count, f.risk, f.fix)
        for f in findings
    ] == [
        ("db.revisions", "revisions", "revision and auto-draft posts",
         0, 42, "low", "remove via clean-db revisions"),
    ]
    findings[0].validate()
    assert check_db_revisions(db_data(revisions=0), DEFAULTS) == []   # measured 0
    assert check_db_revisions(db_data(revisions=None), DEFAULTS) == []  # unknown


# ------------------------------------------------------------ db.transients


def test_transients_three_states():
    findings = check_db_transients(db_data(transients=7), DEFAULTS)
    assert [
        (f.category, f.name, f.detail, f.bytes, f.count, f.risk, f.fix)
        for f in findings
    ] == [
        ("db.transients", "expired-transients", "expired transient options",
         0, 7, "low", "remove via clean-db expired_transients"),
    ]
    findings[0].validate()
    assert check_db_transients(db_data(transients=0), DEFAULTS) == []
    assert check_db_transients(db_data(transients=None), DEFAULTS) == []


# ----------------------------------------------------------- db.orphan_meta


def test_orphan_meta_present_kinds_only():
    assert check_db_orphan_meta(db_data(orphan_meta={}), DEFAULTS) == []
    assert check_db_orphan_meta(
        db_data(orphan_meta={"postmeta": 0}), DEFAULTS
    ) == []                                        # present-at-zero: measured 0
    one = check_db_orphan_meta(db_data(orphan_meta={"postmeta": 11}), DEFAULTS)
    assert [
        (f.category, f.name, f.detail, f.bytes, f.count, f.risk, f.fix)
        for f in one
    ] == [
        ("db.orphan_meta", "postmeta",
         "orphaned postmeta rows (owner object gone)",
         0, 11, "low", "remove via clean-db orphan_meta"),
    ]
    one[0].validate()
    two = check_db_orphan_meta(
        db_data(orphan_meta={"commentmeta": 2, "postmeta": 9}), DEFAULTS
    )
    assert [f.name for f in two] == ["commentmeta", "postmeta"]  # name-sorted
    assert [f.count for f in two] == [2, 9]
    for f in two:
        f.validate()


# --------------------------------------------------------- db.ghost_tables


def test_ghost_component_and_substring_markers():
    settings = replace(DEFAULTS, ghost_table_prefixes=[
        "woocommerce", "actionscheduler_actions",
    ])
    d = db_data(
        tables={
            "wp_woocommerce_orders": T(rows=12, size=2097152),    # component
            "wp_actionscheduler_actions": T(rows=30, size=102400),  # substring
            "wp_xwoocommerce": T(rows=1, size=10),   # partial segment: NO match
            "wp_posts": T(rows=100, size=1048576),   # no marker: not flagged
        },
        active=["akismet/akismet.php"],
    )
    findings = check_db_ghost_tables(d, settings)
    assert len(findings) == 1
    f = findings[0]
    f.validate()
    assert (f.category, f.name, f.count, f.bytes, f.risk) == (
        "db.ghost_tables", "ghost-tables", 2, 2097152 + 102400, "medium",
    )
    assert f.fix == "review with the operator; back up before dropping"
    assert f.detail == (
        "wp_actionscheduler_actions (30 rows, 102400 B)\n"
        "wp_woocommerce_orders (12 rows, 2097152 B)"
    )


def test_ghost_active_plugin_excludes_its_tables():
    d = db_data(
        tables={
            "wp_woocommerce_orders": T(rows=12, size=2097152),
            "wp_jetpack_options": T(rows=3, size=20480),
        },
        active=["woocommerce/woocommerce.php"],
    )
    findings = check_db_ghost_tables(d, DEFAULTS)
    assert len(findings) == 1
    f = findings[0]
    assert f.count == 1                    # active woocommerce keeps its tables
    assert f.detail == "wp_jetpack_options (3 rows, 20480 B)"
    quiet = db_data(
        tables={"wp_woocommerce_orders": T(rows=1, size=2)},
        active=["woocommerce/woocommerce.php"],
    )
    assert check_db_ghost_tables(quiet, DEFAULTS) == []


def test_ghost_unknown_size_tolerated():
    d = db_data(tables={
        "wp_nf3_forms": T(rows=4, size=None),            # size unknown
        "wp_statistics_exclusions": T(rows=2, size=8192),
    })
    findings = check_db_ghost_tables(d, DEFAULTS)
    assert len(findings) == 1
    f = findings[0]
    assert f.count == 2
    assert f.bytes == 8192          # unknown size contributes nothing, no fake 0
    assert f.detail == (
        "wp_nf3_forms (4 rows)\n"
        "wp_statistics_exclusions (2 rows, 8192 B)"
    )


def test_ghost_silent_without_tables_or_markers():
    assert check_db_ghost_tables(db_data(tables={}), DEFAULTS) == []
    tables = {"wp_woocommerce_orders": T(rows=1, size=1)}
    assert check_db_ghost_tables(db_data(tables=tables), Settings()) == []
    # a malformed empty marker matches nothing — not even a table whose
    # "_"-split has an empty component
    weird = replace(DEFAULTS, ghost_table_prefixes=["", "woocommerce"])
    assert check_db_ghost_tables(
        db_data(tables={"wp__double": T(rows=1)}), weird
    ) == []


def test_ghost_mapped_marker_slug_excludes_tables():
    # Markers are table-name tokens, not plugin slugs: the shipped profile
    # maps nf3 -> ninja-forms and statistics -> wp-statistics. An active
    # plugin owning the mapped slug keeps its tables out of the finding.
    d = db_data(
        tables={
            "wp_nf3_forms": T(rows=4, size=1024),
            "wp_statistics_exclusions": T(rows=2, size=8192),
        },
        active=["ninja-forms/ninja-forms.php", "wp-statistics/wp-statistics.php"],
    )
    assert check_db_ghost_tables(d, DEFAULTS) == []
    # same table, plugin inactive -> ghost again
    d2 = db_data(
        tables={"wp_nf3_forms": T(rows=4, size=1024)},
        active=["akismet/akismet.php"],
    )
    findings = check_db_ghost_tables(d2, DEFAULTS)
    assert len(findings) == 1
    assert findings[0].count == 1
    # an explicit map override works too
    custom = replace(DEFAULTS, ghost_marker_plugins={"woocommerce": "woo"})
    d3 = db_data(
        tables={"wp_woocommerce_orders": T(rows=1, size=2)},
        active=["woo/woo.php"],
    )
    assert check_db_ghost_tables(d3, custom) == []


# ------------------------------------------------------------- db.autoload


def test_autoload_big_options_prioritized():
    opts = [("opt_c", 150000), ("opt_a", 300000), ("opt_b", 900000)]
    findings = check_db_autoload(db_data(big_autoload=opts), DEFAULTS)
    assert [
        (f.category, f.name, f.count, f.bytes, f.risk, f.fix)
        for f in findings
    ] == [
        ("db.autoload", "big-autoload-options", 3, 1350000, "medium",
         "review; de-autoload or delete unused options"),
    ]
    assert findings[0].detail == (
        "opt_b (900000 B)\nopt_a (300000 B)\nopt_c (150000 B)"
    )
    findings[0].validate()
    # the per-option signal wins even when the total is also over threshold
    both = check_db_autoload(
        db_data(big_autoload=opts, autoload_bytes=9999999), DEFAULTS
    )
    assert [f.name for f in both] == ["big-autoload-options"]


def test_autoload_big_detail_truncated():
    opts = [(f"opt_{i}", 100000 + i) for i in range(10)]
    f = check_db_autoload(db_data(big_autoload=opts), DEFAULTS)[0]
    assert f.count == 10
    assert f.bytes == sum(100000 + i for i in range(10))
    assert f.detail == "\n".join(
        f"opt_{i} ({100000 + i} B)" for i in range(9, 1, -1)
    ) + "\n(+2 more)"


def test_autoload_total_at_threshold_only():
    findings = check_db_autoload(db_data(autoload_bytes=1048576), DEFAULTS)
    assert [
        (f.category, f.name, f.detail, f.bytes, f.count, f.risk, f.fix)
        for f in findings
    ] == [
        ("db.autoload", "autoload-total",
         "total autoloaded options exceed the warn level",
         1048576, 1, "medium", "review; de-autoload or delete unused options"),
    ]
    findings[0].validate()
    assert check_db_autoload(db_data(autoload_bytes=1048575), DEFAULTS) == []
    assert check_db_autoload(db_data(autoload_bytes=None), DEFAULTS) == []


def test_autoload_total_threshold_from_settings():
    settings = replace(
        DEFAULTS, db=replace(DEFAULTS.db, autoload_total_warn_bytes=5000)
    )
    assert check_db_autoload(db_data(autoload_bytes=4999), settings) == []
    over = check_db_autoload(db_data(autoload_bytes=5000), settings)  # at -> on
    assert len(over) == 1 and over[0].bytes == 5000


# ------------------------------------------------------------- db.optimize


def test_optimize_free_space_thresholds():
    d = db_data(tables={
        "wp_posts": T(rows=10, size=1000, free=2097152),    # above
        "wp_options": T(rows=20, size=2000, free=1048576),  # exactly at
        "wp_postmeta": T(rows=30, size=3000, free=1048575),  # below
        "wp_comments": T(rows=40, size=4000, free=None),   # unknown
    })
    findings = check_db_optimize(d, DEFAULTS)
    assert [
        (f.category, f.name, f.count, f.bytes, f.risk, f.fix)
        for f in findings
    ] == [
        ("db.optimize", "optimize-candidates", 2, 2097152 + 1048576, "low",
         "optimize via clean-db optimize_tables"),
    ]
    assert findings[0].detail == (
        "wp_posts (2097152 B)\nwp_options (1048576 B)"     # free desc
    )
    findings[0].validate()
    quiet = db_data(tables={
        "wp_postmeta": T(free=1048575),
        "wp_comments": T(free=None),
    })
    assert check_db_optimize(quiet, DEFAULTS) == []
    assert check_db_optimize(db_data(tables={}), DEFAULTS) == []


def test_optimize_detail_sorted_truncated():
    tables = {f"wp_t{i}": T(rows=0, size=0, free=2000000 + i) for i in range(10)}
    f = check_db_optimize(db_data(tables=tables), DEFAULTS)[0]
    assert f.count == 10
    assert f.bytes == sum(2000000 + i for i in range(10))
    assert f.detail == "\n".join(
        f"wp_t{i} ({2000000 + i} B)" for i in range(9, 1, -1)
    ) + "\n(+2 more)"


def test_optimize_threshold_from_settings():
    settings = replace(
        DEFAULTS, db=replace(DEFAULTS.db, free_space_warn_bytes=100)
    )
    assert check_db_optimize(db_data(tables={"wp_a": T(free=99)}), settings) == []
    over = check_db_optimize(db_data(tables={"wp_a": T(free=100)}), settings)
    assert len(over) == 1 and over[0].count == 1 and over[0].bytes == 100


# ------------------------------------------------------------- db.charset


def test_charset_mixed_reports_only_offenders():
    d = db_data(tables={
        "wp_posts": T(rows=100, charset="utf8mb4"),    # modern default: fine
        "wp_old_terms": T(rows=5, charset="latin1"),   # offender
        "wp_options": T(rows=300, charset=None),      # unknown: never counted
    })
    findings = check_db_charset(d, DEFAULTS)
    assert [
        (f.category, f.name, f.detail, f.bytes, f.count, f.risk, f.fix)
        for f in findings
    ] == [
        ("db.charset", "non-utf8mb4-tables", "wp_old_terms (latin1)",
         0, 1, "medium",
         "Convert the table to utf8mb4 (a latin1 table corrupts "
         "accents/emoji on import and blocks clean migrations): "
         "ALTER TABLE ... CONVERT TO CHARACTER SET utf8mb4 "
         "COLLATE utf8mb4_unicode_ci; back up first."),
    ]
    findings[0].validate()


def test_charset_all_unknown_and_all_modern_silent():
    all_unknown = db_data(tables={
        "wp_posts": T(charset=None), "wp_options": T(charset=None),
    })
    assert check_db_charset(all_unknown, DEFAULTS) == []      # unknown
    all_modern = db_data(tables={
        "wp_posts": T(charset="utf8mb4"), "wp_options": T(charset="utf8mb4"),
    })
    assert check_db_charset(all_modern, DEFAULTS) == []       # measured empty
    assert check_db_charset(db_data(tables={}), DEFAULTS) == []


def test_charset_detail_sorted_truncated():
    tables = {f"wp_t{i}": T(charset="latin1") for i in range(10)}
    f = check_db_charset(db_data(tables=tables), DEFAULTS)[0]
    assert f.count == 10
    assert f.bytes == 0
    assert f.detail == "\n".join(
        f"wp_t{i} (latin1)" for i in range(8)
    ) + "\n(+2 more)"


# ------------------------------------------------------- db.admin_accounts


def test_admin_accounts_none_and_measured_empty_silent():
    assert check_db_admin_accounts(db_data(admin_users=None), DEFAULTS) == []
    assert check_db_admin_accounts(db_data(admin_users=[]), DEFAULTS) == []


def test_admin_default_login_case_insensitive_with_roster():
    d = db_data(admin_users=[
        {"login": "siteowner", "registered": "2019-06-01 08:30:00",
         "admin": True},
        {"login": "Admin", "registered": None, "admin": True},   # case-fold
        {"login": "admin", "registered": "2015-04-03 10:00:00",
         "admin": True},
        {"login": "editor", "registered": "2021-01-02 03:04:05",
         "admin": True},
    ])
    findings = check_db_admin_accounts(d, DEFAULTS)
    assert [
        (f.category, f.name, f.bytes, f.count, f.risk, f.fix)
        for f in findings
    ] == [
        ("db.admin_accounts", "default-admin-login", 0, 2, "high",
         "Rename the default 'admin' account (create a new admin, "
         "log in as it, delete/reassign the old one): every botnet "
         "hammers wp-login with 'admin'."),
    ]
    f = findings[0]
    f.validate()
    # full login-sorted roster, offenders starred, None registered -> unknown
    assert f.detail == (
        "Admin* (registered unknown)\n"
        "admin* (registered 2015-04-03 10:00:00)\n"
        "editor (registered 2021-01-02 03:04:05)\n"
        "siteowner (registered 2019-06-01 08:30:00)"
    )


def test_admin_roster_without_default_login_silent():
    d = db_data(admin_users=[
        {"login": "siteowner", "registered": "2019-06-01 08:30:00",
         "admin": True},
        {"login": "admin2", "registered": None, "admin": True},
    ])
    assert check_db_admin_accounts(d, DEFAULTS) == []   # "admin2" != "admin"
    # only privileged entries are read (the wire list may widen beyond
    # admins in a later revision)
    widened = db_data(admin_users=[
        {"login": "admin", "registered": None, "admin": False},
        {"login": "siteowner", "registered": None, "admin": True},
    ])
    assert check_db_admin_accounts(widened, DEFAULTS) == []


# ------------------------------------------------------ registry integration

# db.active_missing is registered by wpt.audit.webroot (the plugin-unit
# semantics owner) but still belongs to the "db" selector group.
CHECK_NAMES = [
    "db.active_missing",
    "db.admin_accounts", "db.autoload", "db.charset", "db.ghost_tables",
    "db.optimize", "db.orphan_meta", "db.revisions", "db.transients",
]


def test_registry_contains_all_nine():
    checks = {rec.name: rec for rec in all_checks()}
    for name in CHECK_NAMES:
        assert name in checks, name
        assert checks[name].applies == ("ftp", "local")


def test_select_db_group_selectable():
    assert [rec.name for rec in select_checks("ftp", ["db"], None)] == CHECK_NAMES
    assert [rec.name for rec in select_checks("local", ["db"], None)] == CHECK_NAMES


def _rich_db_site():
    """One DB-side fixture exercising all nine checks once (active
    akismet with an empty tree also fires db.active_missing — the
    tree-based member of the db group)."""
    return db_data(
        revisions=42,
        transients=7,
        orphan_meta={"postmeta": 5, "termmeta": 0, "commentmeta": 3},
        big_autoload=[
            ("opt_mid", 150000), ("opt_huge", 900000), ("opt_big", 300000),
        ],
        tables={
            "wp_posts": T(rows=100, size=1048576, free=0, charset="latin1"),
            "wp_postmeta": T(rows=900, size=2097152, free=1048576,
                              charset="utf8mb4"),  # at limit
            "wp_options": T(rows=300, size=524288, free=2097152,
                            charset="utf8mb4"),
            "wp_woocommerce_orders": T(rows=12, size=2097152, free=None,
                                       charset=None),
            "wp_nf3_forms": T(rows=4, size=None, free=None),  # size unknown
        },
        active=["akismet/akismet.php"],
        admin_users=[
            {"login": "admin", "registered": "2015-04-03 10:00:00",
             "admin": True},
            {"login": "siteowner", "registered": None, "admin": True},
        ],
    )


def test_run_checks_end_to_end():
    data = _rich_db_site()
    findings = run_checks(data, DEFAULTS, "ftp", ["db"], None)
    # every check contributed, in the registry's name-sorted execution order
    assert [(f.category, f.name) for f in findings] == [
        ("db.active_missing", "active-missing-plugins"),
        ("db.admin_accounts", "default-admin-login"),
        ("db.autoload", "big-autoload-options"),
        ("db.charset", "non-utf8mb4-tables"),
        ("db.ghost_tables", "ghost-tables"),
        ("db.optimize", "optimize-candidates"),
        ("db.orphan_meta", "commentmeta"),
        ("db.orphan_meta", "postmeta"),
        ("db.revisions", "revisions"),
        ("db.transients", "expired-transients"),
    ]
    for f in findings:
        f.validate()
    assert {(f.category, f.name): (f.count, f.bytes, f.risk) for f in findings} == {
        ("db.active_missing", "active-missing-plugins"): (1, 0, "high"),
        ("db.admin_accounts", "default-admin-login"): (1, 0, "high"),
        ("db.autoload", "big-autoload-options"): (3, 1350000, "medium"),
        ("db.charset", "non-utf8mb4-tables"): (1, 0, "medium"),
        ("db.ghost_tables", "ghost-tables"): (2, 2097152, "medium"),
        ("db.optimize", "optimize-candidates"): (2, 1048576 + 2097152, "low"),
        ("db.orphan_meta", "commentmeta"): (3, 0, "low"),
        ("db.orphan_meta", "postmeta"): (5, 0, "low"),
        ("db.revisions", "revisions"): (42, 0, "low"),
        ("db.transients", "expired-transients"): (7, 0, "low"),
    }
    # the checks are pure (data, settings) functions: both source modes
    # audit the same gathered facts identically
    local = run_checks(data, DEFAULTS, "local", ["db"], None)
    assert local == findings


def test_ghost_tables_degrades_on_an_unmeasured_active_set():
    """[L53] db.ghost_tables must ask the SAME measured question as the other
    three consumers: an unmeasurable active set (a contested options-table
    identity, an unreadable active_plugins value) must not crash the check
    (audit.check_failed, HIGH) and must not report."""
    from dataclasses import replace
    from wpt.audit.dbcheck import check_db_ghost_tables
    d = replace(db_data(tables={"wp_jetpack_options": T(rows=3, size=20)},
                      active=["woocommerce/woocommerce.php"]), active_plugins=None)
    assert check_db_ghost_tables(d, DEFAULTS) == []
    d2 = replace(d, active_plugins=[])
    # a MEASURED set still reports the ghost table (a removed plugin's)
    assert [f.name for f in check_db_ghost_tables(d2, load())] == ["ghost-tables"]
