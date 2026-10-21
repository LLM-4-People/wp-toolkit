"""Unit tests for the media audit check (wpt.audit.media) — W6e.

Hand-built AuditData only: direct Entry construction, Settings from the
shipped profile (wpt.settings.load()) — the check consumes ONE tunable
(``settings.media.extensions``, the media-extension allowlist), so
every test uses the shipped DEFAULTS unchanged unless it says
otherwise.  No gatherers, no sources, no network, no sleeps —
deterministic.  live_refs fixtures are uploads-RELATIVE POSIX paths
("2023/10/pic-300x233.jpg"), the exact contract the W7 walker must
deliver (see wpt/audit/media.py).

Test -> behavior map (W6e task list):
  test_live_refs_none_degrades_to_the_marker_not_to_candidates
        no live walk AND no database set: no candidate, and the
        zero-count media.unmeasurable marker — never guess a keep-set and
        never read as a clean one
  test_L5_referenced_original_keeps_variants . ref to the original keeps
        its -300x233 and -scaled files [L5]; exact finding shape pinned
  test_L5_variant_ref_keeps_original_symmetric  a ref to ONLY a variant
        keeps the original too — stem matching is symmetric [L5]
  test_stem_chain_reduces_to_original ........ -scaled-1024x768 chained
        suffix reduces to the same stem as the original (PHP strip loop)
  test_file_stem_mirrors_php_helper .......... exact stem pins of
        wpt_file_stem's documented examples, dotfile/loop-bound edges
  test_unreferenced_flagged_count_bytes_detail  count/bytes summed over
        flagged files; detail lines uploads-relative (prefix stripped),
        sorted; every field of the finding pinned
  test_detail_truncates_at_ten ............... 12 files -> 10 lines
        + "(+2 more)", count/bytes still over ALL files
  test_stem_match_same_directory_only ........ a "2023/10/pic.jpg" ref
        does NOT keep "2023/11/pic-300x233.jpg" (other month dir)
  test_stem_similar_files_not_kept ........... "pic-other.jpg",
        "picother.jpg" and WP's collision copy "pic-1.jpg" are not kept
        by "pic.jpg" refs (different stripped stems)
  test_absent_ref_keeps_on_disk_siblings ..... a ref with no on-disk
        file keeps its on-disk stem siblings; the absent ref itself is
        never flagged (it is a reference, not a file)
  test_measured_empty_refs_flag_everything ... live_refs == set() is a
        REAL measured result: every uploads file flagged
  test_non_uploads_files_never_flagged ........ plugins/themes/core
        files and the uploads-backup sibling directory never participate
  test_non_media_uploads_files_never_flagged  [L14] .htaccess, index.php
        and an unlisted extension under uploads are invisible even with
        EMPTY live refs — a content walk can never "reference" a guard
        or config file (Wordfence's PHP-execution block)
  test_is_media_extension_gates ............... the is_media helper:
        dotfiles never media, no-dot never, reversed double extensions
        (.jpg.php) never, case-insensitive allowlist match
  test_uploads_directories_never_flagged ..... dir entries under
        uploads (including the uploads dir itself) are invisible
  test_all_referenced_silent ................. everything kept -> []
  test_no_uploads_files_silent ............... refs but no uploads
        files -> []
  test_deterministic_detail_ordering ......... shuffled walk order ->
        identical finding
  test_check_does_not_mutate_data ............. entries and live_refs
        untouched after the run
  test_registry_integration .................. "media.unreferenced"
        registered for both modes; "media" prefix selects it
  test_run_checks_end_to_end ................. run_checks(["media"])
        pipeline over a fixture, ftp == local, Finding validates
  the UNION keep-set (the live-proven database-only defect):
    test_union_keeps_the_media_the_walk_never_renders  the walk sees 2 of
        10 files, the database references all 10; only the file neither
        side references is reported, and the fix names the full-union
        evidence class
    test_local_mode_degrades_to_the_database_set_with_a_marker  no live
        walk is no longer silence: a real DB-only number, marked DEGRADED
        with the missing side in the operator's words
    test_walk_only_set_says_the_database_half_is_missing  the mirror
        degrade (unreachable bridge)
    test_both_sides_unknown_enumerates_nothing_but_says_so
        neither side measured: [] candidates + the marker
    test_a_run_with_no_database_at_all_keeps_the_media_check_quiet
        an input that declared no table degrades EVERY database check at
        once; the marker would say it once per category
    test_a_measured_set_never_carries_the_marker .. the control: a measured
        (even empty) keep-set reads exactly as it always did
    test_the_unmeasurable_marker_survives_the_report_contract
        the persisted-report contract: both twins carry the degradation,
        count=0 keeps it out of every total, and the category matches NO
        suggested-step rule (a media.unreferenced finding would advise
        `wpt trim-media --apply` for a run that measured nothing)
    test_database_ref_keeps_its_on_disk_variants  the L5 stem rule on a DB
        reference (a restored thumbnail survives)
    test_protected_by_is_the_keep_rule_over_one_path  the apply-side
        re-verification helper
"""

from wpt.audit.data import AuditData, TableFact
from wpt.audit.media import (
    _file_stem,
    UNMEASURED_CATEGORY,
    check_media_unreferenced,
    is_media,
    protected_by,
)
from wpt.audit.registry import all_checks, run_checks, select_checks
from wpt.settings import load
from wpt.types import Entry

#: The shipped profile (wpt/data/profiles/default.json) — exactly as users
#: get it; the check has no tunables of its own.
DEFAULTS = load()


#: One gathered table fact — the marker only asks whether a database was
#: measured, never what it held.
_TABLE = TableFact(rows=10, size_bytes=1024, data_free_bytes=None,
                   collation=None, charset="utf8mb4")


def E(path, size=0, is_dir=False):
    """One Entry, webroot-relative POSIX."""
    return Entry(path=path, is_dir=is_dir, size=size)


def audit_data(entries, live_refs=None, db_refs=None, mode="local",
               measured_db=False):
    """A hand-built AuditData: walked tree + the TWO reference sets.

    ``db_refs`` is the database half of the union keep-set (None = not
    measured, which is what an ftp run without a reachable bridge has).
    ``measured_db`` says whether the run saw a DATABASE at all — the fact
    the unmeasurable marker is about (a dump that declared no table is a
    degradation of every database check at once, and the media check has
    nothing to add to their silence).
    """
    return AuditData(
        mode=mode,
        entries=list(entries),
        siteurl=None,
        home=None,
        template=None,
        blog_public=None,
        wp_version=None,
        mu_plugins=None,
        active_plugins=[],
        plugin_catalog={},
        uploads_basedir="wp-content/uploads",
        posts={},
        revisions=None,
        expired_transients=None,
        orphan_meta={},
        attachments=None,
        nav_menu_items=None,
        autoload_bytes=None,
        big_autoload_options=[],
        tables=({"wp_options": _TABLE} if measured_db else {}),
        live_refs=live_refs,
        db_refs=db_refs,
    )


# --------------------------------------------------------- degrade vs empty


def test_live_refs_none_degrades_to_the_marker_not_to_candidates():
    # no live walk (W7 unwired) and no database set: never guess a
    # keep-set, and never read as a CLEAN one either
    d = audit_data(
        [
            E("wp-content/uploads/2023/10/orphan.jpg", 100),
            E("wp-content/uploads/2023/10/another.png", 50),
        ],
        live_refs=None,  # no live walk — NEVER guess
        measured_db=True,
    )
    findings = check_media_unreferenced(d, DEFAULTS)
    assert [f.category for f in findings] == [UNMEASURED_CATEGORY]
    assert [f.count for f in findings] == [0]      # no candidate at all
    assert findings[0].bytes == 0                 # no reclaimable estimate


def test_measured_empty_refs_flag_everything():
    d = audit_data(
        [
            E("wp-content/uploads/a.jpg", 10),
            E("wp-content/uploads/2023/b.png", 20),
            E("wp-content/plugins/akismet/img.png", 99),  # not uploads
        ],
        live_refs=set(),  # measured: the site references nothing
    )
    findings = check_media_unreferenced(d, DEFAULTS)
    assert [
        (f.category, f.name, f.detail, f.bytes, f.count, f.risk, f.fix)
        for f in findings
    ] == [
        ("media.unreferenced", "unreferenced-media",
         "2023/b.png\na.jpg", 30, 2, "medium",
         "trim-media after reviewing; verify all references afterwards "
         "(evidence: unreferenced by the live walk only (no database "
         "reference set)). DEGRADED — no database reference set: attachment "
         "metadata, theme options, widgets, menus and post content are NOT "
         "part of this set; run it against the live site (ftp source) for "
         "the full reference set"),
    ]
    findings[0].validate()


# ------------------------------------------------------------ L5 keep-set


def test_L5_referenced_original_keeps_variants():
    d = audit_data(
        [
            E("wp-content/uploads/2023/10/pic.jpg", 1000),
            E("wp-content/uploads/2023/10/pic-300x233.jpg", 233),
            E("wp-content/uploads/2023/10/pic-scaled.jpg", 800),
            E("wp-content/uploads/2023/10/zz-unused.jpg", 90),
        ],
        live_refs={"2023/10/pic.jpg"},  # the original is referenced
    )
    findings = check_media_unreferenced(d, DEFAULTS)
    assert [
        (f.category, f.name, f.detail, f.bytes, f.count, f.risk, f.fix)
        for f in findings
    ] == [
        ("media.unreferenced", "unreferenced-media",
         "2023/10/zz-unused.jpg", 90, 1, "medium",
         "trim-media after reviewing; verify all references afterwards "
         "(evidence: unreferenced by the live walk only (no database "
         "reference set)). DEGRADED — no database reference set: attachment "
         "metadata, theme options, widgets, menus and post content are NOT "
         "part of this set; run it against the live site (ftp source) for "
         "the full reference set"),
    ]
    findings[0].validate()


def test_L5_variant_ref_keeps_original_symmetric():
    d = audit_data(
        [
            E("wp-content/uploads/2023/10/pic.jpg", 1000),
            E("wp-content/uploads/2023/10/pic-300x233.jpg", 233),
            E("wp-content/uploads/2023/10/unused.jpg", 70),
        ],
        live_refs={"2023/10/pic-300x233.jpg"},  # ONLY the variant is live
    )
    findings = check_media_unreferenced(d, DEFAULTS)
    assert len(findings) == 1
    f = findings[0]
    f.validate()
    assert (f.count, f.bytes) == (1, 70)
    assert f.detail == "2023/10/unused.jpg"  # the original was kept too


def test_stem_chain_reduces_to_original():
    d = audit_data(
        [
            E("wp-content/uploads/2023/05/img.jpg", 400),
            E("wp-content/uploads/2023/05/img-scaled-1024x768.jpg", 300),
            E("wp-content/uploads/2023/05/img-scaled.jpg", 200),
            E("wp-content/uploads/2023/05/img-1024x768.jpg", 150),
            E("wp-content/uploads/2023/05/other.jpg", 10),
        ],
        live_refs={"2023/05/img.jpg"},
    )
    findings = check_media_unreferenced(d, DEFAULTS)
    assert len(findings) == 1
    f = findings[0]
    assert (f.count, f.bytes) == (1, 10)
    assert f.detail == "2023/05/other.jpg"  # every chained sibling kept


def test_file_stem_mirrors_php_helper():
    # the PHP docblock's own canonical examples (bridge.php wpt_file_stem)
    assert _file_stem("2023/10/pic-300x233.jpg") == "pic"
    assert _file_stem("pic.jpg") == "pic"
    # chained suffixes strip one per pass, exactly like the PHP loop
    assert _file_stem("img-scaled-1024x768.jpg") == "img"
    assert _file_stem("img-1024x768-scaled.jpg") == "img"
    # no extension / dotfile (dot at position 0 -> empty stem, PHP parity)
    assert _file_stem("2023/10/a-300x233") == "a"
    assert _file_stem(".htaccess") == ""
    # incomplete or wrong-case suffixes are NOT stripped (case-sensitive,
    # digits required on both sides of the x, like PCRE without modifiers)
    assert _file_stem("report-2023x.pdf") == "report-2023x"
    assert _file_stem("photo-SCALED.jpg") == "photo-SCALED"
    assert _file_stem("photo-300X233.jpg") == "photo-300X233"
    # the 5-pass loop bound mirrors the PHP for-loop exactly
    six_suffixes = "a" + "-1x1" * 6
    assert _file_stem(six_suffixes + ".jpg") == "a-1x1"  # 5 stripped, 1 left


# ---------------------------------------------------------- flag boundaries


def test_unreferenced_flagged_count_bytes_detail():
    d = audit_data(
        [
            E("wp-content/uploads/banner.jpg", 500),        # kept (a ref)
            E("wp-content/uploads/old1.jpg", 100),
            E("wp-content/uploads/2023/10/old2.png", 200),
        ],
        live_refs={"banner.jpg"},
    )
    findings = check_media_unreferenced(d, DEFAULTS)
    assert [
        (f.category, f.name, f.detail, f.bytes, f.count, f.risk, f.fix)
        for f in findings
    ] == [
        ("media.unreferenced", "unreferenced-media",
         "2023/10/old2.png\nold1.jpg", 300, 2, "medium",
         "trim-media after reviewing; verify all references afterwards "
         "(evidence: unreferenced by the live walk only (no database "
         "reference set)). DEGRADED — no database reference set: attachment "
         "metadata, theme options, widgets, menus and post content are NOT "
         "part of this set; run it against the live site (ftp source) for "
         "the full reference set"),
    ]
    findings[0].validate()


def test_detail_truncates_at_ten():
    entries = [E(f"wp-content/uploads/dir/f{i:02d}.jpg", 10 + i)
               for i in range(12)]
    d = audit_data(entries, live_refs=set())
    findings = check_media_unreferenced(d, DEFAULTS)
    assert len(findings) == 1
    f = findings[0]
    assert f.count == 12                                  # over ALL files
    assert f.bytes == sum(10 + i for i in range(12))
    assert f.detail == "\n".join(
        f"dir/f{i:02d}.jpg" for i in range(10)
    ) + "\n(+2 more)"


def test_stem_match_same_directory_only():
    d = audit_data(
        [
            E("wp-content/uploads/2023/10/pic.jpg", 100),
            E("wp-content/uploads/2023/11/pic-300x233.jpg", 233),
        ],
        live_refs={"2023/10/pic.jpg"},
    )
    findings = check_media_unreferenced(d, DEFAULTS)
    assert len(findings) == 1
    f = findings[0]
    assert (f.count, f.bytes) == (1, 233)
    assert f.detail == "2023/11/pic-300x233.jpg"  # other month dir: NOT kept


def test_stem_similar_files_not_kept():
    d = audit_data(
        [
            E("wp-content/uploads/2023/10/pic.jpg", 100),
            E("wp-content/uploads/2023/10/pic-other.jpg", 100),
            E("wp-content/uploads/2023/10/picother.jpg", 100),
            E("wp-content/uploads/2023/10/pic-1.jpg", 100),  # collision copy
        ],
        live_refs={"2023/10/pic.jpg"},
    )
    findings = check_media_unreferenced(d, DEFAULTS)
    assert len(findings) == 1
    f = findings[0]
    assert f.count == 3
    assert f.detail == (
        "2023/10/pic-1.jpg\n2023/10/pic-other.jpg\n2023/10/picother.jpg"
    )


def test_absent_ref_keeps_on_disk_siblings():
    d = audit_data(
        [
            E("wp-content/uploads/2023/10/ghost-300x200.jpg", 100),
            E("wp-content/uploads/2023/10/stray.jpg", 40),
        ],
        live_refs={"2023/10/ghost.jpg"},  # no on-disk entry for the ref
    )
    findings = check_media_unreferenced(d, DEFAULTS)
    assert len(findings) == 1
    f = findings[0]
    f.validate()
    assert (f.count, f.bytes) == (1, 40)
    # the absent ref itself appears in no finding line — it is a
    # reference, not a file
    assert f.detail == "2023/10/stray.jpg"


def test_non_uploads_files_never_flagged():
    d = audit_data(
        [
            E("wp-content/plugins/akismet/img.png", 100),
            E("wp-content/themes/twentytwentyone/asset.jpg", 50),
            E("wp-admin/images/x.png", 5),
            E("readme.html", 100),
            E("wp-content/uploads-backup/orphan.jpg", 60),  # sibling dir
            E("wp-content/uploads/sub/orphan.jpg", 30),
        ],
        live_refs=set(),
    )
    findings = check_media_unreferenced(d, DEFAULTS)
    assert len(findings) == 1
    f = findings[0]
    assert f.count == 1
    assert f.detail == "sub/orphan.jpg"


def test_non_media_uploads_files_never_flagged():
    """[L14] Non-media uploads files are invisible to the finding even
    at EMPTY live refs (the everything-is-unreferenced plan): a content
    walk can never "reference" a guard or config file, and trim-media
    (the same shared enumeration) must never plan them for deletion —
    the live case was Wordfence's uploads .htaccess PHP-execution
    block landing in a trim plan."""
    d = audit_data(
        [
            E("wp-content/uploads/.htaccess", 152),      # Wordfence block
            E("wp-content/uploads/index.php", 28),        # core guard
            E("wp-content/uploads/.user.ini", 103),       # hoster shim
            E("wp-content/uploads/shell.jpg.php", 400),   # reversed double ext
            E("wp-content/uploads/2023/10/data.xyz", 50),  # unlisted extension
            E("wp-content/uploads/2023/10/orphan.jpg", 100),
        ],
        live_refs=set(),
    )
    findings = check_media_unreferenced(d, DEFAULTS)
    assert len(findings) == 1
    f = findings[0]
    assert f.count == 1
    assert f.detail == "2023/10/orphan.jpg"   # ONLY the media file


def test_is_media_extension_gates():
    # dotfiles have no extension to allow; a name without a dot never
    # matches; a reversed double extension is its LAST extension (.php)
    assert not is_media(".htaccess", ["htaccess", "jpg"])
    assert not is_media(".htaccess", DEFAULTS.media.extensions)
    assert not is_media("README", DEFAULTS.media.extensions)
    assert not is_media("x.jpg.php", DEFAULTS.media.extensions)
    assert not is_media("data.xyz", DEFAULTS.media.extensions)
    assert is_media("photo.JPG", DEFAULTS.media.extensions)     # case
    assert is_media("2023/10/pic-300x233.jpg", DEFAULTS.media.extensions)
    # the uploads prefix is irrelevant to the helper (paths pass through)
    assert is_media("wp-content/uploads/a.png", ["png"])


def test_uploads_directories_never_flagged():
    d = audit_data(
        [
            E("wp-content/uploads", 0, is_dir=True),
            E("wp-content/uploads/2023", 0, is_dir=True),
            E("wp-content/uploads/2023/10", 0, is_dir=True),
        ],
        live_refs=set(),
    )
    assert check_media_unreferenced(d, DEFAULTS) == []


# --------------------------------------------------------------- silence


def test_all_referenced_silent():
    d = audit_data(
        [E("wp-content/uploads/2023/10/pic.jpg", 100)],
        live_refs={"2023/10/pic.jpg"},
    )
    assert check_media_unreferenced(d, DEFAULTS) == []


def test_no_uploads_files_silent():
    d = audit_data(
        [E("wp-content/plugins/akismet/akismet.php", 100)],
        live_refs={"2023/10/none.jpg"},
    )
    assert check_media_unreferenced(d, DEFAULTS) == []


# ---------------------------------------------------------- determinism


def test_deterministic_detail_ordering():
    specs = [("x/3.jpg", 3), ("x/1.jpg", 1), ("x/2.jpg", 2)]
    forward = audit_data(
        [E("wp-content/uploads/" + p, s) for p, s in specs], live_refs=set()
    )
    reverse = audit_data(
        [E("wp-content/uploads/" + p, s) for p, s in reversed(specs)],
        live_refs=set(),
    )
    assert check_media_unreferenced(forward, DEFAULTS) == \
        check_media_unreferenced(reverse, DEFAULTS)


def test_check_does_not_mutate_data():
    # the check is a pure function of the gathered facts: entries and the
    # live reference set are never touched (the ONE documented write is
    # the memoized database map, pinned in the media_refs tests — a
    # hand-built AuditData here has no probe, so nothing is written).
    d = audit_data(
        [E("wp-content/uploads/u/a.jpg", 5), E("wp-content/uploads/u/b.jpg", 6)],
        live_refs={"u/a.jpg"}, db_refs=set(),
    )
    entries_before = list(d.entries)
    refs_obj = d.live_refs
    assert check_media_unreferenced(d, DEFAULTS)[0].count == 1
    assert d.entries == entries_before
    assert d.live_refs is refs_obj and d.live_refs == {"u/a.jpg"}


# ------------------------------------------------------- the UNION keep-set
#
# The live-proven defect (an observed site): a page renders only a FRACTION
# of its attachment images, so a walk-only keep-set planned most of the media
# files and bytes for deletion — every one of them database-referenced
# (featured images in menus/widgets/theme options, srcset candidates,
# attachment pages, gallery templates, PDFs in post content).  The
# defensible remainder on that site was small.


def test_union_keeps_the_media_the_walk_never_renders():
    # the database-heavy shape at the check level: the walk sees 2 of 10 files, the
    # database references all 10; only the 11th, unreferenced by BOTH,
    # may ever be reported
    entries = [E(f"wp-content/uploads/2023/10/f{i:02d}.jpg", 10)
               for i in range(11)]
    walk_sees = {"2023/10/f00.jpg", "2023/10/f01.jpg"}
    database_sees = {f"2023/10/f{i:02d}.jpg" for i in range(10)}
    d = audit_data(entries, live_refs=walk_sees, db_refs=database_sees)
    findings = check_media_unreferenced(d, DEFAULTS)
    assert len(findings) == 1
    f = findings[0]
    assert (f.count, f.bytes) == (1, 10)
    assert f.detail == "2023/10/f10.jpg"   # uploads-relative detail
    assert "unreferenced by the live walk and the database" in f.fix
    assert "DEGRADED" not in f.fix


def test_local_mode_degrades_to_the_database_set_with_a_marker():
    # no live walk (local mode renders nothing) is NOT silence any more:
    # the database half is a REAL measurement, labelled as such so the
    # number is never read as the full picture
    d = audit_data(
        [E("wp-content/uploads/2023/10/db-only.jpg", 100),
         E("wp-content/uploads/2023/10/gone.jpg", 40)],
        live_refs=None, db_refs={"2023/10/db-only.jpg"},
    )
    findings = check_media_unreferenced(d, DEFAULTS)
    assert len(findings) == 1
    f = findings[0]
    assert (f.count, f.bytes, f.detail) == (1, 40, "2023/10/gone.jpg")
    assert "unreferenced by the database only (no live walk)" in f.fix
    assert "DEGRADED" in f.fix
    assert "rendered pages, srcset candidates and CSS url()" in f.fix
    assert "full reference set" in f.fix


def test_walk_only_set_says_the_database_half_is_missing():
    # the mirror degrade: the database map was unavailable, so the
    # walk-only candidates are labelled with what they could not see
    d = audit_data(
        [E("wp-content/uploads/2023/10/a.jpg", 10)],
        live_refs=set(), db_refs=None,
    )
    f = check_media_unreferenced(d, DEFAULTS)[0]
    assert "unreferenced by the live walk only" in f.fix
    assert "no database reference set" in f.fix


def test_both_sides_unknown_enumerates_nothing_but_says_so():
    # neither reference class measured: never guess a keep-set, and the
    # report carries the degradation instead of reading clean
    d = audit_data(
        [E("wp-content/uploads/2023/10/a.jpg", 10)],
        live_refs=None, db_refs=None, measured_db=True,
    )
    findings = check_media_unreferenced(d, DEFAULTS)
    assert [f.category for f in findings] == [UNMEASURED_CATEGORY]
    assert [f.count for f in findings] == [0]
    assert "not a clean one" in findings[0].detail


def test_a_run_with_no_database_at_all_keeps_the_media_check_quiet():
    # THE OTHER HALF of the condition, and the reason it exists: an input
    # that declared no table (an empty or foreign --sql) degrades the whole
    # database half of the audit, of which the media check is one voice.
    # A marker per check would say the same thing once per category; the
    # other database checks' silence already says it.
    d = audit_data(
        [E("wp-content/uploads/2023/10/a.jpg", 10)],
        live_refs=None, db_refs=None, measured_db=False,
    )
    assert check_media_unreferenced(d, DEFAULTS) == []


def test_a_measured_set_never_carries_the_marker():
    # the control for the marker: a MEASURED keep-set (even an empty one)
    # reads exactly as it always did — no marker, and the real candidates
    d = audit_data(
        [
            E("wp-content/uploads/2023/10/a.jpg", 10),
            E("wp-content/uploads/2023/10/b.jpg", 10),
        ],
        live_refs=set(), db_refs=set(), measured_db=True,
    )
    findings = check_media_unreferenced(d, DEFAULTS)
    assert [f.category for f in findings] == ["media.unreferenced"]
    assert findings[0].count == 2


def test_the_unmeasurable_marker_survives_the_report_contract():
    """THE PERSISTED-REPORT CONTRACT: a reader of a --report file must not
    be able to mistake an unmeasured site for a clean one.

    Both twins are checked, because the JSON one is what a later run or a
    dashboard reads: the marker carries the degradation, ``count=0`` keeps
    it out of every total, and the category deliberately matches NO
    suggested-step rule (a ``media.unreferenced`` finding would advise
    ``wpt trim-media --apply`` — a deletion for a run that measured
    nothing).
    """
    from wpt.report import (
        AuditReport, render_report, suggested_step_for, to_json,
    )

    d = audit_data(
        [E("wp-content/uploads/2023/10/a.jpg", 10)],
        live_refs=None, db_refs=None, measured_db=True,
    )
    findings = check_media_unreferenced(d, DEFAULTS)
    report = AuditReport(site="local:site.zip", source_summary="zip + dump",
                         findings=findings)
    payload = to_json(report)
    marker = [f for f in payload["findings"]
              if f["category"] == UNMEASURED_CATEGORY]
    assert len(marker) == 1
    assert "DEGRADED" in marker[0]["detail"]
    assert marker[0]["count"] == 0 and marker[0]["bytes"] == 0
    assert payload["reclaimable_bytes"] == 0
    assert suggested_step_for(UNMEASURED_CATEGORY) is None
    text = render_report(report)
    assert UNMEASURED_CATEGORY in text and "unmeasured-keep-set" in text
    assert "DEGRADED" in text
    # ... and the CONTROL: a healthy measured run still renders no marker
    healthy = check_media_unreferenced(
        audit_data([E("wp-content/uploads/2023/10/a.jpg", 10)],
                   live_refs=set(), db_refs=set(), measured_db=True),
        DEFAULTS)
    assert UNMEASURED_CATEGORY not in render_report(
        AuditReport(site="local:site.zip", source_summary="zip + dump",
                    findings=healthy))


def test_database_ref_keeps_its_on_disk_variants():
    # the L5 stem rule applies to a DATABASE reference exactly as to a
    # rendered one: the attachment's own file keeps its -300x233 and
    # -scaled siblings (this is what saves a thumbnail on the site the
    # live measurement came from)
    d = audit_data(
        [E("wp-content/uploads/2023/11/pic.png", 1000),
         E("wp-content/uploads/2023/11/pic-150x150.png", 233),
         E("wp-content/uploads/2023/11/pic-1024x768.png", 800),
         E("wp-content/uploads/2023/11/orphan.png", 60)],
        live_refs=None, db_refs={"2023/11/pic.png"},
    )
    f = check_media_unreferenced(d, DEFAULTS)[0]
    assert (f.count, f.bytes, f.detail) == (1, 60, "2023/11/orphan.png")


def test_protected_by_is_the_keep_rule_over_one_path():
    # the apply's re-verification: does a fresh reference set protect this
    # planned path?  Same rule as the enumeration, without a tree walk
    refs = {"2023/10/pic.jpg", "2023/11/other.png"}
    assert protected_by(refs, "2023/10/pic.jpg")
    assert protected_by(refs, "2023/10/pic-300x233.jpg")   # stem sibling
    assert protected_by(refs, "2023/10/pic-scaled.jpg")
    assert not protected_by(refs, "2023/10/zz-unused.jpg")
    # never crosses a directory boundary
    assert not protected_by(refs, "2023/11/pic-300x233.jpg")
    assert not protected_by(refs, "2023/10/pic-other.jpg")


# ------------------------------------------------------ registry integration


def test_registry_integration():
    checks = {rec.name: rec for rec in all_checks()}
    rec = checks["media.unreferenced"]
    assert rec.applies == ("ftp", "local")
    assert rec.func is check_media_unreferenced
    assert [r.name for r in select_checks("ftp", ["media"], None)] == \
        ["media.unreferenced"]
    assert [r.name for r in select_checks("local", ["media"], None)] == \
        ["media.unreferenced"]


def test_run_checks_end_to_end():
    d = audit_data(
        [
            E("wp-content/uploads/2023/10/pic.jpg", 1000),
            E("wp-content/uploads/2023/10/pic-300x233.jpg", 233),
            E("wp-content/uploads/2023/10/keep-scaled.jpg", 500),
            E("wp-content/uploads/2023/10/drop-me.png", 77),
        ],
        live_refs={"2023/10/pic-300x233.jpg", "2023/10/keep-scaled.jpg"},
    )
    findings = run_checks(d, DEFAULTS, "ftp", ["media"], None)
    assert [(f.category, f.name) for f in findings] == [
        ("media.unreferenced", "unreferenced-media"),
    ]
    for f in findings:
        f.validate()
    assert (findings[0].count, findings[0].bytes, findings[0].risk) == \
        (1, 77, "medium")
    # pure (data, settings) checks: both source modes audit the same
    # gathered facts identically
    local = run_checks(d, DEFAULTS, "local", ["media"], None)
    assert local == findings
