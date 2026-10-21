import json
from pathlib import Path

import pytest

from wpt.report import (
    SITE_SCALAR_FACTS,
    AuditReport,
    Plan,
    human_bytes,
    render_json,
    render_report,
    site_cell,
    site_facts,
    suggested_step_for,
    suggested_steps,
    to_json,
)
from wpt.report import md_escape
from wpt.types import Finding, PlanItem


def sample_audit() -> AuditReport:
    return AuditReport(
        site="https://example.test",
        source_summary="ftp://host domains/example.test/public_html",
        findings=[
            Finding(category="webroot.junk", name="error_log", detail="25 MB old-host errors",
                    bytes=26214400, count=1, fix="delete"),
            Finding(category="webroot.junk", name="booked.zip", detail="13 MB plugin archive",
                    bytes=13631488, fix="delete"),
            Finding(category="db.revisions", name="revisions", detail="126 stale revisions",
                    count=126, fix="clean via bridge"),
            Finding(category="security.wp_config_perms", name="wp-config perms",
                    detail="0644 world-readable", risk="medium",
                    fix="chmod 0600 wp-config.php"),
            Finding(category="media.unreferenced", name="5107 files",
                    detail="variants of removed images",
                    bytes=834000000, count=5107, risk="low", fix="trim-media"),
            Finding(category="plugins.duplicate", name="two cache plugins",
                    detail="litespeed + wp-super-cache", risk="high", fix="remove one"),
        ],
        totals={"attachments": 334},
    )


def parity_site_facts() -> dict:
    """A FULL site fact set for the parity contract.

    Every shape the section can render appears here with a DISTINCT
    value: scalar facts (counts and versions), a theme WITH a version,
    active plugins with and without a version, a user roster with an
    email and a role, the posts-by-type summary and the table inventory
    (two sizes, so a renderer that always picks the first row fails).
    A renderer that dropped, hardcoded or zeroed any of them fails the
    twin comparison below.
    """
    return {
        "blogname": "Les Balkans",
        "siteurl": "https://example.test",
        "home": "https://www.example.test",
        "wp_version": "7.1",
        "db_version": "57155",
        "locale": "fr_CA",
        "theme": {"slug": "twentytwentyfive", "version": "1.4"},
        "plugins": [
            {"slug": "elementor", "version": "3.31.0"},
            {"slug": "akismet", "version": None},
        ],
        "users": [
            {"login": "admin", "email": "admin@example.test",
             "role": "administrator"},
            {"login": "editeur", "email": None, "role": "editor"},
        ],
        "posts": [
            {"type": "page", "status": "publish", "count": 31},
            {"type": "post", "status": "publish", "count": 214},
        ],
        "tables": [
            {"name": "wp_posts", "rows": 1000, "size_bytes": 41943040},
            {"name": "wp_options", "rows": 500, "size_bytes": 2097152},
        ],
    }


def steps_audit() -> AuditReport:
    """Findings hitting four DIFFERENT rules — two inside one rule's
    category (webroot.junk) to pin the per-rule dedup."""
    return AuditReport(
        site="https://example.test",
        source_summary="ftp://host domains/example.test/public_html",
        findings=[
            Finding(category="webroot.junk", name="error_log", detail="25 MB",
                    bytes=26214400),
            Finding(category="webroot.junk", name="booked.zip", detail="13 MB",
                    bytes=13631488),
            Finding(category="media.unreferenced", name="5107 files",
                    detail="variants", bytes=834000000, count=5107),
            Finding(category="db.revisions", name="revisions", detail="126",
                    count=126),
            # high risk: proves severity does not change the suggestion,
            # and makes "Needs your call" render for the ordering assert.
            Finding(category="core.integrity", name="wp-includes/foo.php",
                    detail="checksum mismatch", risk="high",
                    fix="restore the official file"),
        ],
        # non-empty totals: an empty dict would let a renderer that drops
        # every total still satisfy the parity assertion
        totals={"entries": 42, "mode": "ftp"},
        # the parity fixture carries the site facts too: a fact rendered
        # in the markdown and dropped from the twin (or the reverse) is
        # exactly the drift this test exists for
        site_facts=parity_site_facts(),
    )


def _step_actions(markdown: str) -> list[str]:
    """The action strings of the Suggested next steps bullets, in order."""
    section = markdown.split("## Suggested next steps", 1)[1]
    bullets = [ln for ln in section.splitlines() if ln.startswith("- ")]
    return [b.split("`")[1] for b in bullets]


def test_render_is_deterministic():
    a = sample_audit()
    first = render_report(a)
    second = render_report(sample_audit())
    assert first == second


def test_category_grouping_and_ordering():
    md = render_report(sample_audit())
    # categories render in deterministic alphabetical order
    order = [md.index(f"## {c}") for c in
             ("db.revisions", "media.unreferenced", "plugins.duplicate",
              "security.wp_config_perms", "webroot.junk")]
    assert order == sorted(order)
    # names sorted inside a category
    junk_pos_error = md.index("error_log")
    junk_pos_zip = md.index("booked.zip")
    assert junk_pos_zip < junk_pos_error


def test_needs_your_call_only_non_low_risk():
    md = render_report(sample_audit())
    assert "## Needs your call" in md
    assert "plugins.duplicate" in md
    assert "security.wp_config_perms" in md
    assert "**[HIGH]**" in md
    # low-risk items must NOT appear in that section
    section = md.split("## Needs your call", 1)[1]
    assert "webroot.junk" not in section
    assert "db.revisions" not in section


def test_reclaimable_totals():
    a = sample_audit()
    md = render_report(a)
    total = 26214400 + 13631488 + 834000000
    assert human_bytes(total) in md


def test_json_twin_roundtrip_and_secret_free():
    import json as jsonlib

    a = sample_audit()
    out = render_json(a)
    parsed = jsonlib.loads(out)
    assert parsed["site"] == "https://example.test"
    assert parsed["reclaimable_bytes"] == a.reclaimable_bytes()
    # findings sorted deterministically
    cats = [f["category"] for f in parsed["findings"]]
    assert cats == sorted(cats)


def test_plan_rendered_with_estimates():
    plan = Plan(items=[
        PlanItem(category="clean-files", target="error_log", detail="delete", bytes_est=26214400),
        PlanItem(category="clean-files", target="booked.zip", detail="delete", bytes_est=13631488, done=True),
    ])
    md = render_report(sample_audit(), plan)
    assert "## Plan" in md
    assert "Plan total estimate:" in md
    assert "| yes |" in md


def test_human_bytes():
    assert human_bytes(0) == "0 B"
    assert human_bytes(512) == "512 B"
    assert human_bytes(2048) == "2.0 KB"
    assert human_bytes(1048576) == "1.0 MB"
    assert human_bytes(1073741824) == "1.0 GB"


def test_secret_in_finding_redacted_in_output():
    a = AuditReport(
        site="https://x",
        source_summary="ftp://user@host password=hunter2",
        findings=[Finding(category="c", name="n", detail="token: abc123")],
    )
    md = render_report(a)
    assert "hunter2" not in md
    assert "abc123" not in md
    assert "password=***" in md


def test_suggested_steps_render_mapping_order_and_dedup():
    md = render_report(steps_audit())
    assert "## Suggested next steps" in md
    # the section sits after Needs your call (core.integrity is high risk)
    assert md.index("## Needs your call") < md.index("## Suggested next steps")
    actions = _step_actions(md)
    # four distinct rules -> four lines, in MAPPING (priority) order —
    # investigate before cleanup — not in finding order
    assert actions == [
        "wpt heal-core --apply",
        "wpt clean-files --apply",
        "wpt clean-db --apply",
        "wpt trim-media --apply",
    ]
    # two webroot.junk findings -> ONE clean-files line
    assert actions.count("wpt clean-files --apply") == 1


def test_suggested_steps_family_collapses_to_one_line():
    a = AuditReport(
        site="https://x",
        source_summary="ftp://h",
        findings=[
            Finding(category="webroot.junk", name="error_log", detail="junk"),
            Finding(category="webroot.stale", name="et_temp", detail="stale dir"),
            Finding(category="webroot.migration", name="backup.sql", detail="leftover"),
        ],
    )
    assert [s["action"] for s in to_json(a)["suggested_steps"]] == [
        "wpt clean-files --apply"
    ]


def test_no_findings_means_no_suggested_steps():
    a = AuditReport(site="https://x", source_summary="ftp://h")
    md = render_report(a)
    assert "Suggested next steps" not in md
    assert "suggested_steps" not in to_json(a)
    assert "suggested_steps" not in render_json(a)


def test_unmapped_category_renders_no_step():
    # a future/unmapped check stays silent — never a wrong suggestion
    a = AuditReport(
        site="https://x",
        source_summary="ftp://h",
        findings=[Finding(category="future.thing", name="n", detail="d")],
    )
    assert "Suggested next steps" not in render_report(a)
    assert "suggested_steps" not in to_json(a)


def test_every_registered_check_has_a_step_rule():
    import wpt.audit  # noqa: F401 — imports register every landed check
    from wpt.audit.registry import all_checks

    production = [rec.name for rec in all_checks()
                  if not rec.name.startswith("t.")]
    assert production, "wpt.audit imported no production checks"
    unmapped = [name for name in production if suggested_step_for(name) is None]
    assert unmapped == []


def test_unverifiable_wp_config_finding_is_not_advised_to_harden():
    # wpt harden deliberately refuses a value PHP decides at runtime, so
    # advising `wpt harden --apply` would send the operator to a no-op.
    finding = Finding(
        category="security.disallow_file_edit",
        name="disallow-file-edit-unverifiable",
        detail="d",
    )
    steps = suggested_steps([finding])
    assert len(steps) == 1
    assert "harden" not in steps[0]["action"]


def test_markdown_and_json_twins_cannot_drift():
    """The two renderers are written separately, so a field added to one and
    forgotten in the other is invisible until an operator compares them. Every
    finding field, the attention set, the reclaimable total and the plan rows
    must agree between the markdown and the JSON."""
    import json as jsonlib

    audit = steps_audit()
    plan = Plan(items=[
        # DISTINCT categories/targets/details: a renderer that hardcoded one
        # value instead of reading the item would otherwise pass.
        PlanItem(category="harden", target="wp-config.php", detail="d",
                 bytes_est=1024, requires_apply=True),
        PlanItem(category="trim-media", target=".htaccess", detail="d2",
                 bytes_est=0, requires_apply=False, done=True),
    ])
    markdown = render_report(audit, plan)
    payload = jsonlib.loads(render_json(audit, plan))

    # The markdown ROW is parsed and compared cell by cell, so dropping a
    # value from either renderer fails instead of passing a substring check.
    rows = _markdown_rows(markdown)
    for finding in audit.findings:
        section = f"## {finding.category}"
        matches = [cells for head, cells in rows
                   if head == section and cells[0] == md_escape(finding.name)]
        assert len(matches) == 1, finding.name
        assert matches[0][1:] == [
            md_escape(finding.detail),
            human_bytes(finding.bytes) if finding.bytes else "—",
            str(finding.count),
            finding.risk,
            md_escape(finding.fix) or "—",
        ], finding.name

    # the JSON carries the same findings, field for field
    # the renderers both order by (category, name), so the projections are
    # compared in that order
    assert payload["findings"] == sorted(
        ({name: getattr(finding, name) for name in finding.__dataclass_fields__}
         for finding in audit.findings),
        key=lambda f: (f["category"], f["name"]),
    )

    # the attention set is exactly the non-low findings, in the markdown
    attention = sorted(
        (f for f in audit.findings if f.risk != "low"),
        key=lambda f: ({"high": 0, "medium": 1}[f.risk], f.category, f.name),
    )
    listed = [line for line in markdown.splitlines()
              if line.startswith("- **[") and "**" in line]
    assert len(listed) == len(attention)
    for line, finding in zip(listed, attention):
        assert finding.risk.upper() in line
        assert finding.name in line

    # totals and the reclaimable estimate agree
    assert payload["reclaimable_bytes"] == audit.reclaimable_bytes()
    assert human_bytes(audit.reclaimable_bytes()) in markdown
    assert payload["totals"] == audit.totals

    # the plan rows are compared the same way, and the JSON keeps the
    # per-item detail markdown omits
    plan_rows = _markdown_rows(markdown, header="## Plan")
    for item in plan.items:
        matches = [cells for head, cells in plan_rows
                   if head == "## Plan" and cells[1] == md_escape(item.target)]
        assert len(matches) == 1, item.target
        assert matches[0] == [
            md_escape(item.category),
            md_escape(item.target),
            md_escape(item.detail),
            human_bytes(item.bytes_est) if item.bytes_est else "—",
            "yes" if item.done else "no",
        ], item.target
    assert payload["plan"]["est_bytes"] == plan.est_bytes()
    assert payload["plan"]["items"] == sorted(
        ({name: getattr(item, name) for name in item.__dataclass_fields__}
         for item in plan.items),
        key=lambda i: (i["category"], i["target"]),
    )

    # the SITE section is compared the same way: the expectations are read
    # back OUT OF THE JSON twin, so a markdown renderer that dropped,
    # reordered or hardcoded a fact fails instead of matching itself
    _assert_site_parity(markdown, payload["site_facts"])


def _site_rows(markdown):
    """``(sub-heading, cells)`` for every row of the ``## Site`` section.

    The fact table reports under ``None`` (it has no sub-heading); each
    sub-table reports under its own ``### `` title.  Both tables and
    their header rows are skipped, exactly like the findings parser.
    """
    rows = []
    in_site = False
    sub = None
    in_table = False
    for line in markdown.splitlines():
        if line.startswith("## "):
            in_site = line == "## Site"
            in_table = False
            continue
        if not in_site:
            continue
        if line.startswith("### "):
            sub = line[4:]
            in_table = False
            continue
        if not line.startswith("|"):
            in_table = False
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if set("".join(cells)) <= set("-: "):
            continue
        if not in_table:
            in_table = True
            continue
        rows.append((sub, cells))
    return rows


def _assert_site_parity(markdown, facts):
    """Markdown Site section vs the JSON twin's site_facts, cell by cell."""
    rows = _site_rows(markdown)
    fact_rows = [tuple(cells) for sub, cells in rows if sub is None]
    table_rows: dict[str, list[list[str]]] = {}
    for sub, cells in rows:
        if sub is not None:
            table_rows.setdefault(sub, []).append(cells)

    # scalars: one row per KNOWN fact, in the section's own order, and NO
    # row for a fact the twin does not carry.  The labels/order are
    # spelled out HERE (not read from the module's constant) so deleting
    # or reordering a fact in the renderer cannot silently move the
    # expectation with it — the section shape is a contract.
    theme = facts["theme"]
    expected = [
        ("blog name", "Les Balkans"),
        ("siteurl", "https://example.test"),
        ("home", "https://www.example.test"),
        ("WordPress version", "7.1"),
        ("DB version", "57155"),
        ("locale", "fr_CA"),
        ("active theme",
         f"{theme['slug']} ({theme['version']})" if theme["version"]
         else theme["slug"]),
    ]
    assert fact_rows == expected, fact_rows
    # the renderer still labels exactly the facts the twin carries
    assert [name for name, _label in SITE_SCALAR_FACTS
            if name in facts] == [
        "blogname", "siteurl", "home", "wp_version", "db_version", "locale"]

    assert table_rows["Active plugins"] == [
        [site_cell(p["slug"]), site_cell(p["version"])]
        for p in facts["plugins"]
    ]
    assert table_rows["Users"] == [
        [site_cell(u["login"]), site_cell(u["email"]), site_cell(u["role"])]
        for u in facts["users"]
    ]
    assert table_rows["Posts by type"] == [
        [site_cell(p["type"]), site_cell(p["status"]), site_cell(p["count"])]
        for p in facts["posts"]
    ]
    assert table_rows["Database tables"] == [
        [site_cell(t["name"]), site_cell(t["rows"]),
         site_cell(human_bytes(t["size_bytes"]) if t["size_bytes"] is not None
                   else None)]
        for t in facts["tables"]
    ]


def _markdown_rows(markdown, header=None):
    """``[(section heading, cells)]`` for every table body row."""
    rows = []
    section = None
    in_table = False
    for line in markdown.splitlines():
        if line.startswith("## "):
            section = line
            in_table = False
            continue
        if not line.startswith("|"):
            in_table = False
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if set("".join(cells)) <= set("-: "):
            continue
        if not in_table:
            if section is None or (header and section != header):
                continue
            in_table = True
            continue
        rows.append((section, cells))
    return rows


def test_suggested_steps_json_twin_matches_markdown():
    import json as jsonlib

    a = steps_audit()
    parsed = jsonlib.loads(render_json(a))
    steps = parsed["suggested_steps"]
    assert all(set(s) == {"action", "why"} for s in steps)
    # same dedup + mapping order as the markdown section
    assert _step_actions(render_report(a)) == [s["action"] for s in steps]
    assert steps[0] == {
        "action": "wpt heal-core --apply",
        "why": "restores checksum-proven tampered/missing core files from "
               "the official WP release (snapshot first; still INVESTIGATE "
               "— healing core does not remove backdoors elsewhere), and "
               "never touches the 'added' files it lists",
    }


# ------------------------------------------------- name-pinned steps [L16]


def test_added_known_gets_advice_not_heal_core():
    """[L16] The low-risk added-known finding renders its OWN advice step
    (verify the plugin artifact) — never the heal-core command, which has
    nothing to restore for a known plugin artifact."""
    from wpt.report import suggested_steps
    a = AuditReport(
        site="https://example.test", source_summary="ftp://host webroot",
        findings=[
            Finding(category="core.integrity", name="added-known",
                    detail="added (known): wordfence-waf.php — ...",
                    fix="verify"),
        ],
        totals={},
    )
    steps = suggested_steps(a.findings)
    assert [s["action"] for s in steps] == [
        "verify the file against a freshly installed copy of the named plugin",
    ]
    assert "heal-core" not in steps[0]["action"]


def test_name_pin_and_core_files_both_render():
    """Tampered core files keep the heal-core suggestion at its priority;
    the added-known pin renders BESIDE it (not instead of it)."""
    from wpt.report import suggested_steps
    findings = [
        Finding(category="core.integrity", name="core-files",
                detail="tampered: wp-includes/version.php", fix="restore"),
        Finding(category="core.integrity", name="added-known",
                detail="added (known): wordfence-waf.php — ...", fix="verify"),
    ]
    steps = suggested_steps(findings)
    assert [s["action"] for s in steps] == [
        "wpt heal-core --apply",   # compromise priority first
        "verify the file against a freshly installed copy of the named plugin",
    ]


def test_unpinned_core_files_rule_unchanged():
    """Findings without a pin keep the category rule verbatim (the
    coverage contract: suggested_step_for still answers core.integrity)."""
    from wpt.report import suggested_step_for
    action, why = suggested_step_for("core.integrity")
    assert action == "wpt heal-core --apply"
    assert "INVESTIGATE" in why


# ------------------------------- the new webroot/db categories' routing


def test_new_check_categories_route_to_their_own_rule():
    """First-match precedence for the two landed checks: a dotted prefix
    must not swallow a longer sibling.

    ``webroot.mu_plugins`` sits after webroot.junk/stale/migration and
    ``db.active_missing`` after the four db-cleanup rules; a naive
    non-dotted match would route both into a generic family's advice
    (``wpt clean-files --apply`` / ``wpt clean-db --apply``), which is
    the wrong command for each of them."""
    from wpt.report import suggested_step_for
    mu_action, mu_why = suggested_step_for("webroot.mu_plugins")
    assert mu_action == (
        "review the hosting-platform must-use plugins; remove them if the "
        "site left that platform"
    )
    assert "every request" in mu_why
    missing_action, missing_why = suggested_step_for("db.active_missing")
    assert "restore the missing plugin directories" in missing_action
    # the actionable alternative is named, so the operator is not told
    # (falsely) that no wpt command can touch the DB side
    assert "reconcile-plugins --apply" in missing_why
    for category in ("webroot.junk", "webroot.junk_recurring",
                     "webroot.stale", "webroot.migration"):
        assert suggested_step_for(category)[0] == "wpt clean-files --apply"
    for category in ("db.revisions", "db.transients", "db.orphan_meta",
                     "db.optimize"):
        assert suggested_step_for(category)[0] == "wpt clean-db --apply"


def test_new_check_categories_suggested_steps_dedup_with_their_families():
    """A finding set where a webroot family member AND webroot.mu_plugins
    both fire renders the family's one line plus the platform line — the
    dedup collapses identical (action, why) pairs, and the two steps keep
    their mapping-order priority."""
    from wpt.report import suggested_steps
    findings = [
        Finding(category="webroot.junk", name="license.txt", detail="d"),
        Finding(category="webroot.mu_plugins", name="platform-mu-plugins",
                detail="d", risk="low"),
    ]
    steps = suggested_steps(findings)
    assert [s["action"] for s in steps] == [
        "wpt clean-files --apply",
        "review the hosting-platform must-use plugins; remove them if the "
        "site left that platform",
    ]


def test_active_missing_advice_renders_in_both_twins():
    """The parity contract covers the new advice: the markdown bullet and
    the JSON twin carry the SAME action/why for a db.active_missing
    finding (a renderer that dropped one of them would leave the operator
    with a command in one output only)."""
    import json as jsonlib
    from wpt.report import render_json, render_report
    audit = AuditReport(
        site="https://example.test", source_summary="ftp://host webroot",
        findings=[Finding(category="db.active_missing",
                           name="active-missing-plugins",
                           detail="akismet, litespeed-cache", risk="high",
                           fix="restore")],
        totals={},
    )
    markdown = render_report(audit)
    payload = jsonlib.loads(render_json(audit))
    assert len(payload["suggested_steps"]) == 1
    step = payload["suggested_steps"][0]
    assert "restore the missing plugin directories" in step["action"]
    assert f"`{step['action']}`" in markdown
    assert step["why"] in markdown
    # the advice item of the clean-files unit guard is a PLAN category: it
    # renders as a row in both twins with its "no" (not applied) column
    plan = Plan(items=[PlanItem(category="webroot.active_unit",
                                target="wp-content/plugins/wpo",
                                detail="active plugin — deactivate first",
                                bytes_est=60, requires_apply=False)])
    md_plan = render_report(audit, plan)
    assert "| webroot.active_unit | wp-content/plugins/wpo |" in md_plan
    assert "| 60 B | no |" in md_plan
    plan_json = jsonlib.loads(render_json(audit, plan))
    assert plan_json["plan"]["items"] == [{
        "category": "webroot.active_unit",
        "target": "wp-content/plugins/wpo",
        "detail": "active plugin — deactivate first",
        "bytes_est": 60,
        "requires_apply": False,
        "done": False,
        # PlanItem.ref is part of the JSON item contract (structural
        # reference; empty when the item does not carry one).
        "ref": "",
    }]


def test_plan_total_estimate_excludes_advice_items():
    """The plan total is what the APPLY delivers, so an advice item
    (``requires_apply=False`` — the clean-files active-unit guard) is
    excluded from it.  Counting it told the operator a plan would
    reclaim 200 B when the only item is a unit that is deliberately NOT
    deleted; the per-row estimate stays, so the size is still visible
    next to the advice that explains it."""
    plan = Plan(items=[
        PlanItem(category="webroot.junk", target="readme.html", detail="d",
                 bytes_est=100, requires_apply=True),
        PlanItem(category="webroot.active_unit",
                 target="wp-content/plugins/wpo",
                 detail="active plugin — deactivate first (wpt "
                        "deactivate-plugin wpo) or remove it in wp-admin",
                 bytes_est=200, requires_apply=False),
    ])
    assert plan.est_bytes() == 100
    markdown = render_report(_audit_stub_report(), plan)
    assert "**Plan total estimate: 100 B**" in markdown
    # the guarded row keeps its own size (and its "no" applied column)
    assert "| 200 B | no |" in markdown
    only_advice = Plan(items=[plan.items[1]])
    assert only_advice.est_bytes() == 0
    assert "**Plan total estimate: 0 B**" in render_report(
        _audit_stub_report(), only_advice)


def _audit_stub_report():
    return AuditReport(site="https://example.test",
                       source_summary="ftp://host webroot",
                       findings=[], totals={})


# ------------------------------------------------------ the Site section [L17]


def _gathered_audit_data(**overrides):
    """A gathered AuditData shaped like a live ftp-mode site."""
    from wpt.audit.data import AuditData, TableFact
    from wpt.types import Entry

    base = dict(
        mode="ftp",
        entries=[Entry("index.php", False, 1024)],
        siteurl="https://example.test",
        home="https://example.test",
        template="twentytwentyfive",
        blog_public=1,
        wp_version="7.1",
        mu_plugins=0,
        active_plugins=["elementor/elementor.php", "akismet/akismet.php"],
        plugin_catalog={
            "elementor/elementor.php": {"name": "Elementor",
                                        "version": "3.31.0", "active": True},
            "akismet/akismet.php": {"name": "Akismet", "version": "5.3",
                                    "active": True},
        },
        uploads_basedir="/home/site/uploads",
        posts={("post", "publish"): 214, ("page", "publish"): 31},
        revisions=126,
        expired_transients=5,
        orphan_meta={},
        attachments=900,
        nav_menu_items=14,
        autoload_bytes=1024,
        big_autoload_options=[],
        tables={
            "wp_options": TableFact(500, 2 * 1048576, 1024),
            "wp_posts": TableFact(1000, 40 * 1048576, None),
            "wp_empty": TableFact(0, None, None),
        },
        admin_users=[{"login": "editeur", "registered": "2024-02-03",
                      "admin": False, "email": "editeur@example.test",
                      "role": "editor"},
                     {"login": "admin", "registered": "2020-01-01",
                      "admin": True, "email": "admin@example.test",
                      "role": "administrator"}],
        locale="fr_CA",
        theme_versions={"twentytwentyfive": "1.4"},
    )
    base.update(overrides)
    return AuditData(**base)


def test_site_facts_maps_the_gathered_audit_data():
    """The ONE builder, pinned fact by fact.

    Deciding anything used to mean querying the database by hand: the
    active theme and its version, the plugin roster WITH versions (the
    operator has to know which of two active page builders is in play),
    the account roster (a password reset needs it up front), the locale
    (the whole locale-integrity job) and the DB's table/size summary.
    Every mapping is asserted here, so a builder that dropped, zeroed or
    reordered one fails instead of quietly shipping a thinner report.
    """
    data = _gathered_audit_data()
    data.blogname = "Les Balkans"       # optional fact the gather maps
    data.db_version = "57155"
    assert site_facts(data) == {
        "blogname": "Les Balkans",
        "siteurl": "https://example.test",
        "home": "https://example.test",
        "wp_version": "7.1",
        "db_version": "57155",
        "locale": "fr_CA",
        "theme": {"slug": "twentytwentyfive", "version": "1.4"},
        # sorted by slug, the version read from the remote catalog
        "plugins": [{"slug": "akismet", "version": "5.3"},
                    {"slug": "elementor", "version": "3.31.0"}],
        # sorted by login; email/role come from the entry, never invented
        "users": [
            {"login": "admin", "email": "admin@example.test",
             "role": "administrator"},
            {"login": "editeur", "email": "editeur@example.test", "role": "editor"},
        ],
        "posts": [{"type": "page", "status": "publish", "count": 31},
                  {"type": "post", "status": "publish", "count": 214}],
        # largest first (ties by name): the DB summary answers "where did
        # the measured bytes go?" — the unknown size sorts last, never as 0
        "tables": [
            {"name": "wp_posts", "rows": 1000, "size_bytes": 40 * 1048576},
            {"name": "wp_options", "rows": 500, "size_bytes": 2 * 1048576},
            {"name": "wp_empty", "rows": 0, "size_bytes": None},
        ],
    }


def test_site_facts_degrades_on_what_a_local_dump_cannot_know():
    """A local gather has no plugin catalog, no theme version and no
    email/role on its user entries: those read as UNKNOWN (None / the em
    dash), never as a guess.  The facts it does know still render."""
    data = _gathered_audit_data(
        mode="local", plugin_catalog={}, theme_versions={},
        admin_users=[{"login": "admin", "registered": None, "admin": True}],
    )
    facts = site_facts(data)
    assert facts["plugins"] == [
        {"slug": "akismet", "version": None},
        {"slug": "elementor", "version": None},
    ]
    assert facts["theme"] == {"slug": "twentytwentyfive", "version": None}
    assert facts["users"] == [{"login": "admin", "email": None, "role": None}]


def test_site_facts_prefers_the_active_stylesheet_over_the_parent():
    """``template`` is the PARENT theme on a child-theme site; the option
    whose value is the theme actually rendering is ``stylesheet``.  When
    the gather carries it, the section must name the theme the site uses."""
    data = _gathered_audit_data(template="twentytwentyfour")
    data.stylesheet = "enfant"       # the gather maps it as a field
    data.theme_versions = {"enfant": "2.1", "twentytwentyfour": "1.4"}
    assert site_facts(data)["theme"] == {"slug": "enfant", "version": "2.1"}


def test_site_section_renders_before_the_findings_in_both_twins():
    """The facts are the inventory the findings are read against, so they
    head the report; the JSON twin carries them under their own key (the
    top-level ``site`` key is the audited URL every consumer reads)."""
    import json as jsonlib

    audit = AuditReport(
        site="https://example.test", source_summary="ftp://host webroot",
        findings=[Finding(category="webroot.junk", name="error_log",
                          detail="d", bytes=10)],
        totals={"entries": 1},
        site_facts=parity_site_facts(),
    )
    markdown = render_report(audit)
    assert markdown.index("## Site") < markdown.index("## webroot.junk")
    assert "| elementor | 3.31.0 |" in markdown
    assert "| akismet | — |" in markdown          # unknown version
    assert "| admin | admin@example.test | administrator |" in markdown
    assert "| editeur | — | editor |" in markdown  # unknown email
    assert "| wp_posts | 1000 | 40.0 MB |" in markdown
    assert "| wp_options | 500 | 2.0 MB |" in markdown
    payload = jsonlib.loads(render_json(audit))
    assert payload["site"] == "https://example.test"
    assert payload["site_facts"] == parity_site_facts()


def test_no_site_facts_means_no_section_and_no_key():
    """A gather that carried nothing (no dump facts at all) must degrade
    to an OMITTED section — never a crash, never an empty table, and the
    report renders exactly as it did before the section existed."""
    import json as jsonlib

    from wpt.audit.data import AuditData
    empty = AuditData(
        mode="local", entries=[], siteurl=None, home=None, template=None,
        blog_public=None, wp_version=None, mu_plugins=None, active_plugins=[],
        plugin_catalog={}, uploads_basedir=None, posts={}, revisions=None,
        expired_transients=None, orphan_meta={}, attachments=None,
        nav_menu_items=None, autoload_bytes=None, big_autoload_options=[],
        tables={}, admin_users=None,
    )
    assert site_facts(empty) is None
    for facts in (None, {}, {"plugins": []}):
        audit = AuditReport(site="https://x", source_summary="ftp://h",
                            findings=[Finding("webroot.junk", "n", "d")],
                            totals={}, site_facts=facts)
        markdown = render_report(audit)
        assert "## Site" not in markdown
        assert "site_facts" not in to_json(audit)
        assert "site_facts" not in jsonlib.loads(render_json(audit))
    # and the no-facts report is byte-identical to one that never heard
    # of the section
    plain = AuditReport(site="https://x", source_summary="ftp://h",
                        findings=[Finding("webroot.junk", "n", "d")],
                        totals={})
    assert render_report(
        AuditReport(site="https://x", source_summary="ftp://h",
                    findings=[Finding("webroot.junk", "n", "d")],
                    totals={}, site_facts=None)
    ) == render_report(plain)


def test_site_roster_email_renders_but_a_secret_shaped_fact_is_masked():
    """Zero secrets, without hiding the operator's own data.

    The report is the operator's own DB dump, written to a path they
    choose, and a password-reset task needs the roster: an email that
    merely looks unusual renders verbatim.  A fact whose NAME is a secret
    slot (a future option that holds one) is rendered ``***`` in BOTH
    twins and its value never reaches the output — the redaction choke
    point is the same one the findings pass through.
    """
    facts = parity_site_facts()
    facts["users"][0]["email"] = "keymaster+token@example.test"
    facts["api_key"] = "sk-live-abcdef"
    audit = AuditReport(site="https://x", source_summary="ftp://h",
                        site_facts=facts)
    markdown = render_report(audit)
    assert "keymaster+token@example.test" in markdown
    assert "sk-live-abcdef" not in markdown
    payload = to_json(audit)["site_facts"]
    assert payload["users"][0]["email"] == "keymaster+token@example.test"
    assert payload["api_key"] == "***"


def test_site_facts_are_facts_not_findings(wpt_records):
    """One INFO line, structural counts only — never a value (a login, an
    email, a URL).  And the section adds no finding, no risk and no
    reclaimable bytes: facts are not findings."""
    facts = site_facts(_gathered_audit_data())
    lines = [r.getMessage() for r in wpt_records if r.name == "wpt.report"]
    assert len(lines) == 1
    assert "plugins=2 users=2 posts=2 tables=3" in lines[0]
    for leak in ("example.test", "admin", "fr_CA", "twentytwentyfive"):
        assert leak not in lines[0]
    audit = AuditReport(site="https://x", source_summary="ftp://h",
                        findings=[Finding("webroot.junk", "n", "d", bytes=10)],
                        totals={}, site_facts=facts)
    assert audit.reclaimable_bytes() == 10
    assert list(audit.findings_by_category()) == ["webroot.junk"]
    # facts alone never suggest an action: they carry no category, so the
    # next-steps section stays empty for a report that has only facts
    facts_only = AuditReport(site="https://x", source_summary="ftp://h",
                             totals={}, site_facts=facts)
    assert "suggested_steps" not in to_json(facts_only)
    assert "Suggested next steps" not in render_report(facts_only)


def test_C10_shared_writer_refuses_to_overwrite_a_protected_input(tmp_path):
    """C10: the CLI gate and the shared writer use ONE predicate.  A
    programmatic caller passing this run's zip/dump must be refused before
    the file is touched, not silently served a markdown report."""
    from wpt.report import write_report_files
    from wpt.types import WptError

    archive = tmp_path / "site.zip"
    archive.write_bytes(b"PK\x03\x04 the input")
    before = archive.read_bytes()

    with pytest.raises(WptError, match="input of this run"):
        write_report_files(archive, "# report", '{"ok": true}',
                           protected_paths=(archive,))
    assert archive.read_bytes() == before
    assert not archive.with_suffix(".json").exists()


def test_R11_serialized_secret_tail_never_reaches_either_report_face(
        tmp_path):
    """R11-P2-1: the shared report writer redacts both faces; a serialized
    value carrying an embedded ``";`` used to leave SUFFIXLEAK behind."""
    from wpt.report import write_report_files

    blob = 's:8:"password";s:15:"abc";SUFFIXLEAK";'
    report = tmp_path / "r.md"
    write_report_files(report, f"# report\n\nrow {blob}\n",
                       '{"row": ' + json.dumps(blob) + "}")
    assert "SUFFIXLEAK" not in report.read_text(encoding="utf-8")
    assert "SUFFIXLEAK" not in report.with_suffix(
        ".json").read_text(encoding="utf-8")
    assert "***" in report.read_text(encoding="utf-8")

    deep = "password=" + "(object)" * 500 + "['HUNTER2']"
    deep_report = tmp_path / "deep.md"
    write_report_files(deep_report, deep, json.dumps({"row": deep}))
    assert "HUNTER2" not in deep_report.read_text(encoding="utf-8")
    assert "HUNTER2" not in deep_report.with_suffix(
        ".json").read_text(encoding="utf-8")


def test_REPORT_SURROGATE_writer_encodes_atomically(tmp_path):
    """REPORT-SURROGATE: one writer encodes both faces with
    backslashreplace and replaces each target only after a complete temp
    write (a strict write truncated the markdown to 0 bytes first)."""
    from wpt.report import write_report_files

    report = tmp_path / "report.md"
    write_report_files(report, "site \udcff markdown", '{"site": "\udcff"}')
    assert report.read_text(encoding="utf-8") == "site \\udcff markdown"
    assert report.with_suffix(".json").read_text(encoding="utf-8") == \
        '{"site": "\\udcff"}'
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "report.json", "report.md"]

    # A missing parent fails BEFORE any target is created or truncated.
    with pytest.raises(OSError):
        write_report_files(tmp_path / "missing" / "r.md", "x")


def test_R7_P2_12_md_escape_flattens_carriage_returns():
    """R7-P2-12: ``md_escape`` flattened ``\\n`` but left a raw CR, letting a
    site-controlled path split/inject a markdown table row."""
    assert md_escape("a\rb") == "a b"
    assert md_escape("a\r\nb") == "a b"
    assert md_escape("a|b\r\nc") == "a\\|b c"


# ------------------------------------------------------- round-8 regressions


def test_R8_P2_22_report_writer_survives_deep_json(tmp_path):
    """R8-P2-22: a deep JSON twin raised RecursionError out of the shared
    writer (``json.loads`` was unguarded); the report must still be written
    with the text redactor as the fallback."""
    from wpt.report import write_report_files

    deep = '{"value": ' + "[" * 5_000 + "0" + "]" * 5_000 + "}"
    report = tmp_path / "r.md"
    write_report_files(report, "payload", deep)
    assert report.read_text(encoding="utf-8") == "payload"
    assert report.with_suffix(".json").is_file()


def test_R8_P2_22_redaction_walk_and_redact_are_depth_bounded():
    """R8-P2-22: 2 000-deep structures raised RecursionError out of both
    redaction owners.  They render a placeholder at the structural bound."""
    import json

    from wpt.config import redact
    from wpt.report import redact_text_walk

    payload = []
    cursor = payload
    for _ in range(2_000):
        child = []
        cursor.append(child)
        cursor = child

    walked = redact_text_walk(payload)
    assert "<max-depth>" in json.dumps(walked)
    redacted = redact(payload)
    assert "<max-depth>" in json.dumps(redacted)


def test_R9_P2_10_report_pair_is_published_atomically(tmp_path):
    """P2-10: markdown was replaced before the twin; a twin failure left a
    NEW success markdown beside rc 1."""
    from wpt.report import write_report_files
    from wpt.types import WptError

    report = tmp_path / "r.md"
    twin = report.with_suffix(".json")
    twin.mkdir()

    with pytest.raises(WptError, match="not a regular file"):
        write_report_files(report, "new success", '{"new": true}')

    assert not report.exists()
    assert twin.is_dir()


def test_R9_P2_10_report_pair_rolls_back_a_replaced_face(
        tmp_path, monkeypatch):
    """A failure publishing the LAST face restores the previously published
    twin (both faces stay the old pair, never half-new)."""
    import wpt.report as report_mod

    report = tmp_path / "r.md"
    twin = report.with_suffix(".json")
    report.write_text("OLD MD", encoding="utf-8")
    twin.write_text("OLD TWIN", encoding="utf-8")

    real_replace = report_mod.os.replace

    def _replace(src, dst):
        if (str(dst) == str(report)
                and Path(src).name.startswith(f".{report.name}.")
                and str(src).endswith(".tmp")):
            raise OSError("simulated markdown publish failure")
        return real_replace(src, dst)

    monkeypatch.setattr(report_mod.os, "replace", _replace)
    with pytest.raises(OSError, match="simulated"):
        report_mod.write_report_files(report, "NEW MD", '{"new": true}')

    assert report.read_text(encoding="utf-8") == "OLD MD"
    assert twin.read_text(encoding="utf-8") == "OLD TWIN"


def test_R9_P2_11_json_twin_redacts_secret_named_keys(tmp_path):
    """P2-11: the twin ran only value redaction, so a secret-keyed map kept
    ``HUNTER2`` while the markdown face was redacted."""
    import json

    from wpt.report import _redact_json_text, write_report_files

    text = '{"password":"HUNTER2","db_password":"HUNTER2","safe":"ok"}'
    redacted = json.loads(_redact_json_text(text))
    assert redacted["password"] == "***"
    assert redacted["db_password"] == "***"
    assert redacted["safe"] == "ok"

    report = tmp_path / "r.md"
    write_report_files(report, "markdown", text)
    twin = json.loads(report.with_suffix(".json").read_text(encoding="utf-8"))
    assert twin["password"] == "***"
    assert twin["db_password"] == "***"
    assert "HUNTER2" not in report.with_suffix(".json").read_text(
        encoding="utf-8")


def test_R8_P2_21_underivable_twin_path_is_a_wpt_error():
    """R8-P2-21: ``Path('.').with_suffix('.json')`` raised ValueError out
    of the shared writer (the twin was derived before the guard); the
    caller's bad --report must be one WptError, never a traceback."""
    from pathlib import Path

    from wpt.report import write_report_files
    from wpt.types import WptError

    for bad in (Path("."), Path("/")):
        with pytest.raises(WptError, match="cannot derive the JSON twin"):
            write_report_files(bad, "payload", "{}")


def test_R12_serialized_non_ascii_lengths_never_reach_either_face(tmp_path):
    """R12-P2-13: report markdown and its JSON twin both route through the
    shared redactor; PHP byte lengths and huge/truncated values leak no
    tail on either face."""
    from wpt.report import write_report_files

    leaks = [
        's:8:"password";s:11:"abc";LEAKé";',
        's:8:"password";s:15:"päss";LEAKTAIL";',
        's:8:"password";s:999999999:"PREFIXLEAK";',
        's:8:"password";s:20:"abc',
    ]
    report = tmp_path / "bytes.md"
    text = "\n".join(leaks)
    write_report_files(report, f"# report\n\n{text}\n",
                       json.dumps({"rows": leaks}))
    assert "LEAK" not in report.read_text(encoding="utf-8")
    assert "LEAK" not in report.with_suffix(".json").read_text(
        encoding="utf-8")


def test_R12_writer_protects_from_paths_without_any_cli_gate(tmp_path):
    """R12-P2-22: the committed regression drives the SHARED writer itself
    with ``ctx.extra["from_paths"]`` (the only prior test was CLI-level,
    so dropping the writer wiring would still pass)."""
    from wpt.actions.registry import write_report
    from wpt.cli import Ctx
    from wpt.settings import load

    source = tmp_path / "edited.php"
    source.write_bytes(b"<?php ORIGINAL")
    ctx = Ctx(source="ftp://h", settings=load(), command="files",
              report_path=source,
              extra={"from_paths": [source]})
    assert write_report(ctx, "files", "# report", "{}") == 1
    assert source.read_bytes() == b"<?php ORIGINAL"
    assert not source.with_suffix(".json").exists()


def test_R13_a_failed_audit_never_refreshes_its_baseline_twin(tmp_path):
    """R13-P2-11: ``write_report`` passed the baseline as REFRESHABLE, so
    every failure report replaced a valid ``prev.json`` with failure JSON —
    the comparison basis was destroyed by the run that failed to compare.
    Only the audit's success emitter owns the refresh."""
    from wpt.actions.registry import write_failure_report
    from wpt.cli import Ctx
    from wpt.settings import effective_profile_path, load

    baseline = tmp_path / "prev.json"
    original = b'{"findings": [{"category": "webroot.junk", "name": "old"}]}\n'
    baseline.write_bytes(original)
    report = tmp_path / "prev.md"
    ctx = Ctx(
        source="ftp://example.test", settings=load(), command="audit",
        report_path=report,
        extra={"baseline": baseline,
               "profile": effective_profile_path(None)},
    )
    assert write_failure_report(ctx, "audit", "boom") == 0
    assert report.exists()
    assert "This run did not complete" in report.read_text(encoding="utf-8")
    assert baseline.read_bytes() == original


def test_R13_default_profile_is_a_protected_input_without_a_flag(tmp_path):
    """R13-P2-12: a run without ``--profile`` still READS the packaged
    default, but only an explicit ``--profile`` entered the protected set.
    The effective path is now recorded and the collision is refused before
    bytes move; an explicit programmatic ctx gets the same protection."""
    from wpt.cli import Ctx
    from wpt.report import (report_input_collision, report_protected_inputs,
                            write_report_files)
    from wpt.settings import effective_profile_path, load
    from wpt.types import WptError

    profile = effective_profile_path(None)
    assert profile.is_file()
    report = profile.with_suffix(".md")   # its .json twin IS the default
    ctx = Ctx(source="ftp://example.test", settings=load(), command="audit",
              report_path=report, extra={"profile": profile})
    protected = report_protected_inputs(ctx)
    assert profile in protected
    assert effective_profile_path(None) in protected
    assert report_input_collision(report, protected) == profile

    # The SAME protection without an explicit --profile/extra entry.
    implicit = Ctx(source="ftp://example.test", settings=load(),
                   command="audit", report_path=report, extra={})
    assert profile in report_protected_inputs(implicit)
    assert report_input_collision(report, report_protected_inputs(
        implicit)) == profile

    before = profile.read_bytes()
    with pytest.raises(WptError, match="input of this run"):
        write_report_files(report, "# nope", "{}",
                           protected_paths=protected)
    assert profile.read_bytes() == before
    assert not report.exists()


def test_R14_selected_snapshot_manifest_is_a_protected_report_input(tmp_path):
    """R14-P2: ``restore --report <snapshot>/manifest.md`` replaced the
    rollback manifest.  The selected snapshot root/manifest are now in the
    ONE protected set, so neither the manifest nor its twin can move."""
    from wpt.cli import Ctx
    from wpt.report import (report_input_collision, report_protected_inputs,
                            write_report_files)
    from wpt.settings import load
    from wpt.types import WptError

    snapshot = tmp_path / "backup" / "site" / "20260101-000000"
    snapshot.mkdir(parents=True)
    manifest = snapshot / "manifest.json"
    manifest.write_text('{"format": "wpt-backup-manifest"}\n', encoding="utf-8")
    original = manifest.read_bytes()
    ctx = Ctx(source="ftp://example.test", settings=load(),
              command="restore", report_path=snapshot / "manifest.md",
              extra={"snapshot_dir": str(snapshot)})
    protected = report_protected_inputs(ctx)
    assert snapshot in protected
    assert manifest in protected
    assert report_input_collision(snapshot / "manifest.md", protected) \
        == manifest
    assert report_input_collision(manifest, protected) == manifest

    for face in (snapshot / "manifest.md", manifest):
        with pytest.raises(WptError, match="input of this run"):
            write_report_files(face, "# replaced", "{}",
                               protected_paths=protected)
    assert manifest.read_bytes() == original
    assert not (snapshot / "manifest.md").exists()


@pytest.mark.parametrize("point", ["temp", "backup", "publish",
                                  "after_backup", "after_publish"])
def test_R14_report_pair_is_atomic_against_a_stop_at_every_move(
        tmp_path, monkeypatch, point):
    """R14-P2: a ``StopRequested`` injected at temp creation, at the
    old-face backup move or at the final publish used to leave a ``.tmp``
    or a mixed pair/.bak.  The journal is recorded BEFORE each move and
    the rollback restores the old pair on every point."""
    import wpt.report as report_mod
    from wpt.types import StopRequested

    report = tmp_path / "r.md"
    twin = report.with_suffix(".json")
    report.write_text("OLD MD", encoding="utf-8")
    twin.write_text("OLD TWIN", encoding="utf-8")
    real_replace = report_mod.os.replace
    real_fsync = report_mod.os.fsync

    def _replace(src, dst):
        src_name = Path(src).name
        dst_name = Path(dst).name
        if point == "backup" and dst_name.endswith(".bak"):
            raise StopRequested("stop moving the old face")
        if point == "publish" and str(dst) == str(report) \
                and src_name.endswith(".tmp"):
            raise StopRequested("stop publishing the markdown")
        if point == "after_backup" and dst_name.endswith(".bak"):
            real_replace(src, dst)  # the move REALLY completed...
            raise StopRequested("stop after moving the old face")
        if point == "after_publish" and str(dst) == str(report) \
                and src_name.endswith(".tmp"):
            real_replace(src, dst)  # ... and so did the publish
            raise StopRequested("stop after publishing the markdown")
        return real_replace(src, dst)

    def _fsync(fd):
        if point == "temp":
            raise StopRequested("stop after temp creation")
        return real_fsync(fd)

    monkeypatch.setattr(report_mod.os, "replace", _replace)
    monkeypatch.setattr(report_mod.os, "fsync", _fsync)
    with pytest.raises(StopRequested):
        report_mod.write_report_files(report, "NEW MD", '{"new": true}')
    monkeypatch.undo()
    assert report.read_text(encoding="utf-8") == "OLD MD"
    assert twin.read_text(encoding="utf-8") == "OLD TWIN"
    residues = [p.name for p in tmp_path.iterdir()
                if p.name.endswith((".tmp", ".bak"))]
    assert residues == [], residues


def test_R22_a_stop_at_the_backup_close_leaves_no_empty_bak(
        tmp_path, monkeypatch):
    """R22-P2: a stop landing at the backup temp's ``close()`` happened
    BEFORE the journal recorded it and before any old bytes moved into it;
    rollback therefore kept a 0-byte ``.bak``.  The never-populated backup
    is removed by its creator and the old pair stays intact."""
    import wpt.report as report_mod
    from wpt.types import StopRequested

    report = tmp_path / "r.md"
    twin = report.with_suffix(".json")
    report.write_text("OLD MD", encoding="utf-8")
    twin.write_text("OLD TWIN", encoding="utf-8")
    real = report_mod._stage_report_temp
    state = {"stopped": False}

    class _Boom:
        def __init__(self, handle):
            self._handle = handle
            self.name = handle.name

        def close(self):
            self._handle.close()
            if not state["stopped"]:
                state["stopped"] = True
                raise StopRequested("stop at the backup close")

    def _named(target, suffix, staged, **kwargs):
        temp, handle = real(target, suffix, staged, **kwargs)
        if suffix == ".bak":
            return temp, _Boom(handle)
        return temp, handle

    monkeypatch.setattr(report_mod, "_stage_report_temp", _named)
    with pytest.raises(StopRequested, match="backup close"):
        report_mod.write_report_files(report, "NEW MD", '{"new": true}')

    assert state["stopped"] is True
    assert report.read_text(encoding="utf-8") == "OLD MD"
    assert twin.read_text(encoding="utf-8") == "OLD TWIN"
    residues = [p.name for p in tmp_path.iterdir()
                if p.name.endswith((".tmp", ".bak", ".part"))]
    assert residues == [], residues


@pytest.mark.parametrize("module_name, writer_name, needs_report", [
    ("wpt.backup", "_write_failure", False),
    ("wpt.walk", "_write_failure", False),
    ("wpt.restore", "_fail", False),
    ("wpt.serve", "_write_failure", False),
    ("wpt.proxy", "_write_failure", False),
    ("wpt.doctor", "_write_failure", True),
    ("wpt.actions.clean_db", "_fail_offline", False),
])
def test_R14_failure_writers_contain_a_second_stop(
        tmp_path, monkeypatch, module_name, writer_name, needs_report):
    """A SIGTERM landing during the failure-report write must be one
    warning, never a replacement of the run's PRIMARY reason."""
    import importlib

    from wpt.actions import registry as registry_mod
    from wpt.cli import Ctx
    from wpt.settings import load
    from wpt.types import StopRequested

    module = importlib.import_module(module_name)
    writer = getattr(module, writer_name)

    def _stop(*_args, **_kwargs):
        raise StopRequested("second stop")

    monkeypatch.setattr(registry_mod, "write_failure_report", _stop)
    monkeypatch.setattr(registry_mod, "write_report", _stop)
    ctx = Ctx(source="ftp://example.test", settings=load(),
              command="audit",
              report_path=(tmp_path / "r.md") if needs_report else None,
              extra={})
    if writer_name == "_fail":
        rc = writer(ctx, "PRIMARY reason")
    elif writer_name == "_fail_offline":
        rc = writer(ctx, "PRIMARY reason")
    elif needs_report:
        writer(ctx, RuntimeError("PRIMARY reason"))
        rc = 1
    else:
        rc = writer(ctx, "PRIMARY reason")
    assert rc is None or rc == 1


def test_R16_a_recorded_manifestless_snapshot_root_is_a_subtree(tmp_path):
    """R16-P1: recorded roots are subtrees even when the directory has no
    manifest.json (a selected corrupt root, or one whose marker was moved).
    The marker heuristic alone left its payloads writable by --report."""
    from wpt.cli import Ctx
    from wpt.report import (record_snapshot_root, report_input_collision,
                            report_protected_inputs,
                            report_protected_subtrees)
    from wpt.report import write_report_files
    from wpt.settings import load
    from wpt.types import WptError

    root = tmp_path / "backup" / "site" / "files-20260101T000000Z-abcdef"
    payload = root / "files" / "wp-content" / "a.txt"
    payload.parent.mkdir(parents=True)
    payload.write_bytes(b"ORIGINAL")
    ctx = Ctx(source="ftp://example.test", settings=load(), command="files",
              extra={})
    record_snapshot_root(ctx, root)
    protected = report_protected_inputs(ctx)
    subtrees = report_protected_subtrees(ctx)
    assert root in protected
    assert report_input_collision(payload, protected,
                                  subtrees=subtrees) == root
    with pytest.raises(WptError, match="input of this run"):
        write_report_files(payload, "# replaced", "{}",
                           protected_paths=protected,
                           protected_subtrees=subtrees)
    assert payload.read_bytes() == b"ORIGINAL"


def test_R19_a_stop_in_cleanup_unlink_is_re_raised_after_all_removals(
        tmp_path, monkeypatch):
    """R19-P2: ``_unlink_quietly`` caught BaseException, so a StopRequested
    raised inside the post-publish backup unlink vanished while the pair
    was published (a SIGTERM after the receipt was lost).  Every removal
    still runs, then the first stop is re-raised."""
    import wpt.report as report_mod
    from wpt.types import StopRequested

    report = tmp_path / "r.md"
    report.write_text("OLD", encoding="utf-8")
    report.with_suffix(".json").write_text("OLDJ", encoding="utf-8")
    real_unlink = Path.unlink
    state = {"stopped": False, "unlinks": 0}

    def _unlink(self, *args, **kwargs):
        name = self.name
        if name.endswith(".bak") and not state["stopped"]:
            state["stopped"] = True
            raise StopRequested("SIGTERM during report cleanup")
        state["unlinks"] += 1
        return real_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", _unlink)
    with pytest.raises(StopRequested, match="during report cleanup"):
        report_mod.write_report_files(report, "NEW", '{"new": true}')

    # The stop did not suppress the remaining cleanup: the published pair
    # is there and no temp/back residue survives.
    assert report.read_text(encoding="utf-8") == "NEW"
    assert report.with_suffix(".json").read_text(encoding="utf-8") \
        == '{"new": true}'
    assert not [p for p in tmp_path.iterdir()
                if p.name.endswith((".tmp", ".bak"))]


def test_R15_a_second_stop_in_report_rollback_keeps_the_old_bytes(
        tmp_path, monkeypatch, wpt_records):
    """R15-P2: after a failed publish the journal's restore ``os.replace``
    could raise a second ``StopRequested``; the unconditional backup unlink
    then lost the previous report.  The .bak is kept (a residue is better
    than data loss) and named."""
    import wpt.report as report_mod
    from wpt.types import StopRequested

    report = tmp_path / "r.md"
    twin = report.with_suffix(".json")
    report.write_text("OLD MD", encoding="utf-8")
    twin.write_text("OLD TWIN", encoding="utf-8")
    real_replace = report_mod.os.replace
    state = {"primary": False}

    def _replace(src, dst):
        if str(dst) == str(twin) and Path(src).name.endswith(".tmp"):
            state["primary"] = True
            raise StopRequested("stop publishing the JSON face")
        if state["primary"] and str(dst) == str(twin) \
                and Path(src).name.endswith(".bak"):
            raise StopRequested("second stop restoring the old face")
        return real_replace(src, dst)

    monkeypatch.setattr(report_mod.os, "replace", _replace)
    with pytest.raises(StopRequested):
        report_mod.write_report_files(report, "NEW MD", '{"new": true}')

    # The markdown was never touched; the old JSON bytes survive in a
    # backup rather than being unlinked by the failed rollback.
    assert report.read_text(encoding="utf-8") == "OLD MD"
    backups = [path for path in tmp_path.iterdir()
               if path.name.endswith(".bak")]
    assert len(backups) == 1
    assert backups[0].read_text(encoding="utf-8") == "OLD TWIN"
    assert not twin.exists()
    assert any("kept the previous bytes" in record.getMessage()
               for record in wpt_records)


def test_R14_a_managed_snapshot_name_is_resolved_in_the_protected_set(tmp_path):
    """The pre-dispatch refusal builder carries only ``--snapshot NAME``:
    the protected-set owner resolves it under the run's backup dir/site
    label so an early failure's ``--report .../manifest.md`` is refused."""
    from wpt.cli import Ctx
    from wpt.report import report_input_collision, report_protected_inputs
    from wpt.settings import load

    label = "example.com"
    snapshot = tmp_path / "backup" / label / "20260101-000000"
    snapshot.mkdir(parents=True)
    manifest = snapshot / "manifest.json"
    manifest.write_text("{}\n", encoding="utf-8")
    ctx = Ctx(source="ftp://example.com", settings=load(), command="restore",
              backup_dir=tmp_path / "backup", wp_url="https://example.com",
              extra={"snapshot": snapshot.name})
    protected = report_protected_inputs(ctx)
    resolved = {Path(path).resolve() for path in protected if path is not None}
    assert manifest.resolve() in resolved
    assert report_input_collision(snapshot / "manifest.md", protected) \
        == manifest


def test_R24_report_temp_name_is_journaled_before_creation(
        tmp_path, monkeypatch):
    """R24-P2: ``NamedTemporaryFile`` returned a name that entered ``staged``
    afterwards; a stop on that boundary left an unreferenced ``.tmp``.  The
    candidate is registered before ``os.open``, so a stop before creation is
    still cleaned by the writer's finally."""
    import wpt.report as report_mod
    from wpt.types import StopRequested

    real_open = report_mod.os.open

    def _stopping_open(path, *args, **kwargs):
        if str(path).endswith(".tmp"):
            raise StopRequested("stop before temp creation")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(report_mod.os, "open", _stopping_open)
    report = tmp_path / "r.md"
    with pytest.raises(StopRequested):
        report_mod.write_report_files(report, "NEW")
    assert not report.exists()
    assert list(tmp_path.iterdir()) == []


def test_R25_report_parent_probe_stop_leaves_no_temp(tmp_path, monkeypatch):
    """R25-P2: ``report_parent_problem`` used ``NamedTemporaryFile`` and
    assigned its name afterwards; a stop on that boundary left a probe temp
    nothing owned."""
    import wpt.report as report_mod
    from wpt.types import StopRequested

    real_open = report_mod.os.open

    def _stopping_open(path, *args, **kwargs):
        fd = real_open(path, *args, **kwargs)
        if str(path).endswith(".tmp"):
            report_mod.os.close(fd)
            raise StopRequested("stop at probe creation")
        return fd

    monkeypatch.setattr(report_mod.os, "open", _stopping_open)
    with pytest.raises(StopRequested):
        report_mod.report_parent_problem(tmp_path / "out.md")
    assert list(tmp_path.iterdir()) == []


def test_R25_report_backup_stop_leaves_no_empty_bak(tmp_path, monkeypatch):
    """R25-P2: the ``.bak`` was created before the journal named it; a stop
    on that boundary left a 0-byte backup the rollback never saw.  The name
    is journaled first, and rollback removes a reserved-but-unpopulated
    backup."""
    import wpt.report as report_mod
    from wpt.types import StopRequested

    old = tmp_path / "out.md"
    old.write_text("OLD", encoding="utf-8")
    real_open = report_mod.os.open

    def _stopping_open(path, *args, **kwargs):
        fd = real_open(path, *args, **kwargs)
        if str(path).endswith(".bak"):
            report_mod.os.close(fd)
            raise StopRequested("stop at backup creation")
        return fd

    monkeypatch.setattr(report_mod.os, "open", _stopping_open)
    with pytest.raises(StopRequested):
        report_mod.write_report_files(tmp_path / "out.md", "NEW")
    assert old.read_text(encoding="utf-8") == "OLD"
    assert list(tmp_path.iterdir()) == [old]


def test_R25_symlinked_report_faces_inside_a_protected_subtree_are_refused(
        tmp_path):
    """R25-P2: two report faces that are BOTH symlinks to outside files
    resolve outside the protected snapshot, so the resolve-only check let
    the writer replace the links and put the pair INSIDE the snapshot."""
    import wpt.report as report_mod

    snapshot = tmp_path / "snap"
    snapshot.mkdir()
    (snapshot / "manifest.json").write_text("{}", encoding="utf-8")
    outside_md = tmp_path / "outside.md"
    outside_json = tmp_path / "outside.json"
    outside_md.write_text("MD", encoding="utf-8")
    outside_json.write_text("{}", encoding="utf-8")
    (snapshot / "out.md").symlink_to(outside_md)
    (snapshot / "out.json").symlink_to(outside_json)

    collision = report_mod.report_input_collision(
        snapshot / "out.md", [snapshot], subtrees=[snapshot])
    assert collision == snapshot
    # The writer's own gate refuses too, before any face is replaced.
    with pytest.raises(report_mod.WptError, match="input of this run"):
        report_mod.write_report_files(
            snapshot / "out.md", "NEW", "{}", protected_paths=[snapshot],
            protected_subtrees=[snapshot])
    assert (snapshot / "out.md").is_symlink()
    assert outside_md.read_text(encoding="utf-8") == "MD"
