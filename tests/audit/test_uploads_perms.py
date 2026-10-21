"""security.uploads_perms — world-writable uploads (entries-based).

The check reads only ``data.entries``: a measured POSIX mode with the
other-write bit is a finding; ``None`` is unknown and stays silent.  No
probe, no network, no settings tunable.
"""

from wpt.audit.data import AuditData
from wpt.audit.registry import all_checks
from wpt.audit.security import check_security_uploads_perms
from wpt.settings import load
from wpt.types import Entry

DEFAULTS = load()


def data(entries):
    """A hand-built AuditData carrying only the walked tree."""
    return AuditData(
        mode="ftp",
        entries=list(entries),
        siteurl=None,
        home=None,
        template=None,
        blog_public=None,
        wp_version=None,
        mu_plugins=None,
        active_plugins=[],
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
    )


def E(path, mode=None, is_dir=False):
    return Entry(path=path, is_dir=is_dir, size=0, mode=mode)


def test_registered_for_ftp_mode_only():
    records = {record.name: record for record in all_checks()}
    assert records["security.uploads_perms"].applies == ("ftp",)


def test_world_writable_file_is_one_medium_finding():
    findings = check_security_uploads_perms(
        data([
            E("wp-content/uploads", 0o755, is_dir=True),
            E("wp-content/uploads/2018/03/evil.php", 0o666),
        ]),
        DEFAULTS,
    )
    assert len(findings) == 1
    finding = findings[0]
    finding.validate()
    assert (finding.category, finding.name, finding.risk,
            finding.count) == (
        "security.uploads_perms", "uploads-perms", "medium", 1)
    assert "wp-content/uploads/2018/03/evil.php (0o666)" in finding.detail
    assert "chmod 755" in finding.fix and "644" in finding.fix


def test_world_writable_directory_is_reported():
    for entry in (
        E("wp-content/uploads", 0o777, is_dir=True),          # the root itself
        E("wp-content/uploads/2018", 0o777, is_dir=True),     # a child dir
    ):
        findings = check_security_uploads_perms(data([entry]), DEFAULTS)
        assert len(findings) == 1
        assert findings[0].count == 1
        assert f"{entry.path} (0o777)" in findings[0].detail


def test_regular_modes_are_silent():
    assert check_security_uploads_perms(
        data([
            E("wp-content/uploads", 0o755, is_dir=True),
            E("wp-content/uploads/2018", 0o755, is_dir=True),
            E("wp-content/uploads/2018/03/a.jpg", 0o644),
        ]),
        DEFAULTS,
    ) == []


def test_unknown_modes_are_not_a_finding():
    assert check_security_uploads_perms(
        data([
            E("wp-content/uploads", None, is_dir=True),
            E("wp-content/uploads/2018", None, is_dir=True),
            E("wp-content/uploads/2018/03/a.jpg", None),
        ]),
        DEFAULTS,
    ) == []


def test_paths_outside_uploads_are_ignored():
    assert check_security_uploads_perms(
        data([
            E("wp-content/plugins/x.php", 0o666),
            E("wp-content/uploads-extra/x.php", 0o666),
            E("uploads/x.php", 0o666),
            # a FILE at the directory's name: not the uploads directory
            E("wp-content/uploads", 0o666),
        ]),
        DEFAULTS,
    ) == []


def test_detail_samples_five_paths_then_counts_the_rest():
    findings = check_security_uploads_perms(
        data([E(f"wp-content/uploads/f{i}.php", 0o666) for i in range(7)]),
        DEFAULTS,
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.count == 7
    for i in range(5):
        assert f"wp-content/uploads/f{i}.php (0o666)" in finding.detail
    assert "f5.php" not in finding.detail
    assert "(+2 more)" in finding.detail
