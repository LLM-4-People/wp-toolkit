"""End-to-end LOCAL-mode contract tests — the whole offline surface of the
REAL CLI (``wpt.cli.main``) pinned against drift, one file, no internals.

One realistic corpus-shaped fixture (built per test by ``_fixture``,
everything under tmp_path — no network, no PHP, no sleeps, deterministic):

* the zip mirrors a host-export shape: every entry nested under a
  SINGLE top-level site dir, INCLUDING the root dir entry itself
  ("example.test/") — the shape that exercises ZipSource's root
  auto-detection — carrying wp-config.php (no DISALLOW_FILE_EDIT),
  wp-config-sample.php, readme.html, license.txt, error_log,
  .htaccess.bk, a stray .sql under wp-content/, an ACTIVE plugin dir +
  an INACTIVE one, TWO cache plugins from one duplicate group
  (wp-super-cache + litespeed-cache), a migration leftover dir
  (wp-content/ai1wm-backups/ with a .wpress export), a stale uploads
  subdir (wp-content/uploads/wpcf7_uploads/) and a year/month uploads
  tree with an original + a -WxH variant.
* the .sql dump mirrors a phpMyAdmin-shaped dump that exercises the two
  silent-failure paths: header comment lines, SET statements the dump
  FSM tolerates, backticked CREATE TABLEs with column lists and
  constraint keys, ONE extended multi-row INSERT per table with an
  EXPLICIT column list, MySQL string escaping (``\\"`` inside '...'),
  ``SET NAMES utf8mb4`` — and wp_options storing SCALAR options PLAIN
  ('siteurl', 'https://example.test' — a common dump shape; only arrays
  are PHP-serialized), autoload values mixing yes/on/auto/no, wp_posts
  with 3 published posts + 2 revisions + 1 auto-draft (db.revisions
  counts 3), and a ghost wp_nf3_forms table (CREATE + rows) that no
  active plugin owns (ninja-forms is absent from active_plugins).

Every test drives ``main([...])`` with real argv and asserts only on
artifacts: report files, stdout via capsys, stderr, exit codes. The
updates command needs no WpOrgApi fake: local mode gathers no probe,
so the updates checks degrade before any wp.org request is attempted
(pinned by tests/audit/test_updates.py::test_core_probe_none_silent).

Test -> behavior map:
  test_full_local_audit_end_to_end .......... ``audit --report``: rc 0,
        .md written, .json twin parses, the expected findings
        set ("t."-prefixed throwaways other suites register into the
        shared process filtered out), db.revisions count 3,
        db.ghost_tables naming wp_nf3_forms, webroot.junk covering the
        *.sql and .htaccess.bk patterns, plugins.duplicate naming the
        cache pair active, webroot.migration for ai1wm,
        webroot.stale for wpcf7_uploads, plugins.inactive, site label
        local:example.test.zip, and NO finding text anywhere carrying
        the "example.test/" root prefix (the auto-detect pinned
        end-to-end through the CLI)
  test_updates_command_is_audit_updates_only . ``updates`` over the
        same fixture: rc 0, the report renders, and every JSON finding
        category starts with "updates." — the local degrade means
        exactly [] (the command IS the audit restricted to updates;
        no non-updates finding may leak in)
  test_mutating_commands_dry_run_then_apply_refused
        ................................. ``clean-files`` dry run: rc
        0, the plan printed with every fixture target, the zip
        byte-identical afterwards; ``clean-files --apply --yes``: rc 1
        with the local audit-only refusal on stderr, zip still
        untouched
  test_verify_backup_walk_refuse_local ...... verify / backup / walk
        each refuse local mode: rc 1 (offline mode has no live site)
  test_restore_lists_local_snapshots ........ ``restore`` list mode:
        rc 0 with the "No snapshots for local:example.test.zip." line;
        after a REAL files-only snapshot (wpt.backup.create_snapshot
        over a ZipSource of the fixture — no bridge, no tables) the
        snapshot name is LISTED with action=backup
  test_audit_only_skip_flags ............... ``audit --only webroot
        --skip webroot.junk``: webroot.migration + webroot.stale
        present, webroot.junk absent — the --only/--skip plumbing
        end-to-end
"""

import json
import zipfile

from wpt.cli import main

SITE_LABEL = "local:example.test.zip"
ZIP_NAME = "example.test.zip"
SQL_NAME = "site.sql"
SITE_DIR = "example.test"
JPG = b"\xff\xd8JPG-BYTES-0123456789"

ACTIVE_PLUGINS = [
    "active-plugin/active-plugin.php",
    "wp-super-cache/wp-cache.php",
    "litespeed-cache/litespeed-cache.php",
]

_WEBROOT_FILES = [
    ("wp-config.php", b"<?php // no DISALLOW_FILE_EDIT\n"),
    ("wp-config-sample.php", b"<?php // sample config\n"),
    ("readme.html", b"<h1>WordPress</h1>"),
    ("license.txt", b"WordPress is free software\n"),
    ("error_log", b"[03-Sep-2026 06:26:00] PHP Notice: something\n"),
    (".htaccess.bk", b"# old rules\n"),
    ("wp-content/stray.sql", b"DROP TABLE IF EXISTS leftover;\n"),
    ("wp-content/plugins/active-plugin/active-plugin.php",
     b"<?php /* active */"),
    ("wp-content/plugins/inactive-plugin/index.php",
     b"<?php /* inactive */"),
    ("wp-content/plugins/wp-super-cache/wp-cache.php",
     b"<?php /* wp-super-cache */"),
    ("wp-content/plugins/litespeed-cache/litespeed-cache.php",
     b"<?php /* litespeed-cache */"),
    ("wp-content/ai1wm-backups/export-20260101-000000.wpress",
     b"AI1WM-BACKUP-BYTES"),
    ("wp-content/uploads/wpcf7_uploads/file.txt", b"uploaded junk\n"),
    ("wp-content/uploads/2023/10/pic.jpg", JPG),
    ("wp-content/uploads/2023/10/pic-300x100.jpg", b"\xff\xd8THUMB-BYTES"),
]

_DUMP_HEADER = b"""-- phpMyAdmin SQL Dump
-- version 5.2.3
-- https://www.phpmyadmin.net/
--
-- Host: localhost:3306
-- Generation Time: Jan 01, 2026 at 00:00 AM
-- Server version: 10.11.0-MariaDB
-- PHP Version: 8.3.0

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `example_db`
--

"""

_WP_OPTIONS = [
    (1, "siteurl", "https://example.test", "yes"),
    (2, "home", "https://example.test", "yes"),
    (3, "template", "twentytwentyfour", "on"),
    (4, "stylesheet", "twentytwentyfour", "on"),
    (5, "blog_public", "1", "yes"),
    (6, "active_plugins", None, "yes"),
    (7, "stale_widget_option", "left by a removed plugin", "auto"),
    (8, "small_option", "not autoloaded", "no"),
]

_WP_POSTS = [
    (1, "Hello world", "publish", "post"),
    (2, "Second post", "publish", "post"),
    (3, "Third post", "publish", "post"),
    (100, "Hello world", "inherit", "revision"),
    (101, "Second post", "inherit", "revision"),
    (102, "", "auto-draft", "post"),
]

_WP_NF3_FORMS = [
    (1, "Contact form", "2023-01-15 09:30:00"),
    (2, "Newsletter signup", "2023-02-20 14:00:00"),
]

FULL_AUDIT_FINDINGS = [
    ("db.ghost_tables", "ghost-tables"),
    ("db.revisions", "revisions"),
    # local mode has no live walk, so the media check measures the DATABASE
    # half of the union keep-set and labels the number DEGRADED (a page
    # renders only a fraction of its attachments, so a walk-only keep-set
    # deletes what it never sees)
    ("media.unreferenced", "unreferenced-media"),
    ("plugins.duplicate", "litespeed-cache/wp-super-cache/w3-total-cache"),
    ("plugins.inactive", "inactive-plugins"),
    ("webroot.junk", "*.sql"),
    ("webroot.junk", ".htaccess.bk"),
    ("webroot.junk", "error_log"),
    ("webroot.junk", "license.txt"),
    ("webroot.junk", "readme.html"),
    ("webroot.junk", "wp-config-sample.php"),
    ("webroot.migration", "ai1wm*"),
    ("webroot.stale", "wp-content/uploads/wpcf7_uploads"),
]


def _ser_str(value: str) -> str:
    return 's:%d:"%s";' % (len(value.encode("utf-8")), value)


def _ser_list(values: list[str]) -> str:
    body = "".join("i:%d;%s" % (i, _ser_str(v)) for i, v in enumerate(values))
    return "a:%d:{%s}" % (len(values), body)


def _cell_sql(value) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, int):
        return str(value)
    escaped = (value.replace("\\", "\\\\").replace('"', '\\"')
               .replace("'", "\\'"))
    return "'" + escaped + "'"


def _create(table: str, columns: list[tuple[str, str]],
            keys: tuple[str, ...]) -> bytes:
    cols = ",\n".join("  `%s` %s" % (name, kind) for name, kind in columns)
    tail = "".join(",\n  %s" % key for key in keys)
    return ("CREATE TABLE `%s` (\n%s%s\n) ENGINE=InnoDB "
            "DEFAULT CHARSET=utf8mb4;\n" % (table, cols, tail)).encode()


def _insert(table: str, columns: list[str], rows: list) -> bytes:
    column_list = ", ".join("`%s`" % c for c in columns)
    tuples = ",\n".join(
        "(" + ", ".join(_cell_sql(cell) for cell in row) + ")" for row in rows
    )
    return ("INSERT INTO `%s` (%s) VALUES\n%s;\n"
            % (table, column_list, tuples)).encode()


def _table_section(table: str, create: bytes, insert: bytes) -> bytes:
    structure = ("--\n-- Table structure for table `%s`\n--\n\n"
                 % table).encode()
    data = ("--\n-- Dumping data for table `%s`\n--\n\n" % table).encode()
    return (b"-- --------------------------------------------------------\n\n"
            + structure + create + b"\n" + data + insert + b"\n")


def _dump_bytes() -> bytes:
    options = [(i, name, _ser_list(ACTIVE_PLUGINS) if value is None else value,
                autoload)
               for i, name, value, autoload in _WP_OPTIONS]
    return b"".join([
        _DUMP_HEADER,
        _table_section(
            "wp_options",
            _create("wp_options", [
                ("option_id", "bigint(20) UNSIGNED NOT NULL"),
                ("option_name", "varchar(191) NOT NULL DEFAULT ''"),
                ("option_value", "longtext NOT NULL"),
                ("autoload", "varchar(20) NOT NULL DEFAULT 'yes'"),
            ], keys=("PRIMARY KEY (`option_id`)",
                     "UNIQUE KEY `option_name` (`option_name`)")),
            _insert("wp_options",
                    ["option_id", "option_name", "option_value", "autoload"],
                    options)),
        _table_section(
            "wp_posts",
            _create("wp_posts", [
                ("ID", "bigint(20) UNSIGNED NOT NULL"),
                ("post_title", "text NOT NULL"),
                ("post_status", "varchar(20) NOT NULL DEFAULT 'publish'"),
                ("post_type", "varchar(20) NOT NULL DEFAULT 'post'"),
                ("post_content", "longtext NOT NULL"),
            ], keys=("PRIMARY KEY (`ID`)")),
            _insert("wp_posts",
                    ["ID", "post_title", "post_status", "post_type", "post_content"],
                    [row + ("",) for row in _WP_POSTS])),
        _table_section(
            "wp_postmeta",
            _create("wp_postmeta", [
                ("meta_id", "bigint(20) UNSIGNED NOT NULL"),
                ("post_id", "bigint(20) UNSIGNED NOT NULL"),
                ("meta_key", "varchar(255) DEFAULT NULL"),
                ("meta_value", "longtext"),
            ], keys=("PRIMARY KEY (`meta_id`)")),
            _insert("wp_postmeta",
                    ["meta_id", "post_id", "meta_key", "meta_value"],
                    [(1, 100, "_wp_attached_file", "2023/10/pic.jpg")])),
        _table_section(
            "wp_nf3_forms",
            _create("wp_nf3_forms", [
                ("id", "bigint(20) UNSIGNED NOT NULL"),
                ("title", "varchar(200) NOT NULL DEFAULT ''"),
                ("created_at", "datetime NOT NULL"),
            ], keys=("PRIMARY KEY (`id`)")),
            _insert("wp_nf3_forms", ["id", "title", "created_at"],
                    _WP_NF3_FORMS)),
    ])


def _fixture(tmp_path):
    zpath = tmp_path / ZIP_NAME
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr(SITE_DIR + "/", "")
        for name, blob in _WEBROOT_FILES:
            zf.writestr(SITE_DIR + "/" + name, blob)
    spath = tmp_path / SQL_NAME
    spath.write_bytes(_dump_bytes())
    return zpath, spath


def _argv(zip_path, sql_path, *extra):
    return ["--source", "local", "--zip", str(zip_path),
            "--sql", str(sql_path), *extra]


def _zip_contents(path):
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        return names, {name: zf.read(name) for name in names}


def _production_pairs(pairs):
    production = [p for p in pairs if not p[0].startswith("t.")]
    foreign = [p for p in pairs if p[0].startswith("t.")]
    assert all(cat.startswith("t.") for cat, _name in foreign)
    return production, foreign


def _finding(payload, category, name):
    for finding in payload["findings"]:
        if (finding["category"], finding["name"]) == (category, name):
            return finding
    raise AssertionError(f"no {category}/{name} finding in report")


def _read_report(report_path):
    markdown = report_path.read_text(encoding="utf-8")
    payload = json.loads(
        report_path.with_suffix(".json").read_text(encoding="utf-8")
    )
    return markdown, payload


def test_full_local_audit_end_to_end(tmp_path):
    zpath, spath = _fixture(tmp_path)
    report = tmp_path / "audit-report.md"
    rc = main(_argv(zpath, spath, "--report", str(report), "audit"))
    assert rc == 0
    assert report.exists()
    markdown, payload = _read_report(report)
    production, _foreign = _production_pairs(
        [(f["category"], f["name"]) for f in payload["findings"]]
    )
    assert production == FULL_AUDIT_FINDINGS
    assert payload["site"] == SITE_LABEL
    assert payload["source_summary"] == f"zip:{ZIP_NAME} + {SQL_NAME}"
    assert "# wpt audit — " + SITE_LABEL in markdown
    assert "## webroot.junk" in markdown
    assert "## db.revisions" in markdown
    assert "example.test/" not in json.dumps(payload)
    assert "example.test/" not in markdown
    assert _finding(payload, "db.revisions", "revisions")["count"] == 3
    ghost = _finding(payload, "db.ghost_tables", "ghost-tables")
    assert "wp_nf3_forms" in ghost["detail"]
    assert ghost["count"] == 1
    assert _finding(payload, "webroot.junk", "*.sql")["detail"] == \
        "wp-content/stray.sql"
    assert _finding(payload, "webroot.junk", "*.sql")["risk"] == "high"
    assert _finding(payload, "webroot.junk", ".htaccess.bk")["detail"] == \
        ".htaccess.bk"
    assert _finding(payload, "webroot.junk", ".htaccess.bk")["risk"] == "high"
    duplicate = _finding(payload, "plugins.duplicate",
                          "litespeed-cache/wp-super-cache/w3-total-cache")
    assert duplicate["detail"].startswith(
        "litespeed-cache (active), wp-super-cache (active)"
    )
    # [D1] the group claims no reclaimable bytes, but the figure is not
    # lost: the detail states what a named keeper would unlock.
    assert duplicate["bytes"] == 0
    assert "across the present members becomes reclaimable once a keeper " \
           "is named" in duplicate["detail"]
    assert duplicate["count"] == 2
    assert _finding(payload, "plugins.inactive",
                    "inactive-plugins")["count"] == 1
    assert _finding(payload, "webroot.migration", "ai1wm*")["detail"] == \
        "wp-content/ai1wm-backups"
    assert _finding(payload, "webroot.stale",
                    "wp-content/uploads/wpcf7_uploads")["count"] == 1


def test_updates_command_is_audit_updates_only(tmp_path):
    zpath, spath = _fixture(tmp_path)
    report = tmp_path / "updates-report.md"
    rc = main(_argv(zpath, spath, "--report", str(report), "updates"))
    assert rc == 0
    markdown, payload = _read_report(report)
    assert "# wpt audit — " + SITE_LABEL in markdown
    assert "## db.revisions" not in markdown
    assert "webroot.junk" not in markdown
    assert payload["findings"] == []
    assert all(f["category"].startswith("updates.")
               for f in payload["findings"])


def test_mutating_commands_dry_run_then_rehearsed(tmp_path, capsys):
    zpath, spath = _fixture(tmp_path)
    before = _zip_contents(zpath)
    rc = main(_argv(zpath, spath, "clean-files"))
    assert rc == 0
    out = capsys.readouterr().out
    assert "# wpt clean-files — " + SITE_LABEL in out
    assert "## Plan" in out
    for target in ("wp-content/stray.sql", ".htaccess.bk", "error_log",
                   "license.txt", "readme.html", "wp-config-sample.php",
                   "wp-content/ai1wm-backups",
                   "wp-content/uploads/wpcf7_uploads"):
        assert target in out
    assert _zip_contents(zpath) == before
    # --apply REHEARSES locally: rc 0, original untouched, a materialized
    # twin beside it carrying the cleanup
    rc = main(_argv(zpath, spath, "--apply", "--yes", "clean-files"))
    assert rc == 0
    assert _zip_contents(zpath) == before  # the original IS the rollback
    rehearsed = sorted(tmp_path.glob("example.test-rehearsed-*.zip"))
    assert len(rehearsed) == 1
    with zipfile.ZipFile(rehearsed[0]) as zf:
        names = zf.namelist()
    assert "example.test/readme.html" not in names
    assert "example.test/wp-content/stray.sql" not in names
    assert "example.test/wp-config.php" in names
    assert "example.test/wp-config-sample.php" not in names


def test_verify_backup_walk_refuse_local(tmp_path):
    zpath, spath = _fixture(tmp_path)
    assert main(_argv(zpath, spath, "verify")) == 1
    assert main(_argv(zpath, spath, "backup")) == 1
    assert main(_argv(zpath, spath, "walk")) == 1


def test_restore_lists_local_snapshots(tmp_path, capsys):
    zpath, spath = _fixture(tmp_path)
    backups = tmp_path / "wpt-backup"
    rc = main(_argv(zpath, spath, "--backup-dir", str(backups), "restore"))
    assert rc == 0
    out = capsys.readouterr().out
    assert "# wpt restore — " + SITE_LABEL in out
    assert "No snapshots for " + SITE_LABEL + "." in out

    from wpt.backup import create_snapshot
    from wpt.settings import load
    from wpt.sources.zip import ZipSource

    source = ZipSource(zpath)
    try:
        meta = create_snapshot(
            source=source,
            bridge=None,
            site_label=SITE_LABEL,
            targets=["readme.html", "wp-content/uploads/2023/10/pic.jpg"],
            tables=[],
            backup_dir=backups,
            settings=load().backup,
            action="backup",
            site_raw=SITE_LABEL,
            webroot="",
        )
    finally:
        source.close()
    rc = main(_argv(zpath, spath, "--backup-dir", str(backups), "restore"))
    assert rc == 0
    out = capsys.readouterr().out
    assert "No snapshots" not in out
    assert meta.path.name + "  action=backup" in out


def test_audit_only_skip_flags(tmp_path):
    zpath, spath = _fixture(tmp_path)
    report = tmp_path / "flags-report.md"
    rc = main(_argv(zpath, spath, "--report", str(report), "audit",
                    "--only", "webroot", "--skip", "webroot.junk"))
    assert rc == 0
    markdown, payload = _read_report(report)
    production, _foreign = _production_pairs(
        [(f["category"], f["name"]) for f in payload["findings"]]
    )
    assert production == [
        ("webroot.migration", "ai1wm*"),
        ("webroot.stale", "wp-content/uploads/wpcf7_uploads"),
    ]
    assert "## webroot.migration" in markdown
    assert "## webroot.stale" in markdown
    assert "webroot.junk" not in markdown
