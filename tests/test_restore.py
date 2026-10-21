"""Tests for wpt/restore.py — REAL snapshots built via wpt.backup.create_snapshot
over FakeSource + a real Bridge (FakeSession scripted db_dump / db_restore_table
responses), then restored. Covers full/targeted/config/dry-run restores, the
absent-semantics delete, identical-skip, chunked bridge calls with the b64
marker passed through, fail-closed pre-pass ordering, list_snapshots
ordering, the run_restore --undo-last one-flag rollback (newest resolution,
mutual exclusion, targeting composition, dry-run) and the report's md+json
twin. Deterministic: no network, no sleeps; the snapshot clock
(wpt.backup._now) is pinned wherever ordering matters.
"""

import base64
import hashlib
import json
import logging
import re
from datetime import datetime, timedelta, timezone

import pytest

import wpt.backup as backup
import wpt.restore as restore
from tests.fakes import FakeResponse, FakeSession, FakeSource
from wpt.cli import Ctx
from wpt.settings import BackupSettings, BridgeSettings, load
from wpt.types import (BridgeError, SourceError,
                       StopRequested)
from wpt.wpbridge.client import Bridge

WEBROOT = "domains/example.com/public_html"
SITE = "https://example.com"
BLOB = b"\x00\xffbin"
BLOB_B64 = base64.b64encode(BLOB).decode()
CFG = b"<?php define('DB_NAME', 'db');"
POSTS_ROWS = [["1", "hello"], ["2", ["__wpt_b64__", BLOB_B64]]]


# ------------------------------------------------------------------ helpers


def table_lines(table, rows, create="CREATE TABLE `x` (id bigint)"):
    """Scripted db_dump NDJSON for one table: create, rows, done."""
    lines = [json.dumps({"table": table, "create": create})]
    for row in rows:
        lines.append(json.dumps({"table": table, "row": row}))
    lines.append(json.dumps({"table": table, "done": len(rows)}))
    return lines


def dump_response(lines):
    return FakeResponse(200, lines=lines)


def restore_response(table, inserted, swapped, old_left=False):
    return FakeResponse(200, text=json.dumps(
        {"ok": True, "table": table, "inserted": inserted,
         "swapped": swapped, "old_left": old_left}))


def make_bridge(script=()):
    """A real Bridge over a throwaway FakeSource + scripted FakeSession.

    ``script`` is a sequence of scripted items (or one bare FakeResponse).
    Returns (bridge, session); tests assert on session.posts (each entry is
    (url, kwargs) with the wire body under kwargs["json"]).
    """
    if isinstance(script, (FakeResponse, Exception)):
        script = [script]
    session = FakeSession(list(script))
    bridge = Bridge(FakeSource(), session, WEBROOT, BridgeSettings(), SITE)
    return bridge, session


def snap(source, bridge, label, targets, tables, backup_dir, action="clean-files"):
    return backup.create_snapshot(source, bridge, label, targets, tables,
                                  backup_dir, BackupSettings(), action,
                                  site_raw=label, webroot="")


def make_site():
    source = FakeSource()
    source.files["wp-config.php"] = CFG
    source.files["readme.html"] = b"readme"
    source.files["wp-content/uploads/2020/01/a.jpg"] = BLOB
    return source


def tamper_table_stream(meta, table, mutate_lines):
    """Rewrite db/<table>.ndjson through ``mutate_lines`` and re-sync the
    manifest's sha256/size — a snapshot that still passes verify_snapshot
    but is internally inconsistent (exactly what the pre-pass must catch
    before any bridge call)."""
    ndjson = meta.path / "db" / f"{table}.ndjson"
    data = ("\n".join(mutate_lines(
        ndjson.read_text(encoding="utf-8").splitlines())) + "\n").encode("utf-8")
    ndjson.write_bytes(data)
    manifest_path = meta.path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for entry in manifest["tables"]:
        if entry["name"] == table:
            entry["sha256"] = hashlib.sha256(data).hexdigest()
            entry["size"] = len(data)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


# ------------------------------------------------------------- full restore


def test_full_restore_roundtrip_recovers_files_and_absent_semantics(tmp_path):
    source = make_site()
    bridge, _ = make_bridge(dump_response(table_lines("wp_posts", POSTS_ROWS)))
    meta = snap(source, bridge, "example.com",
                ["wp-config.php", "readme.html",
                 "wp-content/uploads/2020/01/a.jpg", "missing.txt", "never.txt"],
                ["wp_posts"], tmp_path / "bck")
    # mutate the live site after the snapshot
    source.files["wp-content/uploads/2020/01/a.jpg"] = b"tampered"
    del source.files["readme.html"]
    source.files["missing.txt"] = b"appeared while the action ran"
    # wp-config.php left untouched -> the identical-skip case

    rbridge, rsession = make_bridge(restore_response("wp_posts", 2, True))
    report = restore.restore_snapshot(meta.path, source, rbridge,
                                      expected_site="example.com", expected_webroot="")

    assert report == restore.RestoreReport(
        files_restored=2,       # a.jpg (tampered) + readme.html (deleted live)
        files_absent_kept=1,    # never.txt: still absent
        files_deleted=1,        # missing.txt: appeared live, snapshot says absent
        tables_restored=["wp_posts"],
        rows_inserted=2,
    )
    # byte-exact recovery
    assert source.files["wp-content/uploads/2020/01/a.jpg"] == BLOB
    assert source.files["readme.html"] == b"readme"
    assert source.files["wp-config.php"] == CFG
    assert "missing.txt" not in source.files   # absent semantics: deleted
    assert "never.txt" not in source.files
    # one bridge call: full batch, truncate_first, b64 marker passed through
    assert len(rsession.posts) == 1
    params = rsession.posts[0][1]["json"]["params"]
    assert params["table"] == "wp_posts"
    assert params["rows"] == POSTS_ROWS
    assert params["truncate_first"] is True


# ---------------------------------------------------------- targeted restore


def test_only_files_restores_exactly_those_paths(tmp_path):
    source = make_site()
    bridge, _ = make_bridge(dump_response(table_lines("wp_posts", POSTS_ROWS)))
    meta = snap(source, bridge, "s",
                ["readme.html", "wp-content/uploads/2020/01/a.jpg"],
                ["wp_posts"], tmp_path / "bck")
    source.files["readme.html"] = b"changed"
    source.files["wp-content/uploads/2020/01/a.jpg"] = b"also changed"

    rbridge, rsession = make_bridge()  # empty script: any bridge call fails
    report = restore.restore_snapshot(meta.path, source, rbridge,
                                      only_files=["./readme.html"],
                                      expected_site="s", expected_webroot="")  # guard-normalized

    assert report == restore.RestoreReport(
        files_restored=1, files_absent_kept=0, files_deleted=0,
        tables_restored=[], rows_inserted=0,
    )
    assert source.files["readme.html"] == b"readme"
    assert source.files["wp-content/uploads/2020/01/a.jpg"] == b"also changed"
    assert rsession.posts == []  # targeted file restore touches no tables


def test_file_prefix_restores_subtree_only(tmp_path):
    source = make_site()
    bridge, _ = make_bridge()
    meta = snap(source, bridge, "s",
                ["readme.html", "wp-content/uploads/2020/01/a.jpg"],
                [], tmp_path / "bck")
    source.files["readme.html"] = b"changed"
    source.files["wp-content/uploads/2020/01/a.jpg"] = b"changed too"

    rbridge, _ = make_bridge()
    report = restore.restore_snapshot(meta.path, source, rbridge,
                                      file_prefix="wp-content/uploads/",
                                      expected_site="s", expected_webroot="")

    assert report.files_restored == 1
    assert source.files["wp-content/uploads/2020/01/a.jpg"] == BLOB
    assert source.files["readme.html"] == b"changed"  # outside the subtree


def test_only_tables_restores_table_and_leaves_files_alone(tmp_path):
    source = make_site()
    lines = (table_lines("wp_posts", POSTS_ROWS)
             + table_lines("wp_options", [["opt", "val"]], create="CREATE2"))
    bridge, _ = make_bridge(dump_response(lines))
    meta = snap(source, bridge, "s", ["readme.html"],
                ["wp_posts", "wp_options"], tmp_path / "bck")
    source.files["readme.html"] = b"changed"

    rbridge, rsession = make_bridge(restore_response("wp_options", 1, True))
    report = restore.restore_snapshot(meta.path, source, rbridge,
                                      only_tables=["wp_options"],
                                      expected_site="s", expected_webroot="")

    assert report == restore.RestoreReport(
        files_restored=0, files_absent_kept=0, files_deleted=0,
        tables_restored=["wp_options"], rows_inserted=1,
    )
    assert source.files["readme.html"] == b"changed"  # targeted: files untouched
    assert len(rsession.posts) == 1
    params = rsession.posts[0][1]["json"]["params"]
    assert params["table"] == "wp_options"
    assert params["rows"] == [["opt", "val"]]
    assert params["truncate_first"] is True


# ----------------------------------------------------------- config restore


def test_config_restore_passes_allow_config_and_logs_warning(tmp_path):
    source = make_site()
    bridge, _ = make_bridge()
    meta = snap(source, bridge, "s", ["wp-config.php"], [], tmp_path / "bck")
    source.files["wp-config.php"] = b"tampered config"

    records: list[logging.LogRecord] = []

    class ListHandler(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = ListHandler()
    parent = logging.getLogger("wpt")
    parent.addHandler(handler)
    try:
        rbridge, rsession = make_bridge()
        report = restore.restore_snapshot(meta.path, source, rbridge,
                                          only_files=["wp-config.php"],
                                          expected_site="s", expected_webroot="")
    finally:
        parent.removeHandler(handler)

    # the write succeeded at all => allow_config=True was passed
    # (FakeSource.write_bytes raises NotWritableError without it)
    assert source.files["wp-config.php"] == CFG
    assert report.files_restored == 1
    assert rsession.posts == []
    assert any(
        r.levelno == logging.WARNING
        and "guarded write to protected config file: wp-config.php" in r.getMessage()
        for r in records
    )


# ----------------------------------------------------------- identical skip


def test_identical_live_file_skipped_not_counted_not_written(tmp_path):
    source = make_site()
    bridge, _ = make_bridge()
    meta = snap(source, bridge, "s", ["readme.html"], [], tmp_path / "bck")
    # live file left exactly as snapshotted

    report = restore.restore_snapshot(meta.path, source, make_bridge()[0],
                                      expected_site="s", expected_webroot="")

    assert report.files_restored == 0
    assert report.files_absent_kept == 0 and report.files_deleted == 0
    mutating = [op for _, op, _ in source.ops if op in ("write", "delete")]
    assert mutating == []
    assert source.files["readme.html"] == b"readme"


# ----------------------------------------------------------------- dry run


def test_dry_run_reports_as_if_but_mutates_nothing(tmp_path):
    source = make_site()
    bridge, _ = make_bridge(dump_response(table_lines("wp_posts", POSTS_ROWS)))
    meta = snap(source, bridge, "s",
                ["wp-config.php", "readme.html",
                 "wp-content/uploads/2020/01/a.jpg", "missing.txt", "never.txt"],
                ["wp_posts"], tmp_path / "bck")
    source.files["wp-content/uploads/2020/01/a.jpg"] = b"tampered"
    del source.files["readme.html"]
    source.files["missing.txt"] = b"appeared"

    rbridge, rsession = make_bridge(restore_response("wp_posts", 2, True))
    report = restore.restore_snapshot(meta.path, source, rbridge, dry_run=True,
                                      expected_site="s", expected_webroot="")

    assert report == restore.RestoreReport(
        files_restored=2, files_absent_kept=1, files_deleted=1,
        tables_restored=["wp_posts"], rows_inserted=2,
    )
    # zero writes, zero deletes, zero bridge calls
    assert source.files["wp-content/uploads/2020/01/a.jpg"] == b"tampered"
    assert "readme.html" not in source.files
    assert source.files["missing.txt"] == b"appeared"
    assert source.files["wp-config.php"] == CFG
    assert rsession.posts == []
    assert len(rsession.script) == 1  # the scripted response was never consumed


# -------------------------------------------------------------- fail-closed


def test_failclosed_corrupt_snapshot_never_restores(tmp_path):
    source = make_site()
    bridge, _ = make_bridge(dump_response(table_lines("wp_posts", POSTS_ROWS)))
    meta = snap(source, bridge, "s", ["readme.html"], ["wp_posts"], tmp_path / "bck")
    source.files["readme.html"] = b"changed live"

    captured = meta.path / "files/readme.html"
    flipped = bytearray(captured.read_bytes())
    flipped[0] ^= 0xFF
    captured.write_bytes(bytes(flipped))

    rbridge, rsession = make_bridge(restore_response("wp_posts", 2, True))
    with pytest.raises(ValueError, match="verification"):
        restore.restore_snapshot(meta.path, source, rbridge,
                                 expected_site="s", expected_webroot="")
    assert rsession.posts == []
    assert source.files["readme.html"] == b"changed live"  # nothing restored

    captured.write_bytes(b"readme")  # repair the payload, corrupt the manifest
    (meta.path / "manifest.json").write_text("{ not json", encoding="utf-8")
    with pytest.raises(ValueError, match="verification"):
        restore.restore_snapshot(meta.path, source, rbridge,
                                 expected_site="s", expected_webroot="")
    (meta.path / "manifest.json").unlink()
    with pytest.raises(ValueError, match="verification"):
        restore.restore_snapshot(meta.path, source, rbridge,
                                 expected_site="s", expected_webroot="")


def test_failclosed_wrong_manifest_format_or_version(tmp_path):
    source = make_site()
    bridge, _ = make_bridge()
    meta = snap(source, bridge, "s", ["readme.html"], [], tmp_path / "bck")

    manifest_path = meta.path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    manifest["format"] = "not-wpt"  # hashes still verify; the format gate fires
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    with pytest.raises(ValueError, match="not a wpt backup manifest"):
        restore.restore_snapshot(meta.path, source, make_bridge()[0],
                                 expected_site="s", expected_webroot="")

    manifest["format"] = "wpt-backup-manifest"
    manifest["version"] = 2
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported manifest version"):
        restore.restore_snapshot(meta.path, source, make_bridge()[0],
                                 expected_site="s", expected_webroot="")


def test_failclosed_rowcount_mismatch_raises_before_any_bridge_call(tmp_path):
    source = make_site()
    bridge, _ = make_bridge(dump_response(table_lines("wp_posts", POSTS_ROWS)))
    meta = snap(source, bridge, "s", ["readme.html"], ["wp_posts"], tmp_path / "bck")
    source.files["readme.html"] = b"changed live"

    def drop_one_row(lines):
        for i, ln in enumerate(lines):
            if '"row"' in ln:
                return lines[:i] + lines[i + 1:]
        raise AssertionError("no row line found")

    tamper_table_stream(meta, "wp_posts", drop_one_row)

    rbridge, rsession = make_bridge(restore_response("wp_posts", 2, True))
    with pytest.raises(ValueError, match="row line"):
        restore.restore_snapshot(meta.path, source, rbridge,
                                 expected_site="s", expected_webroot="")
    assert rsession.posts == []  # no bridge call was ever made
    assert source.files["readme.html"] == b"changed live"  # no file mutation either


def test_failclosed_malformed_b64_cell_raises_before_any_bridge_call(tmp_path):
    bridge, _ = make_bridge(dump_response(table_lines("wp_posts", POSTS_ROWS)))
    meta = snap(None, bridge, "s", [], ["wp_posts"], tmp_path / "bck")

    def poison(lines):
        out = []
        for ln in lines:
            if '"row"' in ln:
                obj = json.loads(ln)
                obj["row"][1] = ["__wpt_b64__", "!!!not base64!!!"]
                ln = json.dumps(obj, separators=(",", ":"))
            out.append(ln)
        return out

    tamper_table_stream(meta, "wp_posts", poison)

    rbridge, rsession = make_bridge(restore_response("wp_posts", 2, True))
    with pytest.raises(ValueError, match="undecodable"):
        restore.restore_snapshot(meta.path, None, rbridge,
                                 expected_site="s", expected_webroot="")
    assert rsession.posts == []


def test_failclosed_unknown_or_unsafe_targeting_entries(tmp_path):
    source = make_site()
    bridge, _ = make_bridge(dump_response(table_lines("wp_posts", POSTS_ROWS)))
    meta = snap(source, bridge, "s", ["readme.html"], ["wp_posts"], tmp_path / "bck")

    rbridge, rsession = make_bridge()
    with pytest.raises(ValueError, match="only_files not in snapshot"):
        restore.restore_snapshot(meta.path, source, rbridge, only_files=["nope.txt"],
                                 expected_site="s", expected_webroot="")
    with pytest.raises(ValueError, match="only_tables not in snapshot"):
        restore.restore_snapshot(meta.path, source, rbridge, only_tables=["wp_nope"],
                                 expected_site="s", expected_webroot="")
    with pytest.raises(SourceError):  # routed through the source path guard
        restore.restore_snapshot(meta.path, source, rbridge, only_files=["../evil"],
                                 expected_site="s", expected_webroot="")
    assert rsession.posts == []
    assert source.files["readme.html"] == b"readme"  # nothing mutated


def test_failclosed_missing_capability(tmp_path):
    source = make_site()
    bridge, _ = make_bridge(dump_response(table_lines("wp_posts", POSTS_ROWS)))
    meta = snap(source, bridge, "s", ["readme.html"], ["wp_posts"], tmp_path / "bck")
    source.files["readme.html"] = b"changed live"

    with pytest.raises(ValueError, match="requires a source"):
        restore.restore_snapshot(meta.path, None, None,
                                 expected_site="s", expected_webroot="")
    with pytest.raises(ValueError, match="requires a source"):
        restore.restore_snapshot(meta.path, None, None, only_files=["readme.html"],
                                 expected_site="s", expected_webroot="")
    with pytest.raises(ValueError, match="requires a bridge"):
        restore.restore_snapshot(meta.path, source, None,
                                 expected_site="s", expected_webroot="")
    assert source.files["readme.html"] == b"changed live"  # no partial restore


@pytest.mark.parametrize("action", ["update-core", "heal-core", "prune-core"])
def test_core_action_snapshots_restore_the_files_they_replaced(
        tmp_path, action):
    """R12-P1-3: update-core/heal-core/prune-core advertise their pre-action
    snapshot as the rollback, but restore refused every core path.  The
    same audited allow_core unlock now covers the root core files,
    index.php and the wp-includes tree; the dry run proves the plan before
    any write."""
    core = {
        "wp-load.php": b"<?php // load",
        "index.php": b"<?php // front",
        "wp-includes/version.php": b"<?php $wp_version = '6.8.3';",
    }
    source = FakeSource()
    source.files.update(core)
    bridge, _ = make_bridge()
    meta = snap(source, bridge, "s", sorted(core), [], tmp_path / "bck",
                action=action)
    for path in core:
        source.files[path] = b"tampered " + path.encode()

    dry = restore.restore_snapshot(
        meta.path, source, make_bridge()[0], dry_run=True,
        expected_site="s", expected_webroot="")
    assert dry.files_restored == 3
    assert all(source.files[path].startswith(b"tampered") for path in core)

    report = restore.restore_snapshot(
        meta.path, source, make_bridge()[0],
        expected_site="s", expected_webroot="")
    assert report.files_restored == 3
    assert report.files_deleted == 0
    assert {path: source.files[path] for path in core} == core


def test_htaccess_config_restores_with_allow_config(tmp_path):
    # .htaccess is a site-config file: restore unlocks it automatically
    # (harden writes it; restore reverses those writes).
    source = FakeSource()
    source.files[".htaccess"] = b"RewriteEngine On"
    bridge, _ = make_bridge()
    meta = snap(source, bridge, "s", [".htaccess"], [], tmp_path / "bck")
    source.files[".htaccess"] = b"RewriteEngine Off"
    report = restore.restore_snapshot(meta.path, source, make_bridge()[0],
                                      expected_site="s", expected_webroot="")
    assert report.files_restored == 1
    assert source.files[".htaccess"] == b"RewriteEngine On"


def test_R13_absent_protected_files_roll_back_with_audited_delete_unlocks(
        tmp_path, wpt_records):
    """R13-P1-1: harden creates .htaccess and heal-core creates index.php
    after the pre-action snapshot recorded them ABSENT.  Restore's delete
    plan refused both, so the documented rollback could not undo the
    action.  The delete guard now takes the same audited allow_config/
    allow_core unlocks as the write guard; a protected path neither unlock
    names (the bare wp-admin directory) still refuses."""
    source = FakeSource()
    source.files["wp-content/uploads/keep.txt"] = b"keep"
    bridge, _ = make_bridge()
    meta = snap(source, bridge, "s",
                [".htaccess", "index.php", "wp-content/uploads/keep.txt"],
                [], tmp_path / "bck")
    # The action ran: both config/core entry points now exist live.
    source.files[".htaccess"] = b"RewriteEngine On"
    source.files["index.php"] = b"<?php // hardened front"

    dry = restore.restore_snapshot(
        meta.path, source, make_bridge()[0], dry_run=True,
        expected_site="s", expected_webroot="")
    assert dry.files_deleted == 2
    assert source.files[".htaccess"] == b"RewriteEngine On"

    report = restore.restore_snapshot(
        meta.path, source, make_bridge()[0],
        expected_site="s", expected_webroot="")
    assert report.files_deleted == 2
    assert ".htaccess" not in source.files
    assert "index.php" not in source.files
    messages = [record.getMessage() for record in wpt_records]
    assert any("guarded delete of protected config file: .htaccess" in msg
               for msg in messages)
    assert any("guarded core heal: deleting protected core file: index.php"
               in msg for msg in messages)

    # The unlock is audited and NARROW: a protected path neither unlock
    # names still refuses at the source, through restore's own seam too.
    with pytest.raises(SourceError, match="refusing to delete protected"):
        source.delete("wp-admin", allow_core=True)
    with pytest.raises(SourceError, match="refusing to delete protected"):
        source._check_deletable("wp-admin", allow_config=True, allow_core=True)


def test_bridge_payload_anomaly_raises(tmp_path):
    bridge, _ = make_bridge(dump_response(table_lines("wp_posts", POSTS_ROWS)))
    meta = snap(None, bridge, "s", [], ["wp_posts"], tmp_path / "bck")

    rbridge, _ = make_bridge(restore_response("wp_posts", 999, True))
    with pytest.raises(BridgeError, match="inserted=999"):
        restore.restore_snapshot(meta.path, None, rbridge,
                                 expected_site="s", expected_webroot="")


# --------------------------------------------------------------- chunking


def test_chunking_2500_rows_three_calls_stages_then_swaps(tmp_path):
    rows = [[str(i), f"v{i}"] for i in range(2500)]
    rows[0] = ["0", ["__wpt_b64__", BLOB_B64]]  # a bytes cell rides along
    bridge, _ = make_bridge(dump_response(table_lines("wp_posts", rows)))
    meta = snap(None, bridge, "s", [], ["wp_posts"], tmp_path / "bck")

    rbridge, rsession = make_bridge([
        restore_response("wp_posts", 1000, False),   # begin: stage, no swap
        restore_response("wp_posts", 1000, False),   # middle: append
        restore_response("wp_posts", 500, True),     # finalize: atomic swap
    ])
    report = restore.restore_snapshot(meta.path, None, rbridge,
                                      expected_site="s", expected_webroot="")

    assert report.tables_restored == ["wp_posts"]
    assert report.rows_inserted == 2500
    assert len(rsession.posts) == 3
    batches = [post[1]["json"]["params"] for post in rsession.posts]
    assert [len(b["rows"]) for b in batches] == [1000, 1000, 500]
    # staging begins once, the atomic swap is requested exactly once, last
    assert [b["truncate_first"] for b in batches] == [True, False, False]
    assert [b["finalize"] for b in batches] == [False, False, True]
    assert all(b["table"] == "wp_posts" for b in batches)
    # the b64 marker array reaches the bridge exactly as it sat on disk
    assert batches[0]["rows"][0] == ["0", ["__wpt_b64__", BLOB_B64]]


def test_restore_fails_closed_when_swap_not_confirmed(tmp_path):
    # The live table is only safe once the bridge CONFIRMS the atomic swap.
    # An unconfirmed finalize must abort the restore, not report success.
    rows = [[str(i), f"v{i}"] for i in range(2)]
    bridge, _ = make_bridge(dump_response(table_lines("wp_posts", rows)))
    meta = snap(None, bridge, "s", [], ["wp_posts"], tmp_path / "bck")

    rbridge, _ = make_bridge(restore_response("wp_posts", 2, False))
    with pytest.raises(BridgeError, match="did not confirm the atomic swap"):
        restore.restore_snapshot(meta.path, None, rbridge,
                                 expected_site="s", expected_webroot="")


def test_zero_row_restore_fails_closed_when_swap_not_confirmed(tmp_path):
    # The zero-row path validates its single response too: swapped:false on a
    # begin+finalize must NOT be reported as a successful restore.
    bridge, _ = make_bridge(dump_response(table_lines("wp_posts", [])))
    meta = snap(None, bridge, "s", [], ["wp_posts"], tmp_path / "bck")

    rbridge, _ = make_bridge(restore_response("wp_posts", 0, False))
    with pytest.raises(BridgeError, match="did not confirm the atomic swap"):
        restore.restore_snapshot(meta.path, None, rbridge,
                                 expected_site="s", expected_webroot="")


def test_restore_rejects_premature_swap_on_non_final_chunk(tmp_path):
    # A bridge that swaps before the final chunk would leave the live table
    # holding a partial restore; that must abort the run.
    rows = [[str(i), f"v{i}"] for i in range(2500)]
    bridge, _ = make_bridge(dump_response(table_lines("wp_posts", rows)))
    meta = snap(None, bridge, "s", [], ["wp_posts"], tmp_path / "bck")

    rbridge, _ = make_bridge([
        restore_response("wp_posts", 1000, True),   # swapped too early
        restore_response("wp_posts", 1000, False),
        restore_response("wp_posts", 500, False),
    ])
    with pytest.raises(BridgeError, match="on a non-final chunk"):
        restore.restore_snapshot(meta.path, None, rbridge,
                                 expected_site="s", expected_webroot="")


def test_restore_warns_when_old_backup_table_left_behind(tmp_path):
    # A leftover pre-restore backup table (cleanup DROP refused) is INERT and
    # must NOT turn a successful restore into a reported failure; it warns.
    rows = [[str(i), f"v{i}"] for i in range(2)]
    bridge, _ = make_bridge(dump_response(table_lines("wp_posts", rows)))
    meta = snap(None, bridge, "s", [], ["wp_posts"], tmp_path / "bck")

    rbridge, _ = make_bridge(restore_response("wp_posts", 2, True, old_left=True))
    report = restore.restore_snapshot(meta.path, None, rbridge,
                                      expected_site="s", expected_webroot="")
    assert report.rows_inserted == 2
    assert report.tables_restored == ["wp_posts"]


def test_zero_row_table_sends_one_empty_staging_call(tmp_path):
    bridge, _ = make_bridge(dump_response(table_lines("wp_posts", [])))
    meta = snap(None, bridge, "s", [], ["wp_posts"], tmp_path / "bck")

    rbridge, rsession = make_bridge(restore_response("wp_posts", 0, True))
    report = restore.restore_snapshot(meta.path, None, rbridge,
                                      expected_site="s", expected_webroot="")

    assert report.tables_restored == ["wp_posts"]
    assert report.rows_inserted == 0
    assert len(rsession.posts) == 1
    params = rsession.posts[0][1]["json"]["params"]
    assert params["rows"] == []
    assert params["truncate_first"] is True and params["finalize"] is True


# ------------------------------------------------------------ list_snapshots


def test_list_snapshots_newest_first_suffix_aware(tmp_path, monkeypatch):
    t0 = datetime(2026, 9, 15, 10, 30, 0, tzinfo=timezone.utc)
    # _now is called twice per create_snapshot (name + prune); the first
    # three snapshots share one second (base, -2, -3), the fourth is +1s.
    times = [t0] * 6 + [t0 + timedelta(seconds=1)] * 2
    monkeypatch.setattr(backup, "_now", lambda: times.pop(0))
    backup_dir = tmp_path / "bck"
    source = make_site()
    for _ in range(4):
        snap(source, None, "we ird", ["readme.html"], [], backup_dir)

    site = backup_dir / "we-ird"
    assert [p.name for p in restore.list_snapshots(backup_dir, "we ird")] == [
        "20260915-103001",
        "20260915-103000-3",
        "20260915-103000-2",
        "20260915-103000",
    ]
    # foreign entries are ignored; a missing site dir lists nothing
    (site / "not-a-snapshot").mkdir()
    (site / "stray.txt").write_text("x")
    assert len(restore.list_snapshots(backup_dir, "we ird")) == 4
    assert restore.list_snapshots(backup_dir, "other-site") == []
    assert restore.list_snapshots(tmp_path / "missing", "s") == []


# -------------------------------------------------- run_restore (CLI body)
#
# Everything below drives run_restore(ctx) with REAL Ctx objects, the way
# cli._lazy_call dispatches it. The stack seam is monkeypatched exactly as
# the patchability contract pins: wpt.restore.remote_stack returns a
# (prefilled source, FakeSession, recording bridge double) trio. Snapshots
# are REAL on-disk directories built by wpt.backup.create_snapshot (the
# `snap` helper above). Logs are captured with the wpt_records handler
# (caplog cannot see wpt.* — the parent logger does not propagate; same
# pattern as tests/test_verify.py), stdout with capsys.



class RecordingBridge:
    """Bridge double for the command body: records every call + destroy.

    ``info`` answers the configured ``uploads_basedir`` + ``abspath`` in
    the PRODUCTION wire shape (both SERVER-ABSOLUTE — run_restore
    relativizes the basedir against the abspath); ``db_restore_table``
    echoes the batch size as ``inserted`` — the exact payload
    restore_snapshot's anomaly gate accepts.
    """

    def __init__(
        self,
        uploads_basedir: str = "/srv/www/public_html/wp-content/uploads",
        abspath: str = "/srv/www/public_html/",
    ) -> None:
        self.destroyed = 0
        self.calls: list[tuple[str, dict]] = []
        self._uploads_basedir = uploads_basedir
        self._abspath = abspath

    def destroy(self) -> None:
        self.destroyed += 1

    def call(self, action, **params):
        self.calls.append((action, params))
        if action == "info":
            return {"ok": True, "uploads_basedir": self._uploads_basedir,
                    "abspath": self._abspath}
        if action == "db_restore_table":
            return {"ok": True, "table": params["table"],
                    "inserted": len(params["rows"]),
                    "swapped": bool(params.get("finalize", False))}
        raise AssertionError(f"unexpected bridge action: {action!r}")


class CloseRecordingSource(FakeSource):
    """FakeSource counting close() calls (the run_action teardown contract)."""

    def __init__(self) -> None:
        super().__init__()
        self.closed = 0

    def close(self) -> None:
        self.closed += 1


def _no_stack(ctx):
    raise AssertionError("remote_stack must not be built for this command")


def _live_source() -> CloseRecordingSource:
    """The make_site() layout on a close-recording source."""
    source = CloseRecordingSource()
    source.files = {
        "wp-config.php": CFG,
        "readme.html": b"readme",
        "wp-content/uploads/2020/01/a.jpg": BLOB,
    }
    return source


def _snapshot(backup_dir, source, *, label="example.com",
              targets=("readme.html", "wp-content/uploads/2020/01/a.jpg"),
              tables=("wp_posts",), action="clean-files"):
    """A REAL on-disk snapshot via create_snapshot (the engine builder)."""
    bridge = (make_bridge(dump_response(table_lines("wp_posts", POSTS_ROWS)))[0]
              if tables else make_bridge()[0])
    return snap(source, bridge, label, list(targets), list(tables),
                backup_dir, action)


def restore_ctx(tmp_path, **overrides):
    """A real Ctx the way cli.main builds one for the restore subcommand."""
    fields = dict(
        source="ftp://example.com",
        settings=load(),
        command="restore",
        backup_dir=tmp_path / "bck",
        wp_url="https://example.com",
    )
    fields.update(overrides)
    return Ctx(**fields)


def _errors(records):
    return [r.getMessage() for r in records
            if r.name == "wpt.restore" and r.levelno == logging.ERROR]


def test_run_list_mode_prints_snapshots_newest_first_no_stack(
        monkeypatch, tmp_path, capsys):
    t0 = datetime(2026, 9, 15, 10, 30, 0, tzinfo=timezone.utc)
    times = [t0] * 2 + [t0 + timedelta(seconds=1)] * 2
    monkeypatch.setattr(backup, "_now", lambda: times.pop(0))
    backup_dir = tmp_path / "bck"
    source = make_site()
    snap(source, None, "example.com", ["readme.html"], [], backup_dir)
    snap(source, None, "example.com", ["readme.html"], [], backup_dir,
         action="harden")
    monkeypatch.setattr(restore, "remote_stack", _no_stack)

    assert restore.run_restore(
        restore_ctx(tmp_path, backup_dir=backup_dir)) == 0

    out = capsys.readouterr().out
    assert out.splitlines()[0] == "# wpt restore — example.com"
    assert [ln for ln in out.splitlines() if ln[:1].isdigit()] == [
        "20260915-103001  action=harden  created=2026-09-15T10:30:01+00:00",
        "20260915-103000  action=clean-files  created=2026-09-15T10:30:00+00:00",
    ]


def test_run_list_mode_empty_prints_no_snapshots(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(restore, "remote_stack", _no_stack)
    ctx = restore_ctx(tmp_path, source="local", zip=tmp_path / "site.zip",
                      backup_dir=tmp_path / "none")

    assert restore.run_restore(ctx) == 0

    out = capsys.readouterr().out
    assert "# wpt restore — local:site.zip" in out
    assert "No snapshots for local:site.zip." in out


def test_run_bad_snapshot_name_refused_no_stack(monkeypatch, tmp_path,
                                                 wpt_records):
    monkeypatch.setattr(restore, "remote_stack", _no_stack)
    ctx = restore_ctx(tmp_path, extra={"snapshot": "../../etc"})

    assert restore.run_restore(ctx) == 1

    errors = _errors(wpt_records)
    assert len(errors) == 1
    assert "../../etc" in errors[0]


def test_run_missing_snapshot_dir_refused(monkeypatch, tmp_path, wpt_records):
    monkeypatch.setattr(restore, "remote_stack", _no_stack)
    ctx = restore_ctx(tmp_path, extra={"snapshot": "20260915-103000"})

    assert restore.run_restore(ctx) == 1

    errors = _errors(wpt_records)
    assert len(errors) == 1
    assert "20260915-103000" in errors[0]


def test_run_local_mode_restore_refused(monkeypatch, tmp_path, wpt_records):
    backup_dir = tmp_path / "bck"
    meta = _snapshot(backup_dir, make_site(), label="local:site.zip",
                     targets=("readme.html",), tables=())
    monkeypatch.setattr(restore, "remote_stack", _no_stack)
    ctx = restore_ctx(tmp_path, source="local", zip=tmp_path / "site.zip",
                      backup_dir=backup_dir, extra={"snapshot": meta.path.name})

    assert restore.run_restore(ctx) == 1

    errors = _errors(wpt_records)
    assert len(errors) == 1
    assert "restore is ftp-only in v1" in errors[0]


def test_run_dry_run_without_apply_reports_asif_writes_nothing(
        monkeypatch, tmp_path, capsys, wpt_records):
    backup_dir = tmp_path / "bck"
    source = _live_source()
    meta = _snapshot(backup_dir, source)
    source.files["readme.html"] = b"changed live"
    source.files["wp-content/uploads/2020/01/a.jpg"] = b"tampered"
    bridge = RecordingBridge()
    monkeypatch.setattr(restore, "remote_stack",
                        lambda ctx: (source, FakeSession(), bridge))
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir,
                      report_path=tmp_path / "restore.md",
                      extra={"snapshot": meta.path.name})

    assert restore.run_restore(ctx) == 0

    out = capsys.readouterr().out
    assert "# wpt restore — example.com" in out
    assert "nothing was written" in out
    assert "| files restored | 2 |" in out
    assert "| files deleted | 0 |" in out
    assert "| files absent kept | 0 |" in out
    assert "| tables restored | 1 |" in out
    assert "| rows inserted | 2 |" in out
    assert "wp_posts" in out
    markdown = ctx.report_path.read_text(encoding="utf-8")
    assert "| files restored | 2 |" in markdown
    assert not [op for _ts, op, _p in source.ops if op in ("write", "delete")]
    assert source.files["readme.html"] == b"changed live"
    assert source.files["wp-content/uploads/2020/01/a.jpg"] == b"tampered"
    assert bridge.calls == []
    assert any("dry run (pass --apply to execute)" in r.getMessage()
               for r in wpt_records
               if r.name == "wpt.restore" and r.levelno == logging.INFO)
    assert bridge.destroyed == 1
    assert source.closed == 1


def test_R23_real_cli_refuses_a_truthy_non_boolean_absent_entry(
        monkeypatch, tmp_path):
    """R23-P1 through the REAL CLI parser/dispatch: a hand-edited manifest
    with ``absent: "yes"`` must not become a silent live delete.  rc 1,
    no source delete op, and the live bytes survive byte-for-byte."""
    from wpt.cli import main

    backup_dir = tmp_path / "bck"
    source = _live_source()
    source.files["missing.txt"] = b"LIVE-DATA"
    meta = backup.create_snapshot(
        source, None, "example.com", ["missing.txt"], [],
        backup_dir, BackupSettings(), "files",
        site_raw="example.com", webroot="/srv/www/public_html")
    manifest_path = meta.path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][0]["absent"] = "yes"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    monkeypatch.setattr(restore, "remote_stack",
                        lambda ctx: (source, FakeSession(), None))
    rc = main([
        "--source", "ftp://example.com",
        "--webroot", "/srv/www/public_html",
        "--wp-url", "https://example.com",
        "--backup-dir", str(backup_dir),
        "--apply", "--yes",
        "restore", meta.path.name,
    ])
    assert rc == 1
    assert not [op for op in source.ops if op[1] == "delete"]
    assert source.files["missing.txt"] == b"LIVE-DATA"


def test_run_apply_with_yes_restores_bytes_and_tears_down_stack(
        monkeypatch, tmp_path, capsys):
    backup_dir = tmp_path / "bck"
    source = _live_source()
    meta = _snapshot(backup_dir, source)
    source.files["readme.html"] = b"changed live"
    source.files["wp-content/uploads/2020/01/a.jpg"] = b"tampered"
    bridge = RecordingBridge()
    monkeypatch.setattr(restore, "remote_stack",
                        lambda ctx: (source, FakeSession(), bridge))
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir, apply=True, yes=True,
                      extra={"snapshot": meta.path.name})

    assert restore.run_restore(ctx) == 0

    assert source.files["readme.html"] == b"readme"
    assert source.files["wp-content/uploads/2020/01/a.jpg"] == BLOB
    assert len(bridge.calls) == 1
    action, params = bridge.calls[0]
    assert action == "db_restore_table"
    assert params["table"] == "wp_posts"
    assert params["rows"] == POSTS_ROWS
    assert params["truncate_first"] is True
    assert params["finalize"] is True
    assert params["total_rows"] == len(POSTS_ROWS)
    assert re.fullmatch(r"[0-9a-f]{8,16}", params["restore_id"])
    out = capsys.readouterr().out
    assert "Restored snapshot" in out
    assert "| files restored | 2 |" in out
    assert "| rows inserted | 2 |" in out
    assert bridge.destroyed == 1
    assert source.closed == 1


def test_run_apply_without_yes_aborts_on_non_tty(monkeypatch, tmp_path,
                                                  wpt_records):
    backup_dir = tmp_path / "bck"
    source = _live_source()
    meta = _snapshot(backup_dir, source)
    source.files["readme.html"] = b"changed live"
    bridge = RecordingBridge()
    monkeypatch.setattr(restore, "remote_stack",
                        lambda ctx: (source, FakeSession(), bridge))
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir, apply=True, yes=False,
                      extra={"snapshot": meta.path.name})

    assert restore.run_restore(ctx) == 1

    assert source.files["readme.html"] == b"changed live"
    assert bridge.calls == []
    infos = [r.getMessage() for r in wpt_records
             if r.name == "wpt.restore" and r.levelno == logging.INFO]
    assert any("aborted by the operator" in m for m in infos)
    gate = [r.getMessage() for r in wpt_records
            if r.name == "wpt.actions" and r.levelno == logging.ERROR]
    assert any("--apply requires --yes when stdin is not a terminal" in m
               for m in gate)
    assert bridge.destroyed == 1
    assert source.closed == 1


def test_run_config_wp_config_restores_only_config_file(monkeypatch, tmp_path):
    backup_dir = tmp_path / "bck"
    source = _live_source()
    meta = _snapshot(backup_dir, source,
                     targets=("wp-config.php", "readme.html"), tables=())
    source.files["wp-config.php"] = b"tampered config"
    source.files["readme.html"] = b"changed live"
    bridge = RecordingBridge()
    monkeypatch.setattr(restore, "remote_stack",
                        lambda ctx: (source, FakeSession(), bridge))
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir, apply=True, yes=True,
                      extra={"snapshot": meta.path.name,
                             "config": "wp-config"})

    assert restore.run_restore(ctx) == 0

    assert source.files["wp-config.php"] == CFG
    assert source.files["readme.html"] == b"changed live"
    assert bridge.calls == []


def test_run_media_scopes_restore_to_uploads_subtree(monkeypatch, tmp_path):
    backup_dir = tmp_path / "bck"
    source = _live_source()
    meta = _snapshot(backup_dir, source, tables=())
    source.files["readme.html"] = b"changed live"
    source.files["wp-content/uploads/2020/01/a.jpg"] = b"tampered"
    bridge = RecordingBridge()
    monkeypatch.setattr(restore, "remote_stack",
                        lambda ctx: (source, FakeSession(), bridge))
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir, apply=True, yes=True,
                      extra={"snapshot": meta.path.name, "media": True})

    assert restore.run_restore(ctx) == 0

    assert source.files["wp-content/uploads/2020/01/a.jpg"] == BLOB
    assert source.files["readme.html"] == b"changed live"
    assert bridge.calls == [("info", {})]


def test_run_corrupt_snapshot_fails_closed_rc1(monkeypatch, tmp_path,
                                               wpt_records):
    backup_dir = tmp_path / "bck"
    source = _live_source()
    meta = _snapshot(backup_dir, source, tables=())
    source.files["readme.html"] = b"changed live"
    captured = meta.path / "files/readme.html"
    flipped = bytearray(captured.read_bytes())
    flipped[0] ^= 0xFF
    captured.write_bytes(bytes(flipped))
    bridge = RecordingBridge()
    monkeypatch.setattr(restore, "remote_stack",
                        lambda ctx: (source, FakeSession(), bridge))
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir, apply=True, yes=True,
                      extra={"snapshot": meta.path.name})

    assert restore.run_restore(ctx) == 1

    errors = _errors(wpt_records)
    assert len(errors) == 1
    assert errors[0].startswith("restore failed:")
    assert "verification" in errors[0]
    assert source.files["readme.html"] == b"changed live"
    assert bridge.calls == []
    assert bridge.destroyed == 1
    assert source.closed == 1


def test_run_media_without_usable_uploads_basedir_fails(monkeypatch, tmp_path,
                                                        wpt_records):
    backup_dir = tmp_path / "bck"
    source = _live_source()
    meta = _snapshot(backup_dir, source, tables=())
    source.files["readme.html"] = b"changed live"
    bridge = RecordingBridge(uploads_basedir="")
    monkeypatch.setattr(restore, "remote_stack",
                        lambda ctx: (source, FakeSession(), bridge))
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir, apply=True, yes=True,
                      extra={"snapshot": meta.path.name, "media": True})

    assert restore.run_restore(ctx) == 1

    errors = _errors(wpt_records)
    assert len(errors) == 1
    assert "uploads" in errors[0]
    assert source.files["readme.html"] == b"changed live"
    assert bridge.calls == [("info", {})]
    assert bridge.destroyed == 1


def test_run_media_uploads_dir_outside_webroot_fails_closed(monkeypatch,
                                                            tmp_path,
                                                            wpt_records):
    """A custom uploads dir OUTSIDE the webroot (constant UPLOADS in
    wp-config) can never match webroot-relative manifest paths — the
    restore fails closed instead of silently scoping nothing."""
    backup_dir = tmp_path / "bck"
    source = _live_source()
    meta = _snapshot(backup_dir, source, tables=())
    source.files["readme.html"] = b"changed live"
    bridge = RecordingBridge(uploads_basedir="/var/site-data/uploads")
    monkeypatch.setattr(restore, "remote_stack",
                        lambda ctx: (source, FakeSession(), bridge))
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir, apply=True, yes=True,
                      extra={"snapshot": meta.path.name, "media": True})

    assert restore.run_restore(ctx) == 1

    errors = _errors(wpt_records)
    assert len(errors) == 1
    assert "not under the webroot" in errors[0]
    assert source.files["readme.html"] == b"changed live"
    assert bridge.calls == [("info", {})]
    assert bridge.destroyed == 1
    assert source.closed == 1


# ------------------------------------------- --undo-last (the CLI rollback)
#
# ctx.extra["undo_last"] drives the one-flag rollback: resolve the NEWEST
# snapshot (list_snapshots[0]) and restore exactly as if its name had been
# passed. It precedes the snapshot-name logic and the no-name list mode;
# targeting flags still compose with the resolved snapshot.


def test_run_undo_last_restores_newest_of_two_snapshots(
        monkeypatch, tmp_path, capsys, wpt_records):
    t0 = datetime(2026, 9, 15, 10, 30, 0, tzinfo=timezone.utc)
    # _now is called twice per create_snapshot (name + prune): the first
    # snapshot lands at t0, the second one second later.
    times = [t0, t0, t0 + timedelta(seconds=1), t0 + timedelta(seconds=1)]
    monkeypatch.setattr(backup, "_now", lambda: times.pop(0))
    backup_dir = tmp_path / "bck"
    source = _live_source()
    _snapshot(backup_dir, source, tables=())      # readme.html = b"readme"
    source.files["readme.html"] = b"readme v2"
    meta_new = _snapshot(backup_dir, source, tables=())
    source.files["readme.html"] = b"changed after"
    bridge = RecordingBridge()
    monkeypatch.setattr(restore, "remote_stack",
                        lambda ctx: (source, FakeSession(), bridge))
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir, apply=True, yes=True,
                      extra={"undo_last": True})

    assert restore.run_restore(ctx) == 0

    # the NEWER snapshot's bytes are what got restored
    assert source.files["readme.html"] == b"readme v2"
    assert bridge.calls == []  # file-only snapshots: no bridge traffic
    infos = [r.getMessage() for r in wpt_records
             if r.name == "wpt.restore" and r.levelno == logging.INFO]
    assert any(f"undoing with the newest snapshot {meta_new.path.name}" in m
              for m in infos)
    out = capsys.readouterr().out
    assert "Restored snapshot" in out
    assert meta_new.path.name in out  # the resolved name flows through


def test_R17_undo_last_skips_a_legacy_empty_timestamp_dir(
        monkeypatch, tmp_path, wpt_records):
    """R17-B-P2-B: a pre-existing timestamped EMPTY directory (a pre-fix
    crash residue) was listed as a fail-closed candidate and shadowed the
    valid older snapshot for --undo-last.  An empty manifest-less directory
    is not a snapshot; a NON-empty one stays fail-closed."""
    from wpt.restore import list_snapshots

    backup_dir = tmp_path / "bck"
    source = _live_source()
    meta = _snapshot(backup_dir, source, tables=())
    empty = meta.path.parent / "29990101-000000"
    empty.mkdir()
    assert list_snapshots(backup_dir, "example.com", webroot="") == [meta.path]

    source.files["readme.html"] = b"changed live"
    bridge = RecordingBridge()
    monkeypatch.setattr(restore, "remote_stack",
                        lambda ctx: (source, FakeSession(), bridge))
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir, apply=True, yes=True,
                      extra={"undo_last": True})
    assert restore.run_restore(ctx) == 0
    assert source.files["readme.html"] == b"readme"


def test_run_undo_last_with_explicit_name_is_mutually_exclusive(
        monkeypatch, tmp_path, wpt_records):
    backup_dir = tmp_path / "bck"
    source = _live_source()
    meta = _snapshot(backup_dir, source, tables=())
    source.files["readme.html"] = b"changed live"
    monkeypatch.setattr(restore, "remote_stack", _no_stack)
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir, apply=True, yes=True,
                      extra={"undo_last": True, "snapshot": meta.path.name})

    assert restore.run_restore(ctx) == 1

    errors = _errors(wpt_records)
    assert len(errors) == 1
    assert "mutually exclusive" in errors[0]
    assert source.files["readme.html"] == b"changed live"  # nothing restored


def test_run_undo_last_with_no_snapshots_fails(monkeypatch, tmp_path,
                                                wpt_records):
    monkeypatch.setattr(restore, "remote_stack", _no_stack)
    ctx = restore_ctx(tmp_path, extra={"undo_last": True})

    assert restore.run_restore(ctx) == 1

    errors = _errors(wpt_records)
    assert len(errors) == 1
    assert "no snapshots to undo" in errors[0]


def test_run_undo_last_composes_with_config_targeting(monkeypatch, tmp_path):
    backup_dir = tmp_path / "bck"
    source = _live_source()
    _snapshot(backup_dir, source,
              targets=("wp-config.php", "readme.html"), tables=())
    source.files["wp-config.php"] = b"tampered config"
    source.files["readme.html"] = b"changed live"
    bridge = RecordingBridge()
    monkeypatch.setattr(restore, "remote_stack",
                        lambda ctx: (source, FakeSession(), bridge))
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir, apply=True, yes=True,
                      extra={"undo_last": True, "config": "wp-config"})

    assert restore.run_restore(ctx) == 0

    assert source.files["wp-config.php"] == CFG
    assert source.files["readme.html"] == b"changed live"  # targeting holds
    assert bridge.calls == []


def test_run_undo_last_dry_run_reports_asif_writes_nothing(
        monkeypatch, tmp_path, capsys):
    backup_dir = tmp_path / "bck"
    source = _live_source()
    meta = _snapshot(backup_dir, source)
    source.files["readme.html"] = b"changed live"
    source.files["wp-content/uploads/2020/01/a.jpg"] = b"tampered"
    bridge = RecordingBridge()
    monkeypatch.setattr(restore, "remote_stack",
                        lambda ctx: (source, FakeSession(), bridge))
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir,
                      extra={"undo_last": True})

    assert restore.run_restore(ctx) == 0

    out = capsys.readouterr().out
    assert "nothing was written" in out
    assert meta.path.name in out
    assert "| files restored | 2 |" in out
    assert "| rows inserted | 2 |" in out
    assert not [op for _ts, op, _p in source.ops if op in ("write", "delete")]
    assert source.files["readme.html"] == b"changed live"
    assert source.files["wp-content/uploads/2020/01/a.jpg"] == b"tampered"
    assert bridge.calls == []


# -------------------------------------------- report md + JSON twin (_emit)
#
# With ctx.report_path set, _emit writes the markdown as today PLUS a
# small snake_case JSON twin at report_path.with_suffix(".json") (the
# audit _emit pair); stdout stays the markdown, unchanged.


def test_run_json_twin_written_beside_markdown_report(
        monkeypatch, tmp_path, capsys):
    backup_dir = tmp_path / "bck"
    source = _live_source()
    meta = _snapshot(backup_dir, source)
    source.files["readme.html"] = b"changed live"
    source.files["wp-content/uploads/2020/01/a.jpg"] = b"tampered"
    bridge = RecordingBridge()
    monkeypatch.setattr(restore, "remote_stack",
                        lambda ctx: (source, FakeSession(), bridge))
    report_path = tmp_path / "restore.md"
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir,
                      report_path=report_path,
                      extra={"snapshot": meta.path.name})

    assert restore.run_restore(ctx) == 0

    out = capsys.readouterr().out
    markdown = report_path.read_text(encoding="utf-8")
    # stdout is still the markdown — unchanged by the JSON twin
    assert out == markdown + "\n"
    assert "nothing was written" in markdown
    assert "| files restored | 2 |" in markdown
    json_path = report_path.with_suffix(".json")
    assert json_path.is_file()
    text = json_path.read_text(encoding="utf-8")
    payload = json.loads(text)
    # the twin's schema: dry-run boundary + EVERY RestoreReport counter
    assert set(payload) == {"site", "snapshot", "dry_run", "files_restored",
                            "files_deleted", "files_absent_kept",
                            "tables_restored", "rows_inserted"}
    assert payload["site"] == "example.com"
    assert payload["snapshot"] == meta.path.name
    assert payload["dry_run"] is True
    assert payload["files_restored"] == 2
    assert payload["files_deleted"] == 0
    assert payload["files_absent_kept"] == 0
    assert payload["tables_restored"] == ["wp_posts"]
    assert payload["rows_inserted"] == 2
    # the audit render_json formatting contract: sorted keys, indent 2
    assert text == json.dumps(payload, ensure_ascii=False, sort_keys=True,
                              indent=2)


def test_run_no_report_path_writes_no_json_twin(monkeypatch, tmp_path,
                                                 capsys):
    backup_dir = tmp_path / "bck"
    source = _live_source()
    meta = _snapshot(backup_dir, source, tables=())
    source.files["readme.html"] = b"changed live"
    bridge = RecordingBridge()
    monkeypatch.setattr(restore, "remote_stack",
                        lambda ctx: (source, FakeSession(), bridge))
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir,
                      extra={"snapshot": meta.path.name})

    assert restore.run_restore(ctx) == 0

    out = capsys.readouterr().out
    assert "# wpt restore — example.com" in out
    assert "Dry-run restore of snapshot" in out
    # stdout only: no report files appear anywhere next to the run
    assert not list(tmp_path.glob("*.json"))
    assert not list(tmp_path.glob("*.md"))


def test_restore_refuses_a_bridge_endpoint_never_site_content(tmp_path):
    """[L59] a bridge is a token-authenticated endpoint, not content: a
    snapshot must not hold one (backup excludes it) and restore refuses both
    an explicit target and a manifest that carries one — otherwise a token
    recovered from the archive re-arms a working endpoint after the run."""
    from wpt.bridge_name import is_bridge_file
    from wpt.restore import restore_snapshot

    assert is_bridge_file("bridge-af12cd34.php")
    assert not is_bridge_file("bridge-shell.php")

    def _manifest(name, files):
        p = tmp_path / name
        p.mkdir()
        (p / "manifest.json").write_text(
            '{"format": "wpt-backup-manifest", "version": 1, "site": "x", '
            '"site_raw": "x", "webroot": "", '
            '"created": "2026-01-01T00:00:00Z", "files": '
            + str(files).replace("'", '"') + ', "tables": []}')
        return p

    # an explicit target naming a bridge is refused
    with pytest.raises(ValueError, match="bridge"):
        restore_snapshot(_manifest("s1", []), None, None,
                         only_files=["bridge-af12cd34.php"],
                         expected_site="x", expected_webroot="")
    # a manifest that HOLDS one is refused wholesale
    with pytest.raises(ValueError, match="bridge"):
        restore_snapshot(
            _manifest("s2", ["wp-config.php", "bridge-af12cd34.php"]), None, None,
            expected_site="x", expected_webroot="")


# ------------------------------------------------------- triple-check round 2


def test_PROBE1_restore_refuses_a_probe_target_and_a_probe_manifest(
        tmp_path):
    """PROBE1: restore's only_files and stray-artifact checks refused only
    bridge names; a restored probe is a token-gated endpoint."""
    from wpt.php_probe import PhpProbe
    from wpt.restore import restore_snapshot
    from wpt.settings import load

    live = _live_source()
    probe = PhpProbe(live, FakeSession(), load().probe, "https://example.com")
    endpoint = probe.ensure()
    # The real snapshot builder drops the probe (see test_backup); a
    # snapshot that (from an older run/archive) carries one is refused.
    meta = _snapshot(tmp_path / "bck", live, tables=())
    with pytest.raises(ValueError, match="token endpoint"):
        restore_snapshot(meta.path, live, None, only_files=[endpoint],
                         expected_site="example.com", expected_webroot="")

    manifest_path = meta.path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"].append({"path": endpoint, "absent": True})
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    from wpt.backup import verify_snapshot
    assert verify_snapshot(meta.path)
    with pytest.raises(ValueError, match="token endpoint"):
        restore_snapshot(meta.path, live, None,
                         expected_site="example.com", expected_webroot="")


# ------------------------------------------------------- round-3 regressions


def test_SITE_LABEL_malformed_ipv6_url_is_a_clean_refusal(tmp_path):
    """SITE-LABEL: urlparse('http://[::1').hostname raises ValueError;
    restore called it before its handler, so --undo-last and a named restore
    raised instead of rc 1."""
    from wpt.backup import site_label
    from wpt.settings import load

    ctx = Ctx(source="ftp://h", settings=load(),
              wp_url="http://[::1", webroot="domains/site.test/public_html",
              backup_dir=tmp_path / "bk", extra={"undo_last": True})
    assert site_label(ctx) == "domains/site.test/public_html"
    assert restore.run_restore(ctx) == 1

    ctx.extra = {"snapshot": "last"}
    assert restore.run_restore(ctx) == 1
    ctx.extra = {"snapshot": "files-20260101T000000Z-deadbe"}
    assert restore.run_restore(ctx) == 1


def test_REPORT_SURROGATE_restore_writes_complete_faces(tmp_path):
    """REPORT-SURROGATE (restore's direct writer): a surrogate in the site
    label crashed the strict write, leaving a 0-byte markdown and no JSON."""
    from wpt.settings import load

    report = restore.RestoreReport(
        files_restored=1, files_absent_kept=0, files_deleted=0,
        tables_restored=[], rows_inserted=0)
    ctx = Ctx(source="ftp://h", settings=load(), backup_dir=tmp_path / "bk",
              report_path=tmp_path / "restore.md")
    restore._emit(ctx, "bad\udcff.example", "snap", report, dry_run=True)
    markdown = ctx.report_path.read_text(encoding="utf-8")
    twin = ctx.report_path.with_suffix(".json").read_text(encoding="utf-8")
    assert "\\udcff" in markdown
    assert "\\udcff" in twin


# ------------------------------------------------- round-4 identity/teardown


def _round4_snapshot(backup_dir, source, *, label, webroot, targets,
                     action="clean-files"):
    return backup.create_snapshot(
        source, None, label, list(targets), [], backup_dir,
        BackupSettings(), action, site_raw=label, webroot=webroot)


def test_RESTORE_SNAPSHOT_IDENTITY_two_docroots_on_one_host_never_cross(
        monkeypatch, tmp_path, wpt_records):
    """P1-RESTORE-SNAPSHOT-IDENTITY: snapshots were keyed only by hostname,
    so --undo-last for public_html/blog restored public_html's bytes."""
    backup_dir = tmp_path / "bck"
    root = FakeSource()
    root.files["wp-content/a.txt"] = b"ROOT-DOCROOT"
    meta = _round4_snapshot(
        backup_dir, root, label="example.com", webroot="public_html",
        targets=["wp-content/a.txt"])
    monkeypatch.setattr(restore, "remote_stack", _no_stack)
    target = FakeSource()
    target.files["wp-content/a.txt"] = b"BLOG"
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir,
                      webroot="public_html/blog", apply=True, yes=True,
                      extra={"undo_last": True})

    assert restore.run_restore(ctx) == 1
    assert target.files["wp-content/a.txt"] == b"BLOG"
    assert any("webroot" in message for message in _errors(wpt_records))
    assert meta.path.is_dir()


def test_RESTORE_SNAPSHOT_IDENTITY_lossy_label_collision_is_refused(
        monkeypatch, tmp_path, wpt_records):
    """bücher.example and b-cher.example sanitize to ONE directory; the raw
    site recorded in the manifest must refuse the cross-site restore."""
    backup_dir = tmp_path / "bck"
    source = FakeSource()
    source.files["wp-content/a.txt"] = b"BUCHER-SECRET"
    meta = _round4_snapshot(
        backup_dir, source, label="bücher.example", webroot="public_html",
        targets=["wp-content/a.txt"])
    assert meta.path.parent.name == "b-cher.example"
    monkeypatch.setattr(restore, "remote_stack", _no_stack)
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir,
                      wp_url="https://b-cher.example",
                      webroot="public_html", apply=True, yes=True,
                      extra={"snapshot": meta.path.name})

    assert restore.run_restore(ctx) == 1
    assert any("bücher.example" in message or "belongs" in message
               for message in _errors(wpt_records))


@pytest.mark.parametrize("missing", [
    ("site_raw", "webroot"),
    ("webroot",),
])
def test_RESTORE_SNAPSHOT_IDENTITY_pre_identity_manifest_is_refused_everywhere(
        monkeypatch, tmp_path, wpt_records, missing):
    """A pre-identity manifest is UNSUPPORTED on managed AND explicit paths:
    both current identity keys are mandatory, with no migration/trust path."""
    backup_dir = tmp_path / "bck"
    source = _live_source()
    meta = _snapshot(backup_dir, source, tables=())
    manifest_path = meta.path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for key in missing:
        manifest.pop(key, None)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    # Selection keeps an unprovable manifest as the newest CANDIDATE (never
    # silently skipping a newer snapshot, R6-36); the identity gate below
    # is what refuses it on every restore route.  List mode does not
    # advertise it (the round-4 verifier test owns that display rule).
    assert restore.list_snapshots(
        backup_dir, "example.com", webroot="domains/example.com/public_html") \
        == [meta.path]
    monkeypatch.setattr(restore, "remote_stack", _no_stack)
    source.files["readme.html"] = b"changed"

    managed = restore_ctx(
        tmp_path, backup_dir=backup_dir, apply=True, yes=True,
        extra={"snapshot": meta.path.name})
    assert restore.run_restore(managed) == 1
    assert source.files["readme.html"] == b"changed"
    errors = _errors(wpt_records)
    assert any("regenerate the snapshot with the current format" in message
               for message in errors), errors
    for key in missing:
        assert any(key in message for message in errors), errors

    explicit = restore_ctx(
        tmp_path, backup_dir=backup_dir, apply=True, yes=True,
        extra={"snapshot": str(meta.path)})
    assert restore.run_restore(explicit) == 1
    assert source.files["readme.html"] == b"changed"
    explicit_errors = _errors(wpt_records)[len(errors):]
    assert any("regenerate the snapshot with the current format" in message
               for message in explicit_errors), explicit_errors


def test_NEW1_current_manifest_explicit_path_works_but_never_crosses_sites(
        monkeypatch, tmp_path, wpt_records):
    """An explicit path is a LOCATION, not a trust bypass: a current-format
    manifest with matching site_raw/webroot restores, a different site's
    current manifest is refused exactly like a managed one."""
    backup_dir = tmp_path / "bck"
    source = FakeSource()
    source.files["readme.html"] = b"ORIGINAL"
    own = _round4_snapshot(
        backup_dir, source, label="example.com", webroot="public_html",
        targets=["readme.html"])
    source.files["readme.html"] = b"CHANGED"
    monkeypatch.setattr(
        restore, "remote_stack",
        lambda ctx: (source, FakeSession(), RecordingBridge()))
    ctx = restore_ctx(
        tmp_path, backup_dir=backup_dir, wp_url="https://example.com",
        webroot="public_html", apply=True, yes=True,
        extra={"snapshot": str(own.path)})
    assert restore.run_restore(ctx) == 0
    assert source.files["readme.html"] == b"ORIGINAL"

    foreign_source = FakeSource()
    foreign_source.files["readme.html"] = b"FOREIGN"
    foreign = _round4_snapshot(
        backup_dir, foreign_source, label="other.example",
        webroot="public_html", targets=["readme.html"])
    source.files["readme.html"] = b"WORKING"
    cross = restore_ctx(
        tmp_path, backup_dir=backup_dir, wp_url="https://example.com",
        webroot="public_html", apply=True, yes=True,
        extra={"snapshot": str(foreign.path)})
    assert restore.run_restore(cross) == 1
    assert source.files["readme.html"] == b"WORKING"
    assert any("belongs to site" in message for message in _errors(wpt_records))


def test_NEW1_raw_site_identity_is_exact_www_is_not_the_apex(
        monkeypatch, tmp_path, wpt_records):
    """A ``www.example.com`` snapshot must never restore into ``example.com``
    on the explicit path; there is no normalize_domain fallback."""
    backup_dir = tmp_path / "bck"
    source = FakeSource()
    source.files["readme.html"] = b"WWW-ORIGINAL"
    meta = _round4_snapshot(
        backup_dir, source, label="www.example.com", webroot="public_html",
        targets=["readme.html"])
    source.files["readme.html"] = b"APEX-LIVE"
    monkeypatch.setattr(
        restore, "remote_stack",
        lambda ctx: (source, FakeSession(), RecordingBridge()))
    ctx = restore_ctx(
        tmp_path, backup_dir=backup_dir, wp_url="https://example.com",
        webroot="public_html", apply=True, yes=True,
        extra={"snapshot": str(meta.path)})

    assert restore.run_restore(ctx) == 1
    assert source.files["readme.html"] == b"APEX-LIVE"
    assert any("belongs to site" in message for message in _errors(wpt_records))


def test_NEW1_new_manifest_with_both_identity_keys_still_restores(
        monkeypatch, tmp_path):
    """The strict rule must not regress a production-shaped snapshot: both
    keys recorded and matching still restores."""
    backup_dir = tmp_path / "bck"
    source = FakeSource()
    source.files["readme.html"] = b"ORIGINAL"
    meta = _round4_snapshot(
        backup_dir, source, label="example.com", webroot="public_html",
        targets=["readme.html"])
    source.files["readme.html"] = b"CHANGED"
    monkeypatch.setattr(
        restore, "remote_stack",
        lambda ctx: (source, FakeSession(), RecordingBridge()))
    ctx = restore_ctx(
        tmp_path, backup_dir=backup_dir, wp_url="https://example.com",
        webroot="public_html", apply=True, yes=True,
        extra={"snapshot": meta.path.name})
    assert restore.run_restore(ctx) == 0
    assert source.files["readme.html"] == b"ORIGINAL"


def test_ENDPOINT_TRAILING_SLASH_predicate_and_restore_refuse_normalized_names(
        tmp_path):
    """P1-ENDPOINT-TRAILING-SLASH: Source._guard_path normalizes the slash
    away, but the predicate compared the raw tail, so a crafted manifest
    re-armed the real token endpoint."""
    from wpt.bridge_name import is_wpt_endpoint_file
    from wpt.restore import restore_snapshot

    for endpoint in ("wpt-probe-deadbeef.php", "bridge-af12cd34.php"):
        for suffix in ("/", "//", "/.", "/./", "\\"):
            assert is_wpt_endpoint_file(endpoint + suffix), endpoint + suffix
        assert is_wpt_endpoint_file(endpoint.upper())

    source = FakeSource()
    source.files["wp-config.php"] = CFG
    endpoint = "wpt-probe-deadbeef.php"
    source.files[endpoint] = b"<?php probe token"
    # The writer refuses an endpoint outright: it must never enter an archive.
    with pytest.raises(ValueError, match="token endpoint"):
        backup.create_snapshot(
            source, None, "example.com", ["wp-config.php", endpoint], [],
            tmp_path / "refused", BackupSettings(), "backup",
            site_raw="example.com", webroot="")
    meta = backup.create_snapshot(
        source, None, "example.com", ["wp-config.php"], [],
        tmp_path / "bck", BackupSettings(), "backup",
        site_raw="example.com", webroot="")
    manifest_path = meta.path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    # Simulate a manifest forged outside the writer: a trailing-slash path
    # that normalizes to the real endpoint, with matching payload/hash.
    payload = source.files[endpoint]
    stored = meta.path / "files" / endpoint
    stored.write_bytes(payload)
    manifest["files"].append({
        "path": endpoint + "/", "absent": False,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
    })
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    assert backup.verify_snapshot(meta.path) is True
    with pytest.raises(ValueError, match="token endpoint"):
        restore_snapshot(meta.path, source, None,
                         expected_site="example.com", expected_webroot="")


class _StopOnCloseSource(CloseRecordingSource):
    def close(self):
        super().close()
        raise StopRequested("SIGTERM during close")


class _BrokenDestroyBridge(RecordingBridge):
    def destroy(self):
        super().destroy()
        raise SourceError("destroy refused")


def test_RESTORE_TEARDOWN_always_closes_and_stop_returns_1(
        monkeypatch, tmp_path, wpt_records):
    """P2-RESTORE-TEARDOWN: bridge.destroy/source.close escaped run_restore;
    a destroy failure skipped the close and a close stop was lost."""
    backup_dir = tmp_path / "bck"
    source = _StopOnCloseSource()
    source.files = {"readme.html": b"readme"}
    meta = _snapshot(backup_dir, source, tables=())
    monkeypatch.setattr(
        restore, "remote_stack",
        lambda ctx: (source, FakeSession(), RecordingBridge()))
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir, apply=False,
                      extra={"snapshot": meta.path.name})
    assert restore.run_restore(ctx) == 1
    assert source.closed == 1

    source2 = _live_source()
    monkeypatch.setattr(
        restore, "remote_stack",
        lambda ctx: (source2, FakeSession(), _BrokenDestroyBridge()))
    ctx2 = restore_ctx(tmp_path, backup_dir=backup_dir, apply=False,
                       extra={"snapshot": meta.path.name})
    assert restore.run_restore(ctx2) == 0
    assert source2.closed == 1


def test_RESTORE_REPORT_prints_first_and_writes_failure_artifacts(
        monkeypatch, tmp_path, capsys, wpt_records):
    """P2-RESTORE-REPORT: a write failure produced 0 stdout bytes; every
    rc-1 path left no report.  stdout must come first, and failures use the
    shared not-complete writer."""
    backup_dir = tmp_path / "bck"
    source = _live_source()
    meta = _snapshot(backup_dir, source, tables=())
    monkeypatch.setattr(
        restore, "remote_stack",
        lambda ctx: (source, FakeSession(), RecordingBridge()))
    blocker = tmp_path / "blocked"
    blocker.write_text("not a directory", encoding="utf-8")
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir, apply=False,
                      report_path=blocker / "r.md",
                      extra={"snapshot": meta.path.name})
    assert restore.run_restore(ctx) == 1
    assert "Dry-run restore" in capsys.readouterr().out

    # A verification failure still leaves the requested pair behind.
    payload = meta.path / "files" / "readme.html"
    payload.write_bytes(b"tampered after the manifest hash")
    report = tmp_path / "r.md"
    ctx2 = restore_ctx(tmp_path, backup_dir=backup_dir, apply=False,
                       report_path=report,
                       extra={"snapshot": meta.path.name})
    assert restore.run_restore(ctx2) == 1
    assert "## This run did not complete" in report.read_text(
        encoding="utf-8")
    twin = json.loads(report.with_suffix(".json").read_text(encoding="utf-8"))
    assert twin["run"]["status"] == "failed"


def test_ROUND4_VERIFIER_list_mode_lists_only_current_identity(
        monkeypatch, tmp_path, capsys):
    """List mode lists CURRENT-format snapshots only and never advertises
    pre-identity manifests as legacy/discoverable: an old manifest is simply
    unsupported (the refusal tests above own the remediation message)."""
    backup_dir = tmp_path / "bck"
    source = FakeSource()
    source.files["wp-content/a.txt"] = b"OLD"
    old = _round4_snapshot(
        backup_dir, source, label="example.com", webroot="public_html",
        targets=["wp-content/a.txt"])
    manifest_path = old.path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.pop("site_raw")
    manifest.pop("webroot")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    source.files["wp-content/b.txt"] = b"NEW"
    current = _round4_snapshot(
        backup_dir, source, label="example.com", webroot="public_html",
        targets=["wp-content/b.txt"])

    monkeypatch.setattr(restore, "remote_stack", _no_stack)
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir,
                      wp_url="https://example.com", webroot="public_html")
    assert restore.run_restore(ctx) == 0
    out = capsys.readouterr().out
    assert current.path.name in out
    assert f"{old.path.name}  action=" not in out
    assert "legacy" not in out.lower()
    assert "migration" not in out.lower()
    assert "No snapshots" not in out


# ------------------------------------------------------- triple-check round 6


def test_R6_24_symlinked_stored_bytes_and_fifo_manifest_are_refused(tmp_path):
    """R6-24: verify/restore followed a symlink out of the snapshot and
    blocked forever on a FIFO.  The shared bounded regular-file reader
    rejects both before any bytes are trusted or restored."""
    import os

    source = make_site()
    meta = snap(source, None, "example.com", ["readme.html"], [],
                tmp_path / "bck")
    stored = meta.path / "files" / "readme.html"
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"OUTSIDE-SECRET")
    stored.unlink()
    stored.symlink_to(outside)

    assert backup.verify_snapshot(meta.path) is False
    with pytest.raises(ValueError, match="verification"):
        restore.restore_snapshot(meta.path, source, make_bridge()[0],
                                 expected_site="example.com", expected_webroot="")
    assert outside.read_bytes() == b"OUTSIDE-SECRET"

    # FIFO manifest: no hang and no trust
    meta2 = snap(source, None, "example.com", ["readme.html"], [],
                 tmp_path / "bck2")
    manifest = meta2.path / "manifest.json"
    manifest.unlink()
    os.mkfifo(manifest)
    assert backup.verify_snapshot(meta2.path) is False
    with pytest.raises(ValueError, match="verification"):
        restore.restore_snapshot(meta2.path, source, make_bridge()[0],
                                 expected_site="example.com", expected_webroot="")


def test_R6_24_manifest_is_capped_and_only_written_bytes_are_hashed(tmp_path):
    """R6-24: the manifest has a 1 MiB cap, and the restore hashes the
    EXACT bytes it read from the snapshot (a concurrent swap cannot make it
    trust bytes never captured).  The post-write LIVE re-read below is the
    separate SPEC verify-after-write, never a second read of the snapshot."""
    source = make_site()
    meta = snap(source, None, "example.com", ["readme.html"], [],
                tmp_path / "bck")
    (meta.path / "manifest.json").write_bytes(
        b"{" + b" " * (backup.MANIFEST_MAX_BYTES + 1))
    assert backup.verify_snapshot(meta.path) is False

    meta2 = snap(source, None, "example.com", ["readme.html"], [],
                 tmp_path / "bck2")

    class _OneReadSource(FakeSource):
        def __init__(self):
            super().__init__()
            self.files = dict(source.files)
            self.reads = 0

        def read_bytes(self, path):
            self.reads += 1
            if self.reads > 1:
                raise SourceError("snapshot bytes were re-read")
            return super().read_bytes(path)

    live = _OneReadSource()
    live.files["readme.html"] = b"changed live"
    report = restore.restore_snapshot(meta2.path, live, make_bridge()[0],
                                      expected_site="example.com", expected_webroot="")
    assert report.files_restored == 1
    assert live.files["readme.html"] == b"readme"
    # A live file whose size already differs is planned as a write WITHOUT
    # reading it (R7-P2-02); the ONE read is the post-write verification.
    assert live.reads == 1


def test_R6_25_restore_threads_the_deadline_and_teardown_still_runs(
        monkeypatch, tmp_path):
    """R6-25: wpt restore ignored --deadline.  A slow source read must end
    rc 1 through the normal error contract (teardown still closes)."""
    import time

    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    source = make_site()
    meta = snap(source, None, "example.com", ["readme.html"], [],
                tmp_path / "bck")

    class _SlowRead(FakeSource):
        def read_bytes(self, path):
            time.sleep(0.15)
            return super().read_bytes(path)

    slow = _SlowRead()
    slow.files = dict(source.files)
    with pytest.raises(DeadlineExceeded, match="deadline"):
        restore.restore_snapshot(meta.path, slow, make_bridge()[0],
                                 dry_run=True, deadline=Deadline(0.05),
                                 expected_site="example.com", expected_webroot="")

    bridge = make_bridge()[0]
    monkeypatch.setattr(restore, "remote_stack",
                        lambda ctx: (slow, FakeSession(), bridge))
    ctx = restore_ctx(tmp_path, backup_dir=tmp_path / "bck", deadline_s=0.05,
                      extra={"snapshot": meta.path.name})
    started = time.monotonic()
    assert restore.run_restore(ctx) == 1
    assert time.monotonic() - started >= 0.1


def test_R9_P2_1_pre_stack_deadline_and_listing_stop_write_a_report(
        monkeypatch, tmp_path):
    """P2-1: the pre-stack deadline check and a listing/identity stop escaped
    run_restore as a traceback and wrote no pair."""
    backup_dir = tmp_path / "bck"
    source = make_site()
    meta = snap(source, None, "example.com", ["readme.html"], [], backup_dir)
    ctx = restore_ctx(
        tmp_path, backup_dir=backup_dir, deadline_s=1e-9,
        report_path=tmp_path / "tiny.md", extra={"snapshot": meta.path.name})

    assert restore.run_restore(ctx) == 1
    written = ctx.report_path.read_text(encoding="utf-8")
    assert "## This run did not complete" in written
    assert "deadline" in written.lower()

    def _stop(*args, **kwargs):
        raise StopRequested("received SIGTERM (15)")

    monkeypatch.setattr(restore, "list_snapshots", _stop)
    stopped = restore_ctx(
        tmp_path, backup_dir=backup_dir, report_path=tmp_path / "stop.md",
        extra={"undo_last": True})
    assert restore.run_restore(stopped) == 1
    assert "## This run did not complete" in stopped.report_path.read_text(
        encoding="utf-8")


def test_R6_27_a_corrupt_newest_snapshot_is_never_skipped_for_an_older_one(
        monkeypatch, tmp_path):
    """R6-27: an unreadable newest manifest was dropped for a label whose
    sanitizer changes it, and --undo-last silently restored an older state.
    Keep every unreadable manifest so the identity gate refuses it."""
    backup_dir = tmp_path / "bck"
    source = FakeSource()
    source.files["wp-content/a.txt"] = b"OLDER-A"
    meta = _round4_snapshot(
        backup_dir, source, label="bücher.example", webroot="public_html",
        targets=["wp-content/a.txt"])
    newer = meta.path.parent / "99991231-000000"
    newer.mkdir()
    (newer / "manifest.json").write_text("not json", encoding="utf-8")

    listed = restore.list_snapshots(backup_dir, "bücher.example",
                                    webroot="public_html")
    assert newer in listed and meta.path in listed
    assert listed[0] == newer

    live = FakeSource()
    live.files["wp-content/a.txt"] = b"LIVE-STATE"
    monkeypatch.setattr(restore, "remote_stack",
                        lambda ctx: (live, FakeSession(), make_bridge()[0]))
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir,
                      wp_url="https://bücher.example",
                      webroot="public_html", apply=True, yes=True,
                      extra={"undo_last": True})
    assert restore.run_restore(ctx) == 1
    assert live.files["wp-content/a.txt"] == b"LIVE-STATE"


def test_R6_36_a_schema_invalid_newest_snapshot_is_refused_not_skipped(
        monkeypatch, tmp_path, wpt_records):
    """R6-36: a newer ``{}`` manifest was silently omitted, so --undo-last
    restored the OLDER valid snapshot.  A manifest that cannot prove a
    DIFFERENT identity stays the newest candidate and is refused."""
    backup_dir = tmp_path / "bck"
    source = FakeSource()
    source.files["wp-content/a.txt"] = b"OLDER-A"
    older = _round4_snapshot(
        backup_dir, source, label="example.com", webroot="public_html",
        targets=["wp-content/a.txt"])

    for suffix, invalid in (("1", "[]"), ("2", "{}")):
        newer = older.path.parent / f"99991231-00000{suffix}"
        newer.mkdir()
        (newer / "manifest.json").write_text(invalid, encoding="utf-8")
        listed = restore.list_snapshots(backup_dir, "example.com",
                                        webroot="public_html")
        assert listed[0] == newer
        assert older.path in listed

    newest = older.path.parent / "99991231-000002"
    live = FakeSource()
    live.files["wp-content/a.txt"] = b"LIVE-STATE"
    built: list[int] = []

    def _stack(ctx):
        built.append(1)
        return live, FakeSession(), make_bridge()[0]

    monkeypatch.setattr(restore, "remote_stack", _stack)
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir,
                      webroot="public_html", apply=True, yes=True,
                      extra={"undo_last": True})
    assert restore.run_restore(ctx) == 1
    assert built == []                       # refused BEFORE any stack/write
    assert live.files["wp-content/a.txt"] == b"LIVE-STATE"
    assert any("not in the current snapshot format" in message
               for message in _errors(wpt_records))

    # an EXPLICIT path to the same invalid snapshot is refused identically
    explicit = restore_ctx(tmp_path, backup_dir=backup_dir,
                           webroot="public_html", apply=True, yes=True,
                           extra={"snapshot": str(newest)})
    assert restore.run_restore(explicit) == 1
    assert built == []
    assert live.files["wp-content/a.txt"] == b"LIVE-STATE"


def test_R6_37_deeply_nested_manifest_is_a_clear_refusal_not_recursion(
        monkeypatch, tmp_path, wpt_records):
    """R6-37: a 40 KB deeply nested JSON manifest raised a raw
    RecursionError out of list_snapshots/run_restore.  The one parser
    converts it to WptError, so every route refuses/keeps a candidate."""
    backup_dir = tmp_path / "bck"
    source = FakeSource()
    source.files["wp-content/a.txt"] = b"OLDER-A"
    older = _round4_snapshot(
        backup_dir, source, label="example.com", webroot="public_html",
        targets=["wp-content/a.txt"])
    newest = older.path.parent / "99991231-000000"
    newest.mkdir()
    nested = ("[" * 20000 + "0" + "]" * 20000).encode("utf-8")
    (newest / "manifest.json").write_bytes(nested)

    with pytest.raises(Exception, match="too deeply nested"):
        backup.read_snapshot_manifest(newest)
    listed = restore.list_snapshots(backup_dir, "example.com",
                                    webroot="public_html")
    assert listed[0] == newest and older.path in listed

    live = FakeSource()
    live.files["wp-content/a.txt"] = b"LIVE-STATE"
    monkeypatch.setattr(restore, "remote_stack",
                        lambda ctx: (live, FakeSession(), make_bridge()[0]))
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir,
                      webroot="public_html", apply=True, yes=True,
                      extra={"undo_last": True})
    assert restore.run_restore(ctx) == 1
    assert live.files["wp-content/a.txt"] == b"LIVE-STATE"
    assert any("too deeply nested" in message
               for message in _errors(wpt_records))

    # list/restore-mode routes do not raise either (list skips the line)
    list_ctx = restore_ctx(tmp_path, backup_dir=backup_dir,
                           webroot="public_html")
    assert restore.run_restore(list_ctx) == 0


def test_R6_38_snapshot_verification_runs_inside_the_restore_deadline(
        monkeypatch, tmp_path, wpt_records):
    """R6-38: verify_snapshot sat outside --deadline; a slow pre-pass ran
    the whole verification.  The budget is now checked between entries and
    an expired run answers rc 1."""
    import time

    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    source = make_site()
    meta = snap(source, None, "example.com", ["readme.html"], [],
                tmp_path / "bck")
    real_read = backup.read_regular_bounded

    def _slow_read(path, limit, label, **kwargs):
        data = real_read(path, limit, label, **kwargs)
        time.sleep(0.06)
        return data

    monkeypatch.setattr(backup, "read_regular_bounded", _slow_read)
    with pytest.raises(DeadlineExceeded, match="snapshot verification"):
        restore.restore_snapshot(meta.path, source, make_bridge()[0],
                                 dry_run=True, deadline=Deadline(0.03),
                                 expected_site="example.com", expected_webroot="")

    monkeypatch.setattr(restore, "remote_stack",
                        lambda ctx: (source, FakeSession(),
                                     make_bridge()[0]))
    ctx = restore_ctx(tmp_path, backup_dir=tmp_path / "bck",
                      deadline_s=0.03, extra={"snapshot": meta.path.name})
    started = time.monotonic()
    assert restore.run_restore(ctx) == 1
    assert time.monotonic() - started < 1.0
    assert any("deadline" in message for message in _errors(wpt_records))


def test_NF1_restore_refuses_a_symlinked_directory_even_with_matching_hash(
        tmp_path):
    """N-F1: a symlinked directory component under files/ redirected a
    restore write outside the snapshot when the manifest hash matched the
    outside bytes.  The rooted, link-free walk refuses verification first."""
    source = make_site()
    source.files["wp-content/a.txt"] = b"ORIGINAL"
    meta = snap(source, None, "example.com", ["wp-content/a.txt"], [],
                tmp_path / "bck")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "a.txt").write_bytes(b"OUTSIDE-EVIL")
    component = meta.path / backup.FILES_DIR / "wp-content"
    component.rename(meta.path / backup.FILES_DIR / "wp-content-real")
    component.symlink_to(outside, target_is_directory=True)

    manifest_path = meta.path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entry = manifest["files"][0]
    entry["sha256"] = hashlib.sha256(b"OUTSIDE-EVIL").hexdigest()
    entry["size"] = len(b"OUTSIDE-EVIL")
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8")

    with pytest.raises(ValueError, match="verification"):
        restore.restore_snapshot(meta.path, source, None,
                                 expected_site="example.com", expected_webroot="")
    assert source.files["wp-content/a.txt"] == b"ORIGINAL"
    assert (outside / "a.txt").read_bytes() == b"OUTSIDE-EVIL"


def test_NF2_equal_length_table_swap_after_verification_never_reaches_the_bridge(
        tmp_path, monkeypatch):
    """N-F2: verify hashed the table stream, then _load_table_rows read it
    again and sent the rows; an equal-length swap after verification put
    PWNED in the bridge payload.  The verified bytes are now retained and
    replayed, so the stream is read exactly once."""
    source = make_site()
    bridge, _ = make_bridge(dump_response(table_lines("wp_posts", POSTS_ROWS)))
    meta = snap(source, bridge, "s", [], ["wp_posts"], tmp_path / "bck")

    stream = meta.path / "db" / "wp_posts.ndjson"
    original = stream.read_bytes()
    swapped = original.replace(b'"hello"', b'"PWNED"')
    assert len(swapped) == len(original) and swapped != original

    real_read = backup.read_regular_bounded
    table_reads: list[str] = []

    def _swap_after_the_verified_read(path, limit, label, **kwargs):
        data = real_read(path, limit, label, **kwargs)
        if str(path).endswith("wp_posts.ndjson"):
            table_reads.append(str(path))
            if len(table_reads) == 1:
                stream.write_bytes(swapped)  # equal length: still "valid"
        return data

    monkeypatch.setattr(backup, "read_regular_bounded",
                        _swap_after_the_verified_read)
    monkeypatch.setattr(restore, "read_regular_bounded",
                        _swap_after_the_verified_read)

    rbridge, rsession = make_bridge(restore_response("wp_posts", 2, True))
    report = restore.restore_snapshot(
        meta.path, source, rbridge, only_tables=["wp_posts"],
        expected_site="s", expected_webroot="")

    assert report.tables_restored == ["wp_posts"]
    assert report.rows_inserted == 2
    assert len(table_reads) == 1  # verified bytes, read exactly once
    assert table_reads[0].endswith("wp_posts.ndjson")
    assert len(rsession.posts) == 1
    params = rsession.posts[0][1]["json"]["params"]
    assert params["rows"] == POSTS_ROWS
    assert "PWNED" not in json.dumps(params)
    assert stream.read_bytes() == swapped  # the swap really happened


def test_NG1_manifest_swap_after_verification_never_selects_m2_entries(
        tmp_path, monkeypatch):
    """N-G1: restore verified M1, then re-read manifest.json into M2 and used
    M2 for selection and every write hash.  An M2-only table/file/absent
    entry was never verified yet reached the bridge and the live source.
    The manifest is now read ONCE and the verified object is retained."""
    source = make_site()
    source.files["wp-content/a.txt"] = b"ORIGINAL"
    bridge, _ = make_bridge(dump_response(table_lines("wp_posts", POSTS_ROWS)))
    meta = snap(source, bridge, "example.com", ["wp-content/a.txt"],
                ["wp_posts"], tmp_path / "bck")
    source.files["wp-content/a.txt"] = b"CHANGED"
    source.files["wp-content/live-only.txt"] = b"LIVE"

    manifest_path = meta.path / "manifest.json"
    m1_raw = manifest_path.read_bytes()
    m2 = json.loads(m1_raw)
    evil_bytes = (
        "\n".join(table_lines("evil", [["PWNED"]])) + "\n").encode("utf-8")
    (meta.path / backup.DB_DIR / "evil.ndjson").write_bytes(evil_bytes)
    evil_file = b"PWNED-FILE"
    (meta.path / backup.FILES_DIR / "wp-content" / "evil.txt").write_bytes(
        evil_file)
    m2["files"].append({
        "path": "wp-content/evil.txt", "absent": False,
        "sha256": hashlib.sha256(evil_file).hexdigest(),
        "size": len(evil_file),
    })
    m2["files"].append({
        "path": "wp-content/live-only.txt", "absent": True,
    })
    m2["tables"].append({
        "name": "evil", "rows": 1,
        "sha256": hashlib.sha256(evil_bytes).hexdigest(),
        "size": len(evil_bytes),
    })
    m2_raw = (json.dumps(m2, indent=2, ensure_ascii=True) + "\n").encode()

    real_manifest_read = backup.read_snapshot_manifest
    manifest_reads: list[dict] = []

    def _read_then_swap(snapshot_dir):
        manifest = real_manifest_read(snapshot_dir)
        manifest_reads.append(manifest)
        if len(manifest_reads) == 1:
            manifest_path.write_bytes(m2_raw)  # M2 lands after M1's read
        return manifest

    monkeypatch.setattr(backup, "read_snapshot_manifest", _read_then_swap)
    monkeypatch.setattr(restore, "read_snapshot_manifest", _read_then_swap)

    rbridge, rsession = make_bridge([
        restore_response("wp_posts", 2, True),
        restore_response("evil", 1, True),
    ])
    report = restore.restore_snapshot(meta.path, source, rbridge,
                                      expected_site="example.com", expected_webroot="")

    assert report.tables_restored == ["wp_posts"]
    assert report.rows_inserted == 2
    assert report.files_restored == 1
    assert report.files_deleted == 0
    assert source.files["wp-content/a.txt"] == b"ORIGINAL"
    assert "wp-content/evil.txt" not in source.files
    assert source.files["wp-content/live-only.txt"] == b"LIVE"
    assert len(rsession.posts) == 1
    wire = json.dumps([post[1]["json"] for post in rsession.posts])
    assert "PWNED" not in wire
    assert len(manifest_reads) == 1  # the verified object is the only read
    assert manifest_path.read_bytes() == m2_raw  # the swap really happened


def test_NG3_identity_swapped_after_the_pre_stack_gate_is_refused(
        tmp_path, monkeypatch, wpt_records):
    """N-G3: the pre-stack gate checked snapshot A, then a writer replaced
    A's manifest+payload with B's (``other.example``) during remote setup.
    ``restore_snapshot`` compared the manifest's own ``site_raw``/``webroot``
    to itself and restored B into the live source.  The expected identity
    resolved before the stack is now re-checked against the ONE verified
    manifest, before any file/table work."""
    backup_dir = tmp_path / "bck"
    a_source = FakeSource()
    a_source.files["wp-content/a.txt"] = b"A-ORIGINAL"
    a = _round4_snapshot(
        backup_dir, a_source, label="example.com", webroot="public_html",
        targets=["wp-content/a.txt"])
    b_source = FakeSource()
    b_source.files["wp-content/a.txt"] = b"OTHER-SITE"
    b_bridge, _ = make_bridge(dump_response(
        table_lines("wp_posts", [["9", "OTHER-ROW"]])))
    b = backup.create_snapshot(
        b_source, b_bridge, "other.example", ["wp-content/a.txt"],
        ["wp_posts"], backup_dir, BackupSettings(), "clean-files",
        site_raw="other.example", webroot="public_html")

    # A is selected and passes the pre-stack identity gate for this run.
    assert restore.list_snapshots(
        backup_dir, "example.com", webroot="public_html") == [a.path]

    live = FakeSource()
    live.files["wp-content/a.txt"] = b"LIVE"
    bridge = RecordingBridge()

    def _swap_then_stack(ctx):
        # The exact window: replace A's inputs with B's internally
        # consistent manifest + payload after the gate, before verification.
        (a.path / "manifest.json").write_bytes(
            (b.path / "manifest.json").read_bytes())
        (a.path / backup.FILES_DIR / "wp-content" / "a.txt").write_bytes(
            b"OTHER-SITE")
        (a.path / backup.DB_DIR).mkdir(exist_ok=True)
        (a.path / backup.DB_DIR / "wp_posts.ndjson").write_bytes(
            (b.path / backup.DB_DIR / "wp_posts.ndjson").read_bytes())
        return live, FakeSession(), bridge

    monkeypatch.setattr(restore, "remote_stack", _swap_then_stack)
    ctx = restore_ctx(
        tmp_path, backup_dir=backup_dir, wp_url="https://example.com",
        webroot="public_html", apply=True, yes=True,
        extra={"undo_last": True})

    assert restore.run_restore(ctx) == 1
    assert live.files["wp-content/a.txt"] == b"LIVE"
    assert bridge.calls == []  # no bridge/file/table work after the refusal
    assert bridge.destroyed == 1
    assert any("belongs to site" in message and "other.example" in message
               for message in _errors(wpt_records))
    swapped = json.loads((a.path / "manifest.json").read_text(encoding="utf-8"))
    assert swapped["site_raw"] == "other.example"  # the swap really happened


def test_NG3_expected_identity_comparison_is_exact(tmp_path):
    """The post-verification binding compares raw values: a normalized
    webroot spelling and a different raw site are both refused before the
    file plan, while the exact expected identity still restores."""
    backup_dir = tmp_path / "bck"
    source = FakeSource()
    source.files["wp-content/a.txt"] = b"A-ORIGINAL"
    meta = _round4_snapshot(
        backup_dir, source, label="example.com", webroot="public_html",
        targets=["wp-content/a.txt"])

    with pytest.raises(ValueError, match="belongs to site"):
        restore.restore_snapshot(
            meta.path, FakeSource(), None,
            expected_site="other.example", expected_webroot="public_html")
    with pytest.raises(ValueError, match="webroot"):
        restore.restore_snapshot(
            meta.path, FakeSource(), None,
            expected_site="example.com", expected_webroot="/public_html/")

    report = restore.restore_snapshot(
        meta.path, FakeSource(), None,
        expected_site="example.com", expected_webroot="public_html")
    assert report.files_restored == 1


def test_R18_restore_prefix_is_a_directory_boundary_not_a_string_prefix(
        tmp_path):
    """R18-P2: ``--path-prefix wp-content/uploads`` also restored
    ``wp-content/uploads-old/``.  The selector is a subtree: the prefix
    itself or ``prefix + "/"``, never a sibling sharing the spelling."""
    backup_dir = tmp_path / "bck"
    source = FakeSource()
    source.files["wp-content/uploads/a.jpg"] = b"UPLOAD"
    source.files["wp-content/uploads-old/b.jpg"] = b"SIBLING"
    meta = _round4_snapshot(
        backup_dir, source, label="example.com", webroot="public_html",
        targets=["wp-content/uploads/a.jpg", "wp-content/uploads-old/b.jpg"])

    target = FakeSource()
    target.files["wp-content/uploads/a.jpg"] = b"UPLOAD-OLD"
    target.files["wp-content/uploads-old/b.jpg"] = b"SIBLING-OLD"
    report = restore.restore_snapshot(
        meta.path, target, None,
        expected_site="example.com", expected_webroot="public_html",
        file_prefix="wp-content/uploads")
    assert report.files_restored == 1
    assert target.files["wp-content/uploads/a.jpg"] == b"UPLOAD"
    assert target.files["wp-content/uploads-old/b.jpg"] == b"SIBLING-OLD"

    # The trailing-slash spelling is the SAME selection, normalized once.
    target2 = FakeSource()
    target2.files["wp-content/uploads/a.jpg"] = b"UPLOAD-OLD"
    target2.files["wp-content/uploads-old/b.jpg"] = b"SIBLING-OLD"
    report2 = restore.restore_snapshot(
        meta.path, target2, None,
        expected_site="example.com", expected_webroot="public_html",
        file_prefix="wp-content/uploads/")
    assert report2.files_restored == 1
    assert target2.files["wp-content/uploads-old/b.jpg"] == b"SIBLING-OLD"


def test_R18_managed_selection_uses_the_exact_webroot_gate(monkeypatch,
                                                           tmp_path):
    """R18-P2: ``list_snapshots``/``_identity_problem`` normalized the
    webroot, selected a newer ``/public_html/`` snapshot, and the exact
    verified-manifest gate then refused it — hiding the older exact
    snapshot.  Selection now agrees with the gate and falls back."""
    import datetime

    import wpt.backup as backup

    fixed = datetime.datetime(2026, 10, 20, 12, 0, 0).astimezone()
    monkeypatch.setattr(backup, "_now", lambda: fixed)
    backup_dir = tmp_path / "bck"
    source = FakeSource()
    source.files["a.txt"] = b"OLD-EXACT"
    older = _round4_snapshot(
        backup_dir, source, label="example.com", webroot="public_html",
        targets=["a.txt"])
    source.files["a.txt"] = b"NEW-NORMALIZED"
    newer = _round4_snapshot(
        backup_dir, source, label="example.com", webroot="/public_html/",
        targets=["a.txt"])
    assert newer.path != older.path

    listed = restore.list_snapshots(backup_dir, "example.com",
                                    webroot="public_html")
    assert listed == [older.path]
    assert newer.path not in listed

    monkeypatch.setattr(
        restore, "remote_stack",
        lambda ctx: (target, FakeSession(), RecordingBridge()))
    target = FakeSource()
    target.files["a.txt"] = b"LIVE"
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir, webroot="public_html",
                      apply=True, yes=True, extra={"undo_last": True})
    assert restore.run_restore(ctx) == 0
    assert target.files["a.txt"] == b"OLD-EXACT"


def test_NG4_expected_identity_is_required_for_direct_calls(tmp_path):
    """N-G4: both expected identity values are REQUIRED keyword-only
    arguments with no default, so a direct caller can never fall back to
    the shape-only self-comparison.  Omitting either is a TypeError; an
    explicit wrong-shaped value is still refused by the runtime validator.
    """
    backup_dir = tmp_path / "bck"
    source = FakeSource()
    source.files["wp-content/a.txt"] = b"A-ORIGINAL"
    meta = _round4_snapshot(
        backup_dir, source, label="example.com", webroot="public_html",
        targets=["wp-content/a.txt"])
    live = FakeSource()

    with pytest.raises(TypeError):
        restore.restore_snapshot(meta.path, live, None)
    with pytest.raises(TypeError):
        restore.restore_snapshot(
            meta.path, live, None, expected_site="example.com")
    with pytest.raises(TypeError):
        restore.restore_snapshot(
            meta.path, live, None, expected_webroot="public_html")
    with pytest.raises(ValueError, match="non-empty string"):
        restore.restore_snapshot(
            meta.path, live, None,
            expected_site=None, expected_webroot="public_html")
    assert "wp-content/a.txt" not in live.files  # no write on any refusal


def test_NG4_direct_call_cannot_restore_a_swapped_identity_snapshot(tmp_path):
    """N-G4: a direct caller resolved/checked identity A, then a writer
    replaced A's manifest and payload with B's.  Because the identity
    arguments are mandatory, the engine still refuses B before the file
    plan/table pre-pass instead of shape-checking B against itself and
    writing another site's bytes."""
    backup_dir = tmp_path / "bck"
    a_source = FakeSource()
    a_source.files["wp-content/a.txt"] = b"A-ORIGINAL"
    a = _round4_snapshot(
        backup_dir, a_source, label="example.com", webroot="public_html",
        targets=["wp-content/a.txt"])
    b_source = FakeSource()
    b_source.files["wp-content/a.txt"] = b"OTHER-SITE"
    b_bridge, _ = make_bridge(dump_response(
        table_lines("wp_posts", [["9", "OTHER-ROW"]])))
    b = backup.create_snapshot(
        b_source, b_bridge, "other.example", ["wp-content/a.txt"],
        ["wp_posts"], backup_dir, BackupSettings(), "clean-files",
        site_raw="other.example", webroot="public_html")

    # The direct caller resolved identity A before the snapshot was swapped.
    assert backup.verify_snapshot(a.path) is True
    (a.path / "manifest.json").write_bytes(
        (b.path / "manifest.json").read_bytes())
    (a.path / backup.FILES_DIR / "wp-content" / "a.txt").write_bytes(
        b"OTHER-SITE")
    (a.path / backup.DB_DIR).mkdir(exist_ok=True)
    (a.path / backup.DB_DIR / "wp_posts.ndjson").write_bytes(
        (b.path / backup.DB_DIR / "wp_posts.ndjson").read_bytes())
    assert backup.verify_snapshot(a.path) is True  # B is internally consistent

    live = FakeSource()
    live.files["wp-content/a.txt"] = b"LIVE"
    bridge = RecordingBridge()
    with pytest.raises(ValueError, match="belongs to site 'other.example'"):
        restore.restore_snapshot(
            a.path, live, bridge,
            expected_site="example.com", expected_webroot="public_html")

    assert live.files["wp-content/a.txt"] == b"LIVE"
    assert bridge.calls == []  # no file/table work after the refusal
    swapped = json.loads((a.path / "manifest.json").read_text(encoding="utf-8"))
    assert swapped["site_raw"] == "other.example"  # the swap really happened


# ------------------------------------------------- triple-check round 7


def test_R7_P2_02_restore_does_not_read_a_grown_live_file(tmp_path):
    source = make_site()
    meta = snap(source, None, "example.com", ["readme.html"], [],
                tmp_path / "bck")

    class _Tracking(FakeSource):
        def __init__(self):
            super().__init__()
            self.files = {"readme.html": b"L" * (8 * 1024 * 1024)}
            self.reads = 0
            self.bounded = []

        def read_bytes(self, path):
            self.reads += 1
            return super().read_bytes(path)

        def read_bytes_bounded(self, path, max_bytes):
            self.bounded.append(max_bytes)
            return super().read_bytes_bounded(path, max_bytes)

    live = _Tracking()
    report = restore.restore_snapshot(
        meta.path, live, None, expected_site="example.com",
        expected_webroot="")
    assert report.files_restored == 1
    assert live.files["readme.html"] == b"readme"
    # Size differs from the manifest: no PLANNING read; the one read is
    # the mandatory post-write verification.
    assert live.reads == 1 and live.bounded == [6]


def test_R7_P2_02_equal_size_live_file_uses_the_bounded_reader(tmp_path):
    source = make_site()
    meta = snap(source, None, "example.com", ["readme.html"], [],
                tmp_path / "bck")

    class _Tracking(FakeSource):
        def __init__(self):
            super().__init__()
            self.files = {"readme.html": b"REPLAC"[:6]}
            self.bounded = []

        def read_bytes(self, path):  # pragma: no cover - must not be used
            raise AssertionError("unbounded read")

        def read_bytes_bounded(self, path, max_bytes):
            self.bounded.append(max_bytes)
            data = self.files[path]
            assert len(data) <= max_bytes
            return data

    live = _Tracking()
    report = restore.restore_snapshot(
        meta.path, live, None, expected_site="example.com",
        expected_webroot="")
    assert report.files_restored == 1
    # plan equality read + the post-write verification read
    assert live.bounded == [6, 6]


@pytest.mark.parametrize("prefix", [
    "wp-content/uploads/",
    "wp-content\\uploads\\",
])
def test_R7_P2_03_backslash_prefix_is_normalized_and_selects(tmp_path, prefix):
    source = make_site()
    source.files["wp-content/uploads/2021/02/b.jpg"] = b"b"
    meta = snap(source, None, "example.com", [
        "wp-content/uploads/2020/01/a.jpg",
        "wp-content/uploads/2021/02/b.jpg",
        "readme.html",
    ], [], tmp_path / "bck")
    source.files["wp-content/uploads/2020/01/a.jpg"] = b"changed"
    source.files["wp-content/uploads/2021/02/b.jpg"] = b"other"
    report = restore.restore_snapshot(
        meta.path, source, None, file_prefix=prefix, dry_run=True,
        expected_site="example.com", expected_webroot="")
    assert report.files_restored == 2


@pytest.mark.parametrize("prefix", [
    "wp-content/uploads\x00",
    "wp-content/uploads\n",
    "wp-content/uploads\x7f",
    # R25-P2: lone surrogates can never be a manifest path (the source's
    # guard refuses them), so accepting the prefix made the CLI exit 0
    # after restoring zero files.
    "wp-content/uploads/\ud800",
    "wp-content/uploads/\udcff",
])
def test_R7_P2_03_control_characters_are_refused(prefix):
    with pytest.raises(ValueError, match="invalid file_prefix"):
        restore._validate_prefix(prefix)


@pytest.mark.parametrize("prefix", [
    "wp-content/uploads ",
    "wp-content/uploads.",
    "wp-content/uploads. ",
    "wp-content/uploads /2020",
    " wp-content/uploads",
])
def test_R23_prefix_trailing_dot_or_space_is_refused(prefix):
    """R23-P2: a trailing dot/space segment is a Windows filename alias and
    never matches a manifest path (``_guard_path`` refuses it), so the old
    validator accepted a prefix that silently restored zero files.  Leading
    spaces stay legal."""
    if prefix == " wp-content/uploads":
        assert restore._validate_prefix(prefix) == " wp-content/uploads"
        return
    with pytest.raises(ValueError, match="invalid file_prefix"):
        restore._validate_prefix(prefix)


def test_R7_P2_04_unreadable_backup_dir_is_a_one_line_failure(
        monkeypatch, tmp_path, wpt_records):
    def broken(*args, **kwargs):
        raise PermissionError("permission denied")

    monkeypatch.setattr(restore, "list_snapshots", broken)
    ctx = restore_ctx(tmp_path, backup_dir=tmp_path / "unreadable",
                      extra={})
    assert restore.run_restore(ctx) == 1
    assert any("restore failed" in line and "permission denied" in line
               for line in _errors(wpt_records))

    monkeypatch.setattr(restore, "list_snapshots", broken)
    undo = restore_ctx(tmp_path, backup_dir=tmp_path / "unreadable",
                       extra={"undo_last": True})
    assert restore.run_restore(undo) == 1


def test_R7_P2_06_restore_refuses_a_json_report_path(
        monkeypatch, tmp_path, wpt_records):
    source = make_site()
    backup_dir = tmp_path / "bck"
    meta = snap(source, None, "example.com", ["readme.html"], [], backup_dir)
    session = FakeSession()
    monkeypatch.setattr(
        restore, "remote_stack",
        lambda ctx: (source, session, make_bridge()[0]))
    report = tmp_path / "restore.json"
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir, report_path=report,
                      extra={"snapshot": meta.path.name})
    assert restore.run_restore(ctx) == 1
    assert not report.exists()
    assert any("refusing a .json report path" in line
               for line in _errors(wpt_records))


def test_R7_P1_03_restore_treats_a_proven_missing_parent_as_absent(
        tmp_path):
    """R7-P1-03: both restore branches called ``source.exists`` raw, so the
    FTP ``SourceLookupError`` from a missing directory aborted a dry run
    even though the grandparent listing proved the path absent."""
    from tests.fakes import LookupFailingSource

    source = FakeSource()
    source.files["newdir/a.txt"] = b"content"
    meta = snap(source, None, "example.com", ["newdir/a.txt"], [],
                tmp_path / "bck")

    live = LookupFailingSource()
    live.files["readme.html"] = b"readme"
    report = restore.restore_snapshot(
        meta.path, live, None, dry_run=True,
        expected_site="example.com", expected_webroot="")
    assert report.files_restored == 1

    absent = FakeSource()
    meta2 = snap(absent, None, "example.com", ["gone/b.txt"], [],
                 tmp_path / "bck2")
    live2 = LookupFailingSource()
    report2 = restore.restore_snapshot(
        meta2.path, live2, None, dry_run=True,
        expected_site="example.com", expected_webroot="")
    assert report2.files_absent_kept == 1


# ------------------------------------------------------- round-8 regressions


def test_R8_P2_10_ndjson_splits_on_newline_only(tmp_path):
    """R8-P2-10: ``str.splitlines`` also splits on U+2028/U+0085, so a
    verified table whose JSON string cell contains one was unrestorable."""
    backup_dir = tmp_path / "bck"
    source = _live_source()
    meta = _snapshot(backup_dir, source)
    rows = [
        json.dumps({"table": "wp_posts", "create": "CREATE TABLE `x` (id int)"},
                   ensure_ascii=False),
        json.dumps({"table": "wp_posts", "row": ["1", "a\u2028b\u0085c"]},
                   ensure_ascii=False),
        json.dumps({"table": "wp_posts", "row": ["2", "d\u2028e"]},
                   ensure_ascii=False),
        json.dumps({"table": "wp_posts", "done": 2}),
    ]
    tamper_table_stream(meta, "wp_posts", lambda _lines: rows)

    report = restore.restore_snapshot(
        meta.path, source, RecordingBridge(), dry_run=True,
        expected_site="example.com", expected_webroot="")
    assert report.rows_inserted == 2
    assert restore._load_table_rows(
        meta.path, next(e for e in restore.read_snapshot_manifest(meta.path)["tables"]
                        if e["name"] == "wp_posts"), None) == [
        ["1", "a\u2028b\u0085c"], ["2", "d\u2028e"]]


@pytest.mark.parametrize("literal, fragment", [
    ("NaN", "malformed JSON"),
    ("Infinity", "malformed JSON"),
    ("-Infinity", "malformed JSON"),
    ("1e999", "non-finite"),
])
def test_R15_non_finite_numbers_are_refused_in_the_restore_pre_pass(
        tmp_path, literal, fragment):
    """R15-P2: a tampered snapshot with NaN/Infinity passed ``verify_snapshot``
    and the dry-run pre-pass, then the bridge request failed after earlier
    tables could have been swapped.  The grammar (and the strict parser)
    refuses before any bridge call."""
    backup_dir = tmp_path / "bck"
    source = _live_source()
    meta = _snapshot(backup_dir, source)
    rows = [
        json.dumps({"table": "wp_posts",
                    "create": "CREATE TABLE `x` (v double)"}),
        '{"table": "wp_posts", "row": [' + literal + "]}",
        json.dumps({"table": "wp_posts", "done": 1}),
    ]
    tamper_table_stream(meta, "wp_posts", lambda _lines: rows)
    assert backup.verify_snapshot(meta.path) is True
    with pytest.raises(ValueError, match=fragment):
        restore.restore_snapshot(
            meta.path, source, RecordingBridge(), dry_run=True,
            expected_site="example.com", expected_webroot="")


def test_R8_P2_11_deep_table_json_is_a_value_error_not_recursion(tmp_path):
    """R8-P2-11: a deeply nested row escaped ``run_restore`` as a raw
    RecursionError; it is the same malformed-JSON verdict as any bad line."""
    backup_dir = tmp_path / "bck"
    source = _live_source()
    meta = _snapshot(backup_dir, source)
    nested = "[" * 10_000 + "0" + "]" * 10_000
    rows = [
        json.dumps({"table": "wp_posts", "create": "CREATE TABLE `x` (id int)"}),
        '{"table": "wp_posts", "row": ' + nested + "}",
        json.dumps({"table": "wp_posts", "done": 1}),
    ]
    tamper_table_stream(meta, "wp_posts", lambda _lines: rows)

    with pytest.raises(ValueError, match="malformed JSON"):
        restore.restore_snapshot(
            meta.path, source, RecordingBridge(), dry_run=True,
            expected_site="example.com", expected_webroot="")


def test_R8_P2_12_restore_verifies_the_live_bytes_after_each_write(tmp_path):
    """R8-P2-12: the write was never re-read, so a corrupting store reported
    ``files_restored`` for bytes that never landed."""
    class _CorruptingSource(CloseRecordingSource):
        def write_bytes(self, path, data, *, allow_config=False,
                        allow_core=False):
            super().write_bytes(path, data, allow_config=allow_config,
                                allow_core=allow_core)
            self.files[path] = b"X" * len(data)

    backup_dir = tmp_path / "bck"
    live = _live_source()
    meta = _snapshot(backup_dir, live, tables=())
    source = _CorruptingSource()
    source.files = dict(live.files)
    source.files["readme.html"] = b"changed live"

    with pytest.raises(SourceError, match="live bytes do not match"):
        restore.restore_snapshot(
            meta.path, source, None, dry_run=False,
            expected_site="example.com", expected_webroot="")
    assert source.files["readme.html"] == b"X" * len(b"readme")


def test_R8_P2_14_list_mode_writes_the_report_pair(
        monkeypatch, tmp_path, capsys):
    """R8-P2-14: list mode printed the listing and ignored ``--report``."""
    backup_dir = tmp_path / "bck"
    source = _live_source()
    _snapshot(backup_dir, source, tables=())
    monkeypatch.setattr(restore, "remote_stack", _no_stack)
    report_path = tmp_path / "list.md"
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir,
                      report_path=report_path)

    assert restore.run_restore(ctx) == 0
    assert "example.com" in capsys.readouterr().out
    markdown = report_path.read_text(encoding="utf-8")
    assert markdown.startswith("# wpt restore — example.com")
    payload = json.loads(report_path.with_suffix(".json").read_text(
        encoding="utf-8"))
    assert set(payload) == {"site", "snapshots", "total"}
    assert payload["site"] == "example.com"
    assert payload["total"] == 1


def test_R8_P2_16_restore_teardown_stop_replaces_the_success_report(
        monkeypatch, tmp_path):
    """R8-P2-16: a stop during close left a success report beside rc 1."""
    backup_dir = tmp_path / "bck"
    source = _StopOnCloseSource()
    source.files = {"readme.html": b"readme"}
    meta = _snapshot(backup_dir, source, tables=())
    monkeypatch.setattr(
        restore, "remote_stack",
        lambda ctx: (source, FakeSession(), RecordingBridge()))
    report_path = tmp_path / "restore.md"
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir,
                      report_path=report_path,
                      extra={"snapshot": meta.path.name})

    assert restore.run_restore(ctx) == 1
    markdown = report_path.read_text(encoding="utf-8")
    assert "This run did not complete" in markdown
    assert "Dry-run restore" not in markdown
    twin = json.loads(report_path.with_suffix(".json").read_text(
        encoding="utf-8"))
    assert twin["run"]["status"] == "failed"


def test_R8_P2_17_restore_closes_the_http_session(monkeypatch, tmp_path):
    """R8-P2-17: restore ignored the session, leaking its connection pool."""
    class _CloseRecordingSession(FakeSession):
        def __init__(self):
            super().__init__()
            self.closed = 0

        def close(self):
            self.closed += 1

    backup_dir = tmp_path / "bck"
    source = _live_source()
    meta = _snapshot(backup_dir, source, tables=())
    session = _CloseRecordingSession()
    monkeypatch.setattr(
        restore, "remote_stack",
        lambda ctx: (source, session, RecordingBridge()))
    ctx = restore_ctx(tmp_path, backup_dir=backup_dir,
                      extra={"snapshot": meta.path.name})

    assert restore.run_restore(ctx) == 0
    assert session.closed == 1


@pytest.mark.parametrize("path", [".HTACCESS", "WP-CONFIG.PHP"])
def test_R14_config_restore_unlocks_casefolded_names(tmp_path, path):
    """R14-P2: the restore plan passed ``path in Source.PROTECTED``
    (case-sensitive) while the guard compares ``PROTECTED_FOLDED``.  A
    snapshot from a case-insensitive host could not restore its config
    (present write) or delete the file it recorded absent."""
    source = FakeSource()
    source.files[path] = b"CONFIG-BYTES"
    bridge, _ = make_bridge()
    meta = snap(source, bridge, "s", [path], [], tmp_path / "bck")

    # PRESENT: the live file is tampered, the snapshot must write it back.
    source.files[path] = b"tampered"
    report = restore.restore_snapshot(
        meta.path, source, make_bridge()[0],
        expected_site="s", expected_webroot="")
    assert report.files_restored == 1
    assert source.files[path] == b"CONFIG-BYTES"

    # ABSENT: the snapshot records the file missing; the live file must be
    # deleted with the audited config unlock.
    absent_source = FakeSource()
    absent_source.files["readme.html"] = b"x"
    bridge2, _ = make_bridge()
    absent_meta = snap(absent_source, bridge2, "s", [path], [],
                       tmp_path / "bck2")
    live = FakeSource()
    live.files[path] = b"created-after-snapshot"
    absent = restore.restore_snapshot(
        absent_meta.path, live, make_bridge()[0],
        expected_site="s", expected_webroot="")
    assert absent.files_deleted == 1
    assert path not in live.files
