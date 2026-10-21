"""Tests for wpt/backup.py — snapshots over FakeSource and a REAL Bridge wired
to FakeSession/FakeResponse (scripted db_dump NDJSON, bytes cells via the
["__wpt_b64__", ...] marker), plus fail-closed cleanup, collision suffixing,
verify, and retention; batched read_many capture (200-path chunks, split
ok/failed buckets) and the run-deadline fail-closed trips. Deterministic:
no network, no sleeps; the snapshot clock (wpt.backup._now) is pinned
wherever ordering matters; expired budgets use Deadline's monotonic span
(the test_deadline.py simulated-elapsed pattern).
"""

import base64
import hashlib
import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import requests

import wpt.backup as backup
from tests.fakes import FakeResponse, FakeSession, FakeSource
from wpt.cli import Ctx
from wpt.deadline import Deadline
from wpt.report import human_bytes
from wpt.settings import BackupSettings, BridgeSettings, load
from wpt.types import (BridgeError, DeadlineExceeded, SourceError, WptError)
from wpt.wpbridge.client import Bridge

WEBROOT = "domains/example.com/public_html"
SITE = "https://example.com"
BLOB = b"\x00\xffbin"
BLOB_B64 = base64.b64encode(BLOB).decode()


# ------------------------------------------------------------------ helpers


def make_bridge(script_item):
    """A real Bridge over FakeSource+FakeSession with one scripted item."""
    session = FakeSession([script_item])
    return Bridge(FakeSource(), session, WEBROOT, BridgeSettings(), SITE)


def table_lines(table, rows, create="CREATE TABLE `x` (id bigint)"):
    """Scripted db_dump NDJSON for one table: create, rows, done."""
    lines = [json.dumps({"table": table, "create": create})]
    for row in rows:
        lines.append(json.dumps({"table": table, "row": row}))
    lines.append(json.dumps({"table": table, "done": len(rows)}))
    return lines


def dump_response(lines):
    return FakeResponse(200, lines=lines)


def snap(source, bridge, label, targets, tables, backup_dir,
         action="clean-files", settings=None, deadline=None,
         webroot=WEBROOT):
    return backup.create_snapshot(
        source, bridge, label, targets, tables, backup_dir,
        settings or BackupSettings(), action, deadline,
        site_raw=label, webroot=webroot,
    )


def manifest_of(meta):
    return json.loads((meta.path / "manifest.json").read_text(encoding="utf-8"))


def mk_snap_dir(site_dir, name, *, site_raw="s", webroot=""):
    directory = site_dir / name
    directory.mkdir(parents=True)
    (directory / "manifest.json").write_text(
        json.dumps({"site_raw": site_raw, "webroot": webroot}))
    return directory


class BoomSource(FakeSource):
    """FakeSource whose read_many RAISES at the run level on its second
    call (channel-trip semantics: a read_many raise is run-level and
    fails the whole snapshot closed — never a per-file skip)."""

    def __init__(self):
        super().__init__()
        self.read_calls = 0

    def read_many(self, paths, *, max_bytes=None):
        self.read_calls += 1
        if self.read_calls >= 2:
            raise SourceError("ftp channel dead mid-capture")
        return {p: self.files[p] for p in paths}, {}


class BatchSource(FakeSource):
    """FakeSource with an EXPLICIT read_many double (the committed
    Source.read_many contract): per-path failures land in ``failed``,
    every call's size is recorded — the batching-observability double
    for create_snapshot's capture loop."""

    def __init__(self, fail=()):
        super().__init__()
        self._fail = set(fail)
        self.read_calls: list[int] = []

    def read_many(self, paths, *, max_bytes=None):
        self.read_calls.append(len(paths))
        ok: dict[str, bytes] = {}
        failed: dict[str, str] = {}
        for path in paths:
            if path in self._fail:
                failed[path] = f"read failed: {path}"
            else:
                ok[path] = self.files[path]
        return ok, failed


class ExplodingResponse(FakeResponse):
    """FakeResponse whose iter_lines dies mid-stream after the first line."""

    def iter_lines(self, chunk_size=512, decode_unicode=False, delimiter=None):
        yield from self._lines[:1]
        raise requests.ConnectionError("stream reset mid-dump")


# ------------------------------------------------------------- happy path


def test_happy_path_files_tables_manifest_and_b64_roundtrip(tmp_path):
    source = FakeSource()
    cfg = b"<?php define('DB_NAME', 'db');"
    source.files["wp-config.php"] = cfg
    source.files["wp-content/uploads/2020/01/a.jpg"] = BLOB
    rows = [["1", "hello"], ["2", ["__wpt_b64__", BLOB_B64]]]
    bridge = make_bridge(dump_response(table_lines("wp_posts", rows)))

    meta = snap(source, bridge, "example.com",
                ["wp-content/uploads/2020/01/a.jpg", "wp-config.php",
                 "missing.txt"],
                ["wp_posts"], tmp_path / ".wpt-backup")

    site_dir = tmp_path / ".wpt-backup" / "example.com"
    assert meta.path.parent == site_dir
    assert re.fullmatch(r"\d{8}-\d{6}(-\d+)?", meta.path.name)
    assert meta.files == 2 and meta.tables == 1

    # captured bytes on disk, hierarchy preserved
    assert (meta.path / "files/wp-config.php").read_bytes() == cfg
    assert (meta.path / "files/wp-content/uploads/2020/01/a.jpg").read_bytes() == BLOB

    manifest = manifest_of(meta)
    assert manifest["format"] == "wpt-backup-manifest"
    assert manifest["version"] == 1
    assert manifest["site"] == "example.com"
    assert manifest["action"] == "clean-files"
    assert isinstance(manifest["wpt_version"], str) and manifest["wpt_version"]
    datetime.fromisoformat(manifest["created"])  # ISO 8601, parses

    files = manifest["files"]
    assert [e["path"] for e in files] == [
        "wp-content/uploads/2020/01/a.jpg", "wp-config.php", "missing.txt",
    ]
    assert files[0]["sha256"] == hashlib.sha256(BLOB).hexdigest()
    assert files[0]["size"] == len(BLOB) and files[0]["absent"] is False
    assert files[1]["sha256"] == hashlib.sha256(cfg).hexdigest()
    assert files[2] == {"path": "missing.txt", "absent": True}

    ndjson = (meta.path / "db/wp_posts.ndjson").read_bytes()
    tables = manifest["tables"]
    assert tables == [{
        "name": "wp_posts", "rows": 2,
        "sha256": hashlib.sha256(ndjson).hexdigest(), "size": len(ndjson),
    }]

    # NDJSON disk rule: create / row* / done, bytes cells re-marked b64
    lines = ndjson.decode("utf-8").splitlines()
    assert len(lines) == 4
    assert json.loads(lines[0]) == {
        "table": "wp_posts", "create": "CREATE TABLE `x` (id bigint)",
    }
    assert json.loads(lines[1]) == {"table": "wp_posts", "row": ["1", "hello"]}
    row2 = json.loads(lines[2])
    assert row2 == {"table": "wp_posts",
                    "row": ["2", ["__wpt_b64__", BLOB_B64]]}
    assert base64.b64decode(row2["row"][1][1]) == BLOB  # marker round-trips
    assert json.loads(lines[3]) == {"table": "wp_posts", "done": 2}

    assert manifest["totals"] == {"files": 2, "absent": 1, "tables": 1,
                                   "bytes": len(BLOB) + len(cfg) + len(ndjson)}
    assert meta.bytes_written == manifest["totals"]["bytes"]
    assert backup.verify_snapshot(meta.path) is True


def test_site_label_sanitized_to_path_safe_component(tmp_path):
    source = FakeSource()
    source.files["a.txt"] = b"x"
    backup_dir = tmp_path / "bck"
    meta = snap(source, None, "local:dump/../we ird", ["a.txt"], [], backup_dir)
    assert meta.path.parent.name == "local-dump-..-we-ird"
    assert manifest_of(meta)["site"] == "local-dump-..-we-ird"

    # "", ".", ".." are the only regex-unchanged unsafe components;
    # create_snapshot rejects the empty label outright (caller bug)
    assert backup.sanitize_site_label("") == "-"
    with pytest.raises(ValueError):
        snap(source, None, "", ["a.txt"], [], backup_dir, action="t")
    for raw, want in ((".", "-"), ("..", "--"), ("a/b", "a-b")):
        meta = snap(source, None, raw, ["a.txt"], [], backup_dir, action="t")
        assert meta.path.parent.name == want
    # snapshots never escape the backup dir, whatever the label
    assert meta.path.parent.parent == backup_dir


def test_wp_config_capture_has_no_read_side_guards(tmp_path):
    source = FakeSource()
    cfg = b"<?php define('DB_NAME', 'example_db');"
    source.files["wp-config.php"] = cfg
    meta = snap(source, None, "s", ["wp-config.php"], [], tmp_path / "bck")
    assert (meta.path / "files/wp-config.php").read_bytes() == cfg
    entry = manifest_of(meta)["files"][0]
    assert entry == {"path": "wp-config.php", "absent": False,
                     "sha256": hashlib.sha256(cfg).hexdigest(), "size": len(cfg)}
    assert backup.verify_snapshot(meta.path) is True


# ------------------------------------------------------------------- absent


def test_absent_target_recorded_not_captured_and_stray_fails_verify(tmp_path):
    source = FakeSource()
    meta = snap(source, None, "s", ["gone.txt"], [], tmp_path / "bck")
    assert manifest_of(meta)["files"] == [{"path": "gone.txt", "absent": True}]
    assert manifest_of(meta)["totals"] == {"files": 0, "absent": 1,
                                           "tables": 0, "bytes": 0}
    assert not (meta.path / "files").exists()  # nothing captured at all
    assert backup.verify_snapshot(meta.path) is True
    # a stray file for an absent entry breaks integrity
    stray = meta.path / "files/gone.txt"
    stray.parent.mkdir()
    stray.write_bytes(b"should not be here")
    assert backup.verify_snapshot(meta.path) is False


# -------------------------------------------------------------- fail-closed


def test_failclosed_source_error_mid_targets_removes_partial_dir(tmp_path):
    """A run-level read_many RAISE mid-capture (channel trip) is NOT a
    per-file skip: one full batch (200 files) landed on disk, the second
    batch's read trips — the partial snapshot dir, payloads included,
    is removed and the error re-raises (fail-closed)."""
    source = BoomSource()
    targets = _fill_files(source, 250)  # batch 1 (200) ok, batch 2 trips
    with pytest.raises(SourceError):
        snap(source, None, "s", targets, [], tmp_path / "bck")
    assert source.read_calls == 2
    assert not (tmp_path / "bck" / "s").exists()  # site dir removed (was empty)
    assert list((tmp_path / "bck").rglob("manifest.json")) == []


def test_failclosed_bridge_inline_error_envelope_removes_partial_dir(tmp_path):
    source = FakeSource()
    source.files["a.txt"] = b"aaa"
    envelope = {"ok": False, "error": "db gone", "type": "RuntimeException",
                "line": 649}
    bridge = make_bridge(dump_response([json.dumps(envelope)]))
    with pytest.raises(BridgeError):
        snap(source, bridge, "s", ["a.txt"], ["wp_posts"], tmp_path / "bck")
    assert not (tmp_path / "bck" / "s").exists()
    assert list((tmp_path / "bck").rglob("files")) == []


def test_failclosed_bridge_midstream_transport_error_removes_partial_dir(tmp_path):
    source = FakeSource()
    source.files["a.txt"] = b"aaa"
    bridge = make_bridge(ExplodingResponse(
        200, lines=table_lines("wp_posts", [["1", "x"]])[:1]))
    with pytest.raises(requests.ConnectionError):
        snap(source, bridge, "s", ["a.txt"], ["wp_posts"], tmp_path / "bck")
    assert not (tmp_path / "bck" / "s").exists()


def test_failclosed_unrequested_table_in_stream(tmp_path):
    source = FakeSource()
    source.files["a.txt"] = b"aaa"
    bridge = make_bridge(dump_response(
        table_lines("wp_posts", [["1", "x"]])[:1]
        + [json.dumps({"table": "wp_evil", "done": 0})]))
    # In-capture stream anomalies are OPERATIONAL: they speak WptError so
    # every command body's (WptError, OSError) never-raises contract holds.
    with pytest.raises(WptError, match="not requested"):
        snap(source, bridge, "s", ["a.txt"], ["wp_posts"], tmp_path / "bck")
    assert not (tmp_path / "bck" / "s").exists()


@pytest.mark.parametrize("lines, reason", [
    ([json.dumps({"table": "wp_posts", "row": ["1", "x"]}),
      json.dumps({"table": "wp_posts", "done": 2})],
     "done count 2 != 1 row line"),
    ([json.dumps({"table": "wp_posts", "row": ["1", "x"]}),
      json.dumps({"table": "wp_posts", "done": 1}),
      json.dumps({"table": "wp_posts", "done": 1})],
     "line after the done line"),
    ([json.dumps({"table": "wp_posts", "done": 0}),
      json.dumps({"table": "wp_posts", "row": ["1", "x"]})],
     "line after the done line"),
    ([json.dumps({"table": "wp_posts", "row": ["1", "x"]})],
     "missing done line"),
])
def test_failclosed_unrestorable_db_stream_is_refused_at_snapshot_time(
        tmp_path, lines, reason):
    """P2: backup accepted a stream restore refuses (a lying/duplicate/
    late/missing done), wrote it into the manifest and verify passed."""
    source = FakeSource()
    source.files["a.txt"] = b"aaa"
    bridge = make_bridge(dump_response(lines))

    with pytest.raises(WptError, match=reason):
        snap(source, bridge, "s", ["a.txt"], ["wp_posts"], tmp_path / "bck")

    assert not (tmp_path / "bck" / "s").exists()


@pytest.mark.parametrize("lines, reason", [
    # a create line after the table's done line
    ([json.dumps({"table": "wp_posts", "done": 0}),
      json.dumps({"table": "wp_posts",
                  "create": "CREATE TABLE `x` (id bigint)"})],
     "line after the done line"),
    # an unknown line shape after done
    ([json.dumps({"table": "wp_posts", "row": ["1", "x"]}),
      json.dumps({"table": "wp_posts", "done": 1}),
      json.dumps({"table": "wp_posts", "extra": 1})],
     "line after the done line"),
    # a non-string create
    ([json.dumps({"table": "wp_posts", "create": 1}),
      json.dumps({"table": "wp_posts", "done": 0})],
     "create must be a string"),
    # an object cell
    ([json.dumps({"table": "wp_posts", "row": [{"a": 1}]}),
      json.dumps({"table": "wp_posts", "done": 1})],
     "unsupported cell type"),
    # a nested array cell (not the b64 marker pair)
    ([json.dumps({"table": "wp_posts", "row": [["x", "y"]]}),
      json.dumps({"table": "wp_posts", "done": 1})],
     r"unsupported cell type \(array\)"),
])
def test_R9_P2_19_stream_restore_refuses_is_refused_at_snapshot_time(
        tmp_path, lines, reason):
    """P2-19: backup still accepted the shapes restore refuses — create or
    an unknown line after done, a non-string create, and dict/nested-array
    row cells. Each must fail at capture as WptError with no residue."""
    source = FakeSource()
    source.files["a.txt"] = b"aaa"
    bridge = make_bridge(dump_response(lines))

    with pytest.raises(WptError, match=reason) as excinfo:
        snap(source, bridge, "s", ["a.txt"], ["wp_posts"], tmp_path / "bck")

    assert "snapshot failed" in str(excinfo.value)
    assert not (tmp_path / "bck" / "s").exists()
    assert list((tmp_path / "bck").rglob("manifest.json")) == []


def test_R9_P2_19_legal_stream_round_trips_into_the_restore_grammar(tmp_path):
    """The shared grammar must still accept every legal line shape (create,
    scalar cells, a b64 marker pair, done) and the snapshot restore parses
    back to exactly the captured rows."""
    from wpt import restore

    source = FakeSource()
    source.files["a.txt"] = b"aaa"
    rows = [
        ["1", "hello"],
        ["2", ["__wpt_b64__", BLOB_B64]],
        ["3", None, True, 7.5],
    ]
    bridge = make_bridge(dump_response(table_lines("wp_posts", rows)))
    meta = snap(source, bridge, "s", ["a.txt"], ["wp_posts"], tmp_path / "bck")

    manifest = manifest_of(meta)
    entry = manifest["tables"][0]
    assert entry["rows"] == len(rows)
    assert backup.verify_snapshot(meta.path) is True
    assert restore._load_table_rows(meta.path, entry, None) == rows


def test_failclosed_requested_table_missing_from_stream(tmp_path):
    source = FakeSource()
    source.files["a.txt"] = b"aaa"
    bridge = make_bridge(dump_response(table_lines("wp_posts", [])))
    with pytest.raises(WptError, match="never mentioned"):
        snap(source, bridge, "s", ["a.txt"], ["wp_posts", "wp_missing"],
             tmp_path / "bck")
    assert not (tmp_path / "bck" / "s").exists()


def test_failclosed_nan_cell_is_wpterror_not_valueerror(tmp_path):
    """A NaN cell rejected by the NDJSON encoder's allow_nan=False is an
    operational failure: WptError (fail-closed, partial dir removed) —
    never a ValueError that would traceback-escape a command body."""
    source = FakeSource()
    source.files["a.txt"] = b"aaa"
    lines = [
        '{"table": "wp_x", "create": "CREATE TABLE `x` (v double)"}',
        '{"table": "wp_x", "row": [NaN]}',
        '{"table": "wp_x", "done": 1}',
    ]
    bridge = make_bridge(dump_response(lines))
    with pytest.raises(WptError, match="snapshot failed"):
        snap(source, bridge, "s", ["a.txt"], ["wp_x"], tmp_path / "bck")
    assert not (tmp_path / "bck" / "s").exists()


def test_caller_input_validation_creates_nothing(tmp_path):
    source = FakeSource()
    source.files["a.txt"] = b"x"
    backup_dir = tmp_path / "bck"
    with pytest.raises(ValueError):  # targets without a source
        snap(None, None, "s", ["a.txt"], [], backup_dir)
    with pytest.raises(ValueError):  # tables without a bridge
        snap(None, None, "s", [], ["wp_posts"], backup_dir)
    with pytest.raises(ValueError):  # empty label
        snap(source, None, "", [], [], backup_dir)
    with pytest.raises(ValueError):  # empty action
        snap(source, None, "s", [], [], backup_dir, action="")
    with pytest.raises(SourceError):  # target escapes the webroot
        snap(source, None, "s", ["../evil"], [], backup_dir)
    with pytest.raises(SourceError):  # absolute target
        snap(source, None, "s", ["/etc/passwd"], [], backup_dir)
    with pytest.raises(ValueError):  # duplicate targets
        snap(source, None, "s", ["a.txt", "./a.txt"], [], backup_dir)
    with pytest.raises(ValueError):  # unsafe table name
        snap(source, make_bridge(dump_response([])), "s", [], ["a/b"],
             backup_dir)
    with pytest.raises(ValueError):  # duplicate tables
        snap(source, make_bridge(dump_response([])), "s", [], ["wp_posts",
             "wp_posts"], backup_dir)
    assert not backup_dir.exists()  # nothing was ever created on disk


# ------------------------------------------------------------ empty snapshot


def test_R17_creation_rejects_casefold_duplicates_verify_rejects(
        tmp_path):
    """R17-4-P2: creation de-duplicated only EXACTLY, so ``a.txt``+``A.txt``
    (real entries on a case-sensitive host) produced a snapshot that
    ``verify_snapshot`` then refused.  Creation applies the verifier's
    casefold rule before creating anything."""
    source = FakeSource()
    source.files["a.txt"] = b"A"
    source.files["A.txt"] = b"B"
    backup_dir = tmp_path / "bck"
    with pytest.raises(ValueError, match="duplicate targets"):
        snap(source, None, "s", ["a.txt", "A.txt"], [], backup_dir)
    assert not backup_dir.exists()

    bridge = make_bridge(dump_response([]))
    with pytest.raises(ValueError, match="duplicate tables"):
        snap(source, bridge, "s", [], ["wp_posts", "WP_POSTS"], backup_dir)
    assert not backup_dir.exists()


def test_R17_stale_capture_temps_are_swept_but_live_ones_are_kept(
        tmp_path):
    """R17-4-P2: SIGKILL residue in the hidden capture names was invisible to
    SNAPSHOT_NAME_RE/prune forever.  The capture start removes only our two
    temp shapes older than the configured age; a recent temp (a concurrent
    run) survives."""
    import os
    import time

    site_dir = tmp_path / "bck" / "s"
    stale_backup = site_dir / ".20200101-000000-1.tmp"
    stale_files = site_dir / ".files-deadbeef"
    live = site_dir / ".files-cafebabe"
    for directory in (stale_backup, stale_files, live):
        directory.mkdir(parents=True)
        (directory / "partial.txt").write_bytes(b"x")
    old = time.time() - 10_000
    for directory in (stale_backup, stale_files):
        os.utime(directory, (old, old))

    source = FakeSource()
    source.files["a.txt"] = b"x"
    meta = snap(source, None, "s", ["a.txt"], [], tmp_path / "bck",
                settings=BackupSettings(stale_temp_age_s=60))

    assert backup.verify_snapshot(meta.path) is True
    assert not stale_backup.exists()
    assert not stale_files.exists()
    assert live.is_dir()  # may belong to a live concurrent capture


def test_empty_snapshot_creates_dir_and_manifest_only(tmp_path):
    meta = snap(None, None, "s", [], [], tmp_path / "bck", action="noop")
    assert sorted(p.name for p in meta.path.iterdir()) == ["manifest.json"]
    manifest = manifest_of(meta)
    assert manifest["files"] == [] and manifest["tables"] == []
    assert manifest["totals"] == {"files": 0, "absent": 0, "tables": 0,
                                  "bytes": 0}
    assert (meta.files, meta.tables, meta.bytes_written) == (0, 0, 0)
    assert backup.verify_snapshot(meta.path) is True


# ------------------------------------------------------- collision suffixing


def test_same_second_collision_gets_suffix_2_then_3(tmp_path, monkeypatch):
    fixed = datetime(2026, 9, 15, 10, 30, 5, tzinfo=timezone.utc)
    monkeypatch.setattr(backup, "_now", lambda: fixed)
    source = FakeSource()
    source.files["a.txt"] = b"x"
    metas = [snap(source, None, "s", ["a.txt"], [], tmp_path / "bck")
             for _ in range(3)]
    assert [m.path.name for m in metas] == [
        "20260915-103005", "20260915-103005-2", "20260915-103005-3",
    ]
    assert all((m.path / "manifest.json").exists() for m in metas)
    assert backup.verify_snapshot(metas[0].path) is True
    assert backup.verify_snapshot(metas[2].path) is True


def test_R16_an_empty_snapshot_dir_is_never_selected_by_undo_last(
        tmp_path, monkeypatch):
    """R16-P2: a stop/chmod failure after mkdir used to leave a timestamp
    dir with no manifest, and --undo-last selected it over a valid older
    snapshot.  Capture starts in a DOT temp name that SNAPSHOT_NAME_RE cannot
    match; the timestamped final name exists only after the manifest lands."""
    from wpt.restore import list_snapshots
    from wpt.types import StopRequested

    source = FakeSource()
    source.files["readme.html"] = b"<html>ok</html>"
    site_dir = tmp_path / "bck" / "example.com"
    monkeypatch.setattr(
        backup, "_now",
        lambda: datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc))
    good = backup.create_snapshot(
        source, None, "example.com", ["readme.html"], [], tmp_path / "bck",
        BackupSettings(), "clean-files",
        site_raw="example.com", webroot="public_html")

    monkeypatch.setattr(
        backup, "_now",
        lambda: datetime(2026, 1, 2, 12, 0, 0, tzinfo=timezone.utc))
    real_chmod = backup.os.chmod

    def _stop_chmod(path, mode):
        if ".20260102-" in Path(path).name:
            raise StopRequested("stop after mkdir")
        return real_chmod(path, mode)

    monkeypatch.setattr(backup.os, "chmod", _stop_chmod)
    with pytest.raises(StopRequested):
        backup.create_snapshot(
            source, None, "example.com", ["readme.html"], [],
            tmp_path / "bck", BackupSettings(), "clean-files",
            site_raw="example.com", webroot="public_html")
    monkeypatch.setattr(backup.os, "chmod", real_chmod)

    published = [path for path in site_dir.iterdir()
                 if path.is_dir() and backup.SNAPSHOT_NAME_RE.match(path.name)]
    assert published == [good.path]
    assert not [path for path in site_dir.iterdir()
                if path.name.startswith(".")]
    assert list_snapshots(tmp_path / "bck", "example.com",
                          webroot="public_html") == [good.path]


# -------------------------------------------------------------------- verify


def _absent_snapshot(tmp_path):
    source = FakeSource()
    meta = backup.create_snapshot(
        source, None, "example.com", ["missing.txt"], [],
        tmp_path / "bck", BackupSettings(), "files",
        site_raw="example.com", webroot="public_html")
    return meta.path


@pytest.mark.parametrize("duplicate", [
    "missing.txt",                 # exact
    "MISSING.TXT",                 # casefold
    "x/../missing.txt",            # normalized
])
def test_R16_verify_rejects_duplicate_normalized_file_paths(
        tmp_path, duplicate):
    """R16-P2: creation refuses duplicate targets but the VERIFIER accepted a
    hand-edited manifest with a duplicate path; restore then deleted the
    same live file twice, leaving a partial restore when the second delete
    failed.  Verification must refuse before any plan/write."""
    from wpt.restore import restore_snapshot

    snapshot = _absent_snapshot(tmp_path)
    manifest_path = snapshot / backup.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"].append({"path": duplicate, "absent": True})
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    assert backup.verify_snapshot(snapshot) is False

    source = FakeSource()
    source.files["missing.txt"] = b"LIVE"
    with pytest.raises(ValueError, match="failed verification"):
        restore_snapshot(
            snapshot, source, None, expected_site="example.com",
            expected_webroot="public_html")
    assert not [op for op in source.ops if op[1] == "delete"]
    assert source.files["missing.txt"] == b"LIVE"


@pytest.mark.parametrize("value", ["yes", 1, "false", 0, None, "true"])
def test_R23_non_boolean_absent_fails_verify_and_never_deletes(
        tmp_path, value):
    """R23-P1: ``entry.get("absent")`` treated ``"yes"``/``1`` as truthy and
    ``"false"``/``0`` as captured.  A corrupt/hand-edited manifest then
    either deleted a LIVE file on restore (absent) or tried to restore bytes
    that were never captured.  The schema is a JSON boolean: anything else
    fails verification, restore refuses, and the live file survives."""
    from wpt.restore import restore_snapshot

    snapshot = _absent_snapshot(tmp_path)
    manifest_path = snapshot / backup.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][0]["absent"] = value
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    assert backup.verify_snapshot(snapshot) is False
    source = FakeSource()
    source.files["missing.txt"] = b"LIVE-DATA"
    with pytest.raises(ValueError, match="failed verification"):
        restore_snapshot(
            snapshot, source, None, expected_site="example.com",
            expected_webroot="public_html")
    assert not [op for op in source.ops if op[1] == "delete"]
    assert source.files["missing.txt"] == b"LIVE-DATA"


@pytest.mark.parametrize("payload", [
    {"size": 0}, {"sha256": "0" * 64}, {"size": 1, "sha256": "0" * 64},
])
def test_R23_absent_entry_carrying_size_or_sha_fails_verification(
        tmp_path, payload):
    """An absent entry records no stored bytes.  A hybrid carrying size or
    sha256 is schema-invalid and must never select either restore arm."""
    snapshot = _absent_snapshot(tmp_path)
    manifest_path = snapshot / backup.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][0].update(payload)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    assert backup.verify_snapshot(snapshot) is False


def test_R16_verify_rejects_duplicate_table_names(tmp_path):
    """The same duplicate rule for the table list: a repeated table would be
    restored twice from one stream."""
    snapshot = _absent_snapshot(tmp_path)
    manifest_path = snapshot / backup.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["tables"] = [
        {"name": "wp_posts", "rows": 0, "sha256": None, "size": 0},
        {"name": "WP_POSTS", "rows": 0, "sha256": None, "size": 0},
    ]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    assert backup.verify_snapshot(snapshot) is False


def test_verify_detects_tampered_file_and_corrupt_manifest(tmp_path):
    source = FakeSource()
    source.files["a.txt"] = b"hello"
    meta = snap(source, None, "s", ["a.txt"], [], tmp_path / "bck")
    assert backup.verify_snapshot(meta.path) is True

    captured = meta.path / "files/a.txt"
    data = bytearray(captured.read_bytes())
    data[0] ^= 0xFF
    captured.write_bytes(bytes(data))
    assert backup.verify_snapshot(meta.path) is False

    captured.write_bytes(b"hello")  # restore content, corrupt the manifest
    assert backup.verify_snapshot(meta.path) is True
    (meta.path / "manifest.json").write_text("{ not json", encoding="utf-8")
    assert backup.verify_snapshot(meta.path) is False
    (meta.path / "manifest.json").unlink()
    assert backup.verify_snapshot(meta.path) is False


# -------------------------------------------------------------------- prune


def test_prune_keep_last_boundary_exact(tmp_path):
    site = tmp_path / "s"
    now = datetime.now().astimezone()
    names = [(now - timedelta(seconds=k)).strftime("%Y%m%d-%H%M%S")
             for k in range(5, 0, -1)]  # oldest .. newest
    dirs = [mk_snap_dir(site, n) for n in names]
    removed = backup.prune(site, BackupSettings(keep_last=3, keep_days=0),
                           site_raw="s", webroot="")
    assert removed == 2
    assert sorted(d.name for d in dirs if d.exists()) == names[-3:]


def test_prune_keep_days_exempts_old_but_recent_beyond_keep_last(tmp_path):
    site = tmp_path / "s"
    now = datetime.now().astimezone()
    fmt = "%Y%m%d-%H%M%S"
    beyond_days = mk_snap_dir(site, (now - timedelta(days=120)).strftime(fmt))
    within_days = mk_snap_dir(site, (now - timedelta(days=80)).strftime(fmt))
    older = mk_snap_dir(site, (now - timedelta(seconds=2)).strftime(fmt))
    newest = mk_snap_dir(site, (now - timedelta(seconds=1)).strftime(fmt))
    removed = backup.prune(site, BackupSettings(keep_last=2, keep_days=90),
                           site_raw="s", webroot="")
    assert removed == 1
    assert not beyond_days.exists()
    assert within_days.exists()  # beyond keep_last, within keep_days
    assert older.exists() and newest.exists()


def test_prune_keep_param_exempts_one_dir(tmp_path):
    site = tmp_path / "s"
    now = datetime.now().astimezone()
    fmt = "%Y%m%d-%H%M%S"
    oldest = mk_snap_dir(site, (now - timedelta(seconds=3)).strftime(fmt))
    middle = mk_snap_dir(site, (now - timedelta(seconds=2)).strftime(fmt))
    newest = mk_snap_dir(site, (now - timedelta(seconds=1)).strftime(fmt))
    removed = backup.prune(site, BackupSettings(keep_last=1, keep_days=0),
                            keep=oldest, site_raw="s", webroot="")
    assert removed == 1
    assert oldest.exists() and newest.exists()  # keep + rank survivors
    assert not middle.exists()


def test_prune_skips_foreign_entries_and_missing_site_dir(tmp_path):
    site = tmp_path / "s"
    foreign = mk_snap_dir(site, "not-a-snapshot")
    stray = site / "stray.txt"
    stray.write_text("x")
    bad_date = mk_snap_dir(site, "99999999-999999")  # unparsable timestamp
    doomed = mk_snap_dir(site, "20200101-000000")
    removed = backup.prune(site, BackupSettings(keep_last=0, keep_days=0),
                           site_raw="s", webroot="")
    assert removed == 1  # only the well-formed, beyond-both-rules snapshot
    assert not doomed.exists()
    assert foreign.exists() and bad_date.exists() and stray.exists()
    assert backup.prune(tmp_path / "missing", BackupSettings(),
                        site_raw="s", webroot="") == 0


def test_R23_snapshot_site_label_symlink_is_refused_both_writers(tmp_path):
    """R23-P2: ``ensure_private_dir`` did mkdir(exist_ok=True)+chmod on
    ``<backup>/<site-label>``, both FOLLOWING a planted symlink: the snapshot
    landed in the victim and its mode was chmodded 0700.  The shared
    ``open_private_site_dir`` opens the label with O_NOFOLLOW/fchmod."""
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep.txt").write_text("KEEP", encoding="utf-8")
    before_mode = victim.stat().st_mode & 0o777
    backup_dir = tmp_path / "bck"
    backup_dir.mkdir()
    (backup_dir / "example.com").symlink_to(victim, target_is_directory=True)

    with pytest.raises(WptError, match="symbolic link"):
        backup.open_private_site_dir(backup_dir, "example.com")
    assert victim.stat().st_mode & 0o777 == before_mode
    assert sorted(p.name for p in victim.iterdir()) == ["keep.txt"]

    source = FakeSource()
    source.files["a.txt"] = b"x"
    with pytest.raises(WptError, match="symbolic link"):
        backup.create_snapshot(
            source, None, "example.com", ["a.txt"], [], backup_dir,
            BackupSettings(), "files",
            site_raw="example.com", webroot="")
    assert victim.stat().st_mode & 0o777 == before_mode
    assert sorted(p.name for p in victim.iterdir()) == ["keep.txt"]
    assert (backup_dir / "example.com").is_symlink()


def test_R23_prune_and_sweep_refuse_a_symlinked_site_label(tmp_path):
    """Retention/sweep listed ``<backup>/<label>`` through a symlink and could
    delete a matching snapshot (or sweep a temp) OUTSIDE --backup-dir."""
    victim = tmp_path / "victim"
    victim.mkdir()
    doomed = mk_snap_dir(victim, "20200101-000000")
    stale = victim / ".20200101-000000-1.tmp"
    stale.mkdir()
    os.utime(stale, (1, 1))
    site = tmp_path / "bck" / "example.com"
    site.parent.mkdir()
    site.symlink_to(victim, target_is_directory=True)

    assert backup.prune(site, BackupSettings(keep_last=0, keep_days=0),
                        site_raw="s", webroot="") == 0
    assert backup.sweep_stale_snapshot_temps(
        site, BackupSettings(stale_temp_age_s=0)) == 0
    assert doomed.is_dir()
    assert stale.is_dir()
    assert site.is_symlink()


def test_retention_groups_by_manifest_identity_not_label_dir(
        tmp_path, monkeypatch):
    """P1: two docroots on one host share the sanitized label directory.
    Retention must group by the manifest's exact site_raw+webroot; a
    keep_last=1 snapshot for webroot B must never delete A's only snapshot.
    """
    clock = {"now": datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)}
    monkeypatch.setattr(backup, "_now", lambda: clock["now"])
    source = FakeSource()
    source.files["a.txt"] = b"x"
    backup_dir = tmp_path / "bck"
    settings = BackupSettings(keep_last=1, keep_days=0)

    a = snap(source, None, "site.example", ["a.txt"], [], backup_dir,
             settings=settings, webroot="A")
    clock["now"] = datetime(2026, 9, 2, 10, 0, 0, tzinfo=timezone.utc)
    b1 = snap(source, None, "site.example", ["a.txt"], [], backup_dir,
              settings=settings, webroot="B")
    clock["now"] = datetime(2026, 9, 3, 10, 0, 0, tzinfo=timezone.utc)
    b2 = snap(source, None, "site.example", ["a.txt"], [], backup_dir,
              settings=settings, webroot="B")

    assert a.path.is_dir(), "webroot A's only snapshot was deleted by B's retention"
    assert b2.path.is_dir()
    assert not b1.path.exists(), "B's older snapshot must still be pruned"


def test_R19_retention_uses_the_exact_webroot_restore_gate(tmp_path,
                                                           monkeypatch):
    """Retention normalized the webroot while restore selection became
    exact: a snapshot spelled ``/public_html/`` was kept and the only
    EXACT ``public_html`` snapshot (the one ``--undo-last`` can restore)
    was deleted.  Retention now uses the same exact comparison."""
    clock = {"now": datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)}
    monkeypatch.setattr(backup, "_now", lambda: clock["now"])
    source = FakeSource()
    source.files["a.txt"] = b"x"
    backup_dir = tmp_path / "bck"
    settings = BackupSettings(keep_last=1, keep_days=0)
    exact = snap(source, None, "example.com", ["a.txt"], [], backup_dir,
                 settings=settings, webroot="public_html")
    clock["now"] = datetime(2026, 9, 2, 10, 0, 0, tzinfo=timezone.utc)
    normalized = snap(source, None, "example.com", ["a.txt"], [], backup_dir,
                      settings=settings, webroot="/public_html/")
    removed = backup.prune(backup_dir / "example.com", settings,
                           site_raw="example.com", webroot="public_html")
    # The normalized-only snapshot is a DIFFERENT identity: it is neither a
    # candidate nor the newest exact one, so the exact snapshot survives.
    assert removed == 0
    assert exact.path.is_dir()
    assert normalized.path.is_dir()


def test_retention_keeps_unreadable_and_legacy_manifests(tmp_path):
    """Retention fails CLOSED on identity: an unreadable, non-object or
    pre-identity manifest proves nothing and is never deleted."""
    site = tmp_path / "s"
    broken = mk_snap_dir(site, "20200101-000000")
    (broken / "manifest.json").write_text("{ not json", encoding="utf-8")
    legacy = mk_snap_dir(site, "20200102-000000")
    (legacy / "manifest.json").write_text(
        json.dumps({"site": "s"}), encoding="utf-8")
    foreign = mk_snap_dir(site, "20200103-000000",
                          site_raw="s", webroot="OTHER")

    removed = backup.prune(site, BackupSettings(keep_last=0, keep_days=0),
                           site_raw="s", webroot="")

    assert removed == 0
    assert broken.exists() and legacy.exists() and foreign.exists()


def test_create_snapshot_prunes_after_write(tmp_path, monkeypatch):
    counter = {"n": 0}

    def step_clock():
        counter["n"] += 1
        return datetime(2026, 9, 15, 10, 30, 0, tzinfo=timezone.utc) \
            + timedelta(seconds=counter["n"])

    monkeypatch.setattr(backup, "_now", step_clock)
    source = FakeSource()
    source.files["a.txt"] = b"x"
    backup_dir = tmp_path / "bck"
    settings = BackupSettings(keep_last=3, keep_days=0)
    metas = [snap(source, None, "s", ["a.txt"], [], backup_dir, settings=settings)
             for _ in range(12)]
    remaining = {d.name for d in (backup_dir / "s").iterdir()}
    assert len(remaining) == 3
    assert remaining == {m.path.name for m in metas[-3:]}  # newest three


def test_multiple_tables_dumped_in_requested_order(tmp_path):
    source = FakeSource()
    source.files["a.txt"] = b"x"
    lines = (table_lines("wp_posts", [["1", "p"]])
             + table_lines("wp_options", [["opt", "v"]], create="CREATE2"))
    bridge = make_bridge(dump_response(lines))
    meta = snap(source, bridge, "s", ["a.txt"], ["wp_options", "wp_posts"],
                tmp_path / "bck")
    manifest = manifest_of(meta)
    assert [t["name"] for t in manifest["tables"]] == ["wp_options", "wp_posts"]
    opts = (meta.path / "db/wp_options.ndjson").read_bytes()
    posts = (meta.path / "db/wp_posts.ndjson").read_bytes()
    assert manifest["tables"][0]["sha256"] == hashlib.sha256(opts).hexdigest()
    assert manifest["tables"][1]["rows"] == 1
    assert manifest["totals"]["tables"] == 2
    assert meta.bytes_written == len(b"x") + len(opts) + len(posts)
    assert backup.verify_snapshot(meta.path) is True
    # one stream, two files: each table's lines routed only to its own file
    assert [json.loads(ln)["table"] for ln in opts.decode().splitlines()] \
        == ["wp_options"] * 3


# ------------------------------------------------- CLI body (wpt backup)


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def wpt_records():
    """Capture every wpt.* log record (the wpt parent does not propagate)."""
    handler = _Capture()
    parent = logging.getLogger("wpt")
    old_level = parent.level
    parent.addHandler(handler)
    parent.setLevel(logging.DEBUG)
    try:
        yield handler.records
    finally:
        parent.setLevel(old_level)
        parent.removeHandler(handler)


class CliSource(FakeSource):
    """FakeSource recording walk() completion (into ``events``) and
    close() calls — the run_backup lifecycle/ordering double."""

    def __init__(self, events=None):
        super().__init__()
        self.events = events if events is not None else []
        self.closes = 0

    def walk(self, path=""):
        yield from super().walk(path)
        self.events.append("walk-end")

    def close(self):
        self.closes += 1


class WalkBoomSource(CliSource):
    """CliSource whose list_dir always fails: walk() dies before anything."""

    def list_dir(self, path):
        raise SourceError(f"list_dir failed: {path!r}")


class CliBridge:
    """Bridge double for the command body: records every call/destroy,
    answers one scripted db_audit payload and serves a db_dump stream for
    whatever tables were requested (create_snapshot stays fully real)."""

    def __init__(self, tables, events=None):
        self.tables = tables  # the "tables" value the db_audit call returns
        self.calls: list[tuple[str, dict]] = []
        self.destroyed = 0
        self.events = events if events is not None else []

    def call(self, action, **params):
        self.events.append(("bridge", action))
        self.calls.append((action, params))
        if action == "db_audit":
            return {"ok": True, "tables": self.tables}
        raise AssertionError(f"unexpected bridge action: {action}")

    def call_stream(self, action, **params):
        self.events.append(("bridge", action))
        self.calls.append((action, params))
        assert action == "db_dump"
        for table in params["tables"]:
            yield {"table": table, "create": "CREATE TABLE `x` (id int)"}
            yield {"table": table, "row": ["1", "x"]}
            yield {"table": table, "done": 1}

    def destroy(self):
        self.destroyed += 1


def _bctx(tmp_path, **overrides):
    kwargs = dict(
        source="ftp://h", settings=load(),
        wp_url="https://example.com",
        backup_dir=tmp_path / ".wpt-backup",
        report_path=tmp_path / "backup-report.md",
    )
    kwargs.update(overrides)
    return Ctx(**kwargs)


def _stack(monkeypatch, source, bridge):
    """Patch the construction seam: run_backup's remote_stack -> fake trio."""
    monkeypatch.setattr(backup, "remote_stack",
                        lambda ctx: (source, FakeSession(), bridge))


def test_cli_local_mode_refuses(monkeypatch, tmp_path, wpt_records):
    def _never(ctx):
        raise AssertionError("remote_stack must not be called in local mode")

    monkeypatch.setattr(backup, "remote_stack", _never)
    ctx = _bctx(tmp_path, source="local")

    assert backup.run_backup(ctx) == 1
    assert ctx.report_path.exists()          # R6-29: refusal writes it
    assert "requires ftp mode" in ctx.report_path.read_text("utf-8")
    assert not ctx.backup_dir.exists()
    errors = [r for r in wpt_records
              if r.name == "wpt.backup" and r.levelno == logging.ERROR]
    assert len(errors) == 1
    assert "backup requires ftp mode: the zip + dump already are the " \
        "offline snapshot" in errors[0].getMessage()


def test_cli_happy_path(monkeypatch, tmp_path, capsys, wpt_records):
    source = CliSource()
    source.files["wp-config.php"] = b"<?php // config"
    source.files["readme.html"] = b"<h1>WP</h1>"
    source.files["wp-content/uploads/a.jpg"] = b"\xff\xd8JPG"
    bridge = CliBridge([
        {"name": "wp_posts", "rows": 1},
        {"name": "wp_options", "rows": 10},
    ])
    _stack(monkeypatch, source, bridge)
    captured: dict = {}
    real_create = backup.create_snapshot

    def spy(**kwargs):
        meta = real_create(**kwargs)
        captured.update(kwargs)
        captured["meta"] = meta
        return meta

    monkeypatch.setattr(backup, "create_snapshot", spy)
    ctx = _bctx(tmp_path)

    assert backup.run_backup(ctx) == 0

    # the walk fed create_snapshot: every non-dir path, sorted, dirs
    # excluded; the db_audit tables flow sorted; the call is action=backup
    assert captured["targets"] == [
        "readme.html", "wp-config.php", "wp-content/uploads/a.jpg",
    ]
    assert captured["tables"] == ["wp_options", "wp_posts"]
    assert captured["action"] == "backup"
    assert captured["site_label"] == "example.com"
    assert captured["backup_dir"] == ctx.backup_dir
    assert captured["settings"] is ctx.settings.backup
    assert captured["source"] is source and captured["bridge"] is bridge
    # no --deadline: the run budget is unbounded (None), not a hidden bound
    assert captured["deadline"] is None
    # db_audit happened ONCE with an empty payload; then one db_dump
    assert bridge.calls == [
        ("db_audit", {}),
        ("db_dump", {"tables": ["wp_options", "wp_posts"]}),
    ]

    meta = captured["meta"]
    assert meta.files == 3 and meta.tables == 2
    assert meta.path.parent == ctx.backup_dir / "example.com"
    assert backup.SNAPSHOT_NAME_RE.match(meta.path.name)
    manifest = manifest_of(meta)
    assert manifest["action"] == "backup"
    assert manifest["site"] == "example.com"
    assert [e["path"] for e in manifest["files"]] == [
        "readme.html", "wp-config.php", "wp-content/uploads/a.jpg",
    ]
    assert (meta.path / "files/wp-content/uploads/a.jpg").read_bytes() \
        == b"\xff\xd8JPG"
    assert (meta.path / "db/wp_options.ndjson").exists()
    assert backup.verify_snapshot(meta.path) is True

    # report written when report_path is set AND always printed; one
    # info summary logged
    report = ctx.report_path.read_text(encoding="utf-8")
    assert report.startswith("# wpt backup — example.com")
    summary_line = (f"Full snapshot at `{meta.path}`: {meta.files} files, "
                    f"{meta.tables} tables, "
                    f"{human_bytes(meta.bytes_written)}.")
    assert summary_line in report
    out = capsys.readouterr().out
    assert str(meta.path) in out
    assert out == report + "\n"
    infos = [r for r in wpt_records
             if r.name == "wpt.backup" and r.levelno == logging.INFO]
    assert any(f"backup complete: {meta.files} files, {meta.tables} tables"
               in r.getMessage() for r in infos)
    assert bridge.destroyed == 1 and source.closes == 1


def test_cli_prints_report_when_no_report_path(monkeypatch, tmp_path, capsys):
    source = CliSource()
    source.files["a.txt"] = b"x"
    bridge = CliBridge([{"name": "wp_options"}])
    _stack(monkeypatch, source, bridge)
    ctx = _bctx(tmp_path, report_path=None)

    assert backup.run_backup(ctx) == 0
    out = capsys.readouterr().out
    assert out.startswith("# wpt backup — example.com")
    assert "1 files, 1 tables" in out


def test_cli_walk_happens_before_bridge_calls(monkeypatch, tmp_path):
    events: list = []
    source = CliSource(events=events)
    source.files["wp-config.php"] = b"<?php // config"
    bridge = CliBridge([{"name": "wp_options"}], events=events)
    _stack(monkeypatch, source, bridge)
    ctx = _bctx(tmp_path)

    assert backup.run_backup(ctx) == 0
    # the FULL walk completed before the FIRST bridge call, so the
    # snapshot can never contain our own deployed bridge file
    assert events == [
        "walk-end",
        ("bridge", "db_audit"),
        ("bridge", "db_dump"),
    ]


def test_cli_unusable_db_audit_payload_returns_1(monkeypatch, tmp_path,
                                                 wpt_records):
    bad_payloads = [
        "nope",                                   # not a list
        None,                                     # "tables" key absent
        ["wp_options"],                           # list of non-dicts
        [{"rows": 1}],                            # dict without a name
        [{"name": 42}],                           # non-string name
        [{"name": "a/b"}],                        # disk-unsafe name
        [{"name": ""}],                           # empty name
    ]
    for i, bad in enumerate(bad_payloads):
        source = CliSource()
        source.files["a.txt"] = b"x"
        bridge = CliBridge(bad)
        _stack(monkeypatch, source, bridge)
        ctx = _bctx(tmp_path, backup_dir=tmp_path / f"bck-{i}",
                    report_path=tmp_path / f"r-{i}.md")

        assert backup.run_backup(ctx) == 1
        assert bridge.calls == [("db_audit", {})]  # audited, never dumped
        assert not ctx.backup_dir.exists()
        # R6-29: the failure is reportable, not an absence a caller cannot
        # distinguish from "backup found nothing".
        assert ctx.report_path.exists()
        assert "unusable tables list" in ctx.report_path.read_text("utf-8")
        # failure-path teardown: the stack is still fully released
        assert bridge.destroyed == 1 and source.closes == 1
    errors = [r for r in wpt_records
              if r.name == "wpt.backup" and r.levelno == logging.ERROR]
    assert len(errors) == len(bad_payloads)
    assert all("db_audit returned an unusable tables list"
               in r.getMessage() for r in errors)


def test_cli_walk_failure_returns_1(monkeypatch, tmp_path, wpt_records):
    source = WalkBoomSource()
    bridge = CliBridge([{"name": "wp_options"}])
    _stack(monkeypatch, source, bridge)
    ctx = _bctx(tmp_path)

    assert backup.run_backup(ctx) == 1
    assert bridge.calls == []           # the bridge was never called
    assert not ctx.backup_dir.exists()  # nothing was created
    assert ctx.report_path.exists()     # R6-29
    assert "list_dir failed" in ctx.report_path.read_text("utf-8")
    errors = [r for r in wpt_records
              if r.name == "wpt.backup" and r.levelno == logging.ERROR]
    assert len(errors) == 1
    assert "backup failed: list_dir failed" in errors[0].getMessage()
    assert bridge.destroyed == 1 and source.closes == 1


def test_cli_retention_prunes_old_snapshots(monkeypatch, tmp_path):
    source = CliSource()
    source.files["a.txt"] = b"x"
    bridge = CliBridge([{"name": "wp_options"}])
    _stack(monkeypatch, source, bridge)
    site = tmp_path / ".wpt-backup" / "example.com"
    old = [mk_snap_dir(site, "20200101-000000",
                       site_raw="example.com", webroot=""),
           mk_snap_dir(site, "20200102-000000",
                       site_raw="example.com", webroot="")]
    # Packaged defaults are keep_last=10 / keep_days=90: with three
    # snapshots total, keep_last=10 would rank BOTH 2020 dirs among the
    # newest ten and keep them.  keep_last=1 via the production --set
    # override path pins the prune engagement: the fresh snapshot wins
    # the single rank slot and both 2020 dirs sit far beyond keep_days.
    ctx = _bctx(tmp_path, settings=load(overrides={"backup.keep_last": 1}))

    assert backup.run_backup(ctx) == 0

    assert not any(directory.exists() for directory in old)
    (new,) = list(site.iterdir())
    assert backup.SNAPSHOT_NAME_RE.match(new.name)
    assert json.loads(
        (new / "manifest.json").read_text(encoding="utf-8")
    )["action"] == "backup"


# --------------------------------------------- report JSON twin (wpt backup)


def test_cli_report_writes_markdown_and_json_twin(monkeypatch, tmp_path,
                                                   capsys):
    source = CliSource()
    source.files["a.txt"] = b"x"
    bridge = CliBridge([{"name": "wp_options"}])
    _stack(monkeypatch, source, bridge)
    captured: dict = {}
    real_create = backup.create_snapshot

    def spy(**kwargs):
        meta = real_create(**kwargs)
        captured["meta"] = meta
        return meta

    monkeypatch.setattr(backup, "create_snapshot", spy)
    ctx = _bctx(tmp_path)

    assert backup.run_backup(ctx) == 0

    # BOTH twins land side by side; the JSON is ONE object with exactly
    # the five summary keys, snapshot = meta.path as a string
    assert ctx.report_path.exists()
    json_path = ctx.report_path.with_suffix(".json")
    assert json_path.exists()
    meta = captured["meta"]
    text = json_path.read_text(encoding="utf-8")
    payload = json.loads(text)
    assert set(payload) == {"site", "snapshot", "files", "tables", "bytes"}
    assert payload == {
        "site": "example.com",
        "snapshot": str(meta.path),
        "files": meta.files,
        "tables": meta.tables,
        "bytes": meta.bytes_written,
    }
    assert (meta.files, meta.tables) == (1, 1)
    # house JSON convention (utf-8, sorted keys, indent 2): the file IS
    # the canonical dump of its own payload
    assert text == json.dumps(payload, ensure_ascii=False, sort_keys=True,
                              indent=2)
    # the markdown twin is the same summary surface as before
    report = ctx.report_path.read_text(encoding="utf-8")
    assert report.startswith("# wpt backup — example.com")
    # stdout stays markdown-only: exactly the report, never the JSON
    out = capsys.readouterr().out
    assert out == report + "\n"


def test_cli_no_report_path_writes_neither_twin(monkeypatch, tmp_path,
                                                 capsys):
    source = CliSource()
    source.files["a.txt"] = b"x"
    bridge = CliBridge([{"name": "wp_options"}])
    _stack(monkeypatch, source, bridge)
    ctx = _bctx(tmp_path, report_path=None)

    assert backup.run_backup(ctx) == 0

    # neither twin anywhere (the manifest.json under .wpt-backup/... is
    # the engine's own record, not a report)
    assert list(tmp_path.glob("*.md")) == []
    assert list(tmp_path.glob("*.json")) == []
    # stdout: the plain markdown summary, unchanged, JSON never printed
    out = capsys.readouterr().out
    assert out.startswith("# wpt backup — example.com")
    assert "1 files, 1 tables" in out
    assert '"site"' not in out


# --------------------------------------------- capture observability


def _fill_files(source, count, blob=b"x"):
    """``count`` same-size fake files + their target list (one byte per
    file, so the heartbeat's ``bytes so far`` is exactly the file count)."""
    names = [f"f{i:05d}.txt" for i in range(count)]
    for name in names:
        source.files[name] = blob
    return names


def _backup_infos(records):
    return [r.getMessage() for r in records
            if r.name == "wpt.backup" and r.levelno == logging.INFO]


def test_heartbeat_every_500_captured_files_and_elapsed_success_line(
        tmp_path, wpt_records):
    source = FakeSource()
    targets = _fill_files(source, 1200)
    meta = snap(source, None, "s", targets, [], tmp_path / "bck")
    assert meta.files == 1200

    # exactly two heartbeats — at 500 and 1000; never at the 1200 end
    beats = [m for m in _backup_infos(wpt_records) if "snapshot progress" in m]
    assert beats == [
        "snapshot progress: 500/1200 files captured (500 bytes so far)",
        "snapshot progress: 1000/1200 files captured (1000 bytes so far)",
    ]
    # the success summary GAINS a trailing, non-negative elapsed field
    summaries = [m for m in _backup_infos(wpt_records)
                 if m.startswith("snapshot for ")]
    assert len(summaries) == 1
    assert re.fullmatch(
        r"snapshot for clean-files at .*: 1200 file\(s\) captured, "
        r"0 absent, 0 table\(s\), 1200 bytes \(\d+s elapsed\)",
        summaries[0],
    )


def test_no_heartbeat_at_or_below_500_targets(tmp_path, wpt_records):
    source = FakeSource()
    targets = _fill_files(source, 500)  # the boundary: 500th capture is LAST
    meta = snap(source, None, "s", targets, [], tmp_path / "bck")
    assert meta.files == 500
    assert not [m for m in _backup_infos(wpt_records)
                if "snapshot progress" in m]

    # one target past the boundary: the 500th capture has work after it,
    # so exactly one heartbeat fires — strictly inside the capture
    source = FakeSource()
    targets = _fill_files(source, 501)
    snap(source, None, "s2", targets, [], tmp_path / "bck")
    assert [m for m in _backup_infos(wpt_records)
            if "snapshot progress" in m] == [
        "snapshot progress: 500/501 files captured (500 bytes so far)",
    ]


def test_one_debug_line_per_completed_table_never_a_heartbeat(
        tmp_path, wpt_records):
    source = FakeSource()
    source.files["a.txt"] = b"x"
    # stream order (posts first) intentionally differs from the requested
    # order: the debug line fires at each table's done object, i.e. in
    # STREAM completion order
    lines = (table_lines("wp_posts", [["1", "p"]])
             + table_lines("wp_options", [["opt", "v"]], create="CREATE2"))
    bridge = make_bridge(dump_response(lines))
    meta = snap(source, bridge, "s", ["a.txt"], ["wp_options", "wp_posts"],
                tmp_path / "bck")
    assert meta.tables == 2

    debugs = [r.getMessage() for r in wpt_records
              if r.name == "wpt.backup" and r.levelno == logging.DEBUG]
    assert debugs == [
        "table captured: wp_posts (1 rows)",
        "table captured: wp_options (1 rows)",
    ]
    # tables never heartbeat (a few dozen at most, each fast) and the
    # success line carries its elapsed field on table snapshots too
    assert not [m for m in _backup_infos(wpt_records)
                if "snapshot progress" in m]
    summaries = [m for m in _backup_infos(wpt_records)
                 if m.startswith("snapshot for ")]
    assert len(summaries) == 1
    assert re.search(r"\(\d+s elapsed\)$", summaries[0])


# ------------------------------- batched read_many capture + run deadline


def test_batched_capture_split_ok_failed_chunking_fails_closed(
        tmp_path, wpt_records):
    """The capture loop READS through batched read_many (chunks of
    backup._READ_BATCH == 200, present targets only) and ok paths land
    byte-exact with sha256 — but a present target in ``failed`` is a
    HOLE in the reversibility substrate: the whole snapshot fails
    closed (partial dir removed, WptError naming the unreadable
    targets) exactly like the pre-batching read_bytes raise.  A backup
    may never silently lack a file --apply could mutate."""
    fail = {"f00210.txt", "f00350.txt"}       # present, unreadable, BOTH in
    source = BatchSource(fail=fail)           # batch 2 (the raise is per-batch:
    targets = _fill_files(source, 450)        # batch 3 is never fetched)

    with pytest.raises(WptError) as ei:
        snap(source, None, "s", targets, [], tmp_path / "bck")
    assert "2 of 200 present targets unreadable" in str(ei.value)
    assert "f00210.txt" in str(ei.value) and "f00350.txt" in str(ei.value)
    assert "reversibility substrate" in str(ei.value)

    # the batching: batches 1 and 2 fetched (one call each); the trip on
    # batch 2's failed bucket aborted the capture before batch 3
    assert source.read_calls == [200, 200]
    # fail-closed: nothing of the partial snapshot survives
    assert not (tmp_path / "bck" / "s").exists()
    assert list((tmp_path / "bck").rglob("manifest.json")) == []


def test_batched_capture_ok_only_round_trips(tmp_path, wpt_records):
    """The batching mechanics with a fully readable target set: 3 calls
    of at most 200 present paths, absent classification in target order,
    captured bytes byte-exact with sha256, and the snapshot verifies."""
    source = BatchSource()
    targets = _fill_files(source, 450)
    absentees = ("f00300.txt", "f00449.txt")  # not on the source at all
    for name in absentees:
        source.files.pop(name)

    meta = snap(source, None, "s", targets, [], tmp_path / "bck")

    # the batching: 3 calls, present-only, never over 200 paths each
    assert source.read_calls == [200, 199, 49]

    # 450 targets = 448 captured + 2 absent (1 byte per file)
    assert meta.files == 448
    manifest = manifest_of(meta)
    assert manifest["totals"] == {"files": 448, "absent": 2,
                                  "tables": 0, "bytes": 448}
    assert meta.bytes_written == 448

    # manifest: target order kept; absentees keep their entries in place
    expected = []
    for name in targets:
        if name in absentees:
            expected.append({"path": name, "absent": True})
        else:
            expected.append({"path": name, "absent": False,
                             "sha256": hashlib.sha256(b"x").hexdigest(),
                             "size": 1})
    assert manifest["files"] == expected

    assert (meta.path / "files/f00000.txt").read_bytes() == b"x"
    assert (meta.path / "files/f00448.txt").read_bytes() == b"x"
    assert backup.verify_snapshot(meta.path) is True


def test_C1_verify_snapshot_never_converts_a_stop_to_false(tmp_path,
                                                           monkeypatch):
    """C1: a StopRequested from a payload read was caught by the generic
    verify failure branch and returned False, so the run continued.  It must
    propagate as the run-ending signal."""
    from wpt.types import StopRequested

    source = FakeSource()
    source.files["a.txt"] = b"a"
    meta = snap(source, None, "s", ["a.txt"], [], tmp_path / "bck")

    def _stop(*_args, **_kwargs):
        raise StopRequested("received SIGTERM (15)")

    monkeypatch.setattr(backup, "read_regular_bounded", _stop)
    with pytest.raises(StopRequested):
        backup.verify_snapshot(meta.path)


def test_deadline_exceeded_mid_capture_fails_closed(tmp_path):
    """An already-spent run deadline trips the capture's per-BATCH check
    BEFORE the first read: DeadlineExceeded (a RunControl, so no broad
    operational catch can eat it) flows into the EXISTING fail-closed
    cleanup — partial dir removed — and out.  No
    sleeps: the budget is a monotonic SPAN, expired by construction via
    the test_deadline.py simulated-elapsed pattern."""
    source = BatchSource()
    targets = _fill_files(source, 50)
    d = Deadline(0.0001)
    d._started -= 1.0  # simulate elapsed wall time: deterministically spent
    with pytest.raises(DeadlineExceeded):
        snap(source, None, "s", targets, [], tmp_path / "bck", deadline=d)
    assert source.read_calls == []  # the trip precedes the first read
    assert not (tmp_path / "bck" / "s").exists()
    assert list((tmp_path / "bck").rglob("manifest.json")) == []


def test_deadline_exceeded_during_db_dump_fails_closed(tmp_path):
    """The db-dump loop checks the deadline per TABLE: an expired budget
    trips at the first table's first stream object (no file targets, so
    the capture loop's batch checks never fire) — fail-closed."""
    source = FakeSource()
    source.files["a.txt"] = b"aaa"
    bridge = make_bridge(dump_response(table_lines("wp_posts", [["1", "x"]])))
    d = Deadline(0.0001)
    d._started -= 1.0  # deterministically spent (no sleeps)
    with pytest.raises(DeadlineExceeded):
        snap(source, bridge, "s", [], ["wp_posts"], tmp_path / "bck",
             deadline=d)
    assert not (tmp_path / "bck" / "s").exists()
    assert list((tmp_path / "bck").rglob("*.ndjson")) == []


def test_heartbeat_cadence_preserved_across_batched_reads(tmp_path,
                                                          wpt_records):
    """Batching does not move the heartbeat: 1200 targets read in 6
    read_many batches still produce EXACTLY the two at-500/at-1000
    progress lines (the milestones land INSIDE batches 3 and 5) — the
    same messages as the serial loop, never one at the 1200 end."""
    source = BatchSource()
    targets = _fill_files(source, 1200)
    meta = snap(source, None, "s", targets, [], tmp_path / "bck")
    assert meta.files == 1200
    assert source.read_calls == [200] * 6
    beats = [m for m in _backup_infos(wpt_records) if "snapshot progress" in m]
    assert beats == [
        "snapshot progress: 500/1200 files captured (500 bytes so far)",
        "snapshot progress: 1000/1200 files captured (1000 bytes so far)",
    ]


def test_C9_a_duplicate_walk_yield_is_deduped_not_a_ValueError(
        monkeypatch, tmp_path):
    """C9: a source whose walk() repeats a path reached create_snapshot's
    duplicate-target guard as a raw ValueError out of run_backup (no report).
    The walk-to-snapshot boundary dedupes."""
    class _DuplicateWalk(CliSource):
        def walk(self, path=""):
            entries = list(super().walk(path))
            yield from entries
            yield from entries

    source = _DuplicateWalk()
    source.files["a.txt"] = b"a"
    bridge = CliBridge([{"name": "wp_options"}])
    _stack(monkeypatch, source, bridge)
    ctx = _bctx(tmp_path, report_path=None)

    assert backup.run_backup(ctx) == 0
    manifest = next(ctx.backup_dir.rglob("manifest.json"))
    files = json.loads(manifest.read_text(encoding="utf-8"))["files"]
    assert [entry["path"] for entry in files] == ["a.txt"]
    assert manifest.parent.joinpath("files/a.txt").read_bytes() == b"a"


def test_R18_casefold_duplicate_walk_paths_fail_closed_with_a_report(
        monkeypatch, tmp_path, wpt_records):
    """R18-P2: a case-sensitive host can list ``a.txt`` and ``A.txt``.  The
    walk-to-snapshot boundary used to feed both to create_snapshot, whose
    ValueError escaped main() as a traceback with no snapshot/report."""
    source = CliSource()
    source.files["a.txt"] = b"a"
    source.files["A.txt"] = b"A"
    _stack(monkeypatch, source, CliBridge([]))
    ctx = _bctx(tmp_path)

    assert backup.run_backup(ctx) == 1
    assert ctx.report_path.exists()
    text = ctx.report_path.read_text(encoding="utf-8")
    assert "differ only by case" in text
    assert not list(ctx.backup_dir.rglob("manifest.json"))
    errors = [r.getMessage() for r in wpt_records
              if r.name == "wpt.backup" and r.levelno == logging.ERROR]
    assert any("differ only by case" in message for message in errors)


def test_R25_a_legal_backslash_filename_fails_the_snapshot_closed(
        monkeypatch, tmp_path, wpt_records):
    """R25-P1: ``wp-content\\evil.php`` is ONE legal POSIX file name.  The
    walk-to-snapshot boundary normalized it to ``wp-content/evil.php`` and,
    when no such slash path existed, wrote ``{"path": "...", "absent":
    true}`` while the real PHP file was never captured (rc 0).  A connector
    name the guard would rewrite now fails closed, naming the raw name; no
    ``absent`` entry and no manifest can claim the file never existed."""
    from wpt.types import Entry

    class _BackslashWalk(CliSource):
        def __init__(self, paths):
            super().__init__()
            self._paths = paths

        def walk(self, path=""):
            for raw in self._paths:
                yield Entry(path=raw, is_dir=False, size=1)

    for paths in (
        ["readme.html", "wp-content\\evil.php"],
        ["wp-content\\evil.php"],
        # A directory name carrying the backslash hides its whole subtree.
        ["wp-content\\uploads/a.jpg"],
    ):
        source = _BackslashWalk(paths)
        for raw in paths:
            source.files[raw] = b"x"
        _stack(monkeypatch, source, CliBridge([]))
        ctx = _bctx(tmp_path)
        assert backup.run_backup(ctx) == 1
        assert ctx.report_path.exists()
        text = ctx.report_path.read_text(encoding="utf-8")
        assert "backslash" in text
        assert "evil.php" in text or "uploads" in text
        assert not list(ctx.backup_dir.rglob("manifest.json"))
        errors = [r.getMessage() for r in wpt_records
                  if r.name == "wpt.backup" and r.levelno == logging.ERROR]
        assert any("backslash" in message for message in errors)

    # The SHARED walk refuses the same connector name before any consumer
    # (audit/scan/files) can read the wrong slash path.
    shared = FakeSource()
    shared.files["wp-content\\evil.php"] = b"x"
    with pytest.raises(SourceError, match="backslash"):
        list(shared.walk())


def test_R18_casefold_duplicate_tables_fail_closed_with_a_report(
        monkeypatch, tmp_path):
    """The same boundary for MySQL's case-insensitive table names: a
    restore plan would address ``wp_posts``/``WP_POSTS`` as one table."""
    source = CliSource()
    source.files["a.txt"] = b"a"
    _stack(monkeypatch, source,
           CliBridge([{"name": "wp_posts"}, {"name": "WP_POSTS"}]))
    ctx = _bctx(tmp_path)

    assert backup.run_backup(ctx) == 1
    assert ctx.report_path.exists()
    assert "differ only by case" in ctx.report_path.read_text(
        encoding="utf-8")
    assert not list(ctx.backup_dir.rglob("manifest.json"))


def test_R11_normalized_duplicate_walk_paths_are_deduped_with_a_report(
        monkeypatch, tmp_path):
    """R11-P2-7: ``./a.txt`` and ``a.txt`` are the same FTP entry.  Exact
    string dedupe let them reach create_snapshot's duplicate guard as a raw
    ValueError, so the run aborted with no report pair."""
    from wpt.types import Entry

    class _AliasedWalk(CliSource):
        def walk(self, path=""):
            yield Entry(path="./a.txt", is_dir=False, size=1)
            yield Entry(path="a.txt", is_dir=False, size=1)

    source = _AliasedWalk()
    source.files["a.txt"] = b"a"
    bridge = CliBridge([{"name": "wp_options"}])
    _stack(monkeypatch, source, bridge)
    ctx = _bctx(tmp_path)

    assert backup.run_backup(ctx) == 0
    manifest = next(ctx.backup_dir.rglob("manifest.json"))
    files = json.loads(manifest.read_text(encoding="utf-8"))["files"]
    assert [entry["path"] for entry in files] == ["a.txt"]
    assert manifest.parent.joinpath("files/a.txt").read_bytes() == b"a"
    assert ctx.report_path.exists()
    assert ctx.report_path.with_suffix(".json").exists()


def test_cli_passes_the_run_deadline_into_create_snapshot(monkeypatch,
                                                           tmp_path):
    """run_backup builds the run's budget ONCE through the construction
    seam (Deadline.from_ctx) and hands it to create_snapshot: without
    deadline_s the snapshot runs unbounded; 120s arrives as the budget."""
    source = CliSource()
    source.files["a.txt"] = b"x"
    bridge = CliBridge([{"name": "wp_options"}])
    _stack(monkeypatch, source, bridge)
    captured: dict = {}
    real_create = backup.create_snapshot

    def spy(**kwargs):
        meta = real_create(**kwargs)
        captured.update(kwargs)
        return meta

    monkeypatch.setattr(backup, "create_snapshot", spy)

    ctx = _bctx(tmp_path, report_path=None)
    assert backup.run_backup(ctx) == 0
    assert captured["deadline"] is None  # no deadline_s: unbounded

    ctx = _bctx(tmp_path, report_path=None, deadline_s=120)
    assert backup.run_backup(ctx) == 0
    d = captured["deadline"]
    assert isinstance(d, Deadline) and d._seconds == 120.0


def test_C8_the_run_budget_starts_before_the_backup_walk(
        monkeypatch, tmp_path):
    """C8: the budget used to be built AFTER walk()+db_audit, so pre-work
    overran --deadline and the run still answered rc 0.  The walk below
    advances the shared clock; the deadline built at command entry must trip
    on the first walked entry."""
    import wpt.deadline as deadline_mod

    now = [1000.0]
    monkeypatch.setattr(deadline_mod, "_CLOCK", lambda: now[0])

    class _SlowWalk(CliSource):
        def walk(self, path=""):
            now[0] += 1.0
            yield from super().walk(path)

    source = _SlowWalk()
    source.files["a.txt"] = b"x"
    bridge = CliBridge([{"name": "wp_options"}])
    _stack(monkeypatch, source, bridge)
    ctx = _bctx(tmp_path, report_path=None, deadline_s=0.05)

    assert backup.run_backup(ctx) == 1
    assert bridge.calls == []                    # db_audit never reached
    assert not (ctx.backup_dir / "example.com").exists()


def test_a_snapshot_never_archives_a_bridge_endpoint(tmp_path):
    """[L59] a full-site snapshot archived a SIBLING run's live bridge — a
    token-authenticated endpoint — and `restore` wrote it back working; the
    archive outlives the token. backup must never capture one."""
    from wpt.bridge_name import is_bridge_file
    from wpt.backup import _targets_exclude_bridges

    from wpt.types import Entry
    def E(path, size):
        return Entry(path=path, is_dir=False, size=size)
    entries = [E("wp-config.php", 100), E("bridge-af12cd34.php", 166982),
               E("wp-content/bridge-99ffee00.php", 166982),
               E("bridge-notes.php", 40), E("index.php", 28)]
    kept = _targets_exclude_bridges(entries)
    assert kept == ["bridge-notes.php", "index.php", "wp-config.php"]  # sorted
    assert is_bridge_file("bridge-af12cd34.php")
    assert not is_bridge_file("bridge-notes.php")


# ------------------------------------------------------- triple-check round 2


def test_PROBE1_a_real_ensured_probe_is_never_captured(tmp_path):
    """PROBE1: a probe is the bridge's sibling token endpoint; a real
    ``PhpProbe.ensure()`` snapshot must not archive it (restoring it would
    re-arm a working endpoint)."""
    from wpt.php_probe import PhpProbe
    from wpt.settings import load

    source = FakeSource()
    source.files["index.php"] = b"<?php // site"
    probe = PhpProbe(source, FakeSession(), load().probe, SITE)
    endpoint = probe.ensure()
    assert endpoint in source.files

    targets = backup._targets_exclude_bridges(
        entry for entry in source.walk() if not entry.is_dir)
    assert endpoint not in targets
    assert targets == ["index.php"]

    meta = snap(source, None, "example.com", targets, [], tmp_path / "bck")
    manifest = manifest_of(meta)
    assert [entry["path"] for entry in manifest["files"]] == ["index.php"]
    assert endpoint not in (meta.path / "manifest.json").read_text(
        encoding="utf-8")


def test_REPORT_SURROGATE_backup_writes_complete_faces(tmp_path,
                                                       monkeypatch):
    """REPORT-SURROGATE (backup's direct writer): a surrogate site label
    raised UnicodeEncodeError after the snapshot, leaving no report pair."""
    source = CliSource()
    source.files["wp-config.php"] = b"<?php // config"
    bridge = CliBridge([])
    _stack(monkeypatch, source, bridge)
    ctx = _bctx(tmp_path, wp_url="https://bad\udcff.example")

    assert backup.run_backup(ctx) == 0
    markdown = ctx.report_path.read_text(encoding="utf-8")
    twin = ctx.report_path.with_suffix(".json").read_text(encoding="utf-8")
    assert markdown and "\\udcff" in markdown
    site = json.loads(twin)["site"]
    assert site.encode("utf-8", "backslashreplace").decode() == \
        "bad\\udcff.example"
    assert "\\udcff" in twin  # the file's visible bytes are encodable


# ------------------------------------------------------- round-5 identity


def test_ROUND5_create_snapshot_requires_both_current_identity_keys(tmp_path):
    """No defaults/fallbacks: create_snapshot refuses to omit site_raw or
    webroot, and every manifest carries both keys."""
    source = FakeSource()
    source.files["a.txt"] = b"x"
    with pytest.raises(TypeError):
        backup.create_snapshot(
            source, None, "example.com", ["a.txt"], [], tmp_path / "bck",
            BackupSettings(), "backup")
    with pytest.raises(ValueError, match="site_raw"):
        backup.create_snapshot(
            source, None, "example.com", ["a.txt"], [], tmp_path / "bck",
            BackupSettings(), "backup", site_raw="", webroot="public_html")
    with pytest.raises(ValueError, match="webroot"):
        backup.create_snapshot(
            source, None, "example.com", ["a.txt"], [], tmp_path / "bck",
            BackupSettings(), "backup", site_raw="example.com", webroot=None)

    meta = backup.create_snapshot(
        source, None, "example.com", ["a.txt"], [], tmp_path / "bck",
        BackupSettings(), "backup", site_raw="example.com",
        webroot="public_html")
    manifest = manifest_of(meta)
    assert manifest["site_raw"] == "example.com"
    assert manifest["webroot"] == "public_html"


# ------------------------------------------------------- triple-check round 6


class _StopDestroyBridge(CliBridge):
    def destroy(self):
        self.destroyed += 1
        from wpt.types import StopRequested

        raise StopRequested("received SIGTERM (15) during destroy")


def test_R6_28_teardown_stop_keeps_the_source_close_and_rc1(
        monkeypatch, tmp_path, wpt_records):
    """R6-28: a stop/deadline in destroy() skipped source.close(), and a
    generic destroy error escaped.  Both cleanups run independently and the
    first cooperative stop ends the run rc 1."""
    source = CliSource()
    source.files["a.txt"] = b"x"
    bridge = _StopDestroyBridge([{"name": "wp_options"}])
    _stack(monkeypatch, source, bridge)
    ctx = _bctx(tmp_path)

    assert backup.run_backup(ctx) == 1
    assert source.closes == 1
    assert bridge.destroyed == 1
    assert "SIGTERM" in ctx.report_path.read_text("utf-8")


def test_R6_28_a_capture_failure_is_never_masked_by_a_teardown_stop(
        monkeypatch, tmp_path, wpt_records):
    """The primary 'file unreadable' must stay the logged reason even when
    destroy() also raises a cooperative stop."""
    source = WalkBoomSource()
    bridge = _StopDestroyBridge([{"name": "wp_options"}])
    _stack(monkeypatch, source, bridge)
    ctx = _bctx(tmp_path)

    assert backup.run_backup(ctx) == 1
    assert source.closes == 1 and bridge.destroyed == 1
    errors = [r.getMessage() for r in wpt_records
              if r.name == "wpt.backup" and r.levelno == logging.ERROR]
    assert any("list_dir failed" in message for message in errors)
    assert "list_dir failed" in ctx.report_path.read_text("utf-8")


def test_R6_29_refusal_and_walk_failure_write_the_failure_report(
        monkeypatch, tmp_path):
    """R6-29: local refusal and ftp walk failure only logged; --report was
    silently absent.  Both now route through the shared failure writer."""
    local = _bctx(tmp_path / "local", source="local",
                  backup_dir=tmp_path / "local-bck",
                  report_path=tmp_path / "local.md")
    assert backup.run_backup(local) == 1
    assert local.report_path.exists()
    assert "requires ftp mode" in local.report_path.read_text("utf-8")

    source = WalkBoomSource()
    bridge = CliBridge([{"name": "wp_options"}])
    _stack(monkeypatch, source, bridge)
    failed = _bctx(tmp_path / "walk", backup_dir=tmp_path / "walk-bck",
                   report_path=tmp_path / "walk.md")
    assert backup.run_backup(failed) == 1
    assert failed.report_path.exists()
    assert "list_dir failed" in failed.report_path.read_text("utf-8")


def test_R6_36_read_regular_bounded_refuses_a_symlink_final_component(
        tmp_path):
    """R6-36: lstat-then-open let a symlink swapped into the gap read
    OUTSIDE the snapshot.  O_NOFOLLOW refuses a final-component link and a
    real regular file still round-trips byte-exact."""
    exact = tmp_path / "stored.txt"
    exact.write_bytes(b"exact snapshot bytes")
    assert backup.read_regular_bounded(
        exact, 1000, "snapshot file") == b"exact snapshot bytes"

    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"OUTSIDE-SECRET")
    link = tmp_path / "swapped.txt"
    link.symlink_to(outside)

    with pytest.raises(WptError, match="cannot read"):
        backup.read_regular_bounded(link, 1000, "snapshot file")
    assert outside.read_bytes() == b"OUTSIDE-SECRET"


def test_R6_36_a_dangling_link_on_an_absent_entry_fails_verification(
        tmp_path):
    """R6-36: exists() follows a dangling link to False, so an absent entry
    backed by one passed verify_snapshot.  lexists() catches the stray."""
    source = FakeSource()
    source.files["present.txt"] = b"x"
    meta = snap(source, None, "example.com",
                ["present.txt", "missing.txt"], [], tmp_path / "bck")
    assert backup.verify_snapshot(meta.path) is True

    stray = meta.path / backup.FILES_DIR / "missing.txt"
    stray.symlink_to(tmp_path / "does-not-exist")
    assert not stray.exists()          # dangling: exists() follows to False
    assert os.path.lexists(stray)
    assert backup.verify_snapshot(meta.path) is False


def test_N1_snapshot_reader_uses_only_the_opened_fd(tmp_path, monkeypatch):
    """N1: an lstat before open could be defeated by an unlink+copy that
    reused the freed inode, so the reader never trusts a pre-open stat.
    ``os.lstat`` is made unusable; verification still succeeds through the
    single fd it opens and fstats."""
    source = FakeSource()
    source.files["readme.html"] = b"ORIGINAL"
    meta = snap(source, None, "example.com", ["readme.html"], [],
                tmp_path / "bck")

    def _no_pre_open_stat(path):
        raise AssertionError("snapshot verification must not lstat before open")

    monkeypatch.setattr(os, "lstat", _no_pre_open_stat)
    assert backup.verify_snapshot(meta.path) is True


def test_N1_unlink_copy_swap_in_the_open_gap_cannot_pass_verification(
        tmp_path, monkeypatch):
    """N1: unlink+copy between the pre-open stat and the open used to be
    accepted when the filesystem reused the inode.  With no pre-open stat
    the swapped bytes are what the fd holds, and the manifest sha256 gate
    refuses them — verification can never trust the new file."""
    source = FakeSource()
    source.files["readme.html"] = b"ORIGINAL"
    meta = snap(source, None, "example.com", ["readme.html"], [],
                tmp_path / "bck")

    stored_name = "readme.html"
    real_open = os.open
    state = {"swapped": False}

    def _swapping_open(path, flags, *args, dir_fd=None, **kwargs):
        if (os.fspath(path) == stored_name and dir_fd is not None
                and not state["swapped"]):
            # The attack: replace the name in the open gap.  The new file
            # may reuse the freed inode; a pre-open identity compare would
            # then lie.  Only the fd's content and the manifest hash remain.
            os.unlink(stored_name, dir_fd=dir_fd)
            wfd = real_open(
                stored_name,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC,
                0o600, dir_fd=dir_fd)
            try:
                os.write(wfd, b"OUTSIDE-SECRET")
            finally:
                os.close(wfd)
            state["swapped"] = True
        return real_open(path, flags, *args, dir_fd=dir_fd, **kwargs)

    monkeypatch.setattr(os, "open", _swapping_open)
    swapped = backup.read_regular_bounded(
        Path(stored_name), 1000, "snapshot file",
        root=meta.path / backup.FILES_DIR)
    assert swapped == b"OUTSIDE-SECRET"
    assert state["swapped"] is True
    assert backup.verify_snapshot(meta.path) is False


def test_NF1_a_symlinked_directory_component_fails_even_with_a_matching_manifest(
        tmp_path):
    """N-F1: O_NOFOLLOW only guards the FINAL component.  A symlinked
    directory under files/ redirected verification outside the snapshot;
    opening the root as a dirfd and walking each component with
    O_NOFOLLOW|O_DIRECTORY refuses it even when the edited manifest's
    sha256/size match the outside bytes exactly."""
    source = FakeSource()
    source.files["wp-content/a.txt"] = b"ORIGINAL"
    meta = snap(source, None, "example.com", ["wp-content/a.txt"], [],
                tmp_path / "bck")

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "a.txt").write_bytes(b"OUTSIDE-EVIL")
    component = meta.path / backup.FILES_DIR / "wp-content"
    real = meta.path / backup.FILES_DIR / "wp-content-real"
    component.rename(real)
    component.symlink_to(outside, target_is_directory=True)

    manifest_path = meta.path / backup.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entry = manifest["files"][0]
    entry["sha256"] = hashlib.sha256(b"OUTSIDE-EVIL").hexdigest()
    entry["size"] = len(b"OUTSIDE-EVIL")
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8")

    assert backup.verify_snapshot(meta.path) is False
    assert (outside / "a.txt").read_bytes() == b"OUTSIDE-EVIL"


# ------------------------------------------------- triple-check round 7


@pytest.mark.parametrize("count", [6000, 12000])
def test_R7_P1_02_manifest_over_the_reader_cap_fails_closed(tmp_path, count):
    """R7-P1-02: the writer emitted a manifest the reader caps at 1 MiB, so
    ``wpt backup`` reported success over a snapshot restore refused."""
    source = FakeSource()
    targets = [f"wp-content/uploads/file-{index:05d}.txt"
               for index in range(count)]
    source.files.update({target: b"x" for target in targets})
    backup_dir = tmp_path / "bck"
    with pytest.raises(WptError, match="MANIFEST_MAX_BYTES"):
        backup.create_snapshot(
            source, None, "example.com", targets, [], backup_dir,
            BackupSettings(), "backup",
            site_raw="example.com", webroot=WEBROOT)
    site_dir = backup_dir / backup.sanitize_site_label("example.com")
    assert not site_dir.exists() or not list(site_dir.iterdir())


def test_R7_P1_02_a_snapshot_below_the_cap_round_trips(tmp_path):
    source = FakeSource()
    targets = [f"wp-content/uploads/file-{index:03d}.txt"
               for index in range(100)]
    source.files.update({target: b"x" for target in targets})
    meta = snap(source, None, "example.com", targets, [], tmp_path / "bck")
    assert (meta.path / backup.MANIFEST_NAME).stat().st_size \
        <= backup.MANIFEST_MAX_BYTES
    assert backup.verify_snapshot(meta.path) is True


def test_R7_P2_01_create_snapshot_refuses_a_wpt_endpoint(tmp_path):
    """R7-P2-01: a pre-action snapshot could archive a live token endpoint."""
    source = FakeSource()
    source.files["index.php"] = b"<?php"
    source.files["bridge-deadbeef.php"] = b"<?php token"
    for endpoint in ("bridge-deadbeef.php", "wpt-probe-deadbeef.php",
                     "BRIDGE-DEADBEEF.PHP"):
        source.files[endpoint] = b"<?php token"
        with pytest.raises(ValueError, match="token endpoint"):
            snap(source, None, "example.com", ["index.php", endpoint], [],
                 tmp_path / endpoint)


def test_R7_P2_26_manifest_format_and_version_come_from_the_constants(
        tmp_path, monkeypatch):
    source = FakeSource()
    source.files["a.txt"] = b"a"
    monkeypatch.setattr(backup, "MANIFEST_VERSION", 7)
    meta = snap(source, None, "example.com", ["a.txt"], [], tmp_path / "bck")
    manifest = manifest_of(meta)
    assert manifest["format"] == backup.MANIFEST_FORMAT
    assert manifest["version"] == 7


def test_R24_webroot_identity_has_no_normalizer_owner():
    """R24-P2: ``files`` restored a snapshot through a normalizing webroot
    alias while SPEC requires the RAW recorded identity.  No module exports a
    normalizer now; restore selection, files selection and backup retention
    all compare the recorded value exactly."""
    import wpt.files as files
    import wpt.restore as restore

    for module in (backup, files, restore):
        assert not hasattr(module, "normalize_webroot"), module.__name__


def test_R7_P2_29_site_label_and_site_raw_must_agree(tmp_path):
    source = FakeSource()
    source.files["a.txt"] = b"a"
    with pytest.raises(ValueError, match="same site"):
        backup.create_snapshot(
            source, None, "a.example", ["a.txt"], [], tmp_path / "bck",
            BackupSettings(), "backup",
            site_raw="b.example", webroot=WEBROOT)
    assert not (tmp_path / "bck" / "a.example").exists()


# ------------------------------------------------------- round-8 regressions


@pytest.mark.parametrize("umask", [0o002, 0o022])
def test_R8_P2_13_snapshot_dirs_and_payloads_are_private(tmp_path, umask):
    """R8-P2-13: under umask 002/022 the snapshot stored wp-config and DB
    bytes group/world-readable.  Directories are 0700, payload and manifest
    0600, independent of the process umask."""
    import stat

    source = FakeSource()
    source.files["wp-config.php"] = b"<?php define('DB_PASSWORD', 'HUNTER2');"
    source.files["wp-content/uploads/a.txt"] = b"payload"
    old = os.umask(umask)
    try:
        meta = snap(source, None, "example.com",
                    ["wp-config.php", "wp-content/uploads/a.txt"], [],
                    tmp_path / "bck")
    finally:
        os.umask(old)

    directories = [meta.path.parent, meta.path]
    directories += [path for path in meta.path.rglob("*") if path.is_dir()]
    for directory in directories:
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700, directory
    files = [path for path in meta.path.rglob("*") if path.is_file()]
    assert files
    for path in files:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600, path
    assert meta.path / backup.FILES_DIR / "wp-config.php" in files


def test_R8_P2_17_backup_closes_the_http_session(monkeypatch, tmp_path):
    """R8-P2-17: run_backup closed source+bridge but leaked the session."""
    class _CloseRecordingSession(FakeSession):
        def __init__(self):
            super().__init__()
            self.closed = 0

        def close(self):
            self.closed += 1

    source = CliSource()
    source.files["a.txt"] = b"x"
    bridge = CliBridge([])
    session = _CloseRecordingSession()
    monkeypatch.setattr(backup, "remote_stack",
                        lambda ctx: (source, session, bridge))
    ctx = _bctx(tmp_path)

    assert backup.run_backup(ctx) == 0
    assert session.closed == 1


def test_R13_backup_protects_the_profile_a_programmatic_ctx_reads(
        monkeypatch, tmp_path):
    """R13-P2-12: the emitters passed ``(ctx.zip, ctx.sql)`` instead of
    ``report_protected_inputs(ctx)``, so a programmatic ``report_path``
    equal to the profile's markdown face replaced the settings file.  The
    shared owner refuses before bytes move, and the failure writer does not
    overwrite it either."""
    from wpt.settings import _DEFAULT_PROFILE

    profile = tmp_path / "profile.json"
    profile.write_bytes(_DEFAULT_PROFILE.read_bytes())
    report = profile.with_suffix(".md")
    before = profile.read_bytes()

    source = CliSource()
    source.files["readme.html"] = b"readme"
    bridge = CliBridge([{"name": "wp_posts", "rows": 1}])
    _stack(monkeypatch, source, bridge)
    ctx = _bctx(tmp_path, report_path=report,
                extra={"profile": profile})
    assert backup.run_backup(ctx) == 1
    assert profile.read_bytes() == before
    assert not report.exists()
