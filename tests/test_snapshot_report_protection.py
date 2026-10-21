"""R15-P1-1: a --report face can never land at or beneath a snapshot root.

Every route runs through the REAL CLI (``wpt.cli.main``): the pre-dispatch
gate for a selected/listed/undone snapshot, the shared writer for a
freshly created backup, and the actions registry for an action snapshot.
"""

from __future__ import annotations

from datetime import datetime, timezone

import wpt.backup as backup
from tests.fakes import FakeSession, FakeSource
from wpt.cli import main
from wpt.settings import BackupSettings


def _snapshot(tmp_path, *, label="example.com", webroot="public_html"):
    source = FakeSource()
    source.files["readme.html"] = b"ORIGINAL PAYLOAD"
    meta = backup.create_snapshot(
        source, None, label, ["readme.html"], [],
        tmp_path / "bck", BackupSettings(), "clean-files",
        site_raw=label, webroot=webroot)
    return meta.path


def _ftp_args(tmp_path):
    return [
        "--source", "ftp://example.com",
        "--webroot", "public_html",
        "--wp-url", "https://example.com",
        "--backup-dir", str(tmp_path / "bck"),
    ]


def test_R15_selected_payload_report_is_refused_by_the_cli(tmp_path):
    snapshot = _snapshot(tmp_path)
    manifest = snapshot / "manifest.json"
    # Replace the real manifest with a smaller sentinel whose bytes are
    # easy to prove untouched; the payload under files/ is real.
    manifest.write_text('{"format": "wpt-backup-manifest"}\n',
                        encoding="utf-8")
    payload = snapshot / "files" / "readme.html"
    before = (manifest.read_bytes(), payload.read_bytes())

    rc = main([
        *_ftp_args(tmp_path), "restore", snapshot.name,
        "--report", str(payload),
    ])
    assert rc == 1
    assert (manifest.read_bytes(), payload.read_bytes()) == before
    assert not payload.with_suffix(".json").exists()


def test_R15_files_restore_manifest_report_is_refused_by_the_cli(tmp_path):
    snapshot = _snapshot(tmp_path)
    manifest = snapshot / "manifest.json"
    before = manifest.read_bytes()

    rc = main([
        *_ftp_args(tmp_path), "files", "--restore", snapshot.name,
        "--report", str(snapshot / "manifest.md"),
    ])
    assert rc == 1
    assert manifest.read_bytes() == before
    assert not (snapshot / "manifest.md").exists()
    assert (snapshot / "manifest.json").is_file()


def test_R15_undo_last_early_refusal_never_overwrites_the_manifest(tmp_path):
    snapshot = _snapshot(tmp_path)
    manifest = snapshot / "manifest.json"
    before = manifest.read_bytes()

    # The bad deadline is refused BEFORE the command body; the refusal
    # writer must still resolve --undo-last's target snapshot.
    rc = main([
        *_ftp_args(tmp_path), "--deadline", "-1",
        "--report", str(snapshot / "manifest.md"), "restore", "--undo-last",
    ])
    assert rc == 1
    assert manifest.read_bytes() == before
    assert not (snapshot / "manifest.md").exists()
    assert (snapshot / "manifest.json").is_file()


def test_R15_list_mode_report_is_refused_for_every_listed_snapshot(tmp_path):
    snapshot = _snapshot(tmp_path)
    manifest = snapshot / "manifest.json"
    before = manifest.read_bytes()

    rc = main([
        *_ftp_args(tmp_path), "--report", str(snapshot / "manifest.md"),
        "restore",
    ])
    assert rc == 1
    assert manifest.read_bytes() == before
    assert not (snapshot / "manifest.md").exists()


def _files_snapshot(tmp_path, webroot, payload):
    from wpt.cli import Ctx
    from wpt.settings import load
    import wpt.files as files_mod

    ctx = Ctx(source="ftp://example.com", settings=load(), command="files",
              webroot=webroot, wp_url="https://example.com",
              backup_dir=tmp_path / "bck", extra={})
    state = files_mod._State(
        "wp-content/a.txt", True, len(payload), files_mod._sha256(payload),
        payload)
    return files_mod._create_snapshot(ctx, "files", [state]).path


def test_R16_files_restore_last_protects_every_candidate_it_reads(
        tmp_path, monkeypatch):
    """R16-P1: ``files --restore last`` reads each candidate manifest while
    filtering by identity, then restores only the selected one.  A report
    naming a DISCARDED candidate's manifest used to replace it (rc 0).  Every
    inspected root is now recorded, so the real CLI refuses and the
    candidate's manifest/payloads stay verifiable."""
    import wpt.files as files_mod
    from tests.fakes import FakeSource

    other = _files_snapshot(tmp_path, "other_html", b"OTHER")
    selected = _files_snapshot(tmp_path, "public_html", b"SELECTED")
    other_manifest = other / "manifest.json"
    before = other_manifest.read_bytes()
    source = FakeSource()
    source.files["wp-content/a.txt"] = b"MUTATED"
    monkeypatch.setattr(files_mod, "_open_source", lambda ctx: source)

    rc = main([
        *_ftp_args(tmp_path), "files", "--restore", "last", "--apply", "--yes",
        "--report", str(other / "manifest.md"),
    ])
    assert rc == 1
    assert other_manifest.read_bytes() == before
    assert (other / "files" / "wp-content" / "a.txt").read_bytes() == b"OTHER"
    # The files-snapshot identity/reader still parses the untouched manifest.
    assert files_mod._snapshot_identity(other) == ("example.com", "other_html")
    assert files_mod._snapshot_identity(selected) == (
        "example.com", "public_html")
    assert not (other / "manifest.md").exists()
    assert not (other / "manifest.json.json").exists()


def test_R17_files_restore_last_foreign_only_protects_every_inspected_root(
        tmp_path, monkeypatch):
    """R17-1-P1: when EVERY candidate belongs to another identity,
    ``_newest_snapshot`` raises AFTER reading each manifest.  The roots were
    recorded only on success, so a report under an inspected candidate
    replaced its payload.  The finally now records them."""
    import wpt.files as files_mod
    from tests.fakes import FakeSource

    other = _files_snapshot(tmp_path, "other_html", b"ORIGINAL-PAYLOAD")
    manifest = other / "manifest.json"
    payload = other / "files" / "wp-content" / "a.txt"
    before = (manifest.read_bytes(), payload.read_bytes())
    source = FakeSource()
    monkeypatch.setattr(files_mod, "_open_source", lambda ctx: source)

    rc = main([
        *_ftp_args(tmp_path), "files", "--restore", "last", "--apply", "--yes",
        "--report", str(payload),
    ])
    assert rc == 1
    assert (manifest.read_bytes(), payload.read_bytes()) == before
    assert not (other / "manifest.md").exists()
    assert files_mod._snapshot_identity(other) == ("example.com", "other_html")


def test_R17_an_unselected_files_snapshot_subtree_is_protected(tmp_path):
    """R17-8-P2: a report could replace an unselected ``files-*`` snapshot
    under --backup-dir (neither restore's timestamp listing nor the current
    run read it).  Snapshot-shaped directories in BOTH naming families are
    protected subtrees for every report face."""
    snapshot = _files_snapshot(tmp_path, "public_html", b"KEEP")
    manifest = snapshot / "manifest.json"
    before = manifest.read_bytes()

    rc = main([
        *_ftp_args(tmp_path), "--report", str(snapshot / "manifest.md"),
        "restore",
    ])
    assert rc == 1
    assert manifest.read_bytes() == before
    assert not (snapshot / "manifest.md").exists()


class _BackupBridge:
    """The two calls ``wpt backup`` makes: table discovery and teardown."""

    def __init__(self):
        self.calls = []

    def call(self, action, **_kw):
        self.calls.append(action)
        assert action == "db_audit"
        return {"tables": []}

    def call_stream(self, *_args, **_kwargs):
        return iter(())

    def destroy(self):
        self.calls.append("destroy")


def test_R18_a_report_into_a_future_snapshot_is_refused_before_the_backup(
        tmp_path, monkeypatch, capsys):
    """The snapshot a run is ABOUT to create is not a writable parent yet.
    R18 makes the missing-parent check pre-dispatch, so the backup body never
    runs: a report can never be aimed at (and later collide with) the
    rollback basis the same run would create."""
    fixed = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(backup, "_now", lambda: fixed)
    source = FakeSource()
    source.files["readme.html"] = b"<html>site</html>"
    bridge = _BackupBridge()
    monkeypatch.setattr(
        backup, "remote_stack",
        lambda ctx: (source, FakeSession(), bridge))

    snapshot = tmp_path / "bck" / "example.com" / "20260101-120000"
    rc = main([
        *_ftp_args(tmp_path), "backup",
        "--report", str(snapshot / "manifest.md"),
    ])

    assert rc == 1
    assert "no existing parent directory" in capsys.readouterr().err
    assert not snapshot.exists()
    assert bridge.calls == []
    assert "readme.html" in source.files


def test_R16_retention_reads_protect_every_inspected_snapshot(
        tmp_path, monkeypatch):
    """R16-P1: every backup runs retention, which READS each older
    candidate's manifest to prove identity.  Those roots are inputs too: a
    report naming an older manifest used to replace it (rc 0) while the new
    snapshot completed.  The real CLI now refuses and the old snapshot stays
    verifiable."""
    fixed = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(backup, "_now", lambda: fixed)
    old = _snapshot(tmp_path)
    old_manifest = old / "manifest.json"
    before = old_manifest.read_bytes()
    monkeypatch.setattr(
        backup, "_now",
        lambda: datetime(2026, 1, 2, 12, 0, 0, tzinfo=timezone.utc))
    source = FakeSource()
    source.files["readme.html"] = b"<html>site</html>"
    bridge = _BackupBridge()
    monkeypatch.setattr(
        backup, "remote_stack",
        lambda ctx: (source, FakeSession(), bridge))

    rc = main([
        *_ftp_args(tmp_path), "backup",
        "--report", str(old / "manifest.md"),
    ])
    assert rc == 1
    assert old_manifest.read_bytes() == before
    assert backup.verify_snapshot(old) is True
    assert not (old / "manifest.md").exists()
    new = tmp_path / "bck" / "example.com" / "20260102-120000"
    # R17: snapshot-shaped directories under --backup-dir are protected
    # INDEPENDENT of selection, so the refusal now precedes the body and the
    # new backup is never created.  Before R17 the body created it and only
    # the writer refused the report.
    assert not new.is_dir()
    assert bridge.calls == []


def test_R18_an_action_snapshot_report_parent_is_refused_before_apply(
        tmp_path, monkeypatch, capsys):
    """The registry's pre-action snapshot cannot be named by the report that
    the same run is about to write: the missing parent is refused BEFORE
    dispatch, so no snapshot is created and the action never mutates."""
    import wpt.audit

    fixed = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(backup, "_now", lambda: fixed)
    source = FakeSource()
    source.files["readme.html"] = b"junk"
    monkeypatch.setattr(
        wpt.audit, "remote_stack",
        lambda ctx: (source, FakeSession(), _BackupBridge()))

    snapshot = tmp_path / "bck" / "example.com" / "20260101-120000"
    rc = main([
        *_ftp_args(tmp_path), "clean-files", "--apply", "--yes",
        "--report", str(snapshot / "manifest.md"),
    ])

    assert rc == 1
    assert "no existing parent directory" in capsys.readouterr().err
    assert not snapshot.exists()
    assert "readme.html" in source.files
