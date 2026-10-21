"""Tests for ``wpt files`` (selected-file backup/edit/rollback).

Everything runs against an in-memory source (``tests.fakes.FakeSource``); the
FTP and zip construction seams are monkeypatched, so no network or real
archive is touched.  The backup directory and report path are per-test
``tmp_path`` values.
"""

import hashlib
import json
import os
import time
from pathlib import Path

import pytest

import wpt.files as files_mod
from tests.fakes import FakeSource
from wpt.backup import MANIFEST_MAX_BYTES, sanitize_site_label, site_label
from wpt.cli import Ctx
from wpt.deadline import Deadline
from wpt.settings import Settings
from wpt.types import SourceError, StopRequested


class RenameFake(FakeSource):
    """FakeSource plus the rename primitive the transaction needs."""

    def __init__(self) -> None:
        super().__init__()
        self.closed = False
        self.fail_rename_for: set[str] = set()
        self.rename_hook = None

    def rename(self, src, dst, *, allow_config=False, allow_core=False):
        self._check_rename_target(dst, allow_config, allow_core)
        if self.rename_hook is not None:
            self.rename_hook(src, dst, self)
        if dst in self.fail_rename_for:
            raise SourceError(f"rename failed: {src} -> {dst}")
        self._rec("rename", f"{src} -> {dst}")
        self.files[dst] = self.files.pop(src)

    def close(self):
        self.closed = True


class ApplyThenRaiseOnce(RenameFake):
    """A remote that applies the rename and then loses the response once."""

    def __init__(self) -> None:
        super().__init__()
        self.fail_after_apply: set[str] = set()

    def rename(self, src, dst, *, allow_config=False, allow_core=False):
        super().rename(src, dst, allow_config=allow_config,
                       allow_core=allow_core)
        if dst in self.fail_after_apply:
            self.fail_after_apply.remove(dst)
            raise SourceError(f"RNTO response lost for {dst}")


class DeleteThenRaiseOnce(RenameFake):
    """A remote that applies DELE and then loses the response once."""

    def __init__(self) -> None:
        super().__init__()
        self.fail_after_delete: set[str] = set()

    def delete(self, path):
        super().delete(path)
        if path in self.fail_after_delete:
            self.fail_after_delete.remove(path)
            raise SourceError(f"DELE response lost for {path}")


class UnreadableFake(RenameFake):
    """A path that exists and sizes but cannot be read as a regular file."""

    def __init__(self, unreadable: set[str]) -> None:
        super().__init__()
        self.unreadable = set(unreadable)
        for path in self.unreadable:
            self.files[path] = b""

    def read_bytes(self, path):
        if path in self.unreadable:
            raise SourceError(f"{path} is a directory or unreadable")
        return super().read_bytes(path)


def make_ctx(tmp_path, **overrides):
    extra = overrides.pop("extra", {})
    settings = overrides.pop("settings", None) or Settings()
    return Ctx(
        source=overrides.pop("source", "ftp://ftp.example.test"),
        settings=settings,
        command="files",
        apply=overrides.pop("apply", False),
        yes=overrides.pop("yes", False),
        webroot=overrides.pop("webroot", "public_html"),
        backup_dir=tmp_path / "backups",
        report_path=overrides.pop("report_path", None),
        zip=overrides.pop("zip", None),
        extra=extra,
        **overrides,
    )


def install_ftp(monkeypatch, fake):
    monkeypatch.setattr(files_mod, "ftp_source_for", lambda ctx: fake)
    return fake


def site_dir(ctx):
    return Path(ctx.backup_dir) / sanitize_site_label(site_label(ctx))


def snapshots(ctx, kind=None):
    root = site_dir(ctx)
    if not root.is_dir():
        return []
    found = [path for path in root.iterdir() if path.is_dir()]
    if kind is not None:
        found = [path for path in found if path.name.startswith(f"{kind}-")]
    return sorted(found)


def mutations(fake):
    return [(op, path) for _, op, path in fake.ops
            if op in ("write", "delete", "rename")]


def manifest_of(snapshot):
    return json.loads((snapshot / "manifest.json").read_text(encoding="utf-8"))


def sha(data):
    import hashlib

    return hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------------ backup


def test_backup_snapshots_two_files_and_an_absent_target(
        tmp_path, monkeypatch, capsys):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files.update({
        "wp-content/a.txt": b"alpha",
        "wp-content/sub/b.bin": bytes([0, 1, 2, 255]),
    })
    ctx = make_ctx(
        tmp_path,
        extra={"backup": ["wp-content/a.txt", "wp-content/sub/b.bin",
                          "wp-content/missing.txt"]},
        report_path=tmp_path / "files.md",
    )

    assert files_mod.run(ctx) == 0
    out = capsys.readouterr().out
    assert out.startswith("# wpt files — ftp.example.test\n")
    assert "Mode: backup" in out
    assert "Snapshot: " in out
    assert "| path | action | current | desired | status |" in out
    assert "wp-content/a.txt" in out
    assert mutations(fake) == []

    snaps = snapshots(ctx, "files")
    assert len(snaps) == 1
    snapshot = snaps[0]
    manifest = manifest_of(snapshot)
    assert manifest["format"] == "wpt-files"
    assert manifest["version"] == 1
    assert manifest["kind"] == "files"
    assert manifest["site"] == "ftp.example.test"
    assert manifest["source"] == "ftp://ftp.example.test"
    assert manifest["webroot"] == "public_html"
    entries = {entry["path"]: entry for entry in manifest["files"]}
    assert list(entries) == [
        "wp-content/a.txt", "wp-content/sub/b.bin", "wp-content/missing.txt",
    ]
    assert entries["wp-content/a.txt"]["exists"] is True
    assert entries["wp-content/a.txt"]["size"] == 5
    assert entries["wp-content/a.txt"]["sha256"] == sha(b"alpha")
    assert entries["wp-content/a.txt"]["stored"] == "files/wp-content/a.txt"
    assert entries["wp-content/missing.txt"] == {
        "path": "wp-content/missing.txt", "exists": False, "size": 0,
        "sha256": None, "stored": None,
    }
    assert (snapshot / "files" / "wp-content" / "a.txt").read_bytes() == b"alpha"
    assert (snapshot / "files" / "wp-content" / "sub" / "b.bin").read_bytes() \
        == bytes([0, 1, 2, 255])
    assert not any(".tmp" in path.name for path in snapshot.rglob("*"))

    report_md = (tmp_path / "files.md").read_text(encoding="utf-8")
    assert report_md == out
    report = json.loads((tmp_path / "files.json").read_text(encoding="utf-8"))
    assert report["command"] == "files"
    assert report["mode"] == "backup"
    assert report["site"] == "ftp.example.test"
    assert report["snapshot"] == str(snapshot)
    assert report["applied"] is False
    assert report["totals"]["files"] == 3
    assert report["totals"]["captured"] == 2
    assert report["totals"]["absent"] == 1
    rows = {row["path"]: row for row in report["files"]}
    assert rows["wp-content/a.txt"]["exists"] is True
    assert rows["wp-content/a.txt"]["sha256"] == sha(b"alpha")
    assert rows["wp-content/missing.txt"]["sha256"] is None


def test_local_mode_backup_reads_the_zip_source(tmp_path, monkeypatch):
    fake = RenameFake()
    fake.files["wp-content/a.txt"] = b"from zip"
    opened = []

    def zip_source(path, **kwargs):
        opened.append(Path(path))
        return fake

    monkeypatch.setattr(files_mod, "ZipSource", zip_source)
    monkeypatch.setattr(files_mod, "ftp_source_for", lambda ctx: (
        pytest.fail("ftp_source_for must not be used in local mode")))
    ctx = make_ctx(
        tmp_path, source="local", zip=tmp_path / "site.zip", webroot=None,
        extra={"backup": ["wp-content/a.txt"]},
    )

    assert files_mod.run(ctx) == 0
    assert opened == [tmp_path / "site.zip"]
    assert fake.closed is True
    snaps = snapshots(ctx, "files")
    assert len(snaps) == 1
    manifest = manifest_of(snaps[0])
    assert manifest["source"] == "local"
    assert manifest["webroot"] == ""
    assert manifest["site"] == "local-site.zip"


def test_backup_may_read_a_protected_file(tmp_path, monkeypatch):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-config.php"] = b"<?php // config"
    ctx = make_ctx(tmp_path, extra={"backup": ["wp-config.php"]})

    assert files_mod.run(ctx) == 0
    snapshot = snapshots(ctx, "files")[0]
    entry = manifest_of(snapshot)["files"][0]
    assert entry["path"] == "wp-config.php"
    assert entry["exists"] is True
    assert (snapshot / "files" / "wp-config.php").read_bytes() \
        == b"<?php // config"
    assert mutations(fake) == []


# -------------------------------------------------------------------- edit


def test_edit_dry_run_plans_without_snapshot_or_writes(
        tmp_path, monkeypatch, capsys):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"old"
    local = tmp_path / "new.txt"
    local.write_bytes(b"new")
    ctx = make_ctx(
        tmp_path, apply=False, yes=False, report_path=tmp_path / "files.md",
        extra={"paths": ["wp-content/a.txt"], "from_paths": [str(local)]},
    )

    assert files_mod.run(ctx) == 0
    out = capsys.readouterr().out
    assert "Mode: edit" in out
    assert "Applied: no" in out
    assert "planned" in out
    assert mutations(fake) == []
    assert snapshots(ctx) == []
    report = json.loads((tmp_path / "files.json").read_text(encoding="utf-8"))
    assert report["applied"] is False
    assert report["snapshot"] is None
    assert report["files"][0]["status"] == "planned"


def test_edit_apply_writes_new_and_existing_targets(
        tmp_path, monkeypatch, capsys):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/existing.txt"] = b"old body"
    local_existing = tmp_path / "existing.txt"
    local_existing.write_bytes(b"new body")
    local_new = tmp_path / "created.txt"
    local_new.write_bytes(b"created body")
    ctx = make_ctx(
        tmp_path, apply=True, yes=True, report_path=tmp_path / "files.md",
        extra={
            "paths": ["wp-content/existing.txt", "wp-content/created.txt"],
            "from_paths": [str(local_existing), str(local_new)],
        },
    )

    assert files_mod.run(ctx) == 0
    assert fake.files["wp-content/existing.txt"] == b"new body"
    assert fake.files["wp-content/created.txt"] == b"created body"
    assert not any(".wpt-edit-" in path for path in fake.files)

    snaps = snapshots(ctx, "edit")
    assert len(snaps) == 1
    snapshot = snaps[0]
    manifest = manifest_of(snapshot)
    assert manifest["kind"] == "edit"
    entries = {entry["path"]: entry for entry in manifest["files"]}
    assert entries["wp-content/existing.txt"]["exists"] is True
    assert entries["wp-content/existing.txt"]["sha256"] == sha(b"old body")
    assert entries["wp-content/created.txt"]["exists"] is False
    assert (snapshot / "files" / "wp-content" / "existing.txt").read_bytes() \
        == b"old body"

    report = json.loads((tmp_path / "files.json").read_text(encoding="utf-8"))
    assert report["applied"] is True
    assert report["snapshot"] == str(snapshot)
    assert {row["status"] for row in report["files"]} == {"written"}
    assert "transaction committed" in capsys.readouterr().out


def test_edit_apply_without_yes_or_tty_refuses_before_any_write(
        tmp_path, monkeypatch):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"old"
    local = tmp_path / "new.txt"
    local.write_bytes(b"new")
    ctx = make_ctx(
        tmp_path, apply=True, yes=False, report_path=tmp_path / "files.md",
        extra={"paths": ["wp-content/a.txt"], "from_paths": [str(local)]},
    )

    class NoTty:
        def isatty(self):
            return False

    from wpt.actions import registry
    monkeypatch.setattr(registry.sys, "stdin", NoTty())

    assert files_mod.run(ctx) == 1
    assert mutations(fake) == []
    assert snapshots(ctx) == []
    report = (tmp_path / "files.md").read_text(encoding="utf-8")
    assert report.startswith("# wpt files — ")
    assert "files (edit) — the run did not complete" in report


def test_edit_rename_failure_rolls_back_already_changed_targets(
        tmp_path, monkeypatch):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"old a"
    fake.files["wp-content/b.txt"] = b"old b"
    fake.fail_rename_for = {"wp-content/b.txt"}
    local_a = tmp_path / "a.txt"
    local_a.write_bytes(b"new a")
    local_b = tmp_path / "b.txt"
    local_b.write_bytes(b"new b")
    ctx = make_ctx(
        tmp_path, apply=True, yes=True, report_path=tmp_path / "files.md",
        extra={
            "paths": ["wp-content/a.txt", "wp-content/b.txt"],
            "from_paths": [str(local_a), str(local_b)],
        },
    )

    assert files_mod.run(ctx) == 1
    assert fake.files["wp-content/a.txt"] == b"old a"
    assert fake.files["wp-content/b.txt"] == b"old b"
    assert not any(".wpt-edit-" in path for path in fake.files)
    snaps = snapshots(ctx, "edit")
    assert len(snaps) == 1
    assert (snaps[0] / "files" / "wp-content" / "a.txt").read_bytes() == b"old a"
    report = (tmp_path / "files.md").read_text(encoding="utf-8")
    assert report.startswith("# wpt files — ")
    assert "files (edit) — the run did not complete" in report


def test_edit_concurrent_change_aborts_and_rolls_back(
        tmp_path, monkeypatch, wpt_records):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"old a"
    fake.files["wp-content/b.txt"] = b"old b"

    def hook(_src, dst, store):
        if dst == "wp-content/a.txt":
            store.files["wp-content/b.txt"] = b"concurrent edit"

    fake.rename_hook = hook
    local_a = tmp_path / "a.txt"
    local_a.write_bytes(b"new a")
    local_b = tmp_path / "b.txt"
    local_b.write_bytes(b"new b")
    ctx = make_ctx(
        tmp_path, apply=True, yes=True, report_path=tmp_path / "files.md",
        extra={
            "paths": ["wp-content/a.txt", "wp-content/b.txt"],
            "from_paths": [str(local_a), str(local_b)],
        },
    )

    assert files_mod.run(ctx) == 1
    assert fake.files["wp-content/a.txt"] == b"old a"
    assert fake.files["wp-content/b.txt"] == b"concurrent edit"
    assert not any(".wpt-edit-" in path for path in fake.files)
    assert len(snapshots(ctx, "edit")) == 1
    assert any("concurrent change" in record.getMessage()
               for record in wpt_records if record.levelname == "ERROR")


def test_edit_detects_a_change_during_the_temp_upload(
        tmp_path, monkeypatch, wpt_records):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"old a"
    original = fake.write_bytes

    def write(path, data, **kwargs):
        if ".wpt-edit-" in path:
            fake.files["wp-content/a.txt"] = b"concurrent edit"
        return original(path, data, **kwargs)

    fake.write_bytes = write
    local = tmp_path / "a.txt"
    local.write_bytes(b"new a")
    ctx = make_ctx(
        tmp_path, apply=True, yes=True, report_path=tmp_path / "files.md",
        extra={"paths": ["wp-content/a.txt"], "from_paths": [str(local)]},
    )

    assert files_mod.run(ctx) == 1
    assert fake.files["wp-content/a.txt"] == b"concurrent edit"
    assert not any(".wpt-edit-" in path for path in fake.files)
    assert len(snapshots(ctx, "edit")) == 1
    assert any("concurrent change" in record.getMessage()
               for record in wpt_records)


def test_edit_reads_a_directory_target_as_a_clear_error_before_writes(
        tmp_path, monkeypatch):
    fake = install_ftp(monkeypatch, UnreadableFake({"wp-content/dir"}))
    local = tmp_path / "new.txt"
    local.write_bytes(b"new")
    ctx = make_ctx(
        tmp_path, apply=True, yes=True, report_path=tmp_path / "files.md",
        extra={"paths": ["wp-content/dir"], "from_paths": [str(local)]},
    )

    assert files_mod.run(ctx) == 1
    assert mutations(fake) == []
    assert snapshots(ctx) == []
    report = (tmp_path / "files.md").read_text(encoding="utf-8")
    assert "regular file" in report


# ------------------------------------------------------- path / bounds gates


@pytest.mark.parametrize("bad", [
    "../wp-content/a.txt",
    "/etc/passwd",
    "wp-content/../../a.txt",
    "",
    ".",
    "wp-content//a.txt",
    "wp-content/./a.txt",
    "C:\\Windows\\win.ini",
    "wp-content/a\x00.txt",
    "wp-content/a\n.txt",
    "wp-content/a:b.txt",
    "wp-content/.. /wp-config.php",
    "wp-config.php.",
])
def test_unsafe_path_is_refused_before_any_read_or_write(
        tmp_path, monkeypatch, bad):
    fake = install_ftp(monkeypatch, RenameFake())
    ctx = make_ctx(tmp_path, extra={"backup": [bad]})

    assert files_mod.run(ctx) == 1
    assert mutations(fake) == []
    assert snapshots(ctx) == []


def test_case_insensitive_duplicate_paths_are_refused(tmp_path, monkeypatch):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"x"
    ctx = make_ctx(
        tmp_path,
        extra={"backup": ["wp-content/a.txt", "WP-CONTENT/A.TXT"]},
    )

    assert files_mod.run(ctx) == 1
    assert mutations(fake) == []
    assert snapshots(ctx) == []


def test_duplicate_paths_are_refused_after_normalization(tmp_path, monkeypatch):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"x"
    ctx = make_ctx(
        tmp_path,
        extra={"backup": ["wp-content/a.txt", "wp-content\\a.txt"]},
    )

    assert files_mod.run(ctx) == 1
    assert mutations(fake) == []
    assert snapshots(ctx) == []


def test_masked_exists_false_is_caught_by_the_parent_listing(
        tmp_path, monkeypatch):
    class MaskedExists(RenameFake):
        def exists(self, path):
            if path == "wp-content/a.txt":
                return False
            return super().exists(path)

    fake = install_ftp(monkeypatch, MaskedExists())
    fake.files["wp-content/a.txt"] = b"present"
    ctx = make_ctx(tmp_path, extra={"backup": ["wp-content/a.txt"]},
                   report_path=tmp_path / "files.md")

    assert files_mod.run(ctx) == 1
    assert snapshots(ctx) == []
    assert "parent listing contains it" in (
        tmp_path / "files.md").read_text(encoding="utf-8")


def test_max_files_is_enforced_before_capture(tmp_path, monkeypatch):
    settings = Settings()
    settings.files.max_files = 1
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"x"
    fake.files["wp-content/b.txt"] = b"y"
    ctx = make_ctx(
        tmp_path, settings=settings,
        extra={"backup": ["wp-content/a.txt", "wp-content/b.txt"]},
    )

    assert files_mod.run(ctx) == 1
    assert mutations(fake) == []
    assert snapshots(ctx) == []


def test_max_file_bytes_is_enforced_for_backup_and_edit(
        tmp_path, monkeypatch):
    settings = Settings()
    settings.files.max_file_bytes = 4
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/big.txt"] = b"12345"

    backup_ctx = make_ctx(
        tmp_path, settings=settings,
        extra={"backup": ["wp-content/big.txt"]},
    )
    assert files_mod.run(backup_ctx) == 1
    assert snapshots(backup_ctx) == []

    local = tmp_path / "big.txt"
    local.write_bytes(b"12345")
    edit_ctx = make_ctx(
        tmp_path, settings=settings, apply=True, yes=True,
        extra={"paths": ["wp-content/big.txt"], "from_paths": [str(local)]},
    )
    assert files_mod.run(edit_ctx) == 1
    assert mutations(fake) == []
    assert snapshots(edit_ctx) == []


def test_R11_backup_reads_a_root_core_file_but_edit_refuses_it(
        tmp_path, monkeypatch):
    """R11-P2-6: a backup is evidence and reads core source; an edit must
    refuse the same path before any write."""
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-load.php"] = b"<?php // core loader"
    backup_ctx = make_ctx(tmp_path, extra={"backup": ["wp-load.php"]})
    assert files_mod.run(backup_ctx) == 0
    snapshot = snapshots(backup_ctx, "files")[0]
    assert (snapshot / "files" / "wp-load.php").read_bytes() \
        == b"<?php // core loader"

    local = tmp_path / "new.php"
    local.write_bytes(b"<?php // replaced")
    edit_ctx = make_ctx(
        tmp_path, apply=True, yes=True,
        extra={"paths": ["wp-load.php"], "from_paths": [str(local)]},
    )
    assert files_mod.run(edit_ctx) == 1
    assert fake.files["wp-load.php"] == b"<?php // core loader"


@pytest.mark.parametrize("path", [
    "wp-config.php", "wp-admin/x.php", "index.php", ".htaccess",
    "WP-CONFIG.PHP", "wp-content/uploads/.htaccess", "wp-admin./x.php",
    "wp-load.php", "wp-settings.php", "wp-blog-header.php",
    "wp-cron.php", "wp-login.php", "xmlrpc.php", "wp-signup.php",
    "wp-activate.php", "wp-trackback.php", "wp-comments-post.php",
    "wp-mail.php", "wp-links-opml.php", "wp-config-sample.php",
])
def test_protected_edit_targets_are_refused_before_any_write(
        tmp_path, monkeypatch, path):
    fake = install_ftp(monkeypatch, RenameFake())
    local = tmp_path / "new.txt"
    local.write_bytes(b"new")
    ctx = make_ctx(
        tmp_path, apply=True, yes=True,
        extra={"paths": [path], "from_paths": [str(local)]},
    )

    assert files_mod.run(ctx) == 1
    assert mutations(fake) == []
    assert snapshots(ctx) == []


def test_R11_report_may_not_overwrite_a_files_from_local_source(
        tmp_path, monkeypatch):
    """R11-P2-15: --report was compared only with --zip/--sql.  ``files
    --path ... --from source.txt --report source.txt`` replaced the local
    source with the report markdown after the edit was applied."""
    from wpt.cli import main

    monkeypatch.setenv("WPT_PASS", "secret")
    source = tmp_path / "source.txt"
    source.write_bytes(b"LOCAL SOURCE BODY")
    before = source.read_bytes()

    def _never(_ctx):
        raise AssertionError("the remote stack must not be reached")

    monkeypatch.setattr(files_mod, "ftp_source_for", _never)

    rc = main(["--source", "ftp://ftp.example.test", "--user", "u",
               "--password-env", "WPT_PASS", "--webroot", "public_html",
               "--report", str(source), "files",
               "--path", "wp-content/a.txt", "--from", str(source),
               "--apply", "--yes"])

    assert rc == 1
    assert source.read_bytes() == before
    assert not source.with_suffix(".json").exists()


def test_restoring_a_protected_snapshot_is_refused(tmp_path, monkeypatch):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-config.php"] = b"<?php // config"
    backup_ctx = make_ctx(tmp_path, extra={"backup": ["wp-config.php"]})
    assert files_mod.run(backup_ctx) == 0
    snapshot = snapshots(backup_ctx, "files")[0]
    fake.files["wp-config.php"] = b"<?php // edited"

    restore_ctx = make_ctx(
        tmp_path, apply=True, yes=True, report_path=tmp_path / "restore.md",
        extra={"restore": snapshot.name},
    )
    assert files_mod.run(restore_ctx) == 1
    assert fake.files["wp-config.php"] == b"<?php // edited"
    assert mutations(fake) == []
    assert snapshots(restore_ctx, "restore") == []


# ----------------------------------------------------------------- restore


def test_restore_apply_restores_bytes_and_snapshots_current_state(
        tmp_path, monkeypatch):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"old a"
    fake.files["wp-content/b.txt"] = b"old b"
    backup_ctx = make_ctx(
        tmp_path, extra={"backup": ["wp-content/a.txt", "wp-content/b.txt"]},
    )
    assert files_mod.run(backup_ctx) == 0
    snapshot = snapshots(backup_ctx, "files")[0]

    fake.files["wp-content/a.txt"] = b"changed a"
    fake.files.pop("wp-content/b.txt")
    restore_ctx = make_ctx(
        tmp_path, apply=True, yes=True, report_path=tmp_path / "restore.md",
        extra={"restore": snapshot.name},
    )

    assert files_mod.run(restore_ctx) == 0
    assert fake.files["wp-content/a.txt"] == b"old a"
    assert fake.files["wp-content/b.txt"] == b"old b"
    assert not any(".wpt-edit-" in path for path in fake.files)

    rollback = snapshots(restore_ctx, "restore")
    assert len(rollback) == 1
    entries = {entry["path"]: entry
               for entry in manifest_of(rollback[0])["files"]}
    assert entries["wp-content/a.txt"]["exists"] is True
    assert entries["wp-content/a.txt"]["sha256"] == sha(b"changed a")
    assert entries["wp-content/b.txt"]["exists"] is False
    assert (rollback[0] / "files" / "wp-content" / "a.txt").read_bytes() \
        == b"changed a"

    report = json.loads((tmp_path / "restore.json").read_text(encoding="utf-8"))
    assert report["mode"] == "restore"
    assert report["applied"] is True
    assert report["snapshot"] == str(snapshot)
    assert report["totals"]["written"] == 2


def test_restore_last_resolves_the_newest_files_snapshot(
        tmp_path, monkeypatch):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"old"
    backup_ctx = make_ctx(tmp_path, extra={"backup": ["wp-content/a.txt"]})
    assert files_mod.run(backup_ctx) == 0
    fake.files["wp-content/a.txt"] = b"mutated"

    restore_ctx = make_ctx(
        tmp_path, apply=True, yes=True,
        extra={"restore": "last"},
    )
    assert files_mod.run(restore_ctx) == 0
    assert fake.files["wp-content/a.txt"] == b"old"


def test_restore_last_refuses_a_corrupt_newest_snapshot(
        tmp_path, monkeypatch):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"old"
    backup_ctx = make_ctx(tmp_path, extra={"backup": ["wp-content/a.txt"]})
    assert files_mod.run(backup_ctx) == 0
    fake.files["wp-content/a.txt"] = b"mutated"

    newer = site_dir(backup_ctx) / "files-29990101T000000Z-abcdef"
    newer.mkdir()
    (newer / "manifest.json").write_text("not json", encoding="utf-8")
    ctx = make_ctx(
        tmp_path, apply=True, yes=True, report_path=tmp_path / "restore.md",
        extra={"restore": "last"},
    )

    assert files_mod.run(ctx) == 1
    assert fake.files["wp-content/a.txt"] == b"mutated"
    assert mutations(fake) == []
    assert "not valid JSON" in (tmp_path / "restore.md").read_text(encoding="utf-8")


def test_R16_restore_keeps_the_selected_snapshot_and_accumulates_roots(
        tmp_path, monkeypatch):
    """R16-P2: the pre-restore rollback snapshot overwrote
    ``snapshot_dir``, so the shared writer protected only the rollback and
    re-resolved ``last`` after it existed — the selected payload became
    writable.  The selected root stays selected and BOTH roots accumulate."""
    from wpt.report import (report_input_collision, report_protected_inputs,
                            report_protected_subtrees)

    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"old"
    backup_ctx = make_ctx(tmp_path, extra={"backup": ["wp-content/a.txt"]})
    assert files_mod.run(backup_ctx) == 0
    selected = snapshots(backup_ctx, "files")[0]
    fake.files["wp-content/a.txt"] = b"mutated"

    ctx = make_ctx(tmp_path, apply=True, yes=True,
                   extra={"restore": "last"})
    assert files_mod.run(ctx) == 0
    assert fake.files["wp-content/a.txt"] == b"old"
    assert ctx.extra["snapshot_dir"] == str(selected)
    roots = [Path(raw) for raw in ctx.extra["snapshot_roots"]]
    assert selected in roots
    rollback = snapshots(ctx, "restore")
    assert len(rollback) == 1 and rollback[0] in roots
    payload = selected / "files" / "wp-content" / "a.txt"
    assert report_input_collision(
        payload, report_protected_inputs(ctx),
        subtrees=report_protected_subtrees(ctx)) == selected
    assert payload.read_bytes() == b"old"


def test_restore_accepts_an_explicit_path(tmp_path, monkeypatch):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"old"
    backup_ctx = make_ctx(tmp_path, extra={"backup": ["wp-content/a.txt"]})
    assert files_mod.run(backup_ctx) == 0
    snapshot = snapshots(backup_ctx, "files")[0]
    fake.files["wp-content/a.txt"] = b"mutated"

    restore_ctx = make_ctx(
        tmp_path, apply=True, yes=True,
        extra={"restore": str(snapshot)},
    )
    assert files_mod.run(restore_ctx) == 0
    assert fake.files["wp-content/a.txt"] == b"old"


@pytest.mark.parametrize("missing,needle", [
    ("site_raw", "does not record its raw site label"),
    ("webroot", "does not record its webroot"),
])
def test_NEW1_every_files_restore_requires_both_identity_keys(
        tmp_path, monkeypatch, missing, needle):
    """An old manifest must rc 1 on BOTH routes (managed name and explicit
    path): an explicit path selects the location, never a trust bypass."""
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"OLD"
    backup_ctx = make_ctx(tmp_path, extra={"backup": ["wp-content/a.txt"]})
    assert files_mod.run(backup_ctx) == 0
    snapshot = snapshots(backup_ctx, "files")[0]
    manifest_path = snapshot / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.pop(missing)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    fake.files["wp-content/a.txt"] = b"MUTATED"

    for route, reference in (("managed", snapshot.name),
                             ("explicit", str(snapshot))):
        report = tmp_path / f"restore-{route}.md"
        ctx = make_ctx(
            tmp_path, apply=True, yes=True, report_path=report,
            extra={"restore": reference})
        assert files_mod.run(ctx) == 1
        assert fake.files["wp-content/a.txt"] == b"MUTATED"
        assert needle in report.read_text(encoding="utf-8")


@pytest.mark.parametrize("route", ["managed", "explicit"])
def test_NEW1_missing_webroot_is_never_a_wildcard(
        tmp_path, monkeypatch, route):
    """An empty CURRENT webroot must not turn a manifest with no webroot key
    into a match (the missing key is not '' — it is not an identity)."""
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"OLD"
    backup_ctx = make_ctx(
        tmp_path, webroot="", extra={"backup": ["wp-content/a.txt"]})
    assert files_mod.run(backup_ctx) == 0
    snapshot = snapshots(backup_ctx, "files")[0]
    manifest_path = snapshot / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.pop("webroot")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    fake.files["wp-content/a.txt"] = b"MUTATED"

    reference = snapshot.name if route == "managed" else str(snapshot)
    report = tmp_path / f"restore-empty-{route}.md"
    ctx = make_ctx(
        tmp_path, webroot="", apply=True, yes=True, report_path=report,
        extra={"restore": reference})
    assert files_mod.run(ctx) == 1
    assert fake.files["wp-content/a.txt"] == b"MUTATED"
    assert "does not record its webroot" in report.read_text(encoding="utf-8")


def test_NEW1_explicit_files_path_never_crosses_sites(
        tmp_path, monkeypatch):
    """A current-format manifest from a different site is refused on the
    explicit path exactly like a managed one; ``www.`` is a distinct raw
    identity, not a normalized spelling."""
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"WWW-ORIGINAL"
    site_one = make_ctx(
        tmp_path, wp_url="https://www.site.test",
        extra={"backup": ["wp-content/a.txt"]})
    assert files_mod.run(site_one) == 0
    snapshot = snapshots(site_one, "files")[0]
    fake.files["wp-content/a.txt"] = b"APEX-LIVE"

    report = tmp_path / "restore-explicit.md"
    apex = make_ctx(
        tmp_path, apply=True, yes=True, wp_url="https://site.test",
        report_path=report, extra={"restore": str(snapshot)})
    assert files_mod.run(apex) == 1
    assert fake.files["wp-content/a.txt"] == b"APEX-LIVE"
    assert "cross-site restore" in report.read_text(encoding="utf-8")


def test_restore_dry_run_plans_and_writes_nothing(tmp_path, monkeypatch):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"old"
    backup_ctx = make_ctx(tmp_path, extra={"backup": ["wp-content/a.txt"]})
    assert files_mod.run(backup_ctx) == 0
    snapshot = snapshots(backup_ctx, "files")[0]
    fake.files["wp-content/a.txt"] = b"mutated"

    ctx = make_ctx(
        tmp_path, apply=False, report_path=tmp_path / "restore.md",
        extra={"restore": snapshot.name},
    )
    assert files_mod.run(ctx) == 0
    assert fake.files["wp-content/a.txt"] == b"mutated"
    assert mutations(fake) == []
    assert snapshots(ctx, "restore") == []
    report = json.loads((tmp_path / "restore.json").read_text(encoding="utf-8"))
    assert report["applied"] is False
    assert report["files"][0]["status"] == "planned"


def test_restore_refuses_a_different_webroot(tmp_path, monkeypatch):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"old"
    backup_ctx = make_ctx(tmp_path, extra={"backup": ["wp-content/a.txt"]})
    assert files_mod.run(backup_ctx) == 0
    snapshot = snapshots(backup_ctx, "files")[0]
    fake.files["wp-content/a.txt"] = b"mutated"

    ctx = make_ctx(
        tmp_path, apply=True, yes=True, webroot="other-webroot",
        report_path=tmp_path / "restore.md",
        extra={"restore": snapshot.name},
    )
    assert files_mod.run(ctx) == 1
    assert fake.files["wp-content/a.txt"] == b"mutated"
    assert mutations(fake) == []
    assert snapshots(ctx, "restore") == []
    report = (tmp_path / "restore.md").read_text(encoding="utf-8")
    assert "webroot" in report


def test_restore_refuses_a_bad_stored_sha_before_any_write(
        tmp_path, monkeypatch):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"alpha"
    backup_ctx = make_ctx(tmp_path, extra={"backup": ["wp-content/a.txt"]})
    assert files_mod.run(backup_ctx) == 0
    snapshot = snapshots(backup_ctx, "files")[0]
    stored = snapshot / "files" / "wp-content" / "a.txt"
    stored.write_bytes(b"bravo")  # same length, different SHA-256
    fake.files["wp-content/a.txt"] = b"mutated"

    ctx = make_ctx(
        tmp_path, apply=True, yes=True, report_path=tmp_path / "restore.md",
        extra={"restore": snapshot.name},
    )
    assert files_mod.run(ctx) == 1
    assert fake.files["wp-content/a.txt"] == b"mutated"
    assert mutations(fake) == []
    assert snapshots(ctx, "restore") == []
    report = (tmp_path / "restore.md").read_text(encoding="utf-8")
    assert "SHA-256 mismatch" in report


def test_restore_absent_record_deletes_an_added_target(tmp_path, monkeypatch):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/other.txt"] = b"kept"
    backup_ctx = make_ctx(
        tmp_path, extra={"backup": ["wp-content/added.txt"]},
    )
    assert files_mod.run(backup_ctx) == 0
    snapshot = snapshots(backup_ctx, "files")[0]
    fake.files["wp-content/added.txt"] = b"added later"

    ctx = make_ctx(
        tmp_path, apply=True, yes=True, report_path=tmp_path / "restore.md",
        extra={"restore": snapshot.name},
    )
    assert files_mod.run(ctx) == 0
    assert "wp-content/added.txt" not in fake.files
    assert fake.files["wp-content/other.txt"] == b"kept"
    rollback = snapshots(ctx, "restore")[0]
    entry = next(entry for entry in manifest_of(rollback)["files"]
                 if entry["path"] == "wp-content/added.txt")
    assert entry["exists"] is True
    assert (rollback / "files" / "wp-content" / "added.txt").read_bytes() \
        == b"added later"
    report = json.loads((tmp_path / "restore.json").read_text(encoding="utf-8"))
    assert report["files"][0]["status"] == "deleted"


def test_restore_failure_rolls_back_deletes_and_writes(
        tmp_path, monkeypatch):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/b.txt"] = b"old b"
    fake.files["wp-content/c.txt"] = b"old c"
    backup_ctx = make_ctx(
        tmp_path,
        extra={"backup": [
            "wp-content/a.txt", "wp-content/b.txt", "wp-content/c.txt",
        ]},
    )
    assert files_mod.run(backup_ctx) == 0
    snapshot = snapshots(backup_ctx, "files")[0]

    fake.files["wp-content/a.txt"] = b"added a"
    fake.files["wp-content/b.txt"] = b"changed b"
    fake.files["wp-content/c.txt"] = b"changed c"
    fake.fail_rename_for = {"wp-content/c.txt"}
    ctx = make_ctx(
        tmp_path, apply=True, yes=True, report_path=tmp_path / "restore.md",
        extra={"restore": snapshot.name},
    )

    assert files_mod.run(ctx) == 1
    assert fake.files["wp-content/a.txt"] == b"added a"
    assert fake.files["wp-content/b.txt"] == b"changed b"
    assert fake.files["wp-content/c.txt"] == b"changed c"
    assert not any(".wpt-edit-" in path for path in fake.files)
    assert len(snapshots(ctx, "restore")) == 1
    report = (tmp_path / "restore.md").read_text(encoding="utf-8")
    assert "files (restore) — the run did not complete" in report


def test_restore_rollback_incomplete_keeps_snapshot(
        tmp_path, monkeypatch, wpt_records):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/b.txt"] = b"old b"
    backup_ctx = make_ctx(
        tmp_path,
        extra={"backup": ["wp-content/a.txt", "wp-content/b.txt"]},
    )
    assert files_mod.run(backup_ctx) == 0
    snapshot = snapshots(backup_ctx, "files")[0]

    fake.files["wp-content/a.txt"] = b"added a"
    fake.files["wp-content/b.txt"] = b"changed b"
    fake.fail_rename_for = {
        "wp-content/a.txt", "wp-content/b.txt",
    }
    ctx = make_ctx(
        tmp_path, apply=True, yes=True, report_path=tmp_path / "restore.md",
        extra={"restore": snapshot.name},
    )

    assert files_mod.run(ctx) == 1
    assert len(snapshots(ctx, "restore")) == 1
    assert any("rollback incomplete" in record.getMessage()
               for record in wpt_records if record.levelname == "ERROR")
    assert not any(".wpt-edit-" in path for path in fake.files)


# ---------------------------------------------------------- local refusals


def test_malformed_wp_url_does_not_break_the_snapshot_label(
        tmp_path, monkeypatch):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"alpha"
    ctx = make_ctx(
        tmp_path, wp_url="https://[bad",
        extra={"backup": ["wp-content/a.txt"]},
        report_path=tmp_path / "files.md")

    assert files_mod.run(ctx) == 0
    assert any(path.name == "manifest.json"
               for path in Path(ctx.backup_dir).rglob("manifest.json"))
    assert (tmp_path / "files.md").read_text(encoding="utf-8").startswith(
        "# wpt files — ")


def test_applied_rename_that_raised_is_still_rolled_back(
        tmp_path, monkeypatch):
    fake = install_ftp(monkeypatch, ApplyThenRaiseOnce())
    fake.files.update({
        "a.txt": b"old-a",
        "b.txt": b"old-b",
    })
    local_a = tmp_path / "a.txt"
    local_b = tmp_path / "b.txt"
    local_a.write_bytes(b"new-a")
    local_b.write_bytes(b"new-b")
    fake.fail_after_apply.add("a.txt")
    ctx = make_ctx(
        tmp_path, apply=True, yes=True,
        extra={"paths": ["a.txt", "b.txt"],
               "from_paths": [str(local_a), str(local_b)]})

    assert files_mod.run(ctx) == 1
    assert fake.files["a.txt"] == b"old-a"
    assert fake.files["b.txt"] == b"old-b"
    assert not [path for path in fake.files if ".wpt-edit-" in path]


def test_rollback_leaves_a_concurrent_edit_and_reports_the_conflict(
        tmp_path, monkeypatch, wpt_records):
    class MutateAfterRename(RenameFake):
        def rename(self, src, dst, *, allow_config=False, allow_core=False):
            super().rename(src, dst, allow_config=allow_config,
                           allow_core=allow_core)
            if dst == "a.txt":
                self.files["a.txt"] = b"concurrent-after-write"

    fake = install_ftp(monkeypatch, MutateAfterRename())
    fake.files.update({"a.txt": b"old-a", "b.txt": b"old-b"})
    local_a = tmp_path / "a.txt"
    local_b = tmp_path / "b.txt"
    local_a.write_bytes(b"new-a")
    local_b.write_bytes(b"new-b")
    fake.fail_rename_for.add("b.txt")
    ctx = make_ctx(
        tmp_path, apply=True, yes=True,
        extra={"paths": ["a.txt", "b.txt"],
               "from_paths": [str(local_a), str(local_b)]},
        report_path=tmp_path / "files.md")

    assert files_mod.run(ctx) == 1
    assert fake.files["a.txt"] == b"concurrent-after-write"
    assert fake.files["b.txt"] == b"old-b"
    assert "changed concurrently during rollback" in (
        tmp_path / "files.md").read_text(encoding="utf-8")


def test_applied_delete_that_raised_is_restored_from_snapshot(
        tmp_path, monkeypatch):
    fake = install_ftp(monkeypatch, DeleteThenRaiseOnce())
    fake.files["gone.txt"] = b"keep-me"
    backup = make_ctx(tmp_path, extra={"backup": ["gone.txt"]})
    assert files_mod.run(backup) == 0
    snapshot = snapshots(backup, "files")[0]
    manifest = manifest_of(snapshot)
    manifest["files"][0].update({
        "exists": False, "size": 0, "sha256": None, "stored": None})
    (snapshot / "manifest.json").write_text(json.dumps(manifest),
                                             encoding="utf-8")
    fake.fail_after_delete.add("gone.txt")
    ctx = make_ctx(tmp_path, apply=True, yes=True,
                   extra={"restore": str(snapshot)})

    assert files_mod.run(ctx) == 1
    assert fake.files["gone.txt"] == b"keep-me"


@pytest.mark.parametrize("mode_extra", [
    {"paths": ["wp-content/a.txt"], "from_paths": ["LOCAL"]},
    {"restore": "last"},
])
def test_local_edit_and_restore_refuse_before_building_a_source(
        tmp_path, monkeypatch, mode_extra):
    class NeverZip(RenameFake):
        def __init__(self, path, **kwargs):
            pytest.fail("local edit/restore must refuse before opening the zip")

    monkeypatch.setattr(files_mod, "ZipSource", NeverZip)
    monkeypatch.setattr(files_mod, "ftp_source_for", lambda ctx: (
        pytest.fail("local mode must not build an ftp source")))
    local = tmp_path / "new.txt"
    local.write_bytes(b"new")
    extra = dict(mode_extra)
    if "from_paths" in extra:
        extra["from_paths"] = [str(local)]
    ctx = make_ctx(
        tmp_path, source="local", zip=tmp_path / "site.zip", webroot=None,
        apply=True, yes=True, report_path=tmp_path / "files.md", extra=extra,
    )

    assert files_mod.run(ctx) == 1
    report = (tmp_path / "files.md").read_text(encoding="utf-8")
    assert report.startswith("# wpt files — ")
    assert "— the run did not complete" in report


# ---------------------------------------------------------- run-level paths


def test_deadline_is_checked_before_any_remote_read(tmp_path, monkeypatch):
    from wpt.types import DeadlineExceeded

    class _Expired:
        def check(self, context):
            raise DeadlineExceeded("run deadline exceeded")

    monkeypatch.setattr(
        files_mod.Deadline, "from_ctx", lambda ctx: _Expired())
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"alpha"
    ctx = make_ctx(
        tmp_path, extra={"backup": ["wp-content/a.txt"]},
        report_path=tmp_path / "files.md")

    assert files_mod.run(ctx) == 1
    assert mutations(fake) == []
    assert snapshots(ctx) == []
    assert "deadline" in (tmp_path / "files.md").read_text(encoding="utf-8")


def test_oversized_manifest_is_refused_before_json_parsing(
        tmp_path, monkeypatch):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"alpha"
    backup = make_ctx(tmp_path, extra={"backup": ["wp-content/a.txt"]})
    assert files_mod.run(backup) == 0
    snapshot = snapshots(backup, "files")[0]
    (snapshot / "manifest.json").write_text(
        "x" * (MANIFEST_MAX_BYTES + 1), encoding="utf-8")
    restore = make_ctx(
        tmp_path, apply=True, yes=True,
        extra={"restore": str(snapshot)}, report_path=tmp_path / "r.md")

    assert files_mod.run(restore) == 1
    assert fake.files["wp-content/a.txt"] == b"alpha"


def test_fifo_manifest_is_refused_without_blocking(tmp_path, monkeypatch):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"alpha"
    backup = make_ctx(tmp_path, extra={"backup": ["wp-content/a.txt"]})
    assert files_mod.run(backup) == 0
    snapshot = snapshots(backup, "files")[0]
    manifest = snapshot / "manifest.json"
    manifest.unlink()
    os.mkfifo(manifest)

    restore = make_ctx(
        tmp_path, apply=True, yes=True,
        extra={"restore": str(snapshot)}, report_path=tmp_path / "r.md")
    assert files_mod.run(restore) == 1
    assert fake.files["wp-content/a.txt"] == b"alpha"


def test_source_is_closed_in_finally_on_success_and_failure(
        tmp_path, monkeypatch):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"x"
    ok_ctx = make_ctx(tmp_path, extra={"backup": ["wp-content/a.txt"]})
    assert files_mod.run(ok_ctx) == 0
    assert fake.closed is True

    fake.closed = False
    bad_ctx = make_ctx(tmp_path, extra={"backup": ["../escape"]})
    assert files_mod.run(bad_ctx) == 1
    assert fake.closed is True


def test_a_report_write_failure_returns_1(tmp_path, monkeypatch):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"x"
    ctx = make_ctx(
        tmp_path,
        extra={"backup": ["wp-content/a.txt"]},
        report_path=tmp_path / "missing-dir" / "files.md",
    )

    assert files_mod.run(ctx) == 1
    assert fake.closed is True
    # The snapshot itself completed before the report refusal.
    assert len(snapshots(ctx, "files")) == 1


def test_malformed_source_url_still_gets_a_redacted_failure_report(
        tmp_path, monkeypatch):
    ctx = make_ctx(
        tmp_path, source="ftp://user:sup3rsecret@[bad",
        extra={"backup": ["wp-content/a.txt"]},
        report_path=tmp_path / "files.md")

    assert files_mod.run(ctx) == 1
    markdown = ctx.report_path.read_text(encoding="utf-8")
    assert markdown.startswith("# wpt files — ")
    assert "sup3rsecret" not in markdown


def test_restore_refuses_a_stored_pointer_that_disagrees_with_path(
        tmp_path, monkeypatch):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files.update({
        "wp-content/a.txt": b"alpha",
        "wp-content/b.txt": b"beta",
    })
    backup = make_ctx(
        tmp_path,
        extra={"backup": ["wp-content/a.txt", "wp-content/b.txt"]})
    assert files_mod.run(backup) == 0
    snapshot = snapshots(backup, "files")[0]
    manifest = manifest_of(snapshot)
    manifest["files"][0]["stored"] = manifest["files"][1]["stored"]
    (snapshot / "manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8")

    restore = make_ctx(
        tmp_path, extra={"restore": str(snapshot)}, report_path=tmp_path / "r.md")
    assert files_mod.run(restore) == 1
    assert fake.files["wp-content/a.txt"] == b"alpha"


def test_failure_report_uses_the_command_title_and_source_summary(
        tmp_path, monkeypatch):
    install_ftp(monkeypatch, RenameFake())
    ctx = make_ctx(
        tmp_path, extra={"backup": ["../escape"]},
        report_path=tmp_path / "files.md",
    )

    assert files_mod.run(ctx) == 1
    report = (tmp_path / "files.md").read_text(encoding="utf-8")
    assert report.startswith("# wpt files — ftp.example.test\n")
    assert "files (backup) — the run did not complete" in report
    assert "## This run did not complete" in report


# ------------------------------------------------------- round-1 regressions


class LookupFails(RenameFake):
    """exists() says absent AND every listing fails: absence is unproven."""

    def exists(self, path):
        return False

    def list_dir(self, path):
        raise SourceError("control channel dead")


def test_FILES_1_unproven_absence_is_never_recorded_or_overwritten(
        tmp_path, monkeypatch):
    fake = install_ftp(monkeypatch, LookupFails())
    fake.files["wp-content/a.txt"] = b"PRESENT-SECRET"
    backup = make_ctx(
        tmp_path, extra={"backup": ["wp-content/a.txt"]},
        report_path=tmp_path / "backup.md")
    assert files_mod.run(backup) == 1
    assert snapshots(backup) == []
    assert "unproven" in (tmp_path / "backup.md").read_text(encoding="utf-8")

    local = tmp_path / "a.txt"
    local.write_bytes(b"OVERWRITE")
    edit = make_ctx(
        tmp_path, apply=True, yes=True,
        extra={"paths": ["wp-content/a.txt"], "from_paths": [str(local)]},
        report_path=tmp_path / "edit.md")
    assert files_mod.run(edit) == 1
    assert fake.files["wp-content/a.txt"] == b"PRESENT-SECRET"
    assert mutations(fake) == []


def test_FILES_2_rollback_detects_an_editor_during_the_rollback_upload(
        tmp_path, monkeypatch):
    class EditorDuringRollback(RenameFake):
        def __init__(self):
            super().__init__()
            self.a_temp_writes = 0

        def write_bytes(self, path, data, *, allow_config=False,
                        allow_core=False):
            super().write_bytes(path, data, allow_config=allow_config,
                                allow_core=allow_core)
            if ".a.txt.wpt-edit-" in path:
                self.a_temp_writes += 1
                if self.a_temp_writes == 2:   # the rollback's temp upload
                    self.files["a.txt"] = b"EDITOR-SAVED-THIS"

    fake = install_ftp(monkeypatch, EditorDuringRollback())
    fake.files.update({"a.txt": b"old-a", "b.txt": b"old-b"})
    local_a = tmp_path / "a.txt"
    local_b = tmp_path / "b.txt"
    local_a.write_bytes(b"new-a")
    local_b.write_bytes(b"new-b")
    fake.fail_rename_for.add("b.txt")
    ctx = make_ctx(
        tmp_path, apply=True, yes=True,
        extra={"paths": ["a.txt", "b.txt"],
               "from_paths": [str(local_a), str(local_b)]},
        report_path=tmp_path / "files.md")

    assert files_mod.run(ctx) == 1
    assert fake.files["a.txt"] == b"EDITOR-SAVED-THIS"
    assert "concurrent change detected" in (
        tmp_path / "files.md").read_text(encoding="utf-8")


def test_FILES_3_rollback_runs_after_the_run_deadline_expired(
        tmp_path, monkeypatch):
    class SlowRename(RenameFake):
        def rename(self, src, dst, *, allow_config=False, allow_core=False):
            if dst == "a.txt":
                time.sleep(0.08)
            super().rename(src, dst, allow_config=allow_config,
                           allow_core=allow_core)

    fake = install_ftp(monkeypatch, SlowRename())
    fake.files.update({"a.txt": b"old-a", "b.txt": b"old-b"})
    local_a = tmp_path / "a.txt"
    local_b = tmp_path / "b.txt"
    local_a.write_bytes(b"new-a")
    local_b.write_bytes(b"new-b")
    fake.fail_rename_for.add("b.txt")
    monkeypatch.setattr(files_mod.Deadline, "from_ctx",
                        lambda ctx: Deadline(0.05))
    ctx = make_ctx(
        tmp_path, apply=True, yes=True,
        extra={"paths": ["a.txt", "b.txt"],
               "from_paths": [str(local_a), str(local_b)]},
        report_path=tmp_path / "files.md")

    assert files_mod.run(ctx) == 1
    assert fake.files["a.txt"] == b"old-a"
    assert fake.files["b.txt"] == b"old-b"


def test_R11_rollback_restores_under_an_expired_REAL_FtpSource_deadline(
        tmp_path, monkeypatch):
    """R11-P1-3: ``_rollback`` passed ``deadline=None`` to its helpers, but
    the REAL FtpSource still honoured its attached run budget on every
    socket op.  An expired budget therefore suppressed the restore.  The
    Source deadline-suspend owner detaches it for cleanup and restores the
    exact budget afterwards."""
    from tests.sources.test_ftp import FakeFTPServer
    from wpt.settings import FtpSettings
    from wpt.sources.ftp import FtpSource

    srv = FakeFTPServer(fs={"": True, "a.txt": False},
                        contents={"a.txt": b"NEW-BYTES"})
    monkeypatch.setattr("wpt.sources.ftp.ftplib.FTP_TLS", srv.new_connection)
    expired = Deadline(-1)
    source = FtpSource("127.0.0.1", "user", "secret", "",
                       FtpSettings(), deadline=expired)

    old = files_mod._SnapshotEntry(
        path="a.txt", exists=True, size=len(b"OLD-BYTES"),
        sha256=hashlib.sha256(b"OLD-BYTES").hexdigest(), data=b"OLD-BYTES")
    want = files_mod._State(
        path="a.txt", exists=True, size=len(b"NEW-BYTES"),
        sha256=hashlib.sha256(b"NEW-BYTES").hexdigest(), data=b"NEW-BYTES")
    snapshot = files_mod._Snapshot(
        path=tmp_path / "snap", kind="files", webroot="", entries=[old])

    problems = files_mod._rollback(
        source, snapshot, [(old, want)], set(), 8 * 1024 * 1024)

    assert problems == ""
    assert srv.state["contents"]["a.txt"] == b"OLD-BYTES"
    assert source.deadline is expired  # restored, not left detached


def test_FILES_4_colliding_sanitized_labels_never_cross_restore(
        tmp_path, monkeypatch):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"SITE-ONE-SECRET"
    site_one = make_ctx(
        tmp_path, wp_url="https://bücher.example",
        extra={"backup": ["wp-content/a.txt"]})
    assert files_mod.run(site_one) == 0

    fake.files["wp-content/a.txt"] = b"SITE-TWO"
    snapshot = snapshots(site_one, "files")[0]
    site_two = make_ctx(
        tmp_path, wp_url="https://b-cher.example",
        apply=True, yes=True, extra={"restore": snapshot.name},
        report_path=tmp_path / "restore.md")
    assert files_mod.run(site_two) == 1
    assert fake.files["wp-content/a.txt"] == b"SITE-TWO"
    assert "cross-site restore" in (
        tmp_path / "restore.md").read_text(encoding="utf-8")


def test_FILES_5_bounded_read_is_used_with_the_settings_limit(
        tmp_path, monkeypatch):
    class RecordingBound(RenameFake):
        def __init__(self):
            super().__init__()
            self.bounds = []

        def size(self, path):
            return 1   # a lying SIZE: the bound must come from the read

        def read_bytes_bounded(self, path, max_bytes):
            self.bounds.append((path, max_bytes))
            return super().read_bytes(path)

    settings = Settings()
    settings.files.max_file_bytes = 3
    fake = install_ftp(monkeypatch, RecordingBound())
    fake.files["wp-content/big.txt"] = b"12345"
    ctx = make_ctx(tmp_path, settings=settings,
                   extra={"backup": ["wp-content/big.txt"]})

    assert files_mod.run(ctx) == 1
    assert fake.bounds == [("wp-content/big.txt", 3)]
    assert snapshots(ctx) == []


def test_FILES_4_last_selects_the_matching_site_among_colliding_labels(
        tmp_path, monkeypatch):
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"SITE-ONE-SECRET"
    site_one = make_ctx(
        tmp_path, wp_url="https://bücher.example",
        extra={"backup": ["wp-content/a.txt"]})
    assert files_mod.run(site_one) == 0

    fake.files["wp-content/a.txt"] = b"SITE-TWO"
    site_two = make_ctx(
        tmp_path, wp_url="https://b-cher.example",
        extra={"backup": ["wp-content/a.txt"]})
    assert files_mod.run(site_two) == 0

    restore = make_ctx(
        tmp_path, wp_url="https://bücher.example",
        apply=True, yes=True, extra={"restore": "last"})
    assert files_mod.run(restore) == 0
    assert fake.files["wp-content/a.txt"] == b"SITE-ONE-SECRET"


@pytest.mark.parametrize("path", [
    "wp-content/NUL", "CON", "COM1.txt", "LPT9", "nul.txt", "aux",
    "CLOCK$", "com¹", "wp-content/PRN.php",
])
def test_FILES_6_windows_device_names_are_refused(path):
    from wpt.types import WptError

    with pytest.raises(WptError, match="unsafe files target"):
        files_mod._safe_rel(path)


# ------------------------------------------------------- triple-check round 2


def test_FILE1_a_stop_during_snapshot_selection_is_not_a_corrupt_manifest(
        tmp_path, monkeypatch):
    """FILE1: ``_snapshot_identity`` returned None for StopRequested
    (a WptError), so ``--restore last --apply`` kept the candidate and could
    mutate after SIGTERM."""
    from wpt.types import StopRequested

    site = tmp_path / "site"
    for name in ("files-20260101T000000Z-aaaaaa",
                 "files-20260102T000000Z-bbbbbb"):
        directory = site / name
        directory.mkdir(parents=True)
        (directory / "manifest.json").write_text(
            json.dumps({"site_raw": "site.test"}), encoding="utf-8")

    calls = {"count": 0}
    real = files_mod.read_regular_bounded

    def stopping(path, limit, purpose, **kwargs):
        calls["count"] += 1
        raise StopRequested("received SIGTERM (15)")

    monkeypatch.setattr(files_mod, "read_regular_bounded", stopping)
    with pytest.raises(StopRequested):
        files_mod._newest_snapshot(site, site_identity="site.test")
    assert calls["count"] == 1

    # A plain WptError still yields None (kept as the corrupt-newest
    # candidate, never skipped in favour of an older snapshot).
    monkeypatch.setattr(files_mod, "read_regular_bounded", real)

    def unreadable(path, limit, purpose, **kwargs):
        raise files_mod.WptError("manifest unreadable")

    monkeypatch.setattr(files_mod, "read_regular_bounded", unreadable)
    assert files_mod._snapshot_identity(site) is None


class MaskedTempSource(RenameFake):
    """A source whose ``exists`` cannot see .wpt-edit- temp names."""

    def __init__(self, fail_delete=False):
        super().__init__()
        self.fail_delete = fail_delete
        self.deletes: list[str] = []

    def exists(self, path):
        if ".wpt-edit-" in path:
            return False          # the masked lookup the old code trusted
        return super().exists(path)

    def delete(self, path):
        self.deletes.append(path)
        if self.fail_delete:
            raise SourceError(f"delete refused: {path}")
        super().delete(path)


def test_FILE2_temp_cleanup_deletes_even_when_exists_is_masked(tmp_path):
    """FILE2: an ``exists()`` that maps a lookup failure to False left the
    temp holding the NEW bytes on the server, unreported."""
    fake = MaskedTempSource()
    temp = "wp-content/.b.txt.wpt-edit-deadbeef.tmp"
    fake.files[temp] = b"new-b"

    files_mod._cleanup_temps(fake, {temp})

    assert temp not in fake.files
    assert fake.deletes == [temp]


def test_FILE2_a_refused_delete_keeps_the_temp_and_proves_absence(tmp_path):
    fake = MaskedTempSource(fail_delete=True)
    temp = "wp-content/.b.txt.wpt-edit-deadbeef.tmp"
    fake.files[temp] = b"new-b"
    temps = {temp}

    files_mod._cleanup_temps(fake, temps)

    # The delete failed and the listing still contains the name: the
    # residue is NOT discarded from the report.
    assert temp in temps and temp in fake.files
    assert fake.deletes == [temp]

    # When the same delete refusal is followed by a PROVEN absence (the
    # server applied DELE and lost the response), the name may be dropped.
    class DeleteThenVanishes(MaskedTempSource):
        def delete(self, path):
            self.files.pop(path, None)
            raise SourceError("DELE response lost")

    vanishing = DeleteThenVanishes()
    vanishing.files[temp] = b"new-b"
    pending = {temp}
    files_mod._cleanup_temps(vanishing, pending)
    assert pending == set()


def test_FILE2_stop_during_temp_cleanup_finishes_every_name_then_reraises():
    """FILE2/N7: a SIGTERM landing inside temp cleanup was swallowed by the
    broad except; every surviving temp must still be attempted, then the
    first stop must end the run."""
    class StopOneTemp(RenameFake):
        def __init__(self):
            super().__init__()
            self.deletes: list[str] = []
            self.stop_path: str | None = None

        def delete(self, path):
            self.deletes.append(path)
            if path == self.stop_path:
                raise StopRequested("SIGTERM during temp cleanup")
            super().delete(path)

    fake = StopOneTemp()
    names = [f"wp-content/.f{index}.wpt-edit-dead.tmp" for index in range(3)]
    for name in names:
        fake.files[name] = b"new bytes"
    fake.stop_path = names[0]
    temps = set(names)

    with pytest.raises(StopRequested, match="temp cleanup"):
        files_mod._cleanup_temps(fake, temps)

    assert sorted(fake.deletes) == sorted(names)  # cleanup was completed
    assert temps == {names[0]}                    # the stopped temp remains
    assert names[1] not in fake.files and names[2] not in fake.files


def test_FILE2_cleanup_stop_does_not_mask_the_transaction_failure(tmp_path):
    """FILE2/N7: the stop is re-raised only when cleanup is the primary
    event; an ordinary transaction failure already unwinding must win."""
    class StopOnTempDelete(RenameFake):
        def delete(self, path):
            if ".wpt-edit-" in path:
                raise StopRequested("SIGTERM during cleanup")
            super().delete(path)

    source = StopOnTempDelete()
    path = "wp-content/a.txt"
    old_data = b"old"
    new_data = b"new!"
    source.files[path] = old_data
    snapshot = files_mod._Snapshot(
        path=tmp_path / "snapshot", kind="edit", webroot="",
        entries=[files_mod._SnapshotEntry(
            path=path, exists=True, size=len(old_data),
            sha256=hashlib.sha256(old_data).hexdigest(), data=old_data)])
    desired = files_mod._State(
        path=path, exists=True, size=len(new_data),
        sha256=hashlib.sha256(new_data).hexdigest(), data=new_data)
    source.fail_rename_for.add(path)

    with pytest.raises(files_mod.WptError, match="rename failed") as excinfo:
        files_mod._apply_transaction(source, snapshot, [desired], 1024)

    assert "rolled back 1 changed target" in str(excinfo.value)
    assert source.files[path] == old_data


class CaseFoldSource(FakeSource):
    """Case-insensitive remote store (Windows FTP), exact LIST spelling."""

    def exists(self, path):
        # The source's own answer is "absent" for the differently-cased
        # name; only the parent listing (casefolded) proves otherwise.
        return path in self.files

    def size(self, path):
        for key, value in self.files.items():
            if key.casefold() == path.casefold():
                return len(value)
        raise SourceError(f"no such file: {path}")


def test_FILE3_absence_proof_is_casefolded_on_a_case_insensitive_host():
    """FILE3: the listing carried ``wp-content/a.txt`` while the target was
    ``wp-content/A.TXT``; the exact compare "proved" absence and the edit
    overwrote the precious file."""
    fake = CaseFoldSource()
    fake.files["wp-content/a.txt"] = b"PRECIOUS"

    assert files_mod.absence_proven(fake, "wp-content/A.TXT") is False
    with pytest.raises(files_mod.WptError, match="parent listing contains it"):
        files_mod._read_state(fake, "wp-content/A.TXT", 1024, purpose="edit")


# ---------------------------------------------------- round-3 regressions


def test_SITE_IDENTITY_redaction_cannot_collapse_two_sites(tmp_path,
                                                           monkeypatch):
    """SITE-IDENTITY: the snapshot directory, site_raw and managed-restore
    comparison all used the REDACTED display label, so two distinct
    credential-bearing hosts shared 'password----' and cross-restored."""
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"SITE-ONE-SECRET"
    backup_ctx = make_ctx(
        tmp_path, wp_url="https://password=abc.example",
        extra={"backup": ["wp-content/a.txt"]})
    assert files_mod.run(backup_ctx) == 0
    snapshot = snapshots(backup_ctx, "files")[0]
    manifest = json.loads((snapshot / "manifest.json").read_text("utf-8"))
    assert manifest["site_raw"] == "password=abc.example"
    fake.files["wp-content/a.txt"] = b"SITE-TWO"

    cross = make_ctx(
        tmp_path, apply=True, yes=True,
        wp_url="https://password=def.example",
        report_path=tmp_path / "restore.md",
        extra={"restore": snapshot.name})
    assert files_mod.run(cross) == 1
    assert fake.files["wp-content/a.txt"] == b"SITE-TWO"
    assert "no files snapshot" in (tmp_path / "restore.md").read_text("utf-8")
    assert "password-abc.example" in str(snapshot)
    assert "password-def.example" not in str(snapshot)

    same = make_ctx(
        tmp_path, apply=True, yes=True,
        wp_url="https://password=abc.example",
        extra={"restore": snapshot.name})
    assert files_mod.run(same) == 0
    assert fake.files["wp-content/a.txt"] == b"SITE-ONE-SECRET"


def test_SITE_IDENTITY_legacy_identity_directories_are_not_searched(
        tmp_path, monkeypatch):
    """No pre-round-3 directory fallback: moving a snapshot to the old
    ``www.<host>`` / case-folded spelling makes it undiscoverable.  Lookup
    is the ONE exact raw identity directory."""
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"ORIGINAL"
    backup_ctx = make_ctx(
        tmp_path, wp_url="https://www.site.test",
        extra={"backup": ["wp-content/a.txt"]})
    assert files_mod.run(backup_ctx) == 0
    current = site_dir(backup_ctx)
    snapshot = next(current.iterdir())
    legacy = tmp_path / "backups" / "WWW.SITE.test"
    if legacy.exists():
        # A case-insensitive filesystem (macOS APFS default) cannot hold
        # both the raw identity and this legacy spelling; the premise of a
        # second, undiscoverable directory cannot be represented there.
        pytest.skip("case-insensitive filesystem cannot hold both identities")
    legacy.mkdir()
    snapshot.rename(legacy / snapshot.name)

    fake.files["wp-content/a.txt"] = b"CHANGED"
    restore_last = make_ctx(
        tmp_path, apply=True, yes=True, wp_url="https://www.site.test",
        extra={"restore": "last"})
    assert files_mod.run(restore_last) == 1
    assert fake.files["wp-content/a.txt"] == b"CHANGED"

    restore_named = make_ctx(
        tmp_path, apply=True, yes=True, wp_url="https://www.site.test",
        extra={"restore": snapshot.name})
    assert files_mod.run(restore_named) == 1
    assert fake.files["wp-content/a.txt"] == b"CHANGED"


def test_SITE_IDENTITY_exact_raw_label_is_not_normalized(
        tmp_path, monkeypatch):
    """``www.site.test`` and ``site.test`` are distinct raw identities: the old
    normalize_domain fallback must not make one restore the other's bytes."""
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"WWW-ORIGINAL"
    backup_ctx = make_ctx(
        tmp_path, wp_url="https://www.site.test",
        extra={"backup": ["wp-content/a.txt"]})
    assert files_mod.run(backup_ctx) == 0
    assert site_dir(backup_ctx).name == "www.site.test"
    fake.files["wp-content/a.txt"] = b"APEX-LIVE"

    apex_restore = make_ctx(
        tmp_path, apply=True, yes=True, wp_url="https://site.test",
        extra={"restore": "last"})
    assert files_mod.run(apex_restore) == 1
    assert fake.files["wp-content/a.txt"] == b"APEX-LIVE"
    assert not (tmp_path / "backups" / "site.test").exists()


def test_REPORT_TEMPS_a_surviving_temp_is_named_in_the_failure(tmp_path,
                                                               monkeypatch):
    """REPORT-TEMPS: the failure WptError dropped `temps`; a refused DELE
    left the NEW bytes in a temp named only by a log warning."""
    class RefuseTempDelete(RenameFake):
        def delete(self, path):
            if ".wpt-edit-" in path:
                raise SourceError(f"delete refused: {path}")
            super().delete(path)

        def write_bytes(self, path, data, *, allow_config=False,
                        allow_core=False):
            super().write_bytes(path, data, allow_config=allow_config,
                                allow_core=allow_core)
            if ".b.txt.wpt-edit-" in path:
                # An editor saves while the temp upload is in flight; the
                # checked write's final read must abort the transaction.
                self.files["b.txt"] = b"concurrent edit"

    fake = install_ftp(monkeypatch, RefuseTempDelete())
    fake.files["b.txt"] = b"old-b"
    local_b = tmp_path / "b.txt"
    local_b.write_bytes(b"new-b")
    ctx = make_ctx(
        tmp_path, apply=True, yes=True, report_path=tmp_path / "files.md",
        extra={"paths": ["b.txt"], "from_paths": [str(local_b)]})
    assert files_mod.run(ctx) == 1
    temps = [path for path in fake.files if ".wpt-edit-" in path]
    assert temps, "the refused DELE must leave the temp for the report"
    markdown = (tmp_path / "files.md").read_text(encoding="utf-8")
    twin = (tmp_path / "files.json").read_text(encoding="utf-8")
    assert any(temp in markdown for temp in temps)
    assert any(temp in twin for temp in temps)


def test_REPORT_DIRS_rollback_removes_only_directories_it_created(
        tmp_path, monkeypatch):
    """REPORT-DIRS: ensure_write_dir created newdir, rollback tracked files
    only, and the kept snapshot restored rc 0 with newdir still there."""
    class DirAware(RenameFake):
        def __init__(self):
            super().__init__()
            self.dirs: set[str] = set()

        def list_dir(self, path):
            entries = {entry.path: entry
                       for entry in super().list_dir(path)}
            rel = path if path else ""
            for directory in self.dirs:
                parent = directory.rpartition("/")[0]
                if parent == rel and directory not in entries:
                    from wpt.types import Entry
                    entries[directory] = Entry(directory, True, size=0)
            return list(entries.values())

        def write_bytes(self, path, data, *, allow_config=False,
                        allow_core=False):
            parent = path.rpartition("/")[0]
            while parent:
                self.dirs.add(parent)
                parent = parent.rpartition("/")[0]
            super().write_bytes(path, data, allow_config=allow_config,
                                allow_core=allow_core)

        def delete(self, path):
            super().delete(path)

        def rmdir(self, path):
            self._check_deletable(path)
            if self.list_dir(path):
                raise SourceError(f"directory is not empty: {path}")
            self.dirs = {d for d in self.dirs
                         if d != path and not d.startswith(path + "/")}

        def rmdir_recursive(self, path):
            self._check_deletable(path)
            for name in [n for n in self.files
                         if n == path or n.startswith(path + "/")]:
                self.files.pop(name, None)
            self.dirs = {d for d in self.dirs
                         if d != path and not d.startswith(path + "/")}

    fake = install_ftp(monkeypatch, DirAware())
    fake.files["b.txt"] = b"old-b"
    fake.fail_rename_for = {"b.txt"}
    local_a = tmp_path / "a.txt"
    local_a.write_bytes(b"new-a")
    local_b = tmp_path / "b.txt"
    local_b.write_bytes(b"new-b")
    ctx = make_ctx(
        tmp_path, apply=True, yes=True, report_path=tmp_path / "files.md",
        extra={"paths": ["newdir/a.txt", "b.txt"],
               "from_paths": [str(local_a), str(local_b)]})
    assert files_mod.run(ctx) == 1
    assert "newdir" not in fake.dirs
    assert "newdir/a.txt" not in fake.files
    assert fake.files["b.txt"] == b"old-b"

    restore = make_ctx(
        tmp_path, apply=True, yes=True, extra={"restore": "last"},
        report_path=tmp_path / "restore.md")
    assert files_mod.run(restore) == 0
    assert "newdir" not in fake.dirs


def test_REPORT_DIRS_a_late_file_survives_the_non_recursive_rmdir(
        tmp_path):
    """REPORT-DIRS TOCTOU: an emptiness listing followed by
    ``rmdir_recursive`` deleted a file that arrived in between.  Removal is
    now the non-recursive primitive: the host refuses a non-empty directory,
    the late file survives, and the residue is reported."""
    class LateFile(RenameFake):
        def __init__(self):
            super().__init__()
            self.recursive_calls = 0

        def rmdir(self, path):
            # The concurrent writer's file appears AFTER the last listing
            # the transaction performed, before the RMD reaches the host.
            self.files[f"{path}/late.txt"] = b"late"
            super().rmdir(path)

        def rmdir_recursive(self, path):
            self.recursive_calls += 1
            super().rmdir_recursive(path)

    fake = LateFile()
    fake.files["newdir/a.txt"] = b"transaction temp"
    problems = files_mod._remove_created_dirs(fake, ["newdir"])

    assert fake.files["newdir/late.txt"] == b"late"
    assert fake.recursive_calls == 0
    assert any("newdir" in problem and "could not be removed" in problem
               for problem in problems), problems


def test_CLOSE_STOP_scan_returns_1_and_still_reports(tmp_path, monkeypatch):
    """CLOSE-STOP: scan swallowed StopRequested from source.close and wrote
    a success report with rc 0."""
    from wpt.types import StopRequested
    import wpt.scan as scan_mod

    class StopOnClose(FakeSource):
        def close(self):
            raise StopRequested("SIGTERM during close")

    source = StopOnClose()
    source.files["x.php"] = b"<?php echo 'ok';"
    monkeypatch.setattr(scan_mod, "ZipSource", lambda path, **kwargs: source)
    monkeypatch.setattr(scan_mod, "gather_source",
                        lambda src, mode, deadline=None: _data_for(src, mode))
    ctx = make_ctx(
        tmp_path, source="local", zip=tmp_path / "z.zip",
        report_path=tmp_path / "scan.md", extra={})
    ctx.command = "scan"
    assert scan_mod.run(ctx) == 1
    report = (tmp_path / "scan.md").read_text(encoding="utf-8")
    assert "did not complete" in report


def _data_for(source, mode):
    from tests.audit.test_source_scan import data_for
    return data_for(source, mode)


def test_CLOSE_STOP_files_returns_1_and_still_reports(tmp_path, monkeypatch):
    """CLOSE-STOP: files.run swallowed StopRequested from close after the
    snapshot/write, answering rc 0."""
    from wpt.types import StopRequested

    class StopOnClose(RenameFake):
        def close(self):
            raise StopRequested("SIGTERM during close")

    fake = install_ftp(monkeypatch, StopOnClose())
    fake.files["a.txt"] = b"old"
    ctx = make_ctx(
        tmp_path, source="local", zip=tmp_path / "z.zip",
        report_path=tmp_path / "files.md",
        extra={"backup": ["a.txt"]})
    monkeypatch.setattr(files_mod, "ZipSource", lambda path, **kwargs: fake)
    assert files_mod.run(ctx) == 1
    report = (tmp_path / "files.md").read_text(encoding="utf-8")
    assert "did not complete" in report


def test_CLOSE_STOP_ftp_close_re_raises_and_retires_the_session():
    """CLOSE-STOP: FtpSource.close swallowed every exception, including a
    cooperative stop raised by the transport's quit()."""
    from wpt.types import StopRequested

    from wpt.sources.ftp import FtpSource

    class QuitStops:
        def quit(self):
            raise StopRequested("stop during quit")

    source = FtpSource("h", "u", "p", "")
    source._ftp = QuitStops()
    with pytest.raises(StopRequested):
        source.close()
    assert source._ftp is None


def test_REPORT_SURROGATE_files_edit_mutates_then_writes_the_report(
        tmp_path, monkeypatch):
    """REPORT-SURROGATE: an edit was already applied when the strict report
    write raised; the target changed and the operator got a traceback/0-byte
    report."""
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["a.txt"] = b"OLD"
    local = tmp_path / "a.txt"
    local.write_bytes(b"NEW")
    ctx = make_ctx(
        tmp_path, apply=True, yes=True,
        wp_url="https://bad\udcff.example",
        report_path=tmp_path / "files.md",
        extra={"paths": ["a.txt"], "from_paths": [str(local)]})
    assert files_mod.run(ctx) == 0
    assert fake.files["a.txt"] == b"NEW"
    markdown = (tmp_path / "files.md").read_text(encoding="utf-8")
    twin = (tmp_path / "files.json").read_text(encoding="utf-8")
    assert "\\udcff" in markdown
    assert "\\udcff" in twin
    assert json.loads(twin)["applied"] is True


def test_SITE_LABEL_malformed_urls_reach_files_and_audit_stubs(
        tmp_path, monkeypatch):
    """SITE-LABEL: urlparse raises ValueError for an invalid IPv6 literal;
    the report label and the action audit stub must fall back, not raise."""
    from wpt.actions import registry

    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["a.txt"] = b"old"
    ctx = make_ctx(
        tmp_path, wp_url="http://[::1", webroot="public_html",
        report_path=tmp_path / "backup.md",
        extra={"backup": ["a.txt"]})
    assert files_mod.run(ctx) == 0
    assert "# wpt files — public_html" in (
        tmp_path / "backup.md").read_text(encoding="utf-8")
    stub = registry._audit_stub(ctx)
    assert stub.site == "public_html"


def test_REPORT_DIRS_a_non_empty_created_directory_is_reported_residue(
        tmp_path, monkeypatch):
    """REPORT-DIRS: when a created directory cannot be proven empty it must
    be LEFT and named in the failure, never silently deleted or hidden."""
    # This test only needs the parent-creating write and the explicit
    # directory store (the class above is local to its own test).
    class DirAware(RenameFake):
        def __init__(self):
            super().__init__()
            self.dirs: set[str] = set()

        def list_dir(self, path):
            entries = {entry.path: entry for entry in super().list_dir(path)}
            rel = path if path else ""
            for directory in self.dirs:
                parent = directory.rpartition("/")[0]
                if parent == rel and directory not in entries:
                    from wpt.types import Entry
                    entries[directory] = Entry(directory, True, size=0)
            return list(entries.values())

        def write_bytes(self, path, data, *, allow_config=False,
                        allow_core=False):
            parent = path.rpartition("/")[0]
            while parent:
                self.dirs.add(parent)
                parent = parent.rpartition("/")[0]
            super().write_bytes(path, data, allow_config=allow_config,
                                allow_core=allow_core)

        def delete(self, path):
            if path == "newdir/a.txt":
                raise SourceError("delete refused")
            super().delete(path)

    fake = install_ftp(monkeypatch, DirAware())
    fake.files["b.txt"] = b"old-b"
    fake.fail_rename_for = {"b.txt"}
    local_a = tmp_path / "a.txt"
    local_a.write_bytes(b"new-a")
    local_b = tmp_path / "b.txt"
    local_b.write_bytes(b"new-b")
    ctx = make_ctx(
        tmp_path, apply=True, yes=True, report_path=tmp_path / "files.md",
        extra={"paths": ["newdir/a.txt", "b.txt"],
               "from_paths": [str(local_a), str(local_b)]})
    assert files_mod.run(ctx) == 1
    assert "newdir" in fake.dirs
    report = (tmp_path / "files.md").read_text(encoding="utf-8")
    assert "not empty" in report or "could not be removed" in report


def test_FILES_ENDPOINT_backup_and_restore_refuse_token_endpoints(
        tmp_path, monkeypatch):
    """P2-FILES-ENDPOINT: files never consulted is_wpt_endpoint_file, so a
    backup archived a live bridge's token body and restore re-armed it."""
    endpoint = "bridge-af12cd34.php"
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files[endpoint] = b"<?php token body"
    ctx = make_ctx(tmp_path, extra={"backup": [endpoint]})

    assert files_mod.run(ctx) == 1
    assert snapshots(ctx, "files") == []

    # A pre-existing snapshot record naming an endpoint is refused before
    # any read/write (the exact L59 re-arm path).
    ctx2 = make_ctx(tmp_path)
    data = b"<?php token body"
    snap = files_mod._create_snapshot(ctx2, "files", [
        files_mod._State(path=endpoint, exists=True, size=len(data),
                         sha256=hashlib.sha256(data).hexdigest(), data=data)])
    with pytest.raises(files_mod.WptError, match="token endpoint"):
        files_mod._load_snapshot(
            ctx2, snap.path, ctx2.settings.files.max_file_bytes)


# ------------------------------------------------------- triple-check round 6


def test_R6_26_restore_last_filters_both_identity_keys(tmp_path, monkeypatch):
    """R6-26: ``--restore last`` selected by name only, chose a newer
    snapshot for ANOTHER webroot on the same host, then refused.  Selection
    filters the webroot too, so the older matching snapshot wins."""
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"A-OLD"

    ctx_a = make_ctx(tmp_path, webroot="public_html",
                     extra={"backup": ["wp-content/a.txt"]})
    assert files_mod.run(ctx_a) == 0

    fake.files["wp-content/a.txt"] = b"B-OLD"
    ctx_b = make_ctx(tmp_path, webroot="domains/example.com/public_html",
                     extra={"backup": ["wp-content/a.txt"]})
    assert files_mod.run(ctx_b) == 0

    fake.files["wp-content/a.txt"] = b"LIVE"
    restore_ctx = make_ctx(tmp_path, webroot="public_html", apply=True,
                           yes=True, extra={"restore": "last"})
    assert files_mod.run(restore_ctx) == 0
    assert fake.files["wp-content/a.txt"] == b"A-OLD"


def test_NG2_symlinked_snapshot_dir_is_never_read_for_its_manifest(
        tmp_path, monkeypatch):
    """N-G2: the wpt-files manifest reads were not rooted, so a snapshot
    directory replaced by a symlink had its manifest read from the outside
    target (an all-absent external manifest then deleted a live file).
    Every manifest read now walks the snapshot root with O_NOFOLLOW."""
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"LIVE"
    backup_ctx = make_ctx(tmp_path, extra={"backup": ["wp-content/a.txt"]})
    assert files_mod.run(backup_ctx) == 0
    snapshot = snapshots(backup_ctx, "files")[0]

    outside = tmp_path / "outside-snapshot"
    outside.mkdir()
    manifest = manifest_of(snapshot)
    manifest["files"] = [{
        "path": "wp-content/a.txt", "exists": False,
        "size": 0, "sha256": None, "stored": None,
    }]
    (outside / "manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8")

    real = snapshot.with_name(snapshot.name + "-real")
    snapshot.rename(real)
    snapshot.symlink_to(outside, target_is_directory=True)

    restore_ctx = make_ctx(
        tmp_path, apply=True, yes=True, report_path=tmp_path / "restore.md",
        extra={"restore": "last"},
    )
    assert files_mod.run(restore_ctx) == 1
    assert fake.files["wp-content/a.txt"] == b"LIVE"
    assert mutations(fake) == []
    # selection does not read the link target either
    assert files_mod._snapshot_identity(snapshot) is None


# ------------------------------------------------- triple-check round 7


def test_R7_P1_03_missing_ftp_parent_is_proven_absent_for_backup(
        tmp_path, monkeypatch, capsys):
    """R7-P1-03: SIZE and the parent LIST both failed (missing directory),
    and ``files`` treated the unanswerable lookup as fatal even though the
    grandparent listing proved the whole chain absent."""
    from tests.fakes import LookupFailingSource

    fake = install_ftp(monkeypatch, LookupFailingSource())
    fake.files["readme.html"] = b"readme"
    ctx = make_ctx(tmp_path, extra={"backup": ["newdir/x.txt"]})
    assert files_mod.run(ctx) == 0
    assert "absent" in capsys.readouterr().out


def test_R7_RESIDUAL_deep_missing_chain_is_proven_absent_without_recursion(
        tmp_path, monkeypatch, capsys):
    """The ancestor walk is iterative: 1200 missing components used to raise
    RecursionError through ``presence_proven``/``files.run`` instead of the
    command's rc-0 absent answer."""
    from tests.fakes import LookupFailingSource

    fake = install_ftp(monkeypatch, LookupFailingSource())
    fake.files["readme.html"] = b"readme"
    deep = "/".join(["d"] * 1200 + ["x.txt"])
    ctx = make_ctx(tmp_path, extra={"backup": [deep]})
    assert files_mod.run(ctx) == 0
    assert "absent" in capsys.readouterr().out


def test_R7_RESIDUAL_deep_unlistable_chain_is_a_clear_refusal(
        tmp_path, monkeypatch):
    """A deep chain under an existing-but-unlistable parent must fail closed
    through WptError (rc 1, failure report), not RecursionError."""
    from tests.fakes import FakeSource

    class _UnlistableRoot(FakeSource):
        def list_dir(self, path):
            if path == "d" or path.startswith("d/"):
                raise SourceError("ftp listing failed for 'd': 550")
            return super().list_dir(path)

    fake = install_ftp(monkeypatch, _UnlistableRoot())
    fake.files["d/keep.txt"] = b"keep"
    deep = "/".join(["d"] * 1200 + ["x.txt"])
    ctx = make_ctx(tmp_path, report_path=tmp_path / "files.md",
                   extra={"backup": [deep]})
    assert files_mod.run(ctx) == 1
    report = (tmp_path / "files.md").read_text(encoding="utf-8")
    assert "exists but cannot be listed" in report
    assert "RecursionError" not in report


def test_R7_P1_03_missing_ftp_parent_is_proven_absent_for_edit(
        tmp_path, monkeypatch):
    from tests.fakes import LookupFailingSource

    class _EditSource(RenameFake, LookupFailingSource):
        pass

    local = tmp_path / "a.txt"
    local.write_bytes(b"new")
    fake = install_ftp(monkeypatch, _EditSource())
    fake.files["readme.html"] = b"readme"
    ctx = make_ctx(tmp_path, apply=True, yes=True,
                   extra={"paths": ["newdir/a.txt"],
                          "from_paths": [str(local)]})
    assert files_mod.run(ctx) == 0
    assert fake.files["newdir/a.txt"] == b"new"


def test_R7_P2_09_a_close_time_stop_never_replaces_the_primary_failure(
        tmp_path, monkeypatch):
    """R7-P2-09: files wrote the close stop's report over the primary read
    failure, so the operator saw SIGTERM instead of the real cause."""
    from wpt.types import StopRequested

    class _PrimaryThenStop(UnreadableFake):
        def close(self):
            raise StopRequested("SIGTERM during close")

    install_ftp(monkeypatch, _PrimaryThenStop({"a.txt"}))
    ctx = make_ctx(tmp_path, report_path=tmp_path / "files.md",
                   extra={"backup": ["a.txt"]})
    assert files_mod.run(ctx) == 1
    report = (tmp_path / "files.md").read_text(encoding="utf-8")
    assert "a.txt is a directory or unreadable" in report
    assert "SIGTERM during close" not in report


# ------------------------------------------------ triple-check round 8 (P2)


def test_P2_02_created_dir_cleanup_never_masks_the_primary_failure(
        tmp_path, monkeypatch):
    """P2-02: a cleanup deadline during rollback escaped INSTEAD of the
    primary write failure the operator needs to see."""
    from wpt.files import _Snapshot, _SnapshotEntry, _State, _apply_transaction
    from wpt.types import DeadlineExceeded, WptError

    class _Primary(FakeSource):
        def write_bytes(self, path, data, *, allow_config=False,
                        allow_core=False):
            raise WptError("PRIMARY")

    source = _Primary()
    snapshot = _Snapshot(
        path=tmp_path / "snap", kind="edit", webroot="",
        entries=[_SnapshotEntry(path="newdir/a.txt", exists=False)])
    desired = [_State(path="newdir/a.txt", exists=True, size=1,
                      sha256=sha(b"x"), data=b"x")]

    monkeypatch.setattr(
        files_mod, "_remove_created_dirs",
        lambda _source, _dirs: (_ for _ in ()).throw(
            DeadlineExceeded("cleanup deadline")))

    with pytest.raises(WptError) as excinfo:
        _apply_transaction(source, snapshot, desired, 1024)
    assert "PRIMARY" in str(excinfo.value)
    assert "cleanup stopped" in str(excinfo.value)


def test_R17_files_snapshot_sweeps_stale_capture_temps(tmp_path):
    """R17-4-P2: ``.files-*`` capture temps left by SIGKILL were never
    swept.  Both capture owners share the one ownership/age-bounded sweep;
    a fresh temp survives."""
    import os
    import time

    from wpt.files import _State, _create_snapshot

    ctx = make_ctx(tmp_path)
    site = site_dir(ctx)
    site.mkdir(parents=True)
    stale = site / ".files-deadbeef"
    live = site / ".files-cafebabe"
    for directory in (stale, live):
        directory.mkdir()
        (directory / "partial").write_bytes(b"x")
    old = time.time() - 200_000
    os.utime(stale, (old, old))

    meta = _create_snapshot(
        ctx, "files",
        [_State("wp-content/a.txt", True, 1, sha(b"x"), b"x")])
    assert meta.path.is_dir()
    assert not stale.exists()
    assert live.is_dir()


def test_R25_files_snapshot_journals_the_capture_dir_before_creation(
        tmp_path, monkeypatch):
    """R25-P2: ``mkdtemp`` created ``.files-*`` before its name was assigned,
    so a stop on that boundary left an untracked directory.  The candidate is
    set before ``os.mkdir`` and the whole creation is inside the cleanup try."""
    from wpt.files import _State, _create_snapshot

    ctx = make_ctx(tmp_path)
    real_mkdir = files_mod.os.mkdir

    def stop_at_capture(path, *args, **kwargs):
        result = real_mkdir(path, *args, **kwargs)
        if Path(path).name.startswith(".files-"):
            raise StopRequested("stop at capture dir creation")
        return result

    monkeypatch.setattr(files_mod.os, "mkdir", stop_at_capture)
    with pytest.raises(StopRequested):
        _create_snapshot(
            ctx, "files",
            [_State("wp-content/a.txt", True, 1, sha(b"x"), b"x")])
    assert not list(site_dir(ctx).glob(".files-*"))


def test_R23_files_snapshot_refuses_a_symlinked_site_label(tmp_path):
    """R23-P2: the files writer shared ``ensure_private_dir``'s mkdir+chmod,
    both following ``<backup>/<label> -> victim``.  It now uses the shared
    O_NOFOLLOW site-dir owner; the victim keeps its bytes and mode."""
    from wpt.files import _State, _create_snapshot
    from wpt.types import WptError

    ctx = make_ctx(tmp_path)
    site = site_dir(ctx)
    site.parent.mkdir(parents=True, exist_ok=True)
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep.txt").write_text("KEEP", encoding="utf-8")
    before_mode = victim.stat().st_mode & 0o777
    site.symlink_to(victim, target_is_directory=True)

    with pytest.raises(WptError, match="symbolic link"):
        _create_snapshot(
            ctx, "files",
            [_State("wp-content/a.txt", True, 1, sha(b"x"), b"x")])
    assert victim.stat().st_mode & 0o777 == before_mode
    assert sorted(p.name for p in victim.iterdir()) == ["keep.txt"]
    assert site.is_symlink()


def test_P2_03_files_manifest_is_capped_before_it_is_published(tmp_path):
    """P2-03: a 3000-target `wpt files` manifest exceeded the 1 MiB reader
    cap, so the backup succeeded and its own restore refused it."""
    from wpt.files import _State, _create_snapshot
    from wpt.types import WptError

    ctx = make_ctx(tmp_path)
    states = [
        _State(path=f"wp-content/very-long-directory-name/{index:05d}.txt",
               exists=True, size=1, sha256=sha(b"x"), data=b"x")
        for index in range(6000)
    ]

    with pytest.raises(WptError, match="MANIFEST_MAX_BYTES"):
        _create_snapshot(ctx, "files", states)
    assert snapshots(ctx) == []


@pytest.mark.parametrize("alias", ["/public_html/", "public_html/", "\\public_html\\"])
def test_R24_restore_webroot_identity_is_raw_and_exact(tmp_path, monkeypatch,
                                                       alias):
    """R24-P2: ``files --restore`` normalized the webroot while SPEC says the
    RAW recorded identity must match.  A trailing/leading slash or a
    backslash alias must be refused before any write."""
    fake = install_ftp(monkeypatch, RenameFake())
    fake.files["wp-content/a.txt"] = b"old"
    backup_ctx = make_ctx(tmp_path, extra={"backup": ["wp-content/a.txt"]})
    assert files_mod.run(backup_ctx) == 0
    snapshot = snapshots(backup_ctx, "files")[0]
    fake.files["wp-content/a.txt"] = b"mutated"

    ctx = make_ctx(
        tmp_path, apply=True, yes=True, webroot=alias,
        report_path=tmp_path / "restore.md",
        extra={"restore": snapshot.name},
    )
    assert files_mod.run(ctx) == 1
    assert fake.files["wp-content/a.txt"] == b"mutated"
    assert mutations(fake) == []
    assert snapshots(ctx, "restore") == []
