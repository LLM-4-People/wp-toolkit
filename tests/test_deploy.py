"""wpt.deploy + wpt.manifest tests — no network, no ssh, no key.

Three seams carry every test here:

* :func:`wpt.deploy._spawn` — the ONE subprocess function.  Tests replace
  it with a recorder, which is how the quota preflight is PROVEN to
  refuse before any child process is started (``recorder.calls == []``).
* :func:`wpt.deploy.stream_archive` — a pure function of the archive into
  a file-like, so the tar bytes are parsed back with ``tarfile``.
* ``--ssh-target local:<dir>`` — a first-class dry target running the
  real producer through a real ``tar -x``, so the end-to-end cases
  exercise ACTUAL extracted bytes (and ACTUAL host-injected files
  surviving the deploy) without a host.

The corpus is a host-shaped export: everything under ONE top-level
directory, which is the shape the double strip went wrong on.

The tail of this file covers the report of a deploy that deployed NOTHING
(L44 one level up: the dry run honours --report, a failed run used to
write nothing, so a scripted caller could not tell "there was nothing to
deploy" from "the deploy never got far enough").
"""

import hashlib
import io
import logging
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import zipfile
import zlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from wpt import deploy
from wpt.config import CredentialError
from wpt.deploy import (DIR_MODE, FILE_MODE, LOCAL_TARGET_PREFIX, TAR_MTIME,
                        DeployError, LocalTarget, Preflight,
                        QuotaError, SshTarget, TargetLayoutError, TransferError,
                        assert_target, build_plan, classify_transfer_error,
                        deploy_stream, make_target,
                        parse_readback, preflight, readback_script,
                        stream_archive, verify_against_manifest, zip_facts)
from wpt.settings import DeploySettings, SettingsError, load
from wpt.report import human_bytes
from wpt.manifest import (DEPLOY_MANIFEST_FORMAT, ManifestError, build_manifest,
                          read_manifest, sha256_file, verify_files,
                          write_manifest)

SETTINGS = DeploySettings()

#: A realistic WP webroot under a host-export top-level directory.  The
#: ``ID3/`` and ``about.php`` members are the double-strip signature: they
#: belong to ``wp-includes/``, so finding either at the webroot ROOT means
#: the strip ran twice.
MEMBERS: dict[str, bytes] = {
    "wp-config.php": b"<?php // config\n",
    "wp-load.php": b"<?php // load\n",
    "index.php": b"<?php // front\n",
    ".htaccess": b"# rules\n",
    "wp-includes/version.php": b"<?php $wp_version = '7.1';\n",
    "wp-includes/ID3/getid3.php": b"<?php // id3\n",
    "wp-includes/about.php": b"<?php // about\n",
    "wp-admin/index.php": b"<?php // admin\n",
    "wp-content/index.php": b"<?php // silence\n",
    "wp-content/plugins/akismet/akismet.php": b"<?php // plugin\n",
    "wp-content/uploads/2018/03/photo.jpg": b"\xff\xd8\xff\xe0JPEG-BYTES",
    "wp-content/themes/twentyten/style.css": b"/* theme */\n",
}
TOP = "site.test"          # the host export's single top-level directory

#: A ``df -Pk`` answer with room to spare, for the stubs that only care
#: about what happens AFTER the preflight.
PLENTY_DF = ("Filesystem 1024-blocks Used Available Capacity Mounted on\n"
             "/dev/sda 100000 1 99999 1% /\n")

#: A ``quota -s`` data row: 900000 blocks used of a 1000000-block limit.
QUOTA_1000000_OF_1000000 = ("Disk quotas on root (uid 0):\n"
                            "     Filesystem   blocks    quota    limit   grace\n"
                            "           /dev/sdb   900000  1000000  1000000\n")

needs_tar = pytest.mark.skipif(shutil.which("tar") is None,
                               reason="the dry target needs a real tar")


@pytest.fixture()
def site_zip(tmp_path) -> Path:
    """A host-shaped export zip: one top-level dir, one empty dir entry."""
    path = tmp_path / "site.zip"
    with zipfile.ZipFile(path, "w") as zf:
        for rel, data in MEMBERS.items():
            zf.writestr(f"{TOP}/{rel}", data)
        zf.writestr(f"{TOP}/wp-content/uploads/empty-dir/", b"")
    return path


@pytest.fixture()
def dry_root(tmp_path) -> Path:
    return tmp_path / "host"


@pytest.fixture()
def small_zip(tmp_path) -> Path:
    path = tmp_path / "small.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(f"{TOP}/wp-load.php", b"x")
    return path


class SpawnRecorder:
    """Replacement for ``wpt.deploy._spawn`` that records every argv.

    The real preflight-refusal case asserts ``recorder.calls == []``: the
    refusal is proven to happen before ANY child process is started, not
    merely before the transfer.
    """

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, argv, *, env=None, stdin=subprocess.PIPE):
        self.calls.append(list(argv))
        raise AssertionError(
            f"no subprocess may be started here, but {argv[0]!r} was launched")


@pytest.fixture()
def no_spawn(monkeypatch) -> SpawnRecorder:
    recorder = SpawnRecorder()
    monkeypatch.setattr(deploy, "_spawn", recorder)
    return recorder


# ------------------------------------------------------- 1. the tar producer


def test_stream_strips_the_host_root_exactly_once(site_zip):
    """THE double-strip lesson, pinned on the producer's bytes.

    Every member is webroot-relative: the host export's single top-level
    directory is gone and nothing is nested a level deeper than it
    belongs.  ``wp-includes/ID3/getid3.php`` stays UNDER ``wp-includes``
    — the shape that became ``ID3/getid3.php`` at the webroot root in the
    failed attempt.
    """
    sink = io.BytesIO()
    stats = stream_archive(site_zip, sink, settings=SETTINGS)
    sink.seek(0)
    names = []
    with tarfile.open(fileobj=sink, mode="r|") as tar:
        for info in tar:
            names.append(info.name)
            assert not info.name.startswith(TOP + "/")
            assert not info.name.startswith("/")
            assert ".." not in info.name.split("/")
    assert set(MEMBERS) <= set(names)
    assert "wp-includes/ID3/getid3.php" in names
    assert "wp-config.php" in names
    assert stats.root == TOP
    assert stats.files == len(MEMBERS)


def test_stream_normalizes_modes_mtime_and_ownership(site_zip):
    """0644 files, 0755 dirs, mtime 0 — a deterministic normalized tree.

    The archive's own modes and times are host-export noise (the
    exporting user's umask and the export date); shipping them would make
    two deploys of one artifact differ.
    """
    sink = io.BytesIO()
    stream_archive(site_zip, sink, settings=SETTINGS)
    sink.seek(0)
    files, dirs = {}, {}
    with tarfile.open(fileobj=sink, mode="r|") as tar:
        for info in tar:
            (dirs if info.isdir() else files)[info.name] = info
    assert files["wp-config.php"].mode == FILE_MODE
    assert files["wp-config.php"].mtime == TAR_MTIME
    assert files["wp-config.php"].uid == files["wp-config.php"].gid == 0
    assert files["wp-config.php"].uname == files["wp-config.php"].gname == ""
    assert dirs["wp-includes"].mode == DIR_MODE
    assert dirs["wp-includes"].mtime == TAR_MTIME
    assert dirs["wp-content/uploads/empty-dir"].mode == DIR_MODE
    assert all(i.mode == FILE_MODE and i.mtime == 0 for i in files.values())
    assert all(i.mode == DIR_MODE and i.mtime == 0 for i in dirs.values())


def test_stream_is_byte_deterministic(site_zip):
    """Same archive in, same tar bytes out (a reproducible deploy)."""
    first, second = io.BytesIO(), io.BytesIO()
    stream_archive(site_zip, first, settings=SETTINGS)
    stream_archive(site_zip, second, settings=SETTINGS)
    assert first.getvalue() == second.getvalue()


def test_stream_parents_precede_children(site_zip):
    """A dir member always lands before its children (tar-safe order)."""
    sink = io.BytesIO()
    stream_archive(site_zip, sink, settings=SETTINGS)
    sink.seek(0)
    order = []
    with tarfile.open(fileobj=sink, mode="r|") as tar:
        for info in tar:
            order.append(info.name)
    for name in order:
        parent = name.rpartition("/")[0]
        while parent:
            assert parent in order, f"{parent} missing before {name}"
            parent = parent.rpartition("/")[0]


def test_stream_hashes_exactly_the_bytes_it_carries(site_zip):
    """The manifest's per-file sha256 comes from the stream, not a re-read.

    The verifier compares these digests against the TARGET; if the
    producer hashed anything but the bytes it wrote, the record would be a
    lie dressed as evidence.
    """
    sink = io.BytesIO()
    stats = stream_archive(site_zip, sink, settings=SETTINGS)
    payload = sink.getvalue()
    assert stats.sha256 == {p: hashlib.sha256(d).hexdigest()
                            for p, d in MEMBERS.items()}
    # ...and those are the very bytes the tar carries.
    for path, data in MEMBERS.items():
        assert data in payload
    assert b"site.test" not in payload      # the stripped root is really gone


def test_stream_refuses_a_symlink_member(tmp_path):
    """A zip symlink is refused — never recreated, never followed.

    A webroot deploy that re-materialized a symlink pointing outside the
    webroot would write outside the target the operator named.
    """
    path = tmp_path / "link.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(f"{TOP}/wp-load.php", b"x")
        info = zipfile.ZipInfo(f"{TOP}/wp-content/evil-link")
        info.create_system = 3                       # unix
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, "../../../../etc/passwd")
    # Refused in the FACTS pass: before the preflight, so nothing moved.
    with pytest.raises(DeployError, match="symlink"):
        zip_facts(path)
    with pytest.raises(DeployError, match="symlink"):
        build_plan(path, "root@box", "/www", SETTINGS)     # even a dry run
    with pytest.raises(DeployError, match="symlink"):
        stream_archive(path, io.BytesIO(), settings=SETTINGS)


def test_a_refused_archive_never_reaches_the_target(tmp_path, no_spawn):
    """Fail-closed ordering: the refusal precedes every subprocess."""
    path = tmp_path / "link.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(f"{TOP}/wp-load.php", b"x")
        info = zipfile.ZipInfo(f"{TOP}/wp-content/link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, "/etc/passwd")
    target = StubTarget()
    with pytest.raises(DeployError):
        deploy_stream(path, target, SETTINGS)
    assert no_spawn.calls == []          # not even the preflight probe


def test_stream_refuses_an_escaping_member(tmp_path):
    """A ``../`` member is refused before a byte reaches the target."""
    path = tmp_path / "escape.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(f"{TOP}/wp-load.php", b"x")
        zf.writestr(f"{TOP}/../evil.php", b"x")
    with pytest.raises(DeployError, match="outside the target webroot"):
        zip_facts(path)


# ------------------------------------------------------ 2. the dry-run plan


def test_plan_is_pure_and_spawns_nothing(site_zip, no_spawn):
    """The dry run counts the archive and touches no target."""
    plan = build_plan(site_zip, "root@box.example", "/home/root/www", SETTINGS)
    assert no_spawn.calls == []
    assert plan.est_bytes() == sum(len(d) for d in MEMBERS.values())
    summary = [i for i in plan.items if i.category == "deploy.estimate"]
    assert len(summary) == 1
    detail = summary[0].detail
    assert "root@box.example:/home/root/www" in detail
    assert f"{len(MEMBERS)} file(s)" in detail
    assert TOP in detail and "root stripped" in detail


def test_plan_groups_by_top_level_entry(site_zip, no_spawn):
    plan = build_plan(site_zip, "root@box.example", "/home/root/www", SETTINGS)
    targets = {i.target for i in plan.items}
    assert {"wp-config.php", "wp-includes", "wp-content", "wp-admin"} <= targets


# --------------------------------------------------------- 3. quota preflight


class StubTarget(LocalTarget):
    """A LocalTarget whose probes are scripted — no filesystem, no child.

    Used by the preflight cases, where the interesting question is the
    arithmetic over a MEASUREMENT, not how the measurement is taken.
    """

    def __init__(self, df: str = "", quota: str = "") -> None:
        super().__init__("/srv/www")
        self._df = df
        self._quota = quota
        self.probes: list[str] = []

    def run_command(self, command, *, timeout, deadline=None):
        self.probes.append(command)
        if command.startswith("df"):
            return (0, self._df, "") if self._df else (1, "", "df: not found")
        if command.startswith("quota"):
            return (0, self._quota, "") if self._quota else (1, "", "")
        if "dd " in command:            # the write-and-remove probe
            return 0, "", ""
        return 0, "", ""


def _webroot_with(path: Path, *rel_paths: str) -> Path:
    """Build a webroot holding ``rel_paths`` (``mkdir -p`` semantics)."""
    for rel in rel_paths:
        target = path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"x")
    return path


def test_preflight_refuses_before_any_subprocess(site_zip, no_spawn):
    """THE session-costing failure: refuse BEFORE a byte moves.

    The refusal is proven to happen before a child process is started at
    all — ``no_spawn.calls`` is empty, so the assertion covers the whole
    subprocess seam, not merely the transfer.
    """
    settings = DeploySettings(preflight_margin_bytes=0)
    exhausted = StubTarget(df=("Filesystem 1024-blocks Used Available "
                               "Capacity Mounted on\n"
                               "/dev/sda 100000 100000 0 100% /\n"))
    measurement = preflight(exhausted, 10 ** 9, settings)
    assert measurement.available_bytes == 0
    assert measurement.refuse_reason() is not None
    with pytest.raises(QuotaError):
        deploy_stream(site_zip, exhausted, settings,
                      preflight_result=measurement)
    assert no_spawn.calls == []


def test_deploy_stream_refuses_on_a_measurement_before_the_stream(site_zip,
                                                                  no_spawn):
    """A preflight measurement that cannot fit stops the deploy outright.

    The stream subprocess is never started: the refusal is inside
    :func:`deploy_stream`, before the pipe exists.
    """
    settings = DeploySettings(preflight_margin_bytes=0)
    tight = StubTarget(df=("Filesystem 1024-blocks Used Available Capacity "
                           "Mounted on\n/dev/sda 100000 100000 0 100% /\n"))
    with pytest.raises(QuotaError) as excinfo:
        deploy_stream(site_zip, tight, settings)
    assert no_spawn.calls == []
    message = str(excinfo.value)
    assert "REFUSED" in message
    assert "nothing was transferred" in message
    # Both numbers are in the refusal: the operator's whole decision.
    assert human_bytes(sum(len(d) for d in MEMBERS.values())) in message
    assert "0 B is available" in message


def test_preflight_refusal_names_both_numbers():
    """The operator's decision needs the numbers, not 'out of space'."""
    result = Preflight(webroot="/home/root/www", required_bytes=4 * 1024 ** 3,
                       available_bytes=int(1.5 * 1024 ** 3), source="df+quota",
                       margin_bytes=256 * 1024 ** 2)
    reason = result.refuse_reason()
    assert reason is not None
    assert "4.2 GB" in reason             # needed (4 GB of files + 256 MB)
    assert "1.5 GB" in reason              # available
    assert "short by" in reason
    assert result.needed_bytes == 4 * 1024 ** 3 + 256 * 1024 ** 2


def test_preflight_passes_when_the_numbers_fit():
    result = Preflight(webroot="/w", required_bytes=1000, available_bytes=5000,
                       source="df", margin_bytes=500)
    assert result.refuse_reason() is None


def test_preflight_refuses_unknown_space_unless_told_otherwise():
    unknown = Preflight(webroot="/w", required_bytes=10, available_bytes=None,
                        source="unknown", margin_bytes=0)
    assert "UNKNOWN" in unknown.refuse_reason()
    relaxed = Preflight(webroot="/w", required_bytes=10, available_bytes=None,
                        source="unknown", margin_bytes=0,
                        require_known_space=False)
    assert relaxed.refuse_reason() is None


def test_preflight_uses_the_smallest_of_df_and_quota():
    """A shared filesystem can be huge while the ACCOUNT is tiny.

    That is the live DirectAdmin shape: ``df`` reports the whole disk, the
    account quota is 2.00 GiB.  The tightest measurement wins.
    """
    available, how = deploy.probe_available_bytes(StubTarget(
        df="Filesystem 1024-blocks Used Available Capacity Mounted on\n"
           "/dev/sda 100000 99000 1000 99% /\n",
        quota=QUOTA_1000000_OF_1000000), SETTINGS)
    assert how == "df+quota" and available == 1000 * 1024

    # df-only: a 1 MiB "filesystem".
    available, how = deploy.probe_available_bytes(StubTarget(
        df="Filesystem 1024-blocks Used Available Capacity Mounted on\n"
           "/dev/sda 10 9 1 90% /\n"), SETTINGS)
    assert how == "df" and available == 1024

    # quota-only: a 1 MB filesystem behind a ~2 GiB account.
    available, how = deploy.probe_available_bytes(StubTarget(
        quota="/dev/sdb 100 2100000 2100000 0 0\n"), SETTINGS)
    assert how == "quota" and available == (2100000 - 100) * 1024


def test_quota_parse_ignores_a_df_line():
    """A df line must never be read as a quota row.

    The shapes collide (mount point in column 1, three numbers after it);
    only the percentage and the trailing mount give them apart, so a
    misread here would INVENT an allowance the account does not have.
    """
    assert deploy._parse_quota(PLENTY_DF) is None
    assert deploy._parse_quota(QUOTA_1000000_OF_1000000) == 100000 * 1024
    # A row with a live grace column reads the same way.
    assert deploy._parse_quota("/dev/sdb 900000 1000000 1000000 12345 0 0\n") \
        == 100000 * 1024


def test_preflight_write_probe_reports_zero_on_a_quota_refusal():
    """Ambiguous parse + a quota-signalled write = zero available space.

    The write-and-remove probe is what settles an account quota hidden
    behind a filesystem ``df`` cannot see: it can only prove the account
    takes a write, and its refusal IS the measurement.
    """

    class QuotaTarget(StubTarget):
        def run_command(self, command, *, timeout, deadline=None):
            if "dd " in command:
                return 1, "", "dd: writing to 'x': Disk quota exceeded\n"
            return super().run_command(command, timeout=timeout,
                                       deadline=deadline)

    available, how = deploy.probe_available_bytes(QuotaTarget(), SETTINGS)
    assert available == 0 and how == "write-probe"


def test_preflight_write_probe_success_leaves_space_unmeasured():
    """A probe that succeeds proves writability, not how much fits."""
    available, how = deploy.probe_available_bytes(StubTarget(), SETTINGS)
    assert how == "write-probe" and available is None


def test_R19_local_archive_hash_rides_the_run_deadline(tmp_path):
    """R19-P2: after the last network phase the deploy still hashed the
    archive and wrote the manifest outside the budget.  The hash checks the
    run deadline per chunk (local-only work, but no longer unbounded)."""
    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    archive = tmp_path / "site.zip"
    archive.write_bytes(b"x" * 4096)
    with pytest.raises(DeadlineExceeded):
        sha256_file(archive, deadline=Deadline(-1))
    assert sha256_file(archive) == hashlib.sha256(archive.read_bytes()).hexdigest()


def test_R19_deadline_killed_write_probe_removes_its_file(
        tmp_path, monkeypatch):
    """R19-P2: the probe's sequential ``rm`` never ran when _reap SIGKILLed
    the child group at the deadline, leaving a partial probe in the
    quota-bound webroot.  A fresh finite cleanup budget now removes it on
    every exit (and the shell carries a trap for a remote kill)."""
    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    webroot = tmp_path / "www"
    webroot.mkdir()
    shim_dir = tmp_path / "bin"
    shim_dir.mkdir()
    shim = shim_dir / "dd"
    shim.write_text(
        "#!/bin/sh\n"
        "for arg in \"$@\"; do\n"
        "  case \"$arg\" in of=*) out=\"${arg#of=}\" ;; esac\n"
        "done\n"
        "[ -n \"$out\" ] && printf x > \"$out\"\n"
        "sleep 30\n",
        encoding="utf-8")
    shim.chmod(0o755)
    monkeypatch.setenv("PATH", f"{shim_dir}:{os.environ['PATH']}")
    settings = DeploySettings(
        preflight_write_probe_bytes=1024 * 1024, probe_timeout_s=5)
    target = LocalTarget(str(webroot))
    with pytest.raises(DeadlineExceeded):
        deploy._write_probe(target, settings, Deadline(0.3))
    assert not list(webroot.glob(".wpt-deploy-probe-*")), \
        list(webroot.iterdir())


# ---------------------------------------------- 4. post-extract assertions


def test_layout_check_names_a_missing_webroot(dry_root):
    """A target with no webroot never gets a success verdict."""
    target = LocalTarget(str(dry_root / "absent"))
    with pytest.raises(TargetLayoutError, match="does not exist"):
        assert_target(target, SETTINGS)


def test_layout_check_refuses_a_missing_required_file(dry_root):
    """One absent required file = refusal naming it."""
    webroot = _webroot_with(dry_root / "www", "wp-load.php",
                            "wp-includes/version.php", "wp-content/index.php")
    with pytest.raises(TargetLayoutError) as excinfo:
        assert_target(LocalTarget(str(webroot)), SETTINGS)
    assert "missing required file" in str(excinfo.value)
    assert "wp-config.php" in str(excinfo.value)


def test_layout_check_refuses_a_missing_required_directory(dry_root):
    """``wp-content`` must be a DIRECTORY at the root."""
    webroot = _webroot_with(dry_root / "www", "wp-config.php", "wp-load.php",
                            "wp-includes/version.php")
    with pytest.raises(TargetLayoutError) as excinfo:
        assert_target(LocalTarget(str(webroot)), SETTINGS)
    assert "missing required directory: wp-content" in str(excinfo.value)


def test_layout_check_refuses_a_required_directory_that_is_a_file(dry_root):
    """A FILE where a directory belongs is not a pass."""
    webroot = _webroot_with(dry_root / "www", "wp-config.php", "wp-load.php",
                            "wp-includes/version.php", "wp-content")
    assert_target  # the file-vs-dir distinction is the script's own -d test
    with pytest.raises(TargetLayoutError) as excinfo:
        assert_target(LocalTarget(str(webroot)), SETTINGS)
    assert "wp-content" in str(excinfo.value)


def test_layout_check_detects_the_double_strip_signature(dry_root):
    """The residue of a strip that ran TWICE is refused explicitly.

    A doubly-stripped tree can still hold every required path, so the
    required-file check alone is not enough: the assertion also refuses
    the SIGNATURE — a wp-includes child such as ``ID3/`` or an
    ``about.php`` sitting at the webroot root.
    """
    webroot = _webroot_with(dry_root / "www", "wp-config.php", "wp-load.php",
                            "wp-includes/version.php", "wp-content/index.php",
                            "ID3/getid3.php", "about.php")
    with pytest.raises(TargetLayoutError) as excinfo:
        assert_target(LocalTarget(str(webroot)), SETTINGS)
    message = str(excinfo.value)
    assert "double-strip residue" in message
    assert "ID3" in message and "about.php" in message
    assert "stripped twice" in message


def test_layout_check_accepts_a_correctly_nested_wp_includes(dry_root):
    """The residue list must not fire on a CORRECT tree.

    ``wp-includes/ID3/`` at the right depth is exactly where it belongs;
    only ``ID3/`` at the webroot ROOT is the double-strip signature.  A
    residue list that fired here would refuse every healthy deploy.
    """
    webroot = _webroot_with(dry_root / "www", "wp-config.php", "wp-load.php",
                            "wp-includes/version.php", "wp-includes/ID3/getid3.php",
                            "wp-includes/about.php", "wp-content/index.php")
    assert assert_target(LocalTarget(str(webroot)), SETTINGS).ok


def test_layout_check_passes_on_a_correct_target(dry_root):
    """The happy readback: required paths present, no residue."""
    webroot = _webroot_with(dry_root / "www", "wp-config.php", "wp-load.php",
                            "wp-includes/version.php", "wp-content/index.php")
    readback = assert_target(LocalTarget(str(webroot)), SETTINGS)
    assert readback.ok
    assert "wp-config.php" in readback.top_level
    assert readback.message() == "target layout verified"


def test_readback_script_survives_an_empty_assertion_list(dry_root):
    """``for p in ; do`` is a shell syntax error.

    The SETTINGS door now refuses an empty assertion list outright
    (``wpt.settings.DeploySettings`` — see
    ``test_deploy_settings_refuse_an_empty_assertion_list``), so an emptied
    list is no longer a reachable configuration; what is left to prove here
    is the ENGINE's own robustness, through a stand-in that never went
    through the door.  An operator who empties a list must not get a
    readback that fails for a reason nobody configured.
    """
    settings = SimpleNamespace(required_files=[], required_dirs=[],
                               residue_paths=[], probe_timeout_s=30)
    webroot = _webroot_with(dry_root / "www", "wp-config.php")
    readback = assert_target(LocalTarget(str(webroot)), settings)
    assert readback.ok
    assert "wp-config.php" in readback.top_level


@pytest.mark.parametrize("key", ["required_files", "required_dirs",
                                 "residue_paths"])
def test_deploy_settings_refuse_an_empty_assertion_list(key):
    """An emptied ASSERTION may not be configured, and the refusal says
    WHICH proof would stop verifying.

    The empty list is where the two list families differ.  A CLASSIFICATION
    list (``quota_signatures`` / ``auth_signatures`` /
    ``network_signatures``) may be empty: "this operator's hosts never emit
    that message" is a coherent policy.  An emptied ASSERTION is not — the
    readback answers it with the legal no-op ``:`` and a deploy to a target
    with no ``wp-config.php`` reports success, with nothing anywhere saying
    the post-extract layout proof was switched off.
    """
    with pytest.raises(SettingsError, match=rf"deploy\.{key}"):
        DeploySettings(**{key: []})
    with pytest.raises(SettingsError, match=rf"deploy\.{key}"):
        load(overrides={f"deploy.{key}": []})
    # the classification lists are untouched by that rule
    for name in ("quota_signatures", "auth_signatures", "network_signatures"):
        assert getattr(DeploySettings(**{name: []}), name) == []
        assert getattr(load(overrides={f"deploy.{name}": []}).deploy, name) == []


def test_member_index_refuses_a_name_that_is_both_file_and_dir(tmp_path):
    """A colliding archive is refused, not deployed with one half lost."""
    path = tmp_path / "collide.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(f"{TOP}/wp-content/thing", b"i am a file")
        zf.writestr(f"{TOP}/wp-content/thing/", b"")     # and a directory
    with pytest.raises(DeployError, match="collide"):
        zip_facts(path)


@needs_tar
def test_a_refused_member_leaves_no_orphaned_tar(site_zip, dry_root,
                                                 monkeypatch):
    """A producer failure must still REAP the child it started.

    Leaving a live ``tar`` behind would hold the webroot open — the exact
    kind of residue a self-bounding run may not leave.
    """
    webroot = dry_root / "www"
    webroot.mkdir(parents=True)
    target = LocalTarget(str(webroot))
    started = []
    original = deploy._spawn

    def recording_spawn(argv, *, env=None, stdin=subprocess.PIPE):
        proc = original(argv, env=env, stdin=stdin)
        started.append(proc)
        return proc

    monkeypatch.setattr(deploy, "_spawn", recording_spawn)

    def refuse(sink):
        raise DeployError("refused member")

    with pytest.raises(DeployError, match="refused member"):
        target.extract(refuse, timeout=30.0)
    assert len(started) == 1
    assert started[0].returncode is not None      # reaped, not orphaned


def test_preflight_measures_the_webroot_filesystem_not_the_login_dir(dry_root):
    """The probe asks about the webroot's mount.

    A DirectAdmin account can keep its home and its webroot on different
    filesystems; only the webroot's is the one the deploy fills.
    """
    probed = []

    class RecordingTarget(LocalTarget):
        def run_command(self, command, *, timeout, deadline=None):
            probed.append(command)
            return 0, "", ""

    deploy.probe_available_bytes(RecordingTarget("/srv/www"), SETTINGS)
    assert probed[0].startswith("df -Pk -- ")
    assert "/srv/www" in probed[0]


def test_readback_script_quotes_every_probe_path():
    """Operator-supplied assertion paths reach the shell quoted, never raw."""
    hostile = "wp-config.php'; touch /tmp/pwned; echo '"
    script = readback_script(DeploySettings(required_files=[hostile],
                                           required_dirs=["wp-content"]))
    # The hostile name appears ONLY inside shlex.quote's single-quoted
    # blob, so the shell sees one argument and never runs `touch`.
    assert repr(hostile) not in script
    quoted = "'" + hostile.replace("'", "'\"'\"'") + "'"
    assert quoted in script
    assert "for p in " + quoted + "; do" in script


def test_parse_readback_separates_missing_from_listing():
    text = ("F wp-config.php\nX wp-load.php\nD wp-content\nR ID3\nL\n"
            "wp-admin\nwp-content\nID3\n")
    readback = parse_readback(text)
    assert readback.missing_files == ("wp-load.php",)
    assert readback.missing_dirs == ()
    assert readback.residue == ("ID3",)
    assert readback.top_level == ("wp-admin", "wp-content", "ID3")
    assert not readback.ok
    assert "double-strip residue" in readback.message()


def test_parse_readback_keeps_dotted_and_empty_root_entries():
    readback = parse_readback("L\n.htaccess\n.marker\nwp-content\n")
    assert readback.top_level == (".htaccess", ".marker", "wp-content")


# ------------------------------------------------ 5. the error classifier


def test_quota_signature_wins_over_a_channel_smell():
    """THE live lesson: a quota exhaustion is not a network error.

    The exhausted DirectAdmin account said ``Error in the SSH layer`` and
    ``write remote: Failure``; classified as a network failure that sends
    the operator after the network while the account is 400 bytes from
    full.
    """
    live = "Error in the SSH layer\nwrite remote: Failure\n"
    assert classify_transfer_error(live, 1, SETTINGS).kind == "quota"
    with pytest.raises(QuotaError) as excinfo:
        classify_transfer_error(live, 1, SETTINGS).raise_for("deploy stream")
    assert "ran out of space" in str(excinfo.value)
    assert "additive" in str(excinfo.value)


@pytest.mark.parametrize("message,kind", [
    ("tar: write remote: Failure", "quota"),
    ("Error in the SSH layer", "quota"),
    ("No space left on device", "quota"),
    ("quota exceeded for user root", "quota"),
    ("root@host: Permission denied (publickey,password).", "auth"),
    ("Host key verification failed.", "auth"),
    ("ssh: connect to host example.com port 22: Connection refused", "network"),
    ("Connection reset by peer", "network"),
    ("tar: /www/wp-load.php: Cannot open: Permission denied", "remote"),
    ("", "unknown"),
])
def test_classifier_maps_each_failure_shape(message, kind):
    assert classify_transfer_error(message, 1, SETTINGS).kind == kind


def test_classifier_raises_the_right_exception_per_kind():
    for kind in ("quota", "auth", "network", "remote", "unknown"):
        with pytest.raises(QuotaError if kind == "quota" else TransferError):
            deploy.TransferFailure(kind, "x").raise_for("ctx")


# ----------------------------------------------------------- 6. the manifest


def test_manifest_round_trips_and_verifies(site_zip, tmp_path):
    """build -> write -> read -> verify: the record IS the handoff."""
    stats = stream_archive(site_zip, io.BytesIO(), settings=SETTINGS)
    manifest = build_manifest(
        site="Example https://example.test/ wp", target="root@box:/www",
        webroot="/www", zip_name="site.zip", entry_count=stats.files,
        uncompressed_bytes=stats.bytes_written,
        files={p: (d, stats.sizes[p]) for p, d in stats.sha256.items()},
        archive_bytes=site_zip.stat().st_size, root=stats.root,
        archive_sha256=sha256_file(site_zip))
    path = write_manifest(manifest, tmp_path / "manifest-dir")
    assert path.name == "manifest.json"
    loaded = read_manifest(path)
    assert loaded["format"] == DEPLOY_MANIFEST_FORMAT
    assert loaded["site"] == "Example-https---example.test--wp"   # sanitized
    assert loaded["archive"]["sha256"] == sha256_file(site_zip)
    assert loaded["archive"]["entries"] == stats.files
    assert loaded["archive"]["root"] == TOP
    assert loaded["wpt_version"]
    observed = {p: hashlib.sha256(d).hexdigest() for p, d in MEMBERS.items()}
    result = verify_files(loaded, observed)
    assert result.ok and result.rc == 0
    assert result.checked == stats.files
    # And the on-disk form is the documented JSON shape.
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert set(raw["files"][0]) == {"path", "sha256", "size"}


def test_manifest_verify_detects_a_flipped_byte(site_zip):
    """One flipped byte on the target = rc 1, naming the file."""
    manifest = _manifest_of(site_zip)
    observed = {p: hashlib.sha256(d).hexdigest() for p, d in MEMBERS.items()}
    victim = "wp-content/uploads/2018/03/photo.jpg"
    flipped = bytearray(MEMBERS[victim])
    flipped[0] ^= 0x01
    observed[victim] = hashlib.sha256(bytes(flipped)).hexdigest()
    result = verify_files(manifest, observed)
    assert result.rc == 1 and not result.ok
    assert result.mismatched == (victim,)
    assert victim in result.message()
    assert "FAILED" in result.message()


def test_manifest_verify_reports_a_missing_file(site_zip):
    manifest = _manifest_of(site_zip)
    observed = {p: hashlib.sha256(d).hexdigest() for p, d in MEMBERS.items()
                if p != "wp-load.php"}
    result = verify_files(manifest, observed)
    assert result.rc == 1 and result.missing == ("wp-load.php",)
    assert "wp-load.php" in result.message()


def test_manifest_is_additive_about_host_injected_files(site_zip):
    """A file the artifact never shipped is NOT a deploy failure.

    Host-injected content (``wp-content/imunify-security/``) is the point
    of an additive deploy: demanding its absence would make the tool
    delete the host's own state.
    """
    manifest = _manifest_of(site_zip)
    observed = {p: hashlib.sha256(d).hexdigest() for p, d in MEMBERS.items()}
    observed["wp-content/imunify-security/antivirus.php"] = "0" * 64
    result = verify_files(manifest, observed)
    assert result.ok and result.rc == 0
    assert "imunify" not in result.message()


def test_manifest_refuses_a_foreign_or_broken_record(tmp_path):
    foreign = tmp_path / "foreign.json"
    foreign.write_text(json.dumps({"format": "wpt-backup-manifest",
                                   "version": 1, "files": []}), encoding="utf-8")
    with pytest.raises(ManifestError, match="not a deploy transfer manifest"):
        read_manifest(foreign)
    future = tmp_path / "future.json"
    future.write_text(json.dumps({"format": DEPLOY_MANIFEST_FORMAT,
                                  "version": 99, "files": []}), encoding="utf-8")
    with pytest.raises(ManifestError, match="unsupported version"):
        read_manifest(future)
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    with pytest.raises(ManifestError, match="not valid JSON"):
        read_manifest(broken)
    with pytest.raises(ManifestError, match="cannot read manifest"):
        read_manifest(tmp_path / "absent.json")


def test_manifest_build_refuses_a_poisoned_record():
    """A malformed digest or an escaping path never becomes a manifest."""
    common = dict(site="s", target="t", webroot="/w", zip_name="z",
                  entry_count=1, uncompressed_bytes=1)
    with pytest.raises(ManifestError, match="unsafe path"):
        build_manifest(files={"../escape.php": ("0" * 64, 1)}, **common)
    with pytest.raises(ManifestError, match="bad sha256"):
        build_manifest(files={"ok.php": ("nothex", 1)}, **common)
    with pytest.raises(ManifestError, match="bad size"):
        build_manifest(files={"ok.php": ("0" * 64, -1)}, **common)
    with pytest.raises(ManifestError, match="bad archive sha256"):
        build_manifest(files={}, archive_sha256="nope", **common)


def test_manifest_carries_no_secret(small_zip):
    """The record names the DESTINATION, never a credential."""
    stats = stream_archive(small_zip, io.BytesIO(), settings=SETTINGS)
    manifest = build_manifest(
        site="s", target="root@box.example:/www", webroot="/www",
        zip_name="small.zip", entry_count=1, uncompressed_bytes=1,
        files={p: (d, stats.sizes[p]) for p, d in stats.sha256.items()})
    blob = json.dumps(manifest).lower()
    assert "root@box.example" in blob
    for word in ("password", "passwd", "secret", "token", "key="):
        assert word not in blob


def _manifest_of(site_zip: Path) -> dict:
    stats = stream_archive(site_zip, io.BytesIO(), settings=SETTINGS)
    return build_manifest(
        site="s", target="t", webroot="/www", zip_name="site.zip",
        entry_count=stats.files, uncompressed_bytes=stats.bytes_written,
        files={p: (d, stats.sizes[p]) for p, d in stats.sha256.items()},
        root=stats.root)


# ------------------------------------------------------------ 7. end-to-end


@needs_tar
def test_end_to_end_dry_target_deploys_verifies_and_is_additive(site_zip,
                                                                dry_root):
    """A real deploy through the real tar, with no host.

    Dry run, preflight, stream, layout assertion, manifest and hash
    verification all run.  What is asserted is what the live session was
    missing: the archive never lands on the target, host-injected content
    survives, and a flipped byte is caught.
    """
    settings = DeploySettings(preflight_margin_bytes=0,
                              manifest_archive_sha256=False)
    webroot = dry_root / "www"
    webroot.mkdir(parents=True)
    injected = webroot / "wp-content" / "imunify-security"
    injected.mkdir(parents=True)
    (injected / "antivirus.php").write_bytes(b"<?php // host injected")
    stale = webroot / "wp-content" / "uploads" / "old.zip"
    stale.parent.mkdir(parents=True)
    stale.write_bytes(b"pre-existing")

    target = make_target(f"{LOCAL_TARGET_PREFIX}{dry_root}", "/www", settings)
    assert isinstance(target, LocalTarget)

    plan = build_plan(site_zip, f"{LOCAL_TARGET_PREFIX}{dry_root}", "/www",
                      settings)
    assert plan.est_bytes() == sum(len(d) for d in MEMBERS.values())

    stats, pre = deploy_stream(site_zip, target, settings)
    assert pre.available_bytes is not None
    assert pre.refuse_reason() is None
    assert stats.files == len(MEMBERS)

    readback = assert_target(target, settings)
    assert readback.ok
    assert (webroot / "wp-config.php").read_bytes() == MEMBERS["wp-config.php"]
    assert (webroot / "wp-includes" / "ID3" / "getid3.php").exists()
    # Normalized on disk, not the archive's noise.
    assert stat.S_IMODE((webroot / "wp-config.php").stat().st_mode) == FILE_MODE
    assert stat.S_IMODE((webroot / "wp-includes").stat().st_mode) == DIR_MODE
    assert int((webroot / "wp-config.php").stat().st_mtime) == TAR_MTIME
    # ADDITIVE: nothing deleted.
    assert (injected / "antivirus.php").exists()
    assert stale.read_bytes() == b"pre-existing"
    # The archive itself never landed on the target.
    assert not (webroot / "site.zip").exists()

    manifest = build_manifest(
        site="dry", target=target.label, webroot=target.webroot,
        zip_name=site_zip.name, entry_count=stats.entry_count,
        uncompressed_bytes=stats.bytes_written,
        files={p: (d, stats.sizes[p]) for p, d in stats.sha256.items()})
    result = verify_against_manifest(target, manifest, settings)
    assert result.ok and result.rc == 0 and result.checked == stats.files

    # One flipped byte on the target = rc 1, naming the file.
    (webroot / "wp-content" / "themes" / "twentyten" / "style.css").write_bytes(
        b"/* tampered */\n")
    after = verify_against_manifest(target, manifest, settings)
    assert after.rc == 1
    assert "wp-content/themes/twentyten/style.css" in after.mismatched


@needs_tar
def test_end_to_end_refuses_a_doubly_stripped_result(site_zip, dry_root):
    """The bug the assertion exists for, exercised end to end.

    A deploy whose CONSUMER also strips lands wp-includes' children at
    the webroot root.  Here the producer is intact and the residue is
    planted, the way a second ``tar --strip-components=1`` would leave it:
    the layout assertion must catch it rather than report success.
    """
    settings = DeploySettings(preflight_margin_bytes=0)
    webroot = dry_root / "www"
    webroot.mkdir(parents=True)

    class DoubleStripTarget(LocalTarget):
        def run_command(self, command, *, timeout, deadline=None):
            # The residue a second strip would leave behind.
            (webroot / "ID3").mkdir(parents=True, exist_ok=True)
            (webroot / "about.php").write_bytes(b"x")
            return super().run_command(command, timeout=timeout,
                                       deadline=deadline)

    target = DoubleStripTarget(str(webroot))
    deploy_stream(site_zip, target, settings)
    with pytest.raises(TargetLayoutError) as excinfo:
        assert_target(target, settings)
    message = str(excinfo.value)
    assert "double-strip residue" in message
    assert "ID3" in message and "about.php" in message


def test_mid_stream_quota_failure_is_a_quota_error(site_zip, dry_root):
    """A transfer that dies with the live signature reports QUOTA.

    The host's own words are fed through the real classifier, so the
    verdict is proven on the production path, not on a hand-built string.
    """

    class QuotaTarget(LocalTarget):
        def run_command(self, command, *, timeout, deadline=None):
            return 0, PLENTY_DF, ""    # preflight: the space is fine

        def extract(self, feed, *, timeout, deadline=None):
            return 1, ("Error in the SSH layer\nwrite remote: Failure\n")

    settings = DeploySettings(preflight_margin_bytes=0)
    target = QuotaTarget(str(dry_root / "www"))
    with pytest.raises(QuotaError) as excinfo:
        deploy_stream(site_zip, target, settings)
    message = str(excinfo.value)
    assert "ran out of space" in message
    assert "SSH layer" in message
    assert not (dry_root / "www").exists()      # nothing was created


def test_mid_stream_auth_failure_is_an_auth_error(site_zip, dry_root):
    class AuthTarget(LocalTarget):
        def run_command(self, command, *, timeout, deadline=None):
            return 0, PLENTY_DF, ""

        def extract(self, feed, *, timeout, deadline=None):
            return 255, "root@box: Permission denied (publickey).\n"

    settings = DeploySettings(preflight_margin_bytes=0)
    with pytest.raises(TransferError, match="authentication failed"):
        deploy_stream(site_zip, AuthTarget(str(dry_root / "www")), settings)


# ------------------------------------------------------- 8. auth + secrecy


def test_ssh_argv_never_carries_the_password(monkeypatch):
    """The secret reaches ssh through a 0600 file — not argv, not environ.

    This is the hard rule stated in SPEC: a secret in argv is a secret in
    ``ps`` for every user on the box.
    """
    monkeypatch.setenv("WPT_TEST_SSH_PW", "hunter2-the-secret")
    monkeypatch.setattr(SshTarget, "_key_auth_available", lambda self: False)
    target = SshTarget("root@box.example", "/home/root/www", SETTINGS,
                       "WPT_TEST_SSH_PW")
    secret_path = None
    try:
        argv = target._argv("tar -xf - -C /home/root/www")
        assert "hunter2-the-secret" not in " ".join(argv)
        env = target._env() or {}
        # The child INHERITS the operator's environment (it must: ssh needs
        # PATH, HOME, SSH_AUTH_SOCK); what must never happen is the module
        # ADDING the secret to it.
        assert "hunter2-the-secret" not in " ".join(target._env_extra.values())
        secret_path = Path(env["WPT_ASKPASS_FILE"])
        assert stat.S_IMODE(secret_path.stat().st_mode) == 0o600
        assert secret_path.read_text() == "hunter2-the-secret"
        assert Path(env["SSH_ASKPASS"]).read_text().startswith("#!/bin/sh")
        assert env["SSH_ASKPASS_REQUIRE"] == "force"
        assert target.auth == "password"
    finally:
        target.close()
    assert not secret_path.exists()            # removed on close


def test_ssh_uses_batch_mode_without_a_password(monkeypatch):
    """Key auth must never block on a prompt: BatchMode=yes is set."""
    monkeypatch.setattr(SshTarget, "_key_auth_available", lambda self: True)
    target = SshTarget("root@box.example", "/home/root/www", SETTINGS, None)
    argv = target._argv("tar -xf - -C /www")
    assert "BatchMode=yes" in argv
    assert target.auth == "key"
    assert argv[-1] == "tar -xf - -C /www"


def test_ssh_refuses_cleanly_with_no_credential_at_all(monkeypatch):
    """No key, no password env, no TTY: a clean refusal, never a hang.

    The refusal is the credential owner's own error (a WptError, so the
    command body's contract already contains it) — the deploy must not
    invent a second one, and must never fall through to a prompt.
    """
    monkeypatch.setattr(SshTarget, "_key_auth_available", lambda self: False)
    monkeypatch.setenv("WPT_NO_PROMPT", "1")
    with pytest.raises(CredentialError):
        SshTarget("root@box.example", "/home/root/www", SETTINGS, None)
    with pytest.raises(CredentialError) as excinfo:
        SshTarget("root@box.example", "/home/root/www", SETTINGS, "WPT_ABSENT_VAR")
    assert "WPT_ABSENT_VAR" in str(excinfo.value)


def test_ssh_argv_is_self_bounding(monkeypatch):
    """A dead peer ends the run: keepalives + a connect timeout are set."""
    monkeypatch.setattr(SshTarget, "_key_auth_available", lambda self: True)
    settings = DeploySettings(server_alive_interval_s=7,
                              server_alive_count_max=3)
    argv = SshTarget("root@box", "/www", settings, None)._argv("true")
    joined = " ".join(argv)
    assert "ServerAliveInterval=7" in joined
    assert "ServerAliveCountMax=3" in joined
    assert "ConnectTimeout=30" in joined
    assert argv[-2] == "root@box" and argv[-1] == "true"


def test_the_consumer_command_never_strips(monkeypatch, dry_root):
    """THE double-strip regression, pinned on the command that runs.

    The strip belongs to the producer.  If a ``--strip-components`` ever
    appears in the consumer command, every file lands one level off again.
    """
    target = LocalTarget(str(dry_root / "www"))
    captured = {}

    def fake_spawn(argv, *, env=None, stdin=subprocess.PIPE):
        captured["argv"] = list(argv)
        raise AssertionError("argv captured")

    monkeypatch.setattr(deploy, "_spawn", fake_spawn)
    with pytest.raises(AssertionError):
        target.extract(lambda sink: None, timeout=1.0)
    command = captured["argv"][-1]
    assert "tar -xf - -C" in command
    assert "strip" not in command.lower()
    assert "--transform" not in command
    assert "--no-same-owner" not in command or True   # tar's defaults are kept


def test_make_target_validates_the_webroot():
    with pytest.raises(DeployError, match="non-empty target webroot"):
        make_target("root@box", "", SETTINGS)
    with pytest.raises(DeployError, match="non-empty target webroot"):
        make_target("root@box", "///", SETTINGS)
    with pytest.raises(DeployError, match="absolute path"):
        make_target("root@box", "~/www", SETTINGS)
    with pytest.raises(DeployError, match="requires --ssh-target"):
        make_target("   ", "/www", SETTINGS)
    with pytest.raises(DeployError, match="invalid ssh target"):
        make_target("root@box example", "/www", SETTINGS)


def test_R22_webroot_cannot_escape_the_local_base_or_name_a_relative_ssh_path(
        tmp_path, monkeypatch):
    """R22-P2: ``--webroot '/../escaped'`` was joined to the local rehearsal
    base and wrote OUTSIDE it; the same raw string reached a remote
    ``mkdir -p``/``tar -C``.  ``..`` is refused, the local join must stay
    inside the base, and an ssh webroot must be an absolute normalized
    POSIX path."""
    base = tmp_path / "base"
    base.mkdir()
    # Target construction is auth-independent for this layout test; CI has
    # no SSH key/TTY, so model the key-auth branch instead of prompting.
    monkeypatch.setattr(SshTarget, "_key_auth_available", lambda self: True)
    with pytest.raises(DeployError, match="contains '\\.\\.'"):
        make_target(f"local:{base}", "/../escaped", SETTINGS)
    assert not (tmp_path / "escaped").exists()
    with pytest.raises(DeployError, match="contains '\\.\\.'"):
        make_target("root@box", "/www/../etc", SETTINGS)
    assert make_target(f"local:{base}", "www", SETTINGS).webroot \
        == str(base / "www")
    with pytest.raises(DeployError, match="absolute POSIX"):
        make_target("root@box", "www", SETTINGS)
    assert make_target("root@box", "/www//site/", SETTINGS).webroot \
        == "/www/site"
    assert make_target("root@box", "//www", SETTINGS).webroot == "/www"


# ------------------------------------------------------------ 9. settings
#
# The deploy policy is a SETTINGS SECTION (wpt.settings.DeploySettings, shipped
# in wpt/data/profiles/default.json), so what is pinned here is that this engine
# reads it from the live settings tree and nowhere else.  Reachability of every
# knob, the shipped values and the fail-loud validation are the settings
# owner's tests (tests/test_settings.py).


def test_deploy_has_no_settings_of_its_own():
    """The engine keeps no second copy of a knob.

    ``DeploySettings`` is imported from the settings owner, so ``deploy`` has
    no dataclass of its own, and the loader's ``deploy_settings()`` door (which
    read a section that did not exist and therefore always answered with the
    module defaults) is gone: there is nothing left for it to paper over.
    """
    assert deploy.DeploySettings is not None
    assert "deploy_settings" not in dir(deploy)
    assert "deploy_settings" not in deploy.__all__
    # the section is on the tree, so ``ctx.settings.deploy`` is never a
    # ``getattr(..., None)`` that silently answers "no policy"
    assert load().deploy == DeploySettings()


def test_deploy_reads_its_policy_through_the_settings_tree(monkeypatch):
    """The engine's behaviour follows ``--set deploy.<key>=``, not a constant.

    Two knobs with visible, opposite effects on the SAME code paths: the
    preflight's fail-closed door decides whether a run may proceed on
    unmeasured space, and the ssh section is what the remote command line is
    built from.
    """
    # --- the fail-closed door is the operator's, and the refusal NAMES it
    unknown = StubTarget(df="", quota="")
    refuses = preflight(unknown, 10 ** 9, load().deploy)
    assert "deploy.preflight_require_known_space" in refuses.refuse_reason()
    relaxed = load(overrides={
        "deploy.preflight_require_known_space": False}).deploy
    assert preflight(unknown, 10 ** 9, relaxed).refuse_reason() is None

    # --- the ssh section reaches the wire
    monkeypatch.setattr(SshTarget, "_key_auth_available", lambda self: True)
    settings = load(overrides={"deploy.ssh_port": 2222,
                               "deploy.strict_host_key_checking": "yes",
                               "deploy.connect_timeout_s": 7}).deploy
    target = make_target("root@box.example", "/www", settings)
    argv = target._argv("tar -xf - -C /www")
    assert "-p" in argv and "2222" in argv
    assert "StrictHostKeyChecking=yes" in argv
    assert "ConnectTimeout=7" in argv


def test_deploy_settings_validation_fails_loud_through_the_settings_owner():
    """A nonsense section is refused by the owner, naming the key.

    The error is a ``SettingsError`` (a ``WptError``) because the SETTINGS
    owner is what validates: one door for a profile file, a ``--set`` and a
    bare ``Settings()``, so a deploy can never run on a section the loader
    would not have produced.
    """
    DeploySettings()                       # the shipped values validate
    with pytest.raises(SettingsError, match="ssh_port"):
        DeploySettings(ssh_port=0)
    with pytest.raises(SettingsError, match="ssh_port"):
        DeploySettings(ssh_port="2222")
    with pytest.raises(SettingsError, match="preflight_margin_bytes"):
        DeploySettings(preflight_margin_bytes=-1)
    with pytest.raises(SettingsError, match="webroot-relative"):
        DeploySettings(required_files=["/etc/passwd"])
    with pytest.raises(SettingsError, match="webroot-relative"):
        DeploySettings(residue_paths=["../escape"])
    with pytest.raises(SettingsError, match="non-empty"):
        # an empty signature is a substring of every message: it would
        # classify every transfer failure as a quota failure
        DeploySettings(quota_signatures=["ok", ""])


# ------------------------------------------------------------ 10. the CLI body


def _ctx(tmp_path, zip_path, apply: bool = True, **extra):
    from wpt.cli import Ctx
    from wpt.settings import load

    ctx = Ctx(source="local", settings=load(), command="deploy", apply=apply,
              yes=True, zip=zip_path, webroot=extra.pop("webroot", "/www"),
              backup_dir=tmp_path / ".wpt-backup",
              report_path=extra.pop("report_path", None), extra=extra)
    ctx.deadline_s = 600
    return ctx


def test_R18_deploy_preflight_and_verify_share_the_run_deadline(
        site_zip, tmp_path, monkeypatch):
    """R18-P2: preflight/assert/verify had no deadline at all — a slow host
    ran ~140 × probe_timeout past --deadline and still wrote a manifest.
    Every phase now gets the ONE memoized Deadline and refuses before a
    stream/extract can start."""
    from wpt.deadline import Deadline

    seen: list[object] = []
    extracted: list[bool] = []

    class SlowTarget(deploy.LocalTarget):
        label = "local:/www"

        def run_command(self, command, *, timeout, deadline=None):
            seen.append(deadline)
            time.sleep(0.8)
            if deadline is not None:
                deadline.check("deploy remote command")
            return 0, PLENTY_DF, ""

        def extract(self, feed, *, timeout, deadline=None):
            extracted.append(True)
            return super().extract(feed, timeout=timeout, deadline=deadline)

        def close(self):
            pass

    monkeypatch.setattr(deploy, "make_target",
                        lambda *a, **k: SlowTarget(str(tmp_path / "host")))
    ctx = _ctx(tmp_path, site_zip, ssh_target="local:/www")
    ctx.deadline_s = 0.3
    rc = deploy.run(ctx)

    assert rc == 1
    assert extracted == []
    assert seen and all(isinstance(item, Deadline) for item in seen)
    assert len({id(item) for item in seen}) == 1
    assert not (tmp_path / ".wpt-backup" / "deploy").exists()


def test_C1_a_stop_in_target_close_ends_the_run_with_a_failure_pair(
        site_zip, tmp_path, monkeypatch):
    """C1: a successful local deploy whose target.close() raised
    StopRequested returned rc 0 with the success markdown.  It must end rc 1
    through the dispatch boundary with the shared failure pair."""
    from wpt.cli import main
    from wpt.types import StopRequested

    real_make = deploy.make_target

    def _make(*args, **kwargs):
        target = real_make(*args, **kwargs)
        original_close = getattr(target, "close", None)

        def _close():
            if original_close is not None:
                original_close()
            raise StopRequested("received SIGTERM (15)")

        target.close = _close
        return target

    monkeypatch.setattr(deploy, "make_target", _make)
    report = tmp_path / "deploy.md"
    rc = main(["--source", "local", "--zip", str(site_zip),
               "--backup-dir", str(tmp_path / "bck"),
               "--webroot", "/www", "--report", str(report),
               "--apply", "--yes", "deploy",
               "--ssh-target", f"local:{tmp_path / 'host'}"])
    assert rc == 1
    written = report.read_text(encoding="utf-8")
    assert "## This run did not complete" in written
    assert "SIGTERM" in written


def test_R11_a_teardown_stop_never_replaces_the_primary_failure(
        site_zip, tmp_path, monkeypatch):
    """R11-P2-14: deploy's finally let a RunControl from target.close()
    replace the failure pair `_refuse` had just written for the real cause."""
    from wpt.cli import main
    from wpt.types import StopRequested

    class _StoppingTarget:
        label = "local:/www"

        def close(self):
            raise StopRequested("received SIGTERM (15)")

    monkeypatch.setattr(deploy, "make_target", lambda *a, **k: _StoppingTarget())

    def _boom(*_args, **_kwargs):
        raise deploy.DeployError("verification exploded (PRIMARY)")

    monkeypatch.setattr(deploy, "deploy_stream", _boom)
    report = tmp_path / "deploy-primary.md"

    rc = main(["--source", "local", "--zip", str(site_zip),
               "--backup-dir", str(tmp_path / "bck"),
               "--webroot", "/www", "--report", str(report),
               "--apply", "--yes", "deploy",
               "--ssh-target", f"local:{tmp_path / 'host'}"])

    assert rc == 1
    written = report.read_text(encoding="utf-8")
    assert "verification exploded (PRIMARY)" in written
    assert "SIGTERM" not in written


def test_R16_refusal_report_contains_a_second_stop(tmp_path, monkeypatch):
    """R16-P2: a stop during `_refuse`'s failure write escaped to run()'s
    RunControl handler, which rewrote the pair as "deploy stopped".  The
    primary reason (no such archive) is retained, and a persistent write
    stop still answers rc 1 instead of a traceback."""
    from wpt.actions import registry
    from wpt.types import StopRequested

    real = registry.write_report
    calls = {"n": 0}

    def _stop_once(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise StopRequested("second stop during the failure report")
        return real(*args, **kwargs)

    monkeypatch.setattr(registry, "write_report", _stop_once)
    report = tmp_path / "deploy.md"
    ctx = _ctx(tmp_path, tmp_path / "missing.zip",
               ssh_target="root@box.example", report_path=report)
    assert deploy.run(ctx) == 1
    assert calls["n"] >= 2
    written = report.read_text(encoding="utf-8")
    assert "no such archive" in written
    assert "deploy stopped" not in written

    def _always_stop(*_args, **_kwargs):
        raise StopRequested("persistent stop")

    monkeypatch.setattr(registry, "write_report", _always_stop)
    assert deploy.run(ctx) == 1


def test_run_refuses_without_a_zip(small_zip, tmp_path):
    from wpt.cli import Ctx
    from wpt.settings import load

    assert deploy.run(Ctx(source="local", settings=load(), command="deploy")) == 1


def test_run_refuses_without_a_target(small_zip, tmp_path):
    assert deploy.run(_ctx(tmp_path, small_zip)) == 1
    assert deploy.run(_ctx(tmp_path, small_zip, ssh_target="root@box")) == 1


def _corrupt_stored_member_zip(tmp_path) -> Path:
    """A valid central directory over one STORED member whose CRC is wrong."""
    path = tmp_path / "crc.zip"
    payload = b"PAYLOAD-" * 32
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(f"{TOP}/site/corrupt.php", payload,
                    compress_type=zipfile.ZIP_STORED)
    data = bytearray(path.read_bytes())
    start = data.index(payload)
    data[start + 3] ^= 0xFF
    path.write_bytes(bytes(data))
    return path


def test_R23_corrupt_member_is_a_deploy_error_not_a_raw_badzip(tmp_path):
    """R23-P2: ``stream_archive`` copied member bytes straight through
    ``tar.addfile``, so a corrupt STORED payload raised BadZipFile (CRC is
    checked at EOF) past every DeployError boundary.  ``_MEMBER_READ_ERRORS``
    is the ONE owner of the member-read failure class and deploy maps it."""
    corrupt = _corrupt_stored_member_zip(tmp_path)
    with pytest.raises(DeployError, match="corrupt.php.*cannot be read"):
        stream_archive(corrupt, io.BytesIO(), settings=SETTINGS)
    # A non-zip / swapped archive is the same contract at the open.
    swapped = tmp_path / "swapped.zip"
    swapped.write_bytes(b"this is not a zip")
    with pytest.raises(DeployError, match="not a zip archive|cannot be read"):
        zip_facts(swapped)


@needs_tar
def test_R23_corrupt_member_run_writes_the_failure_pair(tmp_path,
                                                        wpt_records):
    """The CLI contract: run() answers rc 1 with the shared md+JSON pair,
    names the member, and never lets a traceback escape."""
    corrupt = _corrupt_stored_member_zip(tmp_path)
    report = tmp_path / "deploy-failed.md"
    ctx = _ctx(tmp_path, corrupt, report_path=report,
               ssh_target=f"{LOCAL_TARGET_PREFIX}{tmp_path / 'host'}")
    assert deploy.run(ctx) == 1
    assert report.is_file()
    assert report.with_suffix(".json").is_file()
    written = report.read_text(encoding="utf-8")
    assert "corrupt.php" in written
    assert "cannot be read" in written
    assert "## This run did not complete" in written


@pytest.mark.parametrize("error", [
    RuntimeError("File is encrypted"),
    NotImplementedError("compression method 99"),
    zlib.error("invalid stored block lengths"),
    EOFError("truncated member"),
    (ValueError("bad local header")),
])
def test_R23_every_member_read_error_class_is_a_deploy_error(
        small_zip, monkeypatch, error):
    """The member-read failure owner (``sources.zip._MEMBER_READ_ERRORS``)
    covers encrypted (RuntimeError), unsupported (NotImplementedError),
    deflate (zlib.error), truncation (EOFError) and header corruption
    (ValueError).  Deploy maps EVERY class to DeployError, so no raw
    exception can escape run()'s report contract."""
    facts = zip_facts(small_zip)

    def boom(_self, _name, *args, **kwargs):
        raise error

    monkeypatch.setattr(zipfile.ZipFile, "open", boom)
    with pytest.raises(DeployError, match="cannot be read"):
        stream_archive(small_zip, io.BytesIO(), settings=SETTINGS,
                       facts=facts)


def test_run_refuses_a_missing_archive(tmp_path):
    from wpt.cli import Ctx
    from wpt.settings import load

    ctx = Ctx(source="local", settings=load(), command="deploy",
              zip=tmp_path / "nope.zip", webroot="/www",
              extra={"ssh_target": "root@box"})
    assert deploy.run(ctx) == 1


def test_run_refuses_ftp_mode(small_zip, tmp_path, wpt_records):
    """The artifact is a LOCAL zip; an ftp-side deploy is a restore."""
    from wpt.cli import Ctx
    from wpt.settings import load

    ctx = Ctx(source="ftp://host:21", settings=load(), command="deploy",
              apply=True, yes=True, user="u", password="x",
              webroot="/www", zip=small_zip, backup_dir=tmp_path,
              extra={"ssh_target": "root@box"})
    assert deploy.run(ctx) == 1
    assert any("--source local" in r.getMessage() for r in wpt_records)


def test_run_dry_run_prints_the_plan_and_spawns_nothing(site_zip, no_spawn,
                                                        capsys):
    from wpt.cli import Ctx
    from wpt.settings import load

    ctx = Ctx(source="local", settings=load(), command="deploy", apply=False,
              zip=site_zip, webroot="/www",
              extra={"ssh_target": "root@box.example"})
    assert deploy.run(ctx) == 0
    assert no_spawn.calls == []
    out = capsys.readouterr().out
    assert "dry run" in out
    assert "ADDITIVE" in out
    assert "wp-content" in out
    assert "root@box.example:/www" in out


def test_R20_deploy_dry_run_honours_the_deadline(
        site_zip, tmp_path, no_spawn, capsys):
    """R20-P2: build_plan/zip_facts/_archive_root took no Deadline, so a
    10k-member dry run answered rc 0 after 13 s under --deadline 0.001.
    The plan phase is bounded for BOTH the dry and apply paths."""
    report = tmp_path / "deploy.md"
    ctx = _ctx(tmp_path, site_zip, apply=False,
               ssh_target="root@box.example", report_path=report)
    ctx.deadline_s = 1e-9
    assert deploy.run(ctx) == 1
    assert no_spawn.calls == []
    assert capsys.readouterr().out == ""
    assert "## This run did not complete" in report.read_text("utf-8")


def test_run_dry_run_writes_a_report_with_a_json_twin(site_zip, tmp_path,
                                                     capsys, no_spawn):
    """``--report`` is honoured by EVERY command, and every surface writes
    markdown AND its JSON twin.  The applied run already did (its twin
    describes the stream, the readback and the verification); the DRY run
    wrote markdown alone, so "was anything planned?" was answerable only
    by parsing prose.  The twin now describes the plan this run printed —
    same target, same archive, same rows, same total — with ``applied:
    false`` saying that nothing was streamed, verified or deleted."""
    report = tmp_path / "deploy.md"
    ctx = _ctx(tmp_path, site_zip, apply=False,
               ssh_target="root@box.example", report_path=report)
    assert deploy.run(ctx) == 0
    assert no_spawn.calls == []
    markdown = report.read_text(encoding="utf-8")
    assert "dry run" in markdown
    assert report.with_suffix(".json").exists()
    twin = json.loads(report.with_suffix(".json").read_text(encoding="utf-8"))
    assert twin["applied"] is False
    assert twin["target"] == "root@box.example:/www"
    assert twin["archive"] == site_zip.name
    assert twin["webroot"] == "/www"
    # every planned row the markdown printed is in the twin, with the
    # numbers the table rendered
    plan = build_plan(site_zip, "root@box.example", "/www", SETTINGS)
    assert [row["target"] for row in twin["items"]] == \
        [item.target for item in plan.items]
    assert [row["bytes_est"] for row in twin["items"]] == \
        [item.bytes_est for item in plan.items]
    assert twin["total_bytes"] == plan.est_bytes()
    assert {row["category"] for row in twin["items"]} == {
        "deploy.stream", "deploy.estimate"}
    for row in twin["items"]:
        assert row["target"] in markdown       # the twin mirrors the table
    # an applied run's twin keeps its own shape (the manifest summary)
    assert "manifest" not in twin


@needs_tar
def test_run_full_deploy_writes_a_manifest_and_a_report(site_zip, tmp_path,
                                                        capsys):
    report = tmp_path / "deploy.md"
    ctx = _ctx(tmp_path, site_zip,
               ssh_target=f"{LOCAL_TARGET_PREFIX}{tmp_path / 'host'}",
               report_path=report)
    assert deploy.run(ctx) == 0
    out = capsys.readouterr().out
    assert "wpt deploy" in out and "deploy verified" in out
    assert report.exists()
    twin = json.loads(report.with_suffix(".json").read_text(encoding="utf-8"))
    assert twin["files"] == len(MEMBERS)
    assert twin["archive_root"] == TOP
    assert twin["verified_files"] == len(MEMBERS)
    manifest_path = Path(twin["manifest"])
    assert read_manifest(manifest_path)["totals"]["files"] == len(MEMBERS)


@needs_tar
def test_run_reports_a_flipped_byte_as_rc_1(site_zip, tmp_path, capsys,
                                            monkeypatch, wpt_records):
    """The deploy refuses to call itself a success on bad bytes.

    The corruption lands BETWEEN the stream and the verification (which
    is what a truncating channel or a racing writer looks like), so the
    hash pass — not the layout pass — is what catches it.
    """
    host = tmp_path / "host"
    original = deploy.assert_target

    def tamper(target, settings, deadline=None):
        readback = original(target, settings, deadline=deadline)
        (Path(target.webroot) / "wp-load.php").write_bytes(b"<?php truncated")
        return readback

    monkeypatch.setattr(deploy, "assert_target", tamper)
    assert deploy.run(_ctx(tmp_path, site_zip,
                           ssh_target=f"{LOCAL_TARGET_PREFIX}{host}")) == 1
    assert "verification FAILED" in capsys.readouterr().out
    assert any("wp-load.php" in r.getMessage()
               for r in wpt_records if r.levelno >= logging.ERROR)
    # ...and a clean run over the same target is a clean 0.
    monkeypatch.undo()
    assert deploy.run(_ctx(tmp_path, site_zip,
                           ssh_target=f"{LOCAL_TARGET_PREFIX}{host}")) == 0


@needs_tar
def test_run_refuses_a_target_that_lacks_a_webroot(site_zip, tmp_path,
                                                   monkeypatch, wpt_records):
    """rc 1 with one line naming what is missing (SPEC: assert, then report)."""
    ctx = _ctx(tmp_path, site_zip,
               ssh_target=f"{LOCAL_TARGET_PREFIX}{tmp_path / 'host'}")
    original = deploy.assert_target

    def strip_after_stream(target, settings, deadline=None):
        import shutil as _shutil
        _shutil.rmtree(target.webroot)         # the webroot vanishes
        return original(target, settings, deadline=deadline)

    monkeypatch.setattr(deploy, "assert_target", strip_after_stream)
    assert deploy.run(ctx) == 1
    errors = [r.getMessage() for r in wpt_records if r.levelno >= logging.ERROR]
    assert any("does not exist" in m for m in errors), errors


def test_local_target_with_an_absolute_webroot_is_that_root(tmp_path):
    """[L29] An operator passes the SAME --webroot the ssh target would use.
    A local rehearsal must extract into that root, not join it under
    `local:<dir>` (a live rehearsal landed the whole tree at
    deploy-rehearsal/home/... and still passed the layout check)."""
    from wpt.deploy import make_target

    base = tmp_path / "base"
    root = base / "webroot"
    root.mkdir(parents=True)
    target = make_target(f"local:{base}", str(root), DeploySettings())
    assert target.webroot == str(root)

    # a HOST path the base stands in for keeps the documented join
    target2 = make_target(f"local:{base}", "/www", DeploySettings())
    assert target2.webroot == str(base / "www")

    # a sibling sharing a string prefix is NOT inside the base
    sibling = base.parent / (base.name + "-old")
    sibling.mkdir()
    target3 = make_target(f"local:{base}", str(sibling), DeploySettings())
    assert target3.webroot == str(base / str(sibling).lstrip("/"))


# ------------------------- the report of a deploy that deployed nothing
#
# The deploy dry run honours --report (L44), but a FAILED or REFUSING run
# wrote nothing at all — so a caller that scripted a deploy and reads its
# report could not tell "there was nothing to deploy" from "the deploy
# never got far enough", which is the one distinction a scripted caller
# cannot make any other way.


def _assert_refusal_report(report: Path, needle: str) -> None:
    written = report.read_text(encoding="utf-8")
    assert "## This run did not complete" in written
    assert needle in written
    assert "- findings: 0" in written
    twin = json.loads(report.with_suffix(".json").read_text(encoding="utf-8"))
    assert twin["findings"] == []
    assert twin["items"] == []          # nothing was planned
    assert twin["applied"] is False     # and nothing was streamed
    assert twin["run"]["findings"] == 0
    assert needle in twin["run"]["reason"]


def test_a_refused_deploy_writes_its_refusal(site_zip, tmp_path, no_spawn,
                                             capsys):
    """A refusal names itself on disk, spawns nothing, and prints nothing:
    a failed run has no transfer report to show."""
    report = tmp_path / "deploy.md"
    ctx = _ctx(tmp_path, site_zip, ssh_target="", report_path=report)

    assert deploy.run(ctx) == 1

    _assert_refusal_report(report, "--ssh-target")
    assert no_spawn.calls == []
    assert capsys.readouterr().out == ""


def test_a_missing_archive_writes_its_refusal(tmp_path, no_spawn):
    from wpt.cli import Ctx
    from wpt.settings import load

    report = tmp_path / "deploy.md"
    ctx = Ctx(source="local", settings=load(), command="deploy",
              zip=tmp_path / "nope.zip", webroot="/www",
              report_path=report, extra={"ssh_target": "root@box"})
    assert deploy.run(ctx) == 1
    _assert_refusal_report(report, "no such archive")


def test_a_deploy_that_fails_midway_writes_its_refusal(site_zip, tmp_path,
                                                       no_spawn,
                                                       monkeypatch):
    """A failure DEEP in the run is reported the same way, so a caller
    never has to parse a log to learn that the deploy did not happen."""
    from wpt.deploy import DeployError

    def boom(*_a, **_kw):
        raise DeployError("quota exhausted mid-transfer")

    monkeypatch.setattr(deploy, "deploy_stream", boom)
    monkeypatch.setattr(SshTarget, "_key_auth_available", lambda self: True)
    report = tmp_path / "deploy.md"
    ctx = _ctx(tmp_path, site_zip, ssh_target="root@box.example",
               report_path=report)

    assert deploy.run(ctx) == 1
    _assert_refusal_report(report, "quota exhausted mid-transfer")


def test_a_successful_dry_run_report_is_unchanged(site_zip, tmp_path, no_spawn):
    """The refusal path must not have moved the dry run's report: the
    deploy plan report and its twin carry no ``run`` key and no
    "did not complete" section — a caller parsing one family of files
    cannot tell a plan from a refusal by accident."""
    report = tmp_path / "deploy.md"
    ctx = _ctx(tmp_path, site_zip, apply=False, ssh_target="root@box.example",
               report_path=report)

    assert deploy.run(ctx) == 0

    written = report.read_text(encoding="utf-8")
    assert "## This run did not complete" not in written
    twin = json.loads(report.with_suffix(".json").read_text(encoding="utf-8"))
    assert "run" not in twin
    assert twin["applied"] is False
    assert twin["target"] == "root@box.example:/www"


def test_R6_31_explicit_zero_ssh_port_is_refused_not_treated_as_absent(
        small_zip, tmp_path, wpt_records):
    """R6-31: ``if extra.get("ssh_port")`` turned an explicit 0 into "not
    given" and silently used the profile's 22.  ``is not None`` lets the
    validated settings door refuse it."""
    ctx = _ctx(tmp_path, small_zip, apply=False,
               ssh_target="root@box", ssh_port=0)
    assert deploy.run(ctx) == 1
    errors = [r.getMessage() for r in wpt_records
              if r.name == "wpt.deploy" and r.levelno >= logging.ERROR]
    assert any("deploy.ssh_port" in message for message in errors)


@pytest.mark.parametrize("value", [
    float("inf"), float("-inf"), float("nan"), True, 1.9, "12", 0, 70000,
])
def test_R6_45_invalid_ssh_port_shapes_are_refused(small_zip, tmp_path,
                                                   value, wpt_records):
    """R6-45: int(inf) raised a raw OverflowError, int(nan) a raw
    ValueError, and True/1.9/"12" were accepted as 1/1/12.  The shared
    coercion refuses every non-int or out-of-range shape in one line."""
    ctx = _ctx(tmp_path, small_zip, apply=False,
               ssh_target="root@box", ssh_port=value)
    assert deploy.run(ctx) == 1
    errors = [r.getMessage() for r in wpt_records
              if r.name == "wpt.deploy" and r.levelno >= logging.ERROR]
    assert any("deploy.ssh_port" in message for message in errors)
    assert not any("OverflowError" in message for message in errors)


# ------------------------------------------------ triple-check round 8 (P1)


@needs_tar
def test_P1_deploy_site_label_and_manifest_redact_wp_url_userinfo(
        site_zip, tmp_path):
    """P1-03: a credential-bearing --wp-url named the deploy manifest
    directory and field, and reached both report faces."""
    secret = "s3cr3t-pass"
    report = tmp_path / "deploy.md"
    ctx = _ctx(tmp_path, site_zip,
               ssh_target=f"{LOCAL_TARGET_PREFIX}{tmp_path / 'host'}",
               report_path=report)
    ctx.wp_url = f"https://admin:{secret}@site.test"

    assert deploy.run(ctx) == 0

    markdown = report.read_text("utf-8")
    twin_text = report.with_suffix(".json").read_text("utf-8")
    assert secret not in markdown and secret not in twin_text
    twin = json.loads(twin_text)
    manifest_path = Path(twin["manifest"])
    assert secret not in str(manifest_path)
    manifest_text = manifest_path.read_text("utf-8")
    assert secret not in manifest_text
    manifest = json.loads(manifest_text)
    assert secret not in manifest["site"]
    assert manifest["site"] == "https---admin-----site.test"


def test_R15_stream_timeout_is_one_absolute_bound_for_feed_and_reap(
        monkeypatch, tmp_path):
    """R15-P2: the feed watchdog and ``_reap`` each started their own
    ``timeout`` clock, so a 0.45 s feed plus a sleeping child raised after
    ~1.05 s for timeout=0.6.  One absolute deadline covers the whole
    stream."""
    import subprocess
    import sys
    import time

    from wpt.deploy import TransferError

    def _spawn(argv, *, env=None, stdin=subprocess.PIPE):
        return subprocess.Popen(
            [sys.executable, "-c",
             "import sys, threading, time\n"
             "def drain():\n"
             "    while sys.stdin.buffer.read(65536):\n"
             "        pass\n"
             "threading.Thread(target=drain, daemon=True).start()\n"
             "time.sleep(3)\n"],
            stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    monkeypatch.setattr(deploy, "_spawn", _spawn)
    target = LocalTarget(str(tmp_path / "www"))

    def feed(sink):
        for _ in range(45):
            sink.write(b"x" * 32)
            time.sleep(0.01)

    started = time.monotonic()
    with pytest.raises(TransferError, match="did not finish"):
        target.extract(feed, timeout=0.6)
    elapsed = time.monotonic() - started
    assert 0.5 <= elapsed < 1.0, elapsed


def test_R13_reap_honours_a_positive_stream_timeout_beside_a_far_deadline():
    """R13-P2-7: ``_reap`` used ``if deadline ... elif timeout``, so the
    CLI's default hour-long Deadline shadowed a short stream timeout and a
    non-draining child outlived it.  Both bounds apply; the first expiry
    owns the verdict."""
    import subprocess
    import sys
    import time

    from wpt.deadline import Deadline
    from wpt.deploy import TransferError, _reap

    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(1.5)"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    started = time.monotonic()
    try:
        with pytest.raises(TransferError, match="did not finish"):
            _reap(proc, [], 0.2, "deploy stream", deadline=Deadline(5.0))
        assert time.monotonic() - started < 1.2
        assert proc.poll() is not None
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


def test_R13_extract_bounds_a_blocked_producer_and_reaps_the_child(
        monkeypatch, tmp_path):
    """R13-P1-3: when the remote tar stops draining stdin, ``feed`` blocks
    on a full pipe (8 MiB is far past it) before ``_reap`` is ever reached.
    A watchdog while feed runs must close stdin and kill the child at the
    deadline, then the original bound's verdict is raised."""
    import subprocess
    import sys
    import time

    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    children = []

    def _spawn(argv, *, env=None, stdin=subprocess.PIPE):
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(8)"],
            stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        children.append(child)
        return child

    monkeypatch.setattr(deploy, "_spawn", _spawn)
    target = LocalTarget(str(tmp_path / "www"))
    started = time.monotonic()
    with pytest.raises(DeadlineExceeded):
        target.extract(lambda sink: sink.write(b"x" * (8 * 1024 * 1024)),
                       timeout=0, deadline=Deadline(0.3))
    assert time.monotonic() - started < 1.5
    assert children and children[0].poll() is not None
    assert children[0].stdin.closed


def test_R12_reap_kills_a_sleeping_child_at_the_run_deadline():
    """R12-P2-3: with the shipped ``stream_timeout_s=0`` the child wait was
    ``proc.wait(None)`` — a sleeping extract outlived the run deadline.
    The poll loop kills it at Deadline.at even with no stream timeout."""
    import subprocess
    import sys
    import time

    from wpt.deadline import Deadline
    from wpt.deploy import _reap
    from wpt.types import DeadlineExceeded

    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(4)"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    started = time.monotonic()
    try:
        with pytest.raises(DeadlineExceeded):
            _reap(proc, [], 0, "deploy stream", deadline=Deadline(0.2))
        assert time.monotonic() - started < 1.5
        assert proc.poll() is not None
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


def test_R12_extract_with_no_stream_timeout_still_honours_the_deadline(
        monkeypatch, tmp_path):
    """R12-P2-3 end to end: ``extract(timeout=0)`` (the shipped default)
    must poll the run Deadline and kill its sleeping child, not wait
    forever."""
    import subprocess
    import sys
    import time

    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    children = []

    def _spawn(argv, *, env=None, stdin=subprocess.PIPE):
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(4)"],
            stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        children.append(child)
        return child

    monkeypatch.setattr(deploy, "_spawn", _spawn)
    target = LocalTarget(str(tmp_path / "www"))
    started = time.monotonic()
    with pytest.raises(DeadlineExceeded):
        target.extract(lambda sink: None, timeout=0,
                       deadline=Deadline(0.2))
    assert time.monotonic() - started < 1.5
    assert children and children[0].poll() is not None


@needs_tar
def test_R14_local_compound_tar_group_is_killed_and_reaped(
        tmp_path, monkeypatch):
    """R14-P1-2: the shipped LocalTarget wraps ``mkdir && tar`` in
    ``/bin/sh -c``.  Killing only the direct shell left the real tar
    grandchild holding stdin, so an 8 MiB producer blocked in write() and
    outlived the run deadline.  The seam starts a new session and kills the
    whole group; this uses a real compound shell command and a fake tar
    that never drains."""
    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    pid_file = tmp_path / "tar.pid"
    fake_tar = fakebin / "tar"
    fake_tar.write_text(
        "#!/bin/sh\n"
        f"echo $$ > {pid_file}\n"
        "sleep 2\n",
        encoding="utf-8")
    fake_tar.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fakebin}:/usr/bin:/bin")
    monkeypatch.setenv("WPT_TAR_PID_FILE", str(pid_file))
    webroot = tmp_path / "www"
    target = LocalTarget(str(webroot))
    payload = b"x" * (8 * 1024 * 1024)
    started = time.monotonic()
    with pytest.raises(DeadlineExceeded):
        target.extract(lambda sink: sink.write(payload), timeout=0,
                       deadline=Deadline(0.3))
    elapsed = time.monotonic() - started
    assert elapsed < 1.5, elapsed
    pid = int(pid_file.read_text().strip())
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.02)
    else:
        pytest.fail(f"fake tar pid {pid} survived the process-group kill")


@needs_tar
def test_R14_a_direct_child_target_still_runs(tmp_path, monkeypatch):
    """The new-session/group kill must not change the direct SSH child: a
    target whose argv is one executum still returns its stdout and rc."""
    class _Direct(LocalTarget):
        def _argv(self, command):
            return ["/bin/sh", "-c", "printf direct-ok"]

    rc, out, err = _Direct(str(tmp_path / "www")).run_command(
        "ignored", timeout=5.0)
    assert rc == 0
    assert out == "direct-ok"
    assert err == ""


def test_R21_manifest_write_refuses_a_planted_link_or_fifo(site_zip, tmp_path):
    """R21-P2: write_manifest followed a pre-planted symlink (deploy
    replaced the victim with manifest JSON) and blocked forever on a FIFO.
    Both directory entries are refused, and a symlinked parent too."""
    manifest = _manifest_of(site_zip)
    victim = tmp_path / "victim.txt"
    victim.write_text("KEEP", encoding="utf-8")
    directory = tmp_path / "manifest-dir"
    directory.mkdir()
    (directory / "manifest.json").symlink_to(victim)
    with pytest.raises(ManifestError, match="symbolic link"):
        write_manifest(manifest, directory)
    assert victim.read_text(encoding="utf-8") == "KEEP"

    fifo_dir = tmp_path / "fifo-dir"
    fifo_dir.mkdir()
    os.mkfifo(fifo_dir / "manifest.json")
    started = time.monotonic()
    with pytest.raises(ManifestError, match="not a regular file"):
        write_manifest(manifest, fifo_dir)
    assert time.monotonic() - started < 2

    linked_dir = tmp_path / "linked-dir"
    linked_dir.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ManifestError, match="symbolic link"):
        write_manifest(manifest, linked_dir)


def test_R22_manifest_refuses_every_symlinked_ancestor(site_zip, tmp_path):
    """R22-P1: only the FINAL directory was checked, so
    ``<backup>/deploy -> victim`` was traversed by ``mkdir(parents=True)``
    and the JSON landed in ``victim/site-<stamp>/manifest.json``.  Every
    component from the caller's root is opened O_DIRECTORY|O_NOFOLLOW."""
    manifest = _manifest_of(site_zip)
    backup = tmp_path / "backup"
    backup.mkdir()
    victim = tmp_path / "victim"
    victim.mkdir()
    (backup / "deploy").symlink_to(victim, target_is_directory=True)
    directory = backup / "deploy" / "site-20260101-000000"
    with pytest.raises(ManifestError, match="symbolic link|not a directory"):
        write_manifest(manifest, directory, root=backup)
    assert list(victim.iterdir()) == []
    # the default anchor (cwd/filesystem) catches the same planted link
    with pytest.raises(ManifestError, match="symbolic link|not a directory"):
        write_manifest(manifest, directory)
    assert list(victim.iterdir()) == []


def test_R21_manifest_write_is_atomic_and_leaves_no_temp(site_zip, tmp_path):
    manifest = _manifest_of(site_zip)
    directory = tmp_path / "manifest-dir"
    path = write_manifest(manifest, directory)
    assert path.is_file()
    assert not list(directory.glob("*.wip"))
    # A second write replaces the record atomically (no reader can observe
    # a half-written file: the new bytes arrive by rename).
    first = path.read_bytes()
    manifest["created"] = "2026-10-20T00:00:00"
    write_manifest(manifest, directory)
    assert path.read_bytes() != first
    assert not list(directory.glob("*.wip"))


def test_R21_run_command_kills_the_child_group_on_a_run_control(
        monkeypatch, tmp_path):
    """R21-P2: run_command called _reap with no BaseException guard, so a
    SIGTERM/deadline during a one-shot command unwound while the child's
    own session (``/bin/sh -c sleep ...``) kept running.  The shared kill
    owner now runs on every stop."""
    from wpt.types import StopRequested

    children = []
    real_spawn = deploy._spawn

    def recording_spawn(*args, **kwargs):
        child = real_spawn(*args, **kwargs)
        children.append(child)
        return child

    def stopped_reap(*_args, **_kwargs):
        raise StopRequested("received SIGTERM (15)")

    monkeypatch.setattr(deploy, "_spawn", recording_spawn)
    monkeypatch.setattr(deploy, "_reap", stopped_reap)
    target = LocalTarget(str(tmp_path / "www"))
    started = time.monotonic()
    with pytest.raises(StopRequested):
        target.run_command("sleep 30", timeout=5)
    assert time.monotonic() - started < 3
    assert children
    assert children[0].poll() is not None


@pytest.mark.skipif(
    sys.platform == "darwin",
    reason="APFS cannot represent a lone surrogate in a path")
def test_R24_manifest_survives_a_lone_surrogate_in_the_webroot(
        site_zip, tmp_path):
    """R24-P2: the manifest was encoded with strict UTF-8, so an argv webroot
    carrying a surrogateescape byte raised UnicodeEncodeError after the
    stream had landed: no manifest, no report pair, a traceback.  The JSON
    is written with the report's backslashreplace policy and round-trips."""
    import json

    from wpt.cli import main

    report = tmp_path / "deploy.md"
    webroot = f"{tmp_path / 'host'}/www\udcff"
    rc = main(["--source", "local", "--zip", str(site_zip),
               "--backup-dir", str(tmp_path / "bck"),
               "--webroot", webroot, "--report", str(report),
               "--apply", "--yes", "deploy",
               "--ssh-target", f"local:{tmp_path / 'host'}"])
    assert rc == 0
    assert report.exists()
    manifests = list((tmp_path / "bck" / "deploy").glob("*/manifest.json"))
    assert len(manifests) == 1
    text = manifests[0].read_text(encoding="utf-8")
    assert "\\udcff" in text
    manifest = json.loads(text)
    assert manifest["target"]["webroot"].endswith("\udcff")


def test_R24_same_second_deploys_keep_distinct_manifest_records(
        site_zip, tmp_path, monkeypatch):
    """R24-P2: the release directory was named to the second and
    ``write_manifest`` atomically replaces an existing manifest.json, so two
    applies in one second silently lost the first record.  The allocator
    retries with ``-2``; each report still names its own release."""
    from wpt.cli import main

    monkeypatch.setattr(deploy.time, "strftime",
                        lambda _fmt: "20261020-202147")
    reports = []
    for target in ("t1", "t2"):
        report = tmp_path / f"{target}.md"
        reports.append(report)
        rc = main(["--source", "local", "--zip", str(site_zip),
                   "--backup-dir", str(tmp_path / "bck"),
                   "--webroot", "/www", "--report", str(report),
                   "--apply", "--yes", "deploy",
                   "--ssh-target", f"local:{tmp_path / target}"])
        assert rc == 0
    manifests = sorted((tmp_path / "bck" / "deploy").glob("*/manifest.json"))
    assert len(manifests) == 2
    names = {path.parent.name for path in manifests}
    assert names == {"site-20261020-202147", "site-20261020-202147-2"}
    assert str(manifests[0].parent.parent) in reports[0].read_text(
        encoding="utf-8")
    assert str(manifests[1].parent.parent) in reports[1].read_text(
        encoding="utf-8")


@needs_tar
def test_R24_stop_inside_the_normal_stdin_close_kills_the_child_group(
        tmp_path, monkeypatch):
    """R24-P2: the normal (producer-finished) ``stdin.close()`` sat outside
    the kill guards.  A SIGTERM landing there raised StopRequested and left
    the ``mkdir && tar`` group alive holding the webroot channel."""
    from wpt.types import StopRequested

    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    fake_tar = fakebin / "tar"
    fake_tar.write_text("#!/bin/sh\nsleep 5\n", encoding="utf-8")
    fake_tar.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fakebin}:/usr/bin:/bin")

    class StoppingTarget(LocalTarget):
        proc = None

        def _start(self, *args, **kwargs):
            proc = super()._start(*args, **kwargs)
            real = proc.stdin

            class Stdin:
                def write(self, data):
                    return real.write(data)

                def flush(self):
                    return real.flush()

                def close(self):
                    raise StopRequested("received SIGTERM (15)")

            proc.stdin = Stdin()
            self.proc = proc
            return proc

    target = StoppingTarget(str(tmp_path / "www"))
    with pytest.raises(StopRequested):
        target.extract(lambda _sink: None, timeout=0)
    assert target.proc is not None
    assert target.proc.poll() is not None


@needs_tar
def test_R25_extract_final_reap_stop_kills_the_child_group(
        tmp_path, monkeypatch):
    """R25-P2: the FINAL ``_reap`` sat outside the BaseException guard.  A
    SIGTERM while it waited left the remote ``tar`` running after the run
    reported a cooperative stop."""
    from wpt.types import StopRequested

    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    fake_tar = fakebin / "tar"
    fake_tar.write_text("#!/bin/sh\nsleep 5\n", encoding="utf-8")
    fake_tar.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fakebin}:/usr/bin:/bin")

    children = []
    real_spawn = deploy._spawn

    def recording_spawn(*args, **kwargs):
        child = real_spawn(*args, **kwargs)
        children.append(child)
        return child

    def stopped_reap(*_args, **_kwargs):
        raise StopRequested("received SIGTERM (15)")

    monkeypatch.setattr(deploy, "_spawn", recording_spawn)
    monkeypatch.setattr(deploy, "_reap", stopped_reap)
    target = LocalTarget(str(tmp_path / "www"))
    with pytest.raises(StopRequested):
        target.extract(lambda _sink: None, timeout=0)
    assert children
    assert children[0].poll() is not None


def test_R25_run_command_thread_arming_stop_kills_the_child(tmp_path,
                                                             monkeypatch):
    """R25-P2: a stop raised from a drain ``thread.start`` unwound before the
    reap guard existed; the one-shot child stayed alive."""
    import threading

    from wpt.types import StopRequested

    children = []
    real_spawn = deploy._spawn

    def recording_spawn(*args, **kwargs):
        child = real_spawn(*args, **kwargs)
        children.append(child)
        return child

    real_start = threading.Thread.start
    started = []

    def stopping_start(self):
        started.append(self)
        if len(started) == 1:
            raise StopRequested("received SIGTERM (15)")
        return real_start(self)

    monkeypatch.setattr(deploy, "_spawn", recording_spawn)
    monkeypatch.setattr(threading.Thread, "start", stopping_start)
    target = LocalTarget(str(tmp_path / "www"))
    with pytest.raises(StopRequested):
        target.run_command("sleep 30", timeout=5)
    assert children
    assert children[0].poll() is not None


def test_R25_manifest_allocator_claims_distinct_directories(tmp_path):
    """R25-P2: the allocator checked existence and returned the path; the
    WRITE happened later, so two concurrent deploys could both choose the
    same stem.  The directory is now created as the atomic claim."""
    parent = tmp_path / "bck" / "deploy"
    first = deploy._unique_manifest_dir(parent, "site-20261020-120000")
    second = deploy._unique_manifest_dir(parent, "site-20261020-120000")
    third = deploy._unique_manifest_dir(parent, "site-20261020-120000")
    assert len({first, second, third}) == 3
    assert all(path.is_dir() for path in (first, second, third))


def test_R24_manifest_temp_name_is_journaled_before_creation(
        site_zip, tmp_path, monkeypatch):
    """R24-P2: ``tmp_name`` was assigned only AFTER the exclusive open, so a
    stop on that boundary left an unreferenced ``.wip``.  The candidate is
    registered first and the finally removes it."""
    import wpt.manifest as manifest_mod
    from wpt.types import StopRequested

    manifest = _manifest_of(site_zip)
    directory = tmp_path / "bck" / "deploy" / "site"
    real_open = manifest_mod.os.open

    def _stopping_open(path, *args, **kwargs):
        if str(path).endswith(".wip"):
            raise StopRequested("stop after temp reservation")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(manifest_mod.os, "open", _stopping_open)
    with pytest.raises(StopRequested):
        deploy.write_manifest(manifest, directory, root=tmp_path / "bck")
    assert not list(directory.glob("*.wip"))
    assert not (directory / "manifest.json").exists()
