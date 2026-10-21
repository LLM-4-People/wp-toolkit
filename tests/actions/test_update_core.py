"""Tests for the update-core action (wpt.actions.update_core).

NO network: the wp.org fetches ride the real WpOrgApi transport over the
shared FakeSession (tests/audit/test_integrity.py conventions) with the
response cache monkeypatched to a tmp_path via ``updates._CACHE_DIR`` —
or SEEDED (version-check JSON / checksums maps / release-zip bytes) for
the local-mode runs, whose fresh plain session cannot be scripted.
Release zips are small REAL in-memory zips, ``wordpress/``-nested like
the official releases, each carrying its own ``wp-includes/version.php``
with the ``$wp_version`` / ``$wp_db_version`` globals the action reads
(tests/actions/test_heal_core.py's zip shape).

The ftp-mode bridge is a double recording every call and modelling the
LIVE server against ONE store: ``info`` reports the version the SOURCE
currently holds (so the post-write verify sees the new tree, exactly as
a fresh PHP process would) and the schema version ``upgrade_core``
advances; ``core_md5`` digests the SAME store the apply writes to, so a
done item proves the digest round trip.  UpdateSource extends the shared
FakeSource with the three seams a core update needs and the shared
double lacks: ``rename`` (the tree swap), a REAL ``rmdir_recursive``
(the shared double's is a guard-only no-op) and the ``allow_core``
unlock forwarded to the shared write guard (the shared double accepts
the kwarg but drops it, so without the forwarding every core write would
hit NotWritableError — reported to the coordinator, exactly as
tests/actions/test_heal_core.py reports it).

Test -> behavior map:

  registration
    test_registration .................. update-core registered as the
        INSTANCE under applies=("ftp", "local") — both modes reachable

  the plan (read-only, no --to)
    test_plan_without_target_is_a_report .. the offer menu, the exact
        version a --to would need, an EMPTY plan, and the request shape
    test_plan_target_unoffered_refuses ... wp.org does not offer it

  the plan's facts (ftp)
    test_plan_minor_bump_items_and_facts  the item set is the release's
        own core surface (wp-admin/, wp-includes/, root *.php), sorted,
        with the release's own sizes; the db_version pair; the PHP/MySQL
        floors against the live site; the maintenance line; the snapshot
        scope + the `wpt restore --undo-last` rollback
    test_plan_junk_policy_subtracts_sample [L19] wp-config-sample.php is
        in the release and is in webroot_junk: never written back
    test_plan_wp_content_is_never_in_scope wp-content/** in the release
        is structurally out of scope

  the refusals (one line, cause + lever)
    test_refuses_offered_pre_release_without_the_flag
    test_refuses_dev_install_without_the_flag
    test_refuses_php_floor_above_live_php
    test_refuses_unreadable_live_php
    test_refuses_multisite
    test_refuses_same_version (idempotency: a second run at the same
        version refuses "ALREADY the running version")
    test_refuses_downgrade
    test_refuses_dirty_core .......... an in-scope file that does not
        match the official CURRENT checksums (the compromise lever)
    test_refuses_unreadable_in_scope_file .. a short/unreadable read of
        a file the swap would overwrite
    test_refuses_unknown_version / test_refuses_unoffered_target
    test_refuses_release_zip_unavailable / test_refuses_checksums_unavailable

  the apply
    test_apply_minor_bump_replaces_files .. the happy path: staged trees
        + one rename per tree, root files temp+rename, .maintenance
        written and REMOVED, no wp-content/ or wp-config.php touched,
        every digest verified, the cache purge left to the registry
    test_apply_major_bump_migrates_the_database .. db_version advanced
        through the bridge's core_upgrade, the verify re-reading the
        DATABASE (a fresh info), and no migration at all when the target
        does not raise the schema version
    test_apply_release_bytes_disagree_with_the_map ... a checksum
        mismatch aborts with NOTHING written (the pre-swap proof)
    test_apply_mid_swap_failure_keeps_the_installed_tree .. an injected
        rename failure rolls the WHOLE write phase back and .maintenance
        is cleaned (the FULL tree state, not one tree of it)
    test_apply_refuses_when_the_site_changed_between_plan_and_apply
    test_apply_no_target_refuses (a hand-built plan with no --to)

  the apply over the FTP SEAM (the real FtpSource against the fake
  ftplib server, so every remote operation is wire traffic)
    test_apply_over_ftp_creates_its_staging_directories_and_swaps ...
        the live 553 reproduced and fixed at the chokepoint (the staging
        MKDs), plus a per-operation verdict on the rest of the apply:
        root temp+rename, the two RNFR/RNTO per name, the .maintenance
        WRITE and DELETE, the parked-copy removal
    test_apply_over_ftp_undo_puts_the_installed_tree_back ... the
        WHOLE-TREE undo when a tree's second rename fails: both trees
        and every root file back, byte for byte (the per-tree undo this
        replaces left the first tree swapped)
    test_apply_over_ftp_undo_at_a_root_file_restores_the_whole_core ...
        the same undo when the failure lands on a ROOT FILE, which had no
        predecessor to put back at all
    test_a_failed_swap_over_ftp_reports_not_done_with_the_snapshot ...

  the wire shape of the schema version (F3/F8)
    test_a_string_db_version_on_the_wire_verifies_the_update ... the
        whole apply over the REAL payload shape (the bridge casts the
        stored option to a JSON STRING); the verify must pass
    test_the_schema_version_the_action_reads_is_a_number_not_the_wire_string
    test_a_schema_ahead_of_the_target_is_not_refused / ..._behind_..._is_
        still_refused / ..._unreadable_..._is_refused_not_assumed

  the fail-closed gates (F12/F13/F14)
    test_an_info_payload_without_multisite_is_refused
    test_an_empty_webroot_walk_refuses_before_any_write
    test_refuses_mysql_floor_above_live_engine / ..._unreadable_...
    test_a_mariadb_engine_suffix_is_compared_not_refused
    test_the_verify_re_reads_the_engine_against_the_floor

  the unknown addition inside a replaced tree (F11)
    test_refuses_an_unknown_addition_inside_a_replaced_tree ... the
        refusal names the lever that EXISTS and says why known_added
        cannot match a core-tree path
    test_known_added_cannot_cover_a_core_tree_path ... the same site
        with the key CONFIGURED: still refused

  a run KILLED mid-swap (F6) — os._exit(137) in a child process over a
  real directory
    test_a_run_killed_mid_swap_leaves_a_recoverable_webroot ... both
        halves of the interrupted name on disk, a two-rename recovery
        that restores the installed core, and a .maintenance file that
        explains itself
    test_the_next_command_reports_a_killed_runs_residue ... the residue
        report names both trees and the live name each goes back to

  the residue (F7) — one owner in wpt.types
    test_the_sweep_removes_the_root_temp_files_too
    test_the_sweep_never_deletes_a_parked_tree_but_reports_it
    test_the_next_run_reports_the_residue_of_a_killed_one
    test_the_residue_report_runs_without_a_target
    test_the_residue_rule_is_one_owner

  a migration that FATALS (F10)
    test_a_migration_that_fatals_still_reports_the_state_it_began_in
    test_a_migration_that_fatals_without_a_marker_says_what_it_read

  the two DRIVERS (update.driver: wordpress | swap | auto, shipped auto)
    test_auto_names_wordpress_when_the_site_can_run_core_updater .. the
        plan NAMES the driver and why, and the plan it names is the same
        plan the swap driver gets
    test_auto_falls_back_to_swap_when_the_site_cannot .. each
        precondition, and the UNREADABLE one, resolve to the driver that
        needs neither
    test_the_plan_asks_the_site_for_the_driver_facts .. the two facts
        ride the plan's own info call (core_upgrade=1)
    test_a_driver_named_outright_and_unavailable_refuses .. wordpress on
        a site that cannot run it refuses, before the release is fetched
    test_the_wordpress_driver_refuses_in_local_mode /
    test_auto_in_local_mode_rehearses_the_swap .. offline there is no
        running PHP, so the driver is the swap
    test_the_apply_refuses_when_the_driver_changed_since_the_plan ..
        plan wordpress, apply would be swap -> REFUSE, nothing written
    test_the_wordpress_driver_installs_the_release_and_verifies .. the
        whole apply through core's own updater: the proven release
        uploaded, the op called once, the plan's stale files removed (the
        step core's copy never does), maintenance engaged and removed,
        the migration run, the digest pass and the live probes green
    test_a_core_failure_leaves_abspath_untouched_and_the_run_not_done ..
        ABSPATH byte-identical, every item not done, no migration
    test_the_verify_says_why_it_does_not_trust_core_s_own_step .. the
        fire-and-forget fact, on both drivers

  the residue of the wordpress driver (wp-content/upgrade/)
    test_the_staging_under_wp_content_is_reported_and_never_swept .. the
        operator's recovery path is NAMED with its owner and kept
    test_a_verified_run_clears_only_the_staging_it_created .. a staging
        this run created, after the verify passed, and nothing else
    test_a_failed_verify_keeps_the_staging_it_created

  the local rehearsal
    test_apply_local_rehearsal_upgrades_a_copy .. the REAL registry flow
        over a real zip: the materialized copy carries the TARGET's file
        set, wp-content/ is byte-identical, .maintenance is absent, the
        original zip is untouched (it IS the rollback)

  the registry end to end
    test_registry_ftp_apply_is_fail_closed ... the pre-action snapshot
        holds every replaced file + the two dumped tables, and
        `wpt restore --undo-last` is the documented rollback
    test_registry_reports_carry_no_secret ... nothing secret in the
        report (the plan carries paths, versions and sizes only)
"""

import hashlib
import io
import json
import logging
import os
import posixpath
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest
import requests

import wpt.audit.updates as updates
from tests.fakes import FakeResponse, FakeSession, FakeSource
from wpt.actions import registry as registry_mod
from wpt.actions.update_core import UpdateCoreAction
from wpt.actions.registry import get_action, run_action
from wpt.cli import Ctx
from wpt.report import Plan, PlanItem
from wpt.settings import load
from wpt.deadline import Deadline
from wpt.types import (BridgeError, DeadlineExceeded, Entry, Source,
                       SourceError, WptError)

#: The repository root, for the child process the SIGKILL test runs.
REPO = Path(__file__).resolve().parents[2]

#: The shipped profile — the action reads update.pre_release_allowed,
#: update.maintenance, http.timeout_s and webroot_junk from it.
DEFAULTS = load()

SITE = "https://example.com"

#: The installed site: 6.8.3, schema 56657.
CURRENT = "6.8.3"
CURRENT_DB = 56657
#: The target of most tests: a MINOR bump, which in real WordPress DOES
#: advance the schema (6.8 -> 7.1 is 56657 -> 60356).
TARGET = "7.1.2"
TARGET_DB = 60356
#: A PATCH target: the same schema as the installed version, so the
#: migration is genuinely a no-op and the run must not call the op.
PATCH = "6.8.4"
PATCH_DB = CURRENT_DB
#: A MAJOR target.
MAJOR = "8.0.0"
MAJOR_DB = 61150

PHP_FLOOR = "7.4"
MYSQL_FLOOR = "5.5.5"
LIVE_PHP = "8.2.12"
LIVE_MYSQL = "8.0.36"

TABLES = ["wp_options", "wp_posts"]

#: Where the wordpress driver's staging lives — core's own directory, and
#: the residue rule's "never swept blindly" owner.
_STAGING_PREFIX = "wp-content/upgrade/"

#: The UpdateBridge default: report the version the STORE's own
#: version.php declares, so a post-write verify sees the swapped tree the
#: way a fresh PHP process would.  Any other value (including None) is
#: forced onto the wire, which is how a scripted wire shape is modelled.
LIVE = "<live>"


def version_php(version: str, db_version: int, *, local: str | None = None
                ) -> bytes:
    """A release's ``wp-includes/version.php`` — the two globals wpt reads."""
    body = (f"<?php\n$wp_version = '{version}';\n"
            f"$wp_db_version = {db_version};\n")
    if local is not None:
        body += f"$wp_local_package = '{local}';\n"
    return (body + "?>\n").encode()


#: The site as installed (one store, two views — see the module docstring).
def site_files() -> dict[str, bytes]:
    return {
        "index.php": b"<?php // index 6.8.3\n",
        "wp-load.php": b"<?php // load 6.8.3\n",
        "wp-includes/version.php": version_php(CURRENT, CURRENT_DB),
        "wp-includes/js/old.js": b"/* 6.8.3 */\n",
        "wp-admin/index.php": b"<?php // admin 6.8.3\n",
        "wp-config.php": b"<?php // the site's own config\n",
        "wp-content/plugins/hello.php": b"<?php /* plugin */\n",
        "wp-content/themes/twentytwentyfour/style.css": b"/* theme */\n",
    }


#: What the TARGET release ships (the zip's own namelist is the scope).
def release_files(version: str = TARGET, db_version: int = TARGET_DB
                  ) -> dict[str, bytes]:
    return {
        "index.php": f"<?php // index {version}\n".encode(),
        "wp-load.php": f"<?php // load {version}\n".encode(),
        "wp-settings.php": f"<?php // settings {version}\n".encode(),
        "wp-includes/version.php": version_php(version, db_version),
        "wp-includes/js/new.js": f"/* {version} */\n".encode(),
        "wp-admin/index.php": f"<?php // admin {version}\n".encode(),
        # OUT of the core surface, and the test pins both exclusions:
        "wp-content/themes/twentytwentyfive/style.css": b"/* bundled */\n",
        "wp-config-sample.php": b"<?php // sample\n",
        "license.txt": "WordPress\n".encode(),
        "readme.html": "<h1>WordPress</h1>\n".encode(),
    }


#: The core surface the update must plan — derived, never hardcoded here.
IN_SCOPE = (
    "index.php",
    "wp-admin/index.php",
    "wp-includes/js/new.js",
    "wp-includes/version.php",
    "wp-load.php",
    "wp-settings.php",
)

#: A file the INSTALLED release shipped inside a replaced tree and the
#: TARGET does not.  Swapping wp-includes removes it, so the plan carries
#: it (bytes_est=0) and the pre-action snapshot captures it — without that,
#: `wpt restore --undo-last` could not undo a deletion.
STALE = ("wp-includes/js/old.js",)
#: Everything the plan lists, sorted.
ALL_ITEMS = tuple(sorted(IN_SCOPE + STALE))


def release_map(version: str = TARGET, db_version: int = TARGET_DB
                ) -> dict[str, str]:
    """``path -> md5`` for EVERY file a release ships — what wp.org's
    checksum map actually answers, wp-content/ and the junk files
    included.  The scope predicate and the junk subtraction are what
    narrow it, so the fixture never pre-narrows the map for them."""
    return {path: hashlib.md5(blob).hexdigest()
            for path, blob in release_files(version, db_version).items()}


def current_map(version: str = CURRENT, db_version: int = CURRENT_DB
                ) -> dict[str, str]:
    """``path -> md5`` for the INSTALLED files, the pristine-current basis.

    The map of the version the site claims to run, which is what the
    pre-write proof compares the tree against (never the target's: every
    file that legitimately changed between the two would read as dirty).
    """
    files = site_files()
    files["wp-includes/version.php"] = version_php(version, db_version)
    return {path: hashlib.md5(blob).hexdigest()
            for path, blob in files.items()
            if path in ("index.php", "wp-load.php", "wp-includes/version.php",
                        "wp-includes/js/old.js", "wp-admin/index.php")}


@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    """Point the SHARED wp.org cache (owned by updates.py) at a tmp dir."""
    d = tmp_path / "cache"
    monkeypatch.setattr(updates, "_CACHE_DIR", d)
    return d


# ------------------------------------------------------------------ doubles


class UpdateSource(FakeSource):
    """FakeSource + the three seams a core update needs (see the module
    docstring): a REAL ``rename`` (the tree swap), a REAL
    ``rmdir_recursive`` (the shared double's is a guard-only no-op) and
    the ``allow_core`` unlock forwarded to the shared write guard."""

    def __init__(self) -> None:
        super().__init__()
        self.writes: list[tuple[str, dict]] = []
        self.fail_rename: set[str] = set()

    def write_bytes(self, path, data, *, allow_config=False, allow_core=False):
        self._check_writable(path, allow_config, allow_core)
        self.writes.append((path, {"allow_config": allow_config,
                                   "allow_core": allow_core}))
        self._rec("write", path)
        self.files[path] = data

    def exists(self, path):
        """A file OR a directory — the real connectors both answer True for
        a tree path (FtpSource through its parent listing, MutableZipSource
        through its prefix scan), and the file-only store would otherwise
        report every core tree as absent and skip the parking rename."""
        if path in self.files:
            return True
        prefix = f"{path.rstrip('/')}/"
        return any(name.startswith(prefix) for name in self.files)

    def rename(self, src, dst, *, allow_config=False, allow_core=False):
        self._check_rename_target(dst, allow_config, allow_core)
        self._rec("rename", f"{src} -> {dst}")
        if src in self.fail_rename:
            raise SourceError(f"RNTO failed: {src}")
        rel_src, rel_dst = src.rstrip("/"), dst.rstrip("/")
        prefix = f"{rel_src}/"
        moved = 0
        for name in [n for n in self.files
                     if n == rel_src or n.startswith(prefix)]:
            self.files[(rel_dst + name[len(rel_src):]
                        if name.startswith(prefix) else rel_dst)] = (
                self.files.pop(name))
            moved += 1
        if not moved:
            raise SourceError(f"no such file: {src}")

    def rmdir_recursive(self, path):
        self._check_deletable(path)
        self._rec("rmdir", path)
        prefix = f"{path.rstrip('/')}/"
        for name in [n for n in self.files
                     if n == path.rstrip("/") or n.startswith(prefix)]:
            del self.files[name]


class ExpiringSource(UpdateSource):
    """UpdateSource whose run budget expires in the MIDDLE of the swap.

    Every remote op checks the CURRENT budget exactly as ``FtpSource._call``
    does; ``expire_at`` names the rename count at which the budget is spent
    and DeadlineExceeded is raised (the second tree's parking rename by
    default).  ``deadline_suspended`` is the real Source owner, so a cleanup
    block swaps in a fresh finite budget and restores the expired one.
    """

    deadline = None
    cleanup_deadline_s = 5
    deadline_suspended = Source.deadline_suspended

    def __init__(self, expire_at: int = 3) -> None:
        super().__init__()
        self.expire_at = expire_at
        self.renames = 0

    def _check(self) -> None:
        if self.deadline is not None and self.deadline.remaining <= 0:
            raise DeadlineExceeded(
                "run deadline exceeded between core swap renames")

    def rename(self, src, dst, *, allow_config=False, allow_core=False):
        self.renames += 1
        if self.renames == self.expire_at:
            self.deadline = Deadline(-1)
        self._check()
        super().rename(src, dst, allow_config=allow_config,
                       allow_core=allow_core)

    def delete(self, path, *, allow_config=False, allow_core=False):
        self._check()
        super().delete(path, allow_config=allow_config,
                       allow_core=allow_core)

    def exists(self, path):
        self._check()
        return super().exists(path)

    def rmdir_recursive(self, path):
        self._check()
        super().rmdir_recursive(path)


class UpdateBridge:
    """The LIVE server, modelled against the one UpdateSource store.

    ``info`` reads the version out of the store's own
    ``wp-includes/version.php`` — so after the swap it reports the TARGET
    version, exactly as a fresh PHP process would — and the schema
    version from ``db_version``, which only ``upgrade_core`` advances.
    ``core_md5`` digests the same store (absent paths land in
    ``missing``, unreadable ones in ``unreadable``).  Every call is
    recorded, and ``core_md5_script`` overrides ``core_md5`` per call
    for the failure shapes (one item per call: a payload, or an
    exception the way ``BridgeError`` raises for an error envelope).

    THE WIRE SHAPE IS THE REAL ONE.  ``db_version`` is answered as a JSON
    STRING, because that is what the deployed bridge does: a stored
    options row is not an int in PHP, so ``info`` casts it
    deliberately, and the test double used to hand the action a Python
    ``int`` — which is how a 100%-live defect (the verify comparing a
    schema version that could never be anything but ``None``, so every
    correctly-updated site was reported NOT-done) stayed green here for
    the whole life of the action.  A double that is more convenient than
    the wire is a double that hides the wire.
    """

    def __init__(self, source, *, wp_version=LIVE, db_version=CURRENT_DB,
                 php=LIVE_PHP, mysql=LIVE_MYSQL, multisite=False,
                 locale="en_US", core_md5_script=(),
                 db_version_after=TARGET_DB, info_after=None,
                 upgrade=None, fs_method="", zip_library="",
                 core_files_error=None, driver_facts_after=None) -> None:
        self.source = source
        self.wp_version = wp_version
        self.db_version = db_version
        self.db_version_after = db_version_after
        self.php = php
        self.mysql = mysql
        self.multisite = multisite
        self.locale = locale
        self.core_md5_script = list(core_md5_script)
        self.upgrade = upgrade
        self.upgraded = 0
        #: Facts ``info`` answers DIFFERENTLY from the THIRD call on (the
        #: verify's read-back is a different PHP process on a real site, so
        #: the double is told explicitly what the database reports once
        #: the write has landed — the "the op returned but the state did
        #: not move" case a read-back exists to catch). MERGED over the
        #: live facts, so a test overrides one of them. None = keep
        #: reading the live store.
        self.info_after = info_after
        self.info_calls = 0
        self.calls: list[tuple[str, dict]] = []
        self.destroyed = 0
        #: The pre-migration marker core_upgrade writes before it starts;
        #: None until a migration has been asked for.
        self.marker: dict | None = None
        #: Set by a test to make the migration FATAL (a memory_limit on a
        #: big migration is the real shape) — see ``upgrade_core``.
        self.fatal_migration = False
        #: The two ``core_upgrade`` facts ``info`` answers when asked with
        #: core_upgrade=1.  "" is UNKNOWN, which the action's driver
        #: selection reads as "not available here" — the default, so the
        #: driver stays ``swap`` unless a test says the site can run
        #: WordPress's own updater.
        self.fs_method = fs_method
        self.zip_library = zip_library
        #: Answers the facts DIFFERENTLY from the Nth info call on, the
        #: same idiom as info_after: the plan reads them, then the apply
        #: re-derives — and a site that loses ``direct`` between the two
        #: must refuse rather than switch driver.
        self.driver_facts_after = driver_facts_after
        #: A ``BridgeError`` the core_upgrade_files method raises, so a
        #: core failure can be driven through the whole apply.
        self.core_files_error = core_files_error
        #: The staging the modelled op leaves behind ('' = core removed
        #: its own, the success route).
        self.core_staging = ""

    # -- the facts

    def _live_version(self) -> str:
        """The version the STORE's own version.php declares."""
        try:
            raw = self.source.files["wp-includes/version.php"]
        except KeyError:   # pragma: no cover
            return self.wp_version
        match = re.search(rb"\$wp_version\s*=\s*'([^']+)'", raw)
        return match.group(1).decode() if match else self.wp_version

    def call(self, action, **params):
        self.calls.append((action, params))
        if action == "info":
            self.info_calls += 1
            # plan info, apply re-derivation info, then the verify's read
            override = self.info_after if self.info_calls > 2 else None
            payload = {
                "ok": True,
                "wp_version": (self._live_version()
                               if self.wp_version == LIVE
                               else self.wp_version or ""),
                "db_version": str(self.db_version),
                "php_version": self.php,
                "mysql_version": self.mysql,
                "multisite": self.multisite,
            }
            if self.locale is not None:
                payload["locale"] = self.locale
            if override:      # a MERGE: a test overrides one fact only
                payload.update(override)
            if params.get("core_upgrade"):
                # Asked for: the two preconditions of WordPress's OWN
                # updater, read from the RUNNING site (the bridge answers
                # them on request, because get_filesystem_method() writes a
                # probe file into the webroot).  Absent from a plain info
                # answer — the double is faithful about that too.
                # From the SECOND info call on (the apply's
                # re-derivation), which is what a site that lost the
                # precondition between plan and apply looks like.
                facts = (self.driver_facts_after
                         if self.driver_facts_after and self.info_calls > 1
                         else None)
                method, library = facts or (self.fs_method, self.zip_library)
                payload["filesystem_method"] = {
                    "filesystem_method": method, "zip_library": library}
            return payload
        if action == "core_md5":
            if self.core_md5_script:
                item = self.core_md5_script.pop(0)
                if callable(item):
                    item = item(params)
                if isinstance(item, Exception):
                    raise item
                return item
            digests: dict[str, str] = {}
            missing: list[str] = []
            unreadable: list[str] = []
            for path in params["paths"]:
                blob = self.source.files.get(path)
                if blob is None:
                    missing.append(path)
                else:
                    digests[path] = hashlib.md5(blob).hexdigest()
            return {"ok": True, "files": digests, "missing": missing,
                    "unreadable": unreadable}
        if action == "db_audit":
            return {"ok": True, "tables": [{"name": name} for name in TABLES]}
        if action == "purge_cache":   # the registry's post-apply hygiene
            return {"ok": True, "purged": True}
        raise AssertionError(f"unexpected bridge action: {action!r}")

    def upgrade_core(self, *, fatal: bool = False) -> dict[str, Any]:
        """The client's core_upgrade method, modelled: the schema moves.

        ``fatal=True`` models the one failure a non-catchable PHP fatal
        produces: the op's answer is GONE (a BridgeError, because the
        client never sees JSON) and the database is left where the
        migration stopped.  The pre-migration marker the op writes before
        it starts is what survives, and ``upgrade_marker`` below serves it
        — the whole reason the client's error path can say anything at
        all about a vanished response.
        """
        self.calls.append(("core_upgrade", {"apply": True}))
        self.marker = {"started": 1_700_000_000, "from_db_version":
                       str(self.db_version), "target_db_version": TARGET_DB,
                       "wp_version": TARGET, "finished": None}
        if fatal or self.fatal_migration:
            raise BridgeError("bridge returned non-JSON (HTTP 200): "
                              "PHP Fatal error: Allowed memory size of "
                              "16777216 bytes exhausted")
        if self.upgrade is not None:
            return self.upgrade
        self.upgraded += 1
        self.db_version = self.db_version_after
        self.marker["finished"] = 1_700_000_060
        return {"db_version": self.db_version, "wp_version": TARGET,
                "target_db_version": TARGET_DB, "output": "",
                "output_truncated": False}

    def core_upgrade_files(self, package: str, target: str) -> dict[str, Any]:
        """The client's core_upgrade_files method, modelled.

        WordPress's own updater, as the action meets it: it EXTRACTS the
        package the action uploaded into ``wp-content/upgrade/`` and copies
        the release onto the same store every other read in this file sees
        — so the verify's digest pass measures the bytes core laid down,
        exactly as it measures the swap driver's.  ``attempt_rollback`` is
        in the answer because the client returns it, and the phases are
        measured (not asserted into existence) so a test can pin what the
        action does with them.

        ``core_files_error`` raises the way the client raises a core
        failure: a BridgeError whose payload is the op's account.
        """
        self.calls.append(("core_upgrade_files",
                           {"apply": True, "package": package,
                            "target": target}))
        if self.core_files_error is not None:
            raise BridgeError(self.core_files_error,
                              payload={"phases": {"copy": {"ok": False}},
                                       "staging": _STAGING_PREFIX + "wordpress"})
        blob = self.source.files.get(package)
        assert blob is not None, "the action must upload the release first"
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            for name in zf.namelist():
                if name.endswith("/"):
                    continue
                self.source.files[name[len("wordpress/"):]] = zf.read(name)
        self.source.files.pop(package, None)   # the op's sweep owns it
        return {
            "phases": {"unzip": {"ok": True, "detail": "extracted"},
                       "copy": {"ok": True, "detail": "landed"},
                       "bundled": {"ok": True, "detail": "none shipped"}},
            "staging": _STAGING_PREFIX + "wordpress-" + target,
            "staging_exists": bool(self.core_staging),
            "upgrade_args": {"pre_check_md5": False, "attempt_rollback": True,
                             "do_rollback": False,
                             "allow_relaxed_file_ownership": False},
            "rollback": {"armed": True, "taken": False, "reason": "no "
                         "rollback package; the snapshot is the rollback"},
            "progress": ["Verifying the unpacked files…", "Upgrading database…"],
            "bundled_added": [],
            "db_step": "suppressed: wpt runs wp_upgrade() itself",
            "filesystem_method": self.fs_method or "direct",
            "zip_library": self.zip_library or "ZipArchive",
            "maintenance_left": False,
            "output": "",
            "output_truncated": False,
            "wp_version": target,
            "from_wp_version": CURRENT,
        }

    def upgrade_marker(self) -> dict[str, Any] | None:
        """The marker's client-side read (the client normalizes the two
        schema versions through the same wire_int the action uses)."""
        self.calls.append(("info", {}))
        if self.marker is None:
            return None
        return {**self.marker,
                "from_db_version": int(self.marker["from_db_version"]),
                "target_db_version": int(self.marker["target_db_version"])}

    def call_stream(self, action, **params):
        """The backup snapshot's db_dump: one create + one done per table."""
        assert action == "db_dump"
        self.calls.append((action, params))
        for name in params["tables"]:
            yield {"table": name, "create": f"CREATE TABLE `{name}` (id int)"}
            yield {"table": name, "done": 0}

    def destroy(self):
        self.destroyed += 1


# ------------------------------------------------------------------ helpers


def _ctx(tmp_path, **overrides):
    """An update-core Ctx; ftp-mode defaults, overridable per test."""
    fields = dict(
        source="ftp://example.com",
        settings=DEFAULTS,
        command="update-core",
        apply=False,
        yes=False,
        backup_dir=tmp_path / "backup",
        wp_url=SITE,
        extra={"to": TARGET},
    )
    fields.update(overrides)
    return Ctx(**fields)


def version_check(*versions: str, php_floor: str = PHP_FLOOR,
                  mysql_floor: str = MYSQL_FLOOR) -> FakeResponse:
    """A live-shaped core/version-check/1.7 payload (offers[0] is latest)."""
    offers = [{"response": "upgrade" if i == 0 else "autoupdate",
               "current": version, "version": version, "locale": "en_US",
               "php_version": php_floor, "mysql_version": mysql_floor}
              for i, version in enumerate(versions)]
    return FakeResponse(text=json.dumps({"offers": offers}))


def checksums_response(checksums: dict[str, str]) -> FakeResponse:
    return FakeResponse(text=json.dumps({"checksums": checksums}))


def release_zip_bytes(files: dict[str, bytes]) -> bytes:
    """A small REAL in-memory release zip, ``wordpress/``-nested."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for rel, blob in files.items():
            zf.writestr("wordpress/" + rel, blob)
    return buf.getvalue()


def seed_checksums(cache_dir, version: str, checksums: dict[str, str],
                   locale: str = "en_US"):
    """A FRESH checksums cache entry (the real transport serves it offline)."""
    import wpt.audit.integrity as integrity

    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / (updates._cache_key(
        integrity._checksums_url(version, locale), None) + ".json")
    path.write_text(json.dumps({"checksums": checksums}), encoding="utf-8")
    return path


def seed_release_zip(cache_dir, version: str, payload: bytes,
                     locale: str = "en_US"):
    cache_dir.mkdir(parents=True, exist_ok=True)
    name = (f"wp-release-{version}.zip" if locale == "en_US"
            else f"wp-release-{version}-{locale}.zip")
    path = cache_dir / name
    path.write_bytes(payload)
    return path


def seed_local_wporg(cache_dir, target=TARGET, target_db=TARGET_DB,
                     current=CURRENT):
    """Everything a LOCAL-mode run reads from wp.org, seeded in the cache.

    A local run builds its own plain session, which no test double
    scripts, so the answers have to be on disk before it starts — which is
    also what makes them shareable with a SUBPROCESS (the rehearsal test
    and the SIGKILL test both need the same four answers, and neither can
    fake a session the code builds itself).
    """
    import wpt.audit.integrity as integrity
    cache_dir.mkdir(parents=True, exist_ok=True)
    seed_checksums(cache_dir, current, current_map())
    seed_checksums(cache_dir, target, release_map(target, target_db))
    seed_release_zip(cache_dir, target,
                     release_zip_bytes(release_files(target, target_db)))
    (cache_dir / (updates._cache_key(updates.DEFAULT_WP_ORG.core_version_check_url.format(locale=updates.DEFAULT_WP_ORG.default_locale), None)
                  + ".json")).write_text(
        json.dumps({"offers": [{"response": "upgrade", "current": target,
                                "version": target, "locale": "en_US",
                                "php_version": PHP_FLOOR,
                                "mysql_version": MYSQL_FLOOR}]}),
        encoding="utf-8")
    assert integrity.DEFAULT_WP_ORG.default_locale == "en_US"


def wporg_script(version=TARGET, db=TARGET_DB, current=CURRENT,
                 current_db=CURRENT_DB, tail=()):
    """The four wp.org answers a plan consumes, in the order it asks.

    version-check, then the TARGET's checksum map, then the release zip,
    then the INSTALLED version's map (the pristine proof).  ``tail`` is
    for the apply's two live probes, which come after every cached
    re-derivation.
    """
    return [version_check(version, current),
            checksums_response(release_map(version, db)),
            FakeResponse(content=release_zip_bytes(release_files(version, db))),
            checksums_response(current_map(current, current_db)),
            *tail]


def live_ok():
    """The site root and the REST root answering after the update."""
    return [FakeResponse(status_code=200), FakeResponse(status_code=200)]


def make_stack(script=(), *, files=None, source_cls=UpdateSource,
               **bridge_kwargs):
    """A fake ftp-mode update stack: (UpdateSource, FakeSession, UpdateBridge)."""
    src = source_cls()
    src.files.update(files if files is not None else site_files())
    return src, FakeSession(list(script)), UpdateBridge(src, **bridge_kwargs)


def _records(wpt_records, level):
    return [r for r in wpt_records
            if r.name == "wpt.actions.update_core" and r.levelno == level]


def _messages(records):
    return [r.getMessage() for r in records]


def _files_written(src):
    return [path for path, _kwargs in src.writes]


# ------------------------------------------------------------- registration


def test_registration():
    record = get_action("update-core")
    assert record is not None
    assert record.applies == ("ftp", "local")
    assert isinstance(record.action, UpdateCoreAction)  # the instance


# ------------------------------------------------------- the plan, no target


def test_plan_without_target_is_a_report(tmp_path, cache_dir, wpt_records):
    """No --to: the offer menu and the exact version a --to would need.
    An EMPTY plan, because a Plan is a list of files and without a target
    there is no honest one."""
    src, session, bridge = make_stack(
        [version_check(TARGET, CURRENT, "6.7.2")])
    plan = UpdateCoreAction().plan(
        _ctx(tmp_path, extra={}), (src, session, bridge))
    assert plan.items == []
    infos = _messages(_records(wpt_records, logging.INFO))
    assert any("WordPress 6.8.3 is installed; wp.org offers 3" in m
               for m in infos)
    assert any("offer: 7.1.2" in m for m in infos)
    assert any(f"wpt update-core --to {TARGET} --apply" in m for m in infos)
    # the request shape: the version-check URL, the identifying UA, the
    # profile timeout — and nothing else (no zip, no checksums)
    assert len(session.gets) == 1
    url, kw = session.gets[0]
    assert url == updates.DEFAULT_WP_ORG.core_version_check_url.format(locale=updates.DEFAULT_WP_ORG.default_locale)
    assert kw["headers"]["User-Agent"].startswith("wpt/")
    assert kw["timeout"] == DEFAULTS.http.timeout_s
    assert [a for a, _p in bridge.calls] == ["info"]


def test_apply_without_a_target_refuses(tmp_path, cache_dir):
    """``--apply`` with no ``--to`` is a refusal, not an empty plan: the
    registry would otherwise write nothing and exit 0, and a green run
    that never chose a version is the worst possible answer."""
    src, session, bridge = make_stack([])
    with pytest.raises(WptError) as excinfo:
        UpdateCoreAction().plan(
            _ctx(tmp_path, apply=True, extra={}), (src, session, bridge))
    assert "requires --to X.Y.Z" in str(excinfo.value)
    assert "never implicit" in str(excinfo.value)
    assert session.gets == [] and src.writes == []


def test_registry_apply_without_a_target_is_refused(tmp_path, monkeypatch,
                                                     cache_dir):
    """The same refusal through the registry: rc 1, no snapshot, no
    bridge teardown skipped."""
    src, session, bridge = make_stack([])
    monkeypatch.setattr(registry_mod, "_stack",
                        lambda ctx: (src, session, bridge))
    rc = run_action(_ctx(tmp_path, apply=True, yes=True, extra={}),
                    "update-core")
    assert rc == 1
    assert not list((tmp_path / "backup").glob("*/*/manifest.json"))
    assert bridge.destroyed == 1
    assert session.gets == []


def test_plan_target_unoffered_refuses(tmp_path, cache_dir):
    src, session, bridge = make_stack([version_check(TARGET, CURRENT)])
    with pytest.raises(WptError) as excinfo:
        UpdateCoreAction().plan(
            _ctx(tmp_path, extra={"to": "9.9.9"}), (src, session, bridge))
    message = str(excinfo.value)
    assert "wp.org does not offer that version" in message
    assert "pick one of those with --to" in message
    # refused before any zip/checksums traffic
    assert len(session.gets) == 1


# ------------------------------------------------------------- the plan body


def test_plan_minor_bump_items_and_facts(tmp_path, cache_dir, wpt_records):
    """The plan's whole contract, asserted field by field."""
    src, session, bridge = make_stack([
        version_check(TARGET, CURRENT),
        checksums_response(release_map()),             # the target's own map
        FakeResponse(content=release_zip_bytes(release_files())),
        checksums_response(current_map()),          # the pristine-current basis
    ])
    plan = UpdateCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    # the item set IS the release's own core surface plus the stale file
    # the tree swap removes — sorted, and never a hardcoded list
    assert [i.target for i in plan.items] == list(ALL_ITEMS)
    assert all(i.category == "update.core" for i in plan.items)
    by_target = {i.target: i for i in plan.items}
    for path in IN_SCOPE:
        assert by_target[path].detail == (
            f"replace with the official WordPress {TARGET} en_US file")
    # the removed file says so, and does not inflate the write estimate
    for path in STALE:
        assert by_target[path].detail == (
            f"not shipped by WordPress {TARGET} — removed with the "
            f"replaced core tree it lives in")
        assert by_target[path].bytes_est == 0
    files = release_files()
    assert [i.bytes_est for i in plan.items] == [
        len(files[p]) if p in IN_SCOPE else 0 for p in ALL_ITEMS]
    assert plan.est_bytes() == sum(len(files[p]) for p in IN_SCOPE)
    assert all(i.requires_apply and not i.done for i in plan.items)
    # the database is in the snapshot scope, discovered over db_audit
    assert plan.backup_tables == TABLES
    # wp.org traffic: offers, the CURRENT map (the pristine proof), the
    # target map and the release zip — four GETs, no POST
    assert [u for u, _kw in session.gets] == [
        updates.DEFAULT_WP_ORG.core_version_check_url.format(locale=updates.DEFAULT_WP_ORG.default_locale),
        "https://api.wordpress.org/core/checksums/1.0/?version=7.1.2&locale=en_US",
        updates.core_release_zip_url(TARGET, "en_US"),
        "https://api.wordpress.org/core/checksums/1.0/?version=6.8.3&locale=en_US",
    ]
    # the narrative: every fact the plan owes the operator
    infos = _messages(_records(wpt_records, logging.INFO))
    assert any("WordPress 6.8.3 -> 7.1.2 (en_US build), db_version 56657 "
               "-> 60356" in m for m in infos)
    assert any("6 core file(s) replaced" in m and "(4 already in the tree, "
               "2 created)" in m for m in infos)
    assert any("1 stale file(s) inside the replaced trees are removed with "
               "them" in m for m in infos)
    assert any("requires PHP 7.4+ and MySQL 5.5.5+ (both are REFUSALS" in m
               for m in infos)
    assert any("live PHP 8.2.12, live MySQL 8.0.36" in m for m in infos)
    # the pristine proof states its OWN scope: it gates the files the swap
    # replaces and removes, not the whole core
    assert any("the pristine proof is TREE-SCOPED, not whole-core" in m
               for m in infos)
    assert any("a site-level *.php the release does not ship is not touched "
               "by the swap" in m for m in infos)
    assert any(".maintenance is engaged before the swap and removed when "
               "the run ends" in m for m in infos)
    assert any("every name (each of the 2 trees, each root file) is parked "
               "and landed back to back" in m for m in infos)
    assert any("snapshot scope = the 6 replaced file(s) + the 1 removed "
               "with them + 2 database table(s) via db_dump" in m
               for m in infos)
    assert any("the rollback is `wpt restore --undo-last`" in m
               for m in infos)
    # nothing was written by a plan
    assert src.writes == []


def test_R12_both_checksum_calls_carry_the_run_deadline(
        tmp_path, cache_dir, monkeypatch):
    """R12-P2-4: the target and installed comparison-checksum fetches were
    called without the run budget, so a slow wp.org answer outlived it.
    Both now pass ``Deadline.from_ctx(ctx)`` (the memoized instance)."""
    import wpt.actions.update_core as update_core

    seen: list = []
    real = update_core._fetch_comparison_checksums

    def _spy(*args, deadline=None, **kwargs):
        seen.append(deadline)
        return real(*args, deadline=deadline, **kwargs)

    monkeypatch.setattr(update_core, "_fetch_comparison_checksums", _spy)
    ctx = _ctx(tmp_path, deadline_s=30)
    UpdateCoreAction().plan(ctx, make_stack(wporg_script()))
    assert len(seen) == 2
    assert seen[0] is ctx._deadline
    assert seen[1] is ctx._deadline


def test_plan_junk_policy_subtracts_sample(tmp_path, cache_dir):
    """[L19] wp-config-sample.php is in the release AND in the shipped
    webroot_junk: writing it back would make webroot.junk flag it again on
    the next audit.  The subtraction is integrity's own, so the audit, the
    heal and the update cannot disagree."""
    src, session, bridge = make_stack([
        version_check(TARGET, CURRENT),
        checksums_response(release_map()),
        FakeResponse(content=release_zip_bytes(release_files())),
        checksums_response(current_map()),
    ])
    plan = UpdateCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    assert "wp-config-sample.php" not in [i.target for i in plan.items]


def test_plan_wp_content_is_never_in_scope(tmp_path, cache_dir):
    """wp-content/** is in the release and structurally out of scope: an
    update that rewrote a theme or a plugin would be a different action."""
    src, session, bridge = make_stack([
        version_check(TARGET, CURRENT),
        checksums_response(release_map()),
        FakeResponse(content=release_zip_bytes(release_files())),
        checksums_response(current_map()),
    ])
    plan = UpdateCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    targets = [i.target for i in plan.items]
    assert not any(t.startswith("wp-content/") for t in targets)
    assert "wp-config.php" not in targets


def test_R16_plan_walk_is_bounded_before_the_first_bridge_call(tmp_path):
    """R16-P2: update-core's plan/apply converted ``source.walk()`` to a
    list before any deadline check.  The shared bounded walk now checks each
    entry (and the end), so a crawling channel ends inside the budget."""
    import time

    from wpt.types import DeadlineExceeded, Entry

    class _SlowWalk(FakeSource):
        def walk(self, path="", **_kwargs):
            for index in range(30):
                time.sleep(0.01)
                yield Entry(f"wp-content/f{index}.php", False, 1)

    src = _SlowWalk()
    ctx = _ctx(tmp_path, deadline_s=0.05)
    started = time.monotonic()
    with pytest.raises(DeadlineExceeded):
        UpdateCoreAction().plan(ctx, (src, FakeSession(), None))
    assert time.monotonic() - started < 0.5


# ----------------------------------------------------------------- refusals


def _refuse(tmp_path, cache_dir, *, bridge_kwargs=None, script=None,
            extra=None, expect):
    """One refusal: the message, and the traffic it took to reach it."""
    src, session, bridge = make_stack(
        script if script is not None else [version_check(TARGET, CURRENT)],
        **(bridge_kwargs or {}))
    ctx = _ctx(tmp_path, extra={"to": TARGET, **(extra or {})})
    with pytest.raises(WptError) as excinfo:
        UpdateCoreAction().plan(ctx, (src, session, bridge))
    assert expect in str(excinfo.value)
    return src, session, bridge


def test_refuses_offered_pre_release_without_the_flag(tmp_path, cache_dir):
    """wp.org DOES offer the RC; only the flag is missing."""
    rc = "6.9-RC1"
    _refuse(tmp_path, cache_dir, script=[version_check(rc, TARGET, CURRENT)],
            extra={"to": rc}, expect="that is a PRE-RELEASE")


def test_allows_a_pre_release_with_the_flag(tmp_path, cache_dir, wpt_records):
    """The same RC with --allow-pre-release is planned, not refused."""
    rc = "6.9-RC1"
    files = {**release_files(rc, 60000)}
    src, session, bridge = make_stack([
        version_check(rc, TARGET, CURRENT),
        checksums_response({path: hashlib.md5(blob).hexdigest()
                            for path, blob in files.items()}),
        FakeResponse(content=release_zip_bytes(files)),
        checksums_response(current_map()),
    ])
    plan = UpdateCoreAction().plan(
        _ctx(tmp_path, extra={"to": rc, "allow_pre_release": True}),
        (src, session, bridge))
    assert [i.target for i in plan.items] == list(ALL_ITEMS)
    assert all(f"WordPress {rc} en_US file" in i.detail
               for i in plan.items if i.target in IN_SCOPE)


def test_allows_a_dev_install_with_the_profile_key(tmp_path, cache_dir):
    """The profile's update.pre_release_allowed is the default answer when
    the flag was not typed (the tri-state door, the purge_originals shape)."""
    from dataclasses import replace

    settings = replace(DEFAULTS, update=replace(DEFAULTS.update,
                                                pre_release_allowed=True))
    src, session, bridge = make_stack(
        [version_check(TARGET, CURRENT)], wp_version="7.2-alpha-59000")
    with pytest.raises(WptError) as excinfo:
        # it gets past the install-shape refusal and dies on the
        # unoffered target, which proves the key was honoured
        UpdateCoreAction().plan(
            _ctx(tmp_path, settings=settings, extra={"to": "9.9.9"}),
            (src, session, bridge))
    assert "development build" not in str(excinfo.value)
    assert "does not offer" in str(excinfo.value)


def test_refuses_dev_install_without_the_flag(tmp_path, cache_dir):
    """A dev/beta/RC INSTALL (not merely a pre-release TARGET) is refused."""
    _refuse(tmp_path, cache_dir,
            bridge_kwargs={"wp_version": "7.2-alpha-59000"},
            expect="that is a development build")


def test_refuses_php_floor_above_live_php(tmp_path, cache_dir):
    _refuse(tmp_path, cache_dir, bridge_kwargs={"php": "7.2.34"},
            expect="it requires PHP 7.4 and this site runs PHP 7.2.34")


def test_refuses_unreadable_live_php(tmp_path, cache_dir):
    _refuse(tmp_path, cache_dir, bridge_kwargs={"php": None},
            expect="the live PHP version could not be read")


def test_refuses_multisite(tmp_path, cache_dir):
    _refuse(tmp_path, cache_dir, bridge_kwargs={"multisite": True},
            expect="refusing to update a MULTISITE installation")


def test_refuses_same_version(tmp_path, cache_dir):
    """Idempotency: a second run at the same version refuses as a no-op."""
    src, session, bridge = _refuse(
        tmp_path, cache_dir, extra={"to": CURRENT},
        expect="is ALREADY the running version")
    assert src.writes == []
    assert len(session.gets) == 1   # the offer list, nothing else


def test_refuses_downgrade(tmp_path, cache_dir):
    _refuse(tmp_path, cache_dir, script=[version_check(TARGET, CURRENT,
                                                       "6.7.2")],
            extra={"to": "6.7.2"}, expect="that is not a NEWER release")


def test_refuses_dirty_core(tmp_path, cache_dir):
    """A tampered in-scope file is refused, with the heal as the lever."""
    files = site_files()
    files["wp-admin/index.php"] = b"<?php /* INJECTED */\n"
    src, session, bridge = make_stack([
        version_check(TARGET, CURRENT),
        checksums_response(release_map()),
        FakeResponse(content=release_zip_bytes(release_files())),
        checksums_response(current_map()),
    ], files=files)
    with pytest.raises(WptError) as excinfo:
        UpdateCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    message = str(excinfo.value)
    assert "do not match the official WordPress 6.8.3 checksums" in message
    assert "wp-admin/index.php" in message
    assert "`wpt heal-core --apply` first" in message
    assert src.writes == []
    # the pristine proof is the LAST fetch of the plan: the scope and the
    # release are known before a single byte of the tree is read
    assert len(session.gets) == 4


def test_dirty_file_outside_the_target_scope_is_not_our_business(
        tmp_path, cache_dir):
    """A stale file the target release DROPPED (wp-includes/js/old.js) is
    not in the update scope: whether it is tampered, missing or pristine
    is prune-core's question, and refusing an upgrade over it would make
    every upgrade past a release that dropped a file impossible."""
    files = site_files()
    files["wp-includes/js/old.js"] = b"/* INJECTED */\n"
    src, session, bridge = make_stack([
        version_check(TARGET, CURRENT),
        checksums_response(release_map()),
        FakeResponse(content=release_zip_bytes(release_files())),
        checksums_response(current_map()),
    ], files=files)
    plan = UpdateCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    # it is planned, as a REMOVAL (the tree swap takes it) — and its
    # tampered bytes are not this action's business: only its removal is
    assert [i.target for i in plan.items] == list(ALL_ITEMS)
    stale = next(i for i in plan.items if i.target == "wp-includes/js/old.js")
    assert "removed with the replaced core tree" in stale.detail


def test_refuses_unreadable_in_scope_file(tmp_path, cache_dir):
    """A file the swap would overwrite that cannot be READ: the snapshot
    could not capture it, and an update may never overwrite a file nothing
    can bring back."""
    src, session, bridge = make_stack([
        version_check(TARGET, CURRENT),
        checksums_response(release_map()),
        FakeResponse(content=release_zip_bytes(release_files())),
        checksums_response(current_map()),
    ], core_md5_script=[BridgeError("bridge action failed: core_md5 boom")])
    with pytest.raises(WptError) as excinfo:
        UpdateCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    assert "could not be read" in str(excinfo.value)
    assert "the snapshot could not capture what the swap would overwrite" \
        in str(excinfo.value)


def test_refuses_unknown_version(tmp_path):
    src, session, bridge = make_stack([], wp_version=None)
    with pytest.raises(WptError, match="unknown WordPress version"):
        UpdateCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    assert session.gets == []      # refused before any wp.org traffic
    assert [a for a, _p in bridge.calls] == ["info"]


def test_refuses_release_zip_unavailable(tmp_path, cache_dir):
    _refuse(tmp_path, cache_dir, script=[
        version_check(TARGET, CURRENT),
        checksums_response(release_map()),
        FakeResponse(status_code=404),
    ], expect="release zip is unavailable")


def test_refuses_checksums_unavailable(tmp_path, cache_dir):
    _refuse(tmp_path, cache_dir, script=[
        version_check(TARGET, CURRENT),
        requests.ConnectionError("boom"),
    ], expect="wp.org checksums for WordPress 7.1.2 are unavailable")


def test_refuses_an_unknown_addition_inside_a_replaced_tree(tmp_path,
                                                             cache_dir):
    """The eighth refusal: a file inside wp-admin/ or wp-includes/ that
    the INSTALLED release never shipped.  Swapping the tree DELETES it, and
    nothing official accounts for it — so the run refuses and names the
    lever instead of destroying somebody's file inside a core tree."""
    files = {**site_files(), "wp-includes/rogue.php": b"<?php /* someone's */\n"}
    src, session, bridge = make_stack([
        version_check(TARGET, CURRENT),
        checksums_response(release_map()),
        FakeResponse(content=release_zip_bytes(release_files())),
        checksums_response(current_map()),
    ], files=files)
    with pytest.raises(WptError) as excinfo:
        UpdateCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    message = str(excinfo.value)
    assert "not part of the official WordPress 6.8.3 release" in message
    assert "wp-includes/rogue.php" in message
    assert "replacing the tree would DELETE them" in message
    # THE LEVER THAT EXISTS: the audit names every one of them and the
    # file leaves the tree by hand.  The lever the message used to name
    # (`core_integrity.known_added`) is a WEBROOT-ROOT *.php signature
    # matcher: it could never match `wp-includes/rogue.php`, so
    # configuring it changed nothing and the operator was left with a
    # dead end.  The message now says so instead of pretending.
    assert "run `wpt audit --only core.integrity`" in message
    assert "move each out of the tree" in message
    assert "core_integrity.known_added does NOT apply here" in message
    assert src.writes == []


def test_known_added_cannot_cover_a_core_tree_path(tmp_path, cache_dir,
                                                  monkeypatch):
    """The same refusal with ``core_integrity.known_added`` CONFIGURED to
    match the file: it still refuses.

    This is the reviewer's reproduction, kept as the regression it is.  A
    profile value that reads like a lever for this refusal but is
    structurally incapable of matching (its signatures are name + content
    marker + size against a webroot-ROOT *.php) is worse than no lever:
    an operator adds the entry, re-runs, and is refused again with no
    visible reason why.
    """
    from dataclasses import replace
    settings = replace(DEFAULTS, core_integrity=replace(
        DEFAULTS.core_integrity,
        known_added=[{"name": "rogue.php", "marker": "someone's",
                      "max_bytes": 4096, "note": "a platform artifact"}]))
    files = {**site_files(), "wp-includes/rogue.php": b"<?php /* someone's */\n"}
    src, session, bridge = make_stack([
        version_check(TARGET, CURRENT),
        checksums_response(release_map()),
        FakeResponse(content=release_zip_bytes(release_files())),
        checksums_response(current_map()),
    ], files=files)
    with pytest.raises(WptError) as excinfo:
        UpdateCoreAction().plan(
            _ctx(tmp_path, settings=settings), (src, session, bridge))
    assert "not part of the official WordPress 6.8.3 release" in \
        str(excinfo.value)
    assert src.writes == []


def test_junk_inside_a_replaced_tree_is_neither_planned_nor_refused(
        tmp_path, cache_dir, wpt_records):
    """wp-admin/error_log is the shipped profile's own junk and is not in
    the official map: the swap removing it is exactly what clean-files
    would do with it, so it is not a refusal (which would make every
    update impossible on a site carrying one) and it is not planned
    (nothing is written for it)."""
    files = {**site_files(), "wp-admin/error_log": b"PHP message\n"}
    src, session, bridge = make_stack([
        version_check(TARGET, CURRENT),
        checksums_response(release_map()),
        FakeResponse(content=release_zip_bytes(release_files())),
        checksums_response(current_map()),
    ], files=files)
    plan = UpdateCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    assert [i.target for i in plan.items] == list(ALL_ITEMS)
    assert any("are this tool's own junk" in m
               for m in _messages(_records(wpt_records, logging.INFO)))


def test_apply_refuses_when_a_removed_file_survives(tmp_path, cache_dir):
    """A stale file the plan said the tree swap removes, still there
    afterwards: the swap did not complete, so nothing is claimed done.

    Modelled as an ``exists()`` that still answers True for the stale
    path — a live editor's write, a plugin that recreates a path inside a
    core tree, or a server that answered the unlink but kept the name.
    The check is a RE-READ of the live tree, so it sees the survivor
    whichever way the survivor got there.
    """
    class StubbornSource(UpdateSource):
        """A name the swap removed that the server still has."""
        def exists(self, path):
            if path == STALE[0]:
                return True
            return super().exists(path)

    src = StubbornSource()
    src.files.update(site_files())
    from tests.fakes import FakeSession
    session = FakeSession(wporg_script(TARGET, TARGET_DB, tail=live_ok()))
    bridge = UpdateBridge(src)
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, stack)
    with pytest.raises(WptError) as excinfo:
        action.apply(ctx, stack, plan)
    assert "are still there" in str(excinfo.value)
    assert "wp-includes/js/old.js" in str(excinfo.value)
    assert not any(i.done for i in plan.items)
    # the parked copy of the core the swap replaced is NOT discarded on a
    # failed verify: it is still the only hand-recovery path
    assert any(p.endswith(".wpt-old") or "/wp-includes.wpt-old" in p
               for p in src.files) or "wp-includes.wpt-old" in str(
                   [p for p in src.files])


# ------------------------------------------------------------------- apply


def test_apply_patch_bump_replaces_files_without_migrating(
        tmp_path, cache_dir, wpt_records):
    """The happy path across a PATCH bump: every replaced file lands, the
    trees are swapped by rename, .maintenance is cleaned — and the schema
    version does not move, so the migration op is never called (a patch
    release that ships no schema change must not touch the database)."""
    src, session, bridge = make_stack(
        wporg_script(PATCH, PATCH_DB, tail=live_ok()),
        db_version_after=PATCH_DB)
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path, extra={"to": PATCH})
    plan = action.plan(ctx, stack)
    applied = action.apply(ctx, stack, plan)
    assert applied is plan
    assert [i.done for i in applied.items] == [True] * len(ALL_ITEMS)
    # the new tree IS the release's, byte for byte
    files = release_files(PATCH, PATCH_DB)
    for path in IN_SCOPE:
        assert src.files[path] == files[path]
    # the tree swap: staged BESIDE the installed tree, then parked and
    # landed back to back, one pair at a time — never a per-file rewrite
    # of the live tree, and never a park/land/park/land that would leave
    # both trees missing at once.  wp-settings.php is a file the target
    # ADDS, so it has no installed predecessor to park: one rename only.
    renames = [p for _ts, op, p in src.ops if op == "rename"]  # "src -> dst"
    assert renames == [
        "wp-admin -> wp-admin.wpt-old", "wp-admin.wpt-new -> wp-admin",
        "wp-includes -> wp-includes.wpt-old",
        "wp-includes.wpt-new -> wp-includes",
        "index.php -> index.php.wpt-old", "index.php.wpt-tmp -> index.php",
        "wp-load.php -> wp-load.php.wpt-old",
        "wp-load.php.wpt-tmp -> wp-load.php",
        "wp-settings.php.wpt-tmp -> wp-settings.php",
    ]
    assert not any(".wpt-new" in p or ".wpt-old" in p for p in src.files)
    assert not any(".wpt-tmp" in p for p in src.files)
    # .maintenance was written and REMOVED (the tool's teardown
    # discipline), and it was written BEFORE the first swap and removed
    # after the last one
    ops = [(op, p) for _ts, op, p in src.ops]
    assert ".maintenance" in _files_written(src)
    engaged = ops.index(("write", ".maintenance"))
    first_swap = ops.index(("rename", "wp-admin -> wp-admin.wpt-old"))
    removed = [i for i, (op, p) in enumerate(ops)
               if op in ("delete", "rmdir") and p == ".maintenance"]
    assert engaged < first_swap
    assert removed and removed[0] > first_swap
    assert ".maintenance" not in src.files
    # the staging writes carried NO unlock; the renames that land the trees
    # and the protected index.php DID
    staged = {p for p, k in src.writes if ".wpt-new" in p or ".wpt-tmp" in p}
    assert staged and all(k == {"allow_config": False, "allow_core": False}
                          for p, k in src.writes if p in staged)
    # wp-content/ and wp-config.php are untouched
    assert src.files["wp-content/plugins/hello.php"] == \
        site_files()["wp-content/plugins/hello.php"]
    assert src.files["wp-config.php"] == site_files()["wp-config.php"]
    assert "wp-includes/js/old.js" not in src.files  # dropped with the old tree
    # the migration was NOT run (the schema version does not move).  The
    # short-circuit is only reachable because the schema version on the
    # wire is a STRING and the action normalizes it: with the test double
    # answering a Python int (as it used to) the value reached
    # _site_facts as None, the short-circuit never fired, and every
    # patch-bump run went to the database for nothing.
    assert bridge.upgraded == 0
    # the live answer: both probes, the site root strictly
    assert [u for u, _kw in session.gets][-2:] == [
        f"{SITE}/", f"{SITE}/wp-json/"]
    # the wp.org re-derivation cost no new traffic (everything is cached):
    # 4 in the plan + the 2 live probes, and nothing else
    assert len(session.gets) == 6
    # the bridge traffic, in order: the plan's info + pristine proof +
    # table discovery, the apply's re-derivation (info + proof), and the
    # verify's own info + digest pass.  NO core_upgrade: this release
    # does not move the schema, so the database is not touched at all.
    # (The registry's post-apply purge_cache is pinned in the registry
    # test below, where the registry is the caller.)
    assert [a for a, _p in bridge.calls] == [
        "info", "core_md5", "db_audit",
        "info", "core_md5",
        "info", "core_md5",
    ]
    infos = _messages(_records(wpt_records, logging.INFO))
    assert any(f"db_version {CURRENT_DB} already matches the target's "
               f"{PATCH_DB}" in m for m in infos)
    assert any(f"WordPress {PATCH} installed and verified" in m
               for m in infos)


def test_apply_minor_bump_migrates_the_database(tmp_path, cache_dir,
                                                wpt_records):
    """A minor bump whose release DOES advance the schema: the migration
    runs through the bridge's core_upgrade op, and the VERIFY re-reads the
    database in a different process (a fresh info) rather than trusting
    the op's own answer."""
    src, session, bridge = make_stack(
        wporg_script(TARGET, TARGET_DB, tail=live_ok()),
        db_version=CURRENT_DB, db_version_after=TARGET_DB)
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, stack)
    applied = action.apply(ctx, stack, plan)
    assert all(i.done for i in applied.items)
    assert src.files["wp-includes/version.php"] == version_php(TARGET, TARGET_DB)
    assert bridge.upgraded == 1
    assert [c for c in bridge.calls if c[0] == "core_upgrade"] == [
        ("core_upgrade", {"apply": True})]
    assert bridge.db_version == TARGET_DB
    # the verify's info came AFTER the migration and saw the new schema
    infos = [a for a, _p in bridge.calls]
    assert infos == ["info", "core_md5", "db_audit",   # the plan
                     "info", "core_md5",               # the re-derivation
                     "core_upgrade",                   # the migration
                     "info", "core_md5"]               # the verify
    assert any(f"db_version {CURRENT_DB} -> {TARGET_DB}" in m
               for m in _messages(_records(wpt_records, logging.INFO)))


def test_apply_major_bump_migrates_the_database(tmp_path, cache_dir):
    """A MAJOR bump: the same engine, on a target two series up."""
    src, session, bridge = make_stack(
        wporg_script(MAJOR, MAJOR_DB, tail=live_ok()),
        db_version=CURRENT_DB, db_version_after=MAJOR_DB)
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path, extra={"to": MAJOR})
    plan = action.plan(ctx, stack)
    applied = action.apply(ctx, stack, plan)
    assert all(i.done for i in applied.items)
    assert src.files["wp-includes/version.php"] == version_php(MAJOR, MAJOR_DB)
    assert bridge.upgraded == 1
    assert bridge.db_version == MAJOR_DB


def test_apply_migration_that_does_not_reach_the_target_refuses(
        tmp_path, cache_dir):
    src, session, bridge = make_stack([
        version_check(TARGET, CURRENT),
        checksums_response(release_map(TARGET, TARGET_DB)),
        FakeResponse(content=release_zip_bytes(release_files(TARGET, TARGET_DB))),
        checksums_response(current_map()),
    ], upgrade={"db_version": 60000, "wp_version": TARGET,
                "target_db_version": TARGET_DB, "output_discarded": False})
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, stack)
    with pytest.raises(WptError) as excinfo:
        action.apply(ctx, stack, plan)
    assert "did not reach the target" in str(excinfo.value)
    assert "the pre-action snapshot is the rollback" in str(excinfo.value)
    assert not any(i.done for i in plan.items)


def test_prove_release_honours_a_configured_prefix():
    """The wordpress driver must prove the release under the configured
    wp_org.release_zip_prefix, not the public default."""
    from types import SimpleNamespace
    action = UpdateCoreAction()
    body = b"<?php $wp_version = '6.8.4';\n"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("custom/wp-includes/version.php", body)
    derived = SimpleNamespace(
        zip_bytes=buf.getvalue(),
        release=SimpleNamespace(
            files={"wp-includes/version.php": body},
            version="6.8.4", locale="en_US"),
        target_map={"wp-includes/version.php": hashlib.md5(body).hexdigest()},
    )
    action._prove_release(derived, "custom/")
    with pytest.raises(WptError) as excinfo:
        action._prove_release(derived)
    assert "absent/unreadable" in str(excinfo.value)


def test_apply_release_bytes_disagree_with_the_map(tmp_path, cache_dir):
    """A release whose bytes do not match its own map aborts with NOTHING
    written: the proof is taken before the first swap, where it costs the
    site nothing."""
    drifted = {**release_files(), "wp-includes/js/new.js": b"/* tampered */\n"}
    src, session, bridge = make_stack([
        version_check(TARGET, CURRENT),
        checksums_response(release_map()),
        FakeResponse(content=release_zip_bytes(drifted)),
        checksums_response(current_map()),
    ])
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, stack)
    with pytest.raises(WptError) as excinfo:
        action.apply(ctx, stack, plan)
    message = str(excinfo.value)
    assert "disagree with its own wp.org checksum map" in message
    assert "wp-includes/js/new.js" in message
    assert "NOTHING was written" in message
    assert src.writes == []            # not even a staging write
    assert src.files == site_files()   # the site is byte-identical
    assert not any(i.done for i in plan.items)


def test_apply_mid_swap_failure_keeps_the_installed_tree(tmp_path, cache_dir):
    """An injected failure on the SECOND tree's swap.

    The FULL tree state is asserted, and that is the point: this test used
    to check ``wp-includes`` only, and passed while ``wp-admin`` sat
    swapped on the site — the mixed core the per-tree undo could not see
    and could not undo.  Every file the site started with must be back,
    byte for byte, and the file the target ADDS must be gone.
    """
    src, session, bridge = make_stack(
        wporg_script(TARGET, TARGET_DB, tail=live_ok()))
    src.fail_rename = {"wp-includes.wpt-new"}
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, stack)
    with pytest.raises(SourceError):
        action.apply(ctx, stack, plan)
    # THE WHOLE TREE: both replaced trees, the root files, wp-content and
    # the config — the installed core, byte for byte
    for path, blob in site_files().items():
        assert src.files[path] == blob, path
    assert "wp-settings.php" not in src.files
    assert "wp-admin/index.php" in src.files and \
        src.files["wp-admin/index.php"] == b"<?php // admin 6.8.3\n"
    # .maintenance is gone (the finally ran) and no staging or parking
    # residue is left
    assert ".maintenance" not in src.files
    assert not any(p.endswith(".wpt-new") for p in src.files)
    assert not any(".wpt-old" in p for p in src.files)
    # nothing is claimed done
    assert not any(i.done for i in plan.items)


def test_R19_expired_swap_rolls_back_and_cleans_under_fresh_budget(
        tmp_path, cache_dir, wpt_records):
    """R19-P1: the run deadline expiring BETWEEN two renames used to leave
    the live ``wp-includes`` absent (both halves parked/staged) and
    ``.maintenance`` on disk, because the undo and cleanup honoured the
    expired budget and the swap caught only SourceError/OSError.  The undo,
    the maintenance removal and the residue sweep now run on the source's
    fresh finite cleanup budget; the installed core comes back."""
    src, session, bridge = make_stack(
        wporg_script(TARGET, TARGET_DB, tail=live_ok()),
        source_cls=ExpiringSource)
    src.expire_at = 3          # second tree's PARKING rename
    src.deadline = Deadline(30)
    # An earlier run's core staging: the sweep must still SEE/REPORT it
    # after the expired budget was replaced by the cleanup budget.
    src.files["wp-content/upgrade/old/x.php"] = b"<?php old"
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, stack)
    with pytest.raises(DeadlineExceeded):
        action.apply(ctx, stack, plan)
    for path, blob in site_files().items():
        assert src.files[path] == blob, path
    assert "wp-settings.php" not in src.files
    assert ".maintenance" not in src.files
    assert not any(p.endswith(".wpt-new") for p in src.files)
    assert not any(".wpt-old" in p for p in src.files)
    residue = _messages(_records(wpt_records, logging.WARNING))
    assert any("wp-content/upgrade/" in message for message in residue)


def test_R20_undo_failure_names_the_observed_state_per_rename(
        wpt_records):
    """R20-P2: one broad try reported BOTH rename failures with the same
    message ("NAME still holds the NEW tree"), which is false when the
    move-out succeeded: the live name is then ABSENT.  Each rename has its
    own diagnostic naming where the new/installed copies actually are."""
    import wpt.actions.update_core as update_core

    class _SecondRenameFails:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []

        def rename(self, src, dst, *, allow_core=False):
            self.calls.append((src, dst))
            if len(self.calls) == 2:
                raise SourceError("simulated restore rename failure")

    source = _SecondRenameFails()
    update_core._undo_landed(source, [
        ("wp-includes", "wp-includes.wpt-new", "wp-includes.wpt-old",
         True, True),
    ])
    assert source.calls == [
        ("wp-includes", "wp-includes.wpt-new"),
        ("wp-includes.wpt-old", "wp-includes"),
    ]
    message = " ".join(_messages(_records(wpt_records, logging.ERROR)))
    assert "restore rename" in message
    assert "wp-includes is now ABSENT" in message
    assert "parked at wp-includes.wpt-new" in message
    assert "INSTALLED one is at wp-includes.wpt-old" in message


def test_apply_refuses_when_the_site_changed_between_plan_and_apply(
        tmp_path, cache_dir):
    """A plan whose file set no longer matches the site is refused: the
    operator confirmed a plan, not a guess."""
    src, session, bridge = make_stack(
        wporg_script(TARGET, TARGET_DB, tail=live_ok()))
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, stack)
    # a hand-edited plan (one file fewer) is what a stale confirmation is
    plan.items = plan.items[:-1]
    with pytest.raises(WptError) as excinfo:
        action.apply(ctx, stack, plan)
    assert "the file set changed between the plan and the apply" in \
        str(excinfo.value)
    assert src.writes == []


def test_apply_no_target_refuses(tmp_path, cache_dir):
    src, session, bridge = make_stack([])
    plan = Plan(items=[PlanItem(category="update.core", target="index.php",
                               detail="x")], backup_tables=[])
    with pytest.raises(WptError, match="no --to target"):
        UpdateCoreAction().apply(_ctx(tmp_path, extra={}),
                                 (src, session, bridge), plan)
    assert src.writes == []


def test_apply_refuses_when_a_replaced_file_does_not_verify(
        tmp_path, cache_dir):
    """The file digests are re-read from the SERVER after the swap; a file
    that does not carry the release's md5 (a truncated transfer the write
    layer did not notice) is a refusal, never a green item."""
    class LyingSource(UpdateSource):
        """One staged file lands with the PREVIOUS release's bytes."""
        def write_bytes(self, path, data, *, allow_config=False,
                        allow_core=False):
            if path.endswith("wp-includes/js/new.js.wpt-tmp") or (
                    path == "wp-includes.wpt-new/js/new.js"):
                data = b"/* 6.8.3 */\n"
            super().write_bytes(path, data, allow_config=allow_config,
                                allow_core=allow_core)

    src = LyingSource()
    src.files.update(site_files())
    from tests.fakes import FakeSession
    session = FakeSession(wporg_script(TARGET, TARGET_DB))
    bridge = UpdateBridge(src)
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, stack)
    with pytest.raises(WptError) as excinfo:
        action.apply(ctx, stack, plan)
    message = str(excinfo.value)
    assert "do not carry the official WordPress 7.1.2 en_US checksum" in message
    assert "wp-includes/js/new.js" in message
    assert "the update is NOT done" in message
    assert not any(i.done for i in plan.items)


def test_apply_refuses_when_the_database_does_not_report_the_target(
        tmp_path, cache_dir):
    """The verify re-reads wp_version + db_version from the DATABASE in a
    different PHP process; a database that does not report the target pair
    means the site is not on the target, and nothing is claimed."""
    src, session, bridge = make_stack(
        wporg_script(TARGET, TARGET_DB),
        # the migration "succeeds", but a LATER info call answers the old
        # schema version: exactly the "op returned, state did not move"
        # case the separate read-back exists to catch
        info_after={"db_version": CURRENT_DB},
    )
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, stack)
    with pytest.raises(WptError) as excinfo:
        action.apply(ctx, stack, plan)
    assert "the database holds db_version" in str(excinfo.value)
    assert "the update is NOT done" in str(excinfo.value)
    assert not any(i.done for i in plan.items)


def test_apply_refuses_when_the_site_still_reports_the_old_version(
        tmp_path, cache_dir):
    """Same read-back, the version half: a site still reporting the old
    core after the swap is not an update."""
    src, session, bridge = make_stack(
        wporg_script(TARGET, TARGET_DB),
        info_after={"wp_version": CURRENT},
    )
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, stack)
    with pytest.raises(WptError) as excinfo:
        action.apply(ctx, stack, plan)
    assert "the site reports WordPress 6.8.3 after the update" in \
        str(excinfo.value)


# ------------------------------------------------------- the local rehearsal


def test_R9_P2_16_local_wporg_offers_session_is_closed(
        tmp_path, cache_dir, monkeypatch):
    """P2-16: update-core's local ``_offers`` created a plain session per
    call and never closed it."""
    import wpt.actions.update_core as update_mod

    created = []

    class _Tracking(requests.Session):
        def __init__(self):
            super().__init__()
            self.closed = 0
            created.append(self)

        def close(self):
            self.closed += 1
            super().close()

    monkeypatch.setattr(update_mod.requests, "Session", _Tracking)
    key = updates._cache_key(updates.DEFAULT_WP_ORG.core_version_check_url.format(locale=updates.DEFAULT_WP_ORG.default_locale), None)
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / f"{key}.json").write_text(
        json.dumps({"offers": [{"current": TARGET}]}), encoding="utf-8")

    offers = update_mod._offers(
        _ctx(tmp_path, source="local", zip=tmp_path / "site.zip"),
        (FakeSource(), None, None))

    assert offers and offers[0]["current"] == TARGET
    assert created and all(session.closed == 1 for session in created)


def test_apply_local_rehearsal_upgrades_a_copy(tmp_path, cache_dir,
                                               wpt_records):
    """The REAL registry local flow over a real zip: the materialized copy
    carries the TARGET's file set, wp-content/ is byte-identical, no
    .maintenance survives, and the ORIGINAL zip is untouched (it IS the
    rollback)."""
    zip_path = tmp_path / "site.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for rel, blob in site_files().items():
            zf.writestr(rel, blob)
    before = zip_path.read_bytes()
    seed_local_wporg(cache_dir)
    rc = run_action(
        _ctx(tmp_path, source="local", zip=zip_path, apply=True, yes=True),
        "update-core",
    )
    assert rc == 0
    assert zip_path.read_bytes() == before
    rehearsed = sorted(tmp_path.glob("site-rehearsed-*.zip"))
    assert len(rehearsed) == 1
    files = release_files()
    with zipfile.ZipFile(rehearsed[0]) as zf:
        names = set(zf.namelist())
        # the target's core surface is present, with the RELEASE's bytes
        for path in IN_SCOPE:
            assert zf.read(path) == files[path]
        # wp-content/ is byte-identical, wp-config.php untouched
        assert zf.read("wp-content/plugins/hello.php") == \
            site_files()["wp-content/plugins/hello.php"]
        assert zf.read("wp-content/themes/twentytwentyfour/style.css") == \
            site_files()["wp-content/themes/twentytwentyfour/style.css"]
        assert zf.read("wp-config.php") == site_files()["wp-config.php"]
        # the retired tree and every staging/temp/maintenance name are gone
        assert not any(".wpt-old" in n or ".wpt-new" in n
                       or ".wpt-tmp" in n for n in names)
        assert ".maintenance" not in names
        # the file the old tree had and the release dropped is gone with it
        assert "wp-includes/js/old.js" not in names
    infos = [r.getMessage() for r in wpt_records
             if r.name == "wpt.actions" and "rehearsed" in r.getMessage()]
    assert infos and f"rehearsed {len(ALL_ITEMS)}/{len(ALL_ITEMS)} items" \
        in infos[0]
    action_infos = _messages(_records(wpt_records, logging.INFO))
    assert any("WordPress 7.1.2 installed and verified" in m
               for m in action_infos)


# ---------------------------------------------------- registry end to end


def test_registry_ftp_apply_is_fail_closed(tmp_path, capsys, monkeypatch,
                                           cache_dir):
    src, session, bridge = make_stack(
        wporg_script(TARGET, TARGET_DB, tail=live_ok()))
    monkeypatch.setattr(registry_mod, "_stack",
                        lambda ctx: (src, session, bridge))
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "update-core")
    assert rc == 0
    # the fail-closed pre-action snapshot: every replaced file (the ones
    # the swap overwrites AND the ones it creates, recorded ABSENT so
    # restore deletes them again) plus both dumped tables
    manifests = list((tmp_path / "backup").glob("*/*/manifest.json"))
    assert len(manifests) == 1
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    assert manifest["action"] == "update-core"
    assert manifest["site"] == "example.com"
    assert [t["name"] for t in manifest["tables"]] == TABLES
    entries = {e["path"]: e for e in manifest["files"]}
    assert set(entries) == set(ALL_ITEMS)
    # installed files are CAPTURED with their sha256; new files are ABSENT
    assert entries["index.php"]["absent"] is False
    assert entries["index.php"]["sha256"] == hashlib.sha256(
        site_files()["index.php"]).hexdigest()
    assert entries["wp-settings.php"] == {"path": "wp-settings.php",
                                          "absent": True}
    # THE REVERSIBILITY HALF: the file the tree swap REMOVES is captured
    # with its bytes, so `wpt restore --undo-last` can bring it back. A
    # snapshot that skipped it would leave a deleted core file with no
    # rollback at all.
    assert entries["wp-includes/js/old.js"]["absent"] is False
    assert entries["wp-includes/js/old.js"]["sha256"] == hashlib.sha256(
        site_files()["wp-includes/js/old.js"]).hexdigest()
    # the registry purged the cache exactly once, after a complete apply
    assert [a for a, _p in bridge.calls][-1] == "purge_cache"
    assert bridge.destroyed == 1
    out = capsys.readouterr().out
    assert out.count("| yes |") == len(ALL_ITEMS)


def test_registry_reports_carry_no_secret(tmp_path, capsys, monkeypatch,
                                          cache_dir):
    """A report is a file an operator keeps and shares: this one carries
    paths, versions and sizes, and nothing else."""
    src, session, bridge = make_stack(wporg_script())
    monkeypatch.setattr(registry_mod, "_stack",
                        lambda ctx: (src, session, bridge))
    ctx = _ctx(tmp_path, report_path=tmp_path / "out.md")
    assert run_action(ctx, "update-core") == 0
    written = (tmp_path / "out.md").read_text(encoding="utf-8")
    assert "## Plan" in written and TARGET in written
    twin = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    assert {i["target"] for i in twin["plan"]["items"]} == set(ALL_ITEMS)
    for blob in (written, json.dumps(twin)):
        for secret in ("password", "secret", "passwd", "FTP_PASS",
                       "Authorization", "db_password"):
            assert secret.lower() not in blob.lower()


def test_files_written_helper_is_used():
    """Guard against a silent regression in the assertion helper itself:
    it must report the staging writes and nothing hidden."""
    src = UpdateSource()
    src.write_bytes("wp-includes.wpt-new/x.php", b"x")
    assert _files_written(src) == ["wp-includes.wpt-new/x.php"]


# ---------------------------------------------- the wire shape of db_version
#
# F3: the deployed bridge casts the stored `db_version` option to a STRING
# (a stored options row is not an int in PHP), and the action demanded an
# int.  Every real payload therefore read as "unknown", the verify's
# comparison could never be satisfied, and the action reported NOT-done
# — with rollback advice and no cache purge — on a site that had been
# updated correctly.  A 100% failure rate that a test double hid for the
# whole life of the action, because the double answered a Python int.


def test_a_string_db_version_on_the_wire_verifies_the_update(tmp_path,
                                                             cache_dir):
    """The whole apply over the REAL wire shape, end to end.

    The deployed `info` op answers ``"db_version": "56657"`` — a JSON
    string.  The verify reads it back after the migration and requires
    the target's schema version.  With an int-only reader the value is
    None and this run raises "the database holds … not the target … the
    update is NOT done" while the site is perfectly updated.
    """
    src, session, bridge = make_stack(
        wporg_script(TARGET, TARGET_DB, tail=live_ok()),
        db_version_after=TARGET_DB)
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, stack)
    applied = action.apply(ctx, stack, plan)
    assert all(i.done for i in applied.items)
    # the verify really did read the database back — three times: the
    # plan, the apply's re-derivation, and the proof itself
    assert [a for a, _p in bridge.calls].count("info") == 3
    # the schema version the action compared was the NUMBER, reached
    # through the one coercion of that shape (see the test below)
    assert bridge.db_version == TARGET_DB


def test_the_schema_version_the_action_reads_is_a_number_not_the_wire_string(
        tmp_path, cache_dir):
    """``_site_facts`` returns an int for the wire's string.

    The coercion itself, pinned where it happens: the bridge client's own
    ``wire_int`` is the single implementation of it, and an int is what
    the migration's comparison and the verify's comparison both need.
    """
    from wpt.actions.update_core import _site_facts
    src, _session, bridge = make_stack([])
    facts = _site_facts(src, bridge)
    assert facts.db_version == CURRENT_DB
    assert isinstance(facts.db_version, int)
    # the same coercion rejects what is not a schema version at all
    bridge.db_version = "not-a-number"
    assert _site_facts(src, bridge).db_version is None


def test_R22_wire_int_accepts_only_ascii_digits():
    """R22-P2: ``str.isdigit()`` accepts non-ASCII digits and characters
    like ``²`` that ``int()`` then rejects with ValueError, so a hostile
    wire fact could crash the consumer.  Only ASCII digits coerce."""
    from wpt.wpbridge.client import wire_int

    assert wire_int("3600") == 3600
    assert wire_int(" 3600 ") == 3600
    assert wire_int(3600) == 3600
    for bad in ("١٢٣", "²", "3.5", "", "  ", "1_000", "+3", "-3",
                "0x10", True, False, 3.5, None, [], {}):
        assert wire_int(bad) is None, bad


def test_a_schema_ahead_of_the_target_is_not_refused(tmp_path, cache_dir,
                                                     wpt_records):
    """F8: the verify requires the schema to be AT OR ABOVE the target.

    WordPress's own rule is ``db_version < $wp_db_version`` triggers a
    migration — so a database that is already past the target needs
    nothing, and requiring strict equality refuses a correct site.  This
    is the same class of defect as F3 with the opposite sign: a run that
    did the right thing and was told it had not.
    """
    ahead = TARGET_DB + 500
    src, session, bridge = make_stack(
        wporg_script(TARGET, TARGET_DB, tail=live_ok()),
        db_version_after=ahead, info_after={"db_version": str(ahead)})
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, stack)
    applied = action.apply(ctx, stack, plan)
    assert all(i.done for i in applied.items)
    assert any("AHEAD of the target's" in m
               for m in _messages(_records(wpt_records, logging.INFO)))


def test_a_schema_behind_the_target_is_still_refused(tmp_path, cache_dir):
    """The other side of the same comparison: BELOW the target is a real
    failure and still refuses."""
    src, session, bridge = make_stack(
        wporg_script(TARGET, TARGET_DB),
        info_after={"db_version": str(TARGET_DB - 1)})
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, stack)
    with pytest.raises(WptError) as excinfo:
        action.apply(ctx, stack, plan)
    assert "below the target's" in str(excinfo.value)
    assert not any(i.done for i in plan.items)


def test_an_unreadable_schema_version_is_refused_not_assumed(tmp_path,
                                                              cache_dir):
    """A payload whose db_version is not a number at all: unknown, and
    unknown is a failure of the proof, never a pass."""
    src, session, bridge = make_stack(
        wporg_script(TARGET, TARGET_DB), info_after={"db_version": None})
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, stack)
    with pytest.raises(WptError) as excinfo:
        action.apply(ctx, stack, plan)
    assert "an unreadable value" in str(excinfo.value)


# ------------------------------------------------ the fail-closed gates


def test_an_info_payload_without_multisite_is_refused(tmp_path, cache_dir):
    """F12: the multisite gate fails CLOSED on a payload that omits the
    key.

    The deployed bridge answers ``is_multisite() ? … : false``, so a
    payload with no ``multisite`` is a bridge that could not answer — and
    the old truthiness test read that missing value as "single site" and
    let the run continue, while the sibling PHP-floor gate on the very
    same payload refused.  Two gates, one payload, opposite verdicts.
    """
    _refuse(tmp_path, cache_dir, bridge_kwargs={"multisite": None},
            expect="MULTISITE state could not be read")


def test_an_empty_webroot_walk_refuses_before_any_write(tmp_path, cache_dir):
    """F13: a walk that measured NOTHING refuses the run.

    The empty walk is not "a site with no core": it is an unmeasured
    webroot — a dead channel, a webroot that moved, a zip that is not the
    site's.  The old code read it as a site with nothing in scope, skipped
    the pristine proof entirely, and then planned every core file as
    ABSENT, so the pre-action snapshot recorded all of them absent and
    `wpt restore --undo-last` on that snapshot would have DELETED the
    installed core.
    """
    src, session, bridge = make_stack(
        wporg_script(TARGET, TARGET_DB, tail=live_ok()), files={})
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    with pytest.raises(WptError) as excinfo:
        action.plan(ctx, stack)
    message = str(excinfo.value)
    assert "the webroot walk returned NO files" in message
    assert "would then delete the site" in message
    # refused before a single byte of wp.org traffic: an unmeasured
    # webroot is refused before anything is derived from it
    assert src.writes == []
    assert session.gets == []


def test_refuses_mysql_floor_above_live_engine(tmp_path, cache_dir):
    """F14: the release's MySQL floor is compared, not printed.

    The floor used to reach the log line and nothing else, so a target
    that fatals on the site's engine was one refusal short of being
    caught — while the PHP floor, the same kind of number from the same
    offer, was a hard gate.
    """
    _refuse(tmp_path, cache_dir, bridge_kwargs={"mysql": "5.1.73"},
            expect="it requires MySQL 5.5.5 and this site runs 5.1.73")


def test_refuses_unreadable_live_mysql(tmp_path, cache_dir):
    """The engine floor fails closed on an unreadable engine, exactly as
    the PHP floor does on an unreadable interpreter."""
    _refuse(tmp_path, cache_dir, bridge_kwargs={"mysql": None},
            expect="the live MySQL version could not be read")


def test_a_mariadb_engine_suffix_is_compared_not_refused(tmp_path, cache_dir):
    """A MariaDB build answers ``10.6.18-MariaDB``: the suffix is dropped
    and the leading numbers decide, so a host whose answer carries a
    vendor suffix is compared, not refused for its shape."""
    src, session, bridge = make_stack(
        [version_check(TARGET, CURRENT),
         checksums_response(release_map()),
         FakeResponse(content=release_zip_bytes(release_files())),
         checksums_response(current_map())],
        mysql="10.6.18-MariaDB")
    plan = UpdateCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    assert [i.target for i in plan.items] == list(ALL_ITEMS)


def test_the_verify_re_reads_the_engine_against_the_floor(tmp_path, cache_dir):
    """F14, second half: the floor is proved again in the verify, from the
    verify's own ``info`` — not remembered from the pre-swap read."""
    src, session, bridge = make_stack(
        wporg_script(TARGET, TARGET_DB, tail=live_ok()),
        info_after={"mysql_version": "5.1.73"})
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, stack)
    with pytest.raises(WptError) as excinfo:
        action.apply(ctx, stack, plan)
    message = str(excinfo.value)
    assert "answers MySQL 5.1.73 after the update, below the WordPress " \
           "7.1.2 floor of 5.5.5" in message
    assert not any(i.done for i in plan.items)


# ------------------------------------------- the same apply over an FTP-shaped
# source: every remote operation the apply performs, on the wire.
#
# The doubles above are in-memory: a flat ``path -> bytes`` store that grows a
# path on STOR, whatever its parent.  That is exactly why the apply above
# passed for a year of tests and then failed on a production site: a REAL
# server answers 553 to a STOR into a directory it does not have, and the
# update stages each replacement core tree BESIDE the installed one
# (``wp-includes.wpt-new/``), so its first upload is always into a directory
# no site has ever had.
#
# These two tests run the SAME action over the real FtpSource against the
# fake ftplib server (tests/sources/test_ftp.py's FakeFTPServer, which
# enforces MKD/CWD/STOR's real rules), so every remote operation the apply
# performs is exercised as wire traffic: the staging MKDs, the root
# temp+rename, the per-tree RNFR/RNTO swap, the .maintenance WRITE and
# DELETE, the retired-tree removal, and the tree-swap UNDO.

WEBROOT = "site/public_html"


def ftp_fs(files: dict[str, bytes] | None = None) -> dict:
    """The site as an FTP server holds it: webroot-relative path -> dir?
    plus EVERY directory spelled out, because a real server has them and
    the fake's STOR refuses a missing parent."""
    files = site_files() if files is None else files
    fs: dict = {WEBROOT: True}
    for rel in files:
        parent = posixpath.dirname(rel)
        while parent:
            fs[f"{WEBROOT}/{parent}"] = True
            parent = posixpath.dirname(parent)
    for rel in files:
        fs[f"{WEBROOT}/{rel}"] = False
    return fs


class FtpBridge(UpdateBridge):
    """UpdateBridge reading the STORE through the FtpSource.

    The double above reads ``source.files``; this one RETRs, so the version
    the verify reads back and every digest it compares are the bytes the
    fake server actually holds after the renames — a green verify over a
    store that never moved is exactly the "green run over nothing" this
    project refuses.
    """

    def _live_version(self) -> str:
        try:
            raw = self.source.read_bytes("wp-includes/version.php")
        except (SourceError, OSError):   # pragma: no cover
            return self.wp_version
        match = re.search(rb"\$wp_version\s*=\s*'([^']+)'", raw)
        return match.group(1).decode() if match else self.wp_version

    def call(self, action, **params):
        if action != "core_md5":
            return super().call(action, **params)
        self.calls.append((action, params))
        digests: dict[str, str] = {}
        missing: list[str] = []
        unreadable: list[str] = []
        for path in params["paths"]:
            try:
                digests[path] = hashlib.md5(
                    self.source.read_bytes(path)).hexdigest()
            except (SourceError, OSError):
                missing.append(path)
        return {"ok": True, "files": digests, "missing": missing,
                "unreadable": unreadable}


def ftp_stack(monkeypatch, script, *, files=None, **server_kwargs):
    """(FtpSource, FakeSession, FtpBridge, FakeFTPServer) — an ftp-mode
    update stack whose every read and write is a real connector call."""
    from tests.sources.test_ftp import FakeFTPServer

    from wpt.settings import FtpSettings
    from wpt.sources.ftp import FtpSource

    site = site_files() if files is None else files
    srv = FakeFTPServer(ftp_fs(site),
                        contents={f"{WEBROOT}/{rel}": blob
                                  for rel, blob in site.items()},
                        **server_kwargs)
    monkeypatch.setattr("wpt.sources.ftp.ftplib.FTP_TLS", srv.new_connection)
    src = FtpSource("host", "user", "secret", WEBROOT,
                    settings=FtpSettings(timeout_s=5, retries=1))
    bridge = FtpBridge(src)
    return src, FakeSession(list(script)), bridge, srv


def _wire(srv, op):
    return [c for c in srv.state["calls"] if c[0] == op]


def test_apply_over_ftp_creates_its_staging_directories_and_swaps(
        tmp_path, cache_dir, monkeypatch):
    """The live failure, reproduced on the seam: every byte of a core
    update goes to a directory the site has never had, and a STOR into a
    missing directory is a 553 the fake server now raises like a real
    one.  The write path creates the parent chain first, so the apply
    completes — and the rest of the remote plan is asserted op by op:

    * staging — MKD per new directory, built from the webroot-relative
      path, then a STOR into each staged file;
    * root files — one STOR under a ``.wpt-tmp`` name and ONE rename onto
      the live name (never a rewrite of the live file);
    * trees — two RNFR/RNTO per tree (park, then land) and the retired
      tree removed file-by-file, deepest directory first;
    * ``.maintenance`` — one STOR at the webroot root before the first
      swap, and ONE DELE after the last one (a file is removed with DELE;
      asking the connector to RMD a file is what left a live site in
      maintenance for WordPress's own ten minutes);
    * residue — no MKD, no rename and no path outside the webroot root.
    """
    src, session, bridge, srv = ftp_stack(
        monkeypatch,
        wporg_script(TARGET, TARGET_DB, tail=live_ok()),
        files=site_files())
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, stack)
    applied = action.apply(ctx, stack, plan)
    assert all(i.done for i in applied.items)

    # the staged trees carried the release, byte for byte, and the live
    # tree now does (read back over the wire, not from a store)
    for path in IN_SCOPE:
        assert src.read_bytes(path) == release_files()[path]

    # the staging directories were CREATED, deepest chain included, and
    # nothing was ever MKD-ed outside the webroot or above it
    assert ("mkd", f"{WEBROOT}/wp-admin.wpt-new") in srv.state["calls"]
    assert ("mkd", f"{WEBROOT}/wp-includes.wpt-new/js") in srv.state["calls"]
    assert [c for c in _wire(srv, "mkd") if c[1] == WEBROOT] == []
    # and the writes landed in them
    assert ("stor", f"{WEBROOT}/wp-includes.wpt-new/js/new.js") in srv.state["calls"]

    # root files: a temp STOR, then a park + ONE rename onto the live
    # name (never a rewrite of the live file) — and a file the release
    # ADDS has nothing to park, so it is one rename only
    assert [(c[1], c[2]) for c in _wire(srv, "rename")] == [
        (f"{WEBROOT}/wp-admin", f"{WEBROOT}/wp-admin.wpt-old"),
        (f"{WEBROOT}/wp-admin.wpt-new", f"{WEBROOT}/wp-admin"),
        (f"{WEBROOT}/wp-includes", f"{WEBROOT}/wp-includes.wpt-old"),
        (f"{WEBROOT}/wp-includes.wpt-new", f"{WEBROOT}/wp-includes"),
        (f"{WEBROOT}/index.php", f"{WEBROOT}/index.php.wpt-old"),
        (f"{WEBROOT}/index.php.wpt-tmp", f"{WEBROOT}/index.php"),
        (f"{WEBROOT}/wp-load.php", f"{WEBROOT}/wp-load.php.wpt-old"),
        (f"{WEBROOT}/wp-load.php.wpt-tmp", f"{WEBROOT}/wp-load.php"),
        (f"{WEBROOT}/wp-settings.php.wpt-tmp", f"{WEBROOT}/wp-settings.php"),
    ]
    assert ("stor", f"{WEBROOT}/index.php.wpt-tmp") in srv.state["calls"]

    # .maintenance: one WRITE at the root, one DELETE, ordered around the
    # swaps — and it is GONE from the server at the end
    ops = [(c[0], c[1]) for c in srv.state["calls"] if len(c) > 1]
    assert ("stor", f"{WEBROOT}/.maintenance") in ops
    engaged = ops.index(("stor", f"{WEBROOT}/.maintenance"))
    first_swap = ops.index(("rename", f"{WEBROOT}/wp-admin"))
    removed = ops.index(("delete", f"{WEBROOT}/.maintenance"))
    assert engaged < first_swap < removed
    assert f"{WEBROOT}/.maintenance" not in srv.state["fs"]

    # the retired trees went away: files DELEd, directories RMDed
    assert not any(".wpt-old" in key for key in srv.state["fs"])
    assert not any(".wpt-new" in key for key in srv.state["fs"])
    assert not any(".wpt-tmp" in key for key in srv.state["fs"])
    # wp-content/ and wp-config.php are untouched, and the stale file went
    # with the tree it lived in
    assert src.read_bytes("wp-content/plugins/hello.php") == \
        site_files()["wp-content/plugins/hello.php"]
    assert src.read_bytes("wp-config.php") == site_files()["wp-config.php"]
    assert not src.exists("wp-includes/js/old.js")
    # the schema moved through the bridge and the verify re-read the site
    assert bridge.upgraded == 1
    assert [u for u, _kw in session.gets][-2:] == [
        f"{SITE}/", f"{SITE}/wp-json/"]


def test_apply_over_ftp_undo_puts_the_installed_tree_back(
        tmp_path, cache_dir, monkeypatch):
    """The swap's UNDO over FTP: when the SECOND rename of a tree fails,
    the run puts the WHOLE site back — both trees, every root file, byte
    for byte.

    The per-tree undo this replaces was undone inside ``_swap_tree``, so
    it only ever knew about the tree it was in: the FIRST tree's swap had
    already completed (and its backup already deleted), and the root
    files had not been written at all.  The site it left behind was a
    MIXED core — new wp-admin, old wp-includes — with ``.maintenance``
    lifted and the operator told "the update is NOT done".  That is the
    state this asserts against, and it is why the undo is now one
    operation over the whole write phase rather than one per tree.
    """
    src, session, bridge, srv = ftp_stack(
        monkeypatch,
        wporg_script(TARGET, TARGET_DB, tail=live_ok()),
        files=site_files(),
        fail_rename=(f"{WEBROOT}/wp-includes.wpt-new",))
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, stack)
    with pytest.raises(SourceError):
        action.apply(ctx, stack, plan)

    # THE WHOLE TREE, not one of it: the installed core is back exactly as
    # it was — including the first tree, which the old per-tree undo left
    # swapped, and every root file, which it left half-written.
    for path, blob in site_files().items():
        assert src.read_bytes(path) == blob, path
    assert not src.exists("wp-settings.php")     # a file the target ADDS
    assert src.read_bytes("wp-admin/index.php") == b"<?php // admin 6.8.3\n"
    # and no staging or parking residue survives it
    assert not any(".wpt-old" in key for key in srv.state["fs"])
    assert not any(".wpt-new" in key for key in srv.state["fs"])
    assert not any(".wpt-tmp" in key for key in srv.state["fs"])

    # the rollback really was renames on the wire, not a rewrite: the
    # first tree is put back through its OWN staging name (which is what
    # frees the live name) and then the parked original comes back.
    wp_admin = [(c[1], c[2]) for c in _wire(srv, "rename")
                if c[1] in (f"{WEBROOT}/wp-admin",
                            f"{WEBROOT}/wp-admin.wpt-old",
                            f"{WEBROOT}/wp-admin.wpt-new")]
    assert wp_admin == [
        (f"{WEBROOT}/wp-admin", f"{WEBROOT}/wp-admin.wpt-old"),
        (f"{WEBROOT}/wp-admin.wpt-new", f"{WEBROOT}/wp-admin"),
        (f"{WEBROOT}/wp-admin", f"{WEBROOT}/wp-admin.wpt-new"),      # undo
        (f"{WEBROOT}/wp-admin.wpt-old", f"{WEBROOT}/wp-admin"),      # undo
    ]
    # the failing tree never had a live name to give back: its own undo
    # ran inside _park_and_land, so the failed pair is a park and nothing
    # else
    wp_includes = [(c[1], c[2]) for c in _wire(srv, "rename")
                   if c[1].startswith(f"{WEBROOT}/wp-includes")]
    assert wp_includes == [
        (f"{WEBROOT}/wp-includes", f"{WEBROOT}/wp-includes.wpt-old"),
        (f"{WEBROOT}/wp-includes.wpt-old", f"{WEBROOT}/wp-includes"),
    ]

    # nothing ran past the failure: no migration, no purge, no claim
    assert bridge.upgraded == 0
    assert "purge_cache" not in [a for a, _p in bridge.calls]
    assert not any(i.done for i in plan.items)
    # and the maintenance file is cleaned up: a run that ends in
    # maintenance is a site the operator waits ten minutes for
    assert f"{WEBROOT}/.maintenance" not in srv.state["fs"]


def test_apply_over_ftp_undo_at_a_root_file_restores_the_whole_core(
        tmp_path, cache_dir, monkeypatch):
    """F5, the other half: the root-file phase has the SAME undo.

    Root files used to be written temp-then-rename with NO predecessor to
    put back, so a failure on the third one left the site with the new
    ``index.php`` beside the old ``wp-load.php`` — a core whose two halves
    disagree, and no name on the server that holds the old bytes.  Each
    root file is now parked before it is landed, so the undo covers it the
    way it covers a tree, and the failure below lands on the SECOND root
    file: the first must be given back too, or the site is still mixed.
    """
    src, session, bridge, srv = ftp_stack(
        monkeypatch,
        wporg_script(TARGET, TARGET_DB, tail=live_ok()),
        files=site_files(),
        fail_rename=(f"{WEBROOT}/wp-load.php.wpt-tmp",))
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, stack)
    with pytest.raises(SourceError):
        action.apply(ctx, stack, plan)

    # EVERY file is back, byte for byte — the two trees, the root files,
    # wp-content and the config
    for path, blob in site_files().items():
        assert src.read_bytes(path) == blob, path
    assert not src.exists("wp-settings.php")
    # and no residue of any of the three shapes survives the undo
    for suffix in (".wpt-old", ".wpt-new", ".wpt-tmp"):
        assert not any(suffix in key for key in srv.state["fs"]), suffix
    # .maintenance is lifted by the same finally, and the site's own
    # answer is back
    assert f"{WEBROOT}/.maintenance" not in srv.state["fs"]
    # nothing was claimed done, nothing was migrated, nothing was purged
    assert not any(i.done for i in plan.items)
    assert bridge.upgraded == 0
    assert "purge_cache" not in [a for a, _p in bridge.calls]


def test_a_failed_swap_over_ftp_reports_not_done_with_the_snapshot(
        tmp_path, cache_dir, monkeypatch):
    """The same failure through the REGISTRY: rc 1, a failure report that
    says the update is NOT done and names the pre-action snapshot as the
    rollback, and a site that is byte-for-byte the installed core."""
    src, session, bridge, srv = ftp_stack(
        monkeypatch,
        wporg_script(TARGET, TARGET_DB, tail=live_ok()),
        files=site_files(),
        fail_rename=(f"{WEBROOT}/wp-includes.wpt-new",))
    monkeypatch.setattr(registry_mod, "_stack",
                        lambda ctx: (src, session, bridge))
    report = tmp_path / "failed.md"
    rc = run_action(_ctx(tmp_path, apply=True, yes=True,
                         report_path=report), "update-core")
    assert rc == 1
    # the pre-action snapshot exists and is the rollback the report names
    manifests = list((tmp_path / "backup").glob("*/*/manifest.json"))
    assert len(manifests) == 1
    written = report.read_text(encoding="utf-8")
    assert str(manifests[0].parent) in written
    # the site is byte-for-byte the installed core
    for path, blob in site_files().items():
        assert src.read_bytes(path) == blob, path
    # and nothing beyond the swap ran
    assert bridge.upgraded == 0
    assert "purge_cache" not in [a for a, _p in bridge.calls]
    assert f"{WEBROOT}/.maintenance" not in srv.state["fs"]


# ---------------------------------------------------------- F7: the residue


def test_the_sweep_removes_the_root_temp_files_too(tmp_path, cache_dir):
    """The root ``*.wpt-tmp`` siblings are swept, not just the two staged
    trees.

    A real live run left ``index.php.wpt-tmp`` and
    ``wp-activate.php.wpt-tmp`` next to the live files — byte-identical to
    them — and they are what makes ``wp core verify-checksums`` report an
    extra file on a site whose core is otherwise perfect.  The sweep
    walked the two ``.wpt-new`` trees and stopped there, so the root
    temporaries were never candidates: a tool that leaves the residue of
    its own success behind, and cannot see it either.
    """
    from wpt.actions.update_core import _sweep_residue
    src = UpdateSource()
    src.files.update(site_files())
    # what a killed run leaves: one staged tree, two root temporaries
    src.files["wp-includes.wpt-new/version.php"] = b"<?php // staged\n"
    src.files["index.php.wpt-tmp"] = b"<?php // index 6.8.3\n"
    src.files["wp-activate.php.wpt-tmp"] = b"<?php // activate\n"
    _sweep_residue(src)
    assert not any(".wpt-tmp" in p for p in src.files)
    assert not any(".wpt-new" in p for p in src.files)
    # and it touched nothing else
    assert src.files == site_files()


def test_the_sweep_never_deletes_a_parked_tree_but_reports_it(tmp_path,
                                                               cache_dir,
                                                               wpt_records):
    """A ``.wpt-old`` is the last copy of the installed core: the sweep
    REPORTS it, naming both paths, and does not delete it.

    The operator (or the pre-action snapshot) owns that decision.  A sweep
    that removed it would destroy the only hand-recovery path from a run
    that was killed mid-swap or that failed its verify — the exact run
    this residue is evidence of.
    """
    from wpt.actions.update_core import _sweep_residue
    src = UpdateSource()
    src.files.update(site_files())
    src.files["wp-includes.wpt-old/version.php"] = \
        site_files()["wp-includes/version.php"]
    _sweep_residue(src)
    assert src.files["wp-includes.wpt-old/version.php"] == \
        site_files()["wp-includes/version.php"]


def test_the_next_run_reports_the_residue_of_a_killed_one(tmp_path, cache_dir,
                                                          wpt_records):
    """F7/F6: the visibility half — a plan over a webroot carrying a killed
    run's residue NAMES it, and says who owns each name.

    No check in the toolkit reports these three names (the docstring that
    claimed ``prune-core`` / ``clean-files`` would see them as junk was
    false), so a SIGKILLed update left a site that no command could
    explain.  The report runs on every plan — with or without a ``--to`` —
    because the next command an operator runs about an update is this one.
    """
    files = {**site_files(),
             "wp-includes.wpt-old/version.php": b"<?php // installed\n",
             "wp-admin.wpt-new/index.php": b"<?php // staged\n",
             "index.php.wpt-tmp": b"<?php // index\n"}
    src, session, bridge = make_stack(
        [version_check(TARGET, CURRENT),
         checksums_response(release_map()),
         FakeResponse(content=release_zip_bytes(release_files())),
         checksums_response(current_map())], files=files)
    UpdateCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    warns = _messages(_records(wpt_records, logging.WARNING))
    joined = "\n".join(warns)
    # all three shapes, named
    assert "wp-includes.wpt-old" in joined
    assert "wp-admin.wpt-new" in joined
    assert "index.php.wpt-tmp" in joined
    # the parked name is named with the LIVE name it goes back to, and as
    # the copy the operator owns
    assert "move whatever now holds wp-includes aside and rename this to " \
           "wp-includes" in joined
    assert "the operator or `wpt restore --undo-last` owns it" in joined
    # and a plan over a clean site says nothing
    clean, session2, bridge2 = make_stack(
        [version_check(TARGET, CURRENT)])
    before = len(_records(wpt_records, logging.WARNING))
    UpdateCoreAction().plan(_ctx(tmp_path), (clean, session2, bridge2))
    assert len(_records(wpt_records, logging.WARNING)) == before


def test_the_residue_report_runs_without_a_target(tmp_path, cache_dir,
                                                  wpt_records):
    """The report is not a plan-phase afterthought: it runs on the
    no-``--to`` report too, which is the cheapest command an operator
    types when something has gone wrong."""
    files = {**site_files(), "wp-admin.wpt-old/index.php": b"<?php // old\n"}
    src, session, bridge = make_stack(
        [version_check(TARGET, CURRENT)], files=files)
    plan = UpdateCoreAction().plan(_ctx(tmp_path, extra={}),
                                  (src, session, bridge))
    assert plan.items == []
    joined = "\n".join(_messages(_records(wpt_records, logging.WARNING)))
    assert "wp-admin.wpt-old" in joined
    assert "move whatever now holds wp-admin aside and rename this to " \
           "wp-admin" in joined


def test_the_residue_rule_is_one_owner(tmp_path):
    """The name rule is ONE function in ONE module, and it is a ROOT-only
    rule: a path with a directory component is somebody else's file."""
    from wpt.types import (RESIDUE_OWNER, RESIDUE_RETIRED, RESIDUE_STAGED,
                           RESIDUE_TEMP, update_core_residue)
    assert update_core_residue("wp-includes.wpt-old") == RESIDUE_RETIRED
    assert update_core_residue("wp-admin.wpt-new") == RESIDUE_STAGED
    assert update_core_residue("index.php.wpt-tmp") == RESIDUE_TEMP
    # NOT ours: a file of somebody else's that happens to end the same way
    assert update_core_residue("wp-content/backups/index.php.wpt-tmp") is None
    assert update_core_residue("wp-includes/js/rogue.wpt-old") is None
    assert update_core_residue(".wpt-tmp") is None      # no bare suffix
    assert update_core_residue("index.php") is None
    # every role says who owns it — the sweep and the report read the same
    # table, so they cannot disagree about a name
    assert set(RESIDUE_OWNER) == {RESIDUE_STAGED, RESIDUE_TEMP,
                                  RESIDUE_RETIRED}
    assert "never deletes it" in RESIDUE_OWNER[RESIDUE_RETIRED]


# ------------------------------------------- F6: a run KILLED mid-swap
#
# The transport's worst case, and the one no `finally` can answer: the
# process dies between the two renames of a name.  No teardown runs, the
# site is left with a live name that does not exist, and WordPress's own
# 10-minute `.maintenance` expiry then converts a self-describing outage
# into a silent fatal ten minutes later.  So the run is killed for real —
# `os._exit(137)`, a SIGKILL's exit status, with no unwinding, no logging
# and no cleanup — and what survives is measured.

#: The driver the SIGKILL test runs in a child process: the REAL action,
#: over a REAL directory, with the wp.org answers pre-seeded in the cache
#: (a local-mode run builds its own session, which nothing can script).
#: ``KILL_AFTER_RENAMES`` names the rename after which the process dies —
#: the first park, i.e. the widest kill window in the whole swap.
KILL_DRIVER = r"""
import os
import sys
from pathlib import Path

sys.path.insert(0, %(repo)r)
from tests.actions.test_update_core import (DirSource, KillingSource,
                                            _ctx, run_action)
import wpt.audit.updates as updates

root, cache, kill_after = sys.argv[1], sys.argv[2], int(sys.argv[3])
updates._CACHE_DIR = Path(cache)
ctx = _ctx(Path(root), source="local", apply=True, yes=True,
           zip=Path(root) / "site.zip")
stack = (KillingSource(root, kill_after=kill_after), None, None)
import wpt.actions.registry as registry_mod
registry_mod._stack = lambda c: stack
rc = run_action(ctx, "update-core")
print("SURVIVED rc=%%d" %% rc)
"""


class DirSource(Source):
    """A Source over a REAL directory on disk.

    Only the SIGKILL test needs one: every other double in this file is
    in-memory, and an in-memory store cannot be left on disk by a process
    that dies.  It is the honest shape for "the site is a directory and
    the run wrote to it" — nothing simulated, the guards and all.
    """

    def __init__(self, root) -> None:
        self._base = Path(root)
        self.root = str(self._base)

    def _p(self, path: str) -> Path:
        rel = self._guard_path(path) if path.strip("/") else ""
        return self._base / rel if rel else self._base

    def list_dir(self, path: str) -> list[Entry]:
        out: list[Entry] = []
        for child in sorted(self._p(path).iterdir()):
            out.append(Entry(path=f"{path.rstrip('/')}/{child.name}"
                             if path.strip("/") else child.name,
                             is_dir=child.is_dir(), size=child.stat().st_size))
        return out

    def walk(self, path: str = ""):
        for entry in self.list_dir(path):
            yield entry
            if entry.is_dir:
                yield from self.walk(entry.path)

    def read_bytes(self, path: str) -> bytes:
        return self._p(path).read_bytes()

    def write_bytes(self, path, data, *, allow_config=False, allow_core=False):
        self._check_writable(path, allow_config, allow_core)
        target = self._p(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def delete(self, path: str) -> None:
        self._check_deletable(path)
        self._p(path).unlink()

    def rmdir_recursive(self, path: str) -> None:
        self._check_deletable(path)
        shutil.rmtree(self._p(path))

    def exists(self, path: str) -> bool:
        return self._p(path).exists()

    def size(self, path: str) -> int:
        return self._p(path).stat().st_size

    def read_many(self, paths, *, max_bytes=None):
        """The bulk reader the plan's pre-write proof rides (local mode
        has no bridge, so this is the only way it can hash a tree)."""
        ok: dict[str, bytes] = {}
        failed: dict[str, str] = {}
        for path in paths:
            try:
                ok[path] = self.read_bytes(path)
            except (SourceError, OSError) as exc:
                failed[path] = str(exc)
        return ok, failed

    def close(self) -> None:
        return None

    def rename(self, src, dst, *, allow_config=False, allow_core=False):
        self._check_rename_target(dst, allow_config, allow_core)
        self._p(src).rename(self._p(dst))


class KillingSource(DirSource):
    """A DirSource that SIGKILLS ITSELF after the Nth rename.

    ``os._exit(137)`` and not an exception: it skips every ``finally``, so
    no maintenance teardown, no undo and no sweep runs — which is the
    whole point.  137 is the status a SIGKILL leaves behind, so the test
    can assert the run really died rather than returned.
    """

    def __init__(self, root, *, kill_after: int) -> None:
        super().__init__(root)
        self.kill_after = kill_after
        self.renames = 0

    def rename(self, src, dst, *, allow_config=False, allow_core=False):
        super().rename(src, dst, allow_config=allow_config,
                       allow_core=allow_core)
        self.renames += 1
        if self.renames == self.kill_after:
            os._exit(137)


def _kill_a_run_mid_swap(tmp_path, cache_dir, *, kill_after):
    """Run the real apply in a child process and kill it after N renames."""
    root = tmp_path / "webroot"
    for rel, blob in site_files().items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blob)
    seed_local_wporg(cache_dir)
    driver = KILL_DRIVER % {"repo": str(REPO)}
    proc = subprocess.run(
        [sys.executable, "-c", driver, str(root), str(cache_dir),
         str(kill_after)],
        capture_output=True, text=True, timeout=180, cwd=str(REPO),
    )
    return root, proc


def test_a_run_killed_mid_swap_leaves_a_recoverable_webroot(tmp_path,
                                                            cache_dir,
                                                            wpt_records):
    """F6: the site is recoverable, the outage is DESCRIBED, and the next
    command finds out.

    The kill lands between the two renames of the SECOND tree: the site
    is left with no ``wp-includes/`` at all, and nothing anywhere saying
    why.  ``wp-admin`` has already been swapped at that point, which is
    precisely the state the old ordering produced and could not undo.
    """
    root, proc = _kill_a_run_mid_swap(tmp_path, cache_dir, kill_after=3)
    assert proc.returncode == 137, proc.stderr[-2000:]
    assert "SURVIVED" not in proc.stdout

    # (a) THE TREE STATE IS ONE A HUMAN CAN RECOVER FROM: every landed
    # name has BOTH halves on disk, so each is two renames — the new one
    # back to its staging name, the parked original back to the live one.
    # Nothing has to be fetched, re-uploaded or reconstructed.
    assert not (root / "wp-includes").exists()
    assert (root / "wp-includes.wpt-old" / "version.php").read_bytes() == \
        site_files()["wp-includes/version.php"]
    assert (root / "wp-includes.wpt-old" / "js" / "old.js").exists()
    assert (root / "wp-includes.wpt-new" / "version.php").exists()
    assert (root / "wp-admin.wpt-old" / "index.php").exists()
    # THE RECOVERY, performed exactly as the residue report describes it:
    # a parked name goes back to its live name, after whatever holds that
    # name is moved aside.  wp-includes was never landed, so its live
    # name is free; wp-admin was, so the new tree moves aside first.
    (root / "wp-includes.wpt-old").rename(root / "wp-includes")
    (root / "wp-admin").rename(root / "wp-admin.wpt-scratch")
    (root / "wp-admin.wpt-old").rename(root / "wp-admin")
    for rel, blob in site_files().items():
        assert (root / rel).read_bytes() == blob, rel

    # (c) THE OUTAGE IS DESCRIBED: the maintenance file is WordPress's own
    # shape (so the 10-minute expiry still applies) PLUS a body a human
    # can read.
    body = (root / ".maintenance").read_text(encoding="utf-8")
    assert re.search(r"\$upgrading = \d+;?", body), body
    assert "wpt update-core" in body
    assert "core files are being swapped" in body
    assert body.startswith("<?php")      # never served as text


def test_the_next_command_reports_a_killed_runs_residue(tmp_path, cache_dir,
                                                        wpt_records):
    """F6(b)/F7: the next run over a killed run's webroot NAMES the
    residue — both trees, and the live name each one goes back to.

    Without this the killed run is invisible: the names it left appear in
    no check, no junk pattern and no plan, so the operator sees a site
    with a missing tree and no account of where its core went.
    """
    root, proc = _kill_a_run_mid_swap(tmp_path, cache_dir, kill_after=3)
    assert proc.returncode == 137
    assert not (root / "wp-includes").exists()
    # a fresh run, over the same webroot, in a process that survives
    src = DirSource(root)
    from wpt.actions.update_core import _report_residue
    _report_residue(list(src.walk()))
    joined = "\n".join(_messages(_records(wpt_records, logging.WARNING)))
    # BOTH trees named, and the parked one named with the live name it
    # goes back to — that rename IS the recovery
    assert "wp-includes.wpt-old" in joined
    assert "wp-includes.wpt-new" in joined
    assert "move whatever now holds wp-includes aside and rename this to " \
           "wp-includes" in joined
    assert "the operator or `wpt restore --undo-last` owns it" in joined
    # and the staged tree is named as this tool's own, removable residue
    assert "removed by the next sweep" in joined


# ------------------------------------------- F10: a migration that FATALS


def test_a_migration_that_fatals_still_reports_the_state_it_began_in(
        tmp_path, cache_dir):
    """A non-catchable PHP fatal inside ``wp_upgrade()`` destroys the
    op's answer — the client never sees JSON — so the run's own diagnosis
    has to come from somewhere else.

    A modest ``memory_limit`` on a big migration is the shape that
    actually happens on shared hosting, and what it leaves behind is a
    database the migration has already half-moved.  The refusal below
    therefore names the pre-migration schema version and the target, so
    the operator can tell "re-run the migration" from "restore the
    database" — instead of the bare "non-JSON" the client raises.
    """
    src, session, bridge = make_stack(
        wporg_script(TARGET, TARGET_DB, tail=live_ok()),
        db_version_after=TARGET_DB)
    bridge.fatal_migration = True
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, stack)
    with pytest.raises(WptError) as excinfo:
        action.apply(ctx, stack, plan)
    message = str(excinfo.value)
    assert "did not report back" in message
    assert "Allowed memory size" in message          # the wire failure
    assert "from db_version 56657" in message         # the pre-migration value
    assert "heading for 60356" in message              # and the target
    assert "pre-action snapshot is the rollback" in message
    # the marker was read back over a SEPARATE call, which is the whole
    # reason it can be read at all
    assert ("info", {}) in bridge.calls
    assert not any(i.done for i in plan.items)
    # and the parked core is still there: the run failed, so the last
    # copy of the installed tree was not discarded
    assert src.files["wp-includes.wpt-old/version.php"] == \
        site_files()["wp-includes/version.php"]


def test_a_migration_that_fatals_without_a_marker_says_what_it_read(
        tmp_path, cache_dir):
    """No marker to read (an older bridge, or a site whose options row is
    unreadable): the refusal still carries the schema version this run
    measured before it started, rather than nothing at all."""
    src, session, bridge = make_stack(
        wporg_script(TARGET, TARGET_DB, tail=live_ok()),
        db_version_after=TARGET_DB)
    bridge.fatal_migration = True
    bridge.upgrade_marker = lambda: None
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, stack)
    with pytest.raises(WptError) as excinfo:
        action.apply(ctx, stack, plan)
    assert "db_version 56657 was read before the migration started" in \
        str(excinfo.value)


def test_a_failed_run_reports_the_parked_core_it_left_behind(tmp_path,
                                                            cache_dir,
                                                            wpt_records):
    """F7 at the end of a FAILED run: the parked copy survives (it is the
    last copy of the installed core) and the run NAMES it, with the live
    name it goes back to.

    Deleting it would be the easy move and the wrong one: a migration that
    did not reach its target, a digest that does not match, a site that
    will not render — every one of those is a hand-recovery situation, and
    the parked tree is the copy the operator recovers from.
    """
    src, session, bridge = make_stack(
        wporg_script(TARGET, TARGET_DB, tail=live_ok()),
        info_after={"db_version": str(CURRENT_DB)})
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, stack)
    with pytest.raises(WptError):
        action.apply(ctx, stack, plan)
    # the copy is still there…
    assert src.files["wp-includes.wpt-old/version.php"] == \
        site_files()["wp-includes/version.php"]
    assert src.files["index.php.wpt-old"] == site_files()["index.php"]
    # …and the run said so, naming the rename that uses it
    joined = "\n".join(_messages(_records(wpt_records, logging.WARNING)))
    assert "wp-includes.wpt-old" in joined
    assert "move whatever now holds wp-includes aside and rename this to " \
           "wp-includes" in joined
    # while the staging and temp copies are cleaned, not reported
    assert not any(".wpt-new" in p for p in src.files)
    assert not any(".wpt-tmp" in p for p in src.files)


# ------------------------------------------------------------- the driver
#
# Two drivers, one set of guarantees. The plan must NAME the driver it
# would use and why; --apply must run that one; and a site whose
# availability changed in between refuses rather than quietly switching.


def _local_site_zip(tmp_path) -> Path:
    """The site as a real offline zip — the local mode's only source."""
    zip_path = tmp_path / "site.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for rel, blob in site_files().items():
            zf.writestr(rel, blob)
    return zip_path


def _wordpress_stack(*, script=None, files=None, **kwargs):
    """A stack whose site can run WordPress's OWN updater.

    The two facts the op answers on request: a ``direct`` filesystem
    method (the only one core's upgrader can be driven with blind) and a
    zip library (core's own unzip_file() needs one). Everything else about
    the double is the same store the swap driver's tests use, so the two
    drivers are measured against one world.
    """
    kwargs.setdefault("fs_method", "direct")
    kwargs.setdefault("zip_library", "ZipArchive")
    return make_stack(script if script is not None else wporg_script(
        TARGET, TARGET_DB, tail=live_ok()), files=files, **kwargs)


def test_auto_names_wordpress_when_the_site_can_run_core_updater(
        tmp_path, cache_dir, wpt_records):
    """``auto`` + a direct filesystem + a zip library = the wordpress
    driver, and the plan says WHY — a plan that does not name its driver
    is a plan whose mechanism nobody confirmed."""
    src, session, bridge = _wordpress_stack()
    plan = UpdateCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    assert [i.target for i in plan.items] == list(ALL_ITEMS)
    joined = "\n".join(_messages(_records(wpt_records, logging.INFO)))
    assert "DRIVER = wordpress" in joined
    assert "direct filesystem and ZipArchive" in joined
    assert "attempt_rollback armed" in joined
    # and the plan is the SAME plan: the refusals, the snapshot scope and
    # the file set do not move with the driver
    assert "snapshot scope = the 6 replaced file(s) + the 1 removed with " \
           "them + 2 database table(s)" in joined
    stale = next(i for i in plan.items
                 if i.target == "wp-includes/js/old.js")
    assert "removed explicitly by the wordpress driver" in stale.detail
    assert "replaced core tree" not in stale.detail
    assert src.writes == []


def test_auto_falls_back_to_swap_when_the_site_cannot(tmp_path, cache_dir,
                                                     wpt_records):
    """Each precondition, and the UNREADABLE case, resolve to the driver
    that needs neither — every site stays updatable."""
    for fs_method, zip_library, why in (
            ("ftpext", "ZipArchive", "filesystem method is ftpext"),
            ("direct", "", "neither ZipArchive nor core's bundled PclZip"),
            ("", "", "filesystem method is unreadable"),
    ):
        src, session, bridge = make_stack(
            wporg_script(TARGET, TARGET_DB, tail=live_ok()),
            fs_method=fs_method, zip_library=zip_library)
        UpdateCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
        joined = "\n".join(_messages(_records(wpt_records, logging.INFO)))
        assert "DRIVER = swap" in joined, (fs_method, zip_library)
        assert why in joined, (fs_method, zip_library)


def test_the_plan_asks_the_site_for_the_driver_facts(tmp_path, cache_dir):
    """The facts are asked for on the SAME info call the plan already
    makes (``core_upgrade=1``), so nothing is fetched twice and the
    driver's basis is the site's own answer, not a guess."""
    src, session, bridge = _wordpress_stack()
    UpdateCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    assert [params.get("core_upgrade") for action, params in bridge.calls
            if action == "info"] == [True]


def test_a_driver_named_outright_and_unavailable_refuses(tmp_path,
                                                         cache_dir):
    """``update.driver=wordpress`` on a site that cannot run it is a
    refusal, not a silent run of the other mechanism."""
    from dataclasses import replace

    settings = replace(DEFAULTS, update=replace(DEFAULTS.update,
                                                driver="wordpress"))
    src, session, bridge = make_stack(
        [version_check(TARGET, CURRENT)], fs_method="ftpext")
    with pytest.raises(WptError) as excinfo:
        UpdateCoreAction().plan(
            _ctx(tmp_path, settings=settings), (src, session, bridge))
    message = str(excinfo.value)
    assert "update.driver=wordpress cannot run on this site" in message
    assert "filesystem method is ftpext" in message
    assert "update.driver=swap" in message
    assert src.writes == []
    # refused before the release is even downloaded
    assert len(session.gets) == 1


def test_the_wordpress_driver_refuses_in_local_mode(tmp_path, cache_dir,
                                                   monkeypatch):
    """There is no running PHP offline, so there is nothing to drive."""
    from dataclasses import replace

    settings = replace(DEFAULTS, update=replace(DEFAULTS.update,
                                                driver="wordpress"))
    zip_path = _local_site_zip(tmp_path)
    seed_local_wporg(cache_dir)
    import wpt.actions.registry as registry_mod
    src, _session, _bridge = registry_mod._stack(
        _ctx(tmp_path, source="local", zip=zip_path, settings=settings))
    with pytest.raises(WptError) as excinfo:
        UpdateCoreAction().plan(
            _ctx(tmp_path, settings=settings, source="local", zip=zip_path,
                 extra={"to": TARGET}), (src, None, None))
    assert "no running PHP" in str(excinfo.value)
    assert "update.driver=swap" in str(excinfo.value)


def test_auto_in_local_mode_rehearses_the_swap(tmp_path, cache_dir,
                                              wpt_records):
    """auto offline: the swap driver, because the swap is the one that
    needs no running WordPress — the rehearsal is a real rehearsal."""
    zip_path = _local_site_zip(tmp_path)
    seed_local_wporg(cache_dir)
    ctx = _ctx(tmp_path, source="local", zip=zip_path,
               extra={"to": TARGET})
    import wpt.actions.registry as registry_mod
    src, _session, _bridge = registry_mod._stack(ctx)
    action = UpdateCoreAction()
    action.plan(ctx, (src, None, None))
    assert "DRIVER = swap" in "\n".join(
        _messages(_records(wpt_records, logging.INFO)))


def test_the_apply_refuses_when_the_driver_changed_since_the_plan(
        tmp_path, cache_dir):
    """A site that lost ``direct`` between the plan and the apply must NOT
    quietly get the other mechanism: the operator confirmed a plan that
    named one driver, and a run that changed driver half way through is
    not a run whose plan was confirmed."""
    src, session, bridge = _wordpress_stack(
        driver_facts_after=("ftpext", "ZipArchive"))
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, stack)
    with pytest.raises(WptError) as excinfo:
        action.apply(ctx, stack, plan)
    message = str(excinfo.value)
    assert "the driver changed between the plan and the apply" in message
    assert "the plan named `wordpress`" in message
    assert "now answers `swap`" in message
    assert "nothing was written" in message
    assert src.files == site_files()


def test_the_wordpress_driver_installs_the_release_and_verifies(
        tmp_path, cache_dir, wpt_records):
    """The whole apply over the wordpress driver: the proven release is
    uploaded, core's updater is driven, the plan's stale files are removed
    (core's copy overwrites and never deletes — that step is the tool's),
    the migration runs, the verify passes, and the plan's items flip.

    Every guarantee the swap driver keeps is kept here, from the SAME
    code: the pre-write proof, the maintenance window removed in the
    finally, the migration through core's own wp_upgrade(), the digest
    pass and the live probes.
    """
    src, session, bridge = _wordpress_stack()
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, stack)
    applied = action.apply(ctx, stack, plan)
    assert applied is plan
    assert all(i.done for i in applied.items)
    # the release's bytes are on the site — landed by core, proved by the
    # verify's digest pass against the target map
    files = release_files()
    for path in IN_SCOPE:
        assert src.files[path] == files[path]
    # WordPress's own updater was driven, through the op, with the package
    # the action uploaded (and the upload is gone afterwards: the sweep
    # removes wpt's own re-fetchable copy)
    op_calls = [c for c in bridge.calls if c[0] == "core_upgrade_files"]
    assert len(op_calls) == 1
    assert op_calls[0][1]["package"] == \
        f"wp-content/wpt-update/wordpress-{TARGET}.zip"
    assert op_calls[0][1]["target"] == TARGET
    assert not any(p.startswith("wp-content/wpt-update/") for p in src.files)
    # the step core's copy does not do: the plan's stale file is gone
    assert "wp-includes/js/old.js" not in src.files
    # wp-content/ and wp-config.php are still untouched
    assert src.files["wp-config.php"] == site_files()["wp-config.php"]
    assert src.files["wp-content/plugins/hello.php"] == \
        site_files()["wp-content/plugins/hello.php"]
    # the maintenance window is the tool's own, engaged and removed
    assert ".maintenance" in _files_written(src)
    assert ".maintenance" not in src.files
    # the phases core reported are in the run's log
    joined = "\n".join(_messages(_records(wpt_records, logging.INFO)))
    assert "core_upgrade_files unzip: ok — extracted" in joined
    assert "core_upgrade_files copy: ok — landed" in joined
    assert "WordPress's own updater announced: Verifying the unpacked" \
           " files… | Upgrading database…" in joined
    assert "installed and verified — 7 core file(s) replaced with the " \
           "wordpress driver" in joined
    # the migration still ran, through core's own wp_upgrade()
    assert bridge.upgraded == 1
    assert [c for c in bridge.calls if c[0] == "core_upgrade"] == [
        ("core_upgrade", {"apply": True})]


def test_a_core_failure_leaves_abspath_untouched_and_the_run_not_done(
        tmp_path, cache_dir, wpt_records):
    """A wordpress-driver failure is NOT DONE, and it is not reported as
    a success with a caveat: the op's refusal carries the phases, the plan
    keeps every item un-done, and the site is exactly as it was."""
    src, session, bridge = _wordpress_stack(
        core_files_error="WordPress's own updater failed: "
                         "copy_failed__copy_dir: Could not copy files.")
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, stack)
    with pytest.raises(WptError) as excinfo:
        action.apply(ctx, stack, plan)
    message = str(excinfo.value)
    assert "copy_failed__copy_dir" in message
    assert "did not finish the file half" in message
    assert "NOT done" in message
    assert "restore --undo-last" in message
    assert not any(i.done for i in plan.items)
    # ABSPATH untouched: no core file changed, and the swap driver's own
    # staging never appeared (a different driver left no trace)
    for path, blob in site_files().items():
        assert src.files[path] == blob, path
    assert not any(".wpt-new" in p or ".wpt-old" in p or ".wpt-tmp" in p
                   for p in src.files)
    assert ".maintenance" not in src.files
    # and the migration never ran: the files were not proven, so the
    # database was not touched
    assert bridge.upgraded == 0
    # the uploaded package is swept even on a failed run: it is wpt's own
    # re-fetchable copy and it is web-served while it exists
    assert not any(p.startswith("wp-content/wpt-update/") for p in src.files)


def test_the_verify_says_why_it_does_not_trust_core_s_own_step(
        tmp_path, cache_dir, wpt_records):
    """The fire-and-forget fact, stated by the verify itself.

    WordPress's own core update POSTs the database migration to itself with
    a 60s timeout and never inspects the response, so a dead callback
    leaves new files on an old schema. wpt therefore runs the migration
    in-process and re-reads the version — and SAYS that, on every run, for
    both drivers, so the re-read is never mistaken for redundancy.
    """
    src, session, bridge = make_stack(
        wporg_script(TARGET, TARGET_DB, tail=live_ok()))
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, stack)
    action.apply(ctx, stack, plan)
    joined = "\n".join(_messages(_records(wpt_records, logging.INFO)))
    assert "WordPress's own step is fire-and-forget, so wpt verifies it " \
           "itself" in joined
    assert "60s timeout and never checks the answer" in joined
    assert "re-read from a fresh process" in joined


def test_the_staging_under_wp_content_is_reported_and_never_swept(
        tmp_path, cache_dir, wpt_records):
    """``wp-content/upgrade/`` is CORE's staging, and on a site whose
    earlier core update died mid-copy it is the operator's recovery path:
    the residue report NAMES it with its owner, and the sweep leaves it
    alone.  A tool that deleted it would destroy the only way back short
    of the snapshot."""
    from wpt.actions.update_core import _sweep_residue

    files = {**site_files(),
             "wp-content/upgrade/wordpress-7.0/version.php": b"<?php // 7.0\n",
             "wp-content/wpt-update/wordpress-7.1.2.zip": b"PK\x03\x04zip"}
    src, session, bridge = make_stack(
        [version_check(TARGET, CURRENT),
         checksums_response(release_map()),
         FakeResponse(content=release_zip_bytes(release_files())),
         checksums_response(current_map())], files=files)
    # every plan reports it, before any target is even named
    UpdateCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    joined = "\n".join(_messages(_records(wpt_records, logging.WARNING)))
    assert "wp-content/upgrade" in joined
    assert "WordPress's own staging directory" in joined
    assert "the operator or `wpt restore --undo-last` owns it" in joined
    # the sweep removes wpt's OWN uploaded package and keeps the staging
    _sweep_residue(src)
    assert "wp-content/upgrade/wordpress-7.0/version.php" in src.files
    assert not any(p.startswith("wp-content/wpt-update/")
                   for p in src.files)


def test_a_verified_run_clears_only_the_staging_it_created(
        tmp_path, cache_dir):
    """The narrow half of the rule: a run that CREATED the staging and
    whose verify PASSED clears it, and nothing else may."""
    from wpt.actions.update_core import _clear_own_staging

    src, session, bridge = _wordpress_stack()
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, stack)
    src.files[f"{_STAGING_PREFIX}wordpress-{TARGET}/version.php"] = \
        release_files()["wp-includes/version.php"]
    # the op's answer says the staging is still there
    bridge.core_staging = _STAGING_PREFIX + f"wordpress-{TARGET}"
    applied = action.apply(ctx, stack, plan)
    assert all(i.done for i in applied.items)
    # the staging this run created is gone, and the tool's own copy too
    assert not any(p.startswith(_STAGING_PREFIX) for p in src.files)
    assert not any(p.startswith("wp-content/wpt-update/") for p in src.files)
    # and a path OUTSIDE the staging area is never touched, whatever it is
    src.files["wp-content/upgrade-not-staging/keep.php"] = b"<?php\n"
    _clear_own_staging(src, "wp-content/upgrade-not-staging/keep.php")
    assert "wp-content/upgrade-not-staging/keep.php" in src.files


def test_a_failed_verify_keeps_the_staging_it_created(tmp_path, cache_dir,
                                                     wpt_records):
    """The other half: until the verify passes, the staging IS the
    recovery path, so a run that failed its proof leaves it and NAMES it."""
    from wpt.actions.update_core import _sweep_residue

    src, session, bridge = _wordpress_stack(
        info_after={"db_version": str(CURRENT_DB)})
    bridge.core_staging = _STAGING_PREFIX + f"wordpress-{TARGET}"
    action = UpdateCoreAction()
    stack = (src, session, bridge)
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, stack)
    with pytest.raises(WptError):
        action.apply(ctx, stack, plan)
    staging = f"{_STAGING_PREFIX}wordpress-{TARGET}/version.php"
    src.files[staging] = release_files()["wp-includes/version.php"]
    _sweep_residue(src)
    assert staging in src.files
    joined = "\n".join(_messages(_records(wpt_records, logging.WARNING)))
    assert "wp-content/upgrade" in joined
    assert "the operator or `wpt restore --undo-last` owns it" in joined


def test_R18_verify_live_deadline_drip_is_a_cooperative_stop(tmp_path):
    """R18-P2: the bounded GET's header timeout is a WptError, which
    ``_fetch_status`` did not catch; the registry reported "apply failed
    after backup" instead of the run-deadline verdict."""
    import http.server
    import threading
    import time

    import requests

    from wpt.actions.update_core import _fetch_status
    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    class Drip(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            try:
                head = (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                for byte in head:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.08)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Drip)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    session = requests.Session()
    session.trust_env = False
    try:
        started = time.monotonic()
        with pytest.raises(DeadlineExceeded):
            _fetch_status(
                session, f"http://127.0.0.1:{server.server_port}/",
                _ctx(tmp_path), "site root", render=True,
                deadline=Deadline(0.5))
        assert time.monotonic() - started < 1.5
    finally:
        session.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_R25_verify_probe_is_bounded_even_without_a_run_deadline(tmp_path):
    """R25-P2: ``--deadline 0`` fell back to ``session.get(timeout=...)``,
    whose timeout is per-read: a 0.08 s/byte header drip held the
    post-update verify for 5-6 s.  The bounded transport is always used."""
    import dataclasses
    import http.server
    import threading
    import time

    import requests

    from wpt.actions.update_core import _fetch_status
    from wpt.types import WptError

    class Drip(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            try:
                head = (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                for byte in head:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.08)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Drip)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    settings = dataclasses.replace(
        DEFAULTS,
        http=dataclasses.replace(DEFAULTS.http, timeout_s=1))
    ctx = _ctx(tmp_path, settings=settings)
    session = requests.Session()
    session.trust_env = False
    try:
        started = time.monotonic()
        with pytest.raises(WptError) as caught:
            _fetch_status(
                session, f"http://127.0.0.1:{server.server_port}/",
                ctx, "site root", render=True, deadline=None)
        assert time.monotonic() - started < 2.2
        assert "pre-action snapshot" in str(caught.value)
    finally:
        session.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_R13_verify_live_probes_share_the_run_deadline(tmp_path):
    """R13-P2-8: ``_verify_live`` issued two plain ``session.get`` calls
    with only a per-read timeout, so an expired run budget still waited up
    to 2x ``http.timeout_s``.  Both probes now take the ctx deadline and
    refuse BEFORE the request when it is already spent."""
    from types import SimpleNamespace

    from wpt.actions.update_core import _fetch_status
    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    ctx = _ctx(tmp_path)
    ctx._deadline = Deadline(0.0)
    session = FakeSession([])
    with pytest.raises(DeadlineExceeded):
        _fetch_status(session, f"{SITE}/", ctx, "site root", render=True,
                      deadline=Deadline.from_ctx(ctx))
    assert session.gets == []

    captured = {}

    def _get(url, **kwargs):
        captured.update(kwargs)
        return FakeResponse(200, "ok")

    ctx._deadline = Deadline(30.0)
    fake = SimpleNamespace(get=_get)
    _fetch_status(fake, f"{SITE}/", ctx, "site root", render=True,
                  deadline=Deadline.from_ctx(ctx))
    assert captured["timeout"] == ctx.settings.http.timeout_s


def test_R24_verify_probe_uses_the_per_request_http_timeout(tmp_path):
    """R24-P1: ``_fetch_status`` armed the shared transport with the RUN
    deadline, so a dripped verification answer consumed the whole budget and
    produced the generic stopped report instead of the SPEC verification
    failure that names the pre-action snapshot.  The transport bound is
    ``min(run, now + http.timeout_s)``; only a spent run is a stop."""
    import dataclasses
    import http.server
    import threading
    import time

    import requests

    from wpt.actions.update_core import _fetch_status
    from wpt.deadline import Deadline
    from wpt.types import WptError

    class Drip(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            try:
                head = (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                for byte in head:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.08)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Drip)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    settings = dataclasses.replace(
        DEFAULTS,
        http=dataclasses.replace(DEFAULTS.http, timeout_s=1))
    ctx = _ctx(tmp_path, settings=settings)
    session = requests.Session()
    session.trust_env = False
    try:
        started = time.monotonic()
        with pytest.raises(WptError) as caught:
            _fetch_status(
                session, f"http://127.0.0.1:{server.server_port}/",
                ctx, "site root", render=True, deadline=Deadline(3))
        assert time.monotonic() - started < 2.2
        assert "pre-action snapshot" in str(caught.value)
    finally:
        session.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
