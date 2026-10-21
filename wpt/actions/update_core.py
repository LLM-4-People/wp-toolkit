"""update-core action: take a live site from core X.Y.Z to an EXPLICIT
target release, and prove the result.

The tool REPORTS updates (``updates`` / ``doctor`` read wp.org's
version-check API) but could not APPLY one: every capability so far
either restores files the site already has AT ITS OWN VERSION
(``heal-core``) or removes files the current release dropped
(``prune-core``).  This is the missing third one — the operator names the
version the site should run, and wpt makes that true.

THE TARGET IS NEVER IMPLICIT.  ``--to X.Y.Z`` is required for an
``--apply``; the target is not "the latest offer" and not "the next
minor", because both are a moving answer taken off the wire and a core
update is the one operation where guessing the destination is
unrecoverable.  Without ``--to`` the run is a read-only report of what
wp.org offers, naming the exact version a ``--to`` would need.

The plan (read-only; ``--apply`` required for any mutation) lists:

1. the target core version with its ``db_version``, beside the site's
   current pair.  The target's schema version is read out of the TARGET
   release zip's own ``wp-includes/version.php`` (``$wp_db_version``) —
   the authoritative statement of what the migration will make the
   database — and the current one from the bridge ``info`` payload (the
   stored ``db_version`` option).  Whether a migration is implied is a
   comparison of those two integers, never an assumption.
2. the EXACT file set the target replaces: every core file the official
   release ships — ``wp-admin/**``, ``wp-includes/**`` and the
   webroot-root ``*.php`` files.  It is derived from the release on
   every run (the zip's own namelist for the set, its own entry sizes
   for the estimate), never from a list of WordPress's filenames that
   goes stale with every release.
3. the release's declared minimum PHP and MySQL against the LIVE site's
   (the bridge ``info`` payload).  BOTH floors are REFUSALS, not
   warnings: the target would be a core that fatals on this host, and a
   number in a dry run nobody reads before the site breaks is not a
   control.  An unreadable floor source is refused for the same reason an
   unreadable live PHP is — an unproven precondition is not a met one —
   so a payload that cannot prove it carries the engine leaves through
   exactly the gate the PHP floor does.  The engine is RE-READ in the
   verify, beside the schema version, so the proof never rests on the
   pre-swap read.
4. that maintenance mode will be engaged: the webroot-root
   ``.maintenance`` file, the one WordPress itself honours
   (``wp_is_maintenance_mode()`` requires it at ``ABSPATH``) and the one
   ``WP_Upgrader::maintenance_mode()`` writes — core's own
   ``$upgrading = <time>;`` line (which is what the 10-minute expiry is
   measured from) plus an explanatory body, so the file a human opens
   during a stuck swap says what is happening instead of looking like a
   stray PHP fragment.
5. the snapshot scope — the same file set plus every database table
   through the existing ``db_dump`` snapshot machinery — and that
   ``wpt restore --undo-last`` is the rollback.  The registry derives
   the snapshot's file scope from the plan's own item targets, so the
   scope the operator reads IS the scope that gets captured.
6. the byte estimate (the release's own sizes, summed), printed by the
   registry from ``plan.est_bytes()``.

WHAT THE PRISTINE PROOF COVERS, STATED HONESTLY.  The pre-write check
proves the files it is ABOUT TO REPLACE are the official bytes of the
version the site claims to run: the two replaced trees, and the root
``*.php`` files the target release itself ships.  It is a TREE-SCOPED
claim, not a whole-core one.  A site-level ``*.php`` the release does not
ship is untouched by the swap (the update only renames the release's own
files onto their names) and is therefore outside this gate, and
``wp-content/`` is out of scope by construction.  Every file the swap
DELETES is a file inside a replaced tree, and those are gated.

``Plan`` carries items and table names only (it is a printed, rebuildable
artifact), so every narrative fact above is one ``log.info`` line from
``wpt.actions.update_core``; the per-file fact is one PlanItem per
replaced file, which is also what makes the snapshot scope and the
"applied" column exact.

TWO DRIVERS, ONE SET OF GUARANTEES.  The file half of a core update can
be laid down two ways, and the choice is a SETTING, not a fork in the
code:

* ``swap`` (the original): each core tree is staged beside the one it
  replaces and swapped with a rename, every landed step recorded so a
  failure anywhere in the write phase is undone in reverse.  It needs
  nothing but a writable channel, which is why it is the driver that
  always works — including the local rehearsal, which has no running
  PHP at all.
* ``wordpress``: WordPress's OWN updater does the work, through the
  bridge's ``core_upgrade_files`` op — core's ``unpack_package()`` (its
  own ``unzip_file()`` into ``wp-content/upgrade/``), then core's
  ``update_core()`` with its ``copy_dir()`` and its
  ``array('wp-content', 'wp-includes/version.php')`` skip list, the
  version file copied LAST so a failed update still reports the old
  version, the bundled theme/plugin re-add, and the post-copy md5
  re-verification — armed with ``attempt_rollback``, the argument the
  admin UI never passes.  Re-implementing that placement would forfeit
  both of those encodings for no benefit.

``update.driver`` chooses between them: ``"wordpress"`` / ``"swap"`` name
one outright, and the shipped ``"auto"`` picks ``wordpress`` when the
site reports a ``direct`` filesystem method AND a zip library — the two
preconditions core's own extractor has, read from the RUNNING site over
the bridge — and ``swap`` everywhere else.  That direction is the safe
one: the swap needs neither precondition, so every site stays
updatable.

THE GUARANTEES ARE THE TOOL'S, NOT THE DRIVER'S.  Whichever driver runs,
the same things wrap it and verify it: the pre-action snapshot, the
pristine proof, ``.maintenance`` engaged before and removed in a
``finally``, the migration through core's own ``wp_upgrade()``, and the
verify (the version re-read from a fresh process, every replaced file
re-hashed, the live probes).  That is also why the two drivers differ
only in HOW the bytes land — the plan, the refusals, the snapshot scope
and the proof are literally the same code, and a driver that turns out
to be unavailable at apply time FAILS the run instead of falling back
mid-apply (a run that changed mechanism half way through is not a run
whose plan was confirmed).

REFUSALS — all of them before a single write, each one line naming the
cause and the lever, and each of them runs in the PLAN phase and again
in the apply (which re-derives every fact, because a Plan is a printed
artifact and the site can change under it):

* ``--apply`` without ``--to``; the target is never implicit.
* a target wp.org does not OFFER, or offers as a pre-release and
  ``--allow-pre-release`` was not given.  The version-check list decides
  both what exists and what its floors are, so a hand-typed version that
  is not on it is never fetched on the assumption that it is real.
* a dev/beta/RC INSTALL (not merely a pre-release TARGET) without the
  same flag: a trunk checkout's ``$wp_version`` is not a release, and no
  official release zip describes the bytes it runs.
* the release's PHP floor above the live PHP, or a live PHP that cannot
  be read at all (an unproven precondition is not a met one).  The MySQL
  floor is the same gate over the same unproven-value rule.
* a multisite install: ``wp_upgrade()`` takes the network path there
  (``upgrade_network()`` plus a per-site ``db_version`` in site meta)
  while this action's snapshot covers one site's files and one database.
  An install whose multisite state the payload does not carry is refused
  too — the same fail-closed shape as the PHP floor, and deliberately the
  OPPOSITE of a truthiness test, which lets a payload that omits the key
  through while its own sibling gate refuses the identical shape.
* a webroot walk that returned NO files: there is nothing to prove
  pristine, and every core file would be snapshotted as ``absent`` — so an
  undo would delete the site.
* ``--to`` equal to the running version (nothing to do — "already
  current") or below it (WordPress cannot migrate a database backwards).
* a dirty or unreadable read of any in-scope file already in the tree:
  the installed core must match the OFFICIAL checksums of the version it
  claims to run before its files are replaced.  A tampered core is a
  compromise finding with its own fix path, and an update over it would
  bury that evidence under a fresh official tree.
* an unknown addition inside a replaced tree.  The lever the refusal
  names is the one that exists: ``wpt audit --only core.integrity``
  shows every one of them, and the file leaves the tree by hand.  It is
  NOT ``core_integrity.known_added``, whose signatures match a
  WEBROOT-ROOT ``*.php`` (name + content marker + size) and could never
  match a path inside ``wp-admin/`` or ``wp-includes/`` in the first
  place — naming a lever that cannot do the job is how an operator loses
  an update they could have run.  The refusal is the SAME shape for
  both drivers, and says what the CHOSEN driver would do to the file:
  the swap DELETES it with the tree, WordPress's own copy OVERWRITES it
  where the release ships that path (and leaves it standing everywhere
  else), so neither driver is a way out of the guard.

``apply`` — the mutation, in the order the guarantees need:

1. Every fact is re-derived exactly as the plan derived it (site facts
   over the bridge, the release zip, both checksum maps — all 1h-cached,
   so the second pass costs no new wp.org traffic), the derived file set
   must still equal the confirmed plan's, AND THE DRIVER MUST STILL BE
   THE ONE THE PLAN NAMED: a site that lost direct filesystem access
   between the two refuses the run instead of quietly getting the other
   mechanism.
2. The zip's own bytes are checked against the TARGET version+locale
   checksum map BEFORE anything is written: a mismatch means this
   download is not the distribution the map describes, and the run
   aborts with the site untouched.
3. The file half runs through the CHOSEN driver (see TWO DRIVERS above);
   under ``swap`` — each replacement TREE is staged beside the one it
   replaces (``wp-includes.wpt-new/``) and swapped with a RENAME per
   tree.  The rename is the point: a per-file rewrite of three thousand
   files can leave ``wp-includes/`` holding half of two releases when the
   transfer dies, and a rename cannot.

   THE SWAP IS ONE UNDO, NOT PER-TREE ONES.  Every name is handled by
   the same two-rename step — park what is installed, land what is
   staged — and every landed step is recorded, so a failure ANYWHERE in
   the write phase (the second tree, the ninth root file) is undone in
   reverse: the new name goes back to its staging name and the parked
   original comes back to the live one.  The alternative is the state a
   per-tree undo cannot see: ``wp-admin`` already swapped, ``wp-includes``
   not, old root files beside new ones, and ``.maintenance`` already
   lifted.  A root file gets the same treatment, which is why it is
   parked too — with only a temp-then-rename it had no predecessor to
   put back.

   ORDER is the kill-window argument.  Each pair is parked and landed back
   to back, so the ONLY instant at which a live name does not exist is
   between two adjacent renames, and exactly one pair is ever in flight.
   The old tree is NOT removed as the swap proceeds: it stays until the
   verify has passed, which is what makes a run that fails after the swap
   (a migration that did not reach its target, a digest that does not
   match) recoverable by hand as well as by snapshot.
4. ``.maintenance`` is engaged before the write and removed in a
   ``finally``: a crash, a deadline trip or a SIGTERM must never leave
   the site in maintenance.  Under the ``wordpress`` driver this is also
   what closes core's own reachable bad state — ``update_core()`` deletes
   the maintenance file on its SUCCESS route only, which is the "delete
   .maintenance over FTP" the documentation tells operators to do by
   hand.  WordPress's own 10-minute expiry on the
   file is the second line under that, not the first — and the file
   itself says what it is, so a site found in maintenance by a human
   is a site that says so.
5. The migration runs through the bridge's ``core_upgrade`` op — core's
   own ``require_once wp-admin/includes/upgrade.php; wp_upgrade();`` — so
   the schema target is the ``$wp_db_version`` of the core that request
   loaded (the one just swapped) and every ``upgrade_XX()`` routine in
   between runs.  Only when the target's schema version is ABOVE the
   installed one: ``wp_upgrade()`` is a documented no-op otherwise, and
   the comparison is ``>=`` on the release side because a site whose
   schema is already AHEAD of the target must never be refused (WordPress
   migrates forward only, and its own rule is
   ``db_version < $wp_db_version``).  What the migration PRINTED is kept
   and logged, and the op leaves a pre-migration marker in the options
   table, so the one failure that can report nothing at all — a
   non-catchable PHP fatal, which destroys the envelope — still leaves
   the operator the schema version the migration began in.  In LOCAL mode
   there is no bridge and no database in the stack: the rehearsal
   replaces the files and says so, exactly as every local db-mutating
   action refuses to run.
6. ``wp-content/`` and ``wp-config.php`` are never touched.  Neither is
   in the release's core surface — the file set is derived from the zip,
   which ships no ``wp-config.php`` and whose ``wp-content/`` entries are
   structurally out of scope — and no staging path, swap or root write
   can name a path outside it.  Under the ``wordpress`` driver core's own
   copy is what enforces it (``copy_dir()`` skips ``wp-content``
   wholesale and re-adds only NEW bundled items), and the plan's stale
   files — which core's copy never deletes — are removed by the tool.
7. The run's own residue is swept LAST, in the ``finally`` that covers
   every path above, so a failure anywhere still leaves no staging
   behind — and so does the residue of a run that was killed outright.
   The sweep is NAME-driven: the webroot-ROOT names through the one owner
   of that rule (``wpt.types.update_core_residue``) — staging trees and
   root temp files are removed, and a parked ``.wpt-old`` name is
   REPORTED with the live name it goes back to, never deleted, it being
   the last copy of the installed core and the operator's or the
   snapshot's to keep — and the two ``wp-content/`` shapes through this
   module's own rule: wpt's uploaded release package is removed (it is
   re-fetchable and web-served while it exists), while core's
   ``wp-content/upgrade/`` staging is only ever REPORTED, because on a
   site whose earlier core update died mid-copy it is the operator's
   recovery path.  A staging THIS run created is cleared after the verify
   passed and not before.  The same rules drive the report a later run
   prints, which is how a killed run becomes visible to the next command
   instead of staying invisible.

VERIFY AFTER WRITE — mandatory, never assumed (the SPEC's
verify-after-mutate rule).  A run that cannot prove its result is NOT
done: the registry answers rc 1 with the snapshot named as the rollback
and does not purge the cache.

* ``wp_version`` and ``db_version`` re-read from the DATABASE through a
  fresh ``info`` call (a different PHP process from the one that ran the
  migration) and required to be the target's pair — the values the
  database now holds, not the ones the migration intended.  Both arrive
  as JSON STRINGS on purpose (a stored option is not an int in PHP) and
  are normalized through the bridge client's own ``wire_int``, the one
  coercion of that shape in the tree.  The schema is required to be AT OR
  ABOVE the target, never equal: a site whose database was already ahead
  is a correct site, and refusing it would be the same defect as
  refusing it for being behind.
* the MySQL engine re-read in the same call and required to still meet
  the release's floor: the fact the refusal was made on is re-proved, not
  remembered.
* every replaced file re-hashed (``core_md5`` in bulk over the scope,
  batched at the bridge's own per-call cap; ``read_many``+md5 locally)
  and required to equal the target release's checksum map.
* the site root fetched and required to render (2xx), and the REST root
  fetched and required to answer without a server error — a
  plain-permalink install legitimately 404s ``/wp-json/``, while a 5xx
  there is the rewrite layer dying on a half-swapped core.
* the parked trees are discarded only now, and the registry then purges
  the page cache, like every other action.

LOCAL MODE: the plan runs against the zip; ``--apply`` is the
REHEARSAL — the same stage/swap/root-write sequence staged in the
``MutableZipSource`` overlay, so the materialized copy beside the
original IS an upgraded site an operator can serve and inspect, with
``wp-content/`` byte-identical and no ``.maintenance`` in the archive
(it is engaged during the swap and removed in the ``finally``).  The
original zip is the rollback; no snapshot is taken.

Logging: ``get_logger("actions.update_core")`` — one info per phase and
one warning per failed cleanup, the refusal lines are the action's own
``WptError`` messages (the registry logs them and writes the failure
report).  No secrets exist on this path: the wp.org fetches are public,
the bridge carries no credential, and nothing here reads one.
"""

from __future__ import annotations

import hashlib
import io
import re
import time
import zipfile
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import requests

from ..audit.data import _opt_str, _read_wp_version
from ..audit.integrity import (
    _CORE_MD5_BATCH,
    _fetch_comparison_checksums,
    _junk_demanded,
    resolve_core_locale,
)
from ..audit.updates import DEFAULT_WP_ORG, WpOrgApi, owned_session
from ..backup import _table_name_ok
from ..config import redact_text
from ..deadline import Deadline, bounded_walk, transport_kwargs
from ..log import get_logger
from ..php_probe import get_bounded
from ..report import Plan, human_bytes
from ..teardown import source_cleanup_budget
from ..types import (
    CORE_RETIRED_SUFFIX,
    CORE_STAGE_SUFFIX,
    CORE_TMP_SUFFIX,
    RESIDUE_OWNER,
    RESIDUE_RETIRED,
    BridgeError,
    DeadlineExceeded,
    Entry,
    PlanItem,
    RunControl,
    SourceError,
    WptError,
    update_core_residue,
)
from ..wpbridge.client import wire_core_upgrade_facts, wire_int
from .registry import register_action

if TYPE_CHECKING:
    from ..cli import Ctx
    from ..types import Source
    from ..wpbridge.client import Bridge

__all__ = ["UpdateCoreAction"]

log = get_logger("actions.update_core")

# ---------------------------------------------------------------------------
# Structural facts (NOT profile tunables — an operator makes no decision
# about any of them, and a knob for one is a knob the tool could be wrong
# about).  The only two policy knobs this action reads live in
# ``update.pre_release_allowed`` and ``update.maintenance``.
# ---------------------------------------------------------------------------

#: The trees a core release replaces, as webroot-relative directories.
#: Both are ``Source.PROTECTED`` names, which is why the rename that
#: lands a staged tree on one carries the audited ``allow_core`` unlock.
_CORE_TREES = ("wp-admin", "wp-includes")
_TREE_PREFIXES = tuple(f"{tree}/" for tree in _CORE_TREES)

#: The webroot-root file shape an update may replace: a top-level
#: ``*.php``.  A predicate, never a list of WordPress's top-level
#: filenames — that list is what goes stale every release, and the
#: [L18] lesson applies to the write side exactly as it did to the read
#: side.  A top-level non-PHP file (``license.txt``, ``readme.html``) is
#: the tool's junk policy's turf (``webroot_junk``), not an update's.
_ROOT_SUFFIX = ".php"

#: The staged copy of a tree being replaced, written BESIDE the live one
#: so the swap is one rename, and the name the installed core is parked
#: under while the new tree is verified.  Both are webroot-ROOT names, so
#: the one owner of the residue rule (``wpt.types.update_core_residue``)
#: can tell them apart from any file inside ``wp-content/`` that happens
#: to end in the same three characters.  Structural, not a tunable.
_STAGE_SUFFIX = CORE_STAGE_SUFFIX
_RETIRED_SUFFIX = CORE_RETIRED_SUFFIX

#: The temp name a root file is written under before its rename.  One
#: rename per file is what makes a truncated write harmless.
_TMP_SUFFIX = CORE_TMP_SUFFIX

#: The webroot-root file WordPress itself honours for maintenance mode.
#: Its content is core's own ``$upgrading = <time>;`` — the value
#: ``wp_is_maintenance_mode()`` compares against its 10-minute expiry —
#: followed by an explanatory body INSIDE the PHP tags, so the file a
#: human opens during a stuck swap tells them what is happening (and
#: prints nothing to a browser, because a file starting with ``<?php``
#: is executed, not served).
_MAINTENANCE = ".maintenance"

# --- the two drivers ------------------------------------------------------
#
# The two values ``update.driver`` can resolve to, plus the setting's own
# "ask the site" value.  Structural names, not tunables: the setting is
# the tunable, and ``wpt.settings.UPDATE_DRIVERS`` is the single owner of
# the accepted set (the door that validates it is the settings section's
# own ``__post_init__``).

_DRIVER_SWAP = "swap"
_DRIVER_WORDPRESS = "wordpress"
# ``"auto"`` (the shipped setting value) needs no constant here: it is the
# one value that resolves to one of the two, and the accepted set is
# validated once, at the load door, by wpt.settings.UPDATE_DRIVERS.

#: Where the release zip the ``wordpress`` driver hands to core's own
#: updater is uploaded.  DELIBERATELY NOT ``wp-content/upgrade/``: core's
#: ``unpack_package()`` WIPES that directory on its way in, so a package
#: parked there would be deleted before it was read — and so would any
#: staging an earlier, interrupted core update left there, which is a
#: recovery path and not wpt's to sweep.  This is wpt's own upload
#: directory: re-fetchable from wp.org, web-served while it exists (so the
#: sweep removes it), and named by the residue report until then.
_PACKAGE_DIR = "wp-content/wpt-update"

#: The release package's name, core's own convention (``WP_Upgrader::
#: unpack_package()`` derives the staging directory from it, so
#: ``wordpress-7.1.2.zip`` stages into ``wp-content/upgrade/wordpress-7.1.2``
#: exactly as it would from wordpress.org).
_PACKAGE_NAME = "wordpress-{version}.zip"


def _package_path(version: str) -> str:
    """The webroot-relative path the release package is uploaded to."""
    return f"{_PACKAGE_DIR}/{_PACKAGE_NAME.format(version=version)}"


#: Core's OWN staging directory (``wp-content/upgrade/``), where
#: ``WP_Upgrader::unpack_package()`` extracts the release.  Not wpt's to
#: sweep: it is core's, and on a site whose earlier core update died
#: mid-copy it is the operator's recovery path.  Named by the residue
#: report with its owner, and cleared only by a VERIFIED run that created
#: it (see ``_clear_own_staging``).
_STAGING_DIR = "wp-content/upgrade"

#: The two ``wp-content/`` residue roles, owned HERE rather than in
#: ``wpt.types`` because the shared rule is deliberately webroot-ROOT-only
#: (a path with a directory component is somebody else's file) and these
#: two are, by construction, inside ``wp-content/``.
RESIDUE_STAGING = "staging"
RESIDUE_PACKAGE = "package"

#: Who owns each of them — the same shape as ``wpt.types.RESIDUE_OWNER``,
#: which owns the three ROOT roles the report also reads.
CORE_UPGRADE_OWNER: dict[str, str] = {
    RESIDUE_STAGING: (
        "WordPress's own staging directory, and on a site whose earlier "
        "core update did not finish it is the recovery path — the operator "
        "or `wpt restore --undo-last` owns it; `wpt update-core` clears it "
        "only for a staging it created itself once its verify has passed"),
    RESIDUE_PACKAGE: (
        "wpt's own uploaded copy of the release zip — re-fetchable from "
        "wp.org and web-served while it exists, so the sweep removes it; "
        "nothing reads it if it survives"),
}


#: The numeric PREFIX of a version, for ORDER: ``6.8.3`` -> 6.8.3,
#: ``6.9-RC1`` -> 6.9, ``7.2-alpha-59000`` -> 7.2.  A pre-release orders
#: by the series it belongs to, which is the only ordering WordPress
#: itself speaks (``version_compare("6.9-RC1", "6.8.3", ">")`` is true).
_ORDER_PREFIX_RE = re.compile(r"\d+(?:\.\d+)*")

#: A plain RELEASE version: two or three dot-separated numbers.  Anything
#: else — ``6.5-RC1``, ``7.0-beta2``, ``6.8-alpha-57000`` — is a
#: PRE-RELEASE, and it is one because of its SHAPE, not because it is on
#: a list of suffixes someone forgot to extend.
_RELEASE_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?")

#: The REST root the verify probes, relative to the site URL: WordPress's
#: own REST index, where a rewrite failure after a core swap shows up.
_REST_PATH = "/wp-json/"

#: How many paths one refusal line names before it counts the rest.  A
#: refusal that listed four thousand paths would be a log flood, not a
#: diagnosis.  Structural (presentation), like the audit's _DETAIL_PATHS.
_REFUSAL_PATHS = 3


# --------------------------------------------------------------- primitives


def _is_release_version(version: str) -> bool:
    """True for a plain ``X.Y[.Z]`` release (never an RC/beta/alpha)."""
    return bool(isinstance(version, str)
                and _RELEASE_VERSION_RE.fullmatch(version))


def _version_tuple(version: str) -> tuple[int, ...] | None:
    """A dotted version as ints, or None when it is not one.

    For the comparison that must be numeric (installed vs target, live PHP
    vs the release's floor).  A non-numeric component (``8.2.12-dev``)
    makes the WHOLE answer None: a compare against a partially-parsed
    version is a guess, and every caller here treats None as "refuse",
    never as "close enough".
    """
    if not isinstance(version, str) or not version.strip():
        return None
    parts = version.strip().split(".")
    if not parts or not all(part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)


def _order_tuple(version: str) -> tuple[int, ...] | None:
    """The LEADING numeric components of a version, for ORDER only.

    ``6.9-RC1`` orders as ``(6, 9)``: a release candidate of 6.9 is newer
    than 6.8.3, and refusing it as "not comparable" would refuse the very
    target the ``--allow-pre-release`` door exists to allow.  Everything
    after the first non-numeric component is dropped, so this answers
    "which series is newer" and NOTHING else — in particular it cannot say
    whether two versions of the SAME series differ, which is why
    :meth:`UpdateCoreAction._refuse_not_newer` still reads the full string
    to tell "already current" from "not newer".
    """
    if not isinstance(version, str) or not version.strip():
        return None
    match = _ORDER_PREFIX_RE.match(version.strip())
    if match is None:
        return None
    return tuple(int(part) for part in match.group(0).split("."))


def _version_at_least(have: str, want: str) -> bool | None:
    """``have >= want`` for two dotted versions; None if either is unparsable.

    A MISSING component is a floor, not a mismatch: PHP's minimum
    ``7.4`` and a site on ``8.2`` compare as ``(8, 2) >= (7, 4)``, so the
    tuples are zero-padded to a common width first.
    """
    a, b = _version_tuple(have), _version_tuple(want)
    if a is None or b is None:
        return None
    width = max(len(a), len(b))
    return (a + (0,) * (width - len(a))) >= (b + (0,) * (width - len(b)))


def _engine_tuple(version: str) -> tuple[int, ...] | None:
    """The leading dotted numbers of a DATABASE ENGINE answer, or None.

    ``wpdb->db_version()`` is a string that carries a vendor suffix on
    real hosts — ``10.6.18-MariaDB``, ``5.7.42-log``, ``8.0.36`` — and the
    suffix is exactly what makes a naive ``str.split('.')`` refuse a
    perfectly good engine.  Everything from the first non-numeric
    component on is dropped, which keeps the numbers comparable and drops
    nothing a floor comparison needs.
    """
    if not isinstance(version, str) or not version.strip():
        return None
    head = re.split(r"[^0-9.]+", version.strip(), maxsplit=1)[0]
    return _version_tuple(head)


def _named_paths(paths: list[str], total: int | None = None) -> str:
    """Up to _REFUSAL_PATHS paths, then the count of the rest."""
    total = len(paths) if total is None else total
    shown = paths[:_REFUSAL_PATHS]
    rest = total - len(shown)
    return ", ".join(shown) + (f" (+{rest} more)" if rest > 0 else "")


def _driver_precondition_gap(site: _Site) -> str | None:
    """Why the ``wordpress`` driver is unavailable here, or None.

    The ONE place the two preconditions are read, so the plan's reason, a
    refusal's reason and the apply-time re-derivation cannot disagree
    about what a site can do.  None means "WordPress's own updater can be
    driven here"; a string names the gap, and it is written for an
    operator reading a refusal, not for a machine.
    """
    if site.filesystem_method != "direct":
        method = site.filesystem_method or "unreadable"
        return (f"the filesystem method is {method}, and only `direct` can be "
                f"driven without an interactive credential prompt")
    if not site.zip_library:
        return ("this PHP reports neither ZipArchive nor core's bundled "
                "PclZip, so core's own unzip_file() cannot extract the "
                "release")
    return None


def _addition_destiny(driver: str) -> str:
    """What the CHOSEN driver does to an unknown addition, in one clause.

    The two drivers destroy one differently — the swap takes the whole
    tree with the file in it, WordPress's own ``copy_dir()`` overwrites
    the file wherever the release ships that path — so the refusal the
    operator reads has to name the one that would actually happen to
    their files.
    """
    if driver == _DRIVER_WORDPRESS:
        return ("WordPress's own copy would OVERWRITE each of them wherever "
                "the release ships that path (and leave the rest standing), "
                "and")
    return "replacing the tree would DELETE them, and"


def _maintenance_bytes() -> bytes:
    """The maintenance file's bytes: core's own line, plus a body a human
    can read.

    ``<?php $upgrading = <time>; ?>`` is byte-for-byte what
    ``WP_Upgrader::maintenance_mode()`` writes, and it is the whole
    functional content: ``wp_is_maintenance_mode()`` includes the file and
    compares ``$upgrading`` against a 10-minute window, so the file both
    engages maintenance and self-expires.  What it is NOT is a
    diagnosis — a site sitting in maintenance with a ten-line PHP fragment
    and no explanation is the outage WordPress's own fatal would have
    named.  So the body is appended INSIDE the tags, where it is a comment
    to PHP and nothing at all to a browser.
    """
    return (
        f"<?php $upgrading = {int(time.time())}; "
        "/* wpt update-core: this site is mid core update. The core files "
        "are being swapped and the database is being migrated. The file is "
        "removed when the run ends; WordPress expires it 10 minutes after "
        "the timestamp above. If it is still here, `wpt update-core` or "
        "`wpt doctor` reports what the run left behind. */ ?>"
    ).encode()


# ------------------------------------------------------------------- facts


@dataclass(frozen=True)
class _Site:
    """The installed site's own facts, as an update needs them.

    ftp: ONE ``info`` call, with the audit's wire-tolerance helper
    ``_opt_str`` for the strings, so a missing/empty/non-string field is
    None rather than a value this action would compare.  local: the
    version from ``wp-includes/version.php`` through the source (the
    gather's own seam) and nothing else — an offline zip has no
    database, no running PHP and no server, so ``db_version``, ``php``,
    ``mysql`` and ``multisite`` stay None and every check that needs one
    says it cannot be evaluated rather than assuming it.

    ``filesystem_method`` / ``zip_library`` are the ``wordpress``
    driver's two preconditions, asked for in the SAME call
    (``info`` with ``core_upgrade=1``, the only way to get them without
    paying for the filesystem ownership probe on every audit's ``info``)
    and normalized through the bridge client's own reader.  ``""`` means
    UNKNOWN-or-unusable, which the driver selection reads as "not
    available here" — the direction that keeps every site updatable
    through the driver that needs no precondition at all.
    """

    version: str
    locale: str = ""
    db_version: int | None = None
    php: str | None = None
    mysql: str | None = None
    multisite: bool | None = None
    filesystem_method: str = ""
    zip_library: str = ""


@dataclass(frozen=True)
class _Driver:
    """The driver this run WOULD use, and why — the plan's first fact.

    Named, never inferred later: a plan that says ``wordpress`` and an
    apply that runs ``swap`` is a run nobody confirmed, so the two are
    compared before the write (see :meth:`UpdateCoreAction.apply`).
    """

    name: str
    why: str


@dataclass(frozen=True)
class _Offer:
    """The target's normalized version-check offer, with its two floors."""

    version: str
    php_floor: str = ""
    mysql_floor: str = ""


@dataclass(frozen=True)
class _Release:
    """The target release, as the official distribution describes itself.

    ``files`` is ``webroot-relative path -> official size`` for every
    core file the release ships, derived from the zip's own namelist (see
    :func:`_release_files`); ``bytes`` is their sum.  ``db_version`` and
    ``wp_version`` are the two globals the release's own
    ``wp-includes/version.php`` declares: the schema version the
    migration will make the database, and the version the new tree
    reports afterwards.
    """

    version: str
    locale: str
    files: dict[str, int]
    bytes: int
    db_version: int
    wp_version: str


@dataclass(frozen=True)
class _ReadBack:
    """What the pre-write read-back found in the two replaced trees.

    ``present``: the in-scope files already installed — the ones the swap
    REPLACES (and whose bytes the snapshot must hold).
    ``stale``: files inside the replaced trees that the INSTALLED release
    shipped and the TARGET does not.  Swapping a whole tree removes them,
    so they are planned (with ``bytes_est=0``: nothing is written for
    them) and snapshotted — otherwise ``wpt restore --undo-last`` could
    not bring back a file the update deleted, which is the one thing a
    rollback has to do.
    ``junk``: files inside the replaced trees that the tool's OWN
    ``webroot_junk`` policy deletes.  Not planned and not refused: the
    swap removing them is the outcome ``clean-files`` would produce
    anyway, and refusing on them would make every update impossible on a
    site carrying ``wp-admin/error_log``.
    """

    present: tuple[str, ...] = ()
    stale: tuple[str, ...] = ()
    junk: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Derived:
    """Everything both phases derive from one target, computed ONCE.

    The apply re-derives it from the live site and wp.org rather than
    trusting the printed Plan (heal-core's discipline); carrying it in a
    value object is what keeps the re-derivation from being a second,
    subtly different code path.
    """

    site: _Site
    offer: _Offer
    release: _Release
    target_map: dict[str, str]
    zip_bytes: bytes
    #: What the pre-write read-back found (see :class:`_ReadBack`).
    read_back: _ReadBack
    #: The driver this run would use, and why (see :class:`_Driver`).
    driver: _Driver


# -------------------------------------------------------------- the sources


def _site_facts(source: "Source", bridge: "Bridge | None", *,
                core_upgrade: bool = False,
                deadline: "Deadline | None" = None) -> _Site:
    """The installed site's facts (see :class:`_Site`).

    The version is the update's only anchor — both checksum maps and the
    release zip are version-pinned — so the caller refuses an empty one;
    it is never guessed.

    THE SCHEMA VERSION IS A WIRE STRING, and that is the bridge's
    deliberate choice: a stored options row is not an int in PHP, so
    ``info`` casts ``db_version`` to a string and every consumer has to
    cope.  It is normalized here through the bridge CLIENT's own
    ``wire_int`` — the single coercion of that shape in the tree, already
    used for the same fact on the ``core_upgrade`` answer.  Demanding an
    ``int`` instead does not "fail loudly": it yields ``None``, and every
    gate that reads ``None`` as "unknown" then refuses a site that was
    updated correctly — the schema comparison can never be made, so the
    run reports NOT-done on a successful update.  ``multisite`` is
    normalized the same way, and a payload that carries no usable value
    at all stays ``None`` (a fact to refuse on, not one to assume).
    """
    if bridge is None:
        return _Site(version=_read_wp_version(source) or "")
    info = bridge.call(
        "info",
        **transport_kwargs(deadline),
        **({"core_upgrade": True} if core_upgrade else {}))
    db_version = wire_int(info.get("db_version"))
    multisite = info.get("multisite")
    facts = wire_core_upgrade_facts(info)
    return _Site(
        version=_opt_str(info.get("wp_version")) or "",
        locale=_opt_str(info.get("locale")) or "",
        db_version=(db_version if db_version is not None and db_version > 0
                    else None),
        php=_opt_str(info.get("php_version")),
        mysql=_opt_str(info.get("mysql_version")),
        multisite=multisite if isinstance(multisite, bool) else None,
        filesystem_method=facts["filesystem_method"],
        zip_library=facts["zip_library"],
    )


def _release_files(zip_bytes: bytes, junk: set[str],
                   prefix: str | None = None) -> dict[str, int] | None:
    """``webroot-relative path -> size`` for the core files a release ships.

    Derived from the zip on every run: an entry under ``wp-admin/`` or
    ``wp-includes/``, or a webroot-root ``*.php``.  ``wp-content/``
    (themes, plugins, uploads) is structurally excluded — it is under
    neither tree and is not at the root — which is why an update can
    never touch it.

    ``junk`` subtracts the paths this tool's own ``webroot_junk`` policy
    DELETES, read through integrity's own subtraction
    (:func:`_junk_demanded`) so the audit, the heal and the update cannot
    disagree: a release ships ``wp-config-sample.php``, ``clean-files``
    deletes it, and an update that wrote it back would make
    ``webroot.junk`` flag it again on the next audit — the [L19] loop, one
    level up from a heal.

    None when the zip cannot be opened or carries no core file at all: a
    corrupt download is a failed fetch, never an empty plan.
    """
    out: dict[str, int] = {}
    prefix = prefix if prefix is not None else DEFAULT_WP_ORG.release_zip_prefix
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            for info in zf.infolist():
                name = info.filename
                if name.endswith("/") or not name.startswith(prefix):
                    continue
                path = name[len(prefix):]
                if not path or path in junk:
                    continue
                under_tree = any(path.startswith(f"{tree}/")
                                 for tree in _CORE_TREES)
                at_root = "/" not in path and path.endswith(_ROOT_SUFFIX)
                if under_tree or at_root:
                    out[path] = info.file_size
    except (OSError, ValueError, EOFError, RuntimeError, zipfile.BadZipFile):
        return None
    return out or None


def _release_version_php(zip_bytes: bytes,
                         prefix: str | None = None) -> bytes | None:
    """The release's own ``wp-includes/version.php`` bytes, or None."""
    prefix = prefix if prefix is not None else DEFAULT_WP_ORG.release_zip_prefix
    name = f"{prefix}wp-includes/version.php"
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            return zf.read(name) if name in zf.namelist() else None
    except (OSError, ValueError, EOFError, RuntimeError, zipfile.BadZipFile):
        return None


def _declares_int(source: bytes, name: str) -> int | None:
    """The int a ``version.php`` declares in ``$<name>``; None otherwise."""
    match = re.search(rf"\${name}\s*=\s*'?(\d+)'?\s*;",
                      source.decode("utf-8", errors="replace"))
    return int(match.group(1)) if match else None


def _declares_str(source: bytes, name: str) -> str | None:
    """The string a ``version.php`` declares in ``$<name>``; None otherwise."""
    match = re.search(rf"\${name}\s*=\s*'([^']*)'\s*;",
                      source.decode("utf-8", errors="replace"))
    return match.group(1) if match else None


def _junk_paths(ctx: "Ctx", paths: list[str]) -> list[str]:
    """Which of ``paths`` this tool's own junk policy DELETES.

    Read through ``wpt.audit.webroot``'s own predicate, the same
    ``junk_file_matches`` integrity's ``_junk_demanded`` sits on, so "is
    this junk" has one answer in the tree.  The import is deferred
    because webroot imports integrity, which imports this module's
    siblings — the same cycle integrity documents for that call.
    """
    from ..audit.webroot import junk_file_matches

    if not paths or not ctx.settings.webroot_junk:
        return []
    return sorted(
        entry.path
        for entry, _pattern in junk_file_matches(
            [Entry(path=path, is_dir=False, size=0) for path in paths],
            list(ctx.settings.webroot_junk),
        )
    )


def _newer_than(version: str, base: tuple[int, ...] | None) -> bool:
    """Is ``version`` in a strictly newer series than ``base``?"""
    there = _order_tuple(version)
    if there is None or base is None:
        return False
    width = max(len(there), len(base))
    return (there + (0,) * (width - len(there))) > (
        base + (0,) * (width - len(base)))


def _staging_path(path: str) -> str:
    """``wp-includes/x.php`` -> ``wp-includes.wpt-new/x.php``.

    The staged path is deliberately OUTSIDE the protected surface, so the
    staging writes need no ``allow_core`` unlock: the audited unlock is
    spent once, on the rename that actually lands the tree.
    """
    tree, _, rest = path.partition("/")
    return f"{tree}{_STAGE_SUFFIX}/{rest}"


# ---------------------------------------------------------------- the action


class UpdateCoreAction:
    """The plan/apply pair; ``stack`` is the registry-built source trio
    (ftp: ``(source, session, bridge)``; local: ``(source, None, None)``
    — a None bridge IS the local shape every branch keys on)."""

    #: The driver the last :meth:`plan` named, re-checked by
    #: :meth:`apply`.  Instance state, not Plan state, because a Plan is a
    #: printed, rebuildable artifact (items and table names) and cannot
    #: carry the fact — the registry drives both phases on THIS object, so
    #: the value cannot be lost between them.
    _planned_driver: str | None = None

    # ------------------------------------------------------------------ plan

    def plan(self, ctx: "Ctx", stack: tuple) -> Plan:
        source, _session, bridge = stack
        # The walk runs BEFORE the first bridge call (the gather's
        # discipline): the bridge lazy-deploys on its first call, and the
        # tree this run reads must be the site's, not wpt's own
        # bridge-<8hex>.php.
        entries = list(bounded_walk(
            source, Deadline.from_ctx(ctx), "update-core walk"))
        files = {e.path: e for e in entries if not e.is_dir}
        # The residue report runs on EVERY plan, with or without a
        # target: a run that was killed between two renames leaves a
        # webroot no check names, and the next command an operator runs
        # about that update is this one.  It is a REPORT — never a
        # refusal, never a mutation — and it is built on the same walk.
        _report_residue(entries)
        # The DRIVER's two preconditions ride the same call: they are asked
        # for here (``core_upgrade=1``) and nowhere else, so an audit's
        # plain ``info`` never pays for the filesystem ownership probe.
        site = _site_facts(source, bridge, core_upgrade=True,
                           deadline=Deadline.from_ctx(ctx))
        if not site.version:
            raise WptError(
                "unknown WordPress version — cannot plan an update (both "
                "the checksum basis and the release are version-pinned); "
                "refusing to guess"
            )
        target = _requested_target(ctx)
        if target is None and ctx.apply:
            # An APPLY with no target is a refusal, not an empty plan: the
            # registry would otherwise snapshot nothing, write nothing and
            # exit 0, and the operator would have a green run that never
            # chose a version.  The report-only path below is the honest
            # reading of the same missing flag.
            raise WptError(
                "update-core --apply requires --to X.Y.Z: the target "
                "version is never implicit (run `wpt update-core` with no "
                "--to to see what wp.org offers, then name one)"
            )
        if target is None:
            # No target: the read-only report, and an EMPTY plan. A Plan
            # is a list of files; without a target there is no honest
            # file list, and inventing one is the thing this action
            # exists not to do.
            self._report_offers(_offers(ctx, stack), site)
            # backup_tables=[] deliberately: an empty plan claims no
            # snapshot scope, so the table discovery (a db_audit call) is
            # not spent on a run that plans nothing.
            return Plan(items=[], backup_tables=[])
        derived = self._derive(ctx, stack, files, site, target)
        # The registry calls .plan() and .apply() on THIS instance, so the
        # plan's driver is remembered here and re-checked in the apply
        # (a Plan is a printed artifact: it cannot carry the fact itself).
        self._planned_driver = derived.driver.name
        tables = self._snapshot_tables(bridge, Deadline.from_ctx(ctx))
        self._announce(derived, maintenance=bool(ctx.settings.update.maintenance),
                       tables=tables)
        return Plan(items=self._items(derived), backup_tables=tables)

    def _snapshot_tables(self, bridge: "Bridge | None",
                         deadline: "Deadline | None" = None) -> list[str]:
        """The database tables the pre-action snapshot must capture.

        EVERY table, discovered through the bridge's own ``db_audit`` and
        validated at this trust boundary with backup's own table-name
        rule: a payload that is not a list of dicts with one disk-safe
        name each is a refusal, because a name that reached the snapshot
        machinery unchecked would be a name it writes to disk.  Local mode
        has no bridge and therefore no database in the stack: the list is
        empty and the plan says so.
        """
        if bridge is None:
            return []
        raw = bridge.call(
            "db_audit", **transport_kwargs(deadline)).get("tables")
        if (not isinstance(raw, list)
                or not all(isinstance(t, dict) and _table_name_ok(t.get("name"))
                           for t in raw)):
            raise WptError(
                "db_audit returned an unusable tables list — the "
                "pre-action snapshot cannot be scoped to the database, so "
                "nothing can be applied"
            )
        return sorted({t["name"] for t in raw})

    def _items(self, derived: _Derived) -> list[PlanItem]:
        """One PlanItem per replaced file, plus the files the swap REMOVES.

        The replaced files carry the release's OWN size (not the installed
        one): this plan estimates what the update WRITES, and a file the
        target creates has no installed size to read.

        The stale files — inside the two replaced trees, shipped by the
        installed release and dropped by the target — carry
        ``bytes_est=0`` and a different detail, because they are DELETED
        rather than written and must not inflate the write estimate.  They
        are items for the one reason that matters: the registry derives
        the pre-action snapshot's file scope from exactly this list, so a
        file the swap removes is captured, and ``wpt restore --undo-last``
        can bring it back.  A rollback that cannot undo a deletion is not a
        rollback.
        """
        release = derived.release
        return sorted(
            [PlanItem(
                category="update.core",
                target=path,
                detail=(f"replace with the official WordPress "
                        f"{release.version} {release.locale} file"),
                bytes_est=size,
            )
             for path, size in release.files.items()]
            + [PlanItem(
                category="update.core",
                target=path,
                detail=(
                    f"not shipped by WordPress {release.version} — "
                    + (
                        "removed explicitly by the wordpress driver after "
                        "core's copy (core never deletes it)"
                        if derived.driver.name == _DRIVER_WORDPRESS
                        else "removed with the replaced core tree it lives in"
                    )),
                bytes_est=0,
            )
               for path in derived.read_back.stale],
            key=lambda item: item.target,
        )

    # -------------------------------------------------------- the derivation

    def _derive(self, ctx: "Ctx", stack: tuple, files: dict[str, Entry],
                site: _Site, target: str) -> _Derived:
        """Every refusal, then every derived fact, for ``target``.

        The shared body of both phases: the plan runs it to print, the
        apply runs it again before it writes (a Plan is a printed,
        rebuildable artifact, and the site can change under it), so an
        apply can never act on a basis the plan did not prove.
        """
        self._refuse_empty_walk(files)
        session, timeout_s = _wporg_transport(ctx, stack)
        bridge = stack[2]
        allow_pre_release = _allow_pre_release(ctx)
        with owned_session(session, stack[2] is None):
            # ONE offer list, read twice: the "is it offered / is it a
            # pre-release" refusal and the floors come from the same answer,
            # so a decision and the numbers it was made on can never be two
            # different fetches.
            offers = _offers(ctx, stack)
            self._refuse_unoffered(offers, target, allow_pre_release)
            self._refuse_install_shape(site, allow_pre_release)
            self._refuse_not_newer(site.version, target)
            offer = _offer_for(offers, target)
            if bridge is not None:
                self._refuse_php_floor(offer, site)
                self._refuse_mysql_floor(offer, site)
                self._refuse_multisite(site)
            # The driver, before the release is even fetched: a driver this
            # site cannot run is a refusal, and a refusal that costs tens of
            # megabytes of download to reach is a refusal in the wrong place.
            driver = self._choose_driver(ctx, site, bridge)
            release, target_map, zip_bytes = self._release(
                ctx, stack, site, target, session, timeout_s)
            read_back = self._read_back(ctx, stack, files, site, release,
                                        session, timeout_s, driver)
        return _Derived(site=site, offer=offer, release=release,
                        target_map=target_map, zip_bytes=zip_bytes,
                        read_back=read_back, driver=driver)

    def _choose_driver(self, ctx: "Ctx", site: _Site,
                       bridge: "Bridge | None") -> _Driver:
        """Which driver this run would use, and why — the plan's first fact.

        ``update.driver`` names one outright or asks the site
        (``auto``, the shipped default).  The question ``auto`` asks is
        exactly the two preconditions WordPress's own extractor has, read
        from the RUNNING site over the bridge: a ``direct`` filesystem
        method (every other one makes core's upgrader block on an
        interactive credential prompt a bridge endpoint cannot answer) and
        a zip library (core falls through ZipArchive to its bundled
        PclZip; with neither, ``unzip_file()`` cannot extract a release).

        The fallback direction is the point: the swap driver needs NEITHER
        precondition, so an unreadable fact, a method core cannot use and
        a PHP without a zip library all resolve to ``swap`` rather than to
        a refusal.  A driver the operator named outright and the site
        cannot run DOES refuse — silently running the other mechanism
        would be a run whose plan nobody confirmed.
        """
        asked = ctx.settings.update.driver
        if asked == _DRIVER_SWAP:
            return _Driver(
                _DRIVER_SWAP,
                "the profile names the swap driver (update.driver=swap): it "
                "needs no filesystem method and no zip library, so it runs "
                "anywhere this action can write",
            )
        if bridge is None:
            if asked == _DRIVER_WORDPRESS:
                raise WptError(
                    "update.driver=wordpress cannot run here: this mode has "
                    "no running PHP — there is no WordPress to drive, and an "
                    "offline zip has nothing to drive it with. Run it against "
                    "the live site, or set update.driver=swap (the swap "
                    "rehearses the same sequence into the copy)"
                )
            return _Driver(
                _DRIVER_SWAP,
                "this mode has no running PHP, so there is no WordPress to "
                "drive; the swap rehearses the same sequence into the copy",
            )
        missing = _driver_precondition_gap(site)
        if missing is not None:
            if asked == _DRIVER_WORDPRESS:
                raise WptError(
                    f"update.driver=wordpress cannot run on this site: "
                    f"{missing} — WordPress's own updater cannot be driven "
                    f"there, and starting a core update it cannot finish is "
                    f"worse than not starting it. Set "
                    f"update.driver=swap (the swap needs neither), or fix "
                    f"the host and re-run the plan"
                )
            return _Driver(
                _DRIVER_SWAP,
                f"the site does not meet WordPress's own extractor "
                f"preconditions ({missing}), and the swap needs neither — "
                f"set update.driver=wordpress to force the refusal",
            )
        return _Driver(
            _DRIVER_WORDPRESS,
            f"the site reports a {site.filesystem_method} filesystem and "
            f"{site.zip_library}, the two preconditions WordPress's own "
            f"updater has; the run drives core's own extractor and copy "
            f"with attempt_rollback armed",
        )

    def _refuse_empty_walk(self, files: dict[str, Entry]) -> None:
        """A webroot walk that returned NOTHING refuses the run.

        The empty walk is not "a site with no core": it is a walk that
        measured nothing — a dead channel that answered empty, a webroot
        that moved, a zip that is not the site's — and every downstream
        gate reads it as the first and most dangerous thing it can read.
        The pristine proof has no file to prove; the plan then lists every
        core file as ``present`` nowhere, so the pre-action snapshot
        records each of them ABSENT, and ``wpt restore --undo-last`` on
        that snapshot DELETES the installed core.  A gate that fails open
        on an unmeasured input is not a gate.
        """
        if files:
            return
        raise WptError(
            "cannot update: the webroot walk returned NO files, so the "
            "installed core cannot be proven pristine and every core file "
            "would be snapshotted as absent (an undo would then delete the "
            "site) — refusing on an unmeasured webroot; re-run `wpt walk` "
            "or `wpt doctor` to see whether the site is there at all"
        )

    # ---- the target's release

    def _release(self, ctx: "Ctx", stack: tuple, site: _Site, target: str,
                 session: requests.Session, timeout_s: int
                 ) -> tuple[_Release, dict[str, str], bytes]:
        """(release, its checksum map, its zip bytes) for ``target``.

        ONE basis, chosen once: the target's checksum map is fetched
        first (it is the cheap half — a missing map is a refusal long
        before tens of megabytes move), and the release zip is then
        fetched at whatever locale that map came from.  So the bytes that
        will be installed and the map they will be proven against can
        never sit on two different builds, and the [L17] localized migration
        lesson cannot recur one level up: the install basis is the same
        ``resolve_core_locale`` basis the AUDIT compares against, and
        when wp.org has no build of this version for the site's locale the
        en_US fallback carries BOTH halves (heal-core's precedent) and
        every fact below then names en_US.
        """
        source = stack[0]
        wp_org = ctx.settings.wp_org
        wanted = resolve_core_locale(
            source, site.locale or None, wp_org.default_locale)
        target_map, locale = _fetch_comparison_checksums(
            target, session, timeout_s, wanted,
            deadline=Deadline.from_ctx(ctx), config=wp_org)
        if target_map is None:
            raise WptError(
                f"cannot update: wp.org checksums for WordPress {target} "
                f"are unavailable at the {wanted} build (and nothing valid "
                "is cached) — there is no verification basis, and an update "
                "is never reported without its proof; refusing"
            )
        if locale != wanted:
            log.warning(
                "update-core: wp.org has no %s build of WordPress %s — the "
                "release and its checksums are both taken from the en_US "
                "build", wanted, target,
            )
        zip_bytes = WpOrgApi(
            session, timeout_s,
            deadline=getattr(Deadline.from_ctx(ctx), "at", None),
            config=wp_org,
        ).fetch_core_release_zip(target, locale)
        if zip_bytes is None:
            raise WptError(
                f"cannot update: the official WordPress {target} {locale} "
                "release zip is unavailable — refusing to install a core "
                "from any other source"
            )
        files = _release_files(
            zip_bytes, _junk_demanded(target_map, ctx.settings.webroot_junk),
            wp_org.release_zip_prefix)
        if not files:
            raise WptError(
                f"cannot update: the official WordPress {target} {locale} "
                "release carries no core file (nothing under wp-admin/ or "
                "wp-includes/, no root *.php) — refusing to install from "
                "an unrecognized distribution"
            )
        version_php = _release_version_php(
            zip_bytes, wp_org.release_zip_prefix)
        db_version = (_declares_int(version_php, "wp_db_version")
                      if version_php else None)
        declared = (_declares_str(version_php, "wp_version")
                    if version_php else None)
        if db_version is None or not declared:
            raise WptError(
                f"cannot update: the official WordPress {target} {locale} "
                "release declares no readable $wp_db_version / $wp_version "
                "in wp-includes/version.php — the migration target would "
                "be unknown; refusing"
            )
        if declared != target:
            raise WptError(
                f"cannot update: the release fetched as {target} declares "
                f"$wp_version = {declared} — refusing to install bytes that "
                "are not the version asked for"
            )
        release = _Release(version=target, locale=locale, files=files,
                           bytes=sum(files.values()), db_version=db_version,
                           wp_version=declared)
        return release, target_map, zip_bytes

    # ---- the refusals

    def _refuse_unoffered(self, offers: list[dict[str, Any]], target: str,
                          allow_pre_release: bool) -> None:
        """A target wp.org does not offer, or offers as a pre-release.

        One wp.org list decides both what exists and what its floors are,
        so a hand-typed version that is not on it is never fetched on the
        assumption that it is real.  A pre-release offer (by the
        version's shape) needs ``--allow-pre-release`` or the profile's
        ``update.pre_release_allowed``.
        """
        offered = {v for raw in offers
                   for v in (raw["version"], raw["current"]) if v}
        if target not in offered:
            wanted = ", ".join(sorted(offered)[:_REFUSAL_PATHS])
            raise WptError(
                f"refusing to update to WordPress {target}: wp.org does "
                f"not offer that version (it offers {wanted}, …) — there "
                f"is nothing official to install; pick one of those with "
                f"--to"
            )
        if not _is_release_version(target) and not allow_pre_release:
            raise WptError(
                f"refusing to update to {target}: that is a PRE-RELEASE "
                f"(not a plain X.Y[.Z] release) — pass "
                f"--allow-pre-release (or set "
                f"update.pre_release_allowed=true) if it is really the "
                f"target"
            )

    def _refuse_install_shape(self, site: _Site,
                              allow_pre_release: bool) -> None:
        """A dev/beta/RC INSTALL is refused without the same flag.

        Distinct from a pre-release TARGET: this is the version the site
        RUNS.  A trunk checkout (``$wp_version = '7.2-alpha-59000'``) is
        not a release, no official release zip describes the bytes it
        runs, and its schema is whatever the checkout carries — installing
        a release over it guesses at both halves of the state.
        """
        if allow_pre_release or _is_release_version(site.version):
            return
        raise WptError(
            f"refusing to update a site running WordPress {site.version}: "
            "that is a development build (dev/beta/RC), not a release, and "
            "no official release describes the files it runs — pass "
            "--allow-pre-release (or set "
            "update.pre_release_allowed=true) if this is deliberate"
        )

    def _refuse_not_newer(self, current: str, target: str) -> None:
        """``--to`` at or below the running version is refused.

        Equal: there is nothing to do, and the words say so — a second
        run of the same command must read as a no-op, not as a failure of
        the tool.  Below, or the same series: WordPress has no downgrade
        path (``wp_upgrade()`` only ever moves ``db_version`` forward),
        and a pre-release of the version already installed is not an
        update either, so both are refused rather than half-attempted and
        reported as an update.

        The ORDER comparison is on the leading numeric components (so
        ``6.9-RC1`` is correctly newer than ``6.8.3``), but the EQUALITY
        test is on the full strings: ``6.9`` and ``6.9-RC1`` are the same
        series, and only the exact string can tell "already running that"
        from "not newer than that".
        """
        here, there = _order_tuple(current), _order_tuple(target)
        if here is None or there is None:
            raise WptError(
                f"cannot compare the running WordPress {current} with the "
                f"target {target} — neither is an X.Y[.Z] version; refusing "
                "to guess which is newer"
            )
        if current == target:
            raise WptError(
                f"WordPress {target} is ALREADY the running version — "
                "nothing to do (run `wpt update-core` with no --to to see "
                "what wp.org offers)"
            )
        width = max(len(here), len(there))
        here_padded = here + (0,) * (width - len(here))
        there_padded = there + (0,) * (width - len(there))
        if there_padded <= here_padded:
            raise WptError(
                f"refusing to update WordPress {current} to {target}: that is "
                "not a NEWER release (same series or lower) — WordPress "
                "cannot migrate a database backwards, and a pre-release of "
                "the installed version is not an update; restore a snapshot "
                "(`wpt restore --undo-last`) or a database backup instead"
            )

    def _refuse_php_floor(self, offer: _Offer, site: _Site) -> None:
        """The release's PHP floor above the running interpreter: a refusal.

        Not a warning: the target would be a core that fatals on this
        host, and a number in a dry run is not a control.  An unreadable
        live PHP is refused too — the floor cannot be SHOWN to be met,
        and an unproven precondition is not a met one.
        """
        if not offer.php_floor:
            log.warning("update-core: the WordPress %s offer declares no "
                        "minimum PHP, so the PHP floor could not be "
                        "checked", offer.version)
            return
        if site.php is None:
            raise WptError(
                f"cannot update to WordPress {offer.version}: the live PHP "
                f"version could not be read (bridge info) and that release "
                f"requires PHP {offer.php_floor}+ — refusing to install a "
                f"core whose floor cannot be shown to be met"
            )
        met = _version_at_least(site.php, offer.php_floor)
        if met is None:
            raise WptError(
                f"cannot update to WordPress {offer.version}: the live PHP "
                f"version {site.php!r} and the release's floor "
                f"{offer.php_floor} are not comparable versions — refusing"
            )
        if not met:
            raise WptError(
                f"refusing to update to WordPress {offer.version}: it "
                f"requires PHP {offer.php_floor} and this site runs PHP "
                f"{site.php} — upgrade PHP on the host first, then re-run"
            )

    def _refuse_multisite(self, site: _Site) -> None:
        """A multisite install is refused (and the op refuses it again).

        ``wp_upgrade()`` takes the network path on multisite: it runs
        ``upgrade_network()`` and writes a per-site ``db_version`` into
        SITE META, while this action's snapshot covers one site's files
        and one database.  Letting core's own routine run over a network
        install would migrate tables this snapshot does not hold.

        AN UNREADABLE FACT IS REFUSED, exactly as an unreadable PHP
        version is.  The shape matters: the bridge answers
        ``is_multisite() ? … : false``, so a payload that OMITS the key
        is a bridge that could not answer — and a truthiness test
        (``if site.multisite``) reads that missing value as "single
        site" and lets the run continue, while the sibling PHP gate on the
        very same payload fails closed.  Two gates, one payload, opposite
        verdicts, is the defect this closes.
        """
        if site.multisite is None:
            raise WptError(
                "cannot update: the install's MULTISITE state could not be "
                "read (the bridge info payload carries no usable "
                "`multisite`), and a core upgrade on a network install "
                "migrates the network (upgrade_network() plus a per-site "
                "db_version in site meta), which this action's single-site "
                "snapshot does not cover — refusing on an unproven fact, "
                "the same shape as the unreadable-PHP refusal"
            )
        if site.multisite:
            raise WptError(
                "refusing to update a MULTISITE installation: a core "
                "upgrade there also migrates the network "
                "(upgrade_network() plus a per-site db_version in site "
                "meta), which this action's single-site snapshot does not "
                "cover — use wp-cli (`wp core update --network`) with a "
                "network-wide backup"
            )

    def _refuse_mysql_floor(self, offer: _Offer, site: _Site) -> None:
        """The release's MySQL floor above the live engine: a refusal.

        The same gate, and the same unproven-value rule, as the PHP floor.
        An engine that cannot be read (``wpdb->db_version()`` failed, or
        the payload carries nothing) is refused, because the floor cannot
        be SHOWN to be met.

        The engine answer is a string with a vendor suffix on real hosts
        (``10.6.18-MariaDB``, ``5.7.42-log``) and a plain ``8.0.36``
        elsewhere, so the comparison is made on the LEADING dotted
        numbers and the suffix is dropped.  That is honest for the
        decision this gate makes — "is this host's engine at least the
        release's floor" — and the one thing it is not is a MariaDB/MySQL
        feature comparison, which no version tuple can be.
        """
        if not offer.mysql_floor:
            log.warning("update-core: the WordPress %s offer declares no "
                        "minimum MySQL, so the engine floor could not be "
                        "checked", offer.version)
            return
        if site.mysql is None:
            raise WptError(
                f"cannot update to WordPress {offer.version}: the live MySQL "
                f"version could not be read (bridge info) and that release "
                f"requires MySQL {offer.mysql_floor}+ — refusing to install "
                f"a core whose floor cannot be shown to be met"
            )
        engine = _engine_tuple(site.mysql)
        floor = _engine_tuple(offer.mysql_floor)
        if engine is None or floor is None:
            raise WptError(
                f"cannot update to WordPress {offer.version}: the live MySQL "
                f"version {site.mysql!r} and the release's floor "
                f"{offer.mysql_floor} are not comparable versions — refusing"
            )
        width = max(len(engine), len(floor))
        met = ((engine + (0,) * (width - len(engine)))
               >= (floor + (0,) * (width - len(floor))))
        if not met:
            raise WptError(
                f"refusing to update to WordPress {offer.version}: it "
                f"requires MySQL {offer.mysql_floor} and this site runs "
                f"{site.mysql} — upgrade the database engine on the host "
                f"first, then re-run"
            )

    def _read_back(self, ctx: "Ctx", stack: tuple,
                   files: dict[str, Entry], site: _Site,
                   release: _Release, session: requests.Session,
                   timeout_s: int, driver: "_Driver") -> _ReadBack:
        """Read the replaced trees BEFORE any write; refuse what is not clean.

        Every in-scope file already in the tree must read COMPLETELY (a
        short or unreadable read means the snapshot could not capture
        what the swap is about to overwrite, and an update may never
        overwrite a file nothing can bring back) and must match the
        OFFICIAL checksum of the version the site claims to run.  The
        digests are compared against the CURRENT version's map, never the
        target's: every file that legitimately changed between the two
        versions would otherwise read as dirty and no upgrade past a
        single patch would be possible.  The basis is the audit's own
        (``_fetch_comparison_checksums`` at the same locale), so the
        update, the heal and the audit can never disagree about the tree.

        The same pass classifies what the two trees hold that the target
        does NOT ship (see :class:`_ReadBack`), and refuses the one shape
        an update must never delete silently: a file inside a replaced
        tree that the INSTALLED release never shipped.  Swapping the tree
        removes it, and it is somebody's file — a plugin's, a host's, an
        operator's — with no official release to account for it.  The
        lever is to look before running: ``wpt audit --only core.integrity``
        names the same files, and each one leaves the tree by hand (or is
        deleted, once the audit has shown the operator what it is).  There
        is deliberately NO profile lever for this: ``known_added``
        signatures are name + content-marker + size matches against a
        WEBROOT-ROOT ``*.php``, which is a different predicate and a
        different scope, and a message naming it as the way out of a
        refusal it cannot satisfy is worse than no lever at all.

        THE GUARD IS DRIVER-INDEPENDENT and its message says what the
        CHOSEN driver would do, because the two destroy an unknown
        addition DIFFERENTLY and neither driver is a way past it: the
        swap removes the tree the file lives in, while WordPress's own
        ``copy_dir()`` OVERWRITES the file where the release ships that
        path (and leaves it standing everywhere else).  A guard that
        applied to one driver and not the other would be a hole exactly
        where the mechanism changed.
        """
        present = tuple(path for path in sorted(release.files)
                        if path in files)
        residue = tuple(sorted(
            path for path in files
            if path.startswith(_TREE_PREFIXES) and path not in release.files))
        if not present and not residue:
            return _ReadBack()
        current, _effective = _fetch_comparison_checksums(
            site.version, session, timeout_s,
            resolve_core_locale(
                stack[0], site.locale or None,
                ctx.settings.wp_org.default_locale),
            deadline=Deadline.from_ctx(ctx),
            config=ctx.settings.wp_org)
        if current is None:
            raise WptError(
                f"cannot update: wp.org checksums for the INSTALLED "
                f"WordPress {site.version} are unavailable — the tree "
                f"cannot be proven pristine before its files are replaced; "
                f"refusing (retry when wp.org answers, or run "
                f"`wpt heal-core --apply`)"
            )
        unknown = [path for path in residue if current.get(path) is None]
        junk = set(_junk_paths(ctx, unknown))
        additions = [path for path in unknown if path not in junk]
        if additions:
            raise WptError(
                f"cannot update: {len(additions)} file(s) inside "
                f"wp-admin/ or wp-includes/ are not part of the official "
                f"WordPress {site.version} release ({_named_paths(additions)}"
                f") — {_addition_destiny(driver.name)} nothing official "
                f"accounts for them; run `wpt audit --only "
                f"core.integrity` to see every one of them, then move each "
                f"out of the tree (or delete it, if it is not something "
                f"the site needs) and re-run. core_integrity.known_added "
                f"does NOT apply here: its signatures match a "
                f"WEBROOT-ROOT *.php (a name plus a content marker), never "
                f"a path inside a core tree, so no value of that key could "
                f"ever match these files"
            )
        if not present:
            return _ReadBack(stale=tuple(residue), junk=tuple(sorted(junk)))
        bridge = stack[2]
        deadline = Deadline.from_ctx(ctx)
        if bridge is not None:
            digests, unreadable = _digests_bridge(bridge, list(present),
                                                  deadline=deadline)
        else:
            digests, unreadable = _digests_source(stack[0], list(present),
                                                  deadline=deadline)
        if unreadable:
            raise WptError(
                f"cannot update: {len(unreadable)} file(s) of the "
                f"{len(present)} in the update scope could not be read "
                f"({_named_paths(sorted(unreadable), len(unreadable))}) — "
                f"the snapshot could not capture what the swap would "
                f"overwrite; refusing (fix the channel or the file, or "
                f"narrow the run)"
            )
        dirty = [path for path in present
                 if current.get(path) is None
                 or digests.get(path) != current.get(path)]
        if dirty:
            raise WptError(
                f"cannot update: {len(dirty)} of {len(present)} file(s) in "
                f"the update scope do not match the official WordPress "
                f"{site.version} checksums ({_named_paths(dirty)}) — the "
                f"installed core is not pristine, and updating would bury "
                f"that evidence under a fresh official tree; run "
                f"`wpt audit --only core.integrity` then "
                f"`wpt heal-core --apply` first"
            )
        return _ReadBack(present=present,
                         stale=tuple(p for p in residue if p not in junk),
                         junk=tuple(sorted(junk)))

    # ---- the plan's narrative

    def _announce(self, derived: _Derived, *, maintenance: bool,
                  tables: list[str]) -> None:
        """One info line per fact the plan owes the operator.

        ``Plan`` has no free-text field (report.py ships items + table
        names), so these lines ARE the plan's narrative — the same
        arrangement heal-core uses for its investigate-only note.
        """
        site, release = derived.site, derived.release
        driver = derived.driver
        log.info(
            "plan: DRIVER = %s — %s. The plan, the refusals, the snapshot "
            "scope, the maintenance window and the verify are the SAME for "
            "either driver; only the mechanism that lays the bytes down "
            "differs, and --apply runs the driver this plan names or fails",
            driver.name, driver.why,
        )
        migration = (None if site.db_version is None
                     else release.db_version > site.db_version)
        log.info(
            "plan: WordPress %s -> %s (%s build), db_version %s -> %s%s",
            site.version, release.version, release.locale,
            site.db_version if site.db_version is not None else "unknown",
            release.db_version,
            "" if migration is not False
            else " (no schema migration implied)",
        )
        read_back = derived.read_back
        log.info(
            "plan: %d core file(s) replaced, %s estimated (%d already in "
            "the tree, %d created); %d stale file(s) inside the replaced "
            "trees are removed with them; wp-content/ and wp-config.php are "
            "never touched", len(release.files), human_bytes(release.bytes),
            len(read_back.present),
            len(release.files) - len(read_back.present),
            len(read_back.stale),
        )
        if read_back.junk:
            log.info("plan: %d file(s) inside the replaced trees are this "
                     "tool's own junk (%s) — removed with the tree, which is "
                     "what `wpt clean-files --apply` does with them anyway",
                     len(read_back.junk), _named_paths(list(read_back.junk))
                     + ("" if driver.name == _DRIVER_SWAP else
                        "; the wordpress driver's copy is additive, so they "
                        "stay until `wpt clean-files` removes them"))
        log.info(
            "plan: WordPress %s requires PHP %s+ and MySQL %s+ (both are "
            "REFUSALS, checked against the live host and re-read in the "
            "verify); live PHP %s, live MySQL %s", release.version,
            derived.offer.php_floor or "unstated",
            derived.offer.mysql_floor or "unstated",
            site.php or "unknown (this mode reads no live PHP)",
            site.mysql or "unknown (this mode reads no live database)",
        )
        log.info(
            "plan: the pristine proof is TREE-SCOPED, not whole-core: it "
            "covers the %d file(s) this release replaces and every file the "
            "tree swap removes — a site-level *.php the release does not "
            "ship is not touched by the swap and is not gated here, and "
            "wp-content/ is out of scope entirely",
            len(release.files) + len(read_back.stale),
        )
        log.info(
            "plan: %s", (
                f"{_MAINTENANCE} is engaged before the swap and removed when "
                f"the run ends — every name (each of the {len(_CORE_TREES)} "
                f"trees, each root file) is parked and landed back to back, "
                f"a failure anywhere in the write phase is undone in "
                f"reverse, and the parked copy is kept until the verify "
                f"passes; WordPress's own 10-minute expiry on the file is "
                f"the second line under all of it"
                if maintenance else
                f"NO {_MAINTENANCE} (update.maintenance is false) — "
                f"visitors can see the swap, and each name is still parked "
                f"and landed back to back with the same undo"
            ),
        )
        log.info(
            "plan: snapshot scope = the %d replaced file(s) + the %d "
            "removed with them%s; the rollback is `wpt restore --undo-last`",
            len(release.files), len(read_back.stale),
            f" + {len(tables)} database table(s) via db_dump"
            if tables else " (this mode has no database to snapshot)",
        )

    def _report_offers(self, offers: list[dict[str, Any]], site: _Site) -> None:
        """The no-``--to`` report: what wp.org offers, and the exact version.

        The version a ``--to`` would need is named from that same list —
        the first offer that is genuinely newer than the running version —
        so the number the operator copies is the number wp.org published,
        never "the latest" fetched from somewhere else.
        """
        log.info("plan: WordPress %s is installed; wp.org offers %d "
                 "version(s) — naming a target is required, so nothing is "
                 "planned", site.version, len(offers))
        for raw in offers[:_REFUSAL_PATHS + 2]:
            log.info("  offer: %s (response %s, PHP %s+, MySQL %s+)",
                     raw["version"] or "?", raw["response"] or "?",
                     raw["php_version"] or "unstated",
                     raw["mysql_version"] or "unstated")
        here = _order_tuple(site.version)
        wanted = next(
            (raw["version"] for raw in offers
             if raw["version"] and _newer_than(raw["version"], here)),
            None,
        )
        if wanted:
            log.info("plan: to plan a real update, name that target "
                     "explicitly: wpt update-core --to %s --apply", wanted)
        else:
            log.info("plan: no offer is newer than the running version "
                     "(`wpt updates` reports the plugin/theme offers)")

    # ----------------------------------------------------------------- apply

    def apply(self, ctx: "Ctx", stack: tuple, plan: Plan) -> Plan:
        source, _session, bridge = stack
        items = [item for item in plan.items if item.requires_apply]
        if not items:
            return plan
        target = _requested_target(ctx)
        if target is None:  # a hand-built plan with no target: refuse
            raise WptError(
                "update-core apply: no --to target — the target is never "
                "implicit; refusing to apply an unspecified update"
            )
        entries = list(bounded_walk(
            source, Deadline.from_ctx(ctx), "update-core walk"))
        files = {e.path: e for e in entries if not e.is_dir}
        _report_residue(entries)
        site = _site_facts(source, bridge, core_upgrade=True,
                           deadline=Deadline.from_ctx(ctx))
        if not site.version:
            raise WptError(
                "unknown WordPress version at apply time — refusing to "
                "update a site whose version cannot be read"
            )
        derived = self._derive(ctx, stack, files, site, target)
        planned = [item.target for item in items]
        if [item.target for item in self._items(derived)] != planned:
            raise WptError(
                "update-core: the file set changed between the plan and "
                f"the apply ({len(derived.release.files)} files now, "
                f"{len(planned)} planned) — re-run the dry run so the plan "
                "that was confirmed is the plan that runs"
            )
        self._refuse_driver_drift(derived)
        # The sweep wraps EVERYTHING below it, including the pre-write
        # proof: it is the mechanism that ends a run of its own, so the
        # residue of a run that failed at the first byte — or of a run
        # that was KILLED, which is why it is keyed on the NAMES in the
        # webroot rather than on anything this run remembers — is cleaned
        # or reported on every exit.
        staging: str | None = None
        try:
            retired, staging = self._install(ctx, source, derived, bridge)
            if bridge is not None:
                self._migrate(bridge, derived)
                self._verify_remote(ctx, stack, derived, plan)
            else:
                log.info("apply: local rehearsal — this mode has no database "
                         "in its stack, so NO schema migration ran; the "
                         "copy's db_version is whatever the live database "
                         "holds when it is deployed (WordPress applies it "
                         "on first load)")
                self._verify_local(ctx, source, derived, plan)
            # Only now is the parked core disposable: it is the last copy
            # of the installed core, and until the verify has passed it is
            # the hand-recovery path for anything the proof cannot
            # establish.  A failure before this point leaves it in place
            # and the sweep NAMES it.  The same rule governs the
            # wordpress driver's staging: cleared only now, only because
            # THIS run created it, and never on the strength of a name
            # alone.
            _discard_retired(source, retired)
            _clear_own_staging(source, staging)
        finally:
            # The residue sweep is owed on EVERY exit, including the
            # deadline/stop that ended the forward work: it must run on a
            # fresh finite budget or an expired source cannot LIST, DELETE
            # or REPORT what this run left behind.
            with source_cleanup_budget(source):
                _sweep_residue(source)
        log.info("apply: WordPress %s installed and verified — %d core "
                 "file(s) replaced with the %s driver, db_version %s",
                 target, len(items), derived.driver.name,
                 derived.release.db_version)
        return plan

    def _refuse_driver_drift(self, derived: _Derived) -> None:
        """The apply must run the driver the PLAN named, or not run at all.

        The driver is re-derived here from the site's own facts, exactly as
        the plan derived it, because a site can change under a plan (a host
        that lost direct filesystem access, a PHP upgrade that dropped
        ZipArchive).  Falling back to the other driver mid-apply would be
        the worst of both worlds: the operator confirmed a plan that named
        one mechanism, and the run would silently use another — with a
        different failure surface, a different residue and a different
        recovery story.  So a plan whose driver no longer holds refuses, and
        the refusal says which one changed.
        """
        planned = getattr(self, "_planned_driver", None)
        if planned is None or planned == derived.driver.name:
            return
        raise WptError(
            f"update-core: the driver changed between the plan and the "
            f"apply — the plan named `{planned}` and the site now answers "
            f"`{derived.driver.name}` ({derived.driver.why}) — re-run the "
            f"dry run so the plan that was confirmed is the plan that runs; "
            f"nothing was written"
        )

    def _install(self, ctx: "Ctx", source: "Source", derived: _Derived,
                 bridge: "Bridge | None") -> tuple[list[tuple[str, bool]],
                                                   str | None]:
        """Lay the release down with the driver this run chose.

        Returns ``(parked names, staging this run created)`` — the two
        things that outlive a run and are therefore disposed of only after
        the verify passed.  Everything either driver needs from the tool
        (the pristine proof of the package bytes, the maintenance window,
        the snapshot the registry took before this was called) is in place
        before this is reached; everything either driver needs afterwards
        (the migration, the verify) is the caller's next step, which is
        what makes the two drivers interchangeable in every guarantee but
        the write itself.
        """
        if derived.driver.name == _DRIVER_WORDPRESS:
            return [], self._wordpress_in(ctx, source, derived, bridge)
        return self._swap_in(ctx, source, derived), None

    # ---- the migration

    def _migrate(self, bridge: "Bridge", derived: _Derived) -> None:
        """Run core's own migration through the bridge's ``core_upgrade`` op.

        Only when the target's schema version is ABOVE the installed one:
        ``wp_upgrade()`` is a documented no-op otherwise, and calling it
        anyway would be an unnecessary write on a database that needs
        nothing.  The comparison is deliberately ``>=`` on the RELEASE's
        side — a site whose database is already at or past the target is a
        correct site, and WordPress's own rule is
        ``db_version < $wp_db_version`` triggers a migration, so anything
        else must not be refused.  The op's answer is the value read BACK
        from the database, never the one the migration intended — and a
        value that does not reach the target is a refusal, not a warning.

        A migration that FATALS (a modest ``memory_limit`` on a big one is
        the shape that happens) is not catchable in PHP and destroys the
        response entirely, so this method's own diagnosis has to survive
        that: the op's pre-migration marker is read afterwards and the
        refusal says what state the database was in when the migration
        began.
        """
        site, release = derived.site, derived.release
        if (site.db_version is not None
                and release.db_version <= site.db_version):
            log.info("apply: db_version %s already matches the target's %s "
                     "— no schema migration needed", site.db_version,
                     release.db_version)
            return
        try:
            result = bridge.upgrade_core()
        except BridgeError as exc:
            raise WptError(
                f"the database migration did not report back ({exc}) — the "
                f"op's own answer is gone, so what is left is the state it "
                f"started from: {_marker_sentence(bridge, site)}; re-run "
                f"`wpt doctor` to read the current db_version. The "
                f"pre-action snapshot is the rollback"
            ) from exc
        if result["db_version"] < release.db_version:
            raise WptError(
                f"the database migration left db_version at "
                f"{result['db_version']} but WordPress {release.version} "
                f"declares {release.db_version} — the migration did not "
                f"reach the target; the pre-action snapshot is the "
                f"rollback"
            )
        if result["db_version"] > release.db_version:
            log.info("apply: the migration left db_version at %s, AHEAD of "
                     "the release's %s — a database past the target is a "
                     "correct state (WordPress migrates forward only) and "
                     "is not refused", result["db_version"],
                     release.db_version)
        log.info("apply: db_version %s -> %s (core_upgrade: core's own "
                 "wp_upgrade())", site.db_version, result["db_version"])

    # ---- verify after write

    def _verify_remote(self, ctx: "Ctx", stack: tuple, derived: _Derived,
                       plan: Plan) -> None:
        """The proofs, in the order a failure is cheapest to read.

        The DATABASE first: a fresh ``info`` call is a different PHP
        process from the one that ran the migration, so it reads the
        versions the database NOW holds rather than the op's own return
        value — and it is where the ENGINE is re-read too, so the MySQL
        floor the run was gated on is proved again against the live host
        instead of remembered.  Then the FILE digests (a fresh bulk read
        of everything the swap wrote), then the two live fetches.  Any
        failure raises, so the registry answers rc 1 with the snapshot
        named as the rollback and does NOT purge the cache.
        """
        _source, session, bridge = stack
        release = derived.release
        deadline = Deadline.from_ctx(ctx)
        info = bridge.call("info", **transport_kwargs(deadline))
        got_version = _opt_str(info.get("wp_version"))
        got_db = wire_int(info.get("db_version"))
        if got_version != release.version:
            raise WptError(
                f"verification failed: the site reports WordPress "
                f"{got_version or 'unknown'} after the update, not "
                f"{release.version} — the update is NOT done; the "
                f"pre-action snapshot is the rollback"
            )
        # AT OR ABOVE, never equal.  The bridge casts the stored option to
        # a STRING on purpose (a stored options row is not an int in PHP),
        # so the raw value is normalized through the one coercion of that
        # shape in the tree — demanding an int here reads every real
        # payload as "unknown" and refuses a site that is perfectly
        # updated.  And a schema AHEAD of the target is a correct site:
        # WordPress migrates forward only (``db_version < $wp_db_version``
        # is what triggers it), so equality would refuse a state that
        # needs nothing.
        if got_db is None or got_db < release.db_version:
            raise WptError(
                f"verification failed: the database holds db_version "
                f"{got_db if got_db is not None else 'an unreadable value'} "
                f"after the update, below the target's {release.db_version} "
                f"— the update is NOT done; the pre-action snapshot is the "
                f"rollback"
            )
        if got_db > release.db_version:
            log.info("verify: the database is at db_version %s, AHEAD of "
                     "the target's %s — a schema past the release's own "
                     "target is a correct site and is not refused",
                     got_db, release.db_version)
        self._assert_engine(info, derived)
        # The step the tool does NOT trust, said out loud: WordPress's own
        # core update fires the database migration as a fire-and-forget
        # ``wp_remote_post( admin_url('upgrade.php?step=upgrade_db'),
        # array('timeout' => 60) )`` and NEVER inspects the response, so a
        # dead callback leaves new files on an old schema.  (The
        # core_upgrade_files op suppresses that request and reports it; this
        # action runs the migration itself, in-process, through core's own
        # wp_upgrade() and re-reads the version here.)  This line is why the
        # re-read above exists, and it is driver-independent: both drivers
        # migrate through the same op and are proved by the same read.
        log.info(
            "verify: WordPress's own step is fire-and-forget, so wpt "
            "verifies it itself — core posts the database upgrade with a "
            "60s timeout and never checks the answer, so the migration runs "
            "in-process (core's own wp_upgrade() through the core_upgrade "
            "op) and db_version above was re-read from a fresh process, not "
            "taken from anything core returned")
        digests, unreadable = _digests_bridge(
            bridge, sorted(release.files), deadline=Deadline.from_ctx(ctx))
        self._assert_digests(derived, digests, unreadable)
        self._assert_removed(stack[0], derived)
        self._verify_live(ctx, session)
        _mark_done(plan)

    def _assert_engine(self, info: dict[str, Any], derived: _Derived) -> None:
        """The MySQL floor, re-proved from the verify's own ``info``.

        The refusal was made on a pre-swap read; this is the same fact
        read again in the same call that carries the schema version, so a
        floor that cannot be read at VERIFY time is a failure of the proof
        rather than an assumption inherited from the plan.
        """
        offer, release = derived.offer, derived.release
        if not offer.mysql_floor:
            return
        engine = _opt_str(info.get("mysql_version"))
        if engine is None:
            raise WptError(
                f"verification failed: the live MySQL version could not be "
                f"read after the update, and WordPress {release.version} "
                f"requires MySQL {offer.mysql_floor}+ — the update is NOT "
                f"done; the pre-action snapshot is the rollback"
            )
        have, floor = _engine_tuple(engine), _engine_tuple(offer.mysql_floor)
        if have is None or floor is None:
            raise WptError(
                f"verification failed: the live MySQL version {engine!r} "
                f"does not compare against the release's floor "
                f"{offer.mysql_floor} — the update is NOT done; the "
                f"pre-action snapshot is the rollback"
            )
        width = max(len(have), len(floor))
        if (have + (0,) * (width - len(have))) < (floor + (0,) * (width - len(floor))):
            raise WptError(
                f"verification failed: the host answers MySQL {engine} after "
                f"the update, below the WordPress {release.version} floor of "
                f"{offer.mysql_floor} — the update is NOT done; the "
                f"pre-action snapshot is the rollback"
            )

    def _verify_local(self, ctx: "Ctx", source: "Source",
                      derived: _Derived, plan: Plan) -> None:
        """The rehearsal's proof: the file digests, and only that.

        Local mode has no database and no live origin, so the two checks
        that need one are absent BY CONSTRUCTION rather than skipped: the
        rehearsal's claim is exactly "these are the target release's
        files", and the digests are that claim's proof.  A rehearsal that
        proved nothing would be the green-run-over-nothing this project
        keeps refusing.
        """
        release = derived.release
        digests, unreadable = _digests_source(
            source, sorted(release.files), deadline=Deadline.from_ctx(ctx))
        self._assert_digests(derived, digests, unreadable)
        self._assert_removed(source, derived)
        _mark_done(plan)

    def _assert_digests(self, derived: _Derived,
                        digests: dict[str, str | None],
                        unreadable: list[str]) -> None:
        """Every replaced file must now carry the release's official md5."""
        release = derived.release
        unread = set(unreadable)
        wrong = [path for path, digest in sorted(digests.items())
                 if path in unread
                 or digest != derived.target_map.get(path)]
        if not wrong:
            return
        raise WptError(
            f"verification failed: {len(wrong)} of {len(release.files)} "
            f"replaced file(s) do not carry the official WordPress "
            f"{release.version} {release.locale} checksum "
            f"({_named_paths(wrong)}) — the update is NOT done; the "
            f"pre-action snapshot is the rollback"
        )

    def _assert_removed(self, source: "Source",
                        derived: _Derived) -> None:
        """A file the swap was supposed to remove must be GONE.

        The retired tree is deleted wholesale, so a survivor means the
        tree swap did not do what the plan said it would (a stale file
        left in the webroot, and one the plan's snapshot now holds a copy
        of for no reason).  Claiming the item done over a survivor is
        exactly the "green run over nothing" this project refuses, so it
        is a refusal naming the paths.
        """
        survivors = [path for path in derived.read_back.stale
                     if source.exists(path)]
        if not survivors:
            return
        raise WptError(
            f"verification failed: {len(survivors)} file(s) the plan said "
            f"the replaced trees remove are still there "
            f"({_named_paths(survivors)}) — the tree swap did not complete; "
            f"the update is NOT done; the pre-action snapshot is the "
            f"rollback"
        )

    def _verify_live(self, ctx: "Ctx", session: requests.Session) -> None:
        """The site must still ANSWER after the swap.

        The site root must RENDER (2xx): a corrupted ``wp-includes`` is a
        fatal there and nowhere else.  The REST root must answer without a
        server error — a plain-permalink install legitimately 404s
        ``/wp-json/`` (so a 404 is not a failure, and refusing it would
        refuse a supported configuration), while a 5xx there is the
        rewrite layer dying on a half-swapped core.  A transport failure
        on either is a failure of both.
        """
        base = (ctx.wp_url or "").rstrip("/")
        if not base:   # pragma: no cover - ftp mode always carries a wp_url
            raise WptError(
                "verification failed: no site URL to fetch after the "
                "update — refusing to report an update as verified"
            )
        _fetch_status(session, f"{base}/", ctx, "site root", render=True,
                      deadline=Deadline.from_ctx(ctx))
        _fetch_status(session, f"{base}{_REST_PATH}", ctx, "REST root",
                      render=False, deadline=Deadline.from_ctx(ctx))

    # ---- the write

    def _wordpress_in(self, ctx: "Ctx", source: "Source", derived: _Derived,
                      bridge: "Bridge | None") -> str | None:
        """WordPress's OWN updater installs the release; return its staging.

        The whole file half, delegated: the release zip (already proven
        against the target's own checksum map) is uploaded to the site and
        core's updater does the extraction, the copy, the version-last
        ordering, the bundled re-add and its post-copy md5 re-verification
        — armed with ``attempt_rollback``, the argument the admin UI never
        passes.  The tool keeps every guarantee around it, and none of them
        is the driver's to keep:

        * the package bytes are proven BEFORE the upload (the same
          pre-write proof the swap driver takes, on the same bytes);
        * ``.maintenance`` is the tool's own, engaged here and removed in
          the ``finally`` — core writes its own and deletes it on its
          SUCCESS route only, which is the reachable "stuck in maintenance"
          state this action exists to close;
        * the DATABASE step is suppressed by the op (core fires it as a
          fire-and-forget POST and never checks the response) and run by
          the caller through ``core_upgrade``, then re-read;
        * the files core's copy is ADDITIVE about are the tool's to finish:
          core never deletes, so the plan's stale files — planned and
          snapshotted for exactly this reason — are removed here, by the
          same source and under the same rules the swap's tree removal
          achieves.

        Returns the staging directory core left behind, or None.  The
        caller clears it only after the verify passed: until then it is
        the recovery path for a run that failed mid-copy.
        """
        release = derived.release
        self._prove_release(derived, ctx.settings.wp_org.release_zip_prefix)
        package = _package_path(release.version)
        log.info("apply: driver=wordpress — uploading the proven WordPress "
                 "%s release to %s; WordPress's own updater extracts it into "
                 "wp-content/upgrade/ and copies it onto the webroot with "
                 "its own skip list, with attempt_rollback armed",
                 release.version, package)
        source.write_bytes(package, derived.zip_bytes)
        if bridge is None:   # pragma: no cover - the driver is never chosen
            raise WptError(
                "update-core: the wordpress driver was chosen without a "
                "bridge to drive it — refusing (this is a defect; report it)"
            )
        self._engage_maintenance(ctx, source)
        try:
            try:
                result = bridge.core_upgrade_files(package, release.version)
            except BridgeError as exc:
                raise WptError(
                    f"{exc} — WordPress's own updater did not finish the "
                    f"file half; the plan is NOT done and the pre-action "
                    f"snapshot (`wpt restore --undo-last`) is the rollback"
                ) from exc
        finally:
            with source_cleanup_budget(source):
                self._disengage_maintenance(ctx, source)
        self._report_phases(result)
        self._retire_stale(source, derived)
        staging = result["staging"] if result["staging_exists"] else ""
        return staging or None

    def _report_phases(self, result: dict[str, Any]) -> None:
        """What WordPress's own updater actually did, phase by phase.

        The op MEASURES each phase (a sentinel pair in the extracted tree,
        the version ``wp-includes/version.php`` declares on disk afterwards,
        the bundled units that appeared) and hands core's own ordered
        progress messages with it.  Both are reported: the measurements
        are what the run may rely on, and the progress list is the order
        core published, which is how a failure names the phase it died in.
        """
        for phase in ("unzip", "copy", "bundled"):
            block = result["phases"].get(phase)
            if not isinstance(block, dict):
                continue
            log.info("apply: core_upgrade_files %s: %s — %s",
                     phase, "ok" if block.get("ok") else "NOT DONE",
                     block.get("detail") or "")
        if result["progress"]:
            log.info("apply: WordPress's own updater announced: %s",
                     " | ".join(str(item) for item in result["progress"]))
        if result["bundled_added"]:
            log.info("apply: core re-added %d bundled unit(s): %s",
                     len(result["bundled_added"]),
                     _named_paths([str(u) for u in result["bundled_added"]]))
        rollback = result["rollback"]
        if rollback.get("critical_code"):
            log.warning(
                "apply: WordPress's own rule says the failure is its "
                "ROLLBACK-worthy class (%s), and it had no rollback package "
                "to restore from — the pre-action snapshot is the rollback",
                rollback["critical_code"])
        if result["maintenance_left"]:
            log.info("apply: WordPress's updater left its own .maintenance "
                     "behind (it removes that file only on its success "
                     "route); the tool's teardown removed it either way")
        if result["output"]:
            log.warning("core_upgrade_files: the updater printed output "
                        "(kept, not discarded): %s%s",
                        redact_text(str(result["output"])),
                        " [truncated]" if result["output_truncated"] else "")

    def _retire_stale(self, source: "Source", derived: _Derived) -> None:
        """Remove the plan's stale files — the step core's copy does not do.

        WordPress's own ``copy_dir()`` OVERWRITES and never deletes, so the
        files the installed release shipped and the target dropped survive
        it.  The swap removes them by replacing the tree; this driver has
        to do it by hand, and it is exactly why they are PLAN ITEMS (the
        registry derives the snapshot scope from the plan, so each one is
        captured and ``wpt restore --undo-last`` can bring it back).

        A delete that fails raises: the plan said these files go, the
        verify proves they are gone, and a survivor must leave the run NOT
        done rather than quietly reported as updated.
        """
        stale = derived.read_back.stale
        if not stale:
            return
        failed: list[str] = []
        for path in stale:
            try:
                if source.exists(path):
                    source.delete(path)
            except (SourceError, OSError) as exc:
                log.warning("update-core: could not remove the stale core "
                            "file %s (%s)", path, exc)
                failed.append(path)
        if failed:
            raise WptError(
                f"cannot finish the update: {len(failed)} stale core file(s) "
                f"the plan removes could not be deleted "
                f"({_named_paths(failed)}) — WordPress's copy overwrites but "
                f"never deletes, so this step is the tool's; the update is "
                f"NOT done and the pre-action snapshot is the rollback"
            )
        log.info("apply: removed %d stale core file(s) WordPress's copy "
                 "left in place: %s", len(stale), _named_paths(list(stale)))

    def _swap_in(self, ctx: "Ctx", source: "Source",
                 derived: _Derived) -> list[tuple[str, bool]]:
        """Stage, prove, engage maintenance, swap every name, undo on failure.

        Returns the PARKED names (with the shape that removes each) — the
        caller's to discard once the verify has passed, and never before.

        The order IS the guarantee.  Nothing reaches a live name until
        every byte has been written to its staging path AND proven against
        the release's checksum map; ``.maintenance`` is engaged before the
        first swap and removed by the ``finally`` no matter which step
        raises; and the undo is INSIDE that try, so a failure is put back
        while the site is still in maintenance rather than after it.
        """
        release = derived.release
        prefix = ctx.settings.wp_org.release_zip_prefix
        landed: list[tuple[str, str, str, bool, bool]] = []
        self._prove_release(derived, prefix)
        with zipfile.ZipFile(io.BytesIO(derived.zip_bytes)) as zf:
            names = {name[len(prefix):]: name
                     for name in zf.namelist()
                     if not name.endswith("/")
                     and name.startswith(prefix)}
            self._stage(ctx, source, zf, names, release)
            self._engage_maintenance(ctx, source)
            try:
                for tree in _CORE_TREES:
                    landed.append(self._park_and_land(
                        source, tree, f"{tree}{_STAGE_SUFFIX}", directory=True))
                for path, _size in sorted(release.files.items()):
                    if "/" not in path:
                        landed.append(self._park_and_land(
                            source, path, f"{path}{_TMP_SUFFIX}",
                            directory=False))
            except (SourceError, OSError, RunControl):
                # The undo runs on a FRESH finite cleanup budget: the
                # failure that brought us here is usually the run deadline
                # itself, and a rollback that keeps honouring the expired
                # budget cannot issue the renames that put the site back.
                with source_cleanup_budget(source):
                    _undo_landed(source, landed)
                raise
            finally:
                with source_cleanup_budget(source):
                    self._disengage_maintenance(ctx, source)
        return [(retired, directory) for _name, _staged, retired, _had, directory
                in landed]

    def _park_and_land(self, source: "Source", name: str, staged: str, *,
                       directory: bool) -> tuple[str, str, str, bool, bool]:
        """ONE name's swap: park what is installed, land what is staged.

        Two renames, back to back, and nothing between them: that is the
        whole kill-window argument.  The instant at which a live name does
        not exist is the instant between these two calls, and it is one
        pair at a time — so a run killed here leaves exactly one name
        missing and BOTH of its halves on disk, which is a state a rename
        (or the next run's report) puts right.

        The parked copy is NOT deleted here.  It is the last copy of the
        installed core, and it stays until the verify has passed: a run
        that fails after the swap — a migration that did not reach its
        target, a digest that does not match, a site that will not render
        — is then recoverable by hand and not only by snapshot.

        Returns the record the caller undoes in reverse:
        ``(live name, staging name, parked name, was-installed, is-tree)``.
        A name the site does not have (a partially-installed tree, a root
        file the release adds) has nothing to park, and the record says so
        so the undo moves the new one back out instead of pretending an
        original existed.
        """
        retired = f"{name}{_RETIRED_SUFFIX}"
        installed = source.exists(name)
        if installed:
            # Moving the live protected tree/root file away is the same
            # audited core unlock the staging swap takes: the source guard
            # refuses a protected rename without it.
            source.rename(name, retired, allow_core=True)
        try:
            source.rename(staged, name, allow_core=True)
        except (SourceError, OSError, RunControl) as exc:
            if installed:
                try:
                    # The SAME audited unlock as the swap itself: the
                    # rollback lands on the protected name too, and a
                    # rollback refused by the guard would leave the site
                    # with no tree at all.  A run deadline/SIGTERM is a
                    # RunControl too: the one-name restore is still owed.
                    with source_cleanup_budget(source):
                        source.rename(retired, name, allow_core=True)
                except (SourceError, OSError, RunControl) as restore_exc:
                    log.error(
                        "update-core: rolling %s back failed (%s) after a "
                        "failed swap (%s) — %s is empty, %s still holds "
                        "the INSTALLED copy; restore the snapshot "
                        "(`wpt restore --undo-last`) to recover, and do "
                        "not delete %s", name, restore_exc, exc, name,
                        retired, retired,
                    )
            raise
        return (name, staged, retired, installed, directory)

    def _prove_release(self, derived: _Derived,
                       prefix: str | None = None) -> None:
        """Every staged byte must equal the official map BEFORE any swap.

        The release zip and the checksum map are the SAME distribution
        (the [L17] property heal-core's restore relies on), so a file
        whose md5 disagrees means this download is not the release the map
        describes — an interrupted or substituted download.  Proving it
        here aborts with the site completely untouched, which is the only
        place a proof like this is worth taking.
        """
        mismatched: list[str] = []
        unreadable: list[str] = []
        prefix = prefix if prefix is not None else DEFAULT_WP_ORG.release_zip_prefix
        with zipfile.ZipFile(io.BytesIO(derived.zip_bytes)) as zf:
            # one namelist read, not one per file (the release ships
            # thousands; namelist() rebuilds the whole index every call)
            shipped = set(zf.namelist())
            for path, _size in sorted(derived.release.files.items()):
                name = f"{prefix}{path}"
                if name not in shipped:
                    unreadable.append(path)
                    continue
                try:
                    blob = zf.read(name)
                except (OSError, ValueError, EOFError, RuntimeError,
                        zipfile.BadZipFile) as exc:
                    log.warning("update-core: reading %s from the release "
                                "zip failed (%s) — not installed",
                                path, exc)
                    unreadable.append(path)
                    continue
                if hashlib.md5(blob).hexdigest() != derived.target_map.get(path):
                    mismatched.append(path)
        if mismatched or unreadable:
            raise WptError(
                f"refusing to install: {len(mismatched)} of "
                f"{len(derived.release.files)} file(s) of the official "
                f"WordPress {derived.release.version} "
                f"{derived.release.locale} release disagree with its own "
                f"wp.org checksum map"
                + (f" ({_named_paths(mismatched)})" if mismatched else "")
                + (f", and {len(unreadable)} are absent/unreadable "
                   f"({_named_paths(unreadable)})" if unreadable else "")
                + " — the download is not the distribution the map "
                  "describes; NOTHING was written"
            )

    def _stage(self, ctx: "Ctx", source: "Source", zf: zipfile.ZipFile,
               names: dict[str, str], release: _Release) -> None:
        """Write every replacement under its staging path.

        The staging path sits OUTSIDE the protected surface
        (``wp-includes.wpt-new/x.php`` is not ``wp-includes/x.php``), so
        no staging write needs the ``allow_core`` unlock: the audited
        unlock is spent once, on the rename that actually lands the tree.

        It is also the path that made this step remote-specific: the
        staged tree is a directory the site has never had, and over FTP a
        ``STOR`` into a directory the server does not have is a bare 553.
        The action therefore creates NOTHING itself — the staging
        directories are the source contract's ``ensure_write_dir``, the
        chokepoint every remote writer already calls, so the fix is not
        an update-core special case (and a restore into a re-created
        uploads directory, or the bridge deployment into a fresh
        webroot, get it for free).  The run deadline is checked once per
        batch, which is what keeps a wedged channel from turning this
        loop into an unbounded run.
        """
        deadline = Deadline.from_ctx(ctx)
        for path, _size in sorted(release.files.items()):
            # Per ENTRY, not per batch: one entry is a whole STOR and a
            # wedged channel could spend the remaining budget on it.
            if deadline is not None:
                deadline.check("core update staging")
            target = (_staging_path(path) if "/" in path
                      else f"{path}{_TMP_SUFFIX}")
            source.write_bytes(target, zf.read(names[path]))

    def _engage_maintenance(self, ctx: "Ctx", source: "Source") -> None:
        """WordPress's own maintenance file, byte-for-byte core's string.

        Written at the webroot ROOT (``ABSPATH . '.maintenance'`` is where
        ``wp_is_maintenance_mode()`` looks) and therefore
        wp-content-independent: it is removed in the ``finally`` below, so
        nothing the update touches can decide whether the site comes back.
        """
        if not ctx.settings.update.maintenance:
            log.info("apply: maintenance mode is OFF (update.maintenance "
                     "is false) — visitors can see the swap")
            return
        source.write_bytes(_MAINTENANCE, _maintenance_bytes())

    def _disengage_maintenance(self, ctx: "Ctx", source: "Source") -> None:
        """Remove it, from the ``finally`` that must not be skipped.

        A failure here is a WARNING and not a second error: the caller is
        already unwinding with a more important one, and the file's own
        10-minute expiry means a site left in maintenance recovers by
        itself.  Saying so is honest about both.

        Removed with ``delete`` because that is the shape THIS run
        created: a single file, written at the webroot root.  Over FTP
        the two removal primitives are not interchangeable —
        ``rmdir_recursive`` LISTs the path first, a server answers 550 on
        a file, and the teardown would degrade into a warning line while
        the site stayed in maintenance for WordPress's own ten minutes
        instead of for the length of this run.
        """
        if not ctx.settings.update.maintenance:
            return
        _remove_quietly(source, _MAINTENANCE, directory=False,
                        note="WordPress expires it 10 minutes after the "
                        "timestamp inside it; remove it by hand if the "
                        "site still shows maintenance")


# ------------------------------------------------------- the residue (one rule)


def _residue_entries(source: "Source") -> list[tuple[str, bool]]:
    """``(webroot-relative path, is_dir)`` for every update-core residue
    name currently in the webroot ROOT.

    ONE listing, and it is the root because that is the only place the
    tool creates a residue name (see ``wpt.types.update_core_residue``):
    the staged and parked trees are siblings of the trees they replace,
    and a root file's temp and parked names are siblings of the file.  A
    walk would cost thousands of entries to re-derive the same answer.
    """
    try:
        entries = source.list_dir("")
    except (SourceError, OSError) as exc:   # pragma: no cover
        log.warning("update-core: could not list the webroot root, so wpt's "
                    "own residue could not be swept or reported (%s)", exc)
        return []
    return sorted(
        (entry.path, entry.is_dir) for entry in entries
        if not entry.is_link and update_core_residue(entry.path) is not None
    )


def _wp_content_residue(source: "Source") -> list[str]:
    """The ``wp-content/`` residue DIRECTORIES currently on the site.

    Two existence probes, not a walk: both shapes are directories
    (``wp-content/upgrade/`` is a whole staging tree, ``wp-content/
    wpt-update/`` holds one package), so naming the directory is both the
    cheap answer and the answer an operator can act on.  A probe that
    fails is a warning, never a silent empty — a sweep that could not see
    is a sweep that cannot report.
    """
    out: list[str] = []
    for path in (_STAGING_DIR, _PACKAGE_DIR):
        try:
            there = source.exists(path)
        except (SourceError, OSError) as exc:   # pragma: no cover
            log.warning("update-core: could not check %s (%s) — its residue "
                        "is neither swept nor reported this run", path, exc)
            continue
        if there:
            out.append(path)
    return out


def _sweep_residue(source: "Source") -> None:
    """Clean (or report) every residue name in the webroot root.

    Runs LAST, on every exit from an apply — and that is the point: a run
    that was KILLED between two renames never reaches its own teardown,
    so the only place its residue can be cleaned (and, more importantly,
    SEEN) is the next run.  Which is why the rule is keyed on the NAMES
    in the webroot and not on anything this run remembers.

    What each role gets, from ``wpt.types.RESIDUE_OWNER`` — the one
    table the report below also reads, so the two cannot disagree:

    * staged / temp — removed.  Both are copies of bytes the live tree
      still holds (a partial write, or a complete one waiting for its
      rename), and leaving them behind is what makes ``wp core
      verify-checksums`` report an extra file and what once left a live
      site with ``index.php.wpt-tmp`` sitting next to ``index.php``.
    * retired — NEVER removed, and REPORTED with the live name it goes
      back to.  It is the last copy of the core the swap replaced; the
      operator or the pre-action snapshot owns that decision, and a sweep
      that deleted it would destroy the only hand-recovery path from a
      run that was killed or that failed its verify.

    A removal that fails is a WARNING naming the path — the operator must
    be able to SEE the residue — never a swallowed error and never a
    failed run over a leftover file.
    """
    found: list[str] = []
    for path, is_dir in _residue_entries(source):
        role = update_core_residue(path)
        if role == RESIDUE_RETIRED:
            found.append(path)     # reported, never removed (see below)
            continue
        _remove_quietly(
            source, path, directory=is_dir,
            note="remove it by hand if it survives; nothing reads it")
    # The two wp-content/ shapes, under the same one-rule discipline:
    # wpt's own uploaded package is REMOVED (it is a re-fetchable copy of
    # a public artifact and it is web-served while it exists), and core's
    # staging is only ever REPORTED here — clearing it is the verified
    # success path's job (see _clear_own_staging), because until the
    # verify passes it is the recovery path from a run that failed
    # mid-copy.
    for path in _wp_content_residue(source):
        if _residue_role(path) == RESIDUE_STAGING:
            found.append(path)
            continue
        _remove_quietly(
            source, path, directory=True,
            note="it is wpt's own uploaded release copy, re-fetchable from "
                 "wp.org; remove it by hand if it survives")
    # Whatever parked name survived the run is REPORTED here, with the
    # live name it goes back to.  On a successful apply there is none —
    # the caller discarded them once the verify passed — so this line is
    # the one an operator sees when a run failed after the swap, or when
    # it was killed: the copy of the core this site is running, and the
    # one rename that puts it back.
    _report_residue_paths(found)


def _residue_role(path: str) -> str | None:
    """The residue role of a webroot path, or None when it is not one.

    ONE classification for every consumer (the sweep, the report, the plan
    line), and it composes two owners that are two different path spaces:

    * the WEBROOT-ROOT names — staged / temp / retired — belong to
      ``wpt.types.update_core_residue``, the owner the whole toolkit
      shares (backup, restore and the audit's residue sweep all ask that
      function), and it is deliberately a ROOT-only rule: a path with a
      directory component in it is somebody else's file.
    * the two ``wp-content/`` shapes below belong to THIS module, because
      the shared root rule cannot reach them by construction.  They are
      named here rather than added to the shared owner precisely so the
      root rule stays root-only.
    """
    if path == _STAGING_DIR or path.startswith(f"{_STAGING_DIR}/"):
        return RESIDUE_STAGING
    if path == _PACKAGE_DIR or path.startswith(f"{_PACKAGE_DIR}/"):
        return RESIDUE_PACKAGE
    return update_core_residue(path)


def _report_residue(entries: list[Entry]) -> None:
    """REPORT every residue path the webroot carries, and who owns it.

    The visibility half of :func:`_sweep_residue`, and the reason a killed
    update is a diagnosable event instead of a silent one.  It runs on
    every plan, before any target is even named, and it is a REPORT: it
    never refuses and never mutates.

    It reads the walk's DIRECTORIES as well as its files, because three of
    the residue shapes are trees: a presence map built from files only
    (which is what the rest of this action needs) can never see a parked
    ``wp-includes.wpt-old/`` or core's ``wp-content/upgrade/`` staging.
    """
    _report_residue_paths(sorted(
        {entry.path for entry in entries
         if not entry.is_link and _residue_role(entry.path) is not None}))


def _report_residue_paths(found: list[str]) -> None:
    """The one report, over paths the shared rule has already classified.

    A parked name is named with the LIVE name it goes back to, because the
    recovery is a rename and an operator cannot do a rename they have not
    been told about — including the part that makes the rename possible
    at all, which is that whatever currently holds the live name has to
    be moved aside first (a killed run leaves a name in either state: not
    yet swapped, where the live name is free, or already swapped, where it
    is not).
    """
    if not found:
        return
    log.warning(
        "update-core: residue from an EARLIER core update is in this "
        "webroot — %d path(s) that no other check reports: %s",
        len(found), _named_paths(found))
    for path in found:
        role = _residue_role(path)
        live = (path[: -len(_RETIRED_SUFFIX)]
                if role == RESIDUE_RETIRED else path)
        owner = (RESIDUE_OWNER[role] if role in RESIDUE_OWNER
                 else CORE_UPGRADE_OWNER[role])
        log.warning("  %s — %s%s", path, owner,
                    f"; to put the installed core back, move whatever now "
                    f"holds {live} aside and rename this to {live}"
                    if role == RESIDUE_RETIRED else "")


def _clear_own_staging(source: "Source", staging: str | None) -> None:
    """Remove the staging THIS run created — only after the verify passed.

    ``wp-content/upgrade/`` is core's own staging area, so the sweep must
    not treat it as wpt's junk: on a site whose earlier core update died
    mid-copy it is the operator's recovery path, and a sweep that deleted
    it would destroy the only way back short of the snapshot.  So the rule
    is narrow on purpose — a staging path this run created (the op refuses
    to start when the directory already holds anything, so an operator's
    staging can never be mistaken for ours) AND a run whose verify passed
    AND an exact match on the path the op reported.

    Called from the apply's success path, immediately before the sweep
    that would otherwise report it, so a successful run leaves nothing of
    its own and a failed one leaves everything, named.
    """
    if not staging:
        return
    if not staging.startswith(f"{_STAGING_DIR}/"):
        log.warning("update-core: the core updater reported the staging "
                    "directory %s, which is outside %s — not touching it",
                    staging, _STAGING_DIR)
        return
    _remove_quietly(
        source, staging, directory=True,
        note="the update is verified and this run created it; remove it by "
             "hand if it survives (it is a copy of the release this run "
             "installed)")


def _discard_retired(source: "Source",
                     parked: list[tuple[str, bool]]) -> None:
    """Remove the copies the SUCCESSFUL swap parked.

    Called only after the verify passed, which is the whole reason the
    parked copy outlives the swap: up to that point it is the last copy
    of the installed core, and the hand-recovery path for a run that
    cannot prove what it did.  A removal that fails is a warning naming
    the path — the operator sees what is left and the snapshot still
    holds the bytes.
    """
    for path, directory in parked:
        _remove_quietly(
            source, path, directory=directory,
            note="the update is verified; remove it by hand if it survives "
                 "(it is a copy of the core this run replaced)")


def _undo_landed(source: "Source",
                 landed: list[tuple[str, str, str, bool, bool]]) -> None:
    """Put every landed name back, in REVERSE order, inside the same try.

    This is the difference between a failed swap and a broken site.  Each
    record is undone by two renames — the new name goes back to its
    staging name (which frees the live name), then the parked original
    comes back — so the site ends byte-for-byte where it started, whether
    the failure landed on the second tree or on the ninth root file.
    A per-tree undo cannot do that: it knows nothing about the roots, and
    it has already deleted the first tree's backup.

    A record whose own undo fails is reported by NAME with the state it
    left behind, because at that point a human (or the snapshot) is the
    only mechanism that can still put it right, and a silent half-undo is
    how a mixed core reaches production.
    """
    for name, staged, retired, installed, directory in reversed(landed):
        shape = "tree" if directory else "file"
        try:
            source.rename(name, staged, allow_core=True)
        except (SourceError, OSError, RunControl) as exc:
            # The NEW tree is still live: nothing moved, so the operator's
            # repair is the same two renames this record wanted (and the old
            # message's claim that NAME was empty was false here).
            log.error(
                "update-core: undoing the %s swap of %s failed at the "
                "move-out rename (%s) — %s still holds the NEW %s, %s "
                "still holds the INSTALLED one; rename %s to %s and %s "
                "back over %s by hand, or run `wpt restore --undo-last`",
                shape, name, exc, name, shape, retired, name, staged,
                retired, name,
            )
            continue
        try:
            if installed:
                source.rename(retired, name, allow_core=True)
        except (SourceError, OSError, RunControl) as exc:
            # The move-out SUCCEEDED: the live name is EMPTY until the
            # installed copy is renamed back.  Report the exact observed
            # state instead of claiming NAME still holds the new tree.
            log.error(
                "update-core: undoing the %s swap of %s failed at the "
                "restore rename (%s) — %s is now ABSENT, the NEW %s is "
                "parked at %s, the INSTALLED one is at %s; rename %s over "
                "%s by hand, or run `wpt restore --undo-last`",
                shape, name, exc, name, shape, staged, retired, retired,
                name,
            )
            continue
        log.info("update-core: undid the %s swap of %s — the installed %s "
                 "is back", shape, name, shape)


def _remove_quietly(source: "Source", path: str, *, directory: bool,
                    note: str) -> None:
    """Delete one of wpt's own webroot paths, or warn that it is still there.

    ``directory`` is the SHAPE this run created, never a guess re-derived
    from the site: the maintenance file is a file and the staged trees are
    directories, and over FTP the two primitives are not interchangeable
    (``rmdir_recursive`` LISTs its argument, so asking it to remove a
    FILE costs a 550 and removes nothing).  Guessing wrong here is what
    left a live site's ``.maintenance`` on disk for the length of
    WordPress's own expiry.
    """
    try:
        if not source.exists(path):
            return
    except (SourceError, OSError) as exc:   # pragma: no cover
        log.warning("update-core: could not check wpt's own %s (%s) — %s",
                    path, exc, note)
        return
    try:
        if directory:
            source.rmdir_recursive(path)
        else:
            source.delete(path)
    except (SourceError, OSError) as exc:   # pragma: no cover
        log.warning("update-core: could not remove wpt's own %s (%s) — %s",
                    path, exc, note)


# ------------------------------------------------------------------ helpers


def _marker_sentence(bridge: "Bridge", site: _Site) -> str:
    """What the migration left behind, in one sentence, for a lost answer.

    A fatal inside ``wp_upgrade()`` destroys the response, so this is the
    only diagnosis a run can offer: the pre-migration marker the op wrote
    to the options table BEFORE it started (read back through ``info``),
    and — when even that is unreadable — the schema version this run
    measured before it began.  The state the migration began in is the
    fact an operator needs to decide between "re-run the migration" and
    "restore the database".
    """
    try:
        marker = bridge.upgrade_marker()
    except (BridgeError, OSError) as exc:
        marker = None
        log.warning("update-core: the pre-migration marker could not be "
                    "read back either (%s)", exc)
    if not marker:
        return (f"db_version {site.db_version} was read before the "
                f"migration started, and no marker survived it")
    finished = marker.get("finished")
    return (
        f"the migration began at unix {marker.get('started')} from "
        f"db_version {marker.get('from_db_version')} heading for "
        f"{marker.get('target_db_version')} on WordPress "
        f"{marker.get('wp_version')}"
        + ("" if finished is None
           else f", and its marker says it finished at {finished}")
        + (f" (this run had read db_version {site.db_version} beforehand)"
           if site.db_version is not None else "")
    )


def _requested_target(ctx: "Ctx") -> str | None:
    """The ``--to`` target, or None.  The ONLY implicit-target door."""
    raw = (ctx.extra or {}).get("to")
    if raw is None:
        return None
    if not isinstance(raw, str) or not raw.strip():
        raise WptError(
            "refusing an empty --to target — name the version to install "
            "(for example --to 7.1.2)"
        )
    return raw.strip()


def _allow_pre_release(ctx: "Ctx") -> bool:
    """``--allow-pre-release`` (tri-state) over ``update.pre_release_allowed``.

    Tri-state exactly like ``webp.purge_originals``: the FLAG wins when
    typed, and the profile key decides only in the "not typed" state.
    """
    if (ctx.extra or {}).get("allow_pre_release") is True:
        return True
    return bool(ctx.settings.update.pre_release_allowed)


def _fetch_status(session: requests.Session, url: str, ctx: "Ctx",
                  label: str, *, render: bool,
                  deadline: Deadline | None = None) -> None:
    """Fetch one URL after the update; raise unless it answers acceptably.

    ``render=True`` demands a 2xx (the site must actually render the page
    a visitor asks for); ``render=False`` demands any non-5xx answer (the
    REST root 404s legitimately on a plain-permalink install, but a 5xx
    there is a fatal).  The response is closed without reading the body:
    this probe proves the site ANSWERS, it never inspects content.

    ``deadline`` is the run's absolute budget: an expired budget raises
    BEFORE the probe, and a real session is driven through the shared
    bounded GET under ``min(Deadline.at, now + http.timeout_s)`` so neither
    a dripped header nor a long run budget can outlive the other bound.
    A per-request timeout is a VERIFICATION failure (naming the snapshot);
    only a spent run budget is a cooperative stop.
    """
    if deadline is not None:
        deadline.check(f"update verification {label}")
    timeout_s = ctx.settings.http.timeout_s
    transport_deadline = time.monotonic() + max(0.001, float(timeout_s))
    if deadline is not None:
        transport_deadline = min(deadline.at, transport_deadline)
    try:
        # ALWAYS the bounded transport, including ``--deadline 0``: requests'
        # ``timeout`` is per-read, so a 0.08 s/byte header drip held the
        # post-update verify for 5-6 s (or indefinitely).  A non-real session
        # double still receives the same ``get(timeout=..., stream=True)``
        # contract inside get_bounded.
        response = get_bounded(
            session, url, timeout_s=timeout_s,
            deadline=transport_deadline, allow_redirects=True,
        )
    except (requests.RequestException, WptError) as exc:
        if deadline is not None and deadline.remaining <= 0:
            # The bounded GET's header/body timeout is the RUN budget, not
            # a site verdict: report the cooperative stop so the registry's
            # deadline path (with its snapshot-rollback wording) owns it.
            raise DeadlineExceeded(
                f"run deadline exceeded at update verification {label!r} — "
                "the update probe was abandoned") from None
        raise WptError(
            f"verification failed: the {label} ({redact_text(url)}) did not "
            f"answer ({redact_text(str(exc))}) — the update is NOT done; the "
            f"pre-action snapshot is the rollback"
        ) from exc
    status = response.status_code
    close = getattr(response, "close", None)
    if callable(close):
        close()
    failed = status >= 500 if not render else not 200 <= status < 300
    if failed:
        raise WptError(
            f"verification failed: the {label} answered HTTP {status} after "
            f"the update — the site is not serving normally; the update is "
            f"NOT done; the pre-action snapshot is the rollback"
        )


def _mark_done(plan: Plan) -> None:
    """Every item flips ``done`` — only ever called after the digests pass."""
    for item in plan.items:
        item.done = True


def _wporg_transport(ctx: "Ctx", stack: tuple
                     ) -> tuple[requests.Session, int]:
    """(session, timeout_s) for the wp.org fetches.

    ftp: the stack's session — the audit's own wp.org transport
    (DNS-override-aware when ``--override-ip`` is set; only
    api.wordpress.org / downloads.wordpress.org are ever requested).
    local: a fresh plain session — the SITE is offline, the wp.org
    reference data is not.  The timeout is the profile's
    ``http.timeout_s`` in both modes.
    """
    if stack[2] is None:
        return requests.Session(), ctx.settings.http.timeout_s
    return stack[1], ctx.settings.http.timeout_s


def _offers(ctx: "Ctx", stack: tuple) -> list[dict[str, Any]]:
    """The version-check offers, or a refusal naming the network fault.

    The whole action is version-check-driven — what exists, what its
    floors are — so an unavailable list is a refusal, never a degradation
    to "no update available", which would be a claim about the SITE.
    """
    session, timeout_s = _wporg_transport(ctx, stack)
    with owned_session(session, stack[2] is None):
        offers = WpOrgApi(
            session, timeout_s,
            deadline=getattr(Deadline.from_ctx(ctx), "at", None),
            config=ctx.settings.wp_org,
        ).core_version_offers()
    if not offers:
        raise WptError(
            "cannot plan an update: the wp.org core version-check API is "
            "unavailable and nothing valid is cached — there is no list to "
            "choose a target from; retry when wp.org answers"
        )
    return offers


def _offer_for(offers: list[dict[str, Any]], version: str) -> _Offer:
    """The offer for ``version`` (the caller has already refused an unoffered one)."""
    for raw in offers:
        if version in (raw["version"], raw["current"]):
            return _Offer(version=version, php_floor=raw["php_version"],
                          mysql_floor=raw["mysql_version"])
    return _Offer(version=version)   # pragma: no cover - refused upstream


def _digests_bridge(bridge: "Bridge", paths: list[str], *,
                    deadline: "Deadline | None" = None
                    ) -> tuple[dict[str, str | None], list[str]]:
    """``(md5 per path, unreadable paths)`` over the bridge's ``core_md5``.

    Batched at the bridge's own per-call cap (``_CORE_MD5_BATCH``,
    integrity's mirror of the PHP constant) so a release with more files
    than one call accepts is measured in full instead of refused by the
    wire.  A payload this action cannot read is an UNREADABLE path, not a
    silent zero: a digest it never got is a digest it will not claim.
    """
    digests: dict[str, str | None] = {}
    unreadable: list[str] = []
    for start in range(0, len(paths), _CORE_MD5_BATCH):
        if deadline is not None:
            deadline.check("core update digest read")
        batch = paths[start:start + _CORE_MD5_BATCH]
        try:
            payload = bridge.call(
                "core_md5", paths=batch, **transport_kwargs(deadline))
        except Exception as exc:
            log.warning("core integrity skipped: core_md5 unavailable (%s)",
                        exc)
            unreadable.extend(batch)
            continue
        files = payload.get("files") if isinstance(payload, dict) else None
        listed = set(payload.get("unreadable") or []) if isinstance(
            payload, dict) else set()
        if not isinstance(files, dict):
            unreadable.extend(batch)
            continue
        for path in batch:
            digest = files.get(path)
            if isinstance(digest, str) and path not in listed:
                digests[path] = digest
            else:
                digests[path] = None
                unreadable.append(path)
    return digests, unreadable


def _digests_source(source: "Source", paths: list[str], *,
                    deadline: "Deadline | None" = None
                    ) -> tuple[dict[str, str | None], list[str]]:
    """``(md5 per path, unreadable paths)`` through the source's bulk reader.

    The local twin of :func:`_digests_bridge`: the overlay and the zip
    both answer ``read_many``, and a path in neither answer bucket is
    unreadable — never assumed good.
    """
    digests: dict[str, str | None] = {}
    unreadable: list[str] = []
    for start in range(0, len(paths), _CORE_MD5_BATCH):
        if deadline is not None:
            deadline.check("core update digest read")
        batch = paths[start:start + _CORE_MD5_BATCH]
        ok, failed = source.read_many(batch)
        for path in batch:
            if path in ok:
                digests[path] = hashlib.md5(ok[path]).hexdigest()
            else:
                digests[path] = None
                unreadable.append(path)
    return digests, unreadable


# The registry stores the decorated OBJECT and calls .plan/.apply on it
# (the deactivate/clean_files precedent: a bare class would be invoked
# with plan(ctx, stack) unbound and crash in run_action).
register_action("update-core", applies=("ftp", "local"))(UpdateCoreAction())
