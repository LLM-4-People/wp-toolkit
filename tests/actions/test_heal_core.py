"""Tests for the heal-core action (wpt.actions.heal_core).

NO network: the wp.org fetches ride the real WpOrgApi transport over
the shared FakeSession (tests/audit/test_integrity.py conventions) with
the response cache monkeypatched to a tmp_path via ``updates._CACHE_DIR``
— or SEEDED (checksums JSON / release-zip bytes) for the local-mode
runs, whose fresh plain session cannot be scripted.  Release zips are
small REAL in-memory zips, ``wordpress/``-nested like the official
releases (tests/audit/test_updates.py's release_zip_bytes shape).

The ftp-mode bridge is a double recording every call and modeling the
LIVE server for core_md5: it digests the SAME HealSource store the
apply writes to (write_bytes "lands on the server"; core_md5 reads it
back) — one store, two views, so a done item proves the digest round
trip.  HealSource extends the shared FakeSource with the two heal pins:
every write_bytes records its kwargs (the allow_core=True audited
unlock) and the shared write guard runs with allow_core forwarded (the
shared tests/fakes.py double accepts the kwarg but drops it — reported
to the coordinator; without the forwarding every core write would hit
NotWritableError).

Test -> behavior map:
  test_registration .......................... heal-core registered as the
        INSTANCE under applies=("ftp", "local") — both modes reachable
  test_plan_tampered_and_missing_items ....... ftp plan: tampered +
        missing -> exact items, (kind, path) sorted, category
        core.integrity, detail "<kind> — restore the official WP <V>
        <locale> file" (the EFFECTIVE COMPARISON LOCALE, the basis the
        audit finding's detail also names), bytes_est = walked size
        (0 for missing); requires_apply,
        not done; backup_tables == [] deliberately; the walk precedes
        the first bridge call; the checksums request shape pinned
        (live-verified URL + locale, UA wpt/, profile timeout)
  test_plan_added_files_are_notes_not_items .. added wp-admin/top-level
        php: NO items, ONE investigate-only info naming both paths;
        wp-config.php (user file) never planned
  test_plan_nothing_to_heal .................. clean core -> EMPTY plan +
        the "nothing to heal" info; added-only -> same empty plan + the
        added-only line
  test_plan_unknown_version_refuses .......... info wp_version None/""
        -> WptError "unknown WordPress version", zero wp.org traffic
  test_plan_checksums_unavailable_refuses .... failed checksums fetch ->
        WptError "no comparison basis"; classification never reached
        (no core_md5 call)
  test_plan_core_md5_failure_refuses ......... core_md5 raising -> the
        primitive's own ONE warning + WptError naming core_md5
  test_plan_local_classification ............. local: version from
        wp-includes/version.php through the source (the gather's seam —
        the tampered file still parses, the live vbs shape),
        classification through affected_files_local (read_many over the
        fake source), cache-served checksums — the fresh plain session
        never touches the network
  test_plan_local_unknown_version_refuses .... no version.php in the
        tree -> the same unknown-version refusal
  test_apply_restores_and_verifies ........... full plan+apply over the
        fake ftp stack: every write carries allow_core=True; the unlock
        pinned SURGICAL (the same core path refuses without it;
        allow_core never unlocks wp-config.php/.htaccess); restored
        bytes ARE the zip's official bytes; done flips only via the
        verify core_md5 (bridge traffic pinned: info, core_md5, info,
        core_md5 — the verify covering exactly the healed paths); ONE
        checksums GET + ONE zip GET (the verify re-fetch is a fresh
        cache hit); the zip caches under .wpt-cache
  test_apply_zip_missing_path_skipped ......... one planned file the
        release zip does not ship: ONE warning, done stays False, the
        sibling still heals, terminal WptError "heal incomplete: 1 of
        2" naming it — never an abort mid-item
  test_apply_verify_mismatch_not_done ......... the zip's bytes disagree
        with the checksums map: the write lands, the digest proof
        fails, ONE warning, not-done, terminal WptError naming the path
  test_apply_write_failure_continues .......... a write failure on one
        item (a scripted STOR error): ONE warning + continue, the
        sibling still heals and verifies, terminal WptError naming the
        failed path — never a mid-apply abort
  test_apply_verify_mandatory_failures ........ core_md5 raising / a
        non-dict payload / a bad-buckets payload: each -> WptError
        "cannot verify the heal" naming the reason; the writes that
        already landed stay unclaimed (done False)
  test_apply_fr_ca_zip_404_falls_back_en_us  [L19] a 404 for the
        localized build => ONE warning + the en_US release, and the
        paths both builds ship IDENTICALLY are still healed (the
        restored bytes verify under the en_US map AND the audit's fr_CA
        basis); the en_US zip is cached, the failed locale fetch is not
  test_apply_fr_ca_zip_404_differing_path_unrestorable  [L19] the loop
        the en_US fallback used to create: a path whose official digests
        DIFFER between the two builds (wp-includes/version.php) is
        reported UNRESTORABLE — one warning, no write, terminal
        "heal incomplete" — so heal-core never writes bytes the audit
        would flag on every run
  test_apply_restore_basis_checksums_unavailable_refuses_before_writes
        the restore-basis map IS the verification map, so it is fetched
        before the writes: unavailable => "cannot verify the heal" with
        NOTHING written
  test_apply_en_us_build_never_heals_locale_bytes  [L17] an en_US BUILD
        with WPLANG=fr_CA (a language pack) plans and heals from the
        en_US release only — the fr_CA map/zip is never requested
  test_apply_fr_ca_missing_top_level_php_from_the_fr_ca_zip  [L17]+[L18]
        a missing TOP-LEVEL functional core file is restored from the
        fr_CA zip (same locale basis as the audit, scope rule
        mode-blind)
  test_plan_skips_junk_demanded_map_path  [L19] wp-config-sample.php is
        a map path AND a webroot_junk pattern: never planned, while
        wp-cron.php in the same tree is
  test_apply_local_rehearsal_junk_vs_missing  [L19]+[L18] the rehearsal
        creates wp-cron.php and leaves wp-config-sample.php absent —
        the clean-files fixed point, end to end
  test_plan_drops_translation_catalogs  [L19] heal-core runs the SAME
        translation-pack pass the audit check runs (a pristine wp.org
        language pack is never a heal target)
  test_apply_empty_plan_no_work ............... zero planned files -> no
        wp.org fetch, no bridge roundtrip, plan returned as-is
  test_apply_local_rehearsal .................. the REAL registry local
        flow (run_action --apply --yes over a real zip + seeded caches):
        rc 0, rehearsed 2/2, the original zip byte-identical, and the
        materialized site-rehearsed-<ts>.zip carries the healed official
        bytes (overlay write + read_many verify + materialize, the
        tests/actions/test_clean_files.py rehearsal pattern)
  test_registry_ftp_apply_end_to_end .......... run_action --apply --yes
        over the fake ftp stack: rc 0; the fail-closed pre-action
        snapshot manifest = the tampered original CAPTURED + the missing
        target as an ABSENT entry (restore reverts the whole heal);
        bridge traffic info/core_md5/info/core_md5/purge_cache; the
        report prints every item done
"""

import hashlib
import io
import json
import logging
import zipfile

import pytest
import requests

import wpt.audit.integrity as integrity
import wpt.audit.updates as updates
from tests.fakes import FakeResponse, FakeSession, FakeSource
from wpt.actions import registry as registry_mod
from wpt.actions.heal_core import HealCoreAction
from wpt.actions.registry import get_action, run_action
from wpt.cli import Ctx
from wpt.deadline import Deadline
from wpt.report import Plan, PlanItem
from wpt.settings import load
from wpt.types import (BridgeError, DeadlineExceeded, NotWritableError,
                       SourceError, WptError)

#: The shipped profile — the action consumes only http.timeout_s.
DEFAULTS = load()

SITE = "https://example.com"

VERSION = "6.8.3"
OFFICIAL_VERSION_PHP = b"<?php\n$wp_version = '6.8.3';\n"
OFFICIAL_GONE_JS = b"/* official gone.js */\n"
EVIL = b"<?php // EVIL BACKDOOR\n"
INDEX = b"<?php // index\n"

#: The local-mode twin: a tampered wp-includes/version.php that STILL
#: parses (the live vbs shape — the version seam survives the tamper).
LOCAL_VERSION = "6.6.2"
LOCAL_OFFICIAL_VERSION_PHP = b"<?php\n$wp_version = '6.6.2';\n"
LOCAL_TAMPERED_VERSION_PHP = (
    b"<?php\n$wp_version = '6.6.2';\n// injected backdoor\n"
)

#: [L17] The fr_CA build shape (the live migration): the localized
#: build's version.php carries the $wp_local_package marker, and the
#: tampered file KEEPS it — the resolver keys the heal to the fr_CA
#: build either from the marker or from the WPLANG site locale.
FR_CA = "fr_CA"
FR_CA_OFFICIAL_VERSION_PHP = (
    b"<?php\n$wp_version = '6.8.3';\n$wp_local_package = 'fr_CA';\n"
)
FR_CA_TAMPERED_VERSION_PHP = (
    b"<?php\n$wp_version = '6.8.3';\n$wp_local_package = 'fr_CA';\n"
    b"// injected backdoor\n"
)
#: A top-level functional core file [L18]: the live migration had
#: wp-cron.php and sibling core files DELETED by the old host.
OFFICIAL_WP_CRON = b"<?php\n/* wp-cron */\n"


@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    """Point the SHARED wp.org cache (owned by updates.py) at a tmp dir
    (tests/audit/test_integrity.py's fixture) — no test ever touches the
    CWD's real .wpt-cache."""
    d = tmp_path / "cache"
    monkeypatch.setattr(updates, "_CACHE_DIR", d)
    return d


# ------------------------------------------------------------------ doubles


def md5(blob: bytes) -> str:
    return hashlib.md5(blob).hexdigest()


class HealSource(FakeSource):
    """FakeSource + the heal pins: every write_bytes records its
    (path, kwargs) — the allow_core=True audited unlock — and the shared
    write guard runs with allow_core FORWARDED (the shared tests/
    fakes.py double accepts the kwarg but drops it, so the guard would
    refuse every core write; reported to the coordinator)."""

    def __init__(self) -> None:
        super().__init__()
        self.writes: list[tuple[str, dict]] = []

    def write_bytes(self, path, data, *, allow_config=False,
                    allow_core=False):
        self._check_writable(path, allow_config, allow_core)
        self.writes.append((path, {"allow_config": allow_config,
                                   "allow_core": allow_core}))
        self._rec("write", path)
        self.files[path] = data


class HealBridge:
    """Bridge double for heal-core's two calls (+ the registry's
    purge_cache/destroy).

    ``info`` answers the scripted ``wp_version`` + ``locale`` (None
    models the unknown version; the locale key is OMITTED when the
    double was built without one — the pre-locale wire shape, kept
    backward-compatible).  ``core_md5`` plays ONE scripted item per
    call (a payload, an Exception — mirroring client.py's BridgeError
    raise for error envelopes — or a callable ``(params) -> payload``);
    with no script left it models the LIVE server: it digests the SAME
    HealSource store the apply writes to (absent paths land in
    ``missing``), so a verified heal proves the write→digest round
    trip.  Every call is recorded."""

    def __init__(self, source, wp_version=VERSION, script=(),
                 locale=None) -> None:
        self.source = source
        self.wp_version = wp_version
        self.script = list(script)
        self.locale = locale
        self.calls: list[tuple[str, dict]] = []
        self.destroyed = 0

    def call(self, action, **params):
        self.calls.append((action, params))
        if action == "info":
            payload = {"wp_version": self.wp_version}
            if self.locale is not None:
                payload["locale"] = self.locale
            return payload
        if action == "core_md5":
            if self.script:
                item = self.script.pop(0)
                if callable(item):
                    item = item(params)
                if isinstance(item, Exception):
                    raise item
                return item
            digests: dict[str, str] = {}
            missing: list[str] = []
            for path in params["paths"]:
                blob = self.source.files.get(path)
                if blob is None:
                    missing.append(path)  # nothing there — live semantics
                else:
                    digests[path] = md5(blob)
            return {"ok": True, "files": digests, "missing": missing,
                    "unreadable": []}
        if action == "purge_cache":  # the registry's post-apply hygiene
            return {"ok": True, "purged": True}
        raise AssertionError(f"unexpected bridge action: {action!r}")

    def destroy(self):
        self.destroyed += 1


class _FailingWriteSource(HealSource):
    """HealSource whose write_bytes raises SourceError on ``fail_path``
    — an ftp STOR failure model for the per-item write-failure path
    (the guard boundary itself is pinned in the restore-and-verify
    test: the same core path refuses without the unlock)."""

    def __init__(self, fail_path: str) -> None:
        super().__init__()
        self.fail_path = fail_path

    def write_bytes(self, path, data, *, allow_config=False,
                    allow_core=False):
        if path == self.fail_path:
            raise SourceError(f"STOR failed: {path}")
        super().write_bytes(path, data, allow_config=allow_config,
                            allow_core=allow_core)


# ------------------------------------------------------------------ helpers


def _ctx(tmp_path, **overrides):
    """A heal-core Ctx; ftp-mode defaults, overridable per test."""
    fields = dict(
        source="ftp://example.com",
        settings=DEFAULTS,
        command="heal-core",
        apply=False,
        yes=False,
        backup_dir=tmp_path / "backup",
        wp_url=SITE,
    )
    fields.update(overrides)
    return Ctx(**fields)


def make_stack(script=(), *, files=None, wp_version=VERSION,
               bridge_script=(), locale=None):
    """A fake ftp-mode heal stack: (HealSource, FakeSession, HealBridge)."""
    src = HealSource()
    src.files.update(files or {})
    session = FakeSession(list(script))
    bridge = HealBridge(src, wp_version=wp_version, script=bridge_script,
                        locale=locale)
    return src, session, bridge


def checksums_response(checksums: dict[str, str]) -> FakeResponse:
    """A live-shaped core/checksums/1.0 payload."""
    return FakeResponse(text=json.dumps({"checksums": checksums}))


def release_zip_bytes(files: dict[str, bytes]) -> bytes:
    """A small REAL in-memory release zip, ``wordpress/``-nested like
    the official releases (the nesting fetch_core_release_zip validates
    and apply strips)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for rel, blob in files.items():
            zf.writestr("wordpress/" + rel, blob)
    return buf.getvalue()


def seed_checksums(cache_dir, version: str, checksums: dict[str, str],
                   locale: str = "en_US"):
    """A FRESH checksums cache entry: the real WpOrgApi transport serves
    it without any network (the local-mode fresh plain session cannot
    be scripted — tests/audit/test_integrity.py's seed pattern)."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / (
        updates._cache_key(integrity._checksums_url(version, locale), None)
        + ".json"
    )
    path.write_text(json.dumps({"checksums": checksums}), encoding="utf-8")
    return path


def seed_release_zip(cache_dir, version: str, payload: bytes,
                     locale: str = "en_US"):
    """A FRESH release-zip cache entry (raw bytes at the transport's own
    wp-release-<version>[-<locale>].zip name)."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    name = (f"wp-release-{version}.zip" if locale == "en_US"
            else f"wp-release-{version}-{locale}.zip")
    path = cache_dir / name
    path.write_bytes(payload)
    return path


def _records(wpt_records, level):
    return [r for r in wpt_records
            if r.name == "wpt.actions.heal_core" and r.levelno == level]


def _messages(records):
    return [r.getMessage() for r in records]


# ------------------------------------------------------------- registration


def test_registration():
    record = get_action("heal-core")
    assert record is not None
    assert record.applies == ("ftp", "local")
    assert isinstance(record.action, HealCoreAction)  # the instance


# ------------------------------------------------------------- plan (ftp)


def test_plan_tampered_and_missing_items(tmp_path, cache_dir):
    files = {
        "index.php": INDEX,                    # clean (matches the map)
        "wp-includes/version.php": EVIL,       # digest differs -> tampered
        # wp-includes/js/gone.js absent          -> missing
    }
    checksums = {
        "index.php": md5(INDEX),
        "wp-includes/version.php": md5(OFFICIAL_VERSION_PHP),
        "wp-includes/js/gone.js": md5(OFFICIAL_GONE_JS),
    }
    src, session, bridge = make_stack(
        [checksums_response(checksums)], files=files,
    )
    plan = HealCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    assert [
        (i.category, i.target, i.detail, i.bytes_est) for i in plan.items
    ] == [
        ("core.integrity", "wp-includes/js/gone.js",
         f"missing — restore the official WP {VERSION} en_US file", 0),
        ("core.integrity", "wp-includes/version.php",
         f"tampered — restore the official WP {VERSION} en_US file",
         len(EVIL)),
    ]
    assert all(i.requires_apply for i in plan.items)
    assert all(not i.done for i in plan.items)
    assert plan.backup_tables == []  # files only — the deliberate pin
    # the request shape: the live-verified checksums URL (version +
    # locale), the identifying UA, the profile timeout, GET-only
    assert len(session.gets) == 1 and session.posts == []
    url, kw = session.gets[0]
    assert url == integrity._checksums_url(VERSION)
    assert "core/checksums/1.0/?version=6.8.3&locale=en_US" in url
    assert kw["headers"]["User-Agent"].startswith("wpt/")
    assert kw["timeout"] == DEFAULTS.http.timeout_s
    # the classification: ONE bulk core_md5 over the map's paths
    assert bridge.calls == [
        ("info", {}),
        ("core_md5", {"paths": list(checksums)}),
    ]


def test_plan_added_files_are_notes_not_items(tmp_path, cache_dir,
                                              wpt_records):
    files = {
        "wp-includes/version.php": EVIL,        # tampered -> an item
        "wp-admin/rogue.php": b"<?php /* added */",
        "rogue.php": b"<?php /* top-level added */",
        "wp-config.php": b"<?php // user config",  # never added, never planned
    }
    checksums = {"wp-includes/version.php": md5(OFFICIAL_VERSION_PHP)}
    src, session, bridge = make_stack(
        [checksums_response(checksums)], files=files,
    )
    plan = HealCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    # added files produce NO items; only the tampered file heals
    assert [i.target for i in plan.items] == ["wp-includes/version.php"]
    assert not any("rogue" in i.target for i in plan.items)
    assert not any(i.target == "wp-config.php" for i in plan.items)
    # ONE investigate-only note naming every added path
    infos = _messages(_records(wpt_records, logging.INFO))
    assert len(infos) == 2  # the added note + the plan summary
    assert "investigate-only, not healed" in infos[0]
    assert "rogue.php" in infos[0] and "wp-admin/rogue.php" in infos[0]
    assert "never auto-deleted" in infos[0]
    assert "1 core file(s) to heal" in infos[1]


def test_plan_nothing_to_heal(tmp_path, cache_dir, wpt_records):
    # a clean core: empty plan, one info naming it
    src, session, bridge = make_stack(
        [checksums_response({"index.php": md5(INDEX)})],
        files={"index.php": INDEX},
    )
    plan = HealCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    assert plan.items == []
    assert plan.backup_tables == []
    infos = _messages(_records(wpt_records, logging.INFO))
    assert infos == ["plan: nothing to heal; the core matches the "
                     "official en_US 6.8.3 checksums"]

    # added-only: same empty plan, the added-only line instead
    src, session, bridge = make_stack(
        [checksums_response({"index.php": md5(INDEX)})],
        files={"index.php": INDEX, "wp-admin/rogue.php": b"<?php /* x */"},
    )
    plan = HealCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    assert plan.items == []
    infos = _messages(_records(wpt_records, logging.INFO))
    assert len(infos) == 2  # one per sub-case above
    assert "nothing to heal" in infos[-1]
    assert "investigate-only, not healed" in infos[-1]
    assert "wp-admin/rogue.php" in infos[-1]


def test_plan_version_skewed_theme_not_healed(tmp_path, monkeypatch,
                                              cache_dir, wpt_records):
    """[L12] A pristine default-theme AUTO-UPDATE past the core-bundled
    copy classifies tampered against the bundled checksums — and must
    NOT be healed: restoring the bundled bytes would DOWNGRADE the
    theme.  The plan runs the same resolve_theme_skew pass the audit
    check runs, so plan and audit can never disagree."""
    tt5 = "twentytwentyfive"
    style_15 = b"/*\nTheme Name: Twenty Twenty-Five\nVersion: 1.5\n*/\n"
    style_14 = b"/*\nTheme Name: Twenty Twenty-Five\nVersion: 1.4\n*/\n"
    checksums = {
        "index.php": md5(INDEX),
        f"wp-content/themes/{tt5}/style.css": md5(style_14),
    }
    seed_checksums(cache_dir, VERSION, checksums)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(f"{tt5}/style.css", style_15)
    (cache_dir / f"theme-{tt5}-1.5.zip").write_bytes(buf.getvalue())

    # ftp mode: the server digests via the fake bridge (style.css is the
    # pristine 1.5, the map says 1.4 => tampered), then the skew pass
    # resolves it against the seeded official 1.5 zip — no heal item
    src, session, bridge = make_stack(
        [], files={"index.php": INDEX,
                   f"wp-content/themes/{tt5}/style.css": style_15},
    )
    plan = HealCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    assert plan.items == []  # the pristine 1.5 file is NOT a heal item
    assert [c[0] for c in bridge.calls] == ["info", "core_md5"]
    # the skew pass's info line comes from the integrity module (its
    # logger), not the action's
    skew_infos = [
        r.getMessage() for r in wpt_records
        if r.name == "wpt.audit.integrity" and r.levelno == logging.INFO
    ]
    assert len(skew_infos) == 1 and f"{tt5}/style.css" in skew_infos[0]
    assert any("nothing to heal" in m
               for m in _messages(_records(wpt_records, logging.INFO)))

    # the CONTROL: with the theme zip UNAVAILABLE (empty cache + a
    # scripted 404), the same file stays tampered and IS planned — the
    # conservative direction, so a temporary wp.org outage can never
    # silently skip real healing
    empty_cache = cache_dir.parent / "empty-cache"
    empty_cache.mkdir()
    monkeypatch.setattr(updates, "_CACHE_DIR", empty_cache)
    src2, session2, bridge2 = make_stack(
        [checksums_response(checksums), FakeResponse(status_code=404)],
        files={"index.php": INDEX,
               f"wp-content/themes/{tt5}/style.css": style_15},
    )
    plan2 = HealCoreAction().plan(
        _ctx(tmp_path), (src2, session2, bridge2)
    )
    assert [(i.target, i.detail) for i in plan2.items] == [
        (f"wp-content/themes/{tt5}/style.css",
         f"tampered — restore the official WP {VERSION} en_US file"),
    ]


def test_R20_heal_plan_that_swallows_the_deadline_ends_rc1(
        tmp_path, monkeypatch, wpt_records):
    """R20-P1 (the 10 ms/50 ms shape): the checksum fetch outlives the run
    budget, then ``affected_files_local`` swallows the DeadlineExceeded and
    returns a partial classification.  The registry's post-plan/emit checks
    must end rc 1 with the failure pair, never print the partial plan as a
    success."""
    import time

    import wpt.actions.heal_core as heal_mod
    import wpt.actions.registry as registry_mod

    src = FakeSource()
    src.files.update({
        "wp-includes/version.php": LOCAL_OFFICIAL_VERSION_PHP,
        "index.php": INDEX,
    })

    def slow_fetch(*_args, **_kwargs):
        time.sleep(0.05)          # 50 ms against a 10 ms budget
        return {"index.php": md5(INDEX)}, "en_US"

    monkeypatch.setattr(heal_mod, "_fetch_comparison_checksums", slow_fetch)
    monkeypatch.setattr(registry_mod, "_stack",
                        lambda ctx: (src, None, None))
    report = tmp_path / "heal.md"
    ctx = Ctx(source="local", settings=DEFAULTS, command="heal-core",
              zip=tmp_path / "site.zip", sql=None, backup_dir=tmp_path / "b",
              deadline_s=0.01, report_path=report)
    assert registry_mod.run_action(ctx, "heal-core") == 1
    written = report.read_text(encoding="utf-8")
    assert "## This run did not complete" in written
    assert "deadline" in written.lower()
    assert "| yes |" not in written


def test_R20_theme_skew_fallback_is_wired_from_heal(tmp_path, cache_dir,
                                                    monkeypatch):
    """The heal-core twin of the check wiring: its plan passes the same
    configured fallback into resolve_theme_skew."""
    import wpt.actions.heal_core as heal_mod

    calls = []

    def fake(affected, *args, **kwargs):
        calls.append(kwargs.get("max_file_bytes"))
        return affected

    monkeypatch.setattr(heal_mod, "resolve_theme_skew", fake)
    settings = load(overrides={"files.max_file_bytes": 7654321})
    tt5 = "twentytwentyfive"
    style_15 = b"/*\nTheme Name: Twenty Twenty-Five\nVersion: 1.5\n*/\n"
    style_14 = b"/*\nTheme Name: Twenty Twenty-Five\nVersion: 1.4\n*/\n"
    seed_checksums(cache_dir, VERSION, {
        "index.php": md5(INDEX),
        f"wp-content/themes/{tt5}/style.css": md5(style_14),
    })
    src, session, bridge = make_stack(
        [], files={"index.php": INDEX,
                   f"wp-content/themes/{tt5}/style.css": style_15})
    HealCoreAction().plan(_ctx(tmp_path, settings=settings),
                          (src, session, bridge))
    assert calls == [7654321]


def test_R11_an_expired_budget_refuses_before_a_wporg_request(
        tmp_path, monkeypatch):
    """R11-P1-1: heal-core's checksums/zip transports ignored the run
    Deadline, so an expired run still started a wp.org request."""
    import wpt.actions.heal_core as heal_mod

    src, session, bridge = make_stack(files={"index.php": INDEX})
    monkeypatch.setattr(heal_mod.Deadline, "from_ctx",
                        lambda _ctx: Deadline(-1))
    ctx = _ctx(tmp_path)

    with pytest.raises(DeadlineExceeded):
        HealCoreAction().plan(ctx, (src, session, bridge))
    assert session.gets == [] and session.posts == []

    plan = Plan(items=[PlanItem(
        category="core.integrity", target="index.php",
        detail="tampered", bytes_est=1)])
    with pytest.raises(DeadlineExceeded):
        HealCoreAction().apply(ctx, (src, session, bridge), plan)
    assert session.gets == [] and session.posts == []


def test_plan_unknown_version_refuses(tmp_path):
    for bad in (None, ""):
        src, session, bridge = make_stack([], wp_version=bad)
        with pytest.raises(WptError, match="unknown WordPress version"):
            HealCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
        assert session.gets == []  # refused before any wp.org traffic
        assert [a for a, _p in bridge.calls] == ["info"]


def test_plan_checksums_unavailable_refuses(tmp_path, cache_dir,
                                            wpt_records):
    src, session, bridge = make_stack(
        [requests.ConnectionError("boom")], files={"index.php": INDEX},
    )
    with pytest.raises(WptError, match="no comparison basis"):
        HealCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    # classification never ran: one info call, no core_md5
    assert [a for a, _p in bridge.calls] == ["info"]
    # the transport's own one warning for the failed fetch
    transport = [r.getMessage() for r in wpt_records
                 if r.name == "wpt.audit.updates"
                 and r.levelno == logging.WARNING]
    assert len(transport) == 1 and "no cached response" in transport[0]


def test_plan_core_md5_failure_refuses(tmp_path, cache_dir, wpt_records):
    src, session, bridge = make_stack(
        [checksums_response({"index.php": md5(INDEX)})],
        files={"index.php": INDEX},
        bridge_script=[BridgeError(
            "bridge request failed after redeploy: ConnectionError"
        )],
    )
    with pytest.raises(WptError, match="core_md5 unavailable"):
        HealCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    # the primitive's own ONE degrade warning carries the reason
    warnings = [r.getMessage() for r in wpt_records
                if r.name == "wpt.audit.integrity"
                and r.levelno == logging.WARNING]
    assert warnings == [
        "core integrity skipped: core_md5 unavailable (bridge request "
        "failed after redeploy: ConnectionError)"
    ]
    assert [a for a, _p in bridge.calls] == ["info", "core_md5"]


def test_R16_plan_walk_is_bounded_before_the_first_fetch(tmp_path):
    """R16-P2: heal-core's plan walked the whole tree before its first
    deadline check, so a crawling channel spent the budget and only then
    raised.  The shared bounded walk checks per entry and at the end."""
    import time

    from wpt.types import DeadlineExceeded, Entry

    class _SlowWalk(FakeSource):
        def walk(self, path="", **_kwargs):
            for index in range(30):
                time.sleep(0.01)
                yield Entry(f"wp-includes/f{index}.php", False, 1)

    src = _SlowWalk()
    ctx = _ctx(tmp_path, deadline_s=0.05)
    started = time.monotonic()
    with pytest.raises(DeadlineExceeded):
        HealCoreAction().plan(ctx, (src, FakeSession(), HealBridge(src)))
    assert time.monotonic() - started < 0.5


# ------------------------------------------------------------ plan (local)


def test_plan_local_classification(tmp_path, cache_dir, wpt_records):
    files = {
        "wp-includes/version.php": LOCAL_TAMPERED_VERSION_PHP,
        "index.php": INDEX,
        "wp-admin/rogue.php": b"<?php /* added */",
        # wp-includes/js/gone.js absent -> missing
    }
    checksums = {
        "wp-includes/version.php": md5(LOCAL_OFFICIAL_VERSION_PHP),
        "index.php": md5(INDEX),
        "wp-includes/js/gone.js": md5(OFFICIAL_GONE_JS),
    }
    seed_checksums(cache_dir, LOCAL_VERSION, checksums)
    src, session, bridge = HealSource(), None, None
    src.files.update(files)
    ctx = _ctx(tmp_path, source="local", zip=tmp_path / "site.zip")
    plan = HealCoreAction().plan(ctx, (src, session, bridge))
    assert [
        (i.category, i.target, i.detail, i.bytes_est) for i in plan.items
    ] == [
        ("core.integrity", "wp-includes/js/gone.js",
         f"missing — restore the official WP {LOCAL_VERSION} en_US file", 0),
        ("core.integrity", "wp-includes/version.php",
         f"tampered — restore the official WP {LOCAL_VERSION} en_US file",
         len(LOCAL_TAMPERED_VERSION_PHP)),
    ]
    assert plan.backup_tables == []
    # the version came from the tampered-but-parseable version.php (the
    # gather's seam); added files are notes here exactly as in ftp mode
    infos = _messages(_records(wpt_records, logging.INFO))
    assert len(infos) == 2
    assert "investigate-only, not healed" in infos[0]
    assert "wp-admin/rogue.php" in infos[0]
    assert "2 core file(s) to heal" in infos[1]


def test_R9_P2_16_local_wporg_session_is_closed(
        tmp_path, cache_dir, monkeypatch):
    """P2-16: local heal-core created a plain wp.org session per phase and
    never closed it."""
    import wpt.actions.heal_core as heal_mod

    created = []

    class _Tracking(requests.Session):
        def __init__(self):
            super().__init__()
            self.closed = 0
            created.append(self)

        def close(self):
            self.closed += 1
            super().close()

    monkeypatch.setattr(heal_mod.requests, "Session", _Tracking)
    src = HealSource()
    src.files["wp-includes/version.php"] = LOCAL_OFFICIAL_VERSION_PHP
    seed_checksums(cache_dir, LOCAL_VERSION, {
        "wp-includes/version.php": md5(LOCAL_OFFICIAL_VERSION_PHP)})

    plan = HealCoreAction().plan(
        _ctx(tmp_path, source="local", zip=tmp_path / "site.zip"),
        (src, None, None))

    assert plan.items == []
    assert created and all(session.closed == 1 for session in created)


def test_plan_local_unknown_version_refuses(tmp_path):
    src = HealSource()  # no wp-includes/version.php in the tree
    src.files["index.php"] = INDEX
    with pytest.raises(WptError, match="unknown WordPress version"):
        HealCoreAction().plan(
            _ctx(tmp_path, source="local", zip=tmp_path / "site.zip"),
            (src, None, None),
        )


# ------------------------------------------------- locale basis [L17] (plan)


def test_plan_fr_ca_uses_fr_ca_map(tmp_path, cache_dir):
    """[L17] The fr_CA build's version.php (marker kept through the
    tamper) drives the plan to the fr_CA checksums map — the request
    shape pinned to locale=fr_CA.  (The locale-blind code fetched en_US
    and planned healing the fr_CA build's version.php with en_US
    bytes — the live defect.)"""
    files = {
        "index.php": INDEX,
        "wp-includes/version.php": FR_CA_TAMPERED_VERSION_PHP,
    }
    checksums = {
        "index.php": md5(INDEX),
        "wp-includes/version.php": md5(FR_CA_OFFICIAL_VERSION_PHP),
    }
    src, session, bridge = make_stack(
        [checksums_response(checksums)], files=files, locale=FR_CA,
    )
    plan = HealCoreAction().plan(_ctx(tmp_path), (src, session, bridge))
    assert [i.target for i in plan.items] == ["wp-includes/version.php"]
    assert len(session.gets) == 1 and session.posts == []
    url, kw = session.gets[0]
    assert url == integrity._checksums_url(VERSION, FR_CA)
    assert "core/checksums/1.0/?version=6.8.3&locale=fr_CA" in url
    assert kw["headers"]["User-Agent"].startswith("wpt/")
    # the version + locale rode ONE info call (no extra bridge traffic)
    assert bridge.calls == [
        ("info", {}),
        ("core_md5", {"paths": list(checksums)}),
    ]
    # the audit trail: the plan detail names the BUILD it heals from —
    # the same basis clause the audit finding's detail carries, so a
    # plan and a re-audit can never read as two contradictory accounts
    # of one core (the en_US and fr_CA maps disagree on version.php)
    assert plan.items[0].detail == (
        f"tampered — restore the official WP {VERSION} {FR_CA} file")


# ------------------------------------------------- locale basis [L17] (apply)


def test_apply_fr_ca_heals_from_fr_ca_build(tmp_path, cache_dir, wpt_records):
    """[L17] The apply restores from the LOCALE build: the fr_CA zip
    (the live-verified dash-subdomain URL, its own cache entry), the
    restored version.php carries $wp_local_package, and verification
    proves it against the fr_CA map — so `wp core verify-checksums
    --locale=fr_CA` passes afterwards."""
    files = {
        "index.php": INDEX,
        "wp-includes/version.php": FR_CA_TAMPERED_VERSION_PHP,
    }
    checksums = {
        "index.php": md5(INDEX),
        "wp-includes/version.php": md5(FR_CA_OFFICIAL_VERSION_PHP),
    }
    zip_files = {"wp-includes/version.php": FR_CA_OFFICIAL_VERSION_PHP}
    src, session, bridge = make_stack(
        [
            checksums_response(checksums),
            FakeResponse(content=release_zip_bytes(zip_files)),
        ],
        files=files, locale=FR_CA,
    )
    ctx = _ctx(tmp_path)
    action = HealCoreAction()
    stack = (src, session, bridge)
    plan = action.plan(ctx, stack)
    applied = action.apply(ctx, stack, plan)
    assert [i.done for i in applied.items] == [True]
    # the restored bytes ARE the fr_CA build's (the marker survives)
    assert src.files["wp-includes/version.php"] == FR_CA_OFFICIAL_VERSION_PHP
    # the zip went to the live-verified dash-subdomain locale URL and
    # cached under its own locale-suffixed name
    zip_url, zip_kw = session.gets[1]
    assert zip_url == updates.core_release_zip_url(VERSION, FR_CA)
    assert zip_url == "https://fr-ca.wordpress.org/wordpress-6.8.3-fr_CA.zip"
    assert zip_kw["headers"]["User-Agent"].startswith("wpt/")
    assert (cache_dir / f"wp-release-{VERSION}-fr_CA.zip").is_file()
    assert not (cache_dir / f"wp-release-{VERSION}.zip").exists()
    # the verify's checksums re-fetch is a FRESH fr_CA cache hit (2
    # session GETs total: plan checksums + apply zip)
    assert len(session.gets) == 2
    assert [a for a, _p in bridge.calls] == [
        "info", "core_md5", "info", "core_md5",
    ]
    assert bridge.calls[3] == (
        "core_md5", {"paths": ["wp-includes/version.php"]},
    )
    infos = _messages(_records(wpt_records, logging.INFO))
    assert ("apply: 1 core file(s) restored from the official WP 6.8.3 "
            "fr_CA release and verified") in infos


def test_apply_fr_ca_zip_404_falls_back_en_us(tmp_path, cache_dir,
                                               wpt_records):
    """[L19] A 404 for the localized build => ONE warning + the en_US
    release — and the paths the two builds ship IDENTICALLY are still
    healed: the restore basis is en_US, so verification uses the en_US
    map and the restored bytes verify cleanly.  wp-includes/js/gone.js
    carries the same official digest in both builds (live-verified: the
    only same-PATH digest difference between the en_US and fr_CA maps
    of a version is wp-includes/version.php), so this restore is correct
    under the audit's fr_CA basis too — no audit/heal disagreement."""
    files = {
        "index.php": INDEX,
        "wp-includes/version.php": FR_CA_OFFICIAL_VERSION_PHP,  # clean
        # wp-includes/js/gone.js absent -> missing
    }
    shared_gone = md5(OFFICIAL_GONE_JS)
    fr_ca_map = {
        "index.php": md5(INDEX),
        "wp-includes/version.php": md5(FR_CA_OFFICIAL_VERSION_PHP),
        "wp-includes/js/gone.js": shared_gone,
    }
    en_map = {
        "index.php": md5(INDEX),
        "wp-includes/version.php": md5(OFFICIAL_VERSION_PHP),
        "wp-includes/js/gone.js": shared_gone,   # identical in both builds
    }
    src, session, bridge = make_stack(
        [
            checksums_response(fr_ca_map),   # plan: the fr_CA checksums
            FakeResponse(status_code=404),   # apply: the fr_CA zip GET
            FakeResponse(content=release_zip_bytes(
                {"wp-includes/js/gone.js": OFFICIAL_GONE_JS})),
            checksums_response(en_map),      # verify: the en_US map
        ],
        files=files, locale=FR_CA,
    )
    ctx = _ctx(tmp_path)
    action = HealCoreAction()
    stack = (src, session, bridge)
    plan = action.plan(ctx, stack)
    applied = action.apply(ctx, stack, plan)
    assert [i.done for i in applied.items] == [True]
    assert src.files["wp-includes/js/gone.js"] == OFFICIAL_GONE_JS
    # the locale zip was requested at its dash-subdomain URL first
    assert [u for u, _kw in session.gets] == [
        integrity._checksums_url(VERSION, FR_CA),
        updates.core_release_zip_url(VERSION, FR_CA),
        updates.core_release_zip_url(VERSION, "en_US"),
        integrity._checksums_url(VERSION, "en_US"),
    ]
    # only the en_US zip cached (the fr_CA fetch failed — never a lie)
    assert not (cache_dir / f"wp-release-{VERSION}-fr_CA.zip").exists()
    assert (cache_dir / f"wp-release-{VERSION}.zip").is_file()
    warnings = _messages(_records(wpt_records, logging.WARNING))
    assert warnings == [
        "apply: the official WordPress 6.8.3 fr_CA release zip is "
        "unavailable — falling back to the en_US release for the files "
        "both builds ship identically",
    ]


def test_apply_fr_ca_zip_404_differing_path_unrestorable(tmp_path, cache_dir,
                                                         wpt_records):
    """[L19] The loop the en_US fallback used to create: wp-includes/
    version.php is the ONE file the fr_CA and en_US builds ship
    differently, so writing the en_US bytes there left a file the audit
    flags as tampered under the fr_CA basis on EVERY run — heal-core
    reported success, nothing converged.  It is now reported
    UNRESTORABLE: one warning naming it, no write, and the terminal
    incomplete error (nothing was healed, so nothing is claimed)."""
    files = {
        "index.php": INDEX,
        "wp-includes/version.php": FR_CA_TAMPERED_VERSION_PHP,
    }
    fr_ca_map = {
        "index.php": md5(INDEX),
        "wp-includes/version.php": md5(FR_CA_OFFICIAL_VERSION_PHP),
    }
    en_map = {
        "index.php": md5(INDEX),
        "wp-includes/version.php": md5(OFFICIAL_VERSION_PHP),  # DIFFERS
    }
    src, session, bridge = make_stack(
        [
            checksums_response(fr_ca_map),   # plan: the fr_CA checksums
            FakeResponse(status_code=404),   # apply: the fr_CA zip GET
            FakeResponse(content=release_zip_bytes(
                {"wp-includes/version.php": OFFICIAL_VERSION_PHP})),
            checksums_response(en_map),      # verify: the en_US map
        ],
        files=files, locale=FR_CA,
    )
    ctx = _ctx(tmp_path)
    action = HealCoreAction()
    stack = (src, session, bridge)
    plan = action.plan(ctx, stack)
    with pytest.raises(WptError) as excinfo:
        action.apply(ctx, stack, plan)
    assert ("heal incomplete: 0 of 1 files restored" in str(excinfo.value)
            and "wp-includes/version.php" in str(excinfo.value))
    # NOT written: the tampered original (whose fr_CA marker is intact)
    # is still the site's file, so the next audit run resolves the same
    # fr_CA basis and reports the same evidence — stable, not a loop.
    assert src.files["wp-includes/version.php"] == FR_CA_TAMPERED_VERSION_PHP
    assert src.writes == []
    warnings = _messages(_records(wpt_records, logging.WARNING))
    assert warnings == [
        "apply: the official WordPress 6.8.3 fr_CA release zip is "
        "unavailable — falling back to the en_US release for the files "
        "both builds ship identically",
        "apply: wp-includes/version.php is not shipped identically by the "
        "official WP 6.8.3 fr_CA and en_US builds (and the fr_CA build's "
        "release zip is unavailable) — not restored, unrestorable from here",
    ]


# ------------------------------------------- missing scope x junk [L19]
#
# The loop [L18] opened one file further down the scope: heal-core
# planned wp-config-sample.php back, clean-files deleted it, forever.
# The plan runs the same primitives with the same profile patterns, so
# the two can never disagree.


def test_plan_skips_junk_demanded_map_path(tmp_path, cache_dir):
    """[L19] wp-config-sample.php is a checksums map path AND one of the
    profile's own webroot_junk patterns — clean-files DELETES it, so the
    heal must not plan restoring it.  wp-cron.php (functional, not junk)
    is planned in the same tree: the subtraction is the junk policy, not
    a blanket "top-level files are optional"."""
    files = {"index.php": INDEX, "wp-includes/version.php":
             LOCAL_OFFICIAL_VERSION_PHP}  # clean: the version is the only
                                          # other healable kind here
    checksums = {
        "index.php": md5(INDEX),
        "wp-includes/version.php": md5(LOCAL_OFFICIAL_VERSION_PHP),
        "wp-config-sample.php": "3" * 32,   # junk-deleted -> not planned
        "wp-cron.php": "1" * 32,            # functional -> planned
        "readme.html": "4" * 32,            # non-php -> out of scope
    }
    seed_checksums(cache_dir, LOCAL_VERSION, checksums)
    src = HealSource()
    src.files.update(files)
    plan = HealCoreAction().plan(
        _ctx(tmp_path, source="local", zip=tmp_path / "site.zip"),
        (src, None, None),
    )
    assert [i.target for i in plan.items] == ["wp-cron.php"]


def test_apply_local_rehearsal_junk_vs_missing(tmp_path, cache_dir,
                                                wpt_records):
    """[L19]+[L18] The rehearsal creates the functional missing top-level
    file (wp-cron.php) and leaves the junk-policy file (wp-config-sample
    .php) absent — the clean-files fixed point, proven end to end."""
    zip_path = tmp_path / "site.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("wp-includes/version.php", LOCAL_OFFICIAL_VERSION_PHP)
        zf.writestr("index.php", INDEX)
        # wp-cron.php AND wp-config-sample.php both absent
    checksums = {
        "wp-includes/version.php": md5(LOCAL_OFFICIAL_VERSION_PHP),
        "index.php": md5(INDEX),
        "wp-cron.php": md5(OFFICIAL_WP_CRON),
        "wp-config-sample.php": "3" * 32,
    }
    seed_checksums(cache_dir, LOCAL_VERSION, checksums)
    seed_release_zip(cache_dir, LOCAL_VERSION, release_zip_bytes({
        "wp-includes/version.php": LOCAL_OFFICIAL_VERSION_PHP,
        "wp-cron.php": OFFICIAL_WP_CRON,
    }))
    rc = run_action(
        _ctx(tmp_path, source="local", zip=zip_path, apply=True, yes=True),
        "heal-core",
    )
    assert rc == 0
    rehearsed = sorted(tmp_path.glob("site-rehearsed-*.zip"))
    assert len(rehearsed) == 1
    with zipfile.ZipFile(rehearsed[0]) as zf:
        names = set(zf.namelist())
        assert "wp-cron.php" in names                 # restored
        assert "wp-config-sample.php" not in names    # the junk policy's
    infos = [r.getMessage() for r in wpt_records
             if r.name == "wpt.actions" and "rehearsed" in r.getMessage()]
    assert infos and "rehearsed 1/1 items" in infos[0]


# ---------------------------------- locale basis under attack [L17]


def test_apply_en_us_build_never_heals_locale_bytes(tmp_path, cache_dir,
                                                     wpt_records):
    """[L17] The invariant the live migration broke, as a heal: an en_US
    BUILD whose site locale is fr_CA (a language PACK — what the web
    installer ships) heals from the en_US release, so no localized build
    bytes are ever written over an en_US tree.  The markerless (but
    tampered) version.php is READABLE, so the site-locale tier is never
    reached; the fr_CA map is not even requested."""
    files = {
        "index.php": INDEX,
        "wp-includes/version.php": EVIL,  # markerless + tampered
    }
    checksums = {
        "index.php": md5(INDEX),
        "wp-includes/version.php": md5(OFFICIAL_VERSION_PHP),
    }
    src, session, bridge = make_stack(
        [
            checksums_response(checksums),
            FakeResponse(content=release_zip_bytes(
                {"wp-includes/version.php": OFFICIAL_VERSION_PHP})),
        ],
        files=files, locale=FR_CA,  # WPLANG=fr_CA
    )
    ctx = _ctx(tmp_path)
    action = HealCoreAction()
    stack = (src, session, bridge)
    plan = action.plan(ctx, stack)
    assert [i.target for i in plan.items] == ["wp-includes/version.php"]
    applied = action.apply(ctx, stack, plan)
    assert [i.done for i in applied.items] == [True]
    # the restored bytes are the en_US build's (no $wp_local_package)
    assert src.files["wp-includes/version.php"] == OFFICIAL_VERSION_PHP
    # and the ONLY zip fetched was the en_US release
    assert [u for u, _kw in session.gets] == [
        integrity._checksums_url(VERSION),
        updates.DEFAULT_WP_ORG.core_release_zip_url.format(version=VERSION),
    ]
    assert not (cache_dir / f"wp-release-{VERSION}-fr_CA.zip").exists()


def test_apply_fr_ca_missing_top_level_php_from_the_fr_ca_zip(
        tmp_path, cache_dir, wpt_records):
    """[L17]+[L18] A missing TOP-LEVEL functional core file is restored
    from the SAME locale build the audit compares against — the scope
    rule is mode-blind AND locale-blind, so the restored file verifies
    under the audit's fr_CA basis too (its digest is the same in both
    builds; wp-includes/version.php is the only same-path exception
    between the two maps, and it has its own unrestorable rule)."""
    files = {
        "index.php": INDEX,
        "wp-includes/version.php": FR_CA_OFFICIAL_VERSION_PHP,
        # wp-cron.php absent
    }
    checksums = {
        "index.php": md5(INDEX),
        "wp-includes/version.php": md5(FR_CA_OFFICIAL_VERSION_PHP),
        "wp-cron.php": md5(OFFICIAL_WP_CRON),
    }
    src, session, bridge = make_stack(
        [
            checksums_response(checksums),
            FakeResponse(content=release_zip_bytes({
                "wp-includes/version.php": FR_CA_OFFICIAL_VERSION_PHP,
                "wp-cron.php": OFFICIAL_WP_CRON,
            })),
        ],
        files=files, locale=FR_CA,
    )
    ctx = _ctx(tmp_path)
    action = HealCoreAction()
    stack = (src, session, bridge)
    plan = action.plan(ctx, stack)
    assert [i.target for i in plan.items] == ["wp-cron.php"]
    applied = action.apply(ctx, stack, plan)
    assert [i.done for i in applied.items] == [True]
    assert src.files["wp-cron.php"] == OFFICIAL_WP_CRON
    zip_url, _kw = session.gets[1]
    assert zip_url == updates.core_release_zip_url(VERSION, FR_CA)
    # no en_US fallback was needed (and none cached)
    assert not (cache_dir / f"wp-release-{VERSION}.zip").exists()
    infos = _messages(_records(wpt_records, logging.INFO))
    assert any(f"official WP {VERSION} {FR_CA} release" in m for m in infos)


def test_plan_drops_translation_catalogs(tmp_path, cache_dir, wpt_records):
    """[L19] heal-core runs the SAME translation-pack pass the audit
    check runs: a pristine wp.org language pack is not tampering, and
    restoring the BUNDLED catalogs would DOWNGRADE the site's
    translations.  Plan and audit can never disagree about it."""
    files = {
        "index.php": INDEX,
        "wp-includes/version.php": LOCAL_OFFICIAL_VERSION_PHP,
        "wp-content/languages/fr_CA.po": b"# an updated translation\n",
    }
    checksums = {
        "index.php": md5(INDEX),
        "wp-includes/version.php": md5(LOCAL_OFFICIAL_VERSION_PHP),
        "wp-content/languages/fr_CA.po": md5(b"# the bundled one\n"),
    }
    seed_checksums(cache_dir, LOCAL_VERSION, checksums)
    src = HealSource()
    src.files.update(files)
    plan = HealCoreAction().plan(
        _ctx(tmp_path, source="local", zip=tmp_path / "site.zip"),
        (src, None, None),
    )
    assert plan.items == []  # the updated catalog is NOT a heal target
    infos = [r.getMessage() for r in wpt_records
             if r.name == "wpt.audit.integrity" and r.levelno == logging.INFO
             and "translation catalog" in r.getMessage()]
    assert len(infos) == 1
    assert "wp-content/languages/fr_CA.po" in infos[0]
    assert any("nothing to heal" in m
               for m in _messages(_records(wpt_records, logging.INFO)))


# ------------------------------------------------------------- apply (ftp)


def test_apply_restores_and_verifies(tmp_path, cache_dir, wpt_records):
    files = {
        "index.php": INDEX,
        "wp-includes/version.php": EVIL,
        # wp-includes/js/gone.js absent
    }
    checksums = {
        "index.php": md5(INDEX),
        "wp-includes/version.php": md5(OFFICIAL_VERSION_PHP),
        "wp-includes/js/gone.js": md5(OFFICIAL_GONE_JS),
    }
    zip_files = {
        "wp-includes/version.php": OFFICIAL_VERSION_PHP,
        "wp-includes/js/gone.js": OFFICIAL_GONE_JS,
    }
    src, session, bridge = make_stack(
        [
            checksums_response(checksums),
            FakeResponse(content=release_zip_bytes(zip_files)),
        ],
        files=files,
    )
    ctx = _ctx(tmp_path)
    action = HealCoreAction()
    stack = (src, session, bridge)
    plan = action.plan(ctx, stack)
    applied = action.apply(ctx, stack, plan)
    assert applied is plan  # the same Plan object, items updated in place
    assert [i.done for i in applied.items] == [True, True]
    # the unlock is SURGICAL: the same protected core path refuses
    # without it, and allow_core never unlocks the config files
    with pytest.raises(NotWritableError):
        src.write_bytes("wp-includes/version.php", b"x")
    with pytest.raises(NotWritableError):
        src.write_bytes("wp-config.php", b"x", allow_core=True)
    with pytest.raises(NotWritableError):
        src.write_bytes(".htaccess", b"x", allow_core=True)
    # every write carried the audited core unlock (and nothing else)
    assert src.writes == [
        ("wp-includes/js/gone.js",
         {"allow_config": False, "allow_core": True}),
        ("wp-includes/version.php",
         {"allow_config": False, "allow_core": True}),
    ]
    # the restored bytes ARE the official release bytes
    assert src.files["wp-includes/version.php"] == OFFICIAL_VERSION_PHP
    assert src.files["wp-includes/js/gone.js"] == OFFICIAL_GONE_JS
    assert src.files["index.php"] == INDEX  # untouched
    # wp.org traffic: ONE checksums GET (plan) + ONE release-zip GET
    # (apply) — the verify's checksums re-fetch is a fresh cache hit
    assert len(session.gets) == 2 and session.posts == []
    zip_url, zip_kw = session.gets[1]
    assert zip_url == updates.DEFAULT_WP_ORG.core_release_zip_url.format(version=VERSION)
    assert zip_kw["headers"]["User-Agent"].startswith("wpt/")
    assert zip_kw["timeout"] == DEFAULTS.http.timeout_s
    assert (cache_dir / f"wp-release-{VERSION}.zip").is_file()
    # bridge traffic: plan info + classification core_md5, the apply's
    # version re-derivation info + the verify core_md5 covering exactly
    # the healed paths, in plan order
    assert [a for a, _p in bridge.calls] == [
        "info", "core_md5", "info", "core_md5",
    ]
    assert bridge.calls[3] == (
        "core_md5",
        {"paths": ["wp-includes/js/gone.js", "wp-includes/version.php"]},
    )
    # one info per phase
    infos = _messages(_records(wpt_records, logging.INFO))
    assert len(infos) == 2
    assert "2 core file(s) to heal" in infos[0]
    assert ("2 core file(s) restored from the official WP 6.8.3 en_US "
            "release and verified") in infos[1]


def test_R16_apply_checks_the_budget_before_every_write(
        tmp_path, cache_dir, monkeypatch):
    """R16-P2: the apply write loop never checked the run deadline, so a
    slow write ran every item after expiry and the registry reported rc 0.
    The check now runs before each item (and before the final verify)."""
    import wpt.actions.heal_core as heal_mod
    from wpt.deadline import Deadline
    from wpt.types import DeadlineExceeded

    files = {
        "index.php": INDEX,
        "wp-includes/version.php": EVIL,
    }
    checksums = {
        "index.php": md5(INDEX),
        "wp-includes/version.php": md5(OFFICIAL_VERSION_PHP),
        "wp-includes/js/gone.js": md5(OFFICIAL_GONE_JS),
    }
    zip_files = {
        "wp-includes/version.php": OFFICIAL_VERSION_PHP,
        "wp-includes/js/gone.js": OFFICIAL_GONE_JS,
    }
    src, session, bridge = make_stack(
        [checksums_response(checksums),
         FakeResponse(content=release_zip_bytes(zip_files))],
        files=files)
    ctx = _ctx(tmp_path, deadline_s=100)
    action = HealCoreAction()
    stack = (src, session, bridge)
    plan = action.plan(ctx, stack)
    assert plan.items

    inner = Deadline.from_ctx(ctx)

    class _Trip:
        def __getattr__(self, name):
            return getattr(inner, name)

        def check(self, context):
            if context == "heal-core write":
                raise DeadlineExceeded("budget expired before the write")
            return inner.check(context)

    monkeypatch.setattr(
        heal_mod.Deadline, "from_ctx",
        classmethod(lambda cls, ctx: _Trip()))
    with pytest.raises(DeadlineExceeded):
        action.apply(ctx, stack, plan)
    assert src.writes == []
    assert not any(item.done for item in plan.items)


def test_apply_zip_missing_path_skipped(tmp_path, cache_dir, wpt_records):
    # the release zip ships only ONE of the two planned files (wp.org
    # checksums/zip map drift): the absent one is skipped with ONE
    # warning, done stays False, the sibling still heals — and the
    # apply ends in the incomplete WptError naming it
    files = {
        "index.php": INDEX,
        "wp-includes/version.php": EVIL,
        # wp-includes/js/gone.js absent
    }
    checksums = {
        "index.php": md5(INDEX),
        "wp-includes/version.php": md5(OFFICIAL_VERSION_PHP),
        "wp-includes/js/gone.js": md5(OFFICIAL_GONE_JS),
    }
    zip_files = {"wp-includes/version.php": OFFICIAL_VERSION_PHP}
    src, session, bridge = make_stack(
        [
            checksums_response(checksums),
            FakeResponse(content=release_zip_bytes(zip_files)),
        ],
        files=files,
    )
    ctx = _ctx(tmp_path)
    action = HealCoreAction()
    stack = (src, session, bridge)
    plan = action.plan(ctx, stack)
    by_target = {i.target: i for i in plan.items}
    with pytest.raises(WptError) as excinfo:
        action.apply(ctx, stack, plan)
    message = str(excinfo.value)
    assert "heal incomplete: 1 of 2 files restored" in message
    assert "wp-includes/js/gone.js" in message
    assert "`wpt restore` reverts" in message
    # the sibling item really healed; the skipped one never wrote
    assert by_target["wp-includes/version.php"].done
    assert not by_target["wp-includes/js/gone.js"].done
    assert src.writes == [
        ("wp-includes/version.php",
         {"allow_config": False, "allow_core": True}),
    ]
    warnings = _messages(_records(wpt_records, logging.WARNING))
    assert warnings == [
        "apply: wp-includes/js/gone.js is absent from the official WP "
        "6.8.3 en_US release zip (wp.org checksums/zip map drift) "
        "— not restored"
    ]


def test_apply_verify_mismatch_not_done(tmp_path, cache_dir, wpt_records):
    # the zip's bytes DISAGREE with the checksums map: the write lands,
    # the digest proof fails, the item stays not-done with ONE warning,
    # and the apply ends incomplete naming the path
    drifted = b"<?php // drifted release bytes\n"
    checksums = {"wp-includes/version.php": md5(OFFICIAL_VERSION_PHP)}
    src, session, bridge = make_stack(
        [
            checksums_response(checksums),
            FakeResponse(content=release_zip_bytes(
                {"wp-includes/version.php": drifted})),
        ],
        files={"wp-includes/version.php": EVIL},
    )
    ctx = _ctx(tmp_path)
    action = HealCoreAction()
    stack = (src, session, bridge)
    plan = action.plan(ctx, stack)
    with pytest.raises(WptError) as excinfo:
        action.apply(ctx, stack, plan)
    message = str(excinfo.value)
    assert "heal incomplete: 0 of 1 files restored" in message
    assert "wp-includes/version.php" in message
    assert not plan.items[0].done
    assert src.files["wp-includes/version.php"] == drifted  # it landed
    warnings = _messages(_records(wpt_records, logging.WARNING))
    assert len(warnings) == 1
    assert ("did not verify against the official WP 6.8.3 en_US "
            "checksums") in warnings[0]
    assert "wp-includes/version.php" in warnings[0]


def test_apply_write_failure_continues(tmp_path, cache_dir, wpt_records):
    # a write failure on one item (an ftp STOR error here) is ONE
    # warning + continue — the sibling item still heals and verifies;
    # the apply ends in the incomplete WptError naming the failed path
    src = _FailingWriteSource("wp-includes/version.php")
    src.files["wp-includes/version.php"] = EVIL
    src.files["wp-trackback.php"] = EVIL
    checksums = {
        "wp-includes/version.php": md5(OFFICIAL_VERSION_PHP),
        "wp-trackback.php": md5(b"<?php // official trackback\n"),
    }
    zip_files = {
        "wp-includes/version.php": OFFICIAL_VERSION_PHP,
        "wp-trackback.php": b"<?php // official trackback\n",
    }
    session = FakeSession([
        checksums_response(checksums),
        FakeResponse(content=release_zip_bytes(zip_files)),
    ])
    bridge = HealBridge(src)
    ctx = _ctx(tmp_path)
    action = HealCoreAction()
    stack = (src, session, bridge)
    plan = action.plan(ctx, stack)
    by_target = {i.target: i for i in plan.items}
    with pytest.raises(WptError) as excinfo:
        action.apply(ctx, stack, plan)
    message = str(excinfo.value)
    assert "heal incomplete: 1 of 2 files restored" in message
    assert "wp-includes/version.php" in message
    assert "`wpt restore` reverts" in message
    assert by_target["wp-trackback.php"].done
    assert not by_target["wp-includes/version.php"].done
    assert src.writes == [
        ("wp-trackback.php", {"allow_config": False, "allow_core": True}),
    ]
    warnings = _messages(_records(wpt_records, logging.WARNING))
    assert warnings == [
        "apply: restoring wp-includes/version.php failed (STOR failed: "
        "wp-includes/version.php) — not restored"
    ]


@pytest.mark.parametrize("session_script, bridge_script, reason", [
    pytest.param([], [BridgeError("bridge action failed: core_md5 boom")],
                 "core_md5 unavailable (bridge action failed: "
                 "core_md5 boom)", id="core-md5-raise"),
    pytest.param([], [["not", "a", "dict"]],
                 "core_md5 unavailable (malformed core_md5 payload)",
                 id="non-dict-payload"),
    pytest.param([], [{"ok": True, "files": "not-a-map", "missing": [],
                       "unreadable": []}],
                 "core_md5 unavailable (malformed core_md5 payload)",
                 id="bad-buckets-payload"),
])
def test_apply_verify_mandatory_failures(tmp_path, cache_dir,
                                         session_script, bridge_script,
                                         reason):
    # verification is MANDATORY: a heal whose proof cannot be taken is
    # never reported — every failure shape refuses with "cannot verify
    # the heal" naming the reason, and writes that already landed stay
    # unclaimed (done False; the pre-action snapshot is the revert)
    checksums = {"wp-includes/version.php": md5(OFFICIAL_VERSION_PHP)}
    # The hand-built plan never fetched a map, so the apply's own
    # comparison-basis fetch (it re-derives what the audit compares
    # against, the same discipline as the version re-derivation) takes
    # the FIRST slot, then the zip GET, then the restore-basis map the
    # verification and the unrestorable decision read — the cases that
    # fail INSIDE verification get a working checksums answer for that
    # last slot, the checksums-unavailable case scripts the
    # ConnectionError there instead.
    src, session, bridge = make_stack(
        [
            checksums_response(checksums),   # apply's comparison basis
            FakeResponse(content=release_zip_bytes(
                {"wp-includes/version.php": OFFICIAL_VERSION_PHP})),
        ] + (list(session_script)
             or [checksums_response(checksums)]),
        bridge_script=list(bridge_script),
    )
    plan = Plan(items=[
        PlanItem(category="core.integrity",
                 target="wp-includes/version.php",
                 detail=f"tampered — restore the official WP {VERSION} "
                        "file"),
    ])
    with pytest.raises(WptError) as excinfo:
        HealCoreAction().apply(
            _ctx(tmp_path), (src, session, bridge), plan)
    assert f"cannot verify the heal: {reason}" in str(excinfo.value)
    # the write DID land before the verification refused — unclaimed
    assert src.files["wp-includes/version.php"] == OFFICIAL_VERSION_PHP
    assert not plan.items[0].done


def test_apply_restore_basis_checksums_unavailable_refuses_before_writes(
        tmp_path, cache_dir, wpt_records):
    """The restore basis's own map is the verification map AND the
    unrestorable decision map, so it is fetched BEFORE the writes: when
    it cannot be had (here the en_US map after the fr_CA zip 404) the
    apply refuses with "cannot verify the heal" having written NOTHING
    — no half-healed tree, nothing to revert."""
    files = {
        "index.php": INDEX,
        "wp-includes/version.php": FR_CA_TAMPERED_VERSION_PHP,
    }
    fr_ca_map = {
        "index.php": md5(INDEX),
        "wp-includes/version.php": md5(FR_CA_OFFICIAL_VERSION_PHP),
    }
    src, session, bridge = make_stack(
        [
            checksums_response(fr_ca_map),   # plan: the fr_CA checksums
            FakeResponse(status_code=404),   # apply: the fr_CA zip GET
            FakeResponse(content=release_zip_bytes(
                {"wp-includes/version.php": OFFICIAL_VERSION_PHP})),
            requests.ConnectionError("boom"),  # the en_US basis map
        ],
        files=files, locale=FR_CA,
    )
    ctx = _ctx(tmp_path)
    action = HealCoreAction()
    stack = (src, session, bridge)
    plan = action.plan(ctx, stack)
    with pytest.raises(WptError) as excinfo:
        action.apply(ctx, stack, plan)
    assert "cannot verify the heal: checksums unavailable" in str(excinfo.value)
    assert src.writes == []
    assert src.files["wp-includes/version.php"] == FR_CA_TAMPERED_VERSION_PHP
    # no zip is cached under a lie: the en_US zip was fetched, but no
    # heal was attempted
    assert (cache_dir / f"wp-release-{VERSION}.zip").is_file()


def test_apply_empty_plan_no_work(tmp_path, cache_dir):
    src, session, bridge = make_stack([])  # any request would fail the fake
    plan = Plan(items=[], backup_tables=[])
    applied = HealCoreAction().apply(
        _ctx(tmp_path), (src, session, bridge), plan)
    assert applied is plan
    assert session.gets == []  # no wp.org fetch
    assert bridge.calls == []  # no bridge roundtrip at all


# ----------------------------------------------------------- apply (local)


def test_apply_local_rehearsal(tmp_path, cache_dir, wpt_records):
    # the REAL registry local flow over a real zip + seeded caches (the
    # tests/actions/test_clean_files.py rehearsal pattern): plan
    # classifies through the zip view, apply stages the heals into the
    # MutableZipSource overlay (allow_core through the REAL shared
    # guard), the verify reads the overlay via read_many, and the
    # materialized twin carries the healed official bytes while the
    # ORIGINAL zip is byte-identical (it IS the rollback)
    zip_path = tmp_path / "site.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("wp-includes/version.php", LOCAL_TAMPERED_VERSION_PHP)
        zf.writestr("index.php", INDEX)
        # wp-includes/js/gone.js absent from the site zip
    before = zip_path.read_bytes()
    checksums = {
        "wp-includes/version.php": md5(LOCAL_OFFICIAL_VERSION_PHP),
        "index.php": md5(INDEX),
        "wp-includes/js/gone.js": md5(OFFICIAL_GONE_JS),
    }
    seed_checksums(cache_dir, LOCAL_VERSION, checksums)
    seed_release_zip(cache_dir, LOCAL_VERSION, release_zip_bytes({
        "wp-includes/version.php": LOCAL_OFFICIAL_VERSION_PHP,
        "wp-includes/js/gone.js": OFFICIAL_GONE_JS,
    }))
    rc = run_action(
        _ctx(tmp_path, source="local", zip=zip_path, apply=True, yes=True),
        "heal-core",
    )
    assert rc == 0
    assert zip_path.read_bytes() == before  # the original is the rollback
    rehearsed = sorted(tmp_path.glob("site-rehearsed-*.zip"))
    assert len(rehearsed) == 1
    with zipfile.ZipFile(rehearsed[0]) as zf:
        assert zf.read("wp-includes/version.php") == LOCAL_OFFICIAL_VERSION_PHP
        assert zf.read("wp-includes/js/gone.js") == OFFICIAL_GONE_JS
        assert zf.read("index.php") == INDEX  # the clean file untouched
    infos = [r.getMessage() for r in wpt_records
             if r.name == "wpt.actions" and "rehearsed" in r.getMessage()]
    assert infos and "rehearsed 2/2 items" in infos[0]
    # the heal phases logged through the action's own logger
    action_infos = _messages(_records(wpt_records, logging.INFO))
    assert any("2 core file(s) restored" in m for m in action_infos)


def test_apply_local_rehearsal_fr_ca(tmp_path, cache_dir, wpt_records):
    """[L17] The REAL registry local flow on the fr_CA build: the
    tampered version.php keeps its $wp_local_package marker, so the
    plan classifies against the seeded fr_CA map and the apply
    restores the fr_CA build's bytes (from the seeded fr_CA zip) —
    the rehearsed twin's version.php carries the marker, which is
    what makes `wp core verify-checksums --locale=fr_CA` pass."""
    zip_path = tmp_path / "site.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("wp-includes/version.php", FR_CA_TAMPERED_VERSION_PHP)
        zf.writestr("index.php", INDEX)
    before = zip_path.read_bytes()
    checksums = {
        "index.php": md5(INDEX),
        "wp-includes/version.php": md5(FR_CA_OFFICIAL_VERSION_PHP),
    }
    seed_checksums(cache_dir, VERSION, checksums, locale=FR_CA)
    seed_release_zip(cache_dir, VERSION, release_zip_bytes({
        "wp-includes/version.php": FR_CA_OFFICIAL_VERSION_PHP,
    }), locale=FR_CA)
    rc = run_action(
        _ctx(tmp_path, source="local", zip=zip_path, apply=True, yes=True),
        "heal-core",
    )
    assert rc == 0
    assert zip_path.read_bytes() == before  # the original is the rollback
    rehearsed = sorted(tmp_path.glob("site-rehearsed-*.zip"))
    assert len(rehearsed) == 1
    with zipfile.ZipFile(rehearsed[0]) as zf:
        assert zf.read("wp-includes/version.php") == FR_CA_OFFICIAL_VERSION_PHP
        assert zf.read("index.php") == INDEX
    # the phase log names the fr_CA basis
    action_infos = _messages(_records(wpt_records, logging.INFO))
    assert any(f"official WP {VERSION} {FR_CA} release" in m
               for m in action_infos)


def test_apply_local_rehearsal_top_level_file(tmp_path, cache_dir,
                                                wpt_records):
    """[L18] The live migration shape: wp-cron.php DELETED by the old
    host (comments and WP-Cron silently broken).  The check's missing
    scope now covers top-level .php map paths, heal-core's plan
    follows, and the rehearsal CREATES the file from the release zip."""
    zip_path = tmp_path / "site.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("wp-includes/version.php", LOCAL_TAMPERED_VERSION_PHP)
        zf.writestr("index.php", INDEX)
        # wp-cron.php absent — the old host deleted it
    before = zip_path.read_bytes()
    checksums = {
        "wp-includes/version.php": md5(LOCAL_OFFICIAL_VERSION_PHP),
        "index.php": md5(INDEX),
        "wp-cron.php": md5(OFFICIAL_WP_CRON),
    }
    seed_checksums(cache_dir, LOCAL_VERSION, checksums)
    seed_release_zip(cache_dir, LOCAL_VERSION, release_zip_bytes({
        "wp-includes/version.php": LOCAL_OFFICIAL_VERSION_PHP,
        "wp-cron.php": OFFICIAL_WP_CRON,
    }))
    rc = run_action(
        _ctx(tmp_path, source="local", zip=zip_path, apply=True, yes=True),
        "heal-core",
    )
    assert rc == 0
    assert zip_path.read_bytes() == before
    rehearsed = sorted(tmp_path.glob("site-rehearsed-*.zip"))
    assert len(rehearsed) == 1
    with zipfile.ZipFile(rehearsed[0]) as zf:
        # the top-level functional file is RE-CREATED from the release
        assert zf.read("wp-cron.php") == OFFICIAL_WP_CRON
        assert zf.read("wp-includes/version.php") == LOCAL_OFFICIAL_VERSION_PHP
        assert zf.read("index.php") == INDEX
    infos = [r.getMessage() for r in wpt_records
             if r.name == "wpt.actions" and "rehearsed" in r.getMessage()]
    assert infos and "rehearsed 2/2 items" in infos[0]


# ---------------------------------------------------- registry end-to-end


def test_registry_ftp_apply_end_to_end(tmp_path, capsys, monkeypatch,
                                       cache_dir):
    files = {
        "index.php": INDEX,
        "wp-includes/version.php": EVIL,
        # wp-includes/js/gone.js absent
    }
    checksums = {
        "index.php": md5(INDEX),
        "wp-includes/version.php": md5(OFFICIAL_VERSION_PHP),
        "wp-includes/js/gone.js": md5(OFFICIAL_GONE_JS),
    }
    zip_files = {
        "wp-includes/version.php": OFFICIAL_VERSION_PHP,
        "wp-includes/js/gone.js": OFFICIAL_GONE_JS,
    }
    src, session, bridge = make_stack(
        [
            checksums_response(checksums),
            FakeResponse(content=release_zip_bytes(zip_files)),
        ],
        files=files,
    )
    monkeypatch.setattr(registry_mod, "_stack",
                        lambda ctx: (src, session, bridge))
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "heal-core")
    assert rc == 0
    # bridge traffic: plan's info + classification core_md5, the
    # apply's info + verify core_md5, then the registry's exactly-one
    # post-apply purge_cache — all before the destroy
    assert [a for a, _p in bridge.calls] == [
        "info", "core_md5", "info", "core_md5", "purge_cache",
    ]
    assert bridge.destroyed == 1
    # the fail-closed pre-action snapshot: the tampered ORIGINAL is
    # captured, the missing target records as ABSENT (restore brings
    # the tampered file back and deletes the healed-missing one — the
    # whole heal reverts)
    manifests = list((tmp_path / "backup").glob("*/*/manifest.json"))
    assert len(manifests) == 1
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    assert manifest["action"] == "heal-core"
    assert manifest["site"] == "example.com"
    assert manifest["tables"] == []  # files only
    entries = {e["path"]: e for e in manifest["files"]}
    assert entries["wp-includes/version.php"]["absent"] is False
    assert entries["wp-includes/version.php"]["sha256"] == hashlib.sha256(
        EVIL).hexdigest()
    assert entries["wp-includes/js/gone.js"] == {
        "path": "wp-includes/js/gone.js", "absent": True,
    }
    # the applied plan prints every item done
    out = capsys.readouterr().out
    assert out.count("| yes |") == 2
    assert "restore the official WP 6.8.3 en_US file" in out
