"""Tests for the users_reset action (wpt.actions.users_reset).

A REAL Bridge over FakeSession/FakeSource (scripted users_reset / db_audit /
db_dump answers — tests/actions/test_deactivate.py conventions):
deterministic, no network, no sleeps.  The registry end-to-end tests
monkeypatch ``wpt.actions.registry._stack`` (the pinned seam) to run the real
``run_action`` flow over a fake ftp-mode stack; ``bridge.destroy()`` (the
registry's finally) is scripted via a self-destruct handler.

Test -> behavior map:
  test_registration ......................... users_reset registered as the
        INSTANCE under applies=("ftp",) — local mode can never reach it
  test_plan_dry_run_lists_users ............. one item per user: category
        db.users, target = the users table, label carries login + roles
        (the label's ONLY carrier); backup_tables = users + usermeta
        EXPLICITLY; requires_apply True, done False; ONE info plan
        summary; the read-only users_reset (params {} — NO apply flag) plus
        exactly one db_audit.  NO password exists anywhere in the plan
  test_plan_clears_previous_credentials ...... a fresh run never exposes a
        previous run's secrets on the registered instance
  test_plan_no_users ........................ zero users -> EMPTY plan,
        backup_tables == [] deliberately, NO db_audit roundtrip
  test_plan_refuses_without_bridge .......... no bridge in the stack ->
        SourceError before any roundtrip (direct-misuse guard)
  test_plan_refuses_unbacked ................. the audit cannot locate
        users / usermeta -> SourceError, never an unbacked mutation
  test_plan_backup_scope_fail_safe ........... a stray *users-suffixed
        table WIDENS the snapshot scope, never a miss; the item's target
        stays the ONE table the identity owner resolves
  test_plan_target_is_the_resolved_users_table_not_the_first_by_name
        THE MEASURED CASE: sorted()[0] named another site's *users table
        in the plan and in every --report artifact; a contested identity
        is refused, both candidates named
  test_plan_target_is_the_users_table_on_an_uncontested_site .... the A/B
  test_apply_resets_every_user .............. ONE users_reset with
        apply=True; every planned item done and enriched; credentials
        published for the CLI; ONE info apply summary carrying the
        session-invalidation count and no password
  test_apply_empty_plan_no_bridge_call ....... zero planned users -> no
        bridge roundtrip
  test_apply_unplanned_user_fails_closed .... a user reset that was NOT in
        the plan (created between plan and apply) -> BridgeError, items
        stay undone — and the credentials are STILL published, because the
        old credentials are already revoked
  test_apply_missing_user_fails_closed ....... a planned login absent from
        the result -> BridgeError, items stay undone
  test_apply_server_error_propagates ........ an ok:false answer propagates
        untouched; no credentials (nothing was reset)
  test_apply_skips_non_apply_items .......... requires_apply=False items
        are neither reset nor marked done
  test_apply_malformed_row_refuses ......... the bridge's ROW content is
        this module's own contract (the client's envelope validation is a
        different layer, bypassed on purpose by _RawBridge): a row that
        carries no usable login+password pair -> BridgeError inside the
        error contract, items stay undone, and NO half-filled credential is
        published — while every COMPLETE sibling row still is, because its
        password is already live
  test_apply_malformed_row_shapes ........... the same refusal for every
        unusable shape: absent / empty / non-string password or login, and
        a row that is not a dict at all (never a KeyError/TypeError)
  test_apply_row_without_email_succeeds ..... email is optional and
        blank-allowed: the reset SUCCEEDS with a blank email, the
        password is never withheld for it
  test_registry_malformed_row_is_clean ....... the real path end to end:
        rc 1, ONE clean error record naming the row, no traceback, no
        report, and the registered action's credentials EMPTY
  test_plan_malformed_inventory_row_refuses .. a read-only inventory row
        without a login/role list is refused (BridgeError), never planned
        and never an unlabelled item
  test_secrets_never_reach_log_or_report .... after a full registry apply
        the generated password appears in NEITHER any captured log record
        NOR stdout (the report the registry prints) — only in the
        credentials the CLI prints itself
  test_registry_dry_run ...................... run_action apply=False: rc 0,
        the read-only users_reset + db_audit, no db_dump, no apply flag
  test_report_file_carries_the_plan_and_ ... --report writes the redacted
        never_a_password .................... plan; the generated
        ...................................... passwords reach NO file (stdout
        only), and the run is otherwise unchanged
  test_registry_ftp_apply_end_to_end ........ apply --yes over the fake
        stack: the fail-closed pre-action snapshot manifest lists EXACTLY
        wp_users + wp_usermeta (scripted db_dump NDJSON), users_reset
        called with apply=True, purge_cache once, rc 0
  test_registry_snapshot_failure_refuses_apply  a working-bridge-less
        backup (db_dump refuses) -> rc 1 "pre-action backup failed", the
        apply NEVER runs, no credentials published
  test_registry_local_mode_refused ........... local mode: rc 1, the
        ftp-only applicability error, the stack never even built
  test_a_refused_run_writes_a_credential_free_report . a FAILED run now
        writes the report it can (L44), and this action's secrets
        contract holds for it: the refusal names the pre-action backup
        failure, and NO password reaches the file, the twin or stdout
"""

import json
import logging

import pytest

from tests.fakes import FakeResponse, FakeSession, FakeSource
from wpt.actions import registry as registry_mod
from wpt.actions.registry import get_action, run_action
from wpt.actions.users_reset import UsersResetAction
from wpt.cli import Ctx
from wpt.report import Plan, render_report
from wpt.settings import BridgeSettings, load
from wpt.types import BridgeError, PlanItem, SourceError
from wpt.wpbridge.client import Bridge

#: The shipped profile — every threshold exactly as users get it.
DEFAULTS = load()

WEBROOT = "domains/example.com/public_html"
SITE = "https://example.com"

#: The generated credentials the fake op returns. These strings must never
#: reach a log record, the report or an exception message.
PASSWORD_ADMIN = "Adm1n-P@ss-UNIQUE-9f3c"
PASSWORD_EDITOR = "Ed1t0r-P@ss-UNIQUE-7ab1"
PASSWORD_AUTHOR = "Auth0r-P@ss-UNIQUE-5de2"
ALL_PASSWORDS = (PASSWORD_ADMIN, PASSWORD_EDITOR, PASSWORD_AUTHOR)


@pytest.fixture
def wpt_caplog(caplog):
    """caplog wired to the non-propagating wpt logger tree (see
    tests/actions/test_deactivate.py — the wpt parent never reaches root)."""
    parent = logging.getLogger("wpt")
    parent.addHandler(caplog.handler)
    with caplog.at_level(logging.DEBUG, logger="wpt"):
        yield caplog
    parent.removeHandler(caplog.handler)


# ------------------------------------------------------------------ helpers


def _ctx(tmp_path, *, settings=DEFAULTS, extra=None, **overrides):
    """A users_reset Ctx; ftp-mode defaults, overridable per test.

    The default target is ``--all``: the pre-existing tests below exercise
    the whole-site reset (the migration requirement the op was born from).
    Targeted tests pass ``extra={"logins": [...]}``; the no-target refusal
    has its own test.
    """
    fields = dict(
        source="ftp://example.com",
        settings=settings,
        command="users_reset",
        apply=False,
        yes=False,
        backup_dir=tmp_path / "backup",
        wp_url=SITE,
        extra={"all": True} if extra is None else extra,
    )
    fields.update(overrides)
    return Ctx(**fields)


def _tables(*names):
    """The named db_audit wire table rows (measured-zero free space)."""
    return [{"name": name, "rows": 10, "size_mb": 0.5, "data_free_kb": 0.0}
            for name in names]


def audit_payload(*table_names):
    """A db_audit payload; defaults to the core tables + users/usermeta."""
    if not table_names:
        table_names = (
            "wp_commentmeta", "wp_options", "wp_postmeta", "wp_posts",
            "wp_termmeta", "wp_usermeta", "wp_users",
        )
    return {
        "posts": [],
        "revisions": 0,
        "expired_transients": 0,
        "orphan_meta": {},
        "tables": _tables(*table_names),
        "autoload_bytes": 123456,
        "attachments": 3,
        "nav_menu_items": 2,
    }


def ok(**payload):
    """An ok:true bridge envelope (the payload the client returns)."""
    return FakeResponse(200, json.dumps({"ok": True, **payload}))


def _user(login, email, roles):
    return {"login": login, "email": email, "roles": roles}


def users_read_only(*rows):
    """The op's READ-ONLY answer: identities, never a password."""
    return ok(results={"users": list(rows), "count": len(rows)})


def users_applied(*rows):
    """The op's APPLIED answer: identities + the generated passwords."""
    passwords = iter(ALL_PASSWORDS)
    out = []
    for row in rows:
        out.append({
            **row,
            "sessions_destroyed": True,
            "password": next(passwords),
        })
    return ok(results={"users": out, "count": len(out)})


ADMIN = _user("admin", "admin@example.test", ["administrator"])
EDITOR = _user("editor", "editor@example.test", ["editor"])
AUTHOR = _user("author", "author@legacy.test", ["author", "subscriber"])


def table_lines(table, rows, create="CREATE TABLE `x` (id bigint)"):
    """Scripted db_dump NDJSON for one table: create, rows, done."""
    lines = [json.dumps({"table": table, "create": create})]
    for row in rows:
        lines.append(json.dumps({"table": table, "row": row}))
    lines.append(json.dumps({"table": table, "done": len(rows)}))
    return lines


def dump_lines(*tables):
    """One db_dump stream covering every table (the snapshot's ONE call)."""
    lines: list[str] = []
    for table in tables:
        lines.extend(table_lines(table, []))
    return lines


def _selfdestruct(src):
    """Script item playing the server side of the bridge self-destruct."""

    def handler(method, url, kwargs):
        name = url.removeprefix(f"{SITE}/").partition("?")[0]
        src.files.pop(f"{WEBROOT}/{name}", None)
        return FakeResponse(200, "gone")

    return handler


def make_stack(script):
    """A fake ftp-mode stack: (FakeSource, None, Bridge over FakeSession).

    The self-destruct handler rides last so the registry's ``finally:
    bridge.destroy()`` GET finds a scripted answer; unit tests that never
    destroy simply leave it unconsumed.
    """
    src = FakeSource()
    session = FakeSession(list(script) + [_selfdestruct(src)])
    bridge = Bridge(src, session, WEBROOT, BridgeSettings(), SITE)
    return src, session, bridge


def posted_actions(session):
    """Every bridge action POSTed, in order."""
    return [kwargs["json"]["action"] for _url, kwargs in session.posts]


def posted_params(session, action):
    """The ``params`` of every POST of ``action``."""
    return [kwargs["json"]["params"]
            for _url, kwargs in session.posts
            if kwargs["json"]["action"] == action]


def _records(caplog, name, level):
    return [r for r in caplog.records if r.name == name and r.levelno == level]


class _RawBridge:
    """A duck-typed bridge that answers EXACTLY the rows it was given.

    ``Bridge._users_payload`` validates the users_reset envelope and every
    row (a missing email is already a BridgeError there), so a real Bridge
    can never hand the action a malformed ROW. That validation belongs to
    another module; the row-content contract belongs to this one, and an
    action must hold it on its own. These tests therefore drive the action
    through a bridge that returns whatever it is given — which is exactly
    the shape that used to raise a bare KeyError out of the registry's
    ``except (WptError, OSError)``.
    """

    def __init__(self, *, users=None, rows=None, audit=None):
        self._users = users if users is not None else []
        self._rows = rows if rows is not None else []
        self._audit = audit if audit is not None else audit_payload()

    def list_users(self):
        return self._users

    def reset_users(self, logins=None):
        return self._rows

    def call(self, action, params=None, **_kw):
        assert action == "db_audit", f"unexpected bridge op: {action}"
        return self._audit


def _one_item_plan(detail="reset password for admin (administrator)"):
    """The plan of a single-user run (apply is driven directly, like the
    fail-closed tests above; the label is spelled out so the tests never
    depend on the module's private label builder)."""
    return Plan(items=[PlanItem(category="db.users", target="wp_users",
                                detail=detail)])


# ------------------------------------------------------------- registration


def test_registration():
    record = get_action("users_reset")
    assert record is not None
    assert record.applies == ("ftp",)
    assert isinstance(record.action, UsersResetAction)  # instance
    assert record.action.credentials == []  # nothing to hand the CLI yet


# ------------------------------------------------------------------- plan


def test_plan_dry_run_lists_users(tmp_path, wpt_caplog):
    src, session, bridge = make_stack([
        users_read_only(ADMIN, EDITOR, AUTHOR),
        ok(**audit_payload()),
    ])
    action = UsersResetAction()
    plan = action.plan(_ctx(tmp_path), (src, None, bridge))
    assert [
        (i.category, i.target, i.detail, i.bytes_est) for i in plan.items
    ] == [
        ("db.users", "wp_users", "reset password for admin (administrator)", 0),
        ("db.users", "wp_users", "reset password for editor (editor)", 0),
        ("db.users", "wp_users",
         "reset password for author (author, subscriber)", 0),
    ]
    # the EXACT tables the op mutates, pinned explicitly
    assert plan.backup_tables == ["wp_usermeta", "wp_users"]
    assert all(i.requires_apply for i in plan.items)
    assert all(not i.done for i in plan.items)
    # read-only wire: the apply flag is ABSENT (the bridge defaults it off)
    assert posted_actions(session) == ["users_reset", "db_audit"]
    assert posted_params(session, "users_reset") == [{}]
    summaries = _records(wpt_caplog, "wpt.actions.users_reset", logging.INFO)
    assert len(summaries) == 1
    assert "3 user(s) to reset" in summaries[0].getMessage()
    # nothing to hand the CLI after a dry run
    assert action.credentials == []


def test_plan_carries_no_password_anywhere(tmp_path):
    # A Plan is a PRINTED artifact (render_report reconstructs it from
    # items + backup_tables), so a credential in it would reach the report.
    src, session, bridge = make_stack([
        users_read_only(ADMIN, EDITOR, AUTHOR),
        ok(**audit_payload()),
    ])
    plan = UsersResetAction().plan(_ctx(tmp_path), (src, None, bridge))
    rendered = json.dumps(
        {"items": [i.__dict__ for i in plan.items],
         "backup_tables": plan.backup_tables},
        default=str,
    )
    for password in ALL_PASSWORDS:
        assert password not in rendered


def test_plan_clears_previous_credentials(tmp_path):
    # The registered action is a module-level INSTANCE: a second run must
    # never leave the previous run's secrets readable.
    action = UsersResetAction()
    action.credentials = [{"login": "admin", "email": "a", "password": "OLD"}]
    src, _session, bridge = make_stack([
        users_read_only(ADMIN), ok(**audit_payload()),
    ])
    action.plan(_ctx(tmp_path), (src, None, bridge))
    assert action.credentials == []


def test_plan_no_users_empty_plan(tmp_path, wpt_caplog):
    src, session, bridge = make_stack([users_read_only()])
    plan = UsersResetAction().plan(_ctx(tmp_path), (src, None, bridge))
    assert plan.items == []
    assert plan.backup_tables == []  # deliberately empty, not unset
    assert posted_actions(session) == ["users_reset"]  # no db_audit roundtrip
    infos = _records(wpt_caplog, "wpt.actions.users_reset", logging.INFO)
    assert len(infos) == 1
    assert "no users to reset" in infos[0].getMessage()


def test_plan_refuses_without_bridge(tmp_path):
    src = FakeSource()
    with pytest.raises(SourceError, match="bridge"):
        UsersResetAction().plan(_ctx(tmp_path), (src, None, None))


@pytest.mark.parametrize("tables", [
    ("wp_options", "wp_posts"),
    ("wp_users", "wp_options"),          # usermeta missing
    ("wp_usermeta", "wp_options"),       # users missing
])
def test_plan_refuses_unbacked(tmp_path, tables):
    src, _session, bridge = make_stack([
        users_read_only(ADMIN),
        ok(**audit_payload(*tables)),
    ])
    with pytest.raises(SourceError, match="unbacked"):
        UsersResetAction().plan(_ctx(tmp_path), (src, None, bridge))


def test_plan_backup_scope_fail_safe(tmp_path):
    # a stray *users-suffixed table merely WIDENS the snapshot scope (it is
    # snapshotted too), never a miss (deactivate-plugin's rule) — while the
    # item's target is the ONE table the identity owner resolves.
    src, _session, bridge = make_stack([
        users_read_only(ADMIN),
        ok(**audit_payload("wp_options", "wp_usermeta", "wp_myusers")),
    ])
    plan = UsersResetAction().plan(_ctx(tmp_path), (src, None, bridge))
    assert plan.backup_tables == ["wp_myusers", "wp_usermeta"]
    assert [i.target for i in plan.items] == ["wp_myusers"]


def test_plan_target_is_the_resolved_users_table_not_the_first_by_name(
        tmp_path):
    """THE MEASURED CASE: ``sorted()``[0] named another site's table.

    ``db_audit`` reports the whole ``information_schema`` base-table set, so
    on a schema holding a second ``*users`` table the plan item — and the
    ``--report`` artifact built from it — named a table the password reset
    never touches (the op writes through ``$wpdb->users`` server-side).  A
    contested identity is refused with both candidates named.
    """
    src, _session, bridge = make_stack([
        users_read_only(ADMIN),
        ok(**audit_payload("wp_options", "wp_usermeta", "wp_users",
                           "legacy_users")),
    ])
    with pytest.raises(SourceError) as excinfo:
        UsersResetAction().plan(_ctx(tmp_path), (src, None, bridge))
    message = str(excinfo.value)
    assert "legacy_users" in message and "wp_users" in message
    assert "target is unknown" in message


def test_plan_target_is_the_users_table_on_an_uncontested_site(tmp_path):
    src, _session, bridge = make_stack([
        users_read_only(ADMIN),
        ok(**audit_payload("wp_options", "wp_usermeta", "wp_users")),
    ])
    plan = UsersResetAction().plan(_ctx(tmp_path), (src, None, bridge))
    assert [i.target for i in plan.items] == ["wp_users"]
    assert plan.backup_tables == ["wp_usermeta", "wp_users"]


# ------------------------------------------------- targeted mode (--login)


def test_plan_requires_a_target(tmp_path):
    # The explicit reversal of the old implicit all-users default: a
    # nameless run refuses (and the registry writes a failure report for
    # it), before ANY bridge call.
    src, session, bridge = make_stack([])  # any bridge call would fail
    with pytest.raises(SourceError, match="needs a target"):
        UsersResetAction().plan(_ctx(tmp_path, extra={}), (src, None, bridge))
    assert session.posts == []


def test_plan_login_and_all_are_mutually_exclusive(tmp_path):
    src, session, bridge = make_stack([])
    with pytest.raises(SourceError, match="mutually exclusive"):
        UsersResetAction().plan(
            _ctx(tmp_path, extra={"logins": ["admin"], "all": True}),
            (src, None, bridge))
    assert session.posts == []


@pytest.mark.parametrize("logins", [[""], ["  "], [7], [None], "admin"])
def test_plan_rejects_bad_login_entries(tmp_path, logins):
    src, session, bridge = make_stack([])
    with pytest.raises(SourceError):
        UsersResetAction().plan(_ctx(tmp_path, extra={"logins": logins}),
                                (src, None, bridge))
    assert session.posts == []


def test_plan_targets_named_logins_case_insensitive(tmp_path, wpt_caplog):
    # --login ADMIN matches the inventory's "admin"; the plan carries the
    # CANONICAL login and only that account's item.
    src, session, bridge = make_stack([
        users_read_only(ADMIN, EDITOR, AUTHOR),
        ok(**audit_payload()),
    ])
    plan = UsersResetAction().plan(
        _ctx(tmp_path, extra={"logins": ["ADMIN"]}), (src, None, bridge))
    assert [i.detail for i in plan.items] == [
        "reset password for admin (administrator)",
    ]
    assert plan.backup_tables == ["wp_usermeta", "wp_users"]
    # The inventory is read WHOLE (the op is asked for everyone; the
    # narrowing is this side's), so an unknown login refuses before apply.
    assert posted_actions(session) == ["users_reset", "db_audit"]
    assert posted_params(session, "users_reset") == [{}]
    infos = _records(wpt_caplog, "wpt.actions.users_reset", logging.INFO)
    assert len(infos) == 1
    assert "1 user(s) to reset (targeted)" in infos[0].getMessage()


def test_plan_ref_is_the_login_when_a_role_contains_a_paren(tmp_path):
    """C11: ``editor (legacy)`` is a legal role name.  The old label parse
    read ``bob (editor`` as the login, so a second account with exactly that
    login was reset twice and ``bob`` was never reset.  The structural
    ``ref`` (not the human label) must carry the login end-to-end."""
    bob = _user("bob", "bob@example.test", ["editor (legacy)"])
    lookalike = _user("bob (editor", "look@example.test", ["subscriber"])
    src, session, bridge = make_stack([
        users_read_only(bob, lookalike),
        ok(**audit_payload()),
        users_applied(bob, lookalike),
    ])
    action = UsersResetAction()
    ctx = _ctx(tmp_path, extra={"logins": ["bob", "bob (editor"]})
    plan = action.plan(ctx, (src, None, bridge))

    assert [item.ref for item in plan.items] == ["bob", "bob (editor"]
    assert [item.detail for item in plan.items] == [
        "reset password for bob (editor (legacy))",
        # the label itself is ambiguous for this legal login; ref is the
        # structural contract that keeps the two accounts distinct.
        "reset password for bob (editor (subscriber)",
    ]

    ctx.apply = True
    applied = action.apply(ctx, (src, None, bridge), plan)
    assert all(item.done for item in applied.items)
    assert posted_params(session, "users_reset")[-1]["logins"] == [
        "bob", "bob (editor",
    ]
    assert [c["login"] for c in action.credentials] == [
        "bob", "bob (editor",
    ]


def test_plan_duplicate_logins_dedupe(tmp_path):
    src, _session, bridge = make_stack([
        users_read_only(ADMIN, EDITOR),
        ok(**audit_payload()),
    ])
    plan = UsersResetAction().plan(
        _ctx(tmp_path, extra={"logins": ["admin", "Admin", "editor"]}),
        (src, None, bridge))
    assert [i.detail for i in plan.items] == [
        "reset password for admin (administrator)",
        "reset password for editor (editor)",
    ]


def test_plan_unknown_login_names_the_roster(tmp_path):
    # The discovery path for an operator who does not know the exact
    # spelling: the refusal names the requested login AND the roster.
    src, session, bridge = make_stack([users_read_only(ADMIN, EDITOR, AUTHOR)])
    with pytest.raises(SourceError) as excinfo:
        UsersResetAction().plan(
            _ctx(tmp_path, extra={"logins": ["ghost"]}), (src, None, bridge))
    message = str(excinfo.value)
    assert "no such user: ghost" in message
    assert "admin, editor, author" in message
    assert posted_actions(session) == ["users_reset"]  # nothing further


def test_plan_unknown_login_on_an_empty_site(tmp_path):
    src, _session, bridge = make_stack([users_read_only()])
    with pytest.raises(SourceError, match="the site has no users"):
        UsersResetAction().plan(
            _ctx(tmp_path, extra={"logins": ["admin"]}), (src, None, bridge))


# ------------------------------------------------------------------ apply


def test_apply_resets_every_user(tmp_path, wpt_caplog):
    src, session, bridge = make_stack([
        users_read_only(ADMIN, EDITOR, AUTHOR),
        ok(**audit_payload()),
        users_applied(ADMIN, EDITOR, AUTHOR),
    ])
    action = UsersResetAction()
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, (src, None, bridge))
    applied = action.apply(ctx, (src, None, bridge), plan)
    assert applied is plan  # the same Plan object, items updated in place
    assert posted_actions(session) == ["users_reset", "db_audit", "users_reset"]
    # the apply call carries the STRICT apply flag (and only the dry-run
    # call above omitted it)
    assert posted_params(session, "users_reset") == [{}, {"apply": True}]
    assert all(i.done for i in applied.items)
    assert [i.detail for i in applied.items] == [
        "reset password for admin (administrator), password reset",
        "reset password for editor (editor), password reset",
        "reset password for author (author, subscriber), password reset",
    ]
    # the credentials reach the CLI presentation layer and NOWHERE else
    assert action.credentials == [
        {"login": "admin", "email": "admin@example.test",
         "password": PASSWORD_ADMIN},
        {"login": "editor", "email": "editor@example.test",
         "password": PASSWORD_EDITOR},
        {"login": "author", "email": "author@legacy.test",
         "password": PASSWORD_AUTHOR},
    ]
    summaries = _records(wpt_caplog, "wpt.actions.users_reset", logging.INFO)
    assert len(summaries) == 2  # one plan summary, one apply summary
    assert "3 user(s) reset" in summaries[1].getMessage()
    assert "session tokens destroyed for 3" in summaries[1].getMessage()
    for password in ALL_PASSWORDS:
        assert password not in summaries[1].getMessage()


def test_apply_targeted_sends_the_logins(tmp_path, wpt_caplog):
    src, session, bridge = make_stack([
        users_read_only(ADMIN, EDITOR),
        ok(**audit_payload()),
        users_applied(EDITOR),
    ])
    action = UsersResetAction()
    ctx = _ctx(tmp_path, extra={"logins": ["editor"]})
    plan = action.plan(ctx, (src, None, bridge))
    applied = action.apply(ctx, (src, None, bridge), plan)
    assert all(i.done for i in applied.items)
    # the apply carries the TARGET list, never the all-users shape
    assert posted_params(session, "users_reset") == [
        {}, {"apply": True, "logins": ["editor"]},
    ]
    assert action.credentials == [
        {"login": "editor", "email": "editor@example.test",
         "password": PASSWORD_ADMIN},
    ]
    infos = _records(wpt_caplog, "wpt.actions.users_reset", logging.INFO)
    assert "1 user(s) to reset (targeted)" in infos[0].getMessage()
    assert "1 user(s) reset" in infos[1].getMessage()


def test_apply_targeted_missing_result_fails_closed(tmp_path):
    # A targeted op that answered another account (only reachable if the
    # server ignored the filter) still fails the plan/result comparison.
    plan = Plan(items=[
        PlanItem(category="db.users", target="wp_users",
                 detail="reset password for editor (editor)"),
    ])
    src, _session, bridge = make_stack([users_applied(ADMIN)])
    action = UsersResetAction()
    with pytest.raises(BridgeError, match="did not report a password"):
        action.apply(_ctx(tmp_path, extra={"logins": ["editor"]}),
                     (src, None, bridge), plan)
    assert not plan.items[0].done
    # the reply's credential is still published (that password is live)
    assert [c["login"] for c in action.credentials] == ["admin"]


def test_login_containing_a_space_round_trips_plan_to_apply(tmp_path):
    # A WordPress login may contain spaces: sanitize_user() keeps them even
    # in STRICT mode, the mode wp_insert_user() uses (an imported or
    # programmatically created account — exactly what a migration carries).
    # The plan/apply correspondence is the label, so a parser that splits
    # the label at the first space truncates "site owner" to "site" and the
    # apply then fails its own verification on an account that was reset
    # correctly — rc 1 for a run that did exactly what it said.
    owner = _user("site owner", "owner@example.test", ["administrator"])
    src, session, bridge = make_stack([
        users_read_only(ADMIN, owner),
        ok(**audit_payload()),
        users_applied(ADMIN, owner),
    ])
    action = UsersResetAction()
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, (src, None, bridge))
    assert [i.detail for i in plan.items] == [
        "reset password for admin (administrator)",
        "reset password for site owner (administrator)",
    ]
    applied = action.apply(ctx, (src, None, bridge), plan)
    assert all(i.done for i in applied.items)
    assert [i.detail for i in applied.items] == [
        "reset password for admin (administrator), password reset",
        "reset password for site owner (administrator), password reset",
    ]
    assert [row["login"] for row in action.credentials] == [
        "admin", "site owner",
    ]
    # The printed report names the account in full, so the operator can
    # match it to the credentials the CLI prints.
    assert "reset password for site owner (administrator)" in \
        render_report(_report_stub(), applied)


def _report_stub():
    from wpt.report import AuditReport

    return AuditReport(site="example.com", source_summary="action plan (ftp)")


def test_apply_empty_plan_no_bridge_call(tmp_path):
    src, session, bridge = make_stack([])  # any POST would fail the fake
    plan = Plan(items=[], backup_tables=[])
    action = UsersResetAction()
    assert action.apply(_ctx(tmp_path), (src, None, bridge), plan) is plan
    assert session.posts == []  # nothing planned -> no bridge roundtrip
    assert action.credentials == []


def test_apply_unplanned_user_fails_closed(tmp_path):
    # A user created between plan and apply gets reset too — the operator
    # must know (rc 1, snapshot intact), and must still receive the
    # credentials, because that account's old password is already gone.
    plan = Plan(items=[
        PlanItem(category="db.users", target="wp_users",
                 detail="reset password for admin (administrator)"),
    ])
    src, _session, bridge = make_stack([users_applied(ADMIN, AUTHOR)])
    action = UsersResetAction()
    with pytest.raises(BridgeError, match="not in the plan"):
        action.apply(_ctx(tmp_path), (src, None, bridge), plan)
    assert not plan.items[0].done
    # the credentials are still published: that account's old password is
    # already revoked, so the operator MUST receive its new one
    assert [c["login"] for c in action.credentials] == ["admin", "author"]


def test_apply_missing_user_fails_closed(tmp_path):
    plan = Plan(items=[
        PlanItem(category="db.users", target="wp_users",
                 detail="reset password for editor (editor)"),
    ])
    src, _session, bridge = make_stack([users_applied(ADMIN)])
    action = UsersResetAction()
    with pytest.raises(BridgeError, match="did not report a password"):
        action.apply(_ctx(tmp_path), (src, None, bridge), plan)
    assert not plan.items[0].done
    assert [c["login"] for c in action.credentials] == ["admin"]


def test_apply_publishes_partial_credentials_on_a_per_user_failure(tmp_path):
    """C12: when the bridge fails closed after user 1, the action must hand
    over every complete row (those passwords are already live) before the
    error unwinds."""
    row = {"login": "admin", "email": "admin@example.test",
           "roles": ["administrator"], "sessions_destroyed": True,
           "password": PASSWORD_ADMIN}

    class _PartialBridge:
        def reset_users(self, logins=None):
            raise BridgeError("users_reset failed for editor",
                              payload={"partial_users": [row]})

    plan = Plan(items=[PlanItem(category="db.users", target="wp_users",
                                detail="reset password for admin "
                                       "(administrator)", ref="admin")])
    action = UsersResetAction()
    with pytest.raises(BridgeError, match="failed for editor"):
        action.apply(_ctx(tmp_path), (FakeSource(), None, _PartialBridge()),
                     plan)
    assert not plan.items[0].done
    assert action.credentials == [
        {"login": "admin", "email": "admin@example.test",
         "password": PASSWORD_ADMIN},
    ]


def test_apply_server_error_propagates(tmp_path):
    plan = Plan(items=[
        PlanItem(category="db.users", target="wp_users",
                 detail="reset password for admin (administrator)"),
    ])
    src, _session, bridge = make_stack([
        FakeResponse(200, json.dumps({"ok": False, "error": "db error: lock"})),
    ])
    action = UsersResetAction()
    with pytest.raises(BridgeError, match="db error: lock"):
        action.apply(_ctx(tmp_path), (src, None, bridge), plan)
    assert not plan.items[0].done
    assert action.credentials == []  # nothing was reset, nothing to hand over


def test_apply_skips_non_apply_items(tmp_path):
    plan = Plan(items=[
        PlanItem(category="db.users", target="wp_users",
                 detail="reset password for admin (administrator)"),
        PlanItem(category="db.users", target="none", detail="advice",
                 requires_apply=False),
    ])
    src, _session, bridge = make_stack([users_applied(ADMIN)])
    applied = UsersResetAction().apply(_ctx(tmp_path), (src, None, bridge), plan)
    assert applied.items[0].done
    assert not applied.items[1].done
    assert applied.items[1].detail == "advice"  # never enriched


def test_apply_malformed_row_refuses_without_swallowing_good_rows(tmp_path):
    # The op already SET every password it returned, so a refusal must be
    # about the run's VERDICT, never about withholding a live credential:
    # the complete sibling row is published (the CLI prints it on the rc-1
    # run) while the unusable one is never published half-filled — an
    # account name next to an empty password is a credential the operator
    # would try and fail.
    plan = Plan(items=[
        PlanItem(category="db.users", target="wp_users",
                 detail="reset password for admin (administrator)"),
        PlanItem(category="db.users", target="wp_users",
                 detail="reset password for editor (editor)"),
    ])
    bridge = _RawBridge(rows=[
        {"login": "admin", "email": "admin@example.test",
         "sessions_destroyed": True, "password": PASSWORD_ADMIN},
        {"login": "editor", "email": "editor@example.test",
         "sessions_destroyed": True},  # no password came back
    ])
    action = UsersResetAction()
    with pytest.raises(BridgeError) as excinfo:
        action.apply(_ctx(tmp_path), (FakeSource(), None, bridge), plan)
    message = str(excinfo.value)
    assert "unusable credential row" in message
    assert "row 1 (login='editor')" in message  # named, never valued
    for password in (PASSWORD_ADMIN, PASSWORD_EDITOR):
        assert password not in message
    assert not any(i.done for i in plan.items)
    assert action.credentials == [
        {"login": "admin", "email": "admin@example.test",
         "password": PASSWORD_ADMIN},
    ]  # whole or nothing: no editor record at all


@pytest.mark.parametrize("bad_row", [
    {"login": "admin", "email": "admin@example.test"},          # no password
    {"login": "admin", "email": "admin@example.test",
     "password": ""},                                          # blank password
    {"login": "admin", "email": "admin@example.test",
     "password": 42},                                          # non-string
    {"email": "admin@example.test", "password": PASSWORD_ADMIN},  # no login
    {"login": "", "password": PASSWORD_ADMIN},                 # blank login
    {"login": 7, "password": PASSWORD_ADMIN},                 # non-string
    "admin",                                                   # not a dict
    None,                                                      # a null row
], ids=["no-password", "blank-password", "int-password", "no-login",
        "blank-login", "int-login", "string-row", "null-row"])
def test_apply_malformed_row_shapes(tmp_path, bad_row):
    # Every unusable shape is refused INSIDE the error contract. Before
    # the fix these escaped as KeyError/TypeError, which the registry does
    # not catch: the operator got a traceback, a lost rc, and — because
    # the comprehension died before the assignment — no credentials at all
    # for a site whose passwords had just been revoked.
    plan = _one_item_plan()
    bridge = _RawBridge(rows=[bad_row])
    action = UsersResetAction()
    with pytest.raises(BridgeError) as excinfo:
        action.apply(_ctx(tmp_path), (FakeSource(), None, bridge), plan)
    assert "unusable credential row" in str(excinfo.value)
    assert PASSWORD_ADMIN not in str(excinfo.value)
    assert not plan.items[0].done
    assert action.credentials == []  # nothing publishable was returned


def test_apply_row_without_email_succeeds(tmp_path):
    # A WordPress user may genuinely have no address, so a missing email is
    # NOT a malformed answer: the reset succeeds, the item is done, and the
    # password is handed over with a blank email.
    plan = _one_item_plan()
    bridge = _RawBridge(rows=[
        {"login": "admin", "sessions_destroyed": True,
         "password": PASSWORD_ADMIN},
    ])
    action = UsersResetAction()
    applied = action.apply(_ctx(tmp_path), (FakeSource(), None, bridge), plan)
    assert applied.items[0].done
    assert action.credentials == [
        {"login": "admin", "email": "", "password": PASSWORD_ADMIN},
    ]


def test_plan_malformed_inventory_row_refuses(tmp_path):
    # Same mechanism, read-only side: a row with no login cannot be
    # LABELLED, and the label is the only carrier of the account into the
    # plan's items. Direct indexing used to raise KeyError out of the plan
    # phase (a traceback, not rc 1).
    bridge = _RawBridge(users=[
        {"login": "admin", "email": "admin@example.test",
         "roles": ["administrator"]},
        {"email": "ghost@example.test", "roles": []},  # no login
    ])
    with pytest.raises(BridgeError, match="cannot plan"):
        UsersResetAction().plan(_ctx(tmp_path), (FakeSource(), None, bridge))


def test_registry_malformed_row_is_clean(tmp_path, capsys, monkeypatch,
                                         wpt_caplog):
    # The real end-to-end path: a payload the CLIENT cannot vouch for
    # (Bridge._users_payload refuses a row with no password) must end as
    # rc 1 + ONE clean error line, never a traceback — and the action's
    # holder must stay EMPTY, because no usable row ever came back.
    src, session, bridge = make_stack([
        users_read_only(ADMIN),
        ok(**audit_payload()),
        FakeResponse(200, lines=dump_lines("wp_usermeta", "wp_users")),
        ok(results={"users": [{"login": "admin",
                              "email": "admin@example.test",
                              "roles": ["administrator"],
                              "sessions_destroyed": True}],
                    "count": 1}),
    ])
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "users_reset")
    assert rc == 1
    out = capsys.readouterr().out
    assert "Traceback" not in out  # the error contract held
    errors = _records(wpt_caplog, "wpt.actions", logging.ERROR)
    assert len(errors) == 1  # ONE clean message
    assert "no password" in errors[0].getMessage()
    assert get_action("users_reset").action.credentials == []
    for password in ALL_PASSWORDS:
        assert password not in out
        assert password not in str(errors[0].__dict__)


def test_secrets_never_reach_log_or_report(tmp_path, capsys, monkeypatch,
                                          wpt_caplog):
    # The hard secrets rule, asserted end to end: a full registry apply
    # writes the generated passwords NOWHERE but the credentials the CLI
    # prints itself.
    src, session, bridge = make_stack([
        users_read_only(ADMIN, EDITOR, AUTHOR),
        ok(**audit_payload()),
        FakeResponse(200, lines=dump_lines("wp_usermeta", "wp_users")),
        users_applied(ADMIN, EDITOR, AUTHOR),
        ok(purged=True),
    ])
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "users_reset")
    assert rc == 0
    out = capsys.readouterr().out
    assert "## Plan" in out  # the registry DID print its redacted report
    for password in ALL_PASSWORDS:
        assert password not in out
    assert wpt_caplog.records
    for record in wpt_caplog.records:
        assert password not in str(record.__dict__)


# ------------------------------------------------------- registry end-to-end


def test_registry_dry_run(tmp_path, capsys, monkeypatch):
    src, session, bridge = make_stack([
        users_read_only(ADMIN, EDITOR),
        ok(**audit_payload()),
    ])
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    rc = run_action(_ctx(tmp_path), "users_reset")
    assert rc == 0
    out = capsys.readouterr().out
    assert "## Plan" in out
    assert "db.users" in out
    assert "reset password for admin (administrator)" in out
    # read-only: the inventory + db_audit, no backup dump, and the
    # users_reset call carried NO apply flag
    assert posted_actions(session) == ["users_reset", "db_audit"]
    assert posted_params(session, "users_reset") == [{}]


def test_registry_ftp_apply_end_to_end(tmp_path, capsys, monkeypatch):
    src, session, bridge = make_stack([
        users_read_only(ADMIN, EDITOR),
        ok(**audit_payload()),
        FakeResponse(200, lines=dump_lines("wp_usermeta", "wp_users")),
        users_applied(ADMIN, EDITOR),
        ok(purged=True),  # the registry's post-apply purge answer
    ])
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "users_reset")
    assert rc == 0
    assert posted_actions(session) == ["users_reset", "db_audit", "db_dump",
                                       "users_reset", "purge_cache"]
    # the fail-closed pre-action snapshot covers EXACTLY the two tables the
    # op mutates — no more, no less
    assert posted_params(session, "db_dump") == [
        {"tables": ["wp_usermeta", "wp_users"]},
    ]
    assert posted_params(session, "users_reset") == [{}, {"apply": True}]
    manifests = list((tmp_path / "backup").glob("*/*/manifest.json"))
    assert len(manifests) == 1
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    assert manifest["action"] == "users_reset"
    assert [t["name"] for t in manifest["tables"]] == ["wp_usermeta", "wp_users"]
    assert manifest["files"] == []  # DB-only action
    out = capsys.readouterr().out
    assert out.count("| yes |") == 2
    assert "password reset" in out
    # the credentials are on the registered action for the CLI to print
    credentials = get_action("users_reset").action.credentials
    assert [c["login"] for c in credentials] == ["admin", "editor"]


def test_report_file_carries_the_plan_and_never_a_password(tmp_path, capsys,
                                                           monkeypatch):
    """--report is the tool's universal contract, and a users_reset run
    honours it without ever widening what a report may carry: the file
    holds the redacted plan, the generated passwords stay on stdout (the
    CLI's own print) and in no file, no log record and no plan item."""
    src, session, bridge = make_stack([
        users_read_only(ADMIN, EDITOR),
        ok(**audit_payload()),
        FakeResponse(200, lines=dump_lines("wp_usermeta", "wp_users")),
        users_applied(ADMIN, EDITOR),
        ok(purged=True),  # the registry's post-apply purge answer
    ])
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    report = tmp_path / "reset.md"
    rc = run_action(_ctx(tmp_path, apply=True, yes=True, report_path=report),
                    "users_reset")
    assert rc == 0
    assert report.exists()
    written = report.read_text(encoding="utf-8")
    # the plan is there — the report is this run's result, not a stub
    assert "## Plan" in written
    assert "reset password for admin (administrator)" in written
    assert "reset password for editor (editor)" in written
    assert written.count("| yes |") == 2
    # ...and NO generated password anywhere in it (stdout-only rule)
    for password in ALL_PASSWORDS:
        assert password not in written
    twin = report.with_suffix(".json")
    assert twin.exists()
    assert not [p for p in ALL_PASSWORDS
                if p in twin.read_text(encoding="utf-8")]
    out = capsys.readouterr().out
    assert "## Plan" in out
    for password in ALL_PASSWORDS:
        assert password not in out


def test_registry_snapshot_failure_refuses_apply(tmp_path, capsys, monkeypatch,
                                                wpt_caplog):
    # No working backup -> the registry refuses to mutate (fail-closed):
    # the reset never runs and no credential exists.
    src, session, bridge = make_stack([
        users_read_only(ADMIN),
        ok(**audit_payload()),
        FakeResponse(200, json.dumps({"ok": False, "error": "db dump failed"})),
    ])
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "users_reset")
    assert rc == 1
    assert posted_actions(session) == ["users_reset", "db_audit", "db_dump"]
    assert posted_params(session, "users_reset") == [{}]  # never applied
    assert capsys.readouterr().out == ""
    errors = _records(wpt_caplog, "wpt.actions", logging.ERROR)
    assert errors
    assert "pre-action backup failed" in errors[0].getMessage()
    assert "refusing to apply" in errors[0].getMessage()
    assert get_action("users_reset").action.credentials == []


def test_registry_local_mode_refused(tmp_path, wpt_caplog, monkeypatch):
    built = []

    def fail_stack(ctx):
        built.append(ctx)
        raise AssertionError("_stack must not be built for an inapplicable mode")

    monkeypatch.setattr(registry_mod, "_stack", fail_stack)
    rc = run_action(
        _ctx(tmp_path, source="local", zip=tmp_path / "site.zip",
             apply=True, yes=True),
        "users_reset",
    )
    assert rc == 1  # ftp-only: a local zip has no WordPress to reset
    assert built == []
    errors = _records(wpt_caplog, "wpt.actions", logging.ERROR)
    assert errors
    message = errors[0].getMessage()
    assert "ftp" in message and "local" in message


def test_report_renders_the_login_intact(tmp_path):
    # The label must survive the report's shared redactor: a
    # ``password: <value>`` shape would be blanked to "password=***" and
    # the operator would lose the account the plan item is about.
    from wpt.report import AuditReport

    action = UsersResetAction()
    src, _session, bridge = make_stack([
        users_read_only(ADMIN), ok(**audit_payload()),
    ])
    plan = action.plan(_ctx(tmp_path), (src, None, bridge))
    rendered = render_report(
        AuditReport(site="example.com", source_summary="action plan (ftp)"),
        plan,
    )
    assert "reset password for admin (administrator)" in rendered
    assert "password=" not in rendered
    assert PASSWORD_ADMIN not in rendered


def test_a_refused_run_writes_a_credential_free_report(tmp_path, monkeypatch,
                                                        capsys):
    """The users_reset secrets contract, extended to the report a FAILED
    run now writes (L44: every dry run got a report; a failed run wrote
    nothing, so a caller could not tell "planned nothing" from "never got
    far enough").

    The pre-action backup refuses here, so the op never runs and NO
    password is ever generated — and the report that explains the refusal
    must not be a place one could appear.  The credential reaches the
    operator once, on stdout, from the CLI; a file is not that.
    """
    src, session, bridge = make_stack([
        users_read_only(ADMIN),
        ok(**audit_payload()),
        FakeResponse(200, json.dumps({"ok": False, "error": "db dump failed"})),
    ])
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    report = tmp_path / "out.md"
    ctx = _ctx(tmp_path, apply=True, yes=True, report_path=report)

    assert run_action(ctx, "users_reset") == 1

    # the refusal is on disk and names itself
    written = report.read_text(encoding="utf-8")
    assert "## This run did not complete" in written
    assert "pre-action backup failed" in written
    assert "db_dump stream never mentioned table" in written
    assert "- findings: 0" in written
    twin = report.with_suffix(".json").read_text(encoding="utf-8")
    assert json.loads(twin)["run"]["findings"] == 0
    # the reset never ran
    assert posted_params(session, "users_reset") == [{}]
    # ... and no password reached ANY of the three surfaces
    for stream in (written, twin, capsys.readouterr().out):
        for password in ALL_PASSWORDS:
            assert password not in stream
    assert get_action("users_reset").action.credentials == []
