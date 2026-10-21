"""Tests for the user-create action (wpt.actions.user_create).

Same harness conventions as tests/actions/test_users_reset.py: a REAL Bridge
over FakeSession/FakeSource with scripted user_create / db_audit / db_dump
answers — deterministic, no network, no sleeps — and the registry end-to-end
tests monkeypatch ``wpt.actions.registry._stack`` (the pinned seam) so the
real ``run_action`` flow (plan, confirm, fail-closed snapshot, apply, purge)
runs over the fake ftp-mode stack.

Test -> behavior map:
  test_registration ......................... user-create registered as the
        INSTANCE under applies=("ftp",) — local mode can never reach it
  test_plan_read_only_validation ............ ONE read-only user_create
        (apply absent) + db_audit; the item names the sanitized login, the
        target is the resolved users table, backup_tables = users+usermeta;
        NO password exists anywhere in the plan
  test_plan_uses_the_sanitized_login ........ the bridge's read-back login
        (sanitize_user strict) is what the plan and the report carry
  test_plan_clears_previous_credentials ..... a fresh run never exposes a
        previous run's secret
  test_plan_requires_the_request_fields ..... login/email/role guards keep a
        direct misuse inside the error contract
  test_plan_refuses_without_bridge .......... no bridge -> SourceError
        before any roundtrip
  test_plan_refuses_unbacked / contested .... the shared user-table
        identity rule refuses an unbacked or contested plan
  test_apply_creates_and_publishes .......... ONE apply call; the item is
        done + enriched; the credential reaches the CLI holder and nowhere
        else; NO password in the apply log line
  test_apply_wrong_login_fails_closed ....... a read-back login that is not
        the planned one -> BridgeError, the live credential is STILL
        published (the account exists), the item stays undone
  test_apply_malformed_row_refuses .......... a row with no usable
        login+password pair -> BridgeError inside the error contract and NO
        half-filled credential published
  test_apply_empty_plan_no_bridge_call ...... nothing planned -> no
        roundtrip
  test_secrets_never_reach_log_or_report .... after a full registry apply
        the generated password appears in NEITHER any captured log record
        NOR stdout (the report the registry prints) NOR the report file
        (--report), only in the credentials the CLI prints itself
  test_registry_malformed_row_is_clean ...... the real path end to end: the
        client refuses a passwordless row -> rc 1, ONE clean error record,
        no traceback, holder EMPTY
  test_registry_dry_run ..................... run_action apply=False: rc 0,
        read-only user_create + db_audit, no db_dump, no apply flag
  test_registry_ftp_apply_end_to_end ........ apply --yes: the pre-action
        snapshot manifest lists EXACTLY wp_users + wp_usermeta, user_create
        called with apply=True, purge_cache once, rc 0
  test_report_file_carries_the_plan_and_never_a_password  the --report
        artifact holds the plan, never the credential
  test_registry_snapshot_failure_refuses_apply  a refusing backup -> rc 1,
        the apply NEVER runs, no credential published
  test_registry_local_mode_refused .......... local mode: rc 1, the
        ftp-only applicability error, the stack never built
"""

import json
import logging

import pytest

from tests.fakes import FakeResponse, FakeSession, FakeSource
from wpt.actions import registry as registry_mod
from wpt.actions.registry import get_action, run_action
from wpt.actions.user_create import UserCreateAction
from wpt.cli import Ctx
from wpt.report import Plan, PlanItem, render_report
from wpt.settings import BridgeSettings, load
from wpt.types import BridgeError, SourceError
from wpt.wpbridge.client import Bridge

#: The shipped profile — every threshold exactly as users get it.
DEFAULTS = load()

WEBROOT = "domains/example.com/public_html"
SITE = "https://example.com"

#: The generated credential the fake op returns. This string must never
#: reach a log record, the report, a file or an exception message.
CREATE_PASSWORD = "N3w-Adm1n-UNIQUE-2c9f"

LOGIN = "newadmin"
EMAIL = "new@example.test"
ROLE = "administrator"


def _ctx(tmp_path, *, settings=DEFAULTS, extra=None, **overrides):
    """A user-create Ctx; ftp-mode defaults, overridable per test."""
    fields = dict(
        source="ftp://example.com",
        settings=settings,
        command="user-create",
        apply=False,
        yes=False,
        backup_dir=tmp_path / "backup",
        wp_url=SITE,
        extra={"login": LOGIN, "email": EMAIL, "role": ROLE}
        if extra is None else extra,
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


def created_read_only(login=LOGIN, email=EMAIL, roles=(ROLE,)):
    """The op's READ-ONLY answer: the account that WOULD be created."""
    return ok(results={
        "user": {"login": login, "email": email, "roles": list(roles)},
        "apply": False,
    })


def created_applied(login=LOGIN, email=EMAIL, roles=(ROLE,),
                    password=CREATE_PASSWORD):
    """The op's APPLIED answer: the read-back + the generated password."""
    return ok(results={
        "user": {"login": login, "email": email, "roles": list(roles),
                 "password": password},
        "apply": True,
    })


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
    """A fake ftp-mode stack: (FakeSource, None, Bridge over FakeSession)."""
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


def _records(records, name, level):
    return [r for r in records if r.name == name and r.levelno == level]


class _RawBridge:
    """A duck-typed bridge that answers EXACTLY the rows it was given.

    ``Bridge._created_user_payload`` validates the envelope and the row (a
    missing password is already a BridgeError there), so a real Bridge can
    never hand the action a malformed ROW.  That validation belongs to
    another module; the row-content contract belongs to this one, and an
    action must hold it on its own.
    """

    def __init__(self, *, checked=None, rows=None, audit=None):
        self._checked = checked if checked is not None else {
            "login": LOGIN, "email": EMAIL, "roles": [ROLE],
        }
        self._rows = rows if rows is not None else []
        self._audit = audit if audit is not None else audit_payload()

    def check_create_user(self, login, email, role):
        return self._checked

    def create_user(self, login, email, role):
        return self._rows

    def call(self, action, params=None, **_kw):
        assert action == "db_audit", f"unexpected bridge op: {action}"
        return self._audit


# ------------------------------------------------------------- registration


def test_registration():
    record = get_action("user-create")
    assert record is not None
    assert record.applies == ("ftp",)
    assert isinstance(record.action, UserCreateAction)  # instance
    # The credential holder is a per-instance list owned by the action; the
    # CLI clears it BEFORE every run (test_user_create_prints_the_credentials_
    # once_after_the_run covers that dispatch contract).  Registration must
    # not invent process-wide state of its own.
    assert isinstance(record.action.credentials, list)


# ------------------------------------------------------------------- plan


def test_plan_read_only_validation(tmp_path, wpt_records):
    src, session, bridge = make_stack([
        created_read_only(),
        ok(**audit_payload()),
    ])
    action = UserCreateAction()
    plan = action.plan(_ctx(tmp_path), (src, None, bridge))
    assert [(i.category, i.target, i.detail, i.bytes_est) for i in plan.items] \
        == [("db.users", "wp_users",
             "create administrator newadmin (new@example.test)", 0)]
    assert plan.backup_tables == ["wp_usermeta", "wp_users"]
    assert plan.items[0].requires_apply
    assert not plan.items[0].done
    # read-only wire: the apply flag is ABSENT, and nothing was dumped
    assert posted_actions(session) == ["user_create", "db_audit"]
    assert posted_params(session, "user_create") == [
        {"login": LOGIN, "email": EMAIL, "role": ROLE},
    ]
    summaries = _records(wpt_records, "wpt.actions.user_create", logging.INFO)
    assert len(summaries) == 1
    assert "create 1 administrator account (newadmin)" in \
        summaries[0].getMessage()
    # nothing to hand the CLI after a dry run
    assert action.credentials == []
    rendered = json.dumps(
        {"items": [i.__dict__ for i in plan.items],
         "backup_tables": plan.backup_tables},
        default=str,
    )
    assert CREATE_PASSWORD not in rendered


def test_plan_uses_the_sanitized_login(tmp_path):
    # The read-only op answers the login AFTER sanitize_user(strict), which
    # is what wp_insert_user will create; the plan must carry THAT login,
    # not the raw request spelling.
    src, _session, bridge = make_stack([
        created_read_only(login="new admin"),
        ok(**audit_payload()),
    ])
    plan = UserCreateAction().plan(_ctx(tmp_path, extra={
        "login": "<b>new admin</b>", "email": EMAIL, "role": ROLE,
    }), (src, None, bridge))
    assert plan.items[0].detail == \
        "create administrator new admin (new@example.test)"


def test_plan_clears_previous_credentials(tmp_path):
    action = UserCreateAction()
    action.credentials = [{"login": "old", "email": "o", "password": "OLD"}]
    src, _session, bridge = make_stack([
        created_read_only(), ok(**audit_payload()),
    ])
    action.plan(_ctx(tmp_path), (src, None, bridge))
    assert action.credentials == []


@pytest.mark.parametrize("extra,error", [
    ({"email": EMAIL, "role": ROLE}, "login"),
    ({"login": LOGIN, "role": ROLE}, "email"),
    ({"login": LOGIN, "email": EMAIL}, "role"),
    ({"login": "  ", "email": EMAIL, "role": ROLE}, "login"),
    ({"login": LOGIN, "email": EMAIL, "role": ""}, "role"),
])
def test_plan_requires_the_request_fields(tmp_path, extra, error):
    src, session, bridge = make_stack([])  # any bridge call would fail
    with pytest.raises(SourceError, match=error):
        UserCreateAction().plan(_ctx(tmp_path, extra=extra),
                                (src, None, bridge))
    assert session.posts == []


def test_plan_refuses_without_bridge(tmp_path):
    with pytest.raises(SourceError, match="bridge"):
        UserCreateAction().plan(_ctx(tmp_path), (FakeSource(), None, None))


def test_plan_refuses_unbacked(tmp_path):
    src, _session, bridge = make_stack([
        created_read_only(),
        ok(**audit_payload("wp_users", "wp_options")),  # usermeta missing
    ])
    with pytest.raises(SourceError, match="unbacked"):
        UserCreateAction().plan(_ctx(tmp_path), (src, None, bridge))


def test_plan_refuses_a_contested_users_identity(tmp_path):
    src, _session, bridge = make_stack([
        created_read_only(),
        ok(**audit_payload("wp_options", "wp_usermeta", "wp_users",
                           "legacy_users")),
    ])
    with pytest.raises(SourceError, match="target is unknown"):
        UserCreateAction().plan(_ctx(tmp_path), (src, None, bridge))


def test_plan_backup_scope_fail_safe(tmp_path):
    # A stray *users-suffixed table WIDENS the snapshot scope; the item's
    # target stays the ONE table the identity owner resolves.
    src, _session, bridge = make_stack([
        created_read_only(),
        ok(**audit_payload("wp_options", "wp_usermeta", "wp_myusers")),
    ])
    plan = UserCreateAction().plan(_ctx(tmp_path), (src, None, bridge))
    assert plan.backup_tables == ["wp_myusers", "wp_usermeta"]
    assert plan.items[0].target == "wp_myusers"


def test_plan_bridge_refusal_propagates(tmp_path):
    # The read-only op refuses a duplicate login: the plan must fail with
    # that message, never proceed to a mutation the site already refused.
    src, session, bridge = make_stack([
        FakeResponse(200, json.dumps({"ok": False, "error":
                                      "a user with that login already exists: admin"})),
    ])
    with pytest.raises(BridgeError, match="already exists: admin"):
        UserCreateAction().plan(_ctx(tmp_path), (src, None, bridge))
    assert posted_actions(session) == ["user_create"]


# ------------------------------------------------------------------ apply


def test_apply_creates_and_publishes(tmp_path, wpt_records):
    src, session, bridge = make_stack([
        created_read_only(),
        ok(**audit_payload()),
        created_applied(),
    ])
    action = UserCreateAction()
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, (src, None, bridge))
    applied = action.apply(ctx, (src, None, bridge), plan)
    assert applied is plan
    assert posted_actions(session) == ["user_create", "db_audit", "user_create"]
    assert posted_params(session, "user_create") == [
        {"login": LOGIN, "email": EMAIL, "role": ROLE},
        {"apply": True, "login": LOGIN, "email": EMAIL, "role": ROLE},
    ]
    assert applied.items[0].done
    assert applied.items[0].detail == \
        "create administrator newadmin (new@example.test), created"
    # the credential reaches the CLI presentation layer and NOWHERE else
    assert action.credentials == [
        {"login": LOGIN, "email": EMAIL, "password": CREATE_PASSWORD},
    ]
    summaries = _records(wpt_records, "wpt.actions.user_create", logging.INFO)
    assert len(summaries) == 2  # one plan summary, one apply summary
    assert "created 1 administrator account (newadmin)" in \
        summaries[1].getMessage()
    assert CREATE_PASSWORD not in summaries[1].getMessage()


def test_plan_and_apply_round_trip_a_role_with_a_space(tmp_path):
    # A role key may contain a space (WP_Roles::add_role() accepts arbitrary
    # keys; "shop manager" is the classic). The label parser must remove the
    # KNOWN role prefix, not split at the first space — a first-space split
    # would derive the login "manager newadmin" and fail every apply on a
    # correctly created account.
    role = "shop manager"
    src, session, bridge = make_stack([
        created_read_only(roles=(role,)),
        ok(**audit_payload()),
        created_applied(roles=(role,)),
    ])
    action = UserCreateAction()
    ctx = _ctx(tmp_path, extra={"login": LOGIN, "email": EMAIL, "role": role})
    plan = action.plan(ctx, (src, None, bridge))
    assert plan.items[0].detail == \
        "create shop manager newadmin (new@example.test)"
    applied = action.apply(ctx, (src, None, bridge), plan)
    assert applied.items[0].done
    assert action.credentials == [
        {"login": LOGIN, "email": EMAIL, "password": CREATE_PASSWORD},
    ]


def test_apply_wrong_login_fails_closed(tmp_path):
    # The read-back login is not the planned one: something rewrote the
    # login between plan and apply.  The run fails closed (snapshot is the
    # rollback) — and the credential is STILL published, because that
    # account now exists with that password.
    src, _session, bridge = make_stack([created_applied(login="different")])
    action = UserCreateAction()
    plan = _one_item_plan()
    with pytest.raises(BridgeError, match="different login than the plan"):
        action.apply(_ctx(tmp_path), (src, None, bridge), plan)
    assert not plan.items[0].done
    assert action.credentials == [
        {"login": "different", "email": EMAIL, "password": CREATE_PASSWORD},
    ]


@pytest.mark.parametrize("bad_row", [
    {"login": LOGIN, "email": EMAIL, "roles": [ROLE]},          # no password
    {"login": LOGIN, "email": EMAIL, "roles": [ROLE],
     "password": ""},                                            # blank
    {"login": LOGIN, "email": EMAIL, "roles": [ROLE],
     "password": 42},                                            # non-string
    {"login": "", "email": EMAIL, "roles": [ROLE],
     "password": CREATE_PASSWORD},                               # no login
    "newadmin",                                                  # not a dict
])
def test_apply_malformed_row_refuses(tmp_path, bad_row):
    plan = _one_item_plan()
    bridge = _RawBridge(rows=bad_row)
    action = UserCreateAction()
    with pytest.raises(BridgeError) as excinfo:
        action.apply(_ctx(tmp_path), (FakeSource(), None, bridge), plan)
    assert "unusable credential row" in str(excinfo.value)
    assert CREATE_PASSWORD not in str(excinfo.value)
    assert not plan.items[0].done
    assert action.credentials == []


def test_apply_malformed_roles_never_withholds_the_password(tmp_path):
    # roles are INFORMATIONAL on the apply answer (the client validates
    # them before the action sees a row; this raw bridge models that the
    # action's own hardening must not withhold a password that is already
    # live just because a cosmetic field is unusable).
    plan = _one_item_plan()
    bridge = _RawBridge(rows={"login": LOGIN, "email": EMAIL,
                              "roles": "administrator",
                              "password": CREATE_PASSWORD})
    action = UserCreateAction()
    applied = action.apply(_ctx(tmp_path), (FakeSource(), None, bridge), plan)
    assert applied.items[0].done
    assert action.credentials == [
        {"login": LOGIN, "email": EMAIL, "password": CREATE_PASSWORD},
    ]


def test_apply_refuses_a_plan_it_cannot_attribute(tmp_path):
    # This action plans exactly one account, and the label is the only
    # carrier of the planned login; a hand-built plan that breaks either
    # shape must refuse BEFORE any bridge call — an unverifiable creation
    # must never be reported as done.
    src, session, bridge = make_stack([])
    action = UserCreateAction()
    ctx = _ctx(tmp_path)
    with pytest.raises(SourceError, match="exactly one"):
        action.apply(ctx, (src, None, bridge), Plan(items=[
            PlanItem(category="db.users", target="wp_users",
                     detail="create administrator a (a@x.test)"),
            PlanItem(category="db.users", target="wp_users",
                     detail="create administrator b (b@x.test)"),
        ]))
    with pytest.raises(SourceError, match="unverified"):
        action.apply(ctx, (src, None, bridge), Plan(items=[
            PlanItem(category="db.users", target="wp_users",
                     detail="something else"),
        ]))
    assert session.posts == []


def test_apply_publishes_the_created_credential_on_a_readback_failure(
        tmp_path):
    """C12: the account and password are live even when the read-back fails.
    The bridge attaches the complete row to ok:false; the action must
    publish it before raising, or the operator locks themselves out."""
    row = {"login": LOGIN, "email": EMAIL, "roles": [ROLE],
           "password": CREATE_PASSWORD}

    class _PartialBridge:
        def create_user(self, login, email, role):
            raise BridgeError("user_create created the account but the "
                              "created user could not be read back",
                              payload={"partial_user": row})

    action = UserCreateAction()
    with pytest.raises(BridgeError, match="could not be read back"):
        action.apply(_ctx(tmp_path), (FakeSource(), None, _PartialBridge()),
                     _one_item_plan())
    assert action.credentials == [
        {"login": LOGIN, "email": EMAIL, "password": CREATE_PASSWORD},
    ]


def test_apply_empty_plan_no_bridge_call(tmp_path):
    src, session, bridge = make_stack([])  # any POST would fail the fake
    plan = Plan(items=[], backup_tables=[])
    action = UserCreateAction()
    assert action.apply(_ctx(tmp_path), (src, None, bridge), plan) is plan
    assert session.posts == []
    assert action.credentials == []


def _one_item_plan():
    return Plan(items=[PlanItem(
        category="db.users", target="wp_users",
        detail="create administrator newadmin (new@example.test)")])


# ------------------------------------------------------- registry end-to-end


def test_registry_dry_run(tmp_path, capsys, monkeypatch):
    src, session, bridge = make_stack([
        created_read_only(),
        ok(**audit_payload()),
    ])
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    rc = run_action(_ctx(tmp_path), "user-create")
    assert rc == 0
    out = capsys.readouterr().out
    assert "## Plan" in out
    assert "db.users" in out
    assert "create administrator newadmin (new@example.test)" in out
    assert posted_actions(session) == ["user_create", "db_audit"]
    assert posted_params(session, "user_create") == [
        {"login": LOGIN, "email": EMAIL, "role": ROLE},
    ]


def test_registry_ftp_apply_end_to_end(tmp_path, capsys, monkeypatch):
    src, session, bridge = make_stack([
        created_read_only(),
        ok(**audit_payload()),
        FakeResponse(200, lines=dump_lines("wp_usermeta", "wp_users")),
        created_applied(),
        ok(purged=True),  # the registry's post-apply purge answer
    ])
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "user-create")
    assert rc == 0
    assert posted_actions(session) == ["user_create", "db_audit", "db_dump",
                                       "user_create", "purge_cache"]
    # the fail-closed pre-action snapshot covers EXACTLY the tables the
    # creation writes (wp_users + wp_usermeta via the role capabilities)
    assert posted_params(session, "db_dump") == [
        {"tables": ["wp_usermeta", "wp_users"]},
    ]
    manifests = list((tmp_path / "backup").glob("*/*/manifest.json"))
    assert len(manifests) == 1
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    assert manifest["action"] == "user-create"
    assert [t["name"] for t in manifest["tables"]] == \
        ["wp_usermeta", "wp_users"]
    assert manifest["files"] == []  # DB-only action
    out = capsys.readouterr().out
    assert "| yes |" in out
    assert "created" in out
    credentials = get_action("user-create").action.credentials
    assert credentials == [
        {"login": LOGIN, "email": EMAIL, "password": CREATE_PASSWORD},
    ]


def test_secrets_never_reach_log_or_report(tmp_path, capsys, monkeypatch,
                                           wpt_records):
    # The hard secrets rule, asserted end to end: a full registry apply
    # writes the generated password NOWHERE but the credentials the CLI
    # prints itself.
    src, session, bridge = make_stack([
        created_read_only(),
        ok(**audit_payload()),
        FakeResponse(200, lines=dump_lines("wp_usermeta", "wp_users")),
        created_applied(),
        ok(purged=True),
    ])
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "user-create")
    assert rc == 0
    out = capsys.readouterr().out
    assert "## Plan" in out  # the registry DID print its report
    assert CREATE_PASSWORD not in out
    assert wpt_records
    for record in wpt_records:
        assert CREATE_PASSWORD not in str(record.__dict__)


def test_report_file_carries_the_plan_and_never_a_password(
        tmp_path, monkeypatch):
    src, session, bridge = make_stack([
        created_read_only(),
        ok(**audit_payload()),
        FakeResponse(200, lines=dump_lines("wp_usermeta", "wp_users")),
        created_applied(),
        ok(purged=True),
    ])
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    report = tmp_path / "create.md"
    rc = run_action(_ctx(tmp_path, apply=True, yes=True, report_path=report),
                    "user-create")
    assert rc == 0
    written = report.read_text(encoding="utf-8")
    assert "## Plan" in written
    assert "create administrator newadmin (new@example.test)" in written
    assert CREATE_PASSWORD not in written
    twin = report.with_suffix(".json").read_text(encoding="utf-8")
    assert CREATE_PASSWORD not in twin


def test_registry_malformed_row_is_clean(tmp_path, capsys, monkeypatch,
                                         wpt_records):
    # The real path end to end: the client refuses a passwordless row, and
    # the run ends rc 1 + ONE clean error line, never a traceback — with
    # the action's holder EMPTY, because no usable row ever came back.
    src, session, bridge = make_stack([
        created_read_only(),
        ok(**audit_payload()),
        FakeResponse(200, lines=dump_lines("wp_usermeta", "wp_users")),
        ok(results={"user": {"login": LOGIN, "email": EMAIL,
                             "roles": [ROLE]},
                    "apply": True}),
    ])
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "user-create")
    assert rc == 1
    out = capsys.readouterr().out
    assert "Traceback" not in out
    errors = _records(wpt_records, "wpt.actions", logging.ERROR)
    assert len(errors) == 1
    assert "no password" in errors[0].getMessage()
    assert get_action("user-create").action.credentials == []
    for record in wpt_records:
        assert CREATE_PASSWORD not in str(record.__dict__)


def test_registry_snapshot_failure_refuses_apply(tmp_path, capsys, monkeypatch,
                                                 wpt_records):
    src, session, bridge = make_stack([
        created_read_only(),
        ok(**audit_payload()),
        FakeResponse(200, json.dumps({"ok": False, "error": "db dump failed"})),
    ])
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, bridge))
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "user-create")
    assert rc == 1
    assert posted_actions(session) == ["user_create", "db_audit", "db_dump"]
    assert posted_params(session, "user_create") == [
        {"login": LOGIN, "email": EMAIL, "role": ROLE},
    ]  # never applied
    assert capsys.readouterr().out == ""
    errors = _records(wpt_records, "wpt.actions", logging.ERROR)
    assert errors
    assert "pre-action backup failed" in errors[0].getMessage()
    assert "refusing to apply" in errors[0].getMessage()
    assert get_action("user-create").action.credentials == []


def test_registry_local_mode_refused(tmp_path, wpt_records, monkeypatch):
    built = []

    def fail_stack(ctx):
        built.append(ctx)
        raise AssertionError("_stack must not be built for an inapplicable mode")

    monkeypatch.setattr(registry_mod, "_stack", fail_stack)
    rc = run_action(
        _ctx(tmp_path, source="local", zip=tmp_path / "site.zip",
             apply=True, yes=True),
        "user-create",
    )
    assert rc == 1  # ftp-only: a local zip has no WordPress to create into
    assert built == []
    errors = _records(wpt_records, "wpt.actions", logging.ERROR)
    assert errors
    message = errors[0].getMessage()
    assert "ftp" in message and "local" in message


def test_report_renders_the_label_intact(tmp_path):
    # The label must survive the report's shared redactor (no
    # ``password: <value>`` shape hides the account the item is about).
    from wpt.report import AuditReport

    action = UserCreateAction()
    src, _session, bridge = make_stack([
        created_read_only(), ok(**audit_payload()),
    ])
    plan = action.plan(_ctx(tmp_path), (src, None, bridge))
    rendered = render_report(
        AuditReport(site="example.com", source_summary="action plan (ftp)"),
        plan,
    )
    assert "create administrator newadmin (new@example.test)" in rendered
    assert "password=" not in rendered
    assert CREATE_PASSWORD not in rendered
