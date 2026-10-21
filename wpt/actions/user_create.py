"""user-create action: create ONE WordPress user through the bridge's
named-op whitelist, handing the generated password to the operator once.

The request names ``login``, ``email`` and ``role`` (the CLI defaults the
role to ``administrator``).  Creation is a bridge op
(``user_create``) — the toolkit's designed extension surface for anything
WordPress can do safely, never arbitrary SQL — and it runs WordPress's own
``wp_insert_user()`` with a password from ``wp_generate_password( 20, true,
false )``, then READS THE ACCOUNT BACK (``get_userdata()``) and returns the
read-back, so the op cannot report a creation WordPress did not persist.
No notification email is sent: the credential reaches the operator on
stdout, one time, and nowhere else.

``plan`` (read-only):

1. ``bridge.check_create_user()`` — the op's read-only mode (``apply``
   absent): it validates the request against the LIVE site (login
   non-empty after ``sanitize_user()``, not already taken; email valid and
   unused; role an existing role) and answers the account it WOULD create,
   with the SANITIZED login.  No password is generated and no row is
   written, so the dry run is safe to print; any refusal (duplicate login
   or email, invalid email, unknown role) is a clean rc-1 here instead of
   a surprise on apply.
2. ``bridge.call("db_audit")`` — the users-table identity through
   :func:`wpt.users.user_tables` (the fail-closed owner of the plan item's
   ``target`` and of the pre-action snapshot scope); a contested or absent
   ``*users``/``*usermeta`` pair refuses the plan, never an unbacked
   mutation.
3. One :class:`PlanItem` (category ``db.users``), detail
   ``"create <role> <login> (<email>)"``.  NO password anywhere: a Plan is
   a printed artifact (``render_report`` reconstructs it from items +
   backup_tables), so a secret in it would reach the report and any log
   echoing it.

``apply``:

* ONE ``bridge.create_user()`` with ``apply`` true.  The op re-runs every
  validation (a login created between plan and apply refuses there), then
  inserts and reads back.
* The returned credential is published on
  :attr:`UserCreateAction.credentials` immediately, under the same
  whole-or-nothing contract as ``users_reset`` (:func:`wpt.users.
  credential_of`): the password is ALREADY live, so a run that ends rc 1
  still hands it over.  The CLI prints it once on stdout; it is never
  logged, never reported, never placed in an exception message.
* Verification, fail-closed and secret-free: the created login must be the
  planned one (the plan carries the sanitized login; the op sanitizes the
  same way, so a contract break or an intervening filter is a clean
  :class:`BridgeError` by name, with the snapshot as the rollback).  The
  item is marked done and enriched ``", created"``; ONE info apply summary
  (login and role only, never a password).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..audit.data import _tables_from_wire
from ..log import get_logger
from ..report import Plan, human_bytes
from ..types import BridgeError, PlanItem, SourceError
from ..users import credential_of, row_label, role_list, text, user_tables
from .registry import register_action

if TYPE_CHECKING:
    from ..cli import Ctx

__all__ = ["UserCreateAction"]

log = get_logger("actions.user_create")

#: Plan-item detail format — the ONE owner of the label shape; ``apply``
#: parses the login back out after the ``create <role> `` prefix. No
#: ``password``-shaped token appears (the report's shared redactor treats
#: ``password: <value>`` as a secret assignment).
_LABEL = "create "


def _label(role: str, login: str, email: str) -> str:
    """The human label for one planned creation."""
    return f"{_LABEL}{role} {login} ({email})"


def _request(ctx: "Ctx") -> tuple[str, str, str]:
    """(login, email, role) from ``ctx.extra``, validated.

    The CLI marks ``--login``/``--email`` required and defaults ``--role``;
    this guard keeps a direct action misuse inside the error contract.
    """
    extra = ctx.extra or {}
    login = extra.get("login")
    email = extra.get("email")
    role = extra.get("role")
    if not isinstance(login, str) or not login.strip():
        raise SourceError("user-create needs --login LOGIN (non-empty)")
    if not isinstance(email, str) or not email.strip():
        raise SourceError("user-create needs --email EMAIL (non-empty)")
    if not isinstance(role, str) or not role.strip():
        raise SourceError("user-create needs --role ROLE (non-empty)")
    return login, email, role


def _login_of(item: PlanItem, role: str) -> str | None:
    """The login carried by one item's label, or ``None`` when the label is
    not in this module's format for ``role``.

    Parsed from the END (the trailing ``(<email>)`` group), then the KNOWN
    role prefix is removed — never a first-space split: a role key may
    itself contain a space (WP_Roles::add_role() accepts arbitrary keys;
    "shop manager" is the classic), so splitting on the first space would
    parse "shop manager bob" as the login "manager bob" and every apply
    would then fail its own attribution check on a correctly created
    account.
    """
    body = item.detail[len(_LABEL):]
    left, sep, _email = body.rpartition(" (")
    if not sep or not body.endswith(")"):
        return None
    prefix = role + " "
    if not left.startswith(prefix):
        return None
    return left[len(prefix):]


class UserCreateAction:
    """The plan/apply pair; ``stack`` is the registry-built source trio."""

    def __init__(self) -> None:
        #: The plaintext credential of the LAST creation this instance
        #: performed, for the CLI presentation layer ONLY. Empty after a
        #: dry run; ``plan()`` clears it so a second run never shows a
        #: previous run's secret. Each record is COMPLETE (login, email —
        #: blank-allowed — and password).
        self.credentials: list[dict[str, str]] = []

    def plan(self, ctx: "Ctx", stack: tuple) -> Plan:
        bridge = stack[2]
        if bridge is None:
            # Unreachable through the registry (ftp-only applicability);
            # guarded so a direct misuse fails inside the error contract.
            raise SourceError("user-create requires the bridge (ftp mode only)")
        self.credentials = []
        login, email, role = _request(ctx)
        row = bridge.check_create_user(login, email, role)
        planned_login = text(row, "login") or login

        tables = _tables_from_wire(bridge.call("db_audit").get("tables"))
        users_table, backup = user_tables(
            tables, what="the user creation")

        item = PlanItem(
            category="db.users",
            target=users_table,
            detail=_label(role, planned_login, email),
        )
        plan = Plan(items=[item], backup_tables=backup)
        log.info(
            "plan: create 1 %s account (%s), %s estimated (the password is "
            "generated only on --apply and never appears in a plan)",
            role, planned_login, human_bytes(plan.est_bytes()),
        )
        return plan

    def apply(self, ctx: "Ctx", stack: tuple, plan: Plan) -> Plan:
        bridge = stack[2]
        if bridge is None:
            raise SourceError("user-create requires the bridge (ftp mode only)")
        pending = [item for item in plan.items if item.requires_apply]
        if not pending:
            return plan  # nothing planned — no bridge roundtrip
        if len(pending) != 1:
            # This action plans exactly one account; a plan carrying more
            # has been tampered with or built by hand, and creating against
            # it would attribute the credential to an unknown item.
            raise SourceError(
                "user-create expects exactly one planned item; the plan "
                f"carries {len(pending)}")
        login, email, role = _request(ctx)
        planned = _login_of(pending[0], role)
        if planned is None:
            raise SourceError(
                "user-create could not read the planned login out of the "
                "plan item; refusing to report an unverified creation")

        try:
            row = bridge.create_user(login, email, role)
        except BridgeError as exc:
            # C12: the account/password may already be live even though the
            # read-back (or a later step) failed.  Publish the complete row
            # the bridge returned beside ok:false, then fail closed.
            partial = (exc.payload or {}).get("partial_user")
            if isinstance(partial, dict):
                credential = credential_of(partial)
                if credential is not None:
                    self.credentials = [credential]
            raise
        credential = credential_of(row)
        if credential is None:
            raise BridgeError(
                "user-create returned an unusable credential row: "
                + row_label(row, 0)
                + " (no password to hand over for that account; the run "
                  "aborted — the pre-action snapshot still holds its old "
                  "state)",
                payload={"unusable_rows": [row_label(row, 0)]},
            )
        # The password is ALREADY SET: publish before any check, under the
        # users_reset rule (the credential is live; withholding it on a
        # later refusal would lock the operator out of the account).
        self.credentials = [credential]

        if credential["login"].lower() != planned.lower():
            raise BridgeError(
                "user-create created a different login than the plan: "
                f"planned {planned!r}, created {credential['login']!r} "
                "(rc 1; the pre-action snapshot is the rollback)")

        roles = role_list(row)
        created_role = roles[0] if roles else role
        pending[0].done = True
        pending[0].detail = pending[0].detail + ", created"
        log.info(
            "apply: created 1 %s account (%s); the new password is on "
            "stdout only — record it now",
            created_role, credential["login"],
        )
        return plan


# The registry stores the decorated OBJECT and calls .plan/.apply on it
# (the users_reset precedent: a bare class would be invoked with
# plan(ctx, stack) unbound and crash in run_action).
register_action("user-create", applies=("ftp",))(UserCreateAction())
