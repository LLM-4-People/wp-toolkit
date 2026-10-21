"""users_reset action: reset WordPress user passwords to fresh random
values and hand the new values to the operator.

Two target modes, named by the CLI and validated here (the action is the
OWNER of the rule, so a direct API call cannot mass-reset by accident):

* ``ctx.extra["logins"]`` — reset ONLY these accounts (one CLI ``--login``
  per entry; case-insensitive, canonicalized to the inventory's login).
  This is the default-shaped mode: a specific user, never the whole site.
* ``ctx.extra["all"]`` — reset EVERY user (the original migration
  requirement: "reset all users with random password and provide them").

Neither target present is a REFUSAL, not an implicit all-users run; a
named login absent from the inventory is refused with the known logins
named (the read-only discovery path, since the command no longer has an
untargeted dry run).

It is a DB write reached only through the bridge's named-op whitelist
(``users_reset``) — the toolkit's designed extension point for anything
WordPress can do safely; never arbitrary SQL.  Registered
``applies=("ftp",)`` ONLY: the write is a bridge op against a LIVE site (a
local zip has no WordPress to reset, and a dumped wp_users row is not a
credential), so local mode is refused by the registry with rc 1 before a
stack is ever built.

``plan`` (read-only, no secrets can exist):

1. ``bridge.list_users()`` — the op's read-only mode (``apply`` absent, so
   the bridge defaults it to false): every user in ``wp_users`` as
   ``{login, email, roles}``.  No password is generated and no session is
   touched, so the dry-run inventory is safe to print.  A targeted run
   filters this inventory client-side (the op is asked for everyone), so an
   unknown login is a clean refusal here rather than a surprise on apply.
   Zero users -> an EMPTY plan (the clean-db "nothing to do" precedent: no
   items, ``backup_tables == []`` deliberately, rc 0 in both phases, and no
   ``db_audit`` roundtrip at all) unless a login was named, which is then
   simply unknown.
2. ``bridge.call("db_audit")`` — the users-table identity, asked of
   :func:`wpt.users.user_tables` (the fail-closed owner of the plan item's
   ``target`` and of the "every audited table whose name ends with
   ``users`` or ``usermeta``" pre-action snapshot scope).  A suffix the
   audit cannot locate means the reset would run unbacked, and a CONTESTED
   users identity (a second table ending in ``users`` this wire cannot tell
   apart) means the target is unknown -> :class:`SourceError`, never a
   plan.  ``plan.backup_tables`` is set EXPLICITLY to all matched tables:
   the op mutates EXACTLY those two tables (the password hash in wp_users,
   and wp_usermeta through core's session-token manager), and the snapshot
   discipline has no exceptions.
3. One :class:`PlanItem` per PLANNED user: category ``db.users`` (the
   ``db.`` prefix the registry's fallback derivation reads; the explicit
   pin above is the authoritative scope), ``target`` = the resolved users
   table (display + fallback), ``detail`` = the ``_LABEL``-owned ``"reset
   password for <login> (<roles>)"`` — the label is the login's ONLY
   carrier and ``apply`` parses it back through this module's format.  NO
   password anywhere: a Plan is a printed artifact
   (``render_report`` reconstructs it from items + backup_tables), so a
   secret in it would reach the report and any log echoing it.  An
   inventory row with no login / no role list cannot be LABELLED at all,
   and the label is the account's only carrier into the items ->
   :class:`BridgeError` (rc 1, row index only), never an unlabelled item
   that would plan one account and verify another.

``apply``:

* ONE ``bridge.reset_users(logins=...)`` — targeted mode names the planned
  logins (canonical, from the inventory); all-users mode sends NO logins
  list, so a user created between plan and apply is reset too and the
  coverage check below FAILS the run closed (the operator must know a
  fourth account was touched) while still handing over every credential.
  The op generates each password with WordPress's own
  ``wp_generate_password( 20, true, false )``, sets it with
  ``wp_set_password()`` and destroys that user's session tokens (core's
  ``wp_set_password`` alone does NOT: it writes the hash, clears
  ``user_activation_key``, cleans the cache and fires the action — see the
  op's docstring in bridge.php).
* The returned rows are published on :attr:`UsersResetAction.credentials`
  IMMEDIATELY — before any verification — because the passwords are ALREADY
  live: a run that then fails (rc 1) has still revoked the old credentials,
  and an operator who never saw the new ones could not log in.  The CLI
  presentation layer prints them once to stdout; they are never logged,
  never rendered into a report, and never placed in an exception message.
* Verification is fail-closed and secret-free: a planned login missing from
  the result, an UNPLANNED login reset (only reachable in all-users mode,
  by a user created between plan and apply), or a malformed answer raises
  :class:`BridgeError` naming logins only.  Items stay ``done=False``, the
  registry reports rc 1, and the pre-action snapshot is the revert.
* Every planned item is marked done and enriched ``", password reset"``;
  ONE info apply summary (counts and the session-invalidation count, never
  a password).

**The malformed-payload contract** lives in :mod:`wpt.users` (one owner
for both user actions): the bridge is untrusted input, so every row is
read with ``.get`` + type checks — a missing or non-string field can never
escape as ``KeyError``/``TypeError``, which the registry's
``except (WptError, OSError)`` would not catch (the operator would get a
traceback AND no credentials).  A row is published WHOLE or NOT AT ALL
(:func:`wpt.users.credential_of`): it must carry a non-empty ``login`` AND
a non-empty ``password``; ``email`` is optional and a blank one is a real
WordPress state, never a reason to withhold a password.  A row that fails
that test is never published half-filled — a login printed with an empty
password is a credential the operator would try and fail — and its
presence raises :class:`BridgeError` (rc 1, one clean message) by row
index + login, never by value.

Every OTHER publishable row in the same answer is still published, and the
CLI still prints them on the rc-1 run.  That is the deliberate half of the
rule: the same argument that makes the credentials print on a failed
VERIFICATION (the old passwords are already revoked, the snapshot is the
rollback) applies verbatim to a malformed payload — a password the op
actually set must reach the operator even when a sibling row was
unusable.  Refusing is about the run's verdict (the reset could not be
verified), never about withholding a credential that exists.  The one case
that is NOT published is a row with a password but no login: it cannot be
attributed to an account, and inventing an identity for it would be a lie
the operator acts on.  That account is covered by the pre-action snapshot
and named in the error message, so it is knowable, not silent.

Logging: ``get_logger("actions.users_reset")`` — one info per phase, counts
and logins only.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..audit.data import _tables_from_wire
from ..log import get_logger
from ..report import Plan, human_bytes
from ..types import BridgeError, PlanItem, SourceError
from ..users import credential_of, row_label, text, user_tables
from .registry import register_action

if TYPE_CHECKING:
    from ..cli import Ctx

__all__ = ["UsersResetAction"]

log = get_logger("actions.users_reset")

#: Plan-item detail format — the ONE owner of the label shape; ``apply``
#: parses the login back out after this fixed prefix. The word "password" is
#: followed by a SPACE, never a ":" or "=": the report's shared redactor
#: treats a ``password: <value>`` shape as a secret assignment and would
#: blank the login out of the printed plan. The login is followed by the
#: parenthesised role list, which is what ``_login_of`` parses back off.
_LABEL = "reset password for "


def _label(login: str, roles: list[str]) -> str:
    """The human label for one planned reset: login + its roles."""
    return f"{_LABEL}{login} ({', '.join(roles) if roles else 'no roles'})"


def _login_of(item: PlanItem) -> str:
    """The login carried by one item (the structural ``ref``), or the label.

    ``ref`` is set by the plan, so a role containing ``" ("`` (a legal
    WordPress role name: ``editor (legacy)``) can never change the parsed
    login.  The label fallback keeps hand-built PlanItems (tests, a plan
    from an older version) working; it is the inverse of :func:`_label`.
    """
    if item.ref:
        return item.ref
    body = item.detail[len(_LABEL):]
    login, sep, _roles = body.rpartition(" (")
    if sep and body.endswith(")"):
        return login
    return body  # no role group at all — the whole suffix is the login


def _target(ctx: "Ctx") -> tuple[list[str] | None, bool]:
    """(the requested logins, the all-users flag) from ``ctx.extra``.

    The target rule, ONE place: exactly one mode must be named, and a
    nameless run is a refusal — the deliberate reversal of the old implicit
    all-users default (a specific account is the default SHAPE; everyone
    requires saying ``--all``).  A login entry must be a non-empty string;
    the caller's value is kept as typed and matched case-insensitively
    against the inventory.
    """
    extra = ctx.extra or {}
    raw = extra.get("logins")
    if raw is not None and not isinstance(raw, list):
        raise SourceError("users_reset: --login must be a list of logins")
    logins = list(raw or [])
    for login in logins:
        if not isinstance(login, str) or not login.strip():
            raise SourceError(
                "users_reset: --login entries must be non-empty strings")
    all_users = extra.get("all") is True
    if logins and all_users:
        raise SourceError(
            "users_reset: --login and --all are mutually exclusive; name "
            "the accounts OR pass --all, never both")
    if not logins and not all_users:
        raise SourceError(
            "users_reset needs a target: pass --login LOGIN (repeatable) "
            "to reset named accounts, or --all to reset every user")
    return (logins if logins else None), all_users


def _select_users(
    labelled: list[tuple[str, list[str]]], requested: list[str]
) -> list[tuple[str, list[str]]]:
    """The inventory rows a targeted run may reset, inventory order.

    Matching is case-insensitive (WordPress logins are, by collation) and
    canonicalizes to the inventory's own spelling, so the apply's coverage
    check compares like with like.  A requested login the inventory does
    not carry refuses the plan and names the known logins — the read-only
    discovery path for an operator who does not know the exact spelling.
    """
    known: dict[str, str] = {}
    for login, _roles in labelled:
        known.setdefault(login.lower(), login)
    wanted: set[str] = set()
    unknown: list[str] = []
    for raw in requested:
        low = raw.lower()
        if low in wanted or low in (u.lower() for u in unknown):
            continue
        if low in known:
            wanted.add(low)
        else:
            unknown.append(raw)
    if unknown:
        roster = ", ".join(login for login, _roles in labelled)
        raise SourceError(
            "users_reset: no such user: " + ", ".join(unknown)
            + (f" (known logins: {roster})" if roster
               else " (the site has no users)"))
    return [(login, roles) for login, roles in labelled
            if login.lower() in wanted]


class UsersResetAction:
    """The plan/apply pair; ``stack`` is the registry-built source trio."""

    def __init__(self) -> None:
        #: The plaintext credentials of the LAST reset this instance
        #: performed, for the CLI presentation layer ONLY (it prints them
        #: once to stdout). Empty after a dry run and until an apply
        #: returns: nothing else in the toolkit may read, log, report or
        #: raise this value. ``plan()`` clears it, so a second run on the
        #: same registered instance never shows a previous run's secrets.
        #: Every record is COMPLETE (login, email — blank-allowed — and
        #: password): the action publishes a row whole or not at all.
        self.credentials: list[dict[str, str]] = []

    def plan(self, ctx: "Ctx", stack: tuple) -> Plan:
        bridge = stack[2]
        if bridge is None:
            # Unreachable through the registry (ftp-only applicability);
            # guarded so a direct misuse fails inside the error contract.
            raise SourceError("users_reset requires the bridge (ftp mode only)")
        # A dry run must never leave a previous run's secrets visible.
        self.credentials = []
        requested, all_users = _target(ctx)

        users = bridge.list_users()
        # Fail-closed on the inventory itself, for the same reason the apply
        # is: a row without a login cannot be LABELLED, and the label is the
        # only carrier of the account into the plan's items — an unlabelled
        # entry would plan one thing and verify another.
        labelled: list[tuple[str, list[str]]] = []
        for index, row in enumerate(users):
            login = text(row, "login")
            roles = row.get("roles") if isinstance(row, dict) else None
            if login is None or not isinstance(roles, list) or any(
                not isinstance(role, str) for role in roles
            ):
                raise BridgeError(
                    "users_reset listed a user this run cannot plan: "
                    + row_label(row, index)
                    + " (an inventory row must carry a login and a list of "
                      "roles)",
                    payload={"unusable_rows": [row_label(row, index)]},
                )
            labelled.append((login, list(roles)))

        if requested is not None:
            labelled = _select_users(labelled, requested)
        if not labelled:
            log.info("plan: the site has no users to reset (nothing to do)")
            return Plan(items=[], backup_tables=[])

        # The tables this op mutates: the TARGET is the one table the
        # identity owner resolves, the snapshot scope stays the
        # over-inclusive suffix match; fail-closed on both.
        tables = _tables_from_wire(bridge.call("db_audit").get("tables"))
        users_table, backup = user_tables(
            tables, what="the password reset")

        items = [
            PlanItem(
                category="db.users",
                target=users_table,
                detail=_label(login, roles),
                ref=login,
            )
            for login, roles in labelled
        ]
        plan = Plan(items=items, backup_tables=backup)
        mode = "all users" if all_users else "targeted"
        log.info(
            "plan: %d user(s) to reset (%s), %s estimated (passwords are "
            "generated only on --apply and never appear in a plan)",
            len(items), mode, human_bytes(plan.est_bytes()),
        )
        return plan

    def _reset_rows(self, bridge, logins):
        """The bridge's rows, publishing partial credentials on a failure.

        C12: a per-user Throwable used to reach the global envelope with no
        rows, losing every password already set.  The bridge now returns
        the complete rows beside ``ok:false``; the client validates them and
        attaches ``partial_users`` to the error, and this seam publishes
        them BEFORE the failure unwinds.
        """
        try:
            return bridge.reset_users(logins)
        except BridgeError as exc:
            partial = (exc.payload or {}).get("partial_users")
            if isinstance(partial, list):
                self.credentials = [
                    credential for row in partial
                    if (credential := credential_of(row)) is not None
                ]
            raise

    def apply(self, ctx: "Ctx", stack: tuple, plan: Plan) -> Plan:
        bridge = stack[2]
        if bridge is None:
            raise SourceError("users_reset requires the bridge (ftp mode only)")
        planned = [
            _login_of(item) for item in plan.items if item.requires_apply
        ]
        if not planned:
            return plan  # nothing planned — no bridge roundtrip
        _requested, all_users = _target(ctx)

        rows = self._reset_rows(bridge, None if all_users else planned)
        # The passwords are ALREADY SET: publish every COMPLETE row to the
        # CLI before any check, so a run that ends rc 1 still handed the
        # operator the only credentials their users now have — including a
        # run that ends rc 1 because a SIBLING row was unusable (module
        # docstring, "the malformed-payload contract") or because the bridge
        # contained a per-user failure and returned its partial rows (C12).
        published: list[dict[str, str]] = []
        by_login: dict[str, dict] = {}
        unusable: list[str] = []
        for index, row in enumerate(rows):
            credential = credential_of(row)
            if credential is None:
                unusable.append(row_label(row, index))
                continue
            published.append(credential)
            by_login[credential["login"]] = row
        self.credentials = published

        if unusable:
            # Refuse BEFORE touching any item, and never half-publish: the
            # rows above are complete, this one is not attributable.
            raise BridgeError(
                "users_reset returned an unusable credential row: "
                + ", ".join(unusable)
                + " (no password to hand over for that account; the run "
                  "aborted — the pre-action snapshot still holds its old "
                  "credentials)",
                payload={"unusable_rows": unusable},
            )

        # Fail-closed verification, secret-free: names only, never a value.
        reset_logins = set(by_login)
        missing = [login for login in planned if login not in reset_logins]
        if missing:
            raise BridgeError(
                "users_reset did not report a password for "
                + ", ".join(missing),
                payload={"reset": sorted(reset_logins)},
            )
        unplanned = sorted(reset_logins - set(planned))
        if unplanned:
            raise BridgeError(
                "users_reset reset user(s) that were not in the plan: "
                + ", ".join(unplanned),
                payload={"reset": sorted(reset_logins)},
            )

        destroyed = sum(
            1 for login in planned if by_login[login].get("sessions_destroyed")
        )
        for item in plan.items:
            if not item.requires_apply:
                continue
            item.done = True
            item.detail = item.detail + ", password reset"
        log.info(
            "apply: %d user(s) reset; session tokens destroyed for %d "
            "(the new passwords are on stdout only — record them now)",
            len(planned), destroyed,
        )
        return plan


# The registry stores the decorated OBJECT and calls .plan/.apply on it
# (the deactivate/clean_files precedent: a bare class would be invoked with
# plan(ctx, stack) unbound and crash in run_action).
register_action("users_reset", applies=("ftp",))(UsersResetAction())
