"""WordPress user-account facts shared by the two user actions.

ONE owner for the things ``users_reset`` and ``user-create`` must agree on:

* **the table pair a db_audit wire names** — :func:`user_tables` returns the
  ONE users table the plan item names (asked of
  :func:`wpt.media_refs.resolve_role_by_name`, the project's table-identity
  owner, so a schema contesting the ``*users`` suffix is refused by BOTH
  actions identically) plus the fail-safe snapshot scope (every audited
  table whose name ends in ``users`` or ``usermeta`` — a stray
  ``wp_myusers`` merely WIDENS the scope, never a miss).  Fail-closed on
  both, because a mutation whose rollback hole is invisible must not be
  planned at all.
* **the credential-row contract** — the bridge is untrusted input, so every
  answer row is read with :func:`text` (``.get`` + a non-empty-string type
  check: a missing key can never escape as ``KeyError``, which the action
  registry's ``except (WptError, OSError)`` does not catch) and published
  WHOLE or NOT AT ALL by :func:`credential_of` (non-empty ``login`` AND
  non-empty ``password``; ``email`` optional and blank-allowed, because a
  WordPress user may genuinely have no address).

Secrets discipline: nothing here logs, and the password in a returned
record is handed to the CLI presentation layer only — never a plan, a
report, an exception message or a log line.
"""

from __future__ import annotations

from .media_refs import resolve_role_by_name
from .types import SourceError

__all__ = [
    "USER_TABLE_SUFFIXES",
    "credential_of",
    "role_list",
    "row_label",
    "text",
    "user_tables",
]

#: db_audit table-name suffixes the user-writing ops mutate: the wp_users
#: row and wp_usermeta (core's session manager and the role capabilities).
#: Structural (never a tunable), derived like clean-db's per-op table map.
#: The FIRST is also the role the ONE table-identity owner resolves for a
#: plan item's target; the pair is the SNAPSHOT scope, which stays the
#: fail-safe over-inclusive match.
USER_TABLE_SUFFIXES = ("users", "usermeta")


def user_tables(tables: dict, *, what: str) -> tuple[str, list[str]]:
    """(the users table a plan item names, the fail-closed snapshot scope).

    ``tables`` is :func:`wpt.audit.data._tables_from_wire`'s answer;
    ``what`` names the mutation in the refusal text ("the password reset",
    "the user creation").  Both failure shapes raise
    :class:`~wpt.types.SourceError`, never a guess:

    * a suffix no audited table matches means the mutation would run
      unbacked (the snapshot restores whole tables);
    * more than one table ending in ``users`` is a CONTESTED identity —
      db_audit carries no column list to tell them apart, so the plan
      cannot name the table the op writes through ``$wpdb->users``, and
      naming the wrong one would put a table nobody touches into the plan
      and every ``--report`` artifact.
    """
    found: set[str] = set()
    missing: list[str] = []
    for suffix in USER_TABLE_SUFFIXES:
        matches = sorted(name for name in tables if name.endswith(suffix))
        found.update(matches)
        if not matches:
            missing.append(suffix)
    if missing:
        raise SourceError(
            "db_audit lists no table to back up " + what + " (needs a table "
            "ending with "
            + ", ".join(repr(s) for s in missing)
            + "); refusing an unbacked mutation"
        )
    role = USER_TABLE_SUFFIXES[0]
    # The loop above proves at least one name ends with ``users``, so the
    # owner always has a candidate here; only the count is in question.
    resolved = resolve_role_by_name(role, tables)
    if resolved.ambiguous:
        raise SourceError(
            "db_audit lists several tables that could be this site's "
            f"{role} table ({', '.join(resolved.candidates)}) and the wire "
            "carries no column list to tell them apart, so " + what +
            "'s target is unknown: refusing rather than naming the wrong "
            "table"
        )
    return resolved.name, sorted(found)


def text(row: object, key: str) -> str | None:
    """A NON-EMPTY string field of one answer row, else ``None``.

    The one reader for bridge answer rows: nothing in the user actions
    indexes a row directly, because a missing key raises ``KeyError`` and
    the registry's ``except (WptError, OSError)`` does not catch it — the
    operator would get a traceback and a lost rc.  A non-dict row (the
    envelope's list-ness is the client's contract; its CONTENT is the
    action's) is simply unanswerable here.
    """
    if not isinstance(row, dict):
        return None
    value = row.get(key)
    return value if isinstance(value, str) and value else None


def row_label(row: object, index: int) -> str:
    """A secret-free identifier for one unusable answer row: its index, plus
    its login when the row has one.  Never a value, never a password."""
    login = text(row, "login")
    return f"row {index} (login={login!r})" if login else f"row {index}"


def credential_of(row: object) -> dict[str, str] | None:
    """One answer row as a credential record, or ``None`` if unusable.

    Publishable means a non-empty ``login`` AND a non-empty ``password`` —
    the two fields the operator needs to actually log in.  ``email`` is
    optional and blank-allowed (a WordPress user may genuinely have no
    address); it is never a reason to withhold a live password.  All-or-
    nothing: the returned record always has all three keys filled, so the
    CLI can never print an account name next to an empty password.
    """
    login = text(row, "login")
    password = text(row, "password")
    if login is None or password is None:
        return None
    email = row.get("email", "") if isinstance(row, dict) else ""
    return {
        "login": login,
        "email": email if isinstance(email, str) else "",
        "password": password,
    }


def role_list(row: object) -> list[str] | None:
    """One answer row's role names as a plain list, or ``None`` when the
    field is absent/malformed.  The bridge's read-back normalizes WP_User's
    two property shapes (name list / name => true map) into names; this
    keeps the client-side type check in the same module as the rest of the
    row contract.
    """
    roles = row.get("roles") if isinstance(row, dict) else None
    if not isinstance(roles, list) or any(
            not isinstance(role, str) for role in roles):
        return None
    return list(roles)
