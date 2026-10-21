"""wpt command-line interface — the single setup choke point.

Command implementations are imported lazily so the skeleton works before every
module lands (W2+); only `proxy` is fully implemented here once dnsoverride exists.
"""

import argparse
import math
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import __version__
from .config import redact_text, resolve_password
from .deadline import Deadline
from .jsonutil import loads_bounded
from .localmode.dbconn import parse_db_uri, resolve_db_password
from .log import get_logger, setup_logging
from .ports import DEFAULT_PROXY_PORT, DEFAULT_SERVE_PORT
from .settings import (LOG_LEVELS, Settings, SettingsError,
                       load as load_settings)
from .types import RunControl, StopRequested, WptError

log = get_logger("cli")

MUTATING_COMMANDS = ("clean-files", "clean-db", "trim-media", "optimize-media",
                     "harden", "deactivate-plugin", "heal-core", "update-core",
                     "users_reset", "user-create", "reconcile-plugins",
                     "prune-core", "deploy",
                     "park-backups", "cull-media", "webp-media")

#: Commands that read the WEBROOT ZIP ONLY: nothing in their plan, apply or
#: rehearsal opens the SQL dump, so local mode requires --zip and no more.
#: (clean-files reads the dump for exactly one fact — the active plugin set —
#: and only when a plugin-unit deletion is actually a candidate; without
#: --sql its own owner, `_active_units`, refuses that plan closed.)
FILE_ONLY_LOCAL_COMMANDS = ("clean-files", "optimize-media", "harden", "deploy",
                            "park-backups", "scan", "files",
                            "heal-core", "update-core", "prune-core")

#: Actions whose apply hands the operator LIVE credentials on stdout (the
#: generated passwords exist nowhere else — never a log, report or
#: exception). The holder is a module-level singleton, so the CLI empties
#: it before the run and prints it once after. ONE owner for the list.
CREDENTIAL_COMMANDS = ("users_reset", "user-create")

#: The commands that read a direct database when ``--db-uri`` is given.
#: clean-db runs its named ops against that database instead of the bridge
#: (or, offline, instead of a dump); doctor adds a connectivity row. Every
#: other command refuses the flag rather than ignoring it.
_DB_URI_COMMANDS = ("clean-db", "doctor")

#: (name, help) of every subcommand — the ONE owner of the command list:
#: the parser is built from it and the usage errors quote from it.
COMMANDS = (
    ("audit", "Full audit (read-only)"),
    ("clean-files", "Delete junk/backup/stale files from the webroot"),
    ("clean-db", "Named DB cleanups via the bridge (revisions, transients, ...)"),
    ("trim-media", "Delete media not referenced by live content"),
    ("optimize-media", "Recompress images in place (local backups kept)"),
    ("harden", "Apply .htaccess/wp-config hardening (diff-printed)"),
    ("verify", "Re-check every live reference after changes"),
    ("updates", "Report available core/plugin/theme updates"),
    ("backup", "Full-site snapshot (files + db; ftp only)"),
    ("restore", "List snapshots (any mode); applying a restore is ftp only"),
    ("deactivate-plugin", "Deactivate a plugin by slug (reversible; ftp only)"),
    ("heal-core", "Restore checksum-proven tampered/missing core files from "
                  "the official WP release"),
    ("update-core", "Update WordPress core to an EXPLICIT target version "
                    "(--to X.Y.Z; snapshot first, maintenance mode, verified)"),
    ("walk", "Crawl the live site: pages, media references, forms"),
    ("users_reset", "Reset a user's password to a random value (--login "
                    "LOGIN, repeatable; --all for every user); the new "
                    "credentials print on stdout (never logged; ftp only)"),
    ("user-create", "Create a new WordPress user — an administrator unless "
                    "--role says otherwise; the generated password prints on "
                    "stdout (never logged; ftp only)"),
    ("reconcile-plugins", "Rewrite active_plugins against the installed "
                          "plugin set (ftp only)"),
    ("serve", "Serve a webroot zip on localhost (offline verify target; local only)"),
    ("doctor", "Preflight self-check: can I work on this site right now?"),
    ("scan", "Source-only dangerous-PHP-pattern scan (no WordPress/DB)"),
    ("logs", "Read bounded host/webroot error logs (ftp only; no --wp-url)"),
    ("discover", "Find WordPress webroot candidates from the FTP account root "
                 "(ftp only; no --webroot/--wp-url required)"),
    ("files", "Backup/edit/rollback selected webroot files (ftp; local "
              "backup from zip)"),
    ("proxy", "Run a local TLS proxy for browsers (DNS override)"),
    ("prune-core", "Delete stale WordPress core files the current release no "
                   "longer ships (two-proof rule, snapshot first)"),
    ("deploy", "Stream a prepared webroot zip into a host over SSH (additive, "
               "quota preflight + layout assertion + manifest verify)"),
    ("park-backups", "Move full-site backup payloads OUT of the webroot (never "
                     "deletes them; advice-only without a provable reference set)"),
    ("cull-media", "Delete oversized image derivatives of dead stem families"),
    ("webp-media", "Convert uploads rasters to WebP and rewrite every reference "
                   "(originals kept unless --purge-originals)"),
)


#: The default local snapshot directory — ONE owner for the Ctx default and
#: the argparse default.
DEFAULT_BACKUP_DIR = Path(".wpt-backup")


@dataclass
class Ctx:
    """Everything an action implementation needs; constructed once per run."""

    source: str
    settings: Settings
    command: str = ""
    apply: bool = False
    yes: bool = False
    backup_dir: Path = DEFAULT_BACKUP_DIR
    # remote mode
    user: str | None = None
    password: str | None = None
    webroot: str | None = None
    wp_url: str | None = None
    override_ip: str | None = None
    # local mode
    zip: Path | None = None
    sql: Path | None = None
    # the direct database source (local mode only; see _DB_URI_COMMANDS).
    # db_password is resolved here, at the credential choke point, exactly
    # like the FTP password — it is never logged and never printed.
    db_uri: str | None = None
    db_password: str | None = None
    db_password_env: str | None = None
    re_dump: Path | None = None
    # outputs
    report_path: Path | None = None
    # the run's self-bounding wall-time budget (seconds; None/0 =
    # unbounded) — resolved from --deadline over settings run.deadline_s
    deadline_s: float | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def mode(self) -> str:
        return "local" if self.source == "local" else "ftp"

    def logger(self, name: str):
        return get_logger(name)


def _parse_set(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise argparse.ArgumentTypeError(f"--set expects key=value, got {value!r}")
    key, _, val = value.partition("=")
    if not key or not val:
        raise argparse.ArgumentTypeError(f"--set expects key=value, got {value!r}")
    return key, val


def _typed_override(key: str, raw: str) -> tuple[str, Any]:
    """Infer the literal's type from the text the operator typed.

    bool/int/float are inferred, then a JSON ARRAY or OBJECT literal is
    decoded: ``--set`` is the only way to change a list- or map-shaped
    setting from the command line, and without this every such key was
    unreachable (the raw string reached the settings owner, which rejects
    a string where a list belongs — so ``media_optimize.exclude_prefixes``,
    ``media.extensions``, ``webroot_junk``, ``known_heavy``, ... could only
    be set through a profile file). A value that merely LOOKS like JSON but
    does not parse is kept as a string, so the settings owner still reports
    the shape error in its own words instead of the CLI inventing one.
    """
    lowered = raw.lower()
    if lowered in ("true", "false"):
        return key, lowered == "true"
    try:
        return key, int(raw)
    except ValueError:
        pass
    try:
        return key, float(raw)
    except ValueError:
        pass
    if raw[:1] in ("[", "{"):
        try:
            decoded = loads_bounded(raw)
        except (ValueError, RecursionError, MemoryError) as exc:
            # A 100k-deep literal exhausts the C decoder's recursion limit
            # (RecursionError is not a ValueError) and used to escape main()
            # as a traceback with no report pair.  It is an operator input
            # refusal, answered through the settings contract.
            if isinstance(exc, ValueError):
                return key, raw
            raise SettingsError(
                f"--set {key}: the JSON literal is too deeply nested or too "
                "large to decode") from exc
        if isinstance(decoded, (list, dict)):
            return key, decoded
    return key, raw


def build_parser() -> argparse.ArgumentParser:
    from .dnsoverride import DEFAULT_CERT_DIR

    p = argparse.ArgumentParser(
        prog="wpt",
        description="Audit, clean, optimize and verify WordPress sites (FTP or zip+sql).",
    )
    p.add_argument("--version", action="version", version=f"wpt {__version__}")
    p.add_argument("--source", default=None,
                   help="ftp://host[:port] or 'local' (proxy defaults to "
                        "local; every other command requires it)")
    p.add_argument("--user", help="FTP user")
    p.add_argument("--password-env", dest="password_env",
                   help="Environment variable holding the password")
    p.add_argument("--webroot", help="FTP path to the WP webroot (relative to FTP login dir)")
    p.add_argument("--wp-url", help="Site URL, e.g. https://example.com")
    p.add_argument("--override-ip", help="DNS override: talk to this IP for --wp-url")
    p.add_argument("--zip", type=Path, help="local mode: webroot zip")
    p.add_argument("--sql", type=Path, help="local mode: MySQL dump")
    p.add_argument("--db-uri", dest="db_uri", metavar="URI",
                   help="local mode: read (and for clean-db --apply, write) the "
                        "database directly, "
                        "mysql://[user[:password]@]host[:port]/database "
                        "(clean-db, doctor)")
    p.add_argument("--db-password-env", dest="db_password_env", metavar="VAR",
                   help="Environment variable holding the --db-uri password "
                        "(preferred over an inline one)")
    p.add_argument("--re-dump", dest="re_dump", type=Path, metavar="PATH",
                   help="clean-db --apply over --db-uri: also write a fresh "
                        "mysqldump-style dump of the database to PATH")
    p.add_argument("--profile", type=Path, help="Settings profile JSON overlay")
    p.add_argument("--set", action="append", default=[], type=_parse_set,
                   metavar="key=value", help="Settings override (repeatable)")
    p.add_argument("--backup-dir", type=Path, default=DEFAULT_BACKUP_DIR)
    p.add_argument("--report", type=Path, help="Write markdown report here")
    p.add_argument("--log-level",
                   help="|".join(sorted(LOG_LEVELS))
                        + " (default: profile log.level; WPT_LOG_LEVEL is "
                          "the fallback when the flag is absent)")
    p.add_argument("--quiet", action="store_true",
                   help="Silence the console log; --log-file still records "
                        "everything")
    p.add_argument("--log-file", help="Also log to this file (the console keeps receiving everything; use --quiet to silence it)")
    p.add_argument("--log-json", action="store_true", help="JSON log format")
    p.add_argument("--deadline", type=float, default=None, metavar="SECONDS",
                   help="Self-bound the whole run to SECONDS of wall time "
                        "(overrides run.deadline_s; 0 disables the bound)")
    p.add_argument("--apply", action="store_true",
                   help="Execute the plan (mutating commands are dry-run without this)")
    p.add_argument("--yes", action="store_true", help="Non-interactive confirmation")

    sub = p.add_subparsers(dest="command", required=True)
    for name, help_ in COMMANDS:
        sub.add_parser(name, help=help_)

    audit_p = sub.choices["audit"]
    audit_p.add_argument("--only", action="append", default=None, metavar="CHECK",
                         help="Run only these checks (name or dotted prefix; repeatable)")
    audit_p.add_argument("--skip", action="append", default=None, metavar="CHECK",
                         help="Skip these checks (name or dotted prefix; repeatable)")
    audit_p.add_argument("--baseline", type=Path, default=None, metavar="PREV.json",
                          help="Diff findings against a previous audit's JSON report")

    deploy_p = sub.choices["deploy"]
    deploy_p.add_argument("--ssh-target", required=True, metavar="USER@HOST",
                          help="ssh destination, or local:<dir> to rehearse the "
                               "deploy locally (extracts with a real tar)")
    deploy_p.add_argument("--ssh-port", type=int, default=None, metavar="PORT",
                          help="ssh port (default 22, or deploy.ssh_port)")
    deploy_p.add_argument("--ssh-password-env", dest="ssh_password_env",
                          metavar="VAR",
                          help="Environment variable holding the ssh password "
                               "(never inline; omit to use key/agent auth)")

    files_p = sub.choices["files"]
    files_p.add_argument("--backup", action="append", default=[], metavar="PATH",
                         help="Snapshot this webroot-relative file (repeatable); "
                              "read-only on the remote side")
    files_p.add_argument("--restore", metavar="SNAPSHOT",
                         help="Restore a files snapshot by directory name/path "
                              "(or 'last')")
    files_p.add_argument("--path", action="append", default=[], metavar="PATH",
                         help="Webroot-relative target for an edit (repeatable; "
                              "pair with --from)")
    files_p.add_argument("--from", dest="from_paths", action="append", default=[],
                         metavar="LOCAL",
                         help="Local file paired by position with --path; "
                              "apply is transactional and snapshotted")

    park_p = sub.choices["park-backups"]
    park_p.add_argument("--park-outside", dest="park_outside", metavar="DIR",
                        help="Directory the payloads are moved INTO; must be "
                             "outside the webroot (default: "
                             "<backup-dir>/parked/<site>-<timestamp>)")

    webp_p = sub.choices["webp-media"]
    webp_p.add_argument("--purge-originals", dest="purge_originals",
                        # tri-state: None = the operator did not type it, so a
                        # profile's webp.purge_originals can ask for it
                        # (store_true without default=None makes that door
                        # dead code) [L37]
                        action="store_true", default=None,
                        help="Delete the originals after the rewritten "
                             "references verify (their bytes are in the "
                             "pre-action snapshot)")
    webp_p.add_argument("--i-know-editors-are-off",
                        dest="i_know_editors_are_off", action="store_true",
                        help="Required with --purge-originals: acknowledge "
                             "that nobody edits the site during the run (an "
                             "editor's stale save re-introduces the original "
                             "filename and a purge behind it breaks the page)")

    update_p = sub.choices["update-core"]
    update_p.add_argument("--to", dest="to", metavar="X.Y.Z",
                          help="The EXPLICIT target core version to install "
                               "(required for --apply: the target is never "
                               "implicit). Without it the run is a read-only "
                               "report of what wp.org offers")
    update_p.add_argument("--allow-pre-release", dest="allow_pre_release",
                          action="store_true", default=None,
                          help="Acknowledge that a pre-release (RC/beta/alpha) "
                               "target — or a dev/beta/RC INSTALL — is "
                               "deliberate (otherwise both are refused; "
                               "update.pre_release_allowed is the default)")

    restore_p = sub.choices["restore"]
    restore_p.add_argument("snapshot", nargs="?", default=None, metavar="TS",
                           help="Snapshot name YYYYmmdd-HHMMSS[-N]; omit to list snapshots")
    restore_p.add_argument("--undo-last", dest="undo_last", action="store_true",
                           help="Restore the NEWEST snapshot (composes with the targeting flags)")
    restore_p.add_argument("--file", action="append", default=None, metavar="PATH",
                           help="Restore only this webroot-relative file (repeatable)")
    restore_p.add_argument("--path-prefix", dest="path_prefix", metavar="DIR",
                           help="Restore only files under this webroot-relative subtree")
    restore_p.add_argument("--table", action="append", default=None, metavar="NAME",
                           help="Restore only this DB table (repeatable)")
    restore_p.add_argument("--config", choices=("wp-config", ".htaccess"),
                           help="Restore only the named config file")
    restore_p.add_argument("--media", action="store_true",
                           help="Restore only the uploads subtree (--apply writes)")

    deact_p = sub.choices["deactivate-plugin"]
    deact_p.add_argument("plugin", metavar="SLUG",
                         help="Plugin slug (directory), e.g. litespeed-cache")

    users_p = sub.choices["users_reset"]
    users_target = users_p.add_mutually_exclusive_group()
    users_target.add_argument("--login", action="append", default=None,
                              metavar="LOGIN",
                              help="Reset only this account (repeatable). The "
                                   "specific-account shape is the default: a "
                                   "run with no target refuses rather than "
                                   "resetting everyone")
    users_target.add_argument("--all", action="store_true",
                              help="Reset EVERY user's password (the whole "
                                   "site; a user created between plan and "
                                   "apply fails the run closed)")

    create_p = sub.choices["user-create"]
    create_p.add_argument("--login", required=True, metavar="LOGIN",
                          help="Login for the new account (WordPress "
                               "sanitizes it; the plan shows the result)")
    create_p.add_argument("--email", required=True, metavar="EMAIL",
                          help="Email for the new account (valid and unused)")
    create_p.add_argument("--role", default="administrator", metavar="ROLE",
                          help="Role to grant (default administrator; must be "
                               "a role the site defines)")

    serve_p = sub.choices["serve"]
    serve_p.add_argument("--port", type=int, default=DEFAULT_SERVE_PORT,
                         help=f"Local port to listen on "
                              f"(default {DEFAULT_SERVE_PORT})")

    proxy_p = sub.choices["proxy"]
    proxy_p.add_argument("--hostname", required=True, help="Real site hostname (SNI/Host)")
    proxy_p.add_argument("--ip", required=True, help="Upstream IP to connect to")
    proxy_p.add_argument("--port", type=int, default=DEFAULT_PROXY_PORT,
                         help=f"Local listen port (default {DEFAULT_PROXY_PORT})")
    proxy_p.add_argument("--cert-dir", type=Path, default=DEFAULT_CERT_DIR)
    return p


# argparse's own "this is a negative number, not an option" rule — the
# scan must agree with it, or `--deadline -5` would read as an unknown flag.
_NEGATIVE_NUMBER = re.compile(r"^-\d+$|^-\d*\.\d+$").match


def _option_spec(parser: argparse.ArgumentParser) -> dict[str, bool]:
    """Every option a parser accepts: name -> takes a value.

    Read off the parser itself (its action registry) so the flag tables
    have exactly ONE owner — the add_argument calls — including the
    --help/--version actions argparse adds on our behalf.
    """
    return {name: action.nargs != 0
            for action in parser._actions
            for name in action.option_strings}


def _resolve(token: str, spec: dict[str, bool]) -> tuple[str, bool] | None:
    """(name, takes_value) for a token argparse would accept as an option.

    Long-option abbreviations resolve the way argparse resolves them
    (prefix match).  An AMBIGUOUS abbreviation resolves to None: we never
    guess between candidates — argparse owns that error, so the token is
    left exactly where the caller typed it.
    """
    name = token.partition("=")[0]
    if name in spec:
        return name, spec[name]
    if not name.startswith("--"):
        return None
    matches = [known for known in spec if known.startswith(name)]
    if len(matches) == 1:
        return matches[0], spec[matches[0]]
    return None


def _is_ambiguous(token: str, spec: dict[str, bool]) -> bool:
    """An abbreviation several options share: argparse raises its own
    'ambiguous option' error, so the token is left exactly as typed rather
    than claimed to be an unknown flag."""
    name = token.partition("=")[0]
    if not name.startswith("--") or name in spec:
        return False
    return 1 < sum(1 for known in spec if known.startswith(name))


def _value_like(token: str) -> bool:
    """Can this token be a flag's value?  argparse refuses an option-looking
    token there (its "expected one argument" error), so the scan must not
    eat one either — that keeps its own usage errors the ones argparse
    raises, and keeps the diagnosis below pointing at the real mistake."""
    return not token.startswith("-") or token == "-" or bool(_NEGATIVE_NUMBER(token))


def _take(argv: list[str], i: int, target: list[str], takes_value: bool) -> int:
    """Append the flag at argv[i] (and its value) to target; next index.

    An inline `--flag=value` already carries its value — the next token is
    the caller's, never swallowed.
    """
    token = argv[i]
    target.append(token)
    j = i + 1
    if takes_value and "=" not in token and j < len(argv) and _value_like(argv[j]):
        target.append(argv[j])
        j += 1
    return j


def _subparsers(parser: argparse.ArgumentParser):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action
    raise RuntimeError("parser has no subcommands")  # pragma: no cover


def _positional_count(parser: argparse.ArgumentParser) -> int:
    """How many bare tokens the parser reads as positionals.

    Read off the action registry like :func:`_option_spec`, so a
    command's positional count has the same single owner as its flags (its
    ``add_argument`` calls). The subparsers action is excluded: it selects
    the command, it is not an argument of one.
    """
    return sum(
        1 for action in parser._actions
        if not action.option_strings
        and not isinstance(action, argparse._SubParsersAction)
    )


def _hoistable(argv: list[str], i: int, takes_value: bool,
               positionals_left: int) -> bool:
    """May the global flag at ``argv[i]`` be lifted ahead of the command?

    A global flag may be written on either side of the command name, so the
    scan may move it — but it may never move it in a way that lets it eat a
    token argparse would not. Two refusals, both about that:

    * a value-taking flag with NO value-like token after it. Hoisting it
      lets the next token become its value, and the next token is the
      command name or a command positional: ``audit --zip`` would read a
      webroot archive called ``audit``, and ``restore --report TS`` would
      take the snapshot name as the report path and quietly LIST snapshots
      instead of restoring one (rc 0). Left where it was typed, argparse
      reports "unrecognized arguments" or "expected one argument" — the
      actual mistake.
    * the same steal when the token is the only one left that could fill a
      positional the command still reads.

    An inline ``--flag=value`` carries its own value, and a flag that takes
    none cannot steal anything, so both are always hoistable. The
    "something is left for the positional" test is deliberately permissive:
    it scans for any bare token, which a later flag may also end up
    claiming — it refuses only the unambiguous case, where nothing at all
    could serve the positional.
    """
    if not takes_value:
        return True
    token = argv[i]
    if "=" in token:
        return True
    j = i + 1
    if j >= len(argv) or not _value_like(argv[j]):
        return False
    if positionals_left and not any(
        not later.startswith("-") for later in argv[j + 1:]
    ):
        return False
    return True


def _misplaced_command_error(token: str, prev: str, later: str | None,
                             later_spec: dict[str, bool]) -> str:
    """The command name is not a command: a flag landed on the wrong side
    of it.  Name the flag and say which side it belongs to — never leave
    the operator with argparse's "invalid choice: '<a filename>'".

    Every argv token quoted here goes through the shared redactor first
    (the same one the log formatters and the report use): the token that
    landed in the command position is exactly where an operator's
    mistyped inline secret ends up, and a usage error must not be the one
    place a password is printed in clear.
    """
    token, prev = redact_text(token), redact_text(prev)
    owns_flag = later is not None and _resolve(prev, later_spec) is not None
    lines = [f"{token!r} is not a wpt command, so it cannot be the command name."]
    if owns_flag:
        lines.append(f"  * {prev!r} is a flag of the {later!r} command and "
                     "belongs AFTER the command name")
        lines.append("  * before the command, the next token is read as that "
                     "flag's value — so the VALUE lands in the command position")
        lines.append(f"Did you mean:  wpt <global flags> {later} {prev} {token}")
    else:
        lines.append("  * it looks like a VALUE for a flag whose flag name is "
                     "missing (a bare filename or path is never a command)")
        if later is not None:
            lines.append(f"  * flags of the {later!r} command belong AFTER the "
                         f"command name: {', '.join(sorted(later_spec))}")
            lines.append(f"Did you mean:  wpt <global flags> {later} --<flag> {token}")
        else:
            lines.append(f"Did you mean:  wpt <global flags> {token} --<flag> <value>")
    lines.append("Run 'wpt --help' or 'wpt <command> --help' for the full usage.")
    return "\n".join(lines)


def _unknown_flag_error(token: str, command: str | None,
                        spec: dict[str, bool], globals_: dict[str, bool]) -> str:
    """A flag that belongs to no parser.  Say where the flags DO go: the
    globals work on either side of the command, the command's own flags
    only after it.  The quoted token is redacted like every other argv
    echo (an operator who typed ``--api-key=<secret>`` must not have it
    printed back by the usage error)."""
    token = redact_text(token)
    if command is not None and _resolve(token, spec) is not None:
        return (f"{token!r} is not a global flag: it belongs to the "
                f"{command!r} command, AFTER the command name.\n"
                f"Run 'wpt {command} --help' for its flags.")
    lines = [f"{token!r} is not a wpt flag."]
    lines.append("Global flags may be written before OR after the command name: "
                 + ", ".join(sorted(globals_)) + ".")
    if command is not None:
        own = sorted(spec)
        lines.append(f"Flags of the {command!r} command (after the command): "
                     + (", ".join(own) if own else "none") + ".")
    lines.append("Run 'wpt --help' or 'wpt <command> --help' for the full usage.")
    return "\n".join(lines)


def _pre_scan(parser: argparse.ArgumentParser, argv: list[str]) -> list[str]:
    """Rewrite argv so a global flag works on EITHER side of the command.

    `audit --report out.md` and `--report out.md audit` are the same run:
    every global flag (and the value it takes) is hoisted ahead of the
    command name, in the order it was typed.  Everything else — the
    command's own flags, its positionals, and the `--` passthrough tail —
    keeps its exact place, so no working invocation changes meaning.

    A misplaced flag used to die as `invalid choice: '<the file you just
    named>'` or `unrecognized arguments: --report`; both shapes are caught
    here and answered with the flag that was put on the wrong side.

    Hoisting is a CONTIGUOUS prefix operation: the moment a global flag
    cannot be moved (see :func:`_hoistable`), every later token is passed
    through verbatim, so nothing downstream of a refused move is reordered
    around it. That keeps argparse's own diagnosis intact — a dangling
    ``--report`` before an ``--apply`` reads as "expected one argument"
    rather than being pushed behind the command and swallowing it.
    """
    globals_ = _option_spec(parser)
    choices = _subparsers(parser).choices
    commands = dict(COMMANDS)
    head: list[str] = []
    rest: list[str] = []
    command: str | None = None
    sub_spec: dict[str, bool] = {}
    positionals_left = 0
    hoisting = True
    unknown: list[str] = []
    i = 0
    while i < len(argv):
        token = argv[i]
        if token == "--":
            rest.extend(argv[i:])   # passthrough: never scanned, never moved
            break
        if token.startswith("-") and token != "-":
            in_sub = _resolve(token, sub_spec) if command is not None else None
            in_global = _resolve(token, globals_)
            if in_sub is not None:
                i = _take(argv, i, rest, in_sub[1])      # the command's own flag
            elif in_global is not None:
                if not hoisting or not _hoistable(
                        argv, i, in_global[1], positionals_left):
                    # stays exactly where it was typed: argparse owns the error
                    hoisting = False
                    rest.append(token)
                    i += 1
                else:
                    i = _take(argv, i, head, in_global[1])  # hoist the flag+value
            elif (_is_ambiguous(token, globals_)
                  or (command is not None
                      and _is_ambiguous(token, sub_spec))):
                rest.append(token)      # argparse's own ambiguous-option error
                i += 1
            else:
                unknown.append(token)
                rest.append(token)
                i += 1
            continue
        if command is not None:
            rest.append(token)        # a positional of the command (TS, slug)
            positionals_left = max(0, positionals_left - 1)
            i += 1
            continue
        if token not in commands:
            # By construction the first bare token IS the command name:
            # anything ahead of it can only be a flag's value.
            later = next((t for t in argv[i + 1:] if t in commands), None)
            later_spec = (_option_spec(choices[later]) if later is not None
                          else {})
            parser.error(_misplaced_command_error(
                token, argv[i - 1] if i else "", later, later_spec))
        command = token
        sub_spec = _option_spec(choices[token])
        positionals_left = _positional_count(choices[token])
        rest.append(token)
        i += 1
    if unknown:
        parser.error(_unknown_flag_error(unknown[0], command, sub_spec, globals_))
    return head + rest


def _lazy_call(ctx: Ctx, module: str, func: str) -> int:
    """Import an implementation lazily; friendly exit while not wired yet."""
    try:
        import importlib

        mod = importlib.import_module(module)
    except ImportError:
        log.warning("module not wired yet (integration pending): %s", module)
        print(f"module not wired yet (integration pending): {module}", file=sys.stderr)
        return 2
    handler = getattr(mod, func, None)
    if not callable(handler):
        # Module landed but its entry point has not (writer chain in flight):
        # fail friendly, never mask a runtime error raised inside the call.
        log.warning("entry point not wired yet (integration pending): %s.%s", module, func)
        print(f"entry point not wired yet (integration pending): {module}.{func}",
              file=sys.stderr)
        return 2
    return int(handler(ctx))


def _install_sigterm_self_shutdown() -> None:
    """SIGTERM = a REQUEST to stop, answered GRACEFULLY (never killed).

    The handler raises in the main thread, so the raise unwinds through
    the running command body's normal machinery: the finally teardowns
    run (bridge destroy, fail-closed snapshot cleanup, source close),
    the error contract logs one clear line, rc 1 comes back. wpt runs
    are therefore always self-ending — from the deadline budget OR from
    a cooperative stop request; no orphaned state either way. (A raise
    from a signal handler lands between bytecodes; a main thread blocked
    in a socket recv delivers it within the existing per-op timeouts.)
    """
    import signal

    def _handler(signum, _frame):
        raise StopRequested(
            f"received SIGTERM ({signum}) — shutting down cleanly; "
            "teardown and cleanup are running"
        )

    try:
        signal.signal(signal.SIGTERM, _handler)
    except ValueError:  # not the main thread (tests embedding main())
        pass


def _write_refusal_report(args, settings: Settings | None, reason: str) -> None:
    """Write the shared failure pair for a pre-dispatch refusal, if asked.

    ``--report`` is a promise made by EVERY command (SPEC), so a run refused
    before its body was reached must still leave the ``not_complete``
    markdown + JSON twin instead of the same absence a successful
    no-findings run leaves.  ``settings`` is None for bootstrap refusals
    that happen before the profile loads; the report header does not need it.
    """
    report_path = getattr(args, "report", None)
    if report_path is None:
        return
    # A pre-dispatch refusal must not overwrite the log it was about to
    # write: writing the failure markdown/twin over an aliased --log-file
    # destroyed the bytes that explain the refusal.
    from .report import report_output_alias_problem

    if report_output_alias_problem(
            getattr(args, "log_file", None), report_path) is not None:
        return
    try:
        from .actions.registry import write_failure_report

        ctx = _ctx_from_args(args, settings)
        write_failure_report(ctx, args.command or "wpt", reason,
                             title=f"wpt {args.command or ''}".rstrip())
    except Exception as exc:  # noqa: BLE001 — a stop reaches the boundary
        # RunControl is deliberately NOT caught here: the pre-dispatch
        # boundary answers it (one log line + its own failure-pair attempt),
        # so a signal during this writer is still a clean rc 1.
        if settings is not None:
            log.warning("could not write the refusal report: %s",
                        redact_text(str(exc)))


def _refuse_input(args, settings: Settings, reason: str) -> int:
    """Log one pre-dispatch input refusal AND write the shared failure pair."""
    log.error("%s", reason)
    _write_refusal_report(args, settings, reason)
    return 1


def _ctx_from_args(args, settings: Settings | None = None) -> Ctx:
    """The minimal Ctx a pre-dispatch failure report needs.

    No command body has run, so only the identity/report fields exist; the
    failure writer reads exactly those (site label, mode, and the complete
    local-input set ``report_protected_inputs`` owns).
    """
    ctx = Ctx(
        source=args.source or "local",
        settings=settings,
        command=args.command,
        backup_dir=args.backup_dir,
        webroot=args.webroot,
        wp_url=args.wp_url,
        zip=args.zip,
        sql=args.sql,
        db_uri=args.db_uri,
        re_dump=getattr(args, "re_dump", None),
        report_path=args.report,
        deadline_s=args.deadline,
        extra={"from_paths": list(getattr(args, "from_paths", None) or []),
               "profile": getattr(args, "profile", None),
               "baseline": getattr(args, "baseline", None),
               "snapshot": getattr(args, "snapshot", None),
               "undo_last": getattr(args, "undo_last", None),
               "restore": getattr(args, "restore", None),
               "ssh_target": getattr(args, "ssh_target", None)},
    )
    if getattr(args, "command", None) == "proxy":
        # The TLS pair is a local INPUT of every proxy run, including runs
        # refused before the command body (bad deadline/--set/SIGTERM).
        from .dnsoverride import DEFAULT_CERT_DIR
        from .proxy import protect_cert_inputs

        protect_cert_inputs(
            ctx, getattr(args, "cert_dir", DEFAULT_CERT_DIR))
    return ctx


def _pre_dispatch_run_control_exit(args, exc: RunControl) -> int:
    """Answer a stop/deadline raised anywhere in the post-handler phase.

    Settings load, password resolution, every input gate and the refusal
    writer used to sit OUTSIDE the one dispatch boundary: a SIGTERM there
    escaped ``main`` as a traceback and left no report pair (R11-P2-13).
    The same shared exit now covers that whole phase.
    """
    return _run_control_exit(_ctx_from_args(args), args.command or "wpt", exc)


def main(argv: list[str] | None = None) -> int:
    # A completed run mutates the site before it writes its report; a
    # non-UTF-8 terminal encoding must degrade a glyph, never turn the
    # report write into a UnicodeEncodeError traceback after the mutation.
    # This is the ONE process-wide output choke point (every command's
    # stdout/stderr rides these streams).
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(errors="replace")
            except (ValueError, OSError):
                pass
    parser = build_parser()
    tokens = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(_pre_scan(parser, tokens))
    if args.source is None:
        # ``proxy`` is a local TLS tunnel over --hostname/--ip only: it reads
        # no source, zip, dump, webroot or site URL, so the documented
        # ``wpt proxy --hostname ... --ip ...`` has no --source to give.
        # Every other command keeps the old required-input contract.
        if args.command == "proxy":
            args.source = "local"
        else:
            parser.error("the following arguments are required: --source")
    _install_sigterm_self_shutdown()
    try:
        return _main_after_handler(args)
    except RunControl as exc:
        return _pre_dispatch_run_control_exit(args, exc)


def _main_after_handler(args) -> int:
    """The whole post-SIGTERM-handler phase, inside ONE RunControl boundary.

    Settings load, credential resolution, every pre-dispatch input gate,
    the report-collision gate and the dispatch itself all live here; before
    this split only ``_dispatch`` was guarded, so a stop during any earlier
    step escaped ``main`` with no failure pair (R11-P2-13).
    """
    if args.deadline is not None and (
            not math.isfinite(args.deadline) or args.deadline < 0):
        # Deadline.from_ctx treats <= 0 as unbounded and NaN/Inf never
        # expires; accepting either would disable self-bounding by typo.
        # 0 stays the documented explicit off switch.
        reason = ("--deadline must be a finite number of seconds >= 0 "
                  "(0 disables the bound)")
        _write_refusal_report(args, None, reason)
        print(f"wpt: {reason}", file=sys.stderr)
        return 1
    overrides: dict[str, Any] = {}
    try:
        for key, raw in args.set:
            k, v = _typed_override(key, raw)
            overrides[k] = v
        settings = load_settings(
            profile_path=str(args.profile) if args.profile else None,
            overrides=overrides,
        )
    except (WptError, OSError, ValueError, RecursionError, MemoryError) as exc:
        # A rejected --set/--profile is an OPERATOR error the settings owner
        # raises for. Unwound here it escaped main() as a traceback; a usage
        # mistake must read as one line with a real exit status, never as a
        # stack trace. stderr is the channel, not the logger: this runs
        # BEFORE setup_logging, so there is no log file to record it in yet.
        # The override loop sits INSIDE this refusal contract: a deeply
        # nested JSON literal raised there (not in load_settings) and wrote
        # no report pair at all.
        _write_refusal_report(args, None, f"settings rejected: {exc}")
        print(f"wpt: {exc}", file=sys.stderr)
        return 1
    # One level owner: --log-level wins, then the documented environment
    # fallback, then the profile.  An unknown name is refused here (settings
    # validates the profile door; setup_logging would silently answer INFO).
    level = args.log_level or os.environ.get("WPT_LOG_LEVEL") or settings.log.level
    normalized = str(level).strip().lower()
    if normalized not in LOG_LEVELS:
        reason = f"log level {level!r} is not one of {sorted(LOG_LEVELS)}"
        _write_refusal_report(args, None, reason)
        print(f"wpt: {reason}", file=sys.stderr)
        return 1
    if args.log_file:
        # --log-file is an APPENDED output opened by setup_logging BEFORE the
        # command body and before the --report gate.  Naming a run input there
        # (zip/dump/profile/baseline/certificate/snapshot — the complete set
        # is report_protected_inputs) would corrupt it even on a read-only
        # command.  Check the ONE protected-set owner before opening anything;
        # a refusal leaves the input byte-identical and writes no log bytes.
        from .report import (non_regular_target_problem,
                             report_hardlink_problem,
                             report_input_collision,
                             report_output_alias_problem,
                             report_protected_inputs,
                             report_protected_subtrees)

        # The OUTPUT shape is checked BEFORE setup_logging opens anything:
        # a FIFO/device/directory has no self-ending open (a no-reader FIFO
        # blocked past --deadline; /dev/full discarded every line and made
        # the run a silent rc 0), and the report faces are the same file
        # class the lone gate is meant to protect.
        shape = non_regular_target_problem(Path(args.log_file))
        if shape is not None:
            reason = f"--log-file {args.log_file}: {shape}; refusing to open it"
            _write_refusal_report(args, settings, reason)
            print(f"wpt: {reason}", file=sys.stderr)
            return 1
        alias = report_output_alias_problem(
            Path(args.log_file), getattr(args, "report", None))
        if alias is not None:
            reason = f"--log-file {args.log_file}: {alias}; refusing to open it"
            _write_refusal_report(args, settings, reason)
            print(f"wpt: {reason}", file=sys.stderr)
            return 1

        gate_ctx = _ctx_from_args(args, settings)
        protected_inputs = report_protected_inputs(gate_ctx)
        collision = report_input_collision(
            Path(args.log_file), protected_inputs,
            subtrees=report_protected_subtrees(gate_ctx),
            json_twin=False)
        if collision is not None:
            reason = (f"--log-file {args.log_file} resolves to this run's "
                      f"input {collision}; refusing to overwrite the input "
                      "it reads")
            _write_refusal_report(args, settings, reason)
            print(f"wpt: {reason}", file=sys.stderr)
            return 1
        linked = report_hardlink_problem(Path(args.log_file),
                                         protected_inputs)
        if linked is not None:
            reason = (f"--log-file {args.log_file}: {linked}; refusing to "
                      "open it")
            _write_refusal_report(args, settings, reason)
            print(f"wpt: {reason}", file=sys.stderr)
            return 1
    try:
        setup_logging(level=normalized,
                      logfile=str(args.log_file) if args.log_file else None,
                      json_mode=args.log_json, console=not args.quiet)
    except OSError as exc:
        # ``FileHandler`` opens eagerly; an unopenable --log-file used to
        # escape main() as a FileNotFoundError traceback.  Same one-line
        # stderr contract as a rejected --set.
        reason = f"cannot open --log-file {args.log_file}: {exc}"
        _write_refusal_report(args, None, reason)
        print(f"wpt: {reason}", file=sys.stderr)
        return 1

    # --db-uri and its companions are validated FIRST, before the per-mode
    # input gates: a mistyped companion flag must be answered with the flag
    # it belongs to, not with "local mode requires --zip and --sql".
    if args.db_uri and args.source != "local":
        # One-line refusal, not a silent ignore: in ftp mode the bridge is
        # the database write path, and two write paths for one command is
        # how a run ends up mutating the wrong one.
        return _refuse_input(
            args, settings,
            "--db-uri is a local-mode source; in ftp mode the bridge is "
            "the database path — drop it or use --source local")
    if args.db_uri and args.command not in _DB_URI_COMMANDS:
        return _refuse_input(
            args, settings,
            f"--db-uri applies to {'/'.join(_DB_URI_COMMANDS)} only")
    if args.db_password_env and not args.db_uri:
        return _refuse_input(
            args, settings,
            "--db-password-env is the --db-uri password; pass --db-uri too")
    if args.re_dump and not (args.db_uri and args.command == "clean-db"):
        return _refuse_input(
            args, settings,
            "--re-dump needs --db-uri on a clean-db run (it re-dumps the "
            "database that was just cleaned)")

    if args.source == "local":
        if args.command == "serve":
            # static serving needs only the zip
            if not args.zip:
                return _refuse_input(args, settings, "serve requires --zip")
        elif args.command in ("doctor", "proxy"):
            # the local panel checks disk + wp.org only; proxy reads no
            # source at all (it is a local TLS tunnel over --hostname/--ip)
            pass
        elif args.command in ("logs", "discover", "backup", "walk"):
            # ftp-only command bodies own the refusal (and its --report
            # failure artifact); the CLI must not demand inputs they never
            # open.  backup/walk are FTP-only (SPEC §backup/§walk), so a
            # local run must hear that reason, not "requires --zip and --sql".
            pass
        elif args.command in FILE_ONLY_LOCAL_COMMANDS:
            # the webroot zip is the whole input: demanding a dump it never
            # opens refused a run that completes [the live clean-files case].
            if not args.zip:
                return _refuse_input(
                    args, settings,
                    f"{args.command} reads the webroot only: local mode "
                    "requires --zip")
        elif args.command == "clean-db" and args.db_uri:
            # --db-uri IS the DB data source: it replaces the dump (and the
            # bridge), and clean-db over a database touches no webroot file,
            # so demanding inputs the run never opens would refuse a run that
            # completes.
            pass
        elif not args.zip or not args.sql:
            return _refuse_input(
                args, settings,
                "local mode requires --zip and --sql "
                "(serve: --zip only; doctor/proxy: neither)")
    else:
        if args.command == "discover":
            # discovery exists to FIND the webroot; it needs neither the
            # webroot nor the public URL.
            pass
        elif args.command == "proxy":
            # proxy reads only --hostname/--ip; the ftp source, webroot and
            # site URL are irrelevant to a local tunnel.
            pass
        elif args.command in ("logs", "scan", "files"):
            # these read/write the webroot only; none opens a WordPress
            # session, so --wp-url is not part of their contract.
            if not args.webroot:
                return _refuse_input(
                    args, settings, f"{args.command} requires --webroot")
        elif not args.webroot or not args.wp_url:
            return _refuse_input(
                args, settings, "ftp mode requires --webroot and --wp-url")

    # --user is a credential identity in EVERY source mode (SPEC: --user
    # always requires --password-env, except proxy which reads no source).
    # The check used to live inside the ftp branch, so local mode accepted
    # --user with no secret source at all.
    if args.user and not args.password_env and args.command != "proxy":
        return _refuse_input(
            args, settings,
            "--user requires --password-env (secrets never inline)")

    try:
        password = resolve_password(args.password_env) if args.password_env else None
    except WptError as e:
        return _refuse_input(args, settings, str(e))

    db_password = None
    if args.db_uri:
        # Same credential choke point as the FTP password: the env var wins
        # over an inline one, and neither the URI's password nor the resolved
        # value is ever logged (DbUri prints redacted).
        try:
            db_password = resolve_db_password(parse_db_uri(args.db_uri),
                                             args.db_password_env)
        except WptError as e:
            return _refuse_input(args, settings, str(e))

    extra: dict[str, Any] = {}
    # An explicit --profile is a local INPUT of the run; a run without the
    # flag still reads the packaged default, which the protected-set owner
    # resolves itself (report_protected_inputs).
    if args.profile is not None:
        extra["profile"] = args.profile
    if args.command == "audit":
        extra["only"] = args.only
        extra["skip"] = args.skip
        extra["baseline"] = args.baseline
    if args.command == "restore":
        extra["snapshot"] = args.snapshot
        extra["undo_last"] = args.undo_last
        extra["file"] = args.file
        extra["path_prefix"] = args.path_prefix
        extra["table"] = args.table
        extra["config"] = args.config
        extra["media"] = args.media
    if args.command == "deactivate-plugin":
        extra["plugin"] = args.plugin
    if args.command == "users_reset":
        extra["logins"] = args.login
        extra["all"] = args.all
    if args.command == "user-create":
        extra["login"] = args.login
        extra["email"] = args.email
        extra["role"] = args.role
    if args.command == "serve":
        extra["port"] = args.port
    if args.command == "park-backups":
        extra["park_outside"] = args.park_outside
    if args.command == "webp-media":
        extra["purge_originals"] = args.purge_originals
        extra["i_know_editors_are_off"] = args.i_know_editors_are_off
        if args.i_know_editors_are_off and args.purge_originals is not True:
            extra["i_know_editors_are_off"] = False
    if args.command == "update-core":
        extra["to"] = args.to
        extra["allow_pre_release"] = args.allow_pre_release
    if args.command == "deploy":
        extra["ssh_target"] = args.ssh_target
        extra["ssh_port"] = args.ssh_port
        extra["ssh_password_env"] = args.ssh_password_env
    if args.command == "files":
        extra["backup"] = args.backup
        extra["restore"] = args.restore
        extra["paths"] = args.path
        extra["from_paths"] = args.from_paths

    ctx = Ctx(
        source=args.source,
        settings=settings,
        command=args.command,
        apply=args.apply,
        yes=args.yes,
        backup_dir=args.backup_dir,
        user=args.user,
        password=password,
        webroot=args.webroot,
        wp_url=args.wp_url,
        override_ip=args.override_ip,
        zip=args.zip,
        sql=args.sql,
        db_uri=args.db_uri,
        db_password=db_password,
        db_password_env=args.db_password_env,
        re_dump=args.re_dump,
        report_path=args.report,
        deadline_s=(args.deadline if args.deadline is not None
                    else settings.run.deadline_s),
        extra=extra,
    )
    if args.command == "proxy":
        # ONE helper for both builders: the resolved certificate/key pair is
        # a protected input BEFORE the pre-dispatch collision gate below.
        from .proxy import protect_cert_inputs

        protect_cert_inputs(ctx, args.cert_dir)

    if args.command in MUTATING_COMMANDS and not args.apply:
        log.info("%s: dry-run mode (pass --apply to execute)", args.command)

    # One run-start line [L15 — a killed run's stale log tail (its SIGTERM
    # error) read as the CURRENT run's output for minutes because the new
    # run logged nothing until its first result]: the operator watching a
    # log file can tell a fresh run started (and which command/target it
    # drives) before any phase completes.  Command, mode, webroot and site
    # URL only — never the user or anything secret-adjacent.
    log.info("wpt %s starting: source=%s webroot=%s site=%s",
             args.command, args.source, args.webroot or "-",
             args.wp_url or "-")

    command = args.command
    report_path = getattr(ctx, "report_path", None)
    if report_path is not None:
        # C10: --report names an OUTPUT.  A path that resolves to one of the
        # run's local INPUTS (the complete set is owned by
        # report_protected_inputs) would destroy the very file it is about
        # to read, so it is refused BEFORE any read and WITHOUT writing the
        # failure pair (writing it would be the overwrite).  The baseline's
        # twin refresh stays legal; the shared writer enforces the same rule
        # for programmatic callers.
        from .report import (report_input_collision, report_output_problem,
                             report_parent_problem,
                             report_protected_inputs,
                             report_protected_subtrees,
                             report_refreshable_inputs)

        problem = report_output_problem(report_path)
        if problem is not None:
            reason = f"--report {report_path}: {problem}"
            log.error("%s", reason)
            print(f"wpt: {reason}", file=sys.stderr)
            return 1
        # Collision BEFORE the writability probe: the probe creates and
        # unlinks a temp in the parent, and a report aimed inside a
        # protected tree (a snapshot, the local deploy target) must not
        # touch it even for a moment.
        collision = report_input_collision(
            report_path, report_protected_inputs(ctx),
            refreshable=report_refreshable_inputs(ctx),
            subtrees=report_protected_subtrees(ctx))
        if collision is not None:
            reason = (f"--report {report_path} resolves to this run's input "
                      f"{collision}; refusing to overwrite the input it "
                      "reads")
            log.error("%s", reason)
            print(f"wpt: {reason}", file=sys.stderr)
            return 1
        parent_problem = report_parent_problem(report_path)
        if parent_problem is not None:
            reason = f"--report {report_path}: {parent_problem}"
            log.error("%s", reason)
            print(f"wpt: {reason}", file=sys.stderr)
            return 1
    # ONE budget for the whole run, built before any command work.  Every
    # later Deadline.from_ctx(ctx) returns THIS instance, so a command's
    # pre-work (walk, identity read, scope expansion, wp.org fetch) can never
    # restart the clock.  An already-spent budget is refused here, before
    # dispatch, for EVERY command.
    deadline = Deadline.from_ctx(ctx)
    try:
        if deadline is not None:
            deadline.check("dispatch")
        return _dispatch(ctx, args, command)
    except RunControl as exc:
        # THE process boundary for a stop/deadline that no command body
        # answered itself.  The command's finally teardowns have already
        # run (the exception unwound through them); log one redacted line,
        # write the shared failure pair, return rc 1 — never a traceback.
        return _run_control_exit(ctx, command, exc)


def _run_control_exit(ctx: Ctx, command: str, exc: RunControl) -> int:
    """The shared stop/deadline exit: one line + the failure report pair."""
    reason = f"{command or 'wpt'}: {exc}"
    log.error("%s", redact_text(reason))
    try:
        from .actions.registry import write_failure_report

        write_failure_report(ctx, command or "wpt", reason,
                             title=f"wpt {command or ''}".rstrip())
    except (Exception, RunControl) as report_exc:  # noqa: BLE001
        # Reporting must never replace the stop's rc 1 — a second SIGTERM
        # landing during the write is still a run that ends here.
        log.warning("could not write the stop/deadline failure report: %s",
                    redact_text(str(report_exc)))
    return 1


def _dispatch(ctx: Ctx, args, command: str) -> int:
    """Route one already-validated run to its command body."""
    if command == "proxy":
        # wpt.proxy is the command BODY (the serve.py precedent): it owns
        # the engine's ImportError fallback and --report, so --report is
        # honoured here like on every other command.
        from .proxy import run_proxy

        return run_proxy(
            ctx,
            hostname=args.hostname, ip=args.ip, port=args.port,
            cert_dir=args.cert_dir,
        )

    if command == "audit":
        # One mode-agnostic entry point: wpt.audit.run branches on ctx.mode
        # (gather_local vs gather_remote) and runs the same check registry.
        return _lazy_call(ctx, "wpt.audit", "run")
    if command == "updates":
        # The updates command IS the audit restricted to the updates checks.
        ctx.extra["only"] = ["updates"]
        return _lazy_call(ctx, "wpt.audit", "run")
    if command == "verify":
        return _lazy_call(ctx, "wpt.verify", "run")
    if command == "backup":
        return _lazy_call(ctx, "wpt.backup", "run_backup")
    if command == "restore":
        return _lazy_call(ctx, "wpt.restore", "run_restore")
    if command == "walk":
        return _lazy_call(ctx, "wpt.walk", "run_walk")
    if command == "serve":
        return _lazy_call(ctx, "wpt.serve", "run_serve")
    if command == "doctor":
        return _lazy_call(ctx, "wpt.doctor", "run")
    if command == "scan":
        return _lazy_call(ctx, "wpt.scan", "run")
    if command == "logs":
        return _lazy_call(ctx, "wpt.logs", "run")
    if command == "discover":
        return _lazy_call(ctx, "wpt.discover", "run")
    if command == "files":
        return _lazy_call(ctx, "wpt.files", "run")
    # The action's credential holder is a module-level singleton, so it is
    # emptied BEFORE the run as well: a run that never reaches plan() (a
    # mode refusal) must not print a PREVIOUS run's passwords, and the
    # print below can only ever carry what this run generated.
    if command in CREDENTIAL_COMMANDS:
        from .actions.registry import get_action
        record = get_action(command)
        if record is not None and hasattr(record.action, "credentials"):
            record.action.credentials = []
    if command == "clean-db" and ctx.db_uri:
        # OFFLINE DATABASE SOURCE: the direct DB replaces the bridge (and
        # the dump). Routed here, not through the registry, because the
        # registry's local branch is the zip REHEARSAL — this run writes no
        # webroot file, so there is no archive to materialize. The action
        # module owns its own flow; the CLI stays the dispatcher.
        from .actions.clean_db import run_offline

        return run_offline(ctx)
    if command == "deploy":
        return _lazy_call(ctx, "wpt.deploy", "run")
    rc = _lazy_call(ctx, "wpt.actions", "run")
    if command in CREDENTIAL_COMMANDS:
        # The generated passwords exist NOWHERE else — not in the plan, not
        # in the report, not in the log (SPEC secrets rule) — so they print
        # here, once, on stdout.  Printed EVEN WHEN rc is 1: a run whose
        # post-apply verification failed still revoked (or created) every
        # credential, so withholding the new ones would lock the operator out
        # of their own site (the snapshot remains the rollback).  An empty
        # list prints nothing at all, which is what keeps a DRY run silent:
        # the password is generated only by the apply, and the action clears
        # its own holder at the start of every plan.
        from .actions.registry import get_action
        record = get_action(command)
        rows = (getattr(record.action, "credentials", None) or []) if record else []
        if rows:
            print("login\temail\tpassword")
            for row in rows:
                print(f"{row.get('login', '')}\t{row.get('email', '')}\t"
                      f"{row.get('password', '')}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
