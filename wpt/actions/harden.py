r"""harden action (W7h): apply .htaccess + wp-config.php hardening, diff-printed.

Two-phase action over the shared registry flow (``wpt.actions.registry`` —
the registry owns dry-run, confirmation, the fail-closed pre-action backup
and the local-mode write refusal; this module is pure domain logic).
Registered ``applies=("ftp", "local")``: ``plan`` only READS the two site
configuration files through the source, so it runs over the live site AND
over an offline zip (a local dry run lists exactly what a harden --apply
would change); the apply WRITES those files, so local mode never reaches
it through the registry (v1 write refusal, rc 1).

Every line of the mutation satisfies one ``wpt.audit.security`` check
whose fix text names this action:

* ``Options -Indexes`` — security.uploads_listing (no directory listing
  for the webroot, wp-content/uploads/ included).
* the HTTPS ``RewriteCond``/``RewriteRule`` pair — security.https_redirect.
* ``RewriteRule ^/?wp-json/wp/v2/users - [F]`` plus the
  ``rest_route`` ``RewriteCond`` — security.rest_users (the leading ``/?``
  is REQUIRED: per-directory matching keeps the slash, so the bare form
  never fires [L68]; WordPress also dispatches the query-string fallback
  ``/?rest_route=/wp/v2/users``, literal or ``%2F``-encoded).
* the ``author=\d`` ``RewriteCond`` + blanket ``[F]`` — security.author_scan.
* the ``<Files xmlrpc.php>`` deny block — security.xmlrpc, carrying BOTH
  the Apache 2.4 directive (``Require all denied``) and the 2.2 fallback
  (``Order Deny,Allow`` / ``Deny from all``) so legacy-era servers are
  covered too.
* ``define( 'DISALLOW_FILE_EDIT', true );`` in wp-config.php —
  security.disallow_file_edit.  The trigger is that check's own active-value
  rule, evaluated by the same PHP-aware scanner (the constants and the
  evaluator are imported from ``wpt.audit.security`` so the audit and the
  action can never disagree).

Out of scope, documented: security.wp_config_perms (wp-config.php
readable beyond 0600) is a FILEMODE issue — the Source contract has no
chmod operation, so this action cannot touch it; that finding's own fix
("chmod 0600 wp-config.php") stays the operator's manual step.
www->apex redirecting and certificate installation are likewise not
webroot file-content facts and stay out of v1.

Plan shape — up to THREE items (category ``webroot.hardening``,
``bytes_est=0``: config edits reclaim nothing):

* ``.htaccess`` — an item when the ``# BEGIN wpt-harden`` marker line is
  absent from the file (idempotency: a second run plans nothing).  A
  MISSING file still plans — creating .htaccess is valid — with detail
  noting "new file".  The pre-action snapshot records a missing file as
  an ABSENT manifest entry (restore will not recreate it; hardening a
  not-yet-existing file stays reversible).
* ``.htaccess`` AGAIN — the canonical WordPress permalink block, when the
  site uses pretty permalinks AND the exact ``# BEGIN WordPress ... # END
  WordPress`` block is absent.  Live defect (a real migration): harden
  once created a root .htaccess carrying ONLY its own block on a site
  with pretty permalinks — every subpage and /wp-json route 404'd until
  the WP block was restored (a local rehearsal could not catch it:
  ``php -S`` ignores .htaccess).  The gate: ``permalink_structure``
  non-empty, read through the audit's own option seams — the analyzer's
  options pass over the ``--sql`` dump locally, the bridge ``info``
  payload remotely (the heal-core precedent for an action needing a
  gathered site fact; apply re-derives FRESH exactly like plan).  An
  EMPTY structure is WordPress's own plain-``?p=N`` default — WP writes
  no rewrite block then, so neither do we.  The presence proof is the
  R1 discipline applied to THEIR markers: a WHOLE-LINE marker pair whose
  body is EXACTLY the canonical block, opened outside any
  ``<IfModule>``/``<IfDefine>`` — a commented-out pair, a truncated
  pair, a non-canonical body or a conditional wrapper reads as MISSING,
  never as present.  Position is FILE order: our block first, the WP
  block second, and the file position of OUR block follows the same rule
  — when the existing .htaccess already carries a ``RewriteRule``, our
  block is placed ABOVE it, because Apache ends the per-directory rewrite
  round at the first ``[L]`` and every rule below WP's catch-all
  (including the HTTPS force) would never run
  (:func:`_rewrite_rule_present`).
* ``wp-config.php`` — an item when DISALLOW_FILE_EDIT has no ACTIVE truthy
  definition.  The config is scanned as PHP (see audit.security
  ``_php_const_state``), so a commented-out line, a string define or
  ``define(..., false)`` is NOT hardening — the old raw-substring test read
  all three as done.  An active truthy DISALLOW_FILE_MODS also closes the
  editor, so it suppresses the item.  A value PHP decides at runtime
  (non-literal, or conditional) is surfaced as an APPLICABLE item that
  ``apply`` refuses: the operator sees it as "not applied" and the run exits
  non-zero, rather than an empty plan reporting success for a file nobody
  hardened.  A MISSING wp-config has nothing to edit: NO item and exactly ONE
  warning (never a crash, never a guess).
* ``backup_tables = []`` deliberately: files only, so the registry's
  pre-action snapshot captures .htaccess + wp-config.php with no bridge
  roundtrip (both .htaccess items share ONE manifest entry — the snapshot
  scope is the deduplicated target set).

Diff-printed surface (SPEC L3; the binding KISS compromise): a PlanItem
detail renders as ONE table line, so detail stays one line; instead
``plan`` logs the FULL proposal at INFO — the exact .htaccess block, and
for wp-config.php the exact define line harden will write plus its
insertion point as a line NUMBER.  The require line's own text is never
logged: wp-config.php carries absolute paths and other site-specific
content.  The proposal is therefore visible in --log-file and on stderr
for the dry run and the apply alike.

``apply`` re-derives everything FRESH (the plan's reads may be stale):

* .htaccess — the block is appended BYTE-EXACTLY (only ASCII is added;
  original bytes carried through untouched), with one newline first when
  the current content is non-empty and does not already end with one.
  Marker already present (hardened behind the plan's back) -> done=True,
  detail `", already hardened"`, NO write.
* .htaccess WP block — re-derived FRESH before any write: pretty
  permalinks must still be active (a plain-permalink site gets no
  rewrite block — WordPress itself writes none; a flip between plan
  and apply REFUSES the item with one warning so the operator re-plans),
  then the same presence check, append, write and read-back verification
  as our own block.
* wp-config.php — the define is inserted IMMEDIATELY BEFORE the first
  line matching ``^require.*wp-settings\.php`` (defines AFTER that
  require load too late — wp-settings bootstraps core); the insertion is
  byte-level, so an invalid-UTF-8 byte in the config passes through
  untouched (a replace-decode + re-encode would rewrite it as U+FFFD —
  a content-destroying hazard for a config file).  No require line ->
  the define is APPENDED at the end plus ONE warning (unusual placement,
  still effective).  ACTIVE truthy already defined (or DISALLOW_FILE_MODS
  truthy) -> done=True + ``", already hardened"``, NO write.  An active
  FALSEY value is REWRITTEN IN PLACE: an appended define cannot override it
  (PHP keeps the first definition and warns on the second), so a second
  define would be a silent no-op.  An unresolvable value -> done=False, one
  warning, NO write.
* Per-item try/except (WptError/OSError): ONE warning, done=False, the
  batch continues — the untouched item is restorable from the
  pre-action snapshot.

Writes go through ``source.write_bytes(..., allow_config=True)`` — the
only unlock the Source contract grants for its two protected config
paths, and the guard audits every unlocked write with its own warning.

Logging: ``get_logger("actions.harden")`` — the plan logs the proposal
at info plus one summary; apply logs per-item outcomes at info with
before/after byte sizes; failures log one warning each.  No wp-config
CONTENT ever reaches a log: only harden's own fixed define line, a fixed
phrase and a line number.
"""

from __future__ import annotations

import bisect
import re
from typing import TYPE_CHECKING

from ..audit.data import _opt_str
from ..audit.security import (
    _PHP_IDENT_RE,
    _DISALLOW_FILE_EDIT,
    _DISALLOW_FILE_MODS,
    _PHP_OPEN_TAG_RE,
    _WP_CONFIG,
    _php_code_mask,
    _php_const_state,
    _brace_follows,
    _inside_alternative_syntax,
    _skip_ws,
    _php_member_before,
    _php_named_arg_after,
    _php_rewrite_const,
    _php_word_before,
)
from ..log import get_logger
from ..localmode.analyzer import analyze
from ..report import Plan, human_bytes
from ..types import PlanItem, Source, SourceError, WptError
from .registry import register_action

if TYPE_CHECKING:
    from ..cli import Ctx

__all__ = ["HardenAction"]

log = get_logger("actions.harden")

#: Idempotency markers around the appended block; the BEGIN line is the
#: plan/apply marker test (this action owns both).
_HTACCESS_MARKER_BEGIN = "# BEGIN wpt-harden"
_HTACCESS_MARKER_END = "# END wpt-harden"

#: The webroot .htaccess — this action's write target (no canonical
#: owner existed among the audit constants; their fix texts name it).
_HTACCESS = ".htaccess"

#: The hardening block, byte-exact — structural Apache/WordPress facts,
#: not a settings tunable (same standing as the security checks' own
#: endpoint constants).
_HTACCESS_BLOCK = "\n".join(
    (
        _HTACCESS_MARKER_BEGIN,
        "Options -Indexes",
        "",
        "<IfModule mod_rewrite.c>",
        "RewriteEngine On",
        "# Force HTTPS",
        "RewriteCond %{HTTPS} !=on",
        # `^` alone matches the ROOT only on this host (LiteSpeed keeps the
        # leading slash in per-directory matching), so a subpage over http
        # was served unredirected [L68]; `^/?` matches every path, with or
        # without the leading slash, on both semantics.
        "RewriteRule ^/? https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]",
        "# Block REST user enumeration (pretty permalink)",
        # same leading-slash reality as the HTTPS force above
        "RewriteRule ^/?wp-json/wp/v2/users - [F]",
        "# Block the ?rest_route= fallback (WordPress dispatches it too)",
        # A per-directory RewriteRule sees the PATH; ``rest_route`` is in the
        # QUERY_STRING, so the pretty rule above never fired for
        # ``/?rest_route=/wp/v2/users``.  Accept a literal or percent-encoded
        # slash, any casing, and a leading separator per segment.
        "RewriteCond %{QUERY_STRING} (^|&)rest_route=(?:%2F|/)+wp"
        "(?:%2F|/)v2(?:%2F|/)users(?:%2F|/|&|$) [NC]",
        "RewriteRule ^/? - [F]",
        "# Block author-scan user enumeration",
        # Per-directory RewriteRule matches the PATH only; the query
        # string is never part of the subject, so the old
        # ``^/?\?author=\d`` rule could never match (the literal '?' is
        # not in the path).  The condition owns the query; the rule fires
        # on every path with `^/?` — `^` alone matched only the ROOT on a
        # host that keeps the leading slash (L68), leaving every subpage
        # author scan unblocked.
        "RewriteCond %{QUERY_STRING} author=\\d [NC]",
        "RewriteRule ^/? - [F]",
        "</IfModule>",
        "",
        "# Block XML-RPC",
        "<Files xmlrpc.php>",
        "<IfModule mod_authz_core.c>",
        "Require all denied",
        "</IfModule>",
        "<IfModule !mod_authz_core.c>",
        "Order Deny,Allow",
        "Deny from all",
        "</IfModule>",
        "</Files>",
        _HTACCESS_MARKER_END,
    )
)

#: The exact bytes appended to .htaccess (trailing newline included;
#: pure ASCII, so the append never rewrites existing content).
_HTACCESS_BLOCK_BYTES = (_HTACCESS_BLOCK + "\n").encode("ascii")

#: Every directive the block installs, derived from the block itself so the
#: proof of "already hardened" can never drift from what is actually written.
#: The canonical body between the markers, stripped for comparison. The block
#: is proof only when it matches this exactly: presence is not enough, because
#: a directive wrapped in an inactive <IfModule> is ignored by Apache.
_HTACCESS_BODY_LINES = tuple(
    line.strip()
    for line in _HTACCESS_BLOCK.splitlines()
    if line.strip() not in (_HTACCESS_MARKER_BEGIN, _HTACCESS_MARKER_END)
)

#: WordPress's OWN permalink-block markers (``insert_with_markers`` writes
#: ``# BEGIN <name>`` / ``# END <name>`` pairs; the .htaccess marker name is
#: "WordPress") — the pair harden must find intact before it leaves the
#: WP block alone.
_WP_MARKER_BEGIN = "# BEGIN WordPress"
_WP_MARKER_END = "# END WordPress"

#: The canonical WordPress rewrite block, byte-exact — the verbatim
#: ``mod_rewrite_rules()`` output (wp-includes/class-wp-rewrite.php) for a
#: webroot install: ``RewriteBase /`` and the ``/index.php`` catch-all are
#: what route every pretty-permalink request into WordPress.  Structural
#: WordPress fact, not a settings tunable (same standing as our own block).
_WP_PERMALINK_BLOCK = "\n".join(
    (
        _WP_MARKER_BEGIN,
        "<IfModule mod_rewrite.c>",
        "RewriteEngine On",
        "RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]",
        "RewriteBase /",
        "RewriteRule ^index\\.php$ - [L]",
        "RewriteCond %{REQUEST_FILENAME} !-f",
        "RewriteCond %{REQUEST_FILENAME} !-d",
        "RewriteRule . /index.php [L]",
        "</IfModule>",
        _WP_MARKER_END,
    )
)

#: The exact bytes appended to .htaccess (trailing newline included; pure
#: ASCII, so the append never rewrites existing content).
_WP_PERMALINK_BLOCK_BYTES = (_WP_PERMALINK_BLOCK + "\n").encode("ascii")

#: The canonical body between the WP markers, stripped for comparison —
#: the presence proof accepts ONLY this exact body (the R1 discipline
#: applied to WordPress's own markers).
_WP_PERMALINK_BODY_LINES = tuple(
    line.strip()
    for line in _WP_PERMALINK_BLOCK.splitlines()
    if line.strip() not in (_WP_MARKER_BEGIN, _WP_MARKER_END)
)


def _rewrite_rule_present(text: str) -> bool:
    """True when the file already carries a ``RewriteRule`` directive.

    Apache runs a directory's rewrite rules in FILE order, and the rules
    we install are only reachable if nothing above them already decided
    the request: WordPress's own permalink block ends in
    ``RewriteRule . /index.php [L]``, and in a per-directory context
    ``[L]`` ends the round — every rule BELOW it (our HTTPS redirect, the
    REST-users and author-scan blocks) is unreachable for exactly the
    requests it protects. Appending to a file that already carries a
    RewriteRule would therefore install the protections and report them as
    applied while they never run, which is worse than not installing them.
    A ``RewriteEngine``/``RewriteBase``/``RewriteCond`` on its own cannot
    end a round, so those files still get the plain append.
    """
    return any(
        line.strip().lower().startswith("rewriterule")
        for line in text.splitlines()
    )


def _marked_block_span(
    text: str, marker_begin: str, marker_end: str, body_lines: tuple[str, ...]
) -> tuple[int, int] | None:
    """The character span of a COMPLETE, INTACT marked block, or None.

    Everything is matched as WHOLE LINES, never as substrings: `# BEGIN
    wpt-hardenX` is not our marker, and a `# Options -Indexes` line is a
    comment, not the directive. One pass collects each marked block's lines and
    accepts only one that still carries the EXACT canonical body, so a
    truncated write, a stray pair, a commented-out copy or a hand-edited
    block is never mistaken for hardening, and a file with many marker pairs
    costs one scan.

    The body must be EXACTLY the canonical bytes: presence is not enough,
    because a directive inside `<IfModule definitely_absent.c>` — closed
    inside the same block or not — is ignored by Apache, so the protections
    would be absent while every required line is present. Our own body wraps
    part of itself in `<IfModule mod_rewrite.c>`, so a conditional-depth test
    would reject the very block we install; matching the canonical body
    accepts it and rejects every reconstruction.

    A block whose OPENING marker sits inside an ``<IfModule>``/``<IfDefine>``
    is not proof either: the wrapper decides whether any of it runs.
    """
    inside = False
    collected: list[str] = []
    conditional_depth = 0
    block_conditional = False
    start = 0
    offset = 0
    for raw in text.splitlines(keepends=True):
        line = raw.strip()
        if line == marker_begin:
            inside = True
            start = offset
            collected = []
            block_conditional = conditional_depth > 0
            offset += len(raw)
            continue
        if line == marker_end:
            if inside and not block_conditional \
                    and tuple(collected) == body_lines:
                return start, offset + len(raw)
            inside = False
            collected = []
            offset += len(raw)
            continue
        if inside:
            collected.append(line)
        lowered = line.lower()
        if lowered.startswith("<ifmodule") or lowered.startswith("<ifdefine"):
            conditional_depth += 1
        elif lowered.startswith("</ifmodule>") \
                or lowered.startswith("</ifdefine>"):
            conditional_depth = max(0, conditional_depth - 1)
        offset += len(raw)
    return None


def _marked_block_present(
    text: str, marker_begin: str, marker_end: str, body_lines: tuple[str, ...]
) -> bool:
    """True when a COMPLETE, INTACT marked block is present (see span)."""
    return _marked_block_span(
        text, marker_begin, marker_end, body_lines) is not None


def _htaccess_is_hardened(text: str) -> bool:
    """True when a COMPLETE, INTACT wpt-harden block is present AND reachable.

    Presence alone is not proof: Apache runs directory rewrite rules in file
    order, so a live ``RewriteRule`` above our marker (WordPress's
    ``[L]`` catch-all, a hand-added redirect) ends the round before our
    rules run.  Such a file is planned for a RELOCATION, not reported as
    already hardened.
    """
    span = _marked_block_span(
        text, _HTACCESS_MARKER_BEGIN, _HTACCESS_MARKER_END,
        _HTACCESS_BODY_LINES)
    if span is None:
        return False
    return not _rewrite_rule_present(text[:span[0]])


def _wp_permalink_block_present(text: str) -> bool:
    """True when the canonical ``# BEGIN WordPress ... # END WordPress``
    permalink block is present — the whole-line, body-exact proof, so a
    commented-out pair, a truncated pair, a non-canonical body or a
    conditional wrapper reads as MISSING, never as present."""
    return _marked_block_present(
        text, _WP_MARKER_BEGIN, _WP_MARKER_END, _WP_PERMALINK_BODY_LINES
    )

#: The wp-config define (binding text) and its two byte forms: the
#: insertion form (no terminator — the line join adds it) and the append
#: form (terminator included).
#: Fully qualified on purpose: inside a namespace an unqualified define()
#: would create Namespace\DISALLOW_FILE_EDIT, which WordPress never reads.
#: `\define` names the global built-in and is valid at file scope too.
_DEFINE_LINE = "\\define( 'DISALLOW_FILE_EDIT', true );"
_DEFINE_LINE_BYTES = _DEFINE_LINE.encode("ascii")
_DEFINE_APPEND_BYTES = (_DEFINE_LINE + "\n").encode("ascii")

#: The wp-settings bootstrap require — the insertion anchor (defines
#: after it load too late).  The keyword is matched in the PHP mask (so only
#: live code counts); the path is matched in the raw text, because the mask
#: blanks string bodies.  PHP keywords are case-insensitive and ``include``
#: loads wp-settings exactly as ``require`` does.
_WP_SETTINGS_REQUIRE = re.compile(
    r"\b(?:require|require_once|include|include_once)\b", re.IGNORECASE
)
_WP_SETTINGS_PATH_RE = re.compile(r"wp-settings\.php")


def _is_require_construct(mask: str, index: int, token_end: int) -> bool:
    """True when the token spanning [index, token_end) is the PHP
    ``require``/``include`` language construct — not a variable, property,
    method, function name, or PHP 8 named argument."""
    if index and mask[index - 1] == "$":
        return False
    if _php_member_before(mask, index):
        return False
    if _php_named_arg_after(mask, token_end):
        return False
    return _php_word_before(mask, index).lower() != "function"

#: One-line plan details (render_report prints one table line per item).
_CATEGORY = "webroot.hardening"
_HTACCESS_DETAIL = (
    "diff-printed hardening block (HTTPS redirect, Options -Indexes, "
    "xmlrpc block, REST users block, author-scan block)"
)
_HTACCESS_NEW_DETAIL = _HTACCESS_DETAIL + " (new file)"
_WP_PERMALINK_DETAIL = (
    "WordPress permalink block (missing; pretty permalinks active)"
)
_WP_CONFIG_DETAIL = "add DISALLOW_FILE_EDIT"


def _read_optional(source: Source, path: str) -> bytes | None:
    """Current bytes of ``path``; None when the file is absent.

    Any other read failure propagates (fail-closed: the registry answers
    rc 1 — a plan over an unreadable file would be a guess).
    """
    if not source.exists(path):
        return None
    return source.read_bytes(path)


def _pretty_permalinks(ctx: "Ctx", stack: tuple) -> bool:
    """True when the site uses PRETTY permalinks (``permalink_structure``
    non-empty) — the fact that makes the canonical WordPress rewrite block
    load-bearing for every subpage and /wp-json route.

    The fact rides the audit's own option seams (the heal-core precedent for
    an action needing a gathered site fact): locally the analyzer's options
    pass over the ``--sql`` dump, remotely the bridge ``info`` payload — the
    same wires siteurl/home travel, so no parallel dump parsing exists here.
    An ABSENT option is WordPress's own plain-``?p=N`` default: not pretty.
    A fact that cannot be READ at all (bridge call failure, unreadable
    dump) PROPAGATES — the plan refuses rather than guessing at the one
    fact every route depends on.  A bridge-less stack (unit-test stacks;
    real ftp stacks always carry one) answers not-pretty at debug level.
    """
    if ctx.mode == "local":
        if ctx.sql is None:
            log.debug("local run carries no --sql dump; "
                      "permalink state unknown, WP block not planned")
            return False
        with open(ctx.sql, "rb") as dump:
            model = analyze(dump, ctx.settings.db)
        return bool(model.permalink_structure)
    bridge = stack[2]
    if bridge is None:
        log.debug("no bridge on the stack; permalink state unknown, "
                  "WP block not planned")
        return False
    return bool(_opt_str(bridge.call("info").get("permalink_structure")))


#: Outcome of looking for the wp-settings bootstrap require.
#: ``ANCHOR`` — a proven top-level require; harden inserts before it.
#: ``NONE`` — no require at all; harden may append, but only where the tail of
#: the file is still PHP code.
#: ``UNSAFE`` — a require exists but the scan cannot prove it is top-level
#: (alternative control syntax) or that it is not lexically broken.  Writing
#: anyway would place the define in a conditional or in inline HTML and report
#: a hardening that never happened, so harden refuses and says so.
_ANCHOR = "anchor"
_NONE = "none"
_UNSAFE = "unsafe"


def _wp_settings_require_insert(data: bytes) -> tuple[str, int, bytes]:
    """``(outcome, byte-offset, payload)`` for the DISALLOW_FILE_EDIT
    insertion.  The offset is a BYTE offset; the payload is what to splice in.

    The ``require`` keyword is recognised in the PHP-aware mask from
    wpt.audit.security, so one inside a block comment, a heredoc or a string is
    invisible: inserting before it would put the define inside the comment and
    harden nothing.  The wp-settings path is matched inside a comment-free
    mask of that one statement, so a require split across lines, or sharing a
    line with ``<?php``, is still found, while a path mentioned only in a
    comment is not.

    When the require shares its line with the open tag, the payload goes
    immediately AFTER the tag — inserting a line before it would place the
    define in inline HTML, where it does nothing at all.
    """
    text = data.decode("utf-8", errors="surrogateescape")
    mask, valid, _ = _php_code_mask(text)
    # Validity comes from the normal mask; the string-preserving one is only
    # for finding the path, and its exposed brackets must not be read as code.
    path_mask, _, _ = _php_code_mask(text, keep_strings=True)
    if not valid:
        return _UNSAFE, 0, b""
    depth = 0
    deferred = 0
    pending_fn = False
    pending_ns = False
    pending_declare = False
    # An arrow body is an EXPRESSION: without real expression parsing its end
    # cannot be located, so every require between the `fn` and the end of that
    # statement is unanchorable (a sibling call argument is evaluated
    # immediately, not deferred). The taint is cleared at the statement's own
    # terminator, so a completed arrow function above the bootstrap is fine.
    arrow_seen = False
    arrow_end = 0
    arrow_stack: list[int] = []  # open `fn (...) => expression` bodies
    exited = False
    # One pass for every statement end, so an arrow's end is O(1): scanning
    # forward per `fn` was quadratic in the number of arrow functions.
    # Statement terminators grouped by delimiter depth, in one pass: resolving
    # an arrow's end by scanning per `fn` was quadratic in the arrow count.
    by_depth: dict[int, list[int]] = {}
    _depth = 0
    for _index, _char in enumerate(mask):
        if _char in "([{":
            _depth += 1
        elif _char in ")]}":
            _depth = max(0, _depth - 1)
        elif _char == ";":
            by_depth.setdefault(_depth, []).append(_index)
    delimiter = 0
    stmt_delim = 0             # delimiter depth the current statement began at
    stmt_delim_stack: list[int] = []
    blocks: list[str] = []
    i = 0
    while i < len(mask):
        char = mask[i]
        if char in "([{":
            delimiter += 1
            if char == "{":
                # A block starts its own statements, so remember where this
                # one began and restore it on exit.
                stmt_delim_stack.append(stmt_delim)
                stmt_delim = delimiter
                if pending_ns:
                    # A namespace block only scopes names; its statements
                    # execute at file level, so depth must not grow.
                    blocks.append("ns")
                    pending_ns = False
                elif pending_declare:
                    # `declare(ticks=1) { ... }` body executes unconditionally.
                    blocks.append("declare")
                    pending_declare = False
                else:
                    if pending_fn:
                        deferred += 1
                    blocks.append("fn" if pending_fn else "")
                    pending_fn = False
                    depth += 1
            else:
                depth += 1
        elif char in ")]}":
            delimiter = max(0, delimiter - 1)
            if char == "}" and stmt_delim_stack:
                stmt_delim = stmt_delim_stack.pop()
            while arrow_stack and delimiter < arrow_stack[-1]:
                arrow_stack.pop()    # the arrow's enclosing group closed
            if char == "}" and blocks and blocks.pop() == "fn":
                deferred = max(0, deferred - 1)
            depth = max(0, depth - 1)
        elif char == ",":
            if arrow_stack and delimiter == arrow_stack[-1]:
                arrow_stack.pop()
        elif char == ";":
            if arrow_stack and delimiter == arrow_stack[-1]:
                arrow_stack.pop()
            if delimiter == stmt_delim:
                stmt_delim = delimiter
            # Every pending header flag is statement-scoped: `namespace X;`,
            # `declare(ticks=1);` and an abstract `function f(): void;` all
            # end here without a body, so a later brace is not theirs.
            pending_ns = False
            pending_declare = False
            pending_fn = False
            if arrow_seen and i == arrow_end:
                arrow_seen = False
        else:
            word = _PHP_IDENT_RE.match(mask, i)
            if word is not None and not _php_member_before(mask, i):
                lowered = word.group(0).lower()
                before = _php_word_before(mask, i).lower()
                if lowered == "function" and before not in ("function", "use"):
                    # `use function x;` is an import, not a declaration.
                    pending_fn = True
                elif lowered == "namespace" and not (i and mask[i - 1] == "$"):
                    pending_ns = True
                elif lowered == "declare" and not (i and mask[i - 1] == "$") \
                        and mask.startswith("(", _skip_ws(mask, word.end())):
                    pending_declare = _brace_follows(mask, word.end())
                elif lowered in ("exit", "die") and not deferred \
                        and not arrow_stack \
                        and not (i and mask[i - 1] == "$") \
                        and not _php_named_arg_after(mask, word.end()):
                    # A top-level `exit`/`die` ENDS the script, so a require
                    # after it never runs and the constant could never be
                    # defined there. The guard cannot prove the exit is
                    # reached, so it is treated as fatal: refuse the anchor.
                    exited = True
                elif lowered == "fn" and before != "function" and not deferred \
                        and not (i and mask[i - 1] == "$"):
                    # The taint lasts exactly this statement, wherever the `;`
                    # that ends it sits relative to the arrow's own depth.
                    # The first `;` AFTER this arrow at the arrow's own
                    # delimiter depth; a closure inside the body has deeper
                    # ones and must not end the scope.
                    arrow_seen = True
                    arrow_stack.append(delimiter)
                    _siblings = by_depth.get(stmt_delim, ())
                    _at = bisect.bisect_right(_siblings, i)
                    if _at < len(_siblings):
                        arrow_end = max(arrow_end, _siblings[_at])
            construct = _WP_SETTINGS_REQUIRE.match(mask, i)
            if construct is None or not _is_require_construct(
                mask, i, construct.end()
            ):
                i += 1
                continue
            if arrow_seen or exited:
                return _UNSAFE, 0, b""
            if deferred:
                # Inside a function/closure body: deferred, so it does not run
                # at load time and cannot be the bootstrap anchor.
                i += 1
                continue
            # A require at ANY depth counts: a nested one (inside an array or
            # a call argument) still loads wp-settings, so appending after it
            # would be too late while claiming success.
            end = _statement_end(mask, i)
            mentions_path = bool(_WP_SETTINGS_PATH_RE.search(path_mask[i:end]))
            if depth != 0:
                # A nested require loads SOMETHING; if it might be wp-settings,
                # refuse, and if its path is unknown it could be anything.
                return _UNSAFE, 0, b""
            if not mentions_path:
                # A live require whose target cannot be proven may already have
                # loaded wp-settings, so a later anchor must not erase that.
                return _UNSAFE, 0, b""
            if _inside_alternative_syntax(mask, i):
                # `if ($x): ... endif;` has no braces, so the require can look
                # top-level to a brace counter while sitting in a conditional.
                return _UNSAFE, 0, b""
            line_start = text.rfind("\n", 0, i) + 1
            # A real open tag is blanked in BOTH masks; one that merely
            # appears inside a string literal survives in path_mask (which
            # keeps string bodies) and must not be treated as a mode switch.
            open_tag = None
            for candidate in _PHP_OPEN_TAG_RE.finditer(text, line_start, i):
                if not path_mask[candidate.start():candidate.end()].strip():
                    open_tag = candidate
                    break
            offset = open_tag.end() if open_tag is not None else line_start
            payload = (
                b"\n" + _DEFINE_LINE_BYTES + b"\n"
                if open_tag is not None
                else _DEFINE_LINE_BYTES + b"\n"
            )
            return _ANCHOR, _byte_offset(text, offset), payload
        i += 1
    return _NONE, 0, b""


def _byte_offset(text: str, char_offset: int) -> int:
    """Convert a character offset into the byte offset of the same position
    in the original bytes (surrogateescape round-trip)."""
    return len(text[:char_offset].encode("utf-8", errors="surrogateescape"))


def _statement_end(mask: str, start: int) -> int:
    """Index of the ';' ending the statement at ``start``, or len(mask)."""
    depth = 0
    for i in range(start, len(mask)):
        char = mask[i]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif char == ";" and depth == 0:
            return i
    return len(mask)


def _log_wp_config_proposal(data: bytes) -> None:
    """Log the proposed wp-config.php change at info — the diff-printed
    surface: what harden will do, matching the branch ``apply`` will take.

    An existing falsey definition is rewritten in place (appending a second
    define cannot override it), so the proposal says exactly that. Only the
    fixed define line and a fixed phrase are logged: the require line itself
    is NOT, because wp-config.php routinely carries absolute paths and other
    site-specific text.
    """
    text = data.decode("utf-8", errors="surrogateescape")
    if _php_const_state(text, _DISALLOW_FILE_EDIT) == "falsey":
        log.info(
            "proposed %s change (existing %s definition rewritten to true):\n%s",
            _WP_CONFIG, _DISALLOW_FILE_EDIT, _DEFINE_LINE,
        )
        return
    outcome, offset, _ = _wp_settings_require_insert(data)
    if outcome == _NONE:
        log.info(
            "proposed %s change (no active wp-settings require line found):\n%s",
            _WP_CONFIG,
            _DEFINE_LINE,
        )
        return
    if outcome == _UNSAFE:
        log.info(
            "proposed %s change: NONE — the require line could not be proven "
            "top-level, so nothing will be written",
            _WP_CONFIG,
        )
        return
    log.info(
        "proposed %s change (inserted before the first active wp-settings "
        "require, line %d):\n%s",
        _WP_CONFIG,
        data[:offset].count(b"\n") + 1,
        _DEFINE_LINE,
    )


def _apply_htaccess(source: Source, item: PlanItem) -> None:
    """Install the hardening block in .htaccess, byte-exactly.

    APPENDED at the end by default (the file's own content is never
    rewritten), but PLACED FIRST when the file already carries a
    ``RewriteRule``: a rewrite rule above ours that ends its round with
    ``[L]`` — WordPress's own permalink catch-all does exactly that —
    makes every rule we install below it unreachable, so appending there
    would report protections the site does not have. The bytes written are
    the same either way; only their position differs.

    Fresh idempotency: a REACHABLE marker already present (the site was
    hardened between plan and apply) settles the item with NO write.  A
    canonical block that sits BELOW a live rewrite rule is unreachable, so
    it is removed and re-placed first — relocating, never duplicating.
    """
    current = _read_optional(source, _HTACCESS) or b""
    text = current.decode("utf-8", errors="surrogateescape")
    span = _marked_block_span(
        text, _HTACCESS_MARKER_BEGIN, _HTACCESS_MARKER_END,
        _HTACCESS_BODY_LINES)
    if span is not None:
        if not _rewrite_rule_present(text[:span[0]]):
            item.done = True
            item.detail = f"{item.detail}, already hardened"
            log.info("apply: %s already hardened", _HTACCESS)
            return
        # The canonical block exists but a live RewriteRule above it ends
        # the round before our protections run.  Remove the exact block and
        # prepend it; ``surrogateescape`` round-trips every unrelated byte.
        remainder = text[:span[0]] + text[span[1]:]
        new = _HTACCESS_BLOCK_BYTES + remainder.encode(
            "utf-8", errors="surrogateescape")
        placement = ("relocated first (an existing RewriteRule shadowed "
                     "the previous block)")
    elif current and _rewrite_rule_present(text):
        tail = current if current.endswith(b"\n") else current + b"\n"
        new = _HTACCESS_BLOCK_BYTES + tail
        placement = "placed first (an existing RewriteRule can shadow it)"
    else:
        new = current
        if new and not new.endswith(b"\n"):
            new += b"\n"
        new += _HTACCESS_BLOCK_BYTES
        placement = "appended"
    source.write_bytes(_HTACCESS, new, allow_config=True)
    _verify_written(source, _HTACCESS, new)
    item.done = True
    log.info(
        "apply: %s hardened, block %s (%d -> %d bytes)",
        _HTACCESS, placement, len(current), len(new),
    )


def _apply_wp_permalink_block(
    ctx: "Ctx", stack: tuple, source: Source, item: PlanItem
) -> None:
    """Append the canonical WordPress permalink block to .htaccess.

    Fresh facts, exactly like the plan phase derived them: pretty permalinks
    must STILL be active — WordPress itself writes no rewrite block for a
    plain-``?p=N`` site, so a flip between plan and apply REFUSES the item
    (one warning, nothing written) instead of installing a block the site
    no longer wants.  Then the same presence check, byte-exact append,
    write and read-back verification as our own block.
    """
    if not _pretty_permalinks(ctx, stack):
        raise SourceError(
            "the site no longer reports pretty permalinks; the WordPress "
            "permalink block is not applicable — re-run wpt harden for a "
            "fresh plan"
        )
    current = _read_optional(source, _HTACCESS) or b""
    if _wp_permalink_block_present(current.decode("utf-8", errors="replace")):
        item.done = True
        item.detail = f"{item.detail}, already hardened"
        log.info("apply: %s WordPress permalink block already present", _HTACCESS)
        return
    new = current
    if new and not new.endswith(b"\n"):
        new += b"\n"
    new += _WP_PERMALINK_BLOCK_BYTES
    source.write_bytes(_HTACCESS, new, allow_config=True)
    _verify_written(source, _HTACCESS, new)
    item.done = True
    log.info(
        "apply: %s WordPress permalink block added (%d -> %d bytes)",
        _HTACCESS, len(current), len(new),
    )


def _verify_written(source: Source, path: str, expected: bytes) -> None:
    """Read the file back and require the exact bytes.

    A write that reports success is not proof on a live site: an FTP upload
    can truncate silently. Since these are protected config files and the
    pre-action snapshot is the only undo, a mismatch must fail the item rather
    than be reported as hardened.
    """
    stored = source.read_bytes(path)
    if stored != expected:
        raise SourceError(
            f"{path} read back {0 if stored is None else len(stored)} bytes "
            f"but {len(expected)} were written; the write did not land as "
            f"intended (restore from the pre-action snapshot)"
        )


def _apply_wp_config(source: Source, item: PlanItem) -> None:
    """Insert the DISALLOW_FILE_EDIT define before the wp-settings
    require line (byte-level; fresh idempotency)."""
    current = _read_optional(source, _WP_CONFIG)
    if current is None:
        raise SourceError(f"no {_WP_CONFIG} on the source; nothing to edit")
    # surrogateescape round-trips the undecodable bytes verbatim, so the
    # in-place rewrite below cannot rewrite them as U+FFFD.
    text = current.decode("utf-8", errors="surrogateescape")
    state = _php_const_state(text, _DISALLOW_FILE_EDIT)
    mods = _php_const_state(text, _DISALLOW_FILE_MODS)
    if state == "truthy" or mods == "truthy":
        item.done = True
        item.detail = f"{item.detail}, already hardened"
        log.info("apply: %s already hardened", _WP_CONFIG)
        return
    if state == "unknown" or mods == "unknown":
        # Matches the audit's unverifiable finding: when either constant is
        # decided at runtime, the hardening state as a whole is unprovable,
        # and rewriting only the resolvable one could report a false success.
        raise SourceError(
            f"{_DISALLOW_FILE_EDIT}/{_DISALLOW_FILE_MODS} in {_WP_CONFIG} is "
            f"set to a value this static scan cannot resolve; set "
            f"{_DISALLOW_FILE_EDIT} to true by hand"
        )
    if state == "falsey":
        # An active falsey define wins over anything appended after it (PHP
        # keeps the first definition and warns on the second), so the existing
        # value is rewritten in place instead.
        new_text = _php_rewrite_const(text, _DISALLOW_FILE_EDIT, "true")
        if new_text is None:
            raise SourceError(
                f"{_DISALLOW_FILE_EDIT} in {_WP_CONFIG} could not be located "
                f"for an in-place edit; set it to true by hand"
            )
        new = new_text.encode("utf-8", errors="surrogateescape")
        _require_active(new, "in-place rewrite")
        source.write_bytes(_WP_CONFIG, new, allow_config=True)
        _verify_written(source, _WP_CONFIG, new)
        item.done = True
        log.info(
            "apply: %s %s false -> true (%d -> %d bytes)",
            _WP_CONFIG, _DISALLOW_FILE_EDIT, len(current), len(new),
        )
        return
    outcome, offset, payload = _wp_settings_require_insert(current)
    if outcome == _UNSAFE:
        raise SourceError(
            f"the wp-settings require in {_WP_CONFIG} could not be proven "
            f"top-level; add {_DISALLOW_FILE_EDIT} by hand"
        )
    if outcome == _NONE:
        text_now = current.decode("utf-8", errors="surrogateescape")
        _, valid, ends_in_php = _php_code_mask(text_now)
        if not valid or not ends_in_php:
            # Appending raw PHP text after a '?>' would be inline HTML: PHP
            # would print it and the constant would never exist.
            raise SourceError(
                f"{_WP_CONFIG} does not end in PHP code; add "
                f"{_DISALLOW_FILE_EDIT} by hand"
            )
        new = current
        if new and not new.endswith(b"\n"):
            new += b"\n"
        new += _DEFINE_APPEND_BYTES
        log.warning(
            "no wp-settings require line found in %s: %s appended at the "
            "end (verify the placement)",
            _WP_CONFIG,
            _DISALLOW_FILE_EDIT,
        )
    else:
        new = current[:offset] + payload + current[offset:]
    _require_active(new, "insertion")
    source.write_bytes(_WP_CONFIG, new, allow_config=True)
    _verify_written(source, _WP_CONFIG, new)
    # Re-verify on the bytes the SITE now holds, not on the proposal: that is
    # the only proof the hardening actually landed.
    _require_active(source.read_bytes(_WP_CONFIG), "stored file", stored=True)
    item.done = True
    log.info(
        "apply: %s hardened (%d -> %d bytes)", _WP_CONFIG, len(current), len(new)
    )


def _require_active(new: bytes, how: str, stored: bool = False) -> None:
    """Refuse to write unless the resulting wp-config.php ACTUALLY activates
    DISALLOW_FILE_EDIT.

    This is the write path's own proof, and it is deliberately stronger than
    the analysis that chose the edit: a file that would place the define
    inside a string, a comment, a conditional, a nested expression or a
    compiler-halted tail all parse as "the constant is not active", so no
    bytes are written and the operator is told to harden by hand. Verifying
    the effect, rather than trusting the intent, is what makes a wp-config
    write safe to attempt automatically.

    With ``stored`` the check runs on the bytes the SITE now holds, after a
    successful write, so the message says the stored bytes are not active
    rather than claiming nothing was written.
    """
    text = new.decode("utf-8", errors="surrogateescape")
    if _php_const_state(text, _DISALLOW_FILE_EDIT) == "truthy":
        return
    if stored:
        raise SourceError(
            f"{_WP_CONFIG} was written but the stored bytes do not activate "
            f"{_DISALLOW_FILE_EDIT}; restore from the pre-action snapshot"
        )
    raise SourceError(
        f"the proposed {_WP_CONFIG} {how} would not activate "
        f"{_DISALLOW_FILE_EDIT}; nothing was written — add it by hand"
    )


class HardenAction:
    """The plan/apply pair; ``stack`` is the registry-built source trio."""

    def plan(self, ctx: "Ctx", stack: tuple) -> Plan:
        source = stack[0]
        items: list[PlanItem] = []

        # .htaccess — the BEGIN marker absent means the block is not
        # there yet; a MISSING file still plans (creating it is valid).
        htaccess = _read_optional(source, _HTACCESS)
        if htaccess is None:
            items.append(
                PlanItem(
                    category=_CATEGORY, target=_HTACCESS, detail=_HTACCESS_NEW_DETAIL
                )
            )
            log.info("proposed new %s:\n%s", _HTACCESS, _HTACCESS_BLOCK)
        elif not _htaccess_is_hardened(
            htaccess.decode("utf-8", errors="replace")
        ):
            items.append(
                PlanItem(
                    category=_CATEGORY, target=_HTACCESS, detail=_HTACCESS_DETAIL
                )
            )
            log.info("proposed %s block:\n%s", _HTACCESS, _HTACCESS_BLOCK)

        # .htaccess AGAIN — the canonical WordPress permalink block, when
        # pretty permalinks are active and the exact WP marker pair is
        # absent (a fresh file will carry BOTH blocks, ours first).
        if _pretty_permalinks(ctx, stack):
            text = (
                "" if htaccess is None
                else htaccess.decode("utf-8", errors="replace")
            )
            if not _wp_permalink_block_present(text):
                items.append(
                    PlanItem(
                        category=_CATEGORY,
                        target=_HTACCESS,
                        detail=_WP_PERMALINK_DETAIL,
                    )
                )
                log.info(
                    "proposed %s WordPress permalink block:\n%s",
                    _HTACCESS, _WP_PERMALINK_BLOCK,
                )

        # wp-config.php — the audit check's active-truthy rule; a MISSING file
        # has nothing to edit: skip with ONE warning.
        wp_config = _read_optional(source, _WP_CONFIG)
        if wp_config is None:
            log.warning(
                "no %s on the source; nothing to edit for %s",
                _WP_CONFIG,
                _DISALLOW_FILE_EDIT,
            )
        else:
            text = wp_config.decode("utf-8", errors="surrogateescape")
            state = _php_const_state(text, _DISALLOW_FILE_EDIT)
            mods = _php_const_state(text, _DISALLOW_FILE_MODS)
            if state == "truthy" or mods == "truthy":
                pass  # already hardened: nothing to plan
            elif state == "unknown" or mods == "unknown":
                # An APPLICABLE item that apply will refuse. Omitting it would
                # make the plan vacuously complete: rc 0, a cache purge, and a
                # report claiming success for a file nobody hardened.
                items.append(
                    PlanItem(
                        category=_CATEGORY,
                        target=_WP_CONFIG,
                        detail=(
                            f"{_DISALLOW_FILE_EDIT} cannot be resolved "
                            f"statically — needs a human"
                        ),
                    )
                )
                log.warning(
                    "%s/%s in %s cannot be resolved statically; apply will "
                    "refuse and report the item as not applied",
                    _DISALLOW_FILE_EDIT, _DISALLOW_FILE_MODS, _WP_CONFIG,
                )
            elif state in ("absent", "falsey"):
                items.append(
                    PlanItem(
                        category=_CATEGORY, target=_WP_CONFIG, detail=_WP_CONFIG_DETAIL
                    )
                )
                _log_wp_config_proposal(wp_config)

        plan = Plan(items=items, backup_tables=[])
        log.info(
            "plan: %d item(s), %s estimated", len(items), human_bytes(plan.est_bytes())
        )
        return plan

    def apply(self, ctx: "Ctx", stack: tuple, plan: Plan) -> Plan:
        source = stack[0]
        for item in plan.items:
            if not item.requires_apply:
                continue
            try:
                if item.target == _HTACCESS:
                    if item.detail == _WP_PERMALINK_DETAIL:
                        _apply_wp_permalink_block(ctx, stack, source, item)
                    else:
                        _apply_htaccess(source, item)
                elif item.target == _WP_CONFIG:
                    _apply_wp_config(source, item)
                else:
                    log.warning(
                        "skipping harden item with unknown target: %s", item.target
                    )
                    continue
            except (WptError, OSError) as exc:
                log.warning(
                    "could not harden %s (%s: %s); continuing",
                    item.target,
                    type(exc).__name__,
                    exc,
                )
                continue
        return plan


# The registry stores the decorated OBJECT and calls .plan/.apply on it,
# so the registered action is the instance (same as clean_files/clean_db/
# trim_media/optimize_media: a bare class would be invoked with
# plan(ctx, stack) unbound and crash in run_action).
register_action("harden", applies=("ftp", "local"))(HardenAction())
