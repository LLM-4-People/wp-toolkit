"""Source-only dangerous-PHP-pattern check (``security.source_patterns``).

The check answers ONE question without WordPress, a bridge, a database or a
live site: does the SOURCE TREE carry request data flowing into a dangerous
PHP sink?  It reads the walked entries, the content source and the run
deadline only; both source modes (an FTP webroot and an offline zip) feed the
same ``AuditData`` shape through :func:`wpt.audit.data.gather_source`.

Candidate scope (binding):
    * non-directory entries;
    * path NOT under any ``settings.source_scan.ignore_prefixes`` prefix
      (shipped: ``wp-admin/`` and ``wp-includes/`` — WordPress's own code is
      not the application's);
    * suffix in ``settings.web_script.extensions`` (case-insensitive; the
      host decides which suffixes execute, so the shipped list is the common
      superset and ``shell.PHP`` counts);
    * ``size <= settings.source_scan.max_file_bytes``.  The gate runs while
      the candidate list is built, so an oversized file is never fetched.

Reads happen in ``_READ_BATCH`` (200) ``read_many`` batches.  The run
deadline is checked before and after EVERY file (whatever its size) and
after every batch, including the last; on expiry the verified findings so
far are returned with ONE warning, never re-raised.  A per-path read
failure skips that file with one debug line and counts toward the
``_CONSECUTIVE_UNREADABLE`` (25) breaker; on the 25th consecutive failure the
scan stops with ONE warning and returns what it verified.  A ``read_many``
run-level raise propagates (a dead transport is not a dead file).

PHP awareness (binding): the raw text is lexed through
:func:`wpt.audit.security._php_code_flags`; a match is trusted only when it
BEGINS in executable code, so the same call quoted in a comment, a string
literal or a heredoc is data, not a match.  A file whose lexer result is not
lexically valid would not run at all, so its matches are not trusted: it is
skipped whole with one debug line.

Taint heuristic (NOT a parser, deliberately conservative): per file, a
variable is tainted when a simple assignment (``$v = ... $_GET[...]``, also
``.=`` and compound forms) or a ``foreach ($_GET as $k => $v)`` binds it to
request data.  Taint propagates through same-file assignments to a bounded
fixed point, so ``$id = $_GET['id']; $q = "id=$id";`` marks ``$q``.  A
variable is NEVER flagged because its name looks tainted: only the
assignment/foreach evidence above taints it.  The scan sees one file at a
time and does not follow calls, includes or cross-file dataflow.

Detected classes (one aggregate finding per class, same
``category="security.source_patterns"``, distinct ``name``):

``session-fixation`` (high)
    ``session_id(...)`` / ``session_name(...)`` whose argument carries a
    request superglobal or a tainted variable.
``reflected-request`` (medium)
    ``echo`` / ``print`` / ``printf`` / ``die`` / ``exit`` output or ``<?=``
    whose value carries request data, UNLESS the same STATEMENT carries a
    clear escaping/sanitizing call (``htmlspecialchars``, ``htmlentities``,
    ``esc_html``, ``esc_attr``, ``esc_url``, ``wp_kses``, ``sanitize_``,
    ``intval``, ``absint``).  This is a HEURISTIC, not proof of safety: the
    same-statement gate is what keeps ordinary escaped output out of the
    report; a sink may span physical lines.
``sql-injection`` (high)
    ``mysql_query`` / ``mysqli_query`` / ``->query`` / ``->get_results`` /
    ``->get_var`` / ``->get_row`` / ``->get_col`` on a statement carrying
    request data.
    ``->prepare`` is deliberately not a sink, and a sink argument that IS
    a ``prepare(...)`` call suppresses the class (its data is bound).
``sql-identifier`` (high)
    ``FROM`` / ``JOIN`` / ``INTO`` / ``UPDATE`` / ``TABLE`` / ``DESCRIBE``
    / ``SHOW COLUMNS FROM`` followed by a request superglobal or a tainted
    variable in identifier position (documents ``$wpdb`` cannot bind an
    identifier with a placeholder).  The tainted value must complete the
    identifier: a completed static table name followed by a concatenated
    clause (``"SELECT * FROM wp_users" . $where``) is not a dynamic table.
``file-include`` (high)
    ``include`` / ``include_once`` / ``require`` / ``require_once`` whose
    expression carries request data.
``code-execution`` (high)
    ``eval`` / ``assert`` / ``system`` / ``exec`` / ``shell_exec`` /
    ``passthru`` / ``popen`` / ``proc_open`` called with request data.
``unserialize-request`` (high)
    ``unserialize(...)`` called with request data.

Each finding has ``count`` = number of matches, ``bytes`` = 0, and a detail
block of up to ``settings.source_scan.detail_limit`` ``path:line sink``
lines in deterministic (path, line, match) order with the house
``(+N more)`` marker.  The fix names the generic root-cause repair, never a
site-specific value.  Log lines carry paths, counts and line numbers only,
never matched source text.  A run that cannot measure (no source) or has no
candidates is silent with a debug line — never a clean-pass claim.
"""

from __future__ import annotations

import re
from bisect import bisect_left, bisect_right
from collections import deque
from collections.abc import Iterable, Iterator

from .data import AuditData
from .registry import register_check
from ..deadline import Deadline
from ..log import get_logger
from ..settings import Settings
from ..types import DeadlineExceeded, Entry, Finding
from .suspicious import _line_starts
from .security import (_php_backtick_end, _php_heredoc_end, _php_lex,
                       _php_member_before, _php_string_end,
                       web_script_extensions)

log = get_logger("audit.source_scan")

__all__ = ["check_security_source_patterns"]

#: read_many batch size — structural, not a tunable (same bound and
#: rationale as the suspicious-content scan): amortizes per-file round-trips
#: while bounding dead-channel waste, deadline overshoot and resident bytes
#: (<= 200 x source_scan.max_file_bytes).
_READ_BATCH = 200

#: Consecutive unreadable files that abort the scan.  Structural, not a
#: tunable — the same circuit-breaker contract as core.integrity and the
#: suspicious-content scan: a stale FTP channel must cost one batch, not days.
_CONSECUTIVE_UNREADABLE = 25

#: The request superglobals whose data is attacker-controlled.  ``_FILES``
#: carries the attacker's uploaded filename/type/tmp_name; ``_SERVER`` is
#: filtered separately (only its HTTP_* header keys, REQUEST_URI and
#: QUERY_STRING are request data — REMOTE_ADDR and friends are not).
_SUPERGLOBALS = frozenset({"_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES"})
_REQUEST_RE = re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b")
#: PHP whitespace between tokens: real spaces/newlines AND comments.  A
#: comment is whitespace to the parser, so ``$_SERVER/*x*/['HTTP_HOST']``
#: reads the same header as the spaced spelling.
_PHP_WS = r"(?:\s|/\*[\s\S]*?\*/|//[^\r\n]*(?:\r\n|\r|\n|$)|\#[^\r\n]*(?:\r\n|\r|\n|$))*"
#: The same PHP whitespace/comments as a LEADING prefix (braced shorthand).
_PHP_LEAD_WS_RE = re.compile(r"^" + _PHP_WS)
#: The same whitespace/comments at an ARBITRARY offset (``re.match`` with a
#: ``pos`` argument ignores ``^``, so the leading-prefix owner cannot be
#: reused after a closing brace).
_PHP_WS_RE = re.compile(_PHP_WS)
#: ``$_SERVER`` starts an accessor whose KEY must be decoded before the
#: membership test: PHP evaluates ``$_SERVER["HTTP\x5fHOST"]`` exactly like
#: ``$_SERVER['HTTP_HOST']``, while a raw-regex test compared the escape
#: text and called the request read inert.  The parser below
#: (:func:`_server_request_span`) is the ONE owner of that decision.
_SERVER_START_RE = re.compile(r"(?:\$\{|\$)_SERVER")
_SERVER_REQUEST_KEY_RE = re.compile(
    r"(?:HTTP_[A-Za-z0-9_]+|REQUEST_URI|QUERY_STRING)", re.IGNORECASE
)
_VAR_RE = re.compile(r"\$([A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*)")
#: ``${name}`` / ``${name['key']}`` are the same variable as ``$name`` in an
#: interpolating string; ``\$`` is a literal dollar even there.  Both are
#: normalized in the same-length request view so taint cannot hide behind
#: either spelling.
_NAME_RE = re.compile(r"[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*")
_ESCAPED_DOLLAR_RE = re.compile(r"(?<!\\)(?:\\\\)*\\\$")

#: A simple assignment target.  Compound assignment is included because
#: ``$sql .= $_GET['x']`` taints exactly like ``=``; ``==``/``=>`` are not
#: assignments and are rejected by the negative look-ahead.  An indexed or
#: property LVALUE (``$data['q'] =``, ``$o->q =``) taints its BASE variable:
#: the value reached request data and later reads of any accessor path must
#: see it (SCAN2).  PHP's braced spelling ``${'name'}`` / ``${"name"}`` is
#: the SAME variable as ``$name`` (PHP 8.4 executes ``${'t'} = ...``), so
#: it is an assignment target too — the scanner only accepted the plain
#: dollar form and missed the taint entirely.
_ASSIGN_RE = re.compile(
    r"(?:\$(?P<name>[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*)"
    r"|\$\{" + _PHP_WS + r"(?:'(?P<braced_s>(?:[^'\\]|\\.)*)'"
    r"|\"(?P<braced_d>(?:[^\"\\]|\\.)*)\""
    r"|\$(?P<braced_var>[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*))"
    + _PHP_WS + r"\})"
    r"(?:\s*(?:\[[^\[\]\r\n]*\]"
    r"|(?:\?->|->)\s*[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*))*"
    r"\s*(?:\.|\+|-|\*|/|%|\?\?)?=(?![=>])"
)
_FOREACH_RE = re.compile(r"(?i)\bforeach\s*\(")

_SESSION_RE = re.compile(r"(?i)\b(session_id|session_name)\s*\(")
_OUTPUT_RE = re.compile(r"(?i)<\?=|\b(?:echo|print|printf|die|exit)\b")
#: Function sinks are name-based; method sinks are the ``->``/``::`` form.
#: ``exec`` is PDO's own execution verb (``$pdo->exec(...)``) — omitting it
#: left request data reaching the database with no finding.  Kept in ONE
#: pattern so a line with both reports both matches (count = matches).
_SQL_SINKS_RE = re.compile(
    r"(?i)\b(?:mysql_query|mysqli_query)\s*\("
    r"|(?:->|::)\s*(?:query|exec|get_results|get_var|get_row|get_col)\s*\("
)
#: ``SHOW COLUMNS FROM`` first: the alternation consumes the whole phrase so
#: its ``FROM`` is not counted a second time.
_SQL_IDENTIFIER_RE = re.compile(
    r"(?i)\b(?:SHOW\s+COLUMNS\s+FROM|DESCRIBE|FROM|JOIN|INTO|UPDATE|TABLE)\b"
)
#: DDL/DML modifier phrases between the keyword and the identifier:
#: ``CREATE TABLE IF NOT EXISTS $t``, ``DROP TABLE IF EXISTS $t``,
#: ``UPDATE LOW_PRIORITY $t``.  They are grammar, not the identifier.
_SQL_IDENTIFIER_MODIFIERS_RE = re.compile(
    r"(?i)(?:IF\s+(?:NOT\s+)?EXISTS|LOW_PRIORITY|HIGH_PRIORITY|DELAYED|"
    r"IGNORE|QUICK|CONCURRENTLY)\b\s*"
)
#: A live string that names a SQL statement.  Used only to keep a bare
#: double-quoted ``"FROM $id"`` doc string from becoming an identifier
#: finding when no SQL sink is on the line.  The check remains a heuristic.
#: ``UPDATE`` is deliberately NOT a bare context word: prose such as
#: ``echo 'Please update ' . $_GET['n']`` used the word itself as proof of
#: a query and raised a HIGH sql-identifier finding (R11-P2-3).  A real
#: UPDATE statement is recognised by its grammar (update target + SET).
_SQL_CONTEXT_RE = re.compile(
    r"(?i)\b(?:SELECT|INSERT|DELETE|REPLACE|SHOW|DESCRIBE|EXPLAIN|"
    r"DROP|ALTER|TRUNCATE|CREATE|RENAME)\b"
)
_UPDATE_STATEMENT_RE = re.compile(
    r"(?i)\bUPDATE\b"
    r"(?:\s+(?:LOW_PRIORITY|HIGH_PRIORITY|DELAYED|IGNORE)\b)*"
    r"\s+[^\s;]+\s+SET\b"
)
#: A literal that ENDS exactly at the UPDATE target (``"UPDATE wp_"``)
#: continues into a concatenated identifier; it is an incomplete statement,
#: not prose (``"Update $t failed"`` carries trailing words and stays out).
_UPDATE_OPEN_RE = re.compile(
    r"(?is)^UPDATE\b(?:\s+(?:LOW_PRIORITY|HIGH_PRIORITY|DELAYED|IGNORE))*"
    r"\s+(?!\$)\S+\s*$"
)
#: A literal that ENDS at the UPDATE keyword itself (``"UPDATE "``): the
#: dynamic target and the SET clause follow in a concatenation.  Accepted
#: only when the continuation really carries ``SET`` (see
#: :func:`_sql_split_prefix_continues`), so prose ``"Update " . $n`` is
#: not a statement.
_UPDATE_PREFIX_RE = re.compile(
    r"(?is)^UPDATE\b(?:\s+(?:LOW_PRIORITY|HIGH_PRIORITY|DELAYED|IGNORE))*"
    r"\s*$"
)
#: A SELECT statement needs SQL-shaped grammar: a select LIST followed by
#: FROM.  ``"Select a file from $d"`` is English prose whose first word
#: happens to be SELECT; a real single-column list (``SELECT id FROM``)
#: still matches, while two bare prose words separated by a space do not.
_SELECT_TOKEN = (
    r"(?:\*|`[^`]*`|'(?:[^'\\]|\\.)*'|\d+(?:\.\d+)?|"
    r"[A-Za-z_][\w$]*(?:\.[A-Za-z_*][\w$]*)*|"
    r"[A-Za-z_]\w*\s*\([^)]*\))"
)
#: One select-list expression: a column/function literal, optionally with a
#: window clause (``ROW_NUMBER() OVER (PARTITION BY id)``), or a standard
#: ``CASE ... END`` expression.  Both execute in MySQL and SQLite and both
#: sit between SELECT and FROM, so the old token-only list treated a real
#: query as prose and lost the identifier finding.
_SELECT_EXPR = (
    r"(?:"
    + _SELECT_TOKEN
    # ``OVER (window)`` and the SQL standard's named window ``OVER w``
    # both execute; accepting only the parenthesized form classified
    # ``SELECT ROW_NUMBER() OVER w FROM $t`` as prose.
    + r"(?:\s+OVER\s*(?:\([^)]*\)|[A-Za-z_]\w*))?"
    # A per-column alias is part of the SELECT LIST, not a suffix of the
    # whole list: ``SELECT a AS x, b AS y FROM t`` is valid SQL and was
    # rejected because only the last expression could carry ``AS``.
    + r"(?:\s+AS\s+[A-Za-z_]\w*)?"
    r"|CASE\b(?:(?!\bEND\b).)*?\bEND\b"
    r"(?:\s+AS\s+[A-Za-z_]\w*)?"
    r")"
)
_SELECT_STATEMENT_RE = re.compile(
    r"(?is)^SELECT\b(?:\s+(?:DISTINCT|ALL|SQL_CALC_FOUND_ROWS|"
    r"SQL_NO_CACHE|SQL_CACHE|STRAIGHT_JOIN))*\s+"
    + _SELECT_EXPR
    + r"(?:\s*,\s*" + _SELECT_EXPR + r")*"
    r"(?:\s|\\)+FROM\b"
)
#: A literal's SQL context is real only when its statement-initial token
#: (after the last ``;``) is a SQL verb.  Free text such as
#: ``"Please select a file from $d"`` names FROM/SELECT words but is not a
#: query; this anchored check keeps that prose silent while every real
#: ``SELECT/INSERT/DELETE/UPDATE ... FROM/INTO`` still reports.  SELECT is
#: checked by :data:`_SELECT_STATEMENT_RE` (its select list must be shaped
#: like SQL, not prose).
_SQL_STATEMENT_START_RE = re.compile(
    r"(?i)^(?:REPLACE|CREATE|DROP|ALTER|TRUNCATE|RENAME|SHOW|"
    r"DESCRIBE|EXPLAIN)\b"
)
#: A real CTE: ``WITH [RECURSIVE] name [(cols)] AS (``.  A bare leading
#: ``WITH`` was accepted as SQL, so English prose ``With the update ...``
#: minted a HIGH sql-identifier finding (R16 residual).  The ``AS (`` is
#: the grammar that separates the two.
#: The SQL grammar window: a statement-start check only reads the prefix
#: that can hold its first tokens.  Normalizing a 500 KiB literal tail per
#: keyword was quadratic (SCAN-QUAD) while the grammar decision is unchanged.
_SQL_GRAMMAR_WINDOW = 8192
_WITH_CTE_RE = re.compile(
    r"(?is)^WITH\s+(?:RECURSIVE\s+)?"
    r"(?:`[^`]+`|[A-Za-z_\x80-\xff][A-Za-z0-9_$\x80-\xff]*)\s*"
    r"(?:\([^)]*\))?\s+AS\s*\("
)
#: INSERT's own grammar: the target is followed by a column list, VALUES,
#: SET or a SELECT.  ``Insert into $t failed`` is prose, not a statement.
_INSERT_STATEMENT_RE = re.compile(
    r"(?is)^INSERT\b(?:\s+(?:LOW_PRIORITY|HIGH_PRIORITY|DELAYED|IGNORE))*"
    r"\s+(?:INTO\s+)?\S+\s*(?:\(|VALUES\b|SET\b|SELECT\b)"
)
#: A literal that ENDS exactly at INSERT's grammar prefix (``"INSERT "``,
#: ``"INSERT INTO "``) continues into a concatenated target; it is an
#: incomplete statement, not prose (``"Insert into $t failed"`` carries a
#: target and trailing words).  Mirrors :data:`_UPDATE_OPEN_RE`.
_INSERT_OPEN_RE = re.compile(
    r"(?is)^INSERT\b(?:\s+(?:LOW_PRIORITY|HIGH_PRIORITY|DELAYED|IGNORE))*"
    r"\s*(?:INTO\s*)?$"
)
#: A literal that ENDS at a PARTIAL INSERT target (``"INSERT INTO wp_"``)
#: continues into the identifier exactly like the UPDATE twin; accepted only
#: when the concatenation carries INSERT grammar (VALUES/SET/SELECT) so
#: ``"Insert into wp_" . $n . " failed"`` stays prose.
_INSERT_TARGET_OPEN_RE = re.compile(
    r"(?is)^INSERT\b(?:\s+(?:LOW_PRIORITY|HIGH_PRIORITY|DELAYED|IGNORE))*"
    r"\s+(?:INTO\s+)?(?!\$)\S+\s*$"
)
#: DELETE needs its FROM clause plus a query clause or the literal's END:
#: ``Delete from $t failed`` is prose; ``DELETE FROM $t WHERE ...`` and
#: ``DELETE FROM $t`` are statements.
_DELETE_STATEMENT_RE = re.compile(
    r"(?is)^DELETE\b(?:\s+(?:LOW_PRIORITY|QUICK|IGNORE))*\s+FROM\s+\S+"
    r"(?:\s+(?:WHERE|ORDER|LIMIT|USING)\b|[\s;)]*$)"
)
#: A literal ending at DELETE's FROM clause (``'DELETE FROM '``) continues
#: into a concatenated target; incomplete, but real SQL.
_DELETE_OPEN_RE = re.compile(
    r"(?is)^DELETE\b(?:\s+(?:LOW_PRIORITY|QUICK|IGNORE))*\s+FROM\s*$"
)


def _sql_line_end(text: str, start: int, limit: int | None = None) -> int:
    """Offset of the first CR or LF at/after ``start`` (or the limit).

    MySQL line comments and heredoc headers end at EITHER line terminator;
    a CR-only file was read as one endless comment (R14-P2).  ``limit``
    bounds each search so a missing terminator scans only the caller's span.
    """
    end = len(text) if limit is None else min(limit, len(text))
    stop = end
    for terminator in ("\n", "\r"):
        found = text.find(terminator, start, stop)
        if found != -1 and found < stop:
            stop = found
    return stop


def _sql_comment_end(text: str, index: int) -> int | None:
    """End offset (exclusive) of a MySQL comment starting at ``index``.

    ONE owner for the comment lexical rule shared by the statement-prefix
    stripper, the same-length space view and the bounded grammar view:
    ``/* ... */`` (unterminated runs to the end), ``--`` only when followed
    by whitespace/end (MySQL's own rule), and ``#`` except ``#[``.  A line
    comment stops AT the line terminator (the caller keeps/skips it); the
    returned offset is always greater than ``index`` for a real comment, so
    every caller advances.
    """
    if index >= len(text):
        return None
    if text.startswith("/*", index):
        close = text.find("*/", index + 2)
        return len(text) if close == -1 else close + 2
    if text.startswith("--", index) and (
            index + 2 >= len(text) or text[index + 2] in " \t\r\n"):
        return _sql_line_end(text, index)
    if text[index] == "#" and not text.startswith("#[", index):
        return _sql_line_end(text, index)
    return None


def _strip_sql_statement_prefix(text: str) -> str:
    """Drop leading whitespace, SQL comments and opening parentheses.

    Valid MySQL may wrap a statement (``"(SELECT ...)"``), prefix it with
    a comment (``"/* hi */ SELECT ..."``), or spell a CTE (``WITH ...``).
    The statement-start test must see the first real token, not the
    wrapper; ``--`` comments need the same trailing-whitespace rule as
    every other SQL view (see :func:`_sql_comment_end`).
    """
    index = 0
    length = len(text)
    while index < length:
        while index < length and text[index].isspace():
            index += 1
        if index >= length:
            break
        stop = _sql_comment_end(text, index)
        if stop is not None:
            index = stop
            continue
        if text[index] == "(":
            index += 1
            continue
        break
    return text[index:]


def _sql_comment_space(text: str) -> str:
    """A same-length view with MySQL comments replaced by spaces.

    SQL comments are whitespace to the parser, so ``UPDATE/*c*/wp_users
    SET`` is the same statement as the spaced spelling, and a commented
    ``FROM x`` is not a live clause.  Offsets stay stable because one
    comment character maps to one space (newlines are preserved).  The
    comment spans come from :func:`_sql_comment_end`, the one lexical
    owner.
    """
    if not text:
        return text
    out = list(text)
    index = 0
    length = len(text)
    while index < length:
        stop = _sql_comment_end(text, index)
        if stop is None:
            index += 1
            continue
        for pos in range(index, stop):
            if out[pos] not in "\r\n":
                out[pos] = " "
        index = stop
    return "".join(out)


def _sql_grammar_view(text: str,
                      limit: int | None = _SQL_GRAMMAR_WINDOW) -> str:
    """A view for the statement-start grammar.

    Comments are whitespace to MySQL, so a long comment must not consume
    the window: collapsing the comment FIRST made the following
    ``* FROM $t`` invisible when the comment crossed the byte limit
    (``SELECT /* 20 KiB */ * FROM $t`` lost its SELECT grammar).  This
    view charges only NON-comment characters toward ``limit`` and emits one
    space per comment, so the real tokens after an arbitrarily long comment
    are still seen while the scan stays linear.

    ``limit=None`` renders the WHOLE statement.  A fixed 8192-byte cut
    silently dropped a real SELECT whose column list was longer than the
    window (the FROM clause lived past the cut); :func:`_sql_statement_context`
    uses the bounded view first and only falls back to the full one when the
    candidate is long enough that the decision could have been truncated.
    """
    out: list[str] = []
    index = 0
    length = len(text)
    while index < length and (limit is None or len(out) < limit):
        stop = _sql_comment_end(text, index)
        if stop is not None:
            index = stop
            out.append(" ")
            continue
        out.append(text[index])
        index += 1
    return "".join(out)


def _sql_quoted_end(text: str, index: int) -> int:
    """End offset (exclusive) of the SQL quoted token at ``index``.

    Handles backslash escapes and doubled quotes, so a parenthesis/CASE
    word inside a string can never steer the nesting scan.  An unterminated
    quote runs to the end (fail closed).
    """
    quote = text[index]
    cursor = index + 1
    length = len(text)
    while cursor < length:
        if text[cursor] == "\\":
            cursor += 2
            continue
        if text[cursor] == quote:
            if cursor + 1 < length and text[cursor + 1] == quote:
                cursor += 2
                continue
            return cursor + 1
        cursor += 1
    return length


def _sql_case_end(text: str, index: int) -> int | None:
    """Exclusive end of the ``CASE ... END`` at ``index`` (nested aware)."""
    cursor = index + 4
    depth = 1
    length = len(text)
    while cursor < length:
        char = text[cursor]
        if char in "'\"`":
            cursor = _sql_quoted_end(text, cursor)
            continue
        if char.isalpha() or char == "_":
            end = cursor + 1
            while end < length and (text[end].isalnum() or text[end] == "_"):
                end += 1
            word = text[cursor:end].upper()
            if word == "CASE":
                depth += 1
            elif word == "END":
                depth -= 1
                if depth == 0:
                    return end
            cursor = end
            continue
        cursor += 1
    return None


def _collapse_sql_nested(text: str) -> str:
    """Collapse balanced ``(...)`` and ``CASE ... END`` to one token.

    The select-list grammar must accept a nested subquery
    (``SELECT (SELECT COUNT(*) FROM x) AS c FROM t``) and a nested CASE
    expression, while still rejecting English prose.  Collapsing each
    balanced expression to ``x`` keeps a function call as ``name(x)`` (the
    token grammar) and leaves the surrounding words intact, so the existing
    prose guard still decides on the same statement shapes.
    """
    out: list[str] = []
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char in "'\"`":
            end = _sql_quoted_end(text, index)
            out.append(text[index:end])
            index = end
            continue
        if char == "(":
            depth = 1
            cursor = index + 1
            while cursor < length and depth:
                inner = text[cursor]
                if inner in "'\"`":
                    cursor = _sql_quoted_end(text, cursor)
                    continue
                if inner == "(":
                    depth += 1
                elif inner == ")":
                    depth -= 1
                cursor += 1
            if depth:
                out.append(text[index:])
                break
            previous = out[-1][-1] if out and out[-1] else ""
            inner = text[index + 1:cursor - 1].lstrip()
            if previous.isalnum() or previous == "_":
                out.append("(x)")
            elif re.match(r"(?is)^\(*\s*SELECT\b", inner):
                # A nested subquery is one select-list expression.
                out.append("x")
            else:
                # A plain parenthesized prose/arithmetic group stays as it
                # was, so the existing prose guard still rejects it.
                out.append(text[index:cursor])
            index = cursor
            continue
        if char.isalpha() or char == "_":
            end = index + 1
            while end < length and (text[end].isalnum() or text[end] == "_"):
                end += 1
            word = text[index:end]
            if word.upper() == "CASE":
                case_end = _sql_case_end(text, index)
                if case_end is not None:
                    out.append("x")
                    index = case_end
                    continue
            out.append(word)
            index = end
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _sql_context_matches(candidate: str) -> bool:
    """Does one normalized statement view begin with real SQL grammar?"""
    if _SELECT_STATEMENT_RE.match(candidate):
        return True
    # Nested CASE/subquery select lists: collapse the balanced expressions
    # only for the SELECT grammar (the other verbs do not need it).
    collapsed = _collapse_sql_nested(candidate)
    if collapsed != candidate and _SELECT_STATEMENT_RE.match(collapsed):
        return True
    if _WITH_CTE_RE.match(candidate):
        return True
    if _SQL_STATEMENT_START_RE.match(candidate):
        return True
    if _UPDATE_STATEMENT_RE.match(candidate):
        return True
    if _UPDATE_OPEN_RE.match(candidate):
        return True
    if _INSERT_STATEMENT_RE.match(candidate):
        return True
    if _INSERT_OPEN_RE.match(candidate):
        return True
    if _DELETE_OPEN_RE.match(candidate):
        return True
    return _DELETE_STATEMENT_RE.match(candidate) is not None


def _sql_statement_context(text: str) -> bool:
    """True when ``text`` begins (after wrappers) with real SQL grammar."""
    candidate = _strip_sql_statement_prefix(text)
    if _sql_context_matches(_sql_grammar_view(candidate)):
        return True
    if len(candidate) <= _SQL_GRAMMAR_WINDOW:
        return False
    # The bounded view ended before a long statement's deciding token (a
    # 3,000-column SELECT list pushed FROM past 8192 bytes).  Scan the
    # whole statement ONCE; callers cache the answer per statement.
    return _sql_context_matches(_sql_grammar_view(candidate, limit=None))


def _sql_literal_body_start(mask: str, literal: tuple[int, int, str]) -> int:
    """The first offset of a literal's SQL BODY.

    A quoted literal starts after its opening quote; a heredoc/nowdoc body
    starts after the ``<<<LABEL\\n`` header (including a CR-only line end).
    ONE owner for the prefix arithmetic the UPDATE gate and the
    statement-context check share.
    """
    open_, close, _quote = literal
    if not mask.startswith("<<<", open_):
        return open_ + 1
    newline = _sql_line_end(mask, open_, close)
    return newline + 1 if newline < close else close


def _sql_split_prefix_continues(mask: str, literal: tuple[int, int],
                                verb: str) -> bool:
    """Does a literal ending AT a SQL verb continue into its own grammar?

    ``$q = "UPDATE " . $table . " SET x=$v"`` splits the statement across
    three literals.  The literal alone is only the verb, and the identifier
    detector needs the grammar that follows in the CONCATENATION: a ``.``
    continuation plus UPDATE's ``SET`` clause.  Prose ``"Update " . $n``
    has no SET and stays silent.  Bounded by the grammar window; one owner
    for the continuation question.
    """
    start = literal[1]
    end = min(len(mask), start + _SQL_GRAMMAR_WINDOW)
    statement_end = mask.find(";", start, end)
    if statement_end != -1:
        end = statement_end
    tail = mask[start:end]
    if re.match(r"\s*\.", tail) is None:
        return False
    if verb.upper() == "UPDATE":
        return re.search(r"(?i)\sSET\b", tail) is not None
    if verb.upper() == "INSERT":
        return re.search(r"(?i)\s(?:VALUES|SET|SELECT|WHERE|ORDER|LIMIT)\b",
                         tail) is not None
    if verb.upper() == "DELETE":
        return re.search(r"(?i)\s(?:WHERE|ORDER|LIMIT|USING)\b",
                         tail) is not None
    return False


def _sql_literal_statement_context(
    mask: str, literal: tuple[int, int],
    keyword_start: int,
    cache: dict[tuple[int, int], bool] | None = None,
) -> bool:
    """True when the literal's current statement STARTS with a SQL verb.

    ``mask`` is the SQL-text view, ``literal`` its enclosing literal span
    (start offset is the opening quote), and ``keyword_start`` the FROM/
    INTO/UPDATE/TABLE token being evaluated.  The prefix after the last
    ``;`` is combined with the keyword itself so ``UPDATE $t SET`` (whose
    keyword starts the statement) and ``SELECT * FROM $t`` both qualify,
    while prose before the keyword (``"Please select a file from"``) does
    not.

    ``cache`` is keyed by the literal and its statement start: the answer is
    identical for every keyword of one statement, so a dense SQL literal
    does not re-render/re-match the same (possibly long) statement once per
    keyword.
    """
    body_start = _sql_literal_body_start(mask, literal)
    semicolon = mask.rfind(";", body_start, keyword_start)
    statement_start = body_start if semicolon == -1 else semicolon + 1
    key = (literal[0], statement_start)
    if cache is not None and key in cache:
        return cache[key]
    prefix = mask[statement_start:keyword_start]
    # Only the CURRENT statement decides the grammar.  Reading through the
    # rest of a long literal made a dense SQL literal re-scan O(n) tails per
    # keyword (quadratic); a top-level ``;`` ends the statement.
    statement_end = mask.find(";", keyword_start, literal[1])
    if statement_end == -1:
        statement_end = literal[1]
    tail = mask[keyword_start:statement_end]
    if not mask.startswith("<<<", literal[0]) \
            and tail.endswith(mask[literal[0]]):
        # A normal quoted literal's span includes its closing quote: the
        # statement grammar must read the SQL TEXT, not that PHP delimiter
        # (``'INSERT INTO '`` ends after ``INTO ``, not ``INTO '``).
        tail = tail[:-1]
    inside = prefix + tail
    # SQL comments are whitespace: ``INSERT/*c*/ INTO wp_`` and
    # ``INSERT INTO/*c*/ wp_`` name the same partial target as the spaced
    # spelling.  The grammar regexes read the comment-collapsed view (the
    # prose guards below stay intact: a comment alone is not a clause).
    stripped_inside = _sql_comment_space(
        _strip_sql_statement_prefix(inside))
    if _UPDATE_OPEN_RE.match(stripped_inside):
        # The literal ENDS at the UPDATE target and a concatenated
        # identifier follows — an incomplete statement, still SQL.
        result = True
    elif (_UPDATE_PREFIX_RE.match(stripped_inside)
          and _sql_split_prefix_continues(mask, literal, "UPDATE")):
        # The literal ends at the verb itself; the dynamic target and SET
        # follow in the concatenation.
        result = True
    elif _INSERT_OPEN_RE.match(stripped_inside):
        # ``"INSERT INTO "`` alone is a split prefix, not a statement:
        # only a continuation with INSERT's own grammar (VALUES/SET/SELECT,
        # or a WHERE-shaped split the existing split tests use) proves it.
        # Prose ``"Insert into " . $n . " failed"`` stays silent.
        result = _sql_split_prefix_continues(mask, literal, "INSERT")
    elif _INSERT_TARGET_OPEN_RE.match(stripped_inside):
        # The literal ends at a PARTIAL target (``"INSERT INTO wp_"``):
        # the concatenated identifier completes it.  Same grammar
        # requirement as the verb-only prefix, so prose stays silent.
        result = _sql_split_prefix_continues(mask, literal, "INSERT")
    elif _DELETE_OPEN_RE.match(stripped_inside):
        result = _sql_split_prefix_continues(mask, literal, "DELETE")
    else:
        result = _sql_statement_context(inside)
    if cache is not None:
        cache[key] = result
    return result
_INCLUDE_RE = re.compile(
    r"(?i)\b(?:include|include_once|require|require_once)\b"
)
_CODE_EXEC_RE = re.compile(
    r"(?i)\b(?:eval|assert|system|exec|shell_exec|passthru|popen|"
    r"proc_open)\s*\("
)
_UNSERIALIZE_RE = re.compile(r"(?i)\bunserialize\s*\(")
#: The recommended parameterized form at the START of a sink argument.
#: Static/member calls accept BOTH `->` and `::` (`parent::prepare(...)` is
#: the same bound pattern PHP accepts).
_PREPARE_AT_RE = re.compile(
    r"(?i)\s*(?:(?:\$[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*"
    r"|\\?[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff\\]*)"
    r"\s*(?:->|\?->|::)\s*)*prepare\s*\("
)
#: The bare ``prepare(`` token used to FIND the call anywhere in an
#: expression; ``_PREPARE_AT_RE`` then parses the receiver chain at that
#: position.  Kept separate so a wrapper such as ``apply_filters("q",
#: $wpdb->prepare(...))`` is recognized on the RHS (R6-18).
_PREPARE_CALL_RE = re.compile(r"(?i)\bprepare\s*\(")
#: A clear same-line escaping/sanitizing call.  PHP function names are
#: case-insensitive; ``wp_kses``/``sanitize_`` are prefixes because the
#: context-specific variants (``wp_kses_post``, ``sanitize_text_field``)
#: carry the family name.
_SANITIZER_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])(?:htmlspecialchars|htmlentities|esc_html|"
    r"esc_attr|esc_url|wp_kses\w*|sanitize_\w*|intval|absint)\s*\("
)

#: The SQL identifier expression is parsed from raw text by
#: :func:`_identifier_expression_request`; SQL whitespace/punctuation ends
#: it, while PHP string segments and concatenation keep it open.

_SESSION_FIX = (
    "Remove request-driven session IDs: generate the session identifier "
    "server-side and never accept session_id()/session_name() arguments "
    "from $_GET/$_POST/$_REQUEST/$_COOKIE."
)
_REFLECTED_FIX = (
    "Escape output at the point of rendering with the context-appropriate "
    "escaper (esc_html/esc_attr/esc_url or htmlspecialchars; wp_kses for "
    "allowed HTML). This check is a line-level heuristic, not proof: a "
    "same-line sanitizer suppresses it, so review each match."
)
_SQL_INJECTION_FIX = (
    "Parameterize the query (prepared statements / $wpdb->prepare with "
    "placeholders) and never concatenate request data into SQL."
)
_SQL_IDENTIFIER_FIX = (
    "Validate table/column identifiers against a strict allowlist; "
    "placeholders bind VALUES, not identifiers, so request data must never "
    "select a table, column or direction."
)
_INCLUDE_FIX = (
    "Allowlist includable paths (or map a fixed key to a fixed file) and "
    "never build an include/require path from request data."
)
_CODE_EXEC_FIX = (
    "Remove request-driven code execution: never pass request data to "
    "eval/assert/system/exec/shell_exec/passthru/popen/proc_open."
)
_UNSERIALIZE_FIX = (
    "Do not unserialize request data: use JSON (json_decode) with an "
    "explicit schema, or an allowlist of classes via allowed_classes."
)

#: (name, risk, fix) in the contract's class order.
_CLASSES: tuple[tuple[str, str, str], ...] = (
    ("session-fixation", "high", _SESSION_FIX),
    ("reflected-request", "medium", _REFLECTED_FIX),
    ("sql-injection", "high", _SQL_INJECTION_FIX),
    ("sql-identifier", "high", _SQL_IDENTIFIER_FIX),
    ("file-include", "high", _INCLUDE_FIX),
    ("code-execution", "high", _CODE_EXEC_FIX),
    ("unserialize-request", "high", _UNSERIALIZE_FIX),
)

_CATEGORY = "security.source_patterns"


# --------------------------------------------------------------- helpers


def _is_candidate(entry: Entry, settings: Settings) -> bool:
    """A non-directory, in-scope, executable-extension file within the size cap."""
    if entry.is_dir:
        return False
    path = entry.path
    for prefix in settings.source_scan.ignore_prefixes:
        if isinstance(prefix, str) and prefix and path.startswith(prefix):
            return False
    lowered = path.lower()
    # ONE normalizer for the extension set: a padded/dotless profile value
    # was accepted here but normalized by security.web_script_extensions, so
    # a session-fixation file could scan clean with rc 0 (R6-19).
    if not any(lowered.endswith(ext) for ext in web_script_extensions(settings)):
        return False
    return entry.size <= settings.source_scan.max_file_bytes


def _candidates(entries: Iterable[Entry], settings: Settings) -> list[Entry]:
    """The scan set, path-sorted for deterministic batch and report order."""
    return sorted(
        (entry for entry in entries if _is_candidate(entry, settings)),
        key=lambda entry: entry.path,
    )


def _line_at(starts: list[int], position: int) -> int:
    """The 1-based line number containing ``position``."""
    return bisect_right(starts, position)


def _php_comment_stop(text: str, index: int) -> int:
    """Offset where a PHP line comment ends: newline, carriage return, or
    the ``?>`` tag.

    A ``//``/``#`` comment ends PHP mode at ``?>``; skipping to the newline
    swallowed a same-line later ``<?php`` block in the whole-file SQL/
    literal views (R6-14).  PHP also accepts a bare ``\r`` as a line end,
    so a CR-only file must not hide every later sink in the "comment"
    (P2-SCAN-CR).  The ``?>`` search is bounded to the physical line: a
    whole-file ``find`` from every comment was O(n²) (P2-SCAN-QUAD).
    """
    line_end = len(text)
    for stop in ("\n", "\r"):
        # Bound each search to the line found so far: the second search must
        # not re-scan the rest of the file for every comment.
        position = text.find(stop, index, line_end)
        if position != -1:
            line_end = position
    close_tag = text.find("?>", index, line_end)
    if close_tag != -1:
        return min(line_end, close_tag)
    return line_end


def _statement_end(text: str, start: int,
                   php_mask: bytearray | None = None) -> int:
    """Offset of the statement's ``;``/``?>`` from ``start`` (or EOF).

    Strings and comments are skipped so a semicolon inside them cannot cut
    the statement short.  With ``php_mask``, inline HTML ends the statement:
    a semicolon in HTML text is output, not a PHP statement terminator.
    """
    index = start
    length = len(text)
    while index < length:
        if text.startswith("?>", index):
            return index
        if php_mask is not None and not php_mask[index]:
            return index
        char = text[index]
        if text.startswith("<<<", index):
            end, _interpolates = _php_heredoc_end(text, index)
            if end is None:
                return length
            index = end
            continue
        if char in "'\"":
            end = _php_string_end(text, index, interpolation_aware=True)
            if end is None:
                return length
            index = end
            continue
        if char == "`":
            end = _php_backtick_end(text, index)
            if end is None:
                return length
            index = end
            continue
        if text.startswith("//", index) or (
                char == "#" and not text.startswith("#[", index)):
            # PHP ends a line comment AND PHP mode at ``?>``; skipping to
            # the newline let the statement cross into the next ``<?=``
            # block, where a later sanitizer suppressed a real sink.
            stop = _php_comment_stop(text, index)
            if stop < length and text.startswith("?>", stop):
                return stop
            index = length if stop == length else stop + 1
            continue
        if text.startswith("/*", index):
            close = text.find("*/", index + 2)
            index = length if close == -1 else close + 2
            continue
        if char == ";":
            return index
        index += 1
    return length


def _statement_starts(text: str,
                      php_mask: bytearray | None = None) -> list[int]:
    """Offsets where each PHP statement starts (``;``/``?>`` separated).

    Strings, comments and heredocs are skipped by :func:`_statement_end`, so
    a semicolon inside SQL text cannot cut a statement short.  This is the
    whole-file lexing the SQL context needs: a query may span physical
    lines and its ``SELECT`` may sit on the line before ``FROM`` (SCAN3).
    With ``php_mask`` only PHP segments produce statements; each segment's
    end is also a boundary, so a statement can never run into inline HTML.
    """
    if php_mask is None:
        starts = [0]
        index = 0
        length = len(text)
        while index < length:
            index = _statement_end(text, index)
            if index >= length:
                break
            index += 2 if text.startswith("?>", index) else 1
            starts.append(index)
        return starts
    boundaries: set[int] = set()
    length = len(text)
    index = 0
    while index < length:
        if not php_mask[index]:
            index += 1
            continue
        segment_start = index
        boundaries.add(segment_start)
        while index < length and php_mask[index]:
            end = _statement_end(text, index, php_mask)
            if end >= length:
                index = length
                break
            if text.startswith("?>", end):
                boundaries.add(end)
                index = end + 2
                break
            index = end + 1
            boundaries.add(index)
        boundaries.add(index)
    return sorted(boundaries)


def _statement_span(starts: list[int], length: int,
                    position: int) -> tuple[int, int]:
    """(start, end) offsets of the statement containing ``position``.

    A PHP segment with no marked byte (an expression-less ``<?=`` at EOF)
    produces NO starts; indexing ``starts[0]`` then raised IndexError and
    the whole source check was lost as ``audit.check_failed`` (R11-P2-1).
    With no statement a whole-file span is the honest answer, and the
    caller's expression text is empty.
    """
    if not starts:
        return 0, length
    index = bisect_right(starts, position) - 1
    start = starts[max(0, index)]
    end = starts[index + 1] if index + 1 < len(starts) else length
    return start, end


def _braced_end(text: str, start: int, limit: int | None = None) -> int | None:
    """End offset (exclusive) of the PHP ``${...}`` interpolation at ``start``.

    ``start`` points at ``$``.  The closing brace is matched quote-aware so
    ``${_GET['}']}`` closes at the real brace, not the one inside the key.
    Returns None when the opener is unterminated.
    """
    if not text.startswith("${", start):
        return None
    index = start + 2
    end = len(text) if limit is None else min(limit, len(text))
    while index < end:
        char = text[index]
        if char in "'\"`":
            close = _php_string_end(
                text, index, interpolation_aware=char in "\"`")
            if close is None or close > end:
                return None
            index = close
            continue
        if char == "}":
            return index + 1
        index += 1
    return None


def _server_request_span(text: str, start: int) -> tuple[int, int] | None:
    """The span of an EXECUTABLE ``$_SERVER[...]`` request-key read.

    ``(start, end)`` when ``text[start:]`` begins with ``$_SERVER`` (or its
    ``${...}`` spelling) and the subscript decodes to a request key —
    ``HTTP_*``, ``REQUEST_URI`` or ``QUERY_STRING`` — else None.  One owner
    for :func:`_request_name`, the braced classifiers and
    :func:`_request_mask`; the key is decoded with :func:`_php_literal_value`
    so ``"HTTP\x5fHOST"`` is the request header, and ``REMOTE_ADDR`` stays
    inert.
    """
    match = _SERVER_START_RE.match(text, start)
    if match is None:
        return None
    pos = _PHP_WS_RE.match(text, match.end()).end()
    if pos >= len(text) or text[pos] != "[":
        return None
    open_bracket = pos
    key, pos = _server_subscript_key(text, pos + 1, start)
    if key is None:
        return None
    if key == _UNRESOLVED_SERVER_KEY:
        # A subscript the scanner cannot prove (a dynamic variable, a
        # function call): fail CLOSED — it may be HTTP_HOST.
        close = _matching_bracket_end(text, open_bracket, len(text))
        if close is None:
            return None
        return match.start(), close
    pos = _PHP_WS_RE.match(text, pos).end()
    if pos >= len(text) or text[pos] != "]":
        return None
    if not _SERVER_REQUEST_KEY_RE.fullmatch(key):
        return None
    return match.start(), pos + 1


#: Sentinel for a ``$_SERVER[...]`` subscript the scanner cannot resolve
#: statically.  Fail closed: an unresolved key may be a request header.
_UNRESOLVED_SERVER_KEY = "\x00unresolved-server-key\x00"


def _php_double_quoted_interpolates(text: str, open_index: int,
                                    close: int) -> bool:
    """True when a double-quoted literal interpolates (an unescaped ``$``).

    PHP evaluates ``"HTTP_$x"``/``"HTTP_{$x}"``/``"HTTP_${x}"`` at runtime,
    so a scanner that decoded the literal as static missed the header read.
    Escaped dollars (``\\$``) stay literal.
    """
    index = open_index + 1
    while index < close - 1:
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == "$":
            return True
        index += 1
    return False


def _static_php_string(text: str, index: int) -> tuple[str | None, int]:
    """Evaluate a quoted PHP string concatenation (``"HTTP_"."HOST"``).

    Returns ``(value, end)`` for one or more quoted literals joined by
    ``.``; ``(None, index)`` when the expression is not fully static —
    including a double-quoted literal with interpolation, which is request
    data the caller must fail closed on.
    """
    parts: list[str] = []
    pos = index
    length = len(text)
    while pos < length:
        pos = _PHP_WS_RE.match(text, pos).end()
        if pos >= length or text[pos] not in "'\"":
            return None, index
        close = _php_string_end(text, pos)
        if close is None:
            return None, index
        if text[pos] == '"' and _php_double_quoted_interpolates(
                text, pos, close):
            return None, index
        parts.append(_php_literal_value(text[pos:close]))
        pos = close
        after = _PHP_WS_RE.match(text, pos).end()
        if after < length and text[after] == ".":
            pos = after + 1
            continue
        return "".join(parts), pos
    return None, index


def _static_assignment(text: str, name: str, before: int) -> str | None:
    """The statically assigned string value of ``$name`` before ``before``.

    ``$k = "HTTP_HOST"; echo $_SERVER[$k]`` reads the header at runtime.
    Only the LAST assignment before the read is considered; a non-static
    right-hand side returns None (the caller then fails closed).

    The assignment TARGET must be live code: comments are blanked AND
    quoted/heredoc bodies are blanked before the search, so a later
    ``/* $k = "REMOTE_ADDR"; */`` or a string containing that text can
    never shadow the real assignment.  The VALUE is still read from the
    raw text (the static-string parser owns PHP escapes).
    """
    view = _comment_mask(text, blank_literals=True)
    pattern = re.compile(
        r"\$" + re.escape(name) + r"\s*=(?!=)")
    value = None
    for match in pattern.finditer(view, 0, before):
        candidate, _end = _static_php_string(text, match.end())
        value = candidate
    return value


def _server_subscript_key(text: str, index: int,
                          read_start: int) -> tuple[str | None, int]:
    """Decode one ``$_SERVER[...]`` subscript: literal, concat, or ``$var``.

    A quoted literal/concat is decoded with PHP escape semantics; a
    statically assigned scalar variable is resolved; anything else is
    returned as :data:`_UNRESOLVED_SERVER_KEY` so the caller fails closed.
    """
    pos = _PHP_WS_RE.match(text, index).end()
    if pos < len(text) and text[pos] in "'\"":
        value, end = _static_php_string(text, pos)
        if value is None:
            # A concat with a variable/call is not statically resolvable:
            # fail closed (it may still produce a request header name).
            return _UNRESOLVED_SERVER_KEY, end
        return value, end
    if text.startswith("$", pos):
        match = _VAR_RE.match(text, pos)
        if match is None:
            return None, pos
        value = _static_assignment(text, match.group(1), read_start)
        return (value if value is not None else _UNRESOLVED_SERVER_KEY,
                match.end())
    key_match = re.match(r"[A-Za-z0-9_]+", text[pos:])
    if key_match is None:
        return None, pos
    return key_match.group(0), pos + len(key_match.group(0))


def _request_name(name: str, text: str, index: int,
                  tainted: set[str]) -> bool:
    """Is the ``$name`` at ``index`` request data (or a tainted variable)?

    ONE predicate for the identifier parsers: the plain superglobals and
    tainted locals, plus ``$_SERVER`` ONLY through its request keys
    (``HTTP_*``/``REQUEST_URI``/``QUERY_STRING``).  The latter used to be
    invisible outside the request-mask view, so an identifier built from
    ``$_SERVER['HTTP_HOST']`` was never reported (R14-P2).
    """
    if name in _SUPERGLOBALS or name in tainted:
        return True
    if name == "_SERVER":
        return _server_request_span(text, index) is not None
    return False


def _strip_php_ws_prefix(text: str) -> tuple[int, str]:
    """Split leading PHP whitespace/comments from ``text``.

    ``${ '_GET'}`` and ``${/*c*/'_GET'}`` are the same runtime read as
    ``${'_GET'}``: a comment is whitespace to the parser.  One owner for
    both the request mask's renderer and the identifier classifier.
    """
    match = _PHP_LEAD_WS_RE.match(text)
    lead = match.end() if match is not None else 0
    return lead, text[lead:]


def _php_literal_value(literal: str) -> str:
    """Decode one PHP quoted literal's escapes for a braced variable name.

    ``${"\\x5fGET"}``, ``${"\\137GET"}`` and ``${"\\u{5f}GET"}`` are all
    ``$_GET`` at runtime.  The request mask and the identifier classifier
    previously compared the RAW escape text, so every such spelling hid the
    superglobal.  Single-quoted literals decode only ``\\\\``/``\\'`` (PHP's
    rule); double-quoted ones decode hex/octal/unicode and the simple
    escapes.  This is a NAME decoder, never an evaluator.
    """
    if not literal or literal[0] not in "'\"":
        return ""
    quote = literal[0]
    close = _php_string_end(literal, 0)
    body = literal[1:close - 1] if close is not None else literal[1:]
    if quote == "'":
        out: list[str] = []
        index = 0
        while index < len(body):
            if body[index] == "\\" and index + 1 < len(body) \
                    and body[index + 1] in "\\'":
                out.append(body[index + 1])
                index += 2
                continue
            out.append(body[index])
            index += 1
        return "".join(out)
    simple = {
        "n": "\n", "r": "\r", "t": "\t", "v": "\v", "f": "\f",
        "e": "\x1b", "\\": "\\", '"': '"', "$": "$",
    }
    out = []
    index = 0
    while index < len(body):
        char = body[index]
        if char != "\\" or index + 1 >= len(body):
            out.append(char)
            index += 1
            continue
        nxt = body[index + 1]
        if nxt == "x":
            match = re.match(r"[0-9A-Fa-f]{1,2}", body[index + 2:])
            if match is not None:
                out.append(chr(int(match.group(0), 16)))
                index += 2 + len(match.group(0))
                continue
        elif nxt == "u" and body[index + 2:index + 3] == "{":
            close_brace = body.find("}", index + 3)
            digits = body[index + 3:close_brace]
            if close_brace != -1 and re.fullmatch(r"[0-9A-Fa-f]{1,6}",
                                                  digits):
                codepoint = int(digits, 16)
                if codepoint <= 0x10FFFF \
                        and not 0xD800 <= codepoint <= 0xDFFF:
                    out.append(chr(codepoint))
                    index = close_brace + 1
                    continue
        elif nxt in "01234567":
            digits = re.match(r"[0-7]{1,3}", body[index + 1:])
            assert digits is not None
            out.append(chr(int(digits.group(0), 8)))
            index += 1 + len(digits.group(0))
            continue
        elif nxt in simple:
            out.append(simple[nxt])
            index += 2
            continue
        # An unknown escape is literal backslash + character in PHP.
        out.append("\\")
        out.append(nxt)
        index += 2
    return "".join(out)


def _braced_reference_request(expression: str, tainted: set[str]) -> bool:
    """Does one ``${...}`` body reference request data?

    PHP accepts the shorthand ``${name['k']}`` (a bare name inside the
    braces), ``${$name}`` (a variable variable) and the quoted-name form
    ``${'name'}`` / ``${'name'['k']}`` — all are the same read as
    ``$name['k']`` at runtime (C13).  PHP whitespace AND comments may sit
    between ``${`` and the name (``${ '_GET'}``, ``${/*c*/'_GET'}``).
    """
    _lead, expression = _strip_php_ws_prefix(expression)
    if not expression:
        return False
    if expression.startswith("$"):
        return _identifier_expression_request(
            expression, 0, len(expression), tainted)
    if expression[0] in "'\"":
        close = _php_string_end(expression, 0)
        if close is None:
            return False
        name = _php_literal_value(expression)
        if name == "_SERVER":
            # Apply the accessor parser to the accessor span, not only to
            # the bare name: ``${'_SERVER'}['HTTP_HOST']`` is request data
            # (PHP 8.4 evaluates it), while REMOTE_ADDR is not (R15-P2).
            return _server_request_span(
                "$_SERVER" + expression[close:], 0) is not None
        return name in _SUPERGLOBALS or name in tainted
    match = _NAME_RE.match(expression)
    if match is None:
        return False
    name = match.group(0)
    if name == "_SERVER":
        # The expression here is the braced BODY (``_SERVER[...]``); the
        # shared accessor parser expects the leading ``$``.
        return _server_request_span("$" + expression, 0) is not None
    return name in _SUPERGLOBALS or name in tainted


def _braced_server_accessor_request(text: str, start: int, braced_end: int,
                                    limit: int) -> bool:
    """Is ``${'_SERVER'}['HTTP_HOST']`` the request-header read?

    The key sits AFTER the closing brace, so :func:`_braced_reference_request`
    (which only owns the body between `${` and `}`) cannot see it.  ONE
    helper for both classifers; a non-request key (``REMOTE_ADDR``) stays
    inert.
    """
    body = text[start + 2:braced_end - 1]
    _lead, stripped = _strip_php_ws_prefix(body)
    name = None
    if stripped[:1] in ("'", '"'):
        close = _php_string_end(stripped, 0)
        if close is not None:
            name = _php_literal_value(stripped)
    else:
        match = _NAME_RE.match(stripped)
        if match is not None:
            name = match.group(0)
    if name != "_SERVER":
        return False
    accessor_end = _skip_accessors(text, braced_end, limit)
    return _server_request_span(
        "$_SERVER" + text[braced_end:accessor_end], 0) is not None


def _interpolating_positions(segment: str) -> bytearray:
    """Same-length flags: 1 inside an INTERPOLATING string/heredoc.

    ``${...}`` is context-sensitive (PHP 8.4): in CODE a bare name is a
    constant and ``${_SERVER[...]}`` is fatal; inside a double-quoted/
    heredoc string the braces select ``$name`` and ``${_SERVER[...]}``
    reads the header.  One scanner owns the boundary for the rewrite.
    """
    inside = bytearray(len(segment))
    index = 0
    length = len(segment)
    while index < length:
        if segment.startswith("<<<", index):
            end, interpolates = _php_heredoc_end(segment, index)
            end = length if end is None else end
            if interpolates:
                for offset in range(index, end):
                    inside[offset] = 1
            index = end
            continue
        char = segment[index]
        if char in "\"`":
            end = _php_string_end(segment, index, interpolation_aware=True)
            end = length if end is None else end
            for offset in range(index, end):
                inside[offset] = 1
            index = end
            continue
        if char == "'":
            end = _php_string_end(segment, index)
            index = length if end is None else end
            continue
        if segment.startswith("//", index) or (
                char == "#" and not segment.startswith("#[", index)):
            index = _php_comment_stop(segment, index)
            continue
        if segment.startswith("/*", index):
            close = segment.find("*/", index + 2)
            index = length if close == -1 else close + 2
            continue
        index += 1
    return inside


def _rewrite_braced_interpolation(segment: str,
                                  aliases: dict[str, str] | None = None) -> str:
    """Rewrite every ``${expr}`` to the same-length ``$expr`` form.

    Removing the braces and padding with spaces keeps every other offset
    stable, while ``$_GET``/``$t`` inside the braces become visible to the
    shared request/variable matchers.  Subscripts and property chains are
    preserved verbatim (``${t['x']}`` -> ``$t['x']``).

    CODE and string semantics differ (PHP 8.4): a bare name in code is a
    constant (``${_GET['c']}`` is fatal), while in an interpolating string
    it selects the variable; ``${'_SERVER'}`` in a string interpolates the
    ARRAY ("Array"), and only an accessor INSIDE the braces reads a key.
    Treating both as code minted reflected-request/SQL findings from code
    that cannot run, and from string text that is static.
    """
    inside = _interpolating_positions(segment)
    out: list[str] = []
    index = 0
    while True:
        start = segment.find("${", index)
        if start == -1:
            out.append(segment[index:])
            break
        end = _braced_end(segment, start)
        if end is None:
            out.append(segment[index:])
            break
        out.append(segment[index:start])
        body = segment[start + 2:end - 1]
        _lead, stripped = _strip_php_ws_prefix(body)
        in_string = bool(inside[start]) if start < len(inside) else False
        rendered = stripped
        if stripped[:1] in ("'", '"'):
            close = _php_string_end(stripped, 0)
            if close is not None:
                # ``${'name'}`` is PHP's ``$name`` (and ``${'name'['k']}``
                # is ``$name['k']``) — in CODE.  In a string the accessor
                # after the closing brace is literal text, so only an
                # accessor INSIDE the braces is request data.
                name = _php_literal_value(stripped)
                suffix = stripped[close:]
                if in_string:
                    is_request = _braced_reference_request(body, set()) and (
                        name == "_SERVER"
                        or suffix.lstrip().startswith(("[", "->", "?->")))
                    if is_request:
                        rendered = name + suffix
                    elif name in _SUPERGLOBALS or name == "_SERVER":
                        # An array interpolated without an accessor is
                        # static ("Array"), not request data.
                        rendered = " " * len(stripped)
                    else:
                        # An ordinary variable: keep the reference so the
                        # taint pass can follow ``${'id'}`` like ``$id``.
                        rendered = name + suffix
                else:
                    # Decode PHP's string escapes: ``${"\x5fGET"}`` is
                    # ``$_GET`` at runtime.
                    rendered = name + suffix
        elif stripped.startswith("$"):
            # ``${$expr}`` selects a variable in both contexts.  When the
            # indirection was statically resolved, render the SELECTED name
            # so ``${$n}`` with ``$n="t"`` matches the same taint as ``$t``.
            variable = _VAR_RE.match(stripped)
            target = aliases.get(variable.group(1)) if (
                aliases is not None and variable is not None) else None
            rendered = target + stripped[variable.end():] \
                if target is not None else stripped
        elif not in_string:
            # A bare constant name in code selects nothing and cannot run.
            rendered = " " * len(stripped)
        out.append("$" + rendered)
        out.append(" " * max(0, end - start - 1 - len(rendered)))
        index = end
    return "".join(out)


def _skip_sql_identifier_modifiers(text: str, index: int,
                                   limit: int) -> int:
    """Skip DDL/DML grammar phrases between a SQL keyword and its identifier."""
    while True:
        match = _SQL_IDENTIFIER_MODIFIERS_RE.match(text, index, limit)
        if match is None:
            return index
        index = match.end()


def _argument_end(text: str, open_index: int, limit: int | None = None) -> int:
    """Offset of the ``)`` matching the ``(`` at ``open_index`` (or the end).

    ``limit`` bounds the scan: the caller that only owns a slice (one
    assignment segment) must not pay for the rest of the statement.  An
    unterminated or out-of-limit call returns ``limit`` (or ``len(text)``
    when no limit was given), exactly as before for every existing caller.
    """
    depth = 0
    index = open_index
    length = len(text) if limit is None else min(limit, len(text))
    while index < length:
        char = text[index]
        if text.startswith("<<<", index):
            end, _interpolates = _php_heredoc_end(text, index)
            if end is None:
                return length
            index = end
            continue
        if char in "'\"":
            end = _php_string_end(text, index, interpolation_aware=True)
            if end is None:
                return length
            index = end
            continue
        if char == "`":
            end = _php_backtick_end(text, index)
            if end is None:
                return length
            index = end
            continue
        if text.startswith("//", index) or (
                char == "#" and not text.startswith("#[", index)):
            # ``?>`` ends the comment and PHP mode; never scan a later
            # block as this argument's expression.
            stop = _php_comment_stop(text, index)
            if stop < length and text.startswith("?>", stop):
                return stop
            index = length if stop == length else stop + 1
            continue
        if text.startswith("/*", index):
            close = text.find("*/", index + 2)
            index = length if close == -1 else close + 2
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return length


def _member_call(text: str, start: int) -> bool:
    """True when the name at ``start`` is a method/static call or a variable."""
    if start and text[start - 1] == "$":
        return True
    return _php_member_before(text, start)


def _is_open_echo_tag(position: int, open_tags: set[int]) -> bool:
    """Is the ``<?=`` at ``position`` a real PHP open tag?

    The one-pass ``_php_lex`` records every real tag offset while it is
    already scanning the file; the old implementation re-lexed the prefix
    for EVERY ``<?=``, which was quadratic on a file full of short echo tags
    (3,200 tags took ~4 s; 1 MiB could run for hours).  Membership is O(1).
    """
    return position in open_tags


def _foreach_bindings(text: str, flags: bytearray
                      ) -> list[tuple[str, set[str], bool]]:
    """``(target, referenced variables, direct request evidence)`` per foreach.

    The old regex recognized only a literal ``foreach ($_GET …)``.  A normal
    ``$ids = $_GET['ids']; foreach ($ids as $id)`` and the accessor form
    ``foreach ($_GET['ids'] as $id)`` therefore never tainted ``$id``.  The
    iterable is parsed like an assignment RHS (same request mask and
    referenced-variable set) and every binding on the right of ``as`` is a
    target; the existing fixed point closes ``$ids`` -> ``$id``.
    """
    bindings: list[tuple[str, set[str], bool]] = []
    for match in _FOREACH_RE.finditer(text):
        if flags[match.start()] != 1:
            continue
        open_index = text.find("(", match.start(), match.end())
        close = _argument_end(text, open_index)
        body = text[open_index + 1:close]
        # Split at the top-level ``as`` (outside strings/brackets).
        split = _top_level_as(body)
        if split is None:
            continue
        iterable, targets = body[:split], body[split + 2:]
        mask = _request_mask(iterable)
        direct = _REQUEST_RE.search(mask) is not None
        referenced = set(_VAR_RE.findall(mask))
        for target in _VAR_RE.findall(targets):
            if target not in _SUPERGLOBALS:
                bindings.append((target, referenced, direct))
    return bindings


def _top_level_as(body: str) -> int | None:
    """Offset of the top-level ``as`` keyword in a foreach header, or None."""
    depth = 0
    index = 0
    length = len(body)
    while index < length:
        char = body[index]
        if body.startswith("//", index) or (
                char == "#" and not body.startswith("#[", index)):
            stop = body.find("\n", index)
            index = length if stop == -1 else stop + 1
            continue
        if body.startswith("/*", index):
            close = body.find("*/", index + 2)
            index = length if close == -1 else close + 2
            continue
        if char in "'\"":
            end = _php_string_end(
                body, index, interpolation_aware=char == '"')
            index = length if end is None else end
            continue
        if char == "`":
            end = _php_backtick_end(body, index)
            index = length if end is None else end
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif depth == 0 and body[index:index + 2].lower() == "as" \
                and (index == 0
                     or not (body[index - 1].isalnum()
                             or body[index - 1] == "_")) \
                and (index + 2 >= length
                     or not (body[index + 2].isalnum()
                             or body[index + 2] == "_")):
            return index
        index += 1
    return None


#: A variable reference with any member/static accessor chain; only the BASE
#: variable participates in taint (``$this``/``$wpdb``), so a property name
#: can never be mistaken for a same-named local.
_QUERY_REFERENCE_RE = re.compile(
    r"\$(?P<base>[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*)"
    r"(?:\s*(?:\?->|->|::)\s*[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*)*"
)


def _query_references(segment: str) -> set[str]:
    """Base variable names referenced by a query text/trailing concat."""
    return {match.group("base")
            for match in _QUERY_REFERENCE_RE.finditer(segment)}


def _strip_enclosing_parens(text: str, start: int,
                            end: int) -> tuple[int, int]:
    """Trim whitespace and fully-enclosing ``(``/``)`` pairs around a span.

    ``query(($wpdb->prepare(...)))`` passes the prepare call wrapped in
    parentheses to the sink; without stripping, the gate matched only at the
    immediate expression start and reported the bound value as raw SQL
    (R6-18).
    """
    while True:
        while start < end and text[start] in " \t\r\n":
            start += 1
        while end > start and text[end - 1] in " \t\r\n":
            end -= 1
        if start < end and text[start] == "(":
            # Bound the balance scan to THIS span: a segment that opens a
            # parenthesis closed later in the statement (a nested assignment
            # chain) must not rescan the whole tail per assignment.
            close = _argument_end(text, start, end)
            if close == end - 1:
                start += 1
                end -= 1
                continue
        return start, end


def _prepare_relevant(text: str, start: int, end: int, *,
                      spans: list[tuple[int, int, str]] | None = None,
                      opens: list[int] | None = None,
                      calls: list[int] | None = None) -> str | None:
    """``prefix + query text + trailing concat`` for a prepare RHS, else None.

    The prepare call may sit ANYWHERE at the top level of the RHS (a
    ``apply_filters("q", $wpdb->prepare(...))`` wrapper) and may be wrapped
    in enclosing parentheses; both are the same parameterized gate.  The
    prefix is included so request data concatenated BEFORE the prepare call
    still reaches the taint test (R6-18).  ``calls`` is the file's ONE list
    of ``prepare(`` candidate offsets (already filtered out of literals):
    with it the search jumps to the first candidate at/after ``start``
    instead of rescanning the statement for every chained assignment.
    """
    start, end = _strip_enclosing_parens(text, start, end)
    if spans is None or opens is None:
        spans = _literal_spans(text)
        opens = [span[0] for span in spans]

    def _candidates() -> Iterator[int]:
        if calls is None:
            for found in _PREPARE_CALL_RE.finditer(text, start, end):
                yield found.start()
            return
        index = bisect_left(calls, start)
        while index < len(calls) and calls[index] < end:
            yield calls[index]
            index += 1

    for position in _candidates():
        if _enclosing_literal(spans, opens, position) is not None:
            continue
        match = _PREPARE_AT_RE.match(text, position, end)
        if match is None:
            continue
        inner_open = match.end() - 1
        # Bound the balance scan to THIS span; a prepare call that closes
        # after it cannot be parsed from this assignment's segment (the next
        # target's dependency edge owns the tail).  Returning ``end`` for an
        # unterminated/out-of-span call keeps the old skip behavior.
        inner_close = _argument_end(text, inner_open, end)
        if inner_close >= end:
            continue
        first_close = _first_argument_end(text, inner_open + 1, inner_close)
        query = text[inner_open + 1:first_close]
        prefix = text[start:match.start()]
        trailing = text[inner_close + 1:end]
        return f"{prefix} {query} {trailing}"
    return None


def _tainted_variables(text: str, flags: bytearray,
                       php_mask: bytearray | None = None,
                       statement_starts: list[int] | None = None,
                       deadline: Deadline | None = None,
                       *, aliases_out: dict[str, str] | None = None
                       ) -> set[str]:
    """Variables bound to request data in this file (see module docstring).

    Direct evidence: a simple/compound assignment whose right-hand side
    carries a request superglobal, or a ``foreach`` binding over one.  Same-file
    assignment chains are closed to a fixed point with a reverse worklist,
    so order and forward references cannot hide a direct binding.

    ``statement_starts`` is the file's ONE statement-boundary list (built by
    :func:`_statement_starts` in the caller): the assignment loop looks its
    statement end up with a bisect instead of rescanning the rest of the file
    for every match.  Assignments inside ONE statement are scanned as
    adjacent segments: each assignment's RHS view runs to just past the next
    assignment's target and the later tail reaches it through the ordinary
    dependency edge, so a chained ``$a = $b = ... = 1`` statement is linear
    in its bytes instead of masking the whole suffix per assignment (a 13 KB
    one-statement chain took 1.45 s and a 1 MiB chain extrapolated to hours).
    ``prepare(`` candidates are collected once for the same reason; the
    deadline is checked per assignment so an oversized candidate cannot
    defeat the run budget.

    A ``prepare()`` assignment is a GATE, not a blanket exclusion: it stays
    bound while every variable in its query text/trailing concat is
    untainted, and taints its target the moment one of them becomes tainted
    (a query built from ``$t='wp_posts'`` or ``$wpdb->prefix`` is bound;
    ``$t=$_GET['t']`` is not).  Comments are PHP whitespace, so the
    assignment/foreach scan runs on the comment-blanked view.

    ``aliases_out`` receives a map from a variable-variable NAME (``$n`` in
    ``${$n}``) to the statically assigned variable it selects, so a later
    ``echo ${$n}`` resolves to ``$t`` and sees taint.  An unresolvable
    ``${$n}`` fails closed: the alias maps to itself and the name is tainted
    as the target.
    """
    code = _comment_mask(text, php_mask)
    if statement_starts is None:
        statement_starts = _statement_starts(text, php_mask)
    prepare_spans = _literal_spans(code, php_mask)
    prepare_opens = [span[0] for span in prepare_spans]
    # One scan for the whole file: chained assignments inside one statement
    # share this candidate list instead of searching the statement again.
    prepare_calls = [
        found.start() for found in _PREPARE_CALL_RE.finditer(code)
        if _enclosing_literal(prepare_spans, prepare_opens,
                              found.start()) is None
    ]
    tainted: set[str] = set()
    aliases = aliases_out if aliases_out is not None else {}
    dependents: dict[str, list[str]] = {}
    pending: dict[str, list[str]] = {}
    queue: deque[str] = deque()

    def _taint(name: str) -> None:
        if name not in tainted:
            tainted.add(name)
            queue.append(name)

    def _record(target: str, referenced: set[str], direct: bool) -> None:
        if direct:
            _taint(target)
        for reference in referenced:
            dependents.setdefault(reference, []).append(target)

    def _scan_assignment(target: str, segment_start: int,
                         segment_end: int) -> None:
        """Taint decision for one assignment of a statement.

        ``segment_end`` is just past the next assignment target (or the
        statement end for the last one).  A prepare call in THIS segment is
        parsed within the same span: scanning to the statement tail here made
        a nested ``$a = f(prepare(...), $b = f(...))`` statement quadratic,
        because every segment copied and masked the whole remaining tail.
        A later prepare is reached transitively through the next target,
        which is a variable occurrence inside this segment.
        """
        call_index = bisect_left(prepare_calls, segment_start)
        if (call_index < len(prepare_calls)
                and prepare_calls[call_index] < segment_end):
            relevant = _prepare_relevant(
                code, segment_start, segment_end, spans=prepare_spans,
                opens=prepare_opens, calls=prepare_calls)
            if relevant is not None:
                mask = _request_mask(relevant)
                direct = _REQUEST_RE.search(mask) is not None
                gate = _query_references(mask)
                if direct:
                    _taint(target)
                elif gate:
                    for reference in gate:
                        pending.setdefault(reference, []).append(target)
                return
        rhs = _request_mask(code[segment_start:segment_end])
        _record(target, set(_VAR_RE.findall(rhs)),
                _REQUEST_RE.search(rhs) is not None)

    previous = None
    for match in _ASSIGN_RE.finditer(code):
        _check(deadline, "source scan taint")
        if flags[match.start()] != 1:
            continue
        name = match.group("name")
        if name is None:
            if match.group("braced_s") is not None:
                name = _php_literal_value("'" + match.group("braced_s") + "'")
            elif match.group("braced_d") is not None:
                name = _php_literal_value('"' + match.group("braced_d") + '"')
            else:
                variable = match.group("braced_var")
                resolved = _static_assignment(code, variable, match.start())
                if resolved is not None and _NAME_RE.fullmatch(resolved):
                    # PHP 8.4 executes ${$n} = ... as the variable NAMED by
                    # $n.  Resolve the static assignment, and remember the
                    # indirection so a later ${$n} read is rewritten to $t.
                    aliases[variable] = resolved
                    name = resolved
                else:
                    # Fail closed: the only name visible at the read site is
                    # the indirection variable itself.
                    aliases[variable] = variable
                    name = variable
        if match.group("name") is not None:
            # A plain static string assignment is the indirection binding
            # for a later ``${$n}`` READ: ``$n="t"; $t=$_GET[...];
            # echo ${$n};`` printed HUNTER but the scan returned {}.  Only
            # the LAST assignment before use is modeled; a non-static (or
            # non-name) value is removed so a stale alias cannot resolve a
            # dynamic read.
            static, _end = _static_php_string(code, match.end())
            if static is not None and _NAME_RE.fullmatch(static):
                aliases[name] = static
            else:
                aliases.pop(name, None)
        if name in _SUPERGLOBALS:
            continue
        if not name:
            continue
        statement_start, statement_end = _statement_span(
            statement_starts, len(text), match.end())
        if previous is not None:
            previous_match, previous_name, previous_start, previous_end = \
                previous
            if statement_start == previous_start:
                _scan_assignment(previous_name, previous_match.end(),
                                 match.end())
                previous = (match, name, statement_start, statement_end)
                continue
            _scan_assignment(previous_name, previous_match.end(),
                             previous_end)
        previous = (match, name, statement_start, statement_end)
    if previous is not None:
        _check(deadline, "source scan taint")
        previous_match, previous_name, _previous_start, previous_end = previous
        _scan_assignment(previous_name, previous_match.end(), previous_end)
    for target, referenced, direct in _foreach_bindings(code, flags):
        _check(deadline, "source scan taint")
        if target not in _SUPERGLOBALS:
            _record(target, referenced, direct)
    # A prepare gate whose variable was already known tainted before the
    # record was collected must activate now; the queue below only sees
    # future taint events.
    for reference, targets in pending.items():
        if reference in tainted:
            for target in targets:
                _taint(target)

    while queue:
        source = queue.popleft()
        for name in dependents.get(source, ()):
            _taint(name)
        for name in pending.get(source, ()):
            _taint(name)
    return tainted


def _blank_interpolation_comments(segment: str, out: list[str],
                                  start: int, end: int) -> None:
    """Blank PHP comments inside ``{$...}`` and ``${...}`` interpolations.

    A double-quoted/backtick/heredoc body stays visible to request matching
    because it INTERPOLATES ``$var``; but ``{$a // $_GET}``,
    ``{$a /* $_GET */}`` and ``${'a' /* $_GET */}`` are COMMENTS inside that
    expression, not request data.  One owner for BOTH PHP interpolation
    spellings: the outer literal loop skips the whole string, so this pass
    walks each span with the same comment/string rules and preserves every
    offset.  ``$`` immediately before the brace (``${``) and immediately
    after it (``{$``) both open an expression; a brace with neither is
    ordinary literal text.
    """
    index = start
    while index < end:
        opener = segment.find("{", index, end)
        if opener == -1:
            return
        braced_dollar = opener > start and segment[opener - 1] == "$"
        dollar_brace = (opener + 1 < end
                        and segment[opener + 1] == "$")
        if not (braced_dollar or dollar_brace):
            index = opener + 1
            continue
        depth = 0
        cursor = opener
        while cursor < end:
            char = segment[cursor]
            if char in "'\"`":
                close = _php_string_end(segment, cursor)
                cursor = end if close is None else min(close, end)
                continue
            if segment.startswith("//", cursor) or (
                    char == "#" and not segment.startswith("#[", cursor)):
                stop = min(_php_comment_stop(segment, cursor), end)
                for offset in range(cursor, stop):
                    if out[offset] not in "\r\n":
                        out[offset] = " "
                cursor = stop
                continue
            if segment.startswith("/*", cursor):
                close = segment.find("*/", cursor + 2, end)
                stop = end if close == -1 else close + 2
                for offset in range(cursor, stop):
                    if out[offset] not in "\r\n":
                        out[offset] = " "
                cursor = stop
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    cursor += 1
                    break
            cursor += 1
        index = cursor


def _request_mask(segment: str, aliases: dict[str, str] | None = None) -> str:
    """A same-length view with comments and NON-interpolating literals blanked.

    PHP single-quoted strings and nowdocs are literal data: ``'$_GET'``
    prints four characters, it never reads the request.  Double-quoted
    strings, heredocs and backtick strings DO interpolate, so their bodies
    stay visible.  Comments are blanked too, so a trailing ``// $_GET``
    cannot taint an otherwise safe line.  Offsets are preserved, which lets
    the SQL-identifier scan keep using raw match positions.
    """
    # ``${'name'}`` is an EXECUTABLE superglobal reference: PHP executes
    # ``echo ${'_GET'}['x']`` exactly like ``echo $_GET['x']``.  Blank the
    # comments inside interpolation expressions FIRST (the rewrite removes
    # the ``${`` marker the comment pass keys on), then rewrite the braces
    # BEFORE the literal-masking loop blanks the quoted name — after that
    # the rewrite saw only spaces (R14-P2).  Same-length throughout, so
    # every raw offset stays valid.
    pre = list(segment)
    _blank_interpolation_comments(segment, pre, 0, len(segment))
    segment = _rewrite_braced_interpolation("".join(pre), aliases)
    out = list(segment)
    index = 0
    length = len(segment)
    while index < length:
        char = segment[index]
        if segment.startswith("<<<", index):
            end, interpolates = _php_heredoc_end(segment, index)
            end = length if end is None else end
            if not interpolates:
                for offset in range(index, end):
                    if out[offset] not in "\r\n":
                        out[offset] = " "
            else:
                _blank_interpolation_comments(segment, out, index, end)
            index = end
            continue
        if char == "'":
            end = _php_string_end(segment, index)
            end = length if end is None else end
            for offset in range(index, end):
                if out[offset] not in "\r\n":
                    out[offset] = " "
            index = end
            continue
        if char == '"':
            end = _php_string_end(segment, index, interpolation_aware=True)
            end = length if end is None else end
            _blank_interpolation_comments(segment, out, index, end)
            index = end
            continue
        if char == "`":
            # A backtick string INTERPOLATES like a double-quoted one; its
            # body stays visible to request matching (R6-15).
            end = _php_backtick_end(segment, index)
            end = length if end is None else end
            _blank_interpolation_comments(segment, out, index, end)
            index = end
            continue
        if segment.startswith("//", index) or (
                char == "#" and not segment.startswith("#[", index)):
            stop = _php_comment_stop(segment, index)
            for offset in range(index, stop):
                if out[offset] not in "\r\n":
                    out[offset] = " "
            index = stop
            continue
        if segment.startswith("/*", index):
            close = segment.find("*/", index + 2)
            stop = length if close == -1 else close + 2
            for offset in range(index, stop):
                if out[offset] not in "\r\n":
                    out[offset] = " "
            index = stop
            continue
        index += 1
    mask = "".join(out)
    mask = _ESCAPED_DOLLAR_RE.sub(lambda m: " " * len(m.group(0)), mask)
    # ``${_SERVER[...]}`` puts a brace between ``$`` and the name, so the
    # request matcher must see the BRACED-REWRITTEN view: normalize
    # ``${expr}`` to ``$expr`` first, then rewrite the request token.
    mask = _rewrite_braced_interpolation(mask)
    # ``$_SERVER['HTTP_HOST']``/``REQUEST_URI`` are the header/request half
    # of _SERVER; rewrite the token to ``$_GET`` (same length) so the common
    # request matcher sees it.  Non-request keys are left untouched.
    #
    # The key may be a quoted literal with PHP escapes, which the masking
    # loop above has already blanked — so the rewrite must consult the RAW
    # segment (the literal was data, but the $_SERVER read is executable
    # code) through the ONE accessor parser and only touch offsets the mask
    # still shows as the variable token.
    for match in _SERVER_START_RE.finditer(segment):
        start = match.start()
        if mask.startswith("$_SERVER", start) \
                and _server_request_span(segment, start) is not None:
            mask = mask[:start] + "$_GET   " + mask[start + len("$_SERVER"):]
    return mask


def _comment_mask(segment: str, php_mask: bytearray | None = None,
                  *, blank_literals: bool = False) -> str:
    """A same-length view with PHP comments blanked to spaces (strings kept).

    Comments are PHP WHITESPACE: ``$wpdb-> /* c */ query(...)`` executes,
    so every name/sink/member regex must run on this view rather than the
    raw text.  String and heredoc bodies are skipped (not blanked) because
    their offsets and content feed the literal/SQL logic; only real code
    comments are removed.  With ``php_mask`` an HTML ``//`` is not a PHP
    comment.

    ``blank_literals=True`` is for the assignment scanner: quotes and
    heredoc/backtick bodies are DATA, so an assignment-looking string
    inside one must not shadow the live assignment (``$k = "HTTP_HOST";
    echo "$k = 'REMOTE_ADDR'"``).  Offsets stay identical.
    """
    out = list(segment)
    index = 0
    length = len(segment)

    def in_php(pos: int) -> bool:
        return php_mask is None or bool(php_mask[pos])

    def blank(start: int, stop: int) -> None:
        for offset in range(start, stop):
            if out[offset] not in "\r\n":
                out[offset] = " "

    while index < length:
        if not in_php(index):
            index += 1
            continue
        if segment.startswith("<<<", index):
            end, _interpolates = _php_heredoc_end(segment, index)
            end = length if end is None else end
            if blank_literals:
                blank(index, end)
            index = end
            continue
        char = segment[index]
        if char in "'\"":
            end = _php_string_end(segment, index, interpolation_aware=True)
            end = length if end is None else end
            if blank_literals:
                blank(index, end)
            index = end
            continue
        if char == "`":
            end = _php_backtick_end(segment, index)
            end = length if end is None else end
            if blank_literals:
                blank(index, end)
            index = end
            continue
        if segment.startswith("//", index) or (
                char == "#" and not segment.startswith("#[", index)):
            stop = _php_comment_stop(segment, index)
            blank(index, stop)
            index = stop
            continue
        if segment.startswith("/*", index):
            close = segment.find("*/", index + 2)
            stop = length if close == -1 else close + 2
            blank(index, stop)
            index = stop
            continue
        index += 1
    return "".join(out)


def _sql_mask(segment: str, php_mask: bytearray | None = None) -> str:
    """A same-length view that keeps SQL TEXT inside quoted literals.

    ``_request_mask`` blanks single-quoted literals because they cannot
    interpolate request data; but a query is usually WRITTEN inside one
    (``$pdo->prepare('SELECT * FROM ' . $_GET['t'])``), so the keyword
    itself disappeared and the injectable identifier was missed.  This view
    blanks comments and nowdocs only and keeps every quoted body: it is
    used for SQL keyword/context visibility, never for request matching.

    With ``php_mask``, inline HTML is blanked too: ``<p>SELECT * FROM $t</p>``
    is output text PHP never parses, and an apostrophe or ``//`` there must
    not corrupt the PHP string/comment view.  Escape sequences inside an
    interpolating literal are normalized to spaces so ``"SELECT *\\nFROM
    $t"`` (PHP renders a newline) still presents a word boundary before
    ``FROM``.
    """
    out = list(segment)
    index = 0
    length = len(segment)
    while index < length:
        if php_mask is not None and not php_mask[index]:
            if out[index] not in "\r\n":
                out[index] = " "
            index += 1
            continue
        char = segment[index]
        if segment.startswith("<<<", index):
            end, interpolates = _php_heredoc_end(segment, index)
            end = length if end is None else end
            if not interpolates:
                for offset in range(index, end):
                    if out[offset] not in "\r\n":
                        out[offset] = " "
            else:
                _normalize_sql_escapes(out, index, end)
                # Comments inside ``{$...}``/``${...}`` are PHP syntax,
                # not SQL text: the SQL view must blank them too or a
                # commented-out ``SELECT * FROM $t`` mints a HIGH finding
                # for code PHP never executes.
                _blank_interpolation_comments(segment, out, index, end)
            index = end
            continue
        if char in "'\"":
            end = _php_string_end(segment, index, interpolation_aware=True)
            end = length if end is None else end
            if char == '"':
                _normalize_sql_escapes(out, index, end)
                _blank_interpolation_comments(segment, out, index, end)
            index = end
            continue
        if char == "`":
            end = _php_backtick_end(segment, index)
            end = length if end is None else end
            _normalize_sql_escapes(out, index, end)
            _blank_interpolation_comments(segment, out, index, end)
            index = end
            continue
        if segment.startswith("//", index) or (
                char == "#" and not segment.startswith("#[", index)):
            stop = _php_comment_stop(segment, index)
            for offset in range(index, stop):
                if out[offset] not in "\r\n":
                    out[offset] = " "
            index = stop
            continue
        if segment.startswith("/*", index):
            close = segment.find("*/", index + 2)
            stop = length if close == -1 else close + 2
            for offset in range(index, stop):
                if out[offset] not in "\r\n":
                    out[offset] = " "
            index = stop
            continue
        index += 1
    return "".join(out)


#: PHP's whitespace escapes inside an interpolating string.  The SQL view
#: keeps their LENGTH but turns the letter into a space, so ``\nFROM`` reads
#: with a word boundary before FROM exactly like the rendered newline.
_SQL_ESCAPE_LETTERS = frozenset("nrtvef")


def _normalize_sql_escapes(out: list[str], start: int, end: int) -> None:
    """Render a PHP literal's whitespace escapes as SQL whitespace.

    PHP decodes ``\\n``/``\\r``/``\\t``/``\\v``/``\\e``/``\\f`` — and
    ``\\xNN`` / ``\\u{...}`` hex escapes — before the string reaches the
    database.  The same-length SQL view keeps the span length but turns
    every decoded whitespace character into a space, so ``"\\x0aFROM $t"``
    (a rendered newline) still presents a word boundary before ``FROM``.
    """
    index = start + 1
    while index < end:
        if out[index] != "\\":
            index += 1
            continue
        run_start = index
        while index < end and out[index] == "\\":
            index += 1
        run = index - run_start
        # An ODD backslash run escapes the following character; an even run
        # leaves a literal backslash, so ``\\n`` is not a newline.
        if run % 2 == 0 or index >= end:
            index += 1
            continue
        char = out[index]
        if char in "xX" and index + 2 < end \
                and all(c in "0123456789abcdefABCDEF"
                        for c in out[index + 1:index + 3]):
            digits = "".join(out[index + 1:index + 3])
            value = int(digits, 16)
            if chr(value).isspace():
                for offset in range(run_start, index + 3):
                    if out[offset] not in "\r\n":
                        out[offset] = " "
            index += 3
            continue
        if char in "01234567":
            # PHP octal escape (one to three digits); ``\12`` is a newline.
            digits = 0
            value = 0
            while digits < 3 and index + digits < end \
                    and out[index + digits] in "01234567":
                value = value * 8 + int(out[index + digits])
                digits += 1
            if digits and value <= 0xFF and chr(value).isspace():
                for offset in range(run_start, index + digits):
                    if out[offset] not in "\r\n":
                        out[offset] = " "
            index += max(1, digits)
            continue
        if char == "u" and index + 1 < end and out[index + 1] == "{":
            close = index + 2
            while close < end and out[close] != "}":
                close += 1
            if close < end:
                digits = "".join(out[index + 2:close])
                if digits and all(c in "0123456789abcdefABCDEF"
                                  for c in digits):
                    value = int(digits, 16)
                    if value <= 0x10FFFF and chr(value).isspace():
                        for offset in range(run_start, close + 1):
                            if out[offset] not in "\r\n":
                                out[offset] = " "
                index = close + 1
                continue
        if char.lower() in _SQL_ESCAPE_LETTERS:
            if out[index] not in "\r\n":
                out[index] = " "
        index += 1


def _literal_spans(text: str,
                   php_mask: bytearray | None = None
                   ) -> list[tuple[int, int, str]]:
    """Every PHP string/heredoc span as ``(start, end_exclusive, quote)``.

    Computed ONCE per file: the SQL identifier scan must know whether a
    keyword sits inside a single-quoted literal (literal data) or an
    interpolating one, and a per-keyword rescan from offset 0 was quadratic
    on a file full of strings.  ``quote`` is the actual quote character, or
    ``"``/``'`` for an interpolating/nowdoc heredoc.

    With ``php_mask`` only PHP segments are lexed: an apostrophe in inline
    HTML is text, not a PHP string opener, and must not swallow the next
    real query.
    """
    spans: list[tuple[int, int, str]] = []
    index = 0
    length = len(text)
    while index < length:
        if php_mask is not None and not php_mask[index]:
            index += 1
            continue
        if text.startswith("<<<", index):
            end, interpolates = _php_heredoc_end(text, index)
            if end is None:
                break
            spans.append((index, end, '"' if interpolates else "'"))
            index = end
            continue
        char = text[index]
        if text.startswith("//", index) or (
                char == "#" and not text.startswith("#[", index)):
            stop = _php_comment_stop(text, index)
            index = length if stop == length else stop + 1
            continue
        if text.startswith("/*", index):
            close = text.find("*/", index + 2)
            index = length if close == -1 else close + 2
            continue
        if char in "'\"`":
            end = _php_string_end(
                text, index, interpolation_aware=char in "\"`")
            if end is None:
                break
            spans.append((index, end, char))
            index = end
            continue
        index += 1
    return spans


def _enclosing_literal(
    spans: list[tuple[int, int, str]], opens: list[int], position: int
) -> tuple[int, int, str] | None:
    """The string span containing ``position`` (open < position < close).

    ``opens`` is the span starts list computed ONCE per file; rebuilding it
    per SQL keyword made a keyword-dense file quadratic.
    """
    index = bisect_right(opens, position) - 1
    if index >= 0:
        open_, close, quote = spans[index]
        if open_ < position < close:
            return open_, close, quote
    return None


def _dollar_escaped(text: str, index: int) -> bool:
    """True when the ``$`` at ``index`` follows an ODD backslash run."""
    count = 0
    cursor = index - 1
    while cursor >= 0 and text[cursor] == "\\":
        count += 1
        cursor -= 1
    return count % 2 == 1


def _skip_concat(text: str, index: int, end: int) -> int | None:
    """Offset after a PHP concatenation operator, or None at a boundary.

    Whitespace alone ends an identifier (``FROM wp_users WHERE``); only a
    ``.``/``+`` continuation keeps the same identifier expression open.
    """
    cursor = index
    while cursor < end and text[cursor] in " \t\r\n":
        cursor += 1
    if cursor < end and text[cursor] in ".+":
        cursor += 1
        while cursor < end and text[cursor] in " \t\r\n":
            cursor += 1
        return cursor
    return None


def _matching_bracket_end(text: str, start: int, end: int) -> int | None:
    """End of the balanced ``[...]``/``{...}`` opening at ``start``."""
    opener = text[start]
    closer = "]" if opener == "[" else "}"
    depth = 0
    index = start
    while index < end:
        char = text[index]
        if text.startswith("<<<", index):
            heredoc_end, _interpolates = _php_heredoc_end(text, index)
            if heredoc_end is None:
                return None
            index = heredoc_end
            continue
        if char in "'\"`":
            string_end = _php_string_end(
                text, index, interpolation_aware=char in "\"`")
            if string_end is None:
                return None
            index = string_end
            continue
        if text.startswith("//", index) or (
                char == "#" and not text.startswith("#[", index)):
            stop = text.find("\n", index)
            index = end if stop == -1 else stop + 1
            continue
        if text.startswith("/*", index):
            close = text.find("*/", index + 2)
            index = end if close == -1 else close + 2
            continue
        if char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return None


def _skip_accessors(text: str, index: int, end: int) -> int:
    """Skip ``[...]``/``->name``/``?->name``/``{$...}`` after a variable."""
    cursor = index
    while cursor < end:
        # PHP whitespace AND comments are legal between the variable/brace
        # and its accessor (``${'_SERVER'} /*c*/ ['HTTP_HOST']``).
        ws = _PHP_WS_RE.match(text, cursor, end)
        if ws is not None and ws.end() > cursor:
            cursor = ws.end()
            continue
        if text.startswith("?->", cursor) or text.startswith("->", cursor):
            after = cursor + (3 if text.startswith("?->", cursor) else 2)
            ws = _PHP_WS_RE.match(text, after, end)
            if ws is not None:
                after = ws.end()
            match = _VAR_RE.match(text, after)
            if match is None:
                match = re.match(
                    r"[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*", text[after:end])
                if match is None:
                    return cursor
                cursor = after + match.end()
            else:
                cursor = match.end()
            continue
        if text[cursor] == "[":
            close = _matching_bracket_end(text, cursor, end)
            if close is None:
                return cursor
            cursor = close
            continue
        if text.startswith("{$", cursor):
            close = _matching_bracket_end(text, cursor, end)
            if close is None:
                return cursor
            cursor = close
            continue
        break
    return cursor


_IDENTIFIER_WORD_RE = re.compile(r"[A-Za-z0-9_\x80-\xff]+")

#: SQL whitespace and punctuation that end a table/column identifier.  PHP
#: concatenation is a different language layer and is handled by
#: :func:`_skip_concat`, so a static prefix may continue across it.
_SQL_IDENTIFIER_BREAK = frozenset(" \t\r\n,;()[]=<>!|")

#: A literal that ends exactly at its closing quote continues into the next
#: PHP concatenation only when its trailing text is still an INCOMPLETE
#: identifier: a WordPress-style prefix (``wp_``), a qualified name awaiting
#: its last segment (``wp_posts.``) or an interpolated expression
#: (``{$wpdb->prefix}``).  A completed static word is the table name itself;
#: a tainted value appended after it starts another clause
#: (``"SELECT * FROM wp_users" . $where``), never the identifier (SCAN5 FP).
_IDENTIFIER_CONTINUATION = frozenset("_.}]")


def _identifier_literal_request(text: str, start: int, close: int,
                                quote: str, tainted: set[str], *,
                                skip_leading_ws: bool) -> str:
    """Classify the identifier text inside one literal.

    ``"dynamic"`` — request data supplies the identifier; ``"static"`` — the
    identifier ended in static text or SQL punctuation, including a complete
    table name that reaches the closing quote; ``"prefix"`` — the literal
    body ended inside an INCOMPLETE identifier (a following PHP
    concatenation may continue it); ``"empty"`` — the body was only the
    keyword separator, so the next segment still starts before the
    identifier.  Single quotes never interpolate; double quotes/heredocs
    honour ``\\$`` parity (SCAN6).

    ``skip_leading_ws`` is set only while no identifier text has been seen:
    whitespace after a prefix ends the expression, while whitespace between
    the keyword and the identifier is just the separator.
    """
    limit = close - 1
    index = start
    if skip_leading_ws:
        index = _skip_sql_comment_ws(text, index, limit)
        index = _skip_sql_identifier_modifiers(text, index, limit)
        index = _skip_sql_comment_ws(text, index, limit)
        if index >= limit:
            return "empty"
    interpolates = quote in "\"`"
    saw_text = False
    last_kind = "static"
    tail = ""
    while index < limit:
        char = text[index]
        if char in _SQL_IDENTIFIER_BREAK:
            return "static"
        if not interpolates:
            saw_text = True
            last_kind = "static"
            tail = char
            index += 1
            continue
        if char == "\\":
            # An escaped character is literal text; the escaped byte is the
            # identifier's tail, not the backslash.
            if index + 1 < limit:
                saw_text = True
                last_kind = "static"
                tail = text[index + 1]
            index += 2
            continue
        if char == "$":
            if _dollar_escaped(text, index):
                saw_text = True
                last_kind = "static"
                tail = "$"
                index += 1
                continue
            if text.startswith("${", index):
                braced_end = _braced_end(text, index, limit)
                if braced_end is None:
                    return "static"
                if _braced_reference_request(
                        text[index + 2:braced_end - 1], tainted):
                    return "dynamic"
                # An accessor AFTER ``}`` is literal text inside a string:
                # ``"${'_SERVER'}['HTTP_HOST']"`` renders ``Array[...]``.
                index = _skip_accessors(text, braced_end, limit)
                saw_text = True
                last_kind = "dynamic"
                tail = "}"
                continue
            match = _VAR_RE.match(text, index)
            if match is None:
                saw_text = True
                last_kind = "static"
                tail = char
                index += 1
                continue
            name = match.group(1)
            if _request_name(name, text, index, tainted):
                return "dynamic"
            index = _skip_accessors(text, match.end(), limit)
            # A non-request expression is still dynamic text: a suffix
            # concatenated after it may complete the same identifier.
            saw_text = True
            last_kind = "dynamic"
            tail = "}"
            continue
        if char == "{":
            if not text.startswith("{$", index):
                saw_text = True
                last_kind = "static"
                tail = char
                index += 1
                continue
            bracket_end = _matching_bracket_end(text, index, limit)
            if bracket_end is None:
                return "static"
            if _identifier_expression_request(
                    text, index + 1, bracket_end - 1, tainted):
                return "dynamic"
            index = bracket_end
            saw_text = True
            last_kind = "dynamic"
            tail = "}"
            continue
        saw_text = True
        last_kind = "static"
        tail = char
        index += 1
    if not saw_text:
        return "empty"
    if last_kind == "dynamic" or tail in _IDENTIFIER_CONTINUATION:
        return "prefix"
    if tail == "`":
        # A literal may END inside an identifier's opening backtick:
        # ``"SELECT * FROM `" . $t . "`"`` (or the SINGLE-quoted twin,
        # which never interpolates but carries the same backtick text).
        # An ODD count means the quote is still open in the SQL identifier
        # and the following concatenation completes it.  The complete
        # ``"`wp_users`"`` form has an even count and stays a finished
        # static identifier.
        count = 0
        escaped = False
        for pos in range(start, limit):
            char = text[pos]
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == "`":
                count += 1
        if count % 2 == 1:
            return "prefix"
    # A complete static identifier ends HERE: text after the closing quote
    # starts another clause, not the same table/column token (SCAN5 FP).
    return "static"


def _skip_sql_comment_ws(text: str, index: int, end: int) -> int:
    """Skip SQL whitespace AND comments at an identifier position.

    MySQL treats ``/*x*/`` and ``-- ...``/``# ...`` as whitespace, so
    ``SELECT * FROM /*x*/ $t`` names the same dynamic table as the spaced
    form.  The scanner previously saw the ``/`` and stopped, silently
    dropping the identifier finding (R15-P2).

    The lexical rule itself lives in :func:`_sql_comment_end` (ONE owner);
    this helper only consumes its span and skips the line terminator, so
    ``#[x]`` stays live (the owner's deliberate exception) and a trailing
    ``--`` is a comment to end-of-text exactly as the owner says.
    """
    while index < end:
        if text[index] in " \t\r\n":
            index += 1
            continue
        stop = _sql_comment_end(text, index)
        if stop is None or stop <= index:
            break
        index = min(stop, end)
        # The owner returns the line terminator for ``--``/``#`` comments;
        # old callers advanced past it, so keep that offset contract.
        if index < end and text[index] in "\r\n":
            index += 1
    return index


def _identifier_expression_request(text: str, start: int, end: int,
                                   tainted: set[str], *,
                                   allow_leading_ws: bool = True) -> bool:
    """Is the identifier expression at ``start`` supplied by request data?

    The identifier is a PHP EXPRESSION, not one token: static text adjacent
    to interpolation (``wp_$table``), a braced prefix
    (``{$wpdb->prefix}$table``), and a concatenation
    (``" . $wpdb->prefix . $table``) all name the same dynamic identifier
    (SCAN5).  Static string segments are traversed too, so
    ``'SELECT * FROM wp_' . $table`` continues across the quote.  A static
    table followed by SQL whitespace (``wp_users WHERE``) or by the closing
    quote of a COMPLETE identifier (``"SELECT * FROM wp_users" . $where``)
    ends the expression, so a tainted VALUE or another clause is never read
    as the table name.  ``\\$`` parity is honoured (SCAN6).
    """
    index = _skip_sql_comment_ws(text, start, end)
    while index < end:
        if text[index] not in ".+":
            break
        # A literal that ended right after the keyword is joined to the
        # identifier by its own concatenation operator.
        index = _skip_sql_comment_ws(text, index + 1, end)
    index = _skip_sql_identifier_modifiers(text, index, end)
    index = _skip_sql_comment_ws(text, index, end)
    while index < end:
        char = text[index]
        if char in "'\"`":
            close = _php_string_end(
                text, index, interpolation_aware=char in "\"`")
            if close is None or close > end:
                return False
            inside = _identifier_literal_request(
                text, index + 1, close, char, tainted,
                skip_leading_ws=allow_leading_ws)
            if inside == "dynamic":
                return True
            if inside == "static":
                return False
            allow_leading_ws = inside == "empty"
            index = close
        elif char == "$":
            if _dollar_escaped(text, index):
                # A literal dollar in an interpolating string: the following
                # text is static, not a variable read.
                index += 1
                continue
            if text.startswith("${", index):
                braced_end = _braced_end(text, index, end)
                if braced_end is None:
                    return False
                if _braced_reference_request(
                        text[index + 2:braced_end - 1], tainted):
                    return True
                if _braced_server_accessor_request(
                        text, index, braced_end, end):
                    return True
                index = _skip_accessors(text, braced_end, end)
                allow_leading_ws = False
                if index < end and (text[index] == "$"
                                    or text.startswith("${", index)
                                    or text.startswith("{$", index)):
                    continue
                nxt = _skip_concat(text, index, end)
                if nxt is None:
                    return False
                index = nxt
                continue
            match = _VAR_RE.match(text, index)
            if match is None:
                return False
            name = match.group(1)
            if _request_name(name, text, index, tainted):
                return True
            index = _skip_accessors(text, match.end(), end)
            allow_leading_ws = False
            if index < end and (text[index] == "$"
                                or text.startswith("{$", index)):
                continue
        elif char == "(":
            # A parenthesized concatenation is the same expression:
            # ``"SELECT * FROM " . ($t)``.  Recurse into the balanced group
            # and then continue the surrounding concatenation.
            close = _argument_end(text, index, end)
            if close >= end:
                return False
            if _identifier_expression_request(
                    text, index + 1, close, tainted):
                return True
            index = close + 1
            allow_leading_ws = False
            nxt = _skip_concat(text, index, end)
            if nxt is None:
                return False
            index = nxt
            continue
        elif char == "{":
            if not text.startswith("{$", index):
                return False
            close = _matching_bracket_end(text, index, end)
            if close is None:
                return False
            if _identifier_expression_request(
                    text, index + 1, close - 1, tainted):
                return True
            index = close
            allow_leading_ws = False
            if index < end and (text[index] == "$"
                                or text.startswith("{$", index)):
                continue
        else:
            match = _IDENTIFIER_WORD_RE.match(text, index)
            if match is None:
                return False
            index = match.end()
            allow_leading_ws = False
            # Adjacent interpolation belongs to the SAME identifier token.
            if index < end and (text[index] == "$"
                                or text.startswith("{$", index)):
                continue
        nxt = _skip_concat(text, index, end)
        if nxt is None:
            return False
        index = nxt
    return False


def _identifier_after_literal(text: str, keyword_end: int,
                              literal: tuple[int, int, str],
                              statement_end: int,
                              tainted: set[str]) -> bool:
    """Is the identifier after a keyword inside ``literal`` dynamic?

    ``'SELECT * FROM ' . $_GET['t']``: the literal ends right after the
    keyword, so the identifier comes from the concatenated expression.
    ``'SELECT * FROM $table'``: the remainder is LITERAL text (single quotes
    never interpolate), so the variable-looking token is static and silent.
    ``'SELECT * FROM wp_' . $table``: the static prefix continues across a
    concatenation until SQL whitespace or request data ends it (SCAN5/N3).
    """
    _open, close, quote = literal
    inside = _identifier_literal_request(
        text, keyword_end, close, quote, tainted, skip_leading_ws=True)
    if inside == "dynamic":
        return True
    if inside == "static":
        return False
    return _identifier_expression_request(
        text, close, statement_end, tainted,
        allow_leading_ws=inside == "empty")


def _prepare_argument(text: str, open_index: int, close: int, *,
                      spans: list[tuple[int, int, str]] | None = None,
                      opens: list[int] | None = None) -> tuple[bool, str]:
    """``(is_prepare, request-relevant expression)`` for one sink argument.

    ``$wpdb->query($wpdb->prepare("... %d", $_GET['id']))`` is exactly the
    parameterized pattern the check recommends: request data in the prepare
    ARGUMENTS AFTER the first is bound.  The FIRST argument is the query
    TEXT itself — concatenating request data into it is still injection —
    and anything concatenated AFTER the prepare call also still injects
    (SCAN1).  ``->prepare``/``::prepare`` themselves stay non-sinks.
    Enclosing parentheses and a wrapping call are stripped/searched so the
    gate survives the shapes PHP accepts (R6-18).
    """
    arg_start = open_index + 1
    arg = text[arg_start:close]
    relevant = _prepare_relevant(text, arg_start, close, spans=spans,
                                 opens=opens)
    if relevant is None:
        return False, arg
    return True, relevant


def _first_argument_end(text: str, start: int, close: int) -> int:
    """Offset of the first top-level ``,`` in ``start..close`` (or close).

    Every PHP STRING shape is skipped, including a backtick shell-command
    string: ``prepare(`printf '%s', ...`, 1)`` contains a comma that is not
    an argument separator, and stopping there made the first argument look
    like a literal and hid real injection (R6-47).  Line comments use the
    shared ``?>``-aware stopper, like every other view.
    """
    depth = 0
    index = start
    while index < close:
        char = text[index]
        if text.startswith("<<<", index):
            end, _interpolates = _php_heredoc_end(text, index)
            if end is None:
                return close
            index = end
            continue
        if char in "'\"":
            end = _php_string_end(text, index, interpolation_aware=True)
            if end is None:
                return close
            index = end
            continue
        if char == "`":
            end = _php_backtick_end(text, index)
            if end is None:
                return close
            index = end
            continue
        if text.startswith("//", index) or (
                char == "#" and not text.startswith("#[", index)):
            stop = _php_comment_stop(text, index)
            if stop >= close or text.startswith("?>", stop):
                return close
            index = stop + 1
            continue
        if text.startswith("/*", index):
            stop = text.find("*/", index + 2)
            index = close if stop == -1 else stop + 2
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                return index
            depth -= 1
        elif char == "," and depth == 0:
            return index
        index += 1
    return close


def _contains_request(segment: str, tainted: set[str],
                      aliases: dict[str, str] | None = None) -> bool:
    """Does ``segment`` carry a request superglobal or a tainted variable?

    Comments and non-interpolating literals are removed first (a trailing
    ``// $_GET`` or a literal ``'$_GET'`` cannot taint an otherwise safe
    line); a double-quoted ``"... $_GET[id]"`` interpolates at runtime and
    therefore still counts.  ``aliases`` resolves ``${$n}`` indirection to
    the statically assigned name it selects.
    """
    clean = _request_mask(segment, aliases)
    if _REQUEST_RE.search(clean):
        return True
    return any(name in tainted for name in _VAR_RE.findall(clean))


def _has_sanitizer(text: str, flags: bytearray, start: int, end: int) -> bool:
    """A clear sanitizer call in executable code within the statement."""
    for match in _SANITIZER_RE.finditer(text, start, end):
        if flags[match.start()] == 1 and not _php_member_before(
                text, match.start()):
            return True
    return False


def _add(matches: dict[str, list[tuple[str, int, int, str]]],
         name: str, path: str, line: int, column: int, sink: str) -> None:
    matches.setdefault(name, []).append((path, line, column, sink))


def _check(deadline: Deadline | None, context: str) -> None:
    if deadline is not None:
        deadline.check(context)


def _scan_file(text: str, path: str, settings: Settings,
               matches: dict[str, list[tuple[str, int, int, str]]],
               deadline: Deadline | None = None) -> None:
    """Lex one file and record every trusted match per class.

    Every file -- whatever its size -- is subject to the SAME run deadline:
    a small file can still be SQL/keyword-dense enough to exhaust the
    budget, and an expired run must never answer "clean".  Each phase and
    each match iteration checks the deadline, so the check is never only at
    the batch boundary.
    """
    _check(deadline, "source scan file")
    # ONE lexer pass produces the executable-code flags, the REAL open-tag
    # offsets and the PHP-mode map.  Every SQL view below consumes that map;
    # no helper re-lexes a prefix per tag/keyword (SCAN-QUAD/SCAN-PHP-MODE).
    open_tags: list[int] = []
    php_mask = bytearray(len(text))
    _mask, flags, valid, _in_php = _php_lex(
        text, open_tags=open_tags, php_mask=php_mask)
    if not valid:
        # PHP would raise a parse error on this file; nothing in it runs, so
        # no signature in it is trustworthy.
        log.debug(
            "source scan: %s is not lexically valid PHP; skipped", path)
        _check(deadline, "source scan file end")
        return
    if deadline is not None:
        deadline.check("source scan taint")
    starts = _line_starts(text)
    # Whole-file statement boundaries ONCE: the taint pass and every sink
    # phase look their statement up with a bisect instead of rescanning the
    # file from each match (the per-assignment rescan was quadratic).
    statement_starts = _statement_starts(text, php_mask)
    aliases: dict[str, str] = {}
    tainted = _tainted_variables(
        text, flags, php_mask,
        statement_starts=statement_starts, deadline=deadline,
        aliases_out=aliases)
    _check(deadline, "source scan taint end")
    # Whole-file lexing ONCE: comments/nowdocs are blanked across physical
    # lines and string spans are known before any keyword is tested (SCAN3).
    sql_mask = _sql_mask(text, php_mask)
    # SQL comments are whitespace: blank them in a same-length view so a
    # commented clause mints no finding and a comment between grammar
    # tokens does not hide one.
    sql_view = _sql_comment_space(sql_mask)
    _check(deadline, "source scan sql view")
    # Comments are PHP whitespace: every executable-name/sink/member/
    # sanitizer regex runs on this same-length view so `$wpdb-> /*c*/ query`
    # is a sink and `$obj-> /*c*/ include` is a method, not an include.
    code_view = _comment_mask(text, php_mask)
    _check(deadline, "source scan comment view")
    literal_spans = _literal_spans(text, php_mask)
    _check(deadline, "source scan literal view")
    literal_opens = [span[0] for span in literal_spans]
    open_tag_set = set(open_tags)
    if deadline is not None:
        deadline.check("source scan views")

    # 1. session-fixation: the dangerous value is the ARGUMENT.
    _check(deadline, "source scan session")
    for match in _SESSION_RE.finditer(code_view):
        _check(deadline, "source scan session")
        if flags[match.start()] != 1 or _member_call(code_view, match.start()):
            continue
        open_index = text.find("(", match.start(), match.end())
        close = _argument_end(text, open_index)
        if _contains_request(text[open_index + 1:close], tainted, aliases):
            line = _line_at(starts, match.start())
            _add(matches, "session-fixation", path, line, match.start(),
                 f"{match.group(1).lower()}()")

    # 2. reflected-request: a statement-level sanitizer suppresses it.
    _check(deadline, "source scan output")
    for match in _OUTPUT_RE.finditer(code_view):
        _check(deadline, "source scan output")
        token = match.group(0)
        line = _line_at(starts, match.start())
        if token == "<?=":
            if not _is_open_echo_tag(match.start(), open_tag_set):
                continue
            # Only the tag's own output expression counts; the HTML text
            # before the tag is not PHP (a '#' there is not a comment) and a
            # '?>' inside the expression's strings is skipped.
            end = _statement_span(
                statement_starts, len(text), match.end())[1]
            carries_request = _contains_request(
                text[match.end():end], tainted, aliases)
            sanitizer_start = match.start()
        else:
            if flags[match.start()] != 1:
                continue
            # `$print`, `$obj->print(...)` and `X::print(...)` are names,
            # not the output construct; the `$`/member gate is the same one
            # every function sink uses.
            if _member_call(code_view, match.start()):
                continue
            # The whole statement, not the physical line: a sink may span
            # lines (`echo sprintf(\n '%s',\n $_GET['q']\n);`).
            end = _statement_span(
                statement_starts, len(text), match.end())[1]
            carries_request = _contains_request(
                text[match.end():end], tainted, aliases)
            sanitizer_start = match.start()
        if not carries_request:
            continue
        if _has_sanitizer(code_view, flags, sanitizer_start, end):
            continue
        _add(matches, "reflected-request", path, line, match.start(),
             token.lower())

    # 3. sql-injection: the sink's STATEMENT carries request data, and
    # ->prepare is deliberately absent as a sink.
    _check(deadline, "source scan sql sinks")
    for match in _SQL_SINKS_RE.finditer(code_view):
        _check(deadline, "source scan sql sinks")
        if flags[match.start()] != 1:
            continue
        token = match.group(0)
        if "->" not in token and "::" not in token \
                and _member_call(code_view, match.start()):
            continue
        line = _line_at(starts, match.start())
        end = _statement_span(
            statement_starts, len(text), match.end())[1]
        open_index = text.find("(", match.start(), match.end())
        if open_index == -1:
            expression = text[match.end():end]
        else:
            close = min(_argument_end(code_view, open_index), end)
            prepared, expression = _prepare_argument(
                code_view, open_index, close,
                spans=literal_spans, opens=literal_opens)
        if not _contains_request(expression, tainted, aliases):
            continue
        if "->" in token or "::" in token:
            separator = "->" if "->" in token else "::"
            method = token.split(separator, 1)[1].strip().rstrip("(").strip()
            sink = f"{separator}{method}()"
        else:
            sink = f"{token.split('(', 1)[0].strip().lower()}()"
        _add(matches, "sql-injection", path, line, match.start(), sink)

    # 4. sql-identifier: identifier position, never a value placeholder.
    #
    # ONE pass assigns every executable sink to its statement; the keyword
    # loop below then only tests membership instead of re-running the sink
    # regex over the whole statement per keyword (the SCAN-QUAD quadratic).
    # The SQL-context answer is likewise computed once per statement.
    _check(deadline, "source scan sql identifiers")
    sink_statement_starts: set[int] = set()
    for match in _SQL_SINKS_RE.finditer(code_view):
        if flags[match.start()] == 1:
            statement_start, _statement_finish = _statement_span(
                statement_starts, len(text), match.start())
            sink_statement_starts.add(statement_start)
    statement_has_sql_context: dict[int, bool] = {}
    literal_statement_context: dict[tuple[int, int], bool] = {}
    for match in _SQL_IDENTIFIER_RE.finditer(sql_view):
        _check(deadline, "source scan sql identifiers")
        line = _line_at(starts, match.start())
        # The keyword usually lives inside a quoted SQL string (single- or
        # double-quoted) or an interpolating heredoc.  The whole-file
        # SQL-TEXT view keeps those bodies and blanks comments/nowdocs
        # across lines, so `'SELECT * FROM ' . $_GET['t']` is visible while
        # a keyword in a multi-line comment stays dead.
        keyword = sql_view[match.start():match.end()]
        if not keyword.strip():
            continue
        literal = _enclosing_literal(
            literal_spans, literal_opens, match.start())
        if keyword.strip().upper() == "UPDATE":
            # English prose ("Please update ...") is not an UPDATE query.
            # A real UPDATE is either a code statement (grammar: target +
            # SET) or the FIRST SQL token of its literal (a following
            # ``;`` may separate statements); a word preceded by prose in
            # the same literal is just English (R11-P2-3), while an
            # incomplete prefix like ``"UPDATE wp_" . $t`` still counts
            # (SCAN5).
            if literal is not None:
                body_start = _sql_literal_body_start(sql_view, literal)
                prefix = sql_view[body_start:match.start()]
                # Wrappers/opening comments are not prose: ``/* hi */ UPDATE
                # ...`` and ``(UPDATE ...)`` are the same statement-initial
                # keyword as the unprefixed spelling.  A heredoc body starts
                # after its header (not at ``<<<``+1), and a CTE's
                # ``WITH ... UPDATE`` is still the same SQL statement
                # (R-15 residual).
                prefix = _strip_sql_statement_prefix(
                    _sql_comment_space(prefix.rsplit(";", 1)[-1]))
                if prefix.strip() and not _WITH_CTE_RE.match(prefix):
                    continue
            elif not _UPDATE_STATEMENT_RE.match(sql_mask, match.start()):
                continue
        # A keyword that is a variable/member name in EXECUTABLE code
        # (`$table`, `->update`, `User::update`) is not SQL; identifiers
        # only count inside SQL text or next to a real sink.
        keyword_in_code = flags[match.start()] == 1
        if keyword_in_code and _member_call(code_view, match.start()):
            continue
        # Statement context, not the physical line: `SELECT *\nFROM
        # $table` and a sink on the previous line are the same query.
        statement_start, statement_end = _statement_span(
            statement_starts, len(text), match.start())
        # A SQL identifier is actionable only in a live SQL context: a
        # sink in the statement, or a live literal that IS a SQL
        # statement (statement-initial verb after the last ``;``).  A bare
        # `"FROM $id"` doc string and a comment are not queries, and
        # English prose that happens to contain "select ... from" is not
        # one either.
        has_sink = statement_start in sink_statement_starts
        if not has_sink:
            if literal is not None:
                has_context = _sql_literal_statement_context(
                    sql_mask, literal, match.start(),
                    cache=literal_statement_context)
            else:
                has_context = statement_has_sql_context.get(statement_start)
                if has_context is None:
                    has_context = (
                        _SQL_CONTEXT_RE.search(
                            sql_mask, statement_start, statement_end) is not None
                        or _UPDATE_STATEMENT_RE.search(
                            sql_mask, statement_start, statement_end) is not None
                    )
                    statement_has_sql_context[statement_start] = has_context
            if not has_context:
                continue
        if keyword_in_code and not has_sink:
            # A bare code keyword (`update(`) with no SQL sink is a
            # function/method name, not a query fragment.
            continue
        # The identifier expression after the keyword decides.  A keyword
        # inside a single-quoted literal is literal SQL text; one inside an
        # interpolating literal/heredoc may carry interpolation; in code it
        # is a PHP expression.  A static table name followed by a tainted
        # VALUE (`wp_users WHERE id=$id`) is not an identifier sink.
        if literal is not None:
            supplied = _identifier_after_literal(
                text, match.end(), literal, statement_end, tainted)
        else:
            supplied = _identifier_expression_request(
                text, match.end(), statement_end, tainted)
        if not supplied:
            continue
        sink = " ".join(match.group(0).upper().split())
        _add(matches, "sql-identifier", path, line, match.start(), sink)

    # 5. file-include: only the include EXPRESSION counts.
    _check(deadline, "source scan includes")
    for match in _INCLUDE_RE.finditer(code_view):
        _check(deadline, "source scan includes")
        if flags[match.start()] != 1 or _member_call(code_view, match.start()):
            continue
        end = _statement_span(
            statement_starts, len(text), match.end())[1]
        if _contains_request(text[match.end():end], tainted, aliases):
            line = _line_at(starts, match.start())
            _add(matches, "file-include", path, line, match.start(),
                 match.group(0).lower())

    # 6. code-execution: the dangerous value is the ARGUMENT.
    _check(deadline, "source scan code execution")
    for match in _CODE_EXEC_RE.finditer(code_view):
        _check(deadline, "source scan code execution")
        if flags[match.start()] != 1 or _member_call(code_view, match.start()):
            continue
        open_index = text.find("(", match.start(), match.end())
        close = _argument_end(text, open_index)
        if _contains_request(text[open_index + 1:close], tainted, aliases):
            line = _line_at(starts, match.start())
            _add(matches, "code-execution", path, line, match.start(),
                 f"{match.group(0)[:match.group(0).find('(')].strip().lower()}()")

    # 7. unserialize-request: the dangerous value is the ARGUMENT.
    _check(deadline, "source scan unserialize")
    for match in _UNSERIALIZE_RE.finditer(code_view):
        _check(deadline, "source scan unserialize")
        if flags[match.start()] != 1 or _member_call(code_view, match.start()):
            continue
        open_index = text.find("(", match.start(), match.end())
        close = _argument_end(text, open_index)
        if _contains_request(text[open_index + 1:close], tainted, aliases):
            line = _line_at(starts, match.start())
            _add(matches, "unserialize-request", path, line, match.start(),
                 "unserialize()")

    # Never return a clean file after the budget expired inside the last
    # phase: the caller must turn this into scan-partial/rc 1.
    _check(deadline, "source scan file end")


def _detail(hits: list[tuple[str, int, int, str]], limit: int) -> str:
    """Up to ``limit`` ``path:line sink`` lines; ``(+N more)`` past it."""
    lines = [f"{path}:{line} {sink}"
             for path, line, _column, sink in hits[:limit]]
    if len(hits) > limit:
        lines.append(f"(+{len(hits) - limit} more)")
    return "\n".join(lines)


def _findings(matches: dict[str, list[tuple[str, int, int, str]]],
              limit: int) -> list[Finding]:
    """One aggregate Finding per class with matches, in contract order."""
    findings: list[Finding] = []
    for name, risk, fix in _CLASSES:
        hits = matches.get(name)
        if not hits:
            continue
        # Deterministic file/line order, then match position (two sinks on
        # one line), then the rendered label.
        hits.sort(key=lambda hit: (hit[0], hit[1], hit[2], hit[3]))
        findings.append(Finding(
            category=_CATEGORY,
            name=name,
            detail=_detail(hits, limit),
            bytes=0,
            count=len(hits),
            risk=risk,
            fix=fix,
        ))
    return findings


def _scan_batches(
    data: AuditData,
    scan_list: list[Entry],
    settings: Settings,
) -> tuple[dict[str, list[tuple[str, int, int, str]]], int, str | None]:
    """Scan the candidates in read batches.

    Returns ``(matches, files read, partial reason)``.  Per batch: the
    deadline first, then ONE ``read_many``; the deadline is checked before
    and after EVERY file and after the batch (including the last).
    Per-path failures skip with a debug line and count toward the breaker;
    a ``read_many`` raise is run-level and propagates.  Deadline expiry and
    the breaker both return the matches verified so far with ONE warning and
    a non-None reason, so the command can never report a truncated scan as a
    clean pass.
    """
    matches: dict[str, list[tuple[str, int, int, str]]] = {}
    scanned = 0
    unreadable = 0
    bound_skips = 0
    deadline = data.deadline
    max_bytes = settings.source_scan.max_file_bytes
    try:
        for start in range(0, len(scan_list), _READ_BATCH):
            if deadline is not None:
                deadline.check("source scan")
            batch = scan_list[start:start + _READ_BATCH]
            # The bound rides the READ, not a post-read length check: a
            # listing that understates a 2 MiB body must not materialize it
            # (FTP/zip connectors stop at max_bytes + 1).
            ok, failed = data.source.read_many(
                [entry.path for entry in batch], max_bytes=max_bytes)
            for entry in batch:
                # Before AND after every file, whatever its size: an
                # expired budget inside one small SQL-dense file must not
                # be hidden until the next batch (SCAN-QUAD).
                _check(deadline, "source scan file")
                if entry.path in ok:
                    unreadable = 0
                    raw = ok[entry.path]
                    if len(raw) > max_bytes:
                        # A connector that ignored the bound (an in-memory
                        # double): the body is already materialized, so this
                        # is a KNOWN skip and the scan is partial, never a
                        # clean pass.
                        bound_skips += 1
                        log.warning(
                            "source scan: %s read %d B over the %d B limit; "
                            "skipped (scan partial)", entry.path, len(raw),
                            max_bytes,
                        )
                        _check(deadline, "source scan file")
                        continue
                    scanned += 1
                    _scan_file(
                        raw.decode("utf-8", errors="replace"),
                        entry.path, settings, matches, deadline,
                    )
                    _check(deadline, "source scan file")
                    continue
                # A failed-map entry — or a path in neither map (a contract
                # violation: no bytes came back either way) — is a read
                # failure, never a guess.
                error = failed.get(entry.path, "no read result")
                if "read bound" in error:
                    # The bounded read stopped before materializing a body
                    # whose LISTING lied about its size: a KNOWN skip, and
                    # the run reports scan-partial rather than "clean".
                    bound_skips += 1
                    log.warning(
                        "source scan: %s exceeded the %d B read bound; "
                        "skipped (scan partial)", entry.path, max_bytes,
                    )
                    unreadable = 0
                    _check(deadline, "source scan file")
                    continue
                log.debug(
                    "source scan: %s unreadable, skipped: %s",
                    entry.path, error,
                )
                unreadable += 1
                if unreadable >= _CONSECUTIVE_UNREADABLE:
                    log.warning(
                        "source scan aborted after %d consecutive "
                        "unreadable files; results are partial",
                        _CONSECUTIVE_UNREADABLE,
                    )
                    return (matches, scanned,
                            f"aborted after {_CONSECUTIVE_UNREADABLE} "
                            "consecutive unreadable files")
                _check(deadline, "source scan file")
            # Including the LAST batch: expiry during its final file (or
            # after it) must still produce scan-partial, never a clean rc 0.
            _check(deadline, "source scan batch")
    except DeadlineExceeded:
        log.warning(
            "source scan stopped: run deadline exceeded; results are partial"
        )
        return matches, scanned, "run deadline exceeded"
    if bound_skips:
        return (matches, scanned,
                f"{bound_skips} file(s) exceeded the "
                f"{max_bytes}-byte read bound and were not scanned")
    return matches, scanned, None


@register_check(_CATEGORY, applies=("ftp", "local"))
def check_security_source_patterns(
    data: AuditData, settings: Settings
) -> list[Finding]:
    """Dangerous request-data flows in executable PHP, one finding per class.

    Candidate scope, batching, deadline partials, the read-failure breaker
    and the PHP-aware match gate are documented in this module's docstring.
    A missing source or an empty candidate set is silent with one debug line
    (unknown), never a clean-pass claim.  ``settings`` is read only for
    ``source_scan`` and the executable-extension set.
    """
    if data.source is None:
        log.debug(
            "source scan: no content source; %d walked entrie(s) unread",
            len(data.entries),
        )
        return []
    scan_list = _candidates(data.entries, settings)
    if not scan_list:
        log.debug(
            "source scan: no candidate PHP file in %d walked entrie(s)",
            len(data.entries),
        )
        return []
    matches, scanned, partial = _scan_batches(data, scan_list, settings)
    findings = _findings(matches, settings.source_scan.detail_limit)
    if partial is not None:
        # A truncated security scan is a BLIND SPOT, not a clean result.
        # The marker is a finding so it reaches the audit report too; the
        # `scan` command turns it into rc 1 (a security gate that ran out
        # of budget must not answer success).
        findings.append(Finding(
            category=_CATEGORY,
            name="scan-partial",
            detail=(
                f"scan incomplete: {partial}; only {scanned} of "
                f"{len(scan_list)} candidate file(s) were read"
            ),
            count=1,
            risk="medium",
            fix=(
                "re-run with a larger --deadline or after restoring the "
                "FTP channel; this report covers only the files read"
            ),
        ))
    log.info(
        "source scan: %d file(s) scanned, %d finding(s)%s",
        scanned, len(findings),
        " — PARTIAL" if partial is not None else "",
    )
    return findings
