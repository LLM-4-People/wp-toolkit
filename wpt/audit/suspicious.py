"""Suspicious-code audit check: backdoor signatures in executable WordPress PHP.

``security.suspicious`` — hacked-site triage over file CONTENTS: every PHP
file WordPress would execute, plus the directories backdoors are documented
to hide in, is fetched through the lazy content seam in READ BATCHES
(``data.source.read_many`` — the gather's Source, both modes: the FTP source
serves a batch from its parallel-read pool (settings
``ftp.parallel_reads``), ZipSource and every other source from the serial
``read_bytes`` default, so the check is transport-agnostic and behaves
identically everywhere) and matched against a high-precision signature
list.  The list is CONSERVATIVE by design: a false positive burns operator
trust far faster than a rare miss, so every shipped pattern pins a call
SHAPE that can PROVE execution (``eval(base64_decode(``, ``eval($_POST``,
a superglobal assigned then evaluated on the same line, a
``$GLOBALS['x']($...)`` dynamic-call backdoor), never a bare token and
never a construct that modern PHP merely tolerates.

SCOPE (Sucuri incident research + WordPress core's own load order): the
scanned set is ``wp-content/{plugins,themes,mu-plugins,uploads}/**/*.php``
— mu-plugins and uploads are where published WordPress backdoors actually
land — every ``wp-content/*.php`` drop-in (db.php, object-cache.php,
sunrise.php, …, which core auto-loads), and webroot ``*.php`` including
wp-config.php.  Dotfiles with no PHP suffix are scanned too (a misspelt
``.htacces`` was a documented payload) except the known config dotfiles,
which hold no PHP and would only cost a read.  ``wp-includes/`` stays out:
core integrity is ``core.integrity``'s job with real hash comparison, and a
text signature there proves nothing.

CODE-ONLY MATCHING (binding): a match counts only when at least one
character of it is EXECUTABLE PHP.  The same bytes inside a comment, a
docblock, a string literal or a heredoc body are data the loader never runs,
and reporting them sends operators chasing their own source — so the scan
is PHP-aware (wpt.audit.security ``_php_code_mask``) and a hit whose span
lies entirely in non-code is dropped.  A cheap raw pass runs first, so a
file with no raw match is never masked and the common case costs one regex
scan.  Consequence for tunables: a profile pattern that can only ever match
inside a string literal will never fire — patterns are expected to describe
code.

Tunables (settings section ``suspicious`` + wpt/data/profiles/default.json —
never literals in code):

* ``max_file_bytes`` — candidates strictly above this size are skipped with
  one debug line (silent at the default info level; obfuscated droppers are
  small, core-sized files are noise).  A file exactly at the limit IS
  scanned.  The gate runs when the batch list is built, so an oversized
  file is never fetched at all.
* ``patterns`` — regex strings compiled ONCE per check run as
  written — a pattern carries its own inline ``(?i)`` where it needs
  case-insensitivity, because PHP function names are case-insensitive while
  variables are not.  A malformed entry (not a string, or failing re.compile)
  is skipped with one error log (bad profile data must not kill the check)
  and the remaining patterns still apply.

Match semantics (binding): the decoded (utf-8, errors="replace") text is
searched line by line (1-based line numbers); each (file, pattern) pair
reports its FIRST matching CODE line number only, once — a file with hits
from several distinct patterns contributes one detail line per pattern.
The result is ONE aggregate Finding (name "suspicious-code"): count =
AFFECTED FILES, bytes = the sum of their entry sizes, detail = up to 8
``path:LINE label`` lines sorted by (path, line) with the house "(+N more)"
truncation marker, risk high.  The finding is a CANDIDATE, not a verdict:
no text signature is proof, so the fix says to verify against a clean copy.
Zero hits anywhere is silence ([]) — a clean scan is the normal result, and
this check has no per-check mode branch: both source modes audit the same
tree identically.

Batching (binding): the size-gated, sorted candidate list is chunked into
``_READ_BATCH`` (200) read batches; per batch the run deadline is checked
FIRST, then ONE ``read_many`` fetches the whole batch —
``ok: dict[path, bytes]`` carries the contents, ``failed:
dict[path, str-error]`` the per-path failures.  A per-path failure is the
batched twin of a read_bytes raise: skip with one debug log, count toward
the breaker.  A ``read_many`` RAISE is run-level (a dead transport, not a
dead file) and propagates to the audit runner, whose per-check containment
logs one error and skips the check — the check degrades per PATH, the
registry per CHECK.  200 is a structural constant, not a tunable: it
amortizes per-file round-trips over the pooled read path while bounding
the three costs a batch can run up — the reads a dead channel wastes
before the 25-failure breaker trips (at most one batch), the work past
an expired run deadline (the budget is re-checked before every batch),
and resident content (<= 200 x max_file_bytes, 200 MiB at the shipped
1 MiB cap).

Progress heartbeat [L15 — a live scan of ~1.6k files crawled ~11
minutes in complete silence]: per batch, once ``_HEARTBEAT_S`` has
elapsed since the last line, ONE info line — ``suspicious: scanned
X/Y file(s), N candidate(s) so far (Ts elapsed)``.  Log cadence only,
never behavior; structural, not a tunable (see _HEARTBEAT_S).

Degrade contract: a per-path read failure (read_many's failed map — a
SourceError/OSError under the serial default) skips that one file with a
debug log; an oversized candidate skips with a debug log; ``data.source``
None (hand-built AuditData — every gather sets the seam) means nothing
can be read: one debug line and [].  Determinism: candidates iterate
sorted by path, and batches are consecutive slices of that sorted list.

Consecutive-failure circuit breaker (the stale-FTP live lesson, mirrored
from core.integrity — the SAME bound and the SAME contract, not a
re-derivation): 25 consecutive unreadable entries — counted over batch
results, spanning batch boundaries; a read failure is a read failure
whether read_bytes raised it or read_many's failed map delivered it —
and the scan ABORTS with ONE warning ("suspicious scan aborted after 25
consecutive unreadable files; results are partial") and returns the
findings verified so far — partial verified results are real, the
warning carries the caveat, and a worst-case stale passive channel costs
at most one batch of reads instead of days.  Any ok entry resets the
counter.  The abort stops processing at the 25th failure and reads NO
further batch; the rest of the already-fetched batch is discarded
unprocessed.  An oversized candidate is a POLICY skip, not a health
signal — it is gated out before any read, so it neither counts toward
the bound nor breaks the consecutive chain.

Run deadline (the bulk-scan time bound): ``data.deadline`` (None =
unbounded; a wpt.deadline.Deadline built by the audit runner from ctx)
is checked before EVERY batch with the label "suspicious scan"; when the
budget is spent the raised DeadlineExceeded is caught around the batch
loop, logged as ONE warning ("suspicious scan stopped: run deadline
exceeded; results are partial") and the findings verified so far still
return — the same partial-results shape as the breaker abort.  A check
function NEVER lets the deadline escape as a raise: the bulk-scan
contract is warning + partials, not an error for the runner to contain.

Structural WordPress constants (fixed layout facts, NOT tunables): the
scanned prefixes ``wp-content/plugins/``, ``wp-content/themes/``,
``wp-content/mu-plugins/`` and ``wp-content/uploads/`` (prefix-anchored so a
sibling like ``wp-content/plugins-x/`` never matches), the drop-in prefix
``wp-content/``, ``.php`` (case-insensitive suffix), and the config dotfiles
skipped without a read.  The presentation limit 8 (detail
lines before the marker) is fixed by this check contract, not a tunable.

_PATTERN_LABELS mirrors the shipped default pattern list (keys are the
exact pattern strings from wpt/data/profiles/default.json) to give each hit a
short human label; a profile-supplied pattern that is not one of the
shipped defaults is labeled ``pattern[i]`` by its settings index.  The
mirror is cosmetic — drift can only degrade labels, never matching — and
is pinned by an exact contract test (tests/audit/test_suspicious.py).
Log lines carry paths, sizes and counts only, never matched file content.
"""

import bisect
import re
import time

from .data import AuditData
from .registry import register_check
from .security import _CODE_UNMODELLED, _php_code_flags
from ..log import get_logger
from ..settings import Settings
from ..types import DeadlineExceeded, Entry, Finding

log = get_logger("audit.suspicious")

# Structural WordPress constants (see module docstring).
_PLUGINS_PREFIX = "wp-content/plugins/"
_THEMES_PREFIX = "wp-content/themes/"
_MU_PLUGINS_PREFIX = "wp-content/mu-plugins/"
_UPLOADS_PREFIX = "wp-content/uploads/"
_LANGUAGES_PREFIX = "wp-content/languages/"
_CONTENT_PREFIX = "wp-content/"
_ADMIN_PREFIX = "wp-admin/"
_SCAN_ROOTS = (
    _PLUGINS_PREFIX, _THEMES_PREFIX, _MU_PLUGINS_PREFIX, _UPLOADS_PREFIX,
    _LANGUAGES_PREFIX, _ADMIN_PREFIX,
)
_PHP_SUFFIX = ".php"
#: Dotfiles that never carry executable PHP, so scanning them would spend a
#: read to find nothing.
_NON_PHP_DOTFILES = frozenset({".htaccess", ".user.ini", ".gitignore", ".keep"})

# Presentation limit fixed by this check contract (not a tunable).
_DETAIL_LINES = 8

#: Consecutive unreadable reads that abort the scan loop.  Structural,
#: not a tunable — the SAME bound and contract as core.integrity's
#: breaker (mirrored, not re-derived): a stale FTP passive channel
#: measured minutes PER FILE on a live run, so the scan gives up after
#: this many consecutive read failures and returns what it verified —
#: the abort warning carries the partial-results caveat.  Counted over
#: batch results (read_many's failed map), spanning batch boundaries.
_CONSECUTIVE_UNREADABLE = 25

#: read_many batch size — structural, not a tunable (see module
#: docstring): amortizes per-file round-trips over the pooled read path
#: while bounding dead-channel waste (at most one batch past the
#: breaker), deadline overshoot (one budget re-check per batch) and
#: resident content (batch x max_file_bytes).
_READ_BATCH = 200

#: Progress heartbeat spacing (seconds) for the batched scan [L15 — a
#: live FTP scan of ~1.6k plugin/theme files ran ~11 minutes with ZERO
#: log output; the operator could not tell a crawling channel from a
#: wedged run].  At every batch whose start is this far past the last
#: heartbeat (or the scan start), ONE info line reports scanned/total
#: and infected-so-far.  Log cadence only, never behavior — the
#: backup.py _HEARTBEAT_EVERY precedent — so it is structural, NOT a
#: settings tunable; module-level so tests can pin it to 0 and force a
#: line per batch.  The 10 s gate keeps every existing fast test silent.
_HEARTBEAT_S = 10.0

# Short human labels for the shipped default patterns (see module docstring;
# keys mirror wpt/data/profiles/default.json "suspicious"."patterns" exactly).
#: Only patterns that can PROVE execution belong here.  Dropped on evidence:
#: ``assert($_)`` (PHP 8 removed string evaluation in assert), the long
#: base64 blob (W3 Total Cache ships legitimate 344-char fixtures and a blob
#: alone proves no execution), ``preg_replace /e`` (a fatal error on PHP 7+,
#: not execution) and ``mail(..., Bcc:)`` (documented wp_mail/WooCommerce
#: functionality).  Each of those reported clean sites as compromised.
_PATTERN_LABELS: dict[str, str] = {
    r"(?i)eval\s*\(\s*\\?\s*(base64_decode|gzinflate|gzuncompress|str_rot13|urldecode)\s*\(":
        "eval(decoder)",
    r"(?i:eval)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\b": "eval(superglobal)",
    r"\$(\w+)\s*=\s*\$_[A-Z]+\[[^\]]*\](?:\s*\[[^\]]*\])*\s*;\s*(?i:eval)\s*\(\s*\$\1\s*\)":
        "superglobal-evaluated",
    r"\$GLOBALS\s*\[\s*['\"]\w+['\"]\s*\]\s*\(\s*\$": "$GLOBALS-call",
}

_FIX = (
    "Quarantine the file and investigate: executable code matched a known "
    "backdoor signature — a candidate, not a verdict. Verify the affected "
    "file against a clean copy of the same plugin/theme/drop-in, or the site "
    "itself for core files, and find the infection vector before restoring."
)


# ----------------------------------------------------------- shared internals


def _compile_patterns(patterns: list[str]) -> list[tuple[int, str, re.Pattern[str]]]:
    """(settings index, pattern text, compiled regex) in settings order.

    An entry that is not a string or fails re.compile is skipped with one
    error log carrying its index — bad profile data must not kill the check;
    the remaining patterns still apply.  Index and text are kept so hits
    label correctly around gaps.
    """
    compiled: list[tuple[int, str, re.Pattern[str]]] = []
    for index, text in enumerate(patterns):
        if not isinstance(text, str):
            log.error(
                "suspicious: pattern %d is not a string (got %s), skipped",
                index, type(text).__name__,
            )
            continue
        try:
            compiled.append((index, text, re.compile(text)))
        except re.error as exc:
            log.error(
                "suspicious: pattern %d is not a valid regex, skipped: %s",
                index, exc,
            )
    return compiled


def _label(index: int, pattern: str) -> str:
    """Human label for one matched pattern: the shipped-default label when
    the pattern text is one of the defaults, else ``pattern[i]``."""
    return _PATTERN_LABELS.get(pattern, f"pattern[{index}]")


def _is_candidate(entry: Entry) -> bool:
    """True for a non-directory entry WordPress would execute, or that a
    backdoor is documented to hide in.

    Sucuri's incident write-ups place WordPress backdoors overwhelmingly in
    ``wp-content/uploads/`` and ``wp-content/mu-plugins/``, and WordPress
    itself auto-loads mu-plugins, the ``wp-content/*.php`` drop-ins and
    ``wp-content/languages/*.php`` (locale files, included on demand), so the
    old plugins/themes-only scope missed the locations that matter most.
    ``wp-admin/`` is included as an entrypoint surface; ``core.integrity``
    remains the hash-based authority for it, but that check needs checksum
    data, and this one works from content alone.
    ``wp-includes/`` stays out: the same hash comparison owns it, and it is
    the one tree an attacker does not choose.

    Scope is decided BEFORE the dotfile rule, so a hidden file cannot slip past
    the prefix exclusions (``wp-includes/``, any other top-level directory).
    """
    if entry.is_dir or entry.is_link:
        # A symlink can point anywhere; the walker already skips most, and a
        # source that reports one must not have it read as site content.
        return False
    path = entry.path
    base = path.rsplit("/", 1)[-1]
    php = path.lower().endswith(_PHP_SUFFIX)
    # A hidden file with no PHP suffix still runs when requested directly (a
    # documented .htacces payload), except the known config dotfiles, which
    # hold no PHP and would only cost a read.
    hidden_payload = base.startswith(".") and not php \
        and base not in _NON_PHP_DOTFILES
    if path.startswith(_ADMIN_PREFIX):
        in_scope = php
    elif path.startswith(_CONTENT_PREFIX):
        # Every .php under wp-content/ at ANY depth, not just the six
        # well-known directories: an attacker writes wherever the web user can
        # write, and wp-content/cache/, wp-content/upgrade/ and any custom
        # directory are as reachable as uploads/. The hidden-payload allowance
        # is kept to this directory's TOP level, where WordPress auto-loads
        # drop-ins (db.php, object-cache.php, sunrise.php).
        rest = path[len(_CONTENT_PREFIX):]
        top_level = "/" not in rest
        # The hidden-payload allowance covers this directory's TOP level,
        # where WordPress auto-loads drop-ins (db.php, object-cache.php,
        # sunrise.php), and the six well-known roots at any depth, where
        # `uploads/.htacces` is a documented backdoor filename. An arbitrary
        # new subdirectory gets its .php files scanned, not its dotfiles.
        hidden_ok = hidden_payload and (top_level or path.startswith(_SCAN_ROOTS))
        in_scope = php or hidden_ok
    elif "/" not in path:
        # The webroot: wp-config.php and any other top-level PHP.
        in_scope = php or hidden_payload
    else:
        in_scope = False
    return in_scope


def _candidates(entries: list[Entry]) -> list[Entry]:
    """The scan set, path-sorted for reproducible batch order."""
    return sorted(
        (entry for entry in entries if _is_candidate(entry)),
        key=lambda entry: entry.path,
    )


def _is_member_call(text: str, flags: bytearray, start: int) -> bool:
    """True when the token at ``start`` is NOT the language construct: it
    follows ``->``/``?->``/``::`` as a method or static call, or is a variable
    callable (``$eval(...)`` calls a closure held in a variable).  PHP
    tokenizes ``$eval`` as a variable, so a literal ``$eval(base64_decode())``
    is ordinary code, not the construct.
    """
    seen: list[str] = []
    index = start - 1
    while index >= 0 and len(seen) < 3:
        char = text[index]
        if flags[index] and not char.isspace():
            if char == "$" and not seen:
                # Directly adjacent, so the name is part of the variable
                # (`$eval(...)`). A `${` further back is an interpolation
                # opener, and the construct after it still counts.
                return True
            seen.append(char)
        index -= 1
    preceding = "".join(reversed(seen))
    # A suffix test, not equality: the name of the receiver sits between the
    # `$` and the operator (`$o->`, `Foo::`, `$o?->`), and whitespace between
    # the operator and the name is tolerated.
    return any(preceding.endswith(operator) for operator in ("->", "::", "?->"))


def _has_comment(text: str) -> bool:
    """True when the file may contain a PHP comment of any of the three
    syntaxes. ``#`` appears in ordinary strings (colours, fragments) too, so
    this is deliberately permissive: it only decides whether a clean file is
    worth lexing."""
    return "//" in text or "/*" in text or "#" in text


def _raw_candidates(
    text: str,
    patterns: list[tuple[int, str, re.Pattern[str]]],
    line_source: str | None = None,
) -> list[tuple[int, int, int, int, str]]:
    """``(lineno, pattern index, start, end, pattern)`` for every match.

    Matching runs over ONE length-preserving view of the file in which every
    line break is replaced by the same number of spaces. Offsets therefore line
    up with the raw text and with the code mask, and because every shipped
    pattern bridges its tokens with ``\\s*``, a signature split across lines —
    the obvious way to hide one from a line scanner — is still found.

    A gap of pure whitespace across a line break is the only thing that can
    join two tokens: a string, an operator or a statement terminator is not
    whitespace, so this cannot join unrelated code across a line.
    """
    joined = _blank_line_breaks(text)
    starts = _line_starts(text if line_source is None else line_source)
    candidates: list[tuple[int, int, int, int, str]] = []
    for index, pattern_text, regex in patterns:
        for match in regex.finditer(joined):
            start = match.start()
            candidates.append((
                bisect.bisect_right(starts, start),
                index,
                start,
                match.end(),
                pattern_text,
            ))
    return candidates


def _blank_line_breaks(text: str) -> str:
    """The file with every CR/LF replaced by the same number of spaces."""
    if "\n" not in text and "\r" not in text:
        return text
    out: list[str] = []
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\r":
            out.append("  " if text.startswith("\r\n", index) else " ")
            index += 2 if text.startswith("\r\n", index) else 1
            continue
        if char == "\n":
            out.append(" ")
            index += 1
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _line_starts(text: str) -> list[int]:
    """Offset of the first character of every physical line."""
    starts = [0]
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\r":
            index += 2 if text.startswith("\r\n", index) else 1
            starts.append(index)
            continue
        if char == "\n":
            index += 1
            starts.append(index)
            continue
        index += 1
    return starts


def _scan_text(
    text: str, patterns: list[tuple[int, str, re.Pattern[str]]]
) -> list[tuple[int, int, str]]:
    """(lineno, settings index, label) for the first CODE hit of each pattern.

    A match is only reported when at least one character of it is executable
    PHP, so the same bytes quoted in a comment, a docblock, a string literal
    or a heredoc never become a finding — the loader never executes those,
    and a scanner that reports them sends operators chasing their own source
    code.  EVERY match on a line is considered, not just the first: a string
    before a real hit must not hide it.  The first CODE hit per pattern wins,
    exactly as the line scanner did.

    The cheap raw pass runs first and a file with no raw match is never
    lexed UNLESS it contains a comment, so the PHP-aware pass costs nothing
    on the clean majority. A comment may split a signature's tokens
    (``eval(/*x*/base64_decode(...))``, and PHP's third comment syntax is
    ``#``) so the raw pass cannot see it; the patterns are then re-run over the
    code mask, where the comment is blanked to spaces and the gap still
    matches.
    """
    candidates = _raw_candidates(text, patterns)
    flags = None
    if _has_comment(text):
        # A comment can split a signature's tokens (`eval(/*x*/base64_decode(`),
        # which the raw pass cannot see. This pass runs whenever a comment is
        # present — NOT only when the raw pass found nothing, because a decoy
        # elsewhere in the file would otherwise suppress the real signature —
        # and its candidates are merged, not replaced.
        bitmap, lexically_valid = _php_code_flags(text)
        if lexically_valid:
            flags = bitmap
            # The blanked text, rebuilt from the code bitmap: non-code becomes
            # a space, so `eval(/*x*/base64_decode(` reads as one call and the
            # pattern still matches across the comment.
            blanked = "".join(
                char if flag else " " for char, flag in zip(text, bitmap)
            )
            # Line numbers come from the ORIGINAL source: the blanked view
            # replaced non-code line breaks with spaces, so its own line
            # starts would attribute a match to the wrong line.
            candidates.extend(
                _raw_candidates(blanked, patterns, line_source=text)
            )
    if not candidates:
        return []
    if flags is None:
        flags, lexically_valid = _php_code_flags(text)
    if not lexically_valid:
        # The file ends inside a string/comment/heredoc: PHP would raise a
        # parse error, so nothing in it is a trustworthy signature.
        log.debug(
            "suspicious: file is not lexically valid PHP; no signature trusted"
        )
        return []
    hits: list[tuple[int, int, str]] = []
    reported: set[int] = set()
    for lineno, index, start, end, pattern_text in candidates:
        if index in reported or not any(flags[start:end]):
            continue
        if not flags[start] or flags[start] == _CODE_UNMODELLED:
            # The match must BEGIN in executable code. With line breaks
            # bridged, a comment ending in `eval(` followed by a real
            # `base64_decode(` on the next line would otherwise join into a
            # signature that PHP never sees. The same applies to the
            # UNMODELLED marker: a region the lexer could not resolve may hold
            # only string text, and reporting it would break this check's
            # "executable code only" contract. The constant scanner still
            # fails closed on it.
            continue
        if _is_member_call(text, flags, start):
            # $obj->eval(...), Foo::eval(...) — a method, not the construct
            continue
        reported.add(index)
        hits.append((lineno, index, _label(index, pattern_text)))
    return hits


def _detail(hits: list[tuple[str, int, str]]) -> str:
    """Up to _DETAIL_LINES "path:LINE label" lines; "(+N more)" past it."""
    lines = [f"{path}:{lineno} {label}" for path, lineno, label in hits]
    if len(lines) <= _DETAIL_LINES:
        return "\n".join(lines)
    return "\n".join(lines[:_DETAIL_LINES]) + f"\n(+{len(lines) - _DETAIL_LINES} more)"


def _scan_batches(
    data: AuditData,
    scan_list: list[Entry],
    patterns: list[tuple[int, str, re.Pattern[str]]],
    max_bytes: int,
) -> tuple[list[tuple[str, int, str]], dict[str, int], int]:
    """Line-scan ``scan_list`` in ``_READ_BATCH`` ``read_many`` batches.

    Per batch: ``data.deadline`` (None = unbounded) is checked first,
    then ONE ``data.source.read_many`` fetches the batch — ``ok`` carries
    the bytes, ``failed`` the per-path errors.  ``max_bytes`` rides the
    READ (``read_bytes_bounded``), not a post-read length check: a listing
    that understates a file's body cannot materialize it.  Results process
    in batch order; the consecutive-failure counter spans batch boundaries,
    an ok entry resets it, and a failed-map entry is the read_bytes-era
    failure (debug skip + breaker count).  A ``read_many`` RAISE is
    run-level and propagates to the runner.  Both bounds funnel back the
    same way — ONE warning and the findings verified so far: the breaker
    aborts ON the 25th consecutive failure, the deadline at its raised
    DeadlineExceeded, which is caught here and never re-raised.
    """
    hits: list[tuple[str, int, str]] = []   # (path, first-hit line, label)
    affected: dict[str, int] = {}           # path -> entry size
    scanned = 0
    unreadable = 0                          # consecutive read failures
    deadline = data.deadline
    started = time.monotonic()
    last_beat = started
    total = len(scan_list)
    try:
        for start in range(0, len(scan_list), _READ_BATCH):
            if deadline is not None:
                deadline.check("suspicious scan")
            now = time.monotonic()
            if now - last_beat >= _HEARTBEAT_S:
                last_beat = now
                log.info(
                    "suspicious: scanned %d/%d file(s), %d candidate(s) so far "
                    "(%.0fs elapsed)",
                    scanned, total, len(affected), now - started,
                )
            batch = scan_list[start:start + _READ_BATCH]
            ok, failed = data.source.read_many(
                [entry.path for entry in batch], max_bytes=max_bytes
            )
            for entry in batch:
                if entry.path in ok:
                    raw = ok[entry.path]
                    unreadable = 0
                    scanned += 1
                    matched: set[int] = set()
                    for lineno, index, label in _scan_text(
                        raw.decode("utf-8", errors="replace"), patterns
                    ):
                        if index not in matched:
                            matched.add(index)
                            hits.append((entry.path, lineno, label))
                    if matched:
                        affected[entry.path] = entry.size
                    continue
                # A failed-map entry — or a path read_many returned in
                # neither map (contract violation: no bytes came back
                # either way, so it is a read failure, never a guess).
                error = failed.get(entry.path, "no read result")
                log.debug(
                    "suspicious: %s unreadable, skipped: %s",
                    entry.path, error,
                )
                unreadable += 1
                if unreadable >= _CONSECUTIVE_UNREADABLE:
                    log.warning(
                        "suspicious scan aborted after %d consecutive "
                        "unreadable files; results are partial",
                        _CONSECUTIVE_UNREADABLE,
                    )
                    return hits, affected, scanned
    except DeadlineExceeded:
        log.warning(
            "suspicious scan stopped: run deadline exceeded; "
            "results are partial"
        )
    return hits, affected, scanned


# ------------------------------------------------------------------- checks


@register_check("security.suspicious", applies=("ftp", "local"))
def check_security_suspicious(data: AuditData, settings: Settings) -> list[Finding]:
    """Backdoor signatures in executable WordPress PHP: ONE aggregate finding.

    Size-gated candidates are line-scanned against
    settings.suspicious.patterns in ``_READ_BATCH`` ``read_many`` batches:
    per-path failures skip with a debug log and count toward the
    25-consecutive-failure breaker (ONE warning + partial findings on
    abort), and the run deadline is checked before every batch (ONE
    warning + partial findings on expiry — the check never raises the
    deadline back).  A tree with zero hits stays silent.
    """
    patterns = _compile_patterns(settings.suspicious.patterns)
    candidates = _candidates(data.entries)
    if data.source is None:
        # Hand-built AuditData (every gather sets the seam): without the
        # content source nothing can be read — silence, never a guess.
        log.debug(
            "suspicious: no content source; %d candidate file(s) unread",
            len(candidates),
        )
        return []
    if not patterns:
        log.debug(
            "suspicious: no patterns configured; %d candidate file(s) skipped",
            len(candidates),
        )
        return []
    max_bytes = settings.suspicious.max_file_bytes
    scan_list: list[Entry] = []
    for entry in candidates:
        if entry.size > max_bytes:
            # Policy skip, not a health signal: gated out before any
            # read, so it neither counts toward the breaker bound nor
            # breaks the consecutive chain.
            log.debug(
                "suspicious: %s skipped, %d B over the %d B limit",
                entry.path, entry.size, max_bytes,
            )
            continue
        scan_list.append(entry)
    hits, affected, scanned = _scan_batches(data, scan_list, patterns,
                                            max_bytes)
    log.debug(
        "suspicious: scanned %d file(s) against %d pattern(s): %d candidate(s)",
        scanned, len(patterns), len(affected),
    )
    if not affected:
        return []
    hits.sort(key=lambda hit: (hit[0], hit[1]))
    log.info(
        "suspicious: %d scanned file(s) matched a backdoor signature "
        "(%d distinct hit(s))",
        len(affected), len(hits),
    )
    return [
        Finding(
            category="security.suspicious",
            name="suspicious-code",
            detail=_detail(hits),
            bytes=sum(affected.values()),
            count=len(affected),
            risk="high",
            fix=_FIX,
        )
    ]
