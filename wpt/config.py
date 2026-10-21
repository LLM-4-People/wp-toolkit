"""Credential resolution and redaction.

Passwords come from environment variables (or a prompt); redact() is applied to every
payload that might reach a log line or a report.
"""

import getpass
import os
import re
from typing import Any

from .types import WptError

SECRET_KEY_RE = re.compile(r"(?i)(pass|pwd|secret|token|key|authorization)")

#: Credential-word prefixes that may be concatenated with a bare ``key`` in
#: one identifier (``apikey``, ``dbpassword``, ``privatekey``).  The tail is
#: checked explicitly instead of broadening ``key`` to every word: that is
#: what keeps ``monkey`` inert.
_SECRET_KEY_PREFIXES = (
    "db", "user", "admin", "api", "private", "access", "signing",
    "client", "secret", "auth", "encryption", "master", "ssh", "tls", "ssl",
)


def is_secret_key(key: Any) -> bool:
    """Does one key NAME denote a credential slot?

    THE key-shape owner shared by :func:`redact` and both free-text
    scanners.  A keyword counts at the start, after ``_`` (the historical
    snake_case shape), or at a CAMEL-CASE boundary (``accessToken``,
    ``apiKey``) — but not inside an ordinary word (``monkey``), which the
    old regex deliberately left alone.
    """
    if not isinstance(key, str) or not key:
        return False
    lower = key.lower()
    # Case-insensitive compound credentials whose secret word is the tail.
    # ``apikey``/``APIKEY`` and ``dbpassword``/``DBPASSWORD`` are ordinary
    # serialized/property spellings that have no underscore or camel-case
    # boundary; the explicit prefixes keep ``monkey`` out.
    if lower.endswith(("password", "passwd", "apikey", "secret", "token")):
        return True
    if lower.endswith("key") and lower.startswith(_SECRET_KEY_PREFIXES):
        return True
    for match in SECRET_KEY_RE.finditer(key):
        start = match.start()
        end = match.end()
        if start == 0 or key[start - 1] in "_-":
            return True
        if key[start].isupper() and (
                key[start - 1].islower() or key[start - 1].isdigit()):
            return True
        # An UPPERCASE acronym run followed by a capitalised word is still a
        # word boundary: APIKey / DBPassword (R16 residual).  All-caps
        # ordinary words (MONKEY) have no following lowercase letter and
        # stay untouched.
        if key[start].isupper() and key[start - 1].isupper() \
                and any(char.islower() for char in match.group(0)):
            return True
        # Lowercase compounds whose SECRET word is the whole tail are
        # credential names (clientsecret); "key" is deliberately excluded
        # because monkey is an ordinary word.
        if end == len(key) and match.group(0).lower() in {
                "secret", "token", "pass", "pwd", "authorization"}:
            return True
    return False
# The Authorization header's ENTIRE value is a credential — handle it whole
# (a generic \S+ value grab would stop at the "Bearer"/"Basic" keyword and
# leave the token itself behind).
_AUTH_HEADER_RE = re.compile(r"(?i)\b(authorization)\b\s*[:=]\s*[^\r\n]+")
#: ONE escape grammar for secret-key spellings, shared by the assignment
#: regex (which must match the raw key) and the decoder (which must resolve
#: it).  PHP evaluates ``\160assword`` and ``\u{70}assword`` as ``password``
#: exactly like JSON's ``\u0070assword``; a grammar that knew only hex left
#: those keys unmatched and the value leaked.
_KEY_ESCAPE_BODY = (
    r"u\{[0-9A-Fa-f]{1,6}\}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}"
    r"|x[0-9A-Fa-f]{2}|[0-7]{1,3}"
)
_KEY_ESCAPE_TOKEN = r"\\" + r"(?:" + _KEY_ESCAPE_BODY + r")"
_KEY_ESCAPE_RE = re.compile(_KEY_ESCAPE_TOKEN)


def _decode_key_escapes(key: str) -> str:
    """Decode JSON/PHP escapes in a quoted key.

    ``json.loads('{"pass\\u0077ord": 1}')`` is ``password``; PHP's
    ``["\\160assword" => ...]`` and ``["\\u{70}assword" => ...]`` are the
    same key at runtime.  The assignment scanner saw the RAW escape text,
    so is_secret_key said no and the value leaked.  ONE grammar
    (:data:`_KEY_ESCAPE_BODY`) feeds both this decoder and the matching
    regex.
    """
    def repl(match: re.Match[str]) -> str:
        body = match.group(0)[1:]
        if body.startswith("u{"):
            code = int(body[2:-1], 16)
        elif body[:1] in ("u", "U", "x"):
            code = int(body[1:], 16)
        else:
            code = int(body, 8)
        if code > 0x10FFFF or 0xD800 <= code <= 0xDFFF:
            return match.group(0)
        return chr(code)
    return _KEY_ESCAPE_RE.sub(repl, key)



# A secret assignment.  The identifier may carry any number of PREFIX
# segments (`db_password`, `wordpress_db_password`, `my_db_password`) — a
# `\b` before the keyword fails after `_` because both characters are word
# characters, so the whole prefix is part of the matched key and the value is
# still redacted.  Python/JSON reprs quote the key and/or value
# (`{'password': 'x'}`, `"password": "x"`), so an optional quotation pair is
# part of the SAME assignment: without it the dict forms leaked verbatim.
# The VALUE is consumed by _secret_value_end, not by a regex alternative: a
# quoted string is parsed escape-aware, and a bytes/container value
# (`b'hunter2'`, `['aaa','bbb']`, `{'value': ...}`) is consumed as one
# balanced token.  A non-greedy `.*?` used to stop at the first quote/comma/
# brace and leak the rest of the container.
#: PHP whitespace AND comments between the pieces of one assignment.  A
#: comment between the key and ``=>`` (``['password' /*c*/ => 'x']``) is
#: whitespace to PHP, so the key/value scanner must look through it exactly
#: like the value-side ``_skip_php_trivia`` already does.
_PHP_KEY_TRIVIA = r"(?:\s|/\*[\s\S]*?\*/|//[^\r\n]*(?:\r\n|\r|\n|$)|\#[^\r\n]*(?:\r\n|\r|\n|$))*"

_SECRET_KEY_ASSIGN_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])"
    r"(?:"
    # PHP's define('DB_PASSWORD', 'value') — the constant name is the key
    # and the comma separates it from the value.
    rf"(?P<define>define{_PHP_KEY_TRIVIA}\({_PHP_KEY_TRIVIA})(?P<definequote>\\?[\"'])"
    r"(?P<defined_key>[A-Za-z_][A-Za-z0-9_]*)"
    rf"(?P=definequote){_PHP_KEY_TRIVIA},\s*"
    r"|"
    # Assignment forms: key=value, key: value, and PHP's array arrow
    # `'key' => value`.  A QUOTED key may be a compound wire name
    # (`"x-api-key"`, `"x.api.token"`): the class must span `-`/`.` or the
    # closing quote never matches and the value leaks (R18).  A JSON-
    # escaped payload spells the delimiters `\"`: the optional backslash is
    # part of the delimiter pair, and a key may START with an escape
    # (`\u0070assword`) which `_decode_key_escapes` resolves.
    r"(?P<keyquote>\\?[\"']?)"
    r"(?P<key>(?:[A-Za-z_]|" + _KEY_ESCAPE_TOKEN + r")"
    r"(?:[A-Za-z0-9_.-]|" + _KEY_ESCAPE_TOKEN + r")*)"
    r"(?P=keyquote)"
    # PHP's var_dump/print_r visibility suffix: [password:protected].
    r"(?:\s*:\s*(?:protected|private|public))?"
    r"\]?"
    rf"{_PHP_KEY_TRIVIA}(?:=>|[:=])\s*"
    r")"
)
# String prefixes Python reprs may put before a quoted value: b'', rb'',
# br'', r'', u'', f''.  At most two letters, directly attached to the quote.
_STRING_PREFIXES = frozenset({"b", "r", "u", "f", "br", "rb", "fr", "rf"})
# A standalone ``Bearer <jwt>`` (e.g. inside a transport error or URL query).
_BEARER_RE = re.compile(r"(?i)\b(?P<pre>Bearer\s+)(?P<val>[A-Za-z0-9._~+/=-]+)")
# ``https://user:secret@host`` and scheme-relative ``//:secret@host`` URL
# credentials.  The prefix accepts the network-path form too: requiring
# ``://`` let an empty-username userinfo (``//:URLSECRET@host``) through
# every redaction sink (R7 residual).  The value runs greedily to the LAST
# ``@`` before the authority terminator: a password can legitimately contain
# ``@`` (``ftp://user:p@ss@host``), and stopping at the first one leaked the
# suffix as if it were the host.  The authority ends at ``/``, ``?`` or
# ``#``; without that bound a query ``?email=a@b`` was read as userinfo and
# a port plus a query leaked the host into the redacted value
# (``https://example.com:***@b``).
_URL_USERINFO_RE = re.compile(
    r"(?P<pre>//[^/\s?#:@]*:)(?P<val>[^/\s?#]+)(?=@)")
# The same userinfo shape without a scheme (``user:secret@host``), which
# urlparse reads as a scheme and a path, so a malformed --source can carry
# it into an error message verbatim.  ``scheme:data@host`` is also ordinary
# URI/prose text, so the candidate is only redacted when it has a plausible
# secret value or network host (see _bare_userinfo_redacts).
#
# PERFORMANCE (one owner): _redact_bare_userinfo_text is a single
# left-to-right scanner, not a regex.  The old ``[^/\s:@]+:`` scanned a long
# brace/word run at EVERY offset before failing (80k braces = 9.43 s, O(n²));
# bounding the runs fixed that but capped the label at 64 and the credential
# at 1024 characters, so longer credentials were logged verbatim.  The
# scanner keeps the plausible-username label class but has no length caps and
# inspects each value/host run a constant number of times, so the pass stays
# linear.  redact_text also skips the scan entirely when the message has no
# ``@`` (no userinfo shape can match).
_USERINFO_LABEL_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._%+~-"
    + "".join(chr(code) for code in range(0x80, 0x100))
)
#: Characters that are part of a WORD, so a candidate match starting after
#: one must move left to the word boundary (the old regex's lookbehind).
#: ``/``, ``@``, ``.`` and ``:`` are DELIMITERS, not word characters: a
#: single-slash source (``ftp:/user:SECRET@host``) and the ``@user:...``
#: form both start their credential right after one, and treating those
#: characters as forbidden advanced ``allowed`` past the label's own
#: letters to the colon, returning no span at all (R6-03).
_USERINFO_FORBIDDEN_PREV = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"
)
#: ``?`` and ``#`` end the URL authority just like ``/``: a query
#: ``?email=a@b`` is not userinfo, so its ``@`` must never start a
#: scheme-less credential candidate back in the host.
_USERINFO_DELIMITERS = frozenset("/@?#")

# Opaque URI schemes whose ``scheme:data@host`` form is address/opaque text,
# not a malformed source credential.  Network schemes use ``://`` credentials
# and are handled by _URL_USERINFO_RE.
_OPAQUE_URI_SCHEMES = frozenset({
    "cid", "data", "geo", "mailto", "mid", "news", "sms", "tel", "urn",
})
# Bare-userinfo labels that name a login/service account.  A value after one
# of these is a credential regardless of its length/host shape; the prose
# guard below must not turn a short password into report text.
_CREDENTIAL_LABELS = frozenset({
    "admin", "deploy", "ftp", "login", "root", "user", "username",
})
# A bare 1-3 character alphabetic value (`note:see@home`) is prose far more
# often than a source password; anything longer, or carrying a non-letter, is
# credential-like.
_MIN_BARE_SECRET_LEN = 4

REDACTED = "***"


class CredentialError(WptError):
    """A required credential could not be resolved."""


def _network_like_host(host: str) -> bool:
    """True when ``host`` has host syntax rather than prose-word syntax."""
    host = host.rstrip(".,;:!?)]}\"'")
    return (host.startswith("[") or host.lower() == "localhost"
            or "." in host or ":" in host)


def _userinfo_delimiter(char: str) -> bool:
    """True for a character that ends a value/host run (regex ``[/\\s@]``)."""
    return char in _USERINFO_DELIMITERS or char.isspace()


def _bare_userinfo_span(
        msg: str, at: int,
        floor: int = 0) -> tuple[int, int, str, str, str] | None:
    """The ``label:value@host`` span ending at ``at``, or ``None``.

    The label keeps the plausible-username class of the old regex with no
    length cap.  The value may not contain ``/``, whitespace or ``@``, so
    only colons after the last such delimiter can separate it from the label.
    Within that segment the first colon with a non-empty value and a valid
    label run is the regex's leftmost match; the earliest start in the run
    whose preceding character passes the old lookbehind wins.  ``floor`` is
    the regex cursor after a consumed match: text before it was already part
    of that match and must not be rescanned.
    """
    boundary = at - 1
    while boundary >= floor and not _userinfo_delimiter(msg[boundary]):
        boundary -= 1
    colon = msg.find(":", max(floor, boundary + 1), at)
    while colon >= 0:
        if colon + 1 < at:
            start = colon
            while start > floor and msg[start - 1] in _USERINFO_LABEL_CHARS:
                start -= 1
            allowed = start
            while (allowed < colon and allowed > 0
                   and msg[allowed - 1] in _USERINFO_FORBIDDEN_PREV):
                allowed += 1
            if allowed < colon:
                end = at + 1
                while end < len(msg) and not _userinfo_delimiter(msg[end]):
                    end += 1
                return (allowed, end, msg[allowed:colon + 1],
                        msg[colon + 1:at], msg[at + 1:end])
        colon = msg.find(":", colon + 1, at)
    return None


def _redact_bare_userinfo_text(msg: str) -> str:
    """Redact scheme-less ``user:secret@host`` credentials in one linear pass."""
    if "@" not in msg:
        return msg
    parts: list[str] = []
    position = 0
    search = 0
    floor = 0
    while True:
        at = msg.find("@", search)
        if at < 0:
            break
        span = _bare_userinfo_span(msg, at, floor)
        if span is None:
            search = at + 1
            continue
        start, end, pre, value, host = span
        if _bare_userinfo_redacts(pre[:-1], value, host):
            parts.append(msg[position:start])
            parts.append(f"{pre}{REDACTED}@{host}")
            position = end
        floor = end
        search = end
        if search < len(msg) and msg[search] == "@":
            # ``host`` stopped at this '@'; the consumed match already owned
            # the text before it, so the next search starts after it (the
            # regex engine resumes at the '@' and cannot match from there).
            search += 1
    parts.append(msg[position:])
    return "".join(parts)


def _bare_userinfo_redacts(label: str, value: str, host: str) -> bool:
    """Whether a scheme-less ``label:value@host`` candidate is a credential.

    ``scheme:data@host`` is ambiguous: it can be a malformed --source with a
    password, or a URI/address/prose construct.  Opaque URI schemes are left
    alone, and a credential-shaped login label always wins.  Otherwise the
    value must be credential-like (four or more characters, or containing a
    non-letter) or the host must look like a network endpoint.  This keeps
    ``note:see@home`` intact while still hiding ``user:abc@host`` and
    ``user:hunter2@host``.
    """
    label = label.lower()
    if label not in _CREDENTIAL_LABELS:
        if label in _OPAQUE_URI_SCHEMES:
            return False
        if (len(value) < _MIN_BARE_SECRET_LEN and value.isalpha()
                and not _network_like_host(host)):
            return False
    return True


def _quoted_end(text: str, open_index: int) -> int:
    """Offset just past the quote opened at ``open_index`` (or len(text)).

    SQL (and PHP's SQL escaping) writes a quote INSIDE a string by doubling
    it: ``'''HUNTER2'`` and ``'HUN''TER2'`` are one value.  Treating the
    first quote of the pair as the closing quote ended the redacted span
    one character early and left the secret in the log/report
    (``user_pass=***'HUNTER2'``).  A doubled quote is consumed as an escape
    and scanning continues, so the whole value is redacted.  An
    unterminated quote fails closed (the rest of the message is redacted).
    """
    quote = text[open_index]
    index = open_index + 1
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == quote:
            if index + 1 < len(text) and text[index + 1] == quote:
                index += 2
                continue
            return index + 1
        index += 1
    return len(text)


def _balanced_end(text: str, open_index: int) -> int:
    """Offset just past the balanced ``{}``/``[]``/``()`` opened here.

    Strings inside the container are skipped escape-aware, so a ``}`` in a
    secret value cannot end the container early.  An unterminated container
    consumes the rest of the message: failing closed (redacting too much) is
    the safe direction for a credential.
    """
    opener = text[open_index]
    closer = {"{": "}", "[": "]", "(": ")"}[opener]
    depth = 0
    index = open_index
    while index < len(text):
        char = text[index]
        if char in "'\"":
            index = _quoted_end(text, index)
            continue
        # PHP comments are whitespace inside an array(...) / object value:
        # a ``}`` in a comment ended the container early and leaked the
        # rest of the secret (R16).  A comment consumes its own delimiters.
        if text.startswith("/*", index):
            close = text.find("*/", index + 2)
            index = len(text) if close == -1 else close + 2
            continue
        if text.startswith("//", index):
            close = text.find("\n", index + 2)
            index = len(text) if close == -1 else close + 1
            continue
        if char == "#":
            close = text.find("\n", index + 1)
            index = len(text) if close == -1 else close + 1
            continue
        if char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return len(text)


_PHP_IDENTIFIER_RE = re.compile(r"[A-Za-z_\\][A-Za-z0-9_\\]*")
_PHP_CAST_RE = re.compile(r"\([A-Za-z_][A-Za-z0-9_\\]*\)")
#: var_export's object constructor: ``Some\Class::__set_state(``.
_PHP_SET_STATE_RE = re.compile(
    r"[A-Za-z_\\][A-Za-z0-9_\\]*\s*::\s*__set_state\s*")
#: A var_dump/print_r PHP type wrapper before the value:
#: ``string(6) "hunter2"``, ``int(7)``, ``array(2) {...}``.  The wrapper is
#: part of the value, so the scanner must consume it and then the value.
_PHP_TYPE_WRAPPER_RE = re.compile(
    r"(?i)(?:string|int|integer|float|double|bool|boolean|array|object|"
    r"null)\s*\(\s*\d+\s*\)"
)
_SERIALIZED_SECRET_KEY_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])s:\d+:(?P<quote>\\?)\""
    r"(?P<key>(?:(?:\x00\*\x00|\\0\*\\0)"
    r"|(?:\x00[A-Za-z_\\][A-Za-z0-9_\\]*\x00"
    r"|\\0[A-Za-z_\\][A-Za-z0-9_\\]*\\0))?"
    r"(?P<name>_*(?:[A-Za-z_\\]|\\(?:u[0-9A-Fa-f]{4}|"
    r"U[0-9A-Fa-f]{8}|x[0-9A-Fa-f]{2}))"
    r"(?:[A-Za-z0-9_\\.\-]|\\(?:u[0-9A-Fa-f]{4}|"
    r"U[0-9A-Fa-f]{8}|x[0-9A-Fa-f]{2}))*))(?P=quote)\""
    r";"
)


def _heredoc_end(text: str, open_index: int) -> int:
    """Offset just past a PHP heredoc/nowdoc whose ``<<<`` starts here.

    The header is ``<<<LABEL`` / ``<<<'LABEL'`` / ``<<<"LABEL"``; the value
    runs to a line whose stripped text is the label, optionally followed by
    ``;`` (PHP 7.3 allows the indented terminator).  An unterminated heredoc
    consumes the rest of the message: failing closed (redacting too much)
    is the safe direction for a credential.
    """
    line_end = text.find("\n", open_index)
    header_end = len(text) if line_end == -1 else line_end
    header = text[open_index:header_end].rstrip("\r")
    match = re.match(r"<<<[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1[ \t]*$",
                     header)
    if match is None:
        return header_end
    label = match.group(2)
    position = header_end + 1
    while position <= len(text):
        line_end = text.find("\n", position)
        stop = len(text) if line_end == -1 else line_end
        stripped = text[position:stop].strip()
        if stripped.startswith(label):
            rest = stripped[len(label):].strip()
            if rest in ("", ";"):
                return stop if line_end == -1 else line_end + 1
        if line_end == -1:
            break
        position = line_end + 1
    return len(text)


def _php_value_prefix_end(text: str, index: int) -> int | None:
    """End offset of a PHP container/value that starts with a prefix.

    Handles the shapes a var_export/config dump puts after a secret key:
    ``array(...)`` (case-insensitive), a cast followed by its container
    (``(object)[...]``, ``(array)(...)``), and ``new Class(...)``.  Returns
    None when ``index`` does not start one, so the caller keeps its bare
    token branch.

    Cast chains are consumed ITERATIVELY, not by mutual recursion: an
    untrusted error/body can carry ``password=(object)(object)...`` and
    recursion would raise ``RecursionError`` before any report was written
    (R11-P2-2).  Only the final value is handed back to
    :func:`_secret_value_end`, whose own prefix branch then sees no cast.
    """
    length = len(text)
    cast_seen = False
    while index < length:
        # ``new Fully\Qualified\Class(...)`` — the constructor arguments are
        # the value; a class without arguments still ends at the identifier.
        if text[index:index + 3].lower() == "new" \
                and (index + 3 >= length or text[index + 3] in " \t\r\n\\"):
            match = _PHP_IDENTIFIER_RE.search(text, index + 3)
            if match is not None:
                after = _skip_php_trivia(text, match.end())
                if after < length and text[after] == "(":
                    return _balanced_end(text, after)
                return match.end()
        # ``Class::__set_state(array(...))`` — var_export's object form.
        # Treat the call like any other container so a secret member inside
        # it is redacted whole instead of only the class name.
        set_state = _PHP_SET_STATE_RE.match(text, index)
        if set_state is not None:
            after = _skip_php_trivia(text, set_state.end())
            if after < length and text[after] == "(":
                return _balanced_end(text, after)
            return set_state.end()
        # ``array(...)`` — PHP's array keyword is case-insensitive.
        if text[index:index + 5].lower() == "array":
            after = _skip_php_trivia(text, index + 5)
            if after < length and text[after] == "(":
                return _balanced_end(text, after)
        # A cast, then the value it casts: ``(object)[...]``,
        # ``(array)(...)``.  Loop instead of recursing on the next cast.
        cast = _PHP_CAST_RE.match(text, index)
        if cast is None:
            if cast_seen:
                return _secret_value_end(text, index)
            return None
        cast_seen = True
        index = _skip_php_trivia(text, cast.end())
    return index


def _skip_php_trivia(text: str, index: int) -> int:
    """Skip PHP whitespace AND comments before a value/type wrapper.

    Comments are PHP whitespace: ``'password' => /* keep */ 'HUNTER2'``
    assigns the string, but the scanner stopped at ``/`` and leaked it.
    Line comments end at CR/LF or the end of the message.
    """
    length = len(text)
    while index < length:
        if text[index] in " \t\r\n":
            index += 1
            continue
        if text.startswith("/*", index):
            close = text.find("*/", index + 2)
            index = length if close == -1 else close + 2
            continue
        if text.startswith("//", index):
            close = text.find("\n", index + 2)
            index = length if close == -1 else close + 1
            continue
        if text[index] == "#" and not text.startswith("#[", index):
            close = text.find("\n", index + 1)
            index = length if close == -1 else close + 1
            continue
        break
    return index


def _secret_value_end(text: str, start: int) -> int:
    """End offset of the complete value beginning at ``start``.

    Handles the shapes a Python/JSON repr or a PHP config dump puts after a
    secret key: a bare token, an escape-aware quoted string (with an optional
    ``b``/``r``/``u``/``f`` prefix), a balanced bytes/list/dict container,
    PHP's ``array(...)`` / ``(object)[...]`` / ``new Class(...)`` values
    (C7) and a heredoc/nowdoc body.  The containers are consumed WHOLE —
    stopping at the first quote/comma/brace leaked the tail of
    ``b'hunter2'``, ``['aaa','bbb']``, nested dicts and
    ``array('client' => 'HUNTER2')``.
    """
    length = len(text)
    index = _skip_php_trivia(text, start)
    if index >= length:
        return index
    # A var_dump type wrapper is part of the value, not the value's end:
    # ``password: string(6) "hunter2"`` used to redact only ``string(6)``
    # and leave the plaintext.  Consume any chain iteratively (no
    # recursion on an untrusted body).
    while True:
        wrapper = _PHP_TYPE_WRAPPER_RE.match(text, index)
        if wrapper is None:
            break
        index = _skip_php_trivia(text, wrapper.end())
        if index >= length:
            return index
    # String prefix directly attached to the quote (b'', rb'', ...).  Only
    # consume letters that are actually followed by a quote, so a bare
    # value like ``b64secret`` is not mistaken for a prefix.
    prefix_end = index
    while prefix_end < length and prefix_end - index < 2 \
            and text[prefix_end].isalpha():
        prefix_end += 1
    if prefix_end > index and prefix_end < length \
            and text[prefix_end] in "'\"" \
            and text[index:prefix_end].lower() in _STRING_PREFIXES:
        return _quoted_end(text, prefix_end)
    if text.startswith('\\"', index) or text.startswith("\\'", index):
        # A JSON-escaped payload carries its delimiters as ``\"``.  Consume
        # through the matching escaped close so the braces around the
        # serialized/JSON object survive the replacement.
        quote = text[index + 1]
        cursor = index + 2
        while cursor < length:
            if text[cursor] == "\\":
                if cursor + 1 < length and text[cursor + 1] == quote:
                    return cursor + 2
                cursor += 2
                continue
            cursor += 1
        return length
    if text[index] in "'\"":
        return _quoted_end(text, index)
    if text.startswith("<<<", index):
        return _heredoc_end(text, index)
    prefixed = _php_value_prefix_end(text, index)
    if prefixed is not None:
        return prefixed
    if text[index] in "{[(":
        return _balanced_end(text, index)
    # The bare branch runs to whitespace/END: a credential value may carry
    # punctuation (``password=abc,def``, ``token=abc]def``) and the old
    # stop set leaked everything after it.  Quoted/bytes/container shapes
    # are consumed by the branches above, so over-redacting punctuation
    # here is the safe direction (R6-33).
    while index < length and not text[index].isspace():
        index += 1
    return index


def _serialized_string_end(text: str, index: int) -> int | None:
    """End offset (past ``";``) of the serialized string at ``index``.

    The declared length is BYTES, so the character end is derived from a
    UTF-8 slice.  An unterminated/mismatched string returns None; callers
    redact to end-of-message (fail closed).  The whole serialized form may
    itself be JSON-escaped (``s:8:\\"password\\";``): the delimiters are
    ``\\"`` and one JSON escape counts as its decoded byte(s).
    """
    match = re.match(r's:(\d+):(\\?)"', text[index:])
    if match is None:
        return None
    try:
        length = int(match.group(1))
    except ValueError:
        return None
    escaped = match.group(2) == "\\"
    value_start = index + match.end()
    if not escaped:
        try:
            tail = text[value_start:].encode("utf-8")
        except UnicodeEncodeError:
            # A literal lone surrogate (json.loads('"\\ud83d"'), argv with
            # surrogateescape) cannot be encoded as UTF-8.  Return a parse
            # failure so the caller redacts to end-of-message; raising here
            # escaped every redaction sink as a UnicodeEncodeError.
            return None
        if length > len(tail):
            return None
        try:
            value_chars = tail[:length].decode("utf-8")
        except UnicodeDecodeError:
            return None
        close = value_start + len(value_chars)
        if close + 1 < len(text) and text[close:close + 2] == '";':
            return close + 2
        return None
    # Escaped representation: consume JSON escapes until the declared BYTE
    # length is reached, then require the escaped close.
    cursor = value_start
    remaining = length
    while remaining > 0:
        if cursor >= len(text):
            return None
        if text[cursor] == "\\" and cursor + 1 < len(text):
            nxt = text[cursor + 1]
            if nxt == "u" and cursor + 5 < len(text):
                digits = text[cursor + 2:cursor + 6]
                if re.fullmatch(r"[0-9A-Fa-f]{4}", digits):
                    codepoint = int(digits, 16)
                    # JSON combines a high/low surrogate pair into ONE
                    # scalar (4 UTF-8 bytes); a lone surrogate cannot be
                    # encoded as UTF-8 at all.  Treat that as a parse
                    # failure so the caller redacts to end-of-message —
                    # ``chr(0xD83D).encode()`` used to raise
                    # UnicodeEncodeError out of the log filter/report.
                    if 0xD800 <= codepoint <= 0xDBFF \
                            and text[cursor + 6:cursor + 8] == "\\u":
                        low_digits = text[cursor + 8:cursor + 12]
                        if re.fullmatch(r"[0-9A-Fa-f]{4}", low_digits):
                            low = int(low_digits, 16)
                            if 0xDC00 <= low <= 0xDFFF:
                                remaining -= 4
                                cursor += 12
                                continue
                    try:
                        size = len(chr(codepoint).encode("utf-8"))
                    except UnicodeEncodeError:
                        return None
                    remaining -= size
                    cursor += 6
                    continue
            remaining -= 1
            cursor += 2
            continue
        char = text[cursor]
        try:
            size = len(char.encode("utf-8"))
        except UnicodeEncodeError:
            return None
        if size > remaining:
            return None
        remaining -= size
        cursor += 1
    if remaining < 0:
        return None
    if text.startswith('\\";', cursor):
        return cursor + 3
    if text.startswith('";', cursor):
        return cursor + 2
    return None


def _serialized_value_end(text: str, index: int, depth: int = 0) -> int:
    """End offset of ONE PHP-serialized value beginning at ``index``.

    Handles null/bool/int/float/double/string/reference scalars and the
    container forms ``a:``/``O:``/``C:``.  Untrusted input is bounded by a
    depth ceiling and every parse failure returns ``len(text)`` so the
    caller redacts the whole remaining blob instead of leaking a member.
    """
    length = len(text)
    if depth > 64 or index >= length:
        return length
    if text.startswith("N;", index):
        return index + 2
    if text.startswith("s:", index):
        end = _serialized_string_end(text, index)
        return length if end is None else end
    if text.startswith(("i:", "b:", "d:"), index):
        semi = text.find(";", index)
        return length if semi == -1 else semi + 1
    if text.startswith(("R:", "r:"), index):
        semi = text.find(";", index)
        return length if semi == -1 else semi + 1
    match = re.match(r"a:(\d+):\{", text[index:])
    if match is not None:
        try:
            count = int(match.group(1))
        except ValueError:
            return length
        cursor = index + match.end()
        for _ in range(max(0, count)):
            cursor = _serialized_value_end(text, cursor, depth + 1)
            if cursor >= length:
                return length
            cursor = _serialized_value_end(text, cursor, depth + 1)
            if cursor >= length:
                return length
        if cursor < length and text[cursor] == "}":
            return cursor + 1
        return length
    object_match = re.match(r'(?:O|C):\d+:"(?:[^"\\\\]|\\\\.)*":',
                            text[index:])
    if object_match is not None:
        if text.startswith("C:", index):
            # C:<classlen>:"Class":<datalen>:{<data>}
            custom = re.match(
                r'C:\d+:"(?:[^"\\\\]|\\\\.)*":(\d+):\{', text[index:])
            if custom is None:
                return length
            try:
                data_length = int(custom.group(1))
            except ValueError:
                return length
            data_start = index + custom.end()
            try:
                tail = text[data_start:].encode("utf-8")
            except UnicodeEncodeError:
                # Same unescaped-lone-surrogate guard as the s: branch:
                # redact the rest of the message instead of raising out of
                # redact_text/report render/log filter.
                return length
            if data_length > len(tail):
                return length
            try:
                data_chars = tail[:data_length].decode("utf-8")
            except UnicodeDecodeError:
                return length
            close = data_start + len(data_chars)
            if close < length and text[close] == "}":
                return close + 1
            return length
        header = re.match(r'O:\d+:"(?:[^"\\\\]|\\\\.)*":(\d+):\{',
                          text[index:])
        if header is None:
            return length
        try:
            count = int(header.group(1))
        except ValueError:
            return length
        cursor = index + header.end()
        for _ in range(max(0, count)):
            cursor = _serialized_value_end(text, cursor, depth + 1)
            if cursor >= length:
                return length
            cursor = _serialized_value_end(text, cursor, depth + 1)
            if cursor >= length:
                return length
        if cursor < length and text[cursor] == "}":
            return cursor + 1
        return length
    return length


def _redact_serialized_secrets(msg: str) -> str:
    """Redact PHP-serialized pairs whose key is secret-shaped.

    A serialized options/usermeta blob does not use ``key=value`` or
    ``'key' => value``, so the assignment scanner cannot see it.  Every
    VALUE TYPE is consumed as a whole — a string, or a container/object
    (``a:``/``O:``/``C:``) nested under the secret key — and replaced with
    a string ``***``.  Any unparsable/truncated value redacts the rest of
    the message (fail closed): a member of a serialized container under a
    secret key must never leak.
    """
    parts: list[str] = []
    position = 0
    for match in _SERIALIZED_SECRET_KEY_RE.finditer(msg):
        if match.start() < position:
            continue
        if not is_secret_key(_decode_key_escapes(match.group("name"))):
            continue
        value_start = match.end()
        if not msg.startswith(("N;", "s:", "a:", "O:", "C:", "i:", "b:",
                               "d:", "R:", "r:"), value_start):
            continue
        end = _serialized_value_end(msg, value_start)
        key_part = msg[match.start():value_start]
        parts.append(msg[position:match.start()])
        parts.append(
            f'{key_part}s:{len(REDACTED)}:"{REDACTED}";')
        position = end
    parts.append(msg[position:])
    return "".join(parts)


def _redact_secret_assignments(msg: str) -> str:
    """Redact every secret ``key = value`` while keeping the key visible.

    A scanner rather than one regex: the value extent depends on balanced
    delimiters and escape-aware quotes, which a regular expression cannot
    express.  The key is preserved (``password=***``) so the log/report still
    says WHAT was removed.
    """
    out: list[str] = []
    position = 0
    for match in _SECRET_KEY_ASSIGN_RE.finditer(msg):
        if match.start() < position:
            # The outer secret's balanced/quoted value already consumed this
            # region whole; re-emitting from an inner match's end leaked the
            # tail of the outer value (``password='password=a hunter2'``).
            continue
        key = match.group("key") or match.group("defined_key")
        if not is_secret_key(_decode_key_escapes(key)):
            # The regex is intentionally broad (it must FIND camelCase and
            # snake_case names); the KEY-SHAPE owner decides whether this
            # assignment is a secret slot.  An ordinary word containing
            # "key" (``monkey=banana``) stays untouched.
            continue
        out.append(msg[position:match.start()])
        out.append(f"{key}={REDACTED}")
        position = _secret_value_end(msg, match.end())
    out.append(msg[position:])
    return "".join(out)


def redact_text(msg: str) -> str:
    """Replace secret assignments in free text.

    Covers ``Authorization`` headers (whole value), ``key=value`` /
    ``key: value`` secret assignments (quoted, bytes, list and dict values
    included), standalone ``Bearer <token>``, ``https://user:secret@host``
    URL credentials (including scheme-relative ``//:secret@host`` with an
    empty username), and the scheme-less source shape ``user:secret@host``.
    Single shared implementation — the log formatters and report renderers
    all route here.
    """
    msg = _AUTH_HEADER_RE.sub(lambda m: f"{m.group(1)}={REDACTED}", msg)
    msg = _redact_serialized_secrets(msg)
    msg = _redact_secret_assignments(msg)
    msg = _BEARER_RE.sub(lambda m: f"{m.group('pre')}{REDACTED}", msg)
    msg = _URL_USERINFO_RE.sub(lambda m: f"{m.group('pre')}{REDACTED}", msg)
    if "@" in msg:
        # No '@' means no userinfo shape can match; skip the scan entirely
        # (brace-heavy log lines were the O(n²) hot path).
        msg = _redact_bare_userinfo_text(msg)
    return msg


def redacted_site_label(value: Any, *, fallback: str = "site") -> str:
    """The ONE operator-facing site label for report renderers.

    ``redact_text`` is the single redaction owner; this wrapper only adds
    the never-empty rule every report header needs.  Manifest/snapshot
    IDENTITY still uses the raw label (backup.site_label), because
    redaction is lossy and identity must stay exact.
    """
    text = value.strip() if isinstance(value, str) else ""
    return redact_text(text) if text else redact_text(fallback)


def resolve_password(env_var: str | None, *, what: str = "password") -> str:
    """Return the password from ``env_var`` (or prompt when interactive).

    Raises CredentialError when the variable is unset and prompting is unavailable.
    """
    if env_var:
        value = os.environ.get(env_var, "")
        if value:
            return value
        raise CredentialError(f"environment variable {env_var!r} is empty or unset")
    if os.environ.get("WPT_NO_PROMPT") == "1":
        raise CredentialError(
            f"{what} required: no --password-env given and prompting disabled (WPT_NO_PROMPT=1)"
        )
    if not sys_stdin_is_tty():
        raise CredentialError(f"{what} required: no --password-env given and stdin is not a TTY")
    value = getpass.getpass(f"{what}: ")
    if not value:
        raise CredentialError(f"{what} was empty")
    return value


def sys_stdin_is_tty() -> bool:
    import sys

    return sys.stdin is not None and sys.stdin.isatty()


#: Structural guards for ``redact``: a report/log payload is never meaningful
#: this deep, and an untrusted bridge payload can be arbitrarily nested.
_REDACT_MAX_DEPTH = 32
_REDACT_CYCLE = "<circular>"
_REDACT_DEPTH = "<max-depth>"


def redact(obj: Any, _key: str = "", *,
           _seen: set[int] | None = None, _depth: int = 0) -> Any:
    """Deep-copy ``obj`` replacing values of secret-looking keys with '***'.

    Strings are only redacted when reached via a matching key context; bare strings
    that merely contain 'password' etc. are left intact (content, not a secret slot).

    Bounded and cycle-safe: a bridge/report payload can be arbitrarily deep
    (untrusted JSON raised RecursionError out of every caller), so depth 32
    and a repeated ancestor become readable placeholders instead of a
    traceback.  Structural safety limits, not operator tunables.
    """
    if _key and is_secret_key(_key):
        # A secret SLOT owns its whole value whatever its type: a nested
        # dict/list/bytes under ``password`` is still the password.
        return "***"
    if isinstance(obj, dict) or isinstance(obj, (list, tuple)):
        if _depth >= _REDACT_MAX_DEPTH:
            return _REDACT_DEPTH
        if _seen is None:
            _seen = set()
        token = id(obj)
        if token in _seen:
            return _REDACT_CYCLE
        _seen.add(token)
        try:
            if isinstance(obj, dict):
                return {k: redact(v, _key=str(k), _seen=_seen,
                                  _depth=_depth + 1)
                        for k, v in obj.items()}
            maker = list if isinstance(obj, list) else tuple
            return maker(redact(v, _key="", _seen=_seen, _depth=_depth + 1)
                         for v in obj)
        finally:
            _seen.discard(token)
    return obj
