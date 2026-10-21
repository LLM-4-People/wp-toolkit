"""Centralized logging — the ONLY logging path in wpt.

Configured once at the CLI choke point via setup_logging(); every module logs through
get_logger(). Secrets are redacted at the formatter level so no payload that reaches
a log file or stderr ever carries credentials.
"""

import json
import logging
import sys
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from .config import REDACTED, is_secret_key, redact_text

_parent = logging.getLogger("wpt")
_parent.propagate = False


#: Recursive redaction guards.  A cyclic or pathologically deep mapping is
#: a LOG PAYLOAD, not a reason to crash the caller: recursion is bounded and
#: a repeat becomes a readable placeholder.  Structural safety limits, not
#: operator tunables (the payload is never meaningful that deep).
_REDACT_MAX_DEPTH = 32
#: Total container occurrences rendered for ONE value.  Depth alone let a
#: shared acyclic DAG (two branches pointing at the same child) be re-walked
#: once per path — depth 20 cost seconds and depth 32 extrapolated to hours
#: (N-F3).  The memo makes each distinct container redact once; this budget
#: also bounds the RENDERED occurrences, which is what both the human
#: ``str()`` sink and the JSON sink serialize.  Generous for a real log
#: payload, far below any exponential blowup.
_REDACT_MAX_NODES = 10_000
_REDACT_CYCLE = "<circular>"
_REDACT_DEPTH = "<max-depth>"
_REDACT_NODES = "<max-nodes>"


def _redact_extra_value(value: Any, key: str = "", *,
                        _seen: set[int] | None = None,
                        _memo: dict[int, tuple[Any, int]] | None = None,
                        _depth: int = 0,
                        _budget: list[int] | None = None) -> Any:
    """Redact one ``extra`` value, key-aware and JSON-safe by construction.

    A mapping's KEY context decides whether its value is a secret
    (``{"password": "x"}``), recursively — redacting only string values left
    nested credentials intact.  Sets/frozensets and bytes are converted to
    the same shape ``json.dumps`` accepts (a list and a text string), and a
    mapping key that is not a string becomes one so the JSON sink cannot
    raise on it.  A self-referencing container (or one deeper than
    ``_REDACT_MAX_DEPTH``) becomes a placeholder instead of a
    ``RecursionError`` out of the log call (R6-39).

    Shared acyclic children are redacted ONCE (``_memo``) and the rendered
    size of that result is charged against ``_budget`` on every reuse, so a
    DAG cannot force exponential revisits or an exponential ``str``/JSON
    rendering; once the budget is spent the remaining occurrences answer
    ``<max-nodes>`` (N-F3).  ``_seen`` tracks only the ANCESTOR path, so a
    genuine cycle still answers ``<circular>``.
    """
    redacted, _ = _redact_rendered(
        value, key, _seen, _memo, _depth,
        [_REDACT_MAX_NODES] if _budget is None else _budget)
    return redacted


def _redact_rendered(
        value: Any, key: str, seen: set[int] | None,
        memo: dict[int, tuple[Any, int]] | None, depth: int,
        budget: list[int]) -> tuple[Any, int]:
    """The recursive worker: ``(redacted value, rendered container count)``."""
    if key and is_secret_key(key):
        return REDACTED, 0
    if isinstance(value, str):
        return redact_text(value), 0
    if isinstance(value, (bytes, bytearray)):
        return redact_text(bytes(value).decode("utf-8", "replace")), 0
    if value is None or isinstance(value, (bool, int, float)):
        return value, 0
    if not isinstance(value, (Mapping, set, frozenset, list, tuple)):
        # An opaque object (an exception, a dataclass, a custom repr) can
        # carry a credential in its str(): render it as redacted TEXT, not
        # as the object the formatters stringify verbatim.
        return redact_text(str(value)), 0
    if depth >= _REDACT_MAX_DEPTH:
        return _REDACT_DEPTH, 0
    if seen is None:
        seen = set()
    if memo is None:
        memo = {}
    token = id(value)
    if token in seen:
        return _REDACT_CYCLE, 0
    cached = memo.get(token)
    if cached is not None:
        rendered, count = cached
        if count > budget[0]:
            return _REDACT_NODES, 0
        budget[0] -= count
        return rendered, count
    if budget[0] <= 0:
        return _REDACT_NODES, 0
    budget[0] -= 1  # this container occurrence
    seen.add(token)
    try:
        if isinstance(value, Mapping):
            rendered_items = [
                (_redact_extra_key(item_key),
                 _redact_rendered(item, str(item_key), seen, memo,
                                  depth + 1, budget))
                for item_key, item in value.items()
            ]
            result = {item_key: item for item_key, (item, _) in rendered_items}
            written = 1 + sum(count for _, (_, count) in rendered_items)
        elif isinstance(value, (set, frozenset)):
            items = list(value)
            rendered_items = [
                _redact_rendered(item, "", seen, memo, depth + 1, budget)
                for item in items
            ]
            result = [item for item, _ in rendered_items]
            written = 1 + sum(count for _, count in rendered_items)
        else:
            rendered_items = [
                _redact_rendered(item, "", seen, memo, depth + 1, budget)
                for item in value
            ]
            result = [item for item, _ in rendered_items]
            written = 1 + sum(count for _, count in rendered_items)
        memo[token] = (result, written)
        return result, written
    finally:
        # Drop after leaving this container so an ancestor repeat is a
        # cycle; the persistent memo is what renders a shared child again.
        seen.discard(token)


def _redact_extra_key(key: Any) -> str:
    """A JSON-serializable, redacted mapping key.

    A key is text like any other (``{"password: hunter2": ...}`` carried the
    secret in the key itself); a non-string key becomes a string so the
    JSON sink cannot raise on it.
    """
    return redact_text(key if isinstance(key, str) else str(key))


#: Record attributes a filter must never rewrite: logging owns them and the
#: formatters read them directly.
_RESERVED_RECORD_KEYS = frozenset({
    "msg", "args", "levelname", "levelno", "name", "filename", "module",
    "funcName", "lineno", "pathname", "process", "processName", "thread",
    "threadName", "stack_info", "exc_info", "exc_text", "taskName", "msecs",
    "relativeCreated", "created", "asctime", "message",
})


class RedactingFilter(logging.Filter):
    """Redacts a record ONCE, before any formatter renders it.

    The message and its ``%s``/``%d`` arguments are formatted first and
    then redacted as one string: redacting the template alone broke
    ``log.info("password=%s", value)`` (the placeholder was gone before
    ``getMessage()`` ran, and logging's own error path dumped the raw
    argument to stderr).  Every extra string value is redacted too — a
    credential can arrive under any key (``extra={"url": ...}``), not only
    under a secret-looking one.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        # A mapping-style call (``log.info("%(password)s", {...})``) carries
        # the secret in the ARGUMENT, and formatting first then redacting the
        # text lost the key context entirely.  Redact the mapping key-aware
        # BEFORE getMessage; positional args keep the format-then-redact path
        # (it is what keeps ``log.info("password=%s", secret)`` safe).  Any
        # Mapping — not only dict — takes this path: MappingProxyType and
        # UserDict bypassed the key-aware redaction and rendered the secret.
        if isinstance(record.args, Mapping):
            record.args = {
                key: _redact_extra_value(value, str(key))
                for key, value in record.args.items()
            }
        try:
            message = record.getMessage()
        except Exception:
            # A malformed %-call must not fall through to logging's
            # handleError(), which prints the raw arguments to stderr.  The
            # fallback names the template and the arity only: rendering
            # ``record.args`` here would put the secret back in the message.
            message = (f"{record.msg} "
                       f"[logging format error: {len(record.args or ())} "
                       "argument(s) omitted]")
        record.msg = redact_text(str(message))
        record.args = ()
        if record.exc_text:
            record.exc_text = redact_text(record.exc_text)
        for key in list(record.__dict__):
            if key in _RESERVED_RECORD_KEYS:
                continue
            if is_secret_key(key):
                setattr(record, key, REDACTED)
            else:
                value = getattr(record, key)
                redacted = _redact_extra_value(value)
                if redacted is not value:
                    setattr(record, key, redacted)
        return True


_PARENT_LOGGER_EXCLUDE = frozenset(
    {
        "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
        "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
        "created", "msecs", "relativeCreated", "thread", "threadName",
        "process", "processName", "taskName", "message", "asctime",
    }
)


def _extras(record: logging.LogRecord) -> dict[str, Any]:
    """Extra fields on the record (secrets already redacted by RedactingFilter).

    Keys are OUTPUT TEXT too: an extra named ``password=KEYHUNTER2`` used to
    print its key verbatim even though the value was ``***``.  Both
    formatters consume this one mapping, so the redacted key reaches the
    human and JSON sinks alike.
    """
    return {
        _redact_extra_key(key): getattr(record, key)
        for key in record.__dict__
        if key not in _PARENT_LOGGER_EXCLUDE and not key.startswith("_")
    }


class RedactingFormatter(logging.Formatter):
    """Formatter base: exception text is redacted like every other string."""

    def formatException(self, ei) -> str:
        return redact_text(super().formatException(ei))


class HumanFormatter(RedactingFormatter):
    def __init__(self) -> None:
        super().__init__(
            fmt="%(asctime)s %(levelname)-7s %(name)s %(message)s",
            datefmt="%H:%M:%S",
        )

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        extras = _extras(record)
        if extras:
            base += " " + " ".join(f"{k}={v}" for k, v in sorted(extras.items()))
        return base


class JsonFormatter(RedactingFormatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "time": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact_text(record.getMessage()),
        }
        # Canonical schema fields WIN over user extras: an extra named
        # ``logger``/``time``/``level``/``exc`` must not be able to forge
        # the record's own identity.
        payload = {**_extras(record), **payload}
        if record.exc_info and record.exc_info[0] is not None:
            payload["exc"] = self.formatException(record.exc_info)
        else:
            # ``exc`` is a schema field, not an extra: a user-supplied one
            # must never forge a traceback on a record that has none.
            payload.pop("exc", None)
        return json.dumps(payload, ensure_ascii=False, sort_keys=True,
                          default=str)


# Alias: free-text redaction has ONE implementation (config.redact_text).
redact_message = redact_text


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced child logger under the single 'wpt' parent."""
    if name.startswith("wpt."):
        return logging.getLogger(name)
    return logging.getLogger(f"wpt.{name}")


def setup_logging(level: str = "info", logfile: str | None = None,
                  json_mode: bool = False, *, console: bool = True
                  ) -> logging.Logger:
    """Configure the 'wpt' logger tree. Idempotent: replaces prior handlers.

    ONE logger, one level, and the sinks the operator asked for as HANDLERS
    of it: the CONSOLE sink (stderr) is always there unless ``console=False``
    (``--quiet``), and ``logfile`` ADDS a file sink beside it.  It never
    REPLACES the console: a run configured with ``--log-file`` that then
    fails printed its whole explanation into the file and left the terminal
    empty, which is the opposite of a chokepoint — the operator watching the
    terminal saw an rc 1 with no reason, and the reason was on disk where
    they were not looking.

    Both sinks carry the same formatters and the same redaction filter, so a
    secret cannot reach the file and be kept out of the console (or the
    reverse), and a WARNING or an ERROR reaches BOTH.
    """
    formatter = JsonFormatter() if json_mode else HumanFormatter()
    for existing in list(_parent.handlers):
        _parent.removeHandler(existing)
        existing.close()
    #: Logger-level redaction is defence in depth for records emitted
    #: directly on the parent; child records reach the HANDLERS, which
    #: each carry their own filter.  kept in sync by setup_logging.
    for existing_filter in list(_parent.filters):
        _parent.removeFilter(existing_filter)
    _parent.addFilter(RedactingFilter())
    if console:
        stderr = logging.StreamHandler(sys.stderr)
        stderr.setFormatter(formatter)
        stderr.addFilter(RedactingFilter())
        _parent.addHandler(stderr)
    if logfile:
        file_handler = logging.FileHandler(
            logfile, encoding="utf-8", errors="backslashreplace")
        file_handler.setFormatter(formatter)
        file_handler.addFilter(RedactingFilter())
        _parent.addHandler(file_handler)
    if not _parent.handlers:
        # ``--quiet`` without ``--log-file`` used to install NO handler, so
        # Python's ``logging.lastResort`` wrote WARNING+ to stderr with no
        # RedactingFilter: the quiet run printed the credential the normal
        # run redacted.  A NullHandler on the parent makes logging find a
        # sink and suppresses lastResort; the level still governs work.
        _parent.addHandler(logging.NullHandler())
    _parent.setLevel(getattr(logging, level.upper(), logging.INFO))
    return _parent
