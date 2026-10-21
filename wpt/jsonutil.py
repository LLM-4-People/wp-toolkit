"""Bounded JSON decoding for untrusted input.

Python 3.15's C decoder no longer raises ``RecursionError`` on very deep
JSON; it returns a deeply nested value.  The callers' "malformed input"
guards must not depend on the interpreter's recursion behaviour, so every
untrusted parse seam uses :func:`loads_bounded`: the normal decoder still
owns the grammar, and this module owns one structural depth bound.
"""

from __future__ import annotations

import json
from typing import Any, Callable

#: Structural nesting bound for untrusted JSON.  This is a safety bound,
#: not an operator tunable: a WordPress row or bridge answer this deep is a
#: wire anomaly, never a value the tool can safely recurse over.
MAX_JSON_DEPTH = 64


def loads_bounded(
    text: str,
    *,
    max_depth: int = MAX_JSON_DEPTH,
    parse_constant: Callable[[str], Any] | None = None,
) -> Any:
    """Decode one JSON document and refuse it past ``max_depth`` levels.

    A parser-level ``RecursionError`` (older interpreters) and the explicit
    depth refusal (3.15+) both surface as ``RecursionError`` so every
    existing untrusted-input boundary keeps its single malformed-input
    verdict.  The exception deliberately has no ``__cause__``: a decoder
    exception may retain the whole document, including a credential.
    """
    if max_depth < 1:
        raise ValueError("max_depth must be at least 1")
    try:
        value = json.loads(text, parse_constant=parse_constant)
    except RecursionError:
        raise RecursionError("JSON is too deeply nested") from None

    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth:
            raise RecursionError("JSON is too deeply nested")
        if isinstance(node, dict):
            stack.extend((child, depth + 1) for child in node.values())
        elif isinstance(node, list):
            stack.extend((child, depth + 1) for child in node)
    return value
