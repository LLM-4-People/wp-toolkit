"""The logging/output chokepoints cannot be bypassed by a new module.

Diagnostics have ONE owner: :func:`wpt.log.get_logger`.  A module that
constructs its own logger or handler would escape the redaction filter, the
JSON schema, and the configured sinks.  Command report surfaces likewise write
through :func:`wpt.report.write_stdout` / :func:`wpt.report.write_stderr`;
only the dispatcher may print directly.

This is a structural contract, not a style check: AST calls are inspected, so
comments and docstrings that mention ``print()`` do not count.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WPT = ROOT / "wpt"


def _calls(path: Path) -> list[ast.Call]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return [node for node in ast.walk(tree) if isinstance(node, ast.Call)]


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _offenders(predicate) -> list[str]:
    out: list[str] = []
    for path in sorted(WPT.rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        for call in _calls(path):
            if predicate(rel, call):
                out.append(f"{rel}:{call.lineno}")
    return out


def test_no_module_constructs_a_logger_outside_wpt_log():
    """Logger/handler construction is owned by wpt/log.py alone."""
    forbidden = {
        "logging.getLogger",
        "logging.basicConfig",
        "logging.Logger",
        "logging.StreamHandler",
        "logging.FileHandler",
        "logging.NullHandler",
    }

    def bad(rel: str, call: ast.Call) -> bool:
        if rel == "wpt/log.py":
            return False
        name = _dotted(call.func)
        return name in forbidden

    offenders = _offenders(bad)
    assert not offenders, (
        "logger construction outside wpt/log.py bypasses the single "
        f"redacting/JSON sink: {offenders}"
    )


def test_only_cli_prints_and_only_report_writes_streams():
    """stdout/stderr writes have one command-output owner (wpt/report)."""
    stream_sinks = {"sys.stdout.write", "sys.stderr.write"}

    def bad(rel: str, call: ast.Call) -> bool:
        name = _dotted(call.func)
        if name == "print":
            return rel != "wpt/cli.py"
        if name in stream_sinks:
            return rel != "wpt/report.py"
        return False

    offenders = _offenders(bad)
    assert not offenders, (
        "direct stdout/stderr writes outside the central sinks: "
        f"{offenders}; use wpt.report.write_stdout/write_stderr (or the "
        "logger for diagnostics)"
    )
