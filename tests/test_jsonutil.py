"""Tests for the bounded untrusted-JSON decoder."""

import pytest

from wpt.jsonutil import MAX_JSON_DEPTH, loads_bounded


def test_loads_bounded_keeps_an_ordinary_document():
    assert loads_bounded('{"ok": true, "rows": [1, 2]}') == {
        "ok": True, "rows": [1, 2]}


def test_loads_bounded_refuses_a_deep_document_without_retaining_it():
    deep = "[" * 200 + "0" + "]" * 200
    with pytest.raises(RecursionError, match="too deeply nested") as excinfo:
        loads_bounded(deep)
    assert excinfo.value.__cause__ is None
    assert excinfo.value.__context__ is None


def test_loads_bounded_accepts_the_configured_boundary():
    at_bound = "[" * MAX_JSON_DEPTH + "0" + "]" * MAX_JSON_DEPTH
    assert isinstance(loads_bounded(at_bound), list)
    over_bound = "[" * (MAX_JSON_DEPTH + 1) + "0" + "]" * (MAX_JSON_DEPTH + 1)
    with pytest.raises(RecursionError, match="too deeply nested"):
        loads_bounded(over_bound)
