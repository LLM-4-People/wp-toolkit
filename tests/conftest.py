"""Shared fixtures for the wpt test suite.

THE single owner of the wpt.* log-capture fixture (the ``wpt`` parent
logger does not propagate, so pytest's caplog cannot see wpt records) —
previously duplicated byte-identically in three test files; every test
now takes it from here.
"""

import logging

import pytest


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture(autouse=True)
def _isolate_wpt_logger():
    """Snapshot and restore the shared ``wpt`` logger around every test.

    The logger is process-wide, so a test that configures it (the CLI calls
    ``setup_logging``, which sets the level and replaces handlers) leaked
    into later tests: a test leaving it at ERROR made a restore test that
    expected a WARNING miss the record. Restore the exact pre-test state —
    level, propagation, disabled flag, filters and handlers — and drop any
    handler the test installed (its owner closes it; closing here could
    double-close a fixture-owned stream)."""
    parent = logging.getLogger("wpt")
    saved_level = parent.level
    saved_propagate = parent.propagate
    saved_disabled = parent.disabled
    saved_filters = list(parent.filters)
    saved_handlers = list(parent.handlers)
    try:
        yield
    finally:
        parent.setLevel(saved_level)
        parent.propagate = saved_propagate
        parent.disabled = saved_disabled
        parent.filters[:] = saved_filters
        parent.handlers[:] = saved_handlers


@pytest.fixture
def wpt_records():
    """Capture every wpt.* log record (the wpt parent does not propagate)."""
    handler = _Capture()
    parent = logging.getLogger("wpt")
    old_level = parent.level
    parent.addHandler(handler)
    parent.setLevel(logging.DEBUG)
    try:
        yield handler.records
    finally:
        parent.setLevel(old_level)
        parent.removeHandler(handler)


@pytest.fixture(autouse=True)
def _isolate_wporg_cache(tmp_path, monkeypatch):
    """Pin the wp.org response cache to a per-test tmp dir (autouse).

    The cache directory is a module-level Path in wpt.audit.updates; a
    test that exercises a cached fetch must never read from — let alone
    write to — the developer's real .wpt-cache (an agent's first run once
    leaked a fake 6.8.3 checksums entry there). Tests that want to pin
    cache behavior monkeypatch the same attribute on top of this."""
    import wpt.audit.updates as _updates

    monkeypatch.setattr(_updates, "_CACHE_DIR", tmp_path / "wporg-cache")
