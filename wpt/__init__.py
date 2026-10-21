"""wpt — WordPress site audit/clean/optimize/verify toolkit."""

__version__ = "0.1.0"

from .log import get_logger, setup_logging
from .settings import Settings, SettingsError
from .types import (
    BridgeError,
    Entry,
    Finding,
    NotWritableError,
    PlanItem,
    Source,
    SourceError,
    WptError,
)

__all__ = [
    "__version__",
    "BridgeError",
    "Entry",
    "Finding",
    "get_logger",
    "NotWritableError",
    "PlanItem",
    "Settings",
    "SettingsError",
    "setup_logging",
    "Source",
    "SourceError",
    "WptError",
]
