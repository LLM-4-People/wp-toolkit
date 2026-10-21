"""Bridge package: the canonical PHP bridge and its Python client."""

from pathlib import Path

from .client import Bridge

#: Packaged bridge script, uploaded by :meth:`Bridge.ensure` under a fresh name.
BRIDGE_PHP = Path(__file__).resolve().parent / "bridge.php"

__all__ = ["Bridge", "BRIDGE_PHP"]
