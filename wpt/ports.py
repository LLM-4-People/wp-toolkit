"""One total coercion for a TCP port value — CLI and programmatic paths.

``argparse``'s ``type=int`` protects only the CLI: a programmatic caller can
put ``inf``/``nan``/``True``/``1.9`` in ``ctx.extra``, and ``int()`` either
raises ``OverflowError``/``ValueError`` (raw, before any command validation)
or silently truncates ``1.9`` to port 1.  Every command that accepts a port
therefore goes through this owner, so the accepted shape and the refusal
message cannot differ between commands.
"""

from typing import Any

__all__ = [
    "DEFAULT_PROXY_PORT", "DEFAULT_SERVE_PORT", "PORT_MAX", "PORT_MIN",
    "PORT_MIN_BINDABLE", "coerce_port",
]

#: The ONE default listen port for each local listener, read by argparse
#: AND the engine/fallback paths so the two can never drift.
DEFAULT_SERVE_PORT = 8080
DEFAULT_PROXY_PORT = 8443

#: The kernel's port range.  A protocol bound, not an operator tunable.
PORT_MIN = 0
#: The smallest port a server can BIND (0 means "ephemeral" to the kernel).
#: One owner for the FTP/deploy bindable-port floor.
PORT_MIN_BINDABLE = 1
PORT_MAX = 65535


def coerce_port(value: Any, *, name: str = "port",
                minimum: int = PORT_MIN, maximum: int = PORT_MAX) -> int:
    """Return ``value`` as an in-range ``int``, or raise ``ValueError``.

    ``bool`` is refused even though it is an ``int`` subclass (``True``
    must never become port 1).  Floats are refused rather than truncated:
    ``1.9`` is not a port.  ``minimum`` lets a caller require a bindable
    port (deploy: 1..65535) while ``0`` stays meaningful for an ephemeral
    listener (serve/proxy).
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(
            f"{name} must be an integer between {minimum} and {maximum} "
            f"(got {value!r})")
    if not minimum <= value <= maximum:
        raise ValueError(
            f"{name} must be an integer between {minimum} and {maximum} "
            f"(got {value!r})")
    return value
