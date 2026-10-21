"""Mutating commands (clean-files, clean-db, trim-media, ...) — action modules.

The CLI lazy-calls :func:`run` for every mutating subcommand; the action
modules self-register via ``@register_action`` at import (one block below,
the registration seam — same pattern as wpt.audit). Each module lives at
``wpt/actions/<command>.py``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .registry import run_action

# The registration seam: importing an action module registers it. Modules
# land one per writer task (clean_files, clean_db, trim_media,
# optimize_media, harden, deactivate, heal_core, reconcile_plugins,
# users_reset); each import below is
# added when its module lands.
from . import clean_files  # noqa: F401
from . import clean_db  # noqa: F401
from . import trim_media  # noqa: F401
from . import optimize_media  # noqa: F401
from . import harden  # noqa: F401
from . import deactivate  # noqa: F401
from . import heal_core  # noqa: F401
from . import update_core  # noqa: F401
from . import reconcile_plugins  # noqa: F401
from . import users_reset  # noqa: F401
from . import user_create  # noqa: F401
from . import prune_core  # noqa: F401
from . import park_backups  # noqa: F401
from . import cull_media  # noqa: F401
from . import images_webp  # noqa: F401

if TYPE_CHECKING:
    from ..cli import Ctx

__all__ = ["run"]


def run(ctx: "Ctx") -> int:
    """Dispatch ctx.command through the registry (never a hardcoded map)."""
    return run_action(ctx, ctx.command)
