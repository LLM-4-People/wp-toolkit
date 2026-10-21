"""The exact grammar of a per-table DB dump NDJSON stream.

ONE owner for the on-disk stream shape shared by :mod:`wpt.backup` and
:mod:`wpt.restore`: :func:`wpt.backup.create_snapshot` validates every
object the bridge streams with :class:`TableStream` BEFORE it writes the
line, and :mod:`wpt.restore` feeds every parsed line through the same
class in its pre-pass.  Keeping one grammar means a snapshot that ``wpt
backup`` reports success for is exactly one that ``wpt restore`` accepts —
an accepted-then-refused stream made the backup a non-rollback (P2-7,
P2-19).

Accepted lines, and nothing else:

* ``{"table": <name>, "create": <str>}`` — schema reference only.
* ``{"table": <name>, "row": [<cell>, ...]}`` — every cell must satisfy
  :func:`check_cell` (the bridge's ``wpt_restore_cell`` rule: scalars plus
  well-formed ``[B64_MARKER, "<base64>"]`` pairs).
* ``{"table": <name>, "done": <int>}`` — exactly one, after every row,
  carrying the row-line count.

No line may follow the ``done`` line; keys are exact (an extra key is a
different, unrecognized line), ``done`` is never a bool, ``create`` is
never a non-string, and a row cell is never an object or a non-marker
array.  Every rejection is a :class:`ValueError` labelled with the
caller's ``where`` (the rest of the error contract is the caller's).
"""

import base64
import binascii
import math
from typing import Any

from .jsonutil import loads_bounded
from .wpbridge.client import B64_MARKER

__all__ = ["TableStream", "check_cell", "loads_ndjson"]


def _reject_constant(value: str) -> Any:
    """``json.loads`` hook: NaN/Infinity literals are not JSON numbers."""
    raise ValueError(f"non-finite JSON number {value}")


def loads_ndjson(line: str) -> Any:
    """Parse ONE NDJSON line with the strict number grammar.

    Python's ``json`` accepts ``NaN``/``Infinity`` and parses ``1e999`` to
    ``inf``; ``requests`` then refuses to serialise the value when the
    restore reaches the bridge, AFTER earlier tables may already have been
    swapped.  The pre-pass must refuse it first (R15-P2).
    """
    return loads_bounded(line, parse_constant=_reject_constant)


def check_cell(cell: Any, where: str) -> None:
    """Validate one parsed NDJSON cell; raise ``ValueError`` if refused.

    Mirrors the bridge's ``wpt_restore_cell`` acceptance rule exactly:
    scalars (str/int/float/bool/None — bool passes as int) plus well-formed
    ``[B64_MARKER, "<base64>"]`` pairs; every other array and any object is
    refused.  A float must be FINITE: JSON has no NaN/Infinity, and a value
    the wire cannot re-serialise is not restorable.  Cells are passed to the
    bridge UNCHANGED — bytes stay in their wire marker form off the disk
    NDJSON (the bridge decodes the marker) — so a malformed cell must fail
    in the pre-pass, before any bridge call.
    """
    if cell is None or isinstance(cell, (str, int)):
        return
    if isinstance(cell, float):
        if not math.isfinite(cell):
            raise ValueError(f"{where}: non-finite number")
        return
    if isinstance(cell, list):
        if len(cell) == 2 and cell[0] == B64_MARKER:
            if not isinstance(cell[1], str):
                raise ValueError(
                    f"{where}: {B64_MARKER} cell without a string payload")
            try:
                base64.b64decode(cell[1], validate=True)
            except (binascii.Error, ValueError) as e:
                raise ValueError(
                    f"{where}: undecodable {B64_MARKER} cell") from e
            return
        raise ValueError(f"{where}: unsupported cell type (array)")
    raise ValueError(f"{where}: unsupported cell type")


class TableStream:
    """Grammar state for one table's dump stream.

    ``accept`` takes the next parsed object (already in DISK form: bytes
    cells remarked as ``[B64_MARKER, "..."]``) and returns the cell list for
    a row line, else ``None``.  It raises :class:`ValueError` for any line
    the restore pre-pass would refuse, including a duplicate/incorrect
    ``done`` and anything after it.
    """

    def __init__(self, table: str) -> None:
        self.table = table
        self.rows = 0
        self.done: int | None = None

    def accept(self, obj: Any, where: str) -> list[Any] | None:
        if not isinstance(obj, dict) or obj.get("table") != self.table:
            raise ValueError(
                f"{where}: line is not a {self.table!r} stream object")
        if self.done is not None:
            raise ValueError(f"{where}: line after the done line")
        keys = set(obj)
        if keys == {"table", "done"}:
            value = obj["done"]
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{where}: done count must be an integer")
            if value != self.rows:
                raise ValueError(
                    f"{where}: done count {value} != {self.rows} row line(s)")
            self.done = value
            return None
        if keys == {"table", "row"}:
            row = obj["row"]
            if not isinstance(row, list):
                raise ValueError(f"{where}: row must be a cell list")
            for index, cell in enumerate(row):
                check_cell(cell, f"{where} cell {index}")
            self.rows += 1
            return row
        if keys == {"table", "create"}:
            if not isinstance(obj["create"], str):
                raise ValueError(f"{where}: create must be a string")
            return None
        raise ValueError(f"{where}: unrecognized stream line")
