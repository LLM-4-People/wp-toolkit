"""Streaming MySQL ``.sql`` dump parser for local mode (W5a).

Byte-level statement state machine exactly per ``docs/research/R4.md`` §B —
deliberately NOT regex- or line-based. A single dump can be one 10 MB+ line
(pitfall 4), so nothing here ever calls ``readline()`` or decodes the whole
file; only extracted values are decoded, lazily, ``errors='replace'``.

Two drivers run over the ONE scanner / sink / tuple-parser implementation:

* ``parse_dump``  — one full streaming pass; classifies every statement;
  per-table row counts come from tuple parsing (statement count != row count).
* ``iter_rows``   — a second streaming pass yielding decoded cells row by row
  for ONE named table (the analyzer layer, W5b, consumes this).

Cell value model (W5b contract)
-----------------------------
* unquoted ``NULL`` (any case)            -> ``None``
* bare integer                            -> ``int``
* bare float (digits, sign, ``.``, ``e``) -> ``float``
* quoted string                           -> ``str``; unescaped per the MySQL
  table ``\\0 \\' \\" \\b \\n \\r \\t \\Z \\\\``; ``\\%`` and ``\\_`` stay the
  literal two-char sequences; any other ``\\x`` -> ``x``; quote doubling
  ``'Bob''s'`` -> ``Bob's``; adjacent literals ``'a' 'b'`` concatenate.
* quoted value that strictly looks like a DECIMAL (digits with a ``.`` or
  exponent, optional sign) -> ``float`` (``'1.50'`` -> ``1.5``).  A quoted
  pure integer (``'123'``) stays ``str`` and a quoted-empty ``''`` stays
  ``''``: at the tuple level the column types are unknown, so ``''`` is NOT
  coerced to ``None``/``0`` (pitfall 10).
* ``_binary '...'`` introducer (space optional) -> ``bytes``; other
  ``_charset`` introducers -> ``str``; ``0x`` hex (odd digit count possible —
  left-padded), ``X'..'`` hex-string and ``b'01'`` bit literals -> ``bytes``
  (big-endian, zero left-padded to a byte boundary).
* unrecognised bare tokens pass through as raw ``str`` (tolerant); structural
  anomalies (truncation, stray top-level bytes inside a tuple region, the 64 MB
  per-statement cap) are logged once via ``wpt.log`` — never with statement
  content, because dumps contain secrets — and parsing continues with the
  partial row dropped.

Column-order contract (W5b contract)
-------------------------------------
``TableStats.columns`` is ALWAYS the CREATE TABLE column order.
``TableStats.insert_columns`` records the explicit column list seen on the
table's INSERT statements, or ``None`` when the dump uses position inserts.
``iter_rows`` yields cells in the STATEMENT's column-list order when the
statement has one, else the CREATE order (in a well-formed dump every INSERT
for a table uses the same shape).  To map ``option_name``/``option_value``:
call ``parse_dump`` once, then use ``insert_columns if not None else columns``.

``DumpSummary.charset`` is the raw token harvested from ``SET NAMES`` (e.g.
``utf8mb4``); cell/create decoding normalizes it to a Python codec internally
(utf8* -> utf-8, unknown -> utf-8) and always uses ``errors='replace'``.
``chunk_size`` is an internal architecture constant (R4 §B), NOT an operator
setting; it is not wired into ``wpt/settings.py`` because no operator need
exists.
"""

from __future__ import annotations

import codecs
from dataclasses import dataclass
from typing import BinaryIO, Iterator

from ..log import get_logger

log = get_logger("localmode.sql_dump")

__all__ = ["Cell", "DumpSummary", "TableStats", "iter_rows", "parse_dump"]

Cell = str | bytes | int | float | None

DEFAULT_CHUNK_SIZE = 262144
_HEAD_LIMIT = 65536
_FEED_BURST = 4096
_STMT_CAP = 64 * 1024 * 1024
_CREATE_CAP = 1024 * 1024
_SET_CAP = 4096
_PREFIX_CAP = 1024 * 1024

_BS = 0x5C
_SQ = 0x27
_DQ = 0x22
_BT = 0x60
_LP = 0x28
_RP = 0x29
_CM = 0x2C
_HSH = 0x23
_DASH = 0x2D
_SLSH = 0x2F
_STAR = 0x2A
_EXCL = 0x21
_NL = 0x0A

_WS = b" \t\r\n\x0b\x0c"
_WS_H = b" \t\r\x0b\x0c"
_WSTOP = b" \t\r\n\x0b\x0c();,`'\""

_UNESCAPE = {
    0x30: b"\x00",
    0x27: b"'",
    0x22: b'"',
    0x62: b"\x08",
    0x6E: b"\n",
    0x72: b"\r",
    0x74: b"\t",
    0x5A: b"\x1a",
    0x5C: b"\\",
}

_CONSTRAINT_WORDS = frozenset(
    b"PRIMARY UNIQUE KEY INDEX CONSTRAINT FULLTEXT SPATIAL FOREIGN CHECK".split()
)

CODE, SQ, DQ, BT, LINE_COMMENT, BLOCK_COMMENT = range(6)

_M_CLS, _M_INS, _M_BODY, _M_CREATE, _M_SET, _M_SKIP = range(6)

_P_W1, _P_W2, _P_W3, _P_TWS, _P_TBL, _P_BTL = range(6)
_P_AFT, _P_CLS, _P_CLID, _P_CLBT, _P_VALWAIT, _P_VAL = range(6, 12)


@dataclass
class TableStats:
    """Per-table facts harvested from one dump.

    ``name`` has backtick doubling already resolved; ``create_sql`` is the
    full CREATE TABLE statement text (comments stripped by the scanner,
    decoded lazily); ``columns`` is the CREATE order; ``row_count`` counts
    tuples across all INSERT/REPLACE statements; ``data_bytes`` approximates
    the INSERT tuple-region bytes scanned; ``insert_columns`` is the explicit
    column list of the table's INSERT statements (``None`` = position
    inserts, i.e. rows arrive in ``columns`` order).
    """

    name: str
    create_sql: str
    columns: list[str]
    row_count: int
    data_bytes: int
    insert_columns: list[str] | None = None


@dataclass
class DumpSummary:
    """Result of one ``parse_dump`` streaming pass."""

    tables: dict[str, TableStats]
    charset: str | None
    statement_count: int


def _codec_for(charset: str | None) -> str:
    if not charset:
        return "utf-8"
    name = charset.strip().strip(",'\"`").lower()
    if not name:
        return "utf-8"
    for cand in (name, name.replace("mb4", "").replace("mb3", "")):
        try:
            codecs.lookup(cand)
            return cand
        except LookupError:
            continue
    return "utf-8"


def _hex_bytes(digits: bytes) -> bytes | None:
    if len(digits) % 2:
        digits = b"0" + digits
    try:
        return bytes.fromhex(digits.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        return None


def _bits_to_bytes(bits: bytes) -> bytes:
    if not bits:
        return b""
    return int(bits, 2).to_bytes((len(bits) + 7) // 8, "big")


def _parse_number(word: bytes) -> int | float | None:
    n = len(word)
    if n == 0:
        return None
    j = 1 if word[0] in (0x2B, 0x2D) else 0
    digits = 0
    dots = 0
    exp = False
    while j < n:
        c = word[j]
        if 0x30 <= c <= 0x39:
            digits += 1
            j += 1
        elif c == 0x2E:
            if dots or exp:
                return None
            dots += 1
            j += 1
        elif c in (0x65, 0x45):
            if exp or digits == 0:
                return None
            exp = True
            j += 1
            if j < n and word[j] in (0x2B, 0x2D):
                j += 1
            k = j
            while k < n and 0x30 <= word[k] <= 0x39:
                k += 1
            if k == j or k != n:
                return None
            j = k
        else:
            return None
    if digits == 0:
        return None
    if dots or exp:
        try:
            return float(word.decode("ascii", "replace"))
        except ValueError:
            return None
    return int(word)


def _looks_float(data: bytes) -> bool:
    n = len(data)
    if n == 0:
        return False
    j = 1 if data[0] in (0x2B, 0x2D) else 0
    digits = 0
    dots = 0
    exps = 0
    while j < n:
        c = data[j]
        if 0x30 <= c <= 0x39:
            digits += 1
        elif c == 0x2E:
            dots += 1
        elif c in (0x65, 0x45):
            exps += 1
            if j + 1 < n and data[j + 1] in (0x2B, 0x2D):
                j += 1
        else:
            return False
        j += 1
    return digits > 0 and (dots > 0 or exps > 0)


def _skip_ws(data: bytes, i: int) -> int:
    n = len(data)
    while i < n and data[i] in _WS:
        i += 1
    return i


def _skip_intro_ws(data: bytes, i: int) -> int:
    n = len(data)
    while True:
        i = _skip_ws(data, i)
        if i < n and data[i : i + 3] == b"/*!":
            i += 3
            while i < n and 0x30 <= data[i] <= 0x39:
                i += 1
            continue
        return i


def _read_word(data: bytes, i: int) -> tuple[bytes, int]:
    j = i
    n = len(data)
    while j < n and data[j] not in _WSTOP:
        j += 1
    return data[i:j], j


def _read_backtick(data: bytes, i: int) -> tuple[bytes, int] | None:
    out = bytearray()
    i += 1
    n = len(data)
    while i < n:
        c = data[i]
        if c == _BS and i + 1 < n:
            out.append(data[i + 1])
            i += 2
        elif c == _BT:
            if i + 1 < n and data[i + 1] == _BT:
                out.append(_BT)
                i += 2
            else:
                return bytes(out), i + 1
        else:
            out.append(c)
            i += 1
    return None


def _first_kind(head: bytes, final: bool) -> str | None:
    n = len(head)
    i = _skip_intro_ws(head, 0)
    if i >= n:
        return None
    w1, j = _read_word(head, i)
    if j >= n and not final:
        return None
    up1 = w1.upper()
    if up1 == b"INSERT" or up1 == b"REPLACE":
        return "insert"
    if up1 == b"CREATE":
        k = _skip_intro_ws(head, j)
        w2, m = _read_word(head, k)
        if m >= n and not final:
            return None
        return "create" if w2.upper() == b"TABLE" else "skip"
    if up1 == b"SET":
        return "set"
    return "skip"


def _harvest_names(data: bytes) -> str | None:
    i = _skip_intro_ws(data, 0)
    w, i = _read_word(data, i)
    if w.upper() != b"SET":
        return None
    i = _skip_intro_ws(data, i)
    w, i = _read_word(data, i)
    if w.upper() != b"NAMES":
        return None
    i = _skip_intro_ws(data, i)
    if i >= len(data):
        return None
    if data[i] == _BT:
        r = _read_backtick(data, i)
        if r is None:
            return None
        tok = r[0]
    else:
        tok = _read_word(data, i)[0]
    tok = tok.strip(b"'`,\"*/")
    if not tok:
        return None
    try:
        return tok.decode("ascii")
    except UnicodeDecodeError:
        return None


def _split_top_level(data: bytes, i: int) -> tuple[list[bytes], int] | None:
    n = len(data)
    depth = 0
    items: list[bytes] = []
    item = bytearray()
    state = 0
    esc = False
    while i < n:
        b = data[i]
        i += 1
        if state == 0:
            if b == _LP:
                depth += 1
                if depth > 1:
                    item.append(b)
            elif b == _RP:
                depth -= 1
                if depth == 0:
                    stripped = bytes(item).strip()
                    if stripped:
                        items.append(stripped)
                    return items, i
                item.append(b)
            elif b == _CM and depth == 1:
                stripped = bytes(item).strip()
                if stripped:
                    items.append(stripped)
                item = bytearray()
            elif b == _SQ:
                state = 1
                esc = False
                if depth >= 1:
                    item.append(b)
            elif b == _DQ:
                state = 2
                esc = False
                if depth >= 1:
                    item.append(b)
            elif b == _BT:
                state = 3
                esc = False
                if depth >= 1:
                    item.append(b)
            elif depth >= 1:
                item.append(b)
        elif state == 1 or state == 2:
            q = _SQ if state == 1 else _DQ
            if depth >= 1:
                item.append(b)
            if esc:
                esc = False
            elif b == _BS:
                esc = True
            elif b == q:
                if i < n and data[i] == q:
                    if depth >= 1:
                        item.append(data[i])
                    i += 1
                else:
                    state = 0
        else:
            if depth >= 1:
                item.append(b)
            if esc:
                esc = False
            elif b == _BS:
                esc = True
            elif b == _BT:
                if i < n and data[i] == _BT:
                    if depth >= 1:
                        item.append(data[i])
                    i += 1
                else:
                    state = 0
    return None


def _column_name(item: bytes) -> bytes | None:
    i = _skip_ws(item, 0)
    if i >= len(item):
        return None
    if item[i] == _BT:
        r = _read_backtick(item, i)
        return r[0] if r else None
    w, _ = _read_word(item, i)
    if not w or w.upper() in _CONSTRAINT_WORDS:
        return None
    return w


def _parse_create(data: bytes, codec: str) -> tuple[str, list[str]] | None:
    i = _skip_intro_ws(data, 0)
    w, i = _read_word(data, i)
    if w.upper() != b"CREATE":
        return None
    i = _skip_intro_ws(data, i)
    w, i = _read_word(data, i)
    if w.upper() != b"TABLE":
        return None
    i = _skip_intro_ws(data, i)
    if i < len(data) and data[i] == _BT:
        r = _read_backtick(data, i)
        if r is None:
            return None
        name, i = r
    else:
        name, i = _read_word(data, i)
        if name.upper() == b"IF":
            i = _skip_intro_ws(data, i)
            _, i = _read_word(data, i)
            i = _skip_intro_ws(data, i)
            _, i = _read_word(data, i)
            i = _skip_intro_ws(data, i)
            if i < len(data) and data[i] == _BT:
                r = _read_backtick(data, i)
                if r is None:
                    return None
                name, i = r
            else:
                name, i = _read_word(data, i)
    if not name:
        return None
    i = _skip_ws(data, i)
    if i >= len(data) or data[i] != _LP:
        return None
    split = _split_top_level(data, i)
    if split is None:
        return None
    items, _ = split
    cols: list[str] = []
    for it in items:
        cn = _column_name(it)
        if cn is not None:
            cols.append(cn.decode(codec, "replace"))
    return name.decode(codec, "replace"), cols


class _ChunkReader:
    __slots__ = ("f", "size", "buf", "pos", "eof")

    def __init__(self, fileobj: BinaryIO, chunk_size: int) -> None:
        self.f = fileobj
        self.size = max(1, chunk_size)
        self.buf = bytearray()
        self.pos = 0
        self.eof = False

    def fill(self, need: int) -> None:
        if len(self.buf) - self.pos >= need:
            return
        if self.pos:
            del self.buf[: self.pos]
            self.pos = 0
        while len(self.buf) < need and not self.eof:
            data = self.f.read(self.size)
            if not data:
                self.eof = True
                break
            self.buf += data

    def ensure(self, need: int) -> bool:
        if len(self.buf) - self.pos >= need:
            return True
        self.fill(need)
        return len(self.buf) - self.pos >= need


class _Scanner:
    """The ONE statement-level byte state machine (R4 §B).

    CODE / LINE_COMMENT / BLOCK_COMMENT / single-quote / double-quote /
    backtick states with backslash-parity, paren depth, executable
    ``/*!NNNNN */`` comment tracking, DELIMITER directives and a tolerant
    terminator (``;`` + optional horizontal whitespace + newline/EOF, or the
    current client delimiter).  Statements are handed to a sink as bounded
    head/classification bytes plus body bursts; comments are skipped, all
    other statement bytes are fed.  ``run()`` is a generator that yields
    after every flush so drivers can drain rows lazily.
    """

    def __init__(self, fileobj: BinaryIO, chunk_size: int, sink: "_Sink") -> None:
        self._rd = _ChunkReader(fileobj, chunk_size)
        self._sink = sink
        self.statement_count = 0
        self._offset = 0
        self._state = CODE
        self._depth = 0
        self._exec = 0
        self._bs_esc = False
        self._sq_esc = False
        self._dq_esc = False
        self._bt_esc = False
        self._delim = b";"
        self._stmt_open = False
        self._head9 = bytearray()
        self._dir_line: bytearray | None = None
        self._dir_over = False
        self._stmt_bytes = 0
        self._skip_feed = False
        self._cap_logged = False
        self._feed_buf = bytearray()
        self._dirty = False

    def run(self) -> Iterator[None]:
        rd = self._rd
        buf = rd.buf
        while True:
            if rd.pos >= len(buf):
                rd.fill(1)
                buf = rd.buf
                if rd.pos >= len(buf):
                    break
                continue
            b = buf[rd.pos]
            rd.pos += 1
            self._offset += 1
            if self._dir_line is not None:
                self._emit(b)
                if b == _NL:
                    self._finish_directive()
                elif len(self._dir_line) < 1024:
                    self._dir_line.append(b)
                else:
                    self._dir_over = True
            elif self._state == CODE:
                if self._bs_esc:
                    self._bs_esc = False
                    self._emit(b)
                elif b == self._delim[0]:
                    self._on_delim(b)
                elif b == _BS:
                    self._bs_esc = True
                elif b == _SQ:
                    self._state = SQ
                    self._sq_esc = False
                    self._emit(b)
                elif b == _DQ:
                    self._state = DQ
                    self._dq_esc = False
                    self._emit(b)
                elif b == _BT:
                    self._state = BT
                    self._bt_esc = False
                    self._emit(b)
                elif b == _LP:
                    self._depth += 1
                    self._emit(b)
                elif b == _RP:
                    if self._depth:
                        self._depth -= 1
                    self._emit(b)
                elif b == _DASH:
                    self._dash(b)
                elif b == _HSH:
                    self._state = LINE_COMMENT
                elif b == _SLSH:
                    self._slash(b)
                elif b == _STAR:
                    if self._exec:
                        if rd.ensure(1) and rd.buf[rd.pos] == _SLSH:
                            rd.pos += 1
                            self._offset += 1
                            self._exec -= 1
                            self._emit(_STAR)
                            self._emit(_SLSH)
                        else:
                            self._emit(b)
                    else:
                        self._emit(b)
                else:
                    self._emit(b)
            elif self._state == SQ:
                if self._sq_esc:
                    self._sq_esc = False
                elif b == _BS:
                    self._sq_esc = True
                elif b == _SQ:
                    if rd.ensure(1) and rd.buf[rd.pos] == _SQ:
                        rd.pos += 1
                        self._offset += 1
                        self._emit(_SQ)
                    else:
                        self._state = CODE
                self._emit(b)
            elif self._state == DQ:
                if self._dq_esc:
                    self._dq_esc = False
                elif b == _BS:
                    self._dq_esc = True
                elif b == _DQ:
                    if rd.ensure(1) and rd.buf[rd.pos] == _DQ:
                        rd.pos += 1
                        self._offset += 1
                        self._emit(_DQ)
                    else:
                        self._state = CODE
                self._emit(b)
            elif self._state == BT:
                if self._bt_esc:
                    self._bt_esc = False
                elif b == _BS:
                    self._bt_esc = True
                elif b == _BT:
                    if rd.ensure(1) and rd.buf[rd.pos] == _BT:
                        rd.pos += 1
                        self._offset += 1
                        self._emit(_BT)
                    else:
                        self._state = CODE
                self._emit(b)
            elif self._state == LINE_COMMENT:
                if b == _NL:
                    self._state = CODE
            else:
                if b == _STAR and rd.ensure(1) and rd.buf[rd.pos] == _SLSH:
                    rd.pos += 1
                    self._offset += 1
                    self._state = CODE
            if self._dirty or len(self._feed_buf) >= _FEED_BURST:
                self._dirty = False
                self._flush_feed()
                yield None
                buf = rd.buf
        if self._dir_line is not None:
            self._finish_directive()
        elif self._stmt_open:
            self._end_statement()
        self._flush_feed()
        yield None

    def _emit(self, b: int) -> None:
        if not self._stmt_open:
            self._stmt_open = True
            self._sink.start()
        self._stmt_bytes += 1
        if len(self._head9) < 9:
            self._head9.append(b)
            if len(self._head9) == 9:
                self._check_directive()
        if self._stmt_bytes > _STMT_CAP:
            if not self._cap_logged:
                self._cap_logged = True
                log.warning(
                    "sql dump: statement exceeds %d-byte cap near offset %d; "
                    "rest of statement skipped", _STMT_CAP, self._offset)
            self._skip_feed = True
            return
        if self._skip_feed:
            return
        self._feed_buf.append(b)

    def _flush_feed(self) -> None:
        buf = self._feed_buf
        if not buf:
            return
        if self._skip_feed:
            buf.clear()
            return
        data = bytes(buf)
        buf.clear()
        if not self._sink.feed(data):
            self._skip_feed = True

    def _check_directive(self) -> None:
        h = self._head9
        if h[:8].upper() == b"DELIMITER" and h[8] in (0x20, 0x09):
            self._dir_line = bytearray(h)
            self._dir_over = False

    def _finish_directive(self) -> None:
        line = self._dir_line
        self._dir_line = None
        if self._dir_over:
            log.warning("sql dump: oversized DELIMITER directive near offset %d; "
                        "delimiter unchanged", self._offset)
        else:
            parts = bytes(line).split()
            if len(parts) >= 2:
                self._delim = parts[-1]
            else:
                log.warning("sql dump: DELIMITER directive without token near "
                            "offset %d; delimiter unchanged", self._offset)
        self._end_statement()

    def _end_statement(self) -> None:
        self._flush_feed()
        if self._stmt_open:
            self._sink.end()
            self._stmt_open = False
            self.statement_count += 1
        self._head9 = bytearray()
        self._dir_line = None
        self._dir_over = False
        self._stmt_bytes = 0
        self._skip_feed = False
        self._cap_logged = False
        self._state = CODE
        self._depth = 0
        self._exec = 0
        self._bs_esc = self._sq_esc = self._dq_esc = self._bt_esc = False
        self._dirty = True

    def _on_delim(self, b: int) -> None:
        if self._depth or self._exec:
            self._emit(b)
            return
        rd = self._rd
        delim = self._delim
        if len(delim) > 1:
            need = len(delim) - 1
            if not rd.ensure(need) or rd.buf[rd.pos : rd.pos + need] != delim[1:]:
                self._emit(b)
                return
            rd.pos += need
            self._offset += need
        hold = bytearray()
        while True:
            if not rd.ensure(1):
                self._end_statement()
                return
            c = rd.buf[rd.pos]
            if c == _NL:
                rd.pos += 1
                self._offset += 1
                self._end_statement()
                return
            if c in _WS_H:
                rd.pos += 1
                self._offset += 1
                hold.append(c)
                continue
            break
        for i in range(len(delim)):
            self._emit(delim[i])
        for i in range(len(hold)):
            self._emit(hold[i])

    def _dash(self, b: int) -> None:
        rd = self._rd
        if rd.ensure(1) and rd.buf[rd.pos] == _DASH:
            if (not rd.ensure(2)) or rd.buf[rd.pos + 1] in _WS:
                rd.pos += 1
                self._offset += 1
                self._state = LINE_COMMENT
                return
        self._emit(b)

    def _slash(self, b: int) -> None:
        rd = self._rd
        if rd.ensure(1) and rd.buf[rd.pos] == _STAR:
            if rd.ensure(2) and rd.buf[rd.pos + 1] == _EXCL:
                rd.pos += 2
                self._offset += 2
                self._exec += 1
                self._emit(b)
                self._emit(_STAR)
                self._emit(_EXCL)
            else:
                rd.pos += 1
                self._offset += 1
                self._state = BLOCK_COMMENT
            return
        self._emit(b)


class _InsertPrefix:
    """Streaming prefix parser: ``INSERT|REPLACE [IGNORE] INTO <table>
    [(cols)] VALUE(S)`` with arbitrary whitespace; backticked table/column
    names (doubling + ``\\``` escape) or unquoted ones.
    """

    __slots__ = ("_buf", "_i", "_st", "_word", "_name", "_cols", "_esc",
                 "table", "columns", "failed", "done")

    def __init__(self) -> None:
        self._buf = bytearray()
        self._i = 0
        self._st = _P_W1
        self._word = bytearray()
        self._name = b""
        self._cols: list[bytes] | None = None
        self._esc = False
        self.table = b""
        self.columns: list[bytes] | None = None
        self.failed = False
        self.done = False

    def feed(self, data: bytes) -> tuple[bool, bytes | None]:
        self._buf += data
        if len(self._buf) > _PREFIX_CAP:
            self.failed = True
        else:
            self._advance()
        if self.failed:
            return False, None
        if self.done:
            return True, bytes(self._buf[self._i:])
        return True, None

    def _advance(self) -> None:
        buf = self._buf
        n = len(buf)
        while not self.done and not self.failed:
            i = self._i
            if i >= n:
                return
            b = buf[i]
            st = self._st
            if st in (_P_W1, _P_W2, _P_W3):
                self._i = i + 1
                if b in _WS:
                    if self._word:
                        self._kw_done(st)
                else:
                    self._word.append(b)
            elif st == _P_TWS:
                if b in _WS:
                    self._i = i + 1
                elif b == _BT:
                    self._i = i + 1
                    self._st = _P_BTL
                    self._word = bytearray()
                else:
                    self._st = _P_TBL
            elif st == _P_TBL:
                if b in _WS or b == _LP:
                    self._name = bytes(self._word)
                    self._word = bytearray()
                    self._st = _P_AFT
                else:
                    self._i = i + 1
                    self._word.append(b)
            elif st == _P_BTL:
                if self._esc:
                    self._esc = False
                    self._i = i + 1
                    self._word.append(b)
                elif b == _BS:
                    self._esc = True
                    self._i = i + 1
                elif b == _BT:
                    if i + 1 < n:
                        if buf[i + 1] == _BT:
                            self._i = i + 2
                            self._word.append(_BT)
                        else:
                            self._i = i + 1
                            self._name = bytes(self._word)
                            self._word = bytearray()
                            self._st = _P_AFT
                    else:
                        return
                else:
                    self._i = i + 1
                    self._word.append(b)
            elif st == _P_AFT:
                if b in _WS:
                    self._i = i + 1
                elif b == _LP:
                    self._i = i + 1
                    self._st = _P_CLS
                    self._cols = []
                else:
                    self._st = _P_VAL
            elif st == _P_CLS:
                if b in _WS or b == _CM:
                    self._i = i + 1
                elif b == _BT:
                    self._i = i + 1
                    self._st = _P_CLBT
                    self._word = bytearray()
                elif b == _RP:
                    self._i = i + 1
                    self._st = _P_VALWAIT
                else:
                    self._st = _P_CLID
            elif st == _P_CLID:
                if b in _WS or b == _CM or b == _RP:
                    self._cols.append(bytes(self._word))
                    self._word = bytearray()
                    self._i = i + 1
                    if b == _RP:
                        self._st = _P_VALWAIT
                    else:
                        self._st = _P_CLS
                else:
                    self._i = i + 1
                    self._word.append(b)
            elif st == _P_CLBT:
                if self._esc:
                    self._esc = False
                    self._i = i + 1
                    self._word.append(b)
                elif b == _BS:
                    self._esc = True
                    self._i = i + 1
                elif b == _BT:
                    if i + 1 < n:
                        if buf[i + 1] == _BT:
                            self._i = i + 2
                            self._word.append(_BT)
                        else:
                            self._i = i + 1
                            self._cols.append(bytes(self._word))
                            self._word = bytearray()
                            self._st = _P_CLS
                    else:
                        return
                else:
                    self._i = i + 1
                    self._word.append(b)
            elif st == _P_VALWAIT:
                if b in _WS:
                    self._i = i + 1
                else:
                    self._st = _P_VAL
            else:
                if b in _WS or b == _LP:
                    self._kw_done(_P_VAL)
                else:
                    self._i = i + 1
                    self._word.append(b)

    def _kw_done(self, st: int) -> None:
        word = bytes(self._word)
        self._word = bytearray()
        up = word.upper()
        if st == _P_W1:
            if up not in (b"INSERT", b"REPLACE"):
                self.failed = True
            else:
                self._st = _P_W2
        elif st == _P_W2:
            if up == b"INTO":
                self._st = _P_TWS
            elif up == b"IGNORE":
                self._st = _P_W3
            else:
                self.failed = True
        elif st == _P_W3:
            if up == b"INTO":
                self._st = _P_TWS
            else:
                self.failed = True
        else:
            if up in (b"VALUE", b"VALUES") and self._name:
                self.table = self._name
                self.columns = self._cols
                self.done = True
            else:
                self.failed = True


class _TupleParser:
    """Streaming splitter for the VALUES region of an INSERT/REPLACE.

    One implementation serves both drivers: ``count`` mode counts tuples and
    data bytes; ``cells`` mode additionally materializes decoded cells.
    Structure: a top-level ``(`` opens a row, depth-1 ``,`` ends a cell,
    depth-1 ``)`` ends the row, any whitespace separates tokens.  Strings are
    scanned with backslash parity (a quote closes iff it is not escaped) and
    quote doubling, both across chunk boundaries.  Stray content at top level
    abandons the rest of the statement (never misattributes rows to a table).
    """

    __slots__ = ("mode", "codec", "rows", "rows_done", "bytes_seen", "anomaly",
                 "_abandoned", "_top", "_depth", "_row", "_parts", "_tok",
                 "_intro", "_quote", "_sbuf", "_str_esc", "_str_close",
                 "_str_bin", "_str_intro")

    def __init__(self, mode: str, codec: str = "utf-8") -> None:
        self.mode = mode
        self.codec = codec
        self.rows: list[list[Cell]] = []
        self.rows_done = 0
        self.bytes_seen = 0
        self.anomaly = False
        self._abandoned = False
        self._top = True
        self._depth = 0
        self._row: list[Cell] | None = None
        self._parts: list[tuple[str, object]] | None = None
        self._tok = bytearray()
        self._intro: bytes | None = None
        self._quote: int | None = None
        self._sbuf = bytearray()
        self._str_esc = False
        self._str_close = False
        self._str_bin = False
        self._str_intro: bytes | None = None

    def feed(self, data: bytes) -> None:
        self.bytes_seen += len(data)
        for b in data:
            self._byte(b)

    def finish(self) -> None:
        self._finish_word()
        if (self._quote is not None or self._str_close or not self._top
                or self._row is not None):
            self.anomaly = True
        self._row = None
        self._parts = None

    def _byte(self, b: int) -> None:
        if self._abandoned:
            return
        q = self._quote
        if q is not None:
            if self._str_close:
                self._str_close = False
                if b == q:
                    self._sbuf.append(b)
                    return
                self._close_string()
                self._structural(b)
                return
            if self._str_esc:
                self._str_esc = False
                self._unescape(b)
                return
            if b == _BS:
                self._str_esc = True
                return
            if b == q:
                self._str_close = True
                return
            self._sbuf.append(b)
            return
        self._structural(b)

    def _unescape(self, b: int) -> None:
        out = _UNESCAPE.get(b)
        if out is not None:
            self._sbuf += out
            return
        if b == 0x25 or b == 0x5F:
            self._sbuf.append(_BS)
            self._sbuf.append(b)
            return
        self._sbuf.append(b)

    def _open_string(self, q: int) -> None:
        intro = self._intro
        self._intro = None
        if self._parts is None:
            self._parts = []
        self._quote = q
        self._sbuf = bytearray()
        self._str_esc = False
        self._str_close = False
        self._str_intro = intro
        self._str_bin = bool(intro) and intro.upper() == b"_BINARY"

    def _close_string(self) -> None:
        content = bytes(self._sbuf)
        self._quote = None
        self._sbuf = bytearray()
        self._str_esc = False
        self._str_close = False
        intro = self._str_intro
        self._str_intro = None
        binary = self._str_bin
        self._str_bin = False
        up = intro.upper() if intro is not None else b""
        if up == b"B":
            ok = bool(content) and all(ch in (0x30, 0x31) for ch in content)
            if ok:
                if self._parts is None:
                    self._parts = []
                self._parts.append(("bin", _bits_to_bytes(content)))
                return
            self.anomaly = True
        elif up == b"X":
            decoded = _hex_bytes(content)
            if decoded is not None:
                if self._parts is None:
                    self._parts = []
                self._parts.append(("bin", decoded))
                return
            self.anomaly = True
        if self._parts is None:
            self._parts = []
        if binary:
            self._parts.append(("bin", content))
        else:
            self._parts.append(("plain", content))

    def _structural(self, b: int) -> None:
        if self._top:
            if b in _WS:
                return
            if b == _LP:
                self._top = False
                self._depth = 1
                self._row = []
                self._parts = None
                return
            if b == _CM:
                return
            self.anomaly = True
            self._abandoned = True
            return
        if self._parts is None:
            self._parts = []
        if b == _LP:
            self._depth += 1
            self._tok.append(b)
        elif b == _RP:
            if self._depth == 1:
                self._finish_word()
                if self._parts is not None:
                    self._finish_cell()
                self._finish_row()
            else:
                self._depth -= 1
                self._tok.append(b)
        elif b == _CM and self._depth == 1:
            self._finish_word()
            self._finish_cell()
        elif b in _WS:
            self._finish_word()
        elif b == _SQ or b == _DQ:
            self._finish_word()
            self._open_string(b)
        else:
            self._tok.append(b)

    def _finish_word(self) -> None:
        if not self._tok:
            return
        word = bytes(self._tok)
        self._tok = bytearray()
        if self._parts is None:
            self._parts = []
        up = word.upper()
        if up == b"NULL":
            self._parts.append(("null", None))
            return
        c0 = word[0]
        if c0 == 0x5F:
            self._intro = word
            return
        if word[:2] in (b"0X", b"0x") and len(word) > 2:
            decoded = _hex_bytes(word[2:])
            if decoded is not None:
                self._parts.append(("bin", decoded))
                return
        if up in (b"B", b"X"):
            self._intro = word
            return
        num = _parse_number(word)
        if num is not None:
            self._parts.append(("num", num))
            return
        self._parts.append(("plain", word))

    def _finish_cell(self) -> None:
        if self._intro is not None:
            if self._parts is None:
                self._parts = []
            self._parts.append(("plain", self._intro))
            self._intro = None
        parts = self._parts
        self._parts = []
        if parts is None or not parts:
            self._row.append("")
            return
        if len(parts) == 1:
            kind, val = parts[0]
            if kind == "plain":
                self._row.append(self._resolve(val))
            else:
                self._row.append(val)
            return
        if all(k in ("plain", "bin") for k, _ in parts):
            if any(k == "bin" for k, _ in parts):
                self._row.append(b"".join(v for _, v in parts))
            else:
                self._row.append(self._resolve(b"".join(v for _, v in parts)))
            return
        self.anomaly = True
        self._row.append("")

    def _resolve(self, val: bytes):
        if _looks_float(val):
            try:
                return float(val.decode("ascii"))
            except ValueError:
                pass
        return val.decode(self.codec, "replace")

    def _finish_row(self) -> None:
        row = self._row
        self._row = None
        self._parts = None
        self._depth = 0
        self._top = True
        self.rows_done += 1
        if self.mode == "cells" and row is not None:
            self.rows.append(row)


class _Sink:
    """Statement routing shared by both drivers: classify on the bounded head
    (first word, skipping ``/*!NNNNN`` introducers), then hand the statement
    bytes to a per-mode consumer.  ``feed`` returns False once the statement
    is of no interest so the scanner can drop the rest of its bytes.
    """

    def __init__(self, *, track_create: bool) -> None:
        self._track_create = track_create
        self._mode = _M_CLS
        self._head = bytearray()
        self._create = bytearray()
        self._setbuf = bytearray()
        self._prefix: _InsertPrefix | None = None
        self._tup: _TupleParser | None = None
        self._n = 0
        self._charset: str | None = None
        self._codec = "utf-8"

    def start(self) -> None:
        self._n += 1
        self._mode = _M_CLS
        self._head = bytearray()
        self._create = bytearray()
        self._setbuf = bytearray()
        self._prefix = None
        self._tup = None

    def feed(self, data: bytes) -> bool:
        if self._mode == _M_SKIP:
            return False
        if self._mode == _M_CLS:
            self._head += data
            kind = _first_kind(bytes(self._head), False)
            if kind is None:
                if len(self._head) > _HEAD_LIMIT:
                    self._mode = _M_SKIP
                    return False
                return True
            self._set_mode(kind)
            leftover = bytes(self._head)
            self._head = bytearray()
            return self._route(leftover)
        return self._route(data)

    def end(self) -> None:
        if self._mode == _M_CLS:
            kind = _first_kind(bytes(self._head), True)
            if kind is not None:
                self._set_mode(kind)
                leftover = bytes(self._head)
                self._head = bytearray()
                self._route(leftover)
        if self._mode == _M_INS:
            log.debug("sql dump: unrecognized or truncated INSERT/REPLACE "
                      "statement #%d skipped", self._n)
        elif self._mode == _M_BODY:
            self._finish_body()
        elif self._mode == _M_CREATE:
            self._finish_create()
        elif self._mode == _M_SET:
            self._finish_set()
        self._prefix = None

    def _set_mode(self, kind: str) -> None:
        if kind == "insert":
            self._mode = _M_INS
            self._prefix = _InsertPrefix()
        elif kind == "create":
            self._mode = _M_CREATE if self._track_create else _M_SKIP
        elif kind == "set":
            self._mode = _M_SET
        else:
            self._mode = _M_SKIP

    def _route(self, data: bytes) -> bool:
        mode = self._mode
        if mode == _M_INS:
            ok, leftover = self._prefix.feed(data)
            if not ok:
                self._mode = _M_SKIP
                return False
            if leftover is not None:
                self._begin_body(leftover)
            return True
        if mode == _M_BODY:
            self._tup.feed(data)
            return True
        if mode == _M_CREATE:
            if len(self._create) + len(data) <= _CREATE_CAP:
                self._create += data
                return True
            self._mode = _M_SKIP
            return False
        if mode == _M_SET:
            if len(self._setbuf) + len(data) <= _SET_CAP:
                self._setbuf += data
                return True
            self._mode = _M_SKIP
            return False
        return False

    def _begin_body(self, leftover: bytes) -> None:
        self._mode = _M_BODY
        self._tup = _TupleParser("count")
        self._tup.feed(leftover)

    def _finish_body(self) -> None:
        self._tup = None

    def _finish_create(self) -> None:
        self._create = bytearray()

    def _finish_set(self) -> None:
        found = _harvest_names(bytes(self._setbuf))
        self._setbuf = bytearray()
        if found is None:
            return
        if self._charset is None:
            self._charset = found
        self._codec = _codec_for(found)


class _SummarySink(_Sink):
    """parse_dump driver: table registry + row/byte counting + charset."""

    def __init__(self) -> None:
        super().__init__(track_create=True)
        self.tables: dict[str, TableStats] = {}

    @property
    def charset(self) -> str | None:
        return self._charset

    def _finish_body(self) -> None:
        tup = self._tup
        prefix = self._prefix
        self._tup = None
        tup.finish()
        name = prefix.table.decode(self._codec, "replace")
        stats = self.tables.get(name)
        if stats is None:
            stats = TableStats(name=name, create_sql="", columns=[],
                               row_count=0, data_bytes=0)
            self.tables[name] = stats
        stats.row_count += tup.rows_done
        stats.data_bytes += tup.bytes_seen
        if prefix.columns is not None:
            cols = [c.decode(self._codec, "replace") for c in prefix.columns]
            if stats.insert_columns is None:
                stats.insert_columns = cols
            elif stats.insert_columns != cols:
                log.debug("sql dump: table %s: differing INSERT column list "
                          "ignored (statement #%d)", name, self._n)
        if tup.anomaly:
            log.warning("sql dump: structural anomaly in INSERT data for "
                        "table %s (statement #%d); affected rows skipped",
                        name, self._n)

    def _finish_create(self) -> None:
        data = bytes(self._create)
        self._create = bytearray()
        parsed = _parse_create(data, self._codec)
        if parsed is None:
            log.debug("sql dump: unparsable CREATE TABLE statement #%d skipped",
                      self._n)
            return
        name, cols = parsed
        prev = self.tables.get(name)
        stats = TableStats(
            name=name,
            create_sql=data.decode(self._codec, "replace"),
            columns=cols,
            row_count=prev.row_count if prev else 0,
            data_bytes=prev.data_bytes if prev else 0,
            insert_columns=prev.insert_columns if prev else None,
        )
        self.tables[name] = stats


class _RowSink(_Sink):
    """iter_rows driver: decode cells for ONE table only."""

    def __init__(self, table: str) -> None:
        super().__init__(track_create=False)
        self._target = table

    def _begin_body(self, leftover: bytes) -> None:
        if self._prefix.table.decode(self._codec, "replace") != self._target:
            self._mode = _M_SKIP
            return
        self._mode = _M_BODY
        self._tup = _TupleParser("cells", self._codec)
        self._tup.feed(leftover)

    def _finish_body(self) -> None:
        tup = self._tup
        tup.finish()
        if tup.anomaly:
            log.warning("sql dump: structural anomaly in INSERT data for "
                        "table %s (statement #%d); affected rows skipped",
                        self._target, self._n)

    def take_rows(self) -> list[list[Cell]]:
        tup = self._tup
        if tup is None or not tup.rows:
            return []
        out = tup.rows
        tup.rows = []
        return out


def parse_dump(fileobj: BinaryIO, *, chunk_size: int = DEFAULT_CHUNK_SIZE) -> DumpSummary:
    """One full streaming pass over a binary-mode dump file object.

    Classifies every statement, counts tuples per table via the INSERT prefix
    (never LOCK TABLES), harvests the ``SET NAMES`` charset, and returns the
    summary.  Reads ``fileobj.read(chunk_size)`` in binary only; never
    readline(), never whole-file decode.
    """
    sink = _SummarySink()
    scanner = _Scanner(fileobj, chunk_size, sink)
    for _ in scanner.run():
        pass
    summary = DumpSummary(tables=sink.tables, charset=sink.charset,
                          statement_count=scanner.statement_count)
    log.info("sql dump parsed: %d tables, %d rows in %d statements",
             len(summary.tables),
             sum(t.row_count for t in summary.tables.values()),
             summary.statement_count)
    return summary


def iter_rows(fileobj: BinaryIO, table: str, *,
              chunk_size: int = DEFAULT_CHUNK_SIZE) -> Iterator[list[Cell]]:
    """Stream the rows of ONE table from a binary-mode dump file object.

    A second pass over the same kind of file; yields decoded cells row by row
    for every INSERT/REPLACE statement whose prefix names ``table``.  Cells
    arrive in the statement's column-list order when it has one, else the
    CREATE order (see the module docstring for the full value model).
    """
    sink = _RowSink(table)
    scanner = _Scanner(fileobj, chunk_size, sink)
    taken = 0
    for _ in scanner.run():
        for row in sink.take_rows():
            taken += 1
            yield row
    log.debug("sql dump: iter_rows table=%s rows=%d", table, taken)
