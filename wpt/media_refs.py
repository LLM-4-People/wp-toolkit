r"""DB-referenced media — the database half of the media keep-set.

THE LIVE-PROVEN DEFECT THIS MODULE EXISTS FOR: a WordPress page renders
only a FRACTION of its attachment images.  On an observed site, the
keep-set built from the live walk alone covered most files and bytes only
through database references the walk never sees — featured images in
menus/widgets/theme options, ``srcset`` candidates, attachment pages,
gallery templates, PDFs linked from post content.  A compliant apply
would have deleted them and broken images across the site.  The
defensible remainder on the same site was small.

So the keep-set is a UNION: the rendered live references (the walker's
``live_refs``) PLUS the media the DATABASE references.  This module owns
the database side, per source mode, and answers ONE question in both:
*which uploads files does the database reference?*

Remote (ftp) — :func:`db_refs_from_bridge` asks the bridge with ONE
read-only ``media_map`` call in ``mode=db``.  That is the same
bulk-work-owner seam the media actions already use for upload paths
(``media_map``), extended with one read-only mode rather than a second
op; the SQL is server-side, whitelisted-identifier, read-only, and
unbounded on purpose (a truncated keep-set is a deletion bug).

Offline (local) — :func:`db_refs_from_dump` streams the .sql dump
through the W5a parser (``wpt.localmode.sql_dump.parse_dump`` /
``iter_rows``) and the analyzer's safe ``php_unserialize``.  It never
re-parses SQL ad hoc: the dump is read with the same state machine the
whole tool already trusts, and the same PHP-serialize subset the
analyzer uses for option values.

Both produce uploads-RELATIVE POSIX paths ("2023/10/pic-300x233.jpg")
— the exact shape ``walk_site``'s ``live_refs`` and the bridge's
``media_map`` use, so the union needs no translation.

What counts as a database reference (the union the live measurement was
proven with — every source below is a real reference class, and a
MISSING variant is a broken-image bug, not a false positive):

* ``_wp_attached_file`` — the authoritative path of every attachment
  (uploads-relative; a value that carries the full uploads marker is
  accepted too, as very old sites store);
* ``_wp_attachment_metadata`` AND the legacy
  ``_wp_attachment_backup_sizes`` — the metadata's own ``file`` key plus
  every ``sizes[*].file`` entry, in BOTH stored forms: a bare basename
  (anchored to the attachment's directory, the bridge's
  ``wpt_media_variants`` rule) and a full uploads-relative path;
* every other postmeta value, every option value, every termmeta value
  and every post's content/excerpt/guid that NAMES an uploads path —
  theme options (page-builder themes), widget instances, nav-menu item meta,
  builder JSON, PDFs and downloads linked from content.

On-disk size VARIANTS of a referenced file are not this module's job:
``wpt.audit.media`` keeps every same-directory stem sibling of a ref
(the L5 rule), which is the same rule bridge.php's ``wpt_media_variants``
applies server-side.

None vs empty (the tool-wide contract): an empty set is a REAL measured
result ("the database references no uploads file"), ``None`` is
UNKNOWN — no usable dump tables, no bridge, or a bridge call that
failed — and must never be read as an empty keep-set.  Every consumer
treats a ``None`` side as DEGRADED (see ``wpt.audit.media``'s evidence
classes) and the trim-media apply refuses closed.

THE TWO MODES MUST RETURN THE SAME SET (the mode-dependent-keep-set
defect this module's gate exists for)
-----------------------------------------------------------

The DB half of the keep-set is measured in one of two places — the dump
here, the bridge's ``wpt_media_db_map`` there — and a destructive plan
is built from ONE of them.  When the two disagree, the SAME database
yields two different DELETE sets, and which one runs decides whether a
referenced attachment survives: a regression sweep measured exactly
that on an observed site, where the local dump path kept a multi-size
``2019/02/SampleImg*`` family as database-referenced while the live
bridge path kept NONE of them.  Thirteen stored-value shapes made the two
halves disagree, and the
bridge's answer is the correct one in EVERY one: each divergence was a
rule the dump path did not implement — no normalization, no keep-gate, no
``maybe_unserialize`` tolerance, no text scan of the attachment rows.
Eight of the thirteen made the offline half lose references the live one
keeps (a deletion bug); five made it keep references the gate refuses (a
harmless over-protection that is still a mode difference).

So every rule below is stated once, here, and MIRRORED there:

=================================  ==================================
rule (this module)                 bridge.php mirror
=================================  ==================================
:func:`ref_normalize`              ``wpt_media_ref_normalize``
:func:`ref_is_kept`                ``wpt_media_ref_is_kept``
:func:`refs_in_text`               ``wpt_media_refs_in_text``
:data:`REF_EXTENSIONS`             ``wpt_media_ref_extensions``
:func:`_meta_file_names`           ``wpt_media_meta_names``
:func:`ref_from_attached_file`     ``wpt_media_attached_ref``
:func:`_php_decode` (metadata)     ``@unserialize``
=================================  ==================================

THE EXTENSION FAMILY IS CARRIED BY THE READ, NOT GUESSED BY IT
--------------------------------------------------------------

``REF_EXTENSIONS`` is the MIRRORED DEFAULT — the copy of the shipped
``wpt/data/profiles/default.json`` ``media.extensions`` list that lives here
and in bridge.php (the deployed file cannot read the operator's profile).
For many runs that is the whole story, but ``media.extensions`` is a
set-reachable profile key [L20] and a WIDENED profile used to break the
one guarantee this module exists for: the KEEP-GATE and the ENUMERATION
came from two different lists, so a file whose extension only the profile
knew (``--set media.extensions=[..., "psd"]``) was invisible to the
bridge's gate, invisible in the union, and therefore a deletion CANDIDATE
— a database-referenced attachment removed by a compliant apply.

So the read mode now carries the caller's family: ``media_map``
``mode=db`` accepts an ``extensions`` list, and the gate answers with
``default UNION requested`` (see :func:`db_refs_from_bridge` and
``wpt_media_ref_extensions``).  The default is a FLOOR, never a ceiling:
the wire can only WIDEN the gate, so no request — a widened profile, a
narrowed one, or a hand-written one that omits or empties the list — can
make the live gate NARROWER than the shipped family, and the only
invariant the deletion rests on holds for every profile: the gate always
contains the enumeration's family, so a reference can never be invisible
to the half of the keep-set that decides whether a file is deletable.

The rules PHP's ``unserialize`` has and this module's decoder reproduces
are in :func:`_php_decode`'s docstring, and the reference is the
DEPLOYED EXPRESSION itself — bridge.php's ``wpt_media_meta_names`` asks
``is_array( @unserialize( $raw ) )``, which attempts the decode on EVERY
value and IGNORES both the diagnostic it may raise and the bytes that
follow the value.  The offline side can only agree with that by
implementing the same rule, and every place it used not to was a
deletion bug measured on this module's own fixtures: a metadata map
carrying ONE null (``N;``), object (``O:``), custom (``C:``), enum
(``E:``) or back-reference (``R:``) value anywhere, a value nested
deeper than the decoder's own bound, or trailing bytes after the value
each made the dump path reject the WHOLE map and lose every registered
size of that attachment — while the live half, running the deployed
expression, kept them all.

``tests/test_media_refs.py`` runs the REAL ``wpt_media_db_map`` out of
bridge.php over a table fixture and diffs it against
:func:`db_refs_from_dump` for the same rows, so a rule that drifts on
either side fails the suite instead of deleting files in one mode only.
The client is deliberately shape-only (``Bridge._usable_db_ref``): the
RULES live server-side, and this module's gate is their offline twin —
not a second decision.

Structural WordPress facts (NOT profile tunables, like media.py's
uploads prefix): the ``wp-content/uploads/`` marker, the metadata key
names, and the attachment-metadata value shape.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, BinaryIO, Mapping, TYPE_CHECKING
from urllib.parse import unquote

from .deadline import check_deadline
from .localmode.sql_dump import TableStats, iter_rows, parse_dump
from .log import get_logger

if TYPE_CHECKING:  # annotation-only (gathered data crosses module boundaries)
    from .wpbridge.client import Bridge

__all__ = [
    "META_SIZE_KEYS",
    "REF_EXTENSIONS",
    "UPLOADS_DIR",
    "UPLOADS_MARKER",
    "UPLOADS_PREFIX",
    "DumpIdentity",
    "PhpDecodeError",
    "RoleResolution",
    "db_refs_for_data",
    "db_refs_from_bridge",
    "db_refs_from_dump",
    "decode_php_value",
    "dump_identity",
    "dump_role_tables",
    "options_prefix",
    "ref_from_attached_file",
    "ref_is_kept",
    "ref_normalize",
    "refs_from_attachment_meta",
    "refs_in_text",
    "resolve_role",
    "resolve_role_by_name",
    "uploads_dirs",
]

log = get_logger("media_refs")

#: The nesting a stored value may have and still be a value, i.e. PHP's own
#: bound and not a tolerance: measured on the PHP 8.4 CLI, ``unserialize()``
#: accepts 4096 nested arrays and returns ``false`` for the 4097th ("Maximum
#: depth of 4096 exceeded"), and that is the default of
#: ``unserialize_max_depth`` the deployed bridge's bare ``@unserialize``
#: reads.  A bound BELOW it is not a safety belt, it is a mode difference: a
#: metadata value nested deeper than the bound is a map the live half reads
#: and this half refuses, so every registered size of that attachment is lost
#: offline and becomes a deletion candidate.  The decoder is ITERATIVE (see
#: :func:`_php_value`) because python's own recursion limit is far below this
#: figure — measured: a recursive descent raised ``RecursionError`` at about
#: 190 levels, which is not the unreadable value a refused map must be.
#:
#: IT IS NOT A MIRROR OF THE BRIDGE'S PROOF BUDGET, and must not become one.
#: The deployed ``wpt_media_rewrite_apply`` proves a value's shape with a
#: WORK budget of 1024 levels (``WPT_MEDIA_SHAPE_WORK_BUDGET`` — a count of
#: levels opened, because that walk's cost is quadratic in the depth), and a
#: value between the two numbers has two different fates, both correct: this
#: decoder READS it (so the keep-set keeps every registered size of that
#: attachment, in both modes), and the bridge REFUSES to rewrite that row —
#: by name, on the per-row ``failed[]`` channel, which is where a per-file
#: answer belongs.  Lowering this constant to the server's number would buy
#: nothing (the client sends the row either way — it is the SHAPE PROOF that
#: refuses it, not the transport) and would cost every offline reference a
#: value that deep names, which is the data-loss direction this constant
#: exists to avoid.  ``tests/test_bridge_php.py`` pins the two numbers
#: against each other and against bridge.php's own ``define``.
_MAX_DEPTH = 4096

#: A PHP integer literal (``i:-5;``): an optional sign then digits, and
#: nothing else — python's ``int()`` would also read " 5" and "1_0".
_INT_LITERAL = re.compile(rb"[+-]?[0-9]+")

#: A PHP double literal (``d:1.5;``, ``d:INF;``, ``d:-INF;``, ``d:NAN;``).
_DOUBLE_RE = re.compile(rb"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?")

#: A PHP array key spelled as an integer.  PHP casts a string key to int
#: ONLY for the canonical decimal form — optional minus, then either "0" or
#: a digit string with no leading zero, and only while the value fits a
#: platform int (verified against PHP 8.4: "0" and "-5" cast, "007",
#: "-0", "+12", " 1", "1.5" and a value past PHP_INT_MAX stay strings).
#: Key CASTING is part of the reference rule: a size map keyed "0" must be
#: read exactly as the live side reads it, or a metadata row's sizes are
#: found in one mode and not the other.
_INT_KEY = re.compile(r"-(?:[1-9][0-9]*)|(?:0|[1-9][0-9]*)")

#: PHP's int range, the bound past which a numeric key stays a string.
_PHP_INT_MIN = -(2 ** 63)
_PHP_INT_MAX = 2 ** 63 - 1

#: The uploads TREE, webroot-relative — the structural WordPress layout
#: fact the walker, the enumeration and the is-a-directory gate all speak
#: in (wpt/audit/media.py re-exports it, so there is one copy).  NOT a
#: profile knob: WordPress puts uploads here in every install.
UPLOADS_DIR = "wp-content/uploads"

#: The same prefix with its trailing slash, for path tests.
UPLOADS_PREFIX = UPLOADS_DIR + "/"

#: The uploads path marker as it appears INSIDE stored text (option values,
#: post content, serialized metadata): a full uploads URL, an absolute path
#: or a site-relative path all contain this exact substring.  Structural
#: WordPress layout fact, not a profile knob (same convention as
#: wpt/audit/media.py's uploads prefix and wpt/walk.py's URL marker).
UPLOADS_MARKER = "wp-content/uploads/"

#: The two postmeta keys whose VALUE is an attachment's size map.  The
#: second is the legacy key some themes/plugins keep a copy of (it holds
#: the same ``sizes`` shape) — a migration that never wrote it would
#: delete every restored thumbnail, so both are read.
META_SIZE_KEYS = ("_wp_attachment_metadata", "_wp_attachment_backup_sizes")

#: Characters that END a path inside stored TEXT (HTML attributes, JSON,
#: CSS url(), PHP-serialized strings, prose).  Matched set-for-set with
#: bridge.php's ``$wpt_media_ref_delims`` — the two implementations MUST
#: stay in lockstep, exactly like ``_file_stem`` / ``wpt_file_stem``.
#: Only ever applied to text capture: a stored PATH value is never cut
#: here, because a filename may legitimately contain a space.
_TEXT_DELIMITERS = frozenset(" \t\r\n\f\v\0\"'<>()[]{}?#;,|&=`\\*!$")

#: Trailing punctuation stripped from a captured tail: a path that ends a
#: sentence or sits in a CSS declaration.  WordPress's own
#: ``sanitize_file_name`` strips these from real filenames, so stripping
#: them here can only help a real file match.
_TRAILING_PUNCTUATION = ".,;:!\u2019\u201d"

#: Column signature per scanned table — a table participates only when its
#: CREATE/INSERT columns prove the columns we read exist (the analyzer's
#: "table detection never guesses" rule).
_COLUMNS = {
    "options": ("option_name", "option_value"),
    "postmeta": ("meta_key", "meta_value"),
    "posts": ("post_content",),
    "termmeta": ("meta_key", "meta_value"),
}

#: The DEFAULT extension family a REFERENCE may carry: the shipped
#: ``wpt/data/profiles/default.json`` ``media.extensions`` list (no dots) —
#: the same allowlist the enumeration files uploads media by
#: (:func:`wpt.audit.media.is_media`, which delegates here).  Mirrored
#: verbatim in bridge.php (``wpt_media_ref_extensions``) because that file
#: is DEPLOYED on a host that cannot read the operator's profile.
#:
#: It is the default AND THE FLOOR, not the only family: a read carries
#: the caller's list (the profile's), and the effective family is this
#: list UNION the caller's — so a widened profile is honoured and no
#: request can narrow the live gate below this shipped family.  Never
#: decide an operator's family from this literal: it is the mirror, the
#: profile is the owner.
#: ``tests/test_media_refs.py`` pins this literal against the shipped
#: default, against bridge.php's ``wpt_media_ref_extensions()`` AND
#: against the WIDENED profile the end-to-end deletion scenario uses.
REF_EXTENSIONS = (
    "jpg", "jpeg", "jpe", "png", "gif", "webp", "avif", "bmp", "ico", "svg",
    "tiff", "mp3", "m4a", "ogg", "oga", "wav", "flac", "mp4", "m4v", "webm",
    "mov", "avi", "ogv", "3gp", "3g2", "pdf", "doc", "docx", "xls", "xlsx",
    "ppt", "pptx", "odt", "key", "txt", "csv", "zip", "gz", "tar",
)


# ------------------------------------------------------------- path plumbing


def _rel_path(value: str) -> str | None:
    """Validate an uploads-RELATIVE path value (no text cleanup).

    Rejects the empty string, a directory, an absolute path and any
    empty/``.``/``..`` segment; returns the POSIX path otherwise.  A stored
    value is taken verbatim (a filename may contain spaces, and it is
    already the on-disk name — no percent-decoding here, that rule belongs
    to URL capture only).  This is the bridge's ``wpt_media_attached_ref``
    segment rule — the two reject the same shapes for the same reason (a
    path that can only address something else is not a reference).
    """
    value = value.strip()
    if not value or value.startswith("/") or value.endswith("/"):
        return None
    segments = value.split("/")
    if any(segment in ("", ".", "..") for segment in segments):
        return None
    return "/".join(segments)


def ref_normalize(raw: Any) -> str | None:
    """One raw reference source -> its uploads-RELATIVE path, or ``None``.

    THE MIRROR of bridge.php's ``wpt_media_ref_normalize``, in the same
    order, so every source (the text scanner, an ``_wp_attached_file``
    value, a ``sizes[*].file`` entry) is anchored the same way in BOTH
    modes:

    * NUL bytes stripped, trimmed, backslashes folded to ``/`` (a
      Windows-shaped stored path is still a path);
    * a value carrying the uploads MARKER is cut to the tail after it —
      this is what maps a site migrated from ANOTHER host
      (``/home/olduser/public_html/wp-content/uploads/2018/03/x.jpg``) to
      its host-independent tail;
    * an absolute value with no marker is refused: nothing anchors it to
      this site's uploads tree;
    * repeated slashes collapsed, and empty/``.``/``..`` segments refused.

    The NUL and backslash rules are not theoretical: a stored
    ``2019\\\\02\\\\photo.jpg`` or a value with a trailing NUL byte kept a
    path that can never match a real file, so the offline keep-set held a
    ref that protected nothing while the live one held the real path.
    """
    if not isinstance(raw, str):
        return None
    value = raw.replace("\0", "").replace("\\", "/").strip()
    if not value:
        return None
    at = value.find(UPLOADS_MARKER)
    if at >= 0:
        value = value[at + len(UPLOADS_MARKER):]
    elif value.startswith("/"):
        return None
    while "//" in value:
        value = value.replace("//", "/")
    segments = value.split("/")
    if any(segment in ("", ".", "..") for segment in segments):
        return None
    return "/".join(segments)


def ref_is_kept(ref: str, extensions: Any = REF_EXTENSIONS,
                dirs: Any = None) -> bool:
    """Is this normalized ref a FILE the keep-set can honour?

    THE MIRROR of bridge.php's ``wpt_media_ref_is_kept``, and the ONE
    implementation of the rule on this side of the wire — the extension
    half is what :func:`wpt.audit.media.is_media` delegates to, so a file
    that is not media and a reference that is not a media file are judged
    by the same code.

    True only when the basename carries an extension from ``extensions``
    (the shipped ``media.extensions`` family, :data:`REF_EXTENSIONS`) and
    the path is not an existing DIRECTORY.  The directory test is the
    belt to the extension's braces: a directory can carry a
    media-looking name (``2023/thumbs.cache``, a plugin's own
    ``cache.png`` folder), and a directory in a keep-set protects nothing
    while making the answer unreadable.  ``dirs`` is that test's only
    input — the set of uploads-relative DIRECTORY paths the source
    enumerated — and ``None`` (the default, and what the bridge does when
    ``wp_upload_dir`` is unreadable) SKIPS the test rather than dropping
    references: the extension gate still holds, and skipping can only
    over-protect, which is the safe direction for a deletion.

    A ref must be in the family for ONE reason: a path with no usable
    extension is not a file reference at all.  A stale
    ``_transient_dirsize_cache`` option on a real site (measured
    an observed run) held many absolute paths to the site's PREVIOUS host,
    several of which were bare YEAR DIRECTORIES ("2018".."2023") — a year, a
    ``.htaccess`` and a ``cache.png`` directory all name nothing
    deletable, and one such row is enough to make a keep-set unreadable.
    """
    if not isinstance(ref, str) or not ref:
        return False
    name = ref.rsplit("/", 1)[-1]
    dot = name.rfind(".")
    if dot <= 0:
        return False  # no extension, or a dotfile (".htaccess")
    if name[dot + 1:].lower() not in extensions:
        return False
    if dirs is not None and ref in dirs:
        return False
    return True


def _clean_tail(tail: str) -> str | None:
    """One tail captured from TEXT -> a usable uploads-relative path.

    Cuts at the first delimiter, percent-DECODES (a stored URL's tail must
    equal the on-disk name — the same rule the walker applies), strips
    trailing sentence punctuation, then validates as a relative path.
    """
    cut = len(tail)
    for char in tail:
        if char in _TEXT_DELIMITERS:
            cut = tail.index(char)
            break
    tail = unquote(tail[:cut]).strip()
    while tail and tail[-1] in _TRAILING_PUNCTUATION:
        tail = tail[:-1]
    return _rel_path(tail)


def refs_in_text(text: Any) -> set[str]:
    """Every uploads-relative path NAMED anywhere in ``text``.

    A non-string (a NULL cell, a numeric option) yields an empty set.  This
    is the extractor the bridge mirrors server-side; it is deliberately
    shape-agnostic about its input (HTML, JSON, CSS, PHP-serialized
    strings, prose) because the reference lives in all of them.
    """
    if not isinstance(text, str) or UPLOADS_MARKER not in text:
        return set()
    found: set[str] = set()
    offset = 0
    while True:
        at = text.find(UPLOADS_MARKER, offset)
        if at < 0:
            break
        offset = at + len(UPLOADS_MARKER)
        tail = _clean_tail(text[offset:])
        if tail is not None:
            found.add(tail)
    return found


def ref_from_attached_file(value: Any) -> str | None:
    """One ``_wp_attached_file`` value -> its uploads-relative path.

    The mirror of bridge.php's ``wpt_media_attached_ref``.  The stored
    value is normally already uploads-relative ("2023/10/pic.jpg"); a
    value that carries the uploads marker (very old sites store the full
    URL/path there) is read through :func:`refs_in_text` and the FIRST
    path in TEXT order wins — the same path PHP's
    ``$refs[0]`` returns.  None = unusable (empty, absolute, traversing).
    """
    if not isinstance(value, str):
        return None
    if UPLOADS_MARKER in value:
        for ref in refs_in_text(value):
            return ref
        return None
    return _rel_path(value)



class _RefGate:
    """THE ONE collection point of a database media map: normalize, gate,
    record — the mirror of bridge.php's ``wpt_media_ref_add``.

    ``dropped`` counts every reference the stored data offered that
    normalization or the gate refused, and rides out of
    :func:`db_refs_from_dump` as one warning: a lossy keep-set is
    REPORTED (the bridge's client does the same with the count the server
    sends), never silently narrowed and never fatal.
    """

    def __init__(self, extensions: Any = REF_EXTENSIONS, dirs: Any = None):
        self.refs: set[str] = set()
        self.dropped = 0
        self._extensions = extensions
        self._dirs = dirs

    def add(self, raw: Any) -> str | None:
        """Record one raw reference source; return its normalized path.

        The normalized value is returned so the caller can ANCHOR to it
        (the attachment-metadata directory rule reads the normalized
        path, never the gate's verdict: a value the gate refuses can
        still be the directory a size map's bare basenames belong in).
        """
        ref = ref_normalize(raw)
        if ref is None or not ref_is_kept(ref, self._extensions, self._dirs):
            self.dropped += 1
            return None
        self.refs.add(ref)
        return ref

    def add_text(self, text: Any) -> None:
        """Every uploads path NAMED in a stored text blob (the text
        scanner, :func:`refs_in_text` — the mirror of the bridge's
        ``wpt_media_refs_in_text`` pass over every LIKE-matching row)."""
        for ref in refs_in_text(text):
            self.add(ref)


def _dir_prefix(path: str) -> str:
    """The DIRECTORY PREFIX of an uploads-relative path: "2023/11/" —
    the concatenation prefix for a bare size basename, and "" at the
    uploads root.  The trailing slash is part of the value, exactly like
    bridge.php's ``$prefix`` in ``wpt_media_variants`` (the two
    implementations join bare basenames the same way)."""
    head, sep, _tail = path.rpartition("/")
    return head + sep


# -------------------------------------------------------- attachment metadata


class _PhpValue:
    """A decoded PHP OBJECT (``O:``), CUSTOM serialization (``C:``) or enum
    case (``E:``) — the stand-in for the three tags :func:`_php_decode`
    consumes without resurrecting.

    A distinct type on purpose: it stands in for exactly what PHP's
    ``is_array()`` says about the decoded value (an object is not an
    array), so the metadata reader's ``isinstance(..., dict)`` test keeps
    PHP's own verdict.  It is never a ``str``, so it can never be read as
    a file name either.  Nothing here ever instantiates a real object.
    """

    __slots__ = ("tag",)

    def __init__(self, tag: str) -> None:
        self.tag = tag

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<php {self.tag}>"


class _PhpDecodeError(ValueError):
    """A stored value PHP's ``unserialize`` would REJECT (false)."""


#: The public name of :class:`_PhpDecodeError` — the ONE decoder's error,
#: so a caller that has to tell "unreadable" from "read" can catch it
#: without importing a private.
PhpDecodeError = _PhpDecodeError


def _php_uint(buf: bytes, pos: int) -> tuple[int, int]:
    """A ``LEN``/``COUNT`` literal -> (value, next position)."""
    end = pos
    while end < len(buf) and 0x30 <= buf[end] <= 0x39:
        end += 1
    if end == pos:
        raise _PhpDecodeError("expected a number")
    try:
        return int(buf[pos:end]), end
    except ValueError:
        raise _PhpDecodeError("number literal too large") from None


def _php_header(buf: bytes, pos: int, tag: bytes) -> tuple[int, int]:
    """``TAG:N:`` -> (N, position after the second colon)."""
    if buf[pos + 1:pos + 2] != b":":
        raise _PhpDecodeError("malformed %s header" % tag.decode())
    number, at = _php_uint(buf, pos + 2)
    if buf[at:at + 1] != b":":
        raise _PhpDecodeError("malformed %s header" % tag.decode())
    return number, at + 1


def _php_string(buf: bytes, pos: int) -> tuple[str, int]:
    """``s:LEN:"..."`` — the payload must be exactly LEN BYTES, as PHP
    counts them (UTF-8 encoded, never character counts)."""
    length, at = _php_header(buf, pos, b"s")
    if buf[at:at + 1] != b'"':
        raise _PhpDecodeError("missing string opening quote")
    end = at + 1 + length
    if (end + 2 > len(buf) or buf[end:end + 1] != b'"'
            or buf[end + 1:end + 2] != b";"):
        raise _PhpDecodeError(
            "string payload is not exactly its declared byte length")
    try:
        return buf[at + 1:end].decode("utf-8"), end + 2
    except UnicodeDecodeError:
        raise _PhpDecodeError("string payload is not valid UTF-8") from None


def _php_value(buf: bytes, pos: int, depth: int) -> tuple[Any, int]:
    """One serialized value -> (value, next position).

    ITERATIVE, over an explicit stack of the OPEN containers, and that is a
    requirement of the rule rather than a style: :data:`_MAX_DEPTH` is what
    PHP itself accepts (4096), so a value PHP reads is a value this decoder
    has to read too, and a recursive descent into 4096 levels does not
    survive python's own stack (measured: it raised ``RecursionError`` at
    about 190 levels, which no ``except`` in this module turns into the
    unreadable value it is).  The stack is the same trick bridge.php's
    ``wpt_media_rewrite_declared_shape`` uses, for the same reason.

    ``seen`` is PHP's back-reference table: PHP's is 1-based with the value
    being decoded in its first slot (so ``R:1;`` inside an array is the
    self-reference PHP has); this list is the same table 0-indexed, so
    ``R:n;`` resolves to ``seen[n - 1]`` exactly as PHP's ``var_hash``
    numbers it (values only — an array KEY takes no index; measured against
    PHP 8.4).  A CONTAINER is registered when it is OPENED, before its own
    members, and a leaf when it is complete, which is the order PHP's
    ``var_hash`` fills; a KEY and a back-reference take no slot (measured
    against PHP 8.4).  A back-reference PAST the end is the one reference
    PHP rejects outright (``unserialize`` returns false).

    Every tag PHP's ``unserialize`` reads is read here: ``N;``/``b:``/``i:``/
    ``d:``/``s:``/``a:``/``O:``/``C:``/``E:``/``R:``/``r:``.  ``O:``/``C:``/
    ``E:`` produce a :class:`_PhpValue` (an object, which ``is_array()``
    refuses) with their members still CONSUMED, because a mis-declared
    length or count is a decode error PHP reports and this decoder must
    report as well; a ``C:`` payload and an ``E:`` case name are opaque to
    both sides (PHP hands them to the class and never parses them), so they
    are skipped by their declared byte length.  An enum case whose case
    does not exist is the one shape PHP refuses and this decoder cannot
    know about (the class is not loaded here) — it is read as an object,
    which can only keep MORE references than the live side does.
    """
    seen: list = []  # PHP's 1-based table, 0-indexed here
    # The OPEN containers, innermost last.  A frame is
    #   [ the container's own value, its members, members left, its key,
    #     a member VALUE comes next, is an object ]
    # An object frame keeps a members map it never reads: the members are
    # consumed because the bytes after them are still bytes, and discarded
    # because an object's properties are not what this module reads.
    frames: list = []
    expect_key = True   # the value at `pos` is the first KEY of the frame
    register = True     # ... and it takes a slot in PHP's var_hash
    have = False        # a finished value is in `out`, waiting to be placed
    out: Any = None
    while True:
        if not have:
            if pos >= len(buf):
                raise _PhpDecodeError("truncated serialized value")
            if depth > _MAX_DEPTH:
                raise _PhpDecodeError("serialized value nested too deeply")
            tag = buf[pos:pos + 1]
            slot = register   # does this value take a var_hash slot?
            if tag == b"N":
                if buf[pos + 1:pos + 2] != b";":
                    raise _PhpDecodeError("malformed null")
                out, pos = None, pos + 2
            elif tag == b"s":
                out, pos = _php_string(buf, pos)
            elif tag == b"i":
                out, pos = _php_scalar(buf, pos, b"i")
            elif tag == b"b":
                if buf[pos + 2:pos + 3] not in (b"0", b"1") or \
                        buf[pos + 3:pos + 4] != b";":
                    raise _PhpDecodeError("malformed boolean")
                out, pos = buf[pos + 2:pos + 3] == b"1", pos + 4
            elif tag == b"d":
                out, pos = _php_scalar(buf, pos, b"d")
            elif tag in (b"R", b"r"):
                out, pos = _php_backref(buf, pos, seen)
                slot = False   # a reference is a pointer, never a new value
            elif tag == b"a":
                count, at = _php_header(buf, pos, b"a")
                if buf[at:at + 1] != b"{":
                    raise _PhpDecodeError("missing array opening brace")
                out = {}
                seen.append(out)   # before its own members: R:1; is itself
                if not count:
                    # an array holding nothing closes on the byte that
                    # follows its brace — no key is read for it
                    if buf[at + 1:at + 2] != b"}":
                        raise _PhpDecodeError(
                            "value does not hold its declared members")
                    pos, slot, have = at + 2, False, True
                else:
                    frames.append([out, out, count, None, True, False])
                    pos = at + 1
                    depth += 1
                    expect_key, register = True, False
                    continue
            elif tag in (b"O", b"C", b"E"):
                stand_in, pos, frame = _php_open_object(buf, pos)
                out = stand_in
                if frame is not None:
                    # opened before its own members, exactly as PHP does:
                    # a back-reference to this very object resolves to it
                    seen.append(stand_in)
                    frames.append(frame)
                    depth += 1
                    expect_key, register = True, False
                    continue
            else:
                raise _PhpDecodeError("unsupported serialization tag %r" % (tag,))
            if slot:
                seen.append(out)
            have = True

        # ---- place the finished value, and decide what is read next
        if not frames:
            return out, pos
        frame = frames[-1]
        if expect_key:
            # an array KEY must be an int or a string; PHP refuses anything
            # else (measured: a float, a bool, a null, an object, an array
            # and a back-reference to one all make unserialize return
            # false), and a bool is an int in python but not in PHP.
            if not frame[5] and (not isinstance(out, (str, int))
                                 or isinstance(out, bool)):
                raise _PhpDecodeError("array key is not an int or string")
            if not frame[5]:
                out = _php_key(out)
            frame[3] = out
            frame[4] = False
            expect_key, register, have = False, True, False
            continue
        if not frame[5]:
            frame[1][frame[3]] = out
        frame[2] -= 1
        if frame[2] > 0:
            expect_key, register, have = True, False, False
            continue
        # the container is COMPLETE: its own closing brace is the next byte
        if buf[pos:pos + 1] != b"}":
            raise _PhpDecodeError(
                "value does not hold its declared number of members")
        pos += 1
        frames.pop()
        depth -= 1
        out = frame[0]   # the container itself, already in ``seen``
        expect_key, register, have = False, True, True


def _php_open_object(buf: bytes, pos: int) -> tuple[Any, int, Any]:
    """``O:``/``C:``/``E:`` -> (the object stand-in, next position, frame).

    A frame means the token OPENS a member list (``O:``): the caller pushes
    it and reads the members.  ``None`` means the token is complete on its
    own — a ``C:`` custom payload and an ``E:`` enum case name are OPAQUE,
    skipped by their declared byte length exactly as PHP skips them (PHP
    hands both to the class and never parses them).
    """
    tag = buf[pos:pos + 1]
    if buf[pos + 1:pos + 2] != b":":
        raise _PhpDecodeError("malformed %s header" % tag.decode())
    name_len, at = _php_uint(buf, pos + 2)
    if buf[at:at + 1] != b":" or buf[at + 1:at + 2] != b'"':
        raise _PhpDecodeError("malformed object class name")
    name_end = at + 2 + name_len
    if buf[name_end:name_end + 1] != b'"':
        raise _PhpDecodeError("malformed object class name")
    if tag == b"E":
        # the declared length spans "Class:Case", and the token ends there
        if b":" not in buf[at + 2:name_end]:
            raise _PhpDecodeError("malformed enum case name")
        if buf[name_end + 1:name_end + 2] != b";":
            raise _PhpDecodeError("malformed enum case")
        return _PhpValue("E"), name_end + 2, None
    if buf[name_end + 1:name_end + 2] != b":":
        raise _PhpDecodeError("malformed object header")
    body_len, after = _php_uint(buf, name_end + 2)
    if buf[after:after + 1] != b":" or buf[after + 1:after + 2] != b"{":
        raise _PhpDecodeError("malformed object body")
    if tag == b"C":
        end = after + 2 + body_len
        if end + 1 > len(buf) or buf[end:end + 1] != b"}":
            raise _PhpDecodeError("custom serialization length is wrong")
        return _PhpValue("C"), end + 1, None
    stand_in = _PhpValue("O")
    if not body_len:
        # an object holding no members closes on the byte that follows its
        # brace — no member name is read for it
        if buf[after + 2:after + 3] != b"}":
            raise _PhpDecodeError("malformed object header")
        return stand_in, after + 3, None
    return stand_in, after + 2, [stand_in, {}, body_len, None, True, True]


def _php_scalar(buf: bytes, pos: int, tag: bytes) -> tuple[Any, int]:
    """``i:N;`` / ``d:FLOAT;`` -> (value, next position).

    The literal is matched, not coerced: python's ``int()`` would also read
    ``" 5"``, ``"1_0"`` and ``"\u00a0"``-style forms PHP refuses, and a
    value PHP rejects must be an unreadable value here too.
    """
    end = pos + 2
    while end < len(buf) and buf[end] != 0x3B:
        end += 1
    if end >= len(buf):
        raise _PhpDecodeError("malformed %s" % tag.decode())
    token = buf[pos + 2:end]
    if tag == b"i":
        if _INT_LITERAL.fullmatch(token) is None:
            raise _PhpDecodeError("malformed integer")
        # PHP SATURATES an integer literal past the platform range (a
        # measured i:99999999999999999999; decodes to PHP_INT_MAX), so
        # python's unbounded int must be clamped to the same answer.
        return max(_PHP_INT_MIN, min(_PHP_INT_MAX, int(token))), end + 1
    text = token.decode("ascii", "replace")
    if text not in ("INF", "+INF", "-INF", "NAN"):
        if _DOUBLE_RE.fullmatch(token) is None:
            raise _PhpDecodeError("malformed double")
    try:
        return float(text.replace("INF", "inf").replace("NAN", "nan")), end + 1
    except ValueError:  # pragma: no cover - the regex already excluded it
        raise _PhpDecodeError("malformed double") from None


def _php_key(key: Any) -> Any:
    """One decoded array key, cast the way PHP's array casts it."""
    if not isinstance(key, str) or _INT_KEY.fullmatch(key) is None:
        return key
    number = int(key)
    if not _PHP_INT_MIN <= number <= _PHP_INT_MAX:
        return key
    return number


def _php_backref(buf: bytes, pos: int, seen: list) -> tuple[Any, int]:
    """``R:N;`` / ``r:N;`` -> the value PHP's ``var_hash`` holds at N.

    PHP's table is 1-based and its first slot is the value being decoded,
    so ``R:1;`` inside an array is a self-reference (measured: PHP decodes
    it into a recursion) and the first decoded VALUE is at ``R:2;``.  A
    reference past the end is the one thing PHP rejects here (verified
    against PHP 8.4: ``unserialize`` returns false, it does not decode as
    null), so it is an unreadable value like any other.
    """
    if buf[pos + 1:pos + 2] != b":":
        raise _PhpDecodeError("malformed reference")
    number, at = _php_uint(buf, pos + 2)
    if buf[at:at + 1] != b";":
        raise _PhpDecodeError("malformed reference")
    if number < 1 or number > len(seen):
        raise _PhpDecodeError("reference to a value that was never stored")
    return seen[number - 1], at + 1


def decode_php_value(raw: str, *, require_eof: bool = False) -> Any:
    """PHP's ``unserialize`` semantics, as a pure decoder (nothing is ever
    evaluated, no object is ever resurrected).

    THE ONE decoder of a stored PHP value, and the ONE owner of that
    question, because the live half of the keep-set runs PHP's own decoder
    — bridge.php's ``wpt_media_meta_names`` asks exactly
    ``is_array( @unserialize( $raw ) )`` — and the offline half can only
    agree with it by implementing the same rule.  Every reader of a stored
    value therefore comes HERE (that is what the public name is for), so a
    caller cannot reach for a stricter reader and get a worse answer for a
    value PHP reads perfectly well: the webp-media rewrite's local gate is
    one such caller, and reading its values through a narrower reader used
    to report "could not be parsed" for a ``C:`` payload, a 200-deep value
    or a value with trailing bytes — shapes the live side rewrites.

    THE RULE (PHP is the reference, because the live half runs PHP's own
    decoder):

    * ``s:LEN:"..."`` — the payload must be exactly LEN BYTES;
    * ``a:N:{...}`` — exactly N key/value pairs, keys CAST the way PHP
      casts them (a canonical decimal string key becomes an int; "007",
      "-0", "+12", "1.5" and a value past PHP_INT_MAX stay strings) and
      keys of any OTHER type refused (PHP's ``unserialize`` returns false
      for a float, a bool, a null, an object, an array or a
      back-reference to one used as a key — measured);
    * ``i:``/``b:``/``d:``/``N;`` — int, bool, float (PHP's INF/NAN
      spellings included), null;
    * ``O:``/``C:``/``E:``/``R:``/``r:`` — decoded and CONSUMED, but
      represented as :class:`_PhpValue` (an object, which ``is_array()``
      refuses) or as the value the back-reference points at.  A single
      ``N;``, ``O:``, ``C:``, ``E:`` or ``R:`` ANYWHERE inside a size map
      must not cost the map: PHP keeps the whole array, and a decoder that
      rejects the map loses every one of that attachment's registered
      sizes;
    * nesting is bounded at :data:`_MAX_DEPTH`, which is the depth PHP
      8.4 itself accepts — a value deeper than that is one PHP's own
      ``unserialize`` returns ``false`` for, so the two agree on every
      payload that can exist;
    * ``require_eof`` is the one thing a caller may ask to be stricter
      about, and it is a POLICY switch, not a second parser.  ``False``
      (the default, and the deployed expression's own behaviour) IGNORES
      bytes AFTER the value, exactly as the deployed ``@unserialize``
      ignores them (measured on PHP 8.4: ``a:1:{s:1:"a";s:1:"x";}junk``
      yields the array and raises only a diagnostic the bridge's ``@``
      suppresses).  The deployed expression is the whole rule: a
      suppressed warning still yields a value, so a decoder that treated
      a diagnostic as a refusal would drop the size map of every
      attachment whose stored value carries one — the deletion bug this
      module exists to prevent.  ``True`` refuses them, which is right for
      a reader of a WHOLE CELL (an option value): there, bytes after the
      value are part of what the site stored, and dropping them would
      report a fact the dump does not contain.
    * anything else — a wrong length, a truncated value, a bad count, a
      back-reference past the end — is the one answer PHP's
      ``unserialize`` gives as ``false``, i.e. UNREADABLE, raised as
      :class:`PhpDecodeError`.

    This is the rule :func:`wpt.localmode.analyzer.php_unserialize`
    delegates to for its narrower purpose (option values, where the
    analyzer applies its own POLICY on top: objects and nulls refused,
    trailing bytes refused, a tighter depth bound).  One implementation,
    two callers: the two readers must not disagree about what a value
    holds, and neither may quietly widen the other's door.
    """
    if not isinstance(raw, str):
        raise _PhpDecodeError("a serialized value is a str")
    try:
        buf = raw.encode("utf-8")
    except UnicodeEncodeError:
        raise _PhpDecodeError("value cannot be measured as UTF-8 bytes") \
            from None
    # the position the value ended at is compared with len(buf) ONLY when
    # the caller asked for it: PHP reads the value and ignores what follows.
    value, pos = _php_value(buf, 0, 0)
    if require_eof and pos != len(buf):
        raise _PhpDecodeError("trailing bytes after the serialized value")
    return value


def _php_decode(raw: str) -> Any:
    """This module's own call of :func:`decode_php_value` — the keep-set
    reads with the deployed expression's leniency, so it never refuses a
    value over bytes that follow it."""
    return decode_php_value(raw)


def _meta_map(raw: Any) -> dict | None:
    """The decoded attachment-metadata value, or None when unreadable.

    WordPress stores it PHP-serialized; some plugins store the same array as
    JSON.  The order IS the rule and it is bridge.php's
    ``wpt_media_meta_names`` order: ``maybe_unserialize`` FIRST (which is
    what PHP's ``@unserialize`` here does — it attempts the decode on
    EVERY value, never a prefix guess), the JSON form only as the
    fallback.  A malformed, truncated or unsupported serialization yields
    None: an unreadable size map is UNKNOWN, never "this attachment has no
    other files" (the fail direction that deletes live thumbnails).
    """
    if not isinstance(raw, str) or not raw:
        return None
    try:
        value: Any = _php_decode(raw)
    except _PhpDecodeError:
        try:
            value = json.loads(raw)
        except ValueError:
            return None
    return value if isinstance(value, dict) else None



def _meta_file_names(raw: Any) -> tuple[list[str], list[str]]:
    """(uploads-relative names, bare basenames) named by a size map.

    TWO stored forms are read, and both are load-bearing:

    * the map's own ``file`` key (the attachment's path) plus every
      ``sizes[*].file`` entry;
    * each entry in either form — one carrying a ``/`` is already
      uploads-relative (leading slashes are stripped, the bridge's
      tolerance), one without is a bare basename the caller must anchor to
      the attachment's own directory.
    """
    full: list[str] = []
    bare: list[str] = []
    meta = _meta_map(raw)
    if meta is None:
        return full, bare
    sizes = meta.get("sizes")
    candidates = [size.get("file") for size in sizes.values()
                  if isinstance(size, dict)] \
        if isinstance(sizes, dict) else []
    candidates.append(meta.get("file"))
    for name in candidates:
        if not isinstance(name, str) or not name:
            continue
        if "/" in name:
            rel = _rel_path(name.lstrip("/"))
            if rel is not None:
                full.append(rel)
        else:
            bare.append(name)
    return full, bare


def refs_from_attachment_meta(raw: Any, dir_prefix: str = "",
                             extensions: Any = REF_EXTENSIONS,
                             dirs: Any = None) -> set[str]:
    """One attachment-metadata value -> every file it names that the
    keep-gate honours (the same gate, the same verdict as the map).

    Both stored forms of a ``sizes[*].file`` entry are read: a bare
    basename is joined to ``dir_prefix`` (the attachment's directory, taken
    from ``_wp_attached_file``; the uploads root when it has none — the
    exact rule bridge.php's ``wpt_media_variants`` applies), while an entry
    carrying a ``/`` is already uploads-relative.  Unreadable metadata
    yields an empty set (see :func:`_meta_map`).
    """
    gate = _RefGate(extensions, dirs)
    full, bare = _meta_file_names(raw)
    for ref in full:
        gate.add(ref)
    for name in bare:
        gate.add(f"{dir_prefix}{name}" if dir_prefix else name)
    return gate.refs


# ------------------------------------------------------------------- bridge


def attachment_ids_for_files(refs_map: Any,
                              planned_files: Any) -> set[int]:
    """Attachment IDs whose OWN resolved file is in ``planned_files``.

    ``media_map``'s refs->ids answer carries both the id and the attachment's
    ``_wp_attached_file`` path.  Stem/basename matching can resolve a planned
    stray duplicate (``2023/09/pic.jpg``) to an attachment in another month
    (``2023/10/pic.jpg``) whose own file is REFERENCED and protected.  Sending
    that id to ``media_delete`` deletes the protected attachment's rows even
    though its file is never touched.  An id is therefore accepted only when
    its resolved file is itself one of the files this run is deleting;
    ``id: null`` and a file outside the planned set are skipped.
    """
    if not isinstance(refs_map, dict):
        return set()
    wanted = {str(path) for path in (planned_files or ()) if path}
    out: set[int] = set()
    for ref in refs_map.values():
        if not isinstance(ref, dict):
            continue
        attachment_id = ref.get("id")
        resolved = ref.get("file")
        if isinstance(attachment_id, bool) \
                or not isinstance(attachment_id, int) \
                or attachment_id <= 0:
            continue
        if not isinstance(resolved, str) or resolved not in wanted:
            continue
        out.add(attachment_id)
    return out


def db_refs_from_bridge(bridge: "Bridge",
                        extensions: Any = None) -> set[str]:
    """The DB-referenced media set from ONE read-only bridge call.

    ``media_map`` in ``mode=db`` — the op the media actions already use for
    upload paths, extended with the database map instead of adding a second
    op.  A :class:`~wpt.types.BridgeError` (including a payload anomaly the
    client validates) propagates: an unproven answer must never become half
    a keep-set, so every caller degrades explicitly instead.

    THE MIRRORED RULE, stated so the two modes cannot drift: the answer is
    already normalized and gated SERVER-SIDE, by bridge.php's
    ``wpt_media_ref_normalize`` + ``wpt_media_ref_is_kept`` +
    ``wpt_media_db_map`` — the same rules :func:`ref_normalize`,
    :func:`ref_is_kept` and :func:`db_refs_from_dump` implement offline.
    Nothing here re-decides them (the client is deliberately shape-only:
    ``Bridge._usable_db_ref`` checks the wire shape, never what a real
    reference is), because a second implementation on this side is how the
    two modes drifted in the first place.  What rides back is the
    server's own ``db_refs_dropped`` count, which the client reports as
    one lossy-keep-set warning; :func:`db_refs_from_dump` reports its gate
    drops the same way, so a lossy set is visible in BOTH modes.

    ``extensions`` is the CALLER'S family (``settings.media.extensions`` —
    the same list the enumeration files by) and it is CARRIED, not
    re-decided: it rides the request and the bridge gates with
    ``REF_EXTENSIONS`` UNION it, so the live gate always CONTAINS the
    enumeration's family whatever the profile says.  ``None`` (the
    default, what a caller that measures no enumeration of its own sends)
    leaves the bridge on its mirrored default.  A request the bridge
    refuses to honor is NOT silently narrowed: the client turns it into a
    :class:`BridgeError`, and every consumer degrades — the plan stays
    informative, the apply refuses.
    """
    refs = bridge.db_media_refs(extensions=extensions)
    log.info("bridge media map (db mode): %d database-referenced file(s)",
             len(refs))
    return refs


def db_refs_for_data(data: Any, extensions: Any = None) -> set[str] | None:
    """The DB-referenced media set for GATHERED audit data, memoized.

    * local mode — ``data.db_refs``, measured by ``gather_local`` from the
      dump (the only offline source; the dump handle is closed by then);
    * ftp mode — ONE ``media_map`` ``mode=db`` call through
      ``data.probe.bridge``, the result written back to ``data.db_refs`` so
      a second consumer in the same run costs nothing (the check must not
      pay a full postmeta scan twice).

    ``extensions`` is the run's own family, forwarded to the bridge read for
    the reason :func:`db_refs_from_bridge` states: the gate and the
    enumeration must measure one database with one family.  It is not part
    of the memo key — a run has ONE settings, so there is one family.

    Never raises: a failing bridge call is ONE warning plus ``None``
    (UNKNOWN) — the audit degrades to its walk-only evidence instead of
    failing the whole run, while the trim-media apply still refuses closed
    on the same fact.
    """
    if getattr(data, "db_refs", None) is not None:
        return data.db_refs
    probe = getattr(data, "probe", None)
    bridge = getattr(probe, "bridge", None)
    if getattr(data, "mode", "") == "local" or bridge is None:
        # local: gather_local measured it (None = the dump was unusable,
        # already warned about); no probe: there is no bridge to ask.
        return getattr(data, "db_refs", None)
    try:
        refs = db_refs_from_bridge(bridge, extensions)
    except Exception as exc:  # noqa: BLE001 — degrade, never fail the audit
        log.warning("database media map unavailable; media references fall "
                    "back to the live walk alone: %s", exc)
        return None
    data.db_refs = refs
    return refs


# --------------------------------------------------------------------- dump


#: The roles resolved by SUFFIX, i.e. the ones a plugin table can contest.
#: The prefix-derived roles cannot be contested: they are exact-name
#: lookups of a prefix the options role already proved.
_SUFFIX_ROLES = ("options", "termmeta")

#: The roles a WordPress database has ALWAYS had, and a dump that does not
#: prove them is therefore NOT a complete measurement of this site — it is
#: a PARTIAL export of it (a phpMyAdmin per-table export, a
#: ``mysqldump --ignore-table``, a transfer whose ``CREATE`` for the table
#: was cut).  ``postmeta`` is the load-bearing one: ``_wp_attached_file``
#: and every attachment-metadata size map live there, so a dump without it
#: measures ZERO database references while the site has thousands, and
#: "zero" is a POSITIVE answer the audit then reports as many deletable
#: photos.  ``posts`` is the same fact one table over (post content and
#: excerpt name PDFs and galleries).  ``termmeta`` is deliberately NOT in
#: this tuple: WordPress only added it in 4.4, so a site without one is
#: COMPLETELY measured and absence must not degrade anything.
_REQUIRED_PREFIX_ROLES = ("postmeta", "posts")


@dataclass(frozen=True)
class RoleResolution:
    """ONE role's identity, and every fact a consumer needs about it.

    ``name`` is the table the role is read from, or ``None`` when the role
    is not identified; ``candidates`` is every table that proved the role
    (empty = the role is simply absent).  The two ``None`` states are
    different facts and consumers act differently on them, so they are
    told apart here instead of by each consumer guessing: ``ambiguous``
    is the fail-closed UNKNOWN, absent is a site that does not have the
    table at all.
    """

    role: str
    name: str | None
    candidates: tuple[str, ...]

    @property
    def ambiguous(self) -> bool:
        return self.name is None and len(self.candidates) > 1

    @property
    def present(self) -> bool:
        return self.name is not None


@dataclass(frozen=True)
class DumpIdentity:
    """A dump's resolved table identity: the roles, and what it cannot measure.

    ``roles`` holds only UNIQUELY identified AND PROVEN roles — it is empty
    whenever the dump is not a complete measurement, because a consumer
    asking "which table was this read from?" must never be handed a table
    the reference set was NOT read from.

    Two different reasons make a dump incomplete, and both are UNKNOWN
    rather than an answer a consumer may act on:

    * ``contested`` — more than one table proved the role, so the identity
      is unknown (a contested role means the measurement read NOTHING for
      it, and every consumer — the keep-set, the analyzer, the witness —
      must degrade on the SAME fact rather than one of them quietly reading
      a table the others skipped);
    * ``unproven`` — a role every WordPress database has
      (:data:`_REQUIRED_PREFIX_ROLES`, ``postmeta`` above all) is absent or
      carries no column proof, so the dump is a PARTIAL export rather than
      a complete measurement of the site.

    ``known`` is the one question every consumer asks, and ``unresolved``
    names the roles to say in the answer, in the order the owner warned
    about them.

    ``options_table`` is the ONE exception to "all or nothing", and it is
    deliberate: the options table is the only role that carries the
    PREFIX every other table is located by, so a uniquely resolved options
    table is a fact the dump really does prove even when the dump as a whole
    is not a complete measurement.  The analyzer needs exactly that much,
    and degrading its site facts to nothing over a missing ``postmeta``
    would not be honesty — it would be collateral damage, and a FAIL-OPEN
    one: a site whose ``active_plugins`` list is unreadable makes every
    plugin directory look unused to ``clean-files`` (see the report on the
    analyzer's ``active_plugins=[]`` contract).  A CONTESTED or absent
    options table leaves this ``None``, exactly as before: then the prefix
    is unknown and no derived fact may be read at all.
    """

    roles: dict[str, TableStats]
    contested: tuple[str, ...] = ()
    unproven: tuple[str, ...] = ()
    options_table: TableStats | None = None

    @property
    def known(self) -> bool:
        return not (self.contested or self.unproven)

    @property
    def unresolved(self) -> tuple[str, ...]:
        """Every role this dump cannot be read through, by reason."""
        return self.contested + self.unproven


def _column_key(columns: Any) -> tuple[str, ...]:
    """One table's proved columns -> a comparable, order-free tuple."""
    return tuple(sorted(str(column) for column in (columns or ())))


def _columns_key(columns_by_name: Mapping[str, Any]) -> tuple[Any, ...]:
    """A whole schema's identity, comparable — the memo key of the rule.

    Column ORDER is deliberately not part of it: the candidate test asks
    whether a table proves a SET of columns, so two readers that listed
    them in a different order are the same input and must resolve once.
    """
    return tuple(sorted(
        (str(name), _column_key(columns))
        for name, columns in columns_by_name.items()
    ))


def _tables_key(tables: Mapping[str, TableStats]) -> tuple[Any, ...]:
    """A parsed dump's identity, comparable — the memo key of the identity.

    Every fact :func:`_identity` reads, and nothing else: each table's
    name, its CREATE columns, its INSERT column list, its row count and
    its CREATE text.  Two parses of the SAME bytes therefore share one
    answer, while two different exports (even of one schema) each resolve
    and warn for themselves.
    """
    return tuple(sorted(
        (str(name), _column_key(stats.columns),
         _column_key(stats.insert_columns), int(stats.row_count or 0),
         str(stats.create_sql or ""))
        for name, stats in tables.items()
    ))


def _role_candidates(role: str,
                     columns_by_name: Mapping[str, Any]) -> tuple[str, ...]:
    """Every table that could BE the ``role``, in NAME order.

    THE ONE candidate rule, and the half of the identity decision every
    consumer shares: a table is a candidate when its name ends in the role
    suffix AND it PROVES the role's column signature (``_COLUMNS``) — a
    name is not a schema, and a table with INSERTs but no CREATE proves
    nothing.  The answer is name-sorted, never dump-ordered and never
    connection-ordered, so two readers of the same schema can never
    disagree about the SET.

    ``columns_by_name`` maps a table name to the column names it proves (a
    dump's ``TableStats.columns``, a live schema's ``information_schema``
    answer) — the rule itself never touches a parser or a connection.
    """
    required = set(_COLUMNS[role])
    return tuple(sorted(
        name for name, columns in columns_by_name.items()
        if name.endswith(role) and required <= set(columns or ())
    ))


def _name_candidates(role: str, names: Any) -> tuple[str, ...]:
    """Every table that COULD BE the ``role`` when only NAMES are known.

    The wire's ``db_audit`` answers ``information_schema`` with NAMES and
    no columns, so this source can neither prove a role nor rule one out:
    a candidate is every table whose name ends in the role suffix, sorted.
    Callers must therefore treat a contest here as UNKNOWN — see
    :func:`resolve_role_by_name`, which is the only supported way in.
    """
    return tuple(sorted(
        str(name) for name in set(names or ()) if str(name).endswith(role)
    ))


#: THE ONE resolution per input, within a run: ``(mode, role)`` -> (the
#: input's identity, the answer).  A run measures ONE input per role (one
#: dump, one live schema), so the second and third readers of that fact —
#: the keep-set, the analyzer and the witness all ask it in the same run —
#: are answered from here and do not resolve or warn again.  A DIFFERENT
#: input replaces the slot, which is why this is a generation cache and
#: not an accumulating one: it holds one answer per role, it cannot grow
#: with the size of a schema, and a run that measures a second schema (or
#: the test suite, which measures many) resolves and warns again for it.
_RESOLUTIONS: dict[tuple[str, str], tuple[Any, RoleResolution]] = {}


def _resolve(mode: str, role: str, input_key: Any, candidates: Any) -> RoleResolution:
    """Resolve one role for one input: memoized, and warned ONCE.

    ``candidates`` is a zero-argument callable producing the name-sorted
    candidate tuple, so the rule itself stays in the two public wrappers
    and the memo cannot become a second candidate rule.
    """
    slot = (mode, role)
    known = _RESOLUTIONS.get(slot)
    if known is not None and known[0] == input_key:
        return known[1]
    found = candidates()
    if len(found) > 1:
        log.warning("multiple %s tables (%s): the %s identity is unknown, so "
                    "nothing is read from any of them",
                    role, ", ".join(found), role)
        resolution = RoleResolution(role, None, found)
    else:
        resolution = RoleResolution(role, found[0] if found else None, found)
    _RESOLUTIONS[slot] = (input_key, resolution)
    return resolution


def resolve_role(role: str, columns_by_name: Mapping[str, Any]) -> RoleResolution:
    """THE table-identity rule: which table is the ``role`` read from.

    Fail-closed: a role is read from a table only when exactly ONE table
    proves it.  Zero candidates is an ABSENT role (a site need not have
    every table); more than one is an UNKNOWN identity, reported as
    ``name=None`` with ``ambiguous`` set plus ONE warning naming every
    candidate — never as the first name in any order.

    That is not defensive nicety, it is a deletion gate.  AIOSEO 4.x really
    creates ``aioseo_options`` (and ``aioseo_termmeta``), carrying the same
    ``option_name``/``option_value`` pair as the core table, and a dump of
    such a site holds both.  The two rules this replaced each picked one and
    disagreed INSIDE ONE RUN: the analyzer read the first in dump order
    (``wp_options``) while the measurement read the first in ``sorted()``
    order (``aioseo_options``), so the keep-set measured 0
    database-referenced files where the control measured a full set — a POSITIVE
    "this database references no uploads file" instead of the UNKNOWN every
    consumer already refuses closed on, after which the audit reported every
    database-attached photo as unreferenced and ``trim-media`` planned their
    deletion.  ``aioseo_termmeta`` displacing ``wp_termmeta`` is the same
    residual.

    Consumers differ only in what they DO with an unknown identity, and
    each difference is forced by what it protects: the keep-set returns
    ``None`` (a half-measured keep-set is not a measurement), the analyzer
    degrades to no site facts, the witness narrows to no role at all, and
    ``clean-db`` refuses the run rather than guessing a prefix.  HOW they
    ask is one function.

    ONE resolution per input: the answer is memoized on the schema's own
    identity (:func:`_columns_key`) and the contested warning fires once
    for it, so a run in which three consumers ask the same question logs
    one sentence about one fact instead of two to four copies of it.  A
    LATER measurement of the same input in the same process — a second
    audit over the same dump, which the CLI never does (one command per
    process) but a test run and an embedding application do — reuses the
    answer and the already-logged warning rather than repeating a fact
    that has not changed; a DIFFERENT input resolves and warns again.
    """
    return _resolve("columns", role, _columns_key(columns_by_name),
                    lambda: _role_candidates(role, columns_by_name))


def resolve_role_by_name(role: str, names: Any) -> RoleResolution:
    """The identity rule for a source that reports table NAMES only.

    THE SAME fail-closed rule as :func:`resolve_role`, asked of the one
    source that cannot prove a role: the bridge's ``db_audit`` answers
    ``information_schema`` with names, rows and bytes, and no column list,
    so a candidate is every table whose name ends in the role suffix
    (:func:`_name_candidates`) and nothing can be ruled out.  Two such
    names are therefore already UNKNOWN — the same answer a column proof
    would give if both tables carried the pair — and the caller must
    refuse rather than pick one.

    It is asked by the mutating actions, whose plan item names the table
    the row is written to: each took ``sorted(matches)[0]`` over the WHOLE
    base-table set, which on a site running All in One SEO 4.x names
    ``aioseo_options`` — a table the mutation never touches, because the
    bridge writes through ``$wpdb->options`` — so the report and every
    ``--report`` artifact named the PLUGIN's table.  The write was safe
    (the bridge rewrote the real table, and the snapshot scope stayed
    over-inclusive) and the report was wrong, which is the same defect in a
    different place: a plan that names a table nobody is going to touch.

    The fail-closed cost is deliberate and must not be "fixed" by taking
    the first name again: a schema holding a second ``*options`` table
    (AIOSEO's, a stray ``wp_myoptions``, a multisite sibling) leaves the
    identity unprovable over this wire, and a mutation must not be planned
    against a table this tool cannot name.  ``wpt clean-db --db-uri`` reads
    a live ``information_schema.COLUMNS``, but that is NOT an escape hatch:
    AIOSEO 4.x's ``aioseo_options`` carries the same column pair, so it
    contests there too and ``clean-db`` refuses as well (MEASURED — a
    docstring here once promised otherwise).  On such a site
    ``deactivate-plugin``, ``reconcile-plugins``, ``users_reset``,
    ``user-create`` and ``clean-db`` all refuse, and the operator's route is
    the panel or
    ``wp option`` on the site itself.  A wire that carried the COLUMN LIST
    beside the table names would make every plan target provable again
    without a refusal.
    """
    known = frozenset(str(name) for name in (names or ()))
    return _resolve("name", role, tuple(sorted(known)),
                    lambda: _name_candidates(role, known))


def options_prefix(options_name: str) -> str:
    """The table prefix the options table's own name declares.

    Where the prefix comes from, ONCE: ``wp_options`` -> ``wp_`` (a table
    literally named ``options`` yields the empty prefix).  ``wp_`` is never
    assumed and no consumer re-derives this, so the prefix roles can never
    be resolved from a different table's name than the options role was.
    """
    return options_name[: -len("options")]


def _columns_of(stats: TableStats) -> list[str]:
    """The table's effective columns (its INSERT column list when present)."""
    return list(stats.insert_columns or stats.columns or ())


def dump_identity(tables: dict[str, TableStats]) -> DumpIdentity:
    """A parsed dump's table identity — THE resolution, for every consumer.

    Suffix roles (``options``, ``termmeta``) are resolved by
    :func:`resolve_role`; the prefix roles (``postmeta``, ``posts``) are
    EXACT-NAME lookups of the prefix :func:`options_prefix` derives from
    the options table itself, so ``wp_`` is never assumed and a plugin
    table that merely ENDS in a role name — ``wp_aioseo_posts`` is a real
    AIOSEO 4.x table — can neither be mistaken for the posts table nor
    displace it.

    A CONTESTED suffix role empties ``roles`` entirely, ``termmeta`` and
    ``postmeta`` included.  That is not a cascade, it is the one honest
    answer: the measurement reads the reference set from these tables as ONE
    measurement, so a dump whose options identity is unknown yields no
    reference set at all (:func:`db_refs_from_dump` -> ``None``) and a
    consumer asking which tables were read must be told the same thing,
    rather than validating a table nobody read.  A REQUIRED role the dump
    does not PROVE (:data:`_REQUIRED_PREFIX_ROLES`) empties ``roles`` for
    the same reason and is reported as ``unproven``: ``termmeta`` is the
    opposite case — a site that genuinely has no ``termmeta`` (WordPress
    before 4.4) is completely measured, so ITS absence never empties
    anything.

    THAT LAST RULE IS A DELETION GATE, and the shape it refuses is the
    commonest export shape there is: a phpMyAdmin per-table export, a
    ``mysqldump --ignore-table``, or a transfer whose ``CREATE`` for
    ``wp_postmeta`` was cut all produce a dump that DECLARES an options
    table and no postmeta — and that dump answers "this database
    references no uploads file", a POSITIVE zero, because
    ``_wp_attached_file`` and every attachment size map live in the table
    that is missing.  Measured on this module's own fixture: the audit then
    reported a populated database's referenced photos (plus a real orphan) as
    unreferenced and ``trim-media`` planned their deletion, with nothing
    but the ordinary local-mode caveat in the log.  A partial export is not
    a site with no attachments, so it is UNKNOWN — the same answer, and the
    same emptiness of ``roles``, the contested path produces.

    ONE resolution per input: the whole identity is memoized on the dump's
    own table facts, so the three consumers that ask it in one run share
    one answer and one warning per unresolved role.

    That is not theoretical.  The witness' currency check used to re-derive
    the identity by BARE SUFFIX (``_table_with(tables, role, …)`` → the first
    name in ``sorted()``), so a dump declaring a decoy ``wp_aioseo_posts``
    with 40 rows passed the check on that table while the real ``wp_posts``
    held 2 of 80, and ``wp_edd_postmeta`` (0 rows) displaced the real
    ``wp_postmeta`` so the check validated a table whose live count was 0 and
    skipped it.  There is now no second rule anywhere: a reader that wants
    to know what was read asks this.
    """
    key = _tables_key(tables)
    slot = ("identity", "")
    known = _RESOLUTIONS.get(slot)
    if known is not None and known[0] == key:
        return known[1]
    identity = _identity(tables)
    if identity.unproven:
        # a partial export is not a site with no attachments: what the
        # missing table holds is UNMEASURED, never measured empty
        log.warning(
            "the dump proves no %s table, so it is a PARTIAL export of this "
            "site (a per-table export, an --ignore-table dump, or a CREATE "
            "statement that was cut) and the database media map is UNKNOWN: "
            "what the dump does not contain is not evidence that the site "
            "does not reference it",
            " and ".join(identity.unproven),
        )
    _RESOLUTIONS[slot] = (key, identity)
    return identity


def _identity(tables: dict[str, TableStats]) -> DumpIdentity:
    """The resolution itself (no cache): :func:`dump_identity`'s worker."""
    proven = {name: stats.columns for name, stats in tables.items()}
    resolved = {role: resolve_role(role, proven) for role in _SUFFIX_ROLES}
    contested = tuple(role for role, found in resolved.items()
                      if found.ambiguous)
    roles: dict[str, TableStats] = {}
    unproven: tuple[str, ...] = ()
    options: TableStats | None = None
    if resolved["options"].present:
        options = tables[resolved["options"].name]
        roles["options"] = options
        prefix = options_prefix(options.name)
        for role in _REQUIRED_PREFIX_ROLES:
            candidate = tables.get(prefix + role)
            if (candidate is not None
                    and set(_COLUMNS[role]) <= set(candidate.columns or ())):
                roles[role] = candidate
            else:
                unproven += (role,)
    if resolved["termmeta"].present:
        roles["termmeta"] = tables[resolved["termmeta"].name]
    if not (contested or unproven):
        return DumpIdentity(roles, (), (), options)
    # one measurement, one identity: a role that was NOT resolved (contested
    # or unprovable) was NOT read, and neither was anything derived from it
    return DumpIdentity({}, contested, unproven, options)


def dump_role_tables(tables: dict[str, TableStats]) -> dict[str, TableStats]:
    """``role -> the table the offline reference set is READ from``.

    The usable half of :func:`dump_identity`, and the reason both are
    public: a consumer that has to reason about a dump's COMPLETENESS must
    ask the measurement which table each role is, because only the
    measurement's answer is the one that was read — and a consumer that
    has to explain WHY a role is missing asks the identity's
    ``contested``.
    """
    return dump_identity(tables).roles


def uploads_dirs(entries: Any, prefix: str = UPLOADS_PREFIX) -> set[str] | None:
    """The uploads-relative DIRECTORY paths a source enumerated, or None.

    The on-disk half of :func:`ref_is_kept`'s belt, expressed as data so it
    works for every source (an ftp walk, a zip walk, a local tree): the
    walk is the authority on what exists on the live host, exactly as
    ``is_dir()`` is server-side.  Entries are webroot-relative (the shape
    every walk yields) and come back uploads-relative, the shape every
    reference is — mixing the two would make the belt test a path that
    does not exist and silently keep a directory's references.

    ``None`` when ``entries`` is not a sequence (no source) — the belt is
    then skipped, which can only over-protect.
    """
    if entries is None:
        return None
    try:
        return {entry.path[len(prefix):] for entry in entries
                if entry.is_dir and entry.path.startswith(prefix)}
    except (AttributeError, TypeError):
        return None


def db_refs_from_dump(dump: BinaryIO, extensions: Any = REF_EXTENSIONS,
                      dirs: Any = None,
                      deadline: Any = None) -> set[str] | None:
    """The DB-referenced media set from an open .sql dump (local mode).

    THE OFFLINE HALF OF THE KEEP-SET, and it must return the SAME set as
    :func:`db_refs_from_bridge` for the same database — a destructive plan
    is built from one mode or the other, and a mode-dependent answer means
    a file the database references is protected in one run and deleted in
    the next.  Every rule that decides the answer therefore has a mirror
    in bridge.php and is stated once here: :func:`ref_normalize` (the
    uploads-marker cut, the NUL/backslash folding, the segment refusal),
    :func:`ref_is_kept` (the extension family and the is-a-directory belt)
    and the stored-value decoder :func:`_php_decode` (PHP's
    ``unserialize`` semantics).  All three are applied through
    :class:`_RefGate`, the mirror of the bridge's single collection point
    ``wpt_media_ref_add`` — there is no second verdict anywhere.

    ``extensions`` is the media family the refs are gated with (the shipped
    :data:`REF_EXTENSIONS` by default; a caller measuring an enumeration of
    its own passes the SAME list it enumerates with, so the gate and the
    enumeration can never measure one database with two families);
    ``dirs`` is the enumerated uploads DIRECTORY set for the is-a-directory
    belt (``None`` skips the belt, the bridge's own unreadable-basedir
    behavior).

    Streams the dump with the W5a parser: one ``parse_dump`` pass for the
    table summary, then one ``iter_rows`` pass per participating table.
    Nothing is buffered beyond one row plus the attachment-id map, and no
    SQL is parsed here.  That is ONE measurement (the passes are the W5a
    parser's own streaming contract, not a re-parse of the dump), and
    ``deadline`` — a :class:`wpt.deadline.Deadline` — is checked BETWEEN
    those passes: a run whose budget is spent while the dump is being read
    ends ITSELF (a ``DeadlineExceeded``, a ``RunControl`` that unwinds
    through every command's teardown to the dispatch boundary) instead of
    returning a
    PARTIAL keep-set that a destructive plan would read as the whole
    measurement.

    Returns ``None`` when the dump carries no usable WordPress tables (the
    measurement is UNKNOWN, never an empty keep-set) and a set otherwise —
    an EMPTY set is a real "this database references no uploads file".  A
    consumer that gates a DELETION on this measurement must treat ``None``
    as "no cross-check", never as "no reference" (see the trim-media
    cross-mode gate).

    A CONTESTED table identity is the same ``None``, never a keep-set read
    from the table this module happened to sort first: ``aioseo_options``
    really does sit in the dumps of AIOSEO 4.x sites, and reading it
    measured 0 database-referenced files on a dump whose ``wp_postmeta``
    names a full set — a positive "this database references no uploads file" that
    the audit then reported as unreferenced, deletable photos.  See
    :func:`resolve_role`.

    A dump that does not PROVE a table every WordPress database has
    (:data:`_REQUIRED_PREFIX_ROLES`) is that same ``None``, for the same
    reason and with the same measured cost: the commonest export shapes
    (a phpMyAdmin per-table export, ``mysqldump --ignore-table``, a cut
    ``CREATE``) declare an options table and no postmeta, and a keep-set
    read without postmeta answers "this database references no uploads
    file" about a site whose ``wp_postmeta`` names a full set.  The owner
    (:func:`dump_identity`) names the missing role in one warning; this is
    where the refusal is enforced, so the warning is not repeated here.

    The postmeta pass keeps a post_id -> directory map so a size-map entry
    stored as a bare basename lands in its attachment's own directory.  A
    metadata row read BEFORE its ``_wp_attached_file`` row (post_id order is
    arbitrary) parks its bare basenames and resolves them when the anchor
    arrives, so row order can never decide which files are protected.

    EVERY postmeta row is ALSO scanned as text, the two attachment keys
    included — the bridge's database map runs one ``meta_value LIKE
    '%wp-content/uploads/%'`` pass over the WHOLE table, so a value that is
    not a recognized map still names its files (a builder's ``source``
    URL, a serialized scalar holding a path).  Skipping those rows is what
    made the offline half lose references the live half kept.
    """
    dump.seek(0)
    summary = parse_dump(dump)
    tables = summary.tables

    # ONE table-identity resolution, shared with every consumer that has to
    # reason about which table the reference set was read from: the witness'
    # currency check asks this same resolution (through
    # ``dump_role_tables``), and the analyzer asks it too, so the warning
    # this run logs and the keep-set it measures can never name different
    # tables.
    identity = dump_identity(tables)
    roles = identity.roles
    if identity.contested:
        log.warning("the dump's %s identity is ambiguous, so nothing is "
                    "measured: the database media map is unknown "
                    "(tables=%d)", " and ".join(identity.contested),
                    len(tables))
        return None
    if identity.unproven:
        # the OWNER already named the missing role and why (one warning per
        # input, shared with the analyzer and the witness); this is only the
        # refusal, so the same sentence is not logged a second time here
        return None
    options_stats = roles.get("options")
    if options_stats is None:
        log.warning("dump carries no usable options table; the database "
                    "media map is unknown (tables=%d)", len(tables))
        return None
    postmeta_stats = roles.get("postmeta")
    posts_stats = roles.get("posts")
    termmeta_stats = roles.get("termmeta")

    gate = _RefGate(extensions, dirs)

    if postmeta_stats is not None:
        anchors: dict[str, str] = {}
        pending: dict[str, list[str]] = {}
        columns = _columns_of(postmeta_stats)
        dump.seek(0)
        check_deadline(deadline, "the database media map (postmeta)")
        for row in iter_rows(dump, postmeta_stats.name):
            record = dict(zip(columns, row))
            key = record.get("meta_key")
            value = record.get("meta_value")
            if not isinstance(key, str):
                continue
            # The text pass covers EVERY row, the attachment keys included:
            # a stored value names an uploads path wherever it sits.
            gate.add_text(value)
            post_id = str(record.get("post_id", ""))
            if key == "_wp_attached_file":
                ref = gate.add(ref_from_attached_file(value))
                if ref is None or not post_id:
                    continue
                anchors[post_id] = _dir_prefix(ref)
                for name in pending.pop(post_id, ()):
                    gate.add(f"{anchors[post_id]}{name}")
                continue
            if key in META_SIZE_KEYS:
                full, bare = _meta_file_names(value)
                for entry in full:
                    gate.add(entry)
                anchor = anchors.get(post_id)
                if anchor is None:
                    # the anchor has not been read yet: park the bare
                    # basenames rather than anchoring them to the wrong
                    # directory, and resolve them at the end of the pass
                    pending.setdefault(post_id, []).extend(bare)
                else:
                    for name in bare:
                        gate.add(f"{anchor}{name}")
                continue
            # every OTHER postmeta row needs nothing more: its value was
            # already read as text above (elementor JSON, Avada data, ...)

        for post_id, names in pending.items():
            anchor = anchors.get(post_id, "")
            for name in names:
                gate.add(f"{anchor}{name}" if anchor else name)

    if posts_stats is not None:
        columns = _columns_of(posts_stats)
        dump.seek(0)
        check_deadline(deadline, "the database media map (posts)")
        for row in iter_rows(dump, posts_stats.name):
            record = dict(zip(columns, row))
            for column in ("post_content", "post_excerpt", "post_guid"):
                gate.add_text(record.get(column))

    if options_stats is not None:
        columns = _columns_of(options_stats)
        dump.seek(0)
        check_deadline(deadline, "the database media map (options)")
        for row in iter_rows(dump, options_stats.name):
            record = dict(zip(columns, row))
            gate.add_text(record.get("option_value"))

    if termmeta_stats is not None:
        columns = _columns_of(termmeta_stats)
        dump.seek(0)
        check_deadline(deadline, "the database media map (termmeta)")
        for row in iter_rows(dump, termmeta_stats.name):
            record = dict(zip(columns, row))
            gate.add_text(record.get("meta_value"))

    if gate.dropped:
        log.warning(
            "dump media map: %d stored reference(s) name no media file and "
            "were dropped by the keep gate (the keep-set is lossy; a file "
            "only such a reference named is no longer protected)",
            gate.dropped,
        )
    log.info("dump media map: %d database-referenced file(s) "
             "(postmeta=%s posts=%s options=%s termmeta=%s)",
             len(gate.refs),
             postmeta_stats is not None, posts_stats is not None,
             True, termmeta_stats is not None)
    return gate.refs
