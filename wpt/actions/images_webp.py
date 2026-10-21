"""webp-media action: convert uploads rasters to WebP AND rewrite every
reference that could still point at the old bytes.

The command name is ``webp-media`` (``wpt webp-media``); this module is
``wpt/actions/images_webp.py`` because the conversion is only one half of
what the action does.  Two-phase action over the shared registry flow
(``wpt.actions.registry`` — the registry owns the dry-run boundary, the
confirmation, the fail-closed pre-action snapshot, the local rehearsal
branch and the post-apply cache purge; this module is pure domain logic).
Registered ``applies=("ftp", "local")``.

WHY IT IS A REWRITE AND NOT A CODEC KNOB
========================================
Converting ``a.jpg`` to ``a.webp`` alone breaks the site: every reference
to the old path 404s.  A large uploads tree compresses to a fraction of its
current bytes at WebP q80 — and every one of those references has to be
rewritten for the saving to exist at all.  The rewrite surfaces are therefore
the heart of this action, and each one below is a documented place a real site
hides a reference:

* ``{prefix}posts``.``post_content`` — the ordinary ``<img src>``.
* ``{prefix}postmeta``.``meta_value`` — EVERY row, not a meta-key
  allowlist.  The keys that matter are ``_wp_attached_file`` (the
  uploads-relative original) and ``_wp_attachment_metadata``, whose JSON
  carries ``file`` (uploads-relative) AND every ``sizes[*].file`` — a BARE
  BASENAME, e.g. ``photo-150x150.jpg`` with no directory at all.  That is
  the classic miss twice over: a rewrite that only understands the
  uploads-relative spelling misses every size row, and a reference scan
  gated on the ``wp-content/uploads/`` marker misses the whole metadata row
  (neither spelling contains it).  The rewrite therefore keys on BOTH
  spellings, and a basename that is not unique in the uploads tree is
  never rewritten or converted (see :func:`_rewrite_map`).  Plus
  ``_wp_attachment_backup_sizes`` and a page builder's ``_fusion*`` rows, whose
  values are JSON/serialized blobs holding the same paths.
* ``{prefix}options``.``option_value`` — ``avada_options``,
  ``theme_mods_avada`` and the ``widget_*`` serialized rows.
* Every ``.css`` under ``wp-content/uploads/`` (the generated
  ``avada-styles`` / builder trees) and under ``wp-content/themes/``
  whose ``url(...)`` points into uploads.  A background referenced ONLY
  from a stylesheet is invisible in the database [L11].
* ``_thumbnail_id`` is an attachment ID, not a path: the path-token
  scanner never matches an integer, so such a row is provably untouched.
* ``wp_usermeta`` normally carries no media paths, but it is still read as
  a GATED surface — "no" is a fact about WordPress, not a licence to break
  an avatar path some plugin wrote.

WHICH TABLES EXIST IS ASKED OF THE DATABASE
===========================================
In local mode the surfaces are discovered by NAME (a table-name SUFFIX
match, so the ``wp_`` prefix is never assumed) — but a suffix is a name,
not a schema.  On a site running all-in-one-seo-pack 5.x the table
``wp_aioseo_posts`` ends with ``posts`` and declares ``id``/``post_id``/
``og_image_url``: no ``ID``, no ``post_content``.  Demanding a column the
dump's own CREATE does not declare used to refuse the whole run before it
could do anything (observed on a site running that plugin), so every
candidate is now resolved against the dump (:func:`_local_surfaces`):

* the columns are there -> a rewritable surface, rewritten like any other
  (the discovery is NOT narrowed — a plugin table that really does carry
  the columns is enumerated);
* a column is absent -> a GATED surface: its rows are read across EVERY
  column as references nothing here can rewrite (that direction can only
  keep an image in its original form, never break one), and the plan names
  the table and the column it lacks;
* a suffix no table provides at all -> the dump cannot describe the
  reference set, which stays a refusal.

SERIALIZED VALUES ARE NOT TEXT
------------------------------
A PHP-serialized option value is length-prefixed (``s:5:"a.jpg";``), so a
naive in-place substitution corrupts it: the declared length stops
matching, ``unserialize()`` returns false, and for ``theme_mods_avada`` /
``widget_*`` that is an unstyled site, not a warning.  The rewrite is
therefore serialization-aware on both sides — server-side (ftp) the bridge
unserializes with WordPress' own ``maybe_unserialize``, rewrites the
string leaves and re-serializes with ``maybe_serialize``; client-side
(local rehearsal) the value is walked with ``wpt.media_refs.decode_php_value``
— the ONE decoder of a stored PHP value, the reference being the same
``@unserialize`` the live side uses — and rewritten per leaf.  ONE reader on
both halves of the same destructive decision: this gate and the keep-set
gating a deletion cannot be answered by two implementations that disagree
about what a value holds.  A value that LOOKS serialized but that PHP's own
``unserialize`` would refuse is FAIL-CLOSED: its references cannot be
enumerated, so every file it might reference is gated out of the conversion
rather than rewritten blind.

THE KEEP-SET GATE (why a file is not converted at all)
======================================================
A file is converted only when every reference to it is one this action can
rewrite.  References live in three places and only the first two are
rewritable:

1. rewritable — the DB surfaces above and the scanned CSS files;
2. derived — rendered HTML, which on any sane site is generated from 1;
3. NOT rewritable — the gated surfaces (``posts.post_excerpt``,
   ``comments.comment_content``/``comment_author_url``,
   ``users.user_url``, ``usermeta.meta_value``, ``termmeta.meta_value``,
   every column of a table the dump does not let the rewrite address),
   a rewritable row whose value cannot be parsed, and a CSS file that
   cannot be read.  An image referenced from (3), and an image the live
   walk references while NO rewritable surface holds that reference, is
   never converted — the plan names both classes with their counts.

After the rewrite, the SECOND half of the gate is the mandatory proof
(below): every touched row and file is re-read and must carry no reference
to a converted original, and every rewritten path must exist on disk.
That is also what catches a hardcoded theme-template reference, which no
plan-time scan can attribute to a page.

THE SET MUST BE COMPLETE BEFORE ANY OF IT IS USED
=================================================
The gate above can only keep an image safe if the reference set it is
computed from is COMPLETE, so the ftp read refuses anything short of a
finished scan: the op's own ``truncated`` marker, a stream that ends
without its terminal summary (a PHP fatal after the first lines, a cut
connection), and a summary whose row count disagrees with the rows that
arrived.  Those three proofs live in ONE place — the client's
``Bridge.iter_rewrite_refs`` / ``Bridge.rewrite_refs``, the only readers of
these two answers — and this action reads the op exclusively through them.
Reading the raw stream here would be a second, weaker reader: a fatal
after the first lines would leave a SHORT set that looks complete, and the
run would then convert images on the strength of references nobody
reported.  The same applies to the apply answer: an unanswered row, a
malformed re-read row, or an answer that omits a requested row raises
there, so a partial write is never mistaken for a finished one.  The purge
re-read rides the same reader, so a set that cannot be proven complete
refuses the delete decision too.

THE DEFAULT KEEPS THE ORIGINALS
===============================
The conversion writes the ``.webp`` BESIDE the original, rewrites every
reference, and only then are the originals deletable.  Deletion is a
SECOND, separately confirmed step (``--purge-originals``, default OFF;
also the ``webp.purge_originals`` profile key), and it adds one plan item
per original so the pre-action snapshot captures those exact bytes —
restore is then the ordinary command.  The default run converts, rewrites
and KEEPS, so the plan carries one advice item saying the space is not
realized until the purge runs.  A local rehearsal can never purge (no
database is written offline), so ``--purge-originals`` in local mode
refuses before touching anything.

THE PURGE IS A WINDOWED OPERATION
=================================
A live site's editors save pages during the day.  A save from a stale
client re-introduces the ORIGINAL filename in ``post_content`` between the
rewrite and the purge, and the purge then deletes the file that reference
resolves to: the page shows a broken image, and the surviving reference
permanently protects bytes that are already gone.  Three rules, and they
are why a purge is a window and not a step:

1. **it is refused without an explicit acknowledgement**
   (``--i-know-editors-are-off``, ``ctx.extra["i_know_editors_are_off"]``),
   in the plan phase as well as the apply, and on BOTH doors — the typed
   flag AND the ``webp.purge_originals`` profile key (the profile is a
   request; the acknowledgement is a human act, and only the human can
   give it).  The refusal names the window and the alternative (convert
   now, purge later) instead of silently doing the safe half;
2. **every per-file delete decision is taken from a reference set RE-READ
   at purge time** (:meth:`ImagesWebpAction._current_refs` — the same
   read-only reader the plan used, plus the stylesheets' current text),
   never from the plan's scan, which is exactly the measurement a live
   edit invalidates.  An original something referenced again KEEPS its
   bytes — and that is an ADVISORY, not a failure: the rewrite it was
   asked for verified, so the conversion is live and the registry's cache
   purge MUST still run (a declined delete that decided rc 1 made the
   site serve the pre-rewrite HTML out of cache while the operator was
   told the run had failed — measured on a real site).  The item stops being
   an applicable one, the report names the kept files and says the space
   waits for a quiet window;
3. **one more sweep after the deletes REPORTS** (never raises on) a
   reference that reappeared pointing at a removed original.  The run does
   not fail — the change it was asked for did land — but the operator
   needs the list, and the pre-action snapshot holds every deleted
   original's bytes for ``wpt restore``.

WHAT A DECLINED DELETE IS NOT
============================
"The rewrite did not land" and "the delete was declined" are different
events with different consequences, and reading the second as the first is
what the purge used to do.  An unproven rewrite is a failure: the whole
point of this action is that a conversion nobody can prove is a broken
site, so it fails closed and no cache is purged.  A declined delete is a
race the design already anticipated (rule 2): the conversion and the
rewrite verified, the site's HTML now points at the twins, and one
original's bytes are still on disk because an editor's save re-introduced
a reference to them.  Nothing is broken; the reclaiming is postponed.  So
it is reported, it does not decide rc, and — the part that used to cost the
operator a stale site — the cache purge still fires, because the pages the
purge invalidates really were rewritten.

A CHALLENGE IS NOT A CHANGE
==========================
The post-apply proof re-fetches the site and asks whether the reference
set moved as a bijection.  A host behind a bot-protection layer (an
observed run on a site that serves one: a small interstitial in place
of the page, 403/503 with a challenge script, or a 200 whose body is
nothing but a challenge) answers SOME client fingerprints with a challenge
and others with the real document.  Two crawls of an unchanged site then
produce two different reference sets over different page samples, and a
naive guard reads that churn as a broken rewrite.  It is not evidence about the site at all: it is evidence about
the transport.

So every fetch this proof makes is classified before it is counted
(:func:`challenge_reason`): a challenge/interstitial/soft-block answer is
INCONCLUSIVE, never "this page has no images".  An inconclusive fetch is
retried (bounded, short delay — a challenge is often per-fingerprint
nonsense a second request does not get), and if it stays inconclusive the
page is EXCLUDED from the comparison and REPORTED
(``N url(s) unprovable (bot-challenge); excluded from the comparison``).
Exclusion is only sound because the crawl attributes every reference to
the page it was seen on (:class:`_PageRecordingSet`): dropping a page from
the comparison must drop exactly that page's references and no other.  A
delta between successive pages would also drop references an earlier page
had already carried, and an unchanged site would read as a rewrite.

The run fails only on a PROVABLE fact: a page both crawls could read whose
references did not move as the mapping says, or a rewritten path the
rendered site still references that answers 404/410.

WHERE THE SAVING IS (the estimate, split by source format)
==========================================================
One blended total hides the decision: on an observed site, most of the
whole estimate was PNG, and a PNG converted to WebP is a LOSSY
re-encode of a format WordPress sites choose for exact or flat artwork
while a JPEG is a photograph either way.  The plan therefore reports the
JPEG and PNG reclaimable totals SEPARATELY (with their file counts) and
keeps the all-files total, so the operator can accept the photographs and
skip the artwork.  Each row names the extensions it counts (``.jpg`` and
``.jpeg`` are ONE JPEG row, listed as ``JPEG (.jpg, .jpeg)``), so a site
holding both spellings can never read as two rows both labelled "JPEG".

SKIP RULES (never converted, each with a report line)
=====================================================
* animated images — a PNG/APNG with ``n_frames > 1`` would silently lose
  every frame but the first; a GIF is not a candidate suffix at all, and
  :func:`classify_image` detects animation in ANY format so a future
  suffix addition cannot forget the check;
* CMYK JPEGs — WebP has no CMYK, so converting shifts the visible colour
  of every print graphic (a silent, permanent regression);
* either dimension over libwebp's 16383px limit, read from the image
  HEADER (:func:`image_dimensions`) so a 16800x16801 PNG is refused
  without ever being decoded (Pillow calls that a decompression bomb);
* any file under a ``webp.data_prefixes`` subtree (the shipped default
  protects Gravity Forms submission records — people-uploaded photos);
* files under ``webp.skip_below_bytes`` (converting a 4 KB icon is noise);
* a file whose bytes are identical to another file already handled — a
  duplicate pair converted twice stores the same WebP twice, saves
  nothing and doubles the reference rewrite;
* a file whose ``.webp`` twin already exists, or whose twin name another
  conversion in the same folder already claims;
* a twin that would not be SMALLER than its original — a bigger file is a
  regression, and the reference rewrite would be pure cost.

PROOF BEFORE REPORT
===================
``apply`` ends with a mandatory verification pass, in this order:
1. every rewritten path is swept on disk — a reference to a ``.webp`` that
   does not exist is exactly the broken-image class this action exists to
   prevent;
2. every rewritten DB row is RE-READ and scanned for a stale reference to
   any converted original (ftp: the value the bridge re-read after its own
   UPDATE; local: the rehearsal model);
3. every rewritten CSS file is re-read byte-for-byte against what was
   written;
4. in ftp mode with a site URL, the page set captured in the plan is
   re-fetched: every page BOTH crawls could read is compared against its
   own reference set, page by page, under the mapping (a bijection —
   everything that disappeared is an old path, everything that appeared is
   a new one, nothing else moved), plus the cardinality of the two
   comparable unions; a page a bot challenge (or a transport error) kept
   from being read is EXCLUDED and reported, never counted as a change;
   and every rewritten path the comparable pages reference is
   HTTP-checked — a 404/410 there is a provable failure, a challenge there
   is inconclusive (see A CHALLENGE IS NOT A CHANGE);
5. under ``--purge-originals`` only, the reference set is re-read again
   immediately before the deletes (which decide them, file by file) and
   once more after them, which REPORTS a reference that reappeared pointing
   at a removed original instead of failing over it (see THE PURGE IS A
   WINDOWED OPERATION).

Anything unproven raises, the items stay not-done and the run exits rc 1
— the pre-action snapshot is the rollback.  The report names
``wpt verify`` for the FULL live reference set (every asset on the site),
which this bounded in-run proof deliberately does not pretend to replace.

COST, STATED PLAINLY
====================
A large image set is two encode passes, not one: the plan encodes every
candidate so the plan can carry the REAL saving (not an estimate) and prove
the image is encodable before it is planned, and the apply re-encodes fresh
because the plan's measurement may be stale.  That is the same discipline
optimize-media follows, and it is why a dry run on a large site is not
instant.

SNAPSHOT SCOPE
==============
``plan.backup_tables`` carries every table the rewrite touches (a restore is
whole-table by contract), and the registry's file scope — derived from the
plan items — captures the pre-rewrite bytes of every rewritten stylesheet
and, under ``--purge-originals``, of every original the run deletes.  The
new ``.webp`` twins are pure additions: the manifest records them as absent
(a restore does not recreate an absent entry), so an undo leaves the twins
behind — harmless, since nothing references them any more, and the next
audit sees them as unreferenced media.

LOGGING
-------
``get_logger("actions.images_webp")``.  Paths, counts and byte totals
only — never image bytes, never a row's cell value.  A batched heartbeat
runs inside the candidate scan (L15: a 12k-image scan must never be
indistinguishable from a wedged run).

SETTINGS (the profile keys this action needs)
=============================================
``webp.quality`` (80), ``webp.skip_below_bytes`` (30720),
``webp.max_dim`` (0 = never resize), ``webp.purge_originals`` (false),
``webp.data_prefixes`` (["wp-content/uploads/gravity_forms/"]),
``webp.verify_pages`` (20 — the size of the before/after page set) and the
live proof's challenge handling ``webp.challenge_max_bytes`` (32768),
``webp.verify_retries`` (2) and ``webp.verify_retry_delay_s`` (1.0).  They
are read ONLY from ``ctx.settings.webp``; there are no module constants
standing in for a knob.
"""

from __future__ import annotations

import hashlib
import io
import posixpath
import re
import time
from dataclasses import dataclass, field, replace as dc_replace
from typing import TYPE_CHECKING, Any, Iterable, Iterator
from urllib.parse import unquote, urljoin, urlparse

import PIL.Image
import PIL.ImageOps
import requests

from ..audit.media import _UPLOADS_PREFIX
from ..deadline import Deadline, bounded_walk
from ..media_refs import PhpDecodeError, decode_php_value
from ..localmode.sql_dump import TableStats, iter_rows, parse_dump
from ..log import get_logger
from ..report import Plan, human_bytes
from ..types import PlanItem, SourceError, WptError
from .. import walk as _walk
from .registry import register_action

if TYPE_CHECKING:
    from ..cli import Ctx
    from ..types import Source

__all__ = ["ImagesWebpAction", "WebpConfig", "challenge_reason",
           "classify_image", "encode_webp", "image_dimensions",
           "looks_serialized", "may_reference_image", "raster_refs",
           "refs_in_value", "rewrite_css", "rewrite_text", "scan_css_refs",
           "scan_refs", "suffix_of", "value_texts"]

log = get_logger("actions.images_webp")

# ---------------------------------------------------------------------------
# Structural facts — NOT profile tunables (the same convention as
# wpt/audit/media.py's uploads prefix and optimize_media's _SUFFIXES).
# ---------------------------------------------------------------------------

#: The uploads marker as it appears INSIDE a reference: a DB value, a CSS
#: ``url()`` or a rendered ``src``.  The leading slash is deliberately
#: absent, so a root-relative ``/wp-content/uploads/...`` and a
#: site-relative ``wp-content/uploads/...`` both match.
_UPLOADS_MARKER = _UPLOADS_PREFIX

#: The REWRITABLE DB surfaces: table-name SUFFIX -> (primary-key column,
#: value column).  Resolved against the real table names at run time
#: (suffix match, the clean-db/trim-media convention) — the ``wp_`` prefix
#: is never assumed.
_REWRITABLE_TABLES: dict[str, tuple[str, str]] = {
    "posts": ("ID", "post_content"),
    "postmeta": ("meta_id", "meta_value"),
    "options": ("option_id", "option_value"),
}

#: GATED (read-only) surfaces: table-name SUFFIX -> the columns read for
#: uploads references.  A candidate referenced from one of these is never
#: converted, because the rewrite cannot reach it.  ``posts`` also appears
#: here: post_excerpt is a real reference surface (a featured-image
#: excerpt is a common theme field) and it is NOT rewritten.
_GATED_TABLES: dict[str, tuple[str, ...]] = {
    "posts": ("post_excerpt",),
    "comments": ("comment_content", "comment_author_url"),
    "users": ("user_url",),
    "usermeta": ("meta_value",),
    "termmeta": ("meta_value",),
}

#: CSS trees scanned for ``url(...)`` uploads references: the uploads tree
#: holds every builder-generated stylesheet (a page builder's generated ``avada-styles``
#: tree, Elementor/builder output) and the themes tree holds a theme's own
#: assets.  No theme slug is hardcoded — a theme name is site state, and a
#: literal here would silently skip every other theme.
_CSS_TREES = ("wp-content/uploads/", "wp-content/themes/")

#: Raster suffixes this action converts — exactly the encoders
#: :func:`encode_webp` implements.  A GIF is not here: it is an animation
#: container, and a static GIF is not worth a WebP twin.
_RASTER_SUFFIXES = frozenset({"jpg", "jpeg", "png"})

#: libwebp's hard dimension limit (16383px per side).  A codec constant,
#: not a tunable: exceeding it is an encoder FAILURE, not a quality
#: choice, so it is a structural skip like ``_RASTER_SUFFIXES``.
_WEBP_MAX_DIM = 16383

#: Heartbeat cadence of the candidate scan: one info line every this many
#: candidates once ``_HEARTBEAT_S`` have passed.  Structural log cadence
#: (the L15 convention): no operator decision changes what the scan
#: converts, so the no-static-configurables rule stops at the logging
#: boundary.
_HEARTBEAT_EVERY = 250
_HEARTBEAT_S = 10.0

#: Rows per bridge call for the rewrite.  Structural: it bounds the
#: in-flight payload of one request (a reference value is a whole post,
#: and the bridge caps the rows of a single call).
_BRIDGE_BATCH = 100

#: How many example paths a skip/gate report line names.  The COUNT is
#: always exact; the examples are a bounded sample.
_EXAMPLES = 5

#: The acknowledgement a purge needs, as ``ctx.extra`` carries it and as the
#: operator types it.  Deleting the originals is a WINDOWED operation — see
#: :func:`_require_purge_ack` — and no tool can observe "nobody is editing".
_PURGE_ACK = "i_know_editors_are_off"
_PURGE_ACK_FLAG = "--i-know-editors-are-off"

# ---------------------------------------------------------------------------
# Bot-challenge detection — a fetch that proves nothing is not a change
# (see the module docstring, "A CHALLENGE IS NOT A CHANGE").  These are
# facts about the WILD, not about this action: a challenge page is written
# by whatever layer sits in front of the site, and the only stable thing
# about one is that it is not the page.  The list is named after the
# platforms' own markers rather than after any HTML shape, so another
# protection layer is one line here and not a heuristic.
# ---------------------------------------------------------------------------

#: Statuses a bot-protection layer answers a challenged request with: the
#: classic WAF block (403) and its "under maintenance"/slow-down answers
#: (503), plus a rate limiter's 429.
_CHALLENGE_STATUSES = frozenset({403, 429, 503})

#: Markers a challenge page carries INSTEAD OF content: the challenge
#: platform's script URL, its cookie/field names and its own copy.  Matched
#: case-insensitively anywhere in the body.
_CHALLENGE_MARKERS = (
    # Cloudflare
    "/cdn-cgi/challenge-platform",
    "cf-browser-verification",
    "cf_chl_opt",
    "cf_chl_prog",
    "__cf_chl",
    # Sucuri
    "sucuri_cloudproxy",
    # Incapsula / Imperva
    "_incapsula_resource",
    "jschl_vc",
    "request unsuccessful. incapsula incident",
    # PerimeterX / HUMAN
    "px-captcha",
    "_pxhc",
    # Distil Networks
    "distil_r_captcha",
    # DataDome
    "datadome",
    # the interstitials' own copy
    "just a moment",
    "checking your browser",
    "attention required",
    "verify you are human",
    "are you a robot",
    "enable javascript and cookies to continue",
    "please enable javascript",
    "we need to verify your browser",
)

#: The subset of markers that can only ever appear on a challenge page: a
#: platform's script or cookie name.  One of these in the body settles it
#: whatever the status and whatever the size.
_CHALLENGE_PLATFORM_MARKERS = tuple(
    marker for marker in _CHALLENGE_MARKERS
    if not any(ch.isspace() for ch in marker))

#: The source formats the reclaimable estimate is split BY.  One blended
#: total hides where the saving is: on an observed site, most of the
#: whole estimate was PNG, and a PNG converted to WebP is a LOSSY re-encode
#: of a format WordPress sites pick for exact or flat artwork — a decision
#: the operator makes per format, not per file.
#:
#: Several suffixes share one TITLE (``.jpg`` and ``.jpeg`` are both JPEG):
#: the split is by FORMAT, and a row names the extensions it actually
#: contains, because a site holding both spellings otherwise printed two
#: rows both labelled "JPEG" and the operator could not tell which was
#: which [D1].
_FORMAT_TITLES = {"jpg": "JPEG", "jpeg": "JPEG", "png": "PNG"}

# ---------------------------------------------------------------------------
# Settings — read ONLY through the ``webp`` section the settings owner
# (``wpt.settings.WebpSettings``) holds, whose shipped values live in
# wpt/data/profiles/default.json.  There is no module constant standing in for
# a knob here and no ``getattr(ctx.settings, "webp", None)`` door: the
# section always exists, so a value is either the profile's, an operator's
# ``--set webp.<key>=``, or a refusal naming the key.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WebpConfig:
    """The resolved settings of one run (see the module docstring)."""

    quality: int
    skip_below_bytes: int
    max_dim: int
    purge_originals: bool
    data_prefixes: tuple[str, ...]
    verify_pages: int
    challenge_max_bytes: int
    verify_retries: int
    verify_retry_delay_s: float


def _config(ctx: "Ctx", *, purge_flag: Any = None) -> WebpConfig:
    """The run's settings, read from the ``webp`` section and nowhere else.

    ``purge_flag`` is ``ctx.extra["purge_originals"]`` and is TRI-STATE:
    a bool is the operator typing the flag, and ``None`` is "the operator
    did not type it" — the only state in which the ``webp.purge_originals``
    profile key gets to decide.  An ``argparse`` ``store_true`` without
    ``default=None`` collapses the two ("not typed" reads as ``False``)
    and makes the profile door dead code, so the CLI defines the flag with
    ``default=None`` and passes the value through untouched.  Either door
    then demands the SAME acknowledgement (``_require_purge_ack``): the
    profile is a request, the acknowledgement is a human act.
    """
    section = ctx.settings.webp
    return WebpConfig(
        quality=section.quality,
        skip_below_bytes=section.skip_below_bytes,
        max_dim=section.max_dim,
        purge_originals=(bool(section.purge_originals) if purge_flag is None
                         else bool(purge_flag)),
        data_prefixes=tuple(section.data_prefixes),
        verify_pages=section.verify_pages,
        challenge_max_bytes=section.challenge_max_bytes,
        verify_retries=section.verify_retries,
        verify_retry_delay_s=section.verify_retry_delay_s,
    )



# ---------------------------------------------------------------------------
# A FETCH IS EITHER EVIDENCE OR IT IS NOT
# ---------------------------------------------------------------------------


def challenge_reason(response: Any, max_bytes: int) -> str:
    """Why this response says nothing about the page it answers, else ``""``.

    A bot-protection layer's answer is a fact about the transport, not about
    the site, and the shapes are all measured: an interstitial where the
    page should be (a small body carrying a challenge script), a WAF block
    (HTTP 403/503) whose body carries a challenge
    marker, and a 200 whose entire body is a challenge — read naively, that
    last one is the most dangerous of the three, because a 200 is exactly
    what a fetch is expected to answer and its body says "this page has no
    images".  So:

    * a PLATFORM marker (a challenge script URL or cookie name — see
      :data:`_CHALLENGE_PLATFORM_MARKERS`) settles it at any size and any
      status: no real document carries one;
    * a COPY marker ("just a moment", "enable javascript and cookies to
      continue", …) settles it when the status is a block status or the
      body is small — a blog post can contain the phrase, an interstitial
      never carries a megabyte of content;
    * a block status with a small body settles it even without a marker:
      that is a refusal, not a document.

    ``max_bytes`` (``webp.challenge_max_bytes``) is the "small" bound.  A
    refusal with a LARGE body is not read as a challenge: that is a real
    page (a 404 page, a maintenance page), and the caller must judge it on
    its status, which is evidence.
    """
    body = getattr(response, "text", "") or ""
    lowered = body.lower()
    status = int(getattr(response, "status_code", 0) or 0)
    marker = next((m for m in _CHALLENGE_MARKERS if m in lowered), "")
    if marker:
        conclusive = (marker in _CHALLENGE_PLATFORM_MARKERS
                      or status in _CHALLENGE_STATUSES
                      or len(body) <= max_bytes)
        if conclusive:
            return (f"bot-challenge ({marker!r}, HTTP {status}, "
                    f"{len(body)} bytes)")
    if status in _CHALLENGE_STATUSES and len(body) <= max_bytes:
        return f"bot-challenge (block stub, HTTP {status}, {len(body)} bytes)"
    return ""


@dataclass(frozen=True)
class _Fetch:
    """One URL's verdict: the response that proves something, or why not."""

    url: str
    response: Any = None
    #: "" when the fetch PROVES something (any answer the challenge
    #: detector cleared, a 404 included — a 404 is evidence about the site,
    #: a challenge is not); otherwise why this URL cannot be counted.
    reason: str = ""
    attempts: int = 0

    @property
    def proved(self) -> bool:
        return not self.reason and self.response is not None

    @property
    def status(self) -> int:
        return int(getattr(self.response, "status_code", 0) or 0)


def _probe(session: Any, url: str, timeout_s: int, cfg: WebpConfig) -> _Fetch:
    """GET one URL until it answers with a document, or report why it cannot.

    A challenge is retried (``webp.verify_retries`` times,
    ``webp.verify_retry_delay_s`` apart): a per-fingerprint challenge
    frequently does not repeat, so a second request is a cheap way to get
    evidence instead of an excuse.  A transport failure is retried on the
    same terms and is never called a challenge — the two are different
    faults and the report says which.
    """
    reason = ""
    attempts = 0
    for attempt in range(cfg.verify_retries + 1):
        if attempt and cfg.verify_retry_delay_s > 0:
            time.sleep(cfg.verify_retry_delay_s)
        attempts += 1
        try:
            response = session.get(url, timeout=timeout_s)
        except requests.RequestException as exc:
            reason = f"not fetchable ({exc.__class__.__name__})"
            log.debug("webp-media: %s could not be fetched: %s", url, exc)
            continue
        reason = challenge_reason(response, cfg.challenge_max_bytes)
        if not reason:
            return _Fetch(url, response, "", attempts)
    log.warning("webp-media: %s is INCONCLUSIVE after %d attempt(s): %s — it "
                "is excluded from the live comparison, not counted as a "
                "change", url, attempts, reason)
    return _Fetch(url, None, reason, attempts)


class _PageRecordingSet(set):
    """The crawler's reference set, remembering which PAGE carried each ref.

    :func:`wpt.walk.walk_site` returns an AGGREGATE reference set, and the
    post-apply proof needs the attribution: excluding a page a bot
    challenge kept us from reading must remove exactly that page's
    references from the comparison.  A difference between successive pages
    would be cheaper and wrong — it also drops a reference an earlier page
    had already carried, so an unchanged site would read as a rewrite.

    The crawler owns this set and adds each accepted reference to itself
    exactly once, so recording the page here costs one ``add`` and copies
    no traversal rule.
    """

    def __init__(self) -> None:
        super().__init__()
        #: the page being read right now, or None outside a page visit
        self.sink: set[str] | None = None

    def add(self, item: str) -> None:
        super().add(item)
        if self.sink is not None:
            self.sink.add(item)


class _PerPageCrawler(_walk._Crawler):
    """The walk's own crawler, plus attribution and challenge-aware fetches.

    The traversal (sitemap seeds, BFS, the page budget, the deadline, the
    politeness delay, the reference rules) is ``wpt.walk``'s and is NOT
    re-implemented here; this subclass only (a) attributes every reference
    to the page it was read on and (b) treats a bot-challenge answer as
    INCONCLUSIVE instead of as "this page has no images", retrying it
    first.  A page an inconclusive fetch covers — the page itself, or a
    stylesheet it pulls in — proves nothing and is recorded as such, so the
    proof excludes it instead of reading its missing references as a change.
    """

    def __init__(self, session: Any, site: str, settings: Any, timeout_s: int,
                 cfg: WebpConfig, deadline: Any = None) -> None:
        super().__init__(session, site, settings, timeout_s, deadline)
        self.refs = _PageRecordingSet()
        self.cfg = cfg
        #: page URL -> the uploads references THAT page carried
        self.page_refs: dict[str, set[str]] = {}
        #: page URL -> why it proves nothing (never "it has no images")
        self.unprovable: dict[str, str] = {}
        self._page_url: str | None = None

    @property
    def exhausted(self) -> bool:
        """True when the frontier was still queued at the end of the crawl
        (the page budget or the run deadline stopped it)."""
        return bool(self._queue)

    def _fetch(self, url: str) -> Any:
        if url in self._fetched_urls:
            return None       # already fetched: the crawler's own dedup
        self._fetched_urls.add(url)
        probe = _probe(self._session, url, self._timeout_s, self.cfg)
        self.fetched += probe.attempts
        if not probe.proved:
            if self._page_url is not None:
                self.unprovable.setdefault(self._page_url, probe.reason)
            return None
        response = probe.response
        if not 200 <= probe.status < 300:
            if self._page_url is not None:
                self.unprovable.setdefault(self._page_url,
                                           f"HTTP {probe.status}")
        elif not _walk._is_html(response):
            if self._page_url is not None:
                self.unprovable.setdefault(self._page_url,
                                           "not an HTML document")
        return response

    def _visit(self, url: str, depth: int) -> None:
        page: set[str] = set()
        self._page_url = url
        self.refs.sink = page
        try:
            super()._visit(url, depth)
        finally:
            self._page_url = None
            self.refs.sink = None
        if url in self.unprovable:
            # A fetch this page could not be read through proves nothing
            # about it, so it is attributed no references at all: the proof
            # excludes it rather than reading its missing references as a
            # change.  What it did NOT prove is the whole point.
            return
        self.page_refs[url] = set(page)


@dataclass(frozen=True)
class _LiveCapture:
    """One live crawl, with the per-page attribution the proof compares."""

    refs: set[str] = field(default_factory=set)
    pages: dict[str, set[str]] = field(default_factory=dict)
    unprovable: dict[str, str] = field(default_factory=dict)
    partial: bool = False


def _live_capture(session: Any, ctx: "Ctx", cfg: WebpConfig,
                  deadline: Any = None) -> _LiveCapture:
    """One bounded crawl of the live site, per page, challenge-aware.

    Never raises: a site-level failure is a partial capture plus warning
    logs, exactly like :func:`wpt.walk.walk_site` — and for the same
    reason.  A partial or challenge-thinned capture WEAKENS the proof (fewer
    pages to compare), so both facts are carried out to the report rather
    than dropped.
    """
    walk_settings = dc_replace(ctx.settings.walk, max_pages=cfg.verify_pages)
    crawler = _PerPageCrawler(session, ctx.wp_url, walk_settings,
                              ctx.settings.http.timeout_s, cfg, deadline)
    partial = False
    try:
        crawler.run()
    except Exception as exc:  # noqa: BLE001 — the capture never raises
        partial = True
        log.error("webp-media: the live crawl was aborted by an unexpected "
                  "error (partial capture kept): %s", exc, exc_info=True)
    return _LiveCapture(refs=set(crawler.refs),
                        pages=dict(crawler.page_refs),
                        unprovable=dict(crawler.unprovable),
                        partial=partial or crawler.exhausted)


#: How an unprovable URL is reported.  A bot challenge is the case the
#: operator has to recognize (their host serves one to some clients); a
#: page the crawl could not read at all is ordinary breakage and says so.
_KIND_CHALLENGE = "bot-challenge"
_KIND_UNREADABLE = "unreadable"
#: Read in one pass only: a crawl's page set is BFS- and budget-derived
#: and legitimately differs between two passes of the same site, so a page
#: only one of them reached is not evidence of anything.
_KIND_SINGLE_PASS = "single-pass"


def _exclusion_kind(reason: str) -> str:
    """Which report bucket an excluded URL belongs to."""
    if _KIND_CHALLENGE in reason:
        return _KIND_CHALLENGE
    if reason:
        return _KIND_UNREADABLE
    return _KIND_SINGLE_PASS


def _excluded_urls(reasons: dict[str, str],
                   before: dict[str, set[str]] | None = None,
                   after: dict[str, set[str]] | None = None
                   ) -> dict[str, list[str]]:
    """The URLs a before/after comparison cannot use, bucketed by why.

    Two reasons, both about evidence and neither about the site: a page a
    fetch could not read (``reasons`` — a bot challenge, a transport error,
    a 404), and a page only ONE of the two passes reached.  The second is
    not a small thing to admit: a crawl's page set is BFS- and
    budget-derived, so two passes over an UNCHANGED site legitimately
    differ (different page counts on the site whose guard this replaced), and reading that difference as a rewrite is
    exactly the false positive the per-page comparison removes.

    ``after=None`` is the plan phase, which has no second pass yet.
    """
    single_pass = (set(before) ^ set(after)) if after is not None else set()
    out: dict[str, list[str]] = {}
    for url in sorted(set(reasons) | single_pass):
        kind = (_exclusion_kind(reasons[url]) if url in reasons
                else _KIND_SINGLE_PASS)
        out.setdefault(kind, []).append(url)
    return out


def _unprovable_item(kind: str, urls: list[str], when: str) -> PlanItem:
    """The report line for URLs the live proof refused to count.

    Never an applicable item: an unprovable URL is missing EVIDENCE, not a
    change this run failed to make, and an advisory is the only shape that
    can say so without also deciding the run's exit status.
    """
    return PlanItem(
        category="media.webp_unprovable",
        target=kind,
        detail=(f"{len(urls)} url(s) unprovable ({kind}); excluded from the "
                f"comparison — {when}: {_sample(urls)}"),
        requires_apply=False,
    )


# ---------------------------------------------------------------------------
# Image inspection — header level first: a 16800x16801 PNG must be refused
# WITHOUT being decoded (Pillow calls that a decompression bomb).
# ---------------------------------------------------------------------------

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
#: SOF markers that carry the frame dimensions (SOF4/SOF8/SOF12 do not).
_JPEG_SOF = frozenset(range(0xC0, 0xD0)) - {0xC4, 0xC8, 0xCC}
#: The decoder refusals :func:`classify_image` / :func:`encode_webp` treat
#: as "this is not an image we can convert".
_DECODE_ERRORS = (PIL.Image.UnidentifiedImageError,
                  PIL.Image.DecompressionBombError,
                  OSError, ValueError, SyntaxError)


def image_dimensions(data: bytes) -> tuple[int, int] | None:
    """``(width, height)`` from the image HEADER, or None when unknown.

    PNG reads the IHDR chunk (bytes 16..24, big-endian, after the 8-byte
    magic and the length/type pair); JPEG walks the marker chain to the
    first SOF segment.  Header-only on purpose: the dimension gate must be
    able to REFUSE a huge image without decoding it, and decoding is
    exactly what a 282-megapixel PNG cannot survive.
    """
    if data[:8] == _PNG_MAGIC and len(data) >= 24 and data[12:16] == b"IHDR":
        return (int.from_bytes(data[16:20], "big"),
                int.from_bytes(data[20:24], "big"))
    if data[:2] != b"\xff\xd8":
        return None
    i, end = 2, len(data)
    while i + 3 < end:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker in _JPEG_SOF:
            if i + 9 > end:
                return None
            return (int.from_bytes(data[i + 7:i + 9], "big"),
                    int.from_bytes(data[i + 5:i + 7], "big"))
        if marker in (0x01, 0xD8) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        if i + 4 > end:
            return None
        length = int.from_bytes(data[i + 2:i + 4], "big")
        if length < 2:
            return None
        i += 2 + length
    return None


#: Skip reasons — one per rule, each rendered as its own report line.
_SKIP_DIMENSIONS = "oversize"
_SKIP_ANIMATED = "animated"
_SKIP_CMYK = "cmyk"
_SKIP_UNREADABLE = "unreadable"
_SKIP_ENCODE = "unencodable"
_SKIP_DATA_TREE = "data-tree"
_SKIP_TINY = "tiny"
_SKIP_DUPLICATE = "duplicate"
_SKIP_TWIN_EXISTS = "twin-exists"
_SKIP_COLLISION = "twin-collision"
_SKIP_NOT_SMALLER = "not-smaller"
_SKIP_ABSENT = "absent"

_SKIP_TITLES = {
    _SKIP_DIMENSIONS: f"over the {_WEBP_MAX_DIM}px libwebp dimension limit",
    _SKIP_ANIMATED: "animated — a WebP twin would lose every frame but the "
                    "first",
    _SKIP_CMYK: "CMYK JPEG — WebP has no CMYK, so the visible colour would "
                "shift",
    _SKIP_UNREADABLE: "not a decodable raster image",
    _SKIP_ENCODE: "the WebP encoder refused it",
    _SKIP_DATA_TREE: "inside a protected data tree (people-uploaded records)",
    _SKIP_TINY: "below webp.skip_below_bytes — converting it is noise",
    _SKIP_DUPLICATE: "byte-identical to an image already handled — one twin "
                     "is enough",
    _SKIP_TWIN_EXISTS: "a .webp of that name already exists",
    _SKIP_COLLISION: "another converted file in that folder claims the same "
                     ".webp name",
    _SKIP_NOT_SMALLER: "the WebP twin would not be smaller than the original",
    _SKIP_ABSENT: "referenced but not present in the webroot",
}

#: Gate reasons: the image stays in its ORIGINAL form on purpose.
_GATE_TABLE = "gated-table"
_GATE_SERIALIZED = "unparseable-value"
_GATE_CSS = "unreadable-css"
_GATE_HTML_ONLY = "rendered-html-only"
_GATE_AMBIGUOUS = "ambiguous-basename"

_GATE_NOTES = {
    _GATE_TABLE: "a database row outside the rewritable surfaces references "
                 "them",
    _GATE_SERIALIZED: "the referencing value is serialized but could not be "
                      "parsed, so it cannot be rewritten safely",
    _GATE_CSS: "the referencing stylesheet could not be read, so its url() "
               "references cannot be rewritten",
    _GATE_HTML_ONLY: "referenced by the rendered site with no rewritable "
                     "surface behind it — nothing can break them",
    _GATE_AMBIGUOUS: "a bare filename in the reference set matches more than "
                     "one uploads folder, so the reference cannot say which "
                     "one it meant",
}


def classify_image(data: bytes) -> tuple[str, str] | None:
    """``(reason, detail)`` when the image must NOT be converted, else None.

    Order is part of the contract: the DIMENSION gate reads the header and
    runs FIRST (a 16800x16801 PNG never reaches a decoder), then the
    decoder's own refusals, then the colour-space and animation gates that
    need the decoded mode and frame count.
    """
    dims = image_dimensions(data)
    if dims is not None and (dims[0] > _WEBP_MAX_DIM or dims[1] > _WEBP_MAX_DIM):
        return _SKIP_DIMENSIONS, f"{dims[0]}x{dims[1]}"
    try:
        with PIL.Image.open(io.BytesIO(data)) as opened:
            if getattr(opened, "mode", "") == "CMYK":
                return _SKIP_CMYK, "CMYK"
            frames = int(getattr(opened, "n_frames", 1) or 1)
            if frames > 1 or bool(getattr(opened, "is_animated", False)):
                return _SKIP_ANIMATED, f"{frames} frame(s)"
    except _DECODE_ERRORS:
        return _SKIP_UNREADABLE, "undecodable"
    return None


def encode_webp(data: bytes, cfg: WebpConfig) -> bytes | None:
    """Re-encode one image as WebP in memory; None when Pillow refuses.

    * EXIF orientation is honored FIRST (``ImageOps.exif_transpose``), so
      the dimension decision and any resize see the DISPLAY orientation
      and the saved pixels carry no orientation tag (a twin with a stale
      tag would render rotated).
    * ``cfg.max_dim`` > 0 downscales to fit (LANCZOS, aspect preserved,
      never upscaled); 0 = never resize.
    * Alpha (RGBA/LA/P) is preserved — WebP carries it.
    * Everything happens in ``BytesIO``; nothing is written to disk.
    """
    try:
        with PIL.Image.open(io.BytesIO(data)) as opened:
            image = PIL.ImageOps.exif_transpose(opened)
            if cfg.max_dim and (image.width > cfg.max_dim
                                 or image.height > cfg.max_dim):
                image.thumbnail((cfg.max_dim, cfg.max_dim),
                                PIL.Image.Resampling.LANCZOS)
            out = io.BytesIO()
            image.save(out, format="WEBP", quality=cfg.quality)
            return out.getvalue()
    except _DECODE_ERRORS:
        return None


# ---------------------------------------------------------------------------
# The reference-rewrite rule — ONE implementation, shared by the CSS
# writes, the local rehearsal model and the plan's reference scan.  The
# bridge mirrors it in PHP for the live database (serialization-aware,
# through WordPress' own maybe_unserialize/maybe_serialize).
# ---------------------------------------------------------------------------

#: RFC 3986 pchar + "/" + "%" — the characters an uploads path can hold.
#: The quoting delimiters, whitespace, "?" and "#" are deliberately
#: EXCLUDED, so a path token ends where the surrounding syntax starts: a
#: query string or a fragment survives the rewrite untouched, which is what
#: WordPress's ``?ver=`` cache-busting needs.
_PATH_TOKEN_RE = re.compile(r"[A-Za-z0-9._~%!$&'()*+,;=:@/\-]+")

#: Characters that may legitimately trail a path token inside its container
#: (``url(a.jpg)``, ``"a.jpg",``, ``[a.jpg]``).  A tail is retried with them
#: stripped, so ONE scanner serves every surface.
_TRAILING_JUNK = ")]}>;,\"'"

#: The raster suffixes WITH their dot, for the cheap pre-filter below.
_RASTER_DOTTED = tuple("." + suffix for suffix in _RASTER_SUFFIXES)


def may_reference_image(value: str) -> bool:
    """Cheap pre-filter: can this text hold an uploads image reference?

    The uploads MARKER is NOT a valid pre-filter, and using one is the
    single most expensive mistake available here: WordPress stores an
    uploads path RELATIVE to the uploads base in ``_wp_attached_file`` and
    in every ``sizes[*].file``, so those rows contain no
    ``wp-content/uploads/`` at all — a marker-gated scan skips the
    attachment metadata, and every thumbnail on the site then points at a
    deleted original.  A reference must carry a raster extension, so that
    is what the pre-filter looks for (case-insensitively: a site may hold
    ``IMG.JPG``).
    """
    lowered = value.lower()
    return any(ext in lowered for ext in _RASTER_DOTTED)


#: The first letters of a PHP-serialized payload (a plain value never
#: starts with one — the only exception is a post body starting with a
#: letter, which is why the head must also carry a colon and a digit).
_SERIAL_HEADS = "sadObin"


def _iter_path_refs(text: str) -> Iterator[tuple[int, int, str]]:
    """Yield ``(start, end, ref)`` candidate uploads paths in ``text``.

    A token is a run of path characters; the uploads tail starts after the
    ``wp-content/uploads/`` marker when the token carries one (an absolute
    or root-relative URL) and at the token's start when it does not — the
    uploads-RELATIVE spelling (``_wp_attached_file``, the metadata's
    ``file``) or the bare BASENAME spelling (every ``sizes[*].file``).
    Each tail
    is offered longest-first with trailing container characters stripped
    and URL-decoded (a filename with a space is percent-encoded in CSS and
    raw in the database — both must resolve to the same file); the caller
    decides which candidate is a real reference.
    """
    for match in _PATH_TOKEN_RE.finditer(text):
        token = match.group(0)
        marker_at = token.find(_UPLOADS_MARKER)
        tail_at = marker_at + len(_UPLOADS_MARKER) if marker_at >= 0 else 0
        tail = token[tail_at:]
        cut = len(tail)
        while cut > 0:
            yield (match.start() + tail_at, match.start() + tail_at + cut,
                   unquote(tail[:cut]))
            if tail[cut - 1] not in _TRAILING_JUNK:
                break
            cut -= 1


def suffix_of(path: str) -> str:
    """The lowercase extension of a path ("" when it has none)."""
    name = path.rpartition("/")[2]
    _, dot, ext = name.rpartition(".")
    return ext.lower() if dot else ""


def scan_refs(text: str) -> set[str]:
    """Every uploads-relative path ``text`` references (any extension).

    A reference SET, not a rewrite: an uploads-RELATIVE reference is only
    ever matched against the conversion map (which holds paths that exist
    on disk), so an unrelated ``foo/bar.jpg`` in a post can never be
    mistaken for an uploads file.
    """
    found: set[str] = set()
    for _start, _end, ref in _iter_path_refs(text):
        if ref and not ref.endswith(("/", ".")) and suffix_of(ref):
            found.add(ref)
    return found


def raster_refs(text: str) -> set[str]:
    """:func:`scan_refs` narrowed to the convertible raster suffixes."""
    return {ref for ref in scan_refs(text)
            if suffix_of(ref) in _RASTER_SUFFIXES}


#: ``url(...)`` tokens: the quoted forms keep their inner text verbatim, an
#: unquoted token runs to the first ``)`` (the CSS url-token grammar).  The
#: expression is wpt/walk.py's — the ONE owner of that grammar, imported
#: rather than copied so the crawler and this action cannot disagree about
#: what a stylesheet references.
_CSS_URL_RE = _walk._CSS_URL_RE


def _css_token_refs(text: str, css_path: str) -> list[tuple[int, int, str]]:
    """``(start, end, ref)`` per ``url()`` token that names an uploads file.

    A stylesheet reference comes in three shapes and only the first carries
    the uploads marker, so a plain text scan misses the other two — and a
    missed ``url(../2023/10/photo.jpg)`` is a background image that
    disappears the moment its file is purged:

    * absolute or root-relative — ``url(/wp-content/uploads/...`` (the
      marker is present; :func:`rewrite_text` already covers those);
    * RELATIVE — ``url(../2023/10/photo.jpg)``, resolved against the
      stylesheet's own webroot path;
    * percent-encoded — ``url(%2Fwp-content%2Fuploads%2F...)``, decoded
      before resolution.

    The span is the token's inner text, so a rewrite splices the extension
    in place and the ``../`` prefix survives byte-for-byte.
    """
    out: list[tuple[int, int, str]] = []
    for match in _CSS_URL_RE.finditer(text):
        group = next((i for i in (1, 2, 3)
                      if match.group(i) is not None), None)
        if group is None:
            continue
        inner = match.group(group)
        ref = _resolve_uploads_ref(inner.strip(), css_path)
        if ref is None:
            continue
        start = match.start(group)
        out.append((start, start + len(inner), ref))
    return out


def _resolve_uploads_ref(raw: str, css_path: str) -> str | None:
    """The uploads-relative path a stylesheet token points at, or None.

    Percent-decoding first (a space in a filename is encoded in CSS), the
    query/fragment dropped (it is not part of the file's path, and it must
    SURVIVE the rewrite — WordPress's ``?ver=`` cache-busting rides on it),
    then the marker, then — for a relative token — resolution against the
    stylesheet's own folder.  A non-http scheme (``data:``, ``blob:``) is
    never an uploads file.
    """
    if not raw or raw.startswith(("data:", "blob:", "#", "about:")):
        return None
    decoded = unquote(raw)
    if "://" in decoded:
        path = urlparse(decoded).path
    else:
        path = decoded.split("?", 1)[0].split("#", 1)[0]
    marker_at = path.find(_UPLOADS_MARKER)
    if marker_at >= 0:
        return path[marker_at + len(_UPLOADS_MARKER):] or None
    if "://" in decoded:
        return None
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(css_path),
                                                  path))
    if resolved.startswith(_UPLOADS_PREFIX):
        return resolved[len(_UPLOADS_PREFIX):] or None
    return None


def _splice_ext(raw: str, ref: str, new: str) -> str | None:
    """``raw`` with the reference's extension swapped, or None when it cannot be.

    The extension is replaced where it ACTUALLY sits: at the end of the
    path portion, which for a CSS token may be followed by a query or a
    fragment (``photo.jpg?v=2``).  When the raw bytes do not carry that
    extension at all (an exotic encoding), the token is left alone — never
    mangled, because a mangled path is a 404.
    """
    old_ext = "." + suffix_of(ref)
    new_ext = "." + suffix_of(new)
    if not old_ext or old_ext == new_ext:
        return None
    cut = len(raw)
    for delimiter in ("?", "#"):
        at = raw.find(delimiter)
        if at >= 0:
            cut = min(cut, at)
    head = raw[:cut]
    if not head.endswith(old_ext):
        return None
    return head[: -len(old_ext)] + new_ext + raw[cut:]


def scan_css_refs(text: str, css_path: str) -> set[str]:
    """Every uploads-relative raster path a stylesheet references.

    The union of the plain-text scan (absolute references) and the
    ``url()`` pass (relative and percent-encoded ones) — a stylesheet is
    the one surface where a reference can hide from a text scan.  A text
    hit carrying CSS syntax (``(``, ``)``, ``{``, ``;``, whitespace) is not
    a path: without this filter ``background:url(../a.jpg`` would enter
    the candidate set as a reference to a file that cannot exist.
    """
    refs = {ref for ref in raster_refs(text) if _is_path_shaped(ref)}
    for _start, _end, ref in _css_token_refs(text, css_path):
        if suffix_of(ref) in _RASTER_SUFFIXES:
            refs.add(ref)
    return refs


#: Characters that are CSS (or HTML) syntax and never part of a reference
#: this action rewrites — the filter that keeps a text scan's false hits
#: out of the candidate set.
_SYNTAX_CHARS = frozenset("(){};<>\"' \t\n\r")


def _is_path_shaped(ref: str) -> bool:
    """False for a text-scan hit that carries surrounding syntax."""
    return bool(ref) and not any(ch in _SYNTAX_CHARS for ch in ref)


def rewrite_css(text: str, css_path: str, mapping: dict[str, str]
                ) -> tuple[str, set[str]]:
    """:func:`rewrite_text` plus the relative/encoded ``url()`` pass.

    The second pass runs on the OUTPUT of the first and only over the
    references the mapping still holds, so the two passes cannot collide
    on one span: a reference the text scan already rewrote is a ``.webp``
    path now, and a ``.webp`` path is never a mapping key.
    """
    new_text, changed = rewrite_text(text, mapping)
    fresh = {ref for _start, _end, ref in _css_token_refs(new_text, css_path)}
    remaining = {ref: new for ref, new in mapping.items() if ref in fresh}
    if not remaining:
        return new_text, changed
    splices: list[tuple[int, int, str]] = []
    for start, end, ref in _css_token_refs(new_text, css_path):
        new = remaining.get(ref)
        if new is None or (start, end) in {(s, e) for s, e, _ in splices}:
            continue
        raw = new_text[start:end]
        replacement = _splice_ext(raw, ref, new)
        if replacement is None:
            log.debug("webp-media: leaving an oddly-encoded url() alone: %r",
                      ref)
            continue
        splices.append((start, end, replacement))
        changed.add(ref)
    if not splices:
        return new_text, changed
    out: list[str] = []
    pos = 0
    for start, end, replacement in sorted(splices):
        if start < pos:
            continue
        out.append(new_text[pos:start])
        out.append(replacement)
        pos = end
    out.append(new_text[pos:])
    return "".join(out), changed


def rewrite_text(text: str, mapping: dict[str, str]) -> tuple[str, set[str]]:
    """Rewrite every reference in ``text`` per ``mapping`` (old -> new).

    Returns ``(new_text, changed)``; the caller asserts afterwards that no
    old reference survives (the keep-set gate).  Only the EXTENSION is
    spliced, so the directory part keeps its original percent-encoding: a
    reference is rewritten in place and never silently re-encoded.  A tail
    whose raw bytes do not end in the extension its decoded form claims is
    left alone and logged, never mangled.
    """
    out: list[str] = []
    changed: set[str] = set()
    pos = 0
    for start, end, ref in _iter_path_refs(text):
        new = mapping.get(ref)
        if new is None or end <= pos:
            continue
        old_ext = "." + suffix_of(ref)
        new_ext = "." + suffix_of(new)
        raw = text[start:end]
        if not (old_ext and raw.endswith(old_ext)):
            log.debug("webp-media: leaving an oddly-encoded reference alone: "
                      "%r", ref)
            continue
        out.append(text[pos:start])
        out.append(raw[: -len(old_ext)] + new_ext)
        pos = end
        changed.add(ref)
    if not changed:
        return text, changed
    out.append(text[pos:])
    return "".join(out), changed


def looks_serialized(value: str) -> bool:
    """True when ``value`` has a PHP-serialized head.

    ``N;`` (null) is the only two-character head; every other type starts
    with a type letter, a colon and a digit (``s:5:``, ``a:2:``, ``d:1.5;``,
    ``b:1;``).  A plain post body never looks like one.
    """
    head = value.lstrip()
    if not head:
        return False
    if head[0] == "N":
        return head.startswith("N;")
    if head[0] not in _SERIAL_HEADS:
        return False
    return len(head) > 2 and head[1] == ":" and head[2].isdigit()


def _string_leaves(structure: Any, depth: int = 0) -> list[str]:
    """Every string inside an unserialized structure, depth-bounded.

    The bound is structural (the analyzer's own reader is depth-bounded
    too): a self-referential or adversarially deep payload must not turn a
    plan into a recursion crash.
    """
    if depth > 12:
        return []
    if isinstance(structure, str):
        return [structure]
    if isinstance(structure, dict):
        out: list[str] = []
        for key, value in structure.items():
            out.extend(_string_leaves(key, depth + 1))
            out.extend(_string_leaves(value, depth + 1))
        return out
    if isinstance(structure, (list, tuple)):
        out = []
        for value in structure:
            out.extend(_string_leaves(value, depth + 1))
        return out
    return []


def value_texts(value: str) -> tuple[list[str], bool]:
    """The text surfaces a DB value's references can live in.

    ``(texts, unparseable)``: a plain value is its own single surface; a
    serialized payload additionally exposes its string leaves (read with
    ``wpt.media_refs.decode_php_value``, the ONE decoder of a stored PHP
    value — the reference being the ``@unserialize`` the live side
    rewrites with, so this gate and the keep-set can never disagree about
    what a value holds).  ``unparseable`` is True when the value LOOKS
    serialized but PHP's own ``unserialize`` would return false for it — the
    fail-closed signal: the row's references cannot be enumerated safely,
    so every file it might reference is gated out instead of rewritten.
    """
    if not looks_serialized(value):
        return [value], False
    try:
        structure = decode_php_value(value)
    except (PhpDecodeError, RecursionError):
        return [value], True
    return [value] + _string_leaves(structure), False


def refs_in_value(value: str) -> tuple[set[str], bool]:
    """``(raster references, unparseable)`` of one DB value."""
    texts, bad = value_texts(value)
    refs: set[str] = set()
    for text in texts:
        refs |= raster_refs(text)
    return refs, bad


# ---------------------------------------------------------------------------
# The run state.  A Plan is a PRINTED artifact (items + backup_tables only),
# so what the rewrite needs rides on the action instance — the users_reset
# credentials-holder precedent.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RowRef:
    """One rewritable DB row, addressed the way the bridge addresses it."""

    table: str          # the real table name ("wp_postmeta")
    key_column: str     # "meta_id"
    row_id: int
    label: str          # display only: "wp_postmeta[1234]"

    @property
    def key(self) -> tuple[str, int]:
        return (self.table, self.row_id)


@dataclass(frozen=True)
class Conversion:
    """One file that will exist as a WebP twin beside its original."""

    rel_old: str        # uploads-relative original ("2023/10/photo.jpg")
    rel_new: str        # uploads-relative twin    ("2023/10/photo.webp")
    path_old: str       # webroot-relative original
    path_new: str       # webroot-relative twin
    orig_bytes: int
    new_bytes: int

    @property
    def saving(self) -> int:
        return max(0, self.orig_bytes - self.new_bytes)


@dataclass
class WebpState:
    """Everything the apply phase needs, carried from the plan."""

    conversions: list[Conversion] = field(default_factory=list)
    #: uploads-relative old -> new: the ONE map every rewrite consumes.
    mapping: dict[str, str] = field(default_factory=dict)
    #: The references a rewritable surface holds (DB rows + CSS).  A raster
    #: path of the live walk outside this set is NOT convertible.
    covered: set[str] = field(default_factory=set)
    row_edits: list[RowRef] = field(default_factory=list)
    #: the OLD references each edited row held (the plan's measurement).
    row_refs: dict[tuple[str, int], frozenset[str]] = field(default_factory=dict)
    #: the ORIGINAL value of each edited row: the apply re-derives its
    #: rewrite from these with the LIVE mapping, because a twin that did not
    #: land must not stay in the value that gets written.
    row_originals: dict[tuple[str, int], str] = field(default_factory=dict)
    #: rewritten value per PLAIN row; absent for a serialized one (the
    #: bridge re-serializes server-side; local mode rehearses the leaves).
    row_values: dict[tuple[str, int], str] = field(default_factory=dict)
    row_leaves: dict[tuple[str, int], tuple[str, ...]] = field(default_factory=dict)
    #: the ORIGINAL text of every CSS file the plan can rewrite (the apply
    #: re-derives the rewrite from the live mapping, like every other action
    #: re-derives its plan measurement).
    css_text: dict[str, str] = field(default_factory=dict)
    css_refs: dict[str, frozenset[str]] = field(default_factory=dict)
    css_edits: dict[str, bytes] = field(default_factory=dict)
    skips: dict[str, list[str]] = field(default_factory=dict)
    gated: dict[str, list[str]] = field(default_factory=dict)
    #: Database surfaces the DUMP could not let the rewrite address (a plugin
    #: table that shares a core name without declaring its columns).  They
    #: are read as GATED references; this is how the plan names them.
    gated_surfaces: list[str] = field(default_factory=list)
    #: An original a purge run left on disk because a reference to it came
    #: back after the rewrite (a stale editor save) — reported, never silent.
    purge_kept: list[str] = field(default_factory=list)
    #: PlanItem index by (category, target) so the apply marks exactly the
    #: items that landed — never a whole category optimistically.
    item_index: dict[tuple[str, str], PlanItem] = field(default_factory=dict)
    db_tables: list[str] = field(default_factory=list)
    #: the map the apply ACTUALLY used (the plan's, minus every twin that
    #: did not land) — what the verification and the report speak about.
    applied_mapping: dict[str, str] = field(default_factory=dict)
    walked: bool = False
    before_refs: set[str] = field(default_factory=set)
    #: The live crawl's PER-PAGE attribution: page URL -> the uploads
    #: references that page carried.  The post-apply proof compares page by
    #: page, so that a page a bot challenge (or a transport error) kept
    #: from being read can be excluded with exactly its own references
    #: (see ``_PageRecordingSet`` and the module docstring).
    before_pages: dict[str, set[str]] = field(default_factory=dict)
    #: Pages the plan's live crawl could not read at all, and why.  They
    #: carry no references on the "before" side either, so both sides of
    #: the comparison are equally blind there — reported, never guessed.
    before_unprovable: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Mode-specific reference sources.
# ---------------------------------------------------------------------------


def _by_suffix(tables: Iterable[str],
               spec: dict[str, tuple[str, ...]]) -> dict[str, tuple[str, ...]]:
    """Real table name -> spec tuple, by SUFFIX match (fail-safe upwards).

    The prefix is never assumed, so a ``wp_``/``wpt_``/prefix-less site all
    work, and a stray ``wp_myoptions`` is merely read, never missed.  A
    suffix is a NAME, though, never a schema — a table that only shares
    one is a candidate, and whether it can be addressed is decided
    against the dump itself (:func:`_local_surfaces`).
    """
    found: dict[str, tuple[str, ...]] = {}
    for name in tables:
        for suffix, columns in spec.items():
            if name.endswith(suffix):
                found[name] = columns
                break
    return found


@dataclass(frozen=True)
class _Surface:
    """One rewritable table, addressed by the column names the DUMP shows."""

    table: str
    key_column: str
    value_column: str


def _local_surfaces(tables: dict[str, TableStats]
                    ) -> tuple[dict[str, _Surface], dict[str, str], list[str]]:
    """The rewritable surfaces of a dump, RESOLVED AGAINST THE DUMP.

    Discovery stays a SUFFIX match, so the ``wp_`` prefix is never assumed
    and a table that only shares a core name is still a candidate.  But a
    suffix is not a schema: on a site running all-in-one-seo-pack 5.x the
    table ``wp_aioseo_posts`` ends with ``posts`` and declares
    ``id``/``post_id``/``og_image_url`` — no ``ID`` and no ``post_content``
    at all.  Demanding a column the CREATE does not declare used to refuse
    the whole run before it could do anything (observed on a site running
    that plugin), so every candidate is now asked what it actually has:

    * the columns are there -> a rewritable surface, rewritten like any
      other.  The discovery is NOT narrowed: a plugin table that really
      does carry the columns is enumerated;
    * a column is absent -> the table is a GATED surface.  Its rows are
      read across EVERY column as references nothing here can rewrite
      (that direction can only keep an image in its original form, never
      break one), and the plan NAMES the surface and what it lacks;
    * a suffix no table provides at all -> the dump cannot describe the
      reference set, which stays a refusal.

    Returns ``(enumerable, gated, absent)``: the real table name -> the
    surface; the real table name -> why it is gated; the suffixes nothing
    provides.
    """
    enumerable: dict[str, _Surface] = {}
    gated: dict[str, str] = {}
    provided: set[str] = set()
    for name in sorted(tables):
        for suffix, (key_column, value_column) in _REWRITABLE_TABLES.items():
            if not name.endswith(suffix):
                continue
            absent = [column for column in (key_column, value_column)
                      if column not in tables[name].columns]
            if absent:
                gated[name] = f"{suffix} needs {' + '.join(absent)}"
            else:
                enumerable[name] = _Surface(name, key_column, value_column)
                provided.add(suffix)
            break
    return (enumerable, gated,
            [suffix for suffix in _REWRITABLE_TABLES if suffix not in provided])


def _rows_local(ctx: "Ctx") -> tuple[list[RowRef], dict[tuple[str, int], str],
                                     dict[str, str], list[str]]:
    """Read the reference rows out of the SQL dump (local mode).

    One streaming pass per table (``wpt.localmode.sql_dump.iter_rows``).
    Cells are addressed by NAME taken from the CREATE statement, which is
    only valid when a table's INSERTs are positional: an explicit column
    list makes cell order ambiguous, so the run refuses rather than rewrite
    a value it cannot reliably address.  Gated columns of a rewritable
    table (posts.post_excerpt) come from the same pass.

    WHICH tables are rewritable is decided by :func:`_local_surfaces`
    against the dump's own columns, never by the table NAME alone: a
    plugin table that merely ends with a core name and does not declare
    the columns joins the GATED surfaces (read across every column) and is
    reported, instead of refusing the run.

    Returns ``(rows, values, gated, surfaces)`` where ``gated`` maps an
    uploads-relative path to the label of the unrewritable reference
    holding it, and ``surfaces`` names the database surfaces this dump
    could not let the rewrite address.
    """
    if ctx.sql is None:
        raise SourceError(
            "webp-media needs --sql: the references it must rewrite live in "
            "the database, and an image with no reference to rewrite is "
            "another action's business"
        )
    try:
        with ctx.sql.open("rb") as handle:
            summary = parse_dump(handle)
    except OSError as exc:
        raise SourceError(f"cannot read the SQL dump {ctx.sql}: {exc}") from exc
    surfaces, ungated, missing = _local_surfaces(summary.tables)
    if missing:
        raise SourceError(
            "the dump defines no table carrying the "
            + ", ".join(repr(s) for s in missing)
            + " surface (nothing ending with that name declares its key and "
              "value columns) — webp-media cannot enumerate the references "
              "it must rewrite; refusing"
        )
    gated = _by_suffix(summary.tables, _GATED_TABLES)
    for name in ungated:
        # A table the rewrite could not address is a GATED surface: every
        # one of its columns is scanned for references nothing here can
        # rewrite, so an image it names keeps its original bytes.
        gated[name] = tuple(summary.tables[name].columns)
    rows: list[RowRef] = []
    values: dict[tuple[str, int], str] = {}
    held: dict[str, str] = {}
    for surface in sorted(surfaces.values(), key=lambda s: s.table):
        name, key_column, value_column = (surface.table, surface.key_column,
                                          surface.value_column)
        stats = summary.tables[name]
        if stats.insert_columns is not None:
            raise SourceError(
                f"webp-media refuses {name}: its INSERT statements carry an "
                "explicit column list, so a cell cannot be addressed by name "
                "— re-export the dump with positional INSERTs"
            )
        key_at = stats.columns.index(key_column)
        value_at = stats.columns.index(value_column)
        gate_at = [stats.columns.index(c) for c in gated.get(name, ())
                   if c in stats.columns]
        with ctx.sql.open("rb") as handle:
            for cells in iter_rows(handle, name):
                row_id = cells[key_at]
                value = cells[value_at]
                if (isinstance(row_id, int) and not isinstance(row_id, bool)
                        and isinstance(value, str)
                        and may_reference_image(value)):
                    rows.append(RowRef(
                        table=name, key_column=key_column, row_id=row_id,
                        label=f"{name}[{row_id}]",
                    ))
                    values[(name, row_id)] = value
                if not gate_at:
                    continue
                label = f"{name}[{row_id}]" if isinstance(row_id, int) else name
                for at in gate_at:
                    other = cells[at]
                    if isinstance(other, str) and may_reference_image(other):
                        for ref in raster_refs(other):
                            held.setdefault(ref, label)
    for name, columns in sorted(gated.items()):
        if name in surfaces:
            continue  # already read from the rewritable pass
        stats = summary.tables[name]
        if stats.insert_columns is not None:
            log.warning("webp-media: %s carries an explicit column list; its "
                        "gated references are not read (fail-safe: they can "
                        "only keep an image from being converted)", name)
            continue
        with ctx.sql.open("rb") as handle:
            for cells in iter_rows(handle, name):
                for at, column in enumerate(stats.columns):
                    if column not in columns:
                        continue
                    cell = cells[at]
                    if isinstance(cell, str) and may_reference_image(cell):
                        label = f"{name}[{_first_int(cells)}]"
                        for ref in raster_refs(cell):
                            held.setdefault(ref, label)
    return (rows, values, held,
            [f"{name} ({why})" for name, why in sorted(ungated.items())])


def _first_int(cells: list[Any]) -> int:
    for cell in cells:
        if isinstance(cell, int) and not isinstance(cell, bool):
            return cell
    return 0


def _rows_bridge(bridge: Any, scan_cap: int = 0
                 ) -> tuple[list[RowRef], dict[tuple[int, int], str],
                             dict[str, str], list[str]]:
    """Read the reference rows through the bridge (ftp mode).

    The read mode of ``media_rewrite_refs``, read through the client's own
    ``Bridge.iter_rewrite_refs`` — the ONE implementation of this wire
    contract.  It is fail-closed, and this action adds nothing weaker beside
    it: a ``truncated`` marker, a stream that ends WITHOUT its terminal
    summary (a PHP fatal after the first lines, a cut connection), a summary
    whose row count disagrees with the rows that arrived and a malformed row
    all raise there, before a single row reaches the surface model below.
    Consuming the raw stream here instead would read a SHORT row set as a
    complete one, and a reference nobody measured is an image this run would
    convert on the strength of a set that is half-measured.

    ``scan_cap`` is the OPERATOR LEVER (``bridge.scan_cap`` in the settings
    profile), forwarded as ``None`` when it is 0 so the shipped default asks
    for nothing and the answer is byte-identical to a run that never
    mentioned a cap.  The op is the validating owner of the bound: it
    CLAMPS a request above its own ceiling, reports ``scan_cap_clamped``
    once, and the client turns that into a WARNING beside the plan — so a
    site over the op's default truncation is measurable, and a cap the
    server did not honour is never silent.

    Each streamed row is ``{table, key, id, value?, gated?}``.  A row with a
    ``value`` is rewritable; a row with only ``gated`` cells is a GATED
    surface (the client's own ref extraction decides — one rule, one
    implementation, no PHP mirror of the path scanner).

    The wire op owns its own schema resolution: which tables a name-matched
    server-side query can address is the bridge's contract, exactly as the
    dump's columns are the local reader's (see :func:`_local_surfaces`),
    so the surface list this returns is empty on this path.
    """
    rows: list[RowRef] = []
    values: dict[tuple[str, int], str] = {}
    held: dict[str, str] = {}
    for obj in bridge.iter_rewrite_refs(scan_cap=scan_cap or None):
        # the reader has already refused anything not addressable, so a row
        # that gets here carries a real table and an integer id
        table = obj["table"]
        row_id = obj["id"]
        label = f"{table}[{row_id}]"
        value = obj.get("value")
        if isinstance(value, str):
            values[(table, row_id)] = value
            rows.append(RowRef(
                table=table, key_column=str(obj.get("key") or ""),
                row_id=row_id, label=label,
            ))
        for cell in obj.get("gated") or ():
            if not isinstance(cell, str):
                continue
            for ref in raster_refs(cell):
                held.setdefault(ref, label)
    return rows, values, held, []


# ---------------------------------------------------------------------------
# The action.
# ---------------------------------------------------------------------------


class ImagesWebpAction:
    """The plan/apply pair; ``stack`` is the registry-built source trio."""

    def __init__(self) -> None:
        #: The plan -> apply hand-off (a Plan cannot carry row values).
        self.state: WebpState | None = None

    # -- plan ------------------------------------------------------------

    def plan(self, ctx: "Ctx", stack: tuple) -> Plan:
        source, session, bridge = stack
        cfg = _config(ctx, purge_flag=ctx.extra.get("purge_originals"))
        # Before the (expensive) candidate scan: a purge the operator has
        # not acknowledged as a windowed operation is refused up front.
        _require_purge_ack(ctx, cfg)
        state = WebpState()
        self.state = state
        deadline = Deadline.from_ctx(ctx)

        state.db_tables = self._db_tables(ctx, bridge)
        rows, values, held, surfaces = self._read_rows(ctx, stack)
        state.gated_surfaces = surfaces
        css_text, css_unreadable = _css_scan(source, deadline)

        # 1. The reference set, per rewritable surface.  A file NO surface
        #    references is another action's business (trim-media owns the
        #    orphans), so it is never a candidate here.
        covered: dict[str, list[str]] = {}
        unparseable: set[str] = set()
        for row in rows:
            value = values.get(row.key)
            if value is None:
                continue
            refs, bad = refs_in_value(value)
            if bad:
                unparseable.add(row.label)
            for ref in refs:
                covered.setdefault(ref, []).append(row.label)
        for path, text in css_text.items():
            for ref in scan_css_refs(text, path):
                covered.setdefault(ref, []).append(path)

        # 2. Gated references: a surface that could not be read or parsed.
        #    Their files keep their original bytes — converting one would
        #    break a reference nothing in this run can rewrite.
        gated: dict[str, list[str]] = {}
        for ref, label in sorted(held.items()):
            if label in unparseable:
                reason = _GATE_SERIALIZED
            elif label in css_unreadable:
                reason = _GATE_CSS
            else:
                reason = _GATE_TABLE
            gated.setdefault(reason, []).append(ref)
        for row in rows:
            if row.label in unparseable:
                gated.setdefault(_GATE_SERIALIZED, []).extend(
                    sorted(raster_refs(values[row.key])))
        state.gated = {reason: sorted(set(paths))
                       for reason, paths in gated.items() if paths}

        # 3. Candidates: referenced, not gated, big enough, outside a data
        #    tree, and decodable/convertible.  Every rejection is a line.
        conversions, mapping = self._candidates(source, cfg, covered, gated,
                                                state, deadline)
        state.conversions = conversions
        state.mapping = mapping
        state.covered = set(covered)

        # 4. The live keep-set report (ftp with a site URL): rendered HTML
        #    is the only truth about the live site, and a raster reference
        #    it holds that NO rewritable surface holds is one this action
        #    cannot rewrite — those images are left alone, and the pages
        #    captured here are the "before" side of the post-apply proof.
        if session is not None and ctx.wp_url:
            self._live_gate(ctx, session, state, cfg)

        # 5. The rewrite set: every row and CSS file whose text changes.
        row_edits, row_values, row_leaves, row_refs = _row_rewrites(
            rows, values, state.mapping)
        state.row_edits = row_edits
        state.row_values = row_values
        state.row_leaves = row_leaves
        state.row_refs = row_refs
        state.row_originals = {row.key: values[row.key] for row in row_edits
                               if row.key in values}
        state.css_text = css_text
        state.css_refs = {path: frozenset(scan_css_refs(text, path))
                          for path, text in css_text.items()}

        items = self._items(state, conversions, row_edits, purge=cfg.purge_originals)
        state.item_index = {(i.category, i.target): i for i in items}
        plan = Plan(items=items,
                    backup_tables=self._backup_tables(state, row_edits))
        _log_plan_summary(cfg, state, conversions, row_edits)
        return plan

    # -- apply -----------------------------------------------------------

    def apply(self, ctx: "Ctx", stack: tuple, plan: Plan) -> Plan:
        source, _session, bridge = stack
        cfg = _config(ctx, purge_flag=ctx.extra.get("purge_originals"))
        _require_purge_ack(ctx, cfg)
        state = self.state
        landed: set[str] = set()
        if state is None or not state.mapping:
            return plan  # nothing planned — no write, no bridge roundtrip
        if cfg.purge_originals and ctx.mode == "local":
            # Fail closed BEFORE any mutation: a local rehearsal writes the
            # webroot but never the database, so deleting the originals
            # would materialize an artifact whose references are broken.
            raise SourceError(
                "--purge-originals is refused in local mode: the rehearsal "
                "rewrites the webroot but cannot write the database, so the "
                "originals are the only files the rewritten references could "
                "resolve to — re-run against the live site (ftp mode)"
            )

        # 1. The twins.  Each is verified by a read-back; one that did not
        #    land is dropped from the map — under BOTH spellings (the
        #    uploads path and the bare basename WordPress also uses), so
        #    nothing is ever rewritten towards a file that is not there.
        mapping: dict[str, str] = {}
        for conversion in state.conversions:
            try:
                data = source.read_bytes(conversion.path_old)
            except (WptError, OSError) as exc:
                log.warning("webp-media: cannot read %s (%s) — not converted, "
                            "and its references are left untouched",
                            conversion.path_old, exc)
                continue
            encoded = encode_webp(data, cfg)
            if encoded is None or len(encoded) >= len(data):
                log.warning("webp-media: %s does not convert to a smaller "
                            "WebP — left as it is", conversion.path_old)
                continue
            try:
                source.write_bytes(conversion.path_new, encoded)
                stored = source.read_bytes(conversion.path_new)
            except (WptError, OSError) as exc:
                log.warning("webp-media: writing %s failed (%s)",
                            conversion.path_new, exc)
                continue
            if len(stored) != len(encoded):
                log.warning("webp-media: %s read back %d bytes, expected %d — "
                            "not marked done", conversion.path_new,
                            len(stored), len(encoded))
                continue
            landed.add(conversion.rel_old)
            self._done(state, "media.webp", conversion.path_new)
        # Narrow the plan's map to what landed, under BOTH spellings: a key
        # survives when the file it names is one of the landed originals (a
        # bare basename resolves to its unique uploads path, which is the
        # only way the plan ever registered it).
        landed_names = {rel.rpartition("/")[2] for rel in landed}
        mapping = {
            old_ref: new_ref
            for old_ref, new_ref in state.mapping.items()
            if old_ref in landed
            or ("/" not in old_ref
                and old_ref in landed_names
                and _unique_owner(state, old_ref) in landed)
        }
        state.applied_mapping = mapping
        if not mapping:
            log.warning("webp-media: no twin could be written; no reference "
                        "was rewritten")
            return plan

        # 2. The rewrite: the database first (the bridge owns the
        #    serialization-aware value write), then the CSS files.
        if any(state.row_refs.get(row.key, frozenset()) & set(mapping)
               for row in state.row_edits):
            self._apply_rows(ctx, bridge, state, mapping)
        self._apply_css(source, state, mapping)

        # 3. THE PROOF (see the module docstring).  Nothing is marked done
        #    before the rewritten reference set has been re-read.
        self._verify(ctx, stack, state, mapping, plan, cfg)

        # 4. The purge: a SECOND, explicitly acknowledged step, and only for
        #    an original whose rewritten reference set verified AND that
        #    nothing references any more (see _purge: the decision is taken
        #    from a reference set re-read HERE, never from the plan's scan).
        if cfg.purge_originals:
            self._purge(ctx, source, stack, state, mapping, plan)
        return plan

    # -- plan internals --------------------------------------------------

    def _db_tables(self, ctx: "Ctx", bridge: Any) -> list[str]:
        """Every real table name, from the audit (ftp) or the dump (local)."""
        if ctx.mode == "local":
            if ctx.sql is None:
                raise SourceError(
                    "webp-media needs --sql: the references it must rewrite "
                    "live in the database"
                )
            try:
                with ctx.sql.open("rb") as handle:
                    return sorted(parse_dump(handle).tables)
            except OSError as exc:
                raise SourceError(
                    f"cannot read the SQL dump {ctx.sql}: {exc}") from exc
        if bridge is None:
            raise SourceError("webp-media needs the bridge in ftp mode")
        from ..audit.data import _tables_from_wire

        return sorted(_tables_from_wire(bridge.call("db_audit").get("tables")))

    def _read_rows(self, ctx: "Ctx", stack: tuple
                   ) -> tuple[list[RowRef], dict[tuple[str, int], str],
                              dict[str, str], list[str]]:
        if ctx.mode == "local":
            return _rows_local(ctx)
        bridge = stack[2]
        if bridge is None:
            raise SourceError("webp-media needs the bridge in ftp mode")
        return _rows_bridge(bridge, ctx.settings.bridge.scan_cap)

    def _candidates(self, source: "Source", cfg: WebpConfig,
                    covered: dict[str, list[str]], gated: dict[str, list[str]],
                    state: WebpState, deadline: Deadline
                    ) -> tuple[list[Conversion], dict[str, str]]:
        """The conversion set, with every rejection bucketed for the report.

        The buckets are per RULE, not per file, so the report reads as
        "here is what was not converted and why": a plan listing only the
        converted files would hide a whole class of trap.

        A BARE reference — a basename with no directory — is resolved
        through :func:`_basename_index` first, because that is how
        WordPress stores a size derivative: ``sizes[*].file`` is
        ``photo-150x150.jpg``, not ``2023/10/photo-150x150.jpg``.  A unique
        basename resolves (and is rewritten under both spellings); an
        ambiguous one gates every file that could be meant, because picking
        one would point half the references at the wrong year folder.
        """
        inventory = _uploads_inventory(source, deadline)
        by_name = _basename_index(inventory)
        targets = _resolve_references(covered, by_name, state)
        gate_refs = {ref for paths in gated.values() for ref in paths}
        conversions: list[Conversion] = []
        digests: dict[str, str] = {}
        scanned = 0
        last_log = time.monotonic()
        for rel in sorted(targets):
            if deadline is not None:
                deadline.check("webp-media candidate scan")
            webroot = _UPLOADS_PREFIX + rel
            if rel in gate_refs:
                # A reference this action cannot rewrite vetoes the file.
                continue
            size = inventory.get(webroot)
            if size is None:
                state.skips.setdefault(_SKIP_ABSENT, []).append(rel)
                continue
            scanned += 1
            if any(webroot.startswith(prefix) for prefix in cfg.data_prefixes):
                state.skips.setdefault(_SKIP_DATA_TREE, []).append(rel)
                continue
            if size < cfg.skip_below_bytes:
                state.skips.setdefault(_SKIP_TINY, []).append(rel)
                continue
            rel_new = twin_name(rel)
            if _UPLOADS_PREFIX + rel_new in inventory:
                state.skips.setdefault(_SKIP_TWIN_EXISTS, []).append(rel)
                continue
            if any(c.rel_new == rel_new for c in conversions):
                state.skips.setdefault(_SKIP_COLLISION, []).append(rel)
                continue
            try:
                data = source.read_bytes(webroot)
            except (WptError, OSError) as exc:
                # A candidate we cannot read is not a candidate: the plan
                # would be guessing about a file it has never seen.
                log.warning("webp-media: cannot read %s (%s) — not converted",
                            webroot, exc)
                state.skips.setdefault(_SKIP_UNREADABLE, []).append(rel)
                continue
            refusal = classify_image(data)
            if refusal is not None:
                state.skips.setdefault(refusal[0], []).append(rel)
                continue
            digest = hashlib.sha256(data).hexdigest()
            if digest in digests:
                # Byte-identical to a file already handled: one twin is
                # enough — two would store the same bytes twice.
                state.skips.setdefault(_SKIP_DUPLICATE, []).append(rel)
                continue
            encoded = encode_webp(data, cfg)
            if encoded is None:
                state.skips.setdefault(_SKIP_ENCODE, []).append(rel)
                continue
            if len(encoded) >= len(data):
                # Never store a bigger twin: the reference rewrite would be
                # pure cost with a worse result.
                state.skips.setdefault(_SKIP_NOT_SMALLER, []).append(rel)
                digests[digest] = rel
                continue
            digests[digest] = rel
            conversions.append(Conversion(
                rel_old=rel, rel_new=rel_new, path_old=webroot,
                path_new=_UPLOADS_PREFIX + rel_new,
                orig_bytes=len(data), new_bytes=len(encoded)))
            now = time.monotonic()
            if (scanned % _HEARTBEAT_EVERY == 0
                    and now - last_log >= _HEARTBEAT_S):
                log.info("webp-media: scanned %d referenced image(s), %d "
                         "converted so far", scanned, len(conversions))
                last_log = now
        return conversions, _rewrite_map(conversions, by_name)

    def _live_gate(self, ctx: "Ctx", session: Any, state: WebpState,
                   cfg: WebpConfig) -> None:
        """Record the live reference set, per page, and what it protects.

        The crawl is the only source of rendered-HTML truth.  A raster
        reference it holds that NO rewritable surface holds cannot be
        rewritten by this action, so its image is never a candidate and the
        plan names the class with its count.  The reference set itself is
        the "before" side of the post-apply proof — kept PER PAGE, because
        that is the only shape a challenge-thinned fetch can be excluded
        from honestly.  A PARTIAL crawl (page budget or deadline) weakens
        the picture to the pages it did read, and a page the bot-protection
        layer kept it from reading weakens it further; both are reported,
        never treated as complete.
        """
        capture = _live_capture(session, ctx, cfg, Deadline.from_ctx(ctx))
        state.walked = True
        state.before_refs = capture.refs
        state.before_pages = capture.pages
        state.before_unprovable = capture.unprovable
        if not capture.refs:
            log.warning("webp-media: the live crawl found 0 uploads references "
                        "— the rendered-HTML gate is empty and only the "
                        "database and CSS surfaces protect this run")
        html_only = {ref for ref in capture.refs
                     if suffix_of(ref) in _RASTER_SUFFIXES} - state.covered
        if html_only:
            state.gated.setdefault(_GATE_HTML_ONLY, []).extend(sorted(html_only))
        if capture.unprovable:
            log.warning("webp-media: %d page(s) of the live crawl could not be "
                        "read (%s) — the rendered-HTML picture and the "
                        "post-apply proof cover the pages that answered",
                        len(capture.unprovable),
                        ", ".join(sorted({_exclusion_kind(reason) for reason
                                          in capture.unprovable.values()})))
        if capture.partial:
            log.warning("webp-media: the live crawl was PARTIAL (%d page(s)) — "
                        "the rendered-HTML picture covers those pages only",
                        len(capture.pages))

    def _backup_tables(self, state: WebpState, row_edits: list[RowRef]
                       ) -> list[str]:
        """The tables the pre-action snapshot must capture.

        The WHOLE touched table: a restore is whole-table by contract
        (SPEC v1 scope), so a row-level scope would promise a precision the
        restore cannot honour.  Fail-closed — a touched table the audit
        cannot locate means the rewrite would run unbacked.
        """
        touched = sorted({row.table for row in row_edits})
        if not touched:
            return []
        missing = [name for name in touched if name not in state.db_tables]
        if missing:
            raise SourceError(
                "the table list has no " + ", ".join(missing)
                + " — webp-media refuses to rewrite rows it could not snapshot"
            )
        return touched

    def _items(self, state: WebpState, conversions: list[Conversion],
               row_edits: list[RowRef], *, purge: bool) -> list[PlanItem]:
        """The plan items — what WOULD change, and what would NOT."""
        items: list[PlanItem] = []
        for conversion in conversions:
            items.append(PlanItem(
                category="media.webp",
                target=conversion.path_new,
                detail=(f"{conversion.rel_old} -> {conversion.rel_new} "
                        f"({human_bytes(conversion.orig_bytes)} -> "
                        f"{human_bytes(conversion.new_bytes)})"),
                bytes_est=conversion.saving,
            ))
        per_table: dict[str, int] = {}
        for row in row_edits:
            per_table[row.table] = per_table.get(row.table, 0) + 1
        for table, count in sorted(per_table.items()):
            items.append(PlanItem(
                category="db.webp_refs",
                target=table,
                detail=(f"{count} row(s) rewritten to the .webp paths — "
                        f"re-read and checked after the write"),
            ))
        for path in sorted(state.css_refs):
            if not state.css_refs[path] & set(state.mapping):
                continue
            items.append(PlanItem(
                category="media.webp_css",
                target=path,
                detail="url(...) references rewritten to the .webp paths",
            ))
        if conversions:
            items.append(PlanItem(
                category="media.webp_estimate",
                target="reclaimable-by-source-format",
                detail=("the reclaimable bytes split by source format — the "
                        "blended total hides where the saving is, and a PNG "
                        "converted to WebP is a LOSSY re-encode of a format "
                        "sites pick for exact or flat artwork, so the PNG side "
                        "is a decision of its own: "
                        + "; ".join(f"{label} {files} file(s), "
                                    f"{human_bytes(saved)}"
                                    for label, files, saved
                                    in _estimate_split(conversions))),
                requires_apply=False,
            ))
        if purge:
            for conversion in conversions:
                items.append(PlanItem(
                    category="media.webp_purge",
                    target=conversion.path_old,
                    detail=("the original is deleted only after the rewritten "
                            "references verify AND a fresh re-read shows "
                            "nothing references it again — an original a live "
                            "editor brought back is kept and reported (its "
                            "bytes are in the pre-action snapshot either "
                            "way)"),
                ))
        else:
            # The default is convert + rewrite + KEEP: the saving is only
            # realized by the purge, and the operator has to be told so.
            if conversions:
                items.append(PlanItem(
                    category="media.webp_advice",
                    target="purge-originals",
                    detail=("the originals are KEPT: this run converts and "
                            "rewrites, so the space is not realized on disk "
                            "until a second run with --purge-originals "
                            "deletes them (after the rewritten references "
                            "verify); the purge is a WINDOWED operation and "
                            "refuses without " + _PURGE_ACK_FLAG),
                    requires_apply=False,
                ))
        for reason, paths in sorted(state.skips.items()):
            if paths:
                items.append(PlanItem(
                    category="media.webp_skipped",
                    target=reason,
                    detail=(f"{len(paths)} item(s) not converted — "
                            f"{_SKIP_TITLES.get(reason, reason)}: "
                            f"{_sample(paths)}"),
                    requires_apply=False,
                ))
        for reason, paths in sorted(state.gated.items()):
            if paths:
                items.append(PlanItem(
                    category="media.webp_gated",
                    target=reason,
                    detail=(f"{len(paths)} referenced image(s) kept in their "
                            f"original form — {_GATE_NOTES.get(reason, reason)}: "
                            f"{_sample(paths)}"),
                    requires_apply=False,
                ))
        if state.gated_surfaces:
            items.append(PlanItem(
                category="media.webp_gated",
                target="unenumerated-surfaces",
                detail=(f"{len(state.gated_surfaces)} database surface(s) this "
                        f"dump does not let the rewrite address (a table can "
                        f"share a core name without carrying its columns), so "
                        f"every reference they hold is read as a GATED one and "
                        f"the images they name are never converted: "
                        f"{_sample(state.gated_surfaces)}"),
                requires_apply=False,
            ))
        if not state.walked:
            items.append(PlanItem(
                category="media.webp_advice",
                target="no-live-proof",
                detail=("no rendered-HTML proof in this mode: the keep-set gate "
                        "covers the database and the scanned CSS only — re-run "
                        "against the live site before purging"),
                requires_apply=False,
            ))
        for kind, urls in sorted(_excluded_urls(state.before_unprovable,
                                                state.before_pages).items()):
            items.append(_unprovable_item(kind, urls,
                                          "read before the rewrite"))
        return items

    # -- apply internals -------------------------------------------------

    def _done(self, state: WebpState, category: str, target: str) -> None:
        item = state.item_index.get((category, target))
        if item is not None:
            item.done = True

    def _apply_rows(self, ctx: "Ctx", bridge: Any, state: WebpState,
                    mapping: dict[str, str]) -> None:
        """Write the rewritten values (bridge in ftp mode, model in local).

        ftp: ONE ``media_rewrite_refs(apply=true)`` call per batch, through
        the client's own ``Bridge.rewrite_refs`` — the one fail-closed
        reader of the apply answer: an unanswered row, a malformed re-read
        row or an answer that omits a requested row raises there, so a
        partial write can never be mistaken for a completed one.  The op
        re-reads every row it wrote and the client returns those re-read
        values, so the verification below is the SERVER's answer, not an
        assumption.
        local: the rehearsal model is updated in memory and nothing is
        persisted — there is no database in local mode, and the plan's
        ``no-live-proof`` advice is where the operator is told so.

        A plain row travels WITH its rewritten value (the client computed it
        and the re-read proves it); a serialized row travels WITHOUT one,
        because only ``maybe_serialize`` can rewrite a length-prefixed value.
        """
        pending = [row for row in state.row_edits
                   if state.row_refs.get(row.key, frozenset()) & set(mapping)]
        if not pending:
            return
        # The rewrite is RE-DERIVED from each row's original value with the
        # LIVE mapping — never the plan's.  A twin that failed to land is
        # out of the mapping, so the value written must not mention it.
        fresh_values: dict[tuple[str, int], str] = {}
        fresh_leaves: dict[tuple[str, int], tuple[str, ...]] = {}
        for row in pending:
            original = state.row_originals.get(row.key)
            if original is None:
                continue
            if looks_serialized(original):
                texts, bad = value_texts(original)
                if bad:
                    continue
                fresh_leaves[row.key] = tuple(
                    rewrite_text(text, mapping)[0] for text in texts)
            else:
                new_value, changed = rewrite_text(original, mapping)
                if changed:
                    fresh_values[row.key] = new_value
        state.row_values = fresh_values
        state.row_leaves = fresh_leaves
        if ctx.mode == "local":
            return
        if bridge is None:
            raise SourceError("webp-media needs the bridge in ftp mode")
        for offset in range(0, len(pending), _BRIDGE_BATCH):
            edits = []
            for row in pending[offset:offset + _BRIDGE_BATCH]:
                entry = {"table": row.table, "key": row.key_column,
                         "id": row.row_id}
                value = state.row_values.get(row.key)
                if value is not None:
                    entry["value"] = value
                edits.append(entry)
            try:
                answer = bridge.rewrite_refs(mapping=mapping, rows=edits)
            except WptError as exc:
                raise SourceError(
                    f"webp-media: the reference rewrite failed ({exc}); the "
                    f"pre-action snapshot is the rollback"
                ) from exc
            for entry in answer:
                value = entry.get("value")
                if isinstance(value, str):
                    state.row_values[(entry["table"], entry["id"])] = value

    def _apply_css(self, source: "Source", state: WebpState,
                   mapping: dict[str, str]) -> None:
        """Rewrite every CSS file whose references this run actually moved.

        The rewrite is RE-DERIVED from the file's own current text with the
        live mapping (the plan's measurement may be stale), then written
        and read back — a write that reports success is not proof on a live
        site, where an FTP upload can truncate silently.
        """
        for path in sorted(state.css_text):
            try:
                raw = source.read_bytes(path)
                text = raw.decode("utf-8")
            except (WptError, OSError) as exc:
                log.warning("webp-media: cannot read %s (%s)", path, exc)
                continue
            except UnicodeDecodeError:
                log.warning("webp-media: %s is not UTF-8 — not rewritten", path)
                continue
            new_text, changed = rewrite_css(text, path, mapping)
            if not changed:
                continue
            data = new_text.encode("utf-8")
            try:
                source.write_bytes(path, data)
                stored = source.read_bytes(path)
            except (WptError, OSError) as exc:
                log.warning("webp-media: rewriting %s failed (%s)", path, exc)
                continue
            state.css_edits[path] = data
            if stored != data:
                log.warning("webp-media: %s did not read back as written — "
                            "not marked done", path)
                continue
            self._done(state, "media.webp_css", path)

    def _purge(self, ctx: "Ctx", source: "Source", stack: tuple,
               state: WebpState, mapping: dict[str, str], plan: Plan) -> None:
        """Delete the originals — only ever after the rewrite verified.

        THE WINDOWED OPERATION.  The site's editors save pages during the
        day, and a save from a stale client re-introduces the ORIGINAL
        filename in ``post_content`` between the rewrite and this call.
        Deleting the file behind that reference does two kinds of damage:
        the page shows a broken image, and the surviving reference
        permanently protects bytes that are already gone.

        So the per-file decision is taken from a reference set RE-READ
        HERE (:meth:`_current_refs` — the same read-only reader the plan
        used, plus the stylesheets' current text), never from the plan's
        scan, which is exactly the measurement a live edit invalidates.  A
        file that is referenced again KEEPS its bytes.

        A kept original is an ADVISORY, not a failure: the rewrite this run
        was asked for verified, so the conversion is live, the pages point
        at the twins, and the registry's cache purge MUST still fire — a
        declined delete that decided rc 1 skipped that purge and left the
        site serving pre-rewrite HTML out of cache while telling the
        operator the run had failed (measured on a real site).  So the item
        stops being applicable, the report names the kept files and says
        the space waits for a quiet window, and only an UNPROVEN REWRITE
        fails the run (that is :meth:`_verify`, and it still fails closed).

        A LAST sweep after the deletes reports — never raises on — a
        reference that reappeared pointing at an original this run removed.
        The operator needs the list, and the pre-action snapshot holds the
        bytes to put back.
        """
        fresh = self._current_refs(ctx, source, stack, state)
        deleted: set[str] = set()
        for conversion in _landed_twins(state, mapping):
            name = conversion.rel_old.rpartition("/")[2]
            back = sorted({ref for ref in (conversion.rel_old, name)
                           if ref in fresh})
            if back:
                state.purge_kept.append(conversion.rel_old)
                log.warning(
                    "webp-media: %s is referenced again (%s) — the original "
                    "is KEPT: something saved it back between the rewrite "
                    "and the purge. The conversion is live and the cache is "
                    "being purged; rerun the purge in a quiet window",
                    conversion.path_old, ", ".join(back))
                self._purge_kept_item(state, conversion, back)
                continue
            try:
                source.delete(conversion.path_old)
            except (WptError, OSError) as exc:
                log.warning("webp-media: could not delete the original %s "
                            "(%s) — the space is not reclaimed",
                            conversion.path_old, exc)
                continue
            deleted.add(conversion.rel_old)
            self._done(state, "media.webp_purge", conversion.path_old)
        self._purge_kept_report(state, plan)
        if not deleted:
            return
        stale = sorted(_stale_after_purge(state, self._current_refs(
            ctx, source, stack, state), deleted))
        if not stale:
            return
        log.warning(
            "webp-media: %d reference(s) point at an original this run "
            "deleted — a page was saved from a stale editor after the "
            "rewrite: %s. The pre-action snapshot holds the bytes; "
            "`wpt restore <snapshot> --file <path>` puts the image back",
            len(stale), _sample(stale))
        plan.items.append(PlanItem(
            category="media.webp_purge_race",
            target="stale-references",
            detail=(f"{len(stale)} reference(s) point at an original this run "
                    f"deleted, so the page that holds them shows a broken "
                    f"image until the operator restores it: {_sample(stale)} — "
                    f"the pre-action snapshot holds every deleted original's "
                    f"bytes (`wpt restore` puts one back)"),
            requires_apply=False,
        ))

    def _purge_kept_item(self, state: WebpState, conversion: Conversion,
                         back: list[str]) -> None:
        """Turn one declined delete from an APPLICABLE item into an advisory.

        The item stops counting towards the run's completion (the registry
        reads ``requires_apply``), and its detail says what actually
        happened — a file this run chose not to delete, and why — so the
        plan reads honestly instead of showing a purge that "did not
        apply".  The bytes are in the pre-action snapshot either way, which
        is what makes keeping them the safe half of the window.
        """
        item = state.item_index.get(("media.webp_purge", conversion.path_old))
        if item is None:
            return
        item.requires_apply = False
        item.detail = (
            f"KEPT, not deleted: a live editor's save re-introduced a "
            f"reference to it between the rewrite and the purge "
            f"({', '.join(back)}). The conversion is live and its "
            f"references are rewritten; the reclaiming of these bytes waits "
            f"for an editor-free window — rerun the purge then")

    def _purge_kept_report(self, state: WebpState, plan: Plan) -> None:
        """One line naming every original the purge did not take.

        The count and the file list are the operator's to-do; the line also
        says plainly that the run did not fail and that the cache was
        purged, because a clean success and "we kept your originals" look
        alike in a terminal and are not the same thing.
        """
        if not state.purge_kept:
            return
        kept = sorted(state.purge_kept)
        log.warning(
            "webp-media: %d original(s) kept: a live editor's save "
            "re-introduced their references; the conversion is live and the "
            "cache was purged — rerun the purge in a quiet window", len(kept))
        plan.items.append(PlanItem(
            category="media.webp_purge_kept",
            target="editor-window",
            detail=(f"{len(kept)} original(s) kept: a live editor's save "
                    f"re-introduced their references; the conversion is live "
                    f"and the cache was purged — rerun the purge in a quiet "
                    f"window (their bytes are in the pre-action snapshot "
                    f"either way): {_sample(kept)}"),
            requires_apply=False,
        ))

    def _current_refs(self, ctx: "Ctx", source: "Source", stack: tuple,
                      state: WebpState) -> set[str]:
        """Every uploads reference the surfaces hold RIGHT NOW.

        The purge's re-read seam: the same read-only reference reader the
        plan used (the bridge's scan, or the dump) plus every stylesheet's
        CURRENT text on disk.  Never the plan's measurement of them — that
        is the snapshot a live editor's save invalidates.
        """
        _rows, values, held, _surfaces = self._read_rows(ctx, stack)
        refs: set[str] = set(held)
        for value in values.values():
            refs |= raster_refs(value)
        for path in sorted(state.css_text):
            try:
                text = source.read_bytes(path).decode("utf-8")
            except (WptError, OSError, UnicodeDecodeError):
                # An unreadable stylesheet is the unreadable-css gate: it
                # can only keep a file alive, so its planned reference set
                # is the conservative answer.
                refs |= set(state.css_refs.get(path, ()))
                continue
            refs |= scan_css_refs(text, path)
        return refs

    def _verify(self, ctx: "Ctx", stack: tuple, state: WebpState,
                mapping: dict[str, str], plan: Plan, cfg: WebpConfig) -> bool:
        """The mandatory proof.  Raises when the run must not report success."""
        source = stack[0]
        ok = True
        # 1. Every rewritten path exists on disk.  The sweep speaks in
        #    UPLOADS-RELATIVE paths — the bare-basename spelling is a
        #    database convention, never a path on disk.
        for path in _landed_twin_paths(state, mapping):
            try:
                present = source.exists(path)
            except (WptError, OSError) as exc:
                log.error("webp-media: cannot confirm %s (%s)", path, exc)
                present = False
            if not present:
                log.error("webp-media: the rewritten path %s does not exist — "
                          "every reference to it is broken", path)
                ok = False
        # 2. Every rewritten row, re-read, carries no stale reference.
        stale_tables: set[str] = set()
        for row in state.row_edits:
            if not state.row_refs.get(row.key, frozenset()) & set(mapping):
                continue
            stale: set[str] = set()
            for text in _row_texts_after(row, state):
                stale |= raster_refs(text) & set(mapping)
            if stale:
                log.error("webp-media: %s still references %s after the "
                          "rewrite", row.label, ", ".join(sorted(stale)))
                stale_tables.add(row.table)
            else:
                self._done(state, "db.webp_refs", row.table)
        ok = not stale_tables and ok
        # 3. Every rewritten CSS file re-reads byte-for-byte.
        for path, data in state.css_edits.items():
            try:
                stored = source.read_bytes(path)
            except (WptError, OSError) as exc:
                log.error("webp-media: %s cannot be re-read (%s)", path, exc)
                ok = False
                continue
            if stored != data:
                log.error("webp-media: %s does not match the rewritten bytes",
                          path)
                ok = False
                continue
            # The explicit stale-reference assertion on top of the byte
            # comparison: a stylesheet is the one surface whose references
            # can hide from a text scan, so it is re-scanned with the
            # url()-aware rule as well.
            stale = scan_css_refs(stored.decode("utf-8"), path) & set(mapping)
            if stale:
                log.error("webp-media: %s still references %s after the "
                          "rewrite", path, ", ".join(sorted(stale)))
                ok = False
        # 4. The live proof (ftp with a site URL).
        if state.walked and ctx.wp_url and stack[1] is not None:
            ok = self._verify_live(ctx, stack, state, mapping, plan,
                                   cfg) and ok
        if not ok:
            raise SourceError(
                "webp-media: the rewritten reference set did not verify (a "
                "rewritten path is missing on disk, a reference to an "
                "original survived, a stylesheet did not read back, or the "
                "live reference set did not move as a bijection) — the "
                "pre-action snapshot is the rollback"
            )
        return True

    def _verify_live(self, ctx: "Ctx", stack: tuple, state: WebpState,
                     mapping: dict[str, str], plan: Plan,
                     cfg: WebpConfig) -> bool:
        """The before/after proof over the captured page set, PAGE BY PAGE.

        Every page both crawls could read is compared against its OWN
        reference set under the rewrite's mapping: everything that
        disappeared is an old path, everything that appeared is a new one,
        nothing else moved.  A missing rewrite shows up as a surviving
        original on a page; a reference this action could not rewrite shows
        up as a path that appeared.  The two unions' cardinality is the
        operator's one-number sanity check.

        A page a fetch could not READ is excluded and reported, never
        counted: that is the observed failure (a host serving a JS
        bot-challenge to some client fingerprints turned three crawls of an
        unchanged site into 61, 78 and back refs, and the guard called the
        rewrite broken).  The only failures here are PROVABLE ones: a page
        both crawls read whose references did not move as the mapping says,
        or a rewritten path the site still references that answers 404/410.
        """
        session = stack[1]
        capture = _live_capture(session, ctx, cfg, Deadline.from_ctx(ctx))
        twins = {c.rel_old: c.rel_new for c in _landed_twins(state, mapping)}
        twin_new = set(twins.values())
        before, after = state.before_pages, capture.pages
        reasons = dict(state.before_unprovable)
        reasons.update(capture.unprovable)
        excluded = _excluded_urls(reasons, before, after)
        unusable = {url for urls in excluded.values() for url in urls}
        if not (set(before) | set(after)) - unusable:
            log.warning("webp-media: no page could be compared — the live "
                        "proof of the rewrite did NOT run; only the database, "
                        "the stylesheets and the on-disk twins stood behind "
                        "this run")
        ok = True
        before_union: set[str] = set()
        after_union: set[str] = set()
        for url in sorted(set(before) | set(after)):
            if url in unusable:
                continue
            expected = {twins.get(ref, ref) for ref in before[url]}
            before_union |= expected
            after_union |= after[url]
            if after[url] == expected:
                continue
            vanished = sorted(expected - after[url])
            appeared = sorted(after[url] - expected)
            if vanished:
                log.error("webp-media: %s: %d reference(s) disappeared that "
                          "were not converted (%s)", url, len(vanished),
                          _sample(vanished))
            if appeared:
                log.error("webp-media: %s: %d reference(s) appeared that are "
                          "not a converted twin (%s)", url, len(appeared),
                          _sample(appeared))
            ok = False
        if len(after_union) != len(before_union):
            log.error("webp-media: the live asset reference count changed "
                      "(%d before, %d after) — the rewrite is not a "
                      "bijection", len(before_union), len(after_union))
            ok = False
        unprovable_assets: dict[str, str] = {}
        for rel in sorted(after_union & twin_new):
            probe = _probe(session, _asset_url(ctx, rel),
                            ctx.settings.http.timeout_s, cfg)
            if not probe.proved:
                # an asset a challenge kept us from reading is the same
                # missing evidence a challenged page is, and lands in the
                # same bucket
                unprovable_assets[rel] = probe.reason
                continue
            if probe.status != 200:
                log.error("webp-media: %s is referenced by the rendered site "
                          "but does not resolve (HTTP %s)", rel, probe.status)
                ok = False
        for rel, reason in unprovable_assets.items():
            excluded.setdefault(_exclusion_kind(reason), []).append(rel)
        for kind, urls in sorted(excluded.items()):
            log.warning("webp-media: %d url(s) unprovable (%s); excluded from "
                        "the comparison — read after the rewrite: %s",
                        len(urls), kind, _sample(urls))
            plan.items.append(_unprovable_item(kind, urls,
                                               "read after the rewrite"))
        return ok


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def twin_name(rel: str) -> str:
    """The twin's uploads-relative name: same folder, ``.webp``."""
    head, _, name = rel.rpartition("/")
    stem, _, _ = name.rpartition(".")
    return f"{head}/{stem}.webp" if head else f"{stem}.webp"


def _sample(paths: list[str]) -> str:
    shown = ", ".join(paths[:_EXAMPLES])
    more = f" (+{len(paths) - _EXAMPLES} more)" if len(paths) > _EXAMPLES else ""
    return shown + more


def _require_purge_ack(ctx: "Ctx", cfg: WebpConfig) -> None:
    """Refuse a purge the operator has not acknowledged as a window.

    A live site's editors save pages during the day, and a save from a
    stale client re-introduces the ORIGINAL filename in ``post_content``
    between the rewrite and the purge.  The purge then deletes the file
    that reference resolves to: a broken image, plus a reference that
    permanently protects bytes that are already gone.  No tool can observe
    "nobody is editing right now" — the operator can, so the operator says
    it out loud, once, before anything is converted or deleted.

    Checked in the plan phase too, so a dry run says the same thing before
    the (expensive) candidate scan rather than after it.
    """
    if not cfg.purge_originals or ctx.extra.get(_PURGE_ACK):
        return
    raise SourceError(
        f"--purge-originals is refused without {_PURGE_ACK_FLAG}: deleting "
        "the originals is a WINDOWED operation — a page saved from a stale "
        "editor between the rewrite and the purge re-introduces the original "
        "filename, and the purge would then delete the file that reference "
        "resolves to (a broken image, and a reference that permanently "
        "protects bytes that are already gone). Run the conversion alone — "
        "the originals are kept by default — and purge later, inside an "
        f"editor-free window, passing {_PURGE_ACK_FLAG} to say the window is "
        "real."
    )


def _estimate_split(conversions: list[Conversion]) -> list[tuple[str, int, int]]:
    """``(label, files, reclaimable bytes)`` per source format, then ALL.

    The all-files total comes LAST and is the plan's own number; the split
    in front of it is what tells the operator where the saving actually is
    (a PNG-heavy set is dominated by a re-encode whose lossiness is their
    call, a JPEG-heavy set is not).

    ONE row per FORMAT, and the label names the extensions the row
    actually holds: ``.jpg`` and ``.jpeg`` are the same format, so they
    share a row, but a site holding both spellings used to print two rows
    both labelled "JPEG" with no way to tell them apart [D1].  A row that
    exists therefore always says which files it is counting.
    """
    rows: dict[str, list] = {}          # title -> [files, saved, {suffixes}]
    for conversion in conversions:
        suffix = suffix_of(conversion.rel_old)
        title = _FORMAT_TITLES.get(suffix, suffix.upper())
        row = rows.setdefault(title, [0, 0, set()])
        row[0] += 1
        row[1] += conversion.saving
        row[2].add(suffix)
    out = [
        (f"{title} ({', '.join('.' + s for s in sorted(row[2]))})", row[0], row[1])
        for title, row in sorted(
            rows.items(), key=lambda item: (min(item[1][2]) not in _FORMAT_TITLES,
                                            min(item[1][2])))
    ]
    out.append(("ALL FILES", len(conversions),
                sum(c.saving for c in conversions)))
    return out


def _stale_after_purge(state: WebpState, refs: set[str],
                       deleted: set[str]) -> set[str]:
    """The re-read references that now point at a deleted original."""
    out: set[str] = set()
    for ref in refs:
        if ref in deleted:
            out.add(ref)
        elif "/" not in ref and _unique_owner(state, ref) in deleted:
            out.add(ref)
    return out


def _uploads_inventory(source: "Source",
                       deadline: Deadline | None = None) -> dict[str, int]:
    """``webroot path -> size`` for EVERY file under uploads.

    Not just the rasters: a ``.webp`` twin that already exists is the
    ``twin-exists`` skip, and a same-named ``.png`` is the
    ``twin-collision`` skip — both are only visible if the inventory holds
    the non-raster siblings too.  Walking the media-extension allowlist here
    would hide exactly the two cases a conversion must refuse.
    """
    inventory: dict[str, int] = {}
    for entry in bounded_walk(source, deadline, "webp uploads inventory"):
        if not entry.is_dir and entry.path.startswith(_UPLOADS_PREFIX):
            inventory[entry.path] = entry.size
    return inventory


def _basename_index(inventory: dict[str, int]) -> dict[str, list[str]]:
    """``basename -> [uploads-relative paths]`` over the uploads tree."""
    index: dict[str, list[str]] = {}
    for path in inventory:
        if suffix_of(path) not in _RASTER_SUFFIXES:
            continue
        index.setdefault(path.rpartition("/")[2], []).append(
            path[len(_UPLOADS_PREFIX):])
    return index


def _rewrite_map(conversions: list[Conversion],
                 by_name: dict[str, list[str]]) -> dict[str, str]:
    """The ONE map every rewrite consumes: uploads path AND bare basename.

    WordPress stores the same file two ways — ``_wp_attached_file`` and a
    rendered ``src`` carry ``2023/10/photo.jpg``, while
    ``_wp_attachment_metadata``'s ``sizes[*].file`` carries the bare
    ``photo-150x150.jpg``.  Both spellings must resolve to the same twin or
    half the references break.  A basename is registered only when it is
    UNIQUE in the uploads tree: an ambiguous name is never rewritten,
    because the reference could equally mean another folder's file.
    """
    mapping: dict[str, str] = {}
    for conversion in conversions:
        mapping[conversion.rel_old] = conversion.rel_new
        name = conversion.rel_old.rpartition("/")[2]
        if len(by_name.get(name, ())) == 1:
            mapping[name] = conversion.rel_new.rpartition("/")[2]
    return mapping


def _resolve_references(covered: dict[str, list[str]],
                        by_name: dict[str, list[str]], state: WebpState
                        ) -> set[str]:
    """The uploads-relative paths the reference set really points at.

    A full-path reference is itself.  A bare basename resolves through
    ``by_name``: exactly one match is the file, several matches mean the
    reference cannot say which folder it meant — every candidate is gated
    out (reported) rather than guessed, and no match at all is an absent
    reference.
    """
    targets: set[str] = set()
    for ref in covered:
        if "/" in ref:
            targets.add(ref)
            continue
        matches = by_name.get(ref, [])
        if len(matches) == 1:
            targets.add(matches[0])
        elif matches:
            state.gated.setdefault(_GATE_AMBIGUOUS, []).extend(matches)
        else:
            state.skips.setdefault(_SKIP_ABSENT, []).append(ref)
    return targets


def _css_scan(source: "Source",
              deadline: Deadline | None = None
              ) -> tuple[dict[str, str], set[str]]:
    """Scan the CSS trees: ``(decoded text per path, unreadable paths)``.

    A stylesheet that cannot be read or decoded is a REWRITABLE surface
    that could not be rewritten, so the images it references are gated out
    of the conversion (with the path named in the report) rather than
    silently broken.
    """
    texts: dict[str, str] = {}
    unreadable: set[str] = set()
    for entry in bounded_walk(source, deadline, "webp css scan"):
        if entry.is_dir or not entry.path.endswith(".css"):
            continue
        if not any(entry.path.startswith(tree) for tree in _CSS_TREES):
            continue
        try:
            texts[entry.path] = source.read_bytes(entry.path).decode("utf-8")
        except (WptError, OSError) as exc:
            log.warning("webp-media: cannot read %s (%s) — its url() "
                        "references are not rewritten", entry.path, exc)
            unreadable.add(entry.path)
        except UnicodeDecodeError:
            log.warning("webp-media: %s is not UTF-8 — not rewritten",
                        entry.path)
            unreadable.add(entry.path)
    return texts, unreadable


def _row_rewrites(rows: list[RowRef], values: dict[tuple[str, int], str],
                  mapping: dict[str, str]
                  ) -> tuple[list[RowRef], dict[tuple[str, int], str],
                             dict[tuple[str, int], tuple[str, ...]],
                             dict[tuple[str, int], frozenset[str]]]:
    """Every row whose text changes, with its rewritten form.

    A plain value is rewritten as text.  A serialized value is NOT
    rewritten client-side — its length prefixes make a text substitution a
    corruption — so its leaves are rewritten (the proof) and the LIVE write
    is the bridge's ``maybe_serialize`` round trip.
    """
    row_edits: list[RowRef] = []
    row_values: dict[tuple[str, int], str] = {}
    row_leaves: dict[tuple[str, int], tuple[str, ...]] = {}
    row_refs: dict[tuple[str, int], frozenset[str]] = {}
    for row in rows:
        value = values.get(row.key)
        if value is None:
            continue
        refs = raster_refs(value)
        if not refs & set(mapping):
            continue
        if looks_serialized(value):
            texts, bad = value_texts(value)
            if bad:
                continue
            rewritten = tuple(rewrite_text(text, mapping)[0] for text in texts)
            if not any(new != old for new, old in zip(rewritten, texts)):
                continue
            row_leaves[row.key] = rewritten
        else:
            new_value, changed = rewrite_text(value, mapping)
            if not changed:
                continue
            row_values[row.key] = new_value
        row_edits.append(row)
        row_refs[row.key] = frozenset(refs & set(mapping))
    return row_edits, row_values, row_leaves, row_refs


def _landed_twins(state: WebpState, mapping: dict[str, str]) -> list[Conversion]:
    """The conversions whose twin is on disk AND in the live map."""
    return [c for c in state.conversions if c.rel_old in mapping]


def _landed_twin_paths(state: WebpState, mapping: dict[str, str]) -> list[str]:
    """The webroot paths of those twins, in a stable order."""
    return sorted(c.path_new for c in _landed_twins(state, mapping))


def _unique_owner(state: WebpState, name: str) -> str:
    """The uploads-relative path a bare basename belongs to, or "".

    The plan only ever registers a basename that is unique in the uploads
    tree, so this lookup cannot be ambiguous; it is a lookup and not a
    search because guessing here would rewrite half the references towards
    the wrong year folder.
    """
    for conversion in state.conversions:
        if conversion.rel_old.rpartition("/")[2] == name:
            return conversion.rel_old
    return ""


def _row_texts_after(row: RowRef, state: WebpState) -> list[str]:
    """The text surfaces of a row AFTER the rewrite (its re-read value)."""
    value = state.row_values.get(row.key)
    if value is not None:
        texts, bad = value_texts(value)
        return [value] if bad else texts
    leaves = state.row_leaves.get(row.key)
    return list(leaves) if leaves is not None else []


def _asset_url(ctx: "Ctx", rel: str) -> str:
    """The site URL of one uploads-relative path."""
    return urljoin(ctx.wp_url.rstrip("/") + "/", _UPLOADS_PREFIX + rel)


def _log_plan_summary(cfg: WebpConfig, state: WebpState,
                      conversions: list[Conversion],
                      row_edits: list[RowRef]) -> None:
    log.info(
        "plan: %d image(s) to convert, %d DB row(s) and %d CSS file(s) to "
        "rewrite, %s reclaimable once the originals are purged",
        len(conversions), len(row_edits), len(state.css_text),
        human_bytes(sum(c.saving for c in conversions)),
    )
    if conversions:
        for label, files, saved in _estimate_split(conversions):
            log.info("plan: reclaimable by source format — %s: %d file(s), %s",
                     label, files, human_bytes(saved))
    for reason, paths in sorted(state.skips.items()):
        if paths:
            log.info("plan: %d item(s) not converted — %s", len(paths),
                     _SKIP_TITLES.get(reason, reason))
    for reason, paths in sorted(state.gated.items()):
        if paths:
            log.info("plan: %d referenced image(s) kept in their original "
                     "form — %s", len(paths), _GATE_NOTES.get(reason, reason))
    for surface in state.gated_surfaces:
        log.info("plan: %s is not a surface this dump lets the rewrite "
                 "address — its references are read as gated ones", surface)
    if conversions and not cfg.purge_originals:
        log.info("plan: the originals are KEPT — re-run with "
                 "--purge-originals to reclaim the space")


# The registry stores the decorated OBJECT and calls .plan/.apply on it, so
# the registered action is the instance (same as clean_files/trim_media:
# a bare class would be invoked with plan(ctx, stack) unbound and crash in
# run_action).
register_action("webp-media", applies=("ftp", "local"))(ImagesWebpAction())
