r"""Live site walker (W7a) — the read-only crawler that produces the audit's
live reference set (the engine behind ``wpt walk``).

``walk_site`` takes an ALREADY-PREPARED ``requests.Session`` — the
DNS-override-aware transport from ``wpt.dnsoverride.resolve_session`` when
``--override-ip`` is set, else a plain session; exactly the session the
audit runner's ``_remote_stack`` builds and the bridge / SiteProbe ride.
The walker NEVER constructs or closes a session.  It walks the live site
with GET requests only: forms are DETECTED and cataloged, NEVER submitted
(pinned by tests/test_walk.py, whose server records every method it sees).

WalkResult — the binding contract for the W7i audit wiring and the media
checks:

* ``live_refs`` — the live media reference set: uploads-RELATIVE POSIX
  paths ("2023/10/pic-300x233.jpg"), the exact shape ``wpt.audit.media``
  and the bridge's ``media_map`` action consume [L5].  URL -> ref
  conversion (applied to every asset URL extracted from rendered HTML and
  to every ``url()`` token of a fetched stylesheet):
  1. resolve the raw attribute value against the referencing document
     (``urljoin``: the page URL for HTML, the stylesheet URL for CSS
     ``url()``, honoring a ``<base href>`` when the page carries one);
  2. require scheme http/https and the SITE host — same hostname and
     effective explicit port (scheme is not host identity: an http link on
     an https site is the same site).  External CDNs with uploads-looking
     paths are NOT this site's files;
  3. collapse ``.``/``..`` path segments the way the server resolves them
     (traversal out of uploads can never fabricate a ref);
  4. keep the tail after the first ``/wp-content/uploads/`` path marker
     (subdirectory installs included); the bare uploads directory is not
     a file;
  5. percent-DECODE the tail — it must equal the on-disk name
     ("with%20space.jpg" -> "with space.jpg"); query and fragment were
     dropped in step 2.
  A ref is a REFERENCE, not a successful fetch: an ``<img src>`` counts
  even when its asset 404s or is never fetched at all.  ``url()`` refs
  require the stylesheet fetch to succeed, obviously [L11: backgrounds
  were referenced ONLY in elementor CSS under wp-content/uploads].
* ``pages`` — absolute same-site page URLs in BFS visit order, deduped,
  the homepage always first.  Every URL whose fetch was ATTEMPTED is
  listed — a page that 404s or times out stays (the visit happened;
  consumers such as ``security.https_redirect`` probe and skip failures
  themselves).
* ``forms`` — absolute form action URLs (``<form action>`` resolved
  against the page; a form with NO action records the document URL per
  HTML), deduped, SORTED, query strings KEPT (the query is part of a form
  target); external-host actions are cataloged too.  Never submitted.
* ``fetched`` — every HTTP request the walk made: sitemap probes + page
  navigations + stylesheet fetches, each unique normalized URL once.

Crawl budget semantics (``settings.walk`` — no statics in code):

* ``max_pages`` caps PAGES (navigations, homepage included; sitemap page
  collection is capped by the same number).  Asset fetches are NOT
  budgeted — a page may reference any number of stylesheets — but each
  unique URL is fetched exactly once.
* ``max_depth`` — the homepage is depth 1, sitemap-seeded pages are
  depth-1 entries, links from a depth-N page enqueue at depth N+1 and
  past ``max_depth`` nothing is enqueued.
* ``delay_s`` sleeps BETWEEN page navigations only (politeness applies to
  navigation, not asset fetches); tests run with 0.
* ``max_response_bytes`` bounds ONE response body — and it is a MEMORY
  bound, applied while the body streams, to every answer the crawler
  takes: a page, a sitemap, a stylesheet.  The body used to be read whole
  (``session.get`` with no stream and no size check), so a 300 MB page
  cost ~936 MB of RSS (measured, ~3.1x the body) and a 3 GB one ended the
  run with a ``MemoryError`` traceback on the operator's laptop.  An
  over-budget answer is REFUSED — one warning naming the URL and the
  bound, the page skipped — never truncated into a parser, because a
  half-parsed page's reference set is a measurement nobody can trust.  A
  refused page is recorded as a failed fetch (``pages`` keeps the
  attempt), exactly like any other unreachable page.

Sitemap strategy: ``{site}/sitemap.xml`` then ``{site}/sitemap_index.xml``
are probed first (WordPress core's ``wp-sitemap.xml`` is not probed in v1);
``<sitemap><loc>`` children (same-host only) are fetched and parsed too.
When NO sitemap yields a usable page — 404/timeout/invalid XML everywhere —
the walk degrades to a homepage+links crawl with exactly ONE warning;
individual failed probes are debug-logged.  The homepage is ALWAYS crawled.

Per HTML page (stdlib ``html.parser`` ONLY — no third-party parsers),
extract: ``img`` src + every srcset candidate (comma-split, descriptors
dropped); every ``link href`` — ``rel`` containing "stylesheet" and
same-host => the stylesheet is FETCHED and its ``url()`` tokens parsed
[L11]; other rels (icons, manifests, canonicals) are plain ref candidates;
``script src``; ``source`` src + srcset (``<picture>``/``<video>``/
``<audio>``); ``video``/``audio`` src + poster; inline ``<style>``
``url()`` tokens (SPEC "CSS url() from page"); ``a href`` — same-host HTML
targets enqueue as pages, and a same-host href resolving under
wp-content/uploads is ALSO a media reference (download links and gallery
lightbox anchors are real uses of the file; a keep-set miss would break
them after trim-media); ``form action``.

Failure semantics: a failed PAGE fetch (transport error or non-2xx) logs a
warning and the crawl continues; a failed ASSET (stylesheet) fetch is
silently skipped — its markup href still counts as a ref.  ``walk_site``
NEVER raises: site-level failures surface as a partial WalkResult plus
warning logs (and an unexpected internal error as one error log).

Structural crawler facts (NOT profile tunables, like media.py's uploads
prefix): the sitemap probe paths, the ``/wp-content/uploads/`` URL marker,
the content-type sniff ("html" substring; an absent type is assumed HTML),
the 2xx page-fetch window, and ``_NON_PAGE_EXTS`` — the heuristic that an
``a href`` whose last path segment ends in one of those extensions (media,
documents, archives, styles, scripts, feeds) is never enqueued as a page.
Page identity keeps the percent-ENCODED path (fetch-faithful: ``%2F`` is
a literal character to the server, not a separator) and drops query +
fragment; only live-ref TAILS are decoded.  Host identity ignores the
scheme and normalizes scheme-default ports.

Out of scope v1 (documented, deliberate): CSS ``@import`` chains; URLs
embedded in JavaScript/JSON; lazy-load ``data-src``/``data-srcset``
attributes; query-string pagination (queries are dropped, so ``?paged=2``
archives are not deep-crawled — pretty-permalink ``/page/2/`` works);
browser-driven interactions (v2 roadmap per SPEC).

W7i wiring (the caller contract): ``walk_site(session, ctx.wp_url,
ctx.settings.walk, ctx.settings.http.timeout_s)`` — the SAME session the
bridge and SiteProbe ride, the public site URL, the walk settings, and the
http timeout; then ``data.live_refs = result.live_refs`` and
``data.pages = result.pages``.
"""

from __future__ import annotations

import json
import re
import time
import xml.etree.ElementTree as ET
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, TYPE_CHECKING
from urllib.parse import unquote, urljoin, urlparse

import requests

from .config import redacted_site_label, redact_text
from .deadline import Deadline, DeadlineExceeded
from .log import get_logger
from .report import (report_protected_inputs,
                     report_protected_subtrees, write_report_files)
from .report import write_stdout
from .settings import WalkSettings
from .types import RunControl, StopRequested, WptError

if TYPE_CHECKING:
    from .cli import Ctx

__all__ = ["WalkResult", "walk_site", "run_walk"]

log = get_logger("walk")

# Structural WordPress / crawler facts — NOT profile tunables (see the
# module docstring; same convention as wpt/audit/media.py's uploads prefix).
_UPLOADS_MARKER = "/wp-content/uploads/"
_SITEMAP_PATHS = ("sitemap.xml", "sitemap_index.xml")
_HTML_MARKER = "html"

# An <a href> whose last path segment ends in one of these extensions is
# never enqueued as a page (binary/data files linkable from content).
_NON_PAGE_EXTS = frozenset({
    # images
    "jpg", "jpeg", "png", "gif", "webp", "avif", "svg", "ico", "bmp",
    "tif", "tiff", "heic", "heif",
    # styles / scripts / data
    "css", "js", "mjs", "json", "xml", "rss", "txt", "md", "csv", "map",
    # fonts
    "woff", "woff2", "ttf", "otf", "eot",
    # archives
    "zip", "gz", "tgz", "bz2", "xz", "tar", "rar", "7z",
    # documents
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "rtf",
    # audio / video
    "mp3", "mp4", "m4a", "m4v", "ogg", "oga", "ogv", "opus", "wav", "webm",
    "mov", "avi", "flv", "wmv", "mpg", "mpeg",
    # packages
    "apk", "exe", "dmg", "iso", "swf",
})

# url(...) tokens in stylesheet text: quoted forms keep their inner text
# verbatim; an unquoted token runs to the first ")" (CSS url-token grammar).
_CSS_URL_RE = re.compile(
    r"url\(\s*(?:'([^']*)'|\"([^\"]*)\"|([^)]*?))\s*\)", re.IGNORECASE
)


@dataclass
class WalkResult:
    """The walker's output — W7i wires ``live_refs`` -> AuditData.live_refs
    and ``pages`` -> AuditData.pages; trim-media/verify treat ``live_refs``
    as the live reference set.  Field semantics in the module docstring."""

    live_refs: set[str]
    pages: list[str]
    forms: list[str]
    fetched: int
    #: True when the walk did NOT cover the whole reachable site (stopped on
    #: its page budget / deadline with pages still queued, or aborted on an
    #: unexpected error). A partial result's reference set is incomplete, so
    #: consumers (verify) must not read an EMPTY partial set as "no media".
    partial: bool = False


# --------------------------------------------------------------- URL plumbing


def _collapse_dots(path: str) -> str:
    """Remove ``.``/``..`` segments the way a web server resolves a path
    (RFC 3986 remove_dot_segments, simplified); dot-free paths unchanged.
    A trailing dot segment resolves to a directory ("/a/b/.." -> "/a/")."""
    if "." not in path:
        return path or "/"
    out: list[str] = []
    for segment in path.split("/"):
        if segment == ".":
            continue
        if segment == "..":
            if len(out) > 1:  # never pop the leading "" (the root)
                out.pop()
            continue
        out.append(segment)
    collapsed = "/".join(out)
    if path.endswith(("/.", "/..")) and not collapsed.endswith("/"):
        collapsed += "/"
    return collapsed or "/"


def _normalize(base: str, raw: str, *, drop_query: bool = True) -> str | None:
    """Resolve ``raw`` against ``base`` into one canonical absolute URL.

    http/https only; fragment always dropped; query dropped unless
    ``drop_query`` is False (form targets keep their query); dot segments
    collapsed server-style; percent-encoding PRESERVED (page identity must
    fetch what the document referenced — decoding is the ref-tail rule's
    job, not the crawl URL's); userinfo stripped defensively.  None for
    non-http(s) or malformed results (javascript:, mailto:, bad ports...).
    """
    if not raw:
        return None
    try:
        parsed = urlparse(urljoin(base, raw.strip()))
        _ = parsed.port  # raises ValueError on a malformed explicit port
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    netloc = parsed.netloc.rpartition("@")[2]
    query = "" if drop_query else (f"?{parsed.query}" if parsed.query else "")
    return f"{parsed.scheme}://{netloc}{_collapse_dots(parsed.path)}{query}"


def _host_key(url: str) -> tuple[str, int | None] | None:
    """Host identity: (lowercased hostname, effective explicit port); None
    for non-http(s).  Scheme-default ports normalize to None; the scheme is
    NOT part of the key (an http:// link on an https site is the same site);
    explicit non-default ports must match exactly."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    hostname = parsed.hostname
    if not hostname:
        return None
    if port == (443 if parsed.scheme == "https" else 80):
        port = None
    return (hostname.lower(), port)


def _is_page_candidate(url: str) -> bool:
    """False when the URL's last path segment carries a known non-HTML
    extension (media/documents/archives/...) — such links enqueue nothing."""
    last = urlparse(url).path.rstrip("/").rsplit("/", 1)[-1]
    if "." not in last:
        return True
    return last.rsplit(".", 1)[-1].lower() not in _NON_PAGE_EXTS


def _is_html(response: requests.Response) -> bool:
    """Content-type sniff: text/html, application/xhtml+xml...; an absent
    content-type is optimistically treated as HTML."""
    content_type = response.headers.get("Content-Type", "").strip().lower()
    return _HTML_MARKER in content_type or not content_type


#: How many bytes a streamed body is pulled in at a time.  A STRUCTURAL
#: constant (the transfer granularity, like ``_DUMP_SENTINEL_TAIL_BYTES``):
#: it decides how often the bound below is consulted, never whether it
#: applies, so a profile knob here would only be a way to talk the check
#: out of stopping.
_BODY_CHUNK_BYTES = 65536


def _read_bounded(response: Any, max_bytes: int,
                  deadline: float | None = None) -> tuple[bytes | None, str]:
    """``(body, why)`` for one streamed answer: the bytes when the whole
    body fitted under ``max_bytes``, else ``None`` and the reason it was
    refused.

    Reads at most ``max_bytes + 1`` — one byte past the bound is what makes
    "over" decidable without downloading an unbounded body — and closes the
    response either way (a streamed response nobody drains holds the
    connection open).  The bound is enforced ON THE STREAM, so a 3 GB
    answer costs ``max_bytes + 1`` of memory, not 3 GB.

    ``deadline`` is an ABSOLUTE ``time.monotonic()`` instant (the earlier
    of the run budget and this request's own timeout).  It is consulted
    before every chunk: requests' per-read timeout re-arms on every
    trickled byte, so a body drip could otherwise hold one page for the
    whole run.  A session double has no socket to bound, so the check is
    the only owner there.

    The two refusals are told apart because they are different facts: an
    answer over the bound (a runaway origin) and a body that stopped
    arriving (a dead connection or an exhausted budget) are not the same
    diagnosis, and the caller says which one it was.
    """
    parts: list[bytes] = []
    total = 0
    try:
        for chunk in response.iter_content(chunk_size=_BODY_CHUNK_BYTES):
            if deadline is not None and time.monotonic() >= deadline:
                return None, ("the body read exceeded its absolute "
                              "deadline; the answer arrived too slowly")
            if not chunk:
                continue
            total += len(chunk)
            if total > max_bytes:
                return None, (f"an over-sized response: it answered more than "
                              f"walk.max_response_bytes ({max_bytes} bytes)")
            parts.append(chunk)
    except requests.RequestException as exc:
        if deadline is not None and time.monotonic() >= deadline:
            return None, ("the body read exceeded its absolute deadline "
                          f"({type(exc).__name__})")
        return None, f"the body could not be read ({exc})"
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()
    return b"".join(parts), ""


def _with_body(response: Any, body: bytes) -> Any:
    """``response`` with its already-bounded body attached.

    The body was consumed from the stream, so requests' own lazy ``.text``
    / ``.content`` have nothing left to read; filling the two attributes
    they read (``_content`` + ``_content_consumed``) is the same thing
    requests itself does after ``iter_content``, and it is what lets the
    page layer keep using ``response.text`` unchanged — one body, one
    accessor, no second parsing path.
    """
    try:
        response._content = body
        response._content_consumed = True
    except AttributeError:       # a test double with __slots__
        log.debug("response double carries no content attribute; the "
                  "crawler reads status/headers only")
    return response


def _css_url_tokens(css_text: str) -> list[str]:
    """url() tokens from stylesheet text: surrounding quotes/whitespace
    stripped; data: URIs included (the host filter drops them later)."""
    tokens: list[str] = []
    for match in _CSS_URL_RE.finditer(css_text):
        value = next((g for g in match.groups() if g is not None), "").strip()
        if value:
            tokens.append(value)
    return tokens


def _sitemap_entries(xml_bytes: bytes) -> tuple[list[str], list[str]]:
    """(page locs, child-sitemap locs) from sitemap XML, namespace-agnostic:
    a ``<sitemap><loc>`` is a child sitemap to fetch; a ``<url><loc>`` is a
    page.  Bytes in (the declaration's encoding is honored); comment/PI
    nodes are skipped (their .tag is not a string)."""
    root = ET.fromstring(xml_bytes)
    pages: list[str] = []
    children: list[str] = []
    for element in root.iter():
        if not isinstance(element.tag, str):
            continue
        kind = element.tag.rsplit("}", 1)[-1].lower()
        if kind not in ("url", "sitemap"):
            continue
        for child in element:
            if not isinstance(child.tag, str):
                continue
            if child.tag.rsplit("}", 1)[-1].lower() == "loc":
                loc = (child.text or "").strip()
                if loc:
                    (children if kind == "sitemap" else pages).append(loc)
    return pages, children


# ------------------------------------------------------------------ extraction


@dataclass
class _PageExtract:
    """Everything one parsed page yields — every URL already absolute and
    normalized (policies are applied by the crawler, not the parser)."""

    doc_url: str  # the page's own URL (an actionless form's target)
    assets: list[str] = field(default_factory=list)  # ref candidates
    css: list[str] = field(default_factory=list)      # stylesheet URLs (fetched)
    links: list[str] = field(default_factory=list)   # <a href> candidates
    forms: list[str] = field(default_factory=list)   # absolute action URLs


class _PageParser(HTMLParser):
    """One HTML page -> one :class:`_PageExtract`.

    Resolves every URL against the current base — the document URL, or the
    first ``<base href>`` (HTML's first-wins rule).  Style blocks are
    collected as text and their ``url()`` tokens resolved with the base
    current at the block's end (a ``<base>`` tag cannot appear inside
    style content, so this is the block's only base).  Self-closing forms
    ride the default handle_startendtag -> handle_starttag path.
    """

    def __init__(self, doc_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.extract = _PageExtract(doc_url=doc_url)
        self._base = doc_url
        self._base_fixed = False
        self._in_style = False
        self._style_chunks: list[str] = []

    def _abs(self, raw: str | None, *, keep_query: bool = False) -> str | None:
        if not raw:
            return None
        return _normalize(self._base, raw, drop_query=not keep_query)

    def _asset(self, raw: str | None) -> None:
        url = self._abs(raw)
        if url:
            self.extract.assets.append(url)

    def _srcset(self, raw: str | None) -> None:
        """srcset = comma-separated "URL [descriptor...]" entries; the URL
        is the first whitespace-separated token, descriptors are dropped."""
        if not raw:
            return
        for candidate in raw.split(","):
            tokens = candidate.split()
            if tokens:
                self._asset(tokens[0])

    def handle_starttag(self, tag: str, attrs) -> None:
        get: dict[str, str | None] = {}
        for name, value in attrs:
            get.setdefault(name, value)  # first occurrence wins (HTML)
        if tag == "base" and not self._base_fixed and get.get("href"):
            fixed = self._abs(get["href"])
            if fixed:
                self._base = fixed
                self._base_fixed = True
        elif tag == "img":
            self._asset(get.get("src"))
            self._srcset(get.get("srcset"))
        elif tag == "link":
            url = self._abs(get.get("href"))
            if not url:
                return
            if "stylesheet" in (get.get("rel") or "").lower().split():
                self.extract.css.append(url)
            else:
                self.extract.assets.append(url)
        elif tag == "script":
            self._asset(get.get("src"))
        elif tag == "source":
            self._asset(get.get("src"))
            self._srcset(get.get("srcset"))
        elif tag in ("video", "audio"):
            self._asset(get.get("src"))
            self._asset(get.get("poster"))
        elif tag == "a":
            url = self._abs(get.get("href"))
            if url:
                self.extract.links.append(url)
        elif tag == "form":
            action = get.get("action")
            url = self._abs(action, keep_query=True) if action \
                else self._abs(self.extract.doc_url, keep_query=True)
            if url:
                self.extract.forms.append(url)
        elif tag == "style":
            self._in_style = True
            self._style_chunks = []

    def handle_endtag(self, tag: str) -> None:
        if tag != "style" or not self._in_style:
            return
        self._in_style = False
        for token in _css_url_tokens("".join(self._style_chunks)):
            self._asset(token)
        self._style_chunks = []

    def handle_data(self, data: str) -> None:
        if self._in_style:
            self._style_chunks.append(data)


# --------------------------------------------------------------------- crawler


class _Crawler:
    """One walk's mutable state: fetch dedup, BFS queue with depths, and
    the four WalkResult accumulators (exposed as plain attributes)."""

    def __init__(self, session: requests.Session, site: str,
                 settings: WalkSettings, timeout_s: int,
                 deadline: Any = None) -> None:
        self._session = session
        self._site = (site or "").rstrip("/")
        self._settings = settings
        self._timeout_s = timeout_s
        # the run's self-bounding budget (wpt.deadline.Deadline, None =
        # unbounded): checked once per page visit AND in every transport
        # read, so a crawling origin ends the walk as a partial result
        # instead of grinding
        self._deadline = deadline
        #: The run budget expired during a transport read or the sitemap
        #: worklist.  The crawl must STOP (not keep treating the deadline
        #: as a page-level failure) and the result is PARTIAL.
        self.deadline_hit = False
        self._deadline_warned = False
        self._site_key = _host_key(self._site)
        self.pages: list[str] = []
        self.refs: set[str] = set()
        self.forms: set[str] = set()
        self.fetched = 0
        #: Site-level health: a failed homepage or a failed sitemap seed
        #: means the crawl did not see the whole reachable site even when
        #: no page was left in the queue.  Consumers treat that as a
        #: PARTIAL reference set, never as "nothing is referenced".
        self.successful_pages = 0
        self.homepage_failed = False
        self.seed_failed = False
        self._seed_urls: set[str] = set()
        #: Pages whose body was refused by the memory bound.  The fetch was
        #: answered but intentionally not parsed; that is a page-level skip
        #: (the crawl continues and other pages prove the site healthy),
        #: not the site-level FAILURE a 500/transport error is.
        self._body_refused: set[str] = set()
        self._fetched_urls: set[str] = set()
        self._scheduled: set[str] = set()
        self._queue: deque[tuple[str, int]] = deque()

    # -- transport ---------------------------------------------------------

    def _note_deadline(self, context: str) -> None:
        """Stop the walk on the RUN budget with ONE warning.

        The budget may expire inside a header/body read (a drip) or in the
        sitemap worklist, both outside ``run``'s per-page check.  This is
        the crawler's own stop signal — never a page-level failure, which
        would keep walking the remaining queue.
        """
        self.deadline_hit = True
        if not self._deadline_warned:
            self._deadline_warned = True
            log.warning(
                "walk stopped: run deadline exceeded at %s; the reference "
                "set is PARTIAL (%d pages, %d refs so far)",
                context, len(self.pages), len(self.refs))

    def _fetch(self, url: str) -> requests.Response | None:
        """One GET through the CALLER'S session; None on failure or when the
        URL was already fetched (every unique URL is fetched once).  The
        attempt is counted either way; transport errors are debug-logged —
        the page layer decides what deserves a warning.

        The body is STREAMED against ``walk.max_response_bytes`` and the
        response is refused whole when it is over the bound (one warning
        naming the URL and the bound).  The previous shape
        (``session.get(url, timeout=...)``) read whatever the origin sent:
        a 300 MB answer cost ~936 MB of RSS (measured, ~3.1x the body) and
        a 3 GB one ended the run with a ``MemoryError`` traceback.  The
        bound is read from the same WalkSettings the traversal already
        takes, so a profile or ``--set`` moves it and nothing else can.

        BOTH the header read and every body chunk ride ONE absolute bound:
        ``min(run deadline, now + http.timeout_s)``.  requests' timeout is
        per-READ, so a server dripping one byte below it reset the clock
        forever (8.96 s of headers under a 1 s budget).  A real session is
        driven through ``php_probe.get_bounded`` (the shared non-blocking
        absolute-deadline transport); a session double keeps its
        synchronous ``get`` contract.  When the RUN budget is the binding
        bound, the crawl stops as PARTIAL rather than calling that page
        unhealthy and continuing.
        """
        if url in self._fetched_urls:
            return None
        self._fetched_urls.add(url)
        self.fetched += 1
        started = time.monotonic()
        absolute = started + float(self._timeout_s)
        if self._deadline is not None:
            absolute = min(absolute, self._deadline.at)
            if absolute <= started:
                self._note_deadline("page fetch")
                return None
        run_binding = (self._deadline is not None
                       and self._deadline.at <= absolute + 1e-9)
        try:
            from .php_probe import get_bounded
            response = get_bounded(
                self._session, url, timeout_s=self._timeout_s,
                deadline=absolute, allow_redirects=True)
        except requests.RequestException as exc:
            log.debug("fetch failed: %s: %s", url, exc)
            if run_binding and self._deadline is not None \
                    and self._deadline.expired:
                self._note_deadline("page fetch")
            return None
        body, why = _read_bounded(response,
                                  self._settings.max_response_bytes,
                                  deadline=absolute)
        if body is None:
            if run_binding and self._deadline is not None \
                    and self._deadline.expired:
                self._note_deadline("page fetch")
                return None
            self._body_refused.add(url)
            log.warning("walk skipped %s: %s — the answer is discarded, not "
                        "truncated", url, why)
            return None
        return _with_body(response, body)

    # -- ref conversion ------------------------------------------------------

    def _add_ref(self, url: str) -> None:
        """Record a live ref when ``url`` is a same-host wp-content/uploads
        file (conversion rules in the module docstring).  Input URLs arrive
        already normalized, so only the tail extraction runs here."""
        if self._site_key is None or _host_key(url) != self._site_key:
            return
        path = urlparse(url).path
        marker_at = path.find(_UPLOADS_MARKER)
        if marker_at < 0:
            return
        tail = path[marker_at + len(_UPLOADS_MARKER):]
        if tail:
            self.refs.add(unquote(tail))

    # -- pages ----------------------------------------------------------------

    def _enqueue(self, url: str, depth: int) -> None:
        if depth > self._settings.max_depth or url in self._scheduled:
            return
        if not _is_page_candidate(url):
            return
        self._scheduled.add(url)
        self._queue.append((url, depth))

    def _visit(self, url: str, depth: int) -> None:
        if self.pages:
            time.sleep(self._settings.delay_s)  # between page navigations only
        self.pages.append(url)  # the ATTEMPT is the visit (failures stay listed)
        response = self._fetch(url)
        ok = response is not None and 200 <= response.status_code < 300
        if not ok:
            if response is None:
                log.warning("page fetch failed: %s", url)
            else:
                log.warning("page fetch failed: HTTP %s at %s",
                            response.status_code, url)
            if url not in self._body_refused:
                if url == f"{self._site}/":
                    self.homepage_failed = True
                if url in self._seed_urls:
                    self.seed_failed = True
            return
        self.successful_pages += 1
        if not _is_html(response):
            return  # fetched fine but not a document — nothing to extract
        parser = _PageParser(response.url or url)
        parser.feed(response.text)
        parser.close()
        extract = parser.extract
        for asset in extract.assets:
            self._add_ref(asset)
        for css_url in extract.css:
            self._add_ref(css_url)  # an uploads stylesheet is itself a media file
            if self._site_key is not None and _host_key(css_url) == self._site_key:
                self._fetch_css(css_url)
        for link in extract.links:
            if self._site_key is None or _host_key(link) != self._site_key:
                continue  # external pages: never crawled, never refs
            self._add_ref(link)
            self._enqueue(link, depth + 1)
        self.forms.update(extract.forms)

    def _fetch_css(self, url: str) -> None:
        """Fetch one same-site stylesheet and record its ``url()`` refs
        [L11].  Failure is silent (debug in _fetch): the stylesheet's own
        markup href still counts as a ref; its ``url()`` refs are lost."""
        response = self._fetch(url)
        if response is None or not 200 <= response.status_code < 300:
            return
        for token in _css_url_tokens(response.text):
            resolved = _normalize(url, token)
            if resolved:
                self._add_ref(resolved)

    # -- sitemaps ---------------------------------------------------------------

    def _sitemap_pages(self) -> list[str]:
        """Page URLs from sitemap.xml + sitemap_index.xml (plus same-host
        ``<sitemap><loc>`` children), deduped, capped at max_pages.  Emits
        exactly ONE warning when no sitemap yields a usable page — the
        pinned degrade to a homepage+links crawl.

        The worklist is bounded by the SAME ``walk.max_pages`` setting as
        pages AND by the run budget at the TOP of every iteration.  An
        index naming 200k children used to queue/fetch them all before the
        first page (and before any deadline check); the homepage is now
        reached even when a hostile index is larger than the budget.
        """
        collected: list[str] = []
        queued_children: set[str] = set()
        worklist = [f"{self._site}/{name}" for name in _SITEMAP_PATHS]
        fetches = 0
        while worklist:
            if self._deadline is not None:
                try:
                    self._deadline.check("sitemap")
                except DeadlineExceeded:
                    self._note_deadline("sitemap")
                    break
            if fetches >= self._settings.max_pages:
                log.debug(
                    "sitemap worklist capped at walk.max_pages (%d); "
                    "remaining child sitemaps are not fetched",
                    self._settings.max_pages)
                break
            url = worklist.pop(0)
            fetches += 1
            response = self._fetch(url)
            if self.deadline_hit:
                break
            if response is None or not 200 <= response.status_code < 300:
                continue  # 404 / timeout / 5xx: this sitemap is unusable
            try:
                page_locs, child_locs = _sitemap_entries(response.content)
            except ET.ParseError:
                log.debug("sitemap is not parseable XML: %s", url)
                continue
            for loc in child_locs:
                child = _normalize(url, loc, drop_query=False)
                if (child and child not in queued_children
                        and self._site_key is not None
                        and _host_key(child) == self._site_key):
                    if len(queued_children) >= self._settings.max_pages:
                        # The worklist ceiling is a count of sitemap URLs,
                        # not a second interpretation of max_pages: a
                        # sitemap index cannot queue more fetches than the
                        # walk's own page budget.
                        break
                    queued_children.add(child)
                    worklist.append(child)
            for loc in page_locs:
                page = _normalize(url, loc)
                if page:
                    collected.append(page)
        unique = list(dict.fromkeys(collected))
        if not unique:
            log.warning(
                "no usable sitemap at %s (tried %s); crawling the homepage "
                "and same-host links only",
                self._site or "<no site url>", ", ".join(_SITEMAP_PATHS),
            )
        return unique[: self._settings.max_pages]

    # -- run ----------------------------------------------------------------------

    def run(self) -> None:
        seeds = self._sitemap_pages()
        if not self.deadline_hit:
            self._enqueue(f"{self._site}/", 1)  # the homepage is always crawled
            for seed in seeds:
                self._enqueue(seed, 1)      # sitemap entries: depth-1 entry pages
                self._seed_urls.add(seed)
        budget = self._settings.max_pages
        while self._queue and len(self.pages) < budget:
            if self.deadline_hit:
                break
            if self._deadline is not None:
                try:
                    self._deadline.check("site walk")
                except DeadlineExceeded:
                    self._note_deadline("site walk")
                    break
            url, depth = self._queue.popleft()
            self._visit(url, depth)
        log.info(
            "walk complete: pages=%d live_refs=%d forms=%d fetches=%d",
            len(self.pages), len(self.refs), len(self.forms), self.fetched,
        )


def walk_site(session: requests.Session, site: str,
              settings: WalkSettings, timeout_s: int = 30,
              deadline: Any = None) -> WalkResult:
    """Walk the live site read-only and return its live reference set.

    ``session`` is the caller's prepared, DNS-override-aware Session (the
    same transport the bridge and SiteProbe use) — never built or closed
    here; every request carries ``timeout_s``; only GETs are issued (forms
    are detected, never submitted).  Site-level failures never raise: the
    result is partial plus warning logs.  A cooperative stop/SIGTERM is
    NOT a site-level failure: it re-raises so the command ends rc 1 with
    the shared failure report instead of returning a successful-looking
    partial walk.  The run deadline is deliberately different (SPEC run
    deadlines): the crawler's own per-page check stops the walk with ONE
    warning and a PARTIAL reference set (``partial=True``) that keeps what
    was measured before the budget expired — the walk's never-raise audit
    contract.  See the module docstring for the full WalkResult contract
    and the W7i wiring recipe.
    """
    crawler = _Crawler(session, site, settings, timeout_s, deadline)
    partial = False
    try:
        crawler.run()
    except (StopRequested, DeadlineExceeded):
        raise
    except Exception as exc:  # noqa: BLE001 — binding contract: never raise
        partial = True
        log.error("walk aborted by an unexpected error (partial result "
                  "kept): %s", exc, exc_info=True)
    if crawler._queue:
        # pages still queued after the loop: stopped on the page budget or
        # the deadline, so the reference set is incomplete.
        partial = True
    if crawler.deadline_hit:
        # The run budget expired inside a transport read/sitemap worklist.
        # The queue may even be empty because the crawl stopped before it
        # was filled; that is still a partial measurement.
        partial = True
    if (crawler.successful_pages == 0 or crawler.homepage_failed
            or crawler.seed_failed):
        # A site-level failure (500 homepage, dead seed) is a PARTIAL
        # measurement even when the queue drained: the pages that failed
        # could reference media the empty set cannot prove unused.  This is
        # the same fact verify/trim-media consume; without it a 500 site
        # read as a complete "no references" crawl and trim-media could
        # delete every upload.
        partial = True
    return WalkResult(
        live_refs=crawler.refs,
        pages=crawler.pages,
        forms=sorted(crawler.forms),
        fetched=crawler.fetched,
        partial=partial,
    )


def run_walk(ctx: Ctx) -> int:
    """Run the ``wpt walk`` command; 0 on a completed walk, 1 on refusal
    or operational failure — never raises, never a traceback.

    The client-facing crawler surface (SPEC §"walk (client-facing
    crawler"): local mode REFUSES (an offline zip has no URLs to fetch);
    ftp mode builds the remote stack through the ONE construction seam
    ``wpt.audit.remote_stack`` — imported FUNCTION-LEVEL, exactly like
    ``wpt.actions.registry._stack``, never at module top: ``wpt.audit``
    imports THIS module at its top (``from ..walk import walk_site``), so
    a module-top ``from .audit import remote_stack`` here would be
    circular.  The test seams follow from that: tests monkeypatch
    ``wpt.audit.remote_stack`` (the stack) and ``wpt.walk.walk_site``
    (a canned WalkResult — the direct in-module call below resolves
    through this module's globals at call time).

    The walk needs NO bridge calls — the bridge is never deployed — but
    the whole stack is torn down through the shared owner in the
    ``finally`` (bridge, source AND session; ``Bridge.destroy`` is
    idempotent, a no-op when never deployed).
    ``walk_site`` never raises for SITE-level failures (already warnings
    plus a partial result) but DOES re-raise a cooperative stop/SIGTERM.
    The run deadline ends the walk ITSELF as a partial result (SPEC: the
    walk keeps its partial reference set), so that path reports rc 0.  A
    re-raised stop reaching the run-level ``(WptError, OSError)`` catch is
    logged at error, rc 1, and the shared
    failure report pair is written (a failed run may not leave the absence
    of a report indistinguishable from "walked nothing").

    Output: the markdown report from :func:`_render` — ALWAYS written to
    stdout through the shared ``wpt.report.write_stdout`` sink, exactly
    like ``wpt.verify`` and the audit's ``_emit``: the report IS the
    command's stdout surface and, with ``ctx.report_path`` set, written there
    (utf-8) PLUS its JSON twin from :func:`_render_json` at
    ``report_path.with_suffix(".json")`` — the md + json pair exactly
    like the audit's and restore's ``_emit``; stdout is unchanged.  One
    info summary is always logged.  rc 0: a walk is read-only, and
    site-level failures are already warnings plus a partial result.  A
    teardown stop after a successful report REPLACES that report with the
    shared failure artifact, so rc 1 can never sit beside a file that
    claims the walk completed.
    """
    if ctx.mode == "local":
        reason = ("walk requires a live site: ftp mode only "
                  "(local mode has no URLs to fetch)")
        log.error("%s", reason)
        _write_failure(ctx, reason)
        return 1
    source = session = bridge = None
    rc = 1
    deadline = Deadline.from_ctx(ctx)
    try:
        if deadline is not None:
            deadline.check("walk setup")
        from .audit import remote_stack

        source, session, bridge = remote_stack(ctx)
        walked = walk_site(session, ctx.wp_url or "",
                           ctx.settings.walk,
                           ctx.settings.http.timeout_s,
                           deadline=deadline)
        site = redacted_site_label(ctx.wp_url or ctx.source)
        markdown = _render(site, walked)
        if ctx.report_path is not None:
            write_report_files(
                ctx.report_path, markdown, _render_json(site, walked),
                protected_paths=report_protected_inputs(ctx),
                protected_subtrees=report_protected_subtrees(ctx))
        write_stdout(markdown)
        log.info("walk: %d pages, %d live refs, %d forms, %d fetches",
                 len(walked.pages), len(walked.live_refs),
                 len(walked.forms), walked.fetched)
        rc = 0
    except RunControl as exc:
        reason = f"walk stopped: {exc}"
        log.error("%s", redact_text(reason))
        _write_failure(ctx, reason)
        rc = 1
    except (WptError, OSError) as exc:
        reason = f"walk failed: {exc}"
        log.error("walk failed: %s", exc)
        _write_failure(ctx, reason)
        rc = 1
    finally:
        from .teardown import teardown_stack

        stop = teardown_stack((source, session, bridge), "walk")
        if stop is not None:
            reason = f"walk: teardown stopped: {stop}"
            log.error("%s", reason)
            if rc == 0:
                # The success report was already written; it would now be a
                # lie beside rc 1.  Replace it with the shared failure pair.
                _write_failure(ctx, reason)
            rc = 1
    return rc


def _write_failure(ctx: Ctx, reason: str) -> None:
    """Best-effort shared failure report pair for every walk failure path."""
    from .actions.registry import write_failure_report

    try:
        write_failure_report(ctx, "walk", reason, title="wpt walk")
    except (Exception, RunControl) as exc:  # noqa: BLE001 — reporting must not mask rc
        log.warning("walk: could not write the failure report: %s",
                    redact_text(str(exc)))


def _render(site: str, walked: WalkResult) -> str:
    """The walk markdown report: a header, one summary line, then the
    Pages / Live media references / Forms sections — each only when
    non-empty (pages in visit order, refs sorted, forms already sorted
    by the walker).  Its machine-readable twin is :func:`_render_json`."""
    lines = [
        f"# wpt walk — {site}",
        "",
        f"Crawled {len(walked.pages)} pages, found {len(walked.live_refs)} "
        f"live media references and {len(walked.forms)} forms "
        f"({walked.fetched} HTTP fetches).",
        "",
    ]
    if walked.pages:
        lines.append("## Pages")
        lines.append("")
        lines.extend(f"- {redact_text(url)}" for url in walked.pages)
        lines.append("")
    if walked.live_refs:
        lines.append("## Live media references")
        lines.append("")
        lines.extend(f"- {redact_text(ref)}"
                     for ref in sorted(walked.live_refs))
        lines.append("")
    if walked.forms:
        lines.append("## Forms")
        lines.append("")
        lines.extend(f"- {redact_text(url)}" for url in walked.forms)
        lines.append("")
    return "\n".join(lines)


def _render_json(site: str, walked: WalkResult) -> str:
    """The machine-readable twin of :func:`_render`: the site, the pages
    in VISIT order, the SORTED live media reference set, the forms (the
    walker already sorted them) and the fetch count — walk's OWN schema,
    not the audit's AuditReport/findings shape.  Formatted exactly like
    :func:`wpt.report.render_json` (utf-8, sorted keys, indent 2) so the
    report surfaces stay consistent."""
    return json.dumps(
        {
            "site": site,
            "pages": [redact_text(url) for url in walked.pages],
            "live_refs": [redact_text(ref) for ref in sorted(walked.live_refs)],
            "forms": [redact_text(url) for url in walked.forms],
            "fetched": walked.fetched,
        },
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    )
