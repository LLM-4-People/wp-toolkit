"""Update audit checks (W6g): wp.org version comparison, per docs/research/R3.md.

Three checks registered under ``updates.*`` with ``applies=("ftp", "local")``
and the uniform signature ``func(data: AuditData, settings: Settings) ->
list[Finding]``.  The wp.org endpoints, cache location/TTL, User-Agent and
transport bounds are the ``wp_org`` settings section; the payload shapes and
the WordPress version/locale/slug character classes are protocol invariants.

wp.org wire (R3, live-verified — followed EXACTLY, not re-derived):

* core — GET ``core/version-check/1.7/?locale=en_US``; latest =
  ``offers[0].current`` (never any other offer; R3).  ``en_US`` is
  DELIBERATE for the update checks even though the integrity check is
  now locale-aware: the offers list is locale-filtered, so a localized
  request can surface a non-latest offer at [0] and misreport "latest".
* plugins — ONE bulk POST to ``plugins/update-check/1.1/`` (R3: the 1.0
  endpoint is obsolete PHP-serialize).  Form fields are JSON-encoded:
  ``plugins={"plugins":{"<folder>/<file>.php":{"Name":...,"Version":...}},
  "active":[...]}`` — keyed by the catalog's plugin FILE path — plus
  ``translations=[]``, ``locale=["en_US"]``, ``all=true``.  ``Name`` is
  the catalog name when known, else the folder slug (R3's fallback).
* themes — ONE bulk POST to ``themes/update-check/1.1/`` with
  ``themes={"active":<slug>,"themes":{<slug>:{"Name":<slug>}}}`` (keyed
  by slug, NOT file path), ``translations=[]``, ``locale=["en_US"]``.
* buckets — response ``plugins``/``themes`` = update available;
  ``no_update`` = current; a key ABSENT from both = premium / not on
  wp.org — always SILENT, never a finding.  PHP serializes empty maps as
  ``[]``, so a bucket may arrive as ``[]`` or ``{}``: both are the empty
  map (live-verified; handled in _bucket).
* info/1.2 is NEVER fetched: the bulk update buckets already carry
  ``new_version`` plus ``url`` (the wp.org page) and ``package`` (the
  zip) — live-verified this session; R3 lists ``package`` and the live
  response adds ``url`` — so the per-slug detail link the SPEC permits
  is taken from the bulk response itself (SPEC: info/1.2 "only for
  detail links" — the bulk response has them).

Release zip (WpOrgApi.fetch_core_release_zip — the source the UPCOMING
heal-core action restores tampered core files from, NOT a check
request): the official WP release zip for a version lives at
``downloads.wordpress.org/release/wordpress-<V>.zip`` — the JSON
host's wp.org sibling for release artifacts, still never the live
site.  Live-verified this session (7.1.1): HTTP 200
``application/zip``, ~37 MB, every entry nested under ``wordpress/``
(the extraction prefix heal-core strips), and file md5s taken from
the zip match api.wordpress.org's ``core/checksums/1.0`` (locale
en_US — the integrity check's comparison map) EXACTLY — the zip is
the SAME distribution those checksums describe, so a core file
restored from it verifies.  LOCALIZED builds (the localized migration
lesson): a non-en_US locale's build lives at
``https://<dash-subdomain>.wordpress.org/wordpress-<V>-<locale>.zip``
(fr_CA → fr-ca.wordpress.org; live-verified for 6.6 across fr_CA,
de_DE, de_DE_formal, pt_BR, zh_CN, en_CA) and is the distribution the
``core/checksums/1.0?locale=<locale>`` map describes — it differs from
the en_US build in exactly wp-includes/version.php (its
``$wp_local_package`` line) plus the bundled wp-content/languages
files.  :func:`core_release_zip_url` is the ONE locale→URL resolver;
both the version and the locale interpolate into the URL and the
cache filename and are validated against their character classes (a
bad either raises WptError — refuse nonsense loudly, never guess).  The
raw bytes cache at ``wp-release-<version>[-<locale>].zip`` under the
same configured cache TTL (a zip is tens of MB: an audit + heal in one
session downloads it once); a fetched payload is validated BEFORE caching
or returning — zip magic, a real central directory, at least one
``wordpress/``-prefixed entry — so a corrupt download is a failed
fetch, never a returned lie.

Theme zip (WpOrgApi.fetch_theme_zip — the integrity check's
theme-skew cross-check source [L12]): the official release zip for a
wp.org theme version lives at
``downloads.wordpress.org/theme/<slug>.<version>.zip``, every entry
nested under ``<slug>/`` (live-verified, twentytwentyfive 1.5) — the
SAME release machinery as the core zip (validated prefix, raw-bytes
cache at ``theme-<slug>-<version>.zip``, one-warning None), with the
slug additionally held to ``[A-Za-z0-9_-]``.

Theme version caveat (the deviation AuditData forces, resolved by live
test): W6b maps only the theme SLUG (``data.template``); the installed
theme version is not in AuditData (the bridge sends no theme version
either).  Live-verified this session: ``themes/update-check/1.1/``
tolerates an absent ``Version`` key and answers normally — the theme
lands in the update bucket with its ``new_version``.  Per the W6g design
rule ("if the API tolerates a missing version, send without"), the
theme is sent WITHOUT a Version key.  Consequence, documented honestly:
the finding's installed-version slot reads "installed version unknown" —
for a wp.org-distributed active theme the check reports the version
wp.org offers (currency cannot be CONFIRMED from the gathered facts,
and wp-admin shows the truth); a premium/custom theme is absent from
both buckets and stays silent.  A W6b follow-up that maps a theme
version would let this check compare versions exactly like plugins.

``data.template`` is WP's ``template`` option: for a CHILD theme that is
the PARENT theme slug (the bridge also sends ``stylesheet``, which W6b
does not map) — so on child-theme sites this check audits the parent
theme.  Reported to the coordinator; this module follows its binding
design (``data.template``).

User-Agent (R3 guidance: identify yourself): every request carries the
configured ``wp_org.user_agent_template`` (default ``wpt/{version}``), whose
``{version}`` comes from the installed ``wpt`` package version via
importlib.metadata (``wpt/dev`` for an uninstalled source checkout).

Cache: responses cached under ``wp_org.cache_dir`` relative to the CWD,
one file per request named ``sha256(url + canonical payload).json``
(_cache_key); release zips are the one non-JSON payload — their RAW
bytes cache at ``wp-release-<version>.zip`` (json.dumps cannot hold a
zip) under the same discipline.  Freshness is mtime-based with the
configured ``wp_org.cache_ttl_s`` (shipped 3600 seconds — one owner in
the settings section, not a module constant).  Missing/stale => fetch
+ write back; a corrupt
or unwritable cache file never breaks the audit (read failure = miss;
write failure is logged at debug and the fetched answer is still
returned).  A failed fetch falls back to a present-but-stale cache
entry with ONE warning; with nothing cached the request layer returns
None after ONE warning and every check degrades to [] — availability is
never guessed.

Degrade contract (local mode stays fully offline): the checks reuse
ONLY ``probe.session`` + ``probe.timeout_s`` (never probe.get/post —
those are for the LIVE SITE; only wp.org endpoints are ever requested:
api.wordpress.org for the JSON APIs, downloads.wordpress.org for
release zips).
``data.probe is None`` (always in local mode) => [] for all three; plus
per-check data guards: ``wp_version`` None => core silent, empty
``plugin_catalog`` => plugins silent, ``template`` None/empty => themes
silent.  Version-less plugin catalog entries are skipped (never sent);
if none remain, no request is made.  A ``requests.RequestException``,
a non-200 status, a non-JSON body or an unusable payload shape => []
with one warning (never a guess).

Determinism: update buckets are iterated sorted, the plugins payload
map is built sorted (canonical form => a stable cache key for the same
plugin set), nothing mutates ``data``, and logging is warning/debug
only (cache hits and fetches at debug; one warning per failed request).
Presentation limit 8 detail lines before the "(+N more)" marker — fixed
by this check contract, not a tunable.  No secrets exist on this path
(public wp.org endpoints; payloads are never logged).
"""

from __future__ import annotations

import functools
import hashlib
import importlib.metadata
import io
import json
import time
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable

import requests

from .data import AuditData
from .registry import register_check
from ..config import redact_text
from ..log import get_logger
from ..php_probe import get_bounded, post_bounded
from ..settings import (
    Settings,
    WpOrgSettings,
    WP_LOCALE_RE,
    WP_RELEASE_VERSION_RE,
    WP_THEME_SLUG_RE,
)
from ..types import DeadlineExceeded, Finding, RunControl, StopRequested, WptError

log = get_logger("audit.updates")


@contextmanager
def owned_session(session: requests.Session, owned: bool):
    """Yield ``session``; close it on exit ONLY when this caller owns it.

    The wp.org transport is shared: in ftp mode the audit stack owns the
    session and must never be closed by a check, while local mode creates a
    fresh plain session per call (``_transport``/``_wporg_transport``) and
    that session leaked its pool.  Callers pass ``owned`` from the exact
    same predicate that created it (``data.probe is None`` in the audit,
    ``stack[2] is None`` in the actions).
    """
    primary: BaseException | None = None
    try:
        yield session
    except BaseException as exc:
        # Remember the body's verdict: a cooperative stop raised by close()
        # must never MASK an in-flight failure (a WptError primary became a
        # DeadlineExceeded from teardown).  On a clean body the stop is the
        # run-ending event and is re-raised.
        primary = exc
        raise
    finally:
        if owned:
            try:
                session.close()
            except RunControl:
                if primary is None:
                    raise
                log.warning(
                    "wp.org session close raised a run-control signal while "
                    "a primary failure was in flight; the primary is kept")
            except Exception as exc:  # noqa: BLE001 — teardown is best-effort
                log.warning("wp.org session close failed: %s",
                            redact_text(str(exc)))


#: Direct ``WpOrgApi`` construction (tests/embedders) uses this instance;
#: production call sites pass ``Settings.wp_org``.  The dataclass remains
#: the owner of every default.
DEFAULT_WP_ORG = WpOrgSettings()

#: Test-only redirects.  Production resolves every value from
#: ``WpOrgSettings``; the test suite sets these to point at a fake server or
#: a temporary cache.  They are None in a production process.
_CACHE_DIR: Path | None = None
_CORE_CHECK_URL: str | None = None
_PLUGINS_CHECK_URL: str | None = None
_THEMES_CHECK_URL: str | None = None
_CORE_RELEASE_ZIP_URL: str | None = None
_LOCALIZED_RELEASE_ZIP_URL: str | None = None
_THEME_ZIP_URL: str | None = None
_WPORG_JSON_MAX_BYTES: int | None = None
_UNSET = object()


def core_release_zip_url(version: str, locale: str,
                         config: WpOrgSettings | None = None) -> str:
    """The official release-zip URL for ``version`` at ``locale``.

    The locale→URL resolver (one authoritative owner): the configured
    ``default_locale`` uses the unlocalized release host; every other locale
    lives at its dash-subdomain on wordpress.org (fr_CA ->
    https://fr-ca.wordpress.org/wordpress-7.1-fr_CA.zip — live-verified).
    Raises WptError for an invalid version or locale before any URL is built
    — refuse nonsense loudly, never guess.
    """
    cfg = config or DEFAULT_WP_ORG
    if (not isinstance(version, str)
            or not WP_RELEASE_VERSION_RE.fullmatch(version)):
        raise WptError(
            f"refusing WordPress release-zip URL for invalid version "
            f"{version!r}: expected a non-empty [A-Za-z0-9.-] version string"
        )
    if (not isinstance(locale, str)
            or not WP_LOCALE_RE.fullmatch(locale)):
        raise WptError(
            f"refusing WordPress release-zip URL for invalid locale "
            f"{locale!r}: expected a non-empty [A-Za-z0-9_] locale string"
        )
    if locale == cfg.default_locale:
        template = _CORE_RELEASE_ZIP_URL or cfg.core_release_zip_url
        return template.format(version=version)
    template = _LOCALIZED_RELEASE_ZIP_URL or cfg.localized_release_zip_url
    return template.format(
        subdomain=locale.replace("_", "-").lower(),
        version=version,
        locale=locale,
    )


#: Presentation limit fixed by this check contract (not a tunable):
#: max detail lines before the "(+N more)" truncation marker.
_DETAIL_LINES = 8


def _package_version() -> str:
    """The installed wpt version; "dev" for an uninstalled source checkout.

    R3 asks for an identifying User-Agent; importlib.metadata is the
    stdlib owner of "what version is deployed" (pyproject name "wpt").
    PackageNotFoundError is the not-installed case (a source checkout
    run without pip install) — "wpt/dev", never a guess about a version.
    """
    try:
        return importlib.metadata.version("wpt")
    except importlib.metadata.PackageNotFoundError:
        return "dev"

# ------------------------------------------------------------- cache helpers


def _cache_key(url: str, form: dict[str, str] | None) -> str:
    """One cache filename per request: sha256(url + canonical payload).

    The canonical form is ``json.dumps({"url":..., "form":...},
    sort_keys=True)`` — deterministic for a given (URL, form-fields) pair
    (the bulk plugins payload itself is built sorted, so the same plugin
    set always maps to the same key).  ``form=None`` (a GET) canonically
    serializes as an empty map.
    """
    canonical = json.dumps({"url": url, "form": form or {}}, sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _read_cache(path: Path) -> tuple[Any, float] | None:
    """(payload, mtime) for a present, parsable cache file; else None.

    Any read/parse failure (absent, torn by an interrupted write,
    corrupt) reads as a miss: the file is refetched and rewritten, never
    trusted half-read.
    """
    try:
        mtime = path.stat().st_mtime
        with path.open(encoding="utf-8") as fh:
            return json.load(fh), mtime
    except (OSError, ValueError):
        return None


def _valid_release_zip(payload: Any,
                      prefix: str | None = None) -> bool:
    """True when ``payload`` is a plausible official wp.org zip whose
    entries nest under ``prefix``.

    Three gates: the zip magic ``PK\\x03\\x04`` at byte 0, a real zip
    central directory (zipfile opens it), and at least one entry under
    the expected extraction prefix — the official CORE release zips
    nest EVERYTHING under ``wordpress/`` (live-verified; the extraction
    prefix the heal-core action strips), the official THEME release
    zips under ``<slug>/`` (live-verified, twentytwentyfive 1.5).
    Anything else is a corrupt download: a failed fetch, never a
    returned lie.
    """
    if not isinstance(payload, bytes) or not payload.startswith(b"PK\x03\x04"):
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as zf:
            names = zf.namelist()
    except (OSError, ValueError, EOFError, zipfile.BadZipFile):
        return False
    prefix = prefix if prefix is not None else DEFAULT_WP_ORG.release_zip_prefix
    return any(name.startswith(prefix) for name in names)


def _read_zip_cache(path: Path,
                   prefix: str | None = None) -> tuple[bytes, float] | None:
    """(payload, mtime) for a present, VALID cached zip; else None.

    The binary twin of ``_read_cache``: raw bytes instead of parsed
    JSON, with the _valid_release_zip gates standing in for json.load —
    an absent, torn or corrupt entry reads as a miss (refetched and
    rewritten, never trusted half-read), so a corrupt cached zip is
    never served, fresh or stale.
    """
    try:
        mtime = path.stat().st_mtime
        with path.open(mode="rb") as fh:
            payload = fh.read()
    except OSError:
        return None
    prefix = prefix if prefix is not None else DEFAULT_WP_ORG.release_zip_prefix
    if not _valid_release_zip(payload, prefix):
        return None
    return payload, mtime


def _bucket(payload: Any, key: str) -> dict[str, dict]:
    """One response bucket as a plain dict — [] counts as the empty map.

    R3 (live-confirmed): PHP serializes empty maps as ``[]`` rather than
    ``{}``, so an update/no_update bucket arrives as ``[]`` when empty.
    A bucket that is absent, a list, or any non-dict is the empty map;
    entries whose value is not a dict are dropped, never raised over.
    """
    if not isinstance(payload, dict):
        return {}
    raw = payload.get(key)
    if not isinstance(raw, dict):
        return {}
    return {
        k: v for k, v in raw.items() if isinstance(k, str) and isinstance(v, dict)
    }


# ------------------------------------------------------------- the wp.org API


class WpOrgApi:
    """One place that knows the wp.org endpoints, the identifying
    User-Agent, the request payloads and the response cache (R3).

    Built per check from the probe's transport — ``WpOrgApi(probe.session,
    probe.timeout_s, config=settings.wp_org)`` — and NEVER used against the
    live site.  The ``wp_org`` settings section owns the endpoints
    (api.wordpress.org for the JSON APIs, downloads.wordpress.org for the
    official release zips), the cache location/TTL, the User-Agent and the
    transport bounds.  JSON answers cache as parsed payloads in sha256-keyed
    files; release zips cache as raw bytes at ``wp-release-<version>.zip``
    (the JSON cache cannot hold a zip) — the same TTL and stale-reuse
    discipline, ONE warning per failed fetch.  A method returns None
    only when no answer could be obtained (after exactly one warning);
    callers then degrade to silence — never guessing availability.
    """

    def __init__(self, session: requests.Session, timeout_s: int,
                 deadline: float | None = None, *,
                 config: WpOrgSettings | None = None) -> None:
        self._session = session
        self._timeout_s = timeout_s
        self._config = config or DEFAULT_WP_ORG
        self._cache_dir = _CACHE_DIR or Path(self._config.cache_dir)
        self._user_agent = self._config.user_agent_template.format(
            version=_package_version())
        self._json_max_bytes = (
            _WPORG_JSON_MAX_BYTES
            if _WPORG_JSON_MAX_BYTES is not None
            else self._config.json_max_bytes
        )
        #: Absolute ``time.monotonic()`` bound shared by every GET this
        #: instance makes (doctor's run budget).  None = per-request
        #: ``now + timeout_s``.  A header drip must not outlive either.
        self._deadline = deadline

    def _expired(self) -> bool:
        """Has the run budget been spent?  (None = unbounded.)"""
        return (self._deadline is not None
                and time.monotonic() >= self._deadline)

    def _raise_if_expired(self) -> None:
        """A spent run budget is a stop, never "wp.org unavailable".

        ``get_bounded``/``read_bounded`` enforce the absolute deadline as a
        transport exception; without this check the failure path served a
        stale cache entry (or returned None) and the command could finish
        rc 0 after its budget.  ONE predicate for the JSON and zip twins.
        """
        if self._expired():
            raise DeadlineExceeded(
                "run deadline exceeded at a wp.org request")

    def _transport_deadline(self) -> float:
        """The absolute instant ONE wp.org request may run until.

        TWO independent bounds: the run's own budget (a spent run is a
        stop) and the per-request ``timeout_s`` (a slow API is only an
        unavailable answer).  Passing the run budget alone let a request
        run for an hour under a long ``--deadline``; passing the timeout
        alone lost the run bound.  The transport gets their minimum; the
        failure path below still consults :meth:`_expired` so only a
        SPENT RUN raises, while a per-request timeout degrades to a stale
        cache entry or None.
        """
        per_request = time.monotonic() + self._timeout_s
        if self._deadline is None:
            return per_request
        return min(self._deadline, per_request)

    # -- transport + cache ---------------------------------------------

    def _request_json(
        self, method: str, url: str, form: dict[str, str] | None
    ) -> Any | None:
        """One wp.org request through the 1h cache; the parsed JSON or None.

        A fresh cache entry is served without any network (debug log).
        A missing/stale entry is fetched; a 200-with-JSON answer is
        written back to the cache (write failures are non-fatal, logged
        at debug — the audit proceeds uncached).  A failed fetch (network
        error, non-200, non-JSON) logs ONE warning and falls back to a
        present-but-stale cache entry when one exists (with that same
        warning naming the fallback); with nothing cached it returns None
        and the caller degrades.  The probe timeout is always passed so a
        slow API never blocks the audit.
        """
        path = self._cache_dir / (_cache_key(url, form) + ".json")
        cached = _read_cache(path)
        if cached is not None and time.time() - cached[1] < self._config.cache_ttl_s:
            log.debug("wp.org cache hit: %s", url)
            if self._deadline is not None and time.monotonic() >= self._deadline:
                raise DeadlineExceeded(
                    "run deadline exceeded at a wp.org request")
            return cached[0]
        timeout_s = self._timeout_s
        if self._deadline is not None and time.monotonic() >= self._deadline:
            raise DeadlineExceeded(
                "run deadline exceeded at a wp.org request")
        try:
            if method == "GET":
                response = get_bounded(
                    self._session, url,
                    timeout_s=timeout_s, deadline=self._transport_deadline(),
                    headers={"User-Agent": self._user_agent},
                    allow_redirects=True,
                    # wp.org is a PUBLIC, CA-signed endpoint: verification
                    # is never inherited from a site session that runs with
                    # http.verify_tls=false (--override-ip).  Checksums and
                    # release zips prove core identity; an unauthenticated
                    # fetch would let a MITM supply both.
                    verify=True,
                )
            else:
                response = post_bounded(
                    self._session, url, form=form or {},
                    timeout_s=timeout_s, deadline=self._transport_deadline(),
                    headers={"User-Agent": self._user_agent},
                    verify=True,
                )
        except (StopRequested, DeadlineExceeded):
            # SIGTERM/--deadline ends the run; it is never an ordinary
            # "wp.org unavailable" degrade (which would let the audit
            # finish rc 0 after the stop).
            raise
        except (requests.RequestException, WptError) as exc:
            return self._failed(url, path, exc)
        if response.status_code != 200:
            return self._failed(url, path, f"HTTP {response.status_code}")
        reader = getattr(response, "read_bounded", None)
        try:
            if callable(reader):
                # The REAL transport's body: a structural wp.org-sized
                # bound, never the probe answer's 256 KiB excerpt limit.
                payload = json.loads(reader(self._json_max_bytes))
            else:
                # A test/embedder double keeps its synchronous contract.
                payload = response.json()
        except (StopRequested, DeadlineExceeded):
            raise
        except (requests.RequestException, WptError) as exc:
            # A truncated/chunked body (ChunkedEncodingError,
            # ContentDecodingError) is a transport failure like any other:
            # one warning + stale-cache degrade, never a check_failed.
            return self._failed(url, path, exc)
        except (ValueError, RecursionError, MemoryError) as exc:
            # json.JSONDecodeError subclasses ValueError; a deeply nested
            # answer raises RecursionError, which is not one.
            return self._failed(url, path, exc)
        # A body that completed only after the budget is still a spent run:
        # never cache it and never hand it back as a success.
        self._raise_if_expired()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload), encoding="utf-8")
        except OSError:
            log.debug("wp.org cache write failed: %s", path)
        log.debug("wp.org fetched: %s", url)
        return payload

    def _failed(
        self,
        url: str,
        path: Path,
        reason: Any,
        reader: Callable[[Path], tuple[Any, float] | None] = _read_cache,
    ) -> Any | None:
        """ONE warning for a failed fetch; a stale cache entry answers.

        ``reader`` is the cache-entry reader for the fetch's kind —
        ``_read_cache`` (parsed JSON, _request_json) or ``_read_zip_cache``
        (validated release-zip bytes, _fetch_zip); an entry the reader
        cannot return (absent, torn, corrupt — anything unusable) counts
        as nothing cached.
        """
        # The FIRST rule of the failure path: a spent budget is the run's
        # verdict, never a stale answer.  Every failure shape funnels here,
        # so the check cannot be forgotten by one of them (a 500, a body
        # failure or a non-200 after the deadline used to serve stale cache
        # and let the command finish rc 0).
        self._raise_if_expired()
        cached = reader(path)
        if cached is not None:
            log.warning(
                "wp.org request for %s failed (%s); reusing stale cached response",
                url, reason,
            )
            return cached[0]
        log.warning(
            "wp.org request for %s failed (%s); no cached response to fall back on",
            url, reason,
        )
        return None

    def _fetch_zip(self, url: str, cache_path: Path,
                   prefix: str | None = None) -> bytes | None:
        """One binary wp.org fetch through the 1h cache; the bytes or None.

        The byte twin of ``_request_json`` for release artifacts (core
        releases AND theme releases): raw bytes instead of a parsed
        JSON payload (the JSON cache cannot hold a zip), a caller-named
        cache file instead of the sha256 key, and the _valid_release_zip
        gates (against the caller's extraction ``prefix``) instead of
        the JSON parse.  The discipline is identical: a fresh VALID
        entry serves without any network (debug log; an absent, torn or
        corrupt entry reads as a miss — refetched, never trusted
        half-read); a fetched payload is validated BEFORE it is cached
        or returned and written back (write failures non-fatal, debug);
        a failed fetch — network error, non-200, or a payload failing
        validation: a corrupt download is a failed fetch, never a
        returned lie — logs ONE warning and falls back to a
        present-but-stale VALID entry (that same warning naming the
        fallback); with nothing valid cached it returns None and the
        caller degrades.  The probe timeout is always passed so a slow
        download never blocks.
        """
        prefix = prefix if prefix is not None else self._config.release_zip_prefix
        cached = _read_zip_cache(cache_path, prefix)
        if cached is not None and time.time() - cached[1] < self._config.cache_ttl_s:
            log.debug("wp.org cache hit: %s", url)
            if self._deadline is not None and time.monotonic() >= self._deadline:
                raise DeadlineExceeded(
                    "run deadline exceeded at a wp.org request")
            return cached[0]
        stale_reader = functools.partial(_read_zip_cache, prefix=prefix)
        if self._deadline is not None and time.monotonic() >= self._deadline:
            raise DeadlineExceeded(
                "run deadline exceeded at a wp.org request")
        try:
            response = get_bounded(
                self._session, url,
                timeout_s=self._timeout_s, deadline=self._transport_deadline(),
                headers={"User-Agent": self._user_agent},
                allow_redirects=True,
                # Same rule as the JSON transport: a release zip is code.
                verify=True,
            )
        except (StopRequested, DeadlineExceeded):
            raise
        except (requests.RequestException, WptError) as exc:
            return self._failed(url, cache_path, exc, reader=stale_reader)
        if response.status_code != 200:
            return self._failed(
                url, cache_path, f"HTTP {response.status_code}",
                reader=stale_reader,
            )
        reader = getattr(response, "read_bounded", None)
        try:
            payload = (reader(self._config.release_zip_max_bytes)
                       if callable(reader) else response.content)
        except (StopRequested, DeadlineExceeded):
            raise
        except (WptError, requests.RequestException) as exc:
            return self._failed(url, cache_path, exc, reader=stale_reader)
        if not _valid_release_zip(payload, prefix):
            return self._failed(
                url, cache_path, "not a valid WordPress release zip",
                reader=stale_reader,
            )
        # Same absolute-stop rule as the JSON twin: a body that landed after
        # the budget is never cached or returned as success.
        self._raise_if_expired()
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_bytes(payload)
        except OSError:
            log.debug("wp.org cache write failed: %s", cache_path)
        log.debug("wp.org fetched: %s", url)
        return payload

    # -- endpoints (R3; the release zip: live-verified, not R3) --------

    def latest_core_version(self) -> str | None:
        """``offers[0].current`` from core/version-check/1.7/ (R3).

        Only offers[0] is the latest (the ~26 offers include branch
        security releases; a localized offer may sit at [0] for other
        locales — en_US here).  None when no answer or an unusable shape.
        """
        offers = self.core_version_offers()
        if not offers:
            return None
        current = offers[0]["current"]
        if not current:
            log.warning("wp.org core version-check payload unusable: empty offers[0].current")
            return None
        return current

    def core_version_offers(self) -> list[dict[str, Any]] | None:
        """EVERY core version-check offer, normalized; None when unusable.

        The full ``offers`` list of ``core/version-check/1.7/`` — the ONE
        fetch ``latest_core_version`` and the update-core action's
        target-selection both read, so a run never asks wp.org the same
        question twice and the "is this version even offered?" decision
        can never be made against a different answer than the "what are
        its PHP/MySQL floors?" one.

        Each offer is ``{"version", "current", "response", "php_version",
        "mysql_version"}``: the version strings are kept as wp.org
        spells them (a pre-release offer carries its suffix —
        ``6.5-RC1`` — and re-shaping it here would invent a version
        nobody offered), and an offer whose ``version``/``current`` is
        unusable is DROPPED rather than half-filled.  ``php_version`` /
        ``mysql_version`` are the floors THAT release declares; both are
        strings (``"7.4"``, ``"5.5.5"``) and are never coerced to a
        number here — a version compare is a decision the caller states
        with its own policy, not a silent float().

        None (after exactly ONE warning, and only when there WAS an
        answer to be unusable) when the request failed with nothing
        cached — the transport already logged that one, and a second
        "unusable" line would blame the payload for a network fault —
        or the payload carries no usable offers list; an empty list is
        likewise None — a zero-offer answer is a refusal, never "no
        update needed".
        """
        url = (_CORE_CHECK_URL
               or self._config.core_version_check_url.format(
                   locale=self._config.default_locale))
        payload = self._request_json("GET", url, None)
        if payload is None:
            return None   # the transport logged the ONE warning
        if not isinstance(payload, dict) or not isinstance(
                payload.get("offers"), list):
            log.warning("wp.org core version-check payload unusable: "
                        "no offers list")
            return None
        offers: list[dict[str, Any]] = []
        for raw in payload["offers"]:
            if not isinstance(raw, dict):
                continue
            version = raw.get("version")
            current = raw.get("current")
            offers.append({
                "version": version if isinstance(version, str) and version else "",
                "current": current if isinstance(current, str) and current else "",
                "response": (raw["response"]
                             if isinstance(raw.get("response"), str) else ""),
                "php_version": (raw["php_version"]
                                if isinstance(raw.get("php_version"), str) else ""),
                "mysql_version": (raw["mysql_version"]
                                  if isinstance(raw.get("mysql_version"), str) else ""),
            })
        return offers or None

    def bulk_plugin_check(
        self, plugins: dict[str, dict[str, Any]]
    ) -> tuple[dict[str, dict], dict[str, dict]] | None:
        """ONE bulk POST (plugins/update-check/1.1/); (updates, current).

        ``plugins`` is the catalog subset to check: plugin FILE path ->
        {"name", "version", "active"}; the caller filters entries with an
        empty version (they are never sent).  The payload map is built
        sorted so the same plugin set yields one canonical cache key.
        The buckets are normalized dicts (_bucket: [] == {}); keys absent
        from both (premium / not on wp.org) are simply missing from both
        return values.  None when no answer could be obtained.
        """
        form = {
            "plugins": json.dumps(
                {
                    "plugins": {
                        file: {
                            "Name": meta.get("name") or file.split("/")[0],
                            "Version": meta.get("version", ""),
                        }
                        for file, meta in sorted(plugins.items())
                    },
                    "active": sorted(
                        file
                        for file, meta in plugins.items()
                        if meta.get("active")
                    ),
                },
                sort_keys=True,
            ),
            "translations": "[]",
            "locale": json.dumps([self._config.default_locale]),
            "all": "true",
        }
        url = (_PLUGINS_CHECK_URL
               or self._config.plugins_update_check_url)
        payload = self._request_json("POST", url, form)
        if payload is None:
            return None
        return _bucket(payload, "plugins"), _bucket(payload, "no_update")

    def bulk_theme_check(
        self, themes: dict[str, str]
    ) -> tuple[dict[str, dict], dict[str, dict]] | None:
        """ONE bulk POST (themes/update-check/1.1/) for the active themes.

        ``themes`` maps slug -> installed style.css version (real versions
        only — a slug with an unreadable version is NOT sent, so the check
        never guesses).  Per R3's verified snippet: "active" is the first
        slug, every entry carries Name + Version.  Returns the (updates,
        current) bucket pair, or None when no answer.
        """
        form = {
            "themes": json.dumps(
                {"active": next(iter(themes), ""),
                 "themes": {slug: {"Name": slug, "Version": version}
                            for slug, version in themes.items()}},
                sort_keys=True,
            ),
            "translations": "[]",
            "locale": json.dumps([self._config.default_locale]),
        }
        url = (_THEMES_CHECK_URL
               or self._config.themes_update_check_url)
        payload = self._request_json("POST", url, form)
        if payload is None:
            return None
        return _bucket(payload, "themes"), _bucket(payload, "no_update")

    def fetch_core_release_zip(self, version: str,
                               locale: str | object = _UNSET) -> bytes | None:
        """The official WordPress release zip for ``version``@``locale``.

        The heal-core source: the zip at :func:`core_release_zip_url`'s
        URL is the SAME distribution api.wordpress.org's
        ``core/checksums/1.0?locale=<locale>`` map describes (en_US AND
        localized builds — live-verified for fr_CA 6.6: every zip entry
        md5 equals the map answer), so a core file restored from it
        satisfies those checksums EXACTLY; the zip nests everything
        under ``wordpress/``, the extraction prefix the heal-core action
        strips.  ``locale`` defaults to ``wp_org.default_locale`` (the
        unlocalized release host); a localized build (e.g. fr_CA) lives at
        its dash-subdomain (fr-ca.wordpress.org) and differs from the en_US
        build in exactly wp-includes/version.php (its ``$wp_local_package``
        line) plus the bundled wp-content/languages files.

        ``version`` and ``locale`` both interpolate into the URL AND the
        cache filename, so both are validated against their character
        classes: anything else raises WptError — refuse nonsense
        loudly, never guess (existence is never guessed either: a
        well-formed but nonexistent version@locale is a plain 404
        through the failed-fetch discipline).

        Cost: a release zip is tens of MB, so the raw bytes cache at
        ``<wp_org.cache_dir>/wp-release-<version>[-<locale>].zip`` (the locale
        joins the name for every non-default build — one entry per
        distribution) under the shared cache TTL — an audit + heal in one
        session downloads it once.

        None only after exactly ONE warning (a failed fetch reuses a
        present-but-stale VALID cache entry with that same warning;
        nothing valid cached => None); the caller degrades — a restore
        source is never guessed.
        """
        locale = (self._config.default_locale
                  if locale is _UNSET else locale)
        url = core_release_zip_url(version, locale, self._config)  # validates
        cache_name = (
            f"wp-release-{version}.zip"
            if locale == self._config.default_locale
            else f"wp-release-{version}-{locale}.zip"
        )
        return self._fetch_zip(url, self._cache_dir / cache_name)

    def fetch_theme_zip(self, slug: str, version: str) -> bytes | None:
        """The official wp.org THEME release zip for ``slug``@``version``.

        The integrity check's theme-skew cross-check source [L12]: the
        zip at ``downloads.wordpress.org/theme/<slug>.<version>.zip`` is
        the release the theme's own style.css ``Version:`` header names,
        so a default-theme file whose md5 equals the zip's entry is the
        PRISTINE official file at the site's installed version — the
        auto-update past the core-bundled copy, not tampering.  The zip
        nests everything under ``<slug>/`` (the extraction prefix the
        cross-check strips; live-verified for twentytwentyfive 1.5).

        ``slug`` and ``version`` both interpolate into the URL AND the
        cache filename, so both are validated against their character
        classes: anything else raises WptError — refuse nonsense
        loudly, never guess (a well-formed but nonexistent
        slug@version is a plain 404 through the failed-fetch
        discipline).

        Cost: theme zips are small (hundreds of KB); the raw bytes
        cache at ``<wp_org.cache_dir>/theme-<slug>-<version>.zip`` under the
        shared cache TTL.  None only after exactly ONE warning; the caller
        degrades — a cross-check basis is never guessed.
        """
        if (not isinstance(slug, str)
                or not WP_THEME_SLUG_RE.fullmatch(slug)):
            raise WptError(
                f"refusing theme-zip download for invalid slug {slug!r}: "
                "expected a non-empty [A-Za-z0-9_-] slug"
            )
        if (not isinstance(version, str)
                or not WP_RELEASE_VERSION_RE.fullmatch(version)):
            raise WptError(
                f"refusing theme-zip download for invalid version "
                f"{version!r}: expected a non-empty [A-Za-z0-9.-] "
                "version string"
            )
        template = (_THEME_ZIP_URL
                    or self._config.theme_release_zip_url)
        return self._fetch_zip(
            template.format(slug=slug, version=version),
            self._cache_dir / f"theme-{slug}-{version}.zip",
            prefix=f"{slug}/",
        )


# ------------------------------------------------------------ shared internals


def _detail_lines(items: list[str]) -> str:
    """Up to _DETAIL_LINES newline-joined lines; "(+N more)" if truncated."""
    if len(items) <= _DETAIL_LINES:
        return "\n".join(items)
    return "\n".join(items[:_DETAIL_LINES]) + f"\n(+{len(items) - _DETAIL_LINES} more)"


def _usable_new_version(entry: dict[str, Any]) -> str | None:
    """The bucket entry's new_version when it is a non-empty string."""
    new = entry.get("new_version")
    return new if isinstance(new, str) and new else None


def _entry_url(entry: dict[str, Any]) -> str:
    """The detail link: the wp.org page (``url``, live-verified in the
    bucket) with the zip ``package`` (R3's documented field) as fallback;
    empty when the entry carries neither."""
    for field in ("url", "package"):
        url = entry.get(field)
        if isinstance(url, str) and url:
            return url
    return ""


# ------------------------------------------------------------------- checks


@register_check("updates.core", applies=("ftp", "local"))
def check_updates_core(data: AuditData, settings: Settings) -> list[Finding]:
    """The WP core version behind the latest wp.org offer.

    ``wp_version`` None (unknown — e.g. no probe, or a local tree whose
    wp-includes/version.php is missing) => [].  Latest
    = cached offers[0].current; a wp_version different from it (string
    inequality, per the W6g design) => one finding "X -> Y", risk medium.
    Equal => [].  Unreachable API / unusable payload => [] after one
    warning (never a guess).
    """
    if data.probe is None or data.wp_version is None:
        return []
    latest = WpOrgApi(
        data.probe.session, data.probe.timeout_s,
        deadline=getattr(data.deadline, "at", None),
        config=settings.wp_org,
    ).latest_core_version()
    if latest is None or latest == data.wp_version:
        return []
    return [
        Finding(
            category="updates.core",
            name="core-update",
            detail=f"{data.wp_version} -> {latest}",
            count=1,
            risk="medium",
            fix="update WordPress via wp-admin; back up first",
        )
    ]


@register_check("updates.plugins", applies=("ftp", "local"))
def check_updates_plugins(data: AuditData, settings: Settings) -> list[Finding]:
    """Plugin updates from ONE bulk wp.org POST: one aggregate finding.

    Empty catalog (always in local mode) or no probe => []; catalog
    entries without a version are skipped (unknown, never sent), and an
    empty remainder sends nothing.  The wp.org "plugins" bucket = update
    available => one finding: count = reportable updates, detail =
    sorted "slug: installed -> new (url)" lines capped at 8 with a
    "(+N more)" marker.  "no_update" (current) and keys absent from both
    buckets (premium / not on wp.org) are silent.  No answer from wp.org
    => [] after one warning.
    """
    if data.probe is None or not data.plugin_catalog:
        return []
    versioned = {
        file: meta
        for file, meta in data.plugin_catalog.items()
        if isinstance(meta, dict)
        and isinstance(meta.get("version"), str)
        and meta["version"]
    }
    if not versioned:
        return []
    result = WpOrgApi(
        data.probe.session, data.probe.timeout_s,
        deadline=getattr(data.deadline, "at", None),
        config=settings.wp_org,
    ).bulk_plugin_check(versioned)
    if result is None:
        return []
    updates, _current = result
    lines: list[str] = []
    for file, entry in sorted(updates.items()):
        if file not in versioned:
            continue
        new = _usable_new_version(entry)
        if new is None:
            continue
        line = (
            f"{file.split('/')[0]}: {versioned[file]['version']} -> {new}"
        )
        url = _entry_url(entry)
        if url:
            line += f" ({url})"
        lines.append(line)
    if not lines:
        return []
    return [
        Finding(
            category="updates.plugins",
            name="plugin-updates",
            detail=_detail_lines(lines),
            count=len(lines),
            risk="medium",
            fix="update plugins via wp-admin; back up first",
        )
    ]


@register_check("updates.themes", applies=("ftp", "local"))
def check_updates_themes(data: AuditData, settings: Settings) -> list[Finding]:
    """Active-theme update offers from ONE bulk wp.org POST.

    ``theme_versions`` (slug -> style.css header Version, gathered best-
    effort in BOTH modes) drives the check: empty => [] (no readable
    version = unknown = silent, never a guess).  Themes whose slug lands
    in the "themes" (update) bucket => one aggregate finding with
    "slug: current -> new (url)" lines; "no_update" and keys absent from
    both buckets (premium / custom themes) are silent; no answer from
    wp.org => [] after one warning.
    """
    if data.probe is None or not data.theme_versions:
        return []
    result = WpOrgApi(
        data.probe.session, data.probe.timeout_s,
        deadline=getattr(data.deadline, "at", None),
        config=settings.wp_org,
    ).bulk_theme_check(dict(data.theme_versions))
    if result is None:
        return []
    updates, _current = result
    lines: list[str] = []
    for slug, entry in sorted(updates.items()):
        if slug not in data.theme_versions:
            continue
        new = _usable_new_version(entry)
        if new is None:
            continue
        line = f"{slug}: {data.theme_versions[slug]} -> {new}"
        url = _entry_url(entry)
        if url:
            line += f" ({url})"
        lines.append(line)
    if not lines:
        return []
    return [
        Finding(
            category="updates.themes",
            name="theme-updates",
            detail=_detail_lines(lines),
            count=len(lines),
            risk="medium",
            fix="update the active theme via wp-admin; back up first",
        )
    ]
