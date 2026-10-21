"""Remote-only security audit checks (W6f) + the SiteProbe transport facade.

Thirteen checks registered under ``security.*`` with ``applies=("ftp",)`` ONLY
(SPEC §Audit modules security.py): every one of them probes the LIVE
site — an HTTP request, a bridge call, a source read or a TLS handshake —
so local mode (an offline zip) can never run them and
``select_checks("local", ...)`` never selects one. Uniform signature
``func(data: AuditData, settings: Settings) -> list[Finding]``; no settings
tunables are consumed (the endpoints and paths probed below are structural
WordPress facts, not profile knobs), so ``settings`` exists only for the
registry's uniform calling convention — exactly like wpt/audit/media.py —
with TWO documented exceptions, both module-level because
``wpt/settings.py`` + ``wpt/data/profiles/default.json`` are coordinator-owned
and promotion is flagged for the writer chain: ``security.php_version``'s
minimum actively-supported PHP minor is owned by
``settings.env.php_min_active`` (packaged default "8.2"; a malformed section
falls back to ``EnvSettings().php_min_active``) and the
``security.web_exposed_script`` signature list + read bound
(``_WEB_SCRIPT_SIGNATURES`` / ``WEB_SCRIPT_MAX_BYTES``).

TWO checks here are NOT remote-only and register for both modes, because
their evidence is a FILE rather than a live answer:
``security.web_exposed_script`` (this module, below) and
``security.suspicious`` (wpt/audit/suspicious.py).

SiteProbe — the transport facade (assembled by the audit runner, W6h):
    * ``session``  — the SAME prepared ``requests.Session`` the Bridge uses
      (``wpt.dnsoverride.resolve_session(hostname, ip, verify=...)`` output
      when ``--override-ip`` is set, else a plain session — verify_tls then
      applies only to the override session; probes set explicit timeouts);
      probes ride the same DNS-override-aware transport as the bridge.
    * ``site``     — the public site URL (``--wp-url``), no trailing slash
      (normalized defensively here so a runner slip cannot produce
      "//xmlrpc.php" request URLs).
    * ``bridge``   — the live Bridge instance (already deployed for
      gather_remote); None = no bridge capability.
    * ``source``   — the (webroot-rooted) ftp Source for file reads.
    * ``timeout_s``— ``settings.http.timeout_s``; EVERY requests timeout
      here flows from it (SPEC: timeouts come from settings.http). ``get``
      / ``post`` / ``head`` inject it and callers must not pass their own.
      ``head`` exists for a URL whose body must never be requested: the
      web server EXECUTES a PHP file on a GET, so dating an unexplained
      top-level script asks for its headers only.

Degrade contract (binding for every check):
    * a capability that is None (no probe, no bridge, no source) means the
      check cannot know -> silence, never a guess;
    * a network failure during ONE probe (``requests.RequestException``)
      degrades to silence for that single probe only (helpers _get/_post);
    * a bridge call failure (``BridgeError``) or an unreadable file
      degrades to None inside the facade (the cached ``info()`` answer —
      payload or None — is final for the probe's lifetime: one
      round-trip, never a per-check retry);
    * a security check that cannot reach the site reports nothing — it
      does NOT guess "secure". Silence is a correct result, not an error.

Check semantics (each returns at most one finding; sorted-sample detail
lists use the "up to N + (+N more)" convention; nothing mutates ``data``):

* security.xmlrpc — POST {site}/xmlrpc.php with a system.listMethods
  methodCall body (content-type text/xml); 200 + "<methodResponse>" in the
  body => xmlrpc enabled (brute-force / login-amplification surface).
* security.rest_users — GET {site}/wp-json/wp/v2/users without following
  redirects; 200 + a JSON LIST carrying >= 1 item with a non-empty string
  "slug" => user enumeration (401/403/404/redirect/non-list/no-slug all
  silent). count = enumerated users; detail lists their slugs.
* security.author_scan — GET {site}/?author=1 without following
  redirects; a 3xx whose Location header contains "/author/" => user
  enumeration via the author archive redirect.
* security.wp_config_perms — bridge ``fileperms`` for "wp-config.php";
  a present permissions string other than "0600" (e.g. "0644") => the
  config is readable beyond the owning account. None/absent/malformed
  payload silent.
* security.disallow_file_edit — wp-config.php text via probe.read_file,
  scanned as PHP (strings/comments/heredoc/inline-HTML aware, case-sensitive
  names, exact PHP truthiness): the constant is not defined with an ACTIVE
  truthy value => admins can edit plugin/theme source in wp-admin. An active
  truthy DISALLOW_FILE_MODS also closes the editor, so it suppresses this.
  Unreadable/absent file silent. A conditional/non-literal value is reported
  as unverifiable, never assumed safe.
* security.relocate — the same PHP-aware scan for RELOCATE: wp-login.php
  derives siteurl from the incoming request and writes that option whenever
  the constant is truthy, so an active truthy RELOCATE is a high-risk
  finding (WordPress migration guidance is to delete it once the move is
  done). "false"/"0"/null/absent/commented => silent; a conditional or
  non-literal value => unverifiable (medium).
* security.https_redirect — samples the homepage plus up to 3
  ``data.pages`` entries (deduped, first-3, page order preserved), GETs
  each with the scheme swapped to http:// without following redirects;
  a response that neither carries a 301/302/307/308 status nor a Location
  pointing at https:// leaves http alive => offender. Any offender => one
  finding (name "https-redirect") listing the sampled URLs. pages None =>
  homepage only (documented limitation, still a valid single sample).
  A per-URL probe failure skips just that URL.
* security.www_apex — when the site host is not "www.*": GET
  https://www.<host>/ FOLLOWING redirects; a 2xx whose final URL is still
  the www host => duplicate www host serving content (SEO + stale-cert
  risk). Unreachable/redirected/elsewhere/non-2xx silent — www not serving
  is the good case.
* security.cert_mismatch — informational: a verified TLS handshake
  (socket.create_connection((host, 443)) wrapped in
  ssl.create_default_context() with server_hostname) against
  ``data.siteurl``'s host (NOT www-prefixed); a failure raising
  ssl.SSLCertVerificationError => the certificate does not cover the DNS
  name — expected pre-migration, hence risk low. Handshake OK / host
  unreachable / any other SSL or socket error silent.
* security.uploads_listing — GET {site}/wp-content/uploads/ without
  following redirects; 200 + "Index of" in the body OR an html
  content-type => directory listing enabled. 403/redirect/404 silent.
* security.debug_log — entries-based (NO probe use — the walked tree is
  the evidence; kept here because it is a security exposure): a FILE
  entry at exactly "wp-content/debug.log" => WP_DEBUG output exposed in
  the webroot. Also reports when probe is None — it never consulted one.
* security.php_version — the host PHP runtime below the minimum
  actively-supported PHP minor: the bridge ``info`` payload (cached on the
  probe — one round-trip serves every consumer) carries php_version,
  parsed as a numeric (major, minor) tuple ("8.10" > "8.9", never a
  float) and compared against ``env.php_min_active`` (default "8.2").
  BELOW it => ONE finding "php-eol" (risk medium): detail = the runtime
  facts line (sapi, mysql, memory_limit, max_execution_time, server —
  an absent fact renders "unknown"). Absent/unparseable php_version, a
  failed info call, no bridge or no probe — silent (unknown, never a
  guess); at-or-above the minimum — silent too: a healthy runtime is
  the updates-check precedent.
* security.web_exposed_script (BOTH modes) — a TOP-LEVEL file whose
  suffix is in the profile's PHP-EXECUTABLE set (``web_script.extensions``
  — WHICH extensions execute is the HOST's ``AddHandler``/mod_php
  configuration, so the shipped list is the COMMON SUPERSET: ``.php``,
  ``.phtml``, ``.php5``, ``.php7``, ``.phps``, ``.phar``, ``.inc``,
  ``.module``; matching is case-insensitive, so ``shell.PHP`` counts),
  that is not an official core file, not a registered known artifact
  (Wordfence's ``wordfence-waf.php`` through ``core_integrity.known_added``,
  wpt's OWN ``bridge-<hex>.php`` through ``web_script.known_artifacts``)
  and not any plugin/theme unit, and whose own bytes carry a
  request-parameter gate or a home-directory walk signature
  (``web_script.signatures`` as the cheap first pass, then the
  structured request-superglobal family ``web_script.request_globals``)
  => ONE high finding per FILE: the matched signatures, the file's own
  date (``Last-Modified`` over a HEAD when a probe exists, "date unknown"
  offline) and the read-only triage + removal commands
  (:data:`WEB_SCRIPT_TRIAGE`, also the text the ``core.integrity``
  "added" finding of the same file must render).  The scan is
  ENCODING-AWARE: a file whose bytes do not decode as UTF-8, or that
  carries a UTF-16 BOM / a high NUL proportion, is ALSO scanned through
  a transcoded view, and a PREDOMINANT single base64/gzip blob that
  DECODES to a signature earns one extra ``encoded-payload`` report
  line.  The map that exempts the official core set rides integrity's own
  fetch seam, and an UNAVAILABLE map NEVER leaves the check asserting
  "not an official core file": it degrades to a clearly-labelled UNPROVEN
  finding under its own category ``security.web_exposed_script_unproven``
  (risk medium, one per file, never a high), whose detail names the
  missing basis and the measured false-positive rate — because roughly
  a small share of ordinary core/plugin/theme PHP files carry one of these
  signatures, an offline run rated ``wp-login.php``/``wp-cron.php``/
  ``xmlrpc.php`` HIGH "not an official core file" with backdoor triage
  text for a site where the only fault was that wp.org could not be
  reached.  The unproven fix text removes nothing and names the
  comparison to run instead.  ONLY an unreachable wp.org demotes — an
  UNREADABLE ``wp-includes/version.php`` is a file inside the
  webroot — the candidate's own author can strip the version from it —
  and it exempts nothing and lowers nothing, so the candidate stays HIGH
  with the incomplete basis (and any altered-core evidence) named in its
  detail [D1].  Neither does an answer wp.org DID give that failed to
  establish the build (a 4xx/5xx, a redirect, an HTML page, an empty
  body, a JSON list): every HTTP response is evidence that wp.org spoke,
  and the request URL carries the attacker-writable ``$wp_version``, so
  a status code is never wpt's to read as a verdict about the site.
  The three webroot fact probes shared with the other checks live here
  too: :func:`publicly_served_paths` (the junk disclosure D3 — at most
  three paths, deadline-checked, SILENT offline, and a 200 that is
  byte-identical to the site's answer for a certainly-missing path is a
  SOFT 404 and claims nothing) and :func:`last_modified`.

Structural WordPress constants (fixed layout facts, NOT tunables):
"xmlrpc.php", "wp-json/wp/v2/users", "?author=1", "wp-config.php",
"wp-content/uploads/", "wp-content/debug.log", "DISALLOW_FILE_EDIT",
"DISALLOW_FILE_MODS", "RELOCATE", "0600" (the only silent wp-config
permission), "Index of" (the Apache listing marker), port 443.
Presentation limit 5 (detail items before the "(+N more)" marker) and the
pages sample cap 3 are fixed by this check contract, not tunables;
``_SERVED_PATH_SAMPLE`` (3) is the same kind of bound for the junk
disclosure probe, which also spends ONE request per call on the
certainly-missing path its soft-404 baseline comes from.

PHP-minimum policy is the existing ``env.php_min_active`` setting (a
malformed section falls back to ``EnvSettings().php_min_active``); the
web-script bounds are the shared ``web_script`` settings.
"""

import base64
import binascii
import re
import secrets
import socket
import ssl
import threading
import time
import zlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse, urlunparse

import requests

from .data import AuditData, _read_wp_version
# NOTE: .integrity is imported DEFERRED inside the check that needs it —
# integrity imports .suspicious, which imports THIS module for the
# PHP-code-mask primitives (wpt.audit.integrity's own "webroot imports
# this module" note is the same precedent), so a module-level import
# here would be a cycle.
from .registry import register_check
from ..bridge_name import probe_name
from ..log import get_logger
from ..netresolve import is_numeric_host, resolve_host_bounded
# The three shipped web_script value sets are RE-EXPORTED under their
# historical module names: wpt.settings owns the values (and
# wpt/data/profiles/default.json restates them, with a contract test pinning
# the two), so the no-settings fallback this module keeps for a call that
# carries no profile cannot drift away from what ships.
from ..settings import (
    WEB_SCRIPT_EXTENSIONS as _WEB_SCRIPT_EXTENSIONS,
    WEB_SCRIPT_MAX_BYTES as _WEB_SCRIPT_MAX_BYTES,
    WEB_SCRIPT_REQUEST_GLOBALS as _WEB_SCRIPT_REQUEST_GLOBALS,
    WEB_SCRIPT_SIGNATURES as _WEB_SCRIPT_SIGNATURES,
    EnvSettings,
    Settings,
    WpOrgSettings,
)
from ..types import (BridgeError, DeadlineExceeded, Entry, Finding, Source,
                     SourceError, WptError)
from ..wpbridge.client import Bridge

log = get_logger("audit.security")

# Structural WordPress constants (see module docstring).
_XMLRPC_ENDPOINT = "xmlrpc.php"
_REST_USERS_PATH = "wp-json/wp/v2/users"
#: The same route as WordPress's public ``rest_route`` query var takes it
#: (no ``wp-json`` prefix): ``/?rest_route=/wp/v2/users``.
_REST_USERS_ROUTE = "/wp/v2/users"
_AUTHOR_QUERY = "?author=1"
_WP_CONFIG = "wp-config.php"
_DISALLOW_FILE_EDIT = "DISALLOW_FILE_EDIT"
_DISALLOW_FILE_MODS = "DISALLOW_FILE_MODS"
_RELOCATE = "RELOCATE"
_SECURE_WP_CONFIG_PERMS = "0600"
_UPLOADS_URL_PATH = "wp-content/uploads/"
_DEBUG_LOG_PATH = "wp-content/debug.log"
_INDEX_MARKER = "Index of"
_METHOD_RESPONSE_MARKER = "<methodResponse>"
_TLS_PORT = 443

# Presentation limits fixed by this check contract (not tunables).
_DETAIL_ITEMS = 5      # max detail items before the "(+N more)" marker
_PAGES_SAMPLE = 3       # data.pages entries sampled beyond the homepage
_SERVED_PATH_SAMPLE = 3  # matched webroot paths probed for public reachability

# The xmlrpc probe body (SPEC): a minimal system.listMethods methodCall.
_XMLRPC_PROBE = (
    '<?xml version="1.0"?>'
    "<methodCall><methodName>system.listMethods</methodName>"
    "<params></params></methodCall>"
)

# http->https redirect statuses a non-followed response can show
# (303 deliberately absent: SPEC pins 301/302/307/308).
_HTTPS_REDIRECT_STATUSES = (301, 302, 307, 308)

# Policy floor: the owner is ``settings.env.php_min_active`` (packaged
# default "8.2"); a malformed section falls back to EnvSettings().

# Facade sentinel: "probe.info() not asked yet". None is a legitimate
# CACHED answer (no bridge / a failed call) and must never re-trigger a
# bridge round-trip.
_UNCACHED: Any = object()


# ------------------------------------------------------------- the facade


@dataclass
class SiteProbe:
    """Transport facade for remote-only security probes (assembled by the
    audit runner: W6h). Checks degrade to silence when a capability is None.

    Field wiring (see module docstring): ``session`` = the prepared
    DNS-override-aware requests Session, ``site`` = the public site URL
    without trailing slash, ``bridge`` = the live Bridge (or None),
    ``source`` = the webroot-rooted ftp Source (or None), ``timeout_s`` =
    ``settings.http.timeout_s``. Methods never raise for a missing
    capability; a network failure propagates as ``requests`` would (the
    CHECK degrades — see _get/_post), a bridge failure maps to None.
    ``info()`` caches the bridge ``info`` payload — one round-trip per
    probe, shared by every check that reads runtime facts.
    """

    session: requests.Session
    site: str
    bridge: Bridge | None = None
    source: Source | None = None
    timeout_s: int = 30
    #: The body bound for a check that needs the response BODY (not only
    #: status/headers).  Wired from ``settings.http.max_response_bytes`` by
    #: the audit runner; a real bounded transport preloads up to this many
    #: bytes so a large homepage/uploads listing still answers its check
    #: instead of being read as "the site did not answer" by the 256 KiB
    #: bridge-excerpt cap.  Bounded per response, never cumulative.
    max_response_bytes: int = 8 * 1024 * 1024
    #: The ``--override-ip`` address in effect for ``site``'s host, or
    #: None.  The raw-socket checks (cert_mismatch) dial THIS address
    #: with server_hostname = the site host — the same override every
    #: session-riding probe already honors; leaving it None dials real
    #: DNS, the pre-override behavior.  [L13: with --override-ip set,
    #: the cert probe dialed real DNS from inside a network whose
    #: resolver answered a *different* server — a valid cert read as
    #: a mismatch.]
    override_ip: str | None = None
    # Bridge "info" cache: the payload dict once fetched, None for a final
    # "cannot ask" — _UNCACHED until the first info() call.
    _info: Any = field(init=False, repr=False, compare=False, default=_UNCACHED)

    def __post_init__(self) -> None:
        # Defensive normalization of the runner's contract: URLs built as
        # f"{site}/path" must never carry "//".
        self.site = self.site.rstrip("/")

    def get(self, url: str, **kw: Any) -> requests.Response:
        """session.get with the facade-owned timeout injected (kw carries
        allow_redirects etc.).  A bounded caller may override ``timeout``
        through kw: the per-request value then rides the run deadline."""
        timeout = kw.pop("timeout", self.timeout_s)
        return self.session.get(url, timeout=timeout, **kw)

    def post(self, url: str, **kw: Any) -> requests.Response:
        """session.post with the facade-owned timeout injected."""
        timeout = kw.pop("timeout", self.timeout_s)
        return self.session.post(url, timeout=timeout, **kw)

    def head(self, url: str, **kw: Any) -> requests.Response:
        """session.head with the facade-owned timeout injected.

        The metadata-only twin of :meth:`get`, for a URL whose BODY must
        never be requested: an unknown top-level PHP file is EXECUTED by
        the web server on a GET (that is exactly how a token-gated probe
        answers), so a check that wants a file's date asks for its
        headers only.
        """
        timeout = kw.pop("timeout", self.timeout_s)
        return self.session.head(url, timeout=timeout, **kw)

    def bridge_call(self, action: str, **params: Any) -> dict[str, Any] | None:
        """One bridge action; None when no bridge or the call failed.

        Bridge.call raises BridgeError on every documented failure path
        (transport, protocol, server-side Throwable); the facade maps all
        of them to None — a check that cannot ask the bridge reports
        nothing.
        """
        if self.bridge is None:
            return None
        try:
            return self.bridge.call(action, **params)
        except BridgeError:
            return None

    def info(self) -> dict[str, Any] | None:
        """The bridge ``info`` payload (site identity + runtime facts),
        cached after the first call; None when no bridge or the call failed.

        One round-trip serves every consumer on this probe (several
        checks read runtime facts from the same payload), and the FIRST
        answer is final: a None (no bridge, BridgeError) is kept too —
        the bridge has already exhausted its own transport/rename
        retries, and a check that cannot ask reports nothing.
        """
        if self._info is _UNCACHED:
            self._info = self.bridge_call("info")
        return self._info

    def read_file(self, path: str) -> str | None:
        """Decoded file text via the source; None when absent/unreadable.

        Decode uses errors="replace" (wp-config.php is text; a stray byte
        must not blind DISALLOW_FILE_EDIT detection). Any read failure —
        SourceError from the real connectors, a missing-file KeyError from
        test doubles — degrades to None: absent is silent, never a guess.
        """
        if self.source is None:
            return None
        try:
            return self.source.read_bytes(path).decode("utf-8", errors="replace")
        except Exception:
            return None


# ----------------------------------------------------------- shared internals


def _preload_bounded_text(response: Any, limit: int,
                          absolute: float) -> None:
    """Attach at most ``limit`` bytes of a streamed answer to ``response``.

    The last-resort branch for a response that is neither the bounded
    transport's ``_SocketResponse`` (``preload_prefix``/``preload``) nor a
    simple double without ``iter_content``.  A plain streamed
    ``requests.Response`` would otherwise be read by ``.text`` whole, with
    requests' per-read timeout as its ONLY bound — the same unbounded
    error/body read the probe cap exists to stop.  The chunk loop checks
    the absolute instant and stops at the cap; `.text` then reads the
    cached prefix.
    """
    iterator = getattr(response, "iter_content", None)
    if not callable(iterator):
        return
    chunks: list[bytes] = []
    total = 0
    for chunk in iterator(chunk_size=64 * 1024):
        if time.monotonic() >= absolute:
            raise requests.Timeout(
                "probe body read exceeded the absolute timeout")
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8", "replace")
        if not chunk:
            continue
        take = min(len(chunk), limit - total)
        chunks.append(chunk[:take])
        total += take
        if take < len(chunk) or total >= limit:
            response.body_truncated = True
            break
    response._content = b"".join(chunks)
    response._content_consumed = True


def _probe_call(probe: SiteProbe, method: str, url: str, *,
                deadline: Any = None, **kw: Any) -> requests.Response | None:
    """One probe verb with the single-probe degrade: a network failure during
    THIS probe reads as unknown (None) and the caller stays silent for it.

    With a run deadline, ONE absolute bound governs the dial, headers and
    body: ``min(deadline.at, now + probe.timeout_s)``.  A long run budget
    must not turn a single trickled header into an hour-long probe; a
    shorter run budget still wins.  The call itself runs on a worker the
    caller stops waiting for at that same instant — so a server or test
    double that ignores ``timeout`` cannot outlive either bound.  The GET
    and POST owners share THIS implementation so one verb cannot drift
    back to an unbounded request.
    """
    call = getattr(probe, method)
    session = getattr(probe, "session", None)
    real_session = all(
        callable(getattr(session, name, None))
        for name in ("prepare_request", "get_adapter",
                     "merge_environment_settings"))
    if deadline is None:
        if not real_session:
            try:
                return call(url, **kw)
            except requests.RequestException:
                return None
        # Even an UNBOUNDED run (--deadline 0) must not materialize an
        # arbitrary body: use the same bounded transport with the probe's
        # own absolute timeout and the configured body cap.
        remaining = float(probe.timeout_s)
        timeout = max(0.001, remaining)
    else:
        remaining = deadline.remaining
        if remaining <= 0:
            return None
        timeout = max(0.001, min(probe.timeout_s, remaining))
    if real_session:
        # A REAL session rides the absolute-deadline transport in THIS
        # thread: the old worker returned None at the deadline while its
        # ``session.get`` kept downloading a dripped body forever ("no
        # worker past the deadline").  The body is preloaded under the
        # same budget so callers can read .text/.json after the socket is
        # closed; a HEAD has no body to read.
        from ..php_probe import get_bounded, head_bounded, post_bounded

        # The transport bound is the ALREADY-MINIMIZED per-probe timeout:
        # both the request and every header/body read end at
        # ``now + min(probe.timeout_s, remaining)``.  Using ``remaining``
        # alone let one dripped header hold this probe for the whole run
        # budget; the run deadline still wins when it is shorter.
        absolute = time.monotonic() + timeout
        try:
            if method == "get":
                response = get_bounded(
                    session, url, timeout_s=timeout, deadline=absolute,
                    allow_redirects=kw.pop("allow_redirects", True),
                    headers=kw.pop("headers", None),
                    verify=kw.pop("verify", None))
            elif method == "post":
                form = kw.pop("data", None)
                json_body = kw.pop("json", None)
                response = post_bounded(
                    session, url, form=form, json_body=json_body,
                    timeout_s=timeout, deadline=absolute,
                    headers=kw.pop("headers", None),
                    verify=kw.pop("verify", None))
            elif method == "head":
                response = head_bounded(
                    session, url, timeout_s=timeout, deadline=absolute,
                    allow_redirects=kw.pop("allow_redirects", True),
                    headers=kw.pop("headers", None),
                    verify=kw.pop("verify", None))
            else:  # pragma: no cover — the three verbs are the contract
                return None
            if method == "head":
                # Headers are the whole answer; close the connection now.
                response.close()
            else:
                try:
                    # A body consumer's bound, NOT the 256 KiB bridge
                    # excerpt: a 307 KiB homepage made every GET return
                    # None (see SiteProbe.max_response_bytes).  The real
                    # socket response caches the preloaded bytes so later
                    # .text/.json reads never touch the closed socket.
                    limit = max(1, int(getattr(
                        probe, "max_response_bytes", 8 * 1024 * 1024)))
                    prefixer = getattr(response, "preload_prefix", None)
                    if callable(prefixer):
                        # Status/headers and a bounded PREFIX are the
                        # answer: a 200 whose body is over the cap is
                        # answered-but-too-large, never "no answer".
                        # (https_redirect and uploads_listing decide from
                        # headers; served-path from the prefix/soft-404
                        # comparison.)
                        prefixer(limit)
                        response.close()
                    else:
                        preload = getattr(response, "preload", None)
                        if callable(preload):
                            preload(limit)
                        else:
                            _preload_bounded_text(response, limit, absolute)
                except (requests.RequestException, WptError, OSError):
                    response.close()
                    return None
            return response
        except (requests.RequestException, WptError, OSError):
            return None
    result: list[Any] = []

    def _work() -> None:
        try:
            result.append(call(url, timeout=timeout, **kw))
        except BaseException as exc:  # noqa: BLE001 — relayed/degraded below
            result.append(exc)

    worker = threading.Thread(target=_work, name="wpt-http-probe",
                              daemon=True)
    worker.start()
    # Wait for the SAME minimized bound the real transport gets: a double
    # that ignores its ``timeout`` kw must not hold this probe past
    # ``min(run deadline, now + probe.timeout_s)``.
    worker.join(timeout)
    if worker.is_alive():
        return None
    answer = result[0] if result else None
    if isinstance(answer, requests.RequestException):
        return None
    if isinstance(answer, BaseException):
        raise answer
    return answer


def _get(probe: SiteProbe, url: str, *, deadline: Any = None,
         **kw: Any) -> requests.Response | None:
    """probe.get with the bounded single-probe degrade (see _probe_call)."""
    return _probe_call(probe, "get", url, deadline=deadline, **kw)


def _post(probe: SiteProbe, url: str, *, deadline: Any = None,
          **kw: Any) -> requests.Response | None:
    """probe.post with the bounded single-probe degrade (see _probe_call)."""
    return _probe_call(probe, "post", url, deadline=deadline, **kw)


def _excerpt(items: list[str], limit: int = _DETAIL_ITEMS) -> str:
    """Up to ``limit`` items, comma-joined; " (+N more)" when truncated."""
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f" (+{len(items) - limit} more)"


def _detail_lines(items: list[str], limit: int = _DETAIL_ITEMS) -> str:
    """Up to ``limit`` newline-joined lines; "(+N more)" when truncated."""
    if len(items) <= limit:
        return "\n".join(items)
    return "\n".join(items[:limit]) + f"\n(+{len(items) - limit} more)"


def _http_twin(url: str) -> str:
    """The sampled URL with its scheme swapped to http:// (a no-op for a
    page already served over http)."""
    return urlunparse(("http",) + urlparse(url)[1:])


def _leaves_http(response: requests.Response) -> bool:
    """Does this non-followed response leave http for https?

    True when the status is one of 301/302/307/308 (a redirect we cannot
    chain-follow with allow_redirects=False) or when a Location header
    points at an https:// URL (the parenthetical signal from SPEC — some
    servers answer with a non-3xx status plus a Location).
    """
    if response.status_code in _HTTPS_REDIRECT_STATUSES:
        return True
    location = response.headers.get("Location")
    return bool(location) and urlparse(location).scheme == "https"


def _fact(value: Any) -> str:
    """One runtime fact for the php_version detail line: a non-empty
    string as-is, anything else (None, empty, wrong type) as "unknown"."""
    return value if isinstance(value, str) and value else "unknown"


# --------------------------------------------------- webroot URL fact probes


def publicly_served_paths(
    probe: SiteProbe | None,
    paths: Sequence[str],
    deadline: Any = None,
    limit: int = _SERVED_PATH_SAMPLE,
) -> list[str]:
    """Which of ``paths`` the LIVE site hands to anyone as itself.

    The webroot is served verbatim: a file sitting in the document root
    under a guessable name is fetchable by anyone, which is a SECURITY
    fact and not a housekeeping one (live: a large ``error_log`` at
    HTTP 200 carrying SQL statements and absolute server paths).  At most
    ``limit`` paths are requested, in the caller's order; the rest are
    never claimed either way.

    Per path:

    * HTTP 200 whose body DIFFERS from the site's answer for a
      certainly-missing path => SERVED (the disclosure).  The status
      alone is not enough: a host with a soft 404 (an SEO plugin, a
      caching layer, a bot challenge) answers 200 + a "not found" page for
      EVERY missing path, and a check that trusted the status put a false
      disclosure INSIDE a high-risk fix text.  One baseline is measured
      per call (:func:`_soft404_baseline`), never one per path;
    * any other status, INCLUDING a 3xx redirect (a deny rule already in
      place), 404, and a 200 that IS the soft-404 baseline => not
      served, silent;
    * the request path is ``urllib.parse.quote``-escaped (``safe="/"``)
      because a junk name can carry a space or a ``#``, and an
      unescaped one asks the server for a DIFFERENT URL than the file
      the tree holds;
    * a network failure => unknown for THAT path only, never a guess;
    * the run's ``deadline`` is checked before each request, so an
      expiring budget returns what was proven and stops (the walk's
      partial-reference-set precedent) instead of crawling;
    * ``probe is None`` (LOCAL mode: an offline zip has no live site) or
      an empty site URL => [] with NO request at all, so an offline audit
      renders byte-identically to a run that has no probe.
    """
    if probe is None or not getattr(probe, "site", ""):
        return []
    sample = [p for p in paths[: max(int(limit), 0)]
              if isinstance(p, str) and p]
    served: list[str] = []
    baseline: tuple[str, bool] | None = None
    measured = False
    for path in sample:
        if deadline is not None and deadline.expired:
            log.debug(
                "served-path probe: run deadline reached after %d of %d "
                "requested path(s)", len(served), len(sample),
            )
            return served
        response = _get(
            probe, f"{probe.site}/{quote(path, safe='/')}",
            deadline=deadline, allow_redirects=False,
        )
        if response is None or response.status_code != 200:
            continue
        if not measured:
            measured = True
            baseline = _soft404_baseline(probe, deadline)
        truncated = bool(getattr(response, "body_truncated", False))
        if baseline is not None:
            baseline_text, baseline_truncated = baseline
            if response.text == baseline_text and (
                    not truncated or baseline_truncated):
                # Same page (or the same bounded prefix of an over-large
                # soft-404 page): not a served artifact.
                log.debug(
                    "served-path probe: %s answers 200 with the site's own "
                    "not-found page (a soft 404) — not counted as served",
                    path,
                )
                continue
        served.append(path)
    return served


#: The certainly-missing path the soft-404 baseline is measured with, under
#: the SAME site: 8 fresh hex bytes through the ONE probe-name owner, so the
#: name cannot be a real file and cannot drift from the deployed shape.
def _soft404_probe_name() -> str:
    return probe_name(secrets.token_hex(4))


def _soft404_baseline(probe: SiteProbe,
                      deadline: Any) -> tuple[str, bool] | None:
    """The body the site answers for a certainly-MISSING path, or None.

    None means no soft-404 page was observed — the missing path answered a
    real 404 (or the probe could not be fetched, in which case the site is
    unreachable and every candidate GET fails too), and a 200 is then a
    200.  The returned flag says the body was over the probe's cap so the
    caller compares the same bounded prefix instead of trusting a short
    prefix as a complete soft-404 page.  ONE request per
    :func:`publicly_served_paths` call at most, and never after an expired
    run budget.
    """
    if deadline is not None and deadline.expired:
        return None
    path = _soft404_probe_name()
    response = _get(
        probe, f"{probe.site}/{path}", deadline=deadline,
        allow_redirects=False,
    )
    if response is None or response.status_code != 200:
        return None
    return response.text, bool(getattr(response, "body_truncated", False))


def last_modified(probe: SiteProbe | None, path: str,
                  deadline: Any = None) -> str | None:
    """The file's own date as the web server reports it, or None.

    A HEAD (never a GET — see :meth:`SiteProbe.head`) for the
    ``Last-Modified`` header: "date it against the site's own history" is
    the first question an operator asks of an unexplained file, and the
    server's own answer is the only one a read-only audit can have.  An
    absent/unparseable header, an error status, a network failure, no
    probe or an empty site URL => None (the caller renders "date
    unknown"), never a guess.  ``deadline`` is the run budget: the HEAD
    rides the same bounded single-probe owner as every other request, so a
    slow answer cannot outlive the scan.
    """
    if probe is None or not getattr(probe, "site", ""):
        return None
    if not isinstance(path, str) or not path:
        return None
    response = _probe_call(
        probe, "head", f"{probe.site}/{path}", deadline=deadline,
        allow_redirects=True)
    if response is None:
        return None
    if response.status_code >= 400:
        return None
    raw = response.headers.get("Last-Modified")
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        parsed = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if parsed is None:
        return None
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


_PHP_IDENT_TAIL = r"A-Za-z0-9_\x80-\xff"
_PHP_IDENT_RE = re.compile(r"[A-Za-z_\x80-\xff][" + _PHP_IDENT_TAIL + r"]*")
_PHP_IDENT_CHAR_RE = re.compile(r"[" + _PHP_IDENT_TAIL + r"]")
_PHP_INT_DEC = r"\d(?:_?\d)*"
#: PHP's numeric-literal grammar: underscores only BETWEEN digits, so
#: ``1_000`` is valid and ``0b1__0`` is a parse error, not a number.
_PHP_NUMBER_RE = re.compile(
    r"[+-]?(?:"
    r"0[xX][0-9a-fA-F](?:_?[0-9a-fA-F])*"
    r"|0[oO][0-7](?:_?[0-7])*"
    r"|0[bB][01](?:_?[01])*"
    r"|" + _PHP_INT_DEC + r"(?:\." + _PHP_INT_DEC + r")?"
    r"(?:[eE][+-]?" + _PHP_INT_DEC + r")?"
    r"|\." + _PHP_INT_DEC + r"(?:[eE][+-]?" + _PHP_INT_DEC + r")?"
    r")"
)
_PHP_OPEN_TAG_RE = re.compile(r"<\?(?:php\b|=)", re.IGNORECASE)
_PHP_HEREDOC_RE = re.compile(
    r"<<<[ \t]*(['\"]?)([A-Za-z_\x80-\xff][" + _PHP_IDENT_TAIL + r"]*)\1"
    r"[^\r\n]*(?:\r\n|\r|\n)"
)
_PHP_SIMPLE_ESCAPES = {
    "n": "\n", "t": "\t", "r": "\r", "v": "\v", "e": "\x1b", "f": "\f",
    "\\": "\\", "$": "$", '"': '"',
}
#: PHP keywords are case-insensitive; constant NAMES are not.
_PHP_TYPE_KEYWORDS = frozenset({"class", "interface", "trait", "enum"})
#: Alternative-syntax (``if ($x): ... endif;``) openers and terminators.
#: ``else``/``elseif`` CONTINUE a block rather than opening one, and
#: ``declare(ticks=1):`` is unconditional — neither may be counted as an opener.
_ALT_CONTROL_WORDS = frozenset({"if", "for", "foreach", "while", "switch"})
_ALT_TERMINATORS = frozenset(
    {"endif", "endfor", "endforeach", "endwhile", "endswitch"}
)


def _alt_syntax_marks(mask: str) -> list[tuple[int, int]]:
    """``[(position, delta)]`` over a blanked PHP mask.

    ``+1`` opens an alternative-syntax block, ``-1`` closes one, and ``0`` is a
    statement boundary that is NOT a block (``declare(...):``, a label, a
    ``case``).

    ONE linear pass. The previous tail-scanning regexes were quadratic, and
    bounding them to keep the cost linear silently MISSED a long condition —
    which let a conditional require look top-level and a hardening write land
    inside a conditional. A state machine is linear and has no cap, so neither
    failure mode can recur.
    """
    marks: list[tuple[int, int]] = []
    length = len(mask)
    depth = 0
    head_kind: str | None = None   # "control" / "declare" once a head is seen
    head_parens = 0                # open parens inside that head
    colon_expected = False         # the head is closed; only ':' may follow
    stmt_start = True
    i = 0
    while i < length:
        char = mask[i]
        if char in " \t\r\n":
            i += 1
            continue
        if colon_expected and char != ":":
            # `if (...) {` or `if (...);` — no alternative block. A later
            # colon is a ternary, a return type or a label, never an
            # alt-syntax opener, so the head is abandoned entirely.
            colon_expected = False
            head_kind = None
        if char == ";":
            if head_parens:
                i += 1
                continue          # a for-loop separator, not a statement end
            head_kind = None
            stmt_start = True
            i += 1
            continue
        if char in "([{":
            if char == "{" and head_kind is not None:
                # A brace inside or after a control head is an expression block
                # (`if (match ($x) { ... }):`) or a closure. Neither shape can
                # be modelled here, so the rest of the file is marked
                # conditional and every caller refuses. Failing closed is the
                # only safe direction for an unmodelled head.
                marks.append((i, 1))
                head_kind = None
                head_parens = 0
                colon_expected = False
            elif char == "(":
                if head_parens:
                    # A NESTED group inside the head (`if (array()):`); the
                    # reset here used to lose the head entirely.
                    head_parens += 1
                elif head_kind is not None and not colon_expected:
                    head_parens = 1
            depth += 1
            stmt_start = False
            i += 1
            continue
        if char in ")]}":
            if char == ")" and head_parens:
                head_parens -= 1
                if not head_parens:
                    colon_expected = True
            depth = max(0, depth - 1)
            stmt_start = False
            i += 1
            continue
        if char == ":":
            if head_parens:
                # `if (true ? false : true):` — punctuation inside the head.
                i += 1
                continue
            if colon_expected and head_kind is not None:
                # declare(ticks=1): is unconditional: a boundary, not a block.
                marks.append((i + 1, 1 if head_kind == "control" else 0))
            else:
                marks.append((i + 1, 0))   # a label or a case boundary
            head_kind = None
            colon_expected = False
            stmt_start = True
            i += 1
            continue
        word = _PHP_IDENT_RE.match(mask, i)
        if word is None:
            stmt_start = False
            i += 1
            continue
        lowered = word.group(0).lower()
        end = word.end()
        if _is_php_keyword_word(mask, i):
            stmt_start = False
            i = end
            continue
        if lowered in _ALT_TERMINATORS:
            # Counted at any bracket depth (an `endif` normally closes a block
            # inside a function body), but only a real terminator: a method
            # named `endif`, a `const endif`, a named argument `endif:` and
            # `Foo\endif` all continue instead. An identifier at EOF has no
            # next token, so it is not a terminator.
            after = _skip_ws(mask, end)
            if after < length and mask[after] == ";":
                marks.append((end, -1))
                stmt_start = True
        elif lowered in _ALT_CONTROL_WORDS:
            head_kind = "control"
            stmt_start = False
        elif lowered == "declare":
            head_kind = "declare"
            stmt_start = False
        elif lowered in ("case", "default"):
            marks.append((end, 0))
            stmt_start = False
        elif stmt_start and _skip_ws(mask, end) < length \
                and mask[_skip_ws(mask, end)] == ":":
            marks.append((end, 0))          # a goto/label statement
            stmt_start = False
        else:
            stmt_start = False
        i = end
    return marks


def _is_php_keyword_word(mask: str, index: int) -> bool:
    """True when the identifier at ``index`` is NOT a keyword: it is a variable
    (``$endif``), a member name (``$o->endif``, ``Foo::endif``) or part of a
    qualified name (``Foo\\endif``)."""
    if index and (mask[index - 1] == "$" or mask[index - 1] == "\\"):
        return True
    return _php_member_before(mask, index)


def _alt_depth_at(marks: list[tuple[int, int]], offset: int) -> int:
    """How many alternative-syntax blocks are open at ``offset``."""
    depth = 0
    for position, delta in marks:
        if position > offset:
            break
        depth += delta
    return depth


def _inside_alternative_syntax(mask: str, offset: int) -> bool:
    """True when ``offset`` falls inside an unclosed alternative-syntax block."""
    return _alt_depth_at(_alt_syntax_marks(mask), offset) > 0
#: A top-level statement that can end execution before a later definition.
_PHP_EXIT_KEYWORDS = frozenset({"return", "exit", "die", "throw"})
#: Constructs that can DEFINE a constant at runtime. PHP executes
#: `eval("define('X', true);")`, so a file containing one cannot be proven
#: free of a definition — reporting "absent" would be a false finding, and
#: for RELOCATE a missed active state. The state becomes indeterminate.
_PHP_RUNTIME_DEFINE = frozenset({"eval", "create_function", "assert"})


def _php_decode_string(literal: str) -> tuple[str, bool]:
    """Decode a PHP string literal as ``(value, statically-known)``.

    Single quotes escape only \\\\ and \\'; double quotes decode the full
    escape set plus variable interpolation. An escape PHP does not recognise
    keeps its backslash, and an interpolated or out-of-range value is not
    statically known — callers must treat that as indeterminate, never guess.
    """
    quote, body = literal[0], literal[1:-1]
    if quote == "'":
        return re.sub(r"\\(['\\])", r"\1", body), True
    out: list[str] = []
    known = True
    i = 0
    while i < len(body):
        char = body[i]
        if char == "$" and i + 1 < len(body) and (
            body[i + 1] == "{" or _PHP_IDENT_CHAR_RE.match(body[i + 1])
        ):
            known = False
            out.append(char)
            i += 1
            continue
        if char != "\\" or i + 1 >= len(body):
            out.append(char)
            i += 1
            continue
        nxt = body[i + 1]
        if nxt in _PHP_SIMPLE_ESCAPES:
            out.append(_PHP_SIMPLE_ESCAPES[nxt])
            i += 2
        elif nxt == "x":
            hex_digits = re.match(r"[0-9A-Fa-f]{1,2}", body[i + 2:i + 4])
            if hex_digits is None:
                out.append(char + nxt)
                i += 2
            else:
                out.append(chr(int(hex_digits.group(0), 16)))
                i += 2 + len(hex_digits.group(0))
        elif nxt in "01234567":
            octal = re.match(r"[0-7]{1,3}", body[i + 1:i + 4])
            assert octal is not None
            out.append(chr(int(octal.group(0), 8)))
            i += 1 + len(octal.group(0))
        elif nxt == "u" and body[i + 2:i + 3] == "{":
            close = body.find("}", i + 3)
            digits = body[i + 3:close] if close != -1 else ""
            try:
                out.append(chr(int(digits, 16)))
            except ValueError:
                known = False
                out.append(char + nxt)
                i += 2
                continue
            i = close + 1
        else:
            # PHP keeps the backslash of an unrecognised escape.
            out.append(char + nxt)
            i += 2
    return "".join(out), known


def _php_string_end(
    text: str, start: int, interpolation_aware: bool = False
) -> int | None:
    """Index just past the string literal starting at ``start`` (a quote), or
    None when it is unterminated. Heredoc/nowdoc are not string literals.

    With ``interpolation_aware`` a double-quoted literal also skips any
    complete ``{$...}`` expression it contains, so a quote inside that
    expression cannot be mistaken for the literal's end.
    """
    quote = text[start]
    i = start + 1
    while i < len(text):
        char = text[i]
        if char == "\\":
            i += 2
            continue
        if interpolation_aware and quote == '"' and (
                (char == "{" and text[i + 1:i + 2] == "$")
                or (char == "$" and text[i + 1:i + 2] == "{")
        ):
            # "{$" starts at the brace, "${" at the dollar
            span_end = _interpolation_end(
                text, i if char == "{" else i + 1, len(text)
            )
            if span_end == -1:
                return None
            i = span_end
            continue
        if char == quote:
            return i + 1
        i += 1
    return None


def _php_backtick_end(text: str, start: int) -> int | None:
    """Index just past the backtick SHELL-COMMAND string opening at
    ``start``, or None when it is unterminated.

    A backtick string is an interpolated string, not inert text: a
    backslash-backtick pair is an escaped delimiter, and ``${...}`` /
    ``{$...}`` inside it execute as PHP.
    """
    i = start + 1
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == "`":
            return i + 1
        i += 1
    return None


def _php_heredoc_end(text: str, start: int) -> tuple[int | None, bool]:
    """``(index just past the heredoc/nowdoc at ``start``, interpolates)``,
    or ``(None, False)``.

    A nowdoc (``<<<'EOT'``) is literal data; a heredoc (``<<<EOT`` and
    ``<<<"EOT"``) evaluates ``$name`` and ``{$...}``, which is code.
    """
    match = _PHP_HEREDOC_RE.match(text, start)
    if match is None:
        return None, False
    label = re.escape(match.group(2))
    # PHP accepts \n, \r\n and \r line endings, and re.M only knows \n, so
    # the line start is matched explicitly.
    terminator = re.compile(
        r"(?:\A|\r\n|\r|\n)[ \t]*" + label
        + r"(?![" + _PHP_IDENT_TAIL + r"])"
    )
    end_match = terminator.search(text, match.end())
    if end_match is None:
        return None, False
    # The label ends the heredoc; a following ';' or ',' belongs to the
    # enclosing statement and must stay visible to the statement tracker.
    return end_match.end(), match.group(1) != "'"


def _blank(out: list[str], start: int, end: int) -> None:
    """Blank [start, end) to spaces in the mask, preserving newlines so that
    offsets and line structure stay identical to the source."""
    for index in range(start, min(end, len(out))):
        if out[index] not in "\r\n":
            out[index] = " "


def _php_balanced_end(mask: str, start: int, limit: int | None = None) -> int:
    """End of a balanced bracket group whose opener is at ``start``.

    ``limit`` bounds the look-ahead and is checked as the scan advances, not
    after it: a malformed ``((((...`` group made a caller's per-keyword
    look-ahead quadratic when the only bound was applied to the result.
    Returns ``limit`` when the budget is exhausted, so the caller sees an
    unproven group rather than a real end.
    """
    pairs = {"[": "]", "(": ")", "{": "}"}
    opener = mask[start]
    closer = pairs[opener]
    stop = len(mask) if limit is None else min(len(mask), limit)
    depth = 0
    for i in range(start, stop):
        if mask[i] == opener:
            depth += 1
        elif mask[i] == closer:
            depth -= 1
            if depth == 0:
                return i + 1
    return stop


def _php_bracket_end(content: str, start: int) -> int:
    """End of the balanced ``[...]`` group opening at ``start``, skipping any
    string literal or comment inside it (used for PHP 8 ``#[Attribute]``)."""
    depth = 0
    i = start
    while i < len(content):
        char = content[i]
        if char in "'\"":
            end = _php_string_end(content, i)
            i = len(content) if end is None else end
            continue
        if content.startswith("//", i) or content[i] == "#":
            stop = i + 2 if content.startswith("//", i) else i + 1
            while stop < len(content) and content[stop] not in "\r\n":
                stop += 1
            i = stop
            continue
        if content.startswith("/*", i):
            close = content.find("*/", i + 2)
            i = len(content) if close == -1 else close + 2
            continue
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(content)


def _php_named_arg_after(mask: str, end: int) -> bool:
    """True when the token ending at ``end`` is a PHP 8 NAMED ARGUMENT
    (``inspect(require: 'x')``) rather than a language construct. A '::' is
    not one."""
    j = end
    while j < len(mask) and mask[j].isspace():
        j += 1
    return j < len(mask) and mask[j] == ":" and mask[j + 1:j + 2] != ":"


def _php_member_before(mask: str, index: int) -> bool:
    """True when the token at ``index`` is a member name — it follows
    ``->``, ``?->`` or ``::`` (whitespace and comments allowed between).

    Scans backwards over whitespace only, indexing the sequence in place: the
    lexer used to pass ``"".join(out[:i])``, copying the whole prefix for every
    member name and making a file full of them quadratic.  Accepts either a
    str mask or the lexer's mutable list.
    """
    j = index - 1
    while j >= 0 and mask[j] in " \t\r\n":
        j -= 1
    if j < 1:
        return False
    if mask[j] == ":":
        return mask[j - 1] == ":"
    if mask[j] == ">":
        return mask[j - 1] == "-"
    return False


def _php_balanced(mask: str) -> bool:
    """True when every bracket in the mask is matched.  PHP would raise a
    parse error otherwise, so nothing in the file can be trusted."""
    pairs = {")": "(", "]": "[", "}": "{"}
    stack: list[str] = []
    for char in mask:
        if char in "([{":
            stack.append(char)
        elif char in pairs:
            if not stack or stack.pop() != pairs[char]:
                return False
    return not stack


#: Both interpolation openers in ONE pattern: two separate searches made the
#: absent form rescan the tail for every interpolation, which was quadratic on
#: a literal full of them.
_INTERPOLATION_OPEN_RE = re.compile(r"\{\$|\$\{")


def _next_interpolation(content: str, start: int, end: int) -> int:
    """Index of the next ``{$`` or ``${`` in [start, end), or -1.

    A backslash-escaped ``${`` is LITERAL text in a PHP double-quoted string
    (``"\\${x}"`` prints ``${x}``), so it must not be read as interpolation.
    """
    search = start
    while search < end:
        match = _INTERPOLATION_OPEN_RE.search(content, search, end)
        if match is None:
            return -1
        if match.group(0) == "${" and _is_escaped(content, match.start()):
            search = match.end()
            continue
        return match.start()
    return -1


def _is_escaped(content: str, index: int) -> bool:
    """True when the character at ``index`` is preceded by an ODD number of
    backslashes, i.e. the last of them escapes it."""
    backslashes = 0
    cursor = index - 1
    while cursor >= 0 and content[cursor] == "\\":
        backslashes += 1
        cursor -= 1
    return backslashes % 2 == 1


def _interpolation_end(content: str, start: int, limit: int) -> int:
    """Index just past the ``}`` closing the ``{$`` that starts at ``start``,
    or -1 when it never closes within the literal.  Nested strings and
    comments are skipped, so a ``}`` inside them does not end the expression.
    """
    depth = 0
    i = start
    while i < limit:
        char = content[i]
        if char in "'\"":
            end = _php_string_end(content, i)
            if end is None or end > limit:
                return -1
            i = end
            continue
        if content.startswith("//", i) or content[i] == "#":
            stop = i + 2 if content.startswith("//", i) else i + 1
            while stop < limit and content[stop] not in "\r\n":
                stop += 1
            i = stop
            continue
        if content.startswith("/*", i):
            close = content.find("*/", i + 2)
            if close == -1 or close + 2 > limit:
                return -1
            i = close + 2
            continue
        if char == "`":
            # A backtick string is a SHELL COMMAND, not PHP source, but it is
            # still an interpolated string: skip the whole literal.
            backtick_end = _php_backtick_end(content, i)
            if backtick_end is None or backtick_end > limit:
                return -1
            i = backtick_end
            continue
        if content.startswith("<<<", i):
            heredoc_end, _interpolating = _php_heredoc_end(content, i)
            if heredoc_end is None or heredoc_end > limit:
                return -1
            i = heredoc_end
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


#: How deep nested string interpolation is followed. Real code never comes
#: close; the bound keeps a pathological literal from exhausting the stack
#: (an unbounded recursion took the whole check down with RecursionError).
_INTERPOLATION_DEPTH = 24
#: A byte in the code bitmap meaning "executable, but past the scan's
#: structural bound". The constant scanner must fail closed on it; the
#: suspicious scanner treats it as ordinary code, because PHP executes it.
_CODE_UNMODELLED = 2


def _reveal_interpolation(
    out: list[str], code: bytearray, content: str, start: int, end: int,
    depth: int = 0,
) -> None:
    """Reveal ``{$...}`` spans inside an interpolating literal as executable.

    PHP evaluates the expression inside curly-brace interpolation, so
    ``"{$GLOBALS['f']($y)}"`` calls a function and is code — a simple
    ``$name`` interpolation is only a value and stays hidden.  The
    expression is itself lexed, so a string literal nested inside it keeps
    its contents hidden: the bitmap must stay a statement about EXECUTABLE
    characters, not about text inside an interpolation.
    """
    i = start
    while True:
        found = _next_interpolation(content, i, end)
        if found == -1:
            return
        # "{$" starts at the brace, "${" starts at the dollar
        brace = found if content[found] == "{" else found + 1
        span_end = _interpolation_end(content, brace, end)
        if span_end == -1:
            return
        # the ${ ... } syntax itself is PHP
        for k in range(found, brace + 1):
            code[k] = 1
            out[k] = content[k]
        code[span_end - 1] = 1
        out[span_end - 1] = content[span_end - 1]
        inner_start, inner_end = brace + 1, span_end - 1
        inner = content[inner_start:inner_end]
        if inner and depth + 1 < _INTERPOLATION_DEPTH:
            sub_mask, sub_code, sub_valid, _php = _php_lex(
                "<?php " + inner, depth=depth + 1
            )
            for offset in range(len(inner)):
                code[inner_start + offset] = sub_code[6 + offset]
                out[inner_start + offset] = sub_mask[6 + offset]
            if not sub_valid:
                # The inner expression did not tokenize cleanly, so the scan
                # cannot say what it does. Mark it unmodelled rather than
                # copying a mask that says "nothing here".
                for offset in range(len(inner)):
                    code[inner_start + offset] = _CODE_UNMODELLED
        elif inner:
            # The recursion bound was reached. PHP still EVALUATES this
            # expression, so the region is executable even though the scan
            # cannot model it: it is marked with the UNMODELLED marker, which
            # the constant scanner treats as "indeterminate" rather than
            # silently reading the body as absent text.
            for offset in range(len(inner)):
                code[inner_start + offset] = _CODE_UNMODELLED
        i = span_end


def _php_code_mask(
    content: str, keep_strings: bool = False
) -> tuple[str, bool, bool]:
    """``(mask, lexically-valid, ends-in-php-mode)`` — see _php_lex."""
    mask, _code, valid, in_php = _php_lex(content, keep_strings)
    return mask, valid, in_php


def _php_code_flags(content: str) -> tuple[bytearray, bool]:
    """``(flags, lexically-valid)`` — one byte per character, 1 where the
    character is EXECUTABLE PHP.

    The explicit answer a content scanner needs, rather than inferring "code"
    from the mask's spaces (which cannot distinguish a blanked literal space
    from a real one).  ``valid`` is False when the file ends inside a string,
    comment or heredoc: PHP would raise a parse error, so no signature in it
    is trustworthy and a caller must not report one.
    """
    _mask, code, valid, _in_php = _php_lex(content)
    return code, valid


def _php_lex(
    content: str, keep_strings: bool = False, depth: int = 0, *,
    open_tags: list[int] | None = None,
    php_mask: bytearray | None = None,
) -> tuple[str, bytearray, bool, bool]:
    """``(mask, lexically-valid, ends-in-php-mode)`` — a same-length copy of
    ``content`` in which every non-code byte is blanked: inline HTML,
    open/close tags, string bodies, comments, heredocs and attributes.

    ``open_tags`` receives the offset of every REAL ``<?php``/``<?=`` open
    tag (not a tag-looking sequence inside HTML text cannot happen, but a
    tag inside a PHP string/comment is not a tag at all).  ``php_mask`` is a
    bytearray filled with 1 for every character inside a PHP segment
    (strings/comments included, tags excluded), so a consumer can tell PHP
    mode from inline HTML without re-lexing a prefix.

    This is what makes the constant scan PHP-aware: a ``//`` inside
    'https://example.com', a ``define(...)`` inside a string, or a ``#`` in a
    password cannot be mistaken for code. A regex over raw wp-config.php text
    gets all three wrong.

    lexically-valid is False when the file ends inside a string, comment or
    heredoc — a parse error, so nothing after it can be trusted and the
    constant state is indeterminate.

    keep_strings leaves string BODIES readable (for searching a path that
    lives inside a literal) while still blanking comments and HTML. In that
    mode the mask is for literal substring search only: brackets inside a
    string are no longer hidden, so it must not drive nesting decisions.
    """
    def _mark(start: int, end: int) -> None:
        if php_mask is not None and end > start:
            php_mask[start:end] = b"\x01" * (end - start)

    out = list(content)
    length = len(content)
    # Explicit "this character is executable PHP" bitmap.  Inferring it from
    # the mask's spaces cannot tell a blanked literal space from a real one,
    # so a profile pattern matching a run of spaces inside a string would be
    # reported as code.
    code = bytearray(length)
    i = 0
    in_php = False
    while i < length:
        if not in_php:
            match = _PHP_OPEN_TAG_RE.search(content, i)
            if match is None:
                _blank(out, i, length)
                break
            _blank(out, i, match.start())
            # The open tag itself is not code: blank it, or its 'php' would
            # read as an identifier and break statement tracking.
            _blank(out, match.start(), match.end())
            if open_tags is not None:
                open_tags.append(match.start())
            i = match.end()
            in_php = True
            continue
        _mark(i, i + 1)
        if content.startswith("?>", i):
            # PHP's close tag implies a statement terminator, so the mask
            # carries a ';' (same offsets) to keep statement tracking honest.
            out[i] = ";"
            out[i + 1] = " "
            in_php = False
            i += 2
            continue
        if content[i] in "'\"":
            end = _php_string_end(content, i, interpolation_aware=True)
            if end is None:
                if not keep_strings:
                    _blank(out, i + 1, length)
                _mark(i, length)
                return "".join(out), code, False, in_php
            _mark(i, end)
            if not keep_strings:
                _blank(out, i + 1, end - 1)
            if content[i] == '"':
                # Single quotes do NOT interpolate; only double quotes do.
                _reveal_interpolation(out, code, content, i, end, depth)
            i = end
            continue
        if content[i] == "`":
            close = _php_backtick_end(content, i)
            if close is None:
                _blank(out, i, length)
                _mark(i, length)
                return "".join(out), code, False, in_php
            _mark(i, close)
            _blank(out, i, close)
            _reveal_interpolation(out, code, content, i, close, depth)
            i = close
            continue
        if content.startswith("<<<", i):
            end, interpolating = _php_heredoc_end(content, i)
            if end is not None:
                _mark(i, end)
                _blank(out, i, end)
                if interpolating:
                    # A nowdoc (<<<'EOT') is literal data like a single-quoted
                    # string; a heredoc evaluates {$...} and $name.
                    _reveal_interpolation(out, code, content, i, end, depth)
                i = end
                continue
            _mark(i, length)
            return "".join(out), code, False, in_php
        if content.startswith("#[", i):
            end = _php_bracket_end(content, i + 1)
            if end >= length:
                _mark(i, length)
                return "".join(out), code, False, in_php
            _mark(i, end)
            _blank(out, i, end)
            i = end
            continue
        if content.startswith("//", i) or content[i] == "#":
            stop = i + 2 if content.startswith("//", i) else i + 1
            while stop < length and content[stop] not in "\r\n" \
                    and not content.startswith("?>", stop):
                stop += 1
            _mark(i, stop)
            _blank(out, i, stop)
            if stop < length and content.startswith("?>", stop):
                # '?>' ends the comment AND implies a statement terminator.
                out[stop] = ";"
                out[stop + 1] = " "
                in_php = False
                i = stop + 2
                continue
            i = stop
            continue
        if content.startswith("/*", i):
            close = content.find("*/", i + 2)
            if close == -1:
                _blank(out, i, length)
                _mark(i, length)
                return "".join(out), code, False, in_php
            _mark(i, close + 2)
            _blank(out, i, close + 2)
            i = close + 2
            continue
        word = _PHP_IDENT_RE.match(content, i)
        if word is not None:
            # Consume the WHOLE identifier in one step. Re-testing at every
            # character (and lower-casing each remainder) made one long
            # token quadratic: a 1 MiB single-line file took minutes, long
            # enough to defeat the scan deadline, which is only checked per
            # batch.
            end = word.end()
            _mark(i, end)
            if content[i:end].lower() == "__halt_compiler" \
                    and not _php_member_before(out, i) \
                    and not (i and content[i - 1] == "$"):
                _blank(out, i, length)
                break
            code[i:end] = b"\x01" * (end - i)
            i = end
            continue
        code[i] = 1
        i += 1
    mask = "".join(out)
    return mask, code, _php_balanced(mask), in_php


#: Guard against a pathological ``((((...))))`` value: each peel layer is a
#: full balance scan, so unbounded nesting is quadratic.
_MAX_PAREN_DEPTH = 64


def _php_peel_parens(expr: str) -> str:
    """Strip fully-enclosing parentheses: ``((false))`` is the literal false.
    Counted on the raw fragment (a bare value has no PHP open tag, so the
    file-level mask would blank all of it)."""
    text = expr.strip()
    # Each layer costs a full balance scan, so the nesting is capped: a value
    # wrapped this deeply is left as-is, which _php_literal reports as unknown.
    for _ in range(_MAX_PAREN_DEPTH):
        if not (text.startswith("(") and text.endswith(")")):
            break
        if _php_balanced_end(text, 0) != len(text):
            break
        text = text[1:-1].strip()
    return text


#: Array nesting is evaluated recursively and each level re-lexes, so a deeply
#: nested VALID literal could recurse until the interpreter gives up. Past this
#: depth the value is simply unknown.
_MAX_LITERAL_DEPTH = 32


def _php_literal(expr: str, depth: int = 0) -> tuple[Any, bool]:
    """A statically known PHP literal, else ``(None, False)`` (unknown)."""
    if depth > _MAX_LITERAL_DEPTH:
        return None, False
    text = _php_peel_parens(_php_strip_comments(expr))
    if not text:
        return None, False
    if len(text) >= 2 and text[0] in "'\"" and _php_string_end(text, 0) == len(text):
        return _php_decode_string(text)
    lowered = text.lower()
    if lowered == "true":
        return True, True
    if lowered == "false":
        return False, True
    if lowered == "null":
        return None, True
    if _PHP_NUMBER_RE.fullmatch(text):
        negative = text.startswith("-")
        digits = text.lstrip("+-").replace("_", "")
        try:
            lowered = digits.lower()
            if lowered.startswith(("0b", "0o", "0x")):
                base = {"0b": 2, "0o": 8, "0x": 16}[lowered[:2]]
                number: Any = int(digits[2:], base)
            elif any(char in digits for char in ".eE"):
                number = float(digits)
            else:
                number = int(digits)
        except ValueError:
            return None, False
        return (-number if negative else number), True
    if lowered in ("array()", "[]"):
        return [], True
    # Emptiness is decided on the code mask, so `array( )` and `[ /*c*/ ]`
    # are falsey and a literal with any content is truthy.
    if lowered.startswith("array(") and lowered.endswith(")"):
        inner = text[6:-1]
    elif text.startswith("[") and text.endswith("]"):
        inner = text[1:-1]
    else:
        return None, False
    blanked, inner_valid, _ = _php_code_mask("<?php " + inner)
    if not inner_valid or not _php_balanced(blanked):
        return None, False
    if not blanked.strip():
        return [], True
    # Emptiness alone is not enough: every element is evaluated BEFORE
    # define() is called, so `[exit]` ends the script without defining
    # anything. Only an array of known literals is a known value.
    for element in _php_array_elements(blanked):
        value, element_known = _php_literal(element, depth + 1)
        if not element_known:
            return None, False
    return [None], True


def _php_strip_comments(text: str) -> str:
    """Remove PHP comments from an expression span, preserving string
    literals. Anything that does not tokenize cleanly is returned unchanged,
    so the caller still fails closed rather than guessing."""
    out: list[str] = []
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char in "'\"":
            end = _php_string_end(text, index)
            if end is None:
                return text
            out.append(text[index:end])
            index = end
            continue
        if text.startswith("//", index) or char == "#":
            stop = index + 2 if text.startswith("//", index) else index + 1
            while stop < length and text[stop] not in "\r\n":
                stop += 1
            out.append(" ")
            index = stop
            continue
        if text.startswith("/*", index):
            close = text.find("*/", index + 2)
            if close == -1:
                return text
            out.append(" ")
            index = close + 2
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _php_array_elements(inner: str) -> list[str]:
    """Top-level ``,``-separated elements of a blanked array body."""
    elements: list[str] = []
    depth = 0
    start = 0
    for index, char in enumerate(inner):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            elements.append(inner[start:index])
            start = index + 1
    tail = inner[start:]
    if tail.strip():
        elements.append(tail)
    return elements


def _php_truthy(value: Any) -> bool:
    """PHP's boolean cast: false/null/0/0.0/'0'/''/[] are falsey, and
    nothing else is."""
    if value is None or value is False:
        return False
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value not in ("", "0")
    return bool(value)


def _php_word_before(mask: str, index: int) -> str:
    """The identifier ADJACENT to ``index`` in the mask, or ''.

    Only whitespace may sit between them. A delimiter (``;``, ``{``, ``}``,
    ``)``, ``,``) ends the statement, so the identifier before it belongs to a
    different statement: without this, the ``function`` in
    ``$f = function () {}; require ...`` would be read as the previous word of
    a later ``require``.
    """
    j = index - 1
    while j >= 0 and mask[j] in " \t\r\n":
        j -= 1
    if j < 0 or not _PHP_IDENT_CHAR_RE.match(mask[j]):
        return ""
    end = j + 1
    while j >= 0 and _PHP_IDENT_CHAR_RE.match(mask[j]):
        j -= 1
    return mask[j + 1:end]


def _php_expr_end(mask: str, start: int, stops: str) -> int:
    """End of a PHP expression starting at ``start``, stopping at a top-level
    character from ``stops``. Strings/comments are already blanked, so
    delimiters inside them cannot confuse the nesting count."""
    depth = 0
    i = start
    while i < len(mask):
        char = mask[i]
        if char in "([":
            depth += 1
        elif char in ")]":
            if depth == 0 and char in stops:
                return i
            depth = max(0, depth - 1)
        elif depth == 0 and char in stops:
            return i
        i += 1
    return len(mask)


def _php_parse_define(
    content: str, mask: str, paren: int
) -> tuple[str | None, int, int]:
    """Parse ``define(<name>, <expr>...)`` with ``paren`` on the opening '('.

    Returns ``(constant-name-or-None, value-start, value-end)``. A name of
    None is a real define() whose name PHP computes at runtime — a
    concatenation, a variable, an interpolated literal — so the scan can no
    longer prove which constant it defines and the state is indeterminate.
    That is deliberately different from "not a define() call".
    """
    i = paren + 1
    while i < len(mask) and mask[i].isspace():
        i += 1
    if i >= len(mask) or content[i] not in "'\"":
        return None, i, i
    name_end = _php_string_end(content, i)
    if name_end is None:
        return None, i, i
    name, known = _php_decode_string(content[i:name_end])
    j = name_end
    while j < len(mask) and mask[j].isspace():
        j += 1
    if j >= len(mask) or mask[j] != ",":
        return None, i, name_end
    value_start = j + 1
    value_end = _php_expr_end(mask, value_start, ",)")
    # `define(NAME, VALUE)` and `define(NAME, VALUE, CASE)` are the only
    # valid forms. A longer top-level list raises ArgumentCountError before
    # anything is defined, so it cannot prove a value at all.
    arguments = 2
    cursor = value_end
    while cursor < len(mask) and mask[cursor] in ",)":
        if mask[cursor] == ")":
            break
        cursor = _skip_ws(mask, cursor + 1)
        if mask[cursor:cursor + 1] == ")":
            break      # a legal trailing comma, not another argument
        if mask[cursor:cursor + 3] == "...":
            # `...$args` expands at runtime, so the real argument count is not
            # the syntactic one: PHP can raise ArgumentCountError before it
            # defines anything.
            return None, value_start, value_end
        arguments += 1
        if arguments > 3:
            return None, value_start, value_end
        third_start = cursor
        cursor = _php_expr_end(mask, cursor, ",)")
        if arguments == 3 and mask[third_start:cursor] != "true" \
                and mask[third_start:cursor] != "false":
            # The third argument is evaluated too, so `define('X', true, exit)`
            # ends the script before the constant exists. Only a literal
            # boolean cast can be proven; anything else is indeterminate.
            case_value, case_known = _php_literal(
                content[third_start:cursor]
            )
            if not case_known or isinstance(case_value, list):
                # An array cannot be coerced to bool for an internal function
                # parameter: PHP raises TypeError before defining anything.
                return None, value_start, value_end
    return name if known else None, value_start, value_end


def _skip_ws(mask: str, index: int) -> int:
    """Index of the next non-whitespace character at or after ``index``."""
    while index < len(mask) and mask[index] in " \t\r\n":
        index += 1
    return index


def _brace_follows(mask: str, start: int) -> bool:
    """True when the next significant token at ``start`` is an opening brace
    rather than a ';' — the difference
    between ``declare(ticks=1) {`` and ``declare(ticks=1);``.  A balanced
    parenthesised argument list is skipped as one unit.

    The look-ahead is BOUNDED: an unterminated header with no delimiter would
    otherwise rescan the rest of the file for every keyword. A realistic
    ``declare(ticks=1)`` or ``namespace Vendor\\Sub`` header is far shorter, so
    an over-budget header is unproven, which is the fail-safe direction.
    """
    j = start
    budget = 64
    while j < len(mask) and budget > 0:
        budget -= 1
        char = mask[j]
        if char in " \t\r\n":
            j += 1
        elif char == "(":
            closing = _php_balanced_end(mask, j, j + budget)
            if closing >= j + budget:
                return False    # beyond the budget: unproven, fail-safe
            j = closing
        elif _PHP_IDENT_RE.match(mask, j) or char == "\\":
            j += 1
        else:
            return char == "{"
    return False




def _php_find_const(content: str, name: str) -> tuple[str, tuple[int, int] | None]:
    """Locate the FIRST definition of ``name`` that PHP would execute, as
    ``(state, value-span)``.

    Only real code counts — never a string, comment, heredoc, attribute or
    inline-HTML region, never a class/interface/trait/enum member — and the
    name match is case-sensitive, as PHP constant names are. A definition is
    only trusted when it is an unconditional statement (brace depth 0 at a
    statement start); ``if (x) define(...)``, ``fn() => define(...)`` and a
    define() with a computed name are all indeterminate. The first definition
    governs: a later duplicate only earns a PHP warning.

    state is "truthy"/"falsey" with the value's exact span, "unknown" when PHP
    decides it at runtime, or "absent" when there is none. Callers must treat
    UNKNOWN as indeterminate, never as "hardened" or "safe".
    """
    mask, lexically_valid, _ = _php_code_mask(content)
    if not lexically_valid:
        return "unknown", None
    code_flags, _valid = _php_code_flags(content)
    if any(byte == _CODE_UNMODELLED for byte in code_flags):
        # Executable text the scanner could not model (interpolation past its
        # structural bound, or an inner expression that did not tokenize).
        # PHP runs it, so every constant state is indeterminate.
        return "unknown", None
    # One linear pass over the file, then a running depth: rescanning the
    # prefix per identifier made a 24 KB config take seconds.
    alt_marks = _alt_syntax_marks(mask)
    # delta 0 is a statement boundary that is not a block: a label, a `case`,
    # and `declare(ticks=1):`, whose body runs unconditionally.
    block_colons = {position - 1 for position, _ in alt_marks}
    alt_index = 0
    alt_depth = 0
    i = 0
    depth = 0
    type_bodies = 0
    pending_type = False
    pending_ns_block = False
    pending_global_ns = False
    pending_declare = False
    pending_fn_decl = False
    fn_bodies = 0
    ns_bodies = 0
    ns_unbracketed = False
    stmt_start = True
    may_not_reach = False
    runtime_define = False
    # One entry per open `fn (...) => expression`, holding the delimiter depth
    # its body began at. A scalar lost the enclosing scope when an arrow nested
    # inside another arrow ended.
    arrow_stack: list[int] = []
    delim = 0                  # every delimiter, not just braces
    blocks: list[str] = []
    while i < len(mask):
        char = mask[i]
        if char in ";{}":
            stmt_start = True
            if char == ";":
                # Every pending header is statement-scoped: `declare(ticks=1);`
                # and an abstract `function f(): void;` end here, so a later
                # brace is not theirs.
                pending_fn_decl = False
            if arrow_stack and char in ";," \
                    and delim == arrow_stack[-1]:
                # A `;` or comma at the arrow's own depth ends that body: a
                # closure inside it has its own, and a sibling `exit` in the
                # same statement is a real file-scope exit.
                arrow_stack.pop()
            if char == "{":
                if pending_global_ns:
                    # `namespace { ... }` is global scope, not a nested block:
                    # a const inside it IS a top-level global const.
                    kind = "globalns"
                    pending_global_ns = False
                    pending_type = False
                    # An explicit global block RESUMES global scope, so an
                    # unqualified `define()` inside it is the built-in again.
                    ns_unbracketed = False
                elif pending_ns_block:
                    # `namespace Foo { ... }` only changes NAME resolution
                    # (already tracked); its statements are still top level.
                    kind = "ns"
                    pending_ns_block = False
                    ns_bodies += 1
                elif pending_declare:
                    # `declare(ticks=1) { ... }` body executes unconditionally.
                    kind = "declare"
                    pending_declare = False
                elif pending_fn_decl:
                    # A function/closure body: an exit inside it cannot end the
                    # file, so it must not taint later definitions.
                    kind = "fn"
                    pending_fn_decl = False
                    fn_bodies += 1
                    depth += 1
                else:
                    kind = "type" if pending_type else ""
                    if kind == "type":
                        type_bodies += 1
                    pending_type = False
                    depth += 1
                blocks.append(kind)
            elif char == "}":
                if blocks:
                    kind = blocks.pop()
                    if kind == "type":
                        type_bodies = max(0, type_bodies - 1)
                    elif kind == "fn":
                        fn_bodies = max(0, fn_bodies - 1)
                    elif kind == "ns":
                        ns_bodies = max(0, ns_bodies - 1)
                depth = max(0, depth - 1)
            i += 1
            continue
        if char in "()[]":
            # Delimiter depth for arrow scopes; braces are counted above.
            delim += 1 if char in "([" else -1
            if delim < 0:
                delim = 0
            while arrow_stack and delim < arrow_stack[-1]:
                arrow_stack.pop()    # the arrow's enclosing group closed
            i += 1
            continue
        if char == ",":
            if arrow_stack and delim == arrow_stack[-1]:
                arrow_stack.pop()
            i += 1
            continue
        if char.isspace():
            i += 1
            continue
        if char == ":" and i in block_colons:
            # The ':' of `if (...):` / `declare(...):` ends the header, so the
            # next statement starts fresh.
            stmt_start = True
            i += 1
            continue
        if i and mask[i - 1] == "$":
            # A VARIABLE, not a keyword — but `$eval(...)` can still hold the
            # construct, so a call of that name still taints the file.
            word = _PHP_IDENT_RE.match(mask, i)
            if word is not None and word.group(0).lower() in _PHP_RUNTIME_DEFINE \
                    and mask[_skip_ws(mask, word.end()):_skip_ws(mask, word.end()) + 1] == "(":
                runtime_define = True
            i += 1
            continue
        word = _PHP_IDENT_RE.match(mask, i)
        if word is None:
            # A namespace separator does not begin a new statement, so a
            # fully-qualified `\define(...)` is still a statement start.
            if char != "\\":
                stmt_start = False
            i += 1
            continue
        while alt_index < len(alt_marks) and alt_marks[alt_index][0] <= i:
            alt_depth += alt_marks[alt_index][1]
            alt_index += 1
        unconditional = (
            stmt_start
            and depth == 0
            and not may_not_reach
            and alt_depth <= 0
        )
        stmt_start = False
        token = word.group(0)
        lowered = token.lower()
        prev = _php_word_before(mask, i).lower()
        is_member = _php_member_before(mask, i)
        callable_ctx = not is_member and prev not in ("function", "new")
        if lowered in _PHP_TYPE_KEYWORDS and not is_member and prev != "function":
            # `new class { ... }` is an anonymous type body too.
            pending_type = True
        if not is_member and lowered == "function" and prev != "function":
            # Only a brace-bodied function declaration owns the next `{`;
            # `fn(...) =>` has none, and `use function x;` is an import.
            pending_fn_decl = True
        if lowered in _PHP_RUNTIME_DEFINE and not is_member \
                and not _php_named_arg_after(mask, word.end()) \
                and prev not in ("function", "new") \
                and mask[_skip_ws(mask, word.end()):_skip_ws(mask, word.end()) + 1] \
                == "(":
            # A CALL, not an assignment: `$eval = "x";` taints nothing, while
            # `$eval(...)` can still hold the construct. A runtime definition
            # anywhere in the file makes every state indeterminate — PHP may
            # define the constant before, after or instead of anything the
            # scan can see.
            runtime_define = True
        if depth == 0 and lowered == "declare" and not is_member:
            after = _skip_ws(mask, word.end())
            if mask[after:after + 1] == "(":
                pending_declare = _brace_follows(mask, word.end())
        if depth == 0 and lowered == "namespace" and not is_member \
                and prev not in ("function", "new"):
            # A declaration is `namespace Name;`, `namespace Name {` or
            # `namespace {`. `namespace\foo()` is a qualified call, not one.
            # The remainder is examined by INDEX: slicing the tail here made a
            # namespace-heavy 1 MiB config quadratic.
            after = _skip_ws(mask, word.end())
            head = mask[after:after + 1]
            if head == "\\":
                pass
            elif head == "{":
                # A bare `namespace {` is the GLOBAL namespace block: its
                # contents are top-level, so depth must not grow.
                pending_global_ns = True
            elif _PHP_IDENT_RE.match(mask, after) is not None:
                pending_ns_block = _brace_follows(mask, word.end())
                ns_unbracketed = not pending_ns_block
            else:
                ns_unbracketed = True
        # A file-scope exit anywhere — including inside an ordinary top-level
        # if/loop/try block — can precede the definition. Inside a function,
        # closure or class body it cannot, so those scopes are excluded.
        if type_bodies == 0 and fn_bodies == 0 and not arrow_stack \
                and not is_member \
                and lowered in _PHP_EXIT_KEYWORDS \
                and prev not in ("function",) \
                and not _php_named_arg_after(mask, word.end()):
            may_not_reach = True
        if type_bodies == 0 and fn_bodies == 0 and not arrow_stack \
                and not is_member \
                and lowered == "goto" \
                and not _php_named_arg_after(mask, word.end()):
            # A jump may bypass the definition entirely.
            may_not_reach = True
        if type_bodies == 0 and fn_bodies == 0 and not is_member \
                and lowered == "fn" and prev != "function" \
                and not _php_named_arg_after(mask, word.end()):
            arrow_stack.append(delim)
        in_ns_block = ns_bodies > 0
        if type_bodies == 0 and lowered == "define" and callable_ctx:
            j = word.end()
            while j < len(mask) and mask[j].isspace():
                j += 1
            if j < len(mask) and mask[j] == "(":
                # Inside a namespace, `define(...)` may be a user function; only
                # the global built-in is definitive, and `\define(...)` is the
                # explicit way to reach it.
                back = i - 1
                while back >= 0 and mask[back].isspace():
                    back -= 1
                global_call = back < 0 or mask[back] == "\\"
                if (ns_unbracketed or in_ns_block) and not global_call:
                    return "unknown", None
                found, start, end = _php_parse_define(content, mask, j)
                if found is None:
                    return "unknown", None
                if runtime_define:
                    # The eval may define this constant BEFORE the define the
                    # scan can see, and the first definition wins.
                    return "unknown", None
                if end >= len(mask) or mask[end] not in ",)":
                    return "unknown", None  # unterminated call: a parse error
                if found == name:
                    return _php_state_of(content[start:end], unconditional), \
                        (start, end)
        elif type_bodies == 0 and lowered == "const" and callable_ctx:
            j = word.end()
            # A namespaced `const` is not the global WordPress constant.
            namespaced = ns_unbracketed or in_ns_block
            while True:
                while j < len(mask) and mask[j].isspace():
                    j += 1
                ident = _PHP_IDENT_RE.match(mask, j)
                if ident is None:
                    break
                k = ident.end()
                while k < len(mask) and mask[k].isspace():
                    k += 1
                if k >= len(mask) or mask[k] != "=":
                    break
                end = _php_expr_end(mask, k + 1, ";,")
                if end >= len(mask) or mask[end] not in ";,":
                    return "unknown", None  # unterminated declaration
                if ident.group(0) == name:
                    if namespaced:
                        # A namespaced `const RELOCATE` does NOT define the
                        # global constant, so keep looking for the real one.
                        break
                    if runtime_define:
                        return "unknown", None
                    return _php_state_of(content[k + 1:end], unconditional), \
                        (k + 1, end)
                j = end + 1
                if end < len(mask) and mask[end] == ";":
                    break
        i = word.end()
    # No definition found, but the file can define one at runtime, so the
    # honest answer is "unknown" — never "absent".
    return ("unknown", None) if runtime_define else ("absent", None)


def _php_state_of(expr: str, unconditional: bool) -> str:
    """The state of one constant value expression found at an unconditional
    statement position."""
    value, known = _php_literal(expr)
    if not known or not unconditional:
        return "unknown"
    return "truthy" if _php_truthy(value) else "falsey"


def _php_const_state(content: str, name: str) -> str:
    """The ACTIVE state of a wp-config.php constant: truthy/falsey/absent/unknown.

    WordPress executes wp-config.php; it never greps it. The toolkit cannot
    execute it, so _php_find_const scans the PHP properly and PHP's exact
    truthiness then applies (true/1/-1/non-empty string except '0' are
    truthy; false/null/0/0.0/'0'/''/[] are falsey).
    """
    return _php_find_const(content, name)[0]


def _php_rewrite_const(content: str, name: str, value: str) -> str | None:
    """``content`` with the value of the definition _php_find_const resolved
    replaced by ``value``, or None when that value is not a statically known
    literal (never rewrite a decision PHP makes at runtime)."""
    state, span = _php_find_const(content, name)
    if span is None or state == "unknown":
        return None
    start, end = span
    original = content[start:end]
    lead = original[:len(original) - len(original.lstrip())]
    trail = original[len(original.rstrip()):]
    return content[:start] + lead + value + trail + content[end:]


def _php_minor(version: str) -> tuple[int, int] | None:
    """The (major, minor) of an "X.Y(.Z...)" PHP version string; None
    when unparseable.

    Only the first two dot-separated components matter — the support
    tier is a property of the MINOR — and both must be plain decimal
    digits, so "8" (no minor), "x.y", "8.x.1" or "PHP 8.3" are unknown,
    while a distro-suffixed release ("8.1.2-1ubuntu2.14") still parses.
    The tuple keeps the comparison numeric-aware: "8.10" > "8.9", never
    a float.
    """
    parts = version.split(".")
    if len(parts) < 2:
        return None
    major, minor = parts[0], parts[1]
    if not (major.isdecimal() and minor.isdecimal()):
        return None
    return (int(major), int(minor))


# ------------------------------------------------------------------- checks


@register_check("security.xmlrpc", applies=("ftp",))
def check_security_xmlrpc(data: AuditData, settings: Settings) -> list[Finding]:
    """xmlrpc.php answering system.listMethods => enabled xmlrpc surface.

    POST {site}/xmlrpc.php with the minimal methodCall body (content-type
    text/xml); 200 + "<methodResponse>" in the body => finding. Anything
    else — 404/405, the plain "XML-RPC server accepts POST requests only"
    page, a network failure, no probe — silent.
    """
    probe = data.probe
    if probe is None:
        return []
    response = _post(
        probe,
        f"{probe.site}/{_XMLRPC_ENDPOINT}",
        deadline=data.deadline,
        data=_XMLRPC_PROBE,
        headers={"Content-Type": "text/xml"},
    )
    if response is None or response.status_code != 200:
        return []
    if _METHOD_RESPONSE_MARKER not in response.text:
        return []
    return [
        Finding(
            category="security.xmlrpc",
            name="xmlrpc-enabled",
            detail=(
                "xmlrpc.php answered a system.listMethods call "
                "(brute-force and login-amplification surface)"
            ),
            risk="medium",
            fix="block xmlrpc.php in .htaccess (wpt harden)",
        )
    ]


@register_check("security.rest_users", applies=("ftp",))
def check_security_rest_users(data: AuditData, settings: Settings) -> list[Finding]:
    """REST /wp/v2/users listing accounts => user enumeration.

    GET without following redirects; 200 + a JSON LIST with at least one
    item carrying a non-empty string "slug" => finding (count = enumerated
    users, detail lists their slugs sorted). 401/403/404/redirect, a
    non-list body, a slug-less list, non-JSON, a network failure or no
    probe — silent.
    """
    probe = data.probe
    if probe is None:
        return []
    # WordPress dispatches BOTH the pretty permalink and the public
    # ``rest_route`` query var (``/?rest_route=/wp/v2/users``; the encoded
    # ``%2F`` spelling is the same request after PHP's query decoder).  A
    # harden block that only matched the path left the audit green on a
    # site that was still enumerable through the fallback.
    routes = (
        (f"{probe.site}/{_REST_USERS_PATH}",
         f"/{_REST_USERS_PATH}"),
        (f"{probe.site}/?rest_route={_REST_USERS_ROUTE}",
         f"/?rest_route={_REST_USERS_ROUTE}"),
        (f"{probe.site}/?rest_route=%2Fwp%2Fv2%2Fusers",
         "/?rest_route=%2Fwp%2Fv2%2Fusers"),
    )
    for url, shown in routes:
        response = _get(probe, url, deadline=data.deadline,
                        allow_redirects=False)
        if response is None or response.status_code != 200:
            continue
        try:
            payload = response.json()
        except ValueError:
            continue
        if not isinstance(payload, list):
            continue
        slugs = sorted(
            item["slug"]
            for item in payload
            if isinstance(item, dict)
            and isinstance(item.get("slug"), str)
            and item["slug"]
        )
        if not slugs:
            continue
        return [
            Finding(
                category="security.rest_users",
                name="rest-users",
                detail=(
                    f"user enumeration via REST: {shown} lists "
                    f"{len(slugs)} user(s): {_excerpt(slugs)}"
                ),
                count=len(slugs),
                risk="medium",
                fix="block REST /wp/v2/users (pretty and ?rest_route=) in "
                    ".htaccess (wpt harden)",
            )
        ]
    return []


@register_check("security.author_scan", applies=("ftp",))
def check_security_author_scan(data: AuditData, settings: Settings) -> list[Finding]:
    """?author=1 redirecting to an /author/ archive => user enumeration.

    GET {site}/?author=1 without following redirects; a 3xx whose Location
    header contains "/author/" => finding (WordPress leaks the account
    slug through the author archive redirect). 200/404, a redirect
    elsewhere, a redirect without a Location, a network failure or no
    probe — silent.
    """
    probe = data.probe
    if probe is None:
        return []
    response = _get(
        probe, f"{probe.site}/{_AUTHOR_QUERY}",
        deadline=data.deadline, allow_redirects=False,
    )
    if response is None or not 300 <= response.status_code < 400:
        return []
    location = response.headers.get("Location")
    if not location or "/author/" not in location:
        return []
    return [
        Finding(
            category="security.author_scan",
            name="author-scan",
            detail=(
                "user enumeration via author redirect: "
                f'"?author=1" redirects to {location}'
            ),
            risk="medium",
            fix="block ?author= scans in .htaccess (wpt harden)",
        )
    ]


@register_check("security.wp_config_perms", applies=("ftp",))
def check_security_wp_config_perms(
    data: AuditData, settings: Settings
) -> list[Finding]:
    """wp-config.php readable beyond the owner => the DB credentials with it.

    bridge ``fileperms`` for "wp-config.php"; a PRESENT permission string
    other than "0600" (e.g. "0644" — group/world readable) => finding, the
    only high-risk one here. "0600" silent; None (absent file), a failed
    bridge call or a malformed payload silent.
    """
    probe = data.probe
    if probe is None:
        return []
    payload = probe.bridge_call("fileperms", paths=[_WP_CONFIG])
    if not isinstance(payload, dict):
        return []
    paths = payload.get("paths")
    if not isinstance(paths, dict):
        return []
    perms = paths.get(_WP_CONFIG)
    if not isinstance(perms, str) or not perms:
        return []
    if perms == _SECURE_WP_CONFIG_PERMS:
        return []
    return [
        Finding(
            category="security.wp_config_perms",
            name="wp-config-perms",
            detail=(
                f"wp-config.php permissions {perms} "
                "(readable beyond the owning account)"
            ),
            risk="high",
            fix="chmod 0600 wp-config.php",
        )
    ]


@register_check("security.disallow_file_edit", applies=("ftp",))
def check_security_disallow_file_edit(
    data: AuditData, settings: Settings
) -> list[Finding]:
    """DISALLOW_FILE_EDIT not ACTIVE in wp-config.php => wp-admin can edit
    plugin/theme source (one slip from a full compromise).

    wp-config.php text via probe.read_file, scanned as PHP (see
    _php_const_state): only an ACTIVE truthy definition hardens. A
    commented-out line, a string define, a differently-cased name or
    ``define(..., false)`` does NOT. Disable-file-mods also disables the
    editor, so an active truthy DISALLOW_FILE_MODS suppresses this finding.
    Unreadable/absent file or no probe — silent (cannot read, cannot judge).
    A value PHP decides at runtime (a non-literal, or a conditional block)
    is INDETERMINATE: reported as unverifiable rather than asserted absent,
    so a hardened site is never silently called safe nor wrongly called open.
    """
    probe = data.probe
    if probe is None:
        return []
    content = probe.read_file(_WP_CONFIG)
    if content is None:
        return []
    state = _php_const_state(content, _DISALLOW_FILE_EDIT)
    mods = _php_const_state(content, _DISALLOW_FILE_MODS)
    if state == "truthy" or mods == "truthy":
        return []
    if state == "unknown" or mods == "unknown":
        return [
            Finding(
                category="security.disallow_file_edit",
                name="disallow-file-edit-unverifiable",
                detail=(
                    "DISALLOW_FILE_EDIT or DISALLOW_FILE_MODS in wp-config.php "
                    "is set to a value this static scan cannot resolve "
                    "(conditional or non-literal); hardening could not be "
                    "verified"
                ),
                risk="medium",
                fix="set DISALLOW_FILE_EDIT unconditionally in wp-config.php",
            )
        ]
    return [
        Finding(
            category="security.disallow_file_edit",
            name="disallow-file-edit",
            detail=(
                "DISALLOW_FILE_EDIT is not active in wp-config.php "
                "(admins can edit plugin and theme source in wp-admin)"
            ),
            risk="medium",
            fix="add DISALLOW_FILE_EDIT to wp-config.php (wpt harden)",
        )
    ]


@register_check("security.relocate", applies=("ftp",))
def check_security_relocate(data: AuditData, settings: Settings) -> list[Finding]:
    """RELOCATE active in wp-config.php => an attacker can redirect the site.

    wp-login.php acts on it whenever the constant is truthy: it derives
    siteurl from the current request and writes that option, so an attacker
    can point the site at a host of their choosing. Current WordPress
    migration guidance is to delete RELOCATE once the move is done. Only an
    ACTIVE truthy value counts — ``define('RELOCATE', 'false')`` is a
    non-empty string and is therefore ALSO truthy in PHP, so it is flagged
    too. A value PHP decides at runtime is reported as unverifiable rather
    than assumed safe.
    """
    probe = data.probe
    if probe is None:
        return []
    content = probe.read_file(_WP_CONFIG)
    if content is None:
        return []
    state = _php_const_state(content, _RELOCATE)
    if state == "absent" or state == "falsey":
        return []
    if state == "unknown":
        return [
            Finding(
                category="security.relocate",
                name="relocate",
                detail=(
                    "RELOCATE in wp-config.php is set to a value this static "
                    "scan cannot resolve (conditional or non-literal); its "
                    "effect could not be verified"
                ),
                risk="medium",
                fix="remove the RELOCATE line from wp-config.php (migration-only)",
            )
        ]
    return [
        Finding(
            category="security.relocate",
            name="relocate",
            detail=(
                "RELOCATE is active in wp-config.php — wp-login.php will "
                "rewrite siteurl from the incoming request"
            ),
            risk="high",
            fix="remove the RELOCATE line from wp-config.php (migration-only)",
        )
    ]


@register_check("security.https_redirect", applies=("ftp",))
def check_security_https_redirect(data: AuditData, settings: Settings) -> list[Finding]:
    """http:// URLs that stay on http => HTTPS is not forced.

    Samples the homepage plus up to 3 data.pages entries (deduped, page
    order kept), GETs each http:// twin without following redirects; a
    response that neither redirects (301/302/307/308) nor carries an
    https:// Location => offender. Any offender => one finding
    (name "https-redirect") listing the sampled URLs (newline-joined, the
    "(+N more)" convention). All-redirect, every-probe-failing, or no
    probe — silent. pages None => homepage only. A single probe's network
    failure skips just that URL (unknown, not "secure", not an offender).
    """
    probe = data.probe
    if probe is None:
        return []
    sampled = [probe.site]
    if data.pages is not None:
        sampled.extend(
            page
            for page in data.pages[:_PAGES_SAMPLE]
            if isinstance(page, str) and page
        )
    offenders: list[str] = []
    for url in dict.fromkeys(sampled):
        response = _get(
            probe, _http_twin(url),
            deadline=data.deadline, allow_redirects=False,
        )
        if response is None or _leaves_http(response):
            continue
        offenders.append(url)
    if not offenders:
        return []
    return [
        Finding(
            category="security.https_redirect",
            name="https-redirect",
            detail=_detail_lines(offenders),
            count=len(offenders),
            risk="medium",
            fix="force HTTPS in .htaccess (wpt harden)",
        )
    ]


@register_check("security.www_apex", applies=("ftp",))
def check_security_www_apex(data: AuditData, settings: Settings) -> list[Finding]:
    """www serving content without redirecting to the apex => duplicate
    host (SEO + stale-cert risk).

    When the site host is not already "www.*": GET https://www.<host>/
    FOLLOWING redirects; a 2xx whose final URL is still the www host =>
    finding. Unreachable (the good case — www not serving), redirected
    anywhere off the www host, non-2xx or no probe — silent.
    """
    probe = data.probe
    if probe is None:
        return []
    host = urlparse(probe.site).netloc
    if not host or host.startswith("www."):
        return []
    www_host = f"www.{host}"
    response = _get(
        probe, f"https://{www_host}/",
        deadline=data.deadline, allow_redirects=True,
    )
    if response is None:
        return []
    if not 200 <= response.status_code < 300:
        return []
    if urlparse(response.url).netloc != www_host:
        return []
    return [
        Finding(
            category="security.www_apex",
            name="www-apex",
            detail=(
                f"{www_host} serves content without redirecting to the "
                "apex host (duplicate host: SEO + stale-cert risk)"
            ),
            risk="low",
            fix="redirect www to apex in the hoster's DNS or .htaccess "
                "(outside wpt harden's v1 scope)",
        )
    ]


def _peer_cert_bounded(host: str, target: str, port: int,
                       timeout_s: float, deadline: Any) -> None:
    """Read the verified peer certificate, bounded by the run deadline.

    The old probe used blocking ``socket.create_connection`` + a blocking
    TLS wrap with no run budget: a stalled resolver, dial or a drip-fed
    handshake outlived ``--deadline`` (R14-P2).  No deadline keeps the
    original synchronous path (and its pinned timeout argument); with one,
    resolve under the absolute budget, dial each address with the remaining
    time and run the whole dial+handshake on a worker the caller stops
    waiting for at the deadline.  A timed-out worker owns only a socket
    (closed here when it was published) or a libc resolver call, never a
    mutation.
    """
    try:
        host.encode("idna")
    except UnicodeError as exc:
        # An unencodable SNI name (an over-long label, an invalid IDNA code
        # point) is an unusable measured value, not a TLS answer.  Raising
        # the check's silent WptError contract keeps a malformed site URL
        # from fabricating a HIGH "check errored" finding.
        raise WptError(
            "certificate probe host is not a valid IDNA name") from exc
    # ONE absolute request bound even when the run has no deadline: a
    # resolver stall or a drip-fed handshake must not outlive
    # ``probe.timeout_s``.  A shorter run deadline still wins.
    request_at = time.monotonic() + max(0.001, float(timeout_s))
    if deadline is not None:
        request_at = min(request_at, deadline.at)
    if request_at <= time.monotonic():
        raise TimeoutError("TLS probe request budget already spent")
    if is_numeric_host(target):
        addresses = [target.strip("[]")]
    else:
        addresses = resolve_host_bounded(
            target, port, request_at,
            label="certificate probe DNS resolution",
            thread_name="wpt-cert-dns")
    result: list[BaseException] = []
    holder: list[socket.socket] = []
    done = threading.Event()

    def _work() -> None:
        try:
            last_error: BaseException | None = None
            for index, address in enumerate(addresses):
                remaining = request_at - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        "TLS probe request budget exceeded")
                # Share the remaining request budget across the addresses
                # still to try.  Giving each address the WHOLE remainder let
                # a blackholed first address spend the budget, so a real
                # certificate mismatch on a later address was silently
                # missed (a transport timeout is "unknown").
                share = remaining / (len(addresses) - index)
                # ONE absolute attempt deadline covers the dial AND the
                # handshake.  Computing a fresh share after a slow connect
                # spent the same share twice and could starve the later
                # address of its certificate (a genuine mismatch read as a
                # silent unknown).
                attempt_at = min(
                    request_at,
                    time.monotonic() + max(0.001, min(timeout_s, share)))
                try:
                    raw = socket.create_connection(
                        (address, port),
                        timeout=max(0.001, attempt_at - time.monotonic()))
                except (OSError, ssl.SSLError) as exc:
                    # A per-address connect failure advances to the next
                    # address; it used to escape the loop entirely.
                    last_error = exc
                    continue
                holder.append(raw)
                try:
                    context = ssl.create_default_context()
                    settimeout = getattr(raw, "settimeout", None)
                    if callable(settimeout):
                        settimeout(max(
                            0.001, attempt_at - time.monotonic()))
                    with context.wrap_socket(
                            raw, server_hostname=host) as tls:
                        tls.getpeercert()
                    return
                except ssl.SSLCertVerificationError:
                    raise
                except (OSError, ssl.SSLError) as exc:
                    last_error = exc
                finally:
                    if raw in holder:
                        holder.remove(raw)
                    try:
                        raw.close()
                    except (OSError, ValueError):
                        pass
            if last_error is not None:
                raise last_error
            raise OSError("no address answered the TLS probe")
        except BaseException as exc:  # noqa: BLE001 — relayed to the caller
            result.append(exc)
        finally:
            done.set()

    worker = threading.Thread(target=_work, name="wpt-cert-probe",
                              daemon=True)
    worker.start()
    if not done.wait(max(0.0, request_at - time.monotonic())):
        # Stop the handshake NOW: closing the published socket unblocks the
        # worker's read; the caller answers silent (unknown), never a guess.
        for raw in list(holder):
            try:
                raw.shutdown(socket.SHUT_RDWR)
            except (OSError, ValueError, AttributeError):
                pass
            try:
                raw.close()
            except (OSError, ValueError, AttributeError):
                pass
        raise TimeoutError("TLS probe request budget exceeded")
    if result:
        raise result[0]


@register_check("security.cert_mismatch", applies=("ftp",))
def check_security_cert_mismatch(data: AuditData, settings: Settings) -> list[Finding]:
    """The TLS cert does not verify for the site's DNS name — informational.

    Opens a real TLS socket to data.siteurl's host (NOT www-prefixed):
    ``socket.create_connection((probe.override_ip or host, 443),
    timeout)`` wrapped in a VERIFIED ssl.create_default_context() with
    server_hostname=host, then reads the peer cert.  The
    ``--override-ip`` address — when one is in effect — is dialed with
    the site host as SNI, the same override every session-riding probe
    honors [L13: the probe used to dial real DNS, so a network whose
    resolver answered a different server (an internal *.host view)
    turned a VALID cert into a false mismatch].  A handshake failing
    with ssl.SSLCertVerificationError => finding (expected
    pre-migration, risk low).  Handshake OK, host unreachable, any
    other socket/SSL error, unknown siteurl or no probe — silent:
    only a VERIFICATION failure says "the cert does not cover the
    name".
    """
    probe = data.probe
    if probe is None:
        return []
    siteurl = data.siteurl
    if not isinstance(siteurl, str) or not siteurl:
        return []
    try:
        parsed = urlparse(siteurl)
        host = parsed.hostname
        port = parsed.port or _TLS_PORT
    except (TypeError, ValueError):
        return []
    if not host:
        return []
    target = probe.override_ip or host
    try:
        _peer_cert_bounded(host, target, port, probe.timeout_s,
                           getattr(data, "deadline", None))
    except ssl.SSLCertVerificationError:
        return [
            Finding(
                category="security.cert_mismatch",
                name="cert-mismatch",
                detail=(
                    f"the TLS certificate does not verify for {host} "
                    "(expected before the migration cutover)"
                ),
                risk="low",
                fix="install a Let's Encrypt cert for the DNS name after the migration",
            )
        ]
    except (OSError, ssl.SSLError, WptError):
        return []
    return []


@register_check("security.uploads_listing", applies=("ftp",))
def check_security_uploads_listing(data: AuditData, settings: Settings) -> list[Finding]:
    """wp-content/uploads/ serving a directory listing => media paths
    enumerable (and ugly 8MB scans by bots).

    GET {site}/wp-content/uploads/ without following redirects; 200 +
    "Index of" in the body OR an html content-type => finding. 403 (the
    usual Options -Indexes answer), a redirect, 404, a network failure or
    no probe — silent.
    """
    probe = data.probe
    if probe is None:
        return []
    response = _get(
        probe, f"{probe.site}/{_UPLOADS_URL_PATH}",
        deadline=data.deadline, allow_redirects=False,
    )
    if response is None or response.status_code != 200:
        return []
    content_type = response.headers.get("Content-Type", "")
    if _INDEX_MARKER not in response.text and "text/html" not in content_type.lower():
        return []
    return [
        Finding(
            category="security.uploads_listing",
            name="uploads-listing",
            detail="wp-content/uploads/ serves a directory listing",
            risk="medium",
            fix="Options -Indexes in .htaccess (wpt harden)",
        )
    ]


@register_check("security.uploads_perms", applies=("ftp",))
def check_security_uploads_perms(data: AuditData, settings: Settings) -> list[Finding]:
    """wp-content/uploads/ world-writable => media can be replaced by any
    account on the host, and a PHP file dropped there executes.

    Entries-based (no probe): every entry at the uploads directory itself
    or under "wp-content/uploads/" whose POSIX mode has the other-write
    bit (``mode & 0o002``) is affected.  ONE finding, count = affected
    paths, detail samples up to _DETAIL_ITEMS "path (0oXXX)" examples plus
    "(+N more)", risk medium.  ``mode is None`` means the source did not
    say: unknown is never world-writable, so a tree with no measured mode
    stays silent.  Paths outside uploads are never scanned.
    """
    uploads = _UPLOADS_URL_PATH.rstrip("/")
    affected: list[str] = []
    for entry in data.entries:
        # A symlink's mode describes the LINK, not the file it resolves to;
        # chmod cannot change it, and the link's stored bytes are a target
        # path, not media content.
        if entry.is_link:
            continue
        # the directory itself, or anything under it — never a sibling
        # whose name merely shares the prefix
        under = entry.path == uploads and entry.is_dir
        if not under and not entry.path.startswith(_UPLOADS_URL_PATH):
            continue
        if entry.mode is not None and entry.mode & 0o002:
            affected.append(f"{entry.path} (0o{entry.mode:03o})")
    if not affected:
        return []
    affected.sort()
    return [
        Finding(
            category="security.uploads_perms",
            name="uploads-perms",
            detail=(
                f"{len(affected)} world-writable path(s) in "
                f"wp-content/uploads/: {_excerpt(affected)}"
            ),
            count=len(affected),
            risk="medium",
            fix=(
                "chmod 755 the affected directories and 644 the affected "
                "files (or ask the host to fix the account umask so new "
                "uploads are not world-writable)"
            ),
        )
    ]


@register_check("security.debug_log", applies=("ftp",))
def check_security_debug_log(data: AuditData, settings: Settings) -> list[Finding]:
    """debug.log exposed in the webroot => WP_DEBUG output (errors, paths,
    sometimes credentials in stack traces) is web-readable.

    Entries-based — a FILE entry at exactly "wp-content/debug.log"
    (WordPress's WP_DEBUG_LOG location). No probe is consulted, so the
    check also reports for a probe-less caller; directories and debug.log
    files elsewhere never match.
    """
    for entry in data.entries:
        if entry.path == _DEBUG_LOG_PATH and not entry.is_dir:
            return [
                Finding(
                    category="security.debug_log",
                    name="debug-log",
                    detail=(
                        "wp-content/debug.log is exposed in the webroot "
                        "(WP_DEBUG output)"
                    ),
                    bytes=entry.size,
                    count=1,
                    risk="medium",
                    fix="delete debug.log; disable WP_DEBUG",
                )
            ]
    return []


@register_check("security.php_version", applies=("ftp",))
def check_security_php_version(data: AuditData, settings: Settings) -> list[Finding]:
    """The host PHP runtime below the minimum actively-supported minor.

    The bridge ``info`` payload (cached on the probe — one round-trip
    serves every consumer) reports the runtime facts; php_version parsed
    as a numeric (major, minor) tuple BELOW ``env.php_min_active`` (default
    "8.2") => ONE finding "php-eol": risk medium, detail = the
    runtime facts line (sapi, mysql, memory_limit, max_execution_time,
    server — an absent fact renders "unknown"). Absent/unparseable
    php_version, a failed info call, no bridge or no probe — silent
    (unknown, never a guess); at-or-above the minimum — silent too: a
    healthy runtime is the updates-check precedent.
    """
    probe = data.probe
    if probe is None:
        return []
    info = probe.info()
    if not isinstance(info, dict):
        return []
    php_version = info.get("php_version")
    if not isinstance(php_version, str) or not php_version:
        return []
    runtime = _php_minor(php_version)
    floor_text = (settings.env.php_min_active
                  if isinstance(settings.env.php_min_active, str)
                  and settings.env.php_min_active.strip()
                  else EnvSettings().php_min_active)
    floor = _php_minor(floor_text)
    if runtime is None or runtime >= floor:
        return []
    return [
        Finding(
            category="security.php_version",
            name="php-eol",
            detail=(
                f"PHP {php_version} (sapi {_fact(info.get('sapi'))}, "
                f"mysql {_fact(info.get('mysql_version'))}, "
                f"memory_limit {_fact(info.get('memory_limit'))}, "
                f"max_execution_time {_fact(info.get('max_execution_time'))}, "
                f"server {_fact(info.get('server_software'))})"
            ),
            risk="medium",
            fix=(
                f"Upgrade the host PHP runtime: {runtime[0]}.{runtime[1]} "
                "is past active support (only older minors get security "
                "fixes); the hoster (DirectAdmin/cPanel) offers selector "
                "switches"
            ),
        )
    ]


# --------------------------------------- web-exposed top-level scripts [D2]

# The CONTENT signatures that make an unknown top-level PHP file a
# security finding rather than a curiosity: a request-parameter gate (an
# operator's token-guarded tool, or an attacker's dropper) or a
# home-directory walk.  Matched as plain substrings over the file's
# bytes — the question is what the file CONTAINS, and the file is
# already unknown, top-level and web-reachable, so no PHP-awareness is
# needed to avoid the false positives ``security.suspicious`` has to
# work for inside wp-content/.  This is the CHEAP first pass; the
# structured request-superglobal family is the second.  The VALUES live
# in one owner — wpt.settings.WEB_SCRIPT_SIGNATURES, re-exported above
# under the historical module name, so the no-settings fallback and the
# shipped profile cannot drift apart.  Order is fixed: the detail lists
# the matches in this order so the rendered text is deterministic.

# The REQUEST-PARAMETER family, matched STRUCTURALLY: the superglobal
# NAME followed by OPTIONAL whitespace and an optional quote, then the
# subscript.  A plain substring loses to ``$_GET ['t']`` (one space) and to
# every sibling superglobal that is as much a request-parameter gate as
# ``$_GET`` (``$_POST``, ``$_REQUEST``, ``$_COOKIE``) — the evasions an
# adversarial review reproduced against the substring scan.  A NAME is
# matched, not a bare ``$``, so an unrelated ``$_GETTER`` never matches;
# PHP superglobals are case-sensitive, so this pass is too.  The note is
# what de-duplicates the family against the first pass: a file carrying
# plain ``$_GET[`` is already reported by the needle, and a note seen in
# the first pass suppresses the family line for the same concept.
# Shipped owner: ``web_script.request_globals``.

#: Optional whitespace + an optional quote between a superglobal's name and
#: its subscript, so ``$_GET[``, ``$_GET ['t']`` and ``$_GET["t"]`` are one
#: match shape.  Built per name by :func:`_request_global_re`.
_GLOBAL_SUBSCRIPT = r"\s*\[\s*[\"\']?"

#: The character class a ``?`` in a ``web_script.known_artifacts`` pattern
#: stands for: ONE HEX DIGIT, either case.  wpt names its own webroot
#: artifact ``bridge-<8 hex>.php``, so that is the only shape the shipped
#: exemption may cover (see :func:`_is_known_artifact`).
_HEX_DIGIT_CLASS = "[0-9a-fA-F]"


# The webroot suffixes a host commonly hands to the PHP handler.  WHICH
# suffixes execute is the host's ``AddHandler``/mod_php configuration, not
# something a file's bytes can say, so this is the COMMON SUPERSET the
# check scans and the profile key ``web_script.extensions`` is its shipped
# owner (with a ``--set`` door for a host that runs a narrower set).  A
# ``.phtml``/``.phar``/``.PHP`` webshell is as web-reachable as a ``.php``
# one, and a candidate filter that stopped at ``endswith(".php")`` never
# considered it.  Compared CASE-INSENSITIVELY: a mixed-case suffix is the
# same handler on a case-insensitive filesystem and an easy evasion on a
# case-sensitive one.  Values: wpt.settings.WEB_SCRIPT_EXTENSIONS.

#: Above this share of NUL bytes a "text" file is really UTF-16 (PHP happily
#: parses a BOM-prefixed UTF-16 file: the interpreter skips the BOM and
#: reads the wide characters), so the transcode pass is worth its two views.
_UTF16_NUL_SHARE = 0.05

#: A base64 run shorter than this is a hash or a data-URI fragment, not a
#: payload; at or above it, decoded by :func:`_decoded_payload` ONLY when it
#: is the dominant content of the file, and only reported when what comes
#: out carries a signature.  The floor is deliberately low: the real gate
#: is the signature in the DECODED bytes, and no ordinary encoded asset
#: decodes to ``$_POST[``.
_ENCODED_MIN_RUN = 32
_ENCODED_MIN_SHARE = 0.5
_ENCODED_RUN_RE = re.compile(
    r"[A-Za-z0-9+/=]{%d,}" % _ENCODED_MIN_RUN
)
_WHITESPACE_RE = re.compile(r"\s+")
#: gzip's window bits, so a decoded blob is inflated with the stdlib
#: zlib instead of :mod:`gzip` (which cannot be given an output bound).
_GZIP_WBITS = 16 + zlib.MAX_WBITS
#: The inflation bound: a dropper payload is small, and a bound is what
#: keeps a short base64 run from unpacking a decompression bomb.
_DECODED_MAX_BYTES = 65536

#: A candidate larger than this is not read (a scope bound, the module
#: fallback for a call that carries no profile): a token-gated operator
#: probe or a dropper is a few KB, so the bound only stops one stray
#: huge file from pulling itself into memory.  A file above it is skipped
#: silently.  The bound is owned by ``settings.WEB_SCRIPT_MAX_BYTES``
#: (imported above as ``_WEB_SCRIPT_MAX_BYTES`` for the no-settings fallback).

#: The read-only triage + removal advice for an unexplained top-level
#: PHP file — ONE owner, exported for the ``core.integrity`` "added"
#: finding of the same file, whose fix was previously unactionable
#: [D2]: a live production docroot carried two web-reachable PHP probes (a
#: prior session's own disk-usage scripts, token-gated), ``core.integrity``
#: rated them HIGH as "added" files, the fix text said nothing actionable,
#: and no wpt command removes a file from the webroot top level — so they
#: stayed live until a human read the report.
WEB_SCRIPT_TRIAGE = (
    "Triage it read-only before touching it: "
    "file <file> && head -c 400 <file> (what does it print; `file` also "
    "names a UTF-16 or base64 payload, whose bytes head renders as "
    "mojibake), "
    r"grep -nE 'token|hash_equals|\$_(GET|POST|REQUEST|COOKIE)' <file> "
    "(where does it gate; a mostly-base64 body decodes with "
    "base64 -d | gunzip), "
    "stat -c %y <file> (date it against the site's own history). "
    "A file you deployed deliberately is not a finding to delete — a dated "
    "one you cannot account for is an incident. "
    "Once it is proven obsolete, remove it: rm <file> (no wpt command "
    "deletes a file from the webroot top level — wpt prune-core works only "
    "inside wp-admin/, wp-includes/ and wp-content/languages/, and "
    "wpt clean-files removes only its own junk patterns), then re-run the "
    "audit to confirm the URL stops answering 200."
)

#: The advice for a candidate whose OFFICIAL-CORE BASIS could not be
#: established (wp.org gave NO ANSWER, or the version was unreadable).  Its
#: own category, so nothing in the report tells the operator to remove it:
#: the one honest answer to "this file carries a token gate and cannot be
#: matched against the official checksums" is to ESTABLISH the comparison,
#: and a run that could not is not evidence of a backdoor.  A stock core
#: file is the expected occupant of this class — measured on ordinary
#: core/plugin/theme PHP files carry one of the signatures — so removing
#: one would break the site on the strength of an outage.  Note what is
#: NOT in this class: a version wp.org says does not exist is positive
#: evidence of an ALTERED core (:func:`_official_core_basis`), and a
#: candidate there stays high.
WEB_SCRIPT_UNPROVEN_TRIAGE = (
    "Do NOT triage or remove this file on this evidence: wpt could not "
    "compare this site with the official WordPress checksums, so it could "
    "not rule out that this IS a stock core file (an offline run rated "
    "wp-login.php, wp-cron.php and xmlrpc.php as backdoors). "
    "Establish the comparison first: make wp.org reachable and "
    "wp-includes/version.php readable, then re-run the audit — with the "
    "map available the file is either exempted as official core or "
    "reported with the backdoor triage. "
    "Until then, decide it yourself against a clean copy of the same "
    "build: download the official WordPress zip for the site's version "
    "and locale, then cmp -s <clean>/<file> <file>; echo $? — exit 0 "
    "means the file IS the official one and must stay, anything else is "
    "the incident to triage read-only."
)

#: The category the UNPROVEN class renders under: its own, so the
#: HIGH-only aggregate advice in the report's next-step table (report.py
#: owns that table) can never be triggered by a file wpt could not
#: classify, and the label is unmissable in the report and the JSON twin.
_WEB_EXPOSED_UNPROVEN_CATEGORY = "security.web_exposed_script_unproven"

#: The core's own statement of its version — the ONE file whose bytes make
#: the comparison possible, and therefore the ONE file an attacker writes
#: to switch the comparison off.
_VERSION_FILE = "wp-includes/version.php"

#: The two refusals, as the ONE owner of the distinction that decides
#: whether a candidate is demoted (webroot.junk states the same two
#: conditions in the same words, so one condition cannot read two ways
#: across the report):
#:
#: ``UNREADABLE`` — wpt could not learn the site's version, so it never
#: asked wp.org anything.  This says NOTHING about wp.org: the file it
#: hinges on is inside the webroot, writable by whoever already wrote the
#: candidate, and an attacker who strips ``$wp_version`` from it would
#: otherwise demote their own webshell [D1].  It is therefore NOT a
#: demoting condition.
#: ``UNFETCHABLE`` — wpt read a version and asked wp.org, and wp.org could
#: not answer it.  This is the offline condition, the only evidence that
#: the comparison was genuinely impossible, and the only demoting one.
_VERSION_UNREADABLE = (
    "the WordPress version could not be read from wp-includes/version.php"
)
_CHECKSUMS_UNFETCHABLE = (
    "the official wp.org checksums for WP {version} ({locale}) could not be "
    "fetched"
)

#: THE THIRD refusal, and the one the demotion used to be conflated with:
#: wp.org ANSWERED, and what it said is that the build this webroot claims
#: to be has no checksums.  That is not an outage and not an offline run —
#: it is a positive answer about a version that does not correspond to a
#: real release, and the version string lives in the file an attacker
#: writes (see :data:`_VERSION_FILE`).  Measured on the live API: a
#: version that does not exist answers HTTP 200 ``{"checksums": false}``,
#: which the map fetch collapses into the same None a dead network
#: produces, so ``$wp_version = '9.9.9'`` beside a real webshell demoted a
#: definite HIGH shell to the MEDIUM "do not remove" class.  So the two
#: are separated HERE, at the one place that decides the demotion, and
#: only a genuine TRANSPORT failure demotes (see
#: :func:`_wp_org_answered`).
_CHECKSUMS_NO_SUCH_BUILD = (
    "wp.org published no checksums for the WordPress build this webroot "
    "claims to be (WP {version}, {locale}) — it answered, and that build is "
    "not a release"
)

#: …and THE FOURTH, which is the same refusal at one remove: wp.org spoke,
#: but what it said does not establish the build.  Every other answer shape
#: lands here — a 4xx/5xx status, a redirect, an HTML error page, an empty
#: body, a JSON list, a checksums map with no usable entry — and the
#: ``{answer}`` slot names WHICH shape it was, because "wp.org spoke" and
#: "wp.org said nothing useful" are different facts and an operator who
#: retries wants to know which one they got.
#:
#: This is the shape the demotion used to be decided by, and it is the one
#: an attacker reaches with a single write: the version string is
#: interpolated into the request URL, so a 20 000-character
#: ``$wp_version`` makes the LIVE api.wordpress.org answer HTTP 400 (URI too
#: long) — a positive statement that the request is malformed, which the map
#: fetch reported as "no answer" and the demotion read as "offline".  A real
#: webshell beside it was demoted to the MEDIUM "Do NOT triage or remove
#: this file on this evidence" class by 20 000 bytes in a file the attacker
#: already had to write.  Every HTTP answer is evidence that wp.org SPOKE,
#: whatever its status or body, so none of them can demote anything.
_CHECKSUMS_NOT_ESTABLISHED = (
    "wp.org answered for the WordPress build this webroot claims to be "
    "(WP {version}, {locale}) with {answer}, which does not establish it — "
    "wp.org spoke, so this run is not offline, and no map was compared"
)

#: The evidence that keeps a candidate HIGH under that refusal.  It is
#: deliberately NOT a claim that the core is altered: a 502 from an edge
#: proxy says nothing about the site, and a detail that lied here would be
#: the same defect one level up.  What IS true of every answered case is
#: that the one statement of which build this webroot is could not be
#: confirmed, that statement is the file an attacker writes to switch the
#: whole comparison off, and no file here may be excused as stock core
#: without it.
_ALTERED_VERSION_UNCONFIRMED = (
    "the only statement of which WordPress build this webroot is the "
    "$wp_version in wp-includes/version.php (the file an attacker writes to "
    "switch this comparison off), and that statement could not be confirmed "
    "against wp.org, so no file in this webroot may be excused as stock core"
)

#: The positive-evidence clause for the one degraded state that IS core
#: compromise: ``wp-includes/version.php`` is present and readable through
#: the source, and the gather's own parser
#: (:func:`wpt.audit.data._read_wp_version`, reused rather than
#: reimplemented) still finds no ``$wp_version`` in it.  The core's own
#: statement of what it is has been rewritten, so nothing in this webroot
#: may be excused as stock core on the strength of a file the attacker
#: controls.
_ALTERED_VERSION_STATEMENT = (
    "wp-includes/version.php is present and readable in this webroot yet "
    "carries no readable $wp_version assignment — the core's own statement "
    "of its version has been altered, so this webroot is not a stock core "
    "and no file in it may be excused as one"
)

#: THE POSITIVE EVIDENCE of the third refusal, and the fact that keeps the
#: candidate HIGH: wp.org was asked for the checksums of the build the
#: core's own version file names and published NONE, because no such build
#: was ever released.  So the file that decides every official-core
#: comparison in this run does not name a real release — which is
#: ``core.integrity``'s own tampered-version finding stated as evidence
#: here, and it is evidence, never a demotion.
_ALTERED_VERSION_NO_SUCH_BUILD = (
    "wp.org was asked for the checksums of WP {version} and published none, "
    "because no such WordPress build was ever released — the $wp_version in "
    "wp-includes/version.php (the file an attacker writes to switch this "
    "comparison off) does not name a real release, which is positive "
    "evidence the core itself was altered and no file in it may be excused "
    "as one"
)


@dataclass(frozen=True)
class _CoreBasis:
    """The official-core comparison's OUTCOME and WHICH condition made it.

    :attr:`official` is the map's path set (empty when no map applied).
    :attr:`refusal` is the ONE reason no map applied, or None — the SAME
    wordings (:data:`_VERSION_UNREADABLE`,
    :data:`_CHECKSUMS_UNFETCHABLE`, :data:`_CHECKSUMS_NO_SUCH_BUILD`,
    :data:`_CHECKSUMS_NOT_ESTABLISHED`) webroot.junk reports for the two it
    knows, so a run that hears both reads one condition.
    :attr:`demote` is the load-bearing field: it is True for
    :data:`_CHECKSUMS_UNFETCHABLE` alone — the run read a version, asked
    wp.org, and got NO ANSWER AT ALL (no response, not a bad one), which is
    the only evidence that the comparison was genuinely impossible.  Three
    conditions deliberately do NOT set it, and each was a way to demote a
    HIGH finding with one write to a file the attacker controls:

    * an unreadable version.php (:data:`_VERSION_UNREADABLE`) — the run
      never learned whether wp.org is reachable at all [D1];
    * a version wp.org says does not exist
      (:data:`_CHECKSUMS_NO_SUCH_BUILD`) — wp.org ANSWERED, so this is
      not an offline run at all.  It is positive evidence that the
      version file does not name a real release, and it is carried as
      :attr:`core_altered` so the candidate stays HIGH with the fact in
      its detail;
    * an answer that does not establish the build
      (:data:`_CHECKSUMS_NOT_ESTABLISHED`) — a 4xx/5xx, a redirect, an HTML
      page, an empty body, a JSON list.  EVERY HTTP response is evidence
      that wp.org spoke, and the STATUS of that response is not wpt's to
      read as a verdict about the site: the request URL carries the
      attacker-writable ``$wp_version``, so a 20 000-character version
      string earns a 400 and used to earn a demotion.
    :attr:`core_altered` is the positive fact the finding's detail carries
    when the basis is incomplete — the altered version statement, a version
    no release ever had, or the unconfirmable build — or None.  It never
    demotes anything, and each text states only what is true of its own
    condition, because a detail that overstates the evidence is the same
    defect one level up.
    """

    official: frozenset[str] = frozenset()
    refusal: str | None = None
    demote: bool = False
    core_altered: str | None = None


def _version_statement_altered(source: Any) -> str | None:
    """:data:`_ALTERED_VERSION_STATEMENT` when the core's version statement
    is present and readable yet carries no version, else None.

    Two conditions, both required, and the difference is the whole point:
    an ABSENT or unreadable ``wp-includes/version.php`` is unknown — a
    partial archive, a permissions failure — and is never reported as
    tampering; a file this webroot DOES carry, read successfully, with no
    ``$wp_version`` in it is an altered core.  The parse is the gather's
    own (:func:`wpt.audit.data._read_wp_version`), so "readable" means
    exactly what it means everywhere else in the tool.
    """
    if source is None:
        return None
    try:
        source.read_bytes(_VERSION_FILE)
    except (SourceError, OSError):
        return None
    if _read_wp_version(source) is not None:
        return None
    return _ALTERED_VERSION_STATEMENT


def _answer_class(status: int, payload: Any, parse_failed: bool) -> str:
    """What wp.org's answer LOOKED like, as the words the operator reads.

    The class is a property of the RESPONSE, never of the site: a status, a
    body shape, a payload shape.  It exists so the refusal can name the
    answer instead of saying "could not be fetched" for six different
    things, and so an operator who retries knows which one they got.
    """
    if parse_failed:
        return f"HTTP {status} and a body that is not JSON"
    if status != 200:
        return f"HTTP {status}"
    if isinstance(payload, dict):
        if "checksums" not in payload:
            return ("HTTP 200 and a JSON object with no `checksums` key, "
                    f"naming {sorted(payload)[:3]}")
        if isinstance(payload["checksums"], dict):
            return ("HTTP 200 and a checksums map that carries no usable "
                    "path/digest entry")
        return 'HTTP 200 and {"checksums": false}'
    return f"HTTP 200 and a JSON {type(payload).__name__}, not a map"


def _answer_basis(answer: str, version: str, locale: str,
                  no_such_build: bool) -> _CoreBasis:
    """The basis an ANSWERED wp.org yields, from its class and nothing else.

    ``no_such_build`` is the one answer that is positive evidence about the
    SITE (wp.org published no checksums for this build, so the version file
    does not name a release).  Every other class is the same refusal with
    the answer named in it — a 4xx/5xx, a redirect, an HTML page, an empty
    body, a JSON list, a checksums map with no usable entry — and it is
    never a demotion, because wp.org spoke.
    """
    if no_such_build:
        return _CoreBasis(
            refusal=_CHECKSUMS_NO_SUCH_BUILD.format(
                version=version, locale=locale),
            core_altered=_ALTERED_VERSION_NO_SUCH_BUILD.format(
                version=version),
        )
    return _CoreBasis(
        refusal=_CHECKSUMS_NOT_ESTABLISHED.format(
            version=version, locale=locale, answer=answer),
        core_altered=_ALTERED_VERSION_UNCONFIRMED,
    )


def _wp_org_answered(session, timeout_s: int, version: str,
                    locale: str, deadline=None,
                    config: WpOrgSettings | None = None) -> _CoreBasis | None:
    """The basis for "wp.org SPOKE" — or None when it did not answer at all.

    THE ONE QUESTION THE DEMOTION TURNS ON, and the answer is a transport
    fact: did a RESPONSE come back?  A response is evidence that wp.org
    spoke, whatever its status and whatever its body carries, so every
    answer shape returns a basis here and NOT ONE of them demotes.  Only a
    ``requests.RequestException`` — a refused connection, a DNS failure, a
    TLS failure, a read timeout: no response at all — returns None, and
    that is the whole offline condition.

    The old shape asked ``WpOrgApi._request_json`` and read "no usable map"
    as "no answer", which made the STATUS the decider: the request URL
    carries the ``$wp_version`` straight out of ``wp-includes/version.php``,
    so an attacker-chosen version decides which branch this took.  Measured
    on the live API, a 20 000-character version string makes wp.org answer
    HTTP 400 (URI too long) — a positive statement that the request is
    malformed — and a definite HIGH webshell beside it was demoted to the
    MEDIUM "do not triage or remove" class.  A 500, a 302, an HTML error
    page, an empty body and a JSON list all demoted the same way.

    THE SINGLE-REQUEST DISCIPLINE IS KEPT, and the common case is a CACHE
    READ: the configured ``wp_org`` cache entry is the one the map fetch
    just wrote or failed to write, read through updates.py's own
    :func:`~wpt.audit.updates._cache_key` /
    :func:`~wpt.audit.updates._read_cache` /
    ``wp_org.cache_ttl_s`` — the same key, the same TTL,
    the same file, imported rather than reimplemented, so a second live
    request per audit is never added and a 200 JSON answer is still paid
    for exactly once.  The cached payload is then classified by the SAME
    rules as a live one (a cached 200 can be a list, an HTML-shaped string
    or an empty map, not only "no such build").  Only a run whose map fetch
    got nothing at all reaches the request below, and that run is degraded
    either way.
    """
    import json
    import time

    import requests

    from ..php_probe import BODYLESS_STATUSES, get_bounded
    from .integrity import _checksums_url
    from .updates import (
        DEFAULT_WP_ORG,
        _CACHE_DIR,
        _WPORG_JSON_MAX_BYTES,
        _cache_key,
        _package_version,
        _read_cache,
    )

    def _spent() -> bool:
        return deadline is not None and deadline.remaining <= 0

    cfg = config or DEFAULT_WP_ORG
    url = _checksums_url(version, locale, cfg)
    cache_dir = _CACHE_DIR or Path(cfg.cache_dir)
    cached = _read_cache(cache_dir / (_cache_key(url, None) + ".json"))
    if cached is not None and time.time() - cached[1] < cfg.cache_ttl_s:
        # A fresh entry exists only because wp.org answered this exact
        # request with a 200 JSON payload in the last hour.
        payload = cached[0]
        return _answer_basis(
            _answer_class(200, payload, False), version, locale,
            _no_such_build(200, payload),
        )
    if _spent():
        raise DeadlineExceeded(
            "run deadline exceeded at the wp.org answer probe — the "
            "request was not started")
    response = None
    body = b""
    status = 0
    body_error: BaseException | None = None
    # ONE per-request transport bound: min(run deadline, now + timeout_s).
    # The run budget alone let a single dripped wp.org answer hold the whole
    # audit; the probe's configured timeout alone could outlive the run.
    transport_deadline = time.monotonic() + max(0.001, float(timeout_s))
    if deadline is not None:
        transport_deadline = min(deadline.at, transport_deadline)
    user_agent = cfg.user_agent_template.format(version=_package_version())
    json_max_bytes = (_WPORG_JSON_MAX_BYTES
                      if _WPORG_JSON_MAX_BYTES is not None
                      else cfg.json_max_bytes)
    try:
        # ONE bounded GET for BOTH states: a run deadline pins the absolute
        # instant, while an explicitly unbounded run (--deadline 0) still
        # gets the probe's own absolute timeout instead of requests'
        # per-read one.
        response = get_bounded(
            session, url, timeout_s=timeout_s,
            deadline=transport_deadline,
            headers={"User-Agent": user_agent}, verify=True,
            allow_redirects=True,
        )
        status = int(getattr(response, "status_code", 0) or 0)
        if 100 <= status < 200 or status in BODYLESS_STATUSES:
            body = b""
        else:
            reader = getattr(response, "read_bounded", None)
            if callable(reader):
                try:
                    body = reader(json_max_bytes)
                except WptError as exc:
                    # A RESPONSE already arrived: wp.org SPOKE, whatever
                    # its body's size/shape.  Classifying this as offline
                    # returned None and demoted a HIGH finding on evidence
                    # wp.org actually sent; keep it an answered-but-
                    # unusable basis (never a demotion).
                    body_error = exc
                    body = b""
            else:
                # A session double: its json() is the whole answer and the
                # caller owns its bound.
                return _answer_from_response(response, version, locale)
        if _spent():
            raise DeadlineExceeded(
                "run deadline exceeded at the wp.org answer probe — the "
                "response body was abandoned")
    except DeadlineExceeded as exc:
        if _spent():
            raise
        if response is not None:
            # Headers arrived before the per-request bound: wp.org SPOKE.
            body_error = exc
        else:
            log.warning(
                "security.web_exposed_script: no complete answer from wp.org "
                "for WP %s (locale %s) within http.timeout_s=%s (%s) — this "
                "is the offline condition", version, locale, timeout_s, exc,
            )
            return None
    except requests.RequestException as exc:
        if _spent():
            raise DeadlineExceeded(
                "run deadline exceeded at the wp.org answer probe — the "
                "request/body was abandoned") from None
        if response is not None:
            # A RESPONSE arrived before the body transport failed (a
            # truncated Content-Length, a reset, a malformed chunked body).
            # wp.org SPOKE: this is answered-but-unusable, never the offline
            # condition that demotes a HIGH finding.
            body_error = exc
        else:
            log.warning(
                "security.web_exposed_script: no answer from wp.org for WP "
                "%s (locale %s) at all (%s) — this is the offline condition",
                version, locale, exc,
            )
            return None
    except WptError as exc:
        if _spent():
            raise DeadlineExceeded(
                "run deadline exceeded at the wp.org answer probe — the "
                "request/body was abandoned") from None
        if response is None:
            log.warning(
                "security.web_exposed_script: no answer from wp.org for WP "
                "%s (locale %s) at all (%s) — this is the offline condition",
                version, locale, exc,
            )
            return None
        body_error = exc
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            try:
                close()
            except Exception:  # noqa: BLE001 — close is best-effort
                pass
    if body_error is not None:
        # wp.org answered; only its body is unusable.  This is an answer
        # basis (`demote=False`), never the offline condition.
        return _answer_basis(
            f"HTTP {status} and a response body that could not be read "
            f"within the bound ({type(body_error).__name__})",
            version, locale, False,
        )
    payload = None
    parse_failed = False
    try:
        payload = json.loads(body)
    except Exception:  # noqa: BLE001 — a body that is not JSON is a CLASS
        parse_failed = True
    return _answer_basis(
        _answer_class(status, payload, parse_failed), version, locale,
        _no_such_build(status, payload) and not parse_failed,
    )


def _answer_from_response(response: Any, version: str,
                          locale: str) -> _CoreBasis:
    """Classify a session DOUBLE's answer (it owns its own body bound)."""
    status = int(getattr(response, "status_code", 0) or 0)
    payload = None
    parse_failed = False
    try:
        payload = response.json()
    except Exception:  # noqa: BLE001 — a body that is not JSON is a CLASS
        parse_failed = True
    return _answer_basis(
        _answer_class(status, payload, parse_failed), version, locale,
        _no_such_build(status, payload) and not parse_failed,
    )


def _no_such_build(status: int, payload: Any) -> bool:
    """True for the live API's "this build is not a release" answer.

    HTTP 200 with a JSON object that CARRIES ``checksums`` and it is not a
    map — measured on api.wordpress.org for a version that was never
    released (``{"checksums": false}``).  The key must be PRESENT: a 200
    object that says something else entirely (an error envelope, a version
    list) is not a statement about the build, and claiming "no such build"
    from it would be a claim wpt cannot support.  Every other answer is a
    different class, and each one is named rather than collapsed into this
    one.
    """
    return (status == 200 and isinstance(payload, dict)
            and "checksums" in payload
            and not isinstance(payload["checksums"], dict))


def _official_core_basis(data: AuditData, settings: Settings) -> _CoreBasis:
    """The exemption's basis and the ONE condition that produced it.

    Resolved through integrity's OWN primitives
    (:func:`resolve_core_locale` + :func:`_fetch_comparison_checksums` +
    :func:`_transport`, the same configured ``wp_org`` core.integrity and
    heal-core use, so a run that also runs core.integrity pays for one
    fetch) and never for a map of its own.

    An empty :attr:`_CoreBasis.official` is the DEGRADED answer, and
    :attr:`_CoreBasis.demote` says how far the degradation goes:

    * the version could not be read — no request at all (there is no URL
      to ask for), the reason is :data:`_VERSION_UNREADABLE`, and
      ``demote`` is False.  The run never learned whether wp.org is
      reachable, and the file that decides the answer is one the
      candidate's own author can write, so this must not lower a verdict
      (:func:`_version_statement_altered` reports the altered core when
      the file is really there).
    * a version was read and wp.org could not answer AT ALL — the offline
      condition, :data:`_CHECKSUMS_UNFETCHABLE`, ``demote`` True.  This
      is the ONLY demoting condition, and it is deliberately narrow: no
      response came, not a bad one.
    * a version was read and wp.org ANSWERED — :data:`_CHECKSUMS_NO_SUCH_BUILD`
      when the answer is "this build is not a release" (the 200
      ``{"checksums": false}`` shape), :data:`_CHECKSUMS_NOT_ESTABLISHED`
      with the answer's own class for every other shape, ``demote`` False
      in both, and :attr:`_CoreBasis.core_altered` carrying the fact
      (:data:`_ALTERED_VERSION_NO_SUCH_BUILD` /
      :data:`_ALTERED_VERSION_UNCONFIRMED`).  The candidate stays HIGH
      with the answer named in its detail: a webshell plus one write to
      ``$wp_version`` must not demote the finding that write is evidence
      for, and the STATUS of wp.org's answer is not wpt's to read as a
      verdict about the site (:func:`_wp_org_answered`).
    * a map applied — every path it lists is official core, whatever
      source the version itself came from.
    """
    from .integrity import (
        _fetch_comparison_checksums,
        _transport,
        resolve_core_locale,
    )
    from .updates import owned_session

    version = data.wp_version
    if not isinstance(version, str) or not version:
        return _CoreBasis(
            refusal=_VERSION_UNREADABLE,
            core_altered=_version_statement_altered(data.source),
        )
    locale = resolve_core_locale(
        data.source, data.locale, settings.wp_org.default_locale)
    session, timeout_s = _transport(data, settings)
    with owned_session(session, data.probe is None):
        checksums, effective = _fetch_comparison_checksums(
            version, session, timeout_s, locale, data.deadline,
            config=settings.wp_org,
        )
        if checksums is not None:
            return _CoreBasis(frozenset(checksums))
        answer = _wp_org_answered(session, timeout_s, version, effective,
                                  data.deadline, config=settings.wp_org)
    if answer is not None:
        log.warning(
            "security.web_exposed_script: wp.org ANSWERED for WP %s "
            "(locale %s) — %s — so the comparison is INCOMPLETE (not "
            "offline), nothing is exempted and the candidates stay high",
            version, effective, answer.refusal,
        )
        return answer
    return _CoreBasis(
        refusal=_CHECKSUMS_UNFETCHABLE.format(version=version,
                                              locale=effective),
        demote=True,
    )


def _web_exposed_candidates(
    data: AuditData, settings: Settings
) -> tuple[list[Entry], _CoreBasis]:
    """Top-level PHP-EXECUTABLE FILE entries that are not provably known
    files, plus the :class:`_CoreBasis` their official-core comparison
    produced (whose ``official`` set is what the map exempted and whose
    ``demote`` flag decides HIGH vs UNPROVEN).

    The scope is the webroot TOP LEVEL only: a file directly under the
    document root is web-reachable at a guessable URL with no plugin,
    theme or core mechanism involved, which is why this is neither a
    ``plugins.inactive`` nor a junk matter.  The suffix set is the
    profile's ``web_script.extensions`` (case-insensitively — see
    :data:`_WEB_SCRIPT_EXTENSIONS` for why a host's handler config, not
    ``.php``, decides what executes).  Exempt before the content read:

    * the wp-config/.htaccess pair (``integrity._USER_FILES`` — the
      site's own config, which is legitimately not in the checksum map
      and legitimately full of secrets);
    * every path the OFFICIAL wp.org checksum map for the site's
      version+build locale lists — the core top-level set
      (wp-cron.php, index.php, xmlrpc.php, ...), which is
      ``core.integrity``'s business and must not be reported twice (a
      tampered core file is its finding, high-risk, with heal-core
      behind it).  The map rides integrity's OWN fetch seam
      (:func:`_official_core_basis`); when it CANNOT be established the
      caller is handed the basis, and whether the survivors are HIGH or
      UNPROVEN is that basis's ``demote`` flag — never the mere fact
      that a basis was missing [D1];
    * every path matching a ``core_integrity.known_added`` signature
      (``_split_known_added`` — the existing mechanism, so a deployed
      artifact an operator registered stays a low-risk added-known
      finding and never a security one);
    * every path matching a ``web_script.known_artifacts`` pattern — the
      ONE owner for the artifacts wpt ITSELF leaves in a docroot.  A
      leftover ``bridge-<8 hex>.php`` is exactly this check's own shape
      (the real bridge.php carries ``hash_equals(``, ``$_GET[`` and
      ``scandir(`` — it IS a token-gated web-reachable endpoint), and
      ``Bridge.destroy()`` is best-effort, so reporting wpt's own residue
      as a HIGH backdoor on every run that could not delete it would
      train the operator to ignore this finding.  The pattern is a
      hex-strict template on the BASENAME (see
      :func:`_is_known_artifact`), which the exact-name
      ``core_integrity.known_added`` cannot express for a random hex
      suffix.
    """
    # Deferred: see the import note at the top of this module (the
    # integrity -> suspicious -> security cycle).
    from .integrity import _USER_FILES, _split_known_added

    extensions = web_script_extensions(settings)
    candidates = [
        entry for entry in data.entries
        if not entry.is_dir
        and "/" not in entry.path
        and entry.path not in _USER_FILES
        and entry.path.lower().endswith(extensions)
    ]
    if not candidates:
        return [], _CoreBasis()
    artifacts = web_script_known_artifacts(settings)
    if artifacts:
        own = [
            entry for entry in candidates
            if _is_known_artifact(entry.path, artifacts)
        ]
        if own:
            log.debug(
                "security.web_exposed_script: %d candidate(s) are wpt's own "
                "registered artifacts (%s) — not this check's business",
                len(own), ", ".join(entry.path for entry in own),
            )
            candidates = [entry for entry in candidates if entry not in own]
    if not candidates:
        return [], _CoreBasis()
    basis = _official_core_basis(data, settings)
    if basis.demote:
        log.warning(
            "security.web_exposed_script: the official-core comparison "
            "basis is UNAVAILABLE — %s — so no top-level file here can be "
            "called official core or unknown: the candidates are reported "
            "as UNPROVEN (risk medium, "
            f"{_WEB_EXPOSED_UNPROVEN_CATEGORY}) instead of high, because "
            "these needles are ordinary WordPress code "
            "(a small share of ordinary core/plugin/theme PHP files carry "
            "one) and an offline run must not tell the operator to triage "
            "wp-login.php as a backdoor. The known-file and content gates "
            "still apply.", basis.refusal,
        )
    elif basis.refusal is not None:
        # The incomplete basis that must NOT lower a verdict: whether the
        # run never reached wp.org or wp.org spoke without establishing
        # the build, it established nothing about the build, so nothing is
        # exempted and nothing is lowered [D1].
        log.warning(
            "security.web_exposed_script: the official-core comparison "
            "basis is INCOMPLETE — %s — so no top-level file here can be "
            "EXEMPTED, and the candidates stay high; wpt does not claim the "
            "map proves they are unknown, and the finding's detail says so. "
            "%s", basis.refusal,
            basis.core_altered or (
                "Nothing in this webroot is evidence of an altered core."
            ),
        )
    remaining = [entry for entry in candidates
                 if entry.path not in basis.official]
    if not remaining:
        return [], basis
    known, unresolved = _split_known_added(
        [("added", entry.path, entry.size) for entry in remaining],
        data.source, settings,
    )
    if known:
        log.debug(
            "security.web_exposed_script: %d candidate(s) match a known "
            "plugin artifact signature — not this check's business",
            len(known),
        )
    # ``_split_known_added`` speaks in (kind, path, size) tuples; this
    # candidate list is Entry objects.  Comparing the two directly was
    # always true, so every known artifact stayed in the return value.
    unresolved_paths = {path for _kind, path, _size in unresolved}
    return [entry for entry in remaining
            if entry.path in unresolved_paths], basis


def web_script_signatures(settings: Settings | None = None
                          ) -> list[tuple[str, str]]:
    """The needles as ``(name, note)`` pairs — the profile's
    ``web_script.signatures`` [L34].

    An EMPTY list means SCAN NOTHING, and says so: the old truthiness
    fallback handed a caller who had emptied the list the six module
    needles while ``to_diff`` reported the section as "no signatures", so
    the effective behaviour was not describable from the profile.  The
    module tuple is the fallback for a call that carries NO settings
    section at all (``settings=None``), and a bare ``Settings()`` still
    scans because :class:`wpt.settings.WebScriptSettings` ships the same
    values as its dataclass default — pinned equal to this tuple by
    ``test_web_script_profile_dataclass_and_module_agree``.
    """
    section = getattr(settings, "web_script", None)
    if section is None:
        return list(_WEB_SCRIPT_SIGNATURES)
    return [(entry["name"], entry["note"]) for entry in section.signatures]


def web_script_request_globals(settings: Settings | None = None
                               ) -> list[tuple[str, str]]:
    """The structured request-superglobal family as ``(name, note)``
    pairs — the profile's ``web_script.request_globals``."""
    section = getattr(settings, "web_script", None)
    if section is None:
        return list(_WEB_SCRIPT_REQUEST_GLOBALS)
    return [(entry["name"], entry["note"]) for entry in section.request_globals]


def _normalize_extension(value: str) -> str:
    """One webroot path suffix, lowercased and dotted.

    A profile entry without the leading dot is accepted and normalized
    rather than silently matching nothing: an unmatched extension is a
    check that quietly scans an empty candidate set.
    """
    suffix = value.strip().lower()
    return suffix if suffix.startswith(".") else f".{suffix}"


def web_script_extensions(settings: Settings | None = None) -> tuple[str, ...]:
    """The PHP-executable suffix set: the profile's
    ``web_script.extensions`` else the module tuple (a bare
    ``Settings()`` still scans)."""
    section = getattr(settings, "web_script", None)
    if section is None:
        return _WEB_SCRIPT_EXTENSIONS
    return tuple(_normalize_extension(value) for value in section.extensions)


def web_script_known_artifacts(settings: Settings | None = None
                               ) -> list[tuple[str, str]]:
    """The ``(pattern, note)`` pairs of wpt's OWN webroot artifacts — the
    profile's ``web_script.known_artifacts`` (a ``?`` in a pattern is ONE
    HEX character — :func:`_is_known_artifact` owns the matching); [] when
    no section is carried.  A malformed entry is skipped with one error (a
    bad ``--set`` must not crash the check), the ``known_added``
    precedent."""
    section = getattr(settings, "web_script", None)
    if section is None:
        return []
    out: list[tuple[str, str]] = []
    for index, entry in enumerate(section.known_artifacts):
        if (isinstance(entry, dict)
                and isinstance(entry.get("name"), str) and entry["name"]
                and "/" not in entry["name"]
                and isinstance(entry.get("note"), str)):
            out.append((entry["name"], entry["note"]))
        else:
            log.error(
                "security.web_exposed_script: web_script.known_artifacts "
                "entry %d is malformed, skipped", index,
            )
    return out


def _is_known_artifact(path: str, artifacts: Sequence[tuple[str, str]]) -> bool:
    """Does a top-level path's BASENAME match a registered artifact?

    NOT plain fnmatch: a ``?`` in a ``known_artifacts`` pattern is ONE HEX
    CHARACTER, never "any character" (see
    :func:`_artifact_template_re`).  wpt's own residue is named
    ``bridge-<8 hex>.php`` (``wpt.bridge_name.BRIDGE_NAME_RE`` is the
    exact-name owner) and
    the exemption is a security hole when it is wider than that name: a
    plain fnmatch ``?`` also exempts ``bridge-shellab.php`` and, before
    the pattern said so, every ``bridge-*.php`` — an attacker's dropper
    named like wpt's endpoint, in a public repository, on the very check
    that exists to catch droppers.  Hex is case-insensitive (the name is
    hex either way), so ``bridge-AB12CD34.php`` is wpt residue and
    ``bridge-shell.php`` / ``bridge-.php`` are not.
    """
    name = path.rsplit("/", 1)[-1]
    return any(_artifact_template_re(pattern).fullmatch(name)
               for pattern, _note in artifacts)


#: Compiled per distinct pattern, for the life of the process: the
#: registered list is read once per candidate set, never re-translated per
#: file.
_ARTIFACT_TEMPLATE_CACHE: dict[str, re.Pattern[str]] = {}


def _artifact_template_re(pattern: str) -> re.Pattern[str]:
    """The pattern as a HEX-STRICT full-match regex (``?`` = one hex
    digit, ``*`` = any run, everything else literal)."""
    compiled = _ARTIFACT_TEMPLATE_CACHE.get(pattern)
    if compiled is None:
        parts = []
        for char in pattern:
            if char == "?":
                parts.append(_HEX_DIGIT_CLASS)
            elif char == "*":
                parts.append(".*")
            else:
                parts.append(re.escape(char))
        compiled = re.compile("".join(parts))
        _ARTIFACT_TEMPLATE_CACHE[pattern] = compiled
    return compiled


def web_script_suffix(path: str, settings: Settings | None = None) -> str:
    """The candidate's own suffix, lowercased — the finding names the
    extension that made the file web-reachable (``.phtml``, ``.phar``, ...),
    because that is the evidence an operator needs to find the handler rule
    that executes it."""
    lowered = path.lower()
    for suffix in web_script_extensions(settings):
        if lowered.endswith(suffix):
            return suffix
    return ""


def web_script_max_bytes(settings: Settings | None = None) -> int:
    """The read bound: profile ``web_script.max_bytes`` else the module
    constant (a scope bound, not a verdict). [L34]"""
    bound = getattr(getattr(settings, "web_script", None), "max_bytes", 0)
    return int(bound or _WEB_SCRIPT_MAX_BYTES)


def _request_global_re(name: str) -> re.Pattern[str]:
    """The superglobal family match: NAME + optional whitespace/quote +
    subscript (see :data:`_GLOBAL_SUBSCRIPT`).  Compiled per call — the
    family is a handful of entries read once per candidate file."""
    return re.compile(re.escape(name) + _GLOBAL_SUBSCRIPT)


def _matched_signatures(text: str, settings: Settings | None = None) -> list[str]:
    """``"<signature> (<what it is>)"`` per signature present, in fixed order.

    Two passes over one text: the cheap literal needles
    (``web_script.signatures``) and then the structured request-superglobal
    family (``web_script.request_globals``), whose match tolerates the
    whitespace and quoting a substring scan loses to.  The NOTE de-dupes
    the two passes — a note already reported by the first pass is not
    repeated for the same concept by the family.

    An EMPTY needle list is the master switch: the content gate is OFF,
    both passes, so "scan nothing" is what an emptied
    ``web_script.signatures`` does.  ``request_globals`` stays a live knob
    in the other direction (an emptied family scans the literals alone).
    """
    needles = web_script_signatures(settings)
    if not needles:
        return []
    out: list[str] = []
    notes: set[str] = set()
    for needle, label in needles:
        if needle in text:
            out.append(f"{needle} ({label})")
            notes.add(label)
    for name, label in web_script_request_globals(settings):
        if label in notes:
            continue
        if _request_global_re(name).search(text):
            out.append(f"{name}[ ({label})")
            notes.add(label)
    return out


def _is_utf16(blob: bytes) -> bool:
    """Is this text file really UTF-16 (a BOM, or mostly NUL bytes)?

    PHP reads a BOM-prefixed UTF-16 file and skips the BOM, so a webshell
    saved as UTF-16 executes exactly like a UTF-8 one while every literal
    in it is invisible to a UTF-8 read.
    """
    if blob[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return True
    return bool(blob) and blob.count(0) / len(blob) > _UTF16_NUL_SHARE


def _text_views(blob: bytes) -> list[str]:
    """The scan views of a candidate's bytes: the UTF-8 read first, then —
    only when the file LOOKS like UTF-16 (:func:`_is_utf16`) — one view
    per UTF-16 byte order.  A plain UTF-8 file is scanned once, and a
    transcode is never scanned over a file that did not need one."""
    views = [blob.decode("utf-8", errors="replace")]
    if _is_utf16(blob):
        for codec in ("utf-16-le", "utf-16-be"):
            view = blob.decode(codec, errors="ignore")
            if view not in views:
                views.append(view)
    return views


def _inflate(blob: bytes) -> bytes | None:
    """gzip-inflate with an output bound; None when it is not gzip, is
    corrupt, or is larger than the bound (a decompression bomb is not a
    dropper payload)."""
    obj = zlib.decompressobj(_GZIP_WBITS)
    try:
        out = obj.decompress(blob, _DECODED_MAX_BYTES)
    except zlib.error:
        return None
    return None if obj.unconsumed_tail else out


def _decoded_payload(text: str) -> str | None:
    """The decoded text of a PREDOMINANT single base64/gzip blob, or None.

    Deliberately narrow, because plain-substring matching cannot see
    through an encoding and decoding ARBITRARY content would report every
    base64-looking block in the webroot as an encoded payload.  It takes
    the longest base64 run of at least :data:`_ENCODED_MIN_RUN`
    characters, and only when that run IS the file (at least
    :data:`_ENCODED_MIN_SHARE` of its non-whitespace text); it decodes
    once, inflating a gzip body under a size bound.  The caller still has
    to find a signature in what comes out before anything is reported.
    """
    stripped = _WHITESPACE_RE.sub("", text)
    if not stripped:
        return None
    runs = _ENCODED_RUN_RE.findall(text)
    if not runs:
        return None
    longest = max(runs, key=len)
    if len(longest) < _ENCODED_MIN_SHARE * len(stripped):
        return None
    try:
        raw = base64.b64decode(longest, validate=True)
    except (binascii.Error, ValueError):
        return None
    if raw[:2] == b"\x1f\x8b":
        raw = _inflate(raw)
        if raw is None:
            return None
    return raw.decode("utf-8", errors="ignore")


def _scan_views(blob: bytes, settings: Settings | None = None
                ) -> tuple[list[str], str | None]:
    """``(signature lines, encoded-payload note)`` for a candidate's bytes.

    The raw views are scanned first (:func:`_text_views`, so a UTF-16
    webshell is caught by its transcoded view).  A PREDOMINANT encoded blob
    is decoded on top of that (:func:`_decoded_payload`) whenever one is
    present, not only when the raw views came up empty: a webshell that
    gates on a plain ``$_GET[`` and then evals a base64 second stage is the
    same finding with something HIDDEN behind it, and the operator has to
    be told.  The note is the one extra report line; when the raw views
    matched nothing, their decoded signatures are also the ones the
    finding names.
    """
    views = _text_views(blob)
    matched: list[str] = []
    for view in views:
        matched = _matched_signatures(view, settings)
        if matched:
            break
    note: str | None = None
    for view in views:
        payload = _decoded_payload(view)
        if payload is None:
            continue
        decoded = _matched_signatures(payload, settings)
        if decoded:
            note = (
                "encoded-payload (base64/gzip): the decoded bytes carry "
                f"{_excerpt(decoded)}"
            )
            if not matched:
                matched = decoded
            break
    return matched, note


def _incomplete_basis_clause(basis: _CoreBasis, path: str) -> str:
    """The detail clause for a HIGH candidate whose exemption basis was
    INCOMPLETE rather than proven (the version could not be read, so no
    request to wp.org was made at all).

    It replaces the "not an official core file" claim, because that claim
    is exactly what the missing basis cannot support: wpt knows the file
    is not a known artifact and not a registered unit, and it knows the
    map was never consulted.  It says so, names the positive fact the run
    has (each :attr:`_CoreBasis.core_altered` text states its own
    conclusion, because a 400 from wp.org and a rewritten version.php are
    not the same evidence), and keeps the one instruction that survives an
    unconsulted map — confirm a stock-core-shaped file against a clean copy
    of the same build before removing it.  Nothing here lowers the risk or
    softens the fix: the triage text stays the backdoor triage [D1].
    """
    altered = basis.core_altered
    return (
        f"The official-core comparison was NOT completed ({basis.refusal}), "
        f"so wpt makes no claim that {path} is unknown to the official core "
        f"— it only knows the file is not a known artifact and not a "
        f"registered unit, and the checksum map was never consulted. "
        + (f"{altered[0].upper()}{altered[1:]}. " if altered else
           "No altered core file was found in this webroot, so the missing "
           "version may be an unreadable or absent file rather than an "
           "attacker's edit. ")
        + "If the file is one WordPress itself ships, confirm it against a "
        "clean copy of the same build (cmp -s <clean>/<file> <file>) before "
        "removing it; otherwise triage it as the finding says."
    )


def _unproven_detail(
    entry: Entry, unproven: str, signatures: list[str], evidence: str,
) -> str:
    """The detail of one UNPROVEN candidate: the missing basis FIRST, then
    the stock-core shape of the name, the measured false-positive rate, and
    only then the evidence the scan really has.

    The order is the whole point.  A reader who sees the signatures
    first reads "backdoor"; a reader who sees the basis first knows the
    file has not been classified.  The stock-core sentence is there so an
    operator looking at ``wp-login.php`` recognises the shape the map
    would have exempted — wpt cannot prove membership without the map,
    so it names the possibility rather than asserting either way.
    """
    return (
        f"UNPROVEN — NOT classified as a backdoor: the comparison basis is "
        f"unavailable ({unproven}), so wpt could not compare this site with "
        f"the official wp.org checksums and cannot say whether "
        f"{entry.path} is official core. A top-level file WordPress itself "
        f"ships (wp-login.php, wp-cron.php, wp-activate.php, xmlrpc.php, …) "
        f"is only recognizable as core through that map, and a small share of "
        f"ordinary core/plugin/theme PHP files carry one of the "
        f"signatures below, so this is expected to be stock core far more "
        f"often than not; it is still web-reachable at "
        f"{entry.path} and carries {_excerpt(signatures)}{evidence}"
    )


@register_check("security.web_exposed_script", applies=("ftp", "local"))
def check_security_web_exposed_script(
    data: AuditData, settings: Settings
) -> list[Finding]:
    """An unknown TOP-LEVEL executable script that gates on a request
    parameter or walks the home directory => HIGH, and it must leave the
    docroot.

    A top-level PHP file is served by the web server directly: no plugin,
    theme or core code loads it, so a file that is not a known file AND
    carries a request-parameter gate (a constant-time token compare, any
    request-superglobal subscript, the raw request-body stream) or a
    home-directory walk signature (``scandir(``, ``/home/``,
    ``phpinfo()``) is either an attacker's dropper or an operator's
    forgotten probe.  Both must leave the document root and NEITHER is a
    ``plugins.inactive``/junk matter: it is not a plugin unit, not a junk
    pattern, and nothing wpt removes.

    WHICH suffixes are scanned is the profile's ``web_script.extensions``,
    compared case-insensitively, and a HOST'S HANDLER CONFIGURATION is what
    actually decides execution (``AddHandler``/``mod_php`` map ``.phtml``,
    ``.phar``, ``.php5`` and ``.module`` to the PHP interpreter on shared
    hosting all the time): the shipped list is the COMMON SUPERSET, so a
    ``shell.phtml`` is as web-reachable as a ``shell.php`` and a filter
    that stopped at ``endswith(".php")`` never even considered it.

    The signature scan runs over the file's bytes in more than one view: a
    UTF-16 webshell (which PHP executes happily, BOM and all) is invisible
    to a UTF-8 read, and an encoded one is invisible to every literal —
    see :func:`_scan_views`.

    Mode-agnostic (both modes read the walked tree + the file's own
    bytes): the evidence is a file, not a live HTTP answer, and the file's
    date is enriched over HTTP when a probe exists (local mode states the
    date as unknown — an offline zip carries no clock).  ``core.integrity``
    already rates such a file HIGH as "added"; this check is the
    ACTIONABLE half of that verdict (the signatures, the date, the triage
    commands and the removal), not a second classification of it.

    Degrade contract: no source (cannot read bytes) => silent; an
    unreadable file => skipped, never a finding; an expired run budget
    (which warns instead of pretending to have scanned).

    THE UNPROVEN CLASS — the one degradation that must never lie: when the
    wp.org checksum map CANNOT BE FETCHED, wpt cannot tell an official core
    file from an unknown one, so it does NOT say "not an official core
    file" and does NOT rate the file high (measured on ordinary
    core/plugin/theme PHP files carry one of these needles, and an offline
    run rated wp-login.php, wp-cron.php, wp-activate.php, xmlrpc.php and
    four more as HIGH "not an official core file" with the backdoor triage
    text, for a site whose only fault was that wp.org could not be
    reached).  Those files are reported under their own category
    ``security.web_exposed_script_unproven``, one MEDIUM finding per
    file, the detail leading with the missing basis and the known
    stock-core-file shape of the candidate, and the fix removing
    nothing (:data:`WEB_SCRIPT_UNPROVEN_TRIAGE`).  That own category is
    load-bearing: report.py's next-step table maps the high class to a
    "triage, then rm it" action, and an unclassified file must never
    trigger it.  With the map available, the same file set is exempt or
    high — the two states are decided by the SAME basis, one fetch, one
    verdict.

    ONLY THAT CONDITION DEMOTES [D1] — "wp.org did not answer AT ALL",
    which is a transport fact (no response: a refused connection, a DNS or
    TLS failure, a timeout), never a property of the response.  Every
    other incomplete basis exempts nothing and lowers nothing:

    * the version could not be read from ``wp-includes/version.php``.  It
      proves nothing about wp.org, because the run never asked: no
      request is made without a version.  It is a file INSIDE the
      webroot, so anyone who can write the candidate can strip
      ``$wp_version`` from it, and a demotion there let a webshell
      demote its own verdict with one extra write (HIGH + backdoor
      triage became MEDIUM + "do NOT triage or remove this file on this
      evidence").
    * wp.org ANSWERED and the answer did not establish the build.  A
      response is evidence that wp.org spoke, whatever its status and
      body — and the request URL carries ``$wp_version`` verbatim, so an
      attacker chooses which answer this run gets: measured on the live
      API, a 20 000-character version string makes wp.org answer HTTP 400
      (URI too long), which read as "no answer" and demoted a real
      webshell to the unproven class.  Every such answer keeps the
      candidate HIGH with the answer's own class named in the detail
      (:func:`_wp_org_answered`).

    An incomplete basis exempts nothing and lowers nothing: the candidate
    stays HIGH, the detail drops the "not an official core file" claim in
    favour of the basis clause, and when the run HAS positive evidence
    (a version no release ever had, a version file rewritten, a build
    that could not be confirmed) the detail names exactly that evidence
    and no more.  The measured ordinary-file rate is what makes the offline
    demotion worth its cost; it is never a reason to discount a candidate
    whose basis failed for a reason the candidate's own author controls.
    """
    if data.deadline is not None and data.deadline.expired:
        # BEFORE the candidate scan: candidate classification may fetch the
        # wp.org checksums, and an expired budget must not issue a request.
        log.warning(
            "security.web_exposed_script: run deadline already reached — "
            "no top-level script scan performed"
        )
        return []
    candidates, basis = _web_exposed_candidates(data, settings)
    if not candidates:
        return []
    source = data.source
    if source is None:
        return []
    readable = [entry for entry in candidates
                if entry.size <= web_script_max_bytes(settings)]
    if len(readable) != len(candidates):
        log.info(
            "security.web_exposed_script: %d top-level executable file(s) "
            "exceed the %d-byte read bound and were not scanned",
            len(candidates) - len(readable), web_script_max_bytes(settings),
        )
    if not readable:
        return []
    max_bytes = web_script_max_bytes(settings)
    try:
        ok, failed = source.read_many(
            [entry.path for entry in readable], max_bytes=max_bytes)
    except Exception as exc:
        log.warning(
            "security.web_exposed_script: reading %d candidate file(s) "
            "failed (%s); no finding from unreadable bytes", len(readable),
            exc,
        )
        return []
    if failed:
        # The bound is a READ bound: a listing that understates a body is
        # refused by the connector and lands here as a KNOWN skip.  Silence
        # about it would let an unmeasured file read as clean.
        log.info(
            "security.web_exposed_script: %d of %d candidate file(s) could "
            "not be read within the %d-byte bound and were not scanned",
            len(failed), len(readable), max_bytes,
        )
    findings: list[Finding] = []
    ordered = sorted(readable, key=lambda e: e.path)
    for index, entry in enumerate(ordered):
        if data.deadline is not None and data.deadline.expired:
            log.warning(
                "security.web_exposed_script: run deadline reached — %d "
                "candidate file(s) not examined", len(ordered) - index,
            )
            break
        blob = ok.get(entry.path)
        if blob is None:
            continue
        # needles + request-superglobal family from the profile [L34], over
        # every view the encoding allows (UTF-8, UTF-16, a decoded blob)
        signatures, encoded = _scan_views(blob, settings)
        if not signatures:
            continue
        if data.deadline is not None and data.deadline.expired:
            log.warning(
                "security.web_exposed_script: run deadline reached — %d "
                "candidate file(s) not examined", len(ordered) - index,
            )
            break
        dated = last_modified(data.probe, entry.path,
                              deadline=getattr(data, "deadline", None))
        evidence = (
            (f"; {encoded}" if encoded else "")
            + (f"; dated {dated}" if dated
               else "; date unknown (no reachable site to date it)")
        )
        if basis.demote:
            category = _WEB_EXPOSED_UNPROVEN_CATEGORY
            risk, fix = "medium", WEB_SCRIPT_UNPROVEN_TRIAGE
            detail = _unproven_detail(
                entry, str(basis.refusal), signatures, evidence,
            )
        else:
            category, risk = "security.web_exposed_script", "high"
            fix = WEB_SCRIPT_TRIAGE
            if basis.refusal is None:
                detail = (
                    f"a top-level {web_script_suffix(entry.path, settings)} "
                    f"file that is not an official core file, a known "
                    f"artifact or any registered unit, served at the "
                    f"document root, carrying "
                    f"{_excerpt(signatures)}{evidence}"
                )
            else:
                detail = (
                    f"a top-level {web_script_suffix(entry.path, settings)} "
                    f"file served at the document root, carrying "
                    f"{_excerpt(signatures)}{evidence}. "
                    + _incomplete_basis_clause(basis, entry.path)
                )
        findings.append(Finding(
            category=category,
            name=entry.path,
            detail=detail,
            bytes=entry.size,
            count=1,
            risk=risk,
            fix=fix,
        ))

    if findings:
        unproven_names = {f.name for f in findings
                          if f.category == _WEB_EXPOSED_UNPROVEN_CATEGORY}
        log.info(
            "security.web_exposed_script: %d web-exposed top-level script(s) "
            "with an operator/backdoor signature: %s", len(findings),
            ", ".join(finding.name for finding in findings),
        )
        if unproven_names:
            log.info(
                "security.web_exposed_script: %d of them are UNPROVEN, not "
                "high — wp.org could not answer for this site's version, so "
                "%s is reported as possibly-stock core (%s)",
                len(unproven_names),
                ", ".join(sorted(unproven_names)), basis.refusal,
            )
    return findings
