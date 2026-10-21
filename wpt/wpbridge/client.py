"""Bridge client — deploy, call and destroy the token-guarded PHP bridge.

SPEC §Bridge protocol (W4). ``bridge.php`` (packaged next to this module) is
uploaded by :meth:`Bridge.ensure` under a fresh random name with a fresh
32-hex token and expiry substituted into its two placeholders; ``call`` /
``call_stream`` speak its JSON wire contract; ``destroy`` removes it again.
Use as a context manager so the bridge can never outlive its use (L6
hygiene: a token-guarded PHP file must never be left on disk).

The bridge answers plain-text ``404 nf`` on auth/expiry failures, the site's
HTML 404 page when LiteSpeed serves a cached 404 for the bridge URL (L6),
``{"ok": false, ...}`` on server-side Thrownables (L4) and NDJSON for
``db_dump`` and the read mode of ``media_rewrite_refs``. Binary cells
arrive as ``["__wpt_b64__", "<base64>"]`` pairs — in the NDJSON stream AND
in the ``media_rewrite_refs`` apply answer, which is why ONE decoder
(:meth:`Bridge._decode_cells`) serves both.
"""

import base64
import binascii
import json
import re
import secrets
import time
from pathlib import Path
from typing import Any, Iterable, Iterator

import requests

from ..config import redact, redact_text
from ..bridge_name import render_endpoint_template
from ..jsonutil import loads_bounded
from ..log import get_logger
from ..php_probe import get_bounded, post_bounded
from ..settings import BridgeSettings
from ..teardown import source_cleanup_budget
from ..types import (BridgeError, DeadlineExceeded, Source, StopRequested,
                     WptError, delete_or_prove_absent, path_may_exist)

log = get_logger("wpbridge")

_BRIDGE_PHP = Path(__file__).resolve().parent / "bridge.php"
# Public wire-protocol constant: the bridge (PHP) and the client (and the
# backup/restore disk format) all mark binary cells with this 2-element
# array tag. Single Python-side owner.
B64_MARKER = "__wpt_b64__"

#: Structural JSON nesting bound.  ``json.loads`` on an untrusted bridge
#: answer can raise RecursionError before it can return a dict, and
#: ``_decode_cells`` recurses over arrays.  A payload this deep is a wire
#: anomaly, never a WordPress value.
_JSON_MAX_DEPTH = 64

#: Ops whose RESPONSE BODY may carry a credential. `users_reset` and
#: `user_create` are the only ones: their apply answers are the places a
#: plaintext password ever exists (the ops' own docblocks in bridge.php).
#: The shared free-text redactor
#: (`config.redact_text`) matches `key=value` / `key: value` / `Authorization`
#: shapes — NOT JSON's `"password":"…"`, whose closing quote sits between the
#: key and the separator, so a body excerpt would reach the log verbatim.
#: Since the error paths that excerpt a body are exactly the ones where the
#: body did NOT parse (a site's leading PHP notice is a documented condition
#: here, SPEC R12), the shape of the answer cannot be proven at that point:
#: these ops get NO body excerpt at all. Add an op here the day its payload
#: can carry a secret; the fail direction is silence, never a leak.
_SECRET_ACTIONS = frozenset({"users_reset", "user_create"})
_SECRET_BODY_WITHHELD = "<body withheld: this op's response may carry credentials>"

#: Structural bounds the bridge owns and the client MIRRORS
#: (bridge.php's WPT_MEDIA_REWRITE_SCAN_CAP / WPT_MEDIA_REWRITE_SCAN_CAP_MAX
#: / WPT_MEDIA_REWRITE_ROW_MAX).  They are not tunables — the scan caps are
#: the points past which the op refuses to answer instead of handing back a
#: half-measured reference set, and the row ceiling is a request bound.
#:  tests/test_bridge_php.py parses the PHP literals and fails when the two
#: sides disagree.
REWRITE_REF_SCAN_CAP = 100_000
#: The CEILING on the ``scan_cap`` a caller may ask for
#: (:meth:`Bridge.iter_rewrite_refs`'s ``scan_cap``), which the op clamps to
#: and reports as ``scan_cap_clamped``.  A site that really does carry more
#: image-bearing rows than :data:`REWRITE_REF_SCAN_CAP` is the case this
#: exists for, and a caller that must not ask for more than the op will
#: honour compares against this rather than against the default.
REWRITE_REF_SCAN_CAP_MAX = 1_000_000
REWRITE_REF_ROW_MAX = 5_000

#: The extension-token shape BOTH sides of the media_map(db) wire accept,
#: mirrored with bridge.php's wpt_media_ref_extensions() (the PHP checks the
#: same ``/^[a-z0-9][a-z0-9_-]{0,31}$/``): a lowercase file suffix, no dot,
#: no path, no wildcard.  The client normalizes the run's family with it
#: BEFORE it goes on the wire — the bridge re-checks it anyway (it is the
#: trust boundary), but a family the client cannot express must not be sent
#: as a request the server will refuse.  tests/test_media_refs.py pins the
#: two spellings against each other.
MEDIA_REF_TOKEN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
#: The ceiling on a requested family (bridge.php's WPT_MEDIA_REF_EXT_MAX) —
#: structural, like the rewrite caps above: past it the request is refused
#: whole rather than spent one entry at a time.
MEDIA_REF_EXT_MAX = 512

#: The per-row refusal MARKER, and the ONE place it is written.  The
#: ``failed`` channel bridge.php's ``media_rewrite_refs`` answers carries a
#: row's refusal as ``<table>[<id>] (<reason>)``; several of its reasons
#: ALREADY begin with the marker (the shape-proof refusals do, so a caller
#: reading a refusal string always finds the marker), and this function
#: writes it — once, whatever the reason arrived as.  The marker means "this
#: row was not written"; saying it twice neither adds information nor reads
#: as a second, different refusal.
_REFUSAL_MARKER = "refused:"

#: The per-row labels the server writes ITSELF, which are not reasons: the
#: op states them in place of a diagnostic, and the marker is not this
#: side's to add to a shape the server chose — "did not verify" is a fact
#: about the write, and marking it would turn it into a different, louder
#: claim.  So a reason (anything else in the parenthesised slot, including
#: one the server sends bare) is marked, and these three are returned
#: byte-for-byte.
#:
#: Two views of one list: bridge.php's ``media_rewrite_apply`` writes exactly
#: these three, and ``tests/test_bridge_php.py`` pins each of those
#: spellings on the wire while ``tests/test_bridge_client.py`` pins them
#: here — the same arrangement ``wpt.settings.JUNK_GROUP_NAMES`` /
#: ``wpt.audit.webroot._JUNK_GROUPS`` use.  A status the server adds later
#: is marked as a reason until it is named here: the failure direction is a
#: louder label on a refusal, never a missing one.
_ROW_STATUS_LABELS = frozenset({
    "row not found",
    "write failed",
    "did not verify",
})


def _refusal_label(entry: str) -> str:
    """One per-row ``failed`` label, carrying the marker EXACTLY once.

    The server owns the wording of a reason and the shape of the label; this
    owns the marker, which only one of the two may supply.  A reason that
    already opens with the marker has its leading copies stripped and
    exactly one written back in its place, and a reason the server sends
    BARE (the per-row catch's exception text) gets the marker written here
    — so the rendered text is the same whatever the reason started with.
    One of the server's own status labels (:data:`_ROW_STATUS_LABELS`) is
    returned untouched: there is no reason to mark.

    Pure and total — a label with no parenthesised reason, or one whose
    reason is itself parenthesised (``(at level 2 its own round trip loses
    the key "a:b")``), keeps its bytes.
    """
    head, sep, reason = entry.partition(" (")
    if not sep or not reason.endswith(")"):
        return entry
    reason = reason[:-1]
    if reason in _ROW_STATUS_LABELS:
        return entry
    while reason.startswith(_REFUSAL_MARKER):
        reason = reason[len(_REFUSAL_MARKER):].lstrip()
    if not reason:
        return f"{head} ({_REFUSAL_MARKER})"
    return f"{head} ({_REFUSAL_MARKER} {reason})"


def _refusal_labels(entries: list[str], limit: int = 3) -> str:
    """The operator-facing rendering of the first ``limit`` failed labels."""
    return ", ".join(_refusal_label(e) for e in entries[:limit])


def _media_ref_extensions(extensions: Any) -> tuple[list[str] | None, str]:
    """A run's media family -> (the list to send, why it cannot be sent).

    The wire normalizer for ``media_map`` ``mode=db``: lowercased plain
    suffixes, deduplicated and sorted, bounded by
    :data:`MEDIA_REF_EXT_MAX` (bridge.php's ``WPT_MEDIA_REF_EXT_MAX``, the
    same structural ceiling the op refuses past).  ``None`` for the list
    means "send nothing" — the bridge then answers with its mirrored
    default, which is the FLOOR of the effective family, so nothing here
    can narrow a gate.

    Three shapes send nothing, and only one of them is a problem:

    * ``None`` — the caller measures no enumeration of its own (the
      pre-existing contract: the bridge answers on its own default);
    * an EMPTY family — the run treats no uploads file as media, so it
      enumerates nothing and has nothing to delete; the default answering
      is harmless;
    * a family the wire cannot EXPRESS — a blank, dotted, over-long,
      non-string or absurdly numerous entry.  That one is returned as a
      PROBLEM, because the run enumerates by a family the live gate
      cannot name: the file it would protect is invisible there, and
      invisible is deletable.  The caller turns a problem into a refusal
      (see :meth:`Bridge.db_media_refs`), never into a quiet fallback.
    """
    if extensions is None:
        return None, ""
    if isinstance(extensions, (str, bytes)) or not isinstance(
            extensions, (list, tuple, set, frozenset)):
        return None, "it is not a list of suffixes"
    out: set[str] = set()
    for value in extensions:
        if not isinstance(value, str):
            return None, f"entry {value!r} is not a string"
        token = value.strip().lower()
        if MEDIA_REF_TOKEN.fullmatch(token) is None:
            return None, f"entry {value!r} is not a plain suffix"
        out.add(token)
    if not out:
        return None, ""
    if len(out) > MEDIA_REF_EXT_MAX:
        return None, f"it carries more than {MEDIA_REF_EXT_MAX} suffixes"
    return sorted(out), ""


def wire_int(value: Any) -> int | None:
    """A wire value that is an INTEGER, or None.

    A JSON number that arrived as an int, or a string of ASCII digits (PHP
    casts every scalar to a string on its way out), becomes the int; a
    float, a bool, a non-ASCII-digit string or None is None. Used at the
    trust boundary for the two schema-version facts, where "unusable" and
    "0" must never be confused.

    PUBLIC, and used by the update-core action for the very same reason
    the client's own ``core_upgrade`` uses it: the bridge DELIBERATELY
    casts ``db_version`` to a string on the way out (a stored option row
    is not an int in PHP), so every consumer of that fact faces a JSON
    STRING.  A consumer that demands an int reads every real payload as
    ``None`` — and a reader that treats None as "unknown" then refuses a
    site that was migrated correctly.  There is exactly ONE coercion of
    this shape in the toolkit and it is this function.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        # ASCII digits only: ``str.isdigit`` also accepts non-ASCII digits
        # (Arabic-Indic "١٢٣") and characters such as "²" that ``int()``
        # then rejects with ValueError — a wire fact must not crash the
        # consumer.  PHP's own scalar cast emits ASCII.
        if text and all("0" <= char <= "9" for char in text):
            return int(text)
    return None


def wire_core_upgrade_facts(payload: dict[str, Any]) -> dict[str, str]:
    """The two core-update facts out of an ``info`` answer, as strings.

    ``info`` asked with ``core_upgrade=1`` answers
    ``{"filesystem_method": ..., "zip_library": ...}`` — the two
    preconditions WordPress's OWN updater needs before it can be driven
    without an interactive credential prompt and without a zip library.
    They are asked for on request only, because
    ``get_filesystem_method()`` writes a probe file into the webroot and
    the zip answer needs ``wp-admin/includes/file.php`` loaded, so an
    audit's plain ``info`` never pays for either.

    PUBLIC, and read by the update-core action out of the SAME ``info``
    call it already makes — one wire shape, one normalizer, so the
    driver selection cannot disagree with the bridge about what a payload
    means.  Anything missing, non-string or empty answers ``""``, which
    the selection reads as "this driver is not available here": the
    direction that picks the driver needing no precondition at all,
    rather than a fabricated ``"direct"`` that would start a core update
    core cannot finish.
    """
    facts = payload.get("filesystem_method")
    if not isinstance(facts, dict):
        return {"filesystem_method": "", "zip_library": ""}
    out = {}
    for key in ("filesystem_method", "zip_library"):
        value = facts.get(key)
        out[key] = value.strip() if isinstance(value, str) else ""
    return out


class Bridge:
    """One upload → call → self-destruct bridge session.

    ``session`` must be an already-prepared ``requests.Session`` (in
    DNS-override mode: ``wpt.dnsoverride.resolve_session`` output) — the
    bridge never builds sessions itself. ``webroot`` is the server path
    prefix the bridge file is written under (relative to the source root);
    ``site`` is the public site URL, whose document root IS the webroot —
    the deployed bridge answers at ``{site}/{name}.php``.
    """

    def __init__(self, source: Source, session: requests.Session,
                 webroot: str, settings: BridgeSettings, site: str,
                 *, deadline: float | None = None) -> None:
        self._source = source
        self._session = session
        self._settings = settings
        self._webroot = webroot.strip("/")
        self._site = site.rstrip("/")
        self._timeout = settings.timeout_s
        # The RUN's absolute monotonic budget, set by the ONE stack seam
        # (``wpt.audit.remote_stack``) for every command that builds a
        # bridge.  ``call``/``call_stream`` fall back to it when a caller
        # passes no explicit deadline, so no convenience method or action
        # call site can issue an unbounded POST by omission (R15-P1-2).
        self._run_deadline = deadline
        self._endpoint: str | None = None   # source-side path: {webroot}/{name}
        self._name: str | None = None       # deployed filename: {name}.php
        self._token: str | None = None
        # Every endpoint uploaded this session: rename cascades leave older
        # files on the server; destroy() must remove them all.
        self._uploads: list[str] = []

    # ------------------------------------------------------------- lifecycle

    def ensure(self) -> str:
        """Upload a fresh bridge under a fresh random name; return its path.

        Every call generates a NEW 32-hex token and a NEW ``bridge-<8hex>.php``
        name (L6: LiteSpeed caches 404 responses per-URL, so a name that has
        ever 404'd stays dead until renamed; a reused token would outlive its
        deployment).
        """
        token = secrets.token_hex(16)
        name = f"bridge-{secrets.token_hex(4)}"
        expiry = int(time.time()) + self._settings.ttl_minutes * 60
        template = _BRIDGE_PHP.read_text(encoding="utf-8")
        try:
            text = render_endpoint_template(
                template, token=token, expiry=expiry)
        except ValueError as exc:
            raise WptError(
                f"bridge template is unusable: {exc}; refusing to deploy "
                f"{_BRIDGE_PHP}"
            ) from None
        # WEBROOT-RELATIVE (just the filename): Source ops take webroot-
        # relative paths and prepend the webroot themselves (FtpSource
        # prefixes its FTP root).  Building "{webroot}/{name}.php" here
        # double-prefixes and the upload 553s on a real server [live-FTP
        # I4: unit fakes store the path as given, so only a real layout
        # caught it].
        endpoint = f"{name}.php"
        # Deployment is a WRITE: an already-spent run budget must not upload
        # a fresh token endpoint only for the next check to abandon it.
        self._check_absolute("deploy", self._run_deadline, run_deadline=True)
        # Record the attempted endpoint BEFORE the write, exactly like
        # PhpProbe.ensure: a protocol that applies the STOR and then reports
        # a failure (lost 226/control timeout) leaves a live token-gated
        # bridge, and destroy() must be able to remove it.  On a refused
        # cleanup the endpoint STAYS tracked for the caller's finally.
        self._endpoint = endpoint
        self._name = f"{name}.php"
        self._token = token
        self._uploads.append(endpoint)
        try:
            self._check_absolute("deploy", self._run_deadline, run_deadline=True)
            self._source.write_bytes(endpoint, text.encode("utf-8"))
        except Exception:
            cleaned = False
            try:
                # FILE2 rule: never trust exists() here.  Attempt the delete
                # unconditionally; a masked "absent" answer would otherwise
                # leave a live token endpoint untracked and destroy() would
                # skip it.
                delete_or_prove_absent(self._source, endpoint)
                cleaned = True
            except (StopRequested, DeadlineExceeded):
                # A cooperative stop during cleanup is run-ending; the
                # original write failure must not mask it.
                raise
            except Exception as cleanup_exc:  # noqa: BLE001
                log.warning(
                    "bridge cleanup after a failed write failed for %s: %s",
                    endpoint, redact_text(str(cleanup_exc)))
            if cleaned:
                self._uploads.remove(endpoint)
                self._endpoint = None
                self._name = None
                self._token = None
            raise
        log.debug("bridge deployed at %s (ttl %d min)", endpoint, self._settings.ttl_minutes)
        return endpoint

    def destroy(self) -> None:
        """Remove the bridge from the server; never raises for a missing file.

        The current endpoint is asked to self-destruct over HTTP first (the
        response must be plain-text ``gone``); a network failure, a wrong
        body, or a file that still exists afterwards falls back to
        ``source.delete``. Endpoints left behind by earlier renames are
        deleted via the source directly (their URLs may be cache-poisoned).
        Tracking is cleared per endpoint only once the delete succeeded or a
        successful listing proved the file absent, so a refused delete stays
        visible to the next ``destroy()``. Idempotent: with nothing tracked a
        second call does no work at all.

        EVERY tracked endpoint is attempted independently: an earlier stop
        (SIGTERM/deadline) on an old endpoint used to abort before the
        CURRENT endpoint's self-destruct/delete, leaving a live token bridge
        until TTL (R11-P2-12).  The first stop is remembered and re-raised
        only after every attempt; an ordinary failure is remembered too (the
        existing retry contract) but never stops the remaining attempts.
        """
        # Cleanup runs after a failure, often after the run deadline expired.
        # The source gets its fresh finite cleanup budget (Source owns the
        # swap; a plain double is a no-op), so the fallback DELE can actually
        # run instead of raising before it issues the command.
        with source_cleanup_budget(self._source):
            self._destroy_all()

    def _destroy_all(self) -> None:
        endpoint = self._endpoint
        first_stop: StopRequested | DeadlineExceeded | None = None
        first_error: Exception | None = None
        for old in [path for path in self._uploads if path != endpoint]:
            # A masked exists()=False is not proof: delete only when a
            # successful listing confirms the file may still be there.
            try:
                if path_may_exist(self._source, old):
                    delete_or_prove_absent(self._source, old)
                # The delete succeeded or the listing proved absence;
                # either way this endpoint must not be retried.
                self._uploads.remove(old)
            except (StopRequested, DeadlineExceeded) as exc:
                first_stop = first_stop or exc
            except Exception as exc:  # noqa: BLE001 — retry on the next call
                first_error = first_error or exc
                log.warning(
                    "bridge cleanup of an earlier endpoint %s failed: %s",
                    old, redact_text(str(exc)))
        if endpoint is not None:
            try:
                self._destroy_current(endpoint)
            except (StopRequested, DeadlineExceeded) as exc:
                first_stop = first_stop or exc
            except Exception as exc:  # noqa: BLE001 — caller retries/must see
                first_error = first_error or exc
        if first_stop is not None:
            raise first_stop
        if first_error is not None:
            raise first_error

    def _destroy_current(self, endpoint: str) -> None:
        """Remove the current endpoint (HTTP self-destruct, source fallback)."""
        assert self._token is not None
        stop: BaseException | None = None
        try:
            present = path_may_exist(self._source, endpoint)
        except (StopRequested, DeadlineExceeded) as exc:
            # A stop while PROVING absence must not skip the source delete
            # that follows (the token-gated endpoint would stay until its
            # TTL).  Fail closed: attempt the delete, remember the stop.
            present = True
            stop = exc
        if not present:
            log.debug("bridge already gone from %s", endpoint)
            self._forget(endpoint)
            return
        # The self-destruct GET is a CLEANUP request: it must end itself
        # even on an endless/dripping body, and it must never outlive the
        # run deadline (a teardown that cannot finish is the rule-10
        # defect).  One absolute bound: the earlier of the bridge timeout
        # and the run deadline.  An already-spent budget skips the request
        # entirely and goes straight to the source delete.
        now = time.monotonic()
        absolute = now + max(0.001, self._timeout)
        if self._run_deadline is not None:
            absolute = min(absolute, self._run_deadline)
        gone = False
        if stop is None and absolute > now:
            try:
                response = get_bounded(
                    self._session,
                    self._url(self._name, self._token, selfdestruct=True),
                    timeout_s=self._timeout,
                    deadline=absolute,
                )
                self._read_body_bounded(
                    response, "self-destruct", absolute, run_deadline=False)
                gone = (response.status_code == 200
                        and response.text.strip() == "gone")
            except (StopRequested, DeadlineExceeded) as e:
                # A stop/deadline from the self-destruct request is the run's
                # verdict, but it must not skip the source fallback: the
                # token-gated endpoint would otherwise stay on the site until
                # its TTL.  Remember it, still attempt the delete, re-raise.
                log.warning(
                    "bridge self-destruct interrupted (%s); falling back "
                    "to source delete", type(e).__name__)
                stop = e
                gone = False
            except (requests.RequestException, WptError, BridgeError) as e:
                log.warning(
                    "bridge self-destruct request failed (%s); falling back "
                    "to source delete", type(e).__name__)
                gone = False
        if not gone:
            log.debug("bridge self-destruct not confirmed for %s; deleting via source", endpoint)
        try:
            if stop is not None:
                # The absence proof itself stopped: fail closed and delete
                # without asking the same stopped operation again.
                delete_or_prove_absent(self._source, endpoint)
                self._forget(endpoint)
            elif path_may_exist(self._source, endpoint):
                delete_or_prove_absent(self._source, endpoint)
                self._forget(endpoint)
            else:
                log.debug("bridge self-destructed at %s", endpoint)
                self._forget(endpoint)
        except (StopRequested, DeadlineExceeded) as e:
            # The fallback hit its own stop: keep the endpoint tracked and
            # let the FIRST stop stay the run's reason.
            stop = stop or e
        if stop is not None:
            raise stop

    def _forget(self, endpoint: str) -> None:
        """Stop tracking ``endpoint`` after its removal or absence was proven."""
        if endpoint in self._uploads:
            self._uploads.remove(endpoint)
        self._endpoint = None
        self._name = None
        self._token = None

    def __enter__(self) -> "Bridge":
        self.ensure()
        return self

    def __exit__(self, _exc_type: type[BaseException] | None,
                 exc: BaseException | None, _tb: Any) -> None:
        # ALWAYS destroy, even on exceptions — L6 hygiene: never leave the
        # bridge on disk. The in-flight exception propagates (returns None).
        self.destroy()

    # --------------------------------------------------------------- calling

    def call(self, action: str, *, replay: bool = True,
             timeout: float | None = None,
             deadline: float | None = None,
             **params: Any) -> dict[str, Any]:
        """Run one bridge action; return the FULL decoded payload (with "ok").

        Raises :class:`BridgeError` carrying the whole server payload in
        ``.payload`` when the bridge answers ``{"ok": false, ...}``.

        ``replay=False`` marks a NON-IDEMPOTENT call: a network failure
        whose request may already have reached the site is NOT retried
        (a create cannot be replayed — the replay fails on the duplicate
        it created), and the error says the outcome is unknown instead of
        pretending the op did not run.  A provably pre-send
        ``ConnectTimeout`` is still retried.

        ``timeout`` is a relative per-CALL budget and ``deadline`` an
        ABSOLUTE ``time.monotonic()`` instant (a run :class:`~wpt.deadline.
        Deadline`'s ``.at``).  Both are enforced by the ONE transport owner
        (:meth:`_request`) as a total bound: the POST, every body read and
        every retry check it, so a server dripping one byte per read can
        never outlive the budget (requests' own timeout resets per read).
        An expired absolute run deadline raises ``DeadlineExceeded``; an
        expired relative ``timeout`` raises ``BridgeError``.  When neither
        is given, the bridge's own run deadline (set by the stack seam) is
        the bound; ``None`` there means the run is explicitly unbounded.
        """
        started = time.monotonic()
        if deadline is None:
            deadline = self._run_deadline
        response = self._request(action, params, replay=replay,
                                 timeout=timeout, deadline=deadline)
        excerpt = self._excerpt(response.text, action)
        if response.status_code != 200:
            msg = f"unexpected bridge response (HTTP {response.status_code}): {excerpt}"
            log.error("bridge %s failed: %s", action, msg)
            raise BridgeError(msg, payload={"status": response.status_code, "body": excerpt})
        try:
            data = loads_bounded(response.text)
        except (ValueError, RecursionError, MemoryError) as e:
            msg = f"bridge returned non-JSON (HTTP 200): {excerpt}"
            log.error("bridge %s failed: %s", action, msg)
            raise BridgeError(msg) from e
        if not isinstance(data, dict):
            msg = f"bridge returned a non-object JSON body (HTTP 200): {excerpt}"
            log.error("bridge %s failed: %s", action, msg)
            raise BridgeError(msg)
        if not data.get("ok"):
            log.warning("bridge %s server error: %s", action,
                        self._sanitize(json.dumps(redact(data), default=str)))
            message = str(data.get("error", "unknown error"))
            # The bridge's per-login scrubbed FAILURE REASONS are the only
            # diagnosis for a partial users_reset (password reset but a later
            # step failed vs. the reset itself failing).  They are emitted by
            # the bridge and already scrubbed by wpt_scrub_secret; surface
            # them in the one operator-facing message.
            reasons = data.get("failed_reasons")
            if isinstance(reasons, dict):
                detail = "; ".join(
                    f"{login}: {reason}"
                    for login, reason in reasons.items()
                    if isinstance(login, str) and isinstance(reason, str)
                )
                if detail:
                    message = f"{message} ({detail})"
            raise BridgeError(
                f"bridge action failed: {self._sanitize(message)}",
                payload=self._safe_payload(data)
            )
        log.debug("bridge %s ok in %d ms", action, int((time.monotonic() - started) * 1000))
        return data

    def _iter_stream_lines(self, response: Any, action: str,
                           absolute: float | None, *,
                           run_deadline: bool):
        """Yield NDJSON lines under the same absolute budget as the POST.

        ``iter_lines`` buffers internally; a peer that drips bytes without
        a newline could hold it past the deadline even though the socket
        timeout is small.  With a real response this reads available bytes
        (``read1``) and checks the budget per chunk; a response double
        without ``raw`` keeps its scripted ``iter_lines``.
        """
        if absolute is None:
            yield from response.iter_lines()
            return
        raw = getattr(response, "raw", None)
        read1 = getattr(raw, "read1", None)
        if not callable(read1):
            for line in response.iter_lines():
                self._check_absolute(action, absolute,
                                     run_deadline=run_deadline)
                yield line
            return
        buffer = b""
        while True:
            self._check_absolute(action, absolute,
                                 run_deadline=run_deadline)
            self._set_socket_timeout(response, absolute - time.monotonic())
            try:
                chunk = read1(65536, decode_content=True)
            except Exception as exc:  # noqa: BLE001 — transport boundary
                if time.monotonic() >= absolute:
                    self._check_absolute(action, absolute,
                                         run_deadline=run_deadline)
                raise BridgeError(
                    f"bridge {action} stream read failed "
                    f"({type(exc).__name__})") from None
            if not chunk:
                break
            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                yield line.rstrip(b"\r")
        if buffer:
            yield buffer

    def call_stream(self, action: str, *,
                    timeout: float | None = None,
                    deadline: float | None = None,
                    **params: Any) -> Iterator[dict[str, Any]]:
        """Run one streaming action (``db_dump``); yield each NDJSON object.

        ``deadline`` is the same ABSOLUTE ``time.monotonic()`` bound as
        :meth:`call`: the request, every line read and the close are under
        it, so a streaming origin dripping one line per read cannot hold the
        run after its budget.

        Every ``["__wpt_b64__", "<base64>"]`` pair anywhere in a line is
        decoded back to bytes (the bridge's binary-safe wire form; per
        bridge.php, ANY 2-element array whose first element is the marker
        decodes). An inline ``{"ok": false}`` envelope (a pre-stream refusal
        or a Throwable mid-stream, after NDJSON output already started)
        raises :class:`BridgeError`. Closing the generator closes the HTTP
        response (try/finally), also on GC.
        """
        started = time.monotonic()
        if deadline is None:
            deadline = self._run_deadline
        absolute = self._absolute_budget(timeout, deadline)
        run_deadline = self._absolute_is_run_deadline(absolute, deadline)
        response = self._request(action, params, stream=True, timeout=timeout,
                                 deadline=deadline)
        try:
            if response.status_code != 200:
                # EVERY non-200 stream answer is bounded by the configured
                # response cap, with or without a run deadline: an unbounded
                # ``--deadline 0`` run (or a direct API call) used to
                # materialize an arbitrary error body through ``.text``.
                self._read_body_bounded(response, action, absolute,
                                        run_deadline=run_deadline)
                excerpt = self._excerpt(response.text, action)
                msg = f"unexpected bridge response (HTTP {response.status_code}): {excerpt}"
                log.error("bridge %s failed: %s", action, msg)
                raise BridgeError(msg, payload={"status": response.status_code, "body": excerpt})
            for raw_line in self._iter_stream_lines(
                    response, action, absolute, run_deadline=run_deadline):
                self._check_absolute(action, absolute,
                                     run_deadline=run_deadline)
                if not raw_line:
                    continue
                if isinstance(raw_line, bytes):
                    try:
                        line = raw_line.decode("utf-8")
                    except UnicodeDecodeError as e:
                        raise BridgeError("bridge stream: invalid UTF-8 line") from e
                else:
                    line = raw_line
                try:
                    obj = loads_bounded(line)
                except (ValueError, RecursionError, MemoryError) as e:
                    raise BridgeError(
                        f"bridge stream: malformed NDJSON line: "
                        f"{self._excerpt(line, action)}"
                    ) from e
                if not isinstance(obj, dict):
                    raise BridgeError(
                        f"bridge stream: non-object NDJSON line: "
                        f"{self._excerpt(line, action)}"
                    )
                if "ok" in obj and not obj["ok"]:
                    log.warning("bridge %s server error: %s", action,
                                self._sanitize(json.dumps(redact(obj), default=str)))
                    raise BridgeError(
                        f"bridge action failed: {self._sanitize(str(obj.get('error', 'unknown error')))}",
                        payload=self._safe_payload(obj)
                    )
                yield self._decode_cells(obj)
            log.debug("bridge %s stream complete in %d ms",
                       action, int((time.monotonic() - started) * 1000))
        finally:
            response.close()

    # ---------------------------------------------------------------- users

    def list_users(self) -> list[dict[str, Any]]:
        """Read-only inventory of every user ``users_reset`` would reset.

        The op's ``apply`` flag is deliberately ABSENT here, and the bridge
        defaults it to false: no password is generated, no session is
        touched, and no secret ever exists. Rows are ``{login, email,
        roles}`` — the dry-run shape, which is why a plan built from this
        can be printed anywhere.
        """
        return self._users_payload(self.call("users_reset"))

    def reset_users(self, logins: Iterable[str] | None = None
                    ) -> list[dict[str, Any]]:
        """Reset user passwords to fresh random values (live WP).

        ``logins`` (optional) TARGETS the named accounts: the op compares
        case-insensitively and refuses an unmatched login, so a reset
        reported for ``logins`` really covered exactly those accounts.
        Without it EVERY user's password is reset.

        The op generates each password with WordPress's own
        ``wp_generate_password()``, sets it with ``wp_set_password()`` and
        destroys that user's session tokens, so the returned rows carry
        ``login``, ``email``, ``roles``, ``sessions_destroyed`` and the new
        ``password``.

        SECRETS: these values are returned to the CLI presentation layer and
        nowhere else. ``call()`` only ever logs a payload on failure (and
        redacts it then), this module never logs the result, and the
        callers keep the passwords out of plans, reports and exception
        messages. Do not print them from an action.
        """
        params: dict[str, Any] = {"apply": True}
        if logins is not None:
            params["logins"] = list(logins)
        try:
            payload = self.call("users_reset", **params)
        except BridgeError as exc:
            partial = self._partial_user_rows(exc.payload)
            if partial:
                raise BridgeError(str(exc), payload={
                    **exc.payload, "partial_users": partial}) from None
            raise
        return self._users_payload(payload, require_password=True)

    def check_create_user(self, login: str, email: str, role: str
                          ) -> dict[str, Any]:
        """Read-only validation of one ``user_create`` request (live WP).

        The op checks the login after ``sanitize_user( strict )`` (the
        sanitization ``wp_insert_user()`` itself applies), the email and
        the role against the live site and returns the account that WOULD
        be created — ``{login (sanitized), email, roles}`` — without
        generating a password or writing a row.  Every refusal (existing
        login or email, invalid email, unknown role) raises
        :class:`BridgeError`, so a plan built on this answer cannot fail
        on apply for a reason the site already knew.
        """
        return self._created_user_payload(
            self.call("user_create", login=login, email=email, role=role),
            require_password=False,
        )

    def create_user(self, login: str, email: str, role: str
                    ) -> dict[str, Any]:
        """Create ONE account (live WP); return the verified read-back.

        The op inserts through core's ``wp_insert_user()`` with a password
        from ``wp_generate_password()``, re-runs every validation (the
        plan/apply race) and reads the account back with
        ``get_userdata()``; the returned row carries ``login``,
        ``email``, ``roles`` and the plaintext ``password``.

        The POST is marked NON-REPLAYABLE (``replay=False``): a lost
        response after the insert would otherwise be retried, and the retry
        would fail on the duplicate the first attempt just created — rc 1
        with an existing account and no password handed over.  A network
        failure whose request may have reached the site therefore raises a
        BridgeError SAYING the outcome is unknown (see :meth:`call`).

        SECRETS: identical discipline to :meth:`reset_users` — the
        credential reaches the CLI presentation layer and nowhere else.
        """
        try:
            payload = self.call("user_create", apply=True, login=login,
                                email=email, role=role, replay=False)
        except BridgeError as exc:
            partial = self._partial_created_user(exc.payload)
            if partial:
                raise BridgeError(str(exc), payload={
                    **exc.payload, "partial_user": partial}) from None
            raise
        return self._created_user_payload(payload, require_password=True)

    @staticmethod
    def _users_payload(payload: dict[str, Any], *,
                       require_password: bool = False) -> list[dict[str, Any]]:
        """Validate the users_reset envelope; return the per-user rows.

        Fail-closed: a payload that does not prove a per-user answer (no
        ``results``, ``users`` not a list, a ``count`` that disagrees with
        it, or a row without a login / email / roles) raises
        :class:`BridgeError` instead of returning a half-understood list the
        caller could report as a successful reset.  ``require_password``
        additionally demands the plaintext value on every row — the
        contract of :meth:`reset_users`, the only caller that may carry one.

        SECRETS: an anomaly message and the attached payload are both
        redacted (``redact`` blanks every ``password``-keyed value) and the
        raw row is never echoed, so a validation failure on an apply call
        cannot leak the credential that came back with it.
        """
        results = payload.get("results")
        if not isinstance(results, dict):
            raise BridgeError("users_reset response anomaly: no results",
                              payload=redact(payload))
        users = results.get("users")
        count = results.get("count")
        if not isinstance(users, list) or isinstance(count, bool) \
                or not isinstance(count, int) or count != len(users):
            raise BridgeError(
                f"users_reset response anomaly: count={count!r}, "
                f"users={type(users).__name__} of length "
                f"{len(users) if isinstance(users, list) else 'n/a'}",
                payload=redact(payload),
            )
        skipped = results.get("skipped")
        if skipped is not None:
            if not isinstance(skipped, list) or any(
                    not isinstance(entry, dict)
                    or not isinstance(entry.get("id"), int)
                    or not isinstance(entry.get("reason"), str)
                    for entry in skipped):
                raise BridgeError(
                    "users_reset response anomaly: skipped rows are not "
                    "{id, reason} objects",
                    payload=redact(payload),
                )
            if skipped:
                # Never a login: the bridge refused to publish a
                # substituted name for a row it did not reset.  The IDs are
                # the operator's only handle, and old passwords stay live.
                log.warning(
                    "users_reset: skipped %d user(s) whose login is not "
                    "valid UTF-8 (IDs %s) — their passwords were NOT "
                    "changed and must be handled by ID",
                    len(skipped),
                    ", ".join(str(entry["id"]) for entry in skipped))
        for index, row in enumerate(users):
            Bridge._user_row(row, index, payload=payload,
                             action="users_reset",
                             require_password=require_password)
        return users

    @staticmethod
    def _created_user_payload(payload: dict[str, Any], *,
                              require_password: bool = False
                              ) -> dict[str, Any]:
        """Validate the user_create envelope; return the single user row.

        Same fail-closed contract as :meth:`_users_payload`, for the one-
        row answer the create op returns (``results.user``): a payload with
        no usable row, or — under ``require_password`` — no plaintext value
        raises :class:`BridgeError` with a redacted payload.
        """
        results = payload.get("results")
        if not isinstance(results, dict):
            raise BridgeError("user_create response anomaly: no results",
                              payload=redact(payload))
        row = results.get("user")
        if not isinstance(row, dict):
            raise BridgeError(
                f"user_create response anomaly: user={type(row).__name__}",
                payload=redact(payload),
            )
        Bridge._user_row(row, 0, payload=payload, action="user_create",
                         require_password=require_password)
        return row

    @staticmethod
    def _user_row(row: Any, index: int, *, payload: dict[str, Any],
                  action: str, require_password: bool) -> None:
        """Validate ONE user answer row in place (raises on any violation).

        The one row rule for both ops: ``login``/``email`` non-empty-ish
        strings (email may be blank — a real WordPress state), ``roles`` a
        list of strings, and, when the caller may carry it, a non-empty
        string ``password``.
        """
        if (not isinstance(row, dict)
                or not isinstance(row.get("login"), str) or not row["login"]
                or not isinstance(row.get("email"), str)
                or not isinstance(row.get("roles"), list)
                or any(not isinstance(r, str) for r in row["roles"])):
            login = row.get("login") if isinstance(row, dict) else None
            raise BridgeError(
                f"{action} response anomaly: malformed user row "
                f"{index} (login={login!r})",
                payload=redact(payload),
            )
        if require_password and (not isinstance(row.get("password"), str)
                                 or not row["password"]):
            raise BridgeError(
                f"{action} response anomaly: no password for user "
                f"{row['login']!r}",
                payload=redact(payload),
            )

    @staticmethod
    def _partial_user_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
        """Every COMPLETE users_reset row in a failure payload (C12).

        The bridge's per-user containment marks the op ``ok:false`` but
        still returns the accounts whose password was already set.  Each
        row is validated with the SAME contract as a success row; a
        malformed row is dropped, never published half-filled.
        """
        results = payload.get("results") if isinstance(payload, dict) else None
        users = results.get("users") if isinstance(results, dict) else None
        if not isinstance(users, list):
            return []
        complete: list[dict[str, Any]] = []
        for index, row in enumerate(users):
            try:
                Bridge._user_row(row, index, payload={}, action="users_reset",
                                 require_password=True)
            except BridgeError:
                continue
            complete.append(row)
        return complete

    @staticmethod
    def _partial_created_user(payload: dict[str, Any]) -> dict[str, Any] | None:
        """The COMPLETE user_create row in a failure payload, or None (C12)."""
        results = payload.get("results") if isinstance(payload, dict) else None
        row = results.get("user") if isinstance(results, dict) else None
        if not isinstance(row, dict):
            return None
        try:
            Bridge._user_row(row, 0, payload={}, action="user_create",
                             require_password=True)
        except BridgeError:
            return None
        return row

    # ------------------------------------------------------------- media map

    def db_media_refs(self, extensions: Any = None) -> set[str]:
        """Every uploads file the DATABASE references — ONE read-only call.

        ``media_map`` in ``mode=db``: the same op the media actions already
        use to resolve upload paths to attachment ids, answering the other
        half of the keep-set instead (the bridge's ``wpt_media_db_map`` —
        attachment paths + metadata size maps, post content, theme/widget/
        menu options, term meta).  A page renders only a FRACTION of its
        attachment images: measured live on a real site, most files
        (most of the media bytes) were database-referenced and invisible to
        the live walk, so a walk-only trim would have deleted them.

        Uploads-relative POSIX paths ("2023/10/pic-300x233.jpg") — the same
        shape the walker and ``media_map``/``media_delete`` speak, so a
        caller unions the two sets without translation.

        TOLERANT about entries, STRICT about the answer.  The bridge gates
        every entry it emits (normalized, extension-bearing, non-directory
        — see ``wpt_media_ref_normalize``/``wpt_media_ref_is_kept``), and a
        real site still offers references that gate refuses: measured live
        an observed run, one stale ``_transient_dirsize_cache`` option held many
        absolute paths to the site's PREVIOUS host, several of them bare year
        DIRECTORIES.  An entry this client cannot use is DROPPED and
        counted — losing it can only under-protect, and one junk row must
        never cost the site the whole union (which is what the former
        all-or-nothing validation did: the keep-set silently degraded to
        walk-only, and ``trim-media --apply`` then refused).  The lossy
        count is reported ONCE, so the operator sees it.

        FAIL-CLOSED on the answer itself: a missing/mistyped ``db_refs``,
        or a ``truncated`` marker, raises :class:`BridgeError` instead of
        returning a partial set — a half-measured keep-set is exactly how a
        referenced file gets deleted.

        ``extensions`` is the CALLER'S media family
        (``settings.media.extensions`` — the same list the enumeration
        files uploads media by), carried on the request so the server-side
        gate answers with it.  The deployed bridge cannot read the
        operator's profile, and answering from its own mirrored literal
        while the enumeration answered from the profile is what made a
        profile-widened file (``--set media.extensions=[..., "psd"]``)
        invisible to the keep-gate and therefore DELETABLE while the
        database referenced it.

        The mirrored default is a FLOOR (bridge.php's
        ``wpt_media_ref_extensions``): the effective family is the default
        UNION the request, so the wire can only WIDEN the gate — no
        hand-written request can make the live gate narrower than the
        shipped family and turn the op into a delete-everything tool.
        Neither side may answer with a family the run did not ask for: one
        this client cannot EXPRESS raises here, and one the server refuses
        (or reports narrower than it was sent) raises in
        :meth:`Bridge._require_gate` — in both cases a keep-set measured
        with a different list than the enumeration assumes, which is the
        defect itself.

        ``None`` (the default) and an EMPTY family both send no list, and
        the bridge answers on its mirrored default exactly as it always
        did: a run that measures no enumeration of its own needs no family,
        and one that treats no uploads file as media has nothing to delete.
        """
        # The wire mode of the read-only DB map (bridge.php
        # wpt_action_media_map): "db" answers the database media map,
        # anything else (the default) resolves refs to attachment ids.  The
        # caller's family rides the same call — a second call would be a
        # second measurement of one database.
        requested, problem = _media_ref_extensions(extensions)
        if problem:
            # The run enumerates uploads media by a family the live gate
            # cannot name.  Answering on the mirrored default instead would
            # be a keep-set measured with a DIFFERENT list than the
            # enumeration assumes — a reference invisible to the gate is a
            # file this tool would delete (the defect the parameter exists
            # to close), so there is no safe fallback to take.
            raise BridgeError(
                f"media_map(db): this run measures a media extension family "
                f"the live gate cannot be told about ({problem}) — the "
                f"database keep-set would be narrower than the files it is "
                f"compared against, so it is refused (media.extensions "
                f"entries are plain lowercase suffixes without dots, at most "
                f"{MEDIA_REF_EXT_MAX} of them)",
                payload={"extensions": repr(extensions)[:200]},
            )
        params: dict[str, Any] = {"mode": "db"}
        if requested is not None:
            params["extensions"] = requested
        payload = self.call("media_map", **params)
        if requested is not None:
            self._require_gate(payload, len(requested))
        if payload.get("truncated"):
            raise BridgeError(
                "media_map(db) response anomaly: the server reported a "
                "truncated reference set; refusing a partial keep-set",
                payload=redact(payload),
            )
        raw = payload.get("db_refs")
        if not isinstance(raw, list):
            raise BridgeError(
                f"media_map(db) response anomaly: no db_refs list "
                f"({type(raw).__name__})",
                payload=redact(payload),
            )
        refs: set[str] = set()
        dropped = 0
        for entry in raw:
            if self._usable_db_ref(entry):
                refs.add(entry)
            else:
                dropped += 1
        # The bridge's own gate counts what it refused; both counts are
        # the same fact seen from two sides (its gate, and this client's
        # shape check), reported once so a lossy keep-set is visible.
        reported = payload.get("db_refs_dropped")
        server_dropped = (reported if isinstance(reported, int)
                          and not isinstance(reported, bool) else 0)
        if server_dropped or dropped:
            log.warning(
                "bridge media map (db): %d reference(s) were dropped as "
                "unusable (%d refused by the server, %d malformed here) — "
                "the keep-set is lossy; a file only a dropped reference "
                "named is no longer protected",
                server_dropped + dropped, server_dropped, dropped,
            )
        return refs

    @staticmethod
    def _usable_db_ref(entry: Any) -> bool:
        """Is one ``db_refs`` entry a shape the keep-set can union?

        A non-empty uploads-RELATIVE POSIX path with no empty/``.``/``..``
        segment.  Deliberately shape-only: the *rules* for what a real
        reference is live in the bridge (one implementation, and the side
        that can see the filesystem), so this check never re-decides them.
        """
        if not isinstance(entry, str) or not entry or entry.startswith("/"):
            return False
        return not any(segment in ("", ".", "..") for segment in entry.split("/"))

    @staticmethod
    def _require_gate(payload: dict[str, Any], requested: int) -> None:
        """The gate the answer was measured with must CONTAIN ours.

        The answer reports the effective family's size (``db_refs_gate``)
        and flags a refused request (``db_refs_gate_fallback``).  A family
        SMALLER than the one this run asked for — or an explicit refusal —
        means the keep-set in hand is not the measurement the enumeration
        assumed, which is precisely the defect this parameter exists to
        close: a file the database references, invisible to the gate,
        planned for deletion.  Fail closed (every consumer degrades to an
        UNKNOWN reference set; the destructive one refuses).

        A family LARGER than ours is the default floor widening a narrowed
        profile: it can only protect more, so it is accepted.  An answer
        that reports no gate at all is accepted for the same reason the
        missing-``db_refs_dropped`` count is: an older answer shape is
        tolerated, never trusted to be wider.
        """
        refused = payload.get("db_refs_gate_fallback") is True
        gate = payload.get("db_refs_gate")
        measured = (gate if isinstance(gate, int)
                    and not isinstance(gate, bool) else None)
        if not refused and (measured is None or measured >= requested):
            return
        size = "an unknown number of" if measured is None else str(measured)
        raise BridgeError(
            f"media_map(db) response anomaly: the server gated the database "
            f"media map with {size} extension(s), which does not contain "
            f"the {requested} this run measures — the keep-set is not the "
            f"measurement this run asked for, so it is refused (give "
            f"media.extensions as plain lowercase suffixes without dots)",
            payload=redact(payload),
        )

    # ------------------------------------------------- webp ref rewrite

    def iter_rewrite_refs(self, *, scan_cap: int | None = None
                          ) -> Iterator[dict[str, Any]]:
        """Stream the read-only reference rows (``media_rewrite_refs``).

        The read mode of the op the webp-media action uses to find every
        database cell that may hold a media reference — the rewritable
        surfaces (a ``value`` the rewrite can move) and the read-only
        ``gated`` surfaces (references nothing can rewrite, so their images
        must keep their original bytes).  Each yielded object is the row
        the bridge emitted: ``{table, key, id, value?, gated?}``.

        ``scan_cap`` is the OPERATOR DOOR for a site that really does carry
        more image-bearing rows than :data:`REWRITE_REF_SCAN_CAP`: the op
        truncates (and this method then refuses the truncated answer) at the
        cap instead of at its own default, so a site over the default is
        measurable rather than permanently unmeasurable.  ``None`` — the
        default — asks for nothing and leaves the answer byte-identical to
        one that never mentioned a cap.  A cap above
        :data:`REWRITE_REF_SCAN_CAP_MAX` is not an error here: the op clamps
        it, says so once on its completion line, and this method logs that
        WARNING, because a cap the caller believes in and the server did not
        honour is how an operator ends up believing a site was measured to
        the depth they asked for when it was not.  The op is the validating
        owner of the bound (a malformed cap is its structured refusal, not a
        local guess), so this argument is forwarded as given.

        FAIL-CLOSED, three times over.  A ``truncated`` marker raises at
        once: a half-measured reference set cannot prove that converting an
        image is safe, which is the whole reason the action needs this set.
        A stream that ends WITHOUT the terminal ``{"ok": true, "rows": N}``
        summary raises too — a connection cut or a fatal after the first
        lines would otherwise look like a complete (and much smaller)
        answer.  And the summary's own row count must be an ``int`` AND
        equal the number of rows yielded: a count the client cannot even
        read as a number is no more a proof than a missing one (the claim
        "a lost line cannot pass as a finished scan" is only true if the
        declared count is actually compared), so ``rows: "2"``, ``true``
        and ``null`` are refused exactly like an absent summary.

        Cells arrive as ``str``, or as ``bytes`` for a value the bridge
        marked ``["__wpt_b64__", ...]`` (a non-UTF-8 BLOB): such a cell
        holds no reference, and a caller that rewrites only text ignores
        it.  Nothing here decides what a reference IS — the caller's own
        extractor does, and a value it cannot parse becomes a gate.
        """
        rows = 0
        declared: Any = None
        completed = False
        params: dict[str, Any] = {}
        if scan_cap is not None:
            params["scan_cap"] = scan_cap
        for obj in self.call_stream("media_rewrite_refs", **params):
            if obj.get("truncated"):
                raise BridgeError(
                    "media_rewrite_refs: the reference scan was truncated by "
                    "the server; a partial reference set cannot prove that "
                    "converting an image is safe — refusing"
                )
            if obj.get("ok") is True:
                declared = obj.get("rows")
                completed = True
                clamped = obj.get("scan_cap_clamped")
                if clamped is not None:
                    # The op said ONCE, on the one line this method already
                    # reads as "the scan finished", that it did not honour
                    # the cap that was asked for.  The scan may still be
                    # complete — but it is bounded where the op decided, not
                    # where the caller did, and that has to be visible in the
                    # log next to the plan this set produces, not only in a
                    # raw answer nobody reads.
                    log.warning(
                        "media_rewrite_refs: the server CLAMPED the requested "
                        "scan cap to %s row(s) (its ceiling is %s); this "
                        "reference set is bounded there, not at the cap that "
                        "was asked for",
                        clamped, REWRITE_REF_SCAN_CAP_MAX,
                    )
                continue
            yield self._rewrite_ref_row(obj, rows)
            rows += 1
        if not completed:
            raise BridgeError(
                "media_rewrite_refs: the reference scan ended without its "
                "completion marker; the answer is incomplete — refusing"
            )
        if isinstance(declared, bool) or not isinstance(declared, int):
            # The count is the proof, so an unreadable one is no proof at
            # all: the same refusal as a missing marker, and the cross-check
            # below must never be SKIPPED by a mistyped count (a "2" that
            # compares unequal to nothing would accept a lost line as a
            # finished scan).
            raise BridgeError(
                f"media_rewrite_refs response anomaly: the completion marker "
                f"reported rows={declared!r} instead of a row count; the "
                f"answer cannot be cross-checked — refusing"
            )
        if declared != rows:
            # The server counts what it emitted: a disagreement means a
            # line was lost, and a lost row is a reference the caller
            # believes nothing holds.
            raise BridgeError(
                f"media_rewrite_refs response anomaly: the server reported "
                f"{declared} row(s) and {rows} arrived; the answer is "
                f"incomplete — refusing"
            )

    def rewrite_refs(self, *, mapping: dict[str, str],
                     rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Apply the reference rewrite; return the PROVEN re-read rows.

        ``mapping`` is ``{old reference: new reference}`` and ``rows`` is
        ``[{table, key, id, value?}]`` — the op's own wire shapes.  A row
        that carries a ``value`` is written verbatim (the caller computed
        the rewrite); a row without one is rewritten SERVER-SIDE through
        ``maybe_unserialize`` -> string-leaf replace -> ``maybe_serialize``,
        which is the only thing that can fix the ``s:NN:`` byte lengths a
        serialized value carries.

        WHAT IS PROVEN, per row, and by this client — not by the server's
        claim alone:

        - A row the client gave a ``value`` for is COMPARED: the re-read
          must equal the value the client asked to write, or the call
          raises.  A server that re-read the old value, an unrelated row or
          anything else is refused (the server's own re-read proves THAT a
          write landed, never WHAT landed).
        - A row the client gave NO value for is flagged
          ``rewritten_by_server: True``: the server computed that value
          inside a serialized structure, so the client cannot recompute it
          and the re-read is a REPORT, never an equality proof.  A row
          without the flag is one the client compared and matched.

        Anything the op could not write, write-verify or find raises
        :class:`BridgeError` (with the row labels, which name a table and an
        id and no value) rather than returning a partial write; so does a
        re-read that does not decode, a mismatching re-read, and an answer
        that does not carry every requested row.

        The apply answer is decoded by the SAME ``__wpt_b64__`` decoder the
        stream reader uses (``call()`` does not decode, so ``call_stream``
        cannot be reused here — but the decoder must not be a second copy).
        A non-UTF-8 cell (a latin1/mojibake ``option_value`` is real) comes
        back as ``bytes``; a cell that cannot be decoded at all makes its
        row UNPROVEN, in the same failed channel as the server's own
        failures — it never turns into a whole-call shape error, because the
        write it would be reporting on has ALREADY happened.
        """
        payload = self.call("media_rewrite_refs", apply=True,
                            mapping=mapping, rows=rows)
        written = payload.get("rows")
        failed = payload.get("failed", [])
        if not isinstance(written, list) or not isinstance(failed, list) \
                or any(not isinstance(f, str) or not f for f in failed):
            raise BridgeError(
                "media_rewrite_refs response anomaly: no rows/failed lists",
                payload=redact(payload),
            )
        if failed:
            raise BridgeError(
                f"media_rewrite_refs: {len(failed)} row(s) were not "
                f"rewritten ({_refusal_labels(failed)})",
                payload=redact(payload),
            )
        # What the client ASKED to write, by label: the comparison below
        # needs the request side, so it is read from the caller's rows.
        requested: dict[tuple[str, int], str] = {}
        for entry in rows:
            if isinstance(entry, dict) and isinstance(entry.get("value"), str):
                requested[(str(entry.get("table")), entry.get("id"))] = entry["value"]
        out: list[dict[str, Any]] = []
        unproven: list[str] = []
        seen: set[tuple[str, int]] = set()
        for index, entry in enumerate(written):
            if (not isinstance(entry, dict)
                    or not isinstance(entry.get("table"), str)
                    or isinstance(entry.get("id"), bool)
                    or not isinstance(entry.get("id"), int)):
                raise BridgeError(
                    f"media_rewrite_refs response anomaly: malformed row "
                    f"{index} in the re-read answer",
                    payload=redact(payload),
                )
            label = f"{entry['table']}[{entry['id']}]"
            try:
                row = self._decode_cells(entry, "bridge answer")
            except BridgeError:
                # The cell cannot be read back, so this row's write is
                # UNPROVEN.  The write already happened: this must fail the
                # call through the failed channel, never as a shape error
                # that hides the fact that one row of N was written.
                unproven.append(f"{label} (re-read value is undecodable)")
                continue
            if not isinstance(row.get("value"), (str, bytes)):
                raise BridgeError(
                    f"media_rewrite_refs response anomaly: malformed row "
                    f"{index} in the re-read answer",
                    payload=redact(payload),
                )
            key = (row["table"], row["id"])
            if key in requested:
                if row["value"] != requested[key]:
                    # The re-read does not match what was asked to be
                    # written: labels only, never a value.  Same condition
                    # the bridge labels "did not verify" on its own side, and
                    # the same words the webp action's failure reporting
                    # already speaks.
                    raise BridgeError(
                        f"media_rewrite_refs response anomaly: the re-read of "
                        f"{label} does not match the value this client asked "
                        f"to write; the write did not verify — refusing",
                        payload=redact(payload),
                    )
            else:
                # Server-rewritten (a serialized value the client cannot
                # recompute): reported, never passed off as an equality
                # proof.
                row["rewritten_by_server"] = True
            out.append(row)
            seen.add(key)
        if unproven:
            raise BridgeError(
                f"media_rewrite_refs: {len(unproven)} re-read(s) could not "
                f"be proven ({', '.join(unproven[:3])})",
                payload=redact(payload),
            )
        asked = {(str(r.get("table")), r.get("id")) for r in rows
                 if isinstance(r, dict)}
        if not asked.issubset(seen):
            missing = sorted(f"{t}[{i}]" for t, i in asked - seen)
            raise BridgeError(
                f"media_rewrite_refs response anomaly: the answer omits "
                f"{len(missing)} requested row(s) ({', '.join(missing[:3])})",
                payload=redact(payload),
            )
        if any("rewritten_by_server" in row for row in out):
            log.info(
                "bridge media_rewrite_refs: %d of %d row(s) were rewritten "
                "server-side (serialized values); their re-read is reported, "
                "not compared",
                sum(1 for row in out if "rewritten_by_server" in row), len(out),
            )
        return out

    @staticmethod
    def _rewrite_ref_row(obj: dict[str, Any], index: int) -> dict[str, Any]:
        """Validate one streamed reference row; return it unchanged.

        Shape-only, and strict: a row the caller cannot address (no table,
        no integer id) or whose cells are not text/binary is refused
        instead of skipped, because a silently dropped row is a reference
        the caller believes nothing holds — the exact half-measured set the
        op's truncation marker exists to prevent.
        """
        table = obj.get("table")
        row_id = obj.get("id")
        if not isinstance(table, str) or not table or not obj.get("key") \
                or isinstance(row_id, bool) or not isinstance(row_id, int):
            raise BridgeError(
                f"media_rewrite_refs response anomaly: malformed row {index} "
                f"(table={table!r}, id={row_id!r})"
            )
        value = obj.get("value")
        if value is not None and not isinstance(value, (str, bytes)):
            raise BridgeError(
                f"media_rewrite_refs response anomaly: non-text value in "
                f"row {index} ({table}[{row_id}])"
            )
        gated = obj.get("gated")
        if gated is not None and (
                not isinstance(gated, list)
                or any(not isinstance(cell, (str, bytes)) for cell in gated)):
            raise BridgeError(
                f"media_rewrite_refs response anomaly: malformed gated cells "
                f"in row {index} ({table}[{row_id}])"
            )
        return obj

    # ------------------------------------------------------------- plugins

    def reconcile_active_plugins(self, *, apply: bool = False) -> dict[str, Any]:
        """Compare ``active_plugins`` against the installed plugin set.

        Read-only by default (``apply=False``): the bridge answers which
        entries are active-but-absent without rewriting anything. With
        ``apply=True`` the op drops exactly those entries through core's
        2-argument ``update_option()`` and re-reads the option afterwards,
        so ``active_now`` is the PERSISTED state, not the write's echo.
        Returns the op payload (``installed``, ``active_before``,
        ``missing``, ``applied``, ``updated``, ``removed``, ``active_after``,
        ``active_now``).
        """
        # The flag is OMITTED when read-only: the bridge defaults it to
        # false, so the fail-closed path is also the shortest wire shape.
        return self.call("reconcile_active_plugins",
                         **({"apply": True} if apply else {}))

    # ------------------------------------------------------------- core

    def upgrade_core(self) -> dict[str, Any]:
        """Run WordPress's own database migration; return the proof.

        ``core_upgrade`` with ``apply=true`` — the ONLY way this method
        puts the op in its mutating shape (the bridge refuses the op
        without the flag, so a stray ``call("core_upgrade")`` migrates
        nothing). The op body is core's own
        ``require_once wp-admin/includes/upgrade.php; wp_upgrade();``:
        the schema target is the ``$wp_db_version`` of the core THIS
        request loaded, so the caller must have swapped the files before
        calling it.

        Returns ``{"db_version", "wp_version", "target_db_version",
        "output", "output_truncated"}``. ``db_version`` is the STORED
        schema version read back after the migration, and both versions
        are normalized to ``int`` here: the values are numeric by
        definition (WordPress's own schema versions are integers), and a
        non-numeric answer is a wire anomaly this method refuses rather
        than handing a caller a string to compare against a number it
        meant. A ``null`` stored value is likewise refused — it means the
        option could not be read, which is "unknown", never "0".

        ``output`` is what the migration PRINTED — captured, bounded and
        UTF-8-cleaned by the op (so the JSON envelope survives it) and
        LOGGED, redacted, through this module's logger rather than
        discarded.  It matters because a modest ``memory_limit`` on a big
        migration, a plugin's notice, or a theme's warning is the only
        evidence of WHY the schema did not move, and the old contract
        threw that evidence away and reported only "something printed".

        A FATAL inside ``wp_upgrade()`` is not catchable and destroys
        this answer entirely (non-JSON, no envelope) — which is why the op
        leaves a marker the client can read afterwards; see
        :meth:`upgrade_marker`.
        """
        payload = self.call("core_upgrade", apply=True)
        out: dict[str, Any] = {}
        for key in ("db_version", "target_db_version"):
            value = payload.get(key)
            number = wire_int(value)
            if number is None or number < 1:
                raise BridgeError(
                    f"core_upgrade response anomaly: unusable {key} "
                    f"({value!r}) — the migration's result cannot be "
                    f"read, so it cannot be reported",
                    payload=redact(payload),
                )
            out[key] = number
        version = payload.get("wp_version")
        if not isinstance(version, str) or not version:
            raise BridgeError(
                f"core_upgrade response anomaly: unusable wp_version "
                f"({version!r})",
                payload=redact(payload),
            )
        out["wp_version"] = version
        output = payload.get("output")
        if not isinstance(output, str):
            raise BridgeError(
                f"core_upgrade response anomaly: output is "
                f"{type(output).__name__}, not a string",
                payload=redact(payload),
            )
        truncated = payload.get("output_truncated")
        if not isinstance(truncated, bool):
            raise BridgeError(
                f"core_upgrade response anomaly: output_truncated is "
                f"{type(truncated).__name__}, not a bool",
                payload=redact(payload),
            )
        if output:
            # redact_text is the shared free-text scrubber (key=value /
            # key: value / Authorization shapes); a migration's output is
            # an unbounded-by-nature blob of whatever core and its hooks
            # decided to print, so it is redacted on the way into the log
            # exactly like every other payload that could reach one.
            log.warning("core_upgrade: the migration printed output (kept, "
                        "not discarded — the reported db_version/wp_version "
                        "were read back from the database): %s%s",
                        redact_text(output),
                        " [truncated]" if truncated else "")
        out["output"] = output
        out["output_truncated"] = truncated
        return out

    def core_upgrade_files(self, package: str, target: str) -> dict[str, Any]:
        """Install a core release with WORDPRESS'S OWN updater.

        ``core_upgrade_files`` with ``apply=true`` — the only way this
        method puts the op in its mutating shape.  ``package`` is the
        webroot-relative path of the release zip the caller already proved
        against wp.org's checksum map and uploaded; ``target`` is the X.Y.Z
        that package must carry.  The op itself runs core's own
        ``unpack_package()`` (its ``unzip_file()`` into
        ``wp-content/upgrade/``) and ``update_core()`` (``copy_dir()`` with
        core's ``array('wp-content', 'wp-includes/version.php')`` skip
        list, version.php last, the bundled theme/plugin re-add), armed
        with ``attempt_rollback`` — the argument the admin UI never passes.

        Returns the op's own account of what it did: ``wp_version`` read
        back off the DISK, ``from_wp_version``, ``staging`` /
        ``staging_exists``, ``upgrade_args``, ``rollback``, the per-phase
        ``phases`` (each MEASURED, not claimed), core's own ordered
        ``progress`` messages, ``bundled_added``, ``db_step``,
        ``filesystem_method``, ``zip_library``, ``maintenance_left``,
        ``output`` / ``output_truncated``.

        A CORE failure is raised, not returned: the op answers
        ``ok: true`` with ``error: {code, message}`` precisely so the
        phases that got that far survive, and this method turns that into a
        :class:`BridgeError` whose ``payload`` IS the account — the caller
        reports the failing phase, the staging directory and whether the
        failure is the class core would have rolled back.  The core error
        is raised BEFORE the version is read, because on a failed run the
        version on disk is legitimately not the target's and the error is
        the diagnosis; the version is required on the success path, where
        it must BE the target.  An unusable answer shape (no phases, no
        staging) is a ``BridgeError`` naming the field, because a driver
        whose result cannot be read cannot be called successful.
        """
        payload = self.call("core_upgrade_files", apply=True,
                            package=package, target=target)
        error = payload.get("error")
        if not (isinstance(error, dict) and error.get("code")):
            if error is not None:
                raise BridgeError(
                    "core_upgrade_files response anomaly: unusable error "
                    f"({error!r}) — a failure that cannot be read cannot be "
                    "reported as one",
                    payload=redact(payload),
                )
        phases = payload.get("phases")
        if not isinstance(phases, dict) or not phases:
            raise BridgeError(
                "core_upgrade_files response anomaly: no phases — the op "
                "did not report what it did, so nothing can be claimed",
                payload=redact(payload),
            )
        staging = payload.get("staging")
        if not isinstance(staging, str):
            raise BridgeError(
                "core_upgrade_files response anomaly: unusable staging "
                f"({staging!r}) — the staging directory is the recovery "
                "path after a failed core update and must be reportable",
                payload=redact(payload),
            )
        out: dict[str, Any] = {
            "phases": phases,
            "staging": staging,
            "staging_exists": bool(payload.get("staging_exists")),
            "upgrade_args": (payload.get("upgrade_args")
                             if isinstance(payload.get("upgrade_args"), dict)
                             else {}),
            "rollback": (payload.get("rollback")
                         if isinstance(payload.get("rollback"), dict) else {}),
            "progress": (payload.get("progress")
                         if isinstance(payload.get("progress"), list) else []),
            "bundled_added": (payload.get("bundled_added")
                              if isinstance(payload.get("bundled_added"), list)
                              else []),
            "db_step": payload.get("db_step") if isinstance(
                payload.get("db_step"), str) else "",
            "filesystem_method": payload.get("filesystem_method")
            if isinstance(payload.get("filesystem_method"), str) else "",
            "zip_library": (payload.get("zip_library")
                            if isinstance(payload.get("zip_library"), str)
                            else ""),
            "maintenance_left": bool(payload.get("maintenance_left")),
            "output": payload.get("output") if isinstance(
                payload.get("output"), str) else "",
            "output_truncated": bool(payload.get("output_truncated")),
        }
        # The core failure, with the account in the payload — and BEFORE the
        # version is read, because on a failed run the version on disk is
        # legitimately something else and the error is the diagnosis.
        if isinstance(error, dict) and error.get("code"):
            raise BridgeError(
                f"WordPress's own updater failed: {error.get('code')}: "
                f"{error.get('message') or 'no message'}",
                payload=redact(payload),
            )
        for key in ("wp_version", "from_wp_version"):
            value = payload.get(key)
            if not isinstance(value, str) or not value:
                raise BridgeError(
                    f"core_upgrade_files response anomaly: unusable {key} "
                    f"({value!r}) — the version the site now runs is what "
                    "the caller verifies, so it must be readable",
                    payload=redact(payload),
                )
            out[key] = value
        if out["wp_version"] != target:
            raise BridgeError(
                f"core_upgrade_files did not install the target: the core on "
                f"disk declares {out['wp_version']}, not {target} — the "
                f"update is NOT done; the pre-action snapshot "
                f"(`wpt restore --undo-last`) is the rollback",
                payload=redact(payload),
            )
        return out

    def upgrade_marker(self) -> dict[str, Any] | None:
        """The marker the last ``core_upgrade`` left in the options table.

        The op writes it BEFORE ``wp_upgrade()`` and stamps it finished
        after, so it survives the one failure mode that cannot report
        anything: a non-catchable PHP fatal inside the migration (a
        ``memory_limit`` on a big migration is the shape that actually
        happens) destroys the response and leaves the database exactly
        where the fatal stopped.  Reading it afterwards tells the operator
        the state the migration BEGAN in — the pre-migration
        ``db_version`` and the target it was heading for — which is the
        difference between "the update failed" and a diagnosis.

        ``None`` when the site has no marker (no ``core_upgrade`` ever
        ran, or the option is not a usable array).  The values are
        normalized through :func:`wire_int` for the two schema versions,
        so a consumer compares numbers and never wire strings.
        """
        payload = self.call("info")
        marker = payload.get("upgrade_marker")
        if not isinstance(marker, dict):
            return None
        out: dict[str, Any] = {"started": marker.get("started"),
                               "finished": marker.get("finished"),
                               "wp_version": marker.get("wp_version")}
        for key in ("from_db_version", "target_db_version"):
            out[key] = wire_int(marker.get(key))
        return out

    # ------------------------------------------------------------- internals

    def _url(self, name: str, token: str, *, selfdestruct: bool = False) -> str:
        # The bridge file sits at the TOP of the webroot, which is the site's
        # document root — so it is served at {site}/{name}, NOT {site}/{webroot}/...
        # (production layout: the FTP login dir is NOT the document root).
        url = f"{self._site}/{name}?t={token}"
        if selfdestruct:
            url += "&selfdestruct=1"
        return url

    def _absolute_budget(self, timeout: float | None,
                         deadline: float | None) -> float | None:
        """The EARLIEST of a relative call budget and an absolute deadline.

        ONE arithmetic owner for :meth:`call`/:meth:`call_stream`: ``None``
        means no total bound (the per-read ``bridge.timeout_s`` still
        applies), a float is an absolute ``time.monotonic()`` instant.
        """
        candidates: list[float] = []
        if deadline is not None:
            candidates.append(float(deadline))
        if timeout is not None:
            candidates.append(time.monotonic()
                              + max(0.001, min(self._timeout, timeout)))
        return min(candidates) if candidates else None

    @staticmethod
    def _absolute_is_run_deadline(absolute: float | None,
                                  deadline: float | None) -> bool:
        """Did the RUN deadline (not a shorter relative timeout) win?

        The verdict difference matters: an expired run deadline is a
        cooperative stop (``DeadlineExceeded``), while a caller's own
        per-call ``timeout`` is an ordinary transport failure
        (``BridgeError``).  ``_absolute_budget`` takes the earliest bound,
        so equality names which one it was.
        """
        return (absolute is not None and deadline is not None
                and absolute == float(deadline))

    def _check_absolute(self, action: str, absolute: float | None, *,
                        run_deadline: bool) -> None:
        """Refuse before/while work when the absolute budget is spent.

        A run deadline is a cooperative stop (``DeadlineExceeded``); a
        caller's relative call budget is an ordinary transport failure
        (``BridgeError``).  Called BEFORE a request is started and between
        body reads, so no expired request ever begins.
        """
        if absolute is None or time.monotonic() < absolute:
            return
        if run_deadline:
            raise DeadlineExceeded(
                f"run deadline exceeded at bridge {action!r} — the request "
                "was abandoned (the run ends itself now)")
        raise BridgeError(
            f"bridge {action} exceeded its absolute call deadline — the "
            "request was abandoned")

    @staticmethod
    def _set_socket_timeout(response: Any, seconds: float) -> None:
        """Re-arm the live socket read bound, when the response exposes it.

        Requests/urllib3 keep the socket under ``raw._fp.fp.raw._sock``;
        a response double (and a fully-consumed response) has no such
        chain, and the per-read timeout from the POST still applies.
        """
        try:
            sock = response.raw._fp.fp.raw._sock
            sock.settimeout(max(0.001, seconds))
        except (AttributeError, OSError, ValueError, TypeError):
            return

    def _read_body_bounded(self, response: Any, action: str,
                           absolute: float | None, *,
                           run_deadline: bool) -> None:
        """Read the whole response body under one absolute deadline.

        ``requests.post(stream=False)`` reads the body inside the call with
        a PER-READ timeout; a one-byte-per-interval drip never trips it.
        Streaming the body lets this loop check the budget after every
        chunk and lower the socket timeout to what is left.  A response
        double without ``iter_content`` already carries its whole ``text``
        and is left untouched.

        TWO independent bounds apply on BOTH transports: the absolute run
        budget (``absolute``; ``None`` = no run budget, the per-call
        transport deadline still applies inside the response) and
        ``bridge.max_response_bytes``, the ONE cap on a non-stream answer.
        A body past the cap is refused, never truncated into a parser.
        """
        iterator = getattr(response, "iter_content", None)
        cap = self._settings.max_response_bytes
        if not callable(iterator):
            # A response double may carry its whole body in ``text`` with no
            # iterable.  Refuse an already-materialized body past the same
            # cap rather than letting the excerpt path read it unbounded.
            existing = getattr(response, "text", None)
            if isinstance(existing, str) \
                    and len(existing.encode("utf-8", "replace")) > cap:
                raise BridgeError(
                    f"bridge {action} response body exceeds the {cap}-byte "
                    "cap (bridge.max_response_bytes) — refusing a runaway "
                    "answer")
            return
        chunks: list[bytes] = []
        total = 0
        raw = getattr(response, "raw", None)
        read1 = getattr(raw, "read1", None)
        stream = None if callable(read1) else iterator(chunk_size=64 * 1024)
        try:
            while True:
                if absolute is not None:
                    self._check_absolute(action, absolute,
                                         run_deadline=run_deadline)
                    self._set_socket_timeout(
                        response, absolute - time.monotonic())
                if callable(read1):
                    # ``read1`` returns whatever is available (never waits
                    # for a fixed chunk size), so the budget is checked at
                    # the drip's own pace instead of after 64 KiB.
                    chunk = read1(65536, decode_content=True)
                    if not chunk:
                        break
                else:
                    try:
                        chunk = next(stream)
                    except StopIteration:
                        break
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8", "replace")
                total += len(chunk)
                if total > cap:
                    raise BridgeError(
                        f"bridge {action} response body exceeds the "
                        f"{cap}-byte cap (bridge.max_response_bytes) — "
                        "refusing a runaway answer")
                chunks.append(chunk)
        except BaseException as exc:
            try:
                response.close()
            except Exception:  # noqa: BLE001 — never mask the budget stop
                pass
            if isinstance(exc, Exception) and not isinstance(
                    exc, (BridgeError, DeadlineExceeded)):
                # ``raw.read1`` bypasses requests' exception translation:
                # a socket timeout arrives as urllib3's ReadTimeoutError.
                # If the absolute budget is spent it IS the budget verdict;
                # any other body failure stays a BridgeError (never a raw
                # transport class escaping the client contract).
                if absolute is not None and time.monotonic() >= absolute:
                    self._check_absolute(action, absolute,
                                         run_deadline=run_deadline)
                raise BridgeError(
                    f"bridge {action} body read failed "
                    f"({type(exc).__name__})") from None
            raise
        try:
            response._content = b"".join(chunks)
            response._content_consumed = True
        except AttributeError:
            pass
        else:
            # The POST was made with ``stream=True`` so the body could be
            # read under the absolute budget; requests no longer releases
            # the connection automatically.  Content is buffered now, so
            # close() only returns it to the pool (R15-P1-2).
            close = getattr(response, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:  # noqa: BLE001 — buffered bytes are safe
                    pass

    def _request(self, action: str, params: dict[str, Any], *,
                 stream: bool = False,
                 replay: bool = True,
                 timeout: float | None = None,
                 deadline: float | None = None) -> requests.Response:
        """POST one action request through the retry state machine.

        Independent retry budgets per failure class:
        - HTTP 404 body ``nf`` (bridge stale/missing or token rejected):
          redeploy once.
        - HTTP 404 with any other body (the site's 404 page — L6: LiteSpeed
          caches 404s per-URL, so the upload landed but its URL answers with
          the cached 404): re-upload under a NEW name, at most
          ``settings.name_retries`` times.
        - ``requests.RequestException``: redeploy once — but only for a
          REPLAYABLE call (``replay=True``, the default) or a provably
          pre-send ``ConnectTimeout``.  A non-idempotent call
          (``replay=False``, e.g. ``user_create``'s apply) whose request may
          already have executed is NOT replayed: the retry would fail on
          the duplicate it just created and the error would hide the
          account, so the failure instead reports that the outcome is
          UNKNOWN (the 404 classes above are safe for it: the token gate
          and a cached 404 both refuse before the op executes).
        """
        absolute = self._absolute_budget(timeout, deadline)
        run_deadline = self._absolute_is_run_deadline(absolute, deadline)
        self._check_absolute(action, absolute, run_deadline=run_deadline)
        if self._endpoint is None or self._token is None or self._name is None:
            self.ensure()
            self._check_absolute(action, absolute, run_deadline=run_deadline)
        assert self._endpoint is not None and self._token is not None
        assert self._name is not None
        nf_retries = 1
        net_retries = 1
        renames_left = self._settings.name_retries
        while True:
            self._check_absolute(action, absolute, run_deadline=run_deadline)
            url = self._url(self._name, self._token)
            request_timeout = self._timeout if timeout is None else max(
                0.001, min(self._timeout, timeout))
            if absolute is not None:
                request_timeout = max(
                    0.001, min(request_timeout, absolute - time.monotonic()))
            try:
                response = post_bounded(
                    self._session, url,
                    json_body={"action": action, "params": params},
                    timeout_s=request_timeout,
                    deadline=absolute,
                )
            except (requests.RequestException, WptError) as e:
                # The raw requests exception embeds the request URL — with the
                # token. Keep its class name and a redacted detail in the
                # message, but never chain it (SPEC: secrets never in
                # exceptions).  A header/body timeout from the absolute
                # transport is the SAME budget verdict: when the deadline is
                # spent, classify it as the run stop instead of a generic
                # transport class.
                if absolute is not None and time.monotonic() >= absolute:
                    self._check_absolute(action, absolute,
                                         run_deadline=run_deadline)
                detail = self._sanitize(str(e))
                retryable = net_retries > 0 and (
                    replay or isinstance(e, requests.ConnectTimeout))
                if retryable:
                    net_retries -= 1
                    log.debug("bridge %s: request failed (%s); redeploying once",
                              action, type(e).__name__)
                    self._check_absolute(action, absolute,
                                         run_deadline=run_deadline)
                    self.ensure()
                    continue
                if not replay and not isinstance(e, requests.ConnectTimeout):
                    # The request may have executed before the response was
                    # lost. Say so; do not replay (the duplicate it created
                    # would be the retry's failure, and the live account
                    # would stay hidden behind an ordinary error).
                    msg = (
                        f"bridge {action} request failed "
                        f"({type(e).__name__}: {detail}) and this operation "
                        "cannot be replayed safely: the site MAY have applied "
                        "it already, so verify the account state before "
                        "retrying (a targeted password reset can issue a "
                        "known password; the pre-action snapshot is the "
                        "rollback for anything else)")
                    log.error("bridge %s failed: %s", action, msg)
                    raise BridgeError(msg) from None
                msg = f"bridge request failed after redeploy: {type(e).__name__}: {detail}"
                log.error("bridge %s failed: %s", action, msg)
                raise BridgeError(msg) from None
            if not stream:
                # The POST above streamed: read the whole body HERE so the
                # response cap applies on BOTH transports, and, when a run
                # budget exists, so the absolute budget bounds it too.
                self._read_body_bounded(response, action, absolute,
                                        run_deadline=run_deadline)
            if response.status_code == 404:
                if stream:
                    # The 404 body is inspected below; cap it even when the
                    # run is explicitly unbounded.
                    self._read_body_bounded(response, action, absolute,
                                            run_deadline=run_deadline)
                body = (response.text or "").strip()
                if body == "nf":
                    if nf_retries > 0:
                        nf_retries -= 1
                        log.debug("bridge %s: deployment stale or missing (nf); redeploying once",
                                  action)
                        self._check_absolute(action, absolute,
                                             run_deadline=run_deadline)
                        self.ensure()
                        continue
                    msg = "bridge kept answering 'nf' after a redeploy (token rejected or file gone)"
                    log.error("bridge %s failed: %s", action, msg)
                    raise BridgeError(msg, payload={"status": 404, "body": "nf"})
                if renames_left > 0:
                    renames_left -= 1
                    log.debug("bridge %s: site 404 page served for the bridge URL "
                              "(L6 cached 404?); re-uploading under a new name", action)
                    self._check_absolute(action, absolute,
                                         run_deadline=run_deadline)
                    self.ensure()
                    continue
                excerpt = self._excerpt(body, action)
                msg = (f"bridge URL kept returning the site 404 page after "
                       f"{self._settings.name_retries} renames (L6)")
                log.error("bridge %s failed: %s", action, msg)
                raise BridgeError(msg, payload={"status": 404, "body": excerpt})
            return response

    def _decode_cells(self, obj: Any, where: str = "bridge stream",
                      _depth: int = 0) -> Any:
        """Recursively decode ``__wpt_b64__`` wire pairs back to bytes.

        THE ONE decoder for the bridge's binary-safe wire form, shared by
        :meth:`call_stream` and the apply answer of
        :meth:`rewrite_refs` (which ``call()`` does not decode).  ``where``
        only labels the failure: a stream line and a one-shot answer are the
        same wire form, so they must not drift into two decoders.
        """
        if _depth >= _JSON_MAX_DEPTH:
            raise BridgeError(
                f"{where}: nested JSON is deeper than {_JSON_MAX_DEPTH} "
                "levels")
        if isinstance(obj, list):
            if len(obj) == 2 and obj[0] == B64_MARKER:
                if not isinstance(obj[1], str):
                    raise BridgeError(f"{where}: __wpt_b64__ cell without a string payload")
                try:
                    return base64.b64decode(obj[1], validate=True)
                except (binascii.Error, ValueError) as e:
                    raise BridgeError(f"{where}: undecodable __wpt_b64__ cell") from e
            return [self._decode_cells(v, where, _depth + 1) for v in obj]
        if isinstance(obj, dict):
            return {k: self._decode_cells(v, where, _depth + 1)
                    for k, v in obj.items()}
        return obj

    def _safe_payload(self, payload: Any, _depth: int = 0) -> Any:
        """A copy of a server payload with every string sanitized.

        ``BridgeError.payload`` is part of an exception a caller may log or
        render; the raw envelope can carry the request token inside its
        ``error`` text.  Sanitizing the STRUCTURE (not just ``str(exc)``)
        keeps the diagnostic shape while guaranteeing the token is absent.

        The walk is bounded like :meth:`_decode_cells`: an untrusted payload
        nested past :data:`_JSON_MAX_DEPTH` raises :class:`BridgeError`
        instead of ``RecursionError`` escaping the client's error contract.
        Dict KEYS are sanitized too — a token echoed into a key is the same
        leak as one echoed into a value.
        """
        if _depth >= _JSON_MAX_DEPTH:
            raise BridgeError(
                f"bridge payload: nested deeper than {_JSON_MAX_DEPTH} "
                "levels")
        if isinstance(payload, str):
            return self._sanitize(payload)
        if isinstance(payload, list):
            return [self._safe_payload(item, _depth + 1) for item in payload]
        if isinstance(payload, dict):
            return {
                (self._sanitize(key) if isinstance(key, str) else key):
                self._safe_payload(item, _depth + 1)
                for key, item in payload.items()
            }
        return payload

    def _sanitize(self, text: str) -> str:
        """Redact the bridge token exactly, then run the shared redactor.

        Applied to everything that can reach a log line or an exception
        message (e.g. requests exception texts, which embed the request URL).
        """
        if self._token:
            text = text.replace(self._token, "***")
        return redact_text(text)

    def _excerpt(self, text: str | None, action: str) -> str:
        """Short redacted body excerpt for error evidence (structural bound).

        Withheld entirely for a credential-bearing op (see
        ``_SECRET_ACTIONS``): the excerpt exists to diagnose a body we could
        not read, so its shape is unproven, and the shared free-text
        redactor cannot blank a JSON `"password":"…"` pair.
        """
        if action in _SECRET_ACTIONS:
            return _SECRET_BODY_WITHHELD
        text = self._sanitize(text or "")
        return text if len(text) <= 200 else text[:200] + "..."
