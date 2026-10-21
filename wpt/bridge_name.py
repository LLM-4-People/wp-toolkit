"""The ONE owner of the deployed wpt endpoint file names.

The bridge and the standalone PHP probe are token-authenticated PHP
endpoints wpt uploads for the length of a run. Neither is ever site
content: a snapshot must not archive one (the archive outlives the token,
and `restore` would write it back as a working endpoint), a restore must
refuse one, and the audit's residue sweep skips a live BRIDGE through the
bridge-only owner (`is_bridge_file`/`BRIDGE_NAME_RE`).  Everyone matches
on these patterns — nobody re-derives them.
"""
import posixpath
import re

BRIDGE_NAME_RE = re.compile(r"^bridge-[0-9a-f]{8}\.php$")
#: The probe's deployed name (``php_probe.ensure``): lowercase hex only.
PROBE_NAME_RE = re.compile(r"^wpt-probe-[0-9a-f]{8}\.php$")
#: The ONE template every probe-shaped name derives from: the deployed
#: runtime probe, and the audit's certainly-missing soft-404 path.
PROBE_NAME_TEMPLATE = "wpt-probe-{suffix}.php"


def probe_name(suffix: str) -> str:
    """The one probe filename for an 8-hex suffix (never re-derived)."""
    return PROBE_NAME_TEMPLATE.format(suffix=suffix)
#: Both endpoint shapes, matched as a BASENAME.
WPT_ENDPOINT_NAME_RE = re.compile(
    r"^(?:bridge-[0-9a-f]{8}|wpt-probe-[0-9a-f]{8})\.php$")


def _basename(path: str) -> str:
    """The normalized basename.

    ``Source._guard_path`` normalizes ``\\`` to ``/`` and collapses ``.``/
    ``..``/trailing separators before a write.  A predicate that compared
    the RAW tail therefore missed ``wpt-probe-deadbeef.php/``, ``//``,
    ``/.`` and ``/./``, and a crafted/legacy manifest could re-arm the
    real token endpoint under a normalized name (PROBE1).
    """
    return posixpath.basename(
        posixpath.normpath(path.replace("\\", "/")))


def _folded_basename(path: str) -> str:
    """``_basename`` case-folded: the endpoint guard's case-insensitive form.

    A case-insensitive host writes ``BRIDGE-<hex>.PHP`` to the same file as
    the lowercase endpoint, so the content guard must not miss it.  The
    residue SWEEP deliberately stays strict lowercase (an uppercase decoy
    is not proven to be wpt's own and is never deleted).
    """
    return _basename(path).casefold()


def is_bridge_file(path: str) -> bool:
    """True when ``path``'s BASENAME is a deployed bridge file."""
    return bool(BRIDGE_NAME_RE.match(_basename(path)))


def is_wpt_endpoint_file(path: str) -> bool:
    """True when ``path``'s BASENAME is any deployed wpt token endpoint."""
    return bool(WPT_ENDPOINT_NAME_RE.match(_folded_basename(path)))


#: The embedded expiry literal (``$wpt_expires = '<unix-ts>';``) — the SAME
#: shape for the bridge and the probe, and the only signal either stale
#: sweep deletes on.
ENDPOINT_EXPIRES_RE = re.compile(r"\$wpt_expires\s*=\s*'(\d+)';")


def endpoint_expiry(text: str) -> int | None:
    """The embedded expiry timestamp, or None when the literal is absent.

    ``int()`` may raise ``ValueError`` for a digit run above Python's
    conversion limit; both sweeps treat that as unverifiable and keep the
    file, so the exception is left to them.
    """
    match = ENDPOINT_EXPIRES_RE.search(text)
    return int(match.group(1)) if match is not None else None


#: The two substitution points every endpoint template must carry.  One
#: renderer for the bridge and the standalone probe: a template edit that
#: drops a placeholder (or a partial substitution) must refuse in BOTH
#: before any token-gated file reaches the webroot.
ENDPOINT_PLACEHOLDERS = ("__WPT_TOKEN__", "__WPT_EXPIRES__")


def render_endpoint_template(template_text: str, *, token: str,
                             expiry: int) -> str:
    """Render one endpoint template, refusing a missing/leftover placeholder.

    Pure and transport-free.  Raises ``ValueError`` naming the placeholder;
    callers translate it into their own command's refusal.
    """
    missing = [p for p in ENDPOINT_PLACEHOLDERS if p not in template_text]
    if missing:
        raise ValueError(
            "missing substitution placeholder(s): " + ", ".join(missing))
    rendered = template_text.replace("__WPT_TOKEN__", token).replace(
        "__WPT_EXPIRES__", str(expiry))
    leftover = [p for p in ENDPOINT_PLACEHOLDERS if p in rendered]
    if leftover:
        raise ValueError(
            "substitution placeholder(s) survived rendering: "
            + ", ".join(leftover))
    return rendered
