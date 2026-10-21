"""FTP source construction shared by every ftp-mode command.

The public site URL, the webroot path and the FTP transport are three
different facts; this module owns the one mapping from ``ctx`` to an
``FtpSource``.  ``wpt.audit.remote_stack`` builds the WEBROOT source through
this function, and the account-root readers (``wpt.logs`` / ``wpt.discover``)
build a second source rooted at the FTP login directory through the same
function.  One parser for ``ftp://host[:port]`` means a port override, a bad
port and a missing host are diagnosed identically wherever they arrive.

``source_cls`` is a parameter for the same reason ``wpt.audit.remote_stack``
imports ``FtpSource`` into its own namespace: the audit tests monkeypatch that
module attribute to fake the remote side.  Passing the module's class through
keeps the seam patchable without making the account-root readers depend on the
audit package.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from .deadline import Deadline
from .sources.ftp import FtpSource
from .types import SourceError

if TYPE_CHECKING:  # annotation-only (cli lazy-calls every command)
    from .cli import Ctx

__all__ = ["DOCROOT_NAMES", "ftp_source_for", "normalize_domain"]

#: Host-layout docroot basenames (structural host shapes, never profile
#: tunables).  ONE owner for both diagnostics: ``wpt.discover`` scans these
#: nested trees and ``wpt.logs`` finds their sibling ``logs`` directory.
#: Two hand-maintained copies had already drifted on ``wwwroot``.
DOCROOT_NAMES = ("public_html", "www", "httpdocs", "wwwroot", "web", "htdocs")


def normalize_domain(value: str | None) -> str:
    """The bare hostname used as a path segment: lowercase, no trailing dot,
    no leading ``www.``.

    The ONE normalizer for both host-log derivation (``wpt.logs``) and
    webroot discovery: a host that publishes ``domains/site.test/`` must be
    found whether the operator typed the URL with ``www.`` or not.
    """
    host = (value or "").strip().rstrip(".").lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def _validated_host(host: str) -> str:
    """Return ``host`` when a DNS client can encode it, else SourceError.

    ``socket.getaddrinfo`` IDNA-encodes a non-ASCII host and raises
    ``UnicodeEncodeError`` (a ValueError, not WptError/OSError) for a
    surrogate or a non-IDNA code point; that escaped every command body as
    a traceback.  Control characters can also inject a second FTP command
    line, so both are refused at the ONE construction seam.
    """
    if any(ord(char) < 32 or ord(char) == 127
           or 0xD800 <= ord(char) <= 0xDFFF for char in host):
        raise SourceError(
            "ftp source host is malformed (control characters or unpaired "
            "surrogates are not a hostname)")
    if ":" not in host:
        try:
            host.encode("idna")
        except UnicodeError as exc:
            raise SourceError(
                "ftp source host is not a valid IDNA hostname"
            ) from exc
    return host


def ftp_source_for(ctx: Ctx, root: str | None = None,
                   source_cls: type = FtpSource) -> FtpSource:
    """Build an FTP source for ``ctx`` rooted at ``root``.

    ``root=None`` means the configured ``ctx.webroot``; ``root=""`` means the
    FTP login directory (the account home), which is the root the host-log
    reader and webroot discovery need.  An explicit ``:port`` in
    ``--source`` overrides the profile's ``ftp.port`` while every other FTP
    setting (timeout, retries, parallel reads) is preserved.
    """
    try:
        parsed = urlparse(ctx.source)
        host = parsed.hostname
    except ValueError as exc:
        # Never echo the raw source: a scheme-less user:password@host is
        # parsed as scheme+path, and the text would carry the password even
        # through redaction's scheme-aware rule.
        raise SourceError(
            "ftp source URL is malformed (expected ftp://host[:port])"
        ) from exc
    if not host:
        raise SourceError(
            "ftp source URL carries no host (expected ftp://host[:port])")
    host = _validated_host(host)
    try:
        port = parsed.port
    except ValueError:
        raise SourceError(
            "ftp source URL carries an invalid port "
            f"(host {host!r})"
        ) from None
    ftp_settings = ctx.settings.ftp
    if port is not None:
        ftp_settings = replace(ftp_settings, port=port)
    resolved_root = (ctx.webroot or "") if root is None else root
    source = source_cls(
        host, ctx.user or "", ctx.password or "",
        resolved_root,
        ftp_settings,
    )
    # The ONE transport-budget seam: every FTP command builds its source
    # through here, so none can forget the run deadline.  Attached AFTER
    # construction so a monkeypatched source_cls with the older signature
    # still works (the attribute is inert on fakes).
    source.deadline = Deadline.from_ctx(ctx)
    # Cleanup needs its OWN fresh finite budget (never the spent run one,
    # never None): Source.deadline_suspended installs this value for a
    # rollback/residue pass.  Set as an attribute for the same fake-seam
    # reason as the deadline above.
    source.cleanup_deadline_s = ctx.settings.run.cleanup_deadline_s
    return source
