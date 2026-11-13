"""``wpt php-version`` — switch the hosting account's PHP runtime, verified.

The runtime a shared host serves is a HOSTING fact, not a WordPress one: on
CloudLinux (the DirectAdmin/cPanel shared-hosting platform this site runs on)
the account's PHP Selector stores one selection per user and every request is
served by the selected interpreter.  WordPress cannot change it, and editing
``.htaccess`` handlers is a per-directory guess.  This command drives the
selector directly over the SAME SSH transport ``wpt deploy`` already owns:

1. READ the selector's current selection and the versions it offers, and the
   runtime the WEB SAPI actually reports through the standalone PHP probe
   (``wpt.php_probe`` — the diagnostic that still answers when WordPress is
   broken, which is exactly the state a bad switch can create);
2. PREFLIGHT: parse-check the ACTIVE workload (the active plugins, the active
   theme, mu-plugins) with the TARGET interpreter's own ``php -l`` before any
   switch.  A theme that depends on ``short_open_tag`` (the live failure this
   guard was built from: the contact template used ``<?`` and the site's
   contact page became a 500 on PHP 8.3) fails here, while the old runtime is
   still serving;
3. APPLY: the selector switch, then re-read the probe until it reports the
   target minor, and check the homepage + ``/wp-json/`` over HTTP;
4. ROLLBACK: any failed verification puts the PREVIOUS selection back and
   re-proves it — a switch that broke the site is never left in place.

Read-only by default: without ``--to`` the command reports the current
runtime, the available versions and a recommendation.  ``--apply`` is the
only write and requires ``--yes`` (the shared confirmation gate).  Every rule
in SPEC's secrets section applies: the SSH password is resolved from
``--ssh-password-env`` and reaches ``ssh`` through the deploy module's
``SSH_ASKPASS`` helper, never argv, never a log line.

LIMITS (stated, not hidden): the preflight is a PARSE check, not a runtime
one — a function removed in PHP 8 (``each()``, ``create_function()``) parses
fine and fails at call time.  The post-switch probe, the HTTP checks and the
host error log are the runtime evidence; the log is read by ``wpt logs`` and
``wpt doctor``, not re-read here.
"""

from __future__ import annotations

import json
import re
import shlex
import time
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

import requests

from .actions.registry import confirm, write_report
from .actions.registry import write_failure_report
from .config import redact_text
from .deadline import Deadline, DeadlineExceeded, transport_kwargs
from .deploy import SshTarget
from .log import get_logger
from .php_probe import PhpProbe, get_bounded
from .report import write_stdout
from .settings import PhpVersionSettings, Settings
from .teardown import teardown_stack
from .types import StopRequested, WptError

log = get_logger("php_version")

#: One selectorctl answer line: ``<minor>\t<full>\t<cgi path>``.  Both
#: ``--list`` and ``-c`` speak the same shape (verified live).
_ROW_RE = re.compile(r"^(\d+\.\d+)\t([^\t]+)\t(\S.*)$")

#: An operator's target: one to three numeric components, normalized to the
#: selector's own ``X.Y`` key.
_TARGET_RE = re.compile(r"^(\d+)\.(\d+)(?:\.\d+)?$")

#: The active theme's stylesheet URL in the rendered homepage — the slug is
#: the directory the preflight must parse.  A site can legitimately serve no
#: theme URL (a static front page); then the whole themes tree is linted.
_THEME_RE = re.compile(r"wp-content/themes/([A-Za-z0-9._-]+)/")

#: Marker lines of the remote lint script (structural protocol, not tunables).
_LINT_COUNT = "WPT_LINT_COUNT="
_LINT_FAIL = "WPT_LINT_FAIL "

#: A cache-buster suffix for the post-switch HTTP checks: LiteSpeed would
#: otherwise answer the pre-switch page from its page cache and hide a fatal.
_BUSTER = "wpt_php_verify"


@dataclass(frozen=True)
class Alternative:
    """One interpreter the selector offers."""

    version: str
    full: str
    cgi_path: str

    @property
    def cli_path(self) -> str:
        """The selector's CLI binary beside its CGI path (CloudLinux ships
        both in the same ``bin`` directory).  Proven executable by the
        preflight before it is trusted."""
        return str(PurePosixPath(self.cgi_path).with_name("php"))


@dataclass
class Row:
    stage: str
    status: str
    detail: str


@dataclass
class Result:
    site: str
    rows: list[Row] = field(default_factory=list)
    applied: bool = False
    rolled_back: bool = False
    target: str = ""
    current: str = ""

    def json_obj(self) -> dict[str, Any]:
        return {
            "site": self.site,
            "current": self.current,
            "target": self.target,
            "applied": self.applied,
            "rolled_back": self.rolled_back,
            "rows": [
                {"stage": row.stage, "status": row.status,
                 "detail": row.detail}
                for row in self.rows
            ],
        }


class _Refusal(Exception):
    """A fail-closed refusal: reported through the shared failure writer."""


# --------------------------------------------------------------------- seams


def _build_stack(ctx: "Any") -> tuple:
    """The command's (source, session, bridge) trio (the audit stack seam)."""
    from .audit import remote_stack

    return remote_stack(ctx)


def _make_runner(ctx: "Any", settings: Settings) -> Any:
    """The SSH transport (tests replace this seam)."""
    from dataclasses import replace

    ssh_port = ctx.extra.get("ssh_port")
    deploy = (replace(settings.deploy, ssh_port=ssh_port)
              if isinstance(ssh_port, int) else settings.deploy)
    target = SshTarget(str(ctx.extra.get("ssh_target") or ""),
                       str(ctx.webroot or "."), deploy,
                       ctx.extra.get("ssh_password_env"))
    return target


def _probe(source, session, settings: Settings, wp_url: str) -> PhpProbe:
    """The standalone PHP runtime probe (tests replace this seam)."""
    return PhpProbe(source, session, settings.probe, wp_url)


def _http_get(session, url: str, timeout: float,
              deadline: float | None = None) -> tuple[int, bytes]:
    """One GET under an ABSOLUTE budget; ``(status, body)``, 0 on failure.

    Rides :func:`wpt.php_probe.get_bounded`, the ONE bounded-HTTP owner: a
    per-read ``timeout`` alone lets a server dripping one header byte at a
    time keep the call blocked for seconds, which is exactly the failure
    that owner exists for.  The body is capped the same way the previous
    slice did it, and the response is always closed.
    """
    try:
        response = get_bounded(
            session, url, timeout_s=timeout,
            deadline=(time.monotonic() + max(0.001, float(timeout))
                      if deadline is None else deadline),
            allow_redirects=True,
        )
    except (requests.RequestException, WptError) as exc:
        log.warning("php-version: HTTP read failed for %s: %s", url,
                    redact_text(str(exc)))
        return 0, b""
    try:
        status = response.status_code
        read = getattr(response, "read_bounded", None)
        if callable(read):
            body = read(262144)
        else:
            body = bytes(response.content[:262144])
        return status, body
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()


# --------------------------------------------------------------------- engine


class _Engine:
    def __init__(self, ctx: "Any", stack: tuple, deadline: Deadline | None,
                 settings: Settings) -> None:
        self.ctx = ctx
        self.source, self.session, self.bridge = stack
        self.deadline = deadline
        self.settings = settings
        self.pv: PhpVersionSettings = settings.php_version
        self.result = Result(site=str(ctx.wp_url or ""))
        self.runner = None
        self.alternatives: list[Alternative] = []
        self.selected: Alternative | None = None
        self.web_version = ""
        self.web_probe_error = ""

    # -- facts -----------------------------------------------------------

    def _check(self, context: str) -> None:
        if self.deadline is not None:
            self.deadline.check(context)

    def _ssh(self, command: str, *, timeout: int | None = None,
             what: str = "selector command") -> tuple[int, str, str]:
        assert self.runner is not None
        self._check(what)
        return self.runner.run_command(
            command, timeout=float(timeout or self.pv.command_timeout_s),
            deadline=self.deadline)

    def _read_selector(self) -> None:
        """Current selection + offered versions, from the selector itself."""
        rc, out, err = self._ssh(shlex.quote(self.pv.selectorctl) + " --list")
        if rc != 0:
            raise _Refusal(
                "the PHP selector could not list its versions: "
                f"{redact_text((err or out).strip())[:300] or 'no output'}")
        self.alternatives = parse_list(out)
        if not self.alternatives:
            raise _Refusal(
                "the PHP selector listed no versions; refusing to switch a "
                "runtime that cannot be named")
        rc, out, err = self._ssh(shlex.quote(self.pv.selectorctl) + " -c")
        if rc != 0:
            raise _Refusal(
                "the PHP selector could not report its current selection: "
                f"{redact_text((err or out).strip())[:300] or 'no output'}")
        self.selected = parse_current(out)
        if self.selected is None:
            raise _Refusal(
                "the PHP selector's current-selection answer was not "
                f"understood: {redact_text(out.strip())[:200]!r}")

    def _read_probe(self) -> None:
        """The runtime the WEB SAPI actually serves (authoritative)."""
        probe = _probe(self.source, self.session, self.settings,
                       str(self.ctx.wp_url or ""))
        try:
            payload = probe.call(deadline=(self.deadline.at
                                           if self.deadline is not None
                                           else None))
        finally:
            try:
                probe.destroy()
            except Exception as exc:  # noqa: BLE001 — never mask the answer
                log.warning("php-version: probe destroy failed: %s",
                            redact_text(str(exc)))
        if not isinstance(payload, dict) or not payload.get("php_version"):
            raise _Refusal(
                "the PHP runtime probe answered without a php_version; the "
                "live runtime is unmeasurable, so a switch could not be "
                "verified")
        self.web_version = str(payload["php_version"])

    # -- lint ------------------------------------------------------------

    def _active_plugin_roots(self) -> list[str]:
        """``wp-content/plugins/<unit>`` for every ACTIVE plugin, measured.

        The bridge's ``info`` catalog is the active-set owner (the same fact
        clean-files' deletion guard reads); an unmeasurable set refuses the
        preflight rather than linting nothing and calling it safe.
        """
        try:
            info = self.bridge.call("info", **transport_kwargs(self.deadline))
        except (WptError, OSError) as exc:
            raise _Refusal(
                "cannot measure the active plugin set (bridge info failed: "
                f"{redact_text(str(exc))}); refusing to lint an unknown "
                "workload") from exc
        plugins = info.get("plugins") if isinstance(info, dict) else None
        if not isinstance(plugins, dict):
            raise _Refusal(
                "cannot measure the active plugin set (the bridge answered "
                "without a plugin catalog); refusing to lint an unknown "
                "workload")
        roots: set[str] = set()
        for key, data in plugins.items():
            if not isinstance(key, str) or not isinstance(data, dict):
                continue
            if data.get("active") is not True:
                continue
            unit = key.split("/", 1)[0] if "/" in key else key
            if unit:
                roots.add(f"wp-content/plugins/{unit}")
        return sorted(roots)

    def _theme_root(self) -> str:
        status, body = _http_get(
            self.session, str(self.ctx.wp_url or ""),
            float(self.pv.http_timeout_s),
            self.deadline.at if self.deadline is not None else None)
        text = body.decode("utf-8", errors="replace")
        match = _THEME_RE.search(text)
        if match:
            return f"wp-content/themes/{match.group(1)}"
        # A static front page names no theme; lint every installed theme
        # rather than skip the one that renders the site.
        return "wp-content/themes"

    def _cd_webroot(self) -> str:
        """The ``cd`` command for the remote webroot.

        A relative ``--webroot`` is FTP-login-relative, and the ssh login
        home is that same directory; ``$HOME`` is spelled as an env var so
        the relative path stays a single-quoted literal (``~`` inside
        ``shlex.quote`` would never expand).  ``--ssh-webroot`` is the
        absolute override for a chrooted FTP whose home differs.
        """
        explicit = self.ctx.extra.get("ssh_webroot")
        if explicit:
            return "cd " + shlex.quote(str(explicit))
        webroot = str(self.ctx.webroot or "").strip("/")
        if not webroot:
            return 'cd "$HOME"'
        return 'cd "$HOME"/' + shlex.quote(webroot)

    def _lint(self, alternative: Alternative) -> tuple[int, list[str]]:
        """Parse-check the active workload with the TARGET interpreter."""
        roots = self._active_plugin_roots() + [self._theme_root(),
                                               "wp-content/mu-plugins"]
        quotes = " ".join(shlex.quote(root) for root in roots)
        php = shlex.quote(alternative.cli_path)
        marker = "wpt-lint-$$"
        script = (
            f"{self._cd_webroot()} || exit 9; "
            f"LIST=/tmp/{marker}.list; "
            f"find {quotes} -type f -name '*.php' -print 2>/dev/null "
            f"| head -n {int(self.pv.lint_max_files)} > \"$LIST\"; "
            f"echo \"{_LINT_COUNT}$(wc -l < \"$LIST\" | tr -d ' ')\"; "
            f"while IFS= read -r f; do {php} -l \"$f\" >/dev/null 2>&1 "
            f"|| echo \"{_LINT_FAIL}$f\"; done < \"$LIST\"; "
            f"rm -f \"$LIST\"")
        rc, out, err = self._ssh(script, timeout=self.pv.lint_timeout_s,
                                 what="PHP compatibility preflight")
        if rc != 0:
            raise _Refusal(
                "the PHP compatibility preflight could not run (is the SSH "
                f"webroot right?): {redact_text((err or out).strip())[:300]}")
        count = 0
        failures: list[str] = []
        for line in out.splitlines():
            if line.startswith(_LINT_COUNT):
                try:
                    count = int(line[len(_LINT_COUNT):].strip())
                except ValueError:
                    count = 0
            elif line.startswith(_LINT_FAIL):
                failures.append(line[len(_LINT_FAIL):].strip())
        if count <= 0:
            raise _Refusal(
                "the PHP compatibility preflight parsed no files; refusing to "
                "switch a workload it could not measure")
        return count, failures

    # -- flow ------------------------------------------------------------

    def execute(self) -> Result:
        target_text = self.ctx.extra.get("to")
        ssh_target = self.ctx.extra.get("ssh_target")
        if target_text and not ssh_target:
            raise _Refusal(
                "changing the PHP version needs --ssh-target USER@HOST "
                "(the hosting account's shell); the live runtime can still "
                "be reported without it")
        self._read_probe()
        self.result.current = self.web_version
        self.result.rows.append(Row(
            "web runtime", "current",
            f"PHP {self.web_version} (the runtime the web server serves)"))
        if ssh_target:
            self.runner = _make_runner(self.ctx, self.settings)
        else:
            self.result.rows.append(Row(
                "php selector", "not queried",
                "no --ssh-target; the account's selector was not read"))
            return self.result
        self._read_selector()
        assert self.selected is not None
        self.result.rows.append(Row(
            "php selector", "current",
            f"PHP {self.selected.full} selected "
            f"({self.selected.version}); {len(self.alternatives)} "
            "version(s) offered"))
        self.result.rows.append(Row(
            "available", "info",
            ", ".join(item.version for item in self.alternatives)))
        if not target_text:
            recommended = self._recommend()
            self.result.rows.append(Row(
                "recommendation", "advice",
                f"switch with --to {recommended} --apply (the profile's "
                f"php_version.recommended, offered; the active-support floor "
                f"is {self.settings.env.php_min_active})"
                if recommended else
                "no offered minor is at or above the active-support floor "
                f"{self.settings.env.php_min_active}"))
            return self.result
        target = normalize_target(str(target_text))
        wanted = next((item for item in self.alternatives
                       if item.version == target), None)
        if wanted is None:
            raise _Refusal(
                f"PHP {target} is not offered by this account's selector "
                f"(offered: {', '.join(i.version for i in self.alternatives)})")
        self.result.target = target
        if _minor(target) < _minor(self.settings.env.php_min_active):
            self.result.rows.append(Row(
                "target", "warning",
                f"PHP {target} is BELOW the active-support floor "
                f"{self.settings.env.php_min_active}: security fixes have "
                "stopped for it"))
        self.result.rows.append(Row(
            "target", "planned",
            f"PHP {self.selected.version} -> {target} "
            f"({wanted.full}); rollback target "
            f"{self.selected.version}"))
        self._check("php-version preflight")
        count, failures = self._lint(wanted)
        if failures:
            for path in failures[: self.pv.lint_max_failures]:
                self.result.rows.append(Row(
                    "preflight", "blocker",
                    f"{path} does not parse under PHP {wanted.full}"))
            hidden = len(failures) - self.pv.lint_max_failures
            if hidden > 0:
                self.result.rows.append(Row(
                    "preflight", "blocker",
                    f"{hidden} more file(s) do not parse (report limit "
                    f"php_version.lint_max_failures)"))
            raise _Refusal(
                f"{len(failures)} active file(s) do not parse under PHP "
                f"{wanted.full}; fix them before switching "
                "(listed in the report)")
        self.result.rows.append(Row(
            "preflight", "pass",
            f"{count} active PHP file(s) parse under PHP {wanted.full}"))
        if not self.ctx.apply:
            return self.result
        if not confirm(self.ctx):
            raise _Refusal("php-version: aborted by the operator")
        return self._apply(wanted)

    def _apply(self, wanted: Alternative) -> Result:
        assert self.selected is not None
        previous = self.selected.version
        if (previous == wanted.version
                and _minor(self.web_version) == _minor(wanted.version)):
            self.result.rows.append(Row(
                "switch", "already",
                f"PHP {wanted.version} is already selected and served; "
                "nothing to change"))
            return self.result
        self._check("php-version apply")
        rc, out, err = self._ssh(
            shlex.quote(self.pv.selectorctl) + " -b " + shlex.quote(
                wanted.version))
        if rc != 0:
            raise _Refusal(
                f"the selector refused PHP {wanted.version}: "
                f"{redact_text((err or out).strip())[:300] or 'no output'}")
        self.result.applied = True
        try:
            self._verify_switch(wanted)
        except _Refusal as exc:
            self.result.rows.append(Row(
                "verify", "FAIL", str(exc)))
            self._rollback(previous, reason=str(exc))
            raise
        self.result.rows.append(Row(
            "verify", "pass",
            f"the web server serves PHP {wanted.version}; the homepage and "
            "/wp-json/ answered"))
        return self.result

    def _verify_switch(self, wanted: Alternative) -> None:
        last = ""
        for attempt in range(self.pv.verify_retries):
            if attempt and self.pv.verify_delay_s:
                time.sleep(float(self.pv.verify_delay_s))
            self._check("php-version verify")
            probe = _probe(self.source, self.session, self.settings,
                           str(self.ctx.wp_url or ""))
            try:
                payload = probe.call(deadline=(self.deadline.at
                                               if self.deadline is not None
                                               else None))
            except (WptError, OSError) as exc:
                last = redact_text(str(exc))
                continue
            finally:
                try:
                    probe.destroy()
                except Exception:  # noqa: BLE001 — best-effort teardown
                    pass
            version = str((payload or {}).get("php_version") or "")
            if _minor(version) == _minor(wanted.version):
                self._http_verify()
                return
            last = f"probe still reports PHP {version or 'nothing'}"
        raise _Refusal(
            f"the switch to PHP {wanted.version} was not served"
            + (f" ({last})" if last else ""))

    def _http_verify(self) -> None:
        base = str(self.ctx.wp_url or "").rstrip("/")
        stamp = str(int(time.time()))
        status, _ = _http_get(
            self.session, f"{base}/?{_BUSTER}={stamp}",
            float(self.pv.http_timeout_s),
            self.deadline.at if self.deadline is not None else None)
        if status >= 500 or status == 0:
            raise _Refusal(
                f"the homepage answered HTTP {status or 'nothing'} after the "
                "switch")
        rest, _ = _http_get(
            self.session, f"{base}/wp-json/?{_BUSTER}={stamp}",
            float(self.pv.http_timeout_s),
            self.deadline.at if self.deadline is not None else None)
        if rest >= 500:
            raise _Refusal(
                f"/wp-json/ answered HTTP {rest} after the switch")

    def _rollback(self, previous: str, *, reason: str) -> None:
        """Put the previous selection back and prove it where possible."""
        try:
            rc, out, err = self._ssh(
                shlex.quote(self.pv.selectorctl) + " -b "
                + shlex.quote(previous),
                timeout=self.pv.command_timeout_s)
        except (WptError, OSError) as exc:
            self.result.rows.append(Row(
                "rollback", "FAIL",
                f"could not restore PHP {previous}: "
                f"{redact_text(str(exc))}; set it by hand in the hosting "
                "panel"))
            return
        if rc != 0:
            self.result.rows.append(Row(
                "rollback", "FAIL",
                f"the selector refused to restore PHP {previous}: "
                f"{redact_text((err or out).strip())[:300] or 'no output'}; "
                "set it by hand in the hosting panel"))
            return
        self.result.rolled_back = True
        try:
            probe = _probe(self.source, self.session, self.settings,
                           str(self.ctx.wp_url or ""))
            try:
                payload = probe.call(deadline=(self.deadline.at
                                               if self.deadline is not None
                                               else None))
            finally:
                try:
                    probe.destroy()
                except Exception:  # noqa: BLE001
                    pass
            served = str((payload or {}).get("php_version") or "")
            self.result.rows.append(Row(
                "rollback", "restored" if _minor(served) == _minor(previous)
                else "warning",
                f"PHP {previous} re-selected after {redact_text(reason)[:200]}; "
                f"the web server reports PHP {served or 'nothing'}"
                + ("" if _minor(served) == _minor(previous)
                   else " — check the site in the hosting panel")))
        except (WptError, OSError) as exc:
            self.result.rows.append(Row(
                "rollback", "warning",
                f"PHP {previous} re-selected after {redact_text(reason)[:200]},"
                f" but the probe could not re-confirm it: "
                f"{redact_text(str(exc))}"))

    def _recommend(self) -> str:
        """The advised minor: the profile's ``recommended`` when offered.

        Falling back to the selector's NEWEST minor would push a site onto a
        PHP release WordPress and its plugins have not been exercised on;
        the profile names the version the project stands behind (8.3, the
        current WordPress recommendation) and ``--to`` stays the explicit
        operator override.
        """
        offered = {item.version for item in self.alternatives}
        preferred = self.pv.recommended
        if preferred in offered:
            return preferred
        floor = _minor(self.settings.env.php_min_active)
        candidates = [item.version for item in self.alternatives
                      if _minor(item.version) >= floor]
        return candidates[-1] if candidates else ""


# ------------------------------------------------------------------- parsing


def parse_list(text: str) -> list[Alternative]:
    """Every ``X.Y`` row of a ``selectorctl --list`` answer, file order."""
    out: list[Alternative] = []
    for line in text.splitlines():
        match = _ROW_RE.match(line.strip())
        if match:
            out.append(Alternative(match.group(1), match.group(2),
                                   match.group(3).strip()))
    return out


def parse_current(text: str) -> Alternative | None:
    """The first selector row of a ``selectorctl -c`` answer."""
    for line in text.splitlines():
        match = _ROW_RE.match(line.strip())
        if match:
            return Alternative(match.group(1), match.group(2),
                               match.group(3).strip())
    return None


def normalize_target(value: str) -> str:
    """``8.3``/``8.3.36`` -> ``8.3``; anything else is a refusal."""
    match = _TARGET_RE.match(value.strip())
    if not match:
        raise _Refusal(
            f"--to {value!r} is not a PHP version (expected X.Y, e.g. 8.3)")
    return f"{int(match.group(1))}.{int(match.group(2))}"


def _minor(value: str) -> tuple[int, int]:
    match = re.match(r"^(\d+)\.(\d+)", value or "")
    if not match:
        return (0, 0)
    return (int(match.group(1)), int(match.group(2)))


# ---------------------------------------------------------------- rendering


def _render(result: Result) -> str:
    lines = [
        f"# wpt php-version — {result.site or '-'}",
        "",
        f"Current runtime: PHP {result.current or 'unknown'}",
        f"Target: {('PHP ' + result.target) if result.target else '—'}"
        f" · applied: {'yes' if result.applied else 'no'}"
        + (" · rolled back" if result.rolled_back else ""),
        "",
        "| stage | result | detail |",
        "|---|---|---|",
    ]
    for row in result.rows:
        detail = row.detail.replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {row.stage} | {row.status} | {detail} |")
    lines.append("")
    return "\n".join(lines)


def _json_text(result: Result) -> str:
    return json.dumps(result.json_obj(), indent=2, ensure_ascii=False,
                      sort_keys=True) + "\n"


def _write_failed_result(ctx: "Any", result: Result, reason: str) -> None:
    """Write the measured rows + the shared not-complete block.

    A refusal after measurement must not erase what was measured: the
    blocker list and the rollback outcome are the operator's diagnosis.
    ``not_complete`` stays the ONE owner of the failure wording.

    The markdown goes to STDOUT as well as the report file.  Without that,
    the L79 flow — a lint blocker on a switch that never happened — printed
    NOTHING when the operator passed no ``--report``, which is the one case
    where the blocker list IS the whole value of the run.
    """
    from .actions.registry import not_complete

    block, payload = not_complete(reason, status="failed")
    markdown = _render(result) + block
    data = result.json_obj()
    data["run"] = payload
    write_stdout(markdown)
    write_report(ctx, "php-version", markdown,
                 json.dumps(data, indent=2, ensure_ascii=False,
                            sort_keys=True) + "\n")


# ----------------------------------------------------------------------- run


def run(ctx: "Any") -> int:
    """Run ``wpt php-version``; never raises for an operational failure."""
    if ctx.mode != "ftp":
        reason = ("php-version is ftp-only: it reads the live runtime, the "
                  "hosting selector over SSH and the active workload")
        log.error("%s", reason)
        write_failure_report(ctx, "php-version", reason, status="refused")
        return 1
    stack = None
    engine: _Engine | None = None
    primary: BaseException | None = None
    teardown_stop: BaseException | None = None
    rc = 1
    try:
        deadline = Deadline.from_ctx(ctx)
        stack = _build_stack(ctx)
        engine = _Engine(ctx, stack, deadline, ctx.settings)
        result = engine.execute()
        markdown = _render(result)
        write_stdout(markdown, end="")
        rc = write_report(ctx, "php-version", markdown, _json_text(result))
    except _Refusal as exc:
        primary = exc
        reason = redact_text(str(exc))
        log.error("php-version: %s", reason)
        # A refusal that was PROVEN by the run (a lint blocker, a failed
        # verification and its rollback) has rows worth keeping: write them
        # with the shared "did not complete" block.  A refusal before any
        # row (bad input, unreadable selector) keeps the shared empty report.
        if engine is not None and engine.result.rows:
            _write_failed_result(ctx, engine.result, reason)
        else:
            write_failure_report(ctx, "php-version", reason, status="refused")
        rc = 1
    except (StopRequested, DeadlineExceeded) as exc:
        primary = exc
        reason = redact_text(f"php-version stopped: {exc}")
        log.error("%s", reason)
        write_failure_report(ctx, "php-version", reason)
        rc = 1
    except (WptError, OSError) as exc:
        primary = exc
        reason = redact_text(str(exc))
        log.error("php-version: %s", reason)
        write_failure_report(ctx, "php-version", reason)
        rc = 1
    finally:
        if stack is not None:
            teardown_stop = teardown_stack(stack, "php-version")
    if teardown_stop is not None:
        reason = redact_text(str(teardown_stop))
        log.error("php-version: %s", reason)
        if primary is None:
            write_failure_report(ctx, "php-version", reason)
        else:
            log.error("php-version: the primary failure above stays the "
                      "run's reason (rc %d)", rc)
        return 1
    return rc
