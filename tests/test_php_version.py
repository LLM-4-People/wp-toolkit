"""Tests for ``wpt php-version`` (the host PHP runtime switch).

The SSH selector, the PHP probe, the HTTP session and the bridge are all
module seams; nothing here opens a socket.  The table-driven cases pin the
selector answer grammar; the flow cases pin the fail-closed rules the live
site needed (a short-tag theme blocked the switch BEFORE the old runtime was
left behind, and a failed verification puts the previous selection back).
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import wpt.php_version as pv
from wpt.cli import Ctx
from wpt.settings import Settings


# ------------------------------------------------------------------- fakes


class FakeRunner:
    """The SSH transport: canned answers keyed by the command shape."""

    def __init__(self, *, list_text="", current_text="", lint_text="",
                 set_rc=0, lint_rc=0):
        self.list_text = list_text
        self.current_text = current_text
        self.lint_text = lint_text
        self.set_rc = set_rc
        self.lint_rc = lint_rc
        self.commands: list[str] = []
        self.selected: list[str] = []

    def run_command(self, command, *, timeout, deadline=None):
        self.commands.append(command)
        if command.endswith("--list"):
            return 0, self.list_text, ""
        if command.endswith(" -c"):
            return 0, self.current_text, ""
        if " -b " in command:
            if self.set_rc == 0:
                self.selected.append(command.rsplit(" ", 1)[-1])
            return self.set_rc, "", "refused" if self.set_rc else ""
        if "WPT_LINT_COUNT" in command:
            return self.lint_rc, self.lint_text, "lint broke" if self.lint_rc else ""
        return 0, "", ""


class FakeProbe:
    def __init__(self, versions):
        self.versions = list(versions)
        self.destroyed = 0

    def call(self, *, deadline=None):
        return {"php_version": self.versions.pop(0)}

    def destroy(self):
        self.destroyed += 1


class FakeSession:
    def __init__(self, status=200, body=b"<link href='/wp-content/themes/yveslessard/style.css'>"):
        self.status = status
        self.body = body
        self.urls: list[str] = []

    def get(self, url, **kwargs):
        self.urls.append(url)
        return SimpleNamespace(status_code=self.status, content=self.body)


class FakeBridge:
    def __init__(self, plugins=None):
        self.plugins = plugins if plugins is not None else {
            "akismet/akismet.php": {"active": True},
            "jetpack/jetpack.php": {"active": True},
            "hello.php": {"active": False},
        }

    def call(self, action, **kwargs):
        assert action == "info"
        return {"plugins": self.plugins}


class FakeSource:
    def close(self):
        pass


def make_ctx(tmp_path, *, apply=False, target=None, ssh=True, report=True):
    extra = {}
    if target is not None:
        extra["to"] = target
    if ssh:
        extra["ssh_target"] = "user@host"
        extra["ssh_port"] = 9999
    return Ctx(
        source="ftp://example.test:21",
        settings=Settings(),
        command="php-version",
        apply=apply,
        yes=True,
        webroot="domains/example.test/public_html",
        wp_url="https://example.test",
        report_path=(tmp_path / "php-version.md") if report else None,
        extra=extra,
    )


@pytest.fixture
def wire(monkeypatch, tmp_path):
    """Install every seam; returns a helper to configure one run."""
    state = SimpleNamespace(runner=None, probes=[], session=None, bridge=None)

    def install(*, runner, probes, session=None, bridge=None):
        state.runner = runner
        state.probes = list(probes)
        state.session = session or FakeSession()
        state.bridge = bridge or FakeBridge()
        monkeypatch.setattr(pv, "_build_stack",
                            lambda ctx: (FakeSource(), state.session, state.bridge))
        monkeypatch.setattr(pv, "_make_runner",
                            lambda ctx, settings: state.runner)

        def probe_factory(source, session, settings, wp_url):
            if not state.probes:
                return FakeProbe(["8.3.36"])
            return FakeProbe([state.probes.pop(0)])

        monkeypatch.setattr(pv, "_probe", probe_factory)

    return state, install


LIST = ("5.2\t5.2.17\t/opt/alt/php52/usr/bin/php-cgi\n"
        "7.2\t7.2.34\t/opt/alt/php72/usr/bin/php-cgi\n"
        "8.3\t8.3.36\t/opt/alt/php83/usr/bin/php-cgi\n")
CURRENT_72 = "7.2\t7.2.34\t/opt/alt/php72/usr/bin/php-cgi\n"
CURRENT_83 = "8.3\t8.3.36\t/opt/alt/php83/usr/bin/php-cgi\n"


def lint_ok(count=42):
    return f"WPT_LINT_COUNT={count}\n"


# ------------------------------------------------------------------ parsing


@pytest.mark.parametrize(
    "text,expected",
    [
        (LIST, [("5.2", "5.2.17"), ("7.2", "7.2.34"), ("8.3", "8.3.36")]),
        ("", []),
        ("not a row\n8.3\t8.3.36\t/opt/alt/php83/usr/bin/php-cgi\n", [("8.3", "8.3.36")]),
        ("8.3\t8.3.36\t\n", []),
    ],
)
def test_parse_list(text, expected):
    assert [(a.version, a.full) for a in pv.parse_list(text)] == expected


def test_parse_current_takes_the_first_row():
    assert pv.parse_current("garbage\n" + CURRENT_72).version == "7.2"
    assert pv.parse_current("") is None


@pytest.mark.parametrize(
    "raw,expected",
    [("8.3", "8.3"), (" 8.3.36 ", "8.3"), ("8.03.1", "8.3"),
     ("7.4", "7.4")],
)
def test_normalize_target(raw, expected):
    assert pv.normalize_target(raw) == expected


@pytest.mark.parametrize("raw", ["", "8", "php8.3", "8.3-rc1", "8.a"])
def test_normalize_target_refuses_non_versions(raw):
    with pytest.raises(pv._Refusal):
        pv.normalize_target(raw)


def test_cli_path_is_beside_the_cgi_binary():
    alt = pv.Alternative("8.3", "8.3.36", "/opt/alt/php83/usr/bin/php-cgi")
    assert alt.cli_path == "/opt/alt/php83/usr/bin/php"


# -------------------------------------------------------------------- flow


def test_read_only_without_ssh_reports_the_live_runtime(wire, tmp_path, capsys):
    state, install = wire
    install(runner=FakeRunner(), probes=["8.3.36"])
    rc = pv.run(make_ctx(tmp_path, ssh=False))
    assert rc == 0
    out = capsys.readouterr().out
    assert "PHP 8.3.36" in out
    assert "selector" not in state.runner.commands
    report = tmp_path / "php-version.md"
    assert report.exists()
    assert json.loads((tmp_path / "php-version.json").read_text())["current"] == "8.3.36"


def test_read_only_names_a_recommendation(wire, tmp_path, capsys):
    state, install = wire
    install(runner=FakeRunner(list_text=LIST, current_text=CURRENT_72),
            probes=["7.2.34"])
    rc = pv.run(make_ctx(tmp_path))
    assert rc == 0
    out = capsys.readouterr().out
    assert "recommendation" in out
    assert "--to 8.3" in out


def test_recommendation_prefers_the_profile_value_not_the_newest(wire, tmp_path,
                                                                capsys):
    """The selector may offer 8.5; the advice must not push a live site onto
    a PHP release WordPress and its plugins were not exercised on.  The
    profile names 8.3; only an ABSENT 8.3 falls back to the highest offered
    minor at or above the floor."""
    _state, install = wire
    install(runner=FakeRunner(list_text=LIST.replace(
                   "8.3\t8.3.36\t/opt/alt/php83/usr/bin/php-cgi\n",
                   "8.3\t8.3.36\t/opt/alt/php83/usr/bin/php-cgi\n"
                   "8.5\t8.5.1\t/opt/alt/php85/usr/bin/php-cgi\n"),
               current_text=CURRENT_72), probes=["8.3.36"])
    assert pv.run(make_ctx(tmp_path)) == 0
    assert "--to 8.3" in capsys.readouterr().out

    _state, install = wire
    only_82 = LIST.replace("8.3\t8.3.36\t/opt/alt/php83/usr/bin/php-cgi\n", "")
    install(runner=FakeRunner(list_text=only_82 + "8.2\t8.2.35\t/opt/alt/php82/usr/bin/php-cgi\n",
                              current_text=CURRENT_72), probes=["8.3.36"])
    assert pv.run(make_ctx(tmp_path)) == 0
    assert "--to 8.2" in capsys.readouterr().out


def test_unknown_target_refuses_and_writes_the_failure_report(wire, tmp_path):
    state, install = wire
    install(runner=FakeRunner(list_text=LIST, current_text=CURRENT_72),
            probes=["7.2.34"])
    rc = pv.run(make_ctx(tmp_path, target="9.9"))
    assert rc == 1
    assert not state.runner.selected
    assert "PHP 9.9 is not offered" in (tmp_path / "php-version.md").read_text()


def test_dry_run_lints_with_the_target_and_never_switches(wire, tmp_path):
    state, install = wire
    runner = FakeRunner(list_text=LIST, current_text=CURRENT_72,
                        lint_text=lint_ok(123))
    install(runner=runner, probes=["7.2.34"])
    rc = pv.run(make_ctx(tmp_path, target="8.3"))
    assert rc == 0
    assert runner.selected == []
    assert any("WPT_LINT_COUNT" in c for c in runner.commands)
    assert "php83/usr/bin/php" in next(c for c in runner.commands
                                       if "WPT_LINT_COUNT" in c)
    assert "preflight" in (tmp_path / "php-version.md").read_text()


def test_a_file_that_does_not_parse_blocks_the_switch(wire, tmp_path, capsys):
    state, install = wire
    runner = FakeRunner(
        list_text=LIST, current_text=CURRENT_72,
        lint_text=lint_ok(2)
        + "WPT_LINT_FAIL wp-content/themes/yveslessard/template-contact.php\n")
    install(runner=runner, probes=["7.2.34"])
    rc = pv.run(make_ctx(tmp_path, target="8.3"))
    assert rc == 1
    assert runner.selected == []
    body = (tmp_path / "php-version.md").read_text()
    assert "blocker" in body and "template-contact.php" in body
    # the blocker list is the whole value of this run, so it reaches
    # STDOUT too — an operator who passed no --report still sees it
    out = capsys.readouterr().out
    assert "blocker" in out and "template-contact.php" in out


def test_a_blocked_switch_prints_its_blockers_without_a_report_file(
        wire, tmp_path, capsys):
    """The one flow whose entire value is the blocker list must reach the
    operator even with no ``--report``: a run that printed nothing looked
    like a crash rather than a refusal (L79)."""
    state, install = wire
    runner = FakeRunner(
        list_text=LIST, current_text=CURRENT_72,
        lint_text=lint_ok(2)
        + "WPT_LINT_FAIL wp-content/themes/yveslessard/template-contact.php\n")
    install(runner=runner, probes=["7.2.34"])
    rc = pv.run(make_ctx(tmp_path, target="8.3", report=False))
    assert rc == 1
    assert runner.selected == []
    out = capsys.readouterr().out
    assert "template-contact.php" in out
    assert "blocker" in out.lower()


def test_an_empty_lint_is_a_refusal_not_a_pass(wire, tmp_path):
    state, install = wire
    runner = FakeRunner(list_text=LIST, current_text=CURRENT_72,
                        lint_text=lint_ok(0))
    install(runner=runner, probes=["7.2.34"])
    rc = pv.run(make_ctx(tmp_path, target="8.3"))
    assert rc == 1
    assert runner.selected == []


def test_apply_switches_verifies_and_reports(wire, tmp_path, capsys):
    state, install = wire
    runner = FakeRunner(list_text=LIST, current_text=CURRENT_72,
                        lint_text=lint_ok(10))
    install(runner=runner, probes=["7.2.34", "8.3.36"], session=FakeSession())
    rc = pv.run(make_ctx(tmp_path, target="8.3", apply=True))
    assert rc == 0
    assert runner.selected == ["8.3"]
    out = capsys.readouterr().out
    assert "applied: yes" in out
    assert "PHP 8.3" in out
    data = json.loads((tmp_path / "php-version.json").read_text())
    assert data["applied"] is True and data["rolled_back"] is False


def test_a_switch_that_is_not_served_is_rolled_back(wire, tmp_path):
    state, install = wire
    runner = FakeRunner(list_text=LIST, current_text=CURRENT_72,
                        lint_text=lint_ok(10))
    # old runtime, then every verify attempt still answers the old minor,
    # and the post-rollback probe answers the old minor again.
    install(runner=runner,
            probes=["7.2.34"] + ["7.2.34"] * 3 + ["7.2.34"])
    rc = pv.run(make_ctx(tmp_path, target="8.3", apply=True))
    assert rc == 1
    assert runner.selected == ["8.3", "7.2"]
    data = json.loads((tmp_path / "php-version.json").read_text())
    assert data["applied"] is True and data["rolled_back"] is True


def test_a_5xx_homepage_after_the_switch_rolls_back(wire, tmp_path):
    state, install = wire
    runner = FakeRunner(list_text=LIST, current_text=CURRENT_72,
                        lint_text=lint_ok(10))

    class Broken(FakeSession):
        def get(self, url, **kwargs):
            self.urls.append(url)
            status = 500 if "?" in url else 200
            return SimpleNamespace(status_code=status, content=self.body)

    install(runner=runner, probes=["7.2.34", "8.3.36", "7.2.34"],
            session=Broken())
    rc = pv.run(make_ctx(tmp_path, target="8.3", apply=True))
    assert rc == 1
    assert runner.selected == ["8.3", "7.2"]


def test_already_selected_is_a_no_op(wire, tmp_path, capsys):
    state, install = wire
    runner = FakeRunner(list_text=LIST, current_text=CURRENT_83,
                        lint_text=lint_ok(10))
    install(runner=runner, probes=["8.3.36"])
    rc = pv.run(make_ctx(tmp_path, target="8.3", apply=True))
    assert rc == 0
    assert runner.selected == []
    assert "already" in capsys.readouterr().out
