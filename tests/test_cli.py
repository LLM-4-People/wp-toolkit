import sys

import pytest

from wpt.cli import (Ctx, _parse_set, _pre_scan, _typed_override,
                      build_parser, main)


from wpt.log import get_logger
def test_every_subcommand_help_exits_zero(capsys):
    parser = build_parser()
    for cmd in ("audit", "clean-files", "clean-db", "trim-media", "optimize-media",
                "harden", "verify", "updates", "proxy"):
        with pytest.raises(SystemExit) as exc:
            parser.parse_args(["--source", "local", "--zip", "z.zip", "--sql", "s.sql", cmd, "--help"])
        assert exc.value.code == 0


def test_R11_a_stop_during_settings_load_is_rc1_with_a_failure_pair(
        tmp_path, monkeypatch):
    """R11-P2-13: the SIGTERM handler is installed before settings load but
    the RunControl boundary only wrapped _dispatch, so a stop there escaped
    main() as a traceback and wrote no report."""
    import wpt.cli as cli
    from wpt.types import StopRequested

    def _stop(**_kwargs):
        raise StopRequested("SIGTERM during settings load")

    monkeypatch.setattr(cli, "load_settings", _stop)
    report = tmp_path / "stop.md"

    assert main(["--source", "local", "--report", str(report), "audit"]) == 1
    assert report.is_file()
    assert report.with_suffix(".json").is_file()
    assert "SIGTERM during settings load" in report.read_text("utf-8")


def test_R11_a_stop_during_a_refusal_report_is_rc1_not_a_traceback(
        tmp_path, monkeypatch):
    """R11-P2-13: a second stop landing in the pre-dispatch refusal writer
    must still answer rc 1 (the shared stop exit catches its own report)."""
    import wpt.actions.registry as registry
    from wpt.types import StopRequested

    report = tmp_path / "refusal.md"

    def _stop(*_args, **_kwargs):
        raise StopRequested("SIGTERM during the refusal report")

    monkeypatch.setattr(registry, "write_failure_report", _stop)

    # This run is refused before dispatch: local audit needs --zip/--sql.
    assert main(["--source", "local", "--report", str(report),
                 "audit"]) == 1


def test_R11_a_one_shot_stop_in_a_refusal_writer_still_writes_the_pair(
        tmp_path, monkeypatch):
    """R11-P2-13: the refusal report is inside the boundary; a stop landing
    in its first write reaches the shared stop exit, which attempts the
    failure pair once more instead of swallowing the signal."""
    import wpt.actions.registry as registry
    from wpt.types import StopRequested

    real = registry.write_report_files
    calls = {"n": 0}

    def _stop_once(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise StopRequested("SIGTERM during the first refusal write")
        return real(*args, **kwargs)

    monkeypatch.setattr(registry, "write_report_files", _stop_once)
    report = tmp_path / "refusal.md"

    assert main(["--source", "local", "--report", str(report),
                 "audit"]) == 1
    assert calls["n"] >= 2
    assert report.is_file()
    assert report.with_suffix(".json").is_file()
    assert "SIGTERM during the first refusal write" in report.read_text("utf-8")


def test_password_env_unset_fails_cleanly(tmp_path, monkeypatch):
    monkeypatch.delenv("WPT_MISSING", raising=False)
    rc = main(["--source", "ftp://h", "--user", "u", "--password-env", "WPT_MISSING",
               "--webroot", "domains/x/public_html", "--wp-url", "https://x", "audit"])
    assert rc == 1
    # no traceback leaked


def test_ftp_mode_requires_webroot_and_url():
    rc = main(["--source", "ftp://h", "audit"])
    assert rc == 1


def test_local_mode_requires_zip_and_sql():
    rc = main(["--source", "local", "audit"])
    assert rc == 1


def test_source_only_commands_have_their_own_input_gates(monkeypatch, tmp_path):
    """The source-only diagnostics do not demand inputs they never open:
    discover needs neither webroot nor URL, logs/scan need the webroot only,
    and local scan needs the zip alone (no dump)."""
    import wpt.cli as cli

    calls = []
    monkeypatch.setattr(
        cli, "_lazy_call",
        lambda ctx, module, func: calls.append(
            (ctx.command, ctx.webroot, ctx.wp_url, ctx.zip)) or 0)

    assert main(["--source", "ftp://h", "discover"]) == 0
    assert main(["--source", "ftp://h", "--webroot", "public_html",
                 "logs"]) == 0
    assert main(["--source", "ftp://h", "--webroot", "public_html",
                 "scan"]) == 0
    assert main(["--source", "local", "--zip", str(tmp_path / "z.zip"),
                 "scan"]) == 0
    assert main(["--source", "local", "logs"]) == 0
    assert main(["--source", "local", "discover"]) == 0

    assert calls == [
        ("discover", None, None, None),
        ("logs", "public_html", None, None),
        ("scan", "public_html", None, None),
        ("scan", None, None, tmp_path / "z.zip"),
        ("logs", None, None, None),
        ("discover", None, None, None),
    ]


def test_files_mode_flags_and_gates(monkeypatch, tmp_path):
    import wpt.cli as cli

    calls = []
    monkeypatch.setattr(
        cli, "_lazy_call",
        lambda ctx, module, func: calls.append((ctx.command, ctx.extra)) or 0)

    assert main([
        "--source", "ftp://h", "--webroot", "public_html", "files",
        "--backup", "a.php", "--backup", "b.php",
    ]) == 0
    assert main([
        "--source", "ftp://h", "--webroot", "public_html", "files",
        "--path", "a.php", "--from", str(tmp_path / "a.php"),
        "--path", "b.php", "--from", str(tmp_path / "b.php"),
    ]) == 0
    assert main([
        "--source", "ftp://h", "--webroot", "public_html", "files",
        "--restore", "last",
    ]) == 0
    assert calls[0][1]["backup"] == ["a.php", "b.php"]
    assert calls[1][1]["paths"] == ["a.php", "b.php"]
    assert calls[1][1]["from_paths"] == [
        str(tmp_path / "a.php"), str(tmp_path / "b.php")]
    assert calls[2][1]["restore"] == "last"

    assert main(["--source", "ftp://h", "files",
                 "--backup", "a.php"]) == 1
    assert main(["--source", "local", "files",
                 "--backup", "a.php"]) == 1


def test_R9_P2_2_pre_dispatch_refusals_write_the_report_pair(tmp_path):
    """P2-2: every pre-dispatch input gate returned rc 1 before the shared
    writer, so --report left neither face."""
    cases = [
        ["--source", "local", "scan"],
        ["--source", "local", "files", "--backup", "index.php"],
        ["--source", "ftp://h", "logs"],
        ["--source", "ftp://h", "audit"],
    ]
    for index, tokens in enumerate(cases):
        report = tmp_path / f"refusal-{index}.md"
        assert main([*tokens, "--report", str(report)]) == 1
        markdown = report.read_text(encoding="utf-8")
        assert "## This run did not complete" in markdown
        twin = report.with_suffix(".json")
        assert twin.is_file()
        assert '"status": "failed"' in twin.read_text(encoding="utf-8")

    # A bootstrap refusal (before the profile/log setup) also honours it.
    report = tmp_path / "deadline.md"
    assert main(["--source", "local", "--report", str(report),
                 "--deadline", "-1", "audit"]) == 1
    assert "## This run did not complete" in report.read_text(encoding="utf-8")


def test_logs_and_scan_still_require_the_webroot_in_ftp_mode():
    assert main(["--source", "ftp://h", "logs"]) == 1
    assert main(["--source", "ftp://h", "scan"]) == 1


def test_set_parsing():
    assert _parse_set("a.b=1") == ("a.b", "1")
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--set", "novalue", "--source", "local", "audit"])


def test_typed_override_inference():
    assert _typed_override("x", "true") == ("x", True)
    assert _typed_override("x", "42") == ("x", 42)
    assert _typed_override("x", "1.5") == ("x", 1.5)
    assert _typed_override("x", "word") == ("x", "word")


def test_audit_local_missing_zip_fails_cleanly(tmp_path):
    # W6h wired local audit: the module runs for real now, so a missing
    # zip must exit 1 with a clean error — never a traceback, never rc 2.
    rc = main(["--source", "local", "--zip", str(tmp_path / "z.zip"),
               "--sql", str(tmp_path / "s.sql"), "audit"])
    assert rc == 1


def test_SCAN_QUAD_real_cli_deadline_bounds_dense_sql_php(tmp_path):
    """SCAN-QUAD residual, real CLI: a 112 KB SQL-dense PHP file scanned
    4.71 s and answered rc 0 under --deadline=0.5 because small files
    disabled the deadline.  The scan is now linear AND per-file checked;
    a budget the work cannot meet yields rc 1 with scan-partial."""
    import json as json_mod
    import time
    import zipfile

    text = '<?php $sql="' + "SELECT * FROM t WHERE id=1; " * 4000 + '";'
    zpath = tmp_path / "dense.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("wp-content/plugins/x/x.php", text)
    report = tmp_path / "scan.md"

    started = time.monotonic()
    rc = main(["--source", "local", "--zip", str(zpath), "--deadline=0.5",
               "--report", str(report), "scan"])
    elapsed = time.monotonic() - started
    # Load-robust: a 1.5 s wall bound made this test fail under xdist
    # scheduling even though the semantics were correct.  The assertion
    # that matters is the verdict pair below (finished => rc 0/clean;
    # stopped => rc 1/scan-partial).  A very generous ceiling still catches
    # a return to unbounded work.
    assert elapsed < 60.0, elapsed
    payload = json_mod.loads(
        report.with_suffix(".json").read_text(encoding="utf-8"))
    names = {finding["name"] for finding in payload["findings"]}
    if rc == 1:
        assert "scan-partial" in names
    else:
        # The linear rewrite finished inside the budget; the old contract
        # violation was answering rc 0 AFTER working past it.
        assert rc == 0 and names == set()

    # A budget this work cannot meet must be honest: scan-partial, rc 1.
    forced = tmp_path / "forced.md"
    rc = main(["--source", "local", "--zip", str(zpath), "--deadline=0.05",
               "--report", str(forced), "scan"])
    assert rc == 1
    forced_payload = json_mod.loads(
        forced.with_suffix(".json").read_text(encoding="utf-8"))
    assert any(finding["name"] == "scan-partial"
               for finding in forced_payload["findings"])

    # THREE such files under the same 0.5 s budget (the verifier's public
    # probe took 33.99 s): bounded near the budget, scan-partial, rc 1.
    three = tmp_path / "three.zip"
    with zipfile.ZipFile(three, "w") as zf:
        for index in range(3):
            zf.writestr(f"wp-content/plugins/x/x{index}.php", text)
    three_report = tmp_path / "three.md"
    started = time.monotonic()
    rc = main(["--source", "local", "--zip", str(three), "--deadline=0.5",
               "--report", str(three_report), "scan"])
    elapsed = time.monotonic() - started
    assert elapsed < 60.0, elapsed
    three_payload = json_mod.loads(
        three_report.with_suffix(".json").read_text(encoding="utf-8"))
    three_names = {finding["name"] for finding in three_payload["findings"]}
    if rc == 1:
        assert "scan-partial" in three_names
    else:
        assert rc == 0 and three_names == set()


def test_audit_local_end_to_end(tmp_path):
    # The real CLI path end to end: a minimal zip + dump, one check group.
    import json as json_mod
    import zipfile

    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.html", "<h1>WP</h1>")
        zf.writestr("wp-config.php", "<?php // no DISALLOW_FILE_EDIT")
    dump = (
        b"CREATE TABLE `wp_options` (`option_id` int, `option_name` text, "
        b"`option_value` longtext, `autoload` varchar(20));\n"
        b"INSERT INTO `wp_options` VALUES (1,'siteurl',"
        b"'s:22:\"https://example.test/\";','yes'),(2,'home',"
        b"'s:22:\"https://example.test/\";','yes'),(3,'template',"
        b"'s:10:\"twentytwenty\";','yes'),(4,'blog_public','i:1;','yes');\n"
        b"CREATE TABLE `wp_posts` (`ID` int, `post_type` text, `post_status` text);\n"
    )
    spath = tmp_path / "site.sql"
    spath.write_bytes(dump)
    report = tmp_path / "report.md"
    rc = main(["--source", "local", "--zip", str(zpath), "--sql", str(spath),
               "--report", str(report), "audit", "--only", "webroot"])
    assert rc == 0
    text = report.read_text(encoding="utf-8")
    assert "webroot.junk" in text and "readme.html" in text
    payload = json_mod.loads(report.with_suffix(".json").read_text(encoding="utf-8"))
    assert payload["site"] == "local:site.zip"
    assert any(f["category"] == "webroot.junk" for f in payload["findings"])


def test_run_start_line_logged(tmp_path):
    """[L15] One run-start info line before any phase output — the live
    lesson: a KILLED run's stale log tail (its SIGTERM error) read as
    the new run's output for minutes.  The line carries command, mode,
    webroot and site URL only — never the user or password.  Captured
    through --log-file (setup_logging REPLACES handlers, so an attached
    capture handler would be gone before the line is emitted)."""
    import zipfile

    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.html", "<h1>WP</h1>")
    dump = (
        b"CREATE TABLE `wp_options` (`option_id` int, `option_name` text, "
        b"`option_value` longtext, `autoload` varchar(20));\n"
        b"INSERT INTO `wp_options` VALUES (1,'siteurl',"
        b"'s:22:\"https://example.test/\";','yes');\n"
    )
    spath = tmp_path / "site.sql"
    spath.write_bytes(dump)
    logfile = tmp_path / "wpt.log"
    rc = main(["--source", "local", "--zip", str(zpath), "--sql", str(spath),
               "--log-file", str(logfile), "audit", "--only", "webroot"])
    assert rc == 0
    lines = logfile.read_text(encoding="utf-8").splitlines()
    assert any("wpt audit starting: source=local webroot=- site=-" in ln
               for ln in lines)


def test_mutating_command_dry_run_plans_over_real_zip(tmp_path):
    # W7d wired clean-files: a dry run over a real zip plans (rc 0) without
    # touching anything; --apply on local mode REHEARSES (a materialized
    # twin — the original is the rollback; pinned in the action suites).
    import zipfile

    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.html", "<h1>WP</h1>")
    rc = main(["--source", "local", "--zip", str(zpath),
               "--sql", str(tmp_path / "s.sql"), "clean-files"])
    assert rc == 0
    with zipfile.ZipFile(zpath) as zf:
        assert zf.namelist() == ["readme.html"]  # zip untouched (dry run)


def test_mutating_command_missing_zip_exits_cleanly(tmp_path):
    # Source setup errors exit 1 with a clean message, never a traceback
    # (the stack construction lives inside the registry's error contract).
    rc = main(["--source", "local", "--zip", str(tmp_path / "missing.zip"),
               "--sql", str(tmp_path / "s.sql"), "clean-files"])
    assert rc == 1


def test_proxy_requires_hostname_ip():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--source", "local", "proxy"])


def test_ctx_mode():
    local_ctx = Ctx(source="local", settings=None)  # type: ignore[arg-type]
    assert local_ctx.mode == "local"
    ftp_ctx = Ctx(source="ftp://h:21", settings=None)  # type: ignore[arg-type]
    assert ftp_ctx.mode == "ftp"


# --------------------------------------------------------------------------
# Global flags on either side of the command name.
#
# The live migration lesson: `--report`/`--apply`/`--yes` lived on the
# global parser, so `wpt ... audit --report out.md` died with
# "unrecognized arguments", and a subcommand flag typed before the command
# (`wpt ... --baseline prev.json audit`) made argparse read the FLAG VALUE
# as the command — "invalid choice: 'reports/she-audit-baseline.json'".
# Both orders now mean the same run, and both wrong orders are answered
# with the flag that was put on the wrong side.
# --------------------------------------------------------------------------


def _site_fixture(tmp_path):
    """A real local-mode webroot zip + dump: enough to audit and to plan."""
    import zipfile

    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("wp-config.php", "<?php // no DISALLOW_FILE_EDIT")
        zf.writestr("readme.html", "<h1>WP</h1>")
        zf.writestr("error_log", "[03-Sep-2026] PHP Notice: something\n")
    spath = tmp_path / "site.sql"
    spath.write_bytes(
        b"CREATE TABLE `wp_options` (`option_id` int, `option_name` text, "
        b"`option_value` longtext, `autoload` varchar(20));\n"
        b"INSERT INTO `wp_options` VALUES (1,'siteurl',"
        b"'https://example.test','yes'),(2,'home','https://example.test','yes');\n"
        b"CREATE TABLE `wp_posts` (`ID` int, `post_type` text, "
        b"`post_status` text);\n"
    )
    return zpath, spath


def test_global_flags_after_the_command_equal_before_it(tmp_path):
    """`audit --report R --apply --yes` == `--report R --apply --yes ... audit`.

    Compared on rc AND on the artifacts (the rendered report and its JSON
    twin), so a hoisted flag that landed in the wrong slot would show."""
    import json as json_mod

    zpath, spath = _site_fixture(tmp_path)
    globals_ = ["--source", "local", "--zip", str(zpath), "--sql", str(spath)]
    before, after = tmp_path / "before.md", tmp_path / "after.md"
    flags = ["--apply", "--yes"]

    assert main([*globals_, "--report", str(before), *flags, "audit",
                 "--only", "webroot"]) == 0
    assert main([*globals_, "audit", "--only", "webroot",
                 "--report", str(after), *flags]) == 0

    for report in (before, after):
        assert report.exists() and report.with_suffix(".json").exists()
        payload = json_mod.loads(
            report.with_suffix(".json").read_text(encoding="utf-8"))
        assert [f["category"] for f in payload["findings"]] == \
            ["webroot.junk", "webroot.junk"]
        assert "readme.html" in report.read_text(encoding="utf-8")
    assert (json_mod.loads(before.with_suffix(".json").read_text(encoding="utf-8"))["findings"]
            == json_mod.loads(after.with_suffix(".json").read_text(encoding="utf-8"))["findings"])


def test_global_flags_after_the_command_agree_on_a_mutating_apply(tmp_path):
    """The same order-insensitivity on a real --apply --yes: both runs
    rehearse the same cleanup into a twin zip, the original untouched."""
    import shutil
    import zipfile

    zpath, spath = _site_fixture(tmp_path)
    globals_ = ["--source", "local", "--zip", str(zpath), "--sql", str(spath)]
    before, after = tmp_path / "before" / "site.zip", tmp_path / "after" / "site.zip"
    before.parent.mkdir()
    after.parent.mkdir()
    for target in (before, after):
        shutil.copy(zpath, target)

    assert main([*globals_, "--zip", str(before), "--apply", "--yes",
                 "clean-files"]) == 0
    assert main([*globals_, "--zip", str(after), "clean-files",
                 "--apply", "--yes"]) == 0

    for run_dir, target in ((tmp_path / "before", before), (tmp_path / "after", after)):
        with zipfile.ZipFile(target) as zf:
            assert "readme.html" in zf.namelist()  # the original IS the rollback
        twins = sorted(run_dir.glob("site-rehearsed-*.zip"))
        assert len(twins) == 1
        with zipfile.ZipFile(twins[0]) as zf:
            names = zf.namelist()
        assert "readme.html" not in names and "error_log" not in names
        assert "wp-config.php" in names


def test_R12_listener_default_ports_have_one_owner():
    """R12-P2-18: argparse and the engine/fallback paths each restated
    8080/8443.  Both now read ``wpt.ports``; the parser defaults must equal
    the exported constants."""
    import wpt.ports as ports
    import wpt.proxy as proxy
    import wpt.serve as serve

    parser = build_parser()
    serve_args = parser.parse_args(["--source", "local", "serve"])
    assert serve_args.port == ports.DEFAULT_SERVE_PORT
    assert serve._FALLBACK_PORT == ports.DEFAULT_SERVE_PORT
    proxy_args = parser.parse_args([
        "--source", "local", "proxy", "--hostname", "h", "--ip", "192.0.2.44"])
    assert proxy_args.port == ports.DEFAULT_PROXY_PORT
    assert proxy.run_proxy.__kwdefaults__["port"] == ports.DEFAULT_PROXY_PORT
    import wpt.dnsoverride as dnsoverride
    assert dnsoverride.ProxyServer.__init__.__kwdefaults__["port"] == \
        ports.DEFAULT_PROXY_PORT


def test_R12_profile_is_a_protected_input_for_the_report_twin(tmp_path):
    """R12-P2-12: ``--profile config.json --report config.md`` replaced the
    profile with the report's JSON twin.  The profile is protected in both
    faces; a different report path still runs."""
    import json as json_mod

    zpath, spath = _site_fixture(tmp_path)
    profile = tmp_path / "config.json"
    original = json_mod.dumps({"log": {"level": "info"}})
    profile.write_text(original, encoding="utf-8")
    globals_ = ["--source", "local", "--zip", str(zpath), "--sql", str(spath),
                "--profile", str(profile)]

    assert main([*globals_, "--report", str(tmp_path / "config.md"),
                 "audit", "--only", "webroot"]) == 1
    assert profile.read_text(encoding="utf-8") == original

    ok = tmp_path / "other.md"
    assert main([*globals_, "--report", str(ok),
                 "audit", "--only", "webroot"]) == 0
    assert profile.read_text(encoding="utf-8") == original
    assert ok.is_file()


def test_R12_baseline_direct_markdown_collision_refused_but_refresh_legal(
        tmp_path):
    """R12-P2-12: naming the baseline itself as the report markdown destroyed
    it, while the documented prev.md + prev.json refresh must stay legal."""
    import json as json_mod

    zpath, spath = _site_fixture(tmp_path)
    globals_ = ["--source", "local", "--zip", str(zpath), "--sql", str(spath)]
    prev = tmp_path / "prev.json"
    prev.write_text("{}", encoding="utf-8")

    assert main([*globals_, "--report", str(prev), "audit",
                 "--baseline", str(prev), "--only", "webroot"]) == 1
    assert prev.read_text(encoding="utf-8") == "{}"

    first = tmp_path / "first.md"
    assert main([*globals_, "--report", str(first), "audit",
                 "--only", "webroot"]) == 0
    baseline = first.with_suffix(".json")
    refresh = baseline.with_suffix(".md")
    assert main([*globals_, "--report", str(refresh), "audit",
                 "--only", "webroot",
                 "--baseline", str(baseline)]) == 0
    assert "## Changed since baseline" in refresh.read_text(encoding="utf-8")
    payload = json_mod.loads(baseline.read_text(encoding="utf-8"))
    assert payload["diff"] == {"new": [], "resolved": [], "changed": []}


def test_subcommand_flag_after_the_command_still_works(tmp_path):
    """`audit --baseline prev.json` — the subcommand's own flag, after the
    command. It was the case that used to be unreadable; the diff it asks
    for is what proves the flag reached the check runner."""
    import json as json_mod

    zpath, spath = _site_fixture(tmp_path)
    globals_ = ["--source", "local", "--zip", str(zpath), "--sql", str(spath)]
    first, second = tmp_path / "first.md", tmp_path / "second.md"
    assert main([*globals_, "--report", str(first), "audit",
                 "--only", "webroot"]) == 0
    baseline = first.with_suffix(".json")
    assert main([*globals_, "audit", "--only", "webroot",
                 "--report", str(second), "--baseline", str(baseline)]) == 0
    assert "## Changed since baseline" in second.read_text(encoding="utf-8")
    assert json_mod.loads(
        second.with_suffix(".json").read_text(encoding="utf-8"))["diff"] == {
        "new": [], "resolved": [], "changed": []}


def test_value_in_command_position_says_which_flag_moved(tmp_path, capsys):
    """`--baseline prev.json audit` used to report "invalid choice:
    'prev.json'". The error now names the flag and the side it belongs on."""
    zpath, spath = _site_fixture(tmp_path)
    prev = tmp_path / "prev.json"
    prev.write_text("{}", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main(["--source", "local", "--zip", str(zpath), "--sql", str(spath),
              "--baseline", str(prev), "audit"])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "is not a wpt command" in err
    assert "'--baseline' is a flag of the 'audit' command and belongs AFTER" in err
    assert f"audit --baseline {prev}" in err
    assert "invalid choice" not in err


def test_unknown_flag_points_at_the_command_s_own_flags(tmp_path, capsys):
    """A flag that belongs to no parser names where flags DO go: the
    globals work on either side of the command, the command's own only
    after it."""
    zpath, spath = _site_fixture(tmp_path)
    with pytest.raises(SystemExit) as exc:
        main(["--source", "local", "--zip", str(zpath), "--sql", str(spath),
              "audit", "--bogus"])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "'--bogus' is not a wpt flag" in err
    assert "before OR after the command name" in err
    assert "--baseline" in err  # the audit command's own flags are listed

    with pytest.raises(SystemExit):
        main(["--source", "local", "--zip", str(zpath), "--sql", str(spath),
              "--only", "webroot", "audit"])
    err = capsys.readouterr().err
    assert "is not a wpt command" in err
    assert "audit --only webroot" in err


def test_working_invocation_forms_are_untouched(tmp_path):
    """The forms that always worked still parse to the same args: globals
    only before the command, subcommand flags and positionals after it,
    inline `--flag=value`, long-option abbreviations, `--deadline -5` (R11)
    and the `--` tail.  (An inline value once swallowed the command name
    that followed it — `--report=r.md audit` parsed `--report=r.md` AND
    `audit` as one flag, so the run died with "required: command".)"""
    parser = build_parser()
    zpath, spath = _site_fixture(tmp_path)
    base = ["--source", "local", "--zip", str(zpath), "--sql", str(spath)]
    expected = parser.parse_args([*base, "--report", "r.md", "audit",
                                  "--only", "webroot"])
    for tokens in ([*base, "--report", "r.md", "audit", "--only", "webroot"],
                   [*base, "audit", "--only", "webroot", "--report", "r.md"],
                   [*base, "--report=r.md", "audit", "--only=webroot"],
                   [*base, "--report=r.md", "audit", "--onl", "webroot"],
                   [*base, "audit", "--report=r.md", "--onl", "webroot"],
                   [*base, "audit", "--only=webroot", "--report", "r.md"]):
        got = parser.parse_args(_pre_scan(parser, tokens))
        assert vars(got) == vars(expected), tokens

    # a negative number is a value, not a flag
    got = parser.parse_args(_pre_scan(
        parser, [*base, "audit", "--deadline", "-5"]))
    assert got.deadline == -5
    # the `--` tail is passed through untouched
    got = parser.parse_args(_pre_scan(
        parser, [*base, "restore", "--undo-last", "--", "--weird-name"]))
    assert got.undo_last and got.snapshot == "--weird-name"
    assert got.command == "restore"


def test_a_global_flag_never_eats_the_command_or_a_positional(tmp_path, capsys):
    """The hoisting can never take a token argparse would not: a value-taking
    global with no value of its own used to swallow whatever came next — the
    COMMAND NAME, or a command's own positional. The live damage was silent,
    not loud: `restore --report 20260921-120000` parsed the snapshot as the
    report path, so restore ran with no target and rc 0'd after LISTING
    snapshots instead of restoring one. `audit --zip` read a webroot archive
    named "audit". Every shape now fails closed on the real mistake."""
    zpath, spath = _site_fixture(tmp_path)
    base = ["--source", "local", "--zip", str(zpath), "--sql", str(spath)]

    # the scan itself: the flag stays exactly where it was typed, i.e.
    # AFTER the command it was written after
    parser = build_parser()
    for tokens in ([*base, "audit", "--zip"],
                   [*base, "audit", "--report"],
                   [*base, "restore", "--report", "20260921-120000"],
                   [*base, "deactivate-plugin", "--report", "litespeed-cache"]):
        scanned = _pre_scan(parser, tokens)
        command_at = next(i for i, t in enumerate(scanned)
                          if t in ("audit", "restore", "deactivate-plugin"))
        flag = "--report" if "--report" in tokens else "--zip"
        # the LAST occurrence: `base` carries its own --zip/--sql
        flag_at = len(scanned) - 1 - scanned[::-1].index(flag)
        assert flag_at > command_at, tokens

    for tokens, named in (
        ([*base, "audit", "--zip"], "--zip"),
        ([*base, "audit", "--report"], "--report"),
        ([*base, "restore", "--report", "20260921-120000"], "--report"),
        ([*base, "deactivate-plugin", "--report", "litespeed-cache"],
         "--report"),
        ([*base, "audit", "--log-level"], "--log-level"),
    ):
        capsys.readouterr()
        with pytest.raises(SystemExit) as exc:
            main(tokens)
        assert exc.value.code == 2, tokens
        err = capsys.readouterr().err
        # argparse's own diagnosis, naming the flag that was left behind
        assert f"unrecognized arguments: {named}" in err, tokens
        assert "required: command" not in err, tokens

    # the restore case is the one that used to succeed and do the wrong thing
    capsys.readouterr()
    with pytest.raises(SystemExit) as exc:
        main([*base, "restore", "--report", "20260921-120000"])
    assert exc.value.code == 2
    assert "20260921-120000" not in capsys.readouterr().out  # no snapshot list


def test_hoisting_stops_at_the_first_flag_it_cannot_move(tmp_path, capsys):
    """Hoisting is a contiguous-prefix operation: once a global is left where
    it was typed, nothing after it is reordered around it — otherwise the
    hoisted `--apply` would jump in front and the refused `--report` would
    read it as "this flag wants a value", naming the wrong mistake."""
    zpath, spath = _site_fixture(tmp_path)
    base = ["--source", "local", "--zip", str(zpath), "--sql", str(spath)]
    parser = build_parser()
    scanned = _pre_scan(
        parser, [*base, "--report", "--apply", "audit", "--only", "webroot"])
    # --report and --apply keep their relative order, command last
    assert scanned.index("--report") < scanned.index("--apply")
    assert scanned.index("--apply") < scanned.index("audit")
    assert scanned.index("audit") < scanned.index("--only")
    capsys.readouterr()
    with pytest.raises(SystemExit) as exc:
        main([*base, "--report", "--apply", "audit", "--only", "webroot"])
    assert exc.value.code == 2
    assert "expected one argument" in capsys.readouterr().err


def test_set_carries_a_list_or_map_value(tmp_path, capsys):
    """`--set` is the only way to change a list-shaped setting from the
    command line, and every list key (media_optimize.exclude_prefixes,
    media.extensions, webroot_junk, known_heavy, ...) was unreachable: the
    raw string reached the settings owner, which rejects a string where a
    list belongs. A JSON array/object literal is now decoded, so the shipped
    Gravity Forms exclusion can be adjusted without writing a profile."""
    assert _typed_override("k", '["a/", "b/"]') == ("k", ["a/", "b/"])
    assert _typed_override("k", "[]") == ("k", [])
    assert _typed_override("k", '{"a": 1}') == ("k", {"a": 1})
    # scalars keep their inferred type, and a value that only LOOKS like
    # JSON is left to the settings owner to reject in its own words
    assert _typed_override("k", "12") == ("k", 12)
    assert _typed_override("k", "1.5") == ("k", 1.5)
    assert _typed_override("k", "true") == ("k", True)
    assert _typed_override("k", "[not json") == ("k", "[not json")
    assert _typed_override("k", "wp-content/uploads/") == (
        "k", "wp-content/uploads/")

    # end to end: the override reaches the action that consumes the key
    import io
    import zipfile

    import PIL.Image

    zpath, spath = _site_fixture(tmp_path)
    rng = __import__("random").Random(7)
    big = PIL.Image.frombytes("RGB", (900, 700), rng.randbytes(900 * 700 * 3))
    buf = io.BytesIO()
    big.save(buf, format="JPEG", quality=95)
    with zipfile.ZipFile(zpath, "a") as zf:
        zf.writestr("wp-content/uploads/gravity_forms/2024/sub/photo.jpg",
                    buf.getvalue())
    rc = main(["--source", "local", "--zip", str(zpath), "--sql", str(spath),
               "--set", 'media_optimize.exclude_prefixes=["x/"]',
               "--set", "media_optimize.skip_below_bytes=1",
               "optimize-media"])
    assert rc == 0
    # the replaced list wins: the shipped gravity_forms exclusion is gone,
    # so the file is now scanned (and the run says so)
    out = capsys.readouterr().out
    assert "gravity_forms" in out


def test_a_rejected_settings_override_is_a_clean_refusal(tmp_path, capsys):
    """A bad --set/--profile is an operator error the settings owner raises
    for. Unwound it escaped main() as a traceback — the one place a usage
    mistake answered with a stack trace and no exit status of its own."""
    zpath, spath = _site_fixture(tmp_path)
    base = ["--source", "local", "--zip", str(zpath), "--sql", str(spath)]
    capsys.readouterr()
    rc = main([*base, "--set", "media_optimize.exclude_prefixes=notalist",
               "audit"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "exclude_prefixes" in err and "expected list of strings" in err
    assert "Traceback" not in err
    # a malformed profile file refuses the same way
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert main([*base, "--profile", str(bad), "audit"]) == 1


def test_usage_errors_never_echo_a_secret_looking_token(tmp_path, capsys):
    """The new usage errors quote argv tokens, and the token that lands in
    the wrong place is exactly where an operator's mistyped inline secret
    ends up. They route through the shared redactor, like the log
    formatters and the report renderers do."""
    zpath, spath = _site_fixture(tmp_path)
    base = ["--source", "local", "--zip", str(zpath), "--sql", str(spath)]
    # the token that landed in the COMMAND position
    capsys.readouterr()
    with pytest.raises(SystemExit) as exc:
        main([*base, "secret=abc123", "audit"])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "abc123" not in err
    assert "***" in err
    # ... and the token of an unknown flag
    capsys.readouterr()
    with pytest.raises(SystemExit) as exc:
        main([*base, "audit", "--api-secret=abc123"])
    assert exc.value.code == 2
    assert "abc123" not in capsys.readouterr().err
    # ... while a plain path is still quoted verbatim: the message is only
    # useless if it cannot name the thing that was typed
    capsys.readouterr()
    with pytest.raises(SystemExit):
        main([*base, "--baseline", str(tmp_path / "prev.json"), "audit"])
    assert str(tmp_path / "prev.json") in capsys.readouterr().err


def test_users_reset_prints_the_credentials_once_after_the_run(tmp_path,
                                                              capsys,
                                                              monkeypatch):
    """The presentation half of the users_reset contract, which is the CLI's
    alone: the generated passwords exist nowhere else, so they print once on
    stdout, under a header, AFTER the run — including when the run ended rc 1
    (a post-apply verification failure still revoked every old password, so
    withholding the new ones locks the operator out of their own site). A dry
    run and a refusal print nothing at all."""
    import wpt.actions as actions_module
    from wpt.actions.registry import get_action

    action = get_action("users_reset").action
    seen = []

    def fake_run(ctx):
        seen.append(ctx.apply)
        # what the real action does: plan() empties the holder, only the
        # apply publishes
        action.credentials = []
        if ctx.apply:
            action.credentials = [{"login": "admin", "email": "a@b.test",
                                   "password": "N3w-Pa55!"}]
        return 0 if ctx.apply else 1

    monkeypatch.setattr(actions_module, "run", fake_run)
    ftp = ["--source", "ftp://h", "--webroot", "/w", "--wp-url", "https://h",
           "users_reset"]

    # an apply: printed once, with the header, and after the run
    capsys.readouterr()
    assert main([*ftp, "--apply", "--yes"]) == 0
    out = capsys.readouterr().out
    assert out.count("N3w-Pa55!") == 1
    assert out.splitlines()[-2:] == ["login\temail\tpassword",
                                     "admin\ta@b.test\tN3w-Pa55!"]
    assert seen == [True]

    # rc 1 from the run itself: still printed — the passwords are live
    action.credentials = []
    monkeypatch.setattr(actions_module, "run",
                        lambda ctx: (setattr(
                            action, "credentials",
                            [{"login": "admin", "email": "a@b.test",
                              "password": "N3w-Pa55!"}]) or 1))
    capsys.readouterr()
    assert main([*ftp, "--apply", "--yes"]) == 1
    assert capsys.readouterr().out.count("N3w-Pa55!") == 1

    # a dry run: the action publishes nothing, so nothing is printed
    monkeypatch.setattr(actions_module, "run", fake_run)
    action.credentials = []
    capsys.readouterr()
    assert main(ftp) == 1
    assert "password" not in capsys.readouterr().out
    assert seen == [True, False]

    # a refusal that never reaches plan(): the holder is emptied BEFORE the
    # run, so an earlier run's passwords are never reprinted by this one
    action.credentials = [{"login": "STALE", "email": "s", "password": "S"}]
    monkeypatch.setattr(actions_module, "run", lambda ctx: 1)
    capsys.readouterr()
    assert main([*ftp, "--apply", "--yes"]) == 1
    assert capsys.readouterr().out == ""
    action.credentials = []


def test_users_reset_target_flags_map_and_are_mutually_exclusive(capsys,
                                                                 monkeypatch):
    """--login (repeatable) and --all are the two target modes; argparse
    refuses both at once, and each maps to ctx.extra exactly."""
    import wpt.actions as actions_module

    seen = []

    def fake_run(ctx):
        seen.append(dict(ctx.extra))
        return 0

    monkeypatch.setattr(actions_module, "run", fake_run)
    ftp = ["--source", "ftp://h", "--webroot", "/w", "--wp-url", "https://h",
           "users_reset"]

    assert main([*ftp, "--login", "alex", "--login", "bob"]) == 0
    assert seen[-1] == {"logins": ["alex", "bob"], "all": False}
    assert main([*ftp, "--all"]) == 0
    assert seen[-1] == {"logins": None, "all": True}
    assert main(ftp) == 0  # no target is the ACTION's refusal, rc 1 in prod
    assert seen[-1] == {"logins": None, "all": False}

    with pytest.raises(SystemExit) as exc:
        main([*ftp, "--login", "alex", "--all"])
    assert exc.value.code == 2


def test_user_create_flags_map_and_required_ones_are_enforced(capsys,
                                                              monkeypatch):
    import wpt.actions as actions_module

    seen = []
    monkeypatch.setattr(
        actions_module, "run",
        lambda ctx: (seen.append(dict(ctx.extra)), 0)[1])
    ftp = ["--source", "ftp://h", "--webroot", "/w", "--wp-url", "https://h",
           "user-create"]

    assert main([*ftp, "--login", "newadmin", "--email", "n@b.test"]) == 0
    assert seen[-1] == {"login": "newadmin", "email": "n@b.test",
                        "role": "administrator"}
    assert main([*ftp, "--login", "newadmin", "--email", "n@b.test",
                 "--role", "editor"]) == 0
    assert seen[-1] == {"login": "newadmin", "email": "n@b.test",
                        "role": "editor"}

    with pytest.raises(SystemExit) as exc:
        main([*ftp, "--login", "newadmin"])  # --email is required
    assert exc.value.code == 2
    with pytest.raises(SystemExit) as exc:
        main([*ftp, "--email", "n@b.test"])  # --login is required
    assert exc.value.code == 2


def test_user_create_prints_the_credentials_once_after_the_run(
        capsys, monkeypatch):
    """The presentation half for the second credential-bearing command: the
    generated password exists nowhere else, so it prints once on stdout,
    under a header, AFTER the run — and a dry run prints nothing."""
    import wpt.actions as actions_module
    from wpt.actions.registry import get_action

    action = get_action("user-create").action
    seen = []

    def fake_run(ctx):
        seen.append(ctx.apply)
        action.credentials = []
        if ctx.apply:
            action.credentials = [{"login": "newadmin", "email": "n@b.test",
                                   "password": "N3w-Pa55!"}]
        return 0 if ctx.apply else 1

    monkeypatch.setattr(actions_module, "run", fake_run)
    ftp = ["--source", "ftp://h", "--webroot", "/w", "--wp-url", "https://h",
           "user-create", "--login", "newadmin", "--email", "n@b.test"]

    capsys.readouterr()
    assert main([*ftp, "--apply", "--yes"]) == 0
    out = capsys.readouterr().out
    assert out.count("N3w-Pa55!") == 1
    assert out.splitlines()[-2:] == ["login\temail\tpassword",
                                     "newadmin\tn@b.test\tN3w-Pa55!"]

    action.credentials = []
    capsys.readouterr()
    assert main(ftp) == 1
    assert "password" not in capsys.readouterr().out
    assert seen == [True, False]

    # a refusal that never reaches plan(): the holder is emptied BEFORE the
    # run, so an earlier run's password is never reprinted by this one
    action.credentials = [{"login": "STALE", "email": "s", "password": "S"}]
    monkeypatch.setattr(actions_module, "run", lambda ctx: 1)
    capsys.readouterr()
    assert main([*ftp, "--apply", "--yes"]) == 1
    assert capsys.readouterr().out == ""
    action.credentials = []


def test_file_only_local_command_needs_no_sql(tmp_path, capsys):
    """clean-files local mode reads the webroot only: demanding a dump it
    never opens refused a run that completes (live lesson)."""
    import zipfile

    zpath, spath = _site_fixture(tmp_path)
    rc = main(["--source", "local", "--zip", str(zpath), "clean-files"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "## Plan" in out
    assert "readme.html" in out and "error_log" in out
    with zipfile.ZipFile(zpath) as zf:
        assert zf.namelist() == ["wp-config.php", "readme.html", "error_log"]

    # ... and --sql is still accepted (and ignored) for the same command
    rc = main(["--source", "local", "--zip", str(zpath), "--sql", str(spath),
               "clean-files"])
    assert rc == 0
    assert "## Plan" in capsys.readouterr().out


def test_local_commands_that_read_the_dump_still_refuse_without_it(tmp_path):
    """audit/updates/verify/backup/restore/walk keep the zip+sql demand;
    clean-db and trim-media (also dump/bridge-backed) are unchanged."""
    zpath, spath = _site_fixture(tmp_path)
    args = ["--source", "local", "--zip", str(zpath)]
    for command in ("audit", "updates", "verify", "backup", "restore", "walk",
                    "clean-db", "trim-media"):
        assert main([*args, command]) == 1, command
        # with the dump, only the ones that read it get past the gate
        assert main([*args, "--sql", str(spath), command]) in (0, 1), command
    # the file-only family still refuses without the zip
    for command in ("clean-files", "optimize-media", "harden", "heal-core"):
        assert main(["--source", "local", command]) == 1, command


def test_backup_walk_local_refuse_end_to_end(tmp_path):
    # The new dispatches reach their modules: backup + walk refuse local
    # mode (rc 1) — the same zip used by the local audit e2e works here.
    import zipfile

    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.html", "<h1>WP</h1>")
    args = ["--source", "local", "--zip", str(zpath), "--sql",
            str(tmp_path / "s.sql")]
    assert main([*args, "backup"]) == 1
    assert main([*args, "walk"]) == 1


def test_restore_list_local_end_to_end(tmp_path, capsys):
    # LIST mode is pure local disk, so local mode works: the site label
    # is local:<zip name> and an empty backup dir lists "No snapshots".
    import zipfile

    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.html", "<h1>WP</h1>")
    rc = main(["--source", "local", "--zip", str(zpath), "--sql",
               str(tmp_path / "s.sql"), "restore"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "# wpt restore — local:site.zip" in out
    assert "No snapshots for local:site.zip." in out


def test_restore_bad_name_fails_closed_end_to_end(tmp_path):
    # A non-snapshot name is refused before any stack is built (rc 1).
    import zipfile

    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.html", "<h1>WP</h1>")
    rc = main(["--source", "local", "--zip", str(zpath), "--sql",
               str(tmp_path / "s.sql"), "restore", "../../etc"])
    assert rc == 1


def test_restore_local_apply_refused_end_to_end(tmp_path, monkeypatch):
    # A real snapshot name on a local ctx: restore mode runs, local mode
    # is refused (v1 restore is ftp-only) — rc 1, listing was fine.
    import zipfile
    from wpt.backup import MANIFEST_NAME

    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.html", "<h1>WP</h1>")
    snap = tmp_path / "bck" / "local-site.zip" / "20240101-120000"
    snap.mkdir(parents=True)
    (snap / MANIFEST_NAME).write_text("{}", encoding="utf-8")
    rc = main(["--source", "local", "--zip", str(zpath), "--sql",
               str(tmp_path / "s.sql"), "--backup-dir", str(tmp_path / "bck"),
               "restore", "20240101-120000"])
    assert rc == 1


def test_new_subcommand_help_exits_zero(capsys):
    parser = build_parser()
    for cmd in ("backup", "restore", "walk"):
        with pytest.raises(SystemExit) as exc:
            parser.parse_args(["--source", "local", "--zip", "z.zip",
                               "--sql", "s.sql", cmd, "--help"])
        assert exc.value.code == 0


def test_deactivate_plugin_local_refused_end_to_end(tmp_path):
    # The subcommand dispatches through the actions registry; local mode
    # is refused (deactivate-plugin applies to ftp only).
    import zipfile

    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.html", "<h1>WP</h1>")
    rc = main(["--source", "local", "--zip", str(zpath), "--sql",
               str(tmp_path / "s.sql"), "deactivate-plugin", "litespeed-cache"])
    assert rc == 1


def test_restore_undo_last_with_no_snapshots_end_to_end(tmp_path):
    # --undo-last with an empty backup dir: rc 1, clean error.
    import zipfile

    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.html", "<h1>WP</h1>")
    rc = main(["--source", "local", "--zip", str(zpath), "--sql",
               str(tmp_path / "s.sql"), "--backup-dir", str(tmp_path / "bck"),
               "restore", "--undo-last"])
    assert rc == 1


def test_sigterm_self_shutdown_is_graceful():
    """The SIGTERM handler converts a stop request into a RunControl raised
    in the main thread — which unwinds through the running command body's
    finally teardowns to the dispatch boundary (one clear log, rc 1; those
    paths are pinned by the per-command error-contract tests). Killing is
    never needed: the run ends itself."""
    import signal

    import wpt.cli
    from wpt.types import RunControl, StopRequested

    previous = signal.getsignal(signal.SIGTERM)
    wpt.cli._install_sigterm_self_shutdown()
    try:
        signal.raise_signal(signal.SIGTERM)
        raise AssertionError("SIGTERM must raise through the handler")
    except RunControl as e:
        assert isinstance(e, StopRequested)
        assert "SIGTERM" in str(e)
        assert "cleanly" in str(e)
    finally:
        # The handler is process-global: leave xdist's (or the embedding
        # test runner's) SIGTERM disposition exactly as we found it.
        signal.signal(signal.SIGTERM, previous)


# --------------------------------------------------------------------------
# The direct database source (--db-uri), local mode only.
#
# The migration lesson: clean-db was ftp-only, so "clean, then test, then
# publish" meant publishing first or hand-porting the bridge's SQL. The
# offline path replaces the bridge for ONE command (clean-db) and adds a
# connectivity row to the doctor; everything else must refuse the flag
# loudly rather than ignore it, and ftp mode must refuse it outright (the
# bridge is the write path there — two write paths for one command is how
# a run mutates the wrong one).
# --------------------------------------------------------------------------


def _capture_offline(monkeypatch):
    """Patch the offline entry point; return the list of ctxs it saw."""
    import wpt.actions.clean_db as clean_db_mod

    seen = []
    monkeypatch.setattr(clean_db_mod, "run_offline",
                        lambda ctx: (seen.append(ctx), 0)[1])
    return seen


def test_db_uri_flags_are_globals_on_either_side_of_the_command(tmp_path,
                                                                monkeypatch):
    seen = _capture_offline(monkeypatch)
    monkeypatch.setenv("WPT_DB_PASS", "from-env")
    uri = "mysql://wpuser:pw@db.internal:3307/wp_stage"
    base = ["--source", "local", "--db-uri", uri,
            "--db-password-env", "WPT_DB_PASS", "--re-dump",
            str(tmp_path / "out.sql")]
    before = main([*base, "clean-db"])
    after = main(["--source", "local", "clean-db", "--db-uri", uri,
                  "--db-password-env", "WPT_DB_PASS", "--re-dump",
                  str(tmp_path / "out.sql")])
    assert (before, after) == (0, 0)
    assert len(seen) == 2
    for ctx in seen:
        assert ctx.db_uri == uri
        assert ctx.db_password_env == "WPT_DB_PASS"
        assert ctx.re_dump == tmp_path / "out.sql"
        assert ctx.mode == "local"


def test_db_uri_clean_db_needs_no_zip_and_no_sql(tmp_path, monkeypatch):
    """The direct database IS the DB data source: it replaces the dump, and
    this run touches no webroot file, so demanding inputs it never opens
    would refuse a run that completes."""
    seen = _capture_offline(monkeypatch)
    assert main(["--source", "local", "--db-uri", "mysql://u@h/db",
                 "clean-db"]) == 0
    assert seen[0].zip is None and seen[0].sql is None
    # ... and WITHOUT --db-uri the dump is still demanded (unchanged)
    assert main(["--source", "local", "clean-db"]) == 1


def test_db_uri_is_refused_in_ftp_mode(capsys):
    """One line, one reason — and never the password the operator typed."""
    assert main(["--source", "ftp://h", "--webroot", "/w", "--wp-url",
                 "https://h", "--db-uri", "mysql://u:sup3rs3cret@h/db",
                 "clean-db"]) == 1
    err = capsys.readouterr().err
    assert "local" in err and "bridge" in err
    assert "sup3rs3cret" not in err
    assert err.strip().count("\n") == 0  # one line, not a paragraph


def test_db_uri_applies_to_clean_db_and_doctor_only(tmp_path, capsys):
    zpath, spath = _site_fixture(tmp_path)
    base = ["--source", "local", "--zip", str(zpath), "--sql", str(spath),
            "--db-uri", "mysql://u@h/db"]
    for command in ("audit", "updates", "verify", "backup", "restore", "walk",
                    "clean-files", "trim-media"):
        assert main([*base, command]) == 1, command
    assert "clean-db/doctor" in capsys.readouterr().err


def test_db_password_env_and_re_dump_need_their_companions(tmp_path, capsys):
    # a typo in a flag name is caught here, not at the first DELETE
    assert main(["--source", "local", "--db-password-env", "WPT_X",
                 "clean-db"]) == 1
    assert "--db-uri" in capsys.readouterr().err
    assert main(["--source", "local", "--re-dump", str(tmp_path / "d.sql"),
                 "clean-db"]) == 1
    assert "--db-uri" in capsys.readouterr().err
    # --re-dump is clean-db's own output, not another command's
    assert main(["--source", "local", "--db-uri", "mysql://u@h/db",
                 "--re-dump", str(tmp_path / "d.sql"), "doctor"]) == 1
    assert "--re-dump" in capsys.readouterr().err


def test_a_bad_db_uri_is_one_clean_line(capsys):
    assert main(["--source", "local", "--db-uri", "postgres://u:pw@h/db",
                 "clean-db"]) == 1
    err = capsys.readouterr().err
    assert "not supported" in err and "mysql://" in err
    assert "pw@" not in err  # the userinfo never comes back


def test_db_password_env_resolves_at_the_credential_choke_point(tmp_path,
                                                                 monkeypatch):
    seen = _capture_offline(monkeypatch)
    monkeypatch.setenv("WPT_DB_PASS", "from-env")
    assert main(["--source", "local", "--db-uri",
                 "mysql://wpuser:inline@db/wp_stage",
                 "--db-password-env", "WPT_DB_PASS", "clean-db"]) == 0
    # the env var wins over the inline one (it stays off the command line)
    assert seen[0].db_password == "from-env"
    # ... and the FTP-style refusal when it is unset
    monkeypatch.delenv("WPT_DB_PASS")
    assert main(["--source", "local", "--db-uri", "mysql://u@h/db",
                 "--db-password-env", "WPT_DB_PASS", "clean-db"]) == 1


def test_the_run_start_line_never_carries_the_db_password(tmp_path, monkeypatch,
                                                          caplog):
    import logging

    seen = _capture_offline(monkeypatch)
    with caplog.at_level(logging.DEBUG, logger="wpt"):
        main(["--source", "local", "--db-uri",
              "mysql://wpuser:sup3rs3cret@db/wp_stage", "clean-db"])
    parent = logging.getLogger("wpt")
    parent.addHandler(caplog.handler)
    try:
        assert main(["--source", "local", "--db-uri",
                     "mysql://wpuser:sup3rs3cret@db/wp_stage", "clean-db"]) == 0
    finally:
        parent.removeHandler(caplog.handler)
    assert "sup3rs3cret" not in caplog.text
    assert len(seen) == 2


def test_a_db_uri_typed_in_the_command_position_is_redacted(tmp_path, capsys):
    """The classic flag-before-command slip puts the VALUE where the command
    goes — the one place an inline DSN password would be printed back."""
    zpath, spath = _site_fixture(tmp_path)
    uri = "mysql://wpuser:sup3rs3cret@db/wp_stage"
    # the flag's NAME went missing, so its value sits where the command goes
    with pytest.raises(SystemExit) as exc:
        main(["--source", "local", "--zip", str(zpath), uri, "clean-db"])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "is not a wpt command" in err
    assert "sup3rs3cret" not in err and "***" in err


def test_quiet_silences_only_the_console_and_log_file_adds_a_sink(tmp_path, capsys):
    """[L47] --log-file must ADD a file sink, not replace the console: a run
    that fails printed its explanation only into the file (rc 1, 0 bytes on
    stderr). --quiet is the operator's switch for the console alone."""
    from wpt.log import setup_logging

    logfile = tmp_path / "wpt.log"
    setup_logging(level="info", logfile=str(logfile), console=True)
    get_logger("test").error("both sinks must see this")
    for handler in _all_handlers():
        handler.flush()
    assert "both sinks must see this" in logfile.read_text()
    assert capsys.readouterr().err  # the console received it too

    setup_logging(level="info", logfile=str(logfile), console=False)
    get_logger("test").error("file only")
    for handler in _all_handlers():
        handler.flush()
    assert "file only" in logfile.read_text()


def _all_handlers():
    import logging
    return logging.getLogger("wpt").handlers


# ------------------------------------------------------- triple-check round 2


def test_CLI1_local_prune_core_needs_only_the_zip(monkeypatch, tmp_path):
    """CLI1: SPEC says prune-core runs with ``--zip`` alone (it never reads
    the dump); the local gate demanded ``--sql`` too."""
    import wpt.cli as cli

    calls = []
    monkeypatch.setattr(
        cli, "_lazy_call",
        lambda ctx, module, func: calls.append(ctx.command) or 0)
    assert main(["--source", "local", "--zip", str(tmp_path / "z.zip"),
                 "prune-core"]) == 0
    assert calls == ["prune-core"]


def test_CLI2_main_reconfigures_output_streams_for_non_utf8_terminals(
        monkeypatch):
    """CLI2: an ASCII stdout raised UnicodeEncodeError on the report's em
    dash AFTER mutations committed.  ``main`` is the one process-wide output
    choke point and must switch both streams to ``errors='replace'``."""
    import wpt.cli as cli

    class _AsciiStream:
        encoding = "ascii"

        def __init__(self):
            self.errors = "strict"
            self.written = []

        def reconfigure(self, *, errors=None):
            self.errors = errors

        def write(self, text):
            # The real TextIOWrapper encodes here under its error mode.
            text.encode(self.encoding, self.errors)
            self.written.append(text)

        def flush(self):
            pass

    out, err = _AsciiStream(), _AsciiStream()
    monkeypatch.setattr(cli.sys, "stdout", out)
    monkeypatch.setattr(cli.sys, "stderr", err)
    monkeypatch.setattr(
        cli, "_lazy_call",
        lambda ctx, module, func: out.write("report — done\n") or 0)

    assert main(["--source", "ftp://h", "discover"]) == 0
    assert out.errors == "replace" and err.errors == "replace"
    assert out.written == ["report — done\n"]


def test_DOC8_wpt_log_level_environment_fallback_is_read(monkeypatch):
    """DOC8: SPEC documents ``WPT_LOG_LEVEL``; it must select the level
    when ``--log-level`` is absent, and an invalid value is refused."""
    import logging
    import wpt.cli as cli

    monkeypatch.setattr(cli, "_lazy_call", lambda ctx, module, func: 0)
    monkeypatch.setenv("WPT_LOG_LEVEL", "debug")
    assert main(["--source", "ftp://h", "discover"]) == 0
    assert logging.getLogger("wpt").level == logging.DEBUG

    monkeypatch.setenv("WPT_LOG_LEVEL", "bogus")
    assert main(["--source", "ftp://h", "discover"]) == 1


def test_PROXY_CLI_documented_invocation_needs_no_source(monkeypatch, capsys):
    """PROXY-CLI: the documented ``wpt proxy --hostname … --ip …`` exited 2
    because --source was globally required, and local/ftp gates demanded
    inputs the body never reads."""
    import wpt.proxy as proxy_mod

    calls = []
    monkeypatch.setattr(
        proxy_mod, "run_proxy",
        lambda ctx, **kwargs: calls.append((ctx.source, kwargs)) or 0)

    assert main(["proxy", "--hostname", "site.test", "--ip", "192.0.2.44"]) == 0
    assert main(["--source", "local", "proxy", "--hostname", "site.test",
                 "--ip", "192.0.2.44"]) == 0
    assert main(["--source", "ftp://h", "proxy", "--hostname", "site.test",
                 "--ip", "192.0.2.44"]) == 0
    assert [source for source, _kwargs in calls] == [
        "local", "local", "ftp://h"]
    assert calls[0][1]["hostname"] == "site.test"
    assert calls[0][1]["ip"] == "192.0.2.44"


def test_DEADLINE_ARG_refuses_negative_nan_and_inf_at_the_door(capsys):
    """DEADLINE-ARG: argparse accepted any float; -5 silently disabled the
    bound and NaN/Inf produced a Deadline that never expires."""
    for value in ("-5", "nan", "inf", "-inf"):
        rc = main(["--source", "local", f"--deadline={value}", "doctor"])
        assert rc == 1, value
        err = capsys.readouterr().err
        assert "deadline" in err.lower()
        assert "finite" in err.lower()
        assert "Traceback" not in err
    # 0 remains the documented off switch (parser accepts it; the command's
    # own gate/body is not entered here because --source is validated first).
    parser = build_parser()
    args = parser.parse_args(["--source", "local", "--deadline=0", "doctor"])
    assert args.deadline == 0


def test_C6_deep_set_and_profile_are_one_line_refusals_with_a_report(
        tmp_path, capsys):
    """C6: a 100k-deep JSON literal raised RecursionError out of main() for
    both --set and --profile, with no report pair.  Both are operator input
    refusals answered through the settings contract."""
    deep = "[" * 100_000 + "0" + "]" * 100_000

    report = tmp_path / "deep-set.md"
    rc = main(["--source", "local", "--set", f"webroot_junk={deep}",
               "--report", str(report), "doctor"])
    assert rc == 1
    assert "too deeply nested" in capsys.readouterr().err
    assert report.exists() and report.with_suffix(".json").exists()

    profile = tmp_path / "profile.json"
    profile.write_text('{"a":' + deep + "}", encoding="utf-8")
    report = tmp_path / "deep-profile.md"
    rc = main(["--source", "local", "--profile", str(profile),
               "--report", str(report), "doctor"])
    assert rc == 1
    assert "too deeply nested" in capsys.readouterr().err
    assert report.exists() and report.with_suffix(".json").exists()


def test_C8_an_expired_budget_is_refused_before_dispatch(tmp_path):
    """C8: an already-expired --deadline still dispatched harden/optimize/
    restore to rc 0.  The gateway refuses EVERY command before its body and
    writes the failure pair."""
    import json as json_mod
    import zipfile

    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as archive:
        archive.writestr("wp-config.php", "<?php // config")
        archive.writestr("readme.html", "<h1>WP</h1>")
    report = tmp_path / "expired.md"

    rc = main(["--source", "local", "--zip", str(zpath),
               "--deadline", "1e-9", "--report", str(report),
               "clean-files", "--apply", "--yes"])
    assert rc == 1
    markdown = report.read_text(encoding="utf-8")
    assert markdown.startswith("# wpt clean-files — ")
    assert "## This run did not complete" in markdown
    twin = json_mod.loads(report.with_suffix(".json").read_text("utf-8"))
    assert twin["run"]["status"] == "failed"
    assert "dispatch" in twin["run"]["reason"]
    # nothing was mutated: the archive is still the input zip
    assert zipfile.is_zipfile(zpath)


def test_R11_C10_a_symlink_alias_names_the_protected_input(
        tmp_path, capsys):
    """R11-P2-18: the refusal named the report alias as "the input"; the
    diagnostic must name the file that would be destroyed."""
    import zipfile

    zpath = tmp_path / "copy.zip"
    with zipfile.ZipFile(zpath, "w") as archive:
        archive.writestr("wp-config.php", "<?php // config")
    alias = tmp_path / "alias.md"
    alias.symlink_to(zpath)
    before = zpath.read_bytes()

    rc = main(["--source", "local", "--zip", str(zpath),
               "--report", str(alias), "clean-files"])

    assert rc == 1
    assert zpath.read_bytes() == before
    err = capsys.readouterr().err
    assert f"resolves to this run's input {zpath}" in err
    assert f"input {alias}" not in err


def test_C10_report_path_that_is_an_input_is_refused_before_reading(
        tmp_path, capsys):
    """C10: --report copy.zip replaced the zip the audit was reading and
    exited 0, contradicting the "the ORIGINAL zip is never opened for
    write" contract.  The shared gate refuses before any read/write."""
    import zipfile

    zpath = tmp_path / "copy.zip"
    spath = tmp_path / "copy.sql"
    with zipfile.ZipFile(zpath, "w") as archive:
        archive.writestr("wp-config.php", "<?php // config")
    spath.write_text("-- empty dump\n", encoding="utf-8")
    before = zpath.read_bytes()

    rc = main(["--source", "local", "--zip", str(zpath), "--sql",
               str(spath), "--report", str(zpath), "audit"])
    assert rc == 1
    assert zpath.read_bytes() == before
    assert zipfile.is_zipfile(zpath)
    err = capsys.readouterr().err
    assert "resolves to this run's input" in err
    assert not zpath.with_suffix(".json").exists()


def test_LOG_FILE_SURROGATE_real_cli_keeps_the_run_start_line(
        tmp_path, capsys):
    """LOG-FILE-SURROGATE: a surrogate --wp-url made logging's FileHandler
    raise on the run-start line; the file kept only the later line and stderr
    showed "--- Logging error ---"."""
    logfile = tmp_path / "wpt.log"
    rc = main(["--source", "local", "--wp-url", "https://\udcff.example",
               "--log-file", str(logfile), "logs"])
    captured = capsys.readouterr()
    assert rc == 1
    assert "Logging error" not in captured.err
    assert "UnicodeEncodeError" not in captured.err
    content = logfile.read_text(encoding="utf-8")
    assert "wpt logs starting" in content
    assert "\\udcff" in content


def test_REPORT_SURROGATE_real_cli_doctor_writes_both_faces(
        tmp_path, monkeypatch):
    """REPORT-SURROGATE: a site-controlled surrogate reached the strict
    write_text and crashed after the table, leaving a 0-byte markdown and no
    JSON twin."""
    from types import SimpleNamespace
    from tests.fakes import FakeSession, FakeResponse
    import json as json_mod
    import wpt.doctor

    monkeypatch.setattr(wpt.doctor, "remote_stack",
                        lambda ctx: (_ for _ in ()).throw(
                            AssertionError("local panel")))
    monkeypatch.setattr(wpt.doctor.requests, "Session", lambda: FakeSession([
        FakeResponse(200, json_mod.dumps(
            {"offers": [{"current": "6.7.2"}]}))]))
    monkeypatch.setattr(wpt.doctor.shutil, "disk_usage",
                        lambda _path: SimpleNamespace(free=3 * 1024 ** 3))
    report = tmp_path / "doctor.md"
    rc = main(["--source", "local", "--wp-url", "https://\udcff.example",
               "--report", str(report), "doctor"])
    assert rc == 0
    markdown = report.read_text(encoding="utf-8")
    twin = report.with_suffix(".json").read_text(encoding="utf-8")
    assert markdown and "\\udcff" in markdown
    assert json_mod.loads(twin)


def test_REPORT_SURROGATE_real_cli_doctor_run_level_failure(
        tmp_path, monkeypatch):
    """REPORT-SURROGATE run-level failure: the failure report was also
    written strictly, so the surrogate traceback replaced rc 1."""
    import wpt.doctor
    from wpt.types import WptError

    def _boom(ctx, deadline=None):
        raise WptError("panel failed for https://\udcff.example")

    monkeypatch.setattr(wpt.doctor, "_local_panel", _boom)
    report = tmp_path / "doctor.md"
    rc = main(["--source", "local", "--report", str(report), "doctor"])
    assert rc == 1
    markdown = report.read_text(encoding="utf-8")
    twin = report.with_suffix(".json").read_text(encoding="utf-8")
    assert "did not complete" in markdown
    assert "\\udcff" in markdown
    assert "\\udcff" in twin


def test_REPORT_SURROGATE_real_cli_scan_logs_discover_files(
        tmp_path, monkeypatch):
    """REPORT-SURROGATE reaches scan/logs/discover/files too: every report
    face must encode a surrogate site/argv value completely."""
    monkeypatch.chdir(tmp_path)  # a default .wpt-backup would land here
    import json as json_mod
    import zipfile

    zip_path = tmp_path / "site.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("wp-config.php", "<?php // config")
        archive.writestr("a.txt", "hello")

    report = tmp_path / "scan.md"
    rc = main(["--source", "local", "--zip", str(zip_path),
               "--wp-url", "https://\udcff.example",
               "--report", str(report), "scan"])
    assert rc == 0
    assert "\\udcff" in report.read_text(encoding="utf-8")
    assert json_mod.loads(report.with_suffix(".json").read_text("utf-8"))

    report = tmp_path / "logs.md"
    rc = main(["--source", "local", "--wp-url", "https://\udcff.example",
               "--report", str(report), "logs"])
    assert rc == 1
    assert "\\udcff" in report.read_text(encoding="utf-8")
    assert "\\udcff" in report.with_suffix(".json").read_text("utf-8")

    # discover titles its report with the SOURCE; an FTP refusal carrying a
    # surrogate in that label must still encode both faces.
    import wpt.discover as discover_mod
    from wpt.types import WptError

    def _boom(ctx, root=None):
        raise WptError("cannot reach https://\udcff.example")

    monkeypatch.setattr(discover_mod, "ftp_source_for", _boom)
    report = tmp_path / "discover.md"
    rc = main(["--source", "ftp://h", "--report", str(report), "discover"])
    assert rc == 1
    assert "\\udcff" in report.read_text(encoding="utf-8")
    assert "\\udcff" in report.with_suffix(".json").read_text("utf-8")

    # files: a local zip NAME carrying a surrogate reaches the report title.
    # APFS rejects a lone surrogate in a filename, so that filesystem face is
    # covered on the platforms that can represent it; the three report faces
    # above still run on macOS.
    if sys.platform != "darwin":
        import os
        surrogate_zip = tmp_path / os.fsdecode(b"z\xff.zip")
        with zipfile.ZipFile(surrogate_zip, "w") as archive:
            archive.writestr("a.txt", "hello")
        report = tmp_path / "files.md"
        rc = main(["--source", "local", "--zip", str(surrogate_zip),
                   "--backup-dir", str(tmp_path / "bck"),
                   "--report", str(report), "files", "--backup", "a.txt"])
        assert rc == 0
        assert "\\udcff" in report.read_text(encoding="utf-8")
        assert "\\udcff" in report.with_suffix(".json").read_text("utf-8")
        assert not (tmp_path / ".wpt-backup").exists()


def test_LOG_HELP_STALE_help_derives_from_the_one_level_owner():
    """P2-LOG-HELP-STALE: help said debug|info|warning|error while
    LOG_LEVELS includes critical, and the env precedence was undocumented."""
    from wpt.settings import LOG_LEVELS

    parser = build_parser()
    action = next(a for a in parser._actions
                  if "--log-level" in a.option_strings)
    for level in LOG_LEVELS:
        assert level in action.help
    assert "WPT_LOG_LEVEL" in action.help


def test_R17_log_file_cannot_append_to_a_protected_input(
        tmp_path, capsys):
    """R17-8-P1: --log-file opened (append) BEFORE the collision gate, so a
    read-only command corrupted the zip/dump/profile it was reading.  The
    log path is checked against the same protected owner before opening."""
    import shutil
    import zipfile

    import wpt.settings as settings_mod

    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.html", "x")
    spath = tmp_path / "dump.sql"
    spath.write_bytes(b"-- dump\n")
    profile = tmp_path / "profile.json"
    shutil.copyfile(settings_mod._DEFAULT_PROFILE, profile)

    for log_path, extra in (
        (zpath, []),
        (spath, []),
        (profile, ["--profile", str(profile)]),
    ):
        before = log_path.read_bytes()
        args = ["--source", "local", "--zip", str(zpath),
                "--sql", str(spath), *extra,
                "--log-file", str(log_path), "audit"]
        assert main(args) == 1, log_path
        assert log_path.read_bytes() == before, log_path
        assert "resolves to this run's input" in capsys.readouterr().err


def test_R17_log_file_cannot_append_into_a_snapshot(
        tmp_path, capsys):
    """A snapshot manifest/payload is a run input too: the log gate protects
    every selected/known snapshot subtree before FileHandler opens."""
    import wpt.backup as backup
    from tests.fakes import FakeSource
    from wpt.settings import BackupSettings

    source = FakeSource()
    source.files["readme.html"] = b"KEEP"
    meta = backup.create_snapshot(
        source, None, "example.com", ["readme.html"], [],
        tmp_path / "bck", BackupSettings(),
        "backup", site_raw="example.com", webroot="public_html")
    manifest = meta.path / "manifest.json"
    before = manifest.read_bytes()

    rc = main([
        "--source", "ftp://example.com", "--webroot", "public_html",
        "--wp-url", "https://example.com", "--backup-dir", str(tmp_path / "bck"),
        "--log-file", str(manifest), "restore", meta.path.name,
    ])
    assert rc == 1
    assert manifest.read_bytes() == before
    assert "resolves to this run's input" in capsys.readouterr().err


def test_R17_json_report_is_refused_before_a_mutating_apply(tmp_path, capsys):
    """R17-8-P2: the writer refused ``out.json`` only after the action had
    already applied/materialized.  The output-shape gate now runs
    pre-dispatch, so local apply leaves no rehearsal residue."""
    import zipfile

    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.html", "junk")
        zf.writestr("wp-config.php", "cfg")
    before = zpath.read_bytes()
    report = tmp_path / "out.json"

    rc = main(["--source", "local", "--zip", str(zpath),
               "--backup-dir", str(tmp_path / "bck"),
               "--apply", "--yes", "--report", str(report), "clean-files"])
    assert rc == 1
    assert zpath.read_bytes() == before
    assert not list(tmp_path.glob("site-rehearsed-*.zip"))
    assert not report.exists()
    assert "refusing a .json report path" in capsys.readouterr().err


def test_R18_report_non_regular_target_is_refused_before_apply(
        tmp_path, capsys):
    """R18-P2: a FIFO report target was renamed away and replaced by the
    report.  Both faces are refused pre-dispatch, with no rehearsal/apply."""
    import os
    import zipfile

    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.html", "junk")
        zf.writestr("wp-config.php", "cfg")
    before = zpath.read_bytes()

    for name in ("out.md", "out.json"):
        fifo = tmp_path / name
        os.mkfifo(fifo)
        rc = main(["--source", "local", "--zip", str(zpath),
                   "--backup-dir", str(tmp_path / "bck"),
                   "--apply", "--yes", "--report", str(tmp_path / "out.md"),
                   "clean-files"])
        assert rc == 1, name
        assert fifo.exists() and not fifo.is_file(), name
        assert zpath.read_bytes() == before
        assert not list(tmp_path.glob("site-rehearsed-*.zip"))
        assert "not a regular file" in capsys.readouterr().err
        fifo.unlink()


def test_R18_report_twin_directory_and_missing_parent_are_refused_before_apply(
        tmp_path, capsys):
    """R18-P2: a twin ``out.json/`` directory and a missing report parent
    were checked only AFTER the local apply had created its rehearsal zip."""
    import zipfile

    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.html", "junk")
        zf.writestr("wp-config.php", "cfg")
    before = zpath.read_bytes()
    (tmp_path / "out.json").mkdir()

    rc = main(["--source", "local", "--zip", str(zpath),
               "--backup-dir", str(tmp_path / "bck"),
               "--apply", "--yes", "--report", str(tmp_path / "out.md"),
               "clean-files"])
    assert rc == 1
    assert "not a regular file" in capsys.readouterr().err
    assert zpath.read_bytes() == before
    assert not list(tmp_path.glob("site-rehearsed-*.zip"))

    rc = main(["--source", "local", "--zip", str(zpath),
               "--backup-dir", str(tmp_path / "bck"),
               "--apply", "--yes",
               "--report", str(tmp_path / "missing" / "out.md"),
               "clean-files"])
    assert rc == 1
    assert "no existing parent directory" in capsys.readouterr().err
    assert zpath.read_bytes() == before
    assert not list(tmp_path.glob("site-rehearsed-*.zip"))


def test_R20_log_file_naming_the_redump_output_is_refused(tmp_path, capsys):
    """R20-P2: clean-db's ``--re-dump`` is the run's own OUTPUT; a
    --log-file naming it appended log bytes into the fresh dump."""
    dump = tmp_path / "fresh.sql"
    dump.write_bytes(b"-- previous dump\n")
    assert main(["--source", "local", "--db-uri", "mysql://u@h/db",
                 "--re-dump", str(dump), "--log-file", str(dump),
                 "clean-db"]) == 1
    assert dump.read_bytes() == b"-- previous dump\n"
    assert "input" in capsys.readouterr().err


def test_R18_log_file_hardlink_alias_to_a_protected_input_is_refused(
        tmp_path, capsys):
    """R18-P2: ``os.link(zip, looks.log)`` is a different PATH but the same
    inode, so the path-based gate appended log bytes into the zip."""
    import os
    import zipfile

    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.html", "x")
    before = zpath.read_bytes()
    alias = tmp_path / "looks.log"
    os.link(zpath, alias)

    rc = main(["--source", "local", "--zip", str(zpath),
               "--log-file", str(alias), "audit"])
    assert rc == 1
    assert zpath.read_bytes() == before
    assert alias.read_bytes() == before
    assert "same inode" in capsys.readouterr().err


def test_R22_log_file_symlink_to_a_hardlinked_snapshot_payload_is_refused(
        tmp_path, capsys):
    """R22-P2: the multi-link refusal was skipped for symlinks.  A snapshot
    payload hardlinked outside the tree, then reached through a symlinked
    ``--log-file``, was appended with log text (rc 0) because the resolved
    path sat outside the snapshot root.  Any resolved st_nlink > 1 is now
    refused regardless of the symlink spelling."""
    import os
    import zipfile

    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.html", "x")
    backup = tmp_path / "backup"
    payload = (backup / "site" / "20260101-000000" / "files"
               / "wp-config.php")
    payload.parent.mkdir(parents=True)
    payload.write_text("ORIGINAL-PAYLOAD", encoding="utf-8")
    outside = tmp_path / "outside.bin"
    os.link(payload, outside)
    run_log = tmp_path / "run.log"
    run_log.symlink_to(outside)

    rc = main(["--source", "local", "--zip", str(zpath),
               "--backup-dir", str(backup),
               "--log-file", str(run_log), "scan"])
    assert rc == 1
    assert payload.read_text(encoding="utf-8") == "ORIGINAL-PAYLOAD"
    assert outside.read_text(encoding="utf-8") == "ORIGINAL-PAYLOAD"
    assert run_log.is_symlink()
    assert "hardlink" in capsys.readouterr().err


def test_R19_log_file_special_targets_are_refused_before_any_open(
        tmp_path, capsys):
    """R19-P2: ``--log-file`` was opened eagerly BEFORE the deadline gate.
    A no-reader FIFO blocked past --deadline; ``/dev/full`` discarded every
    line and the run answered silently.  Both are now refused pre-dispatch,
    as is the log sharing the report's markdown/twin file."""
    import os
    import zipfile

    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.html", "junk")

    fifo = tmp_path / "run.log"
    os.mkfifo(fifo)
    rc = main(["--source", "local", "--zip", str(zpath),
               "--deadline", "0.5", "--log-file", str(fifo), "audit"])
    assert rc == 1
    assert "not a regular file" in capsys.readouterr().err
    assert fifo.exists() and not fifo.is_file()

    if os.path.exists("/dev/full"):
        rc = main(["--source", "local", "--zip", str(zpath),
                   "--log-file", "/dev/full", "audit"])
        assert rc == 1, "a device --log-file must not be a silent rc 0"
        assert "not a regular file" in capsys.readouterr().err

    report = tmp_path / "run.md"
    for log in (report, report.with_suffix(".json")):
        rc = main(["--source", "local", "--zip", str(zpath),
                   "--log-file", str(log), "--report", str(report),
                   "audit"])
        assert rc == 1, log
        assert "report face" in capsys.readouterr().err


def test_R19_report_parent_writability_probe_refuses_before_rehearsal(
        tmp_path, capsys):
    """R19-P2: the pre-dispatch parent gate checked only ``is_dir()``, so a
    0555 parent let a local apply materialize its rehearsal zip before the
    writer failed (on FTP the live site would already be mutated)."""
    import os
    import zipfile

    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.html", "junk")
        zf.writestr("wp-config.php", "cfg")
    before = zpath.read_bytes()
    ro = tmp_path / "ro"
    ro.mkdir()
    os.chmod(ro, 0o555)
    try:
        rc = main(["--source", "local", "--zip", str(zpath),
                   "--backup-dir", str(tmp_path / "bck"),
                   "--apply", "--yes", "--report", str(ro / "out.md"),
                   "clean-files"])
        assert rc == 1
        assert zpath.read_bytes() == before
        assert not list(tmp_path.glob("site-rehearsed-*.zip"))
        err = capsys.readouterr().err
        assert "cannot be written" in err or "Permission denied" in err
    finally:
        os.chmod(ro, 0o755)
    assert not list(ro.iterdir())


def test_R18_deploy_manifest_under_backup_dir_is_a_protected_subtree(
        tmp_path, capsys):
    """R18-P2: ``<backup-dir>/deploy/<site>-<stamp>/manifest.json`` matched
    no snapshot NAME pattern, so a report with the same stem replaced its
    manifest twin."""
    import zipfile

    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.html", "x")
    spath = tmp_path / "dump.sql"
    spath.write_text("-- empty\n", encoding="utf-8")
    deploy_dir = tmp_path / "bck" / "deploy" / "example.test-20261020-120000"
    deploy_dir.mkdir(parents=True)
    manifest = deploy_dir / "manifest.json"
    manifest.write_text('{"format": "wpt-deploy-manifest"}', encoding="utf-8")
    before = manifest.read_bytes()

    rc = main(["--source", "local", "--zip", str(zpath), "--sql", str(spath),
               "--backup-dir", str(tmp_path / "bck"),
               "--report", str(deploy_dir / "manifest.md"), "audit"])
    assert rc == 1
    assert manifest.read_bytes() == before
    assert not (deploy_dir / "manifest.md").exists()
    assert "resolves to this run's input" in capsys.readouterr().err

    # R19: --log-file rides the SAME protected-subtree owner.
    rc = main(["--source", "local", "--zip", str(zpath), "--sql", str(spath),
               "--backup-dir", str(tmp_path / "bck"),
               "--log-file", str(deploy_dir / "run.log"), "audit"])
    assert rc == 1
    assert manifest.read_bytes() == before
    assert not (deploy_dir / "run.log").exists()
    assert "resolves to this run's input" in capsys.readouterr().err


def test_R19_deploy_local_target_is_a_protected_report_subtree(
        tmp_path, capsys):
    """R19-P2: a report inside ``--ssh-target local:<dir>`` was written
    AFTER verification, replacing a deployed file (and a dry run replaced a
    pre-existing target file).  The local target root is now a protected
    subtree before dispatch: rc 1, target bytes unchanged, no report."""
    import zipfile

    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("index.php", "<?php deployed")
    target = tmp_path / "target"
    target.mkdir()
    existing = target / "index.php"
    existing.write_text("<?php ORIGINAL", encoding="utf-8")
    before = existing.read_bytes()

    rc = main(["--source", "local", "--zip", str(zpath),
               "--webroot", str(target),
               "--backup-dir", str(tmp_path / "bck"),
               "--apply", "--yes", "--report", str(target / "report.php"),
               "deploy", "--ssh-target", f"local:{target}"])
    assert rc == 1
    assert existing.read_bytes() == before
    assert not (target / "report.php").exists()
    assert not (target / "report.json").exists()
    assert "resolves to this run's input" in capsys.readouterr().err


def test_CLI_LOGFILE_an_unwritable_path_is_one_line_and_rc_1(tmp_path, capsys):
    """P2-CLI-LOGFILE: setup_logging ran outside the settings try, so an
    unopenable --log-file escaped main() as a FileNotFoundError traceback."""
    missing = tmp_path / "no-such-dir" / "wpt.log"
    assert main(["--source", "local", "--log-file", str(missing),
                 "doctor"]) == 1
    err = capsys.readouterr().err
    assert "cannot open --log-file" in err
    assert "Traceback" not in err


def test_PROXY_HOSTNAME_an_invalid_idna_label_is_one_line_and_rc_1(capsys):
    """P2-PROXY-HOSTNAME: idna encoding ran outside run_proxy's try and the
    catch omitted UnicodeError, so a bad label was a traceback."""
    assert main(["proxy", "--hostname", "x" * 64,
                 "--ip", "127.0.0.1", "--port", "0"]) == 1
    err = capsys.readouterr().err
    assert "proxy failed" in err
    assert "Traceback" not in err


def test_R6_04_quiet_cli_never_prints_the_unredacted_failure(tmp_path, capsys):
    """R6-04 through the REAL CLI: --quiet without --log-file used to leave
    lastResort as the only sink, and it printed the credential-bearing path
    raw.  Quiet must emit nothing at all."""
    secret = tmp_path / "password=SECRET.zip"
    sql = tmp_path / "dump.sql"
    sql.write_text("-- empty\n", encoding="utf-8")
    rc = main(["--source", "local", "--zip", str(secret), "--sql", str(sql),
               "--quiet", "audit"])
    assert rc == 1
    err = capsys.readouterr().err
    assert err == ""
    assert "SECRET" not in err


def test_R7_P2_08_local_user_still_requires_password_env(tmp_path, capsys):
    """R7-P2-08: the --user/--password-env gate lived inside the ftp branch,
    so local mode accepted a login identity with no secret source."""
    import zipfile

    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.html", b"x")
    assert main(["--source", "local", "--zip", str(zpath),
                 "--user", "alice", "scan"]) == 1
    assert "--user requires --password-env" in capsys.readouterr().err


def test_R24_refusal_pair_never_overwrites_an_aliased_log_file(tmp_path, capsys):
    """R24-P2: the pre-dispatch alias gate refused the run, then
    ``_write_refusal_report`` wrote the failure markdown over the very log
    file the operator had named — destroying the bytes that explain it.
    The refusal pair is skipped for an aliased log; the log survives."""
    import zipfile

    zpath = tmp_path / "site.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("readme.html", "junk")
    log = tmp_path / "run.log"
    log.write_text("PRE-EXISTING-LOG-BYTES\n", encoding="utf-8")

    rc = main(["--source", "local", "--zip", str(zpath),
               "--log-file", str(log), "--report", str(log), "audit"])
    assert rc == 1
    assert "cannot share one file" in capsys.readouterr().err
    assert log.read_text(encoding="utf-8") == "PRE-EXISTING-LOG-BYTES\n"
    assert not log.with_suffix(".json").exists()

    # The settings refusal happens BEFORE the alias gate; it must keep the
    # log too.
    rc = main(["--source", "local", "--zip", str(zpath),
               "--log-file", str(log), "--report", str(log),
               "--set", "bogus.key=1", "audit"])
    assert rc == 1
    assert log.read_text(encoding="utf-8") == "PRE-EXISTING-LOG-BYTES\n"
    assert not log.with_suffix(".json").exists()
