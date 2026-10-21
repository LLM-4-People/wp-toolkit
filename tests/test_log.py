import json
import logging

import pytest

import wpt.log as logmod


def test_get_logger_namespaces_under_wpt():
    logger = logmod.get_logger("sources.ftp")
    assert logger.name == "wpt.sources.ftp"
    assert logger.parent is logging.getLogger("wpt")


def test_setup_logging_idempotent(capsys):
    logmod.setup_logging(level="debug")
    logmod.setup_logging(level="debug")
    parent = logging.getLogger("wpt")
    assert len(parent.handlers) == 1
    for h in parent.handlers:
        h.flush()
    assert "wpt" not in capsys.readouterr().err or True  # no crash, single handler


def test_log_file_ADDS_a_sink_and_never_silences_the_terminal(tmp_path, capsys):
    """``--log-file`` must not delete the channel the operator is watching.

    The reproduced failure: a run configured with a log file that then
    failed returned rc 1 with ZERO bytes on stderr, so the terminal — the
    one place a human is looking — carried no explanation at all and the
    only copy was on disk.  A centralized chokepoint adds a sink; it never
    takes one away.
    """
    logfile = tmp_path / "wpt.log"
    logmod.setup_logging(level="error", logfile=str(logfile))
    parent = logging.getLogger("wpt")
    assert len(parent.handlers) == 2
    logmod.get_logger("test").error("deploy preflight REFUSED: no space")
    for handler in parent.handlers:
        handler.flush()
    err = capsys.readouterr().err
    assert "deploy preflight REFUSED" in err
    assert "deploy preflight REFUSED" in logfile.read_text(encoding="utf-8")


def test_quiet_silences_the_console_and_keeps_the_file(tmp_path, capsys):
    """``--quiet`` turns the CONSOLE sink off, and only that.

    One switch, one sink: an operator quieting a cron run still gets the
    whole log on disk, and a WARNING is never lost, only redirected.
    """
    logfile = tmp_path / "wpt.log"
    logmod.setup_logging(level="warning", logfile=str(logfile), console=False)
    parent = logging.getLogger("wpt")
    assert len(parent.handlers) == 1
    assert isinstance(parent.handlers[0], logging.FileHandler)
    logmod.get_logger("test").warning("reference scan was truncated")
    for handler in parent.handlers:
        handler.flush()
    assert capsys.readouterr().err == ""
    assert "reference scan was truncated" in logfile.read_text(encoding="utf-8")


def test_one_logger_one_level_reaches_every_sink(tmp_path, capsys):
    """Both sinks belong to the SAME logger, so the level governs both.

    A level applied to one handler and not the other is how a file ends up
    with everything and the terminal with nothing (or the reverse), which
    makes the two sinks disagree about what the run did.
    """
    logfile = tmp_path / "wpt.log"
    logmod.setup_logging(level="warning", logfile=str(logfile))
    logmod.get_logger("test").info("routine progress")
    logmod.get_logger("test").warning("something the operator must see")
    for handler in logging.getLogger("wpt").handlers:
        handler.flush()
    err = capsys.readouterr().err
    content = logfile.read_text(encoding="utf-8")
    assert "routine progress" not in err
    assert "routine progress" not in content
    assert "something the operator must see" in err
    assert "something the operator must see" in content


def test_the_file_sink_is_closed_when_it_is_replaced(tmp_path):
    """A reconfigured run must not leave a handle on the old log file.

    The sinks are rebuilt on every ``setup_logging`` call, so a stale
    FileHandler left open would keep a deleted log file alive on Windows and
    leak a descriptor on every reconfiguration.
    """
    first = tmp_path / "first.log"
    second = tmp_path / "second.log"
    logmod.setup_logging(level="info", logfile=str(first))
    stale = logging.getLogger("wpt").handlers[-1]
    logmod.setup_logging(level="info", logfile=str(second))
    assert stale.stream is None or stale.stream.closed


def test_secret_extra_redacted_in_human_formatter(tmp_path):
    logmod.setup_logging(level="info", logfile=str(tmp_path / "w.log"))
    logmod.get_logger("test").info("connecting", extra={"password": "hunter2"})
    logging.getLogger("wpt").handlers[0].flush()
    content = (tmp_path / "w.log").read_text()
    assert "hunter2" not in content
    assert "***" in content


def test_secret_extra_redacted_in_json_formatter(tmp_path):
    logmod.setup_logging(level="info", logfile=str(tmp_path / "w.log"), json_mode=True)
    logmod.get_logger("test").info("connecting", extra={"api_token": "abc123"})
    logging.getLogger("wpt").handlers[0].flush()
    content = (tmp_path / "w.log").read_text()
    assert "abc123" not in content
    payload = json.loads(content.strip().splitlines()[-1])
    assert payload["msg"] == "connecting"
    assert payload["api_token"] == "***"


def test_secret_in_a_message_argument_is_redacted(tmp_path):
    """The formatter scrubbed ``msg`` but not its ``%s`` args, so an
    exception string carrying a userinfo URL reached the log verbatim."""
    logfile = tmp_path / "args.log"
    logmod.setup_logging(level="error", logfile=str(logfile))
    logmod.get_logger("test").error(
        "scan failed: %s", "ftp://user:sup3rsecret@example.test")
    for handler in logging.getLogger("wpt").handlers:
        handler.flush()
    content = logfile.read_text(encoding="utf-8")
    assert "sup3rsecret" not in content
    assert "user:***@example.test" in content


def test_redact_message_kv_forms():
    msg = "ftp login password=hunter2 token: abc command issued"
    out = logmod.redact_message(msg)
    assert "hunter2" not in out and "abc" not in out
    assert "password=***" in out and "token=***" in out


def test_redact_message_bearer_and_url_credentials():
    from wpt.config import redact_text
    # Authorization: Bearer <jwt> — the WHOLE header value is the credential,
    # so the token (after the "Bearer" keyword) must be gone.
    out = redact_text("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.secret")
    assert "eyJhbGciOiJIUzI1NiJ9.secret" not in out
    assert "Authorization" in out
    # a standalone Bearer token (transport error) is redacted too
    out = redact_text("sent Bearer eyJhbGciOiJIUzI1NiJ9x refused")
    assert "eyJhbGciOiJIUzI1NiJ9x" not in out
    # URL credentials https://user:secret@host
    out = redact_text("GET https://admin:s3cr3t@example.test/wp failed")
    assert "s3cr3t" not in out
    assert "admin:***@example.test" in out


def test_level_filtering(tmp_path):
    logmod.setup_logging(level="warning", logfile=str(tmp_path / "w.log"))
    logmod.get_logger("test").info("should not appear")
    logmod.get_logger("test").warning("should appear")
    logging.getLogger("wpt").handlers[0].flush()
    content = (tmp_path / "w.log").read_text()
    assert "should not appear" not in content
    assert "should appear" in content


def test_exc_info_in_json(tmp_path):
    logmod.setup_logging(level="info", logfile=str(tmp_path / "w.log"), json_mode=True)
    try:
        raise RuntimeError("boom-boom-secret")
    except RuntimeError:
        logmod.get_logger("test").exception("failure")
    logging.getLogger("wpt").handlers[0].flush()
    content = (tmp_path / "w.log").read_text()
    assert "RuntimeError" in content


def _flush_all():
    for handler in logging.getLogger("wpt").handlers:
        handler.flush()


def test_LOG_1_exception_traceback_is_redacted_in_both_sinks(tmp_path):
    """The formatted traceback (and JSON ``exc``) is a string like any
    other: a userinfo URL inside it must not reach either sink."""
    human = tmp_path / "human.log"
    logmod.setup_logging(level="debug", logfile=str(human))
    try:
        raise RuntimeError("connect ftp://user:TRACE_SECRET@example.test failed")
    except RuntimeError:
        logmod.get_logger("test").exception("scan failed")
    _flush_all()
    assert "TRACE_SECRET" not in human.read_text(encoding="utf-8")

    json_file = tmp_path / "json.log"
    logmod.setup_logging(level="debug", logfile=str(json_file), json_mode=True)
    try:
        raise RuntimeError("connect ftp://user:JSON_SECRET@example.test failed")
    except RuntimeError:
        logmod.get_logger("test").exception("scan failed")
    _flush_all()
    payload = json.loads(json_file.read_text(encoding="utf-8").strip())
    assert "JSON_SECRET" not in payload["exc"]
    assert "user:***@example.test" in payload["exc"]


def test_LOG_1_exception_object_argument_is_redacted(tmp_path):
    logfile = tmp_path / "excarg.log"
    logmod.setup_logging(level="error", logfile=str(logfile))
    exc = RuntimeError("ftp://user:ARG_SECRET@example.test")
    logmod.get_logger("test").error("scan failed: %s", exc)
    _flush_all()
    assert "ARG_SECRET" not in logfile.read_text(encoding="utf-8")


def test_LOG_1_secret_template_with_placeholder_formats_then_redacts(
        tmp_path, capsys):
    """LOG-1: redacting ``msg`` before ``getMessage()`` removed the
    placeholder, dropped the record, and let logging's handler print the
    raw arguments to stderr.  Format once, redact once."""
    logfile = tmp_path / "template.log"
    logmod.setup_logging(level="info", logfile=str(logfile))
    log = logmod.get_logger("test")
    log.info("config password=%s", "hunter2")
    log.info("wrote %d files", 5)
    _flush_all()
    content = logfile.read_text(encoding="utf-8")
    assert "config password=***" in content
    assert "hunter2" not in content
    assert "wrote 5 files" in content
    err = capsys.readouterr().err
    assert "hunter2" not in err
    assert "Arguments:" not in err


def test_LOG_1_extra_values_are_redacted_not_only_secret_keys(tmp_path):
    logfile = tmp_path / "extra.log"
    logmod.setup_logging(level="info", logfile=str(logfile),
                         json_mode=True)
    logmod.get_logger("test").info(
        "connecting", extra={"url": "ftp://user:EXTRA_SECRET@example.test"})
    _flush_all()
    content = logfile.read_text(encoding="utf-8")
    assert "EXTRA_SECRET" not in content
    assert "user:***@example.test" in content


def test_LOG_1_extra_nested_values_are_redacted(tmp_path):
    logfile = tmp_path / "nested.log"
    logmod.setup_logging(level="info", logfile=str(logfile))
    logmod.get_logger("test").info(
        "connecting",
        extra={"context": {"url": "ftp://user:NESTED_SECRET@example.test"}})
    _flush_all()
    assert "NESTED_SECRET" not in logfile.read_text(encoding="utf-8")


def test_R6_39_cyclic_extra_and_mapping_args_are_bounded_placeholders(capsys):
    """R6-39: a cyclic extra raised RecursionError out of a filtering log
    call (default console and --log-file sinks).  A repeat becomes
    ``<circular>`` and a pathologically deep value ``<max-depth>``."""
    logmod.setup_logging(level="info")
    logger = logmod.get_logger("test")

    cycle: dict[str, object] = {}
    cycle["self"] = cycle
    logger.info("cyclic extra", extra={"data": cycle})
    logger.info("cyclic args %(data)s", {"data": cycle})

    deep: object = "leaf"
    for _ in range(logmod._REDACT_MAX_DEPTH + 5):
        deep = [deep]
    logger.info("deep extra", extra={"data": deep})

    _flush_all()
    err = capsys.readouterr().err
    assert "cyclic extra" in err and "cyclic args" in err
    assert "<circular>" in err
    assert "<max-depth>" in err
    assert "RecursionError" not in err


def test_NF3_shared_dag_is_memoized_and_bounded(capsys):
    """N-F3: shared children were re-walked on every branch (depth 20 =
    seconds, depth 32 = hours).  Each distinct container is redacted once,
    its rendered size is charged on reuse, and a total-node budget bounds
    the text/JSON sinks; a small shared child still renders on both
    branches."""
    import time

    leaf = ["leaf"]
    assert logmod._redact_extra_value([leaf, leaf]) == [["leaf"], ["leaf"]]

    dag: object = "leaf"
    for _ in range(22):
        dag = [dag, dag]  # binary DAG: exponentially many paths, 23 nodes

    started = time.monotonic()
    redacted = logmod._redact_extra_value(dag)
    assert time.monotonic() - started < 3.0
    assert "<max-nodes>" in repr(redacted)

    logmod.setup_logging(level="info")
    logger = logmod.get_logger("test")
    started = time.monotonic()
    logger.info("shared dag", extra={"data": dag})
    _flush_all()
    assert time.monotonic() - started < 3.0
    err = capsys.readouterr().err
    assert "shared dag" in err
    assert "RecursionError" not in err


def test_REDACT_1_prefixed_secret_keys_are_redacted():
    from wpt.config import redact_text

    secrets = {
        "db_password": "hunter2",
        "api_key": "abc123",
        "api_token": "tok-999",
        "client_secret": "shh-555",
        "access_token": "at-777",
        "secret_key": "sk-888",
    }
    text = " ".join(f"{key}={value}" for key, value in secrets.items())
    out = redact_text(text)
    for value in secrets.values():
        assert value not in out
    for key in secrets:
        assert f"{key}=***" in out
    # A word merely containing "key" is not a secret assignment.
    assert redact_text("monkey=banana") == "monkey=banana"


@pytest.mark.parametrize("line", [
    "user_pass='''HUNTER2'",
    "password='HUN''TER2'",
    'password="""HUNTER2"',
    'password="HUN""TER2"',
    "WordPress database error: user_pass='''HUNTER2' WHERE ID=1",
])
def test_R25_doubled_sql_quote_escape_never_leaks_the_secret(line):
    """R25-P1: SQL/PHP escape a quote in a string by DOUBLING it.  The
    redaction span ended at the first quote of ``''``, so ``'''HUNTER2'``
    became ``***'HUNTER2'`` (and ``'HUN''TER2'`` leaked the suffix).  The
    scanner consumes the doubled quote as one escape and redacts the whole
    value."""
    from wpt.config import redact_text

    out = redact_text(line)
    assert "HUNTER2" not in out
    assert "HUN" not in out
    assert "***" in out


def test_R20_json_and_php_escaped_secret_keys_are_redacted():
    """R20-P2: a JSON-escaped key (``pass\\u0077ord``) decodes to a secret
    slot at load time, but the text scanner compared the raw escapes and
    leaked the value.  The quoted key is decoded at the assignment owner;
    the key stays visible and the value is redacted."""
    from wpt.config import redact_text

    for text, secret in (
        (r'{"pass\u0077ord":"HUNTER2"}', "HUNTER2"),
        (r'{"api\u0053ecret":"HUNTER2"}', "HUNTER2"),
        (r'"pass\x77ord" => "HUNTER2"', "HUNTER2"),
    ):
        out = redact_text(text)
        assert secret not in out, text
        assert "***" in out
        assert "monkey" not in out
    # An escaped ordinary word is still ordinary.
    inert = r'{"monk\u0065y":"banana"}'
    assert redact_text(inert) == inert


def test_SEC_1_scheme_less_userinfo_is_redacted():
    from wpt.config import redact_text

    out = redact_text("user:hunter2@host")
    assert "hunter2" not in out
    assert "user:***@host" in out
    out = redact_text("source user:hunter2@host refused")
    assert "hunter2" not in out


def test_REDACT_2_multi_segment_secret_prefixes_are_redacted():
    """Follow-up to REDACT-1: every `[A-Za-z0-9]+_` prefix segment counts."""
    from wpt.config import redact_text

    out = redact_text(
        "WORDPRESS_DB_PASSWORD=hunter2 my_db_password=x a_b_c_token=tok")
    assert out == (
        "WORDPRESS_DB_PASSWORD=*** my_db_password=*** a_b_c_token=***")
    # A word merely containing "key" is still not a secret assignment.
    assert redact_text("monkey=banana") == "monkey=banana"
    assert redact_text("some_monkey=banana") == "some_monkey=banana"


def test_SEC_2_bare_userinfo_leaves_known_uri_schemes_and_prose_intact():
    """Follow-up to SEC-1: only credential-shaped bare userinfo is redacted."""
    from wpt.config import redact_text

    assert redact_text("mailto:user@example.com") == "mailto:user@example.com"
    assert redact_text("note:see@home") == "note:see@home"
    assert redact_text("user:hunter2@host") == "user:***@host"
    assert redact_text("user:pass@host") == "user:***@host"


def test_SEC_3_credential_login_labels_redact_short_values():
    """Follow-up to SEC-2: a login label wins over the prose length guard."""
    from wpt.config import redact_text

    for label in ("user", "username", "login", "admin", "root", "ftp",
                  "deploy"):
        assert redact_text(f"{label}:abc@host") == f"{label}:***@host"
    assert redact_text("ADMIN:abc@HOST") == "ADMIN:***@HOST"
    assert redact_text("note:see@home") == "note:see@home"
    assert redact_text("mailto:user@example.com") == "mailto:user@example.com"
    assert redact_text("user:hunter2@host") == "user:***@host"


def test_REDACT_BARE_USERINFO_is_linear_on_brace_heavy_lines():
    """REDACT: the old ``[^/\\s:@]+:`` label scanned a long run at every
    offset and backtracked, so 80k braces took 9.43 s (O(n²)) in the
    redaction choke point.  The linear scanner (and the no-``@`` pre-check)
    keeps that cost bounded without capping credential lengths, and the
    credential/prose decisions are unchanged."""
    import time

    from wpt.config import _redact_bare_userinfo_text, redact_text

    payload = "{" * 80000
    started = time.monotonic()
    assert redact_text(payload) == payload
    assert time.monotonic() - started < 0.2
    # Even the scan alone stays bounded when the line carries an '@'.
    started = time.monotonic()
    assert _redact_bare_userinfo_text(payload + "x@y") == payload + "x@y"
    assert time.monotonic() - started < 0.2
    # A long plausible-username run must not rescan itself at every offset.
    started = time.monotonic()
    assert _redact_bare_userinfo_text("a" * 80000 + "@") == "a" * 80000 + "@"
    assert time.monotonic() - started < 0.2

    for credential in ("user:hunter2@host", "user:abc@host"):
        assert redact_text(credential) == credential.replace(
            credential.split(":", 1)[1].split("@", 1)[0], "***")
    assert redact_text("note:see@home") == "note:see@home"
    assert redact_text("mailto:user@example.com") == "mailto:user@example.com"


def test_REDACT_BARE_USERINFO_has_no_credential_length_caps():
    """The bounded-run performance fix capped label/value/host and leaked
    every credential longer than the cap (65-char user, 1025-char password).
    The linear scanner keeps the plausible-username class with no caps."""
    from wpt.config import redact_text

    label = "u" * 65
    assert redact_text(f"{label}:hunter2@host") == f"{label}:***@host"

    password = "p" * 1025
    assert redact_text(f"user:{password}@host") == "user:***@host"
    assert redact_text(f"user:{password}{password}@host") == "user:***@host"

    host = "h" * 5000 + ".example"
    assert redact_text(f"user:hunter2@{host}") == f"user:***@{host}"

    # Ordinary prose and non-credentials keep their old treatment, including
    # when the label is longer than the old cap.
    intact = (
        "note:see@home",
        "mailto:user@example.com",
        "data:foo@host",
        "contact user@example.com for details",
        "note: see @ home",
        "meet@noon",
        "u" * 65 + ":see@home",
    )
    for text in intact:
        assert redact_text(text) == text


def test_LOG1_quoted_dict_credentials_are_redacted(tmp_path):
    """LOG1: Python/JSON reprs put a quote between key and colon, so the
    one redactor missed ``{'password': 'x'}`` / ``"password": "x"`` in
    messages, ``%s`` args and tracebacks."""
    from wpt.config import redact_text

    for text in ("{'password': 'DICTSEC'}",
                 '"password": "DICTSEC"',
                 '{"api_token": "DICTSEC"}',
                 "{'db_password': 'DICTSEC'}"):
        out = redact_text(text)
        assert "DICTSEC" not in out, text
        assert "***" in out

    logfile = tmp_path / "dict.log"
    logmod.setup_logging(level="debug", logfile=str(logfile))
    logmod.get_logger("test").info("dict=%s", {"password": "DICTSEC"})
    try:
        raise RuntimeError("bad row: " + str({"password": "TRACESECRET"}))
    except RuntimeError:
        logmod.get_logger("test").exception("failed")
    _flush_all()
    content = logfile.read_text(encoding="utf-8")
    assert "DICTSEC" not in content and "TRACESECRET" not in content

    json_file = tmp_path / "dict.json"
    logmod.setup_logging(level="debug", logfile=str(json_file),
                         json_mode=True)
    try:
        raise RuntimeError("bad row: " + str({"password": "TRACESECRET"}))
    except RuntimeError:
        logmod.get_logger("test").exception("failed")
    _flush_all()
    payload = json.loads(json_file.read_text(encoding="utf-8").strip())
    assert "TRACESECRET" not in payload["exc"]


def test_LOG1_escaped_quotes_inside_a_quoted_secret_are_fully_redacted():
    """N2: a non-greedy quoted-value match stopped at an escaped quote and
    leaked the suffix of the real secret."""
    from wpt.config import redact_text

    for text in ("{'password': 'ab\\'cd'}",
                 '{"password": "ab\\"cd"}',
                 "prefix {'api_token': 'ab\\'cd'} suffix"):
        out = redact_text(text)
        assert "ab" not in out and "cd" not in out, text
        assert "***" in out

    # Normal quoted/dict forms still redact, and a non-secret value is not
    # touched merely because it contains an escaped quote.
    assert redact_text("{'password': 'plain'}") == "{password=***}"
    assert redact_text('{"password": "plain"}') == "{password=***}"
    assert redact_text("password=plain") == "password=***"
    assert redact_text("{'other': 'ab\\'cd'}") == "{'other': 'ab\\'cd'}"
    assert redact_text('{"other": "ab\\"cd"}') == '{"other": "ab\\"cd"}'


def test_R15_camelcase_secret_keys_are_redacted_by_the_same_owner():
    """R15-P2: only underscore-separated key prefixes matched, so
    ``accessToken`` survived every face while ``redact({'accessToken':…})``
    already blanked it.  The key-shape owner accepts camelCase boundaries
    and still leaves ordinary words (``monkey``) alone."""
    from wpt.config import is_secret_key, redact_text

    assert is_secret_key("accessToken")
    assert is_secret_key("apiKey")
    assert is_secret_key("some_password")
    # R16 residual: an uppercase acronym run ending in a capitalised word,
    # hyphenated header names, and a lowercase compound secret tail.
    assert is_secret_key("APIKey")
    assert is_secret_key("DBPassword")
    assert is_secret_key("X-Api-Key")
    assert is_secret_key("clientsecret")
    # R17: ordinary all-lowercase/all-caps compounds (no boundary character)
    # and the hyphen/dot serialized spellings.
    for key in ("apikey", "APIKEY", "dbpassword", "DBPASSWORD",
                "userpassword", "adminpassword", "privatekey", "accesskey",
                "signingkey", "clientkey", "x-api-key", "x.api.token"):
        assert is_secret_key(key), key
    assert not is_secret_key("monkey")
    for text in (
        "accessToken=HUNTER2",
        '{"accessToken":"HUNTER2"}',
        "'accessToken': 'HUNTER2'",
        '{"x-api-key":"HUNTER2"}',
        "{'x-api-key': 'HUNTER2'}",
        '{"x.api.token": "HUNTER2"}',
        '{"API-KEY": "HUNTER2"}',
        '{"apikey": "HUNTER2"}',
        '{"dbpassword": "HUNTER2"}',
        's:11:"accessToken";s:7:"HUNTER2";',
        "APIKey=HUNTER2",
        "DBPassword=HUNTER2",
        "X-Api-Key: HUNTER2",
        "clientsecret=HUNTER2",
        "apikey=HUNTER2",
        "APIKEY=HUNTER2",
        "dbpassword=HUNTER2",
        "DBPASSWORD=HUNTER2",
        's:9:"x-api-key";s:7:"HUNTER2";',
        's:11:"x.api.token";s:7:"HUNTER2";',
    ):
        out = redact_text(text)
        assert "HUNTER2" not in out, (text, out)
        assert "***" in out, (text, out)
    assert redact_text("monkey=banana") == "monkey=banana"
    assert redact_text("some_monkey=banana") == "some_monkey=banana"

    # The LOG payload walker uses the SAME owner (not a second regex) for
    # its key context.
    from wpt.log import _redact_extra_value

    assert _redact_extra_value("HUNTER2", "accessToken") == "***"
    assert _redact_extra_value("HUNTER2", "APIKey") == "***"
    assert _redact_extra_value("HUNTER2", "DBPassword") == "***"
    assert _redact_extra_value("HUNTER2", "X-Api-Key") == "***"
    assert _redact_extra_value("banana", "monkey") == "banana"

    from wpt.config import redact

    for key in ("APIKey", "DBPassword", "X-Api-Key", "clientsecret",
                "apikey", "APIKEY", "dbpassword", "DBPASSWORD"):
        assert redact({key: "HUNTER2"})[key] == "***", key


def test_R18_quoted_compound_secret_keys_are_redacted_through_the_log_sink(
        tmp_path):
    """R18-P2: ``redact_text`` matched only identifier-shaped keys, so a
    JSON payload ``{"x-api-key":"HUNTER2"}`` reached the log verbatim.  The
    assignment owner now accepts ``-``/``.`` inside a quoted key too."""
    import wpt.log as logmod

    logfile = tmp_path / "pipeline.log"
    logmod.setup_logging(level="info", logfile=str(logfile), console=False)
    logger = logmod.get_logger("r18")
    logger.info("payload", extra={"blob": '{"x-api-key":"HUNTER2"}'})
    logger.info("payload", extra={"blob": '{"x.api.token":"HUNTER3"}'})
    logger.info("payload", extra={"blob": '{"dbpassword":"HUNTER4"}'})
    text = logfile.read_text(encoding="utf-8")
    for secret in ("HUNTER2", "HUNTER3", "HUNTER4"):
        assert secret not in text, (secret, text)
    assert "***" in text


def test_R16_php_containers_skip_comments_and_understand_set_state():
    """R16-P2: a ``}`` in a PHP comment ended an array() value early and
    leaked the secret; var_export's ``Class::__set_state(array(...))`` was
    not recognized as a container at all."""
    from wpt.config import redact_text

    cases = (
        "password=array(/* } */ 'HUNTER2')",
        "password=array( // } comment\n 'HUNTER2')",
        "password=Some\\Class::__set_state(array( 'x' => 'HUNTER2' ))",
        "password=(object) array(/* ] */ 'HUNTER2')",
    )
    for text in cases:
        out = redact_text(text)
        assert "HUNTER2" not in out, (text, out)
        assert "***" in out, (text, out)


def test_LOG2_nested_extras_are_key_aware_and_json_safe(tmp_path):
    """LOG2: nested mapping credentials leaked, a secret in a mapping KEY
    leaked, and a set/bytes extra made ``json.dumps`` lose the record."""
    human = tmp_path / "nested.log"
    logmod.setup_logging(level="debug", logfile=str(human))
    logmod.get_logger("test").info(
        "context", extra={
            "context": {"password": "NESTSECRET",
                        "a": {"b": [{"api_token": "DEEPSECRET"}]}},
            "blob": {"password: hunter2": "visible"},
            "binary": b"password=BYTESECRET",
        })
    _flush_all()
    content = human.read_text(encoding="utf-8")
    assert "NESTSECRET" not in content
    assert "DEEPSECRET" not in content
    assert "hunter2" not in content
    assert "BYTESECRET" not in content

    json_file = tmp_path / "nested.json"
    logmod.setup_logging(level="debug", logfile=str(json_file),
                         json_mode=True)
    logmod.get_logger("test").info(
        "set-extra", extra={"values": {"PWSECRET"},
                            "blob": {1: b"password=BYSECRET"}})
    _flush_all()
    payload = json.loads(json_file.read_text(encoding="utf-8").strip())
    assert payload["values"] == ["PWSECRET"]
    assert "BYSECRET" not in json.dumps(payload)


def test_LOG3_canonical_json_fields_win_over_user_extras(tmp_path):
    """LOG3: extras named ``logger``/``time``/``level``/``exc`` overwrote
    the record's own identity."""
    logfile = tmp_path / "canonical.json"
    logmod.setup_logging(level="info", logfile=str(logfile), json_mode=True)
    logmod.get_logger("test").info(
        "real message",
        extra={"logger": "SPOOFED", "time": "1999-01-01",
               "level": "CRITICAL", "exc": "FORGED TRACEBACK"})
    _flush_all()
    payload = json.loads(logfile.read_text(encoding="utf-8").strip())
    assert payload["logger"] == "wpt.test"
    assert payload["level"] == "INFO"
    assert payload["time"] != "1999-01-01"
    assert "FORGED TRACEBACK" not in payload.get("exc", "")


def test_LOG_FILE_SURROGATE_keeps_the_run_start_line(tmp_path, capsys):
    """LOG-FILE-SURROGATE: FileHandler encoded strictly, so a surrogate in
    the run-start site value raised inside logging (stderr "--- Logging
    error ---") and the first line was lost from the file."""
    logfile = tmp_path / "wpt.log"
    logmod.setup_logging(level="info", logfile=str(logfile), console=False)
    logmod.get_logger("test").info(
        "wpt logs starting: site=%s", "https://\udcff.example")
    for handler in logging.getLogger("wpt").handlers:
        handler.flush()
    captured = capsys.readouterr()
    assert "Logging error" not in captured.err
    assert "UnicodeEncodeError" not in captured.err
    content = logfile.read_text(encoding="utf-8")
    assert "wpt logs starting" in content
    assert "\\udcff" in content


def test_REDACT_CONTAINER_complete_balanced_values_are_redacted(tmp_path):
    """REDACT-CONTAINER: the bare-value alternative stopped at the first
    quote/comma/brace, leaking bytes, lists and nested dicts; a mapping-arg
    log call lost the key context entirely."""
    from wpt.config import redact_text

    cases = [
        ("{'password': b'hunter2'}", "{password=***}"),
        ("{'tokens': ['aaa','bbb']}", "{tokens=***}"),
        ("{'password': {'value':'deepsecret'}}", "{password=***}"),
        ("{'password': {'outer': ['a', {'b': 'c'}]}}", "{password=***}"),
        ("{'password': 'ab\\'cd'}", "{password=***}"),
        ('{"password": "ab\\"cd"}', "{password=***}"),
        ("password=%s" % "hunter2", "password=***"),
        ("token: abc command issued", "token=*** command issued"),
    ]
    for text, expected in cases:
        assert redact_text(text) == expected, text
        assert "hunter2" not in redact_text(text)
    # No over-redaction of a benign container/text.
    assert redact_text("{'other': ['aaa','bbb']}") == \
        "{'other': ['aaa','bbb']}"
    assert redact_text("monkey=banana") == "monkey=banana"

    logfile = tmp_path / "redact.log"
    logmod.setup_logging(level="info", logfile=str(logfile), console=False)
    logmod.get_logger("test").info(
        "%(password)s %(detail)s",
        {"password": "hunter2", "detail": "kept"})
    for handler in logging.getLogger("wpt").handlers:
        handler.flush()
    content = logfile.read_text(encoding="utf-8")
    assert "hunter2" not in content
    assert "kept" in content


def test_URL_USERINFO_a_password_with_an_at_sign_is_fully_redacted():
    """P2-URL-USERINFO: `[^/\\s@]+` stopped at the first `@`, leaking the
    rest of `ftp://user:p@ss@host` as if it were the host."""
    from wpt.config import redact_text

    assert redact_text("ftp://user:p@ss@host") == "ftp://user:***@host"
    assert redact_text("https://u:sec@ret@host/path") == (
        "https://u:***@host/path")


def test_REDACT_NESTED_an_inner_match_never_reemits_a_consumed_tail():
    """P2-REDACT-NESTED: finditer returned secret keys INSIDE a value the
    outer key had already consumed whole; the loop re-emitted the tail."""
    from wpt.config import redact_text

    assert redact_text("password='password=a hunter2'") == "password=***"
    assert redact_text(
        "password={'password': 'a', 'value': 'deepsecret'}") == "password=***"
    assert "hunter2" not in redact_text(
        "password='password=a hunter2'")
    assert "deepsecret" not in redact_text(
        "password={'password': 'a', 'value': 'deepsecret'}")


# ------------------------------------------------------- triple-check round 6


def test_R6_03_userinfo_after_slash_or_at_is_redacted_everywhere(tmp_path):
    """R6-03: ``/`` and ``@`` are delimiters, not word characters.  The old
    forbidden-prev set advanced past the label's own letters and returned no
    span, so ``ftp:/user:SECRET@host`` reached the logs failure report."""
    from wpt.config import redact_text
    from wpt.cli import Ctx
    from wpt.settings import load
    import wpt.logs as logs_mod

    for raw in ("ftp:/user:SECRET@host",
                "https:/user:SECRET@host",
                "@user:SECRET@host",
                "user:SECRET@host"):
        out = redact_text(raw)
        assert "SECRET" not in out, (raw, out)
        assert "***" in out

    ctx = Ctx(source="ftp:/user:SECRET@host", settings=load(),
              command="logs", webroot="public_html",
              backup_dir=tmp_path / "bk",
              report_path=tmp_path / "logs.md")
    logs_mod._write_failure(ctx, "boom")
    twin = (tmp_path / "logs.json").read_text("utf-8")
    assert "SECRET" not in twin
    assert "***" in twin


def test_R6_04_quiet_without_a_file_has_a_null_sink_not_last_resort(capsys):
    """R6-04: no console + no log file left NO handler, so lastResort wrote
    WARNING+ to stderr with no RedactingFilter.  A NullHandler keeps quiet
    truly quiet, and the logger-level filter is still present."""
    logmod.setup_logging(level="error", console=False)
    parent = logging.getLogger("wpt")
    assert any(isinstance(handler, logging.NullHandler)
               for handler in parent.handlers)
    assert any(isinstance(f, logmod.RedactingFilter) for f in parent.filters)
    logmod.get_logger("test").error("ftp://user:QUIET@host")
    for handler in parent.handlers:
        handler.flush()
    assert capsys.readouterr().err == ""


def test_R6_33_bare_credential_value_runs_to_whitespace():
    """R6-33: the bare branch stopped at ``, ] } ' "`` and leaked the rest
    of the value into logs."""
    from wpt.config import redact_text

    assert redact_text("password=abc,def") == "password=***"
    assert redact_text("token=abc]def") == "token=***"
    assert redact_text("secret=abc}def") == "secret=***"
    logfile = None
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        logfile = Path(tmp) / "w.log"
        logmod.setup_logging(level="info", logfile=str(logfile),
                             console=False)
        logmod.get_logger("test").info("password=%s", "abc,def")
        for handler in logging.getLogger("wpt").handlers:
            handler.flush()
        content = logfile.read_text(encoding="utf-8")
    assert "def" not in content
    assert "***" in content


# ------------------------------------------------- triple-check round 7


def test_R7_P2_13_url_userinfo_with_empty_username_is_redacted():
    from wpt.config import redact_text

    assert redact_text("ftp://:URLSECRET@example.com") == \
        "ftp://:***@example.com"
    assert "URLSECRET" not in redact_text(
        "source ftp://:URLSECRET@example.com refused")
    assert redact_text("ftp://user:URLSECRET@example.com") == \
        "ftp://user:***@example.com"


def test_R7_RESIDUAL_url_userinfo_is_bounded_to_the_authority():
    """The URL userinfo scan ran past the authority: a port plus a query
    ``@`` turned ``example.com:8443?email=a@b`` into
    ``example.com:***@b``, and a real credential lost its query tail the
    same way.  ``/``, ``?`` and ``#`` end the authority; only a credential
    before the last authority ``@`` may be redacted."""
    from wpt.config import redact_text

    # No-over-redaction: the '@' is in the query/path, never in userinfo.
    for benign in (
        "https://example.com:8443?email=a@b",
        "https://example.com?email=a@b",
        "https://example.com/path/a@b",
        "https://example.com/path?email=a@b",
        "https://example.com/?email=a@b#top",
        "mailto:user@example.com",
        "note:see@home",
    ):
        assert redact_text(benign) == benign, benign

    # Real userinfo stays redacted, bounded to the authority.
    assert redact_text("https://user:pass@example.com?email=a@b") == \
        "https://user:***@example.com?email=a@b"
    assert redact_text(
        "https://user:pass@example.com:8443/path?email=a@b") == \
        "https://user:***@example.com:8443/path?email=a@b"
    assert redact_text("https://user:p@ss@example.com/path") == \
        "https://user:***@example.com/path"
    assert redact_text("ftp://:URLSECRET@example.com?x=1") == \
        "ftp://:***@example.com?x=1"
    for leaked, raw in (
        ("pass", "https://user:pass@example.com?email=a@b"),
        ("URLSECRET", "ftp://:URLSECRET@example.com?x=1"),
    ):
        assert leaked not in redact_text(raw), raw


def test_R7_RESIDUAL_scheme_relative_empty_user_userinfo_is_redacted_everywhere(
        tmp_path):
    """R7 residual: ``//:URLSECRET@host`` is a network-path reference with an
    empty username; requiring ``://`` let it through the URL redactor, the
    bare-label guard, the report scrubber, the discover title and both log
    sinks."""
    from wpt.cli import Ctx
    from wpt.config import redact_text
    from wpt.report import _scrub
    from wpt.settings import load
    import wpt.discover as discover_mod

    raw = "//:URLSECRET@example.com"
    assert redact_text(raw) == "//:***@example.com"
    assert redact_text(f"source {raw} refused") == \
        "source //:***@example.com refused"
    assert "URLSECRET" not in redact_text(f"source {raw} refused")

    scrubbed = _scrub({"source": raw, "detail": f"source {raw} refused"})
    assert scrubbed["source"] == "//:***@example.com"
    assert "URLSECRET" not in repr(scrubbed)

    ctx = Ctx(source=raw, settings=load(), command="discover",
              webroot="public_html", backup_dir=tmp_path / "bk",
              report_path=tmp_path / "discover.md")
    assert "URLSECRET" not in discover_mod.safe_source_label(ctx.source)
    assert "URLSECRET" not in discover_mod._markdown(ctx, []).splitlines()[0]

    logfile = tmp_path / "human.log"
    logmod.setup_logging(level="info", logfile=str(logfile))
    logmod.get_logger("test").info("source %s", raw)
    for handler in logging.getLogger("wpt").handlers:
        handler.flush()
    human = logfile.read_text(encoding="utf-8")
    assert "URLSECRET" not in human
    assert "//:***@example.com" in human

    logfile2 = tmp_path / "json.log"
    logmod.setup_logging(level="info", logfile=str(logfile2), json_mode=True)
    logmod.get_logger("test").info("source %s", raw)
    for handler in logging.getLogger("wpt").handlers:
        handler.flush()
    raw_json = logfile2.read_text(encoding="utf-8")
    assert "URLSECRET" not in raw_json
    payload = json.loads(raw_json.strip().splitlines()[-1])
    assert "//:***@example.com" in payload["msg"]


def test_R7_P2_14_redact_masks_nested_container_and_bytes_secrets():
    from wpt.config import redact

    assert redact({"password": {"value": "SECRET"}}) == {"password": "***"}
    assert redact({"password": ["SECRET"]}) == {"password": "***"}
    assert redact({"password": b"SECRET"}) == {"password": "***"}
    assert redact({"nested": {"password": "SECRET"}}) == {
        "nested": {"password": "***"}}


def test_R7_P2_15_secret_bearing_extra_key_is_redacted_in_both_sinks(
        tmp_path):
    logfile = tmp_path / "human.log"
    logmod.setup_logging(level="info", logfile=str(logfile))
    logmod.get_logger("test").info(
        "payload", extra={"password=KEYHUNTER2": "visible"})
    for handler in logging.getLogger("wpt").handlers:
        handler.flush()
    human = logfile.read_text(encoding="utf-8")
    assert "KEYHUNTER2" not in human
    assert "password=***=***" in human

    logfile2 = tmp_path / "json.log"
    logmod.setup_logging(level="info", logfile=str(logfile2),
                         json_mode=True)
    logmod.get_logger("test").info(
        "payload", extra={"password=KEYHUNTER2": "visible"})
    for handler in logging.getLogger("wpt").handlers:
        handler.flush()
    raw = logfile2.read_text(encoding="utf-8")
    assert "KEYHUNTER2" not in raw
    payload = json.loads(raw.strip().splitlines()[-1])
    assert payload["password=***"] == "***"


def test_R7_P2_16_malformed_percent_call_never_embeds_argument_values(
        tmp_path):
    logfile = tmp_path / "human.log"
    logmod.setup_logging(level="info", logfile=str(logfile))
    logmod.get_logger("test").info("password=%s", "HUNTER2", "extra")
    for handler in logging.getLogger("wpt").handlers:
        handler.flush()
    human = logfile.read_text(encoding="utf-8")
    assert "HUNTER2" not in human
    assert "logging format error" in human

    logfile2 = tmp_path / "json.log"
    logmod.setup_logging(level="info", logfile=str(logfile2),
                         json_mode=True)
    logmod.get_logger("test").info("password=%s", "HUNTER2", "extra")
    for handler in logging.getLogger("wpt").handlers:
        handler.flush()
    raw = logfile2.read_text(encoding="utf-8")
    assert "HUNTER2" not in raw


# ------------------------------------------------------- round-8 regressions


def test_R8_P2_18_non_dict_mapping_arguments_are_key_aware(tmp_path):
    """R8-P2-18: the filter checked only ``dict``, so MappingProxyType and
    UserDict rendered a ``%(password)s`` argument verbatim."""
    from collections import UserDict
    from types import MappingProxyType

    for name, mapping in (("proxy", MappingProxyType({"password": "HUNTER2"})),
                          ("userdict", UserDict({"password": "HUNTER2"}))):
        human = tmp_path / f"{name}.log"
        logmod.setup_logging(level="debug", logfile=str(human))
        logmod.get_logger("test").info("%(password)s", mapping)
        _flush_all()
        content = human.read_text(encoding="utf-8")
        assert "HUNTER2" not in content, name
        assert "***" in content, name

        json_file = tmp_path / f"{name}.json"
        logmod.setup_logging(level="debug", logfile=str(json_file),
                             json_mode=True)
        logmod.get_logger("test").info("%(password)s", mapping)
        _flush_all()
        payload = json.loads(json_file.read_text(encoding="utf-8").strip())
        assert "HUNTER2" not in json.dumps(payload), name


def test_R8_P2_19_opaque_extra_values_are_redacted(tmp_path):
    """R8-P2-19: an exception (or any opaque object) in ``extra`` was
    stringified by the formatter after the filter, so its credential
    survived in both sinks; nested lists leaked too."""
    human = tmp_path / "opaque.log"
    logmod.setup_logging(level="debug", logfile=str(human))
    logmod.get_logger("test").info(
        "failed", extra={"error": ValueError("password=HUNTER2"),
                         "nested": [ValueError("token=TOPSECRET")]})
    _flush_all()
    content = human.read_text(encoding="utf-8")
    assert "HUNTER2" not in content and "TOPSECRET" not in content

    json_file = tmp_path / "opaque.json"
    logmod.setup_logging(level="debug", logfile=str(json_file),
                         json_mode=True)
    logmod.get_logger("test").info(
        "failed", extra={"error": ValueError("password=HUNTER2"),
                         "nested": [ValueError("token=TOPSECRET")]})
    _flush_all()
    payload = json.loads(json_file.read_text(encoding="utf-8").strip())
    assert "HUNTER2" not in json.dumps(payload)
    assert "TOPSECRET" not in json.dumps(payload)


def test_R11_serialized_secret_length_and_cast_depth_are_bounded(tmp_path):
    """R11-P2-1/P2-11: a serialized value is N bytes (an embedded ``";``
    is data, not the terminator), and a cast chain is consumed iteratively
    instead of recursing to RecursionError."""
    from wpt.config import redact_text

    leaks = [
        's:8:"password";s:15:"abc";SUFFIXLEAK";',
        's:8:"password";s:16:"abc\\";SUFFIXLEAK";',
    ]
    for blob in leaks:
        out = redact_text(blob)
        assert "SUFFIXLEAK" not in out, out
        assert "***" in out, out

    deep = "password=" + "(object)" * 500 + "['HUNTER2']"
    assert "HUNTER2" not in redact_text(deep)
    assert "***" in redact_text(deep)

    logfile = tmp_path / "deep.log"
    logmod.setup_logging(level="debug", logfile=str(logfile))
    logmod.get_logger("test").error("row: %s", leaks[0])
    logmod.get_logger("test").error("deep: %s", deep)
    _flush_all()
    content = logfile.read_text(encoding="utf-8")
    assert "SUFFIXLEAK" not in content and "HUNTER2" not in content


def test_R8_P2_20_php_arrow_and_define_credentials_are_redacted(tmp_path):
    """R8-P2-20: the one scanner accepted only ``:``/``=``, so PHP's
    ``'password' => 'x'`` and ``define('DB_PASSWORD', 'x')`` reached logs
    and reports verbatim."""
    from wpt.config import redact_text

    for text in ("'password' => 'HUNTER2'",
                 "define('DB_PASSWORD', 'HUNTER2')",
                 "array('api_key' => 'HUNTER2')",
                 "$cfg['db_password'] = 'HUNTER2'"):
        out = redact_text(text)
        assert "HUNTER2" not in out, text
        assert "***" in out, text

    # C7: the value after a secret key is not always a quoted scalar.  A
    # container/constructor/heredoc value used to be cut at its first space,
    # leaving the credential inside the remainder of the line.
    from wpt.config import redact_text

    for text in (
        "'api_secret' => array('client' => 'HUNTER2', 'n' => 1)",
        "'api_secret' => (object)['client' => 'HUNTER2']",
        "'api_secret' => new Secret('HUNTER2')",
        "'api_secret' => <<<TXT\nHUNTER2\nTXT",
        's:8:"password";s:7:"HUNTER2";',
    ):
        out = redact_text(text)
        assert "HUNTER2" not in out, text
        assert "***" in out, text

    human = tmp_path / "php.log"
    logmod.setup_logging(level="debug", logfile=str(human))
    logmod.get_logger("test").info(
        "config row: 'password' => 'HUNTER2' and "
        "define('DB_PASSWORD', 'TOPSECRET')")
    _flush_all()
    content = human.read_text(encoding="utf-8")
    assert "HUNTER2" not in content and "TOPSECRET" not in content
    assert "***" in content


# ------------------------------------------------ round 12 (P2 regressions)


def test_R12_php_type_wrappers_visibility_and_serialized_keys_are_redacted(
        tmp_path):
    """R12-P2-9: var_dump wrappers (string(6) "…"), print_r visibility
    tokens ([password:protected] => …), JSON-quoted keys, and serialized
    private/protected/underscored keys all leaked the value."""
    from wpt.config import redact_text

    leaks = [
        'password: string(6) "hunter2"',
        '[password:protected] => hunter2',
        '["password"]=> string(6) "hunter2"',
        's:11:"\x00*\x00password";s:7:"hunter2";',
        's:9:"_password";s:7:"hunter2";',
    ]
    for text in leaks:
        out = redact_text(text)
        assert "hunter2" not in out, (text, out)
        assert "***" in out, (text, out)

    human = tmp_path / "wrapped.log"
    json_file = tmp_path / "wrapped.json"
    logmod.setup_logging(level="debug", logfile=str(human))
    logmod.setup_logging(level="debug", logfile=str(json_file),
                         json_mode=True)
    logmod.get_logger("test").error("row: %s", leaks[1])
    logmod.get_logger("test").error("row: %s", leaks[0])
    _flush_all()
    assert "hunter2" not in human.read_text(encoding="utf-8")
    assert "hunter2" not in json_file.read_text(encoding="utf-8")


def test_R12_serialized_byte_lengths_and_huge_or_truncated_values_fail_closed(
        tmp_path):
    """R12-P2-13: PHP lengths are BYTES; character offsets landed past the
    terminator for non-ASCII values and leaked the tail, while a huge or
    truncated declared length used a quote fallback that also leaked."""
    from wpt.config import redact_text

    leaks = [
        's:8:"password";s:11:"abc";LEAKé";',       # 11 bytes, 10 chars
        's:8:"password";s:15:"päss";LEAKTAIL";',    # 15 bytes, 14 chars
        's:8:"password";s:999999999:"PREFIXLEAK";',  # declared > remaining
        's:8:"password";s:20:"abc',                  # truncated
    ]
    for text in leaks:
        out = redact_text(text)
        assert "LEAK" not in out, (text, out)
        assert "***" in out, (text, out)

    human = tmp_path / "bytes.log"
    logmod.setup_logging(level="debug", logfile=str(human))
    for text in leaks:
        logmod.get_logger("test").error("row: %s", text)
    _flush_all()
    content = human.read_text(encoding="utf-8")
    assert "LEAK" not in content and "é\";" not in content


def test_R13_namespaced_serialized_private_keys_are_redacted(tmp_path):
    """R13-P2-17: the serialized-key class segment allowed only bare
    identifiers, so a namespaced private key
    (``\\x00App\\\\Models\\\\User\\x00password``) survived redaction in both
    NUL spellings and reached logs/reports intact."""
    from wpt.config import redact_text

    leaks = [
        's:25:"\x00App\\Models\\User\x00password";s:7:"hunter2";',
        's:27:"\\0App\\Models\\User\\0password";s:7:"hunter2";',
    ]
    for text in leaks:
        out = redact_text(text)
        assert "hunter2" not in out, (text, out)
        assert "***" in out, (text, out)

    human = tmp_path / "namespaced.log"
    json_file = tmp_path / "namespaced.json"
    logmod.setup_logging(level="debug", logfile=str(human))
    logmod.setup_logging(level="debug", logfile=str(json_file),
                         json_mode=True)
    logmod.get_logger("test").error("PHP Fatal: %s", leaks[0])
    logmod.get_logger("test").error("PHP Fatal: %s", leaks[1])
    _flush_all()
    assert "hunter2" not in human.read_text(encoding="utf-8")
    assert "hunter2" not in json_file.read_text(encoding="utf-8")


def test_R14_serialized_containers_under_a_secret_key_are_redacted():
    """R14-P2: only a following ``s:<len>:"value"`` was consumed, so a
    serialized ARRAY/OBJECT under ``token``/``password`` leaked every
    member.  Both container forms are consumed whole and replaced."""
    from wpt.config import redact_text

    array = ('PHP Fatal: s:5:"token";a:1:{s:5:"value";s:7:"hunter2";}')
    obj = ('PHP Fatal: s:8:"password";O:8:"stdClass":1:'
           '{s:5:"value";s:7:"hunter2";}')
    truncated = 'PHP Fatal: s:5:"token";a:1:{s:5:"value";s:7:"hunter2"'
    for text in (array, obj, truncated):
        out = redact_text(text)
        assert "hunter2" not in out, out
        assert 's:5:"token"' in out or 's:8:"password"' in out


def test_R21_json_escaped_payloads_redact_through_every_sink():
    """R21-P2: a JSON string INSIDE a JSON log line spells the whole inner
    object with ``\\"`` delimiters.  The assignment scanner only accepted a
    bare quote, so the nested password reached the log/report verbatim;
    escaped serialized options leaked the same way."""
    from wpt.config import redact_text

    cases = (
        '{"request_body":"{\\"password\\":\\"HUNTER2\\"}"}',
        '{\\"password\\":\\"HUNTER2\\"}',
        'a:1:{s:8:\\"password\\";s:7:\\"HUNTER2\\";}',
        '{\\"x-api-key\\":\\"HUNTER2\\"}',
    )
    for text in cases:
        out = redact_text(text)
        assert "HUNTER2" not in out, text
    # the inert word stays untouched (the key-shape owner still decides)
    assert redact_text('{\\"monkey\\":\\"banana\\"}') == \
        '{\\"monkey\\":\\"banana\\"}'


def test_R21_php_comments_before_a_secret_value_are_whitespace():
    """R21-P2: ``'password' => /* keep */ 'HUNTER2'`` stopped the value
    scanner at ``/`` and leaked the credential.  A comment (block or line)
    before the value and between type wrappers is PHP whitespace."""
    from wpt.config import redact_text

    cases = (
        "'password' => /* keep */ 'HUNTER2'",
        "password=/*c*/ 'HUNTER2'",
        "password=//c\n'HUNTER2'",
        "password=#c\n'HUNTER2'",
        "define('DB_PASSWORD', /*c*/ 'HUNTER2')",
        "'password' => /*c*/ array('client' => 'HUNTER2')",
        "password: string(7) /*c*/ 'HUNTER2'",
    )
    for text in cases:
        out = redact_text(text)
        assert "HUNTER2" not in out, text


def test_R22_php_comment_between_key_and_operator_is_whitespace():
    """R22-P2: ``['password' /*c*/ => 'HUNTER2']`` executes in PHP, but the
    key regex allowed only spaces between the key and ``=>``, so the value
    reached the log/report.  Block/line comments are the same whitespace on
    the KEY side as on the value side."""
    from wpt.config import redact_text

    cases = (
        "['password' /*c*/ => 'HUNTER2']",
        "'db_password' /*c*/ => array('x' => 'HUNTER2')",
        "define('DB_PASSWORD' /*c*/, 'HUNTER2')",
        "'password' // c\n => 'HUNTER2'",
        "'password' # c\n => 'HUNTER2'",
        "['password' /*c*/ => ['nested' => 'HUNTER2']]",
    )
    for text in cases:
        out = redact_text(text)
        assert "HUNTER2" not in out, (text, out)


def test_R23_literal_lone_surrogate_never_escapes_any_redaction_sink(
        tmp_path):
    """R23-P1: the R22 guard covered only the JSON-ESCAPED serialized branch.
    A literal lone surrogate (``json.loads('"\\ud83d"')``, exactly what
    response.json() gives for a malformed bridge/probe answer) still reached
    the unescaped ``s:`` and ``C:`` encodes and raised UnicodeEncodeError out
    of redact_text, render_report/render_json and the mandatory log filter.
    Every branch now fails closed and every sink writes."""
    import json

    from wpt.config import redact_text
    from wpt.report import (AuditReport, render_json, render_report,
                            write_report_files)

    texts = [
        # the verifier's exact reproducer (unescaped s: payload)
        json.loads('"a:1:{s:8:\\"password\\";s:3:\\"\\ud83d\\";}"'),
        # C: custom object with surrogate bytes in its data section
        json.loads('"a:1:{s:8:\\"password\\";C:3:\\"Foo\\":2:'
                   '{\\ud83d\\ud83d};}"'),
        # O: object whose nested string value carries the surrogate
        json.loads('"a:1:{s:8:\\"password\\";O:3:\\"Foo\\":1:'
                   '{s:1:\\"a\\";s:1:\\"\\ud83d\\";}}"'),
    ]
    for text in texts:
        out = redact_text(text)
        assert out.encode("utf-8")  # never raises
        assert "\\ud83d" not in out
        report = AuditReport(site="https://x", source_summary=text,
                             findings=[])
        rendered = render_report(report)
        assert rendered.encode("utf-8")
        assert render_json(report).encode("utf-8")
        path = tmp_path / "literal-surrogate.md"
        write_report_files(path, rendered, render_json(report))
        assert path.is_file()

    human = tmp_path / "literal-surrogate.log"
    logmod.setup_logging(level="debug", logfile=str(human))
    for text in texts:
        logmod.get_logger("test").error("row: %s", text)
    _flush_all()
    human.read_text(encoding="utf-8").encode("utf-8")


@pytest.mark.parametrize("text", [
    '["\\160assword" => "HUNTER2"]',
    "['\\160assword' => 'HUNTER2']",
    '["\\u{70}assword" => "HUNTER2"]',
    "['\\u{70}assword' => array('x' => 'HUNTER2')]",
    '"\\141pi_key" => "HUNTER2"',
    '"\\u{61}pi_key" => "HUNTER2"',
])
def test_R23_octal_and_brace_escaped_secret_keys_are_redacted(text):
    """R23-P2: PHP evaluates ``\\160assword`` and ``\\u{70}assword`` as
    ``password``, but the key grammar/decoder knew only ``\\xNN``/``\\uXXXX``
    so the secret leaked verbatim into logs/reports.  ONE shared escape
    grammar drives both the regex and the decoder."""
    from wpt.config import redact_text

    out = redact_text(text)
    assert "HUNTER2" not in out, (text, out)
    # ordinary words containing "key" stay inert
    assert redact_text("monkey=banana") == "monkey=banana"


def test_R22_escaped_surrogate_never_crashes_redaction_or_a_log_sink(
        tmp_path):
    """R22-P1: a JSON-escaped serialized string containing a surrogate pair
    made ``chr(codepoint).encode('utf-8')`` raise UnicodeEncodeError out of
    ``redact_text`` — through the mandatory log filter and the report
    writer.  A lone/paired surrogate now fails CLOSED (redact to end) and
    the sinks still write."""
    import json

    from wpt.config import redact_text
    from wpt.report import AuditReport, render_report, write_report_files

    payload = r's:8:\"password\";s:6:\"\ud83d\ude00\";'
    lone = r's:8:\"password\";s:6:\"\ud83d\";'
    for text in (payload, lone):
        out = redact_text(text)
        assert "password" in out
        assert "\\ud83d" not in out
        rendered = render_report(AuditReport(
            site="https://x", source_summary=text, findings=[]))
        assert "password" in rendered
        report = tmp_path / "surrogate-report.md"
        write_report_files(report, rendered, "{}")
        assert report.is_file()

    human = tmp_path / "surrogate.log"
    logmod.setup_logging(level="debug", logfile=str(human))
    for text in (payload, lone):
        logmod.get_logger("test").error("row: %s", text)
    _flush_all()
    assert "password" in human.read_text(encoding="utf-8")

    json_file = tmp_path / "surrogate.json"
    logmod.setup_logging(level="debug", logfile=str(json_file),
                         json_mode=True)
    for text in (payload, lone):
        logmod.get_logger("test").error("row: %s", text)
    _flush_all()
    assert json.loads(json_file.read_text(encoding="utf-8").splitlines()[-1])


def test_R24_bare_cr_php_comment_is_trivia_for_secret_keys():
    """R24-P1: PHP accepts a bare CR as a line end.  ``_PHP_KEY_TRIVIA`` only
    knew CRLF/LF, so ``["password" // c\\r => "HUNTER2"]`` read as a comment
    that had not ended and the value survived every redaction sink."""
    from wpt.config import redact_text

    for text in (
        '["password" // c\r => "HUNTER2"]',
        '["password" # c\r => "HUNTER2"]',
        '["password" // c\r=>"HUNTER2"]',
    ):
        out = redact_text(text)
        assert "HUNTER2" not in out, out
        assert "***" in out


def test_R24_serialized_scalar_at_a_nonzero_offset_keeps_the_tail():
    """R24-P2: ``_serialized_value_end`` tested ``text[:2]`` instead of the
    slice at ``index``, so a scalar after a leading ``i:0;`` was not
    recognized and the rest of the message was dropped."""
    from wpt.config import redact_text

    text = 'a:1:{s:8:"password";i:0;s:4:"keep";s:4:"DATA";}'
    out = redact_text(text)
    assert "keep" in out and "DATA" in out, out
    nested = 'i:0;s:8:"password";a:1:{s:1:"x";s:6:"TOPSECRET";}'
    out = redact_text(nested)
    assert "TOPSECRET" not in out
    assert "***" in out
