"""The BINDING DOCS as derived facts, checked against their owners.

`SPEC.md` and `README.md` are binding and are read by every contributor, so
a claim in them is a promise.  The claims that are DERIVED — the settings
listing, the command table, the global-flag surface, the junk-pattern list —
have exactly one owner in the tree, and this file checks the doc against
that owner rather than trusting the doc.  Nothing here asserts prose: the
source of truth is always the shipped profile, the actions registry, the
audit registry, a settings dataclass or `wpt.cli`'s parser, never SPEC's own
text.

DOC-INTERNAL assertions (shape only) are marked as such below.  A table is
compared to its OWN HEADER, never to another part of the document; there is
no code twin for a lesson id, a residual id or a prose sentence, so the only
mechanical claim available is that a table is uniform, and that is what is
asserted.

DELIBERATELY NOT ASSERTED (considered and rejected — do not re-add):

* `format_usage()` compared to the usage block.  argparse's wrapping,
  indentation and metavar casing are implementation details that change
  without any behaviour change.  The block is checked for SET MEMBERSHIP of
  the flag strings, which is what a reader consumes.
* Any default VALUE in the docs (`--deadline SECONDS`, `--port 8443`).
  Defaults belong to the profile, covered by `tests/test_settings.py`; a
  doc default is a second owner waiting to drift.
* Lesson ids being gapless 1..N.  Ids are assigned by history (L29/L30
  look reserved, L17 carries letter suffixes), and a gap is not a defect.
* Prose wording anywhere.  A rewording is not a drift; a wrong NUMBER, a
  missing SECTION, a missing COMMAND and a wrong CELL COUNT are.
* A dated narrative progress log.  A machine check on a narrative produces
  false confidence.
"""

from __future__ import annotations

import dataclasses
import json
import pathlib
import re

import pytest

import wpt.actions  # noqa: F401  — registers every action
import wpt.audit  # noqa: F401  — imports register every landed check
from wpt.actions.registry import _ACTIONS
from wpt.audit.registry import all_checks
from wpt.cli import build_parser
from wpt.settings import JUNK_GROUP_NAMES, Settings, load

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT / "SPEC.md"
README_PATH = ROOT / "README.md"
PROFILE_PATH = ROOT / "wpt" / "data" / "profiles" / "default.json"

SETTINGS_HEADING = "Settings / profiles (W1, single source of tunables)"
CLI_HEADING = "CLI surface"
REGISTER_HEADING = "Residual register"
TESTMAP_HEADING = "Test Map — every lesson becomes a test"


# --------------------------------------------------------------- extraction


def section(md: str, heading: str) -> str:
    """The body of the ``## <heading>`` section, up to the next ``##``.

    Anchored on the HEADING TEXT, never a line number, so inserting a
    section above cannot silently move the text a test reads.
    """
    marker = "\n## " + heading
    start = md.index(marker) + 1
    rest = md[start:]
    nxt = rest.find("\n## ")
    return rest if nxt < 0 else rest[:nxt]


def fenced(section_text: str, lang: str | None = None) -> list[str]:
    """Every fenced block in a section; ``lang`` filters (e.g. ``json``),
    and ``None`` collects every block regardless of its language."""
    blocks: list[str] = []
    inside = False
    open_lang = ""
    body: list[str] = []
    for line in section_text.splitlines():
        stripped = line.strip()
        if not inside:
            if stripped.startswith("```"):
                inside, open_lang, body = True, stripped[3:].strip(), []
            continue
        if stripped.startswith("```"):
            if lang is None or open_lang == lang:
                blocks.append("\n".join(body))
            inside, open_lang, body = False, "", []
            continue
        body.append(line)
    return blocks


def cells(line: str) -> list[str]:
    """Markdown table cells, split on a ``|`` that is NEITHER inside a
    backtick span NOR backslash-escaped.

    Required, not optional: the residual register's R1 cell contains
    ``<IfModule mod_rewrite.c>`` and a Test Map cell contains ``}``, so a
    naive ``line.split("|")`` mis-counts rows that are correct.
    """
    out: list[str] = []
    current: list[str] = []
    in_code = False
    escaped = False
    for char in line:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if char == "`":
            in_code = not in_code
            current.append(char)
            continue
        if char == "|" and not in_code:
            out.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    out.append("".join(current).strip())
    # a table row is wrapped in pipes: drop the empty leading/trailing
    if out and out[0] == "":
        out = out[1:]
    if out and out[-1] == "":
        out = out[:-1]
    return out


def table_rows(section_text: str, first_cell: str) -> tuple[list[str], list[list[str]]]:
    """(header cells, data rows) of the table whose first data cell starts
    with ``first_cell``.  Shape-only: the header is the table's own."""
    header: list[str] | None = None
    rows: list[list[str]] = []
    for line in section_text.splitlines():
        if not line.lstrip().startswith("|"):
            # a BLANK line inside a table is a paragraph break in the
            # source, not the table's end (a blank line there also SPLITS
            # the rendered table in two, which is a defect the doc repair
            # fixes rather than this parser accommodating); real prose ends
            # the table.
            if rows and line.strip():
                break
            continue
        parsed = cells(line)
        if set("".join(parsed)) <= set("-: "):     # the ---|--- separator
            continue
        if header is None:
            header = parsed
            continue
        if parsed[0].startswith(first_cell):
            rows.append(parsed)
    assert header is not None, f"no table starting with {first_cell!r}"
    return header, rows


@pytest.fixture(scope="module")
def spec() -> str:
    return SPEC_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def readme() -> str:
    return README_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def profile() -> dict:
    return json.loads(PROFILE_PATH.read_text(encoding="utf-8"))


# ------------------------------------------------- (a) the settings listing


def spec_settings_listing(spec: str) -> dict:
    """SPEC's settings listing, parsed.  It is introduced as *the* shipped
    profile, so it must parse as the whole object it claims to be."""
    blocks = fenced(section(spec, SETTINGS_HEADING), "json")
    assert len(blocks) == 1, (
        f"the '{SETTINGS_HEADING}' section must hold exactly ONE ```json block "
        f"(the listing that claims to BE wpt/data/profiles/default.json); it has "
        f"{len(blocks)}. A second json fence would leave 'the listing' "
        f"ambiguous."
    )
    return json.loads(blocks[0])


def test_spec_lists_every_section_the_profile_ships(spec, profile):
    """(a1) every top-level key of the shipped profile appears in SPEC.

    Measured: the listing carried 16 of 29 — all of `deploy` (21 policy
    knobs), plus `conditional_junk`, which gates two destructive junk
    groups, were absent.
    """
    listed = spec_settings_listing(spec)
    missing = sorted(set(profile) - set(listed))
    extra = sorted(set(listed) - set(profile))
    assert not missing and not extra, (
        f"SPEC's settings listing is missing {len(missing)} section(s) the "
        f"shipped profile has: {missing}"
        + (f"; and lists {len(extra)} the profile does not have: {extra}"
           if extra else "")
        + ". The listing claims to BE wpt/data/profiles/default.json."
    )


@pytest.mark.parametrize("section_name", sorted(
    name for name, value in json.loads(
        PROFILE_PATH.read_text(encoding="utf-8")).items()
    if isinstance(value, dict)))
def test_each_listed_section_has_exactly_the_profile_keys(
        spec, profile, section_name):
    """(a2) per shared section, the same key NAMES and the same COUNT.

    The failure names the missing key, not just a count, so the repair is
    mechanical.  A list-valued section (webroot_junk, media.extensions, …)
    has no keys; its membership and order are :func:`a3`'s subject.
    """
    listed = spec_settings_listing(spec)
    assert section_name in listed, (
        f"section {section_name!r} is in the profile but not in SPEC's "
        f"listing"
    )
    want, got = profile[section_name], listed[section_name]
    assert isinstance(got, dict), (
        f"section {section_name!r} must be a JSON object in the listing (the "
        f"profile's shape); SPEC has {type(got).__name__}"
    )
    missing = sorted(set(want) - set(got))
    extra = sorted(set(got) - set(want))
    assert not missing and not extra, (
        f"section {section_name!r}: SPEC lists {len(got)} key(s), the profile "
        f"has {len(want)}"
        + (f"; missing: {missing}" if missing else "")
        + (f"; extra: {extra}" if extra else "")
    )


def test_every_listed_section_has_the_profiles_shape(spec, profile):
    """(a3) a mapping section is listed as an object and a list section as
    an array, and every list section matches the profile's list EXACTLY —
    membership AND order.  This is where ``media.extensions`` was wrong by
    14 against 39, and where ``core_integrity.known_stale`` was listed for
    a key the profile does not ship at all."""
    listed = spec_settings_listing(spec)
    for name, want in profile.items():
        got = listed.get(name)
        if isinstance(want, list):
            assert isinstance(got, list), (
                f"section {name!r} must be a JSON array in the listing (the "
                f"profile's shape); SPEC has {type(got).__name__}"
            )
            assert got == want, (
                f"section {name!r}: the listing has {len(got)} value(s), the "
                f"profile has {len(want)}"
                f"; missing: {[v for v in want if v not in got]}"
                f"; extra: {[v for v in got if v not in want]}"
                + (f"; order differs at index "
                   f"{next(i for i, (a, b) in enumerate(zip(got, want)) if a != b)}"
                   if sorted(map(str, got)) == sorted(map(str, want)) else "")
            )
        else:
            assert isinstance(got, dict), (
                f"section {name!r} must be a JSON object in the listing (the "
                f"profile's shape); SPEC has {type(got).__name__}"
            )


def test_the_settings_dataclass_mirror_matches_the_profile(profile):
    """(a5) the mirror SPEC documents — every profile section is a
    ``Settings`` field — cannot drift."""
    fields = {f.name for f in dataclasses.fields(Settings)}
    missing = sorted(set(profile) - fields)
    extra = sorted(fields - set(profile))
    assert not missing and not extra, (
        f"Settings dataclass <-> profile: missing field(s) {missing}"
        + (f"; field(s) with no profile key {extra}" if extra else "")
    )


# ------------------------------------- (b) the command table <-> registry


def readme_command_rows(readme: str) -> dict[str, list[str]]:
    """The command table's rows, keyed by the command token of the first
    cell.  The token is ``cell.strip().strip("`").split()[0]``, so the
    documented ``deactivate-plugin <slug>`` form is read without asserting
    any wording."""
    _header, rows = table_rows(section(readme, "Commands"), "`")
    out: dict[str, list[str]] = {}
    for row in rows:
        token = row[0].strip().strip("`").split()[0]
        out[token] = row
    return out


def registered_commands() -> set[str]:
    """DOCS-1: the subparser choices — the command set, including the fourteen that
    are not actions (audit, updates, verify, backup, restore, walk, serve,
    doctor, scan, logs, discover, files, proxy, deploy)."""
    action = build_parser()._subparsers._group_actions[0]
    return set(action.choices)


def test_every_registered_command_has_a_readme_row(readme):
    """(b1) every registered command — action or not — is documented."""
    rows = readme_command_rows(readme)
    missing = sorted(registered_commands() - set(rows))
    assert not missing, f"undocumented commands: {missing}"


def test_every_readme_command_is_registered(readme):
    """(b2) the OTHER direction: the table names no phantom command."""
    rows = readme_command_rows(readme)
    unknown = sorted(set(rows) - registered_commands())
    assert not unknown, (
        f"README's command table lists {len(unknown)} command(s) that are not "
        f"registered: {unknown}"
    )


@pytest.mark.parametrize("name", sorted(_ACTIONS))
def test_an_ftp_only_action_is_marked_in_the_readme(name, readme):
    """(b4) the FTP-only marker, owned by the actions registry.  P2-DOC-
    CLEANDB-FTP-ONLY: ``clean-db`` is the one action with an OFFLINE mode;
    its FTP applies tuple still names the bridge path, so the row must
    scope the marker ("FTP only for the bridge") AND name the ``--db-uri``
    local path.
    """
    row = next((line for line in readme.splitlines()
                if line.startswith(f"| `{name}")), None)
    assert row is not None, f"{name} has no row in the command table"
    ftp_only = tuple(_ACTIONS[name].applies) == ("ftp",)
    if name == "clean-db":
        assert "FTP only for the bridge" in row
        assert "--db-uri" in row and "local mode" in row
        return
    marked = "FTP only" in row or "ftp only" in row
    assert marked == ftp_only, (
        f"{name} applies to {_ACTIONS[name].applies} but its README row "
        f"{'marks' if marked else 'does not mark'} it FTP only"
    )


# --------------------------------- (c) the global flags in the usage block


def global_flags() -> dict[str, str]:
    """option string -> dest, for every top-parser action except ``help``
    and the ``command`` positional."""
    out: dict[str, str] = {}
    for action in build_parser()._actions:
        if action.dest in ("help", "command"):
            continue
        for option in action.option_strings:
            out[option] = action.dest
    return out


def test_spec_cli_section_mentions_every_global_flag(spec):
    """(c1) every flag registered on the top parser is named in SPEC's
    ``## CLI surface`` section (token membership, never the block verbatim).

    Measured: ``--version``, ``--quiet``, ``--log-json`` and
    ``--backup-dir`` were on the parser and in no doc.
    """
    body = section(spec, CLI_HEADING)
    missing = sorted(
        option for option in global_flags()
        if option not in set(re.findall(r"--[\w-]+", body))
    )
    assert not missing, (
        f"{len(missing)} global flag(s) are registered on the top parser but "
        f"the SPEC '{CLI_HEADING}' section never mentions them: "
        + ", ".join(f"{flag} (dest {global_flags()[flag]!r})"
                    for flag in missing)
    )


def test_spec_commands_line_lists_every_registered_command(spec):
    """(c2) every subparser name is a token on SPEC's ``commands:`` line.

    Token membership only — the line is prose-wrapped and its order is a
    human choice, so neither is asserted.  Measured: ``cull-media``,
    ``park-backups`` and ``webp-media`` were missing, which made SPEC and
    README contradict each other on the command set.
    """
    body = section(spec, CLI_HEADING)
    # the entry may wrap over several indented lines; the whole run up to
    # the next blank line is ONE entry
    line: list[str] = []
    for block in fenced(body):
        rows = block.splitlines()
        for index, row in enumerate(rows):
            if not row.strip().startswith("commands:"):
                continue
            line = [row]
            for following in rows[index + 1:]:
                if not following.strip() or not following.startswith((" ", "\t")):
                    break
                line.append(following)
            break
        if line:
            break
    assert line, (
        f"the SPEC '{CLI_HEADING}' usage block has no 'commands:' line"
    )
    tokens = set(re.findall(r"[a-z][\w-]*", "\n".join(line)))
    missing = sorted(registered_commands() - tokens)
    assert not missing, (
        f"SPEC's 'commands:' line omits {len(missing)} registered "
        f"command(s): {missing}"
    )


# ------------------------------- (d) the residual register: DOC-INTERNAL


def test_the_residual_register_is_uniform_and_ascending(spec):
    """(d1) every row has exactly the header's cell count; (d2) ids ascend.

    DOC-INTERNAL — the register is a human record with no code twin, so its
    own header is the only available truth and only SHAPE is asserted.
    Measured: cell shape was uniform but the file order ran
    R1..R22, R24, R25, R28, R29, R30, R27, R26, R23.
    """
    header, rows = table_rows(section(spec, REGISTER_HEADING), "R")
    ids: list[int] = []
    for row in rows:
        label = row[0]
        assert len(row) == len(header), (
            f"residual register row {label} has {len(row)} cells, the header "
            f"declares {len(header)}: {row}"
        )
        ids.append(int(label[1:]))
    out_of_order = [
        (ids[i], ids[i + 1]) for i in range(len(ids) - 1)
        if ids[i + 1] < ids[i]
    ]
    assert not out_of_order, (
        "residual register is out of ascending # order at "
        + "; ".join(f"{a} is followed by {b}" for a, b in out_of_order)
        + ". Rows must be in ascending # order."
    )


# ---------------------------------- (e) the lessons table: DOC-INTERNAL


#: A lesson id as it appears at the head of a Test Map cell or as a
#: citation: ``L12``, ``L17b``, ``L45``.  The citation form also matches the
#: ``[L4]:``/``[L11:`` shapes used inline.
_LESSON_TOKEN = re.compile(r"L(\d+[a-z]?)")
_LESSON_CITE = re.compile(r"\[L(\d+[a-z]?)[\]:]")


def test_the_test_map_is_uniform_with_unique_lesson_ids(spec):
    """(e1) every Test Map row has the header's cell count; (e2) ids unique.

    DOC-INTERNAL — there is no code twin for a lesson id.

    Measured: 8 rows had 4 cells (residual-register rows that migrated in,
    carrying an Owner column and a ``**FIXED**`` disposition) under a
    2-cell header, and ``L41`` was used by two different lessons.
    """
    header, rows = table_rows(section(spec, TESTMAP_HEADING), "L")
    by_id: dict[str, list[str]] = {}
    for row in rows:
        match = _LESSON_TOKEN.match(row[0])
        assert match is not None, (
            f"Test Map row {row[0]!r} does not start with a lesson id"
        )
        lesson = match.group(0)
        assert len(row) == len(header), (
            f"Test Map row {lesson} has {len(row)} cells, the header declares "
            f"{len(header)} — a residual-register row has migrated into the "
            f"Test Map. Cells: {row}"
        )
        by_id.setdefault(lesson, []).append(row[0])
    duplicated = {k: v for k, v in by_id.items() if len(v) > 1}
    assert not duplicated, (
        "lesson id(s) used by more than one row: "
        + "; ".join(f"{k} -> {v}" for k, v in sorted(duplicated.items()))
        + " — one of each pair is mis-numbered."
    )


def _cited_lesson_ids(paths: list[pathlib.Path]) -> dict[str, list[str]]:
    """lesson id -> the files whose docstrings/comments cite it, over
    ``[L#]``/``[L#:``/``[L#a]``."""
    cited: dict[str, list[str]] = {}
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for match in _LESSON_CITE.finditer(text):
            cited.setdefault(f"L{match.group(1)}", []).append(
                str(path.relative_to(ROOT)))
    return cited


def test_every_lesson_cited_in_the_tests_exists_in_spec():
    """(e3) every ``[L#]`` the suite cites is DEFINED by SPEC's Test Map.

    A test or source comment citing a lesson no row defines is a promise to
    a future reader with no referent — measured: two docstrings cited
    ``[L53]``, and ``wpt/actions/harden.py``/``wpt/doctor.py`` cited
    ``[L68]``/``[L69]`` while SPEC defined neither.
    """
    spec = SPEC_PATH.read_text(encoding="utf-8")
    _header, rows = table_rows(section(spec, TESTMAP_HEADING), "L")
    defined = {
        _LESSON_TOKEN.match(row[0]).group(0)      # the loop above proved
        for row in rows                           # every row has one
    }
    # The CONTRACT covers the source too: `wpt/` cites lessons in its
    # comments (L68/L69 were dangling because only tests/ was scanned).
    cited = _cited_lesson_ids(sorted(
        (*((ROOT / "tests").rglob("*.py")),
         *((ROOT / "wpt").rglob("*.py")))))
    undefined = {lesson: sorted(set(where))
                 for lesson, where in cited.items() if lesson not in defined}
    assert not undefined, (
        "the suite cites lesson(s) SPEC's Test Map does not define: "
        + "; ".join(
            f"[{lesson}] cited in {', '.join(where)}"
            for lesson, where in sorted(undefined.items()))
        + " — the header promises every lesson maps to at least one "
          "regression test, so a citation with no row is a dangling promise."
    )


# ------------------------------------------ (f) the junk-pattern list


def test_specs_webroot_junk_list_equals_the_profiles(spec, profile):
    """(f1) the one list a human will actually eyeball, compared against
    the LOADED, door-validated list (what the code matches on) element-wise
    and in order."""
    listed = spec_settings_listing(spec)["webroot_junk"]
    loaded = list(load().webroot_junk)
    assert listed == loaded, (
        f"SPEC's webroot_junk has {len(listed)} pattern(s), the loaded "
        f"profile has {len(loaded)}"
        f"; missing: {[p for p in loaded if p not in listed]}"
        f"; extra: {[p for p in listed if p not in loaded]}"
        + (f"; order differs at index "
           f"{next(i for i, (a, b) in enumerate(zip(listed, loaded)) if a != b)}"
           if sorted(listed) == sorted(loaded) else "")
    )


def test_every_grouped_junk_pattern_names_a_shipped_group():
    """(f2) every ``<group>:<glob>`` entry names a group the settings
    loader knows.  A doc example must not be needed to catch a typo in a
    profile pattern."""
    unknown = [
        pattern for pattern in load().webroot_junk
        if ":" in pattern and pattern.split(":", 1)[0] not in JUNK_GROUP_NAMES
    ]
    assert not unknown, (
        f"profile pattern(s) name a group the loader does not define "
        f"{sorted(JUNK_GROUP_NAMES)}: {unknown}"
    )


# ------------------------------- the audit-check count README publishes


def test_the_readme_audit_row_check_count_is_true(readme):
    """DOCS-2: README's ``audit`` row publishes a check COUNT; the registry
    owns it.  Measured: README said 33, the registry registers 38."""
    row = readme_command_rows(readme)["audit"]
    published = re.search(r"\((\d+) checks\)", row[1])
    assert published is not None, (
        f"README's audit row no longer states a check count: {row[1][:80]!r}"
    )
    checks = sorted(rec.name for rec in all_checks()
                    if not rec.name.startswith("t."))
    assert int(published.group(1)) == len(checks), (
        f"README says {published.group(1)} checks; the registry has "
        f"{len(checks)} ({checks})"
    )


def _assert_listing_matches(listed, shipped, path: str = "") -> None:
    """Every shipped leaf (scalar, list, nested object) equals the listing.

    Objects and lists recurse, so scalar leaves include list members.  A
    scalar must match VALUE AND JSON TYPE: Python's ``==`` conflates
    ``False`` with ``0``, ``True`` with ``1`` and ``21`` with ``21.0``, which
    would let a boolean/number drift pass the docs contract.
    """
    if isinstance(shipped, dict):
        assert isinstance(listed, dict), (
            f"{path or 'top level'}: listing has {type(listed).__name__}, "
            f"profile ships an object")
        assert set(listed) == set(shipped), (
            f"{path or 'top level'}: listing keys {sorted(listed)} != "
            f"profile keys {sorted(shipped)}")
        for key, value in shipped.items():
            child = f"{path}.{key}" if path else key
            _assert_listing_matches(listed[key], value, child)
        return
    if isinstance(shipped, list):
        assert isinstance(listed, list), (
            f"{path or 'top level'}: listing has {type(listed).__name__}, "
            f"profile ships a list")
        assert len(listed) == len(shipped), (
            f"{path or 'top level'}: listing has {len(listed)} item(s), "
            f"profile ships {len(shipped)}")
        for index, (item, expected) in enumerate(zip(listed, shipped)):
            _assert_listing_matches(item, expected, f"{path}[{index}]")
        return
    assert type(listed) is type(shipped), (
        f"{path or 'top level'}: the listing has {listed!r} "
        f"({type(listed).__name__}), the profile ships {shipped!r} "
        f"({type(shipped).__name__})")
    assert listed == shipped, (
        f"{path or 'top level'}: the listing has {listed!r}, the profile "
        f"ships {shipped!r}")


def test_every_listed_section_carries_the_profile_lists_value_for_value(spec, profile):
    """[L57] + R7-P2-23: the listing must carry every shipped value — list
    membership/order AND scalar leaves — or the doc can silently drift."""
    listed = spec_settings_listing(spec)
    _assert_listing_matches(listed, profile)


def test_R7_P2_23_the_listing_comparison_catches_a_scalar_mutation(spec,
                                                                  profile):
    """R7-P2-23 prevention: the old test skipped every non-list nested value,
    so a changed scalar (a limit, a boolean, a label) stayed green."""
    import copy

    listed = copy.deepcopy(spec_settings_listing(spec))
    mutated = copy.deepcopy(profile)
    section_name = next(name for name, value in mutated.items()
                        if isinstance(value, dict))
    values = mutated[section_name]
    scalar = next((k for k, v in values.items()
                   if not isinstance(v, (dict, list))), None)
    if scalar is None:
        pytest.skip("no scalar leaf in the first shipped section")
    mutated[section_name][scalar] = object()
    with pytest.raises(AssertionError):
        _assert_listing_matches(listed, mutated)


def test_R7_RESIDUAL_listing_scalar_types_cannot_drift(spec, profile):
    """R7 residual: Python ``==`` says ``False == 0`` and ``21 == 21.0``, so
    a JSON boolean/number drift passed the "exact" listing test.  Scalar
    leaves (list members included) must match value AND type."""
    import copy

    listed = copy.deepcopy(spec_settings_listing(spec))
    for section, key, replacement in (
            ("http", "verify_tls", 0),      # JSON false -> JSON 0
            ("ftp", "port", 21.0),          # JSON integer -> JSON float
    ):
        mutated = copy.deepcopy(profile)
        mutated[section][key] = replacement
        with pytest.raises(AssertionError, match="profile ships"):
            _assert_listing_matches(listed, mutated)

    # Scalars nested in lists are leaves too.
    with pytest.raises(AssertionError, match="profile ships"):
        _assert_listing_matches({"items": [1.0]}, {"items": [1]})
    with pytest.raises(AssertionError, match="profile ships"):
        _assert_listing_matches({"flag": 1}, {"flag": True})


def test_every_subparser_flag_is_documented(spec):
    """[L58] the contract checked the TOP parser only, so an undocumented
    per-command flag (the surface where --apply/--purge-originals/
    --i-know-editors-are-off live) was invisible. Every option string a
    subparser declares must appear in the commands section of SPEC."""
    parser = build_parser()
    body = section(spec, CLI_HEADING)
    subparsers = parser._subparsers
    actions = getattr(subparsers, "_group_actions", None)
    choices = actions[0].choices if actions else subparsers.choices
    for name, sub in choices.items():
        for opt in (a.option_strings for a in sub._actions):
            for flag in opt:
                if flag in ("--help", "-h"):   # argparse's own, not a
                    continue                    # product flag
                assert flag in body, (
                    f"command {name!r} declares {flag!r}, which the "
                    f"CLI surface section of SPEC never mentions"
                )


# ------------------------------------------------------- triple-check round 2


def test_DOC6_spec_documents_the_clean_db_db_uri_exception(spec):
    """DOC6: the local-input contract said --zip/--sql are required for
    EVERY command, while the code intentionally runs ``clean-db --db-uri``
    with neither (SPEC's own example does exactly that)."""
    cli = section(spec, CLI_HEADING)
    assert "clean-db` with `--db-uri`" in cli
    # and the SQL clause names the same exception
    assert "except\n`clean-db` with `--db-uri`" in cli or (
        "`clean-db` with `--db-uri`, which reads the database directly" in cli)


def test_DOC8_wpt_log_level_is_a_real_input():
    """DOC8: SPEC documents ``WPT_LOG_LEVEL``; the CLI must actually read
    it (the token was dead while the doc promised it)."""
    import wpt.cli as cli_module
    import inspect

    # The post-handler phase moved into its own function so the RunControl
    # boundary covers settings/password/gates (R11-P2-13); the documented
    # input still lives there.
    assert "WPT_LOG_LEVEL" in inspect.getsource(cli_module._main_after_handler)


def test_DOC9_the_false_settings_validation_count_is_gone():
    """DOC9: "66 of the 70 shipped keys" was not a real measure and the
    named keys were unvalidated.  The docs state the contract instead."""
    spec_text = SPEC_PATH.read_text(encoding="utf-8")
    settings_text = (ROOT / "wpt" / "settings.py").read_text(encoding="utf-8")
    assert "66 of the 70" not in spec_text
    assert "66 of the 70" not in settings_text
    # DOC7: the named complete sections, not "these two"
    assert "These two and not the older sections" not in settings_text
    assert "These sections and not the older ones" in settings_text


def test_DOC_RESTORE_FLAGS_parser_shapes_match_the_spec(spec):
    """P2-DOC-RESTORE-FLAGS: SPEC said --path-prefix changes the docroot and
    --media takes a PATH; the shipped flags are a subtree selector and a
    boolean uploads switch."""
    restore_p = build_parser()._subparsers._group_actions[0].choices[
        "restore"]
    actions = {option: action for action in restore_p._actions
               for option in action.option_strings}
    prefix = actions["--path-prefix"]
    assert prefix.dest == "path_prefix" and prefix.nargs != 0
    media = actions["--media"]
    assert media.dest == "media" and media.nargs == 0
    assert "restore under a different docroot" not in spec
    assert "--media PATH" not in spec


def test_DOC_PROXY_INPUTS_spec_and_readme_name_the_real_inputs(spec, readme):
    """P2-DOC-PROXY-INPUTS: SPEC's local/ftp clauses omitted proxy and the
    README claimed it reads only --hostname/--ip."""
    body = section(spec, CLI_HEADING)
    local = body.split("**Inputs by mode (local)**", 1)[1].split(
        "**Inputs by mode (ftp)**", 1)[0]
    assert "proxy" in local
    ftp = body.split("**Inputs by mode (ftp)**", 1)[1]
    assert "proxy" in ftp
    assert "--port" in readme and "--cert-dir" in readme
    assert "reads only `--hostname/--ip`" not in readme


def test_R6_32_spec_states_the_proxy_user_password_exception():
    """R6-32: SPEC claimed ``--user`` ALWAYS requires ``--password-env`` while
    the CLI exempts proxy (which reads no source).  The binding doc states
    the exception it actually implements."""
    spec = SPEC_PATH.read_text(encoding="utf-8")
    assert "except for `proxy`" in spec
    assert "which reads no" in spec[spec.index("except for `proxy`"):]


# ------------------------------------------------- triple-check round 7


def test_R7_P2_21_spec_names_the_real_settings_load_api(spec):
    """R7-P2-21: SPEC documented ``Settings.load(...)``; no such method
    exists — the canonical API is module-level ``wpt.settings.load``."""
    import wpt.settings

    body = section(spec, SETTINGS_HEADING)
    assert "wpt.settings.load(profile_path" in body
    assert "Settings.load(" not in body
    assert callable(wpt.settings.load)
    assert not hasattr(wpt.settings.Settings, "load")


def test_R7_P2_24_spec_local_zip_only_list_is_the_code_list(spec):
    """R7-P2-24: the local ``--zip``-only sentence omitted park-backups and
    update-core even though cli.FILE_ONLY_LOCAL_COMMANDS contains them."""
    from wpt.cli import FILE_ONLY_LOCAL_COMMANDS

    body = section(spec, CLI_HEADING)
    start = body.index("read the webroot only")
    sentence = body[max(0, start - 400):start]
    missing = [name for name in FILE_ONLY_LOCAL_COMMANDS
               if f"`{name}`" not in sentence]
    assert not missing, missing


def test_R7_P2_30_endpoint_owner_documentation_is_exact(spec):
    """R7-P2-30: SPEC/docstrings named a non-existent ``_BRIDGE_NAME_RE``
    and claimed the audit's bridge-only sweep uses the endpoint predicate."""
    import wpt.audit.security

    settings_docs = section(spec, SETTINGS_HEADING)
    assert "_BRIDGE_NAME_RE" not in settings_docs
    if wpt.audit.__doc__:
        assert "_BRIDGE_NAME_RE" not in wpt.audit.__doc__
    assert "bridge_name.BRIDGE_NAME_RE" in (wpt.audit.security
                                            ._is_known_artifact.__doc__ or "")
    assert "wpt.bridge_name.is_bridge_file" in spec
    assert "_BRIDGE_NAME_RE" not in spec


# ------------------------------------------------------- round-8 regressions


def test_R8_P2_25_residual_register_marks_r10_r11_closed(spec):
    """R8-P2-25: R10/R11 still described defects that no longer exist
    (zip set is_link; negative --deadline was accepted)."""
    register = section(spec, REGISTER_HEADING)
    rows = {line.split("|")[1].strip(): line
            for line in register.splitlines() if line.startswith("| R")}
    assert "**CLOSED**" in rows["R10"]
    assert "`_zip_is_link`" in rows["R10"]
    assert "**CLOSED**" in rows["R11"]
    assert "negative `--deadline`" in rows["R11"]


def test_R20_deploy_knob_count_matches_the_dataclass(spec):
    """R20's count is derived from ``DeploySettings``, not a second owner.

    Round 16 removed ``deploy.askpass_timeout_s`` from the dataclass and the
    profile but left the register advertising 21 knobs; the behavioral test
    pinned 20 while the prose drifted.  This parses the claim and compares it
    to the one owner, so the next removal cannot leave a stale count.
    """
    register = section(spec, REGISTER_HEADING)
    row = next(line for line in register.splitlines()
               if line.startswith("| R20 |"))
    match = re.search(r"one owner of (\d+) policy knobs", row)
    assert match is not None, "R20 no longer states its deploy-knob count"
    from wpt.settings import DeploySettings

    assert int(match.group(1)) == len(dataclasses.fields(DeploySettings))


def test_R8_P2_26_out_of_scope_names_plugin_theme_not_core(spec, readme):
    """R8-P2-26: core updates ship as ``update-core`` yet the docs still
    called every update out of scope."""
    out = spec.split("## Out of scope v1", 1)[1]
    assert "plugin/theme updates" in out
    assert "core updates ship as `update-core`" in out
    roadmap = readme.split("## Roadmap", 1)[1]
    assert "plugin/theme updates" in roadmap
    assert "core updates already ship" in roadmap


def test_R8_P2_27_local_inputs_name_backup_walk_as_ftp_only(spec):
    """R8-P2-27/R9-P2-18: SPEC's local --zip exception list omitted backup
    and walk, which the CLI deliberately lets reach their FTP-only bodies."""
    body = section(spec, CLI_HEADING)
    local = body.split("**Inputs by mode (local)**", 1)[1].split(
        "**Inputs by mode (ftp)**", 1)[0]
    assert "`backup`" in local
    assert "`walk`" in local
    assert "FTP-only" in local
    assert "backup requires ftp mode" in (ROOT / "wpt" / "backup.py").read_text(
        encoding="utf-8")
    assert "walk requires a live site" in (ROOT / "wpt" / "walk.py").read_text(
        encoding="utf-8")


def test_R9_P2_17_spec_and_deadline_document_the_listener_exception(spec):
    """P2-17: serve/proxy own their accept loop past --deadline; SPEC and
    deadline.py must state the exception instead of promising universality."""
    import wpt.deadline

    section_text = section(
        spec, "Run deadlines + graceful SIGTERM (self-bounding runs — rule 10)")
    assert "`wpt serve`" in section_text and "`wpt proxy`" in section_text
    assert "NOT bounded by `--deadline`" in section_text
    assert "accept loop" in section_text
    doc = wpt.deadline.__doc__ or ""
    assert "serve" in doc and "proxy" in doc
    assert "accept loop" in doc
    assert "not" in doc.lower() and "deadline" in doc.lower()


def test_R15_readme_names_both_update_drivers_and_stale_removal(readme):
    """R15-P2-17: the stale-file detail is driver-aware in the code, and
    both docs must keep naming BOTH drivers and what each does to a stale
    file.  This is the mechanical assertion fixes.md R14-P2-20 claimed."""
    row = readme_command_rows(readme)["update-core"]
    text = " ".join(row)
    assert "`swap`" in text and "`wordpress`" in text
    assert "stale files are removed" in text
    spec = section(
        SPEC_PATH.read_text(encoding="utf-8"),
        "update-core (move a live site to an explicit core version)")
    assert "stale files" in spec and "removed explicitly" in spec


def test_R8_P2_28_readme_documents_the_listener_deadline_exception(readme):
    """R8-P2-28: README promised every command ends itself on --deadline,
    but serve/proxy block in their accept loop until interrupted."""
    assert "`serve` and `proxy` own their process" in readme
    assert "`--deadline` does not stop their accept loop" in readme


def test_R22_every_spec_documented_in_readme_claim_resolves(spec, readme):
    """R22-P2: SPEC promised the Chrome interstitial bypass was
    "documented in README", and README had no occurrence of it.  Every
    quoted phrase SPEC calls documented in README must exist there."""
    claims = re.findall(r'"([^"]{3,})"\s+documented in README', spec)
    assert claims, "SPEC has no README cross-reference to check"
    for claim in claims:
        assert claim in readme, f"SPEC says {claim!r} is in README"


def test_R25_readme_and_spec_qualify_local_snapshot_rollback(spec, readme):
    """R25-P2: README promised every mutating action snapshots its scope and
    that update-core ``--apply`` snapshots trees + every table, while local
    mode deliberately takes NO snapshot (the original zip is the rollback).
    The two docs now name the mode split explicitly."""
    row = " ".join(readme_command_rows(readme)["update-core"])
    assert "**FTP** snapshots" in row
    assert "**local**" in row and "ORIGINAL zip is the rollback" in row
    readme_flat = " ".join(readme.split())
    spec_flat = " ".join(spec.split())
    assert "every **FTP** mutating action snapshots" in readme_flat
    assert "no pre-action snapshot in local mode" in spec_flat
    assert "does NOT take the FTP pre-action snapshot" in spec_flat


def test_R23_readme_proxy_certificate_matches_the_certificate_owner(readme):
    """R23-P2: README said the proxy mints a certificate for the OVERRIDDEN
    HOSTNAME, generated PER RUN.  ``ensure_cert`` is the owner: a localhost
    pair (CN=localhost; SAN localhost/127.0.0.1/::1) reused while usable.
    The doc must name the real identity and lifecycle, and the owner must
    still be the code the words describe."""
    import inspect

    from wpt import dnsoverride

    assert "localhost" in readme
    assert "`127.0.0.1`" in readme and "`::1`" in readme
    assert "reused" in readme
    assert "7-day" in readme
    assert "not regenerated per run" in readme
    assert "certificate for the overridden hostname" not in readme
    source = inspect.getsource(dnsoverride.ensure_cert)
    assert "CN=localhost" in source
    assert "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1" in source
    assert "_cert_pair_usable" in source


def test_R24_proxy_origin_and_stale_owner_docs_match_the_code():
    """R24-P2 docs: the CLI cited a non-existent ``_active_plugin_files``,
    the webp docstring promised module fallbacks that do not exist, and the
    proxy docs must name localhost (the one advertised/rewrite/cert origin)."""
    import inspect

    import wpt.cli as cli
    import wpt.dnsoverride as dnsoverride
    import wpt.proxy as proxy
    from wpt.actions import images_webp

    cli_text = inspect.getsource(cli)
    assert "_active_plugin_files" not in cli_text
    assert "_active_units" in cli_text
    assert "fall back to the module constants" not in (
        images_webp.__doc__ or "")
    assert "https://localhost:<port>" in (dnsoverride.__doc__ or "")
    assert "127.0.0.1:<port>" not in (dnsoverride.__doc__ or "")
    assert "SIGTERM" in (proxy.run_proxy.__doc__ or "")
    assert "0 after a clean Ctrl-C" in (proxy.run_proxy.__doc__ or "")
    spec = SPEC_PATH.read_text(encoding="utf-8")
    assert "CN=localhost" in spec
    assert "key-matched and still carrying those exact localhost" in spec
