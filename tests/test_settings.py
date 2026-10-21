import json

import pytest

import wpt.settings as settings_mod
from wpt.settings import Settings, SettingsError, apply_override, load, to_diff
from wpt.types import Source


def test_load_defaults():
    s = load()
    assert s.ftp.port == 21
    assert s.ftp.timeout_s == 45
    assert s.bridge.ttl_minutes == 15
    assert s.media_optimize.jpeg_quality == 82
    assert s.media_optimize.min_savings_ratio == 0.2
    assert s.http.verify_tls is False
    assert s.log.level == "info"
    assert "error_log" in s.webroot_junk
    assert ["litespeed-cache", "wp-super-cache", "w3-total-cache"] in s.duplicate_plugin_groups
    assert isinstance(s.duplicate_plugin_groups[0], list)
    assert "jetpack" in s.ghost_table_prefixes
    # the core wp_links table must never be a default ghost marker
    assert "links" not in s.ghost_table_prefixes
    assert "actionscheduler_actions" in s.ghost_table_prefixes
    assert s.ghost_marker_plugins == {"nf3": "ninja-forms",
                                      "statistics": "wp-statistics"}


def test_dot_path_override():
    s = load(overrides={"media_optimize.jpeg_quality": 75})
    assert s.media_optimize.jpeg_quality == 75
    assert s.media_optimize.png_max_dim == 1200  # untouched


def test_override_wrong_type_raises():
    with pytest.raises(SettingsError):
        load(overrides={"media_optimize.jpeg_quality": "high"})
    with pytest.raises(SettingsError):
        load(overrides={"http.verify_tls": "yes"})


def test_override_unknown_key_raises():
    with pytest.raises(SettingsError):
        load(overrides={"media_optimize.nonsense": 1})
    with pytest.raises(SettingsError):
        load(overrides={"nope.section": 1})
    with pytest.raises(SettingsError):
        load(overrides={"": 1})


def test_ghost_marker_plugins_shape_validated():
    raw = json.loads(settings_mod._DEFAULT_PROFILE.read_text(encoding="utf-8"))
    raw["ghost_marker_plugins"] = {"nf3": 3}
    with pytest.raises(SettingsError):
        settings_mod._load(raw)
    raw["ghost_marker_plugins"] = ["nf3"]
    with pytest.raises(SettingsError):
        settings_mod._load(raw)


def test_bool_bool_strictness():
    with pytest.raises(SettingsError):
        load(overrides={"http.verify_tls": 1})


def test_user_profile_deep_merge(tmp_path):
    profile = {
        "ftp": {"timeout_s": 60},
        "webroot_junk": ["custom_junk.log"],
    }
    p = tmp_path / "profile.json"
    p.write_text(json.dumps(profile))
    s = load(profile_path=str(p))
    assert s.ftp.timeout_s == 60
    assert s.ftp.port == 21  # untouched nested default preserved
    assert s.webroot_junk == ["custom_junk.log"]  # lists replace
    assert s.media_optimize.jpeg_quality == 82  # other sections untouched


def test_profile_unknown_top_level_raises(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"surprise": 1}))
    with pytest.raises(SettingsError):
        load(profile_path=str(p))


def test_profile_unknown_nested_key_raises(tmp_path):
    p = tmp_path / "bad2.json"
    p.write_text(json.dumps({"ftp": {"nope": 1}}))
    with pytest.raises(SettingsError):
        load(profile_path=str(p))


def test_to_diff_shows_only_changes():
    s = load(overrides={"media_optimize.jpeg_quality": 75, "log.level": "debug"})
    diff = to_diff(s)
    assert diff["media_optimize"] == {"jpeg_quality": 75}
    assert diff["log"] == {"level": "debug"}
    assert "ftp" not in diff
    assert "webroot_junk" not in diff


def test_apply_override_float_and_int():
    s = load()
    apply_override(s, "media_optimize.min_savings_ratio", 0.1)
    assert s.media_optimize.min_savings_ratio == 0.1
    apply_override(s, "bridge.ttl_minutes", 30)
    assert s.bridge.ttl_minutes == 30


def test_list_override():
    s = load(overrides={"known_heavy": ["a", "b"]})
    assert s.known_heavy == ["a", "b"]


@pytest.mark.parametrize("key,value", [
    ("suspicious.max_file_bytes", 0),
    ("suspicious.max_file_bytes", -1),
    ("ftp.parallel_reads", 0),
])
def test_override_is_held_to_the_same_validator_as_the_profile(key, value):
    # An override used to be the one path that could set a value the profile
    # loader rejects: a size gate of zero reached the scanner.
    for apply_it in (lambda: apply_override(load(), key, value),
                     lambda: load(overrides={key: value})):
        with pytest.raises(SettingsError, match=key.split(".")[-1]):
            apply_it()


def test_a_valid_override_still_applies_after_validation():
    s = load(overrides={"suspicious.max_file_bytes": 2048})
    assert s.suspicious.max_file_bytes == 2048


@pytest.mark.parametrize("key,value", [
    ("suspicious.patterns", [1]),
    ("suspicious.patterns", "not-a-list"),
    ("webroot_junk", [1]),
    ("known_heavy", [{"a": 1}]),
    ("ghost_marker_plugins", {"x": 1}),
    ("ghost_marker_plugins", ["x"]),
    ("duplicate_plugin_groups", [["a"], "b"]),
    ("suspicious.max_file_bytes", 0),
    ("ftp.parallel_reads", 0),
])
def test_override_and_profile_reject_exactly_the_same_values(key, value):
    # The override path used to be the weaker door: a list of ints passed as an
    # override where the profile rejected it, and a valid map was refused.
    import json
    import tempfile
    from pathlib import Path

    defaults = json.loads(
        Path("wpt/data/profiles/default.json").read_text(encoding="utf-8")
    )
    node = defaults
    parts = key.split(".")
    for part in parts[:-1]:
        node = node[part]
    node[parts[-1]] = value
    path = Path(tempfile.mkdtemp()) / "profile.json"
    path.write_text(json.dumps(defaults), encoding="utf-8")

    with pytest.raises(SettingsError):
        load(profile_path=path)
    with pytest.raises(SettingsError):
        load(overrides={key: value})


def test_a_rejected_override_leaves_the_tree_untouched():
    # Validation runs on a replacement BEFORE the live object is touched, so a
    # caller that catches the SettingsError does not keep a tree the loader
    # would never have produced.
    for key, value in (("ftp.parallel_reads", 0),
                       ("suspicious.max_file_bytes", 0),
                       ("suspicious.patterns", [1])):
        s = load()
        before = s.ftp.parallel_reads, s.suspicious.max_file_bytes, \
            s.suspicious.patterns
        with pytest.raises(SettingsError):
            apply_override(s, key, value)
        assert (s.ftp.parallel_reads, s.suspicious.max_file_bytes,
                s.suspicious.patterns) == before, key


def test_a_valid_map_override_is_accepted():
    assert load(overrides={"ghost_marker_plugins": {"x": "y"}}).ghost_marker_plugins \
        == {"x": "y"}
    with pytest.raises(SettingsError):
        load(overrides={"known_heavy": "not-a-list"})


def test_default_profile_is_packaged_and_valid():
    path = settings_mod._DEFAULT_PROFILE
    assert path.exists()
    raw = json.loads(path.read_text())
    # every top-level key maps to the Settings dataclass
    s = _load_raw = load()
    for key in raw:
        assert hasattr(s, key) or key in ("log",)


def test_ftp_parallel_reads_semantic_validation():
    """Out-of-range bulk parallelism fails at the SETTINGS owner through
    the standard error contract — not as a raw ValueError out of
    ThreadPoolExecutor at bulk-read time."""
    import pytest

    from wpt.settings import FtpSettings, SettingsError

    with pytest.raises(SettingsError, match="parallel_reads.*>= 1"):
        FtpSettings(parallel_reads=0)
    FtpSettings(parallel_reads=1)     # serial is valid
    FtpSettings()                     # the packaged default


# -------------------------------------------- media + core_integrity sections


def test_media_extensions_defaults_wired():
    """[L14] The media-extension allowlist ships in the profile and
    drives unreferenced-media flagging + trim-media deletion."""
    s = load()
    assert "jpg" in s.media.extensions
    assert "png" in s.media.extensions
    assert isinstance(s.media.extensions, list)
    # overrides replace the whole list (the suspicious.patterns contract)
    s2 = load(overrides={"media.extensions": ["webp"]})
    assert s2.media.extensions == ["webp"]


def test_media_extensions_override_type_validated():
    with pytest.raises(SettingsError, match="expected list"):
        load(overrides={"media.extensions": "jpg"})


def test_known_added_defaults_wired():
    """[L16] The known plugin-artifact signatures ship in the profile —
    Wordfence's WAF bootstrap by default — validated entry-by-entry."""
    s = load()
    assert s.core_integrity.known_added == [{
        "name": "wordfence-waf.php",
        "marker": "wordfence/waf/bootstrap.php",
        "max_bytes": 2048,
        "note": ("the Wordfence plugin's WAF bootstrap, deployed at the "
                 "webroot top level by Wordfence itself and wired via "
                 "auto_prepend_file"),
    }]


@pytest.mark.parametrize("raw", [
    [{"name": "x.php"}],                       # missing keys
    [{"name": "x.php", "marker": "m", "max_bytes": 10, "note": "n",
      "extra": 1}],                            # unknown key
    [{"name": "x.php", "marker": "m", "max_bytes": True, "note": "n"}],
    ["wordfence-waf.php"],                     # not an object
    {"name": "x.php"},                         # not a list
])
def test_known_added_malformed_profile_raises(tmp_path, raw):
    path = tmp_path / "profile.json"
    path.write_text(json.dumps({"core_integrity": {"known_added": raw}}),
                    encoding="utf-8")
    with pytest.raises(SettingsError):
        load(str(path))


def test_to_diff_covers_new_sections():
    """media / core_integrity appear in to_diff when they differ from the
    packaged defaults (the harden --set preview surface)."""
    s = load(overrides={"media.extensions": ["webp"]})
    diff = to_diff(s)
    assert diff["media"] == {"extensions": ["webp"]}
    assert "core_integrity" not in diff


# ------------------------------------------- media_optimize.exclude_prefixes


def test_exclude_prefixes_ships_the_form_record_subtree():
    """[live migration] optimize-media recompressed user-submitted Gravity
    Forms attachments under a profile with no exclusion; the shipped default
    protects that subtree, and the structural code default excludes nothing."""
    s = load()
    assert s.media_optimize.exclude_prefixes == [
        "wp-content/uploads/gravity_forms/"
    ]
    # the code default is structural: an absent key means "no exclusions"
    from wpt.settings import MediaOptimizeSettings
    assert MediaOptimizeSettings().exclude_prefixes == []


def test_exclude_prefixes_set_override():
    """--set media_optimize.exclude_prefixes=... REPLACES the shipped list
    (the collection contract every other list follows) and round-trips
    through to_diff."""
    s = load(overrides={"media_optimize.exclude_prefixes":
                        ["wp-content/uploads/2023/"]})
    assert s.media_optimize.exclude_prefixes == ["wp-content/uploads/2023/"]
    assert s.media_optimize.jpeg_quality == 82  # siblings untouched
    assert to_diff(s)["media_optimize"] == {
        "exclude_prefixes": ["wp-content/uploads/2023/"]}
    # an empty list is a valid value: "no exclusions"
    empty = load(overrides={"media_optimize.exclude_prefixes": []})
    assert empty.media_optimize.exclude_prefixes == []
    assert to_diff(empty)["media_optimize"] == {"exclude_prefixes": []}


@pytest.mark.parametrize("key,value", [
    ("media_optimize.exclude_prefixes", "wp-content/uploads/"),
    ("media_optimize.exclude_prefixes", ["wp-content/uploads/", 3]),
    ("media_optimize.exclude_prefixes", [None]),
])
def test_exclude_prefixes_shape_validated(key, value):
    """One validator, both doors: the profile loader and the override path
    reject exactly the same values."""
    import tempfile
    from pathlib import Path

    for apply_it in (lambda: load(overrides={key: value}),
                     lambda: apply_override(load(), key, value)):
        with pytest.raises(SettingsError, match="exclude_prefixes"):
            apply_it()
    defaults = json.loads(
        Path("wpt/data/profiles/default.json").read_text(encoding="utf-8")
    )
    defaults["media_optimize"]["exclude_prefixes"] = value
    path = Path(tempfile.mkdtemp()) / "profile.json"
    path.write_text(json.dumps(defaults), encoding="utf-8")
    with pytest.raises(SettingsError, match="exclude_prefixes"):
        load(profile_path=path)


@pytest.mark.parametrize("entry", [
    "",
    "   ",
    "/wp-content/uploads/",
    "   /wp-content/uploads/",   # padded absolute: the strip is what counts
    "wp-content\\uploads\\",     # a Windows path; walk paths are POSIX
    "C:\\inetpub\\uploads\\",
    "..",                        # no webroot-relative path can contain one
    "../",
    "wp-content/uploads/../../x/",
    "..\\uploads\\",
])
def test_exclude_prefixes_reject_unmatchable_entries(entry):
    """A blank entry matches EVERY file (the action silently stops doing
    anything) and a root-absolute one matches NOTHING (the operator believes
    a subtree is protected while it is still recompressed) — both fail at
    the owner instead. The same "matches nothing while looking deliberate"
    verdict covers a Windows separator and a ".." segment: neither can occur
    in a walk path, so both are the never-matching shape, not a preference.
    The blank test runs on the STRIPPED entry, so padding cannot smuggle an
    absolute path past it."""
    from wpt.settings import MediaOptimizeSettings

    with pytest.raises(SettingsError, match="exclude_prefixes"):
        MediaOptimizeSettings(exclude_prefixes=[entry])
    with pytest.raises(SettingsError, match="exclude_prefixes"):
        load(overrides={"media_optimize.exclude_prefixes": [entry]})
    # a sibling path that legitimately shares a name is untouched: the match
    # is a literal prefix, so a trailing "/" is what a subtree uses
    assert MediaOptimizeSettings(
        exclude_prefixes=["wp-content/uploads/2023/"]).exclude_prefixes


def test_exclude_prefixes_accepts_a_prefix_a_walk_path_can_carry():
    """The counterpart pin: the validator refuses the NEVER-MATCHING shapes
    only. An unusual prefix that a real webroot CAN carry (a space in a
    directory name, a dot-prefixed plugin dir, a single-file prefix) stays
    legal — a key that rejected matchable paths could not protect them."""
    from wpt.settings import MediaOptimizeSettings

    for entry in ("wp-content/uploads/my forms/",
                  "wp-content/plugins/.hidden/",
                  "wp-content/uploads/2024/01/one-big.jpg"):
        assert MediaOptimizeSettings(
            exclude_prefixes=[entry]).exclude_prefixes == [entry]


def test_R13_padded_and_windows_prefixes_are_refused_at_every_door():
    """R13-P1-5: the validator checked ``prefix.strip()`` but returned the
    RAW entry.  A padded or drive-letter prefix therefore looked valid while
    every consumer's ``startswith`` compared the raw string and never
    matched — the protected Gravity Forms originals became convertible and
    ``--purge-originals`` could delete them.  Direct dataclass, profile
    file and ``--set`` all reject the never-matching shapes."""
    import tempfile
    from pathlib import Path

    from wpt.settings import (MediaOptimizeSettings, WebpSettings,
                              apply_override, load)

    bad = [
        " wp-content/uploads/gravity_forms/",
        "wp-content/uploads/gravity_forms/ ",
        "C:/inetpub/uploads/",
        "C:\\inetpub\\uploads\\",
        "~/uploads/",
        "~wp-content/uploads/",
    ]
    for entry in bad:
        for make in (
            lambda: WebpSettings(data_prefixes=[entry]),
            lambda: MediaOptimizeSettings(exclude_prefixes=[entry]),
            lambda: load(overrides={"webp.data_prefixes": [entry]}),
            lambda: apply_override(load(), "webp.data_prefixes", [entry]),
        ):
            with pytest.raises(SettingsError, match="data_prefixes|exclude_prefixes|prefixes"):
                make()
        defaults = json.loads(
            Path("wpt/data/profiles/default.json").read_text(encoding="utf-8"))
        defaults["webp"]["data_prefixes"] = [entry]
        path = Path(tempfile.mkdtemp()) / "profile.json"
        path.write_text(json.dumps(defaults), encoding="utf-8")
        with pytest.raises(SettingsError, match="data_prefixes"):
            load(profile_path=path)

    # The valid shape is still stored verbatim, so the webp conversion gate
    # sees exactly the string operators configured and the purge can never
    # delete an excluded original.
    valid = load().webp.data_prefixes
    assert valid == ["wp-content/uploads/gravity_forms/"]
    assert all(not prefix.startswith((" ", "C:", "~")) for prefix in valid)


# ------------------- duplicate_plugin_groups_preferred (the operator's call)


def test_duplicate_preference_defaults_to_unset():
    """Unset = today's behavior: the check keeps its own evidence-based
    advice and no command appears out of nowhere."""
    s = load()
    assert s.duplicate_plugin_groups_preferred == {}
    assert to_diff(s) == {}


def test_duplicate_preference_is_a_group_name_to_slug_map():
    """The key is the group name exactly as the finding names it (the
    members joined with "/") and the value is the member to keep."""
    s = load(overrides={"duplicate_plugin_groups_preferred": {
        "elementor/fusion-builder": "elementor"}})
    assert s.duplicate_plugin_groups_preferred == {
        "elementor/fusion-builder": "elementor"}
    assert to_diff(s) == {"duplicate_plugin_groups_preferred": {
        "elementor/fusion-builder": "elementor"}}


def test_duplicate_preference_shape_validated_like_every_other_map():
    """Same contract as every other string map: not a list, not
    non-string keys or values — on BOTH doors."""
    for value in (["elementor"], {"elementor/fusion-builder": 1},
                  {1: "elementor"}, {"elementor/fusion-builder": None}):
        for apply_it in (
                lambda: load(overrides={
                    "duplicate_plugin_groups_preferred": value}),
                lambda: apply_override(load(), "duplicate_plugin_groups_preferred",
                                       value)):
            with pytest.raises(SettingsError,
                               match="duplicate_plugin_groups_preferred"):
                apply_it()


@pytest.mark.parametrize("preferred", [
    # a group that does not exist in the profile
    {"elementor/beaver-builder": "elementor"},
    # a single member's slug is not a group name
    {"elementor": "elementor"},
    # members in the WRONG order make a different group name
    {"fusion-builder/elementor": "elementor"},
    # the value is a plugin, but not a member of the named group
    {"elementor/fusion-builder": "w3-total-cache"},
    {"litespeed-cache/wp-super-cache/w3-total-cache": "elementor"},
])
def test_duplicate_preference_rejects_a_typo_loudly(preferred):
    """A preference the check could never honour is a TYPO. Ignoring it
    would leave the operator believing a decision is in force while the
    finding still renders its generic advice — so both doors fail loud,
    and the message names the group (or the member) that is wrong."""
    for apply_it in (
            lambda: load(overrides={
                "duplicate_plugin_groups_preferred": preferred}),
            lambda: apply_override(
                load(), "duplicate_plugin_groups_preferred", preferred)):
        with pytest.raises(SettingsError,
                           match="duplicate_plugin_groups_preferred"):
            apply_it()


def test_duplicate_preference_rejected_from_a_profile_file(tmp_path):
    """The profile door validates identically: a shipped profile whose
    preference names a group it does not define is refused at load, not at
    audit time."""
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({
        "duplicate_plugin_groups": [["a", "b"]],
        "duplicate_plugin_groups_preferred": {"a/b": "c"},
    }), encoding="utf-8")
    with pytest.raises(SettingsError, match="is not a member"):
        load(profile_path=str(p))
    p.write_text(json.dumps({
        "duplicate_plugin_groups": [["a", "b"]],
        "duplicate_plugin_groups_preferred": {"x/y": "a"},
    }), encoding="utf-8")
    with pytest.raises(SettingsError, match="names no group"):
        load(profile_path=str(p))


def test_rejected_duplicate_preference_leaves_the_tree_untouched():
    """The cross-field check runs on the PROSPECTIVE pair before the live
    tree is touched, so a caller that catches the SettingsError does not
    keep a preference the loader would never have produced."""
    s = load()
    with pytest.raises(SettingsError):
        apply_override(s, "duplicate_plugin_groups_preferred",
                       {"elementor/fusion-builder": "nope"})
    assert s.duplicate_plugin_groups_preferred == {}


def test_both_duplicate_keys_can_be_overridden_groups_first():
    """The documented order: a --set list that overrides BOTH keys sets the
    groups first, and the preference is then checked against the NEW
    groups (a single profile file is order-free and always works)."""
    s = load(overrides={
        "duplicate_plugin_groups": [["page-builder-a", "page-builder-b"]],
        "duplicate_plugin_groups_preferred": {
            "page-builder-a/page-builder-b": "page-builder-a"},
    })
    assert s.duplicate_plugin_groups_preferred == {
        "page-builder-a/page-builder-b": "page-builder-a"}


def test_web_script_section_ships_validates_and_overrides():
    """[L34] the security.web_exposed_script needles and read bound are
    profile data (the no-static-configurables rule), with a loud
    validator and a --set door."""
    import json
    import pytest
    from wpt.settings import (Settings, SettingsError, apply_override,
                              load, to_diff)

    s = load()
    assert [e["name"] for e in s.web_script.signatures] == [
        "hash_equals(", "$_GET[", "scandir(", "/home/", "phpinfo(",
        "php://input"]
    assert [e["name"] for e in s.web_script.request_globals] == [
        "$_GET", "$_POST", "$_REQUEST", "$_COOKIE"]
    # [D3] the shipped pattern spells the eight hex characters out, and
    # the matcher is hex-strict (wpt/audit/security.py owns the matching):
    # 'bridge-*.php' also exempted an attacker's 'bridge-shell.php'
    assert [e["name"] for e in s.web_script.known_artifacts] == [
        "bridge-????????.php", "wpt-probe-????????.php"]

    assert s.web_script.extensions == [
        ".php", ".phtml", ".php5", ".php7", ".phps", ".phar", ".inc",
        ".module"]
    assert s.web_script.max_bytes == 262144
    # a malformed profile fails loud, never silently scanning nothing
    with pytest.raises(SettingsError):
        apply_override(s, "web_script.signatures", [{"name": ""}])
    with pytest.raises(SettingsError):
        apply_override(s, "web_script.signatures", [{"name": "x"}])
    with pytest.raises(SettingsError):
        apply_override(s, "web_script.request_globals", [{"note": "x"}])
    with pytest.raises(SettingsError):
        apply_override(s, "web_script.known_artifacts", [{"name": "a/b"}])
    # a blank suffix is a typo that would scan an empty candidate set
    with pytest.raises(SettingsError):
        apply_override(s, "web_script.extensions", [".php", "  "])
    # an EMPTY signature list is accepted and MEANS "scan nothing" (it is
    # the master switch for the content gate, not "restore the defaults"),
    # and the diff reports exactly that
    apply_override(s, "web_script.signatures", [])
    assert s.web_script.signatures == []
    assert to_diff(s)["web_script"] == {"signatures": []}
    apply_override(s, "web_script.signatures", [dict(entry) for entry in
                                                Settings().web_script.signatures])
    assert to_diff(s) == {}
    # int override through the real path (apply_override mutates in place)
    apply_override(s, "web_script.max_bytes", 1024)
    assert s.web_script.max_bytes == 1024
    assert to_diff(s)["web_script"] == {"max_bytes": 1024}
    # a bare Settings() carries the shipped values (the dataclass default
    # is the profile's, not an empty list that would scan nothing)
    bare = Settings()
    assert [e["name"] for e in bare.web_script.signatures] == [
        e["name"] for e in s.web_script.signatures]
    # and the shipped profile file carries the section
    import pathlib
    import wpt.settings as _st
    raw = json.loads(pathlib.Path(_st._DEFAULT_PROFILE).read_text(encoding="utf-8"))
    assert "web_script" in raw and raw["web_script"]["max_bytes"] == 262144
    assert set(raw["web_script"]) == {
        "extensions", "signatures", "request_globals", "known_artifacts",
        "max_bytes"}
    # a profile file naming an unknown section key still fails loud
    with pytest.raises(SettingsError):
        _st._load({"web_script": {"nope": []}})


# ------------------------------------------- media.extensions (the validator)


@pytest.mark.parametrize("entry", [
    "",                          # a blank entry matches no file
    "   ",                       # ... and the test is on the stripped entry
    ".jpg",                      # this list is stored WITHOUT the dot
    "psd ",                      # padding is not a separator to strip
    "ps d",                      # no file's extension contains whitespace
    "a/b",                       # ... nor a path separator
    "a\\b",
])
def test_media_extensions_reject_entries_that_can_never_match(entry):
    """THE CLASS, in one profile key: the two halves fail in OPPOSITE
    DIRECTIONS for an entry that is not the exact lowercase token.

    The enumeration files a file by its own extension; the keep-gate
    lowercases that extension and looks it up in this list.  So "JPG"
    (normalized here) matches on both sides, while ".jpg" or "ps d"
    matched on NEITHER — and an entry the enumeration reads but the gate
    cannot is a file the keep-set does not keep: the offline gate
    silently measuring an EMPTY set for a database that references
    media, which is a deletion bug reachable through a documented,
    set-reachable profile key [L20].

    So the never-matching shapes are refused at the owner, on BOTH doors.
    """
    from wpt.settings import MediaSettings

    for apply_it in (
        lambda: MediaSettings(extensions=[entry]),
        lambda: load(overrides={"media.extensions": [entry]}),
        lambda: apply_override(load(), "media.extensions", [entry]),
    ):
        with pytest.raises(SettingsError, match=r"media\.extensions\["):
            apply_it()


def test_media_extensions_lowercases_so_both_halves_agree():
    """The normalization half: the list is stored lowercase, so a family
    written in caps names the same files in the enumeration and in the
    keep-gate.  Before it, "JPG" planned every .jpg on the site for
    deletion while the database map protected none of them."""
    from wpt.settings import MediaSettings

    widened = MediaSettings(extensions=["JPG", "PNG", "Psd"])
    assert widened.extensions == ["jpg", "png", "psd"]
    s = load(overrides={"media.extensions": ["JPG", "WEBP"]})
    assert s.media.extensions == ["jpg", "webp"]
    assert to_diff(s)["media"] == {"extensions": ["jpg", "webp"]}


def test_media_extensions_accepts_an_unusual_but_real_extension():
    """The counterpart pin: only the never-matching shapes are refused.  A
    family the tool cannot foresee (a numeric one, a vendor one) stays
    legal — this key exists to widen the family, and a validator that
    refused real extensions could not do its job."""
    from wpt.settings import MediaSettings

    for family in ("3gp", "avif", "heic", "jxl", "psd", "x-3dm"):
        assert MediaSettings(extensions=[family]).extensions == [family]
    shipped = load().media.extensions
    assert MediaSettings(extensions=shipped).extensions == shipped


# ------------------------------------------- the webroot_junk GROUP door
#
# A grouped ``webroot_junk`` pattern renders the GROUP's risk/WHY/fix, and
# the group globs are root-scoped BY THE DOOR (not by convention): a group
# glob carrying any of ``/ * ? [ ]`` is refused at load, because
# ``fnmatch``'s ``*`` crosses ``/``.  ``host_placeholder_page:*.php`` in a
# profile reported WordPress's own top-level core files (wp-login.php,
# wp-cron.php, xmlrpc.php, wp-signup.php, wp-mail.php,
# wp-comments-post.php, wp-trackback.php) HIGH with the group's "no site
# content is lost — delete it" fix, and the clean-files plan carried SEVEN
# of them (the core-junk exemption covers wp-admin/ and wp-includes/ only);
# ``*.html`` reached a theme's ``home.html`` and a plugin's authored
# ``index.html`` — the exact files L41's root-scoping was built to make
# unreachable.


def test_every_shipped_group_pattern_loads_through_the_door():
    """The counterpart pin: the shipped list really does declare grouped
    patterns, and the door accepts every one of them.  A door that refused
    the shipped profile would be a door nobody keeps."""
    from wpt.settings import JUNK_GROUP_NAMES, junk_pattern_parts

    shipped = json.loads(
        settings_mod._DEFAULT_PROFILE.read_text(encoding="utf-8"))["webroot_junk"]
    grouped = [p for p in shipped if junk_pattern_parts(p)[0]]
    assert grouped, "the shipped list declares no grouped pattern at all"
    for pattern in grouped:
        group, glob = junk_pattern_parts(pattern)
        assert group in JUNK_GROUP_NAMES
        assert not any(char in glob for char in "*/?[]")
    assert load().webroot_junk == shipped


@pytest.mark.parametrize("group", ["host_placeholder_page", "host_account_quota",
                                   "superseded_htaccess"])
@pytest.mark.parametrize("glob", [
    "*.php",          # the measured case: fnmatch '*' crosses '/'
    "*",              # every file in the webroot
    "home.*",
    "home.ht?ml",     # '?' is one character: still a webroot-root glob
    "[ab].html",      # a character class
    "wp-*.php",
    "**",
    "*.html",
    "wp-includes/home.html",   # a PATH: a group is the webroot ROOT, nothing else
    "sub/home.html",
])
def test_a_known_groups_glob_that_can_leave_the_root_is_refused_loud(group, glob):
    """The door, on BOTH paths a profile can take.

    A refusal that names only "invalid pattern" leaves the operator no idea
    which key or which entry, so the message carries the key with its index
    and the group whose root-scoping was broken.
    """
    pattern = f"{group}:{glob}"
    with pytest.raises(SettingsError, match=rf"webroot_junk\[1\]:.*{group}"):
        load(overrides={"webroot_junk": ["readme.html", pattern]})
    with pytest.raises(SettingsError, match=r"webroot_junk\[0\]"):
        apply_override(load(), "webroot_junk", [pattern])


def test_a_group_glob_is_refused_from_a_profile_file_too(tmp_path):
    """The user-profile door is the same door: it is deep-merged over the
    shipped list, so a hand-edited profile must not be a weaker one."""
    profile = tmp_path / "p.json"
    profile.write_text(json.dumps(
        {"webroot_junk": ["host_placeholder_page:*.php"]}), encoding="utf-8")
    with pytest.raises(SettingsError, match=r"webroot_junk\[0\]"):
        load(str(profile))


# ------------------------- the door's two closed paths (the LITERAL bypass)
#
# The metacharacter rule closed the GLOB, not the LITERAL: a profile that
# spells the file out one at a time (``host_placeholder_page:wp-cron.php``)
# carried no metacharacter, so the door admitted it — and the run then minted
# the group's HIGH finding over one of WordPress's own top-level core files,
# with the group's "no site content is lost — delete it" fix, and the
# clean-files plan DELETED it (reproduced end to end: the plan's target was
# ``wp-cron.php`` and the write-guard does not refuse that path, so the apply
# carried it out).  A group names the SOURCE HOST's control files; the two
# rules below are the two ways a pattern could claim something else.


@pytest.mark.parametrize("group", ["host_placeholder_page", "host_account_quota",
                                   "superseded_htaccess"])
@pytest.mark.parametrize("glob", [
    "wp-cron.php",       # the measured bypass: one literal, no metacharacter
    "wp-login.php",
    "xmlrpc.php",
    "index.php",         # also a never-deleted path (the second rule)
    "wp-config-sample.php",   # a top-level core .php, junk only as a BARE name
    "some-host-page.php",     # ANY root .php: the rule is the suffix
])
def test_a_known_group_may_not_name_a_root_php_file(group, glob):
    """Rule 3: a ``.php`` at a WordPress webroot ROOT is core's executable
    surface, never a host control file.

    The rule is the SUFFIX and not a list of core filenames, which is what
    makes it hold for the next release and for the versions this tool has
    never seen: every top-level core entry point is a ``.php`` (the loader
    resolves ``index.php``; wp-cron.php, xmlrpc.php and wp-signup.php sit
    beside it), and wpt/audit/integrity.py states the same structural fact
    from the other side.  A host control file really named ``*.php`` is still
    reachable — as a BARE pattern, which keeps its own text-derived risk and
    its own wording, and is told so in the message.

    The message names the key, the group AND the file: an operator who
    cannot see which of their entries was refused, or which file it named,
    has no way to fix the profile."""
    with pytest.raises(SettingsError, match=(
            rf"webroot_junk\[1\]: the {group!r} group may not name {glob!r}")):
        load(overrides={"webroot_junk": ["readme.html", f"{group}:{glob}"]})


@pytest.mark.parametrize("group", ["host_placeholder_page", "host_account_quota",
                                   "superseded_htaccess"])
@pytest.mark.parametrize("glob", sorted(Source.PROTECTED - {
    "wp-admin/", "wp-includes/"}))
def test_a_known_group_may_not_name_a_path_wpt_never_deletes(group, glob):
    """Rule 2, and the ONE-owner pin: the refuse list this door consults IS
    ``Source.PROTECTED`` — the set the write-guard's ``_check_deletable``
    raises on and the clean-files plan excludes — imported, never copied.

    ``superseded_htaccess:.htaccess`` is the case that matters most: a
    group reporting the LIVE access config (which the harden action owns and
    the guard protects) at a "safe to delete" fix, or ``wp-config.php``'s
    credentials at one.  The two trailing-slash members are excluded from the
    cases above because a group glob may not carry ``/`` at all (rule 1
    refuses them first); the set itself is used whole."""
    assert settings_mod._NEVER_DELETED is Source.PROTECTED, (
        "the door must consult the write-guard's own refuse set; a second "
        "list of protected paths is a list that drifts")
    with pytest.raises(SettingsError, match=(
            rf"webroot_junk\[0\]: the {group!r} group may not name {glob!r} "
            r"—\s*it is a path wpt must never delete")):
        load(overrides={"webroot_junk": [f"{group}:{glob}"]})


def test_every_shipped_group_pattern_still_loads_through_the_closed_door():
    """The counterpart pin for BOTH new rules, and the whole shipped list
    walked through the door it now carries: every grouped pattern names a
    host control file (``home.html``, ``404.shtml``, ``test.html``,
    ``.ftpquota``, ``old.htaccess``, ``.htaccess.old``) — none of them a
    root ``.php`` and none of them in the refuse set.  A door that refused
    the shipped profile would be a door nobody keeps, and the shipped profile
    is what every run starts from."""
    from wpt.settings import JUNK_GROUP_NAMES, junk_pattern_parts

    shipped = json.loads(
        settings_mod._DEFAULT_PROFILE.read_text(encoding="utf-8"))["webroot_junk"]
    grouped = [p for p in shipped if junk_pattern_parts(p)[0]]
    assert grouped, "the shipped list declares no grouped pattern at all"
    for pattern in grouped:
        group, glob = junk_pattern_parts(pattern)
        assert group in JUNK_GROUP_NAMES
        assert glob not in Source.PROTECTED, pattern
        assert not glob.endswith(".php"), pattern
    assert load().webroot_junk == shipped


@pytest.mark.parametrize("pattern", [
    "*.sql",               # the shipped dump exposure: basename, any depth
    "*.html",
    "*.tar.gz",
    "readme.html",
    "error_log",
    "weird*.php",          # no colon at all: bare
    "weird:12:00.html",    # only the FIRST colon splits -> unknown group
    "no_such_group:*.php",  # an unknown group degrades to the BARE shape
    "*.html:home.html",    # a metacharacter on the LEFT: never a group
    ":home.html",          # an empty side: never a group
])
def test_a_bare_pattern_is_unaffected_by_the_group_door(pattern):
    """The counterpart that must NOT break: a bare pattern is matched on the
    BASENAME at any depth BY DESIGN, metacharacters and all — that is how
    ``*.sql`` and ``*.tar.gz`` work.  The door refuses a glob only where a
    group is named, because that is the only place a glob means something
    other than "any basename"."""
    from wpt.settings import JUNK_GROUP_NAMES, junk_pattern_parts

    s = load(overrides={"webroot_junk": [pattern]})
    assert s.webroot_junk == [pattern]
    group, _glob = junk_pattern_parts(pattern)
    assert group is None or group not in JUNK_GROUP_NAMES


# ------------------------------------- media.dump_behind_row_ratio (the door)


def test_the_shipped_dump_behind_ratio_is_the_documented_half():
    """PINNED, because the default IS the safety property, not a preference.

    The threshold answers "may a dump that holds this share of the live
    rows certify that a file is unreferenced?"  One half is the widest
    tolerance that still refuses a dump that PREDATES the live content: a
    table with thousands of live rows and single digits in the dump is a
    ratio of ~0.001, two orders of magnitude below 0.5.  Nothing held the
    published 0.5 — the suite was green with the shipped value at 0.95, and
    a dump carrying 30% of the live rows was ACCEPTED at a 0.4 threshold
    with everything else passing.
    """
    from wpt.settings import MediaSettings

    shipped = json.loads(
        settings_mod._DEFAULT_PROFILE.read_text(encoding="utf-8"))
    assert shipped["media"]["dump_behind_row_ratio"] == 0.5
    assert load().media.dump_behind_row_ratio == 0.5
    assert MediaSettings().dump_behind_row_ratio == 0.5
    # an operator may still tighten or loosen it — it is their call, and the
    # door states what each end of the range would do
    assert load(overrides={"media.dump_behind_row_ratio": 0.4}).media \
        .dump_behind_row_ratio == 0.4


@pytest.mark.parametrize("value", [
    0,          # would refuse EVERY dump
    0.0,
    -1,
    1.5,        # would accept a dump that lost every row
    2,
    "0.5",      # a string compares as a TypeError three tables deep
    None,
    True,       # a bool IS an int in Python
    float("inf"),
    float("nan"),
])
def test_the_behind_ratio_door_refuses_nonsense_at_load(value):
    """The gate validated this, but ONLY where it reads it — which is after
    the whole plan phase has run, on the ``--set``/profile path a value
    reaches the tool by.  One validator per shape, at the owner, on both
    doors: a setting that is only checked at the end of the run is checked
    too late to be a door."""
    from wpt.settings import MediaSettings

    for apply_it in (
        lambda: MediaSettings(dump_behind_row_ratio=value),
        lambda: load(overrides={"media.dump_behind_row_ratio": value}),
    ):
        with pytest.raises(SettingsError, match="media.dump_behind_row_ratio"):
            apply_it()


@pytest.mark.parametrize("value", [0.01, 0.5, 1])
def test_the_behind_ratio_door_accepts_the_whole_legal_range(value):
    from wpt.settings import MediaSettings

    assert load(overrides={"media.dump_behind_row_ratio": value}).media \
        .dump_behind_row_ratio == pytest.approx(value)
    assert MediaSettings(dump_behind_row_ratio=value).dump_behind_row_ratio \
        == pytest.approx(value)


def test_exactly_one_settings_section_owns_the_behind_ratio():
    """NO SECOND COPY of the threshold.

    ``BackupPayloadSettings`` carried a dead duplicate of the field for one
    revision: no reader, no validator, and no entry in any profile — a
    second spelling of a safety threshold that no code consulted and a
    profile could have set in the belief it did something.  The shape of the
    defect is the same one the project keeps finding (a fact with two
    homes), so the pin is on the FIELD ITSELF: exactly one section may
    declare it, and that is the one ``behind_row_ratio`` reads.
    """
    from dataclasses import fields

    owners = sorted(
        name for name, section in settings_mod._SECTIONS.items()
        if "dump_behind_row_ratio" in section.__dataclass_fields__
    )
    assert owners == ["media"]
    assert not any(f.name == "dump_behind_row_ratio"
                   for f in fields(settings_mod.BackupPayloadSettings))


# ---------------------------------------------------------------------------
# The deploy + webp sections: the knobs that used to be module constants
#
# Both were absent from the tree entirely.  ``wpt.deploy.DeploySettings``
# carried 21 policy knobs in a dataclass of its own, reached only through a
# ``getattr(settings, "deploy", None)`` door that was ALWAYS None (the
# section did not exist), so ``--set deploy.<key>=`` was an "unknown
# settings section" refusal and the module's defaults were the shipped
# values.  The ``webp`` section did not exist at all: nine keys the action's
# own comments named were module constants, and the
# ``webp.purge_originals`` tri-state narrative described a key no operator
# could set.
# ---------------------------------------------------------------------------


def test_the_dataclass_defaults_are_the_shipped_profile_values():
    """A bare ``Settings()`` and a loaded profile must not disagree.

    The dataclass restates the profile so a bare ``Settings()`` is complete,
    and this is the pin that keeps the two from drifting — the same
    arrangement ``web_script`` uses, and the same reason.
    """
    shipped = json.loads(
        (settings_mod._DEFAULT_PROFILE).read_text(encoding="utf-8"))
    loaded = load()
    for section in ("deploy", "webp", "update", "walk", "http", "wp_org",
                    "backup", "db", "proxy"):
        assert section in shipped, f"{section} missing from the profile"
        for key, value in shipped[section].items():
            assert getattr(getattr(loaded, section), key) == value, \
                f"{section}.{key}"
            assert getattr(getattr(Settings(), section), key) == value, \
                f"{section}.{key} (the dataclass default)"
    # and the whole tree still diffs empty against itself
    assert to_diff(loaded) == {}


def test_R22_http_and_proxy_bare_dataclasses_match_the_profile():
    """The bare classes are the second door into the same policy.

    A direct ``HttpSettings()`` / ``ProxySettings()`` is what tests and
    embedders construct; the defaults must be the shipped profile values,
    and every field must be validated on that door too (a
    ``verify_tls="yes"`` string used to construct successfully while the
    FTP twin refused it).  Mutating ``http.timeout_s`` 30 -> 31 kept the
    whole suite green before this pin.
    """
    from wpt.settings import HttpSettings, ProxySettings, SettingsError

    assert HttpSettings() == HttpSettings(timeout_s=30, verify_tls=False,
                                          max_response_bytes=8388608)
    assert ProxySettings() == ProxySettings(cert_timeout_s=30,
                                            max_request_bytes=67108864)
    from wpt.settings import UpdateSettings

    assert UpdateSettings() == UpdateSettings(
        pre_release_allowed=False, maintenance=True, driver="auto")
    assert HttpSettings().verify_tls is False
    with pytest.raises(SettingsError, match="http.verify_tls"):
        HttpSettings(verify_tls="yes")
    with pytest.raises(SettingsError, match="http.verify_tls"):
        HttpSettings(verify_tls=1)
    with pytest.raises(SettingsError, match="http.timeout_s"):
        HttpSettings(timeout_s=0)
    with pytest.raises(SettingsError, match="proxy.max_request_bytes"):
        ProxySettings(max_request_bytes=0)


def test_the_shipped_response_bound_fits_a_real_document():
    """``walk.max_response_bytes`` is sized from the DOCUMENT it parses.

    A rendered Avada / page-builder front page measures 0.3-1.5 MB of HTML
    and the biggest generated stylesheet on such a site is well under
    1 MB, so the shipped 16 MiB is roughly ten times the largest real
    answer the crawler will ever be asked to hold: no real page is ever
    refused, and the runaway answer the bound exists for (measured: a
    300 MB page cost 934 MiB of RSS, ~3.1x its body) is refused at 16 MiB
    — a seventeenth of what used to be paid.  The number is a PROFILE
    value, so an operator with a genuinely enormous document can raise it
    (``--set walk.max_response_bytes=...``) without editing code.
    """
    from wpt.settings import WalkSettings

    profile = json.loads(
        (settings_mod._DEFAULT_PROFILE).read_text(encoding="utf-8"))
    shipped = profile["walk"]["max_response_bytes"]
    assert shipped == 16 * 1024 * 1024
    assert load().walk.max_response_bytes == shipped
    assert WalkSettings().max_response_bytes == shipped
    # reachable through the one override door
    assert load(overrides={"walk.max_response_bytes": 33554432}
                ).walk.max_response_bytes == 33554432
    # ... and 0 (which would refuse EVERY page and report a site with no
    # reachable pages) is a one-line refusal naming the key
    with pytest.raises(SettingsError, match="walk.max_response_bytes"):
        load(overrides={"walk.max_response_bytes": 0})


def test_every_deploy_knob_is_reachable_through_set():
    """Every knob, through the same door — a profile file or ``--set``.

    A knob that cannot be set is a knob the operator does not have, which is
    how ``strict_host_key_checking`` came to ship a value nobody could read
    or change.
    """
    from dataclasses import fields

    from wpt.settings import DeploySettings

    names = [f.name for f in fields(DeploySettings)]
    assert len(names) == 20
    shipped = load().deploy
    for name in names:
        value = getattr(shipped, name)
        override = (list(value) if isinstance(value, list) else value)
        s = load(overrides={f"deploy.{name}": override})
        assert getattr(s.deploy, name) == value, name
        # ... and it round-trips through to_diff, so a report can show it
        changed = load(overrides={f"deploy.{name}": _other(value)})
        assert to_diff(changed).get("deploy", {}).get(name, _MISSING) \
            == _other(value), name


def _other(value):
    """A different value of the same type, for a round-trip check."""
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, str):
        return value + "-changed"
    if isinstance(value, list):
        return list(value) + ["wpt-round-trip"]
    return value


_MISSING = object()


def test_the_host_key_default_is_accept_new_and_the_mutation_fails():
    """The security default, pinned as a VALUE, not as a comment.

    ``strict_host_key_checking: "accept-new"`` -> ``"no"`` turns OFF ssh
    host-key verification for every deploy — a man-in-the-middle is then
    accepted silently, and the deploy WRITES to the target.  During the
    audit that mutation left all 2234 tests green; this is the test that
    makes it fail.
    """
    from wpt.settings import DeploySettings

    assert load().deploy.strict_host_key_checking == "accept-new"
    assert DeploySettings().strict_host_key_checking == "accept-new"
    assert DeploySettings(strict_host_key_checking="no").strict_host_key_checking \
        == "no"          # reachable, and honest about what it does
    # the shipped PROFILE says the same, so the diff can never hide it
    profile = json.loads(settings_mod._DEFAULT_PROFILE.read_text("utf-8"))
    assert profile["deploy"]["strict_host_key_checking"] == "accept-new"
    # a blank policy is refused: it would be passed to ssh as nothing at all
    with pytest.raises(SettingsError, match="strict_host_key_checking"):
        load(overrides={"deploy.strict_host_key_checking": ""})


@pytest.mark.parametrize("key,value", [
    ("deploy.ssh_port", "2222"),
    ("deploy.ssh_port", 0),
    ("deploy.connect_timeout_s", -1),
    ("deploy.probe_timeout_s", 0),
    ("deploy.stream_bytes_per_s", 0),
    ("deploy.verify_batch_paths", 0),
    ("deploy.preflight_write_probe_bytes", 0),
    ("deploy.server_alive_interval_s", -1),
    ("deploy.preflight_margin_bytes", -1),
    ("deploy.stream_timeout_s", -1),
    ("deploy.manifest_archive_sha256", "yes"),
    ("deploy.required_files", "/etc/passwd"),
    ("deploy.residue_paths", ["../escape"]),
    ("deploy.quota_signatures", ["ok", ""]),
    ("deploy.nonsense", 1),
    ("webp.quality", 900),
    ("webp.quality", "high"),
    ("webp.challenge_max_bytes", 0),
    ("webp.verify_pages", -1),
    ("webp.data_prefixes", ["/abs/"]),
    ("webp.purge_originals", "yes"),
    ("bridge.scan_cap", -1),
    ("bridge.max_response_bytes", 0),
    ("bridge.max_response_bytes", -1),
    ("bridge.max_response_bytes", "16M"),
    ("bridge.max_response_bytes", True),
    ("walk.max_response_bytes", 0),
    ("walk.max_response_bytes", -1),
    ("walk.max_response_bytes", "16M"),
    ("walk.max_response_bytes", True),
])
def test_a_nonsense_value_fails_loud_naming_the_key(key, value):
    """The refusal is one line, names the key, and is a SettingsError.

    Every case is a value that would otherwise be USED: a policy the engine
    reads and believes.  None of them may be silently ignored.
    """
    with pytest.raises(SettingsError, match=key.split(".")[0]):
        load(overrides={key: value})


def test_the_scan_cap_door_is_the_operators_and_only_his():
    """``bridge.scan_cap``: 0 asks for nothing, a positive value is a lever.

    The op owns the bound (it clamps above its ceiling and reports it), so
    the profile must NOT refuse a value above the ceiling — refusing it
    locally would replace a visible clamp with a silent one — and must not
    mirror the op's own default either (0 is how that is spelled).
    """
    assert load().bridge.scan_cap == 0
    assert load(overrides={"bridge.scan_cap": 250_000}).bridge.scan_cap == 250_000
    assert load(overrides={"bridge.scan_cap": 5_000_000}).bridge.scan_cap \
        == 5_000_000        # passed through: the op clamps and says so
    assert to_diff(load(overrides={"bridge.scan_cap": 250_000}))["bridge"] \
        == {"scan_cap": 250_000}


def test_a_section_the_profile_does_not_spell_out_is_refused():
    """A key missing from the profile must fail, not fall back silently.

    The silent fallback is the shape of the defect from the other side: a
    knob deleted from ``wpt/data/profiles/default.json`` (or a key added to a
    dataclass and forgotten in the profile) loaded with the dataclass
    default, and ``to_diff`` reported nothing — it compares against the
    profile, and the fallback agreed with it by construction.  Deleting
    ``deploy.preflight_margin_bytes`` or ``webp.verify_retries`` from the
    shipped profile left the whole suite GREEN before this.
    """
    from wpt.settings import _load

    shipped = json.loads(
        (settings_mod._DEFAULT_PROFILE).read_text(encoding="utf-8"))
    for section, key in (("deploy", "preflight_margin_bytes"),
                         ("webp", "verify_retries"),
                         ("deploy", "ssh_port"),
                         ("update", "maintenance"),
                         ("webp", "quality"),
                         ("http", "max_response_bytes"),
                         ("proxy", "max_request_bytes")):
        raw = json.loads(json.dumps(shipped))
        del raw[section][key]
        with pytest.raises(SettingsError, match=f"{section}: missing keys"):
            _load(raw)
        # ... and an EXTRA key is refused the same way, so a typo in the
        # profile is not a knob that silently does nothing
        raw = json.loads(json.dumps(shipped))
        raw[section]["not_a_knob"] = 1
        with pytest.raises(SettingsError, match="unknown keys"):
            _load(raw)
    # the shipped profile itself is complete, so it loads
    assert _load(shipped) == load()


def test_php_min_active_rejects_a_non_version_before_a_check_can_fabricate_one():
    """[L61] 66 of the shipped keys refuse nonsense loudly; this one compared
    the runtime against the string, raised a TypeError inside the check, and
    the audit turned it into a HIGH "check errored — report as a bug"."""
    from wpt.settings import SettingsError, apply_override
    for bad in ("nonsense", "8.x", "8", "8.2.1", "8.", ".2", 8, 0.5, True, ""):
        with pytest.raises(SettingsError):
            apply_override(load(), "env.php_min_active", bad)
    for good in ("8.2", "7.4", " 8.2 ", "8.2\n"):
        assert apply_override(load(), "env.php_min_active", good) is None
    assert load(overrides={"env.php_min_active": " 8.2 "}) \
        .env.php_min_active == "8.2"
    assert load(overrides={"env.php_min_active": "8.2\n"}) \
        .env.php_min_active == "8.2"


def test_the_update_driver_key_is_validated_at_the_one_door():
    """``update.driver`` names a MECHANISM, so a typo must not read as
    "not wordpress" and silently run the other driver: the accepted set is
    one frozenset (wpt.settings.UPDATE_DRIVERS), the door is the section's
    own __post_init__ (so the profile path and the --set path are the same
    door), and the shipped default is the one that asks the site."""
    from wpt.settings import UPDATE_DRIVERS
    assert UPDATE_DRIVERS == {"auto", "swap", "wordpress"}
    assert load().update.driver == "auto"
    for bad in ("WordPress", "wp", "", "swap,wordpress", 1, None, True):
        with pytest.raises(SettingsError, match="update.driver"):
            apply_override(load(), "update.driver", bad)
    for good in sorted(UPDATE_DRIVERS):
        assert apply_override(load(), "update.driver", good) is None
    # and a rejected override leaves the live tree alone (the loader's own
    # validate-before-replace rule)
    settings = load()
    with pytest.raises(SettingsError):
        apply_override(settings, "update.driver", "nope")
    assert settings.update.driver == "auto"


def test_files_settings_defaults_and_validation():
    """The selected-file editor's bounds are a normal settings section:
    both the profile and --set path reject zero/negative values, and the
    shipped defaults are the profile values."""
    from wpt.settings import FilesSettings, SettingsError, apply_override

    shipped = load()
    assert shipped.files.max_files == 20
    assert shipped.files.max_file_bytes == 8 * 1024 * 1024
    for key in ("files.max_files", "files.max_file_bytes"):
        for bad in (0, -1, True, 1.5, "20"):
            with pytest.raises(SettingsError, match="files\\."):
                apply_override(shipped, key, bad)
        assert apply_override(shipped, key, 1) is None
    with pytest.raises(SettingsError, match="files.max_files"):
        FilesSettings(max_files=0)
    with pytest.raises(SettingsError, match="files.max_file_bytes"):
        FilesSettings(max_file_bytes=0)


# ------------------------------------------------------- triple-check round 2


def test_SET1_known_stale_object_signatures_load_on_both_doors(tmp_path):
    """SET1: ``core_integrity.known_stale`` is the SAME object shape as
    ``known_added`` (name/marker/max_bytes/note), but had no validator and
    fell through to ``_load_str_list`` — both the profile and ``--set``
    refused the documented form."""
    entry = {"name": "wp-includes/*.svg", "marker": "<svg",
             "max_bytes": 1000, "note": "stale core asset"}

    overridden = load(overrides={"core_integrity.known_stale": [entry]})
    assert overridden.core_integrity.known_stale == [entry]

    raw = json.loads(settings_mod._DEFAULT_PROFILE.read_text(encoding="utf-8"))
    raw["core_integrity"]["known_stale"] = [entry]
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps(raw), encoding="utf-8")
    assert load(profile_path=str(profile)).core_integrity.known_stale == [entry]

    for malformed in ([{"name": "x"}],
                      [dict(entry, max_bytes="lots")],
                      [dict(entry, extra="nope")],
                      ["bare-string"]):
        with pytest.raises(SettingsError, match="known_stale"):
            load(overrides={"core_integrity.known_stale": malformed})


@pytest.mark.parametrize("key", ["media_optimize.jpeg_max_dim",
                                 "media_optimize.png_max_dim"])
def test_SET2_media_max_dimensions_must_be_positive(key):
    """SET2: 0 reached ``thumbnail((0, 0))`` and raised ZeroDivisionError
    inside optimize-media; the load door now names the key."""
    for bad in (0, -1, True, 1.5, "2560"):
        with pytest.raises(SettingsError, match=key.rsplit(".", 1)[-1]):
            load(overrides={key: bad})
    assert load(overrides={key: 1}) is not None


def test_SET3_web_script_max_bytes_must_be_positive():
    """SET3: a negative bound filtered EVERY candidate, so the web-script
    security check silently reported a clean webroot."""
    for bad in (0, -5, True, "big"):
        with pytest.raises(SettingsError, match="web_script.max_bytes"):
            load(overrides={"web_script.max_bytes": bad})
    assert load(overrides={"web_script.max_bytes": 1}) is not None


@pytest.mark.parametrize("value", [-1, -0.5, True, "60"])
def test_SET4_negative_run_deadline_is_refused_but_zero_is_off(value):
    """SET4: Deadline.from_ctx treats <=0 as unbounded, so a negative value
    silently disabled self-bounding; 0 stays the documented explicit off."""
    with pytest.raises(SettingsError, match="run.deadline_s"):
        load(overrides={"run.deadline_s": value})
    assert load(overrides={"run.deadline_s": 0}).run.deadline_s == 0


def test_DOC9_the_named_sections_reject_nonsense_values():
    """DOC9: the profile no longer claims a false count; the named
    sections validate at the same load/--set door."""
    for key, bad in (("log.level", "bogus"),
                     ("ftp.port", 0),
                     ("ftp.port", 70000),
                     ("ftp.port", -1),
                     ("walk.delay_s", -3),
                     ("walk.max_pages", 0),
                     ("http.timeout_s", 0),
                     ("http.max_response_bytes", 0),
                     ("http.max_response_bytes", -1),
                     ("http.max_response_bytes", True),
                     ("http.max_response_bytes", "16M"),
                     ("proxy.max_request_bytes", 0),
                     ("proxy.max_request_bytes", -1),
                     ("proxy.max_request_bytes", True),
                     ("proxy.max_request_bytes", "64M"),
                     ("proxy.cert_timeout_s", 0),
                     ("proxy.cert_timeout_s", -1),
                     ("proxy.cert_timeout_s", float("nan")),
                     ("media_optimize.jpeg_quality", 101),
                     ("media_optimize.min_savings_ratio", -1),
                     ("media_optimize.skip_below_bytes", -1),
                     ("webp.verify_retry_delay_s", float("inf"))):
        with pytest.raises(SettingsError, match=key.replace(".", r"\.")):
            load(overrides={key: bad})
    assert load(overrides={"log.level": "DEBUG"}).log.level == "debug"
    assert load(overrides={"ftp.port": 65535}).ftp.port == 65535
    assert load(overrides={"walk.delay_s": 0}).walk.delay_s == 0


def test_BRIDGE_BOUNDS_timeout_ttl_and_retries_are_positive():
    """BRIDGE-BOUNDS: only scan_cap was validated; a negative timeout reached
    requests as a raw ValueError and negative ttl/retries corrupted the
    expiry/rename arithmetic."""
    from wpt.settings import BridgeSettings, SettingsError

    for key, value in (("timeout_s", -1), ("ttl_minutes", -5),
                       ("name_retries", 0), ("timeout_s", 0)):
        with pytest.raises(SettingsError, match=key):
            load(overrides={f"bridge.{key}": value})
        with pytest.raises(SettingsError):
            BridgeSettings(**{key: value})
    assert load(overrides={"bridge.timeout_s": 1}).bridge.timeout_s == 1
    assert load().bridge.max_response_bytes == 16777216
    assert load(overrides={"bridge.max_response_bytes": 1048576}) \
        .bridge.max_response_bytes == 1048576


def test_JUNK_CASE_a_case_variant_php_or_protected_name_is_refused():
    """JUNK-CASE: the grouped-junk door compared case-sensitively while the
    delete guard folds, so WP-CRON.PHP was accepted and matched/deletable."""
    from tests.fakes import FakeSource
    from wpt.settings import SettingsError, load as load_settings
    from wpt.types import SourceError

    for value in ("host_placeholder_page:WP-CRON.PHP",
                  "superseded_htaccess:WP-CONFIG.PHP"):
        with pytest.raises(SettingsError):
            load_settings(overrides={"webroot_junk": [value]})
    # The delete guard folds the same way; a case-variant protected name is
    # never deletable.
    with pytest.raises(SourceError):
        FakeSource()._check_deletable("WP-CONFIG.PHP")
    # The baseline door still accepts an ordinary host control file.
    load_settings(overrides={
        "webroot_junk": ["host_placeholder_page:index.html"]})


def test_SET_WEBP_DELAY_requires_a_finite_non_negative_retry_delay():
    """P2-SET-WEBP-DELAY: inf/nan loaded; inf reached time.sleep as a raw
    OverflowError, nan silently skipped the retry sleep."""
    import math

    for bad in (float("inf"), float("nan"), -1, -0.5, 1e300, 10 ** 400,
                True, "1"):
        with pytest.raises(SettingsError, match="verify_retry_delay_s"):
            load(overrides={"webp.verify_retry_delay_s": bad})
    assert load(overrides={"webp.verify_retry_delay_s": 0}).webp.\
        verify_retry_delay_s == 0
    value = load(overrides={"webp.verify_retry_delay_s": 1.5}).webp.\
        verify_retry_delay_s
    assert value == 1.5 and math.isfinite(value)


def test_SET_MEDIA_RATIO_quality_ratio_and_size_floor_are_validated():
    """P2-SET-MEDIA-RATIO: -1/0/999 quality, a negative savings ratio (a
    LARGER recompression planned as savings) and a negative size floor all
    loaded; only the dimensions and prefix list were checked."""
    import math

    for key, bad in (
            ("media_optimize.jpeg_quality", -1),
            ("media_optimize.jpeg_quality", 101),
            ("media_optimize.jpeg_quality", 1.5),
            ("media_optimize.jpeg_quality", True),
            ("media_optimize.jpeg_quality", "82"),
            ("media_optimize.min_savings_ratio", -1),
            ("media_optimize.min_savings_ratio", 1.1),
            ("media_optimize.min_savings_ratio", float("nan")),
            ("media_optimize.min_savings_ratio", float("inf")),
            ("media_optimize.min_savings_ratio", 10 ** 400),
            ("media_optimize.skip_below_bytes", -1),
            ("media_optimize.skip_below_bytes", True),
    ):
        with pytest.raises(SettingsError):
            load(overrides={key: bad})
    good = load(overrides={
        "media_optimize.jpeg_quality": 75,
        "media_optimize.min_savings_ratio": 0,
        "media_optimize.skip_below_bytes": 0,
    }).media_optimize
    assert (good.jpeg_quality, good.min_savings_ratio,
            good.skip_below_bytes) == (75, 0, 0)
    assert math.isfinite(good.min_savings_ratio)


def test_R6_31_ssh_port_is_bounded_on_both_sides():
    """R6-31: only >0 was checked, so 70000 reached ``ssh -p`` and explicit
    0 silently fell back to 22."""
    from wpt.settings import DeploySettings

    for port in (0, -1, 65536, 70000):
        with pytest.raises(SettingsError):
            DeploySettings(ssh_port=port)
        with pytest.raises(SettingsError):
            load(overrides={"deploy.ssh_port": port})
    assert DeploySettings(ssh_port=65535).ssh_port == 65535
    assert DeploySettings(ssh_port=1).ssh_port == 1


# ------------------------------------------------- triple-check round 7


def test_R7_P2_22_empty_web_script_extensions_is_refused():
    """R7-P2-22: ``extensions: []`` loaded and silently scanned nothing;
    ``signatures: []`` is the documented master switch, not this."""
    import pytest
    from wpt.settings import SettingsError, load

    with pytest.raises(SettingsError, match="at least one suffix"):
        load(overrides={"web_script.extensions": []})


def test_R7_P2_27_port_bounds_have_one_owner():
    """R7-P2-27: the upper bound was duplicated as 65535 in settings; the
    bindable floor 1 also has one named owner."""
    import wpt.ports as ports
    import wpt.settings as settings

    assert settings.PORT_MAX == ports.PORT_MAX == 65535
    assert settings.PORT_MIN_BINDABLE == ports.PORT_MIN_BINDABLE == 1
    with pytest.raises(settings.SettingsError):
        settings.FtpSettings(port=0)
    with pytest.raises(settings.SettingsError):
        settings.FtpSettings(port=ports.PORT_MAX + 1)


# ------------------------------------------------ round 12 (P2 regressions)


@pytest.mark.parametrize("entry", ["", "   ", ".", "./wp-content/",
                                   "a//b", "a/./b", "/wp-content/cache/",
                                   "wp-content/../x/"])
def test_R12_page_cache_dirs_use_the_shared_prefix_validator(entry):
    """R12-P2-15: ``page_cache_dirs`` had no __post_init__ and accepted
    empty, "." and double-separator entries that match nothing (or the
    whole tree).  Direct construction, ``--set`` and the profile file all
    reach the SAME validator."""
    import tempfile
    from pathlib import Path

    from wpt.settings import ConditionalJunkSettings, apply_override, load

    with pytest.raises(SettingsError, match="page_cache_dirs"):
        ConditionalJunkSettings(page_cache_dirs=[entry])
    with pytest.raises(SettingsError, match="page_cache_dirs"):
        load(overrides={"conditional_junk.page_cache_dirs": [entry]})
    with pytest.raises(SettingsError, match="page_cache_dirs"):
        apply_override(load(), "conditional_junk.page_cache_dirs", [entry])
    defaults = json.loads(
        Path("wpt/data/profiles/default.json").read_text(encoding="utf-8")
    )
    defaults["conditional_junk"]["page_cache_dirs"] = [entry]
    path = Path(tempfile.mkdtemp()) / "profile.json"
    path.write_text(json.dumps(defaults), encoding="utf-8")
    with pytest.raises(SettingsError, match="page_cache_dirs"):
        load(profile_path=path)


def test_R12_page_cache_dirs_accepts_the_documented_directory_prefix():
    from wpt.settings import ConditionalJunkSettings, load

    prefix = "wp-content/cache/supercache/"
    assert ConditionalJunkSettings(page_cache_dirs=[prefix]).page_cache_dirs \
        == [prefix]
    assert load(overrides={
        "conditional_junk.page_cache_dirs": [prefix],
    }).conditional_junk.page_cache_dirs == [prefix]


def test_R12_ftp_tls_verification_defaults_on_and_refuses_a_dead_ca_option():
    """R12-P1-7: FTPS verifies by default; ``verify_tls=false`` is an
    explicit bool opt-out; a CA bundle cannot be combined with an
    unverified context (it would be silently ignored)."""
    from wpt.settings import FtpSettings, load

    assert FtpSettings().verify_tls is True
    assert load().ftp.verify_tls is True
    assert FtpSettings(verify_tls=False).verify_tls is False
    with pytest.raises(SettingsError, match="verify_tls"):
        FtpSettings(verify_tls=False, ca_file="/tmp/ca.pem")
    with pytest.raises(SettingsError, match="verify_tls"):
        FtpSettings(verify_tls="yes")
    with pytest.raises(SettingsError, match="ca_file"):
        FtpSettings(ca_file=7)


def test_R24_direct_constructors_validate_bool_policy_values():
    """R24-P2: complete-section dataclasses are embedder-facing too.  A
    string "false" is truthy; UpdateSettings/WebpSettings accepted it (and
    WebpSettings.challenge_max_bytes accepted bool/str and only then raised
    a raw TypeError)."""
    from wpt.settings import SettingsError, UpdateSettings, WebpSettings

    for kwargs in ({"pre_release_allowed": "false"},
                   {"maintenance": "no"},
                   {"pre_release_allowed": 0}):
        with pytest.raises(SettingsError):
            UpdateSettings(**kwargs)
    for kwargs in ({"purge_originals": "false"},
                   {"purge_originals": 1},
                   {"challenge_max_bytes": True},
                   {"challenge_max_bytes": 1.5},
                   {"challenge_max_bytes": "32768"}):
        with pytest.raises(SettingsError):
            WebpSettings(**kwargs)
    # Legitimate values still construct.
    assert UpdateSettings(pre_release_allowed=False, maintenance=False)
    assert WebpSettings(purge_originals=True, challenge_max_bytes=1)
