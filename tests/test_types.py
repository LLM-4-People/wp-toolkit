import dataclasses

import pytest

from wpt.types import (
    Entry,
    Finding,
    NotWritableError,
    PlanItem,
    Source,
    SourceError,
)


class DummySource(Source):
    """Minimal concrete source used to exercise the shared guards."""

    root = "domains/x/public_html"

    def list_dir(self, path):
        return []

    def walk(self, path=""):
        return iter([])

    def read_bytes(self, path):
        return b""

    def write_bytes(self, path, data, *, allow_config=False, allow_core=False):
        self._check_writable(path, allow_config, allow_core)

    def delete(self, path):
        self._check_deletable(path)

    def rmdir_recursive(self, path):
        self._check_deletable(path)

    def exists(self, path):
        return False

    def size(self, path):
        return 0

    def close(self):
        pass


@pytest.fixture()
def src():
    return DummySource()


class RenamingSource(DummySource):
    """DummySource plus the rename primitive and BOTH shared guards."""

    def rename(self, src, dst, *, allow_config=False, allow_core=False):
        self._check_rename_source(src, allow_config, allow_core)
        self._check_rename_target(dst, allow_config, allow_core)
        self.renamed = getattr(self, "renamed", []) + [(src, dst)]


def test_source_is_abstract():
    with pytest.raises(TypeError):
        Source()  # type: ignore[abstract]


def test_guard_path_rejects_traversal(src):
    for bad in ("../etc/passwd", "a/../../b", "/absolute", "..", ".", ""):
        with pytest.raises(SourceError):
            src._guard_path(bad)


def test_guard_path_normalizes(src):
    assert src._guard_path("wp-content//uploads/x.png") == "wp-content/uploads/x.png"
    assert src._guard_path("a\\b.txt") == "a/b.txt"


def test_guard_rejects_non_string(src):
    with pytest.raises(SourceError):
        src._guard_path(None)  # type: ignore[arg-type]


@pytest.mark.parametrize("path", ["a\nb", "a\rb", "a\x00b", "a\x1fb",
                                  "a\x7fb", "a\ud800b"])
def test_FTP_1_guard_rejects_control_del_and_surrogates(src, path):
    with pytest.raises(SourceError):
        src._guard_path(path)


@pytest.mark.parametrize("path", ["wp-config.php", ".htaccess", "index.php", "wp-admin"])
def test_write_protected_blocked_without_flag(src, path):
    with pytest.raises(NotWritableError):
        src.write_bytes(path, b"x")


def test_write_wp_config_allowed_with_flag(src):
    src.write_bytes("wp-config.php", b"x", allow_config=True)


def test_config_files_writable_with_flag_only(src):
    # Both site-config files (wp-config.php, .htaccess) unlock with
    # allow_config — harden/restore need them; core sources never do.
    src.write_bytes(".htaccess", b"x", allow_config=True)
    with pytest.raises(NotWritableError):
        src.write_bytes(".htaccess", b"x")                 # flag required
    with pytest.raises(NotWritableError):
        src.write_bytes("wp-config.php", b"x")            # flag required
    with pytest.raises(NotWritableError):
        src.write_bytes("index.php", b"x", allow_config=True)  # core stays locked


@pytest.mark.parametrize("path", ["wp-config.php", ".htaccess", "index.php", "wp-admin", "wp-includes"])
def test_delete_protected_blocked(src, path):
    with pytest.raises(SourceError):
        src.delete(path)
    with pytest.raises(SourceError):
        src.rmdir_recursive(path)


def test_regular_paths_pass_guards(src):
    src.delete("wp-content/uploads/old.png")
    src.rmdir_recursive("wp-content/plugins/dead-plugin")
    src.write_bytes("wp-content/new.txt", b"x")


@pytest.mark.parametrize("root", ["", "domains/x/public_html"])
def test_TYPES_1_wp_content_delete_guard_is_independent_of_root(root):
    """root="" is the documented account-root mapping (--webroot /): the
    structural wp-content guard must still refuse there."""
    source = DummySource()
    source.root = root
    with pytest.raises(SourceError, match="structural dir"):
        source.delete("wp-content")
    with pytest.raises(SourceError, match="structural dir"):
        source.rmdir_recursive("wp-content")


@pytest.mark.parametrize("path", [
    "WP-CONFIG.PHP", "Wp-Config.Php", ".HTACCESS", "INDEX.PHP",
    "WP-ADMIN", "wp-includes/version.php", "WP-ADMIN/includes/file.php",
])
def test_TYPES_3_protected_names_are_casefolded(src, path):
    # The alias must not walk past the guard: a write without the audited
    # unlock is refused exactly like its lowercase spelling.
    with pytest.raises(NotWritableError):
        src.write_bytes(path, b"x")
    if path.casefold() in Source.PROTECTED_FOLDED:
        with pytest.raises(SourceError):
            src.delete(path)
        with pytest.raises(SourceError):
            src.rmdir_recursive(path)
    # The config unlock is case-insensitive in BOTH directions.
    if path.casefold() in ("wp-config.php", ".htaccess"):
        src.write_bytes(path, b"x", allow_config=True)


def test_TYPES_2_rename_refuses_protected_sources_without_the_core_unlock():
    src = RenamingSource()
    with pytest.raises(NotWritableError):
        src.rename("wp-config.php", "stolen.php")
    with pytest.raises(NotWritableError):
        src.rename("wp-config.php", "stolen.php", allow_config=True)
    with pytest.raises(NotWritableError):
        src.rename("wp-admin", "moved")
    with pytest.raises(NotWritableError):
        src.rename("wp-includes", "moved")
    with pytest.raises(NotWritableError):
        src.rename("index.php", "moved")
    with pytest.raises(NotWritableError):
        src.rename("wp-content", "moved")
    # the update-core swap's audited unlock moves the live core tree
    src.rename("wp-admin", "wp-admin.wpt-old", allow_core=True)
    src.rename("wp-includes.wpt-new", "wp-includes", allow_core=True)
    src.rename("index.php", "index.php.wpt-old", allow_core=True)
    assert ("wp-admin", "wp-admin.wpt-old") in src.renamed


def test_entry_and_finding_defaults():
    e = Entry(path="a.png", is_dir=False, size=10)
    assert e.is_link is False
    f = Finding(category="webroot.junk", name="error_log", detail="25 MB")
    assert f.risk == "low" and f.bytes == 0 and f.count == 1


def test_finding_validate_risk():
    ok = Finding(category="db.revisions", name="x", detail="y")
    assert ok.validate() is ok
    bad = Finding(category="db.revisions", name="x", detail="y", risk="critical")
    with pytest.raises(ValueError):
        bad.validate()
    with pytest.raises(ValueError):
        Finding(category="", name="x", detail="y").validate()


def test_finding_is_frozen_dataclass():
    assert dataclasses.is_dataclass(Finding)
    assert dataclasses.is_dataclass(PlanItem)
    p = PlanItem(category="c", target="t", detail="d")
    assert p.requires_apply is True and p.done is False


def test_write_guard_is_prefix_recursive_for_core_dirs(src):
    """Writes ANYWHERE under wp-admin/ or wp-includes/ are refused (the
    toolkit never edits WordPress source); deletes inside them stay
    allowed — wp-admin/error_log is exactly the junk clean-files removes
    (the delete guard keeps its exact-membership rule)."""
    with pytest.raises(NotWritableError):
        src.write_bytes("wp-admin/includes/evil.php", b"x")
    with pytest.raises(NotWritableError):
        src.write_bytes("wp-includes/js/evil.js", b"x")
    with pytest.raises(NotWritableError):
        src.write_bytes("wp-admin/anything", b"x")
    src.delete("wp-admin/error_log")  # junk inside core dirs: deletable
    with pytest.raises(SourceError):
        src.delete("wp-admin")        # the core dir itself: never


# --------------------------------------------- the allow_core heal unlock

def test_core_heal_unlock_is_surgical(src, wpt_records):
    """allow_core unlocks EXACTLY the heal-core restore surface — top-level
    index.php plus the wp-admin/ and wp-includes/ subtrees — and nothing
    else: wp-config.php/.htaccess stay config-only (wp.org does not ship
    them), the bare directory names stay refused, and every core path
    still refuses without the flag. The unlocked write is audited with a
    warning log line, exactly like allow_config."""
    import logging

    # the heal surface unlocks
    src.write_bytes("index.php", b"x", allow_core=True)
    src.write_bytes("wp-includes/version.php", b"x", allow_core=True)
    src.write_bytes("wp-admin/includes/file.php", b"y", allow_core=True)
    warns = [r.getMessage() for r in wpt_records
             if r.name == "wpt.source" and r.levelno == logging.WARNING]
    assert any("guarded core heal: restoring protected core file: "
               "wp-includes/version.php" in m for m in warns)

    # the config files are NEVER core-healable
    with pytest.raises(NotWritableError):
        src.write_bytes("wp-config.php", b"x", allow_core=True)
    with pytest.raises(NotWritableError):
        src.write_bytes(".htaccess", b"x", allow_core=True)

    # the bare directory names stay refused even for heals
    with pytest.raises(NotWritableError):
        src.write_bytes("wp-admin", b"x", allow_core=True)
    with pytest.raises(NotWritableError):
        src.write_bytes("wp-includes", b"x", allow_core=True)

    # and every core path still refuses without the flag
    for path in ("index.php", "wp-includes/version.php",
                 "wp-admin/includes/file.php"):
        with pytest.raises(NotWritableError):
            src.write_bytes(path, b"x")

    # user-content paths ignore the flag entirely (writes fine either way)
    src.write_bytes("wp-content/themes/tt5/style.css", b"z")


def test_R11_wordpress_root_core_files_are_one_protected_owner(src):
    """R11-P2-6: every official webroot-root PHP core file is source code:
    heal/update may write it under the audited allow_core unlock, while a
    selected-file edit/delete never can.  The list lives in ONE table."""
    core_root = {
        "wp-load.php", "wp-settings.php", "wp-blog-header.php",
        "wp-cron.php", "wp-login.php", "xmlrpc.php", "wp-signup.php",
        "wp-activate.php", "wp-trackback.php", "wp-comments-post.php",
        "wp-mail.php", "wp-links-opml.php", "wp-config-sample.php",
    }
    assert Source.CORE_ROOT_FILES == core_root
    assert core_root <= Source.PROTECTED
    for path in sorted(core_root):
        with pytest.raises(NotWritableError):
            src.write_bytes(path, b"x")
        src.write_bytes(path, b"x", allow_core=True)
        # Deletion stays clean-files' policy: wp-config-sample.php is junk,
        # and an operator may name a bare core entry point on purpose.
        src.delete(path)
    # wp-config.php is configuration, not core: allow_core never unlocks it.
    with pytest.raises(NotWritableError):
        src.write_bytes("wp-config.php", b"x", allow_core=True)


# ------------------------------------------- the rename destination guard

def test_rename_is_refused_by_default(src):
    """A source that cannot rename must SAY so, never silently degrade
    into "write every file again" (which is the half-updated tree the
    operation exists to avoid).  The ABC default raises."""
    with pytest.raises(NotWritableError, match="cannot rename"):
        src.rename("wp-includes.wpt-new", "wp-includes")


def test_rename_target_guard_is_surgical(src, wpt_records):
    """A rename lands bytes at its destination, so the destination is
    guarded exactly as a write is — with ONE addition: the two bare core
    TREE names, which a write can never legitimately land on but a
    staging swap must (that is what makes the swap one filesystem
    operation).  The unlock is the same audited ``allow_core``, and it
    buys nothing else: the config files stay unrenameable, and the bare
    names still refuse without the flag."""
    import logging

    class Renaming(DummySource):
        def rename(self, src, dst, *, allow_config=False, allow_core=False):
            self._check_rename_target(dst, allow_config, allow_core)
            self.renamed = getattr(self, "renamed", []) + [(src, dst)]

    src = Renaming()
    # the bare tree names: refused without the unlock, audited with it
    for tree in ("wp-admin", "wp-includes"):
        with pytest.raises(NotWritableError, match="rename onto protected"):
            src.rename(f"{tree}.wpt-new", tree)
    src.rename("wp-includes.wpt-new", "wp-includes", allow_core=True)
    src.rename("wp-admin.wpt-new", "wp-admin", allow_core=True)
    warns = [r.getMessage() for r in wpt_records
             if r.name == "wpt.source" and r.levelno == logging.WARNING]
    assert sum("guarded core heal: swapping the protected core tree" in m
               for m in warns) == 2

    # a root file the swap also lands: index.php is the heal surface
    src.rename("index.php.wpt-tmp", "index.php", allow_core=True)
    with pytest.raises(NotWritableError):
        src.rename("index.php.wpt-tmp", "index.php")

    # the config files: the rename guard is EXACTLY as surgical as the
    # write guard and no more — allow_core (the heal unlock) never reaches
    # them, and the config unlock behaves as it does for a write.
    for path in ("wp-config.php", ".htaccess"):
        with pytest.raises(NotWritableError):
            src.rename(f"{path}.wpt-tmp", path)
        with pytest.raises(NotWritableError):
            src.rename(f"{path}.wpt-tmp", path, allow_core=True)
        src.rename(f"{path}.wpt-tmp", path, allow_config=True)

    # user-content paths ignore the flag entirely (same as a write)
    src.rename("wp-content/cache/a", "wp-content/cache/b")


# ------------------------------------------------------- triple-check round 2


@pytest.mark.parametrize("path", [
    "wp-config.php.",
    "wp-config.php ",
    "wp-admin./shell.php",
    "wp-admin /shell.php",
    "wp-content/.. /wp-config.php",
    "wp-includes./version.php",
    "dir./file.php",
])
def test_TYPE1_windows_dot_space_aliases_never_reach_a_protected_name(src, path):
    """TYPE1: Windows strips a segment's trailing dots/spaces, so the alias
    resolved to the protected name while every guard saw a different string."""
    with pytest.raises(SourceError, match="trailing dot/space"):
        src._guard_path(path)
    with pytest.raises(SourceError, match="trailing dot/space"):
        src.write_bytes(path, b"x", allow_config=False)
    with pytest.raises(SourceError, match="trailing dot/space"):
        src.delete(path)
    with pytest.raises(SourceError, match="trailing dot/space"):
        src.rmdir_recursive(path)


def test_TYPE1_canonical_posix_segments_still_normalize(src):
    """The alias rule must not reject the ordinary ``.``/``..`` segments
    normpath owns (``wp-content/./a.txt`` is safe and unchanged)."""
    assert src._guard_path("wp-content/./a.txt") == "wp-content/a.txt"
    assert src._guard_path("wp-content/x/../a.txt") == "wp-content/a.txt"


def test_R6_22_rename_onto_wp_content_requires_the_same_locked_unlock():
    """R6-22: only wp-admin/wp-includes took the locked branch, so a rename
    could REPLACE wp-content without allow_core — exactly the delete-class
    mutation the source-side guard refuses."""
    source = DummySource()
    for name in ("wp-content", "WP-CONTENT"):
        with pytest.raises(NotWritableError):
            source._check_rename_target(name, False, False)
        source._check_rename_target(name, False, True)
