import logging

from wpt.sources.base import WalkMixin
from wpt.types import Entry


class FakeSource(WalkMixin):
    """Only implements list_dir — walk() must come entirely from the mixin.

    Contract: children entries carry FULL relpaths (like the real connectors).
    """

    root = "fake"

    def __init__(self, tree: dict[str, list[Entry]]) -> None:
        self.tree = tree

    def list_dir(self, path: str) -> list[Entry]:
        rel = self._guard_path(path) if path else ""
        return self.tree.get(rel, [])

    def read_bytes(self, path):
        return b""

    def write_bytes(self, path, data, *, allow_config=False):
        self._check_writable(path, allow_config)

    def delete(self, path):
        self._check_deletable(path)

    def rmdir_recursive(self, path):
        self._check_deletable(path)

    def exists(self, path):
        return True

    def size(self, path):
        return 0

    def close(self):
        pass


def sample_tree() -> FakeSource:
    return FakeSource({
        "": [
            Entry("wp-config.php", is_dir=False, size=3000),
            Entry("wp-content", is_dir=True, size=0),
        ],
        "wp-content": [
            Entry("wp-content/uploads", is_dir=True, size=0),
            Entry("wp-content/plugins", is_dir=True, size=0),
            Entry("wp-content/private_html", is_dir=True, size=0, is_link=True),
        ],
        "wp-content/uploads": [
            Entry("wp-content/uploads/2018", is_dir=True, size=0),
            Entry("wp-content/uploads/readme.txt", is_dir=False, size=12),
        ],
        "wp-content/uploads/2018": [
            Entry("wp-content/uploads/2018/03", is_dir=True, size=0),
        ],
        "wp-content/uploads/2018/03": [
            Entry("wp-content/uploads/2018/03/photo.png", is_dir=False, size=100),
        ],
        "wp-content/plugins": [
            Entry("wp-content/plugins/elementor", is_dir=True, size=0),
        ],
        "wp-content/plugins/elementor": [
            Entry("wp-content/plugins/elementor/elementor.php", is_dir=False, size=2000),
        ],
    })


def test_walk_yields_posix_relpaths_including_month_dirs():
    paths = [e.path for e in sample_tree().walk()]
    assert "wp-content/uploads/2018/03/photo.png" in paths  # L9: month dirs recursed
    assert "wp-config.php" in paths
    assert "wp-content/plugins/elementor/elementor.php" in paths


def test_walk_never_follows_symlinked_dirs():
    paths = [e.path for e in sample_tree().walk()]
    assert all("private_html" not in p for p in paths)  # L10: no double-count


def test_walk_is_deterministic_dirs_before_sibling_files():
    src = sample_tree()
    first = [e.path for e in src.walk()]
    second = [e.path for e in src.walk()]
    assert first == second
    assert first.index("wp-content") < first.index("wp-config.php")


def test_walk_with_path_prefix():
    paths = [e.path for e in sample_tree().walk("wp-content/plugins")]
    assert paths == [
        "wp-content/plugins/elementor",
        "wp-content/plugins/elementor/elementor.php",
    ]


# ------------------------------------------------------ progress heartbeat


def test_walk_heartbeat_emits_progress(monkeypatch, wpt_records):
    """[L15] With the heartbeat gates pinned open, one info milestone per
    yielded entry — the live lesson: a ~10-minute SILENT walk is
    indistinguishable from a wedged run, so the operator must see pace."""
    import wpt.sources.base as base

    monkeypatch.setattr(base, "_WALK_HEARTBEAT_EVERY", 1)
    monkeypatch.setattr(base, "_WALK_HEARTBEAT_MIN_S", 0.0)
    paths = [e.path for e in sample_tree().walk()]
    beats = [r.getMessage() for r in wpt_records
             if r.name == "wpt.sources.walk" and r.levelno == logging.INFO]
    assert len(beats) == len(paths)
    assert beats[0].startswith("webroot walk: 1 entries so far")
    assert f"webroot walk: {len(paths)} entries so far" in beats[-1]


def test_walk_fast_walk_stays_silent(wpt_records):
    """The shipped gates keep a fast in-memory walk completely silent
    (the time gate a crawling FTP channel is what the heartbeat is for)."""
    assert len(list(sample_tree().walk())) == 10
    assert not [r for r in wpt_records if r.name == "wpt.sources.walk"]


def test_mixin_requires_source_contract():
    import pytest

    with pytest.raises(TypeError):
        WalkMixin()
