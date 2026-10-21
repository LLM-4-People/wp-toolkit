"""Shared in-memory test doubles (importable from every test package dir).

FakeSource: in-memory path->bytes Source (WalkMixin) recording every operation
with timestamps; list_dir() derives a one-level listing from the store, so
walk() works like a real connector. FakeResponse/FakeSession: canned
requests doubles — FakeSession plays a scripted response list (FakeResponse
objects, Exception instances, or callables receiving (method, url, kwargs))
and records every post/get call.
"""

import time

from wpt.sources.base import WalkMixin
from wpt.types import Entry, SourceError, SourceLookupError

#: How long a test server's accept loop blocks before noticing ``shutdown()``.
#: The http.server default is 0.5 s, which every test fixture that starts a
#: real server pays again on teardown; 10 ms keeps the same behavior with a
#: negligible shutdown wait. Tests that assert on a *production* server's
#: default must not use this.
SERVE_POLL_INTERVAL_S = 0.01


class FakeSource(WalkMixin):
    """In-memory path->bytes store; records ops as (timestamp, op, path)."""

    root = "fake"

    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.ops: list[tuple[float, str, str]] = []

    def _rec(self, op: str, path: str) -> None:
        self.ops.append((time.monotonic(), op, path))

    def list_dir(self, path):
        rel = path if path else ""
        prefix = f"{rel}/" if rel else ""
        seen: dict[str, Entry] = {}
        for name in self.files:
            if not name.startswith(prefix):
                continue
            rest = name[len(prefix):]
            if "/" in rest:
                child, _, _ = rest.partition("/")
                key = self._join(rel, child)
                if key not in seen:
                    seen[key] = Entry(path=key, is_dir=True, size=0)
            else:
                seen[name] = Entry(path=name, is_dir=False, size=len(self.files[name]))
        return list(seen.values())

    def read_bytes(self, path):
        if path not in self.files:
            raise SourceError(f"no such file: {path}")
        return self.files[path]

    def write_bytes(self, path, data, *, allow_config=False, allow_core=False):
        self._check_writable(path, allow_config, allow_core)
        self._rec("write", path)
        self.files[path] = data

    def delete(self, path, *, allow_config=False, allow_core=False):
        self._check_deletable(path, allow_config, allow_core)
        self._rec("delete", path)
        self.files.pop(path, None)

    def rmdir(self, path):
        self._check_deletable(path)
        if self.list_dir(path):
            raise SourceError(f"directory is not empty: {path}")

    def rmdir_recursive(self, path):
        self._check_deletable(path)

    def exists(self, path):
        self._rec("exists", path)
        return path in self.files

    def size(self, path):
        return len(self.files.get(path, b""))

    def close(self):
        pass


class LookupFailingSource(FakeSource):
    """FakeSource with FTP's missing-DIRECTORY presence contract.

    ``FtpSource.size`` falls back to the parent listing; when BOTH fail it
    raises ``SourceLookupError`` rather than reporting "missing".  A missing
    SUBDIRECTORY is exactly that shape: ``LIST newdir`` answers 550 while
    the grandparent listing succeeds and omits ``newdir``.  ``exists`` and
    ``size`` reproduce that, and ``list_dir`` raises the same 550-shaped
    ``SourceError`` a real server does.
    """

    def _dir_exists(self, path: str) -> bool:
        if not path:
            return True
        prefix = path.rstrip("/") + "/"
        return any(name.startswith(prefix) for name in self.files)

    def list_dir(self, path):
        if path and not self._dir_exists(path):
            raise SourceError(f"ftp listing failed for {path!r}: 550")
        return super().list_dir(path)

    def exists(self, path):
        self._rec("exists", path)
        if path in self.files:
            return True
        parent = path.rpartition("/")[0]
        if parent and not self._dir_exists(parent):
            raise SourceLookupError(
                f"cannot determine whether {path!r} exists: SIZE failed and "
                "the parent listing failed")
        return False

    def size(self, path):
        if path in self.files:
            return len(self.files[path])
        parent = path.rpartition("/")[0]
        if parent and not self._dir_exists(parent):
            raise SourceLookupError(
                f"cannot determine whether {path!r} exists: SIZE failed and "
                "the parent listing failed")
        raise SourceError(f"no such file: {path}")


class FakeResponse:
    """Canned requests.Response double (json() parses .text; lines feed
    iter_lines; content serves binary payloads such as release zips)."""

    def __init__(self, status_code=200, text="", lines=None, content=b""):
        self.status_code = status_code
        self.text = text
        # binary bodies (release zips): .text mirrors requests' decode
        # behavior loosely; tests read .content for byte-exact checks
        self.content = content
        self._lines = [ln if isinstance(ln, bytes) else ln.encode("utf-8")
                        for ln in (lines or [])]
        self.closed = False

    def json(self):
        import json

        return json.loads(self.text)  # json.JSONDecodeError is a ValueError

    def iter_lines(self, chunk_size=512, decode_unicode=False, delimiter=None):
        yield from self._lines

    def close(self):
        self.closed = True


class FakeSession:
    """Records every post/get call and plays a scripted response list.

    Script items: a FakeResponse (returned), an Exception instance (raised),
    or a callable (method, url, kwargs) -> FakeResponse.
    """

    def __init__(self, script=()):
        self.script = list(script)
        self.posts: list[tuple[str, dict]] = []
        self.gets: list[tuple[str, dict]] = []

    def post(self, url, **kwargs):
        self.posts.append((url, kwargs))
        return self._advance("POST", url, kwargs)

    def get(self, url, **kwargs):
        self.gets.append((url, kwargs))
        return self._advance("GET", url, kwargs)

    def _advance(self, method, url, kwargs):
        assert self.script, f"unexpected {method} request to {url}"
        item = self.script.pop(0)
        if callable(item):
            item = item(method, url, kwargs)
        if isinstance(item, Exception):
            raise item
        return item
