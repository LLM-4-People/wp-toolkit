"""Packaging contract: the sdist ships the COMPLETE runnable test tree."""

import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile

ROOT = pathlib.Path(__file__).resolve().parents[1]

#: Build artifacts that must never leak into a packaging source copy: a
#: stale ``build/``/``*.egg-info`` makes the sdist/wheel tests pass on bytes
#: the source tree no longer has (R15-P2).
_BUILD_IGNORE = shutil.ignore_patterns(
    "build", "dist", "*.egg-info", "__pycache__", ".git", ".pytest_cache",
    ".wpt-cache", ".wpt-backup", ".wpt-cert", "*.pyc")


def _build_source(tmp_path: pathlib.Path) -> pathlib.Path:
    """A hermetic COPY of the repository for one build.

    Both packaging tests run ``python -m build`` in this copy, never in the
    working tree: a retained ``build/lib`` or ``wpt.egg-info`` silently
    satisfied assertions from bytes the current sources had deleted, and
    the two tests raced each other under ``-n``.
    """
    target = tmp_path / "source"
    shutil.copytree(ROOT, target, ignore=_BUILD_IGNORE)
    return target


def test_R15_build_source_never_copies_stale_artifacts(tmp_path, monkeypatch):
    """R15-P2: the packaging tests ran ``build`` in the working tree, so a
    retained ``build/lib``/``*.egg-info`` satisfied assertions from bytes
    the current sources had deleted.  The copy is the fix's owner: prove
    those names never reach it."""
    module = sys.modules[__name__]
    repo = tmp_path / "repo"
    (repo / "wpt").mkdir(parents=True)
    (repo / "wpt" / "real.py").write_text("REAL = True\n", encoding="utf-8")
    (repo / "tests").mkdir()
    (repo / "tests" / "test_real.py").write_text("", encoding="utf-8")
    stale_wheel = repo / "build" / "lib" / "wpt" / "php_probe.php"
    stale_wheel.parent.mkdir(parents=True)
    stale_wheel.write_text("STALE", encoding="utf-8")
    (repo / "wpt.egg-info").mkdir()
    (repo / "wpt.egg-info" / "SOURCES.txt").write_text(
        "stale\n", encoding="utf-8")
    (repo / "__pycache__").mkdir()

    monkeypatch.setattr(module, "ROOT", repo)
    copied = _build_source(tmp_path / "copy")

    assert (copied / "wpt" / "real.py").is_file()
    assert (copied / "tests" / "test_real.py").is_file()
    assert not (copied / "build").exists()
    assert not (copied / "wpt.egg-info").exists()
    assert not (copied / "__pycache__").exists()


REQUIRED = (
    "tests/__init__.py",
    "tests/conftest.py",
    "tests/fakes.py",
    "tests/actions/__init__.py",
    "tests/actions/test_clean_files.py",
    "tests/audit/__init__.py",
    "tests/audit/test_source_scan.py",
    "tests/sources/__init__.py",
    "tests/sources/test_zip.py",
)


def test_R7_P2_25_sdist_ships_a_runnable_test_tree(tmp_path):
    """R7-P2-25: the built sdist carried 30 root ``test*.py`` files but no
    ``tests/__init__.py``/``conftest.py``/``fakes.py`` or subpackages, so an
    extracted sdist could not collect its own tests (16 errors).  R14: the
    contract is EVERY repo test module, not a hand-picked sample."""
    out = tmp_path / "dist"
    out.mkdir()
    source_root = _build_source(tmp_path)
    subprocess.run(
        [sys.executable, "-m", "build", "--sdist", "--no-isolation",
         "--outdir", str(out)],
        cwd=source_root, check=True, capture_output=True, text=True,
        timeout=180,
    )
    archives = list(out.glob("*.tar.gz"))
    assert len(archives) == 1, archives
    with tarfile.open(archives[0]) as archive:
        names = archive.getnames()
        prefix = names[0].split("/", 1)[0] + "/"
        shipped = {name[len(prefix):] for name in names
                   if name.startswith(prefix)}
        repo_tests = sorted(
            path.relative_to(source_root).as_posix()
            for path in (source_root / "tests").rglob("*.py"))
        assert repo_tests
        missing = [path for path in repo_tests if path not in shipped]
        assert not missing, missing
        assert all(path in shipped for path in REQUIRED), (
            [path for path in REQUIRED if path not in shipped])
        # SPEC cites docs/research/R*.md as BINDING recipes; an sdist that
        # shipped the contract without them handed the reader dangling
        # references (R16-P2).
        shipped_docs = {path for path in shipped
                        if path.startswith("docs/")}
        assert "docs/research/R1.md" in shipped_docs
        spec_text = (source_root / "SPEC.md").read_text(encoding="utf-8")
        cited = set(re.findall(r"docs/research/[A-Za-z0-9_-]+\.md",
                               spec_text))
        assert cited, "SPEC cites no research docs"
        missing_docs = sorted(path for path in cited
                              if path not in shipped)
        assert not missing_docs, missing_docs
        extracted = tmp_path / "src"
        archive.extractall(extracted, filter="data")

    root = extracted / prefix.rstrip("/")
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        [str(root), env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
    collected = subprocess.run(
        [sys.executable, "-m", "pytest", "tests", "--collect-only", "-q",
         "-p", "no:cacheprovider"],
        cwd=root, env=env, capture_output=True, text=True, timeout=180,
    )
    assert collected.returncode == 0, collected.stdout[-4000:] + \
        collected.stderr[-2000:]
    assert "tests collected" in collected.stdout


def test_R14_P2_wheel_installs_the_profile_php_payloads_and_entrypoint(
        tmp_path):
    """R14: the packaging test only sampled an sdist.  Build and INSTALL a
    wheel: the packaged profile, both PHP payloads and the console script
    must work from the installed layout, not only from the source tree."""
    out = tmp_path / "dist"
    out.mkdir()
    source_root = _build_source(tmp_path)
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--no-isolation",
         "--outdir", str(out)],
        cwd=source_root, check=True, capture_output=True, text=True,
        timeout=180,
    )
    wheels = list(out.glob("*.whl"))
    assert len(wheels) == 1, wheels
    site = tmp_path / "site"
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "--no-deps", "--no-compile",
         "--target", str(site), str(wheels[0])],
        cwd=source_root, check=True, capture_output=True, text=True,
        timeout=180,
    )
    assert (site / "wpt" / "data" / "profiles" / "default.json").is_file()
    assert (site / "wpt" / "php_probe.php").is_file()
    assert (site / "wpt" / "wpbridge" / "bridge.php").is_file()
    env = os.environ.copy()
    env["PYTHONPATH"] = str(site)
    env.pop("PYTHONSAFEPATH", None)
    version = subprocess.run(
        [sys.executable, str(site / "bin" / "wpt"), "--version"],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60,
    )
    assert version.returncode == 0, version.stderr
    assert version.stdout.startswith("wpt "), version.stdout
    # The installed package must LOAD the profile it shipped, not a
    # source-tree path that happens to exist on this machine.
    loaded = subprocess.run(
        [sys.executable, "-c",
         "from wpt.settings import load; print(load().run.deadline_s)"],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60,
    )
    assert loaded.returncode == 0, loaded.stderr
    assert loaded.stdout.strip().isdigit()


def test_R8_P2_24_python_sources_compile_without_syntax_warnings():
    """R8-P2-24: an invalid ``\\?`` escape in harden.py and its test made
    the whole suite emit SyntaxWarning.  A shipped source that warns under
    ``-W error::SyntaxWarning`` is a latent compile failure."""
    import warnings

    sources = sorted(ROOT.glob("wpt/**/*.py")) + sorted(
        ROOT.glob("tests/**/*.py"))
    assert sources
    for path in sources:
        with warnings.catch_warnings():
            warnings.simplefilter("error", SyntaxWarning)
            compile(path.read_text(encoding="utf-8"), str(path), "exec")


def test_R8_P2_29_dev_extras_declare_the_build_toolchain():
    """R8-P2-29: test_packaging runs ``python -m build --no-isolation`` but
    the dev extras omitted ``build``/``setuptools``; the suite passed only
    on this host's user-site install."""
    import re
    import tomllib

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(
        encoding="utf-8"))
    extras = project["project"]["optional-dependencies"]["dev"]
    names = {
        re.split(r"[<>=!~; ]", spec, maxsplit=1)[0].lower()
        for spec in extras
    }
    assert {"build", "setuptools", "wheel"} <= names
    # The DECLARED build floor must itself provide bdist_wheel: a fresh venv
    # with setuptools==69 (declared) and no wheel failed
    # ``python -m build --wheel --no-isolation`` before this pin.
    build_requires = project["build-system"]["requires"]
    build_names = {
        re.split(r"[<>=!~; ]", spec, maxsplit=1)[0].lower()
        for spec in build_requires
    }
    assert "wheel" in build_names, build_requires
