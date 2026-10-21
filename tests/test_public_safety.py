"""The public tree must stay free of credentials and identifying fixtures."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "scripts" / "check_public_safety.py"


def _scan(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCANNER), "--root", str(root)],
        capture_output=True,
        text=True,
        timeout=120,
    )


def _clean_copy(tmp_path: Path) -> Path:
    """A copy of the source tree without local caches or VCS metadata."""
    target = tmp_path / "public"
    shutil.copytree(
        ROOT,
        target,
        ignore=shutil.ignore_patterns(
            ".git",
            "__pycache__",
            ".pytest_cache",
            ".ruff_cache",
            ".mypy_cache",
            ".tox",
            ".venv",
            "venv",
            "env",
            "build",
            "dist",
            "site",
            "node_modules",
            "htmlcov",
            "*.egg-info",
            "*.pyc",
        ),
    )
    return target


def test_public_tree_passes_the_safety_scan(tmp_path):
    result = _scan(_clean_copy(tmp_path))
    assert result.returncode == 0, result.stdout + result.stderr


def test_scanner_rejects_identifying_fixtures(tmp_path):
    bad = tmp_path / "bad.md"
    bad.write_text(
        "\n".join(
            [
                "https://" + "client" + ".uk/path",
                "https://" + "real" + ".cloud/path",
                "https://" + "real" + ".de/path",
                "contact: " + "user@" + "acme" + "-corp.com",
                "resolver: " + "1.1." + "1.1",
                "token: " + "gh" + "p_" + "A" * 36,
                "home: " + "/home/" + "notallowed" + "/secret",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    result = _scan(tmp_path)
    assert result.returncode == 1, result.stdout + result.stderr
    for category in (
        "non-reserved domain",
        "non-example email domain",
        "public IP fixture",
        "GitHub token",
        "local home-directory path",
    ):
        assert category in result.stderr, result.stderr
    # A failure must not echo the matched client value into CI logs.
    assert "real.cloud" not in result.stderr
    assert "notallowed" not in result.stderr


def test_scanner_accepts_reserved_fixtures(tmp_path):
    good = tmp_path / "good.md"
    good.write_text(
        "\n".join(
            [
                "https://site.test/path",
                "contact: admin@example.com",
                "resolver: 192.0.2.10",
                "dns: 2001:db8::1",
                "home: /home/olduser/public_html",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    result = _scan(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


def test_scanner_rejects_generated_caches(tmp_path):
    cache = tmp_path / "__pycache__"
    cache.mkdir()
    (cache / "settings.cpython-313.pyc").write_bytes(b"not text")
    result = _scan(tmp_path)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "generated cache/artifact directory" in result.stderr


def test_scanner_rejects_untracked_operational_files_without_git(tmp_path):
    (tmp_path / "site.sql").write_text("CREATE TABLE t (id int);\n", encoding="utf-8")
    result = _scan(tmp_path)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "secret/operational artifact" in result.stderr

def test_scanner_rejects_url_only_and_idn_domains(tmp_path):
    """A URL's hostname cannot be hidden by the "/" path filter, and an
    IDN host (ASCII-invisible to DOMAIN_RE) is still a real domain."""
    bad = tmp_path / "url.md"
    bad.write_text(
        "https://" + "client" + ".uk/path\n"
        + "https://" + "m\u00e4rchen" + "b\u00fccher" + ".de/x\n"
        + "m\u00e4rchen" + "b\u00fccher" + ".de\n"
        + "Gr\u00fc\u00dfe " + "m\u00e4rchen" + "b\u00fccher" + ".de\n"
        + "\u043f\u0440\u0438\u043c\u0435\u0440.\u0440\u0444\n",
        encoding="utf-8",
    )
    result = _scan(tmp_path)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "non-reserved domain" in result.stderr
    assert "client.uk" not in result.stderr
    assert "m\u00e4rchen" not in result.stderr


def test_scanner_accepts_reserved_idn_url(tmp_path):
    good = tmp_path / "idn.md"
    good.write_text(
        "https://" + "m\u00e4rchen" + "b\u00fccher" + ".example/path\n",
        encoding="utf-8",
    )
    result = _scan(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr

def test_scanner_rejects_a_domain_that_appears_only_in_a_url(tmp_path):
    """The gate's path filter must not let an email or another fixture be
    the only thing that makes a URL-only client host fail."""
    bad = tmp_path / "url-only.md"
    bad.write_text(
        "see https://" + "client" + ".uk/path\n",
        encoding="utf-8",
    )
    result = _scan(tmp_path)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "non-reserved domain" in result.stderr
