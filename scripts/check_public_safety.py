#!/usr/bin/env python3
"""Fail when the public tree contains credentials or identifying fixtures.

This is a release gate, not a general-purpose secret scanner. It deliberately
reports only the category, path, and line; it never echoes a matched value.

The scan covers the working tree, not only ``git ls-files``: a stale cache,
an untracked dump, or a local ``__pycache__`` is exactly the kind of residue
that must not travel in a directory archive even when Git ignores it.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import pathlib
import re
import sys
import urllib.parse

# The gate's own source and its regression test contain pattern strings;
# do not scan them as data.
SKIP_FILES = {"scripts/check_public_safety.py", "tests/test_public_safety.py"}

# Never walk VCS metadata; it is not part of the exported tree.
SKIP_DIRS = {".git"}

# Generated residue: report it and stop walking.  These directories are
# normally gitignored, which is precisely why a working-tree scan must see
# them rather than trusting the index.
GENERATED_DIRS = {
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
}
GENERATED_SUFFIXES = {".pyc", ".pyo", ".egg-info"}

# Operational data must never be tracked or exported.
OPERATIONAL_DIRS = {
    ".wpt-backup", ".wpt-live", ".wpt-cert", ".wpt-cache",
}
OPERATIONAL_FILE_SUFFIXES = {
    ".pem", ".key", ".crt", ".csr", ".p12", ".pfx",
    ".log", ".pid", ".sql", ".dump", ".db", ".sqlite3",
    ".zip", ".tar.gz", ".tgz",
}

BINARY_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".pyc", ".pyo", ".zip", ".gz", ".tgz", ".tar", ".bz2", ".xz",
}

DOC_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)
# These are plugin/PHP version-shaped strings in fixtures, not addresses.
ALLOWED_PUBLIC_IPS = {"5.0.1.1", "6.5.0.2", "7.6.0.1"}

# Hosts reserved for documentation/tests, plus the public project and
# standards hosts the docs legitimately link to.
ALLOWED_DOMAIN_SUFFIXES = (
    "example.com",
    "example.org",
    "example.net",
    "example.test",
    "test",
    "example",
    "invalid",
    "internal",
    "localhost",
    "github.com",
    "github.io",
    "githubusercontent.com",
    "shields.io",
    "pypi.org",
    "python.org",
    "pythonhosted.org",
    "openssl.org",
    "wordpress.org",
    "w.org",
    "wp.org",
    "phpmyadmin.net",
    "mysql.com",
    "sitemaps.org",
    "contributor-covenant.org",
    "keepachangelog.com",
    "semver.org",
    "opensource.org",
    "spdx.org",
    "creativecommons.org",
    "mozilla.org",
    "letsencrypt.org",
    "rfc-editor.org",
    "iana.org",
    "w3.org",
    "schema.org",
    "unpkg.com",
)
ALLOWED_HOSTS = {"not-on-wp.org"}

# Synthetic home-directory account names used by fixtures and docs.  Any
# other /home/<name> (or /Users/<name>) is a local-path disclosure.
ALLOWED_LOCAL_USERS = {
    "acme", "example", "hostaccount", "localuser", "old", "olduser",
    "root", "site", "u", "user", "x",
}

# A bare ``entry.name``, ``log.info``, or ``probe.app`` is a Python/code
# attribute chain, not a hostname.  A URL/``www.`` context overrides this.
CODE_LIKE_TLDS = {"app", "at", "biz", "cat", "cc", "co", "edu", "gov",
                   "id", "info", "jobs", "me", "mil", "mobi", "museum",
                   "name", "pro", "site", "tel", "travel", "tv"}

CODE_HOST_LABELS = {
    "action", "app", "args", "base", "body", "bridge", "bytes", "category", "check",
    "child", "cls", "config", "context", "count", "ctx", "data", "detail",
    "dir", "directory", "entry", "error", "extra", "file", "group", "host",
    "id", "info", "item", "key", "kind", "kwargs", "line", "local", "log",
    "logger", "message", "meta", "mode", "msg", "mtime", "name", "node",
    "obj", "owner", "parent", "path", "plan", "plugin", "post", "probe",
    "rec", "record", "remote", "report", "request", "response", "result",
    "root", "row", "self", "session", "settings", "size", "source", "state",
    "status", "target", "test", "text", "theme", "type", "uid", "url",
    "user", "value", "word",
}

# Include common gTLDs and a broad ccTLD set.  The gate is a release
# backstop, not a full public-suffix implementation; an unknown real TLD
# should be added here with a regression test.
DOMAIN_TLDS = (
    "com", "org", "net", "io", "co", "ai", "app", "dev", "cloud", "xyz",
    "site", "info", "store", "online", "tech", "me", "tv", "cc", "uk",
    "ca", "de", "fr", "nl", "be", "ch", "at", "se", "no", "dk", "fi",
    "pl", "cz", "sk", "hu", "ro", "bg", "gr", "pt", "es", "it", "ie",
    "is", "lu", "mt", "cy", "hr", "si", "rs", "lt", "lv", "ee", "ua",
    "ru", "tr", "il", "ae", "sa", "za", "ng", "ke", "au", "nz", "jp",
    "cn", "hk", "sg", "my", "id", "ph", "th", "vn", "in", "pk", "bd",
    "br", "mx", "ar", "cl", "pe", "us", "gov", "edu", "mil", "biz",
    "name", "pro", "travel", "jobs", "mobi", "cat", "tel", "asia",
)
DOMAIN_RE = re.compile(
    r"(?<![\w.-])"
    r"((?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+"
    r"(?:" + "|".join(DOMAIN_TLDS) + r"))"
    r"(?![\w.-])",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(
    r"(?<![\w.+-])([A-Za-z0-9._%+\-\u0080-\uffff]+@"
    r"([A-Za-z0-9.\-\u0080-\uffff]+\.[A-Za-z\u0080-\uffff]{2,}))"
)
# A URL's hostname must be checked even when the host is preceded by "/" in
# the URL itself; the DOMAIN_RE path-context filter must not hide it.
URL_RE = re.compile(r"https?://[^\s<>\"'`\\]+", re.IGNORECASE)
# IDN labels are not matched by DOMAIN_RE's ASCII label class.  This
# companion catches a bare Unicode domain; URL_RE handles Unicode hosts in
# URLs, including a host with a port or a path.
IDN_DOMAIN_RE = re.compile(
    r"(?<![\w.-])((?:[^\W\d_][\w-]*\.)+[A-Za-z\u0080-\uffff]{2,})"
    r"(?![\w.-])",
    re.UNICODE,
)
IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
URL_IPV6_RE = re.compile(r"https?://\[([0-9A-Fa-f:]+)\]")
HOME_PATH_RE = re.compile(
    r"(?<![\w/])(?:/home|/Users|/export/home)/([A-Za-z0-9._-]+)"
    r"(?=/|$|[\s\"'`])"
)
WINDOWS_HOME_RE = re.compile(
    r"\b[A-Za-z]:\\Users\\([A-Za-z0-9._-]+)(?=\\|$|\s)"
)


def _host_allowed(host: str) -> bool:
    host = host.strip().lower().rstrip(".")
    if not host:
        return True
    if host in ALLOWED_HOSTS:
        return True
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    return any(
        ascii_host == suffix or ascii_host.endswith("." + suffix)
        for suffix in ALLOWED_DOMAIN_SUFFIXES
    )


def _is_documentation_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified:
        return True
    return any(ip in network for network in DOC_NETWORKS)


def _artifact_findings(root: pathlib.Path) -> list[tuple[str, str, int, str]]:
    """Report generated/operational paths anywhere in the working tree."""
    findings: list[tuple[str, str, int, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        current = pathlib.Path(dirpath)
        rel_dir = current.relative_to(root)
        for name in list(dirnames):
            rel = (rel_dir / name).as_posix()
            if name in SKIP_DIRS:
                dirnames.remove(name)
                continue
            if name in OPERATIONAL_DIRS:
                findings.append(("P0", rel, 1, "operational directory"))
                dirnames.remove(name)
                continue
            if name in GENERATED_DIRS or name.endswith(".egg-info"):
                findings.append(("P1", rel, 1, "generated cache/artifact directory"))
                dirnames.remove(name)
        for name in sorted(filenames):
            rel_path = rel_dir / name
            rel = rel_path.as_posix()
            if name == ".env" or name.startswith(".env."):
                findings.append(("P0", rel, 1, "environment file"))
            if name.endswith(tuple(OPERATIONAL_FILE_SUFFIXES)):
                findings.append(("P0", rel, 1, "secret/operational artifact"))
            if name.endswith(tuple(GENERATED_SUFFIXES)):
                findings.append(("P1", rel, 1, "generated bytecode/cache artifact"))
    return findings


def _iter_text_files(root: pathlib.Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            name for name in dirnames
            if name not in SKIP_DIRS
            and name not in GENERATED_DIRS
            and name not in OPERATIONAL_DIRS
            and not name.endswith(".egg-info")
        )
        current = pathlib.Path(dirpath)
        for name in sorted(filenames):
            path = current / name
            rel = path.relative_to(root).as_posix()
            if rel in SKIP_FILES:
                continue
            if path.suffix.lower() in BINARY_SUFFIXES:
                continue
            yield path, rel


def _scan_text(
    rel: str,
    text: str,
) -> list[tuple[str, str, int, str]]:
    findings: list[tuple[str, str, int, str]] = []
    lines = text.splitlines()

    secret_patterns = (
        ("private-key block", re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
        ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
        ("GitHub fine-grained token", re.compile(
            r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
        ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
        ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
        ("Stripe live key", re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b")),
        ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
        ("JWT-like token", re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    )

    for number, line in enumerate(lines, 1):
        for label, pattern in secret_patterns:
            if pattern.search(line):
                findings.append(("P0", rel, number, label))

        for match in DOMAIN_RE.finditer(line):
            host = match.group(1).lower()
            prefix = line[max(0, match.start() - 16):match.start()].lower()
            url_context = "://" in prefix or prefix.endswith("www.")
            first = host.split(".", 1)[0]
            tld = host.rsplit(".", 1)[-1]
            path_context = (
                match.start() > 0 and line[match.start() - 1] == "/"
                or bool(re.search(r"\d{4}/\d{2}/", line[max(0, match.start() - 12):match.start()]))
            )
            # A leading "/" is a path for a fixture like 2023/10/file.xyz,
            # but it is also the separator in https://host/; never let that
            # hide a URL's hostname.
            if path_context and not url_context:
                continue
            if (not url_context
                    and (len(first) <= 1 or first in CODE_HOST_LABELS
                         or tld in CODE_LIKE_TLDS)):
                continue
            if not _host_allowed(host):
                findings.append(("P1", rel, number, "non-reserved domain"))

        # Unicode domains are invisible to DOMAIN_RE.  Scan bare IDN labels
        # too; _host_allowed applies IDNA before the reserved-suffix check.
        for match in IDN_DOMAIN_RE.finditer(line):
            host = match.group(1).lower()
            if not any(ord(ch) > 127 for ch in host):
                continue
            tld = host.rsplit(".", 1)[-1]
            # A non-ASCII TLD is a real IDN suffix even though the ASCII
            # TLD table cannot list it; a filename suffix like .jpg is
            # still not a domain.
            if (tld not in DOMAIN_TLDS
                    and tld not in {"example", "test", "invalid", "internal",
                                    "localhost"}
                    and not any(ord(ch) > 127 for ch in tld)):
                continue
            if not _host_allowed(host):
                findings.append(("P1", rel, number, "non-reserved domain"))

        # Parse URL hosts explicitly: this covers ASCII hosts behind a "/",
        # Unicode hosts, ports, and hosts that DOMAIN_RE's TLD table omits.
        for match in URL_RE.finditer(line):
            try:
                hostname = urllib.parse.urlsplit(match.group(0)).hostname
            except ValueError:
                continue
            if not hostname:
                continue
            literal = hostname.strip().rstrip(".")
            # Templates, command examples, and single-label placeholders
            # (``https://host``) are not public domains.  Require a dotted
            # literal hostname before applying the reserved-suffix policy.
            if "." not in literal or any(
                    ch in literal for ch in "{}(),;%…"):
                continue
            try:
                ipaddress.ip_address(literal)
            except ValueError:
                if not _host_allowed(literal):
                    findings.append(("P1", rel, number, "non-reserved domain"))
            # An IP host is handled by IP_RE; do not duplicate it here.

        for match in EMAIL_RE.finditer(line):
            host = match.group(2).lower()
            if not _host_allowed(host):
                findings.append(("P1", rel, number, "non-example email domain"))

        for match in IP_RE.finditer(line):
            value = match.group(0)
            if value in ALLOWED_PUBLIC_IPS:
                continue
            if not _is_documentation_ip(value):
                findings.append(("P1", rel, number, "public IP fixture"))

        for match in URL_IPV6_RE.finditer(line):
            value = match.group(1)
            try:
                ipaddress.ip_address(value)
            except ValueError:
                continue
            if not _is_documentation_ip(value):
                findings.append(("P1", rel, number, "public IPv6 URL fixture"))

        for pattern in (HOME_PATH_RE, WINDOWS_HOME_RE):
            for match in pattern.finditer(line):
                if match.group(1).lower() not in ALLOWED_LOCAL_USERS:
                    findings.append(("P1", rel, number, "local home-directory path"))

    return findings


def scan(root: pathlib.Path) -> tuple[list[tuple[str, str, int, str]], int]:
    findings = _artifact_findings(root)
    text_files = 0
    for path, rel in _iter_text_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        text_files += 1
        findings.extend(_scan_text(rel, text))

    # Duplicate findings are noise; keep the first occurrence per location/kind.
    unique: dict[tuple[str, int, str], tuple[str, str, int, str]] = {}
    for finding in findings:
        severity, rel, line, message = finding
        unique.setdefault((rel, line, message), finding)
    return list(unique.values()), text_files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[1],
        help="repository root to scan",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        print(f"public safety scan: root is not a directory: {root}", file=sys.stderr)
        return 2

    findings, text_files = scan(root)
    if findings:
        print(
            f"public safety scan FAILED: {len(findings)} finding(s) "
            f"across {text_files} text file(s)",
            file=sys.stderr,
        )
        for severity, rel, line, message in findings:
            print(f"{severity} {rel}:{line}: {message}", file=sys.stderr)
        return 1

    print(f"public safety scan: clean ({text_files} text files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
