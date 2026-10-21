# Publishing checklist

This repository is a fresh-history public export. Do not merge or push the
private development history: it contains private operational work that is not
part of the public product.

## Before the first push

The repository URLs point at `github.com/LLM-4-People/wp-toolkit`. If the
repository is renamed or transferred, update the same URLs in
`pyproject.toml`, `mkdocs.yml`, `SECURITY.md`, `CODE_OF_CONDUCT.md`,
`.github/ISSUE_TEMPLATE/config.yml`, and the documentation links.

Run the release gate:

   ```bash
   python -m pytest tests/ -q -n auto --dist worksteal
   python -m ruff check wpt tests
   python -m vulture wpt --min-confidence 80
   # the privacy gate walks the working tree, including ignored caches
   find . -type d \( -name '__pycache__' -o -name '.pytest_cache' \
     -o -name '.ruff_cache' -o -name '.mypy_cache' \) -prune -exec rm -rf {} +
   find . -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
   rm -rf build dist site
   python scripts/check_public_safety.py
   python -m build
   python -m twine check dist/*
   mkdocs build --strict
   ```

1. Confirm that no operational files are staged:

   ```bash
   git status --short --ignored
   git ls-files | rg '(^|/)\.wpt-|\.env|\.pem$|\.key$|\.crt$|\.log$|\.sql$|\.zip$'
   ```

2. Inspect the first commit. The public repository must have one initial
   commit, not a rewritten private history.

## GitHub repository settings

- **Description:** Audit, clean, optimize, and verify WordPress sites from FTP
  or an offline zip + SQL dump.
- **Topics:** `wordpress`, `wordpress-tools`, `cli`, `python`, `audit`,
  `security`, `ftp`, `migration`, `backup`, `devops`.
- **Social preview:** upload `docs/assets/social-preview.png` (1280×640).
- **Actions:** enable workflows.
- **Pages:** deploy from GitHub Actions (the `docs` workflow).
- **Dependabot:** enable version updates (the repository ships a config).
- **Branch protection:** require CI, CodeQL, and dependency review on `main`;
  require a pull request and dismiss stale approvals.
- **Merge policy:** squash merge; delete branches after merge.

## PyPI (optional)

The release workflow is prepared for PyPI Trusted Publishing, but publication is
disabled until configured.

1. Create a PyPI project named `wpt` (or change the distribution name in
   `pyproject.toml` if it is unavailable).
2. Add a trusted publisher for this repository, workflow `release.yml`, and
   environment `pypi`.
3. Create a GitHub environment named `pypi`.
4. Set the repository variable `PYPI_PUBLISH=true` only when you are ready.

The release workflow always builds and attaches artifacts to the GitHub
Release. The PyPI job runs only when that variable is `true`.

## Release

1. Update `CHANGELOG.md` and, if needed, `wpt/__init__.py`.
2. Run the release gate above.
3. Commit the release preparation.
4. Tag `v0.1.0` (or the next semantic version) and push the tag.
5. Confirm the release workflow, artifacts, and optional PyPI publication.

## Credential hygiene

If a password, token, private key, or client identifier was ever committed to a
private tree, rotate it. A public history rewrite does not revoke a credential.
Never add `.wpt-*`, `.env`, certificates, dumps, logs, snapshots, or client
artifacts to this repository.

## Windows

Windows is a wheel/CLI smoke target, not a full-suite target. Do not advertise
the full POSIX test suite as Windows-compatible.
