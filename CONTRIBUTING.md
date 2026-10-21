# Contributing

Thanks for improving `wpt`. This project handles production websites, so the
bar for safety, test coverage, and documentation is deliberately high.

## Ground rules

- **Never commit client data, credentials, dumps, logs, certificates, or
  operational snapshots.** Use synthetic values: `example.test`,
  `example.com`, `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`.
- **One source of truth.** Settings live in `wpt/data/profiles/default.json` and
  `wpt/settings.py`; the README command table is the canonical command list;
  `SPEC.md` is the binding engineering contract.
- **One logging and output path.** Diagnostics go through
  `wpt.log.get_logger` (never `logging.getLogger`, a handler, or a direct
  stderr write). Command reports go through `wpt.report.write_stdout` /
  `write_stderr`; only `wpt/cli.py` may print directly.
- **Every bug gets a regression test.** Reproduce it first, then add the
  smallest test that would have caught it.
- **No workarounds.** Fix the owner of the failure, not a caller or a symptom.
- **Keep changes cohesive.** One logical change per pull request; update docs
  and changelog with behavior changes.

## Setup

Requirements: Python 3.12+, PHP 8.3+ (for bridge and PHP probe tests), OpenSSL,
and a POSIX shell for the full suite.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev,db]"
```

For the documentation site:

```bash
python -m pip install -e ".[docs]"
```

## Tests and checks

Run the full suite before opening a pull request:

```bash
python -m pytest tests/ -q -n auto --dist worksteal
python -m pytest tests/ -q                    # serial fallback
python -m ruff check wpt tests
python -m vulture wpt --min-confidence 80
find wpt -name '*.php' -print0 | xargs -0 -n1 php -l
# remove generated residue before the working-tree privacy gate
find . -type d \( -name '__pycache__' -o -name '.pytest_cache' \
  -o -name '.ruff_cache' -o -name '.mypy_cache' \) -prune -exec rm -rf {} +
find . -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
rm -rf build dist site
python scripts/check_public_safety.py
```

Packaging and docs:

```bash
python -m build
python -m twine check dist/*
mkdocs build --strict
```

The suite uses deterministic fakes for FTP, HTTP, SSH, and MySQL boundaries.
Do not add tests that require a real third-party host, a real client domain, or
ambient credentials. If a test needs a server, bind to loopback and clean it up
with a bounded timeout.

## Test design

- Assert observable behavior and invariants, not implementation details.
- Cover happy paths, boundaries, invalid input, failure paths, and improper
  usage.
- Add integration tests for persistence, I/O, protocols, and cross-module
  contracts.
- Add concurrency/lifecycle tests for background work, cancellation, timeouts,
  and shutdown.
- Keep every test deterministic, isolated, and bounded by a timeout.

## Documentation

- Update `README.md` when the command surface, global flags, or safety contract
  changes. `tests/test_docs.py` mechanically checks the command table, settings
  listing, audit count, and README/SPEC cross-references.
- Update `SPEC.md` when an interface, invariant, or residual risk changes.
- Update `CHANGELOG.md` under `Unreleased` for user-visible changes.
- Keep public examples synthetic and free of real sites or people.

## Pull requests

Include:

1. What changed and why.
2. The failing reproduction or the invariant being strengthened.
3. The tests that cover it.
4. The commands you ran and their result.
5. Any residual risk, unsupported platform, or blocked live validation.

Small, focused pull requests are easier to review than broad rewrites. Do not
include unrelated formatting churn.

## Security

Do not report a vulnerability in a public issue. Follow
[SECURITY.md](SECURITY.md). If you accidentally expose a credential, remove it
from the working tree, rotate it, and tell the maintainers immediately; a
history rewrite alone is not remediation.

## Platform notes

The full suite is POSIX. Linux is the primary CI target, macOS is the
compatibility target, and Windows is a wheel/CLI smoke target. Do not add a
Windows-only test that depends on POSIX paths, FIFOs, `/proc`, `O_DIRECTORY`,
or signal semantics.

## License

By contributing, you agree that your contribution is licensed under the MIT
License in [LICENSE](LICENSE).
