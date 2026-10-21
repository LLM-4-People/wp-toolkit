# Development

## Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev,db,docs]"
```

PHP 8.3+ and OpenSSL are needed for the full suite. The CI matrix runs the full
suite on Linux (Python 3.12–3.15) and macOS, and a wheel/CLI smoke test on
Windows.

## Test loop

```bash
python -m pytest tests/ -q -n auto --dist worksteal
python -m pytest tests/ -q                    # serial fallback
python -m ruff check wpt tests
find wpt -name '*.php' -print0 | xargs -0 -n1 php -l
# the privacy gate walks the working tree, including ignored caches
find . -type d \( -name '__pycache__' -o -name '.pytest_cache' \
  -o -name '.ruff_cache' -o -name '.mypy_cache' \) -prune -exec rm -rf {} +
find . -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
rm -rf build dist site
python scripts/check_public_safety.py
```

The suite uses deterministic fakes for FTP, HTTP, SSH, and MySQL boundaries.
Do not add a test that needs a real host, a real client domain, or ambient
credentials. Bind test servers to loopback, give every wait a bound, and clean
up in a fixture or `finally` block.

## Documentation

```bash
python -m pip install -e ".[docs]"
mkdocs serve
mkdocs build --strict
```

`README.md` is the canonical command table. `SPEC.md` is the binding engineering
contract. `tests/test_docs.py` checks the command table, settings listing, audit
count, and README/SPEC cross-references, so a doc change can fail the suite.

## Packaging

```bash
python -m build
python -m twine check dist/*
python -m pytest tests/test_packaging.py -q
```

The sdist ships the complete runnable test tree, the profile, both PHP payloads,
and the cited research docs. `tests/test_packaging.py` builds in a hermetic copy
so stale `build/` or `*.egg-info` bytes cannot satisfy an assertion.

## Code map

- `wpt/cli.py` — parser, global options, command dispatch.
- `wpt/settings.py` and `wpt/data/profiles/default.json` — one settings owner.
- `wpt/sources/` — FTP and zip source adapters.
- `wpt/audit/` — registered audit checks.
- `wpt/actions/` — registered plan/apply actions.
- `wpt/wpbridge/` and `wpt/php_probe.php` — WordPress runtime bridge and probe.
- `wpt/log.py`, `wpt/config.py` — logging and redaction choke points.
- `wpt/report.py` — report rendering and the shared stdout/stderr sinks.
- `docs/` — public guides; `docs/research/` — verified implementation recipes.

## Release

The maintainer checklist is in
[PUBLISHING.md](https://github.com/LLM-4-People/wp-toolkit/blob/main/PUBLISHING.md).
In short: update `CHANGELOG.md`, run the release gate, tag `vX.Y.Z`, and let the
release workflow build and attach the sdist and wheel.

## Contributing

Read [CONTRIBUTING.md](https://github.com/LLM-4-People/wp-toolkit/blob/main/CONTRIBUTING.md)
and [SPEC.md](https://github.com/LLM-4-People/wp-toolkit/blob/main/SPEC.md) before
opening a pull request. Keep public examples synthetic and free of client data.
