## Summary

<!-- What changed, and why? Link the issue or reproduction. -->

## Type

- [ ] Bug fix (with a regression test)
- [ ] Feature
- [ ] Documentation
- [ ] Packaging, CI, or release
- [ ] Refactor with no behavior change

## Verification

<!-- List the commands you ran and their result. -->

```bash
python -m pytest tests/ -q -n auto --dist worksteal
python -m ruff check wpt tests
python scripts/check_public_safety.py
```

- [ ] The full test suite passes.
- [ ] `ruff` passes.
- [ ] `scripts/check_public_safety.py` passes.
- [ ] PHP files pass `php -l` (if changed).
- [ ] `python -m build` and `twine check` pass (if packaging changed).
- [ ] `mkdocs build --strict` passes (if docs changed).

## Safety

- [ ] No credentials, client domains, account IDs, personal data, dumps, logs,
      certificates, or operational snapshots are included.
- [ ] Mutating behavior remains plan-first, snapshot-backed, and fail-closed.
- [ ] Destructive paths, rollback, and failure modes are covered by tests.
- [ ] README/SPEC/CHANGELOG are updated where behavior or contracts changed.

## Notes

<!-- Residual risk, unsupported platform, or blocked live validation. -->
