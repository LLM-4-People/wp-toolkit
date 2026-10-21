# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-10-21

### Added

- A single `wpt` CLI for WordPress audit, cleanup, optimization, backup,
  restore, verification, and migration workflows.
- Live FTP/FTPS and offline zip + SQL dump source modes, plus a local rehearsal
  mode that never mutates the original archive.
- A 38-check read-only audit covering core integrity, security, database
  health, media, performance, and configuration.
- Plan-first destructive actions with `--apply`, interactive confirmation, and
  fail-closed snapshots for FTP mutations.
- Full-site backup and restore, selected-file backup/edit/rollback, and a
  transactional deploy command that streams a webroot over SSH.
- Local TLS proxy for pre-migration DNS override, plus a doctor preflight
  command for connectivity, TLS, PHP, bridge, and write-access checks.
- Markdown reports with JSON twins, baselines for change-only review, and
  suggested next steps for each finding.
- Self-bounding runs with deadlines, circuit breakers, heartbeat progress, and
  graceful SIGTERM handling.
- A public documentation site, GitHub Actions CI, CodeQL, dependency review,
  release automation, and issue/PR templates.

### Security

- Passwords are read from environment variables (or prompts), never from files
  or command lines.
- One logging path redacts credentials before they reach the console, a file,
  a report, or an exception.
- Operational snapshots, certificates, dumps, and logs are excluded from
  source control and the published package.

### Documentation

- New quickstart, command workflows, safety model, architecture, development,
  and FAQ guides.
- The binding engineering contract remains in `SPEC.md`; README command and
  settings claims are mechanically checked by the test suite.

### Known limitations

- The full test suite is POSIX. Windows is covered by a wheel/CLI smoke test;
  POSIX-only paths and process semantics are not exercised there.
- Plugin/theme updates and multisite support are out of scope for v1.
- Live FTP, SSH, and MySQL validation requires operator-supplied credentials
  and a reachable site; the test suite uses deterministic fakes for those
  boundaries.
