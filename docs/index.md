---
hide:
  - navigation
  - toc
---

<div class="wpt-hero" markdown>

![wpt](assets/logo.svg){ .wpt-hero__logo }

# Audit. Clean. Optimize. Verify.

**WordPress operations from FTP or an offline archive — plan-first,
snapshot-backed, and verified.**

[Quickstart](quickstart.md){ .md-button .md-button--primary }
[Safety model](safety.md){ .md-button }
[View on GitHub](https://github.com/LLM-4-People/wp-toolkit){ .md-button }

</div>

<p class="wpt-badges">
  <img alt="Python 3.12+" src="https://img.shields.io/badge/python-3.12%2B-3776AB?logo=python&logoColor=white">
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-2ea44f">
  <img alt="Status: beta" src="https://img.shields.io/badge/status-beta-f59e0b">
  <img alt="Platform: Linux and macOS" src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-0f766e">
</p>

`wpt` treats a WordPress site as a reproducible artifact: a live FTP webroot or
an offline zip + MySQL dump. It plans every change, snapshots what it touches,
applies only when asked, and verifies the result.

## Two source modes, one contract

<div class="grid cards" markdown>

- :material-server-network: **FTP / FTPS**

    Work against a live webroot even when DNS points somewhere else, with
    TLS verification on by default.

- :material-archive-outline: **Zip + SQL dump**

    Audit and rehearse offline. The original archive stays untouched and is the
    rollback.

- :material-folder-outline: **Local rehearsal**

    Serve and verify a rehearsed zip before publishing it.

</div>

## What it does

<div class="grid cards" markdown>

- :material-shield-search: **38-check audit**

    Core integrity, security, database health, media, performance, and
    configuration — with a Markdown report and a JSON twin.

- :material-wrench-outline: **Clean and optimize**

    Junk files, stale core files, revisions, transients, orphan metadata,
    oversized media, WebP conversion, and hardening.

- :material-backup-restore: **Backup and restore**

    Full-site snapshots with manifests, selected-file rollback, and a
    transactional deploy that streams a webroot over SSH.

- :material-magnify-scan: **Verify**

    Re-walk the site and re-fetch every live reference. Exit non-zero when
    something is broken.

- :material-timer-sand: **Self-bounding**

    Deadlines, circuit breakers, heartbeat progress, and graceful SIGTERM
    handling instead of a run that grinds forever.

- :material-lock-outline: **Secrets stay out of files**

    Passwords come from the environment; one logging path redacts them before
    they reach a log, report, or exception.

</div>

## Quick start

Audit an offline archive and dump:

```bash
wpt --source local --zip site.zip --sql dump.sql audit --report audit.md
```

Preview a cleanup, then apply it:

```bash
wpt --source local --zip site.zip --sql dump.sql clean-files
wpt --source local --zip site.zip --sql dump.sql clean-files --apply --yes
```

!!! warning "Plan first"

    The first command is a dry-run plan. The second applies it. For a live
    site, use `--apply` only after reading the plan and taking a snapshot.

## Safety by default

- **Read-only by default.** No mutation happens without `--apply`.
- **Snapshots for FTP mutations.** Every FTP mutating action snapshots its
  affected scope first; no snapshot means no apply.
- **Local mode rehearses.** It mutates an in-memory overlay and materializes a
  new zip; the original is the rollback.
- **One redaction path.** Credentials never reach a log, report, receipt, or
  exception.
- **Bounded work.** A dead or crawling FTP channel trips a breaker instead of
  holding the run hostage.

[Read the full safety model](safety.md){ .md-button .md-button--primary }
[How the pieces fit](architecture.md){ .md-button }

## Documentation map

- [Quickstart](quickstart.md) — install, first audit, reports, apply.
- [Commands](commands.md) — task-oriented workflows.
- [Safety](safety.md) — plans, snapshots, rollback, local mode.
- [Architecture](architecture.md) — sources, actions, bridge, audit, tests.
- [Development](development.md) — setup, tests, packaging, release.
- [FAQ](faq.md) — platforms, databases, and operational limits.
- [Research](research/R1.md) — verified implementation recipes.

`wpt` is MIT licensed. Copyright © 2026 The wpt authors.
