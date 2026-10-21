# wp-toolkit

**Audit, clean, optimize, and verify WordPress sites — from FTP or an offline
zip + SQL dump.**

<p>
  <img alt="Python 3.12+" src="https://img.shields.io/badge/python-3.12%2B-3776AB?logo=python&logoColor=white">
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-2ea44f">
  <img alt="Status: beta" src="https://img.shields.io/badge/status-beta-f59e0b">
  <img alt="Platform: Linux and macOS" src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-0f766e">
</p>

`wpt` is a Python 3.12+ command-line toolkit for WordPress site operations. It
treats a site as a reproducible artifact: a live FTP webroot, an offline zip +
MySQL dump. Every command plans first, mutates only on
request, snapshots what it touches, and verifies the result.

It is built for migrations, incident response, and recurring maintenance — the
moments when a site is too important for an unverified one-liner.

## Why wpt

- **Plan, then apply.** Every mutating command prints a dry-run plan. `--apply`
  executes it; `--yes` skips the interactive confirmation.
- **Snapshots and rollback.** FTP mutations snapshot their affected scope first
  (fail-closed). Local mode rehearses into a new zip and leaves the original
  untouched.
- **One audit, 38 checks.** Core integrity, security, database health, media,
  performance, and configuration — with a Markdown report and a JSON twin.
- **Works offline.** Audit and rehearse from a zip + SQL dump with no live
  server, then deploy or verify when the site is reachable.
- **Self-bounding.** Deadlines, circuit breakers, and graceful SIGTERM handling
  keep a bad FTP channel from turning into an all-day run.
- **Secrets stay out of files.** Passwords normally come from environment
  variables or prompts, and the single logging path redacts them before they
  reach a log, report, or exception. An inline `--db-uri` password is accepted
  for compatibility, but it is visible in shell history; use
  `--db-password-env` instead.

## Install

From a checkout of this repository:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[db]"
wpt --version
```

The `db` extra enables offline `--db-uri` operations and the re-dump writer.
When published, the same install is available as `pip install "wpt[db]"`.

Requirements: Python 3.12+, PHP 8.3+ for the bridge and PHP probes, and
OpenSSL for the local proxy certificate. The full test suite is POSIX; Windows
is covered by a wheel/CLI smoke test.

## Quick start

Audit an offline archive and dump:

```bash
wpt --source local --zip site.zip --sql dump.sql audit --report audit.md
```

Audit a live site without changing DNS:

```bash
export FTP_PASS='...'
wpt --source ftp://host:21 --user U --password-env FTP_PASS \
    --webroot domains/site/public_html --wp-url https://site.test \
    --override-ip 192.0.2.44 audit --report audit.md
```

Preview and apply a cleanup:

```bash
wpt --source local --zip site.zip --sql dump.sql clean-files
wpt --source local --zip site.zip --sql dump.sql clean-files --apply --yes
```

The first command is a plan. The second executes it. `--report` writes the
human-readable report plus a JSON twin for automation.

## Logging and global options

Every command accepts `--log-level`, `--log-file PATH` (adds a file sink; the
console keeps receiving everything), `--log-json`, and `--quiet` (console
only). The other global options are `--version`, `--profile PATH` (a settings
overlay), `--set key=value` (repeatable), `--backup-dir DIR`, and
`--db-password-env VAR` (the password for `--db-uri`).

There is one logger, two handlers, and the same redaction filter on both. A
refusal is never only in the file: the console and the report agree.

## Commands

Every command works from either source unless its row says otherwise. Run
`wpt <command> --help` for the full flag set.

Self-bounding runs (never killed from outside): every command accepts
`--deadline SECONDS` (default `run.deadline_s` = 3600; `0` = unbounded) and
ends ITSELF through the normal error contract when the budget expires —
cleanup, teardown, rc 1. SIGTERM is likewise a cooperative stop the run
answers gracefully. The two long-running listeners are the deliberate
exception: `serve` and `proxy` own their process until interrupted, so
`--deadline` does not stop their accept loop (SIGTERM still ends both
cleanly through the same teardown). Bulk FTP reads run through
`ftp.parallel_reads` (default 4) dedicated worker sessions with two channel
bounds: a consecutive-failure breaker and a slow-op window (10 near-timeout
ops = trip), so both a dead and a merely crawling passive channel end in
minutes instead of hours.

The command set (all work from either source unless noted):

| command | what it does |
|---|---|
| `audit` | Full read-only audit (38 checks); `--only` / `--skip` select checks (an unknown or mode-inapplicable name fails loud, never an empty report); `--baseline prev.json` diffs against a previous run (NEW / resolved / changed, naming the fields that differ: detail, count, risk, bytes); writes markdown + JSON with `--report` |
| `updates` | The audit restricted to core/plugin/theme update checks |
| `clean-files` | Delete junk/backup/stale/migration files from the webroot |
| `clean-db` | Named DB cleanups via the bridge (revisions, transients, orphan meta, ...); offline against a direct database with `--db-uri` (needs `PyMySQL`), `--re-dump` writes a fresh dump — **FTP only for the bridge**; `--db-uri` runs the same plan offline in local mode |
| `prune-core` | Delete STALE WordPress core files the current release no longer ships — proven by the previous release's checksums or a `core_integrity.known_stale` signature; unknown files stay investigate-only (snapshot first, survivors re-walked after) |
| `park-backups` | Move full-site backup payloads (`*.zip`, `*.tar.gz`, dead duplicate webroots, …) OUT of the document root — never deletes them; degrades to advice without a provable reference set or an outside destination |
| `cull-media` | Delete oversized image DERIVATIVES of dead stem families (measured, fail-closed, never resizes) — **FTP only** |
| `webp-media` | Convert uploads rasters to WebP **and rewrite every reference** (posts/postmeta/options rows, `sizes[*].file` basenames, generated CSS `url()`); animated/CMYK/>16383px/tiny/data-tree/duplicate images are skipped with a report line, originals are KEPT unless `--purge-originals` deletes them after the rewritten set verifies |
| `update-core` | Update WordPress core to an EXPLICIT `--to X.Y.Z` (never implicit): the plan lists the target's `db_version`, the exact replaced file set, whether the chosen driver is WordPress's own extractor/copy or the tool's tree swap, the release's PHP/MySQL floors and the snapshot scope; `--apply` proves the release against wp.org's checksums before writing, writes with the selected driver (`swap`: each core tree staged beside its original and swapped by one rename under `.maintenance`; `wordpress`: core's own extractor/copier overwrites, then the plan's stale files are removed), migrates the database through core's own `wp_upgrade()`, then verifies the versions, every digest and the live site. **FTP** snapshots the replaced trees + every table first; **local** runs the same sequence into a rehearsed copy and the ORIGINAL zip is the rollback (no pre-action snapshot, no tables) |
| `deploy` | Stream a prepared webroot zip into a host over SSH **without the archive ever landing there** (quota preflight → normalized tar stream → layout assertion → manifest verification); additive, never deletes — local mode rehearses into `local:<dir>` |
| `trim-media` | Delete media not referenced by live content — the keep-set is the UNION of the live walk and the database references (a walk-only set deletes what the walk never sees); `--apply` is fail-closed until the full union is measurable |
| `optimize-media` | Recompress images in place (per-file local backups kept) |
| `harden` | Apply .htaccess/wp-config hardening (diff-printed, idempotent) |
| `deactivate-plugin <slug>` | Deactivate a plugin safely (options-table snapshot first; reactivate in wp-admin or `restore --undo-last --table wp_options`) — **FTP only** |
| `users_reset --login LOGIN` | Reset the named account's password to a random value (`--login` repeatable; a run with no target refuses, `--all` resets every user); the new credentials print once on stdout (never in plan/report/log), session tokens destroyed; snapshots wp_users + wp_usermeta — **FTP only** |
| `user-create --login LOGIN --email EMAIL` | Create a new WordPress user (administrator unless `--role`); the plan validates login/email/role read-only, `--apply` creates through core's `wp_insert_user()` and reads the account back; the generated password prints once on stdout (never in plan/report/log) — **FTP only** |
| `reconcile-plugins` | Rewrite `active_plugins` against the installed plugin set (deactivates entries whose plugin is gone; wp_options snapshot first, verified by re-read) — **FTP only** |
| `heal-core` | Restore checksum-proven tampered/missing WordPress core files from the official wp.org release of the site's exact version (snapshot first, md5-verified after; the "added" files are listed for investigation, never auto-deleted) |
| `verify` | Re-walk the site and re-fetch EVERY live reference — rc 1 if any is broken (ftp; or local + `--wp-url` against a `serve` rehearsal) |
| `backup` | Full-site snapshot: every walked file + every table, manifest + payloads under `.wpt-backup/` (ftp only); every manifest records the current identity keys `site_raw` + `webroot` |
| `restore` | List snapshots, or restore one — `--undo-last` rolls back the newest; targetable with `--file`, `--path-prefix`, `--table`, `--config`, `--media`; dry-run unless `--apply` (listing works from either source; **applying a restore is FTP only**). Snapshots require the current identity format (`site_raw` + `webroot`); a pre-identity manifest is refused, managed or explicit, with a regenerate-the-snapshot message — there is no legacy migration/import path |
| `walk` | Crawl the live site read-only: pages visited, media references, forms (ftp only) |
| `serve` | Serve a webroot zip on `http://127.0.0.1:<port>/` — the offline rehearsal target for `verify` (local only) |
| `doctor` | Preflight self-check: ftp+webroot, WordPress layout, write access, standalone PHP runtime, bridge round-trip, site reachability, TLS certificate/policy, host error log, wp.org API, disk — PASS/WARN/FAIL in seconds |
| `scan` | Source-only dangerous-PHP-pattern scan (request-driven `session_id`, reflected request data, SQL/table identifiers, includes, code execution, unserialize) — no WordPress/bridge/DB; local mode needs `--zip` only; a truncated scan emits `scan-partial` and exits 1 |
| `logs` | Read bounded host/webroot error logs (DirectAdmin/panel log dirs, `error_log`, `debug.log`, `.tar.gz` archives) and report fatal/error patterns — **FTP only**, no `--wp-url` needed |
| `discover` | Find WordPress webroot candidates from the FTP account root (`domains/*/public_html`, cPanel-style `<domain>/public_html`, `public_html`, …) — **FTP only**, no `--webroot`/`--wp-url` needed |
| `files` | Snapshot (`--backup PATH`), transactionally edit (`--path PATH --from LOCAL`, `--apply`), or roll back (`--restore SNAPSHOT`, `--apply`) selected regular files; every apply snapshots first; every restore (managed name/`last` or an explicit path) requires the current manifest identity (`site_raw` + `webroot`) — an explicit path selects the snapshot location, never a trust bypass; `--backup` may READ protected files, while edit/restore refuse WordPress core/config paths (including any `.htaccess`). Local mode can only **back up** from a zip |
| `proxy` | Local TLS-terminating browser proxy for pre-migration sites (DNS override) |

**The proxy's certificate in a browser:** `wpt proxy` mints a throwaway
self-signed **localhost** certificate (CN `localhost`; SAN `localhost`,
`127.0.0.1`, `::1`), so a browser may show its "connection is not private"
interstitial. The browser talks to `https://localhost:<bound-port>`, not to
the overridden hostname. The pair is generated on first use and **reused**
until it is within a day of its 7-day expiry, and only while its key matches
and its subject/SAN still name `localhost` + `127.0.0.1` + `::1`. It is not regenerated per run,
and it is not a trust anchor. For **Chrome**, type `thisisunsafe` while that
page has focus to bypass the interstitial for this throwaway cert (it is
Chrome's own keyboard bypass, not a wpt command). Prefer a browser profile
or `--override-ip` setup you can throw away for a migration session.

Audit checks worth knowing: **core.integrity** (wp.org official checksums —
tampered/added/missing core files, the hacked-site proof; default-theme
files that are a pristine official theme AUTO-UPDATE past the bundled copy
are cross-checked against the official theme release and reclassified
[L12], and well-known plugin bootstraps like Wordfence's
`wordfence-waf.php` report as a low-risk "added-known" note instead of
compromise evidence [L16]), **security.suspicious**
(high-precision backdoor signatures in the PHP WordPress actually executes —
**every `.php` under `wp-content/` at any depth, `wp-admin/`, the webroot
and `wp-config.php`** — matched against executable code only, never text
quoted in a comment or a string, and found even when a comment or a line
break splits the call),
**security.php_version**
(EOL PHP runtime), **security.source_patterns** (source-only legacy-PHP
patterns: request-driven sessions, reflected request data, SQL/table
identifiers, includes, code execution — the non-WordPress path), and
**security.uploads_perms** (world-writable files/directories under
`wp-content/uploads/` when the FTP LIST carries modes), **db.charset**
(non-utf8mb4 tables), **db.admin_accounts** (default `admin` login) — plus
the original webroot/plugins/db/media/security suite. Media findings cover media-extension files only — uploads
`.htaccess`/`index.php` guards are never flagged or trimmed [L14].
Reports end with **Suggested next steps** — each finding mapped to the
exact command that fixes it. After a successful action `--apply` the site's
page caches are purged (LiteSpeed/W3TC/WP Super Cache) so changes are visible
immediately; `restore --apply` restores files rather than live output and
does not purge.

Reliability (live-host hardened): the FTP source trips a consecutive-failure
breaker when the passive data channel goes stale (bounded to minutes, never
hours); stale bridge files and expired PHP probes from killed runs are swept
automatically; long captures log heartbeat progress (webroot walks, bulk
scans, snapshot captures — a run is never silently grinding); bulk scans
carry circuit breakers.

All mutating commands (including `restore`) print a dry-run plan first;
pass `--apply` to execute and `--yes` to skip the interactive confirm.
Snapshots land in `.wpt-backup/` locally — never in the webroot — and
every **FTP** mutating action snapshots its own affected scope before
applying (fail-closed: no snapshot, no apply). In **local** mode the
action mutates only an in-memory overlay and materializes a rehearsed
copy; the original zip is the rollback, so there is no pre-action
snapshot and no database. Every command with `--report` writes a
markdown report plus a JSON twin for scripted use.

The proxy's own inputs are `--hostname`, `--ip`, `--port`, `--cert-dir`, and
`--report`; it defaults `--source` to local and reads no zip, dump, webroot, or
site URL.

Reports are intentionally boring: Markdown for people, JSON for scripts, and
the same finding IDs in both. Use `--baseline` to see only what changed since
the last run.

## Local rehearsal

In local mode, `--apply` does not mutate the original zip: the action
stages in memory and materializes a cleaned copy beside it
(`<zip>-rehearsed-<timestamp>.zip`). The original is the rollback.
Serve the cleaned copy and verify it offline:

```bash
wpt --source local --zip site.zip --sql dump.sql --apply --yes clean-files
wpt --source local --zip site-rehearsed-<ts>.zip --sql dump.sql serve --port 8123
wpt --source local --zip site-rehearsed-<ts>.zip --sql dump.sql \
    --wp-url http://127.0.0.1:8123 verify
```

(Serving is static — rendered-page crawling still needs the real site;
media references and file checks work fully offline.)

## Documentation

- [Quickstart](docs/quickstart.md) — install, first audit, reports, and apply.
- [Commands](docs/commands.md) — task-oriented workflows for the command table.
- [Safety model](docs/safety.md) — plans, snapshots, rollback, and local mode.
- [Architecture](docs/architecture.md) — source adapters, actions, audit, bridge,
  and the test strategy.
- [Development](docs/development.md) — local setup, tests, packaging, and release.
- [FAQ](docs/faq.md) — supported platforms, databases, and operational limits.
- [SPEC.md](SPEC.md) — the binding engineering contract.
- [CHANGELOG.md](CHANGELOG.md) — release history.

## Development

```bash
python3 -m pip install -e ".[dev,db]"
# Fast: parallel, work-stealing distribution.
python3 -m pytest tests/ -q -n auto --dist worksteal
# Serial fallback: same suite, one worker, deterministic order.
python3 -m pytest tests/ -q
python3 -m ruff check wpt tests
```

Use `-n auto` (or a number tuned to your machine) for the parallel run. The
full suite is POSIX; Windows is smoke-tested only. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the test, documentation, and review
contract.

## Roadmap (v2+)

- Apply plugin/theme updates after audit approval (core updates already ship
  as `update-core`)
- DirectAdmin / cPanel panel connectors
- SSH connector, multisite support

## License

MIT. Copyright © 2026 The wpt authors. See [LICENSE](LICENSE).
