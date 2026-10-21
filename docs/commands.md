# Commands

The canonical command table is in the
[README](https://github.com/LLM-4-People/wp-toolkit#commands). This page is a
task-oriented map; when the two disagree, the README table and the CLI parser
win, and `tests/test_docs.py` enforces the table.

## Source modes

| Mode | Inputs | Best for |
|---|---|---|
| `local` | `--zip` + `--sql` for database-aware commands (audit, updates, verify, restore, clean-db, trim-media, webp-media) | Offline audit and rehearsal |
| `ftp` | `--source ftp://host`, `--user`, `--password-env`, `--webroot` | Live inspection and FTP-applied changes |
| Direct database | `--db-uri` + `--db-password-env` | Offline `clean-db` and database inspection |

The proxy and serve commands are special: `proxy` defaults to local and reads
no source, zip, dump, webroot, or site URL; `serve` is local-only and serves a
rehearsed webroot.

## Audit and inspect

- `audit` — the full 38-check read-only audit.
- `updates` — only core, plugin, and theme update checks.
- `doctor` — preflight: source, layout, write access, PHP, bridge, reachability,
  TLS, logs, wp.org API, and disk.
- `scan` — source-only dangerous-PHP-pattern scan.
- `logs` — bounded host/webroot error-log reading.
- `discover` — find WordPress webroot candidates from an FTP account root.
- `walk` — crawl the live site read-only.
- `verify` — re-walk and re-fetch every live reference; non-zero if broken.

## Clean and optimize

- `clean-files` — junk, backup, stale, and migration files.
- `clean-db` — revisions, transients, orphan metadata, and table optimization.
- `prune-core` — stale core files no longer shipped by the current release.
- `park-backups` — move full-site backup payloads out of the document root.
- `cull-media` — delete oversized derivatives of dead media families.
- `webp-media` — convert uploads to WebP and rewrite references.
- `trim-media` — delete media not referenced by live content.
- `optimize-media` — recompress images in place with per-file backups.
- `harden` — .htaccess and wp-config hardening.
- `heal-core` — restore checksum-proven core files from the official release.
- `update-core` — move a live site to an explicit core version.

Every one of these is a plan until `--apply`. Read the plan, and keep a
snapshot or the original archive available.

## Backup, change, and deploy

- `backup` — full-site snapshot: files and tables with a manifest.
- `restore` — list snapshots or restore one; dry-run unless `--apply`.
- `files` — snapshot, edit, or roll back selected regular files.
- `deploy` — stream a prepared webroot zip over SSH without landing the archive
  on the host; additive, never deletes.

## Accounts and plugins

- `deactivate-plugin <slug>` — deactivate a plugin with an options snapshot.
- `users_reset --login LOGIN` — reset passwords; new credentials print once.
- `user-create --login LOGIN --email EMAIL` — create a user through WordPress
  core; generated password prints once.
- `reconcile-plugins` — rewrite `active_plugins` against the installed set.

## Local tools

- `serve` — serve a webroot zip on `http://127.0.0.1:<port>/` for offline verify.
- `proxy` — local TLS-terminating browser proxy for DNS override.

## Common inputs

- `--source local|ftp://...` selects the source adapter.
- `--zip`, `--sql`, and `--db-uri` select offline inputs.
- `--webroot`, `--wp-url`, and `--override-ip` describe a live site.
- `--user` plus `--password-env VAR` supplies FTP credentials from the
  environment.
- `--report PATH` writes Markdown plus a JSON twin.
- `--apply` executes a plan; `--yes` skips the interactive confirmation.
- `--deadline SECONDS` bounds a run; `serve` and `proxy` own their accept loop
  until interrupted.
- `--profile`, `--set key=value`, and `--backup-dir` tune behavior without
  editing code.

## Reports

Reports contain findings, not credentials. They are safe to share only after
you review paths, hostnames, user logins, and operational details. Redact
anything client-specific before attaching a report to an issue.

## Next steps

- [Safety](safety.md) — the mutation and rollback contract.
- [Quickstart](quickstart.md) — a first audit and rehearsal.
- [FAQ](faq.md) — common operational questions.
