# FAQ

## Does `wpt` change my site without asking?

No. Mutating commands print a dry-run plan. They execute only with `--apply`;
`--yes` skips the interactive confirmation, not the plan. FTP mutations also
require a successful snapshot first.

## Can I use it on a live site?

Yes, with authorization. Start with `audit` and `doctor`, then run a mutating
command without `--apply` and read the plan. For DNS migrations, use
`--override-ip` or the local proxy. Rehearse against a local copy when you can.

## Does it store my password?

No. Passwords normally come from environment variables (`--password-env`,
`--db-password-env`) or prompts. An inline password in `--db-uri` is accepted
for compatibility, but it is visible in shell history and must be avoided on a
shared machine. Passwords are redacted by the logging path and are never
written to a plan, report, receipt, or exception.

## Which WordPress, PHP, and MySQL versions are supported?

The bridge is verified against WordPress 6.0–7.1 and PHP 8.3+ is the supported
runtime. MySQL and MariaDB are supported through the pure-Python PyMySQL driver
for `--db-uri`; the FTP/bridge path talks to WordPress rather than the database
directly.

## Does it support multisite?

Not in v1. Multisite is out of scope, along with a direct SSH connector and
panel APIs.

## Can it update plugins and themes?

Not in v1. Core updates ship as `update-core`; plugin/theme updates are on the
roadmap. The audit's `updates` command reports what is available without
applying it.

## Why does local mode not take a snapshot?

Local mode mutates an in-memory overlay and writes a new rehearsed archive. The
original zip is the rollback, so a second copy would be redundant. FTP mode has
no original archive to fall back on, so it snapshots the affected scope before
applying.

## How do I restore a change?

Use `restore` to list snapshots and restore one. `--undo-last` rolls back the
newest; `--file`, `--path-prefix`, `--table`, `--config`, and `--media` select a
scope. Applying a restore is FTP-only. Local mode restores by using the
original archive.

## Where are snapshots and reports written?

Snapshots land outside the webroot under `.wpt-backup/` by default. Reports go
where `--report PATH` points and get a JSON twin. Keep both out of source
control.

## Why does `park-backups` not delete backups?

It moves full-site backup payloads out of the document root so they are no
longer web-exposed. Deletion is deliberately not its job. `clean-files` is the
command that can remove junk and stale backup-shaped files, and it shows them in
a plan first.

## Why is Windows only smoke-tested?

The full suite depends on POSIX paths, FIFOs, `/proc`, `O_DIRECTORY`, and Unix
signal semantics. Windows gets a wheel/CLI smoke test so installation and the
entry point stay healthy without pretending the full behavioral suite is
portable.

## Why does the proxy show a certificate warning?

It uses a throwaway self-signed certificate for `localhost` (`CN=localhost`;
SAN `localhost`, `127.0.0.1`, `::1`). It is reused while usable, not
regenerated per run, and is not a trust anchor. In Chrome, type `thisisunsafe`
while the page has focus to bypass the interstitial for this certificate. See
[the safety model](safety.md#the-proxy-certificate).

## Does it need a live database?

No. An offline audit uses a SQL dump. `clean-db --db-uri` can read a direct
database when the `db` extra and a driver are installed, but it is not required
for the rest of the toolkit.

## How do I report a security issue?

Follow [SECURITY.md](https://github.com/LLM-4-People/wp-toolkit/blob/main/SECURITY.md).
Do not open a public issue with credentials, client data, or an exploitable
reproduction.

## What is the license?

MIT. Copyright © 2026 The wpt authors. See
[LICENSE](https://github.com/LLM-4-People/wp-toolkit/blob/main/LICENSE).
