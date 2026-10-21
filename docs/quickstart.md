# Quickstart

This page takes you from a checkout to a first audit, a reviewed plan, and an
offline rehearsal. All examples use synthetic hosts and documentation IPs.

## Before you start

- Python 3.12 or newer.
- PHP 8.3 or newer for the bridge and PHP probes.
- OpenSSL for the local proxy certificate.
- A site, archive, and database dump you are authorized to inspect.
- `rsync` is useful for local backups but is not required by `wpt`.

## Install

From a checkout of this repository:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[db]"
wpt --version
```

The `db` extra adds the pure-Python MySQL driver used by `--db-uri` and the
re-dump writer. When the package is published, the same install is available as
`pip install "wpt[db]"`.

For development and the full test suite:

```bash
python -m pip install -e ".[dev,db]"
```

## First audit: offline

An offline audit needs a webroot zip and a SQL dump. It does not need a live
server or database connection.

```bash
wpt --source local --zip site.zip --sql dump.sql audit --report audit.md
```

The command prints a plan-style summary. With `--report`, it also writes:

- `audit.md` — a human-readable report with findings and suggested next steps;
- `audit.json` — the same findings for scripts and dashboards.

Use `--baseline previous.json` to show only what changed since an earlier run.

## First audit: live FTP

The FTP source supports FTPS with certificate and hostname verification on by
default. Keep the password in the environment rather than an inline DSN:

```bash
export FTP_PASS='...'
wpt --source ftp://host:21 --user U --password-env FTP_PASS \
    --webroot domains/site/public_html --wp-url https://site.test \
    --override-ip 192.0.2.44 audit --report audit.md
```

`--override-ip` lets HTTPS and the bridge reach a site whose DNS still points at
the old host. The proxy command supports a browser workflow for the same
situation.

!!! note "Authorized use only"

    Run live operations only against sites you own or have explicit permission
    to change.

## Read the plan

Start with a command that changes something and inspect the plan before
applying it:

```bash
wpt --source local --zip site.zip --sql dump.sql clean-files
```

The plan lists every target and the estimated effect. Apply it only after you
have reviewed the targets and have a rollback path:

```bash
wpt --source local --zip site.zip --sql dump.sql clean-files --apply --yes
```

In local mode, `--apply` does not mutate `site.zip`. It materializes a
rehearsed copy beside it. In FTP mode, the action snapshots its affected scope
first and refuses to apply if the snapshot fails.

## Rehearse offline

Local mode is the safest place to test a plan:

```bash
wpt --source local --zip site.zip --sql dump.sql --apply --yes clean-files
wpt --source local --zip site-rehearsed-<ts>.zip --sql dump.sql serve --port 8123
wpt --source local --zip site-rehearsed-<ts>.zip --sql dump.sql \
    --wp-url http://127.0.0.1:8123 verify
```

Serving is static; rendered-page crawling still needs the real site. Media
references and file checks work fully offline.

## Doctor and proxy

Run the preflight when a live check fails or before a migration:

```bash
wpt doctor --source ftp://host:21 --user U --password-env FTP_PASS \
    --webroot domains/site/public_html --wp-url https://site.test
```

For a browser-based migration preview:

```bash
wpt proxy --hostname site.test --ip 192.0.2.44
```

The proxy mints a throwaway localhost certificate. A browser may show a
"connection is not private" interstitial; this is expected. The certificate is
reused while usable and is not a trust anchor. See the
[safety model](safety.md#the-proxy-certificate) before installing anything.

## Next steps

- [Commands](commands.md) — task-oriented workflows.
- [Safety](safety.md) — snapshots, rollback, and mode differences.
- [FAQ](faq.md) — database, platform, and compatibility questions.
