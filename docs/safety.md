# Safety model

`wpt` is built around one rule: **a production site is not a scratchpad**.
Every command is read-only by default, every mutation is planned, and every
FTP mutation has a snapshot or does not run.

## The contract

1. **Plan.** A mutating command prints a dry-run plan with targets and
   estimated effects.
2. **Review.** Read the plan. Confirm the source, webroot, site URL, and scope.
3. **Snapshot.** In FTP mode, the action snapshots its affected scope first.
   If the snapshot fails, the apply fails closed.
4. **Apply.** Pass `--apply` to execute. Pass `--yes` only when you have already
   reviewed the plan and want to skip the interactive confirmation.
5. **Verify.** Re-read or re-walk the affected scope. Reports and manifests
   record what changed.

`restore --apply` is intentionally different: it restores files you select
rather than live output, so it does not purge page caches.

## What gets snapshotted

- **FTP mutating actions** snapshot their affected scope before applying.
- **`backup`** captures every walked file and every table with a manifest under
  `.wpt-backup/` (FTP only).
- **`files`** snapshots selected files with a manifest, bytes, and SHA-256
  before an edit or restore.
- **`update-core`** snapshots the replaced core trees and tables in FTP mode.
- **`restore`** requires the current manifest identity (`site_raw` + `webroot`);
  an older manifest is refused with a regenerate-the-snapshot message.

Snapshots live outside the webroot. Never commit `.wpt-backup/`, `.wpt-live/`,
`.wpt-cert/`, or `.wpt-cache/` to source control.

## Local mode

Local mode is the rehearsal path. `--apply` mutates an in-memory overlay and
materializes a cleaned copy beside the original:

```text
site.zip  ->  site-rehearsed-<timestamp>.zip
```

The original archive is the rollback. Local mode does **not** take the FTP
pre-action snapshot, and it has no live database. That is deliberate: the
archive you started with is the recovery point.

## Secrets

- Use `--password-env VAR` for the FTP/WordPress password and
  `--db-password-env VAR` for a database password.
- Prefer those environment variables. A password embedded in an inline
  `--db-uri` is accepted for compatibility, but it is visible in shell history
  and the process list; do not use that form on a shared machine.
- One logging path redacts credentials before they reach the console, a file, a
  report, a receipt, or an exception.
- Review reports before sharing them. Redaction protects credentials, not
  client hostnames or user logins.

## Self-bounding runs

Every command accepts `--deadline SECONDS`. When the budget expires, the run
ends itself through the normal error contract: cleanup, teardown, and a
non-zero exit. SIGTERM is a cooperative stop, not a signal to kill from outside.

The two long-running listeners are the deliberate exception: `serve` and
`proxy` own their process until interrupted, so `--deadline` does not stop
their accept loop. SIGTERM still ends both cleanly through the same teardown.

Bulk FTP reads use dedicated worker sessions with two channel bounds: a
consecutive-failure breaker and a slow-op window. A dead or crawling passive
channel ends in minutes, not hours.

## The proxy certificate

`wpt proxy` mints a throwaway self-signed **localhost** certificate:

- CN `localhost`;
- SAN `localhost`, `127.0.0.1`, and `::1`;
- reused while usable, until it is within a day of its 7-day expiry;
- not regenerated per run;
- not a trust anchor.

The browser talks to `https://localhost:<bound-port>`, not to the overridden
hostname. A "connection is not private" interstitial is expected. In Chrome,
type `thisisunsafe` while the page has focus to bypass it for this throwaway
certificate. That is Chrome's keyboard bypass, not a `wpt` command. Prefer a
browser profile you can discard for the migration session.

## Before you apply

- Confirm you are authorized to change the site.
- Run the command without `--apply` and read every target.
- Check that the source mode and webroot are the ones you intend.
- Make sure a snapshot location exists and has free space.
- For a live migration, rehearse against a local copy first.
- Keep an independent backup; a tool snapshot is not a substitute for your own
  recovery plan.

## If something goes wrong

1. Stop and read the plan/report; do not start a second mutation.
2. Preserve the snapshot and logs.
3. Use `restore` with the current manifest identity to roll back the selected
   scope.
4. If a credential may have been exposed, rotate it immediately.
5. Report a reproducible security issue through the process in
   [SECURITY.md](https://github.com/LLM-4-People/wp-toolkit/blob/main/SECURITY.md).

The binding contract and per-module invariants are in
[SPEC.md](https://github.com/LLM-4-People/wp-toolkit/blob/main/SPEC.md).
