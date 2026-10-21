# WP-Toolkit (wpt) — Engineering Spec (single source of truth)

Every agent and human contributing to this repo reads this file first and treats it as
binding. Lessons marked **[L#]** came from reference field work — each maps to at
least one regression test (see Test Map).

## Purpose

`wpt` audits, cleans, optimizes, backs up, restores, and verifies ANY WordPress site
from two sources, WITHOUT editing WordPress/plugin/theme source code:

1. **ftp** — live site over FTPS + HTTPS (works even when DNS points elsewhere)
2. **local** — offline zip of the webroot + a MySQL .sql dump

Lessons marked **[L#]** below came from reference field work — each maps
to at least one regression test (see Test Map). L12–L16 came from the
synthetic `example.test` audit session.

It is a FRAMEWORK: every capability is a registered module (audit checks, actions,
bridge ops) driven by data (profiles) — new behaviors are added by registering, not
by editing core logic. The bridge's whitelist IS the extension surface for anything
WordPress can do safely.

Governing principles: DRY, KISS, YAGNI. Ultra-modular, resilient, agnostic, dynamic.
Read-only by default; every destructive action is a dry-run plan until `--apply`.

## Hard rules (apply to every module, no exceptions)

- **Secrets** come from env vars (`--password-env VAR`) or prompts. Never in files,
  logs, reports, or exceptions. `wpt/config.py: redact()` is applied to every payload
  that might reach a log or report.
- **Backups are local, never in the webroot.** Modified files (wp-config.php, .htaccess)
  and deleted media originals go to `.wpt-backup/<site>/<timestamp>/`. [L1: a .bak in
  the webroot was world-readable on a real site]
- **One writer at a time.** Agents never edit files outside their ownership list. If an
  interface mismatch is found, report it to the coordinator — do not patch others' files.
- **No static configurables in code.** Every tunable (junk patterns, ghost-table
  prefixes, media quality rules, thresholds, timeouts) lives in
  `wpt/data/profiles/default.json`, loaded into `wpt/settings.py` dataclasses, overridable
  via `--profile PATH` and `--set key=value`. Code contains only structural defaults.
- **Centralized logging.** `wpt/log.py` is the ONLY logging path (built on stdlib
  `logging`, configured once at the CLI choke point: `--log-level`, `WPT_LOG_LEVEL`,
  `--log-file`, JSON and human formatters). All modules use `from wpt.log import get_logger`.
  No module calls `print()` outside the CLI presentation layer.
- **Verify after every change.** Mutating actions end with a verification pass
  (live reference-set recheck) and refuse to report success without it. [L2: a media
  trim looked successful but broke 36 srcset variants — caught only by URL verification]
- **Commit locally after every verified change** (coordinator does this; conventional
  messages: `module: what changed`).
- **No band-aids.** Root-cause fixes only. If a workaround seems necessary, stop and
  report instead.

## CLI surface

```
wpt --version
wpt --source ftp://host:21 --user U --password-env P --webroot domains/site/public_html \
    --wp-url https://site.test [--override-ip 192.0.2.44] [--profile p.json] [--set k=v ...] \
    [--log-level info] [--log-file wpt.log] [--log-json] [--quiet] \
    [--backup-dir .wpt-backup] [--deadline SECONDS] <command> \
    [--apply] [--yes] [--report out.md]

commands: audit | clean-files | clean-db | cull-media | park-backups |
          webp-media | trim-media | optimize-media | harden | verify |
          updates | backup | restore | walk | serve | doctor | scan |
          logs | discover | files | proxy |
          deactivate-plugin | heal-core | users_reset | user-create |
          reconcile-plugins | update-core |
          prune-core | deploy

wpt --source local --zip site.zip --sql dump.sql audit
wpt proxy --hostname site.test --ip 192.0.2.44 [--port 8443]
# proxy is a self-contained local TLS tunnel: it defaults --source to local
# and reads no zip/dump/webroot/site URL.

wpt --source local --db-uri mysql://[user[:password]@]host[:port]/database \
    [--db-password-env VAR] [--re-dump PATH] clean-db [--apply] [--yes]
wpt --source local --db-uri <uri> doctor          # adds a connectivity row

wpt --source local --zip site.zip --sql dump.sql webp-media [--purge-originals] \
    [--i-know-editors-are-off]
wpt --source local --zip site-final.zip deploy --ssh-target root@box \
    --webroot /home/user/domains/site.test/public_html [--ssh-port 2222] \
    [--ssh-password-env VAR] [--apply] [--report deploy.md]
```

**Global flags are accepted before OR after the command name** (`audit
--report out.md` ≡ `--report out.md audit`); a command's own flags
(`audit --only/--skip/--baseline`, `restore --undo-last/--file/…`, `deploy
--ssh-target/--ssh-port/--ssh-password-env`, `park-backups --park-outside`,
`proxy --hostname/--ip/--port/--cert-dir`, `webp-media
--purge-originals/--i-know-editors-are-off`, `serve --port`) belong after it. A global flag is hoisted from the tail
only when it carries a value of its own and that value is not the only token
a command positional could take [L19: a hoisted `--report` silently ate
`restore`'s snapshot name and the run exited 0 after merely LISTING
snapshots]. Anything else in the command position is refused with a message
naming the flag and the side it belongs on — never `invalid choice:
'<file>'`. A rejected `--set`/`--profile` is a one-line stderr refusal, rc 1,
never a traceback.

**Inputs by mode (local)**: `--zip` is required for every command except
`doctor`, `logs`, `discover`, `proxy`, the FTP-only `backup` and `walk`
(their bodies refuse local mode with a report-shaped failure), and
`clean-db` with `--db-uri`; `--sql` is
additionally required by the dump-reading commands (`audit`, `updates`,
`verify`, `restore`, `clean-db`, `trim-media`, `webp-media`) except
`clean-db` with `--db-uri`, which reads the database directly. `clean-files`,
`optimize-media`, `harden`, `heal-core`, `prune-core`, `deploy`,
`park-backups`, `update-core`, `scan` and
`files` read the webroot only and run with `--zip` alone — except a local
`clean-files` plan that deletes a plugin/theme UNIT, which also requires
`--sql` (the active set is unknowable without it; junk-only plans stay
`--zip`). `logs` and `discover` are FTP-only; their bodies refuse local mode
with a report-shaped failure. `files` supports a local `--backup` from the zip; its mutating
`--restore`/edit modes are FTP only and refuse local mode before any write.

**Inputs by mode (ftp)**: `discover` needs neither `--webroot` nor
`--wp-url`; `logs`, `scan` and `files` need `--webroot` but not `--wp-url`;
`proxy` needs neither (it is a self-contained local TLS tunnel and reads no
source, zip/dump, webroot or site URL); every other ftp command needs both.
`--user` always requires `--password-env`, except for `proxy`, which reads no
source and therefore has no credential to resolve.

**`--report` is honoured by EVERY command.** The actions registry and the deploy
dry run write the run's plan through ONE shared writer
(`registry.write_report`): the same markdown the run printed (plan table,
reclaimable estimate, plan total), created even for an empty plan, paired
with a JSON twin; a path that cannot be written fails the run (rc 1). The
report carries the PLAN only — a `users_reset`/`user-create` credential
never reaches it
[L44: every action dry run and the deploy dry run silently ignored
`--report`, so a caller could not tell from the filesystem whether a run had
planned anything].

**`--set` carries scalars, JSON array literals and JSON object literals** —
a value that parses as a JSON list/object sets that shape (every list- and
map-shaped key — `webroot_junk`, `known_heavy`, `media.extensions`,
`media_optimize.exclude_prefixes`, `core_integrity.known_added` — used to be
reachable only through a profile file) [L20]; anything that merely LOOKS like
JSON is left a string so the settings owner still speaks its own error.


Per-command flags (every one of these is part of the contract — the docs test
fails if a subparser declares a flag this section does not name):

    audit            --only CHECKS   run just these checks
                     --skip CHECKS   skip these checks
                     --baseline JSON re-audit against a previous report (resolved diff)
    users_reset      --login LOGIN   reset only this account (repeatable). A
                                     specific account is the default SHAPE: a
                                     run with NO target refuses, never a
                                     silent all-users reset. An unknown login
                                     names the roster (the read-only
                                     discovery path)
                     --all           reset EVERY user's password; a user
                                     created between plan and apply fails the
                                     run closed
    user-create      --login LOGIN   the new account's login (required;
                                     WordPress sanitizes it, the plan shows
                                     the result)
                     --email EMAIL   the new account's email (required;
                                     valid and unused)
                     --role ROLE     the role to grant (default
                                     administrator; must exist on the site)
    restore          --undo-last    revert the most recent snapshot for this webroot
                     --file PATH    one file from a snapshot
                     --path-prefix P  restore only files under this webroot-
                                      relative subtree (a file_prefix selector)
                     --table NAME   one database table from a snapshot
                     --config FILE  one config file from a snapshot
                     --media        restore the uploads subtree (boolean; the
                                      path comes from the bridge's uploads_basedir)
    serve            --port N       the rehearsal origin's port
    proxy            --hostname H   the name to answer for
                     --ip ADDR      where to reach the real site
                     --port N       the local TLS port
                     --cert-dir D   where the throwaway certificate is written
    deploy           --ssh-target T box, or local:DIR to rehearse
                     --ssh-port N   the ssh port
                     --ssh-password-env VAR  the password's environment variable
    update-core      --to X.Y.Z  the EXPLICIT target core version (required
                                for --apply; a target is never implicit)
                     --allow-pre-release  accept a pre-release TARGET, or a
                                dev/beta/RC INSTALL
    park-backups     --park-outside DIR  where payloads are moved (must be outside the webroot)
    webp-media       --purge-originals    delete the originals once the rewrite verifies
                     --i-know-editors-are-off  acknowledge the purge window

### Source-only scan, logs and webroot discovery

Three read-only diagnostics exist so the toolkit can answer questions that
do not require WordPress, the bridge or the database:

- **`scan`** — walks the webroot (FTP or `--zip`) and runs exactly the
  `security.source_patterns` check. It detects request-driven
  `session_id`/`session_name`, reflected request data, request data in SQL
  sinks and SQL identifiers, request-driven `include`/`require`, and
  request-driven code execution/unserialize. It is a source-only HEURISTIC
  (no cross-file dataflow): findings are review candidates, not a parser
  verdict. No bridge, no HTTP, no dump. Local mode needs `--zip` only; ftp
  mode needs `--webroot` but no `--wp-url`. `--report` writes the audit
  report's markdown + JSON twin. The deadline is checked before and after
  every file (whatever its size) and after every batch, including the last;
  a deadline- or breaker-truncated scan emits `scan-partial` and exits 1: a
  security gate that ran out of budget must never report a clean pass.
- **`logs`** — FTP only. Reads bounded host log directories derived from
  the webroot (`domains/<domain>/logs`, `<webroot-parent>/logs`, `logs`)
  plus direct `error_log`/`php_errorlog`/`wp-content/debug.log` files.
  Plain files and in-memory `.tar.gz`/`.gz` members are bounded by
  `logs.max_files`, `logs.max_file_bytes`, `logs.max_archive_bytes` and
  `logs.max_decompressed_bytes`;
  nothing is extracted to disk. Every rendered line is redacted and
  truncated; the report is a triage table (file, line, pattern, match),
  not a log dump.
- **`discover`** — FTP only, read-only. Lists a bounded set of account-root
  candidates (`public_html`, `httpdocs`, `www`, `domains/*/public_html`,
  cPanel-style `<domain>/public_html`, …) and marks each by the exact
  top-level WordPress markers `wp-config.php`, `wp-content` and
  `wp-includes`. It reads no file, writes nothing, opens no HTTP and exits
  1 when no complete webroot is found. The operator chooses the candidate;
  the command never auto-selects one.

### Selected-file backup / edit / rollback

`wpt files` is the generic, non-WordPress-file surface the site-recovery
workflow lacked. It names REGULAR files explicitly; it never syncs a tree.

- `files --backup PATH [--backup PATH ...]` snapshots the named
  webroot-relative files into `--backup-dir` (manifest + bytes + SHA-256),
  including an `exists: false` record for a target that is not there. This
  mode is read-only on the remote side and works from an offline `--zip` as
  well as FTP.
- `files --path PATH --from LOCAL [...] --apply` pairs each target with a
  local file, verifies the current target has not changed since the
  pre-write snapshot, uploads each new body to a sibling temporary name,
  reads it back, and renames it into place. A failure rolls every already
  renamed target back from the snapshot; the snapshot path is printed and
  kept for `--restore`.
- `files --restore SNAPSHOT --apply` restores a snapshot (a directory name,
  `last`, or a path). EVERY route requires the current identity: the
  manifest must record both `site_raw` and `webroot`, and both must match
  the current run. The manifest and every stored byte are read through the
  same rooted, link-free reader (a symlinked snapshot directory is refused,
  never followed). It verifies every stored SHA-256, snapshots the current
  state first, and uses the same temp+rename/rollback transaction.

`--apply` requires `--yes` (the shared `confirm()` gate). Every mode honors
`--report` with the command's markdown + JSON twin. `--backup` may READ a
protected file (a backup is evidence), but edit/restore refuse WordPress
core paths, `wp-config.php`, any `.htaccess` and the bare `index.php` through
`Source`'s protected-path guard: use `heal-core`/`harden`/`deploy` for those.
An explicit `--restore /path/to/snapshot` selects the snapshot LOCATION; it
is not a trust bypass: the manifest must still record and match the current
RAW site label and webroot (two labels can sanitize to one directory
component, e.g. `b-cher.example`). `last` is scoped to the current site
label under `--backup-dir` and applies the same identity rule. Lookup uses
ONE exact raw identity directory and one exact recorded identity:
pre-round-3 spellings (`www.<host>`, original case, redacted label) are
never searched or normalized, so a shared sanitized directory cannot
cross-restore.
`files.max_files` and `files.max_file_bytes` bound the
run, and every remote read goes through `Source.read_bytes_bounded` so a
lying `size()` cannot materialize an unbounded body. The command is
FTP-mutating; local mode is backup-only.

The doctor panel (`wpt doctor`, ftp) is now: `ftp + webroot`,
`wordpress layout`, `write access`, `php runtime`, `bridge round-trip`,
`site reachability`, `tls certificate`, `https policy`, `host error log`,
`wp.org API`, `disk` (plus the conditional `wpt residue` row when a prior
update left staging names). `wordpress layout` checks the same three markers
BEFORE the bridge is deployed, so a non-WordPress root fails with a precise
message and no executable bridge file is written. `write access` writes and
removes one unique per-run `.wpt-write-probe-<16hex>`; `php runtime` deploys the token-gated,
no-WordPress `wpt-probe-<8hex>.php`, reads PHP version/SAPI/extensions/
session flags, and self-deletes. `host error log` calls the same bounded
collector as `wpt logs`. A homepage HTTP 5xx is now a FAIL (4xx stays WARN).

One `wpt <command> starting: source=... webroot=... site=...` INFO line is
logged at the dispatch choke point before any phase output [L15: a killed
run's stale SIGTERM log tail read as the current run's output for minutes] —
command/mode/webroot/site URL only, never credentials.

## Backup / restore / walk (v1 scope — user-required)

### backup
- **Pre-action auto-snapshot (ALWAYS)**: before any `--apply`, the action's affected
  scope is snapshotted automatically to `.wpt-backup/<site>/<YYYYmmdd-HHMMSS>[-N]/`
  (local timestamp; name order = creation order) following the same manifest format.
  An action that cannot snapshot its scope REFUSES to run (fail-closed: partial
  snapshots are removed and the apply aborts). Capture reads run through the
  batched `read_many` protocol (200-path batches, `Deadline`-checked) and a
  present target that CANNOT be read fails the whole snapshot closed — a hole
  in the reversibility substrate is never silently skipped (--apply could
  write the file; restore would have nothing to bring back and no manifest
  entry to even know).
- **`wpt backup`** (ftp only — the zip + dump already ARE the offline snapshot in
  local mode): v1 scope is FULL — every walked file (enumerated BEFORE the first
  bridge call, so the snapshot never contains our own bridge file) + every table
  `db_audit` reports; writes the same layout as the auto-snapshot:
  `manifest.json` + `files/<path>` (captured file bytes, hierarchy preserved) +
  `db/<table>.ndjson` (db_dump rows, one JSON object per line; binary cells as
  `["__wpt_b64__","<base64>"]` — disk form = wire form).
- **manifest.json** (format "wpt-backup-manifest", version 1): {site, site_raw,
  webroot, action, created
  (ISO 8601 local), wpt_version, files: [{path, absent, sha256, size} | {path,
  absent: true} — absent entries are NOT recreated on restore], tables: [{name, rows,
  sha256, size}], totals}. `site_raw` and `webroot` are REQUIRED current identity
  keys: `create_snapshot` takes both with no defaults, every manifest carries
  both, and restore refuses a manifest missing either (no legacy format).
  One format for auto + explicit; `wpt/backup.py` is the
  authoritative owner, `verify_snapshot` recomputes every hash and retains
  the EXACT parsed manifest it verified: restore selects and hashes from that
  object, never from a second read of `manifest.json` (a manifest swapped
  after verification cannot select unverified entries). Every payload
  read opens the snapshot directory as a root fd and walks each component
  with `O_NOFOLLOW` (a symlinked directory under `files/` or `db/` cannot
  redirect bytes outside the snapshot), and each table stream is read once:
  restore replays the exact bytes verification hashed. The operator-named
  `--backup-dir` is the trust anchor: ancestors above it are trusted (it may
  itself be a symlink), while every component below it — the site-label
  directory, the snapshot directory and every payload/manifest path — is
  opened with `O_NOFOLLOW`; a planted `<backup>/<label> -> victim` symlink is
  refused by both snapshot writers and retention/sweep. In-capture
  operational failures (NaN cells rejected by the encoders, anomalous db_dump
  streams) surface as WptError at the engine boundary — every command body's
  never-raises contract holds. The capture validates each stream object with
  the SAME exact grammar restore applies (`wpt/dbstream.py`: exact key sets,
  the cell rule, one `done` carrying the row count, nothing after `done`), so
  a snapshot `wpt backup` reports success for is one `wpt restore` accepts.
- Retention via settings profile: `backup.keep_last` (default 10), `backup.keep_days`
  (default 90) — pruned on each backup, oldest first (keep_last rank OR keep_days
  recency; the fresh snapshot is always exempt). `backup.stale_temp_age_s`
  (default 86400) bounds the sweep of hidden capture temps left by a killed run:
  only our two temp shapes older than the age are removed, so a live concurrent
  capture is never touched.

### restore
- `wpt restore` (interactive: lists snapshots — pure local disk, works in both
  modes) or `wpt restore <ts>` with targeting: `--file <path>` (single file,
  repeatable), `--path-prefix <dir>` (a subtree), `--table <name>` (repeatable),
  `--config wp-config|.htaccess` (restored through the same restore_snapshot path —
  the write hits the source's config guard and its audit log line),
  `--media` (the uploads subtree, derived from the bridge's uploads_basedir
  RELATIVIZED against its abspath — the raw wire value is server-absolute and can
  never match webroot-relative manifest paths; an uploads dir outside the webroot
  fails closed). `--undo-last` restores the NEWEST snapshot (mutually exclusive
  with an explicit name; composes with every targeting flag) — the ergonomic
  "that apply made it worse" rollback. Restore mode itself is ftp-only (zip
  rewriting is v2).
- EVERY restore (managed name/`--undo-last` OR an explicit snapshot path)
  requires the CURRENT manifest identity: BOTH `site_raw` and `webroot` must
  be recorded and match the current run.  A sanitized-only `site` is never
  proof (two labels can sanitize to one directory component, e.g.
  `b-cher.example`), and a missing `webroot` is never a wildcard.  A
  pre-identity manifest is unsupported and refused with a clear "regenerate
  the snapshot with the current format" message; there is NO migration or
  trusted-import bypass.  Snapshots therefore require the current identity
  format, and old snapshots must be regenerated, not restored.  The current
  identity is resolved BEFORE remote setup and passed into
  `restore_snapshot` as REQUIRED arguments (no default and no shape-only
  fallback for direct callers); the manifest retained by `verify_snapshot`
  must match that expected `site_raw` and `webroot` EXACTLY (no normalization)
  before any file/table work, so a snapshot swapped after the pre-stack gate
  can never restore another site's bytes.
- Every restore is verify-after-write (re-read + sha256 match for files; row counts
  reported for tables via bridge). Restores NEVER auto-apply: without `--apply`
  the run is a full-pre-pass dry run printing the as-if report; with `--apply` the
  run is gated on the registry's canonical confirm (--yes / interactive y-N).
- DB restore requires the bridge `db_restore_table` action (INSERT-only chunks +
  temporary table swap semantics validated per chunk); v1 restores whole tables,
  not row-level (YAGNI).

### walk (client-facing crawler)
- `wpt walk` (ftp only — no live site offline): starts at --wp-url (honoring
  --override-ip), frontier seeded from sitemap.xml (+ sitemap index), expanded by
  same-host links extracted from rendered HTML; per page: ALL asset URLs
  (img src, srcset, CSS url() from page + linked generated CSS [L11]), forms found
  (action URLs — detected, never submitted).
  - Politeness: `walk.max_pages` (default 200), `walk.delay_s` (default 0.5),
    `walk.max_depth` (default 5) — settings profile, no statics.
  - Output: markdown + a JSON twin ({site, pages, live_refs, forms, fetched}) —
    every command with `--report` writes both. The "live reference set" it produces
    is the single source
    of truth for "what the site uses right now", consumed by trim-media and
    re-fetched wholesale by `wpt verify` [L2]. Per-page status/title tables and
    menus/external-link reports = v2 roadmap (WalkResult v1 carries pages/refs/
    forms/fetched only).

## Local rehearsal + serve (live-validated design)

- Local mode `--apply` REHEARSES: the actions registry's local stack is a
  `MutableZipSource` (wpt/sources/zipwriter.py) — a ZipSource subclass whose
  write/delete ops stage an in-memory overlay (guarded by the SAME shared
  write-guard as FtpSource) over the read-only view. The apply mutates only
  the overlay; on success it materializes `<zip>-rehearsed-<YYYYmmdd-HHMMSS>.zip`
  beside the original (tmp-then-rename, faithful host-export twin, root
  prefix preserved). The ORIGINAL zip is never opened for write — it IS the
  rollback (no pre-action snapshot in local mode). DB-mutating actions stay
  ftp-only (their applies= tuples never include local).
- `wpt serve` (local only): stdlib threaded static HTTP server over a zip on
  127.0.0.1 (never exposed), traversal-safe, .php served as raw source.
  Its pair is `wpt verify`: LOCAL mode with a `--wp-url` runs against the
  served rehearsal (plain session, no bridge, no source — verify never reads
  the zip); local WITHOUT a wp_url refuses. Rendering-page crawling still
  needs the real site (static PHP is not parsed as HTML) — media/asset
  verification works fully offline.
- Write-guard (types.py, live-hardened): PROTECTED core dirs (wp-admin/,
  wp-includes/) protect their WHOLE SUBTREE on the WRITE path (exact
  membership let nested core paths through — fixed after the MutableZipSource
  review); deletes inside them stay allowed (wp-admin/error_log junk) with
  their own exact-membership rule.

## heal-core (restore checksum-proven core files)

Live-motivated (example.com: wp-includes/version.php + 3 default-theme
files tampered). `@register_action("heal-core", applies=("ftp", "local"))`:
- **Scope = RESTORE only**: the tampered + missing kinds of the core.integrity
  classification (the ONE owner: wpt/audit/integrity.py's public primitives —
  `added_files`, `affected_files_local`, `affected_files_bridge`,
  `_fetch_checksums`). "added" files (top-level/core-dir php not in the
  checksums) are NEVER auto-deleted — custom top-level php can be legitimate;
  the plan names them as investigate-only notes.
- **Version-pinned basis**: version from bridge `info` (ftp) /
  wp-includes/version.php (local); checksums + release zip BOTH for that
  exact version (the en_US checksums API and the downloads.wordpress.org
  release zip are the SAME distribution — a restored file verifies by
  construction; live-verified for 7.1: the zip's file md5s equal the
  checksums answers exactly, and the 7.1 map DOES checksum the default
  theme, 235 twentytwentyfive entries). The plan ALSO runs the integrity
  check's `resolve_theme_skew` [L12] before healing: a pristine official
  default-theme AUTO-UPDATE past the bundled copy is dropped (restoring
  the bundled bytes would DOWNGRADE the theme) — every failure shape
  keeps the tampered classification, so plan and audit can never
  disagree.
- **The write**: `write_bytes(..., allow_core=True)` — the audited surgical
  guard unlock (types.py) for exactly `index.php` + `wp-admin/` +
  `wp-includes/` (wp-config.php/.htaccess NEVER core-healable; bare dir
  names stay refused; a warning log line records every unlocked write).
- **Mandatory verification**: after the writes, ONE bulk digest pass
  (bridge `core_md5` / local `read_many`+md5) against the same checksums;
  any mismatch leaves the item not-done and fails the apply (rc 1, the
  pre-action snapshot holds the originals — `wpt restore` reverts).
- **Safety**: the registry's standard flow — dry-run plan, confirm, the
  fail-closed pre-action snapshot of exactly the heal targets,
  post-apply purge_cache, and the local-mode REHEARSAL branch (the
  original zip is the rollback; the healed copy materializes beside it).
- `WpOrgApi.fetch_core_release_zip(version)`: binary 1h cache under
  `.wpt-cache/`, PK-magic + `wordpress/`-prefix validation, corrupt
  cache entry = a miss (never a returned lie).

## deploy (publish a prepared webroot to a host over SSH)

`wpt deploy` publishes a prepared webroot zip to a host WITHOUT the archive
ever landing there: the zip is read entry-by-entry and a NORMALIZED tar
(files `0644`, dirs `0755`, `mtime=0`) is piped into
`ssh <target> 'tar -xf - -C <webroot>'`, so the account never holds the zip
and the extraction at once [L21: a live migration exhausted the account quota
mid-transfer with only "Error in the SSH layer" and truncated chunks]. The
archive's single top-level host dir is stripped ONCE, by the producer (the
`ZipSource` root owner); the consumer command contains no `--strip-components`
[L22: a first attempt shipped files one level too deep because the strip ran
in BOTH].

The deploy is ADDITIVE (`tar -x` never deletes — host-injected dirs like
`wp-content/imunify-security/` survive; the verifier never demands the
absence of a file the artifact did not ship). Ordering is the contract:
dry-run plan (pure; spawns nothing) → **quota preflight** → stream →
**post-extract layout assertion** → **manifest verification**. The preflight
measures the deploy account's available space (`df -Pk` on the webroot's
filesystem, `quota`, the min of both, a write-and-remove probe when neither
parses) plus `deploy.preflight_margin_bytes` and refuses with one line
naming both numbers BEFORE a single byte moves; unmeasurable space is a
refusal too. A mid-transfer write failure carrying a quota signature is
re-reported as a QUOTA failure, never as a network error. The layout
assertion REQUIRES `wp-config.php` + `wp-load.php` +
`wp-includes/version.php` and `wp-content/` at the webroot root and refuses
the double-strip RESIDUE (a `wp-includes` child such as `ID3/`, or
`about.php`, at the root); success is never reported for a target that fails
it. The password comes from an env var or a prompt, reaches ssh through an
`SSH_ASKPASS` helper reading a 0600 file (never argv, never the child's
environment); without one, key/agent auth runs with `BatchMode=yes` +
`ServerAlive*`, and with neither the deploy refuses cleanly. A transfer
manifest (format `wpt-deploy-manifest` v1, the `wpt/backup.py` manifest
STYLE plus `archive`/`target` blocks) is written only on a verified deploy;
per-file sha256s are computed in the producer as the bytes pass and
re-verified on the target. Local mode rehearses the whole engine into
`local:<dir>` (a real `tar -x`, no network).

## prune-core (delete stale core files WordPress no longer ships)

Live-motivated: a masked `wp-includes/version.php` let years of incomplete
upgrades accumulate many files wp.org no longer ships (a legacy bundled
library, the generated icon set, old block `view.js`/`editor.css` pairs,
retired `css/dist`+`js/dist` bundles, legacy header images, language
catalogs) — all listed by `wp-cli core verify-checksums` as "should not
exist", only the executable ones seen by
`core.integrity` (its `added` scope), and never deletable by it. The
operator was hand-deleting over SSH. `@register_action("prune-core",
applies=("ftp","local"))`:

- **THE TWO-PROOF RULE** — a file is planned only when (1) it is absent from
  the official checksum map of the site's exact version + build locale (the
  same comparison basis as `core.integrity` and heal-core), (2) it is inside
  `wp-admin/`, `wp-includes/` or a `wp-content/languages/` catalog path
  (integrity's own predicate — never outside those trees), AND (3) it
  carries a staleness marker: it appears in the checksum map of a PREVIOUS
  patch release of the same build (release provenance via `WpOrgApi` at the
  same locale, deliberately WITHOUT the en_US fallback — a localized
  build's own file must never be "proven stale") **OR** it matches a
  `core_integrity.known_stale` signature (fnmatch name + content marker +
  max_bytes + note; the `known_added` precedent). Files matching NEITHER are
  unknown additions (a possible implant): never planned, named in one
  investigate-only line exactly like heal-core names `added`.
- **Fail-closed**: unknown version, unavailable comparison map, or a
  previous-release window whose maps ALL fail ⇒ the whole plan refuses, zero
  deletions. A `.0` patch (no earlier release in its series) gets one warning
  and signatures only — no invented version.
- **The delete** goes through the source's own deletable guard (wp-config.php
  / .htaccess / index.php and the bare core dir names stay refused); every
  delete inside a protected core subtree is announced by the audited warning
  line first. **Mandatory verification**: the tree is re-walked after the
  deletes — a planned file that survived is an item NOT done; a current-map
  file that was present before and gone after without being planned is
  collateral damage. Either ⇒ rc 1, the pre-action snapshot (exactly the plan
  scope) is the rollback. Idempotent: a second run plans nothing.

## Offline database source (`--db-uri`)

`--db-uri` names a DIRECT database as the source of DB data in LOCAL mode (it
replaces the dump, and for `clean-db` the bridge). Accepted form:
`mysql://[user[:password]@]host[:port]/database[?charset=utf8mb4]` (alias
`mysql+pymysql://`); host defaults `127.0.0.1`, port `3306`, charset
`utf8mb4`; the database name is required; every other shape is refused with
the accepted form named. The password comes from `--db-password-env` (the
same `resolve_password` path as `--password-env`, unset = the same clean
refusal) and takes precedence over an inline one; the URI prints redacted
only and no log line, usage error or artifact ever carries it.

`clean-db --db-uri` runs the SAME plan, the SAME named ops (`revisions`,
`expired_transients`, `orphan_meta`, `optimize_tables`), the SAME results
contract and the SAME confirmation as ftp mode — the plan builder and the
settle step are literally the same code, and the ops' SQL is the bridge's,
mirrored ONCE and contract-pinned against `bridge.php` by a test that parses
the PHP literals (editing either side fails the suite). The table prefix is
DISCOVERED from the database's own options table by the ONE owner of table
identity, `wpt.media_refs.resolve_role` / `options_prefix` (the same owner the
analyzer asks — see "Table identity is one fail-closed owner"; `wp_` is never
assumed; **ambiguity REFUSES, naming every candidate table once per (wire,
role, input); absence refuses**). `--db-uri` is NOT a route around a
contested identity: it resolves the identity from a live
`information_schema.COLUMNS`, and a plugin table carrying the same column pair
(AIOSEO 4.x's `aioseo_options`) contests it exactly as the dump does, so
`clean-db` refuses there too [L53]. `--re-dump
<path>` then writes a fresh mysqldump-style dump — the operator's next upload
artifact — produced by the tool's own pure-Python writer (no `mysqldump`
binary; operator machines have none), written to a unique same-directory
`.part` temp and installed with an atomic hard link that refuses to overwrite
(so a target that appeared mid-dump is never clobbered), and only after a
VERIFIED apply. The offline path does not pretend
to the ftp machinery: no pre-action snapshot (the rollback is the dump the
database was imported from — the apply says so out loud), no zip rehearsal
(it touches no webroot file), no cache purge. After a successful apply it
re-reads the same facts and re-checks every applied op's trigger; a
surviving (or unmeasurable) trigger leaves the item not-done and the run at
rc 1. `--db-uri` in ftp mode is a clean one-line refusal; on any command
other than `clean-db`/`doctor` it is refused rather than ignored.

**Dependency**: one optional package, imported lazily and only for a
`--db-uri` connect — PyMySQL (pure Python, MIT, MySQL + MariaDB); install
`PyMySQL[rsa]` (the extra is MySQL 8's `caching_sha2_password`). Missing =
one line naming the package, never a traceback. `doctor` in local mode with
`--db-uri` gains one `database (--db-uri)` row.

## Post-apply cache purge

Every successful ftp-mode action `--apply` asks the bridge for `purge_cache`
exactly once (best-effort hygiene: LiteSpeed/W3TC/WP Super Cache would
otherwise serve stale pages and the operator sees "no change"). Failure = ONE
warning; rc and report never move. Never runs on dry runs, refusals, failures
or local mode. `restore --apply` is the exception and does NOT purge: it
restores files the operator selects, not the live site's cached output, and it
returns before the action registry's purge step.

## Module ownership map (historical)

The project was built in sequential ownership slices; this table is kept as an
architecture map for maintainers.

| Order | Owner | Files |
|---|---|---|
| W1a | done | `pyproject.toml`, `wpt/{__init__,types,log,settings}.py`, `wpt/data/profiles/default.json`, `tests/test_{types,log,settings}.py` |
| W1b | done | `wpt/{config,report,cli}.py`, `tests/test_{report,cli}.py` |
| W2 | coord | `wpt/sources/{__init__,base,ftp,zip}.py`, `tests/sources/*` |
| W3 | coord | `wpt/dnsoverride.py`, `tests/test_dnsoverride.py` (recipe: docs/research/R1.md) |
| W4 | coord | `wpt/wpbridge/{__init__,client}.py`, `wpt/wpbridge/bridge.php`, `tests/test_bridge_*.py` (+ `db_dump`/`db_restore_table` actions for backup/restore) |
| W5 | coord | `wpt/localmode/{__init__,sql_dump,analyzer}.py`, `tests/test_sql_dump.py` (arch: docs/research/R4.md) |
| W6 | coord | `wpt/audit/*` (+ check registries), `tests/audit/*` |
| W7 | coord | `wpt/backup/`, `wpt/restore/`, `wpt/walk.py`, `wpt/users.py`, `wpt/actions/*` (+ action registry), CLI wiring, `tests/test_e2e_local.py`, docs |

## Framework registries (extension points — no core edits to add behavior)

- `wpt/audit/registry.py`: checks are `@register_check("name", applies=["ftp","local"])`
  decorated functions returning list[Finding]; `wpt audit --only x --skip y` selects.
- `wpt/actions/registry.py`: actions are `@register_action("clean-files")` decorated
  `run(ctx) -> Plan`; the CLI dispatches through the registry, not a hardcoded map.
- Bridge ops are a data-driven whitelist in the PHP (name → handler map); adding an
  op = one entry + one client method. Never arbitrary SQL/PHP.
- Profile keys drive every threshold (see Settings); registries read settings, never
  literals. New tunables = new profile key + Settings field, nothing else.

Each writer: run the FULL suite
(`python3 -m pytest tests/ -q -n 20 --dist worksteal`; `-n auto` works and
`-n 20` is tuned for 12 cores — serial fallback `python3 -m pytest tests/ -q`)
— all green before handing back. New lessons found → add to Test Map + this spec via the coordinator.

## Core interfaces (in `wpt/types.py`, W1)

```python
@dataclass
class Entry:
    path: str            # relative to source root, POSIX
    is_dir: bool
    size: int
    is_link: bool = False

@dataclass
class Finding:
    category: str        # dotted: "webroot.junk", "db.revisions", "media.orphan"
    name: str
    detail: str
    bytes: int = 0       # reclaimable estimate
    count: int = 1
    risk: str = "low"    # low|medium|high
    fix: str = ""

@dataclass
class PlanItem:
    category: str
    target: str
    detail: str
    bytes_est: int = 0
    requires_apply: bool = True
    done: bool = False
    ref: str = ""       # structural reference (e.g. a login); never parsed
                        # back out of the human `detail` label

class Source(ABC):      # full contract in W1; safety rules below
    root: str
    # list_dir, walk, read_bytes, read_bytes_bounded, write_bytes, delete,
    # rmdir_recursive, exists, size, close  — see original interface below
```

Source safety (enforced in the ABC's concrete children, tested): reject `..` in paths
(and C0/DEL/surrogates, which would reach `ftplib.putline`); `delete`/`rmdir_recursive`
refuse `wp-config.php`, root `.htaccess`, `index.php`, `wp-admin`, `wp-includes`
(case-folded, and the structural `wp-content` guard holds at root `""` too);
`write_bytes` on `wp-config.php` requires `allow_config=True` (config files are edited
via a dedicated, diff-printing helper — they are configuration, never source code
[L3]); `rename` guards BOTH the source and destination, with the audited
`allow_core` unlock for update-core's tree swap and the verified-snapshot
restore that rolls an update/heal/prune back.

FTPS transport: `ftp.verify_tls` (default **true**) uses
`ssl.create_default_context()` — certificate and hostname verification —
before `auth`/`login` transmit the password; `ftp.ca_file` optionally adds a
private CA. `ftp.verify_tls=false` is the explicit pre-migration opt-out:
the connector uses an unverified context and logs a loud warning per
connect. A bare `ftplib.FTP_TLS()` (stdlib `CERT_NONE`) is never used.

## Settings / profiles (W1, single source of tunables)

`wpt/data/profiles/default.json` — every knob, consumed via `wpt/settings.py`:

```json
{
  "ftp": {
    "port": 21,
    "timeout_s": 45,
    "retries": 1,
    "verify_tls": true,
    "ca_file": "",
    "max_consecutive_failures": 5,
    "parallel_reads": 4
  },
  "bridge": {
    "ttl_minutes": 15,
    "name_retries": 3,
    "timeout_s": 30,
    "scan_cap": 0,
    "max_response_bytes": 16777216
  },
  "db": {
    "autoload_big_bytes": 102400,
    "autoload_total_warn_bytes": 1048576,
    "free_space_warn_bytes": 1048576,
    "connect_timeout_s": 10.0,
    "read_timeout_s": 300.0
  },
  "media_optimize": {
    "jpeg_quality": 82,
    "jpeg_max_dim": 2560,
    "png_max_dim": 1200,
    "min_savings_ratio": 0.2,
    "skip_below_bytes": 30720,
    "exclude_prefixes": [
      "wp-content/uploads/gravity_forms/"
    ]
  },
  "media": {
    "extensions": [
      "jpg",
      "jpeg",
      "jpe",
      "png",
      "gif",
      "webp",
      "avif",
      "bmp",
      "ico",
      "svg",
      "tiff",
      "mp3",
      "m4a",
      "ogg",
      "oga",
      "wav",
      "flac",
      "mp4",
      "m4v",
      "webm",
      "mov",
      "avi",
      "ogv",
      "3gp",
      "3g2",
      "pdf",
      "doc",
      "docx",
      "xls",
      "xlsx",
      "ppt",
      "pptx",
      "odt",
      "key",
      "txt",
      "csv",
      "zip",
      "gz",
      "tar"
    ],
    "dump_behind_row_ratio": 0.5
  },
  "core_integrity": {
    "known_added": [
      {
        "name": "wordfence-waf.php",
        "marker": "wordfence/waf/bootstrap.php",
        "max_bytes": 2048,
        "note": "the Wordfence plugin's WAF bootstrap, deployed at the webroot top level by Wordfence itself and wired via auto_prepend_file"
      }
    ]
  },
  "http": {
    "timeout_s": 30,
    "verify_tls": false,
    "max_response_bytes": 8388608
  },
  "wp_org": {
    "core_version_check_url": "https://api.wordpress.org/core/version-check/1.7/?locale={locale}",
    "core_checksums_url": "https://api.wordpress.org/core/checksums/1.0/",
    "plugins_update_check_url": "https://api.wordpress.org/plugins/update-check/1.1/",
    "themes_update_check_url": "https://api.wordpress.org/themes/update-check/1.1/",
    "core_release_zip_url": "https://downloads.wordpress.org/release/wordpress-{version}.zip",
    "localized_release_zip_url": "https://{subdomain}.wordpress.org/wordpress-{version}-{locale}.zip",
    "theme_release_zip_url": "https://downloads.wordpress.org/theme/{slug}.{version}.zip",
    "default_locale": "en_US",
    "release_zip_prefix": "wordpress/",
    "cache_dir": ".wpt-cache",
    "cache_ttl_s": 3600,
    "json_max_bytes": 8388608,
    "release_zip_max_bytes": 268435456,
    "user_agent_template": "wpt/{version}"
  },
  "proxy": {
    "cert_timeout_s": 30,
    "max_request_bytes": 67108864,
    "cert_validity_days": 7,
    "cert_renew_before_s": 86400
  },
  "log": {
    "level": "info"
  },
  "webroot_junk": [
    "error_log",
    "readme.html",
    "license.txt",
    "wp-config-sample.php",
    ".htaccess.bk",
    "*.sql",
    "host_placeholder_page:home.html",
    "host_placeholder_page:layout-styles.css",
    "host_placeholder_page:404.shtml",
    "host_placeholder_page:test.html",
    "host_account_quota:.ftpquota",
    "superseded_htaccess:old.htaccess",
    "superseded_htaccess:.htaccess.old"
  ],
  "stale_content_dirs": [
    "et_temp",
    "ao_ccss",
    "wpcf7_uploads",
    "wpo",
    "fusionredux"
  ],
  "ghost_table_prefixes": [
    "woocommerce",
    "jetpack",
    "nf3",
    "wpforms",
    "statistics",
    "actionscheduler_actions"
  ],
  "ghost_marker_plugins": {
    "nf3": "ninja-forms",
    "statistics": "wp-statistics"
  },
  "duplicate_plugin_groups": [
    [
      "litespeed-cache",
      "wp-super-cache",
      "w3-total-cache"
    ],
    [
      "elementor",
      "fusion-builder"
    ]
  ],
  "duplicate_plugin_groups_preferred": {},
  "migration_leftovers": [
    "all-in-one-wp-migration",
    "velvet-blues-update-urls",
    "search-and-replace",
    "ai1wm*"
  ],
  "known_heavy": [
    "jetpack",
    "worker",
    "wp-statistics"
  ],
  "mu_plugin_known_platform": [
    "automation-by-installatron",
    "0-worker"
  ],
  "backup": {
    "keep_last": 10,
    "keep_days": 90,
    "stale_temp_age_s": 86400,
    "free_pass_bytes": 2147483648,
    "free_warn_bytes": 524288000
  },
  "walk": {
    "max_pages": 200,
    "delay_s": 0.5,
    "max_depth": 5,
    "max_response_bytes": 16777216
  },
  "suspicious": {
    "max_file_bytes": 1048576,
    "patterns": [
      "(?i)eval\\s*\\(\\s*\\\\?\\s*(base64_decode|gzinflate|gzuncompress|str_rot13|urldecode)\\s*\\(",
      "(?i:eval)\\s*\\(\\s*\\$_(POST|GET|REQUEST|COOKIE)\\b",
      "\\$(\\w+)\\s*=\\s*\\$_[A-Z]+\\[[^\\]]*\\](?:\\s*\\[[^\\]]*\\])*\\s*;\\s*(?i:eval)\\s*\\(\\s*\\$\\1\\s*\\)",
      "\\$GLOBALS\\s*\\[\\s*['\\\"]\\w+['\\\"]\\s*\\]\\s*\\(\\s*\\$"
    ]
  },
  "backup_payloads": {
    "extensions": [
      "*.zip",
      "*.tar.gz",
      "*.tgz",
      "*.sql",
      "*.sql.gz",
      "*.tar"
    ],
    "directories": [
      "sample-backup",
      "updraft",
      "fm_backup"
    ],
    "max_park_file_bytes": 268435456
  },
  "conditional_junk": {
    "geoip_files": [
      "GeoIP.dat",
      "GeoIPv6.dat"
    ],
    "geoip_plugins": [
      "geoip-detect"
    ],
    "page_cache_files": [
      "*.wpc.log",
      "wpo-plugins-tables-list.json"
    ],
    "page_cache_dirs": [
      "wp-content/cache/supercache/"
    ],
    "page_cache_plugin": "wp-super-cache"
  },
  "obsolete_assets": {
    "known_added": [
      {
        "name": "*.eot",
        "note": "legacy EOT font — no @font-face needs it (every browser in service reads woff2/woff); shipped OFF: enable per site",
        "enabled": false
      },
      {
        "name": "*.map",
        "note": "CSS source map — only read by a browser devtools session, never by a visitor; shipped OFF: enable per site",
        "enabled": false
      },
      {
        "name": "*.po",
        "note": "gettext SOURCE catalog — .mo/.l10n.php are the runtime formats; enable ONLY the locales the site does not serve (the audit's Site section names the site locale)",
        "enabled": false
      }
    ]
  },
  "cull_media": {
    "min_oversize_px": 0,
    "max_plan_files": 0
  },
  "env": {
    "php_min_active": "8.2"
  },
  "webp": {
    "quality": 80,
    "skip_below_bytes": 30720,
    "max_dim": 0,
    "purge_originals": false,
    "data_prefixes": [
      "wp-content/uploads/gravity_forms/"
    ],
    "verify_pages": 20,
    "verify_retries": 2,
    "verify_retry_delay_s": 1.0,
    "challenge_max_bytes": 32768
  },
  "deploy": {
    "ssh_port": 22,
    "connect_timeout_s": 30,
    "server_alive_interval_s": 15,
    "server_alive_count_max": 4,
    "strict_host_key_checking": "accept-new",
    "probe_timeout_s": 120,
    "stream_timeout_s": 0,
    "stream_bytes_per_s": 20971520,
    "stream_overhead_s": 60,
    "verify_batch_paths": 200,
    "manifest_archive_sha256": true,
    "preflight_margin_bytes": 268435456,
    "preflight_write_probe_bytes": 8388608,
    "preflight_require_known_space": true,
    "required_files": [
      "wp-config.php",
      "wp-load.php",
      "wp-includes/version.php"
    ],
    "required_dirs": [
      "wp-content"
    ],
    "residue_paths": [
      "ID3",
      "about.php",
      "version.php",
      "class-wp-error.php",
      "class-wp-query.php",
      "rest-api",
      "blocks",
      "SimplePie",
      "pomo",
      "sodium_compat",
      "Text",
      "Requests"
    ],
    "quota_signatures": [
      "no space left on device",
      "disk quota",
      "quota exceeded",
      "over quota",
      "edquot",
      "not enough space",
      "no room left",
      "filesystem full",
      "out of disk space",
      "quota violation",
      "write remote: failure",
      "error in the ssh layer"
    ],
    "auth_signatures": [
      "permission denied (publickey",
      "permission denied, please try again",
      "authentication failed",
      "too many authentication failures",
      "no supported authentication methods",
      "host key verification failed",
      "host key has changed",
      "no mutual signature algorithm"
    ],
    "network_signatures": [
      "connection refused",
      "connection reset",
      "connection timed out",
      "operation timed out",
      "network is unreachable",
      "no route to host",
      "could not resolve hostname",
      "broken pipe",
      "connection closed",
      "kex_exchange_identification",
      "connection lost"
    ]
  },
  "update": {
    "pre_release_allowed": false,
    "maintenance": true,
    "driver": "auto"
  },
  "run": {
    "deadline_s": 3600,
    "cleanup_deadline_s": 120
  },
  "web_script": {
    "extensions": [
      ".php",
      ".phtml",
      ".php5",
      ".php7",
      ".phps",
      ".phar",
      ".inc",
      ".module"
    ],
    "signatures": [
      {
        "name": "hash_equals(",
        "note": "a constant-time token compare"
      },
      {
        "name": "$_GET[",
        "note": "a GET request parameter"
      },
      {
        "name": "scandir(",
        "note": "a directory listing call"
      },
      {
        "name": "/home/",
        "note": "an absolute home-directory path"
      },
      {
        "name": "phpinfo(",
        "note": "a PHP configuration dump"
      },
      {
        "name": "php://input",
        "note": "the raw request-body stream"
      }
    ],
    "request_globals": [
      {
        "name": "$_GET",
        "note": "a GET request parameter"
      },
      {
        "name": "$_POST",
        "note": "a POST request parameter"
      },
      {
        "name": "$_REQUEST",
        "note": "a merged request parameter"
      },
      {
        "name": "$_COOKIE",
        "note": "a request cookie"
      }
    ],
    "known_artifacts": [
      {
        "name": "bridge-????????.php",
        "note": "wpt's own token-guarded bridge endpoint, deployed by wpt itself (Bridge.ensure); destroy() is best-effort, so a leftover copy is wpt residue to remove, not a third-party backdoor. A '?' is ONE HEX DIGIT (case-insensitive), never 'any character': the shipped name is bridge-<8 hex>.php, and a wider pattern would exempt an attacker's bridge-shell.php"
      },
      {
        "name": "wpt-probe-????????.php",
        "note": "wpt's own short-lived PHP runtime probe (PhpProbe); it self-deletes after the token-gated answer and the stale sweep removes an expired copy, so a leftover is wpt residue, not a third-party backdoor. A '?' is ONE HEX DIGIT (case-insensitive)"
      }
    ],
    "max_bytes": 262144
  },
  "probe": {
    "ttl_minutes": 15,
    "name_retries": 3,
    "timeout_s": 15
  },
  "tls": {
    "warn_days": 14
  },
  "logs": {
    "max_files": 20,
    "max_file_bytes": 4194304,
    "max_archive_bytes": 33554432,
    "max_decompressed_bytes": 268435456,
    "detail_limit": 20
  },
  "discover": {
    "max_candidates": 50
  },
  "source_scan": {
    "max_file_bytes": 1048576,
    "detail_limit": 20,
    "ignore_prefixes": [
      "wp-admin/",
      "wp-includes/"
    ]
  },
  "files": {
    "max_files": 20,
    "max_file_bytes": 8388608
  }
}
```

The block above is the shipped `wpt/data/profiles/default.json`, verbatim and
complete (38 top-level keys: 31 object sections and 7 list sections) —
regenerate it from the file, never hand-type it; `tests/test_docs.py`
compares every leaf against the profile itself: objects and lists recurse,
lists carry the same values in the same order, and each scalar (including a
list member) must match value AND JSON type (`false` never equals `0`, `21`
never equals `21.0`). One structural
default lives in code and is therefore NOT a key of the shipped file:
`core_integrity.known_stale` (`CoreIntegritySettings.known_stale`, default
`[]`, read by `prune_core._known_stale_signatures`). An empty list is valid —
the release-provenance proof then stands alone — and a profile that adds
signatures reaches the same field. Only the shipped file's keys are the
listing's contract; a dataclass default is a floor, not a shipped value.

`wpt.settings.load(profile_path, overrides: dict[str, Any])` — dot-path overrides
(`--set media_optimize.jpeg_quality=75`), validated, deep-merged. All modules receive
`Settings` via the `Ctx` object; nobody reads env or hardcodes numbers themselves.

optimize-media never optimizes — or even plans — a file under
`media_optimize.exclude_prefixes` (webroot-relative prefixes; a directory
prefix ends in `/`; the shipped default protects the Gravity Forms
submission-record subtree [L25: a live run recompressed people-uploaded form
photos]); the plan summary reports how many files the exclusion skipped, and
excluded files are never READ (not even for the plan). Silence, not a
finding — the action is not a check.

## Bridge protocol (W4) — heart of remote mode

Binding implementation recipe: `docs/research/R2.md` (verified against WP source).

### bridge.php
```php
define( 'WP_USE_THEMES', false );
define( 'WP_DISABLE_FATAL_ERROR_HANDLER', true );   // BEFORE wp-load: stop WP masking hard fatals
require_once __DIR__ . '/wp-load.php';
error_reporting( E_ALL );                            // AFTER wp-load: WP rewrites these during load
ini_set( 'display_errors', '1' );                    //   for JSON requests otherwise
if ( ! function_exists( 'get_plugins' ) ) {          // WP <= 6.7 needs the admin include
    require_once ABSPATH . 'wp-admin/includes/plugin.php';
}
```
- `wp_upload_dir( null, false )` (no mkdir side effect); `json_decode(..., JSON_THROW_ON_ERROR)`.
- Single file; every action wrapped in `try/catch (Throwable)` returning
  `{"ok":false,"error":...,"type":...,"line":...}` with HTTP 200. [L4]
- Non-stream answers are held under ONE cap, `bridge.max_response_bytes`
  (shipped 16 MiB): the same bound applies with and without a run deadline,
  so a valid large `core_md5`/`info` answer (a real 4,008-path map is
  339,095 bytes) is accepted while a runaway body is refused before it is
  buffered whole. `db_dump` is NDJSON and streams line-by-line through
  `call_stream`; the one-shot cap never applies to it. The client reads
  both transports through `_SocketResponse.raw.read1` (64 KiB chunks, one
  absolute budget check per chunk), never one byte at a time.
- Auth: embedded 32-hex token via `?t=` compared with `hash_equals` + embedded expiry
  timestamp; failure returns plain-text 404 'nf'. Self-destruct param deletes the file.
- Action whitelist (POST JSON via `php://input`), nothing else:
  `info` (site + plugin catalog + environment facts: php_version,
  php_version_id, memory_limit, max_execution_time, sapi, server_software,
  mysql_version, wp_debug), `db_audit` (tables incl. per-table `collation`;
  `users` = admins list via the `<prefix>user_level` = 10 join, null =
  unknown), `media_map` (refs→attachments by file AND by stem, stripping
  `-WxH`/`-scaled` suffixes [L5: migrated sites lack attachment metadata, so variant
  matching must be stem-based]), `core_md5` (bulk server-side md5 of
  webroot-relative core paths, ≤5000 per call, traversal-refused —
  live-validated: client-side FTP reads of ~3780 core files are not viable;
  the bridge is the bulk-work owner, like db_dump/media_map),
  `db_clean` (named ops ONLY: revisions,
  expired_transients, orphan_meta, optimize_tables — NO arbitrary SQL), `plugin_deactivate`,
  `media_rewrite_refs` (two modes over one op: a read-only NDJSON
  reference SCAN terminated by `{"ok":true,"rows":N,"gated_cells":M,
  "truncated":false}` — or by `{"truncated":true}` at the structural cap,
  which the client REFUSES — and an APPLY whose rows are re-read after the
  write and whose serialized values are rewritten server-side through
  `maybe_unserialize` → recursive string-leaf replace → `maybe_serialize`;
  every table/key/column whitelisted, every row validated before the first
  write, the object/alloptions caches dropped), `purge_cache`
  (function_exists-guarded), `fileperms`,
  `users_reset`, `user_create` and `reconcile_active_plugins` (all DEFAULT to
  read-only via a strict `apply` boolean; see the actions contract),
  `db_reconcile`-shaped
  table ops unchanged. `info` also answers `locale` (get_locale()) and
  `permalink_structure` — each `''` for a non-string option value (a bare
  `(string)` cast would emit "Array to string conversion" under the bridge's
  `display_errors` and corrupt the whole answer, R12).
- Requires `wp-admin/includes/plugin.php` include for `get_plugins()` (verify via R2).

`media_delete` accepts any path that resolves INSIDE `wp_upload_dir()`'s
basedir (NUL stripped; empty/absolute/`..`-segment refused; realpath
containment enforced, and re-proved at the last possible moment with
clearstatcache + realpath identity + dev/ino — a symlink swapped inside the
transaction is reported as refused, never unlinked). NO path-shape rule:
the former `must be under YYYY/` requirement was a layout assumption that
failed a live trim-media closed (the real union figure was a small set, versus
a degraded walk-only count of most files and a large byte total; the later
measurement disproved the degraded count, so 0 were deleted).

`users_reset` — reset one or more users' passwords. Params: `apply` (strict
boolean, default false) and the optional `logins` list: its PRESENCE means
TARGETED (only rows whose `user_login` matches an entry, compared
case-insensitively; EVERY requested login must match or the whole op throws
BEFORE the first write, so a typo can never silently reset a subset), its
ABSENCE means every user, and an empty list is refused (never read as
"everyone"). Every selected `wp_users` row gets
`wp_generate_password(20, true, false)` + `wp_set_password()`
(wp_set_password alone does NOT destroy sessions: the op also calls
`WP_Session_Tokens::get_instance($id)->destroy_all()`) and the answer
carries `{login, email, roles, password}` per user. The ACTION's
credentials contract (secrets rule): the plan/log/report NEVER carry a
password — they reach the operator ONCE, on stdout, from the CLI, EVEN on
rc 1 (a failed verification still revoked the old passwords; the snapshot is
the rollback). A bridge answer row is published to the holder WHOLE or NOT
AT ALL (non-empty `login` + non-empty `password`; `email` optional): every
field is read with `.get` + a type check so a missing key can never escape
as `KeyError` (which the registry's `except (WptError, OSError)` does not
catch — traceback, lost rc, and no credentials for a site whose passwords
were just revoked); an unusable row raises `BridgeError` naming the row
index and login only, while every OTHER publishable row in the same answer
is still published and printed on the rc-1 run. The target rule
(`--login` repeatable = the default shape; `--all` = everyone; neither =
refusal; an unknown login names the known roster) and the shared
table-identity + credential-row contract live in `wpt/users.py`, the one
owner both user actions ask.

`user_create` — create ONE user. Params: `apply` (strict boolean, default
false), `login`, `email`, `role` (non-empty strings; the role must be an
existing role). Read-only, the op validates against the live site (login
after `sanitize_user(strict)` — the sanitization `wp_insert_user()` itself
applies — no longer than 60 characters, not blocked by the site's
`illegal_user_logins` filter, not already taken; email `is_email()` and
unused; role existing)
and answers the account that WOULD be created, so a plan that passes
cannot fail at insert time for a reason the site already knew. With `apply` the op
generates the password with `wp_generate_password(20, true, false)`, inserts
through `wp_insert_user()` (which re-runs the duplicate checks — the
plan/apply race — hashes the password, sets the role and fires
`user_register`), then READS THE ACCOUNT BACK with `get_userdata()` and
answers the read-back plus the plaintext password; no notification email is
sent. The plan-side answer carries the sanitized login, the apply
verification compares it against the read-back login, and an unusable row
follows the same whole-or-nothing credential contract as `users_reset`.

`reconcile_active_plugins` — compares `get_option('active_plugins')` against
`get_plugins()`; with `apply` it rewrites the option with the CORE-FAITHFUL
2-argument `update_option()` (the 3-arg form would flip autoload on WP 6.6+)
and re-reads it; it REFUSES when the inventory is unavailable or the option
is not an array (WP's own repair would deactivate EVERYTHING, which is the
opposite of a reconcile) and reports an unplanned removal as a failure.

### client.py
- Fresh random filename per upload (`bridge-<8hex>.php`). [L6: LiteSpeed caches 404
  responses per-URL — a bridge URL that 404'd once stays 404 until renamed; on
  site-404-HTML response: re-upload under a new name, retry ≤ name_retries]
- `call()` raises `BridgeError` carrying the server payload; `destroy()` in `finally`.

## DNS override (W3)
- **UNBLOCKED**: binding recipe in `docs/research/R1.md` (empirically verified, 38/38
  checks). W3 implements `resolve_session` + `run_proxy` exactly per that report:
  host-keyed pool + `_new_conn` dial override (NOT the server_hostname approach),
  `trust_env=False`, one-time `disable_warnings(InsecureRequestWarning)`, host-gated
  override documented (cross-host redirects fall back to real DNS), pin urllib3<3.
- `resolve_session(hostname, ip, port=443) -> requests.Session` via custom
  HTTPAdapter + urllib3 connection that dials `ip:port` (the URL's explicit
  port, default 443) with `server_hostname=hostname`,
  Host header = hostname, TLS verify off (documented: only for pre-migration sites),
  warnings suppressed. Exact recipe comes from research task R1 — do not guess.
- `run_proxy(...)`: threaded TLS-terminating browser proxy; per-request
  `http.client.HTTPSConnection` with CERT_NONE context; rewrites absolute
  `https://hostname` → `https://localhost:port` in bodies; filters
  content-length/connection/csp/alt-svc headers; rewrites Location + Set-Cookie
  domain; `ensure_cert(dir)` self-signed cert helper. [L7: cert interstitial bypass
  via typing "thisisunsafe" documented in README for Chrome]  The cert pair is
  generated into fresh temp files and atomically replaced onto the directory
  entries whenever it is (re)generated — CN=localhost with SAN localhost +
  127.0.0.1 + ::1, reused while `_cert_pair_usable` proves it unexpired,
  key-matched and still carrying those exact localhost subject/SAN names (a
  planted symlink/FIFO never receives bytes; `proxy.cert_timeout_s` bounds
  openssl), and request bodies ride ONE absolute deadline, require the
  exact declared Content-Length, and are refused 413 above
  `proxy.max_request_bytes` before buffering.

## FTP source (W2)
- FTPS: `FTP_TLS`, `.auth()`, `.prot_p()`, one reset-retry. [L8: stale connections]
- `walk()` recurses ALL subdirs. [L9: year-only walk missed month dirs like 2018/03]
- Never follow symlinked dirs (`private_html -> public_html` double-counts [L10]).
- **Walk progress heartbeat [L15]**: `WalkMixin.walk()` (the one traversal
  owner, both sources) emits ONE info milestone — `webroot walk: N entries
  so far (Ts elapsed)` — at every 500-entry count milestone once 10s passed
  since the last line (structural log cadence, the backup heartbeat
  precedent: no operator decision changes what a walk returns). The double
  gate keeps an in-memory zip walk silent while a crawling FTP channel
  reports pace — [L15: a live 15k-entry walk ran ~10 minutes with zero log
  output, indistinguishable from a wedged run].
- **read_many bulk protocol**: `read_many(paths) -> (ok: {path: bytes},
  failed: {path: error-str})` — the serial default on `WalkMixin` (loops
  `read_bytes`; per-path `(SourceError, OSError)` -> `failed`, anything else
  raises = RUN-LEVEL). `FtpSource.read_many` overrides it with a
  `ThreadPoolExecutor` of `ftp.parallel_reads` (default 4; 1 = serial through
  the same machinery) DEDICATED worker sessions (ftplib is not thread-safe);
  a worker channel death marks its chunk remainder `failed` with the same
  verdict (no per-path re-reads on a dead session); if EVERY path failed and
  any failure carries a channel signature, the call re-raises
  `FtpChannelUnhealthy` (both messages count: the breaker's "unhealthy" and
  the slow window's "degraded").
- **Two channel bounds in `_call`** (live-measured on a semi-degraded host:
  every passive data connect stalls ~30-45s then SUCCEEDS — a 16k-file bulk
  read crawls at ~1 op/30s serially): the consecutive-FAILURE breaker
  (`ftp.max_consecutive_failures`, outright failed ops) AND the slow-OP
  window (structural: last 10 ops ALL > 0.8 x `ftp.timeout_s` ->
  `FtpChannelUnhealthy` "...degraded..." EVEN IF the op succeeded; any fast
  op resets the window). Together: a dead channel ends in minutes, a
  crawling channel ends after ~10 near-timeout ops, a healthy one is
  unaffected.
- `rmdir_recursive`: deepest-first (FTP has no recursive delete).
- ZipSource: read-only; mutating ops raise `NotWritableError` with a plan message.
  `root=None` (the default the audit/actions/backup stacks use) AUTO-DETECTS a
  single top-level host-export dir ("site.test/..." — the real phpMyAdmin/host zips
  nest everything under one site dir, root-dir entry included) and strips it, so
  every path the checks see is webroot-relative; a flat archive, a top-level FILE,
  or two top-level dirs stay rootless (no guessing — pinned by corpus-shaped
  regression tests in tests/sources/test_zip.py + tests/test_e2e_local.py).

## Run deadlines + graceful SIGTERM (self-bounding runs — rule 10)

wpt runs are NEVER killed from the outside; they end THEMSELVES:
- `wpt/deadline.py`: `Deadline` (monotonic span) + `DeadlineExceeded`.
  `DeadlineExceeded` and `StopRequested` inherit `RunControl`, a
  **`BaseException`** — deliberately NOT a `WptError`, so no
  `except (WptError, OSError)` and no generic `except Exception` can
  turn a stop/expiry into a partial success or a diagnosis row.  The
  command's `finally` teardowns still run, then ONE boundary
  (`cli.main`, and `run_action` for registered actions) logs one
  redacted line, writes the shared failure markdown + JSON pair when
  `--report` was asked for, and returns rc 1. Budget = settings
  `run.deadline_s` (default 3600) overridden by the global
  `--deadline SECONDS` flag; `0` = explicitly unbounded.
  `Deadline.from_ctx(ctx)` is the construction seam; the audit runner also
  injects it into `AuditData.deadline` (checks never receive ctx).
- Hot loops that check it: backup capture (per 200-path read_many batch)
  and db dump (per table), suspicious scan + core.integrity local loop
  (per batch, degrade: ONE warning + partial findings — the local read
  loop never raises; its post-scan theme/known-artifact re-reads re-raise
  a stop/deadline to the shared failure report), the site walk (per page
  visit — partial reference set + the walk's never-raise contract) in
  audit/verify/walk/trim-media.
- SIGTERM: a REQUEST the run answers gracefully — the CLI handler raises
  `StopRequested` (a `RunControl`, not a `WptError`) in the main thread.
  It unwinds through the running command body's finally teardowns
  (bridge destroy, fail-closed cleanup) to the dispatch boundary, which
  writes the failure pair and returns rc 1.  The handler is installed
  before settings load, and the whole post-handler phase (settings,
  credentials, input gates, refusal writer, dispatch) sits inside that
  boundary, so a stop at any of those points is never a traceback. No
  orphaned state either way; the run-level re-raise in backup capture
  makes channel trips fail-closed the same way.
- THE LISTENER EXCEPTION: `wpt serve` and `wpt proxy` are long-running
  listeners that own their process until interrupted. Their accept loop is
  NOT bounded by `--deadline` — the operator stops them with Ctrl-C or
  SIGTERM, which still ends both cleanly through their own teardown. Every
  other command ends itself when its budget expires.

## SQL dump analyzer (W5)

Binding architecture + the full 23-item pitfall checklist + 10 naive-parser failure
fixtures: `docs/research/R4.md` — implement the byte-level state machine there,
NOT regexes; every pitfall/fixture is a required unit test.

- Streaming (chunked) parser, never whole-file loads (dumps can be one 10MB line).
- Table list from CREATE TABLE; row/byte estimates from INSERT tuple parsing
  (statement count != row count); extract `siteurl`, `home`, `active_plugins` (safe
  pure-Python PHP-unserialize: s/a/i/b/d only, length-echo validated, no eval),
  `template`, `stylesheet`, `blog_public`, big autoload options, posts by (type,status).
  SCALAR options are stored PLAIN in real dumps (maybe_serialize keeps scalars
  as-is; corpus-proven) — accept both plain and serialized shapes. Autoload values
  per WP 6.6: {yes, on, auto-on, auto} autoload (AUTOLOAD_ON in analyzer, mirrored
  in the bridge's db_audit SQL, contract-tested).
  Active theme VERSIONS come from style.css header reads through the source
  (both modes) — AuditData.theme_versions feeds updates.themes; unknown = silent.

## Audit modules (W6)

### Core integrity is LOCALE-aware (L17) and top-level-aware (L18)

`core/checksums/1.0/?version=X&locale=<build-locale>` — the build locale
resolves from `wp-includes/version.php`'s `$wp_local_package` (wp-cli
parity: the marker in the file itself), falling back to the site locale
(WPLANG / `get_locale()`) when the file is unreadable, else `en_US`. A
failed or `{"checksums": false}` locale fetch degrades to the en_US map with
ONE warning. heal-core restores from the LOCALE build
(`https://<dash-subdomain>.wordpress.org/wordpress-<V>-<locale>.zip`; en_US
stays `downloads.wordpress.org/release/…`); a zip 404 falls back to en_US but
restores ONLY the paths both builds ship identically and reports the paths
whose official digests DIFFER as unrestorable — it never writes bytes the
integrity check would flag on every subsequent run (the map is fetched BEFORE
the writes, so an unavailable basis refuses with nothing written).

`core.integrity`'s finding detail opens with ONE basis clause — `against the
official <locale> <version> checksums`, naming the EFFECTIVE comparison
locale (en_US after the one-warning fallback) — and heal-core's plan item
detail carries the same build (`restore the official WP <V> <locale> file`).
The per-file evidence lines alone say nothing about WHICH distribution
judged them, and an en_US and a locale map of the same version disagree on
`wp-includes/version.php`: an observed localized re-audit reporting "0 tampered,
0 missing" was read as proof the run had compared against en_US while the
site was fr_CA — it had used the fr_CA map, and said so nowhere [L17c].

The `missing` scope = `wp-admin/`+`wp-includes/` paths **plus TOP-LEVEL `.php`
map paths** (wp-cron.php, wp-comments-post.php, wp-mail.php, wp-signup.php,
wp-trackback.php — a live host had DELETED all five; comments and WP-Cron
were silently broken and wpt reported nothing) MINUS the map paths the
tool's own `webroot_junk` policy deletes (`wp-config-sample.php` — the two
actions used to fight over it forever) and never `wp-config.php`/
`.htaccess`. The scope rule is mode-, locale- and junk-policy-blind so
clean-files, core.integrity and heal-core share ONE fixed point.

Tampered `wp-content/languages/` runtime catalogs (`.po`, `.mo`,
`.l10n.php`, `.json`, any depth) are exempt with one info line: a wp.org
language pack is replaced on demand and 8 of them are our own
`webroot.junk_recurring` candidates. (Measured live: the packs
currently match the bundled bytes — insurance, not a live false positive.)

### webroot.junk exempts OFFICIAL core files (L17b)

The junk patterns (`license.txt`, …) matched files that ARE in the official
checksum map (`wp-includes/ID3/license.txt`, …): clean-files deleted them,
`core.integrity` reported them missing, heal-core restored them, and the
finding set never resolved. Matched paths present in the map under
`wp-admin/`/`wp-includes/` are now EXEMPT from the finding AND from the
clean-files plan (one shared predicate). Top-level `license.txt`,
`readme.html`, `wp-config-sample.php` are map members too but stay deletable
— that is the tool's designed behavior. Fetch rides integrity's cached
primitives; unknown version / fetch failure keeps today's matching (one
warning).

### clean-files unit + active-unit rules (L23)

A `migration_leftovers` match strictly inside `wp-content/plugins/<unit>/`
or `wp-content/themes/<unit>/` selects the UNIT DIRECTORY, never the inner
file: the live case deleted `ai1wm-wp-cli.php` from INSIDE the still-active
`all-in-one-wp-migration-unlimited-extension`, and WordPress then fataled on
every request. Any planned plugin/theme unit that WordPress is using becomes
an ADVICE item (`webroot.active_unit`, `requires_apply=False`; the active
facts — one bridge `info` payload / one analyzer pass, fetched lazily,
fail-closed without them) whose detail names the deactivate-first command.
rc stays 0; `--apply` skips the advice; the snapshot scope ignores it.
Deleting a whole unit is never "safe by accident" either: WP merely
auto-skips a missing main file.

A SECOND fail-closed case at the same chokepoint: an active set that was
ANSWERED but not MEASURED (the options-table identity absent or contested, or
an `active_plugins` value that is not a readable serialized list). "Not in the
active set" is a DELETION verdict, so it is only ever drawn from a set somebody
measured: the model's contract is three states (`ActiveSet`: `plugins=None`
plus a one-clause reason and every candidate table), an unknown set becomes the
SAME advice item a measured-active unit produces, and the legacy-GeoIP gate —
whose detail asserts the plugin is NOT active — plans nothing at all.

### security.web_exposed_script (L17d)

A TOP-LEVEL `.php` file in the webroot that is absent from the official
checksum map, is not a known core/plugin file, is not a `known_added`
signature match, and whose bytes carry a request-parameter gate or a
home-directory walk signature (`hash_equals(`, `$_GET[`, `scandir(`,
`/home/`, `phpinfo(`) is HIGH, one finding per file: the matched
signatures, the file's own date (a HEAD — a GET would EXECUTE it) and the
read-only triage + removal commands. Both the attacker's dropper and the
operator's forgotten token-gated probe must leave the docroot; neither is a
junk matter and no wpt command removes one. The `core.integrity` "added"
finding renders the same triage text for the same file
(`security.WEB_SCRIPT_TRIAGE`). The needles and the read bound are profile
data (`web_script.signatures` / `web_script.max_bytes`), validated loud
[L34]. Live: two token-gated disk-usage probes a PRIOR wpt session had left
in a production docroot were rated HIGH as "added" and then sat behind the
unactionable words "Investigate the added file." until a human read the
report; a second live site's a large `error_log` was reported as "delete"
while being served at HTTP 200 (the junk fix text now LEADS with the
served disclosure and the FilesMatch deny to add) [L17e].

### db.active_missing + webroot.mu_plugins (L24)

`db.active_missing` has a second HIGH finding,
`active-plugin-entry-missing`, for an active slug whose unit SURVIVED with
no loadable entry file: an active slug can survive as a directory whose
orphaned `vendor/*.php` files are still served and EXECUTING at guessable
URLs, with the main file gone, reported as nothing because the directory is
present, while `reconcile-plugins` catches it in one item. The offline check cannot run WordPress's plugin-header scan,
so its fix text says exactly that and defers the authoritative answer to
`wpt reconcile-plugins` (ftp) [L45].

`db.active_missing` (both modes, HIGH): `active_plugins` entries whose
plugin unit is ABSENT from the walked tree — an export zip can be missing
several active plugin directories (page builder, cache, SEO, form export,
and others) while no check notices; the detail names the missing slugs, and
the fix names `wpt reconcile-plugins`/reinstall. Entries that cannot name a unit
(mu-plugin paths, absolute/`..` shapes) are skipped silently. The inverse
(installed but not listed) stays `plugins.inactive`'s. `webroot.mu_plugins`
(low): mu-plugin units matching a profile `mu_plugin_known_platform` prefix
(hosting-platform leftovers) — operator review, never deletion.

`plugins.inactive` names the DATA caveat explicitly: an inactive plugin's
database can still be live — inactive units can own active feeds, cron
events, options, and tables — so the fix text orders the data check before
the file deletion [L35].

**An UNMEASURED active set is reported as its own marker, never as a
verdict** [L53]. `AuditData.active_plugins` is `list[str] | None`; `[]` is a
real answer (a site running no plugins) and `None` is the absence of one
(an absent or contested options-table identity, or an `active_plugins` option
that is not a readable serialized list). On `None`, `plugins.inactive` and
`db.active_missing` each emit ONE low-risk, `count=0` marker under its own
category — `plugins.active_set_unknown` / `db.active_set_unknown` — and
`plugins.duplicate` and `db.ghost_tables` stay SILENT. A category of its own
is the point: the two measured categories' suggested steps are
`wpt deactivate-plugin <slug>` and `wpt reconcile-plugins --apply`, and BOTH
REFUSE in the only mode that produces these markers (local: no bridge to
read WordPress's own answer), so a run that measured nothing must not send
the operator to two refusals; `count=0` keeps each marker out of every
total, and the fix text scopes the refusal to the ACTIVE SET — never "nothing
is deletable", which the same run's other plans contradict. No
`audit.check_failed`: a measurement nobody made is a report fact, not a
check error.

### plugins.duplicate carries CONTENT evidence

Per group member the detail now states whether it holds content in the DB
(postmeta prefixes `_elementor_` / `_fusion` — the basis the widely used
builder-meta-cleanup plugin gates on). The fix: an optional
`duplicate_plugin_groups_preferred` map (group → the slug to KEEP; unknown
group or out-of-group slug = SettingsError, loud) wins; else exactly one
content holder is the keep and the zero-content members get the exact
`wpt deactivate-plugin <slug> --apply` command; ≥2 holders refuses to pick.
No auto-deactivation anywhere.
- Same Finding shape for both sources (bridge for remote, analyzer for local).
- `integrity.py` — `core.integrity` (both modes): wp.org OFFICIAL checksums
  (`core/checksums/1.0/?version=X&locale=en_US` → `{checksums: {path: md5}}`)
  against the walked tree — tampered (md5 differs), added (.php under
  wp-admin//wp-includes//top-level not in the map; wp-config/.htaccess exempt),
  missing (wp-admin/wp-includes paths absent). ftp mode hashes BULK via the
  bridge's `core_md5`; local mode reads via the source with a
  25-consecutive-failure circuit breaker (live lesson: a stale FTP passive
  channel must bound a scan, not crawl for days). Failed fetch → one warning +
  [] (never partial guessing).
  - **Default-theme version skew [L12]**: the checksums map describes the
    default theme BUNDLED with the core release, but WP ships default-theme
    auto-updates independent of core — pristine official theme files then
    mismatch the bundled checksums and read as false "tampered" (live:
    example.test, 3 of 4 high findings). `resolve_theme_skew` — the shared
    post-classification pass the check AND heal-core run (a heal restoring
    bundled bytes over a pristine auto-update would DOWNGRADE the theme) —
    cross-checks every tampered `wp-content/themes/<slug>/` path against
    `WpOrgApi.fetch_theme_zip(slug, version)` (the official theme release of
    the version the site's own style.css declares, validated + 1h-cached like
    the core zip): matching md5 → dropped with one info line; EVERY failure
    shape (unknown version, unavailable zip, unreadable, still-different)
    keeps the tampered classification — benign is never guessed.  Both
    callers pass the configured `files.max_file_bytes` into the pass: a
    non-Unix FTP listing's unknown size (-1) is never used as a read bound,
    and the official zip's largest entry is the data-driven companion cap.
  - **Known plugin-deployed artifacts [L16]**: added top-level files matching
    a `core_integrity.known_added` profile signature (name + size + content
    marker + NO suspicious-patterns hit — the shipped default is Wordfence's
    `wordfence-waf.php` WAF bootstrap) report as the separate low-risk
    `added-known` finding; any mismatch keeps the high classification.
- `suspicious.py` — `security.suspicious` (both modes): high-precision
  backdoor signatures in the PHP WordPress actually executes, read lazily via
  `AuditData.source`; patterns + max_file_bytes live in the settings profile;
  clean = silence. The scan SET follows WordPress's own load order plus where
  backdoors are actually planted (Sucuri incident research): all
  `wp-content/{plugins,themes,mu-plugins,uploads}/**/*.php` (mu-plugins and
  uploads are the documented hotspots), every `wp-content/*.php` drop-in
  (db.php, object-cache.php, sunrise.php — core auto-loads these), webroot
  `*.php` incl. wp-config.php, and dotfiles with no PHP suffix (a misspelt
  `.htacces` was a documented payload) except the known config dotfiles,
  which hold no PHP. `wp-includes/` is excluded: core integrity is
  `core.integrity`'s job with real hash comparison.
  A match counts only when at least one character of it is EXECUTABLE PHP —
  the same bytes in a comment, docblock, string literal or heredoc body are
  data the loader never runs, and reporting them sends operators chasing
  their own source. The scan is therefore PHP-aware
  (`security._php_code_mask`), with a cheap raw pre-pass so a clean file is
  never masked. The shipped list is deliberately down to four patterns that
  can PROVE execution; four earlier ones were removed as false positives on
  documented WordPress code: `assert($_)`, a long base64 blob (W3TC ships
  344-char fixtures; a blob alone proves no execution), `preg_replace /e`
  (a fatal error on PHP 7+, not execution) and `mail(..., Bcc:)` (normal
  wp_mail/WooCommerce usage). The finding is a CANDIDATE, never a verdict:
  the fix tells the operator to verify against a clean copy.
  The batched scan emits ONE info heartbeat per batch once 10s
  (`_HEARTBEAT_S`, structural log cadence) have passed since the last —
  [L15: a live ~11-minute scan ran in total silence, indistinguishable
  from a wedged run].
- `security.py` (remote only): xmlrpc POST, REST /wp/v2/users, /?author=1, wp-config
  perms (0644 → finding), DISALLOW_FILE_EDIT, HTTPS redirect on a subpage, www→apex,
  cert CN/SAN mismatch (the raw-socket probe dials `--override-ip` with the site
  host as SNI [L13: real DNS from inside a hoster network answered a different
  server and turned a valid cert into a false mismatch]), uploads dir listing,
  `security.uploads_perms` (world-writable files/directories under
  `wp-content/uploads/` when the FTP LIST actually carried a mode; unknown
  modes are silent), debug.log exposure, `security.php_version` (EOL PHP:
  runtime below `env.php_min_active` → medium finding carrying the runtime
  facts; healthy = silence), `security.relocate` (active truthy RELOCATE →
  high; wp-login.php
  then rewrites siteurl from the incoming request — high = finding, fix is the
  manual line deletion, outside harden's write path).
  Both wp-config constant checks (DISALLOW_FILE_EDIT, RELOCATE) read the file
  as PHP, not as text: strings/comments/heredoc/inline-HTML are skipped,
  constant names are case-sensitive, and PHP's exact truthiness applies, so a
  commented-out or `false` define no longer counts as hardening. A value PHP
  decides at runtime (non-literal or conditional) is reported as unverifiable,
  never silently assumed safe. An active truthy DISALLOW_FILE_MODS suppresses
  the DISALLOW_FILE_EDIT finding (it closes the editor too).
- `harden.py` wp-config write contract — FAIL CLOSED, verified by EFFECT:
  the emitted line is `\define( 'DISALLOW_FILE_EDIT', true );` (fully
  qualified, so it still names the global constant inside a namespace). The
  insertion anchor is the first ACTIVE top-level `require|include[_once]` of
  wp-settings; a require that is nested, deferred (function/closure body),
  conditional (alternative syntax), preceded by an unproven require, or
  lexically broken yields NO write and one warning — never an append that
  would land after the bootstrap. Alternative-syntax blocks are tracked by a
  single linear bracket-stack pass, so a long or multi-line condition is still
  detected: a bounded tail-scan once missed one, which placed the constant
  INSIDE a conditional and reported success while PHP left it undefined. That
  pass also refuses to read a `function endif()`, `const endif`, `endif:` named
  argument or `Foo\endif` as a terminator, treats `declare(ticks=1):` and a
  label as statement boundaries that are NOT blocks, never reads a ternary
  colon as a block opener (a ternary INSIDE the head is expression
  punctuation, and the `):` after it still opens the block), and bounds every
  forward look-ahead so a malformed file cannot make a scan quadratic. A
  top-level `exit`/`die`/`goto` before the require, or an `exit` inside the
  head of an arrow function, decides reachability the same way: an exit inside
  an arrow body or a named argument is not a file-scope exit. Arrow bodies are
  EXPRESSION scopes kept on a stack, so a nested arrow cannot clobber its
  enclosing one; a body ends at the `;` or comma at its own delimiter depth,
  or when its enclosing group closes, so a closure inside it and a sibling
  `exit` in the same statement are both handled. `fn` owns no brace body, so
  the block after it is not a function body. A control head containing a nested group or a brace
  (`array()`, a named argument, a `match` expression) is not modelled: the
  scan then treats the rest of the file as conditional, so every caller
  refuses rather than writing into a condition it could not prove. A signature
  is reported only when the name is the language construct: a method call
  (`$o->eval`, `$o?->eval`, `Foo::eval`) and a variable callable
  (`$eval(...)` calling a closure) are ordinary code, while `${eval(...)}` is
  the construct reached through interpolation. A constant value counts as known
  only when it can be proven statically: `define()` with a fourth argument
  raises `ArgumentCountError` before defining anything (and `...$args`
  unpacking makes the real count unknowable), while a trailing comma after
  three is legal; the THIRD argument is evaluated before `define()` runs, so it
  must be a provable literal as well (`define('X', true, exit)` never defines
  anything, and an array is not bool-coercible so PHP raises `TypeError`); an array's elements are evaluated before `define()` is
  called, so `define('X', [exit])` ends the script without ever defining `X`;
  and a comment inside the value is stripped before the literal is read. Every
  unprovable case reports indeterminate, as does a literal nested deeper than
  the evaluator's structural bound. Before writing, the proposed bytes must
  already show the constant active; after writing, the file is read back,
  compared byte-for-byte, and re-scanned, and only then is the item done. An
  unresolved constant becomes an APPLICABLE item that apply refuses, so the
  run exits non-zero instead of reporting success for a file nobody hardened.
  A refused item is an operational failure: rc 1, no cache purge, no
  rehearsal materialization. Accepted residual limits: the static evaluator
  is not a PHP parser (a parse error delimiter balance cannot see, e.g.
  `$x = ;`, may still be written), and definitions created at runtime via
  eval/callbacks/includes are outside static proof.
- `dbcheck.py` additions (both modes): `db.charset` (non-utf8mb4 tables —
  the migration landmine; charset derived remote from the wire collation,
  local from the CREATE SQL token) and `db.admin_accounts` (default `admin`
  login → high, full admin roster in the detail; remote from the bridge's
  admins query, local from the analyzer's wp_users+wp_usermeta user_level=10
  join — mode-blind wire shape; None=unknown silent, []=measured silent).
- `media.py`: live usage set = rendered HTML refs + url() refs inside generated CSS
  under wp-content/uploads [L11: backgrounds were referenced ONLY in elementor CSS] +
  srcset attributes. Keep-set = refs ∪ all on-disk stems matching referenced
  attachments [L5]. Only MEDIA-extension files participate (the
  `media.extensions` allowlist) — .htaccess/index.php/stray logs under uploads
  are invisible to the finding AND to trim-media [L14: Wordfence's uploads
  PHP-execution block landed in a live trim plan when every uploads file
  counted as media].
- `updates.py`: wp.org APIs per `docs/research/R3.md` (live-verified): core latest =
  `offers[0].current` from `core/version-check/1.7/`; plugins/themes via ONE bulk POST
  each to `plugins/update-check/1.1/` and `themes/update-check/1.1/` (form fields are
  JSON-encoded; response `plugins`/`no_update` buckets; absent keys = premium;
  `[]`-vs-`{}` empty-map ambiguity). Per-slug `info/1.2` only for detail links, with
  fields-trimming params. Send an identifying User-Agent (`wpt/<version>`).
  1h cache in `.wpt-cache/`.
- `webroot.py` note: `.po` catalogs in wp-content/languages are runtime-safe to delete
  (.l10n.php/.mo are the runtime formats) but RECURRING — wp.org language packs re-ship
  .po on every translation auto-update (which is ON by default). Report category
  `webroot.junk_recurring`.
- Audit runner: `--baseline prev.json` diffs the finding set (identity =
  category/name) into NEW/resolved — rendered in the markdown + a `diff` key
  in the JSON twin; unreadable/malformed baselines fail closed.

## Report (W1)
Markdown + JSON, per-category tables, reclaimable totals, risk column, "Needs your
call" for risk != low, deterministic ordering, zero secrets (redact enforced).
Suggested next steps: category-prefix first-match rules; a `_NAME_PINS`
overlay swaps in its own advice for findings whose NAME diverges from their
category's action [L16: the low-risk "added-known" finding renders a
verify-the-plugin step, never heal-core, which has nothing to restore].

## Report (W1) — site facts

`AuditReport.site_facts` renders a `## Site` section (markdown) /
`site_facts` key (JSON twin) carrying blog name, siteurl/home, WP version
(core + db_version), locale, the active theme (+ version when known), the
ACTIVE plugin roster with versions, the privileged-user roster
(login/email/role), the posts-by-(type,status) summary and the DB
table/size summary. Facts, NOT findings: no category, no risk, no
reclaimable bytes, no suggested step; one INFO line with structural counts
only, never a value. Unknown = omitted (row/cell), an empty fact set = no
section at all (never a header over an empty table). The section rides the
same redaction choke point as the findings (a fact whose NAME looks like a
secret renders `***` in both twins; a user email renders verbatim — the
operator's own dump, and a password-reset task needs the roster). The
markdown↔JSON parity contract extends to it, cell by cell.

## The cross-mode witness (`wpt.actions.dump_witness`)

ONE implementation, used by BOTH destructive media actions (`trim-media` and
`cull-media` — `cull-media` once deleted through the same `media_delete` op
with no cross-check at all). A dump corroborates a deletion only when it is
WHOLE (`-- Dump completed on` trailer: the trailer proves the FILE ended,
never that the DATABASE was in it — a dump cut inside the `INSERT` rows with
the trailer appended satisfies every other condition and authorizes exactly
the deletion the gate exists to prevent), is THIS site's (`siteurl`/`home`
read by the analyzer, compared with `--wp-url` on host+path, scheme/port/
`www.`/trailing-slash insensitive), DECLARES every table the live schema has
(refused by name), is not BEHIND the live row counts of the tables the
decision reads (`media.dump_behind_row_ratio` — validated at load, `0 < v <= 1`, `SettingsError` on nonsense, and the shipped `0.5` is pinned by a test because a dump retaining under half the live rows cannot certify anything — a dump that predates the live content cannot certify that anything
is unreferenced), and measured something where the live map measured
something. The question is asked in the PLAN phase, before the pre-action
snapshot, so a refusal costs one stat instead of a full-site walk, an FTP
download of the deletion scope and a three-table `db_dump`.

## Table identity is one fail-closed owner

`wpt.media_refs.resolve_role` decides which table a dump role names: a
candidate must end in the role's suffix AND prove its column signature; the
set is name-sorted, never dump-ordered. Exactly one candidate → that table.
Zero → ABSENT (a site need not have the table). **Two or more → UNKNOWN**,
and the warning is per (wire, role, input) — ONE resolution and ONE warning
for each distinct question, however many consumers ask it [L54]. A dump that
CONTESTS a role (`aioseo_options` beside `wp_options`) measures nothing at
all, because a half-measured keep-set is not a measurement. When the options
role is resolved, `postmeta`/`posts` are REQUIRED (a dump without them is a
PARTIAL export, not a site without attachments); `termmeta` is optional. The
prefix derivation is `options_prefix`, and the consumers — the analyzer, the
media keep-set, the cross-mode witness, `clean-db --db-uri`, the audit's
`db.ghost_tables` (which asks the same measured question and stays silent on
UNKNOWN rather than crashing), and the plan-item target + snapshot scope of
`deactivate-plugin`/`reconcile-plugins` and of both user actions
(`users_reset`/`user-create`, through the shared `wpt/users.py` owner) — all
ask this owner. A contested identity is refused, never guessed.

**A contested options identity is a REFUSAL, not a puzzle to route around.**
Four to seven consumers read one dump, so the owner memoizes the answer and
warns once per (wire, role, input) instead of once per reader [L54]. The
consequence is measured, not hypothetical: on an AIOSEO 4.x site — whose
`aioseo_options` carries the same `option_name`/`option_value` column pair, so
the identity is contested there too — `deactivate-plugin`, `reconcile-plugins`,
`users_reset`, `user-create` AND `clean-db` all refuse, and the operator's
route is the panel
or `wp option` on the site itself. `--db-uri` is NOT a fifth route: it reads
the same identity from a live `information_schema.COLUMNS` and therefore
contests the same way [L53].

## webp-media (convert uploads rasters, rewrite every reference)

Which tables EXIST is asked of the DATABASE [L31]: the rewritable surfaces
are DISCOVERED by a table-name suffix match (the `wp_` prefix is never
assumed) but RESOLVED against the dump's own CREATE — a suffix is a name,
not a schema. On all-in-one-seo-pack 5.x, `wp_aioseo_posts` ends with
`posts` and declares no `ID`/`post_content`, and demanding them refused the
whole run before it could do anything. Now: columns present → a rewritable
surface (the discovery is deliberately NOT narrowed); a column absent → a
GATED surface whose every column is read as an unrewritable reference (that
direction can only keep an image original, never break one) and the plan
names it. The reference map carries BOTH spellings — `file` /
`_wp_attached_file` are uploads-relative, every `sizes[*].file` is a BARE
BASENAME anchored to the attachment's directory — and a basename matching two
folders gates both (never a coin flip). Serialized values are rewritten
through PHP's own `maybe_unserialize`/`maybe_serialize` (only PHP fixes
`s:NN:` lengths); a value that LOOKS serialized but won't parse gates its
images instead of being rewritten blind. Skips, each a reported bucket:
animated (APNG/GIF), CMYK (visible colour shift), >16383px (libwebp's
limit, read from the PNG IHDR / JPEG SOF header so a 16800×16801 PNG is
never decoded), data trees (gravity_forms submissions), <30KB, byte
duplicates, existing twins, and anything not smaller.

THE PURGE IS A WINDOWED OPERATION [L32]: `--purge-originals` (a TRI-STATE flag: absent =
the operator did not type it, so a profile's `webp.purge_originals`
can open the same door) is refused without an explicit
acknowledgement (`--i-know-editors-are-off`, which is itself ignored unless
a purge was actually asked for), in the
plan phase as well as the apply, and whether the flag or the profile key
asks for it. Every per-file delete decision is taken from a reference set
RE-READ at purge time (the same read-only reader the plan used, plus the
stylesheets' current text), never from the plan's scan: a live editor's
save from a stale client re-introduces the ORIGINAL filename between the
rewrite and the purge, and deleting behind it both breaks the page and
creates a reference that permanently protects bytes that are already gone.
Such a file is KEPT, reported, and its plan item stays not-done (an
incomplete plan, never a clean success). One more sweep after the deletes
REPORTS (never raises on) a reference that reappeared pointing at a removed
original; the pre-action snapshot is the rollback.

The estimate is SPLIT BY SOURCE FORMAT [L33] (JPEG total, PNG total, all
files) with counts: one blended number hid the decision — most of one
field estimate was PNG.

## update-core (move a live site to an explicit core version)

`@register_action("update-core", applies=("ftp","local"))`. Core only in this
slice (`updates.plugins`/`updates.themes` still REPORT). The target is never
implicit: `--to X.Y.Z` is required to apply; without it the plan lists what
wp.org offers and names the version a `--to` would need.

- **Drivers** — the write step has two, and the choice is explicit
  (`update.driver`: `wordpress` | `swap` | `auto`, shipped `auto`). `auto`
  asks the SITE (through `info`'s `core_upgrade` facts) and picks `wordpress`
  when its filesystem method is `direct` and it has ZipArchive or PclZip, else
  `swap` (which needs neither, and is the floor: no site becomes unupdatable).
  The `wordpress` driver runs core's own extractor and copier through the
  bridge (`core_upgrade_files`: `WP_Upgrader::unzip_file()` into core's
  `wp-content/upgrade/` staging, then core's `copy_dir()` with core's own
  skip list so `version.php` lands LAST, the post-copy md5 re-verify, the
  bundled re-add) and passes `attempt_rollback => true`, the argument the
  admin UI never passes; it refuses a non-`direct` filesystem or a missing
  zip library as PRECONDITIONS (not retries), and refuses a non-empty
  `wp-content/upgrade/` rather than letting core's wipe delete a recovery
  path. The plan NAMES the driver it would use and why; the apply
  re-derives it and refuses if it changed (a driver that disappears
  mid-run must not silently swap). The refusals, the snapshot, the
  maintenance discipline, the migration op and the verify are IDENTICAL
  across drivers — only the write differs. The unknown-addition guard
  applies to both (the fix text says what the chosen driver would do: the
  swap would DELETE them, WordPress's copy would OVERWRITE them). The
  `wordpress` driver's staging is core's, and the sweep never deletes it
  blindly — the residue report names it with its owner, and it is cleared
  only when this run created it and the verify passed. One thing the tool
  adds around core: core fires the DATABASE step as a fire-and-forget
  `wp_remote_post` and never checks the response, so the verify re-reads
  `db_version` itself instead of inferring completion.
- **Plan**: the target's core and `db_version` against the live ones; the
  exact replaced file set, DERIVED from the release zip's own namelist
  (`wp-admin/**`, `wp-includes/**`, the root core `*.php`) — never a
  filename list; the release's PHP/MySQL floors from the version-check
  offer against the LIVE site's PHP; whether the schema must migrate;
  that maintenance mode (`.maintenance`, the file WordPress honours) will be
  engaged; the snapshot scope with `wpt restore --undo-last` named as the
  rollback; and one item per replaced file PLUS one per file the swap
  DELETES (bytes 0) so the snapshot can undo that deletion. Local mode with
  `--apply` rehearses the same sequence into a copy: it does NOT take the
  FTP pre-action snapshot or read tables — the original zip IS the rollback
  (see the local-rehearsal section above).
- **Refusals, before any write**: `--apply` without `--to`; a target
  wp.org does not offer; a pre-release target (or a dev/beta/RC INSTALL)
  without `--allow-pre-release`; the target's PHP floor above the live PHP
  (or unreadable); multisite; `--to` at or below the running version; a
  dirty or unreadable in-scope file against the official CURRENT map; and
  an UNKNOWN addition inside a replaced tree (the swap would delete it).
- **Apply**: every release byte proven against the target's checksum map
  BEFORE the first write; the write step follows the driver named in the
  plan and re-derived before the first write. With `update.driver=swap`
  each core tree is staged beside its original and swapped by ONE rename
  (the first rename is undone if the second fails). With
  `update.driver=wordpress` core's own `WP_Upgrader` extractor and
  `copy_dir()` run through the bridge, overwriting in place; the plan's
  stale files — shipped by the installed release but absent from the
  target — are then removed explicitly, because core's copy never deletes
  them. Root files are temp+rename in both drivers; the database is
  migrated through core's own `wp_upgrade()` in the `core_upgrade` bridge
  op (whitelisted, `apply`-gated, multisite-refusing, L4-enveloped);
  `.maintenance` is removed in a `finally`. `wp-content/` and
  `wp-config.php` are never in scope — the bundled default theme is
  therefore not updated by this command (`prune-core` and the
  plugin/theme reports cover the rest).
- **Verify after write**: `wp_version` and `db_version` re-read from a fresh
  process and required to equal the targets; every replaced file re-hashed
  against the release map; every removed file proven gone; the site root
  2xx and the REST root not 5xx; then the cache purge. Any failure ⇒ not
  done, the snapshot named as the rollback, rc 1, no purge.

## Residual register
Every known limitation, with its owner and its disposition. A FIXED row was a
defect found by a review round and closed with a regression test; an ACCEPTED
row is a deliberate limit with the reason it is safe; an OPEN row belongs to
another writer and is the coordinator's to schedule.

| # | Residual | Owner | Disposition |
|---|---|---|---|
| R1 | `.htaccess` idempotency matched a `# BEGIN wpt-harden` SUBSTRING, so a truncated block, an empty marker pair, a comment mentioning it, a commented-out directive, or a block whose directives sit inside an inactive `<IfModule>` all reported "already hardened" | harden | **FIXED** — the proof is a whole-line marker pair whose body is EXACTLY the canonical block we install, opened outside any `<IfModule>`/`<IfDefine>`. Presence is not enough (a wrapped directive is ignored by Apache) and our own `<IfModule mod_rewrite.c>` section is accepted because the whole body matches. One pass, so many marker pairs stay linear |
| R2 | `apply_override` set values without the loader's validators, so `--set suspicious.max_file_bytes=0` reached the scanner as a size gate of zero, a list of ints passed where the profile rejects one, and a valid string map was refused | settings | **FIXED** — the override path and the profile loader now share one validator per shape (`_load_str_list`, `_load_str_map`, `_load_str_lists`, `_load_known_added`) and the owning section's `__post_init__` runs on a REPLACEMENT first, so a rejected override leaves the live tree untouched; a test asserts the two paths reject exactly the same values |
| R3 | A baseline diff compared only `detail`, so a finding that doubled in count or rose in risk answered "No changes"; absent optional fields were read as 0/"" rather than the Finding defaults; and a malformed baseline entry was skipped, reporting every current finding as new | audit | **FIXED** — the comparison shape is (detail, count, risk, bytes) with `fix` staying prose, the markdown names the fields that actually differ, an absent field carries the value the same finding would hold by default (`count=1`, `risk=low`, `bytes=0`, `detail=""`), and a malformed entry — wrong type, missing identity, not an object — raises `WptError` instead of being skipped |
| R4 | A signature split across physical lines, or by a `//`, `/*` or `#` comment, was invisible to a line scanner | suspicious | **FIXED** — matching runs over a length-preserving view with line breaks blanked to spaces, the comment-aware pass is enabled by all three comment syntaxes, and a match must BEGIN in executable code so a comment cannot join unrelated code. Line numbers come from the original source |
| R5 | Scope covered five `wp-content/` trees, so a backdoor in `wp-content/cache/`, `wp-content/upgrade/` or any custom directory was missed | suspicious | **FIXED** — every `.php` under `wp-content/` at any depth is scanned; the hidden-payload allowance stays at the top level and the six documented roots (plugins, themes, mu-plugins, uploads, languages, wp-admin), where `uploads/.htacces` is a known filename |
| R6 | Markdown and JSON renderings are written separately and could drift | report | **FIXED** — a parity contract test PARSES both renderings and compares every cell and field against the dataclasses, over a fixture with non-empty `fix`/`totals` and DISTINCT plan categories and targets; 35 renderer mutations (dropped, hardcoded and zeroed, markdown and JSON) were each confirmed to fail it |
| R7 | `wp-includes/` is not scanned by `security.suspicious`, and executable text past the lexer's interpolation bound is not reported by it | suspicious | **ACCEPTED** — `core.integrity` owns `wp-includes/` by checksum comparison, and it is the one tree an attacker does not choose. The content scanner treats an UNMODELLED interpolation region as NOT code, so the check's "executable code only" contract holds; the constant scanner still fails closed on that region, so a hardening write can never be justified by it |
| R8 | The constant scanner is a lexer, not a PHP parser: a parse error it cannot see (`$x = ;`), a construct that can define a constant at runtime (`eval(...)`, a `$eval(...)` variable callable, `create_function`, `assert`), and any interpolation the lexer cannot model (past its recursion bound, or whose inner expression did not tokenize) are all reported indeterminate | security | **ACCEPTED** — every unprovable case fails closed, a runtime define makes the state indeterminate rather than absent, and a refused item makes the run exit non-zero rather than reporting success |
| R9 | A control head containing a brace (`if (match ($x) { ... }):`, a closure) and a look-ahead beyond its budget are not modelled | security/harden | **ACCEPTED** — both are marked conditional or unproven, so a write can never land inside a condition the scanner could not prove |
| R10 | `zip.py` never populates `Entry.is_link`, so a symlinked entry in a zip reads as a regular file | sources | **CLOSED** — `ZipSource` sets `Entry.is_link` from the archive entry's external attributes (`_zip_is_link`), and `tests/sources/test_zip.py` pins both the symlink and the regular-file answers |
| R11 | `--deadline -5` is accepted and silently treated as unbounded | cli | **CLOSED** — `cli.py` refuses a non-finite or negative `--deadline` before dispatch (rc 1, one stderr line naming the accepted form); `tests/test_cli.py` pins the refusal |
| R12 | A `WP_DEBUG` + `display_errors` site emits HTML before the bridge JSON, so a valid payload fails to parse | wpbridge | **OPEN** — outside this writer's ownership; a BridgeError is raised rather than guessing at a body |
| R13 | The streaming SQL analyzer makes up to five independent passes over the dump | localmode | **OPEN** — the mechanism is one `analyze(dump)` call (one `parse_dump` summary pass plus four `iter_rows` row passes, each rewinding the stream), not five separately guarded calls. The run budget is built before the local gather and checked immediately before and after that call, and per walked entry; `db_refs_from_dump` receives the same deadline. `parse_dump`/`iter_rows` themselves take no deadline, so one very large dump can outlive `--deadline` while a pass is in progress |
| R14 | A subdirectory install's media URL is rebuilt from the configured site URL | verify | **CLOSED** — not a defect: `Ctx.wp_url` is used verbatim, so `https://host/subdir` yields `https://host/subdir/wp-content/uploads/...` and nothing is stripped |
| R15 | FTP existence uses `SIZE` with a parent `LIST` fallback | sources | **CLOSED** — not a defect: `MLST` is never issued, and a failed size operation falls back to a directory listing |
| R16 | Search-replace is not serialization-aware | — | **CLOSED** — not a defect: the product performs no search/replace operation; the name in `migration_leftovers` is a plugin slug |
| R17 | The stdlib cannot speak the MySQL wire protocol, so `--db-uri` needs one optional third-party driver (PyMySQL); a run without it fails with a one-line install message and every other command is unaffected | localmode/dbconn | **ACCEPTED** — shelling out to mysql/mysqldump is unavailable on operator machines, and writing a wire-protocol client is a far larger, less trustworthy surface than a maintained pure-Python one |
| R18 | `report.render_report` scrubs `key=value` / `key: value` shapes but not free text, so a credential embedded in a plan DETAIL would survive into the report | report | **ACCEPTED** (defense in depth only) — the primary protection is structural: no action puts a credential in a plan/finding/log/exception (users_reset's contract above), and the client redacts the JSON body itself. A report-layer free-text scrubber remains the second layer |
| R19 | `$wp_local_package` lives in `wp-includes/version.php` — the file an attacker tampers with — so an injected marker naming a locale that HAS builds becomes the comparison basis | integrity | **ACCEPTED** — no resolver can out-vote it (the language catalogs cannot discriminate build from pack); bounded by construction: the blast radius is that single file, live-verified as the only same-path digest difference between an en_US and a locale map across 4 versions × 2 locales |
| R20 | CLOSED — the `deploy` section is a settings section: `wpt.settings.DeploySettings` is the one owner of 20 policy knobs, `wpt/data/profiles/default.json` ships the values, every knob is `--set`-reachable and validated, and `wpt/deploy.py` reads only `ctx.settings.deploy` (no local dataclass, no `getattr` fallback). | — | — |
| R21 | The `prune-core` release-provenance window is 4 patch releases in the same minor, a structural constant | prune_core | **ACCEPTED** — files dropped several minors ago (SimplePie, 6.4) fall outside the window and land in the investigate-only note unless a `core_integrity.known_stale` signature covers them; widening across minors would require guessing a previous minor the tool cannot know |
| R22 | `users_reset` loads every user (and a `WP_User` per user) with no chunking: a mid-run fatal on a spam-farmed site leaves a PARTIAL reset | users_reset | **ACCEPTED** — the snapshot is the revert, and the read-only plan phase fails first on such a site; batching is scheduled with the other perf work |
| R23 | An inner stale/junk dir nested inside an active unit still plans (only the UNIT itself is guarded) | clean_files | **ACCEPTED** — documented; byte-identical to the pre-guard junk behavior and never deletes the active unit's own files |
| R24 | The comparison locale's tier-3 floor is silent: with `version.php` unreadable AND no site-locale fact (bridge `info.locale` empty, dump WPLANG absent) the check compares against en_US with no warning | integrity | **ACCEPTED** — the floor is L17-spec'd and the tool cannot know a locale it was never told; the basis is now stated in the finding detail, the plan item and the info line, so a wrong-basis verdict is visible rather than silent |
| R25 | webp-media's purge re-reads the database surfaces and the stylesheets but not rendered HTML (the bijection walk ran immediately before it) | images_webp | **ACCEPTED** — a third crawl on every purge was judged not worth it; the window is operator-acknowledged (`--i-know-editors-are-off`) and the snapshot is the rollback |
| R26 | An operator who widened `media.extensions` beyond the shipped family lost those references from the DB half of the keep-set in one mode only. | media_refs / wpbridge | **CLOSED** — the read mode now carries the caller's family and the effective gate is the mirrored default **UNION** the request (a floor: the wire can only widen it), and a family the client cannot express is a refusal, not a fallback; the two sides are pinned set-for-set by a test that evaluates the deployed PHP literal. `svg` was already in the shipped family. |
| R27 | `WalkResult` carries no PER-PAGE reference attribution, so webp-media's post-apply proof subclasses the walk's private crawler to get it | walk / images_webp | **ACCEPTED (until scheduled)** — the per-page seam is the right fix (one recording set in the crawler, `page_refs: dict[str, set[str]]` on `WalkResult`, after which the subclass collapses); today the subclass reads the crawler's private fields, which is the shape the review flagged |
| R28 | A collapse confined to a serialized OBJECT's properties, and a self-referential `R:` value, cannot be proven lossless by the declared-shape comparison (their keys are stored mangled) | wpbridge | **ACCEPTED** — neither occurs in a WordPress-authored value; objects are walked but never compared, so the shape proof yields "no proof" rather than a wrong verdict |
| R29 | CLOSED — the analyzer's reader is a delegate to the one decoder (it casts numeric string keys to int as PHP does), and the options-table identity is now one fail-closed owner shared by the analyzer, the media keep-set, the cross-mode witness and `clean-db`. | — | — |
| R30 | The junk exemption is now fail-closed for the PLAN only, so a site with no reachable wp.org sees core-dir junk REPORTED (with the basis named) that the plan will not touch | webroot | **ACCEPTED (deliberate)** — an air-gapped run reporting a served a large `wp-includes/error_log` with "the delete plan will not touch this until the basis is available" is the honest outcome; a silent 0-finding report is not |

## Test Map — every lesson becomes a test

| Lesson | Test |
|---|---|
| L1 webroot .bak exposure | webroot junk pattern test + backup-dir rule test |
| L2 verify-after-mutate | verify module asserts 200s on the full reference set after trim |
| L3 wp-config is config | Source refuses wp-config write without allow_config; harden prints diff |
| L4 opaque 500s | bridge returns structured JSON on induced Throwable (php harness) |
| L5 stem matching | media_map unit test: variant `-300x128.png` of missing-metadata attachment |
| L6 LiteSpeed 404 cache | bridge client retry test: first call returns site-404 HTML → renames + retries |
| L7 cert interstitial | proxy test with self-signed cert + Host/SNI assertions |
| L8 stale FTP conn | ftp source reset-retry test (mock) |
| L9 month dirs | walk() fixture with nested year/month structure |
| L10 symlink double-count | walk() skips is_link dirs, no double count |
| L11 CSS-only backgrounds | media live-walk parses url() from a fetched CSS fixture |
| L12 default-theme auto-update reads as "tampered" (live: example.test, 3 of 4 high findings false) | resolve_theme_skew: pristine official theme release of the declared version → dropped (audit + heal-core; seeded-cache + 404 + raise + unknown-version tests) |
| L13 cert probe ignored --override-ip (valid cert read as mismatch from inside a hoster network) | cert_mismatch dials probe.override_ip with the site host as SNI (tls-fixture test pinning the dialed address) |
| L14 uploads .htaccess landed in a trim-media plan (Wordfence PHP-execution block deletable) | media.extensions allowlist: is_media gate + check + trim-media plan tests (dotfiles/double-ext/unlisted never flagged) |
| L15 silent 10-min walk + 11-min scan indistinguishable from a wedged run | walk heartbeat (milestone + time gate) + suspicious per-batch heartbeat + CLI run-start line (each with pinned-open and default-silent tests) |
| L16 Wordfence's wordfence-waf.php read as high-risk "added" evidence on every Wordfence site | core_integrity.known_added signature gate: name+size+marker+no-malware → separate low-risk added-known finding (marker-absent/malware/oversize/impostor stay high) |
| L17 locale-blind checksums (a fr_CA site read as tampered forever; heal wrote en_US bytes) | integrity locale resolver tiers + fr_CA-clean fixture + one-warning fallback + fr_CA heal + zip-404 unrestorable policy + webroot core-junk exemption tests |
| L18 five deleted top-level core files (wp-cron.php, wp-comments-post.php, …) reported nothing | missing-top-level scope + junk-policy subtraction (wp-config-sample.php never loops) + rehearsal restores wp-cron.php + never names wp-config.php/.htaccess |
| L19 flag order: `audit --report x` died; a hoisted `--report` then ate `restore`'s snapshot name and exited 0 | after-command globals ≡ before-command globals over a real local fixture; 5 positional-eat shapes fail closed rc 2; misplacement errors name the flag and side; usage errors never echo a secret-looking token |
| L20 `--set` could not carry a list/map value (every list key needed a profile file) | `--set` JSON list/object literals end-to-end; look-alike strings stay strings; rejected overrides are one-line rc 1 refusals, not tracebacks |
| L21 account quota exhausted mid-upload with "SSH layer"/truncated chunk failures | deploy quota preflight refuses with both numbers and the subprocess proven NOT called; transfer classifier maps the live signatures to a quota failure |
| L22 double-strip shipped files one level too deep | producer tar bytes carry the host root gone, consumer command contains no `strip`, layout assertion refuses the planted residue |
| L23 `ai1wm*` deleted vendor files inside an ACTIVE plugin → fatal on every request | clean-files unit rule + active-unit advice (plugins AND themes) + local rehearsal survival + rc-0 skip |
| L24 a migration zip missing several active plugin directories went unnoticed | `db.active_missing` fires on the real artifact (proved live) + non-unit entries silent + the inverse stays plugins.inactive |
| L25 optimize-media recompressed people-uploaded form records with no exclusion available | `exclude_prefixes` default absent from the plan, never downloaded, skip count reported, profile/--set/empty overrides, plan↔apply consistent |
| L26 harden created a root .htaccess without the WP permalink block → every subpage 404'd | canonical WP block planned+applied when permalink_structure is non-empty; whole-line marker discipline; placement ABOVE any existing RewriteRule (the [L] catch-all) |
| L27 users_reset malformed bridge row could strand live passwords (KeyError) | whole-or-nothing row publication, BridgeError naming no values, good rows still published on rc 1, plan-side same rule |
| L28 media_delete refused `bb-plugin/cache/...` (YYYY/-shape rule) → trim-media failed closed with 0 deletions | uploads-containment delete + trim plan filter + TOCTOU re-proof (outside-uploads unlink refused) + prefix-confusion pin |
| L29 a deploy rehearsal passed `--webroot` the operator also passes to the ssh target, and the local target JOINED it under `local:<dir>` — a live rehearsal landed the whole tree at `deploy-rehearsal/home/...` and still passed the layout check | `make_target` resolves an ABSOLUTE `--webroot` against the local base to that root itself; a host-shaped path keeps the documented join, and a sibling sharing a string prefix is not inside the base |
| L30 a Gravity Forms `.sql` export sat under `uploads/` and the old advice was "Delete now" — the uploads exemption swallowed it | the exemption is scoped to the dump's OWN media family; a backup payload in the webroot is a HIGH exposure finding (park-backups moves it, the check never advises a delete), while a log file stays junk UNDER uploads too |
| L31 a suffix-matched plugin table (`wp_aioseo_posts` on AIOSEO 5.x) made webp-media refuse before planning — a suffix is a NAME, not a schema | AIOSEO 4.x/5.0 real column lists gate as surfaces (never narrowed), a table missing one column names that column, a dump with no plugin table plans unchanged |
| L32 the purge half of a reference-rewriting conversion races a live editor (a stale save re-introduces the original filename) | purge refused without an explicit acknowledgement (plan AND apply), per-file delete decided from a PURGE-TIME re-read, the kept file's item not done, the post-delete sweep reporting without failing |
| L33 one blended image-conversion estimate hid the decision (most of one field estimate was PNG) | JPEG/PNG/all-files totals with counts in the plan, plan total unchanged |
| L34 a security signature list and its read bound lived as module constants | `web_script` profile section: shipped values, loud validator, `--set` door, and the check reads them (module tuples as the structural fallback) |
| L45 the round-trip-loss proof was INERT for real values — the byte reader never consumed a level's closing `}`, so it returned "no proof" for every healthy `_wp_attachment_metadata` (measured at **1,295 of 4,000** randomized healthy payloads) and the loss it exists to prevent was fail-OPEN, silently | ONE entry point (`wpt_media_rewrite_shape_proof`) composing TWO proofs, refusing if either refuses: the stored BYTES vs the array PHP reads out of them (rewritten frame protocol — a level's own `}` is consumed, including for an empty level), AND PHP's own `serialize()`/`unserialize()` round trip compared with the same hardened depth-bounded cycle-safe pair. The round trip provably CANNOT replace the byte reader (both its sides are post-`unserialize()`, so they agree on a value that already lost a member — measured), so the reader stays and its LIVENESS is pinned on real values |
| L50 the junk-group door refused a metacharacter glob but a LITERAL group pattern (`host_placeholder_page:wp-cron.php`) loaded, minted the group's HIGH 'no site content is lost' fix over a core file, and the plan deleted it | **FIXED** — a group glob is refused at load for three shapes: a metacharacter that can leave the root (`/ * ? [ ]`), a member of the one owner of "never delete this path" (`Source.PROTECTED`), or a `.php` at all (a root `.php` is WordPress's own executable surface — a SHAPE rule, not a filename list, so it holds for every release). A bare pattern is untouched by all three |
| L57 the docs contract compared a profile section's KEY NAMES only, so any NESTED list (media.extensions 39 values, web_script.signatures, deploy.*_signatures) could be reordered or truncated with the suite green | **FIXED** — the listing assertion recurses through objects AND lists: every list carries the same values in the same order and every scalar leaf (list members included) matches value AND JSON type, so `false`/`0` and `21`/`21.0` drift cannot pass (test: `test_every_listed_section_carries_the_profile_lists_value_for_value`) |
| L59 a full-site snapshot archived a SIBLING run's live bridge (`bridge-<hex>.php`) — a token-authenticated endpoint wpt deployed seconds earlier — and `restore` wrote it back as a working endpoint, so a token recovered from an archive (which outlives the token) re-armed it | **FIXED** — one owner for the deployed endpoint name shapes (`wpt.bridge_name.is_wpt_endpoint_file`, covering the bridge AND the standalone `wpt-probe-<hex>.php` probe, used by backup, restore and files): `backup` never archives one, `restore` refuses one as an explicit target AND refuses a whole manifest that carries one. The audit's stale-bridge sweep is deliberately BRIDGE-ONLY (`wpt.bridge_name.is_bridge_file` / `BRIDGE_NAME_RE`): it deletes only a proven expired bridge, never an arbitrary endpoint-shaped file |
| L60 a `--zip` that is not a zip archive escaped as a raw Python traceback from 8 commands (BadZipFile is neither WptError nor OSError, so every command body's error contract missed it) | **FIXED** — `ZipSource` raises the one-line `not a zip archive: <path>`; `--quiet` is irrelevant to a refusal |
| L62 `--db-uri` naming the WRONG database was never refused: the apply deleted another site's revisions and termmeta rows and reported success | **FIXED** — the offline path reads the database's OWN `siteurl`/`home` and compares them with `--wp-url` through `dump_witness`'s comparison (imported, never re-derived); a mismatch refuses naming the DATABASE, a database with neither option is refused as non-WordPress, a half-stated one proceeds with one warning |
| L63 `verify` ignored `--deadline` in the per-reference re-check loop: an 18 s run inside a 3 s budget reported 10,000 refs clean | **FIXED** — the deadline is threaded into `_recheck_refs` and checked per reference, so exhaustion ends the run through the ordinary error contract |
| L64 the documented offline rehearsal pair (`serve` + `verify`) could never verify anything (a static server cannot render PHP) and returned a GREEN pass having checked nothing | **FIXED** — a zero-reference walk is now an explicit `not a pass` (rc 1) with the wording spelled out, and `serve`'s receipt states where the rehearsal stops; a fake renderer was refused as a pretence |
| L65 a failing or refusing run wrote NO report, so a caller could not tell "planned nothing" from "never got far enough" | **FIXED** — every failure path now writes the report it can (the refusal, zero findings, `redact_text` applied), and a success report never gains the `run` key |
| L67 round 11's guard mis-fired: the owner was handed a BASENAME, so `responsive-menu/index.php` — a shape `get_plugins()` itself offers — was reported INACTIVE (with a live deactivate step) and dropped from db.active_missing's reinstall list, while the two sibling call sites passed the plugins-relative path | **FIXED** — the owner takes the whole plugins-relative path and the exception is scoped to the DIRECT CHILD `index.php`; a directory plugin whose own main file is `index.php` stays a plugin |
| L66 the crawler held any answer in memory: a 300 MB page cost 936 MB of RSS and a 3 GB page ended the run with a `MemoryError` | **FIXED** — the body is streamed through a bound (`walk.max_response_bytes`, 16 MiB shipped) and an over-sized answer is discarded with one line |
| L61 `env.php_min_active` had no shape validator (each shipped settings section validates its own shape at the load door), so `--set env.php_min_active=nonsense` compared the runtime against a string, raised a TypeError inside the check, and the audit turned it into a HIGH "check errored — report as a bug" at rc 0 | **FIXED** — the field validates at load (`EnvSettings.__post_init__`: a two-component version-shaped string like `8.2`; the stripped form is stored), naming the key |
| L58 the contract checked the TOP parser only, so an undocumented PER-COMMAND flag (where --apply/--purge-originals/--i-know-editors-are-off live) was invisible | **FIXED** — every option string a subparser declares must appear in SPEC's Commands section (test: `test_every_subparser_flag_is_documented`) |
| L56 `wp-content/plugins/index.php` (WordPress's own `// Silence is golden.` guard) was reported as an INACTIVE PLUGIN, putting a core file on the operator's removal list at medium risk | **FIXED** — `_plugin_units` skips the guard exactly the way `_plugin_relative_path` already skipped it on the option side: a direct child FILE that is not a plugin is not a unit (test: `test_wordpresss_own_directory_guard_is_not_a_plugin_unit`) |
| L51 the refusal marker had two producers (the bridge prefixed it, the client stripped and re-added it) and the PHP stem bound was a bare literal `5` with a one-way pin | **FIXED** — the bridge sends the BARE reason and the client is the single marker owner (the three status labels the server writes itself are returned byte-for-byte through a named list the pin reads from the deployed file); the stem bound is `WPT_MEDIA_STEM_PASSES`, pinned to the Python constant both ways |
| L47 `--log-file` REPLACED the stderr handler, so a run that failed (rc 1) printed its explanation only into the file — 0 bytes on the terminal, the opposite of a centralized chokepoint | **FIXED** — `--log-file` ADDS a file sink beside the console sink (one logger, two handlers, the same redaction filter); `--quiet` silences the console alone and the file still records everything |
| L48 the shape walker's bound counted LEVELS OPENED (a 1024-sibling width cost the same as a 1024-deep chain, ~1 s), and a value over budget THREW past the per-row loop, aborting a batch whose earlier rows were already written and unreported | **FIXED** — the budget is work, not depth; the throw is caught per row and travels on the existing `failed[]` channel ("refused: … work budget of 1024 levels"), so a batch always completes and states which rows were written. A value is refused, never truncated, and the client's `_MAX_DEPTH` stays PHP's own 4096 (a keep-set bound) with the relationship to the deployed budget pinned by a test |
| L49 two `unserialize` implementations answered the same stored values differently — webp's local rewrite gate reported "could not be parsed" for a `C:` payload, a 200-deep value and trailing bytes that PHP and the keep-gate both read | **FIXED** — `wpt.media_refs` is the one implementation; the analyzer delegates to it with its own POLICY (objects and nulls refused via an allow-list walk, trailing bytes refused, depth 64, a self-ancestor refused), ~90 lines of duplicated parser deleted |
| L55 a WordPress webroot shipped the source host's control files — a `home.html` "coming soon" page (a full-site visual outage at the site URL), a `404.shtml` that can take over LiteSpeed error handling, a `test.html`, `.ftpquota` with the OLD ACCOUNT's real quota numbers and two superseded `.htaccess` variants — and `webroot.junk` flagged none of them | **FIXED** — a `webroot_junk` entry may be `<group>:<glob>`: a grouped pattern matches the webroot-relative PATH and yields ONE finding per group with the group's risk, WHY and fix (`host_placeholder_page` HIGH, `host_account_quota` MEDIUM, `superseded_htaccess` MEDIUM — never conflated with the live `.htaccess`, which harden owns and the write-guard protects). The group globs are root-scoped BY CONSTRUCTION, so a theme's `home.html`, a plugin's authored `index.html` and `home.php` are unreachable; an empty side, a glob metacharacter on the left, or an unknown group name falls back to the bare behavior, so a profile can never invent a risk |
| L46 a documented profile knob (`media.extensions`) let the keep-gate and the enumeration come from two different lists, so a supported `--set` override could make trim-media delete a DB-referenced file in ftp mode; and the webshell check's new unproven class was steerable — one write to `wp-includes/version.php` demoted a definite HIGH shell to MEDIUM "do not remove" | **FIXED** — the `media_map` read carries the caller's family and the effective gate is the mirrored default **UNION** the request (a floor: the wire can only widen it; an inexpressible family is a refusal), and the cross-mode gate is MANDATORY for a destructive ftp apply (no `--sql` ⇒ one-line refusal; the dump read once, same extensions, same dirs, deadline honoured); the demotion is driven by the ABSENCE OF AN HTTP RESPONSE alone — any answer wp.org DID give (4xx, 5xx, a redirect, an HTML page, an empty body, a JSON list) is evidence it spoke and never demotes, because the request URL carries the ATTACKER-WRITABLE `$wp_version` and a 20,000-character version earns a live HTTP 414/400 that used to turn a confirmed HIGH webshell into MEDIUM 'do not remove' — a tampered-but-readable version file no longer lowers a verdict, and `core.integrity`'s own tampered finding is named in the detail |
| L39 the DB half of the media keep-set was MODE-DEPENDENT — 13 stored-value shapes (a size map carrying one `N;`/`O;`/`R;` lost every registered size offline; NUL/backslash paths kept; the attachment rows skipped the text scan; neither the extension nor the is-dir gate applied), so on one real site the same multi-size attachment family was protected offline and deletable over ftp | ONE rule set in `wpt/media_refs.py` (ref_normalize / ref_is_kept / PHP unserialize semantics, verified against the PHP 8.4 CLI) mirrored in bridge.php and measured against the real `wpt_media_db_map`; `is_media` delegates to the same gate; trim-media local-vs-ftp delete-set equality; and a CROSS-MODE APPLY GATE (a file the dump references and the fresh live union does not is refused, because a snapshot disagreement is undecidable) |
| L40 `webroot.junk` and `security.web_exposed_script` both DEGENERATED when wp.org was unreachable: junk reported NOTHING (a served `wp-includes/error_log` vanished offline, exit 0) and the web-script check fired HIGH on stock core (wp-login.php, wp-cron.php, xmlrpc.php, and other core files, with the backdoor triage text) | the delete PLAN and the CHECK split (the plan stays fail-closed, the check reports with an `unproven core basis` clause); the web-script check moves its unmap-comparable candidates to `security.web_exposed_script_unproven` (medium, its own category so report.py's triage rule can never fire on them) — both with the ordinary-file signature rate named in the detail |
| L41 the shipped `known_artifacts` pattern `bridge-*.php` exempted `bridge-shell.php` (a public evasion in a public repo) | `bridge-????????.php` with a hex-strict matcher (`?` = one hex digit, either case), pinned against the name wpt actually deploys |
| L42 a real page under 32 KB whose text merely CONTAINS challenge copy was classified as a bot-challenge and excluded from the live proof | the copy marker must be small AND near the document head (an interstitial leads with it) |
| L43 the L33 estimate split printed two rows both labelled "JPEG" on a mixed `.jpg`/`.jpeg` site | one row per FORMAT with the extensions it counts; plan total unchanged |
| L44 every action dry run and the deploy dry run silently ignored `--report`, so a caller could not tell from the filesystem whether a run had planned anything | ONE shared writer (`registry.write_report`) for the actions registry and the deploy dry run: the same markdown the run printed, created even for an EMPTY plan, paired with a JSON twin, and a path that cannot be written fails the run (rc 1). A `users_reset` credential never reaches either |
| L36 the web-script scan (substring + `.php`-only) missed six webshell evasions — `$_POST[`, `$_REQUEST[`, `php://input`, `$_GET [` (whitespace), a UTF-16 payload, a base64/gzinflate payload — never considered `.phtml`/`.phar`/`.PHP`, and rated wpt's OWN leftover `bridge-<hex>.php` a backdoor | the request-superglobal family pass, the profile's executable-extension superset (case-insensitive), encoding-aware views, the `encoded-payload` line, and the `known_artifacts` exemption — each evasion a HIGH-finding test against the real bridge bytes |
| L37 `publicly_served_paths` trusted any HTTP 200 and requested unescaped paths (a soft-404 host produced a false disclosure; a space/`#` asked for another URL) | one certainly-missing baseline per call + body comparison, `quote(safe="/")`, the claim keeping the tree's spelling |
| L38 an emptied `web_script.signatures` fell back to the six module needles while `to_diff` reported none | empty list == scan nothing (master switch); shipped profile == dataclass default == module fallback, pinned by one contract test |
| L35 an inactive plugin's DATA can still be live (active feeds, cron events, options, and tables) | the plugins.inactive fix text orders the database check before the file deletion |
| L52 a PARTIAL dump measured a keep-set of ZERO — a positive "this database references no uploads file" — and the audit then treated the database-attached photos as deletable (a dump with the options role resolved but no `postmeta`/`posts`; `4b5f8c4`) | the dump-identity partiality rule: once the options role is resolved, `postmeta`/`posts` are REQUIRED, so a partial dump yields `db_refs is None` — UNKNOWN, never an empty set. `db_refs_from_dump` returns None for both partiality and a contested identity, and the media check enumerates nothing rather than everything |
| L53 the active set was `list[str]` on the audit side too, so an unmeasurable set read as "nothing is active": `plugins.inactive` reported every installed plugin, `plugins.duplicate` guessed a keep-one, `db.active_missing` reported "nothing missing", and `db.ghost_tables` CRASHED on `None` into a HIGH `audit.check_failed` (`aa5bc4c`, `6e81f0f`, `051e58b`) | `AuditData.active_plugins` is `list[str] | None` and every consumer asks the same measured question: `plugins.inactive`/`db.active_missing` degrade into a zero-count `plugins.active_set_unknown`/`db.active_set_unknown` marker (its own category, so no suggested-step rule — both would refuse offline — can fire, and no total counts a measurement nobody made) while `plugins.duplicate` and `db.ghost_tables` stay SILENT. No `check_failed`, and a measured empty set still reports (`[]` is a real answer) |
| L54 four to seven consumers (analyzer, media keep-set, cross-mode witness, `clean-db --db-uri`, three plan-item routers) asked the same table-identity question of ONE dump and each re-derived it, so one run logged the same sentence two to four times and two rules could pick DIFFERENT tables inside one run (`aioseo_options` vs `wp_options` ⇒ 0 refs where the control measured the full set) (`4b5f8c4`) | the owner memoizes (`_resolve` keyed on mode+role+the input's own identity, one cache slot per wire): N consumers on one dump produce EXACTLY ONE resolution and ONE warning per (wire, role, input), naming every candidate; a DIFFERENT input re-resolves and re-warns, so the guarantee is per input and never global silence |
| L68 the canonical harden block's rules required the optional leading slash, so on a host that keeps it (LiteSpeed per-directory matching) the HTTPS force only matched the root and the REST-user block never fired | `^/?` is the anchor for every path, with or without the leading slash; the REST rule ALSO has a `QUERY_STRING` condition for WordPress's `?rest_route=/wp/v2/users` dispatch (literal or `%2F`), and `security.rest_users` probes both forms (tests: `test_author_scan_rule_matches_the_path_apache_actually_sees`, `test_R25_harden_rest_route_query_fallback_is_blocked`, `test_R25_rest_users_detects_the_query_fallback`) |
| L69 a killed/failed update-core leaves core staging names (`*.wpt-old`, the staging prefix, `wp-content/upgrade/`) the operator cannot see before the next run | `doctor`'s conditional residue row names every staging/retired-core directory (and the WordPress updater's `wp-content/upgrade/` only when it is a directory), from the one `update_core_residue` owner (test: `test_R25_doctor_names_update_core_staging_residue`) |
| L70 a non-WordPress webroot made `doctor` upload a bridge, answer an opaque HTTP 500 and leave the operator without the PHP/DB fact that explained it | the `wordpress layout` preflight reads the root listing it already has and stands the bridge down with a precise "not a WordPress webroot — missing …" row; the standalone `php runtime` probe still runs (it loads no WordPress), and the PHP probe template is package-data-pinned |
| L71 a missing `pdo_mysql` was invisible because the bridge's `info` call cannot run when `wp-load.php`/PDO/DB are broken | the token-gated, no-WordPress `wpt-probe-<8hex>.php` returns PHP/SAPI/extensions/session flags, self-deletes, and is swept by expiry (tests: `test_php_probe.py`) |
| L72 the fatal that explained a 500 existed only in the host's rotated `domains/<domain>/logs/*.tar.gz`, outside the webroot | `wpt logs` reads bounded host/webroot logs (plain/gzip/tar members in memory), redacts/truncates every line, and the doctor surfaces the latest matching line; tests: `test_logs.py` and the doctor host-log cases |
| L73 FTP `LIST`'s `total N` header crashed the parser and the protocol's mode/owner/mtime metadata was discarded, so a permissions question could not be answered | the Unix LIST parser skips non-entry lines, populates optional `Entry.mode`/`mtime`/`owner`/`group`, and `security.uploads_perms` reports world-writable upload paths only when the mode was actually measured |
| L74 a legacy application's request-driven sinks (session IDs, reflected output, SQL/table identifiers, includes, code execution) had no source-only check and could only be found by manual code review | `security.source_patterns` + `wpt scan` run the PHP-aware heuristic without WordPress/bridge/DB; both modes, source-only, review-candidate findings with root-cause fixes; tests: `test_source_scan.py` and `test_scan.py` |
| L75 the operator knew the FTP login but not the docroot, and `--webroot` had to be guessed | `wpt discover` scans a bounded account-root candidate set and marks each by the three exact WordPress markers without writing, reading or opening HTTP; tests: `test_discover.py` |
| L76 a homepage HTTP 500 read as WARN, so a WP site with a working bridge could exit 0 on a dead front page | `doctor` classifies 5xx as FAIL (4xx stays WARN); test: `test_site_500` |
| L77 the only TLS signal was a low-risk `security.cert_mismatch` finding that discarded SAN/issuer/expiry and said nothing about HTTP→HTTPS or HSTS | the doctor's `tls certificate` and `https policy` rows report bounded certificate facts, verification, expiry window, redirect and HSTS; tests: `test_doctor_network.py` |
| L78 editing a non-WordPress application file had no backup/rollback path, so a bad FTP write had no recovery point and a multi-file change could stop halfway | `wpt files` snapshots selected files (manifest + bytes + SHA-256), pairs `--path` with `--from`, writes siblings/temp and renames after read-back, rolls every already-changed target back on failure, and restores by verified snapshot; WordPress core/config paths stay refused; tests: `test_files.py` |

## Documentation
- `README.md` — usage and the canonical command table.
- `SPEC.md` — this file, the binding engineering contract.
- `CHANGELOG.md` — release history.
- `docs/` — quickstart, safety, architecture, development, FAQ, and research notes.

## Out of scope v1 (README roadmap)
Applying plugin/theme updates (core updates ship as `update-core`); panel APIs
(DirectAdmin/cPanel); SSH connector; multisite.
