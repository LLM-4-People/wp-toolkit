# Security policy

## Supported versions

| Version | Supported |
|---|---|
| `0.1.x` | Yes |
| Other / unreleased | No |

## Reporting a vulnerability

Do **not** open a public issue for a security problem. Report it privately
through GitHub Security Advisories:

<https://github.com/LLM-4-People/wp-toolkit/security/advisories/new>

If advisories are unavailable, contact the maintainers through the repository
profile and ask for a private channel.

Include:

- the affected version and commit;
- the command, source mode, and configuration involved;
- a minimal reproduction with synthetic hosts and credentials;
- the observed impact and any suggested fix;
- redacted logs or reports. Never include a real password, token, private key,
  client domain, or personal data.

## Scope

Reports are especially valuable for:

- credential or secret leakage into a log, report, exception, receipt, or
  generated artifact;
- path traversal, symlink races, or writes outside the intended webroot;
- unsafe archive extraction or SQL/payload handling;
- remote code execution, command injection, or unsafe deserialization;
- destructive actions that can apply without a plan, confirmation, or snapshot;
- report/JSON output that exposes data the operator did not select;
- dependency or supply-chain issues in the shipped package.

## Operational guidance

- Passwords normally come from environment variables (`--password-env`,
  `--db-password-env`) or prompts. An inline `--db-uri` password is accepted
  for compatibility, but it is visible in shell history and the process list;
  use `--db-password-env` instead. Never put a password in a profile.
- `.wpt-backup/`, `.wpt-live/`, `.wpt-cert/`, `.wpt-cache/`, dumps, logs, and
  certificates are operational data. They are intentionally excluded from
  source control and the published package; keep them out of pull requests and
  issue reports.
- If a credential was ever committed or shared, rotate it. Removing it from a
  working tree or rewriting history is not a substitute for rotation.
- The local proxy certificate is a throwaway localhost certificate, not a
  trust anchor. Do not install it system-wide.

## Disclosure

We will acknowledge a report as soon as practical, investigate with the
reporter, and coordinate a fix and disclosure date. Please give us a reasonable
window before publishing details. We do not operate a paid bug bounty.

## Safe harbor

We will not pursue legal action for good-faith research that follows this
policy, avoids privacy violations and service disruption, and reports findings
privately. This safe harbor does not authorize testing against sites or systems
you do not own or have permission to test.
