# Security policy

## Supported version

ExtortSignal is currently a pre-1.0 project. Security fixes are applied to the
latest published version only.

## Reporting a vulnerability

Please use the hosting repository's private security-advisory feature. Do not
open a public issue containing an exploit, client profile, API key, `.env`
content, database, raw observation, DLS address, or screenshot of sensitive
operational data.

Include the affected version, reproduction steps, impact, and a minimal test
case with synthetic `.example` data. Maintainers should acknowledge a complete
report within seven days and coordinate disclosure after a fix is available.

## Deployment boundary

ExtortSignal has no built-in user authentication. The supported default is
localhost-only operation. Do not expose the application directly to a LAN or
the internet. Direct-site activity must run from the separate, allowlisted Kali
worker process and must never download leaks, authenticate, submit forms, or
contact threat actors. The supported Kali service uses a dedicated account,
authenticated loopback job control, loopback-only network policy, and filesystem
denial for the API credential store, client database, `.env`, and raw-feed archive.

Host-header allowlisting and the required same-origin mutation marker protect
the default browser workflow against common local cross-site request paths, but
they do not establish a user identity or replace authentication. Keep
`EXTORTSIGNAL_TRUSTED_HOSTS` limited to loopback unless an authenticated reverse
proxy terminates access. Custom AI and private SMTP destinations must be
explicitly allowlisted with exact hostnames after administrative review.

## Confidentiality, integrity, and availability

- Runtime data is private operational material even when the underlying claim
  originated from a public feed. Keep `data/`, `.env`, credentials, client
  profiles, screenshots, AI results and email drafts out of repositories,
  support bundles and public issues. Database and credential files must not be
  group- or world-readable.
- Preserve source provenance and hashes. Do not edit archived observations to
  correct normalized records; retain corrections as new observations or
  analyst decisions. Run `python3 scripts/public-release-audit.py` before any
  publication or support bundle is created.
- Back up runtime data only to encrypted, access-controlled storage and test a
  restore periodically. The local SQLite deployment has no replication or
  automatic disaster recovery. Public-feed failure and DLS unavailability are
  expected conditions and must not be interpreted as evidence that no claim
  exists.

## Public-release gate

Use `scripts/sanitize-public-release.py` to remove client-derived runtime state
and disable active capture selections. `scripts/public-release-audit.py` checks
both release-candidate source files and, when present, the ignored local
database. `scripts/package-release.sh` archives committed source only and
rejects runtime, credential, database, key and generated paths.
