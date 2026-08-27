# Changelog

## Unreleased

- Replace mandatory first-client onboarding with a reusable product tour that
  explains the workspaces, Passive/Active safety boundaries, and analyst flow.
- Reconcile ransomware.live and RansomLook clear-web DLS catalogues for
  recently active actors, preserving cross-source provenance and partial-sync
  failures without contacting listed onion hosts.
- Document upstream data attribution and redistribution limitations.
- Add repeatable public-release sanitization and repository/runtime privacy audits.
- Add a scoped release reset for AI/capture job history, AI-generated analyses,
  custom settings, DLS allowlists, and AI/SMTP credentials while optionally
  retaining operator records, plus a contributor map for safe DLS profiles.
- Force SQLite database and sidecar files to user-only permissions outside systemd.
- Document confidentiality, integrity, availability, backup, and release-gate controls.

## 0.1.0 — 2026-07-18

First public-beta candidate of ExtortSignal.

- Local-first collection and deduplication of public ransomware claims.
- Client, subsidiary, third-party, industry, keyword, and geography matching.
- Analyst workflow for alerts, review status, activity, and victim intelligence.
- Optional AI enrichment, flexible trend analysis, and sanitized email drafting.
- Passive collection plus guarded, allowlisted capture queues for an isolated worker.
- SMTP digest configuration, source health, historical imports, and Kali setup tooling.
- Apache-2.0 licensing with contributor and security-reporting guidance.
- GitHub CI, Ruff, CodeQL, Dependency Review, Dependabot, and release-hygiene automation.

This release has no built-in authentication and is intended for localhost-only
use. Actor claims remain unverified allegations and require analyst review.
