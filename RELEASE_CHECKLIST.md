# Public release checklist

## Required before publication

- [ ] Run the sanitization dry run and review the selected row counts:
      `python3 scripts/sanitize-public-release.py`.
- [ ] Remove client-derived runtime state and saved credentials:
      `python3 scripts/sanitize-public-release.py --apply --clear-secrets`.
- [ ] Run `python3 scripts/public-release-audit.py` and resolve every finding.
- [ ] Confirm runtime and secret paths are ignored by Git.
- [ ] Verify backend tests, Ruff, security lint and the production frontend build.
- [ ] Confirm the localhost-only boundary and CIA limitations remain documented.
- [ ] Confirm Apache-2.0 licensing, notices and third-party attribution.
- [ ] Review `DATA_SOURCES.md` against each provider's current terms and API licence.
- [ ] Set the public repository URL and enable private security advisories.
- [ ] Confirm a monitored security-reporting contact or process.
- [ ] Enable secret scanning and push protection in the repository settings.
- [ ] Protect `main` and require CI and Security checks before merging.
- [ ] Require CodeQL too when the repository is public or GitHub Code Security is licensed.
- [ ] Configure `SNYK_TOKEN` if Snyk Open Source scanning is required.

## For every release

- [ ] Run `PYTHONPATH=backend .venv/bin/python -m pytest backend/tests`.
- [ ] Run `.venv/bin/python -m ruff check backend scripts` and
      `.venv/bin/python -m ruff check --select S backend/ransom_monitor`.
- [ ] Run `cd frontend && pnpm run build`.
- [ ] Run `python3 scripts/public-release-audit.py --repository-only`.
- [ ] Run `./scripts/package-release.sh`.
- [ ] Inspect the archive listing for `data/`, `.env`, secrets, databases,
      `.venv`, `node_modules`, build output, caches, and personal paths.
- [ ] Install the archive in a clean Kali/Debian VM.
- [ ] Confirm the service binds to `127.0.0.1`, the first-run product tour can
      be completed or skipped without a client, and no synthetic client is created.
- [ ] Confirm `data/` and database files are not group/world-readable.
- [ ] Record an encrypted backup/restore decision for retained operator data.
- [ ] Review source API terms, attribution, and availability.
- [ ] Record known limitations and compatibility changes in the release notes.
