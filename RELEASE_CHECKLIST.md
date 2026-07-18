# Public release checklist

## Required before publication

- [x] Remove local databases, raw records, saved credentials, and `.env`.
- [x] Confirm runtime and secret paths are ignored by Git.
- [x] Scan source files for credentials and personal filesystem paths.
- [x] Verify backend tests and the production frontend build.
- [x] Document the localhost-only security boundary.
- [x] Provide a clean release-packaging command.
- [x] Choose and add a software license.
- [ ] Set the public repository URL and enable private security advisories.
- [ ] Confirm a monitored security-reporting contact or process.
- [ ] Enable secret scanning and push protection in the repository settings.
- [ ] Protect `main` and require CI and Security checks before merging.
- [ ] Require CodeQL too when the repository is public or GitHub Code Security is licensed.

## For every release

- [ ] Run `PYTHONPATH=backend .venv/bin/python -m pytest backend/tests`.
- [ ] Run `cd frontend && pnpm run build`.
- [ ] Run `./scripts/package-release.sh`.
- [ ] Inspect the archive listing for `data/`, `.env`, secrets, databases,
      `.venv`, `node_modules`, build output, caches, and personal paths.
- [ ] Install the archive in a clean Kali/Debian VM.
- [ ] Confirm the service binds to `127.0.0.1` and first-run onboarding is empty.
- [ ] Review source API terms, attribution, and availability.
- [ ] Record known limitations and compatibility changes in the release notes.
