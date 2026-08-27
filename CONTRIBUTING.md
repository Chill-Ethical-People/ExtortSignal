# Contributing

ExtortSignal welcomes defensive security improvements, source reliability
fixes, accessibility work, tests, and documentation.

## Safety boundary

Use synthetic `.example` organizations in tests and issues. Never commit or
upload client profiles, API or SMTP credentials, databases, raw observations,
leaked data, real DLS evidence, or screenshots containing operational data.
Do not add code that downloads leaks, authenticates to threat-actor services,
submits forms, contacts actors, or bypasses access controls.

## Local checks

```bash
PYTHONPATH=backend .venv/bin/python -m pytest backend/tests
.venv/bin/python -m ruff check backend
```

```bash
cd frontend
pnpm run build
```

```bash
bash -n run.sh setup-kali.sh scripts/package-release.sh
python3 scripts/check-dependency-mirror.py
python3 scripts/public-release-audit.py --repository-only
./scripts/package-release.sh
```

Open a focused pull request, describe the user-facing effect, and update
`CHANGELOG.md` when behavior changes. Security reports belong in the private
process described by `SECURITY.md`, not in a public issue.
