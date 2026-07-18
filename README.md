<p align="center">
  <img src="frontend/public/extortsignal-mark.svg" alt="ExtortSignal logo" width="104" height="104">
</p>

<h1 align="center">ExtortSignal</h1>

[![CI](../../actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)
[![Security checks](../../actions/workflows/security.yml/badge.svg)](../../actions/workflows/security.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB.svg)](https://www.python.org/)
[![React 19](https://img.shields.io/badge/React-19-61DAFB.svg)](https://react.dev/)

ExtortSignal is a local-first, defensive monitor for public ransomware claims. It collects from public aggregators, stores original observations locally, matches claimed organizations against client profiles, and presents results in a non-technical web interface.

**Early signal. Clear action.**

ExtortSignal does **not** download leaked data or treat actor claims as confirmed incidents. Public-feed collection runs in passive mode. Direct-site evidence capture is separately allowlisted and designed for an isolated Kali worker.

## Included in this build

- RansomLook, RansomFeed, and Ransomware.live public-source adapters.
- Automatic polling every two minutes while the application is running.
- Append-only compressed raw observations.
- SQLite storage with WAL mode.
- Cross-source deduplication.
- Exact domain, exact company-name, alias, and fuzzy-name matching.
- Multi-market and multi-industry client profiles for multinational organizations.
- Subsidiary and third-party relationship monitoring with name and domain matching.
- Critical, high, and human-review alert levels.
- Guided first-run client setup.
- Dashboard, alerts, client directory, review queue, activity, and source health.
- Victim-intelligence explorer with period, actor, country, industry, and status filters.
- Maintained threat-actor DLS catalog imported from ransomware.live.
- Per-site capture allowlisting and a guarded queue for an isolated Kali worker.
- Synthetic sample workspace for safe evaluation.
- Responsive, keyboard-accessible interface.
- Passive and active operating modes with configurable scheduling.
- Optional AI-assisted victim enrichment, actor analysis, and sanitized client-email drafting.
- SMTP delivery for approved victim-summary notifications.
- Separate source publication and local ingestion timestamps.

## Evidence warning

Every record is an allegation published or repeated through a public source. Verify important claims with independent sources and internal telemetry before client notification, reporting, or incident-response action.

The main application never connects to `.onion` addresses. Direct screenshots are
designed to run only from a separately isolated Kali VM after an authenticated
worker is configured. The worker must not download leaks, submit forms, contact
actors, authenticate to sites, or access the host LAN.

## Local setup

### One-command Kali setup

From the project folder in Kali:

```bash
chmod +x setup-kali.sh
./setup-kali.sh
```

Copy the complete ExtortSignal project folder into Kali before running the
installer; the script is not a standalone application. It installs the backend
and frontend, creates `.env` and a worker token,
preserves existing data, and starts a localhost-only systemd service. To also
install Tor and Chromium prerequisites for the later isolated capture worker:

```bash
./setup-kali.sh --prepare-capture
```

The installer does not contact any threat-actor site. Direct capture remains an
explicit per-site action in the GUI. Run `./setup-kali.sh --help` for options.

### Manual setup

Requirements:

- Python 3.11 or newer.
- Node.js 20 or newer.
- pnpm.

Create the backend environment:

```bash
cd ExtortSignal
python3 -m venv .venv
.venv/bin/pip install -e 'backend[dev]'
```

Install and build the GUI:

```bash
cd frontend
pnpm install
pnpm run build
cd ..
```

Start the complete application:

```bash
chmod +x run.sh
./run.sh
```

Open <http://127.0.0.1:8765>.

On first launch, add a real client profile or choose **Explore with synthetic sample data**. Synthetic records use reserved `.example` domains and are safe to retain.

## Configuration

Copy `.env.example` to `.env` to configure the application. `run.sh` loads this
local file automatically; it is excluded from Git. API keys and SMTP passwords
entered through the GUI are saved in `data/secrets.json` with user-only file
permissions. They are never returned by the API, but the file is a local
credential store rather than an operating-system keychain and must be protected
and excluded from backups or support bundles.

The Sources page also provides **Synchronize all available**. It requests
RansomLook history from 2015, exhausts RansomFeed's country catalog and splits
any 1,000-record country response into yearly partitions, then deduplicates all
overlaps before ingestion. If a yearly partition still reaches the upstream
limit, the source card reports partial coverage instead of claiming completion.
Ransomware.live's configured free v2 endpoint exposes recent victims rather than
a paginated archive, so the application imports its full response and labels it
`recent-only`.

Useful controls:

```bash
RANSOM_MONITOR_AUTO_COLLECT=0 ./run.sh
RANSOM_MONITOR_COLLECT_INTERVAL=300 ./run.sh
RANSOM_MONITOR_DATA_DIR=/private/claimwatch-data ./run.sh
```

Data defaults to `data/` and is excluded from Git. Back it up as sensitive operational data.

## Development

Run the backend and Vite separately:

```bash
.venv/bin/python -m uvicorn ransom_monitor.main:app --app-dir backend --host 127.0.0.1 --port 8765 --reload
```

```bash
cd frontend
pnpm run dev
```

The development GUI runs at <http://127.0.0.1:5173> and proxies API requests to the backend.

## Tests

```bash
PYTHONPATH=backend .venv/bin/python -m pytest backend/tests
```

```bash
cd frontend
pnpm run build
```

## Current limitations

- No user authentication; keep the application bound to localhost or place it behind an authenticated reverse proxy.
- Direct-site screenshot execution requires the separate isolated worker; the GUI currently provides catalog, allowlisting, and queue controls.
- Email drafts require analyst approval; the platform does not automatically send individual client notifications.
- AI enrichment quality depends on the configured provider and available public context.
- GUI-entered credentials use a permission-restricted local file, not an operating-system keychain.
- Source APIs can change without notice; source health exposes failures without stopping the application.

## Public source references

- [Ransomware.live public recent-victims API](https://api.ransomware.live/v2/recentvictims)
- [RansomFeed public API documentation](https://api.ransomfeed.it/docs/html)
- [RansomLook public API](https://www.ransomlook.io/api/posts)

## Privacy and public-release packaging

Runtime data is sensitive and intentionally excluded from version control. The
`data/` directory can contain client profiles, alerts, raw observations, saved
AI/SMTP credentials, and enrichment results. Never attach it to an issue or a
release archive. Local `.env` files must also remain private.

Create a clean source archive with:

```bash
./scripts/package-release.sh
```

The archive excludes runtime data, credentials, virtual environments,
dependencies, build output, caches, and Git metadata. Review
`RELEASE_CHECKLIST.md` before publishing.

## Contributing and license

ExtortSignal is available under the [Apache License 2.0](LICENSE). Contributions
must stay within the defensive safety boundary in [CONTRIBUTING.md](CONTRIBUTING.md),
and security reports should follow [SECURITY.md](SECURITY.md).

## Repository quality checks

GitHub Actions runs the Python test suite on Python 3.11 and 3.12, Ruff static
and security analysis, Python and npm dependency audits, frontend type-checking
and production builds, shell syntax checks, and release-archive hygiene checks.
Dependency Review blocks newly introduced high-severity dependencies, while
Dependabot proposes weekly Python, npm, and Actions updates.

CodeQL configuration is retained for public repositories and private
repositories with GitHub Code Security. Because GitHub does not permit CodeQL
on an unlicensed private repository, it is gated behind repository visibility
or the `CODEQL_PRIVATE_ENABLED=true` repository variable.

### Optional Snyk scanning

The Security checks workflow also supports Snyk Open Source tests for the
Python and frontend dependency trees. Add a repository Actions secret named
`SNYK_TOKEN`, then run the **Security checks** workflow manually or push a
change. High- and critical-severity fixable findings fail the Snyk job. If the
secret is absent, the job explains that it is disabled and exits successfully.

Snyk does not currently support PEP 621 metadata for pip scans, so
`backend/requirements.txt` is a runtime-only mirror of the dependencies in
`backend/pyproject.toml` and must be updated with it.

## Brand assets

- `frontend/public/extortsignal-mark.svg` — primary application mark
- `frontend/public/chill-ethical-capybara-on-dark.svg` — subtle capybara-only studio mark
- `frontend/public/favicon.svg` — browser icon
- `brand/extortsignal-brand-board.png` — generated identity direction

## API

When running, interactive API documentation is available at <http://127.0.0.1:8765/docs>.

Important endpoints:

```text
GET   /api/v1/dashboard
GET   /api/v1/clients
POST  /api/v1/clients
PUT   /api/v1/clients/{client_id}
GET   /api/v1/claims
GET   /api/v1/alerts
PATCH /api/v1/alerts/{alert_id}
GET   /api/v1/sources
POST  /api/v1/collect
POST  /api/v1/backfill?start_year=2015
POST  /api/v1/demo/seed
```
