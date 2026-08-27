<p align="center">
  <img src="frontend/public/extortsignal-mark.svg" alt="ExtortSignal logo" width="104" height="104">
</p>

<h1 align="center">ExtortSignal</h1>

<p align="center">
  <a href="../../actions/workflows/ci.yml"><img alt="CI status" src="../../actions/workflows/ci.yml/badge.svg"></a>
  <a href="../../actions/workflows/security.yml"><img alt="Security checks status" src="../../actions/workflows/security.yml/badge.svg"></a>
  <a href="../../actions/workflows/snyk.yml"><img alt="Snyk status" src="../../actions/workflows/snyk.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="Apache-2.0 license" src="https://img.shields.io/badge/License-Apache--2.0-blue.svg"></a>
  <a href="https://www.python.org/"><img alt="Python 3.11 or newer" src="https://img.shields.io/badge/Python-3.11%2B-3776AB.svg"></a>
  <a href="https://react.dev/"><img alt="React 19" src="https://img.shields.io/badge/React-19-61DAFB.svg"></a>
</p>

ExtortSignal is a local-first, defensive monitor for public ransomware claims. It collects from public aggregators, stores original observations locally, matches claimed organizations against client profiles, and presents results in a non-technical web interface.

**Early signal. Clear action.**

ExtortSignal does **not** download leaked data or treat actor claims as confirmed incidents. Public-feed collection runs in passive mode. Direct-site evidence capture is separately allowlisted and designed for an isolated Kali worker.

## Included in this build

- RansomLook, RansomFeed, and Ransomware.live public-source adapters.
- Automatic polling every two minutes while the application is running.
- Append-only compressed raw observations with per-source observation metadata,
  content hashes, and parser provenance even when multiple feeds resolve to one
  normalized claim.
- Indexed SQLite storage with WAL mode, batched ingestion, busy-timeout handling,
  memory-mapped reads, and composite time/facet indexes for concurrent local use.
- Cross-source deduplication.
- Exact domain, exact company-name, alias, and fuzzy-name matching.
- Multi-market and multi-industry client profiles for multinational organizations.
- Subsidiary and third-party relationship monitoring with name and domain matching.
- Critical, high, and human-review alert levels.
- Guided first-run product tour that teaches the workspaces, collection modes,
  and analyst workflow without requiring or creating a client profile.
- Dashboard, alerts, client directory, review queue, activity, and source health.
- Victim-intelligence explorer with period, actor, country, industry, and status filters.
- Maintained threat-actor DLS catalog imported from ransomware.live.
- Per-site capture allowlisting and a guarded queue for an isolated Kali worker.
- Local DOM-plus-Tesseract OCR evidence, text hashing, duplicate detection, status signals, and line-level change counts.
- GUI-configurable lazy-load coverage controls with explicit stable, scroll-limit, and height-limit outcomes for every capture.
- OCR continuity anchors that verify overlap with the previous capture and flag suspected uncaptured content. A bounded, deterministic adapter can expand exact load-more controls, follow same-origin next-page controls, and capture valid ARIA tabs as separate evidence states.
- Synthetic sample workspace for safe evaluation.
- Responsive, keyboard-accessible interface.
- Passive and active operating modes with configurable scheduling.
- Offline threat-actor dossiers for every retained label, with richer bundled
  analyst profiles for established operations and conservative, clearly marked
  fallbacks for emerging labels. Optional AI updates must cite retained MITRE,
  government, or original security-research evidence before they can overlay
  the local profile; victim-list statistics always remain separate.
- A documented [actor identity and profile standard](docs/actor-identity-and-profile-standard.md)
  with conservative cross-source aliases, related-but-distinct safeguards, and
  a repeatable full-archive normalization audit.
- Optional AI-assisted victim enrichment, actor analysis, and sanitized client-email drafting.
- Canonical organization profiles that propagate reviewed/enriched industry,
  geography, nature, and source provenance across linked victim observations.
- SMTP delivery for approved victim-summary notifications.
- Separate source publication and local ingestion timestamps.

## Evidence warning

Every record is an allegation published or repeated through a public source. Verify important claims with independent sources and internal telemetry before client notification, reporting, or incident-response action.

Passive collection never connects to `.onion` addresses. Direct screenshots run
only when Active mode is selected inside an isolated Kali VM and a catalog entry
is explicitly allowlisted. The worker must not download leaks, submit forms,
contact actors, authenticate to sites, or access the host LAN.

Direct capture runs in a separate process and fails closed unless the configured proxy is an unauthenticated
SOCKS5 listener on loopback and completes a local SOCKS handshake. Each browser
run uses a new ephemeral context with no granted permissions; downloads,
popups, dialogs, WebSockets, service workers, DNS prefetch, and non-proxied
WebRTC UDP are
blocked. A request interceptor permits only `GET` and `HEAD` traffic to the
exact allowlisted onion origin
and records blocked off-origin requests plus the OPSEC preflight outcome with
the capture job. Read-only interaction is capped per job and excludes forms,
typing, authentication, downloads, messaging, and arbitrary coordinate clicks.
An exact Enter/Continue/View site/Proceed control may be clicked once only after
non-white visual content renders. These controls reduce exposure, but they are not a guarantee
of anonymity; use a dedicated, patched VM with NAT, no shared clipboard/folders,
no personal accounts, and no access to production networks.
The Kali installer runs the worker under a dedicated system account. It receives
bounded jobs through an authenticated loopback API and can write only to
`data/captures`; systemd denies it access to `.env`, the main database, raw
public-feed archives, and the credential store.

## Local setup

### One-command Kali setup

From the project folder in Kali:

```bash
chmod +x setup-kali.sh
./setup-kali.sh
```

Copy the complete ExtortSignal project folder into Kali before running the
installer; the script is not a standalone application. It installs the backend
and frontend, creates `.env` and a worker token, preserves existing data, and
starts a localhost-only web service. To also install Tor and Chromium and create
the separately sandboxed capture-worker service:

```bash
./setup-kali.sh --prepare-capture
```

The installer does not contact any threat-actor site. Direct capture remains an
explicit per-site action in the GUI. The GUI reports the worker online only
after an authenticated heartbeat. Useful service checks are:

```bash
sudo systemctl status extortsignal extortsignal-capture
sudo journalctl -u extortsignal-capture -f
```

Run `./setup-kali.sh --help` for installer options.

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

The API accepts only the configured host headers and requires the
`X-ExtortSignal-Request: same-origin` marker on every state-changing API
request. The GUI adds it automatically. Command-line and integration clients
must add the same header to `POST`, `PUT`, `PATCH`, and `DELETE` requests.
These controls reduce local cross-site request risk; they are not user
authentication. Keep the service on localhost unless an authenticated reverse
proxy is deliberately configured.

The Sources page also provides **Synchronize all available**. It requests
RansomLook history from 2015, exhausts RansomFeed's country catalog and splits
any 1,000-record country response into yearly partitions, then deduplicates all
overlaps before ingestion. If a yearly partition still reaches the upstream
limit, the source card reports partial coverage instead of claiming completion.
Routine ransomware.live monitoring uses its recent-victims endpoint for prompt
detection. Full synchronization separately exhausts the documented
`/victims/{year}/{month}` partitions from the requested start year through the
current month. Failed months are listed explicitly and mark the source partial.

When automatic collection is enabled, ExtortSignal also runs a non-blocking
rolling-history bootstrap once per day. It requests data from the beginning of
the previous calendar year, which guarantees a request window longer than 365
days from archive-capable sources. Source cards report the observed date span
and flag an upstream response that does not demonstrate a full year; the
application never presents a failed or capped source partition as complete.

The Intelligence volume graph exposes both earliest-publication and
source-reported estimated-attack-date views. Both deduplicate a normalized
actor–victim pair across public sources; the attack-date view reports field
coverage because records without that upstream field are excluded.

Configured AI providers do not receive unrestricted browsing control. For
actor profiles and trend analysis, ExtortSignal performs bounded clear-web
discovery across public-sector and established security-research publishers,
retains attributable excerpts and URLs locally, and supplies that evidence to
the model. Victim enrichment combines bounded organization, reporting, incident
and prior-local-claim candidates. Search results remain candidates, public
victim claims remain allegations, and direct DLS content is never sent to cloud
AI enrichment.

SQLite remains the intentionally dependency-free local database. Claim rows
carry a normalized `observed_at` value and indexed actor, geography, industry,
source, publication-state, and time combinations. Feed batches are archived and
written in a single WAL transaction, while dashboard queries use the indexed
time window rather than scanning unrelated history.

Useful controls:

```bash
RANSOM_MONITOR_AUTO_COLLECT=0 ./run.sh
RANSOM_MONITOR_COLLECT_INTERVAL=300 ./run.sh
RANSOM_MONITOR_DATA_DIR=/private/claimwatch-data ./run.sh
```

Data defaults to `data/` and is excluded from Git. Back it up as sensitive operational data.

## Security and CIA model

ExtortSignal is designed for a single-operator, localhost deployment. Its
security controls reduce risk but do not turn the current pre-1.0 build into a
multi-user internet service.

- **Confidentiality:** runtime databases, raw observations, screenshots,
  credentials and `.env` are excluded from Git. SQLite, WAL and SHM files are
  forced to user-only permissions. GUI-entered secrets remain in the local
  permission-restricted credential store, and external AI requests sanitize
  monitored-client identifiers where the workflow requires it.
- **Integrity:** source observations retain hashes and parser provenance;
  normalized claims preserve their underlying observations; SQLite foreign-key
  and integrity checks are part of the public-release audit; CI runs tests,
  static analysis, dependency review and archive-content checks. Release
  archives include a SHA-256 checksum.
- **Availability:** SQLite WAL mode and bounded retry handling keep public-feed
  failures isolated, health endpoints expose readiness, and the capture worker
  is a separate restartable service. Operators remain responsible for encrypted
  backups and restore testing because the project does not yet include managed
  backup or high-availability orchestration.

See [SECURITY.md](SECURITY.md) for the supported deployment boundary and
residual risks.

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

### Extending DLS capture behavior

DLS presentation changes must be handled as small, actor-scoped, read-only
profiles. Do not hard-code onion addresses or loosen the global network and
interaction guardrails to make one site render.

| Change | Code location |
| --- | --- |
| Actor aliases and canonical identity | `backend/ransom_monitor/actor_names.py` |
| Clear-web catalogue eligibility and mirror reconciliation | `backend/ransom_monitor/collectors.py` |
| Exclusion of recovery, negotiation, support, and decryptor portals | `backend/ransom_monitor/dls_policy.py` |
| Actor-specific readiness, navigation labels, selectors, waits, and bounded pagination | `CAPTURE_SITE_PROFILES` in `backend/ransom_monitor/capture_worker.py` |
| Shared scroll, exact-label click, ARIA-tab, load-more, and same-origin next-page behavior | `capture_interactive_evidence()` in `backend/ransom_monitor/capture_worker.py` |
| Local OCR, continuity anchors, duplicate detection, and change analysis | `backend/ransom_monitor/capture_analysis.py` |
| Capture regression and OPSEC tests | `backend/tests/test_capture_worker.py` and `backend/tests/test_capture_analysis.py` |
| Evidence-led actor behavior register | `docs/dls-capture-audit.md` |

Before adding or changing a profile, review retained screenshots, DOM/OCR text,
and capture-job metadata. Record the observed presentation in
`docs/dls-capture-audit.md`, then add the smallest profile needed. Supported
profile controls cover bounded retry timing, readiness text, exact navigation
labels, victim-card/table selectors, entry-screen text, pagination limits, and
an optional stop-before heading. A selector is a readiness assertion; it must
not be used to click arbitrary elements.

Every change must preserve the global invariants: loopback Tor SOCKS preflight,
one exact onion origin, `GET`/`HEAD` only, ephemeral browser contexts, denied
permissions, blocked downloads/popups/dialogs/WebSockets, and no forms, typing,
authentication, messaging, leak downloads, cross-origin navigation, or
anti-bot bypass. If retained evidence does not establish a safe interaction,
the correct behavior is to fail closed and report the presentation as not
capture-ready.

Run the focused checks before testing inside Kali:

```bash
PYTHONPATH=backend .venv/bin/python -m pytest \
  backend/tests/test_capture_worker.py backend/tests/test_capture_analysis.py
.venv/bin/ruff check backend/ransom_monitor/capture_worker.py \
  backend/ransom_monitor/dls_policy.py backend/tests/test_capture_worker.py
```

Restart `extortsignal-capture` after deploying a profile change; the worker
loads `CAPTURE_SITE_PROFILES` at process start. Test only an explicitly
allowlisted target in Active mode and inspect the evidence pages, extracted
text, interaction audit, OPSEC result, coverage status, and continuity result
in the Direct sites GUI before accepting the change.

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
- Direct-site screenshot execution requires `setup-kali.sh --prepare-capture` inside an isolated Kali VM. The separate worker authenticates to the localhost control plane, and Passive/Off mode is checked atomically before each queued job is reserved. Successful evidence is stored privately as review-sized `data/captures/THREAT-ACTOR/YYYY-MM-DD_HH-MM-SS_TZ_pNNN.png` pages with a same-capture `.txt` DOM/OCR record. The GUI provides a page-by-page viewer instead of creating one extremely tall PNG. OCR and text comparisons are local; extracted DLS text is not sent to a cloud AI provider.
- Email drafts require analyst approval; the platform does not automatically send individual client notifications.
- AI enrichment quality depends on the configured provider and available public context.
- GUI-entered credentials use a permission-restricted local file, not an operating-system keychain.
- Source APIs can change without notice; source health exposes failures without stopping the application.

## Public data sources and attribution

ExtortSignal credits RansomFeed, RansomLook, and Ransomware.live on retained
observations and uses clear-web catalogue metadata from RansomLook and
Ransomware.live to reconcile current public DLS mirrors. Catalogue collection
does not open the returned onion hosts. See [DATA_SOURCES.md](DATA_SOURCES.md)
for source roles, licences, reuse limitations, and attribution links.

## Privacy and public-release packaging

Runtime data is sensitive and intentionally excluded from version control. The
`data/` directory can contain client profiles, alerts, raw observations, saved
AI/SMTP credentials, and enrichment results. Never attach it to an issue or a
release archive. Local `.env` files must also remain private.

Before making a repository public, review the cleanup plan and then sanitize
the local runtime. This intentionally keeps public CTI observations while
removing clients, alerts, drafts, analyst feedback, email recipients, focus
regions, AI analysis/profile-refresh history, queued or completed AI/capture
jobs, active DLS allowlists, synthetic demo rows, custom runtime settings and,
when requested, locally saved or `.env` AI/SMTP credentials. The capture-worker
token is retained so the isolated worker remains paired with the local API:

```bash
python3 scripts/sanitize-public-release.py
python3 scripts/sanitize-public-release.py --apply --clear-secrets
python3 scripts/public-release-audit.py
```

The first command is a dry run. The second is irreversible; keep any required
encrypted backup outside the repository. The final audit checks candidate Git
files for runtime data, personal paths and common credential formats, then
checks the local database for private rows, unsafe permissions, referential
integrity, duplicate fingerprints and missing archived evidence.

To reset only job/AI history, runtime settings, DLS allowlists, and AI/SMTP
credentials while retaining clients, alerts, drafts, feedback, and sample
records, use the narrower operator-maintenance mode:

```bash
python3 scripts/sanitize-public-release.py --apply --clear-secrets \
  --keep-operator-records
```

Create a clean source archive with:

```bash
./scripts/package-release.sh
```

Commit the reviewed source changes so the worktree is clean, then create the
archive. It excludes runtime data, credentials, virtual environments,
dependencies, build output, caches, and Git metadata. Packaging refuses a dirty
worktree, archives the committed `HEAD`, and writes a matching `.sha256` file.
Review `RELEASE_CHECKLIST.md` before publishing.

## Contributing and license

ExtortSignal is available under the [Apache License 2.0](LICENSE). Contributions
must stay within the defensive safety boundary in [CONTRIBUTING.md](CONTRIBUTING.md),
and security reports should follow [SECURITY.md](SECURITY.md).

## Repository quality checks

GitHub Actions runs the Python test suite on Python 3.11 and 3.12, Ruff static
and security analysis, Python and npm dependency audits, frontend type-checking
and production builds, shell syntax checks, and release-archive hygiene checks.
Dependency Review blocks newly introduced high-severity dependencies when the
repository is public or GitHub Code Security is licensed, while Dependabot
proposes weekly Python, npm, and Actions updates. Set the
`DEPENDENCY_REVIEW_PRIVATE_ENABLED=true` repository variable to enable it for a
licensed private repository.

CodeQL configuration is retained for public repositories and private
repositories with GitHub Code Security. Because GitHub does not permit CodeQL
on an unlicensed private repository, it is gated behind repository visibility
or the `CODEQL_PRIVATE_ENABLED=true` repository variable.

### Optional Snyk scanning

The dedicated Snyk workflow runs Snyk Open Source tests for the Python and
frontend dependency trees. Add a repository Actions secret named `SNYK_TOKEN`,
then run the **Snyk** workflow manually or push a change. High- and
critical-severity fixable findings fail the workflow and its dedicated badge.
The workflow also fails clearly if the credential is removed.

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
