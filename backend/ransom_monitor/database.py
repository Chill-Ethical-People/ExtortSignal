from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .actor_names import canonical_actor_name
from .source_metadata import normalize_leak_size


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS clients (
    id TEXT PRIMARY KEY,
    canonical_name TEXT NOT NULL,
    primary_domain TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    country TEXT NOT NULL DEFAULT '',
    industry TEXT NOT NULL DEFAULT '',
    priority TEXT NOT NULL DEFAULT 'standard',
    aliases_json TEXT NOT NULL DEFAULT '[]',
    countries_json TEXT NOT NULL DEFAULT '[]',
    cities_json TEXT NOT NULL DEFAULT '[]',
    industries_json TEXT NOT NULL DEFAULT '[]',
    related_entities_json TEXT NOT NULL DEFAULT '[]',
    keywords_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_domain ON clients(primary_domain);

CREATE TABLE IF NOT EXISTS claims (
    id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL,
    source_record_id TEXT NOT NULL,
    source_url TEXT NOT NULL DEFAULT '',
    threat_actor TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    published_at TEXT,
    discovered_at TEXT,
    attack_date TEXT,
    received_at TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    country TEXT NOT NULL DEFAULT '',
    industry TEXT NOT NULL DEFAULT '',
    domains_json TEXT NOT NULL DEFAULT '[]',
    raw_path TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'alleged',
    publication_status TEXT NOT NULL DEFAULT 'claimed',
    leak_size TEXT NOT NULL DEFAULT '',
    leak_size_bytes INTEGER,
    leak_size_source TEXT NOT NULL DEFAULT '',
    source_screenshot_url TEXT NOT NULL DEFAULT '',
    source_tags_json TEXT NOT NULL DEFAULT '[]',
    detail_checked_at TEXT,
    detail_status TEXT NOT NULL DEFAULT 'not_checked',
    ai_industry TEXT NOT NULL DEFAULT '',
    ai_country TEXT NOT NULL DEFAULT '',
    ai_description TEXT NOT NULL DEFAULT '',
    ai_organization_type TEXT NOT NULL DEFAULT '',
    ai_rationale TEXT NOT NULL DEFAULT '',
    ai_sources_json TEXT NOT NULL DEFAULT '[]',
    ai_past_incidents_json TEXT NOT NULL DEFAULT '[]',
    ai_osint_status TEXT NOT NULL DEFAULT 'not_checked',
    ai_osint_checked_at TEXT,
    ai_confidence INTEGER,
    ai_provider TEXT NOT NULL DEFAULT '',
    ai_enriched_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_claims_received ON claims(received_at DESC);
CREATE INDEX IF NOT EXISTS idx_claims_actor_received ON claims(threat_actor COLLATE NOCASE, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_claims_country_received ON claims(country COLLATE NOCASE, received_at DESC);

CREATE TABLE IF NOT EXISTS source_observations (
    id TEXT PRIMARY KEY,
    observation_key TEXT NOT NULL UNIQUE,
    claim_id TEXT NOT NULL REFERENCES claims(id),
    source TEXT NOT NULL,
    source_record_id TEXT NOT NULL,
    source_url TEXT NOT NULL DEFAULT '',
    published_at TEXT,
    received_at TEXT NOT NULL,
    raw_path TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    parser_version TEXT NOT NULL DEFAULT 'extortsignal-0.1',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_source_observations_claim
ON source_observations(claim_id, received_at DESC);

CREATE INDEX IF NOT EXISTS idx_source_observations_source
ON source_observations(source, received_at DESC);

CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    entity_key TEXT NOT NULL UNIQUE,
    canonical_name TEXT NOT NULL,
    normalized_name TEXT NOT NULL,
    primary_domain TEXT NOT NULL DEFAULT '',
    aliases_json TEXT NOT NULL DEFAULT '[]',
    domains_json TEXT NOT NULL DEFAULT '[]',
    description TEXT NOT NULL DEFAULT '',
    industry TEXT NOT NULL DEFAULT '',
    country TEXT NOT NULL DEFAULT '',
    organization_type TEXT NOT NULL DEFAULT '',
    confidence INTEGER NOT NULL DEFAULT 0,
    provenance_json TEXT NOT NULL DEFAULT '[]',
    analyst_reviewed INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_organizations_name
ON organizations(normalized_name);

CREATE INDEX IF NOT EXISTS idx_organizations_domain
ON organizations(primary_domain COLLATE NOCASE);

CREATE TABLE IF NOT EXISTS claim_organizations (
    claim_id TEXT PRIMARY KEY REFERENCES claims(id),
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    match_basis TEXT NOT NULL,
    confidence INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_claim_organizations_org
ON claim_organizations(organization_id);

CREATE TABLE IF NOT EXISTS organization_field_evidence (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    claim_id TEXT NOT NULL REFERENCES claims(id),
    field_name TEXT NOT NULL,
    field_value TEXT NOT NULL,
    source_kind TEXT NOT NULL,
    source_refs_json TEXT NOT NULL DEFAULT '[]',
    confidence INTEGER NOT NULL DEFAULT 0,
    observed_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_organization_evidence_org
ON organization_field_evidence(organization_id, field_name, created_at DESC);

CREATE TABLE IF NOT EXISTS threat_actor_cti_profiles (
    attack_id TEXT PRIMARY KEY,
    canonical_name TEXT NOT NULL,
    aliases_json TEXT NOT NULL DEFAULT '[]',
    profile_json TEXT NOT NULL,
    source TEXT NOT NULL,
    source_version TEXT NOT NULL DEFAULT '',
    refreshed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cti_actor_name
ON threat_actor_cti_profiles(canonical_name COLLATE NOCASE);

CREATE TABLE IF NOT EXISTS threat_actor_profile_refreshes (
    actor TEXT PRIMARY KEY COLLATE NOCASE,
    profile_json TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    generated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_actor_osint_evidence (
    id TEXT PRIMARY KEY,
    actor TEXT NOT NULL COLLATE NOCASE,
    source_name TEXT NOT NULL,
    source_tier TEXT NOT NULL,
    title TEXT NOT NULL,
    source_url TEXT NOT NULL,
    published_at TEXT,
    retrieved_at TEXT NOT NULL,
    excerpt TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    content_sha256 TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_actor_osint_actor_retrieved
ON threat_actor_osint_evidence(actor, retrieved_at DESC);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    claim_id TEXT NOT NULL REFERENCES claims(id),
    client_id TEXT NOT NULL REFERENCES clients(id),
    severity TEXT NOT NULL,
    score INTEGER NOT NULL,
    reason TEXT NOT NULL,
    evidence TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new',
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT,
    notified_at TEXT,
    UNIQUE(claim_id, client_id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, created_at DESC);

CREATE TABLE IF NOT EXISTS notification_drafts (
    id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL REFERENCES alerts(id),
    client_id TEXT NOT NULL REFERENCES clients(id),
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    scenario TEXT NOT NULL DEFAULT 'contextual_match',
    generated_by TEXT NOT NULL DEFAULT 'standard_template',
    client_name_sanitized INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notification_drafts_alert
ON notification_drafts(alert_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_notification_drafts_client
ON notification_drafts(client_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS alert_ai_assessments (
    id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL REFERENCES alerts(id),
    claim_id TEXT NOT NULL REFERENCES claims(id),
    assessment_json TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    generated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alert_ai_assessments_alert
ON alert_ai_assessments(alert_id, generated_at DESC);

CREATE TABLE IF NOT EXISTS analyst_feedback (
    id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL UNIQUE REFERENCES alerts(id),
    claim_id TEXT NOT NULL REFERENCES claims(id),
    client_id TEXT NOT NULL REFERENCES clients(id),
    disposition TEXT NOT NULL DEFAULT 'false_positive',
    category TEXT NOT NULL DEFAULT 'unrelated_organization',
    analyst_note TEXT NOT NULL DEFAULT '',
    document_text TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    claim_snapshot_json TEXT NOT NULL DEFAULT '{}',
    client_snapshot_json TEXT NOT NULL DEFAULT '{}',
    match_snapshot_json TEXT NOT NULL DEFAULT '{}',
    embedding_model TEXT NOT NULL DEFAULT '',
    embedding_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_analyst_feedback_disposition
ON analyst_feedback(disposition, updated_at DESC);

CREATE TABLE IF NOT EXISTS source_health (
    source TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'not_checked',
    last_checked_at TEXT,
    last_success_at TEXT,
    latest_record_at TEXT,
    records_received INTEGER NOT NULL DEFAULT 0,
    message TEXT NOT NULL DEFAULT 'Waiting for the first check',
    coverage_status TEXT NOT NULL DEFAULT 'not_checked',
    coverage_message TEXT NOT NULL DEFAULT '',
    coverage_checked_at TEXT,
    coverage_gaps_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS dls_targets (
    id TEXT PRIMARY KEY,
    group_name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    fqdn TEXT NOT NULL UNIQUE,
    location_type TEXT NOT NULL DEFAULT 'DLS',
    title TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    available INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL,
    capture_enabled INTEGER NOT NULL DEFAULT 0,
    first_seen_at TEXT NOT NULL,
    last_catalog_sync_at TEXT NOT NULL,
    last_capture_at TEXT,
    last_capture_status TEXT NOT NULL DEFAULT 'never'
);

CREATE INDEX IF NOT EXISTS idx_dls_targets_group ON dls_targets(group_name COLLATE NOCASE);

CREATE TABLE IF NOT EXISTS capture_jobs (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES dls_targets(id),
    status TEXT NOT NULL DEFAULT 'queued',
    requested_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    error TEXT NOT NULL DEFAULT '',
    screenshot_path TEXT NOT NULL DEFAULT '',
    screenshot_paths_json TEXT NOT NULL DEFAULT '[]',
    segment_count INTEGER NOT NULL DEFAULT 0,
    css_blur_element_count INTEGER NOT NULL DEFAULT 0,
    text_path TEXT NOT NULL DEFAULT '',
    content_sha256 TEXT NOT NULL DEFAULT '',
    scroll_count INTEGER NOT NULL DEFAULT 0,
    page_height INTEGER NOT NULL DEFAULT 0,
    capture_truncated INTEGER NOT NULL DEFAULT 0,
    coverage_status TEXT NOT NULL DEFAULT 'not_measured',
    anchor_lines_json TEXT NOT NULL DEFAULT '[]',
    continuity_status TEXT NOT NULL DEFAULT 'no_baseline',
    continuity_anchor TEXT NOT NULL DEFAULT '',
    continuity_page INTEGER NOT NULL DEFAULT 0,
    pagination_detected INTEGER NOT NULL DEFAULT 0,
    more_content_suspected INTEGER NOT NULL DEFAULT 0,
    text_sha256 TEXT NOT NULL DEFAULT '',
    extraction_method TEXT NOT NULL DEFAULT '',
    duplicate_of_job_id TEXT NOT NULL DEFAULT '',
    detected_statuses_json TEXT NOT NULL DEFAULT '[]',
    status_changed INTEGER NOT NULL DEFAULT 0,
    added_line_count INTEGER NOT NULL DEFAULT 0,
    removed_line_count INTEGER NOT NULL DEFAULT 0,
    opsec_status TEXT NOT NULL DEFAULT 'not_checked',
    tor_preflight_passed INTEGER NOT NULL DEFAULT 0,
    blocked_request_count INTEGER NOT NULL DEFAULT 0,
    blocked_popup_count INTEGER NOT NULL DEFAULT 0,
    blocked_download_count INTEGER NOT NULL DEFAULT 0,
    opsec_controls_json TEXT NOT NULL DEFAULT '[]'
    ,alert_id TEXT NOT NULL DEFAULT ''
    ,claim_id TEXT NOT NULL DEFAULT ''
    ,victim_name TEXT NOT NULL DEFAULT ''
    ,capture_scope TEXT NOT NULL DEFAULT 'site_overview'
    ,victim_match_found INTEGER NOT NULL DEFAULT 0
    ,evidence_readiness TEXT NOT NULL DEFAULT 'not_assessed'
    ,readiness_reason TEXT NOT NULL DEFAULT ''
    ,victim_candidates_json TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_capture_jobs_status ON capture_jobs(status, requested_at);

CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS actor_ai_analysis (
    actor TEXT PRIMARY KEY COLLATE NOCASE,
    analysis_json TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    generated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS intelligence_ai_analysis_history (
    id TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    scope_value TEXT NOT NULL DEFAULT '',
    period_days INTEGER NOT NULL,
    label TEXT NOT NULL,
    context_json TEXT NOT NULL,
    analysis_json TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    generated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_intelligence_ai_history_generated
ON intelligence_ai_analysis_history(generated_at DESC);

CREATE TABLE IF NOT EXISTS ai_jobs (
    id TEXT PRIMARY KEY,
    job_type TEXT NOT NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    payload_json TEXT NOT NULL DEFAULT '{}',
    result_json TEXT,
    error TEXT NOT NULL DEFAULT '',
    destination TEXT NOT NULL DEFAULT 'home',
    target_id TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    seen_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_ai_jobs_status_created
ON ai_jobs(status, created_at);
"""


class Database:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # A manual/non-systemd launch does not inherit the Kali service's
        # UMask=0077. Pre-create the database privately so client profiles,
        # alerts, credentials metadata, and WAL contents never briefly inherit
        # a typical 0644 shell umask.
        if not self.path.exists():
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
        self._harden_permissions()

    def _harden_permissions(self) -> None:
        for candidate in (
            self.path,
            Path(f"{self.path}-wal"),
            Path(f"{self.path}-shm"),
        ):
            if candidate.exists():
                candidate.chmod(0o600)

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=15.0)
        self._harden_permissions()
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=15000")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.execute("PRAGMA temp_store=MEMORY")
        connection.execute("PRAGMA cache_size=-32768")
        connection.execute("PRAGMA mmap_size=268435456")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()
            self._harden_permissions()

    def initialize(self) -> None:
        with self.connection() as connection:
            connection.executescript(SCHEMA)
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(clients)")}
            migrations = {
                "countries_json": "TEXT NOT NULL DEFAULT '[]'",
                "cities_json": "TEXT NOT NULL DEFAULT '[]'",
                "industries_json": "TEXT NOT NULL DEFAULT '[]'",
                "related_entities_json": "TEXT NOT NULL DEFAULT '[]'",
                "keywords_json": "TEXT NOT NULL DEFAULT '[]'",
                "description": "TEXT NOT NULL DEFAULT ''",
            }
            for name, definition in migrations.items():
                if name not in columns:
                    connection.execute(f"ALTER TABLE clients ADD COLUMN {name} {definition}")
            claim_columns = {row["name"] for row in connection.execute("PRAGMA table_info(claims)")}
            claim_migrations = {
                "published_at": "TEXT",
                "attack_date": "TEXT",
                "observed_at": "TEXT",
                "publication_status": "TEXT NOT NULL DEFAULT 'claimed'",
                "leak_size": "TEXT NOT NULL DEFAULT ''",
                "leak_size_bytes": "INTEGER",
                "leak_size_source": "TEXT NOT NULL DEFAULT ''",
                "source_screenshot_url": "TEXT NOT NULL DEFAULT ''",
                "source_tags_json": "TEXT NOT NULL DEFAULT '[]'",
                "detail_checked_at": "TEXT",
                "detail_status": "TEXT NOT NULL DEFAULT 'not_checked'",
                "ai_industry": "TEXT NOT NULL DEFAULT ''",
                "ai_country": "TEXT NOT NULL DEFAULT ''",
                "ai_description": "TEXT NOT NULL DEFAULT ''",
                "ai_organization_type": "TEXT NOT NULL DEFAULT ''",
                "ai_rationale": "TEXT NOT NULL DEFAULT ''",
                "ai_sources_json": "TEXT NOT NULL DEFAULT '[]'",
                "ai_past_incidents_json": "TEXT NOT NULL DEFAULT '[]'",
                "ai_osint_status": "TEXT NOT NULL DEFAULT 'not_checked'",
                "ai_osint_checked_at": "TEXT",
                "ai_confidence": "INTEGER",
                "ai_provider": "TEXT NOT NULL DEFAULT ''",
                "ai_enriched_at": "TEXT",
            }
            for name, definition in claim_migrations.items():
                if name not in claim_columns:
                    connection.execute(f"ALTER TABLE claims ADD COLUMN {name} {definition}")
            legacy_sizes = connection.execute(
                "SELECT id, leak_size, leak_size_source FROM claims WHERE leak_size <> '' AND leak_size_bytes IS NULL"
            ).fetchall()
            for row in legacy_sizes:
                parsed = normalize_leak_size(
                    row["leak_size"], source=row["leak_size_source"] or "legacy:leak_size"
                )
                if parsed is not None:
                    connection.execute(
                        "UPDATE claims SET leak_size = ?, leak_size_bytes = ?, leak_size_source = ? WHERE id = ?",
                        (parsed.raw, parsed.bytes, parsed.source, row["id"]),
                    )
            connection.execute(
                "UPDATE claims SET published_at = discovered_at WHERE published_at IS NULL AND discovered_at IS NOT NULL"
            )
            connection.execute(
                "UPDATE claims SET observed_at = COALESCE(published_at, discovered_at, received_at) WHERE observed_at IS NULL OR observed_at = ''"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_claims_observed ON claims(observed_at DESC)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_claims_actor_observed ON claims(threat_actor COLLATE NOCASE, observed_at DESC)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_claims_country_observed ON claims(country COLLATE NOCASE, observed_at DESC)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_claims_industry_observed ON claims(industry COLLATE NOCASE, observed_at DESC)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_claims_source_observed ON claims(source, observed_at DESC)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_claims_publication_observed ON claims(publication_status, observed_at DESC)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_claims_leak_size_bytes ON claims(leak_size_bytes DESC)"
            )
            for row in connection.execute("SELECT DISTINCT threat_actor FROM claims"):
                canonical = canonical_actor_name(row["threat_actor"])
                if canonical != row["threat_actor"]:
                    connection.execute(
                        "UPDATE claims SET threat_actor = ? WHERE threat_actor = ?",
                        (canonical, row["threat_actor"]),
                    )
            for row in connection.execute("SELECT DISTINCT group_name FROM dls_targets"):
                canonical = canonical_actor_name(row["group_name"])
                if canonical != row["group_name"]:
                    connection.execute(
                        "UPDATE dls_targets SET group_name = ? WHERE group_name = ?",
                        (canonical, row["group_name"]),
                    )
            connection.execute(
                "UPDATE threat_actor_osint_evidence SET actor = ? WHERE actor = ?",
                ("Unknown", ""),
            )
            for row in connection.execute(
                "SELECT DISTINCT actor FROM threat_actor_osint_evidence"
            ).fetchall():
                canonical = canonical_actor_name(row["actor"])
                if canonical != row["actor"]:
                    connection.execute(
                        "UPDATE threat_actor_osint_evidence SET actor = ? WHERE actor = ?",
                        (canonical, row["actor"]),
                    )

            # These tables use the actor label as a case-insensitive primary key.
            # Merge older alias rows into the preferred name while retaining the
            # newest generated result and keeping the actor embedded in JSON aligned.
            for table, payload_column in (
                ("threat_actor_profile_refreshes", "profile_json"),
                ("actor_ai_analysis", "analysis_json"),
            ):
                # Both identifiers come exclusively from the fixed tuple above;
                # every runtime value remains a bound parameter.
                rows = connection.execute(
                    f"SELECT actor, {payload_column}, provider, model, generated_at FROM {table}"  # noqa: S608
                ).fetchall()
                for row in rows:
                    canonical = canonical_actor_name(row["actor"])
                    if canonical == row["actor"]:
                        continue
                    try:
                        payload = json.loads(row[payload_column])
                    except (TypeError, ValueError):
                        payload = {}
                    payload["actor"] = canonical
                    payload_json = json.dumps(payload)
                    existing = connection.execute(
                        f"SELECT actor, generated_at FROM {table} WHERE actor = ? COLLATE NOCASE",  # noqa: S608
                        (canonical,),
                    ).fetchone()
                    if existing is not None and existing["actor"] != row["actor"]:
                        if row["generated_at"] >= existing["generated_at"]:
                            connection.execute(
                                f"UPDATE {table} SET {payload_column} = ?, provider = ?, model = ?, generated_at = ? WHERE actor = ? COLLATE NOCASE",  # noqa: S608
                                (
                                    payload_json,
                                    row["provider"],
                                    row["model"],
                                    row["generated_at"],
                                    canonical,
                                ),
                            )
                        connection.execute(
                            f"DELETE FROM {table} WHERE actor = ?",  # noqa: S608
                            (row["actor"],),
                        )
                    else:
                        connection.execute(
                            f"UPDATE {table} SET actor = ?, {payload_column} = ? WHERE actor = ?",  # noqa: S608
                            (canonical, payload_json, row["actor"]),
                        )
            connection.execute(
                """
                INSERT OR IGNORE INTO source_observations(
                    id, observation_key, claim_id, source, source_record_id,
                    source_url, published_at, received_at, raw_path,
                    content_sha256, parser_version, created_at
                )
                SELECT id, 'legacy:' || fingerprint, id, source, source_record_id,
                       source_url, published_at, received_at, raw_path,
                       '', 'legacy-claim-row', received_at
                FROM claims
                WHERE raw_path <> ''
                """
            )
            alert_columns = {row["name"] for row in connection.execute("PRAGMA table_info(alerts)")}
            for name, definition in {
                "updated_at": "TEXT",
                "notified_at": "TEXT",
            }.items():
                if name not in alert_columns:
                    connection.execute(f"ALTER TABLE alerts ADD COLUMN {name} {definition}")
            connection.execute(
                "UPDATE alerts SET status = 'investigating' WHERE status = 'acknowledged'"
            )
            capture_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(capture_jobs)")
            }
            for name, definition in {
                "text_path": "TEXT NOT NULL DEFAULT ''",
                "screenshot_paths_json": "TEXT NOT NULL DEFAULT '[]'",
                "segment_count": "INTEGER NOT NULL DEFAULT 0",
                "css_blur_element_count": "INTEGER NOT NULL DEFAULT 0",
                "scroll_count": "INTEGER NOT NULL DEFAULT 0",
                "page_height": "INTEGER NOT NULL DEFAULT 0",
                "capture_truncated": "INTEGER NOT NULL DEFAULT 0",
                "coverage_status": "TEXT NOT NULL DEFAULT 'not_measured'",
                "anchor_lines_json": "TEXT NOT NULL DEFAULT '[]'",
                "continuity_status": "TEXT NOT NULL DEFAULT 'no_baseline'",
                "continuity_anchor": "TEXT NOT NULL DEFAULT ''",
                "continuity_page": "INTEGER NOT NULL DEFAULT 0",
                "pagination_detected": "INTEGER NOT NULL DEFAULT 0",
                "more_content_suspected": "INTEGER NOT NULL DEFAULT 0",
                "text_sha256": "TEXT NOT NULL DEFAULT ''",
                "extraction_method": "TEXT NOT NULL DEFAULT ''",
                "duplicate_of_job_id": "TEXT NOT NULL DEFAULT ''",
                "detected_statuses_json": "TEXT NOT NULL DEFAULT '[]'",
                "status_changed": "INTEGER NOT NULL DEFAULT 0",
                "added_line_count": "INTEGER NOT NULL DEFAULT 0",
                "removed_line_count": "INTEGER NOT NULL DEFAULT 0",
                "opsec_status": "TEXT NOT NULL DEFAULT 'not_checked'",
                "tor_preflight_passed": "INTEGER NOT NULL DEFAULT 0",
                "blocked_request_count": "INTEGER NOT NULL DEFAULT 0",
                "blocked_popup_count": "INTEGER NOT NULL DEFAULT 0",
                "blocked_download_count": "INTEGER NOT NULL DEFAULT 0",
                "opsec_controls_json": "TEXT NOT NULL DEFAULT '[]'",
                "alert_id": "TEXT NOT NULL DEFAULT ''",
                "claim_id": "TEXT NOT NULL DEFAULT ''",
                "victim_name": "TEXT NOT NULL DEFAULT ''",
                "capture_scope": "TEXT NOT NULL DEFAULT 'site_overview'",
                "victim_match_found": "INTEGER NOT NULL DEFAULT 0",
                "evidence_readiness": "TEXT NOT NULL DEFAULT 'not_assessed'",
                "readiness_reason": "TEXT NOT NULL DEFAULT ''",
                "victim_candidates_json": "TEXT NOT NULL DEFAULT '[]'",
            }.items():
                if name not in capture_columns:
                    connection.execute(f"ALTER TABLE capture_jobs ADD COLUMN {name} {definition}")
            connection.execute(
                """UPDATE capture_jobs
                   SET evidence_readiness = 'not_ready',
                       readiness_reason = CASE
                           WHEN readiness_reason = '' THEN error
                           ELSE readiness_reason
                       END,
                       victim_candidates_json = '[]'
                   WHERE status = 'failed'
                     AND evidence_readiness = 'not_assessed'"""
            )
            connection.execute(
                """CREATE INDEX IF NOT EXISTS idx_capture_jobs_readiness
                   ON capture_jobs(evidence_readiness, completed_at DESC)"""
            )
            source_health_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(source_health)")
            }
            for name, definition in {
                "coverage_status": "TEXT NOT NULL DEFAULT 'not_checked'",
                "coverage_message": "TEXT NOT NULL DEFAULT ''",
                "coverage_checked_at": "TEXT",
                "coverage_gaps_json": "TEXT NOT NULL DEFAULT '[]'",
            }.items():
                if name not in source_health_columns:
                    connection.execute(
                        f"ALTER TABLE source_health ADD COLUMN {name} {definition}"
                    )
            for row in connection.execute(
                "SELECT id, country, industry, countries_json, industries_json FROM clients"
            ):
                countries = decode_json(row["countries_json"])
                industries = decode_json(row["industries_json"])
                if not countries and row["country"]:
                    countries = [row["country"]]
                if not industries and row["industry"]:
                    industries = [row["industry"]]
                connection.execute(
                    "UPDATE clients SET countries_json = ?, industries_json = ? WHERE id = ?",
                    (json.dumps(countries), json.dumps(industries), row["id"]),
                )
            for source in (
                "ransomlook",
                "ransomfeed",
                "ransomware_live",
                "dls_catalog",
            ):
                connection.execute(
                    "INSERT OR IGNORE INTO source_health(source) VALUES (?)", (source,)
                )
            defaults = {
                "operating_mode": "passive",
                "scheduling_enabled": "true",
                "public_interval_minutes": "2",
                "catalog_interval_hours": "6",
                "active_interval_minutes": "30",
                "capture_max_scrolls": "60",
                "capture_stable_passes": "3",
                "capture_scroll_delay_ms": "1000",
                "capture_max_page_height": "50000",
                "capture_segment_height": "1400",
                "ai_enabled": "false",
                "ai_provider": "ollama",
                "ai_model": "qwen3:4b",
                "ai_base_url": "http://127.0.0.1:11434/v1",
                "focus_regions": "[]",
                "victim_digest_enabled": "false",
                "victim_digest_interval_hours": "24",
                "victim_digest_recipients": "[]",
                "smtp_host": "",
                "smtp_port": "587",
                "smtp_security": "starttls",
                "smtp_username": "",
                "smtp_from": "",
                "last_public_run_at": "",
                "last_catalog_run_at": "",
                "last_active_run_at": "",
                "last_capture_worker_heartbeat_at": "",
                "last_victim_digest_at": "",
                "last_victim_digest_run_at": "",
                "last_history_backfill_at": "",
            }
            now = iso(datetime.now(timezone.utc))
            for key, value in defaults.items():
                connection.execute(
                    "INSERT OR IGNORE INTO app_settings(key, value, updated_at) VALUES (?, ?, ?)",
                    (key, value, now),
                )
            connection.execute("PRAGMA optimize")


def iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def decode_json(value: str | None) -> list:
    if not value:
        return []
    try:
        decoded = json.loads(value)
        return decoded if isinstance(decoded, list) else []
    except json.JSONDecodeError:
        return []
