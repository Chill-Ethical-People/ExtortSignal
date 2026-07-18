from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator


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
    received_at TEXT NOT NULL,
    country TEXT NOT NULL DEFAULT '',
    industry TEXT NOT NULL DEFAULT '',
    domains_json TEXT NOT NULL DEFAULT '[]',
    raw_path TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'alleged',
    publication_status TEXT NOT NULL DEFAULT 'claimed',
    leak_size TEXT NOT NULL DEFAULT '',
    ai_industry TEXT NOT NULL DEFAULT '',
    ai_country TEXT NOT NULL DEFAULT '',
    ai_description TEXT NOT NULL DEFAULT '',
    ai_organization_type TEXT NOT NULL DEFAULT '',
    ai_rationale TEXT NOT NULL DEFAULT '',
    ai_sources_json TEXT NOT NULL DEFAULT '[]',
    ai_confidence INTEGER,
    ai_provider TEXT NOT NULL DEFAULT '',
    ai_enriched_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_claims_received ON claims(received_at DESC);

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

CREATE TABLE IF NOT EXISTS source_health (
    source TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'not_checked',
    last_checked_at TEXT,
    last_success_at TEXT,
    latest_record_at TEXT,
    records_received INTEGER NOT NULL DEFAULT 0,
    message TEXT NOT NULL DEFAULT 'Waiting for the first check'
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
    text_path TEXT NOT NULL DEFAULT '',
    content_sha256 TEXT NOT NULL DEFAULT ''
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
"""


class Database:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connection() as connection:
            connection.executescript(SCHEMA)
            columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(clients)")
            }
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
                    connection.execute(
                        f"ALTER TABLE clients ADD COLUMN {name} {definition}"
                    )
            claim_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(claims)")
            }
            claim_migrations = {
                "published_at": "TEXT",
                "publication_status": "TEXT NOT NULL DEFAULT 'claimed'",
                "leak_size": "TEXT NOT NULL DEFAULT ''",
                "ai_industry": "TEXT NOT NULL DEFAULT ''",
                "ai_country": "TEXT NOT NULL DEFAULT ''",
                "ai_description": "TEXT NOT NULL DEFAULT ''",
                "ai_organization_type": "TEXT NOT NULL DEFAULT ''",
                "ai_rationale": "TEXT NOT NULL DEFAULT ''",
                "ai_sources_json": "TEXT NOT NULL DEFAULT '[]'",
                "ai_confidence": "INTEGER",
                "ai_provider": "TEXT NOT NULL DEFAULT ''",
                "ai_enriched_at": "TEXT",
            }
            for name, definition in claim_migrations.items():
                if name not in claim_columns:
                    connection.execute(
                        f"ALTER TABLE claims ADD COLUMN {name} {definition}"
                    )
            connection.execute(
                "UPDATE claims SET published_at = discovered_at WHERE published_at IS NULL AND discovered_at IS NOT NULL"
            )
            alert_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(alerts)")
            }
            for name, definition in {
                "updated_at": "TEXT",
                "notified_at": "TEXT",
            }.items():
                if name not in alert_columns:
                    connection.execute(f"ALTER TABLE alerts ADD COLUMN {name} {definition}")
            connection.execute(
                "UPDATE alerts SET status = 'investigating' WHERE status = 'acknowledged'"
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
                "last_victim_digest_at": "",
                "last_victim_digest_run_at": "",
            }
            now = iso(datetime.now(timezone.utc))
            for key, value in defaults.items():
                connection.execute(
                    "INSERT OR IGNORE INTO app_settings(key, value, updated_at) VALUES (?, ?, ?)",
                    (key, value, now),
                )


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
