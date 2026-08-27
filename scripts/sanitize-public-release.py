#!/usr/bin/env python3
"""Remove private operator state while retaining public CTI observations."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sqlite3
import stat
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA_DIR = ROOT / "data"
DEFAULT_DATABASE = DEFAULT_DATA_DIR / "ransom-monitor.sqlite3"

PRIVATE_TABLES = (
    "clients",
    "alerts",
    "notification_drafts",
    "alert_ai_assessments",
    "analyst_feedback",
    "threat_actor_profile_refreshes",
    "actor_ai_analysis",
    "intelligence_ai_analysis_history",
    "ai_jobs",
    "capture_jobs",
)

JOB_AND_AI_TABLES = (
    "threat_actor_profile_refreshes",
    "actor_ai_analysis",
    "intelligence_ai_analysis_history",
    "ai_jobs",
    "capture_jobs",
)

STANDARD_SETTINGS = {
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

SECRET_ENV_KEY = re.compile(r"^[A-Z][A-Z0-9_]*(?:API_KEY|SMTP_PASSWORD)$")


def tables(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }


def count(connection: sqlite3.Connection, table: str) -> int:
    # Table is selected from the fixed PRIVATE_TABLES tuple or discovered schema.
    return int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def remove_private_files(paths: set[str], data_dir: Path) -> int:
    removed = 0
    root = data_dir.resolve()
    for value in paths:
        if not value:
            continue
        candidate = Path(value).expanduser()
        try:
            resolved = candidate.resolve()
            resolved.relative_to(root)
        except (OSError, ValueError):
            continue
        if resolved.is_file():
            resolved.unlink()
            removed += 1
    sample_dir = root / "raw" / "sample"
    if sample_dir.exists():
        shutil.rmtree(sample_dir)
    return removed


def clear_environment_credentials(env_file: Path) -> int:
    """Blank AI/SMTP secrets without changing the capture-worker identity."""
    if not env_file.exists():
        return 0
    original_mode = stat.S_IMODE(env_file.stat().st_mode)
    cleared = 0
    output: list[str] = []
    for line in env_file.read_text(encoding="utf-8").splitlines(keepends=True):
        ending = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
        content = line[: -len(ending)] if ending else line
        leading = content[: len(content) - len(content.lstrip())]
        assignment = content.strip()
        export_prefix = ""
        if assignment.startswith("export "):
            export_prefix = "export "
            assignment = assignment[7:].lstrip()
        key, separator, value = assignment.partition("=")
        key = key.strip()
        if separator and SECRET_ENV_KEY.fullmatch(key):
            if value.strip():
                cleared += 1
            output.append(f"{leading}{export_prefix}{key}={ending}")
        else:
            output.append(line)
    temporary = env_file.with_name(f".{env_file.name}.sanitize.tmp")
    temporary.write_text("".join(output), encoding="utf-8")
    temporary.chmod(original_mode)
    temporary.replace(env_file)
    return cleared


def sanitize(
    database: Path,
    data_dir: Path,
    clear_secrets: bool,
    env_file: Path | None = None,
    keep_operator_records: bool = False,
) -> dict[str, int]:
    connection = sqlite3.connect(database, timeout=30)
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=30000")
    connection.execute("PRAGMA secure_delete=ON")
    available = tables(connection)
    before = {
        table: count(connection, table)
        for table in PRIVATE_TABLES
        if table in available
    }
    sample_paths: set[str] = set()
    sample_org_ids: list[str] = []
    try:
        connection.execute("BEGIN IMMEDIATE")
        if not keep_operator_records and "claims" in available:
            if "source_observations" in available:
                sample_paths.update(
                    str(row[0] or "")
                    for row in connection.execute(
                        "SELECT raw_path FROM source_observations WHERE source = 'sample'"
                    )
                )
            sample_paths.update(
                str(row[0] or "")
                for row in connection.execute(
                    "SELECT raw_path FROM claims WHERE source = 'sample'"
                )
            )
            if "claim_organizations" in available:
                sample_org_ids = [
                    str(row[0])
                    for row in connection.execute(
                        """SELECT DISTINCT organization_id
                           FROM claim_organizations
                           WHERE claim_id IN (SELECT id FROM claims WHERE source = 'sample')"""
                    )
                ]

        operator_tables = (
            "notification_drafts",
            "alert_ai_assessments",
            "analyst_feedback",
            "alerts",
        )
        selected_tables = JOB_AND_AI_TABLES + (() if keep_operator_records else operator_tables)
        for table in selected_tables:
            if table in available:
                connection.execute(f"DELETE FROM {table}")

        if not keep_operator_records and "claims" in available:
            if "organization_field_evidence" in available:
                connection.execute(
                    """DELETE FROM organization_field_evidence
                       WHERE claim_id IN (SELECT id FROM claims WHERE source = 'sample')"""
                )
            if "claim_organizations" in available:
                connection.execute(
                    """DELETE FROM claim_organizations
                       WHERE claim_id IN (SELECT id FROM claims WHERE source = 'sample')"""
                )
            if "source_observations" in available:
                connection.execute(
                    """DELETE FROM source_observations
                       WHERE source = 'sample'
                          OR claim_id IN (SELECT id FROM claims WHERE source = 'sample')"""
                )
            connection.execute("DELETE FROM claims WHERE source = 'sample'")

        if (
            not keep_operator_records
            and "organizations" in available
            and "claim_organizations" in available
        ):
            for organization_id in sample_org_ids:
                connection.execute(
                    """DELETE FROM organizations
                       WHERE id = ?
                         AND NOT EXISTS (
                           SELECT 1 FROM claim_organizations
                           WHERE organization_id = organizations.id
                         )""",
                    (organization_id,),
                )

        if not keep_operator_records and "clients" in available:
            connection.execute("DELETE FROM clients")
        if "dls_targets" in available:
            connection.execute("UPDATE dls_targets SET capture_enabled = 0")
        if "app_settings" in available:
            now = datetime.now(timezone.utc).isoformat()
            # A release reset must not retain unknown or operator-specific keys.
            # Recreate the exact fresh-install settings set instead of updating a
            # privacy-sensitive subset in place.
            connection.execute("DELETE FROM app_settings")
            for key, value in STANDARD_SETTINGS.items():
                connection.execute(
                    "INSERT INTO app_settings(key, value, updated_at) VALUES (?, ?, ?)",
                    (key, value, now),
                )
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.execute("VACUUM")
        connection.execute("PRAGMA optimize")
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()

    removed_files = (
        0
        if keep_operator_records
        else remove_private_files(sample_paths, data_dir)
    )
    secrets_path = data_dir / "secrets.json"
    if clear_secrets and secrets_path.exists():
        secrets_path.unlink()
        removed_files += 1
    cleared_environment_credentials = (
        clear_environment_credentials(env_file)
        if clear_secrets and env_file is not None
        else 0
    )

    for suffix in ("", "-wal", "-shm"):
        candidate = Path(f"{database}{suffix}")
        if candidate.exists():
            candidate.chmod(0o600)

    check = sqlite3.connect(database)
    available = tables(check)
    after = {
        table: count(check, table)
        for table in PRIVATE_TABLES
        if table in available
    }
    check.close()
    result = {f"removed_{table}": before[table] - after[table] for table in before}
    result["removed_private_files"] = removed_files
    result["cleared_environment_credentials"] = cleared_environment_credentials
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Clear clients, client-derived alerts and drafts, region/email selections, "
            "queued AI/capture jobs, active DLS allowlists, and synthetic demo rows."
        )
    )
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument(
        "--env-file",
        type=Path,
        default=ROOT / ".env",
        help="Local environment file whose AI/SMTP credentials are blanked with --clear-secrets",
    )
    parser.add_argument("--apply", action="store_true", help="Perform the irreversible cleanup")
    parser.add_argument(
        "--clear-secrets",
        action="store_true",
        help="Also remove the ignored local data/secrets.json credential store",
    )
    parser.add_argument(
        "--keep-operator-records",
        action="store_true",
        help=(
            "Retain clients, alerts, drafts, feedback, and sample records while "
            "clearing job/AI history, settings, allowlists, and requested credentials"
        ),
    )
    args = parser.parse_args()
    database = args.database.expanduser().resolve()
    data_dir = args.data_dir.expanduser().resolve()
    env_file = args.env_file.expanduser().resolve()
    if not database.exists():
        print(f"No runtime database exists at {database}; nothing to sanitize.")
        return 0

    connection = sqlite3.connect(database)
    available = tables(connection)
    selected_tables = (
        JOB_AND_AI_TABLES
        if args.keep_operator_records
        else PRIVATE_TABLES
    )
    summary = {
        table: count(connection, table)
        for table in selected_tables
        if table in available
    }
    focus_count = 0
    if "app_settings" in available:
        row = connection.execute(
            "SELECT value FROM app_settings WHERE key = 'focus_regions'"
        ).fetchone()
        if row:
            try:
                value = json.loads(row[0])
                focus_count = len(value) if isinstance(value, list) else 0
            except (TypeError, ValueError):
                focus_count = 1
    connection.close()
    print("Private runtime rows selected for deletion:")
    for table, rows in summary.items():
        print(f"  {table}: {rows}")
    print(f"  focus-region selections: {focus_count}")
    print(
        "  synthetic sample claims and related evidence: "
        + ("retained" if args.keep_operator_records else "selected")
    )
    print("  active DLS capture allowlists: reset")
    print("  runtime configuration: reset to fresh-install defaults")
    if args.keep_operator_records:
        print("  clients, alerts, drafts, feedback, and sample records: retained")
    if args.clear_secrets:
        print(f"  saved and environment AI/SMTP credentials: clear ({env_file})")
    if not args.apply:
        print("Dry run only. Re-run with --apply after reviewing the summary.")
        return 0

    result = sanitize(
        database,
        data_dir,
        args.clear_secrets,
        env_file,
        keep_operator_records=args.keep_operator_records,
    )
    print("Sanitization complete:")
    for name, value in sorted(result.items()):
        print(f"  {name}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
