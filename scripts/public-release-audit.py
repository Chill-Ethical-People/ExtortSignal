#!/usr/bin/env python3
"""Fail closed when public-release source or runtime privacy checks fail."""

from __future__ import annotations

import argparse
import re
import sqlite3
import stat
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE = ROOT / "data" / "ransom-monitor.sqlite3"

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
PRIVATE_SETTINGS = {
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
}
DISALLOWED_NAMES = {".env", "secrets.json"}
DISALLOWED_SUFFIXES = {".db", ".pem", ".p12", ".pfx", ".sqlite", ".sqlite3"}
SECRET_PATTERNS = (
    re.compile("BEGIN " + "PRIVATE KEY"),
    re.compile("BEGIN " + "RSA PRIVATE KEY"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"AIza[0-9A-Za-z_-]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"),
    re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    re.compile(
        r"(?im)^(?:export\s+)?[A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD)="
        r"[^\s#'\"]{8,}\s*$"
    ),
    re.compile(r"https?://[^\s/:]+:[^\s/@]+@"),
)
PERSONAL_PATH_PATTERNS = (
    re.compile(r"/" + r"Users/[^/\s]+/"),
    re.compile(r"/" + r"home/(?!extortsignal(?:/|\s))[^/\s]+/"),
)


def candidate_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [ROOT / value.decode() for value in result.stdout.split(b"\0") if value]


def audit_repository(errors: list[str]) -> None:
    required_ignores = {
        "data/",
        ".venv/",
        "frontend/node_modules/",
        "release/",
        "*.sqlite3",
        ".env",
    }
    ignore_file = ROOT / ".gitignore"
    ignore_lines = {
        line.strip()
        for line in ignore_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    for rule in sorted(required_ignores - ignore_lines):
        errors.append(f".gitignore is missing required rule: {rule}")

    for path in candidate_files():
        relative = path.relative_to(ROOT)
        if "data" in relative.parts:
            errors.append(f"runtime data is a release candidate: {relative}")
            continue
        if path.name in DISALLOWED_NAMES and path.name != ".env.example":
            errors.append(f"private configuration is a release candidate: {relative}")
            continue
        if path.suffix.casefold() in DISALLOWED_SUFFIXES:
            errors.append(f"credential/database file is a release candidate: {relative}")
            continue
        try:
            payload = path.read_bytes()
        except OSError as error:
            errors.append(f"cannot inspect {relative}: {error}")
            continue
        if b"\0" in payload or len(payload) > 4_000_000:
            continue
        text = payload.decode("utf-8", errors="replace")
        # Explicit negative-test credentials are recognizable placeholders and
        # exercise URL credential rejection without representing a secret.
        scanned_text = text.replace("http://user:pass@127.0.0.1:8765", "")
        for pattern in SECRET_PATTERNS:
            if pattern.search(scanned_text):
                errors.append(f"possible committed credential in {relative}")
                break
        for pattern in PERSONAL_PATH_PATTERNS:
            if pattern.search(text):
                errors.append(f"personal absolute path in {relative}")
                break


def table_names(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }


def audit_runtime(database: Path, errors: list[str]) -> None:
    if not database.exists():
        return
    connection = sqlite3.connect(database)
    connection.execute("PRAGMA foreign_keys=ON")
    available = table_names(connection)
    quick_check = [str(row[0]) for row in connection.execute("PRAGMA quick_check")]
    if quick_check != ["ok"]:
        errors.append(f"SQLite quick_check failed: {quick_check}")
    foreign_key_errors = list(connection.execute("PRAGMA foreign_key_check"))
    if foreign_key_errors:
        errors.append(f"SQLite has {len(foreign_key_errors)} foreign-key violations")

    for table in PRIVATE_TABLES:
        if table not in available:
            continue
        rows = int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        if rows:
            errors.append(f"private runtime table {table} still contains {rows} row(s)")
    if "claims" in available:
        sample_rows = int(
            connection.execute("SELECT COUNT(*) FROM claims WHERE source = 'sample'").fetchone()[0]
        )
        if sample_rows:
            errors.append(f"synthetic sample workspace still contains {sample_rows} claim(s)")
        duplicates = int(
            connection.execute(
                """SELECT COUNT(*) FROM (
                     SELECT fingerprint FROM claims
                     GROUP BY fingerprint HAVING COUNT(*) > 1
                   )"""
            ).fetchone()[0]
        )
        if duplicates:
            errors.append(f"claims contain {duplicates} duplicate fingerprint group(s)")
    if "dls_targets" in available:
        active = int(
            connection.execute(
                "SELECT COUNT(*) FROM dls_targets WHERE capture_enabled <> 0"
            ).fetchone()[0]
        )
        if active:
            errors.append(f"{active} direct-site capture allowlist(s) remain enabled")
    if "app_settings" in available:
        settings = {
            str(row[0]): str(row[1])
            for row in connection.execute("SELECT key, value FROM app_settings")
        }
        for key, expected in PRIVATE_SETTINGS.items():
            if settings.get(key, expected) != expected:
                errors.append(f"private setting {key} has not been reset")

    missing_paths: list[str] = []
    if "source_observations" in available:
        for row in connection.execute(
            "SELECT DISTINCT raw_path FROM source_observations WHERE raw_path <> ''"
        ):
            path = Path(str(row[0]))
            if not path.is_file():
                missing_paths.append(str(path))
                if len(missing_paths) == 5:
                    break
    if missing_paths:
        errors.append(
            "archived source evidence is missing for at least: " + ", ".join(missing_paths)
        )
    connection.close()

    for suffix in ("", "-wal", "-shm"):
        path = Path(f"{database}{suffix}")
        if not path.exists():
            continue
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            errors.append(f"runtime database file is not private ({mode:04o}): {path}")
    secrets = database.parent / "secrets.json"
    if secrets.exists() and secrets.stat().st_size:
        errors.append("local credential store still exists and is non-empty")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument(
        "--repository-only",
        action="store_true",
        help="Skip ignored runtime-database checks for clean CI/release checkouts",
    )
    args = parser.parse_args()
    errors: list[str] = []
    audit_repository(errors)
    if not args.repository_only:
        audit_runtime(args.database.expanduser().resolve(), errors)
    if errors:
        print("Public-release audit failed:")
        for error in errors:
            print(f"  - {error}")
        return 1
    scope = "repository" if args.repository_only else "repository and runtime"
    print(f"Public-release audit passed for {scope}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
