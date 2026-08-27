from __future__ import annotations

import gzip
import hashlib
import json
import re
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .actor_names import (
    RELATED_BUT_DISTINCT_ACTORS,
    actor_identity_key,
    canonical_actor_name,
    known_actor_aliases,
)
from .actor_profiles_static import ai_refresh_is_usable, build_static_profile
from .database import Database, decode_json, iso
from .dls_policy import is_public_evidence_location
from .matching import extract_domains, match_claim, normalize_name
from .schemas import ClaimInput, ClientCreate, DlsLocationInput, RuntimeSettingsUpdate, utc_now
from .source_metadata import (
    extract_labelled_leak_size,
    extract_record_leak_size,
    leak_size_source_priority,
)


ALERT_SELECT = """
SELECT a.*, c.title AS claim_title, c.threat_actor, c.source,
       c.source_url, c.published_at, c.discovered_at, c.received_at,
       COALESCE(NULLIF(c.ai_country, ''), c.country) AS claim_country,
       COALESCE(NULLIF(c.ai_industry, ''), c.industry) AS claim_industry,
       cl.canonical_name AS client_name,
       cl.primary_domain
FROM alerts a
JOIN claims c ON c.id = a.claim_id
JOIN clients cl ON cl.id = a.client_id
"""


def display_datetime(value: str | None) -> str:
    """Render user-facing timestamps consistently in the server's local timezone."""
    if not value:
        return "Not supplied"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return "Invalid date"
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone().strftime("%Y-%m-%d %H:%M:%S")


GEOGRAPHY_ALIASES = {
    "hk": "hong kong",
    "hong kong sar": "hong kong",
    "hong kong s a r": "hong kong",
    "sg": "singapore",
    "uk": "united kingdom",
    "great britain": "united kingdom",
    "us": "united states",
    "u s": "united states",
    "usa": "united states",
    "united states of america": "united states",
}


def _normalized_geography(value: str | None) -> str:
    normalized = " ".join(re.sub(r"[^a-z0-9]+", " ", (value or "").casefold()).split())
    return GEOGRAPHY_ALIASES.get(normalized, normalized)


def _geography_matches(value: str | None, target: str) -> bool:
    observed = _normalized_geography(value)
    selected = _normalized_geography(target)
    if not observed or not selected:
        return False
    if observed == selected or observed in selected or selected in observed:
        return True
    # Public sources usually report only the country. Preserve a useful match
    # when the analyst selected a finer Hong Kong or Singapore region.
    for parent in ("hong kong", "singapore"):
        if parent in selected and observed == parent:
            return True
    return False


def _focus_region_matches(claim: dict, focus_regions: list[str]) -> list[str]:
    geography = claim.get("country") or claim.get("ai_country") or ""
    return [region for region in focus_regions if _geography_matches(geography, region)]


def _focus_region_sql_terms(focus_regions: list[str]) -> list[str]:
    terms: set[str] = set()
    for region in focus_regions:
        normalized = _normalized_geography(region)
        if normalized:
            terms.add(normalized)
        if "hong kong" in normalized:
            terms.add("hong kong")
        if "singapore" in normalized:
            terms.add("singapore")
        for alias, canonical in GEOGRAPHY_ALIASES.items():
            if canonical == normalized:
                terms.add(alias)
    return sorted(terms)


def _source_datetime(value) -> datetime | None:
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    if text.upper().endswith(" UTC"):
        text = f"{text[:-4].strip()}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _row_client(row) -> dict:
    countries = decode_json(row["countries_json"]) or ([row["country"]] if row["country"] else [])
    industries = decode_json(row["industries_json"]) or (
        [row["industry"]] if row["industry"] else []
    )
    return {
        "id": row["id"],
        "canonical_name": row["canonical_name"],
        "primary_domain": row["primary_domain"],
        "description": row["description"],
        "country": row["country"],
        "industry": row["industry"],
        "countries": countries,
        "cities": decode_json(row["cities_json"]),
        "industries": industries,
        "related_entities": decode_json(row["related_entities_json"]),
        "keywords": decode_json(row["keywords_json"]),
        "priority": row["priority"],
        "aliases": decode_json(row["aliases_json"]),
        "created_at": row["created_at"],
    }


def _row_claim(row) -> dict:
    return {
        "id": row["id"],
        "fingerprint": row["fingerprint"],
        "source": row["source"],
        "source_record_id": row["source_record_id"],
        "source_url": row["source_url"],
        "threat_actor": canonical_actor_name(row["threat_actor"]),
        "title": row["title"],
        "description": row["description"],
        "published_at": row["published_at"] or row["discovered_at"],
        "discovered_at": row["discovered_at"],
        "attack_date": row["attack_date"],
        "received_at": row["received_at"],
        "country": row["country"],
        "industry": row["industry"],
        "domains": decode_json(row["domains_json"]),
        "status": row["status"],
        "publication_status": row["publication_status"],
        "leak_size": row["leak_size"],
        "leak_size_bytes": row["leak_size_bytes"],
        "leak_size_source": row["leak_size_source"],
        "source_screenshot_url": row["source_screenshot_url"],
        "source_tags": decode_json(row["source_tags_json"]),
        "detail_checked_at": row["detail_checked_at"],
        "detail_status": row["detail_status"],
        "ai_industry": row["ai_industry"],
        "ai_country": row["ai_country"],
        "ai_description": row["ai_description"],
        "ai_organization_type": row["ai_organization_type"],
        "ai_rationale": row["ai_rationale"],
        "ai_sources": decode_json(row["ai_sources_json"]),
        "ai_past_incidents": decode_json(row["ai_past_incidents_json"]),
        "ai_osint_status": row["ai_osint_status"],
        "ai_osint_checked_at": row["ai_osint_checked_at"],
        "ai_confidence": row["ai_confidence"],
        "ai_provider": row["ai_provider"],
        "ai_enriched_at": row["ai_enriched_at"],
    }


def _row_organization(row) -> dict:
    return {
        "id": row["id"],
        "canonical_name": row["canonical_name"],
        "primary_domain": row["primary_domain"],
        "aliases": decode_json(row["aliases_json"]),
        "domains": decode_json(row["domains_json"]),
        "description": row["description"],
        "industry": row["industry"],
        "country": row["country"],
        "organization_type": row["organization_type"],
        "confidence": row["confidence"],
        "provenance": decode_json(row["provenance_json"]),
        "analyst_reviewed": bool(row["analyst_reviewed"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _row_ai_job(row) -> dict:
    def object_json(value: str | None) -> dict:
        if not value:
            return {}
        try:
            decoded = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return {}
        return decoded if isinstance(decoded, dict) else {}

    return {
        "id": row["id"],
        "job_type": row["job_type"],
        "title": row["title"],
        "status": row["status"],
        "payload": object_json(row["payload_json"]),
        "result": object_json(row["result_json"]) if row["result_json"] else None,
        "error": row["error"],
        "destination": row["destination"],
        "target_id": row["target_id"],
        "created_at": row["created_at"],
        "started_at": row["started_at"],
        "completed_at": row["completed_at"],
        "seen_at": row["seen_at"],
    }


def _row_notification_draft(row) -> dict:
    return {
        "id": row["id"],
        "alert_id": row["alert_id"],
        "client_id": row["client_id"],
        "subject": row["subject"],
        "body": row["body"],
        "scenario": row["scenario"],
        "generated_by": row["generated_by"],
        "client_name_sanitized": bool(row["client_name_sanitized"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "disclaimer": "Saved locally for analyst review. Sending remains a separate, explicit action.",
    }


def _row_analyst_feedback(row) -> dict:
    return {
        "id": row["id"],
        "alert_id": row["alert_id"],
        "claim_id": row["claim_id"],
        "client_id": row["client_id"],
        "disposition": row["disposition"],
        "category": row["category"],
        "analyst_note": row["analyst_note"],
        "document_text": row["document_text"],
        "metadata": json.loads(row["metadata_json"] or "{}"),
        "claim_snapshot": json.loads(row["claim_snapshot_json"] or "{}"),
        "client_snapshot": json.loads(row["client_snapshot_json"] or "{}"),
        "match_snapshot": json.loads(row["match_snapshot_json"] or "{}"),
        "embedding_model": row["embedding_model"],
        "embedding": decode_json(row["embedding_json"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _row_dls_target(row) -> dict:
    fqdn = row["fqdn"]
    return {
        "id": row["id"],
        "group_name": canonical_actor_name(row["group_name"]),
        "description": row["description"],
        "fqdn": fqdn,
        "address_hint": f"{fqdn[:12]}…{fqdn[-12:]}",
        "location_type": row["location_type"],
        "title": row["title"],
        "enabled": bool(row["enabled"]),
        "available": bool(row["available"]),
        "source": row["source"],
        "capture_enabled": bool(row["capture_enabled"]),
        "first_seen_at": row["first_seen_at"],
        "last_catalog_sync_at": row["last_catalog_sync_at"],
        "last_capture_at": row["last_capture_at"],
        "last_capture_status": row["last_capture_status"],
    }


def _row_capture_job(row) -> dict:
    result = dict(row)
    result["capture_truncated"] = bool(result.get("capture_truncated"))
    result["status_changed"] = bool(result.get("status_changed"))
    result["pagination_detected"] = bool(result.get("pagination_detected"))
    result["more_content_suspected"] = bool(result.get("more_content_suspected"))
    result["tor_preflight_passed"] = bool(result.get("tor_preflight_passed"))
    result["victim_match_found"] = bool(result.get("victim_match_found"))
    statuses = result.pop("detected_statuses_json", "[]")
    result["detected_statuses"] = decode_json(statuses)
    result["anchor_lines"] = decode_json(result.pop("anchor_lines_json", "[]"))
    result["opsec_controls"] = decode_json(result.pop("opsec_controls_json", "[]"))
    result["victim_candidates"] = decode_json(result.pop("victim_candidates_json", "[]"))
    paths = decode_json(result.pop("screenshot_paths_json", "[]"))
    if not paths and result.get("screenshot_path"):
        paths = [result["screenshot_path"]]
    result["screenshot_paths"] = paths
    result["segment_count"] = len(paths) or int(result.get("segment_count") or 0)
    return result


CAPTURE_INTERSTITIAL_MARKERS = {
    "awaiting forwarding to the platform": "forwarding queue",
    "verifying browser": "browser verification",
    "verifying your browser": "browser verification",
    "finalizing verification": "browser verification",
    "click anywhere to enter": "entry screen",
    "log in to recovery": "recovery login",
    "login to recovery": "recovery login",
    "captcha": "CAPTCHA",
    "502 bad gateway": "502 gateway error",
    "503 service unavailable": "503 service error",
    "504 gateway timeout": "504 gateway timeout",
    "404 not found": "404 response",
}

CAPTURE_IGNORED_DOMAINS = {
    "cloudflare.com",
    "facebook.com",
    "darkforums.su",
    "exploit.in",
    "forum.exploit.in",
    "github.com",
    "google.com",
    "instagram.com",
    "linkedin.com",
    "t.me",
    "telegram.org",
    "twitter.com",
    "wikipedia.org",
    "x.com",
    "youtube.com",
}


def _capture_text_context(text: str, needles: list[str], radius: int = 8) -> str:
    lines = [" ".join(line.split()) for line in text.splitlines()]
    indexes = [
        index
        for index, line in enumerate(lines)
        if any(needle.casefold() in line.casefold() for needle in needles if needle)
    ]
    if not indexes:
        return ""
    selected: list[str] = []
    seen: set[int] = set()
    for index in indexes[:3]:
        for line_index in range(max(0, index - 2), min(len(lines), index + radius + 1)):
            if line_index not in seen:
                seen.add(line_index)
                selected.append(lines[line_index])
    return "\n".join(selected)


def _claim_fingerprint(payload: ClaimInput) -> str:
    # A claim is the actor/victim allegation, not an aggregator's copy of it.
    # Publication timestamps frequently differ between public sources, so date
    # must not participate in the canonical identity.
    fingerprint_source = _claim_identity(payload.threat_actor, payload.title)
    return hashlib.sha256(fingerprint_source.encode()).hexdigest()


def _claim_identity(threat_actor: str, title: str) -> str:
    return "|".join((actor_identity_key(threat_actor), normalize_name(title)))


def _deduplicate_claims(claims: list[dict]) -> list[dict]:
    """Collapse legacy cross-source copies for analytics without losing evidence rows."""
    consolidated: dict[str, dict] = {}
    for claim in claims:
        identity = _claim_identity(claim["threat_actor"], claim["title"])
        current = consolidated.get(identity)
        if current is None:
            consolidated[identity] = {
                **claim,
                "domains": list(claim["domains"]),
                "source_record_count": 1,
                "source_claim_ids": [claim["id"]],
            }
            continue

        current["source_record_count"] += 1
        current["source_claim_ids"].append(claim["id"])
        current["domains"] = sorted(set(current["domains"]) | set(claim["domains"]))
        for field in (
            "country",
            "industry",
            "ai_country",
            "ai_industry",
            "ai_organization_type",
            "ai_rationale",
        ):
            if not current[field] and claim[field]:
                current[field] = claim[field]
        if claim["leak_size"] and (
            not current["leak_size"]
            or leak_size_source_priority(claim["leak_size_source"])
            > leak_size_source_priority(current["leak_size_source"])
        ):
            for field in ("leak_size", "leak_size_bytes", "leak_size_source"):
                current[field] = claim[field]
        elif current["leak_size_bytes"] is None and claim["leak_size_bytes"] is not None:
            current["leak_size_bytes"] = claim["leak_size_bytes"]
        current["source_tags"] = sorted(
            set(current["source_tags"]) | set(claim["source_tags"]), key=str.casefold
        )
        if not current["source_screenshot_url"] and claim["source_screenshot_url"]:
            current["source_screenshot_url"] = claim["source_screenshot_url"]
        if not current["attack_date"] and claim["attack_date"]:
            current["attack_date"] = claim["attack_date"]
        for field in ("description", "ai_description"):
            if len(claim[field]) > len(current[field]):
                current[field] = claim[field]
        for field in ("published_at", "discovered_at", "received_at"):
            values = [value for value in (current[field], claim[field]) if value]
            current[field] = min(values) if values else None
        if claim["publication_status"] == "data_leaked":
            current["publication_status"] = "data_leaked"
        if (claim["ai_confidence"] or 0) > (current["ai_confidence"] or 0):
            for field in (
                "ai_confidence",
                "ai_provider",
                "ai_enriched_at",
                "ai_sources",
                "ai_past_incidents",
                "ai_osint_status",
                "ai_osint_checked_at",
            ):
                current[field] = claim[field]
    return list(consolidated.values())


def _observation_key(payload: ClaimInput) -> str:
    record_identity = payload.source_record_id.strip()
    if not record_identity:
        observed = payload.published_at or payload.discovered_at
        record_identity = "|".join(
            (
                payload.source_url.strip(),
                normalize_name(payload.threat_actor),
                normalize_name(payload.title),
                iso(observed) or "",
            )
        )
    content_identity = json.dumps(
        payload.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    content_digest = hashlib.sha256(content_identity.encode()).hexdigest()
    return hashlib.sha256(
        (f"{payload.source.strip().casefold()}\0{record_identity}\0{content_digest}").encode()
    ).hexdigest()


def _organization_entity_key(name: str, domains: list[str]) -> tuple[str, str]:
    normalized_domains = sorted(
        {domain.strip().lower().rstrip(".") for domain in domains if domain.strip()}
    )
    identity = (
        f"domain:{normalized_domains[0]}" if normalized_domains else f"name:{normalize_name(name)}"
    )
    return hashlib.sha256(identity.encode()).hexdigest(), (
        normalized_domains[0] if normalized_domains else ""
    )


class MonitorService:
    def __init__(self, database: Database, raw_dir: Path, capture_dir: Path | None = None):
        self.database = database
        self.raw_dir = raw_dir
        self.capture_dir = capture_dir or raw_dir.parent / "captures"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.capture_dir.mkdir(parents=True, exist_ok=True)

    def runtime_settings(self, *, scheduler_process_enabled: bool, worker_configured: bool) -> dict:
        with self.database.connection() as connection:
            values = {
                row["key"]: row["value"]
                for row in connection.execute("SELECT key, value FROM app_settings")
            }
        return {
            "operating_mode": values.get("operating_mode", "passive"),
            "scheduling_enabled": values.get("scheduling_enabled", "true") == "true",
            "public_interval_minutes": int(values.get("public_interval_minutes", "2")),
            "catalog_interval_hours": int(values.get("catalog_interval_hours", "6")),
            "active_interval_minutes": int(values.get("active_interval_minutes", "30")),
            "capture_max_scrolls": int(values.get("capture_max_scrolls", "60")),
            "capture_stable_passes": int(values.get("capture_stable_passes", "3")),
            "capture_scroll_delay_ms": int(values.get("capture_scroll_delay_ms", "1000")),
            "capture_max_page_height": int(values.get("capture_max_page_height", "50000")),
            "capture_segment_height": int(values.get("capture_segment_height", "1400")),
            "ai_enabled": values.get("ai_enabled", "false") == "true",
            "ai_provider": values.get("ai_provider", "ollama"),
            "ai_model": values.get("ai_model", "qwen3:4b"),
            "ai_base_url": values.get("ai_base_url", "http://127.0.0.1:11434/v1"),
            "focus_regions": decode_json(values.get("focus_regions", "[]")),
            "victim_digest_enabled": values.get("victim_digest_enabled", "false") == "true",
            "victim_digest_interval_hours": int(values.get("victim_digest_interval_hours", "24")),
            "victim_digest_recipients": decode_json(values.get("victim_digest_recipients", "[]")),
            "smtp_host": values.get("smtp_host", ""),
            "smtp_port": int(values.get("smtp_port", "587")),
            "smtp_security": values.get("smtp_security", "starttls"),
            "smtp_username": values.get("smtp_username", ""),
            "smtp_from": values.get("smtp_from", ""),
            "last_public_run_at": values.get("last_public_run_at") or None,
            "last_catalog_run_at": values.get("last_catalog_run_at") or None,
            "last_active_run_at": values.get("last_active_run_at") or None,
            "last_victim_digest_at": values.get("last_victim_digest_at") or None,
            "last_victim_digest_run_at": values.get("last_victim_digest_run_at") or None,
            "scheduler_process_enabled": scheduler_process_enabled,
            "worker_configured": worker_configured,
        }

    def capture_controls(self, defaults: dict[str, int]) -> dict[str, int]:
        keys = (
            "capture_max_scrolls",
            "capture_stable_passes",
            "capture_scroll_delay_ms",
            "capture_max_page_height",
            "capture_segment_height",
        )
        with self.database.connection() as connection:
            values = {
                row["key"]: row["value"]
                for row in connection.execute(
                    # Keys and placeholder count are a fixed local tuple.
                    f"SELECT key, value FROM app_settings WHERE key IN ({','.join('?' for _ in keys)})",  # noqa: S608
                    keys,
                )
            }
        return {key: int(values.get(key, defaults[key])) for key in keys}

    def update_runtime_settings(self, payload: RuntimeSettingsUpdate) -> None:
        values = payload.model_dump()
        now = iso(utc_now())
        with self.database.connection() as connection:
            for key, value in values.items():
                stored = (
                    json.dumps(value)
                    if isinstance(value, list)
                    else str(value).lower()
                    if isinstance(value, bool)
                    else str(value)
                )
                connection.execute(
                    "INSERT INTO app_settings(key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                    (key, stored, now),
                )

    def history_backfill_due(self, interval_hours: int = 24) -> bool:
        with self.database.connection() as connection:
            row = connection.execute(
                "SELECT value FROM app_settings WHERE key = 'last_history_backfill_at'"
            ).fetchone()
        if not row or not row["value"]:
            return True
        try:
            last = datetime.fromisoformat(row["value"].replace("Z", "+00:00"))
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            return utc_now() >= last + timedelta(hours=interval_hours)
        except ValueError:
            return True

    def mark_history_backfill(self) -> str:
        completed_at = iso(utc_now())
        with self.database.connection() as connection:
            connection.execute(
                """
                INSERT INTO app_settings(key, value, updated_at)
                VALUES ('last_history_backfill_at', ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at
                """,
                (completed_at, completed_at),
            )
        return completed_at

    def mark_schedule_run(self, kind: str) -> None:
        if kind not in {"public", "catalog", "active", "victim_digest"}:
            raise ValueError("Unknown schedule kind")
        now = iso(utc_now())
        with self.database.connection() as connection:
            connection.execute(
                "UPDATE app_settings SET value = ?, updated_at = ? WHERE key = ?",
                (now, now, f"last_{kind}_run_at"),
            )

    def mark_capture_worker_heartbeat(self) -> str:
        now = iso(utc_now())
        with self.database.connection() as connection:
            connection.execute(
                """
                INSERT INTO app_settings(key, value, updated_at)
                VALUES ('last_capture_worker_heartbeat_at', ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at
                """,
                (now, now),
            )
        return now

    def capture_worker_online(self, maximum_age_seconds: int = 20) -> bool:
        with self.database.connection() as connection:
            row = connection.execute(
                "SELECT value FROM app_settings WHERE key = 'last_capture_worker_heartbeat_at'"
            ).fetchone()
        if row is None or not row["value"]:
            return False
        try:
            heartbeat = datetime.fromisoformat(row["value"].replace("Z", "+00:00"))
            if heartbeat.tzinfo is None:
                heartbeat = heartbeat.replace(tzinfo=timezone.utc)
        except ValueError:
            return False
        age = utc_now() - heartbeat
        return timedelta(0) <= age <= timedelta(seconds=maximum_age_seconds)

    def daily_focus_victims(self, hours: int = 24, limit: int = 100) -> dict:
        since = iso(utc_now() - timedelta(hours=hours))
        with self.database.connection() as connection:
            region_row = connection.execute(
                "SELECT value FROM app_settings WHERE key = 'focus_regions'"
            ).fetchone()
            rows = connection.execute(
                "SELECT * FROM claims WHERE received_at > ? ORDER BY received_at DESC",
                (since,),
            ).fetchall()
        focus_regions = decode_json(region_row["value"] if region_row else "[]")
        claims = _deduplicate_claims([_row_claim(row) for row in rows])
        matched: list[dict] = []
        for claim in claims:
            regions = _focus_region_matches(claim, focus_regions)
            if not regions:
                continue
            matched.append(
                {
                    **claim,
                    "is_focus_region": True,
                    "is_new_today": True,
                    "matched_focus_regions": regions,
                }
            )
        return {
            "since": since,
            "focus_regions": focus_regions,
            "count": len(matched),
            "items": matched[:limit],
            "truncated": len(matched) > limit,
        }

    def victim_digest_context(self, interval_hours: int = 24) -> dict:
        with self.database.connection() as connection:
            last_row = connection.execute(
                "SELECT value FROM app_settings WHERE key = 'last_victim_digest_at'"
            ).fetchone()
            region_row = connection.execute(
                "SELECT value FROM app_settings WHERE key = 'focus_regions'"
            ).fetchone()
            since = last_row["value"] if last_row and last_row["value"] else None
            if since is None:
                since = iso(utc_now() - timedelta(hours=interval_hours))
            rows = connection.execute(
                "SELECT * FROM claims WHERE received_at > ? ORDER BY received_at DESC",
                (since,),
            ).fetchall()
        focus_regions = decode_json(region_row["value"] if region_row else "[]")
        claims = _deduplicate_claims([_row_claim(row) for row in rows])
        victim_items = []
        focus_region_victims = []
        for claim in claims:
            matched_regions = _focus_region_matches(claim, focus_regions)
            item = {
                "name": claim["title"],
                "actor": claim["threat_actor"],
                "country": claim["country"] or claim["ai_country"],
                "industry": claim["industry"] or claim["ai_industry"],
                "published_at": claim["published_at"],
                "ingested_at": claim["received_at"],
                "matched_focus_regions": matched_regions,
            }
            victim_items.append(item)
            if matched_regions:
                focus_region_victims.append(item)
        actors = Counter(claim["threat_actor"] or "Unknown" for claim in claims)
        countries = Counter(
            claim["country"] or claim["ai_country"] or "Unknown" for claim in claims
        )
        industries = Counter(
            claim["industry"] or claim["ai_industry"] or "Unknown" for claim in claims
        )
        return {
            "since": since,
            "generated_at": iso(utc_now()),
            "count": len(claims),
            "focus_regions": focus_regions,
            "focus_region_count": len(focus_region_victims),
            "top_actors": [{"name": name, "count": count} for name, count in actors.most_common(5)],
            "top_countries": [
                {"name": name, "count": count} for name, count in countries.most_common(5)
            ],
            "top_industries": [
                {"name": name, "count": count} for name, count in industries.most_common(5)
            ],
            "focus_region_victims": focus_region_victims[:100],
            "recent_victims": victim_items[:100],
            "victim_list_truncated": len(victim_items) > 100,
        }

    def mark_victim_digest_sent(self) -> str:
        sent_at = iso(utc_now())
        with self.database.connection() as connection:
            connection.execute(
                "INSERT INTO app_settings(key, value, updated_at) VALUES ('last_victim_digest_at', ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                (sent_at, sent_at),
            )
        return sent_at

    def schedule_active_captures(self, worker_configured: bool) -> dict:
        if not worker_configured:
            return {"queued": 0, "blocked": "worker_not_configured"}
        with self.database.connection() as connection:
            targets = connection.execute(
                """
                SELECT t.id, t.title, t.location_type FROM dls_targets t
                WHERE t.capture_enabled = 1 AND t.enabled = 1 AND t.available = 1
                  AND NOT EXISTS (
                    SELECT 1 FROM capture_jobs j
                    WHERE j.target_id = t.id AND j.status IN ('queued', 'running')
                  )
                """
            ).fetchall()
        eligible_targets = [
            row
            for row in targets
            if is_public_evidence_location(row["title"], row["location_type"])
        ]
        jobs = [self.queue_capture(row["id"], True) for row in eligible_targets]
        return {
            "queued": len(jobs),
            "blocked": None,
            "excluded_non_evidence_portals": len(targets) - len(eligible_targets),
        }

    def list_clients(self) -> list[dict]:
        with self.database.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM clients ORDER BY canonical_name COLLATE NOCASE"
            ).fetchall()
        return [_row_client(row) for row in rows]

    def create_client(self, payload: ClientCreate) -> dict:
        client_id = str(uuid.uuid4())
        created_at = iso(utc_now())
        with self.database.connection() as connection:
            connection.execute(
                """
                INSERT INTO clients(
                    id, canonical_name, primary_domain, description, country, industry,
                    priority, aliases_json, countries_json, cities_json, industries_json,
                    related_entities_json, keywords_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    client_id,
                    payload.canonical_name,
                    payload.primary_domain,
                    payload.description,
                    payload.country,
                    payload.industry,
                    payload.priority,
                    json.dumps(payload.aliases),
                    json.dumps(payload.countries),
                    json.dumps(payload.cities),
                    json.dumps(payload.industries),
                    json.dumps([entity.model_dump() for entity in payload.related_entities]),
                    json.dumps(payload.keywords),
                    created_at,
                ),
            )
        self.rematch_all_claims(client_id)
        return self.get_client(client_id)

    def get_client(self, client_id: str) -> dict:
        with self.database.connection() as connection:
            row = connection.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
        if row is None:
            raise KeyError(client_id)
        return _row_client(row)

    def update_client(self, client_id: str, payload: ClientCreate) -> dict:
        with self.database.connection() as connection:
            result = connection.execute(
                """
                UPDATE clients SET
                    canonical_name = ?, primary_domain = ?, description = ?, country = ?, industry = ?,
                    priority = ?, aliases_json = ?, countries_json = ?, cities_json = ?, industries_json = ?,
                    related_entities_json = ?, keywords_json = ?
                WHERE id = ?
                """,
                (
                    payload.canonical_name,
                    payload.primary_domain,
                    payload.description,
                    payload.country,
                    payload.industry,
                    payload.priority,
                    json.dumps(payload.aliases),
                    json.dumps(payload.countries),
                    json.dumps(payload.cities),
                    json.dumps(payload.industries),
                    json.dumps([entity.model_dump() for entity in payload.related_entities]),
                    json.dumps(payload.keywords),
                    client_id,
                ),
            )
            if result.rowcount == 0:
                raise KeyError(client_id)
        self.rematch_all_claims(client_id)
        return self.get_client(client_id)

    def delete_client(self, client_id: str) -> dict:
        client = self.get_client(client_id)
        with self.database.connection() as connection:
            counts = {
                "deleted_alerts": int(
                    connection.execute(
                        "SELECT COUNT(*) AS count FROM alerts WHERE client_id = ?",
                        (client_id,),
                    ).fetchone()["count"]
                ),
                "deleted_drafts": int(
                    connection.execute(
                        "SELECT COUNT(*) AS count FROM notification_drafts WHERE client_id = ?",
                        (client_id,),
                    ).fetchone()["count"]
                ),
                "deleted_feedback": int(
                    connection.execute(
                        "SELECT COUNT(*) AS count FROM analyst_feedback WHERE client_id = ?",
                        (client_id,),
                    ).fetchone()["count"]
                ),
                "deleted_assessments": int(
                    connection.execute(
                        """SELECT COUNT(*) AS count FROM alert_ai_assessments
                           WHERE alert_id IN (SELECT id FROM alerts WHERE client_id = ?)""",
                        (client_id,),
                    ).fetchone()["count"]
                ),
            }
            connection.execute("DELETE FROM analyst_feedback WHERE client_id = ?", (client_id,))
            connection.execute("DELETE FROM notification_drafts WHERE client_id = ?", (client_id,))
            connection.execute(
                """DELETE FROM alert_ai_assessments
                   WHERE alert_id IN (SELECT id FROM alerts WHERE client_id = ?)""",
                (client_id,),
            )
            connection.execute(
                """UPDATE capture_jobs SET alert_id = ''
                   WHERE alert_id IN (SELECT id FROM alerts WHERE client_id = ?)""",
                (client_id,),
            )
            connection.execute(
                """UPDATE ai_jobs SET target_id = ''
                   WHERE destination = 'alerts'
                     AND target_id IN (SELECT id FROM alerts WHERE client_id = ?)""",
                (client_id,),
            )
            connection.execute("DELETE FROM alerts WHERE client_id = ?", (client_id,))
            result = connection.execute("DELETE FROM clients WHERE id = ?", (client_id,))
            if result.rowcount == 0:
                raise KeyError(client_id)
        return {
            "deleted_client": {
                "id": client["id"],
                "canonical_name": client["canonical_name"],
            },
            **counts,
        }

    def list_claims(self, limit: int = 100) -> list[dict]:
        with self.database.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM claims ORDER BY received_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [_row_claim(row) for row in rows]

    def activity_claims(
        self,
        *,
        page: int = 1,
        page_size: int = 100,
        query: str = "",
        actor: str = "",
        country: str = "",
        date_basis: str = "published",
        date_from: str = "",
        date_to: str = "",
        sort: str = "ingested",
        direction: str = "desc",
        focus_only: bool = False,
        new_only: bool = False,
    ) -> dict:
        """Return a bounded page while keeping the complete retained set traversable."""
        where: list[str] = []
        values: list[object] = []
        with self.database.connection() as connection:
            region_row = connection.execute(
                "SELECT value FROM app_settings WHERE key = 'focus_regions'"
            ).fetchone()
        focus_regions = decode_json(region_row["value"] if region_row else "[]")
        if query.strip():
            needle = f"%{query.strip()}%"
            where.append(
                "(title LIKE ? OR source LIKE ? OR threat_actor LIKE ? OR description LIKE ? OR ai_description LIKE ? OR domains_json LIKE ?)"
            )
            values.extend([needle] * 6)
        if actor.strip():
            where.append("threat_actor = ? COLLATE NOCASE")
            values.append(actor.strip())
        if country.strip():
            where.append("COALESCE(NULLIF(country, ''), NULLIF(ai_country, '')) = ? COLLATE NOCASE")
            values.append(country.strip())
        date_column = (
            "COALESCE(published_at, discovered_at)" if date_basis == "published" else "received_at"
        )
        if date_from:
            where.append(f"{date_column} >= ?")
            values.append(f"{date_from}T00:00:00")
        if date_to:
            where.append(f"{date_column} <= ?")
            values.append(f"{date_to}T23:59:59.999999+00:00")
        if new_only:
            where.append("received_at > ?")
            values.append(iso(utc_now() - timedelta(hours=24)))
        if focus_only:
            focus_terms = _focus_region_sql_terms(focus_regions)
            if focus_terms:
                geography_sql = "LOWER(COALESCE(NULLIF(country, ''), NULLIF(ai_country, '')))"
                clauses = []
                for term in focus_terms:
                    if len(term) <= 3:
                        clauses.append(f"{geography_sql} = ?")
                        values.append(term)
                    else:
                        clauses.append(f"{geography_sql} LIKE ?")
                        values.append(f"%{term}%")
                where.append("(" + " OR ".join(clauses) + ")")
            else:
                where.append("1 = 0")
        where_sql = f" WHERE {' AND '.join(where)}" if where else ""
        sort_columns = {
            "claim": "title COLLATE NOCASE",
            "actor": "threat_actor COLLATE NOCASE",
            "country": "COALESCE(NULLIF(country, ''), NULLIF(ai_country, '')) COLLATE NOCASE",
            "leak_size": "COALESCE(leak_size_bytes, -1)",
            "published": "COALESCE(published_at, discovered_at)",
            "ingested": "received_at",
        }
        order = "ASC" if direction == "asc" else "DESC"
        order_sql = sort_columns.get(sort, sort_columns["ingested"])
        offset = (page - 1) * page_size
        with self.database.connection() as connection:
            total = connection.execute(
                # Every WHERE fragment is selected from fixed local SQL; values are bound.
                f"SELECT COUNT(*) FROM claims{where_sql}",  # noqa: S608
                values,
            ).fetchone()[0]
            rows = connection.execute(
                # Sort and filter fragments are selected from local allowlists.
                f"SELECT * FROM claims{where_sql} ORDER BY {order_sql} {order}, id {order} LIMIT ? OFFSET ?",  # noqa: S608
                [*values, page_size, offset],
            ).fetchall()
            actors = [
                row[0]
                for row in connection.execute(
                    "SELECT DISTINCT threat_actor FROM claims WHERE threat_actor <> '' ORDER BY threat_actor COLLATE NOCASE"
                )
            ]
            countries = [
                row[0]
                for row in connection.execute(
                    "SELECT DISTINCT COALESCE(NULLIF(country, ''), NULLIF(ai_country, '')) AS value FROM claims WHERE value IS NOT NULL ORDER BY value COLLATE NOCASE"
                )
            ]
        freshness_cutoff = utc_now() - timedelta(hours=24)
        items = []
        for row in rows:
            claim = _row_claim(row)
            matched_regions = _focus_region_matches(claim, focus_regions)
            received_at = _source_datetime(claim["received_at"])
            items.append(
                {
                    **claim,
                    "is_focus_region": bool(matched_regions),
                    "is_new_today": bool(received_at and received_at >= freshness_cutoff),
                    "matched_focus_regions": matched_regions,
                }
            )
        daily_focus = self.daily_focus_victims(hours=24, limit=1)
        return {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": max(1, (total + page_size - 1) // page_size),
            "actors": actors,
            "countries": countries,
            "focus_regions": focus_regions,
            "daily_focus_count": daily_focus["count"],
        }

    def claim_source_evidence(self, claim_id: str) -> dict:
        with self.database.connection() as connection:
            row = connection.execute("SELECT * FROM claims WHERE id = ?", (claim_id,)).fetchone()
        if row is None:
            raise KeyError(claim_id)
        claim = _row_claim(row)
        raw_record: object = {}
        raw_path = Path(row["raw_path"])
        if raw_path.is_file() and raw_path.resolve().is_relative_to(self.raw_dir.resolve()):
            try:
                with gzip.open(raw_path, "rt", encoding="utf-8") as source:
                    raw_record = json.load(source).get("record", {})
            except (OSError, ValueError, TypeError):
                raw_record = {"archive_error": "Archived source record could not be decoded"}
        return {
            "claim_id": claim_id,
            "source": claim["source"],
            "source_record_id": claim["source_record_id"],
            "source_url": claim["source_url"],
            "description": claim["description"],
            "archived_record": raw_record,
            "observations": self.list_source_observations(claim_id),
        }

    def list_source_observations(self, claim_id: str) -> list[dict]:
        with self.database.connection() as connection:
            claim = connection.execute(
                "SELECT threat_actor, title FROM claims WHERE id = ?", (claim_id,)
            ).fetchone()
            if claim is None:
                return []
            candidates = connection.execute(
                """SELECT id, threat_actor, title FROM claims
                   WHERE threat_actor = ? COLLATE NOCASE
                      OR title = ? COLLATE NOCASE""",
                (claim["threat_actor"], claim["title"]),
            ).fetchall()
            identity = _claim_identity(claim["threat_actor"], claim["title"])
            claim_ids = [
                row["id"]
                for row in candidates
                if _claim_identity(row["threat_actor"], row["title"]) == identity
            ]
            placeholders = ",".join("?" for _ in claim_ids)
            rows = connection.execute(
                f"""
                SELECT id, source, source_record_id, source_url, published_at,
                       received_at, content_sha256, parser_version
                FROM source_observations
                WHERE claim_id IN ({placeholders})
                ORDER BY received_at DESC, id
                """,  # noqa: S608
                claim_ids,
            ).fetchall()
        return [dict(row) for row in rows]

    def replace_cti_profiles(self, profiles: list[dict], source_version: str = "") -> int:
        refreshed_at = iso(utc_now())
        with self.database.connection() as connection:
            for profile in profiles:
                connection.execute(
                    """INSERT INTO threat_actor_cti_profiles(attack_id, canonical_name, aliases_json, profile_json, source, source_version, refreshed_at)
                       VALUES (?, ?, ?, ?, 'MITRE ATT&CK', ?, ?)
                       ON CONFLICT(attack_id) DO UPDATE SET canonical_name=excluded.canonical_name,
                       aliases_json=excluded.aliases_json, profile_json=excluded.profile_json,
                       source_version=excluded.source_version, refreshed_at=excluded.refreshed_at""",
                    (
                        profile["attack_id"],
                        profile["canonical_name"],
                        json.dumps(profile["aliases"]),
                        json.dumps(profile),
                        source_version,
                        refreshed_at,
                    ),
                )
        return len(profiles)

    def match_cti_profile(self, actor: str) -> dict | None:
        key = re.sub(r"[^a-z0-9]", "", actor.casefold())
        with self.database.connection() as connection:
            rows = connection.execute("SELECT * FROM threat_actor_cti_profiles").fetchall()
        for row in rows:
            names = [row["canonical_name"], *decode_json(row["aliases_json"])]
            for index, name in enumerate(names):
                if re.sub(r"[^a-z0-9]", "", name.casefold()) == key:
                    result = json.loads(row["profile_json"])
                    result["match_confidence"] = "high" if index == 0 else "moderate"
                    result["match_basis"] = "canonical_name" if index == 0 else "associated_name"
                    result["refreshed_at"] = row["refreshed_at"]
                    return result
        return None

    def save_actor_osint_evidence(self, actor: str, evidence: list[dict]) -> int:
        actor = canonical_actor_name(actor)
        saved = 0
        with self.database.connection() as connection:
            for item in evidence:
                excerpt = str(item.get("excerpt", "")).strip()[:6500]
                source_url = str(item.get("source_url", "")).strip()[:1000]
                if not item.get("id") or not source_url.startswith("https://") or not excerpt:
                    continue
                connection.execute(
                    """INSERT INTO threat_actor_osint_evidence(
                           id, actor, source_name, source_tier, title, source_url,
                           published_at, retrieved_at, excerpt, evidence_type, content_sha256
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(id) DO UPDATE SET
                           source_name=excluded.source_name,
                           source_tier=excluded.source_tier,
                           title=excluded.title,
                           published_at=excluded.published_at,
                           retrieved_at=excluded.retrieved_at,
                           excerpt=excluded.excerpt,
                           evidence_type=excluded.evidence_type,
                           content_sha256=excluded.content_sha256""",
                    (
                        str(item["id"])[:80],
                        actor[:160],
                        str(item.get("source_name", "OSINT publication"))[:200],
                        str(item.get("source_tier", "reporting"))[:80],
                        str(item.get("title", "Untitled source"))[:500],
                        source_url,
                        str(item.get("published_at", ""))[:50] or None,
                        str(item.get("retrieved_at", iso(utc_now())))[:50],
                        excerpt,
                        str(item.get("evidence_type", "published_research"))[:80],
                        hashlib.sha256(excerpt.encode()).hexdigest(),
                    ),
                )
                saved += 1
        return saved

    def actor_osint_evidence(self, actor: str, limit: int = 30) -> list[dict]:
        actor = canonical_actor_name(actor)
        with self.database.connection() as connection:
            rows = connection.execute(
                """SELECT id, actor, source_name, source_tier, title, source_url,
                          published_at, retrieved_at, excerpt, evidence_type, content_sha256
                   FROM threat_actor_osint_evidence
                   WHERE actor = ? COLLATE NOCASE
                   ORDER BY CASE source_tier
                                WHEN 'authoritative' THEN 0
                                WHEN 'authoritative-framework' THEN 1
                                WHEN 'research' THEN 2
                                WHEN 'cited-osint' THEN 3
                                ELSE 4
                            END,
                            COALESCE(published_at, retrieved_at) DESC
                   LIMIT ?""",
                (actor, max(1, min(100, limit))),
            ).fetchall()
        return [dict(row) for row in rows]

    def actor_analysis_context(self, actor: str, days: int = 90) -> dict:
        context = self.intelligence_analysis_context("actor", actor, days)
        return {**context, "actor": context["scope_value"]}

    def actor_profile_index(self, days: int = 365, limit: int = 500) -> list[dict]:
        """Return lightweight actor navigation metadata without building dossiers."""
        cutoff = iso(utc_now() - timedelta(days=days)) if days else ""
        date_expression = "COALESCE(published_at, discovered_at, received_at)"
        where = (
            f"WHERE {date_expression} >= ? AND TRIM(threat_actor) <> ''"
            if cutoff
            else "WHERE TRIM(threat_actor) <> ''"
        )
        parameters: tuple[object, ...] = (cutoff, limit) if cutoff else (limit,)
        with self.database.connection() as connection:
            # The date expression and WHERE clause are selected from fixed local
            # strings above; cutoff and limit remain bound parameters.
            rows = connection.execute(
                f"""SELECT threat_actor AS actor,
                           COUNT(*) AS claim_count,
                           MIN({date_expression}) AS first_observed_at,
                           MAX({date_expression}) AS last_observed_at
                    FROM claims
                    {where}
                    GROUP BY threat_actor COLLATE NOCASE
                    ORDER BY claim_count DESC, last_observed_at DESC
                    LIMIT ?""",  # noqa: S608
                parameters,
            ).fetchall()
        return [dict(row) for row in rows]

    def actor_profiles(
        self,
        days: int = 365,
        limit: int = 250,
        actor: str = "",
    ) -> list[dict]:
        """Combine sourced baseline CTI with a separate local-observation layer."""
        actor = canonical_actor_name(actor) if actor.strip() else ""
        with self.database.connection() as connection:
            if actor:
                rows = connection.execute(
                    """SELECT * FROM claims
                       WHERE threat_actor = ? COLLATE NOCASE
                       ORDER BY COALESCE(published_at, discovered_at, received_at) DESC""",
                    (actor,),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM claims ORDER BY COALESCE(published_at, discovered_at, received_at) DESC"
                ).fetchall()
            catalog_rows = connection.execute(
                "SELECT group_name, description, source FROM dls_targets WHERE description <> ''"
            ).fetchall()
            refresh_rows = connection.execute(
                "SELECT actor, profile_json FROM threat_actor_profile_refreshes"
            ).fetchall()
            osint_rows = connection.execute(
                """SELECT id, actor, source_name, source_tier, title, source_url,
                          published_at, retrieved_at, excerpt, evidence_type, content_sha256
                   FROM threat_actor_osint_evidence
                   ORDER BY COALESCE(published_at, retrieved_at) DESC"""
            ).fetchall()
        claims = [_row_claim(row) for row in rows]

        def normalize_actor(value: str) -> str:
            return actor_identity_key(value)

        catalog_profiles: dict[str, dict] = {}
        for row in catalog_rows:
            key = normalize_actor(row["group_name"])
            description = re.sub(r"<br\s*/?>", "\n", row["description"], flags=re.IGNORECASE)
            description = re.sub(r"<[^>]+>", "", description).strip()
            if description and (
                key not in catalog_profiles
                or len(description) > len(catalog_profiles[key]["description"])
            ):
                catalog_profiles[key] = {
                    "name": row["group_name"],
                    "description": description,
                    "source": row["source"],
                }
        refreshed_profiles = {
            normalize_actor(row["actor"]): json.loads(row["profile_json"]) for row in refresh_rows
        }
        osint_profiles: dict[str, list[dict]] = {}
        for row in osint_rows:
            osint_profiles.setdefault(normalize_actor(row["actor"]), []).append(dict(row))
        now = utc_now()
        cutoff = now - timedelta(days=days) if days else None
        trend_days = days if days and days <= 365 else 90
        current_start = now - timedelta(days=trend_days)
        previous_start = current_start - timedelta(days=trend_days)

        def observed_at(claim: dict) -> datetime:
            value = claim["published_at"] or claim["discovered_at"] or claim["received_at"]
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

        all_groups: dict[str, list[dict]] = {}
        for claim in claims:
            actor = claim["threat_actor"].strip() or "Unknown"
            all_groups.setdefault(actor, []).append(claim)
        selected = [claim for claim in claims if cutoff is None or observed_at(claim) >= cutoff]
        groups: dict[str, list[dict]] = {}
        for claim in selected:
            actor = claim["threat_actor"].strip() or "Unknown"
            groups.setdefault(actor, []).append(claim)

        profiles: list[dict] = []
        for actor, actor_claims in groups.items():
            cti_profile = self.match_cti_profile(actor)
            catalog_profile = catalog_profiles.get(normalize_actor(actor))
            dates = [observed_at(claim) for claim in actor_claims]
            history_dates = [observed_at(claim) for claim in all_groups.get(actor, actor_claims)]
            countries = Counter(
                claim["country"] or claim["ai_country"]
                for claim in actor_claims
                if claim["country"] or claim["ai_country"]
            )
            industries = Counter(
                claim["industry"] or claim["ai_industry"]
                for claim in actor_claims
                if claim["industry"] or claim["ai_industry"]
            )
            sources = Counter(claim["source"] for claim in actor_claims)
            current_count = sum(date >= current_start for date in history_dates)
            previous_count = sum(previous_start <= date < current_start for date in history_dates)
            change = current_count - previous_count
            growth = (
                None
                if previous_count == 0 and current_count
                else (0.0 if previous_count == 0 else round(change / previous_count * 100, 1))
            )
            top_countries = [
                {"name": name, "count": count} for name, count in countries.most_common(3)
            ]
            top_industries = [
                {"name": name, "count": count} for name, count in industries.most_common(3)
            ]
            country_coverage = sum(
                bool(claim["country"] or claim["ai_country"]) for claim in actor_claims
            )
            industry_coverage = sum(
                bool(claim["industry"] or claim["ai_industry"]) for claim in actor_claims
            )
            country_text = (
                ", ".join(item["name"] for item in top_countries) or "geographies not supplied"
            )
            industry_text = (
                ", ".join(item["name"] for item in top_industries) or "industries not supplied"
            )
            completeness = (
                sum(bool(claim["country"] or claim["ai_country"]) for claim in actor_claims)
                + sum(bool(claim["industry"] or claim["ai_industry"]) for claim in actor_claims)
            ) / max(1, len(actor_claims) * 2)
            confidence = (
                "high"
                if len(actor_claims) >= 20 and completeness >= 0.6
                else ("moderate" if len(actor_claims) >= 5 and completeness >= 0.3 else "low")
            )
            aliases = sorted(
                (name for name in known_actor_aliases(actor) if name != actor),
                key=str.casefold,
            )
            period_text = (
                f"the selected {days}-day period" if days else "the locally retained dataset"
            )
            summary = (
                f"{actor} is an actor label associated with {len(actor_claims)} unverified public victim "
                f"claim{'s' if len(actor_claims) != 1 else ''} in {period_text}. Industry was supplied "
                f"for {industry_coverage} claims; the most frequently reported values were {industry_text}. "
                f"Geography was supplied for {country_coverage} claims; the most frequent values were {country_text}."
            )
            static_profile = build_static_profile(
                actor=actor,
                cti_profile=cti_profile,
                catalog_profile=catalog_profile,
                claim_count=len(actor_claims),
                first_observed_at=min(history_dates).isoformat(),
                last_observed_at=max(history_dates).isoformat(),
                top_industries=top_industries,
                top_countries=top_countries,
            )
            baseline_summary = static_profile["summary"]
            baseline_source = static_profile["sources"][0]["name"]
            baseline_confidence = static_profile["source_confidence"]
            refreshed_profile = refreshed_profiles.get(normalize_actor(actor))
            osint_evidence = osint_profiles.get(normalize_actor(actor), [])[:30]
            usable_refresh = ai_refresh_is_usable(
                refreshed_profile,
                {str(item["id"]) for item in osint_evidence},
            )
            cited_source_count = (
                int(refreshed_profile.get("independent_source_count", 0) or 0)
                if usable_refresh
                else 0
            )
            professional_sources = (
                refreshed_profile.get("sources", [])
                if usable_refresh
                else [source["name"] for source in static_profile["sources"]]
            )
            source_references = (
                [
                    {
                        "name": item["source_name"],
                        "url": item["source_url"],
                    }
                    for item in osint_evidence
                    if item["source_name"] in professional_sources
                ]
                if usable_refresh
                else static_profile["sources"]
            )
            top_techniques = [
                {
                    "id": str(item.get("id", "")),
                    "name": str(item.get("name", "")),
                    "tactics": [str(value) for value in item.get("tactics", []) if value],
                    "url": str(item.get("url", "")),
                }
                for item in (cti_profile.get("techniques", []) if cti_profile else [])[:10]
            ]
            documented_tactics = sorted(
                {
                    tactic.replace("-", " ")
                    for item in top_techniques
                    for tactic in item["tactics"]
                    if tactic
                }
            )
            if top_techniques:
                priority_actions = [
                    f"Map the {len(cti_profile.get('techniques', []))} documented ATT&CK technique relationships to the local detection-coverage matrix.",
                    (
                        "Prioritize telemetry validation for documented tactics: "
                        + ", ".join(documented_tactics[:8])
                        + "."
                        if documented_tactics
                        else "Validate telemetry for the documented ATT&CK technique relationships."
                    ),
                    "Treat public victim claims as collection leads and corroborate them with internal telemetry before escalation.",
                ]
                hunt_hypotheses = [
                    (
                        f"If activity consistent with {actor} is present, telemetry may contain "
                        f"the documented {item['id']} {item['name']} behavior; validate the "
                        "ATT&CK procedure and cited source before operational use."
                    )
                    for item in top_techniques[:5]
                ]
            else:
                priority_actions = [
                    "Review the cited actor dossier before translating narrative reporting into detections.",
                    "Do not infer actor-specific access methods or malware from victim-list observations.",
                    "Corroborate any matching public claim with internal identity, endpoint, network and recovery telemetry.",
                ]
                hunt_hypotheses = [
                    "No structured ATT&CK-backed actor hunt hypothesis is available in retained evidence; use the cited source material for analyst-led scoping."
                ]
            refreshed_priority_actions = (
                refreshed_profile.get("priority_actions", []) if usable_refresh else []
            )
            if isinstance(refreshed_priority_actions, list) and refreshed_priority_actions:
                priority_actions = [
                    str(item) for item in refreshed_priority_actions if str(item).strip()
                ][:4]
            refreshed_hunt_hypotheses = (
                refreshed_profile.get("hunt_hypotheses", []) if usable_refresh else []
            )
            if isinstance(refreshed_hunt_hypotheses, list) and refreshed_hunt_hypotheses:
                hunt_hypotheses = [
                    str(item) for item in refreshed_hunt_hypotheses if str(item).strip()
                ][:5]
            related_labels = [
                {"name": right, "relationship": reason}
                for left, right, reason in RELATED_BUT_DISTINCT_ACTORS
                if actor_identity_key(left) == actor_identity_key(actor)
            ] + [
                {"name": left, "relationship": reason}
                for left, right, reason in RELATED_BUT_DISTINCT_ACTORS
                if actor_identity_key(right) == actor_identity_key(actor)
            ]
            profile_status = (
                "sourced_profile"
                if static_profile["source_kind"]
                in {"static_local_curated", "static_local_framework"}
                or usable_refresh
                else "catalogue_context_only"
                if catalog_profile
                else "label_only"
            )
            professional_profile = {
                "profile_schema": static_profile.get(
                    "profile_schema", "ExtortSignal CTI Profile 1.0"
                ),
                "profile_status": profile_status,
                "actor_class": static_profile.get("actor_class", "unresolved_actor_label"),
                "distribution": static_profile.get("distribution", "TLP:CLEAR"),
                "summary": (
                    refreshed_profile.get("summary", "").strip()
                    if usable_refresh
                    else baseline_summary
                )
                or baseline_summary,
                "motivation": (
                    refreshed_profile.get("motivation", "").strip()
                    if usable_refresh
                    else static_profile["motivation"]
                ),
                "targeting": (
                    refreshed_profile.get("targeting", "").strip()
                    if usable_refresh
                    else static_profile["targeting"]
                ),
                "capabilities": (
                    refreshed_profile.get("capabilities", "").strip()
                    if usable_refresh
                    else static_profile["capabilities"]
                ),
                "campaign_history": (
                    refreshed_profile.get("campaign_history", "").strip()
                    if usable_refresh
                    else static_profile["campaign_history"]
                ),
                "source_kind": (
                    "ai_refreshed" if usable_refresh else static_profile["source_kind"]
                ),
                "sources": [str(source) for source in professional_sources if str(source).strip()],
                "source_references": source_references,
                "source_confidence": (
                    "high"
                    if cited_source_count >= 3
                    else "moderate"
                    if cited_source_count == 2
                    else "low"
                    if usable_refresh
                    else baseline_confidence
                ),
                "analytic_confidence": (
                    refreshed_profile.get("confidence")
                    if usable_refresh
                    else static_profile["analytic_confidence"]
                ),
                "generated_at": (refreshed_profile.get("generated_at") if usable_refresh else None),
                "reviewed_at": static_profile["reviewed_at"],
                "caveats": (
                    refreshed_profile.get("caveats", [])
                    if usable_refresh
                    else static_profile["caveats"]
                ),
                "identity": {
                    "attack_id": cti_profile.get("attack_id", "") if cti_profile else "",
                    "canonical_name": (
                        cti_profile.get("canonical_name", "")
                        if cti_profile
                        else static_profile["canonical_name"]
                    ),
                    "aliases": (
                        cti_profile.get("aliases", []) if cti_profile else static_profile["aliases"]
                    ),
                    "resolution_basis": (
                        "MITRE ATT&CK canonical-name match"
                        if cti_profile and cti_profile.get("match_basis") == "canonical_name"
                        else "MITRE ATT&CK documented associated-name match; exact overlap is not assumed"
                        if cti_profile
                        else "curated equivalent-alias registry"
                        if len(known_actor_aliases(actor)) > 1
                        else "exact retained actor label"
                    ),
                    "related_but_distinct": related_labels,
                },
                "technique_count": len(cti_profile.get("techniques", [])) if cti_profile else 0,
                "software_count": len(cti_profile.get("software", [])) if cti_profile else 0,
                "campaign_count": len(cti_profile.get("campaigns", [])) if cti_profile else 0,
                "field_evidence": (
                    refreshed_profile.get("field_evidence", {}) if usable_refresh else {}
                ),
                "osint_evidence_count": len(osint_evidence),
                "independent_source_count": (
                    cited_source_count
                    if usable_refresh
                    else len({source["name"] for source in static_profile["sources"]})
                ),
                "osint_researched_at": (
                    refreshed_profile.get("osint_researched_at")
                    if usable_refresh
                    else (osint_evidence[0]["retrieved_at"] if osint_evidence else None)
                ),
                "ai_overlay_status": (
                    "applied"
                    if usable_refresh
                    else "insufficient_evidence"
                    if refreshed_profile
                    else "not_requested"
                ),
                "top_techniques": top_techniques,
                "priority_actions": priority_actions,
                "hunt_hypotheses": hunt_hypotheses,
                "detection_coverage": {
                    "status": "not_assessed",
                    "documented_technique_count": len(
                        cti_profile.get("techniques", []) if cti_profile else []
                    ),
                    "message": (
                        "No organization-specific detection matrix is imported. Technique relationships are intelligence context, not evidence of local coverage."
                    ),
                },
                "key_judgments": (
                    [
                        str(item)
                        for item in refreshed_profile.get("key_judgments", [])
                        if str(item).strip()
                    ][:4]
                    if usable_refresh
                    and isinstance(refreshed_profile.get("key_judgments"), list)
                    and refreshed_profile.get("key_judgments")
                    else [
                        (
                            "Actor identity and behavior are supported by retained external CTI."
                            if profile_status == "sourced_profile"
                            else "The retained evidence supports an actor label, not a complete technical identity."
                        ),
                        "Local victim-list observations are allegations and remain analytically separate from sourced actor behavior.",
                        "Observed sector and geography concentration may reflect affiliate activity, source coverage and reporting bias rather than targeting intent.",
                    ]
                ),
            }
            profiles.append(
                {
                    "actor": actor,
                    "summary": summary,
                    "claim_count": len(actor_claims),
                    "current_count": current_count,
                    "previous_count": previous_count,
                    "change": change,
                    "growth_percent": growth,
                    "trend_basis_days": trend_days,
                    "first_observed_at": min(dates).isoformat(),
                    "last_observed_at": max(dates).isoformat(),
                    "top_countries": top_countries,
                    "top_industries": top_industries,
                    "country_coverage": country_coverage,
                    "industry_coverage": industry_coverage,
                    "sources": [
                        {"name": name, "count": count} for name, count in sources.most_common()
                    ],
                    "possible_aliases": aliases,
                    "confidence": confidence,
                    "caveat": "Observed-claims profile only; origin, motivation, capabilities, access methods and attribution are not established.",
                    "cti_profile": cti_profile,
                    "catalog_profile": catalog_profile,
                    "baseline_profile": {
                        "summary": baseline_summary,
                        "source": baseline_source,
                        "confidence": baseline_confidence,
                        "source_kind": static_profile["source_kind"],
                        "reviewed_at": static_profile["reviewed_at"],
                    },
                    "professional_profile": professional_profile,
                    "ai_profile_refresh": refreshed_profile,
                    "osint_evidence": osint_evidence,
                }
            )
        profiles.sort(
            key=lambda item: (item["claim_count"], item["last_observed_at"]), reverse=True
        )
        return profiles[:limit]

    def save_actor_profile_refresh(
        self, actor: str, profile: dict, provider: str, model: str
    ) -> dict:
        actor = canonical_actor_name(actor)
        generated_at = iso(utc_now())
        with self.database.connection() as connection:
            retained_evidence_ids = {
                str(row["id"])
                for row in connection.execute(
                    "SELECT id FROM threat_actor_osint_evidence WHERE actor = ? COLLATE NOCASE",
                    (actor,),
                ).fetchall()
            }
            overlay_status = (
                "applied"
                if ai_refresh_is_usable(profile, retained_evidence_ids)
                else "insufficient_evidence"
            )
            stored = {
                **profile,
                "actor": actor,
                "provider": provider,
                "model": model,
                "generated_at": generated_at,
                "overlay_status": overlay_status,
            }
            connection.execute(
                """INSERT INTO threat_actor_profile_refreshes(
                       actor, profile_json, provider, model, generated_at
                   ) VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(actor) DO UPDATE SET
                       profile_json=excluded.profile_json,
                       provider=excluded.provider,
                       model=excluded.model,
                       generated_at=excluded.generated_at""",
                (actor, json.dumps(stored), provider, model, generated_at),
            )
        return stored

    def intelligence_analysis_context(self, scope: str, value: str = "", days: int = 90) -> dict:
        filters = {"actor": "", "country": "", "industry": ""}
        if scope not in {"overall", "actor", "region", "industry"}:
            raise ValueError(scope)
        if scope != "overall" and not value.strip():
            raise ValueError("A value is required for the selected analysis scope")
        if scope == "actor":
            filters["actor"] = value.strip()
        elif scope == "region":
            filters["country"] = value.strip()
        elif scope == "industry":
            filters["industry"] = value.strip()

        result = self.intelligence(days=days, page_size=200, **filters)
        victims = result["victims"]
        if not victims:
            raise KeyError(value or scope)
        labels = {
            "overall": "Overall ransomware trend",
            "actor": f"Threat actor · {victims[0]['threat_actor']}",
            "region": f"Region · {value.strip()}",
            "industry": f"Victim industry · {value.strip()}",
        }
        actor_names = (
            [victims[0]["threat_actor"]]
            if scope == "actor"
            else [item["name"] for item in result["top_groups"][:5]]
        )
        profile_lookup = {
            re.sub(r"[^a-z0-9]", "", profile["actor"].casefold()): profile
            for profile in self.actor_profiles(days=3650, limit=500)
        }
        selected_group_counts = {
            item["name"].casefold(): item["count"] for item in result["top_groups"]
        }
        threat_actor_context = []
        for actor_name in actor_names:
            profile = profile_lookup.get(re.sub(r"[^a-z0-9]", "", actor_name.casefold()))
            if not profile:
                continue
            threat_actor_context.append(
                {
                    "actor": profile["actor"],
                    "professional_profile": profile["professional_profile"],
                    "local_observations": {
                        "claim_count": selected_group_counts.get(
                            actor_name.casefold(), result["total"] if scope == "actor" else 0
                        ),
                        "observation_window_days": days,
                        "top_countries": profile["top_countries"],
                        "top_industries": profile["top_industries"],
                        "caveat": profile["caveat"],
                    },
                }
            )

        return {
            "scope": scope,
            "scope_value": "" if scope == "overall" else value.strip(),
            "label": labels[scope],
            "period_days": days,
            "claim_count": result["total"],
            "growth": result["overall_growth"],
            "top_groups": result["top_groups"][:5],
            "top_countries": result["top_countries"][:5],
            "top_industries": result["top_industries"][:5],
            "monthly_trend": result["monthly_trend"],
            "threat_actor_context": threat_actor_context,
            "recent_victims": [
                {
                    "name": claim["title"],
                    "threat_actor": claim["threat_actor"],
                    "country": claim["country"] or claim["ai_country"],
                    "industry": claim["industry"] or claim["ai_industry"],
                    "organization_type": claim["ai_organization_type"],
                    "published_at": claim["published_at"],
                }
                for claim in victims[:12]
            ],
        }

    def save_actor_ai_analysis(self, actor: str, analysis: dict, provider: str, model: str) -> dict:
        actor = canonical_actor_name(actor)
        generated_at = iso(utc_now())
        stored = {
            **analysis,
            "actor": actor,
            "provider": provider,
            "model": model,
            "generated_at": generated_at,
        }
        with self.database.connection() as connection:
            connection.execute(
                """INSERT INTO actor_ai_analysis(actor, analysis_json, provider, model, generated_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(actor) DO UPDATE SET analysis_json = excluded.analysis_json,
                   provider = excluded.provider, model = excluded.model, generated_at = excluded.generated_at""",
                (actor, json.dumps(stored), provider, model, generated_at),
            )
        return stored

    def save_intelligence_ai_analysis(
        self, context: dict, analysis: dict, provider: str, model: str
    ) -> dict:
        generated_at = iso(utc_now())
        record_id = str(uuid.uuid4())
        stored = {
            **context,
            **analysis,
            "id": record_id,
            "provider": provider,
            "model": model,
            "generated_at": generated_at,
        }
        with self.database.connection() as connection:
            connection.execute(
                """INSERT INTO intelligence_ai_analysis_history(
                       id, scope, scope_value, period_days, label, context_json,
                       analysis_json, provider, model, generated_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    record_id,
                    context["scope"],
                    context["scope_value"],
                    context["period_days"],
                    context["label"],
                    json.dumps(context),
                    json.dumps(stored),
                    provider,
                    model,
                    generated_at,
                ),
            )
        return stored

    def list_intelligence_ai_analysis_history(self, limit: int = 20) -> list[dict]:
        with self.database.connection() as connection:
            rows = connection.execute(
                """SELECT analysis_json FROM intelligence_ai_analysis_history
                   ORDER BY generated_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [json.loads(row["analysis_json"]) for row in rows]

    def enqueue_ai_job(
        self,
        job_type: str,
        title: str,
        payload: dict,
        destination: str,
        target_id: str = "",
    ) -> dict:
        job_id = str(uuid.uuid4())
        created_at = iso(utc_now())
        with self.database.connection() as connection:
            connection.execute(
                """INSERT INTO ai_jobs(
                       id, job_type, title, status, payload_json, destination,
                       target_id, created_at
                   ) VALUES (?, ?, ?, 'queued', ?, ?, ?, ?)""",
                (
                    job_id,
                    job_type,
                    title[:240],
                    json.dumps(payload),
                    destination[:40],
                    target_id[:160],
                    created_at,
                ),
            )
        return self.get_ai_job(job_id)

    def get_ai_job(self, job_id: str) -> dict:
        with self.database.connection() as connection:
            row = connection.execute("SELECT * FROM ai_jobs WHERE id = ?", (job_id,)).fetchone()
        if row is None:
            raise KeyError(job_id)
        return _row_ai_job(row)

    def list_ai_jobs(self, limit: int = 50) -> list[dict]:
        with self.database.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM ai_jobs ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [_row_ai_job(row) for row in rows]

    def ai_job_history(
        self,
        *,
        page: int = 1,
        page_size: int = 50,
        status: str = "",
        job_type: str = "",
        query: str = "",
    ) -> dict:
        conditions: list[str] = []
        parameters: list[object] = []
        if status:
            conditions.append("status = ?")
            parameters.append(status)
        if job_type:
            conditions.append("job_type = ?")
            parameters.append(job_type)
        if query.strip():
            conditions.append("title LIKE ? COLLATE NOCASE")
            parameters.append(f"%{query.strip()}%")
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        offset = (page - 1) * page_size
        with self.database.connection() as connection:
            total = int(
                connection.execute(
                    f"SELECT COUNT(*) FROM ai_jobs {where}",  # noqa: S608 - fixed clauses only
                    parameters,
                ).fetchone()[0]
            )
            rows = connection.execute(
                f"""SELECT * FROM ai_jobs {where}
                    ORDER BY created_at DESC LIMIT ? OFFSET ?""",  # noqa: S608 - fixed clauses only
                [*parameters, page_size, offset],
            ).fetchall()
            count_rows = connection.execute(
                "SELECT status, COUNT(*) AS count FROM ai_jobs GROUP BY status"
            ).fetchall()
            type_rows = connection.execute(
                "SELECT DISTINCT job_type FROM ai_jobs ORDER BY job_type"
            ).fetchall()
        pages = max(1, (total + page_size - 1) // page_size)
        return {
            "items": [_row_ai_job(row) for row in rows],
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": pages,
            "status_counts": {row["status"]: row["count"] for row in count_rows},
            "job_types": [row["job_type"] for row in type_rows],
        }

    def requeue_interrupted_ai_jobs(self) -> None:
        with self.database.connection() as connection:
            connection.execute(
                """UPDATE ai_jobs SET status = 'queued', started_at = NULL,
                   error = 'Restarted after the application stopped during processing'
                   WHERE status = 'running'"""
            )

    def claim_next_ai_job(self) -> dict | None:
        with self.database.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM ai_jobs WHERE status = 'queued' ORDER BY created_at LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            started_at = iso(utc_now())
            connection.execute(
                "UPDATE ai_jobs SET status = 'running', started_at = ?, error = '' WHERE id = ?",
                (started_at, row["id"]),
            )
        return self.get_ai_job(row["id"])

    def finish_ai_job(self, job_id: str, result: dict) -> dict:
        completed_at = iso(utc_now())
        with self.database.connection() as connection:
            connection.execute(
                """UPDATE ai_jobs SET status = 'completed', result_json = ?,
                   error = '', completed_at = ? WHERE id = ?""",
                (json.dumps(result), completed_at, job_id),
            )
        return self.get_ai_job(job_id)

    def fail_ai_job(self, job_id: str, error: str) -> dict:
        completed_at = iso(utc_now())
        with self.database.connection() as connection:
            connection.execute(
                """UPDATE ai_jobs SET status = 'failed', error = ?, completed_at = ?
                   WHERE id = ?""",
                (" ".join(error.split())[:1000], completed_at, job_id),
            )
        return self.get_ai_job(job_id)

    def mark_ai_job_seen(self, job_id: str) -> dict:
        with self.database.connection() as connection:
            result = connection.execute(
                "UPDATE ai_jobs SET seen_at = ? WHERE id = ?",
                (iso(utc_now()), job_id),
            )
            if result.rowcount == 0:
                raise KeyError(job_id)
        return self.get_ai_job(job_id)

    def save_claim_ai_enrichment(self, claim_id: str, enrichment: dict, provider: str) -> dict:
        enriched_at = iso(utc_now())
        with self.database.connection() as connection:
            result = connection.execute(
                """UPDATE claims SET ai_industry = ?, ai_country = ?, ai_description = ?,
                   ai_organization_type = ?, ai_rationale = ?, ai_sources_json = ?,
                   ai_past_incidents_json = ?, ai_osint_status = ?, ai_osint_checked_at = ?,
                   ai_confidence = ?, ai_provider = ?, ai_enriched_at = ?
                   WHERE id = ?""",
                (
                    enrichment.get("industry", "")[:160],
                    enrichment.get("country_or_region", "")[:120],
                    enrichment.get("brief_description", "")[:4000],
                    enrichment.get("organization_type", "")[:120],
                    enrichment.get("rationale", "")[:300],
                    json.dumps(enrichment.get("source_urls", [])[:8]),
                    json.dumps(enrichment.get("past_incidents", [])[:10]),
                    enrichment.get("osint_status", "completed")[:80],
                    enriched_at,
                    max(0, min(100, int(enrichment.get("confidence", 0)))),
                    provider[:120],
                    enriched_at,
                    claim_id,
                ),
            )
            if result.rowcount == 0:
                raise KeyError(claim_id)
        self._upsert_organization_profile(claim_id, enrichment, provider, enriched_at)
        return self.get_claim(claim_id)

    def organization_profile_for_claim(self, claim_id: str) -> dict | None:
        with self.database.connection() as connection:
            row = connection.execute(
                """
                SELECT o.*
                FROM claim_organizations co
                JOIN organizations o ON o.id = co.organization_id
                WHERE co.claim_id = ?
                """,
                (claim_id,),
            ).fetchone()
        return _row_organization(row) if row is not None else None

    def _upsert_organization_profile(
        self,
        claim_id: str,
        enrichment: dict,
        provider: str,
        enriched_at: str,
    ) -> None:
        claim = self.get_claim(claim_id)
        domains = sorted(
            {domain.strip().lower().rstrip(".") for domain in claim["domains"] if domain.strip()}
        )
        entity_key, primary_domain = _organization_entity_key(claim["title"], domains)
        organization_id = f"org-{entity_key[:32]}"
        confidence = max(0, min(100, int(enrichment.get("confidence", 0))))
        source_refs = [
            str(value)[:1000] for value in enrichment.get("source_urls", []) if str(value).strip()
        ][:8]
        provenance_item = {
            "claim_id": claim_id,
            "provider": provider[:120],
            "source_refs": source_refs,
            "observed_at": enriched_at,
        }
        normalized_name = normalize_name(claim["title"])
        with self.database.connection() as connection:
            existing = connection.execute(
                "SELECT * FROM organizations WHERE entity_key = ?",
                (entity_key,),
            ).fetchone()
            aliases = (
                sorted(
                    {
                        *decode_json(existing["aliases_json"]),
                        claim["title"],
                    }
                )
                if existing is not None
                else [claim["title"]]
            )
            merged_domains = (
                sorted({*decode_json(existing["domains_json"]), *domains})
                if existing is not None
                else domains
            )
            provenance = (
                [*decode_json(existing["provenance_json"]), provenance_item][-50:]
                if existing is not None
                else [provenance_item]
            )
            connection.execute(
                """
                INSERT INTO organizations(
                    id, entity_key, canonical_name, normalized_name,
                    primary_domain, aliases_json, domains_json, description,
                    industry, country, organization_type, confidence,
                    provenance_json, analyst_reviewed, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                ON CONFLICT(entity_key) DO UPDATE SET
                    aliases_json = excluded.aliases_json,
                    domains_json = excluded.domains_json,
                    primary_domain = CASE
                        WHEN organizations.primary_domain = '' THEN excluded.primary_domain
                        ELSE organizations.primary_domain
                    END,
                    description = CASE
                        WHEN organizations.analyst_reviewed = 0
                             AND (organizations.description = ''
                                  OR excluded.confidence >= organizations.confidence)
                            THEN excluded.description
                        ELSE organizations.description
                    END,
                    industry = CASE
                        WHEN organizations.analyst_reviewed = 0
                             AND (organizations.industry = ''
                                  OR excluded.confidence >= organizations.confidence)
                            THEN excluded.industry
                        ELSE organizations.industry
                    END,
                    country = CASE
                        WHEN organizations.analyst_reviewed = 0
                             AND (organizations.country = ''
                                  OR excluded.confidence >= organizations.confidence)
                            THEN excluded.country
                        ELSE organizations.country
                    END,
                    organization_type = CASE
                        WHEN organizations.analyst_reviewed = 0
                             AND (organizations.organization_type = ''
                                  OR excluded.confidence >= organizations.confidence)
                            THEN excluded.organization_type
                        ELSE organizations.organization_type
                    END,
                    confidence = CASE
                        WHEN organizations.analyst_reviewed = 0
                            THEN MAX(organizations.confidence, excluded.confidence)
                        ELSE organizations.confidence
                    END,
                    provenance_json = excluded.provenance_json,
                    updated_at = excluded.updated_at
                """,
                (
                    organization_id,
                    entity_key,
                    claim["title"][:300],
                    normalized_name,
                    primary_domain,
                    json.dumps(aliases),
                    json.dumps(merged_domains),
                    str(enrichment.get("brief_description", ""))[:4000],
                    str(enrichment.get("industry", ""))[:160],
                    str(enrichment.get("country_or_region", ""))[:120],
                    str(enrichment.get("organization_type", ""))[:120],
                    confidence,
                    json.dumps(provenance),
                    enriched_at,
                    enriched_at,
                ),
            )
            organization = connection.execute(
                "SELECT * FROM organizations WHERE entity_key = ?",
                (entity_key,),
            ).fetchone()
            if organization is None:
                raise RuntimeError("Canonical organization profile was not persisted")
            if primary_domain:
                candidates = connection.execute(
                    """
                    SELECT id, title, domains_json
                    FROM claims
                    WHERE id = ? OR title = ? COLLATE NOCASE
                       OR domains_json LIKE ?
                    """,
                    (claim_id, claim["title"], f'%"{primary_domain}"%'),
                ).fetchall()
            else:
                candidates = connection.execute(
                    """
                    SELECT id, title, domains_json
                    FROM claims
                    WHERE id = ? OR title = ? COLLATE NOCASE
                    """,
                    (claim_id, claim["title"]),
                ).fetchall()
            linked_claim_ids = []
            for candidate in candidates:
                candidate_domains = {
                    value.lower().rstrip(".")
                    for value in decode_json(candidate["domains_json"])
                    if value
                }
                if (
                    candidate["id"] == claim_id
                    or normalize_name(candidate["title"]) == normalized_name
                    or bool(candidate_domains & set(domains))
                ):
                    linked_claim_ids.append(candidate["id"])
                    connection.execute(
                        """
                        INSERT INTO claim_organizations(
                            claim_id, organization_id, match_basis,
                            confidence, updated_at
                        ) VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(claim_id) DO UPDATE SET
                            organization_id = excluded.organization_id,
                            match_basis = excluded.match_basis,
                            confidence = excluded.confidence,
                            updated_at = excluded.updated_at
                        """,
                        (
                            candidate["id"],
                            organization_id,
                            "domain" if candidate_domains & set(domains) else "normalized_name",
                            confidence,
                            enriched_at,
                        ),
                    )
            field_values = {
                "description": str(enrichment.get("brief_description", ""))[:4000],
                "industry": str(enrichment.get("industry", ""))[:160],
                "country": str(enrichment.get("country_or_region", ""))[:120],
                "organization_type": str(enrichment.get("organization_type", ""))[:120],
            }
            for field_name, field_value in field_values.items():
                if not field_value:
                    continue
                connection.execute(
                    """
                    INSERT INTO organization_field_evidence(
                        id, organization_id, claim_id, field_name, field_value,
                        source_kind, source_refs_json, confidence,
                        observed_at, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        organization_id,
                        claim_id,
                        field_name,
                        field_value,
                        f"ai:{provider[:100]}",
                        json.dumps(source_refs),
                        confidence,
                        enriched_at,
                        enriched_at,
                    ),
                )
            if linked_claim_ids:
                placeholders = ",".join("?" for _ in linked_claim_ids)
                canonical_sources = sorted(
                    {
                        ref
                        for item in decode_json(organization["provenance_json"])
                        if isinstance(item, dict)
                        for ref in item.get("source_refs", [])
                        if isinstance(ref, str) and ref
                    }
                )[:8]
                connection.execute(
                    f"""
                    UPDATE claims
                    SET ai_industry = ?, ai_country = ?, ai_description = ?,
                        ai_organization_type = ?, ai_sources_json = ?,
                        ai_confidence = ?, ai_provider = ?, ai_enriched_at = ?
                    WHERE id IN ({placeholders})
                    """,  # noqa: S608
                    (
                        organization["industry"],
                        organization["country"],
                        organization["description"],
                        organization["organization_type"],
                        json.dumps(canonical_sources),
                        int(organization["confidence"]),
                        provider[:120],
                        enriched_at,
                        *linked_claim_ids,
                    ),
                )

    def list_unenriched_claims(self, limit: int = 25) -> list[dict]:
        with self.database.connection() as connection:
            rows = connection.execute(
                """SELECT * FROM claims
                   WHERE ai_enriched_at IS NULL
                   ORDER BY received_at DESC
                   LIMIT ?""",
                (limit,),
            ).fetchall()
        return [_row_claim(row) for row in rows]

    def unenriched_claim_count(self) -> int:
        with self.database.connection() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM claims WHERE ai_enriched_at IS NULL"
            ).fetchone()
        return int(row["count"])

    def list_alerts(self, limit: int = 100) -> list[dict]:
        with self.database.connection() as connection:
            rows = connection.execute(
                ALERT_SELECT
                + """
                ORDER BY CASE a.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,
                         a.created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_alert(self, alert_id: str) -> dict:
        with self.database.connection() as connection:
            row = connection.execute(
                ALERT_SELECT + " WHERE a.id = ?",
                (alert_id,),
            ).fetchone()
        if row is None:
            raise KeyError(alert_id)
        return dict(row)

    def save_notification_draft(self, alert_id: str, draft: dict) -> dict:
        alert = self.get_alert(alert_id)
        draft_id = str(uuid.uuid4())
        now = iso(utc_now())
        with self.database.connection() as connection:
            connection.execute(
                """INSERT INTO notification_drafts(
                       id, alert_id, client_id, subject, body, scenario, generated_by,
                       client_name_sanitized, created_at, updated_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    draft_id,
                    alert_id,
                    alert["client_id"],
                    str(draft.get("subject", ""))[:300],
                    str(draft.get("body", ""))[:20_000],
                    str(draft.get("scenario", "contextual_match"))[:80],
                    str(draft.get("generated_by", "standard_template"))[:120],
                    int(bool(draft.get("client_name_sanitized", False))),
                    now,
                    now,
                ),
            )
        return self.get_notification_draft(draft_id)

    def get_notification_draft(self, draft_id: str) -> dict:
        with self.database.connection() as connection:
            row = connection.execute(
                "SELECT * FROM notification_drafts WHERE id = ?", (draft_id,)
            ).fetchone()
        if row is None:
            raise KeyError(draft_id)
        return _row_notification_draft(row)

    def list_notification_drafts(self, alert_id: str) -> list[dict]:
        with self.database.connection() as connection:
            rows = connection.execute(
                """SELECT * FROM notification_drafts
                   WHERE alert_id = ? ORDER BY updated_at DESC""",
                (alert_id,),
            ).fetchall()
        return [_row_notification_draft(row) for row in rows]

    def update_notification_draft(
        self, alert_id: str, draft_id: str, subject: str, body: str
    ) -> dict:
        with self.database.connection() as connection:
            result = connection.execute(
                """UPDATE notification_drafts SET subject = ?, body = ?, updated_at = ?
                   WHERE id = ? AND alert_id = ?""",
                (subject[:300], body[:20_000], iso(utc_now()), draft_id, alert_id),
            )
            if result.rowcount == 0:
                raise KeyError(draft_id)
        return self.get_notification_draft(draft_id)

    @staticmethod
    def _retrieval_terms(value: str) -> set[str]:
        stop = {
            "the",
            "and",
            "for",
            "with",
            "from",
            "that",
            "this",
            "was",
            "were",
            "client",
            "claim",
        }
        return {
            token
            for token in re.findall(r"[a-z0-9][a-z0-9.-]{2,}", value.casefold())
            if token not in stop
        }

    def false_positive_precedents(self, alert_id: str, limit: int = 3) -> list[dict]:
        alert = self.get_alert(alert_id)
        current_text = " ".join(
            str(value)
            for value in (
                alert["claim_title"],
                alert["client_name"],
                alert["reason"],
                alert["evidence"],
                alert["threat_actor"],
                alert.get("claim_country", ""),
                alert.get("claim_industry", ""),
            )
            if value
        )
        current_terms = self._retrieval_terms(current_text)
        with self.database.connection() as connection:
            rows = connection.execute(
                """SELECT * FROM analyst_feedback
                   WHERE disposition = 'false_positive' AND alert_id != ?
                   ORDER BY updated_at DESC LIMIT 250""",
                (alert_id,),
            ).fetchall()
        matches: list[dict] = []
        for row in rows:
            terms = self._retrieval_terms(row["document_text"])
            union = current_terms | terms
            similarity = len(current_terms & terms) / len(union) if union else 0.0
            if similarity < 0.08:
                continue
            feedback = _row_analyst_feedback(row)
            matches.append(
                {
                    "feedback_id": feedback["id"],
                    "category": feedback["category"],
                    "analyst_note": feedback["analyst_note"],
                    "similarity": round(similarity, 3),
                    "created_at": feedback["created_at"],
                    "retrieval_basis": "local lexical preview; embedding fields are reserved for a future local model",
                }
            )
        return sorted(matches, key=lambda item: item["similarity"], reverse=True)[:limit]

    def record_false_positive(self, alert_id: str, category: str, analyst_note: str) -> dict:
        alert = self.get_alert(alert_id)
        claim = self.get_claim(alert["claim_id"])
        client = self.get_client(alert["client_id"])
        now = iso(utc_now())
        note = analyst_note or "Analyst marked this alert as a false positive"
        claim_snapshot = {
            key: claim.get(key)
            for key in (
                "id",
                "title",
                "threat_actor",
                "source",
                "country",
                "industry",
                "ai_country",
                "ai_industry",
                "domains",
                "published_at",
                "received_at",
            )
        }
        client_snapshot = {
            key: client.get(key)
            for key in (
                "id",
                "canonical_name",
                "primary_domain",
                "countries",
                "cities",
                "industries",
                "aliases",
                "related_entities",
                "keywords",
            )
        }
        match_snapshot = {
            "severity": alert["severity"],
            "score": alert["score"],
            "reason": alert["reason"],
            "evidence": alert["evidence"],
        }
        document_text = "\n".join(
            (
                "Disposition: false positive",
                f"Category: {category}",
                f"Analyst rationale: {note}",
                f"Named victim: {claim['title']}",
                f"Threat actor: {claim['threat_actor']}",
                f"Monitored client: {client['canonical_name']}",
                f"Client domain: {client['primary_domain']}",
                f"Claim geography: {claim['country'] or claim['ai_country']}",
                f"Claim industry: {claim['industry'] or claim['ai_industry']}",
                f"Match reason: {alert['reason']}",
                f"Match evidence: {alert['evidence']}",
            )
        )
        feedback_id = str(uuid.uuid4())
        metadata = {
            "schema": "extortsignal.analyst-feedback.v1",
            "disposition": "false_positive",
            "category": category,
            "source": "analyst_workbench",
            "created_at": now,
        }
        with self.database.connection() as connection:
            existing = connection.execute(
                "SELECT id, created_at FROM analyst_feedback WHERE alert_id = ?", (alert_id,)
            ).fetchone()
            if existing:
                feedback_id = existing["id"]
                connection.execute(
                    """UPDATE analyst_feedback SET category = ?, analyst_note = ?,
                       document_text = ?, metadata_json = ?, claim_snapshot_json = ?,
                       client_snapshot_json = ?, match_snapshot_json = ?, updated_at = ?
                       WHERE id = ?""",
                    (
                        category,
                        note,
                        document_text,
                        json.dumps(metadata),
                        json.dumps(claim_snapshot),
                        json.dumps(client_snapshot),
                        json.dumps(match_snapshot),
                        now,
                        feedback_id,
                    ),
                )
            else:
                connection.execute(
                    """INSERT INTO analyst_feedback(
                           id, alert_id, claim_id, client_id, disposition, category,
                           analyst_note, document_text, metadata_json, claim_snapshot_json,
                           client_snapshot_json, match_snapshot_json, created_at, updated_at
                       ) VALUES (?, ?, ?, ?, 'false_positive', ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        feedback_id,
                        alert_id,
                        alert["claim_id"],
                        alert["client_id"],
                        category,
                        note,
                        document_text,
                        json.dumps(metadata),
                        json.dumps(claim_snapshot),
                        json.dumps(client_snapshot),
                        json.dumps(match_snapshot),
                        now,
                        now,
                    ),
                )
            connection.execute(
                """UPDATE alerts SET status = 'dismissed', note = ?, updated_at = ?
                   WHERE id = ?""",
                (note[:500], now, alert_id),
            )
        return {
            "alert": self.get_alert(alert_id),
            "feedback": self.get_analyst_feedback(feedback_id),
        }

    def get_analyst_feedback(self, feedback_id: str) -> dict:
        with self.database.connection() as connection:
            row = connection.execute(
                "SELECT * FROM analyst_feedback WHERE id = ?", (feedback_id,)
            ).fetchone()
        if row is None:
            raise KeyError(feedback_id)
        return _row_analyst_feedback(row)

    def update_alert(self, alert_id: str, status: str, note: str) -> dict:
        updated_at = iso(utc_now())
        notified_at = updated_at if status == "client_notified" else None
        with self.database.connection() as connection:
            result = connection.execute(
                "UPDATE alerts SET status = ?, note = ?, updated_at = ?, notified_at = COALESCE(?, notified_at) WHERE id = ?",
                (status, note, updated_at, notified_at, alert_id),
            )
            if result.rowcount == 0:
                raise KeyError(alert_id)
        return self.get_alert(alert_id)

    def update_alerts(self, alert_ids: list[str], status: str, note: str) -> dict:
        unique_ids = list(dict.fromkeys(alert_ids))
        updated_at = iso(utc_now())
        placeholders = ",".join("?" for _ in unique_ids)
        with self.database.connection() as connection:
            existing_ids = {
                row["id"]
                for row in connection.execute(
                    # Placeholder text is generated locally; IDs remain bound.
                    f"SELECT id FROM alerts WHERE id IN ({placeholders})",  # noqa: S608
                    unique_ids,
                ).fetchall()
            }
            if existing_ids:
                existing_placeholders = ",".join("?" for _ in existing_ids)
                connection.execute(
                    f"""UPDATE alerts
                        SET status = ?,
                            note = CASE WHEN ? <> '' THEN ? ELSE note END,
                            updated_at = ?,
                            notified_at = CASE
                                WHEN ? = 'client_notified' THEN ?
                                ELSE notified_at
                            END
                        WHERE id IN ({existing_placeholders})""",  # noqa: S608
                    (
                        status,
                        note[:500],
                        note[:500],
                        updated_at,
                        status,
                        updated_at,
                        *existing_ids,
                    ),
                )
        missing_ids = [alert_id for alert_id in unique_ids if alert_id not in existing_ids]
        return {
            "requested": len(unique_ids),
            "updated": len(existing_ids),
            "missing": len(missing_ids),
            "missing_alert_ids": missing_ids[:20],
            "status": status,
            "updated_at": updated_at,
        }

    def record_false_positives(
        self, alert_ids: list[str], category: str, analyst_note: str
    ) -> dict:
        unique_ids = list(dict.fromkeys(alert_ids))[:100]
        recorded: list[str] = []
        failures: list[dict] = []
        for alert_id in unique_ids:
            try:
                self.record_false_positive(alert_id, category, analyst_note)
                recorded.append(alert_id)
            except KeyError:
                failures.append({"alert_id": alert_id, "error": "Alert not found"})
        return {
            "requested": len(unique_ids),
            "recorded": len(recorded),
            "failed": len(failures),
            "recorded_alert_ids": recorded,
            "failures": failures,
            "status": "dismissed",
            "category": category,
            "updated_at": iso(utc_now()),
        }

    def save_alert_ai_assessment(
        self, alert_id: str, assessment: dict, provider: str, model: str
    ) -> dict:
        alert = self.get_alert(alert_id)
        assessment_id = str(uuid.uuid4())
        generated_at = iso(utc_now())
        stored = {
            **assessment,
            "id": assessment_id,
            "alert_id": alert_id,
            "claim_id": alert["claim_id"],
            "provider": provider,
            "model": model,
            "generated_at": generated_at,
        }
        with self.database.connection() as connection:
            connection.execute(
                """INSERT INTO alert_ai_assessments(
                       id, alert_id, claim_id, assessment_json,
                       provider, model, generated_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    assessment_id,
                    alert_id,
                    alert["claim_id"],
                    json.dumps(stored),
                    provider[:120],
                    model[:160],
                    generated_at,
                ),
            )
        return stored

    def list_alert_ai_assessments(self, alert_id: str, limit: int = 10) -> list[dict]:
        with self.database.connection() as connection:
            rows = connection.execute(
                """SELECT assessment_json FROM alert_ai_assessments
                   WHERE alert_id = ? ORDER BY generated_at DESC LIMIT ?""",
                (alert_id, limit),
            ).fetchall()
        return [json.loads(row["assessment_json"]) for row in rows]

    def alert_intelligence_context(self, alert_id: str) -> dict:
        alert = self.get_alert(alert_id)
        claim = self.get_claim(alert["claim_id"])
        client = self.get_client(alert["client_id"])
        profile = next(
            (
                item
                for item in self.actor_profiles(days=365)
                if item["actor"].casefold() == alert["threat_actor"].casefold()
            ),
            None,
        )
        reason = alert["reason"].casefold()
        if "subsidiary" in reason:
            scenario = "subsidiary_named"
        elif "third party" in reason:
            scenario = "third_party_named"
        elif any(
            label in reason
            for label in ("domain match", "company name", "known alias", "company-name similarity")
        ):
            scenario = "client_named"
        else:
            client_industries = {value.casefold() for value in client["industries"]}
            client_regions = {
                value.casefold() for value in [*client["countries"], *client["cities"]]
            }
            claim_industry = (claim["industry"] or claim["ai_industry"]).casefold()
            claim_regions = {
                value.casefold() for value in (claim["country"], claim["ai_country"]) if value
            }
            industry_match = bool(claim_industry and claim_industry in client_industries)
            region_match = bool(client_regions & claim_regions)
            if industry_match and region_match:
                scenario = "same_industry_same_region"
            elif industry_match:
                scenario = "same_industry_other_region"
            elif region_match:
                scenario = "same_region"
            else:
                scenario = "contextual_match"
        return {
            "alert": alert,
            "claim": claim,
            "client": client,
            "scenario": scenario,
            "actor_profile": profile,
            "published_at": claim["published_at"] or claim["discovered_at"],
            "ingested_at": claim["received_at"],
            "saved_drafts": self.list_notification_drafts(alert_id),
            "ai_assessments": self.list_alert_ai_assessments(alert_id),
            "false_positive_precedents": self.false_positive_precedents(alert_id),
            "capture_jobs": self.capture_jobs_for_alert(alert_id),
        }

    def client_notification_draft(self, alert_id: str) -> dict:
        context = self.alert_intelligence_context(alert_id)
        alert = context["alert"]
        observed = display_datetime(
            alert.get("published_at") or alert.get("discovered_at") or alert["created_at"]
        )
        ingested = display_datetime(alert.get("received_at") or alert["created_at"])
        subject = (
            f"Action requested: unverified ransomware claim referencing {alert['client_name']}"
        )
        body = f"""Dear [Client contact],

We are notifying you of an unverified public ransomware/extortion claim that appears to reference {alert["client_name"]}.

What we observed
- Claimed organization: {alert["claim_title"]}
- Named threat actor: {alert["threat_actor"]}
- Published by source: {observed}
- Ingested into monitoring platform: {ingested}
- Monitoring source: {alert["source"]}
- Match basis: {alert["reason"]}

Important context
This is a threat-actor allegation from a public source. It is not independent confirmation of unauthorized access, encryption, or data loss. We have not downloaded or reviewed any allegedly stolen material.

Recommended checks
1. Review current EDR, identity, VPN, email, and perimeter alerts for related anomalies.
2. Confirm that critical backups are recent, isolated, and recoverable.
3. Check with incident response, legal, and communications contacts before any external response.
4. Preserve relevant logs and advise us whether you want continued monitoring or escalation.

Please acknowledge receipt and let us know your preferred incident contact and next update time.

Regards,
[Your name / security team]
"""
        draft = {
            "alert_id": alert_id,
            "subject": subject,
            "body": body,
            "scenario": context["scenario"],
            "generated_by": "standard_template",
            "client_name_sanitized": False,
            "disclaimer": "Review and approve before sending. This draft deliberately treats the claim as unverified.",
        }
        return self.save_notification_draft(alert_id, draft)

    def source_detail_candidate_ids(
        self, payloads: list[ClaimInput], *, retry_minutes: int = 360
    ) -> set[str]:
        """Return source records whose rendered detail metadata should be checked.

        A successful explicit leak-size extraction is stable. Empty detail pages
        are rechecked on a bounded interval because aggregators can add a data
        volume after the victim first appears.
        """
        by_fingerprint = {_claim_fingerprint(payload): payload for payload in payloads}
        if not by_fingerprint:
            return set()
        rows: dict[str, object] = {}
        fingerprints = list(by_fingerprint)
        with self.database.connection() as connection:
            for offset in range(0, len(fingerprints), 800):
                chunk = fingerprints[offset : offset + 800]
                placeholders = ",".join("?" for _ in chunk)
                for row in connection.execute(
                    f"SELECT fingerprint, leak_size, detail_checked_at, detail_status FROM claims WHERE fingerprint IN ({placeholders})",  # noqa: S608
                    chunk,
                ):
                    rows[row["fingerprint"]] = row
        now = utc_now()
        selected: set[str] = set()
        for fingerprint, payload in by_fingerprint.items():
            if payload.leak_size:
                continue
            row = rows.get(fingerprint)
            if row is None:
                selected.add(payload.source_record_id)
                continue
            if row["leak_size"]:
                continue
            checked_at = row["detail_checked_at"]
            if not checked_at:
                selected.add(payload.source_record_id)
                continue
            try:
                parsed = datetime.fromisoformat(str(checked_at).replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                selected.add(payload.source_record_id)
                continue
            retry_interval = 30 if row["detail_status"] == "failed" else max(60, retry_minutes)
            if parsed < now - timedelta(minutes=retry_interval):
                selected.add(payload.source_record_id)
        return selected

    def reparse_archived_source_metadata_v2(self) -> dict:
        """One-time local reparse of retained raw observations after parser upgrades."""
        marker_key = "source_metadata_reparse_v2"
        with self.database.connection() as connection:
            marker = connection.execute(
                "SELECT value FROM app_settings WHERE key = ?", (marker_key,)
            ).fetchone()
            if marker and marker["value"] == "complete":
                return {"status": "already_complete", "scanned": 0, "updated": 0, "failed": 0}
            observations = connection.execute(
                """SELECT claim_id, raw_path FROM source_observations
                   WHERE raw_path <> '' ORDER BY created_at, id"""
            ).fetchall()

        scanned = 0
        updated = 0
        failed = 0
        pending: list[tuple[str, ClaimInput]] = []

        def flush() -> None:
            nonlocal updated
            if not pending:
                return
            with self.database.connection() as connection:
                for claim_id, payload in pending:
                    self._merge_claim_metadata(connection, claim_id, payload)
                    updated += 1
            pending.clear()

        raw_root = self.raw_dir.resolve()
        for observation in observations:
            path = Path(observation["raw_path"])
            try:
                if not path.is_file() or not path.resolve().is_relative_to(raw_root):
                    failed += 1
                    continue
                with gzip.open(path, "rt", encoding="utf-8") as source:
                    archived = json.load(source).get("record", {})
                if not isinstance(archived, dict):
                    failed += 1
                    continue
                raw = archived.get("raw") if isinstance(archived.get("raw"), dict) else {}
                leak_size = extract_record_leak_size(raw)
                attack_date = _source_datetime(
                    raw.get("attackdate")
                    or raw.get("attack_date")
                    or raw.get("estimated_attack_date")
                    or raw.get("est_attack_date")
                )
                screenshot = str(
                    raw.get("screenshot")
                    or raw.get("screenshot_url")
                    or raw.get("image")
                    or archived.get("source_screenshot_url")
                    or ""
                ).strip()
                tags = (
                    list(archived.get("source_tags") or [])
                    if isinstance(archived.get("source_tags"), list)
                    else []
                )
                if raw.get("new_group") is True or raw.get("is_new_group") is True:
                    tags.append("New group")
                enriched_record = {
                    **archived,
                    "attack_date": attack_date or archived.get("attack_date"),
                    "leak_size": leak_size.raw
                    if leak_size is not None
                    else archived.get("leak_size", ""),
                    "leak_size_bytes": leak_size.bytes
                    if leak_size is not None
                    else archived.get("leak_size_bytes"),
                    "leak_size_source": leak_size.source
                    if leak_size is not None
                    else archived.get("leak_size_source", ""),
                    "source_screenshot_url": screenshot,
                    "source_tags": tags,
                }
                pending.append(
                    (observation["claim_id"], ClaimInput.model_validate(enriched_record))
                )
                scanned += 1
                if len(pending) >= 500:
                    flush()
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                failed += 1
        flush()
        with self.database.connection() as connection:
            connection.execute(
                """INSERT INTO app_settings(key, value, updated_at) VALUES (?, 'complete', ?)
                   ON CONFLICT(key) DO UPDATE SET value = 'complete', updated_at = excluded.updated_at""",
                (marker_key, iso(utc_now())),
            )
        return {
            "status": "complete",
            "scanned": scanned,
            "updated": updated,
            "failed": failed,
        }

    def _merge_claim_metadata(self, connection, claim_id: str, payload: ClaimInput) -> None:
        existing = connection.execute("SELECT * FROM claims WHERE id = ?", (claim_id,)).fetchone()
        if existing is None:
            return
        domains = sorted(
            set(decode_json(existing["domains_json"]))
            | set(payload.domains)
            | set(extract_domains(f"{payload.title}\n{payload.description}"))
        )
        tags = sorted(
            set(decode_json(existing["source_tags_json"])) | set(payload.source_tags),
            key=str.casefold,
        )
        publication_status = existing["publication_status"]
        if payload.publication_status == "data_leaked":
            publication_status = "data_leaked"
        description = (
            payload.description
            if len(payload.description) > len(existing["description"])
            else existing["description"]
        )

        published_at = iso(payload.published_at or payload.discovered_at)
        discovered_at = iso(payload.discovered_at)
        observed_at = iso(payload.published_at or payload.discovered_at)

        def earliest(current: str | None, candidate: str | None) -> str | None:
            values = [value for value in (current, candidate) if value]
            return min(values) if values else None

        leak_size = existing["leak_size"]
        leak_size_bytes = existing["leak_size_bytes"]
        leak_size_source = existing["leak_size_source"]
        if payload.leak_size and (
            not leak_size
            or leak_size_source_priority(payload.leak_size_source)
            > leak_size_source_priority(leak_size_source)
        ):
            leak_size = payload.leak_size
            leak_size_bytes = payload.leak_size_bytes
            leak_size_source = payload.leak_size_source
        elif leak_size_bytes is None and payload.leak_size_bytes is not None:
            leak_size_bytes = payload.leak_size_bytes

        detail_checked_at = existing["detail_checked_at"]
        detail_status = existing["detail_status"]
        incoming_checked_at = iso(payload.detail_checked_at)
        if incoming_checked_at and (
            not detail_checked_at or incoming_checked_at >= detail_checked_at
        ):
            detail_checked_at = incoming_checked_at
            detail_status = payload.detail_status

        connection.execute(
            """
            UPDATE claims SET description = ?, published_at = ?, discovered_at = ?,
                attack_date = COALESCE(attack_date, ?), observed_at = ?,
                country = CASE WHEN country = '' THEN ? ELSE country END,
                industry = CASE WHEN industry = '' THEN ? ELSE industry END,
                domains_json = ?, publication_status = ?, leak_size = ?,
                leak_size_bytes = ?, leak_size_source = ?,
                source_screenshot_url = CASE WHEN source_screenshot_url = '' THEN ? ELSE source_screenshot_url END,
                source_tags_json = ?, detail_checked_at = ?, detail_status = ?
            WHERE id = ?
            """,
            (
                description,
                earliest(existing["published_at"], published_at),
                earliest(existing["discovered_at"], discovered_at),
                iso(payload.attack_date),
                earliest(existing["observed_at"], observed_at),
                payload.country,
                payload.industry,
                json.dumps(domains),
                publication_status,
                leak_size,
                leak_size_bytes,
                leak_size_source,
                payload.source_screenshot_url,
                json.dumps(tags),
                detail_checked_at,
                detail_status,
                claim_id,
            ),
        )

    def ingest(self, payload: ClaimInput) -> tuple[dict, bool]:
        payload = payload.model_copy(
            update={"threat_actor": canonical_actor_name(payload.threat_actor)}
        )
        fingerprint = _claim_fingerprint(payload)
        received_at = utc_now()
        with self.database.connection() as connection:
            existing = connection.execute(
                "SELECT * FROM claims WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
            if existing is None:
                candidates = connection.execute(
                    """SELECT * FROM claims
                       WHERE threat_actor = ? COLLATE NOCASE
                          OR title = ? COLLATE NOCASE""",
                    (payload.threat_actor, payload.title),
                ).fetchall()
                identity = _claim_identity(payload.threat_actor, payload.title)
                existing = next(
                    (
                        row
                        for row in candidates
                        if _claim_identity(row["threat_actor"], row["title"]) == identity
                    ),
                    None,
                )
            if existing:
                self._merge_claim_metadata(connection, existing["id"], payload)
                updated = connection.execute(
                    "SELECT * FROM claims WHERE id = ?", (existing["id"],)
                ).fetchone()
                claim = _row_claim(updated)
                claim_id = existing["id"]
                created = False
            else:
                claim = None
                claim_id = str(uuid.uuid4())
                created = True

        if not created:
            self._store_source_observation(payload, claim_id, received_at)
            return claim, False

        domains = sorted(
            set(payload.domains) | set(extract_domains(f"{payload.title}\n{payload.description}"))
        )
        with self.database.connection() as connection:
            connection.execute(
                """
                INSERT INTO claims(
                    id, fingerprint, source, source_record_id, source_url,
                    threat_actor, title, description, published_at, discovered_at, attack_date,
                    received_at, observed_at, country, industry, domains_json, raw_path, status,
                    publication_status, leak_size, leak_size_bytes, leak_size_source,
                    source_screenshot_url, source_tags_json, detail_checked_at, detail_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'alleged', ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    claim_id,
                    fingerprint,
                    payload.source,
                    payload.source_record_id,
                    payload.source_url,
                    payload.threat_actor,
                    payload.title,
                    payload.description,
                    iso(payload.published_at or payload.discovered_at),
                    iso(payload.discovered_at),
                    iso(payload.attack_date),
                    iso(received_at),
                    iso(payload.published_at or payload.discovered_at or received_at),
                    payload.country,
                    payload.industry,
                    json.dumps(domains),
                    "",
                    payload.publication_status,
                    payload.leak_size,
                    payload.leak_size_bytes,
                    payload.leak_size_source,
                    payload.source_screenshot_url,
                    json.dumps(payload.source_tags),
                    iso(payload.detail_checked_at),
                    payload.detail_status,
                ),
            )
        self._store_source_observation(payload, claim_id, received_at)
        claim = self.get_claim(claim_id)
        self._match_claim(claim)
        return claim, True

    def ingest_many(self, payloads: list[ClaimInput]) -> int:
        """Archive source observations and insert normalized claims in a WAL transaction.

        Existing fingerprints are queried in bounded chunks rather than loading the
        entire table. Every distinct upstream record is retained even when multiple
        sources resolve to the same normalized claim.
        """
        payloads = [
            payload.model_copy(update={"threat_actor": canonical_actor_name(payload.threat_actor)})
            for payload in payloads
        ]
        unique: dict[str, ClaimInput] = {}
        for payload in payloads:
            unique.setdefault(_claim_fingerprint(payload), payload)
        if not unique:
            return 0

        claim_by_fingerprint: dict[str, str] = {}
        keys = list(unique)
        with self.database.connection() as connection:
            for offset in range(0, len(keys), 800):
                chunk = keys[offset : offset + 800]
                placeholders = ",".join("?" for _ in chunk)
                claim_by_fingerprint.update(
                    {
                        row["fingerprint"]: row["id"]
                        for row in connection.execute(
                            # The placeholder count is generated locally; all values remain bound.
                            f"SELECT id, fingerprint FROM claims WHERE fingerprint IN ({placeholders})",  # noqa: S608
                            chunk,
                        )
                    }
                )

            # Older databases used actor + victim + date fingerprints. Resolve
            # those rows by normalized actor/victim identity so new source copies
            # attach to the existing canonical allegation.
            missing_payloads = [
                payload
                for fingerprint, payload in unique.items()
                if fingerprint not in claim_by_fingerprint
            ]
            for offset in range(0, len(missing_payloads), 300):
                chunk = missing_payloads[offset : offset + 300]
                actors = list(dict.fromkeys(payload.threat_actor for payload in chunk))
                titles = list(dict.fromkeys(payload.title for payload in chunk))
                actor_placeholders = ",".join("?" for _ in actors)
                title_placeholders = ",".join("?" for _ in titles)
                candidates = connection.execute(
                    f"""SELECT id, threat_actor, title FROM claims
                        WHERE threat_actor COLLATE NOCASE IN ({actor_placeholders})
                           OR title COLLATE NOCASE IN ({title_placeholders})""",  # noqa: S608
                    [*actors, *titles],
                ).fetchall()
                for row in candidates:
                    canonical_fingerprint = hashlib.sha256(
                        _claim_identity(row["threat_actor"], row["title"]).encode()
                    ).hexdigest()
                    if canonical_fingerprint in unique:
                        claim_by_fingerprint.setdefault(canonical_fingerprint, row["id"])

        received_at = utc_now()
        rows: list[tuple] = []
        inserted_ids: list[str] = []
        for fingerprint, payload in unique.items():
            if fingerprint in claim_by_fingerprint:
                continue
            claim_id = str(uuid.uuid4())
            claim_by_fingerprint[fingerprint] = claim_id
            domains = sorted(
                set(payload.domains)
                | set(extract_domains(f"{payload.title}\n{payload.description}"))
            )
            observed_at = payload.published_at or payload.discovered_at or received_at
            rows.append(
                (
                    claim_id,
                    fingerprint,
                    payload.source,
                    payload.source_record_id,
                    payload.source_url,
                    payload.threat_actor,
                    payload.title,
                    payload.description,
                    iso(payload.published_at or payload.discovered_at),
                    iso(payload.discovered_at),
                    iso(payload.attack_date),
                    iso(received_at),
                    iso(observed_at),
                    payload.country,
                    payload.industry,
                    json.dumps(domains),
                    "",
                    payload.publication_status,
                    payload.leak_size,
                    payload.leak_size_bytes,
                    payload.leak_size_source,
                    payload.source_screenshot_url,
                    json.dumps(payload.source_tags),
                    iso(payload.detail_checked_at),
                    payload.detail_status,
                )
            )
            inserted_ids.append(claim_id)

        stored_ids: set[str] = set()
        if rows:
            with self.database.connection() as connection:
                connection.executemany(
                    """
                    INSERT OR IGNORE INTO claims(
                        id, fingerprint, source, source_record_id, source_url,
                        threat_actor, title, description, published_at, discovered_at, attack_date,
                        received_at, observed_at, country, industry, domains_json,
                        raw_path, status, publication_status, leak_size, leak_size_bytes,
                        leak_size_source, source_screenshot_url, source_tags_json,
                        detail_checked_at, detail_status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'alleged', ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )
                stored_ids = {
                    row[0]
                    for offset in range(0, len(inserted_ids), 800)
                    for row in connection.execute(
                        # IDs and placeholder counts are generated locally.
                        f"SELECT id FROM claims WHERE id IN ({','.join('?' for _ in inserted_ids[offset : offset + 800])})",  # noqa: S608
                        inserted_ids[offset : offset + 800],
                    )
                }

        # Public sources commonly add sector, attack-date or exfiltrated-volume
        # metadata after the first sighting. Merge those later observations into
        # the canonical claim while every distinct raw payload remains archived.
        with self.database.connection() as connection:
            for payload in payloads:
                claim_id = claim_by_fingerprint.get(_claim_fingerprint(payload))
                if claim_id:
                    self._merge_claim_metadata(connection, claim_id, payload)

        for payload in payloads:
            claim_id = claim_by_fingerprint.get(_claim_fingerprint(payload))
            if claim_id:
                self._store_source_observation(payload, claim_id, received_at)
        for claim_id in stored_ids:
            self._match_claim(self.get_claim(claim_id))
        return len(stored_ids)

    def get_claim(self, claim_id: str) -> dict:
        with self.database.connection() as connection:
            row = connection.execute("SELECT * FROM claims WHERE id = ?", (claim_id,)).fetchone()
        if row is None:
            raise KeyError(claim_id)
        claim = _row_claim(row)
        claim["organization_profile"] = self.organization_profile_for_claim(claim_id)
        return claim

    def prior_claim_incidents(self, claim_id: str, limit: int = 10) -> list[dict]:
        """Find earlier retained allegations for the same named organization."""
        current = self.get_claim(claim_id)
        current_name = normalize_name(current["title"])
        current_domains = {domain.casefold() for domain in current["domains"] if domain}
        with self.database.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM claims WHERE id != ? ORDER BY COALESCE(published_at, discovered_at, received_at) DESC",
                (claim_id,),
            ).fetchall()
        incidents = []
        for row in rows:
            candidate = _row_claim(row)
            candidate_domains = {domain.casefold() for domain in candidate["domains"] if domain}
            same_domain = bool(current_domains & candidate_domains)
            same_name = bool(current_name and normalize_name(candidate["title"]) == current_name)
            if not (same_domain or same_name):
                continue
            incidents.append(
                {
                    "published_at": candidate["published_at"] or candidate["received_at"],
                    "incident_type": "previous public ransomware claim",
                    "summary": f"Previously listed by {candidate['threat_actor']} in {candidate['source']}.",
                    "source_url": candidate["source_url"],
                    "source_name": candidate["source"],
                    "threat_actor": candidate["threat_actor"],
                    "evidence_type": "local_claim",
                    "confidence": 100 if same_domain else 85,
                }
            )
            if len(incidents) >= limit:
                break
        return incidents

    def rematch_all_claims(self, client_id: str) -> None:
        client = self.get_client(client_id)
        with self.database.connection() as connection:
            rows = connection.execute("SELECT * FROM claims").fetchall()
        matched_claim_ids: set[str] = set()
        for claim in (_row_claim(row) for row in rows):
            if match_claim(claim, client) is None:
                continue
            matched_claim_ids.add(claim["id"])
            self._match_claim(claim, [client])

        # Remove only untouched alerts that no longer match the edited profile.
        # Reviewed alerts and any record with dependent analyst/evidence artifacts
        # remain available as workflow history.
        with self.database.connection() as connection:
            candidates = connection.execute(
                "SELECT id, claim_id, status FROM alerts WHERE client_id = ?",
                (client_id,),
            ).fetchall()
            for alert in candidates:
                if alert["claim_id"] in matched_claim_ids or alert["status"] != "new":
                    continue
                has_artifacts = connection.execute(
                    """SELECT
                           EXISTS(SELECT 1 FROM notification_drafts WHERE alert_id = ?) OR
                           EXISTS(SELECT 1 FROM alert_ai_assessments WHERE alert_id = ?) OR
                           EXISTS(SELECT 1 FROM analyst_feedback WHERE alert_id = ?) OR
                           EXISTS(SELECT 1 FROM capture_jobs WHERE alert_id = ?) OR
                           EXISTS(SELECT 1 FROM ai_jobs WHERE destination = 'alerts' AND target_id = ?)
                           AS present""",
                    (alert["id"],) * 5,
                ).fetchone()["present"]
                if not has_artifacts:
                    connection.execute("DELETE FROM alerts WHERE id = ?", (alert["id"],))

    def _match_claim(self, claim: dict, clients: list[dict] | None = None) -> None:
        for client in clients or self.list_clients():
            result = match_claim(claim, client)
            if result is None:
                continue
            with self.database.connection() as connection:
                connection.execute(
                    """
                    INSERT INTO alerts(
                        id, claim_id, client_id, severity, score, reason,
                        evidence, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'new', ?)
                    ON CONFLICT(claim_id, client_id) DO UPDATE SET
                        severity = excluded.severity,
                        score = excluded.score,
                        reason = excluded.reason,
                        evidence = excluded.evidence,
                        updated_at = CASE
                            WHEN alerts.status = 'new' THEN excluded.created_at
                            ELSE alerts.updated_at
                        END
                    WHERE alerts.status = 'new'
                    """,
                    (
                        str(uuid.uuid4()),
                        claim["id"],
                        client["id"],
                        result.severity,
                        result.score,
                        result.reason,
                        result.evidence,
                        iso(utc_now()),
                    ),
                )

    def source_health(self) -> list[dict]:
        with self.database.connection() as connection:
            rows = connection.execute("SELECT * FROM source_health ORDER BY source").fetchall()
            observation_rows = connection.execute(
                """
                SELECT source, COUNT(DISTINCT claim_id) AS stored,
                       COUNT(*) AS observation_versions,
                       MIN(COALESCE(published_at, received_at, created_at)) AS oldest,
                       MAX(COALESCE(published_at, received_at, created_at)) AS newest
                FROM source_observations
                GROUP BY source
                """
            ).fetchall()
            catalog_stored = connection.execute("SELECT COUNT(*) FROM dls_targets").fetchone()[0]
        observation_stats = {row["source"]: dict(row) for row in observation_rows}
        result: list[dict] = []
        for row in rows:
            item = dict(row)
            stats = observation_stats.get(item["source"], {})
            item["observations_stored"] = (
                catalog_stored if item["source"] == "dls_catalog" else stats.get("stored", 0)
            )
            item["oldest_observation_at"] = stats.get("oldest")
            item["newest_observation_at"] = stats.get("newest")
            item["observation_versions_stored"] = stats.get("observation_versions", 0)
            item["coverage_gaps"] = decode_json(item.pop("coverage_gaps_json", "[]"))
            result.append(item)
        return result

    def intelligence(
        self,
        *,
        days: int = 30,
        query: str = "",
        actor: str = "",
        country: str = "",
        industry: str = "",
        publication_status: str = "",
        page: int = 1,
        page_size: int = 50,
    ) -> dict:
        now = utc_now()
        query_floor = None
        if days:
            query_floor = min(
                now - timedelta(days=max(366, days * 2)),
                now - timedelta(days=366),
            )
        with self.database.connection() as connection:
            if query_floor:
                rows = connection.execute(
                    "SELECT * FROM claims WHERE observed_at >= ? ORDER BY observed_at DESC",
                    (iso(query_floor),),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM claims ORDER BY observed_at DESC"
                ).fetchall()
            client_rows = connection.execute(
                "SELECT countries_json, cities_json FROM clients"
            ).fetchall()
            focus_regions_row = connection.execute(
                "SELECT value FROM app_settings WHERE key = 'focus_regions'"
            ).fetchone()
        raw_claims = [_row_claim(row) for row in rows]
        claims = _deduplicate_claims(raw_claims)
        cutoff = now - timedelta(days=days) if days else None
        monitored_geographies = sorted(
            {
                geography.strip()
                for geography in (
                    [
                        item
                        for row in client_rows
                        for item in (
                            decode_json(row["countries_json"]) + decode_json(row["cities_json"])
                        )
                    ]
                    + decode_json(focus_regions_row["value"] if focus_regions_row else "[]")
                )
                if geography.strip()
            },
            key=str.casefold,
        )

        def observed_at(claim: dict) -> datetime:
            value = claim["published_at"] or claim["discovered_at"] or claim["received_at"]
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

        def claim_country(claim: dict) -> str:
            return claim["country"] or claim["ai_country"]

        def claim_industry(claim: dict) -> str:
            return claim["industry"] or claim["ai_industry"]

        claims.sort(key=observed_at, reverse=True)

        period_claims = [
            claim for claim in claims if cutoff is None or observed_at(claim) >= cutoff
        ]
        facets = {
            "actors": sorted({c["threat_actor"] for c in period_claims if c["threat_actor"]}),
            "countries": sorted({claim_country(c) for c in period_claims if claim_country(c)}),
            "industries": sorted({claim_industry(c) for c in period_claims if claim_industry(c)}),
            "statuses": sorted(
                {c["publication_status"] for c in period_claims if c["publication_status"]}
            ),
        }
        needle = query.casefold().strip()

        def apply_filters(candidates: list[dict]) -> list[dict]:
            selected = []
            for claim in candidates:
                haystack = " ".join(
                    [
                        claim["title"],
                        claim["threat_actor"],
                        claim["description"],
                        claim_country(claim),
                        claim_industry(claim),
                        claim["ai_description"],
                        " ".join(claim["domains"]),
                    ]
                ).casefold()
                if needle and needle not in haystack:
                    continue
                if actor and claim["threat_actor"] != actor:
                    continue
                if country and claim_country(claim) != country:
                    continue
                if industry and claim_industry(claim) != industry:
                    continue
                if publication_status and claim["publication_status"] != publication_status:
                    continue
                selected.append(claim)
            return selected

        filtered = apply_filters(period_claims)
        observation_counts: dict[str, int] = {}
        filtered_claim_ids = [
            claim_id for claim in filtered for claim_id in claim["source_claim_ids"]
        ]
        with self.database.connection() as connection:
            for offset in range(0, len(filtered_claim_ids), 800):
                chunk = filtered_claim_ids[offset : offset + 800]
                placeholders = ",".join("?" for _ in chunk)
                observation_counts.update(
                    {
                        row["claim_id"]: row["count"]
                        for row in connection.execute(
                            f"""SELECT claim_id, COUNT(*) AS count
                                FROM source_observations
                                WHERE claim_id IN ({placeholders})
                                GROUP BY claim_id""",  # noqa: S608
                            chunk,
                        )
                    }
                )
        raw_source_records = sum(
            max(
                claim["source_record_count"],
                sum(observation_counts.get(claim_id, 0) for claim_id in claim["source_claim_ids"]),
            )
            for claim in filtered
        )
        comparison_days = days or 30
        current_start = now - timedelta(days=comparison_days)
        previous_start = current_start - timedelta(days=comparison_days)
        comparison_current = apply_filters(
            [claim for claim in claims if observed_at(claim) >= current_start]
        )
        comparison_previous = apply_filters(
            [claim for claim in claims if previous_start <= observed_at(claim) < current_start]
        )

        def growth_percent(current: int, previous: int) -> float | None:
            if previous == 0:
                return 0.0 if current == 0 else None
            return round((current - previous) / previous * 100, 1)

        current_groups = Counter(c["threat_actor"] or "Unknown" for c in comparison_current)
        previous_groups = Counter(c["threat_actor"] or "Unknown" for c in comparison_previous)
        group_growth = []
        for name in set(current_groups) | set(previous_groups):
            current_count = current_groups[name]
            previous_count = previous_groups[name]
            group_growth.append(
                {
                    "name": name,
                    "current_count": current_count,
                    "previous_count": previous_count,
                    "change": current_count - previous_count,
                    "growth_percent": growth_percent(current_count, previous_count),
                }
            )
        group_growth.sort(key=lambda item: (item["current_count"], item["change"]), reverse=True)

        def geography_matches(claim: dict, geography: str) -> bool:
            claim_geo = " ".join(claim_country(claim).casefold().replace(",", " ").split())
            target = " ".join(geography.casefold().replace(",", " ").split())
            return bool(
                claim_geo
                and target
                and (claim_geo == target or target in claim_geo or claim_geo in target)
            )

        monitored_region_growth = []
        for geography in monitored_geographies:
            current_count = sum(geography_matches(claim, geography) for claim in comparison_current)
            previous_count = sum(
                geography_matches(claim, geography) for claim in comparison_previous
            )
            total_count = sum(geography_matches(claim, geography) for claim in filtered)
            monitored_region_growth.append(
                {
                    "name": geography,
                    "count": total_count,
                    "current_count": current_count,
                    "previous_count": previous_count,
                    "change": current_count - previous_count,
                    "growth_percent": growth_percent(current_count, previous_count),
                }
            )
        monitored_region_growth.sort(
            key=lambda item: (item["current_count"], item["count"]), reverse=True
        )

        group_counts = Counter(c["threat_actor"] or "Unknown" for c in filtered)
        country_counts = Counter(claim_country(c) or "Unknown" for c in filtered)
        industry_counts = Counter(claim_industry(c) or "Unknown" for c in filtered)
        source_counts = Counter(c["source"] for c in filtered)
        trend_claims = apply_filters(claims)
        month_keys = []
        for offset in range(11, -1, -1):
            absolute_month = now.year * 12 + (now.month - 1) - offset
            month_keys.append(f"{absolute_month // 12:04d}-{absolute_month % 12 + 1:02d}")
        month_counts = Counter(
            observed_at(claim).strftime("%Y-%m")
            for claim in trend_claims
            if observed_at(claim).strftime("%Y-%m") in month_keys
        )
        attack_month_counts: Counter[str] = Counter()
        attack_dated_claims = 0
        for claim in trend_claims:
            if not claim.get("attack_date"):
                continue
            try:
                attacked_at = datetime.fromisoformat(
                    claim["attack_date"].replace("Z", "+00:00")
                )
            except (TypeError, ValueError):
                continue
            attack_dated_claims += 1
            month = attacked_at.strftime("%Y-%m")
            if month in month_keys:
                attack_month_counts[month] += 1
        if days:
            denominator = days
        elif filtered:
            span = max(observed_at(c) for c in filtered) - min(observed_at(c) for c in filtered)
            denominator = max(1, span.days + 1)
        else:
            denominator = 1
        start = (page - 1) * page_size
        return {
            "period_days": days,
            "total": len(filtered),
            "raw_source_records": raw_source_records,
            "duplicates_collapsed": max(0, raw_source_records - len(filtered)),
            "daily_average": round(len(filtered) / denominator, 1),
            "countries_affected": len({claim_country(c) for c in filtered if claim_country(c)}),
            "active_groups": len({c["threat_actor"] for c in filtered if c["threat_actor"]}),
            "growth_basis_days": comparison_days,
            "overall_growth": {
                "current_count": len(comparison_current),
                "previous_count": len(comparison_previous),
                "change": len(comparison_current) - len(comparison_previous),
                "growth_percent": growth_percent(len(comparison_current), len(comparison_previous)),
            },
            "group_growth": group_growth[:15],
            "monitored_geographies": monitored_geographies,
            "monitored_region_growth": monitored_region_growth,
            "top_groups": [
                {"name": name, "count": count} for name, count in group_counts.most_common(10)
            ],
            "top_countries": [
                {
                    "name": name,
                    "count": count,
                    "is_monitored": any(
                        geography.casefold() in name.casefold()
                        or name.casefold() in geography.casefold()
                        for geography in monitored_geographies
                    ),
                }
                for name, count in country_counts.most_common(10)
            ],
            "top_industries": [
                {"name": name, "count": count} for name, count in industry_counts.most_common(10)
            ],
            "sources": [
                {"name": name, "count": count} for name, count in source_counts.most_common()
            ],
            "monthly_trend": [
                {"month": month, "count": month_counts[month]} for month in month_keys
            ],
            "monthly_attack_trend": [
                {"month": month, "count": attack_month_counts[month]} for month in month_keys
            ],
            "attack_date_coverage": round(
                attack_dated_claims / len(trend_claims) * 100, 1
            )
            if trend_claims
            else 0.0,
            "counting_method": (
                "Normalized threat-actor and victim pairs are deduplicated across sources. "
                "First-publication trend uses the earliest retained publication/discovery date; "
                "estimated-attack trend includes only records with a source-reported attack date."
            ),
            "facets": facets,
            "page": page,
            "page_size": page_size,
            "pages": max(1, (len(filtered) + page_size - 1) // page_size),
            "victims": filtered[start : start + page_size],
            "generated_at": iso(utc_now()),
        }

    def sync_dls_catalog(
        self, locations: list[DlsLocationInput], *, retire_missing: bool = False
    ) -> int:
        synced_at = iso(utc_now())
        created = 0
        with self.database.connection() as connection:
            if retire_missing:
                # The table is a derived public-catalogue snapshot. Retire the
                # previous union before applying a complete multi-source union;
                # partial upstream results call this method with False so a
                # transient provider failure cannot retire the other source's
                # last-known mirrors.
                connection.execute(
                    """
                    UPDATE dls_targets
                    SET enabled = 0, available = 0, last_catalog_sync_at = ?
                    """,
                    (synced_at,),
                )
            for location in locations:
                target_id = hashlib.sha256(location.fqdn.encode()).hexdigest()[:32]
                existing = connection.execute(
                    "SELECT id FROM dls_targets WHERE fqdn = ?", (location.fqdn,)
                ).fetchone()
                connection.execute(
                    """
                    INSERT INTO dls_targets(
                        id, group_name, description, fqdn, location_type, title,
                        enabled, available, source, first_seen_at, last_catalog_sync_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(fqdn) DO UPDATE SET
                        group_name = excluded.group_name,
                        description = excluded.description,
                        location_type = excluded.location_type,
                        title = excluded.title,
                        enabled = excluded.enabled,
                        available = excluded.available,
                        source = excluded.source,
                        last_catalog_sync_at = excluded.last_catalog_sync_at
                    """,
                    (
                        target_id,
                        location.group_name,
                        location.description,
                        location.fqdn,
                        location.location_type,
                        location.title,
                        int(location.enabled),
                        int(location.available),
                        location.source,
                        synced_at,
                        synced_at,
                    ),
                )
                created += int(existing is None)
        return created

    def list_dls_targets(self, query: str = "", limit: int = 500) -> list[dict]:
        with self.database.connection() as connection:
            if query.strip():
                needle = f"%{query.strip()}%"
                rows = connection.execute(
                    """
                    SELECT * FROM dls_targets
                    WHERE group_name LIKE ? OR title LIKE ? OR fqdn LIKE ?
                    ORDER BY available DESC, group_name COLLATE NOCASE
                    LIMIT ?
                    """,
                    (needle, needle, needle, limit),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT * FROM dls_targets
                    ORDER BY available DESC, group_name COLLATE NOCASE
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
        return [_row_dls_target(row) for row in rows]

    def update_dls_target(self, target_id: str, capture_enabled: bool) -> dict:
        with self.database.connection() as connection:
            result = connection.execute(
                "UPDATE dls_targets SET capture_enabled = ? WHERE id = ?",
                (int(capture_enabled), target_id),
            )
            if result.rowcount == 0:
                raise KeyError(target_id)
            row = connection.execute(
                "SELECT * FROM dls_targets WHERE id = ?", (target_id,)
            ).fetchone()
        return _row_dls_target(row)

    def update_dls_targets(self, target_ids: list[str], capture_enabled: bool) -> dict:
        unique_ids = list(dict.fromkeys(target_ids))
        if not unique_ids:
            return {"requested": 0, "updated": 0, "capture_enabled": capture_enabled}
        with self.database.connection() as connection:
            result = connection.executemany(
                "UPDATE dls_targets SET capture_enabled = ? WHERE id = ?",
                [(int(capture_enabled), target_id) for target_id in unique_ids],
            )
        return {
            "requested": len(unique_ids),
            "updated": result.rowcount,
            "capture_enabled": capture_enabled,
        }

    def queue_capture(
        self,
        target_id: str,
        worker_configured: bool,
        *,
        alert_id: str = "",
        claim_id: str = "",
        victim_name: str = "",
        capture_scope: str = "site_overview",
    ) -> dict:
        target = next(
            (item for item in self.list_dls_targets(limit=5000) if item["id"] == target_id),
            None,
        )
        if target is None:
            raise KeyError(target_id)
        if not is_public_evidence_location(target["title"], target["location_type"]):
            raise PermissionError(
                "This catalog entry is a negotiation or recovery portal, not a public victim list"
            )
        if not target["capture_enabled"]:
            raise PermissionError("Enable isolated capture for this site first")
        with self.database.connection() as connection:
            mode_row = connection.execute(
                "SELECT value FROM app_settings WHERE key = 'operating_mode'"
            ).fetchone()
        if mode_row is None or mode_row["value"] != "active":
            raise PermissionError("Switch monitoring to Active mode before capturing a direct site")
        if not worker_configured:
            raise RuntimeError("The isolated Kali capture worker is not configured")
        job_id = str(uuid.uuid4())
        with self.database.connection() as connection:
            connection.execute(
                """INSERT INTO capture_jobs(
                       id, target_id, status, requested_at, alert_id, claim_id,
                       victim_name, capture_scope
                   ) VALUES (?, ?, 'queued', ?, ?, ?, ?, ?)""",
                (
                    job_id,
                    target_id,
                    iso(utc_now()),
                    alert_id[:80],
                    claim_id[:80],
                    victim_name[:240],
                    capture_scope[:40],
                ),
            )
        return self.get_capture_job(job_id)

    def queue_alert_capture(self, alert_id: str, worker_configured: bool) -> dict:
        alert = self.get_alert(alert_id)
        actor_key = actor_identity_key(alert["threat_actor"])
        candidates = [
            target
            for target in self.list_dls_targets(limit=5000)
            if actor_identity_key(target["group_name"]) == actor_key
        ]
        if not candidates:
            raise LookupError("No direct-site catalog entry matches this threat actor")
        target = next(
            (
                item
                for item in candidates
                if item["capture_enabled"] and item["available"] and item["enabled"]
            ),
            next(
                (item for item in candidates if item["capture_enabled"] and item["enabled"]),
                None,
            ),
        )
        if target is None:
            raise PermissionError(
                "Allowlist a matching direct site before capturing evidence for this alert"
            )
        return self.queue_capture(
            target["id"],
            worker_configured,
            alert_id=alert_id,
            claim_id=alert["claim_id"],
            victim_name=alert["claim_title"],
            capture_scope="flagged_victim",
        )

    def capture_jobs_for_alert(self, alert_id: str, limit: int = 20) -> list[dict]:
        with self.database.connection() as connection:
            rows = connection.execute(
                """SELECT j.*, t.group_name,
                          substr(t.fqdn, 1, 12) || '…' || substr(t.fqdn, -12) AS address_hint
                   FROM capture_jobs j JOIN dls_targets t ON t.id = j.target_id
                   WHERE j.alert_id = ? ORDER BY j.requested_at DESC LIMIT ?""",
                (alert_id, limit),
            ).fetchall()
        return [_row_capture_job(row) for row in rows]

    def get_capture_job(self, job_id: str) -> dict:
        with self.database.connection() as connection:
            row = connection.execute(
                """
                SELECT j.*, t.group_name, t.address_hint
                FROM capture_jobs j
                JOIN (
                    SELECT *, substr(fqdn, 1, 12) || '…' || substr(fqdn, -12) AS address_hint
                    FROM dls_targets
                ) t ON t.id = j.target_id
                WHERE j.id = ?
                """,
                (job_id,),
            ).fetchone()
        if row is None:
            raise KeyError(job_id)
        return _row_capture_job(row)

    def claim_next_capture_job(self) -> dict | None:
        """Atomically reserve the oldest queued job for the local Kali worker."""
        with self.database.connection() as connection:
            row = connection.execute(
                """
                SELECT j.id, j.target_id, j.alert_id, j.claim_id, j.victim_name,
                       j.capture_scope, t.fqdn, t.group_name
                FROM capture_jobs j JOIN dls_targets t ON t.id = j.target_id
                WHERE j.status = 'queued' AND t.capture_enabled = 1 AND t.enabled = 1
                  AND EXISTS (
                    SELECT 1 FROM app_settings s
                    WHERE s.key = 'operating_mode' AND s.value = 'active'
                  )
                ORDER BY j.requested_at ASC LIMIT 1
                """
            ).fetchone()
            if row is None:
                return None
            started_at = iso(utc_now())
            updated = connection.execute(
                "UPDATE capture_jobs SET status = 'running', started_at = ?, error = '' WHERE id = ? AND status = 'queued'",
                (started_at, row["id"]),
            )
            if updated.rowcount != 1:
                return None
        result = dict(row)
        result["started_at"] = started_at
        return result

    def requeue_interrupted_capture_jobs(self) -> int:
        """Return jobs left running by an unclean shutdown to the queue."""
        with self.database.connection() as connection:
            result = connection.execute(
                "UPDATE capture_jobs SET status = 'queued', started_at = NULL, error = 'Requeued after worker restart' WHERE status = 'running'"
            )
        return result.rowcount

    def clear_capture_jobs(self, statuses: list[str]) -> dict:
        """Permanently remove only non-evidence capture job states.

        Running work and completed evidence are deliberately outside the
        allowed status set. Queued rows contain no evidence artifacts, while
        failed workers clean partial artifacts before recording failure.
        """
        selected = list(dict.fromkeys(statuses))
        allowed = {"queued", "failed"}
        if not selected or any(status not in allowed for status in selected):
            raise ValueError("Only queued and failed capture jobs can be cleared")
        placeholders = ",".join("?" for _ in selected)
        with self.database.connection() as connection:
            counts = {
                row["status"]: int(row["count"])
                for row in connection.execute(
                    # Placeholder text is generated locally from an allowlisted
                    # status set; status values remain bound.
                    f"""SELECT status, COUNT(*) AS count
                        FROM capture_jobs
                        WHERE status IN ({placeholders})
                        GROUP BY status""",  # noqa: S608
                    selected,
                ).fetchall()
            }
            deleted = connection.execute(
                f"DELETE FROM capture_jobs WHERE status IN ({placeholders})",  # noqa: S608
                selected,
            ).rowcount
        return {
            "statuses": selected,
            "deleted": deleted,
            "deleted_by_status": {
                status: counts.get(status, 0) for status in selected
            },
        }

    def _capture_evidence_assessment(self, target_id: str, text: str) -> dict:
        """Classify retained text and identify locally observed victim candidates.

        Candidate extraction is deterministic and deliberately conservative. A
        candidate means only that a retained claim name or domain is visible in
        the captured page; it does not confirm compromise or attribution.
        """
        compact_text = " ".join(text.casefold().split())
        normalized_text = " " + re.sub(r"[^a-z0-9]+", " ", compact_text).strip() + " "
        observed_domains = {
            domain.casefold().strip(".")
            for domain in extract_domains(text)
            if domain
            and not domain.casefold().endswith(".onion")
            and domain.casefold() not in CAPTURE_IGNORED_DOMAINS
        }
        with self.database.connection() as connection:
            target = connection.execute(
                "SELECT group_name FROM dls_targets WHERE id = ?", (target_id,)
            ).fetchone()
            claim_rows = connection.execute(
                """SELECT id, title, threat_actor, published_at, discovered_at,
                          received_at, domains_json
                   FROM claims
                   ORDER BY COALESCE(published_at, discovered_at, received_at) DESC
                   LIMIT 5000"""
            ).fetchall()
        actor_key = normalize_name(target["group_name"]) if target else ""
        candidates: list[dict] = []
        claimed_domains: set[str] = set()
        seen: set[str] = set()
        for row in claim_rows:
            if normalize_name(row["threat_actor"]) != actor_key:
                continue
            title = " ".join(str(row["title"] or "").split())
            title_key = re.sub(r"[^a-z0-9]+", " ", title.casefold()).strip()
            domains = {
                str(domain).casefold().strip(".")
                for domain in decode_json(row["domains_json"])
                if str(domain).strip()
            }
            domain_matches = sorted(domains & observed_domains)
            title_matches = len(title_key) >= 8 and f" {title_key} " in normalized_text
            if not domain_matches and not title_matches:
                continue
            key = normalize_name(title) or (domain_matches[0] if domain_matches else "")
            if not key or key in seen:
                continue
            seen.add(key)
            claimed_domains.update(domain_matches)
            context = _capture_text_context(text, [title, *domain_matches, *sorted(domains)])
            leak_size = extract_labelled_leak_size(context, source="dls_dom:capture_evidence")
            candidates.append(
                {
                    "claim_id": row["id"],
                    "name": title,
                    "domain": domain_matches[0] if domain_matches else "",
                    "published_at": row["published_at"]
                    or row["discovered_at"]
                    or row["received_at"]
                    or "",
                    "source": "retained_claim_match",
                    "confidence": "high" if domain_matches else "medium",
                    "leak_size": leak_size.raw if leak_size else "",
                    "leak_size_bytes": leak_size.bytes if leak_size else None,
                }
            )
            if len(candidates) >= 25:
                break
        if len(candidates) < 25:
            last_observed_date = ""
            expect_label = False
            generic_labels = {
                "blog",
                "contact",
                "data breach",
                "home",
                "latest victims",
                "news",
                "published",
                "recent posts",
                "victims",
            }
            for raw_line in text.splitlines():
                line = " ".join(raw_line.split()).strip(" -|•")
                if not line or line.casefold().startswith("---"):
                    continue
                for date_format in ("%d %B %Y", "%d %b %Y", "%Y-%m-%d"):
                    try:
                        last_observed_date = datetime.strptime(line, date_format).date().isoformat()
                        break
                    except ValueError:
                        continue
                status_token = re.sub(r"[^a-z]", "", line.casefold())
                if status_token in {"new", "listed", "published", "victim"}:
                    expect_label = True
                    continue
                if not expect_label:
                    continue
                expect_label = False
                normalized_line = normalize_name(line)
                if (
                    len(line) < 4
                    or len(line) > 180
                    or normalized_line in generic_labels
                    or line.casefold().startswith(("http", "www."))
                    or "@" in line
                    or "/" in line
                ):
                    continue
                key = normalized_line
                if not key or key in seen:
                    continue
                seen.add(key)
                candidates.append(
                    {
                        "name": line,
                        "domain": "",
                        "published_at": last_observed_date,
                        "source": "capture_label",
                        "confidence": "medium",
                    }
                )
                if len(candidates) >= 25:
                    break
        if len(candidates) < 25:
            domain_order = sorted(
                observed_domains - claimed_domains,
                key=lambda value: (
                    compact_text.find(value) if value in compact_text else len(compact_text)
                ),
            )
            for domain in domain_order:
                key = normalize_name(domain)
                if not key or key in seen:
                    continue
                seen.add(key)
                candidates.append(
                    {
                        "name": domain,
                        "domain": domain,
                        "published_at": "",
                        "source": "capture_domain",
                        "confidence": "medium",
                    }
                )
                if len(candidates) >= 25:
                    break

        interstitial = next(
            (
                label
                for marker, label in CAPTURE_INTERSTITIAL_MARKERS.items()
                if marker in compact_text[:5_000]
            ),
            "",
        )
        if candidates:
            return {
                "evidence_readiness": "ready",
                "readiness_reason": (
                    f"Captured evidence contains {len(candidates)} locally observed "
                    "victim candidate(s); analyst verification is required"
                ),
                "victim_candidates": candidates,
            }
        if interstitial:
            return {
                "evidence_readiness": "not_ready",
                "readiness_reason": f"Capture remained on {interstitial}",
                "victim_candidates": [],
            }
        if len(compact_text) < 160:
            return {
                "evidence_readiness": "not_ready",
                "readiness_reason": "Capture did not contain enough readable victim-list text",
                "victim_candidates": [],
            }
        return {
            "evidence_readiness": "review",
            "readiness_reason": (
                "Page evidence was retained, but no victim name or domain could be "
                "identified deterministically"
            ),
            "victim_candidates": [],
        }

    def assess_capture_job_evidence(self, job_id: str) -> dict:
        job = self.get_capture_job(job_id)
        if job["status"] != "completed":
            return job
        relative = str(job.get("text_path") or "")
        text_file = (self.capture_dir / relative).resolve() if relative else None
        if (
            text_file is None
            or not text_file.is_relative_to(self.capture_dir.resolve())
            or not text_file.is_file()
        ):
            assessment = {
                "evidence_readiness": "not_ready",
                "readiness_reason": "Capture text evidence is missing",
                "victim_candidates": [],
            }
        else:
            text = text_file.read_text(encoding="utf-8", errors="replace")
            assessment = self._capture_evidence_assessment(job["target_id"], text)
        with self.database.connection() as connection:
            connection.execute(
                """UPDATE capture_jobs
                   SET evidence_readiness = ?, readiness_reason = ?,
                       victim_candidates_json = ?
                   WHERE id = ? AND status = 'completed'""",
                (
                    assessment["evidence_readiness"],
                    assessment["readiness_reason"][:500],
                    json.dumps(assessment["victim_candidates"]),
                    job_id,
                ),
            )
            for candidate in assessment["victim_candidates"]:
                candidate_claim_id = str(candidate.get("claim_id") or "")
                candidate_size = str(candidate.get("leak_size") or "")
                if not candidate_claim_id or not candidate_size:
                    continue
                row = connection.execute(
                    "SELECT leak_size, leak_size_source FROM claims WHERE id = ?",
                    (candidate_claim_id,),
                ).fetchone()
                capture_source = f"dls_dom:capture_job:{job_id}"[:80]
                if row is None or (
                    row["leak_size"]
                    and leak_size_source_priority(row["leak_size_source"])
                    >= leak_size_source_priority(capture_source)
                ):
                    continue
                connection.execute(
                    """UPDATE claims
                       SET leak_size = ?, leak_size_bytes = ?, leak_size_source = ?
                       WHERE id = ?""",
                    (
                        candidate_size,
                        candidate.get("leak_size_bytes"),
                        capture_source,
                        candidate_claim_id,
                    ),
                )
        return self.get_capture_job(job_id)

    def complete_capture_job(
        self,
        job_id: str,
        screenshot_path: Path,
        content_sha256: str,
        *,
        scroll_count: int = 0,
        page_height: int = 0,
        capture_truncated: bool = False,
        coverage_status: str = "not_measured",
        anchor_lines: list[str] | None = None,
        continuity_status: str = "no_baseline",
        continuity_anchor: str = "",
        continuity_page: int = 0,
        pagination_detected: bool = False,
        more_content_suspected: bool = False,
        screenshot_paths: list[Path] | None = None,
        css_blur_element_count: int = 0,
        text_path: Path | None = None,
        text_sha256: str = "",
        extraction_method: str = "",
        duplicate_of_job_id: str = "",
        detected_statuses: list[str] | None = None,
        status_changed: bool = False,
        added_line_count: int = 0,
        removed_line_count: int = 0,
        opsec_status: str = "not_checked",
        tor_preflight_passed: bool = False,
        blocked_request_count: int = 0,
        blocked_popup_count: int = 0,
        blocked_download_count: int = 0,
        opsec_controls: list[str] | None = None,
        victim_match_found: bool = False,
    ) -> dict:
        resolved = screenshot_path.resolve()
        if not resolved.is_relative_to(self.capture_dir.resolve()):
            raise ValueError("Capture evidence must remain inside the configured capture directory")
        if not resolved.is_file():
            raise ValueError("Primary capture screenshot is missing from the evidence directory")
        completed_at = iso(utc_now())
        stored_path = str(resolved.relative_to(self.capture_dir.resolve()))
        resolved_screenshots = screenshot_paths or [screenshot_path]
        stored_screenshot_paths: list[str] = []
        for candidate in resolved_screenshots:
            resolved_candidate = candidate.resolve()
            if not resolved_candidate.is_relative_to(self.capture_dir.resolve()):
                raise ValueError(
                    "Capture evidence must remain inside the configured capture directory"
                )
            if not resolved_candidate.is_file():
                raise ValueError("Capture screenshot is missing from the evidence directory")
            stored_screenshot_paths.append(
                str(resolved_candidate.relative_to(self.capture_dir.resolve()))
            )
        stored_text_path = ""
        if text_path is not None:
            resolved_text = text_path.resolve()
            if not resolved_text.is_relative_to(self.capture_dir.resolve()):
                raise ValueError("Capture text must remain inside the configured capture directory")
            if not resolved_text.is_file():
                raise ValueError("Capture text is missing from the evidence directory")
            stored_text_path = str(resolved_text.relative_to(self.capture_dir.resolve()))
        with self.database.connection() as connection:
            row = connection.execute(
                "SELECT target_id, status FROM capture_jobs WHERE id = ?", (job_id,)
            ).fetchone()
            if row is None:
                raise KeyError(job_id)
            if row["status"] != "running":
                raise ValueError("Capture job is not in the running state")
            updated = connection.execute(
                "UPDATE capture_jobs SET status = 'completed', completed_at = ?, screenshot_path = ?, screenshot_paths_json = ?, segment_count = ?, css_blur_element_count = ?, text_path = ?, content_sha256 = ?, text_sha256 = ?, extraction_method = ?, duplicate_of_job_id = ?, detected_statuses_json = ?, status_changed = ?, added_line_count = ?, removed_line_count = ?, scroll_count = ?, page_height = ?, capture_truncated = ?, coverage_status = ?, anchor_lines_json = ?, continuity_status = ?, continuity_anchor = ?, continuity_page = ?, pagination_detected = ?, more_content_suspected = ?, opsec_status = ?, tor_preflight_passed = ?, blocked_request_count = ?, blocked_popup_count = ?, blocked_download_count = ?, opsec_controls_json = ?, victim_match_found = ?, error = '' WHERE id = ?",
                (
                    completed_at,
                    stored_path,
                    json.dumps(stored_screenshot_paths),
                    len(stored_screenshot_paths),
                    max(0, css_blur_element_count),
                    stored_text_path,
                    content_sha256,
                    text_sha256,
                    extraction_method,
                    duplicate_of_job_id,
                    json.dumps(detected_statuses or []),
                    int(status_changed),
                    max(0, added_line_count),
                    max(0, removed_line_count),
                    max(0, scroll_count),
                    max(0, page_height),
                    int(capture_truncated),
                    coverage_status
                    if coverage_status
                    in {
                        "stable",
                        "scroll_limit",
                        "height_limit",
                        "interaction_limit",
                        "previous_anchor_found",
                        "victim_found",
                    }
                    else "not_measured",
                    json.dumps(anchor_lines or []),
                    continuity_status
                    if continuity_status in {"no_baseline", "matched", "missing", "ocr_unavailable"}
                    else "no_baseline",
                    continuity_anchor[:240],
                    max(0, continuity_page),
                    int(pagination_detected),
                    int(more_content_suspected),
                    opsec_status
                    if opsec_status in {"passed", "failed", "not_checked"}
                    else "not_checked",
                    int(tor_preflight_passed),
                    max(0, blocked_request_count),
                    max(0, blocked_popup_count),
                    max(0, blocked_download_count),
                    json.dumps(opsec_controls or []),
                    int(victim_match_found),
                    job_id,
                ),
            )
            if updated.rowcount != 1:
                raise ValueError("Capture job state changed before completion")
            connection.execute(
                "UPDATE dls_targets SET last_capture_at = ?, last_capture_status = 'completed' WHERE id = ?",
                (completed_at, row["target_id"]),
            )
        return self.assess_capture_job_evidence(job_id)

    def previous_capture_text(self, target_id: str, exclude_job_id: str) -> dict:
        with self.database.connection() as connection:
            row = connection.execute(
                """
                SELECT id, text_path, text_sha256, detected_statuses_json, anchor_lines_json
                FROM capture_jobs
                WHERE target_id = ? AND id != ? AND status = 'completed' AND text_path != ''
                ORDER BY completed_at DESC LIMIT 1
                """,
                (target_id, exclude_job_id),
            ).fetchone()
        if row is None:
            return {
                "id": "",
                "text": "",
                "text_sha256": "",
                "detected_statuses": [],
                "anchor_lines": [],
            }
        text_file = (self.capture_dir / row["text_path"]).resolve()
        text = ""
        if text_file.is_relative_to(self.capture_dir.resolve()) and text_file.is_file():
            text = text_file.read_text(encoding="utf-8", errors="replace")
        return {
            "id": row["id"],
            "text": text,
            "text_sha256": row["text_sha256"],
            "detected_statuses": decode_json(row["detected_statuses_json"]),
            "anchor_lines": decode_json(row["anchor_lines_json"]),
        }

    def fail_capture_job(
        self,
        job_id: str,
        message: str,
        *,
        opsec_status: str = "not_checked",
        tor_preflight_passed: bool = False,
        blocked_request_count: int = 0,
        blocked_popup_count: int = 0,
        blocked_download_count: int = 0,
        opsec_controls: list[str] | None = None,
    ) -> dict:
        completed_at = iso(utc_now())
        safe_message = " ".join(message.split())[:500]
        with self.database.connection() as connection:
            row = connection.execute(
                "SELECT target_id, status FROM capture_jobs WHERE id = ?", (job_id,)
            ).fetchone()
            if row is None:
                raise KeyError(job_id)
            if row["status"] != "running":
                raise ValueError("Capture job is not in the running state")
            updated = connection.execute(
                "UPDATE capture_jobs SET status = 'failed', completed_at = ?, error = ?, evidence_readiness = 'not_ready', readiness_reason = ?, victim_candidates_json = '[]', opsec_status = ?, tor_preflight_passed = ?, blocked_request_count = ?, blocked_popup_count = ?, blocked_download_count = ?, opsec_controls_json = ? WHERE id = ?",
                (
                    completed_at,
                    safe_message,
                    safe_message,
                    opsec_status
                    if opsec_status in {"passed", "failed", "not_checked"}
                    else "not_checked",
                    int(tor_preflight_passed),
                    max(0, blocked_request_count),
                    max(0, blocked_popup_count),
                    max(0, blocked_download_count),
                    json.dumps(opsec_controls or []),
                    job_id,
                ),
            )
            if updated.rowcount != 1:
                raise ValueError("Capture job state changed before failure was recorded")
            connection.execute(
                "UPDATE dls_targets SET last_capture_at = ?, last_capture_status = 'failed' WHERE id = ?",
                (completed_at, row["target_id"]),
            )
        return self.get_capture_job(job_id)

    def capture_screenshot_path(self, job_id: str, page_number: int = 1) -> Path:
        job = self.get_capture_job(job_id)
        paths = job.get("screenshot_paths") or []
        if page_number < 1 or page_number > len(paths):
            raise FileNotFoundError(job_id)
        relative = str(paths[page_number - 1])
        candidate = (self.capture_dir / relative).resolve()
        if not candidate.is_relative_to(self.capture_dir.resolve()) or not candidate.is_file():
            raise FileNotFoundError(job_id)
        return candidate

    def capture_text_path(self, job_id: str) -> Path:
        job = self.get_capture_job(job_id)
        relative = str(job.get("text_path") or "")
        if not relative:
            raise FileNotFoundError(job_id)
        candidate = (self.capture_dir / relative).resolve()
        if not candidate.is_relative_to(self.capture_dir.resolve()) or not candidate.is_file():
            raise FileNotFoundError(job_id)
        return candidate

    def capture_overview(
        self,
        worker_configured: bool,
        query: str = "",
        ocr_configured: bool = False,
        worker_online: bool = False,
    ) -> dict:
        targets = self.list_dls_targets(query=query)
        with self.database.connection() as connection:
            pending_assessments = [
                row["id"]
                for row in connection.execute(
                    """SELECT id FROM capture_jobs
                       WHERE status = 'completed'
                         AND evidence_readiness = 'not_assessed'
                       ORDER BY completed_at DESC LIMIT 200"""
                ).fetchall()
            ]
        for job_id in pending_assessments:
            self.assess_capture_job_evidence(job_id)
        with self.database.connection() as connection:
            job_status_counts = {
                row["status"]: int(row["count"])
                for row in connection.execute(
                    "SELECT status, COUNT(*) AS count FROM capture_jobs GROUP BY status"
                ).fetchall()
            }
            jobs = connection.execute(
                """
                SELECT j.*, t.group_name,
                       substr(t.fqdn, 1, 12) || '…' || substr(t.fqdn, -12) AS address_hint
                FROM capture_jobs j JOIN dls_targets t ON t.id = j.target_id
                ORDER BY requested_at DESC LIMIT 50
                """
            ).fetchall()
        return {
            "worker_configured": worker_configured,
            "worker_online": worker_online,
            "ocr_configured": ocr_configured,
            "evidence_directory": str(self.capture_dir.resolve()),
            "catalog_total": len(targets),
            "available": sum(1 for item in targets if item["available"]),
            "capture_enabled": sum(1 for item in targets if item["capture_enabled"]),
            "job_status_counts": job_status_counts,
            "targets": targets,
            "jobs": [_row_capture_job(row) for row in jobs],
        }

    def mark_source(
        self,
        source: str,
        *,
        status: str,
        message: str,
        received: int = 0,
        latest_record_at: datetime | None = None,
        coverage_status: str | None = None,
        coverage_message: str = "",
        coverage_gaps: list[str] | None = None,
    ) -> None:
        checked = iso(utc_now())
        success = checked if status == "working" else None
        with self.database.connection() as connection:
            connection.execute(
                """
                INSERT INTO source_health(
                    source, status, last_checked_at, last_success_at,
                    latest_record_at, records_received, message
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source) DO UPDATE SET
                    status = excluded.status,
                    last_checked_at = excluded.last_checked_at,
                    last_success_at = COALESCE(excluded.last_success_at, source_health.last_success_at),
                    latest_record_at = COALESCE(excluded.latest_record_at, source_health.latest_record_at),
                    records_received = source_health.records_received + excluded.records_received,
                    message = excluded.message
                """,
                (
                    source,
                    status,
                    checked,
                    success,
                    iso(latest_record_at),
                    received,
                    message,
                ),
            )
            if coverage_status is not None:
                connection.execute(
                    """
                    UPDATE source_health
                    SET coverage_status = ?, coverage_message = ?,
                        coverage_checked_at = ?, coverage_gaps_json = ?
                    WHERE source = ?
                    """,
                    (
                        coverage_status,
                        coverage_message,
                        checked,
                        json.dumps(coverage_gaps or []),
                        source,
                    ),
                )

    def dashboard(self) -> dict:
        alerts = self.list_alerts(20)
        claims = self.list_claims(20)
        today = datetime.now(timezone.utc).date().isoformat()
        with self.database.connection() as connection:
            client_count = connection.execute("SELECT COUNT(*) FROM clients").fetchone()[0]
            claims_today = connection.execute(
                "SELECT COUNT(*) FROM claims WHERE substr(received_at, 1, 10) = ?", (today,)
            ).fetchone()[0]
        daily_focus = self.daily_focus_victims(hours=24, limit=8)
        return {
            "urgent_alerts": sum(
                1
                for alert in alerts
                if alert["status"] == "new" and alert["severity"] in {"critical", "high"}
            ),
            "awaiting_review": sum(
                1 for alert in alerts if alert["status"] == "new" and alert["severity"] == "review"
            ),
            "claims_today": claims_today,
            "monitored_clients": client_count,
            "new_alerts": alerts[:5],
            "recent_claims": claims[:8],
            "focus_regions": daily_focus["focus_regions"],
            "daily_focus_count": daily_focus["count"],
            "daily_focus_victims": daily_focus["items"],
            "sources": self.source_health(),
            "generated_at": iso(utc_now()),
        }

    def seed_demo(self) -> dict:
        if not self.list_clients():
            self.create_client(
                ClientCreate(
                    canonical_name="Meridian Harbour Group",
                    primary_domain="meridianharbour.example",
                    country="Hong Kong",
                    industry="Financial services",
                    priority="critical",
                    aliases=["Meridian Harbour"],
                )
            )
        demo_claims = [
            ClaimInput(
                source="sample",
                source_record_id="sample-001",
                threat_actor="Black Quartz",
                title="Meridian Harbour Group",
                description="The actor alleges that data associated with meridianharbour.example was obtained.",
                discovered_at=utc_now(),
                country="Hong Kong",
                industry="Financial services",
                domains=["meridianharbour.example"],
                raw={"synthetic": True},
            ),
            ClaimInput(
                source="sample",
                source_record_id="sample-002",
                threat_actor="The Gentlemen",
                title="Rosenfeld Precision Works",
                description="A public ransomware claim recorded for interface demonstration.",
                discovered_at=utc_now(),
                country="Germany",
                industry="Manufacturing",
                raw={"synthetic": True},
            ),
        ]
        for claim in demo_claims:
            self.ingest(claim)
        self.mark_source(
            "ransomlook", status="working", message="Connected successfully", received=2
        )
        self.mark_source(
            "ransomfeed", status="working", message="Connected successfully", received=1
        )
        self.mark_source(
            "ransomware_live",
            status="working",
            message="Connected successfully",
            received=1,
        )
        return self.dashboard()

    def _store_source_observation(
        self,
        payload: ClaimInput,
        claim_id: str,
        received_at: datetime,
    ) -> bool:
        observation_key = _observation_key(payload)
        with self.database.connection() as connection:
            existing = connection.execute(
                "SELECT id FROM source_observations WHERE observation_key = ?",
                (observation_key,),
            ).fetchone()
        if existing is not None:
            return False

        observation_id = str(uuid.uuid4())
        path = self._archive(payload, observation_id, received_at)
        content_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        with self.database.connection() as connection:
            result = connection.execute(
                """
                INSERT OR IGNORE INTO source_observations(
                    id, observation_key, claim_id, source, source_record_id,
                    source_url, published_at, received_at, raw_path,
                    content_sha256, parser_version, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'extortsignal-0.2', ?)
                """,
                (
                    observation_id,
                    observation_key,
                    claim_id,
                    payload.source,
                    payload.source_record_id,
                    payload.source_url,
                    iso(payload.published_at or payload.discovered_at),
                    iso(received_at),
                    str(path),
                    content_sha256,
                    iso(received_at),
                ),
            )
            if result.rowcount:
                connection.execute(
                    """
                    UPDATE claims
                    SET raw_path = CASE
                        WHEN raw_path = '' THEN ?
                        WHEN source = ? AND source_record_id = ? THEN ?
                        ELSE raw_path
                    END
                    WHERE id = ?
                    """,
                    (
                        str(path),
                        payload.source,
                        payload.source_record_id,
                        str(path),
                        claim_id,
                    ),
                )
                return True
        path.unlink(missing_ok=True)
        return False

    def _archive(self, payload: ClaimInput, archive_id: str, received_at: datetime) -> Path:
        target_dir = (
            self.raw_dir
            / payload.source
            / f"{received_at.year:04d}"
            / f"{received_at.month:02d}"
            / f"{received_at.day:02d}"
        )
        target_dir.mkdir(parents=True, exist_ok=True)
        target_dir.chmod(0o700)
        path = target_dir / f"{archive_id}.json.gz"
        with gzip.open(path, "wt", encoding="utf-8") as output:
            json.dump(
                {
                    "received_at": iso(received_at),
                    "record": payload.model_dump(mode="json"),
                },
                output,
                ensure_ascii=False,
                indent=2,
            )
        path.chmod(0o600)
        return path
