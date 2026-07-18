from __future__ import annotations

import gzip
import hashlib
import json
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .database import Database, decode_json, iso
from .matching import extract_domains, match_claim, normalize_name
from .schemas import ClaimInput, ClientCreate, DlsLocationInput, RuntimeSettingsUpdate, utc_now


def _row_client(row) -> dict:
    countries = decode_json(row["countries_json"]) or ([row["country"]] if row["country"] else [])
    industries = decode_json(row["industries_json"]) or ([row["industry"]] if row["industry"] else [])
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
        "threat_actor": row["threat_actor"],
        "title": row["title"],
        "description": row["description"],
        "published_at": row["published_at"] or row["discovered_at"],
        "discovered_at": row["discovered_at"],
        "received_at": row["received_at"],
        "country": row["country"],
        "industry": row["industry"],
        "domains": decode_json(row["domains_json"]),
        "status": row["status"],
        "publication_status": row["publication_status"],
        "leak_size": row["leak_size"],
        "ai_industry": row["ai_industry"],
        "ai_country": row["ai_country"],
        "ai_description": row["ai_description"],
        "ai_organization_type": row["ai_organization_type"],
        "ai_rationale": row["ai_rationale"],
        "ai_sources": decode_json(row["ai_sources_json"]),
        "ai_confidence": row["ai_confidence"],
        "ai_provider": row["ai_provider"],
        "ai_enriched_at": row["ai_enriched_at"],
    }


def _row_dls_target(row) -> dict:
    fqdn = row["fqdn"]
    return {
        "id": row["id"],
        "group_name": row["group_name"],
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


def _claim_fingerprint(payload: ClaimInput) -> str:
    discovered = payload.published_at or payload.discovered_at or utc_now()
    fingerprint_source = "|".join(
        [
            normalize_name(payload.threat_actor),
            normalize_name(payload.title),
            discovered.date().isoformat(),
        ]
    )
    return hashlib.sha256(fingerprint_source.encode()).hexdigest()


class MonitorService:
    def __init__(self, database: Database, raw_dir: Path):
        self.database = database
        self.raw_dir = raw_dir
        self.raw_dir.mkdir(parents=True, exist_ok=True)

    def runtime_settings(self, *, scheduler_process_enabled: bool, worker_configured: bool) -> dict:
        with self.database.connection() as connection:
            values = {row["key"]: row["value"] for row in connection.execute("SELECT key, value FROM app_settings")}
        return {
            "operating_mode": values.get("operating_mode", "passive"),
            "scheduling_enabled": values.get("scheduling_enabled", "true") == "true",
            "public_interval_minutes": int(values.get("public_interval_minutes", "2")),
            "catalog_interval_hours": int(values.get("catalog_interval_hours", "6")),
            "active_interval_minutes": int(values.get("active_interval_minutes", "30")),
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

    def update_runtime_settings(self, payload: RuntimeSettingsUpdate) -> None:
        values = payload.model_dump()
        now = iso(utc_now())
        with self.database.connection() as connection:
            for key, value in values.items():
                stored = json.dumps(value) if isinstance(value, list) else str(value).lower() if isinstance(value, bool) else str(value)
                connection.execute(
                    "INSERT INTO app_settings(key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                    (key, stored, now),
                )

    def mark_schedule_run(self, kind: str) -> None:
        if kind not in {"public", "catalog", "active", "victim_digest"}:
            raise ValueError("Unknown schedule kind")
        now = iso(utc_now())
        with self.database.connection() as connection:
            connection.execute(
                "UPDATE app_settings SET value = ?, updated_at = ? WHERE key = ?",
                (now, now, f"last_{kind}_run_at"),
            )

    def victim_digest_context(self, interval_hours: int = 24) -> dict:
        with self.database.connection() as connection:
            last_row = connection.execute(
                "SELECT value FROM app_settings WHERE key = 'last_victim_digest_at'"
            ).fetchone()
            since = last_row["value"] if last_row and last_row["value"] else None
            if since is None:
                since = iso(utc_now() - timedelta(hours=interval_hours))
            rows = connection.execute(
                "SELECT * FROM claims WHERE received_at > ? ORDER BY received_at DESC",
                (since,),
            ).fetchall()
        claims = [_row_claim(row) for row in rows]
        actors = Counter(claim["threat_actor"] or "Unknown" for claim in claims)
        countries = Counter(claim["country"] or "Unknown" for claim in claims)
        industries = Counter(
            claim["industry"] or claim["ai_industry"] or "Unknown" for claim in claims
        )
        return {
            "since": since,
            "generated_at": iso(utc_now()),
            "count": len(claims),
            "top_actors": [{"name": name, "count": count} for name, count in actors.most_common(5)],
            "top_countries": [{"name": name, "count": count} for name, count in countries.most_common(5)],
            "top_industries": [{"name": name, "count": count} for name, count in industries.most_common(5)],
            "recent_victims": [
                {
                    "name": claim["title"],
                    "actor": claim["threat_actor"],
                    "country": claim["country"],
                    "industry": claim["industry"] or claim["ai_industry"],
                    "published_at": claim["published_at"],
                }
                for claim in claims[:15]
            ],
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
                SELECT t.id FROM dls_targets t
                WHERE t.capture_enabled = 1 AND t.enabled = 1
                  AND NOT EXISTS (
                    SELECT 1 FROM capture_jobs j
                    WHERE j.target_id = t.id AND j.status IN ('queued', 'running')
                  )
                """
            ).fetchall()
        jobs = [self.queue_capture(row["id"], True) for row in targets]
        return {"queued": len(jobs), "blocked": None}

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
            row = connection.execute(
                "SELECT * FROM clients WHERE id = ?", (client_id,)
            ).fetchone()
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

    def list_claims(self, limit: int = 100) -> list[dict]:
        with self.database.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM claims ORDER BY received_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [_row_claim(row) for row in rows]

    def actor_analysis_context(self, actor: str, days: int = 90) -> dict:
        context = self.intelligence_analysis_context("actor", actor, days)
        return {**context, "actor": context["scope_value"]}

    def actor_profiles(self, days: int = 365, limit: int = 250) -> list[dict]:
        """Build bounded analyst profiles from locally observed claims only."""
        with self.database.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM claims ORDER BY COALESCE(published_at, discovered_at, received_at) DESC"
            ).fetchall()
        claims = [_row_claim(row) for row in rows]
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

        normalized_names: dict[str, list[str]] = {}
        for actor in groups:
            key = "".join(character for character in actor.casefold() if character.isalnum())
            normalized_names.setdefault(key, []).append(actor)

        profiles: list[dict] = []
        for actor, actor_claims in groups.items():
            dates = [observed_at(claim) for claim in actor_claims]
            history_dates = [observed_at(claim) for claim in all_groups.get(actor, actor_claims)]
            countries = Counter(claim["country"] for claim in actor_claims if claim["country"])
            industries = Counter(
                claim["industry"] or claim["ai_industry"]
                for claim in actor_claims
                if claim["industry"] or claim["ai_industry"]
            )
            sources = Counter(claim["source"] for claim in actor_claims)
            current_count = sum(date >= current_start for date in history_dates)
            previous_count = sum(previous_start <= date < current_start for date in history_dates)
            change = current_count - previous_count
            growth = None if previous_count == 0 and current_count else (
                0.0 if previous_count == 0 else round(change / previous_count * 100, 1)
            )
            top_countries = [{"name": name, "count": count} for name, count in countries.most_common(3)]
            top_industries = [{"name": name, "count": count} for name, count in industries.most_common(3)]
            country_coverage = sum(bool(claim["country"]) for claim in actor_claims)
            industry_coverage = sum(
                bool(claim["industry"] or claim["ai_industry"]) for claim in actor_claims
            )
            country_text = ", ".join(item["name"] for item in top_countries) or "geographies not supplied"
            industry_text = ", ".join(item["name"] for item in top_industries) or "industries not supplied"
            completeness = (
                sum(bool(claim["country"]) for claim in actor_claims)
                + sum(bool(claim["industry"] or claim["ai_industry"]) for claim in actor_claims)
            ) / max(1, len(actor_claims) * 2)
            confidence = "high" if len(actor_claims) >= 20 and completeness >= 0.6 else (
                "moderate" if len(actor_claims) >= 5 and completeness >= 0.3 else "low"
            )
            key = "".join(character for character in actor.casefold() if character.isalnum())
            aliases = sorted(
                (name for name in normalized_names.get(key, []) if name != actor),
                key=str.casefold,
            )
            period_text = f"the selected {days}-day period" if days else "the locally retained dataset"
            summary = (
                f"{actor} is an actor label associated with {len(actor_claims)} unverified public victim "
                f"claim{'s' if len(actor_claims) != 1 else ''} in {period_text}. Industry was supplied "
                f"for {industry_coverage} claims; the most frequently reported values were {industry_text}. "
                f"Geography was supplied for {country_coverage} claims; the most frequent values were {country_text}."
            )
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
                    "sources": [{"name": name, "count": count} for name, count in sources.most_common()],
                    "possible_aliases": aliases,
                    "confidence": confidence,
                    "caveat": "Observed-claims profile only; origin, motivation, capabilities, access methods and attribution are not established.",
                }
            )
        profiles.sort(key=lambda item: (item["claim_count"], item["last_observed_at"]), reverse=True)
        return profiles[:limit]

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
            "recent_victims": [
                {
                    "name": claim["title"],
                    "threat_actor": claim["threat_actor"],
                    "country": claim["country"],
                    "industry": claim["industry"] or claim["ai_industry"],
                    "organization_type": claim["ai_organization_type"],
                    "published_at": claim["published_at"],
                }
                for claim in victims[:12]
            ],
        }

    def save_actor_ai_analysis(self, actor: str, analysis: dict, provider: str, model: str) -> dict:
        generated_at = iso(utc_now())
        stored = {**analysis, "actor": actor, "provider": provider, "model": model, "generated_at": generated_at}
        with self.database.connection() as connection:
            connection.execute(
                """INSERT INTO actor_ai_analysis(actor, analysis_json, provider, model, generated_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(actor) DO UPDATE SET analysis_json = excluded.analysis_json,
                   provider = excluded.provider, model = excluded.model, generated_at = excluded.generated_at""",
                (actor, json.dumps(stored), provider, model, generated_at),
            )
        return stored

    def save_claim_ai_enrichment(self, claim_id: str, enrichment: dict, provider: str) -> dict:
        enriched_at = iso(utc_now())
        with self.database.connection() as connection:
            result = connection.execute(
                """UPDATE claims SET ai_industry = ?, ai_country = ?, ai_description = ?,
                   ai_organization_type = ?, ai_rationale = ?, ai_sources_json = ?,
                   ai_confidence = ?, ai_provider = ?, ai_enriched_at = ?
                   WHERE id = ?""",
                (
                    enrichment.get("industry", "")[:160],
                    enrichment.get("country_or_region", "")[:120],
                    enrichment.get("brief_description", "")[:600],
                    enrichment.get("organization_type", "")[:120],
                    enrichment.get("rationale", "")[:300],
                    json.dumps(enrichment.get("source_urls", [])[:3]),
                    max(0, min(100, int(enrichment.get("confidence", 0)))),
                    provider[:120],
                    enriched_at,
                    claim_id,
                ),
            )
            if result.rowcount == 0:
                raise KeyError(claim_id)
        return self.get_claim(claim_id)

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
                """
                SELECT a.*, c.title AS claim_title, c.threat_actor, c.source,
                       c.source_url, c.published_at, c.discovered_at, c.received_at,
                       cl.canonical_name AS client_name,
                       cl.primary_domain
                FROM alerts a
                JOIN claims c ON c.id = a.claim_id
                JOIN clients cl ON cl.id = a.client_id
                ORDER BY CASE a.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,
                         a.created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

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
        return next(item for item in self.list_alerts(500) if item["id"] == alert_id)

    def alert_intelligence_context(self, alert_id: str) -> dict:
        try:
            alert = next(item for item in self.list_alerts(500) if item["id"] == alert_id)
        except StopIteration as error:
            raise KeyError(alert_id) from error
        claim = self.get_claim(alert["claim_id"])
        client = self.get_client(alert["client_id"])
        profile = next(
            (
                item for item in self.actor_profiles(days=365)
                if item["actor"].casefold() == alert["threat_actor"].casefold()
            ),
            None,
        )
        reason = alert["reason"].casefold()
        if "subsidiary" in reason:
            scenario = "subsidiary_named"
        elif "third party" in reason:
            scenario = "third_party_named"
        elif any(label in reason for label in ("domain match", "company name", "known alias", "company-name similarity")):
            scenario = "client_named"
        else:
            client_industries = {value.casefold() for value in client["industries"]}
            client_regions = {value.casefold() for value in [*client["countries"], *client["cities"]]}
            claim_industry = (claim["industry"] or claim["ai_industry"]).casefold()
            claim_regions = {value.casefold() for value in (claim["country"], claim["ai_country"]) if value}
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
        }

    def client_notification_draft(self, alert_id: str) -> dict:
        context = self.alert_intelligence_context(alert_id)
        alert = context["alert"]
        observed = alert.get("published_at") or alert.get("discovered_at") or alert["created_at"]
        ingested = alert.get("received_at") or alert["created_at"]
        subject = f"Action requested: unverified ransomware claim referencing {alert['client_name']}"
        body = f"""Dear [Client contact],

We are notifying you of an unverified public ransomware/extortion claim that appears to reference {alert['client_name']}.

What we observed
- Claimed organization: {alert['claim_title']}
- Named threat actor: {alert['threat_actor']}
- Published by source: {observed}
- Ingested into monitoring platform: {ingested}
- Monitoring source: {alert['source']}
- Match basis: {alert['reason']}

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
        return {
            "alert_id": alert_id,
            "subject": subject,
            "body": body,
            "scenario": context["scenario"],
            "generated_by": "standard_template",
            "client_name_sanitized": False,
            "disclaimer": "Review and approve before sending. This draft deliberately treats the claim as unverified.",
        }

    def ingest(self, payload: ClaimInput) -> tuple[dict, bool]:
        fingerprint = _claim_fingerprint(payload)
        with self.database.connection() as connection:
            existing = connection.execute(
                "SELECT * FROM claims WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
            if existing:
                domains = sorted(
                    set(decode_json(existing["domains_json"]))
                    | set(payload.domains)
                    | set(extract_domains(f"{payload.title}\n{payload.description}"))
                )
                publication_status = existing["publication_status"]
                if payload.publication_status == "data_leaked":
                    publication_status = "data_leaked"
                connection.execute(
                    """
                    UPDATE claims SET
                        description = CASE WHEN description = '' THEN ? ELSE description END,
                        published_at = COALESCE(published_at, ?),
                        country = CASE WHEN country = '' THEN ? ELSE country END,
                        industry = CASE WHEN industry = '' THEN ? ELSE industry END,
                        domains_json = ?,
                        publication_status = ?,
                        leak_size = CASE WHEN leak_size = '' THEN ? ELSE leak_size END
                    WHERE id = ?
                    """,
                    (
                        payload.description,
                        iso(payload.published_at or payload.discovered_at),
                        payload.country,
                        payload.industry,
                        json.dumps(domains),
                        publication_status,
                        payload.leak_size,
                        existing["id"],
                    ),
                )
                updated = connection.execute(
                    "SELECT * FROM claims WHERE id = ?", (existing["id"],)
                ).fetchone()
                return _row_claim(updated), False

        claim_id = str(uuid.uuid4())
        received_at = utc_now()
        domains = sorted(
            set(payload.domains)
            | set(extract_domains(f"{payload.title}\n{payload.description}"))
        )
        raw_path = self._archive(payload, claim_id, received_at)
        with self.database.connection() as connection:
            connection.execute(
                """
                INSERT INTO claims(
                    id, fingerprint, source, source_record_id, source_url,
                    threat_actor, title, description, published_at, discovered_at, received_at,
                    country, industry, domains_json, raw_path, status,
                    publication_status, leak_size
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'alleged', ?, ?)
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
                    iso(received_at),
                    payload.country,
                    payload.industry,
                    json.dumps(domains),
                    str(raw_path),
                    payload.publication_status,
                    payload.leak_size,
                ),
            )
        claim = self.get_claim(claim_id)
        self._match_claim(claim)
        return claim, True

    def ingest_many(self, payloads: list[ClaimInput]) -> int:
        """Ingest a feed batch while avoiding one database lookup per duplicate."""
        with self.database.connection() as connection:
            fingerprints = {
                row[0] for row in connection.execute("SELECT fingerprint FROM claims")
            }
        created = 0
        for payload in payloads:
            fingerprint = _claim_fingerprint(payload)
            if fingerprint in fingerprints:
                continue
            _, is_new = self.ingest(payload)
            if is_new:
                fingerprints.add(fingerprint)
                created += 1
        return created

    def get_claim(self, claim_id: str) -> dict:
        with self.database.connection() as connection:
            row = connection.execute(
                "SELECT * FROM claims WHERE id = ?", (claim_id,)
            ).fetchone()
        if row is None:
            raise KeyError(claim_id)
        return _row_claim(row)

    def rematch_all_claims(self, client_id: str) -> None:
        client = self.get_client(client_id)
        with self.database.connection() as connection:
            rows = connection.execute("SELECT * FROM claims").fetchall()
        for claim in (_row_claim(row) for row in rows):
            self._match_claim(claim, [client])

    def _match_claim(self, claim: dict, clients: list[dict] | None = None) -> None:
        for client in clients or self.list_clients():
            result = match_claim(claim, client)
            if result is None:
                continue
            with self.database.connection() as connection:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO alerts(
                        id, claim_id, client_id, severity, score, reason,
                        evidence, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'new', ?)
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
            rows = connection.execute(
                "SELECT * FROM source_health ORDER BY source"
            ).fetchall()
        return [dict(row) for row in rows]

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
        with self.database.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM claims ORDER BY COALESCE(published_at, discovered_at, received_at) DESC"
            ).fetchall()
            client_rows = connection.execute(
                "SELECT countries_json, cities_json FROM clients"
            ).fetchall()
            focus_regions_row = connection.execute(
                "SELECT value FROM app_settings WHERE key = 'focus_regions'"
            ).fetchone()
        claims = [_row_claim(row) for row in rows]
        now = utc_now()
        cutoff = now - timedelta(days=days) if days else None
        monitored_geographies = sorted(
            {
                geography.strip()
                for geography in (
                    [item for row in client_rows for item in (decode_json(row["countries_json"]) + decode_json(row["cities_json"]))]
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

        period_claims = [
            claim for claim in claims if cutoff is None or observed_at(claim) >= cutoff
        ]
        facets = {
            "actors": sorted({c["threat_actor"] for c in period_claims if c["threat_actor"]}),
            "countries": sorted({c["country"] for c in period_claims if c["country"]}),
            "industries": sorted({c["industry"] for c in period_claims if c["industry"]}),
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
                        claim["title"], claim["threat_actor"], claim["description"],
                        claim["country"], claim["industry"], " ".join(claim["domains"]),
                    ]
                ).casefold()
                if needle and needle not in haystack:
                    continue
                if actor and claim["threat_actor"] != actor:
                    continue
                if country and claim["country"] != country:
                    continue
                if industry and claim["industry"] != industry:
                    continue
                if publication_status and claim["publication_status"] != publication_status:
                    continue
                selected.append(claim)
            return selected

        filtered = apply_filters(period_claims)
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
            claim_geo = " ".join(claim["country"].casefold().replace(",", " ").split())
            target = " ".join(geography.casefold().replace(",", " ").split())
            return bool(claim_geo and target and (claim_geo == target or target in claim_geo or claim_geo in target))

        monitored_region_growth = []
        for geography in monitored_geographies:
            current_count = sum(geography_matches(claim, geography) for claim in comparison_current)
            previous_count = sum(geography_matches(claim, geography) for claim in comparison_previous)
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
        monitored_region_growth.sort(key=lambda item: (item["current_count"], item["count"]), reverse=True)

        group_counts = Counter(c["threat_actor"] or "Unknown" for c in filtered)
        country_counts = Counter(c["country"] or "Unknown" for c in filtered)
        industry_counts = Counter(c["industry"] or "Unknown" for c in filtered)
        source_counts = Counter(c["source"] for c in filtered)
        month_counts = Counter(observed_at(c).strftime("%Y-%m") for c in filtered)
        if days:
            denominator = days
        elif filtered:
            span = max(observed_at(c) for c in filtered) - min(
                observed_at(c) for c in filtered
            )
            denominator = max(1, span.days + 1)
        else:
            denominator = 1
        start = (page - 1) * page_size
        return {
            "period_days": days,
            "total": len(filtered),
            "daily_average": round(len(filtered) / denominator, 1),
            "countries_affected": len({c["country"] for c in filtered if c["country"]}),
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
                        geography.casefold() in name.casefold() or name.casefold() in geography.casefold()
                        for geography in monitored_geographies
                    ),
                }
                for name, count in country_counts.most_common(10)
            ],
            "top_industries": [
                {"name": name, "count": count}
                for name, count in industry_counts.most_common(10)
            ],
            "sources": [
                {"name": name, "count": count} for name, count in source_counts.most_common()
            ],
            "monthly_trend": [
                {"month": month, "count": month_counts[month]}
                for month in sorted(month_counts)[-12:]
            ],
            "facets": facets,
            "page": page,
            "page_size": page_size,
            "pages": max(1, (len(filtered) + page_size - 1) // page_size),
            "victims": filtered[start : start + page_size],
            "generated_at": iso(utc_now()),
        }

    def sync_dls_catalog(self, locations: list[DlsLocationInput]) -> int:
        synced_at = iso(utc_now())
        created = 0
        with self.database.connection() as connection:
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
        placeholders = ",".join("?" for _ in unique_ids)
        with self.database.connection() as connection:
            result = connection.execute(
                f"UPDATE dls_targets SET capture_enabled = ? WHERE id IN ({placeholders})",
                (int(capture_enabled), *unique_ids),
            )
        return {
            "requested": len(unique_ids),
            "updated": result.rowcount,
            "capture_enabled": capture_enabled,
        }

    def queue_capture(self, target_id: str, worker_configured: bool) -> dict:
        target = next(
            (item for item in self.list_dls_targets(limit=5000) if item["id"] == target_id),
            None,
        )
        if target is None:
            raise KeyError(target_id)
        if not target["capture_enabled"]:
            raise PermissionError("Enable isolated capture for this site first")
        if not worker_configured:
            raise RuntimeError("The isolated Kali capture worker is not configured")
        job_id = str(uuid.uuid4())
        with self.database.connection() as connection:
            connection.execute(
                "INSERT INTO capture_jobs(id, target_id, status, requested_at) VALUES (?, ?, 'queued', ?)",
                (job_id, target_id, iso(utc_now())),
            )
        return self.get_capture_job(job_id)

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
        return dict(row)

    def capture_overview(self, worker_configured: bool, query: str = "") -> dict:
        targets = self.list_dls_targets(query=query)
        with self.database.connection() as connection:
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
            "catalog_total": len(targets),
            "available": sum(1 for item in targets if item["available"]),
            "capture_enabled": sum(1 for item in targets if item["capture_enabled"]),
            "targets": targets,
            "jobs": [dict(row) for row in jobs],
        }

    def mark_source(
        self,
        source: str,
        *,
        status: str,
        message: str,
        received: int = 0,
        latest_record_at: datetime | None = None,
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

    def dashboard(self) -> dict:
        alerts = self.list_alerts(20)
        claims = self.list_claims(20)
        today = datetime.now(timezone.utc).date().isoformat()
        with self.database.connection() as connection:
            client_count = connection.execute("SELECT COUNT(*) FROM clients").fetchone()[0]
            claims_today = connection.execute(
                "SELECT COUNT(*) FROM claims WHERE substr(received_at, 1, 10) = ?", (today,)
            ).fetchone()[0]
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

    def _archive(self, payload: ClaimInput, claim_id: str, received_at: datetime) -> Path:
        target_dir = (
            self.raw_dir
            / payload.source
            / f"{received_at.year:04d}"
            / f"{received_at.month:02d}"
            / f"{received_at.day:02d}"
        )
        target_dir.mkdir(parents=True, exist_ok=True)
        path = target_dir / f"{claim_id}.json.gz"
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
        return path
