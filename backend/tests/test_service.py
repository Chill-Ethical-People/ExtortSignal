from datetime import timedelta
from pathlib import Path

import pytest

from ransom_monitor.database import Database
from ransom_monitor.schemas import ClaimInput, ClientCreate, DlsLocationInput, RelatedEntity, RuntimeSettingsUpdate, utc_now
from ransom_monitor.service import MonitorService


def build_service(tmp_path: Path) -> MonitorService:
    database = Database(tmp_path / "test.sqlite3")
    database.initialize()
    return MonitorService(database, tmp_path / "raw")


def test_ingest_deduplicates_and_matches(tmp_path):
    service = build_service(tmp_path)
    service.create_client(
        ClientCreate(
            canonical_name="Meridian Harbour Group",
            primary_domain="meridianharbour.example",
        )
    )
    payload = ClaimInput(
        source="fixture",
        source_record_id="one",
        threat_actor="Fixture Group",
        title="Meridian Harbour Group",
        domains=["meridianharbour.example"],
    )
    first, created = service.ingest(payload)
    second, duplicate_created = service.ingest(payload)
    assert created is True
    assert duplicate_created is False
    assert first["id"] == second["id"]
    assert len(service.list_alerts()) == 1


def test_alert_workflow_and_client_notification_draft(tmp_path):
    service = build_service(tmp_path)
    service.create_client(
        ClientCreate(
            canonical_name="Meridian Harbour Group",
            primary_domain="meridianharbour.example",
        )
    )
    service.ingest(
        ClaimInput(
            source="fixture",
            source_record_id="workflow-one",
            threat_actor="Fixture Group",
            title="Meridian Harbour Group",
            domains=["meridianharbour.example"],
        )
    )
    alert = service.list_alerts()[0]
    investigating = service.update_alert(alert["id"], "investigating", "Triage started")
    assert investigating["status"] == "investigating"
    assert investigating["updated_at"] is not None

    draft = service.client_notification_draft(alert["id"])
    assert "unverified ransomware claim" in draft["subject"]
    assert "not independent confirmation" in draft["body"]
    assert draft["scenario"] == "client_named"
    assert draft["generated_by"] == "standard_template"
    assert draft["client_name_sanitized"] is False

    context = service.alert_intelligence_context(alert["id"])
    assert context["published_at"] is None
    assert context["ingested_at"] is not None
    assert context["actor_profile"]["actor"] == "Fixture Group"

    notified = service.update_alert(alert["id"], "client_notified", "Draft approved")
    assert notified["notified_at"] is not None


def test_bulk_ingest_skips_existing_and_in_batch_duplicates(tmp_path):
    service = build_service(tmp_path)
    first = ClaimInput(
        source="fixture",
        source_record_id="one",
        threat_actor="Fixture Group",
        title="First Organization",
    )
    second = ClaimInput(
        source="fixture",
        source_record_id="two",
        threat_actor="Fixture Group",
        title="Second Organization",
    )
    service.ingest(first)

    assert service.ingest_many([first, second, second]) == 1
    assert len(service.list_claims()) == 2


def test_actor_profiles_summarize_observed_data_and_surface_name_variants(tmp_path):
    service = build_service(tmp_path)
    for index, actor in enumerate(("The Gentlemen", "thegentlemen")):
        service.ingest(
            ClaimInput(
                source="fixture",
                source_record_id=f"profile-{index}",
                threat_actor=actor,
                title=f"Victim {index}",
                country="Poland",
                industry="Healthcare",
                discovered_at=utc_now() - timedelta(days=index + 1),
            )
        )
    service.ingest(
        ClaimInput(
            source="fixture",
            source_record_id="profile-previous",
            threat_actor="The Gentlemen",
            title="Previous-period victim",
            discovered_at=utc_now() - timedelta(days=45),
        )
    )

    profiles = service.actor_profiles(days=30)
    first = next(profile for profile in profiles if profile["actor"] == "The Gentlemen")

    assert first["claim_count"] == 1
    assert first["current_count"] == 1
    assert first["previous_count"] == 1
    assert first["top_countries"] == [{"name": "Poland", "count": 1}]
    assert first["top_industries"] == [{"name": "Healthcare", "count": 1}]
    assert first["possible_aliases"] == ["thegentlemen"]
    assert "origin, motivation, capabilities" in first["caveat"]


def test_claim_maintains_publication_and_ingestion_timestamps(tmp_path):
    service = build_service(tmp_path)
    published_at = utc_now() - timedelta(hours=7)

    claim, created = service.ingest(
        ClaimInput(
            source="fixture",
            source_record_id="timestamp-one",
            threat_actor="Fixture Group",
            title="Timestamp Organization",
            published_at=published_at,
        )
    )

    assert created is True
    assert claim["published_at"] == published_at.isoformat()
    assert claim["received_at"] is not None
    assert claim["published_at"] != claim["received_at"]


def test_ai_enrichment_is_stored_separately_from_source_fields(tmp_path):
    service = build_service(tmp_path)
    claim, _ = service.ingest(
        ClaimInput(
            source="fixture",
            source_record_id="ai-enrichment-one",
            threat_actor="Fixture Group",
            title="Meridian Services",
            description="Source-provided description",
            industry="Source industry",
        )
    )

    enriched = service.save_claim_ai_enrichment(
        claim["id"],
        {
            "industry": "Business services",
            "brief_description": "A services organization described by the supplied record.",
            "organization_type": "Private company",
            "confidence": 72,
        },
        "Fixture AI",
    )

    assert enriched["industry"] == "Source industry"
    assert enriched["description"] == "Source-provided description"
    assert enriched["ai_industry"] == "Business services"
    assert enriched["ai_confidence"] == 72
    assert enriched["ai_provider"] == "Fixture AI"

    context = service.actor_analysis_context("Fixture Group", 90)
    assert context["claim_count"] == 1
    assert context["recent_victims"][0]["name"] == "Meridian Services"


def test_victim_digest_tracks_only_claims_after_last_successful_send(tmp_path):
    service = build_service(tmp_path)
    service.ingest(
        ClaimInput(
            source="fixture",
            source_record_id="digest-one",
            threat_actor="Fixture Group",
            title="Digest Organization",
            country="Canada",
            industry="Manufacturing",
        )
    )

    first = service.victim_digest_context(24)
    assert first["count"] == 1
    assert first["top_actors"] == [{"name": "Fixture Group", "count": 1}]
    assert first["top_industries"] == [{"name": "Manufacturing", "count": 1}]

    service.mark_victim_digest_sent()
    second = service.victim_digest_context(24)
    assert second["count"] == 0


def test_demo_seed_is_idempotent(tmp_path):
    service = build_service(tmp_path)
    service.seed_demo()
    service.seed_demo()
    assert len(service.list_clients()) == 1
    assert len(service.list_claims()) == 2


def test_client_profile_supports_multiple_markets_and_relationships(tmp_path):
    service = build_service(tmp_path)
    client = service.create_client(
        ClientCreate(
            canonical_name="Meridian Harbour Group",
            primary_domain="meridianharbour.example",
            description="Regional financial and logistics services group.",
            countries=["Hong Kong", "Singapore"],
            cities=["Kowloon", "Singapore"],
            industries=["Financial services", "Technology"],
            keywords=["HarbourPay", "Meridian Vault"],
            related_entities=[
                RelatedEntity(
                    name="Meridian Cloud Services",
                    domain="meridiancloud.example",
                    relationship="subsidiary",
                )
            ],
        )
    )
    assert client["countries"] == ["Hong Kong", "Singapore"]
    assert client["cities"] == ["Kowloon", "Singapore"]
    assert client["industries"] == ["Financial services", "Technology"]
    assert client["description"].startswith("Regional financial")
    assert client["keywords"] == ["HarbourPay", "Meridian Vault"]
    assert client["related_entities"][0]["relationship"] == "subsidiary"

    updated = service.update_client(
        client["id"],
        ClientCreate(
            canonical_name="Meridian Harbour Group",
            primary_domain="meridianharbour.example",
            description="Updated description.",
            countries=["Hong Kong", "Singapore", "United Kingdom"],
            cities=["London"],
            industries=["Financial services"],
            related_entities=[],
            keywords=["HarbourPay"],
        ),
    )
    assert updated["countries"][-1] == "United Kingdom"
    assert updated["cities"] == ["London"]
    assert updated["related_entities"] == []
    assert updated["description"] == "Updated description."
    assert updated["keywords"] == ["HarbourPay"]


def test_intelligence_aggregates_and_filters_claims(tmp_path):
    service = build_service(tmp_path)
    service.ingest(
        ClaimInput(
            source="fixture",
            source_record_id="intel-one",
            threat_actor="Qilin",
            title="Northstar Manufacturing",
            country="Canada",
            industry="Manufacturing",
            publication_status="data_leaked",
        )
    )
    service.ingest(
        ClaimInput(
            source="fixture",
            source_record_id="intel-two",
            threat_actor="Akira",
            title="Harbour Health",
            country="Hong Kong",
            industry="Healthcare",
        )
    )

    result = service.intelligence(days=30, country="Canada")

    assert result["total"] == 1
    assert result["victims"][0]["title"] == "Northstar Manufacturing"
    assert result["victims"][0]["publication_status"] == "data_leaked"
    assert result["top_groups"] == [{"name": "Qilin", "count": 1}]
    assert "Hong Kong" in result["facets"]["countries"]


def test_flexible_intelligence_analysis_context_supports_multiple_scopes(tmp_path):
    service = build_service(tmp_path)
    service.ingest(ClaimInput(source="fixture", source_record_id="scope-one", threat_actor="Fixture Group", title="Canadian Manufacturer", country="Canada", industry="Manufacturing"))
    service.ingest(ClaimInput(source="fixture", source_record_id="scope-two", threat_actor="Other Group", title="French Hospital", country="France", industry="Healthcare"))
    overall = service.intelligence_analysis_context("overall", days=90)
    actor = service.intelligence_analysis_context("actor", "Fixture Group", 90)
    region = service.intelligence_analysis_context("region", "Canada", 90)

    assert overall["scope"] == "overall"
    assert overall["top_groups"]
    assert actor["label"] == "Threat actor · Fixture Group"
    assert all(item["threat_actor"] == "Fixture Group" for item in actor["recent_victims"])
    assert region["scope_value"] == "Canada"
    assert all(item["country"] == "Canada" for item in region["recent_victims"])


def test_intelligence_calculates_growth_and_monitored_geographies(tmp_path):
    service = build_service(tmp_path)
    service.create_client(
        ClientCreate(
            canonical_name="Harbour Client",
            primary_domain="harbour-client.example",
            countries=["Hong Kong"],
            cities=["Kowloon"],
        )
    )
    service.ingest(
        ClaimInput(
            source="fixture", source_record_id="growth-previous", threat_actor="Qilin",
            title="Previous victim", country="Hong Kong",
            discovered_at=utc_now() - timedelta(days=45),
        )
    )
    for index in range(2):
        service.ingest(
            ClaimInput(
                source="fixture", source_record_id=f"growth-current-{index}", threat_actor="Qilin",
                title=f"Current victim {index}", country="Hong Kong",
                discovered_at=utc_now() - timedelta(days=index + 1),
            )
        )

    result = service.intelligence(days=30)

    assert result["overall_growth"]["current_count"] == 2
    assert result["overall_growth"]["previous_count"] == 1
    assert result["overall_growth"]["growth_percent"] == 100.0
    assert result["group_growth"][0]["name"] == "Qilin"
    hong_kong = next(item for item in result["monitored_region_growth"] if item["name"] == "Hong Kong")
    assert hong_kong["current_count"] == 2
    assert result["top_countries"][0]["is_monitored"] is True


def test_dls_catalog_requires_allowlist_and_worker_before_queue(tmp_path):
    service = build_service(tmp_path)
    location = DlsLocationInput(
        group_name="Fixture Group",
        description="Fixture defensive-research entry",
        fqdn=f"{'a' * 56}.onion",
        available=True,
    )

    assert service.sync_dls_catalog([location]) == 1
    target = service.list_dls_targets()[0]
    assert target["group_name"] == "Fixture Group"
    assert target["capture_enabled"] is False

    with pytest.raises(PermissionError):
        service.queue_capture(target["id"], worker_configured=True)

    service.update_dls_target(target["id"], True)
    with pytest.raises(RuntimeError):
        service.queue_capture(target["id"], worker_configured=False)

    job = service.queue_capture(target["id"], worker_configured=True)
    assert job["status"] == "queued"
    assert job["group_name"] == "Fixture Group"


def test_dls_catalog_supports_bulk_allow_and_disallow(tmp_path):
    service = build_service(tmp_path)
    for index, letter in enumerate(("b", "c", "d"), start=1):
        service.sync_dls_catalog(
            [
                DlsLocationInput(
                    group_name=f"Fixture Group {index}",
                    fqdn=f"{letter * 56}.onion",
                    available=True,
                )
            ]
        )

    targets = service.list_dls_targets()
    selected_ids = [targets[0]["id"], targets[1]["id"]]

    allowed = service.update_dls_targets(selected_ids, True)
    assert allowed == {"requested": 2, "updated": 2, "capture_enabled": True}
    by_id = {target["id"]: target for target in service.list_dls_targets()}
    assert all(by_id[target_id]["capture_enabled"] is True for target_id in selected_ids)
    assert by_id[targets[2]["id"]]["capture_enabled"] is False

    disallowed = service.update_dls_targets(selected_ids, False)
    assert disallowed == {"requested": 2, "updated": 2, "capture_enabled": False}
    by_id = {target["id"]: target for target in service.list_dls_targets()}
    assert all(by_id[target_id]["capture_enabled"] is False for target_id in selected_ids)


def test_runtime_settings_persist_and_active_schedule_deduplicates(tmp_path):
    service = build_service(tmp_path)
    defaults = service.runtime_settings(scheduler_process_enabled=True, worker_configured=False)
    assert defaults["operating_mode"] == "passive"
    assert defaults["public_interval_minutes"] == 2

    service.update_runtime_settings(
        RuntimeSettingsUpdate(
            operating_mode="active",
            scheduling_enabled=True,
            public_interval_minutes=5,
            catalog_interval_hours=12,
            active_interval_minutes=30,
            ai_enabled=True,
            ai_provider="ollama",
            ai_model="qwen3:4b",
            ai_base_url="http://127.0.0.1:11434/v1",
            focus_regions=["Hong Kong", "Greater Bay Area"],
        )
    )
    updated = service.runtime_settings(scheduler_process_enabled=True, worker_configured=True)
    assert updated["operating_mode"] == "active"
    assert updated["ai_enabled"] is True
    assert updated["focus_regions"] == ["Hong Kong", "Greater Bay Area"]

    service.sync_dls_catalog([
        DlsLocationInput(group_name="Allowlisted", fqdn=f"{'b' * 56}.onion", available=True)
    ])
    target = service.list_dls_targets()[0]
    service.update_dls_target(target["id"], True)
    assert service.schedule_active_captures(worker_configured=True)["queued"] == 1
    assert service.schedule_active_captures(worker_configured=True)["queued"] == 0
