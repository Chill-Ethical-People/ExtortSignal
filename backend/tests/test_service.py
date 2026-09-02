from datetime import timedelta
import re
import sqlite3
from pathlib import Path

import pytest

from ransom_monitor.database import Database
from ransom_monitor.schemas import (
    ClaimInput,
    ClientCreate,
    DlsLocationInput,
    RelatedEntity,
    RuntimeSettingsUpdate,
    utc_now,
)
from ransom_monitor.service import MonitorService


def build_service(tmp_path: Path) -> MonitorService:
    database = Database(tmp_path / "test.sqlite3")
    database.initialize()
    return MonitorService(database, tmp_path / "raw")


def test_source_health_keeps_archive_coverage_and_reports_actual_observations(tmp_path):
    service = build_service(tmp_path)
    service.ingest(
        ClaimInput(
            source="ransomlook",
            source_record_id="source-one",
            threat_actor="Example Group",
            title="Example Victim",
            published_at=utc_now(),
            raw={"id": "source-one"},
        )
    )
    service.mark_source(
        "ransomlook",
        status="delayed",
        message="Partial archive sync",
        coverage_status="partial",
        coverage_message="one year failed",
        coverage_gaps=["2021"],
    )
    service.mark_source(
        "ransomlook",
        status="working",
        message="Recent check completed",
    )

    source = next(item for item in service.source_health() if item["source"] == "ransomlook")
    assert source["status"] == "working"
    assert source["observations_stored"] == 1
    assert source["coverage_status"] == "partial"
    assert source["coverage_message"] == "one year failed"
    assert source["coverage_gaps"] == ["2021"]
    assert source["oldest_observation_at"] is not None


def test_database_migrates_observed_date_and_creates_query_indexes(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE claims (
            id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE,
            source TEXT NOT NULL, source_record_id TEXT NOT NULL,
            source_url TEXT NOT NULL DEFAULT '', threat_actor TEXT NOT NULL,
            title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
            published_at TEXT, discovered_at TEXT, received_at TEXT NOT NULL,
            country TEXT NOT NULL DEFAULT '', industry TEXT NOT NULL DEFAULT '',
            domains_json TEXT NOT NULL DEFAULT '[]', raw_path TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'alleged'
        );
        INSERT INTO claims(
            id, fingerprint, source, source_record_id, threat_actor, title,
            published_at, received_at
        ) VALUES (
            'one', 'fingerprint', 'fixture', 'one', 'Actor', 'Victim',
            '2025-07-01T00:00:00+00:00', '2025-07-02T00:00:00+00:00'
        );
        """
    )
    connection.commit()
    connection.close()

    Database(path).initialize()
    connection = sqlite3.connect(path)
    observed_at = connection.execute("SELECT observed_at FROM claims WHERE id = 'one'").fetchone()[
        0
    ]
    indexes = {row[1] for row in connection.execute("PRAGMA index_list(claims)")}
    connection.close()

    assert observed_at == "2025-07-01T00:00:00+00:00"
    assert {
        "idx_claims_observed",
        "idx_claims_actor_observed",
        "idx_claims_country_observed",
        "idx_claims_industry_observed",
    }.issubset(indexes)


def test_database_normalizes_retained_actor_state_without_losing_newest_profile(tmp_path):
    path = tmp_path / "actor-state.sqlite3"
    database = Database(path)
    database.initialize()
    with database.connection() as connection:
        connection.execute(
            """INSERT INTO threat_actor_osint_evidence(
                   id, actor, source_name, source_tier, title, source_url,
                   retrieved_at, excerpt, evidence_type, content_sha256
               ) VALUES ('evidence', 'hunters', 'CISA', 'authoritative', 'Advisory',
                         'https://www.cisa.gov/example', '2026-08-01T00:00:00+00:00',
                         'Documented behavior.', 'published_research', 'hash')"""
        )
        connection.execute(
            """INSERT INTO threat_actor_profile_refreshes(
                   actor, profile_json, provider, model, generated_at
               ) VALUES ('hunters', '{"actor":"hunters","summary":"older alias"}',
                         'provider', 'model', '2026-08-01T00:00:00+00:00')"""
        )
        connection.execute(
            """INSERT INTO actor_ai_analysis(
                   actor, analysis_json, provider, model, generated_at
               ) VALUES ('hunters', '{"actor":"hunters","summary":"analysis"}',
                         'provider', 'model', '2026-08-01T00:00:00+00:00')"""
        )

    database.initialize()
    with database.connection() as connection:
        evidence_actor = connection.execute(
            "SELECT actor FROM threat_actor_osint_evidence WHERE id = 'evidence'"
        ).fetchone()["actor"]
        profile = connection.execute(
            "SELECT actor, profile_json FROM threat_actor_profile_refreshes"
        ).fetchone()
        analysis = connection.execute(
            "SELECT actor, analysis_json FROM actor_ai_analysis"
        ).fetchone()

    assert evidence_actor == "Hunters International"
    assert profile["actor"] == "Hunters International"
    assert analysis["actor"] == "Hunters International"
    assert '"actor": "Hunters International"' in profile["profile_json"]
    assert '"actor": "Hunters International"' in analysis["analysis_json"]


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


def test_distinct_source_observations_are_preserved_for_one_claim(tmp_path):
    service = build_service(tmp_path)
    observed = utc_now() - timedelta(days=1)
    payloads = [
        ClaimInput(
            source="source-one",
            source_record_id="one",
            source_url="https://source-one.example/record/one",
            threat_actor="Fixture Group",
            title="Shared Victim",
            discovered_at=observed - timedelta(days=2),
            raw={"source": "one"},
        ),
        ClaimInput(
            source="source-two",
            source_record_id="two",
            source_url="https://source-two.example/record/two",
            threat_actor="Fixture Group",
            title="Shared Victim",
            discovered_at=observed,
            raw={"source": "two"},
        ),
    ]

    assert service.ingest_many(payloads) == 1
    claim = service.list_claims()[0]
    observations = service.list_source_observations(claim["id"])

    assert {item["source"] for item in observations} == {"source-one", "source-two"}
    assert all(len(item["content_sha256"]) == 64 for item in observations)
    intelligence = service.intelligence(days=30)
    assert intelligence["total"] == 1
    assert intelligence["raw_source_records"] == 2
    assert intelligence["duplicates_collapsed"] == 1

    service.ingest(payloads[0])
    assert len(service.list_source_observations(claim["id"])) == 2

    changed = payloads[0].model_copy(
        update={
            "description": "The source record was subsequently updated.",
            "raw": {"source": "one", "revision": 2},
        }
    )
    service.ingest(changed)
    assert len(service.list_source_observations(claim["id"])) == 3


def test_actor_aliases_share_one_claim_identity_across_sources(tmp_path):
    service = build_service(tmp_path)
    payloads = [
        ClaimInput(
            source="source-one",
            source_record_id="alias-one",
            threat_actor="the gentlemen",
            title="Shared Alias Victim",
        ),
        ClaimInput(
            source="source-two",
            source_record_id="alias-two",
            threat_actor="thegentlemen",
            title="Shared Alias Victim",
        ),
    ]

    assert service.ingest_many(payloads) == 1
    claims = service.list_claims()
    assert len(claims) == 1
    assert claims[0]["threat_actor"] == "The Gentlemen"
    assert len(service.list_source_observations(claims[0]["id"])) == 2


def test_bulk_ingest_merges_later_source_detail_metadata(tmp_path):
    service = build_service(tmp_path)
    base = ClaimInput(
        source="ransomware_live",
        source_record_id="https://www.ransomware.live/id/example",
        source_url="https://www.ransomware.live/id/example",
        threat_actor="Orova",
        title="FixIT Tek",
        published_at=utc_now(),
        country="US",
        industry="Technology",
        domains=["fixittek.com"],
        raw={"data_size": None},
    )
    assert service.ingest_many([base]) == 1
    assert service.source_detail_candidate_ids([base]) == {base.source_record_id}

    checked_at = utc_now()
    enriched = base.model_copy(
        update={
            "attack_date": checked_at - timedelta(days=2),
            "leak_size": "150.00 GB",
            "leak_size_bytes": 150_000_000_000,
            "leak_size_source": "detail_page:data_exfiltrated",
            "source_screenshot_url": "https://images.ransomware.live/fixit.png",
            "source_tags": ["New group"],
            "detail_checked_at": checked_at,
            "detail_status": "enriched",
            "raw": {
                "data_size": None,
                "_extortsignal_detail_page": {"fields": {"data exfiltrated": "150.00 GB"}},
            },
        }
    )

    assert service.ingest_many([enriched]) == 0
    claim = service.list_claims()[0]
    assert claim["leak_size"] == "150.00 GB"
    assert claim["leak_size_bytes"] == 150_000_000_000
    assert claim["leak_size_source"] == "detail_page:data_exfiltrated"
    assert claim["attack_date"] == enriched.attack_date.isoformat()
    assert claim["source_screenshot_url"].endswith("fixit.png")
    assert claim["source_tags"] == ["New group"]
    assert claim["detail_status"] == "enriched"
    assert service.source_detail_candidate_ids([base]) == set()
    assert len(service.list_source_observations(claim["id"])) == 2


def test_archived_source_metadata_is_reparsed_once_after_parser_upgrade(tmp_path):
    service = build_service(tmp_path)
    service.ingest_many(
        [
            ClaimInput(
                source="fixture",
                source_record_id="archived-size",
                threat_actor="Fixture Group",
                title="Archived Metadata Victim",
                raw={
                    "attack_date": "2026-07-01",
                    "exfiltrated_data_size": "2.5 TB",
                    "screenshot_url": "https://images.example/evidence.png",
                    "is_new_group": True,
                },
            )
        ]
    )

    result = service.reparse_archived_source_metadata_v2()
    claim = service.list_claims()[0]

    assert result == {"status": "complete", "scanned": 1, "updated": 1, "failed": 0}
    assert claim["attack_date"] == "2026-07-01T00:00:00+00:00"
    assert claim["leak_size"] == "2.5 TB"
    assert claim["leak_size_bytes"] == 2_500_000_000_000
    assert claim["source_screenshot_url"] == "https://images.example/evidence.png"
    assert claim["source_tags"] == ["New group"]
    assert service.reparse_archived_source_metadata_v2()["status"] == "already_complete"


def test_intelligence_collapses_legacy_cross_source_claim_rows(tmp_path):
    service = build_service(tmp_path)
    now = utc_now()
    with service.database.connection() as connection:
        for suffix, source, observed in (
            ("one", "source-one", now - timedelta(days=3)),
            ("two", "source-two", now - timedelta(days=1)),
        ):
            connection.execute(
                """INSERT INTO claims(
                       id, fingerprint, source, source_record_id, threat_actor,
                       title, published_at, discovered_at, received_at,
                       observed_at, domains_json
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]')""",
                (
                    suffix,
                    f"legacy-{suffix}",
                    source,
                    suffix,
                    "Fixture Group",
                    "Shared Victim Ltd",
                    observed.isoformat(),
                    observed.isoformat(),
                    observed.isoformat(),
                    observed.isoformat(),
                ),
            )

    result = service.intelligence(days=30)

    assert result["total"] == 1
    assert result["raw_source_records"] == 2
    assert result["duplicates_collapsed"] == 1
    assert result["top_groups"] == [{"name": "Fixture Group", "count": 1}]


def test_victim_enrichment_is_shared_through_canonical_organization(tmp_path):
    service = build_service(tmp_path)
    first, _ = service.ingest(
        ClaimInput(
            source="source-one",
            source_record_id="one",
            threat_actor="Actor One",
            title="Universal Profile Ltd",
            domains=["universal.example"],
        )
    )
    second, _ = service.ingest(
        ClaimInput(
            source="source-two",
            source_record_id="two",
            threat_actor="Actor Two",
            title="Universal Profile Ltd",
            domains=["universal.example"],
        )
    )

    service.save_claim_ai_enrichment(
        first["id"],
        {
            "industry": "Critical Infrastructure",
            "country_or_region": "Singapore",
            "brief_description": "A canonical organization profile shared across claims.",
            "organization_type": "Operator",
            "source_urls": ["https://registry.example/universal"],
            "past_incidents": [],
            "confidence": 88,
            "osint_status": "completed",
        },
        "fixture-provider",
    )

    refreshed_second = service.get_claim(second["id"])
    assert refreshed_second["ai_industry"] == "Critical Infrastructure"
    assert refreshed_second["ai_country"] == "Singapore"
    assert refreshed_second["organization_profile"]["confidence"] == 88

    service.save_claim_ai_enrichment(
        second["id"],
        {
            "industry": "Unknown",
            "country_or_region": "Unknown",
            "brief_description": "A lower-confidence conflicting result.",
            "organization_type": "Unknown",
            "source_urls": ["https://low-confidence.example/universal"],
            "past_incidents": [],
            "confidence": 20,
            "osint_status": "completed",
        },
        "low-confidence-provider",
    )

    protected_first = service.get_claim(first["id"])
    protected_second = service.get_claim(second["id"])
    assert protected_first["ai_industry"] == "Critical Infrastructure"
    assert protected_second["ai_country"] == "Singapore"
    assert protected_second["organization_profile"]["confidence"] == 88


def test_alert_operations_use_direct_lookup_not_bounded_alert_list(tmp_path, monkeypatch):
    service = build_service(tmp_path)
    service.create_client(
        ClientCreate(
            canonical_name="Direct Lookup Ltd",
            primary_domain="direct-lookup.example",
        )
    )
    service.ingest(
        ClaimInput(
            source="fixture",
            source_record_id="direct-alert",
            threat_actor="Fixture Group",
            title="Direct Lookup Ltd",
            domains=["direct-lookup.example"],
        )
    )
    alert_id = service.list_alerts()[0]["id"]

    monkeypatch.setattr(
        service,
        "list_alerts",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("bounded list lookup must not be used")
        ),
    )
    updated = service.update_alert(alert_id, "investigating", "Direct lookup")

    assert updated["id"] == alert_id
    assert updated["status"] == "investigating"


def test_activity_pages_cover_complete_dataset_and_restore_archived_evidence(tmp_path):
    service = build_service(tmp_path)
    for index in range(205):
        service.ingest(
            ClaimInput(
                source="fixture",
                source_record_id=str(index),
                threat_actor="Fixture Group",
                title=f"Victim {index:03d}",
                description=f"Complete description {index}",
                raw={"index": index, "source_detail": "preserved"},
            )
        )

    first = service.activity_claims(page=1, page_size=100)
    last = service.activity_claims(page=3, page_size=100)
    evidence = service.claim_source_evidence(first["items"][0]["id"])

    assert first["total"] == 205
    assert first["pages"] == 3
    assert len(last["items"]) == 5
    assert evidence["archived_record"]["raw"]["source_detail"] == "preserved"


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
    assert draft["id"]
    assert re.search(
        r"Ingested into monitoring platform: \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", draft["body"]
    )

    saved = service.list_notification_drafts(alert["id"])
    assert [item["id"] for item in saved] == [draft["id"]]
    updated_draft = service.update_notification_draft(
        alert["id"], draft["id"], "Reviewed subject", "Reviewed body"
    )
    assert updated_draft["subject"] == "Reviewed subject"
    assert updated_draft["body"] == "Reviewed body"

    context = service.alert_intelligence_context(alert["id"])
    assert context["published_at"] is None
    assert context["ingested_at"] is not None
    assert context["actor_profile"]["actor"] == "Fixture Group"
    assert context["ai_assessments"] == []

    assessment = service.save_alert_ai_assessment(
        alert["id"],
        {
            "executive_summary": "Analyst review is required.",
            "named_victim_profile": "A fixture organization.",
            "alert_relevance": "Exact domain match.",
            "analytic_assessment": "Treat as an unverified allegation.",
            "recommended_actions": ["Validate internal telemetry."],
            "evidence_gaps": ["No internal confirmation supplied."],
            "confidence": 75,
        },
        "Fixture AI",
        "fixture-model",
    )
    assert assessment["alert_id"] == alert["id"]
    refreshed_context = service.alert_intelligence_context(alert["id"])
    assert refreshed_context["ai_assessments"][0]["id"] == assessment["id"]
    assert refreshed_context["ai_assessments"][0]["provider"] == "Fixture AI"

    notified = service.update_alert(alert["id"], "client_notified", "Draft approved")
    assert notified["notified_at"] is not None


def test_bulk_alert_status_update_is_bounded_to_selected_alerts(tmp_path):
    service = build_service(tmp_path)
    for index in range(2):
        service.create_client(
            ClientCreate(
                canonical_name=f"Selected Client {index}",
                primary_domain=f"selected-{index}.example",
            )
        )
        service.ingest(
            ClaimInput(
                source="fixture",
                source_record_id=f"bulk-alert-{index}",
                threat_actor="Fixture Group",
                title=f"Selected Client {index}",
                domains=[f"selected-{index}.example"],
            )
        )

    alerts = service.list_alerts()
    result = service.update_alerts(
        [alerts[0]["id"], alerts[1]["id"], "missing-alert"],
        "investigating",
        "Bulk triage started",
    )

    assert result["requested"] == 3
    assert result["updated"] == 2
    assert result["missing"] == 1
    assert result["missing_alert_ids"] == ["missing-alert"]
    updated = {alert["id"]: alert for alert in service.list_alerts()}
    assert updated[alerts[0]["id"]]["status"] == "investigating"
    assert updated[alerts[1]["id"]]["note"] == "Bulk triage started"

    service.update_alert(alerts[0]["id"], "monitoring", "Preserve this analyst note")
    notified = service.update_alerts([alerts[0]["id"]], "client_notified", "")
    refreshed = service.get_alert(alerts[0]["id"])
    assert notified["updated"] == 1
    assert refreshed["status"] == "client_notified"
    assert refreshed["note"] == "Preserve this analyst note"
    assert refreshed["notified_at"] is not None


def test_bulk_false_positive_records_each_decision_and_reports_missing(tmp_path):
    service = build_service(tmp_path)
    fixtures = [
        ("Jade Falcon Holdings", "jade-falcon.example"),
        ("Saffron Delta Logistics", "saffron-delta.example"),
    ]
    for index, (name, domain) in enumerate(fixtures):
        service.create_client(
            ClientCreate(
                canonical_name=name,
                primary_domain=domain,
            )
        )
        service.ingest(
            ClaimInput(
                source="fixture",
                source_record_id=f"false-match-{index}",
                threat_actor="Fixture Group",
                title=name,
                domains=[domain],
            )
        )

    alerts = service.list_alerts()
    result = service.record_false_positives(
        [alerts[0]["id"], alerts[1]["id"], "missing-alert"],
        "ambiguous_name",
        "Bulk analyst decision",
    )

    assert result["requested"] == 3
    assert result["recorded"] == 2
    assert result["failed"] == 1
    assert {item["status"] for item in service.list_alerts()} == {"dismissed"}
    with service.database.connection() as connection:
        feedback_count = connection.execute(
            "SELECT COUNT(*) AS count FROM analyst_feedback"
        ).fetchone()["count"]
    assert feedback_count == 2


def test_delete_client_removes_private_workflow_records_but_preserves_claim(tmp_path):
    service = build_service(tmp_path)
    client = service.create_client(
        ClientCreate(
            canonical_name="Deletion Client",
            primary_domain="deletion-client.example",
        )
    )
    claim, _ = service.ingest(
        ClaimInput(
            source="fixture",
            source_record_id="deletion-claim",
            threat_actor="Fixture Group",
            title="Deletion Client",
            domains=["deletion-client.example"],
        )
    )
    alert = service.list_alerts()[0]
    service.save_notification_draft(
        alert["id"],
        {
            "subject": "Draft subject",
            "body": "Draft body",
            "scenario": "client_named",
        },
    )
    service.save_alert_ai_assessment(
        alert["id"],
        {"executive_summary": "Assessment", "confidence": 50},
        "Fixture AI",
        "fixture-model",
    )
    service.record_false_positive(alert["id"], "unrelated_organization", "Deletion test")

    result = service.delete_client(client["id"])

    assert result["deleted_client"]["canonical_name"] == "Deletion Client"
    assert result["deleted_alerts"] == 1
    assert result["deleted_drafts"] == 1
    assert result["deleted_assessments"] == 1
    assert result["deleted_feedback"] == 1
    assert service.list_clients() == []
    assert service.list_alerts() == []
    assert service.get_claim(claim["id"])["title"] == "Deletion Client"


def test_false_positive_feedback_is_rag_ready_and_retrievable(tmp_path):
    service = build_service(tmp_path)
    service.create_client(
        ClientCreate(
            canonical_name="Harbour Holdings",
            primary_domain="harbour.example",
            aliases=["Harbour"],
            industries=["Logistics"],
        )
    )
    for record_id, title in (
        ("feedback-one", "Harbour Freight"),
        ("feedback-two", "Harbour Logistics"),
    ):
        service.ingest(
            ClaimInput(
                source="fixture",
                source_record_id=record_id,
                threat_actor="Fixture Group",
                title=title,
                industry="Logistics",
                country="Hong Kong",
            )
        )

    alerts = service.list_alerts()
    first = next(item for item in alerts if item["claim_title"] == "Harbour Freight")
    second = next(item for item in alerts if item["claim_title"] == "Harbour Logistics")
    result = service.record_false_positive(
        first["id"], "similar_name", "Unrelated company with a shared trading word"
    )
    feedback = result["feedback"]

    assert feedback["metadata"]["schema"] == "extortsignal.analyst-feedback.v1"
    assert feedback["claim_snapshot"]["title"] == "Harbour Freight"
    assert "Analyst rationale" in feedback["document_text"]
    assert (
        next(item for item in service.list_alerts() if item["id"] == first["id"])["status"]
        == "dismissed"
    )
    precedents = service.false_positive_precedents(second["id"])
    assert precedents
    assert precedents[0]["category"] == "similar_name"


def test_alert_can_queue_allowlisted_focused_victim_capture(tmp_path):
    service = build_service(tmp_path)
    service.create_client(
        ClientCreate(
            canonical_name="Named Victim",
            primary_domain="named-victim.example",
        )
    )
    service.ingest(
        ClaimInput(
            source="fixture",
            source_record_id="focused-capture",
            threat_actor="Fixture Group",
            title="Named Victim",
            domains=["named-victim.example"],
        )
    )
    service.sync_dls_catalog(
        [DlsLocationInput(group_name="Fixture Group", fqdn=f"{'a' * 56}.onion", available=True)]
    )
    target = service.list_dls_targets()[0]
    service.update_dls_target(target["id"], True)
    service.update_runtime_settings(RuntimeSettingsUpdate(operating_mode="active"))

    alert = service.list_alerts()[0]
    job = service.queue_alert_capture(alert["id"], worker_configured=True)

    assert job["alert_id"] == alert["id"]
    assert job["claim_id"] == alert["claim_id"]
    assert job["victim_name"] == "Named Victim"
    assert job["capture_scope"] == "flagged_victim"


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

    assert first["claim_count"] == 2
    assert first["current_count"] == 2
    assert first["previous_count"] == 1
    assert first["top_countries"] == [{"name": "Poland", "count": 2}]
    assert first["top_industries"] == [{"name": "Healthcare", "count": 2}]
    assert set(first["possible_aliases"]) == {"the gentlemen", "thegentlemen"}
    assert "origin, motivation, capabilities" in first["caveat"]


def test_actor_profile_index_returns_lightweight_ranked_navigation(tmp_path):
    service = build_service(tmp_path)
    for index in range(3):
        service.ingest(
            ClaimInput(
                source="fixture",
                source_record_id=f"qilin-{index}",
                threat_actor="Qilin",
                title=f"Qilin victim {index}",
                discovered_at=utc_now() - timedelta(days=index + 1),
            )
        )
    service.ingest(
        ClaimInput(
            source="fixture",
            source_record_id="akira-one",
            threat_actor="Akira",
            title="Akira victim",
            discovered_at=utc_now() - timedelta(days=2),
        )
    )

    index = service.actor_profile_index(days=30, limit=10)

    assert [item["actor"] for item in index] == ["Qilin", "Akira"]
    assert index[0]["claim_count"] == 3
    assert set(index[0]) == {
        "actor",
        "claim_count",
        "first_observed_at",
        "last_observed_at",
    }


def test_actor_profiles_can_fetch_one_canonical_actor(tmp_path):
    service = build_service(tmp_path)
    service.ingest(
        ClaimInput(
            source="fixture",
            source_record_id="one",
            threat_actor="qilin",
            title="First victim",
        )
    )
    service.ingest(
        ClaimInput(
            source="fixture",
            source_record_id="two",
            threat_actor="LockBit 3",
            title="Second victim",
        )
    )

    profiles = service.actor_profiles(days=0, limit=1, actor="Qilin")

    assert len(profiles) == 1
    assert profiles[0]["actor"] == "Qilin"
    assert profiles[0]["claim_count"] == 1
    assert profiles[0]["professional_profile"]["profile_schema"] == (
        "ExtortSignal CTI Profile 1.0"
    )


def test_actor_profile_uses_catalog_baseline_and_persists_ai_refresh(tmp_path):
    service = build_service(tmp_path)
    service.sync_dls_catalog(
        [
            DlsLocationInput(
                group_name="Example Group",
                description="Externally catalogued double-extortion actor description.",
                fqdn=f"{'a' * 56}.onion",
            )
        ]
    )
    service.ingest(
        ClaimInput(
            source="fixture",
            source_record_id="profile",
            threat_actor="example-group",
            title="Example victim",
        )
    )

    baseline = service.actor_profiles()[0]
    assert baseline["baseline_profile"]["source"] == "Ransomware.live group catalogue"
    assert "Externally catalogued" in baseline["baseline_profile"]["summary"]
    assert baseline["professional_profile"]["source_kind"] == "static_local_catalog"
    assert "Externally catalogued" in baseline["professional_profile"]["summary"]
    assert baseline["professional_profile"]["sources"] == ["Ransomware.live group catalogue"]
    assert baseline["professional_profile"]["motivation"]
    assert baseline["professional_profile"]["targeting"]
    assert baseline["professional_profile"]["capabilities"]
    assert baseline["professional_profile"]["campaign_history"]
    assert baseline["professional_profile"]["profile_schema"] == "ExtortSignal CTI Profile 1.0"
    assert baseline["professional_profile"]["profile_status"] == "catalogue_context_only"
    assert baseline["professional_profile"]["distribution"] == "TLP:CLEAR"
    assert baseline["professional_profile"]["detection_coverage"]["status"] == "not_assessed"
    assert baseline["professional_profile"]["priority_actions"]
    assert baseline["professional_profile"]["hunt_hypotheses"]

    service.save_actor_osint_evidence(
        "example-group",
        [
            {
                "id": "evidence-one",
                "source_name": "CISA",
                "source_tier": "authoritative",
                "title": "Example advisory",
                "source_url": "https://www.cisa.gov/example-advisory",
                "published_at": "2026-01-01T00:00:00+00:00",
                "retrieved_at": "2026-01-02T00:00:00+00:00",
                "excerpt": "Sourced example actor behavior.",
                "evidence_type": "published_research",
            }
        ],
    )
    service.save_actor_profile_refresh(
        "example-group",
        {
            "summary": "Refreshed sourced summary.",
            "motivation": "Financial extortion supported by the retained advisory.",
            "targeting": "The retained advisory documents broad targeting.",
            "capabilities": "The retained advisory documents ransomware behavior.",
            "campaign_history": "The retained advisory documents the example campaign.",
            "key_judgments": ["The cited advisory supports the actor assessment."],
            "priority_actions": ["Validate controls against the cited behavior."],
            "hunt_hypotheses": ["Relevant telemetry may show the cited behavior."],
            "confidence": 72,
            "sources": ["CISA"],
            "independent_source_count": 1,
            "field_evidence": {
                "summary": ["evidence-one"],
                "motivation": ["evidence-one"],
                "targeting": ["evidence-one"],
                "capabilities": ["evidence-one"],
                "campaign_history": ["evidence-one"],
                "key_judgments": ["evidence-one"],
                "priority_actions": ["evidence-one"],
                "hunt_hypotheses": ["evidence-one"],
            },
        },
        "Fixture AI",
        "fixture-model",
    )
    refreshed_profile = service.actor_profiles()[0]
    refreshed = refreshed_profile["ai_profile_refresh"]
    assert refreshed["summary"] == "Refreshed sourced summary."
    assert refreshed["provider"] == "Fixture AI"
    assert refreshed["overlay_status"] == "applied"
    assert refreshed_profile["professional_profile"]["summary"] == "Refreshed sourced summary."
    assert refreshed_profile["professional_profile"]["source_kind"] == "ai_refreshed"
    assert refreshed_profile["professional_profile"]["analytic_confidence"] == 72
    assert refreshed_profile["professional_profile"]["key_judgments"] == [
        "The cited advisory supports the actor assessment."
    ]
    assert refreshed_profile["professional_profile"]["priority_actions"] == [
        "Validate controls against the cited behavior."
    ]
    assert refreshed_profile["professional_profile"]["hunt_hypotheses"] == [
        "Relevant telemetry may show the cited behavior."
    ]


def test_actor_profile_retains_osint_evidence_separately_from_local_claims(tmp_path):
    service = build_service(tmp_path)
    service.ingest(
        ClaimInput(
            source="fixture",
            source_record_id="actor-osint",
            threat_actor="Example Group",
            title="Alleged victim",
        )
    )
    evidence = {
        "id": "osint-example",
        "source_name": "CISA",
        "source_tier": "authoritative",
        "title": "Example Group advisory",
        "source_url": "https://www.cisa.gov/example-group",
        "published_at": "2026-01-01T00:00:00+00:00",
        "retrieved_at": "2026-01-02T00:00:00+00:00",
        "excerpt": "Example Group uses documented ransomware techniques.",
        "evidence_type": "published_research",
    }

    assert service.save_actor_osint_evidence("Example Group", [evidence]) == 1
    profile = service.actor_profiles()[0]

    assert profile["osint_evidence"][0]["source_name"] == "CISA"
    assert profile["professional_profile"]["osint_evidence_count"] == 1
    assert profile["professional_profile"]["independent_source_count"] == 1
    assert "victim" not in profile["osint_evidence"][0]["excerpt"].casefold()


def test_uncited_actor_ai_refresh_does_not_replace_local_profile(tmp_path):
    service = build_service(tmp_path)
    service.ingest(
        ClaimInput(
            source="fixture",
            source_record_id="orova-one",
            threat_actor="orova",
            title="Unverified organization",
        )
    )
    baseline = service.actor_profiles()[0]["professional_profile"]
    service.save_actor_profile_refresh(
        "orova",
        {
            "summary": "Not established in retained OSINT.",
            "motivation": "Not established in retained OSINT.",
            "targeting": "Not established in retained OSINT.",
            "capabilities": "Not established in retained OSINT.",
            "campaign_history": "Not established in retained OSINT.",
            "confidence": 0,
            "sources": [],
            "independent_source_count": 0,
            "field_evidence": {},
        },
        "Fixture AI",
        "fixture-model",
    )

    profile = service.actor_profiles()[0]

    assert profile["ai_profile_refresh"] is not None
    assert profile["ai_profile_refresh"]["overlay_status"] == "insufficient_evidence"
    assert profile["professional_profile"]["summary"] == baseline["summary"]
    assert profile["professional_profile"]["source_kind"] == "static_local_label"
    assert profile["professional_profile"]["ai_overlay_status"] == "insufficient_evidence"


def test_curated_local_actor_profile_is_available_without_ai(tmp_path):
    service = build_service(tmp_path)
    service.ingest(
        ClaimInput(
            source="fixture",
            source_record_id="lockbit-one",
            threat_actor="lockbit3",
            title="Unverified organization",
        )
    )

    profile = service.actor_profiles()[0]["professional_profile"]

    assert profile["source_kind"] == "static_local_curated"
    assert profile["identity"]["canonical_name"] == "LockBit"
    assert "ransomware-as-a-service" in profile["summary"]
    assert profile["motivation"]
    assert profile["targeting"]
    assert profile["capabilities"]
    assert profile["campaign_history"]
    assert profile["source_references"][0]["url"].startswith("https://www.cisa.gov/")
    assert profile["profile_status"] == "sourced_profile"
    assert profile["actor_class"] == "criminal_ransomware_extortion"
    assert profile["key_judgments"]


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
            "country_or_region": "Canada",
            "past_incidents": [
                {
                    "published_at": "2026-01-02T03:04:05+00:00",
                    "incident_type": "Data breach",
                    "summary": "A prior public report was identified.",
                    "source_url": "https://news.example/report",
                    "evidence_type": "news_report",
                    "confidence": 80,
                }
            ],
            "osint_status": "candidates_found",
            "confidence": 72,
        },
        "Fixture AI",
    )

    assert enriched["industry"] == "Source industry"
    assert enriched["description"] == "Source-provided description"
    assert enriched["ai_industry"] == "Business services"
    assert enriched["ai_confidence"] == 72
    assert enriched["ai_provider"] == "Fixture AI"
    assert enriched["ai_country"] == "Canada"
    assert enriched["ai_past_incidents"][0]["evidence_type"] == "news_report"
    assert enriched["ai_osint_status"] == "candidates_found"
    assert enriched["ai_osint_checked_at"] is not None

    context = service.actor_analysis_context("Fixture Group", 90)
    assert context["claim_count"] == 1
    assert context["recent_victims"][0]["name"] == "Meridian Services"
    assert context["threat_actor_context"][0]["actor"] == "Fixture Group"
    assert (
        context["threat_actor_context"][0]["professional_profile"]["source_kind"]
        == "static_local_label"
    )


def test_prior_claim_incidents_and_analysis_history_are_persisted(tmp_path):
    service = build_service(tmp_path)
    first, _ = service.ingest(
        ClaimInput(
            source="fixture",
            source_record_id="history-one",
            source_url="https://source.example/one",
            threat_actor="First Group",
            title="Repeated Organization",
            domains=["repeated.example"],
            published_at=utc_now() - timedelta(days=60),
        )
    )
    latest, _ = service.ingest(
        ClaimInput(
            source="fixture",
            source_record_id="history-two",
            source_url="https://source.example/two",
            threat_actor="Second Group",
            title="Repeated Organization",
            domains=["repeated.example"],
            published_at=utc_now() - timedelta(days=2),
        )
    )

    incidents = service.prior_claim_incidents(latest["id"])
    assert incidents[0]["threat_actor"] == "First Group"
    assert incidents[0]["evidence_type"] == "local_claim"
    assert first["id"] != latest["id"]

    context = service.intelligence_analysis_context("overall", "", 90)
    stored = service.save_intelligence_ai_analysis(
        context,
        {
            "summary": "Observed increase.",
            "patterns": [],
            "risk_observations": [],
            "caveats": [],
            "confidence": 75,
        },
        "Fixture AI",
        "fixture-model",
    )
    history = service.list_intelligence_ai_analysis_history()
    assert history[0]["id"] == stored["id"]
    assert history[0]["summary"] == "Observed increase."
    assert history[0]["provider"] == "Fixture AI"


def test_ai_job_queue_persists_results_and_acknowledgement(tmp_path):
    service = build_service(tmp_path)
    queued = service.enqueue_ai_job(
        "provider_test",
        "AI provider verification",
        {},
        "settings",
    )
    assert queued["status"] == "queued"

    running = service.claim_next_ai_job()
    assert running is not None
    assert running["id"] == queued["id"]
    assert running["status"] == "running"

    completed = service.finish_ai_job(queued["id"], {"status": "verified"})
    assert completed["status"] == "completed"
    assert completed["result"] == {"status": "verified"}
    assert completed["seen_at"] is None

    seen = service.mark_ai_job_seen(queued["id"])
    assert seen["seen_at"] is not None


def test_ai_job_history_supports_pagination_and_filters(tmp_path):
    service = build_service(tmp_path)
    completed = service.enqueue_ai_job(
        "provider_test",
        "Verify Gemini provider",
        {},
        "settings",
    )
    service.finish_ai_job(completed["id"], {"status": "verified"})
    service.enqueue_ai_job(
        "actor_profile_refresh",
        "Refresh actor profile · Qilin",
        {"actor": "Qilin"},
        "intelligence",
    )
    service.enqueue_ai_job(
        "victim_enrichment",
        "Victim research · Example Company",
        {"claim_id": "claim-one"},
        "activity",
    )

    first_page = service.ai_job_history(page=1, page_size=2)
    queued = service.ai_job_history(page=1, page_size=10, status="queued")
    searched = service.ai_job_history(page=1, page_size=10, query="Gemini")

    assert first_page["total"] == 3
    assert first_page["pages"] == 2
    assert len(first_page["items"]) == 2
    assert queued["total"] == 2
    assert all(item["status"] == "queued" for item in queued["items"])
    assert searched["items"][0]["title"] == "Verify Gemini provider"
    assert first_page["status_counts"] == {"completed": 1, "queued": 2}
    assert first_page["job_types"] == [
        "actor_profile_refresh",
        "provider_test",
        "victim_enrichment",
    ]


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


def test_focus_region_watch_deduplicates_and_supports_daily_activity_filter(tmp_path):
    service = build_service(tmp_path)
    service.update_runtime_settings(
        RuntimeSettingsUpdate(
            operating_mode="passive",
            focus_regions=["Hong Kong Island", "Singapore"],
        )
    )
    claims = [
        ("hk", "Regional Group", "Harbour Victim", "Hong Kong", "Financial services"),
        ("sg", "Regional Group", "Marina Victim", "SG", "Technology"),
        ("ca", "Other Group", "Canadian Victim", "Canada", "Manufacturing"),
    ]
    for record_id, actor, title, country, industry in claims:
        service.ingest(
            ClaimInput(
                source="fixture",
                source_record_id=record_id,
                threat_actor=actor,
                title=title,
                country=country,
                industry=industry,
            )
        )
    # A second public source for the same actor/victim is evidence, not a new victim.
    service.ingest(
        ClaimInput(
            source="secondary-fixture",
            source_record_id="hk-copy",
            threat_actor="Regional Group",
            title="Harbour Victim",
            country="HK",
        )
    )

    daily = service.daily_focus_victims()
    digest = service.victim_digest_context(24)
    filtered = service.activity_claims(
        page=1,
        page_size=100,
        focus_only=True,
        new_only=True,
    )

    assert daily["count"] == 2
    assert {item["title"] for item in daily["items"]} == {
        "Harbour Victim",
        "Marina Victim",
    }
    assert digest["count"] == 3
    assert digest["focus_region_count"] == 2
    assert len(digest["focus_region_victims"]) == 2
    assert filtered["total"] == 2
    assert filtered["daily_focus_count"] == 2
    assert all(item["is_focus_region"] for item in filtered["items"])
    assert all(item["is_new_today"] for item in filtered["items"])


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


def test_editing_client_rematches_claims_and_removes_only_untouched_stale_alerts(tmp_path):
    service = build_service(tmp_path)
    client = service.create_client(
        ClientCreate(
            canonical_name="Original Client",
            primary_domain="original-client.example",
        )
    )
    original_claim, _ = service.ingest(
        ClaimInput(
            source="fixture",
            source_record_id="original-client-claim",
            threat_actor="Fixture Group",
            title="Original Client",
            domains=["original-client.example"],
        )
    )
    replacement_claim, _ = service.ingest(
        ClaimInput(
            source="fixture",
            source_record_id="replacement-client-claim",
            threat_actor="Fixture Group",
            title="Replacement Client",
            domains=["replacement-client.example"],
        )
    )
    assert {alert["claim_id"] for alert in service.list_alerts()} == {original_claim["id"]}

    service.update_client(
        client["id"],
        ClientCreate(
            canonical_name="Replacement Client",
            primary_domain="replacement-client.example",
        ),
    )

    assert {alert["claim_id"] for alert in service.list_alerts()} == {replacement_claim["id"]}


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
    service.ingest(
        ClaimInput(
            source="fixture",
            source_record_id="scope-one",
            threat_actor="Fixture Group",
            title="Canadian Manufacturer",
            country="Canada",
            industry="Manufacturing",
        )
    )
    service.ingest(
        ClaimInput(
            source="fixture",
            source_record_id="scope-two",
            threat_actor="Other Group",
            title="French Hospital",
            country="France",
            industry="Healthcare",
        )
    )
    overall = service.intelligence_analysis_context("overall", days=90)
    actor = service.intelligence_analysis_context("actor", "Fixture Group", 90)
    region = service.intelligence_analysis_context("region", "Canada", 90)

    assert overall["scope"] == "overall"
    assert overall["top_groups"]
    assert {item["actor"] for item in overall["threat_actor_context"]} == {
        "Fixture Group",
        "Other Group",
    }
    assert actor["label"] == "Threat actor · Fixture Group"
    assert actor["threat_actor_context"][0]["local_observations"]["claim_count"] == 1
    assert all(item["threat_actor"] == "Fixture Group" for item in actor["recent_victims"])
    assert region["scope_value"] == "Canada"
    assert all(item["country"] == "Canada" for item in region["recent_victims"])


def test_intelligence_calculates_growth_and_monitored_geographies(tmp_path):
    service = build_service(tmp_path)
    reference = utc_now()
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
            source="fixture",
            source_record_id="growth-previous",
            threat_actor="Qilin",
            title="Previous victim",
            country="Hong Kong",
            discovered_at=reference - timedelta(days=45),
        )
    )
    for index in range(2):
        service.ingest(
            ClaimInput(
                source="fixture",
                source_record_id=f"growth-current-{index}",
                threat_actor="Qilin",
                title=f"Current victim {index}",
                country="Hong Kong",
                # Monthly trend is calendar-based, so use the same current-month
                # observation time even when CI runs near a month boundary.
                discovered_at=reference,
                attack_date=reference if index == 0 else None,
            )
        )

    result = service.intelligence(days=30)

    assert result["overall_growth"]["current_count"] == 2
    assert result["overall_growth"]["previous_count"] == 1
    assert result["overall_growth"]["growth_percent"] == 100.0
    assert result["group_growth"][0]["name"] == "Qilin"
    hong_kong = next(
        item for item in result["monitored_region_growth"] if item["name"] == "Hong Kong"
    )
    assert hong_kong["current_count"] == 2
    assert result["top_countries"][0]["is_monitored"] is True
    assert len(result["monthly_trend"]) == 12
    assert result["monthly_trend"][-1]["count"] == 2
    assert result["monthly_attack_trend"][-1]["count"] == 1
    assert result["attack_date_coverage"] == round(1 / 3 * 100, 1)
    assert "deduplicated across sources" in result["counting_method"]
    assert all(
        left["month"] < right["month"]
        for left, right in zip(result["monthly_trend"], result["monthly_trend"][1:])
    )


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
    with pytest.raises(PermissionError, match="Active mode"):
        service.queue_capture(target["id"], worker_configured=True)

    service.update_runtime_settings(RuntimeSettingsUpdate(operating_mode="active"))
    with pytest.raises(RuntimeError):
        service.queue_capture(target["id"], worker_configured=False)

    job = service.queue_capture(target["id"], worker_configured=True)
    assert job["status"] == "queued"
    assert job["group_name"] == "Fixture Group"

    claimed = service.claim_next_capture_job()
    assert claimed is not None
    assert claimed["id"] == job["id"]
    assert service.claim_next_capture_job() is None

    assert service.requeue_interrupted_capture_jobs() == 1
    service.update_runtime_settings(RuntimeSettingsUpdate(operating_mode="passive"))
    assert service.claim_next_capture_job() is None
    service.update_runtime_settings(RuntimeSettingsUpdate(operating_mode="active"))
    claimed = service.claim_next_capture_job()
    assert claimed is not None
    assert claimed["id"] == job["id"]

    screenshot = service.capture_dir / "2026-07-19" / job["id"] / "page.png"
    screenshot.parent.mkdir(parents=True)
    screenshot.write_bytes(b"fixture-png")
    screenshot_two = screenshot.with_name("page-002.png")
    screenshot_two.write_bytes(b"fixture-png-two")
    text_path = screenshot.with_suffix(".txt")
    text_path.write_text(
        "Latest victim listing\nAcme Research\nacme.example\nData published",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Primary capture screenshot is missing"):
        service.complete_capture_job(
            job["id"],
            screenshot.with_name("missing-primary.png"),
            "a" * 64,
            screenshot_paths=[screenshot],
        )
    completed = service.complete_capture_job(
        job["id"],
        screenshot,
        "a" * 64,
        screenshot_paths=[screenshot, screenshot_two],
        text_path=text_path,
        text_sha256="b" * 64,
        extraction_method="dom+ocr",
        detected_statuses=["listed", "published"],
        anchor_lines=["new victim organization"],
        continuity_status="matched",
        continuity_anchor="previous victim organization",
        continuity_page=3,
        pagination_detected=True,
        more_content_suspected=False,
        status_changed=True,
        added_line_count=2,
        opsec_status="passed",
        tor_preflight_passed=True,
        blocked_request_count=4,
        blocked_popup_count=1,
        blocked_download_count=2,
        opsec_controls=["loopback_tor_socks_preflight", "same_onion_request_isolation"],
    )
    assert completed["status"] == "completed"
    assert completed["screenshot_path"].endswith("page.png")
    assert completed["segment_count"] == 2
    assert len(completed["screenshot_paths"]) == 2
    assert completed["detected_statuses"] == ["listed", "published"]
    assert completed["status_changed"] is True
    assert completed["extraction_method"] == "dom+ocr"
    assert completed["anchor_lines"] == ["new victim organization"]
    assert completed["continuity_status"] == "matched"
    assert completed["continuity_page"] == 3
    assert completed["pagination_detected"] is True
    assert completed["opsec_status"] == "passed"
    assert completed["tor_preflight_passed"] is True
    assert completed["blocked_request_count"] == 4
    assert completed["blocked_popup_count"] == 1
    assert completed["blocked_download_count"] == 2
    assert completed["opsec_controls"] == [
        "loopback_tor_socks_preflight",
        "same_onion_request_isolation",
    ]
    assert completed["evidence_readiness"] == "ready"
    assert completed["victim_candidates"][0]["domain"] == "acme.example"
    with pytest.raises(ValueError, match="running state"):
        service.complete_capture_job(job["id"], screenshot, "a" * 64)
    assert service.capture_screenshot_path(job["id"]) == screenshot
    assert service.capture_screenshot_path(job["id"], 2) == screenshot_two
    assert service.capture_text_path(job["id"]) == text_path
    assert service.previous_capture_text(target["id"], "different-job")["text"].startswith(
        "Latest victim"
    )
    assert service.previous_capture_text(target["id"], "different-job")["anchor_lines"] == [
        "new victim organization"
    ]

    label_assessment = service._capture_evidence_assessment(
        target["id"],
        "Recent posts\n16 May 2026\n[NEW]\nExample Medical Services Data Breach",
    )
    assert label_assessment["evidence_readiness"] == "ready"
    assert label_assessment["victim_candidates"][0] == {
        "name": "Example Medical Services Data Breach",
        "domain": "",
        "published_at": "2026-05-16",
        "source": "capture_label",
        "confidence": "medium",
    }

    interstitial_assessment = service._capture_evidence_assessment(
        target["id"], "Verifying your browser... Finalizing verification..."
    )
    assert interstitial_assessment["evidence_readiness"] == "not_ready"
    assert interstitial_assessment["victim_candidates"] == []


def test_capture_job_cleanup_removes_only_queued_and_failed_states(tmp_path):
    service = build_service(tmp_path)
    service.sync_dls_catalog(
        [
            DlsLocationInput(
                group_name="Cleanup Fixture",
                fqdn=f"{'e' * 56}.onion",
                available=True,
            )
        ]
    )
    target = service.list_dls_targets()[0]
    service.update_dls_target(target["id"], True)
    service.update_runtime_settings(RuntimeSettingsUpdate(operating_mode="active"))

    failed_job = service.queue_capture(target["id"], worker_configured=True)
    assert service.claim_next_capture_job()["id"] == failed_job["id"]
    service.fail_capture_job(failed_job["id"], "fixture failure")

    completed_job = service.queue_capture(target["id"], worker_configured=True)
    assert service.claim_next_capture_job()["id"] == completed_job["id"]
    screenshot = service.capture_dir / "cleanup" / "completed_p001.png"
    screenshot.parent.mkdir(parents=True)
    screenshot.write_bytes(b"completed evidence")
    service.complete_capture_job(
        completed_job["id"],
        screenshot,
        "a" * 64,
        screenshot_paths=[screenshot],
    )

    running_job = service.queue_capture(target["id"], worker_configured=True)
    assert service.claim_next_capture_job()["id"] == running_job["id"]
    queued_job = service.queue_capture(target["id"], worker_configured=True)

    result = service.clear_capture_jobs(["queued", "failed", "queued"])

    assert result == {
        "statuses": ["queued", "failed"],
        "deleted": 2,
        "deleted_by_status": {"queued": 1, "failed": 1},
    }
    with pytest.raises(KeyError):
        service.get_capture_job(queued_job["id"])
    with pytest.raises(KeyError):
        service.get_capture_job(failed_job["id"])
    assert service.get_capture_job(running_job["id"])["status"] == "running"
    assert service.get_capture_job(completed_job["id"])["status"] == "completed"
    assert screenshot.is_file()

    with pytest.raises(ValueError, match="Only queued and failed"):
        service.clear_capture_jobs(["completed"])


def test_recovery_portal_cannot_be_queued_as_public_dls_evidence(tmp_path):
    service = build_service(tmp_path)
    service.sync_dls_catalog(
        [
            DlsLocationInput(
                group_name="DragonForce",
                title="DragonForce | Recovery",
                fqdn=f"{'a' * 56}.onion",
                available=True,
            )
        ]
    )
    target = service.list_dls_targets()[0]
    service.update_dls_target(target["id"], True)
    service.update_runtime_settings(RuntimeSettingsUpdate(operating_mode="active"))

    with pytest.raises(PermissionError, match="recovery portal"):
        service.queue_capture(target["id"], worker_configured=True)

    scheduled = service.schedule_active_captures(worker_configured=True)
    assert scheduled["queued"] == 0
    assert scheduled["excluded_non_evidence_portals"] == 1


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


def test_dls_catalog_snapshot_retires_targets_missing_upstream(tmp_path):
    service = build_service(tmp_path)
    first = DlsLocationInput(group_name="Current group", fqdn=f"{'e' * 56}.onion", available=True)
    retired = DlsLocationInput(group_name="Retired group", fqdn=f"{'f' * 56}.onion", available=True)
    service.sync_dls_catalog([first, retired], retire_missing=True)
    service.sync_dls_catalog([first], retire_missing=True)

    targets = {target["group_name"]: target for target in service.list_dls_targets()}
    assert targets["Current group"]["enabled"] is True
    assert targets["Current group"]["available"] is True
    assert targets["Retired group"]["enabled"] is False
    assert targets["Retired group"]["available"] is False


def test_runtime_settings_persist_and_active_schedule_deduplicates(tmp_path):
    service = build_service(tmp_path)
    defaults = service.runtime_settings(scheduler_process_enabled=True, worker_configured=False)
    assert defaults["operating_mode"] == "passive"
    assert service.capture_worker_online() is False
    assert service.mark_capture_worker_heartbeat()
    assert service.capture_worker_online() is True
    assert defaults["public_interval_minutes"] == 2
    assert defaults["capture_max_scrolls"] == 60

    service.update_runtime_settings(
        RuntimeSettingsUpdate(
            operating_mode="active",
            scheduling_enabled=True,
            public_interval_minutes=5,
            catalog_interval_hours=12,
            active_interval_minutes=30,
            capture_max_scrolls=120,
            capture_stable_passes=5,
            capture_scroll_delay_ms=1500,
            capture_max_page_height=100000,
            capture_segment_height=1400,
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
    assert updated["capture_max_scrolls"] == 120
    assert updated["capture_stable_passes"] == 5

    service.sync_dls_catalog(
        [DlsLocationInput(group_name="Allowlisted", fqdn=f"{'b' * 56}.onion", available=True)]
    )
    target = service.list_dls_targets()[0]
    service.update_dls_target(target["id"], True)
    service.sync_dls_catalog(
        [DlsLocationInput(group_name="Stale mirror", fqdn=f"{'c' * 56}.onion", available=False)]
    )
    stale = next(
        item for item in service.list_dls_targets() if item["group_name"] == "Stale mirror"
    )
    service.update_dls_target(stale["id"], True)
    assert service.schedule_active_captures(worker_configured=True)["queued"] == 1
    assert service.schedule_active_captures(worker_configured=True)["queued"] == 0
