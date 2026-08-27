import asyncio
import json

import httpx
import pytest

from ransom_monitor.ai_enrichment import (
    AIEnrichmentError,
    _parse_json_content,
    normalize_actor_analysis,
    normalize_notification_draft,
    normalize_victim_enrichment,
    probe_ai_connection,
)


def test_notification_draft_requires_exactly_four_paragraphs():
    result = normalize_notification_draft(
        {"subject": "Client alert", "paragraphs": ["One", "Two", "Three", "Four"]}
    )
    assert result["paragraphs"] == ["One", "Two", "Three", "Four"]
    with pytest.raises(AIEnrichmentError, match="exactly four"):
        normalize_notification_draft(
            {"subject": "Client alert", "paragraphs": ["One", "Two", "Three"]}
        )


def test_json_parser_extracts_object_after_reasoning_and_fence():
    result = _parse_json_content(
        '<think>Classify conservatively.</think>\n```json\n{"summary":"Observed only","confidence":61}\n```'
    )
    assert result == {"summary": "Observed only", "confidence": 61}


def test_json_parser_accepts_openai_content_blocks():
    result = _parse_json_content([{"type": "text", "text": '{"industry":"Technology"}'}])
    assert result["industry"] == "Technology"


def run_probe(handler):
    async def execute():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await probe_ai_connection(
                base_url="https://provider.example/v1",
                model="verified-model",
                api_key="secret-test-key",
                client=client,
            )

    return asyncio.run(execute())


def test_connection_probe_requires_live_random_challenge_response():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"data": [{"id": "verified-model"}]})
        payload = json.loads(request.content)
        assert request.headers["Authorization"] == "Bearer secret-test-key"
        if payload.get("response_format"):
            challenge = payload["messages"][1]["content"].rsplit(": ", 1)[1]
            content = json.dumps({"challenge": challenge, "ok": True})
        else:
            content = payload["messages"][0]["content"].rsplit(": ", 1)[1]
        return httpx.Response(200, json={
            "id": "chatcmpl-test-123",
            "model": "verified-model-2026-07",
            "choices": [{"message": {"content": content}}],
        })

    result = run_probe(handler)

    assert result["status"] == "verified"
    assert result["challenge_verified"] is True
    assert result["json_verified"] is True
    assert len(result["checks"]) == 3
    assert result["response_id"] == "chatcmpl-test-123"
    assert result["upstream_model"] == "verified-model-2026-07"
    assert result["endpoint_host"] == "provider.example"


def test_connection_probe_rejects_canned_success_response():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"data": [{"id": "verified-model"}]})
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "connection ok"}}],
        })

    with pytest.raises(AIEnrichmentError, match="random verification challenge"):
        run_probe(handler)


def test_connection_probe_explains_rejected_credential():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": "invalid key"}})

    with pytest.raises(AIEnrichmentError, match="rejected the API credential"):
        run_probe(handler)


def test_normalize_actor_analysis_limits_untrusted_model_output():
    result = normalize_actor_analysis(
        {
            "summary": "  Observed activity only.  ",
            "patterns": ["One", "Two", "Three", "Four", "Five", "Six"],
            "risk_observations": ["Review concentration"],
            "caveats": ["Public claims are unverified"],
            "confidence": "84",
        }
    )
    assert result["summary"] == "Observed activity only."
    assert len(result["patterns"]) == 5
    assert result["confidence"] == 84


def test_normalize_victim_enrichment_handles_invalid_confidence():
    result = normalize_victim_enrichment(
        {
            "industry": "Technology",
            "brief_description": "A supplied-record classification.",
            "organization_type": "Company",
            "confidence": "unknown",
        }
    )
    assert result["industry"] == "Technology"
    assert result["confidence"] == 0


def test_normalize_victim_enrichment_bounds_incident_candidates():
    result = normalize_victim_enrichment(
        {
            "past_incidents": [
                {
                    "published_at": "2026-01-02T03:04:05+00:00",
                    "incident_type": "Data breach",
                    "summary": "A publication reported a prior incident.",
                    "source_url": "https://news.example/report",
                    "confidence": 81,
                },
                {"summary": "Missing evidence URL"},
            ]
        }
    )

    assert len(result["past_incidents"]) == 1
    assert result["past_incidents"][0]["confidence"] == 81
