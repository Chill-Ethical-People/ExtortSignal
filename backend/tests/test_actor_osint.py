import asyncio

import httpx

from ransom_monitor import actor_osint


def test_actor_research_keeps_attributable_curated_sources(monkeypatch):
    original = httpx.AsyncClient
    fetched_hosts: list[str] = []

    def handler(request):
        fetched_hosts.append(request.url.host)
        if request.url.host == "api.gdeltproject.org":
            assert request.url.params["timespan"] in {"1year", "5years"}
            return httpx.Response(
                200,
                json={
                    "articles": [
                        {
                            "title": "Example Group ransomware tactics observed",
                            "url": "https://www.cisa.gov/example-group-advisory",
                            "seendate": "20260102T030405Z",
                        },
                        {
                            "title": "Example Group rumor",
                            "url": "https://untrusted.example/report",
                            "seendate": "20260101T000000Z",
                        },
                    ]
                },
            )
        if request.url.host == "www.cisa.gov":
            return httpx.Response(
                200,
                headers={"content-type": "text/html; charset=utf-8"},
                text="""<html><head><title>Example Group advisory</title>
                <meta name="description" content="CISA describes Example Group ransomware behavior." />
                </head><body><main>Example Group affiliates use phishing and exposed remote services.
                Defenders should review the cited ATT&amp;CK techniques and mitigations.</main></body></html>""",
            )
        raise AssertionError(f"Unexpected request: {request.url}")

    def client(**kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return original(**kwargs)

    monkeypatch.setattr(actor_osint.httpx, "AsyncClient", client)
    result = asyncio.run(
        actor_osint.research_actor_osint(
            "Example Group",
            ["Example Alias"],
            {
                "canonical_name": "Example Group",
                "description": "ATT&CK description of Example Group.",
                "attack_url": "https://attack.mitre.org/groups/G9999/",
                "modified": "2026-01-01T00:00:00Z",
                "refreshed_at": "2026-01-03T00:00:00+00:00",
                "techniques": [{"id": "T1566", "name": "Phishing"}],
                "software": [],
                "campaigns": [],
                "references": [
                    {
                        "source": "Microsoft Security",
                        "title": "Microsoft research on Example Group",
                        "url": "https://www.microsoft.com/security/blog/example-group/",
                    }
                ],
            },
        )
    )

    assert result["status"] == "evidence_found"
    assert {item["source_name"] for item in result["evidence"]} == {
        "CISA",
        "MITRE ATT&CK",
        "Microsoft Security",
    }
    assert "untrusted.example" not in fetched_hosts
    cisa = next(item for item in result["evidence"] if item["source_name"] == "CISA")
    assert cisa["source_tier"] == "authoritative"
    assert cisa["published_at"] == "2026-01-02T03:04:05+00:00"
    assert "phishing" in cisa["excerpt"].casefold()
    assert len(result["queries"]) == 1


def test_actor_research_failure_preserves_structured_mitre_evidence(monkeypatch):
    original = httpx.AsyncClient

    def client(**kwargs):
        kwargs["transport"] = httpx.MockTransport(lambda request: httpx.Response(503))
        return original(**kwargs)

    monkeypatch.setattr(actor_osint.httpx, "AsyncClient", client)
    result = asyncio.run(
        actor_osint.research_actor_osint(
            "Example Group",
            [],
            {
                "canonical_name": "Example Group",
                "description": "Structured group description.",
                "attack_url": "https://attack.mitre.org/groups/G9999/",
                "techniques": [],
                "software": [],
                "campaigns": [],
            },
        )
    )

    assert result["status"] == "evidence_found"
    assert result["evidence_count"] == 1
    assert result["evidence"][0]["source_name"] == "MITRE ATT&CK"
    assert result["warnings"]
