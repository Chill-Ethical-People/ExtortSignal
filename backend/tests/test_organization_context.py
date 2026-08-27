import asyncio

import httpx

from ransom_monitor import organization_context


def test_background_lookup_returns_bounded_public_candidates(monkeypatch):
    original = httpx.AsyncClient

    def handler(request):
        assert request.url.host == "en.wikipedia.org"
        assert request.url.params["generator"] == "search"
        return httpx.Response(
            200,
            json={
                "query": {
                    "pages": [
                        {
                            "title": "Example Corporation",
                            "extract": "Example Corporation is a manufacturing company.",
                        }
                    ]
                }
            },
        )

    def client(**kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return original(**kwargs)

    organization_context._cache.clear()
    monkeypatch.setattr(organization_context.httpx, "AsyncClient", client)
    result = asyncio.run(
        organization_context.lookup_organization_background(
            "Example Corporation", ["example.com"]
        )
    )

    assert result["status"] == "candidates_found"
    assert result["candidates"] == [
        {
            "title": "Example Corporation",
            "extract": "Example Corporation is a manufacturing company.",
            "url": "https://en.wikipedia.org/wiki/Example_Corporation",
        }
    ]


def test_background_lookup_failure_is_visible_and_nonfatal(monkeypatch):
    original = httpx.AsyncClient

    def client(**kwargs):
        kwargs["transport"] = httpx.MockTransport(
            lambda request: httpx.Response(503)
        )
        return original(**kwargs)

    organization_context._cache.clear()
    monkeypatch.setattr(organization_context.httpx, "AsyncClient", client)
    result = asyncio.run(
        organization_context.lookup_organization_background("Unavailable Co", [])
    )

    assert result["status"] == "lookup_unavailable"
    assert result["candidates"] == []


def test_incident_lookup_returns_dated_bounded_candidates(monkeypatch):
    original = httpx.AsyncClient

    def handler(request):
        assert request.url.host == "api.gdeltproject.org"
        assert request.url.params["timespan"] == "5years"
        return httpx.Response(200, json={"articles": [{
            "title": "Example Corporation reports data breach",
            "url": "https://news.example/example-breach",
            "seendate": "20260102T030405Z",
            "domain": "news.example",
            "sourcecountry": "United States",
        }]})

    def client(**kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return original(**kwargs)

    organization_context._cache.clear()
    monkeypatch.setattr(organization_context.httpx, "AsyncClient", client)
    result = asyncio.run(
        organization_context.lookup_public_incident_candidates("Example Corporation")
    )

    assert result["status"] == "candidates_found"
    assert result["coverage"] == "past_five_years"
    assert result["candidates"][0]["published_at"] == "2026-01-02T03:04:05+00:00"


def test_organization_reporting_is_bounded_to_matching_https_titles(monkeypatch):
    original = httpx.AsyncClient

    def client(**kwargs):
        kwargs["transport"] = httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json={
                    "articles": [
                        {
                            "title": "Example Corporation expands manufacturing services",
                            "url": "https://business.example/example-profile",
                            "seendate": "20250102T030405Z",
                            "domain": "business.example",
                        },
                        {
                            "title": "Unrelated company expands",
                            "url": "https://business.example/unrelated",
                            "seendate": "20250102T030405Z",
                        },
                        {
                            "title": "Example Corporation insecure result",
                            "url": "http://business.example/insecure",
                            "seendate": "20250102T030405Z",
                        },
                    ]
                },
            )
        )
        return original(**kwargs)

    organization_context._cache.clear()
    monkeypatch.setattr(organization_context.httpx, "AsyncClient", client)
    result = asyncio.run(
        organization_context.lookup_organization_reporting_candidates(
            "Example Corporation", ["example.com"]
        )
    )

    assert result["coverage"] == "past_five_years_title_index"
    assert [item["url"] for item in result["candidates"]] == [
        "https://business.example/example-profile"
    ]
