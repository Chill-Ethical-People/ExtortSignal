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
