import asyncio
from datetime import datetime, timezone

import httpx

from ransom_monitor import collectors
from ransom_monitor.collectors import RansomFeedCollector


def install_transport(monkeypatch, handler):
    original = httpx.AsyncClient

    def client(**kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return original(**kwargs)

    monkeypatch.setattr(collectors.httpx, "AsyncClient", client)


def victim(identifier, country):
    return {
        "id": identifier,
        "victim": f"Victim {identifier}",
        "gang": "example-group",
        "country": country,
        "date": "2026-01-02 00:00:00",
    }


def test_ransomfeed_routine_fetch_uses_maximum_recent_limit(monkeypatch):
    seen = []

    def handler(request):
        seen.append(request.url.path)
        return httpx.Response(200, json=[victim(1, "A")])

    install_transport(monkeypatch, handler)
    records = asyncio.run(RansomFeedCollector("https://feed.example", 5).fetch())

    assert seen == ["/offset/1000"]
    assert [record.source_record_id for record in records] == ["1"]


def test_ransomfeed_full_fetch_splits_capped_country_by_year(monkeypatch):
    year = datetime.now(timezone.utc).year
    seen = []

    def handler(request):
        path = request.url.path
        seen.append(path)
        if path == "/list/country":
            return httpx.Response(200, json=["A", "B"])
        if path == "/country/A/offset/2":
            return httpx.Response(200, json=[victim(1, "A"), victim(2, "A")])
        if path == f"/country/A/date/{year}/offset/2":
            return httpx.Response(200, json=[victim(2, "A")])
        if path == "/country/B/offset/2":
            return httpx.Response(200, json=[victim(3, "B")])
        return httpx.Response(404)

    install_transport(monkeypatch, handler)
    records, report = asyncio.run(
        RansomFeedCollector("https://feed.example", 5).fetch_all(
            start_year=year, page_limit=2, concurrency=2
        )
    )

    assert {record.source_record_id for record in records} == {"2", "3"}
    assert f"/country/A/date/{year}/offset/2" in seen
    assert report == {
        "coverage": "complete across the source country catalog and capped year partitions",
        "requests": 4,
        "countries": 2,
        "truncated_partitions": [],
    }


def test_ransomfeed_full_fetch_reports_a_still_capped_partition(monkeypatch):
    year = datetime.now(timezone.utc).year

    def handler(request):
        if request.url.path == "/list/country":
            return httpx.Response(200, json={"data": ["A"]})
        return httpx.Response(200, json=[victim(1, "A"), victim(2, "A")])

    install_transport(monkeypatch, handler)
    _, report = asyncio.run(
        RansomFeedCollector("https://feed.example", 5).fetch_all(
            start_year=year, page_limit=2
        )
    )

    assert report["truncated_partitions"] == [f"A/{year}"]
    assert report["coverage"].startswith("partial:")
