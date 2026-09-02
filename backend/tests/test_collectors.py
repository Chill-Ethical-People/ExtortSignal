import asyncio
from datetime import datetime, timezone

import httpx

from ransom_monitor import collectors
from ransom_monitor.collectors import (
    RansomFeedCollector,
    RansomLookCatalogCollector,
    RansomLookCollector,
    RansomwareLiveCollector,
    RansomwareLiveCatalogCollector,
    operator_dls_catalog,
    parse_ransomware_live_detail,
    reconcile_dls_catalogs,
    record_description,
)
from ransom_monitor.schemas import DlsLocationInput
from ransom_monitor.source_metadata import extract_record_leak_size, normalize_leak_size


def test_record_description_preserves_longest_upstream_narrative():
    assert (
        record_description(
            {
                "description": "short",
                "post_description": "the complete upstream description",
            }
        )
        == "the complete upstream description"
    )


def test_leak_size_parser_preserves_source_value_and_normalizes_bytes():
    parsed = extract_record_leak_size({"metadata": {"data_exfiltrated": "approximately 1.25 TiB"}})

    assert parsed is not None
    assert parsed.raw == "approximately 1.25 TiB"
    assert parsed.bytes == 1_374_389_534_720
    assert parsed.source == "structured:metadata.data_exfiltrated"
    assert normalize_leak_size("2,300 GB").bytes == 2_300_000_000_000


def test_ransomware_live_detail_parser_extracts_labelled_rows():
    html = """
    <div class="rl-info-row">
      <span class="rl-info-label">Group</span>
      <span class="rl-info-value"><span>Orova</span><span>New Group</span></span>
    </div>
    <div class="rl-info-row">
      <span class="rl-info-label">Est. attack date</span>
      <span class="rl-info-value">2026-08-05</span>
    </div>
    <div class="rl-info-row">
      <span class="rl-info-label">Country</span>
      <span class="rl-info-value"><img alt="US"></span>
    </div>
    <div class="rl-info-row">
      <span class="rl-info-label">Data exfiltrated</span>
      <span class="rl-info-value">150.00 GB</span>
    </div>
    """

    assert parse_ransomware_live_detail(html) == {
        "group": "Orova New Group",
        "est. attack date": "2026-08-05",
        "country": "US",
        "data exfiltrated": "150.00 GB",
    }


def test_ransomware_live_supplements_null_api_size_from_detail_page(monkeypatch):
    source_url = "https://www.ransomware.live/id/example"

    def handler(request):
        if request.url.path == "/v2/recentvictims":
            return httpx.Response(
                200,
                json=[
                    {
                        "victim": "FixIT Tek",
                        "group": "Orova",
                        "url": source_url,
                        "discovered": "2026-08-05T07:21:07+00:00",
                        "attackdate": "2026-08-05T00:00:00+00:00",
                        "country": "US",
                        "activity": "Technology",
                        "domain": "fixittek.com",
                        "data_size": None,
                        "screenshot": "https://images.ransomware.live/fixit.png",
                    }
                ],
            )
        return httpx.Response(
            200,
            headers={"content-type": "text/html; charset=utf-8"},
            text="""
              <div class="rl-info-row"><span class="rl-info-label">Group</span><span class="rl-info-value"><span>Orova</span><span>New Group</span></span></div>
              <div class="rl-info-row"><span class="rl-info-label">Data exfiltrated</span><span class="rl-info-value">150.00 GB</span></div>
            """,
        )

    install_transport(monkeypatch, handler)
    collector = RansomwareLiveCollector("https://api.ransomware.live/v2/recentvictims", 5)
    records = asyncio.run(collector.fetch())
    enriched, report = asyncio.run(collector.enrich_details(records, {records[0].source_record_id}))

    assert report == {"checked": 1, "enriched": 1, "failed": 0}
    assert enriched[0].leak_size == "150.00 GB"
    assert enriched[0].leak_size_bytes == 150_000_000_000
    assert enriched[0].leak_size_source == "detail_page:data_exfiltrated"
    assert enriched[0].attack_date.isoformat() == "2026-08-05T00:00:00+00:00"
    assert enriched[0].source_screenshot_url.endswith("fixit.png")
    assert enriched[0].source_tags == ["New group"]
    assert enriched[0].raw["_extortsignal_detail_page"]["fields"]["data exfiltrated"] == "150.00 GB"


def test_ransomware_live_full_fetch_exhausts_monthly_archive(monkeypatch):
    now = datetime.now(timezone.utc)
    seen = []

    def handler(request):
        seen.append(request.url.path)
        month = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(
            200,
            json=[
                {
                    "id": f"record-{month}",
                    "victim": f"Victim {month}",
                    "group": "Example Group",
                    "discovered": f"{now.year}-{month}-01T00:00:00+00:00",
                }
            ],
        )

    install_transport(monkeypatch, handler)
    records, report = asyncio.run(
        RansomwareLiveCollector(
            "https://api.ransomware.live/v2/recentvictims", 5
        ).fetch_all(start_year=now.year, concurrency=2)
    )

    expected_paths = [
        f"/v2/victims/{now.year}/{month:02d}" for month in range(1, now.month + 1)
    ]
    assert seen == expected_paths
    assert len(records) == now.month
    assert report["requests"] == now.month
    assert report["months"] == now.month
    assert report["truncated_partitions"] == []
    assert report["coverage"].startswith("complete across")


def test_ransomware_live_full_fetch_reports_failed_months_and_keeps_others(monkeypatch):
    now = datetime.now(timezone.utc)

    def handler(request):
        if request.url.path.endswith("/02"):
            return httpx.Response(503)
        return httpx.Response(
            200,
            json=[
                {
                    "id": request.url.path,
                    "victim": request.url.path,
                    "group": "Example Group",
                    "discovered": f"{now.year}-01-01T00:00:00+00:00",
                }
            ],
        )

    install_transport(monkeypatch, handler)
    records, report = asyncio.run(
        RansomwareLiveCollector(
            "https://api.ransomware.live/v2/recentvictims", 5
        ).fetch_all(start_year=now.year)
    )

    assert len(records) == now.month - 1
    assert report["truncated_partitions"] == [f"{now.year}-02"]
    assert report["coverage"].startswith("partial:")
    assert report["requests"] == now.month + 2


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


def test_ransomlook_full_fetch_uses_calendar_year_periods(monkeypatch):
    now = datetime.now(timezone.utc)
    seen = []

    def handler(request):
        seen.append(request.url.path)
        year = request.url.path.split("/")[-2][:4]
        return httpx.Response(
            200,
            json=[
                {
                    "misp_uuid": f"post-{year}",
                    "post_title": f"Victim {year}",
                    "group_name": "Example Group",
                    "discovered": f"{year}-01-02 00:00:00",
                }
            ],
        )

    install_transport(monkeypatch, handler)
    records, report = asyncio.run(
        RansomLookCollector("https://look.example/api/posts", 5).fetch_all(
            start_year=now.year - 1, concurrency=2
        )
    )

    assert len(records) == 2
    assert seen[0] == f"/api/posts/period/{now.year - 1}-01-01/{now.year - 1}-12-31"
    assert seen[1].startswith(f"/api/posts/period/{now.year}-01-01/")
    assert report["years"] == 2
    assert report["requests"] == 2
    assert report["truncated_partitions"] == []
    assert report["coverage"].startswith("complete across")


def test_ransomlook_full_fetch_retries_and_reports_failed_year(monkeypatch):
    now = datetime.now(timezone.utc)

    def handler(_request):
        return httpx.Response(503)

    install_transport(monkeypatch, handler)
    records, report = asyncio.run(
        RansomLookCollector("https://look.example/api/posts", 5).fetch_all(
            start_year=now.year
        )
    )

    assert records == []
    assert report["requests"] == 2
    assert report["truncated_partitions"] == [str(now.year)]
    assert report["coverage"].startswith("partial:")


def test_ransomfeed_routine_fetch_uses_maximum_recent_limit(monkeypatch):
    seen = []

    def handler(request):
        seen.append(request.url.path)
        return httpx.Response(200, json=[victim(1, "A")])

    install_transport(monkeypatch, handler)
    records = asyncio.run(RansomFeedCollector("https://feed.example", 5).fetch())

    assert seen == ["/offset/1000"]
    assert [record.source_record_id for record in records] == ["1"]


def test_ransomfeed_full_fetch_uses_public_export_and_enriches_recent_rows(monkeypatch):
    export = (
        "ID^HASH^VICTIM^GANG^DATE^GUID^DESCR\n"
        "1^hash-one^Victim One^example-group^\"2025-01-02 00:00:00\"^guid-one^Older description\n"
        "2^hash-two^Victim Two^example-group^\"2026-01-02 00:00:00\"^guid-two^\n"
    )

    def handler(request):
        if request.url.path == "/offset/1000":
            enriched = victim(2, "USA")
            enriched["work_sector"] = "Technology"
            return httpx.Response(200, json=[enriched, victim(3, "UK")])
        if request.url.path == "/stats":
            return httpx.Response(200, json={"total": 3})
        return httpx.Response(404)

    install_transport(monkeypatch, handler)
    monkeypatch.setattr(collectors, "_download_ransomfeed_export", lambda *_args: export)
    records, report = asyncio.run(RansomFeedCollector("https://feed.example", 5).fetch_all())

    assert {record.source_record_id for record in records} == {"1", "2", "3"}
    enriched = next(record for record in records if record.source_record_id == "2")
    assert enriched.country == "USA"
    assert enriched.industry == "Technology"
    assert report == {
        "coverage": "complete public full-dataset export; 3 unique records reconcile to the source aggregate",
        "requests": 3,
        "archive_format": "caret-delimited CSV",
        "export_records": 2,
        "recent_enrichment_records": 2,
        "warnings": [],
        "upstream_total": 3,
        "reconciled_records": 3,
        "aggregate_delta": 0,
        "truncated_partitions": [],
    }


def test_ransomfeed_full_fetch_reports_aggregate_shortfall(monkeypatch):
    export = (
        "ID^HASH^VICTIM^GANG^DATE^GUID^DESCR\n"
        "1^hash^Victim One^example-group^\"2026-01-02 00:00:00\"^guid^\n"
    )

    def handler(request):
        if request.url.path == "/offset/1000":
            return httpx.Response(200, json=[])
        if request.url.path == "/stats":
            return httpx.Response(200, json={"total": 3})
        return httpx.Response(404)

    install_transport(monkeypatch, handler)
    monkeypatch.setattr(collectors, "_download_ransomfeed_export", lambda *_args: export)
    _, report = asyncio.run(
        RansomFeedCollector("https://feed.example", 5).fetch_all(page_limit=1000)
    )

    assert report["aggregate_delta"] == -2
    assert report["truncated_partitions"] == ["aggregate-shortfall:2"]
    assert report["coverage"].startswith("partial:")


def test_ransomfeed_full_export_is_retained_when_optional_rest_checks_fail(monkeypatch):
    export = (
        "ID^HASH^VICTIM^GANG^DATE^GUID^DESCR\n"
        "1^hash^Victim One^example-group^\"2026-01-02 00:00:00\"^guid^\n"
    )

    def handler(_request):
        raise httpx.ConnectError("temporary TLS failure")

    install_transport(monkeypatch, handler)
    monkeypatch.setattr(collectors, "_download_ransomfeed_export", lambda *_args: export)
    records, report = asyncio.run(RansomFeedCollector("https://feed.example", 5).fetch_all())

    assert len(records) == 1
    assert report["upstream_total"] == 0
    assert report["truncated_partitions"] == ["aggregate-total-unavailable"]
    assert report["warnings"] == [
        "recent REST enrichment unavailable",
        "aggregate verification unavailable",
    ]


def test_dls_catalog_keeps_only_unique_current_v3_dls_hosts(monkeypatch):
    host = f"{'a' * 56}.onion"

    def handler(_request):
        return httpx.Response(
            200,
            json=[
                {
                    "name": "Fixture actor",
                    "locations": [
                        {"fqdn": host, "type": "DLS", "enabled": False},
                        {
                            "fqdn": host,
                            "type": "DLS",
                            "enabled": True,
                            "available": True,
                        },
                        {"fqdn": f"{'b' * 56}.onion", "type": "Chat"},
                        {"fqdn": "legacyaddress123.onion", "type": "DLS"},
                        {"fqdn": "https://example.onion/path", "type": "DLS"},
                    ],
                }
            ],
        )

    install_transport(monkeypatch, handler)
    locations = asyncio.run(RansomwareLiveCatalogCollector("https://catalog.example", 5).fetch())

    assert len(locations) == 1
    assert locations[0].fqdn == host
    assert locations[0].enabled is True
    assert locations[0].available is True


def test_collectors_normalize_actor_aliases_and_exclude_recovery_portals(monkeypatch):
    blog_host = f"{'c' * 56}.onion"
    recovery_host = f"{'d' * 56}.onion"

    def handler(_request):
        return httpx.Response(
            200,
            json=[
                {
                    "name": "incRansom",
                    "locations": [
                        {
                            "fqdn": blog_host,
                            "type": "DLS",
                            "title": "Disclosures blog",
                            "enabled": True,
                        },
                        {
                            "fqdn": recovery_host,
                            "type": "DLS",
                            "title": "INC Recovery",
                            "enabled": True,
                        },
                    ],
                }
            ],
        )

    install_transport(monkeypatch, handler)
    locations = asyncio.run(RansomwareLiveCatalogCollector("https://catalog.example", 5).fetch())

    assert [(item.group_name, item.fqdn) for item in locations] == [("INC Ransom", blog_host)]


def test_ransomlook_catalog_queries_only_requested_public_groups(monkeypatch):
    blog_host = f"{'e' * 56}.onion"
    chat_host = f"{'f' * 56}.onion"

    def handler(request):
        if request.url.path == "/api/groups":
            return httpx.Response(200, json=["incRansom", "Historical Group"])
        if request.url.path == "/api/group/incRansom":
            return httpx.Response(
                200,
                json=[
                    {
                        "meta": "Current <b>public</b> profile",
                        "locations": [
                            {
                                "fqdn": blog_host,
                                "version": 3,
                                "title": "Disclosures blog",
                                "available": True,
                                "fs": False,
                                "chat": False,
                                "admin": False,
                            },
                            {
                                "fqdn": chat_host,
                                "version": 3,
                                "title": "Enter the key",
                                "available": True,
                                "chat": True,
                            },
                        ],
                    },
                    [],
                ],
            )
        return httpx.Response(404)

    install_transport(monkeypatch, handler)
    locations, report = asyncio.run(
        RansomLookCatalogCollector("https://look.example/api/groups", 5).fetch_for_actors(
            ["INC Ransom"]
        )
    )

    assert [(item.group_name, item.fqdn) for item in locations] == [
        ("INC Ransom", blog_host)
    ]
    assert locations[0].description == "Current public profile"
    assert locations[0].source == "ransomlook"
    assert report["actors_matched"] == 1
    assert report["non_dls_role"] == 1


def test_dls_catalog_reconciliation_retains_cross_source_provenance():
    shared = f"{'g' * 56}.onion"
    live = DlsLocationInput(
        group_name="Fixture actor",
        fqdn=shared,
        title="Unavailable mirror",
        enabled=True,
        available=False,
        source="ransomware_live",
    )
    look = DlsLocationInput(
        group_name="Fixture actor",
        fqdn=shared,
        title="Victim list",
        enabled=True,
        available=True,
        source="ransomlook",
    )

    locations, report = reconcile_dls_catalogs([[live], [look]])

    assert len(locations) == 1
    assert locations[0].title == "Victim list"
    assert locations[0].available is True
    assert locations[0].source == "ransomware_live+ransomlook"
    assert report == {
        "accepted": 1,
        "overlapping_hosts": 1,
        "identity_conflicts": 0,
        "identity_conflict_labels": [],
        "availability_conflicts": 1,
    }


def test_operator_dls_catalog_adds_fulcrumsec_without_network_discovery():
    locations = operator_dls_catalog()

    assert len(locations) == 1
    assert locations[0].group_name == "FulcrumSec"
    assert locations[0].fqdn == "fulcrumsec.vg"
    assert locations[0].source == "operator_static"
    assert locations[0].enabled is True
    assert locations[0].available is True
