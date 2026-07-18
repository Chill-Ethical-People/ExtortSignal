from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import httpx

from .schemas import ClaimInput, DlsLocationInput


def parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None


class RansomLookCollector:
    name = "ransomlook"

    def __init__(self, url: str, timeout: float):
        self.url = url
        self.timeout = timeout

    async def fetch(self, days: int = 2) -> list[ClaimInput]:
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers={"User-Agent": "ExtortSignal/0.1 defensive-research"},
        ) as client:
            response = await client.get(self.url, params={"days": days})
            response.raise_for_status()
            payload = response.json()
        records = payload if isinstance(payload, list) else payload.get("posts", [])
        claims: list[ClaimInput] = []
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                continue
            title = str(record.get("post_title") or record.get("title") or "").strip()
            if not title:
                continue
            actor = str(record.get("group_name") or record.get("group") or "Unknown").strip()
            discovered = parse_datetime(record.get("discovered") or record.get("date"))
            record_id = str(
                record.get("id")
                or record.get("uuid")
                or f"{actor}:{title}:{discovered or index}"
            )
            claims.append(
                ClaimInput(
                    source=self.name,
                    source_record_id=record_id,
                    source_url=str(record.get("url") or record.get("link") or ""),
                    threat_actor=actor,
                    title=title,
                    description=str(record.get("description") or ""),
                    published_at=discovered,
                    country=str(record.get("country") or ""),
                    industry=str(record.get("sector") or record.get("industry") or ""),
                    domains=_domains(record),
                    publication_status=_publication_status(record),
                    leak_size=_leak_size(record),
                    raw=record,
                )
            )
        return claims

    async def fetch_all(self, days: int) -> tuple[list[ClaimInput], dict]:
        claims = await self.fetch(days=days)
        return claims, {
            "coverage": f"all records returned for the requested {days}-day window",
            "requests": 1,
            "truncated_partitions": [],
        }


class RansomFeedCollector:
    name = "ransomfeed"

    def __init__(self, url: str, timeout: float):
        self.url = url.rstrip("/")
        self.timeout = timeout

    async def fetch(self, limit: int = 1000) -> list[ClaimInput]:
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers={"User-Agent": "ExtortSignal/0.1 defensive-research"},
        ) as client:
            response = await client.get(f"{self.url}/offset/{min(limit, 1000)}")
            response.raise_for_status()
            payload = response.json()
        return self._parse_records(_records(payload))

    async def fetch_all(
        self, start_year: int = 2015, page_limit: int = 1000, concurrency: int = 6
    ) -> tuple[list[ClaimInput], dict]:
        """Fetch every record addressable through RansomFeed's capped REST API.

        The API's ``offset`` route is a limit (maximum 1,000), not pagination.
        Country partitions below the cap are complete. Capped countries are
        split by year, and any still-capped country/year is surfaced rather
        than silently described as complete.
        """
        page_limit = min(max(page_limit, 1), 1000)
        current_year = datetime.now(timezone.utc).year
        headers = {"User-Agent": "ExtortSignal/0.2 defensive-research"}
        request_count = 0
        request_lock = asyncio.Lock()

        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True, headers=headers
        ) as client:
            async def get_json(path: str) -> Any:
                nonlocal request_count
                response = await client.get(f"{self.url}{path}")
                response.raise_for_status()
                async with request_lock:
                    request_count += 1
                return response.json()

            country_payload = await get_json("/list/country")
            countries = _catalog_values(country_payload, "country")
            if not countries:
                raise ValueError("RansomFeed returned an empty country catalog")

            semaphore = asyncio.Semaphore(max(1, min(concurrency, 10)))

            async def get_partition(path: str) -> list[dict]:
                async with semaphore:
                    return _records(await get_json(path))

            async def fetch_country(country: str) -> tuple[list[dict], list[str]]:
                encoded = quote(country, safe="")
                records = await get_partition(
                    f"/country/{encoded}/offset/{page_limit}"
                )
                if len(records) < page_limit:
                    return records, []
                partitions = await asyncio.gather(
                    *(
                        get_partition(
                            f"/country/{encoded}/date/{year}/offset/{page_limit}"
                        )
                        for year in range(start_year, current_year + 1)
                    )
                )
                truncated = [
                    f"{country}/{year}"
                    for year, items in zip(range(start_year, current_year + 1), partitions)
                    if len(items) >= page_limit
                ]
                return [record for items in partitions for record in items], truncated

            partition_results = await asyncio.gather(
                *(fetch_country(country) for country in countries)
            )

        unique: dict[str, dict] = {}
        truncated_partitions: list[str] = []
        for records, truncated in partition_results:
            truncated_partitions.extend(truncated)
            for record in records:
                unique[_record_key(record)] = record
        coverage = (
            "partial: one or more source partitions still reached the 1,000-record cap"
            if truncated_partitions
            else "complete across the source country catalog and capped year partitions"
        )
        return self._parse_records(list(unique.values())), {
            "coverage": coverage,
            "requests": request_count,
            "countries": len(countries),
            "truncated_partitions": truncated_partitions,
        }

    def _parse_records(self, records: list[dict]) -> list[ClaimInput]:
        claims: list[ClaimInput] = []
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                continue
            title = str(record.get("victim") or record.get("post_title") or "").strip()
            if not title:
                continue
            actor = str(record.get("gang") or record.get("group_name") or "Unknown").strip()
            discovered = parse_datetime(
                record.get("date") or record.get("discovered") or record.get("published")
            )
            claims.append(
                ClaimInput(
                    source=self.name,
                    source_record_id=str(record.get("id") or f"{actor}:{title}:{discovered or index}"),
                    source_url=str(record.get("url") or record.get("link") or ""),
                    threat_actor=actor,
                    title=title,
                    description=str(record.get("description") or ""),
                    published_at=discovered,
                    country=str(record.get("country") or record.get("region") or ""),
                    industry=str(record.get("work_sector") or record.get("sector") or ""),
                    domains=_domains(record),
                    publication_status=_publication_status(record),
                    leak_size=_leak_size(record),
                    raw=record,
                )
            )
        return claims


class RansomwareLiveCollector:
    name = "ransomware_live"

    def __init__(self, url: str, timeout: float):
        self.url = url
        self.timeout = timeout

    async def fetch(self) -> list[ClaimInput]:
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers={"User-Agent": "ExtortSignal/0.1 defensive-research"},
        ) as client:
            response = await client.get(self.url)
            response.raise_for_status()
            payload = response.json()
        records = _records(payload)
        claims: list[ClaimInput] = []
        for index, record in enumerate(records):
            title = str(record.get("victim") or record.get("post_title") or "").strip()
            if not title:
                continue
            actor = str(record.get("group") or record.get("group_name") or "Unknown").strip()
            discovered = parse_datetime(
                record.get("discovered") or record.get("attackdate") or record.get("published")
            )
            claims.append(
                ClaimInput(
                    source=self.name,
                    source_record_id=str(
                        record.get("id")
                        or record.get("url")
                        or f"{actor}:{title}:{discovered or index}"
                    ),
                    source_url=str(record.get("url") or ""),
                    threat_actor=actor,
                    title=title,
                    description=str(record.get("description") or ""),
                    published_at=discovered,
                    country=str(record.get("country") or ""),
                    industry=str(record.get("activity") or record.get("sector") or ""),
                    domains=_domains(record),
                    publication_status=_publication_status(record),
                    leak_size=_leak_size(record),
                    raw=record,
                )
            )
        return claims

    async def fetch_all(self) -> tuple[list[ClaimInput], dict]:
        claims = await self.fetch()
        return claims, {
            "coverage": "recent-only: the configured free endpoint does not expose a paginated archive",
            "requests": 1,
            "truncated_partitions": ["upstream recent-victims window"],
        }


class RansomwareLiveCatalogCollector:
    """Import maintained group and public DLS location metadata.

    This collector only calls ransomware.live over HTTPS. It records onion
    addresses for the isolated Kali worker but never opens them on the app host.
    """

    name = "dls_catalog"

    def __init__(self, url: str, timeout: float):
        self.url = url
        self.timeout = timeout

    async def fetch(self) -> list[DlsLocationInput]:
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers={"User-Agent": "ExtortSignal/0.2 defensive-research"},
        ) as client:
            response = await client.get(self.url)
            response.raise_for_status()
            payload = response.json()
        groups = payload if isinstance(payload, list) else _records(payload)
        locations: list[DlsLocationInput] = []
        for group in groups:
            if not isinstance(group, dict):
                continue
            group_name = str(group.get("name") or group.get("group") or "").strip()
            if not group_name:
                continue
            description = str(group.get("description") or "").strip()
            for location in group.get("locations") or []:
                if not isinstance(location, dict):
                    continue
                fqdn = str(location.get("fqdn") or "").strip().lower()
                location_type = str(location.get("type") or "DLS").strip().upper()
                if not fqdn.endswith(".onion") or location_type != "DLS":
                    continue
                locations.append(
                    DlsLocationInput(
                        group_name=group_name,
                        description=description,
                        fqdn=fqdn,
                        location_type=location_type,
                        title=str(location.get("title") or ""),
                        enabled=bool(location.get("enabled", True)),
                        available=bool(location.get("available", False)),
                        source="ransomware_live",
                    )
                )
        return locations


def _domains(record: dict) -> list[str]:
    values: list[str] = []
    for key in ("domain", "website", "victim_website"):
        value = record.get(key)
        if value:
            values.append(str(value))
    domains = record.get("domains")
    if isinstance(domains, list):
        values.extend(str(value) for value in domains)
    return values


def _records(payload: Any) -> list[dict]:
    if isinstance(payload, list):
        return [record for record in payload if isinstance(record, dict)]
    if isinstance(payload, dict):
        for key in ("data", "results", "victims", "items", "posts"):
            candidate = payload.get(key)
            if isinstance(candidate, list):
                return [record for record in candidate if isinstance(record, dict)]
    return []


def _catalog_values(payload: Any, field: str) -> list[str]:
    values: list[Any] = payload if isinstance(payload, list) else []
    if isinstance(payload, dict):
        for key in ("data", "results", "items", "countries", "gangs"):
            if isinstance(payload.get(key), list):
                values = payload[key]
                break
    result: list[str] = []
    for item in values:
        if isinstance(item, str):
            value = item
        elif isinstance(item, dict):
            value = str(item.get(field) or item.get("name") or item.get("value") or "")
        else:
            value = ""
        # Preserve source whitespace because it can be part of an exact API
        # filter value (the current catalog contains one such entry).
        if value.strip() and value not in result:
            result.append(value)
    return result


def _record_key(record: dict) -> str:
    identifier = record.get("id") or record.get("uuid")
    if identifier not in (None, ""):
        return f"id:{identifier}"
    return json.dumps(record, sort_keys=True, ensure_ascii=False, default=str)


def _publication_status(record: dict) -> str:
    value = str(
        record.get("status")
        or record.get("publication_status")
        or record.get("leak_status")
        or "claimed"
    ).strip().lower()
    aliases = {
        "published": "data_leaked",
        "leaked": "data_leaked",
        "data leaked": "data_leaked",
        "data_leaked": "data_leaked",
        "new": "claimed",
        "unknown": "unknown",
    }
    return aliases.get(value, value.replace(" ", "_"))[:40]


def _leak_size(record: dict) -> str:
    return str(
        record.get("leak_size")
        or record.get("size")
        or record.get("data_size")
        or ""
    ).strip()[:120]
