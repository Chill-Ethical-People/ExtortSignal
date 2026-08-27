from __future__ import annotations

import asyncio
import csv
import io
import json
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any
from urllib.error import URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

import httpx

from .actor_names import canonical_actor_name
from .dls_policy import is_public_evidence_location
from .schemas import ClaimInput, DlsLocationInput
from .source_metadata import (
    extract_record_leak_size,
    leak_size_source_priority,
    normalize_leak_size,
)


def parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip().replace("Z", "+00:00")
    if text.upper().endswith(" UTC"):
        text = f"{text[:-4].strip()}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None


def record_description(record: dict) -> str:
    """Keep the longest source-supplied narrative without synthesizing missing text."""
    candidates = [
        record.get("description"),
        record.get("post_description"),
        record.get("content"),
        record.get("details"),
        record.get("excerpt"),
    ]
    values = [str(value).strip() for value in candidates if value and str(value).strip()]
    return max(values, key=len, default="")


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
        return self._parse_records(records)

    def _parse_records(self, records: list[dict]) -> list[ClaimInput]:
        claims: list[ClaimInput] = []
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                continue
            title = str(record.get("post_title") or record.get("title") or "").strip()
            if not title:
                continue
            actor = canonical_actor_name(
                str(record.get("group_name") or record.get("group") or "Unknown")
            )
            discovered = parse_datetime(record.get("discovered") or record.get("date"))
            record_id = str(
                record.get("id") or record.get("uuid") or f"{actor}:{title}:{discovered or index}"
            )
            claims.append(
                ClaimInput(
                    source=self.name,
                    source_record_id=record_id,
                    source_url=str(record.get("url") or record.get("link") or ""),
                    threat_actor=actor,
                    title=title,
                    description=record_description(record),
                    published_at=discovered,
                    attack_date=_attack_date(record),
                    country=str(record.get("country") or ""),
                    industry=str(record.get("sector") or record.get("industry") or ""),
                    domains=_domains(record),
                    publication_status=_publication_status(record),
                    **_source_metadata(record),
                    raw=record,
                )
            )
        return claims

    async def fetch_all(
        self, start_year: int = 2015, concurrency: int = 3
    ) -> tuple[list[ClaimInput], dict]:
        """Fetch bounded calendar-year partitions from RansomLook's period API.

        A single multi-year ``days`` response is difficult to distinguish from
        a silently shortened upstream response.  The public period route makes
        every requested year independently observable and retryable.
        """
        now = datetime.now(timezone.utc)
        start_year = max(2015, min(start_year, now.year))
        parsed = urlsplit(self.url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("RansomLook history requires a configured HTTPS API URL")
        api_path = parsed.path.rstrip("/")
        if api_path.endswith("/posts"):
            api_path = api_path[: -len("/posts")]
        period_root = f"{parsed.scheme}://{parsed.netloc}{api_path}/posts/period".rstrip("/")
        periods = [
            (
                year,
                datetime(year, 1, 1, tzinfo=timezone.utc).date().isoformat(),
                (now.date() if year == now.year else datetime(year, 12, 31).date()).isoformat(),
            )
            for year in range(start_year, now.year + 1)
        ]
        semaphore = asyncio.Semaphore(max(1, min(concurrency, 4)))
        failed: set[str] = set()
        request_count = 0
        request_lock = asyncio.Lock()

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,
            headers={"User-Agent": "ExtortSignal/0.2 defensive-research"},
            transport=httpx.AsyncHTTPTransport(retries=2),
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=3),
        ) as client:

            async def fetch_period(year: int, start: str, end: str) -> list[dict]:
                nonlocal request_count
                try:
                    async with request_lock:
                        request_count += 1
                    async with semaphore:
                        response = await client.get(f"{period_root}/{start}/{end}")
                    response.raise_for_status()
                    records = _records(response.json())
                    failed.discard(str(year))
                    return records
                except (httpx.HTTPError, TypeError, ValueError):
                    failed.add(str(year))
                    return []

            partitions = await asyncio.gather(
                *(fetch_period(year, start, end) for year, start, end in periods)
            )
            for year_text in sorted(failed):
                year = int(year_text)
                _, start, end = next(item for item in periods if item[0] == year)
                retry_records = await fetch_period(year, start, end)
                if year_text not in failed:
                    partitions.append(retry_records)

        unique: dict[str, dict] = {}
        for records in partitions:
            for record in records:
                unique[_record_key(record)] = record
        coverage = (
            f"partial: {len(failed)} of {len(periods)} calendar-year partitions failed after retry"
            if failed
            else f"complete across {len(periods)} calendar-year partitions from {start_year} through {now.year}"
        )
        return self._parse_records(list(unique.values())), {
            "coverage": coverage,
            "requests": request_count,
            "years": len(periods),
            "truncated_partitions": sorted(failed),
        }


class RansomFeedCollector:
    name = "ransomfeed"

    def __init__(
        self,
        url: str,
        timeout: float,
        export_url: str = "https://www.ransomfeed.it/export-data.php",
    ):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.export_url = export_url

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
        self, start_year: int = 2015, page_limit: int = 1000, concurrency: int = 3
    ) -> tuple[list[ClaimInput], dict]:
        """Fetch RansomFeed's public full-dataset export and reconcile it.

        The filtered REST routes are useful for prompt monitoring and current
        enrichment but are not historically exhaustive: source statistics can
        exceed an actor filter even when it returns fewer than the documented
        1,000-row cap. The dashboard's public ``Tutto il dataset`` CSV is the
        authoritative free archive and is checked against ``/stats.total``.
        """
        del start_year, concurrency  # The public export is already complete history.
        page_limit = min(max(page_limit, 1), 1000)
        headers = {"User-Agent": "ExtortSignal/0.2 defensive-research"}
        export = urlsplit(self.export_url)
        if (
            export.scheme != "https"
            or not export.hostname
            or not export.hostname.lower().endswith("ransomfeed.it")
        ):
            raise ValueError("RansomFeed history requires the official HTTPS export URL")

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers=headers,
            transport=httpx.AsyncHTTPTransport(retries=2),
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=3),
        ) as client:
            export_text = await asyncio.to_thread(
                _download_ransomfeed_export,
                self.export_url,
                self.timeout,
            )
            recent_result, stats_result = await asyncio.gather(
                client.get(f"{self.url}/offset/{page_limit}"),
                client.get(f"{self.url}/stats"),
                return_exceptions=True,
            )

        export_records = _parse_ransomfeed_export(export_text)
        if not export_records:
            raise ValueError("RansomFeed full-dataset export contained no records")
        warnings: list[str] = []
        recent_records: list[dict] = []
        if isinstance(recent_result, httpx.Response):
            try:
                recent_result.raise_for_status()
                recent_records = _records(recent_result.json())
            except (httpx.HTTPError, TypeError, ValueError):
                warnings.append("recent REST enrichment unavailable")
        else:
            warnings.append("recent REST enrichment unavailable")
        stats_payload: Any = {}
        if isinstance(stats_result, httpx.Response):
            try:
                stats_result.raise_for_status()
                stats_payload = stats_result.json()
            except (httpx.HTTPError, TypeError, ValueError):
                warnings.append("aggregate verification unavailable")
        else:
            warnings.append("aggregate verification unavailable")
        upstream_total = int(stats_payload.get("total", 0)) if isinstance(stats_payload, dict) else 0

        unique: dict[str, dict] = {}
        for record in export_records:
            unique[_record_key(record)] = record
        # Prefer non-empty REST fields on the recent head; the CSV remains the
        # provenance-bearing base record and supplies all historical IDs.
        for record in recent_records:
            key = _record_key(record)
            existing = unique.get(key, {})
            unique[key] = {
                **existing,
                **{field: value for field, value in record.items() if value not in (None, "")},
            }
        truncated_partitions: list[str] = []
        aggregate_delta = len(unique) - upstream_total if upstream_total else None
        if upstream_total <= 0:
            truncated_partitions.append("aggregate-total-unavailable")
        elif aggregate_delta is not None and aggregate_delta < 0:
            truncated_partitions.append(f"aggregate-shortfall:{-aggregate_delta}")
        coverage = (
            "partial: the public full-dataset export did not reconcile to the source aggregate"
            if truncated_partitions
            else (
                f"complete public full-dataset export; {len(unique)} unique records "
                "reconcile to the source aggregate"
            )
        )
        return self._parse_records(list(unique.values())), {
            "coverage": coverage,
            "requests": 3,
            "archive_format": "caret-delimited CSV",
            "export_records": len(export_records),
            "recent_enrichment_records": len(recent_records),
            "warnings": warnings,
            "upstream_total": upstream_total,
            "reconciled_records": len(unique),
            "aggregate_delta": aggregate_delta,
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
            actor = canonical_actor_name(
                str(record.get("gang") or record.get("group_name") or "Unknown")
            )
            discovered = parse_datetime(
                record.get("date") or record.get("discovered") or record.get("published")
            )
            claims.append(
                ClaimInput(
                    source=self.name,
                    source_record_id=str(
                        record.get("id") or f"{actor}:{title}:{discovered or index}"
                    ),
                    source_url=str(record.get("url") or record.get("link") or ""),
                    threat_actor=actor,
                    title=title,
                    description=record_description(record),
                    published_at=discovered,
                    attack_date=_attack_date(record),
                    country=str(record.get("country") or record.get("region") or ""),
                    industry=str(record.get("work_sector") or record.get("sector") or ""),
                    domains=_domains(record),
                    publication_status=_publication_status(record),
                    **_source_metadata(record),
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
        return self._parse_records(_records(payload))

    def _parse_records(self, records: list[dict]) -> list[ClaimInput]:
        claims: list[ClaimInput] = []
        for index, record in enumerate(records):
            title = str(record.get("victim") or record.get("post_title") or "").strip()
            if not title:
                continue
            actor = canonical_actor_name(
                str(record.get("group") or record.get("group_name") or "Unknown")
            )
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
                    description=record_description(record),
                    published_at=discovered,
                    attack_date=_attack_date(record),
                    country=str(record.get("country") or ""),
                    industry=str(record.get("activity") or record.get("sector") or ""),
                    domains=_domains(record),
                    publication_status=_publication_status(record),
                    **_source_metadata(record),
                    raw=record,
                )
            )
        return claims

    async def enrich_details(
        self, claims: list[ClaimInput], record_ids: set[str], concurrency: int = 6
    ) -> tuple[list[ClaimInput], dict]:
        """Supplement API records from their public ransomware.live detail pages.

        The recent API can expose a null ``data_size`` while the corresponding
        server-rendered detail page contains a labelled exfiltrated-data value.
        Only same-site HTTPS ``/id/`` pages are requested and individual page
        failures do not discard the base API observation.
        """
        selected = [claim for claim in claims if claim.source_record_id in record_ids]
        if not selected:
            return claims, {"checked": 0, "enriched": 0, "failed": 0}
        semaphore = asyncio.Semaphore(max(1, min(concurrency, 8)))

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,
            headers={"User-Agent": "ExtortSignal/0.2 defensive-research"},
            transport=httpx.AsyncHTTPTransport(retries=1),
            limits=httpx.Limits(max_connections=8, max_keepalive_connections=6),
        ) as client:

            async def enrich(claim: ClaimInput) -> tuple[bool, bool]:
                checked_at = datetime.now(timezone.utc)
                claim.detail_checked_at = checked_at
                parsed_url = urlsplit(claim.source_url)
                if (
                    parsed_url.scheme != "https"
                    or (parsed_url.hostname or "").casefold()
                    not in {"ransomware.live", "www.ransomware.live"}
                    or not parsed_url.path.startswith("/id/")
                ):
                    claim.detail_status = "unsupported_url"
                    return False, True
                try:
                    async with semaphore:
                        response = await client.get(claim.source_url)
                    response.raise_for_status()
                    if "text/html" not in response.headers.get("content-type", "text/html"):
                        raise ValueError("detail response was not HTML")
                    fields = parse_ransomware_live_detail(response.text)
                    enriched = _apply_ransomware_live_detail(claim, fields)
                    claim.detail_status = "enriched" if enriched else "no_additional_metadata"
                    claim.raw = {
                        **claim.raw,
                        "_extortsignal_detail_page": {
                            "url": claim.source_url,
                            "checked_at": checked_at.isoformat(),
                            "fields": fields,
                        },
                    }
                    return enriched, False
                except (httpx.HTTPError, ValueError, TypeError):
                    claim.detail_status = "failed"
                    return False, True

            tasks = [asyncio.create_task(enrich(claim)) for claim in selected]
            done, pending = await asyncio.wait(
                tasks,
                timeout=max(20.0, min(90.0, self.timeout * 3)),
            )
            for claim, task in zip(selected, tasks):
                if task in pending:
                    claim.detail_status = "failed"
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            results = [task.result() for task in done]
            results.extend((False, True) for _ in pending)
        return claims, {
            "checked": len(selected),
            "enriched": sum(1 for enriched, _ in results if enriched),
            "failed": sum(1 for _, failed in results if failed),
        }

    async def fetch_all(
        self, start_year: int = 2015, concurrency: int = 4
    ) -> tuple[list[ClaimInput], dict]:
        """Fetch every monthly archive partition through the current month.

        Routine collection deliberately keeps using the prompt, 100-record
        ``recentvictims`` feed. Full synchronization uses ransomware.live's
        documented ``victims/{year}/{month}`` archive instead, reports every
        failed month, and never describes a partial run as complete.
        """
        now = datetime.now(timezone.utc)
        start_year = max(2015, min(start_year, now.year))
        months = [
            (year, month)
            for year in range(start_year, now.year + 1)
            for month in range(1, 13)
            if (year, month) <= (now.year, now.month)
        ]
        parsed = urlsplit(self.url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("Ransomware.live archive requires a configured HTTPS API URL")
        path = parsed.path.rstrip("/")
        for suffix in ("/recentvictims", "/victims/recent"):
            if path.endswith(suffix):
                path = path[: -len(suffix)]
                break
        archive_root = f"{parsed.scheme}://{parsed.netloc}{path}/victims".rstrip("/")
        semaphore = asyncio.Semaphore(max(1, min(concurrency, 6)))
        failed: set[str] = set()
        request_count = 0
        request_lock = asyncio.Lock()

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,
            headers={"User-Agent": "ExtortSignal/0.2 defensive-research"},
            transport=httpx.AsyncHTTPTransport(retries=2),
            limits=httpx.Limits(max_connections=6, max_keepalive_connections=4),
        ) as client:

            async def fetch_month(year: int, month: int) -> list[dict]:
                nonlocal request_count
                partition = f"{year}-{month:02d}"
                try:
                    async with request_lock:
                        request_count += 1
                    async with semaphore:
                        response = await client.get(f"{archive_root}/{year}/{month:02d}")
                    response.raise_for_status()
                    records = _records(response.json())
                    failed.discard(partition)
                    return records
                except (httpx.HTTPError, TypeError, ValueError):
                    failed.add(partition)
                    return []

            partitions = await asyncio.gather(
                *(fetch_month(year, month) for year, month in months)
            )
            # A long archive pass can encounter isolated upstream connection
            # resets. Retry only failed partitions, serially and with bounded
            # backoff, before declaring a visible coverage gap.
            for retry_round in range(2):
                if not failed:
                    break
                await asyncio.sleep(0.5 * (retry_round + 1))
                for partition in sorted(failed):
                    year, month = (int(value) for value in partition.split("-", 1))
                    retry_records = await fetch_month(year, month)
                    if partition not in failed:
                        partitions.append(retry_records)

        unique: dict[str, dict] = {}
        for records in partitions:
            for record in records:
                unique[_record_key(record)] = record
        coverage = (
            f"partial: {len(failed)} of {len(months)} monthly archive partitions failed after three attempts"
            if failed
            else (
                f"complete across {len(months)} monthly archive partitions "
                f"from {months[0][0]}-{months[0][1]:02d} to {months[-1][0]}-{months[-1][1]:02d}"
            )
        )
        return self._parse_records(list(unique.values())), {
            "coverage": coverage,
            "requests": request_count,
            "months": len(months),
            "truncated_partitions": sorted(failed),
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
        locations, _report = await self.fetch_with_report()
        return locations

    async def fetch_with_report(self) -> tuple[list[DlsLocationInput], dict]:
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers={"User-Agent": "ExtortSignal/0.2 defensive-research"},
            transport=httpx.AsyncHTTPTransport(retries=2),
        ) as client:
            response = await client.get(self.url)
            response.raise_for_status()
            payload = response.json()
        groups = payload if isinstance(payload, list) else _records(payload)
        locations_by_fqdn: dict[str, DlsLocationInput] = {}
        report = {
            "groups": len(groups),
            "locations_seen": 0,
            "invalid_hosts": 0,
            "non_dls": 0,
            "non_public_evidence": 0,
            "duplicate_hosts": 0,
            "accepted": 0,
        }
        for group in groups:
            if not isinstance(group, dict):
                continue
            raw_group_name = str(group.get("name") or group.get("group") or "").strip()
            if not raw_group_name:
                continue
            group_name = canonical_actor_name(raw_group_name)
            description = str(group.get("description") or "").strip()
            for location in group.get("locations") or []:
                if not isinstance(location, dict):
                    continue
                report["locations_seen"] += 1
                fqdn = str(location.get("fqdn") or "").strip().lower()
                location_type = str(location.get("type") or "DLS").strip().upper()
                title = str(location.get("title") or "").strip()
                # A current Tor v3 hostname is 56 base32 characters.  Do not
                # silently repair URLs, paths, legacy v2 names, or malformed
                # catalog values: active capture must fail closed.
                if re.fullmatch(r"[a-z2-7]{56}\.onion", fqdn) is None:
                    report["invalid_hosts"] += 1
                    continue
                if location_type != "DLS":
                    report["non_dls"] += 1
                    continue
                if not is_public_evidence_location(title, location_type):
                    report["non_public_evidence"] += 1
                    continue
                candidate = DlsLocationInput(
                    group_name=group_name,
                    description=description,
                    fqdn=fqdn,
                    location_type=location_type,
                    title=title,
                    enabled=bool(location.get("enabled", True)),
                    available=bool(location.get("available", False)),
                    source="ransomware_live",
                )
                existing = locations_by_fqdn.get(fqdn)
                if existing is not None:
                    report["duplicate_hosts"] += 1
                # Prefer an enabled/available duplicate while keeping a single
                # canonical target for a hostname.
                if existing is None or (
                    (candidate.enabled, candidate.available)
                    > (existing.enabled, existing.available)
                ):
                    locations_by_fqdn[fqdn] = candidate
        report["accepted"] = len(locations_by_fqdn)
        return list(locations_by_fqdn.values()), report


def _onion_fqdn(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    if "://" in text:
        return str(urlsplit(text).hostname or "").rstrip(".")
    return text.split("/", 1)[0].split(":", 1)[0].rstrip(".")


class RansomLookCatalogCollector:
    """Supplement current actor mirrors from RansomLook's public metadata API.

    The collector first obtains the public group-name index, then requests only
    actors observed locally in the bounded recent-activity window supplied by
    the caller. It never opens a returned onion address.
    """

    name = "ransomlook_catalog"

    def __init__(self, groups_url: str, timeout: float):
        self.groups_url = groups_url.rstrip("/")
        self.timeout = timeout

    async def fetch_for_actors(
        self, actor_names: list[str], *, concurrency: int = 4, limit: int = 250
    ) -> tuple[list[DlsLocationInput], dict]:
        requested_values = [name for name in actor_names if str(name).strip()]
        actor_keys = {
            canonical_actor_name(name).casefold()
            for name in requested_values[:limit]
        }
        semaphore = asyncio.Semaphore(max(1, min(concurrency, 6)))
        report = {
            "groups": 0,
            "actors_requested": len(actor_keys),
            "actors_omitted_by_limit": max(0, len(requested_values) - limit),
            "actors_matched": 0,
            "group_requests_failed": 0,
            "locations_seen": 0,
            "invalid_hosts": 0,
            "non_public_evidence": 0,
            "non_dls_role": 0,
            "duplicate_hosts": 0,
            "accepted": 0,
        }
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers={"User-Agent": "ExtortSignal/0.2 defensive-research"},
            transport=httpx.AsyncHTTPTransport(retries=2),
            limits=httpx.Limits(max_connections=6, max_keepalive_connections=6),
        ) as client:
            response = await client.get(self.groups_url)
            response.raise_for_status()
            payload = response.json()
            public_names = payload if isinstance(payload, list) else []
            report["groups"] = len(public_names)
            indexed_names: dict[str, str] = {}
            for value in public_names:
                if isinstance(value, str) and value.strip():
                    indexed_names.setdefault(
                        canonical_actor_name(value).casefold(), value.strip()
                    )
            matched_names = sorted(
                {indexed_names[key] for key in actor_keys if key in indexed_names},
                key=str.casefold,
            )
            report["actors_matched"] = len(matched_names)
            group_base_url = self.groups_url.rsplit("/groups", 1)[0]

            async def fetch_group(name: str) -> tuple[str, dict | None]:
                async with semaphore:
                    try:
                        detail = await client.get(
                            f"{group_base_url}/group/{quote(name, safe='')}"
                        )
                        detail.raise_for_status()
                        value = detail.json()
                        group = (
                            value[0]
                            if isinstance(value, list)
                            and value
                            and isinstance(value[0], dict)
                            else None
                        )
                        return name, group
                    except (httpx.HTTPError, ValueError, TypeError):
                        return name, None

            group_results = await asyncio.gather(
                *(fetch_group(name) for name in matched_names)
            )

        locations_by_fqdn: dict[str, DlsLocationInput] = {}
        for name, group in group_results:
            if group is None:
                report["group_requests_failed"] += 1
                continue
            group_name = canonical_actor_name(name)
            description = " ".join(
                re.sub(r"<[^>]+>", " ", str(group.get("meta") or "")).split()
            )[:4000]
            for location in group.get("locations") or []:
                if not isinstance(location, dict):
                    continue
                report["locations_seen"] += 1
                fqdn = _onion_fqdn(location.get("fqdn") or location.get("slug"))
                if (
                    re.fullmatch(r"[a-z2-7]{56}\.onion", fqdn) is None
                    or location.get("version") not in (None, 3)
                ):
                    report["invalid_hosts"] += 1
                    continue
                if any(bool(location.get(role)) for role in ("fs", "chat", "admin")):
                    report["non_dls_role"] += 1
                    continue
                title = str(location.get("title") or "").strip()[:240]
                if not is_public_evidence_location(title, "DLS"):
                    report["non_public_evidence"] += 1
                    continue
                candidate = DlsLocationInput(
                    group_name=group_name,
                    description=description,
                    fqdn=fqdn,
                    location_type="DLS",
                    title=title,
                    enabled=True,
                    available=bool(location.get("available", False)),
                    source="ransomlook",
                )
                existing = locations_by_fqdn.get(fqdn)
                if existing is not None:
                    report["duplicate_hosts"] += 1
                if existing is None or (
                    candidate.available,
                    bool(candidate.title),
                ) > (existing.available, bool(existing.title)):
                    locations_by_fqdn[fqdn] = candidate
        report["accepted"] = len(locations_by_fqdn)
        return list(locations_by_fqdn.values()), report


def reconcile_dls_catalogs(
    catalogues: list[list[DlsLocationInput]],
) -> tuple[list[DlsLocationInput], dict]:
    """Merge independent clear-web catalogues without opening listed hosts."""
    candidates: dict[str, list[DlsLocationInput]] = {}
    for catalogue in catalogues:
        for location in catalogue:
            candidates.setdefault(location.fqdn, []).append(location)

    source_priority = {"ransomware_live": 10, "ransomlook": 20}
    merged: list[DlsLocationInput] = []
    overlaps = 0
    identity_conflicts = 0
    identity_conflict_labels: set[str] = set()
    availability_conflicts = 0
    for fqdn, entries in candidates.items():
        if len(entries) > 1:
            overlaps += 1
        identities = {
            canonical_actor_name(entry.group_name).casefold() for entry in entries
        }
        identity_conflicts += int(len(identities) > 1)
        if len(identities) > 1:
            identity_conflict_labels.add(
                " <> ".join(
                    sorted(
                        {canonical_actor_name(entry.group_name) for entry in entries},
                        key=str.casefold,
                    )
                )
            )
        availability_conflicts += int(len({entry.available for entry in entries}) > 1)
        preferred = max(
            entries,
            key=lambda entry: (
                source_priority.get(entry.source, 0),
                entry.available,
                bool(entry.title),
            ),
        )
        ordered_sources = [
            source
            for source in ("ransomware_live", "ransomlook")
            if any(entry.source == source for entry in entries)
        ]
        ordered_sources.extend(
            sorted(
                {
                    entry.source
                    for entry in entries
                    if entry.source not in ordered_sources
                }
            )
        )
        description = max(
            (entry.description for entry in entries), key=len, default=""
        )
        merged.append(
            preferred.model_copy(
                update={
                    "fqdn": fqdn,
                    "description": description,
                    "enabled": any(entry.enabled for entry in entries),
                    "available": any(entry.available for entry in entries),
                    "source": "+".join(ordered_sources),
                }
            )
        )
    return merged, {
        "accepted": len(merged),
        "overlapping_hosts": overlaps,
        "identity_conflicts": identity_conflicts,
        "identity_conflict_labels": sorted(identity_conflict_labels, key=str.casefold),
        "availability_conflicts": availability_conflicts,
    }


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


def _parse_ransomfeed_export(text: str) -> list[dict]:
    """Normalize RansomFeed's public caret-delimited full-dataset CSV."""
    reader = csv.DictReader(io.StringIO(text.lstrip("\ufeff")), delimiter="^")
    records: list[dict] = []
    for raw in reader:
        row = {
            str(key or "").strip().lower(): str(value or "").strip()
            for key, value in raw.items()
        }
        if not row.get("id") or not row.get("victim"):
            continue
        records.append(
            {
                "id": row["id"],
                "hash": row.get("hash", ""),
                "victim": row["victim"],
                "gang": row.get("gang", ""),
                "date": row.get("date", ""),
                "guid": row.get("guid", ""),
                "description": row.get("descr", ""),
                "_extortsignal_archive": "ransomfeed-full-export",
            }
        )
    return records


def _download_ransomfeed_export(url: str, timeout: float) -> str:
    """Download the provider-linked CSV with Python's standard HTTPS client.

    The hosting edge currently returns a bot-challenge page to HTTPX while
    serving the same unauthenticated export to standard clients. Revalidate the
    exact public HTTPS destination here so this helper remains safe if it is
    reused independently of the collector.
    """
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or (parsed.hostname or "").casefold()
        not in {"ransomfeed.it", "www.ransomfeed.it"}
        or parsed.path != "/export-data.php"
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("RansomFeed export URL is not the approved public endpoint")
    request = Request(  # noqa: S310 - exact HTTPS host and path are validated above
        url,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
            ),
            "Accept": "text/csv,text/plain;q=0.9,*/*;q=0.1",
        },
    )
    try:
        with urlopen(  # noqa: S310 - exact HTTPS host and path are validated above
            request, timeout=timeout
        ) as response:
            content_type = response.headers.get_content_type()
            if content_type not in {
                "text/csv",
                "text/plain",
                "application/octet-stream",
            }:
                raise ValueError("RansomFeed export did not return a CSV content type")
            return response.read().decode("utf-8-sig")
    except (OSError, URLError, UnicodeError) as error:
        raise ValueError("RansomFeed full-dataset export could not be downloaded") from error


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
    value = (
        str(
            record.get("status")
            or record.get("publication_status")
            or record.get("leak_status")
            or "claimed"
        )
        .strip()
        .lower()
    )
    aliases = {
        "published": "data_leaked",
        "leaked": "data_leaked",
        "data leaked": "data_leaked",
        "data_leaked": "data_leaked",
        "new": "claimed",
        "unknown": "unknown",
    }
    return aliases.get(value, value.replace(" ", "_"))[:40]


def _attack_date(record: dict) -> datetime | None:
    return parse_datetime(
        record.get("attackdate")
        or record.get("attack_date")
        or record.get("estimated_attack_date")
        or record.get("est_attack_date")
    )


def _source_metadata(record: dict) -> dict:
    leak_size = extract_record_leak_size(record)
    screenshot = str(
        record.get("screenshot") or record.get("screenshot_url") or record.get("image") or ""
    ).strip()
    tags = record.get("tags") if isinstance(record.get("tags"), list) else []
    if record.get("new_group") is True or record.get("is_new_group") is True:
        tags = [*tags, "New group"]
    return {
        "leak_size": leak_size.raw if leak_size else "",
        "leak_size_bytes": leak_size.bytes if leak_size else None,
        "leak_size_source": leak_size.source if leak_size else "",
        "source_screenshot_url": screenshot,
        "source_tags": [str(value) for value in tags],
    }


class _RansomwareLiveDetailParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.fields: dict[str, str] = {}
        self._row_depth = 0
        self._section = ""
        self._section_span_depth = 0
        self._label: list[str] = []
        self._value: list[str] = []

    @staticmethod
    def _classes(attributes: list[tuple[str, str | None]]) -> set[str]:
        value = next((value or "" for key, value in attributes if key == "class"), "")
        return set(value.split())

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        classes = self._classes(attrs)
        if tag == "div" and "rl-info-row" in classes and self._row_depth == 0:
            self._row_depth = 1
            self._label = []
            self._value = []
            return
        if self._row_depth and tag == "div":
            self._row_depth += 1
        if self._row_depth and tag == "span":
            if "rl-info-label" in classes:
                self._section = "label"
                self._section_span_depth = 1
            elif "rl-info-value" in classes:
                self._section = "value"
                self._section_span_depth = 1
            elif self._section:
                self._section_span_depth += 1
        if self._row_depth and self._section == "value" and tag == "img":
            alt = next((value or "" for key, value in attrs if key == "alt"), "")
            if alt:
                self._value.append(alt)

    def handle_endtag(self, tag: str) -> None:
        if not self._row_depth:
            return
        if tag == "span" and self._section_span_depth:
            self._section_span_depth -= 1
            if self._section_span_depth == 0:
                self._section = ""
        if tag == "div":
            self._row_depth -= 1
            if self._row_depth == 0:
                label = " ".join(" ".join(self._label).split()).casefold()
                value = " ".join(" ".join(self._value).split())
                if label and value:
                    self.fields[label] = value
                self._section = ""

    def handle_data(self, data: str) -> None:
        if self._row_depth and self._section == "label":
            self._label.append(data)
        elif self._row_depth and self._section == "value":
            self._value.append(data)


def parse_ransomware_live_detail(html: str) -> dict[str, str]:
    parser = _RansomwareLiveDetailParser()
    parser.feed(html)
    parser.close()
    return parser.fields


def _apply_ransomware_live_detail(claim: ClaimInput, fields: dict[str, str]) -> bool:
    changed = False
    size_value = fields.get("data exfiltrated") or fields.get("data leaked")
    size = normalize_leak_size(size_value, source="detail_page:data_exfiltrated")
    if size is not None and (
        not claim.leak_size
        or leak_size_source_priority(size.source)
        > leak_size_source_priority(claim.leak_size_source)
    ):
        claim.leak_size = size.raw
        claim.leak_size_bytes = size.bytes
        claim.leak_size_source = size.source
        changed = True
    if claim.attack_date is None and fields.get("est. attack date"):
        claim.attack_date = parse_datetime(fields["est. attack date"])
        changed = changed or claim.attack_date is not None
    if not claim.country and fields.get("country"):
        claim.country = fields["country"][:80]
        changed = True
    group_value = fields.get("group", "")
    if "new group" in group_value.casefold() and "New group" not in claim.source_tags:
        claim.source_tags.append("New group")
        changed = True
    return changed
