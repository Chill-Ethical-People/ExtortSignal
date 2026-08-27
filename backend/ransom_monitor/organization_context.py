from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import time
from typing import Any
from urllib.parse import quote

import httpx


WIKIPEDIA_API = "https://en.wikipedia.org/w/api.php"
GDELT_DOC_API = "https://api.gdeltproject.org/api/v2/doc/doc"
_cache: dict[str, tuple[float, dict]] = {}
_cache_lock = asyncio.Lock()


async def lookup_organization_background(
    name: str, domains: list[str], timeout: float = 12.0
) -> dict:
    """Return bounded public organization candidates from a fixed HTTPS API.

    Search results are evidence candidates, not an identity assertion. The AI
    must decide whether a candidate matches the victim name/domain and may
    return no enrichment when the match is ambiguous.
    """
    clean_name = " ".join(name.split())[:180]
    # Keep search broad enough to return identity candidates. Domains remain
    # in the AI payload as a strong matching signal, but requiring a domain in
    # the article text would incorrectly suppress many valid organizations.
    query = f'"{clean_name}"'
    cache_key = query.casefold()
    async with _cache_lock:
        cached = _cache.get(cache_key)
        if cached and cached[0] > time.monotonic():
            return cached[1]

    params = {
        "action": "query",
        "generator": "search",
        "gsrsearch": query,
        "gsrnamespace": "0",
        "gsrlimit": "3",
        "prop": "extracts",
        "exintro": "1",
        "explaintext": "1",
        "exchars": "900",
        "format": "json",
        "formatversion": "2",
    }
    result = {"provider": "Wikipedia", "query": query, "candidates": [], "status": "no_match"}
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "ExtortSignal/0.2 defensive-organization-enrichment"},
        ) as client:
            response = await client.get(WIKIPEDIA_API, params=params)
            response.raise_for_status()
            payload: Any = response.json()
        pages = payload.get("query", {}).get("pages", []) if isinstance(payload, dict) else []
        for page in pages:
            if not isinstance(page, dict):
                continue
            title = " ".join(str(page.get("title") or "").split())[:200]
            extract = " ".join(str(page.get("extract") or "").split())[:900]
            if not title or not extract:
                continue
            result["candidates"].append(
                {
                    "title": title,
                    "extract": extract,
                    "url": f"https://en.wikipedia.org/wiki/{quote(title.replace(' ', '_'))}",
                }
            )
        result["status"] = "candidates_found" if result["candidates"] else "no_match"
    except (httpx.HTTPError, TypeError, ValueError):
        result["status"] = "lookup_unavailable"

    async with _cache_lock:
        _cache[cache_key] = (time.monotonic() + 86400, result)
    return result


def _gdelt_date(value: Any) -> str:
    cleaned = "".join(character for character in str(value or "") if character.isdigit())[:14]
    if len(cleaned) != 14:
        return ""
    try:
        parsed = datetime.strptime(cleaned, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return ""
    return parsed.isoformat()


async def lookup_public_incident_candidates(name: str, timeout: float = 12.0) -> dict:
    """Return bounded news candidates about possible prior cyber incidents.

    Results are search candidates, not proof that an incident occurred or that
    the article refers to the same organization. Identity and incident relevance
    must be assessed against the supplied title, URL and publication date.
    """
    clean_name = " ".join(name.split())[:180].replace('"', "")
    query = f'"{clean_name}" (ransomware OR "cyber attack" OR "data breach" OR hacked)'
    cache_key = f"incident:{query.casefold()}"
    async with _cache_lock:
        cached = _cache.get(cache_key)
        if cached and cached[0] > time.monotonic():
            return cached[1]

    params = {
        "query": query,
        "mode": "artlist",
        "format": "json",
        "maxrecords": "15",
        "timespan": "5years",
        "sort": "datedesc",
    }
    result = {
        "provider": "GDELT DOC 2.0",
        "query": query,
        "coverage": "past_five_years",
        "candidates": [],
        "status": "no_match",
    }
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "ExtortSignal/0.2 defensive-organization-enrichment"},
        ) as client:
            response = await client.get(GDELT_DOC_API, params=params)
            response.raise_for_status()
            payload: Any = response.json()
        articles = payload.get("articles", []) if isinstance(payload, dict) else []
        seen_urls: set[str] = set()
        for article in articles:
            if not isinstance(article, dict):
                continue
            url = str(article.get("url") or "").strip()[:1000]
            title = " ".join(str(article.get("title") or "").split())[:300]
            published_at = _gdelt_date(article.get("seendate"))
            if not url.startswith("https://") or not title or not published_at or url in seen_urls:
                continue
            seen_urls.add(url)
            result["candidates"].append(
                {
                    "title": title,
                    "url": url,
                    "published_at": published_at,
                    "publisher": str(article.get("domain") or "")[:200],
                    "source_country": str(article.get("sourcecountry") or "")[:120],
                }
            )
        result["status"] = "candidates_found" if result["candidates"] else "no_match"
    except (httpx.HTTPError, TypeError, ValueError):
        result["status"] = "lookup_unavailable"

    async with _cache_lock:
        _cache[cache_key] = (time.monotonic() + 21600, result)
    return result


async def lookup_organization_reporting_candidates(
    name: str, domains: list[str], timeout: float = 12.0
) -> dict:
    """Find bounded clear-web reporting that may supplement sparse company context.

    These are title-level discovery candidates, not verified organization facts.
    The AI must resolve identity against the supplied name/domain and cite only
    returned URLs. No candidate page, form, download, DLS or arbitrary URL is
    opened by this lookup.
    """
    clean_name = " ".join(name.split())[:180].replace('"', "")
    domain_terms = [
        value.casefold().strip().removeprefix("www.")[:253]
        for value in domains[:3]
        if value and "." in value
    ]
    domain_query = " OR ".join(f'"{value}"' for value in domain_terms)
    identity = f'("{clean_name}"' + (f" OR {domain_query}" if domain_query else "") + ")"
    query = f"{identity} (company OR organization OR business OR services OR industry)"
    cache_key = f"organization-reporting:{query.casefold()}"
    async with _cache_lock:
        cached = _cache.get(cache_key)
        if cached and cached[0] > time.monotonic():
            return cached[1]

    result = {
        "provider": "GDELT DOC 2.0",
        "query": query,
        "coverage": "past_five_years_title_index",
        "candidates": [],
        "status": "no_match",
    }
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            headers={"User-Agent": "ExtortSignal/0.2 defensive-organization-enrichment"},
        ) as client:
            response = await client.get(
                GDELT_DOC_API,
                params={
                    "query": query,
                    "mode": "artlist",
                    "format": "json",
                    "maxrecords": "25",
                    "timespan": "5years",
                    "sort": "datedesc",
                },
            )
            response.raise_for_status()
            payload: Any = response.json()
        articles = payload.get("articles", []) if isinstance(payload, dict) else []
        seen_urls: set[str] = set()
        for article in articles:
            if not isinstance(article, dict):
                continue
            url = str(article.get("url") or "").strip()[:1000]
            title = " ".join(str(article.get("title") or "").split())[:300]
            published_at = _gdelt_date(article.get("seendate"))
            if not url.startswith("https://") or not title or url in seen_urls:
                continue
            normalized_title = "".join(character for character in title.casefold() if character.isalnum())
            normalized_name = "".join(
                character for character in clean_name.casefold() if character.isalnum()
            )
            if normalized_name and normalized_name not in normalized_title and not any(
                domain.split(".", 1)[0].replace("-", "") in normalized_title
                for domain in domain_terms
            ):
                continue
            seen_urls.add(url)
            result["candidates"].append(
                {
                    "title": title,
                    "url": url,
                    "published_at": published_at,
                    "publisher": str(article.get("domain") or "")[:200],
                    "source_country": str(article.get("sourcecountry") or "")[:120],
                }
            )
            if len(result["candidates"]) >= 12:
                break
        result["status"] = "candidates_found" if result["candidates"] else "no_match"
    except (httpx.HTTPError, TypeError, ValueError):
        result["status"] = "lookup_unavailable"

    async with _cache_lock:
        _cache[cache_key] = (time.monotonic() + 21600, result)
    return result
