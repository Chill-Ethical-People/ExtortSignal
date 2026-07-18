from __future__ import annotations

import asyncio
import time
from typing import Any
from urllib.parse import quote

import httpx


WIKIPEDIA_API = "https://en.wikipedia.org/w/api.php"
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
