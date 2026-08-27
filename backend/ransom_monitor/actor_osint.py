from __future__ import annotations

import asyncio
import hashlib
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlsplit

import httpx


GDELT_DOC_API = "https://api.gdeltproject.org/api/v2/doc/doc"
USER_AGENT = "ExtortSignal/0.2 defensive-threat-intelligence-research"

# Retrieval is intentionally limited to established public-sector and security-
# research publishers. GDELT discovers candidate URLs, but does not grant an
# arbitrary URL permission to the application.
TRUSTED_PUBLISHERS: dict[str, tuple[str, str]] = {
    "cisa.gov": ("CISA", "authoritative"),
    "fbi.gov": ("FBI", "authoritative"),
    "ic3.gov": ("FBI IC3", "authoritative"),
    "ncsc.gov.uk": ("UK NCSC", "authoritative"),
    "cyber.gov.au": ("Australian Signals Directorate", "authoritative"),
    "cyber.gc.ca": ("Canadian Centre for Cyber Security", "authoritative"),
    "cert.europa.eu": ("CERT-EU", "authoritative"),
    "europol.europa.eu": ("Europol", "authoritative"),
    "cloud.google.com": ("Google Threat Intelligence", "research"),
    "microsoft.com": ("Microsoft Security", "research"),
    "talosintelligence.com": ("Cisco Talos", "research"),
    "unit42.paloaltonetworks.com": ("Palo Alto Networks Unit 42", "research"),
    "securelist.com": ("Kaspersky Securelist", "research"),
    "news.sophos.com": ("Sophos", "research"),
    "sentinelone.com": ("SentinelOne", "research"),
    "trendmicro.com": ("Trend Micro", "research"),
    "crowdstrike.com": ("CrowdStrike", "research"),
    "mandiant.com": ("Mandiant", "research"),
    "recordedfuture.com": ("Recorded Future", "research"),
    "blackberry.com": ("BlackBerry Research & Intelligence", "research"),
    "welivesecurity.com": ("ESET Research", "research"),
    "fortinet.com": ("FortiGuard Labs", "research"),
    "trellix.com": ("Trellix Advanced Research Center", "research"),
    "rapid7.com": ("Rapid7", "research"),
    "checkpoint.com": ("Check Point Research", "research"),
    "broadcom.com": ("Broadcom Threat Hunter Team", "research"),
    "nccgroup.com": ("NCC Group Research", "research"),
    "therecord.media": ("The Record", "reporting"),
    "bleepingcomputer.com": ("BleepingComputer", "reporting"),
}


def _publisher(url: str) -> tuple[str, str] | None:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return None
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        return None
    host = parsed.hostname.casefold().rstrip(".")
    for domain, publisher in TRUSTED_PUBLISHERS.items():
        if host == domain or host.endswith(f".{domain}"):
            return publisher
    return None


def _source_id(actor: str, url: str, title: str) -> str:
    digest = hashlib.sha256(f"{actor.casefold()}\0{url}\0{title}".encode()).hexdigest()[:24]
    return f"osint-{digest}"


def _clean(value: Any, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def _gdelt_date(value: Any) -> str:
    cleaned = "".join(character for character in str(value or "") if character.isdigit())[:14]
    if len(cleaned) != 14:
        return ""
    try:
        return (
            datetime.strptime(cleaned, "%Y%m%d%H%M%S")
            .replace(tzinfo=timezone.utc)
            .isoformat()
        )
    except ValueError:
        return ""


class _ReadableHTML(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.description = ""
        self._in_title = False
        self._ignored_depth = 0
        self._parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.casefold()
        if tag in {"script", "style", "svg", "noscript", "nav", "footer"}:
            self._ignored_depth += 1
        if tag == "title":
            self._in_title = True
        if tag == "meta":
            values = {name.casefold(): value or "" for name, value in attrs}
            label = (values.get("name") or values.get("property")).casefold()
            if label in {"description", "og:description", "twitter:description"}:
                candidate = _clean(values.get("content"), 1200)
                if len(candidate) > len(self.description):
                    self.description = candidate

    def handle_endtag(self, tag: str) -> None:
        tag = tag.casefold()
        if tag == "title":
            self._in_title = False
        if tag in {"script", "style", "svg", "noscript", "nav", "footer"}:
            self._ignored_depth = max(0, self._ignored_depth - 1)

    def handle_data(self, data: str) -> None:
        if self._ignored_depth:
            return
        value = _clean(data, 1000)
        if not value:
            return
        if self._in_title:
            self.title = _clean(f"{self.title} {value}", 400)
        elif len(" ".join(self._parts)) < 9000:
            self._parts.append(value)

    def excerpt(self) -> str:
        body = _clean(" ".join(self._parts), 6500)
        if self.description and self.description.casefold() not in body.casefold():
            body = _clean(f"{self.description} {body}", 6500)
        return body


def _actor_terms(actor: str, aliases: list[str]) -> list[str]:
    terms: list[str] = []
    for value in [actor, *aliases]:
        cleaned = _clean(value, 100).strip("\"'")
        if len(cleaned) >= 3 and cleaned.casefold() not in {item.casefold() for item in terms}:
            terms.append(cleaned)
    return terms[:6]


def _relevant(text: str, terms: list[str]) -> bool:
    haystack = re.sub(r"[^a-z0-9]+", " ", text.casefold())
    compact = haystack.replace(" ", "")
    return any(
        re.sub(r"[^a-z0-9]+", " ", term.casefold()).strip() in haystack
        or re.sub(r"[^a-z0-9]", "", term.casefold()) in compact
        for term in terms
    )


def mitre_evidence(actor: str, profile: dict) -> list[dict]:
    """Convert retained ATT&CK material and its bibliography to evidence records."""
    if not profile:
        return []
    retrieved_at = _clean(profile.get("refreshed_at"), 50) or datetime.now(timezone.utc).isoformat()
    attack_url = _clean(profile.get("attack_url"), 1000)
    title = f"MITRE ATT&CK profile: {_clean(profile.get('canonical_name') or actor, 160)}"
    details = [
        _clean(profile.get("description"), 3500),
        "Documented techniques: "
        + ", ".join(
            f"{item.get('id', '')} {item.get('name', '')}".strip()
            for item in profile.get("techniques", [])[:40]
        ),
        "Associated software: "
        + ", ".join(_clean(item.get("name"), 100) for item in profile.get("software", [])[:30]),
        "Associated campaigns: "
        + ", ".join(_clean(item.get("name"), 100) for item in profile.get("campaigns", [])[:20]),
    ]
    evidence = [
        {
            "id": _source_id(actor, attack_url, title),
            "actor": actor,
            "source_name": "MITRE ATT&CK",
            "source_tier": "authoritative-framework",
            "title": title,
            "source_url": attack_url,
            "published_at": _clean(profile.get("modified"), 50),
            "retrieved_at": retrieved_at,
            "excerpt": _clean(" ".join(details), 6500),
            "evidence_type": "structured_cti",
        }
    ]
    for reference in profile.get("references", [])[:40]:
        url = _clean(reference.get("url"), 1000)
        if not url.startswith("https://"):
            continue
        publisher = _publisher(url)
        source_name = _clean(reference.get("source"), 160) or (
            publisher[0] if publisher else (urlsplit(url).hostname or "OSINT publication")
        )
        reference_title = _clean(reference.get("title"), 500) or f"Reference cited by {title}"
        evidence.append(
            {
                "id": _source_id(actor, url, reference_title),
                "actor": actor,
                "source_name": source_name,
                "source_tier": publisher[1] if publisher else "cited-osint",
                "title": reference_title,
                "source_url": url,
                "published_at": "",
                "retrieved_at": retrieved_at,
                "excerpt": reference_title,
                "evidence_type": "mitre_citation",
            }
        )
    for relationship_type, items in (
        ("technique", profile.get("techniques", [])),
        ("software", profile.get("software", [])),
        ("campaign", profile.get("campaigns", [])),
    ):
        for item in items[:40]:
            for reference in item.get("references", [])[:10]:
                url = _clean(reference.get("url"), 1000)
                if not url.startswith("https://"):
                    continue
                publisher = _publisher(url)
                source_name = _clean(reference.get("source"), 160) or (
                    publisher[0] if publisher else (urlsplit(url).hostname or "OSINT publication")
                )
                relationship_title = _clean(reference.get("title"), 500) or (
                    f"{_clean(item.get('name'), 160)} {relationship_type} relationship cited by ATT&CK"
                )
                excerpt = _clean(
                    " ".join(
                        [
                            relationship_title,
                            item.get("relationship", ""),
                            item.get("description", ""),
                        ]
                    ),
                    3500,
                )
                evidence.append(
                    {
                        "id": _source_id(actor, url, relationship_title),
                        "actor": actor,
                        "source_name": source_name,
                        "source_tier": publisher[1] if publisher else "cited-osint",
                        "title": relationship_title,
                        "source_url": url,
                        "published_at": "",
                        "retrieved_at": retrieved_at,
                        "excerpt": excerpt,
                        "evidence_type": f"mitre_{relationship_type}_citation",
                    }
                )
    return evidence


async def research_actor_osint(
    actor: str,
    aliases: list[str],
    mitre_profile: dict | None = None,
    *,
    timeout: float = 15.0,
    candidate_limit: int = 20,
) -> dict:
    """Discover and retain bounded, attributable public research for one actor.

    Search results are candidates until the actor label occurs in the fetched
    article. Only a fixed publisher set can be fetched, and only HTTPS is used.
    """
    actor = _clean(actor, 160)
    candidate_limit = max(1, min(candidate_limit, 20))
    terms = _actor_terms(actor, aliases)
    retrieved_at = datetime.now(timezone.utc).isoformat()
    evidence = mitre_evidence(actor, mitre_profile or {})
    quoted = " OR ".join(f'"{term.replace(chr(34), "")}"' for term in terms[:4])
    queries = [
        {
            "focus": "identity_capabilities_campaigns_and_recent_trend",
            "query": (
                f"({quoted}) (ransomware OR extortion OR malware OR cyberattack) "
                "(campaign OR victims OR activity OR trend OR technique OR affiliate "
                "OR vulnerability OR initial access)"
            ),
            "timespan": "5years",
        }
    ]
    warnings: list[str] = []
    candidates: list[dict] = []
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json, text/html"},
        ) as client:
            async def discover(spec: dict[str, str]) -> tuple[dict[str, str], list[dict]]:
                response = await client.get(
                    GDELT_DOC_API,
                    params={
                        "query": spec["query"],
                        "mode": "artlist",
                        "format": "json",
                        "maxrecords": "50",
                        "timespan": spec["timespan"],
                        "sort": "datedesc",
                    },
                )
                response.raise_for_status()
                payload: Any = response.json()
                articles = payload.get("articles", []) if isinstance(payload, dict) else []
                return spec, [item for item in articles if isinstance(item, dict)]

            discovery_results = await asyncio.gather(
                *(discover(spec) for spec in queries), return_exceptions=True
            )
            discovered: list[tuple[dict[str, str], list[dict]]] = []
            for spec, result in zip(queries, discovery_results):
                if isinstance(result, BaseException):
                    warnings.append(
                        f"{spec['focus']} discovery was unavailable: {type(result).__name__}"
                    )
                    continue
                discovered.append(result)
            per_host: dict[str, int] = {}
            seen_urls: set[str] = set()
            for spec, articles in discovered:
                for article in articles:
                    url = _clean(article.get("url"), 1000)
                    title = _clean(article.get("title"), 500)
                    publisher = _publisher(url)
                    if (
                        not publisher
                        or not title
                        or url in seen_urls
                        or not _relevant(title, terms)
                    ):
                        continue
                    host = (urlsplit(url).hostname or "").casefold()
                    if per_host.get(host, 0) >= 3:
                        continue
                    per_host[host] = per_host.get(host, 0) + 1
                    seen_urls.add(url)
                    candidates.append(
                        {
                            "url": url,
                            "title": title,
                            "published_at": _gdelt_date(article.get("seendate")),
                            "source_name": publisher[0],
                            "source_tier": publisher[1],
                            "research_focus": spec["focus"],
                        }
                    )
                    if len(candidates) >= candidate_limit:
                        break
                if len(candidates) >= candidate_limit:
                    break

            semaphore = asyncio.Semaphore(4)

            async def fetch_candidate(candidate: dict) -> dict | None:
                try:
                    async with semaphore:
                        article_response = await client.get(candidate["url"])
                    if article_response.status_code != 200:
                        return None
                    content_type = article_response.headers.get("content-type", "").casefold()
                    if "text/html" not in content_type or len(article_response.content) > 2_500_000:
                        return None
                    parser = _ReadableHTML()
                    parser.feed(article_response.text[:2_500_000])
                    excerpt = parser.excerpt()
                    if len(excerpt) < 120 or not _relevant(
                        f"{candidate['title']} {excerpt}", terms
                    ):
                        return None
                    return {
                        "id": _source_id(actor, candidate["url"], candidate["title"]),
                        "actor": actor,
                        "source_name": candidate["source_name"],
                        "source_tier": candidate["source_tier"],
                        "title": parser.title or candidate["title"],
                        "source_url": candidate["url"],
                        "published_at": candidate["published_at"],
                        "retrieved_at": retrieved_at,
                        "excerpt": excerpt,
                        "evidence_type": "published_research",
                        "research_focus": candidate["research_focus"],
                    }
                except (httpx.HTTPError, UnicodeError, ValueError):
                    return None

            fetched = await asyncio.gather(*(fetch_candidate(item) for item in candidates))
            evidence.extend(item for item in fetched if item is not None)
    except (httpx.HTTPError, TypeError, ValueError) as error:
        warnings.append(f"Public research discovery was unavailable: {type(error).__name__}")

    unique = {item["id"]: item for item in evidence if item.get("source_url")}
    result = list(unique.values())
    source_names = sorted({item["source_name"] for item in result}, key=str.casefold)
    return {
        "actor": actor,
        "query": queries[0]["query"],
        "queries": queries,
        "retrieved_at": retrieved_at,
        "status": "evidence_found" if result else "no_evidence",
        "evidence": result,
        "evidence_count": len(result),
        "independent_source_count": len(source_names),
        "source_names": source_names,
        "warnings": warnings,
    }
