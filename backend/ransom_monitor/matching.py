from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from urllib.parse import urlparse


LEGAL_SUFFIXES = {
    "limited",
    "ltd",
    "inc",
    "incorporated",
    "llc",
    "plc",
    "corp",
    "corporation",
    "company",
    "co",
    "gmbh",
    "group",
    "holdings",
    "sa",
}

DOMAIN_PATTERN = re.compile(
    r"(?<!@)\b(?:https?://)?(?:www\.)?([a-z0-9][a-z0-9.-]+\.[a-z]{2,})\b",
    re.IGNORECASE,
)


def normalize_name(value: str) -> str:
    tokens = re.findall(r"[a-z0-9]+", value.casefold())
    while tokens and tokens[-1] in LEGAL_SUFFIXES:
        tokens.pop()
    return " ".join(tokens)


def normalize_text(value: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", value.casefold()))


def normalize_domain(value: str) -> str:
    candidate = value.strip().lower()
    if "://" not in candidate:
        candidate = "//" + candidate
    parsed = urlparse(candidate)
    return (parsed.hostname or "").removeprefix("www.").rstrip(".")


def extract_domains(text: str) -> list[str]:
    domains = {normalize_domain(match) for match in DOMAIN_PATTERN.findall(text)}
    return sorted(domain for domain in domains if domain)


@dataclass(frozen=True)
class MatchResult:
    score: int
    severity: str
    reason: str
    evidence: str


def match_claim(claim: dict, client: dict) -> MatchResult | None:
    title = str(claim.get("title", ""))
    description = str(claim.get("description", ""))
    haystack = f"{title}\n{description}"
    claim_domains = {
        normalize_domain(value) for value in claim.get("domains", []) if value
    } | set(extract_domains(haystack))
    client_domain = normalize_domain(str(client.get("primary_domain", "")))

    if client_domain and client_domain in claim_domains:
        return MatchResult(
            score=100,
            severity="critical",
            reason=f"Exact verified domain match: {client_domain}",
            evidence=_evidence(haystack, client_domain),
        )

    for entity in client.get("related_entities", []):
        relationship = str(entity.get("relationship", "third_party"))
        related_domain = normalize_domain(str(entity.get("domain", "")))
        if related_domain and related_domain in claim_domains:
            label = relationship.replace("_", " ")
            return MatchResult(
                score=88,
                severity="high",
                reason=f"Exact {label} domain match: {related_domain}",
                evidence=_evidence(haystack, related_domain),
            )

    title_normalized = normalize_name(title)
    canonical = normalize_name(str(client.get("canonical_name", "")))
    aliases = [normalize_name(value) for value in client.get("aliases", [])]
    names = [value for value in [canonical, *aliases] if len(value) >= 4]

    for index, name in enumerate(names):
        if title_normalized == name or re.search(rf"\b{re.escape(name)}\b", normalize_name(haystack)):
            label = "canonical company name" if index == 0 else "known alias"
            score = 90 if index == 0 else 80
            return MatchResult(
                score=score,
                severity="critical" if score >= 90 else "high",
                reason=f"Exact {label} match: {name}",
                evidence=_evidence(haystack, name),
            )

    for entity in client.get("related_entities", []):
        related_name = normalize_name(str(entity.get("name", "")))
        if len(related_name) < 4:
            continue
        if title_normalized == related_name or re.search(
            rf"\b{re.escape(related_name)}\b", normalize_name(haystack)
        ):
            relationship = str(entity.get("relationship", "third_party")).replace("_", " ")
            score = 84 if relationship == "subsidiary" else 78
            return MatchResult(
                score=score,
                severity="high",
                reason=f"Exact monitored {relationship} name match: {related_name}",
                evidence=_evidence(haystack, related_name),
            )

    if canonical and title_normalized:
        similarity = SequenceMatcher(None, canonical, title_normalized).ratio()
        if similarity >= 0.88:
            return MatchResult(
                score=70,
                severity="high",
                reason=f"Strong company-name similarity ({similarity:.0%})",
                evidence=title[:280],
            )
        if similarity >= 0.72:
            return MatchResult(
                score=50,
                severity="review",
                reason=f"Possible company-name similarity ({similarity:.0%})",
                evidence=title[:280],
            )

    normalized_haystack = normalize_text(haystack)
    matched_keywords = []
    for keyword in client.get("keywords", []):
        normalized_keyword = normalize_text(str(keyword))
        if len(normalized_keyword) < 3:
            continue
        if re.search(rf"\b{re.escape(normalized_keyword)}\b", normalized_haystack):
            matched_keywords.append(str(keyword))
    if matched_keywords:
        shown = ", ".join(matched_keywords[:4])
        score = min(65, 42 + (len(matched_keywords) - 1) * 8)
        return MatchResult(
            score=score,
            severity="review",
            reason=f"Client keyword match: {shown}",
            evidence=_evidence(haystack, matched_keywords[0]),
        )
    return None


def _evidence(text: str, needle: str) -> str:
    folded = text.casefold()
    position = folded.find(needle.casefold())
    if position < 0:
        return text[:280]
    start = max(0, position - 80)
    end = min(len(text), position + len(needle) + 120)
    return text[start:end].replace("\n", " ").strip()
