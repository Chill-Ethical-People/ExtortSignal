from __future__ import annotations

import hashlib
from difflib import SequenceMatcher


STATUS_PATTERNS = {
    "listed": ("new victim", "recent victim", "listed", "added on"),
    "countdown": ("countdown", "time left", "days left", "deadline"),
    "published": ("data published", "published", "download available", "full data"),
    "removed": ("removed", "deleted", "no longer available"),
}


def meaningful_lines(text: str) -> list[str]:
    lines: list[str] = []
    for raw_line in text.splitlines():
        line = " ".join(raw_line.split()).strip()
        if 2 < len(line) <= 500:
            lines.append(line)
    return lines


def normalized_capture_text(text: str) -> str:
    return "\n".join(line.casefold() for line in meaningful_lines(text))


def anchor_candidates(
    text: str, limit: int = 12, ignored_values: list[str] | None = None
) -> list[str]:
    """Select short, distinctive first-page OCR lines as continuity anchors."""
    ignored_terms = (
        "new victim",
        "recent victim",
        "read more",
        "view count",
        "leaked size",
        "days left",
        "time left",
        "countdown",
        "search",
    )
    ignored_exact = {
        " ".join(value.casefold().split())
        for value in (ignored_values or [])
        if value.strip()
    } | {"home", "victims", "news", "contact", "about", "language", "menu"}
    anchors: list[str] = []
    for line in meaningful_lines(text):
        normalized = " ".join(line.casefold().split())
        if normalized in ignored_exact:
            continue
        if not 4 <= len(normalized) <= 120:
            continue
        if any(term in normalized for term in ignored_terms):
            continue
        if sum(character.isalpha() for character in normalized) < 3:
            continue
        if len(normalized.split()) > 14:
            continue
        if normalized not in anchors:
            anchors.append(normalized)
        if len(anchors) >= limit:
            break
    return anchors


def continuity_analysis(
    current_text: str,
    previous_anchors: list[str],
    *,
    pagination_detected: bool,
    coverage_status: str,
) -> dict:
    current_lines = normalized_capture_text(current_text).splitlines()
    anchors = [" ".join(anchor.casefold().split()) for anchor in previous_anchors if anchor]
    if not anchors:
        status = "no_baseline"
        matched_anchor = ""
    elif not current_lines:
        status = "ocr_unavailable"
        matched_anchor = ""
    else:
        matched_anchor = next(
            (
                anchor
                for anchor in anchors
                if any(
                    anchor in line
                    or line in anchor
                    or SequenceMatcher(None, anchor, line).ratio() >= 0.86
                    for line in current_lines
                )
            ),
            "",
        )
        status = "matched" if matched_anchor else "missing"
    return {
        "continuity_status": status,
        "continuity_anchor": matched_anchor,
        "more_content_suspected": status == "missing"
        and (coverage_status != "stable" or pagination_detected),
    }


def detected_statuses(text: str) -> list[str]:
    normalized = normalized_capture_text(text)
    return [
        status
        for status, terms in STATUS_PATTERNS.items()
        if any(term in normalized for term in terms)
    ]


def analyze_capture_text(text: str, previous_text: str = "") -> dict:
    normalized = normalized_capture_text(text)
    previous_normalized = normalized_capture_text(previous_text)
    current_lines = set(normalized.splitlines()) if normalized else set()
    previous_lines = set(previous_normalized.splitlines()) if previous_normalized else set()
    current_statuses = detected_statuses(text)
    previous_statuses = detected_statuses(previous_text)
    union = current_lines | previous_lines
    similarity = (
        len(current_lines & previous_lines) / len(union)
        if previous_lines and union
        else 0.0
    )
    return {
        "text_sha256": hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        if normalized
        else "",
        "detected_statuses": current_statuses,
        "status_changed": bool(previous_text) and current_statuses != previous_statuses,
        "added_line_count": len(current_lines - previous_lines) if previous_lines else len(current_lines),
        "removed_line_count": len(previous_lines - current_lines),
        "duplicate": bool(previous_normalized)
        and (normalized == previous_normalized or similarity >= 0.98),
    }
