from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Iterator


_SIZE_TOKEN = re.compile(
    r"(?<![\w.])(?P<number>\d{1,3}(?:[ ,]\d{3})*(?:\.\d+)?|\d+(?:\.\d+)?)\s*"
    r"(?P<unit>bytes?|[kmgtpe](?:i)?b)(?!\w)",
    re.IGNORECASE,
)
_LABELLED_SIZE = re.compile(
    r"(?:data\s+(?:exfiltrated|extracted|leaked)|(?:exfiltrated|extracted|leaked|stolen)\s+data"
    r"|(?:leak|data|exfiltration)\s+size|data\s+volume)\s*[:=\-]?\s*"
    r"(?:approximately|approx\.?|about|around|over|more\s+than|up\s+to)?\s*"
    r"(?P<size>\d{1,3}(?:[ ,]\d{3})*(?:\.\d+)?\s*(?:bytes?|[kmgtpe](?:i)?b))",
    re.IGNORECASE,
)

_EXPLICIT_SIZE_KEYS = {
    "data_exfiltrated",
    "data_extracted",
    "data_leaked",
    "data_size",
    "data_volume",
    "exfiltrated_data",
    "exfiltrated_data_size",
    "exfiltrated_size",
    "extraction_size",
    "leak_size",
    "leaked_data",
    "leaked_data_size",
    "stolen_data_size",
}
_BYTE_SIZE_KEYS = {
    "data_size_bytes",
    "exfiltrated_bytes",
    "leak_size_bytes",
    "leaked_bytes",
    "stolen_data_bytes",
}

_DECIMAL_MULTIPLIERS = {
    "b": 1,
    "byte": 1,
    "bytes": 1,
    "kb": 1_000,
    "mb": 1_000_000,
    "gb": 1_000_000_000,
    "tb": 1_000_000_000_000,
    "pb": 1_000_000_000_000_000,
    "eb": 1_000_000_000_000_000_000,
}
_BINARY_MULTIPLIERS = {
    "kib": 1 << 10,
    "mib": 1 << 20,
    "gib": 1 << 30,
    "tib": 1 << 40,
    "pib": 1 << 50,
    "eib": 1 << 60,
}


@dataclass(frozen=True)
class LeakSize:
    raw: str
    bytes: int | None
    source: str


def normalize_leak_size(value: Any, *, source: str = "") -> LeakSize | None:
    """Preserve a source value and derive bytes only when a unit is explicit."""
    if value is None or isinstance(value, bool):
        return None
    raw = " ".join(str(value).split()).strip(" |;,")[:120]
    if not raw or raw.casefold() in {"n/a", "na", "none", "null", "unknown", "-"}:
        return None
    match = _SIZE_TOKEN.search(raw)
    if match is None:
        return LeakSize(raw=raw, bytes=None, source=source[:80])
    number = match.group("number").replace(" ", "").replace(",", "")
    unit = match.group("unit").casefold()
    multiplier = _BINARY_MULTIPLIERS.get(unit) or _DECIMAL_MULTIPLIERS.get(unit)
    if multiplier is None:
        return LeakSize(raw=raw, bytes=None, source=source[:80])
    try:
        byte_count = int(Decimal(number) * multiplier)
    except (InvalidOperation, ValueError, OverflowError):
        byte_count = None
    return LeakSize(raw=raw, bytes=byte_count, source=source[:80])


def extract_labelled_leak_size(text: str, *, source: str) -> LeakSize | None:
    match = _LABELLED_SIZE.search(text or "")
    if match is None:
        return None
    return normalize_leak_size(match.group("size"), source=source)


def _mapping_fields(
    value: dict[str, Any], *, prefix: str = "", depth: int = 0
) -> Iterator[tuple[str, Any, dict[str, Any]]]:
    if depth > 2:
        return
    for key, item in value.items():
        normalized = re.sub(r"[^a-z0-9]+", "_", str(key).casefold()).strip("_")
        field = f"{prefix}.{normalized}" if prefix else normalized
        yield field, item, value
        if isinstance(item, dict):
            yield from _mapping_fields(item, prefix=field, depth=depth + 1)


def extract_record_leak_size(record: dict[str, Any]) -> LeakSize | None:
    """Extract explicit source metadata before considering labelled narrative text."""
    candidates: list[tuple[int, str, Any, dict[str, Any]]] = []
    for path, value, container in _mapping_fields(record):
        key = path.rsplit(".", 1)[-1]
        if key in _BYTE_SIZE_KEYS:
            candidates.append((40, path, value, container))
        elif key in _EXPLICIT_SIZE_KEYS:
            candidates.append((30, path, value, container))
        elif key == "size" and isinstance(value, str) and _SIZE_TOKEN.search(value):
            candidates.append((10, path, value, container))

    for _, path, value, container in sorted(candidates, reverse=True):
        key = path.rsplit(".", 1)[-1]
        if value is None or value == "":
            continue
        if key in _BYTE_SIZE_KEYS and isinstance(value, (int, float, Decimal)):
            return LeakSize(str(value), max(0, int(value)), f"structured:{path}"[:80])
        if isinstance(value, (int, float, Decimal)):
            unit = next(
                (
                    container.get(candidate)
                    for candidate in ("data_unit", "size_unit", "unit")
                    if container.get(candidate)
                ),
                None,
            )
            if unit:
                value = f"{value} {unit}"
        parsed = normalize_leak_size(value, source=f"structured:{path}")
        if parsed is not None:
            return parsed

    for field in ("description", "post_description", "details", "content", "excerpt"):
        value = record.get(field)
        if value:
            parsed = extract_labelled_leak_size(str(value), source=f"narrative:{field}")
            if parsed is not None:
                return parsed
    return None


def leak_size_source_priority(source: str) -> int:
    source = (source or "").casefold()
    if source.startswith("structured:"):
        return 40
    if source.startswith("detail_page:"):
        return 35
    if source.startswith("narrative:"):
        return 20
    if source.startswith("dls_dom:"):
        return 18
    if source.startswith("dls_ocr:"):
        return 10
    return 25 if source else 0
