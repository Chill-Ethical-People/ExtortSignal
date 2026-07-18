from __future__ import annotations

import re


CLIENT_PLACEHOLDER = "MONITORED_CLIENT"


def redact_client_identifiers(value: str, client: dict) -> str:
    """Replace monitored-client names and domains before an external AI call."""
    identifiers = [
        client.get("canonical_name", ""),
        client.get("primary_domain", ""),
        *(client.get("aliases") or []),
    ]
    result = str(value or "")
    for identifier in sorted(
        {str(item).strip() for item in identifiers if len(str(item).strip()) >= 3},
        key=len,
        reverse=True,
    ):
        result = re.sub(re.escape(identifier), CLIENT_PLACEHOLDER, result, flags=re.IGNORECASE)
    return result


def restore_client_placeholder(value: str, client_name: str) -> str:
    """Restore the real client name only after the AI response is local again."""
    return re.sub(
        r"\bMONITORED[_ ]CLIENT\b",
        client_name,
        str(value or ""),
        flags=re.IGNORECASE,
    )
