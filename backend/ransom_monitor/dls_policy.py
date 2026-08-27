from __future__ import annotations

import re


PUBLIC_EVIDENCE_TOKENS = {
    "blog",
    "disclosure",
    "disclosures",
    "leak",
    "leaks",
    "victim",
    "victims",
}
NON_EVIDENCE_PORTAL_TOKENS = {"decryptor", "negotiation", "recovery", "support"}


def is_public_evidence_location(title: str, location_type: str = "DLS") -> bool:
    """Fail closed for negotiation/recovery portals mislabeled as public DLS pages."""
    if location_type.strip().upper() != "DLS":
        return False
    tokens = set(re.findall(r"[a-z0-9]+", str(title or "").casefold()))
    if not tokens:
        return True
    return not (
        bool(tokens & NON_EVIDENCE_PORTAL_TOKENS) and not bool(tokens & PUBLIC_EVIDENCE_TOKENS)
    )
