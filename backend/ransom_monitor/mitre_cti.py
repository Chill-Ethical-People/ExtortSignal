from __future__ import annotations

from typing import Any


def parse_enterprise_attack(bundle: dict[str, Any]) -> tuple[list[dict], str]:
    """Create sourced group profiles from the official ATT&CK STIX bundle."""
    objects = {item.get("id"): item for item in bundle.get("objects", []) if item.get("id")}
    groups = [item for item in objects.values() if item.get("type") == "intrusion-set" and not item.get("revoked") and not item.get("x_mitre_deprecated")]
    relationships = [item for item in objects.values() if item.get("type") == "relationship" and not item.get("revoked")]

    def ref(item: dict) -> dict:
        references = item.get("external_references", [])
        attack = next((entry for entry in references if str(entry.get("external_id", "")).startswith(("G", "T", "S", "C"))), {})
        return {"id": attack.get("external_id", ""), "url": attack.get("url", ""), "references": [
            {"source": entry.get("source_name", ""), "title": entry.get("description", ""), "url": entry.get("url", "")}
            for entry in references if entry.get("url")
        ]}

    profiles: list[dict] = []
    for group in groups:
        group_ref = ref(group)
        techniques, software, campaigns = [], [], []
        for relationship in relationships:
            related_id = ""
            if relationship.get("source_ref") == group["id"] and relationship.get("relationship_type") == "uses":
                related_id = relationship.get("target_ref", "")
            elif relationship.get("target_ref") == group["id"] and relationship.get("relationship_type") in {"attributed-to", "uses"}:
                related_id = relationship.get("source_ref", "")
            item = objects.get(related_id)
            if not item:
                continue
            item_ref = ref(item)
            relationship_refs = ref(relationship)["references"]
            if item.get("type") == "attack-pattern":
                techniques.append({"id": item_ref["id"], "name": item.get("name", ""), "tactics": [phase.get("phase_name", "") for phase in item.get("kill_chain_phases", [])], "relationship": relationship.get("description", ""), "url": item_ref["url"], "references": relationship_refs})
            elif item.get("type") in {"malware", "tool"}:
                software.append({"id": item_ref["id"], "name": item.get("name", ""), "type": item.get("type", ""), "description": item.get("description", ""), "url": item_ref["url"], "references": relationship_refs})
            elif item.get("type") == "campaign":
                campaigns.append({"id": item_ref["id"], "name": item.get("name", ""), "description": item.get("description", ""), "first_seen": item.get("first_seen"), "last_seen": item.get("last_seen"), "url": item_ref["url"], "references": relationship_refs})
        profiles.append({
            "attack_id": group_ref["id"], "canonical_name": group.get("name", ""),
            "aliases": group.get("aliases", []), "description": group.get("description", ""),
            "created": group.get("created"), "modified": group.get("modified"),
            "attack_url": group_ref["url"], "references": group_ref["references"],
            "techniques": sorted(techniques, key=lambda item: item["id"]),
            "software": sorted(software, key=lambda item: item["name"].casefold()),
            "campaigns": sorted(campaigns, key=lambda item: item["name"].casefold()),
            "source_note": "External CTI is an exact ATT&CK name/alias match. ATT&CK mappings are documented subsets of public reporting, not proof of attribution or complete behavior.",
        })
    version = max((str(group.get("modified", "")) for group in groups), default="")
    return profiles, version
