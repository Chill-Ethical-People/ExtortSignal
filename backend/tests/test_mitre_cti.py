from ransom_monitor.mitre_cti import parse_enterprise_attack


def test_mitre_parser_keeps_sourced_identity_techniques_and_aliases():
    group_id = "intrusion-set--one"
    technique_id = "attack-pattern--one"
    bundle = {
        "objects": [
            {
                "id": group_id,
                "type": "intrusion-set",
                "name": "Example Group",
                "aliases": ["Example Group", "Example Alias"],
                "description": "Publicly documented group.",
                "modified": "2026-01-01T00:00:00Z",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "G9999", "url": "https://attack.mitre.org/groups/G9999/"}
                ],
            },
            {
                "id": technique_id,
                "type": "attack-pattern",
                "name": "Example Technique",
                "kill_chain_phases": [{"phase_name": "discovery"}],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T9999", "url": "https://attack.mitre.org/techniques/T9999/"}
                ],
            },
            {
                "id": "relationship--one",
                "type": "relationship",
                "relationship_type": "uses",
                "source_ref": group_id,
                "target_ref": technique_id,
            },
        ]
    }

    profiles, version = parse_enterprise_attack(bundle)

    assert version == "2026-01-01T00:00:00Z"
    assert profiles[0]["attack_id"] == "G9999"
    assert "Example Alias" in profiles[0]["aliases"]
    assert profiles[0]["techniques"][0] == {
        "id": "T9999",
        "name": "Example Technique",
        "tactics": ["discovery"],
        "relationship": "",
        "url": "https://attack.mitre.org/techniques/T9999/",
        "references": [],
    }
