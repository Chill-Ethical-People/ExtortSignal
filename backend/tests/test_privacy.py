from ransom_monitor.privacy import (
    CLIENT_PLACEHOLDER,
    redact_client_identifiers,
    restore_client_placeholder,
)


def test_client_identifiers_are_redacted_case_insensitively_and_restored_locally():
    client = {
        "canonical_name": "Fleet Ship Management Limited",
        "primary_domain": "fleetship.com",
        "aliases": ["Fleet Ship"],
    }
    original = "FLEET SHIP was matched through fleetship.com for Fleet Ship Management Limited."

    redacted = redact_client_identifiers(original, client)

    assert redacted == (
        f"{CLIENT_PLACEHOLDER} was matched through {CLIENT_PLACEHOLDER} "
        f"for {CLIENT_PLACEHOLDER}."
    )
    assert "fleet" not in redacted.casefold()
    assert restore_client_placeholder(
        "MONITORED_CLIENT and Monitored Client require review.",
        client["canonical_name"],
    ) == "Fleet Ship Management Limited and Fleet Ship Management Limited require review."
