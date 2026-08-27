import pytest

from ransom_monitor.network_policy import (
    OutboundDestinationError,
    validate_ai_endpoint,
    validate_smtp_destination,
)


def test_known_cloud_provider_is_pinned_to_catalog_host():
    assert (
        validate_ai_endpoint(
            "openai",
            "https://api.openai.com/v1",
            "https://api.openai.com/v1",
        )
        == "https://api.openai.com/v1"
    )
    with pytest.raises(OutboundDestinationError, match="catalog endpoint host"):
        validate_ai_endpoint(
            "openai",
            "https://127.0.0.1:8443/v1",
            "https://api.openai.com/v1",
        )
    with pytest.raises(OutboundDestinationError, match="must use HTTPS"):
        validate_ai_endpoint(
            "openai",
            "http://api.openai.com/v1",
            "https://api.openai.com/v1",
        )


def test_local_and_custom_ai_endpoints_fail_closed():
    assert (
        validate_ai_endpoint(
            "ollama",
            "http://127.0.0.1:11434/v1",
            "http://127.0.0.1:11434/v1",
        )
        == "http://127.0.0.1:11434/v1"
    )
    with pytest.raises(OutboundDestinationError, match="loopback"):
        validate_ai_endpoint(
            "ollama",
            "http://192.168.1.10:11434/v1",
            "http://127.0.0.1:11434/v1",
        )
    with pytest.raises(OutboundDestinationError, match="not explicitly trusted"):
        validate_ai_endpoint(
            "custom",
            "https://169.254.169.254/v1",
            "",
        )
    assert (
        validate_ai_endpoint(
            "custom",
            "https://ai.internal.example/v1",
            "",
            trusted_custom_hosts=("ai.internal.example",),
        )
        == "https://ai.internal.example/v1"
    )
    with pytest.raises(OutboundDestinationError, match="must use HTTPS"):
        validate_ai_endpoint(
            "custom",
            "http://ai.internal.example:9000/v1",
            "",
            trusted_custom_hosts=("ai.internal.example",),
        )


def test_smtp_destination_rejects_urls_and_untrusted_private_addresses():
    assert validate_smtp_destination("smtp.example.com") == "smtp.example.com"
    assert validate_smtp_destination("127.0.0.1") == "127.0.0.1"
    with pytest.raises(OutboundDestinationError, match="hostname, not a URL"):
        validate_smtp_destination("smtp://smtp.example.com")
    with pytest.raises(OutboundDestinationError, match="untrusted private"):
        validate_smtp_destination("10.10.10.10")
    assert (
        validate_smtp_destination(
            "mail.internal.example",
            trusted_private_hosts=("mail.internal.example",),
        )
        == "mail.internal.example"
    )
