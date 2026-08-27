from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit


LOCAL_AI_PROVIDERS = {"ollama", "lmstudio", "vllm"}
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
HOSTNAME = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.IGNORECASE,
)


class OutboundDestinationError(ValueError):
    """Raised when a configured network destination violates the local policy."""


def _literal_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _normalized_http_endpoint(value: str):
    parsed = urlsplit(value.strip())
    try:
        port = parsed.port
    except ValueError as error:
        raise OutboundDestinationError("Endpoint port is invalid") from error
    if parsed.scheme not in {"http", "https"}:
        raise OutboundDestinationError("Endpoint must use HTTP or HTTPS")
    if not parsed.hostname:
        raise OutboundDestinationError("Endpoint must include a hostname")
    if parsed.username or parsed.password:
        raise OutboundDestinationError("Endpoint credentials are not allowed in the URL")
    if parsed.query or parsed.fragment:
        raise OutboundDestinationError("Endpoint query strings and fragments are not allowed")
    if port is not None and not 1 <= port <= 65535:
        raise OutboundDestinationError("Endpoint port is invalid")
    return parsed


def validate_ai_endpoint(
    provider_id: str,
    endpoint: str,
    canonical_endpoint: str,
    *,
    trusted_custom_hosts: tuple[str, ...] = (),
) -> str:
    """Validate an OpenAI-compatible base URL without broadening network access.

    Known cloud providers remain pinned to their catalog hostname. Local providers
    remain pinned to loopback. A custom provider may use loopback or an exact
    hostname explicitly trusted by the administrator.
    """
    parsed = _normalized_http_endpoint(endpoint)
    host = (parsed.hostname or "").lower().rstrip(".")
    trusted = {value.lower().rstrip(".") for value in trusted_custom_hosts}

    if provider_id in LOCAL_AI_PROVIDERS:
        if host not in LOOPBACK_HOSTS:
            raise OutboundDestinationError(
                "Local AI providers must use a loopback endpoint"
            )
        return endpoint.strip().rstrip("/")

    if provider_id != "custom":
        canonical = _normalized_http_endpoint(canonical_endpoint)
        canonical_host = (canonical.hostname or "").lower().rstrip(".")
        if parsed.scheme != "https":
            raise OutboundDestinationError("Cloud AI providers must use HTTPS")
        if host != canonical_host:
            raise OutboundDestinationError(
                f"{provider_id} must use its catalog endpoint host"
            )
        if parsed.port not in {None, 443}:
            raise OutboundDestinationError("Cloud AI providers must use HTTPS port 443")
        canonical_path = canonical.path.rstrip("/")
        configured_path = parsed.path.rstrip("/")
        if canonical_path and not (
            configured_path == canonical_path
            or configured_path.startswith(f"{canonical_path}/")
        ):
            raise OutboundDestinationError(
                "Cloud AI endpoint path must remain under the catalog API path"
            )
        return endpoint.strip().rstrip("/")

    if host in LOOPBACK_HOSTS:
        return endpoint.strip().rstrip("/")
    if host not in trusted:
        raise OutboundDestinationError(
            "Custom non-loopback AI endpoint hostname is not explicitly trusted"
        )
    if parsed.scheme != "https":
        raise OutboundDestinationError("Trusted custom AI providers must use HTTPS")
    literal = _literal_ip(host)
    if literal is not None and not literal.is_global:
        raise OutboundDestinationError(
            "Custom AI endpoint cannot use a private, reserved, or link-local address"
        )
    if literal is None and not HOSTNAME.fullmatch(host):
        raise OutboundDestinationError("Custom AI endpoint hostname is invalid")
    return endpoint.strip().rstrip("/")


def validate_smtp_destination(
    host: str,
    *,
    trusted_private_hosts: tuple[str, ...] = (),
) -> str:
    """Accept a hostname only, blocking URL syntax and untrusted private IP literals."""
    cleaned = host.strip().lower().rstrip(".")
    if not cleaned:
        raise OutboundDestinationError("SMTP host is required")
    if any(character in cleaned for character in ("/", "\\", "@", "?", "#")):
        raise OutboundDestinationError("SMTP host must be a hostname, not a URL")
    trusted = {value.lower().rstrip(".") for value in trusted_private_hosts}
    if cleaned in LOOPBACK_HOSTS or cleaned in trusted:
        return cleaned
    literal = _literal_ip(cleaned)
    if literal is not None:
        if not literal.is_global:
            raise OutboundDestinationError(
                "SMTP host cannot use an untrusted private, reserved, or link-local address"
            )
        return cleaned
    if not HOSTNAME.fullmatch(cleaned):
        raise OutboundDestinationError("SMTP hostname is invalid")
    return cleaned
