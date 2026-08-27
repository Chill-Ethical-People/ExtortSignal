from __future__ import annotations

import ipaddress
from pathlib import Path
import secrets


MUTATION_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
MUTATION_HEADER = "X-ExtortSignal-Request"
MUTATION_HEADER_VALUE = "same-origin"


def mutation_request_allowed(method: str, path: str, marker: str | None) -> bool:
    if method.upper() not in MUTATION_METHODS or not path.startswith("/api/v1/"):
        return True
    return marker == MUTATION_HEADER_VALUE


def capture_worker_request_allowed(peer: str, authorization: str, token: str) -> bool:
    if len(token) < 24:
        return False
    try:
        if not ipaddress.ip_address(peer).is_loopback:
            return False
    except ValueError:
        if peer != "localhost":
            return False
    return secrets.compare_digest(authorization, f"Bearer {token}")


def resolve_frontend_file(frontend_root: Path, request_path: str) -> Path | None:
    """Return a contained frontend file, never a lexical ``..`` traversal."""
    root = frontend_root.resolve()
    candidate = (root / request_path).resolve()
    if candidate.is_file() and candidate.is_relative_to(root):
        return candidate
    return None
