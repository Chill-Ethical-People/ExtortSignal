from ransom_monitor.web_security import (
    MUTATION_HEADER_VALUE,
    capture_worker_request_allowed,
    mutation_request_allowed,
    resolve_frontend_file,
)


def test_capture_worker_requires_loopback_and_constant_token():
    token = "x" * 32
    assert capture_worker_request_allowed("127.0.0.1", f"Bearer {token}", token)
    assert capture_worker_request_allowed("::1", f"Bearer {token}", token)
    assert not capture_worker_request_allowed("10.0.0.5", f"Bearer {token}", token)
    assert not capture_worker_request_allowed("127.0.0.1", "Bearer wrong", token)
    assert not capture_worker_request_allowed("127.0.0.1", "Bearer short", "short")


def test_mutating_api_requires_same_origin_marker():
    assert mutation_request_allowed("GET", "/api/v1/claims", None)
    assert mutation_request_allowed("POST", "/health/ready", None)
    assert not mutation_request_allowed("POST", "/api/v1/collect", None)
    assert mutation_request_allowed(
        "POST",
        "/api/v1/collect",
        MUTATION_HEADER_VALUE,
    )


def test_frontend_file_resolution_rejects_parent_traversal(tmp_path):
    frontend = tmp_path / "frontend"
    dist = frontend / "dist"
    dist.mkdir(parents=True)
    index = dist / "index.html"
    index.write_text("safe", encoding="utf-8")
    secret = frontend / ".env"
    secret.write_text("do-not-serve", encoding="utf-8")

    assert resolve_frontend_file(dist, "index.html") == index
    assert resolve_frontend_file(dist, "../.env") is None
    assert resolve_frontend_file(dist, "%2e%2e/.env") is None
