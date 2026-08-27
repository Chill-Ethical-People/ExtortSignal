from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

import httpx

from .web_security import MUTATION_HEADER, MUTATION_HEADER_VALUE


class CaptureWorkerAPIClient:
    """Authenticated loopback client used by the separate DLS capture process."""

    def __init__(self, base_url: str, token: str, capture_dir: Path):
        parsed = urlsplit(base_url.strip())
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Capture worker API must use an unauthenticated loopback HTTP URL")
        if len(token) < 24:
            raise ValueError("Capture worker token must contain at least 24 characters")
        self.capture_dir = capture_dir.resolve()
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=httpx.Timeout(30, connect=5),
            follow_redirects=False,
            headers={
                "Authorization": f"Bearer {token}",
                MUTATION_HEADER: MUTATION_HEADER_VALUE,
                "Accept": "application/json",
            },
        )

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self._client.aclose()

    async def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        response = await self._client.request(method, path, **kwargs)
        response.raise_for_status()
        return response

    async def heartbeat(self) -> None:
        await self._request("POST", "/api/v1/internal/capture-worker/heartbeat")

    async def requeue_interrupted_capture_jobs(self) -> None:
        await self._request("POST", "/api/v1/internal/capture-worker/requeue")

    async def claim_next_capture_job(self) -> dict | None:
        response = await self._request("POST", "/api/v1/internal/capture-worker/claim")
        if response.status_code == 204:
            return None
        return response.json()

    async def job_context(self, job_id: str, target_id: str) -> dict:
        response = await self._request(
            "GET", f"/api/v1/internal/capture-worker/jobs/{job_id}/context"
        )
        payload = response.json()
        if payload.get("target_id") != target_id:
            raise RuntimeError("Capture context target did not match the reserved job")
        return payload

    def _relative_artifact(self, path: Path) -> str:
        resolved = path.resolve()
        if not resolved.is_relative_to(self.capture_dir):
            raise RuntimeError("Capture artifact escaped the configured evidence directory")
        return str(resolved.relative_to(self.capture_dir))

    async def complete_capture_job(
        self,
        job_id: str,
        screenshot_path: Path,
        content_sha256: str,
        **metadata,
    ) -> None:
        screenshot_paths = metadata.pop("screenshot_paths", [screenshot_path])
        text_path = metadata.pop("text_path", None)
        payload = {
            **metadata,
            "screenshot_path": self._relative_artifact(screenshot_path),
            "screenshot_paths": [self._relative_artifact(path) for path in screenshot_paths],
            "text_path": self._relative_artifact(text_path) if text_path else "",
            "content_sha256": content_sha256,
        }
        await self._request(
            "POST",
            f"/api/v1/internal/capture-worker/jobs/{job_id}/complete",
            json=payload,
        )

    async def fail_capture_job(self, job_id: str, message: str, **metadata) -> None:
        await self._request(
            "POST",
            f"/api/v1/internal/capture-worker/jobs/{job_id}/fail",
            json={"error": message, **metadata},
        )
