import asyncio

import pytest

from ransom_monitor.capture_worker_client import CaptureWorkerAPIClient


def test_worker_control_plane_is_pinned_to_loopback(tmp_path):
    token = "x" * 32
    for endpoint in (
        "https://api.example/worker",
        "http://10.0.0.8:8765",
        "http://user:pass@127.0.0.1:8765",
    ):
        with pytest.raises(ValueError, match="loopback"):
            CaptureWorkerAPIClient(endpoint, token, tmp_path)


def test_worker_serializes_only_contained_evidence_paths(tmp_path):
    capture_dir = tmp_path / "captures"
    capture_dir.mkdir()
    client = CaptureWorkerAPIClient(
        "http://127.0.0.1:8765", "x" * 32, capture_dir
    )
    try:
        evidence = capture_dir / "actor" / "capture.png"
        evidence.parent.mkdir()
        evidence.write_bytes(b"png")
        assert client._relative_artifact(evidence) == "actor/capture.png"
        with pytest.raises(RuntimeError, match="escaped"):
            client._relative_artifact(tmp_path / "outside.png")
    finally:
        asyncio.run(client._client.aclose())
