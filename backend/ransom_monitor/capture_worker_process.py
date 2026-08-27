from __future__ import annotations

import asyncio

from .capture_worker import capture_worker_heartbeat_loop, capture_worker_loop
from .capture_worker_client import CaptureWorkerAPIClient
from .config import get_settings


async def run() -> None:
    settings = get_settings()
    if not settings.capture_worker_configured:
        raise SystemExit(
            "Capture worker is not configured; rerun setup-kali.sh --prepare-capture"
        )
    async with CaptureWorkerAPIClient(
        settings.capture_worker_api_url,
        settings.capture_worker_token,
        settings.capture_dir,
    ) as coordinator:
        await asyncio.gather(
            capture_worker_loop(coordinator, settings),
            capture_worker_heartbeat_loop(coordinator),
        )


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
