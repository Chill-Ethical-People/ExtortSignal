from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    database_path: Path
    raw_dir: Path
    frontend_dist: Path
    collect_timeout_seconds: float = 20.0
    backfill_timeout_seconds: float = 120.0
    auto_collect: bool = True
    collect_interval_seconds: int = 120
    ransomlook_url: str = "https://www.ransomlook.io/api/posts"
    ransomfeed_url: str = "https://api.ransomfeed.it"
    ransomware_live_url: str = "https://api.ransomware.live/v2/recentvictims"
    ransomware_live_groups_url: str = "https://api.ransomware.live/v2/groups"
    capture_worker_token: str = ""

    @property
    def capture_worker_configured(self) -> bool:
        return len(self.capture_worker_token) >= 24


def get_settings() -> Settings:
    project_root = Path(__file__).resolve().parents[2]
    data_dir = Path(os.getenv("RANSOM_MONITOR_DATA_DIR", project_root / "data")).resolve()
    return Settings(
        data_dir=data_dir,
        database_path=data_dir / "ransom-monitor.sqlite3",
        raw_dir=data_dir / "raw",
        frontend_dist=project_root / "frontend" / "dist",
        collect_timeout_seconds=float(os.getenv("RANSOM_MONITOR_TIMEOUT", "20")),
        backfill_timeout_seconds=float(
            os.getenv("RANSOM_MONITOR_BACKFILL_TIMEOUT", "120")
        ),
        auto_collect=os.getenv("RANSOM_MONITOR_AUTO_COLLECT", "1").lower()
        not in {"0", "false", "no"},
        collect_interval_seconds=max(
            60, int(os.getenv("RANSOM_MONITOR_COLLECT_INTERVAL", "120"))
        ),
        capture_worker_token=os.getenv("EXTORTSIGNAL_CAPTURE_WORKER_TOKEN", "").strip(),
    )
