from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    database_path: Path
    raw_dir: Path
    capture_dir: Path
    frontend_dist: Path
    collect_timeout_seconds: float = 20.0
    backfill_timeout_seconds: float = 120.0
    auto_collect: bool = True
    collect_interval_seconds: int = 120
    ransomlook_url: str = "https://www.ransomlook.io/api/posts"
    ransomlook_groups_url: str = "https://www.ransomlook.io/api/groups"
    ransomfeed_url: str = "https://api.ransomfeed.it"
    ransomware_live_url: str = "https://api.ransomware.live/v2/recentvictims"
    ransomware_live_groups_url: str = "https://api.ransomware.live/v2/groups"
    capture_worker_token: str = ""
    capture_worker_enabled: bool = False
    capture_worker_api_url: str = "http://127.0.0.1:8765"
    chromium_path: str = ""
    tor_proxy: str = "socks5://127.0.0.1:9050"
    capture_timeout_seconds: int = 90
    capture_max_scrolls: int = 60
    capture_scroll_delay_ms: int = 1000
    capture_max_page_height: int = 50000
    capture_segment_height: int = 1400
    tesseract_path: str = ""
    capture_ocr_mode: str = "always"
    capture_ocr_timeout_seconds: int = 180
    trusted_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "::1")
    trusted_custom_ai_hosts: tuple[str, ...] = ()
    trusted_private_smtp_hosts: tuple[str, ...] = ()

    @property
    def ocr_configured(self) -> bool:
        return bool(self.tesseract_path) and self.capture_ocr_mode != "off"

    @property
    def capture_worker_configured(self) -> bool:
        return (
            self.capture_worker_enabled
            and len(self.capture_worker_token) >= 24
            and bool(self.chromium_path)
        )


def get_settings() -> Settings:
    project_root = Path(__file__).resolve().parents[2]
    data_dir = Path(os.getenv("RANSOM_MONITOR_DATA_DIR", project_root / "data")).resolve()
    chromium_path = os.getenv("EXTORTSIGNAL_CHROMIUM_PATH", "").strip()
    if not chromium_path:
        chromium_path = shutil.which("chromium") or shutil.which("chromium-browser") or ""
    tesseract_path = os.getenv("EXTORTSIGNAL_TESSERACT_PATH", "").strip()
    if not tesseract_path:
        tesseract_path = shutil.which("tesseract") or ""
    ocr_mode = os.getenv("EXTORTSIGNAL_CAPTURE_OCR_MODE", "always").strip().lower()
    if ocr_mode not in {"auto", "always", "off"}:
        ocr_mode = "auto"
    trusted_hosts = tuple(
        value.strip()
        for value in os.getenv(
            "EXTORTSIGNAL_TRUSTED_HOSTS", "127.0.0.1,localhost,::1"
        ).split(",")
        if value.strip()
    )
    trusted_custom_ai_hosts = tuple(
        value.strip().lower().rstrip(".")
        for value in os.getenv("EXTORTSIGNAL_TRUSTED_CUSTOM_AI_HOSTS", "").split(",")
        if value.strip()
    )
    trusted_private_smtp_hosts = tuple(
        value.strip().lower().rstrip(".")
        for value in os.getenv(
            "EXTORTSIGNAL_TRUSTED_PRIVATE_SMTP_HOSTS", ""
        ).split(",")
        if value.strip()
    )
    return Settings(
        data_dir=data_dir,
        database_path=data_dir / "ransom-monitor.sqlite3",
        raw_dir=data_dir / "raw",
        capture_dir=data_dir / "captures",
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
        capture_worker_enabled=os.getenv("EXTORTSIGNAL_CAPTURE_WORKER_ENABLED", "0").lower()
        in {"1", "true", "yes"},
        capture_worker_api_url=os.getenv(
            "EXTORTSIGNAL_CAPTURE_WORKER_API_URL", "http://127.0.0.1:8765"
        ).strip(),
        chromium_path=chromium_path,
        tor_proxy=os.getenv("EXTORTSIGNAL_TOR_PROXY", "socks5://127.0.0.1:9050").strip(),
        capture_timeout_seconds=max(
            30, min(300, int(os.getenv("EXTORTSIGNAL_CAPTURE_TIMEOUT", "90")))
        ),
        capture_max_scrolls=max(
            1, min(200, int(os.getenv("EXTORTSIGNAL_CAPTURE_MAX_SCROLLS", "60")))
        ),
        capture_scroll_delay_ms=max(
            250, min(5000, int(os.getenv("EXTORTSIGNAL_CAPTURE_SCROLL_DELAY_MS", "1000")))
        ),
        capture_max_page_height=max(
            5000, min(100000, int(os.getenv("EXTORTSIGNAL_CAPTURE_MAX_PAGE_HEIGHT", "50000")))
        ),
        capture_segment_height=max(
            800, min(2400, int(os.getenv("EXTORTSIGNAL_CAPTURE_SEGMENT_HEIGHT", "1400")))
        ),
        tesseract_path=tesseract_path,
        capture_ocr_mode=ocr_mode,
        capture_ocr_timeout_seconds=max(
            30, min(600, int(os.getenv("EXTORTSIGNAL_CAPTURE_OCR_TIMEOUT", "180")))
        ),
        trusted_hosts=trusted_hosts or ("127.0.0.1", "localhost", "::1"),
        trusted_custom_ai_hosts=trusted_custom_ai_hosts,
        trusted_private_smtp_hosts=trusted_private_smtp_hosts,
    )
