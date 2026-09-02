from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
import unicodedata
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from .actor_names import actor_identity_key
from .capture_analysis import (
    analyze_capture_text,
    anchor_candidates,
    continuity_analysis,
    normalized_capture_text,
)
from .capture_worker_client import CaptureWorkerAPIClient
from .config import Settings


LOGGER = logging.getLogger(__name__)


ONION_HOST = re.compile(r"^(?:[a-z2-7]{16}|[a-z2-7]{56})\.onion$")
OPERATOR_CLEARNET_CAPTURE_HOSTS = frozenset({"fulcrumsec.vg"})
LOOPBACK_PROXY_HOSTS = {"127.0.0.1", "localhost", "::1"}
OPSEC_CONTROLS = (
    "loopback_tor_socks_preflight",
    "exact_target_request_isolation",
    "websockets_blocked",
    "browser_dns_fail_closed",
    "webrtc_non_proxied_udp_disabled",
    "downloads_blocked",
    "popups_and_dialogs_blocked",
    "permissions_denied",
    "ephemeral_browser_context",
    "private_evidence_permissions",
    "bounded_read_only_interactions",
    "actor_scoped_interaction_profiles",
    "same_origin_get_head_only",
)
ENTRY_LABELS = ("enter", "continue", "view site", "proceed")
LOAD_MORE_LABELS = ("load more", "show more", "show older", "more")
NEXT_PAGE_LABELS = ("next", "next page", "older", "›", "»", "→")
MAX_INTERACTION_ACTIONS = 24
MAX_PAGINATION_PAGES = 10
MAX_READ_ONLY_TABS = 8
MAX_LOAD_MORE_CLICKS = 12
MAX_CAPTURE_STATES = 16
MAX_REVIEW_SEGMENTS = 120
MIN_READABLE_EVIDENCE_CHARS = 40
GENERIC_TERMINAL_PAGE_TEXT = (
    "502 bad gateway",
    "503 service unavailable",
    "504 gateway timeout",
    "onionsite not found",
)


CAPTURE_SITE_PROFILES: dict[str, dict[str, object]] = {
    "akira": {
        "navigation_attempts": 2,
        "navigation_retry_delay_ms": 5_000,
        "ready_timeout_ms": 45_000,
        "min_body_chars": 180,
        "candidate_selector": "article, [class*='victim' i], [class*='card' i], table tbody tr",
        "min_candidate_count": 1,
        "reject_if_not_ready": True,
    },
    "chaos": {
        "ready_timeout_ms": 45_000,
        "min_body_chars": 160,
        "require_no_busy_indicator": True,
        "required_text_any": ("leaked size", "view count"),
        "candidate_selector": "article, [class*='victim' i], [class*='card' i]",
        "min_candidate_count": 1,
        "reject_if_not_ready": True,
    },
    "clop": {
        "navigation_attempts": 2,
        "navigation_retry_delay_ms": 5_000,
        "ready_timeout_ms": 180_000,
        "blocked_text": (
            "awaiting forwarding to the platform",
            "automatically redirected",
        ),
        "min_body_chars": 500,
        "reject_if_not_ready": True,
    },
    "deadlock": {
        "ready_timeout_ms": 20_000,
        "min_body_chars": 400,
        "required_text_any": ("published", "coming soon"),
        "reject_if_not_ready": True,
    },
    "direwolf": {
        "ready_timeout_ms": 10_000,
        "min_body_chars": 160,
        "reject_if_not_ready": True,
    },
    "dragonforce": {
        "ready_timeout_ms": 10_000,
        "terminal_text": ("log in to recovery",),
        "min_body_chars": 200,
        "reject_if_not_ready": True,
    },
    "gunra": {
        "navigation_attempts": 2,
        "navigation_retry_delay_ms": 5_000,
        "ready_timeout_ms": 60_000,
        "min_body_chars": 160,
        "require_no_busy_indicator": True,
        "candidate_selector": "article, [class*='victim' i], [class*='card' i], table tbody tr",
        "min_candidate_count": 1,
        "reject_if_not_ready": True,
    },
    "thegentlemen": {
        "ready_timeout_ms": 60_000,
        "blocked_text": (
            "verifying your browser",
            "running security checks",
            "finalizing verification",
        ),
        "terminal_text": ("cannot read properties of undefined",),
        "min_body_chars": 240,
        "reject_if_not_ready": True,
    },
    "lockbit5": {
        "screen_gate_text": "click anywhere to enter",
        "post_click_wait_ms": 12_000,
        "ready_timeout_ms": 25_000,
        "min_body_chars": 220,
        "candidate_selector": "table tbody tr",
        "min_candidate_count": 1,
        "reject_if_not_ready": True,
    },
    "lynx": {
        "navigation_labels": ("leaks",),
        "post_click_wait_ms": 5_000,
        "ready_timeout_ms": 15_000,
        "min_body_chars": 160,
        "required_text_any": ("date of publication",),
        "reject_if_not_ready": True,
    },
    "kazu": {
        "navigation_attempts": 2,
        "navigation_retry_delay_ms": 5_000,
        "navigation_labels": ("recent posts",),
        "post_click_wait_ms": 5_000,
        "ready_timeout_ms": 60_000,
        "min_body_chars": 180,
        "require_no_busy_indicator": True,
        "required_text_any": ("recent posts",),
        "candidate_selector": (
            "article, [class*='post-card' i], [class*='post-item' i], "
            "[class*='victim-card' i], table tbody tr"
        ),
        "min_candidate_count": 1,
        "max_pagination_pages": 10,
        "reject_if_not_ready": True,
    },
    "incransom": {
        "navigation_attempts": 2,
        "navigation_retry_delay_ms": 5_000,
        "ready_timeout_ms": 90_000,
        "min_body_chars": 260,
        "require_no_busy_indicator": True,
        "reject_if_not_ready": True,
    },
    "medusalocker": {
        "ready_timeout_ms": 90_000,
        "blocked_text": ("verifying browser", "verifying your browser"),
        "min_body_chars": 180,
        "candidate_selector": "article, [class*='victim' i], [class*='card' i], table tbody tr",
        "min_candidate_count": 1,
        "reject_if_not_ready": True,
    },
    "safepay": {
        "ready_timeout_ms": 20_000,
        "min_body_chars": 240,
        "candidate_selector": "[class*='card' i], article",
        "min_candidate_count": 3,
        "max_pagination_pages": 10,
        "reject_if_not_ready": True,
    },
    "shinyhunters": {
        "navigation_attempts": 2,
        "navigation_retry_delay_ms": 5_000,
        "screen_gate_text": "click anywhere to enter",
        "post_click_wait_ms": 5_000,
        "ready_timeout_ms": 180_000,
        "blocked_text": (
            "awaiting forwarding to the platform",
            "automatically redirected",
        ),
        "min_body_chars": 240,
        "reject_if_not_ready": True,
    },
    "spacebears": {
        "navigation_attempts": 2,
        "navigation_retry_delay_ms": 5_000,
        "navigation_labels": ("list of companies",),
        "post_click_wait_ms": 4_000,
        "ready_timeout_ms": 20_000,
        "min_body_chars": 240,
        "candidate_selector": "[class*='company' i], [class*='card' i], article",
        "min_candidate_count": 1,
        "required_text_any": ("list of companies",),
        "reject_if_not_ready": True,
        "stop_before_heading": "contact",
        "max_pagination_pages": 1,
    },
    "fulcrumsec": {
        "navigation_attempts": 2,
        "navigation_retry_delay_ms": 5_000,
        "ready_timeout_ms": 45_000,
        "min_body_chars": 120,
        "candidate_selector": (
            "article, [class*='victim' i], [class*='company' i], "
            "[class*='card' i], table tbody tr"
        ),
        "min_candidate_count": 1,
        "reject_if_not_ready": True,
    },
}


def capture_site_profile(group_name: str) -> dict[str, object]:
    """Return a bounded, actor-specific read-only interaction profile."""
    slug = safe_actor_directory(group_name)
    identity = actor_identity_key(group_name)
    profile_key = {"cl0p": "clop"}.get(identity, identity)
    return dict(
        CAPTURE_SITE_PROFILES.get(profile_key)
        or CAPTURE_SITE_PROFILES.get(slug)
        or CAPTURE_SITE_PROFILES.get(slug.replace("-", ""), {})
    )


def chromium_user_agent(browser_version: str) -> str:
    """Build a conventional desktop Chrome UA that matches the installed browser.

    Playwright's headless default contains a ``HeadlessChrome`` token.  Using the
    actual Chromium version avoids both that unusual token and a stale hard-coded
    browser version.  This is presentation compatibility, not anti-bot bypassing.
    """
    match = re.search(r"\d+(?:\.\d+){1,3}", browser_version)
    if match is None:
        raise ValueError("Cannot derive a Chromium user agent from the browser version")
    version = match.group(0)
    return (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        f"(KHTML, like Gecko) Chrome/{version} Safari/537.36"
    )


def validate_onion_host(fqdn: str) -> str:
    host = fqdn.strip().lower().rstrip(".")
    if not ONION_HOST.fullmatch(host):
        raise ValueError("Capture blocked: the catalog target is not a valid onion hostname")
    return host


def validate_capture_host(fqdn: str) -> str:
    """Allow Tor hosts plus a narrow reviewed clear-web capture allowlist."""
    host = fqdn.strip().lower().rstrip(".")
    if ONION_HOST.fullmatch(host) or host in OPERATOR_CLEARNET_CAPTURE_HOSTS:
        return host
    raise ValueError(
        "Capture blocked: target is neither a valid onion hostname nor an "
        "operator-approved clear-web DLS hostname"
    )


def validate_tor_proxy(proxy: str) -> tuple[str, int]:
    """Accept only an unauthenticated SOCKS5 listener on this VM."""
    parsed = urlparse(proxy)
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("OPSEC gate failed: Tor proxy port is invalid") from error
    if parsed.scheme.lower() != "socks5":
        raise ValueError("OPSEC gate failed: Tor proxy must use socks5://")
    if parsed.username or parsed.password:
        raise ValueError("OPSEC gate failed: credentials are not allowed in the Tor proxy URL")
    if (parsed.hostname or "").lower() not in LOOPBACK_PROXY_HOSTS:
        raise ValueError("OPSEC gate failed: Tor proxy must be bound to loopback")
    if port is None or not 1 <= port <= 65535:
        raise ValueError("OPSEC gate failed: Tor proxy must include a valid port")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("OPSEC gate failed: Tor proxy URL must not include a path or query")
    return parsed.hostname.lower(), port


async def tor_socks_preflight(proxy: str, timeout_seconds: float = 5.0) -> None:
    """Verify the local listener completes a SOCKS5 no-auth handshake.

    This intentionally makes no external request. A capture still fails closed if the
    local Tor listener is absent or is not speaking SOCKS5.
    """
    host, port = validate_tor_proxy(proxy)
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout_seconds
        )
        writer.write(b"\x05\x01\x00")
        await asyncio.wait_for(writer.drain(), timeout=timeout_seconds)
        response = await asyncio.wait_for(reader.readexactly(2), timeout=timeout_seconds)
        if response != b"\x05\x00":
            raise RuntimeError("local listener rejected the SOCKS5 no-auth handshake")
    except (OSError, TimeoutError, asyncio.IncompleteReadError, RuntimeError) as error:
        raise RuntimeError(
            f"OPSEC gate failed: local Tor SOCKS preflight failed ({error})"
        ) from None
    finally:
        if writer is not None:
            writer.close()
            await writer.wait_closed()


def request_allowed_for_target(url: str, target_host: str, method: str = "GET") -> bool:
    """Restrict browser traffic to the exact allowlisted target origin."""
    parsed = urlparse(url)
    if parsed.scheme in {"data", "blob", "about"}:
        return method.upper() in {"GET", "HEAD"}
    return (
        method.upper() in {"GET", "HEAD"}
        and parsed.scheme in {"http", "https"}
        and parsed.hostname == target_host
    )


def browser_launch_options(settings: Settings) -> dict:
    return {
        "executable_path": settings.chromium_path,
        "headless": True,
        "proxy": {"server": settings.tor_proxy},
        "args": [
            "--disable-background-networking",
            "--disable-breakpad",
            "--disable-component-update",
            "--disable-extensions",
            "--disable-features=MediaRouter",
            "--disable-sync",
            "--dns-prefetch-disable",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            "--metrics-recording-only",
            "--no-first-run",
            "--no-default-browser-check",
            "--proxy-bypass-list=<-loopback>",
            "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
        ],
    }


def safe_actor_directory(group_name: str) -> str:
    ascii_name = unicodedata.normalize("NFKD", group_name).encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", ascii_name).strip("-._").lower()
    return slug[:100] or "unknown-actor"


def capture_evidence_rejection_reason(text: str) -> str:
    """Reject output that contains no claim evidence or only an error/interstitial."""
    payload_lines = [
        line
        for line in normalized_capture_text(text).splitlines()
        if not line.startswith(
            (
                "--- capture state",
                "--- local ocr",
                "--- review page",
                "--- read-only interaction audit",
            )
        )
    ]
    payload = "\n".join(payload_lines).strip()
    normalized = " ".join(payload.casefold().split())
    terminal = next(
        (value for value in GENERIC_TERMINAL_PAGE_TEXT if value in normalized[:1_000]),
        "",
    )
    if terminal:
        return f"Captured presentation is an upstream error page ({terminal})"
    if len(payload) < MIN_READABLE_EVIDENCE_CHARS:
        return "Captured presentation did not contain enough readable evidence"
    interstitial = next(
        (
            value
            for value in (
                "awaiting forwarding to the platform",
                "verifying browser",
                "verifying your browser",
                "click anywhere to enter",
            )
            if value in normalized[:1_000]
        ),
        "",
    )
    if interstitial and len(normalized) < 1_200:
        return f"Captured presentation remained on an interstitial ({interstitial})"
    return ""


def evidence_path(settings: Settings, job: dict) -> tuple[Path, Path]:
    started = datetime.fromisoformat(str(job["started_at"])).astimezone()
    actor_dir = settings.capture_dir / safe_actor_directory(str(job["group_name"]))
    timestamp = started.strftime("%Y-%m-%d_%H-%M-%S_%Z")
    screenshot = actor_dir / f"{timestamp}_p001.png"
    if screenshot.exists():
        screenshot = actor_dir / f"{timestamp}_{str(job['id'])[:8]}_p001.png"
    return actor_dir, screenshot


def review_page_ranges(
    total_height: int, segment_height: int, overlap: int = 80
) -> list[tuple[int, int]]:
    """Return human-sized page clips with a small overlap at each boundary."""
    total_height = max(1, total_height)
    segment_height = max(1, segment_height)
    overlap = max(0, min(overlap, segment_height - 1))
    step = segment_height - overlap
    ranges: list[tuple[int, int]] = []
    top = 0
    while top < total_height:
        height = min(segment_height, total_height - top)
        ranges.append((top, height))
        if top + height >= total_height:
            break
        top += step
    return ranges


def numbered_screenshot_path(first_path: Path, page_number: int) -> Path:
    return first_path.with_name(re.sub(r"_p001\.png$", f"_p{page_number:03d}.png", first_path.name))


async def capture_review_pages(
    page,
    first_path: Path,
    total_height: int,
    settings: Settings,
    controls: dict[str, int] | None = None,
    *,
    start_page_number: int = 1,
    max_segments: int | None = None,
) -> list[Path]:
    controls = controls or {}
    max_page_height = controls.get("capture_max_page_height", settings.capture_max_page_height)
    segment_height = controls.get("capture_segment_height", settings.capture_segment_height)
    captured_height = min(max(1, total_height), max_page_height)
    paths: list[Path] = []
    ranges = review_page_ranges(captured_height, segment_height)
    if max_segments is not None:
        ranges = ranges[: max(0, max_segments)]
    for page_number, (top, _height) in enumerate(ranges, start=start_page_number):
        path = numbered_screenshot_path(first_path, page_number)
        paths.append(path)
        await page.evaluate("position => window.scrollTo(0, position)", top)
        await page.wait_for_timeout(150)
        await page.screenshot(
            path=str(path),
            animations="disabled",
            timeout=settings.capture_timeout_seconds * 1000,
            full_page=False,
        )
    await page.evaluate("window.scrollTo(0, 0)")
    return paths


def remove_empty_capture_directory(directory: Path, capture_root: Path) -> None:
    try:
        if directory.resolve().is_relative_to(capture_root.resolve()):
            directory.rmdir()
    except OSError:
        pass


async def tesseract_ocr(screenshot_path: Path, settings: Settings) -> str:
    if not settings.ocr_configured:
        return ""
    process = await asyncio.create_subprocess_exec(
        settings.tesseract_path,
        str(screenshot_path),
        "stdout",
        "-l",
        "eng",
        "--psm",
        "11",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=settings.capture_ocr_timeout_seconds
        )
    except TimeoutError:
        process.kill()
        await process.communicate()
        raise RuntimeError("Local OCR timed out") from None
    if process.returncode != 0:
        detail = stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(detail[-300:] or "Local OCR failed")
    return stdout.decode("utf-8", errors="replace")[:5_000_000]


async def scroll_until_stable(
    page, settings: Settings, controls: dict[str, int] | None = None
) -> dict:
    """Trigger lazy loading without clicking links, forms, or download controls."""
    controls = controls or {}
    max_scrolls = controls.get("capture_max_scrolls", settings.capture_max_scrolls)
    stable_required = controls.get("capture_stable_passes", 3)
    scroll_delay_ms = controls.get("capture_scroll_delay_ms", settings.capture_scroll_delay_ms)
    max_page_height = controls.get("capture_max_page_height", settings.capture_max_page_height)
    previous_height = 0
    stable_passes = 0
    passes = 0
    coverage_status = "scroll_limit"
    for passes in range(1, max_scrolls + 1):
        height = int(
            await page.evaluate(
                "Math.max(document.body.scrollHeight, document.documentElement.scrollHeight)"
            )
        )
        if height >= max_page_height:
            coverage_status = "height_limit"
            break
        await page.evaluate("window.scrollTo(0, document.documentElement.scrollHeight)")
        await page.wait_for_timeout(scroll_delay_ms)
        new_height = int(
            await page.evaluate(
                "Math.max(document.body.scrollHeight, document.documentElement.scrollHeight)"
            )
        )
        stable_passes = stable_passes + 1 if new_height <= previous_height + 8 else 0
        previous_height = max(previous_height, new_height)
        if stable_passes >= stable_required:
            coverage_status = "stable"
            break
    await page.evaluate("window.scrollTo(0, 0)")
    await page.wait_for_timeout(250)
    final_height = int(
        await page.evaluate(
            "Math.max(document.body.scrollHeight, document.documentElement.scrollHeight)"
        )
    )
    if final_height > max_page_height:
        coverage_status = "height_limit"
    return {
        "scroll_count": passes,
        "page_height": final_height,
        "capture_truncated": coverage_status != "stable",
        "coverage_status": coverage_status,
    }


async def css_blur_element_count(page) -> int:
    """Count visible elements whose computed page styling explicitly applies blur."""
    return int(
        await page.evaluate(
            r"""
            Array.from(document.querySelectorAll('body *')).filter((element) => {
              const style = getComputedStyle(element);
              const filter = `${style.filter || ''} ${style.backdropFilter || ''}`;
              if (!/blur\([^)]*[1-9][0-9.]*px\)/i.test(filter)) return false;
              const rect = element.getBoundingClientRect();
              return rect.width > 0 && rect.height > 0 && style.visibility !== 'hidden';
            }).length
            """
        )
    )


async def pagination_control_detected(page) -> bool:
    """Detect a visible read-only pagination/load-more control without activating it."""
    return bool(
        await page.evaluate(
            r"""
            Array.from(document.querySelectorAll('a, button')).some((element) => {
              const style = getComputedStyle(element);
              const rect = element.getBoundingClientRect();
              if (rect.width <= 0 || rect.height <= 0 || style.visibility === 'hidden') return false;
              const text = (element.textContent || '').trim().toLowerCase();
              const rel = (element.getAttribute('rel') || '').toLowerCase();
              const label = (element.getAttribute('aria-label') || '').trim().toLowerCase();
              return rel.split(/\s+/).includes('next')
                || /^(next|older|more|load more|show more|show older|next page)$/i.test(text)
                || /^(next|older|more|load more|show more|show older|next page)$/i.test(label)
                || Boolean(element.closest('[class*="pagination" i], [class*="pager" i]'))
                  && /^(›|»|→)$/i.test(text);
            })
            """
        )
    )


async def wait_for_visual_ready(page, timeout_ms: int = 10_000) -> bool:
    """Wait until the document has visible, non-white presentation content."""
    deadline = time.monotonic() + max(0, timeout_ms) / 1000
    while time.monotonic() < deadline:
        ready = bool(
            await page.evaluate(
                r"""
                (() => {
                  if (!document.body) return false;
                  const styles = [getComputedStyle(document.documentElement), getComputedStyle(document.body)];
                  const nonWhite = styles.some((style) => {
                    const color = (style.backgroundColor || '').replace(/\s+/g, '').toLowerCase();
                    const image = (style.backgroundImage || '').toLowerCase();
                    return image !== '' && image !== 'none'
                      || !['', 'transparent', 'rgba(0,0,0,0)', 'rgb(255,255,255)', 'rgba(255,255,255,1)'].includes(color);
                  });
                  const visibleMedia = Array.from(document.querySelectorAll('img, svg, canvas, video')).some((element) => {
                    const rect = element.getBoundingClientRect();
                    const style = getComputedStyle(element);
                    return rect.width > 8 && rect.height > 8 && style.visibility !== 'hidden' && style.display !== 'none';
                  });
                  return nonWhite || visibleMedia;
                })()
                """
            )
        )
        if ready:
            return True
        await page.wait_for_timeout(250)
    return False


async def site_readiness_state(page) -> dict[str, object]:
    """Return only presentation signals needed by a capture readiness profile."""
    return dict(
        await page.evaluate(
            r"""
            (() => {
              const normalize = (value) => (value || '').replace(/\s+/g, ' ').trim().toLowerCase();
              const visible = (element) => {
                const style = getComputedStyle(element);
                const rect = element.getBoundingClientRect();
                return rect.width > 0 && rect.height > 0 && style.visibility !== 'hidden'
                  && style.display !== 'none' && Number(style.opacity || '1') > 0;
              };
              const text = normalize(document.body?.innerText || '');
              const busy = Array.from(document.querySelectorAll(
                '[aria-busy="true"], [class*="spinner" i], [class*="loading" i], [class*="loader" i]'
              )).some(visible);
              return { text, text_length: text.length, busy };
            })()
            """
        )
    )


async def wait_for_site_ready(page, profile: dict[str, object]) -> dict[str, object]:
    """Wait for a known site's victim-list presentation without bypassing a gate."""
    timeout_ms = int(profile.get("ready_timeout_ms", 0) or 0)
    if timeout_ms <= 0:
        return {"ready": True, "waited_ms": 0, "reason": "no site-specific wait"}
    blocked_text = tuple(str(value).lower() for value in profile.get("blocked_text", ()))
    terminal_text = tuple(
        dict.fromkeys(
            (
                *GENERIC_TERMINAL_PAGE_TEXT,
                *(str(value).lower() for value in profile.get("terminal_text", ())),
            )
        )
    )
    required_text_any = tuple(str(value).lower() for value in profile.get("required_text_any", ()))
    min_body_chars = int(profile.get("min_body_chars", 0) or 0)
    require_no_busy = bool(profile.get("require_no_busy_indicator", False))
    candidate_selector = str(profile.get("candidate_selector", ""))
    min_candidate_count = int(profile.get("min_candidate_count", 0) or 0)
    started = time.monotonic()
    deadline = started + timeout_ms / 1000
    last_reason = "content not ready"
    while True:
        try:
            state = await site_readiness_state(page)
        except Exception as error:
            last_reason = f"waiting for navigation to settle ({type(error).__name__})"
            if time.monotonic() >= deadline:
                return {
                    "ready": False,
                    "waited_ms": round((time.monotonic() - started) * 1000),
                    "reason": last_reason,
                }
            await page.wait_for_timeout(500)
            continue
        text = str(state.get("text", ""))
        terminal = next((value for value in terminal_text if value in text), "")
        if terminal:
            return {
                "ready": False,
                "waited_ms": round((time.monotonic() - started) * 1000),
                "reason": f"terminal presentation contains {terminal!r}",
            }
        blocking = next((value for value in blocked_text if value in text), "")
        enough_text = int(state.get("text_length", 0)) >= min_body_chars
        no_busy = not require_no_busy or not bool(state.get("busy"))
        required_present = not required_text_any or any(
            value in text for value in required_text_any
        )
        candidate_count = 0
        if candidate_selector:
            try:
                candidate_count = int(await page.locator(candidate_selector).count())
            except Exception:
                candidate_count = 0
        enough_candidates = candidate_count >= min_candidate_count
        if not blocking and enough_text and no_busy and enough_candidates and required_present:
            return {
                "ready": True,
                "waited_ms": round((time.monotonic() - started) * 1000),
                "reason": "victim-list presentation ready",
            }
        if blocking:
            last_reason = f"waiting for {blocking!r} to clear"
        elif not enough_text:
            last_reason = f"waiting for at least {min_body_chars} visible characters"
        elif not enough_candidates:
            last_reason = f"waiting for at least {min_candidate_count} victim-list items"
        elif not required_present:
            last_reason = "waiting for an expected victim-list marker"
        else:
            last_reason = "waiting for loading indicator to clear"
        if time.monotonic() >= deadline:
            return {
                "ready": False,
                "waited_ms": round((time.monotonic() - started) * 1000),
                "reason": last_reason,
            }
        await page.wait_for_timeout(500)


async def click_screen_entry_gate(page, target_host: str, required_text: str) -> dict | None:
    """Perform one trusted pointer click after validating an exact entry phrase."""
    candidate = await page.evaluate(
        r"""
        ({ targetHost, requiredText }) => {
          const normalize = (value) => (value || '').replace(/\s+/g, ' ').trim().toLowerCase();
          const marker = normalize(requiredText);
          if (!marker || !normalize(document.body?.innerText || '').includes(marker)) return null;
          const visible = (element) => {
            const style = getComputedStyle(element);
            const rect = element.getBoundingClientRect();
            return rect.width > 0 && rect.height > 0 && style.visibility !== 'hidden'
              && style.display !== 'none' && Number(style.opacity || '1') > 0;
          };
          const safe = (element) => {
            if (!element || !visible(element) || element.closest('form')) return false;
            if (element.matches('input, textarea, select, option, [contenteditable="true"]')) return false;
            if (element.hasAttribute('download') || element.hasAttribute('formaction')) return false;
            const href = element.getAttribute('href');
            if (href) {
              try {
                const url = new URL(href, location.href);
                if (!['http:', 'https:'].includes(url.protocol) || url.hostname !== targetHost) return false;
              } catch (_error) {
                return false;
              }
            }
            return true;
          };
          const centre = document.elementFromPoint(innerWidth / 2, innerHeight / 2);
          const interactive = centre?.closest('a, button, [role="button"], [onclick]');
          const labelled = Array.from(document.querySelectorAll('a, button, [role="button"], [onclick]'))
            .find((element) => normalize(element.getAttribute('aria-label') || element.textContent || '').includes(marker));
          const candidate = interactive || labelled || centre;
          if (!safe(candidate)) return null;
          const rect = candidate.getBoundingClientRect();
          return {
            x: Math.max(1, Math.min(innerWidth - 1, rect.left + rect.width / 2)),
            y: Math.max(1, Math.min(innerHeight - 1, rect.top + rect.height / 2)),
            before_url: location.href,
          };
        }
        """,
        {"targetHost": target_host, "requiredText": required_text},
    )
    if not candidate:
        return None
    await page.mouse.click(float(candidate["x"]), float(candidate["y"]))
    return {
        "kind": "site_entry",
        "label": required_text,
        "before_url": str(candidate["before_url"]),
    }


async def navigate_to_capture_target(page, url: str, settings: Settings, profile: dict) -> int:
    """Retry only transient Tor navigation failures with a bounded site profile."""
    attempts = max(1, min(3, int(profile.get("navigation_attempts", 1) or 1)))
    delay_ms = max(1_000, min(15_000, int(profile.get("navigation_retry_delay_ms", 3_000))))
    transient = (
        "ERR_SOCKS_CONNECTION_FAILED",
        "ERR_TIMED_OUT",
        "ERR_CONNECTION_RESET",
        "ERR_CONNECTION_CLOSED",
    )
    for attempt in range(1, attempts + 1):
        try:
            await page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=settings.capture_timeout_seconds * 1000,
            )
            return attempt
        except Exception as error:
            if attempt >= attempts or not any(marker in str(error) for marker in transient):
                raise
            await page.wait_for_timeout(delay_ms)
    return attempts


async def page_state_fingerprint(page) -> str:
    state = await page.evaluate(
        r"""
        (() => {
          const text = (document.body?.innerText || '').replace(/\s+/g, ' ').trim();
          const height = Math.max(document.body?.scrollHeight || 0, document.documentElement.scrollHeight || 0);
          const selectedTabs = Array.from(document.querySelectorAll('[role="tab"][aria-selected="true"]'))
            .map((element) => (element.getAttribute('aria-label') || element.textContent || '').replace(/\s+/g, ' ').trim())
            .join('|');
          return `${location.href}\n${height}\n${selectedTabs}\n${text.length}\n${text.slice(-4000)}`;
        })()
        """
    )
    return hashlib.sha256(str(state).encode("utf-8", errors="replace")).hexdigest()


async def selected_tab_label(page) -> str:
    return str(
        await page.evaluate(
            r"""
            (() => {
              const element = document.querySelector('[role="tab"][aria-selected="true"]');
              return (element?.getAttribute('aria-label') || element?.textContent || '').replace(/\s+/g, ' ').trim();
            })()
            """
        )
        or ""
    )


async def click_read_only_control(
    page,
    kind: str,
    target_host: str,
    *,
    excluded_labels: list[str] | None = None,
    requested_label: str = "",
) -> dict | None:
    """Click one narrowly classified, visible, non-form control.

    The network route remains authoritative: even a misleading control cannot
    issue a mutation or leave the exact onion origin.
    """
    return await page.evaluate(
        r"""
        ({ kind, targetHost, entryLabels, loadMoreLabels, nextLabels, excludedLabels, requestedLabel }) => {
          const normalize = (value) => (value || '').replace(/\s+/g, ' ').trim().toLowerCase();
          const excluded = new Set(excludedLabels.map(normalize));
          const labelFor = (element) => normalize(element.getAttribute('aria-label') || element.textContent || '');
          const visible = (element) => {
            const style = getComputedStyle(element);
            const rect = element.getBoundingClientRect();
            return rect.width > 0 && rect.height > 0 && style.visibility !== 'hidden'
              && style.display !== 'none' && Number(style.opacity || '1') > 0;
          };
          const safe = (element) => {
            if (!visible(element) || element.closest('form')) return false;
            if (element.matches('input, textarea, select, option, [contenteditable="true"]')) return false;
            if (element.hasAttribute('download') || element.hasAttribute('formaction')) return false;
            if (element.matches(':disabled, [aria-disabled="true"]')) return false;
            const href = element.getAttribute('href');
            if (href) {
              try {
                const url = new URL(href, location.href);
                if (!['http:', 'https:'].includes(url.protocol) || url.hostname !== targetHost) return false;
              } catch (_error) {
                return false;
              }
            }
            return true;
          };
          const elements = Array.from(document.querySelectorAll('a, button, [role="button"], [role="tab"]'));
          const candidate = elements.find((element) => {
            if (!safe(element)) return false;
            const label = labelFor(element);
            if (!label || excluded.has(label)) return false;
            const rel = normalize(element.getAttribute('rel'));
            if (kind === 'entry') return entryLabels.includes(label);
            if (kind === 'load_more') return loadMoreLabels.includes(label);
            if (kind === 'next') return nextLabels.includes(label) || rel.split(/\s+/).includes('next');
            if (kind === 'named') return label === normalize(requestedLabel);
            if (kind === 'tab') {
              const panelId = element.getAttribute('aria-controls');
              return element.getAttribute('role') === 'tab'
                && element.getAttribute('aria-selected') !== 'true'
                && Boolean(panelId && document.getElementById(panelId));
            }
            if (kind === 'tab_named') {
              return element.getAttribute('role') === 'tab' && label === normalize(requestedLabel);
            }
            return false;
          });
          if (!candidate) return null;
          const label = labelFor(candidate);
          const beforeUrl = location.href;
          candidate.scrollIntoView({ block: 'center', inline: 'center' });
          candidate.click();
          return { kind, label, before_url: beforeUrl };
        }
        """,
        {
            "kind": kind,
            "targetHost": target_host,
            "entryLabels": list(ENTRY_LABELS),
            "loadMoreLabels": list(LOAD_MORE_LABELS),
            "nextLabels": list(NEXT_PAGE_LABELS),
            "excludedLabels": excluded_labels or [],
            "requestedLabel": requested_label,
        },
    )


async def settle_after_interaction(page, delay_ms: int) -> None:
    await page.wait_for_timeout(max(250, delay_ms))
    try:
        await page.wait_for_load_state("domcontentloaded", timeout=5_000)
    except Exception as error:
        if type(error).__name__ != "TimeoutError":
            raise


async def content_height_before_heading(page, heading_text: str, fallback: int) -> int:
    """Bound evidence before an exact later-page heading such as Contact.

    This does not mutate the page. It prevents unrelated forms and footer content
    from being preserved after the victim list has already been captured.
    """
    if not heading_text:
        return fallback
    try:
        result = await page.evaluate(
            r"""
            (wanted) => {
              const normalize = (value) => (value || '').replace(/\s+/g, ' ').trim().toLowerCase();
              const minimumTop = Math.max(innerHeight * 0.75, 640);
              const candidates = Array.from(document.body?.querySelectorAll('*') || [])
                .filter((element) => normalize(element.textContent) === normalize(wanted))
                .map((element) => element.getBoundingClientRect().top + window.scrollY)
                .filter((top) => top > minimumTop)
                .sort((left, right) => left - right);
              if (!candidates.length) return 0;
              const top = candidates[0];
              return Math.max(0, Math.floor(top - 48));
            }
            """,
            heading_text,
        )
        return min(fallback, int(result)) if int(result or 0) > 0 else fallback
    except Exception:
        return fallback


async def content_text_before_heading(page, heading_text: str, fallback: str) -> str:
    """Exclude an unrelated late-page section from extracted evidence text."""
    if not heading_text:
        return fallback
    try:
        result = await page.evaluate(
            r"""
            (wanted) => {
              const normalize = (value) => (value || '').replace(/\s+/g, ' ').trim().toLowerCase();
              const minimumTop = Math.max(innerHeight * 0.75, 640);
              const candidates = Array.from(document.body?.querySelectorAll('*') || [])
                .map((element) => ({
                  element,
                  top: element.getBoundingClientRect().top + window.scrollY,
                }))
                .filter(({ element, top }) => top > minimumTop
                  && normalize(element.textContent) === normalize(wanted))
                .sort((left, right) => left.top - right.top);
              if (!candidates.length || !document.body) return '';
              const range = document.createRange();
              range.selectNodeContents(document.body);
              range.setEndBefore(candidates[0].element);
              return range.toString();
            }
            """,
            heading_text,
        )
        return str(result) if str(result or "").strip() else fallback
    except Exception:
        return fallback


async def capture_interactive_evidence(
    page,
    first_path: Path,
    settings: Settings,
    controls: dict[str, int],
    target_host: str,
    group_name: str = "",
    previous_anchors: list[str] | None = None,
    target_text: str = "",
) -> tuple[dict, str, list[Path], list[dict]]:
    """Collect bounded evidence across scroll, expansion, tabs, and pagination."""
    actions: list[dict] = []
    texts: list[str] = []
    paths: list[Path] = []
    total_scrolls = 0
    total_height = 0
    all_stable = True
    pagination_seen = False
    budget_exhausted = False
    state_count = 0
    page_count = 0
    delay_ms = controls.get("capture_scroll_delay_ms", settings.capture_scroll_delay_ms)
    profile = capture_site_profile(group_name)
    previous_anchors = previous_anchors or []
    victim_match_found = False
    stop_reason = ""
    max_pagination_pages = min(
        MAX_PAGINATION_PAGES,
        max(
            1,
            int(profile.get("max_pagination_pages", MAX_PAGINATION_PAGES) or MAX_PAGINATION_PAGES),
        ),
    )
    post_click_wait_ms = int(profile.get("post_click_wait_ms", delay_ms) or delay_ms)

    if await wait_for_visual_ready(page):
        screen_gate_text = str(profile.get("screen_gate_text", ""))
        if screen_gate_text:
            before = await page_state_fingerprint(page)
            gate = await click_screen_entry_gate(page, target_host, screen_gate_text)
            if gate:
                await settle_after_interaction(page, post_click_wait_ms)
                gate["changed"] = before != await page_state_fingerprint(page)
                actions.append(gate)
        before = await page_state_fingerprint(page)
        entry = await click_read_only_control(page, "entry", target_host)
        if entry:
            await settle_after_interaction(page, post_click_wait_ms)
            entry["changed"] = before != await page_state_fingerprint(page)
            actions.append(entry)
        for label in profile.get("navigation_labels", ()):
            if len(actions) >= MAX_INTERACTION_ACTIONS:
                budget_exhausted = True
                break
            before = await page_state_fingerprint(page)
            navigation = await click_read_only_control(
                page, "named", target_host, requested_label=str(label)
            )
            if not navigation:
                continue
            navigation["kind"] = "site_navigation"
            await settle_after_interaction(page, post_click_wait_ms)
            navigation["changed"] = before != await page_state_fingerprint(page)
            actions.append(navigation)

    readiness = await wait_for_site_ready(page, profile)
    if int(readiness.get("waited_ms", 0)) > 0:
        actions.append(
            {
                "kind": "site_wait",
                "label": f"{int(readiness['waited_ms'])} ms: {readiness['reason']}",
                "changed": bool(readiness.get("ready")),
            }
        )
    if not bool(readiness.get("ready")) and bool(profile.get("reject_if_not_ready")):
        raise RuntimeError(
            f"Victim list did not become capture-ready: {readiness.get('reason', 'presentation unavailable')}"
        )

    async def record_state(label: str) -> str:
        nonlocal \
            state_count, \
            total_scrolls, \
            total_height, \
            all_stable, \
            budget_exhausted, \
            victim_match_found
        if state_count >= MAX_CAPTURE_STATES or len(paths) >= MAX_REVIEW_SEGMENTS:
            budget_exhausted = True
            return "interaction_limit"
        metrics = await scroll_until_stable(page, settings, controls)
        total_scrolls += int(metrics["scroll_count"])
        total_height += int(metrics["page_height"])
        all_stable = all_stable and metrics["coverage_status"] == "stable"
        try:
            body_text = await page.locator("body").inner_text(
                timeout=settings.capture_timeout_seconds * 1000
            )
        except Exception:
            body_text = ""
        body_text = await content_text_before_heading(
            page,
            str(profile.get("stop_before_heading", "")),
            body_text,
        )
        normalized_body = normalized_capture_text(body_text)
        target_normalized = " ".join(target_text.casefold().split())
        if target_normalized and target_normalized in normalized_body:
            victim_match_found = True
        continuity = continuity_analysis(
            body_text,
            previous_anchors,
            pagination_detected=page_count > 1,
            coverage_status=str(metrics["coverage_status"]),
        )
        state_count += 1
        texts.append(f"--- Capture state {state_count}: {label} ---\n{body_text}")
        review_height = await content_height_before_heading(
            page,
            str(profile.get("stop_before_heading", "")),
            int(metrics["page_height"]),
        )
        remaining = MAX_REVIEW_SEGMENTS - len(paths)
        new_paths = await capture_review_pages(
            page,
            first_path,
            review_height,
            settings,
            controls,
            start_page_number=len(paths) + 1,
            max_segments=remaining,
        )
        paths.extend(new_paths)
        expected_segments = len(
            review_page_ranges(
                min(review_height, controls["capture_max_page_height"]),
                controls["capture_segment_height"],
            )
        )
        if len(new_paths) < expected_segments:
            budget_exhausted = True
        if victim_match_found:
            return "victim_found"
        # A focused evidence request must keep looking for the named victim.
        # Incremental scheduled captures may stop as soon as they overlap the
        # prior capture, but that shortcut could otherwise hide an older
        # victim selected by an analyst.
        if (
            not target_normalized
            and previous_anchors
            and continuity["continuity_status"] == "matched"
        ):
            return "previous_anchor_found"
        return ""

    seen_pages: set[str] = set()
    while page_count < max_pagination_pages and len(actions) < MAX_INTERACTION_ACTIONS:
        fingerprint = await page_state_fingerprint(page)
        if fingerprint in seen_pages:
            break
        seen_pages.add(fingerprint)
        page_count += 1

        for _ in range(MAX_LOAD_MORE_CLICKS):
            if len(actions) >= MAX_INTERACTION_ACTIONS:
                budget_exhausted = True
                break
            before = await page_state_fingerprint(page)
            action = await click_read_only_control(page, "load_more", target_host)
            if not action:
                break
            await settle_after_interaction(page, delay_ms)
            after = await page_state_fingerprint(page)
            action["changed"] = before != after
            actions.append(action)
            pagination_seen = True
            if before == after:
                break

        stop_reason = await record_state(f"page {page_count}")
        if stop_reason:
            break
        if budget_exhausted:
            break

        original_tab = await selected_tab_label(page)
        clicked_tabs: list[str] = [original_tab] if original_tab else []
        tab_was_clicked = False
        for _ in range(MAX_READ_ONLY_TABS):
            if len(actions) >= MAX_INTERACTION_ACTIONS or state_count >= MAX_CAPTURE_STATES:
                budget_exhausted = True
                break
            before = await page_state_fingerprint(page)
            action = await click_read_only_control(
                page, "tab", target_host, excluded_labels=clicked_tabs
            )
            if not action:
                break
            clicked_tabs.append(str(action["label"]))
            tab_was_clicked = True
            await settle_after_interaction(page, delay_ms)
            after = await page_state_fingerprint(page)
            action["changed"] = before != after
            actions.append(action)
            if before != after:
                stop_reason = await record_state(f"page {page_count}, tab {action['label']}")
                if stop_reason:
                    break
            if budget_exhausted:
                break
        if stop_reason:
            break
        if original_tab and tab_was_clicked and not budget_exhausted:
            restore = await click_read_only_control(
                page, "tab_named", target_host, requested_label=original_tab
            )
            if restore:
                await settle_after_interaction(page, delay_ms)
                restore["kind"] = "tab_restore"
                restore["changed"] = True
                actions.append(restore)

        pagination_seen = pagination_seen or await pagination_control_detected(page)
        if budget_exhausted or len(actions) >= MAX_INTERACTION_ACTIONS:
            budget_exhausted = True
            break
        before = await page_state_fingerprint(page)
        next_action = await click_read_only_control(page, "next", target_host)
        if not next_action:
            break
        pagination_seen = True
        await settle_after_interaction(page, delay_ms)
        after = await page_state_fingerprint(page)
        next_action["changed"] = before != after
        actions.append(next_action)
        if before == after:
            break

    if page_count >= max_pagination_pages and await pagination_control_detected(page):
        budget_exhausted = True
    coverage_status = stop_reason or (
        "interaction_limit" if budget_exhausted else ("stable" if all_stable else "scroll_limit")
    )
    return (
        {
            "scroll_count": total_scrolls,
            "page_height": total_height,
            "capture_truncated": budget_exhausted or not all_stable,
            "coverage_status": coverage_status,
            "pagination_detected": pagination_seen,
            "victim_match_found": victim_match_found,
        },
        "\n\n".join(texts),
        paths,
        actions,
    )


async def run_capture_job(
    coordinator: CaptureWorkerAPIClient, settings: Settings, job: dict
) -> None:
    actor_dir, screenshot_path = evidence_path(settings, job)
    text_path = screenshot_path.with_name(re.sub(r"_p001\.png$", ".txt", screenshot_path.name))
    screenshot_paths: list[Path] = []
    browser = None
    opsec_passed = False
    blocked_requests = 0
    blocked_popups = 0
    blocked_downloads = 0
    context = await coordinator.job_context(str(job["id"]), str(job["target_id"]))
    previous = context["previous"]
    controls = context["controls"]
    previous_anchors = previous["anchor_lines"] or anchor_candidates(
        previous["text"], ignored_values=[str(job["group_name"])]
    )
    try:
        host = validate_capture_host(str(job["fqdn"]))
        await tor_socks_preflight(settings.tor_proxy)
        opsec_passed = True
        try:
            from playwright.async_api import async_playwright
        except ImportError as error:
            raise RuntimeError(
                "Playwright is missing; rerun setup-kali.sh --prepare-capture"
            ) from error

        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(**browser_launch_options(settings))
            context = await browser.new_context(
                viewport={
                    "width": 1440,
                    "height": controls["capture_segment_height"],
                },
                accept_downloads=False,
                service_workers="block",
                locale="en-US",
                timezone_id="UTC",
                permissions=[],
                user_agent=chromium_user_agent(browser.version),
            )
            await context.clear_permissions()

            async def isolate_request(route) -> None:
                nonlocal blocked_requests
                if request_allowed_for_target(route.request.url, host, route.request.method):
                    await route.continue_()
                else:
                    blocked_requests += 1
                    await route.abort("blockedbyclient")

            async def close_popup(popup) -> None:
                nonlocal blocked_popups
                blocked_popups += 1
                await popup.close()

            async def cancel_download(download) -> None:
                nonlocal blocked_downloads
                blocked_downloads += 1
                await download.cancel()

            async def block_websocket(websocket_route) -> None:
                nonlocal blocked_requests
                blocked_requests += 1
                await websocket_route.close()

            await context.route("**/*", isolate_request)
            await context.route_web_socket("**/*", block_websocket)
            page = await context.new_page()
            page.on("popup", lambda popup: asyncio.create_task(close_popup(popup)))
            page.on("dialog", lambda dialog: asyncio.create_task(dialog.dismiss()))
            page.on("download", lambda download: asyncio.create_task(cancel_download(download)))
            page.set_default_timeout(settings.capture_timeout_seconds * 1000)
            profile = capture_site_profile(str(job["group_name"]))
            navigation_attempt = await navigate_to_capture_target(
                page, f"http://{host}/", settings, profile
            )
            actor_dir.mkdir(parents=True, exist_ok=True)
            actor_dir.chmod(0o750)
            metrics, dom_text, screenshot_paths, actions = await capture_interactive_evidence(
                page,
                screenshot_path,
                settings,
                controls,
                host,
                str(job["group_name"]),
                previous_anchors,
                str(job.get("victim_name", "")),
            )
            if navigation_attempt > 1:
                actions.insert(
                    0,
                    {
                        "kind": "navigation_retry",
                        "label": f"target reached on attempt {navigation_attempt}",
                        "changed": True,
                    },
                )
            if actions:
                audit_lines = [
                    f"{index}. {action['kind']}: {action['label']} "
                    f"({'content changed' if action.get('changed') else 'no observed change'})"
                    for index, action in enumerate(actions, start=1)
                ]
                dom_text = f"{dom_text}\n\n--- Read-only interaction audit ---\n" + "\n".join(
                    audit_lines
                )
            metrics["css_blur_element_count"] = await css_blur_element_count(page)
            for captured_path in screenshot_paths:
                captured_path.chmod(0o640)
            await context.close()
            await browser.close()
            browser = None

        normalized_dom = normalized_capture_text(dom_text)
        should_ocr = settings.ocr_configured and (
            settings.capture_ocr_mode == "always" or len(normalized_dom) < 500
        )
        ocr_text = ""
        top_ocr_text = ""
        ocr_page_texts: list[str] = []
        ocr_failed = False
        if should_ocr:
            ocr_pages: list[str] = []
            for page_number, path in enumerate(screenshot_paths, start=1):
                try:
                    page_text = await tesseract_ocr(path, settings)
                    ocr_page_texts.append(page_text)
                    if page_text:
                        if page_number == 1:
                            top_ocr_text = page_text
                        ocr_pages.append(f"--- Review page {page_number} ---\n{page_text}")
                except RuntimeError:
                    ocr_page_texts.append("")
                    ocr_failed = True
            ocr_text = "\n\n".join(ocr_pages)
        if ocr_text and settings.capture_ocr_mode == "always" and normalized_dom:
            extracted_text = f"{dom_text}\n\n--- Local OCR ---\n{ocr_text}"
            extraction_method = "dom+ocr"
        elif ocr_text:
            extracted_text = ocr_text
            extraction_method = "ocr"
        elif normalized_dom:
            extracted_text = dom_text
            extraction_method = "dom_ocr_failed" if ocr_failed else "dom"
        else:
            extracted_text = ""
            extraction_method = "ocr_failed" if ocr_failed else "none"
        extracted_text = extracted_text[:5_000_000]
        rejection_reason = capture_evidence_rejection_reason(extracted_text)
        if rejection_reason:
            raise RuntimeError(rejection_reason)
        text_path.write_text(extracted_text, encoding="utf-8")
        text_path.chmod(0o640)
        text_analysis = analyze_capture_text(extracted_text, previous["text"])
        ignored_anchor_values = [str(job["group_name"])]
        previous_anchors = previous["anchor_lines"] or anchor_candidates(
            previous["text"], ignored_values=ignored_anchor_values
        )
        continuity_text = ocr_text or dom_text
        continuity = continuity_analysis(
            continuity_text,
            previous_anchors,
            pagination_detected=bool(metrics["pagination_detected"]),
            coverage_status=str(metrics["coverage_status"]),
        )
        continuity["continuity_page"] = next(
            (
                page_number
                for page_number, page_text in enumerate(ocr_page_texts, start=1)
                if continuity_analysis(
                    page_text,
                    previous_anchors,
                    pagination_detected=False,
                    coverage_status="stable",
                )["continuity_status"]
                == "matched"
            ),
            0,
        )
        anchors = anchor_candidates(top_ocr_text or dom_text, ignored_values=ignored_anchor_values)
        capture_hasher = hashlib.sha256()
        for path in screenshot_paths:
            capture_hasher.update(path.read_bytes())
        digest = capture_hasher.hexdigest()
        await coordinator.complete_capture_job(
            str(job["id"]),
            screenshot_path,
            digest,
            screenshot_paths=screenshot_paths,
            anchor_lines=anchors,
            **continuity,
            text_path=text_path,
            extraction_method=extraction_method,
            duplicate_of_job_id=previous["id"] if text_analysis["duplicate"] else "",
            **metrics,
            opsec_status="passed",
            tor_preflight_passed=True,
            blocked_request_count=blocked_requests,
            blocked_popup_count=blocked_popups,
            blocked_download_count=blocked_downloads,
            opsec_controls=list(OPSEC_CONTROLS),
            **{
                key: text_analysis[key]
                for key in (
                    "text_sha256",
                    "detected_statuses",
                    "status_changed",
                    "added_line_count",
                    "removed_line_count",
                )
            },
        )
    except asyncio.CancelledError:
        if browser is not None:
            await browser.close()
        for path in screenshot_paths:
            path.unlink(missing_ok=True)
        text_path.unlink(missing_ok=True)
        remove_empty_capture_directory(actor_dir, settings.capture_dir)
        await coordinator.fail_capture_job(
            str(job["id"]),
            "Capture interrupted because the worker stopped",
            opsec_status="passed" if opsec_passed else "failed",
            tor_preflight_passed=opsec_passed,
            blocked_request_count=blocked_requests,
            blocked_popup_count=blocked_popups,
            blocked_download_count=blocked_downloads,
            opsec_controls=list(OPSEC_CONTROLS),
        )
        raise
    except Exception as error:  # Worker must record a terminal job state and continue.
        if browser is not None:
            await browser.close()
        for path in screenshot_paths:
            path.unlink(missing_ok=True)
        text_path.unlink(missing_ok=True)
        remove_empty_capture_directory(actor_dir, settings.capture_dir)
        await coordinator.fail_capture_job(
            str(job["id"]),
            str(error),
            opsec_status="passed" if opsec_passed else "failed",
            tor_preflight_passed=opsec_passed,
            blocked_request_count=blocked_requests,
            blocked_popup_count=blocked_popups,
            blocked_download_count=blocked_downloads,
            opsec_controls=list(OPSEC_CONTROLS),
        )


async def capture_worker_heartbeat_loop(coordinator: CaptureWorkerAPIClient) -> None:
    while True:
        try:
            await coordinator.heartbeat()
        except Exception as error:
            # The job loop independently retries the authenticated local API.
            LOGGER.warning("Capture worker heartbeat failed: %s", type(error).__name__)
        await asyncio.sleep(5)


async def capture_worker_loop(coordinator: CaptureWorkerAPIClient, settings: Settings) -> None:
    while True:
        try:
            await coordinator.requeue_interrupted_capture_jobs()
            while True:
                job = await coordinator.claim_next_capture_job()
                if job is None:
                    await asyncio.sleep(3)
                    continue
                await run_capture_job(coordinator, settings, job)
        except asyncio.CancelledError:
            raise
        except Exception:
            # Reconnect and recover any reservation left by a control-plane outage.
            await asyncio.sleep(5)
