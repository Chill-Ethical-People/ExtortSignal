import asyncio
from pathlib import Path

import pytest
import ransom_monitor.capture_worker as capture_worker_module

from ransom_monitor.capture_worker import (
    browser_launch_options,
    capture_evidence_rejection_reason,
    capture_interactive_evidence,
    capture_site_profile,
    capture_review_pages,
    content_height_before_heading,
    content_text_before_heading,
    evidence_path,
    numbered_screenshot_path,
    request_allowed_for_target,
    review_page_ranges,
    safe_actor_directory,
    click_screen_entry_gate,
    navigate_to_capture_target,
    scroll_until_stable,
    tor_socks_preflight,
    validate_onion_host,
    validate_tor_proxy,
    wait_for_site_ready,
    chromium_user_agent,
)
from ransom_monitor.config import Settings


def settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path,
        database_path=tmp_path / "db.sqlite3",
        raw_dir=tmp_path / "raw",
        capture_dir=tmp_path / "captures",
        frontend_dist=tmp_path / "dist",
        capture_worker_token="x" * 32,
        capture_worker_enabled=True,
        chromium_path="/usr/bin/chromium",
        capture_scroll_delay_ms=250,
    )


def test_browser_is_tor_routed_without_loopback_bypass(tmp_path):
    options = browser_launch_options(settings(tmp_path))
    assert options["proxy"] == {"server": "socks5://127.0.0.1:9050"}
    assert "--proxy-bypass-list=<-loopback>" in options["args"]
    assert "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1" in options["args"]
    assert "--no-sandbox" not in options["args"]
    assert "--dns-prefetch-disable" in options["args"]
    assert "--force-webrtc-ip-handling-policy=disable_non_proxied_udp" in options["args"]
    assert validate_onion_host(f"{'a' * 56}.onion") == f"{'a' * 56}.onion"


def test_browser_user_agent_matches_chromium_without_headless_marker():
    user_agent = chromium_user_agent("Chromium 140.0.7339.80")
    assert "Chrome/140.0.7339.80" in user_agent
    assert "HeadlessChrome" not in user_agent
    assert user_agent.startswith("Mozilla/5.0 (X11; Linux x86_64)")

    with pytest.raises(ValueError):
        chromium_user_agent("unknown")


def test_actor_specific_capture_profiles_are_bounded_and_read_only():
    gentlemen = capture_site_profile("thegentlemen")
    assert gentlemen["ready_timeout_ms"] == 60_000
    assert "verifying your browser" in gentlemen["blocked_text"]

    lockbit = capture_site_profile("LockBit5")
    assert lockbit["screen_gate_text"] == "click anywhere to enter"
    assert lockbit["post_click_wait_ms"] == 12_000

    assert capture_site_profile("Lynx")["navigation_labels"] == ("leaks",)
    kazu = capture_site_profile("Kazu")
    assert kazu["required_text_any"] == ("recent posts",)
    assert kazu["navigation_labels"] == ("recent posts",)
    assert kazu["require_no_busy_indicator"] is True
    assert kazu["min_candidate_count"] == 1
    assert kazu["max_pagination_pages"] == 10
    assert capture_site_profile("INC Ransom")["require_no_busy_indicator"] is True
    assert capture_site_profile("ShinyHunters")["screen_gate_text"] == ("click anywhere to enter")
    assert capture_site_profile("Cl0p")["ready_timeout_ms"] == 180_000
    assert capture_site_profile("unknown actor") == {}

    for actor in (
        "akira",
        "chaos",
        "clop",
        "deadlock",
        "direwolf",
        "dragonforce",
        "gunra",
        "thegentlemen",
        "lockbit5",
        "lynx",
        "kazu",
        "incransom",
        "medusalocker",
        "safepay",
        "shinyhunters",
        "spacebears",
    ):
        profile = capture_site_profile(actor)
        assert int(profile["ready_timeout_ms"]) <= 180_000
        assert profile["reject_if_not_ready"] is True
        assert not profile.get("typing")
        assert not profile.get("authentication")


def test_site_readiness_waits_for_gate_text_and_busy_indicator_to_clear():
    class FakeReadinessPage:
        def __init__(self):
            self.states = [
                {"text": "verifying your browser", "text_length": 22, "busy": True},
                {"text": "victim " * 60, "text_length": 420, "busy": False},
            ]
            self.index = 0

        async def evaluate(self, _script: str):
            state = self.states[min(self.index, len(self.states) - 1)]
            self.index += 1
            return state

        async def wait_for_timeout(self, _milliseconds: int):
            return None

    result = asyncio.run(
        wait_for_site_ready(
            FakeReadinessPage(),
            {
                "ready_timeout_ms": 1_000,
                "blocked_text": ("verifying your browser",),
                "min_body_chars": 240,
                "require_no_busy_indicator": True,
            },
        )
    )

    assert result["ready"] is True
    assert result["reason"] == "victim-list presentation ready"


def test_site_readiness_rejects_terminal_and_requires_actor_marker():
    class FakeReadinessPage:
        def __init__(self, states):
            self.states = states
            self.index = 0

        async def evaluate(self, _script: str):
            state = self.states[min(self.index, len(self.states) - 1)]
            self.index += 1
            return state

        async def wait_for_timeout(self, _milliseconds: int):
            return None

    terminal = asyncio.run(
        wait_for_site_ready(
            FakeReadinessPage(
                [{"text": "502 bad gateway nginx", "text_length": 21, "busy": False}]
            ),
            {"ready_timeout_ms": 1_000, "min_body_chars": 10},
        )
    )
    assert terminal["ready"] is False
    assert "terminal presentation" in terminal["reason"]

    marker = asyncio.run(
        wait_for_site_ready(
            FakeReadinessPage(
                [
                    {"text": "generic portal text " * 20, "text_length": 400, "busy": False},
                    {
                        "text": "victim cards include leaked size 10 gb",
                        "text_length": 400,
                        "busy": False,
                    },
                ]
            ),
            {
                "ready_timeout_ms": 1_000,
                "min_body_chars": 100,
                "required_text_any": ("leaked size",),
            },
        )
    )
    assert marker["ready"] is True


@pytest.mark.parametrize(
    ("text", "reason_fragment"),
    [
        ("--- Capture state 1: page 1 ---\n", "enough readable evidence"),
        ("502 Bad Gateway\nnginx", "upstream error page"),
        (
            "click anywhere to enter\nYou have been placed in a queue, awaiting forwarding to the platform.",
            "interstitial",
        ),
    ],
)
def test_capture_evidence_quality_rejects_false_successes(text, reason_fragment):
    assert reason_fragment in capture_evidence_rejection_reason(text)


def test_capture_evidence_quality_accepts_claim_material():
    text = "Published victim.example on 2026-07-26 with a company description and status."
    assert capture_evidence_rejection_reason(text) == ""


def test_evidence_can_stop_before_non_semantic_late_page_heading():
    class FakePage:
        def __init__(self):
            self.results = [32_000, "List of companies\nVictim One\nVictim Two"]

        async def evaluate(self, _script: str, _argument: str):
            return self.results.pop(0)

    page = FakePage()
    assert asyncio.run(content_height_before_heading(page, "contact", 35_000)) == 32_000
    assert asyncio.run(content_text_before_heading(page, "contact", "full page")) == (
        "List of companies\nVictim One\nVictim Two"
    )


def test_actor_readiness_runs_even_when_page_is_visually_blank(monkeypatch, tmp_path):
    async def no_visual_content(_page):
        return False

    async def not_ready(_page, _profile):
        return {
            "ready": False,
            "waited_ms": 30_000,
            "reason": "waiting for readable content",
        }

    monkeypatch.setattr(capture_worker_module, "wait_for_visual_ready", no_visual_content)
    monkeypatch.setattr(capture_worker_module, "wait_for_site_ready", not_ready)

    with pytest.raises(RuntimeError, match="did not become capture-ready"):
        asyncio.run(
            capture_interactive_evidence(
                object(),
                tmp_path / "gunra_p001.png",
                settings(tmp_path),
                {},
                f"{'a' * 56}.onion",
                "gunra",
            )
        )


def test_screen_entry_gate_uses_a_trusted_pointer_click():
    class Mouse:
        def __init__(self):
            self.clicks = []

        async def click(self, x, y):
            self.clicks.append((x, y))

    class Page:
        def __init__(self):
            self.mouse = Mouse()

        async def evaluate(self, _script, _argument):
            return {"x": 720, "y": 700, "before_url": "http://fixture.onion/"}

    page = Page()
    result = asyncio.run(click_screen_entry_gate(page, "fixture.onion", "click anywhere to enter"))

    assert page.mouse.clicks == [(720.0, 700.0)]
    assert result["kind"] == "site_entry"


def test_transient_navigation_is_retried_within_profile(tmp_path):
    class Page:
        def __init__(self):
            self.calls = 0
            self.waits = []

        async def goto(self, *_args, **_kwargs):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("net::ERR_SOCKS_CONNECTION_FAILED")

        async def wait_for_timeout(self, milliseconds):
            self.waits.append(milliseconds)

    page = Page()
    attempt = asyncio.run(
        navigate_to_capture_target(
            page,
            "http://fixture.onion/",
            settings(tmp_path),
            {"navigation_attempts": 2, "navigation_retry_delay_ms": 1_500},
        )
    )

    assert attempt == 2
    assert page.calls == 2
    assert page.waits == [1_500]


@pytest.mark.parametrize(
    "host",
    ["example.com", "127.0.0.1", "http://example.onion", "bad name.onion"],
)
def test_capture_rejects_non_onion_targets(host):
    with pytest.raises(ValueError):
        validate_onion_host(host)


def test_tor_proxy_must_be_unauthenticated_loopback_socks5():
    assert validate_tor_proxy("socks5://127.0.0.1:9050") == ("127.0.0.1", 9050)
    assert validate_tor_proxy("socks5://[::1]:9150") == ("::1", 9150)
    for proxy in (
        "http://127.0.0.1:9050",
        "socks5://10.0.0.5:9050",
        "socks5://user:pass@127.0.0.1:9050",
        "socks5://127.0.0.1",
    ):
        with pytest.raises(ValueError, match="OPSEC gate failed"):
            validate_tor_proxy(proxy)


def test_browser_requests_are_confined_to_exact_onion_origin():
    host = f"{'a' * 56}.onion"
    assert request_allowed_for_target(f"http://{host}/", host)
    assert request_allowed_for_target(f"https://{host}/asset.js", host)
    assert request_allowed_for_target("data:image/png;base64,AA==", host)
    assert not request_allowed_for_target("https://example.com/tracker", host)
    assert not request_allowed_for_target(f"http://{'b' * 56}.onion/", host)
    assert not request_allowed_for_target("file:///etc/passwd", host)
    assert request_allowed_for_target(f"http://{host}/page/2", host, "HEAD")
    assert not request_allowed_for_target(f"http://{host}/search", host, "POST")
    assert not request_allowed_for_target(f"http://{host}/api", host, "PUT")


def test_tor_preflight_performs_only_local_socks_handshake():
    async def scenario():
        async def socks_handler(reader, writer):
            assert await reader.readexactly(3) == b"\x05\x01\x00"
            writer.write(b"\x05\x00")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(socks_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            await tor_socks_preflight(f"socks5://127.0.0.1:{port}")
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())


class FakePage:
    def __init__(self, heights: list[int]):
        self.heights = heights
        self.index = 0
        self.scroll_calls = 0

    async def evaluate(self, script: str):
        if script.startswith("Math.max"):
            value = self.heights[min(self.index, len(self.heights) - 1)]
            self.index += 1
            return value
        self.scroll_calls += 1
        return None

    async def wait_for_timeout(self, _milliseconds: int):
        return None


def test_scroll_until_height_stabilizes_after_lazy_loading(tmp_path):
    page = FakePage([1000, 2000, 2000, 3000, 3000, 3000, 3000, 3000, 3000])
    result = asyncio.run(scroll_until_stable(page, settings(tmp_path)))
    assert result["scroll_count"] >= 4
    assert result["page_height"] == 3000
    assert result["capture_truncated"] is False
    assert result["coverage_status"] == "stable"
    assert page.scroll_calls >= 2


def test_scroll_reports_height_limit_instead_of_claiming_complete(tmp_path):
    page = FakePage([1000, 2200, 2200])
    result = asyncio.run(
        scroll_until_stable(
            page,
            settings(tmp_path),
            {
                "capture_max_scrolls": 20,
                "capture_stable_passes": 3,
                "capture_scroll_delay_ms": 250,
                "capture_max_page_height": 2000,
            },
        )
    )

    assert result["coverage_status"] == "height_limit"
    assert result["capture_truncated"] is True


def test_evidence_path_uses_safe_actor_and_capture_time(tmp_path):
    configured = settings(tmp_path)
    actor_dir, screenshot = evidence_path(
        configured,
        {
            "id": "12345678-abcd",
            "group_name": "The Gentlemen / ../",
            "started_at": "2026-07-19T07:26:10+00:00",
        },
    )
    assert safe_actor_directory("The Gentlemen / ../") == "the-gentlemen"
    assert actor_dir == configured.capture_dir / "the-gentlemen"
    assert screenshot.parent == actor_dir
    assert screenshot.name.startswith("2026-07-19_")
    assert screenshot.name.endswith("_p001.png")
    assert screenshot.suffix == ".png"


def test_review_pages_are_numbered_and_overlap_boundaries(tmp_path):
    pages = review_page_ranges(3100, 1400)

    assert pages == [(0, 1400), (1320, 1400), (2640, 460)]
    first = tmp_path / "2026-07-19_12-00-00_HKT_p001.png"
    assert numbered_screenshot_path(first, 12).name.endswith("_p012.png")


class FakeCapturePage:
    def __init__(self):
        self.scroll_positions = []
        self.screenshots = []

    async def evaluate(self, script: str, argument=None):
        if argument is not None:
            self.scroll_positions.append(argument)
        return None

    async def wait_for_timeout(self, _milliseconds: int):
        return None

    async def screenshot(self, **kwargs):
        self.screenshots.append(kwargs)


def test_review_capture_scrolls_viewport_instead_of_using_fragile_page_clips(tmp_path):
    page = FakeCapturePage()
    first = tmp_path / "capture_p001.png"
    paths = asyncio.run(
        capture_review_pages(
            page,
            first,
            3100,
            settings(tmp_path),
            {"capture_max_page_height": 50000, "capture_segment_height": 1400},
        )
    )

    assert page.scroll_positions == [0, 1320, 2640]
    assert len(paths) == 3
    assert all(item["full_page"] is False for item in page.screenshots)
    assert all("clip" not in item for item in page.screenshots)


def test_review_capture_can_continue_numbering_and_obey_global_limit(tmp_path):
    page = FakeCapturePage()
    first = tmp_path / "capture_p001.png"
    paths = asyncio.run(
        capture_review_pages(
            page,
            first,
            5000,
            settings(tmp_path),
            {"capture_max_page_height": 5000, "capture_segment_height": 1000},
            start_page_number=7,
            max_segments=2,
        )
    )

    assert [path.name for path in paths] == ["capture_p007.png", "capture_p008.png"]
    assert len(page.screenshots) == 2
