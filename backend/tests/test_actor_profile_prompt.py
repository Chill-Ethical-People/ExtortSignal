from ransom_monitor.actor_profile_prompt import (
    ACTOR_PROFILE_PROMPT_VERSION,
    ACTOR_PROFILE_REFRESH_SYSTEM_PROMPT,
)


def test_actor_profile_prompt_matches_professional_profile_overlay() -> None:
    assert ACTOR_PROFILE_PROMPT_VERSION in ACTOR_PROFILE_REFRESH_SYSTEM_PROMPT
    for field in (
        "summary",
        "motivation",
        "targeting",
        "capabilities",
        "campaign_history",
        "key_judgments",
        "priority_actions",
        "hunt_hypotheses",
        "field_evidence",
        "confidence",
        "caveats",
    ):
        assert field in ACTOR_PROFILE_REFRESH_SYSTEM_PROMPT

    assert "Do not use model memory" in ACTOR_PROFILE_REFRESH_SYSTEM_PROMPT
    assert "Do not return or attempt to alter those fields" in ACTOR_PROFILE_REFRESH_SYSTEM_PROMPT
    assert "unverified public victim-list allegations" in ACTOR_PROFILE_REFRESH_SYSTEM_PROMPT
    assert "retained OSINT evidence IDs" in ACTOR_PROFILE_REFRESH_SYSTEM_PROMPT
