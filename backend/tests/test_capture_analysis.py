from ransom_monitor.capture_analysis import (
    analyze_capture_text,
    anchor_candidates,
    continuity_analysis,
    normalized_capture_text,
)


def test_capture_analysis_detects_duplicate_and_status_signals():
    previous = "New victim\nAcme Holdings\nData published"
    current = "  NEW   VICTIM \nAcme Holdings\nData published  "

    result = analyze_capture_text(current, previous)

    assert result["duplicate"] is True
    assert result["detected_statuses"] == ["listed", "published"]
    assert result["status_changed"] is False
    assert result["added_line_count"] == 0
    assert result["removed_line_count"] == 0
    assert result["text_sha256"]


def test_capture_analysis_reports_changed_lines_and_status():
    result = analyze_capture_text(
        "Countdown\nNew victim\nExample Ltd",
        "Data published\nOld Example",
    )

    assert result["duplicate"] is False
    assert result["status_changed"] is True
    assert result["detected_statuses"] == ["listed", "countdown"]
    assert result["added_line_count"] == 3
    assert result["removed_line_count"] == 2


def test_normalized_capture_text_drops_noise_and_caps_line_length():
    text = "\n  Useful   victim name  \nxx\n" + ("a" * 501)
    assert normalized_capture_text(text) == "useful victim name"


def test_ocr_anchor_continuity_finds_previous_victim_with_minor_error():
    previous_anchors = anchor_candidates(
        "Acme Industrial Holdings\nLeaked size 200 Gb\nExample description"
    )
    result = continuity_analysis(
        "New Company\nAcme lndustrial Holdings\nOther content",
        previous_anchors,
        pagination_detected=False,
        coverage_status="stable",
    )

    assert result["continuity_status"] == "matched"
    assert result["continuity_anchor"] == "acme industrial holdings"
    assert result["more_content_suspected"] is False


def test_anchor_candidates_ignore_actor_brand_and_navigation():
    assert anchor_candidates(
        "CHAOS\nHome\nspectrumchemical.com\nLeaked size 139 Gb",
        ignored_values=["Chaos"],
    ) == ["spectrumchemical.com"]


def test_missing_anchor_and_pagination_suspects_more_content():
    result = continuity_analysis(
        "Only new victims are visible",
        ["previous victim limited"],
        pagination_detected=True,
        coverage_status="stable",
    )

    assert result["continuity_status"] == "missing"
    assert result["more_content_suspected"] is True
