from ransom_monitor.matching import extract_domains, match_claim, normalize_name


def test_normalize_name_removes_legal_suffixes():
    assert normalize_name("Meridian Harbour Holdings Limited") == "meridian harbour"


def test_extract_domains():
    assert extract_domains("See https://www.example.org/report") == ["example.org"]


def test_exact_domain_match_is_critical():
    result = match_claim(
        {
            "title": "Meridian Harbour",
            "description": "Claim concerning meridianharbour.example",
            "domains": [],
        },
        {
            "canonical_name": "Meridian Harbour Group",
            "primary_domain": "meridianharbour.example",
            "aliases": [],
        },
    )
    assert result is not None
    assert result.score == 100
    assert result.severity == "critical"


def test_unrelated_company_does_not_match():
    assert (
        match_claim(
            {"title": "Rosenfeld Precision Works", "description": "", "domains": []},
            {
                "canonical_name": "Meridian Harbour Group",
                "primary_domain": "meridianharbour.example",
                "aliases": [],
            },
        )
        is None
    )


def test_related_company_domain_match_is_high_priority():
    result = match_claim(
        {
            "title": "Meridian Cloud Services",
            "description": "Claim concerning meridiancloud.example",
            "domains": ["meridiancloud.example"],
        },
        {
            "canonical_name": "Meridian Harbour Group",
            "primary_domain": "meridianharbour.example",
            "aliases": [],
            "related_entities": [
                {
                    "name": "Meridian Cloud Services",
                    "domain": "meridiancloud.example",
                    "relationship": "subsidiary",
                }
            ],
        },
    )
    assert result is not None
    assert result.score == 88
    assert result.severity == "high"
    assert "subsidiary domain" in result.reason


def test_client_keyword_match_is_sent_to_review_with_evidence():
    result = match_claim(
        {
            "title": "Actor publishes Northstar cold-chain documents",
            "description": "The allegation references the Blue Harpoon platform.",
            "domains": [],
        },
        {
            "canonical_name": "Unrelated Legal Name",
            "primary_domain": "unrelated.example",
            "aliases": [],
            "keywords": ["Blue Harpoon", "not present"],
        },
    )
    assert result is not None
    assert result.severity == "review"
    assert result.score == 42
    assert "Blue Harpoon" in result.reason
    assert "Blue Harpoon" in result.evidence
