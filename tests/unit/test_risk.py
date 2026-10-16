import re

import pytest

from phishguard.core.risk import (
    ADVICE,
    ADVISORY_FOOTER,
    CANT_ASSESS,
    HEADLINES,
    HIGH,
    LOW,
    SUSPICIOUS,
    assess,
    combine,
    model_band,
)
from phishguard.core.url.rules import RuleHit

HI = RuleHit("brand_impersonation", "high", "Mentions paypal but is not that site.")
WARN = RuleHit("excess_subdomains", "warn", "Unusually many subdomain levels.")
SHORT = RuleHit("shortener", "warn", "Shortened link: the real destination is hidden.")


@pytest.mark.parametrize(
    ("score", "band"),
    [(0.0, LOW), (0.299, LOW), (0.3, SUSPICIOUS), (0.599, SUSPICIOUS), (0.6, HIGH), (1.0, HIGH)],
)
def test_model_band_boundaries(score, band):
    assert model_band(score, t_high=0.6, t_low=0.3) == band


def test_high_rule_raises_low_to_suspicious():
    assert combine(LOW, [HI]) == SUSPICIOUS


def test_warn_rule_does_not_change_band():
    assert combine(LOW, [WARN]) == LOW


@pytest.mark.parametrize("band", [SUSPICIOUS, HIGH])
def test_rules_never_lower_a_band(band):
    assert combine(band, [WARN]) == band
    assert combine(band, [HI]) == band


@pytest.mark.parametrize("band", [LOW, SUSPICIOUS, HIGH])
def test_shortener_overrides_the_model_band(band):
    assert combine(band, [SHORT]) == CANT_ASSESS


def test_shortener_with_brand_in_path_is_suspicious():
    assert combine(LOW, [SHORT, HI]) == SUSPICIOUS
    assert combine(HIGH, [SHORT, HI]) == SUSPICIOUS


def test_no_rules_keeps_model_band():
    assert combine(LOW, []) == LOW


def test_wording_is_fixed_by_adr_0002():
    assert HEADLINES == {
        HIGH: "Likely phishing",
        SUSPICIOUS: "Suspicious: be careful",
        LOW: "No strong phishing signs found",
        CANT_ASSESS: "Can't assess",
    }


def test_the_word_safe_never_appears_and_no_percentages():
    texts = [*HEADLINES.values(), *ADVICE.values(), ADVISORY_FOOTER]
    for text in texts:
        assert not re.search(r"\bsafe\b", text, re.IGNORECASE)
        assert "%" not in text


def test_low_band_says_it_is_not_a_guarantee():
    assert "not a guarantee" in assess(0.0, 0.6, 0.3, []).advice


def test_assess_returns_footer_and_headline():
    risk = assess(0.9, 0.6, 0.3, [])
    assert (risk.band, risk.headline, risk.footer) == (HIGH, "Likely phishing", ADVISORY_FOOTER)
