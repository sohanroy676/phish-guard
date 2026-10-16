"""Turn a model score and rule hits into a risk band with fixed wording (ADR 0002, ADR 0005).

The wording lives only here. It never says "Safe" and never shows a score as a percentage.
"""

from collections.abc import Iterable
from dataclasses import dataclass

from phishguard.core.url.rules import RuleHit

HIGH = "high"
SUSPICIOUS = "suspicious"
LOW = "low"
CANT_ASSESS = "cant_assess"

HEADLINES = {
    HIGH: "Likely phishing",
    SUSPICIOUS: "Suspicious: be careful",
    LOW: "No strong phishing signs found",
    CANT_ASSESS: "Can't assess",
}

ADVICE = {
    HIGH: "Do not open this link or enter any details. If it came from a message, delete it.",
    SUSPICIOUS: "Be careful. Do not enter passwords or payment details until you have checked "
    "the sender another way.",
    LOW: "This is not a guarantee of safety. Stay careful with links you did not expect.",
    CANT_ASSESS: "The real destination is hidden, so this link cannot be assessed. "
    "Ask the sender for the full address instead.",
}

ADVISORY_FOOTER = (
    "PhishGuard is an advisory tool. It works offline and never opens the link, "
    "so it can be wrong. Treat it as a second opinion."
)


@dataclass(frozen=True)
class Risk:
    band: str
    headline: str
    advice: str
    footer: str


def model_band(score: float, t_high: float, t_low: float) -> str:
    if score >= t_high:
        return HIGH
    if score >= t_low:
        return SUSPICIOUS
    return LOW


def combine(band: str, hits: Iterable[RuleHit]) -> str:
    """Apply rules to a model band.

    Rules only raise a band, with one exception: for a shortened link the model sees just the
    shortener's own host, so its band says nothing about the hidden destination (ADR 0005).
    """
    hits = list(hits)
    high_rule = any(h.severity == "high" for h in hits)
    if any(h.rule_id == "shortener" for h in hits):
        return SUSPICIOUS if high_rule else CANT_ASSESS
    if band == LOW and high_rule:
        return SUSPICIOUS
    return band


def assess(score: float, t_high: float, t_low: float, hits: Iterable[RuleHit]) -> Risk:
    band = combine(model_band(score, t_high, t_low), hits)
    return Risk(band, HEADLINES[band], ADVICE[band], ADVISORY_FOOTER)
