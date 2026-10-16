"""Pin raw model scores and bands for saved inputs, so a retrain without a version bump is caught.

The .joblib files are git-ignored, so these tests skip when a model is not trained locally.
When a model version changes, regenerate the file:
    python tests/golden/test_scores.py
"""

import json
from pathlib import Path

import pytest

from phishguard.core.email.parse import from_fields, parse_raw
from phishguard.core.email.scoring import load_email_scorer
from phishguard.core.registry import MODELS_DIR
from phishguard.core.risk import model_band
from phishguard.core.url.normalize import normalize_url
from phishguard.core.url.scoring import load_url_scorer

GOLDEN = Path(__file__).with_name("scores.json")
URL_VERSION, EMAIL_VERSION = "v2", "v1"
TOLERANCE = 1e-6

URLS = [
    "https://en.wikipedia.org/wiki/Phishing",
    "http://paypal.com.secure-login-verify.xyz/account/update",
    "http://192.168.0.1/login",
    "https://xn--pple-43d.com/signin",
]
RAW_EMAIL = (
    "From: Support <help@bank.example>\nTo: me@example.com\nSubject: Verify now\n"
    "Date: Mon, 1 Jan 2024 10:00:00 +0000\n\n"
    "Your account is suspended. Verify your password immediately.\n"
)
EMAILS = {
    "fields_phish": lambda: from_fields(
        "Urgent: account suspended", "x@evil.example", "Verify your password immediately."
    ),
    "fields_ham": lambda: from_fields(
        "Lunch", "a@b.example", "Meeting agenda for the project schedule, thanks."
    ),
    "raw_phish": lambda: parse_raw(RAW_EMAIL),
}

PRIMARY = {"url": "lr_char.joblib", "email": "lr_text.joblib"}


def _has(kind: str, version: str) -> bool:
    """The manifest is committed but the .joblib is git-ignored, so test the model file."""
    return (MODELS_DIR / kind / version / PRIMARY[kind]).is_file()


def compute(kinds=("url", "email")) -> dict:
    out: dict = {"url_version": URL_VERSION, "email_version": EMAIL_VERSION, "url": {}, "email": {}}
    if "url" in kinds and _has("url", URL_VERSION):
        s = load_url_scorer(URL_VERSION)
        for u in URLS:
            score = s.score(normalize_url(u))
            out["url"][u] = {
                "score": round(score, 6),
                "band": model_band(score, s.t_high, s.t_low),
            }
    if "email" in kinds and _has("email", EMAIL_VERSION):
        s = load_email_scorer(EMAIL_VERSION)
        for name, make in EMAILS.items():
            score = s.score(make())
            out["email"][name] = {
                "score": round(score, 6),
                "band": model_band(score, s.t_high, s.t_low),
            }
    return out


def _golden() -> dict:
    return json.loads(GOLDEN.read_text(encoding="utf-8"))


def _check(kind: str):
    golden, current = _golden(), compute((kind,))
    assert golden[f"{kind}_version"] == current[f"{kind}_version"]
    assert set(golden[kind]) == set(current[kind]), "golden inputs and computed inputs differ"
    for key, want in golden[kind].items():
        got = current[kind][key]
        assert got["band"] == want["band"], f"{key}: band changed without a version bump"
        assert got["score"] == pytest.approx(want["score"], abs=TOLERANCE), (
            f"{key}: score changed without a version bump"
        )


@pytest.mark.skipif(not _has("url", URL_VERSION), reason="real URL model not trained locally")
def test_url_scores_match_golden():
    _check("url")


@pytest.mark.skipif(not _has("email", EMAIL_VERSION), reason="real email model not trained locally")
def test_email_scores_match_golden():
    _check("email")


@pytest.mark.skipif(
    not (_has("url", URL_VERSION) and _has("email", EMAIL_VERSION)), reason="models not trained"
)
def test_golden_file_is_not_trivially_empty():
    g = _golden()
    assert len(g["url"]) == len(URLS) and len(g["email"]) == len(EMAILS)
    assert {v["band"] for v in g["url"].values()} - {"low"}, "golden has no flagged URL"


if __name__ == "__main__":
    GOLDEN.write_text(json.dumps(compute(), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {GOLDEN}")
