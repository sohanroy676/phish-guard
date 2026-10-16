import pandas as pd

from phishguard.training.audit import compute_audit, render_markdown


def test_audit_counts(synthetic_raw):
    stats = compute_audit(synthetic_raw)
    assert stats["rows"] == len(synthetic_raw)
    assert stats["phishing"] + stats["legitimate"] == stats["rows"]
    assert stats["unsupported_urls"] == 1
    assert stats["exact_duplicate_urls"] >= 1
    assert stats["conflicting_texts"] == 1
    assert stats["phishing_stats"]["https_rate"] < 0.05
    assert stats["legitimate_stats"]["https_rate"] > 0.9


def test_audit_warns_about_scheme_gap_and_recommends_excluding_is_https(synthetic_raw):
    stats = compute_audit(synthetic_raw)
    assert any("is_https" in w for w in stats["warnings"])


def test_audit_warns_when_phishing_outnumbers_legitimate():
    raw = pd.DataFrame(
        {
            "URL": [f"http://a{i}.xyz/x" for i in range(5)] + ["https://ok.com/"],
            "label": [0] * 5 + [1],
        }
    ).assign(y=lambda d: 1 - d["label"])
    assert any("flipped" in w for w in compute_audit(raw)["warnings"])


def test_audit_markdown_contains_sections(synthetic_raw):
    md = render_markdown(compute_audit(synthetic_raw), "abc123", "data/raw/x.csv")
    for text in ("# URL data audit", "abc123", "Class counts", "https rate"):
        assert text in md
