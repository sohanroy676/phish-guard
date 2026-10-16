import socket

import pytest

from phishguard.core.email.features import (
    FEATURE_NAMES,
    anchor_mismatches,
    email_features,
    feature_matrix,
    link_domain,
    model_text,
)
from phishguard.core.email.parse import Link, from_fields, parse_raw
from phishguard.core.lists import load_list


def fields(body: str, subject: str = "s"):
    return from_fields(subject, "a@b.example", body)


def test_feature_names_are_unique_and_match_dict_order():
    assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES)
    assert tuple(email_features(fields("hi"))) == FEATURE_NAMES


def test_empty_matrix_has_the_right_width():
    assert feature_matrix([]).shape == (0, len(FEATURE_NAMES))
    assert feature_matrix([fields("a"), fields("b")]).shape == (2, len(FEATURE_NAMES))


def test_empty_email_gives_all_zero_counts_without_dividing_by_zero():
    values = email_features(fields("", subject=""))
    assert all(v == 0.0 for v in values.values())


def test_link_and_text_features():
    body = "URGENT! Verify your account: http://bit.ly/x http://1.2.3.4/p pay $50"
    f = email_features(fields(body))
    assert f["n_links"] == 2 and f["n_link_domains"] == 2
    assert f["shortener_links"] == 1 and f["ip_link_ratio"] == 0.5
    assert f["money_tokens"] == 1 and f["exclaim_count"] == 1
    assert f["urgency_words"] >= 3 and f["upper_ratio"] > 0.1


def test_script_and_html_features():
    raw = "From: a@b.example\nSubject: s\nContent-Type: text/html\n\n<a href='javascript:x()'>y</a>"
    f = email_features(parse_raw(raw))
    assert f["script_links"] == 1 and f["has_html"] == 1.0


@pytest.mark.parametrize(
    "href", ["javascript:x()", "mailto:a@b.com", "/relative", "", "ftp://x.com"]
)
def test_non_web_hrefs_have_no_domain(href):
    assert link_domain(href) is None


def test_link_domain_is_the_registered_domain():
    assert link_domain("https://a.b.paypal.co.uk/x") == "paypal.co.uk"
    assert link_domain("www.example.com/x") == "example.com"


def test_anchor_mismatch_detection():
    links = (
        Link("http://evil.xyz", "www.paypal.com"),
        Link("http://paypal.com/a", "https://www.paypal.com/login"),
        Link("http://evil.xyz", "Click here"),
        Link("javascript:x()", "paypal.com"),
    )
    assert anchor_mismatches(links) == [links[0]]


def test_model_text_is_masked_lowercased_and_stoplisted():
    parsed = fields("Pay $500 to john@x.com via http://a.b/c. Enron said March 2024.", "URGENT")
    text = model_text(parsed)
    assert text.startswith("urgent")
    for artefact in ("enron", "march", "2024", "john", "500", "a.b"):
        assert artefact not in text
    assert "moneytoken" in text and "emailtoken" in text and "urltoken" in text


def test_stoplist_matches_whole_words_and_phrases_only():
    text = model_text(fields("Decision on corporate matters, from Yahoo Groups. Marching band."))
    assert "corporate" in text and "marching" in text
    assert "yahoo" not in text and "groups" not in text


@pytest.mark.parametrize("name", ["artefact_stoplist", "email_keywords"])
def test_email_lists_are_not_empty(name):
    assert load_list(name)


def test_email_features_make_no_network_calls(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network used")

    monkeypatch.setattr(socket.socket, "connect", boom)
    email_features(fields("see http://a.example/x"))
