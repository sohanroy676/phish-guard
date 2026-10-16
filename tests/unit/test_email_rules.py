import pytest

from phishguard.core.email.parse import from_fields, parse_raw
from phishguard.core.email.rules import run_rules


def mail(headers: str = "", body: str = "hello", html: bool = False) -> str:
    base = "From: Alice <alice@good.com>\nSubject: Hi\n" + headers
    if html:
        base += "Content-Type: text/html\n"
    return base + "\n" + body


def ids(raw: str, **kw) -> list[str]:
    return [h.rule_id for h in run_rules(parse_raw(raw), **kw)]


def test_topmost_auth_failure_fires():
    raw = mail("Authentication-Results: mx.example; spf=fail; dkim=pass; dmarc=fail\n")
    hits = run_rules(parse_raw(raw))
    assert [h.rule_id for h in hits] == ["auth_fail"]
    assert hits[0].severity == "high" and "DMARC" in hits[0].message and "SPF" in hits[0].message


def test_auth_failure_in_a_lower_header_does_not_fire():
    raw = mail(
        "Authentication-Results: mx.example; spf=pass; dkim=pass; dmarc=pass\n"
        "Authentication-Results: relay.example; spf=fail\n"
    )
    assert ids(raw) == []


def test_auth_failure_after_an_unrelated_header_and_passing_top_one_is_ignored():
    raw = mail(
        "Authentication-Results: a; spf=pass\nReceived: x\nAuthentication-Results: b; dmarc=fail\n"
    )
    assert "auth_fail" not in ids(raw)


@pytest.mark.parametrize("value", ["spf=pass", "spf=softfail", "spf=neutral", "dkim=none"])
def test_non_fail_results_stay_quiet(value):
    assert ids(mail(f"Authentication-Results: mx; {value}\n")) == []


def test_fail_word_in_another_header_is_ignored():
    assert ids(mail("X-Note: spf=fail\n")) == []


def test_reply_to_on_another_domain_warns():
    hits = run_rules(parse_raw(mail("Reply-To: help@other.org\n")))
    assert [(h.rule_id, h.severity) for h in hits] == [("reply_to_mismatch", "warn")]


def test_reply_to_on_the_same_registered_domain_is_fine():
    assert ids(mail("Reply-To: sales@mail.good.com\n")) == []


def test_display_name_with_brand_on_foreign_domain_fires():
    raw = "From: PayPal Support <help@evil.xyz>\nSubject: s\n\nbody"
    assert ids(raw) == ["display_name_mismatch"]


def test_display_name_brand_on_its_own_domain_is_fine():
    assert ids("From: PayPal <service@paypal.com>\nSubject: s\n\nbody") == []


def test_display_name_that_is_a_different_domain_fires():
    raw = 'From: "billing@paypal.com" <x@evil.xyz>\nSubject: s\n\nbody'
    assert ids(raw) == ["display_name_mismatch"]


def test_brand_inside_a_longer_own_domain_is_fine():
    assert ids("From: Yahoo Groups <noreply@yahoogroups.com>\nSubject: s\n\nbody") == []


def test_anchor_mismatch_fires():
    raw = mail(body='<a href="http://evil.xyz/x">www.paypal.com</a>', html=True)
    hits = run_rules(parse_raw(raw))
    assert [(h.rule_id, h.severity) for h in hits] == [("anchor_href_mismatch", "high")]


def test_anchor_matching_href_or_plain_words_is_fine():
    ok = '<a href="https://click.paypal.com/a">paypal.com</a><a href="http://e.xyz">Click here</a>'
    assert ids(mail(body=ok, html=True)) == []


def test_anchor_like_an_abbreviation_is_not_a_domain():
    assert ids(mail(body='<a href="http://e.example">e.g.</a>', html=True)) == []


def test_javascript_href_warns_and_mailto_is_ignored():
    body = '<a href="javascript:go()">x</a><a href="mailto:a@b.example">b.example</a>'
    assert ids(mail(body=body, html=True)) == ["script_link"]


def test_pasted_fields_never_fire_header_rules():
    body = "Authentication-Results: spf=fail; dmarc=fail\nReply-To: x@evil.xyz"
    parsed = from_fields("Subject", "PayPal <help@evil.xyz>", body)
    assert run_rules(parsed) == []


def test_plain_text_urls_have_no_anchor_to_mismatch():
    parsed = from_fields("s", "a@b.example", "see http://evil.xyz and www.paypal.com")
    assert run_rules(parsed) == []


def test_headers_flag_off_runs_body_rules_only():
    raw = mail(
        "Authentication-Results: mx; spf=fail\n",
        body='<a href="http://evil.xyz">www.paypal.com</a>',
        html=True,
    )
    assert ids(raw, headers=False) == ["anchor_href_mismatch"]


def test_every_hit_is_well_formed():
    raw = mail(
        "Authentication-Results: mx; spf=fail\nReply-To: a@evil.xyz\n",
        body='<a href="javascript:x()">y</a><a href="http://e.xyz">www.paypal.com</a>',
        html=True,
    )
    hits = run_rules(parse_raw(raw))
    assert len(hits) == 4
    for h in hits:
        assert h.severity in {"high", "warn"} and h.message.endswith(".")


def test_hostile_addresses_do_not_crash():
    raw = "From: x <@@@>\nReply-To: <>\nSubject: s\n\nbody"
    assert ids(raw) == []
