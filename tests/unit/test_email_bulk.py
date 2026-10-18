import pytest

from phishguard.core.email.bulk import BulkInfo, bulk_info, is_link_wrapper
from phishguard.core.email.parse import from_fields, parse_raw
from phishguard.core.risk import CANT_ASSESS, HIGH, LOW, SUSPICIOUS, email_decision
from phishguard.core.url.normalize import normalize_url
from phishguard.core.url.rules import RuleHit

AUTH_PASS = "Authentication-Results: mx.google.com; dmarc=pass (p=NONE) header.from=shop.com\n"


def mail(headers: str = "") -> str:
    return "From: Shop <news@shop.com>\nSubject: Sale\n" + headers + "\nhello"


@pytest.mark.parametrize(
    "header",
    [
        "List-Unsubscribe: <https://shop.com/u>\n",
        "List-Id: <news.shop.com>\n",
        "Precedence: bulk\n",
    ],
)
def test_bulk_markers(header):
    assert bulk_info(parse_raw(mail(header))).is_bulk


def test_plain_mail_and_pasted_fields_are_not_bulk():
    assert not bulk_info(parse_raw(mail("Precedence: first-class\n"))).is_bulk
    assert bulk_info(from_fields("s", "a@b.com", "List-Unsubscribe: x")) == BulkInfo()


def test_authenticated_needs_an_aligned_dmarc_pass_in_the_topmost_header():
    unsub = "List-Unsubscribe: <https://shop.com/u>\n"
    assert bulk_info(parse_raw(mail(unsub + AUTH_PASS))).authenticated
    subdomain = AUTH_PASS.replace("shop.com\n", "mail.shop.com\n")
    assert bulk_info(parse_raw(mail(unsub + subdomain))).authenticated
    for bad in (
        AUTH_PASS.replace("dmarc=pass", "dmarc=fail"),
        AUTH_PASS.replace("header.from=shop.com", "header.from=evilshop.com"),
        AUTH_PASS.replace("header.from=shop.com", "header.from=other.com"),
        "Authentication-Results: mx; dmarc=pass\n",  # no header.from to compare
    ):
        assert not bulk_info(parse_raw(mail(unsub + bad))).authenticated
    lower = "Authentication-Results: mx; dmarc=fail header.from=shop.com\n" + AUTH_PASS
    assert not bulk_info(parse_raw(mail(unsub + lower))).authenticated
    assert not bulk_info(parse_raw(mail(AUTH_PASS))).authenticated  # not bulk at all


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://bit.ly/abc", True),
        ("https://sub.list-manage.com/track/click?u=1", True),
        ("https://evil-list-manage.com/x", False),
        ("https://example.com/", False),
        ("https://twitter.com/x", False),
    ],
)
def test_is_link_wrapper(url, expected):
    assert is_link_wrapper(normalize_url(url)) is expected


BULK = BulkInfo(True, False)
BULK_AUTH = BulkInfo(True, True)
STRONG = [RuleHit("anchor_href_mismatch", "high", "x")]


def test_bulk_without_strong_rule_sets_model_warnings_aside():
    d = email_decision(HIGH, [SUSPICIOUS], [], BULK)
    assert (d.band, d.bulk_gated) == (CANT_ASSESS, True)


def test_a_high_link_still_counts_in_bulk_mail():
    assert email_decision(HIGH, [HIGH], [], BULK).band == HIGH


@pytest.mark.parametrize("rule", ["auth_fail", "display_name_mismatch", "anchor_href_mismatch"])
def test_strong_rule_keeps_the_warning_on_bulk_mail(rule):
    d = email_decision(HIGH, [], [RuleHit(rule, "high", "x")], BULK_AUTH)
    assert d.band == HIGH and not d.bulk_gated


def test_low_needs_an_authenticated_sender_in_bulk_mail():
    assert email_decision(LOW, [LOW], [], BULK).band == CANT_ASSESS
    assert email_decision(LOW, [LOW], [], BULK_AUTH).band == LOW
    assert email_decision(HIGH, [], [], BULK_AUTH).band == CANT_ASSESS  # auth never gives Low


def test_non_bulk_mail_is_unchanged():
    assert email_decision(HIGH, [], []).band == HIGH
    assert email_decision(LOW, [SUSPICIOUS], []).band == SUSPICIOUS
    assert email_decision(LOW, [], [], BulkInfo()).band == LOW
    assert email_decision(LOW, [], [], hidden_links=True).band == CANT_ASSESS


def test_hidden_links_do_not_block_low_in_authenticated_bulk_mail():
    assert email_decision(LOW, [], [], BULK_AUTH, hidden_links=True).band == LOW


def test_without_headers_a_text_only_high_is_capped_at_suspicious():
    assert email_decision(HIGH, [], [], headers_available=False).band == SUSPICIOUS
    assert email_decision(HIGH, [HIGH], [], headers_available=False).band == HIGH
    assert email_decision(HIGH, [], STRONG, headers_available=False).band == HIGH


# ADR 0010: links on the authenticated sender's own popular domain
@pytest.fixture
def popular(monkeypatch):
    from phishguard.core.email import bulk as bulk_module

    real = bulk_module.load_list
    monkeypatch.setattr(
        bulk_module,
        "load_list",
        lambda name: (
            frozenset({"shop.com", "evil-ok.com"}) if name == "popular_domains" else real(name)
        ),
    )


def owned(link: str, headers: str = AUTH_PASS) -> bool:
    from phishguard.core.email.bulk import is_sender_owned_link

    return is_sender_owned_link(normalize_url(link), bulk_info(parse_raw(mail(headers))))


def test_sender_owned_link_needs_everything(popular):
    assert owned("https://shop.com/deal")
    assert owned("https://track.shop.com/deal")  # same registered domain
    assert not owned("https://other.com/deal")  # not the sender's domain
    assert not owned("https://shop.com/deal", "")  # no authentication results
    fail = AUTH_PASS.replace("dmarc=pass", "dmarc=fail")
    assert not owned("https://shop.com/deal", fail)
    forged = AUTH_PASS.replace("header.from=shop.com", "header.from=evilshop.com")
    assert not owned("https://shop.com/deal", forged)


def test_sender_owned_link_not_for_unlisted_domain_or_pasted_fields(popular):
    from phishguard.core.email.bulk import is_sender_owned_link

    unlisted = AUTH_PASS.replace("shop.com", "unlisted.org")
    parsed = parse_raw(mail(unlisted).replace("news@shop.com", "news@unlisted.org"))
    assert not is_sender_owned_link(normalize_url("https://unlisted.org/x"), bulk_info(parsed))
    fields = from_fields("s", "news@shop.com", "body")
    assert not is_sender_owned_link(normalize_url("https://shop.com/x"), bulk_info(fields))


def test_sender_owned_link_with_a_url_rule_hit_still_counts(popular):
    # A userinfo trick on the sender's own domain must not be waved through.
    assert not owned("https://paypal.com@shop.com/login")


def test_shared_hosts_are_never_in_the_bundled_list():
    from phishguard.core.lists import load_list

    popular_list = load_list("popular_domains")
    assert "facebook.com" in popular_list
    for host in ("google.com", "web.app", "github.io", "sharepoint.com", "bit.ly"):
        assert host not in popular_list


def test_link_discount_reasons(popular):
    from phishguard.core.email.bulk import link_discount

    bulk = bulk_info(parse_raw(mail(AUTH_PASS)))
    assert link_discount(normalize_url("https://shop.com/a"), bulk) == "sender_owned"
    assert link_discount(normalize_url("https://bit.ly/abc"), bulk) == "wrapper"
    assert link_discount(normalize_url("https://other.com/a"), bulk) is None
