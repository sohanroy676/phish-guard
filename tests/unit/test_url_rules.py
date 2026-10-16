import pytest

from phishguard.core.url.rules import run_rules


def ids(url):
    return [h.rule_id for h in run_rules(url)]


def test_shortener_fires():
    assert "shortener" in ids("https://bit.ly/abc123")


def test_brand_fires_on_roadmap_example():
    assert "brand_impersonation" in ids("http://paypal.com.verify-account.xyz/")


@pytest.mark.parametrize(
    "url",
    [
        "https://paypal.com",
        "https://www.paypal.com/signin",
        "https://github.com/x",
        "https://example.com",
    ],
)
def test_legit_hosts_stay_quiet(url):
    assert ids(url) == []


def test_brand_in_path_of_other_site_fires():
    assert "brand_impersonation" in ids("http://evil.example.org/paypal/login")


def test_ip_userinfo_punycode():
    assert "ip_host" in ids("http://203.0.113.5/x")
    assert "userinfo" in ids("http://paypal.com@evil.example.org/")
    assert "punycode" in ids("http://xn--pypal-4ve.com/")


def test_free_hosting_brand_and_subdomains_and_keywords():
    assert "free_hosting_brand" in ids("https://paypal-login.netlify.app/")
    assert "excess_subdomains" in ids("http://a.b.c.d.example.com/")
    assert "suspicious_keywords" in ids("http://example.com/login/verify/account")


def test_deterministic_order_and_fields():
    a = run_rules("http://paypal.com@evil.example.org/login/verify/account")
    assert a == run_rules("http://paypal.com@evil.example.org/login/verify/account")
    assert all(h.severity in {"high", "warn"} and h.message for h in a)
