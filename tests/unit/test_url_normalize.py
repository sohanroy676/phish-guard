import pytest

from phishguard.core.url.normalize import UnsupportedURL, normalize_url


def test_roadmap_example_refangs_and_lowercases():
    u = normalize_url("hxxps://Secure-PayPa1[.]com/Login")
    assert (u.scheme, u.host, u.path) == ("https", "secure-paypa1.com", "/Login")


@pytest.mark.parametrize(
    "bad",
    [
        "ftp://example.com",
        "ftp://example.com/file",
        "javascript:alert(1)",
        "data:text/html,<b>x</b>",
        "file:///etc/passwd",
        "mailto:a@b.com",
        "",
        "   ",
        "http://",
        "https:///path",
        "http://exa mple.com",
        "http://a.com/\x00",
        "http://" + "a" * 3000 + ".com",
        "http://[::1",
        "http://example.com:99999",
    ],
)
def test_unsupported_inputs_raise(bad):
    with pytest.raises(UnsupportedURL):
        normalize_url(bad)


@pytest.mark.parametrize("bad", [None, 123, b"http://a.com", ["http://a.com"]])
def test_non_string_raises_unsupported(bad):
    with pytest.raises(UnsupportedURL):
        normalize_url(bad)


def test_bare_host_defaults_to_http():
    assert normalize_url("example.com/x").scheme == "http"
    assert normalize_url("example.com:8080").port == 8080


def test_case_trailing_dot_and_mixed_fang():
    u = normalize_url("HXXPS://WWW.Example(.)COM./a")
    assert (u.scheme, u.host) == ("https", "www.example.com")
    assert u.subdomain == "www" and u.registrable == "example.com"


def test_userinfo_is_flagged_and_not_the_host():
    u = normalize_url("http://paypal.com@evil.example.org/x")
    assert u.host == "evil.example.org" and u.has_userinfo


def test_idn_becomes_punycode():
    assert normalize_url("http://bücher.example/").host == "xn--bcher-kva.example"


def test_idempotent_on_its_own_output():
    u = normalize_url("hxxp://A[.]B.co[.]uk/p?q=1")
    again = normalize_url(f"{u.scheme}://{u.host}{u.path}?{u.query}")
    assert again == u


def test_query_kept_and_multi_part_suffix():
    u = normalize_url("https://a.b.example.co.uk/p?x=1&y=2")
    assert u.query == "x=1&y=2" and u.suffix == "co.uk" and u.domain == "example"


def test_unknown_suffix_does_not_crash():
    u = normalize_url("http://localhost/")
    assert u.host == "localhost"
