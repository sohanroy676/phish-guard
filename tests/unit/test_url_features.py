import math

import pytest

from phishguard.core.url.features import FEATURE_NAMES, feature_vector, url_features

INPUTS = [
    "https://example.com",
    "http://192.168.0.1:8080/a/b?c=d",
    "hxxp://user:pw@evil[.]xyz//a//b?x=1&y=2&z=3",
    "http://bücher.example/ü",
    "https://" + "a." * 40 + "com/" + "x" * 1500,
    "bit.ly/abc123",
    "http://localhost",
    "http://paypal.com.verify-account.xyz/login",
]


def test_feature_names_fixed_and_unique():
    assert len(FEATURE_NAMES) == 30
    assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES)


@pytest.mark.parametrize("url", INPUTS)
def test_same_keys_order_and_finite(url):
    f = url_features(url)
    assert tuple(f) == FEATURE_NAMES
    assert all(isinstance(v, float) and math.isfinite(v) for v in f.values())
    assert len(feature_vector(url)) == len(FEATURE_NAMES)


def test_deterministic():
    assert url_features(INPUTS[2]) == url_features(INPUTS[2])


def test_known_values():
    f = url_features("https://www.example.com/a/b?x=1&y=2")
    assert f["is_https"] == 1 and f["has_ip_host"] == 0
    assert f["subdomain_count"] == 1 and f["slash_count_path"] == 2
    assert f["param_count"] == 2 and f["tld_len"] == 3


def test_ip_userinfo_port_flags():
    f = url_features("http://a@10.0.0.1:8080/")
    assert f["has_ip_host"] == 1 and f["has_userinfo"] == 1 and f["non_default_port"] == 1
    assert url_features("https://example.com:443/")["non_default_port"] == 0


def test_brand_features():
    evil = url_features("http://paypal.com.verify-account.xyz/")
    real = url_features("https://www.paypal.com/signin")
    assert evil["brand_in_subdomain"] == 1 and evil["suspicious_tld"] == 1
    assert real["brand_in_subdomain"] == 0 and real["brand_in_path"] == 0


def test_shortener_and_free_hosting():
    assert url_features("https://bit.ly/abc123")["is_shortener"] == 1
    assert url_features("https://foo.netlify.app/")["is_free_hosting"] == 1
    assert url_features("https://example.com/")["is_shortener"] == 0


def test_invalid_input_raises_not_garbage():
    from phishguard.core.url.normalize import UnsupportedURL

    with pytest.raises(UnsupportedURL):
        url_features("ftp://example.com")
