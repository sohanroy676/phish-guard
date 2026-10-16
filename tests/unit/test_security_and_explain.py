import pytest

from phishguard.app import security
from phishguard.app.config import Settings, check_secrets
from phishguard.core.explain import lr_reasons
from phishguard.core.url.normalize import normalize_url


def test_defang_host_hides_scheme_and_dots_and_drops_path():
    u = normalize_url("https://Login.Example.com/reset?token=abc")
    assert security.defang_host(u) == "hxxps://login[.]example[.]com"
    assert security.defang_host(normalize_url("http://a.com/x")) == "hxxp://a[.]com"


def test_input_hmac_is_stable_keyed_and_hides_the_url():
    u = normalize_url("https://example.com/a?b=1")
    first = security.input_hmac("pepper-pepper-pepper", u)
    assert first == security.input_hmac("pepper-pepper-pepper", u)
    assert first != security.input_hmac("other-pepper-other!", u)
    assert "example" not in first and len(first) == 64


def test_input_hmac_treats_equivalent_urls_alike_and_different_paths_apart():
    a = security.input_hmac("p" * 16, normalize_url("HTTPS://Example.com:443/a"))
    b = security.input_hmac("p" * 16, normalize_url("https://example.com/a"))
    c = security.input_hmac("p" * 16, normalize_url("https://example.com/b"))
    assert a == b != c


def test_csrf_ok_rejects_missing_and_wrong():
    assert security.csrf_ok("abc", "abc")
    assert not security.csrf_ok("abc", None)
    assert not security.csrf_ok("abc", "")
    assert not security.csrf_ok("abc", "abd")


@pytest.mark.parametrize("secret", ["", "change-me", "short"])
def test_check_secrets_rejects_missing_or_placeholder(secret):
    good = "g" * 20
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        check_secrets(Settings(_env_file=None, secret_key=secret, hmac_pepper=good))
    with pytest.raises(RuntimeError, match="HMAC_PEPPER"):
        check_secrets(Settings(_env_file=None, secret_key=good, hmac_pepper=secret))


def test_check_secrets_accepts_real_values():
    check_secrets(Settings(_env_file=None, secret_key="k" * 20, hmac_pepper="p" * 20))


def test_lr_reasons_name_host_fragments_without_duplicates(client):
    scorer = client.app.state.url_scorer
    reasons = lr_reasons(scorer.model, "secure-login-paypal7.xyz")
    assert 1 <= len(reasons) <= 4
    assert all(r.startswith("The host contains") for r in reasons)
    assert len(set(reasons)) == len(reasons)


def test_lr_reasons_are_empty_for_a_clean_host(client):
    scorer = client.app.state.url_scorer
    assert lr_reasons(scorer.model, "www.shop3.com") == []
