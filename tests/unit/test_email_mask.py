import pytest

from phishguard.core.email.mask import mask_text


def test_roadmap_example():
    assert (
        mask_text("Pay $500 to john@x.com via http://a.b/c")
        == "Pay moneytoken to emailtoken via urltoken"
    )


@pytest.mark.parametrize(
    "text",
    ["$1,234.50", "€ 20", "£99", "USD 500", "500 dollars", "20.5 EUR", "¥1000"],
)
def test_amounts_become_money(text):
    assert mask_text(f"send {text} now") == "send moneytoken now"


def test_punctuation_after_an_amount_is_kept():
    assert mask_text("send $5, then 10 dollars.") == "send moneytoken, then moneytoken."


def test_other_numbers_and_years_become_numtoken():
    assert mask_text("Invoice 4521 dated 2024, call 555-1234") == (
        "Invoice numtoken dated numtoken, call numtoken-numtoken"
    )


def test_no_digits_survive():
    masked = mask_text("a1b2 http://x.example/9?id=77 v3.1 $5 7,000")
    assert not any(ch.isdigit() for ch in masked)


def test_url_trailing_punctuation_stays_in_text():
    assert mask_text("see http://a.example/x.") == "see urltoken."
    assert mask_text("(www.a.example)") == "(urltoken)"


def test_url_with_embedded_address_is_one_token():
    assert mask_text("http://a.example/?to=bob@x.com") == "urltoken"


def test_empty_and_unicode_text():
    assert mask_text("") == ""
    assert mask_text("héllo wörld ✓") == "héllo wörld ✓"


def test_multiple_values_are_all_masked():
    assert mask_text("a@b.co, c@d.org") == "emailtoken, emailtoken"


def test_masking_is_idempotent():
    once = mask_text("Pay $500 to john@x.com via http://a.b/c 2024")
    assert mask_text(once) == once
