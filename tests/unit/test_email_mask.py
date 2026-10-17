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


# --- sender mask context (ADR 0009) -------------------------------------------------------------

from phishguard.core.email.mask import BRAND_TOKEN, MaskContext  # noqa: E402
from phishguard.core.email.parse import from_fields  # noqa: E402


def ctx(addr="news@mail.acmeshop.co.uk", name="AcmeShop Deals"):
    return MaskContext.from_sender(addr, name)


def test_no_context_output_is_unchanged():
    text = "AcmeShop sale: Pay $500 to john@x.com via http://a.b/c 2024"
    assert mask_text(text, None) == mask_text(text)
    assert BRAND_TOKEN not in mask_text(text)


def test_brand_from_domain_label_and_display_name_is_hidden():
    out = mask_text("Thanks for shopping at AcmeShop! Deals from acmeshop.co.uk", ctx())
    assert "acmeshop" not in out.lower()
    assert out.count(BRAND_TOKEN) == 3


def test_brand_only_in_display_name():
    c = MaskContext.from_sender("billing@x-mailer.example", "Zorbo Telecom")
    out = mask_text("Your Zorbo Telecom bill; zorbo is great", c)
    assert "zorbo" not in out.lower() and "telecom" not in out.lower()


def test_brand_inside_a_longer_word_is_kept():
    out = mask_text("acmeshopper and preacmeshop and acmeshops", ctx())
    assert out == "acmeshopper and preacmeshop and acmeshops"


def test_possessive_and_punctuation_still_match():
    out = mask_text("(AcmeShop's) offer, AcmeShop.", ctx())
    assert out == f"({BRAND_TOKEN}'s) offer, {BRAND_TOKEN}."


@pytest.mark.parametrize("text", ["ACMESHOP", "acmeshop", "AcMeShOp", "ACMEshop DEALS"])
def test_case_tricks(text):
    assert "acmeshop" not in mask_text(text, ctx()).lower()


def test_subdomains_use_the_registered_domain_label():
    c = MaskContext.from_sender("a@deep.mail.news.bigcorp.com.au", "")
    assert mask_text("welcome to bigcorp", c) == f"welcome to {BRAND_TOKEN}"


def test_idn_and_punycode_are_both_hidden():
    c = MaskContext.from_sender("info@xn--bcher-kva.com", "")
    assert BRAND_TOKEN in mask_text("Willkommen bei bücher", c)
    assert BRAND_TOKEN in mask_text("see xn--bcher-kva", c)
    c2 = MaskContext.from_sender("info@bücher.com", "")
    assert BRAND_TOKEN in mask_text("Willkommen bei BÜCHER", c2)


def test_empty_sender_changes_nothing():
    text = "Pay $5 at acme 2024"
    assert mask_text(text, MaskContext.from_sender("", "")) == mask_text(text)
    assert mask_text(text, MaskContext.from_sender(None, None)) == mask_text(text)
    assert MaskContext().terms() == ()


def test_generic_and_short_names_are_not_masked():
    c = MaskContext.from_sender("noreply@ab.example", "The Support Team")
    text = "the support team will contact you"
    assert mask_text(text, c) == text


def test_context_masking_is_idempotent():
    once = mask_text("AcmeShop sent 12 offers from acmeshop.co.uk", ctx())
    assert mask_text(once, ctx()) == once


def test_regex_metacharacters_in_names_are_literal():
    c = MaskContext.from_sender("x@y.example", "A+B (Co.) [Shop]")
    assert mask_text("welcome", c) == "welcome"  # must not raise or match everything
    assert mask_text("visit A+B (Co.) [Shop] now", c) == f"visit {BRAND_TOKEN} now"


def test_model_text_with_context_drops_the_brand_and_without_does_not():
    from phishguard.core.email.features import model_text, sender_context

    parsed = from_fields(
        "AcmeShop weekly", "AcmeShop Deals <news@acmeshop.co.uk>", "Big sale today"
    )
    assert "acmeshop" in model_text(parsed)
    masked = model_text(parsed, sender_context(parsed))
    assert "acmeshop" not in masked and BRAND_TOKEN not in masked
