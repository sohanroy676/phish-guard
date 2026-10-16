"""Mask URLs, addresses, amounts and numbers so the text model sees patterns, not values."""

import re

# Tokens are alphabetic on purpose: a word TF-IDF keeps them, a digit filter would not.
URL_TOKEN = "urltoken"
EMAIL_TOKEN = "emailtoken"
MONEY_TOKEN = "moneytoken"
NUM_TOKEN = "numtoken"

URL_RE = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"'\[\]]+""")
TRAILING_PUNCT = ".,;:!?)"
_EMAIL_RE = re.compile(r"(?i)[a-z0-9._%+\-]+@[a-z0-9\-]+(?:\.[a-z0-9\-]+)+")
_CURRENCY = r"(?:[$€£¥]|usd|eur|gbp)"
_AMOUNT = r"\d(?:[\d,]*\d)?(?:\.\d+)?"
_MONEY_RE = re.compile(
    rf"(?i)(?:{_CURRENCY}\s?{_AMOUNT}|{_AMOUNT}\s?(?:dollars?|euros?|pounds?|usd|eur|gbp)\b)"
)
_NUM_RE = re.compile(r"\d(?:[\d,.]*\d)?")


def _mask_url(match: re.Match) -> str:
    # Trailing sentence punctuation belongs to the text, not the link.
    url = match.group(0)
    stripped = url.rstrip(TRAILING_PUNCT)
    return URL_TOKEN + url[len(stripped) :]


def mask_text(text: str) -> str:
    text = URL_RE.sub(_mask_url, text)
    text = _EMAIL_RE.sub(EMAIL_TOKEN, text)
    text = _MONEY_RE.sub(MONEY_TOKEN, text)
    return _NUM_RE.sub(NUM_TOKEN, text)
