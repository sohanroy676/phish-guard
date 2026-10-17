"""Mask URLs, addresses, amounts and numbers so the text model sees patterns, not values.

An optional `MaskContext` (the sender's address, display name and domain) also hides the sender's
own name and brand, so a model cannot learn "this brand is legitimate" (ADR 0009). Without a
context the output is exactly what it was before the context existed.
"""

import re
from dataclasses import dataclass
from functools import cache

from phishguard.core.url.normalize import get_extractor

# Tokens are alphabetic on purpose: a word TF-IDF keeps them, a digit filter would not.
URL_TOKEN = "urltoken"
EMAIL_TOKEN = "emailtoken"
MONEY_TOKEN = "moneytoken"
NUM_TOKEN = "numtoken"
BRAND_TOKEN = "brandtoken"

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


# Words in a display name or address that say nothing about who the sender is.
_GENERIC_TERMS = frozenset(
    """the and for you your with from this that team support noreply reply mail email info news
    newsletter notification notifications service services customer care update updates alert
    alerts billing account accounts security help hello online store shop sales admin com org net
    inc llc ltd corp www will not are our new""".split()
)
_MIN_TERM = 3
_WORD_SPLIT_RE = re.compile(r"[^\w]+|_+")


def _unicode_host(host: str) -> str:
    try:
        return ".".join(
            label.encode("ascii").decode("idna") if label.startswith("xn--") else label
            for label in host.split(".")
        )
    except UnicodeError:
        return host


def _punycode(text: str) -> str | None:
    try:
        return text.encode("idna").decode("ascii")
    except UnicodeError:
        return None


@dataclass(frozen=True)
class MaskContext:
    """Who sent the message. Everything here is hidden from the text the model reads."""

    sender_addr: str = ""
    display_name: str = ""
    domain_label: str = ""  # e.g. "amazon" for mail.amazon.co.uk
    brand_words: tuple[str, ...] = ()

    @classmethod
    def from_sender(cls, addr: str | None, display_name: str | None) -> "MaskContext":
        addr = (addr or "").strip().lower()
        host = _unicode_host(addr.rsplit("@", 1)[1]) if "@" in addr else ""
        label = get_extractor()(host).domain if host else ""
        words = tuple(w for w in _WORD_SPLIT_RE.split((display_name or "").lower()) if w)
        return cls(addr, " ".join((display_name or "").split()), label, words)

    def terms(self) -> tuple[str, ...]:
        """Casefolded phrases to hide, longest first."""
        found: set[str] = set()
        host = _unicode_host(self.sender_addr.rsplit("@", 1)[1]) if "@" in self.sender_addr else ""
        registered = get_extractor()(host).top_domain_under_public_suffix if host else ""
        local = self.sender_addr.rsplit("@", 1)[0] if "@" in self.sender_addr else ""
        phrases = [self.sender_addr, self.display_name, registered, self.domain_label]
        phrases += [*self.brand_words, *_WORD_SPLIT_RE.split(local)]
        phrases += [*_WORD_SPLIT_RE.split(self.display_name)]
        for phrase in phrases:
            phrase = " ".join(phrase.lower().split())
            generic = all(w in _GENERIC_TERMS for w in _WORD_SPLIT_RE.split(phrase) if w)
            if len(phrase) < _MIN_TERM or phrase.isdigit() or generic:
                continue
            found.add(phrase)
            if (ascii_form := _punycode(phrase)) and ascii_form != phrase:
                found.add(ascii_form)
        return tuple(sorted(found, key=lambda t: (-len(t), t)))


@cache
def _context_re(terms: tuple[str, ...]) -> re.Pattern | None:
    if not terms:
        return None
    body = "|".join(r"\s+".join(re.escape(part) for part in t.split()) for t in terms)
    # Whole words only: "amazon" is hidden in "Amazon's" but not in "amazonian".
    return re.compile(rf"(?<!\w)(?:{body})(?!\w)", re.IGNORECASE)


def mask_text(text: str, ctx: MaskContext | None = None) -> str:
    text = URL_RE.sub(_mask_url, text)
    text = _EMAIL_RE.sub(EMAIL_TOKEN, text)
    if ctx is not None and (pattern := _context_re(ctx.terms())) is not None:
        text = pattern.sub(BRAND_TOKEN, text)
    text = _MONEY_RE.sub(MONEY_TOKEN, text)
    return _NUM_RE.sub(NUM_TOKEN, text)
