"""Email model inputs. Single source of truth for training and serving.

Everything here is header-independent, so pasted fields and uploaded files are scored alike.
"""

import math
import re
from functools import cache

import numpy as np

from phishguard.core.email.mask import (
    BRAND_TOKEN,
    MONEY_TOKEN,
    NUM_TOKEN,
    URL_TOKEN,
    MaskContext,
    mask_text,
)
from phishguard.core.email.parse import Link, ParsedEmail
from phishguard.core.lists import load_list
from phishguard.core.url.features import is_ip_host
from phishguard.core.url.normalize import normalize_url

FEATURE_NAMES: tuple[str, ...] = (
    "n_links",
    "n_link_domains",
    "ip_link_ratio",
    "shortener_links",
    "anchor_mismatch_count",
    "script_links",
    "has_html",
    "n_attachments",
    "log_text_len",
    "subject_len",
    "exclaim_count",
    "upper_ratio",
    "money_tokens",
    "urgency_words",
)

MODEL_TEXT_CHARS = 20_000  # the text model reads at most this much, in training and serving alike

# An anchor that is itself a domain or URL, e.g. "www.paypal.com" or "https://bank.com/login".
_ANCHOR_DOMAIN_RE = re.compile(r"^(?:https?://)?[^\s/:?#]+\.[^\s/:?#]+(?:[/:?#]\S*)?$")


def link_domain(href: str) -> str | None:
    """Registered domain of an http(s) or bare `www.` link, else None (mailto:, javascript:)."""
    href = href.strip()
    if not href.lower().startswith(("http://", "https://", "www.")):
        return None
    try:
        u = normalize_url(href)
    except ValueError:
        return None
    return u.registrable


def text_domain(anchor: str) -> str | None:
    anchor = anchor.strip().lower()
    if not _ANCHOR_DOMAIN_RE.match(anchor):
        return None
    if not anchor.startswith(("http://", "https://")):
        anchor = "http://" + anchor
    try:
        u = normalize_url(anchor)
    except ValueError:
        return None
    return u.registrable if u.suffix else None  # a known public suffix, so "e.g." is not a domain


def anchor_mismatches(links: tuple[Link, ...]) -> list[Link]:
    """Links whose visible text names one domain while the href goes to another."""
    out = []
    for link in links:
        shown, real = text_domain(link.anchor), link_domain(link.href)
        if shown and real and shown != real:
            out.append(link)
    return out


# Numbers and URLs say more about message format and era than about intent (dates and list
# footers in old plain-text ham, hrefs that never reach the text of HTML phishing), so the text
# model does not see them. Masking still produces them, other code can use them.
_FORMAT_TOKENS_RE = re.compile(f"{NUM_TOKEN}|{URL_TOKEN}")
# With a sender context the brand token is dropped too: how often a mail names its own sender is
# a property of the corpus, not of intent.
_BRAND_TOKEN_RE = re.compile(BRAND_TOKEN)
_SEPARATOR_RE = re.compile(r"[_=\-*#~]{3,}")  # rulers such as "_____" or "-----" in footers


@cache
def _stoplist_re() -> re.Pattern:
    entries = sorted(load_list("artefact_stoplist"), key=len, reverse=True)
    return re.compile(r"\b(?:" + "|".join(re.escape(e) for e in entries) + r")\b")


def sender_context(parsed: ParsedEmail) -> MaskContext:
    """The mask context a model trained with `mask: sender` reads, in training and serving."""
    return MaskContext.from_sender(parsed.from_addr, parsed.from_display)


def model_text(parsed: ParsedEmail, ctx: MaskContext | None = None) -> str:
    """Masked, lowercased subject and body with corpus artefacts removed. Input of `lr_text`."""
    text = _SEPARATOR_RE.sub(" ", mask_text(f"{parsed.subject}\n{parsed.text}", ctx).lower())
    text = _FORMAT_TOKENS_RE.sub(" ", text)
    if ctx is not None:
        text = _BRAND_TOKEN_RE.sub(" ", text)
    return _stoplist_re().sub(" ", text)[:MODEL_TEXT_CHARS]


def email_features(parsed: ParsedEmail, ctx: MaskContext | None = None) -> dict[str, float]:
    domains = [link_domain(link.href) for link in parsed.links]
    real = [d for d in domains if d]
    shorteners = load_list("shorteners")
    text = parsed.text
    masked = mask_text(f"{parsed.subject}\n{text}", ctx).lower()
    letters = [ch for ch in text if ch.isalpha()]
    values = {
        "n_links": len(parsed.links),
        "n_link_domains": len(set(real)),
        "ip_link_ratio": (sum(is_ip_host(d) for d in real) / len(real) if real else 0.0),
        "shortener_links": sum(d in shorteners for d in real),
        "anchor_mismatch_count": len(anchor_mismatches(parsed.links)),
        "script_links": sum(link.href.lower().startswith("javascript:") for link in parsed.links),
        "has_html": parsed.has_html,
        "n_attachments": parsed.n_attachments,
        "log_text_len": math.log1p(len(text)),
        "subject_len": len(parsed.subject),
        "exclaim_count": text.count("!") + parsed.subject.count("!"),
        "upper_ratio": sum(ch.isupper() for ch in letters) / len(letters) if letters else 0.0,
        "money_tokens": masked.count(MONEY_TOKEN),
        "urgency_words": sum(word in masked for word in load_list("email_keywords")),
    }
    return {name: float(values[name]) for name in FEATURE_NAMES}


def feature_vector(parsed: ParsedEmail) -> list[float]:
    return list(email_features(parsed).values())


def feature_matrix(emails) -> np.ndarray:
    rows = [feature_vector(p) for p in emails]
    return np.array(rows, dtype=float).reshape(-1, len(FEATURE_NAMES))
