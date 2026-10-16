"""Rule checks on a parsed email. Rules can raise a band, never lower it.

Header rules run only when the input had real headers (`has_raw_headers`). Pasted fields have no
trustworthy headers, so they can never trigger them.
"""

import re

from phishguard.core.email.features import anchor_mismatches, text_domain
from phishguard.core.email.parse import ParsedEmail
from phishguard.core.url.features import brand_tokens
from phishguard.core.url.normalize import normalize_url
from phishguard.core.url.rules import RuleHit

_AUTH_FAIL_RE = re.compile(r"\b(spf|dkim|dmarc)=fail\b", re.IGNORECASE)


def _addr_host(addr: str):
    """Normalised host of an address's domain part, or None."""
    if "@" not in addr:
        return None
    try:
        return normalize_url(addr.rsplit("@", 1)[1])
    except ValueError:
        return None


def _auth_fail_hit(parsed: ParsedEmail) -> RuleHit | None:
    # Only the topmost Authentication-Results header was added by the receiving server.
    # Lower ones may have been written by the sender or a relay, so they are ignored.
    for name, value in parsed.headers:
        if name == "authentication-results":
            failed = sorted({m.group(1).upper() for m in _AUTH_FAIL_RE.finditer(value)})
            if failed:
                return RuleHit(
                    "auth_fail",
                    "high",
                    f"The sender failed an email authentication check ({', '.join(failed)}).",
                )
            return None
    return None


def _header_rules(parsed: ParsedEmail) -> list[RuleHit]:
    hits: list[RuleHit] = []
    auth = _auth_fail_hit(parsed)
    if auth:
        hits.append(auth)
    sender, reply = _addr_host(parsed.from_addr), _addr_host(parsed.reply_to_addr)
    if sender and reply and sender.registrable != reply.registrable:
        hits.append(
            RuleHit(
                "reply_to_mismatch", "warn", "Replies go to a different domain than the sender."
            )
        )
    display = parsed.from_display.lower()
    if sender and display:
        brands = {b for b in brand_tokens(display) if b not in sender.domain}
        shown = text_domain(display)
        if brands or (shown and shown != sender.registrable):
            hits.append(
                RuleHit(
                    "display_name_mismatch",
                    "high",
                    "The sender's name mentions a company or site that the address does not match.",
                )
            )
    return hits


def run_rules(parsed: ParsedEmail, headers: bool = True) -> list[RuleHit]:
    """`headers=False` runs the body rules only (used for the training baseline)."""
    hits = _header_rules(parsed) if headers and parsed.has_raw_headers else []
    if anchor_mismatches(parsed.links):
        hits.append(
            RuleHit(
                "anchor_href_mismatch",
                "high",
                "A link's visible text names one site but it goes to another.",
            )
        )
    if any(link.href.lower().startswith("javascript:") for link in parsed.links):
        hits.append(RuleHit("script_link", "warn", "Contains a link that runs a script."))
    return hits
