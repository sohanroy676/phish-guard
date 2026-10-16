"""Bulk-mail detection from headers, and link-wrapper detection (ADR 0008).

The text model was trained on 1999-2003 prose, so it is out of its depth on modern bulk mail.
These checks only tell the band logic when that is the case. They never prove a message is safe:
phishers can add a List-Unsubscribe header, and replayed or relayed phishing can pass DMARC.
"""

import re
from dataclasses import dataclass

from phishguard.core.email.parse import ParsedEmail
from phishguard.core.email.rules import _addr_host
from phishguard.core.lists import load_list
from phishguard.core.url.normalize import NormalizedURL

_BULK_HEADERS = {"list-unsubscribe", "list-id"}
_BULK_PRECEDENCE = {"bulk", "list", "junk"}
_DMARC_PASS_RE = re.compile(r"\bdmarc=pass\b", re.IGNORECASE)
_HEADER_FROM_RE = re.compile(r"\bheader\.from=([^\s;()]+)", re.IGNORECASE)


@dataclass(frozen=True)
class BulkInfo:
    is_bulk: bool = False
    authenticated: bool = False


def _from_registrable(parsed: ParsedEmail) -> str | None:
    host = _addr_host(parsed.from_addr)
    return host.registrable if host else None


def _dmarc_pass(parsed: ParsedEmail) -> bool:
    """True when the topmost Authentication-Results (the receiver's own) shows an aligned pass."""
    for name, value in parsed.headers:
        if name != "authentication-results":
            continue
        if not _DMARC_PASS_RE.search(value):
            return False
        claimed = _HEADER_FROM_RE.search(value)
        sender = _from_registrable(parsed)
        if claimed is None or sender is None:
            return False
        shown = claimed.group(1).strip("<>").lower()
        return shown == sender or shown.endswith("." + sender)
    return False


def bulk_info(parsed: ParsedEmail) -> BulkInfo:
    """Bulk-mail markers need real headers; pasted fields never have them."""
    if not parsed.has_raw_headers:
        return BulkInfo()
    names = {name for name, _ in parsed.headers}
    precedence = {v.strip().lower() for n, v in parsed.headers if n == "precedence"}
    is_bulk = bool(names & _BULK_HEADERS) or bool(precedence & _BULK_PRECEDENCE)
    return BulkInfo(is_bulk, is_bulk and _dmarc_pass(parsed))


def is_link_wrapper(url: NormalizedURL) -> bool:
    """True for a shortener, redirector or email click-tracking host (hides the destination)."""
    wrappers = load_list("redirectors")
    if url.host in wrappers or url.registrable in wrappers:
        return True
    return any(url.host.endswith("." + w) for w in wrappers if w.count(".") > 1)
