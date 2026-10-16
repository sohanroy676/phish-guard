"""Refang and normalise a URL string. Offline only: tldextract uses its bundled suffix list."""

import re
from dataclasses import dataclass
from functools import cache
from urllib.parse import urlsplit

import tldextract

MAX_URL_LEN = 2048
_CONTROL = re.compile(r"[\x00-\x20\x7f]")
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:")
_DEFAULT_PORTS = {"http": 80, "https": 443}


class UnsupportedURL(ValueError):
    """Raised when the input cannot be assessed as an http/https URL."""


@dataclass(frozen=True)
class NormalizedURL:
    scheme: str
    host: str
    path: str
    query: str
    port: int | None
    has_userinfo: bool
    subdomain: str
    domain: str
    suffix: str

    @property
    def registrable(self) -> str:
        return f"{self.domain}.{self.suffix}" if self.suffix else self.domain


@cache
def get_extractor() -> tldextract.TLDExtract:
    """Extractor that never fetches the suffix list and never writes a cache."""
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def _refang(s: str) -> str:
    s = re.sub(r"^hxxp", "http", s, flags=re.IGNORECASE)
    for fanged in ("[.]", "(.)", "{.}", "[dot]", "(dot)"):
        s = s.replace(fanged, ".")
    for fanged in ("[:]", "(:)"):
        s = s.replace(fanged, ":")
    return s.replace("[://]", "://")


def normalize_url(raw: str) -> NormalizedURL:
    if not isinstance(raw, str):
        raise UnsupportedURL("Enter a link as text.")
    s = raw.strip()
    if not s:
        raise UnsupportedURL("Enter a link to check.")
    if len(s) > MAX_URL_LEN:
        raise UnsupportedURL("That link is too long to assess.")
    if _CONTROL.search(s):
        raise UnsupportedURL("The link contains spaces or control characters.")
    s = _refang(s)
    if "://" not in s:
        if _SCHEME.match(s) and not re.match(r"^[^/]*:\d+(/|$)", s):
            raise UnsupportedURL("Only http/https links can be assessed.")
        s = "http://" + s.lstrip("/")
    try:
        parts = urlsplit(s)
        scheme = parts.scheme.lower()
        if scheme not in _DEFAULT_PORTS:
            raise UnsupportedURL("Only http/https links can be assessed.")
        host = (parts.hostname or "").rstrip(".").lower()
        port = parts.port
    except ValueError as exc:
        raise UnsupportedURL("That link could not be read.") from exc
    if not host:
        raise UnsupportedURL("That link has no host name.")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise UnsupportedURL("That host name is not valid.") from exc
    ext = get_extractor()(host)
    return NormalizedURL(
        scheme=scheme,
        host=host,
        path=parts.path,
        query=parts.query,
        port=port,
        has_userinfo="@" in parts.netloc,
        subdomain=ext.subdomain,
        domain=ext.domain,
        suffix=ext.suffix,
    )
