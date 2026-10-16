"""URL feature vector. Single source of truth for training and serving."""

import ipaddress
import math
import re
from collections import Counter
from collections.abc import Iterable

import numpy as np

from phishguard.core.lists import load_list
from phishguard.core.url.normalize import NormalizedURL, normalize_url

SUSPICIOUS_TLDS = frozenset(
    {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work", "support", "zip", "country"}
)

FEATURE_NAMES: tuple[str, ...] = (
    "url_len",
    "host_len",
    "path_len",
    "query_len",
    "dot_count",
    "hyphen_count_host",
    "digit_count_host",
    "digit_ratio_host",
    "digit_ratio_path",
    "special_char_count",
    "at_count",
    "slash_count_path",
    "param_count",
    "subdomain_count",
    "host_entropy",
    "path_entropy",
    "tld_len",
    "is_https",
    "has_ip_host",
    "has_userinfo",
    "non_default_port",
    "is_punycode",
    "suspicious_tld",
    "is_shortener",
    "is_free_hosting",
    "keyword_count",
    "brand_in_subdomain",
    "brand_in_path",
    "brand_in_domain_hyphenated",
    "double_slash_in_path",
)

_SPECIAL = re.compile(r"[^A-Za-z0-9./:\-_]")


def is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def brand_tokens(text: str) -> set[str]:
    """Brands appearing as a substring of `text` (lowercased)."""
    return {b for b in load_list("brands") if b in text}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _digit_ratio(s: str) -> float:
    return sum(ch.isdigit() for ch in s) / len(s) if s else 0.0


def url_text(url: NormalizedURL | str) -> str:
    """Host + path + query without the scheme. Text input for the n-gram model."""
    u = normalize_url(url) if isinstance(url, str) else url
    return f"{u.host}{u.path}" + (f"?{u.query}" if u.query else "")


def host_text(url: NormalizedURL | str) -> str:
    """Host only. Input for the n-gram model, which must not learn from path or scheme."""
    return (normalize_url(url) if isinstance(url, str) else url).host


def domain_text(url: NormalizedURL | str) -> str:
    """Registered domain (the host for IPs and names with no public suffix), without subdomains.

    Input for the n-gram model since ADR 0006: PhiUSIIL legitimate hosts are almost all
    `www.<site>`, so a model that reads subdomains learns `www.` as a legitimacy signal.
    """
    u = normalize_url(url) if isinstance(url, str) else url
    return u.registrable if u.domain and u.suffix else u.host


def url_features(url: NormalizedURL | str) -> dict[str, float]:
    """Return features in FEATURE_NAMES order, always the same keys."""
    u = normalize_url(url) if isinstance(url, str) else url
    full = url_text(u)
    path_q = u.path + u.query
    sub_labels = [x for x in u.subdomain.split(".") if x]
    reg_dom = u.registrable
    lower_path = path_q.lower()
    keywords = load_list("keywords")
    brands_in_sub = brand_tokens(u.subdomain)
    values = {
        "url_len": len(full),
        "host_len": len(u.host),
        "path_len": len(u.path),
        "query_len": len(u.query),
        "dot_count": u.host.count("."),
        "hyphen_count_host": u.host.count("-"),
        "digit_count_host": sum(ch.isdigit() for ch in u.host),
        "digit_ratio_host": _digit_ratio(u.host),
        "digit_ratio_path": _digit_ratio(u.path),
        "special_char_count": len(_SPECIAL.findall(full)),
        "at_count": int(u.has_userinfo) + path_q.count("@"),
        "slash_count_path": u.path.count("/"),
        "param_count": len(u.query.split("&")) if u.query else 0,
        "subdomain_count": len(sub_labels),
        "host_entropy": _entropy(u.host),
        "path_entropy": _entropy(u.path),
        "tld_len": len(u.suffix),
        "is_https": u.scheme == "https",
        "has_ip_host": is_ip_host(u.host),
        "has_userinfo": u.has_userinfo,
        "non_default_port": u.port is not None and u.port != {"http": 80, "https": 443}[u.scheme],
        "is_punycode": "xn--" in u.host,
        "suspicious_tld": u.suffix.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS,
        "is_shortener": reg_dom in load_list("shorteners"),
        "is_free_hosting": reg_dom in load_list("free_hosting")
        or u.host in load_list("free_hosting"),
        "keyword_count": sum(k in u.host or k in lower_path for k in keywords),
        "brand_in_subdomain": bool(brands_in_sub - {u.domain}),
        "brand_in_path": bool(brand_tokens(lower_path) - {u.domain}),
        "brand_in_domain_hyphenated": bool(brand_tokens(u.domain)) and "-" in u.domain,
        "double_slash_in_path": "//" in u.path,
    }
    return {name: float(values[name]) for name in FEATURE_NAMES}


def feature_vector(url: NormalizedURL | str) -> list[float]:
    return list(url_features(url).values())


def feature_matrix(urls: Iterable[NormalizedURL | str]) -> np.ndarray:
    """One row per URL, columns in FEATURE_NAMES order."""
    return np.array([feature_vector(u) for u in urls], dtype=float).reshape(-1, len(FEATURE_NAMES))
