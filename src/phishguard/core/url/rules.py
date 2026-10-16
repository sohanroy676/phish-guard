"""Rule checks on a normalised URL. Rules can raise a band, never lower it."""

from dataclasses import dataclass

from phishguard.core.lists import load_list
from phishguard.core.url.features import brand_tokens, is_ip_host
from phishguard.core.url.normalize import NormalizedURL, normalize_url


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    severity: str  # "high" or "warn"
    message: str


def run_rules(url: NormalizedURL | str) -> list[RuleHit]:
    u = normalize_url(url) if isinstance(url, str) else url
    hits: list[RuleHit] = []
    reg = u.registrable

    if reg in load_list("shorteners"):
        hits.append(RuleHit("shortener", "warn", "Shortened link: the real destination is hidden."))
    # Brand name used outside the real brand domain, e.g. paypal.com.verify-account.xyz
    outside = brand_tokens(f"{u.subdomain}.{u.path}".lower()) - {u.domain}
    if outside and not is_ip_host(u.host):
        names = ", ".join(sorted(outside))
        hits.append(
            RuleHit("brand_impersonation", "high", f"Mentions {names} but is not that site.")
        )
    if is_ip_host(u.host):
        hits.append(RuleHit("ip_host", "high", "Uses a raw IP address instead of a domain name."))
    if u.has_userinfo:
        hits.append(
            RuleHit("userinfo", "high", "Contains a user@ part that can hide the real host.")
        )
    if "xn--" in u.host:
        hits.append(
            RuleHit("punycode", "warn", "Uses an internationalised name that may imitate another.")
        )
    if reg in load_list("free_hosting") and brand_tokens(u.host + u.path.lower()):
        hits.append(RuleHit("free_hosting_brand", "high", "Brand name on a free hosting site."))
    if len([x for x in u.subdomain.split(".") if x]) >= 4:
        hits.append(RuleHit("excess_subdomains", "warn", "Unusually many subdomain levels."))
    if sum(k in u.host or k in u.path.lower() for k in load_list("keywords")) >= 3:
        hits.append(
            RuleHit("suspicious_keywords", "warn", "Several account/login words in the link.")
        )
    return hits
