"""HMAC helpers, host defanging and session tokens. Nothing here stores raw input."""

import hashlib
import hmac
import secrets

from phishguard.core.url.normalize import NormalizedURL


def hmac_hex(key: str, message: str) -> str:
    return hmac.new(key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def canonical_url(u: NormalizedURL) -> str:
    default = {"http": 80, "https": 443}[u.scheme]
    port = f":{u.port}" if u.port and u.port != default else ""
    query = f"?{u.query}" if u.query else ""
    return f"{u.scheme}://{u.host}{port}{u.path}{query}"


def input_hmac(pepper: str, u: NormalizedURL) -> str:
    """Keyed hash of the normalised URL. Lets the app spot repeats without keeping the URL."""
    return hmac_hex(pepper, "url:" + canonical_url(u))


def defang_host(u: NormalizedURL) -> str:
    scheme = "hxxps" if u.scheme == "https" else "hxxp"
    return f"{scheme}://{u.host.replace('.', '[.]')}"


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(secret_key: str, token: str) -> str:
    return hmac_hex(secret_key, "session:" + token)


def csrf_ok(expected: str, supplied: str | None) -> bool:
    return bool(supplied) and hmac.compare_digest(expected, supplied)
