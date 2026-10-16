import dataclasses
import json
import sqlite3

import numpy as np
import pytest
from fastapi.testclient import TestClient

from conftest import PASSWORD
from phishguard.app.config import Settings
from phishguard.app.main import create_app
from phishguard.core.registry import ModelIntegrityError

BODY = {"email": "user@example.com", "password": PASSWORD, "consent": True}
BRAND_URL = "http://paypal.com.secure-login-verify.xyz/account/update?session=SECRET123"


def test_register_requires_consent(client):
    response = client.post("/api/auth/register", json={**BODY, "consent": False})
    assert response.status_code == 422
    assert "agree" in response.json()["detail"]
    assert client.post("/api/auth/register", json={**BODY, "consent": True}).status_code == 201


def test_register_without_consent_field_is_rejected(client):
    body = {k: v for k, v in BODY.items() if k != "consent"}
    assert client.post("/api/auth/register", json=body).status_code == 422


@pytest.mark.parametrize("email", ["", "no-at-sign", "a@b", "a b@c.com", "x" * 300 + "@a.com"])
def test_register_rejects_bad_email(client, email):
    assert client.post("/api/auth/register", json={**BODY, "email": email}).status_code == 422


@pytest.mark.parametrize("password", ["", "short", "x" * 129])
def test_register_rejects_bad_password_length(client, password):
    assert client.post("/api/auth/register", json={**BODY, "password": password}).status_code == 422


def test_duplicate_email_is_rejected_case_insensitively(client):
    assert client.post("/api/auth/register", json=BODY).status_code == 201
    other = {**BODY, "email": "USER@example.com"}
    assert client.post("/api/auth/register", json=other).status_code == 409


def test_register_sets_httponly_cookie_and_returns_csrf(client):
    response = client.post("/api/auth/register", json=BODY)
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie
    assert response.json()["csrf_token"]
    assert "password" not in response.text


def test_login_logout_cycle(client):
    client.post("/api/auth/register", json=BODY)
    client.cookies.clear()
    assert client.get("/api/me").status_code == 401
    login = client.post("/api/auth/login", json=BODY)
    assert login.status_code == 200
    assert client.get("/api/me").json()["email"] == "user@example.com"
    csrf = {"X-CSRF-Token": login.json()["csrf_token"]}
    assert client.post("/api/auth/logout", headers=csrf).status_code == 204
    assert client.get("/api/me").status_code == 401


def test_logout_invalidates_the_old_cookie_server_side(client):
    login = client.post("/api/auth/register", json=BODY)
    old_cookie = client.cookies["phishguard_session"]
    csrf = {"X-CSRF-Token": login.json()["csrf_token"]}
    client.post("/api/auth/logout", headers=csrf)
    client.cookies.set("phishguard_session", old_cookie)
    assert client.get("/api/me").status_code == 401


def test_login_error_is_identical_for_unknown_email_and_wrong_password(client):
    client.post("/api/auth/register", json=BODY)
    wrong = client.post("/api/auth/login", json={**BODY, "password": "wrong-password-1"})
    unknown = client.post("/api/auth/login", json={**BODY, "email": "nobody@example.com"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_forged_session_cookie_is_rejected(client):
    client.cookies.set("phishguard_session", "not-a-real-token")
    assert client.get("/api/me").status_code == 401


def test_password_is_stored_as_argon2id_hash(client, settings):
    client.post("/api/auth/register", json=BODY)
    db_path = settings.database_url.removeprefix("sqlite:///")
    stored = sqlite3.connect(db_path).execute("select password_hash from users").fetchone()[0]
    assert stored.startswith("$argon2id$") and PASSWORD not in stored


def test_analyze_requires_login(client):
    assert client.post("/api/analyze/url", json={"url": "https://a.com"}).status_code == 401


def test_analyze_requires_csrf(logged_in):
    response = logged_in.post("/api/analyze/url", json={"url": "https://a.com"})
    assert response.status_code == 403
    bad = logged_in.post(
        "/api/analyze/url", json={"url": "https://a.com"}, headers={"X-CSRF-Token": "nope"}
    )
    assert bad.status_code == 403


def analyze(client, url):
    return client.post("/api/analyze/url", json={"url": url}, headers=client.csrf)


def test_phishy_host_is_flagged_with_reasons_and_rule_warnings_kept_apart(logged_in):
    data = analyze(logged_in, BRAND_URL).json()
    assert data["band"] in {"high", "suspicious"}
    assert data["headline"] in {"Likely phishing", "Suspicious: be careful"}
    assert data["model_reasons"] and isinstance(data["model_reasons"][0], str)
    assert "brand_impersonation" in [w["rule_id"] for w in data["rule_warnings"]]
    assert data["display_host"] == "hxxp://paypal[.]com[.]secure-login-verify[.]xyz"
    assert set(data) == {
        "band", "headline", "advice", "footer", "display_host", "model_reasons", "rule_warnings",
    }  # fmt: skip


def test_clean_host_is_low_with_no_reasons_and_no_percentage(logged_in):
    data = analyze(logged_in, "https://www.shop3.com/products").json()
    assert data["band"] == "low" and data["headline"] == "No strong phishing signs found"
    assert data["model_reasons"] == [] and data["rule_warnings"] == []
    assert "not a guarantee" in data["advice"]
    assert "%" not in json.dumps(data)


class _FixedScore:
    """A model that always says 0.99, as the real one does for bit.ly."""

    def predict_proba(self, _hosts):
        return np.array([[0.01, 0.99]])


def test_shortener_is_cant_assess(logged_in):
    scorer = logged_in.app.state.url_scorer
    logged_in.app.state.url_scorer = dataclasses.replace(scorer, model=_FixedScore())
    data = analyze(logged_in, "https://bit.ly/3abcXYZ").json()
    assert data["band"] == "cant_assess" and data["headline"] == "Can't assess"
    assert data["rule_warnings"][0]["rule_id"] == "shortener"


@pytest.mark.parametrize(
    "url", ["ftp://example.com/file", "", "   ", "https://", "http://a.com/" + "x" * 3000]
)
def test_unsupported_input_is_a_friendly_422(logged_in, url):
    response = analyze(logged_in, url)
    assert response.status_code == 422
    assert isinstance(response.json()["detail"], str)


def test_ftp_message_matches_roadmap(logged_in):
    detail = analyze(logged_in, "ftp://example.com/file").json()["detail"]
    assert detail == "Only http/https links can be assessed."


def test_oversized_body_is_rejected(logged_in):
    assert analyze(logged_in, "a" * 20_000).status_code == 422


def test_database_never_holds_the_full_url_or_path(logged_in, settings):
    analyze(logged_in, BRAND_URL)
    analyze(logged_in, "https://www.shop3.com/products/item9?id=7")
    db_path = settings.database_url.removeprefix("sqlite:///")
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "select input_hmac, display_host, band, model_reasons, rule_warnings from analyses"
    ).fetchall()
    assert len(rows) == 2
    blob = json.dumps(rows) + json.dumps(conn.execute("select * from analyses").fetchall())
    for secret in ("SECRET123", "account/update", "/products", "item9", "http://", "https://"):
        assert secret not in blob
    assert all(len(r[0]) == 64 for r in rows)
    assert all(r[1].startswith("hxxp") for r in rows)


def test_history_is_per_user(client, settings):
    first = client.post("/api/auth/register", json=BODY)
    client.post(
        "/api/analyze/url",
        json={"url": "https://www.shop3.com"},
        headers={"X-CSRF-Token": first.json()["csrf_token"]},
    )
    db_path = settings.database_url.removeprefix("sqlite:///")
    user_ids = sqlite3.connect(db_path).execute("select distinct user_id from analyses").fetchall()
    assert user_ids == [(1,)]


def test_health_lists_loaded_model(client):
    assert client.get("/api/health").json()["models"] == {"url": "v1"}


def test_analyze_is_503_without_a_model(tmp_path):
    s = Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'n.db'}",
        secret_key="s" * 20,
        hmac_pepper="p" * 20,
    )
    with TestClient(create_app(s)) as c:
        reg = c.post("/api/auth/register", json=BODY)
        csrf = {"X-CSRF-Token": reg.json()["csrf_token"]}
        assert (
            c.post("/api/analyze/url", json={"url": "https://a.com"}, headers=csrf).status_code
            == 503
        )
        assert c.get("/api/health").json()["models"] == {}


def test_app_refuses_to_start_when_model_file_is_tampered(settings, models_root):
    path = models_root / "url" / "v1" / "lr_char.joblib"
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0xFF
    path.write_bytes(bytes(data))
    with pytest.raises(ModelIntegrityError, match="SHA-256"), TestClient(create_app(settings)):
        pass


def test_app_refuses_to_start_with_placeholder_secrets(settings):
    bad = settings.model_copy(update={"secret_key": "change-me"})
    with pytest.raises(RuntimeError, match="SECRET_KEY"), TestClient(create_app(bad)):
        pass
