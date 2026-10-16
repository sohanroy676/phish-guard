import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from conftest import PASSWORD

SECRET_URL = "http://paypal.com.secure-login-verify.xyz/account/update?session=SECRET123"
MARKER = "zq9-unique-marker-4471"


def second_user(app, email="other@example.com"):
    other = TestClient(app)  # no context manager: shares the app state, own cookie jar
    response = other.post(
        "/api/auth/register", json={"email": email, "password": PASSWORD, "consent": True}
    )
    assert response.status_code == 201
    other.csrf = {"X-CSRF-Token": response.json()["csrf_token"]}
    return other


def analyze(client, url):
    response = client.post("/api/analyze/url", json={"url": url}, headers=client.csrf)
    assert response.status_code == 200
    return response


def test_history_is_empty_for_new_user(logged_in):
    assert logged_in.get("/api/history").json()["items"] == []
    assert logged_in.get("/api/dashboard/summary").json()["total"] == 0


def test_history_lists_own_analyses_newest_first(logged_in):
    analyze(logged_in, "https://first-example.com")
    analyze(logged_in, SECRET_URL)
    items = logged_in.get("/api/history").json()["items"]
    assert [i["kind"] for i in items] == ["url", "url"]
    assert items[0]["display_host"].startswith("hxxp")
    assert items[1]["display_host"] == "hxxps://first-example[.]com"
    assert set(items[0]) == {
        "id", "created_at", "kind", "display_host", "band",
        "model_reasons", "rule_warnings", "model_version",
    }  # fmt: skip


def test_users_never_see_each_others_rows(logged_in):
    other = second_user(logged_in.app)
    analyze(logged_in, SECRET_URL)
    assert other.get("/api/history").json()["items"] == []
    assert other.get("/api/dashboard/summary").json()["total"] == 0
    analyze(other, "https://other-example.com")
    mine = logged_in.get("/api/history").json()["items"]
    assert len(mine) == 1 and "other-example" not in json.dumps(mine)
    assert logged_in.get("/api/dashboard/summary").json()["total"] == 1


def test_delete_all_only_removes_own_rows(logged_in):
    other = second_user(logged_in.app)
    analyze(logged_in, SECRET_URL)
    analyze(other, SECRET_URL)
    response = other.delete("/api/history", headers=other.csrf)
    assert response.json() == {"deleted": 1}
    assert other.get("/api/history").json()["items"] == []
    assert len(logged_in.get("/api/history").json()["items"]) == 1


def test_delete_requires_login_and_csrf(logged_in, client):
    analyze(logged_in, SECRET_URL)
    anonymous = TestClient(logged_in.app)
    assert anonymous.delete("/api/history").status_code == 401
    assert logged_in.delete("/api/history").status_code == 403
    assert logged_in.delete("/api/history", headers={"X-CSRF-Token": "nope"}).status_code == 403
    assert len(logged_in.get("/api/history").json()["items"]) == 1


def test_reads_require_login(client):
    for path in ("/api/history", "/api/dashboard/summary", "/api/events"):
        assert client.get(path).status_code == 401


def test_other_users_csrf_token_does_not_authorise_delete(logged_in):
    other = second_user(logged_in.app)
    analyze(logged_in, SECRET_URL)
    assert logged_in.delete("/api/history", headers=other.csrf).status_code == 403


def test_filters_and_validation(logged_in):
    analyze(logged_in, SECRET_URL)
    analyze(logged_in, "https://first-example.com")
    bands = {i["band"] for i in logged_in.get("/api/history").json()["items"]}
    one = sorted(bands)[0]
    filtered = logged_in.get("/api/history", params={"band": one}).json()["items"]
    assert filtered and all(i["band"] == one for i in filtered)
    assert logged_in.get("/api/history", params={"kind": "email"}).json()["items"] == []
    assert logged_in.get("/api/history", params={"kind": "sms"}).status_code == 422
    assert logged_in.get("/api/history", params={"band": "safe"}).status_code == 422
    assert logged_in.get("/api/history", params={"limit": 0}).status_code == 422
    assert logged_in.get("/api/history", params={"limit": 10_000}).status_code == 422
    assert logged_in.get("/api/history", params={"offset": -1}).status_code == 422
    page = logged_in.get("/api/history", params={"limit": 1, "offset": 1}).json()["items"]
    assert len(page) == 1


def test_sql_injection_in_filters_is_rejected(logged_in):
    response = logged_in.get("/api/history", params={"band": "high' OR '1'='1"})
    assert response.status_code == 422


def test_no_raw_input_in_history_or_dashboard(email_client, email_settings):
    client = email_client  # already registered and logged in
    analyze(client, f"{SECRET_URL}&{MARKER}=1")
    lines = [
        "From: Bob <bob@evil-bank.example>",
        "To: me@example.com",
        f"Subject: Urgent {MARKER}",
        "Date: Mon, 1 Jan 2024 10:00:00 +0000",
        "",
        f"Click {MARKER} now at http://evil-bank.example/account/update?session=SECRET123",
    ]
    raw = "\n".join(lines) + "\n"
    response = client.post(
        "/api/analyze/email/upload", files={"file": ("a.eml", raw.encode())}, headers=client.csrf
    )
    assert response.status_code == 200
    texts = [
        client.get("/api/history").text,
        client.get("/api/history", params={"kind": "email"}).text,
        client.get("/api/dashboard/summary").text,
    ]
    assert json.loads(texts[1])["items"][0]["display_host"] == "evil-bank[.]example"
    for text in texts:
        for leak in (MARKER, "SECRET123", "session=", "bob@evil-bank", "/account/update"):
            assert leak not in text
        assert "input_hmac" not in text
    db_path = email_settings.database_url.removeprefix("sqlite:///")
    stored = json.dumps(sqlite3.connect(db_path).execute("select * from analyses").fetchall())
    assert MARKER not in stored and "SECRET123" not in stored


def test_dashboard_summary_shape(logged_in):
    analyze(logged_in, SECRET_URL)
    analyze(logged_in, "https://first-example.com")
    data = logged_in.get("/api/dashboard/summary").json()
    assert data["total"] == 2 == sum(data["by_band"].values())
    assert data["by_kind"] == {"url": 2, "email": 0}
    assert len(data["trend"]) == 30 and data["trend"][-1]["count"] == 2
    assert sum(d["count"] for d in data["trend"]) == 2
    assert len(data["recent_high_risk"]) <= 5
    assert all(r["band"] in ("high", "suspicious") for r in data["recent_high_risk"])


@pytest.mark.parametrize("method", ["post", "put", "patch"])
def test_history_is_read_or_delete_only(logged_in, method):
    response = getattr(logged_in, method)("/api/history", headers=logged_in.csrf)
    assert response.status_code == 405
