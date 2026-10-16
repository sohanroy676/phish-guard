import sqlite3

import pytest
from fastapi.testclient import TestClient

from phishguard.app.main import create_app
from phishguard.core.registry import ModelIntegrityError

PHISH = "verify your account password now urgent suspended"
HAM = "meeting agenda notes lunch project schedule thanks"
RAW = (
    "From: Support <help@bank.example>\nTo: me@example.com\nSubject: Hello\n"
    "Date: Mon, 1 Jan 2024 10:00:00 +0000\n{extra}\n\n{body}\n"
)


def fields(client, subject="Hi", sender="a@b.example", body=HAM):
    return client.post(
        "/api/analyze/email",
        json={"mode": "fields", "subject": subject, "sender": sender, "body": body},
        headers=client.csrf,
    )


def raw(client, source):
    return client.post(
        "/api/analyze/email", json={"mode": "raw", "source": source}, headers=client.csrf
    )


def upload(client, data, name="mail.eml"):
    return client.post(
        "/api/analyze/email/upload", files={"file": (name, data)}, headers=client.csrf
    )


def test_phishing_text_is_flagged_with_reasons_and_no_percent(email_client):
    r = fields(email_client, "Urgent", "x@evil.example", PHISH)
    assert r.status_code == 200
    data = r.json()
    assert data["band"] in ("high", "suspicious")
    assert data["model_reasons"] and all("email text" in m for m in data["model_reasons"])
    assert "%" not in str(data) and "safe" not in data["headline"].lower()
    assert data["sender"] == "evil[.]example"
    assert "weak signal" in data["model_note"] and "1999-2003" in data["model_note"]
    assert "123" in data["model_note"] and "safe" not in data["model_note"].lower()


def test_benign_text_is_low_without_reasons(email_client):
    data = fields(email_client).json()
    assert data["band"] == "low" and data["model_reasons"] == []


def test_pasted_fields_never_fire_header_rules(email_client):
    body = "Authentication-Results: spf=fail dkim=fail\nReply-To: a@other.example\n" + HAM
    data = fields(email_client, sender="PayPal <x@evil.example>", body=body).json()
    assert data["header_checks"]["available"] is False
    assert data["header_checks"]["message"].startswith("Header checks unavailable: paste the")
    assert data["header_checks"]["warnings"] == []


def test_real_headers_fire_header_rules_and_raise_band(email_client):
    src = RAW.format(extra="Authentication-Results: mx.example; spf=fail", body=HAM)
    data = raw(email_client, src).json()
    assert data["header_checks"]["available"] is True
    assert [w["rule_id"] for w in data["header_checks"]["warnings"]] == ["auth_fail"]
    assert data["band"] == "suspicious"


def test_lookalike_link_is_flagged_and_raises_band(email_client):
    body = '<html><body><a href="http://evil-login.example/x">www.paypal.com</a></body></html>'
    src = RAW.format(extra="Content-Type: text/html", body=body)
    data = raw(email_client, src).json()
    assert any(link["lookalike"] for link in data["links"])
    assert data["band"] in ("suspicious", "high")
    assert [w["rule_id"] for w in data["rule_warnings"]] == ["anchor_href_mismatch"]


def test_shortener_link_gives_cant_assess_when_text_is_clean(email_client):
    r = fields(email_client, body=HAM + " http://bit.ly/abc123")
    assert r.json()["band"] == "cant_assess"


def test_html_and_script_in_body_are_data_not_markup(email_client):
    payload = "<script>alert(1)</script><img src=x onerror=alert(2)>"
    r = fields(email_client, subject=payload, body=payload)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert "<script>" not in str(r.json())


def test_upload_eml_works(email_client):
    r = upload(email_client, RAW.format(extra="", body=HAM).encode())
    assert r.status_code == 200 and r.json()["header_checks"]["available"] is True


def test_huge_upload_is_413_too_large(email_client):
    r = upload(email_client, b"Subject: x\n\n" + b"a" * (2 * 1024 * 1024 + 10))
    assert r.status_code == 413 and "too large" in r.json()["detail"]


def test_upload_over_parser_limit_is_413(email_client):
    r = upload(email_client, b"Subject: x\n\n" + b"a" * 1_500_000)
    assert r.status_code == 413 and "too large" in r.json()["detail"]


@pytest.mark.parametrize("data", [b"just some notes, no headers", b"\x00\x01\x02\xff" * 50, b""])
def test_non_email_upload_is_422(email_client, data):
    r = upload(email_client, data, "notes.txt")
    assert r.status_code == 422 and "not a valid email file" in r.json()["detail"]


def test_empty_inputs_are_422(email_client):
    assert fields(email_client, "", "", "").status_code == 422
    assert raw(email_client, "   ").status_code == 422
    assert raw(email_client, "no headers here").status_code == 422


def test_oversized_pasted_fields_are_413(email_client):
    assert fields(email_client, body="a" * 1_100_000).status_code == 413


def test_login_and_csrf_are_required(email_client):
    body = {"mode": "fields", "subject": "x", "body": "y"}
    assert email_client.post("/api/analyze/email", json=body).status_code == 403
    no_token = email_client.post("/api/analyze/email/upload", files={"file": ("a", b"x")})
    assert no_token.status_code == 403
    with TestClient(email_client.app) as anon:
        assert anon.post("/api/analyze/email", json=body).status_code == 401


def test_503_without_email_model(logged_in):
    r = logged_in.post(
        "/api/analyze/email", json={"mode": "fields", "body": "hi"}, headers=logged_in.csrf
    )
    assert r.status_code == 503
    assert logged_in.get("/api/health").json()["models"] == {"url": "v1"}


def test_tampered_email_model_refuses_to_start(email_settings, email_models_root):
    with (email_models_root / "email" / "v1" / "lr_text.joblib").open("ab") as f:
        f.write(b"x")
    with pytest.raises(ModelIntegrityError), TestClient(create_app(email_settings)):
        pass


def test_health_reports_email_model(email_client):
    assert email_client.get("/api/health").json()["models"] == {"url": "v1", "email": "v1"}


def test_database_holds_no_raw_email_text(email_client, email_settings):
    secret = "zebra-secret-body http://very-secret-host.example/private/path?token=abc"
    fields(
        email_client,
        "zebra-secret-subject",
        "Alice Smith <alice.local@senderdomain.example>",
        PHISH + " " + secret,
    )
    raw(email_client, RAW.format(extra="", body=secret))
    path = email_settings.database_url.removeprefix("sqlite:///")
    con = sqlite3.connect(path)
    rows = con.execute("select * from analyses where kind = 'email'").fetchall()
    con.close()
    blob = repr(rows).lower()
    assert len(rows) == 2
    for leak in ("zebra", "very-secret-host", "private/path", "alice", "token=abc"):
        assert leak not in blob
    assert "senderdomain[.]example" in blob


def test_bulk_mail_text_warning_becomes_cant_assess_with_its_own_advice(email_client):
    plain = raw(email_client, RAW.format(extra="", body=PHISH)).json()
    bulk = raw(
        email_client,
        RAW.format(extra="List-Unsubscribe: <https://bank.example/u>", body=PHISH),
    ).json()
    assert plain["band"] in ("high", "suspicious")
    assert bulk["band"] == "cant_assess"
    assert "bulk or marketing mail" in bulk["advice"] and "safe" not in bulk["advice"].lower()
    assert bulk["bulk_mail"] == {"detected": True, "authenticated": False}
    assert bulk["model_reasons"]  # the n-grams are still shown


def test_bulk_header_does_not_hide_a_strong_rule(email_client):
    src = RAW.format(
        extra="List-Unsubscribe: <https://bank.example/u>\nAuthentication-Results: mx; spf=fail",
        body=PHISH,
    )
    assert raw(email_client, src).json()["band"] in ("high", "suspicious")


def test_pasted_fields_can_not_claim_bulk_and_high_is_capped(email_client):
    body = "List-Unsubscribe: <https://x.example>\n" + PHISH
    data = fields(email_client, "Urgent", "x@evil.example", body).json()
    assert data["bulk_mail"]["detected"] is False
    assert data["band"] in ("suspicious", "cant_assess")
