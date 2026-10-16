"""Every feature must work with no network: no DNS lookups, no outbound connections."""

import socket

import pytest

RAW = (
    "From: A <a@bank.example>\nTo: me@example.com\nSubject: Hi\n\n"
    "Please verify http://evil.example/x now\n"
)


@pytest.fixture
def no_network(monkeypatch):
    attempts: list[str] = []

    def record(name):
        def blocked(*args, **kwargs):
            attempts.append(f"{name}{args[:2]}")
            raise AssertionError(f"network use: {name}")

        return blocked

    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr"):
        monkeypatch.setattr(socket, name, record(name))
    monkeypatch.setattr(socket.socket, "connect", record("connect"))
    monkeypatch.setattr(socket.socket, "connect_ex", record("connect_ex"))
    return attempts


def test_every_feature_works_offline(email_client, no_network):
    c = email_client
    # Hosts that would resolve (or not) on a real network must never be looked up.
    for url in (
        "http://paypal.com.secure-login-verify.xyz/a",
        "https://www.shop1.com/",
        "bit.ly/x",
    ):
        assert c.post("/api/analyze/url", json={"url": url}, headers=c.csrf).status_code == 200
    fields = {
        "mode": "fields",
        "subject": "Hi",
        "sender": "a@b.example",
        "body": "lunch http://x.example/",
    }
    assert c.post("/api/analyze/email", json=fields, headers=c.csrf).status_code == 200
    raw = {"mode": "raw", "source": RAW}
    assert c.post("/api/analyze/email", json=raw, headers=c.csrf).status_code == 200
    up = c.post("/api/analyze/email/upload", files={"file": ("m.eml", RAW)}, headers=c.csrf)
    assert up.status_code == 200

    history = c.get("/api/history").json()
    assert len(history["items"] if isinstance(history, dict) else history) == 6
    assert c.get("/api/dashboard/summary").status_code == 200
    assert c.delete("/api/history", headers=c.csrf).status_code in (200, 204)

    assert no_network == []


def test_offline_guard_actually_catches_lookups(no_network):
    """Adversarial: prove the guard fails if code tried a DNS lookup."""
    with pytest.raises(AssertionError):
        socket.getaddrinfo("example.com", 80)
    assert no_network
