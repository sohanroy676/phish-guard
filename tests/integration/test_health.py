import pytest
from pytest_socket import SocketConnectBlockedError

from phishguard.app.config import Settings
from phishguard.app.db import db_is_ok, make_engine


def test_health_reports_ok(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "db": "ok", "models": {"url": "v1"}}


def test_health_rejects_post(client):
    assert client.post("/api/health").status_code == 405


def test_unknown_api_route_is_404(client):
    assert client.get("/api/nope").status_code == 404


def test_db_uses_wal_mode(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'wal.db'}")
    with engine.connect() as conn:
        mode = conn.exec_driver_sql("PRAGMA journal_mode").scalar()
    assert mode == "wal"


def test_db_is_ok_false_for_unreachable_db(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'missing_dir' / 'x.db'}")
    assert db_is_ok(engine) is False


def test_settings_defaults_do_not_contain_secrets():
    s = Settings(_env_file=None)
    assert s.secret_key == "" and s.hmac_pepper == ""


def test_network_is_blocked():
    import socket

    with pytest.raises(SocketConnectBlockedError):
        socket.create_connection(("example.com", 80), timeout=1)
