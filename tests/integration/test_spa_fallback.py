"""The demo build is served by FastAPI, so a refresh on a client-side route must still load."""

import pytest
from fastapi.testclient import TestClient

from phishguard.app import main
from phishguard.app.main import create_app


@pytest.fixture
def spa_client(settings, tmp_path, monkeypatch):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<html>app-shell</html>", encoding="utf-8")
    (dist / "assets" / "app.js").write_text("console.log(1)", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("outside", encoding="utf-8")
    monkeypatch.setattr(main, "WEB_DIST", dist)
    with TestClient(create_app(settings)) as c:
        yield c


@pytest.mark.parametrize("path", ["/", "/history", "/analyze/email", "/dashboard", "/no/such/page"])
def test_client_routes_get_the_app_shell(spa_client, path):
    r = spa_client.get(path)
    assert r.status_code == 200 and "app-shell" in r.text


def test_real_assets_are_served(spa_client):
    assert spa_client.get("/assets/app.js").text == "console.log(1)"


def test_missing_asset_is_a_real_404(spa_client):
    assert spa_client.get("/assets/missing.js").status_code == 404


def test_unknown_api_route_stays_json_404(spa_client):
    r = spa_client.get("/api/nope")
    assert r.status_code == 404 and "app-shell" not in r.text


def test_api_still_works_with_the_fallback(spa_client):
    assert spa_client.get("/api/health").json()["status"] == "ok"


@pytest.mark.parametrize("path", ["/../secret.txt", "/%2e%2e/secret.txt", "/..%2fsecret.txt"])
def test_path_traversal_does_not_leak_files(spa_client, path):
    assert "outside" not in spa_client.get(path).text
