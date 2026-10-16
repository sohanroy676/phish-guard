import json

import joblib
import pandas as pd
import pytest
import sklearn
from fastapi.testclient import TestClient

from phishguard.app.config import Settings
from phishguard.app.main import create_app
from phishguard.core.registry import sha256_file
from phishguard.training.models import lr_char, lr_text
from synthetic import make_synthetic_raw

SECRETS = {"secret_key": "test-secret-key-0123456789", "hmac_pepper": "test-pepper-0123456789"}
PASSWORD = "correct-horse-battery"


@pytest.fixture
def synthetic_raw() -> pd.DataFrame:
    return make_synthetic_raw()


@pytest.fixture
def models_root(tmp_path):
    """A tiny but real host-only model in the registry layout (the real one is git-ignored)."""
    hosts = [f"www.shop{i}.com" for i in range(60)] + [
        f"secure-login-paypal{i}.xyz" for i in range(60)
    ]
    y = [0] * 60 + [1] * 60
    params = {"C": 1.0, "ngram_range": [2, 4], "max_features": 5000}
    model = lr_char(params, 0).fit(hosts, y)
    vdir = tmp_path / "models" / "url" / "v1"
    vdir.mkdir(parents=True)
    joblib.dump(model, vdir / "lr_char.joblib")
    entry = {
        "file": "lr_char.joblib",
        "sha256": sha256_file(vdir / "lr_char.joblib"),
        "input": "host_text",
        "t_high": 0.6,
        "t_low": 0.3,
    }
    manifest = {
        "sklearn_version": sklearn.__version__,
        "primary": "lr_char",
        "models": {"lr_char": entry},
    }
    (vdir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return tmp_path / "models"


@pytest.fixture
def settings(tmp_path, models_root):
    return Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        model_version_url="v1",
        models_dir=models_root,
        **SECRETS,
    )


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings)) as c:
        yield c


@pytest.fixture
def logged_in(client):
    """The client after registering, plus the CSRF headers for POST requests."""
    body = {"email": "user@example.com", "password": PASSWORD, "consent": True}
    response = client.post("/api/auth/register", json=body)
    assert response.status_code == 201
    client.csrf = {"X-CSRF-Token": response.json()["csrf_token"]}
    return client


@pytest.fixture
def email_models_root(models_root):
    """The tiny URL model plus a tiny word model in the email registry layout."""
    phish = [f"verify your account password now urgent suspended {i % 5}" for i in range(40)]
    ham = [f"meeting agenda notes lunch project schedule thanks {i % 5}" for i in range(40)]
    params = {"C": 10.0, "ngram_range": [1, 2], "max_features": 5000}
    model = lr_text(params, 0).fit(phish + ham, [1] * 40 + [0] * 40)
    vdir = models_root / "email" / "v1"
    vdir.mkdir(parents=True)
    joblib.dump(model, vdir / "lr_text.joblib")
    entry = {
        "file": "lr_text.joblib",
        "sha256": sha256_file(vdir / "lr_text.joblib"),
        "input": "text",
        "t_high": 0.6,
        "t_low": 0.3,
    }
    manifest = {
        "sklearn_version": sklearn.__version__,
        "primary": "lr_text",
        "models": {"lr_text": entry},
    }
    (vdir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return models_root


@pytest.fixture
def email_settings(settings, email_models_root):
    return settings.model_copy(update={"model_version_email": "v1"})


@pytest.fixture
def email_client(email_settings):
    with TestClient(create_app(email_settings)) as c:
        body = {"email": "user@example.com", "password": PASSWORD, "consent": True}
        response = c.post("/api/auth/register", json=body)
        assert response.status_code == 201
        c.csrf = {"X-CSRF-Token": response.json()["csrf_token"]}
        yield c
