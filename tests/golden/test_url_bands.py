"""Pin the bands and wording for the roadmap URLs using the real trained model.

The .joblib files are git-ignored, so these tests skip when the model is not trained locally.
"""

import pytest
from fastapi.testclient import TestClient

from conftest import PASSWORD, SECRETS
from phishguard.app.config import Settings
from phishguard.app.main import create_app
from phishguard.core.registry import MODELS_DIR

pytestmark = pytest.mark.skipif(
    not (MODELS_DIR / "url" / "v1" / "lr_char.joblib").is_file(),
    reason="real URL model not trained locally",
)


@pytest.fixture(scope="module")
def real_client(tmp_path_factory):
    settings = Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path_factory.mktemp('golden') / 'g.db'}",
        model_version_url="v1",
        **SECRETS,
    )
    with TestClient(create_app(settings)) as client:
        body = {"email": "g@example.com", "password": PASSWORD, "consent": True}
        client.csrf = {
            "X-CSRF-Token": client.post("/api/auth/register", json=body).json()["csrf_token"]
        }
        yield client


def check(client, url):
    return client.post("/api/analyze/url", json={"url": url}, headers=client.csrf)


def test_shortened_link_cannot_be_assessed(real_client):
    data = check(real_client, "https://bit.ly/3abcXYZ").json()
    assert data["band"] == "cant_assess"
    assert "destination is hidden" in data["rule_warnings"][0]["message"]


def test_brand_on_a_foreign_domain_is_flagged(real_client):
    data = check(real_client, "http://paypal.com.secure-login-verify.xyz/account/update").json()
    assert data["band"] in {"high", "suspicious"}
    assert data["model_reasons"]
    assert any(w["rule_id"] == "brand_impersonation" for w in data["rule_warnings"])


@pytest.mark.xfail(
    reason="Known limitation (ADR 0005): the host-only model over-flags subdomain hosts.",
    strict=True,
)
def test_wikipedia_has_no_strong_signs_and_never_says_safe(real_client):
    data = check(real_client, "https://en.wikipedia.org/wiki/Phishing").json()
    assert data["band"] == "low"
    assert data["headline"] == "No strong phishing signs found"
    assert "safe" not in " ".join(str(v) for v in data.values()).lower().replace("safety", "")


def test_ftp_is_rejected_with_the_roadmap_message(real_client):
    response = check(real_client, "ftp://example.com/file")
    assert (response.status_code, response.json()["detail"]) == (
        422,
        "Only http/https links can be assessed.",
    )
