import pytest
from fastapi.testclient import TestClient

from phishguard.app.config import Settings
from phishguard.app.main import create_app


@pytest.fixture
def client(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'test.db'}")
    with TestClient(create_app(settings)) as c:
        yield c
