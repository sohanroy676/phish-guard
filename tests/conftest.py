import pandas as pd
import pytest
from fastapi.testclient import TestClient

from phishguard.app.config import Settings
from phishguard.app.main import create_app
from synthetic import make_synthetic_raw


@pytest.fixture
def synthetic_raw() -> pd.DataFrame:
    return make_synthetic_raw()


@pytest.fixture
def client(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'test.db'}")
    with TestClient(create_app(settings)) as c:
        yield c
