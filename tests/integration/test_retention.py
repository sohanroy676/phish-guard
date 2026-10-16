from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from conftest import SECRETS
from phishguard.app.config import Settings
from phishguard.app.main import create_app
from phishguard.app.models_db import Analysis, SessionRow, User
from phishguard.app.retention import purge_old

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


@pytest.fixture
def factory(client):
    return client.app.state.sessionmaker


def add_rows(factory, ages, now=NOW):
    """One user, one analysis per age (a timedelta before NOW). Returns the row ids."""
    with factory() as db:
        user = User(email="p@example.com", password_hash="x", consent_at=NOW)
        db.add(user)
        db.flush()
        rows = [
            Analysis(
                user_id=user.id,
                input_hmac="0" * 64,
                display_host="example[.]com",
                band="low",
                model_reasons=[],
                rule_warnings=[],
                model_version="v1",
                latency_ms=1,
                created_at=now - age,
            )
            for age in ages
        ]
        db.add_all(rows)
        db.commit()
        return [r.id for r in rows]


def remaining(factory):
    with factory() as db:
        return set(db.scalars(select(Analysis.id)))


def test_boundary_at_thirty_days(factory):
    fresh, almost, exact, just_over, old = add_rows(
        factory,
        [
            timedelta(days=1),
            timedelta(days=29, hours=23, minutes=59),
            timedelta(days=30),
            timedelta(days=30, seconds=1),
            timedelta(days=90),
        ],
    )
    assert purge_old(factory, 30, now=NOW) == 2
    assert remaining(factory) == {fresh, almost, exact}


def test_zero_days_purges_everything_older_than_now(factory):
    ids = add_rows(factory, [timedelta(seconds=1), timedelta(days=5)])
    assert purge_old(factory, 0, now=NOW) == 2
    assert remaining(factory) == set() and ids


def test_purge_with_nothing_to_delete(factory):
    assert purge_old(factory, 30, now=NOW) == 0


def test_purge_removes_expired_sessions_only(factory):
    with factory() as db:
        user = User(email="s@example.com", password_hash="x", consent_at=NOW)
        db.add(user)
        db.flush()
        for name, expires in (
            ("old", NOW - timedelta(hours=1)),
            ("live", NOW + timedelta(hours=1)),
        ):
            db.add(
                SessionRow(
                    token_hash=name * 32, user_id=user.id, csrf_token="c", expires_at=expires
                )
            )
        db.commit()
    purge_old(factory, 30, now=NOW)
    with factory() as db:
        assert [s.token_hash[:3] for s in db.scalars(select(SessionRow))] == ["liv"]


def test_purge_runs_on_startup(tmp_path, models_root):
    settings = Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'p.db'}",
        model_version_url="v1",
        models_dir=models_root,
        retention_days=30,
        **SECRETS,
    )
    with TestClient(create_app(settings)) as c:
        add_rows(c.app.state.sessionmaker, [timedelta(days=31)], now=datetime.now(UTC))
    with TestClient(create_app(settings)) as c:
        assert remaining(c.app.state.sessionmaker) == set()


def test_negative_retention_is_rejected():
    with pytest.raises(ValueError):
        Settings(_env_file=None, retention_days=-1, **SECRETS)
