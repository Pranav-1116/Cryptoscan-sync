"""Organization settings (key/value) repository tests (SQLite)."""

from __future__ import annotations

import pytest
from db.connection.session import Base, SessionLocal, configure_session
from db.repositories.settings_repository import SECTOR_SETTING_KEY, SettingsRepository
from sqlalchemy import create_engine


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    configure_session(engine)
    s = SessionLocal()
    yield s
    s.close()


def test_set_and_get_json(session):
    repo = SettingsRepository(session)
    repo.set(SECTOR_SETTING_KEY, {"sector": "banking"}, updated_by="admin")
    session.commit()
    assert repo.get(SECTOR_SETTING_KEY) == {"sector": "banking"}
    assert repo.get(SECTOR_SETTING_KEY)["sector"] == "banking"


def test_get_default_when_missing(session):
    repo = SettingsRepository(session)
    assert repo.get("nope", default="generic") == "generic"
    assert repo.get_raw("nope") is None


def test_update_overwrites(session):
    repo = SettingsRepository(session)
    repo.set(SECTOR_SETTING_KEY, {"sector": "generic"}, updated_by="a")
    repo.set(SECTOR_SETTING_KEY, {"sector": "energy"}, updated_by="b")
    session.commit()
    assert repo.get(SECTOR_SETTING_KEY)["sector"] == "energy"
    row = session.query(__import__("db.models.app_setting", fromlist=["AppSetting"]).AppSetting).one()
    assert row.updated_by == "b"


def test_all_returns_mapping(session):
    repo = SettingsRepository(session)
    repo.set("a", {"x": 1})
    repo.set("b", "plain-string")
    session.commit()
    everything = repo.all()
    assert everything["a"] == {"x": 1}
    assert everything["b"] == "plain-string"
