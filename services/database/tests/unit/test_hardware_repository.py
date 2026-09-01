"""Live hardware repository — assets, event journal, agent heartbeats."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from db.connection.session import Base, SessionLocal, configure_session
from db.repositories.hardware_repository import HardwareRepository


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    configure_session(engine)
    s = SessionLocal()
    yield s
    s.close()


def _state(asset_id="srv-1", **over):
    state = {
        "asset_id": asset_id,
        "agent_id": "edge-1",
        "manufacturer": "Dell",
        "model": "R760",
        "device_type": "server",
        "serial_reference": "SN-1",
        "hardware_revision": "A02",
        "first_seen": "2026-08-31T10:00:00+00:00",
        "last_seen": "2026-08-31T10:00:00+00:00",
        "firmware": {"BIOS": "2.18"},
        "tpm": {"present": True, "version": "2.0"},
        "evidence_history": ["ev-1"],
        "risk_score": 8,
        "risk_level": "HIGH",
    }
    state.update(over)
    return state


def test_upsert_and_get_asset(session):
    repo = HardwareRepository(session)
    row = repo.upsert_asset(_state())
    session.commit()
    assert row.asset_id == "srv-1"
    assert row.firmware["BIOS"] == "2.18"
    assert row.tpm["version"] == "2.0"
    assert row.risk_level == "HIGH"

    found = repo.get_asset("srv-1")
    assert found is not None and found.manufacturer == "Dell"
    assert repo.get_asset("ghost") is None


def test_upsert_updates_existing(session):
    repo = HardwareRepository(session)
    repo.upsert_asset(_state())
    session.commit()
    repo.upsert_asset(_state(firmware={"BIOS": "2.19"},
                             previous_state={"firmware": {"BIOS": "2.18"}}))
    session.commit()
    row = repo.get_asset("srv-1")
    assert row.firmware["BIOS"] == "2.19"
    assert row.previous_state["firmware"]["BIOS"] == "2.18"
    assert repo.count_assets() == 1


def test_list_assets_by_agent(session):
    repo = HardwareRepository(session)
    repo.upsert_asset(_state("a", agent_id="edge-1"))
    repo.upsert_asset(_state("b", agent_id="edge-2"))
    session.commit()
    assert repo.count_assets() == 2
    assert repo.count_assets(agent_id="edge-1") == 1
    assert [a.asset_id for a in repo.list_assets(agent_id="edge-2")] == ["b"]


def test_event_journal_append_and_query(session):
    repo = HardwareRepository(session)
    repo.append_event({
        "event_type": "BIOS_CHANGED", "asset_id": "srv-1", "agent_id": "edge-1",
        "source": "agent", "observed_at": "2026-08-31T12:30:00+00:00",
        "change_class": "FIRMWARE_CHANGE", "state_verdict": "CHANGED",
        "payload": {"component": "BIOS", "version": "2.19"},
        "evidence_id": "ev-9", "chain_hash": "abc123",
    })
    repo.append_event({
        "event_type": "TPM_AVAILABLE", "asset_id": "srv-1",
        "observed_at": "2026-08-31T13:00:00+00:00",
    })
    session.commit()
    rows, total = repo.list_events(asset_id="srv-1")
    assert total == 2
    assert rows[0].event_type == "TPM_AVAILABLE"  # newest first
    assert rows[1].payload["component"] == "BIOS"
    rows2, _ = repo.list_events(event_type="BIOS_CHANGED")
    assert len(rows2) == 1


def test_timeline_oldest_first(session):
    repo = HardwareRepository(session)
    for ts, etype in (("2026-08-31T10:00:00+00:00", "HARDWARE_DISCOVERED"),
                      ("2026-08-31T12:30:00+00:00", "BIOS_CHANGED"),
                      ("2026-08-31T14:10:00+00:00", "TPM_CHANGED")):
        repo.append_event({"event_type": etype, "asset_id": "srv-1",
                           "observed_at": ts})
    session.commit()
    timeline = repo.timeline("srv-1")
    assert [e.event_type for e in timeline] == [
        "HARDWARE_DISCOVERED", "BIOS_CHANGED", "TPM_CHANGED"]


def test_events_since(session):
    repo = HardwareRepository(session)
    repo.append_event({"event_type": "HARDWARE_DISCOVERED", "asset_id": "a",
                       "observed_at": "2026-08-31T10:00:00+00:00"})
    repo.append_event({"event_type": "BIOS_CHANGED", "asset_id": "a",
                       "observed_at": "2026-08-31T12:00:00+00:00"})
    session.commit()
    since = datetime(2026, 8, 31, 11, 0, tzinfo=timezone.utc)
    rows = repo.events_since(since)
    assert len(rows) == 1 and rows[0].event_type == "BIOS_CHANGED"


def test_agent_heartbeat_upsert(session):
    repo = HardwareRepository(session)
    repo.upsert_agent({
        "agent_id": "edge-1", "last_heartbeat": "2026-08-31T10:00:00+00:00",
        "last_successful_discovery": "2026-08-31T09:55:00+00:00",
        "event_queue": 4, "event_lag": 2, "agent_health": "HEALTHY",
        "agent_status": "ONLINE", "hardware_count": 12,
    })
    session.commit()
    row = repo.get_agent("edge-1")
    assert row.event_queue_depth == 4
    assert row.hardware_count == 12
    assert row.agent_status == "ONLINE"

    repo.upsert_agent({"agent_id": "edge-1", "last_heartbeat": "2026-08-31T11:00:00+00:00",
                       "event_queue": 0, "event_lag": 0, "agent_health": "HEALTHY",
                       "agent_status": "ONLINE"})
    session.commit()
    assert repo.get_agent("edge-1").event_queue_depth == 0
    assert repo.list_agents()[0].agent_id == "edge-1"
    assert repo.get_agent("ghost") is None


def test_update_risk(session):
    repo = HardwareRepository(session)
    repo.upsert_asset(_state())
    session.commit()
    repo.update_risk("srv-1", score=13, level="CRITICAL")
    session.commit()
    assert repo.get_asset("srv-1").risk_level == "CRITICAL"
    repo.update_risk("ghost", score=1, level="LOW")  # no-op, no crash
