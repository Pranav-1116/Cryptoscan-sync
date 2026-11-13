"""CryptoLog insights API tests (docs/cryptolog/01_PRODUCT_SPEC.md, §9).

Timeline and overview aggregation over recorded events: counts name what
they count, gaps stay gaps (never a quiet-estate claim), integrity without
a checkpoint reads UNVERIFIED — not a failed chain and never a pass.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


AS_OF = "2026-11-07T04:00:00Z"


def _event_dict(**over):
    base = {
        "event_type": "TLS_NEGOTIATION_OBSERVED",
        "category": "TLS",
        "logging_kind": "ACTIVITY",
        "tenant_id": "tenant_001",
        "severity": "INFO",
        "asset_id": "asset_gateway_001",
        "source": {"collector_id": "collector_nbom_01",
                   "collector_version": "1.0.0",
                   "source_type": "NETWORK_OBSERVATION"},
        "cryptographic_context": {"protocol": "TLS",
                                  "protocol_version": "TLS1.2",
                                  "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                                  "evidence_level": "NETWORK_NEGOTIATED"},
        "observation": {"observed_at": AS_OF},
        "evidence": {"evidence_ids": ["evidence_001"]},
    }
    base.update(over)
    return base


@pytest.fixture()
def api():
    from db.connection.session import Base
    from db.models.cryptolog import (
        CryptoLogAlert, CryptoLogCheckpoint, CryptoLogCorrection, CryptoLogEvent,
    )

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False},
        poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=[
        CryptoLogEvent.__table__, CryptoLogCorrection.__table__,
        CryptoLogAlert.__table__, CryptoLogCheckpoint.__table__])
    session = sessionmaker(bind=engine)()

    from api import dependencies
    from api.routers import cryptolog
    from api.errors import install_error_contract

    app = FastAPI()
    app.include_router(cryptolog.router, prefix="/api/v1")
    install_error_contract(app)
    app.dependency_overrides[dependencies.get_db_session] = lambda: session
    app.dependency_overrides[dependencies.get_current_user] = lambda: "auditor"
    app.dependency_overrides[dependencies.require_intelligence_writer] = lambda: "writer"
    app.dependency_overrides[dependencies.require_intelligence_manager] = lambda: "manager"
    return TestClient(app)


def test_timeline_buckets_recorded_events_and_names_gaps_as_gaps(api):
    events = [
        _event_dict(event_id="event_001",
                    observation={"observed_at": "2026-11-07T04:00:00Z"}),
        _event_dict(event_id="event_002", category="HSM_KMS", severity="HIGH",
                    logging_kind="CHANGE", event_type="HSM_KEY_METADATA_CHANGE",
                    observation={"observed_at": "2026-11-07T09:00:00Z"}),
        _event_dict(event_id="event_003", severity="MEDIUM",
                    observation={"observed_at": "2026-11-08T02:00:00Z"}),
    ]
    for event in events:
        assert api.post("/api/v1/cryptolog/events", json=event).status_code == 201

    res = api.get("/api/v1/cryptolog/timeline")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["event_count"] == 3
    assert [b["bucket_start"] for b in body["buckets"]] == ["2026-11-07", "2026-11-08"]
    first = body["buckets"][0]
    assert first["total"] == 2
    assert first["by_category"] == {"TLS": 1, "HSM_KMS": 1}
    assert first["by_severity"] == {"INFO": 1, "HIGH": 1}
    assert first["critical_changes"] == 1, \
        "a HIGH configuration change is a named critical change"
    assert "never proof the estate was quiet" in body["note"], \
        "a gap in the record is never drawn as a quiet estate"

    hourly = api.get("/api/v1/cryptolog/timeline?bucket=hour").json()
    assert hourly["bucket"] == "hour"
    assert len(hourly["buckets"]) == 3, "hour buckets separate same-day events"


def test_timeline_window_filter_is_honest_about_the_window(api):
    api.post("/api/v1/cryptolog/events", json=_event_dict(
        event_id="event_001", observation={"observed_at": "2026-11-07T04:00:00Z"}))
    api.post("/api/v1/cryptolog/events", json=_event_dict(
        event_id="event_002", observation={"observed_at": "2026-11-09T04:00:00Z"}))
    body = api.get("/api/v1/cryptolog/timeline"
                   "?start_occurred=2026-11-08&end_occurred=2026-11-10").json()
    assert body["event_count"] == 1
    assert body["window"]["start_occurred"] == "2026-11-08"
    assert body["buckets"][0]["bucket_start"] == "2026-11-09"

    empty = api.get("/api/v1/cryptolog/timeline").json()
    assert empty["event_count"] == 2, "the unwindowed timeline counts everything recorded"


def test_asset_timeline_does_not_include_other_assets(api):
    for ident, asset in (("event-a", "pay-api"), ("event-b", "clearing-api")):
        assert api.post("/api/v1/cryptolog/events", json=_event_dict(
            event_id=ident, asset_id=asset)).status_code == 201
    all_assets = api.get("/api/v1/cryptolog/timeline").json()
    scoped = api.get("/api/v1/cryptolog/timeline?asset_id=pay-api").json()
    assert all_assets["event_count"] == 2
    assert scoped["event_count"] == 1
    assert scoped["window"]["asset_id"] == "pay-api"
    assert "this asset" in scoped["note"]
    absent = api.get("/api/v1/cryptolog/timeline?asset_id=not-recorded").json()
    assert absent["event_count"] == 0
    assert absent["buckets"] == []


def test_overview_counts_only_recorded_events_and_names_them(api):
    api.post("/api/v1/cryptolog/events", json=_event_dict(event_id="event_001"))
    api.post("/api/v1/cryptolog/events", json=_event_dict(
        event_id="event_002", severity="CRITICAL", logging_kind="CHANGE",
        event_type="CRYPTO_CONFIGURATION_CHANGED", category="CONFIGURATION",
        source={"collector_id": "collector_cfg_02", "collector_version": "1.0.0",
                "source_type": "CONFIGURATION_OBSERVATION"}))
    body = api.get("/api/v1/cryptolog/overview").json()
    assert body["event_total"] == 2
    assert body["by_severity"] == {"INFO": 1, "CRITICAL": 1}
    assert body["by_logging_kind"] == {"ACTIVITY": 1, "CHANGE": 1}
    assert body["critical_changes"] == 1
    assert [c["collector_id"] for c in body["collectors"]] == \
        ["collector_cfg_02", "collector_nbom_01"], \
        "collection health names its collectors and their volumes"
    assert "never a clean zero" in body["note"]


def test_overview_integrity_without_a_checkpoint_is_unverified(api):
    body = api.get("/api/v1/cryptolog/overview").json()
    assert body["integrity"]["state"] == "UNVERIFIED"
    assert body["integrity"]["checkpoint_count"] == 0
    assert "not yet anchored" in body["integrity"]["note"], \
        "an uncheckpointed store is UNVERIFIED — not a failed chain, never a pass"
    assert body["event_total"] == 0


def test_overview_counts_alerts_honestly(api):
    api.post("/api/v1/cryptolog/events", json=_event_dict(event_id="event_001"))
    api.post("/api/v1/cryptolog/alerts/evaluate", json={
        "events": [_event_dict(event_id="event_001")]})
    body = api.get("/api/v1/cryptolog/overview").json()
    assert body["alerts_total"] >= 1
    assert body["alerts_open"] == body["alerts_total"], \
        "freshly evaluated alerts are OPEN until a transition says otherwise"
