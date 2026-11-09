"""CryptoLog tenancy, RBAC seam and retention tests (docs/cryptolog/01_PRODUCT_SPEC.md §7, §10).

Tenant isolation is enforced by the store: a tenant-scoped read never
returns another tenant's records. Every cryptolog route carries its
authentication seam. Retention plans are projections — they perform
nothing, and a deletion always needs a disposition the plan does not
grant.
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
def store():
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
    from db.repositories.cryptolog_repository import (
        CryptoLogAlertRepository, CryptoLogRepository,
    )
    return {
        "session": session,
        "events": CryptoLogRepository(session),
        "alerts": CryptoLogAlertRepository(session),
    }


@pytest.fixture()
def api(store):
    from api import dependencies
    from api.routers import cryptolog
    from api.errors import install_error_contract

    app = FastAPI()
    app.include_router(cryptolog.router, prefix="/api/v1")
    install_error_contract(app)
    app.dependency_overrides[dependencies.get_db_session] = lambda: store["session"]
    app.dependency_overrides[dependencies.get_current_user] = lambda: "auditor"
    app.dependency_overrides[dependencies.require_intelligence_writer] = lambda: "writer"
    app.dependency_overrides[dependencies.require_intelligence_manager] = lambda: "manager"
    return TestClient(app)


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------


def test_a_tenant_read_never_returns_another_tenants_events(store):
    repo = store["events"]
    repo.insert_event(_event_dict(event_id="event_a1"))
    ranged = store["alerts"].events_in_range
    assert [r["event"]["event_id"] for r in
            ranged(tenant_id="tenant_001")] == ["event_a1"]
    assert ranged(tenant_id="tenant_002") == [], \
        "a tenant-scoped read of another tenant is empty, never a leak"
    assert repo.get_event("tenant_002", "event_a1") is None
    assert repo.get_event("tenant_001", "event_a1") is not None


def test_mixed_tenant_batch_rejects_foreign_item_without_dropping_own(api, store):
    from db.tenancy import tenant_scope

    with tenant_scope("tenant_001"):
        response = api.post("/api/v1/cryptolog/events/batch", json={
            "events": [_event_dict(event_id="batch-own"),
                       _event_dict(event_id="batch-foreign", tenant_id="tenant_002")]
        })
    assert response.status_code == 200, response.text
    assert [item["outcome"] for item in response.json()["items"]] == [
        "ACCEPTED", "REJECTED"]
    assert store["events"].get_event("tenant_001", "batch-own") is not None
    assert store["events"].get_event("tenant_002", "batch-foreign") is None


def test_alerts_and_checkpoints_are_tenant_scoped(store):
    alerts = store["alerts"]
    alerts.insert_alert(tenant_id="tenant_001", alert={
        "alert_id": "alrt_a1", "rule_id": "CL-002", "event_id": "event_a1",
        "asset_id": "a1", "severity": "HIGH", "state": "OPEN", "title": "t",
        "occurred_at": AS_OF,
    })
    assert alerts.list_alerts(tenant_id="tenant_002")["total_count"] == 0
    assert alerts.list_alerts(tenant_id="tenant_001")["total_count"] == 1
    alerts.insert_checkpoint(tenant_id="tenant_001", checkpoint={
        "checkpoint_ref": "cp_a1", "retention_ref": "WORM:7y",
        "signer_id": "s", "signature": "sig", "chain_hash": "h",
        "merkle_root_hash": "r", "event_count": 0,
    })
    assert alerts.list_checkpoints(tenant_id="tenant_002")["total_count"] == 0
    assert alerts.list_checkpoints(tenant_id="tenant_001")["total_count"] == 1


# ---------------------------------------------------------------------------
# RBAC seam
# ---------------------------------------------------------------------------


def test_every_cryptolog_route_carries_its_authentication_seam():
    from api.dependencies import get_current_user
    from api.routers import cryptolog

    unauthenticated = []
    for route in cryptolog.router.routes:
        names = {d.call.__name__ for d in route.dependant.dependencies
                 if d.call is not None}
        if get_current_user.__name__ not in names:
            unauthenticated.append(f"{route.methods} {route.path}")
    assert unauthenticated == [], \
        f"routes without an authentication seam: {unauthenticated}"


# ---------------------------------------------------------------------------
# Retention: projections, never production changes
# ---------------------------------------------------------------------------


def test_the_retention_policy_states_its_windows_and_the_disposition_bar(api):
    body = api.get("/api/v1/cryptolog/retention/policy").json()
    assert body["activity_retention_days"] == 180
    assert body["require_disposition_ref"] is True
    assert "disposition" in body["note"]


def test_a_retention_plan_performs_nothing(api):
    api.post("/api/v1/cryptolog/events", json=_event_dict(
        event_id="event_old",
        observation={"observed_at": "2020-01-01T00:00:00Z"}))
    before = api.get("/api/v1/cryptolog/events").json()
    result = api.post("/api/v1/cryptolog/retention/plan", json={})
    assert result.status_code == 200, result.text
    plan = result.json()
    assert plan["counts"]["DELETE_CANDIDATE"] == 1
    assert plan["rows"][0]["action"] == "DELETE_CANDIDATE"
    assert "never presented as a production change" in plan["not_proven"][1]
    assert "disposition-gated" in plan["note"]
    after = api.get("/api/v1/cryptolog/events").json()
    assert after == before, \
        "a plan is a projection: the store is untouched before and after"
