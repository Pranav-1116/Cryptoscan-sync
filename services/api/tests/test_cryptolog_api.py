"""CryptoLog ingestion API tests (docs/cryptolog/01_PRODUCT_SPEC.md, Phase 2).

Idempotent ingestion, never a silent overwrite, partial-success batches,
keyset pagination without invented totals, and corrections that preserve
the original byte-identical."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from shared_models.cryptolog_events import event_hash


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
                                  "protocol_version": "TLS1.3",
                                  "cipher_suite": "TLS_AES_256_GCM_SHA384",
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


def test_ingest_is_idempotent_and_conflicts_never_silently_overwrite(api):
    first = api.post("/api/v1/cryptolog/events", json=_event_dict())
    assert first.status_code == 201, first.text
    assert first.json()["outcome"] == "INSERTED"
    event_id = first.json()["event"]["event_id"]

    again = api.post("/api/v1/cryptolog/events", json=_event_dict())
    assert again.status_code == 200
    assert again.json()["outcome"] == "DUPLICATE"
    assert again.json()["event"]["event_id"] == event_id, \
        "idempotent re-ingestion keeps the existing record"

    conflict_body = _event_dict(
        processing={"deduplication_key": "nbom:gateway:tls"},
        attributes={"note": "first"})
    ok = api.post("/api/v1/cryptolog/events", json=conflict_body)
    assert ok.status_code == 201
    clash = api.post("/api/v1/cryptolog/events", json=_event_dict(
        processing={"deduplication_key": "nbom:gateway:tls"},
        severity="HIGH", attributes={"note": "different"}))
    assert clash.status_code == 409
    detail = clash.json()["detail"]
    assert detail["outcome"] == "CONFLICT"
    assert "never a silent overwrite" in detail["note"]
    assert detail["existing_event_id"] == ok.json()["event"]["event_id"]


def test_batch_reports_partial_success_with_reasons(api):
    good = _event_dict()
    bad = _event_dict(evidence={"evidence_ids": []})
    private = _event_dict(attributes={"private_key": "-----BEGIN"})
    res = api.post("/api/v1/cryptolog/events/batch",
                   json={"events": [good, bad, private]})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["schema"] == "cryptoscan.bulk-result/1"
    outcomes = [row["outcome"] for row in body["items"]]
    assert outcomes == ["ACCEPTED", "REJECTED", "REJECTED"]
    assert all(row["reason"] for row in body["items"])
    assert body["totals"] == {"accepted": 1, "rejected": 2, "skipped": 0,
                              "total": 3}
    assert body["partial"] is True, "a genuine mix: some accepted, some not"
    assert body["has_rejections"] is True
    assert "rumor" in body["items"][1]["reason"]
    assert "prohibited value" in body["items"][2]["reason"]


def test_validation_refusals_reach_the_error_envelope(api):
    refused = api.post("/api/v1/cryptolog/events", json=_event_dict(
        evidence={"evidence_ids": []}))
    assert refused.status_code == 422
    assert refused.json()["error_code"] == "INVALID_ARGUMENT"
    secret = api.post("/api/v1/cryptolog/events", json=_event_dict(
        source={"collector_id": "c", "source_type": "NETWORK_OBSERVATION",
                "password": "hunter2"}))
    assert secret.status_code == 422
    assert "prohibited value" in secret.json()["detail"]


def test_search_is_keyset_paginated_with_honest_boundaries(api):
    for index in range(3):
        api.post("/api/v1/cryptolog/events", json=_event_dict(
            asset_id=f"asset-{index}", severity=["INFO", "HIGH", "LOW"][index],
            evidence={"evidence_ids": [f"ev-{index}"]}))
    page = api.get("/api/v1/cryptolog/events",
                   params={"limit": 2, "tenant_id": "tenant_001"}).json()
    assert page["returned"] == 2
    assert page["next_cursor"]
    assert "total_count" not in page, "cursor pages claim no totals"

    rest = api.get("/api/v1/cryptolog/events",
                   params={"limit": 2, "cursor": page["next_cursor"],
                           "tenant_id": "tenant_001"}).json()
    assert rest["returned"] == 1
    assert rest["next_cursor"] is None

    filtered = api.get("/api/v1/cryptolog/events",
                       params={"severity": "HIGH"}).json()
    assert [e["asset_id"] for e in filtered["events"]] == ["asset-1"]

    over = api.get("/api/v1/cryptolog/events", params={"limit": 5000})
    assert over.status_code == 422, "limit is clamped at 200"

    bad_cursor = api.get("/api/v1/cryptolog/events",
                         params={"cursor": "not-a-row"})
    assert bad_cursor.status_code == 422
    assert "unknown cursor" in bad_cursor.json()["detail"]


def test_corrections_supersede_but_never_rewrite_the_original(api):
    created = api.post("/api/v1/cryptolog/events", json=_event_dict(
        processing={"deduplication_key": "nbom:gateway:tls"})).json()
    event_id = created["event"]["event_id"]
    original_hash = event_hash(created["event"])

    fixed = api.post(f"/api/v1/cryptolog/events/{event_id}/corrections",
                     json={"corrected_event": _event_dict(
                               severity="HIGH",
                               investigation_status="INVESTIGATION_REQUIRED",
                               processing={"deduplication_key":
                                           "nbom:gateway:tls"}),
                           "reason": "severity understated after triage",
                           "actor": "auditor",
                           "evidence_ids": ["ev-triage"]})
    assert fixed.status_code == 201, fixed.text
    correction = fixed.json()["correction"]
    assert correction["original_hash"] == original_hash

    stored = api.get(f"/api/v1/cryptolog/events/{event_id}").json()
    assert stored["severity"] == "INFO", "the original row is never rewritten"
    assert event_hash(stored) == original_hash

    listing = api.get(f"/api/v1/cryptolog/events/{event_id}/corrections").json()
    assert listing["returned"] == 1
    assert listing["corrections"][0]["actor"] == "auditor"

    no_reason = api.post(f"/api/v1/cryptolog/events/{event_id}/corrections",
                         json={"corrected_event": _event_dict(),
                               "reason": "", "actor": "auditor",
                               "evidence_ids": ["e"]})
    assert no_reason.status_code == 422


def test_missing_event_reads_404_not_an_empty_truth(api):
    missing = api.get("/api/v1/cryptolog/events/clog_nope")
    assert missing.status_code == 404


def test_alert_evaluation_is_deterministic_and_never_confirms(api):
    events = [{
        "event_id": "event-rc4", "event_type": "TLS_NEGOTIATION_OBSERVED", "category": "TLS",
        "logging_kind": "ACTIVITY", "tenant_id": "tenant_001",
        "severity": "INFO", "asset_id": "asset_gateway_001",
        "source": {"collector_id": "c1", "collector_version": "1",
                   "source_type": "NETWORK_OBSERVATION"},
        "cryptographic_context": {"protocol": "TLS",
                                  "protocol_version": "TLS1.2",
                                  "cipher_suite": "TLS_RSA_WITH_RC4_128_SHA",
                                  "evidence_level": "NETWORK_NEGOTIATED"},
        "observation": {"observed_at": AS_OF},
        "evidence": {"evidence_ids": ["ev-rc4"]},
    }]
    assert api.post("/api/v1/cryptolog/events", json=events[0]).status_code == 201
    res = api.post("/api/v1/cryptolog/alerts/evaluate",
                   json={"events": events, "assessments": {
                       "asset_gateway_001": {
                           "asset_criticality": "CRITICAL",
                           "exposure": "INTERNET_FACING"}}})
    assert res.status_code == 200, res.text
    alerts = res.json()["alerts"]
    assert [a["rule_id"] for a in alerts] == ["CL-002"]
    alert = alerts[0]
    assert alert["severity"] == "HIGH", "unverified caller factors cannot raise the rule severity"
    assert alert["severity_basis"]["unapplied_operator_assessments"] is True
    assert "did not change the rule severity" in alert["what_is_not_proven"]
    assert alert["lifecycle"]["status"] == "OPEN"
    assert "never automatically becomes a confirmed compromise" \
        in alert["what_is_not_proven"]

    refused = api.post("/api/v1/cryptolog/alerts/transition", json={
        "alert": alert, "action": "RESOLVE", "actor": "auditor",
        "at": AS_OF, "note": "it is a compromise",
        "resolution": "CONFIRMED_INCIDENT"})
    assert refused.status_code == 422
    assert "never declares a compromise" in refused.json()["detail"]

    confirmed = api.post("/api/v1/cryptolog/alerts/transition", json={
        "alert": alert, "action": "RESOLVE", "actor": "auditor",
        "at": AS_OF, "note": "bank SOC opened incident inc-77",
        "resolution": "CONFIRMED_INCIDENT",
        "evidence_ids": ["ev-rc4", "inc-77"]})
    assert confirmed.status_code == 200, confirmed.text
    assert confirmed.json()["lifecycle"]["status"] == "RESOLVED"
    assert confirmed.json()["lifecycle"]["history"][-1]["evidence_ids"] \
        == ["ev-rc4", "inc-77"]
