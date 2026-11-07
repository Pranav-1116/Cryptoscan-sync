"""CryptoLog alert listing and integrity API tests (docs/cryptolog/01_PRODUCT_SPEC.md,
sections 5 and 11).

Honest totals, append-only transitions with the CONFIRMED_INCIDENT bar,
checkpoints that refuse to sign without a key, verification that reports
UNVERIFIED honestly and never trusts an unverifiable checkpoint, and a
merkle proof that verifies against the checkpoint root.
"""

from __future__ import annotations

import os

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
                                  "protocol_version": "TLS1.2",
                                  "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                                  "evidence_level": "NETWORK_NEGOTIATED"},
        "observation": {"observed_at": AS_OF},
        "evidence": {"evidence_ids": ["evidence_001"]},
    }
    base.update(over)
    return base


def _weak_alert_event(event_id: str):
    """A weak-cipher negotiation — CL-002 names its driver."""
    return _event_dict(event_id=event_id,
                       cryptographic_context={
                           "protocol": "TLS",
                           "protocol_version": "TLS1.2",
                           "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                           "evidence_level": "NETWORK_NEGOTIATED"},
                       evidence={"evidence_ids": ["evidence_001"]})


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
    client = TestClient(app)
    client.db_session = session
    return client


@pytest.fixture()
def signing_key(monkeypatch):
    monkeypatch.setenv("CRYPTOLOG_CHECKPOINT_SECRET", "test-secret-key")
    monkeypatch.setenv("CRYPTOLOG_SIGNER_ID", "test-signer")
    return "test-secret-key"


@pytest.fixture()
def no_signing_key(monkeypatch):
    monkeypatch.delenv("CRYPTOLOG_CHECKPOINT_SECRET", raising=False)
    monkeypatch.delenv("CRYPTOLOG_SIGNER_ID", raising=False)


# ---------------------------------------------------------------------------
# Alert listing and lifecycle
# ---------------------------------------------------------------------------


def test_alert_listing_is_honest_when_empty(api):
    res = api.get("/api/v1/cryptolog/alerts")
    assert res.status_code == 200
    body = res.json()
    assert body["total_count"] == 0
    assert body["rows"] == []
    assert res.headers["X-Total-Count"] == "0", \
        "an empty corpus is zero alerts, never a page size mistaken for a total"


def test_evaluate_persists_alerts_and_listing_filters_honestly(api):
    res = api.post("/api/v1/cryptolog/alerts/evaluate",
                   json={"events": [_weak_alert_event("event_001")]})
    assert res.status_code == 200, res.text
    alerts = res.json()["alerts"]
    assert res.json()["persisted"]["INSERTED"] == len(alerts) >= 1
    for alert in alerts:
        assert alert["what_is_proven"] and alert["what_is_not_proven"], \
            "every alert states what is proven AND what is not proven"

    listing = api.get("/api/v1/cryptolog/alerts").json()
    assert listing["total_count"] == len(alerts)
    assert len(listing["rows"]) == len(alerts)

    rule = alerts[0]["rule_id"]
    filtered = api.get(f"/api/v1/cryptolog/alerts?rule_id={rule}").json()
    assert filtered["total_count"] >= 1
    empty = api.get("/api/v1/cryptolog/alerts?rule_id=CL-999").json()
    assert empty["total_count"] == 0 and empty["rows"] == [], \
        "a filter that matches nothing reports zero — never an invented total"

    again = api.post("/api/v1/cryptolog/alerts/evaluate",
                     json={"events": [_weak_alert_event("event_001")]})
    assert again.json()["persisted"]["DUPLICATE"] == len(alerts), \
        "re-evaluation is idempotent per alert identity"


def test_alert_detail_and_unknown_alert_404(api):
    created = api.post("/api/v1/cryptolog/alerts/evaluate",
                       json={"events": [_weak_alert_event("event_001")]}).json()
    alert_id = created["alerts"][0]["alert_id"]
    res = api.get(f"/api/v1/cryptolog/alerts/{alert_id}")
    assert res.status_code == 200
    assert res.json()["alert_id"] == alert_id
    missing = api.get("/api/v1/cryptolog/alerts/alert_missing_999")
    assert missing.status_code == 404, \
        "a missing alert is a named absence, never an empty success"


def _open_alert(api):
    created = api.post("/api/v1/cryptolog/alerts/evaluate",
                       json={"events": [_weak_alert_event("event_001")]}).json()
    return created["alerts"][0]["alert_id"]


def test_transition_is_append_only(api):
    alert_id = _open_alert(api)
    first = api.post(f"/api/v1/cryptolog/alerts/{alert_id}/transition",
                     json={"action": "ACKNOWLEDGE", "actor": "analyst_lin",
                           "at": AS_OF, "note": "reviewing"})
    assert first.status_code == 201, first.text
    row = first.json()
    assert row["state"] == "ACKNOWLEDGED"
    assert len(row["transitions"]) == 1

    second = api.post(f"/api/v1/cryptolog/alerts/{alert_id}/transition",
                      json={"action": "REOPEN", "actor": "analyst_lin",
                            "at": AS_OF, "note": "re-examining"})
    assert second.status_code == 201
    history = second.json()["transitions"]
    assert len(history) == 2, "history grows, never rewrites"
    assert history[0]["action"] == "ACKNOWLEDGE", \
        "the earlier entry survives the later transition byte-identical"


def test_confirmed_incident_demands_named_actor_and_evidence(api):
    alert_id = _open_alert(api)
    refused = api.post(f"/api/v1/cryptolog/alerts/{alert_id}/transition",
                       json={"action": "RESOLVE", "actor": "analyst_lin",
                             "at": AS_OF, "note": "confirmed",
                             "resolution": "CONFIRMED_INCIDENT"})
    assert refused.status_code == 422
    assert "demands evidence" in refused.json()["detail"], \
        "the engine never declares a compromise without named evidence"

    accepted = api.post(f"/api/v1/cryptolog/alerts/{alert_id}/transition",
                        json={"action": "RESOLVE", "actor": "analyst_lin",
                              "at": AS_OF, "note": "evidence reviewed",
                              "resolution": "CONFIRMED_INCIDENT",
                              "evidence_ids": ["evidence_042"]})
    assert accepted.status_code == 201
    assert accepted.json()["state"] == "RESOLVED"


# ---------------------------------------------------------------------------
# Integrity: checkpoints, verification, proofs
# ---------------------------------------------------------------------------


def test_checkpoint_refuses_without_a_signing_key(api, no_signing_key):
    res = api.post("/api/v1/cryptolog/integrity/checkpoint",
                   json={"checkpoint_ref": "cp_001",
                         "retention_ref": "WORM:retention-7y"})
    assert res.status_code == 503
    assert "cannot be honestly signed" in res.json()["detail"], \
        "no key means a refusal, never an unsigned checkpoint sold as signed"


def test_checkpoint_signs_and_verify_reports_the_full_state(api, signing_key):
    for i in (1, 2):
        res = api.post("/api/v1/cryptolog/events", json=_weak_alert_event(f"event_{i:03d}"))
        assert res.status_code == 201, res.text
    cp = api.post("/api/v1/cryptolog/integrity/checkpoint",
                  json={"checkpoint_ref": "cp_001",
                        "retention_ref": "WORM:retention-7y"})
    assert cp.status_code == 201, cp.text
    body = cp.json()["checkpoint"]
    assert body["leaf_count"] == 2
    assert body["signature"], "a checkpoint is signed, not merely recorded"
    assert body["retention_ref"] == "WORM:retention-7y"

    verify = api.post("/api/v1/cryptolog/integrity/verify",
                      json={"checkpoint_ref": "cp_001"})
    assert verify.status_code == 200
    result = verify.json()
    assert result["input"]["checkpoint_signature_verified"] is True
    assert result["overall_state"] == "VERIFIED", result
    assert "relative to the trusted checkpoint" in result["note"], \
        "integrity is proven relative to the checkpoint — the sources still need validation"


def test_verify_without_checkpoint_is_honestly_unverified(api, signing_key):
    api.post("/api/v1/cryptolog/events", json=_weak_alert_event("event_001"))
    result = api.post("/api/v1/cryptolog/integrity/verify", json={}).json()
    assert result["overall_state"] == "CHECKPOINT_MISSING"
    assert "never VERIFIED" in result["note"]


def test_verify_never_trusts_an_unverifiable_checkpoint(api, signing_key):
    api.post("/api/v1/cryptolog/events", json=_weak_alert_event("event_001"))
    api.post("/api/v1/cryptolog/integrity/checkpoint",
             json={"checkpoint_ref": "cp_001", "retention_ref": "WORM:7y"})
    os.environ.pop("CRYPTOLOG_CHECKPOINT_SECRET", None)  # key withdrawn later
    result = api.post("/api/v1/cryptolog/integrity/verify",
                      json={"checkpoint_ref": "cp_001"}).json()
    assert result["input"]["checkpoint_signature_verified"] is False
    assert result["overall_state"] == "SIGNATURE_INVALID", \
        "an unverifiable checkpoint never earns VERIFIED"


def test_verify_detects_a_tampered_event(api, signing_key):
    for i in (1, 2):
        api.post("/api/v1/cryptolog/events", json=_weak_alert_event(f"event_{i:03d}"))
    api.post("/api/v1/cryptolog/integrity/checkpoint",
             json={"checkpoint_ref": "cp_001", "retention_ref": "WORM:7y"})
    from db.models.cryptolog import CryptoLogEvent
    row = api.db_session.query(CryptoLogEvent).filter(
        CryptoLogEvent.event_id == "event_002").one()
    row.severity = "INFO"          # touch a tracked column …
    row.attributes = {"observed": AS_OF, "tampered": "yes"}  # … and the payload
    api.db_session.flush()

    result = api.post("/api/v1/cryptolog/integrity/verify",
                      json={"checkpoint_ref": "cp_001"}).json()
    assert result["overall_state"] == "INVALID_HASH", result
    assert result["note"]


def test_merkle_proof_verifies_against_the_checkpoint(api, signing_key):
    for i in (1, 2, 3):
        api.post("/api/v1/cryptolog/events", json=_weak_alert_event(f"event_{i:03d}"))
    api.post("/api/v1/cryptolog/integrity/checkpoint",
             json={"checkpoint_ref": "cp_001", "retention_ref": "WORM:7y"})
    proof = api.get("/api/v1/cryptolog/integrity/merkle-proof"
                    "?event_id=event_002&checkpoint_ref=cp_001")
    assert proof.status_code == 200, proof.text
    body = proof.json()
    assert body["verified"] is True
    stored = api.get("/api/v1/cryptolog/events/event_002").json()
    assert body["event_hash"] == event_hash(stored), \
        "the proof names the exact hash it covers"

    outside = api.get("/api/v1/cryptolog/integrity/merkle-proof"
                      "?event_id=event_999&checkpoint_ref=cp_001")
    assert outside.status_code == 404, \
        "an event outside the window is a named absence, never a proof of nothing"


def test_checkpoint_creation_is_idempotent(api, signing_key):
    payload = {"checkpoint_ref": "cp_001", "retention_ref": "WORM:7y"}
    first = api.post("/api/v1/cryptolog/integrity/checkpoint", json=payload)
    assert first.status_code == 201
    second = api.post("/api/v1/cryptolog/integrity/checkpoint", json=payload)
    assert second.status_code == 200
    assert second.json()["outcome"] == "DUPLICATE"
    listing = api.get("/api/v1/cryptolog/integrity/checkpoints").json()
    assert listing["total_count"] == 1
