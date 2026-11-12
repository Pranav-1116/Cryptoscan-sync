"""CryptoLog Phase-5 reads: the deterministic rule catalogue and event
correlation (docs/cryptolog/01_PRODUCT_SPEC.md §8, and the eight-workspace
design: Event Rules & Detection, Event Correlation).

A rule is a detection, never a verdict. A correlation group is a pattern in
the recorded store: shared evidence references and recorded asset identity
are evidence-backed; a shared algorithm name is a hypothesis of possible
dependency, never an established edge. An empty result is absence of
recorded correlation, never proof that nothing relates.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

AS_OF = "2026-11-12T10:00:00Z"


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


def _ingest(api, **over):
    response = api.post("/api/v1/cryptolog/events", json=_event_dict(**over))
    assert response.status_code == 201, response.text
    return response.json()["event"]["event_id"]


def test_rules_catalogue_lists_deterministic_detections(api):
    response = api.get("/api/v1/cryptolog/rules")
    assert response.status_code == 200, response.text
    body = response.json()
    ids = [r["rule_id"] for r in body["rules"]]
    assert ids == sorted(ids), "the catalogue is presented in stable order"
    assert "CL-002" in ids
    weak = next(r for r in body["rules"] if r["rule_id"] == "CL-002")
    assert weak["detection"] == "Weak cipher suite observed"
    assert weak["investigation"], "every rule states its investigation"
    assert "a detection, never a verdict" in body["note"]
    assert "unmeasured, never clean" in body["note"]


def test_correlation_groups_shared_evidence_and_names_the_basis(api):
    first = _ingest(api, event_id="EV-A",
                    evidence={"evidence_ids": ["ev-shared"]},
                    asset_id="asset_a")
    second = _ingest(api, event_id="EV-B",
                     evidence={"evidence_ids": ["ev-shared"]},
                     asset_id="asset_b")
    _ingest(api, event_id="EV-SOLO",
            evidence={"evidence_ids": ["ev-solo"]}, asset_id="asset_c")

    response = api.get("/api/v1/cryptolog/correlation")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["event_count"] == 3
    shared = [g for g in body["groups"] if g["basis"] == "shared_evidence"]
    assert shared, "events carrying one evidence reference correlate"
    group = shared[0]
    assert group["key"] == "ev-shared"
    assert group["event_ids"] == sorted([first, second])
    assert group["asset_ids"] == ["asset_a", "asset_b"]
    assert group["evidence_backed"] is True
    assert "shared evidence" in group["note"]


def test_shared_algorithm_is_a_hypothesis_never_an_edge(api):
    _ingest(api, event_id="EV-1",
            cryptographic_context={"protocol": "TLS", "algorithm": "RSA",
                                   "evidence_level": "NETWORK_NEGOTIATED"},
            evidence={"evidence_ids": ["ev-1"]}, asset_id="asset_a")
    _ingest(api, event_id="EV-2",
            cryptographic_context={"protocol": "TLS", "algorithm": "RSA",
                                   "evidence_level": "NETWORK_NEGOTIATED"},
            evidence={"evidence_ids": ["ev-2"]}, asset_id="asset_b")

    body = api.get("/api/v1/cryptolog/correlation").json()
    algorithm_groups = [g for g in body["groups"] if g["basis"] == "shared_algorithm"]
    assert algorithm_groups, "a repeated algorithm name is a recorded pattern"
    group = algorithm_groups[0]
    assert group["key"] == "RSA"
    assert group["event_ids"] == ["EV-1", "EV-2"]
    assert group["evidence_backed"] is False, \
        "a name match is never evidence-backed"
    assert "never an established edge" in group["note"]
    assert "possible dependency" in group["note"]
    assert "never proof that nothing relates" in body["note"]


def test_same_asset_events_correlate_on_recorded_identity(api):
    _ingest(api, event_id="EV-1", asset_id="asset_hsm",
            evidence={"evidence_ids": ["ev-1"]})
    _ingest(api, event_id="EV-2", asset_id="asset_hsm",
            evidence={"evidence_ids": ["ev-2"]})

    body = api.get("/api/v1/cryptolog/correlation").json()
    asset_groups = [g for g in body["groups"] if g["basis"] == "shared_asset"]
    assert asset_groups and asset_groups[0]["key"] == "asset_hsm"
    assert asset_groups[0]["event_ids"] == ["EV-1", "EV-2"]
    assert asset_groups[0]["evidence_backed"] is True
    assert "never inferred" in asset_groups[0]["note"]


def test_empty_store_is_absence_of_recorded_correlation_never_proof(api):
    body = api.get("/api/v1/cryptolog/correlation").json()
    assert body["groups"] == []
    assert body["event_count"] == 0
    assert body["groups_truncated"] is False
    assert "never proof that nothing relates" in body["note"]


def test_correlation_never_invents_events(api):
    ingested = {_ingest(api, event_id=f"EV-{i}",
                        evidence={"evidence_ids": [f"ev-{i % 2}"]},
                        asset_id=f"asset_{i % 3}")
                for i in range(4)}
    body = api.get("/api/v1/cryptolog/correlation").json()
    for group in body["groups"]:
        assert set(group["event_ids"]) <= ingested, \
            "a correlation group names recorded events only"
        assert group["event_count"] == len(group["event_ids"])
