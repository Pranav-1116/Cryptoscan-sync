"""CryptoLog reports API tests (docs/cryptolog/01_PRODUCT_SPEC.md, §9).

The auditor pack: one archive whose manifest hashes every file — an
examiner proves the pack is untouched, and a missing artifact is
unverifiable, not valid. The verify endpoint says exactly that.
"""

from __future__ import annotations

import io
import json
import zipfile

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from shared_models.report_manifest import (
    ARTIFACT_UNVERIFIABLE, DIGEST_MISMATCH, VALID, verify_manifest,
    verify_manifest_files,
)


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


def _export(api, body=None):
    res = api.post("/api/v1/cryptolog/reports/export", json=body or {})
    assert res.status_code == 200, res.text
    archive = zipfile.ZipFile(io.BytesIO(res.content))
    names = set(archive.namelist())
    docs = {}
    for name in names:
        docs[name] = archive.read(name)
    manifest = json.loads(docs["manifest.json"])
    return res, manifest, docs


def test_the_auditor_pack_hashes_every_file_and_states_its_boundaries(api):
    api.post("/api/v1/cryptolog/events", json=_event_dict(event_id="event_001"))
    api.post("/api/v1/cryptolog/events", json=_event_dict(event_id="event_002"))
    res, manifest, docs = _export(api)

    assert res.headers["X-Report-Id"] == manifest["report_id"]
    assert set(docs) == {"events.json", "alerts.json", "integrity.json",
                         "report.md", "manifest.json"}
    verify_manifest(manifest)
    assert manifest["totals"]["events"] == 2
    assert manifest["filters"]["start_occurred"] is None

    for name, meta in manifest["files"].items():
        assert meta["sha256"] and meta["bytes"] == len(docs[name]), \
            "every artifact carries its digest and size"

    verdict = verify_manifest_files(manifest, docs)
    assert verdict["verified"] is True

    report = docs["report.md"].decode("utf-8")
    assert "What is proven" in report and "What is NOT proven" in report
    assert "source validation is separate" in report
    integrity = json.loads(docs["integrity.json"])
    assert integrity["verification"]["overall_state"] == "CHECKPOINT_MISSING", \
        "an uncheckpointed export records UNVERIFIED honestly, never a pass"


def test_export_refuses_a_truncated_alert_register(api, monkeypatch):
    from db.repositories.cryptolog_repository import CryptoLogAlertRepository

    monkeypatch.setattr(
        CryptoLogAlertRepository, "list_alerts",
        lambda self, **kwargs: {"rows": [], "total_count": 1001})
    response = api.post("/api/v1/cryptolog/reports/export", json={})
    assert response.status_code == 409
    assert "partial alert list" in response.json()["detail"]


def test_export_refuses_a_truncated_checkpoint_register(api, monkeypatch):
    from db.repositories.cryptolog_repository import CryptoLogAlertRepository

    monkeypatch.setattr(
        CryptoLogAlertRepository, "list_checkpoints",
        lambda self, **kwargs: {"rows": [], "total_count": 51})
    response = api.post("/api/v1/cryptolog/reports/export", json={})
    assert response.status_code == 409
    assert "partial checkpoint list" in response.json()["detail"]


def test_export_refuses_a_truncated_event_window(api, monkeypatch):
    from db.repositories.cryptolog_repository import CryptoLogAlertRepository

    for ident in ("event-1", "event-2"):
        assert api.post("/api/v1/cryptolog/events", json=_event_dict(
            event_id=ident)).status_code == 201
    original = CryptoLogAlertRepository.events_in_range

    def one_event_budget(self, **kwargs):
        return original(self, **{**kwargs, "max_events": 1})

    monkeypatch.setattr(CryptoLogAlertRepository, "events_in_range",
                        one_event_budget)
    result = api.post("/api/v1/cryptolog/reports/export",
                      json={"tenant_id": "tenant_001"})
    assert result.status_code == 409
    assert "partial chain" in result.json()["detail"]


def test_export_uses_resolved_tenant_and_refuses_foreign_selection(api):
    from db.tenancy import tenant_scope

    api.post("/api/v1/cryptolog/events", json=_event_dict(event_id="event-owned"))
    with tenant_scope("tenant_001"):
        _, manifest, _ = _export(api)
        forged = api.post("/api/v1/cryptolog/reports/export",
                          json={"tenant_id": "tenant_002"})
    assert manifest["tenant_id"] == "tenant_001"
    assert manifest["scope"] == "tenant_001"
    assert forged.status_code == 403


def test_export_refuses_unsupported_filter_and_mixed_chains(api):
    assert api.post("/api/v1/cryptolog/reports/export",
                    json={"category": "TLS"}).status_code == 422
    api.post("/api/v1/cryptolog/events", json=_event_dict(
        event_id="event-a", tenant_id="tenant_001"))
    api.post("/api/v1/cryptolog/events", json=_event_dict(
        event_id="event-b", tenant_id="tenant_002"))
    mixed = api.post("/api/v1/cryptolog/reports/export", json={})
    assert mixed.status_code == 409, mixed.text
    assert "multiple ledger partitions" in mixed.json()["detail"]


def test_a_missing_artifact_is_unverifiable_never_valid(api):
    api.post("/api/v1/cryptolog/events", json=_event_dict(event_id="event_001"))
    _, manifest, docs = _export(api)
    del docs["events.json"]
    verdict = verify_manifest_files(manifest, docs)
    assert verdict["verified"] is False
    assert verdict["files"]["events.json"] == ARTIFACT_UNVERIFIABLE
    assert verdict["files"]["report.md"] == VALID
    assert "unverifiable, not valid" in verdict["problems"][0]["detail"]


def test_a_changed_artifact_is_a_named_mismatch(api):
    api.post("/api/v1/cryptolog/events", json=_event_dict(event_id="event_001"))
    _, manifest, docs = _export(api)
    docs["events.json"] = b'{"tampered": true}'
    verdict = verify_manifest_files(manifest, docs)
    assert verdict["verified"] is False
    assert verdict["files"]["events.json"] == DIGEST_MISMATCH


def test_the_verify_endpoint_says_what_an_examiner_needs(api):
    api.post("/api/v1/cryptolog/events", json=_event_dict(event_id="event_001"))
    _, manifest, docs = _export(api)
    documents = {
        name: json.loads(blob) if name.endswith(".json") else blob.decode("utf-8")
        for name, blob in docs.items() if name != "manifest.json"
    }

    ok = api.post("/api/v1/cryptolog/reports/verify",
                  json={"manifest": manifest, "documents": documents})
    assert ok.status_code == 200, ok.text
    assert ok.json()["verified"] is True

    missing = dict(documents)
    missing.pop("alerts.json")
    verdict = api.post("/api/v1/cryptolog/reports/verify",
                       json={"manifest": manifest, "documents": missing}).json()
    assert verdict["verified"] is False
    assert verdict["files"]["alerts.json"] == "ARTIFACT_UNVERIFIABLE"
    assert "unverifiable, not valid" in verdict["note"]

    tampered = dict(documents)
    tampered["events.json"] = {"schema": "tampered", "events": []}
    verdict = api.post("/api/v1/cryptolog/reports/verify",
                       json={"manifest": manifest, "documents": tampered}).json()
    assert verdict["verified"] is False
    assert verdict["files"]["events.json"] == "DIGEST_MISMATCH"


def test_the_export_window_travels_in_the_manifest_filters(api):
    api.post("/api/v1/cryptolog/events", json=_event_dict(
        event_id="event_001", observation={"observed_at": AS_OF}))
    _, manifest, docs = _export(api, {
        "start_occurred": "2026-11-01", "end_occurred": "2026-11-30",
    })
    assert manifest["filters"]["start_occurred"] == "2026-11-01"
    events_doc = json.loads(docs["events.json"])
    assert events_doc["window"]["start_occurred"] == "2026-11-01"
