"""Intelligence API — the boundary properties of the roadmap wiring.

The unit suites prove the shared models. These prove what only exists at the
router: detectors over real rows fire only with evidence and explain the ones
that did not run; the risk endpoint refuses to score quantum urgency without
the caller's threat horizon; unknown dimensions are UNKNOWN, never zero; PQC
support-derived claims never read as readiness; and a simulation refuses to
start without an explicitly selected versioned snapshot and stays hypothetical.

The harness is a real SQLite session with real rows — a MagicMock would happily
"find" findings nobody recorded.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

NOW = datetime(2026, 11, 7, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture()
def session(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401 — registers every model on the metadata
    from db.models.base import Base
    from db.models.certificate import Certificate
    from db.models.crypto_asset import CryptoAsset
    from db.models.crypto_asset_evidence import CryptoAssetEvidence
    from db.models.crypto_live import CryptoLiveState
    from db.models.evidence_record import EvidenceRecord
    from db.models.graph_snapshot import GraphSnapshot

    engine = create_engine(f"sqlite:///{tmp_path / 'intel.db'}")
    Base.metadata.create_all(engine, tables=[
        CryptoAsset.__table__,
        CryptoAssetEvidence.__table__,
        EvidenceRecord.__table__,
        CryptoLiveState.__table__,
        Certificate.__table__,
        GraphSnapshot.__table__,
    ])
    factory = sessionmaker(bind=engine)
    db = factory()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


@pytest.fixture()
def api(session):
    from api import dependencies
    from api.routers import roadmap_intelligence

    app = FastAPI()
    app.include_router(roadmap_intelligence.router, prefix="/api")
    app.dependency_overrides[dependencies.get_db_session] = lambda: session
    app.dependency_overrides[dependencies.get_current_user] = lambda: {
        "username": "auditor"}
    return TestClient(app)


def add_cert(db, *, fingerprint: str, days):
    from db.models.certificate import Certificate
    row = Certificate(fingerprint_sha256=fingerprint, subject=f"cn={fingerprint}",
                      days_until_expiry=days)
    db.add(row)
    db.commit()


def add_live(db, *, asset_id: str, algorithms, usage=None, protocols=None,
             last_seen=NOW):
    from db.models.crypto_live import CryptoLiveState
    row = CryptoLiveState(asset_id=asset_id, algorithms=algorithms,
                          usage=usage, protocols=protocols,
                          last_seen=last_seen)
    db.add(row)
    db.commit()


def add_asset(db, *, asset_id: str, algorithm: str, key_size=None):
    from db.models.crypto_asset import CryptoAsset
    row = CryptoAsset(id=asset_id, algorithm=algorithm, key_size=key_size,
                      file_path="src/app.py")
    db.add(row)
    db.commit()
    return row


def add_snapshot(db, *, version: int, edges):
    from db.models.graph_snapshot import GraphSnapshot
    row = GraphSnapshot(version=version, fingerprint=f"fp{version}" * 2,
                        edges=edges, nodes=[])
    db.add(row)
    db.commit()
    return row


class TestFindings:

    def test_a_certificate_near_expiry_becomes_a_full_finding(self, api, session):
        add_cert(session, fingerprint="aa" * 32, days=5)
        body = api.get("/api/intelligence/findings").json()
        finding = next(f for f in body["findings"]
                       if f["class"] == "CERTIFICATE_RISK")
        assert finding["asset"] == "cn=" + "aa" * 32
        assert finding["evidence_ids"] == ["aa" * 32]
        assert finding["not_proven"].strip()
        assert finding["investigate"].strip()
        assert finding["compromise_declared"] is False
        assert "CERTIFICATE_RISK" in body["detectors_fired"]

    def test_an_undated_certificate_is_unknown_not_safe(self, api, session):
        add_cert(session, fingerprint="bb" * 32, days=None)
        body = api.get("/api/intelligence/findings").json()
        finding = next(f for f in body["findings"]
                       if f["class"] == "CERTIFICATE_RISK")
        assert "could not be determined" in finding["what_changed"]
        assert "does not prove" in finding["not_proven"]

    def test_capability_sightings_are_never_exposure(self, api, session):
        add_live(session, asset_id="svc-1", algorithms={"MD5": 1})
        body = api.get("/api/intelligence/findings").json()
        assert not any(f["class"] == "WEAK_ALGORITHM_EXPOSURE"
                       for f in body["findings"])
        # and the absence is explained, not silent
        assert "capability-only sightings are not exposure" in (
            body["detectors_not_fired"]["WEAK_ALGORITHM_EXPOSURE"])

    def test_live_weak_use_fires_the_exposure_detector(self, api, session):
        add_live(session, asset_id="svc-1", algorithms={"MD5": 1},
                 usage={"MD5": "OBSERVED"})
        body = api.get("/api/intelligence/findings").json()
        finding = next(f for f in body["findings"]
                       if f["class"] == "WEAK_ALGORITHM_EXPOSURE")
        assert finding["asset"] == "svc-1"
        assert finding["evidence_ids"] == ["live:svc-1"]

    def test_every_threat_class_is_accounted_for(self, api, session):
        body = api.get("/api/intelligence/findings").json()
        from shared_models.threat_intelligence import THREAT_CLASSES
        accounted = set(body["detectors_fired"]) | set(body["detectors_not_fired"])
        assert accounted == set(THREAT_CLASSES)
        assert "never an all-clear" in body["note"]


class TestRisk:

    def test_the_threat_horizon_is_a_required_policy_input(self, api, session):
        add_asset(session, asset_id="a1", algorithm="RSA-2048")
        response = api.get("/api/intelligence/risk/a1")
        assert response.status_code == 422  # no horizon, no score

    def test_dimensions_stay_separate_and_unknown_is_never_zero(self, api, session):
        add_asset(session, asset_id="a1", algorithm="RSA-2048", key_size=2048)
        body = api.get(
            "/api/intelligence/risk/a1?quantum_threat_horizon_years=5").json()
        assert body["dimensions"]["CRYPTO_RISK"]["known"] is True
        assert body["dimensions"]["QUANTUM_URGENCY"]["known"] is True
        assert body["blended_score"] is None          # never blended by default
        vendor = body["dimensions"]["VENDOR_RISK"]
        assert vendor["score"] is None
        assert "never zero" in vendor["reason"]
        dependency = body["dimensions"]["OPERATIONAL_DEPENDENCY"]
        assert dependency["score"] is None
        assert "never assumed zero" in dependency["reason"]

    def test_unknown_assets_get_404_not_a_clean_report(self, api):
        assert api.get(
            "/api/intelligence/risk/ghost?quantum_threat_horizon_years=5"
        ).status_code == 404


class TestPqcClaims:

    def test_support_is_never_readiness(self, api, session):
        add_live(session, asset_id="payments-api",
                 algorithms={"ML-KEM-768": 1})
        body = api.get("/api/intelligence/pqc/claims").json()
        entry = body["subjects"]["payments-api"]
        assert entry["readiness"] == "SUPPORT_ONLY"
        assert "not PQC readiness" in entry["readiness_reason"]
        assert entry["stages"]["SUPPORT_AVAILABLE"]["state"] == "CLAIMED"
        assert entry["stages"]["MIGRATION_VALIDATED"]["state"] == "NOT_CLAIMED"

    def test_runtime_use_is_a_separate_stage(self, api, session):
        add_live(session, asset_id="payments-api",
                 algorithms={"ML-KEM-768": 1},
                 usage={"ML-KEM-768": "OBSERVED"})
        body = api.get("/api/intelligence/pqc/claims").json()
        entry = body["subjects"]["payments-api"]
        assert entry["stages"]["RUNTIME_OBSERVED"]["state"] == "CLAIMED"
        assert entry["readiness"] == "OBSERVED_NOT_VALIDATED"
        assert "MIGRATION_VALIDATED is never derived" in body["derived_from"]

    def test_a_subject_filter_narrows_the_report(self, api, session):
        add_live(session, asset_id="a", algorithms={"ML-DSA-65": 1})
        add_live(session, asset_id="b", algorithms={"ML-DSA-65": 1})
        body = api.get("/api/intelligence/pqc/claims?subject=a").json()
        assert list(body["subjects"]) == ["a"]


class TestSimulation:

    def test_a_simulation_refuses_without_a_selected_snapshot(self, api):
        response = api.post("/api/intelligence/simulation", json={
            "scenario": "CA_COMPROMISE", "focal_asset": "cert-1"})
        assert response.status_code == 422
        assert "versioned snapshot" in str(response.json())

    def test_an_unknown_scenario_is_refused(self, api, session):
        add_snapshot(session, version=1, edges=[])
        response = api.post("/api/intelligence/simulation", json={
            "scenario": "MADE_UP", "focal_asset": "x", "snapshot_version": 1})
        assert response.status_code == 422
        assert "unknown scenario" in str(response.json())

    def test_the_run_is_hypothetical_and_names_its_snapshot(self, api, session):
        add_snapshot(session, version=3, edges=[
            {"from": "lb-1", "to": "cert-1", "label": "uses"},
        ])
        body = api.post("/api/intelligence/simulation", json={
            "scenario": "CA_COMPROMISE", "focal_asset": "cert-1",
            "snapshot_version": 3}).json()
        assert body["result_kind"] == "SIMULATION"
        assert body["hypothetical"] is True
        assert body["snapshot"]["version"] == 3
        assert "never be shown as a real production change" in body["note"]

    def test_edges_without_evidence_are_assumed_never_proven(self, api, session):
        add_snapshot(session, version=4, edges=[
            {"from": "lb-1", "to": "cert-1", "label": "uses"},
        ])
        body = api.post("/api/intelligence/simulation", json={
            "scenario": "CA_COMPROMISE", "focal_asset": "cert-1",
            "snapshot_version": 4}).json()
        assumed = {row["asset"] for row in body["assumed_dependencies"]}
        proven = {row["asset"] for row in body["proven_dependencies"]}
        assert "lb-1" in assumed
        assert proven == set()
        assert "never shown as proven" in body["evidence_note"]

    def test_a_missing_snapshot_is_404(self, api, session):
        add_snapshot(session, version=1, edges=[])
        assert api.post("/api/intelligence/simulation", json={
            "scenario": "KMS_OUTAGE", "focal_asset": "x",
            "snapshot_version": 99}).status_code == 404
