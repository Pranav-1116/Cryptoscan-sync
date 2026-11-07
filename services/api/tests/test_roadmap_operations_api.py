"""Roadmap operations API — persistence proves the last three roadmap lines.

The unit suites prove the shared models. These prove what only exists at the
router: governance state moves only through audited transitions; deployment
readiness is computed from filed attestations + custody, and empty is "not
verified" never "ready"; a support claim is answered from filed qualification
records; external validations are filed evidence of acts performed elsewhere —
the platform never marks them done and never turns NOT_FILED into a pass; and
estate coverage computes from a filed batch, with no batch read as
NOT_FILED — never as zeros.

The harness is a real SQLite session with real rows.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture()
def session(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401 — registers every model on the metadata
    from db.models.base import Base
    from db.models.roadmap_coverage import CoverageReport
    from db.models.roadmap_deployment import (
        DeploymentAttestation, DeploymentCustodyEntry)
    from db.models.roadmap_governance import GovernanceTicket
    from db.models.roadmap_qualification import (
        DiscoveryQualification, ExternalValidation)

    engine = create_engine(f"sqlite:///{tmp_path / 'ops.db'}")
    Base.metadata.create_all(engine, tables=[
        GovernanceTicket.__table__,
        DeploymentAttestation.__table__,
        DeploymentCustodyEntry.__table__,
        DiscoveryQualification.__table__,
        ExternalValidation.__table__,
        CoverageReport.__table__,
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
    from api.routers import roadmap_operations

    app = FastAPI()
    app.include_router(roadmap_operations.router, prefix="/api")
    app.dependency_overrides[dependencies.get_db_session] = lambda: session
    app.dependency_overrides[dependencies.get_current_user] = lambda: {
        "username": "auditor"}
    return TestClient(app)


# ---------------------------------------------------------------- governance

class TestGovernanceWorkflow:

    def test_a_ticket_moves_only_through_audited_transitions(self, api):
        created = api.post("/api/intelligence/governance/tickets", json={
            "subject": "rotate the root CA", "role": "PLATFORM_ADMIN",
            "actor": "ana"}).json()
        assert created["state"] == "OPEN"

        wrong_role = api.post(
            f"/api/intelligence/governance/tickets/"
            f"{created['ticket_id']}/transition",
            json={"action": "ASSIGN", "role": "AUDITOR", "actor": "eve",
                  "assignee": "boris"})
        assert wrong_role.status_code == 422

        assigned = api.post(
            f"/api/intelligence/governance/tickets/"
            f"{created['ticket_id']}/transition",
            json={"action": "ASSIGN", "role": "PLATFORM_ADMIN", "actor": "ana",
                  "assignee": "boris"}).json()
        assert assigned["state"] == "ASSIGNED"
        assert assigned["assignee"] == "boris"

        fetched = api.get(
            f"/api/intelligence/governance/tickets/"
            f"{created['ticket_id']}").json()
        assert fetched["audit_verified"] is True
        assert [e["action"] for e in fetched["ticket"]["audit"]] == [
            "OPEN_TICKET", "ASSIGN"]

    def test_an_authorization_without_an_expiry_is_refused(self, api):
        created = api.post("/api/intelligence/governance/tickets", json={
            "subject": "accept the RSA-2048 residual", "role": "CRYPTO_ENGINEER",
            "actor": "cy"}).json()
        for action, role in (("ASSIGN", "PLATFORM_ADMIN"), ("START",
                                                            "CRYPTO_ENGINEER")):
            api.post(f"/api/intelligence/governance/tickets/"
                     f"{created['ticket_id']}/transition",
                     json={"action": action, "role": role, "actor": "cy",
                           "assignee": "cy"})
        refused = api.post(
            f"/api/intelligence/governance/tickets/"
            f"{created['ticket_id']}/transition",
            json={"action": "ACCEPT_RISK", "role": "EXECUTIVE", "actor": "ceo",
                  "evidence_ids": ["RISK-MEMO-7"]})
        assert refused.status_code == 422
        assert "expir" in refused.json()["detail"].lower()


# ------------------------------------------------------- deployment controls

def custody_payload():
    return [{"custody_class": cls, "controller": "BANK",
             "location": "bank DC, bank-controlled vault"}
            for cls in ("database", "evidence", "crypto_metadata")]


def attest_all_controls(api, *, evidence="DRILL-1"):
    from shared_models.deployment_controls import CONTROLS
    for control in CONTROLS:
        assert api.post("/api/intelligence/deployment/attestations", json={
            "control": control, "status": "OK",
            "evidence_ids": [evidence],
            "observed_at": "2026-11-01T02:00:00+00:00",
            "actor": "infra", "note": "drill log filed"}).status_code == 200


class TestDeploymentControls:

    def test_no_attestations_is_not_verified_never_ready(self, api):
        report = api.get("/api/intelligence/deployment/readiness").json()
        assert report["verdict"] != "DEPLOYMENT_READY"
        assert "not verified" in report["source"]

    def test_fileed_attestations_and_bank_custody_reach_ready(self, api):
        assert api.put("/api/intelligence/deployment/custody",
                       json=custody_payload()).json()["stored"] == 3
        attest_all_controls(api)
        report = api.get("/api/intelligence/deployment/readiness").json()
        assert report["verdict"] == "DEPLOYMENT_READY"
        assert report["custody"]["database"]["controller"] == "BANK"

    def test_a_failed_drill_stays_visible_and_keeps_the_control_unready(self,
                                                                       api):
        assert api.put("/api/intelligence/deployment/custody",
                       json=custody_payload()).status_code == 200
        attest_all_controls(api)
        failed = api.post("/api/intelligence/deployment/attestations", json={
            "control": "DATA_CUSTODY", "status": "FAILED",
            "evidence_ids": ["DRILL-FAIL-2"], "observed_at":
                "2026-11-02T02:00:00+00:00", "actor": "infra"}).json()
        assert failed["status"] == "FAILED"
        report = api.get("/api/intelligence/deployment/readiness").json()
        assert report["verdict"] != "DEPLOYMENT_READY"
        assert "DATA_CUSTODY" in str(report)


# --------------------------------------------------- discovery qualification

class TestDiscoveryQualification:

    def test_a_fixture_is_not_a_support_claim_and_revoked_beats_older_pass(
            self, api):
        assert api.post("/api/intelligence/qualification", json={
            "collector": "windows-cng", "family": "windows-capi-cng-schannel",
            "state": "FIXTURE_VERIFIED",
            "evidence_ids": ["CI-FIXTURE-1"]}).status_code == 200
        claim = api.get("/api/intelligence/qualification/claim",
                        params={"collector": "windows-cng",
                                "family": "windows-capi-cng-schannel"}).json()
        assert claim["claimable"] is False

        assert api.post("/api/intelligence/qualification", json={
            "collector": "windows-cng", "family": "windows-capi-cng-schannel",
            "state": "LIVE_QUALIFIED", "evidence_ids": ["LAB-RUN-9"],
            "observed_at": "2026-11-01T00:00:00+00:00"}).status_code == 200
        claim = api.get("/api/intelligence/qualification/claim",
                        params={"collector": "windows-cng",
                                "family": "windows-capi-cng-schannel"}).json()
        assert claim["claimable"] is True

        assert api.post("/api/intelligence/qualification", json={
            "collector": "windows-cng", "family": "windows-capi-cng-schannel",
            "state": "REVOKED", "observed_at": "2026-11-02T00:00:00+00:00",
            "reason": "regression"}).status_code == 200
        claim = api.get("/api/intelligence/qualification/claim",
                        params={"collector": "windows-cng",
                                "family": "windows-capi-cng-schannel"}).json()
        assert claim["claimable"] is False
        assert "revoked" in claim["reason"].lower()

    def test_a_live_qualification_without_evidence_is_refused(self, api):
        refused = api.post("/api/intelligence/qualification", json={
            "collector": "aws-kms", "family": "cloud-kms",
            "state": "LIVE_QUALIFIED"})
        assert refused.status_code == 422
        assert "trench coat" in refused.json()["detail"]

    def test_the_summary_reports_measured_zeroes(self, api):
        summary = api.get("/api/intelligence/qualification/summary").json()
        family = summary["families"]["linux-openssl-engine"]
        assert family["counts"]["LIVE_QUALIFIED"] == 0
        assert family["claimable_collectors"] == []
        assert "not support" in summary["note"]


# ------------------------------------------------------ external validation

class TestExternalValidationRegister:

    def test_the_register_is_honest_before_anything_is_filed(self, api):
        report = api.get("/api/intelligence/external-validations").json()
        assert report["kinds"]["DR_DRILL"]["status"] == "NOT_FILED"
        assert "not filed is not passed" in \
            report["kinds"]["DR_DRILL"]["reason"]
        assert "never marks them done" in report["note"]

    def test_a_filing_without_evidence_or_a_real_performer_is_refused(
            self, api):
        no_evidence = api.post("/api/intelligence/external-validations", json={
            "kind": "DR_DRILL", "performed_by": "bank DR team",
            "performed_at": "2026-11-01T02:00:00+00:00", "scope": "region pair"})
        assert no_evidence.status_code == 422
        self_performed = api.post("/api/intelligence/external-validations",
                                  json={
            "kind": "DR_DRILL", "performed_by": "CryptoScan",
            "evidence_ids": ["LOG-1"],
            "performed_at": "2026-11-01T02:00:00+00:00", "scope": "region pair"})
        assert self_performed.status_code == 422

    def test_a_filed_act_names_its_external_performer(self, api):
        filed = api.post("/api/intelligence/external-validations", json={
            "kind": "THIRD_PARTY_PEN_TEST", "performed_by": "external auditors",
            "evidence_ids": ["PEN-2026-Q4"],
            "performed_at": "2026-10-15T00:00:00+00:00",
            "scope": "API + agent surface", "result": "PARTIAL"}).json()
        assert filed["filed"] is True
        report = api.get("/api/intelligence/external-validations").json()
        entry = report["kinds"]["THIRD_PARTY_PEN_TEST"]
        assert entry["status"] == "FILED"
        assert entry["latest"]["performed_by"] == "external auditors"
        assert entry["latest"]["result"] == "PARTIAL"
        assert report["kinds"]["SOC2_ISO_AUDIT"]["status"] == "NOT_FILED"


# ------------------------------------------------------------ estate coverage

class TestEstateCoverage:

    def test_no_batch_is_not_filed_never_zeros(self, api):
        report = api.get("/api/intelligence/coverage").json()
        assert report["status"] == "NOT_FILED"
        assert report["is_clean_result"] is False
        assert report["coverage_percent"] is None
        assert "no readings is not clean coverage" in report["reason"]

    def test_a_filed_batch_computes_gaps_that_never_read_clean(self, api):
        filed = api.post("/api/intelligence/coverage", json={
            "batch_id": "RUN-2026-11-07-01",
            "captured_at": "2026-11-07T03:00:00+00:00",
            "authorized_targets": 100, "discovered_assets": 80,
            "outcomes": [
                {"plane": "linux", "status": "COMPLETE", "expected": 60,
                 "collected": 60, "impact": "linux plane complete"},
                {"plane": "windows-cng", "status": "FAILED", "expected": 40,
                 "collected": 20, "reason": "access denied",
                 "impact": "windows estate unmeasured"}],
            "access_denied_targets": 12, "unknown_assets": 8})
        assert filed.status_code == 200

        report = api.get("/api/intelligence/coverage").json()
        assert report["status"] == "FILED"
        assert report["verdict"] == "COVERAGE_INCOMPLETE"
        assert any(g["kind"] in {"COLLECTOR_FAILED", "UNKNOWN_ASSET"}
                   for g in report["gaps"])
        assert all(g["is_clean_result"] is False for g in report["gaps"])

        duplicate = api.post("/api/intelligence/coverage", json={
            "batch_id": "RUN-2026-11-07-01",
            "captured_at": "2026-11-07T04:00:00+00:00",
            "authorized_targets": 100, "discovered_assets": 80, "outcomes": []})
        assert duplicate.status_code == 409

    def test_a_batch_with_counts_but_no_outcome_rows_is_refused(self, api):
        refused = api.post("/api/intelligence/coverage", json={
            "batch_id": "RUN-ZERO-ROWS", "captured_at":
                "2026-11-07T05:00:00+00:00",
            "authorized_targets": 100, "discovered_assets": 100, "outcomes": []})
        assert refused.status_code == 422
        assert "refuses" in refused.json()["detail"]
