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
    from db.models.roadmap_gates import GateFiling
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
        GateFiling.__table__,
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


# ============================ gap analysis §G–§6 at the request boundary =====

class TestFindingsAPI:

    def test_a_finding_carries_the_structure_and_its_evidence(self, api):
        row = api.post("/api/intelligence/findings", json={
            "finding_id": "F-1", "pattern_id": "CERT_RISK", "tenant_id": "bank",
            "affected_asset_ids": ["cert-1"], "affected_system_ids": ["pay"],
            "severity": "HIGH", "confidence": "MEDIUM",
            "first_seen": "2026-11-01T00:00:00+00:00",
            "last_seen": "2026-11-07T00:00:00+00:00",
            "evidence_ids": ["EV-1"], "observed_change": "downgrade",
            "expected_state": "policy P-7", "reason": "weakens transport",
            "not_proven": "does not prove compromise",
            "recommended_investigation": "who changed the policy"}).json()
        assert row["change_class"] == "CONFIGURATION_CHANGE"
        assert row["digest"].startswith("sha256:")

    def test_the_engine_never_confirms_its_own_pattern(self, api):
        refused = api.post("/api/intelligence/findings", json={
            "finding_id": "F-2", "pattern_id": "CORR", "tenant_id": "bank",
            "affected_asset_ids": ["a"], "affected_system_ids": [],
            "severity": "HIGH", "confidence": "LOW",
            "first_seen": "2026-11-01T00:00:00+00:00",
            "last_seen": "2026-11-07T00:00:00+00:00",
            "evidence_ids": ["EV-1"], "observed_change": "c",
            "expected_state": "e", "reason": "r",
            "not_proven": "n", "recommended_investigation": "i",
            "change_class": "CONFIRMED_INCIDENT"})
        assert refused.status_code == 422
        assert "never automatically" in refused.json()["detail"]


class TestReconciliationAPI:

    def test_agreement_conflict_and_missing_cross_the_wire(self, api):
        report = api.post("/api/intelligence/reconciliation", json={
            "subject": "app-1",
            "claims": [
                {"bom": "SBOM", "subject": "app-1", "claim_kind": "PRESENCE",
                 "relationship": "uses-library", "target": "openssl",
                 "evidence_ids": ["SBOM-1"]},
                {"bom": "CBOM", "subject": "app-1", "claim_kind": "PRESENCE",
                 "relationship": "uses-library", "target": "openssl",
                 "evidence_ids": ["CBOM-1"]},
            ]}).json()
        assert report["counts"]["AGREES"] >= 1
        assert report["counts"]["MISSING"] >= 1
        assert "never assumed agreement" in report["note"]

    def test_presence_is_never_responsibility(self, api):
        verdict = api.post("/api/intelligence/reconciliation/attribution",
                           json={
            "component": "openssl", "operation": "tls-7",
            "claims": [{"bom": "SBOM", "subject": "app-1",
                        "claim_kind": "PRESENCE", "relationship": "contains",
                        "target": "openssl", "evidence_ids": ["SBOM-1"]}]}).json()
        assert verdict["attribution"] == "UNATTRIBUTED"
        assert "presence is not responsibility" in verdict["reason"]


class TestCertificateJourneyAPI:

    def test_the_investigator_journey_is_answerable_with_blind_spots(self, api):
        report = api.post("/api/intelligence/investigation/certificate", json={
            "certificate_id": "cert-39", "expiry": "2026-12-01",
            "usage_edges": [
                {"asset": "lb-1", "relationship": "presents",
                 "target": "cert-39", "evidence_ids": ["PCAP-1"]},
                {"asset": "gw-2", "relationship": "presents",
                 "target": "cert-39", "evidence_ids": []}],
            "dependency_edges": [
                {"system": "payments", "asset": "lb-1",
                 "relationship": "depends_on", "evidence_ids": ["CMDB-1"]}],
            "ownership": {}}).json()
        assert report["assets_using"] == ["lb-1"]
        assert report["business_systems"]["affected"][0]["system"] == "payments"
        assert report["connections"]["unevidenced"][0]["asset"] == "gw-2"
        assert "unknown" in report["unknown_owners"]


class TestMigrationPlanAPI:

    def test_a_plan_names_its_policy_snapshot_assumptions_cost_and_approvals(
            self, api):
        refused = api.post("/api/intelligence/migration/plans", json={
            "plan_id": "P-1", "policy_version": "",
            "algorithm_profiles": [{"from": "RSA", "to": "ML-DSA"}],
            "source_snapshot": {"snapshot_id": "S", "version": 1},
            "assumptions": ["a"], "cost_model": {},
            "approvals": [{"actor": "ciso", "at": "2026-11-07"}]})
        assert refused.status_code == 422

        ok = api.post("/api/intelligence/migration/plans", json={
            "plan_id": "P-1", "policy_version": "PQ-3",
            "algorithm_profiles": [{"from": "RSA", "to": "ML-DSA"}],
            "source_snapshot": {"snapshot_id": "S", "version": 1},
            "assumptions": ["firmware lands first"],
            "cost_model": {"lines": [{"item": "hsm", "estimate": 40000}]},
            "approvals": [{"actor": "ciso", "at": "2026-11-07"}]}).json()
        assert ok["policy_version"] == "PQ-3"

    def test_validation_needs_post_change_evidence(self, api):
        refused = api.post("/api/intelligence/migration/validate", json={
            "asset": "app-1", "claimed_state": "VALIDATED",
            "before_state": "CONFIGURED", "evidence_ids": [],
            "validated_at": "2026-11-08", "validator": "qa"})
        assert refused.status_code == 422
        ok = api.post("/api/intelligence/migration/validate", json={
            "asset": "app-1", "claimed_state": "VALIDATED",
            "before_state": "CONFIGURED", "evidence_ids": ["POST-1"],
            "validated_at": "2026-11-08", "validator": "qa"}).json()
        assert ok["claimed_state"] == "VALIDATED"


class TestGatesAPI:

    def test_the_register_starts_not_passed_and_external_gates_refuse_self_filing(
            self, api):
        report = api.get("/api/intelligence/gates").json()
        assert report["counts"]["NOT_PASSED"] == 12
        assert report["pilot_ready"] is False

        refused = api.post("/api/intelligence/gates", json={
            "gate": "RECOVERY", "evidence_ids": ["R-1"],
            "performed_by": "CryptoScan", "performed_at": "2026-11-08"})
        assert refused.status_code == 422
        synthetic = api.post("/api/intelligence/gates", json={
            "gate": "COLLECTOR_QUALIFICATION", "evidence_ids": ["Q-1"],
            "performed_by": "qa", "performed_at": "2026-11-08",
            "synthetic": True})
        assert synthetic.status_code == 422

    def test_a_filed_gate_passes_on_evidence(self, api):
        assert api.post("/api/intelligence/gates", json={
            "gate": "EVIDENCE_INTEGRITY", "evidence_ids": ["TAMPER-TEST-1"],
            "performed_by": "qa team", "performed_at": "2026-11-08"}).status_code == 200
        report = api.get("/api/intelligence/gates").json()
        assert report["gates"]["EVIDENCE_INTEGRITY"]["status"] == "PASSED"
        assert report["gates"]["RECOVERY"]["status"] == "NOT_PASSED"
        assert report["pilot_ready"] is False


class TestCollectorContractAPI:

    def _contract(self):
        return {"collector_id": "linux-procfs", "version": "2.1.0",
                "supported_asset_types": ["crypto-library"],
                "required_permissions": ["read:/proc"],
                "data_sensitivity": "INTERNAL",
                "signature": {"algorithm": "ed25519", "value": "sig-1"}}

    def test_a_zero_result_without_an_explanation_is_refused(self, api):
        refused = api.post("/api/intelligence/collector-contracts", json={
            "contract": self._contract(),
            "started_at": "2026-11-07T01:00:00+00:00",
            "ended_at": "2026-11-07T01:05:00+00:00",
            "target_scope": "prod", "state": "SUCCESS",
            "assets_found": [], "evidence_ids": ["RUN-1"],
            "coverage_metrics": {}})
        assert refused.status_code == 422
        assert "must explain itself" in refused.json()["detail"]

        ok = api.post("/api/intelligence/collector-contracts", json={
            "contract": self._contract(),
            "started_at": "2026-11-07T01:00:00+00:00",
            "ended_at": "2026-11-07T01:05:00+00:00",
            "target_scope": "prod", "state": "SUCCESS",
            "assets_found": [], "evidence_ids": ["RUN-1"],
            "coverage_metrics": {}, "zero_reason": "FOUND_NOTHING"}).json()
        assert ok["zero_reason"] == "FOUND_NOTHING"

    def test_an_unsigned_contract_is_refused(self, api):
        bad = dict(self._contract(), signature={})
        refused = api.post("/api/intelligence/collector-contracts", json={
            "contract": bad,
            "started_at": "2026-11-07T01:00:00+00:00",
            "ended_at": "2026-11-07T01:05:00+00:00",
            "target_scope": "prod", "state": "SUCCESS",
            "assets_found": [{"asset_id": "a"}], "evidence_ids": ["RUN-1"],
            "coverage_metrics": {}})
        assert refused.status_code == 422
        assert "integrity metadata" in refused.json()["detail"]


class TestObservationIntakeAPI:

    def test_duplicates_collapse_and_the_graph_digest_is_stable(self, api):
        row = api.post("/api/intelligence/observations/intake", json={
            "observations": [
                {"plane": "linux", "asset_type": "lib", "locator": "p1",
                 "asset_id": "lib-1", "evidence_ids": ["E1"]},
                {"plane": "linux", "asset_type": "lib", "locator": "p1",
                 "asset_id": "lib-1", "evidence_ids": ["E2"]},
                {"kind": "relationship", "subject": "app", "predicate": "uses",
                 "object": "lib-1", "evidence_ids": ["E3"]}]}).json()
        assert row["duplicates_collapsed"] == 1
        assert row["assets"][0]["evidence_ids"] == ["E1", "E2"]
        assert row["projection"]["vertex_count"] == 1
        assert row["projection"]["graph_digest"].startswith("sha256:")

    def test_an_unplaceable_observation_is_refused(self, api):
        refused = api.post("/api/intelligence/observations/intake", json={
            "observations": [{"plane": "linux", "asset_type": "lib",
                              "locator": ""}]})
        assert refused.status_code == 422


class TestComplianceAPI:

    def test_a_policy_match_alone_never_reads_as_compliant(self, api):
        report = api.post("/api/intelligence/compliance/status", json={
            "requirements": [{"requirement_id": "PCI-6.4",
                              "framework": "PCI-DSS", "clause": "6.4",
                              "text": "changes controlled"}],
            "assessments": [{"requirement_id": "PCI-6.4",
                             "policy_match": True}]}).json()
        assert report["requirements"]["PCI-6.4"]["status"] == "POLICY_MATCH_ONLY"

    def test_an_assessment_needs_evidence_and_an_assessor(self, api):
        refused = api.post("/api/intelligence/compliance/assessments", json={
            "requirement_id": "PCI-6.4", "policy_match": True,
            "evidence_ids": [], "assessed_by": "auditor", "outcome": "COMPLIANT"})
        assert refused.status_code == 422
        ok = api.post("/api/intelligence/compliance/assessments", json={
            "requirement_id": "PCI-6.4", "policy_match": True,
            "evidence_ids": ["CHANGE-1"], "assessed_by": "auditor",
            "outcome": "COMPLIANT"}).json()
        assert ok["outcome"] == "COMPLIANT"
