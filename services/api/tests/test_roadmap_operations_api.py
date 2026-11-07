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
    from api.errors import install_error_contract
    install_error_contract(app)
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


# ---- gap analysis §C/§5/Phase-2 contract surfaces (wave 15) ----

def test_graph_projection_rebuilds_the_same_logical_graph(api):
    rows = {
        "assets": [
            {"identifier": "asset:rsa", "evidence_ids": ["ev-1"]},
            {"identifier": "asset:cert", "evidence_ids": ["ev-2"]},
        ],
        "relationships": [
            {"subject": "asset:cert", "predicate": "USES",
             "object": "asset:rsa", "evidence_ids": ["ev-2"]},
            {"subject": "asset:rsa", "predicate": "DEPLOYED_IN",
             "object": "app:payments", "evidence_ids": []},
        ],
    }
    first = api.post("/api/intelligence/graph-projection", json=rows)
    assert first.status_code == 200, first.text
    flipped = {
        "assets": list(reversed(rows["assets"])),
        "relationships": list(reversed(rows["relationships"])),
    }
    second = api.post("/api/intelligence/graph-projection", json=flipped)
    assert second.json()["graph_digest"] == first.json()["graph_digest"]
    edges = {tuple(sorted((e["subject"], e["object"]))): e
             for e in first.json()["edges"]}
    unproven = edges[("app:payments", "asset:rsa")]
    assert unproven["provenance"] == "UNKNOWN", "evidence-less edges stay UNKNOWN"

    refused = api.post("/api/intelligence/graph-projection",
                       json={"assets": [{"evidence_ids": []}], "relationships": []})
    assert refused.status_code == 422
    assert refused.json()["error_code"] == "INVALID_ARGUMENT"


def test_evidence_reprocess_keeps_the_original_and_reports_the_verdict(api):
    record = {
        "content_hash": "ab" * 32,
        "finding_data": {"snippet": "AES-256 at src/c.ts:17"},
        "normalized_crypto": {"algorithm": "AES"},
        "normalization": {"normalizer_version": "norm-1"},
    }
    resp = api.post("/api/intelligence/evidence-reprocess", json={
        "record": record,
        "normalizer_version": "norm-2",
        "normalized_crypto": {"algorithm": "AES", "key_size": 256},
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["original_intact"]["original_intact"] is True
    assert body["record"]["finding_data"] == record["finding_data"]
    assert body["record"]["content_hash"] == record["content_hash"]
    assert body["record"]["normalization"]["normalizer_version"] == "norm-2"
    assert body["record"]["superseded_normalizations"][0][
        "normalization"]["normalizer_version"] == "norm-1"

    refused = api.post("/api/intelligence/evidence-reprocess", json={
        "record": {"finding_data": None, "content_hash": "x"},
        "normalizer_version": "norm-2", "normalized_crypto": {},
    })
    assert refused.status_code == 422


def test_vendor_exposure_and_risk_name_the_gaps(api):
    exposure = api.post("/api/intelligence/vendor-exposure", json={
        "deployments": [
            {"asset": "hsm-01", "vendor": "ACME", "product": "Luna",
             "version": "7.13"},
            {"asset": "hsm-02", "vendor": "ACME", "product": "Luna",
             "version": "9.0"},
        ],
        "support_records": [
            {"vendor": "ACME", "product": "Luna", "version": "7.13",
             "status": "END_OF_SUPPORT", "end_of_support_at": "2026-01-31",
             "evidence_ref": "decl-1"},
        ],
        "as_of": "2026-11-07",
    })
    assert exposure.status_code == 200, exposure.text
    body = exposure.json()
    assert body["is_clean_result"] is False
    assert body["unsupported_deployed"][0]["deployment"]["asset"] == "hsm-01"
    assert body["unknown_support"][0]["deployment"]["asset"] == "hsm-02"

    risk = api.post("/api/intelligence/vendor-risk", json={
        "vendor": "ACME",
        "deployments": [
            {"asset": "hsm-01", "vendor": "ACME", "product": "Luna",
             "version": "7.13"},
        ],
        "support_records": [
            {"vendor": "ACME", "product": "Luna", "version": "7.13",
             "status": "END_OF_SUPPORT", "end_of_support_at": "2026-01-31",
             "evidence_ref": "decl-1"},
        ],
        "changes": [
            {"change": "END_OF_SUPPORT_ANNOUNCED", "evidence_ref": "adv-1"},
        ],
        "as_of": "2026-11-07",
    })
    assert risk.status_code == 200
    risk_body = risk.json()
    assert "score" not in risk_body
    names = {d["driver"] for d in risk_body["drivers"]}
    assert "unsupported_product_deployed" in names
    assert "supplier_change:end_of_support_announced" in names
    for driver in risk_body["drivers"]:
        assert driver["records"]


def test_asset_alias_resolve_reports_conflicts_and_merge_preserves_keys(api):
    resolved = api.post("/api/intelligence/asset-alias/resolve", json={
        "keys": ["ip:10.0.0.5", "asset:db-9"],
        "aliases": [
            {"alias_key": "ip:10.0.0.5", "canonical_key": "asset:web-1"},
        ],
    })
    assert resolved.status_code == 200, resolved.text
    rows = {r["key"]: r for r in resolved.json()["resolutions"]}
    assert rows["ip:10.0.0.5"]["canonical_key"] == "asset:web-1"
    assert rows["asset:db-9"]["state"] == "UNALIASED"

    conflicted = api.post("/api/intelligence/asset-alias/resolve", json={
        "keys": ["ip:10.0.0.5"],
        "aliases": [
            {"alias_key": "ip:10.0.0.5", "canonical_key": "asset:web-1"},
            {"alias_key": "ip:10.0.0.5", "canonical_key": "asset:web-2"},
        ],
    })
    assert conflicted.json()["conflicted"] == ["ip:10.0.0.5"]
    assert conflicted.json()["is_clean_result"] is False

    merged = api.post("/api/intelligence/asset-alias/merge", json={
        "keys": ["host:web-1", "ip:10.0.0.5"],
        "canonical_key": "asset:web-1",
        "actor": "alice",
        "reason": "same physical host",
        "evidence_ref": "ev-9",
    })
    assert merged.status_code == 200, merged.text
    assert merged.json()["original_keys"] == ["host:web-1", "ip:10.0.0.5"]
    assert {row["alias_key"] for row in merged.json()["aliases"]} == {
        "host:web-1", "ip:10.0.0.5"}

    refused = api.post("/api/intelligence/asset-alias/merge", json={
        "keys": ["a", "b"], "canonical_key": "asset:x", "actor": "x",
        "reason": "r", "evidence_ref": "",
    })
    assert refused.status_code == 422
    assert refused.json()["error_code"] == "INVALID_ARGUMENT"


def test_supplier_concentration_and_readiness_surfaces(api):
    # §6: two critical services behind one supplier is a named finding
    conc = api.post("/api/intelligence/supplier-concentration", json={
        "dependencies": [
            {"service": "payments-api", "supplier": "ACME HSM",
             "component": "Luna 7", "criticality": "CRITICAL",
             "evidence_ref": "ev-1"},
            {"service": "settlement-api", "supplier": "ACME HSM",
             "component": "Luna 7", "criticality": "HIGH",
             "evidence_ref": "ev-2"},
        ],
        "as_of": "2026-11-07",
    })
    assert conc.status_code == 200, conc.text
    body = conc.json()
    assert body["state"] == "CONCENTRATED"
    assert body["findings"][0]["subject"] == "ACME HSM"
    assert "score" not in body

    refused = api.post("/api/intelligence/supplier-concentration", json={
        "dependencies": [{"service": "x", "supplier": "y",
                          "criticality": "CRITICAL", "evidence_ref": ""}]})
    assert refused.status_code == 422
    assert refused.json()["error_code"] == "INVALID_ARGUMENT"

    # §5.2: readiness needs evidence + a vendor claim of testing is not
    # independent test evidence
    ready = api.post("/api/intelligence/supplier-readiness", json={
        "vendor": "ACME HSM", "product": "Luna",
        "responses": [
            {"dimension": "pqc_roadmap", "status": "ANSWERED",
             "evidence_ref": "ev-r", "verification": "INDEPENDENT_TEST"},
            {"dimension": "implementation_capability", "status": "ANSWERED",
             "evidence_ref": "ev-i", "verification": "VENDOR_CLAIM"},
            {"dimension": "testing_evidence", "status": "ANSWERED",
             "evidence_ref": "ev-t", "verification": "VENDOR_CLAIM"},
            {"dimension": "product_support_lifecycle", "status": "ANSWERED",
             "evidence_ref": "ev-l", "verification": "INDEPENDENT_TEST"},
            {"dimension": "upgrade_commitment", "status": "ANSWERED",
             "evidence_ref": "ev-u", "verification": "INDEPENDENT_TEST"},
        ],
        "as_of": "2026-11-07",
    })
    assert ready.status_code == 200, ready.text
    ready_body = ready.json()
    assert ready_body["state"] == "PARTIAL"
    assert ready_body["is_clean_result"] is False
    testing = next(d for d in ready_body["dimensions"]
                   if d["dimension"] == "testing_evidence")
    assert testing["met"] is False

    least = api.post("/api/intelligence/supplier-readiness/least-ready",
                     json={"assessments": [ready_body]})
    assert least.status_code == 200
    assert least.json()["state"] == "CONSTRAINED"
    assert least.json()["suppliers"][0]["vendor"] == "ACME HSM"


def test_production_qualification_register_keeps_external_only_honesty(api):
    # the platform cannot perform a real-environment qualification
    refused = api.post("/api/intelligence/production-qualification/file", json={
        "activity": "LINUX_WINDOWS_ENV_QUALIFICATION",
        "evidence_ids": ["ev-1"], "performed_by": "cryptoscan",
        "performed_at": "2026-11-07", "result": "PASS"})
    assert refused.status_code == 422
    assert refused.json()["error_code"] == "INVALID_ARGUMENT"

    # a synthetic filing stays labelled synthetic and never reads QUALIFIED
    synthetic = api.post("/api/intelligence/production-qualification/file", json={
        "activity": "LARGE_ESTATE_SYNTHETIC_TESTING",
        "evidence_ids": ["ev-scale"], "performed_by": "cryptoscan scale validation",
        "performed_at": "2026-11-07", "result": "PASS", "synthetic": True})
    assert synthetic.status_code == 200, synthetic.text
    assert synthetic.json()["state"] == "SYNTHETIC_ONLY"

    qualified = api.post("/api/intelligence/production-qualification/file", json={
        "activity": "BACKUP_RESTORE_DRILL",
        "evidence_ids": ["ev-drill"], "performed_by": "Bank DR team",
        "performed_at": "2026-11-07", "result": "PASS"})
    assert qualified.status_code == 200, qualified.text
    assert qualified.json()["state"] == "QUALIFIED"

    status = api.post("/api/intelligence/production-qualification/status",
                      json={"rows": [synthetic.json(), qualified.json()]})
    assert status.status_code == 200, status.text
    body = status.json()
    assert body["production_ready"] is False
    assert "LINUX_WINDOWS_ENV_QUALIFICATION" in body["blockers"]
    assert body["synthetic_results"] == ["LARGE_ESTATE_SYNTHETIC_TESTING"]
    not_filed = next(a for a in body["activities"]
                     if a["activity"] == "BANK_PILOT_ACCEPTANCE")
    assert not_filed["state"] == "NOT_FILED"
    assert "never passed" in body["note"]
