"""Phase 1 coverage over actual approved/intaken SQL evidence, not new scans."""

import pytest
from test_assurance_workflows import assured as assured, admin
from test_software_supply_chain_api import banks as banks
from test_collection_foundation import completed, prepared, P, decision
from db.models.scan import Scan
from db.models.evidence_record import EvidenceRecord
from db.repositories.user_repository import verify_audit_chain
from shared_models.collection import CollectionResult, TargetSpec, CollectionError
from shared_models.collection_coverage import project_coverage, SURFACES, BOMS, CoverageReport
from shared_models.host_collection import digest, Kind
from typing import get_args


def source(assured):
    clients, db, body, auth, job = completed(assured)
    jid = job["subject_id"]
    value = clients["reader_a"].get(P + f"/jobs/{jid}/evidence").json()
    result = CollectionResult.model_validate({k: v for k, v in value.items() if k != "envelope_sha256"})
    return clients, db, body, auth, job, result


def test_phase_one_surface_coverage_same_evidence_and_all_six_boms(assured):
    clients, db, _, _, job, result = source(assured)
    before = (db.query(Scan).count(), db.query(EvidenceRecord).count())
    path = P + f"/jobs/{job['subject_id']}/coverage/surfaces"
    response = clients["reader_a"].get(path)
    assert response.status_code == 200, response.text
    report = CoverageReport.model_validate(response.json())
    assert set(report.surfaces) == set(SURFACES) and set(report.bom_observation_counts) == set(BOMS)
    cert = report.surfaces["certificates"]
    assert (cert.approved_inputs, cert.parsed_inputs, cert.failed_inputs, cert.outcome) == (2, 1, 1, "PARTIAL")
    assert cert.approved_input_parse_percent == 50
    assert any(i.status == "UNAVAILABLE" and i.reason == "NOT_FOUND" for i in cert.inputs)
    assert cert.inputs[0].evidence_ids and cert.inputs[0].local_basis_counts["OBSERVED"] == 1
    config = report.surfaces["crypto_configuration"]
    assert config.inputs[0].local_basis_counts == {"OBSERVED": 0, "DECLARED": 1}
    assert config.approved_input_parse_percent == 100 and not config.complete_surface_coverage_verified
    hardware = report.surfaces["hardware_metadata"]
    assert hardware.outcome == "NOT_REQUESTED" and hardware.approved_input_parse_percent is None
    assert (
        not report.asset_absence_proven
        and not report.whole_host_coverage_verified
        and report.whole_host_percent is None
    )
    assert report.envelope_sha256 == digest(result) and report.materialized_without_collection
    assert report.bom_observation_counts["SBOM"] == 1 and report.bom_observation_counts["VBOM"] == 0
    assert clients["reader_a"].get(path).json() == response.json()
    assert before == (db.query(Scan).count(), db.query(EvidenceRecord).count()) and before[0] == 1
    assert clients["bank_b"].get(path).status_code == 404
    assert clients["platform_admin"].get(path).status_code == 404
    assert admin(clients).get(path).status_code == 200
    assert verify_audit_chain(db)["status"] == "OK"


@pytest.mark.parametrize(
    "change",
    [
        "target-system",
        "target-environment",
        "manifest-kind",
        "source-path",
        "source-host",
        "fact-hash",
        "domain-promotion",
        "failed-input-fact",
        "duplicate-observation",
        "duplicate-ordinal",
        "extra-error",
        "duplicate-error",
        "denominator",
        "envelope-digest",
    ],
)
def test_projection_refuses_inconsistent_evidence_not_silent_coverage(assured, change):
    _, _, body, _, _, result = source(assured)
    target = TargetSpec.model_validate(body)
    first = result.observations[0]
    if change == "target-system":
        target = target.model_copy(update={"system_id": "another-system"})
    elif change == "target-environment":
        target = target.model_copy(update={"environment": "another-environment"})
    elif change == "manifest-kind":
        item = target.manifest.inputs[0].model_copy(update={"kind": "BINARY_METADATA"})
        target = target.model_copy(
            update={"manifest": target.manifest.model_copy(update={"inputs": [item, *target.manifest.inputs[1:]]})}
        )
    elif change in {"source-path", "source-host"}:
        key = "path" if change == "source-path" else "host_id"
        first = first.model_copy(update={"source": first.source.model_copy(update={key: "other"})})
        result = result.model_copy(update={"observations": [first, *result.observations[1:]]})
    elif change == "fact-hash":
        result = result.model_copy(
            update={"observations": [first.model_copy(update={"fact_sha256": "0" * 64}), *result.observations[1:]]}
        )
    elif change == "domain-promotion":
        result = result.model_copy(
            update={
                "observations": [
                    first.model_copy(update={"contributes_to": ["HBOM", "TechBOM"]}),
                    *result.observations[1:],
                ]
            }
        )
    elif change == "failed-input-fact":
        result = result.model_copy(
            update={
                "observations": [
                    first.model_copy(update={"input_id": result.errors[0].input_id}),
                    *result.observations[1:],
                ]
            }
        )
    elif change == "duplicate-observation":
        result = result.model_copy(update={"observations": [*result.observations, first]})
    elif change == "duplicate-ordinal":
        result = result.model_copy(
            update={"observations": [*result.observations, first.model_copy(update={"observation_id": "another-id"})]}
        )
    elif change == "extra-error":
        result = result.model_copy(update={"errors": [result.errors[0].model_copy(update={"input_id": "unapproved"})]})
    elif change == "duplicate-error":
        result = result.model_copy(update={"errors": result.errors * 2})
    elif change == "denominator":
        result = result.model_copy(update={"coverage": result.coverage.model_copy(update={"approved_inputs": 99})})
    with pytest.raises(ValueError):
        project_coverage(result, target, "0" * 64 if change == "envelope-digest" else digest(result))


def test_not_completed_and_changed_original_cannot_be_reported_as_covered(assured):
    clients, _, body, _, job = prepared(assured)
    path = P + f"/jobs/{job['subject_id']}/coverage/surfaces"
    assert clients["reader_a"].get(path).status_code == 409


def test_every_input_kind_has_exactly_one_surface():
    kinds = [k for values in SURFACES.values() for k in values]
    assert len(kinds) == len(set(kinds)) and set(kinds) == set(get_args(Kind))
    assert "NETWORK_TLS_CLIENT_OFFER" in SURFACES["network_listeners"]


@pytest.mark.parametrize("status", ["DENIED", "UNSUPPORTED", "INVALID", "BUDGET_EXCEEDED", "UNAVAILABLE"])
def test_failed_is_never_absent_or_not_requested(assured, status):
    _, _, body, _, _, result = source(assured)
    target = TargetSpec.model_validate(body)
    result = result.model_copy(
        update={
            "observations": [],
            "errors": [
                CollectionError(input_id=i.input_id, status=status, reason="ENGINEERING_NEGATIVE")
                for i in target.manifest.inputs
            ],
            "status": "FAILED",
            "coverage": result.coverage.model_copy(update={"parsed_inputs": 0}),
        }
    )
    report = project_coverage(result, target, digest(result))
    assert report.surfaces["certificates"].outcome == "FAILED"
    assert report.surfaces["certificates"].approved_input_parse_percent == 0
    assert report.surfaces["hardware_metadata"].outcome == "NOT_REQUESTED"
    assert report.surfaces["hardware_metadata"].approved_input_parse_percent is None
    assert not report.asset_absence_proven and all(n == 0 for n in report.bom_observation_counts.values())


def test_tampered_original_refuses_coverage_and_revoke_does_not_recollect(assured):
    clients, db, _, auth, job, _ = source(assured)
    path = P + f"/jobs/{job['subject_id']}/coverage/surfaces"
    before = clients["reader_a"].get(path).json()
    assert admin(clients).post(P + f"/targets/{auth['subject_id']}/revoke", json=decision(2)).status_code == 200
    assert clients["reader_a"].get(path).json() == before
    db.query(EvidenceRecord).first().finding_data = {"corrupt": True}
    db.commit()
    assert clients["reader_a"].get(path).status_code == 409
