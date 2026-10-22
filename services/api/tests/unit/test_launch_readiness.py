"""Synthetic assessor keys + real authenticated SQL APIs; not external assurance."""

import base64
from copy import deepcopy
from datetime import timedelta
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from db.models.base import utcnow
from db.models.user import User
from db.models.assurance import AssuranceRevision
from api.assurance import store
from shared_models.launch_assurance import AssessmentReport, REQUIRED_CASES, DUTIES
from test_assurance_workflows import assured as assured, admin, done, blob, approval
from test_software_supply_chain_api import banks as banks, register

P = "/api/v1/assurance/launch"


def uid(db, name):
    return db.query(User).filter_by(username=name).one().id


def proposed(clients, db):
    a = clients["bank_a"]
    artifact = register(a)
    key = Ed25519PrivateKey.generate()
    evidence = blob(a)
    body = {
        "artifact_id": artifact["id"],
        "environment_ref": "isolated-test/site-17",
        "provider_organization": "SYNTHETIC TEST ONLY",
        "lead_tester_ref": "fixture/tester",
        "public_key_base64": base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(),
        "independence_declaration_blob_id": evidence["blob_id"],
        "scope_blob_id": evidence["blob_id"],
        "deployment_manifest_blob_id": evidence["blob_id"],
        "expires_at": (utcnow() + timedelta(days=30)).isoformat(),
        "exclusions": ["No real customer or assessor; synthetic API contract test"],
        "cases": [
            {
                "case_id": case,
                "area": area,
                "procedure": "Negative test " + case,
                "expected_result": "Deny unauthorized effects",
            }
            for case, area in REQUIRED_CASES.items()
        ],
    }
    eng = done(a.post(P + "/engagements", json=body))
    return eng, body, key, artifact, evidence


def approved(clients, db):
    eng, body, key, artifact, evidence = proposed(clients, db)
    eng = done(admin(clients).post(P + f"/engagements/{eng['subject_id']}/approve", json=approval()))
    return eng, body, key, artifact, evidence


def payload(eng, artifact, evidence, sequence=1):
    return {
        "schema_version": "cryptoscan.independent-test/1",
        "estate_scope": "tenant:a",
        "engagement_id": eng["subject_id"],
        "engagement_revision": eng["revision"],
        "sequence": sequence,
        "scope_sha256": eng["payload"]["scope_sha256"],
        "artifact_id": artifact["id"],
        "artifact_digest": artifact["digest"],
        "deployment_manifest_sha256": evidence["sha256"],
        "environment_ref": "isolated-test/site-17",
        "started_at": utcnow().isoformat(),
        "ended_at": utcnow().isoformat(),
        "report_blob_id": evidence["blob_id"],
        "report_sha256": evidence["sha256"],
        "cases": [
            {"case_id": case, "outcome": "PASSED", "evidence_ref": "fixture/negative-case"} for case in REQUIRED_CASES
        ],
        "findings": [],
        "retests": [],
    }


def signed(key, p, rev=0):
    canonical = AssessmentReport.model_validate(p).model_dump(mode="json")
    return {
        "expected_revision": rev,
        "payload": p,
        "signature_base64": base64.b64encode(key.sign(store.encoded(canonical))).decode(),
    }


def submit(client, eng, key, p, rev=0):
    return client.post(P + f"/engagements/{eng['subject_id']}/reports", json=signed(key, p, rev))


def test_engagement_scope_and_independent_review_exact_estate(assured):
    clients, db, _ = assured
    eng, body, key, artifact, evidence = proposed(clients, db)
    path = P + f"/engagements/{eng['subject_id']}"
    assert clients["bank_a"].post(path + "/approve", json=approval()).status_code == 403
    assert admin(clients, "b").post(path + "/approve", json=approval()).status_code == 404
    assert clients["bank_b"].get(path + "/status").status_code == 404
    status = done(clients["bank_a"].get(path + "/status"), 200)
    assert status["state"] == "BLOCKED" and not status["certified"]
    assert submit(clients["bank_a"], eng, key, payload(eng, artifact, evidence)).status_code == 409
    withdrawn = done(admin(clients).post(path + "/withdraw", json=approval()))
    assert withdrawn["payload"]["independence"] == "UNREVIEWED_EXTERNAL_ASSERTION"
    assert "approved_at" not in withdrawn["payload"]
    malformed = {**body, "cases": body["cases"][:-1]}
    assert clients["bank_a"].post(P + "/engagements", json=malformed).status_code == 422
    assert clients["reader_a"].post(P + "/engagements", json=body).status_code == 403
    # Same-human scope approval is denied even after gaining trust role.
    admin_eng = done(admin(clients).post(P + "/engagements", json=body))
    assert (
        admin(clients).post(P + f"/engagements/{admin_eng['subject_id']}/approve", json=approval()).status_code == 409
    )


@pytest.mark.parametrize(
    "mutation,code",
    [
        ("tamper", 422),
        ("estate", 409),
        ("digest", 409),
        ("scope", 409),
        ("omitted", 422),
        ("duplicate", 422),
        ("future", 409),
        ("preapproval", 409),
        ("report_blob", 409),
        ("unknown_retest", 422),
        ("failed_untracked", 422),
    ],
)
def test_report_negative_contracts(assured, mutation, code):
    clients, db, _ = assured
    eng, _, key, artifact, evidence = approved(clients, db)
    p = payload(eng, artifact, evidence)
    if mutation == "estate":
        p["estate_scope"] = "tenant:b"
    if mutation == "digest":
        p["artifact_digest"] = "sha256:" + "b" * 64
    if mutation == "scope":
        p["scope_sha256"] = "b" * 64
    if mutation == "omitted":
        p["cases"][0]["case_id"] = "unscoped.case"
    if mutation == "duplicate":
        p["cases"][-1] = p["cases"][0]
    if mutation == "future":
        p["ended_at"] = (utcnow() + timedelta(days=1)).isoformat()
    if mutation == "preapproval":
        p["started_at"] = (utcnow() - timedelta(days=1)).isoformat()
    if mutation == "report_blob":
        p["report_sha256"] = "b" * 64
    if mutation == "unknown_retest":
        p["retests"] = [
            {
                "finding_id": "unknown",
                "expected_finding_sha256": "a" * 64,
                "outcome": "RESOLVED",
                "evidence_ref": "fixture/nope",
            }
        ]
    if mutation == "failed_untracked":
        p["cases"][0]["outcome"] = "FAILED"
    body = signed(key, p)
    if mutation == "tamper":
        body["payload"]["cases"][0]["evidence_ref"] += "/tampered"
    assert clients["bank_a"].post(P + f"/engagements/{eng['subject_id']}/reports", json=body).status_code == code
    assert store.latest(db, "a", "security_report", eng["subject_id"], required=False) is None


def test_signed_report_replay_withdrawal_and_explicit_untested(assured):
    clients, db, _ = assured
    eng, _, key, artifact, evidence = approved(clients, db)
    p = payload(eng, artifact, evidence)
    p["cases"][0]["outcome"] = "NOT_TESTED"
    done(submit(clients["bank_a"], eng, key, p))
    assert submit(clients["bank_a"], eng, key, p).status_code == 409
    status = done(clients["bank_a"].get(P + f"/engagements/{eng['subject_id']}/status"), 200)
    assert "FAILED_OR_UNTESTED_CASES" in status["issues"]
    done(admin(clients).post(P + f"/engagements/{eng['subject_id']}/withdraw", json=approval(2)))
    p = payload(eng, artifact, evidence, 2)
    assert submit(clients["bank_a"], eng, key, p, 1).status_code == 409


def test_finding_action_not_resolution_later_exact_signed_retest_required(assured):
    clients, db, _ = assured
    a, reviewer = clients["bank_a"], admin(clients)
    eng, _, key, artifact, evidence = approved(clients, db)
    p = payload(eng, artifact, evidence)
    case = p["cases"][0]["case_id"]
    p["cases"][0]["outcome"] = "FAILED"
    p["findings"] = [
        {
            "finding_ref": "F-1",
            "case_ids": [case],
            "severity": "HIGH",
            "description": "Synthetic isolation failure",
            "evidence_ref": "fixture/F-1",
        }
    ]
    report = done(submit(a, eng, key, p))
    fid = report["payload"]["finding_ids"][0]
    finding_path = P + f"/findings/{fid}"
    replacement = register(a, "sha256:" + "b" * 64)
    plan = {
        "expected_revision": 1,
        "owner_user_id": uid(db, "bank_a"),
        "replacement_artifact_id": replacement["id"],
        "deployment_manifest_blob_id": evidence["blob_id"],
        "change_ref": "change/fix",
        "verification_criteria": "Repeat exact negative case on replacement",
    }
    assert clients["bank_b"].post(finding_path + "/plan", json=plan).status_code == 404
    done(a.post(finding_path + "/plan", json=plan))
    assert a.post(finding_path + "/plan", json=plan).status_code == 409
    done(reviewer.post(finding_path + "/approve", json=approval(2)))
    assert (
        reviewer.post(
            finding_path + "/report-complete",
            json={
                "expected_revision": 3,
                "completed_at": utcnow().isoformat(),
                "evidence_blob_id": evidence["blob_id"],
            },
        ).status_code
        == 409
    )
    done(
        a.post(
            finding_path + "/report-complete",
            json={
                "expected_revision": 3,
                "completed_at": utcnow().isoformat(),
                "evidence_blob_id": evidence["blob_id"],
            },
        )
    )
    current = store.latest(db, "a", "security_finding", fid)
    p = payload(eng, replacement, evidence, 2)
    p["retests"] = [
        {
            "finding_id": fid,
            "expected_finding_sha256": current.payload_sha256,
            "outcome": "RESOLVED",
            "evidence_ref": "fixture/retest-after-fix",
        }
    ]
    wrong = deepcopy(p)
    wrong["artifact_id"] = artifact["id"]
    wrong["artifact_digest"] = artifact["digest"]
    assert submit(a, eng, key, wrong, 1).status_code == 409
    stale = deepcopy(p)
    stale["retests"][0]["expected_finding_sha256"] = "a" * 64
    assert submit(a, eng, key, stale, 1).status_code == 409
    assert submit(a, eng, key, {**p, "retests": []}, 1).status_code == 422
    done(submit(a, eng, key, p, 1))
    status = done(a.get(P + f"/engagements/{eng['subject_id']}/status"), 200)
    assert status["state"] == "SCOPED_SIGNED_TEST_RECORDS_COMPLETE"
    assert not status["certified"]
    # A later inconclusive retest reopens attention; the old resolution remains historical.
    current = store.latest(db, "a", "security_finding", fid)
    p = payload(eng, replacement, evidence, 3)
    p["retests"] = [
        {
            "finding_id": fid,
            "expected_finding_sha256": current.payload_sha256,
            "outcome": "INCONCLUSIVE",
            "evidence_ref": "fixture/collector-unavailable",
        }
    ]
    done(submit(a, eng, key, p, 2))
    assert (
        "UNRESOLVED_OR_UNTESTED_FINDING:" + fid
        in done(a.get(P + f"/engagements/{eng['subject_id']}/status"), 200)["issues"]
    )
    history = db.query(AssuranceRevision).filter_by(kind="security_finding", subject_id=fid).all()
    assert any(r.payload["state"] == "RETEST_RECORDED_RESOLVED" for r in history)


def assignment_body(db, evidence, **changes):
    return {
        "expected_revision": 0,
        "duty": "BACKUP_RESTORE",
        "owner_user_id": uid(db, "bank_a"),
        "backup_user_id": uid(db, "platform_admin"),
        "procedure_blob_id": evidence["blob_id"],
        "escalation_ref": "roster/oncall",
        "service_window": "Synthetic exercise only; no contractual SLA",
        "review_due_at": (utcnow() + timedelta(days=30)).isoformat(),
        "exercise_max_age_seconds": 3600,
        **changes,
    }


def test_ownership_ack_exercise_review_reassignment_and_inactive_owners(assured):
    clients, db, _ = assured
    a, reviewer = clients["bank_a"], admin(clients)
    evidence = blob(a)
    body = assignment_body(db, evidence)
    assigned = done(a.post(P + "/assignments", json=body))
    path = P + f"/assignments/{assigned['subject_id']}"
    assert a.post(P + "/assignments", json=body).status_code == 409
    assert clients["bank_b"].post(path + "/acknowledge", json=approval()).status_code == 404
    assert clients["reader_a"].post(path + "/acknowledge", json=approval()).status_code == 403
    done(a.post(path + "/acknowledge", json=approval()))
    assert a.post(path + "/acknowledge", json=approval(2)).status_code == 409
    done(reviewer.post(path + "/acknowledge", json=approval(2)))
    exercise = {
        "expected_revision": 0,
        "assignment_revision": 3,
        "started_at": utcnow().isoformat(),
        "ended_at": utcnow().isoformat(),
        "evidence_blob_id": evidence["blob_id"],
        "outcome": "PASSED",
        "checks": ["Restored isolated fixture; checked checksums"],
        "limitations": ["Not a witnessed bank recovery"],
    }
    done(a.post(path + "/exercises", json=exercise))
    assert done(a.get(P + "/operations"), 200)["duties"][2]["issues"] == ["EXERCISE_FAILED_UNREVIEWED_OR_STALE"]
    done(reviewer.post(path + "/review-exercise", json=approval()))
    status = done(a.get(P + "/operations"), 200)
    assert not status["duties"][2]["issues"] and not status["sla_authorized"]
    assert len(status["duties"]) == len(DUTIES) == 9
    assert not status["all_owner_reviewed_records_current"]
    # Replacement procedure invalidates both owner acknowledgement and exercise.
    done(a.post(P + "/assignments", json={**body, "expected_revision": 3}))
    status = done(a.get(P + "/operations"), 200)
    assert "CURRENT_ASSIGNMENT_EXERCISE_MISSING" in status["duties"][2]["issues"]
    user = db.query(User).filter_by(username="bank_a").one()
    user.is_active = False
    db.commit()
    status = done(reviewer.get(P + "/operations"), 200)
    assert "OWNER_OR_BACKUP_NO_LONGER_ACTIVE" in status["duties"][2]["issues"]


@pytest.mark.parametrize("change", ["same", "foreign", "readonly", "past"])
def test_assignment_negative(assured, change):
    clients, db, _ = assured
    evidence = blob(clients["bank_a"])
    body = assignment_body(db, evidence)
    if change == "same":
        body["backup_user_id"] = body["owner_user_id"]
    if change == "foreign":
        body["owner_user_id"] = uid(db, "bank_b")
    if change == "readonly":
        body["owner_user_id"] = uid(db, "reader_a")
    if change == "past":
        body["review_due_at"] = (utcnow() - timedelta(days=1)).isoformat()
    assert clients["bank_a"].post(P + "/assignments", json=body).status_code == (
        404 if change in {"foreign", "readonly"} else 422
    )


@pytest.fixture()
def pilot_setup(assured, ssh):
    from db.models.assurance import CollectionPhaseReceipt
    from db.models.hardware_live import HardwareAsset
    from db.models.vendor import Vendor
    from test_assurance_workflows import new_scan, source_job, signer_and_key, supplier_body
    from test_software_supply_chain_api import scan, attach, deploy
    from test_operator_decisions import tls, approved as approve_change, reported, check

    clients, db, tmp = assured
    a, reviewer = clients["bank_a"], admin(clients)
    eng, _, key, artifact, evidence = approved(clients, db)
    done(submit(a, eng, key, payload(eng, artifact, evidence)))
    sbom, _ = scan(a, tmp)
    binding = attach(a, artifact, sbom)
    deployment = done(deploy(a, artifact, system_id="system-a"))
    source = new_scan(db)
    source_job_row = source_job(db, source)
    ssh[2]["keys"] = [{"type": "ssh-ed25519", "fingerprint_sha256": "SHA256:synthetic"}]
    done(a.post("/api/v1/network/ssh-scan", json={"hosts": ["10.21.0.10"]}), 200)
    receipt = db.query(CollectionPhaseReceipt).filter_by(tenant_id="a", phase="host_keys").one()
    hardware = HardwareAsset(
        tenant_id="a",
        asset_id="fixture-hw",
        manufacturer="Fixture maker",
        model="Fixture device",
        firmware={"version": "1"},
    )
    vendor = Vendor(tenant_id="a", name="Synthetic Fixture Supplier")
    db.add_all([hardware, vendor])
    db.commit()
    signer, supplier_key, _ = signer_and_key(clients)
    supplier = done(a.post("/api/v1/assurance/supplier-evidence", json=supplier_body(artifact, signer, supplier_key)))
    done(reviewer.post(f"/api/v1/assurance/supplier-evidence/{supplier['subject_id']}/approve", json=approval()), 200)
    before = tls(db)
    change_id = approve_change(clients, before)
    reported(clients, change_id)
    after = tls(db, fp="b" * 64, start=utcnow() - timedelta(milliseconds=5))
    assert check(clients, change_id, after)["payload"]["result"] == "VERIFIED"
    refs = [
        ("source", "SOURCE", source.target_location, "LOCAL_SOURCE"),
        ("ssh", "ENDPOINT", receipt.endpoint, "SSH_HOST_KEYS"),
        ("tls", "ENDPOINT", "bank.example:443", "EXTERNAL_EXPORT"),
        ("deployment", "DEPLOYMENT", deployment["id"], "EXTERNAL_EXPORT"),
        ("hardware", "HARDWARE", hardware.id, "EXTERNAL_EXPORT"),
        ("supplier", "SUPPLIER", supplier["subject_id"], "EXTERNAL_EXPORT"),
    ]
    targets = [
        {
            "target_id": name,
            "system_id": "system-a",
            "owner_ref": "fixture/pilot-owner",
            "kind": kind,
            "source_class": "source" if kind == "SOURCE" else "network",
            "target_ref": ref,
            "method": method,
            "permission_ref": "permission/" + name,
            "freshness_seconds": 3600,
        }
        for name, kind, ref, method in refs
    ]
    reg = done(
        a.post(
            "/api/v1/assurance/registers",
            json={
                "expected_revision": 0,
                "scope_description": "One payments workflow only",
                "register_owner": "fixture/owner",
                "completeness": "PARTIAL",
                "completeness_evidence_ref": "fixture/partial",
                "targets": targets,
            },
        )
    )
    for target, job in (("source", source_job_row.id), ("ssh", receipt.job_id)):
        done(
            a.put(
                f"/api/v1/assurance/registers/{reg['subject_id']}/observations/{target}",
                json={
                    "expected_revision": 0,
                    "outcome": "RECEIPT",
                    "job_id": job,
                    "evidence_ref": "fixture/receipt",
                    "reason": "Observed exact fixture target",
                },
            ),
            200,
        )
    body = {
        "expected_revision": 0,
        "workflow": "PAYMENTS_RELEASE_REMEDIATION_V1",
        "title": "Synthetic payments release pilot",
        "business_value": "Prove one evidence-to-change loop",
        "customer_owner_user_id": uid(db, "platform_admin"),
        "technical_owner_user_id": uid(db, "bank_a"),
        "system_id": "system-a",
        "register_id": reg["subject_id"],
        "source_scan_id": source.id,
        "artifact_id": artifact["id"],
        "sbom_binding_id": binding["id"],
        "deployment_id": deployment["id"],
        "source_build_binding_blob_id": evidence["blob_id"],
        "tls_run_id": after.id,
        "tls_endpoint": "bank.example:443",
        "tls_permission_ref": "permission/tls",
        "ssh_receipt_id": receipt.id,
        "ssh_permission_ref": "permission/ssh",
        "hardware_id": hardware.id,
        "vendor_id": vendor.id,
        "supplier_evidence_id": supplier["subject_id"],
        "remediation_change_id": change_id,
        "engagement_id": eng["subject_id"],
        "success_criteria": ["Exact endpoint replacement fingerprint independently observed"],
        "exclusions": ["All other bank systems; no commercial SLA"],
        "expires_at": (utcnow() + timedelta(days=7)).isoformat(),
    }
    return clients, db, body, evidence


# Imported fixtures share the same real authenticated bank/SQL base.
from test_ssh_receipt_contract import ssh as ssh  # noqa: E402


def fill_operating_duties(clients, db, evidence):
    a, reviewer = clients["bank_a"], admin(clients)
    for duty in DUTIES:
        row = done(a.post(P + "/assignments", json=assignment_body(db, evidence, duty=duty)))
        path = P + f"/assignments/{row['subject_id']}"
        done(a.post(path + "/acknowledge", json=approval()))
        done(reviewer.post(path + "/acknowledge", json=approval(2)))
        done(
            a.post(
                path + "/exercises",
                json={
                    "expected_revision": 0,
                    "assignment_revision": 3,
                    "started_at": utcnow().isoformat(),
                    "ended_at": utcnow().isoformat(),
                    "evidence_blob_id": evidence["blob_id"],
                    "outcome": "PASSED",
                    "checks": ["Synthetic contract exercise"],
                    "limitations": ["No actual site qualification"],
                },
            )
        )
        done(reviewer.post(path + "/review-exercise", json=approval()))


def test_bounded_pilot_requires_operations_technical_and_customer_review_then_reopens(pilot_setup):
    clients, db, body, evidence = pilot_setup
    a, reviewer = clients["bank_a"], admin(clients)
    pilot = done(a.post(P + "/pilots", json=body))
    path = P + f"/pilots/{pilot['subject_id']}"
    status = done(a.get(path + "/status"), 200)
    assert "OPERATIONAL_OWNERSHIP_OR_EXERCISES_INCOMPLETE" in status["issues"]
    assert not status["evidence_loop_ready"] and not status["whole_bank_visibility"]
    assert reviewer.post(path + "/accept", json=approval()).status_code == 409
    assert clients["bank_b"].get(path + "/status").status_code == 404
    fill_operating_duties(clients, db, evidence)
    status = done(a.get(path + "/status"), 200)
    assert status["issues"] == ["CURRENT_TECHNICAL_OWNER_REVIEW_MISSING"]
    assert reviewer.post(path + "/technical-review", json=approval()).status_code == 409
    done(a.post(path + "/technical-review", json=approval()))
    done(reviewer.post(path + "/accept", json=approval(2)))
    status = done(a.get(path + "/status"), 200)
    assert status["commercial_acceptance_current"] and not status["sla_authorized"]
    assert status["unresolved_targets"] == ["tls", "deployment", "hardware", "supplier"]
    # New operating assertion invalidates the exact technical/acceptance snapshot.
    row = store.latest(db, "a", "operating_exercise", store.subject("duty", DUTIES[0]))
    store.append(
        db,
        "a",
        row.kind,
        row.subject_id,
        row.revision,
        {**row.payload, "review_reason": "Later review supersedes prior acceptance snapshot"},
        uid(db, "platform_admin"),
    )
    status = done(a.get(path + "/status"), 200)
    assert not status["commercial_acceptance_current"]
    assert "CURRENT_TECHNICAL_OWNER_REVIEW_MISSING" in status["issues"]
    # Fresh manifest also resets technical/customer reviews, never overwrites history.
    revised = done(a.put(path, json={**body, "expected_revision": 3}))
    assert revised["payload"]["state"] == "PROPOSED"
    assert a.put(path, json={**body, "expected_revision": 3}).status_code == 409


@pytest.mark.parametrize(
    "field",
    [
        "source_scan_id",
        "artifact_id",
        "sbom_binding_id",
        "deployment_id",
        "hardware_id",
        "vendor_id",
        "supplier_evidence_id",
        "tls_permission_ref",
        "ssh_permission_ref",
        "source_build_binding_blob_id",
    ],
)
def test_pilot_exact_identity_and_endpoint_permission_refusal(pilot_setup, field):
    clients, _, body, _ = pilot_setup
    body[field] = "unknown-or-unapproved"
    response = clients["bank_a"].post(P + "/pilots", json=body)
    assert response.status_code in {404, 409}, response.text


def test_external_payload_cli_matches_server_bytes_and_refuses_duplicate_keys(assured, tmp_path):
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "report_tool", Path(__file__).resolve().parents[4] / "scripts/independent_report.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    clients, db, _ = assured
    eng, _, key, artifact, evidence = approved(clients, db)
    p = payload(eng, artifact, evidence)
    path = tmp_path / "report.json"
    path.write_bytes(store.encoded(p))
    assert module.encoded(module.canonical(path)) == store.encoded(
        AssessmentReport.model_validate(p).model_dump(mode="json")
    )
    key.public_key().verify(
        key.sign(module.encoded(module.canonical(path))),
        store.encoded(AssessmentReport.model_validate(p).model_dump(mode="json")),
    )
    path.write_text('{"sequence":1,"sequence":2}')
    with pytest.raises(ValueError, match="Duplicate"):
        module.canonical(path)


@pytest.mark.parametrize("mode", ["revoked", "expired", "deactivated", "role_removed"])
def test_launch_write_rechecks_durable_human_authority(assured, mode):
    from db.models.user import UserSession

    clients, db, _ = assured
    evidence = blob(clients["bank_a"])
    body = assignment_body(db, evidence)
    user = db.query(User).filter_by(username="bank_a").one()
    session = db.query(UserSession).filter_by(user_id=user.id).one()
    if mode == "revoked":
        session.revoked_at = utcnow()
    if mode == "expired":
        session.expires_at = utcnow() - timedelta(seconds=1)
    if mode == "deactivated":
        user.is_active = False
    if mode == "role_removed":
        user.roles = "readonly"
    db.commit()
    assert clients["bank_a"].post(P + "/assignments", json=body).status_code in {401, 403}
    assert db.query(AssuranceRevision).filter_by(kind="operating_assignment").count() == 0


def test_machine_or_untyped_principal_cannot_acknowledge_human_duty(assured):
    from types import SimpleNamespace
    from db.repositories.execution_control import request_principal
    from fastapi import HTTPException

    clients, db, _ = assured
    request = SimpleNamespace(state=SimpleNamespace(api_key_auth=None))
    for principal in ({"v": 2, "kind": "api_key"}, {"v": 1, "kind": "user"}, None):
        with request_principal(principal), pytest.raises(HTTPException) as exc:
            store.actor(db, request, "bank_a", "assurance.operate")
        assert exc.value.status_code == 403


def test_pilot_gate_expiry_tamper_revocation_and_selected_source_binding(pilot_setup, monkeypatch):
    from api.assurance import launch
    from test_assurance_workflows import new_scan, source_job
    from db.models.assurance import CollectionPhaseReceipt

    clients, db, body, evidence = pilot_setup
    a = clients["bank_a"]
    pilot = done(a.post(P + "/pilots", json={**body, "evidence_max_age_seconds": 60}))
    path = P + f"/pilots/{pilot['subject_id']}"
    now = utcnow()
    monkeypatch.setattr(launch, "utcnow", lambda: now + timedelta(seconds=61))
    assert "ENDPOINT_OBSERVATIONS_STALE" in done(a.get(path + "/status"), 200)["issues"]
    monkeypatch.setattr(launch, "utcnow", utcnow)
    # Same source location but another completed scan must not substitute the
    # manifest's explicitly selected source observation in generic coverage.
    other = new_scan(db)
    job = source_job(db, other)
    done(
        a.put(
            f"/api/v1/assurance/registers/{body['register_id']}/observations/source",
            json={
                "expected_revision": 1,
                "outcome": "RECEIPT",
                "job_id": job.id,
                "evidence_ref": "fixture/later-scan",
                "reason": "New separate observation",
            },
        ),
        200,
    )
    assert "SOURCE_COVERAGE_DOES_NOT_BIND_SELECTED_SCAN" in done(a.get(path + "/status"), 200)["issues"]
    receipt = db.get(CollectionPhaseReceipt, body["ssh_receipt_id"])
    receipt.observation = {"tampered": True}
    db.commit()
    status = done(a.get(path + "/status"), 200)
    assert any("SSH observation integrity" in x for x in status["issues"])
    assert not status["commercial_acceptance_current"]
    eng = store.latest(db, "a", "security_engagement", body["engagement_id"])
    done(admin(clients).post(P + f"/engagements/{body['engagement_id']}/withdraw", json=approval(eng.revision)))
    assert "INDEPENDENT_SECURITY_RECORDS_INCOMPLETE" in done(a.get(path + "/status"), 200)["issues"]


def test_launch_templates_are_typed_unexecuted_starting_points():
    import json
    from pathlib import Path
    from shared_models.launch_assurance import Engagement, OperatingAssignment, OperatingExercise, Pilot

    from shared_models.launch_assurance import FindingPlan, FindingCompletion

    root = Path(__file__).resolve().parents[4] / "docs/templates/launch"
    for name, model in (
        ("engagement", Engagement),
        ("assessment-report", AssessmentReport),
        ("operating-assignment", OperatingAssignment),
        ("operating-exercise", OperatingExercise),
        ("payments-pilot", Pilot),
    ):
        model.model_validate(json.loads((root / (name + ".json")).read_text()))
    for name, model in (("finding-plan", FindingPlan), ("finding-completion", FindingCompletion)):
        model.model_validate(json.loads((root / (name + ".json")).read_text()))
    report = json.loads((root / "assessment-report.json").read_text())
    assert all(case["outcome"] == "NOT_TESTED" for case in report["cases"])
    assert "signature_base64" not in report


def test_corrupt_retained_report_evidence_is_not_current_assurance(assured):
    from sqlalchemy import update
    from db.models.assurance import AssuranceBlob

    clients, db, _ = assured
    eng, _, key, artifact, evidence = approved(clients, db)
    done(submit(clients["bank_a"], eng, key, payload(eng, artifact, evidence)))
    # Privileged bulk mutation simulates damaged storage, not an allowed ORM write.
    db.execute(update(AssuranceBlob).where(AssuranceBlob.id == evidence["blob_id"]).values(data=b"damaged"))
    db.commit()
    status = done(clients["bank_a"].get(P + f"/engagements/{eng['subject_id']}/status"), 200)
    assert "SCOPE_OR_REPORT_EVIDENCE_UNAVAILABLE_OR_CORRUPT" in status["issues"]
    assert status["state"] == "BLOCKED"


def test_rediscovery_cannot_shrink_tracked_finding_case_set(assured):
    clients, db, _ = assured
    eng, _, key, artifact, evidence = approved(clients, db)
    p = payload(eng, artifact, evidence)
    for case in p["cases"][:2]:
        case["outcome"] = "FAILED"
    finding = {
        "finding_ref": "F-1",
        "case_ids": [c["case_id"] for c in p["cases"][:2]],
        "severity": "HIGH",
        "description": "Synthetic two-case isolation finding",
        "evidence_ref": "fixture/negative",
    }
    p["findings"] = [finding]
    done(submit(clients["bank_a"], eng, key, p))
    p = payload(eng, artifact, evidence, 2)
    p["cases"][0]["outcome"] = "FAILED"
    p["findings"] = [{**finding, "case_ids": [finding["case_ids"][0]]}]
    assert submit(clients["bank_a"], eng, key, p, 1).status_code == 409
    assert store.latest(db, "a", "security_report", eng["subject_id"]).revision == 1


def test_report_and_finding_revision_commit_is_atomic(assured, monkeypatch):
    from fastapi import HTTPException

    clients, db, _ = assured
    eng, _, key, artifact, evidence = approved(clients, db)
    p = payload(eng, artifact, evidence)
    p["cases"][0]["outcome"] = "FAILED"
    p["findings"] = [
        {
            "finding_ref": "F-atomic",
            "case_ids": [p["cases"][0]["case_id"]],
            "severity": "HIGH",
            "description": "Synthetic transaction failure",
            "evidence_ref": "fixture/atomic",
        }
    ]
    append = store.append

    def fail_finding(session, owner, kind, *args, **kwargs):
        if kind == "security_finding":
            raise HTTPException(409, "Simulated finding write failure")
        return append(session, owner, kind, *args, **kwargs)

    monkeypatch.setattr(store, "append", fail_finding)
    assert submit(clients["bank_a"], eng, key, p).status_code == 409
    assert store.latest(db, "a", "security_report", eng["subject_id"], required=False) is None
    assert db.query(AssuranceRevision).filter_by(kind="security_finding").count() == 0
