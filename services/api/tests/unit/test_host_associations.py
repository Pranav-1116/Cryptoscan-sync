"""Actual scoped identities/host evidence, not matching-name or runtime proof."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import pytest
from sqlalchemy import text
from test_assurance_workflows import assured as assured, admin
from test_software_supply_chain_api import banks as banks, register, scan as scan_sbom, attach, deploy
from test_host_evidence import setup, submit, P
from test_execution_controls import controlled as controlled, configure
from test_ssh_receipt_contract import ssh as ssh
from db.models.assurance import AssuranceRevision, CollectionPhaseReceipt
from db.models.hardware_live import HardwareAsset
from db.models.vendor import Vendor
from db.models.scan_job import ScanJob
from db.models.evidence_record import EvidenceRecord
from db.models.software_supply_chain import ReleaseSbomBinding, SoftwareDeployment
from db.repositories.user_repository import UserRepository, verify_audit_chain
from api.assurance import store


def ready(assured):
    clients, db, identifier, _, snapshot = setup(assured)
    response = submit(clients, identifier, snapshot)
    assert response.status_code == 201, response.text
    hardware = HardwareAsset(
        tenant_id="a",
        asset_id="synthetic-hsm-a",
        device_type="hsm",
        manufacturer="Synthetic",
        model="fixture",
        current_fingerprint="a" * 64,
    )
    vendor = Vendor(tenant_id="a", name="Synthetic supplier", extra_json={"ML-KEM": "vendor-only declaration"})
    job = ScanJob(
        tenant_id="a",
        system_id="system-a",
        target_repo="synthetic.invalid:22",
        triggered_by="fixture",
        job_type="MANUAL",
        status="COMPLETED",
    )
    db.add_all([hardware, vendor, job])
    db.flush()
    observation = {
        "status": "OK",
        "endpoint": "synthetic.invalid:22",
        "keys": [{"key_type": "ssh-ed25519", "bits": 256}],
    }
    receipt = CollectionPhaseReceipt(
        tenant_id="a",
        job_id=job.id,
        ordinal=0,
        endpoint="synthetic.invalid:22",
        phase="host_keys",
        started_at=datetime.now(timezone.utc),
        state="COMPLETED",
        observation_succeeded=True,
        observation=observation,
        observation_sha256=store.digest(observation),
    )
    db.add(receipt)
    db.commit()
    targets = {"hardware": hardware.id, "vendor": vendor.id, "phase_receipt": receipt.id}
    return clients, db, identifier, targets


def path(identifier):
    return P + f"/approvals/{identifier}"


def resolved(client, identifier, target_type, target_id, package=None):
    params = {"target_type": target_type, "target_id": target_id}
    if package:
        params["package_identity"] = package
    return client.get(path(identifier) + "/association-target", params=params)


def proposal(clients, identifier, typ, target_id, package=None, **changes):
    result = resolved(clients["bank_a"], identifier, typ, target_id, package)
    assert result.status_code == 200, result.text
    return {
        "input_id": "cert",
        "fact_ordinal": 0,
        "target_type": typ,
        "target_id": target_id,
        "package_identity": package,
        "expected_target_sha256": result.json()["target_sha256"],
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
        "reason": "Explicit association reviewed against separate bank scope evidence",
        "evidence_ref": "review/association-17",
        **changes,
    }


def create(clients, identifier, body):
    result = clients["bank_a"].post(path(identifier) + "/associations", json=body)
    assert result.status_code == 201, result.text
    return result.json()


def decide(clients, identifier, record, *, retract=False, client=None):
    return (client or admin(clients)).post(
        path(identifier) + f"/associations/{record['subject_id']}/" + ("retract" if retract else "review"),
        json={
            "expected_revision": record["revision"],
            "evidence_ref": "review/independent-18",
            "reason": "Independent customer reviewer checked this limited metadata association",
        },
    )


def graph(client, identifier):
    return client.get(path(identifier) + "/graph")


def test_no_relationships_from_coexistence_and_pending_is_not_a_graph_edge(assured):
    clients, db, identifier, targets = ready(assured)
    result = graph(clients["reader_a"], identifier)
    assert result.status_code == 200, result.text
    value = result.json()
    assert set(value["domains"]) == {"SBOM", "CBOM", "NBOM", "HBOM", "VBOM", "TechBOM"}
    assert not value["domains"]["HBOM"]["represented"] and not value["domains"]["VBOM"]["represented"]
    assert all(e["predicate"] != "CUSTOMER_REVIEWED_METADATA_ASSOCIATION" for e in value["edges"])
    pending = create(clients, identifier, proposal(clients, identifier, "hardware", targets["hardware"]))
    assert graph(clients["reader_a"], identifier).json()["associations"][0]["state"] == "PROPOSED"
    assert not graph(clients["reader_a"], identifier).json()["domains"]["HBOM"]["represented"]
    reviewed = decide(clients, identifier, pending)
    assert reviewed.status_code == 200, reviewed.text
    value = graph(clients["reader_a"], identifier).json()
    edge = next(e for e in value["edges"] if e["predicate"] == "CUSTOMER_REVIEWED_METADATA_ASSOCIATION")
    assert (
        edge["evidence_status"] == "DECLARED"
        and edge["runtime_use"] == "UNKNOWN"
        and not edge["operational_dependency_verified"]
    )
    assert edge["provenance"]["reviewed_by"] != edge["provenance"]["proposed_by"]
    assert edge["provenance"]["snapshot_sha256"] == value["snapshot_sha256"]
    assert edge["provenance"]["evidence_id"] and edge["provenance"]["fact_sha256"]
    assert value["pqc_use"] == "UNKNOWN" and not value["host_identity_attested"]
    assert verify_audit_chain(db)["status"] == "OK"


def test_all_six_boms_are_connected_only_by_explicit_reviewed_associations(assured):
    clients, db, identifier, targets = ready(assured)
    _, _, tmp = assured
    artifact = register(clients["bank_a"])
    sbom, purl = scan_sbom(clients["bank_a"], tmp)
    binding = attach(clients["bank_a"], artifact, sbom)
    deployed = deploy(clients["bank_a"], artifact, system_id="system-a")
    assert deployed.status_code == 201, deployed.text
    targets.update(sbom_binding=binding["id"], deployment=deployed.json()["id"])
    for typ, target_id in targets.items():
        row = create(
            clients, identifier, proposal(clients, identifier, typ, target_id, purl if typ == "sbom_binding" else None)
        )
        review = decide(clients, identifier, row)
        assert review.status_code == 200, review.text
    result = graph(clients["reader_a"], identifier)
    assert result.status_code == 200, result.text
    value = result.json()
    assert all(v["represented"] and v["operational_use"] == "UNKNOWN" for v in value["domains"].values())
    assert len([e for e in value["edges"] if e["predicate"] == "CUSTOMER_REVIEWED_METADATA_ASSOCIATION"]) == 5
    for e in value["edges"]:
        assert e["provenance"] and e["runtime_use"] == "UNKNOWN" and not e["operational_dependency_verified"]
    package_edge = next(
        e
        for e in value["edges"]
        if e["predicate"] == "CUSTOMER_REVIEWED_METADATA_ASSOCIATION"
        and e["provenance"]["target_type"] == "sbom_binding"
    )
    assert package_edge["provenance"]["package_identity"] == purl
    assert next(n for n in value["nodes"] if n["id"] == package_edge["to"])["package_identity"] == purl
    assert any(
        n["bom"] == "CBOM" and n["kind"] == "TLS_CONFIGURATION" and n["metadata"]["local_basis"] == "DECLARED"
        for n in value["nodes"]
    )
    export = clients["reader_a"].get(path(identifier) + "/graph/export")
    assert export.status_code == 200, export.text
    assert export.headers["Cache-Control"] == "no-store"
    assert verify_audit_chain(db)["status"] == "OK"
    # Existing native CBOM is still metadata, not inferred dependency fanout.
    assert not clients["bank_a"].get(path(identifier) + "/cbom").json().get("dependencies")


@pytest.mark.parametrize("role", ["readonly", "auditor"])
def test_readers_cannot_propose_review_retract_or_modify_scans(assured, role):
    clients, db, identifier, targets = ready(assured)
    body = proposal(clients, identifier, "vendor", targets["vendor"])
    row = create(clients, identifier, body)
    UserRepository(db).set_roles("reader_a", [role])
    db.commit()
    reader = clients["reader_a"]
    assert graph(reader, identifier).status_code == 200
    assert reader.post(path(identifier) + "/associations", json=body).status_code == 403
    assert decide(clients, identifier, row, client=reader).status_code == 403
    assert decide(clients, identifier, row, client=reader, retract=True).status_code == 403
    # A proposer who later gets CISO authority is still the SAME human.
    UserRepository(db).set_roles("bank_a", ["ciso"])
    db.commit()
    assert decide(clients, identifier, row, client=clients["bank_a"]).status_code == 409


@pytest.mark.parametrize(
    "change", ["fingerprint", "expired", "foreign", "hardware_claim", "vendor_claim", "target_deleted"]
)
def test_stale_target_removes_only_reviewed_association_not_history(assured, change):
    clients, db, identifier, targets = ready(assured)
    typ = "vendor" if change == "vendor_claim" else "hardware"
    row = create(clients, identifier, proposal(clients, identifier, typ, targets[typ]))
    assert decide(clients, identifier, row).status_code == 200
    if change == "fingerprint":
        db.get(HardwareAsset, targets[typ]).current_fingerprint = "b" * 64
    if change == "foreign":
        db.execute(text("UPDATE hardware_assets SET tenant_id='b' WHERE id=:id"), {"id": targets[typ]})
    if change == "hardware_claim":
        db.get(HardwareAsset, targets[typ]).crypto_capabilities = {"ML-KEM": "changed supplier-only assertion"}
    if change == "target_deleted":
        db.execute(text("DELETE FROM hardware_assets WHERE id=:id"), {"id": targets[typ]})
    if change == "vendor_claim":
        db.get(Vendor, targets[typ]).extra_json = {"ML-KEM": "changed supplier-only assertion"}
    db.commit()
    db.expire_all()
    from api.assurance import host_associations

    with (
        patch.object(host_associations, "utcnow", return_value=datetime.now(timezone.utc) + timedelta(days=2))
        if change == "expired"
        else patch.object(host_associations, "utcnow", wraps=host_associations.utcnow)
    ):
        response = graph(clients["reader_a"], identifier)
    assert response.status_code == 200, response.text
    value = response.json()
    assert value["associations"][0]["state"] == "STALE"
    assert not any(e["predicate"] == "CUSTOMER_REVIEWED_METADATA_ASSOCIATION" for e in value["edges"])
    assert store.latest(db, "a", "bom_relationship", row["subject_id"]).payload["state"] == "REVIEWED"


def test_scope_ownership_and_generic_approval_cannot_bypass_host_adapter(assured):
    clients, db, identifier, targets = ready(assured)
    body = proposal(clients, identifier, "hardware", targets["hardware"])
    row = create(clients, identifier, body)
    assert (
        admin(clients)
        .post(
            "/api/v1/assurance/relationships/" + row["subject_id"] + "/approve",
            json={
                "expected_revision": 1,
                "evidence_ref": "review/test",
                "reason": "Must not bypass host-specific source and target validation",
            },
        )
        .status_code
        == 409
    )
    for reader in (clients["bank_b"], clients["platform_admin"]):
        assert graph(reader, identifier).status_code == 404
        assert resolved(reader, identifier, "hardware", targets["hardware"]).status_code == 404
    foreign = HardwareAsset(tenant_id="b", asset_id="foreign", device_type="hsm")
    db.add(foreign)
    db.commit()
    assert resolved(clients["bank_a"], identifier, "hardware", foreign.id).status_code == 404


@pytest.mark.parametrize("change", ["denied_input", "ordinal", "target_sha", "raw", "promote", "package_on_hardware"])
def test_invalid_or_promoted_association_is_not_persisted(assured, change):
    clients, db, identifier, targets = ready(assured)
    body = proposal(clients, identifier, "hardware", targets["hardware"])
    if change == "denied_input":
        body["input_id"] = "denied"
    if change == "ordinal":
        body["fact_ordinal"] = 999
    if change == "target_sha":
        body["expected_target_sha256"] = "f" * 64
    if change == "raw":
        body["raw_contents"] = "forbidden"
    if change == "promote":
        body["runtime_use"] = "OBSERVED"
    if change == "package_on_hardware":
        body["package_identity"] = "pkg:pypi/requests@2.31.0"
    result = clients["bank_a"].post(path(identifier) + "/associations", json=body)
    assert result.status_code in {409, 422}, result.text
    assert not db.query(AssuranceRevision).filter_by(kind="bom_relationship").count()


@pytest.mark.parametrize("change", ["failed", "observation_hash", "job_system", "job_failed"])
def test_failed_or_unbound_endpoint_does_not_establish_association(assured, change):
    clients, db, identifier, targets = ready(assured)
    receipt = db.get(CollectionPhaseReceipt, targets["phase_receipt"])
    if change == "failed":
        receipt.observation_succeeded = False
    if change == "observation_hash":
        receipt.observation_sha256 = "b" * 64
    if change == "job_system":
        db.get(ScanJob, receipt.job_id).system_id = "system-b"
    if change == "job_failed":
        db.get(ScanJob, receipt.job_id).status = "FAILED"
    db.commit()
    assert resolved(clients["bank_a"], identifier, "phase_receipt", receipt.id).status_code == 409


def test_retraction_and_stale_revision_do_not_delete_provenance(assured):
    clients, db, identifier, targets = ready(assured)
    row = create(clients, identifier, proposal(clients, identifier, "hardware", targets["hardware"]))
    reviewed = decide(clients, identifier, row)
    assert reviewed.status_code == 200
    assert decide(clients, identifier, row, retract=True).status_code == 409
    retracted = decide(clients, identifier, reviewed.json(), retract=True)
    assert retracted.status_code == 200
    value = graph(clients["reader_a"], identifier).json()
    assert value["associations"][0]["state"] == "RETRACTED"
    assert not any(e["predicate"] == "CUSTOMER_REVIEWED_METADATA_ASSOCIATION" for e in value["edges"])
    assert db.query(AssuranceRevision).filter_by(kind="bom_relationship").count() == 3


@pytest.mark.parametrize("change", ["host_content", "association_hash", "missing_predecessor", "history_budget"])
def test_graph_fails_closed_on_integrity_or_budget_failure(assured, change, monkeypatch):
    clients, db, identifier, targets = ready(assured)
    row = create(clients, identifier, proposal(clients, identifier, "hardware", targets["hardware"]))
    assert decide(clients, identifier, row).status_code == 200
    if change == "host_content":
        db.query(EvidenceRecord).first().finding_data = {"tampered": True}
    if change == "association_hash":
        db.execute(
            text("UPDATE assurance_revisions SET payload_sha256=:sha WHERE kind='bom_relationship' AND revision=1"),
            {"sha": "f" * 64},
        )
    if change == "missing_predecessor":
        db.execute(text("DELETE FROM assurance_revisions WHERE kind='bom_relationship' AND revision=1"))
    if change == "history_budget":
        from api.assurance import host_associations

        monkeypatch.setattr(host_associations, "MAX_HISTORY", 1)
    db.commit()
    db.expire_all()
    assert graph(clients["reader_a"], identifier).status_code == 409


def test_association_audit_failure_is_atomic(assured, monkeypatch):
    clients, db, identifier, targets = ready(assured)
    body = proposal(clients, identifier, "hardware", targets["hardware"])
    original = UserRepository.audit

    def fail(self, *args, **kwargs):
        if args[1].startswith("host.association."):
            raise RuntimeError("synthetic association audit failure")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(UserRepository, "audit", fail)
    with pytest.raises(RuntimeError, match="association audit"):
        clients["bank_a"].post(path(identifier) + "/associations", json=body)
    assert db.query(AssuranceRevision).filter_by(kind="bom_relationship").count() == 0


def test_new_graph_routes_remain_blocked_in_production(controlled):
    configure(controlled)
    for suffix in ["graph", "graph/export", "association-target?target_type=hardware&target_id=x"]:
        assert controlled["clients"]["bank_a"].get(path("x") + "/" + suffix).status_code == 409


@pytest.mark.parametrize("value", [None, 123, True, [], {}, "bad", "2026-10-25T00:00:00"])
def test_bad_expiry_is_a_validation_refusal_not_server_error(assured, value):
    clients, _, identifier, targets = ready(assured)
    body = proposal(clients, identifier, "hardware", targets["hardware"], expires_at=value)
    assert clients["bank_a"].post(path(identifier) + "/associations", json=body).status_code == 422


@pytest.mark.parametrize("change", ["target_changed", "role_revoked", "audit_failure", "source_changed"])
def test_review_revalidates_current_authority_and_source_atomically(assured, monkeypatch, change):
    clients, db, identifier, targets = ready(assured)
    row = create(clients, identifier, proposal(clients, identifier, "hardware", targets["hardware"]))
    if change == "target_changed":
        db.get(HardwareAsset, targets["hardware"]).current_fingerprint = "f" * 64
    if change == "source_changed":
        db.query(EvidenceRecord).first().finding_data = {"corrupt": True}
    if change == "role_revoked":
        UserRepository(db).set_roles("platform_admin", ["readonly"])
    db.commit()
    if change == "audit_failure":

        def fail(*args, **kwargs):
            raise RuntimeError("synthetic review audit failure")

        monkeypatch.setattr(UserRepository, "audit", fail)
        with pytest.raises(RuntimeError, match="review audit"):
            decide(clients, identifier, row)
    else:
        response = decide(clients, identifier, row)
        assert response.status_code == (403 if change == "role_revoked" else 409), response.text
    assert store.latest(db, "a", "bom_relationship", row["subject_id"]).revision == 1


@pytest.mark.parametrize("change", ["audit_deleted", "audit_changed", "retraction_tail_deleted"])
def test_audit_commitment_detects_missing_or_changed_history(assured, change):
    clients, db, identifier, targets = ready(assured)
    row = create(clients, identifier, proposal(clients, identifier, "hardware", targets["hardware"]))
    reviewed = decide(clients, identifier, row)
    assert reviewed.status_code == 200
    if change == "audit_deleted":
        db.execute(text("DELETE FROM audit_log WHERE action='host.association.propose'"))
    if change == "audit_changed":
        db.execute(text("UPDATE audit_log SET detail='{}' WHERE action='host.association.review'"))
    if change == "retraction_tail_deleted":
        assert decide(clients, identifier, reviewed.json(), retract=True).status_code == 200
        db.execute(text("DELETE FROM assurance_revisions WHERE kind='bom_relationship' AND revision=3"))
    db.commit()
    db.expire_all()
    assert graph(clients["reader_a"], identifier).status_code == 409


@pytest.mark.parametrize(
    "change", ["wrong_package", "wrong_environment", "retracted_deployment", "binding_hash", "original_bytes"]
)
def test_exact_sbom_and_deployment_closure_are_reopened(assured, monkeypatch, change):
    clients, db, identifier, _ = ready(assured)
    _, _, tmp = assured
    artifact = register(clients["bank_a"])
    sbom, purl = scan_sbom(clients["bank_a"], tmp)
    binding = attach(clients["bank_a"], artifact, sbom)
    deployed = deploy(clients["bank_a"], artifact, system_id="system-a").json()
    body = proposal(clients, identifier, "sbom_binding", binding["id"], purl)
    row = create(clients, identifier, body)
    if change == "wrong_package":
        assert (
            resolved(
                clients["bank_a"], identifier, "sbom_binding", binding["id"], "pkg:pypi/requests@0.0.0"
            ).status_code
            == 409
        )
        return
    if change == "wrong_environment":
        db.get(SoftwareDeployment, deployed["id"]).environment = "test"
    if change == "retracted_deployment":
        db.get(SoftwareDeployment, deployed["id"]).lifecycle_state = "RETRACTED"
    if change == "binding_hash":
        db.get(ReleaseSbomBinding, binding["id"]).sbom_sha256 = "f" * 64
    if change == "original_bytes":
        monkeypatch.setattr("api.routers.devsecops._artifact_blob", lambda *a, **k: (b'{"components":[]}', None))
    db.commit()
    assert decide(clients, identifier, row).status_code == 409
    assert graph(clients["reader_a"], identifier).json()["associations"][0]["state"] == "STALE"


@pytest.mark.parametrize(
    "change", ["unsupported_phase", "old_observation", "missing_time", "no_keys", "endpoint_mismatch"]
)
def test_unsupported_stale_or_incomplete_network_metadata_stays_unresolved(assured, change):
    clients, db, identifier, targets = ready(assured)
    row = db.get(CollectionPhaseReceipt, targets["phase_receipt"])
    if change == "unsupported_phase":
        row.phase = "OPEN_PORT"
    if change == "old_observation":
        row.started_at = datetime.now(timezone.utc) - timedelta(days=8)
    if change == "missing_time":
        row.started_at = None
    if change in {"no_keys", "endpoint_mismatch"}:
        row.observation = {
            **row.observation,
            **({"keys": []} if change == "no_keys" else {"endpoint": "different.invalid:22"}),
        }
        row.observation_sha256 = store.digest(row.observation)
    db.commit()
    assert resolved(clients["bank_a"], identifier, "phase_receipt", row.id).status_code == 409


def test_real_ssh_receipt_producer_can_be_associated_without_claiming_endpoint_identity(assured, ssh):
    clients, db, identifier, _ = ready(assured)
    _, _, state = ssh
    state["keys"] = [{"key_type": "ssh-ed25519", "bits": 256}]
    collected = clients["bank_a"].post("/api/v1/network/ssh-scan", json={"hosts": ["10.21.0.10"], "include_kex": False})
    assert collected.status_code == 200, collected.text
    phase = db.query(CollectionPhaseReceipt).filter_by(job_id=collected.json()["job_id"]).one()
    assert db.get(ScanJob, phase.job_id).system_id is None  # no existing system identity is invented
    row = create(clients, identifier, proposal(clients, identifier, "phase_receipt", phase.id))
    review = decide(clients, identifier, row)
    assert review.status_code == 200, review.text
    result = graph(clients["reader_a"], identifier).json()
    assert result["domains"]["NBOM"]["represented"] and result["domains"]["NBOM"]["operational_use"] == "UNKNOWN"
    assert not result["host_identity_attested"]


def test_complete_projection_byte_budget_is_an_explicit_refusal(assured, monkeypatch):
    clients, _, identifier, _ = ready(assured)
    from api.assurance import host_associations

    monkeypatch.setattr(host_associations, "MAX_GRAPH_BYTES", 1)
    response = graph(clients["reader_a"], identifier)
    assert response.status_code == 409 and "byte budget" in response.json()["detail"]


def test_host_input_reference_ids_are_unambiguous(assured):
    clients, db, identifier, body, snapshot = setup(assured)
    from shared_models.host_collection import HostManifest

    original = body["manifest"]
    original["inputs"][1]["input_id"] = "cert:fact:0"
    manifest = HostManifest.model_validate(original)
    # A distinct approved profile; never rewrite the immutable first approval.
    approved = admin(clients).post(
        P + "/approvals", json={"system_id": "system-a", "manifest": manifest.model_dump(mode="json")}
    )
    assert approved.status_code == 201, approved.text
    identifier = approved.json()["subject_id"]
    from inventory.host import collect

    updated = collect(manifest).model_dump(mode="json")
    response = submit(clients, identifier, updated)
    assert response.status_code == 201, response.text
    result = graph(clients["reader_a"], identifier)
    assert result.status_code == 200, result.text
    node_ids = [n["id"] for n in result.json()["nodes"]]
    assert len(node_ids) == len(set(node_ids))


def test_pending_retraction_retains_the_original_proposer(assured):
    clients, db, identifier, targets = ready(assured)
    row = create(clients, identifier, proposal(clients, identifier, "hardware", targets["hardware"]))
    result = decide(clients, identifier, row, retract=True)
    assert result.status_code == 200, result.text
    value = graph(clients["reader_a"], identifier).json()["associations"][0]
    assert value["proposed_by"] == row["created_by"]
    assert value["created_by"] != value["proposed_by"] and value["state"] == "RETRACTED"


@pytest.mark.parametrize("method,budget,scope", [("post", 10, "host_write"), ("get", 60, "host_read")])
def test_graph_routes_use_actual_host_rate_buckets(assured, method, budget, scope):
    from fastapi.testclient import TestClient
    from api.middleware.rate_limit import RateLimitMiddleware

    clients, _, _ = assured
    with TestClient(RateLimitMiddleware(clients["bank_a"].app)) as limited:
        limited.cookies.update(clients["bank_a"].cookies)
        request = (
            (lambda: limited.post(path("missing") + "/associations", json={}))
            if method == "post"
            else (lambda: graph(limited, "missing"))
        )
        responses = [request() for _ in range(budget + 1)]
    assert all(r.status_code == (422 if method == "post" else 404) for r in responses[:budget])
    assert responses[-1].status_code == 429 and responses[-1].json()["scope"] == scope
    assert "Retry-After" in responses[-1].headers
