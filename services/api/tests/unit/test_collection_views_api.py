"""Real auth/SQL/retained-source snapshots and drift; synthetic fixtures only."""

from copy import deepcopy
import pytest
from test_assurance_workflows import assured as assured, admin
from test_software_supply_chain_api import banks as banks
from test_execution_controls import controlled as controlled, configure
import test_collection_foundation as host
import test_oci_collection_api as oci
from db.models.assurance import AssuranceRevision
from db.models.user import AuditLog
from db.repositories.user_repository import UserRepository, verify_audit_chain
from api.assurance import store
from shared_models.host_collection import digest
from shared_models.oci_intake import OciJobReturn
from inventory.collection import OfflineLinuxCollector

P = "/api/v1/collection"


def request_for(clients, family, job):
    jid = job["subject_id"]
    if family == "host":
        source = clients["reader_a"].get(P + f"/jobs/{jid}/evidence")
        assert source.status_code == 200, source.text
        sha = source.json()["envelope_sha256"]
    else:
        source = clients["reader_a"].get(P + f"/oci/jobs/{jid}/evidence")
        assert source.status_code == 200, source.text
        sha = digest(OciJobReturn.model_validate(source.json()).evidence)
    return {"family": family, "job_id": jid, "expected_source_sha256": sha}


def take(clients, body):
    result = clients["bank_a"].post(P + "/snapshots", json=body)
    assert result.status_code == 201, result.text
    return result.json()


def second_host(clients, body, auth):
    tid = auth["subject_id"]
    changed = admin(clients).put(P + f"/targets/{tid}", json={"expected_revision": auth["revision"], "target": body})
    assert changed.status_code == 200, changed.text
    authorized = admin(clients).post(P + f"/targets/{tid}/authorize", json=host.decision(changed.json()["revision"]))
    assert authorized.status_code == 200, authorized.text
    job = clients["bank_a"].post(
        P + "/jobs", json={"target_id": tid, "expected_target_revision": authorized.json()["revision"]}
    )
    assert job.status_code == 201, job.text
    jid = job.json()["subject_id"]
    assert clients["bank_a"].post(P + f"/jobs/{jid}/handoff", json={"expected_revision": 1}).status_code == 200
    intake = host.imported(clients, body, authorized.json())
    assert intake.status_code == 201, intake.text
    result = clients["bank_a"].post(P + f"/jobs/{jid}/complete", json={"expected_revision": 2})
    assert result.status_code == 200, result.text
    return result.json()


def pair(assured):
    clients, db, body, auth, job = host.completed(assured)
    first = take(clients, request_for(clients, "host", job))
    second = second_host(clients, body, auth)
    latest = take(clients, request_for(clients, "host", second))
    return clients, db, first, latest


def drift(clients, first, latest):
    response = clients["bank_a"].post(
        P + "/metadata-drift",
        json={"baseline_snapshot_id": first["subject_id"], "candidate_snapshot_id": latest["subject_id"]},
    )
    assert response.status_code == 201, response.text
    return response.json()


@pytest.mark.parametrize("family", ["host", "oci"])
def test_snapshot_is_durable_six_view_graph_over_original_source_without_execution(assured, monkeypatch, family):
    clients, db, _, _, job = host.completed(assured) if family == "host" else oci.complete(assured)
    body = request_for(clients, family, job)
    count = db.query(AuditLog).count()

    def no_collection(*args, **kwargs):
        raise AssertionError("Snapshot/read must never execute collection")

    monkeypatch.setattr(OfflineLinuxCollector, "collect", no_collection)
    monkeypatch.setattr("inventory.oci_job_capture.capture_oci_job", no_collection)
    row = take(clients, body)
    value = row["payload"]
    assert db.query(AuditLog).count() == count + 1
    assert value["snapshot"]["source_sha256"] == body["expected_source_sha256"]
    assert value["snapshot"]["runtime_use"] == "UNKNOWN"
    assert value["snapshot_sha256"] == digest(value["snapshot"])
    assert set(value["domains"]) == {"SBOM", "CBOM", "NBOM", "HBOM", "VBOM", "TechBOM"}
    assert not value["standard_document"]
    assert {e["relationship"] for e in value["metadata_graph"]["edges"]} == {"HAS_METADATA_REFERENCE"}
    if family == "oci":
        assert value["domains"]["VBOM"]["state"] == "DECLARED_ONLY"
        assert value["coverage"]["approved_inputs"] == 3  # config is not an extra approved file
    else:
        assert value["coverage"]["parsed_inputs"] == 3 and value["coverage"]["approved_inputs"] == 4
    path = P + "/snapshots/" + row["subject_id"]
    read = clients["reader_a"].get(path)
    assert read.status_code == 200, read.text
    assert read.json()["payload"] == row["payload"] and read.headers["Cache-Control"] == "no-store"
    assert clients["bank_a"].post(P + "/snapshots", json=body).status_code == 409
    assert clients["reader_a"].get(P + "/snapshots").json()["snapshots"][0]["source_revalidated"]
    assert verify_audit_chain(db)["status"] == "OK"


@pytest.mark.parametrize("outcome", ["PARTIAL", "FAILED"])
def test_oci_input_gaps_stay_visible_and_vbom_stays_declared(assured, outcome):
    clients, _, _, _, job = oci.complete(assured, outcome=outcome)
    row = take(clients, request_for(clients, "oci", job))
    value = row["payload"]
    assert any(i["status"] != "PARSED" for i in value["snapshot"]["inputs"] if i["input_basis"] == "APPROVED_INPUT")
    assert not value["snapshot"]["whole_asset_coverage_verified"]
    assert value["domains"]["VBOM"]["state"] == "DECLARED_ONLY"
    assert value["domains"]["NBOM"]["state"] == value["domains"]["HBOM"]["state"] == "UNKNOWN"


def test_host_repeat_identity_drift_and_cursor_pages(assured):
    clients, db, first, latest = pair(assured)
    event = drift(clients, first, latest)
    report = event["payload"]["report"]
    assert not report["changes"] and report["unchanged_slots"] == 3
    assert event["payload"]["baseline_record_sha256"] == first["payload_sha256"]
    read = clients["reader_a"].get(P + "/metadata-drift/" + event["subject_id"])
    assert read.status_code == 200 and read.json()["payload"] == event["payload"]
    assert (
        clients["bank_a"]
        .post(
            P + "/metadata-drift",
            json={"baseline_snapshot_id": first["subject_id"], "candidate_snapshot_id": latest["subject_id"]},
        )
        .status_code
        == 409
    )
    page = clients["reader_a"].get(P + "/snapshots?limit=1").json()
    assert len(page["snapshots"]) == 1 and page["next_cursor"]
    next_page = clients["reader_a"].get(P + "/snapshots?limit=1&cursor=" + page["next_cursor"]).json()
    assert len(next_page["snapshots"]) == 1 and next_page["next_cursor"] is None
    assert {page["snapshots"][0]["snapshot_id"], next_page["snapshots"][0]["snapshot_id"]} == {
        first["subject_id"],
        latest["subject_id"],
    }
    assert verify_audit_chain(db)["status"] == "OK"


def test_host_later_failed_certificate_is_unknown_not_removed(assured):
    from pathlib import Path

    clients, db, body, auth, job = host.completed(assured)
    first = take(clients, request_for(clients, "host", job))
    Path(body["manifest"]["inputs"][0]["path"]).unlink()  # only the disposable synthetic fixture
    second = second_host(clients, body, auth)
    latest = take(clients, request_for(clients, "host", second))
    event = drift(clients, first, latest)
    report = event["payload"]["report"]
    assert len(report["changes"]) == 1
    assert report["changes"][0]["state"] == "UNRESOLVED_COLLECTION_GAP"
    assert not report["changes"][0]["asset_absence_proven"]
    assert verify_audit_chain(db)["status"] == "OK"

    import json
    import os

    output = os.getenv("CRYPTOSCAN_COLLECTION_VIEWS_WITNESS_DIR")
    if output:
        folder = Path(output)
        folder.mkdir(parents=True, exist_ok=True)
        original = clients["reader_a"].get(P + f"/jobs/{job['subject_id']}/evidence")
        candidate = clients["reader_a"].get(P + f"/jobs/{second['subject_id']}/evidence")
        assert original.status_code == candidate.status_code == 200
        for name, value in {
            "baseline-snapshot": first,
            "candidate-snapshot": latest,
            "metadata-drift": event,
            "baseline-source": original.json(),
            "candidate-source": candidate.json(),
        }.items():
            (folder / (name + ".json")).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


@pytest.mark.parametrize("who", ["bank_b", "platform_admin"])
def test_other_estates_cannot_read_or_reference_snapshots_or_drift(assured, who):
    clients, _, first, latest = pair(assured)
    event = drift(clients, first, latest)
    for suffix in ["/snapshots/" + first["subject_id"], "/metadata-drift/" + event["subject_id"]]:
        assert clients[who].get(P + suffix).status_code == 404
    assert clients[who].get(P + "/snapshots").json()["snapshots"] == []
    assert (
        clients[who]
        .post(
            P + "/metadata-drift",
            json={"baseline_snapshot_id": first["subject_id"], "candidate_snapshot_id": latest["subject_id"]},
        )
        .status_code
        == 404
    )


@pytest.mark.parametrize("role", ["readonly", "auditor"])
def test_readers_can_inspect_but_cannot_materialize(assured, role):
    clients, db, _, _, job = host.completed(assured)
    body = request_for(clients, "host", job)
    row = take(clients, body)
    UserRepository(db).set_roles("reader_a", [role])
    db.commit()
    reader = clients["reader_a"]
    assert reader.get(P + "/snapshots/" + row["subject_id"]).status_code == 200
    assert reader.post(P + "/snapshots", json=body).status_code == 403
    assert (
        reader.post(
            P + "/metadata-drift",
            json={
                "baseline_snapshot_id": row["subject_id"],
                "candidate_snapshot_id": "22222222-2222-2222-2222-222222222222",
            },
        ).status_code
        == 403
    )


def test_wrong_expected_source_and_nonterminal_job_refused(assured):
    clients, db, target, _, job = oci.prepare(assured)
    value = {"family": "oci", "job_id": job["subject_id"], "expected_source_sha256": "0" * 64}
    assert clients["bank_a"].post(P + "/snapshots", json=value).status_code == 409
    assert db.query(AssuranceRevision).filter_by(kind="collection_snapshot").count() == 0
    assert oci.submit(clients, target, job).status_code == 201
    assert clients["bank_a"].post(P + "/snapshots", json=value).status_code == 409


def test_client_cannot_supply_or_promote_observations(assured):
    clients, db, _, _, job = host.completed(assured)
    value = request_for(clients, "host", job)
    value["observations"] = []
    assert clients["bank_a"].post(P + "/snapshots", json=value).status_code == 422
    assert db.query(AssuranceRevision).filter_by(kind="collection_snapshot").count() == 0


def test_reversed_drift_refused_without_persisting_report(assured):
    clients, db, first, latest = pair(assured)
    response = clients["bank_a"].post(
        P + "/metadata-drift",
        json={"baseline_snapshot_id": latest["subject_id"], "candidate_snapshot_id": first["subject_id"]},
    )
    assert response.status_code == 409
    assert db.query(AssuranceRevision).filter_by(kind="collection_metadata_drift").count() == 0


def test_historical_snapshot_and_source_read_survive_authorization_revocation(assured):
    clients, _, _, auth, job = oci.complete(assured)
    body = request_for(clients, "oci", job)
    assert admin(clients).post(oci.P + f"/targets/{auth['subject_id']}/revoke", json=oci.decision(2)).status_code == 200
    row = take(clients, body)
    assert clients["reader_a"].get(P + "/snapshots/" + row["subject_id"]).status_code == 200


def reseal(db, row, value):
    envelope = {
        "scope": row.scope_key,
        "kind": row.kind,
        "subject_id": row.subject_id,
        "revision": row.revision,
        "payload": value,
        "created_by": row.created_by,
        "previous_sha256": row.previous_sha256,
    }
    db.query(AssuranceRevision).filter_by(id=row.id).update(
        {"payload": value, "payload_sha256": store.digest(envelope)}, synchronize_session=False
    )
    db.commit()
    db.expire_all()


@pytest.mark.parametrize("change", ["graph", "projection", "snapshot", "source", "drift"])
def test_resealed_tampering_is_recomputed_against_original_closure(assured, change):
    clients, db, first, latest = pair(assured)
    event = drift(clients, first, latest)
    kind, identifier = (
        ("collection_metadata_drift", event["subject_id"])
        if change == "drift"
        else ("collection_snapshot", first["subject_id"])
    )
    if change == "source":
        kind, identifier = "collection_job", first["payload"]["snapshot"]["job_id"]
    row = (
        db.query(AssuranceRevision)
        .filter_by(kind=kind, subject_id=identifier)
        .order_by(AssuranceRevision.revision.desc())
        .first()
    )
    value = deepcopy(row.payload)
    if change == "graph":
        value["metadata_graph"]["edges"][0]["relationship"] = "USES_HSM"
    elif change == "projection":
        value["domains"]["HBOM"]["complete"] = True
    elif change == "snapshot":
        value["snapshot"]["observations"][0]["local_basis"] = "DECLARED"
    elif change == "source":
        value["envelope_sha256"] = "0" * 64
    else:
        value["report"]["whole_asset_coverage_verified"] = True
    reseal(db, row, value)
    path = P + ("/metadata-drift/" + event["subject_id"] if change == "drift" else "/snapshots/" + first["subject_id"])
    assert clients["reader_a"].get(path).status_code == 409
    assert clients["reader_a"].get(P + "/metadata-drift/" + event["subject_id"]).status_code == 409


@pytest.mark.parametrize("kind", ["snapshot", "metadata-drift"])
def test_materialization_and_audit_rollback_together(assured, monkeypatch, kind):
    if kind == "snapshot":
        clients, db, _, _, job = host.completed(assured)
        body = request_for(clients, "host", job)
        path, record_kind = "/snapshots", "collection_snapshot"
    else:
        clients, db, first, latest = pair(assured)
        body = {"baseline_snapshot_id": first["subject_id"], "candidate_snapshot_id": latest["subject_id"]}
        path, record_kind = "/metadata-drift", "collection_metadata_drift"
    before = db.query(AuditLog).count()
    original = UserRepository.audit

    def fail(self, username, action, **kwargs):
        if action == "collection." + kind + ".create":
            raise RuntimeError("synthetic atomic audit refusal")
        return original(self, username, action, **kwargs)

    monkeypatch.setattr(UserRepository, "audit", fail)
    with pytest.raises(RuntimeError, match="synthetic atomic audit"):
        clients["bank_a"].post(P + path, json=body)
    assert db.query(AssuranceRevision).filter_by(kind=record_kind).count() == 0
    assert db.query(AuditLog).count() == before


def test_materialization_remains_blocked_when_controlled_execution_is_required(controlled):
    configure(controlled)
    clients = controlled["clients"]
    body = {"family": "host", "job_id": "11111111-1111-1111-1111-111111111111", "expected_source_sha256": "a" * 64}
    assert clients["bank_a"].post(P + "/snapshots", json=body).status_code == 409
    assert clients["reader_a"].get(P + "/snapshots").status_code == 409


def second_oci(assured, clients, auth, *, inputs=None, layers=None):
    from services.inventory.tests.test_oci_evidence import fixture

    target, _ = fixture(assured[2], inputs=inputs, layers=layers)
    target = target.model_copy(update={"system_id": "system-a", "environment": "prod"})
    tid = auth["subject_id"]
    updated = admin(clients).put(
        oci.P + f"/targets/{tid}",
        json={"expected_revision": auth["revision"], "target": target.model_dump(mode="json")},
    )
    assert updated.status_code == 200, updated.text
    approval = admin(clients).post(oci.P + f"/targets/{tid}/authorize", json=oci.decision(updated.json()["revision"]))
    assert approval.status_code == 200, approval.text
    job = clients["bank_a"].post(
        oci.P + "/jobs", json={"target_id": tid, "expected_target_revision": approval.json()["revision"]}
    )
    assert job.status_code == 201, job.text
    jid = job.json()["subject_id"]
    handoff = clients["bank_a"].post(oci.P + f"/jobs/{jid}/handoff", json={"expected_revision": 1})
    assert handoff.status_code == 200, handoff.text
    captured = oci.submit(clients, target, handoff.json())
    assert captured.status_code == 201, captured.text
    return captured.json()


@pytest.mark.parametrize("case", ["version", "gap", "scope"])
def test_successive_oci_images_retain_slots_but_distinguish_changes_gaps_and_scope(assured, case):
    from services.inventory.tests.test_oci_evidence import DPKG, OS, tar
    from shared_models.oci_collection import ImageInput

    clients, db, _, auth, job = oci.complete(assured)
    first = take(clients, request_for(clients, "oci", job))
    if case == "scope":
        second = second_oci(
            assured, clients, auth, inputs=[ImageInput(input_id="os", kind="LINUX_OS_RELEASE", path="etc/os-release")]
        )
    elif case == "gap":
        second = second_oci(assured, clients, auth, layers=[tar([("etc/os-release", OS, "file")])])
    else:
        second = second_oci(
            assured,
            clients,
            auth,
            layers=[
                tar(
                    [
                        ("etc/os-release", OS, "file"),
                        ("var/lib/dpkg/status", DPKG.replace(b"3.0.17", b"3.0.18"), "file"),
                        ("usr/lib/libcrypto.so.3", b"\x7fELFowned-fixture-not-real-library", "file"),
                    ]
                )
            ],
        )
    latest = take(clients, request_for(clients, "oci", second))
    report = drift(clients, first, latest)["payload"]["report"]
    expected = {
        "version": "CHANGED_METADATA_RECORD",
        "gap": "UNRESOLVED_COLLECTION_GAP",
        "scope": "OUT_OF_COMPARISON_SCOPE",
    }[case]
    assert {e["state"] for e in report["changes"]} == {expected}
    if case == "version":
        assert len(report["changes"]) == 1
        slots = [{o["identity_slot"] for o in r["payload"]["snapshot"]["observations"]} for r in (first, latest)]
        assert slots[0] == slots[1]
    assert all(not e["asset_absence_proven"] for e in report["changes"])
    assert verify_audit_chain(db)["status"] == "OK"


def test_cross_family_drift_refused_even_for_same_system(assured):
    clients, db, _, _, host_job = host.completed(assured)
    first = take(clients, request_for(clients, "host", host_job))
    clients, _, _, _, oci_job = oci.complete(assured)
    latest = take(clients, request_for(clients, "oci", oci_job))
    response = clients["bank_a"].post(
        P + "/metadata-drift",
        json={"baseline_snapshot_id": first["subject_id"], "candidate_snapshot_id": latest["subject_id"]},
    )
    assert response.status_code == 409
    assert db.query(AssuranceRevision).filter_by(kind="collection_metadata_drift").count() == 0
