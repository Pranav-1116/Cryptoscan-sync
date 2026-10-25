"""One scoped Linux intake -> software evidence, never another collection."""

import pytest
from test_assurance_workflows import assured as assured, admin
from test_software_supply_chain_api import banks as banks
from test_collection_foundation import target_body, decision, imported, P
from db.models.scan import Scan
from db.models.evidence_record import EvidenceRecord
from shared_models.collection import TargetSpec, CollectionResult
from shared_models.linux_software import LinuxSoftwareInventory, project_linux_software, PackageGroup
from shared_models.host_collection import digest
from pydantic import ValidationError


def collected(assured, *, duplicate=False, extra=None):
    clients, db, body = target_body(assured)
    _, _, tmp = assured
    path = tmp / "status"
    text = "Package: openssl\nStatus: hold ok installed\nVersion: 3.0.13\n\nPackage: helper\nStatus: install ok installed\n"
    if duplicate:
        text += "\nPackage: openssl\nStatus: install ok installed\nVersion: 9\n"
    path.write_text(text)
    body["manifest"]["inputs"].append({"input_id": "packages", "kind": "DPKG_STATUS", "path": str(path)})
    if extra:
        if extra == "LINUX_PROCESS_MAPS":
            source_path = "linux-proc://self/maps"
        else:
            source = tmp / "extra-packages"
            if extra == "APK_INSTALLED":
                source.write_text("P:openssl\nV:3.3.2-r1\n")
            else:
                from services.inventory.tests.test_rpm_metadata import database, header

                source.write_bytes(database([header()]))
            source_path = str(source)
        body["manifest"]["inputs"].append({"input_id": "extra", "kind": extra, "path": source_path})
    target = clients["bank_a"].post(P + "/targets", json=body)
    assert target.status_code == 201, target.text
    tid = target.json()["subject_id"]
    auth = admin(clients).post(P + f"/targets/{tid}/authorize", json=decision(1))
    assert auth.status_code == 200, auth.text
    job = clients["bank_a"].post(P + "/jobs", json={"target_id": tid, "expected_target_revision": 2})
    assert job.status_code == 201, job.text
    jid = job.json()["subject_id"]
    assert clients["bank_a"].post(P + f"/jobs/{jid}/handoff", json={"expected_revision": 1}).status_code == 200
    response = imported(clients, body, auth.json())
    assert response.status_code == 201, response.text
    response = clients["bank_a"].post(P + f"/jobs/{jid}/complete", json={"expected_revision": 2})
    assert response.status_code == 200, response.text
    return clients, db, body, jid, tid


def test_real_intake_software_keeps_packages_binary_and_unknowns_separate(assured):
    clients, db, _, jid, tid = collected(assured)
    before = (db.query(Scan).count(), db.query(EvidenceRecord).count())
    path = P + f"/jobs/{jid}/software/linux"
    response = clients["reader_a"].get(path)
    assert response.status_code == 200, response.text
    inventory = LinuxSoftwareInventory.model_validate(response.json())
    packages = {p.name: p for p in inventory.packages}
    assert (
        set(packages) == {"openssl", "helper"}
        and packages["openssl"].version == "3.0.13"
        and packages["helper"].version is None
    )
    assert all(
        p.package_manager == "dpkg"
        and p.runtime_use == p.cryptographic_use == p.licenses == p.dependencies == "UNKNOWN"
        and p.purl is None
        and p.package_artifact_sha256 is None
        for p in inventory.packages
    )
    record = packages["openssl"].records[0]
    assert (
        record.evidence_id
        and record.fact_sha256
        and record.source.input_content_sha256
        and record.fact.algorithm == "UNKNOWN"
    )
    assert inventory.provenance == "IMPORTED" and record.fact.local_basis == "OBSERVED"
    assert len(inventory.binary_presence) == 1 and not inventory.mapped_library_paths
    assert inventory.coverage.bom_observation_counts["SBOM"] == 3
    assert (
        not inventory.standard_document
        and not inventory.installed_package_inventory_complete
        and not inventory.host_identity_attested
    )
    assert clients["reader_a"].get(path).json() == response.json()
    assert before == (db.query(Scan).count(), db.query(EvidenceRecord).count()) and before[0] == 1
    assert clients["bank_b"].get(path).status_code == 404
    assert clients["platform_admin"].get(path).status_code == 404
    assert admin(clients).get(path).status_code == 200
    assert admin(clients).post(P + f"/targets/{tid}/revoke", json=decision(2)).status_code == 200
    assert clients["reader_a"].get(path).json() == response.json()
    db.query(EvidenceRecord).first().finding_data = {"corrupt": True}
    db.commit()
    assert clients["reader_a"].get(path).status_code == 409


def test_ambiguous_package_input_is_explicit_gap_not_no_packages(assured):
    clients, _, _, jid, _ = collected(assured, duplicate=True)
    response = clients["reader_a"].get(P + f"/jobs/{jid}/software/linux")
    assert response.status_code == 200, response.text
    value = response.json()
    assert value["packages"] == [] and value["package_inputs"][0]["status"] == "INVALID"
    assert not value["coverage"]["asset_absence_proven"] and len(value["binary_presence"]) == 1


@pytest.mark.parametrize(
    "change", ["wrong-platform", "wrong-source", "changed-fact", "promoted-domain", "changed-envelope"]
)
def test_software_projection_requires_bound_linux_evidence(assured, change):
    clients, _, body, jid, _ = collected(assured)
    raw = clients["reader_a"].get(P + f"/jobs/{jid}/evidence").json()
    value = CollectionResult.model_validate({k: v for k, v in raw.items() if k != "envelope_sha256"})
    target = TargetSpec.model_validate(body)
    row = next(r for r in value.observations if r.fact.kind == "SOFTWARE")
    if change == "wrong-platform":
        target = target.model_copy(update={"manifest": target.manifest.model_copy(update={"platform": "windows"})})
    elif change == "wrong-source":
        row = row.model_copy(update={"source": row.source.model_copy(update={"kind": "WINDOWS_UNINSTALL"})})
    elif change == "changed-fact":
        row = row.model_copy(update={"fact_sha256": "0" * 64})
    elif change == "promoted-domain":
        row = row.model_copy(update={"contributes_to": ["CBOM", "TechBOM"]})
    value = value.model_copy(
        update={"observations": [row if r.observation_id == row.observation_id else r for r in value.observations]}
    )
    with pytest.raises(ValueError):
        project_linux_software(value, target, "0" * 64 if change == "changed-envelope" else digest(value))


def test_duplicate_versions_preserved_without_selecting_winner(assured):
    clients, _, _, jid, _ = collected(assured)
    value = clients["reader_a"].get(P + f"/jobs/{jid}/software/linux").json()
    group = next(p for p in value["packages"] if p["name"] == "openssl")
    second = group["records"][0].copy()
    second["observation_id"] = "synthetic-second"
    second["fact_ordinal"] = 1
    second["fact"] = {**second["fact"], "software_version": "9"}
    second["fact_sha256"] = digest(second["fact"])
    group.update(records=[*group["records"], second], version=None, identity_status="MULTIPLE_RECORDS_UNRESOLVED")
    parsed = PackageGroup.model_validate(group)
    assert parsed.version is None and [r.fact.software_version for r in parsed.records] == ["3.0.13", "9"]
    group["version"] = "9"
    with pytest.raises(ValidationError):
        PackageGroup.model_validate(group)


@pytest.mark.parametrize(
    "flag",
    [
        "standard_document",
        "dependencies_complete",
        "installed_package_inventory_complete",
        "host_identity_attested",
        "production_execution_qualified",
    ],
)
def test_inventory_schema_refuses_promoted_claims(assured, flag):
    clients, _, _, jid, _ = collected(assured)
    value = clients["reader_a"].get(P + f"/jobs/{jid}/software/linux").json()
    value[flag] = True
    with pytest.raises(ValidationError):
        LinuxSoftwareInventory.model_validate(value)


def test_no_package_scope_has_no_package_denominator(assured):
    from test_collection_foundation import completed

    clients, _, _, _, job = completed(assured)
    response = clients["reader_a"].get(P + f"/jobs/{job['subject_id']}/software/linux")
    assert response.status_code == 200, response.text
    assert response.json()["package_inputs"] == [] and response.json()["packages"] == []
    assert response.json()["coverage"]["surfaces"]["software"]["approved_inputs"] == 1  # Only binary presence.
    assert len(response.json()["binary_presence"]) == 1


def test_uncommitted_job_cannot_manufacture_software_inventory(assured):
    from test_collection_foundation import prepared

    clients, _, _, _, job = prepared(assured)
    assert clients["reader_a"].get(P + f"/jobs/{job['subject_id']}/software/linux").status_code == 409


@pytest.mark.parametrize(
    "kind,manager,version", [("APK_INSTALLED", "apk", "3.3.2-r1"), ("RPM_SQLITE", "rpm", "1:3.2.2-5.el9")]
)
def test_other_linux_package_namespaces_are_not_merged(assured, kind, manager, version):
    clients, _, _, jid, _ = collected(assured, extra=kind)
    response = clients["reader_a"].get(P + f"/jobs/{jid}/software/linux")
    assert response.status_code == 200, response.text
    groups = [p for p in response.json()["packages"] if p["name"] == "openssl"]
    assert len(groups) == 2 and len({g["identity_slot"] for g in groups}) == 2
    assert {(g["package_manager"], g["version"]) for g in groups} == {("dpkg", "3.0.13"), (manager, version)}
    assert len(response.json()["package_inputs"]) == 2


def test_approved_self_maps_are_separate_not_package_or_crypto_invocation(assured):
    clients, _, _, jid, _ = collected(assured, extra="LINUX_PROCESS_MAPS")
    response = clients["reader_a"].get(P + f"/jobs/{jid}/software/linux")
    assert response.status_code == 200, response.text
    value = response.json()
    assert len(value["packages"]) == 2 and value["mapped_library_paths"]
    assert all(
        r["fact"]["runtime_use"] == r["fact"]["operation_use"] == "UNKNOWN" for r in value["mapped_library_paths"]
    )
    assert all(
        r["fact"]["library_path"].startswith("/") and r["source"]["kind"] == "LINUX_PROCESS_MAPS"
        for r in value["mapped_library_paths"]
    )
    assert value["coverage"]["bom_observation_counts"]["SBOM"] == 3 + len(value["mapped_library_paths"])
