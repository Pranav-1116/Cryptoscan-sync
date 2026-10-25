"""Actual authorized intake/read boundary; synthetic package/certificate inputs."""

from copy import deepcopy
import pytest
from test_assurance_workflows import assured as assured, admin
from test_software_supply_chain_api import banks as banks
from test_linux_software_inventory import collected
from test_collection_foundation import P, decision, prepared
from db.models.scan import Scan
from db.models.evidence_record import EvidenceRecord
from db.models.user import AuditLog
from cbom.cyclonedx16 import validate_cyclonedx16
from cbom.linux_sbom import build_linux_sbom, LinuxSBOMValidationError
from shared_models.linux_software import LinuxSoftwareInventory
from shared_models.linux_relationships import LinuxRelationships, project_linux_relationships
from shared_models.collection import CollectionResult, TargetSpec
from shared_models.host_collection import digest


def urls(jid):
    return [P + f"/jobs/{jid}/relationships/linux", P + f"/jobs/{jid}/software/linux/cyclonedx-1.6"]


def props(items):
    return {p["name"]: p["value"] for p in items}


def test_linux_graph_and_official_sbom_reuse_originals_without_writes(assured):
    clients, db, _, jid, tid = collected(assured)
    before = tuple(db.query(m).count() for m in (Scan, EvidenceRecord, AuditLog))
    graph_response = clients["reader_a"].get(urls(jid)[0])
    assert graph_response.status_code == 200, graph_response.text
    graph = LinuxRelationships.model_validate(graph_response.json())
    assert len(graph.nodes) == 5 and not graph.edges
    assert len(graph.unsupported_relationships) == 6
    assert all(n.evidence_id and n.fact_sha256 and n.provenance == "IMPORTED" for n in graph.nodes)
    assert {n.fact.local_basis for n in graph.nodes} == {"OBSERVED", "DECLARED"}
    response = clients["reader_a"].get(urls(jid)[1])
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/vnd.cyclonedx+json")
    assert "no-store" in response.headers["cache-control"] and "attachment" in response.headers["content-disposition"]
    bom = response.json()
    assert validate_cyclonedx16(bom)["ok"]
    assert len(bom["components"]) == 3 and "dependencies" not in bom
    assert bom["compositions"] == [{"aggregate": "incomplete"}]
    by_name = {c["name"]: c for c in bom["components"]}
    assert by_name["openssl"]["version"] == "3.0.13" and "version" not in by_name["helper"]
    assert by_name["openssl"]["type"] == "application"
    assert (
        props(by_name["openssl"]["properties"])["cryptoscan:component_type_basis"]
        == "CYCLONEDX_SPEC_DEFAULT_NOT_OBSERVED_CLASSIFICATION"
    )
    assert all("hashes" not in c and "licenses" not in c and "purl" not in c for c in bom["components"])
    metadata = props(bom["metadata"]["properties"])
    assert metadata["cryptoscan:envelope_sha256"] == graph.coverage.envelope_sha256
    assert metadata["cryptoscan:inventory_completeness"] == "NOT_PROVEN"
    for path in urls(jid):
        saved = clients["reader_a"].get(path).json()
        assert clients["reader_a"].get(path).json() == saved
        assert clients["bank_b"].get(path).status_code == 404
        assert clients["platform_admin"].get(path).status_code == 404
        assert admin(clients).get(path).status_code == 200
    assert tuple(db.query(m).count() for m in (Scan, EvidenceRecord, AuditLog)) == before
    assert admin(clients).post(P + f"/targets/{tid}/revoke", json=decision(2)).status_code == 200
    assert clients["reader_a"].get(urls(jid)[0]).json() == graph_response.json()
    assert clients["reader_a"].get(urls(jid)[1]).json() == bom
    db.query(EvidenceRecord).first().finding_data = {"tampered": True}
    db.commit()
    assert all(clients["reader_a"].get(path).status_code == 409 for path in urls(jid))


def test_failed_package_input_is_visible_even_in_valid_standard_export(assured):
    clients, _, _, jid, _ = collected(assured, duplicate=True)
    response = clients["reader_a"].get(urls(jid)[1])
    assert response.status_code == 200, response.text
    bom = response.json()
    assert validate_cyclonedx16(bom)["ok"] and len(bom["components"]) == 1
    metadata = props(bom["metadata"]["properties"])
    assert metadata["cryptoscan:package_inputs_failed"] == "1"
    assert metadata["cryptoscan:package_input:packages"].startswith("INVALID:")
    graph = clients["reader_a"].get(urls(jid)[0]).json()
    assert (
        graph["coverage"]["surfaces"]["software"]["failed_inputs"] == 1
        and not graph["coverage"]["asset_absence_proven"]
    )


def test_uncompleted_job_cannot_export_or_create_relationships(assured):
    clients, _, _, _, job = prepared(assured)
    assert all(clients["reader_a"].get(path).status_code == 409 for path in urls(job["subject_id"]))


def test_mapped_paths_stay_out_of_artifact_components_and_missing_process_is_gap(assured):
    clients, _, _, jid, _ = collected(assured, extra="LINUX_PROCESS_MAPS")
    graph = clients["reader_a"].get(urls(jid)[0]).json()
    assert not graph["edges"] and any(u["reason"] == "NO_MATCHING_OBSERVATION" for u in graph["unresolved"])
    bom = clients["reader_a"].get(urls(jid)[1]).json()
    assert (
        len(bom["components"]) == 3
        and int(props(bom["metadata"]["properties"])["cryptoscan:mapped_path_records_not_components"]) > 0
    )


@pytest.mark.parametrize("schema", ["bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"])
def test_export_fails_closed_if_pinned_schema_missing_or_modified(assured, monkeypatch, schema, tmp_path):
    import cbom.cyclonedx16 as validation

    clients, _, _, jid, _ = collected(assured)
    copies = tmp_path / "schemas"
    copies.mkdir()
    for path in validation.SCHEMA_DIR.iterdir():
        if path.is_file():
            (copies / path.name).write_bytes(path.read_bytes())
    (copies / schema).write_bytes(b"{}")
    monkeypatch.setattr(validation, "SCHEMA_DIR", copies)
    response = clients["reader_a"].get(urls(jid)[1])
    assert response.status_code == 503 and "components" not in response.json()


def test_schema_validity_is_not_semantic_completeness_and_ambiguity_is_omitted(assured):
    clients, _, _, jid, _ = collected(assured)
    raw = clients["reader_a"].get(P + f"/jobs/{jid}/software/linux").json()
    group = next(p for p in raw["packages"] if p["name"] == "openssl")
    second = deepcopy(group["records"][0])
    second["observation_id"] = "synthetic-other"
    second["fact_ordinal"] = 2
    second["fact"]["software_version"] = "9"
    second["fact_sha256"] = digest(second["fact"])
    group.update(records=group["records"] + [second], version=None, identity_status="MULTIPLE_RECORDS_UNRESOLVED")
    raw["coverage"]["bom_observation_counts"]["SBOM"] += 1
    raw["coverage"]["bom_observation_counts"]["TechBOM"] += 1
    surface = raw["coverage"]["surfaces"]["software"]
    surface["fact_count"] += 1
    item = next(i for i in surface["inputs"] if i["input_id"] == "packages")
    item["fact_count"] += 1
    item["local_basis_counts"]["OBSERVED"] += 1
    raw["package_inputs"] = [deepcopy(item)]
    bom = build_linux_sbom(LinuxSoftwareInventory.model_validate(raw))
    assert validate_cyclonedx16(bom)["ok"] and len(bom["components"]) == 2
    assert not any(c["name"] == "openssl" for c in bom["components"])
    assert props(bom["metadata"]["properties"])["cryptoscan:ambiguous_package_groups_omitted"] == "1"


@pytest.mark.parametrize(
    "change", ["invented-field", "wrong-type", "bad-version", "dangling-dependency", "duplicate-ref"]
)
def test_official_validator_rejects_invalid_standard_document(assured, change):
    clients, _, _, jid, _ = collected(assured)
    bom = clients["reader_a"].get(urls(jid)[1]).json()
    if change == "invented-field":
        bom["components"][0]["cryptoUse"] = "PROVEN"
    elif change == "wrong-type":
        bom["components"][0]["type"] = "package"
    elif change == "bad-version":
        bom["specVersion"] = "9.9"
    elif change == "dangling-dependency":
        bom["dependencies"] = [{"ref": "not-captured", "dependsOn": []}]
    else:
        bom["components"].append(deepcopy(bom["components"][0]))
    assert not validate_cyclonedx16(bom)["ok"]


def test_builder_cannot_return_export_when_final_validation_refuses(assured, monkeypatch):
    clients, _, _, jid, _ = collected(assured)
    value = LinuxSoftwareInventory.model_validate(clients["reader_a"].get(P + f"/jobs/{jid}/software/linux").json())
    monkeypatch.setattr("cbom.linux_sbom.validate_cyclonedx16", lambda _: {"ok": False})
    with pytest.raises(LinuxSBOMValidationError):
        build_linux_sbom(value)


def test_relationship_factory_checks_original_envelope_and_linux_scope(assured):
    clients, _, body, jid, _ = collected(assured)
    raw = clients["reader_a"].get(P + f"/jobs/{jid}/evidence").json()
    value = CollectionResult.model_validate({k: v for k, v in raw.items() if k != "envelope_sha256"})
    target = TargetSpec.model_validate(body)
    with pytest.raises(ValueError):
        project_linux_relationships(value, target, "b" * 64)
    wrong = target.model_copy(update={"manifest": target.manifest.model_copy(update={"platform": "windows"})})
    with pytest.raises(ValueError):
        project_linux_relationships(value, wrong, raw["envelope_sha256"])


def test_admitted_synthetic_runtime_facts_produce_only_supported_joins(assured, monkeypatch):
    # Synthetic interface injection, not execution against real services/hardware.
    import test_linux_software_inventory as intake
    from shared.shared_models.tests.test_linux_relationships import process, library, service
    from hashlib import sha256

    original = intake.target_body

    def scoped(assured):
        clients, db, body = original(assured)
        body["manifest"]["inputs"] += [
            {"input_id": "process", "kind": "LINUX_PROCESS", "path": "linux-proc://self/process"},
            {"input_id": "mapping", "kind": "LINUX_PROCESS_MAPS", "path": "linux-proc://self/maps"},
            {"input_id": "service", "kind": "LINUX_SERVICE", "path": "systemd://payments.service"},
        ]
        return clients, db, body

    def capture(item, limit, charge):
        data = b"synthetic-runtime-interface"
        charge(len(data))
        fact = {"LINUX_PROCESS": process, "LINUX_PROCESS_MAPS": library, "LINUX_SERVICE": service}[item.kind]()
        return data, [fact.model_copy(update={"interface_sha256": sha256(data).hexdigest()})]

    monkeypatch.setattr(intake, "target_body", scoped)
    monkeypatch.setattr("inventory.linux_runtime.collect_live", capture)
    clients, _, _, jid, _ = intake.collected(assured)

    def forbidden(*args):
        raise AssertionError("Projection must not collect again")

    monkeypatch.setattr("inventory.linux_runtime.collect_live", forbidden)
    response = clients["reader_a"].get(urls(jid)[0])
    assert response.status_code == 200, response.text
    value = LinuxRelationships.model_validate(response.json())
    assert {e.relation for e in value.edges} == {"PROCESS_HAS_MAPPED_PATH", "PROCESS_REPORTS_SERVICE_UNIT"}
    assert all(e.runtime_use == "UNKNOWN" for e in value.edges)
    document = clients["reader_a"].get(urls(jid)[1])
    assert document.status_code == 200, document.text
    assert "dependencies" not in document.json()  # Metadata joins never become software dependencies.
