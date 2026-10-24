"""Original bank questions O1/O4/O5/G2: real schema and negative exports."""
import copy
import json

import pytest
from cbom.generator import CbomGenerator
from cbom.inventory import records_from_bom, validate_document
from cbom.cyclonedx16 import validate_cyclonedx16


def document():
    return CbomGenerator().from_records([
        {"id": "rsa", "algorithm": "RSA", "key_size": 2048, "mode": "CBC", "padding": "OAEP",
         "file_path": "payments/key.py", "line_number": 7, "application": "payments",
         "owner": "payments-security", "data_classification": "confidential", "retention_years": 12,
         "criticality": "critical", "code_snippet": "DO-NOT-EXPORT-SECRET", "private_key": "DO-NOT-EXPORT-SECRET"},
        {"id": "kem", "algorithm": "ML-KEM-768", "purpose": "KEY_EXCHANGE"},
        {"id": "opaque", "algorithm": "VendorOpaqueCrypto"},
    ], name="synthetic-bank", spec_version="1.6", scan_id="fixture")


def test_full_official_schema_not_subset_and_no_input_mutation():
    bom = document()
    from cbom.cyclonedx16 import validate_cyclonedx16
    before = copy.deepcopy(bom)
    report = validate_cyclonedx16(bom)
    assert report["ok"], report
    assert report["validation_basis"] == "CYCLONEDX_1_6_OFFICIAL_SCHEMA_AND_REFERENCES"
    assert bom == before
    assert bom["specVersion"] == "1.6"
    assert bom["compositions"][0]["aggregate"] == "incomplete"
    assert "dependencies" not in bom  # inventory membership is not runtime dependency proof
    assert "DO-NOT-EXPORT-SECRET" not in json.dumps(bom)


def test_native_crypto_fields_and_business_context_survive_round_trip():
    bom = document()
    crypto = bom["components"][0]["cryptoProperties"]
    assert crypto["algorithmProperties"]["mode"] == "cbc"
    assert crypto["algorithmProperties"]["padding"] == "oaep"
    assert "algorithm" not in crypto["algorithmProperties"]
    assert "quantumVulnerable" not in crypto
    props = {p["name"]: p["value"] for p in bom["components"][0]["properties"]}
    assert props["cryptoscan:owner"] == "payments-security"
    assert props["cryptoscan:application"] == "payments"
    assert props["cryptoscan:data_classification"] == "confidential"
    assert props["cryptoscan:deployment_readiness"] == "NOT_ESTABLISHED"
    record = records_from_bom(bom)[0]
    assert (record["algorithm"], record["key_size"], record["mode"]) == ("RSA", 2048, "cbc")
    assert record["owner"] == "payments-security"
    assert record["retention_years"] == 12


@pytest.mark.parametrize("mutation", [
    lambda b: b.update(extraBankField=True),
    lambda b: b.update(version=True),
    lambda b: b["metadata"].update(timestamp="not-a-timestamp"),
    lambda b: b["components"][0]["cryptoProperties"].update(quantumVulnerable=False),
    lambda b: b["components"][0]["cryptoProperties"]["algorithmProperties"].update(mode="GCM"),
    lambda b: b["components"][0]["cryptoProperties"]["algorithmProperties"].update(primitive="aead"),
    lambda b: b["components"][0].update(evidence={"file": "custom-not-standard"}),
    lambda b: b["compositions"][0].update(aggregate="INCOMPLETE"),
    lambda b: b["components"].append(copy.deepcopy(b["components"][0])),
    lambda b: b.update(dependencies=[{"ref": "rsa", "dependsOn": ["foreign-ref"]}]),
    lambda b: b["compositions"][0].update(assemblies=["unknown-ref"]),
])
def test_real_schema_and_referential_errors_are_rejected_at_import(mutation):
    bom = document()
    mutation(bom)
    report = validate_document(bom)
    assert report["ok"] is False
    assert report["errors"]


@pytest.mark.parametrize("value", [None, [], "secret", 3, {"specVersion": "1.6"}])
def test_malformed_documents_do_not_raise(value):
    from cbom.cyclonedx16 import validate_cyclonedx16
    assert validate_cyclonedx16(value)["ok"] is False


def test_missing_schema_fails_closed(tmp_path, monkeypatch):
    from cbom import cyclonedx16
    bom = document()
    monkeypatch.setattr(cyclonedx16, "SCHEMA_DIR", tmp_path)
    assert cyclonedx16.validate_cyclonedx16(bom)["ok"] is False


def test_schema_tampering_is_not_accepted(tmp_path, monkeypatch):
    from cbom import cyclonedx16
    for source in cyclonedx16.SCHEMA_DIR.iterdir():
        if source.is_file():
            (tmp_path / source.name).write_bytes(source.read_bytes())
    (tmp_path / "bom-1.6.schema.json").write_text('{"type":"object"}')
    bom = document()
    monkeypatch.setattr(cyclonedx16, "SCHEMA_DIR", tmp_path)
    assert cyclonedx16.validate_cyclonedx16(bom)["ok"] is False


def test_schema_cannot_fetch_remote_references(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: pytest.fail("validator attempted network"))
    assert validate_document(document())["ok"]


def test_xml_cannot_silently_relabel_native16_as15():
    with pytest.raises(ValueError, match="1.6"):
        CbomGenerator().to_xml(document())


def test_unknown_and_hybrid_are_not_invented_ready_or_certified():
    bom = CbomGenerator().from_records([
        {"id": "a", "algorithm": "X25519MLKEM768"},
        {"id": "b", "algorithm": "not-real-ML-KEM"},
    ], spec_version="1.6")
    assert validate_document(bom)["ok"]
    for c in bom["components"]:
        assert "certificationLevel" not in c["cryptoProperties"]["algorithmProperties"]
        props = {p["name"]: p["value"] for p in c["properties"]}
        assert props["cryptoscan:deployment_readiness"] == "NOT_ESTABLISHED"
    assert bom["components"][0]["cryptoProperties"]["algorithmProperties"]["primitive"] == "combiner"
    assert bom["components"][1]["cryptoProperties"]["algorithmProperties"]["primitive"] == "unknown"


def test_legacy_default_remains_explicitly_compatible():
    assert CbomGenerator().from_records([])["specVersion"] == "1.5"


def test_standard_dependencies_are_retained_but_never_certify_replacement():
    bom = CbomGenerator().from_records([
        {"id": "a", "algorithm": "AES"}, {"id": "b", "algorithm": "RSA"},
    ], dependencies=[{"ref": "a", "dependsOn": ["b"]}], spec_version="1.6")
    assert validate_document(bom)["ok"]
    assert bom["dependencies"] == [{"ref": "a", "dependsOn": ["b"]}]
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert props["cryptoscan:dependency_basis"] == "SOURCE_RELATIONSHIPS_NOT_RUNTIME_OR_REPLACEMENT_PROOF"


def test_shared_asset_has_unique_ref_without_losing_business_context():
    bom = CbomGenerator().from_records([
        {"id": "shared", "algorithm": "AES", "system_id": "a", "system_name": "payments", "owner": "team-a"},
        {"id": "shared", "algorithm": "AES", "system_id": "b", "system_name": "ledger", "owner": "team-b"},
    ], spec_version="1.6")
    assert len(bom["components"]) == 1
    contexts = [json.loads(p["value"]) for p in bom["components"][0]["properties"] if p["name"] == "cryptoscan:business_context"]
    assert {c["system_id"] for c in contexts} == {"a", "b"}
    assert {c["owner"] for c in contexts} == {"team-a", "team-b"}
    assert validate_document(bom)["ok"]


def test_conflicting_identity_is_not_silently_merged():
    with pytest.raises(ValueError):
        CbomGenerator().from_records([
            {"id": "same", "algorithm": "RSA"}, {"id": "same", "algorithm": "AES"},
        ], spec_version="1.6")


@pytest.mark.parametrize("name,reported_size,parameter_set", [
    ("ML-KEM-768", 1184, "768"), ("ML-DSA-65", 1952, "65"),
    ("SLH-DSA-SHA2-128s", 32, "SHA2-128s"),
])
def test_pqc_parameter_identifiers_are_not_serialized_public_key_lengths(name, reported_size, parameter_set):
    bom = CbomGenerator().from_records([{"id": "pqc", "algorithm": name, "key_size": reported_size}], spec_version="1.6")
    algorithm = bom["components"][0]["cryptoProperties"]["algorithmProperties"]
    assert algorithm["parameterSetIdentifier"] == parameter_set
    parsed = records_from_bom(bom)[0]
    assert parsed["key_size"] == reported_size
    assert parsed["parameter_set_identifier"] == parameter_set
    assert parsed["key_size_basis"] == "REPORTED_UNIT_NOT_ESTABLISHED"


def test_retained_banking_example_is_native_schema_valid_and_explicitly_synthetic():
    from pathlib import Path
    root = Path(__file__).resolve().parents[3]
    examples = root / "docs/examples/bank-pqc-discovery"
    bom = json.loads((examples / "cbom.cyclonedx16.json").read_text())
    report = json.loads((examples / "report.json").read_text())
    assert validate_document(bom)["ok"]
    assert len(bom["components"]) == report["exported_crypto_components"] == report["supplied_records"] == 8
    assert report["bank_approved"] is False and report["scanner_executed"] is False
    assert report["migration_plan"]["inventory"]["pqc_ready_sites"] == 0


def test_standard_jsf_hmac_is_schema_valid_and_not_a_uri_algorithm():
    from cbom.generator import CbomGenerator
    generator = CbomGenerator()
    bom = generator.from_records([{"id":"one", "algorithm":"AES"}], spec_version="1.6")
    signed = generator.sign_standard(bom, "test-only-secret", alg="HS256")
    assert validate_cyclonedx16(signed)["ok"]
    assert generator.verify_standard(signed, "test-only-secret")[0]
    signed["signature"]["algorithm"] = "HS256-not-a-URI"
    assert not validate_cyclonedx16(signed)["ok"]
