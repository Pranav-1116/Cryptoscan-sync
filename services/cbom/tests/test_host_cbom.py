"""Golden native1.6 metadata contract, not attestation or external-tool signoff."""

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
import pytest
from cbom.generator import CbomGenerator
from cbom.cyclonedx16 import validate_cyclonedx16
from evidence.core.pipeline import EvidencePipeline
from shared_models.host_collection import HostManifest, HostSnapshot, HostEvidenceRef
from shared_models.safe_finding import safe_finding

FIXTURE = Path(__file__).parent / "fixtures/host-cyclonedx16.json"


def golden_input():
    ref = HostEvidenceRef(
        local_basis="OBSERVED",
        snapshot_sha256="a" * 64,
        approval_id="00000000-0000-4000-8000-000000000001",
        system_id="payments",
        host_id="payments-linux-1",
        environment="test",
        input_id="cert",
        fact_ordinal=0,
        fact_kind="CERTIFICATE",
        receipt_status="PARSED",
        receipt_reason="METADATA_ONLY",
        observed_at="2026-10-24T00:00:00+00:00",
        fingerprint_sha256="b" * 64,
        signature_hash="SHA256",
    )
    return {
        "id": "00000000-0000-4000-8000-000000000002",
        "algorithm": "RSA",
        "key_size": 2048,
        "mode": "UNKNOWN",
        "purpose": "PUBLIC_KEY_METADATA",
        "file_path": "/approved/public.pem",
        "line_number": 0,
        "confidence": "LOW",
        "finding_data": {
            "host_evidence": ref.model_dump(mode="json"),
            "source": {"file_path": "/approved/public.pem"},
            "crypto": {"algorithm": "RSA", "key_size": 2048, "mode": "UNKNOWN", "purpose": "PUBLIC_KEY_METADATA"},
        },
    }


def golden_document():
    class Clock:
        @staticmethod
        def now(tz):
            return datetime(2026, 10, 24, tzinfo=timezone.utc)

    with patch("cbom.generator.datetime", Clock):
        return CbomGenerator().from_records(
            [golden_input()],
            name="payments-linux-1",
            spec_version="1.6",
            scan_id="00000000-0000-4000-8000-000000000003",
            metadata_properties=[{"name": "cryptoscan:source_basis", "value": "IMPORTED"}],
        )


def test_official_schema_and_golden_host_property_vocabulary():
    document = golden_document()
    assert validate_cyclonedx16(document)["ok"]
    assert document == json.loads(FIXTURE.read_text())
    assert not document.get("dependencies")
    props = {p["name"]: p["value"] for p in document["components"][0]["properties"]}
    assert props["cryptoscan:host:library"] == props["cryptoscan:host:library_version"] == "UNKNOWN"
    assert props["cryptoscan:host:source_basis"] == "IMPORTED"
    assert props["cryptoscan:host:fingerprint_sha256"] == "b" * 64


@pytest.mark.parametrize("model,name", [(HostManifest, "host-manifest-v1"), (HostSnapshot, "host-snapshot-v1")])
def test_pinned_host_schemas_do_not_drift_silently(model, name):
    import shared_models.host_collection as contract

    path = Path(contract.__file__).parent / "schemas" / (name + ".schema.json")
    assert model.model_json_schema() == json.loads(path.read_text())


def test_receipts_are_not_crypto_assets_for_dict_pipeline_or_orm_inputs():
    data = golden_input()
    ref = data["finding_data"]["host_evidence"]
    finding = {
        "finding_type": "HOST_COLLECTION_RECEIPT",
        "host_evidence": {**ref, "fact_kind": "RECEIPT", "fact_ordinal": -1, "local_basis": "UNKNOWN"},
        "crypto": {"algorithm": "UNKNOWN"},
        "source": {"file_path": "/approved/libssl.so"},
    }
    records, _ = EvidencePipeline().process([finding])
    for inputs in ([finding], records, [{"finding_data": finding}]):
        assert CbomGenerator().from_records(inputs, spec_version="1.6")["components"] == []
    from db.models.evidence_record import EvidenceRecord

    record = EvidenceRecord(finding_data=finding)
    assert CbomGenerator().from_records([record], spec_version="1.6")["components"] == []


def test_host_reference_is_covered_by_evidence_hash_and_raw_fields_are_refused():
    from evidence.hashing.content_hasher import ContentHasher

    data = golden_input()["finding_data"]
    first = ContentHasher.compute_hash(safe_finding(data))
    data["host_evidence"]["snapshot_sha256"] = "c" * 64
    assert first != ContentHasher.compute_hash(safe_finding(data))
    data["host_evidence"]["private_key"] = "forbidden-test-canary"
    with pytest.raises(ValueError):
        safe_finding(data)


def test_mutable_host_enrichment_cannot_override_committed_source():
    data = golden_input()
    data["algorithm"], data["key_size"], data["confidence"] = "ML-KEM-768", 1, "HIGH"
    data["normalized_crypto"] = {"standard_name": "ML-KEM-768", "algorithm_family": "kem", "quantum_vulnerable": False}
    data["compliance_status"] = {"overall": "COMPLIANT"}
    data["library"] = "uncommitted-version"
    component = CbomGenerator().from_records([data], spec_version="1.6")["components"][0]
    assert component["name"] == "RSA-2048"  # variant from the committed source, never the mutable ML-KEM enrichment
    props = {p["name"]: p["value"] for p in component["properties"]}
    assert props["cryptoscan:reported_key_size"] == "2048"
    assert props["cryptoscan:host:pqc_assessment"] == "UNKNOWN"
    assert "uncommitted-version" not in json.dumps(component)
