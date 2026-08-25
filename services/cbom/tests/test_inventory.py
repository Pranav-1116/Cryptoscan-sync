from cbom.generator import CbomGenerator
from cbom.inventory import (
    bom_system_name,
    diff_boms,
    fingerprint,
    is_quantum_vulnerable,
    records_from_bom,
    search_records,
    summarize_records,
    validate_document,
)


def _aes():
    return {
        "id": "a1",
        "algorithm": "AES",
        "mode": "GCM",
        "key_size": 256,
        "file_path": "crypto.py",
        "line_number": 12,
        "system_name": "payments-api",
    }


def _rsa():
    return {
        "id": "r1",
        "algorithm": "RSA",
        "key_size": 2048,
        "file_path": "tls.go",
        "line_number": 40,
        "system_name": "payments-api",
    }


def test_summarize_and_search_estate():
    summary = summarize_records(
        [_aes(), _rsa()],
        source_type="system",
        source_id="sys-1",
        name="payments-api",
        environment="prod",
    )
    assert summary["components"] == 2
    assert summary["algorithms"]["AES"] == 1
    assert summary["quantum_vulnerable"] >= 1
    hits = search_records([_aes(), _rsa()], "rsa")
    assert hits[0]["algorithm"] == "RSA"
    assert hits[0]["system_name"] == "payments-api"
    assert search_records([_aes()], "") == []


def test_ingest_round_trip_and_diff():
    generator = CbomGenerator()
    left = generator.from_records([_aes()], name="payments-api", version="1")
    right = generator.from_records([_aes(), _rsa()], name="payments-api", version="2")
    assert validate_document(left)["ok"]
    assert bom_system_name(left) == "payments-api"
    extracted = records_from_bom(right)
    assert {item["algorithm"] for item in extracted} == {"AES", "RSA"}
    delta = diff_boms(left, right)
    assert delta["counts"]["added"] == 1
    assert delta["added"][0]["algorithm"] == "RSA"
    assert delta["counts"]["removed"] == 0
    assert delta["counts"]["unchanged"] == 1


def test_ingest_skips_non_crypto_components():
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"component": {"name": "vendor-sdk"}},
        "components": [
            {"type": "library", "name": "requests"},
            {
                "type": "cryptographic-asset",
                "name": "ML-KEM-768",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {"algorithm": "ML-KEM-768", "primitive": "kem"},
                },
            },
        ],
    }
    records = records_from_bom(bom)
    assert len(records) == 1
    assert records[0]["algorithm"] == "ML-KEM-768"
    assert not is_quantum_vulnerable("ML-KEM-768")


def test_validate_document_rejects_sbom_without_format():
    assert not validate_document({"components": []})["ok"]
    assert not validate_document("nope")["ok"]


def test_generator_embeds_system_and_portfolio_metadata():
    bom = CbomGenerator().from_records(
        [{**_aes(), "system_id": "sys-1", "system_name": "payments-api"}],
        name="cryptoscan-portfolio",
        version="aggregate",
        metadata_properties=[{"name": "cryptoscan:scope", "value": "estate"}],
    )
    props = {item["name"]: item["value"] for item in bom["components"][0]["properties"]}
    assert props["cryptoscan:system"] == "payments-api"
    meta = {item["name"]: item["value"] for item in bom["metadata"]["properties"]}
    assert meta["cryptoscan:scope"] == "estate"
    assert fingerprint(_aes()) == "AES|GCM|256"
