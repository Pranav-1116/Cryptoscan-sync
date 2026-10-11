"""VBOM generator (advanced/46 P1#5, round 30): document shapes."""

from __future__ import annotations

from datetime import datetime, timezone

from vendor_intel.vbom import VbomGenerator


def _vendor(vid="v-1", name="Acme Crypto Corp", **extra):
    base = {
        "id": vid,
        "name": name,
        "vendor_type": "kms",
        "criticality": "high",
        "integration_type": "api",
        "primary_contact": "sales@acme.example",
        "security_contact": "sec@acme.example",
        "technical_contact": "tech@acme.example",
        "contract_end_date": datetime(2027, 3, 1, tzinfo=timezone.utc),
        "data_classifications": ["PII", "PCI-DSS"],
    }
    base.update(extra)
    return base


def _inventory(algorithm="RSA-2048", pqc_ready=False, **extra):
    base = {
        "crypto_use_case": "key_management",
        "algorithm": algorithm,
        "key_size": 2048,
        "mode": None,
        "key_management": "vendor HSM",
        "pqc_ready": pqc_ready,
        "discovery_method": "sbom_import",
        "confidence": "HIGH",
        "discovered_at": datetime(2026, 10, 1, tzinfo=timezone.utc),
        "verified_at": None,
        "source_document": "acme-cbom-2026.json",
    }
    base.update(extra)
    return base


def test_native_document_carries_vendor_inventory_and_provenance():
    gen = VbomGenerator()
    gen.add_vendor(
        _vendor(),
        inventory=[_inventory(), _inventory("ML-KEM-768", pqc_ready=True)],
        systems=[{"system_id": "sys-1", "system_name": "Payments", "dependency_type": "api"}],
        profile={"revision": 3, "status": "APPROVED", "captured_at": "2026-09-01T00:00:00+00:00"},
    )
    doc = gen.to_document()
    assert doc["vbomFormat"] == "ZELNX-VBOM"
    assert doc["summary"]["vendors"] == 1
    assert doc["summary"]["crypto_entries"] == 2
    assert doc["summary"]["pqc_ready_entries"] == 1
    assert doc["summary"]["pqc_ready_pct"] == 50.0
    vendor = doc["vendors"][0]
    assert vendor["bom-ref"] == "vendor:v-1"
    assert vendor["contacts"]["technical"] == "tech@acme.example"
    assert vendor["contract_end_date"].startswith("2027-03-01")
    assert vendor["systems"][0]["system_name"] == "Payments"
    assert vendor["profile"]["status"] == "APPROVED"
    assert vendor["pqc_coverage"] == {"entries": 2, "pqc_ready": 1, "not_ready": 1}
    # provenance rides on every entry (advanced/46 §7.2)
    entry = vendor["crypto"][0]
    assert entry["discovery_method"] == "sbom_import"
    assert entry["confidence"] == "HIGH"
    assert entry["source_document"] == "acme-cbom-2026.json"
    assert entry["discovered_at"].startswith("2026-10-01")


def test_cyclonedx_export_maps_inventory_to_crypto_assets():
    gen = VbomGenerator()
    gen.add_vendor(
        _vendor(vid="v-9", name="EdgeCA"),
        inventory=[_inventory(algorithm="ECDSA-P256", key_size=256, mode=None)],
    )
    doc = gen.to_cyclonedx()
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    comp = doc["components"][0]
    assert comp["type"] == "cryptographic-asset"
    assert comp["supplier"] == {"name": "EdgeCA"}
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["cryptoscan:vendor-id"] == "v-9"
    assert props["cryptoscan:pqc-ready"] == "false"
    algo = comp["cryptoProperties"]["algorithmProperties"]
    assert algo["algorithm"] == "ECDSA-P256"
    assert algo["parameterSetIdentifier"] == "256"
    ev = {p["name"]: p["value"] for p in comp["evidence"]["properties"]}
    assert ev["cryptoscan:source-document"] == "acme-cbom-2026.json"


def test_vendor_without_inventory_stays_visible():
    gen = VbomGenerator()
    gen.add_vendor(_vendor(vid="v-2", name="Silent Vendor"))
    doc = gen.to_cyclonedx()
    assert len(doc["components"]) == 1
    assert doc["components"][0]["type"] == "service"
    props = {p["name"]: p["value"] for p in doc["components"][0]["properties"]}
    assert props["cryptoscan:inventory"] == "none-declared"
    native = gen.to_document()
    assert native["summary"]["vendors_with_inventory"] == 0
    assert native["summary"]["vendors_missing_contract_end"] == 0


def test_replace_and_remove_are_not_stacking():
    gen = VbomGenerator()
    gen.add_vendor(_vendor(), inventory=[_inventory()])
    gen.add_vendor(_vendor(), inventory=[_inventory("AES-256-GCM")])
    assert len(gen.vendors()) == 1
    assert gen.vendors()[0]["crypto"][0]["algorithm"] == "AES-256-GCM"
    assert gen.remove_vendor("v-1") is True
    assert gen.remove_vendor("v-1") is False
    assert gen.summary()["vendors"] == 0


def test_confidence_mix_and_entry_requires_id():
    gen = VbomGenerator()
    gen.add_vendor(_vendor(vid="a"), inventory=[
        _inventory(confidence="HIGH"), _inventory(algorithm="X", confidence="LOW"),
        _inventory(algorithm="Y", confidence=None),
    ])
    gen.add_vendor(_vendor(vid="b", name="Zeta"), inventory=[_inventory(confidence="MEDIUM")])
    mix = gen.summary()["entries_by_confidence"]
    assert mix == {"HIGH": 1, "LOW": 1, "UNKNOWN": 1, "MEDIUM": 1}
    try:
        gen.add_vendor({"name": "no id"})
        raised = False
    except ValueError:
        raised = True
    assert raised
