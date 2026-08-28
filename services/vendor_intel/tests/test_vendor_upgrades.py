"""Vendor scoring through the shared registry + quantum classifier."""

from __future__ import annotations

from vendor_intel.risk import score_vendor
from vendor_intel.sbom_import import import_vendor_cbom


def _inv(*algos):
    return [{"algorithm": name} for name in algos]


# --------------------------------------------------------------------------- #
# registry-backed classical risk ladder
# --------------------------------------------------------------------------- #

def test_rsa1024_disallowed_via_registry_key_size():
    scored = score_vendor(inventory=_inv("RSA-1024"))
    assert scored["factors"]["crypto_risk"] == 50
    assert scored["issue"] == "Weak or deprecated crypto"
    assert scored["inventory_summary"]["by_status"] == {"DISALLOWED": 1}


def test_tls_protocol_versions_classified_from_registry():
    tls10 = score_vendor(inventory=_inv("TLS 1.0"))
    assert tls10["factors"]["crypto_risk"] == 50
    assert tls10["inventory_summary"]["by_status"] == {"DISALLOWED": 1}
    tls12 = score_vendor(inventory=_inv("TLS1.2"))
    assert tls12["factors"]["crypto_risk"] == 35
    assert tls12["issue"] == "Deprecated crypto"


def test_restricted_and_unclassified_tiers():
    assert score_vendor(inventory=_inv("Blowfish"))["factors"]["crypto_risk"] == 25
    unknown = score_vendor(inventory=_inv("vendor-secret-cipher"))
    assert unknown["factors"]["crypto_risk"] == 25
    assert unknown["issue"] == "Unclassified crypto"
    assert unknown["inventory_summary"]["recognized"] == 0


def test_strong_inventory_is_five():
    scored = score_vendor(inventory=_inv("AES-256", "TLS 1.3"))
    assert scored["factors"]["crypto_risk"] == 5
    assert scored["issue"] == "Strong crypto"


def test_empty_inventory_is_no_evidence_not_safety():
    scored = score_vendor(inventory=[])
    assert scored["factors"]["crypto_risk"] == 30
    assert scored["issue"] == "No crypto disclosure"
    assert scored["pqc_evidence"]["shor_vulnerable_sites"] == 0
    assert scored["pqc_evidence"]["inventory_algorithms"] == 0
    assert "no evidence" in scored["pqc_evidence"]["note"]


# --------------------------------------------------------------------------- #
# evidence-based PQC risk
# --------------------------------------------------------------------------- #

def test_shor_evidence_flags_readiness_discrepancy():
    scored = score_vendor(inventory=_inv("RSA-2048", "AES-256"), pqc_status="ready")
    assert scored["pqc_evidence"]["shor_vulnerable_sites"] == 1
    assert scored["pqc_evidence"]["shor_vulnerable_algorithms"] == ["RSA"]
    assert scored["pqc_evidence"]["discrepancy"].startswith("claims PQC readiness")
    assert scored["factors"]["pqc_risk"] >= 20  # paperwork does not override evidence


def test_deployed_pqc_evidence_beats_missing_paperwork():
    scored = score_vendor(inventory=_inv("ML-KEM-768", "ML-DSA-65"), pqc_status="none")
    assert scored["factors"]["pqc_risk"] == 0
    assert scored["pqc_evidence"]["pqc_algorithms"] == ["ML-DSA-65", "ML-KEM-768"]
    assert scored["pqc_evidence"]["discrepancy"] is None
    assert scored["score"] <= 10  # 5 crypto + 0 pqc, no multiplier


def test_shor_without_readiness_claim_keeps_status_based_risk():
    scored = score_vendor(inventory=_inv("RSA-2048"), pqc_status="none")
    assert scored["factors"]["pqc_risk"] == 15
    assert scored["pqc_evidence"]["shor_vulnerable_sites"] == 1
    assert scored["pqc_evidence"]["discrepancy"] is None


def test_score_formula_and_contract_unchanged():
    scored = score_vendor(
        inventory=_inv("RSA-1024"),
        classifications=["PCI-DSS"],
        cbom_provided=True,
        long_lived_data=True,
    )
    factors = scored["factors"]
    assert set(factors) == {"crypto_risk", "pqc_risk", "data_risk_multiplier", "transparency"}
    expected = int(round((factors["crypto_risk"] + factors["pqc_risk"]) * factors["data_risk_multiplier"] + factors["transparency"]))
    assert scored["score"] == max(0, min(100, expected))
    assert scored["pqc_status"] == "none"


# --------------------------------------------------------------------------- #
# SBOM import: pqc_ready via the shared classifier
# --------------------------------------------------------------------------- #

def _component(name, primitive="signature", param=None):
    return {
        "type": "cryptographic-asset",
        "name": name,
        "cryptoProperties": {"algorithmProperties": {"primitive": primitive, "parameterSetIdentifier": param}},
    }


def test_sbom_pqc_ready_via_classifier_not_prefixes():
    items = import_vendor_cbom({"bomFormat": "CycloneDX", "components": [_component("Dilithium3")]})
    assert items[0]["pqc_ready"] is True  # registry family signature-pqc (prefix list missed it)
    classical = import_vendor_cbom({"bomFormat": "CycloneDX", "components": [_component("AES-256", primitive="ae", param="256")]})
    assert classical[0]["pqc_ready"] is False
