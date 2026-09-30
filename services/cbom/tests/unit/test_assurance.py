"""Unit tests for the Assurance & Control engine.

Covers VEX enrichment + prioritization, xBOM correlation across the shared
BOM layers, the pre-deploy admission gate, and runtime drift verification.
"""

from __future__ import annotations

from cbom.assurance import (
    assess_vex,
    correlate_xbom,
    evaluate_admission,
    is_blocking,
    is_weak,
    runtime_drift,
)
from cbom.technology_bom import materialize_technology_bom


def _inventory() -> dict:
    return {
        "applications": [
            {"id": "sys-pay", "name": "payment-api", "version": "2.3.1",
             "owner": "payments", "environment": "prod", "criticality": "TIER-1"},
            {"id": "sys-web", "name": "web-frontend", "version": "1.0.0",
             "owner": "platform", "environment": "prod", "criticality": "TIER-1"},
        ],
        "crypto": [
            {"id": "ca-rsa", "algorithm": "RSA-2048", "key_size": 2048,
             "purpose": "ENCRYPTION", "mode": "GCM", "asset": "sys-pay",
             "file_path": "src/Pay.java", "confidence": "HIGH",
             "library": "openssl"},
            {"id": "ca-aes", "algorithm": "AES-256", "key_size": 256,
             "purpose": "ENCRYPTION", "mode": "GCM", "asset": "sys-db",
             "file_path": "db/aes.py", "confidence": "HIGH", "library": "cryptography"},
            {"id": "ca-ecb", "algorithm": "AES-128", "key_size": 128,
             "purpose": "ENCRYPTION", "mode": "ECB", "asset": "sys-legacy",
             "file_path": "legacy.py", "confidence": "MEDIUM"},
            {"id": "ca-md5", "algorithm": "MD5", "key_size": None,
             "purpose": "HASHING", "asset": "sys-pay", "file_path": "hash.py",
             "confidence": "LOW"},
        ],
        "hardware": [
            {"id": "hw-hsm", "asset_id": "hsm-01", "manufacturer": "ZELNX",
             "model": "HSM-3000", "device_type": "hsm", "risk_level": "HIGH"},
        ],
        "vendors": [
            {"name": "ZELNX", "product": "HSM-3000", "model": "HSM-3000",
             "risk_level": "HIGH", "lifecycle": "supported"},
        ],
        "certificates": [{"fingerprint": "aa" * 32, "subject": "CN=pay"}],
        "dependencies": [["sys-pay", "sys-db"]],
        "scan": {"collected_at": "2026-09-09T00:00:00+00:00"},
    }


def _state() -> dict:
    return materialize_technology_bom(_inventory(), environment="prod", state_version=1)


def test_weak_and_blocking_verdicts():
    assert is_weak({"algorithm": "RSA-1024", "purpose": "ENCRYPTION", "key_size": 1024}) is True
    assert is_weak({"algorithm": "RSA-2048", "purpose": "ENCRYPTION", "key_size": 2048}) is False
    assert is_weak({"algorithm": "AES-128", "purpose": "ENCRYPTION", "key_size": 128, "mode": "ECB"}) is True
    # MD5 for hashing is weak but not blocking
    assert is_blocking({"algorithm": "MD5", "purpose": "HASHING"}) is False
    # AES-ECB in a blocking purpose blocks
    assert is_blocking({"algorithm": "AES-128", "purpose": "ENCRYPTION", "mode": "ECB"}) is True


def test_vex_enriches_and_prioritizes():
    state = _state()
    comps = state["layers"]["cbom"]["components"]
    vulns = [
        {"cve": "CVE-2024-1111", "package": "openssl", "severity": "CRITICAL", "summary": "RSA padding oracle"},
        {"cve": "CVE-2024-2222", "package": "nonexistent-lib", "severity": "HIGH", "summary": "not deployed"},
        {"cve": "CVE-2024-3333", "package": "md5", "severity": "MEDIUM", "summary": "deprecated hash"},
    ]
    result = assess_vex(comps, vulns, reachable=["crypto:ca-rsa:sys-pay"])
    assert result["total"] == 3
    # the CRITICAL openssl vuln is reachable/exploitable -> P0
    by_cve = {f["cve"]: f for f in result["findings"]}
    assert by_cve["CVE-2024-1111"]["priority"] == "P0"
    assert by_cve["CVE-2024-1111"]["vex_status"] == "affected"
    # a CVE with no matching component -> not_affected
    assert by_cve["CVE-2024-2222"]["vex_status"] == "not_affected"
    # summary fields present
    assert result["top_p0"]


def test_xbom_correlates_across_layers():
    state = _state()
    system_assets = [
        {"system_id": "sys-pay", "asset_id": "ca-rsa"},
        {"system_id": "sys-pay", "asset_id": "ca-md5"},
        {"system_id": "sys-db", "asset_id": "ca-aes"},
        {"system_id": "sys-legacy", "asset_id": "ca-ecb"},
    ]
    bps = [{"name": "Payment Processing", "process_type": "payments",
            "revenue_daily": 100000, "sla_uptime": 99.99, "system_ids": ["sys-pay"]}]
    res = correlate_xbom(state, system_assets=system_assets, business_processes=bps)
    assert res["layer_set"] == ["sbom", "cbom", "hbom", "vendor"]
    assert res["count"] == 4
    # AES-ECB is deploy-relevant (blocking) so at least one trace flags it
    assert res["deploy_relevant"] >= 1
    # find the payment crypto that maps to a business process
    pay = [t for t in res["traces"] if t["crypto"]["algorithm"] == "RSA-2048"]
    assert pay and pay[0]["applications"] and pay[0]["applications"][0]["name"] == "payment-api"
    assert any(bp["name"] == "Payment Processing" for bp in pay[0]["business_processes"])


def test_xbom_trace_by_ref():
    state = _state()
    system_assets = [{"system_id": "sys-pay", "asset_id": "ca-rsa"}]
    res = correlate_xbom(state, bom_ref="crypto:ca-rsa:sys-pay", system_assets=system_assets)
    assert res["count"] == 1
    assert res["traces"][0]["crypto"]["bom-ref"] == "crypto:ca-rsa:sys-pay"


def test_admission_gate_fails_on_blocking_weak_crypto():
    state = _state()
    res = evaluate_admission(state)
    # AES-ECB (ca-ecb) sits in ENCRYPTION (blocking) and is weak
    assert res["decision"] == "FAIL"
    assert res["admitted"] is False
    assert res["blocking_count"] >= 1
    assert any(b["algorithm"] == "AES-128" and b["purpose"] == "ENCRYPTION" for b in res["blocking"])
    # MD5-HASHING is a warning, not a block
    assert any(w["algorithm"] == "MD5" for w in res["warnings"])
    assert res["snapshot_id"]


def test_admission_gate_clean_passes():
    inv = _inventory()
    inv["crypto"] = [c for c in inv["crypto"] if c["id"] not in ("ca-ecb", "ca-md5")]
    state = materialize_technology_bom(inv, environment="prod", state_version=2)
    res = evaluate_admission(state)
    assert res["decision"] == "PASS"
    assert res["admitted"] is True


def test_runtime_drift_detects_runtime_only_and_tls_weak():
    state = _state()
    runtime = [
        {"hostname": "pay-01", "process_name": "java", "algorithm": "RSA-2048",
         "key_size": 2048, "tls_version": "1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384"},
        {"hostname": "pay-02", "process_name": "java", "algorithm": "DES",
         "key_size": 56, "tls_version": "1.0", "cipher_suite": "TLS_RSA_WITH_DES_CBC_SHA"},
        {"hostname": "db-01", "process_name": "python", "algorithm": "RC4",
         "key_size": 128, "tls_version": "", "cipher_suite": "TLS_RSA_WITH_RC4_128_SHA"},
    ]
    res = runtime_drift(state, runtime)
    assert res["observed"] == 3
    # DES is runtime-only (not in BOM) AND weak -> drift
    assert res["runtime_only"] >= 1
    assert res["weak_at_runtime"] >= 1
    assert res["tls_below_1_2"] >= 1
    assert res["halting"]  # weak-at-runtime rows
    # RC4 observed at runtime should be flagged drift
    rc4 = [r for r in res["drift_rows"] if r["algorithm"] == "RC4"]
    assert rc4 and rc4[0]["drift"] is True
