"""Binary scan BOM projections: one bounded observation, several honest views."""

from devsecops.binary_boms import build_binary_bom_bundle, diff_binary_bom_bundles


def _records():
    return [{
        "format": "elf",
        "path": "release/bin/payment",
        "file_name": "payment",
        "sha256": "a" * 64,
        "arch": "x86-64",
        "machine": "x86-64",
        "version_info": {"vendor": "Acme Systems", "product": "Payment Engine", "version": "4.2"},
        "imports": ["SSL_connect", "connect", "EVP_aes_256_gcm"],
        "exports": [],
        "strings": ["https://payments.example.test", "TLS_AES_256_GCM_SHA384"],
        "crypto": {"algorithms": ["AES", "TLS 1.3"], "libraries": [
            {"library": "OpenSSL", "provider": "OpenSSL", "version": "3.0.0",
             "evidence_classes": ["IMPORT_MATCH"]}],
        },
        "findings": [{"code": "BIN-LEGACY-TLS", "severity": "HIGH",
                       "title": "legacy TLS marker", "detail": "static evidence"}],
        "embedded": [{
            "format": "firmware",
            "path": "release/firmware.bin!boot",
            "arch": "arm64",
            "device_tree": {"model": "Acme Board", "compatible": ["acme,board-v2"]},
            "containers": [{"format": "squashfs", "offset": 128}],
        }],
    }]


def test_binary_scan_materializes_all_bom_views_with_scope_caveats():
    records = _records()
    result = {"target": "release", "binaries": records,
              "files_walked": 2, "binaries_scanned": 2,
              "vulnerabilities": [{"id": "CVE-TEST-1", "severity": "high",
                                   "package": "OpenSSL"}]}
    bundle = build_binary_bom_bundle(
        {"target": "release", "binaries": records}, result=result,
        sbom={"bomFormat": "CycloneDX", "components": [{"name": "payment"}]},
        cbom={"bomFormat": "CycloneDX", "components": [{"name": "AES"}]},
        target="release", created_by="test")

    assert {"sbom", "cbom", "hbom", "nbom", "vbom", "vulnerability_bom",
            "technology_bom"}.issubset(bundle)
    assert bundle["hbom"]["components"]
    assert any("Acme Board" == row["name"] for row in bundle["hbom"]["components"])
    assert bundle["nbom"]["cryptoscan"]["coverage"]["network_probe_performed"] is False
    assert any(row["name"].startswith("tls capability")
               for row in bundle["nbom"]["components"])
    assert any(row["vendor"] == "Acme Systems" for row in bundle["vbom"]["components"])
    assert {row["id"] for row in bundle["vulnerability_bom"]["vulnerabilities"]} >= {
        "BIN-LEGACY-TLS", "CVE-TEST-1"}
    assert "nbom" in bundle["technology_bom"]["layers"]
    assert "vulnerability" in bundle["technology_bom"]["layers"]


def test_empty_binary_views_do_not_claim_live_hardware_or_network_inventory():
    bundle = build_binary_bom_bundle({"target": "empty", "binaries": []}, result={}, target="empty")
    assert bundle["hbom"]["cryptoscan"]["coverage"]["live_hardware_observed"] is False
    assert bundle["nbom"]["cryptoscan"]["coverage"]["network_probe_performed"] is False
    assert bundle["vulnerability_bom"]["vulnerabilities"] == []


def test_binary_bundle_snapshots_have_stable_identity_and_diff_support():
    first = build_binary_bom_bundle({"target": "release", "binaries": _records()}, target="release")
    second = build_binary_bom_bundle({"target": "release", "binaries": _records()}, target="release")
    assert first["hbom"]["serialNumber"] == second["hbom"]["serialNumber"]
    assert first["hbom"]["cryptoscan"]["snapshot_fingerprint"] == \
           second["hbom"]["cryptoscan"]["snapshot_fingerprint"]
    delta = diff_binary_bom_bundles(first, second)
    assert delta["changed"] is False
    assert set(delta["layers"]) >= {"hbom", "nbom", "vbom", "vulnerability_bom"}
