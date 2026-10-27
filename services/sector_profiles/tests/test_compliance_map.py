"""Sector compliance mapping: attribute policy findings to frameworks."""

from __future__ import annotations

from sector_profiles import map_findings_to_frameworks


def test_banking_maps_payment_tls_to_pci():
    findings = [
        {"algorithm": "TLS1.0", "protocol": "TLS", "asset_type": "payment_gateway",
         "status": "FAIL", "severity": "CRITICAL"},
        {"algorithm": "AES-256", "status": "PASS", "severity": "LOW"},  # not a gap
    ]
    result = map_findings_to_frameworks("banking", findings)
    assert "PCI-DSS" in result["frameworks_with_gaps"]
    # the passing AES finding is not mapped
    assert result["findings_mapped_to_gaps"] == 1
    pci = next(f for f in result["frameworks"] if f["framework"] == "PCI-DSS")
    assert pci["status"] == "FAIL" and pci["gaps"] >= 1


def test_energy_maps_scada_to_nerc():
    findings = [
        {"protocol": "scada", "asset_type": "scada_controller",
         "status": "FAIL", "severity": "CRITICAL"},
    ]
    result = map_findings_to_frameworks("energy", findings)
    assert "NERC-CIP" in result["frameworks_with_gaps"]
    # HIPAA is not an energy framework
    assert all(f["framework"] != "HIPAA" for f in result["frameworks"])


def test_healthcare_maps_patient_to_hipaa():
    findings = [
        {"algorithm": "TLS1.1", "asset_type": "patient_api", "status": "FAIL", "severity": "HIGH"},
    ]
    result = map_findings_to_frameworks("healthcare", findings)
    assert "HIPAA" in result["frameworks_with_gaps"]


def test_no_gaps_all_pass():
    findings = [{"algorithm": "AES-256", "status": "PASS"}, {"algorithm": "RSA", "key_size": 3072, "status": "PASS"}]
    result = map_findings_to_frameworks("banking", findings)
    assert result["frameworks_with_gaps"] == []
    assert all(f["status"] == "PASS" for f in result["frameworks"])


def test_cloud_kms_maps_to_soc2():
    findings = [
        {"asset_type": "kms", "algorithm": "RSA-1024", "status": "FAIL", "severity": "HIGH"},
    ]
    result = map_findings_to_frameworks("cloud_saas", findings)
    frameworks = result["frameworks_with_gaps"]
    assert "SOC2" in frameworks or "CSA-CCM" in frameworks
