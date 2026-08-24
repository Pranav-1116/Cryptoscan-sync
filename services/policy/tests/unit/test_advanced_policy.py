from pathlib import Path

from policy.core.engine import PolicyEngine


def engine() -> PolicyEngine:
    return PolicyEngine(str(Path(__file__).resolve().parents[2] / "rule_definitions"))


def test_pci_skips_without_scope():
    result = engine().evaluate({"algorithm": "DES", "purpose": "ENCRYPTION"})
    assert "PCIDSS-001" not in result.failed_rule_ids()


def test_pci_fails_des_in_scope():
    result = engine().evaluate(
        {
            "algorithm": "DES",
            "purpose": "ENCRYPTION",
            "compliance_scopes": ["PCI-DSS"],
        }
    )
    assert "PCIDSS-001" in result.failed_rule_ids()


def test_pci_requires_aes_gcm_256():
    result = engine().evaluate(
        {
            "algorithm": "AES",
            "mode": "CBC",
            "key_size": 128,
            "purpose": "ENCRYPTION",
            "compliance_scopes": ["PAN"],
        }
    )
    assert "PCIDSS-002" in result.failed_rule_ids()


def test_cnsa_retires_rsa_after_2025():
    result = engine().evaluate(
        {
            "algorithm": "RSA",
            "purpose": "SIGNING",
            "compliance_scopes": ["CNSA"],
            "evaluation_date": "2026-08-24",
        }
    )
    assert "CNSA-001" in result.failed_rule_ids()


def test_fips_rejects_md5():
    result = engine().evaluate({"algorithm": "MD5", "purpose": "HASHING", "compliance_scopes": ["FIPS"]})
    assert "FIPS140-001" in result.failed_rule_ids()


def test_hipaa_rejects_sha1_for_ephi():
    result = engine().evaluate({"algorithm": "SHA-1", "purpose": "HASHING", "compliance_scopes": ["EPHI"]})
    assert "HIPAA-001" in result.failed_rule_ids()
