from pathlib import Path

from policy.core.engine import PolicyEngine
from policy.core.scope_resolver import scopes_apply


def engine() -> PolicyEngine:
    return PolicyEngine(str(Path(__file__).resolve().parents[2] / "rule_definitions"))


def test_scope_resolver_requires_intersection():
    assert not scopes_apply({"algorithm": "DES"}, ["PCI-DSS"])
    assert scopes_apply({"compliance_scopes": ["pci-dss"]}, ["PCI-DSS"])


def test_pci_inventory_requires_purpose():
    result = engine().evaluate(
        {"algorithm": "AES", "purpose": "UNKNOWN", "compliance_scopes": ["PCI-DSS"]}
    )
    assert "PCIDSS-003" in result.failed_rule_ids()


def test_pci_auth_rejects_raw_sha():
    result = engine().evaluate(
        {"algorithm": "SHA-256", "purpose": "PASSWORD_HASHING", "compliance_scopes": ["PCI-DSS"]}
    )
    assert "PCIDSS-004" in result.failed_rule_ids()


def test_nist_rejects_dsa():
    result = engine().evaluate(
        {"algorithm": "DSA", "purpose": "SIGNING", "compliance_scopes": ["NIST-131A"]}
    )
    assert "NIST131A-003" in result.failed_rule_ids()


def test_cnsa_hybrid_waives_rsa():
    failing = engine().evaluate(
        {"algorithm": "RSA", "purpose": "SIGNING", "compliance_scopes": ["CNSA"]}
    )
    assert "CNSA-002" in failing.failed_rule_ids()
    passing = engine().evaluate(
        {
            "algorithm": "RSA",
            "purpose": "SIGNING",
            "compliance_scopes": ["CNSA"],
            "hybrid_mode": True,
        }
    )
    assert "CNSA-002" not in passing.failed_rule_ids()


def test_fips_rsa_key_size():
    result = engine().evaluate(
        {"algorithm": "RSA", "key_size": 1024, "purpose": "KEY_GENERATION", "compliance_scopes": ["FIPS"]}
    )
    assert "FIPS140-002" in result.failed_rule_ids()


def test_critical_failure_flag_on_des():
    result = engine().evaluate({"algorithm": "DES", "purpose": "ENCRYPTION"})
    assert result.overall_status == "FAIL"
    assert result.has_critical_failure
