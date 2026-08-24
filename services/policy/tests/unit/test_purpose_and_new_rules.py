from pathlib import Path

from policy.conditions.purpose_condition import PurposeCondition
from policy.core.engine import PolicyEngine


def engine() -> PolicyEngine:
    return PolicyEngine(str(Path(__file__).resolve().parents[2] / "rule_definitions"))


def test_purpose_condition_filters():
    cond = PurposeCondition()
    skip = cond.evaluate({"purpose": "HASHING"}, {"purpose_list": ["ENCRYPTION"]})
    assert skip.result == "NOT_APPLICABLE"
    fail = cond.evaluate({"purpose": "KEY_EXCHANGE"}, {"forbidden_purposes": ["KEY_EXCHANGE"]})
    assert fail.result == "FAIL"


def test_nist_rsa_key_agreement_fails_in_scope():
    result = engine().evaluate(
        {"algorithm": "RSA", "purpose": "KEY_AGREEMENT", "compliance_scopes": ["NIST-131A"]}
    )
    assert "NIST131A-005" in result.failed_rule_ids()


def test_cnsa_requires_aes_256():
    result = engine().evaluate(
        {"algorithm": "AES", "purpose": "ENCRYPTION", "key_size": 128, "compliance_scopes": ["CNSA"]}
    )
    assert "CNSA-003" in result.failed_rule_ids()


def test_pci_forbids_tls10():
    result = engine().evaluate(
        {"algorithm": "TLS1.0", "purpose": "KEY_EXCHANGE", "compliance_scopes": ["PCI-DSS"]}
    )
    assert "PCIDSS-005" in result.failed_rule_ids()


def test_new_rules_are_loaded():
    counts = engine().get_rule_count()
    assert counts["enabled"] >= 20
