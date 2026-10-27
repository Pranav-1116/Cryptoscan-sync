"""Qatar (QCB / PDPPL) and Bahrain (CBB / Bahrain PDPL) packs, and the cross-jurisdiction guarantee.

Grounding:
  - QCB Technology Risk Circular (2018) / Information Security Standard.
  - Qatar Law No. 13 of 2016 (PDPPL), Arts. 8–13.
  - CBB Rulebook Module OM-5 Cyber Security (2021); Bahrain Open Banking Framework (2020).
  - Bahrain Law No. 30 of 2018 (PDPL), Art. 8.
"""

from __future__ import annotations

from pathlib import Path

from policy.core.engine import PolicyEngine

GCC_RULE_IDS = ["QCB-001", "QCB-002", "QCB-003", "PDPPL-001", "PDPPL-002", "CBB-001", "CBB-002", "CBB-003", "BHPDPL-001", "BHPDPL-002"]
UAE_PERSONAL_DATA = ["PDPL-001", "PDPL-002", "DIFC-001", "DIFC-002", "ADGM-001"]


def engine() -> PolicyEngine:
    return PolicyEngine(str(Path(__file__).resolve().parents[2] / "rule_definitions"))


def _outcome(result, rule_id: str) -> str:
    for r in result.rules_evaluated:
        if r.rule_id == rule_id:
            return str(r.evaluation_result)
    raise AssertionError(f"{rule_id} not evaluated")


def test_gcc_rules_load_enabled_with_references():
    e = engine()
    for rule_id in GCC_RULE_IDS:
        rule = e.get_rule(rule_id)
        assert rule is not None and rule.enabled and rule.standard_reference and rule.remediation, rule_id


def test_qcb_scoped_legacy_and_tls():
    e = engine()
    r = e.evaluate({"algorithm": "3DES", "purpose": "ENCRYPTION", "compliance_scopes": ["QCB", "PAYMENT", "CARD"]})
    assert _outcome(r, "QCB-001") == "FAIL" and "QCB-001" in [x.rule_id for x in r.critical_failures()]
    assert _outcome(r, "CBB-001") == "NOT_APPLICABLE" and _outcome(r, "PDPPL-001") == "NOT_APPLICABLE"
    r = e.evaluate({"algorithm": "TLS1.0", "purpose": "NETWORK_ENCRYPTION", "compliance_scopes": ["QCB", "REMOTE-ACCESS"]})
    assert _outcome(r, "QCB-002") == "FAIL"
    r = e.evaluate({"algorithm": "RSA", "key_size": 1024, "compliance_scopes": ["QCB"]})
    assert _outcome(r, "QCB-003") == "FAIL"
    r = e.evaluate({"algorithm": "RSA", "key_size": 3072, "compliance_scopes": ["QCB"]})
    assert _outcome(r, "QCB-003") == "PASS"


def test_cbb_open_banking_tls_floor():
    e = engine()
    r = e.evaluate({"algorithm": "TLS1.1", "purpose": "NETWORK_ENCRYPTION", "compliance_scopes": ["CBB", "OPEN-BANKING"]})
    assert _outcome(r, "CBB-002") == "FAIL" and _outcome(r, "QCB-002") == "NOT_APPLICABLE"
    r = e.evaluate({"algorithm": "TLS1.3", "purpose": "NETWORK_ENCRYPTION", "compliance_scopes": ["CBB", "OPEN-BANKING"]})
    assert _outcome(r, "CBB-002") == "PASS"


def test_personal_data_rules_follow_the_jurisdiction_not_the_generic_tag():
    """A Qatari KYC store tagged [PDPPL, PERSONAL_DATA] is judged under PDPPL only; the UAE / Bahrain personal-data
    rules stay NOT_APPLICABLE. PERSONAL_DATA on its own selects no law at all."""
    e = engine()
    qa = e.evaluate({"algorithm": "DES", "purpose": "ENCRYPTION", "compliance_scopes": ["PDPPL", "PERSONAL_DATA"]})
    assert _outcome(qa, "PDPPL-001") == "FAIL" and _outcome(qa, "PDPPL-002") == "FAIL"
    for rid in UAE_PERSONAL_DATA + ["BHPDPL-001", "BHPDPL-002"]:
        assert _outcome(qa, rid) == "NOT_APPLICABLE", rid
    bh = e.evaluate({"algorithm": "SHA-1", "purpose": "HASHING", "compliance_scopes": ["BH-PDPL", "PERSONAL_DATA"]})
    assert _outcome(bh, "BHPDPL-001") == "FAIL"
    for rid in UAE_PERSONAL_DATA + ["PDPPL-001", "PDPPL-002"]:
        assert _outcome(bh, rid) == "NOT_APPLICABLE", rid
    generic = e.evaluate({"algorithm": "DES", "purpose": "ENCRYPTION", "compliance_scopes": ["PERSONAL_DATA"]})
    for rid in UAE_PERSONAL_DATA + GCC_RULE_IDS:
        assert _outcome(generic, rid) == "NOT_APPLICABLE", rid
    # the UAE pack still fires on its own tags
    ae = e.evaluate({"algorithm": "DES", "purpose": "ENCRYPTION", "compliance_scopes": ["PDPL", "PERSONAL_DATA"]})
    assert _outcome(ae, "PDPL-002") == "FAIL" and _outcome(ae, "PDPPL-001") == "NOT_APPLICABLE"
