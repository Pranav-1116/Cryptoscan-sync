"""UAE regulatory pack — CBUAE / DIFC (DFSA) / ADGM (FSRA) / Federal PDPL.

Grounding:
  - CBUAE Cybersecurity Framework (9 domains) + Information Security Standards
    (ISO/IEC 27001-aligned) — all licensed financial institutions.
  - DIFC Data Protection Law No. 5/2020 (in force 2020-07-01), Art. 23.
  - ADGM Data Protection Regulations 2021 (in force 2021-08-14).
  - UAE Federal PDPL, Decree-Law No. 45/2021 (in force 2022-01-02), Art. 20.

The rules are deterministic: they evaluate the crypto inventory itself
(algorithm / mode / key size / purpose / scope tags), never text claims.
"""
from __future__ import annotations

from pathlib import Path

from policy.core.engine import PolicyEngine

UAE_RULE_IDS = {
    "CBUAE-001", "CBUAE-002", "CBUAE-003", "CBUAE-004", "CBUAE-005",
    "DIFC-001", "DIFC-002",
    "PDPL-001", "PDPL-002",
    "ADGM-001",
}


def engine() -> PolicyEngine:
    return PolicyEngine(str(Path(__file__).resolve().parents[2] / "rule_definitions"))


def _outcome(result, rule_id: str) -> str:
    for r in result.rules_evaluated:
        if r.rule_id == rule_id:
            return str(r.evaluation_result)
    raise AssertionError(f"{rule_id} not evaluated")


# --------------------------------------------------------------------------- #
# Pack integrity
# --------------------------------------------------------------------------- #

def test_uae_rules_load_into_engine():
    e = engine()
    for rule_id in UAE_RULE_IDS:
        rule = e.get_rule(rule_id)
        assert rule is not None, f"{rule_id} missing from the loaded pack"
        assert rule.enabled is True, f"{rule_id} must ship enabled"
        assert rule.standard_reference, f"{rule_id} needs a standard reference"
        assert rule.remediation, f"{rule_id} needs remediation guidance"


def test_uae_rule_ids_are_unique_and_prefixed():
    e = engine()
    uae = [r.rule_id for r in e.get_enabled_rules()
           if r.rule_id.split("-")[0] in {"CBUAE", "DIFC", "PDPL", "ADGM"}]
    assert len(uae) == len(set(uae)) == len(UAE_RULE_IDS)


def test_uae_scoped_rules_are_scope_gated():
    """A finding with no scope tags trips no UAE rule except the estate floor."""
    result = engine().evaluate({"algorithm": "AES", "mode": "GCM", "key_size": 256,
                                "purpose": "ENCRYPTION"})
    for rule_id in UAE_RULE_IDS - {"CBUAE-001"}:
        assert _outcome(result, rule_id) == "NOT_APPLICABLE", rule_id
    assert _outcome(result, "CBUAE-001") == "PASS"


# --------------------------------------------------------------------------- #
# CBUAE — estate floor and payment channels
# --------------------------------------------------------------------------- #

def test_cbuae_001_floor_flags_des():
    result = engine().evaluate({"algorithm": "3DES", "purpose": "ENCRYPTION",
                                "compliance_scopes": ["CBUAE"]})
    assert "CBUAE-001" in result.failed_rule_ids()
    assert result.critical_failures(), "legacy crypto is a critical failure"


def test_cbuae_002_payment_data_strong_encryption_pass():
    result = engine().evaluate({
        "algorithm": "AES", "mode": "GCM", "key_size": 256,
        "purpose": "ENCRYPTION", "compliance_scopes": ["CBUAE", "PAYMENT"],
    })
    assert _outcome(result, "CBUAE-002") == "PASS"


def test_cbuae_002_payment_data_rejects_short_key_and_cbc():
    result = engine().evaluate({
        "algorithm": "AES", "mode": "CBC", "key_size": 128,
        "purpose": "ENCRYPTION", "compliance_scopes": ["PAYMENT"],
    })
    assert _outcome(result, "CBUAE-002") == "FAIL"


def test_cbuae_003_tls_floor_rejects_tls11():
    result = engine().evaluate({
        "algorithm": "TLS1.1", "purpose": "TRANSPORT",
        "compliance_scopes": ["CBUAE", "CUSTOMER-FACING"],
    })
    assert _outcome(result, "CBUAE-003") == "FAIL"
    result13 = engine().evaluate({
        "algorithm": "TLS1.3", "purpose": "TRANSPORT",
        "compliance_scopes": ["CBUAE"],
    })
    assert _outcome(result13, "CBUAE-003") == "PASS"


def test_cbuae_004_rsa_floor():
    weak = engine().evaluate({
        "algorithm": "RSA", "key_size": 1024, "purpose": "SIGNATURE",
        "compliance_scopes": ["CBUAE"],
    })
    assert _outcome(weak, "CBUAE-004") == "FAIL"
    ok = engine().evaluate({
        "algorithm": "RSA", "key_size": 3072, "purpose": "SIGNATURE",
        "compliance_scopes": ["CBUAE"],
    })
    assert _outcome(ok, "CBUAE-004") == "PASS"


def test_cbuae_005_ecc_floor_ignores_rsa():
    short = engine().evaluate({
        "algorithm": "ECC", "key_size": 192, "purpose": "KEY_AGREEMENT",
        "compliance_scopes": ["CBUAE"],
    })
    assert _outcome(short, "CBUAE-005") == "FAIL"
    rsa = engine().evaluate({
        "algorithm": "RSA", "key_size": 1024, "purpose": "SIGNATURE",
        "compliance_scopes": ["CBUAE"],
    })
    assert _outcome(rsa, "CBUAE-005") == "NOT_APPLICABLE"


# --------------------------------------------------------------------------- #
# DIFC / PDPL / ADGM — personal-data technical measures
# --------------------------------------------------------------------------- #

def test_difc_002_flags_rc4_on_personal_data():
    result = engine().evaluate({
        "algorithm": "RC4", "purpose": "ENCRYPTION",
        "compliance_scopes": ["DIFC", "PERSONAL_DATA"],
    })
    assert _outcome(result, "DIFC-002") == "FAIL"
    critical_ids = [r.rule_id for r in result.critical_failures()]
    assert "DIFC-002" in critical_ids


def test_difc_001_personal_data_encryption_pass():
    result = engine().evaluate({
        "algorithm": "AES", "mode": "GCM", "key_size": 256,
        "purpose": "ENCRYPTION", "compliance_scopes": ["DIFC", "PERSONAL_DATA"],
    })
    assert _outcome(result, "DIFC-001") == "PASS"
    # Scope lists are OR-activated by design: a DIFC-tagged asset that
    # encrypts is in scope for the DP Law (DIFC entities process personal
    # data under it), so the rule applies and passes on strong crypto.
    infra = engine().evaluate({
        "algorithm": "DES", "purpose": "ENCRYPTION",
        "compliance_scopes": ["DIFC"],
    })
    assert _outcome(infra, "DIFC-001") == "FAIL"
    # An asset with no DIFC / personal-data tags at all is out of scope.
    neutral = engine().evaluate({
        "algorithm": "AES", "mode": "GCM", "key_size": 256,
        "purpose": "ENCRYPTION", "compliance_scopes": ["CBUAE"],
    })
    assert _outcome(neutral, "DIFC-001") == "NOT_APPLICABLE"


def test_pdpl_001_and_002():
    weak = engine().evaluate({
        "algorithm": "DES", "purpose": "ENCRYPTION",
        "compliance_scopes": ["PDPL", "PERSONAL_DATA"],
    })
    assert _outcome(weak, "PDPL-001") == "FAIL"
    assert _outcome(weak, "PDPL-002") == "FAIL"
    strong = engine().evaluate({
        "algorithm": "CHACHA20-POLY1305", "purpose": "ENCRYPTION",
        "compliance_scopes": ["UAE-PDPL-45-2021"],
    })
    assert _outcome(strong, "PDPL-001") == "PASS"
    assert _outcome(strong, "PDPL-002") == "PASS"


def test_adgm_001_tech_measures():
    result = engine().evaluate({
        "algorithm": "MD5", "purpose": "HASHING",
        "compliance_scopes": ["ADGM", "PERSONAL_DATA"],
    })
    # MD5 is a hashing purpose — the encryption rule does not apply, and the
    # pack has no hash-forbidden rule for ADGM (honest scoping).
    assert _outcome(result, "ADGM-001") == "NOT_APPLICABLE"
    enc = engine().evaluate({
        "algorithm": "AES", "mode": "GCM", "key_size": 256,
        "purpose": "ENCRYPTION", "compliance_scopes": ["ADGM"],
    })
    assert _outcome(enc, "ADGM-001") == "PASS"


def test_unscoped_asset_trips_only_estate_floor():
    """Estate-wide rule applies; all scoped UAE rules stay NOT_APPLICABLE."""
    result = engine().evaluate({"algorithm": "MD5", "purpose": "HASHING"})
    assert "CBUAE-001" in result.failed_rule_ids()
    for rule_id in UAE_RULE_IDS - {"CBUAE-001"}:
        assert _outcome(result, rule_id) == "NOT_APPLICABLE", rule_id
