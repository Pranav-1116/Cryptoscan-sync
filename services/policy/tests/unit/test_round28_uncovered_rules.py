"""Round 28: direct tests for the rules the coverage matrix flagged.

`GET /policy/rules/coverage` (audit 65 P0#4) found 8 rules with no test
referencing them: CNSA-004, FIPS140-003, HIPAA-002, NIST131A-001/002/004/
006, PCIDSS-006. Each gets a failing case (and where meaningful a passing
case) so the shipped packs have no untested rule.
"""

from pathlib import Path

from policy.core.engine import PolicyEngine


def engine() -> PolicyEngine:
    return PolicyEngine(str(Path(__file__).resolve().parents[2] / "rule_definitions"))


def test_cnsa_004_hybrid_required_for_key_exchange():
    # classical-only RSA key exchange in CNSA scope: fails the transition rule
    failing = engine().evaluate(
        {"algorithm": "RSA", "purpose": "KEY_EXCHANGE", "compliance_scopes": ["CNSA"]})
    assert "CNSA-004" in failing.failed_rule_ids()
    # the hybrid construction passes the transition window
    passing = engine().evaluate(
        {"algorithm": "X25519MLKEM768", "purpose": "KEY_EXCHANGE",
         "compliance_scopes": ["CNSA"]})
    assert "CNSA-004" not in passing.failed_rule_ids()


def test_fips140_003_sha1_signing_rejected():
    failing = engine().evaluate(
        {"algorithm": "SHA1WITHRSA", "purpose": "SIGNING",
         "compliance_scopes": ["FIPS"]})
    assert "FIPS140-003" in failing.failed_rule_ids()
    passing = engine().evaluate(
        {"algorithm": "SHA256WITHRSA", "purpose": "SIGNING",
         "compliance_scopes": ["FIPS"]})
    assert "FIPS140-003" not in passing.failed_rule_ids()


def test_hipaa_002_password_hashing_requires_kdf():
    failing = engine().evaluate(
        {"algorithm": "SHA-256", "purpose": "PASSWORD_HASHING",
         "compliance_scopes": ["HIPAA"]})
    assert "HIPAA-002" in failing.failed_rule_ids()
    passing = engine().evaluate(
        {"algorithm": "ARGON2ID", "purpose": "PASSWORD_HASHING",
         "compliance_scopes": ["HIPAA"]})
    assert "HIPAA-002" not in passing.failed_rule_ids()


def test_nist131a_001_rsa_key_transport_disallowed():
    failing = engine().evaluate(
        {"algorithm": "RSA", "purpose": "ENCRYPTION",
         "compliance_scopes": ["NIST-131A"]})
    assert "NIST131A-001" in failing.failed_rule_ids()
    passing = engine().evaluate(
        {"algorithm": "X25519", "purpose": "KEY_EXCHANGE",
         "compliance_scopes": ["NIST-131A"]})
    assert "NIST131A-001" not in passing.failed_rule_ids()


def test_nist131a_002_md5_and_sha1_disallowed():
    for algorithm in ("MD5", "SHA-1"):
        result = engine().evaluate(
            {"algorithm": algorithm, "compliance_scopes": ["NIST-131A"]})
        assert "NIST131A-002" in result.failed_rule_ids(), algorithm
    ok = engine().evaluate(
        {"algorithm": "SHA-256", "compliance_scopes": ["NIST-131A"]})
    assert "NIST131A-002" not in ok.failed_rule_ids()


def test_nist131a_004_signing_requires_approved_algorithms():
    failing = engine().evaluate(
        {"algorithm": "DSA", "purpose": "SIGNING",
         "compliance_scopes": ["NIST-131A"]})
    assert "NIST131A-004" in failing.failed_rule_ids()
    passing = engine().evaluate(
        {"algorithm": "ED25519", "purpose": "SIGNING",
         "compliance_scopes": ["NIST-131A"]})
    assert "NIST131A-004" not in passing.failed_rule_ids()


def test_nist131a_006_sha1_purpose_gated():
    failing = engine().evaluate(
        {"algorithm": "SHA-1", "purpose": "SIGNING",
         "compliance_scopes": ["NIST-131A"]})
    assert "NIST131A-006" in failing.failed_rule_ids()
    # outside the gated purposes the rule does not apply
    untouched = engine().evaluate(
        {"algorithm": "SHA-1", "purpose": "UNKNOWN",
         "compliance_scopes": ["NIST-131A"]})
    assert "NIST131A-006" not in untouched.failed_rule_ids()


def test_pcidss_006_ae_modes_required_for_pan_encryption():
    failing = engine().evaluate(
        {"algorithm": "AES", "mode": "CBC", "purpose": "ENCRYPTION",
         "compliance_scopes": ["PCI-DSS", "PAN"]})
    assert "PCIDSS-006" in failing.failed_rule_ids()
    passing = engine().evaluate(
        {"algorithm": "AES", "mode": "GCM", "purpose": "ENCRYPTION",
         "compliance_scopes": ["PCI-DSS", "PAN"]})
    assert "PCIDSS-006" not in passing.failed_rule_ids()


def test_all_shipped_rules_now_have_test_references():
    """The coverage matrix over the real packs: no rule left untested."""
    from policy.rules.rule_coverage import rule_test_coverage

    rules_dir = Path(__file__).resolve().parents[2] / "rule_definitions"
    result = rule_test_coverage(rules_dir, rules_dir.parent / "tests")
    uncovered = [row["rule_id"] for row in result["rules"] if not row["covered"]]
    assert uncovered == [], f"rules without any test reference: {uncovered}"
