from drift.classifiers.severity_calculator import Severity, SeverityCalculator


def test_new_des_is_critical():
    calc = SeverityCalculator()
    assert calc.calculate_for_new_crypto({"algorithm": "DES", "compliance_status": "FAIL"}) == Severity.CRITICAL


def test_new_aes_is_medium():
    calc = SeverityCalculator()
    assert calc.calculate_for_new_crypto({"algorithm": "AES", "compliance_status": "PASS"}) == Severity.MEDIUM


def test_removed_compliant_is_medium():
    calc = SeverityCalculator()
    assert calc.calculate_for_removed_crypto({"algorithm": "AES", "compliance_status": "PASS"}) == Severity.MEDIUM


def test_removed_weak_is_info():
    calc = SeverityCalculator()
    assert calc.calculate_for_removed_crypto({"algorithm": "DES", "compliance_status": "FAIL"}) == Severity.INFO


def test_hardcoded_key_is_critical():
    calc = SeverityCalculator()
    assert calc.calculate_for_new_crypto({"algorithm": "AES", "is_hardcoded_key": True}) == Severity.CRITICAL
