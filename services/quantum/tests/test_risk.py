from datetime import date

from quantum.risk import analyze_quantum_risk, classify, migration_deadline, score_asset


def test_rsa_is_hndl_high_aes256_is_low():
    assert classify("RSA", key_size=2048)["harvest_now_decrypt_later_risk"] == "HIGH"
    assert classify("AES", key_size=256)["vulnerable"] is False
    assert classify("DES")["harvest_now_decrypt_later_risk"] == "CRITICAL"
    report = analyze_quantum_risk(
        [
            {"algorithm": "RSA", "key_size": 2048, "file_path": "a.py", "line_number": 1},
            {"algorithm": "AES", "key_size": 256, "file_path": "b.py", "line_number": 2},
        ]
    )
    assert report["overall_hndl_risk"] == "HIGH"
    assert report["vulnerable_count"] == 1


def test_hndl_and_deadline_for_healthcare_rsa():
    scored = score_asset(
        {"algorithm": "RSA", "key_size": 2048, "purpose": "KEY_EXCHANGE"},
        system={
            "compliance_scopes": ["DORA", "HIPAA"],
            "data_classifications": ["PHI"],
            "criticality": "TIER-1",
            "extra": {"data_retention_years": 30, "network_type": "PUBLIC_INTERNET"},
        },
        today=date(2024, 2, 1),
    )
    assert scored["threat_type"] == "SHOR_VULNERABLE"
    assert scored["hndl_risk"] == "CRITICAL"
    assert scored["quantum_risk_score"] >= 80
    assert scored["recommended_replacement"] == "ML-KEM-768"
    assert scored["hybrid_mode_recommended"] is True
    deadline = migration_deadline(scopes=["DORA"], retention_years=30, today=date(2024, 2, 1))
    assert deadline["deadline_date"] == "2025-01-17"
    assert deadline["days_remaining"] == 351
