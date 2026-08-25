from quantum.risk import analyze_quantum_risk, classify


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
