from remediation.engine import suggest_remediations


def test_des_gets_aes_suggestion():
    report = suggest_remediations(
        [{"algorithm": "DES", "compliance_status": "FAIL", "file_path": "a.java", "line_number": 4}]
    )
    assert report["count"] == 1
    assert report["suggestions"][0]["replace_with"] == "AES-256-GCM"
    assert "policy engine" in report["disclaimer"]
