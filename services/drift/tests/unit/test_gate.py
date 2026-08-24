from drift.core.gate import evaluate_gate, gate_to_sarif


def test_gate_blocks_new_des_encryptor():
    findings = [
        {
            "algorithm": "DES",
            "purpose": "ENCRYPTION",
            "compliance_status": "FAIL",
            "file_path": "Pay.java",
            "line_number": 12,
        }
    ]
    gate = evaluate_gate(findings, [{"drift_type": "NEW", "algorithm": "DES", "purpose": "ENCRYPTION", "reason": "new DES"}])
    assert gate["decision"] == "FAIL"
    assert gate["blocking"]


def test_gate_warns_on_md5_hash_only():
    findings = [
        {
            "algorithm": "MD5",
            "purpose": "HASHING",
            "compliance_status": "FAIL",
            "file_path": "Cache.java",
            "line_number": 3,
        }
    ]
    gate = evaluate_gate(findings, [])
    assert gate["decision"] == "WARN"
    assert not gate["blocking"]
    assert gate["warnings"]


def test_gate_pass_when_clean():
    findings = [
        {
            "algorithm": "AES",
            "purpose": "ENCRYPTION",
            "mode": "GCM",
            "compliance_status": "PASS",
        }
    ]
    gate = evaluate_gate(findings, [])
    assert gate["decision"] == "PASS"
    sarif = gate_to_sarif(gate, scan_id="s1")
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is True


def test_upgrade_is_warning_not_block():
    gate = evaluate_gate(
        [],
        [{"drift_type": "CHANGED", "algorithm": "AES", "purpose": "ENCRYPTION", "reason": "UPGRADED CBC to GCM"}],
    )
    assert gate["decision"] == "WARN"
    assert any(item["code"] == "UPGRADE" for item in gate["warnings"])
