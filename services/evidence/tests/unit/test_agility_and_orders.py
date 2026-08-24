from evidence.intelligence.agility import compute_agility
from evidence.intelligence.work_orders import build_work_orders
from evidence.pack.audit_zip import build_audit_zip


def test_agility_penalizes_hardcoded_fails():
    findings = [
        {
            "algorithm": "DES",
            "purpose": "ENCRYPTION",
            "compliance_status": "FAIL",
            "finding_data": {"crypto": {"raw_transformation": "DES/ECB/PKCS5Padding"}, "metadata": {"confidence_reason": "literal-api"}},
        },
        {
            "algorithm": "AES",
            "purpose": "ENCRYPTION",
            "compliance_status": "PASS",
            "confidence": "LOW",
            "finding_data": {"metadata": {"confidence_reason": "factory"}},
        },
    ]
    score = compute_agility(findings)
    assert score["total_sites"] == 2
    assert score["hardcoded_sites"] >= 1
    assert score["factory_sites"] >= 1
    assert 0 <= score["score"] <= 100
    empty = compute_agility([])
    assert empty["score"] == 100


def test_work_orders_group_des():
    findings = [
        {
            "evidence_id": "e1",
            "algorithm": "DES",
            "purpose": "ENCRYPTION",
            "compliance_status": "FAIL",
            "file_path": "A.java",
            "line_number": 10,
            "policy_evaluation": {
                "rules_evaluated": [{"rule_id": "BASELINE-001", "evaluation_result": "FAIL"}]
            },
        },
        {
            "evidence_id": "e2",
            "algorithm": "DES",
            "purpose": "ENCRYPTION",
            "compliance_status": "FAIL",
            "file_path": "B.java",
            "line_number": 4,
        },
        {
            "evidence_id": "e3",
            "algorithm": "AES",
            "purpose": "ENCRYPTION",
            "mode": "GCM",
            "compliance_status": "PASS",
        },
    ]
    orders = build_work_orders(findings)
    assert orders["total_orders"] == 1
    assert orders["total_sites"] == 2
    assert orders["orders"][0]["replacement"].startswith("AES-256-GCM")


def test_audit_zip_contains_verifier():
    blob = build_audit_zip(
        evidence_pack={"pack_format": "cryptoscan-evidence-pack", "records": []},
        gate={"decision": "PASS"},
    )
    assert blob[:2] == b"PK"
    import io
    import zipfile

    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        names = set(archive.namelist())
        assert "README.txt" in names
        assert "verify_pack.py" in names
        assert "evidence-pack.json" in names
        assert "gate.json" in names
