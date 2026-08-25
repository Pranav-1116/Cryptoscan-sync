from deduplication.core.engine import DeduplicationEngine


def test_merges_same_location_across_scanners():
    findings = [
        {
            "finding_id": "a",
            "scanner_id": "static-python-scanner-v1.0",
            "source": {"file_path": "app.py", "line_number": 4, "language": "PYTHON"},
            "crypto": {"algorithm": "MD5", "purpose": "HASHING"},
            "metadata": {"confidence": "HIGH", "library": "hashlib"},
        },
        {
            "finding_id": "b",
            "scanner_id": "container-scanner-v1.0",
            "source": {"file_path": "app.py", "line_number": 4, "language": "PYTHON"},
            "crypto": {"algorithm": "MD5", "purpose": "HASHING"},
            "metadata": {"confidence": "MEDIUM", "library": "hashlib"},
        },
    ]
    assets = DeduplicationEngine().merge(findings)
    assert len(assets) == 1
    assert assets[0]["confidence"] == "VERIFIED"
    assert assets[0]["occurrence_count"] == 2
    assert set(assets[0]["evidence_ids"]) == {"a", "b"}
    roles = {row["evidence_id"]: row["role"] for row in assets[0]["members"]}
    assert roles["a"] == "PRIMARY"
    assert roles["b"] == "SUPPORTING"
    assert assets[0]["primary_evidence_id"] == "a"
