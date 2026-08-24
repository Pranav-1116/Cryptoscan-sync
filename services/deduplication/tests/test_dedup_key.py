from deduplication.core.engine import DeduplicationEngine
from deduplication.core.keys import dedup_key


def test_dedup_key_is_stable_sha256():
    finding = {
        "algorithm": "MD5",
        "purpose": "HASHING",
        "file_path": "app.py",
        "line_number": 4,
    }
    key = dedup_key(finding)
    assert len(key) == 64
    assert key == dedup_key({"crypto": {"algorithm": "md5", "purpose": "hashing"}, "source": {"file_path": "app.py", "line_number": 4}})
    assets = DeduplicationEngine().merge([{"finding_id": "a", **finding, "scanner_id": "s"}])
    assert assets[0]["dedup_key"] == key
