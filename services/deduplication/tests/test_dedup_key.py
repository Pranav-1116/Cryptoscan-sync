from deduplication.core.engine import DeduplicationEngine
from deduplication.core.keys import canonical_dedup_key, dedup_key


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
    # canonical mode (default): asset carries the registry-canonical key
    assets = DeduplicationEngine().merge([{"finding_id": "a", **finding, "scanner_id": "s"}])
    assert assets[0]["dedup_key"] == canonical_dedup_key(finding)
    assert assets[0]["dedup_key"] == assets[0]["dedup_key"]  # stable per asset
    # legacy raw identity is still available opt-in
    legacy = DeduplicationEngine().merge([{"finding_id": "a", **finding, "scanner_id": "s"}], canonical=False)
    assert legacy[0]["dedup_key"] == key
