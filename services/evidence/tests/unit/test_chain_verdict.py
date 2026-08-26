from evidence.hashing.chain_hasher import ChainHasher
from evidence.verification.chain_verdict import verdict_for_records


def test_verdict_valid_and_broken():
    content = [
        "a" * 64,
        "b" * 64,
        "c" * 64,
    ]
    chain = ChainHasher.compute_chain(content, "scan-1")
    rows = [
        {"content_hash": content[i], "chain_hash": chain[i]}
        for i in range(3)
    ]
    ok = verdict_for_records(rows, "scan-1")
    assert ok["result"] == "VALID"
    assert ok["records"] == 3
    rows[1]["chain_hash"] = "d" * 64
    broken = verdict_for_records(rows, "scan-1")
    assert broken["result"] == "BROKEN_AT_SEQUENCE"
    assert broken["broken_at"] == 1
    invalid = verdict_for_records([{"content_hash": "short", "chain_hash": "x"}], "scan-1")
    assert invalid["result"] == "INVALID"
