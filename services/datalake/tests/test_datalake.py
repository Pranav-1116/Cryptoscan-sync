"""Data-lake hash-chaining and tamper-detection tests."""

from __future__ import annotations

import base64

import pytest
from datalake.manifest import (
    DataLakeExporter,
    batch_digest,
    record_digest,
    verify_batch,
    verify_chain,
)

pytest.importorskip("cryptography", reason="seal test needs cryptography")
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,  # noqa: E402
)


def _records(n=3):
    return [
        {"finding_id": f"f{i}", "algorithm": "DES" if i % 2 else "AES", "severity": "high"}
        for i in range(n)
    ]


def test_batches_chain_sequentially():
    ex = DataLakeExporter("lake-1")
    anchor = ex._anchor
    b1 = ex.build_batch(_records(3))
    b2 = ex.build_batch(_records(2))
    assert b1.batch_id == 1 and b2.batch_id == 2
    assert b1.previous_digest == anchor
    assert b2.previous_digest == b1.chain_digest
    assert verify_chain([b1, b2], lake_anchor=anchor).ok is True


def test_verify_batch_passes_on_clean_data():
    ex = DataLakeExporter("lake-1")
    recs = _records()
    b = ex.build_batch(recs)
    res = verify_batch(b, recs, expected_previous=ex._anchor)
    assert res.ok is True


def test_tampered_record_detected():
    ex = DataLakeExporter("lake-1")
    recs = _records()
    b = ex.build_batch(recs)
    recs[1]["algorithm"] = "RSA"  # mutate after export
    res = verify_batch(b, recs)
    assert res.ok is False
    assert any("tampered record" in e for e in res.errors)


def test_missing_record_count_detected():
    ex = DataLakeExporter("lake-1")
    b = ex.build_batch(_records(3))
    res = verify_batch(b, _records(2))  # one record dropped
    assert res.ok is False
    assert any("record_count" in e for e in res.errors)


def test_broken_chain_link_detected():
    ex = DataLakeExporter("lake-1")
    ex.build_batch(_records(2))  # predecessor batch
    b2 = ex.build_batch(_records(2))
    # pretend b2 chained off a bogus predecessor
    res = verify_batch(b2, _records(2), expected_previous="deadbeef" * 8)
    assert res.ok is False
    assert any("chain" in e for e in res.errors)


def test_deterministic_digests_stable():
    recs = _records(2)
    assert record_digest(recs[0]) == record_digest(dict(recs[0]))
    assert len(batch_digest([record_digest(r) for r in recs])) == 64


def test_signed_seal_verifies_and_tamper_fails():
    priv = Ed25519PrivateKey.generate()
    pub = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    ex = DataLakeExporter("lake-1")
    recs = _records()
    b = ex.build_batch(recs)
    b.signature = base64.b64encode(priv.sign(b.batch_digest.encode("ascii"))).decode()
    assert verify_batch(b, recs, expected_previous=ex._anchor, public_key_b64=pub).ok is True
    b.batch_digest = "0" * 64  # tamper the sealed digest
    res = verify_batch(b, recs, expected_previous=ex._anchor, public_key_b64=pub)
    assert res.ok is False
    assert any("signature verification failed" in e for e in res.errors)
