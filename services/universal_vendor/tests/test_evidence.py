"""Evidence chain tests (spec §1 tamper-evident output)."""

from __future__ import annotations

from universal_vendor.evidence import (
    build_evidence_chain,
    content_hash,
    verify_evidence_chain,
)
from universal_vendor.models import UniversalObservation
from universal_vendor.normalizer import normalize_to_crypto


def _observations():
    return [
        {"vendor": "Cisco", "product": "IOS-XE", "algorithm": "AES-256-GCM",
         "asset_id": "r1"},
        {"vendor": "Palo Alto", "product": "PAN-OS", "algorithm": "ECDH",
         "asset_id": "fw1"},
        {"vendor": "F5", "product": "BIG-IP", "algorithm": "RSA", "key_size": 2048,
         "asset_id": "lb1"},
    ]


def test_chain_build_and_verify():
    records = build_evidence_chain(_observations(), scan_id="scan-1")
    assert len(records) == 3
    assert all(r["scan_id"] == "scan-1" for r in records)
    verification = verify_evidence_chain(records, scan_id="scan-1")
    assert verification["chain_intact"] is True
    assert verification["records"] == 3


def test_chain_detects_tampering():
    records = build_evidence_chain(_observations(), scan_id="scan-1")
    records[1]["observation"]["algorithm"] = "RC4"  # tamper
    verification = verify_evidence_chain(records, scan_id="scan-1")
    assert verification["chain_intact"] is False
    assert any("content_hash" in error for error in verification["errors"])


def test_chain_hash_links_positions():
    records = build_evidence_chain(_observations(), scan_id="scan-1")
    assert records[0]["previous_hash"] is None
    assert records[1]["previous_hash"] == records[0]["chain_hash"]
    assert records[2]["previous_hash"] == records[1]["chain_hash"]


def test_content_hash_deterministic():
    assert content_hash({"a": 1, "b": [2, 3]}) == content_hash({"b": [2, 3], "a": 1})


def test_normalizer_to_crypto_keeps_vendor_specific():
    obs = UniversalObservation(
        vendor="AWS", product="KMS", algorithm="SYMMETRIC_DEFAULT",
        key_size=256, asset_id="key/123",
        vendor_specific={"key_state": "Enabled", "rotation": "90d"},
    )
    crypto = normalize_to_crypto(obs)
    assert crypto.vendor == "AWS"
    assert crypto.key_size == 256
    assert crypto.vendor_specific["key_state"] == "Enabled"
    assert crypto.vendor_specific["rotation"] == "90d"
