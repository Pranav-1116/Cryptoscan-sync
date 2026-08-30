"""ZELNX scan modes (§23) + evidence chain (§22)."""

from __future__ import annotations

import pytest

from cloud_scanner.enterprise.evidence import (
    EvidenceChain,
    canonical_json,
    evidence_block,
    sha256,
)
from cloud_scanner.enterprise.scan_modes import (
    DEFAULT_MODES,
    SCAN_MODES,
    CloudScanMode,
    describe,
    is_read_only,
    requires_deep,
    requires_events,
    validate_modes,
)


# ------------------------------------------------------------------ §23 modes


def test_default_enterprise_mode_is_inventory_plus_crypto():
    assert DEFAULT_MODES == {CloudScanMode.INVENTORY_ONLY, CloudScanMode.CRYPTO_DISCOVERY}


def test_all_five_modes_are_registered():
    assert SCAN_MODES == {
        "INVENTORY_ONLY", "CRYPTO_DISCOVERY", "DEEP_CRYPTO_DISCOVERY",
        "CONTINUOUS_MONITORING", "EVENT_DRIVEN",
    }


def test_validate_modes_accepts_any_case_and_dedups():
    modes = validate_modes(["inventory_only", "CRYPTO_DISCOVERY", "crypto_discovery"])
    assert modes == {CloudScanMode.INVENTORY_ONLY, CloudScanMode.CRYPTO_DISCOVERY}


def test_validate_modes_defaults_when_empty():
    assert validate_modes(None) == set(DEFAULT_MODES)
    assert validate_modes([]) == set(DEFAULT_MODES)


def test_validate_modes_rejects_unknown_mode():
    with pytest.raises(ValueError):
        validate_modes(["INVENTORY_ONLY", "PERPETUAL_SCAN"])


def test_all_modes_are_read_only():
    for mode in CloudScanMode:
        assert is_read_only({mode}) is True


def test_deep_and_event_requirement_flags():
    assert requires_deep({CloudScanMode.DEEP_CRYPTO_DISCOVERY}) is True
    assert requires_deep({CloudScanMode.INVENTORY_ONLY}) is False
    assert requires_events({CloudScanMode.EVENT_DRIVEN}) is True
    assert requires_events({CloudScanMode.CRYPTO_DISCOVERY}) is False


def test_describe_includes_read_only_note():
    info = describe({CloudScanMode.INVENTORY_ONLY})
    assert info["read_only"] is True
    assert info["default"] == ["CRYPTO_DISCOVERY", "INVENTORY_ONLY"]
    assert "read-only" in str(info["note"]).lower()


# ------------------------------------------------------------------ §22 evidence


def test_canonical_json_is_sorted_and_compact():
    a = canonical_json({"b": 1, "a": 2})
    b = canonical_json({"a": 2, "b": 1})
    assert a == b == '{"a":2,"b":1}'


def test_evidence_block_carries_provenance():
    block = evidence_block(source_provider="aws", api_source="kms:list",
                           account="111", confidence="MEASURED")
    assert block.source_provider == "aws"
    assert block.account == "111"
    assert block.api_source == "kms:list"
    assert block.normalization_version == "zelix-1.0"
    assert block.confidence == "MEASURED"
    assert block.timestamp  # isoformat


def test_chain_links_content_and_previous_hashes():
    chain = EvidenceChain()
    record1 = chain.append({"kind": "key", "resource": "k1", "algorithm": "AES"})
    record2 = chain.append({"kind": "cert", "resource": "c1"})
    assert record1.sequence == 1
    assert record1.previous_chain_hash == "genesis"
    assert record1.content_hash == sha256(record1.canonical)
    assert record1.chain_hash == sha256(f"genesis|{record1.content_hash}")
    assert record2.previous_chain_hash == record1.chain_hash
    assert chain.head == record2.chain_hash


def test_chain_verifies():
    chain = EvidenceChain()
    for i in range(5):
        chain.append({"sequence": i, "payload": f"value-{i}"})
    assert chain.verify() is True
    assert len(chain) == 5


def test_chain_detects_tampered_observation():
    chain = EvidenceChain()
    chain.append({"kind": "key", "resource": "k1"})
    record = chain.append({"kind": "cert", "resource": "c1"})
    chain.append({"kind": "tls", "resource": "e1"})
    # tamper with the stored observation
    chain._records[1].observation["resource"] = "c1-tampered"
    assert chain.verify() is False


def test_chain_detects_reordering():
    chain = EvidenceChain()
    chain.append({"kind": "a"})
    chain.append({"kind": "b"})
    # swap records — previous_chain_hash links break
    chain._records[0], chain._records[1] = chain._records[1], chain._records[0]
    assert chain.verify() is False


def test_chain_verify_from_anchor():
    chain = EvidenceChain()
    for i in range(4):
        chain.append({"i": i})
    assert chain.verify_from(2) is True
    chain._records[2].observation["i"] = 99
    assert chain.verify_from(2) is False


def test_chain_tail_returns_last_n():
    chain = EvidenceChain()
    for i in range(10):
        chain.append({"i": i})
    tail = chain.tail(3)
    assert [record["sequence"] for record in tail] == [8, 9, 10]


def test_evidence_hashes_are_deterministic():
    chain_a = EvidenceChain()
    chain_b = EvidenceChain()
    record_a = chain_a.append({"kind": "key", "resource": "k1", "algorithm": "AES"})
    record_b = chain_b.append({"kind": "key", "algorithm": "AES", "resource": "k1"})
    assert record_a.content_hash == record_b.content_hash
    assert record_a.chain_hash == record_b.chain_hash


def test_evidence_chain_head_starts_at_genesis():
    chain = EvidenceChain()
    assert chain.head == "genesis"
    assert chain.verify() is True
    assert chain.tail(3) == []
