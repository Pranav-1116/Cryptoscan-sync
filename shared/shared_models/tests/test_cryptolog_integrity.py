"""CryptoLog layered integrity tests (docs/cryptolog/01_PRODUCT_SPEC.md,
Phase 3).

Five layers: canonical event hash, partitioned hash chain, Merkle batches,
signed checkpoints, independent checkpoint retention. The governing honesty
rule: a hash chain proves integrity relative to the trusted checkpoint — not
that the event itself is true."""

from __future__ import annotations

import hashlib
import hmac as _hmac

import pytest

from shared_models.cryptolog_events import event_hash, make_event
from shared_models.cryptolog_integrity import (
    ARTIFACT_MISSING, CHAIN_BROKEN, CHECKPOINT_MISSING, INVALID_HASH,
    SIGNATURE_INVALID, UNVERIFIED, VERIFIED, VERIFICATION_STATES,
    build_chain, chain_append, chain_genesis, make_checkpoint, merkle_proof,
    merkle_root, verify_checkpoint, verify_merkle_proof, verify_range,
)

AS_OF = "2026-11-07T04:00:00Z"
PARTITION = "tenant_001:2026-11"


def _event(asset="asset_gateway_001", severity="INFO", ev="ev-1", **over):
    base = dict(event_type="TLS_NEGOTIATION_OBSERVED", category="TLS",
                logging_kind="ACTIVITY", tenant_id="tenant_001",
                severity=severity, asset_id=asset,
                source={"collector_id": "c1", "collector_version": "1",
                        "source_type": "NETWORK_OBSERVATION"},
                cryptographic_context={"protocol": "TLS",
                                       "protocol_version": "TLS1.3",
                                       "evidence_level": "NETWORK_NEGOTIATED"},
                observed_at=AS_OF, evidence_ids=[ev], **over)
    return make_event(**base)


def _key():
    """An HMAC signer/verifier pair standing in for the protected signer."""
    key = hashlib.sha256(b"test-signing-key").digest()

    def sign(payload: bytes) -> str:
        return _hmac.new(key, payload, hashlib.sha256).hexdigest()

    def verify(signature: str, payload: bytes) -> bool:
        return _hmac.compare_digest(
            signature, _hmac.new(key, payload, hashlib.sha256).hexdigest())

    return sign, verify


def _entries(partition, events):
    hashes = [event_hash(e) for e in events]
    chains = build_chain(partition, hashes)
    return [{"event_id": e["event_id"], "event_hash": h, "chain_hash": c}
            for e, h, c in zip(events, hashes, chains)]


def test_chain_is_bound_to_its_partition_and_deterministic():
    assert chain_genesis(PARTITION) != chain_genesis("tenant_002:2026-11")
    with pytest.raises(ValueError):
        chain_genesis("")
    hashes = [event_hash(_event(ev="a")), event_hash(_event(ev="b"))]
    assert build_chain(PARTITION, hashes) == build_chain(PARTITION, hashes)
    assert build_chain(PARTITION, hashes)[-1] == chain_append(
        build_chain(PARTITION, hashes)[0], hashes[1])


def test_chain_detects_tampering_deletion_and_reordering():
    events = [_event(ev="a", asset="asset-1"),
              _event(ev="b", asset="asset-2"),
              _event(ev="c", asset="asset-3")]
    entries = _entries(PARTITION, events)
    store = {e["event_id"]: e for e in events}

    # intact range awaits its checkpoint
    clean = verify_range(partition_id=PARTITION, entries=entries,
                         events_by_id=store, checkpoint=None)
    assert clean["overall_state"] == CHECKPOINT_MISSING

    # one edited event is INVALID_HASH at its position
    tampered = dict(store)
    victim = events[1]
    edited = dict(victim)
    edited["severity"] = "HIGH"
    tampered[victim["event_id"]] = edited
    res = verify_range(partition_id=PARTITION, entries=entries,
                       events_by_id=tampered, checkpoint=None)
    states = [r["state"] for r in res["results"]]
    assert states[1] == INVALID_HASH

    # a deleted entry breaks the chain at the gap
    shortened = [entries[0], entries[2]]
    res = verify_range(partition_id=PARTITION, entries=shortened,
                       events_by_id=store, checkpoint=None)
    assert res["results"][1]["state"] == CHAIN_BROKEN

    # reordered entries break the chain where the order changes
    swapped = [entries[1], entries[0], entries[2]]
    res = verify_range(partition_id=PARTITION, entries=swapped,
                       events_by_id=store, checkpoint=None)
    assert res["results"][0]["state"] == CHAIN_BROKEN


def test_a_missing_artifact_is_artifact_missing_never_an_invented_row():
    events = [_event(ev="a")]
    entries = _entries(PARTITION, events)
    res = verify_range(partition_id=PARTITION, entries=entries,
                       events_by_id={}, checkpoint=None)
    assert res["results"][0]["state"] == ARTIFACT_MISSING
    assert "missing from the store" in res["results"][0]["note"]


def test_merkle_root_is_deterministic_and_proofs_verify_per_leaf():
    leaves = [event_hash(_event(ev="a")), event_hash(_event(ev="b")),
              event_hash(_event(ev="c"))]
    root = merkle_root(leaves)
    assert root == merkle_root(leaves)
    assert root != merkle_root(list(reversed(leaves)))
    for index in range(len(leaves)):
        proof = merkle_proof(leaves, index)
        assert verify_merkle_proof(leaves[index], proof, root)
    assert not verify_merkle_proof(leaves[0], merkle_proof(leaves, 1), root)


def test_a_checkpoint_binds_its_payload_and_names_independent_retention():
    sign, verify = _key()
    leaves = [event_hash(_event(ev="a")), event_hash(_event(ev="b"))]
    chains = build_chain(PARTITION, leaves)
    with pytest.raises(ValueError):
        make_checkpoint(partition_id=PARTITION, sequence=0,
                        chain_hash=chains[-1], merkle_root_hash=merkle_root(leaves),
                        event_count=2, created_at=AS_OF, retention_ref="",
                        signer_id="hsm-04", sign=sign)
    with pytest.raises(ValueError):
        make_checkpoint(partition_id=PARTITION, sequence=0,
                        chain_hash=chains[-1], merkle_root_hash=merkle_root(leaves),
                        event_count=2, created_at=AS_OF,
                        retention_ref="worm://checkpoints", signer_id="",
                        sign=sign)
    checkpoint = make_checkpoint(
        partition_id=PARTITION, sequence=0, chain_hash=chains[-1],
        merkle_root_hash=merkle_root(leaves), event_count=2,
        created_at=AS_OF, retention_ref="worm://checkpoints",
        signer_id="hsm-04", sign=sign)
    assert verify_checkpoint(checkpoint, verify)

    def wrong_key(signature, payload):
        return False

    assert not verify_checkpoint(checkpoint, wrong_key)


def test_verified_needs_a_checkpoint_that_verifies():
    sign, verify = _key()
    events = [_event(ev="a", asset="asset-1"), _event(ev="b", asset="asset-2")]
    entries = _entries(PARTITION, events)
    store = {e["event_id"]: e for e in events}
    leaves = [row["event_hash"] for row in entries]
    checkpoint = make_checkpoint(
        partition_id=PARTITION, sequence=0, chain_hash=entries[-1]["chain_hash"],
        merkle_root_hash=merkle_root(leaves), event_count=2,
        created_at=AS_OF, retention_ref="worm://checkpoints",
        signer_id="hsm-04", sign=sign)

    res = verify_range(partition_id=PARTITION, entries=entries,
                       events_by_id=store, checkpoint=checkpoint,
                       verify=verify)
    assert res["overall_state"] == VERIFIED
    assert all(r["state"] == VERIFIED for r in res["results"])
    assert "not that the event itself is true" in res["note"]

    # a forged checkpoint never verifies the range
    forged = dict(checkpoint)
    forged["signature"] = "00" * 32
    res = verify_range(partition_id=PARTITION, entries=entries,
                       events_by_id=store, checkpoint=forged, verify=verify)
    assert res["overall_state"] == SIGNATURE_INVALID

    # an empty range verifies nothing
    res = verify_range(partition_id=PARTITION, entries=[],
                       events_by_id=store, checkpoint=checkpoint,
                       verify=verify)
    assert res["overall_state"] == UNVERIFIED
    assert "UNVERIFIED, never VERIFIED" in res["note"]


def test_the_state_vocabulary_is_complete():
    assert set(VERIFICATION_STATES) == {
        VERIFIED, UNVERIFIED, INVALID_HASH, CHAIN_BROKEN, SIGNATURE_INVALID,
        CHECKPOINT_MISSING, ARTIFACT_MISSING}
