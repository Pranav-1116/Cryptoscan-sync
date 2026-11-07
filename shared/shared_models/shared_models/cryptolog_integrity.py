"""CryptoLog layered integrity architecture (docs/cryptolog/01_PRODUCT_SPEC.md,
Phase 3): event hash, partitioned hash chain, Merkle batches, signed
checkpoints and independent checkpoint retention.

Five layers, each proving one thing:

1. **Event hash** — every event gets a canonical hash (Phase 1
   ``event_hash``). Deterministic serialization: fixed schema, stable field
   ordering, explicit null handling.
2. **Partitioned hash chain** — ``Chain_i = SHA256(Chain_{i-1} || H_i)`` over
   a defined partition (tenant and time window). Detects changes, deletions
   and reordering within the verified chain.
3. **Merkle tree** — periodic roots over batches of event hashes, so any
   single event can be proven member of a committed batch.
4. **Signed checkpoints** — the Merkle root and checkpoint metadata signed
   with a protected signing key (the bank's HSM or approved KMS in
   production; the module takes the signer as a callable and never holds
   keys).
5. **Independent checkpoint retention** — checkpoints name their retention
   location outside the event store: an attacker who controls both the event
   database and its only checkpoint store could rewrite both.

The honesty rule that governs every result here:

    "Do not claim that a hash chain proves the event itself is true. It
    proves integrity relative to the trusted checkpoint and recorded
    provenance. The original observation still needs source validation."

Verification states (the complete vocabulary, nothing else):
VERIFIED, UNVERIFIED, INVALID_HASH, CHAIN_BROKEN, SIGNATURE_INVALID,
CHECKPOINT_MISSING, ARTIFACT_MISSING.
"""

from __future__ import annotations

import hashlib
import hmac

from shared_models.cryptolog_events import event_hash as _event_hash
from typing import Any, Callable, Iterable, Mapping, Sequence

CHAIN_SCHEMA = "cryptoscan.cryptolog-chain/1"
MERKLE_SCHEMA = "cryptoscan.cryptolog-merkle/1"
CHECKPOINT_SCHEMA = "cryptoscan.cryptolog-checkpoint/1"

VERIFIED = "VERIFIED"
UNVERIFIED = "UNVERIFIED"
INVALID_HASH = "INVALID_HASH"
CHAIN_BROKEN = "CHAIN_BROKEN"
SIGNATURE_INVALID = "SIGNATURE_INVALID"
CHECKPOINT_MISSING = "CHECKPOINT_MISSING"
ARTIFACT_MISSING = "ARTIFACT_MISSING"

VERIFICATION_STATES: tuple[str, ...] = (
    VERIFIED, UNVERIFIED, INVALID_HASH, CHAIN_BROKEN, SIGNATURE_INVALID,
    CHECKPOINT_MISSING, ARTIFACT_MISSING)

_HONESTY_NOTE = (
    "a hash chain proves integrity relative to the trusted checkpoint and "
    "recorded provenance, not that the event itself is true: the original "
    "observation still needs source validation")


def _sha(*parts: bytes) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.hexdigest()


def _clean(value: Any) -> str:
    return str(value or "").strip()


# ---- Layer 2: partitioned hash chain --------------------------------------

def chain_genesis(partition_id: str) -> str:
    """Chain_0 for a partition: bound to the schema and the partition id so
    chains from different partitions can never validate against each other."""
    part = _clean(partition_id)
    if not part:
        raise ValueError("partition_id is mandatory: a chain is ordered "
                         "within a defined partition")
    return _sha(f"{CHAIN_SCHEMA}|genesis|{part}".encode("utf-8"))


def chain_append(previous_chain_hash: str, event_hash: str) -> str:
    """Chain_i = SHA256(Chain_{i-1} || H_i)."""
    prev = _clean(previous_chain_hash)
    current = _clean(event_hash)
    if not prev or not current:
        raise ValueError("a chain link needs both the previous chain hash "
                         "and the event hash")
    return _sha(prev.encode("utf-8"), current.encode("utf-8"))


def build_chain(partition_id: str,
                event_hashes: Sequence[str]) -> list[str]:
    """Chain hashes for an ordered batch of event hashes in one partition."""
    chain = chain_genesis(partition_id)
    out = []
    for h in event_hashes:
        chain = chain_append(chain, h)
        out.append(chain)
    return out


# ---- Layer 3: Merkle batches ----------------------------------------------

_EMPTY_ROOT = _sha(f"{MERKLE_SCHEMA}|EMPTY".encode("utf-8"))


def merkle_root(leaf_hashes: Sequence[str]) -> str:
    """Root over a batch of event hashes.

    Deterministic pairing; an odd node at any level is paired with itself
    (last-pair duplication), so the root depends only on the ordered leaves.
    An empty batch has a defined root, never a blank string.
    """
    level = [_clean(h) for h in leaf_hashes]
    for h in level:
        if not h:
            raise ValueError("a Merkle leaf is a non-empty event hash")
    if not level:
        return _EMPTY_ROOT
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(_sha(left.encode("utf-8"), right.encode("utf-8")))
        level = nxt
    return level[0]


def merkle_proof(leaf_hashes: Sequence[str], index: int) -> list[dict[str, str]]:
    """Sibling path proving ``leaf_hashes[index]`` belongs to the batch.
    Each step records the sibling hash and whether it sits right or left."""
    level = [_clean(h) for h in leaf_hashes]
    if not 0 <= index < len(level):
        raise ValueError(f"leaf index {index} outside the batch of "
                         f"{len(level)}")
    proof: list[dict[str, str]] = []
    position = index
    while len(level) > 1:
        is_right = position % 2 == 1
        sibling_index = position - 1 if is_right else position + 1
        sibling = level[sibling_index] if sibling_index < len(level) \
            else level[position]
        proof.append({"hash": sibling,
                      "side": "left" if is_right else "right"})
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(_sha(left.encode("utf-8"), right.encode("utf-8")))
        level = nxt
        position //= 2
    return proof


def verify_merkle_proof(leaf_hash: str, proof: Sequence[Mapping[str, str]],
                        root: str) -> bool:
    """True when the leaf and its sibling path fold to ``root``."""
    node = _clean(leaf_hash)
    for step in proof:
        sibling = _clean(step.get("hash"))
        if str(step.get("side")) == "left":
            node = _sha(sibling.encode("utf-8"), node.encode("utf-8"))
        else:
            node = _sha(node.encode("utf-8"), sibling.encode("utf-8"))
    return hmac.compare_digest(node, _clean(root))


# ---- Layer 4: signed checkpoints ------------------------------------------

def checkpoint_payload(*, partition_id: str, sequence: int,
                       chain_hash: str, merkle_root_hash: str,
                       event_count: int, created_at: str,
                       retention_ref: str) -> bytes:
    """The exact bytes a checkpoint signature binds. Deterministic, so the
    same checkpoint verifies identically wherever it is retained."""
    parts = (
        f"{CHECKPOINT_SCHEMA}|partition={_clean(partition_id)}"
        f"|sequence={int(sequence)}|chain={_clean(chain_hash)}"
        f"|merkle={_clean(merkle_root_hash)}|events={int(event_count)}"
        f"|created={_clean(created_at)}|retention={_clean(retention_ref)}"
    )
    return parts.encode("utf-8")


def make_checkpoint(*, partition_id: str, sequence: int, chain_hash: str,
                    merkle_root_hash: str, event_count: int, created_at: str,
                    retention_ref: str, signer_id: str,
                    sign: Callable[[bytes], str]) -> dict[str, Any]:
    """Build and sign a checkpoint.

    ``sign`` is the protected signer (the bank's HSM or approved KMS in
    production); this module never holds keys. ``retention_ref`` names the
    INDEPENDENT retention location (Layer 5): a checkpoint kept only beside
    the event store proves nothing against whoever can rewrite both.
    """
    if not _clean(signer_id):
        raise ValueError("signer_id is mandatory: a checkpoint names its "
                         "signer")
    if not _clean(retention_ref):
        raise ValueError(
            "retention_ref is mandatory: keep signed checkpoints in a "
            "separate protected location — an attacker who controls both the "
            "event database and its only checkpoint store could rewrite both")
    if not _clean(chain_hash) or not _clean(merkle_root_hash):
        raise ValueError("a checkpoint binds its chain hash and Merkle root")
    if int(sequence) < 0:
        raise ValueError("checkpoint sequence starts at 0")
    payload = checkpoint_payload(
        partition_id=partition_id, sequence=sequence, chain_hash=chain_hash,
        merkle_root_hash=merkle_root_hash, event_count=event_count,
        created_at=created_at, retention_ref=retention_ref)
    signature = str(sign(payload) or "")
    if not signature:
        raise ValueError("the signer returned no signature: an unsigned "
                         "checkpoint is not a checkpoint")
    return {
        "schema": CHECKPOINT_SCHEMA,
        "partition_id": _clean(partition_id),
        "sequence": int(sequence),
        "chain_hash": _clean(chain_hash),
        "merkle_root_hash": _clean(merkle_root_hash),
        "event_count": int(event_count),
        "created_at": _clean(created_at),
        "retention_ref": _clean(retention_ref),
        "signer_id": _clean(signer_id),
        "signature": signature,
    }


def verify_checkpoint(checkpoint: Mapping[str, Any],
                      verify: Callable[[str, bytes], bool]) -> bool:
    """True when the signature covers the checkpoint's exact payload."""
    payload = checkpoint_payload(
        partition_id=str(checkpoint.get("partition_id") or ""),
        sequence=int(checkpoint.get("sequence") or 0),
        chain_hash=str(checkpoint.get("chain_hash") or ""),
        merkle_root_hash=str(checkpoint.get("merkle_root_hash") or ""),
        event_count=int(checkpoint.get("event_count") or 0),
        created_at=str(checkpoint.get("created_at") or ""),
        retention_ref=str(checkpoint.get("retention_ref") or ""))
    return bool(verify(str(checkpoint.get("signature") or ""), payload))


# ---- verification over a range -------------------------------------------

def verify_range(*, partition_id: str,
                 entries: Sequence[Mapping[str, Any]],
                 events_by_id: Mapping[str, Mapping[str, Any]],
                 checkpoint: Mapping[str, Any] | None,
                 verify: Callable[[str, bytes], bool] | None = None
                 ) -> dict[str, Any]:
    """Verify an ordered range of chain entries against their events and the
    covering checkpoint.

    ``entries`` is the recorded chain (event_id, event_hash, chain_hash in
    order). ``events_by_id`` is the preserved event store. Every failure maps
    to exactly one verification state; nothing here upgrades UNVERIFIED to
    VERIFIED without a checkpoint whose signature checks out.
    """
    if not _clean(partition_id):
        raise ValueError("partition_id is mandatory")
    results: list[dict[str, Any]] = []
    previous = chain_genesis(partition_id)
    chain_ok = True
    for entry in entries:
        event_id = str(entry.get("event_id") or "")
        recorded_hash = _clean(entry.get("event_hash"))
        recorded_chain = _clean(entry.get("chain_hash"))
        event = events_by_id.get(event_id)
        if event is None:
            state = ARTIFACT_MISSING
            note = "the recorded event artifact is missing from the store"
        elif not hmac.compare_digest(_event_hash(event), recorded_hash):
            state = INVALID_HASH
            note = "the stored event does not hash to its recorded hash"
        elif not chain_ok:
            state = CHAIN_BROKEN
            note = "an earlier link broke this chain"
        elif not hmac.compare_digest(
                chain_append(previous, recorded_hash), recorded_chain):
            state = CHAIN_BROKEN
            note = "the recorded chain hash does not follow from the " \
                   "previous link and this event hash"
        else:
            state = UNVERIFIED
            note = "hashes and chain are consistent; awaiting a trusted " \
                   "checkpoint"
        if state != UNVERIFIED:
            chain_ok = False
        previous = recorded_chain or previous
        results.append({"event_id": event_id, "state": state, "note": note})

    overall: str
    if checkpoint is None:
        overall = CHECKPOINT_MISSING
        overall_note = ("no signed checkpoint covers this range: a chain "
                        "without a trusted checkpoint is UNVERIFIED, never "
                        "VERIFIED")
        for row in results:
            if row["state"] == UNVERIFIED:
                row["state"] = CHECKPOINT_MISSING
                row["note"] = overall_note
    elif verify is None or not verify_checkpoint(checkpoint, verify):
        overall = SIGNATURE_INVALID
        overall_note = "the covering checkpoint's signature does not verify"
        for row in results:
            if row["state"] == UNVERIFIED:
                row["state"] = SIGNATURE_INVALID
                row["note"] = overall_note
    else:
        bad = [row for row in results if row["state"] != UNVERIFIED
               and row["state"] != VERIFIED]
        if bad:
            overall = bad[0]["state"]
            overall_note = bad[0]["note"]
        elif results:
            overall = VERIFIED
            overall_note = _HONESTY_NOTE
            for row in results:
                row["state"] = VERIFIED
                row["note"] = _HONESTY_NOTE
        else:
            overall = UNVERIFIED
            overall_note = ("an empty range verifies nothing: UNVERIFIED, "
                            "never VERIFIED")
    return {
        "schema": CHAIN_SCHEMA,
        "partition_id": _clean(partition_id),
        "results": results,
        "overall_state": overall,
        "note": overall_note,
        "checkpoint_used": bool(checkpoint),
    }
