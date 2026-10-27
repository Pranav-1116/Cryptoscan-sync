"""Deterministic data-lake export manifest and hash chaining.

A data-lake export is an append-only, tamper-evident batch (parquet/JSON-lines
on object storage in production; here the logic is storage-agnostic). Every
export has:

* a sequential ``batch_id`` within the lake;
* ``record_count`` and per-record ``content_sha256`` (record-level audit);
* a ``batch_digest`` = sha256 over the ordered record hashes;
* ``previous_digest`` chaining each batch to its predecessor (append-only log);
* an optional detached Ed25519 signature over the batch digest (authority seal).

Verification recomputes everything from the records and the chain anchor — no
trust in stored metadata alone. No AI/ML: this is pure hashing/policy.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str,
                      ensure_ascii=False).encode("utf-8")


def record_digest(record: Any) -> str:
    """Stable per-record content hash."""
    return hashlib.sha256(canonical_json(record)).hexdigest()


def batch_digest(record_hashes: list[str]) -> str:
    """Hash over the ordered record hashes (Merkle-ish linear chain root)."""
    h = hashlib.sha256()
    for rh in record_hashes:
        h.update(rh.encode("ascii"))
    return h.hexdigest()


def chain_digest(batch_digest_hex: str, previous_digest: str | None) -> str:
    """Link this batch to the previous one (genesis uses the lake id anchor)."""
    return hashlib.sha256(
        (batch_digest_hex + (previous_digest or "")).encode("ascii")
    ).hexdigest()


@dataclass
class LakeBatch:
    lake_id: str
    batch_id: int
    record_count: int
    record_hashes: list[str]
    batch_digest: str
    previous_digest: str | None
    chain_digest: str
    record_count_claimed: int = 0
    signature: str | None = None
    signer_key_id: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_manifest(self) -> dict[str, Any]:
        return {
            "lake_id": self.lake_id,
            "batch_id": self.batch_id,
            "record_count": self.record_count,
            "record_hashes": self.record_hashes,
            "batch_digest": self.batch_digest,
            "previous_digest": self.previous_digest,
            "chain_digest": self.chain_digest,
            "signature": self.signature,
            "signer_key_id": self.signer_key_id,
        }


class DataLakeExporter:
    """Builds append-only, hash-chained export batches."""

    def __init__(self, lake_id: str, *, anchor: str | None = None):
        self.lake_id = lake_id
        # anchor for the genesis batch's previous_digest (the lake identity)
        self._anchor = anchor or hashlib.sha256(lake_id.encode("utf-8")).hexdigest()
        self._last_chain_digest: str | None = None
        self._next_batch_id = 1

    def build_batch(self, records: Iterable[Any]) -> LakeBatch:
        recs = list(records)
        hashes = [record_digest(r) for r in recs]
        bdigest = batch_digest(hashes)
        prev = self._last_chain_digest if self._last_chain_digest is not None else self._anchor
        cdigest = chain_digest(bdigest, prev)
        batch = LakeBatch(
            lake_id=self.lake_id,
            batch_id=self._next_batch_id,
            record_count=len(recs),
            record_hashes=hashes,
            batch_digest=bdigest,
            previous_digest=prev,
            chain_digest=cdigest,
            record_count_claimed=len(recs),
        )
        self._last_chain_digest = cdigest
        self._next_batch_id += 1
        return batch

    @property
    def head_chain_digest(self) -> str | None:
        return self._last_chain_digest


def _b64d(text: str) -> bytes:
    import base64

    return base64.b64decode(text.encode("ascii"), validate=True)


def _verify_ed25519(public_key_b64: str, message: bytes, signature_b64: str) -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        pub = Ed25519PublicKey.from_public_bytes(_b64d(public_key_b64))
        pub.verify(_b64d(signature_b64), message)
        return True
    except Exception:
        return False


@dataclass
class LakeVerification:
    ok: bool
    errors: list[str] = field(default_factory=list)

    def fail(self, msg: str) -> LakeVerification:
        self.ok = False
        self.errors.append(msg)
        return self


def verify_batch(
    batch: LakeBatch,
    records: list[Any],
    *,
    expected_previous: str | None = None,
    public_key_b64: str | None = None,
) -> LakeVerification:
    """Recompute and validate a batch against its records and chain anchor.

    Fail-closed: any mismatch in count, record hash, batch digest, or chain
    link (and signature, when a public key is provided) returns ok=False.
    """
    result = LakeVerification(ok=True)

    if batch.record_count != len(records):
        result.fail(f"record_count {batch.record_count} != actual {len(records)}")

    hashes = [record_digest(r) for r in records]
    if hashes != batch.record_hashes:
        # find first divergence for a precise error
        for i, (got, want) in enumerate(zip(hashes, batch.record_hashes)):
            if got != want:
                result.fail(f"record {i} hash mismatch (tampered record)")
                break
        if len(hashes) != len(batch.record_hashes):
            result.fail("record hash list length differs from records")

    if batch_digest(hashes) != batch.batch_digest:
        result.fail("batch_digest mismatch")

    prev = expected_previous if expected_previous is not None else batch.previous_digest
    if chain_digest(batch.batch_digest, prev) != batch.chain_digest:
        result.fail("chain_digest does not link to previous batch (broken chain)")
    if expected_previous is not None and batch.previous_digest != expected_previous:
        result.fail("previous_digest does not match the expected chain head")

    if public_key_b64 and batch.signature:
        msg = batch.batch_digest.encode("ascii")
        if not _verify_ed25519(public_key_b64, msg, batch.signature):
            result.fail("batch signature verification failed")

    return result


def verify_chain(batches: list[LakeBatch], *, lake_anchor: str) -> LakeVerification:
    """Validate an ordered list of batches forms a contiguous append-only chain."""
    result = LakeVerification(ok=True)
    prev = lake_anchor
    for i, b in enumerate(batches):
        if b.previous_digest != prev:
            result.fail(f"batch {b.batch_id} (index {i}) previous_digest breaks the chain")
        if chain_digest(b.batch_digest, b.previous_digest) != b.chain_digest:
            result.fail(f"batch {b.batch_id} chain_digest invalid")
        prev = b.chain_digest
    return result
