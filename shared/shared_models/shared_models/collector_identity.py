"""Approval-pinned Ed25519 handoff identity, NOT executable/host attestation.

No private keys, network key discovery or self-selected intake trust anchors.
"""

import base64
import json
from datetime import datetime
from pydantic import Field, field_validator
from shared_models.host_collection import Strict, Token, Digest, HostSnapshot, HostManifest, digest


def decode(value, size):
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise ValueError("Noncanonical base64") from None
    if len(data) != size or base64.b64encode(data).decode() != value:
        raise ValueError("Invalid encoded key/signature length")
    return data


class CollectorIdentityPolicy(Strict):
    key_id: Token
    public_key: str = Field(min_length=44, max_length=44)
    release_sha256: Digest

    @field_validator("public_key")
    @classmethod
    def key(cls, value):
        decode(value, 32)
        return value


class CollectorStatement(Strict):
    schema_version: str = Field(pattern=r"^cryptoscan.collector-statement/v1$")
    approval_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    nonce: Digest
    key_id: Token
    release_sha256: Digest
    host_id: Token
    manifest_sha256: Digest
    snapshot_sha256: Digest
    signed_at: datetime

    @field_validator("signed_at", mode="before")
    @classmethod
    def aware(cls, value):
        return HostManifest.aware(value)


class CollectorAttestation(Strict):
    statement: CollectorStatement
    signature: str = Field(min_length=88, max_length=88)

    @field_validator("signature")
    @classmethod
    def signature_bytes(cls, value):
        decode(value, 64)
        return value


def statement_bytes(statement):
    return json.dumps(
        statement.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def prepare_statement(snapshot, approval_id, nonce, policy, signed_at):
    return CollectorStatement(
        schema_version="cryptoscan.collector-statement/v1",
        approval_id=approval_id,
        nonce=nonce,
        key_id=policy.key_id,
        release_sha256=policy.release_sha256,
        host_id=snapshot.manifest.host_id,
        manifest_sha256=snapshot.manifest_sha256,
        snapshot_sha256=digest(snapshot),
        signed_at=signed_at,
    )


def verify_collector(
    policy: CollectorIdentityPolicy,
    proof: CollectorAttestation,
    snapshot: HostSnapshot,
    approval_id,
    nonce,
    earliest,
    latest,
):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    expected = prepare_statement(snapshot, approval_id, nonce, policy, proof.statement.signed_at)
    if (
        proof.statement != expected
        or not earliest <= snapshot.started_at <= snapshot.finished_at <= proof.statement.signed_at <= latest
        or proof.statement.signed_at >= snapshot.manifest.expires_at
    ):
        raise ValueError("Collector signature scope/time mismatch")
    try:
        Ed25519PublicKey.from_public_bytes(decode(policy.public_key, 32)).verify(
            decode(proof.signature, 64), statement_bytes(proof.statement)
        )
    except InvalidSignature:
        raise ValueError("Collector signature verification failed") from None
    return {
        "key_id": policy.key_id,
        "release_sha256": policy.release_sha256,
        "identity_basis": "APPROVAL_PINNED_SIGNING_KEY_NOT_HOST_ATTESTATION",
    }
