"""Bank-side exporter capture authenticity boundary (no private keys here).

A signature binds the exact normalized JSON capture to tenant, canonical asset,
source, authorization reference and collection times. It proves the approved
signer asserted those bytes; it does not prove the exporter measured the bank.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

SCHEMA = "cryptoscan.performance-capture-attestation/1"


def payload_sha256(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True,
        separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()


def capture_binding(*, tenant_id: str, asset_ref: str, source_id: str,
                    source_type: str, observed_at: str,
                    previous_observed_at: str | None, authorization_ref: str,
                    payload_digest: str, previous_digest: str | None,
                    key_id: str | None, issuer: str | None) -> dict[str, Any]:
    return {"schema": SCHEMA, "algorithm": "Ed25519", "key_id": key_id,
            "issuer": issuer, "tenant_id": tenant_id, "asset_ref": asset_ref,
            "source_id": source_id, "source_type": source_type,
            "observed_at": observed_at,
            "previous_observed_at": previous_observed_at,
            "authorization_ref": authorization_ref,
            "payload_sha256": payload_digest,
            "previous_sha256": previous_digest}


def receipt_id(binding: Mapping[str, Any]) -> str:
    """Digest of exact signed context, not merely repeatable raw sample bytes."""
    return hashlib.sha256(json.dumps(binding, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()


def verify_capture_attestation(
    *, attestation: Mapping[str, Any], public_key_path: Path,
    tenant_id: str, asset_ref: str, source_id: str, source_type: str,
    observed_at: str, previous_observed_at: str | None,
    authorization_ref: str, payload_digest: str,
    previous_digest: str | None,
) -> dict[str, str]:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if not public_key_path.is_absolute() or public_key_path.is_symlink() \
            or not public_key_path.is_file() or public_key_path.stat().st_size > 8192:
        raise ValueError("bank capture trust anchor is missing or unsafe")
    repository = Path(__file__).resolve().parents[3]
    if repository == public_key_path.resolve() or repository in public_key_path.resolve().parents:
        raise ValueError("bank capture trust anchor must be outside the source repository")
    key_id, issuer = attestation.get("key_id"), attestation.get("issuer")
    if not isinstance(key_id, str) or not key_id.strip() \
            or not isinstance(issuer, str) or not issuer.strip():
        raise ValueError("capture signer and key ID are required")
    required = {"schema", "algorithm", "key_id", "issuer", "signature"}
    if set(attestation) != required or attestation.get("schema") != SCHEMA \
            or attestation.get("algorithm") != "Ed25519":
        raise ValueError("unsupported bank capture attestation")
    signed = capture_binding(
        tenant_id=tenant_id, asset_ref=asset_ref, source_id=source_id,
        source_type=source_type, observed_at=observed_at,
        previous_observed_at=previous_observed_at,
        authorization_ref=authorization_ref, payload_digest=payload_digest,
        previous_digest=previous_digest, key_id=key_id, issuer=issuer)
    try:
        signature = base64.b64decode(attestation["signature"], validate=True)
        if len(signature) != 64:
            raise ValueError("capture signature length invalid")
        key = serialization.load_pem_public_key(public_key_path.read_bytes())
    except (OSError, ValueError, TypeError, UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError("capture signature or bank public key invalid") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("bank capture public key must be Ed25519")
    message = json.dumps(signed, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    try:
        key.verify(signature, message)
    except InvalidSignature as exc:
        raise ValueError("bank capture signature does not bind this tenant, source and snapshot") from exc
    return {"key_id": key_id, "issuer": issuer, "payload_sha256": payload_digest}
