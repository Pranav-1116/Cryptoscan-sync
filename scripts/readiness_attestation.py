"""Verify detached, site-bound readiness evidence without private keys.

A PASS-shaped JSON receipt is not proof it came from the bank or its assessor.
The operator supplies the trusted Ed25519 public key and site identifier; the
signer signs the canonical attestation body, which binds category, exact artifact
bytes, repository revision, site, and approval reference. This verifies origin
under that trust anchor, not the truth of the underlying observation.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SCHEMA = "cryptoscan.readiness-attestation/1"
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_ATTESTATION_BYTES = 64 * 1024


def verify_artifact(
    artifact: Path,
    attestation: Path,
    public_key: Path,
    *,
    category: str,
    repository_commit: str,
    site_id: str,
) -> dict[str, str]:
    """Return the verified binding, or raise ValueError without claiming PASS."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if not site_id or not repository_commit or len(repository_commit) != 40:
        raise ValueError("site ID and full repository commit are required")
    try:
        if artifact.is_symlink() or not artifact.is_file() or artifact.stat().st_size > MAX_ARTIFACT_BYTES:
            raise ValueError("evidence artifact missing, symlinked or above size budget")
        if attestation.is_symlink() or not attestation.is_file() or attestation.stat().st_size > MAX_ATTESTATION_BYTES:
            raise ValueError("attestation missing, symlinked or above size budget")
        if not public_key.is_file() or public_key.stat().st_size > 8192:
            raise ValueError("trusted public key missing or above size budget")
        repository = Path(__file__).resolve().parents[1]
        if public_key.resolve() == repository or repository in public_key.resolve().parents:
            raise ValueError("trusted public key must be supplied outside the source repository")
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        value: Any = json.loads(attestation.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("evidence or attestation unreadable") from exc
    if not isinstance(value, dict):
        raise ValueError("attestation must be an object")
    required = ("schema", "algorithm", "category", "artifact_sha256",
                "repository_commit", "site_id", "issued_at", "key_id",
                "issuer", "approval_ref", "signature")
    if set(value) != set(required) or value["schema"] != SCHEMA or value["algorithm"] != "Ed25519":
        raise ValueError("unsupported readiness attestation schema")
    if (value["category"] != category or value["artifact_sha256"] != digest
            or value["repository_commit"] != repository_commit
            or value["site_id"] != site_id):
        raise ValueError("attestation does not bind this site, revision, category and artifact")
    for field in ("key_id", "issuer", "approval_ref"):
        if not isinstance(value[field], str) or not value[field].strip():
            raise ValueError(f"attestation missing {field}")
    try:
        issued = datetime.fromisoformat(value["issued_at"].replace("Z", "+00:00"))
        if issued.tzinfo is None or issued > datetime.now(timezone.utc) + timedelta(minutes=5):
            raise ValueError("issued_at must be timezone-aware and not in the future")
        signature = base64.b64decode(value["signature"], validate=True)
        if len(signature) != 64:
            raise ValueError("invalid Ed25519 signature length")
        key = serialization.load_pem_public_key(public_key.read_bytes())
    except (AttributeError, TypeError, OSError, UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ValueError("attestation signature, time or public key invalid") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("trusted public key must be Ed25519")
    signed = {k: value[k] for k in required if k != "signature"}
    message = json.dumps(signed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    try:
        key.verify(signature, message)
    except InvalidSignature as exc:
        raise ValueError("readiness attestation signature invalid") from exc
    return {"artifact_sha256": digest, "issuer": value["issuer"],
            "approval_ref": value["approval_ref"], "issued_at": value["issued_at"],
            "key_id": value["key_id"], "site_id": site_id}
