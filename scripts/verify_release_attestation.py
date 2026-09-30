#!/usr/bin/env python3
"""Verify a signed release-image lock without handling private key material.

The image renderer creates an immutable ``release-image-lock.json``. This
verifier is the next trust boundary: an external release signer (ideally an
HSM-backed or CI-protected signer) produces a detached Ed25519 attestation,
and the deployment/release gate verifies it against an operator-supplied
trusted public key.

The verifier does not generate keys, accept private keys, fetch keys from the
network, or treat a digest alone as approval. The attestation signs the exact
lock bytes and records their SHA-256, so changing a digest, registry, source
hash, or render timestamp invalidates the signature.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

SCHEMA = "cryptoscan.release-attestation/1"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not readable JSON: {type(exc).__name__}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return value


def _decode_signature(value: Any) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("attestation signature must be a non-empty base64 string")
    try:
        signature = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError("attestation signature is not strict base64") from exc
    if len(signature) != 64:
        raise ValueError("Ed25519 signatures must decode to exactly 64 bytes")
    return signature


def verify_attestation(
    release_manifests: Path,
    public_key_path: Path,
    attestation_path: Path,
) -> dict[str, Any]:
    """Verify an attestation and return a non-secret machine-readable report."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:  # pragma: no cover - dependency is in requirements.txt
        raise ValueError("cryptography is required to verify release attestations") from exc

    root = release_manifests.resolve()
    if not root.is_dir():
        raise ValueError(f"release manifest directory does not exist: {release_manifests}")
    lock_path = root / "release-image-lock.json"
    if not lock_path.is_file():
        raise ValueError(f"release image lock is missing: {lock_path}")

    lock_bytes = lock_path.read_bytes()
    lock = _load_json(lock_path, "release-image-lock.json")
    if lock.get("schema") != "cryptoscan.immutable-image-release/1":
        raise ValueError("release image lock has an unsupported schema")
    digests = lock.get("digests")
    if not isinstance(digests, dict) or set(("api", "worker", "neo4j")) - digests.keys():
        raise ValueError("release image lock must contain api, worker and neo4j digests")
    for name in ("api", "worker", "neo4j"):
        digest = digests[name]
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest.lower()):
            raise ValueError(f"release image lock contains an invalid {name} digest")

    attestation = _load_json(attestation_path, "release attestation")
    if attestation.get("schema") != SCHEMA:
        raise ValueError("release attestation has an unsupported schema")
    if attestation.get("algorithm") != "Ed25519":
        raise ValueError("release attestation algorithm must be Ed25519")
    if attestation.get("signed_file") != "release-image-lock.json":
        raise ValueError("release attestation must sign release-image-lock.json")
    if not isinstance(attestation.get("key_id"), str) or not attestation["key_id"].strip():
        raise ValueError("release attestation must identify the signing key with key_id")
    if attestation.get("lock_sha256") != _sha256(lock_bytes):
        raise ValueError("release attestation lock_sha256 does not match the lock bytes")

    try:
        public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError(f"trusted public key could not be loaded: {type(exc).__name__}") from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("trusted public key must be an Ed25519 public key")

    signature = _decode_signature(attestation.get("signature"))
    try:
        public_key.verify(signature, lock_bytes)
    except InvalidSignature as exc:
        raise ValueError("release attestation signature does not verify") from exc

    public_key_digest = hashlib.sha256(
        public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).hexdigest()
    return {
        "schema": SCHEMA,
        "verdict": "PASS",
        "signed_file": str(lock_path),
        "lock_sha256": _sha256(lock_bytes),
        "public_key_sha256": public_key_digest,
        "key_id": attestation.get("key_id"),
        "algorithm": "Ed25519",
        "digests": {name: digests[name] for name in ("api", "worker", "neo4j")},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-manifests", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--report", type=Path, help="write the non-secret verification report")
    args = parser.parse_args(argv)
    try:
        report = verify_attestation(args.release_manifests, args.public_key, args.attestation)
    except ValueError as exc:
        print(f"Release attestation: FAIL: {exc}", file=sys.stderr)
        return 1
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Release attestation: PASS ({report['algorithm']}, lock={report['lock_sha256']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
