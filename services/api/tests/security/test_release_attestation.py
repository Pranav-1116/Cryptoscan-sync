"""Detached release attestations must verify exact immutable lock bytes."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "scripts" / "verify_release_attestation.py"


def _verifier():
    cryptography = pytest.importorskip("cryptography")
    assert cryptography
    spec = importlib.util.spec_from_file_location("verify_release_attestation", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _fixture(tmp_path: Path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    release = tmp_path / "release"
    release.mkdir()
    lock = {
        "schema": "cryptoscan.immutable-image-release/1",
        "registry": "registry.example/bank",
        "digests": {"api": "a" * 64, "worker": "b" * 64, "neo4j": "c" * 64},
    }
    lock_path = release / "release-image-lock.json"
    lock_path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")

    private = Ed25519PrivateKey.generate()
    public_path = tmp_path / "release.pub.pem"
    public_path.write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    attestation_path = release / "release-attestation.json"
    signature = private.sign(lock_path.read_bytes())
    attestation_path.write_text(
        json.dumps(
            {
                "schema": "cryptoscan.release-attestation/1",
                "algorithm": "Ed25519",
                "key_id": "release-authority-2026",
                "signed_file": "release-image-lock.json",
                "lock_sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
                "signature": base64.b64encode(signature).decode("ascii"),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return release, public_path, attestation_path, lock_path


def test_attestation_verifies_exact_lock_bytes(tmp_path):
    verifier = _verifier()
    release, public, attestation, lock = _fixture(tmp_path)

    report = verifier.verify_attestation(release, public, attestation)

    assert report["verdict"] == "PASS"
    assert report["lock_sha256"] == hashlib.sha256(lock.read_bytes()).hexdigest()
    assert report["key_id"] == "release-authority-2026"


def test_lock_tampering_invalidates_attestation(tmp_path):
    verifier = _verifier()
    release, public, attestation, lock = _fixture(tmp_path)
    lock.write_text(lock.read_text(encoding="utf-8").replace("registry.example/bank", "evil.example/bank"), encoding="utf-8")

    with pytest.raises(ValueError, match="lock_sha256"):
        verifier.verify_attestation(release, public, attestation)


def test_wrong_public_key_is_rejected(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    verifier = _verifier()
    release, _public, attestation, _lock = _fixture(tmp_path)
    wrong_public = tmp_path / "wrong.pub.pem"
    wrong_public.write_bytes(
        Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    with pytest.raises(ValueError, match="does not verify"):
        verifier.verify_attestation(release, wrong_public, attestation)
