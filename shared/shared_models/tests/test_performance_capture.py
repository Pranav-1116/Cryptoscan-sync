"""Bank capture trust anchor: rotation must be deliberate, never silent.

A keyset selects by exact key_id; an unlisted key_id is refused rather than
mapped to another key. Single-PEM anchors keep their original behaviour so an
operator can adopt rotation without breaking an existing deployment.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from shared_models.performance_capture import (
    SCHEMA,
    capture_binding,
    payload_sha256,
    verify_capture_attestation,
)


def _keypair():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return private, public


def _sign(private: Ed25519PrivateKey, binding: dict) -> str:
    message = json.dumps(binding, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    return base64.b64encode(private.sign(message)).decode("ascii")


def _context(**overrides):
    context = dict(
        tenant_id="tenant-a", asset_ref="app:svc-pay", source_id="node-1",
        source_type="node_exporter", observed_at="2026-10-16T12:00:00+00:00",
        previous_observed_at=None, authorization_ref="AUTH-77",
        payload_digest="a" * 64, previous_digest=None,
        key_id="bank-2026-q4", issuer="bank-collector-1")
    context.update(overrides)
    return context


def _attestation(private: Ed25519PrivateKey, context: dict) -> dict:
    binding = capture_binding(**context)
    return {"schema": SCHEMA, "algorithm": "Ed25519",
            "key_id": context["key_id"], "issuer": context["issuer"],
            "signature": _sign(private, binding)}


def _verify(attestation: dict, anchor: Path, context: dict) -> dict:
    return verify_capture_attestation(
        attestation=attestation, public_key_path=anchor,
        tenant_id=context["tenant_id"], asset_ref=context["asset_ref"],
        source_id=context["source_id"], source_type=context["source_type"],
        observed_at=context["observed_at"],
        previous_observed_at=context["previous_observed_at"],
        authorization_ref=context["authorization_ref"],
        payload_digest=context["payload_digest"],
        previous_digest=context["previous_digest"])


def test_single_pem_anchor_keeps_working_for_any_key_id(tmp_path: Path):
    private, public = _keypair()
    anchor = tmp_path / "anchor.pem"
    anchor.write_bytes(public)
    context = _context()
    assert _verify(_attestation(private, context), anchor, context)["key_id"] == "bank-2026-q4"


def test_keyset_anchor_selects_by_exact_key_id(tmp_path: Path):
    old_private, old_public = _keypair()
    new_private, new_public = _keypair()
    anchor = tmp_path / "anchor.json"
    anchor.write_text(json.dumps({"keys": [
        {"key_id": "bank-2026-q3", "public_key_pem": old_public.decode()},
        {"key_id": "bank-2026-q4", "public_key_pem": new_public.decode()},
    ]}), encoding="utf-8")
    context = _context(key_id="bank-2026-q4")
    assert _verify(_attestation(new_private, context), anchor, context)["key_id"] == "bank-2026-q4"
    retired = _context(key_id="bank-2026-q3")
    assert _verify(_attestation(old_private, retired), anchor, retired)["key_id"] == "bank-2026-q3"


def test_keyset_refuses_an_unlisted_key_id_never_maps_it(tmp_path: Path):
    _, new_public = _keypair()
    rogue_private, _ = _keypair()
    anchor = tmp_path / "anchor.json"
    anchor.write_text(json.dumps({"keys": [
        {"key_id": "bank-2026-q4", "public_key_pem": new_public.decode()},
    ]}), encoding="utf-8")
    context = _context(key_id="bank-2026-q3")
    with pytest.raises(ValueError, match="key_id is not trusted"):
        _verify(_attestation(rogue_private, context), anchor, context)


def test_keyset_signature_from_the_wrong_key_is_refused(tmp_path: Path):
    _, other_public = _keypair()
    rogue_private, _ = _keypair()
    anchor = tmp_path / "anchor.json"
    anchor.write_text(json.dumps({"keys": [
        {"key_id": "bank-2026-q4", "public_key_pem": other_public.decode()},
    ]}), encoding="utf-8")
    context = _context()
    with pytest.raises(ValueError):
        _verify(_attestation(rogue_private, context), anchor, context)


def test_keyset_malformed_entries_are_refused(tmp_path: Path):
    anchor = tmp_path / "anchor.json"
    anchor.write_text(json.dumps({"keys": [{"key_id": "x"}]}), encoding="utf-8")
    context = _context()
    with pytest.raises(ValueError, match="malformed"):
        _verify(_attestation(Ed25519PrivateKey.generate(), context), anchor, context)
    anchor.write_text(json.dumps({"keys": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="malformed"):
        _verify(_attestation(Ed25519PrivateKey.generate(), context), anchor, context)
    anchor.write_text(json.dumps({"keys": [
        {"key_id": "k", "public_key_pem": "nope"},
        {"key_id": "k", "public_key_pem": "nope"},
    ]}), encoding="utf-8")
    with pytest.raises(ValueError, match="malformed|repeats"):
        _verify(_attestation(Ed25519PrivateKey.generate(), context), anchor, context)


def test_attestation_binds_the_payload_digest(tmp_path: Path):
    private, public = _keypair()
    anchor = tmp_path / "anchor.pem"
    anchor.write_bytes(public)
    context = _context()
    attestation = _attestation(private, context)
    tampered = dict(context, payload_digest="b" * 64)
    with pytest.raises(ValueError, match="does not bind"):
        _verify(attestation, anchor, tampered)


def test_binding_canonical_json_is_deterministic():
    left = capture_binding(**_context())
    right = capture_binding(**_context())
    assert left == right
    assert payload_sha256({"b": 1, "a": 2}) == payload_sha256({"a": 2, "b": 1})
