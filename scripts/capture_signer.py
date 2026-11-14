#!/usr/bin/env python3
"""Reference bank-capture signer — a QUALIFICATION AID, never a production key.

A bank integrator builds and checks a signing pipeline against the exact
capture-attestation schema before connecting a collector. The production
Ed25519 private key stays inside the bank's own collector/signing service and
never enters CryptoScan; keys this tool generates are TEST keys for integration
checks and CI, and captures signed with them are engineering checks, never bank
observations.

Three commands, no network client and no database: this script emits request
bodies and checks signatures, so the bank-facing integration path stays the
one the API authorises (docs/bank-environment/98-cli-architecture.md).

  keygen  — write a TEST Ed25519 keypair plus a trust-anchor keyset fragment
  sign    — emit one POST /api/v1/performance/captures/import request body,
            attestation bound to tenant, canonical asset, source, authorization
            reference, collection times and payload digests
  verify  — check a signed capture body against a trust anchor before sending

The signature covers the canonical compact sorted-key JSON of the binding that
shared_models.performance_capture builds — the same object the server
reconstructs. Run with the repository's PYTHONPATH (services/*:shared/*).
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]


def _bootstrap_imports() -> None:
    for pattern in ("services/*", "shared/*"):
        for path in sorted(ROOT.glob(pattern)):
            if path.is_dir() and str(path) not in sys.path:
                sys.path.insert(0, str(path))


_bootstrap_imports()

from shared_models.performance_capture import (  # noqa: E402
    capture_binding,
    payload_sha256,
    verify_capture_attestation,
)

TEST_KEY_WARNING = (
    "capture_signer: TEST KEY generated — qualification aid only. "
    "Production bank captures are signed by the bank's own service; this key "
    "must never sign a real bank observation."
)


def _parse_aware(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise SystemExit(f"capture_signer: {label} is not an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise SystemExit(f"capture_signer: {label} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _load_json_object(path: str, label: str) -> dict[str, Any]:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"capture_signer: {label} is not readable JSON") from exc
    if not isinstance(document, dict):
        raise SystemExit(f"capture_signer: {label} must be a JSON object")
    return document


def _sign_binding(private, binding: Mapping[str, Any]) -> dict[str, Any]:
    from cryptography.hazmat.primitives import serialization  # noqa: F401
    message = json.dumps(binding, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    signature = base64.b64encode(private.sign(message)).decode("ascii")
    return {"schema": binding["schema"], "algorithm": "Ed25519",
            "key_id": binding["key_id"], "issuer": binding["issuer"],
            "signature": signature}


def cmd_keygen(args: argparse.Namespace) -> int:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    private_path = out_dir / f"{args.key_id}.key.pem"
    public_path = out_dir / f"{args.key_id}.pub.pem"
    keyset_path = out_dir / f"{args.key_id}.keyset.json"
    for path in (private_path, public_path, keyset_path):
        if path.exists():
            print(f"capture_signer: refusing to overwrite {path}", file=sys.stderr)
            return 2
    private = Ed25519PrivateKey.generate()
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode("ascii")
    private_path.write_text(private_pem, encoding="utf-8")
    os.chmod(private_path, 0o600)
    public_path.write_text(public_pem, encoding="utf-8")
    keyset_path.write_text(json.dumps({"keys": [
        {"key_id": args.key_id, "public_key_pem": public_pem}]}, indent=2) + "\n",
        encoding="utf-8")
    print(TEST_KEY_WARNING, file=sys.stderr)
    print(json.dumps({"private_key": str(private_path), "public_key": str(public_path),
                      "keyset_fragment": str(keyset_path)}, indent=2))
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    from cryptography.hazmat.primitives import serialization

    try:
        private = serialization.load_pem_private_key(
            Path(args.key).read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise SystemExit("capture_signer: signing key is not a readable Ed25519 private key") from exc
    observed_at = _parse_aware(args.observed_at, "--observed-at")
    previous_at = (_parse_aware(args.previous_at, "--previous-at")
                   if args.previous_at else None)
    if (previous_at is None) != (args.previous is None):
        raise SystemExit("capture_signer: --previous and --previous-at must be supplied together")
    if previous_at is not None and not previous_at < observed_at:
        raise SystemExit("capture_signer: --previous-at must be earlier than --observed-at")
    payload = _load_json_object(args.payload, "--payload")
    previous = _load_json_object(args.previous, "--previous") if args.previous else None
    try:
        payload_digest = payload_sha256(payload)
        previous_digest = payload_sha256(previous) if previous is not None else None
    except (TypeError, ValueError) as exc:
        raise SystemExit("capture_signer: payload contains non-JSON or non-finite values") from exc
    observed_iso, previous_iso = _iso(observed_at), (_iso(previous_at) if previous_at else None)
    binding = capture_binding(
        tenant_id=args.tenant_id, asset_ref=args.asset_ref,
        source_id=args.source_id, source_type=args.source_type,
        observed_at=observed_iso, previous_observed_at=previous_iso,
        authorization_ref=args.authorization_ref,
        payload_digest=payload_digest, previous_digest=previous_digest,
        key_id=args.key_id, issuer=args.issuer)
    body: dict[str, Any] = {
        "tenant_id": args.tenant_id, "asset_ref": args.asset_ref,
        "source_id": args.source_id, "source_type": args.source_type,
        "authorization_ref": args.authorization_ref,
        "observed_at": observed_iso, "payload": payload,
        "attestation": _sign_binding(private, binding)}
    if previous is not None:
        body["previous_observed_at"] = previous_iso
        body["previous"] = previous
    rendered = json.dumps(body, indent=2, ensure_ascii=False, allow_nan=False)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
        print(f"capture_signer: signed capture body written to {args.out}", file=sys.stderr)
    else:
        print(rendered)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    body = _load_json_object(args.capture, "--capture")
    attestation = body.get("attestation")
    if not isinstance(attestation, Mapping):
        print("capture_signer: capture body carries no attestation", file=sys.stderr)
        return 1
    payload = body.get("payload")
    previous = body.get("previous")
    if not isinstance(payload, Mapping):
        print("capture_signer: capture body carries no payload", file=sys.stderr)
        return 1
    try:
        observed = _parse_aware(str(body.get("observed_at")), "observed_at")
        previous_at = (body.get("previous_observed_at")
                       if body.get("previous_observed_at") else None)
        previous_iso = (_iso(_parse_aware(str(previous_at), "previous_observed_at"))
                        if previous_at else None)
        payload_digest = payload_sha256(payload)
        previous_digest = payload_sha256(previous) if previous is not None else None
        signer = verify_capture_attestation(
            attestation=attestation, public_key_path=Path(args.public_key).resolve(),
            tenant_id=str(body.get("tenant_id")), asset_ref=str(body.get("asset_ref")),
            source_id=str(body.get("source_id")), source_type=str(body.get("source_type")),
            observed_at=_iso(observed), previous_observed_at=previous_iso,
            authorization_ref=str(body.get("authorization_ref")),
            payload_digest=payload_digest, previous_digest=previous_digest)
    except ValueError as exc:
        print(f"capture_signer: attestation invalid — {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"verified": True, "key_id": signer["key_id"],
                      "issuer": signer["issuer"],
                      "payload_sha256": signer["payload_sha256"]}, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="capture_signer", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="generate a TEST Ed25519 keypair")
    keygen.add_argument("--out-dir", required=True)
    keygen.add_argument("--key-id", required=True)
    keygen.set_defaults(func=cmd_keygen)

    sign = sub.add_parser("sign", help="emit a signed capture request body")
    sign.add_argument("--key", required=True)
    sign.add_argument("--key-id", required=True)
    sign.add_argument("--issuer", required=True)
    sign.add_argument("--tenant-id", required=True)
    sign.add_argument("--asset-ref", required=True)
    sign.add_argument("--source-id", required=True)
    sign.add_argument("--source-type", required=True,
                      choices=["node_exporter", "postgres_exporter", "otlp"])
    sign.add_argument("--authorization-ref", required=True)
    sign.add_argument("--observed-at", required=True)
    sign.add_argument("--previous-at")
    sign.add_argument("--payload", required=True)
    sign.add_argument("--previous")
    sign.add_argument("--out")
    sign.set_defaults(func=cmd_sign)

    verify = sub.add_parser("verify", help="check a signed capture body")
    verify.add_argument("--public-key", required=True)
    verify.add_argument("--capture", required=True)
    verify.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
