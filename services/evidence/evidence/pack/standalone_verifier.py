"""Tiny auditor-facing verifier embedded in the CRA/NIST zip.

This module is copied verbatim into the audit pack so a reviewer can run:

    python verify_pack.py evidence-pack.json [--secret SECRET]

without installing CryptoScan. It reimplements the chain formula on purpose
so the pack is self-describing.
"""

STANDALONE_VERIFIER_SOURCE = r'''#!/usr/bin/env python3
"""CryptoScan evidence-pack verifier (no CryptoScan install required)."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
from typing import Any, Mapping


PACK_FORMAT = "cryptoscan-evidence-pack"


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def compute_chain(content_hashes: list[str], scan_id: str) -> list[str]:
    chain: list[str] = []
    previous = None
    for index, content_hash in enumerate(content_hashes):
        if index == 0:
            chain_input = f"{content_hash}{scan_id}"
        else:
            chain_input = f"{content_hash}{previous}"
        digest = sha256_hex(chain_input)
        chain.append(digest)
        previous = digest
    return chain


def canonical(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def expected_signature(pack: Mapping[str, Any], secret: str) -> str:
    body = {key: value for key, value in pack.items() if key != "integrity"}
    integrity = dict(pack.get("integrity") or {})
    integrity.pop("signature", None)
    body["integrity"] = integrity
    return hmac.new(secret.encode("utf-8"), canonical(body).encode("utf-8"), hashlib.sha256).hexdigest()


def records_digest(records: list[Mapping[str, Any]]) -> str:
    joined = "|".join(f"{r.get('content_hash','')}:{r.get('chain_hash','')}" for r in records)
    return sha256_hex(joined)


def verify(pack: Mapping[str, Any], secret: str | None = None) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    if pack.get("pack_format") != PACK_FORMAT:
        errors.append(f"unknown pack_format {pack.get('pack_format')!r}")
    records = list(pack.get("records") or [])
    scan_id = str((pack.get("scan") or {}).get("scan_id") or "")
    content_hashes = [str(r.get("content_hash") or "") for r in records]
    stored = [str(r.get("chain_hash") or "") for r in records]
    for index, digest in enumerate(content_hashes + stored):
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest.lower()):
            errors.append(f"invalid hash at combined index {index}")
    chain_ok = False
    if records and scan_id and not errors:
        computed = compute_chain(content_hashes, scan_id)
        chain_ok = computed == stored
        if not chain_ok:
            for index, (got, expected) in enumerate(zip(stored, computed)):
                if got != expected:
                    errors.append(f"chain break at position {index}")
                    break
    elif not records:
        chain_ok = True
    elif not scan_id:
        errors.append("scan.scan_id missing")
    integrity = pack.get("integrity") or {}
    if integrity.get("records_digest") and integrity["records_digest"] != records_digest(records):
        errors.append("records_digest mismatch")
    signature = integrity.get("signature")
    signature_ok = None
    if signature and secret:
        signature_ok = hmac.compare_digest(expected_signature(pack, secret), str(signature))
        if not signature_ok:
            errors.append("HMAC signature mismatch")
    elif signature:
        warnings.append("signed pack; pass --secret to check HMAC")
    result = "PASS" if not errors else "FAIL"
    return {
        "result": result,
        "chain_intact": chain_ok,
        "signature_ok": signature_ok,
        "records": len(records),
        "errors": errors,
        "warnings": warnings,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a CryptoScan evidence pack")
    parser.add_argument("pack", help="Path to evidence-pack.json")
    parser.add_argument("--secret", help="HMAC secret used by the issuing instance")
    args = parser.parse_args(argv)
    with open(args.pack, encoding="utf-8") as handle:
        pack = json.load(handle)
    report = verify(pack, secret=args.secret)
    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
'''
