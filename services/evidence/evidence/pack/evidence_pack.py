"""
Build and verify a standalone CryptoScan evidence pack.

A pack is JSON an auditor can take off-box. Integrity is two layers:

1. The existing SHA-256 hash chain over finding content hashes
   (detects delete / reorder / edit of any finding).
2. An optional HMAC-SHA256 issued by the CryptoScan instance
   (proves the pack was produced by a holder of SECRET_KEY).

The chain can be verified with no secret. The signature needs the
same SECRET_KEY the issuing instance used.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Optional

from evidence.hashing.chain_hasher import ChainHasher

PACK_FORMAT = "cryptoscan-evidence-pack"
PACK_VERSION = "1.0"
SIGNATURE_ALG = "HMAC-SHA256"
HASH_ALG = "SHA-256"


def _canonical(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _as_record(item: Mapping[str, Any], index: int) -> dict[str, Any]:
    evaluation = item.get("policy_evaluation") or {}
    failed = []
    for rule in evaluation.get("rules_evaluated") or []:
        if str(rule.get("evaluation_result") or "").upper() == "FAIL":
            failed.append(
                {
                    "rule_id": rule.get("rule_id"),
                    "message": rule.get("message"),
                    "severity": rule.get("severity"),
                }
            )
    return {
        "evidence_id": item.get("evidence_id") or item.get("id") or f"finding-{index}",
        "chain_position": item.get("chain_position", index),
        "algorithm": item.get("algorithm") or "UNKNOWN",
        "mode": item.get("mode"),
        "key_size": item.get("key_size"),
        "purpose": item.get("purpose"),
        "file_path": item.get("file_path") or "",
        "line_number": item.get("line_number") or 0,
        "compliance_status": item.get("compliance_status"),
        "is_hardcoded_key": bool(item.get("is_hardcoded_key")),
        "content_hash": item.get("content_hash") or "",
        "chain_hash": item.get("chain_hash") or "",
        "failed_rules": failed,
    }


def records_digest(records: Iterable[Mapping[str, Any]]) -> str:
    joined = "|".join(
        f"{r.get('content_hash','')}:{r.get('chain_hash','')}" for r in records
    )
    return _sha256_hex(joined)


def sign_pack(pack: Mapping[str, Any], secret: str) -> str:
    """HMAC over the pack with integrity.signature removed."""
    body = {key: value for key, value in pack.items() if key != "integrity"}
    integrity = dict(pack.get("integrity") or {})
    integrity.pop("signature", None)
    body["integrity"] = integrity
    return hmac.new(
        secret.encode("utf-8"),
        _canonical(body).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def build_evidence_pack(
    *,
    scan: Mapping[str, Any],
    records: Iterable[Mapping[str, Any]],
    policy: Optional[Mapping[str, Any]] = None,
    secret: Optional[str] = None,
    extra: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    items = [_as_record(row, index) for index, row in enumerate(records)]
    scan_id = str(scan.get("scan_id") or scan.get("id") or "")
    content_hashes = [item["content_hash"] for item in items]
    stored_chain = [item["chain_hash"] for item in items]
    hashes_ok = all(len(h) == 64 and h.isalnum() for h in content_hashes + stored_chain) if items else True
    chain_ok = True
    if items and all(content_hashes) and all(stored_chain):
        chain_ok = ChainHasher.verify_chain(content_hashes, stored_chain, scan_id)
    elif items and all(content_hashes) and not all(stored_chain):
        computed = ChainHasher.compute_chain(content_hashes, scan_id)
        for item, chain_hash in zip(items, computed):
            item["chain_hash"] = chain_hash
        stored_chain = computed
        chain_ok = True

    pack: dict[str, Any] = {
        "pack_format": PACK_FORMAT,
        "pack_version": PACK_VERSION,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "scan": {
            "scan_id": scan_id,
            "target_location": scan.get("target_location"),
            "target_commit": scan.get("target_commit"),
            "target_branch": scan.get("target_branch"),
            "operator": scan.get("operator"),
            "status": scan.get("status"),
            "scanner_id": scan.get("scanner_id"),
            "scanner_version": scan.get("scanner_version"),
            "manifest_hash": scan.get("manifest_hash"),
        },
        "policy": dict(policy or {}),
        "records": items,
        "integrity": {
            "hash_algorithm": HASH_ALG,
            "signature_alg": SIGNATURE_ALG,
            "records_digest": records_digest(items),
            "chain_ok": bool(chain_ok and hashes_ok),
            "record_count": len(items),
        },
    }
    if extra:
        pack["extra"] = dict(extra)
    pack["integrity"]["signed"] = bool(secret)
    if secret:
        pack["integrity"]["signature"] = sign_pack(pack, secret)
    return pack


def verify_evidence_pack(
    pack: Mapping[str, Any],
    *,
    secret: Optional[str] = None,
) -> dict[str, Any]:
    """Offline verification. Does not need a database."""
    errors: list[str] = []
    warnings: list[str] = []

    if pack.get("pack_format") != PACK_FORMAT:
        errors.append(f"unknown pack_format {pack.get('pack_format')!r}")
    if pack.get("pack_version") != PACK_VERSION:
        warnings.append(f"unexpected pack_version {pack.get('pack_version')!r}")

    records = list(pack.get("records") or [])
    scan_id = str((pack.get("scan") or {}).get("scan_id") or "")
    content_hashes = [str(r.get("content_hash") or "") for r in records]
    stored_chain = [str(r.get("chain_hash") or "") for r in records]

    hashes_ok = True
    for index, digest in enumerate(content_hashes):
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest.lower()):
            hashes_ok = False
            errors.append(f"invalid content_hash at position {index}")
    for index, digest in enumerate(stored_chain):
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest.lower()):
            hashes_ok = False
            errors.append(f"invalid chain_hash at position {index}")

    chain_ok = False
    if records and hashes_ok and scan_id:
        chain_ok = ChainHasher.verify_chain(content_hashes, stored_chain, scan_id)
        if not chain_ok:
            computed = ChainHasher.compute_chain(content_hashes, scan_id)
            for index, (got, expected) in enumerate(zip(stored_chain, computed)):
                if got != expected:
                    errors.append(f"chain break at position {index}")
                    break
    elif not records:
        chain_ok = True
    elif not scan_id:
        errors.append("scan.scan_id missing; cannot recompute chain")

    integrity = dict(pack.get("integrity") or {})
    expected_digest = records_digest(records)
    if integrity.get("records_digest") and integrity["records_digest"] != expected_digest:
        errors.append("records_digest mismatch")

    signature = integrity.get("signature")
    signature_ok: Optional[bool] = None
    if signature and secret:
        expected_sig = sign_pack(pack, secret)
        signature_ok = hmac.compare_digest(expected_sig, str(signature))
        if not signature_ok:
            errors.append("HMAC signature mismatch")
    elif signature and not secret:
        warnings.append("pack is signed but no secret was provided; signature not checked")
    elif not signature:
        warnings.append("pack is unsigned")

    result = "PASS" if not errors else "FAIL"
    return {
        "result": result,
        "chain_intact": chain_ok and hashes_ok,
        "signature_ok": signature_ok,
        "signed": bool(signature),
        "records": len(records),
        "scan_id": scan_id,
        "errors": errors,
        "warnings": warnings,
    }
