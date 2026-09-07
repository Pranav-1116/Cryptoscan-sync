"""Audit-log tamper verification + signed attestation report.

Walks the hash-chained audit log end to end, recomputing every entry hash and
the previous-hash link, and produces a deterministic, HMAC-signed attestation
report (JSON) that a third party can verify offline with the shared secret.

Works directly on a list of audit-entry dicts (from any store), so it is
testable without a database; the API layer supplies rows from the repository's
verify_audit_chain / audit listing.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
from typing import Any, Iterable, Protocol

GENESIS_HASH = "0" * 64


def _aware_iso(value: Any) -> str:
    if isinstance(value, dt.datetime):
        v = value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
        return v.astimezone(dt.timezone.utc).isoformat()
    return str(value) if value is not None else ""


def entry_hash(prev: str | None, entry: dict) -> str:
    """Must match db.repositories.user_repository.audit_entry_hash canonical form."""
    canonical = "|".join([
        str(prev or GENESIS_HASH),
        str(entry.get("actor") or ""),
        str(entry.get("action") or ""),
        str(entry.get("target_type") or ""),
        str(entry.get("target_id") or ""),
        str(entry.get("detail") or ""),
        str(entry.get("ip_address") or ""),
        str(entry.get("outcome") or ""),
        _aware_iso(entry.get("created_at")),
    ])
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_entries(entries: Iterable[dict]) -> dict[str, Any]:
    """Recompute the full chain; return the first break with full diagnostics."""
    rows = sorted(entries, key=lambda r: (r.get("chain_sequence") is None,
                                          r.get("chain_sequence") or 0))
    expected_prev = GENESIS_HASH
    checked = 0
    mismatches: list[dict] = []
    seq_seen: list[int] = []
    for row in rows:
        seq = row.get("chain_sequence")
        if seq is not None:
            seq_seen.append(seq)
        # 1) previous-hash link
        if str(row.get("previous_hash") or GENESIS_HASH) != expected_prev:
            mismatches.append({
                "sequence": seq, "code": "PREVIOUS_HASH_MISMATCH",
                "expected": expected_prev, "found": row.get("previous_hash"),
                "detail": "entry removed, reordered, or previous_hash forged",
            })
            # continue verification from the recorded value to find more breaks
        # 2) content hash
        recomputed = entry_hash(row.get("previous_hash"), row)
        if recomputed != str(row.get("entry_hash") or ""):
            mismatches.append({
                "sequence": seq, "code": "ENTRY_HASH_MISMATCH",
                "expected": recomputed, "found": row.get("entry_hash"),
                "action": row.get("action"),
                "detail": "entry content modified after write (tampering)",
            })
        expected_prev = str(row.get("entry_hash") or recomputed)
        checked += 1

    # 3) sequence continuity (gaps indicate deleted entries)
    gaps = []
    if seq_seen:
        full = set(range(min(seq_seen), max(seq_seen) + 1))
        gaps = sorted(full - set(seq_seen))

    tampered = bool(mismatches) or bool(gaps)
    return {
        "status": "TAMPERED" if tampered else "VERIFIED",
        "entries_checked": checked,
        "chain_head": expected_prev if rows else None,
        "mismatches": mismatches,
        "sequence_gaps": gaps,
        "verified_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }


def build_attestation(entries: Iterable[dict], *, org: str, signer: str,
                      secret: str, now: dt.datetime | None = None) -> dict[str, Any]:
    """Produce a signed attestation over the verification result."""
    ref = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    result = verify_entries(entries)
    body = {
        "org": org,
        "signer": signer,
        "generated_at": ref.isoformat(),
        "status": result["status"],
        "entries_checked": result["entries_checked"],
        "chain_head": result["chain_head"],
        "tamper_detected": result["status"] != "VERIFIED",
        "mismatch_count": len(result["mismatches"]),
        "sequence_gap_count": len(result["sequence_gaps"]),
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    signature = hmac.new(secret.encode(), canonical, hashlib.sha256).hexdigest()
    return {
        "attestation": body,
        "algorithm": "HMAC-SHA256",
        "signature": signature,
        "details": {"mismatches": result["mismatches"], "sequence_gaps": result["sequence_gaps"]},
    }


def verify_attestation(report: dict[str, Any], *, secret: str) -> bool:
    body = report.get("attestation") or {}
    sig = report.get("signature") or ""
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return hmac.compare_digest(
        hmac.new(secret.encode(), canonical, hashlib.sha256).hexdigest(), sig)
