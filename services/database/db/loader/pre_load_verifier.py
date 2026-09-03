"""Verify evidence records (structure, content hashes, chain linkage) before DB load."""

from __future__ import annotations

from typing import Any

from db.loader.chain import chain_hash as compute_chain_hash
from db.loader.chain import content_hash as compute_content_hash

_HEX64 = "0123456789abcdef"


class PreLoadVerification:
    """Structured result of a pre-load integrity check."""

    def __init__(self) -> None:
        self.passed = True
        self.structural_errors: list[str] = []
        self.content_hash_errors: list[str] = []
        self.chain_hash_errors: list[str] = []

    def fail(self, *buckets: list[str]) -> None:
        self.passed = False

    @property
    def errors(self) -> list[str]:
        return self.structural_errors + self.content_hash_errors + self.chain_hash_errors

    @property
    def error(self) -> str | None:
        return "; ".join(self.errors) if self.errors else None


def _is_hex64(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in _HEX64 for c in value.lower())
    )


def _chain_fields(rec: dict[str, Any]) -> dict[str, Any]:
    """Extract chain fields from either nested `chain` or flat layout."""
    chain = rec.get("chain") if isinstance(rec.get("chain"), dict) else {}
    return {
        "position": chain.get("position", rec.get("chain_position", rec.get("position"))),
        "chain_hash": chain.get("chain_hash", rec.get("chain_hash")),
        "previous_hash": chain.get("previous_hash", rec.get("previous_hash")),
    }


def verify_records_detailed(
    records: list[dict[str, Any]],
    scan_session_id: str | None = None,
) -> PreLoadVerification:
    result = PreLoadVerification()
    if not records:
        return result

    expected_previous = scan_session_id or ""
    for index, rec in enumerate(records):
        rid = str(rec.get("evidence_id") or f"record[{index}]")

        # ---- structural ------------------------------------------------- #
        finding = rec.get("finding") or rec.get("finding_data")
        has_nested_chain = isinstance(rec.get("chain"), dict)
        chain = _chain_fields(rec)
        missing = []
        if not rec.get("content_hash"):
            missing.append("content_hash")
        if not finding:
            missing.append("finding")
        if not has_nested_chain and (chain["position"] is None or not chain["chain_hash"]):
            missing.append("chain")
        position = chain["position"]
        if missing:
            result.structural_errors.append(f"{rid}: missing required field(s): {', '.join(missing)}")
            result.passed = False
            continue
        if position != index:
            result.structural_errors.append(
                f"{rid}: chain position {position} out of order (expected {index})"
            )
            result.passed = False
        if not _is_hex64(rec.get("content_hash")):
            result.structural_errors.append(f"{rid}: content_hash must be 64-char hex")
            result.passed = False
        if not _is_hex64(chain["chain_hash"]):
            result.structural_errors.append(f"{rid}: chain_hash must be 64-char hex")
            result.passed = False
        if any(rid in e for e in result.structural_errors):
            # cannot meaningfully verify hashes for a structurally broken record
            expected_previous = chain["chain_hash"] or expected_previous
            continue

        # ---- content hash ---------------------------------------------- #
        recomputed_content = compute_content_hash(finding)
        if recomputed_content != rec["content_hash"]:
            result.content_hash_errors.append(
                f"{rid}: content_hash does not match finding payload"
            )
            result.passed = False

        # ---- chain linkage --------------------------------------------- #
        prev = chain["previous_hash"]
        if index == 0:
            # genesis anchors to scan_session_id (or empty); previous_hash must be null/empty
            if prev not in (None, ""):
                result.chain_hash_errors.append(
                    f"{rid}: genesis record must have no previous_hash"
                )
                result.passed = False
            anchor = scan_session_id or ""
        else:
            if prev != expected_previous:
                result.chain_hash_errors.append(
                    f"{rid}: previous_hash does not link to preceding record"
                )
                result.passed = False
            anchor = expected_previous

        expected_chain = compute_chain_hash(rec["content_hash"], anchor)
        if expected_chain != chain["chain_hash"]:
            result.chain_hash_errors.append(
                f"{rid}: chain_hash does not match sha256(content_hash || previous)"
            )
            result.passed = False

        expected_previous = chain["chain_hash"]

    return result


def verify_records(records: list[dict[str, Any]]) -> tuple[bool, str | None]:
    """Structural pre-load check for the legacy flat-layout ingestion path.

    Validates chain positions are contiguous and hash fields are well-formed
    hex, but does NOT recompute content/chain hashes — those use the evidence
    service's own canonical scheme and are verified elsewhere. Full
    cryptographic verification lives in :func:`verify_records_detailed`
    (used by the integrity-checked ``EvidenceLoader.load_from_data`` path).
    """
    if not records:
        return True, None
    positions = [r.get("chain_position") for r in records]
    if positions != list(range(len(records))):
        return False, "chain_position sequence is not contiguous"
    for rec in records:
        if not _is_hex64(rec.get("content_hash")):
            return False, "invalid content_hash"
        chain_hash = rec.get("chain_hash")
        if chain_hash and not _is_hex64(chain_hash):
            return False, "invalid chain_hash"
    return True, None
