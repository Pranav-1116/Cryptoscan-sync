"""
Pre-load integrity verifier.

Verifies evidence record integrity BEFORE loading into the database.
If verification fails, the load is aborted — no corrupted data enters the DB.
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PreLoadVerificationResult:
    """Result of pre-load verification."""

    passed: bool
    total_records: int
    verified_records: int = 0
    content_hash_errors: list[dict[str, Any]] = field(default_factory=list)
    chain_hash_errors: list[dict[str, Any]] = field(default_factory=list)
    manifest_errors: list[str] = field(default_factory=list)
    structural_errors: list[str] = field(default_factory=list)

    @property
    def total_errors(self) -> int:
        return (
            len(self.content_hash_errors)
            + len(self.chain_hash_errors)
            + len(self.manifest_errors)
            + len(self.structural_errors)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "total_records": self.total_records,
            "verified_records": self.verified_records,
            "total_errors": self.total_errors,
            "content_hash_errors": self.content_hash_errors,
            "chain_hash_errors": self.chain_hash_errors,
            "manifest_errors": self.manifest_errors,
            "structural_errors": self.structural_errors,
        }


class PreLoadVerifier:
    """
    Verifies evidence record integrity before database insertion.

    Performs three checks:
    1. Content hash verification (each record's hash matches its content)
    2. Chain hash verification (blockchain-style linkage is intact)
    3. Manifest verification (manifest hash covers all records)

    If ANY check fails, the load should be aborted.
    """

    def verify(
        self,
        evidence_records: list[dict[str, Any]],
        manifest: dict[str, Any] | None = None,
        scan_session_id: str | None = None,
    ) -> PreLoadVerificationResult:
        """
        Verify evidence records before loading to database.

        Args:
            evidence_records: List of evidence record dicts from evidence pipeline.
            manifest: Optional scan manifest for full verification.
            scan_session_id: Session ID for chain anchor verification.

        Returns:
            PreLoadVerificationResult with pass/fail and error details.
        """
        result = PreLoadVerificationResult(
            passed=False,
            total_records=len(evidence_records),
        )

        if not evidence_records:
            logger.warning("No evidence records to verify")
            result.passed = True
            return result

        # Structural check
        self._verify_structure(evidence_records, result)
        if result.structural_errors:
            logger.error(
                "Structural errors found in evidence records",
                extra={"errors": result.structural_errors},
            )
            return result

        # Content hash verification
        self._verify_content_hashes(evidence_records, result)

        # Chain hash verification
        self._verify_chain_hashes(evidence_records, result, scan_session_id)

        # Manifest verification (if provided)
        if manifest:
            self._verify_manifest(evidence_records, manifest, result)

        result.verified_records = len(evidence_records)
        result.passed = result.total_errors == 0

        if result.passed:
            logger.info(
                "Pre-load verification PASSED",
                extra={"total_records": result.total_records},
            )
        else:
            logger.error(
                "Pre-load verification FAILED",
                extra={
                    "total_records": result.total_records,
                    "total_errors": result.total_errors,
                },
            )

        return result

    def _verify_structure(
        self,
        records: list[dict[str, Any]],
        result: PreLoadVerificationResult,
    ) -> None:
        """Check that all records have required fields."""
        required_fields = {"evidence_id", "content_hash", "finding", "chain"}

        for i, record in enumerate(records):
            missing = required_fields - set(record.keys())
            if missing:
                result.structural_errors.append(
                    f"Record {i} missing fields: {sorted(missing)}"
                )

            chain = record.get("chain", {})
            if not isinstance(chain, dict):
                result.structural_errors.append(
                    f"Record {i}: 'chain' must be a dict"
                )
            else:
                chain_required = {"position", "chain_hash"}
                chain_missing = chain_required - set(chain.keys())
                if chain_missing:
                    result.structural_errors.append(
                        f"Record {i}: chain missing fields: {sorted(chain_missing)}"
                    )

    def _verify_content_hashes(
        self,
        records: list[dict[str, Any]],
        result: PreLoadVerificationResult,
    ) -> None:
        """Recompute and verify content hashes for all records."""
        for record in records:
            evidence_id = record.get("evidence_id", "unknown")
            stored_hash = record.get("content_hash", "")
            finding = record.get("finding", {})

            if not stored_hash:
                result.content_hash_errors.append({
                    "evidence_id": evidence_id,
                    "error": "Missing content_hash",
                })
                continue

            computed_hash = self._compute_content_hash(finding)

            if computed_hash != stored_hash:
                result.content_hash_errors.append({
                    "evidence_id": evidence_id,
                    "stored_hash": stored_hash,
                    "computed_hash": computed_hash,
                    "error": "Content hash mismatch — possible tampering",
                })

    def _verify_chain_hashes(
        self,
        records: list[dict[str, Any]],
        result: PreLoadVerificationResult,
        scan_session_id: str | None,
    ) -> None:
        """Verify blockchain-style chain hash linkage."""
        # Sort by chain position
        try:
            sorted_records = sorted(records, key=lambda r: r["chain"]["position"])
        except (KeyError, TypeError):
            result.chain_hash_errors.append({
                "error": "Cannot sort records by chain position",
            })
            return

        previous_hash: str | None = None

        for record in sorted_records:
            evidence_id = record.get("evidence_id", "unknown")
            chain = record.get("chain", {})
            position = chain.get("position", -1)
            stored_chain_hash = chain.get("chain_hash", "")
            content_hash = record.get("content_hash", "")

            # Determine previous hash for chain computation
            if position == 0:
                prev = scan_session_id or ""
            else:
                prev = previous_hash or ""

            computed_chain_hash = self._compute_chain_hash(content_hash, prev)

            if computed_chain_hash != stored_chain_hash:
                result.chain_hash_errors.append({
                    "evidence_id": evidence_id,
                    "position": position,
                    "stored_chain_hash": stored_chain_hash,
                    "computed_chain_hash": computed_chain_hash,
                    "error": "Chain hash mismatch — records may have been tampered with or reordered",
                })

            previous_hash = stored_chain_hash

    def _verify_manifest(
        self,
        records: list[dict[str, Any]],
        manifest: dict[str, Any],
        result: PreLoadVerificationResult,
    ) -> None:
        """Verify the scan manifest hash."""
        summary = manifest.get("summary", {})
        stored_manifest_hash = summary.get("manifest_hash", "")

        if not stored_manifest_hash:
            result.manifest_errors.append("Manifest missing 'manifest_hash' in summary")
            return

        # Recompute manifest hash from all evidence IDs
        evidence_ids = sorted(r.get("evidence_id", "") for r in records)
        computed_hash = hashlib.sha256(
            json.dumps(evidence_ids, sort_keys=True).encode("utf-8")
        ).hexdigest()

        if computed_hash != stored_manifest_hash:
            result.manifest_errors.append(
                f"Manifest hash mismatch: stored={stored_manifest_hash!r}, "
                f"computed={computed_hash!r}. Evidence records may have been "
                f"added, deleted, or reordered."
            )

        # Verify total count
        expected_count = summary.get("total_findings", 0)
        if expected_count != len(records):
            result.manifest_errors.append(
                f"Finding count mismatch: manifest says {expected_count}, "
                f"but got {len(records)} records"
            )

    @staticmethod
    def _compute_content_hash(finding: dict[str, Any]) -> str:
        """
        Compute SHA-256 hash of a finding's canonical form.

        Must match the algorithm used in the evidence pipeline's
        canonical_serializer and content_hasher.
        """
        # Canonical serialization: sort keys, no whitespace, UTF-8
        canonical = json.dumps(finding, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _compute_chain_hash(content_hash: str, previous_hash: str) -> str:
        """
        Compute chain hash linking this record to the previous one.

        Must match the algorithm in the evidence pipeline's chain_hasher.
        """
        combined = content_hash + previous_hash
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()