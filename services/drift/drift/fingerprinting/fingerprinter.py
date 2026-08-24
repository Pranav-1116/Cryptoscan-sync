"""
Fingerprinter — creates stable fingerprints for crypto findings.

A fingerprint is a deterministic hash of the key attributes of a
finding that identifies it uniquely within a scan for drift comparison.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# Fields included in fingerprint calculation
FINGERPRINT_FIELDS = [
    "algorithm",
    "mode",
    "file_path",
    "line_number",
    "class_name",
    "method_name",
]

# Fields that change but don't affect identity
EXCLUDED_FROM_FINGERPRINT = [
    "evidence_id",
    "scan_id",
    "content_hash",
    "chain_hash",
    "chain_position",
    "created_at",
    "normalized_crypto",
    "policy_evaluation",
]


@dataclass(frozen=True)
class Fingerprint:
    """A stable fingerprint for a crypto finding."""
    hash: str  # 64-char hex SHA-256
    algorithm: str
    file_path: str
    line_number: int | None
    mode: str | None
    source_data: dict[str, Any]

    def __str__(self) -> str:
        return self.hash

    def __hash__(self) -> int:
        return hash(self.hash)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Fingerprint):
            return NotImplemented
        return self.hash == other.hash


class Fingerprinter:
    """
    Creates deterministic fingerprints for evidence records.

    The fingerprint uniquely identifies a cryptographic finding
    by its semantic content (algorithm + location), NOT by its
    database identifiers (which change per scan).

    This allows comparison across scan sessions.
    """

    def fingerprint(self, evidence_record: dict[str, Any]) -> Fingerprint:
        """
        Create a fingerprint for a single evidence record.

        Args:
            evidence_record: Dict with finding data (from DB or model)

        Returns:
            Fingerprint with stable hash
        """
        canonical = self._extract_canonical(evidence_record)
        hash_value = self._compute_hash(canonical)

        return Fingerprint(
            hash=hash_value,
            algorithm=canonical.get("algorithm", "UNKNOWN"),
            file_path=canonical.get("file_path", ""),
            line_number=canonical.get("line_number"),
            mode=canonical.get("mode"),
            source_data=canonical,
        )

    def fingerprint_batch(
        self, evidence_records: list[dict[str, Any]]
    ) -> list[Fingerprint]:
        """Create fingerprints for a batch of evidence records."""
        fingerprints = []
        errors = 0

        for record in evidence_records:
            try:
                fp = self.fingerprint(record)
                fingerprints.append(fp)
            except Exception as exc:
                errors += 1
                logger.warning(
                    "fingerprint_error",
                    evidence_id=str(record.get("evidence_id", "unknown")),
                    error=str(exc),
                )

        if errors > 0:
            logger.warning(
                "fingerprint_batch_errors",
                total=len(evidence_records),
                errors=errors,
                successful=len(fingerprints),
            )

        return fingerprints

    def _extract_canonical(
        self, evidence_record: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Extract canonical fields for fingerprinting.

        Handles both flat DB records and nested finding_data JSONB.
        """
        canonical: dict[str, Any] = {}

        # Try flat fields first (from DB columns)
        for field in FINGERPRINT_FIELDS:
            value = evidence_record.get(field)
            if value is not None:
                canonical[field] = value

        # If flat fields missing, try nested finding_data
        finding_data = evidence_record.get("finding_data", {})
        if isinstance(finding_data, dict):
            # Extract from nested source
            source = finding_data.get("source", {})
            crypto = finding_data.get("crypto", {})

            if "algorithm" not in canonical:
                canonical["algorithm"] = crypto.get("algorithm", "UNKNOWN")
            if "mode" not in canonical:
                canonical["mode"] = crypto.get("mode")
            if "file_path" not in canonical:
                canonical["file_path"] = source.get("file_path", "")
            if "line_number" not in canonical:
                canonical["line_number"] = source.get("line_number")
            if "class_name" not in canonical:
                canonical["class_name"] = source.get("class_name")
            if "method_name" not in canonical:
                canonical["method_name"] = source.get("method_name")

        # Normalize values
        canonical["algorithm"] = self._normalize_algorithm(
            canonical.get("algorithm", "UNKNOWN")
        )
        canonical["file_path"] = self._normalize_path(
            canonical.get("file_path", "")
        )

        return canonical

    def _compute_hash(self, canonical: dict[str, Any]) -> str:
        """
        Compute SHA-256 hash of canonical fields.

        Uses sorted JSON serialization for determinism.
        """
        # Only include defined fingerprint fields, sorted
        fingerprint_data = {
            k: v
            for k, v in canonical.items()
            if k in FINGERPRINT_FIELDS and v is not None
        }

        # Canonical JSON: sorted keys, no whitespace
        canonical_json = json.dumps(
            fingerprint_data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=str,  # Handle non-serializable types
        )

        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    @staticmethod
    def _normalize_algorithm(algorithm: str) -> str:
        """Normalize algorithm name for consistent fingerprinting."""
        if not algorithm:
            return "UNKNOWN"
        # Uppercase and strip whitespace
        return algorithm.upper().strip()

    @staticmethod
    def _normalize_path(file_path: str) -> str:
        """
        Normalize file path for consistent fingerprinting.

        Removes workspace/temp prefixes that vary between runs.
        """
        if not file_path:
            return ""

        # Normalize path separators
        normalized = file_path.replace("\\", "/")

        # Remove common temp prefixes
        prefixes_to_strip = [
            "/tmp/cryptoscan/",
            "/workspace/",
            "/var/tmp/",
        ]
        for prefix in prefixes_to_strip:
            if normalized.startswith(prefix):
                # Find repo root (first component after prefix)
                rest = normalized[len(prefix):]
                # Skip the job-specific UUID directory
                parts = rest.split("/", 1)
                if len(parts) > 1:
                    normalized = parts[1]
                break

        return normalized