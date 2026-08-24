"""
InventoryBuilder — builds fingerprint sets from scan evidence records.

Creates a fingerprint inventory (dict mapping hash → record) for
efficient O(1) lookup during drift comparison.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

import structlog

from drift.fingerprinting.fingerprinter import Fingerprint, Fingerprinter

logger = structlog.get_logger(__name__)


@dataclass
class CryptoInventory:
    """
    A set of fingerprinted crypto findings from one scan.

    Provides O(1) lookup by fingerprint hash.
    """
    scan_id: UUID
    fingerprints: dict[str, Fingerprint] = field(default_factory=dict)
    records_by_hash: dict[str, dict[str, Any]] = field(default_factory=dict)
    skipped_count: int = 0

    @property
    def hashes(self) -> set[str]:
        return set(self.fingerprints.keys())

    @property
    def total_count(self) -> int:
        return len(self.fingerprints)

    def get_record(self, fingerprint_hash: str) -> dict[str, Any] | None:
        return self.records_by_hash.get(fingerprint_hash)

    def get_fingerprint(self, fingerprint_hash: str) -> Fingerprint | None:
        return self.fingerprints.get(fingerprint_hash)


class InventoryBuilder:
    """
    Builds CryptoInventory from a list of evidence records.

    Handles:
    - Duplicate fingerprints (same finding at same location)
    - Invalid/unparseable records (skipped with logging)
    - Large inventories efficiently
    """

    def __init__(self, fingerprinter: Fingerprinter | None = None) -> None:
        self._fingerprinter = fingerprinter or Fingerprinter()

    def build(
        self,
        scan_id: UUID,
        evidence_records: list[dict[str, Any]],
    ) -> CryptoInventory:
        """
        Build inventory from list of evidence records.

        Args:
            scan_id: UUID of the scan these records belong to
            evidence_records: List of dicts from evidence_records table

        Returns:
            CryptoInventory with fingerprint → record mapping
        """
        inventory = CryptoInventory(scan_id=scan_id)
        duplicate_count = 0

        log = logger.bind(
            scan_id=str(scan_id),
            total_records=len(evidence_records),
        )
        log.info("building_crypto_inventory")

        for record in evidence_records:
            try:
                fp = self._fingerprinter.fingerprint(record)
                fp_hash = fp.hash

                if fp_hash in inventory.fingerprints:
                    # Duplicate fingerprint — same finding at same location
                    # Keep the first occurrence
                    duplicate_count += 1
                    logger.debug(
                        "duplicate_fingerprint_skipped",
                        fingerprint=fp_hash[:16],
                        algorithm=fp.algorithm,
                        file_path=fp.file_path,
                    )
                    continue

                inventory.fingerprints[fp_hash] = fp
                inventory.records_by_hash[fp_hash] = record

            except Exception as exc:
                inventory.skipped_count += 1
                logger.warning(
                    "evidence_record_fingerprint_failed",
                    evidence_id=str(record.get("evidence_id", "unknown")),
                    error=str(exc),
                )

        log.info(
            "crypto_inventory_built",
            total_fingerprints=inventory.total_count,
            duplicates_skipped=duplicate_count,
            records_skipped=inventory.skipped_count,
        )

        return inventory

    def build_from_scan_id(
        self,
        scan_id: UUID,
        evidence_records: list[dict[str, Any]],
    ) -> CryptoInventory:
        """Alias for build() — explicit naming for clarity in callers."""
        return self.build(scan_id=scan_id, evidence_records=evidence_records)