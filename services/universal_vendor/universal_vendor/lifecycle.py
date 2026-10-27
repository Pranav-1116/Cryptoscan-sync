"""Vendor lifecycle + vulnerability context (spec §23).

For each discovered product: vendor / product / version / support status /
end of support / end of life / crypto relevance — connected to migration
planning ("legacy firewall + PQC migration required + EOS soon → higher
migration priority").

External lifecycle intelligence is versioned and evidence-backed. Only
widely-documented milestones are seeded; everything else is UNKNOWN.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from universal_vendor.models import LifecycleStatus

DB_VERSION = "2026-08"


@dataclass(frozen=True)
class LifecycleEntry:
    vendor: str
    product: str
    version: Optional[str]
    support_status: str
    end_of_support: Optional[str]
    end_of_life: Optional[str]
    crypto_relevance: str
    evidence_source: str = ""
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "vendor": self.vendor,
            "product": self.product,
            "version": self.version,
            "support_status": self.support_status,
            "end_of_support": self.end_of_support,
            "end_of_life": self.end_of_life,
            "crypto_relevance": self.crypto_relevance,
            "evidence_source": self.evidence_source,
            "confidence": self.confidence,
        }


# Evidence-backed protocol/OS milestones (public, widely documented):
#   - TLS 1.0/1.1 deprecated by RFC 8996 (March 2021)
#   - Windows Server 2012/2012 R2 EOL 2023-10-10
#   - Windows Server 2008/2008 R2 EOL 2020-01-14
#   - Ubuntu 16.04 LTS standard support EOL 2021-04-30
#   - NIST SP 800-131A Rev.2 (2019): SHA-1 disallowed for signatures
#   - CA/Browser Forum: SHA-1 cert issuance prohibited from 2016-01-01
_SEED: list[LifecycleEntry] = [
    LifecycleEntry(
        vendor="IETF", product="TLS", version="1.0/1.1",
        support_status=LifecycleStatus.END_OF_LIFE.value,
        end_of_support="2021-03-25", end_of_life="2021-03-25",
        crypto_relevance="protocol deprecated; no PQC suite support",
        evidence_source="RFC 8996 (2021-03): TLS 1.0/1.1 deprecated",
        confidence=0.99,
    ),
    LifecycleEntry(
        vendor="Microsoft", product="Windows Server", version="2012/2012 R2",
        support_status=LifecycleStatus.END_OF_SUPPORT.value,
        end_of_support="2023-10-10", end_of_life="2023-10-10",
        crypto_relevance="OS TLS stack frozen; no new cipher suites",
        evidence_source="Microsoft lifecycle documentation",
        confidence=0.98,
    ),
    LifecycleEntry(
        vendor="Microsoft", product="Windows Server", version="2008/2008 R2",
        support_status=LifecycleStatus.END_OF_LIFE.value,
        end_of_support="2020-01-14", end_of_life="2020-01-14",
        crypto_relevance="OS TLS stack frozen; legacy ciphers only",
        evidence_source="Microsoft lifecycle documentation",
        confidence=0.98,
    ),
    LifecycleEntry(
        vendor="Canonical", product="Ubuntu", version="16.04 LTS",
        support_status=LifecycleStatus.END_OF_SUPPORT.value,
        end_of_support="2021-04-30", end_of_life="2021-04-30",
        crypto_relevance="older OpenSSL; ESM-only security patching",
        evidence_source="Canonical Ubuntu release lifecycle",
        confidence=0.95,
    ),
    LifecycleEntry(
        vendor="NIST", product="SHA-1", version="any",
        support_status=LifecycleStatus.END_OF_SUPPORT.value,
        end_of_support="2019-03-11", end_of_life=None,
        crypto_relevance="SHA-1 disallowed for digital signatures",
        evidence_source="NIST SP 800-131A Rev.2 (2019)",
        confidence=0.99,
    ),
    LifecycleEntry(
        vendor="CA/Browser Forum", product="SHA-1 certificates", version="any",
        support_status=LifecycleStatus.END_OF_SUPPORT.value,
        end_of_support="2016-01-01", end_of_life="2016-01-01",
        crypto_relevance="SHA-1 cert issuance prohibited",
        evidence_source="CA/Browser Forum ballot (2016-01-01)",
        confidence=0.98,
    ),
]


class VendorLifecycleDatabase:
    def __init__(self, version: str = DB_VERSION) -> None:
        self.version = version
        self._entries: list[LifecycleEntry] = list(_SEED)

    def add(self, entry: LifecycleEntry) -> None:
        self._entries.append(entry)

    def lookup(self, vendor: str, product: str,
               version: str | None = None) -> LifecycleEntry | None:
        candidates = [
            entry for entry in self._entries
            if entry.vendor.lower() == vendor.lower()
            and entry.product.lower() in product.lower()
        ]
        if not candidates:
            return None
        if version:
            for entry in candidates:
                if entry.version and str(entry.version).lower() in str(version).lower():
                    return entry
        return max(candidates, key=lambda entry: entry.confidence)

    def status(self, vendor: str, product: str,
               version: str | None = None) -> dict[str, Any]:
        entry = self.lookup(vendor, product, version)
        if entry is None:
            return {
                "vendor": vendor, "product": product, "version": version,
                "support_status": LifecycleStatus.UNKNOWN.value,
                "reason": "no verified lifecycle entry; NOT inferred",
                "db_version": self.version,
            }
        return {
            "vendor": entry.vendor, "product": entry.product,
            "version": entry.version or version,
            "support_status": entry.support_status,
            "end_of_support": entry.end_of_support,
            "end_of_life": entry.end_of_life,
            "crypto_relevance": entry.crypto_relevance,
            "evidence_source": entry.evidence_source,
            "confidence": entry.confidence,
            "db_version": self.version,
        }

    def migration_priority(self, vendor: str, product: str,
                           version: str | None = None,
                           *, pqc_required: bool = False) -> dict[str, Any]:
        """Spec §23 example: legacy + PQC-migration-required + EOS → high."""
        lifecycle = self.status(vendor, product, version)
        status = lifecycle.get("support_status")
        eos_soon = lifecycle.get("end_of_support") is not None
        priority = "LOW"
        if pqc_required and status in (LifecycleStatus.END_OF_SUPPORT.value,
                                       LifecycleStatus.END_OF_LIFE.value):
            priority = "HIGH"
        elif pqc_required or eos_soon:
            priority = "MEDIUM"
        return {
            "vendor": vendor, "product": product, "version": version,
            "lifecycle": lifecycle,
            "pqc_required": pqc_required,
            "migration_priority": priority,
        }

    def entries(self) -> list[dict[str, Any]]:
        return [entry.to_dict() for entry in self._entries]

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"VendorLifecycleDatabase(version={self.version!r}, entries={len(self._entries)})"
