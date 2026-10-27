"""VBOM — Vendor Bill of Materials (advanced/46 P1#5, round 30 build).

A VBOM is the vendor-facing slice of the crypto estate: one entry per
external vendor, carrying the vendor's own crypto inventory (from
questionnaire, SBOM import, doc extraction, or API scan), the systems
that depend on that vendor, and the latest due-diligence profile state.

The generator is PURE: it assembles plain dicts, so the document shape
is testable without a database. :func:`build_vbom` is the DB-facing
assembler that feeds it from ``vendors`` + ``vendor_crypto_inventory`` +
``system_vendors`` + ``vendor_profile_revisions`` (the surfaces report
46 named: "From vendor_intel + vendor_crypto").

Every inventory entry carries its own provenance (discovery_method,
confidence, discovered_at, verified_at, source_document) — the evidence
cross-reference advanced/46 §7.2 asked BOM components to carry.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Optional


def _iso(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


class VbomGenerator:
    """Assemble vendor entries into native + CycloneDX-style documents."""

    def __init__(self) -> None:
        self._vendors: dict[str, dict[str, Any]] = {}

    # ── assembly ────────────────────────────────────────────────────

    def add_vendor(
        self,
        vendor: Mapping[str, Any],
        *,
        inventory: Iterable[Mapping[str, Any]] = (),
        systems: Iterable[Mapping[str, Any]] = (),
        profile: Optional[Mapping[str, Any]] = None,
    ) -> dict[str, Any]:
        """Add or replace one vendor entry.

        ``vendor`` needs ``id``/``name``; ``inventory`` rows are the
        vendor_crypto_inventory shape (algorithm, key_size, mode,
        crypto_use_case, key_management, pqc_ready, discovery_method,
        confidence, discovered_at, verified_at, source_document);
        ``systems`` rows are {system_id, system_name?, dependency_type?}.
        """
        vendor_id = str(vendor.get("id") or vendor.get("vendor_id") or "").strip()
        if not vendor_id:
            raise ValueError("vendor entry requires an id")
        entries = []
        for row in inventory or ():
            entry = dict(row)
            entry["pqc_ready"] = bool(row.get("pqc_ready"))
            # DB rows arrive ISO-ified via to_dict; pure callers may pass
            # datetimes — normalize so the document shape is stable.
            for stamp in ("discovered_at", "verified_at"):
                if entry.get(stamp) is not None:
                    entry[stamp] = _iso(entry[stamp])
            entries.append(entry)
        pqc_ready = sum(1 for e in entries if e["pqc_ready"])
        entry_block = {
            "bom-ref": f"vendor:{vendor_id}",
            "vendor_id": vendor_id,
            "name": vendor.get("name") or vendor_id,
            "vendor_type": vendor.get("vendor_type"),
            "criticality": vendor.get("criticality"),
            "integration_type": vendor.get("integration_type"),
            "contacts": {
                "primary": vendor.get("primary_contact"),
                "security": vendor.get("security_contact"),
                "technical": vendor.get("technical_contact"),
            },
            "contract_end_date": _iso(vendor.get("contract_end_date")),
            "data_classifications": list(vendor.get("data_classifications") or []),
            "systems": [
                {
                    "system_id": s.get("system_id"),
                    "system_name": s.get("system_name"),
                    "dependency_type": s.get("dependency_type"),
                }
                for s in systems or ()
            ],
            "profile": dict(profile) if profile else None,
            "crypto": entries,
            "pqc_coverage": {
                "entries": len(entries),
                "pqc_ready": pqc_ready,
                "not_ready": len(entries) - pqc_ready,
            },
        }
        self._vendors[vendor_id] = entry_block
        return entry_block

    def remove_vendor(self, vendor_id: str) -> bool:
        existed = self._vendors.pop(str(vendor_id), None) is not None
        return existed

    # ── output ──────────────────────────────────────────────────────

    def vendors(self) -> list[dict[str, Any]]:
        return sorted(self._vendors.values(), key=lambda v: (v["name"], v["vendor_id"]))

    def summary(self) -> dict[str, Any]:
        rows = list(self._vendors.values())
        entries = [e for v in rows for e in v["crypto"]]
        pqc_ready = sum(1 for e in entries if e.get("pqc_ready"))
        by_confidence: dict[str, int] = {}
        for entry in entries:
            key = str(entry.get("confidence") or "UNKNOWN").upper()
            by_confidence[key] = by_confidence.get(key, 0) + 1
        legacy = sum(
            1
            for v in rows
            if (v.get("contract_end_date") is None)
        )
        return {
            "vendors": len(rows),
            "crypto_entries": len(entries),
            "pqc_ready_entries": pqc_ready,
            "pqc_ready_pct": round(100.0 * pqc_ready / len(entries), 1) if entries else 0.0,
            "vendors_with_inventory": sum(1 for v in rows if v["crypto"]),
            "systems_linked": sum(len(v["systems"]) for v in rows),
            "entries_by_confidence": by_confidence,
            "vendors_missing_contract_end": legacy,
        }

    def to_document(self, *, name: str = "zelinx-vbom") -> dict[str, Any]:
        return {
            "vbomFormat": "ZELNX-VBOM",
            "version": 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "name": name,
            "summary": self.summary(),
            "vendors": self.vendors(),
        }

    def to_cyclonedx(self, *, name: str = "zelinx-vbom") -> dict[str, Any]:
        """CycloneDX-style export.

        Each vendor crypto inventory entry becomes a ``cryptographic-asset``
        component with ``supplier`` naming the vendor and cryptoProperties
        carrying the algorithm parameters; vendor-level facts ride as
        properties so nothing in the native document is lost.
        """
        components: list[dict[str, Any]] = []
        for vendor in self.vendors():
            vid = vendor["vendor_id"]
            base_props = [
                {"name": "cryptoscan:vendor-id", "value": vid},
                {"name": "cryptoscan:criticality", "value": vendor.get("criticality") or ""},
                {"name": "cryptoscan:vendor-type", "value": vendor.get("vendor_type") or ""},
            ]
            if not vendor["crypto"]:
                # vendor with no inventory yet still appears, honestly
                # flagged, rather than vanishing from the document
                components.append({
                    "type": "service",
                    "name": vendor["name"],
                    "bom-ref": f"vbom:{vid}",
                    "supplier": {"name": vendor["name"]},
                    "properties": base_props + [
                        {"name": "cryptoscan:inventory", "value": "none-declared"},
                    ],
                })
                continue
            for index, entry in enumerate(vendor["crypto"]):
                ref = f"vbom:{vid}:{index}"
                if entry.get("algorithm"):
                    ref = f"vbom:{vid}:{entry['algorithm']}:{index}"
                props = list(base_props) + [
                    {"name": "cryptoscan:use-case", "value": str(entry.get("crypto_use_case") or "")},
                    {"name": "cryptoscan:key-management", "value": str(entry.get("key_management") or "")},
                    {"name": "cryptoscan:pqc-ready", "value": str(bool(entry.get("pqc_ready"))).lower()},
                    {"name": "cryptoscan:discovery-method", "value": str(entry.get("discovery_method") or "")},
                    {"name": "cryptoscan:confidence", "value": str(entry.get("confidence") or "")},
                ]
                components.append({
                    "type": "cryptographic-asset",
                    "name": f"{vendor['name']}: {entry.get('algorithm') or 'undeclared algorithm'}",
                    "bom-ref": ref,
                    "supplier": {"name": vendor["name"]},
                    "cryptoProperties": {
                        "assetType": "algorithm",
                        "algorithmProperties": {
                            "algorithm": entry.get("algorithm"),
                            "parameterSetIdentifier": (
                                str(entry["key_size"]) if entry.get("key_size") is not None else None
                            ),
                            "mode": entry.get("mode"),
                        },
                        "oid": None,
                    },
                    "evidence": {
                        "properties": [
                            {"name": "cryptoscan:discovered-at", "value": _iso(entry.get("discovered_at")) or ""},
                            {"name": "cryptoscan:verified-at", "value": _iso(entry.get("verified_at")) or ""},
                            {"name": "cryptoscan:source-document", "value": str(entry.get("source_document") or "")},
                        ],
                    },
                    "properties": props,
                })
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "component": {"type": "service", "name": name},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            "components": components,
        }


# ── DB assembler ─────────────────────────────────────────────────────


def build_vbom(session, vendor_id: str | None = None) -> VbomGenerator:
    """Assemble a VBOM from the vendor tables.

    ``vendor_id=None`` builds the estate-wide document. Uses the same
    repositories the vendor routers use, so tenant scoping and soft
    deletes behave identically to every other vendor surface.
    """
    from db.models.system import System
    from db.models.vendor import SystemVendor
    from db.repositories.intelligence_repository import IntelligenceRepository
    from db.repositories.maturity_repository import MaturityRepository
    from db.repositories.vendor_profile_repository import VendorProfileRepository
    from sqlalchemy import select

    intel = IntelligenceRepository(session)
    maturity = MaturityRepository(session)
    profiles = VendorProfileRepository(session)

    vendors = (
        [intel.get_vendor(vendor_id)]
        if vendor_id is not None
        else list(intel.list_vendors())
    )
    gen = VbomGenerator()
    for vendor in vendors:
        if vendor is None:
            raise ValueError("vendor not found")
        systems = []
        links = session.execute(
            select(SystemVendor).where(SystemVendor.vendor_id == vendor.id)
        ).scalars().all()
        if links:
            rows = session.execute(
                select(System).where(System.id.in_([l.system_id for l in links]))
            ).scalars().all()
            names = {s.id: s.name for s in rows}
            for link in links:
                systems.append({
                    "system_id": link.system_id,
                    "system_name": names.get(link.system_id),
                    "dependency_type": link.dependency_type,
                })
        profile_row = profiles.latest(vendor.id)
        profile = None
        if profile_row is not None:
            profile = {
                "revision": profile_row.revision,
                "status": profile_row.status,
                "schema_version": profile_row.schema_version,
                "source": profile_row.source,
                "captured_at": _iso(profile_row.captured_at),
                "completeness": profile_row.completeness_json,
            }
        gen.add_vendor(
            {
                "id": vendor.id,
                "name": vendor.name,
                "vendor_type": vendor.vendor_type,
                "criticality": vendor.criticality,
                "integration_type": vendor.integration_type,
                "primary_contact": vendor.primary_contact,
                "security_contact": vendor.security_contact,
                "technical_contact": vendor.technical_contact,
                "contract_end_date": vendor.contract_end_date,
                "data_classifications": vendor.data_classifications or [],
            },
            inventory=[row.to_dict() for row in maturity.list_vendor_crypto(vendor.id)],
            systems=systems,
            profile=profile,
        )
    return gen
