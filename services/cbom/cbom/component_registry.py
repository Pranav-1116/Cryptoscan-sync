"""The single component-construction registry (advanced/46, round 38).

Report 46's "three generators" finding closed at the construction
level: every BOM component shape in the platform — TechBOM layer
components, CBOM-generator crypto components, NBOM network components —
is built HERE, in one module. The generators remain as assemblers
(``CbomGenerator``, ``materialize_technology_bom``, ``build_nbom``) but
none of them defines what a component IS anymore; they compose what
this registry constructs. Two generators can no longer drift apart on
identity fields or shapes, because there is one definition of each.

All functions are verbatim moves from the generators (round 38); the
generators' existing outputs are pinned byte-for-byte by their test
suites, which now double as the registry's contract tests.
"""

from __future__ import annotations

from typing import Any, Mapping

from cbom.mappers.oid_lookup import lookup_oid
from cbom.mappers.primitive_mapper import map_primitive

#: recorded confidence -> method score (unchanged semantics from the
#: CBOM generator; evidence-recorded confidence, never fabricated upward)
CONFIDENCE_SCORES = {

    "HIGH": 0.9,
    "CONFIRMED": 0.9,
    "MEDIUM": 0.6,
    "LIKELY": 0.6,
    "LOW": 0.3,
    "TENTATIVE": 0.3,
}


#: the generator's original module-level name, referenced by the
# verbatim-moved body below
_CONFIDENCE_SCORES = CONFIDENCE_SCORES


# ── TechBOM layer components (from technology_bom.py) ────────────────


def app_component(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "application",
        "name": row.get("name") or row.get("id") or "unknown",
        "version": row.get("version") or row.get("tag") or "unknown",
        "supplier": row.get("supplier") or row.get("owner") or "",
        "asset": row.get("asset") or row.get("name") or "",
        "environment": row.get("environment") or "",
        "criticality": row.get("criticality") or "",
        "bom-ref": f"app:{row.get('id') or row.get('name') or 'unknown'}",
    }


def crypto_layer_component(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "crypto",
        "algorithm": (row.get("algorithm") or "").upper(),
        "key_type": row.get("key_type") or "",
        "key_size": row.get("key_size"),
        "purpose": row.get("purpose") or "",
        "mode": row.get("mode") or "",
        "library": row.get("library") or "",
        "asset": row.get("asset") or row.get("host") or "",
        "application": row.get("application") or "",
        "location": row.get("file_path") or row.get("location") or "",
        "pqc_status": row.get("pqc_status") or "",
        "quantum_status": row.get("quantum_status") or "",
        "confidence": row.get("confidence") or "LOW",
        "first_seen": row.get("first_seen"),
        "last_seen": row.get("last_seen"),
        "bom-ref": f"crypto:{row.get('id') or (row.get('algorithm') or '')}:{row.get('asset') or ''}",
    }


def hardware_component(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "hardware",
        "manufacturer": row.get("manufacturer") or "",
        "model": row.get("model") or "",
        "device_type": row.get("device_type") or "other",
        "hardware_id": row.get("asset_id") or row.get("serial_reference") or row.get("id") or "",
        "serial_reference": row.get("serial_reference") or "",
        "firmware_version": (row.get("firmware") or {}).get("version") if isinstance(row.get("firmware"), dict) else row.get("firmware_version") or "",
        "security_module": row.get("security_module") or (
            "hsm" if row.get("hsm") else ("tpm" if row.get("tpm") else "")
        ),
        "asset": row.get("asset") or row.get("asset_id") or "",
        "last_seen": row.get("last_seen"),
        "risk_level": row.get("risk_level") or "",
        "bom-ref": f"hw:{row.get('asset_id') or row.get('id') or 'unknown'}",
    }


def vendor_component(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "vendor",
        "name": row.get("name") or row.get("vendor") or "",
        "product": row.get("product") or "",
        "model": row.get("model") or "",
        "version": row.get("version") or "",
        "assets": row.get("assets") or [],
        "lifecycle": row.get("lifecycle") or "",
        "risk_level": row.get("risk_level") or "",
        "crypto_capability": row.get("crypto_capability") or "",
        "bom-ref": f"vendor:{row.get('name') or row.get('vendor') or 'unknown'}",
    }


# ── CBOM-generator crypto component (from generator.py) ──────────────


def cbom_crypto_component(data: dict[str, Any]) -> dict[str, Any]:
    """One CycloneDX cryptoProperties component from a crypto asset row.

    ``data`` is the row's dict shape (``to_dict()`` or a plain dict) —
    identical inputs to ``CbomGenerator._component`` before round 38.
    """
    normalized = data.get("normalized_crypto") or {}
    algorithm = str(data.get("algorithm") or normalized.get("standard_name") or "UNKNOWN")
    primitive = normalized.get("algorithm_family") or map_primitive(algorithm, data.get("purpose"))
    oid = lookup_oid(algorithm)
    # Evidence confidence (report 08 P1#6): the recorded confidence of
    # the observation, not a hardcoded 0.9. Unrecorded stays at the
    # source-analysis default — never fabricated upward.
    recorded = str(data.get("confidence") or "").upper()
    method_confidence = _CONFIDENCE_SCORES.get(recorded, 0.9)
    component: dict[str, Any] = {
        "type": normalized.get("cbom_component_type") or "cryptographic-asset",
        "name": normalized.get("standard_name") or data.get("algorithm") or "UNKNOWN",
        "bom-ref": data.get("id") or data.get("evidence_id") or data.get("finding_id"),
        "cryptoProperties": {
            "assetType": "algorithm",
            "oid": oid,
            "algorithmProperties": {
                "primitive": primitive,
                "algorithm": data.get("algorithm"),
                "mode": data.get("mode"),
                "padding": data.get("padding"),
                "parameterSetIdentifier": str(data.get("key_size")) if data.get("key_size") else None,
            },
            "nistDesignation": normalized.get("nist_designation"),
            "quantumVulnerable": normalized.get("quantum_vulnerable"),
        },
        "evidence": {
            "identity": [
                {
                    "field": "bom-ref",
                    "confidence": 1,
                    "methods": [
                        {
                            "technique": "source-code-analysis",
                            "confidence": method_confidence,
                            "value": f"{data.get('file_path')}:{data.get('line_number')}",
                        }
                    ],
                }
            ],
            "occurrences": [
                {
                    "location": data.get("file_path"),
                    "line": data.get("line_number"),
                }
            ],
            "file": data.get("file_path"),
            "line": data.get("line_number"),
            "content_hash": data.get("content_hash"),
            "chain_hash": data.get("chain_hash"),
            "compliance_status": data.get("compliance_status"),
        },
    }
    # report 08 P2#7: the discovery location in standard
    # externalReferences form (complements the custom properties)
    location = data.get("file_path")
    if location:
        component["externalReferences"] = [
            {"type": "other", "url": f"file://{location}"}
        ]
    properties: list[dict[str, Any]] = []
    if data.get("system_name"):
        properties.append({"name": "cryptoscan:system", "value": str(data["system_name"])})
    if data.get("system_id"):
        properties.append({"name": "cryptoscan:system_id", "value": str(data["system_id"])})
    if recorded:
        properties.append({"name": "cryptoscan:confidence", "value": recorded})
    if properties:
        component["properties"] = properties
    return component

# ── NBOM network component (from nbom.py) ────────────────────────────


def cyclonedx_component(kind: str, name: str, ref: str, props: Mapping[str, Any],
               findings: list[dict[str, Any]]) -> dict[str, Any]:
    """A CycloneDX component. Properties carry the network facts verbatim."""
    return {
        "type": "cryptographic-asset" if kind in ("cipher-suite", "certificate", "tunnel") else "device",
        "bom-ref": ref,
        "name": name,
        "properties": (
            [{"name": "cryptoscan:kind", "value": kind}]
            + [{"name": f"cryptoscan:{k}", "value": str(v)}
               for k, v in sorted(props.items()) if v is not None]
        ),
        "cryptoscan:findings": findings,
    }
