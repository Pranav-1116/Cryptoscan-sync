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

from shared_models.asset_identity import crypto_asset_key_from_row

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


def software_component(row: dict[str, Any]) -> dict[str, Any]:
    """A package or crypto library a scan declared — an SBOM component.

    Two fields carry the honesty of this row: ``origin`` says whether the scanner
    saw the library referenced by code or only by a manifest, and
    ``declared_not_installed`` states that a coordinate in a manifest is a build
    declaration, not an installed package. Neither is a guess: both come from the
    scan's own cascade report.
    """
    kind = str(row.get("component_type") or "package")
    ecosystem = str(row.get("ecosystem") or "")
    name = row.get("name") or "unknown"
    version = row.get("version") or "unknown"
    coordinate = str(row.get("coordinate") or (f"{ecosystem}/{name}" if ecosystem else f"{kind}/{name}"))
    return {
        "type": "library" if kind == "library" else "package",
        "name": name,
        "version": version,
        "supplier": ecosystem or "declared",
        "asset": coordinate,
        "environment": "",
        "criticality": "crypto" if row.get("crypto_bearing") else "",
        "bom-ref": f"{kind}:{coordinate}",
        "ecosystem": ecosystem or None,
        "origin": row.get("origin") or "MANIFEST_DECLARED",
        "declared_in": row.get("declared_in"),
        "dependency_type": row.get("dependency_type"),
        "direct": row.get("direct"),
        "algorithms": list(row.get("algorithms") or []),
        "declared_but_unused": bool(row.get("declared_but_unused")),
        "used_but_undeclared": bool(row.get("used_but_undeclared")),
        "crypto_bearing": bool(row.get("crypto_bearing")),
        "declared_not_installed": True,
    }


def crypto_layer_component(row: dict[str, Any]) -> dict[str, Any]:
    from shared_models.import_provenance import project_import_provenance
    row = project_import_provenance(row)
    return {
        **{key: row[key] for key in ("source_basis", "reported_confidence", "source_disposition") if key in row},
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
    from shared_models.import_provenance import project_import_provenance
    data = project_import_provenance(data)
    normalized = data.get("normalized_crypto") or {}
    algorithm = str(data.get("algorithm") or normalized.get("standard_name") or "UNKNOWN")
    primitive = normalized.get("algorithm_family") or map_primitive(algorithm, data.get("purpose"))
    oid = lookup_oid(algorithm)
    # Evidence confidence (report 08 P1#6): the recorded confidence of
    # the observation, not a hardcoded 0.9. Unrecorded stays at the
    # source-analysis default — never fabricated upward.
    declared = data.get("source_basis") in {"IMPORTED", "IMPORTED_DECLARATIONS_NOT_SCANNER_OBSERVATIONS", "LEGACY_IMPORT_REVIEW_REQUIRED"}
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
        },
        "evidence": {
            "identity": [
                {
                    "field": "bom-ref",
                    "confidence": method_confidence if declared else 1,
                    "methods": [
                        {
                            "technique": "other" if declared else "source-code-analysis",
                            "confidence": method_confidence,
                            "value": "Imported declaration metadata; deployment unverified" if declared else f"{data.get('file_path')}:{data.get('line_number')}",
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
    # §4.2 identity spine (round 57): the same canonical key as the
    # crypto_assets row and the fact row — a BOM component joins back to
    # the write side without inventing identity.
    spine_key = crypto_asset_key_from_row(data)
    if spine_key and data.get("algorithm"):
        properties.append({"name": "cryptoscan:asset_key", "value": spine_key})
    if data.get("system_name"):
        properties.append({"name": "cryptoscan:system", "value": str(data["system_name"])})
    if data.get("system_id"):
        properties.append({"name": "cryptoscan:system_id", "value": str(data["system_id"])})
    if recorded:
        properties.append({"name": "cryptoscan:confidence", "value": recorded})
    # CycloneDX 1.5/1.6 cryptoProperties has no `quantumVulnerable`; the status
    # travels as a namespaced property with its basis (review item 15). A boolean
    # could not distinguish "Grover-weakened but acceptable" from "Shor-broken".
    from cbom import pqc_handoff
    properties.extend(pqc_handoff.component_properties(algorithm, data.get("key_size")))
    # Bank business context is caller-supplied metadata, not independently verified.
    # Explicit allowlist: never copy arbitrary finding_data or key/secret values.
    for field in ("application", "owner", "data_classification", "retention_years", "criticality", "exposure", "purpose", "library"):
        value = data.get(field)
        if value is not None and isinstance(value, (str, int, float)) and not isinstance(value, bool):
            properties.append({"name": f"cryptoscan:{field}", "value": str(value)})
    # Preserve imported declarations independently of operational owner fields.
    # This is allowlisted context, not a copy of the uploaded document.
    source_extra = data.get("extra") if isinstance(data.get("extra"), dict) else {}
    imported = source_extra.get("cbom_import")
    imported = imported if isinstance(imported, dict) else {}
    if imported:
        if imported.get("padding") is not None:
            component["cryptoProperties"]["algorithmProperties"]["padding"] = imported["padding"]
        import json
        for context in imported.get("business_contexts") or []:
            properties.append({"name": "cryptoscan:business_context", "value": json.dumps(context, sort_keys=True)})
        for key in ("source_basis", "document_sha256", "parameter_set_identifier", "key_size_basis"):
            if imported.get(key) is not None:
                properties.append({"name": f"cryptoscan:import_{key}", "value": str(imported[key])})
    for key in ("source_basis", "reported_confidence"):
        if data.get(key) is not None:
            properties.append({"name": f"cryptoscan:{key}", "value": str(data[key])})
    if data.get("host_evidence"):
        from shared_models.host_collection import HostEvidenceRef
        host = HostEvidenceRef.model_validate(data["host_evidence"])
        for key, value in host.model_dump(mode="json").items():
            properties.append({"name": f"cryptoscan:host:{key}", "value": str(value)})
    if data.get("is_hardcoded_key") is True:
        properties.append({"name": "cryptoscan:hardcoded_key", "value": "true"})
    # Evidence-backed parameters the asset row itself has no column for
    # (named curve, negotiated cipher suites) — supplied by the assembler from
    # linked evidence, never inferred from the key size.
    if isinstance(data.get("curve"), str) and data["curve"]:
        component["cryptoProperties"]["algorithmProperties"]["curve"] = data["curve"]
        properties.append({"name": "cryptoscan:curve", "value": data["curve"]})
    # Assembler-built evidence chain: richer occurrences (evidence id, symbol,
    # scan/commit context) and generated provenance properties. Names are
    # restricted to CryptoScan's own namespace; the 1.6 projection allowlists
    # them again.
    if isinstance(data.get("cbom_occurrences"), list) and data["cbom_occurrences"]:
        component["evidence"]["occurrences"] = [dict(o) for o in data["cbom_occurrences"] if isinstance(o, dict)]
    for prop in data.get("cbom_properties") or []:
        if isinstance(prop, dict) and str(prop.get("name", "")).startswith("cryptoscan:"):
            properties.append({"name": str(prop["name"]), "value": str(prop.get("value", ""))})
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
