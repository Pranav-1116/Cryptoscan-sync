"""Cross-BOM associations and observed-value comparison (advanced/46).

A canonical key groups comparable components, not necessarily the same
physical asset: crypto keys group by algorithm, for example. Each observed
field retains its BOM and component ref. Variation among rows in one BOM is
reported separately from disagreements between unambiguous BOM values.
Only supplied documents are indexed; this module does not infer missing
inventory or merge the independent generators.
"""

from __future__ import annotations

import re
from typing import Any, Mapping


def _norm_name(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip())


def _norm_algorithm(value: Any) -> str:
    return _norm_name(value).upper()


def canonical_identity(component: Mapping[str, Any]) -> dict[str, str] | None:
    """Canonical grouping key, not a physical asset ID; None if unavailable."""
    ctype = _norm_name(component.get("type")).lower()
    name = _norm_name(component.get("name"))
    if ctype in ("cryptographic-asset", "crypto"):
        # The NBOM also emits cryptographic-asset rows for certificates,
        # cipher suites and tunnels; their names are NOT algorithm evidence.
        algorithm = _norm_algorithm(
            component.get("algorithm")
            or _dig(component, ("cryptoProperties", "algorithmProperties", "algorithm")))
        if not algorithm:
            return None
    elif ctype == "hardware":
        # TechBOM hardware rows have a model and asset reference, not a name.
        model = _norm_name(component.get("model"))
        hw_id = _norm_name(component.get("hardware_id") or component.get("serial_reference"))
        if not model and not hw_id:
            return None
    elif ctype == "device":
        # HBOM CycloneDX emits asset_id as a property, not a top-level field.
        hw_id = _norm_name(next((p.get("value") for p in (component.get("properties") or [])
                                 if isinstance(p, Mapping) and p.get("name") == "asset_id"), None))
        if hw_id:
            return {"kind": "hardware", "identity": f"hardware:{hw_id.lower()}",
                    "label": hw_id}
        network_kind = next((p.get("value") for p in (component.get("properties") or [])
                             if isinstance(p, Mapping) and p.get("name") == "cryptoscan:kind"), None)
        if network_kind == "endpoint" and name:
            return {"kind": "endpoint", "identity": f"endpoint:{name.lower()}",
                    "label": name}
        if not name:
            return None
    elif not name:
        return None
    if ctype in ("cryptographic-asset", "crypto"):
        # This associates uses of an algorithm; it cannot establish that
        # two observations describe the same key, device, or deployment.
        return {"kind": "crypto", "identity": f"crypto:{algorithm}",
                "label": algorithm}

    if ctype == "vendor" or (ctype == "service" and any(
            isinstance(p, Mapping) and p.get("name") == "cryptoscan:vendor-id"
            for p in (component.get("properties") or []))):
        # An empty-inventory VBOM vendor is serialized as a CycloneDX service.
        return {"kind": "vendor", "identity": f"vendor:{name.lower()}",
                "label": name}

    if ctype in ("application", "service"):
        return {"kind": "application", "identity": f"application:{name.lower()}",
                "label": name}

    if ctype == "hardware":
        # A model groups many devices; prefer the source's reference when present.
        return {"kind": "hardware",
                "identity": f"hardware:{(hw_id or model).lower()}",
                "label": hw_id or model}

    # NBOM listener and device names are separate namespaces.
    if ctype in ("network", "endpoint"):
        return {"kind": "endpoint", "identity": f"endpoint:{name.lower()}",
                "label": name}
    if ctype == "device":
        return {"kind": "network-device", "identity": f"network-device:{name.lower()}",
                "label": name}

    return None


def _dig(mapping: Mapping[str, Any], path: tuple[str, ...]) -> Any:
    current: Any = mapping
    for key in path:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


def _key_size(component: Mapping[str, Any]) -> str:
    raw = (component.get("key_size")
           or _dig(component, ("cryptoProperties", "algorithmProperties",
                               "parameterSetIdentifier")))
    if raw in (None, "", "None"):
        return ""
    return str(raw).strip()


#: fields compared across BOMs for agreement (None = not comparable)
_COMPARABLE_FIELDS: tuple[tuple[str, str], ...] = (
    ("key_size", "key size"),
    ("mode", "mode"),
    ("purpose", "purpose"),
    ("risk_level", "risk level"),
    ("lifecycle", "lifecycle"),
)


def _comparable_values(component: Mapping[str, Any]) -> dict[str, str]:
    values: dict[str, str] = {}
    if component.get("type") in ("cryptographic-asset", "crypto"):
        size = _key_size(component)
        if size:
            values["key size"] = size
        mode = _dig(component, ("cryptoProperties", "algorithmProperties", "mode")) \
            or component.get("mode")
        if _norm_name(mode):
            values["mode"] = _norm_name(mode)
        purpose = component.get("purpose")
        if _norm_name(purpose):
            values["purpose"] = _norm_name(purpose)
    if _norm_name(component.get("risk_level")):
        values["risk level"] = _norm_name(component["risk_level"]).upper()
    if _norm_name(component.get("lifecycle")):
        values["lifecycle"] = _norm_name(component["lifecycle"]).upper()
    return values


def _iter_components(document: Mapping[str, Any]):
    """Components of any document shape: top-level, layers, or nbom style."""
    if isinstance(document.get("components"), list):
        yield from document["components"]
    layers = document.get("layers")
    if isinstance(layers, Mapping):
        for layer in layers.values():
            if isinstance(layer, Mapping) and isinstance(layer.get("components"), list):
                yield from layer["components"]


def index_bom(bom_kind: str, document: Mapping[str, Any]) -> list[dict[str, Any]]:
    """One document → identity rows (with provenance, no value merging)."""
    rows: list[dict[str, Any]] = []
    for component in _iter_components(document):
        if not isinstance(component, Mapping):
            continue
        ident = canonical_identity(component)
        if ident is None:
            continue
        rows.append({
            "bom": bom_kind,
            "kind": ident["kind"],
            "identity": ident["identity"],
            "label": ident["label"],
            "ref": _norm_name(component.get("bom-ref")) or None,
            "values": _comparable_values(component),
        })
    return rows


def compare_members(members: list[dict[str, Any]]) -> tuple[list[dict[str, Any]],
                                                           list[dict[str, Any]]]:
    """Compare per-component observations without collapsing rows within a BOM.

    A field is a cross-BOM disagreement only if each reporting BOM has one
    unambiguous value and those values differ. Mixed values within a BOM
    remain visible as variation, not an assertion that distinct assets clash.
    """
    fields: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for member in members:
        for field, value in member["values"].items():
            fields.setdefault(field, {}).setdefault(member["bom"], []).append({
                "bom": member["bom"], "ref": member["ref"], "value": value,
            })

    conflicts: list[dict[str, Any]] = []
    variations: list[dict[str, Any]] = []
    for field, by_bom in sorted(fields.items()):
        distinct_by_bom = {bom: {row["value"] for row in rows}
                           for bom, rows in by_bom.items()}
        for bom, distinct in sorted(distinct_by_bom.items()):
            if len(distinct) > 1:
                variations.append({
                    "field": field, "bom": bom,
                    "values": sorted(by_bom[bom], key=lambda row: (row["value"], row["ref"] or "")),
                })
        if len(by_bom) > 1 and all(len(values) == 1 for values in distinct_by_bom.values()) \
                and len(set.union(*distinct_by_bom.values())) > 1:
            conflicts.append({
                "field": field,
                "values": sorted((row for rows in by_bom.values() for row in rows),
                                 key=lambda row: (row["bom"], row["ref"] or "", row["value"])),
            })
    return conflicts, variations


def cross_boms(boms: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Links + conflicts across every indexed BOM. Pure, no DB."""
    rows: list[dict[str, Any]] = []
    for bom_kind, document in boms.items():
        rows.extend(index_bom(bom_kind, document or {}))

    by_identity: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_identity.setdefault(row["identity"], []).append(row)

    links: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    variations: list[dict[str, Any]] = []
    for identity, members in sorted(by_identity.items()):
        boms_present = sorted({m["bom"] for m in members})
        field_conflicts, field_variations = compare_members(members)
        conflicts.extend({"identity": identity, **entry} for entry in field_conflicts)
        variations.extend({"identity": identity, **entry} for entry in field_variations)
        if len(boms_present) < 2:
            continue
        links.append({
            "identity": identity,
            "kind": members[0]["kind"],
            "label": members[0]["label"],
            "relationship": ("algorithm_association" if members[0]["kind"] == "crypto"
                             else "attribute_association"),
            "asset_identity_confirmed": False,
            "present_in": [
                {"bom": m["bom"], "ref": m["ref"]} for m in members],
            "bom_count": len(boms_present),
        })

    return {
        "model": "cross-bom/linking-v1",
        "boms": sorted(boms.keys()),
        "indexed": len(rows),
        "linked_identities": len(links),
        "links": links,
        "conflict_count": len(conflicts),
        "conflicts": conflicts,
        "variation_count": len(variations),
        "variations": variations,
        "note": "Canonical keys associate matching algorithms/names, not confirmed "
                "physical assets. Mixed values within one BOM are variations, "
                "not cross-BOM conflicts. The single-generator merge remains open (46).",
    }
