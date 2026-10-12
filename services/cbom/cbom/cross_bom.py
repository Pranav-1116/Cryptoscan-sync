"""Cross-BOM linking and conflict detection (advanced/46, round 36).

Report 46's finding: five BOMs, zero shared identifiers, no linking, no
conflict detection. The TechBOM materializer (one inventory snapshot →
SBOM/CBOM/HBOM/vendor layers) fixed the shared-data-model half. This
module is the linking half: a canonical identity for every component —
across the CBOM generator, the TechBOM layers, the NBOM and the VBOM —
plus two honest questions over that identity:

* where does this thing appear? (links: identity in ≥2 BOMs, with each
  BOM's own ref so a human can jump to it)
* do the BOMs agree about it? (conflicts: same identity, same field,
  different non-empty values — e.g. TechBOM says the key is 2048 bits
  and the CBOM generator row for the same algorithm says 1024)

Identity is deliberately conservative: only fields that mean the same
thing in every BOM participate (algorithm names uppercased and
whitespace-collapsed, component names lowercased). Anything that cannot
be canonically identified stays unlinked — reported as counts, never
inferred. The single-generator merge (three generators → one) remains
the open rearchitecture this report records; this layer links their
outputs without touching them.
"""

from __future__ import annotations

import re
from typing import Any, Mapping


def _norm_name(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip())


def _norm_algorithm(value: Any) -> str:
    return _norm_name(value).upper()


def canonical_identity(component: Mapping[str, Any]) -> dict[str, str] | None:
    """Canonical identity for one component, or None when unidentifiable."""
    ctype = _norm_name(component.get("type")).lower()
    name = _norm_name(component.get("name"))
    if ctype in ("cryptographic-asset", "crypto"):
        # TechBOM crypto rows carry `algorithm`, not `name`; CBOM
        # generator rows carry both. Either names the asset.
        algorithm = _norm_algorithm(
            component.get("algorithm")
            or _dig(component, ("cryptoProperties", "algorithmProperties", "algorithm"))
            or name)
        if not algorithm:
            return None
    else:
        if not name:
            return None
    if ctype in ("cryptographic-asset", "crypto"):
        # identity is the ALGORITHM only — key size/mode/purpose are
        # comparable attributes (disagreements become conflicts, not
        # silently-separate identities)
        return {"kind": "crypto", "identity": f"crypto:{algorithm}",
                "label": algorithm}

    if ctype == "vendor":
        return {"kind": "vendor", "identity": f"vendor:{name.lower()}",
                "label": name}

    if ctype in ("application", "service"):
        return {"kind": "application", "identity": f"application:{name.lower()}",
                "label": name}

    if ctype == "hardware":
        model = _norm_name(component.get("model"))
        hw_id = _norm_name(component.get("hardware_id") or component.get("serial_reference"))
        if model or hw_id:
            return {"kind": "hardware",
                    "identity": f"hardware:{(model or hw_id).lower()}",
                    "label": model or hw_id}
        return None

    # NBOM-style network component: name is usually host:port
    if ctype in ("network", "endpoint", "device"):
        return {"kind": "endpoint", "identity": f"endpoint:{name.lower()}",
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
    for identity, members in sorted(by_identity.items()):
        boms_present = sorted({m["bom"] for m in members})
        if len(boms_present) < 2:
            continue
        links.append({
            "identity": identity,
            "kind": members[0]["kind"],
            "label": members[0]["label"],
            "present_in": [
                {"bom": m["bom"], "ref": m["ref"]} for m in members],
            "bom_count": len(boms_present),
        })
        # conflict: same identity, same comparable field, disagreeing values
        fields: dict[str, dict[str, str]] = {}
        for member in members:
            for field, value in member["values"].items():
                fields.setdefault(field, {})[member["bom"]] = value
        for field, values in sorted(fields.items()):
            distinct = set(values.values())
            if len(distinct) > 1:
                conflicts.append({
                    "identity": identity,
                    "field": field,
                    "values": [{"bom": bom, "value": value}
                               for bom, value in sorted(values.items())],
                })

    return {
        "model": "cross-bom/linking-v1",
        "boms": sorted(boms.keys()),
        "indexed": len(rows),
        "linked_identities": len(links),
        "links": links,
        "conflict_count": len(conflicts),
        "conflicts": conflicts,
        "note": "identities are canonical (algorithm/name-normalized) and "
                "conservative; anything not canonically identifiable stays "
                "unlinked. The single-generator merge remains open (46).",
    }
