"""Downloading a BOM from the live twin: CycloneDX 1.6 and the native document.

A BOM that exists as a *file the platform produced* is a different artefact from a
projection of the current twin. This module renders the projection, not a stored copy:
"download the current CBOM" therefore costs one projection and needs no scan, and the
download carries the projection id it was computed from — so two files can be shown to
describe the same instant of the estate, or not.

Two rules the renderer keeps:

* **deterministic.** The CycloneDX ``serialNumber`` is derived from the projection id and
  the BOM kind, and the timestamp is the projection's own ``generated_at``. Re-downloading
  the same projection produces the same document, so a hash comparison is meaningful.
* **limits travel with the document.** The projection's ``boundary``, its unknown counts and
  its coverage caveat are written into CycloneDX ``properties`` under ``cryptoscan:`` keys.
  A BOM handed to an auditor without them invites the reader to assume completeness.

The native format is the projection verbatim, wrapped in an export envelope; nothing is
improved on the way out.
"""

from __future__ import annotations

import uuid
from typing import Any, Mapping

SCHEMA = "cryptoscan.bom-export/1"

#: what a caller may ask for
FORMATS = ("json", "cyclonedx")

#: CycloneDX and the estate's vocabulary are not the same; the mapping is stated, not implied
COMPONENT_TYPES = {
    "LIBRARY": "library",
    "PACKAGE": "library",
    "IMAGE": "container",
    "CONTAINER": "container",
    "POD": "container",
    "HOST": "device",
    "HARDWARE": "device",
    "FIRMWARE": "firmware",
    "APPLICATION": "application",
    "SERVICE": "application",
    "SYSTEM": "application",
    "CLUSTER": "platform",
    "NAMESPACE": "platform",
    "NETWORK_ENDPOINT": "device",
    "LOAD_BALANCER": "device",
    "API_GATEWAY": "device",
    "DATABASE": "application",
    "MESSAGE_BROKER": "application",
    "CLOUD_RESOURCE": "application",
    "HSM": "device",
    "KMS_KEY": "data",
    "VENDOR": "application",
    "CRYPTO_ARTIFACT": "cryptographic-asset",
}

#: CycloneDX 1.6 crypto asset classes
CRYPTO_ASSET_TYPES = {
    "ALGORITHM": "algorithm",
    "PROTOCOL": "protocol",
    "CERTIFICATE": "certificate",
    "KEY": "related-crypto-material",
    "HASH": "algorithm",
    "CIPHER": "algorithm",
}

LIMITS = [
    "a downloaded BOM is a projection of the twin at projection_id, not a stored document: "
    "nothing is served that was not computed from that evidence state",
    "the document is not authoritative for the estate — the twin is, and the twin is built "
    "from evidence, not from this file",
    "CycloneDX cannot express 'UNKNOWN': an asset with no crypto evidence is absent from the "
    "CBOM, and the unknown counts are carried in properties rather than invented components",
    "component type mapping (estate type → CycloneDX type) is stated in this module and is "
    "lossy in both directions",
    "the timestamp is the projection's generation time, which is not the time the estate was "
    "observed",
]


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _component_type(component: Mapping[str, Any]) -> str:
    kind = str(component.get("type") or "").upper()
    if kind == "CRYPTO_ARTIFACT":
        return "cryptographic-asset"
    return COMPONENT_TYPES.get(kind, "application")


def _crypto_properties(component: Mapping[str, Any]) -> dict[str, Any]:
    """CycloneDX ``cryptoProperties`` for a crypto component, with UNKNOWN fields omitted."""
    layer = str(component.get("layer") or "").upper()
    asset_type = CRYPTO_ASSET_TYPES.get("PROTOCOL" if layer == "PROTOCOL" else "ALGORITHM", "algorithm")
    properties: dict[str, Any] = {"assetType": asset_type}
    algorithm: dict[str, Any] = {}
    if component.get("algorithm"):
        algorithm["name"] = component["algorithm"]
    if component.get("mode"):
        algorithm["mode"] = component["mode"]
    if isinstance(component.get("key_size"), int):
        properties["algorithmProperties"] = {
            **({"parameterSetIdentifier": str(component["key_size"])} if component.get("key_size") else {}),
            **({"curve": component["curve"]} if component.get("curve") else {}),
        }
    if algorithm:
        algorithm.setdefault("primitive", "unknown")
        properties["algorithmProperties"] = {
            **(properties.get("algorithmProperties") or {}),
            **algorithm,
        }
    if component.get("protocol"):
        properties["protocolProperties"] = {"type": component["protocol"]}
    return properties


def _properties(component: Mapping[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    mapping = {
        "cryptoscan:estate_type": component.get("type"),
        "cryptoscan:evidence_type": component.get("evidence_type"),
        "cryptoscan:usage_state": component.get("usage_state"),
        "cryptoscan:confidence": component.get("confidence"),
        "cryptoscan:layer": component.get("layer"),
        "cryptoscan:owner": component.get("owner"),
        "cryptoscan:environment": component.get("environment"),
        "cryptoscan:location": component.get("location"),
        "cryptoscan:observed_at": component.get("observed_at"),
        "cryptoscan:source": component.get("source"),
    }
    for name, value in mapping.items():
        if value in (None, "", []):
            continue
        rows.append({"name": name, "value": str(value)})
    for evidence_id in component.get("evidence_ids") or []:
        rows.append({"name": "cryptoscan:evidence_id", "value": str(evidence_id)})
    return rows


def _identity(component: Mapping[str, Any]) -> dict[str, Any]:
    identity = component.get("identity")
    attributes = component.get("attributes")
    out: dict[str, Any] = {}
    if isinstance(identity, Mapping) and identity:
        out["identity"] = dict(identity)
    if isinstance(attributes, Mapping) and attributes:
        out["attributes"] = dict(attributes)
    return out


def to_cyclonedx(projection: Mapping[str, Any]) -> dict[str, Any]:
    """Render one projection as a CycloneDX 1.6 BOM.

    Deterministic: the serial number is a UUIDv5 over (projection id, BOM kind), so the same
    projection always renders the same document.
    """
    kind = str(projection.get("bom") or "").upper()
    projection_id = str(projection.get("projection_id") or "")
    if not projection_id:
        raise ValueError("a projection without a projection id cannot be exported")
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"cryptoscan:{projection_id}:{kind}")

    components: list[dict[str, Any]] = []
    ref_for: dict[str, str] = {}
    for component in projection.get("components") or []:
        ref = str(component.get("bom_ref") or component.get("asset_id") or component.get("artifact_id") or "")
        if not ref:
            continue
        entry: dict[str, Any] = {
            "type": _component_type(component),
            "bom-ref": ref,
            "name": str(component.get("name") or component.get("asset_name") or "unnamed"),
        }
        version = (component.get("identity") or {}).get("version") if isinstance(component.get("identity"), Mapping) else None
        if version:
            entry["version"] = str(version)
        properties = _properties(component)
        if properties:
            entry["properties"] = properties
        if entry["type"] == "cryptographic-asset":
            entry["cryptoProperties"] = _crypto_properties(component)
        entry.update(_identity(component))
        components.append(entry)
        for key in ("asset_id", "artifact_id", "bom_ref"):
            if component.get(key):
                ref_for[str(component[key])] = ref

    dependencies: list[dict[str, Any]] = []
    for edge in projection.get("relationships") or []:
        source = ref_for.get(str(edge.get("from")))
        target = ref_for.get(str(edge.get("to")))
        if not source or not target:
            # one end is outside this projection: CycloneDX has nowhere to say UNKNOWN
            continue
        dependencies.append({"ref": source, "dependsOn": [target]})

    metadata_properties = [
        {"name": "cryptoscan:projection_id", "value": projection_id},
        {"name": "cryptoscan:estate", "value": str(projection.get("estate") or "")},
        {"name": "cryptoscan:identity_version", "value": str(projection.get("identity_version") or "")},
        {"name": "cryptoscan:boundary", "value": str(projection.get("boundary") or "")},
        {"name": "cryptoscan:question", "value": str(projection.get("question") or "")},
        {"name": "cryptoscan:unknowns", "value": str((projection.get("unknowns") or {}))},
        {"name": "cryptoscan:not_authoritative", "value": "the digital twin is the source of truth; this file is a projection of it"},
    ]
    for name, value in _count_properties(projection).items():
        metadata_properties.append({"name": name, "value": value})

    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": _iso(projection.get("generated_at")),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "CryptoScan",
                        "description": "projection of the Cryptoscan digital twin",
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": f"cryptoscan-{kind.lower()}-projection",
                "bom-ref": f"urn:cryptoscan:projection:{projection_id}",
            },
            "properties": metadata_properties,
        },
        "components": components,
        "dependencies": dependencies,
    }
    return document


def _count_properties(projection: Mapping[str, Any]) -> dict[str, str]:
    counts = projection.get("counts") or {}
    unknowns = projection.get("unknowns") or {}
    out: dict[str, str] = {}
    if counts:
        out["cryptoscan:counts"] = str(counts)
    if unknowns:
        out["cryptoscan:unknown_counts"] = str(unknowns)
    return out


def to_document(projection: Mapping[str, Any], fmt: str = "cyclonedx") -> dict[str, Any]:
    """Render a projection in the requested format, or raise for a format nobody defined."""
    chosen = str(fmt or "cyclonedx").strip().lower()
    if chosen not in FORMATS:
        raise ValueError(f"unknown export format {fmt!r}; expected one of {', '.join(FORMATS)}")
    if chosen == "cyclonedx":
        return to_cyclonedx(projection)
    return {
        "schema": SCHEMA,
        "format": "json",
        "projection_id": projection.get("projection_id"),
        "exported_from": "the current digital twin",
        "not_authoritative": (
            "this file is a projection of the twin at projection_id; downloading it again "
            "from a later twin may produce a different document, which is a real change, not "
            "an error"
        ),
        "projection": dict(projection),
        "limits": LIMITS,
    }


def filename(projection: Mapping[str, Any], fmt: str = "cyclonedx") -> str:
    """A stable, filesystem-safe name: kind, projection prefix, format."""
    kind = str(projection.get("bom") or "BOM").lower()
    projection_id = str(projection.get("projection_id") or "")[:12] or "unprojected"
    suffix = "cdx.json" if str(fmt).lower() == "cyclonedx" else "json"
    return f"cryptoscan-{kind}-{projection_id}.{suffix}"
