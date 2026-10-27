"""Validate a CycloneDX 1.5 CBOM document.

Two layers:
- **Schema-subset conformance** (:mod:`cbom.validators.cbom_validator` +
  the bundled ``cyclonedx-1.5.schema.json`` subset).
- **Deep structural validation** (this module): referential integrity and
  format rules the subset schema cannot express — duplicate ``bom-ref``s,
  dangling dependency references, ``serialNumber`` format, ISO timestamps,
  well-formedness of the embedded ``cryptoscan:jws``.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

from cbom.generator import CbomGenerator

_SERIAL_RE = re.compile(r"^urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

COMPONENT_TYPES = {
    "application",
    "framework",
    "library",
    "container",
    "platform",
    "operating-system",
    "device",
    "device-driver",
    "firmware",
    "file",
    "machine-learning-model",
    "data",
    "cryptographic-asset",
}


def deep_validate(bom: dict[str, Any]) -> dict[str, Any]:
    """Referential/format validation on top of the schema-subset checks.

    Returns ``{"ok": bool, "errors": [...], "warnings": [...]}``.
    """
    errors: list[str] = []
    warnings: list[str] = []

    serial = bom.get("serialNumber")
    if serial is not None and not _SERIAL_RE.match(str(serial)):
        errors.append(f"serialNumber must match urn:uuid:<uuid>, got {serial!r}")

    version = bom.get("version", 1)
    if not isinstance(version, int) or version < 1:
        errors.append(f"version must be a positive integer, got {version!r}")

    metadata = bom.get("metadata") or {}
    timestamp = metadata.get("timestamp")
    if timestamp:
        try:
            datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
        except ValueError:
            errors.append(f"metadata.timestamp is not ISO-8601: {timestamp!r}")

    components = bom.get("components") or []
    refs: dict[str, int] = {}
    # The metadata component is a legitimate dependency target too.
    meta_ref = ((bom.get("metadata") or {}).get("component") or {}).get("bom-ref")
    if meta_ref:
        refs[str(meta_ref)] = -1
    for index, component in enumerate(components):
        name = component.get("name")
        if not name:
            errors.append(f"components[{index}] missing name")
        ctype = component.get("type")
        if ctype is not None and str(ctype) not in COMPONENT_TYPES:
            warnings.append(f"components[{index}] ({name}) has non-standard type {ctype!r}")
        bom_ref = component.get("bom-ref")
        if bom_ref:
            if bom_ref in refs:
                errors.append(
                    f"duplicate bom-ref {bom_ref!r} on components[{index}] and components[{refs[bom_ref]}]"
                )
            else:
                refs[bom_ref] = index
        crypto = component.get("cryptoProperties") or {}
        if not crypto:
            errors.append(f"components[{index}] ({name}) missing cryptoProperties")
        elif not (crypto.get("oid") or crypto.get("algorithmType") or crypto.get("primitive")):
            warnings.append(
                f"components[{index}] ({name}) cryptoProperties lacks oid/algorithmType/primitive"
            )

    for index, dep in enumerate(bom.get("dependencies") or []):
        ref = dep.get("ref") or dep.get("dependsOn")
        target = dep.get("ref")
        depends_on = dep.get("dependsOn") or []
        if not ref:
            errors.append(f"dependencies[{index}] missing ref")
        elif target is not None and str(target) not in refs and str(target) not in {"root"}:
            errors.append(f"dependencies[{index}] references unknown bom-ref {target!r}")
        for child in depends_on:
            if str(child) not in refs and str(child) not in {"root"}:
                errors.append(f"dependencies[{index}] dependsOn unknown bom-ref {child!r}")

    props = {
        item.get("name"): item.get("value")
        for item in (metadata.get("properties") or [])
        if isinstance(item, dict)
    }
    jws = props.get("cryptoscan:jws")
    if jws:
        segments = str(jws).split(".")
        if len(segments) != 3:
            errors.append(f"cryptoscan:jws is malformed ({len(segments)} segments, expected 3)")
        else:
            try:
                json.loads(__import__("base64").urlsafe_b64decode(segments[0] + "=" * (-len(segments[0]) % 4)))
            except Exception:
                errors.append("cryptoscan:jws header is not valid base64url JSON")
    if props.get("cryptoscan:signatureAlg") and not jws and not props.get("cryptoscan:signature"):
        warnings.append("cryptoscan:signatureAlg set but no signature property present")

    return {"ok": not errors, "errors": errors, "warnings": warnings}


def validate_cbom(bom: dict[str, Any]) -> dict[str, Any]:
    """Full validation: schema-subset + deep structural checks."""
    base = CbomGenerator().validate(bom)
    deep = deep_validate(bom)
    return {
        "ok": base.get("ok", False) and deep["ok"],
        "errors": list(base.get("errors") or []) + deep["errors"],
        "warnings": deep["warnings"],
    }
