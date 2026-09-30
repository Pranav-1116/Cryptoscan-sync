"""Materialize the BOM family for one binary/firmware scan.

A binary scan is not only an SBOM.  The same bounded observations can produce:

* SBOM  - software packages and binary components;
* CBOM  - algorithms, crypto libraries, certificates and key-material metadata;
* HBOM  - hardware/firmware execution context inferred from the artifact;
* NBOM  - network capabilities suggested by static binary evidence; and
* VBOM  - vendor/product evidence embedded in the artifact.

The module deliberately keeps the layers separate.  A static binary cannot prove
that a listener is reachable, that a device is physically deployed, or that a
vendor supports an unmentioned component.  Those limits are carried in each
document and in the evidence properties.  The functions are pure and stdlib-only
so they can be called by the synchronous API, the worker, and tests alike.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping


SPEC_VERSION = "1.5"
_TOOL = {"vendor": "CryptoScan", "name": "binary-bom-materializer", "version": "1.0"}
_NETWORK_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("tcp", ("socket", "connect", "accept", "listen", "getaddrinfo", "WSASocket")),
    ("tls", ("SSL_connect", "SSL_CTX_new", "SSL_read", "SSL_write", "TLS", "tls")),
    ("http", ("HTTP", "http://", "https://", "curl_easy", "WinHttp", "NSURLSession")),
    ("ssh", ("ssh", "libssh", "ssh_connect", "SSH2")),
    ("dns", ("gethostbyname", "getaddrinfo", "res_query", "DNS")),
    ("mqtt", ("mqtt", "MQTT")),
    ("quic", ("QUIC", "quic")),
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _digest(*values: Any) -> str:
    raw = "|".join(str(value) for value in values if value is not None)
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:24]


def _ref(prefix: str, *values: Any) -> str:
    return f"{prefix}:{_digest(*values)}"


def _property(name: str, value: Any) -> dict[str, str]:
    return {"name": f"cryptoscan:{name}", "value": str(value)}


def _without_volatile(value: Any, *, key: str | None = None) -> Any:
    """Remove publication-time fields before calculating a content fingerprint."""
    if key in {"serialNumber", "timestamp", "generated_at", "as_of", "snapshot_id",
               "fingerprint", "snapshot_fingerprint"}:
        return None
    if isinstance(value, dict):
        return {name: cleaned for name, item in value.items()
                if (cleaned := _without_volatile(item, key=name)) is not None}
    if isinstance(value, list):
        return [_without_volatile(item) for item in value]
    return value


def _snapshot_fingerprint(document: Mapping[str, Any]) -> str:
    canonical = json.dumps(_without_volatile(dict(document)), sort_keys=True,
                           separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _document(
    name: str,
    target: str,
    components: list[dict[str, Any]],
    *,
    dependencies: list[dict[str, Any]] | None = None,
    vulnerabilities: list[dict[str, Any]] | None = None,
    coverage: dict[str, Any] | None = None,
    created_by: str | None = None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "timestamp": _now(),
        "tools": [_TOOL],
        "component": {"type": "application", "bom-ref": "cryptoscan:binary-target",
                      "name": target or "binary-target"},
        "properties": [_property("bom-type", name),
                       _property("source", "bounded-static-binary-analysis")],
    }
    if created_by:
        metadata["authors"] = [{"name": str(created_by)}]
    if coverage:
        metadata["properties"].extend(_property(key, value)
                                      for key, value in sorted(coverage.items())
                                      if value is not None and not isinstance(value, (dict, list)))
    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        # Set below from the content fingerprint rather than a random UUID. This
        # keeps repeated scans diffable while publication time remains available
        # in metadata.timestamp for audit context.
        "serialNumber": "",
        "version": 1,
        "metadata": metadata,
        "components": components,
    }
    if dependencies:
        document["dependencies"] = dependencies
    if vulnerabilities is not None:
        document["vulnerabilities"] = vulnerabilities
    document["cryptoscan"] = {
        "coverage": coverage or {},
        "note": "No result is a proof that the corresponding live estate is empty; "
                "unobserved scope is reported as unknown.",
    }
    fingerprint = _snapshot_fingerprint(document)
    stable_name = f"cryptoscan:{name}:{target}:{fingerprint}"
    document["serialNumber"] = f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, stable_name)}"
    document["cryptoscan"]["snapshot_fingerprint"] = fingerprint
    return document


def _flatten(records: Iterable[Mapping[str, Any]], depth: int = 0) -> list[dict[str, Any]]:
    if depth > 4:
        return []
    output: list[dict[str, Any]] = []
    for raw in records:
        record = dict(raw)
        output.append(record)
        children = record.get("embedded") or []
        if isinstance(children, list):
            output.extend(_flatten(children, depth + 1))
    return output


def _path(record: Mapping[str, Any]) -> str:
    return str(record.get("path") or record.get("name") or "unknown-binary")


def build_hbom(
    records: Iterable[Mapping[str, Any]],
    *,
    target: str = "binary-target",
    created_by: str | None = None,
) -> dict[str, Any]:
    """Build hardware/firmware context inferred from binaries.

    Architecture, device-tree, uImage and firmware-container facts are useful
    HBOM evidence, but they are not a live CMDB assertion.  Every component says
    whether the identity came from a device tree, image header, or only an
    executable architecture.
    """
    components: list[dict[str, Any]] = []
    seen: set[str] = set()
    scanned = 0
    firmware_context = 0
    for record in _flatten(records):
        scanned += 1
        firmware = record.get("firmware") or {}
        tree = (firmware.get("device_tree") if isinstance(firmware, dict) else None)
        tree = tree or record.get("device_tree") or {}
        uimage = record.get("uimage") or (firmware.get("uimage") if isinstance(firmware, dict) else {}) or {}
        if not isinstance(tree, dict):
            tree = {}
        if not isinstance(uimage, dict):
            uimage = {}
        containers = (firmware.get("containers") if isinstance(firmware, dict) else None)
        containers = containers or record.get("containers") or []
        containers = containers if isinstance(containers, list) else []
        model = tree.get("model")
        compatible = tree.get("compatible") or []
        arch = record.get("arch") or uimage.get("arch") or record.get("machine")
        fmt = record.get("format")
        if not (model or compatible or uimage or arch or fmt == "firmware"):
            continue
        if model or compatible or uimage or fmt == "firmware":
            firmware_context += 1
        evidence_kind = ("device-tree" if model or compatible else
                         "uimage-header" if uimage else "binary-architecture")
        identity = model or (compatible[0] if compatible else None) or arch or fmt or "unknown"
        ref = _ref("hbom", identity, arch, target)
        props = [
            _property("evidence-kind", evidence_kind),
            _property("found-in", _path(record)),
            _property("observed", "false"),
            _property("identity-confidence", "HIGH" if model or compatible else "MEDIUM" if uimage else "LOW"),
        ]
        for key, value in (("format", fmt), ("architecture", arch), ("machine", record.get("machine")),
                           ("model", model), ("uimage-os", uimage.get("os")),
                           ("uimage-type", uimage.get("image_type")),
                           ("firmware-version", record.get("version"))):
            if value:
                props.append(_property(key, value))
        if compatible:
            props.append(_property("compatible", ",".join(str(item) for item in compatible[:12])))
        if containers:
            props.append(_property("embedded-containers", ",".join(
                sorted({str(row.get("format")) for row in containers if isinstance(row, dict)}))))
        if ref in seen:
            continue
        seen.add(ref)
        components.append({
            "type": "device",
            "bom-ref": ref,
            "name": str(identity),
            "properties": props,
        })
    return _document("HBOM", target, components,
                     coverage={"binary_records": scanned, "hardware_context_records": firmware_context,
                               "live_hardware_observed": False}, created_by=created_by)


def _record_text(record: Mapping[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("imports", "exports", "strings"):
        values.extend(str(item) for item in (record.get(key) or []) if item)
    for key in ("java", "python", "dex", "wasm"):
        value = record.get(key) or {}
        if isinstance(value, dict):
            for field in ("classes", "member_names", "names", "strings", "imports", "exports"):
                values.extend(str(item) for item in (value.get(field) or []) if item)
    return values


def build_nbom(
    records: Iterable[Mapping[str, Any]],
    *,
    target: str = "binary-target",
    created_by: str | None = None,
) -> dict[str, Any]:
    """Build a static network-capability inventory, not a reachability claim."""
    components: list[dict[str, Any]] = []
    dependencies: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    record_count = 0
    for record in _flatten(records):
        record_count += 1
        path = _path(record)
        names = _record_text(record)
        lower_names = [name.lower() for name in names]
        imports = [str(item) for item in (record.get("imports") or [])]
        for capability, markers in _NETWORK_MARKERS:
            matches = [marker for marker in markers
                       if any(marker.lower() in value for value in lower_names)]
            if not matches:
                continue
            key = (path, capability)
            if key in seen:
                continue
            seen.add(key)
            confidence = "HIGH" if any(marker in imports for marker in matches) else "MEDIUM"
            ref = _ref("nbom", path, capability)
            components.append({
                "type": "device",
                "bom-ref": ref,
                "name": f"{capability} capability in {path}",
                "properties": [
                    _property("kind", "static-network-capability"),
                    _property("protocol", capability),
                    _property("found-in", path),
                    _property("evidence", ",".join(matches[:12])),
                    _property("confidence", confidence),
                    _property("observed", "false"),
                    _property("reachability-proven", "false"),
                    _property("probe-performed", "false"),
                ],
            })
            dependencies.append({"ref": ref, "dependsOn": [f"hbom:{_digest(path)}"]})
    return _document(
        "NBOM", target, components, dependencies=dependencies,
        coverage={"binary_records": record_count, "capability_count": len(components),
                  "network_probe_performed": False, "live_endpoints_observed": False},
        created_by=created_by)


def build_vbom(
    records: Iterable[Mapping[str, Any]],
    *,
    target: str = "binary-target",
    created_by: str | None = None,
) -> dict[str, Any]:
    """Build vendor/product evidence from package and binary metadata."""
    components: list[dict[str, Any]] = []
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    record_count = 0
    for record in _flatten(records):
        record_count += 1
        path = _path(record)
        version_info = record.get("version_info") or {}
        candidates: list[tuple[str, str, str]] = []
        vendor = version_info.get("vendor") or record.get("vendor")
        product = version_info.get("product") or record.get("product")
        version = version_info.get("version") or record.get("version")
        if vendor:
            candidates.append((str(vendor), str(product or record.get("format") or "binary"), "version-metadata"))
        rpm = record if record.get("format") == "rpm" else {}
        if rpm.get("vendor"):
            candidates.append((str(rpm["vendor"]), str(rpm.get("name") or "rpm-package"), "rpm-metadata"))
        java = record.get("java") or {}
        if isinstance(java, dict) and java.get("group"):
            candidates.append((str(java["group"]), str(java.get("artifact") or "java-artifact"), "maven-metadata"))
        for library in (record.get("crypto") or {}).get("libraries") or []:
            provider = library.get("provider") or library.get("library")
            if provider:
                candidates.append((str(provider), str(library.get("library") or provider), "crypto-fingerprint"))
        for vendor_name, product_name, evidence in candidates:
            key = (vendor_name.lower(), product_name.lower())
            component = by_key.get(key)
            if component is None:
                ref = _ref("vbom", vendor_name, product_name)
                component = {
                    "type": "platform",
                    "bom-ref": ref,
                    "name": product_name,
                    "vendor": vendor_name,
                    "properties": [_property("vendor", vendor_name),
                                   _property("product", product_name),
                                   _property("evidence", evidence),
                                   _property("observed", "true"),
                                   _property("source", path)],
                }
                if version:
                    component["version"] = str(version)
                by_key[key] = component
                components.append(component)
            locations = [item for item in component["properties"] if item["name"] == "cryptoscan:found-in"]
            if not any(item.get("value") == path for item in locations):
                component["properties"].append(_property("found-in", path))
    return _document("VBOM", target, components,
                     coverage={"binary_records": record_count, "vendor_evidence_count": len(components),
                               "vendor_validation_performed": False}, created_by=created_by)


def build_vulnerability_bom(
    records: Iterable[Mapping[str, Any]],
    result: Mapping[str, Any] | None = None,
    *,
    target: str = "binary-target",
    created_by: str | None = None,
) -> dict[str, Any]:
    """Build a vulnerability/findings BOM without inventing advisory data."""
    result = result or {}
    flat = _flatten(records)
    vulnerabilities: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    affected: list[dict[str, Any]] = []
    for record in flat:
        path = _path(record)
        ref = _ref("binary", path, record.get("sha256"))
        affected.append({"ref": ref, "path": path, "sha256": record.get("sha256")})
        findings = list(record.get("findings") or [])
        for finding in findings:
            code = str(finding.get("code") or "BIN-UNKNOWN")
            key = (code, path)
            if key in seen:
                continue
            seen.add(key)
            vulnerabilities.append({
                "id": code,
                "source": {"name": "CryptoScan binary rules"},
                "ratings": [{"severity": str(finding.get("severity") or "info").lower()}],
                "description": str(finding.get("detail") or finding.get("title") or code),
                "analysis": {"state": "in_triage", "justification": "static_binary_evidence"},
                "affects": [{"ref": ref}],
                "properties": [_property("path", path), _property("evidence", "binary-finding")],
            })
    for advisory in result.get("vulnerabilities") or []:
        if not isinstance(advisory, dict):
            continue
        code = str(advisory.get("id") or advisory.get("cve") or advisory.get("code") or "ADVISORY-UNKNOWN")
        package = str(advisory.get("package") or advisory.get("component") or "")
        key = (code, package)
        if key in seen:
            continue
        seen.add(key)
        vulnerabilities.append({
            "id": code,
            "source": {"name": str(advisory.get("source") or "advisory-feed")},
            "ratings": [{"severity": str(advisory.get("severity") or "unknown").lower()}],
            "description": str(advisory.get("description") or advisory.get("summary") or code),
            "analysis": {"state": "in_triage", "justification": "advisory_feed_match"},
            "affects": [{"ref": _ref("binary", package)}],
            "properties": [_property("package", package), _property("evidence", "advisory-feed")],
        })
    return _document(
        "VULNERABILITY_BOM", target, affected, vulnerabilities=vulnerabilities,
        coverage={"binary_records": len(flat), "finding_count": len(vulnerabilities),
                  "advisory_feed_matches": len(result.get("vulnerabilities") or []),
                  "exploitability_verified": False}, created_by=created_by)


def _component_key(component: Mapping[str, Any]) -> str:
    return str(component.get("bom-ref") or _ref(
        "component", component.get("type"), component.get("name"),
        component.get("version"), component.get("vendor")))


def _view_components(document: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    rows = [row for row in document.get("components") or [] if isinstance(row, Mapping)]
    if rows:
        return rows
    # The unified technology view stores components under materialized layers.
    for layer in (document.get("layers") or {}).values():
        if isinstance(layer, Mapping):
            rows.extend(row for row in layer.get("components") or [] if isinstance(row, Mapping))
    return rows


def _view_vulnerabilities(document: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    rows = [row for row in document.get("vulnerabilities") or [] if isinstance(row, Mapping)]
    if rows:
        return rows
    layer = (document.get("layers") or {}).get("vulnerability")
    if isinstance(layer, Mapping):
        return [row for row in layer.get("vulnerabilities") or [] if isinstance(row, Mapping)]
    return rows


def _diff_document(previous: Mapping[str, Any] | None,
                   current: Mapping[str, Any] | None) -> dict[str, Any]:
    before = dict(previous or {})
    after = dict(current or {})
    old_components = {_component_key(row): row for row in _view_components(before)}
    new_components = {_component_key(row): row for row in _view_components(after)}
    added = sorted(set(new_components) - set(old_components))
    removed = sorted(set(old_components) - set(new_components))
    modified = sorted(ref for ref in set(old_components) & set(new_components)
                      if _without_volatile(old_components[ref]) !=
                      _without_volatile(new_components[ref]))
    old_vulnerabilities = {str(row.get("id") or row.get("bom-ref")): row
                           for row in _view_vulnerabilities(before)}
    new_vulnerabilities = {str(row.get("id") or row.get("bom-ref")): row
                           for row in _view_vulnerabilities(after)}
    vulnerability_added = sorted(set(new_vulnerabilities) - set(old_vulnerabilities))
    vulnerability_removed = sorted(set(old_vulnerabilities) - set(new_vulnerabilities))
    return {
        "from_fingerprint": (before.get("cryptoscan") or {}).get("snapshot_fingerprint"),
        "to_fingerprint": (after.get("cryptoscan") or {}).get("snapshot_fingerprint"),
        "changed": bool(added or removed or modified or vulnerability_added or vulnerability_removed),
        "added": added, "removed": removed, "modified": modified,
        "vulnerabilities_added": vulnerability_added,
        "vulnerabilities_removed": vulnerability_removed,
    }


def diff_binary_bom_bundles(previous: Mapping[str, Mapping[str, Any]],
                            current: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Diff two materialized binary BOM bundles by stable component reference.

    Publication timestamps and serial numbers are ignored. The returned layer
    keys are explicit, including the separate vulnerability BOM and technology
    snapshot, so "no evidence" is not confused with "unchanged and clean".
    """
    layers = sorted(set(previous) | set(current))
    result: dict[str, Any] = {"changed": False, "layers": {}}
    for layer in layers:
        delta = _diff_document(previous.get(layer), current.get(layer))
        result["layers"][layer] = delta
        result["changed"] = result["changed"] or bool(delta["changed"])
    return result


def build_binary_bom_bundle(
    scan: Mapping[str, Any],
    result: Mapping[str, Any] | None = None,
    *,
    sbom: Mapping[str, Any] | None = None,
    cbom: Mapping[str, Any] | None = None,
    target: str | None = None,
    created_by: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Return every BOM projection produced from one binary scan."""
    records = scan.get("binaries") or []
    result = result or {}
    target = str(target or scan.get("target") or "binary-target")
    hbom = build_hbom(records, target=target, created_by=created_by)
    nbom = build_nbom(records, target=target, created_by=created_by)
    vbom = build_vbom(records, target=target, created_by=created_by)
    vulnerability_bom = build_vulnerability_bom(records, result, target=target, created_by=created_by)
    bundle: dict[str, dict[str, Any]] = {
        "sbom": dict(sbom or {}),
        "cbom": dict(cbom or {}),
        "hbom": hbom,
        "nbom": nbom,
        "vbom": vbom,
        "vulnerability_bom": vulnerability_bom,
        # Common aliases make the API explicit without making VBOM ambiguous:
        # in this repository VBOM is the vendor view; vulnerability_bom is separate.
        "vendor_bom": vbom,
        "vulbom": vulnerability_bom,
    }
    try:
        from cbom.technology_bom import materialize_technology_bom, fingerprint_state, snapshot_id

        inventory = {
            "applications": [{"id": row.get("sha256") or row.get("path"),
                               "name": row.get("file_name") or row.get("name"),
                               "version": row.get("version"),
                               "asset": target, "environment": "binary-scan"}
                              for row in result.get("binaries") or []],
            "crypto": [{"id": component.get("bom-ref"), "algorithm": component.get("name"),
                        "asset": target, "location": ",".join(
                            str(item.get("location")) for item in
                            (component.get("evidence") or {}).get("occurrences") or [])}
                       for component in (cbom or {}).get("components") or []],
            "hardware": [{"id": component.get("bom-ref"), "asset_id": component.get("bom-ref"),
                          "model": component.get("name"), "device_type": "inferred-binary-context"}
                         for component in hbom.get("components") or []],
            "vendors": [{"name": component.get("vendor"), "product": component.get("name"),
                         "version": component.get("version"), "assets": [target]}
                        for component in vbom.get("components") or []],
            "certificates": [], "dependencies": [],
            "scan": {"target": target, "source": "binary-scan", "bounded": True},
        }
        technology = materialize_technology_bom(inventory, environment="binary-scan", state_version=1)
        technology["layers"]["nbom"] = {"components": nbom.get("components") or [],
                                         "count": len(nbom.get("components") or [])}
        technology["layers"]["vulnerability"] = {
            "components": vulnerability_bom.get("components") or [],
            "vulnerabilities": vulnerability_bom.get("vulnerabilities") or [],
            "count": len(vulnerability_bom.get("vulnerabilities") or []),
        }
        technology["components_by_layer"]["nbom"] = len(nbom.get("components") or [])
        technology["components_by_layer"]["vulnerability"] = len(vulnerability_bom.get("vulnerabilities") or [])
        technology["total_components"] = sum(technology["components_by_layer"].values())
        technology["fingerprint"] = fingerprint_state(technology)
        technology["snapshot_id"] = snapshot_id(technology, version=1)
        bundle["technology_bom"] = technology
    except Exception as exc:  # noqa: BLE001 - optional materializer must not lose scan results
        # The full technology materializer may be unavailable in a deliberately
        # minimal worker image. Still return a truthful unified view instead of
        # dropping HBOM/NBOM/VBOM just because an optional dependency is absent.
        layers = {
            "sbom": {"components": list((sbom or {}).get("components") or [])},
            "cbom": {"components": list((cbom or {}).get("components") or [])},
            "hbom": {"components": hbom.get("components") or []},
            "nbom": {"components": nbom.get("components") or []},
            "vbom": {"components": vbom.get("components") or []},
            "vulnerability": {"components": vulnerability_bom.get("components") or [],
                              "vulnerabilities": vulnerability_bom.get("vulnerabilities") or []},
        }
        counts = {name: len(layer.get("components") or []) for name, layer in layers.items()}
        counts["vulnerability"] = len(layers["vulnerability"].get("vulnerabilities") or [])
        bundle["technology_bom"] = {
            "status": "PARTIAL",
            "error": f"{type(exc).__name__}: {exc}",
            "environment": "binary-scan",
            "generated_at": _now(),
            "layers": layers,
            "components_by_layer": counts,
            "total_components": sum(counts.values()),
            "snapshot_id": f"BINARY-TECHBOM-{_digest(target, *counts.values())}",
            "cryptoscan": {"bounded": True, "materializer": "fallback",
                           "note": "unified view was assembled without the optional technology-BOM package"},
        }
    return bundle
