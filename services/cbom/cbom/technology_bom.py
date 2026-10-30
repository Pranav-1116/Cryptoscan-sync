"""Unified Technology BOM — shared SBOM / CBOM / HBOM / VBOM state.

The spec is explicit: the shared BOM views are NOT separate databases. They are
materialized views of the same underlying environment graph
(assets + evidence + identity + relationships). This module is the pure,
deterministic materializer for the shared inventory state: it takes one
structured inventory snapshot and derives SBOM, CBOM, HBOM and vendor-layer
projections, a
content-addressed state version, an immutable snapshot id, a diff between
versions and export formats.

Binary and firmware scans extend this shared state with bounded, tenant-scoped
NBOM capability candidates and a separate vulnerability BOM through
``devsecops.binary_boms``. Those sidecars are not live network observations and
must remain distinguishable from the authorized network-scan layer.

Pipeline (spec):  Scan -> Evidence -> Normalize -> Resolve Asset -> Build Graph
              -> Materialize shared BOM state -> Version the state
              -> Live investigation -> Export an exact snapshot.

The engine is pure (no DB, no I/O) so it is unit-testable in isolation. The
router feeds it records from the real inventory and persists snapshots.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

# --------------------------------------------------------------------------- #
# Input shape
# --------------------------------------------------------------------------- #

def empty_inventory() -> dict[str, Any]:
    """The honest empty inventory. Every list is empty so an un-scanned estate
    renders zeroes, never fabricated components."""
    return {
        "applications": [],   # systems / app components -> SBOM
        "crypto": [],         # crypto assets -> CBOM
        "hardware": [],       # hardware assets -> HBOM
        "certificates": [],   # certificates -> CBOM evidence
        "vendors": [],        # vendor inventory -> VBOM
        "dependencies": [],   # relationship edges (graph)
        # packages and crypto libraries a scan's manifest/lockfile pass declared ->
        # SBOM. Kept separate from ``applications`` because an application is a
        # system and a package is a coordinate: collapsing them would report one
        # as the other.
        "software": [],
        "scan": {},           # scan metadata (id, completed_at, scanners)
    }


# --------------------------------------------------------------------------- #
# Component normalization (one truth -> per-layer views)
# --------------------------------------------------------------------------- #

# round 38: component construction lives in the single registry — this
# module is now an assembler over it (report 46's three-generators merge)
from cbom.component_registry import (
    app_component as _app_component,
    crypto_layer_component as _crypto_component,
    hardware_component as _hardware_component,
    software_component as _software_component,
    vendor_component as _vendor_component,
)

#: layer -> the inventory collections that feed it, each with its own builder.
#: The SBOM layer has two: the applications the estate registers, and the
#: packages/libraries a scan's manifest pass declared.
_LAYER_BUILDERS: dict[str, tuple[tuple[str, Any], ...]] = {
    "sbom": (("applications", _app_component), ("software", _software_component)),
    "cbom": (("crypto", _crypto_component),),
    "hbom": (("hardware", _hardware_component),),
    "vendor": (("vendors", _vendor_component),),
}


def canonical_dependencies(inv: dict[str, Any]) -> list[list[str]]:
    """Dependency edges, canonicalized to sorted ``[source, target, type]``.

    The inventory speaks two dialects — pair lists from the system-dependency
    table (``["sys-a", "sys-b"]``) and dicts from graph snapshots
    (``{"source": ..., "target": ..., "type": ...}``). Both normalize here so
    the state (and therefore the fingerprint) sees edges, not just a count:
    a re-wired estate with identical components is a new BOM version.
    """
    edges: set[tuple[str, str, str]] = set()
    for dep in inv.get("dependencies") or []:
        if isinstance(dep, dict):
            source = dep.get("source") or dep.get("from") or dep.get("parent")
            target = dep.get("target") or dep.get("to") or dep.get("child")
            edge_type = dep.get("type") or dep.get("relation") or dep.get("label") or ""
        elif isinstance(dep, (list, tuple)) and len(dep) >= 2:
            source, target = dep[0], dep[1]
            edge_type = str(dep[2]) if len(dep) > 2 else ""
        else:
            continue
        if source and target:
            edges.add((str(source), str(target), str(edge_type or "")))
    return sorted([list(edge) for edge in edges])


# --------------------------------------------------------------------------- #
# Materialization
# --------------------------------------------------------------------------- #

def materialize_technology_bom(
    inventory: dict[str, Any] | None = None,
    *,
    environment: str = "",
    state_version: int = 0,
) -> dict[str, Any]:
    """Materialize the shared BOM layers from ONE inventory snapshot.

    ``inventory`` keys are the unified-model collections. The same underlying
    asset/relationship set is projected into SBOM, CBOM, HBOM and the vendor
    layer; a single change to an asset therefore updates whichever layers it
    appears in. Binary sidecars are materialized by the bounded binary BOM
    projector, not inferred by this general inventory materializer.
    """
    inv = inventory or empty_inventory()
    layers: dict[str, Any] = {}
    layer_counts: dict[str, int] = {}
    all_components: list[dict[str, Any]] = []

    for layer, sources in _LAYER_BUILDERS.items():
        comps = []
        for collection, builder in sources:
            for row in inv.get(collection) or []:
                if not isinstance(row, dict):
                    continue
                comps.append(builder(row))
        layers[layer] = {"components": comps, "count": len(comps)}
        layer_counts[layer] = len(comps)
        all_components.extend(comps)

    # certificates split into CBOM only as metadata (evidence), not a top-level
    # component layer, but count them for the dashboard.
    certs = inv.get("certificates") or []
    layers["certificates"] = {"count": len(certs), "components": list(certs)}

    generated_at = datetime.now(timezone.utc).isoformat()
    deps = canonical_dependencies(inv)
    state: dict[str, Any] = {
        "environment": environment or "default",
        "state_version": int(state_version),
        "generated_at": generated_at,
        "as_of": generated_at,
        "total_components": len(all_components),
        "components_by_layer": layer_counts,
        "certificate_count": len(certs),
        "dependency_count": len(deps),
        # the edges themselves, canonicalized — the fingerprint hashes this
        # list, so edge-only changes produce a new snapshot version
        "dependencies": deps,
        "layers": layers,
        "scan": inv.get("scan") or {},
    }
    state["fingerprint"] = fingerprint_state(state)
    state["snapshot_id"] = snapshot_id(state, version=int(state_version))
    return state


def fingerprint_state(state: dict[str, Any]) -> str:
    """Content-addressed digest over the materialized component set.

    Same state -> same fingerprint, so a snapshot is only recorded when it
    actually changed (mirrors the graph snapshot's no-duplicate rule)."""
    canon = {
        "environment": state.get("environment"),
        "layers": {k: v.get("components") for k, v in (state.get("layers") or {}).items()},
        "dependencies": sorted(str(d) for d in (state.get("dependencies") or [])),
    }
    blob = json.dumps(canon, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def snapshot_id(state: dict[str, Any], *, version: int = 0) -> str:
    """Immutable snapshot identity, e.g. ``TECHBOM-2026-09-07-143218``.

    Carries the environment + state version so the customer always knows which
    environment state an export represents (spec #14)."""
    as_of = (state.get("as_of") or state.get("generated_at") or "")
    stamp = as_of.replace("-", "").replace(":", "").replace("T", "-")
    stamp = stamp.split(".")[0][:15]  # YYYYMMDD-HHMMSS
    return f"TECHBOM-{stamp}"


# --------------------------------------------------------------------------- #
# Compare / diff
# --------------------------------------------------------------------------- #

def diff_technology_bom(prev: dict[str, Any], cur: dict[str, Any]) -> dict[str, Any]:
    """Diff two materialized states per layer (added/removed/changed).

    Components are keyed by their ``bom-ref``. A component whose ref survives
    but whose fields moved (key growth, version bump) is a *changed* entry
    naming the fields and their from/to values — a diff that only reports
    appearance and disappearance stays silent about migrations. Dependency
    edges are diffed the same way. ``prev`` is the baseline, ``cur`` the newer
    state.
    """
    out: dict[str, Any] = {
        "from": {"snapshot_id": prev.get("snapshot_id"), "state_version": prev.get("state_version"),
                 "total_components": prev.get("total_components")},
        "to": {"snapshot_id": cur.get("snapshot_id"), "state_version": cur.get("state_version"),
               "total_components": cur.get("total_components")},
        "changed": False,
        "layers": {},
    }
    prev_layers = prev.get("layers") or {}
    cur_layers = cur.get("layers") or {}
    for layer in ("sbom", "cbom", "hbom", "vendor"):
        prev_by_ref = {c.get("bom-ref"): c
                       for c in (prev_layers.get(layer) or {}).get("components", [])}
        cur_by_ref = {c.get("bom-ref"): c
                      for c in (cur_layers.get(layer) or {}).get("components", [])}
        p, c = set(prev_by_ref), set(cur_by_ref)
        added = sorted(c - p)
        removed = sorted(p - c)
        changed_refs = sorted(
            ref for ref in (p & c) if prev_by_ref[ref] != cur_by_ref[ref])
        changed = bool(added or removed or changed_refs)
        out["changed"] = out["changed"] or changed
        out["layers"][layer] = {
            "added_count": len(added),
            "removed_count": len(removed),
            "changed_count": len(changed_refs),
            "added": _layer_diff_entries(cur_layers, layer, added),
            "removed": _layer_diff_entries(prev_layers, layer, removed),
            "changed": [
                {
                    "bom-ref": ref,
                    "fields": {
                        key: {"from": prev_by_ref[ref].get(key),
                              "to": cur_by_ref[ref].get(key)}
                        for key in sorted(set(prev_by_ref[ref]) | set(cur_by_ref[ref]))
                        if prev_by_ref[ref].get(key) != cur_by_ref[ref].get(key)
                    },
                }
                for ref in changed_refs
            ],
        }
        # aggregate counts on the summary too
        out["layers"][layer]["from_count"] = len(p)
        out["layers"][layer]["to_count"] = len(c)
    # dependency edges: same discipline as components — appearance,
    # disappearance, and nothing inferred
    prev_deps = {tuple(str(x) for x in d) for d in prev.get("dependencies") or []}
    cur_deps = {tuple(str(x) for x in d) for d in cur.get("dependencies") or []}
    deps_added = sorted(list(d) for d in cur_deps - prev_deps)
    deps_removed = sorted(list(d) for d in prev_deps - cur_deps)
    out["dependencies"] = {
        "added_count": len(deps_added),
        "removed_count": len(deps_removed),
        "added": deps_added,
        "removed": deps_removed,
        "from_count": len(prev_deps),
        "to_count": len(cur_deps),
    }
    if deps_added or deps_removed:
        out["changed"] = True
    return out


def _layer_diff_entries(layers: dict[str, Any], layer: str, refs: list[str]) -> list[dict[str, Any]]:
    by_ref = {c.get("bom-ref"): c for c in (layers.get(layer) or {}).get("components", [])}
    return [{k: v for k, v in by_ref.get(ref, {}).items()} for ref in refs]


# --------------------------------------------------------------------------- #
# Export — JSON / CSV / CycloneDX / SPDX
# --------------------------------------------------------------------------- #

def export_technology_bom(
    state: dict[str, Any],
    *,
    fmt: str = "json",
    layer: str = "all",
) -> dict[str, Any]:
    """Export a materialized BOM state.

    Supports ``json``, ``csv``, ``cyclonedx`` and ``spdx``. ``layer`` selects a
    single BOM ("sbom"|"cbom"|"hbom"|"vendor") or "all". Every export is wrapped
    with an integrity hash + the immutable snapshot id so an auditor can verify
    it (spec #13/#19).
    """
    fmt = (fmt or "json").strip().lower()
    payload = _select_layer(state, layer)
    body: Any
    mime = "application/json"
    if fmt == "cyclonedx":
        body, mime = _to_cyclonedx(state, layer)
    elif fmt == "cyclonedx-xml":
        body, mime = _to_cyclonedx_xml(state, layer)
    elif fmt == "spdx":
        body, mime = _to_spdx(state, layer)
    elif fmt == "csv":
        body, mime = _to_csv(state, layer)
    elif fmt == "pdf":
        body, mime = _to_pdf(state, layer)
    elif fmt == "xml":
        # generic exported XML — alias of the CycloneDX XML representation
        body, mime = _to_cyclonedx_xml(state, layer)
    else:
        body = payload
    integrity = _integrity(state, body)
    return {
        "snapshot_id": state.get("snapshot_id"),
        "environment": state.get("environment"),
        "state_version": state.get("state_version"),
        "generated_at": state.get("generated_at"),
        "layer": layer,
        "format": fmt,
        "mime_type": mime,
        "integrity_sha256": integrity,
        "data": body,
    }


def _select_layer(state: dict[str, Any], layer: str) -> dict[str, Any]:
    layers = state.get("layers") or {}
    if layer in layers:
        return {"layer": layer, **layers[layer]}
    return state


def _integrity(state: dict[str, Any], body: Any) -> str:
    if isinstance(body, (bytes, bytearray)):
        payload = bytes(body)
    else:
        payload = json.dumps({"snapshot_id": state.get("snapshot_id"), "body": body},
                             sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _cdx_type(component: dict[str, Any], layer: str) -> str:
    """CycloneDX component type for one component.

    For a single-layer export the type is fixed; for the unified ``all`` export
    the type is recovered from the component's bom-ref prefix (or, for
    certificate evidence rows, ``cryptographic-asset``).
    """
    if layer != "all":
        return {"sbom": "library", "cbom": "crypto-asset",
                "hbom": "device", "vendor": "platform"}.get(layer, "unknown")
    ref = str(component.get("bom-ref") or "")
    if ref.startswith("app:"):
        return "library"
    if ref.startswith("crypto:"):
        return "crypto-asset"
    if ref.startswith("hw:"):
        return "device"
    if ref.startswith("vendor:"):
        return "platform"
    if component.get("fingerprint") or "subject" in component:
        return "cryptographic-asset"
    return "unknown"


def _to_cyclonedx(state: dict[str, Any], layer: str) -> tuple[dict[str, Any], str]:
    """A minimal valid CycloneDX 1.5 BOM for the selected layer.

    CBOM components are the platform's core artifact; SBOM/HBOM/Vendor also map
    to CycloneDX component types so the same reliable format covers every view.
    """
    comps = _layer_components(state, layer)
    components = []
    for c in comps:
        ctype = _cdx_type(c, layer)
        comp: dict[str, Any] = {
            "type": ctype,
            "name": c.get("name") or c.get("algorithm") or c.get("model")
                     or c.get("subject") or "component",
            "bom-ref": c.get("bom-ref") or "",
        }
        if c.get("version"):
            comp["version"] = str(c["version"])
        if c.get("supplier"):
            comp["supplier"] = {"name": c["supplier"]}
        if c.get("purpose"):
            comp["description"] = c["purpose"]
        if c.get("key_size"):
            comp["properties"] = [{"name": "crypto:key_size", "value": str(c["key_size"])},
                                  {"name": "crypto:algorithm", "value": c.get("algorithm", "")}]
        components.append(comp)
    dig = hashlib.sha256((state.get("snapshot_id") or "").encode()).hexdigest()[:32]
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": state.get("state_version") or 1,
        "serialNumber": f"urn:uuid:{dig[:8]}-{dig[8:12]}-{dig[12:16]}-{dig[16:20]}-{dig[20:32]}",
        "metadata": {
            "timestamp": state.get("generated_at"),
            "component": {"type": "application", "name": "ZELNX Technology BOM",
                          "version": str(state.get("state_version") or "")},
        },
        "components": components,
    }
    return doc, "application/json"


def _to_spdx(state: dict[str, Any], layer: str) -> tuple[dict[str, Any], str]:
    """A minimal valid SPDX 2.3 document for the selected layer."""
    comps = _layer_components(state, layer)
    packages = []
    for c in comps:
        pkg: dict[str, Any] = {
            "SPDXID": "SPDXRef-" + hashlib.sha1((c.get("bom-ref") or "").encode()).hexdigest()[:16],
            "name": c.get("name") or c.get("algorithm") or c.get("model")
                     or c.get("subject") or "component",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "versionInfo": str(c.get("version") or "") or None,
        }
        packages.append(pkg)
    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "ZELNX Technology BOM",
        "documentNamespace": f"https://zelnx.io/spdx/{state.get('snapshot_id') or 'snapshot'}",
        "creationInfo": {"created": state.get("generated_at"),
                         "creators": ["Tool: ZELNX"]},
        "packages": packages,
    }
    return doc, "application/json"


def _to_csv(state: dict[str, Any], layer: str) -> tuple[str, str]:
    import csv
    import io

    comps = _layer_components(state, layer)
    keys = sorted({k for c in comps for k in c})
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=keys)
    writer.writeheader()
    for c in comps:
        writer.writerow({k: c.get(k, "") for k in keys})
    return buf.getvalue(), "text/csv"


def _layer_components(state: dict[str, Any], layer: str) -> list[dict[str, Any]]:
    layers = state.get("layers") or {}
    if layer == "all":
        return [c for l in layers.values() for c in (l.get("components") if isinstance(l, dict) else [])]
    return (layers.get(layer) or {}).get("components", [])


# --------------------------------------------------------------------------- #
# Export — XML (CycloneDX XML) + PDF
# --------------------------------------------------------------------------- #

def _to_cyclonedx_xml(state: dict[str, Any], layer: str) -> tuple[str, str]:
    """CycloneDX 1.5 XML representation of the selected layer."""
    import xml.etree.ElementTree as ET

    comps = _layer_components(state, layer)
    dig = hashlib.sha256((state.get("snapshot_id") or "").encode()).hexdigest()[:32]
    serial = f"urn:uuid:{dig[:8]}-{dig[8:12]}-{dig[12:16]}-{dig[16:20]}-{dig[20:32]}"

    ns = "http://cyclonedx.org/schema/bom/1.5"
    ET.register_namespace("", ns)
    root = ET.Element(f"{{{ns}}}bom")
    root.set("version", str(state.get("state_version") or 1))
    root.set("serialNumber", serial)

    metadata = ET.SubElement(root, f"{{{ns}}}metadata")
    if state.get("generated_at"):
        ET.SubElement(metadata, f"{{{ns}}}timestamp").text = state["generated_at"]
    comp_el = ET.SubElement(metadata, f"{{{ns}}}component")
    comp_el.set("type", "application")
    name_el = ET.SubElement(comp_el, f"{{{ns}}}name")
    name_el.text = "ZELNX Technology BOM"

    comps_el = ET.SubElement(root, f"{{{ns}}}components")
    for c in comps:
        el = ET.SubElement(comps_el, f"{{{ns}}}component")
        el.set("type", _cdx_type(c, layer))
        if c.get("bom-ref"):
            el.set("bom-ref", c["bom-ref"])
        n = ET.SubElement(el, f"{{{ns}}}name")
        n.text = (c.get("name") or c.get("algorithm") or c.get("model")
                  or c.get("subject") or "component")
        if c.get("version"):
            v = ET.SubElement(el, f"{{{ns}}}version")
            v.text = str(c["version"])
        if c.get("purpose"):
            d = ET.SubElement(el, f"{{{ns}}}description")
            d.text = c["purpose"]

    xml_str = ET.tostring(root, encoding="unicode")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + xml_str, "application/xml"


def _pdf_escape(text: Any) -> str:
    return str(text).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _to_pdf(state: dict[str, Any], layer: str) -> tuple[bytes, str]:
    """A dependency-free PDF 1.4 summary of the BOM layer (human-readable)."""

    comps = _layer_components(state, layer)
    lines: list[tuple[str, int]] = []

    def line(text: Any, size: int = 10, gap: bool = False) -> None:
        lines.append((_pdf_escape(text), size))
        if gap:
            lines.append(("", 6))

    line("ZELNX Technology BOM", 16)
    line(f"Snapshot: {state.get('snapshot_id') or '—'}    Environment: {state.get('environment') or '—'}", 9)
    line(f"State version: {state.get('state_version') or 0}    Generated: {state.get('generated_at') or '—'}", 9)
    line(f"Layer: {layer}    Components: {len(comps)}", 10, gap=True)

    for layer_name, ldata in (state.get("layers") or {}).items():
        line(f"{layer_name}: {ldata.get('count', 0)}", 9)
    line("", 6)

    line("Components", 13, gap=True)
    for c in comps[:200]:
        name = c.get("name") or c.get("algorithm") or c.get("model") or c.get("subject") or (c.get("bom-ref") or "—")
        ver = c.get("version") or c.get("firmware_version") or ""
        extra = f"  v{ver}" if ver else ""
        line(f"  {name}{extra}   [{_cdx_type(c, layer)}]", 9)
    if len(comps) > 200:
        line(f"  … plus {len(comps) - 200} more (truncated)", 8)

    line("", 6)
    line(f"integrity_sha256: {state.get('_export_integrity') or state.get('fingerprint') or ''}", 8)

    pages = [lines[i:i + 46] for i in range(0, len(lines), 46)] or [[("", 10)]]
    pdf = _build_pdf(pages, title="ZELNX Technology BOM")
    return pdf, "application/pdf"


def _build_pdf(pages: list[list[tuple[str, int]]], *, title: str) -> bytes:
    import zlib

    objects: list[bytes] = []

    def add(obj: bytes) -> int:
        objects.append(obj)
        return len(objects)

    page_ids, content_ids, next_id = [], [], 4
    for _ in pages:
        page_ids.append(next_id)
        content_ids.append(next_id + 1)
        next_id += 2

    def stream_obj(data: bytes) -> bytes:
        comp = zlib.compress(data)
        return (b"<< /Length " + str(len(comp)).encode() + b" /Filter /FlateDecode >>\nstream\n"
                + comp + b"\nendstream")

    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    kids = b" ".join(f"{pid} 0 R".encode() for pid in page_ids)
    objects.append(b"<< /Type /Pages /Kids [" + kids + b"] /Count " + str(len(pages)).encode()
                   + b" /MediaBox [0 0 612 792] >>")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    for idx, text_lines in enumerate(pages):
        cid = content_ids[idx]
        objects.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                       b"/Resources << /Font << /F1 3 0 R >> >> /Contents "
                       + f"{cid} 0 R".encode() + b" >>")
        objects.append(stream_obj(_page_content(text_lines).encode("latin-1", "replace")))

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref_pos = len(out)
    out += b"xref\n0 " + str(len(objects) + 1).encode() + b"\n0000000000 65535 f \n"
    for off in offsets[1:]:
        out += f"{off:010d} 00000 n \n".encode()
    out += (b"trailer\n<< /Size " + str(len(objects) + 1).encode() + b" /Root 1 0 R >>\n"
            b"startxref\n" + str(xref_pos).encode() + b"\n%%EOF")
    return bytes(out)


def _page_content(lines: list[tuple[str, int]]) -> str:
    ops = ["BT", "/F1 10 Tf", "50 740 Td", "14 TL"]
    for text, size in lines:
        ops.append(f"/F1 {size} Tf")
        ops.append(f"({text}) Tj")
        ops.append("T*")
    ops.append("ET")
    return "\n".join(ops)


# --------------------------------------------------------------------------- #
# Filtering (Export Service — validate -> filter -> generate)
# --------------------------------------------------------------------------- #

def filter_technology_bom(state: dict[str, Any], filters: dict[str, Any] | None = None) -> dict[str, Any]:
    """Project the state onto a sub-set that matches ``filters`` (no fabrication).

    Supported filters (all optional):
    - ``layer``       "sbom"|"cbom"|"hbom"|"vendor"|"certificates"|"all" (default all)
    - ``search``      substring on name / bom-ref / algorithm / model / vendor
    - ``risk_level``  keep hbom+vendor components at >= this risk level (LOW/MEDIUM/HIGH/CRITICAL)
    - ``key_size_min`` keep crypto components with key_size >= this
    - ``type``        component type substring (library/crypto/hardware/vendor/certificate)
    - ``include_certificates`` bool (default True)
    """
    f = {k: v for k, v in (filters or {}).items() if v not in (None, "", "all", "ALL")}
    layer = str(f.get("layer") or "all")
    search = str(f.get("search") or "").strip().lower()
    risk = str(f.get("risk_level") or "").upper()
    key_min = f.get("key_size_min")
    ctype = str(f.get("type") or "").strip().lower()
    include_certs = f.get("include_certificates", True) not in (False, "false", "0")

    layers = {k: dict(v) for k, v in (state.get("layers") or {}).items()}
    selected = ["sbom", "cbom", "hbom", "vendor"] if layer == "all" else [layer]

    def keep(c: dict[str, Any]) -> bool:
        if search:
            hay = " ".join(str(c.get(k, "")) for k in ("name", "bom-ref", "algorithm", "model", "subject", "vendor"))
            if search not in hay.lower():
                return False
        if risk:
            lvl = str(c.get("risk_level") or "").upper()
            order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            if lvl and order.get(lvl, 0) < order.get(risk, 0):
                return False
        if ctype and ctype not in f"{c.get('type')} {c.get('device_type')} {c.get('algorithm')}".lower():
            return False
        if key_min is not None:
            try:
                sz = int(c.get("key_size") or 0)
                if sz < int(key_min):
                    return False
            except (TypeError, ValueError):
                return False
        return True

    new_layers: dict[str, Any] = {}
    for name, ldata in layers.items():
        if name == "certificates":
            if not include_certs:
                continue
            comps = list(ldata.get("components") or [])
            if search:
                comps = [c for c in comps if search in str(c.get("subject", "")).lower()
                         or search in str(c.get("fingerprint", "")).lower()]
            new_layers[name] = {"count": len(comps), "components": comps}
            continue
        if name not in selected:
            continue
        comps = [c for c in (ldata.get("components") or []) if keep(c)]
        new_layers[name] = {"count": len(comps), "components": comps}

    new_state = dict(state)
    new_state["layers"] = new_layers
    new_state["components_by_layer"] = {
        k: v["count"] for k, v in new_layers.items() if k != "certificates"
    }
    new_state["total_components"] = sum(v["count"] for k, v in new_layers.items() if k != "certificates")
    new_state["certificate_count"] = (new_layers.get("certificates") or {}).get("count", 0)
    new_state["filter"] = f
    new_state["fingerprint"] = fingerprint_state(new_state)
    return new_state
