"""SBOM import/export in CycloneDX (1.x) and SPDX (2.3) + dependency pinning.

Deterministic conversion into a single normalized component model, plus
export back out to both standards. Import supports CycloneDX BOM JSON and
SPDX JSON/Tag-Value-ish field maps. Also provides dependency-graph version
pinning checks (unpinned/range/branch/ digest-less references).

Normalized component:
  {"purl","name","version","ecosystem","license","hashes":{"sha256":...},
   "depends_on":[purl,...],"supplier"}
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from devsecops.container_scan import version_compare


@dataclass
class Component:
    name: str
    version: str | None = None
    ecosystem: str = "generic"
    purl: str | None = None
    license: str | None = None
    supplier: str | None = None
    hashes: dict[str, str] = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)

    def to_norm(self) -> dict[str, Any]:
        return {"purl": self.purl, "name": self.name, "version": self.version,
                "ecosystem": self.ecosystem, "license": self.license,
                "supplier": self.supplier, "hashes": self.hashes,
                "depends_on": self.depends_on}


_PURL_RE = re.compile(r"^pkg:([a-zA-Z0-9]+)/(.+)$")


def _eco_from_purl(purl: str | None) -> tuple[str, str, str | None]:
    """Return (ecosystem, name, version) from a Package URL."""
    if not purl:
        return "generic", "", None
    m = _PURL_RE.match(purl.split("?")[0])
    if not m:
        return "generic", purl, None
    eco = m.group(1).lower()
    rest = m.group(2)
    if "@" in rest:
        path, version = rest.rsplit("@", 1)
    else:
        path, version = rest, None
    name = path.split("/")[-1]
    return eco, name, version


# ------------------------------------------------------------ import ------ #
def import_cyclonedx(doc: dict[str, Any]) -> list[dict[str, Any]]:
    comps: list[Component] = []
    deps_index = {d.get("ref"): d.get("dependsOn", []) or []
                  for d in (doc.get("dependencies") or [])}
    for c in doc.get("components", []) or []:
        purl = c.get("purl")
        eco, name, ver = _eco_from_purl(purl)
        hashes = {h.get("alg", "").lower().replace("-", ""): h.get("content")
                  for h in (c.get("hashes") or [])}
        lic = None
        if c.get("licenses"):
            lic0 = c["licenses"][0]
            lic = (lic0.get("license", {}) or {}).get("id") or lic0.get("expression")
        comps.append(Component(
            name=c.get("name") or name,
            version=c.get("version") or ver,
            ecosystem=eco,
            purl=purl, license=lic,
            supplier=(c.get("supplier") or {}).get("name") if isinstance(c.get("supplier"), dict) else c.get("supplier"),
            hashes=hashes,
            depends_on=list(deps_index.get(c.get("bom-ref") or c.get("purl"), [])),
        ))
    return [c.to_norm() for c in comps]


def import_spdx(doc: dict[str, Any]) -> list[dict[str, Any]]:
    # SPDX JSON
    comps: list[Component] = []
    name_to_purl: dict[str, str] = {}
    packages = doc.get("packages")
    if packages is not None:
        for p in packages:
            ext_refs = {r.get("referenceType"): r.get("referenceLocator")
                        for r in (p.get("externalRefs") or [])}
            purl = ext_refs.get("purl")
            eco, name, ver = _eco_from_purl(purl)
            checksums = {c.get("algorithm", "").lower().replace("-", ""): c.get("checksumValue")
                         for c in (p.get("checksums") or [])}
            comp = Component(
                name=p.get("name") or name,
                version=p.get("versionInfo") or ver,
                ecosystem=eco, purl=purl,
                license=(p.get("licenseConcluded") if p.get("licenseConcluded") not in ("NOASSERTION",) else None),
                supplier=(p.get("supplier") or "").replace("Organization: ", "").replace("Person: ", "") or None,
                hashes=checksums)
            name_to_purl[p.get("SPDXID")] = purl or comp.name
            comps.append(comp)
        for rel in doc.get("relationships", []) or []:
            if rel.get("relationshipType") == "DEPENDS_ON":
                src = name_to_purl.get(rel.get("spdxElementId"))
                dst = name_to_purl.get(rel.get("relatedSpdxElement"))
                for c in comps:
                    if c.purl == src and dst and dst not in c.depends_on:
                        c.depends_on.append(dst)
        return [c.to_norm() for c in comps]
    # Tag-Value-ish: caller may pass a pre-normalized {"components":[...]}
    return list(doc.get("components", []))


def import_sbom(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Auto-detect CycloneDX vs SPDX and return normalized components."""
    if "components" in doc and "bomFormat" in doc:
        return import_cyclonedx(doc)
    if "bomFormat" in doc or doc.get("specVersion", "").startswith("1.") or "spdxVersion" in doc:
        return import_spdx(doc)
    if "spdxVersion" in doc or "packages" in doc:
        return import_spdx(doc)
    if "components" in doc:  # already normalized or cyclonedx-ish
        if doc.get("components") and isinstance(doc["components"][0], dict) and "purl" in doc["components"][0]:
            if "bom-ref" in str(doc) or "dependencies" in doc:
                return import_cyclonedx(doc)
            return list(doc["components"])
    raise ValueError("unrecognized SBOM format (expected CycloneDX or SPDX JSON)")


# ------------------------------------------------------------ export ------ #
def export_cyclonedx(components: list[dict[str, Any]], *, tool: str = "CryptoScan") -> dict[str, Any]:
    cdx_comps = []
    deps = []
    for c in components:
        ref = c.get("purl") or f"pkg:{c.get('ecosystem','generic')}/{c.get('name')}"
        entry = {
            "type": "library", "bom-ref": ref, "name": c.get("name"),
            "version": c.get("version"), "purl": c.get("purl"),
            "licenses": ([{"license": {"id": c["license"]}}] if c.get("license") else []),
            "hashes": [{"alg": {"sha256": "SHA-256", "sha1": "SHA-1"}.get(k, k.upper()),
                        "content": v} for k, v in (c.get("hashes") or {}).items()],
        }
        if c.get("supplier"):
            entry["supplier"] = {"name": c["supplier"]}
        cdx_comps.append(entry)
        if c.get("depends_on"):
            deps.append({"ref": ref, "dependsOn": c["depends_on"]})
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "metadata": {"tools": [{"vendor": "CryptoScan", "name": tool}],
                     "component": {"type": "application", "name": "cryptoscan-sbom"}},
        "components": cdx_comps,
        "dependencies": deps,
    }


def export_spdx(components: list[dict[str, Any]], *, doc_name: str = "CryptoScan-SBOM") -> dict[str, Any]:
    packages, relationships = [], []
    for i, c in enumerate(components, start=1):
        spdx_id = f"SPDXRef-Package-{i}"
        packages.append({
            "SPDXID": spdx_id, "name": c.get("name"),
            "versionInfo": c.get("version"),
            "licenseConcluded": c.get("license") or "NOASSERTION",
            "supplier": f"Organization: {c['supplier']}" if c.get("supplier") else "NOASSERTION",
            "externalRefs": ([{"referenceCategory": "PACKAGE-MANAGER",
                              "referenceType": "purl", "referenceLocator": c["purl"]}]
                             if c.get("purl") else []),
            "checksums": [{"algorithm": {"sha256": "SHA256"}.get(k, k.upper()),
                           "checksumValue": v} for k, v in (c.get("hashes") or {}).items()],
        })
    return {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT", "name": doc_name,
            "documentNamespace": f"https://cryptoscan.internal/sbom/{doc_name}",
            "creationInfo": {"creators": ["Tool: CryptoScan"], "specVersion": "2.3"},
            "packages": packages, "relationships": relationships}


# ------------------------------------------------------- pinning checks --- #
_RANGE_RE = re.compile(r"[\^~*xX]|>=|<=|>|<|\|\||\s-\s|latest|main|master|HEAD")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")


def check_pinning(components: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Flag dependencies not pinned to an exact, verifiable version."""
    findings = []
    total = 0
    for c in components:
        total += 1
        name = c.get("name") or "?"
        version = c.get("version")
        coord = c.get("purl") or f"{c.get('ecosystem','?')}:{name}@{version}"
        if not version:
            findings.append({"coordinate": coord, "code": "PIN-MISSING", "severity": "HIGH",
                             "detail": "no version specified"})
        else:
            if str(version).lower() in ("latest", "main", "master", "head") or _RANGE_RE.search(str(version)):
                findings.append({"coordinate": coord, "code": "PIN-RANGE", "severity": "MEDIUM",
                                 "detail": f"version specifier is a range/branch: {version!r}"})
        # containers/image refs should always carry a sha256 digest
        if c.get("ecosystem") in ("docker", "oci", "container"):
            has_digest = _DIGEST_RE.search(str(c.get("purl") or "")) or c.get("hashes", {}).get("sha256")
            if not has_digest:
                findings.append({"coordinate": coord, "code": "PIN-NO-DIGEST", "severity": "MEDIUM",
                                 "detail": "image reference not pinned by sha256 digest"})
    unpinned_coords = {f["coordinate"] for f in findings if f["code"] in ("PIN-MISSING", "PIN-RANGE")}
    return {"total_components": total, "pinned": total - len(unpinned_coords),
            "unpinned": len(unpinned_coords), "findings": findings}


def dependency_graph(components: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a simple deterministic adjacency graph and detect cycles."""
    nodes = [c.get("purl") or c.get("name") for c in components]
    edges = []
    for c in components:
        src = c.get("purl") or c.get("name")
        for dst in c.get("depends_on", []):
            edges.append({"from": src, "to": dst})
    # cycle detection (DFS)
    adj: dict[str, list[str]] = {}
    for e in edges:
        adj.setdefault(e["from"], []).append(e["to"])
    cycles: list[list[str]] = []
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {n: WHITE for n in nodes}

    def dfs(u, stack):
        color[u] = GRAY
        for v in adj.get(u, []):
            if color.get(v) == GRAY:
                cycles.append(stack[stack.index(v):] + [v] if v in stack else [v])
            elif color.get(v) == WHITE:
                dfs(v, stack + [v])
        color[u] = BLACK

    for n in nodes:
        if color.get(n) == WHITE:
            dfs(n, [n])
    return {"nodes": nodes, "edges": edges, "edge_count": len(edges),
            "cycles": cycles, "has_cycle": bool(cycles)}
