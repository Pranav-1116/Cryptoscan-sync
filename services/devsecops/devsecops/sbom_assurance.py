"""SBOM assurance: minimum-elements validation and SBOM-to-SBOM diffing.

Two deterministic checks a supply-chain reviewer actually runs:

* ``check_minimum_elements(bom)`` — the NTIA "Minimum Elements for an SBOM"
  checklist (supplier, component name, version, other unique identifiers,
  dependency relationship, SBOM author, timestamp) evaluated against a
  CycloneDX or SPDX document, with per-element coverage counts and the exact
  gaps. No element is marked present without evidence in the document.
* ``diff_boms(old, new)`` — what changed between two SBOMs: components added,
  removed, version-changed (with upgrade/downgrade direction), crypto-relevant
  deltas and a review verdict. Accepts CycloneDX (own or imported) and SPDX.

Both engines are pure functions over documents — no network, no AI.
"""
from __future__ import annotations

from typing import Any

# NTIA minimum elements (2021) — the widely-adopted baseline for "is this
# SBOM complete enough to consume?". `recommended` entries are reported too
# but never fail the document.
ELEMENTS: tuple[tuple[str, str, str], ...] = (
    ("supplier", "Supplier name", "who produced the component"),
    ("component_name", "Component name", "name of each component"),
    ("version", "Component version", "version of each component"),
    ("unique_id", "Other unique identifiers", "purl/CPE identifier"),
    ("dependencies", "Dependency relationship", "how components relate"),
    ("author", "Author of SBOM data", "who produced the SBOM"),
    ("timestamp", "Timestamp", "when the SBOM was created"),
)
RECOMMENDED: tuple[tuple[str, str, str], ...] = (
    ("hashes", "Component hashes", "cryptographic fingerprint per component"),
)


def _is_cdx(bom: dict[str, Any]) -> bool:
    return str(bom.get("bomFormat") or "").lower() == "cyclonedx"


def _cdx_components(bom: dict[str, Any]) -> list[dict[str, Any]]:
    return [c for c in (bom.get("components") or []) if isinstance(c, dict)]


def _spdx_root_ids(bom: dict[str, Any]) -> set[str]:
    """SPDXIDs that describe the document's own subject, not a component.

    SPDX describes the scanned target as a package (our renderer uses
    ``SPDXRef-Container``) and links it with a ``DESCRIBES`` relationship —
    counting it as a component would skew every coverage figure.
    """
    targets = {"SPDXRef-DOCUMENT"}
    doc_name = str(bom.get("name") or "").strip().lower()
    for rel in bom.get("relationships") or []:
        if isinstance(rel, dict) and str(rel.get("relationshipType") or "").upper() == "DESCRIBES":
            target = str(rel.get("relatedSpdxElement") or "")
            if target:
                targets.add(target)
    if doc_name:
        for pkg in bom.get("packages") or []:
            if isinstance(pkg, dict) and str(pkg.get("name") or "").strip().lower() == doc_name:
                targets.add(str(pkg.get("SPDXID") or ""))
    return targets


def spdx_components(bom: dict[str, Any]) -> list[dict[str, Any]]:
    """Real components of an SPDX document (its described subject excluded)."""
    roots = _spdx_root_ids(bom)
    out = []
    for pkg in bom.get("packages") or []:
        if isinstance(pkg, dict) and str(pkg.get("SPDXID") or "") not in roots:
            out.append(pkg)
    return out


def _count(rows: list[dict[str, Any]], predicate) -> int:
    return sum(1 for row in rows if predicate(row))


def _coverage(hits: int, total: int) -> str:
    return f"{hits}/{total} components"


def check_minimum_elements(bom: dict[str, Any] | None) -> dict[str, Any]:
    """Evaluate the NTIA minimum elements against a CycloneDX/SPDX document."""
    bom = bom or {}
    if not isinstance(bom, dict) or not bom:
        return {"format": "unknown", "compliant": False, "elements": [],
                "gaps": ["document is empty or not a JSON object"], "score": "0/7"}
    cdx = _is_cdx(bom)
    if not cdx and not bom.get("spdxVersion"):
        return {"format": "unknown", "compliant": False, "elements": [],
                "gaps": ["unsupported document: expected CycloneDX or SPDX JSON"],
                "score": "0/7"}

    components = _cdx_components(bom) if cdx else spdx_components(bom)
    total = len(components)
    metadata = bom.get("metadata") if isinstance(bom.get("metadata"), dict) else {}

    if cdx:
        supplier_hits = _count(components, lambda c: bool(c.get("supplier")))
        name_hits = _count(components, lambda c: bool(str(c.get("name") or "").strip()))
        version_hits = _count(components, lambda c: bool(str(c.get("version") or "").strip()))
        id_hits = _count(components, lambda c: bool(c.get("purl") or c.get("cpe")))
        hash_hits = _count(components, lambda c: bool(c.get("hashes")))
        dep_edges = bom.get("dependencies") or []
        has_deps = bool(dep_edges)
        author = metadata.get("authors") or ((metadata.get("supplier") or {}).get("name") if isinstance(metadata.get("supplier"), dict) else None) or metadata.get("manufacturer")
        timestamp = metadata.get("timestamp")
        spec_version = str(bom.get("specVersion") or "")
    else:
        supplier_hits = _count(components, lambda c: bool(c.get("supplier") or c.get("originator")) and
                              str(c.get("supplier") or c.get("originator")) != "NOASSERTION")
        name_hits = _count(components, lambda c: bool(str(c.get("name") or "").strip()))
        version_hits = _count(components, lambda c: bool(str(c.get("versionInfo") or "").strip())
                              and str(c.get("versionInfo")) != "NOASSERTION")
        id_hits = _count(components, lambda c: any(
            isinstance(ref, dict) and str(ref.get("referenceType") or "").lower() in ("purl", "cpe23type", "cpe22type")
            for ref in (c.get("externalRefs") or [])))
        license_hits = 0
        del license_hits
        hash_hits = _count(components, lambda c: any(
            str(ref.get("referenceType") or "").lower() == "purl" for ref in (c.get("externalRefs") or []))
            and False) or 0
        hash_hits = _count(components, lambda c: bool(c.get("checksums")))
        dep_edges = bom.get("relationships") or []
        has_deps = bool(dep_edges)
        creators = ((bom.get("creationInfo") or {}).get("creators") or [])
        author = creators or None
        timestamp = (bom.get("creationInfo") or {}).get("created")
        spec_version = str(bom.get("spdxVersion") or "")

    def _status(hits: int) -> str:
        if not total:
            return "FAIL"
        if hits == total:
            return "PASS"
        return "PARTIAL" if hits else "FAIL"

    results: list[dict[str, Any]] = []
    for element_id, label, why in ELEMENTS:
        if element_id == "supplier":
            status, detail = _status(supplier_hits), _coverage(supplier_hits, total)
        elif element_id == "component_name":
            status, detail = _status(name_hits), _coverage(name_hits, total)
        elif element_id == "version":
            status, detail = _status(version_hits), _coverage(version_hits, total)
        elif element_id == "unique_id":
            status, detail = _status(id_hits), _coverage(id_hits, total)
        elif element_id == "dependencies":
            status, detail = ("PASS" if has_deps else "FAIL"), f"{len(dep_edges)} relationship(s)"
        elif element_id == "author":
            status, detail = ("PASS" if author else "FAIL"), (str(author[:2]) if isinstance(author, list) else str(author) if author else "not declared")
        else:  # timestamp
            status, detail = ("PASS" if timestamp else "FAIL"), (str(timestamp) if timestamp else "not declared")
        entry = {"id": element_id, "label": label, "why": why, "status": status, "detail": detail}
        results.append(entry)

    recommended = []
    for element_id, label, why in RECOMMENDED:
        recommended.append({"id": element_id, "label": label, "why": why,
                            "status": _status(hash_hits), "detail": _coverage(hash_hits, total)})

    required = [e for e in results]
    satisfied = sum(1 for e in required if e["status"] == "PASS")
    gaps = [
        f"{e['label']}: {e['detail']}" if e["status"] == "PARTIAL" else f"{e['label']}: {e['detail']}"
        for e in required if e["status"] != "PASS"
    ]
    if not total:
        gaps.insert(0, "document declares no components")
    return {
        "format": "cyclonedx" if cdx else "spdx",
        "spec_version": spec_version,
        "component_count": total,
        "elements": required,
        "recommended": recommended,
        "score": f"{satisfied}/{len(required)}",
        "compliant": satisfied == len(required) and total > 0,
        "gaps": gaps,
    }


# ------------------------------------------------------------------- diff ---- #
def _norm_components(bom: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """name(lowercased) -> {version, crypto, purl, license} for either format."""
    out: dict[str, dict[str, Any]] = {}
    if _is_cdx(bom):
        for comp in _cdx_components(bom):
            name = str(comp.get("name") or "").strip().lower()
            if not name:
                continue
            props = {p.get("name"): p.get("value") for p in (comp.get("properties") or [])
                     if isinstance(p, dict)}
            licenses = comp.get("licenses") or []
            license_str = None
            if licenses and isinstance(licenses[0], dict):
                license_str = ((licenses[0].get("license") or {}).get("id")
                               or (licenses[0].get("license") or {}).get("name")
                               or licenses[0].get("expression"))
            out[name] = {
                "version": str(comp.get("version") or "") or None,
                "crypto": props.get("cryptoscan:crypto-library") == "true",
                "purl": str(comp.get("purl") or "") or None,
                "license": license_str,
            }
    else:
        for pkg in spdx_components(bom):
            name = str(pkg.get("name") or "").strip().lower()
            if not name:
                continue
            purl = None
            for ref in pkg.get("externalRefs") or []:
                if isinstance(ref, dict) and str(ref.get("referenceType") or "").lower() == "purl":
                    purl = str(ref.get("referenceLocator") or "") or None
                    break
            lic = str(pkg.get("licenseDeclared") or "")
            out[name] = {
                "version": str(pkg.get("versionInfo") or "") or None,
                "crypto": False,
                "purl": purl,
                "license": None if lic in ("", "NOASSERTION") else lic,
            }
    return out


def _vercmp(a: str, b: str) -> int:
    """Best-effort ordering: numeric tuple compare, then string compare."""
    import re

    def parts(value: str) -> tuple:
        return tuple(int(p) if p.isdigit() else p.lower()
                     for p in re.split(r"[._+-]", str(value)))

    pa, pb = parts(a), parts(b)
    try:
        return (pa > pb) - (pa < pb)
    except TypeError:  # mixed str/int across positions
        return (str(a) > str(b)) - (str(a) < str(b))


def diff_boms(old: dict[str, Any] | None, new: dict[str, Any] | None) -> dict[str, Any]:
    """Component-level diff between two SBOM documents (CycloneDX or SPDX)."""
    before, after = _norm_components(old or {}), _norm_components(new or {})
    added, removed, changed = [], [], []
    for name in sorted(set(after) - set(before)):
        row = after[name]
        added.append({"name": name, "version": row["version"], "crypto": row["crypto"]})
    for name in sorted(set(before) - set(after)):
        row = before[name]
        removed.append({"name": name, "version": row["version"], "crypto": row["crypto"]})
    for name in sorted(set(before) & set(after)):
        old_row, new_row = before[name], after[name]
        if (old_row["version"] or "") != (new_row["version"] or ""):
            direction = "change"
            if old_row["version"] and new_row["version"]:
                cmp = _vercmp(new_row["version"], old_row["version"])
                direction = "upgrade" if cmp > 0 else ("downgrade" if cmp < 0 else "change")
            changed.append({"name": name, "from": old_row["version"], "to": new_row["version"],
                            "direction": direction, "crypto": new_row["crypto"] or old_row["crypto"]})
        if (old_row["license"] or "") != (new_row["license"] or ""):
            changed.append({"name": name, "from": old_row["license"], "to": new_row["license"],
                            "direction": "license_change", "crypto": new_row["crypto"] or old_row["crypto"]})
    crypto_delta = {
        "added": [r for r in added if r["crypto"]],
        "removed": [r for r in removed if r["crypto"]],
        "changed": [c for c in changed if c["crypto"]],
    }
    change_count = len(added) + len(removed) + len(changed)
    crypto_touched = bool(crypto_delta["added"] or crypto_delta["removed"] or crypto_delta["changed"])
    if not change_count:
        verdict = "UNCHANGED"
    elif crypto_touched:
        verdict = "CRYPTO_REVIEW"
    else:
        verdict = "UPDATED"
    return {
        "verdict": verdict,
        "change_count": change_count,
        "summary": {
            "from": {"components": len(before)},
            "to": {"components": len(after)},
            "added": len(added), "removed": len(removed), "changed": len(changed),
        },
        "added": added,
        "removed": removed,
        "changed": changed,
        "crypto_delta": crypto_delta,
    }
