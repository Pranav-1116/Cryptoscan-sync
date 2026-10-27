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
                "component_count": 0, "gaps": ["document is empty or not a JSON object"],
                "score": "0/7"}
    cdx = _is_cdx(bom)
    if not cdx and not bom.get("spdxVersion"):
        return {"format": "unknown", "compliant": False, "elements": [],
                "component_count": 0,
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
        # SPDX records component digests as checksums (purl lives in externalRefs
        # and is counted under unique identifiers above)
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

    required = list(results)
    satisfied = sum(1 for e in required if e["status"] == "PASS")
    gaps = [f"{e['label']}: {e['detail']}" for e in required if e["status"] != "PASS"]
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
def _stable_ref_key(ref: str, name: str) -> str:
    """A version-independent identity for a component reference.

    A purl carries the version (``pkg:pypi/requests@2.31.0``), so keying a diff
    on the raw ref would turn every upgrade into "removed + added". Stripping the
    version keeps upgrades, downgrades and licence changes recognisable.
    """
    if not ref:
        return name
    head = ref.split("@", 1)[0] if "@" in ref else ref
    return head.strip().lower()


def _norm_components(bom: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Key -> {name, version, crypto, purl, license} for either format.

    The key is the lowercased component name, which is what every caller of the
    diff expects. Names are not unique, though: a binary called ``openssl`` and
    the ``OpenSSL`` library inside it are two components. When one name covers
    several components the key becomes the version-independent reference, so a
    collision cannot hide a component from the diff.
    """
    rows: list[dict[str, Any]] = []
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
            ref = str(comp.get("bom-ref") or "").strip()
            rows.append({
                "name": name, "ref": ref,
                "payload": {
                    "name": name,
                    "ref": ref,
                    "version": str(comp.get("version") or "") or None,
                    "crypto": props.get("cryptoscan:crypto-library") == "true",
                    "purl": str(comp.get("purl") or "") or None,
                    "license": license_str,
                },
            })
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
            spdx_id = str(pkg.get("SPDXID") or "")
            rows.append({
                "name": name,
                "ref": "" if spdx_id in ("", "NOASSERTION") else spdx_id,
                "payload": {
                    "name": name,
                    "ref": spdx_id if spdx_id not in ("", "NOASSERTION") else None,
                    "version": str(pkg.get("versionInfo") or "") or None,
                    "crypto": False,
                    "purl": purl,
                    "license": None if lic in ("", "NOASSERTION") else lic,
                },
            })

    out: dict[str, dict[str, Any]] = {}
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(row["name"], []).append(row)
    for name, group in grouped.items():
        if len(group) == 1:
            out[name] = group[0]["payload"]
            continue
        # deterministic: the entry with the shortest stable key keeps the plain
        # name, the others are keyed by their own reference
        for row in sorted(group, key=lambda r: (_stable_ref_key(r["ref"], name), r["ref"])):
            key = _stable_ref_key(row["ref"], name)
            if key == name or key in out:
                key = (row["ref"] or name).strip().lower()
            while key in out:
                key = f"{key}#{len(out)}"
            out[key] = row["payload"]
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

    def _row(key: str, row: dict[str, Any]) -> dict[str, Any]:
        return {"name": row.get("name") or key, "ref": row.get("ref") or key,
                "version": row["version"], "crypto": row["crypto"]}

    for key in sorted(set(after) - set(before)):
        added.append(_row(key, after[key]))
    for key in sorted(set(before) - set(after)):
        removed.append(_row(key, before[key]))
    for key in sorted(set(before) & set(after)):
        old_row, new_row = before[key], after[key]
        name = new_row.get("name") or key
        if (old_row["version"] or "") != (new_row["version"] or ""):
            direction = "change"
            if old_row["version"] and new_row["version"]:
                cmp = _vercmp(new_row["version"], old_row["version"])
                direction = "upgrade" if cmp > 0 else ("downgrade" if cmp < 0 else "change")
            changed.append({"name": name, "ref": key, "from": old_row["version"],
                            "to": new_row["version"], "direction": direction,
                            "crypto": new_row["crypto"] or old_row["crypto"]})
        if (old_row["license"] or "") != (new_row["license"] or ""):
            changed.append({"name": name, "ref": key, "from": old_row["license"],
                            "to": new_row["license"], "direction": "license_change",
                            "crypto": new_row["crypto"] or old_row["crypto"]})
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


# ------------------------------------------------------------------- gate ---- #
DEFAULT_GATE_POLICY: dict[str, Any] = {
    # fail on any critical CVE unless the policy raises the allowance
    "allow_critical": 0,
    "allow_high": None,          # None = unlimited
    "deny_licenses": [],         # e.g. ["GPL-3.0-only", "AGPL-3.0-only"]
    "require_minimum_elements": False,
    "max_unpinned": None,        # None = do not gate on pinning
    "require_signed": False,
    # findings a *scanner* raised about the artifact itself (a binary that ships
    # a private key) are not CVEs and never appear in the document, so they are
    # gated separately — a leaked key must not be a PASS
    "allow_scanner_critical": 0,
    "allow_scanner_high": None,
    # full license policy (see devsecops.sbom_license); `deny_licenses` above
    # remains as the simple, backwards-compatible deny list
    "license_policy": None,
}


def _cve_counts(bom: dict[str, Any]) -> dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for vuln in bom.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        severity = "UNKNOWN"
        ratings = vuln.get("ratings") or []
        if ratings and isinstance(ratings[0], dict):
            severity = str(ratings[0].get("severity") or "unknown").upper()
        elif vuln.get("severity"):
            severity = str(vuln["severity"]).upper()
        counts[severity if severity in counts else "UNKNOWN"] += 1
    return counts


def _licenses(bom: dict[str, Any]) -> list[tuple[str, str]]:
    """(component, license) pairs from either format."""
    out: list[tuple[str, str]] = []
    if _is_cdx(bom):
        for comp in _cdx_components(bom):
            for lic in comp.get("licenses") or []:
                if not isinstance(lic, dict):
                    continue
                value = (lic.get("expression")
                         or (lic.get("license") or {}).get("id")
                         or (lic.get("license") or {}).get("name"))
                if value:
                    out.append((str(comp.get("name") or "?"), str(value)))
    else:
        for pkg in spdx_components(bom):
            value = str(pkg.get("licenseDeclared") or "")
            if value and value != "NOASSERTION":
                out.append((str(pkg.get("name") or "?"), value))
    return out


def evaluate_gate(bom: dict[str, Any] | None, *,
                  policy: dict[str, Any] | None = None,
                  unpinned: int | None = None,
                  signed: bool | None = None,
                  scanner_findings: dict[str, int] | None = None) -> dict[str, Any]:
    """Deterministic supply-chain gate for a rendered SBOM.

    Blockers fail a pipeline; warnings inform. Every finding names the policy
    field that produced it, and counts come from the document itself — except
    ``scanner_findings``, which the caller passes because they are facts the
    scanning service recorded about the artifact (a binary that ships a private
    key) and are not CVEs in the document. A scanner finding is a blocker above
    the allowance and a warning within it, so a critical one never reads PASS.
    """
    bom = bom or {}
    effective = dict(DEFAULT_GATE_POLICY)
    effective.update({k: v for k, v in (policy or {}).items() if k in DEFAULT_GATE_POLICY})
    blockers: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []

    counts = _cve_counts(bom)
    if counts["CRITICAL"] > int(effective["allow_critical"]):
        blockers.append({"code": "GATE-CVE-CRITICAL", "severity": "CRITICAL",
                         "detail": f"{counts['CRITICAL']} critical CVE(s) "
                                   f"(allowed: {effective['allow_critical']})"})
    allow_high = effective["allow_high"]
    if allow_high is not None and counts["HIGH"] > int(allow_high):
        blockers.append({"code": "GATE-CVE-HIGH", "severity": "HIGH",
                         "detail": f"{counts['HIGH']} high CVE(s) (allowed: {allow_high})"})
    elif allow_high is None and counts["HIGH"]:
        warnings.append({"code": "GATE-CVE-HIGH-PRESENT", "severity": "HIGH",
                         "detail": f"{counts['HIGH']} high CVE(s) present (no limit configured)"})

    denied = {str(x).lower() for x in (effective["deny_licenses"] or [])}
    if denied:
        hits = sorted({(name, lic) for name, lic in _licenses(bom) if lic.lower() in denied})
        for name, lic in hits[:50]:
            blockers.append({"code": "GATE-LICENSE-DENIED", "severity": "HIGH",
                             "detail": f"{name} declares denied license {lic}"})
        if len(hits) > 50:
            warnings.append({"code": "GATE-LICENSE-DENIED-TRUNCATED", "severity": "INFO",
                             "detail": f"{len(hits) - 50} further license findings omitted"})

    license_report = None
    if effective["license_policy"]:
        from devsecops.sbom_license import check_license_policy

        license_report = check_license_policy(bom, policy=effective["license_policy"])
        for violation in license_report["violations"]:
            severity = "CRITICAL" if violation["code"] == "LICENSE-FORBIDDEN" else "HIGH"
            target = blockers if violation["code"] == "LICENSE-FORBIDDEN" else warnings
            target.append({"code": violation["code"].replace("LICENSE-", "GATE-LICENSE-"),
                           "severity": severity, "detail": violation["detail"]})

    compliance = check_minimum_elements(bom)
    if effective["require_minimum_elements"] and not compliance["compliant"]:
        blockers.append({"code": "GATE-MINIMUM-ELEMENTS", "severity": "MEDIUM",
                         "detail": f"minimum elements {compliance['score']}: "
                                   + "; ".join(compliance["gaps"])})
    elif not compliance["compliant"]:
        warnings.append({"code": "GATE-MINIMUM-ELEMENTS-GAPS", "severity": "MEDIUM",
                         "detail": f"{compliance['score']} — " + "; ".join(compliance["gaps"])})

    if effective["max_unpinned"] is not None and unpinned is not None:
        if unpinned > int(effective["max_unpinned"]):
            blockers.append({"code": "GATE-UNPINNED", "severity": "MEDIUM",
                             "detail": f"{unpinned} unpinned component(s) (allowed: {effective['max_unpinned']})"})
        elif unpinned:
            warnings.append({"code": "GATE-UNPINNED-PRESENT", "severity": "LOW",
                             "detail": f"{unpinned} unpinned component(s) within the allowance"})

    if effective["require_signed"] and signed is False:
        blockers.append({"code": "GATE-UNSIGNED", "severity": "MEDIUM",
                         "detail": "artifact manifest is not signed"})

    scanner_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for severity, value in (scanner_findings or {}).items():
        key = str(severity).upper()
        if key in scanner_counts:
            scanner_counts[key] = int(value or 0)
    for severity, limit_field, code in (("CRITICAL", "allow_scanner_critical", "GATE-SCAN-CRITICAL"),
                                        ("HIGH", "allow_scanner_high", "GATE-SCAN-HIGH")):
        if not scanner_counts[severity]:
            continue
        limit = effective[limit_field]
        if limit is not None and scanner_counts[severity] > int(limit):
            blockers.append({"code": code, "severity": severity,
                             "detail": f"{scanner_counts[severity]} {severity} finding(s) from the "
                                       f"scan itself (allowed: {limit}) — a finding about the "
                                       f"artifact is not a CVE and is not in the document"})
        else:
            # within the allowance (or no allowance configured for this severity):
            # reported, never silently dropped
            warnings.append({"code": f"{code}-PRESENT", "severity": severity,
                             "detail": f"{scanner_counts[severity]} {severity} finding(s) from the "
                                       f"scan itself"})

    result = {
        "verdict": "FAIL" if blockers else "PASS",
        "policy": effective,
        "counts": {"components": compliance["component_count"], **counts,
                   "unpinned": unpinned, "minimum_elements": compliance["score"],
                   **({"scanner_findings": scanner_counts} if scanner_findings else {})},
        "blockers": blockers,
        "warnings": warnings,
    }
    if license_report is not None:
        result["license_verdict"] = license_report["verdict"]
        result["license_inventory"] = {
            "distinct_licenses": license_report["inventory"]["distinct_licenses"],
            "undeclared": len(license_report["inventory"]["undeclared"]),
            "classes": license_report["inventory"]["classes"],
        }
    return result
