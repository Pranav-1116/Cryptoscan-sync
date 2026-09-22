"""VEX (Vulnerability Exploitability eXchange) generation — deterministic.

A VEX statement answers the question a CVE list cannot: *for this product, is
this vulnerability actually a problem, and what are we doing about it?*

What the engine will and will not claim:

* An advisory matched against a component is reported as
  CycloneDX ``analysis.state = exploitable`` — that is what the advisory itself
  asserts for the version range it matched. The platform does not invent
  reachability analysis it has not performed.
* Operators can override any statement with an explicit analysis
  (``analyses={"CVE-...": {"state": "not_affected", "justification":
  "code_not_reachable", ...}}``). Overrides are validated against the CycloneDX
  enums, recorded with who issued them, and nothing else can produce those
  states.
* An advisory present in the document whose affected component is *not* present
  at a vulnerable version is reported ``not_affected`` /
  ``code_not_present`` — that is provable from the document alone.

The output is a CycloneDX 1.5 document with ``vulnerabilities[].analysis`` so it
can be exchanged directly; a markdown rendering is provided for humans.
"""
from __future__ import annotations

from typing import Any

# CycloneDX analysis.state / analysis.justification enums (1.4/1.5)
STATES = ("resolved", "resolved_with_pedigree", "exploitable", "in_triage",
          "false_positive", "not_affected")
JUSTIFICATIONS = ("code_not_present", "code_not_reachable", "requires_configuration",
                  "requires_dependency", "requires_environment", "protected_by_compiler",
                  "protected_at_runtime", "protected_at_perimeter", "protected_by_mitigating_control")
RESPONSES = ("can_not_fix", "will_not_fix", "update", "rollback", "workaround_available")


def _norm(text: str | None) -> str:
    return str(text or "").strip().lower()


def _cdx_vulns(bom: dict[str, Any]) -> list[dict[str, Any]]:
    return [v for v in (bom.get("vulnerabilities") or []) if isinstance(v, dict)]


def _severity(vuln: dict[str, Any]) -> str:
    ratings = vuln.get("ratings") or []
    if ratings and isinstance(ratings[0], dict) and ratings[0].get("severity"):
        return str(ratings[0]["severity"]).upper()
    return str(vuln.get("severity") or "UNKNOWN").upper()


def _affected_refs(vuln: dict[str, Any]) -> list[str]:
    return [str(a.get("ref")) for a in (vuln.get("affects") or []) if isinstance(a, dict) and a.get("ref")]


def _component_refs(bom: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """bom-ref (and purl) -> component, for the affected-component lookup."""
    index: dict[str, dict[str, Any]] = {}
    for comp in bom.get("components") or []:
        if not isinstance(comp, dict):
            continue
        for key in (comp.get("bom-ref"), comp.get("purl")):
            if key:
                index[str(key)] = comp
    return index


def fixed_version_from(bom: dict[str, Any], cve: str) -> str | None:
    """Best-effort remediation version recorded for an advisory.

    The document itself does not carry ``fixed`` (CycloneDX has no field for a
    vendor remediation version in the analysis block), so this reads the
    generated-document convention: ``affects[].versions`` / a
    ``cryptoscan:fixed-version`` property when a caller stored one.
    """
    for vuln in _cdx_vulns(bom):
        if str(vuln.get("id")) != cve:
            continue
        for entry in vuln.get("affects") or []:
            if not isinstance(entry, dict):
                continue
            if entry.get("fixedVersion"):
                return str(entry["fixedVersion"])
            for version in entry.get("versions") or []:
                if isinstance(version, dict) and version.get("status") == "unaffected" and version.get("version"):
                    return str(version["version"])
        for prop in vuln.get("properties") or []:
            if isinstance(prop, dict) and prop.get("name") == "cryptoscan:fixed-version":
                return str(prop.get("value"))
    return None


def validate_analyses(analyses: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    """Validate operator-supplied analyses; raise ValueError on anything unknown."""
    clean: dict[str, dict[str, Any]] = {}
    for cve, entry in (analyses or {}).items():
        if not isinstance(entry, dict):
            raise ValueError(f"analysis for {cve} must be an object")
        state = str(entry.get("state") or "").strip()
        if state not in STATES:
            raise ValueError(f"analysis for {cve}: state must be one of {', '.join(STATES)}")
        justification = entry.get("justification")
        if justification is not None and str(justification) not in JUSTIFICATIONS:
            raise ValueError(f"analysis for {cve}: justification must be one of "
                             f"{', '.join(JUSTIFICATIONS)}")
        if state == "not_affected" and not justification:
            # CycloneDX requires a justification to assert not_affected — an
            # unexplained "not affected" is exactly the rubber stamp VEX exists
            # to prevent.
            raise ValueError(f"analysis for {cve}: a not_affected statement requires a "
                             "justification (e.g. code_not_reachable)")
        responses = entry.get("response") or []
        if isinstance(responses, str):
            responses = [responses]
        for response in responses:
            if str(response) not in RESPONSES:
                raise ValueError(f"analysis for {cve}: response must be one of {', '.join(RESPONSES)}")
        clean[str(cve)] = {
            "state": state,
            "justification": str(justification) if justification else None,
            "detail": str(entry.get("detail") or "") or None,
            "response": [str(r) for r in responses],
        }
    return clean


def statements(bom: dict[str, Any] | None, *,
               analyses: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Per-advisory VEX statements for a document (deterministic order)."""
    bom = bom or {}
    overrides = validate_analyses(analyses)
    components = _component_refs(bom)
    out: list[dict[str, Any]] = []
    for vuln in _cdx_vulns(bom):
        cve = str(vuln.get("id") or "").strip()
        if not cve:
            continue
        refs = _affected_refs(vuln)
        present = [ref for ref in refs if ref in components]
        fixed = fixed_version_from(bom, cve)
        override = overrides.get(cve)
        if override:
            state = override["state"]
            justification = override["justification"]
            detail = override["detail"] or "statement issued by an operator"
            response = override["response"]
            source = "operator"
        elif refs and not present:
            state, justification = "not_affected", "code_not_present"
            detail = "no component in this document matches the affected version range"
            response = []
            source = "derived"
        elif fixed:
            state, justification = "exploitable", None
            detail = f"matched component is inside the affected range; {fixed} fixes it"
            response = ["update"]
            source = "derived"
        else:
            state, justification = "in_triage", None
            detail = "component inside the affected range; no fixed version recorded"
            response = ["can_not_fix"]
            source = "derived"
        out.append({
            "cve": cve, "state": state, "justification": justification, "detail": detail,
            "response": response, "severity": _severity(vuln), "source": source,
            "fixed_version": fixed,
            "affects": present or refs,
            "affected_components": [
                {"ref": ref, "name": components[ref].get("name"),
                 "version": components[ref].get("version")} for ref in present
            ],
        })
    out.sort(key=lambda s: (s["cve"], s["state"]))
    return out


def counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    summary = {state: 0 for state in STATES}
    for row in rows:
        summary[row["state"]] = summary.get(row["state"], 0) + 1
    return {k: v for k, v in summary.items() if v}


def build_vex_document(bom: dict[str, Any] | None, *, analyses: dict[str, Any] | None = None,
                       author: str | None = None, serial: str | None = None,
                       version: int = 1) -> dict[str, Any]:
    """A CycloneDX 1.5 VEX document (vulnerabilities with analysis blocks)."""
    import uuid
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    rows = statements(bom, analyses=analyses)
    vulnerabilities = []
    for row in rows:
        analysis: dict[str, Any] = {"state": row["state"]}
        if row["justification"]:
            analysis["justification"] = row["justification"]
        if row["detail"]:
            analysis["detail"] = row["detail"]
        if row["response"]:
            analysis["response"] = row["response"]
        entry: dict[str, Any] = {
            "id": row["cve"],
            "bom-ref": f"cryptoscan:vex/{row['cve']}",
            "ratings": [{"severity": row["severity"].lower()}],
            "analysis": analysis,
            "affects": [{"ref": ref} for ref in row["affects"]],
        }
        if row["fixed_version"]:
            entry["recommendation"] = f"upgrade to {row['fixed_version']} or later"
        if row["source"] == "operator" and author:
            entry["properties"] = [{"name": "cryptoscan:vex-issued-by", "value": author}]
        vulnerabilities.append(entry)
    metadata: dict[str, Any] = {"timestamp": now, "tools": [
        {"vendor": "CryptoScan", "name": "SBOM VEX generator", "version": "1.0"}]}
    if author:
        metadata["authors"] = [{"name": author}]
    target = ((bom or {}).get("metadata") or {}).get("component")
    if isinstance(target, dict):
        metadata["component"] = target
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial or f"urn:uuid:{uuid.uuid4()}",
        "version": version,
        "metadata": metadata,
        "vulnerabilities": vulnerabilities,
    }
    document["compositions"] = [{"aggregate": "complete",
                                 "vulnerabilities": [row["cve"] for row in rows]}]
    return document


def render_markdown(rows: list[dict[str, Any]], *, target: str | None = None) -> str:
    """Human-readable VEX statement table."""
    summary = counts(rows)
    lines = [f"# VEX statements — {target or 'document'}", ""]
    if summary:
        lines.append("Statements: " + ", ".join(f"{k} {v}" for k, v in sorted(summary.items())))
    else:
        lines.append("No advisories are recorded in this document.")
    if rows:
        lines += ["", "| CVE | Severity | State | Justification | Affected | Action |",
                  "| --- | --- | --- | --- | --- | --- |"]
        for row in rows:
            affected = ", ".join(
                f"{a.get('name')}@{a.get('version')}" for a in row["affected_components"]) or "—"
            action = row["fixed_version"] and f"upgrade to {row['fixed_version']}" or (
                ", ".join(row["response"]) or "—")
            lines.append(f"| {row['cve']} | {row['severity']} | {row['state']} | "
                         f"{row['justification'] or '—'} | {affected} | {action} |")
    return "\n".join(lines)
