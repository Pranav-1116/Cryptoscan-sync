"""Supplier concentration risk (PQC ICT supply-chain analysis, §6).

"Organizations must account for concentration risk when multiple critical
services depend on the same cryptographic supplier, cloud platform, or
technology component."

A concentrated supplier is a single point of migration failure: one delayed
firmware release or unsupported product stalls every service behind it.
The analysis is evidence-linked clusters and named findings — never one
blended number — and no recorded dependencies reads as UNKNOWN risk, never
as a safe supply chain.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

CONCENTRATION_SCHEMA = "cryptoscan.supplier-concentration/1"

CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
CRITICALITIES: tuple[str, ...] = (CRITICAL, HIGH, MEDIUM, LOW)

SEVERE = (CRITICAL, HIGH)


def _clean(value: Any) -> str:
    return str(value or "").strip()


def supplier_concentration(*, dependencies: Iterable[Mapping[str, Any]],
                           as_of: str | None = None) -> dict[str, Any]:
    """Cluster services onto suppliers and name the concentrations.

    Every dependency is attributed and evidence-backed: a bare "service X
    uses supplier Y" without evidence is refused — "every graph relationship
    should have evidence behind it".
    """
    rows = []
    for dep in dependencies:
        service = _clean(dep.get("service"))
        supplier = _clean(dep.get("supplier"))
        component = _clean(dep.get("component"))
        evidence_ref = _clean(dep.get("evidence_ref"))
        criticality = _clean(dep.get("criticality") or "").upper()
        if not (service and supplier):
            raise ValueError(
                "every dependency names its service and its supplier: an "
                "unattributed dependency cannot be clustered")
        if criticality not in CRITICALITIES:
            raise ValueError(
                f"dependency {service!r} carries criticality "
                f"{dep.get('criticality')!r}; expected one of "
                f"{', '.join(CRITICALITIES)}")
        if not evidence_ref:
            raise ValueError(
                f"dependency {service!r} -> {supplier!r} needs evidence_ref: "
                "a supply-chain relationship without evidence is a guess")
        rows.append({
            "service": service, "supplier": supplier,
            "component": component or None,
            "criticality": criticality, "evidence_ref": evidence_ref,
        })

    by_supplier: dict[str, list[dict[str, Any]]] = {}
    by_component: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_supplier.setdefault(row["supplier"], []).append(row)
        if row["component"]:
            by_component.setdefault(row["component"], []).append(row)

    def _cluster(key: str, grouped: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
        out = []
        for name, members in grouped.items():
            severe = [m for m in members if m["criticality"] in SEVERE]
            out.append({
                "name": name,
                "services": sorted({m["service"] for m in members}),
                "severe_services": sorted({m["service"] for m in severe}),
                "count": len({m["service"] for m in members}),
                "severe_count": len({m["service"] for m in severe}),
                "evidence_refs": sorted({m["evidence_ref"] for m in members}),
            })
        return sorted(out, key=lambda c: (-c["severe_count"], -c["count"], c["name"]))

    supplier_clusters = _cluster("supplier", by_supplier)
    component_clusters = _cluster("component", by_component)

    findings = []
    for cluster in supplier_clusters:
        if cluster["severe_count"] >= 2:
            findings.append({
                "finding": "supplier_concentration",
                "subject": cluster["name"],
                "severe_services": cluster["severe_services"],
                "evidence_refs": cluster["evidence_refs"],
                "note": (f"{cluster['severe_count']} critical/high services "
                         f"depend on one supplier: a delayed release or "
                         f"unsupported product stalls all of them"),
            })
    for cluster in component_clusters:
        if cluster["severe_count"] >= 2:
            findings.append({
                "finding": "component_concentration",
                "subject": cluster["name"],
                "severe_services": cluster["severe_services"],
                "evidence_refs": cluster["evidence_refs"],
                "note": (f"{cluster['severe_count']} critical/high services "
                         f"share one component: one vulnerability or "
                         f"migration blocker reaches all of them"),
            })

    if not rows:
        state = "UNKNOWN"
        is_clean = False
        note = ("no dependencies recorded: an unknown supply chain is not "
                "a safe one")
    elif findings:
        state = "CONCENTRATED"
        is_clean = False
        note = ("named clusters explain the exposure; there is no combined "
                "score")
    else:
        state = "NO_CONCENTRATION"
        is_clean = True
        note = ("no supplier or component backs more than one critical/high "
                "service")
    return {
        "schema": CONCENTRATION_SCHEMA,
        "as_of": as_of,
        "state": state,
        "supplier_clusters": supplier_clusters,
        "component_clusters": component_clusters,
        "findings": findings,
        "is_clean_result": is_clean,
        "note": note,
    }
