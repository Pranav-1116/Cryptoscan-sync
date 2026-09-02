"""Compliance intelligence — traceable, evidence-backed status.

Maps Requirements -> Controls -> Assets -> Findings -> Evidence to produce an
honest compliance posture rather than a static checklist. A control is:

    COMPLIANT    — applicable assets pass and have current evidence
    GAP          — a finding evidences failure
    NOT_EVIDENCED— in scope but no evidence (cannot claim compliance)
    NOT_APPLICABLE

Coverage % = controls with evidence / applicable controls; and the share
that are compliant. Deterministic.
"""

from __future__ import annotations

COMPLIANT = "COMPLIANT"
GAP = "GAP"
NOT_EVIDENCED = "NOT_EVIDENCED"
NOT_APPLICABLE = "NOT_APPLICABLE"


def evaluate_control(control: dict, findings: list[dict], evidence: list[dict]) -> dict:
    """Evaluate one control given mapped findings + evidence.

    control: {id, framework, assets:[asset_ids], severity_threshold}
    findings: {control_id, asset_id, severity, status}
    evidence: {control_id, asset_id, current:bool}
    """
    cid = control["id"]
    assets = set(control.get("assets") or [])
    mapped = [f for f in findings if f.get("control_id") == cid
              and (not assets or f.get("asset_id") in assets)]
    failing = [f for f in mapped if f.get("status", "open") == "open"]
    ev = [e for e in evidence if e.get("control_id") == cid
          and (not assets or e.get("asset_id") in assets)]
    current_ev = [e for e in ev if e.get("current", False)]

    if failing:
        return {"control_id": cid, "framework": control.get("framework"),
                "status": GAP, "open_findings": len(failing),
                "evidence": len(current_ev), "assets": len(assets)}
    in_scope_assets = assets or {f.get("asset_id") for f in mapped}
    if not in_scope_assets:
        return {"control_id": cid, "framework": control.get("framework"),
                "status": NOT_APPLICABLE, "open_findings": 0,
                "evidence": len(current_ev), "assets": 0}
    if not current_ev:
        return {"control_id": cid, "framework": control.get("framework"),
                "status": NOT_EVIDENCED, "open_findings": 0,
                "evidence": 0, "assets": len(in_scope_assets)}
    return {"control_id": cid, "framework": control.get("framework"),
            "status": COMPLIANT, "open_findings": 0,
            "evidence": len(current_ev), "assets": len(in_scope_assets)}


def framework_posture(controls: list[dict], findings: list[dict], evidence: list[dict]) -> dict:
    results = [evaluate_control(c, findings, evidence) for c in controls]
    applicable = [r for r in results if r["status"] != NOT_APPLICABLE]
    by_status: dict[str, int] = {}
    for r in applicable:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    total = len(applicable)
    evidenced = total - by_status.get(NOT_EVIDENCED, 0)
    compliant = by_status.get(COMPLIANT, 0)
    return {
        "total_controls": total,
        "by_status": by_status,
        "compliant": compliant,
        "gaps": by_status.get(GAP, 0),
        "not_evidenced": by_status.get(NOT_EVIDENCED, 0),
        "coverage_pct": round(100 * evidenced / total, 2) if total else 0.0,
        "compliance_pct": round(100 * compliant / total, 2) if total else 0.0,
        "controls": results,
    }
