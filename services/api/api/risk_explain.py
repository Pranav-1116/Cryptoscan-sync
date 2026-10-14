"""Risk explainability chain (§4.6, round 58).

The unified risk engine returns a scored decomposition; this module
assembles the chain behind it. For one system's risk verdict it answers,
from persisted state only:

* WHAT asset is affected — the system's crypto assets, keyed by the
  identity spine (round 57);
* WHERE the evidence lives — per failing finding: file:line, content
  hash, chain position and the scan verify path;
* WHY a control fails — the worker's STORED per-rule verdicts
  (``evidence.policy_evaluation``): the exact rule ids, severities and
  messages that were recorded when the scan ran, tenant overrides
  included — not a re-evaluation that could silently differ;
* WHO owns the business impact — system owners and linked business
  processes;
* WHICH inputs are DECLARED versus OBSERVED — every factor carries its
  basis; a declared dependency edge is topology someone registered, not
  an observed blast radius;
* WHY a remediation/PQC wave is recommended — the real wave assignment
  from the quantum planner, per vulnerable site, with deadline, threat
  type and replacement target.

Honesty rules: no scan → the explanation says so and fabricates nothing;
unknown algorithms are counted as a coverage limitation; every citation
carries an id that resolves in the API.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.business_process import BusinessProcess
from db.models.system_business_process import SystemBusinessProcess
from quantum.plan import build_migration_plan
from shared_models.asset_identity import crypto_asset_key_from_row

#: the eight unified factors — each labeled with its epistemic basis.
#: DECLARED = someone registered it (environment, criticality, topology);
#: OBSERVED = a collector recorded it (evidence, drift, CVEs).
FACTOR_BASES: dict[str, tuple[str, str]] = {
    "technical": ("OBSERVED", "evidence FAIL rows and open drift events from the latest scan"),
    "crypto": ("OBSERVED", "algorithm designations observed in the latest scan's evidence"),
    "pqc": ("OBSERVED", "quantum impact of the observed algorithms"),
    "exposure": ("DECLARED", "system.environment / cloud_provider as registered in the CMDB"),
    "business_criticality": ("DECLARED", "system.criticality as registered in the CMDB"),
    "dependency_impact": (
        "DECLARED",
        "outgoing dependency edges — declared topology, NOT an observed blast radius",
    ),
    "evidence_confidence": ("OBSERVED", "highest evidence confidence in the latest scan"),
    "threat": ("OBSERVED", "CVE rows recorded for the latest scan"),
}

_EVIDENCE_TRAIL_CAP = 50


def cite_failing_controls(evidence_rows: Iterable[Any]) -> list[dict[str, Any]]:
    """Group the stored FAIL/WARN rule verdicts per rule, most severe
    first, each citing the evidence ids that produced it."""
    by_rule: dict[str, dict[str, Any]] = {}
    for row in evidence_rows:
        evaluation = getattr(row, "policy_evaluation", None) or {}
        for result in evaluation.get("rules_evaluated") or []:
            outcome = str(result.get("evaluation_result") or "").upper()
            if outcome not in {"FAIL", "WARN"}:
                continue
            entry = by_rule.setdefault(
                result.get("rule_id") or "UNKNOWN",
                {
                    "rule_id": result.get("rule_id"),
                    "rule_name": result.get("rule_name"),
                    "severity": str(result.get("severity") or "").upper(),
                    "worst_outcome": outcome,
                    "remediation": result.get("remediation"),
                    "messages": [],
                    "evidence_ids": [],
                },
            )
            if outcome == "FAIL":
                entry["worst_outcome"] = "FAIL"
            if result.get("message") and result["message"] not in entry["messages"]:
                entry["messages"].append(result["message"])
            if row.id not in entry["evidence_ids"]:
                entry["evidence_ids"].append(row.id)
    controls = sorted(
        by_rule.values(),
        key=lambda c: (c["worst_outcome"] != "FAIL", -(len(c["evidence_ids"])), str(c["rule_id"])),
    )
    for control in controls:
        control["evidence_count"] = len(control["evidence_ids"])
    return controls


def evidence_trail(scan_id: str | None, evidence_rows: list[Any]) -> dict[str, Any]:
    """Where the evidence lives: ids, locations, hashes and the verify
    path — the same chain the hash-chain verifier walks."""
    if not scan_id:
        return {"scan_id": None, "entries": [], "note": "No scan recorded for this system — nothing to cite."}
    failing = [r for r in evidence_rows
               if str(getattr(r, "compliance_status", "") or "").upper() == "FAIL"]
    entries = [
        {
            "evidence_id": row.id,
            "algorithm": row.algorithm,
            "location": f"{row.file_path}:{row.line_number}" if row.file_path else None,
            "content_hash": row.content_hash,
            "chain_position": row.chain_position,
            "compliance_status": row.compliance_status,
        }
        for row in failing
    ]
    entries.sort(key=lambda e: (e["chain_position"] is None, e["chain_position"] or 0))
    capped = entries[:_EVIDENCE_TRAIL_CAP]
    return {
        "scan_id": scan_id,
        "verify_path": f"/api/v1/scans/{scan_id}/verify",
        "total_failing": len(entries),
        "entries": capped,
        "note": (f"Showing the first {_EVIDENCE_TRAIL_CAP} of {len(entries)} failing findings."
                 if len(entries) > _EVIDENCE_TRAIL_CAP else
                 "Each entry resolves via the scan verify path (hash-chain checked)."),
    }


def pqc_rationale(system: Any, assets: Iterable[Any]) -> dict[str, Any]:
    """Why a PQC wave is recommended — the REAL wave assignment from the
    quantum planner, run over this system's assets, per vulnerable site."""
    findings = []
    for asset in assets:
        row = asset.to_dict() if hasattr(asset, "to_dict") else dict(asset)
        row["system_id"] = str(system.id)
        findings.append(row)
    plan = build_migration_plan(findings, systems=[system.to_dict() if hasattr(system, "to_dict") else dict(system)])
    # the workstream target IS the recommended replacement; join it onto
    # the wave sites so each site carries its full rationale
    target_by_site: dict[tuple, str] = {}
    for stream in plan["workstreams"]:
        for site in stream["sites"]:
            target_by_site[
                (site.get("algorithm"), site.get("file_path"), site.get("line_number"))
            ] = str(stream.get("target") or "UNKNOWN")
    sites = []
    for wave, info in plan["waves"].items():
        for site in info["sites"]:
            identity = (site.get("algorithm"), site.get("file_path"), site.get("line_number"))
            sites.append({
                "wave": wave,
                "wave_focus": info["focus"],
                "algorithm": site.get("algorithm"),
                "location": (f"{site.get('file_path')}:{site.get('line_number')}"
                             if site.get("file_path") else None),
                "migration_deadline": site.get("deadline"),
                "hndl_risk": site.get("hndl_risk"),
                "quantum_risk_score": site.get("quantum_risk_score"),
                "recommended_replacement": target_by_site.get(identity, "UNKNOWN"),
            })
    return {
        "vulnerable_sites": plan["inventory"]["vulnerable_sites"],
        "total_sites": plan["inventory"]["total_sites"],
        "by_threat_type": plan["inventory"]["by_threat_type"],
        "sites": sites,
        "mosca": plan["mosca"],
        "summary": plan["summary"],
        "note": "Wave assignment reuses the estate planner logic (quantum.plan) on this system's assets.",
    }


def accountability(db: Session, system: Any) -> dict[str, Any]:
    """Who owns the business impact — honest nulls when unassigned."""
    processes = db.execute(
        select(BusinessProcess)
        .join(SystemBusinessProcess, SystemBusinessProcess.process_id == BusinessProcess.id)
        .where(SystemBusinessProcess.system_id == system.id)
    ).scalars().all()
    return {
        "owner": system.owner,
        "technical_owner": system.technical_owner,
        "security_owner": system.security_owner,
        "business_processes": [
            {"process_id": p.id, "name": p.name, "role": None}
            for p in processes
        ],
        "note": ("Owners as registered; unassigned stays null — it is a gap to fix, not a default."
                 if not (system.owner or system.technical_owner or system.security_owner)
                 else "Owners as registered in the CMDB."),
    }


def assemble_explanation(
    system: Any,
    assessment: Mapping[str, Any],
    evidence_rows: list[Any],
    assets: Iterable[Any],
    accountability_block: Mapping[str, Any],
    pqc_block: Mapping[str, Any],
) -> dict[str, Any]:
    """The full chain for one system's risk verdict."""
    levels: Mapping[str, int] = assessment.get("levels") or {}
    signals: Mapping[str, Any] = assessment.get("signals") or {}
    factors = [
        {
            "factor": name,
            "level": levels.get(name),
            "basis": FACTOR_BASES[name][0],
            "basis_note": FACTOR_BASES[name][1],
        }
        for name in FACTOR_BASES
    ]
    asset_rows = []
    for asset in assets:
        row = asset.to_dict() if hasattr(asset, "to_dict") else dict(asset)
        asset_rows.append({
            "asset_id": row.get("id"),
            "asset_key": row.get("asset_key") or crypto_asset_key_from_row(row),
            "algorithm": row.get("algorithm"),
            "purpose": row.get("purpose"),
            "location": (f"{row.get('file_path')}:{row.get('line_number')}"
                         if row.get("file_path") else None),
            "lifecycle_state": row.get("lifecycle_state"),
        })
    limitations = []
    if not assessment.get("scan_id"):
        limitations.append("No scan recorded — observed factors are 0 because nothing was observed, not because the system is clean.")
    if signals.get("unknown_algorithms"):
        limitations.append(
            f"{signals['unknown_algorithms']} evidence row(s) name an unrecognized algorithm — "
            "their crypto/PQC contribution is unmeasured (coverage limitation, not a pass)."
        )
    limitations.append(
        "Dependency impact counts declared edges; it is not an observed blast radius."
    )
    return {
        "system_id": str(system.id),
        "system_name": system.name,
        "risk": {
            "score": assessment.get("score"),
            "level": assessment.get("level"),
            "calculation_version": assessment.get("calculation_version"),
        },
        "factors": factors,
        "affected_assets": asset_rows,
        "failing_controls": cite_failing_controls(evidence_rows),
        "evidence_trail": evidence_trail(assessment.get("scan_id"), evidence_rows),
        "accountability": dict(accountability_block),
        "pqc_rationale": dict(pqc_block),
        "limitations": limitations,
        "model": "risk-explanation/v1",
    }
