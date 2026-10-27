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


def _wave_sites(plan: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Flatten a migration plan's waves into per-site rationale rows, each
    joined with its workstream's recommended replacement."""
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
    return sites


def pqc_rationale(system: Any, assets: Iterable[Any]) -> dict[str, Any]:
    """Why a PQC wave is recommended — the REAL wave assignment from the
    quantum planner, run over this system's assets, per vulnerable site."""
    findings = []
    for asset in assets:
        row = asset.to_dict() if hasattr(asset, "to_dict") else dict(asset)
        row["system_id"] = str(system.id)
        findings.append(row)
    plan = build_migration_plan(findings, systems=[system.to_dict() if hasattr(system, "to_dict") else dict(system)])
    sites = _wave_sites(plan)
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

# --------------------------------------------------------------------------- #
# §4.6, round 68 — the SAME explainability depth at the ASSET level.
#
# The system-level chain above explains a system's verdict; every row of
# GET /risk/unified is scored by ``from_asset`` over an inventory row and
# carries only the decomposition. This half answers, for ONE inventory
# asset, from persisted state only:
#
# * WHICH inputs set each factor level — the exact inventory fields the
#   engine read, the rule that applied, and what level 0 MEANS (unknown,
#   never "clean");
# * WHERE the observation came from — for crypto assets, the evidence rows
#   joined on the identity spine (round 57), with chain position and the
#   scan verify path; a row that cannot join says so;
# * WHY a control fails — the worker's STORED per-rule verdicts on the
#   joined evidence, not a re-evaluation;
# * WHY PQC flags the asset — the real wave assignment for this asset's
#   own site, with deadline and replacement target;
# * WHO owns it — the asset's registered owners, honest nulls.
#
# Levels are never re-derived here: they come from ``from_asset``'s own
# factor detail, so the explanation cannot drift from the score it
# explains. The classification narrative reuses the engine's public
# helpers (``crypto_designation`` & co.) — the single authority.
# --------------------------------------------------------------------------- #

ASSET_EXPLANATION_MODEL = "asset-risk-explanation/v1"

#: the inventory window an explain can see — the same per-type cap
#: GET /risk/unified accepts (its Query limit ceiling). An asset beyond
#: the window is equally invisible to /unified, so the 404 is honest.
_ASSET_WINDOW = 1000


def find_inventory_row(session: Session, asset_id: str) -> dict[str, Any] | None:
    """The unified-inventory row for ``asset_id`` — built by the SAME
    ``collect_inventory`` call /risk/unified scores, never a parallel
    row-shape that could drift."""
    from api.routers.inventory import collect_inventory

    rows = collect_inventory(session, limit=_ASSET_WINDOW)
    return next((r for r in rows if r.get("id") == asset_id), None)


def _asset_factor_provenance(row: Mapping[str, Any], detail: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Per factor: the authoritative level/points/weight plus WHICH inputs
    set it and what the rule was. Level 0 is always explained as unknown
    or unregistered, never as safe."""
    from universal_platform.risk import crypto_designation

    alg = row.get("algorithm") or row.get("public_key_algorithm")
    designation = crypto_designation(alg)
    pqc = str(row.get("pqc") or "").lower()
    relationships = row.get("relationships") or {}
    dep_counts = {k: len(v) for k, v in relationships.items() if isinstance(v, list)}
    dep_total = sum(dep_counts.values())

    crypto_inputs = {"algorithm": alg, "stored crypto_level": row.get("crypto_level")}
    if designation:
        crypto_rule = (f"algorithm name matches the {designation['family_class']} family "
                       f"token '{designation['token']}' → level {designation['level']}; "
                       "max with any stored crypto_level")
    else:
        crypto_rule = ("algorithm name matches no classified family — level 0 means "
                       "UNCLASSIFIED, not safe; max with any stored crypto_level")

    if pqc == "vulnerable":
        pqc_rule = ("inventory classifies the algorithm as quantum-vulnerable "
                    "(name contains a family token like RSA/ECDSA/DH/…) → level 4")
    elif pqc == "ready":
        pqc_rule = ("inventory classifies the algorithm as PQC-ready (name matches a "
                    "post-quantum family like ML-KEM/ML-DSA/…) → level 0")
    else:
        pqc_rule = ("inventory could not classify the algorithm either way → level from "
                    "the stored pqc_level, or 0 meaning UNKNOWN, not ready")

    env = row.get("environment") or row.get("env")
    derived: dict[str, dict[str, Any]] = {
        "technical": {
            "inputs": {"risk label": row.get("risk"), "stored technical_level": row.get("technical_level")},
            "rule": ("the inventory's deterministic risk label maps CRITICAL/TIER-1→4, "
                     "HIGH/TIER-2→3, MEDIUM/TIER-3→2, LOW→1; when the label maps to 0 "
                     "the stored technical_level is used instead"),
        },
        "crypto": {"inputs": crypto_inputs, "rule": crypto_rule},
        "pqc": {"inputs": {"pqc classification": row.get("pqc"), "stored pqc_level": row.get("pqc_level")},
                "rule": pqc_rule},
        "exposure": {
            "inputs": {"environment": env, "cloud_provider": row.get("cloud_provider"),
                       "stored exposure_level": row.get("exposure_level")},
            "rule": ("DECLARED environment: prod/production/internet/public/dmz→4, "
                     "staging/preprod/external→2; level 0 means NOT REGISTERED, not 'internal'"),
        },
        "business_criticality": {
            "inputs": {"criticality": row.get("criticality")},
            "rule": ("DECLARED criticality: TIER-1/CRITICAL→4, HIGH/TIER-2→3, "
                     "MEDIUM/TIER-3→2, LOW→1; level 0 means UNREGISTERED, not unimportant"),
        },
        "dependency_impact": {
            "inputs": {"declared edges by relationship": dep_counts, "total": dep_total},
            "rule": ("one level per declared CMDB edge, capped at 4 — declared topology, "
                     "NOT an observed blast radius"),
        },
        "evidence_confidence": {
            "inputs": {"confidence": row.get("confidence")},
            "rule": ("OBSERVED confidence: HIGH/CONFIRMED→4, MEDIUM/LIKELY→3, "
                     "LOW/TENTATIVE→1; level 0 means no recorded confidence"),
        },
        "threat": {
            "inputs": {"threat_level": row.get("threat_level")},
            "rule": ("inventory rows carry no threat feed today — level 0 means UNKNOWN, "
                     "not 'no active threat'"),
        },
    }
    factors = []
    for name, (basis, basis_note) in FACTOR_BASES.items():
        d = detail.get(name) or {}
        factors.append({
            "factor": name,
            "level": d.get("level"),
            "points": d.get("points"),
            "weight": d.get("weight"),
            "basis": basis,
            "basis_note": basis_note,
            "derived_from": derived[name],
        })
    return factors


def asset_evidence_trail(session: Session, row: Mapping[str, Any]) -> dict[str, Any]:
    """WHERE the observation came from, for crypto assets: the evidence
    rows that join on the identity spine — same spine, same fields, so a
    same-algorithm row at another path never joins. Non-crypto rows get an
    honest note instead of a fabricated trail."""
    from db.models.crypto_asset import CryptoAsset
    from db.models.evidence_record import EvidenceRecord
    from db.tenancy import filtered_get

    if not str(row.get("id") or "").startswith("crypto:"):
        return {
            "asset_key": None,
            "entries": [],
            "note": ("No evidence-row join exists for this asset type — the "
                     "observation source is the entity's own store."),
        }
    crypto = filtered_get(session, CryptoAsset, str(row.get("id")).split(":", 1)[1])
    if crypto is None:
        return {"asset_key": None, "entries": [],
                "note": "Crypto asset row no longer resolvable — refresh the inventory."}
    asset_dict = crypto.to_dict() if hasattr(crypto, "to_dict") else dict(crypto)
    key = crypto.asset_key or crypto_asset_key_from_row(asset_dict)
    if not key:
        return {"asset_key": None, "entries": [],
                "note": ("Asset has no file locator — the identity spine cannot join it "
                         "to evidence (identity is what + why + WHERE; no WHERE, no join).")}
    candidates = session.execute(
        select(EvidenceRecord).where(
            EvidenceRecord.algorithm == crypto.algorithm,
            EvidenceRecord.file_path == crypto.file_path,
        )
    ).scalars().all()
    matched = [ev for ev in candidates
               if crypto_asset_key_from_row(
                   ev.to_dict() if hasattr(ev, "to_dict") else dict(ev)) == key]
    entries = [
        {
            "evidence_id": ev.id,
            "scan_id": ev.scan_id,
            "verify_path": f"/api/v1/scans/{ev.scan_id}/verify",
            "algorithm": ev.algorithm,
            "location": f"{ev.file_path}:{ev.line_number}" if ev.file_path else None,
            "content_hash": ev.content_hash,
            "chain_position": ev.chain_position,
            "compliance_status": ev.compliance_status,
        }
        for ev in matched
    ]
    entries.sort(key=lambda e: (str(e["scan_id"]), e["chain_position"] is None, e["chain_position"] or 0))
    capped = entries[:_EVIDENCE_TRAIL_CAP]
    return {
        "asset_key": key,
        "total_observations": len(entries),
        "entries": capped,
        "failing_controls": cite_failing_controls(matched),
        "note": (f"Joined on the identity spine ({key[:18]}…); {len(entries)} observation(s) "
                 f"across {len({e['scan_id'] for e in entries})} scan(s)."
                 if entries else
                 "No evidence rows join this asset on the identity spine — the "
                 "observation's chain position cannot be cited."),
    }


def asset_pqc_rationale(row: Mapping[str, Any], crypto: Any) -> dict[str, Any] | None:
    """Why PQC flags THIS asset: the real wave assignment for its own
    site, with deadline, HNDL risk and the recommended replacement."""
    if str(row.get("pqc") or "").lower() != "vulnerable" or crypto is None:
        return None
    finding = crypto.to_dict() if hasattr(crypto, "to_dict") else dict(crypto)
    plan = build_migration_plan([finding])
    return {
        "vulnerable_sites": plan["inventory"]["vulnerable_sites"],
        "sites": _wave_sites(plan),
        "mosca": plan["mosca"],
        "note": "Wave assignment reuses the estate planner (quantum.plan) on this one asset.",
    }


def assemble_asset_explanation(session: Session, asset_id: str) -> dict[str, Any] | None:
    """The full chain for one inventory asset's /unified score."""
    from db.models.crypto_asset import CryptoAsset
    from db.tenancy import filtered_get
    from universal_platform.risk import from_asset

    row = find_inventory_row(session, asset_id)
    if row is None:
        return None
    score = from_asset(row)

    crypto = None
    if asset_id.startswith("crypto:"):
        crypto = filtered_get(session, CryptoAsset, asset_id.split(":", 1)[1])

    trail = asset_evidence_trail(session, row)
    limitations = [
        "Dependency impact counts declared CMDB edges, not an observed blast radius.",
        "Threat level 0 means no threat feed on this inventory row — unknown, not 'no active threat'.",
    ]
    if not row.get("environment") and not row.get("env"):
        limitations.append("Exposure level 0 — no environment registered for this asset (declared input missing), not 'internal'.")
    if asset_id.startswith("crypto:") and not trail.get("entries"):
        limitations.append(str(trail.get("note")))
    if asset_id.startswith("cert:"):
        limitations.append("Certificate fields come from the certificate store (collector/CT imports); no evidence-row join exists for certificates yet.")
    if asset_id.startswith("system:"):
        limitations.append("This is the inventory-row decomposition; the deeper system chain "
                           "(full evidence trail, controls, wave plan) is at "
                           f"/api/v1/risk/systems/{asset_id.split(':', 1)[1]}/explain.")

    accountability = {
        "owner": row.get("owner"),
        "technical_owner": row.get("technical_owner") or (crypto.technical_owner if crypto else None),
        "security_owner": row.get("security_owner") or (crypto.security_owner if crypto else None),
        "systems_using": (row.get("relationships") or {}).get("used_by", []),
        "note": ("Owners as registered; unassigned stays null — it is a gap to fix, not a default."
                 if not (row.get("owner") or row.get("technical_owner") or row.get("security_owner"))
                 else "Owners as registered on the asset."),
    }
    return {
        "asset_id": asset_id,
        "asset_type": row.get("asset_type"),
        "name": row.get("name"),
        "risk": {
            "score": score["score"],
            "level": score["level"],
            "calculation_version": score["calculation_version"],
            "weights_source": score["weights_source"],
        },
        "factors": _asset_factor_provenance(row, score["factors"]),
        "inventory_row": row,
        "evidence_trail": trail,
        "pqc_rationale": asset_pqc_rationale(row, crypto),
        "accountability": accountability,
        "system_explain_path": (f"/api/v1/risk/systems/{asset_id.split(':', 1)[1]}/explain"
                                if asset_id.startswith("system:") else None),
        "limitations": limitations,
        "model": ASSET_EXPLANATION_MODEL,
    }
