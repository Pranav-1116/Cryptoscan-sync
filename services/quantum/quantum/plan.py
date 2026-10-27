"""PQC migration planning on top of the deterministic risk engine.

Mosca's inequality is the decision rule for quantum migration timing:

    x + y > z   ->   you are already late

where x = data shelf-life (retention), y = migration time, z = time until
a cryptographically relevant quantum computer (CRQC).  y is always an
INPUT the caller estimates — it is never invented here.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
import math
from numbers import Real
from typing import Any, Iterable, Mapping

from quantum.risk import QUANTUM_THREAT_YEAR, CALC_VERSION, analyze_quantum_risk

_PRIORITY_ORDER = {"P1": 1, "P2": 2, "P3": 3}


def mosca(
    *,
    retention_years: int | None,
    migration_years: float | None = None,
    threat_year: int = QUANTUM_THREAT_YEAR,
    today: date | None = None,
) -> dict[str, Any]:
    """Evaluate Mosca's inequality x + y > z for one data category."""
    if retention_years is not None and (type(retention_years) is not int or not 0 <= retention_years <= 1000):
        raise ValueError("retention_years must be a nonnegative integer no greater than1000")
    if migration_years is not None and (isinstance(migration_years, bool) or not isinstance(migration_years, Real)
            or not math.isfinite(migration_years) or not 0 <= migration_years <= 1000):
        raise ValueError("migration_years must be finite and between0 and1000")
    if type(threat_year) is not int or not 1 <= threat_year <= 9999:
        raise ValueError("threat_year must be an integer calendar year")
    scenario = {"scenario_only": True,
        "threat_year_basis": "ASSUMPTION_NOT_FORECAST_OR_REGULATORY_DEADLINE",
        "time_resolution": "calendar_year"}
    today = today or datetime.now(timezone.utc).date()
    z = threat_year - today.year
    if retention_years is None:
        return {
            **scenario,
            "computable": False,
            "reason": "no retention data — shelf-life (x) unknown",
            "threat_year": threat_year,
            "z_years_to_crqc": z,
        }
    x = float(retention_years)
    y = float(migration_years) if migration_years is not None else None
    if x >= z:
        verdict = "ALREADY_LATE"
        explanation = "Under this threat-year assumption, the supplied shelf life exceeds the scenario horizon even with zero migration duration"
    elif y is not None and x + y >= z:
        # zero slack counts as at-risk: finishing exactly when CRQC arrives is no margin
        verdict = "AT_RISK"
        explanation = "Under this threat-year assumption, shelf life plus migration meets or exceeds the scenario horizon; review urgency"
    elif y is not None:
        verdict = "SAFE_MARGIN"
        explanation = "There is scenario slack under the supplied threat-year assumption, not a forecast"
    else:
        verdict = "UNKNOWN_MARGIN"
        explanation = "Shelf life fits within the threat-year assumption, but migration duration was not supplied"
    slack = None
    if y is not None:
        slack = round(z - x - y, 2)
    return {
        **scenario,
        "computable": True,
        "verdict": verdict,
        "x_shelf_life_years": x,
        "y_migration_years": y,
        "z_years_to_crqc": z,
        "slack_years": slack,
        "inequality": f"x({x:g}) + y({y if y is None else f'{y:g}'}) {'?' if y is None else f'= {x + y:g}'} vs z({z})",
        "explanation": explanation,
        "threat_year": threat_year,
    }


def _family(algorithm: str | None) -> str:
    from shared_models.algorithm_registry import parse_algorithm

    if parse_algorithm(algorithm or "").family == "kem-hybrid-pqc":
        return "PQC"
    algo = str(algorithm or "").upper().replace("_", "-")
    if algo.startswith("RSA"):
        return "RSA"
    if algo in {"ECDH", "ECDSA", "ED25519", "X25519", "ED448", "X448"} or algo.startswith("EC"):
        return "ECC"
    if "DH" in algo or "DIFFIE" in algo:
        return "DH"
    if algo == "DSA":
        return "DSA"
    if algo.startswith("ML-") or algo in {"KYBER", "DILITHIUM", "SPHINCS+"} or algo.startswith("SLH"):
        return "PQC"
    if algo.startswith("AES"):
        return "AES"
    if algo.startswith("SHA"):
        return "SHA"
    if algo in {"DES", "3DES", "RC4", "MD5", "SHA-1", "SHA1", "SSLV3"}:
        return "LEGACY"
    return "OTHER"


def build_migration_plan(
    findings: Iterable[Mapping[str, Any]],
    *,
    systems: Iterable[Mapping[str, Any]] | None = None,
    migration_years: float | None = None,
    today: date | None = None,
) -> dict[str, Any]:
    """Group quantum-vulnerable sites into replacement workstreams and waves."""
    today = today or datetime.now(timezone.utc).date()
    # Multiple consumers below must see the same cohort, including generators.
    findings, systems = list(findings), list(systems or [])
    report = analyze_quantum_risk(findings, systems=systems, today=today)
    assets = report["assets"]

    retentions: list[int] = []
    for system in systems or []:
        extra = system.get("extra") or {}
        value = extra.get("data_retention_years")
        if value is None:
            value = system.get("data_retention_years")
        if value is not None:
            retentions.append(int(value))

    by_family: dict[str, int] = {}
    by_threat: dict[str, int] = {}
    workstreams: dict[str, dict[str, Any]] = {}
    wave1: list[dict[str, Any]] = []
    wave2: list[dict[str, Any]] = []
    wave3: list[dict[str, Any]] = []
    for finding, asset in zip(findings, assets):
        # analyze_quantum_risk keeps row order; system_id comes from the original finding
        asset = {**asset, "system_id": finding.get("system_id")}
        family = _family(asset.get("algorithm"))
        by_family[family] = by_family.get(family, 0) + 1
        threat = str(asset.get("threat_type") or "UNKNOWN")
        by_threat[threat] = by_threat.get(threat, 0) + 1
        if not asset.get("vulnerable"):
            continue
        site = {
            "algorithm": asset.get("algorithm"),
            "file_path": asset.get("file_path"),
            "line_number": asset.get("line_number"),
            "system_id": asset.get("system_id"),
            "quantum_risk_score": asset.get("quantum_risk_score"),
            "risk_category": asset.get("risk_category"),
            "hndl_risk": asset.get("hndl_risk"),
            "deadline": asset.get("migration_deadline"),
        }
        # workstream keyed by the concrete replacement target
        target = str(asset.get("recommended_replacement") or "UNKNOWN")
        stream = workstreams.setdefault(
            target,
            {
                "target": target,
                "hybrid": bool(asset.get("hybrid_mode_recommended")),
                "sites": [],
                "site_count": 0,
                "max_score": 0,
                "earliest_deadline": None,
            },
        )
        stream["sites"].append(site)
        stream["site_count"] += 1
        stream["max_score"] = max(stream["max_score"], int(asset.get("quantum_risk_score") or 0))
        deadline = asset.get("migration_deadline")
        if deadline and (stream["earliest_deadline"] is None or str(deadline) < str(stream["earliest_deadline"])):
            stream["earliest_deadline"] = str(deadline)
        # waves: HNDL-heavy asymmetric first, then remaining asymmetric, then Grover-marginal
        if threat in {"SHOR_VULNERABLE", "CLASSICALLY_BROKEN"}:
            if str(asset.get("hndl_risk")) in {"CRITICAL", "HIGH"}:
                wave1.append(site)
            else:
                wave2.append(site)
        elif threat == "GROVER_WEAKENED":
            wave3.append(site)

    streams = []
    for stream in workstreams.values():
        score = stream.pop("max_score")
        stream["priority"] = "P1" if score >= 80 else "P2" if score >= 60 else "P3"
        stream["systems"] = sorted({str(site.get("system_id")) for site in stream["sites"] if site.get("system_id")})
        streams.append(stream)
    streams.sort(key=lambda row: (_PRIORITY_ORDER[row["priority"]], -row["site_count"], row["target"]))

    plan_mosca = (
        mosca(retention_years=max(retentions), migration_years=migration_years, today=today)
        if retentions
        else mosca(retention_years=None, today=today)
    )
    return {
        "inventory": {
            "total_sites": len(assets),
            "vulnerable_sites": report["vulnerable_count"],
            "pqc_ready_sites": report["pqc_ready_count"],
            "pqc_candidate_sites": report["pqc_candidate_count"],
            "deployment_readiness": "NOT_ESTABLISHED",
            "by_family": dict(sorted(by_family.items())),
            "by_threat_type": dict(sorted(by_threat.items())),
        },
        "workstreams": streams,
        "waves": {
            "1": {
                "focus": "harvest-now-decrypt-later critical/high asymmetric crypto",
                "sites": wave1,
                "site_count": len(wave1),
            },
            "2": {
                "focus": "remaining Shor-vulnerable / classically broken crypto",
                "sites": wave2,
                "site_count": len(wave2),
            },
            "3": {
                "focus": "Grover-marginal symmetric sizing (AES-128 -> AES-256, SHA-256 -> SHA-384)",
                "sites": wave3,
                "site_count": len(wave3),
            },
        },
        "mosca": plan_mosca,
        "summary": (
            f"{report['vulnerable_count']} of {len(assets)} sites are migration-review candidates across "
            f"{len(streams)} replacement workstreams; HNDL wave 1 = {len(wave1)} sites."
        ),
        "calculation_version": f"{CALC_VERSION}+plan",
    }
