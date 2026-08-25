"""Portfolio trends, heat maps, PQC forecast, and executive roll-up."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping


def _month(value: Any) -> str:
    if isinstance(value, datetime):
        return value.strftime("%Y-%m")
    text = str(value or "")
    if len(text) >= 7 and text[4] == "-":
        return text[:7]
    return datetime.now(timezone.utc).strftime("%Y-%m")


def algorithm_trends(assets: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for asset in assets:
        algo = str(asset.get("algorithm") or "UNKNOWN")
        counts[_month(asset.get("created_at"))][algo] += 1
    rows = []
    for month in sorted(counts):
        for algo, total in sorted(counts[month].items()):
            rows.append({"month": month, "algorithm": algo, "count": total})
    return rows


def compliance_trend(findings: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    buckets: dict[str, dict[str, int]] = defaultdict(lambda: {"pass": 0, "fail": 0, "total": 0})
    for row in findings:
        month = _month(row.get("created_at") or row.get("scan_start"))
        buckets[month]["total"] += 1
        status = str(row.get("compliance_status") or "").upper()
        if status == "PASS":
            buckets[month]["pass"] += 1
        elif status == "FAIL":
            buckets[month]["fail"] += 1
    out = []
    for month in sorted(buckets):
        item = buckets[month]
        rate = round(100.0 * item["pass"] / item["total"], 1) if item["total"] else 0.0
        out.append({"month": month, "pass": item["pass"], "fail": item["fail"], "total": item["total"], "rate": rate})
    return out


def heat_map(systems: Iterable[Mapping[str, Any]], assets: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    by_system: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for asset in assets:
        sid = str(asset.get("system_id") or "unassigned")
        by_system[sid].append(asset)
    rows = []
    for system in systems:
        sid = str(system.get("id") or "")
        owned = by_system.get(sid, [])
        fails = sum(1 for item in owned if str(item.get("compliance_status") or "").upper() == "FAIL")
        critical = sum(
            1
            for item in owned
            if str((item.get("extra") or {}).get("quantum_risk", {}).get("risk_category") or "").upper() == "CRITICAL"
            or str(item.get("algorithm") or "").upper() in {"DES", "MD5", "RC4", "RSA"}
            and str(item.get("compliance_status") or "").upper() == "FAIL"
        )
        unit = system.get("owner") or system.get("environment") or "unassigned"
        if critical > 10:
            cell = "CRITICAL"
        elif critical >= 5:
            cell = "HIGH"
        elif critical >= 1 or fails:
            cell = "MEDIUM"
        else:
            cell = "CLEAR"
        rows.append(
            {
                "system_id": sid,
                "system": system.get("name"),
                "unit": unit,
                "fails": fails,
                "critical": critical,
                "cell": cell,
            }
        )
    return rows


def pqc_forecast(
    *,
    vulnerable: int,
    migrated: int = 0,
    monthly_rate: float | None = None,
    deadline_months: int = 12,
    history: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    remaining = max(0, int(vulnerable) - int(migrated))
    rate = monthly_rate
    if rate is None and history:
        points = list(history)
        if len(points) >= 2:
            first = float(points[0].get("migrated") or 0)
            last = float(points[-1].get("migrated") or 0)
            months = max(1, len(points) - 1)
            total = float(points[-1].get("total") or remaining or 1)
            rate = max(0.0, (last - first) / months / total)
    rate = 0.042 if rate is None else float(rate)
    per_month = max(0.1, remaining * rate) if remaining else 0.1
    months_to_done = remaining / per_month if remaining else 0
    required = remaining / deadline_months if deadline_months else remaining
    at_risk = months_to_done > deadline_months and remaining > 0
    return {
        "vulnerable": remaining,
        "monthly_rate": round(rate, 4),
        "months_to_completion": round(months_to_done, 1),
        "deadline_months": deadline_months,
        "status": "AT_RISK" if at_risk else "ON_TRACK",
        "required_monthly": round(required, 1),
        "recommendation": (
            f"Accelerate by {round(months_to_done - deadline_months, 1)} months"
            if at_risk
            else "On track at the current pace"
        ),
    }


def recommendations(
    assets: Iterable[Mapping[str, Any]],
    *,
    systems: Iterable[Mapping[str, Any]] = (),
    limit: int = 10,
) -> list[dict[str, Any]]:
    system_by_id = {str(row.get("id")): row for row in systems}
    ranked = []
    for asset in assets:
        extra = asset.get("extra") or {}
        ctx = extra.get("business_context") or asset.get("business_context") or {}
        q = extra.get("quantum_risk") or asset.get("quantum_risk") or {}
        fail = str(asset.get("compliance_status") or "").upper() == "FAIL"
        if not fail and str(q.get("risk_category") or "").upper() not in {"CRITICAL", "HIGH"}:
            continue
        system = system_by_id.get(str(asset.get("system_id") or "")) or {}
        agility = int(system.get("current_agility_score") or extra.get("agility_score") or 50)
        score = (
            float(ctx.get("total_revenue_at_risk") or 0) * 0.3
            + float(q.get("quantum_risk_score") or (90 if fail else 40)) * 0.3
            + (100 - agility) * 0.2
            + (80 if fail else 20) * 0.2
        )
        ranked.append(
            {
                "title": f"Migrate {asset.get('algorithm')} in {system.get('name') or asset.get('file_path')}",
                "algorithm": asset.get("algorithm"),
                "system": system.get("name"),
                "priority_score": round(score, 2),
                "revenue_protected": ctx.get("total_revenue_at_risk") or 0,
                "customers_protected": ctx.get("total_customers_at_risk") or 0,
                "deadline": q.get("migration_deadline"),
                "owner": system.get("owner") or (ctx.get("business_owners") or ["unassigned"])[0],
            }
        )
    ranked.sort(key=lambda row: row["priority_score"], reverse=True)
    for index, row in enumerate(ranked[:limit], start=1):
        row["rank"] = index
    return ranked[:limit]


def executive_summary(
    *,
    assets: list[Mapping[str, Any]],
    findings: list[Mapping[str, Any]],
    systems: list[Mapping[str, Any]],
    quantum: Mapping[str, Any] | None = None,
    forecast: Mapping[str, Any] | None = None,
    recs: list[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    fail = sum(1 for row in findings if str(row.get("compliance_status") or "").upper() == "FAIL")
    total = len(findings) or 1
    rate = round(100.0 * (total - fail) / total, 1)
    q = quantum or {}
    vulnerable = int(q.get("vulnerable_count") or 0)
    posture = "HIGH" if rate < 60 or (q.get("overall_hndl_risk") == "CRITICAL") else "MODERATE" if rate < 85 else "LOW"
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "overall_posture": posture,
        "totals": {
            "assets": len(assets),
            "findings": len(findings),
            "systems": len(systems),
            "compliance_rate": rate,
            "quantum_vulnerable": vulnerable,
            "pqc_ready": int(q.get("pqc_ready_count") or 0),
        },
        "forecast": forecast or {},
        "top_recommendations": recs or [],
        "summary": (
            f"Compliance {rate}%. {vulnerable} quantum-vulnerable assets. "
            f"Forecast {(forecast or {}).get('status', 'UNKNOWN')}."
        ),
    }


def build_analytics(
    *,
    assets: Iterable[Mapping[str, Any]] = (),
    findings: Iterable[Mapping[str, Any]] = (),
    systems: Iterable[Mapping[str, Any]] = (),
    quantum: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    asset_list = list(assets)
    finding_list = list(findings)
    system_list = list(systems)
    recs = recommendations(asset_list, systems=system_list)
    q = quantum or {}
    forecast = pqc_forecast(vulnerable=int(q.get("vulnerable_count") or 0), migrated=int(q.get("pqc_ready_count") or 0))
    return {
        "trends": algorithm_trends(asset_list),
        "compliance": compliance_trend(finding_list),
        "heatmap": heat_map(system_list, asset_list),
        "forecast": forecast,
        "recommendations": recs,
        "executive": executive_summary(
            assets=asset_list,
            findings=finding_list,
            systems=system_list,
            quantum=q,
            forecast=forecast,
            recs=recs,
        ),
    }
