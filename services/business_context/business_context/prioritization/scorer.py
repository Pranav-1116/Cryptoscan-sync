"""Business-driven priority score (logic-3 week 35-36)."""

from __future__ import annotations

from typing import Any, Iterable


def priority_score(
    *,
    revenue_daily: float = 0,
    customer_count: int = 0,
    compliance_fail: bool = False,
    technical_severity: str = "MEDIUM",
) -> float:
    severity = {"CRITICAL": 100, "HIGH": 70, "MEDIUM": 40, "LOW": 15, "INFO": 5}.get(
        str(technical_severity).upper(), 40
    )
    return round(
        float(revenue_daily) * 0.4
        + int(customer_count) * 0.0001
        + (80 if compliance_fail else 0)
        + severity * 0.3,
        2,
    )


def priority_label(score: float, *, compliance_fail: bool = False, revenue_daily: float = 0) -> str:
    if score >= 500_000 or (compliance_fail and revenue_daily > 0):
        return "P0"
    if compliance_fail or score >= 10_000:
        return "P1"
    return "P2"


def rank_assets(assets: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = list(assets)
    return sorted(
        rows,
        key=lambda row: float(((row.get("business_context") or {}).get("priority_score")) or 0),
        reverse=True,
    )
