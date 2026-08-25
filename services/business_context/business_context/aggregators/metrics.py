"""Aggregate revenue / customer / SLA / scope values across related records."""

from __future__ import annotations

from typing import Any, Iterable


def _num(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def sum_revenue(processes: Iterable[dict[str, Any]]) -> float:
    return round(sum(_num(item.get("revenue_daily")) for item in processes), 2)


def sum_customers(processes: Iterable[dict[str, Any]]) -> int:
    return int(sum(_num(item.get("customer_count")) for item in processes))


def sum_transactions(processes: Iterable[dict[str, Any]]) -> int:
    return int(sum(_num(item.get("transaction_volume")) for item in processes))


def min_sla(processes: Iterable[dict[str, Any]]) -> float | None:
    values = [_num(item.get("sla_uptime")) for item in processes if item.get("sla_uptime") is not None]
    return min(values) if values else None


def union_scopes(systems: Iterable[dict[str, Any]]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for system in systems:
        for scope in system.get("compliance_scopes") or []:
            token = str(scope)
            if token not in seen:
                seen.add(token)
                out.append(token)
    return out


def union_classifications(processes: Iterable[dict[str, Any]]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for process in processes:
        for item in process.get("data_classifications") or []:
            token = str(item)
            if token not in seen:
                seen.add(token)
                out.append(token)
    return out
