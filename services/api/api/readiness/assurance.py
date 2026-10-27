"""Compute an honest, tenant-scoped readiness view.

This module is deliberately pure. It does not infer customer, provider,
independent-review, or regulated evidence from source code or local tests.
The API can therefore expose one consistent readiness contract without turning
an absent external artifact into a green deployment decision.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

SCANNER_FAMILIES: tuple[str, ...] = (
    "vendor", "universal", "source", "runtime", "hardware", "network",
    "cloud", "container", "ot", "telecom", "payment", "keyassure",
    "binary", "devsecops",
)

_TERMINAL_GOOD = {"PASS", "PASSED", "OK", "DEGRADED"}
_NON_QUALIFYING = {"UNCONFIGURED", "UNAVAILABLE", "BLOCKED", "FAILED", "FAIL", "SKIP", "PREFLIGHT", "PENDING", "NOT_RUN"}


def normalize_status(value: Any, default: str = "UNAVAILABLE") -> str:
    status = str(value or default).strip().upper().replace("-", "_")
    aliases = {"SUCCESS": "PASS", "COMPLETED": "PASS", "ERROR": "FAIL", "NOT CONFIGURED": "UNCONFIGURED"}
    return aliases.get(status, status)


def _scanner_rows(snapshot: dict[str, Any] | None) -> list[dict[str, Any]]:
    snapshot = snapshot or {}
    results = snapshot.get("results") or {}
    availability = snapshot.get("scanner_availability") or {}
    rows: list[dict[str, Any]] = []
    for family in SCANNER_FAMILIES:
        result = results.get(family) if isinstance(results, dict) else None
        available = availability.get(family) if isinstance(availability, dict) else None
        if isinstance(result, dict):
            status = normalize_status(result.get("status"))
            source = "observed_result"
            detail = result.get("error") or result.get("summary")
        elif isinstance(available, dict):
            status = normalize_status(available.get("status"), "UNCONFIGURED")
            # The runner uses CONFIGURED to mean that an operator supplied a
            # route, not that a scan passed. Keep it non-green until a result
            # exists.
            if status == "CONFIGURED":
                status = "PENDING"
            source = "availability"
            detail = available.get("reason")
        else:
            status = "UNAVAILABLE"
            source = "missing"
            detail = "family is not present in the snapshot"
        rows.append({"family": family, "status": status, "source": source, "detail": detail})
    return rows


def _status_counts(rows: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        status = normalize_status(row.get("status"))
        counts[status] = counts.get(status, 0) + 1
    return dict(sorted(counts.items()))


def _external_state(external: dict[str, Any] | None) -> dict[str, Any]:
    """Summarize supplied external evidence without validating its truth."""
    external = external or {}
    rows = external.get("categories") if isinstance(external.get("categories"), list) else []
    statuses = [normalize_status(row.get("status")) for row in rows if isinstance(row, dict)]
    if not rows:
        return {"status": "SKIP", "reason": "no customer/provider/independent evidence supplied", "categories": []}
    if any(status in {"FAIL", "BLOCKED"} for status in statuses):
        status = "FAIL"
    elif any(status not in {"PASS"} for status in statuses):
        status = "SKIP"
    else:
        status = "PASS"
    return {"status": status, "categories": rows, "observed_statuses": _status_counts({"status": item} for item in statuses)}


def build_readiness_summary(
    snapshot: dict[str, Any] | None = None,
    *,
    dependency: dict[str, Any] | None = None,
    external: dict[str, Any] | None = None,
    now: datetime | None = None,
    snapshot_max_age_seconds: int = 3600,
) -> dict[str, Any]:
    """Return a readiness decision with explicit gaps and no score inflation.

    ``PASS`` means the supplied evidence met this function's mechanical
    contract. It is not a customer attestation or regulatory approval.
    """
    now = now or datetime.now(timezone.utc)
    snapshot = snapshot or {}
    rows = _scanner_rows(snapshot)
    counts = _status_counts(rows)
    observed_at = snapshot.get("ts") or snapshot.get("last_run_at")
    stale = False
    if observed_at:
        try:
            timestamp = datetime.fromisoformat(str(observed_at).replace("Z", "+00:00"))
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            stale = (now - timestamp.astimezone(timezone.utc)).total_seconds() > snapshot_max_age_seconds
        except ValueError:
            stale = True
    else:
        stale = True

    configured = sum(row["status"] not in {"UNCONFIGURED", "UNAVAILABLE", "PENDING"} for row in rows)
    green = sum(row["status"] in _TERMINAL_GOOD for row in rows)
    scanner_status = "PASS" if green == len(rows) and not stale else "DEGRADED" if green else "SKIP"
    scanner_gaps = [row for row in rows if row["status"] not in _TERMINAL_GOOD]

    dep = dependency or {}
    dep_status = normalize_status(dep.get("status"), "SKIP")
    if dep and dep_status == "PASS" and dep.get("unresolved_relationships"):
        dep_status = "DEGRADED"
    external_state = _external_state(external)
    mechanical = {
        "scanner_coverage": scanner_status,
        "dependency_cascade": dep_status,
        "fresh_snapshot": "FAIL" if stale else "PASS",
    }
    staging = "PASS" if all(value == "PASS" for value in mechanical.values()) else "BLOCKED"
    pilot = "PASS" if staging == "PASS" and external_state["status"] == "PASS" else "SKIP"
    regulated = "PASS" if pilot == "PASS" else "BLOCKED"
    return {
        "generated_at": now.astimezone(timezone.utc).isoformat(),
        "decision": "PASS" if regulated == "PASS" else "BLOCKED",
        "controlled_staging": {"status": staging, "mechanical_checks": mechanical},
        "production_pilot": {"status": pilot, "external_evidence": external_state["status"]},
        "regulated_production": {"status": regulated, "reason": "external qualification is not inferred" if regulated != "PASS" else None},
        "scanner": {
            "families_total": len(rows),
            "families_configured": configured,
            "families_green": green,
            "status_counts": counts,
            "stale": stale,
            "rows": rows,
            "gaps": scanner_gaps,
        },
        "dependency_cascade": dep,
        "external_evidence": external_state,
        "safety": {
            "destructive_actions": "not executed",
            "secret_values": "not accepted or persisted",
            "customer_attestation_inferred": False,
        },
    }
