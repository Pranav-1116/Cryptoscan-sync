"""Multi-region, data residency/sovereignty and HA/DR logic.

Pure/deterministic: region routing by residency, failover decisions given
regional health, and RPO/RTO assessment from backup timestamps.
"""

from __future__ import annotations

from datetime import datetime, timezone


def route_region(tenant: dict, preferred: str | None = None) -> str:
    """Choose the processing region for a tenant: residency-locked preferred,
    else a permitted region, else the tenant's home residency region."""
    allowed = tenant.get("processing_regions") or []
    home = tenant.get("data_residency_region", "us")
    if preferred and (not allowed or preferred in allowed):
        return preferred
    if home and (not allowed or home in allowed):
        return home
    if allowed:
        return allowed[0]
    return home


def residency_violations(tenant: dict, data_regions: list[str]) -> list[str]:
    """Return the regions where this tenant's data is present but forbidden."""
    allowed = set(tenant.get("processing_regions") or [])
    if not allowed:
        return []
    home = tenant.get("data_residency_region")
    allowed |= {home} if home else set()
    return sorted({r for r in data_regions if r not in allowed})


def rpo_minutes(last_backup_at: str | None, now: datetime | None = None) -> float | None:
    """Data-loss exposure = minutes since the last successful backup."""
    if not last_backup_at:
        return None
    now = now or datetime.now(timezone.utc)
    try:
        dt = datetime.fromisoformat(str(last_backup_at).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return round((now - dt).total_seconds() / 60, 1)
    except ValueError:
        return None


def assess_dr(config: dict, *, last_backup_at: str | None = None,
              primary_healthy: bool = True, secondary_healthy: bool = True,
              now: datetime | None = None) -> dict:
    """Evaluate RPO/RTO posture + failover readiness."""
    rpo_target = config.get("rpo_minutes", 60)
    rto_target = config.get("rto_minutes", 60)
    exposure = rpo_minutes(last_backup_at, now)
    rpo_ok = exposure is not None and exposure <= rpo_target
    within_target = rpo_ok
    can_failover = primary_healthy is False and secondary_healthy
    recommendation = "healthy"
    if primary_healthy is False:
        recommendation = "failover" if can_failover else "critical: secondary unavailable"
    elif exposure is None:
        recommendation = "no backups configured"
    elif not within_target:
        recommendation = f"backup age {exposure}m exceeds RPO {rpo_target}m"
    return {
        "rpo_target_minutes": rpo_target, "rto_target_minutes": rto_target,
        "rpo_actual_minutes": exposure, "rpo_within_target": within_target,
        "primary_healthy": primary_healthy, "secondary_healthy": secondary_healthy,
        "failover_ready": bool(secondary_healthy),
        "recommended_action": recommendation,
    }


def dr_test_schedule(last_test_at: str | None, cadence_days: int = 90,
                     now: datetime | None = None) -> dict:
    """Whether a DR restore test is due (and the next due date)."""
    now = now or datetime.now(timezone.utc)
    if not last_test_at:
        return {"due": True, "days_overdue": None}
    try:
        dt = datetime.fromisoformat(str(last_test_at).replace("Z", "+00:00"))
        age_days = (now - dt).total_seconds() / 86400
        due = age_days >= cadence_days
        return {"due": due, "days_since_test": round(age_days, 1),
                "cadence_days": cadence_days}
    except ValueError:
        return {"due": True, "days_overdue": None}
