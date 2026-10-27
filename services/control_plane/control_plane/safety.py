"""Safe-scanning / impact-protection logic.

Centralizes the decision of *whether and how* a scan may run against a scope:
safety mode, maintenance windows, exclusions, budgets and automatic stop
conditions. Pure/deterministic so it is fully unit-testable and reusable by
the orchestrator, workers and OT scanner.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

# ordered least -> most intrusive
IMPACT_ORDER = ("passive", "safe", "low_impact", "standard", "deep")

DEFAULT_BUDGETS = {
    "passive": {"rate_limit_qps": 2, "max_connections": 25, "concurrent_scans": 1, "scan_budget_minutes": 480},
    "safe": {"rate_limit_qps": 3, "max_connections": 25, "concurrent_scans": 1, "scan_budget_minutes": 360},
    "low_impact": {"rate_limit_qps": 5, "max_connections": 50, "concurrent_scans": 1, "scan_budget_minutes": 300},
    "standard": {"rate_limit_qps": 10, "max_connections": 100, "concurrent_scans": 2, "scan_budget_minutes": 240},
    "deep": {"rate_limit_qps": 20, "max_connections": 200, "concurrent_scans": 4, "scan_budget_minutes": 120},
}


def _weekday(now: datetime) -> str:
    return now.strftime("%a").lower()


def maintenance_window_open(windows: list[dict] | None, now: datetime | None = None,
                            tz_offset_hours: int = 0) -> bool:
    """True if now (UTC) is inside one of the declared weekly maintenance
    windows. Empty windows => no restriction (always open). Times are
    interpreted in the policy's local time via ``tz_offset_hours``."""
    if not windows:
        return True
    now = now or datetime.now(timezone.utc)
    local = now
    try:
        from datetime import timedelta

        local = now + timedelta(hours=tz_offset_hours)
    except Exception:  # noqa: BLE001 - defensive tz fallback
        local = now
    day = _weekday(local)
    for w in windows:
        if str(w.get("day", "")).lower() not in {day, day[:3], "*"}:
            continue
        try:
            sh, sm = (int(x) for x in str(w.get("start", "00:00")).split(":")[:2])
            duration = int(w.get("duration_minutes", 60))
        except (ValueError, TypeError):
            continue
        start_min = sh * 60 + sm
        cur = local.hour * 60 + local.minute
        if start_min <= cur < start_min + duration:
            return True
    return False


@dataclass
class ScanDecision:
    permitted: bool
    mode: str
    active_probing: bool
    reason: str
    budgets: dict = field(default_factory=dict)
    excluded: dict = field(default_factory=dict)


def evaluate_scan(
    policy: dict | None,
    *,
    asset: str | None = None,
    port: int | None = None,
    protocol: str | None = None,
    is_ot: bool = False,
    now: datetime | None = None,
) -> ScanDecision:
    """Decide how a scan may proceed given a safe-scan policy.

    Fail-closed toward passive: emergency stop blocks everything; OT forces
    passive unless inside a maintenance window; exclusions drop specific
    assets/ports/protocols; budgets clamp the rate/connection limits.
    """
    policy = policy or {}
    now = now or datetime.now(timezone.utc)

    if policy.get("emergency_stop"):
        return ScanDecision(False, "emergency_stop", False,
                            "emergency stop is engaged — all scanning halted",
                            excluded={"reason": "emergency_stop"})

    mode = policy.get("mode", "standard")
    if mode == "emergency_stop":
        return ScanDecision(False, "emergency_stop", False,
                            "policy mode is emergency_stop", excluded={"reason": "mode"})

    # exclusions
    excluded_assets = policy.get("excluded_assets", []) or []
    excluded_ports = policy.get("excluded_ports", []) or []
    excluded_protocols = policy.get("excluded_protocols", []) or []
    if asset and asset in excluded_assets:
        return ScanDecision(False, mode, False, f"asset {asset} excluded",
                            excluded={"asset": asset})
    if port is not None and port in list(excluded_ports):
        return ScanDecision(False, mode, False, f"port {port} excluded",
                            excluded={"port": port})
    if protocol and str(protocol).lower() in [str(p).lower() for p in excluded_protocols]:
        return ScanDecision(False, mode, False, f"protocol {protocol} excluded",
                            excluded={"protocol": protocol})

    windows = policy.get("maintenance_windows") or []
    tz_name = policy.get("maintenance_timezone") or "UTC"
    # crude UTC offset table for the common regions; unknown => 0
    offsets = {"UTC": 0, "UAE": 4, "IST": 5.5, "EU": 1, "US": -5, "Asia/Kolkata": 5.5}
    tz_off = int(offsets.get(tz_name, 0))
    in_window = maintenance_window_open(windows, now, tz_off)

    active_mode = mode in {"standard", "deep", "low_impact"}
    active_probing = active_mode

    if is_ot:
        # OT: passive always; active only inside a maintenance window
        if not in_window and mode not in {"passive", "safe"}:
            active_probing = False
            mode = "passive"
            reason = "OT environment outside maintenance window — passive only"
        elif not in_window:
            active_probing = False
            reason = "OT environment — passive/safe observation"
        else:
            active_probing = active_mode
            reason = "OT inside maintenance window"
    else:
        if windows and not in_window and mode == "deep":
            # deep scans respect maintenance windows on IT too
            mode = "standard"
            active_probing = True
            reason = "outside maintenance window — downgraded deep to standard"
        else:
            reason = f"mode {mode}"

    budgets = dict(DEFAULT_BUDGETS.get(mode if mode in DEFAULT_BUDGETS else "standard"))
    # policy can only tighten (lower) the defaults, never loosen beyond them
    for key, default_val in budgets.items():
        val = policy.get(key)
        if isinstance(val, int) and 0 < val <= default_val:
            budgets[key] = val

    return ScanDecision(True, mode, active_probing, reason, budgets=budgets,
                        excluded={"assets": excluded_assets, "ports": list(excluded_ports),
                                  "protocols": excluded_protocols})


def should_auto_stop(conditions: dict | None, runtime: dict) -> tuple[bool, str]:
    """Evaluate automatic stop conditions against live runtime metrics.

    conditions e.g. {"max_error_rate": 0.05, "max_latency_ms": 2000,
    "max_connection_failures": 50}; runtime provides current values.
    Fail-closed: missing metrics do not trigger a stop, but thresholds
    exceeded do.
    """
    conditions = conditions or {}
    checks = {
        "max_error_rate": ("error_rate", lambda v, t: v >= t),
        "max_latency_ms": ("latency_ms", lambda v, t: v >= t),
        "max_connection_failures": ("connection_failures", lambda v, t: v >= t),
        "max_target_unreachable": ("targets_unreachable", lambda v, t: v >= t),
    }
    for cond_key, (rt_key, breach) in checks.items():
        threshold = conditions.get(cond_key)
        current = runtime.get(rt_key)
        if threshold is None or current is None:
            continue
        try:
            if breach(float(current), float(threshold)):
                return True, f"{rt_key}={current} breached {cond_key}={threshold}"
        except (TypeError, ValueError):
            continue
    return False, "within thresholds"
