"""Priority-based 24/7 scheduling engine.

Priority Score = business criticality + internet exposure + crypto risk +
                 change frequency + compliance importance

Higher-priority assets are monitored more frequently; low-priority assets
less frequently.  Everything is configurable via ``MonitoringPolicy``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from network_scanner.enterprise.live.modes import MonitoringPolicy

PRIORITY_COMPONENTS = (
    "business_criticality",
    "internet_exposure",
    "crypto_risk",
    "change_frequency",
    "compliance_importance",
)

TIERS = ("CRITICAL", "HIGH", "STANDARD", "LOW")

DEFAULT_WEIGHTS: dict[str, float] = {
    "business_criticality": 1.0,
    "internet_exposure": 1.0,
    "crypto_risk": 1.0,
    "change_frequency": 0.6,
    "compliance_importance": 1.0,
}

# score thresholds → tier (inclusive lower bounds)
TIER_THRESHOLDS: tuple[tuple[str, float], ...] = (
    ("CRITICAL", 8.0),
    ("HIGH", 6.0),
    ("STANDARD", 4.0),
    ("LOW", 0.0),
)

Clock = Callable[[], Any]


def priority_score(risk: dict[str, float] | None = None,
                   *, weights: dict[str, float] | None = None) -> float:
    """Weighted priority score in [0, 10].

    ``risk`` maps component name → value in [0, 10].  Missing components
    default to 0 (no risk signal).  A ``weights`` map can re-balance the
    components; unknown weights are ignored.
    """
    risk = risk or {}
    weights = dict(DEFAULT_WEIGHTS if weights is None else weights)
    total = 0.0
    weight_sum = 0.0
    for component in PRIORITY_COMPONENTS:
        w = weights.get(component, 0.0)
        if w <= 0:
            continue
        value = risk.get(component, 0.0)
        try:
            value = max(0.0, min(10.0, float(value)))
        except (TypeError, ValueError):
            value = 0.0
        total += w * value
        weight_sum += w
    if weight_sum <= 0:
        return 0.0
    return round(total / weight_sum, 2)


def tier_for_score(score: float) -> str:
    for name, threshold in TIER_THRESHOLDS:
        if score >= threshold:
            return name
    return "LOW"


@dataclass
class ScheduledItem:
    """A monitored asset plus its scheduling metadata."""

    asset_id: str
    risk: dict[str, float] = field(default_factory=dict)
    priority: float = 0.0
    tier: str = "STANDARD"
    last_scanned: Any = None
    last_deep_scan: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {"asset_id": self.asset_id,
                "risk": dict(self.risk),
                "priority": self.priority,
                "tier": self.tier}


class Scheduler:
    """Assigns tiers and decides which assets are due for (light/deep) scans.

    ``now`` is injectable as a callable returning the current timestamp.
    """

    def __init__(self, *, policy: MonitoringPolicy | None = None,
                 weights: dict[str, float] | None = None,
                 clock: Clock | None = None) -> None:
        self.policy = policy or MonitoringPolicy()
        self.weights = dict(weights or DEFAULT_WEIGHTS)
        self._clock = clock

    # ------------------------------------------------------------- schedule

    def schedule(self, asset_id: str,
                 risk: dict[str, float] | None = None,
                 *, last_scanned: Any = None,
                 last_deep_scan: Any = None) -> ScheduledItem:
        risk = risk or {}
        score = priority_score(risk, weights=self.weights)
        return ScheduledItem(
            asset_id=asset_id,
            risk=dict(risk),
            priority=score,
            tier=tier_for_score(score),
            last_scanned=last_scanned,
            last_deep_scan=last_deep_scan,
        )

    # ------------------------------------------------------------- due-ness

    def _now(self) -> Any:
        return self._clock() if self._clock else None

    def lightweight_due(self, item: ScheduledItem, *, now: Any = None) -> bool:
        now = now if now is not None else self._now()
        if item.last_scanned is None:
            return True
        if now is None:
            return False
        try:
            elapsed = (now - item.last_scanned).total_seconds()
        except Exception:
            return True
        return elapsed >= self.policy.interval_for(item.tier)

    def deep_due(self, item: ScheduledItem, *, now: Any = None) -> bool:
        now = now if now is not None else self._now()
        return self.policy.deep_due(item.last_deep_scan, now)

    def due_assets(self, items: list[ScheduledItem], *, now: Any = None) -> list[str]:
        """Assets due for a periodic lightweight scan, highest priority first."""
        return [item.asset_id for item in sorted(
            (i for i in items if self.lightweight_due(i, now=now)),
            key=lambda i: i.priority, reverse=True)]

    def deep_due_assets(self, items: list[ScheduledItem], *, now: Any = None) -> list[str]:
        """Assets due for a scheduled deep scan, highest priority first."""
        return [item.asset_id for item in sorted(
            (i for i in items if self.deep_due(i, now=now)),
            key=lambda i: i.priority, reverse=True)]

    def summarize(self, items: list[ScheduledItem]) -> dict[str, Any]:
        by_tier: dict[str, int] = {}
        for item in items:
            by_tier[item.tier] = by_tier.get(item.tier, 0) + 1
        return {"assets": len(items), "by_tier": by_tier}
