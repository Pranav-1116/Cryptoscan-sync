"""Performance retention plans (docs/performance/01_PRODUCT_SPEC.md §9:
"Define retention and aggregation policies").

A plan is a PROJECTION: it names which rows a retention policy would
expire and which it would keep. Planning never deletes anything —
originals are never removed by a plan, and a plan that cannot classify a
row names it as unknown rather than guessing an age.

The output is deterministic: the same rows and policy produce the same
plan, every time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Mapping, Sequence

from shared_models.performance_metrics import PerformanceMetric

DEFAULT_SAMPLES_DAYS = 30
DEFAULT_AGGREGATES_DAYS = 365


@dataclass(frozen=True)
class RetentionPolicy:
    policy_key: str
    samples_days: int = DEFAULT_SAMPLES_DAYS
    aggregates_days: int = DEFAULT_AGGREGATES_DAYS

    def __post_init__(self) -> None:
        if self.samples_days <= 0 or self.aggregates_days <= 0:
            raise ValueError(
                "retention windows are positive — a zero-day window would "
                "expire everything instantly, which is a deletion decision, "
                "not a policy")


@dataclass
class RetentionPlan:
    policy_key: str
    window_start: datetime
    window_end: datetime
    expired: Dict[str, int] = field(default_factory=dict)
    retained: Dict[str, int] = field(default_factory=dict)
    unknown: int = 0

    @property
    def expired_total(self) -> int:
        return sum(self.expired.values())

    @property
    def retained_total(self) -> int:
        return sum(self.retained.values())

    def as_dict(self) -> Dict[str, Any]:
        return {
            "policy_key": self.policy_key,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "expired": dict(sorted(self.expired.items())),
            "retained": dict(sorted(self.retained.items())),
            "expired_total": self.expired_total,
            "retained_total": self.retained_total,
            "unknown": self.unknown,
            "note": "a retention plan is a projection — it names what the "
                    "policy would expire; planning never deletes originals",
        }


def plan_retention(rows: Sequence[PerformanceMetric], *,
                   policy: RetentionPolicy,
                   now: datetime) -> RetentionPlan:
    """Classify every row under the policy's sample window. A row whose
    observed_at cannot be compared to the window is counted unknown —
    never silently dropped and never guessed."""
    if now.tzinfo is None:
        raise ValueError("now must carry its timezone — retention is "
                         "computed on instants, not naive labels")
    cutoff = now - timedelta(days=policy.samples_days)
    plan = RetentionPlan(policy_key=policy.policy_key,
                         window_start=cutoff, window_end=now)
    for row in rows:
        observed = row.observed_at
        if observed is None:
            plan.unknown += 1
            continue
        bucket = plan.expired if observed < cutoff else plan.retained
        bucket[row.metric_name] = bucket.get(row.metric_name, 0) + 1
    return plan
