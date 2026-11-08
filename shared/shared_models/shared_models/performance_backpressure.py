"""Bounded ingest with backpressure (docs/performance/01_PRODUCT_SPEC.md §9:
"Use bounded queues and backpressure").

A performance ingestion gateway has bounded queues: when the queue is
full, the offer is REFUSED with its reason and counted — backpressure
never silently drops a measurement, and a refused row is never later
drawn as if it had been ingested. Drain order is FIFO; the queue never
grows past its bound.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence

from shared_models.performance_metrics import PerformanceMetric


@dataclass
class BoundedIngestQueue:
    """A bounded FIFO for metric rows under backpressure."""

    max_pending: int
    _pending: List[PerformanceMetric] = field(default_factory=list)
    _refused: int = 0
    _accepted: int = 0

    def __post_init__(self) -> None:
        if self.max_pending <= 0:
            raise ValueError(
                "a bounded queue has a positive bound — an unbounded "
                "queue is how ingestion falls over in production")

    @property
    def pending(self) -> int:
        return len(self._pending)

    @property
    def refused_count(self) -> int:
        return self._refused

    @property
    def accepted_count(self) -> int:
        return self._accepted

    def offer(self, row: PerformanceMetric) -> bool:
        """Offer one row. Returns True if queued, False under
        backpressure — the refusal is counted, never silent."""
        if len(self._pending) >= self.max_pending:
            self._refused += 1
            return False
        self._pending.append(row)
        self._accepted += 1
        return True

    def offer_many(self, rows: Sequence[PerformanceMetric]
                   ) -> Dict[str, Any]:
        offered = sum(1 for row in rows if self.offer(row))
        return {"offered": offered,
                "refused": len(rows) - offered,
                "pending": self.pending,
                "refused_total": self.refused_count}

    def drain(self) -> List[PerformanceMetric]:
        """Remove and return every queued row, in FIFO order."""
        rows = list(self._pending)
        self._pending.clear()
        return rows

    def as_dict(self) -> Dict[str, Any]:
        return {
            "max_pending": self.max_pending,
            "pending": self.pending,
            "accepted_total": self.accepted_count,
            "refused_total": self.refused_count,
            "note": "backpressure refuses and counts — it never silently "
                    "drops a measurement",
        }
