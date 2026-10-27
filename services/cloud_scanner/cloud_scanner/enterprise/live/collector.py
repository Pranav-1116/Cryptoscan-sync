"""ZELNX Live Cloud Intelligence Engine — multi-region distributed
architecture (§22) and collector resilience (§23).

§22 — ZELNX global control plane with regional collectors (UAE / EU /
USA).  Each collector monitors assigned cloud environments, maintains a
local processing queue, collects evidence, performs normalization,
supports temporary disconnection, and securely synchronizes approved
results (scale + data residency).

§23 — collector resilience:

    CLOUD EVENT → LOCAL EVENT QUEUE → PROCESSING → CENTRAL PLATFORM
    AVAILABLE? → NO → LOCAL DURABLE QUEUE / YES → SYNC

Retry policies, idempotency, duplicate detection, ordering strategy,
dead-letter queues, checkpointing and backpressure control.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from cloud_scanner.enterprise.live.event_schema import CloudEvent

REGIONS = ("UAE", "EU", "USA")

Processor = Callable[[CloudEvent], Any | None]


@dataclass
class ProcessedOutcome:
    """Outcome of processing one event (idempotency-aware)."""

    event_id: str
    status: str = "processed"  # processed | duplicate | failed | dead_lettered
    attempt: int = 1
    error: str = ""
    result: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "status": self.status,
            "attempt": self.attempt,
            "error": self.error,
            "result": self.result,
        }


class LocalEventQueue:
    """In-collector durable event queue (§22/§23).

    ``persist`` (callable) makes the queue durable across disconnects;
    without one it stays in-memory (still ordered + deduplicated).
    """

    def __init__(self, *, max_depth: int = 10000, persist: Callable[[list[dict]], None] | None = None,
                 load: Callable[[], list[dict]] | None = None) -> None:
        self._max_depth = max_depth
        self._persist = persist
        self._seen_ids: set[str] = set()
        self._queue: list[CloudEvent] = []
        self._dead_letter: list[CloudEvent] = []
        if load:
            for row in load() or []:
                if isinstance(row, dict):
                    self._queue.append(CloudEvent(**{k: v for k, v in row.items()
                                                     if k in CloudEvent.__dataclass_fields__}))
                    if row.get("event_id"):
                        self._seen_ids.add(str(row["event_id"]))

    def push(self, events: list[CloudEvent]) -> dict[str, int]:
        pushed = 0
        duplicates = 0
        for event in events:
            if not event.event_id:
                continue
            if event.event_id in self._seen_ids:
                duplicates += 1
                continue
            if len(self._queue) >= self._max_depth:
                self._dead_letter.append(event)  # backpressure: shed into DLQ
                continue
            self._queue.append(event)
            self._seen_ids.add(event.event_id)
            pushed += 1
        self._checkpoint()
        return {"pushed": pushed, "duplicates": duplicates,
                "dead_lettered": len(self._dead_letter), "depth": len(self._queue)}

    def pop(self, n: int = 1) -> list[CloudEvent]:
        batch, self._queue = self._queue[:n], self._queue[n:]
        return batch

    def depth(self) -> int:
        return len(self._queue)

    def dead_letter_depth(self) -> int:
        return len(self._dead_letter)

    def retry_dead_letter(self) -> int:
        count = len(self._dead_letter)
        self._queue.extend(self._dead_letter)
        self._dead_letter = []
        self._checkpoint()
        return count

    def _checkpoint(self) -> None:
        if self._persist is not None:
            self._persist([event.to_dict() for event in self._queue])

    def summary(self) -> dict[str, Any]:
        return {"depth": len(self._queue), "dead_letter": len(self._dead_letter),
                "seen": len(self._seen_ids)}


@dataclass
class CollectorConfig:
    """Configuration of one regional collector."""

    collector_id: str
    region: str
    provider: str = "aws"  # aws | azure | gcp
    environment: str = "assigned"
    max_retries: int = 3
    backoff_seconds: int = 2
    order_key: str = "timestamp"
    batch_size: int = 100


class RegionalCollector:
    """One regional collector: queue → process → sync (§22/§23)."""

    def __init__(self, config: CollectorConfig, *,
                 process: Processor | None = None,
                 queue: LocalEventQueue | None = None,
                 clock: Callable[[], str] | None = None,
                 sync: Callable[[list[dict]], None] | None = None) -> None:
        self.config = config
        self._process = process or (lambda event: None)
        self._queue = queue or LocalEventQueue()
        self._clock = clock or (lambda: "")
        self._sync = sync
        self._outcomes: list[ProcessedOutcome] = []
        self._checkpoints: list[dict[str, Any]] = []
        self._online = True

    # ------------------------------------------------------------------- ingest

    def ingest(self, events: list[CloudEvent]) -> dict[str, int]:
        stats = self._queue.push(events)
        return stats

    # ----------------------------------------------------------------- process

    def drain(self, *, sync: bool = True) -> dict[str, Any]:
        """Process queued events with retry + idempotency + DLQ."""
        processed = 0
        duplicates = 0
        failed = 0
        dead_lettered = 0
        for event in self._queue.pop(self.config.batch_size):
            outcome = self._process_event(event)
            if outcome.status == "processed":
                processed += 1
            elif outcome.status == "duplicate":
                duplicates += 1
            elif outcome.status == "dead_lettered":
                dead_lettered += 1
            else:
                failed += 1
            self._outcomes.append(outcome)
        self._checkpoint_now()
        synced = 0
        if sync and self._online and self._sync is not None:
            synced = self._sync_batch()
        return {
            "processed": processed,
            "duplicates": duplicates,
            "failed": failed,
            "dead_lettered": dead_lettered,
            "synced": synced,
            "queue_depth": self._queue.depth(),
            "checkpoint": self.last_checkpoint(),
        }

    def _process_event(self, event: CloudEvent) -> ProcessedOutcome:
        for attempt in range(1, self.config.max_retries + 1):
            try:
                result = self._process(event)
                return ProcessedOutcome(event_id=event.event_id, attempt=attempt,
                                        status="processed", result=result)
            except Exception as exc:  # noqa: BLE001
                last_error = str(exc)[:300]
                if attempt < self.config.max_retries:
                    continue
        # exhausted retries → dead-letter
        self._dead_letter(event)
        return ProcessedOutcome(event_id=event.event_id,
                                attempt=self.config.max_retries,
                                status="dead_lettered", error=last_error)

    def _dead_letter(self, event: CloudEvent) -> None:
        self._queue._dead_letter.append(event)  # noqa: SLF001 — collector-owned queue

    # -------------------------------------------------------------------- sync

    def _sync_batch(self) -> int:
        if self._sync is None:
            return 0
        pending = [outcome for outcome in self._outcomes
                   if outcome.status == "processed" and not getattr(outcome, "_synced", False)]
        if not pending:
            return 0
        self._sync([outcome.to_dict() for outcome in pending])
        for outcome in pending:
            outcome._synced = True  # noqa: SLF001
        return len(pending)

    def disconnect(self) -> None:
        """Temporary disconnection — queue stays durable locally (§23)."""
        self._online = False
        self._checkpoint_now()

    def reconnect(self) -> None:
        self._online = True

    @property
    def online(self) -> bool:
        return self._online

    # -------------------------------------------------------------- checkpointing

    def _checkpoint_now(self) -> None:
        self._checkpoints.append({
            "collector_id": self.config.collector_id,
            "at": self._clock(),
            "queue_depth": self._queue.depth(),
            "dead_letter": self._queue.dead_letter_depth(),
            "processed_total": len(self._outcomes),
        })

    def last_checkpoint(self) -> dict[str, Any] | None:
        return self._checkpoints[-1] if self._checkpoints else None

    def summary(self) -> dict[str, Any]:
        return {
            "collector_id": self.config.collector_id,
            "region": self.config.region,
            "provider": self.config.provider,
            "online": self._online,
            "queue": self._queue.summary(),
            "outcomes": {
                status: sum(1 for o in self._outcomes if o.status == status)
                for status in ("processed", "duplicate", "failed", "dead_lettered")
            },
            "checkpoints": len(self._checkpoints),
            "last_checkpoint": self.last_checkpoint(),
        }


class GlobalControlPlane:
    """ZELNX global control plane coordinating regional collectors (§22)."""

    def __init__(self, *, sync: Callable[[str, list[dict]], None] | None = None) -> None:
        self._collectors: dict[str, RegionalCollector] = {}
        self._sync = sync
        self._sync_log: list[dict[str, Any]] = []

    def register(self, collector: RegionalCollector) -> None:
        self._collectors[collector.config.collector_id] = collector

    def collector(self, collector_id: str) -> RegionalCollector | None:
        return self._collectors.get(collector_id)

    def collectors(self) -> list[RegionalCollector]:
        return list(self._collectors.values())

    def receive_sync(self, collector_id: str, outcomes: list[dict[str, Any]]) -> int:
        if self._sync is not None:
            self._sync(collector_id, outcomes)
        self._sync_log.append({"collector_id": collector_id, "records": len(outcomes),
                               "at": ""})
        return len(outcomes)

    def summary(self) -> dict[str, Any]:
        return {
            "collectors": len(self._collectors),
            "by_region": {
                region: sum(1 for c in self._collectors.values()
                            if c.config.region == region)
                for region in REGIONS
            },
            "sync_events_received": sum(entry["records"] for entry in self._sync_log),
            "collector_states": {
                c.config.collector_id: ("online" if c.online else "offline")
                for c in self._collectors.values()
            },
        }
