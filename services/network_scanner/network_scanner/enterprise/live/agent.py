"""Distributed 24/7 architecture — control plane + edge agents.

Each agent scans locally, normalizes locally, collects evidence, sends
approved metadata centrally, and keeps monitoring even when temporarily
disconnected (local queue → evidence cache → reconnect → secure sync).

    ZELNX CONTROL PLANE → Scheduler/Orchestrator → UAE / EU / USA agents
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

from network_scanner.enterprise.live.health import ScannerHealthMonitor


class LocalQueue:
    """Bounded FIFO queue for offline-first event/evidence buffering."""

    def __init__(self, *, max_items: int = 10_000,
                 spill_path: str | None = None) -> None:
        self._items: list[dict[str, Any]] = []
        self._max = max_items
        self._spill = spill_path

    def put(self, item: dict[str, Any]) -> bool:
        if len(self._items) >= self._max:
            return False  # queue full — caller must decide (drop/rotate)
        self._items.append(dict(item))
        return True

    def put_many(self, items: Iterable[dict[str, Any]]) -> int:
        accepted = 0
        for item in items:
            if self.put(item):
                accepted += 1
        return accepted

    def get_many(self, n: int = 100) -> list[dict[str, Any]]:
        out, self._items = self._items[:n], self._items[n:]
        return out

    def pending(self) -> int:
        return len(self._items)

    def clear(self) -> None:
        self._items = []


class EvidenceCache:
    """Bounded local cache of collected evidence records."""

    def __init__(self, *, max_items: int = 5_000) -> None:
        self._items: dict[str, dict[str, Any]] = {}
        self._max = max_items

    def store(self, key: str, record: dict[str, Any]) -> None:
        if key in self._items or len(self._items) < self._max:
            self._items[key] = dict(record)

    def get(self, key: str) -> dict[str, Any] | None:
        record = self._items.get(key)
        return dict(record) if record is not None else None

    def items(self) -> dict[str, dict[str, Any]]:
        return {k: dict(v) for k, v in self._items.items()}

    def size(self) -> int:
        return len(self._items)


class SecureSyncEngine:
    """Offline-tolerant sync: buffer locally, upload on reconnect."""

    def __init__(self, *, queue: LocalQueue | None = None,
                 uploader: Callable[[list[dict[str, Any]]], dict[str, Any]] | None = None,
                 is_online: Callable[[], bool] | None = None) -> None:
        self._queue = queue or LocalQueue()
        self._uploader = uploader
        self._online = is_online or (lambda: True)
        self._synced = 0
        self._failed = 0

    @property
    def queue(self) -> LocalQueue:
        return self._queue

    def enqueue(self, item: dict[str, Any]) -> bool:
        return self._queue.put(item)

    def sync(self, *, batch: int = 100) -> dict[str, Any]:
        if not self._online():
            return {"online": False, "synced": 0, "pending": self._queue.pending()}
        if self._uploader is None:
            return {"online": True, "synced": 0, "pending": self._queue.pending(),
                    "error": "no uploader configured"}
        batch_items = self._queue.get_many(batch)
        try:
            result = self._uploader(batch_items) or {}
        except Exception:
            for item in batch_items:  # re-queue on failure
                self._queue.put(item)
            self._failed += len(batch_items)
            return {"online": True, "synced": 0, "failed": len(batch_items),
                    "pending": self._queue.pending()}
        self._synced += len(batch_items)
        return {"online": True, "synced": len(batch_items),
                "pending": self._queue.pending(),
                "result": result, "failed": self._failed}

    def stats(self) -> dict[str, Any]:
        return {"synced_total": self._synced, "failed_total": self._failed,
                "pending": self._queue.pending()}


class EdgeAgent:
    """A regional agent: local scan/normalize/evidence + secure sync.

    All components are injectable — the agent itself performs no I/O.
    """

    def __init__(self, *, region: str, agent_id: str = "",
                 queue: LocalQueue | None = None,
                 sync: SecureSyncEngine | None = None,
                 health: ScannerHealthMonitor | None = None,
                 collector: Callable[[], list[dict[str, Any]]] | None = None,
                 plugins: Iterable[str] = ()) -> None:
        self.region = region
        self.agent_id = agent_id or f"{region.lower()}-agent"
        self.queue = queue or LocalQueue()
        self.sync = sync or SecureSyncEngine(queue=self.queue)
        self.health = health or ScannerHealthMonitor(agent_id=self.agent_id)
        self._collector = collector
        self.plugins = list(plugins)

    def collect(self) -> list[dict[str, Any]]:
        """Run the local collector and buffer everything into the queue."""
        if self._collector is None:
            return []
        items = self._collector() or []
        accepted = self.queue.put_many(items)
        self.health.tick(queue_depth=self.queue.pending())
        return items[:accepted]

    def sync_now(self, *, batch: int = 100) -> dict[str, Any]:
        # bridge the agent queue into the sync engine's queue when they differ
        if self.sync.queue is not self.queue:
            items = self.queue.get_many(batch)
            self.sync.queue.put_many(items)
        result = self.sync.sync(batch=batch)
        self.health.tick(queue_depth=self.queue.pending())
        return result

    def status(self) -> dict[str, Any]:
        return {"agent_id": self.agent_id, "region": self.region,
                "plugins": list(self.plugins),
                "health": self.health.report(),
                "queue_depth": self.queue.pending(),
                "sync": self.sync.stats()}


class ControlPlane:
    """Central orchestrator: registers agents and aggregates their status."""

    def __init__(self, *, agents: Iterable[EdgeAgent] | None = None,
                 clock: Callable[[], Any] | None = None) -> None:
        self._agents: dict[str, EdgeAgent] = {}
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        for agent in agents or []:
            self.register(agent)

    def register(self, agent: EdgeAgent) -> None:
        self._agents[agent.agent_id] = agent

    def agents(self) -> list[EdgeAgent]:
        return list(self._agents.values())

    def get(self, agent_id: str) -> EdgeAgent | None:
        return self._agents.get(agent_id)

    def orchestrate_sync(self, *, batch: int = 100) -> list[dict[str, Any]]:
        return [agent.sync_now(batch=batch) for agent in self._agents.values()]

    def summary(self) -> dict[str, Any]:
        states: dict[str, int] = {}
        total_pending = 0
        regions: list[str] = []
        for agent in self._agents.values():
            state = agent.health.state(now=self._clock())
            states[state] = states.get(state, 0) + 1
            total_pending += agent.queue.pending()
            if agent.region not in regions:
                regions.append(agent.region)
        return {"agents": len(self._agents), "regions": sorted(regions),
                "health_states": states, "total_pending": total_pending}
