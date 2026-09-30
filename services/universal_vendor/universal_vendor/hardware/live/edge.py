"""24/7 distributed hardware monitoring — edge agent (§21).

For large/global deployments:

    ZELNX CONTROL PLANE ── REGION A/B/C ── ZELNX EDGE ── HARDWARE NETWORK

The edge keeps operating when the central platform is temporarily
unavailable: hardware events land in a local durable queue, local evidence
keeps the SHA-256 chain, and central sync drains the queue only after the
control plane acknowledges receipt.

Hard rule: a missing control plane never drops events and never fabricates
hardware removal — the queue grows and sync retries later.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from universal_vendor.evidence import build_evidence_chain, verify_evidence_chain
from universal_vendor.hardware.live.events import HardwareEvent


class EdgeHardwareQueue:
    """Append-only durable JSONL queue on the edge agent."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else Path("/tmp/zelinx-edge-hardware/events.jsonl")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._queued: list[HardwareEvent] = []
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    self._queued.append(HardwareEvent.model_validate_json(line))
                except Exception as _handler_exc:
                    logger.warning(
                        "exception_suppressed",
                        extra={"error_type": type(_handler_exc).__name__},
                    )
                    continue  # corrupted tail: skip, keep file for forensics

    def enqueue(self, event: HardwareEvent) -> None:
        self._queued.append(event)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(event.model_dump_json() + "\n")

    def pending(self) -> list[HardwareEvent]:
        return list(self._queued)

    def __len__(self) -> int:
        return len(self._queued)

    def clear(self) -> None:
        self.path.write_text("", encoding="utf-8")
        self._queued = []


class EdgeEvidenceStore:
    """Local hardware evidence records, hash-chained (§17, §21)."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else Path("/tmp/zelinx-edge-hardware/evidence.jsonl")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._records: list[dict[str, Any]] = []
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    self._records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    def append(self, observation: dict[str, Any], *, scan_id: str) -> dict[str, Any]:
        previous_hash = self._records[-1]["chain_hash"] if self._records else None
        chain = build_evidence_chain([observation], scan_id=scan_id,
                                     start_index=len(self._records),
                                     previous_hash=previous_hash)
        record = chain[0]
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
        self._records.append(record)
        return record

    def records(self) -> list[dict[str, Any]]:
        return list(self._records)

    def verify(self, *, scan_id: str) -> dict[str, Any]:
        return verify_evidence_chain(self._records, scan_id=scan_id)


class EdgeHardwareAgent:
    """One edge agent: durable queue + local evidence + central sync.

    ``flush`` is the delivery callback (e.g. an HTTPS POST to the control
    plane). The queue is only drained after ``flush`` succeeds — a failing
    or absent control plane leaves the queue intact.
    """

    def __init__(
        self,
        agent_id: str,
        *,
        queue_path: str | Path | None = None,
        evidence_path: str | Path | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.queue = EdgeHardwareQueue(queue_path)
        self.evidence = EdgeEvidenceStore(evidence_path)
        self._last_sync: Optional[str] = None
        self._sync_failures: int = 0

    def ingest(self, event: HardwareEvent) -> HardwareEvent:
        """Local durable ingest — works with the control plane offline."""
        if not event.agent_id:
            event.agent_id = self.agent_id
        self.queue.enqueue(event)
        self.evidence.append(event.model_dump(mode="json"),
                             scan_id=f"edge:{self.agent_id}")
        return event

    def pending_count(self) -> int:
        return len(self.queue)

    def evidence_count(self) -> int:
        return len(self.evidence.records())

    def sync(
        self,
        flush: Callable[[list[dict[str, Any]]], None],
    ) -> dict[str, Any]:
        """Deliver pending events through ``flush``; drain only on success."""
        pending = self.queue.pending()
        if not pending:
            return {"synced": True, "events_sent": 0,
                    "agent_id": self.agent_id, "drained": False}
        payload = [e.model_dump(mode="json") for e in pending]
        try:
            flush(payload)  # control-plane call; raises on failure/offline
        except Exception as exc:
            self._sync_failures += 1
            return {"synced": False, "reason": f"{type(exc).__name__}: {exc}",
                    "events_sent": 0, "queued": len(pending),
                    "agent_id": self.agent_id, "sync_failures": self._sync_failures}
        self.queue.clear()  # durable clear only after ACK
        self._last_sync = datetime.now(timezone.utc).isoformat()
        self._sync_failures = 0
        return {"synced": True, "events_sent": len(pending),
                "queued": 0, "agent_id": self.agent_id,
                "synced_at": self._last_sync}

    def state(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "queue_depth": self.pending_count(),
            "evidence_records": self.evidence_count(),
            "last_sync": self._last_sync,
            "sync_failures": self._sync_failures,
            "control_plane_reachable": self._last_sync is not None,
        }
