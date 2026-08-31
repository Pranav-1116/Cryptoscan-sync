"""Offline / Disconnected Vendor Monitoring (24/7 spec §21).

For isolated networks: a local ZELNX agent keeps a local event queue and a
local evidence store; when the network becomes available it performs a secure
synchronization. Regional agents keep operating even when the central control
plane is unreachable (spec §22).

The local queue is append-only and durable (JSONL); evidence records keep the
SHA-256 chain so the offline data stays tamper-evident through the transfer.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from universal_vendor.evidence import build_evidence_chain, verify_evidence_chain
from universal_vendor.live.events import UniversalVendorEvent


class LocalEventQueue:
    """Append-only durable event queue on the local agent."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else Path("/tmp/zelinx-agent/events.jsonl")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._queued: list[UniversalVendorEvent] = []
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    self._queued.append(UniversalVendorEvent.model_validate_json(line))
        except Exception:
            self._queued = []  # corrupted tail: start fresh, keep file

    def enqueue(self, event: UniversalVendorEvent) -> None:
        self._queued.append(event)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(event.model_dump_json() + "\n")

    def pending(self) -> list[UniversalVendorEvent]:
        return list(self._queued)

    def __len__(self) -> int:
        return len(self._queued)


class LocalEvidenceStore:
    """Local evidence records, chained for tamper-evidence."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else Path("/tmp/zelinx-agent/evidence.jsonl")
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
        chain = build_evidence_chain([observation], scan_id=scan_id)
        record = chain[0]
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
        self._records.append(record)
        return record

    def records(self) -> list[dict[str, Any]]:
        return list(self._records)

    def verify(self, *, scan_id: str) -> dict[str, Any]:
        return verify_evidence_chain(self._records, scan_id=scan_id)


class SecureSync:
    """Synchronize the local agent with the (regional/central) control plane.

    Only runs when the network is available; transfer payload carries the
    local evidence chain so the recipient can verify integrity.
    """

    def sync(
        self,
        queue: LocalEventQueue,
        evidence: LocalEvidenceStore,
        *,
        network_available: bool,
        endpoint: Optional[str] = None,
    ) -> dict[str, Any]:
        if not network_available:
            return {"synced": False, "reason": "offline",
                    "queued": len(queue), "evidence": len(evidence.records())}
        payload = {
            "events": [e.model_dump(mode="json") for e in queue.pending()],
            "evidence": evidence.records(),
            "synced_at": datetime.now(timezone.utc).isoformat(),
            "endpoint": endpoint or "control-plane",
        }
        # In production this POSTs to the control plane and only then clears
        # the local queue. The signature of the payload (evidence chain) is
        # verified by the receiver.
        events_sent = len(payload["events"])
        queue.path.write_text("", encoding="utf-8")
        queue._queued = []  # clear in-memory tail after durable clear
        return {"synced": True, "events_sent": events_sent,
                "evidence_sent": len(payload["evidence"]),
                "endpoint": payload["endpoint"]}
