"""Live CBOM — event-sourced Cryptographic Bill of Materials.

    EVENT (Asset Discovered / Certificate Changed / TLS Changed / VPN Changed
           / Device Removed) → EVENT LOG → CBOM MATERIALIZER → LIVE CBOM

Because every change is an event, the CBOM can be reconstructed at any
historical time by replaying events up to that timestamp.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

CBOM_EVENT_TYPES = (
    "ASSET_DISCOVERED",
    "ASSET_UPDATED",
    "ASSET_REMOVED",
    "CERTIFICATE_CHANGED",
    "TLS_CHANGED",
    "VPN_CHANGED",
    "DEVICE_REMOVED",
    "CRYPTO_DRIFT",
)

_EVENT_TO_ASSET_OP: dict[str, str] = {
    "ASSET_DISCOVERED": "upsert",
    "ASSET_UPDATED": "upsert",
    "CERTIFICATE_CHANGED": "upsert",
    "TLS_CHANGED": "upsert",
    "VPN_CHANGED": "upsert",
    "ASSET_REMOVED": "remove",
    "DEVICE_REMOVED": "remove",
    "CRYPTO_DRIFT": "upsert",
}


@dataclass
class CbomEvent:
    sequence: int
    event_type: str
    asset_id: str
    occurred_at: Any
    snapshot: dict[str, Any] = field(default_factory=dict)
    change: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.event_type not in CBOM_EVENT_TYPES:
            raise ValueError(f"unknown CBOM event type '{self.event_type}'")

    def to_dict(self) -> dict[str, Any]:
        occurred = self.occurred_at
        if hasattr(occurred, "isoformat"):
            occurred = occurred.isoformat()
        return {"sequence": self.sequence, "event_type": self.event_type,
                "asset_id": self.asset_id, "occurred_at": occurred,
                "snapshot": dict(self.snapshot), "change": dict(self.change)}


class CbomEventLog:
    """Append-only event log with monotonically increasing sequence numbers."""

    def __init__(self) -> None:
        self._events: list[CbomEvent] = []

    def append(self, event_type: str, asset_id: str, *,
               occurred_at: Any = None, snapshot: dict[str, Any] | None = None,
               change: dict[str, Any] | None = None,
               clock: Callable[[], Any] | None = None) -> CbomEvent:
        occurred = occurred_at
        if occurred is None:
            occurred = (clock() if clock else datetime.now(timezone.utc))
        event = CbomEvent(sequence=len(self._events), event_type=event_type,
                          asset_id=asset_id, occurred_at=occurred,
                          snapshot=dict(snapshot or {}),
                          change=dict(change or {}))
        self._events.append(event)
        return event

    def events(self, *, after: int = -1, before: int | None = None,
               asset_id: str | None = None,
               event_type: str | None = None) -> list[CbomEvent]:
        out = self._events[after + 1:]
        if before is not None:
            out = [e for e in out if e.sequence < before]
        if asset_id is not None:
            out = [e for e in out if e.asset_id == asset_id]
        if event_type is not None:
            out = [e for e in out if e.event_type == event_type]
        return list(out)

    def __len__(self) -> int:
        return len(self._events)


class LiveCBOM:
    """The materialized current state (replay target)."""

    def __init__(self) -> None:
        self._components: dict[str, dict[str, Any]] = {}
        self._events_applied = 0

    def apply(self, event: CbomEvent) -> None:
        op = _EVENT_TO_ASSET_OP[event.event_type]
        if op == "remove":
            self._components.pop(event.asset_id, None)
        else:
            current = self._components.setdefault(event.asset_id, {})
            current.update(event.snapshot)
            if event.change:
                current.setdefault("changes", [])
                current["changes"] = list(current["changes"]) + [dict(event.change)]
        self._events_applied += 1

    def components(self) -> dict[str, dict[str, Any]]:
        return {k: dict(v) for k, v in self._components.items()}

    def get(self, asset_id: str) -> dict[str, Any] | None:
        state = self._components.get(asset_id)
        return dict(state) if state is not None else None

    def summary(self) -> dict[str, Any]:
        crypto_components = sum(
            1 for state in self._components.values()
            if any(key in state for key in ("crypto", "tls_version",
                                            "certificate_fingerprints",
                                            "vpn", "algorithms")))
        return {"component_count": len(self._components),
                "crypto_components": crypto_components,
                "events_applied": self._events_applied}


class CbomMaterializer:
    """Event log → LiveCBOM; supports point-in-time reconstruction."""

    def __init__(self, *, log: CbomEventLog | None = None,
                 clock: Callable[[], Any] | None = None) -> None:
        self.log = log or CbomEventLog()
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    # ------------------------------------------------------------- ingest

    def ingest(self, event_type: str, asset_id: str, *,
               snapshot: dict[str, Any] | None = None,
               change: dict[str, Any] | None = None,
               occurred_at: Any | None = None) -> CbomEvent:
        return self.log.append(event_type, asset_id, occurred_at=occurred_at,
                               snapshot=snapshot, change=change,
                               clock=self._clock)

    def ingest_report(self, report: dict[str, Any], *,
                      asset_id: str | None = None) -> list[CbomEvent]:
        """Ingest a discovery report: assets, TLS state, certs, tunnels."""
        events: list[CbomEvent] = []
        assets = report.get("assets") or []
        if not asset_id:
            for asset in assets:
                aid = str(asset.get("asset_id") or asset.get("hostname") or "")
                if aid:
                    events.append(self.ingest("ASSET_DISCOVERED", aid,
                                              snapshot=asset))
        tls_intel = report.get("tls_intelligence") or []
        for entry in tls_intel:
            endpoint = str(entry.get("endpoint") or "")
            if endpoint:
                events.append(self.ingest("TLS_CHANGED", endpoint,
                                          snapshot={"tls": dict(entry)}))
        tunnels = report.get("tunnels") or []
        for tunnel in tunnels:
            tid = str(tunnel.get("tunnel_id") or tunnel.get("endpoint_a") or "")
            if tid:
                events.append(self.ingest("VPN_CHANGED", tid,
                                          snapshot={"tunnel": dict(tunnel)}))
        return events

    # ------------------------------------------------------------- materialize

    def live(self) -> LiveCBOM:
        cbom = LiveCBOM()
        for event in self.log.events():
            cbom.apply(event)
        return cbom

    def reconstruct(self, as_of: Any) -> LiveCBOM:
        """Replay events up to and including ``as_of`` — historical CBOM."""
        cbom = LiveCBOM()
        for event in self.log.events():
            try:
                if event.occurred_at <= as_of:
                    cbom.apply(event)
            except TypeError:
                cbom.apply(event)
        return cbom

    def history(self, asset_id: str) -> list[CbomEvent]:
        return self.log.events(asset_id=asset_id)
