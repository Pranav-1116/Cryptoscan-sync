"""ZELNX Live Hardware Engine — 24/7 live hardware state (spec §1–§22).

Event-driven, stateful hardware monitoring: universal hardware events (§2),
live state engine (§3), agent heartbeats (§4), change-triggered targeted
re-discovery (§6), firmware/TPM/HSM monitoring (§7–§9), crypto capability
records (§10), correlation (§11–§13), drift (§14), versioned live HBOM
(§15), historical timeline (§16), evidence chain (§17), PQC impact (§18),
live risk (§19), alert correlation (§20), edge durability (§21), safety
(§22 — see universal_vendor.hardware.safety).

Everything is deterministic and catalog-driven — no AI, no learned models.
"""

from __future__ import annotations

# backward-compatible surface (the original live.py module)
from universal_vendor.hardware.live.state import (
    LiveHardwareMonitor,
    HardwareStateEngine,
    HardwareDriftEngine,
    _HARDWARE_EVENT_TYPES,
)

from universal_vendor.hardware.live.events import (
    HardwareEvent,
    HardwareEventBus,
    HardwareEventEnvelope,
    HardwareEventPipeline,
    HardwareEventType,
    classify_change,
    analyze_impact,
    canonical_event_types,
    normalize_event_type,
)
from universal_vendor.hardware.live.heartbeat import (
    AgentHeartbeatEngine,
    HeartbeatRecord,
    AgentHealth,
    AgentStatus,
)
from universal_vendor.hardware.live.reaction import ChangeReactionPlanner
from universal_vendor.hardware.live.discovery_router import (
    LiveDiscoveryRouter,
    discovery_mechanism,
)
from universal_vendor.hardware.live.timeline import HardwareTimeline
from universal_vendor.hardware.live.edge import (
    EdgeHardwareAgent,
    EdgeHardwareQueue,
    EdgeEvidenceStore,
)
from universal_vendor.hardware.live.pqc_impact import HardwarePqcImpactEngine
from universal_vendor.hardware.live.controller import LiveHardwareController

__all__ = [
    "LiveHardwareMonitor",
    "HardwareStateEngine",
    "HardwareDriftEngine",
    "HardwareEvent",
    "HardwareEventBus",
    "HardwareEventEnvelope",
    "HardwareEventPipeline",
    "HardwareEventType",
    "classify_change",
    "analyze_impact",
    "canonical_event_types",
    "normalize_event_type",
    "AgentHeartbeatEngine",
    "HeartbeatRecord",
    "AgentHealth",
    "AgentStatus",
    "ChangeReactionPlanner",
    "LiveDiscoveryRouter",
    "discovery_mechanism",
    "HardwareTimeline",
    "EdgeHardwareAgent",
    "EdgeHardwareQueue",
    "EdgeEvidenceStore",
    "HardwarePqcImpactEngine",
    "LiveHardwareController",
]
