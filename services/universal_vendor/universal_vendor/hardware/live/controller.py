"""LiveHardwareController — the LIVE HARDWARE ENGINE (24/7 spec).

    Agent Telemetry / Management APIs / Passive Events
        → Hardware Event Bus
        → Hardware Identity Engine
        → Live Hardware State
        → (NEW DEVICE | DEVICE CHANGE | DEVICE REMOVED)
        → Targeted Re-Discovery
        → Hardware Crypto Analysis
        → Firmware Analysis
        → Drift Engine
        → Evidence Engine
        → Live HBOM + Live CBOM
        → Crypto Dependency Graph
        → PQC Readiness Engine
        → Risk / Alert / Governance

One controller wires the deterministic pipeline: events → identity →
classification → impact → targeted scan plan → state → evidence chain →
versioned HBOM → timeline → drift → risk recalc → correlated alerts →
PQC impact. Heartbeats (§4) and edge sync (§21) plug in alongside.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Optional

from universal_vendor.evidence import build_evidence_chain, verify_evidence_chain
from universal_vendor.hardware.firmware import FirmwareIntelligence
from universal_vendor.hardware.hbom import HbomGenerator
from universal_vendor.hardware.live.events import (
    HardwareEvent,
    HardwareEventBus,
    HardwareEventPipeline,
    HardwareEventType,
)
from universal_vendor.hardware.live.discovery_router import LiveDiscoveryRouter
from universal_vendor.hardware.live.heartbeat import AgentHeartbeatEngine
from universal_vendor.hardware.live.pqc_impact import HardwarePqcImpactEngine
from universal_vendor.hardware.live.reaction import ChangeReactionPlanner
from universal_vendor.hardware.live.state import HardwareStateEngine
from universal_vendor.hardware.live.timeline import HardwareTimeline
from universal_vendor.hardware.alert import HardwareAlertCorrelator
from universal_vendor.hardware.risk import HardwareRiskEngine, HardwareRiskScore


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class LiveHardwareController:
    """24/7 live hardware engine — event-driven, stateful, targeted."""

    def __init__(
        self,
        *,
        state: Optional[HardwareStateEngine] = None,
        bus: Optional[HardwareEventBus] = None,
        pipeline: Optional[HardwareEventPipeline] = None,
        planner: Optional[ChangeReactionPlanner] = None,
        heartbeats: Optional[AgentHeartbeatEngine] = None,
        timeline: Optional[HardwareTimeline] = None,
        hbom: Optional[HbomGenerator] = None,
        firmware: Optional[FirmwareIntelligence] = None,
        drift: Optional[Any] = None,
        risk: Optional[HardwareRiskEngine] = None,
        alerts: Optional[HardwareAlertCorrelator] = None,
        pqc: Optional[HardwarePqcImpactEngine] = None,
        correlation: Optional[Any] = None,
        discovery_router: Optional[LiveDiscoveryRouter] = None,
        evidence_scan_id: str = "live-hardware",
        risk_hook: Optional[Callable[[str, HardwareRiskScore], None]] = None,
    ) -> None:
        self.state = state or HardwareStateEngine()
        self.bus = bus or HardwareEventBus()
        self.planner = planner or ChangeReactionPlanner()
        self.pipeline = pipeline or HardwareEventPipeline(identity=None,
                                                          reaction_planner=self.planner)
        self.heartbeats = heartbeats or AgentHeartbeatEngine()
        self._timeline = timeline or HardwareTimeline()
        self.hbom = hbom or HbomGenerator()
        self.firmware = firmware or FirmwareIntelligence()
        self.drift = drift
        self.risk = risk or HardwareRiskEngine()
        self.alerts = alerts or HardwareAlertCorrelator()
        self.pqc = pqc or HardwarePqcImpactEngine()
        self.correlation = correlation
        self.discovery_router = discovery_router or LiveDiscoveryRouter()
        self.evidence_scan_id = evidence_scan_id
        self._risk_hook = risk_hook
        self._evidence: list[dict[str, Any]] = []
        self._risk_scores: dict[str, HardwareRiskScore] = {}
        self._targeted_plans: list[dict[str, Any]] = []
        self._event_count = 0
        self._chain_valid = True

    # ── §2/§6 event ingestion ─────────────────────────────────────────

    def ingest(self, event: HardwareEvent | dict[str, Any]) -> dict[str, Any]:
        """Ingest one hardware event and run the full live pipeline.

        Returns the event envelope with classification, impact, targeted
        plan, state verdict, evidence id and risk delta.
        """
        if isinstance(event, dict):
            event = HardwareEvent(**event)
        self._event_count += 1
        envelope = self.pipeline.process(event)
        self.bus.emit(event)

        # live state (§3/§16)
        verdict = self.state.apply_event(event.to_state_event(),
                                         timestamp=event.observed_at)

        # evidence chain (§17)
        evidence = self._append_evidence(envelope, verdict)
        chain_ok = verify_evidence_chain(self._evidence, scan_id=self.evidence_scan_id)
        self._chain_valid = bool(chain_ok.get("valid", chain_ok.get("verified", True)))

        # timeline (§16)
        state_event = event.to_state_event()
        state_event["observed_at"] = event.observed_at
        self._timeline.record(state_event)

        # firmware intelligence (§7)
        if event.component and event.version:
            self.firmware.set_context(source=event.source, evidence_id=evidence["evidence_id"])
            self.firmware.observe(asset_id=envelope.asset_id,
                                  component=event.component, version=event.version)

        # live HBOM versioning (§15) — every change produces a new state
        if verdict in ("NEW", "CHANGED", "REMOVED"):
            self.hbom.snapshot(reason=f"{event.event_type.value}:{event.asset_id}")

        # drift (§14)
        drift_result = None
        if self.drift is not None:
            drift_result = self.drift.evaluate(envelope.asset_id,
                                               self.state.get(envelope.asset_id).to_dict()
                                               if self.state.get(envelope.asset_id) else {})

        # risk recalculation (§19)
        risk_delta = None
        if verdict in ("NEW", "CHANGED", "REMOVED"):
            risk_delta = self._reassess_risk(envelope.asset_id, event)

        # alert correlation (§20): one root incident per asset — every
        # change event collapses under a single HARDWARE_CHANGE root while
        # discovery gets its own root; no alert storms.
        root_type = ("HARDWARE_DISCOVERED" if envelope.change_class == "NEW_DISCOVERY"
                     else "HARDWARE_CHANGE")
        incident = self.alerts.report(
            root_asset_id=envelope.asset_id,
            root_type=root_type,
            event_type=event.event_type.value,
            detail={"change_class": envelope.change_class,
                    "impact": envelope.impact},
        )

        # PQC impact (§18)
        pqc_assessment = None
        if envelope.impact.get("pqc_affected"):
            pqc_assessment = self.pqc.assess(
                asset_id=envelope.asset_id,
                manufacturer=event.manufacturer or "",
                model=event.model or "",
                version=event.version,
                hardware_change_type=event.event_type.value,
                declared_capability=_pqc_capability(event),
            )

        plan = self.planner.plan(
            event_type=event.event_type.value,
            change_class=envelope.change_class,
            asset_id=envelope.asset_id,
            payload=event.payload,
        )
        self._targeted_plans.append({
            "timestamp": event.observed_at, "asset_id": envelope.asset_id,
            "event_type": event.event_type.value, "plan": plan,
        })

        # §12: NIC hardware change -> affected network relationships
        network_relationships = None
        if event.event_type.value in ("NIC_CHANGED",) and self.correlation is not None:
            network_relationships = self._network_relationships(envelope.asset_id)

        return {
            "envelope": envelope.to_dict(),
            "state_verdict": verdict,
            "evidence_id": evidence["evidence_id"],
            "chain_hash": evidence["chain_hash"],
            "hbom_version": self.hbom.current_version(),
            "drift": drift_result,
            "risk": risk_delta,
            "incident": incident,
            "pqc_assessment": pqc_assessment,
            "targeted_plan": plan,
            "network_relationships": network_relationships,
        }

    # ── §4 heartbeats ─────────────────────────────────────────────────

    def ingest_heartbeat(self, *, agent_id: str, **fields: Any) -> dict[str, Any]:
        """Central heartbeat ingestion; returns the health record."""
        record = self.heartbeats.heartbeat(agent_id, **fields)
        return {"heartbeat": record.to_dict(),
                "agent_status": self.heartbeats.agent_status(agent_id)}

    def evaluate_agents(self, *, now: Optional[str] = None) -> list[dict[str, Any]]:
        """HEARTBEAT LOST → AGENT_UNAVAILABLE → ALERT (never hardware removal)."""
        return self.heartbeats.evaluate(now=now)

    # ── §16 timeline ──────────────────────────────────────────────────

    def state_at(self, asset_id: str, at: str) -> Optional[dict[str, Any]]:
        """'Show hardware state at <time>' — journal replay (§16)."""
        return self._timeline.state_at(asset_id, at)

    def timeline(self, asset_id: Optional[str] = None) -> list[dict[str, Any]]:
        return self._timeline.timeline(asset_id)

    # ── query surfaces ────────────────────────────────────────────────

    def live_state(self, asset_id: Optional[str] = None) -> list[dict[str, Any]]:
        states = [self.state.get(asset_id)] if asset_id else self.state.all()
        return [s.to_dict() for s in states if s is not None]

    def hbom_versions(self) -> list[dict[str, Any]]:
        return self.hbom.version_history()

    def incidents(self) -> list[dict[str, Any]]:
        return self.alerts.incidents()

    def targeted_plans(self) -> list[dict[str, Any]]:
        return list(self._targeted_plans)

    def evidence(self) -> list[dict[str, Any]]:
        return list(self._evidence)

    def evidence_valid(self) -> bool:
        """Verify the whole evidence chain live (tamper check on query)."""
        check = verify_evidence_chain(self._evidence, scan_id=self.evidence_scan_id)
        self._chain_valid = bool(check.get("valid", check.get("verified", False)))
        return self._chain_valid

    def risk_score(self, asset_id: str) -> Optional[dict[str, Any]]:
        score = self._risk_scores.get(asset_id)
        return score.to_dict() if score else None

    def agent_health(self, agent_id: Optional[str] = None) -> list[dict[str, Any]]:
        if agent_id:
            return [self.heartbeats.health(agent_id)]
        return self.heartbeats.agents()

    def event_count(self) -> int:
        return self._event_count

    # ── §5/§6 targeted re-discovery ───────────────────────────────────

    def rediscover(self, *, asset_id: str, device_type: str,
                   event_type: str = "HARDWARE_CHANGED",
                   context: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Change-triggered targeted re-discovery (§6).

        Plans the minimal required actions for the event, executes ONLY the
        §5 mechanism appropriate for the device type, and ingests whatever
        the targeted discovery observed. Unrelated subsystems are never
        touched.
        """
        plan = self.planner.plan(event_type=event_type, asset_id=asset_id)
        outcome = self.discovery_router.execute(
            device_type=device_type, context=context or {}, asset_id=asset_id)
        ingested = []
        for raw in outcome.get("observations", []):
            # targeted re-discovery: the caller knows which asset changed (§6);
            # the mechanism may report a different identity (e.g. DMI serial),
            # which is carried as the serial_reference, never as the asset key.
            event = HardwareEvent(
                event_type=HardwareEventType.HARDWARE_CHANGED,
                asset_id=asset_id,
                manufacturer=raw.get("manufacturer"),
                model=raw.get("model"),
                serial_reference=str(raw.get("serial_reference")
                                     or raw.get("asset_id") or ""),
                device_type=str(raw.get("device_type") or device_type),
                source=str(raw.get("source") or "rediscovery"),
                payload=raw,
            )
            ingested.append(self.ingest(event))
            # §6 example: BIOS verification updates the firmware state —
            # discovery mechanisms report firmware as a version string.
            firmware_version = raw.get("firmware")
            if isinstance(firmware_version, str) and firmware_version:
                component = "BIOS" if outcome["mechanism"] == "agent_dmi_smbios_pci" \
                    else "FIRMWARE"
                ingested.append(self.ingest(HardwareEvent(
                    event_type=HardwareEventType.FIRMWARE_CHANGED,
                    asset_id=asset_id,
                    component=component, version=firmware_version,
                    source=str(raw.get("source") or "rediscovery"),
                )))
        return {"plan": plan, "mechanism": outcome["mechanism"],
                "blocked": outcome.get("blocked", False),
                "passive_only": outcome.get("passive_only", False),
                "observations": len(outcome.get("observations", [])),
                "ingested": ingested}

    def run_monitor(self, monitor: Any) -> list[dict[str, Any]]:
        """Bridge the LiveHardwareMonitor sources into the live engine:
        Agent Telemetry / Management APIs / Passive Events → Event Bus."""
        results = []
        for raw in monitor.collect():
            try:
                event = HardwareEvent(**raw) if isinstance(raw, dict) else raw
            except Exception:
                continue
            results.append(self.ingest(event))
        return results

    def _network_relationships(self, asset_id: str) -> list[dict[str, Any]]:
        """§12 — network devices/paths affected by this hardware change."""
        method = getattr(self.correlation, "network_relationships", None)
        if method is not None:
            try:
                return method(asset_id)
            except Exception:
                return []
        return []

    # ── internals ─────────────────────────────────────────────────────

    def _append_evidence(self, envelope, verdict: str) -> dict[str, Any]:
        observation = {
            "event_type": envelope.event.event_type.value,
            "asset_id": envelope.asset_id,
            "change_class": envelope.change_class,
            "state_verdict": verdict,
            "observed_at": envelope.event.observed_at,
            "payload": envelope.event.payload,
        }
        previous_hash = self._evidence[-1]["chain_hash"] if self._evidence else None
        chain = build_evidence_chain([observation], scan_id=self.evidence_scan_id,
                                     start_index=len(self._evidence),
                                     previous_hash=previous_hash)
        record = chain[0]
        self._evidence.append(record)
        return record

    def _reassess_risk(self, asset_id: str, event: HardwareEvent) -> dict[str, Any]:
        state = self.state.get(asset_id)
        score = self.risk.assess(
            asset_id=asset_id,
            hardware_criticality=_criticality(state.device_type if state else ""),
            firmware_state=_firmware_state(state.firmware if state else {}),
            pqc_capability=_pqc_capability(event),
        )
        previous = self._risk_scores.get(asset_id)
        self._risk_scores[asset_id] = score
        if self._risk_hook is not None:
            self._risk_hook(asset_id, score)
        delta = None
        if previous is not None:
            delta = score.score - previous.score
        return {"asset_id": asset_id, "score": score.score, "level": score.level,
                "delta": delta}


def _criticality(device_type: str) -> str:
    if device_type in ("hsm", "tpm", "secure_element", "firewall", "smart_card"):
        return "critical"
    if device_type in ("server", "blade_server", "rack_server", "san", "nas",
                       "raid_controller", "hypervisor_host"):
        return "high"
    return "medium"


def _firmware_state(firmware: dict[str, str]) -> str:
    if not firmware:
        return "unknown"
    return "current"  # state engine stores observed versions; aging is drift's job


def _pqc_capability(event: HardwareEvent) -> str:
    caps = event.crypto_capabilities or {}
    if caps.get("pqc_hybrid") is True:
        return "SUPPORTED"
    if caps.get("pqc_hybrid") is False:
        return "NOT_SUPPORTED"
    hsm = event.hsm or {}
    return str(hsm.get("pqc_capability") or caps.get("pqc_capability") or "UNKNOWN").upper()
