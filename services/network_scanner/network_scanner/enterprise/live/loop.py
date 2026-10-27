"""24/7 Scanner Loop orchestrator.

    START → Load Authorized Scope → Discover Assets → Create/Update Asset
    State → Monitor for Events
        ├─ New Asset?                → Scan New Asset
        ├─ Configuration Changed?    → Re-scan Crypto Configuration
        ├─ Certificate Changed?      → Rebuild Certificate Dependencies
        ├─ Network Topology Changed? → Update Graph
        └─ No Change?                → Continue Monitoring

The monitor NEVER restarts its entire scan because one asset changed —
changes trigger targeted rescans scoped to the impacted assets only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

from network_scanner.enterprise.live.alerts import AlertEngine
from network_scanner.enterprise.live.asset_state import (
    AssetStateEngine,
)
from network_scanner.enterprise.live.cbom import CbomMaterializer
from network_scanner.enterprise.live.cert_watcher import CertificateWatcher
from network_scanner.enterprise.live.drift import DriftDetector
from network_scanner.enterprise.live.events import (
    AssetIdentification,
    EventNormalizer,
    ImpactAnalysis,
)
from network_scanner.enterprise.live.evidence import EvidenceChain
from network_scanner.enterprise.live.health import ScannerHealthMonitor
from network_scanner.enterprise.live.modes import (
    MONITORING_MODES,
    MonitoringPolicy,
    enabled_modes,
)
from network_scanner.enterprise.live.passive_monitor import PassiveMonitor
from network_scanner.enterprise.live.scheduler import Scheduler, ScheduledItem
from network_scanner.enterprise.live.tls_watcher import TlsWatcher
from network_scanner.enterprise.live.topology_monitor import TopologyMonitor


@dataclass
class CycleResult:
    """One cycle of the 24/7 loop — everything that happened."""

    cycle: int
    scanned_assets: list[str] = field(default_factory=list)
    targeted_rescans: list[str] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    transitions: list[dict[str, Any]] = field(default_factory=list)
    tls_changes: list[dict[str, Any]] = field(default_factory=list)
    cert_changes: list[dict[str, Any]] = field(default_factory=list)
    topology_changes: list[dict[str, Any]] = field(default_factory=list)
    drift: list[dict[str, Any]] = field(default_factory=list)
    passive_observations: list[dict[str, Any]] = field(default_factory=list)
    pqc_re_evaluations: list[dict[str, Any]] = field(default_factory=list)
    alerts: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    cbom_events: list[dict[str, Any]] = field(default_factory=list)
    deep_scans: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"cycle": self.cycle,
                "scanned_assets": list(self.scanned_assets),
                "targeted_rescans": list(self.targeted_rescans),
                "events": list(self.events),
                "transitions": list(self.transitions),
                "tls_changes": list(self.tls_changes),
                "cert_changes": list(self.cert_changes),
                "topology_changes": list(self.topology_changes),
                "drift": list(self.drift),
                "passive_observations": list(self.passive_observations),
                "pqc_re_evaluations": list(self.pqc_re_evaluations),
                "alerts": list(self.alerts),
                "evidence": list(self.evidence),
                "cbom_events": list(self.cbom_events),
                "deep_scans": list(self.deep_scans)}


ScanFn = Callable[[list[str], str], dict[str, Any]]
PqcEvaluator = Callable[[dict[str, Any]], dict[str, Any]]


def _default_pqc_evaluator(snapshot: dict[str, Any]) -> dict[str, Any]:
    algorithms = snapshot.get("algorithms") or []
    if isinstance(algorithms, str):
        algorithms = [algorithms]
    return {"pqc_status": snapshot.get("pqc_status", "NOT_ASSESSED"),
            "algorithms_assessed": list(algorithms),
            "re_evaluated": True}


class LiveNetworkMonitor:
    """The 24/7 live monitoring loop.

    Every I/O boundary is injectable: ``scan_fn`` performs discovery,
    ``options["events"]`` supplies the raw event stream, and each engine
    component can be replaced for tests.
    """

    def __init__(
        self,
        *,
        scope_specs: Iterable[str] | None = None,
        scan_fn: ScanFn | None = None,
        options: dict[str, Any] | None = None,
        state: AssetStateEngine | None = None,
        scheduler: Scheduler | None = None,
        drift: DriftDetector | None = None,
        tls_watcher: TlsWatcher | None = None,
        cert_watcher: CertificateWatcher | None = None,
        topology: TopologyMonitor | None = None,
        passive: PassiveMonitor | None = None,
        event_normalizer: EventNormalizer | None = None,
        identification: AssetIdentification | None = None,
        impact: ImpactAnalysis | None = None,
        evidence: EvidenceChain | None = None,
        cbom: CbomMaterializer | None = None,
        alerts: AlertEngine | None = None,
        health: ScannerHealthMonitor | None = None,
        pqc_evaluator: PqcEvaluator | None = None,
        policy: MonitoringPolicy | None = None,
        clock: Callable[[], Any] | None = None,
    ) -> None:
        self.scope_specs = list(scope_specs or [])
        self._scan_fn = scan_fn
        self._options = dict(options or {})
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self.state = state or AssetStateEngine(clock=self._clock)
        self.scheduler = scheduler or Scheduler(policy=policy or MonitoringPolicy(),
                                                clock=self._clock)
        self.drift = drift or DriftDetector()
        self.tls_watcher = tls_watcher or TlsWatcher(clock=self._clock)
        self.cert_watcher = cert_watcher or CertificateWatcher(clock=self._clock)
        self.topology = topology or TopologyMonitor(clock=self._clock)
        self.passive = passive or PassiveMonitor(clock=self._clock)
        self.event_normalizer = event_normalizer or EventNormalizer(clock=self._clock)
        self.identification = identification or AssetIdentification()
        self.impact = impact or ImpactAnalysis()
        self.evidence = evidence or EvidenceChain(clock=self._clock)
        self.cbom = cbom or CbomMaterializer(clock=self._clock)
        self.alerts = alerts or AlertEngine(clock=self._clock)
        self.health = health or ScannerHealthMonitor(clock=self._clock)
        self._pqc = pqc_evaluator or _default_pqc_evaluator
        self._items: dict[str, ScheduledItem] = {}
        self._results: list[CycleResult] = []
        self._cycle = 0
        self._baseline_topology_seen = False
        self._cycle_crypto_changed: set[str] = set()

    # ------------------------------------------------------------- cycle

    def cycle(self, *, now: Any | None = None) -> CycleResult:
        self._cycle += 1
        now = now if now is not None else self._clock()
        result = CycleResult(cycle=self._cycle)
        self._cycle_crypto_changed = set()
        self.health.heartbeat(now=now)

        # MODE 2 — passive observations first (no probing)
        for observation in self.passive.poll(now=now):
            result.passive_observations.append(observation.to_dict())
            self.cbom.ingest("ASSET_UPDATED", observation.asset,
                             snapshot={"passive": observation.to_dict()},
                             occurred_at=now)

        # MODES 3+4 — periodic lightweight + scheduled deep scans
        self._run_scheduled_scans(result, now=now)

        # MODE 1+5 — event-driven targeted rescans
        self._drain_events(result, now=now)

        # drift / evidence / CBOM / PQC / alerts for what changed
        self._finalize(result, now=now)
        self._results.append(result)
        return result

    def _run_scheduled_scans(self, result: CycleResult, *, now: Any) -> None:
        if not self.scope_specs:
            return
        items = list(self._items.values())
        if not items:
            self._full_scan(result, now=now)
            return
        for asset_id in self.scheduler.due_assets(items, now=now):
            self._targeted_scan([asset_id], result, deep=False, now=now)
        for asset_id in self.scheduler.deep_due_assets(items, now=now):
            result.deep_scans.append(asset_id)
            self._targeted_scan([asset_id], result, deep=True, now=now)

    def _full_scan(self, result: CycleResult, *, now: Any) -> None:
        if self._scan_fn is None:
            return
        report = self._scan(self.scope_specs, "LIGHTWEIGHT")
        for asset in report.get("assets") or []:
            self._register_asset(asset, result, now=now, deep=True)
        self._apply_crypto_report(report, result, now=now)
        self.health.mark_scan_success(now=now)
        result.scanned_assets.extend(list(self._items.keys()))

    def _scan(self, scope_specs: list[str], mode: str) -> dict[str, Any]:
        if self._scan_fn is None:
            return {}
        # translate live-loop scan labels to engine scan modes:
        # LIGHTWEIGHT → SAFE (periodic lightweight), DEEP → DEEP (targeted)
        engine_mode = "SAFE" if mode != "DEEP" else "DEEP"
        return self._scan_fn(scope_specs, engine_mode) or {}

    def _register_asset(self, asset: dict[str, Any], result: CycleResult,
                        *, now: Any, deep: bool = False) -> str | None:
        asset_id = str(asset.get("asset_id") or asset.get("hostname")
                       or asset.get("ip") or "").strip()
        if not asset_id:
            return None
        transition = self.state.observe(asset_id, asset, deep=deep, now=now)
        result.transitions.append(transition.to_dict())
        if transition.crypto_changed:
            self._cycle_crypto_changed.add(asset_id)
        self.identification.register(asset_id, asset)
        def _num(value: Any, default: float = 0.0) -> float:
            try:
                return float(value) if value not in (None, "") else default
            except (TypeError, ValueError):
                return default

        risk = {
            "business_criticality": _num(asset.get("criticality")),
            "internet_exposure": 1.0 if asset.get("internet_exposed") else 0.0,
            "crypto_risk": _num(asset.get("crypto_risk")),
            "change_frequency": _num(asset.get("change_frequency")),
            "compliance_importance": _num(asset.get("compliance_importance")),
        }
        item = self.scheduler.schedule(asset_id, risk, last_scanned=now,
                                       last_deep_scan=now if deep else None)
        self._items[asset_id] = item
        event_type = "ASSET_DISCOVERED" if transition.kind == "FIRST_SEEN" else "ASSET_UPDATED"
        cbom_event = self.cbom.ingest(event_type, asset_id,
                                      snapshot=dict(asset), occurred_at=now)
        result.cbom_events.append(cbom_event.to_dict())
        return asset_id

    def _apply_crypto_report(self, report: dict[str, Any], result: CycleResult,
                             *, now: Any) -> None:
        for entry in report.get("tls_intelligence") or []:
            endpoint = str(entry.get("endpoint") or "")
            if not endpoint:
                continue
            change = self.tls_watcher.observe(endpoint, dict(entry))
            if change is not None:
                result.tls_changes.append(change.to_dict())
                self.cbom.ingest("TLS_CHANGED", endpoint,
                                 snapshot={"tls": dict(entry)}, occurred_at=now)
                if change.alert:
                    self._raise_drift_alert(endpoint, change)
        for cert in (report.get("certificates")
                     or report.get("evidence", {}).get("certificates") or []):
            for change in self.cert_watcher.observe(cert, now=now):
                result.cert_changes.append(change.to_dict())
                self.cbom.ingest("CERTIFICATE_CHANGED", change.fingerprint,
                                 snapshot={"certificate": dict(cert)},
                                 change={"kind": change.kind}, occurred_at=now)
        topology = report.get("topology")
        if topology and not self._baseline_topology_seen:
            self.topology.observe(topology, now=now)
            self._baseline_topology_seen = True
        elif topology:
            for change in self.topology.observe(topology, now=now):
                result.topology_changes.append(change.to_dict())

    def _drain_events(self, result: CycleResult, *, now: Any) -> None:
        for raw_event in self._options.get("events") or []:
            event = self.event_normalizer.normalize(raw_event)
            if event is None:
                continue
            event = self.identification.identify(event)
            impact = self.impact.analyze(event)
            result.events.append({"event": event.to_dict(), "impact": impact})
            self.evidence.append({"kind": "network_event",
                                  "event": event.to_dict()})
            # targeted rescan only — never a full restart
            for asset_id in impact["impacted_assets"]:
                self._targeted_scan([asset_id], result,
                                    deep=impact["targeted_scan_mode"] == "DEEP",
                                    now=now)
                result.targeted_rescans.append(asset_id)

    def _targeted_scan(self, asset_ids: list[str], result: CycleResult, *,
                       deep: bool, now: Any) -> None:
        if self._scan_fn is None:
            return
        report = self._scan(asset_ids, "DEEP" if deep else "LIGHTWEIGHT")
        for asset in report.get("assets") or []:
            self._register_asset(asset, result, now=now)
        self._apply_crypto_report(report, result, now=now)

    # ------------------------------------------------------------- finalize

    def _finalize(self, result: CycleResult, *, now: Any) -> None:
        # PQC re-evaluation on every crypto change this cycle
        for asset_id in sorted(self._cycle_crypto_changed):
            state = self.state.get(asset_id)
            if state is None:
                continue
            evaluation = self._pqc(dict(state.current))
            result.pqc_re_evaluations.append({"asset_id": asset_id, **evaluation})
        incidents = self.alerts.drain(correlate=True)
        result.alerts.extend(incident.to_dict() for incident in incidents)
        self.health.tick(now=now)

    def _raise_drift_alert(self, endpoint: str, change: Any) -> None:
        self.alerts.raise_alert(
            severity="CRITICAL",
            title=f"CRYPTO DRIFT on {endpoint}",
            what_changed=", ".join(change.changed_fields),
            where=endpoint,
            evidence=list(change.drift),
            impact="TLS posture degraded below policy",
            dependencies=[endpoint],
            recommended_action="Re-apply the approved TLS policy to this endpoint",
            correlation_key=f"tls-drift:{endpoint}",
            source="tls_watcher")

    # ------------------------------------------------------------- report

    def report(self) -> dict[str, Any]:
        return {
            "monitoring": {
                "modes": list(MONITORING_MODES),
                "enabled_modes": enabled_modes(self._options.get("mode_overrides")),
                "scope_specs": list(self.scope_specs),
                "policy": self.scheduler.policy.to_dict(),
                "cycles_run": self._cycle,
            },
            "assets": self.state.to_dicts(),
            "scheduler": self.scheduler.summarize(list(self._items.values())),
            "tls_snapshot": self.tls_watcher.snapshot(),
            "topology_changes": [c.to_dict() for c in self.topology.changes()],
            "passive_observations": self.passive.to_dicts(),
            "evidence": self.evidence.to_dicts(),
            "evidence_verified": self.evidence.verify(),
            "cbom": self.cbom.live().summary(),
            "alerts": self.alerts.to_dicts(),
            "health": self.health.report(),
            "cycles": [r.to_dict() for r in self._results],
        }

    def run(self, *, cycles: int = 1,
            stop: Callable[[], bool] | None = None,
            now: Any | None = None) -> list[CycleResult]:
        """Run the loop synchronously for ``cycles`` iterations."""
        results: list[CycleResult] = []
        for _ in range(cycles):
            if stop is not None and stop():
                break
            results.append(self.cycle(now=now))
        return results
