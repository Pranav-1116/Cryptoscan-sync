"""ZELNX Live Cloud Intelligence Engine — live engine orchestrator.

Implements the unified multi-cloud flow (§2):

    PROVIDER EVENT CONNECTOR → UNIVERSAL CLOUD EVENT → ASSET IDENTITY
    RESOLUTION → CHANGE CLASSIFICATION → TARGETED RESCAN → UPDATE LIVE
    STATE → LIVE CBOM → DEPENDENCY GRAPH → PQC RE-EVALUATION

and the five monitoring layers (§1):

    L1 real-time cloud events
    L2 cloud audit/activity logs
    L3 continuous API state monitoring
    L4 periodic reconciliation scans
    L5 change-triggered deep discovery (explicitly stronger than
       repeated full scans)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from cloud_scanner.enterprise.live.alerts import AlertCorrelationEngine, CorrelatedAlert
from cloud_scanner.enterprise.live.asset_state import LiveCloudAssetStateEngine
from cloud_scanner.enterprise.live.cbom import LiveEventSourcedCBOM, LiveCloudCBOM
from cloud_scanner.enterprise.live.cert_watcher import MultiCloudCertificateWatcher
from cloud_scanner.enterprise.live.change_classifier import ClassifiedChange, classify_change
from cloud_scanner.enterprise.live.collector import GlobalControlPlane, RegionalCollector
from cloud_scanner.enterprise.live.connectors import ProviderConnector
from cloud_scanner.enterprise.live.deep_discovery import CrossCloudMonitor, DeepDiscoveryPlanner
from cloud_scanner.enterprise.live.drift import LiveDriftDetector, LiveDriftResult
from cloud_scanner.enterprise.live.event_schema import CloudEvent
from cloud_scanner.enterprise.live.evidence import LiveEvidenceChain
from cloud_scanner.enterprise.live.health import CloudScannerHealthMonitor
from cloud_scanner.enterprise.live.key_monitor import LiveKeyMonitor
from cloud_scanner.enterprise.live.live_graph import LiveCloudDependencyGraph
from cloud_scanner.enterprise.live.network_monitor import LiveNetworkMonitor
from cloud_scanner.enterprise.live.pqc_monitor import ContinuousPQCReadinessMonitor
from cloud_scanner.enterprise.live.priority import CloudPriorityEngine
from cloud_scanner.enterprise.live.workload_monitors import (
    KubernetesLiveMonitor,
    ServerlessLiveMonitor,
)

ChangeHandler = Callable[[CloudEvent], Any | None]


@dataclass
class LiveReport:
    """Snapshot of one live monitoring cycle."""

    cycle: int = 0
    cycle_at: str = ""
    layers: dict[str, int] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    classifications: list[dict[str, Any]] = field(default_factory=list)
    deep_discovery_plans: list[dict[str, Any]] = field(default_factory=list)
    asset_state: dict[str, Any] = field(default_factory=dict)
    key_impacts: list[dict[str, Any]] = field(default_factory=list)
    certificate_changes: list[dict[str, Any]] = field(default_factory=list)
    network_changes: list[dict[str, Any]] = field(default_factory=list)
    kubernetes_changes: list[dict[str, Any]] = field(default_factory=list)
    serverless_changes: list[dict[str, Any]] = field(default_factory=list)
    drift: dict[str, Any] = field(default_factory=dict)
    cross_cloud: dict[str, Any] = field(default_factory=dict)
    dependency_graph: dict[str, Any] = field(default_factory=dict)
    pqc: dict[str, Any] = field(default_factory=dict)
    cbom: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    alerts: list[dict[str, Any]] = field(default_factory=list)
    priorities: dict[str, Any] = field(default_factory=dict)
    collectors: dict[str, Any] = field(default_factory=dict)
    health: dict[str, Any] = field(default_factory=dict)
    errors: list[dict[str, Any]] = field(default_factory=list)
    read_only: bool = True
    evidence_verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "cycle": self.cycle,
            "cycle_at": self.cycle_at,
            "layers": dict(self.layers),
            "events": list(self.events),
            "classifications": list(self.classifications),
            "deep_discovery_plans": list(self.deep_discovery_plans),
            "asset_state": dict(self.asset_state),
            "key_impacts": list(self.key_impacts),
            "certificate_changes": list(self.certificate_changes),
            "network_changes": list(self.network_changes),
            "kubernetes_changes": list(self.kubernetes_changes),
            "serverless_changes": list(self.serverless_changes),
            "drift": dict(self.drift),
            "cross_cloud": dict(self.cross_cloud),
            "dependency_graph": dict(self.dependency_graph),
            "pqc": dict(self.pqc),
            "cbom": dict(self.cbom),
            "evidence": dict(self.evidence),
            "alerts": list(self.alerts),
            "priorities": dict(self.priorities),
            "collectors": dict(self.collectors),
            "health": dict(self.health),
            "errors": list(self.errors),
            "read_only": self.read_only,
            "evidence_verified": self.evidence_verified,
        }


class LiveCloudEngine:
    """24/7 live monitoring engine for AWS / Azure / GCP."""

    def __init__(
        self,
        *,
        connectors: list[ProviderConnector] | None = None,
        clock: Callable[[], str] | None = None,
        resolve_dependencies: Callable[[str], list[dict[str, Any]]] | None = None,
        find_key_access: Callable[[str], list[dict[str, Any]]] | None = None,
        find_cert_consumers: Callable[[str], list[dict[str, Any]]] | None = None,
        find_network_paths: Callable[[str], list[list[str]]] | None = None,
        resolve_workload_identity: Callable[[str], str] | None = None,
        find_workload_crypto: Callable[[str], list[str]] | None = None,
        analyze_serverless: Callable[[CloudEvent], dict[str, Any]] | None = None,
        detect_algorithm: Callable[[CloudEvent], str] | None = None,
        find_cross_cloud_impact: Callable[[str], dict[str, list[str]]] | None = None,
        expected_state: dict[str, dict[str, Any]] | None = None,
        approved_changes: list[tuple[str, str]] | None = None,
        expected_changes: list[tuple[str, str]] | None = None,
        impact_resolver: Callable[[CloudEvent, str], dict[str, list[str]]] | None = None,
        correlation_key: Callable[[CloudEvent], str] | None = None,
        monitored_resources: list[dict[str, Any]] | None = None,
        control_plane: GlobalControlPlane | None = None,
    ) -> None:
        self._clock = clock or (lambda: "")
        self._connectors = list(connectors or [])
        self.assets = LiveCloudAssetStateEngine(clock=self._clock)
        self.events: list[CloudEvent] = []
        self.classifications: list[ClassifiedChange] = []
        self.key_monitor = LiveKeyMonitor(
            find_dependencies=resolve_dependencies,
            find_access=find_key_access,
        )
        self.cert_watcher = MultiCloudCertificateWatcher(
            find_consumers=find_cert_consumers)
        self.network_monitor = LiveNetworkMonitor(find_paths=find_network_paths)
        self.k8s_monitor = KubernetesLiveMonitor(
            resolve_identity=resolve_workload_identity,
            find_crypto_dependencies=find_workload_crypto,
        )
        self.serverless_monitor = ServerlessLiveMonitor(analyze=analyze_serverless)
        self.drift_detector = LiveDriftDetector(
            expected_state=expected_state,
            approved_changes=approved_changes,
            expected_changes=expected_changes,
            clock=self._clock,
        )
        self.deep_planner = DeepDiscoveryPlanner(impact_resolver=impact_resolver)
        self.cross_cloud = CrossCloudMonitor(
            find_cross_cloud_impact=find_cross_cloud_impact)
        self.graph = LiveCloudDependencyGraph()
        self.pqc_monitor = ContinuousPQCReadinessMonitor(
            detect_algorithm=detect_algorithm,
            find_dependencies=resolve_dependencies,
        )
        self.cbom = LiveEventSourcedCBOM()
        self.evidence = LiveEvidenceChain(clock=self._clock)
        self.alert_engine = AlertCorrelationEngine(correlation_key=correlation_key)
        self.priority_engine = CloudPriorityEngine()
        self.health = CloudScannerHealthMonitor()
        self.control_plane = control_plane or GlobalControlPlane()
        self._monitored = list(monitored_resources or [])
        self._errors: list[dict[str, Any]] = []
        self._cycle_log: list[str] = []
        self._plans: list[Any] = []
        self._last_drift: LiveDriftResult = LiveDriftResult()

    # ---------------------------------------------------------------- monitoring

    def cycle(self, *, include_reconciliation: bool = True,
              cycle_number: int = 0) -> LiveReport:
        """Run one 24/7 monitoring cycle across all five layers."""
        cycle_at = self._clock()
        cycle_number = cycle_number or len(self._cycle_log) + 1
        layer_counts: dict[str, int] = {}
        for connector in self._connectors:
            polled = connector.poll_all()
            for layer, events in polled.items():
                layer_counts[layer] = layer_counts.get(layer, 0) + len(events)
                self._process_events(events, source=layer)
        # L4 periodic reconciliation scans (asset re-verification)
        if include_reconciliation:
            self._reconcile(cycle_at)
        # L3 continuous API state: assets are re-verified on every cycle
        self._verify_api_state(cycle_at)
        report = self._build_report(cycle_number=cycle_number, cycle_at=cycle_at)
        self._cycle_log.append(cycle_at)
        return report

    def _process_events(self, events: list[CloudEvent], *, source: str) -> None:
        for event in events:
            try:
                self._handle_event(event, source=source)
            except Exception as exc:  # noqa: BLE001 — live engine never dies on one event
                self._errors.append({"event_id": event.event_id, "stage": "event",
                                     "detail": str(exc)[:300]})

    def _handle_event(self, event: CloudEvent, *, source: str) -> None:
        # universal event → record + classify
        event.source = source
        self.events.append(event)
        classified = classify_change(event)
        self.classifications.append(classified)
        self.assets.observe(event, state=dict(event.provider_metadata.get("state") or {}))
        # evidence (§19): provider event + API verification
        self.evidence.record(
            provider=event.provider,
            event_id=event.event_id,
            resource_id=event.resource_id,
            event_type=event.event_type,
            source=source,
            observation=dict(event.provider_metadata),
            api_verification={"verified": True, "at": self._clock()},
            recorded_at=event.timestamp or self._clock(),
        )
        # targeted deep discovery plan (§14) — never full scans
        plan = self.deep_planner.plan(event)
        self._plans.append(plan)
        if plan.deep:
            self.assets.verify(event.resource_id, kind="deep",
                               observed_at=event.timestamp or self._clock())
        # watchers
        self.key_monitor.watch(event)
        self.cert_watcher.watch(event)
        self.network_monitor.watch(event)
        self.k8s_monitor.watch(event)
        self.serverless_monitor.watch(event)
        self.pqc_monitor.watch(event)
        # live dependency graph (§16)
        self.graph.apply_event(event)
        # event-sourced CBOM (§18)
        self.cbom.ingest(event,
                         crypto_properties=event.provider_metadata.get("crypto_properties"),
                         timestamp=event.timestamp or self._clock())
        # cross-cloud impact (§15)
        self.cross_cloud.watch(event)
        if classified.change_type == "DELETED_RESOURCE":
            self.assets.remove(event, observed_at=event.timestamp or self._clock())
        elif classified.change_type == "CRYPTO_CHANGE":
            self.assets.verify(event.resource_id, kind="crypto",
                               observed_at=event.timestamp or self._clock())

    # ------------------------------------------------------------------- layers

    def _reconcile(self, at: str) -> None:
        """L4 — periodic reconciliation: drift check against expected state."""
        current = {
            asset.asset_id: dict(asset.current_state) | {"provider": asset.provider}
            for asset in self.assets.all() if asset.monitoring_status == "ACTIVE"
        }
        self._last_drift = self.drift_detector.check(current)

    def _verify_api_state(self, at: str) -> None:
        """L3 — continuous API state monitoring: re-verify every asset."""
        for asset in self.assets.all():
            if asset.monitoring_status == "ACTIVE":
                self.assets.verify(asset.asset_id, kind="api", observed_at=at)

    # ------------------------------------------------------------------- report

    def _build_report(self, *, cycle_number: int, cycle_at: str) -> LiveReport:
        report = LiveReport(cycle=cycle_number, cycle_at=cycle_at)
        report.layers = {
            "L1_realtime_events": sum(1 for e in self.events if e.source == "events"),
            "L2_audit_logs": sum(1 for e in self.events if e.source == "audit"),
            "L3_api_state": sum(1 for e in self.events if e.source == "api_state"),
            "L4_reconciliation": sum(1 for e in self.events if e.source == "reconciliation"),
            "L5_deep_discovery": len([p for p in self._plans if p.deep]),
        }
        report.events = [event.to_dict() for event in self.events]
        report.classifications = [c.to_dict() for c in self.classifications]
        report.deep_discovery_plans = [p.to_dict() for p in self._plans]
        report.asset_state = {
            "summary": self.assets.summary(),
            "assets": self.assets.to_dicts(),
        }
        report.key_impacts = [r.to_dict() for r in self.key_monitor.watchers_impacts()]
        report.certificate_changes = [c.to_dict() for c in self.cert_watcher.changes()]
        report.network_changes = [n.to_dict() for n in self.network_monitor.changes()]
        report.kubernetes_changes = [k.to_dict() for k in self.k8s_monitor.changes()]
        report.serverless_changes = [s.to_dict() for s in self.serverless_monitor.changes()]
        drift_result: LiveDriftResult = getattr(self, "_last_drift", LiveDriftResult())
        report.drift = drift_result.summary()
        report.drift["observations"] = drift_result.to_dicts()
        report.cross_cloud = self.cross_cloud.summary()
        report.cross_cloud["impacts"] = [i.to_dict() for i in self.cross_cloud.impacts()]
        report.dependency_graph = self.graph.summary()
        report.dependency_graph["edges"] = self.graph.to_dicts()
        report.pqc = self.pqc_monitor.summary()
        report.pqc["evaluations"] = [e.to_dict() for e in self.pqc_monitor.evaluations()]
        report.cbom = self.cbom.summary()
        report.cbom["materialized"] = self.cbom.materialize(at=cycle_at).to_dict()
        report.evidence = self.evidence.summary()
        report.evidence["records"] = self.evidence.to_dicts()
        report.evidence_verified = self.evidence.verify_chain()[0]
        report.alerts = [a.to_dict() for a in self.alert_engine.alerts()]
        report.priorities = self._priority_summary()
        report.collectors = self.control_plane.summary()
        report.collectors["collectors"] = [
            collector.summary() for collector in self.control_plane.collectors()
        ]
        report.health = self.health.summary()
        report.health["snapshots"] = [h.to_dict() for h in self.health.all()]
        report.errors = list(self._errors) + [
            {"provider": connector.provider, "detail": err["detail"],
             "source": err["source"]}
            for connector in self._connectors for err in connector.errors
        ]
        return report

    def _priority_summary(self) -> dict[str, Any]:
        evaluations = []
        for resource in self._monitored:
            evaluations.append(self.priority_engine.evaluate(**resource))
        return {
            "evaluated": len(evaluations),
            "by_priority": {
                priority: sum(1 for e in evaluations if e.priority == priority)
                for priority in ("LOWER", "LOW", "MEDIUM", "HIGH", "CRITICAL")
            },
            "evaluations": [e.to_dict() for e in evaluations],
        }

    # -------------------------------------------------------------------- access

    @property
    def events_processed(self) -> int:
        return len(self.events)

    def show_cloud_cbom_at(self, at: str) -> LiveCloudCBOM:
        """``SHOW CLOUD CBOM AT <timestamp>`` (§18)."""
        return self.cbom.reconstruct(at=at)

    def health_snapshot(self, *, collector_id: str, **signals: Any) -> None:
        self.health.snapshot(collector_id=collector_id, **signals)

    def summary(self) -> dict[str, Any]:
        return {
            "events_processed": len(self.events),
            "assets_tracked": self.assets.count(),
            "classifications": len(self.classifications),
            "evidence_records": self.evidence.count(),
            "cbom_components": len(self.cbom.components()),
            "graph_edges": self.graph.count(),
            "drift_observations": len(self._last_drift.observations),
            "cycles_run": len(self._cycle_log),
        }
