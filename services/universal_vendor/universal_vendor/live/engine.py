"""LiveVendorEngine — the 24/7 orchestrator.

Wires the whole live architecture into one loop:

    vendor connectors → event gateway → normalizer → identity resolver →
    live asset state → (new/changed/removed asset) → targeted vendor scan →
    crypto analysis → evidence generation → live vendor CBOM →
    universal dependency graph → PQC/risk/compliance → alert/simulation.

Ticks are incremental and safe to call repeatedly (24/7 without load).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from universal_vendor.live.cbom import LiveCbom
from universal_vendor.live.cert_watcher import UniversalCertificateWatcher
from universal_vendor.live.correlation import CorrelationEngine
from universal_vendor.live.drift import CryptoDriftEngine
from universal_vendor.live.events import EventGateway, UniversalVendorEvent
from universal_vendor.live.fingerprint import ConfigFingerprintTracker
from universal_vendor.live.firmware import FirmwareMonitor
from universal_vendor.live.health import HealthMonitor
from universal_vendor.live.identity import AssetIdentityResolver
from universal_vendor.live.monitoring import LiveVendorMonitor
from universal_vendor.live.pqc_live import LivePqcMonitor
from universal_vendor.live.state import LiveAssetStateEngine
from universal_vendor.scan_modes import UniversalVendorScanner
from universal_vendor.lifecycle import VendorLifecycleDatabase
from universal_vendor.pqc_readiness import PqcReadinessDatabase


class LiveVendorEngine:
    """One loop: collect → normalize → resolve → state → CBOM → graph → PQC."""

    def __init__(
        self,
        *,
        monitor: Optional[LiveVendorMonitor] = None,
        gateway: Optional[EventGateway] = None,
        identity: Optional[AssetIdentityResolver] = None,
        state: Optional[LiveAssetStateEngine] = None,
        cbom: Optional[LiveCbom] = None,
        correlation: Optional[CorrelationEngine] = None,
        fingerprints: Optional[ConfigFingerprintTracker] = None,
        drift: Optional[CryptoDriftEngine] = None,
        cert_watcher: Optional[UniversalCertificateWatcher] = None,
        firmware: Optional[FirmwareMonitor] = None,
        pqc: Optional[LivePqcMonitor] = None,
        health: Optional[HealthMonitor] = None,
        scanner: Optional[UniversalVendorScanner] = None,
        lifecycle_db: Optional[VendorLifecycleDatabase] = None,
        pqc_db: Optional[PqcReadinessDatabase] = None,
    ) -> None:
        self.monitor = monitor or LiveVendorMonitor()
        self.gateway = gateway or EventGateway()
        self.identity = identity or AssetIdentityResolver()
        self.state = state or LiveAssetStateEngine()
        self.cbom = cbom or LiveCbom()
        self.correlation = correlation or CorrelationEngine()
        self.fingerprints = fingerprints or ConfigFingerprintTracker()
        self.drift = drift or CryptoDriftEngine()
        self.cert_watcher = cert_watcher or UniversalCertificateWatcher()
        self.firmware = firmware or FirmwareMonitor()
        self.lifecycle_db = lifecycle_db or VendorLifecycleDatabase()
        self.pqc_db = pqc_db or PqcReadinessDatabase()
        self.pqc = pqc or LivePqcMonitor(pqc_db=self.pqc_db,
                                         lifecycle_db=self.lifecycle_db)
        self.health = health or HealthMonitor()
        self.scanner = scanner
        self._tick_count = 0

    def tick(self, *, deep_scan: bool = True) -> dict[str, Any]:
        """One incremental pass. Returns per-stage outcomes."""
        self._tick_count += 1

        # 1. collect from live connectors (§1)
        events = self.monitor.collect()
        for event in events:
            self.gateway.ingest(event)
            self._apply_event(event, deep_scan=deep_scan)

        # 2. ingest any events already in the gateway (e.g. offline sync)
        for event in self.gateway.events():
            self._apply_event(event, deep_scan=deep_scan)

        # 3. fingerprint + drift pass over monitored configs
        drift_results = []
        for asset_id, snapshot in self.monitor.snapshots().items():
            if snapshot:
                drift_results.append(self.drift.evaluate(asset_id, snapshot))

        return {
            "tick": self._tick_count,
            "events_processed": len(events),
            "state_assets": self.state.count(),
            "cbom_version": self.cbom.version(),
            "cbom_components": len(self.cbom.components()),
            "graph_nodes": self.correlation.graph.node_count(),
            "graph_edges": self.correlation.graph.edge_count(),
            "drift_results": [d.to_dict() for d in drift_results],
            "health": [h.to_dict() for h in self.health.all()],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def _apply_event(self, event: UniversalVendorEvent, *, deep_scan: bool) -> None:
        # resolve identity → asset state → CBOM → dependency graph node (§17)
        outcome = self.state.apply(event)
        self.cbom.materialize(event)
        asset_id = event.asset_id or f"{event.vendor}:{event.product}"
        self.correlation.graph.add_node(
            asset_id,
            vendor=event.vendor, product=event.product,
            asset_type=event.asset_type,
        )
        self.identity.register_identity(
            self._identity_from_event(event),
            asset=self._unified_asset(event),
        )
        if outcome in ("NEW_ASSET", "CHANGED_ASSET") and deep_scan and self.scanner:
            self._targeted_scan(event)

    def _targeted_scan(self, event: UniversalVendorEvent) -> None:
        """Run a targeted vendor scan (crypto analysis + evidence)."""
        try:
            report = self.scanner.run(
                {
                    "banner": f"{event.vendor} {event.product}",
                    "config": "",
                    "version": event.product_version,
                },
                scan_id=f"live-{event.event_id}",
                plugin_id=self._best_plugin(event),
            )
            for obs in report.observations:
                self.cbom.materialize(UniversalVendorEvent(
                    vendor=obs.vendor, product=obs.product,
                    product_version=obs.product_version, asset_id=obs.asset_id,
                    asset_type=obs.asset_type,
                    event_type="CRYPTO_CHANGED", change_type="OBSERVED",
                    source="live-targeted-scan",
                    evidence_reference=obs.evidence.get("evidence_id")
                    if isinstance(obs.evidence, dict) else None,
                    vendor_metadata={"algorithm": obs.algorithm,
                                     "algorithms": [obs.algorithm] if obs.algorithm else []},
                ))
        except Exception:
            pass  # a failed targeted scan never breaks the loop

    def _best_plugin(self, event: UniversalVendorEvent) -> Optional[str]:
        candidates = []
        for cls in self._all_plugins():
            if cls.vendor.lower() == event.vendor.lower():
                candidates.append(cls)
        if not candidates:
            return None
        # prefer exact product match, else first by category
        for cls in candidates:
            if cls.product.lower() == event.product.lower():
                return cls.plugin_id
        return candidates[0].plugin_id

    def _all_plugins(self):
        from universal_vendor.plugins import build_registry

        return build_registry().all()

    @staticmethod
    def _identity_from_event(event: UniversalVendorEvent):
        from universal_vendor.live.identity import AssetIdentity

        value = event.asset_id or f"{event.vendor}:{event.product}"
        return AssetIdentity(kind="vendor_asset", value=value,
                             source=event.source, confidence=event.confidence)

    @staticmethod
    def _unified_asset(event: UniversalVendorEvent):
        from universal_vendor.live.identity import UnifiedAssetRecord

        return UnifiedAssetRecord(
            asset_id=event.asset_id or f"{event.vendor}:{event.product}",
            vendor=event.vendor, product=event.product,
            asset_type=event.asset_type,
        )
