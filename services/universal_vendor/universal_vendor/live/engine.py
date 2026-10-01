"""LiveVendorEngine — the 24/7 orchestrator.

Wires the whole live architecture into one loop:

    vendor connectors → event gateway → normalizer → identity resolver →
    live asset state → (new/changed/removed asset) → targeted vendor scan →
    crypto analysis → evidence generation → live vendor CBOM →
    universal dependency graph → PQC/risk/compliance → alert/simulation.

Ticks are incremental and safe to call repeatedly (24/7 without load).
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


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
from universal_vendor.models import ScanMode
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
        tenant_id: str | None = None,
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
        self.tenant_id = tenant_id
        self.monitor = monitor if monitor is not None else LiveVendorMonitor.from_environment(
            tenant_id=tenant_id,
        )
        self.gateway = gateway or EventGateway(tenant_id=tenant_id)
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
        self._evidence: dict[str, dict[str, Any]] = {}
        self._evidence_verification: dict[str, dict[str, Any]] = {}
        # EventGateway is append-only, but each event must enter the state,
        # CBOM, graph, and targeted scanner exactly once. Replaying the whole
        # gateway on every tick causes duplicate deep scans and falsely bumps
        # the realtime CBOM version even when the source is unchanged.
        self._processed_gateway_index = 0
        self._tick_count = 0

    @staticmethod
    def _connector_state_key(connector: Any) -> str:
        """Identify a source without persisting credentials or raw evidence."""
        endpoint = getattr(connector, "_endpoint", None)
        path = getattr(connector, "_path", None)
        host = getattr(connector, "_host", None)
        port = getattr(connector, "_port", None)
        return "|".join(str(value or "") for value in (
            getattr(connector, "asset_id", ""), endpoint, path, host, port,
        ))

    @staticmethod
    def _safe_durable_value(value: Any) -> Any:
        if isinstance(value, dict):
            sensitive = ("password", "secret", "token", "private", "plaintext",
                         "ciphertext", "keymaterial", "authorization")
            return {
                str(key): "<redacted>" if any(
                    token in "".join(char for char in str(key).lower() if char.isalnum())
                    for token in sensitive
                ) else LiveVendorEngine._safe_durable_value(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [LiveVendorEngine._safe_durable_value(item) for item in value]
        if isinstance(value, str) and "BEGIN " in value and "PRIVATE KEY" in value:
            return "<redacted-private-key>"
        return value

    def export_state(self) -> dict[str, Any]:
        """Export durable cursors, evidence references, and safe CBOM state."""
        cursors: dict[str, dict[str, Any]] = {}
        for connector in self.monitor.connectors():
            key = self._connector_state_key(connector)
            cursor: dict[str, Any] = {}
            for attribute in ("_last_fingerprint", "_etag", "_last_modified", "_offset"):
                value = getattr(connector, attribute, None)
                if value is not None:
                    cursor[attribute.removeprefix("_")] = value
            if key and cursor:
                cursors[key] = cursor
        return {
            "tick_count": self._tick_count,
            "cbom": self.cbom.export_state(),
            "source_cursors": cursors,
            "evidence": self._safe_durable_value(list(self._evidence.values())),
            "evidence_verification": self._safe_durable_value(
                list(self._evidence_verification.values())
            ),
        }

    def restore_state(self, state: dict[str, Any] | None) -> None:
        """Restore state produced by :meth:`export_state` before polling."""
        if not isinstance(state, dict):
            return
        self.cbom.restore_state(state.get("cbom"))
        self._evidence = {
            str(item.get("evidence_id") or item.get("hash") or index): item
            for index, item in enumerate(state.get("evidence") or [])
            if isinstance(item, dict)
        }
        self._evidence_verification = {
            str(index): item
            for index, item in enumerate(state.get("evidence_verification") or [])
            if isinstance(item, dict)
        }
        try:
            self._tick_count = max(0, int(state.get("tick_count") or 0))
        except (TypeError, ValueError):
            self._tick_count = 0
        cursors = state.get("source_cursors") or {}
        if not isinstance(cursors, dict):
            return
        for connector in self.monitor.connectors():
            values = cursors.get(self._connector_state_key(connector))
            if not isinstance(values, dict):
                continue
            for name, value in values.items():
                attribute = f"_{name}"
                if attribute in {"_last_fingerprint", "_etag", "_last_modified", "_offset"}:
                    setattr(connector, attribute, value)
        # A new process starts with an empty in-memory gateway. When restoring
        # an already-running cached engine, retain its current suffix so the
        # restore itself cannot replay events already consumed this process.
        self._processed_gateway_index = len(self.gateway)

    def tick(self, *, deep_scan: bool = True) -> dict[str, Any]:
        """One incremental pass. Returns per-stage outcomes."""
        self._tick_count += 1

        # 1. collect from live connectors (§1). Ingestion is separated from
        # processing so events already inserted by an offline sync or another
        # source are handled by the same cursor below.
        collected = self.monitor.collect()
        for event in collected:
            self.gateway.ingest(event)

        # 2. process only the append-only gateway suffix that this engine has
        # not consumed. This is the realtime boundary: no synthetic replay,
        # no repeated targeted scans, and no repeated CBOM version bumps.
        pending = self.gateway.events(since_index=self._processed_gateway_index)
        for event in pending:
            self._apply_event(event, deep_scan=deep_scan)
        self._processed_gateway_index += len(pending)

        # 3. persist only the source fingerprint in live asset state. The raw
        # artifact remains behind its evidence hash and is never fabricated by
        # this state layer.
        for connector, heartbeat in zip(self.monitor.connectors(), self.monitor.heartbeats()):
            connector_id = connector.asset_id or f"{connector.vendor}:{connector.product}"
            if self.health.state(connector_id) is None:
                self.health.register(connector_id, vendor=connector.vendor,
                                     product=connector.product)
            status = str(heartbeat.get("status") or "")
            connection_status = "connected" if heartbeat.get("ok") else "unreachable"
            authentication_status = (
                "unauthorized" if "credential" in str(heartbeat.get("error") or "").lower()
                or "401" in str(heartbeat.get("error") or "")
                or "403" in str(heartbeat.get("error") or "")
                else "authenticated"
            )
            self.health.heartbeat(
                connector_id, connection_status=connection_status,
                authentication_status=authentication_status,
                plugin_health="ok" if heartbeat.get("ok") else "degraded",
                note=status,
            )
        drift_results = []
        for asset_id, snapshot in self.monitor.snapshots().items():
            if snapshot:
                fingerprint_input = snapshot.get("fingerprint") or snapshot
                observed = self.fingerprints.observe(asset_id, fingerprint_input)
                self.state.update_config_hash(
                    asset_id, observed["config_hash"],
                    snapshot={"source": snapshot.get("source"),
                              "status": snapshot.get("status")},
                )
                drift_results.append(self.drift.evaluate(asset_id, snapshot))

        return {
            "tick": self._tick_count,
            "events_processed": len(pending),
            "source_events_collected": len(collected),
            "state_assets": self.state.count(),
            "cbom_version": self.cbom.version(),
            "cbom_components": len(self.cbom.components()),
            "graph_nodes": self.correlation.graph.node_count(),
            "graph_edges": self.correlation.graph.edge_count(),
            "drift_results": [d.to_dict() for d in drift_results],
            "health": [h.to_dict() for h in self.health.all()],
            "source_status": self.monitor.status(),
            "heartbeats": self.monitor.heartbeats(),
            "evidence": list(self._evidence.values()),
            "evidence_verification": list(self._evidence_verification.values()),
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
        """Scan the evidence actually returned by a configured live source.

        A realtime event without scanner-readable evidence is intentionally not
        rescanned.  In particular, vendor/product labels are not a banner and
        an empty config is not a valid observation.  The source event remains
        in the durable event/CBOM path with its honest availability state.
        """
        try:
            plugin_id = self._best_plugin(event)
            if not plugin_id:
                logger.info("live_targeted_scan_unavailable", extra={"reason": "no_vendor_plugin"})
                return
            metadata = event.vendor_metadata or {}
            context = dict(metadata.get("scan_context") or {})
            artifact = metadata.get("artifact")
            evidence_candidates = [
                artifact, context.get("config"), context.get("banner"),
                context.get("api_metadata"), context.get("metadata"),
                context.get("crypto_metadata"), context.get("cbom"),
                context.get("sbom"),
            ]
            has_source_evidence = any(
                candidate not in (None, "", [], {}) for candidate in evidence_candidates
            )
            if not context and artifact is not None:
                if isinstance(artifact, dict):
                    context["api_metadata"] = artifact
                    if artifact.get("config") is not None:
                        context["config"] = artifact["config"]
                    if artifact.get("banner") is not None:
                        context["banner"] = artifact["banner"]
                elif isinstance(artifact, str):
                    context["config"] = artifact
            # Preserve only the event's real identity/provenance as scanner
            # context. These values help common discovery correlate records;
            # they are not used to invent a banner or crypto observation.
            if event.asset_id is not None:
                context.setdefault("asset_id", event.asset_id)
            context.setdefault("vendor", event.vendor)
            context.setdefault("product", event.product)
            if event.product_version is not None and "version" not in context:
                context["version"] = event.product_version
            if event.evidence_reference is not None:
                context.setdefault("evidence_reference", event.evidence_reference)
            if not has_source_evidence:
                logger.info("live_targeted_scan_unavailable", extra={
                    "reason": "source_evidence_not_scan_readable",
                })
                return
            report = self.scanner.run(
                context,
                scan_id=f"live-{event.event_id}",
                mode=ScanMode.DEEP_DISCOVERY,
                plugin_id=plugin_id,
            )
            for evidence in report.evidence:
                if isinstance(evidence, dict):
                    evidence_id = str(evidence.get("evidence_id") or evidence.get("hash") or len(self._evidence))
                    self._evidence[evidence_id] = evidence
                    if len(self._evidence) > 10_000:
                        self._evidence.pop(next(iter(self._evidence)))
            if report.evidence_verification:
                self._evidence_verification[report.scan_id] = report.evidence_verification
            for obs in report.observations:
                observation = obs.model_dump(mode="json")
                safe_metadata = {
                    "algorithm": obs.algorithm,
                    "algorithms": [obs.algorithm] if obs.algorithm else [],
                    "observation": observation,
                    "source_event_id": event.event_id,
                    "source_evidence_reference": event.evidence_reference,
                    "scan_id": report.scan_id,
                    "graph": report.graph,
                }
                self.cbom.materialize(UniversalVendorEvent(
                    vendor=obs.vendor, product=obs.product,
                    product_version=obs.product_version, asset_id=obs.asset_id or event.asset_id,
                    asset_type=obs.asset_type,
                    tenant_id=event.tenant_id,
                    event_type="CRYPTO_CHANGED", change_type="OBSERVED",
                    source=event.source,
                    evidence_reference=obs.evidence.get("evidence_id")
                    if isinstance(obs.evidence, dict) else event.evidence_reference,
                    vendor_metadata=safe_metadata,
                ))
            for edge in (report.graph or {}).get("edges", []):
                if edge.get("source") and edge.get("target"):
                    self.correlation.graph.add_edge(
                        str(edge["source"]), str(edge["target"]),
                        str(edge.get("relationship") or "DEPENDS_ON"),
                        detail=edge.get("detail") or {},
                    )
        except Exception as _handler_exc:
            logger.warning(
                "exception_suppressed",
                extra={"error_type": type(_handler_exc).__name__},
            )
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
