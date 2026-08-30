"""ZELNX Cloud Discovery Engine — orchestrator.

Runs the multi-cloud discovery pipeline over injected provider adapters and
produces a unified report covering all 23 spec areas:

1  multi-cloud account discovery    13 cloud dependency graph
2  full cloud asset inventory       14 multi-cloud relationships
3  cloud key discovery              15 unified crypto posture
4  certificate discovery            16 cloud PQC readiness
5  cloud PKI intelligence           17 migration simulation
6  cloud encryption discovery       18 cost intelligence
7  cloud network cryptography       19 compliance mapping
8  cloud TLS discovery              20 drift detection
9  Kubernetes crypto discovery      21 event-driven monitoring
10 serverless crypto discovery      22 evidence collection
11 secret/key reference discovery   23 scan modes (read-only)

Default modes: INVENTORY_ONLY + CRYPTO_DISCOVERY.  Every discovery stage
records evidence; the evidence chain is verifiable end-to-end.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from cloud_scanner.enterprise.asset_inventory import AssetInventory, AssetInventoryBuilder
from cloud_scanner.enterprise.certificate_discovery import (
    CertificateDiscovery,
    CertificateInventory,
)
from cloud_scanner.enterprise.compliance_mapping import ComplianceMappingEngine, ComplianceReport
from cloud_scanner.enterprise.cost_intelligence import CostEstimate, CostIntelligenceEngine
from cloud_scanner.enterprise.dependency_graph import CloudDependencyGraph
from cloud_scanner.enterprise.drift import DriftResult, detect_drift
from cloud_scanner.enterprise.encryption_discovery import (
    EncryptionDiscovery,
    EncryptionInventory,
)
from cloud_scanner.enterprise.event_monitor import (
    CloudCbom,
    CloudEventMonitor,
    CloudEventNormalizer,
    EventMonitorResult,
)
from cloud_scanner.enterprise.evidence import EvidenceChain, evidence_block
from cloud_scanner.enterprise.iam_access import AccessInventory, IamAccessDiscovery
from cloud_scanner.enterprise.key_discovery import KeyDiscovery, KeyInventory
from cloud_scanner.enterprise.kubernetes_crypto import (
    KubernetesCryptoDiscovery,
    KubernetesInventory,
)
from cloud_scanner.enterprise.migration_simulation import (
    CloudMigrationSimulator,
    CloudSimulationResult,
)
from cloud_scanner.enterprise.models import EvidenceSource
from cloud_scanner.enterprise.multi_cloud import MultiCloudDiscovery, MultiCloudInventory
from cloud_scanner.enterprise.network_crypto import NetworkCryptoDiscovery, NetworkCryptoInventory
from cloud_scanner.enterprise.org_hierarchy import OrgHierarchy, OrgHierarchyBuilder
from cloud_scanner.enterprise.pki_intelligence import PkiIntelligence, PkiIntelligenceEngine
from cloud_scanner.enterprise.posture import CryptoPosture, PostureEngine
from cloud_scanner.enterprise.pqc_readiness import CloudPqcReadinessEngine, PqcInventory
from cloud_scanner.enterprise.scan_modes import (
    CloudScanMode,
    DEFAULT_MODES,
    is_read_only,
    mode_names,
    requires_deep,
    requires_events,
    validate_modes,
)
from cloud_scanner.enterprise.secret_refs import SecretInventory, SecretReferenceDiscovery
from cloud_scanner.enterprise.serverless_crypto import (
    ServerlessCryptoDiscovery,
    ServerlessInventory,
)
from cloud_scanner.enterprise.tls_discovery import TlsDiscovery, TlsInventory

DEFAULT_MAX_ITEMS = 2000


def _num(value: Any, default: float = 0.0) -> float:
    try:
        return float(value) if value not in (None, "") else default
    except (TypeError, ValueError):
        return default


@dataclass
class DiscoveryReport:
    """Everything the engine learned in one discovery pass."""

    organization: OrgHierarchy = field(default_factory=OrgHierarchy)
    inventory: AssetInventory = field(default_factory=AssetInventory)
    keys: KeyInventory = field(default_factory=KeyInventory)
    certificates: CertificateInventory = field(default_factory=CertificateInventory)
    pki: PkiIntelligence = field(default_factory=PkiIntelligence)
    encryption: EncryptionInventory = field(default_factory=EncryptionInventory)
    network: NetworkCryptoInventory = field(default_factory=NetworkCryptoInventory)
    tls: TlsInventory = field(default_factory=TlsInventory)
    kubernetes: KubernetesInventory = field(default_factory=KubernetesInventory)
    serverless: ServerlessInventory = field(default_factory=ServerlessInventory)
    secrets: SecretInventory = field(default_factory=SecretInventory)
    access: AccessInventory = field(default_factory=AccessInventory)
    graph: CloudDependencyGraph = field(default_factory=CloudDependencyGraph)
    multi_cloud: MultiCloudInventory = field(default_factory=MultiCloudInventory)
    posture: CryptoPosture | None = None
    pqc: PqcInventory = field(default_factory=PqcInventory)
    compliance: ComplianceReport | None = None
    simulation: CloudSimulationResult | None = None
    cost: CostEstimate | None = None
    evidence: EvidenceChain = field(default_factory=EvidenceChain)
    drift_latest: DriftResult = field(default_factory=DriftResult)
    errors: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        posture = self.posture.to_dict() if self.posture else {}
        return {
            "organization": self.organization.to_dict(),
            "asset_inventory": {
                "workloads": self.inventory.to_dicts(),
                "summary": self.inventory.summary(),
            },
            "keys": {"keys": self.keys.to_dicts(), "summary": self.keys.summary()},
            "certificates": {
                "certificates": self.certificates.to_dicts(),
                "relations": [rel.to_dict() for rel in self.certificates.relations],
                "summary": self.certificates.summary(),
            },
            "pki": {
                "cas": self.pki.to_dicts(),
                "trust": [rel.to_dict() for rel in self.pki.trust],
                "weak_chains": self.pki.weak_chains(),
                "summary": self.pki.summary(),
            },
            "encryption": {
                "resources": self.encryption.to_dicts(),
                "summary": self.encryption.summary(),
            },
            "network_crypto": self.network.to_dicts(),
            "tls": {"endpoints": self.tls.to_dicts(), "summary": self.tls.summary()},
            "kubernetes": {"clusters": self.kubernetes.to_dicts(), "summary": self.kubernetes.summary()},
            "serverless": {"functions": self.serverless.to_dicts(), "summary": self.serverless.summary()},
            "secrets": {"secrets": self.secrets.to_dicts(), "summary": self.secrets.summary()},
            "iam_access": {"bindings": self.access.to_dicts(), "summary": self.access.summary()},
            "dependency_graph": self.graph.to_dicts(),
            "graph_summary": self.graph.summary(),
            "multi_cloud": {"relationships": self.multi_cloud.to_dicts(),
                            "summary": self.multi_cloud.summary()},
            "posture": posture,
            "pqc_readiness": {"results": self.pqc.to_dicts(), "summary": self.pqc.summary()},
            "compliance": self.compliance.to_dicts() if self.compliance else [],
            "compliance_summary": self.compliance.summary() if self.compliance else {},
            "migration_simulation": self.simulation.to_dict() if self.simulation else {},
            "cost": self.cost.to_dict() if self.cost else {},
            "evidence": self.evidence.to_dicts(),
            "evidence_verified": self.evidence.verify(),
            "errors": list(self.errors),
        }


class ZelixCloudDiscoveryEngine:
    """ZELNX Cloud Discovery Engine.

    All I/O is injected through :class:`ProviderAdapter` instances (or plain
    dicts with the same keys) — unit tests never touch cloud SDKs and the
    engine never makes live calls on its own.
    """

    def __init__(
        self,
        *,
        providers: Iterable[Any] | None = None,
        modes: list[str] | set[str] | None = None,
        options: dict[str, Any] | None = None,
        evidence: EvidenceChain | None = None,
        compliance: ComplianceMappingEngine | None = None,
        cost: CostIntelligenceEngine | None = None,
        pqc: CloudPqcReadinessEngine | None = None,
        event_monitor: CloudEventMonitor | None = None,
        clock: Callable[[], str] | None = None,
    ) -> None:
        from datetime import datetime, timezone

        self._clock = clock or (lambda: datetime.now(timezone.utc).isoformat())
        self.modes: set[CloudScanMode] = validate_modes(modes)
        self._options = dict(options or {})
        self._providers = list(providers or [])
        self._evidence = evidence or EvidenceChain()
        self._compliance = compliance
        self._cost = cost
        self._pqc = pqc
        self._event_monitor = event_monitor or CloudEventMonitor(
            normalizer=CloudEventNormalizer(clock=self._clock))
        self._report = DiscoveryReport()
        self._snapshots: list[dict[str, dict[str, Any]]] = []
        self._event_results: list[EventMonitorResult] = []

    # ------------------------------------------------------------------ stages

    def discover(self) -> DiscoveryReport:
        """Run the enabled mode stages over the injected providers."""
        report = self._report
        entries = self._provider_entries()

        # §1 organization hierarchy + §2 asset inventory (INVENTORY_ONLY base)
        report.organization = OrgHierarchyBuilder(
            entries, max_accounts=int(self._options.get("max_accounts", DEFAULT_MAX_ITEMS)),
        ).discover()
        report.inventory = AssetInventoryBuilder(
            entries, max_workloads=int(self._options.get("max_workloads", DEFAULT_MAX_ITEMS)),
        ).discover()

        if CloudScanMode.CRYPTO_DISCOVERY in self.modes:
            self._discover_crypto(report, entries)

        if requires_deep(self.modes):
            self._discover_deep(report, entries)

        # shared analytics (crypto + deep)
        if CloudScanMode.CRYPTO_DISCOVERY in self.modes:
            self._analyze(report)

        self._record_evidence(report)
        self._collect_errors(report)
        self._snapshots.append(self._snapshot(report))
        # §20 drift: compare the previous snapshot with the current one
        if len(self._snapshots) > 1:
            report.drift_latest = detect_drift(
                self._snapshots[-2], self._snapshots[-1],
                approved_changes={
                    tuple(item) for item in (self._options.get("approved_changes") or [])
                },
                detected_at=self._clock(),
                seq=len(report.evidence),
            )
        return report

    def _discover_crypto(self, report: DiscoveryReport, entries: list[dict[str, Any]]) -> None:
        report.keys = KeyDiscovery(entries).discover()
        report.certificates = CertificateDiscovery(entries).discover()
        report.pki = PkiIntelligenceEngine(entries).discover(
            certificates=report.certificates.certificates)
        report.encryption = EncryptionDiscovery(entries).discover()
        report.network = NetworkCryptoDiscovery(entries).discover()
        report.tls = TlsDiscovery(entries).discover()

    def _discover_deep(self, report: DiscoveryReport, entries: list[dict[str, Any]]) -> None:
        report.kubernetes = KubernetesCryptoDiscovery(entries).discover()
        report.serverless = ServerlessCryptoDiscovery(entries).discover()
        report.secrets = SecretReferenceDiscovery(entries).discover()
        report.access = IamAccessDiscovery(entries).discover()
        report.multi_cloud = MultiCloudDiscovery(entries).discover()

    def _analyze(self, report: DiscoveryReport) -> None:
        # §13 dependency graph from normalized models + explicit rows
        report.graph = CloudDependencyGraph()
        report.graph.build_from_workloads(
            report.inventory.workloads,
            keys=report.keys.keys,
            certificates=report.certificates.certificates,
            endpoints=report.tls.endpoints,
        )
        for tunnel in report.network.tunnels:
            report.graph.add_edge(tunnel.source, tunnel.target, tunnel.kind,
                                  provider=tunnel.provider, account=tunnel.account)
        # §15 posture
        report.posture = PostureEngine(
            keys=report.keys,
            certificates=report.certificates,
            pki=report.pki,
            encryption=report.encryption,
            network=report.network,
            tls=report.tls,
            kubernetes=report.kubernetes,
            serverless=report.serverless,
            graph=report.graph,
        ).evaluate()
        # §16 PQC readiness
        engine = self._pqc or CloudPqcReadinessEngine(
            keys=report.keys, certificates=report.certificates, tls=report.tls)
        report.pqc = engine.assess()
        # §19 compliance
        report.compliance = (self._compliance or ComplianceMappingEngine(
            keys=report.keys, certificates=report.certificates, tls=report.tls)).evaluate()
        # §17 migration simulation over the dependency graph
        report.simulation = self._simulate(report)
        # §18 cost intelligence
        report.cost = self._estimate_costs(report)

    # ------------------------------------------------------------------ events

    def process_events(self, raw_events: list[dict[str, Any]], *,
                       approved_changes: set[tuple[str, str]] | None = None) -> EventMonitorResult:
        """§21 event-driven monitoring: normalize → detect → CBOM → policy → drift."""
        self.modes = self.modes | {CloudScanMode.EVENT_DRIVEN}
        result = self._event_monitor.process(raw_events, approved_changes=approved_changes)
        self._event_results.append(result)
        for event in result.events:
            self._evidence.append({"kind": "cloud_event", "event": event.to_dict()})
        return result

    # ------------------------------------------------------------------ continuous

    def run(self, *, cycles: int = 1,
            stop: Callable[[], bool] | None = None) -> list[DiscoveryReport]:
        """§20/§23 CONTINUOUS_MONITORING: repeated discovery + drift between
        consecutive snapshots."""
        self.modes = self.modes | {CloudScanMode.CONTINUOUS_MONITORING}
        reports: list[DiscoveryReport] = []
        for _ in range(max(1, int(cycles or 1))):
            if stop is not None and stop():
                break
            reports.append(self.discover())
        return reports

    # ------------------------------------------------------------------ report

    def report(self) -> dict[str, Any]:
        data = self._report.to_dict()
        data["scan"] = {
            "modes": mode_names(self.modes),
            "read_only": is_read_only(self.modes),
            "default_modes": sorted(mode.value for mode in DEFAULT_MODES),
            "providers": [p.provider if hasattr(p, "provider") else str(p.get("provider"))
                          for p in self._providers],
            "evidence_chain_head": self._evidence.head,
            "evidence_records": len(self._evidence),
        }
        data["drift"] = {
            "latest": [obs.to_dict() for obs in self._report.drift_latest.observations],
            "summary": self._report.drift_latest.summary(),
        }
        data["events"] = {
            "processed": len(self._event_results),
            "latest": self._event_results[-1].to_dict() if self._event_results else {},
            "cbom": self._event_monitor.cbom.summary(),
        }
        return data

    # ------------------------------------------------------------------ helpers

    def _provider_entries(self) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for provider in self._providers:
            if hasattr(provider, "to_provider_entry"):
                entries.append(provider.to_provider_entry())
            elif isinstance(provider, dict):
                entries.append(dict(provider))
        return entries

    def _collect_errors(self, report: DiscoveryReport) -> None:
        """Aggregate per-stage errors into the report-level error list."""
        sources = [
            report.organization.errors, report.inventory.errors, report.keys.errors,
            report.certificates.errors, report.pki.errors, report.encryption.errors,
            report.network.errors, report.tls.errors, report.kubernetes.errors,
            report.serverless.errors, report.secrets.errors, report.access.errors,
            report.multi_cloud.errors, report.pqc.errors,
        ]
        for source in sources:
            report.errors.extend(list(source))

    def _record_evidence(self, report: DiscoveryReport) -> None:
        def record(kind: str, provider: str, account: str, resource: str,
                   state: dict[str, Any]) -> None:
            evidence = evidence_block(
                source_provider=provider,
                api_source=f"zelix:{kind}",
                account=account or None,
                timestamp=self._clock(),
            )
            report.evidence.append({
                "kind": kind,
                "provider": provider,
                "account": account,
                "resource": resource,
                "state": state,
                "evidence": evidence.to_dict(),
            })

        for account in report.organization.accounts:
            record("account", account.provider, account.account_id, account.account_id,
                   {"name": account.name, "status": account.status})
        for workload in report.inventory.workloads:
            record("workload", workload.cloud_provider, workload.account, workload.workload_id,
                   {"runtime": workload.runtime, "region": workload.region})
        for key in report.keys.keys:
            record("key", key.provider, key.account, key.key_id, {
                "algorithm": key.algorithm, "key_size": key.key_size,
                "rotation_enabled": key.rotation_enabled, "key_state": key.key_state})
        for cert in report.certificates.certificates:
            record("certificate", cert.provider, cert.account, cert.certificate_id, {
                "domain": cert.domain, "valid_to": cert.valid_to,
                "signature_algorithm": cert.signature_algorithm})
        for endpoint in report.tls.endpoints:
            record("tls_endpoint", endpoint.provider, endpoint.account, endpoint.endpoint,
                   {"tls_version": endpoint.tls_version,
                    "classification": endpoint.classification})
        for resource in report.encryption.resources:
            record("encryption", resource.provider, resource.account, resource.resource_id,
                   {"at_rest": resource.at_rest, "in_transit": resource.in_transit})
        for cluster in report.kubernetes.clusters:
            record("cluster", cluster.provider, cluster.account, cluster.cluster_id,
                   {"secrets_encryption": cluster.secrets_encryption,
                    "api_tls_version": cluster.api_tls_version})
        for binding in report.access.bindings:
            record("iam_binding", binding.evidence.source_provider or "",
                   binding.source_account or binding.target_account, binding.key_id,
                   {"identity": binding.identity, "permission": binding.permission,
                    "cross_account": binding.cross_account})
        for relationship in report.multi_cloud.relationships:
            record("cross_cloud", relationship.source_provider, relationship.source_account,
                   f"{relationship.source}->{relationship.target}",
                   {"kind": relationship.kind, "crypto_dependencies": relationship.crypto_dependencies})

    def _snapshot(self, report: DiscoveryReport) -> dict[str, dict[str, Any]]:
        snap: dict[str, dict[str, Any]] = {}
        for key in report.keys.keys:
            snap[key.key_id] = {"provider": key.provider, "account": key.account,
                                "algorithm": key.algorithm, "key_size": key.key_size,
                                "rotation_enabled": key.rotation_enabled}
        for cert in report.certificates.certificates:
            snap[cert.certificate_id] = {"provider": cert.provider, "account": cert.account,
                                         "serial": cert.serial, "valid_to": cert.valid_to}
        for endpoint in report.tls.endpoints:
            snap[endpoint.endpoint] = {"provider": endpoint.provider, "account": endpoint.account,
                                       "tls_version": endpoint.tls_version,
                                       "classification": endpoint.classification}
        for resource in report.encryption.resources:
            snap[resource.resource_id] = {"provider": resource.provider,
                                          "account": resource.account,
                                          "encryption_enabled": resource.at_rest != "NOT_ENCRYPTED",
                                          "at_rest": resource.at_rest}
        for account in report.organization.accounts:
            snap[f"account:{account.account_id}"] = {"provider": account.provider,
                                                     "account_id": account.account_id,
                                                     "status": account.status}
        return snap

    def _simulate(self, report: DiscoveryReport) -> CloudSimulationResult:
        from cloud_scanner.enterprise.migration_simulation import CloudMigrationSimulator

        simulator = CloudMigrationSimulator(report.graph)
        # attach the network path simulator when a path graph can be built
        simulator._network_simulator = self._network_simulator(report)
        candidates = [key.key_id for key in report.keys.keys
                      if key.algorithm and key.algorithm != "AES"]
        candidates += [cert.certificate_id for cert in report.certificates.certificates
                       if cert.public_key_algorithm]
        candidates += [endpoint.endpoint for endpoint in report.tls.endpoints
                       if endpoint.key_exchange]
        return simulator.simulate(candidates[:20])

    # cloud relationship -> network graph relationship
    _NETWORK_RELATION_MAP = {
        "VPN_TUNNEL": "USES_VPN",
        "PRIVATE_CONNECT": "USES_IPSEC",
        "INTERCONNECT": "CONNECTED_TO",
        "TRANSIT": "CONNECTED_TO",
        "RUNS_ON": "DEPENDS_ON",
        "USES_KEY": "DEPENDS_ON",
        "USES_CERTIFICATE": "USES_CERTIFICATE",
        "EXPOSED_BY": "CONNECTED_TO",
        "TERMINATES_TLS": "TERMINATES_TLS_FOR",
        "STORED_IN": "DEPENDS_ON",
        "CONNECTS_TO": "CONNECTED_TO",
    }

    def _network_simulator(self, report: DiscoveryReport) -> Any:
        """Build a network path simulator from tunnel relationships."""
        try:
            from network_scanner.enterprise.simulation import MigrationSimulator  # type: ignore
            from network_scanner.enterprise.topology import NetworkGraph  # type: ignore

            graph = NetworkGraph()
            seen: set[tuple[str, str]] = set()
            for tunnel in report.network.tunnels:
                if (tunnel.source, tunnel.target) in seen:
                    continue
                seen.add((tunnel.source, tunnel.target))
                graph.add_edge(
                    tunnel.source, tunnel.target,
                    self._NETWORK_RELATION_MAP.get(tunnel.kind, "CONNECTED_TO"))
            for edge in report.graph.edges():
                graph.add_edge(
                    edge.source, edge.target,
                    self._NETWORK_RELATION_MAP.get(edge.relation, "CONNECTED_TO"))
            simulator = MigrationSimulator(graph)
            return _NetworkSimulatorAdapter(simulator)
        except Exception:
            return None

    def _estimate_costs(self, report: DiscoveryReport) -> CostEstimate:
        engine = self._cost or CostIntelligenceEngine(
            currency=str(self._options.get("currency") or "USD"))
        return engine.estimate(
            workloads=report.inventory.count(),
            storage_gb=_num(self._options.get("storage_gb")),
            egress_gb=_num(self._options.get("egress_gb")),
            hsm_keys=sum(1 for key in report.keys.keys if key.hsm_backed),
            kms_keys=report.keys.count(),
            certificates=report.certificates.count(),
            log_gb=_num(self._options.get("log_gb")),
            engineering_hours=_num(self._options.get("engineering_hours")),
            vendor_delta=_num(self._options.get("vendor_delta")),
            region=self._options.get("region"),
        )


class _NetworkSimulatorAdapter:
    """Adapter: network MigrationSimulator.evaluate → simulate_steps."""

    def __init__(self, simulator: Any) -> None:
        self._simulator = simulator

    def simulate_steps(self, steps: list[dict[str, Any]]) -> dict[str, Any]:
        try:
            from network_scanner.enterprise.simulation import MigrationStep  # type: ignore

            parsed = [
                MigrationStep(
                    algorithm=str(step.get("algorithm") or "RSA"),
                    replacement=str(step.get("replacement") or "ML-KEM-768"),
                    asset=str(step.get("asset") or ""),
                    hybrid=bool(step.get("hybrid", True)),
                )
                for step in steps
            ]
            return self._simulator.evaluate(parsed)
        except Exception as exc:  # noqa: BLE001
            return {"error": str(exc)[:300]}
