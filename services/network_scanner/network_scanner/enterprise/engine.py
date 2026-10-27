"""Global Network Discovery Engine — orchestrates the full architecture.

    Target Spec → Active/Passive/Vendor/Controller Discovery → Asset Registry
    → Protocol Detection → CryptoObservation → Evidence → Dependency Graph
    → CBOM → PQC Risk & Simulation

The engine is the single entry point the scanner CLI, API and monitor use.
All heavy I/O is injected so tests run offline; live defaults probe real
networks (TLS/IPsec/SNMP/sweep) under the configured scan mode.
"""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

from network_scanner.enterprise.assets import AssetRegistry, NetworkAsset
from network_scanner.enterprise.blast_radius import blast_radius
from network_scanner.enterprise.cert_intel import certificate_intelligence_report
from network_scanner.enterprise.credentials import CredentialRef, CredentialVault, scrub_all
from network_scanner.enterprise.geo import GeoLocation, GeographyModel
from network_scanner.enterprise.passive_engine import PassiveDiscoveryEngine, PassiveSource
from network_scanner.enterprise.pqc_readiness import assess_asset_readiness, network_pqc_readiness
from network_scanner.enterprise.protocols.engine import ProtocolDetectionEngine
from network_scanner.enterprise.scan_modes import ScanMetadata, ScanMode
from network_scanner.enterprise.sdwan import SdwanTopology, discover_sdwan
from network_scanner.enterprise.simulation import MigrationSimulator, default_steps_from_crypto
from network_scanner.enterprise.target_spec import TargetSpec, parse_scope_spec
from network_scanner.enterprise.tls_intel import build_tls_intelligence, profile_all
from network_scanner.enterprise.topology import NetworkGraph
from network_scanner.enterprise.tunnels import Tunnel, tunnels_from_ike_probe
from network_scanner.enterprise.vendors import REGISTRY, NetworkVendorPlugin

DEFAULT_PLUGINS = ("snmp", "cisco")


def _sweep_probe_cap() -> int:
    return int(os.environ.get("NETWORK_SWEEP_PROBE_CAP", "32"))


class GlobalNetworkDiscoveryEngine:
    """One-stop discovery + crypto intelligence + PQC simulation engine."""

    def __init__(
        self,
        *,
        mode: ScanMode | None = None,
        vault: CredentialVault | None = None,
        tls_probe: Callable[[str], dict[str, Any]] | None = None,
        ike_probe: Callable[[str], dict[str, Any]] | None = None,
        sweep: Callable[[str], list[str]] | None = None,
        snmp_sock_factory: Callable | None = None,
        authorization_scope: str = "",
    ) -> None:
        if mode is None:
            from network_scanner.enterprise.scan_modes import ScanAuthorization

            mode = ScanMode("SAFE", authorization=ScanAuthorization(authorization_scope=authorization_scope))
        self.mode = mode
        self.vault = vault or CredentialVault()
        self.tls_probe = tls_probe or self._default_tls_probe
        self.ike_probe = ike_probe or self._default_ike_probe
        self.sweep = sweep or self._default_sweep
        self.snmp_sock_factory = snmp_sock_factory

        self.assets = AssetRegistry()
        self.protocols = ProtocolDetectionEngine(allow_udp_init=self.mode.udp_init_probes)
        self.passive = PassiveDiscoveryEngine()
        self.graph = NetworkGraph()
        self.tunnels: list[Tunnel] = []
        self.metadata = ScanMetadata(self.mode)
        self.plugins: list[NetworkVendorPlugin] = []
        self._findings: list[dict[str, Any]] = []
        self._plugin_topology: list[dict[str, Any]] = []

    # ------------------------------------------------------------- defaults

    @staticmethod
    def _default_tls_probe(endpoint: str) -> dict[str, Any]:
        from network_scanner.probing.active_prober import probe_endpoint

        return probe_endpoint(endpoint, timeout=3.0, check_http=False)

    @staticmethod
    def _default_ike_probe(host: str) -> dict[str, Any]:
        from network_scanner.probing.ipsec_probe import probe_ike

        return probe_ike(host, timeout=3.0)

    @staticmethod
    def _default_sweep(cidr: str) -> list[str]:
        from network_scanner.discovery.subnet_discoverer import discover_subnet

        result = discover_subnet(cidr, timeout=1.0, workers=8)
        return [str(e) for e in result.get("endpoints") or []]

    # ------------------------------------------------------------- discovery

    def load_plugins(self, names: Iterable[str] | None = None) -> int:
        names = list(names or DEFAULT_PLUGINS)
        options = self._plugin_options()
        for name in names:
            plugin_cls = REGISTRY.get(name)
            if plugin_cls is None:
                continue
            self.plugins.append(plugin_cls(
                vault=self.vault,
                community=options.get("snmp_community", "public"),
                sock_factory=self.snmp_sock_factory,
            ))
        return len(self.plugins)

    def _plugin_options(self) -> dict[str, Any]:
        return getattr(self, "_options", {})

    # ------------------------------------------------------------- pipeline

    def run(self, scope_specs: Iterable[str | dict[str, Any]], *,
            plugins: Iterable[str] | None = None,
            passive_sources: Iterable[PassiveSource] = (),
            vendor_data: Iterable[dict[str, Any]] | None = None,
            tunnel_data: Iterable[dict[str, Any]] | None = None,
            options: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run the full pipeline and return the report."""
        self._options = dict(options or {})
        self.load_plugins(plugins)
        specs = [parse_scope_spec(s) for s in scope_specs]

        # 1) discover assets
        for spec in specs:
            self._discover_spec(spec)

        # 2) vendor / controller discovery
        for plugin in self.plugins:
            self._run_plugin(plugin, specs)

        # 3) vendor-supplied structured data (tests / controller exports)
        for record in vendor_data or []:
            self._ingest_vendor_record(record)

        # 4) passive (dict sources accepted for API/CLI convenience)
        for source in passive_sources:
            if isinstance(source, PassiveSource):
                self.passive.ingest(source)
            elif isinstance(source, dict):
                self.passive.ingest(PassiveSource(
                    kind=str(source.get("kind") or "LOG"),
                    name=str(source.get("name") or "source"),
                    lines=list(source.get("lines") or []),
                ))
        self.protocols.record_many(self.passive.to_protocol_observations())

        # 5) tunnels from IKE probes + explicit tunnel data
        for tunnel in tunnel_data or []:
            try:
                parsed = Tunnel(**tunnel)
            except (TypeError, ValueError):
                continue
            self.tunnels.append(parsed)
            for endpoint in (parsed.endpoint_a, parsed.endpoint_b):
                if endpoint and ":" not in endpoint:
                    self.assets.upsert(NetworkAsset.from_host(
                        endpoint, network_zone="vpn", source="tunnel"))

        # 6) build dependency graph
        self._build_graph()

        # 7) evidence: TLS findings + cert inventory
        evidence = self._collect_evidence()

        # 8) intelligence layers
        tls_intel = self._tls_intelligence()
        cert_report = certificate_intelligence_report(
            evidence.get("certificates", []), endpoints=evidence.get("endpoints", [])
        )

        # 9) PQC readiness + simulation + blast radius + geo
        pqc = network_pqc_readiness(
            self.assets.to_dicts(),
            asset_crypto=self._asset_crypto(),
            asset_deps=self._asset_dependencies(),
            tunnels=self.tunnels,
        )
        simulation = self._simulate(pqc)
        radius = {asset: blast_radius(self.graph, asset, asset_attributes=self._asset_attrs())
                  for asset in self._crypto_assets()}
        geo = GeographyModel(self._geo_locations(options)).exposure_by_geography(
            self.graph, assets=self.assets.to_dicts(), asset_issues=self._asset_issues()
        )

        self.metadata.finish()
        report = self._report(specs, evidence, tls_intel, cert_report, pqc, simulation, radius, geo)
        self._last_report = report
        return report

    # ------------------------------------------------------------- steps

    def _discover_spec(self, spec: TargetSpec) -> None:
        if spec.hosts:
            for host in spec.hosts:
                self.assets.upsert(NetworkAsset.from_host(host, network_zone=spec.name,
                                                          source="scope-spec"))
        for network in spec.networks:
            try:
                endpoints = self.sweep(network)
            except Exception:  # noqa: BLE001 — offline tests / no sweep
                endpoints = []
            sweep_hosts: list[str] = []
            for endpoint in endpoints:
                host = endpoint.split(":")[0]
                if not host:
                    continue
                self.assets.upsert(NetworkAsset.from_host(host, network_zone=spec.name,
                                                          source="sweep"))
                if host not in sweep_hosts:
                    sweep_hosts.append(host)
            # probe every discovered host once (TLS + optional UDP crypto)
            for host in sweep_hosts[: _sweep_probe_cap()]:
                self._probe_host(host)
        for host in list(spec.hosts):
            if ":" not in host or host.count(":") == 1:
                self._probe_host(host)

    def _probe_host(self, host: str) -> None:
        if not host:
            return
        self.metadata.targets_probed += 1
        asset = self.assets.get(host) or self.assets.upsert(NetworkAsset.from_host(host, source="probe"))
        try:
            finding = self.tls_probe(host)
            self._findings.append(finding)
            self.protocols.from_probe_results(host, [finding])
        except Exception as exc:  # noqa: BLE001
            self._findings.append({"endpoint": host, "status": "PROBE_ERROR",
                                   "detail": f"{type(exc).__name__}: {str(exc)[:200]}"})
        if self.mode.allows("udp_init"):
            try:
                ike = self.ike_probe(host)
                self._findings.append(ike)
                self.tunnels.extend(tunnels_from_ike_probe([ike]))
            except Exception as exc:  # noqa: BLE001
                self._findings.append({"endpoint": f"{host}:500", "status": "PROBE_ERROR",
                                       "detail": f"{type(exc).__name__}: {str(exc)[:200]}"})

    def _run_plugin(self, plugin: NetworkVendorPlugin, specs: list[TargetSpec]) -> None:
        targets: list[str] = []
        for spec in specs:
            targets.extend(spec.hosts)
            if spec.name:
                targets.append(spec.name)
        try:
            devices = plugin.discover_devices(targets or ["127.0.0.1"],
                                              sock_factory=self.snmp_sock_factory)
        except Exception as exc:  # noqa: BLE001
            self._findings.append({"plugin": plugin.vendor, "status": "PLUGIN_ERROR",
                                   "detail": f"{type(exc).__name__}: {str(exc)[:200]}"})
            return
        for device in devices:
            if not device.get("ip") and not device.get("asset_identity"):
                continue
            try:
                normalized = plugin.normalize(device)
            except Exception:  # noqa: BLE001
                normalized = None
            if normalized and normalized.get("asset_identity"):
                asset = NetworkAsset(**{k: v for k, v in normalized.items()
                                        if k in NetworkAsset.__dataclass_fields__})
                self.assets.upsert(asset)
                profile = plugin.collect_crypto_configuration(device, crypto_profile=normalized)
                device["crypto_profile"] = profile
                self.protocols.from_vendor_config(
                    asset.asset_identity, plugin.collect_protocols(device, crypto_profile=profile)
                )
                self._plugin_topology.extend(plugin.collect_topology([device]))
            self._findings.append({"plugin": plugin.vendor, "device": device.get("ip") or device.get("asset_identity"),
                                   "crypto_profile": plugin.collect_crypto_configuration(device)})

    def _ingest_vendor_record(self, record: dict[str, Any]) -> None:
        asset = NetworkAsset.from_dict(record) if record.get("asset_identity") else None
        if asset:
            self.assets.upsert(asset)
        if record.get("crypto_profile"):
            self.protocols.from_vendor_config(
                record.get("asset_identity") or record.get("ip") or "",
                record["crypto_profile"].get("protocols") or [],
            )

    # ------------------------------------------------------------- graph

    def _build_graph(self) -> None:
        for asset in self.assets.all():
            self.graph.add_node(asset.asset_identity)
        # plugin topology (route tables, CDP/LLDP hints)
        self.graph.add_edges(self._plugin_topology)
        # TLS termination edges from probe findings where possible
        for finding in self._findings:
            endpoint = finding.get("endpoint")
            if not endpoint:
                continue
            for cert in finding.get("certificates") or []:
                fp = cert.get("fingerprint_sha256") or cert.get("sha256_fingerprint")
                if fp:
                    self.graph.add_edge(endpoint, f"cert:{fp}", "USES_CERTIFICATE",
                                        crypto={"subject": cert.get("subject")})
        # tunnel edges
        for tunnel in self.tunnels:
            self.graph.add_edge(tunnel.endpoint_a, tunnel.endpoint_b, "USES_VPN",
                                crypto={"protocol": tunnel.protocol,
                                        "encryption": tunnel.encryption_algorithm,
                                        "dh_group": tunnel.dh_group})

    def _collect_evidence(self) -> dict[str, Any]:
        certs: list[dict[str, Any]] = []
        endpoints: list[str] = []
        for finding in self._findings:
            endpoint = finding.get("endpoint")
            if endpoint:
                endpoints.append(str(endpoint))
            for cert in finding.get("certificates") or []:
                row = dict(cert)
                row.setdefault("endpoints", [endpoint] if endpoint else [])
                certs.append(row)
        deduped: dict[str, dict[str, Any]] = {}
        for cert in certs:
            fp = cert.get("fingerprint_sha256") or cert.get("sha256_fingerprint")
            key = fp or str(cert.get("subject"))
            if key in deduped:
                deduped[key].setdefault("endpoints", []).extend(cert.get("endpoints") or [])
            else:
                deduped[key] = cert
        return {"certificates": list(deduped.values()), "endpoints": sorted(set(endpoints))}

    def _tls_intelligence(self) -> list[dict[str, Any]]:
        by_endpoint: dict[str, list[dict[str, Any]]] = {}
        for finding in self._findings:
            endpoint = finding.get("endpoint")
            if endpoint:
                by_endpoint.setdefault(str(endpoint), []).append(finding)
        rows = []
        for endpoint, findings in by_endpoint.items():
            info = build_tls_intelligence(endpoint, findings)
            rows.append({"intelligence": info.to_dict(), "profiles": profile_all(info)})
        return rows

    def _asset_crypto(self) -> dict[str, list[str]]:
        mapping: dict[str, list[str]] = {}
        for finding in self._findings:
            endpoint = str(finding.get("endpoint") or "").split(":")[0]
            crypto = finding.get("crypto") or {}
            algorithm = crypto.get("algorithm") or finding.get("algorithm")
            if endpoint and algorithm:
                mapping.setdefault(endpoint, []).append(str(algorithm))
        return mapping

    def _asset_dependencies(self) -> dict[str, list[str]]:
        deps: dict[str, list[str]] = {}
        for asset in self.assets.all():
            protocols = [obs.protocol for obs in self.protocols.for_asset(asset.asset_identity)]
            if protocols:
                deps[asset.asset_identity] = protocols
        return deps

    def _asset_attrs(self) -> dict[str, dict[str, Any]]:
        return {asset.asset_identity: asset.to_dict() for asset in self.assets.all()}

    def _asset_issues(self) -> dict[str, list[str]]:
        issues: dict[str, list[str]] = {}
        for finding in self._findings:
            endpoint = str(finding.get("endpoint") or "")
            host = endpoint.split(":")[0]
            if not host:
                continue
            issues.setdefault(host, []).extend(finding.get("policy_issues") or [])
            issues.setdefault(host, []).extend(finding.get("issues") or [])
        return {host: sorted(set(issue_list)) for host, issue_list in issues.items()}

    def _crypto_assets(self) -> list[str]:
        """Assets that carry crypto (have findings or tunnel endpoints)."""
        crypto: set[str] = set()
        for finding in self._findings:
            if finding.get("crypto") or finding.get("certificates"):
                crypto.add(str(finding.get("endpoint") or "").split(":")[0])
        for tunnel in self.tunnels:
            crypto.add(tunnel.endpoint_a)
            crypto.add(tunnel.endpoint_b)
        return sorted(crypto)

    def _simulate(self, pqc: dict[str, Any]) -> dict[str, Any]:
        steps: list[Any] = []
        for row in pqc.get("assets") or []:
            steps.extend(default_steps_from_crypto(row.get("classical_crypto") or [],
                                                   asset=row.get("asset")))
        if not steps:
            return {"simulation": "no_classical_crypto_to_migrate", "steps": [],
                    "paths_evaluated": 0, "verdict": "NONE_REQUIRED"}
        simulator = MigrationSimulator(self.graph)
        return simulator.evaluate(steps)

    def _geo_locations(self, options: dict[str, Any] | None) -> list[GeoLocation]:
        raw = (options or {}).get("geo")
        if not raw:
            return []
        if isinstance(raw, list):
            return [GeoLocation(**loc) for loc in raw if isinstance(loc, dict)]
        return []

    # ------------------------------------------------------------- report

    def _report(self, specs: list[TargetSpec], evidence: dict[str, Any],
                tls_intel: list[dict[str, Any]], cert_report: dict[str, Any],
                pqc: dict[str, Any], simulation: dict[str, Any],
                radius: dict[str, Any], geo: dict[str, Any]) -> dict[str, Any]:
        return {
            "scan_metadata": self.metadata.to_dict(),
            "scope": [spec.to_dict() for spec in specs],
            "assets": self.assets.to_dicts(),
            "asset_summary": self.assets.summary(),
            "protocol_observations": self.protocols.to_dicts(),
            "passive_observations": self.passive.to_dicts(),
            "tunnels": [t.to_dict() for t in self.tunnels],
            "evidence": {"certificates": evidence["certificates"],
                         "endpoint_count": len(evidence["endpoints"])},
            "tls_intelligence": tls_intel,
            "certificate_intelligence": cert_report,
            "topology": self.graph.to_dict(),
            "topology_edge_counts": self.graph.edge_counts(),
            "neo4j_cypher": self.graph.to_neo4j_cypher(),
            "pqc_network_readiness": pqc,
            "migration_simulation": simulation,
            "blast_radius": radius,
            "geographic_exposure": geo,
            "findings": scrub_all(self._findings),
            "plugins": [p.vendor for p in self.plugins],
        }

    # ------------------------------------------------------------- json

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self._last_report if hasattr(self, "_last_report") else {},
                          indent=indent, default=str)


def run_network_discovery(scope_specs: Iterable[str | dict[str, Any]], **kwargs: Any) -> dict[str, Any]:
    """Convenience entry point mirroring the scanner/CLI surface."""
    engine = GlobalNetworkDiscoveryEngine(**kwargs)
    report = engine.run(scope_specs)
    engine._last_report = report  # noqa: SLF001
    return report
