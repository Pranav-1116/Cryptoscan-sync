"""Enterprise layer — orchestrating engine + scanner/CLI wiring.

The GlobalNetworkDiscoveryEngine runs the full pipeline (target spec →
discovery → assets → protocols → graph → intelligence → PQC → simulation →
blast radius → geo) with injected probes for offline tests. Also covers the
NetworkTlsScanner.discover_network entry point and the CLI --scope path.
"""

from __future__ import annotations

import json

import pytest

from network_scanner.core.scanner import NetworkTlsScanner
from network_scanner.enterprise.engine import (
    DEFAULT_PLUGINS,
    GlobalNetworkDiscoveryEngine,
    run_network_discovery,
)
from network_scanner.enterprise.scan_modes import ScanAuthorization, ScanMode


def _fake_tls(endpoint: str) -> dict:
    return {
        "endpoint": endpoint, "status": "OK",
        "crypto": {"tls_version": "TLSv1.2", "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                   "algorithm": "RSA", "key_size": 2048},
        "certificates": [{"subject": "CN=api.example.com", "issuer": "CN=Int CA",
                          "fingerprint_sha256": "ab" * 32,
                          "not_after": "2027-01-01T00:00:00Z",
                          "signature_algorithm": "sha256WithRSAEncryption"}],
        "policy_issues": [],
    }


def _fake_ike(host: str) -> dict:
    return {"endpoint": f"{host}:500", "status": "OK", "proposals": [],
            "issues": ["WEAK_IKE_DH_GROUP:MODP-1024"]}


def _fake_sweep(cidr: str) -> list[str]:
    return ["10.0.0.5:443", "10.0.0.6:8443"]


class _DeadSock:
    def settimeout(self, t: float) -> None:
        pass

    def sendto(self, data: bytes, addr: tuple) -> None:
        raise TimeoutError("no agent")

    def recvfrom(self, size: int) -> tuple:
        raise TimeoutError("no agent")

    def close(self) -> None:
        pass


def _dead_sock_factory(family: int = 2, socktype: int = 2) -> _DeadSock:
    return _DeadSock()


def _engine(**kw) -> GlobalNetworkDiscoveryEngine:
    base = dict(tls_probe=_fake_tls, ike_probe=_fake_ike, sweep=_fake_sweep,
                snmp_sock_factory=_dead_sock_factory)
    base.update(kw)
    return GlobalNetworkDiscoveryEngine(**base)


class TestEnginePipeline:
    def test_full_pipeline(self) -> None:
        engine = _engine()
        report = engine.run(
            ["10.0.0.0/24"],
            plugins=["snmp"],
            tunnel_data=[{
                "tunnel_id": "tnl-1", "endpoint_a": "branch-a", "endpoint_b": "dc-router",
                "encryption_algorithm": "3DES", "integrity_algorithm": "MD5",
                "dh_group": 2, "pre_shared_key_used": True,
            }],
        )
        assert report["scan_metadata"]["scan_mode"] == "SAFE"
        assert report["scan_metadata"]["end_time"] is not None
        assert report["asset_summary"]
        assert report["protocol_observations"]
        assert report["evidence"]["certificates"]
        assert report["tls_intelligence"]
        assert report["certificate_intelligence"]["certificate_count"] >= 1
        assert report["topology_edge_counts"].get("USES_CERTIFICATE") == 2
        assert report["topology_edge_counts"].get("USES_VPN") == 1
        assert report["neo4j_cypher"]
        assert report["migration_simulation"]
        assert report["blast_radius"]
        assert report["geographic_exposure"] is not None
        assert report["plugins"] == ["snmp"]

    def test_pqc_migration_required_for_weak_tunnel(self) -> None:
        engine = _engine()
        report = engine.run(["branch-a.example.com"], tunnel_data=[{
            "tunnel_id": "t", "endpoint_a": "branch-a.example.com", "endpoint_b": "dc",
            "encryption_algorithm": "3DES", "dh_group": 2,
        }])
        statuses = report["pqc_network_readiness"]["by_status"]
        assert statuses.get("MIGRATION_REQUIRED", 0) >= 1

    def test_scan_mode_metadata_and_authorization(self) -> None:
        mode = ScanMode("DEEP", ScanAuthorization(authorization_scope="emirates-dc"))
        engine = _engine(mode=mode)
        report = engine.run(["10.0.0.1"])
        assert report["scan_metadata"]["scan_mode"] == "DEEP"
        assert report["scan_metadata"]["authorization_scope"] == "emirates-dc"

    def test_engine_default_safe_never_sends_udp_init(self) -> None:
        engine = _engine()
        assert engine.mode.udp_init_probes is False
        assert engine.mode.allows("udp_init") is False

    def test_run_network_discovery_convenience(self) -> None:
        report = run_network_discovery(["10.0.0.0/24"], tls_probe=_fake_tls,
                                       ike_probe=_fake_ike, sweep=_fake_sweep,
                                       snmp_sock_factory=_dead_sock_factory)
        assert report["scope"][0]["value"] == "10.0.0.0/24"
        assert report["findings"]

    def test_findings_scrubbed(self) -> None:
        engine = _engine()

        def leaky_tls(endpoint: str) -> dict:
            finding = _fake_tls(endpoint)
            finding["password"] = "hunter2"
            return finding

        engine = _engine(tls_probe=leaky_tls)
        report = engine.run(["10.0.0.1"])
        assert "hunter2" not in json.dumps(report["findings"])

    def test_vendor_data_ingestion(self) -> None:
        engine = _engine()
        report = engine.run(
            ["10.0.0.1"],
            vendor_data=[{
                "asset_identity": "rtr-1", "ip": "10.0.0.1", "manufacturer": "Cisco",
                "device_type": "router", "os": "IOS-XE",
                "crypto_profile": {"protocols": [{"protocol": "IPsec",
                                                  "status": "CRYPTOGRAPHY_CONFIGURED"}]},
            }],
        )
        assert report["assets"]
        assert any(o["asset"] == "rtr-1" for o in report["protocol_observations"])

    def test_passive_sources_through_engine(self) -> None:
        engine = _engine()
        report = engine.run(["10.0.0.1"], passive_sources=[{
            "kind": "FIREWALL_LOG", "name": "fw", "lines": [
                "tls=1.2 to api.example.com cipher=AES128-GCM-SHA256",
            ],
        }])
        assert report["passive_observations"]
        assert any(o["asset"] == "api.example.com" for o in report["passive_observations"])

    def test_plugin_error_is_data_not_crash(self) -> None:
        engine = _engine()

        class ExplodingPlugin:
            vendor = "exploder"

            def __init__(self, **kw) -> None:
                pass

            def discover_devices(self, targets, **kw):
                raise RuntimeError("boom")

        engine.plugins = [ExplodingPlugin()]  # type: ignore[assignment]
        report = engine.run(["10.0.0.1"])
        assert any("PLUGIN_ERROR" in str(f) for f in report["findings"])

    def test_to_json_export(self) -> None:
        engine = _engine()
        report = engine.run(["10.0.0.1"])
        engine._last_report = report  # noqa: SLF001
        text = engine.to_json()
        assert "scan_metadata" in text


class TestScannerWiring:
    def test_discover_network_on_scanner(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import network_scanner.enterprise.engine as engine_mod

        class FakeEngine:
            def __init__(self, **kw) -> None:
                self.mode = kw.get("mode")

            def run(self, scope_specs, **kw):
                assert scope_specs == ["10.0.0.0/24"]
                return {"scan_metadata": {"scan_mode": self.mode.mode},
                        "scope": [{"value": "10.0.0.0/24"}], "assets": [], "findings": [],
                        "protocol_observations": [], "tunnels": [], "tls_intelligence": [],
                        "certificate_intelligence": {}, "topology": {}, "topology_edge_counts": {},
                        "neo4j_cypher": "", "pqc_network_readiness": {},
                        "migration_simulation": {}, "blast_radius": {}, "geographic_exposure": {},
                        "passive_observations": [], "plugins": [], "scan_id": None,
                        "target_kind": "global-network-discovery"}

        monkeypatch.setattr(engine_mod, "GlobalNetworkDiscoveryEngine", FakeEngine)
        scanner = NetworkTlsScanner(live=True, timeout=2.0)
        report = scanner.discover_network(["10.0.0.0/24"], scan_id="s-1", mode="SAFE")
        assert report["scan_id"] == "s-1"
        assert report["target_kind"] == "global-network-discovery"
        assert report["scan_metadata"]["scan_mode"] == "SAFE"

    def test_discover_network_default_mode_safe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import network_scanner.enterprise.engine as engine_mod

        captured: dict = {}

        class FakeEngine:
            def __init__(self, **kw) -> None:
                captured["mode"] = kw.get("mode").mode

            def run(self, scope_specs, **kw):
                return {"scan_metadata": {}, "scope": [], "assets": [], "findings": [],
                        "protocol_observations": [], "tunnels": [], "tls_intelligence": [],
                        "certificate_intelligence": {}, "topology": {}, "topology_edge_counts": {},
                        "neo4j_cypher": "", "pqc_network_readiness": {},
                        "migration_simulation": {}, "blast_radius": {}, "geographic_exposure": {},
                        "passive_observations": [], "plugins": []}

        monkeypatch.setattr(engine_mod, "GlobalNetworkDiscoveryEngine", FakeEngine)
        scanner = NetworkTlsScanner(live=True, timeout=2.0)
        scanner.discover_network(["10.0.0.1"])
        assert captured["mode"] == "SAFE"

    def test_discover_network_converts_passive_dicts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import network_scanner.enterprise.engine as engine_mod

        seen: dict = {}

        class FakeEngine:
            def __init__(self, **kw) -> None:
                pass

            def run(self, scope_specs, **kw):
                seen["sources"] = list(kw.get("passive_sources") or [])
                return {"scan_metadata": {}, "scope": [], "assets": [], "findings": [],
                        "protocol_observations": [], "tunnels": [], "tls_intelligence": [],
                        "certificate_intelligence": {}, "topology": {}, "topology_edge_counts": {},
                        "neo4j_cypher": "", "pqc_network_readiness": {},
                        "migration_simulation": {}, "blast_radius": {}, "geographic_exposure": {},
                        "passive_observations": [], "plugins": []}

        monkeypatch.setattr(engine_mod, "GlobalNetworkDiscoveryEngine", FakeEngine)
        scanner = NetworkTlsScanner(live=True, timeout=2.0)
        scanner.discover_network(["10.0.0.1"], passive_sources=[
            {"kind": "FIREWALL_LOG", "name": "fw", "lines": ["tls=1.2"]},
        ])
        assert len(seen["sources"]) == 1
        assert seen["sources"][0].kind == "FIREWALL_LOG"

    def test_deep_without_authorization_raises(self) -> None:
        from network_scanner.enterprise.scan_modes import ScanMode

        with pytest.raises(ValueError):
            ScanMode("DEEP")


class TestCliWiring:
    def test_cli_scope_parses(self, tmp_path, capsys: pytest.CaptureFixture) -> None:
        from network_scanner.main import main

        # localhost: no sweep, no UDP init in SAFE mode; TLS probe is refused
        out = tmp_path / "discovery.json"
        argv = ["--scope", "localhost", "--mode", "safe", "--plugin", "cisco",
                "-o", str(out)]
        try:
            code = main(argv)
        except SystemExit as exc:  # argparse may exit for missing target
            code = exc.code
        data = json.loads(out.read_text())
        # either a full report or a clean probe-error finding; the CLI must
        # not crash or leak secret material
        assert code in (0, 1)
        assert data["scan_metadata"]["scan_mode"] == "SAFE"
        assert "password" not in json.dumps(data) or "REDACTED" in json.dumps(data)

    def test_default_plugins(self) -> None:
        assert "snmp" in DEFAULT_PLUGINS
        assert "cisco" in DEFAULT_PLUGINS
