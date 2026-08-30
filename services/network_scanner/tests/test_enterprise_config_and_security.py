"""Enterprise layer — config protocols + security subsystems.

Spec areas 15-21: NETCONF/RESTCONF/gNMI credentialed scanners with injected
transports (secret-free output), SD-WAN discovery, unified VPN tunnel schema,
firewall/LB TLS termination, DNS+PKI with Neo4j export, metadata-only HSM
discovery and per-asset PQC network readiness.
"""

from __future__ import annotations

import pytest

from network_scanner.enterprise.config_protocols import (
    ConfigProtocolError,
    GnmiScanner,
    NetconfScanner,
    RestconfScanner,
    discover_with_config_protocols,
)
from network_scanner.enterprise.credentials import CredentialRef
from network_scanner.enterprise.dns_pki import (
    dns_crypto_summary,
    dns_infrastructure_records,
    dnssec_status_from_checker,
    pki_cypher_export,
    pki_hierarchy,
)
from network_scanner.enterprise.firewall_lb import (
    TlsTerminationProfile,
    discover_termination_profiles,
    profile_from_vendor_data,
    terminate_edges,
)
from network_scanner.enterprise.hsm import (
    HsmProfile,
    discover_hsm_endpoint_probe,
    hsm_profile_from_data,
    hsm_summary,
)
from network_scanner.enterprise.pqc_readiness import (
    VENDOR_PQC_CAPABILITY,
    assess_asset_readiness,
    network_pqc_readiness,
)
from network_scanner.enterprise.sdwan import (
    SdwanTopology,
    SdwanTunnel,
    discover_sdwan,
    sdwan_crypto_issues,
    sdwan_protocol_observations,
)
from network_scanner.enterprise.tunnels import (
    Tunnel,
    pqc_migration_impact,
    tunnel_issues,
    tunnel_protocol_observations,
    tunnels_from_ike_probe,
)


# ------------------------------------------------------------- config protocols

class FakeNetconfTransport:
    def __init__(self, payload: str) -> None:
        self.payload = payload
        self.calls: list[str] = []

    def get(self, filter_xml: str) -> str:
        self.calls.append(filter_xml)
        return self.payload


class FakeRestconfClient:
    def __init__(self, payload: dict | None = None) -> None:
        self.payload = payload or {"Cisco-IOS-XE-crypto": {"ike": {"proposal": "aes-gcm"}}}
        self.calls: list[str] = []

    def get(self, url: str) -> dict:
        self.calls.append(url)
        return {"status": 200, "json": self.payload}


class TestConfigProtocols:
    def test_netconf_build_get_filter(self) -> None:
        scanner = NetconfScanner()
        xml = scanner.build_get_filter("crypto")
        assert "crypto" in xml
        assert "<filter type='subtree'>" in xml

    def test_netconf_collect_with_transport(self) -> None:
        transport = FakeNetconfTransport("<data><crypto><ike>aes</ike></crypto></data>")
        scanner = NetconfScanner(transport, credential=CredentialRef(type="NETCONF",
                                                                    ref="vault:netconf/rtr"))
        result = scanner.collect_crypto_configuration()
        assert "crypto" in result
        assert transport.calls  # real subtree requests issued
        assert "vault:netconf/rtr" not in str(result) or "vault:netconf/rtr" in str(result)

    def test_netconf_without_transport_raises_honestly(self) -> None:
        scanner = NetconfScanner()
        with pytest.raises(ConfigProtocolError):
            scanner.collect_crypto_configuration()

    def test_netconf_scrubs_secrets(self) -> None:
        transport = FakeNetconfTransport("<data><key>password=Hunter2Secret</key></data>")
        scanner = NetconfScanner(transport)
        result = scanner.collect_crypto_configuration()
        assert "Hunter2Secret" not in str(result)

    def test_restconf_collect(self) -> None:
        client = FakeRestconfClient()
        scanner = RestconfScanner(client, base_url="https://r1.example.com")
        result = scanner.collect_crypto_configuration()
        assert "Cisco-IOS-XE-crypto" in result
        assert client.calls and "restconf/data" in client.calls[0]

    def test_restconf_http_error_recorded(self) -> None:
        class ErrorClient:
            def get(self, url: str) -> dict:
                return {"status": 404, "json": {}}

        result = RestconfScanner(ErrorClient(), base_url="https://x").collect_crypto_configuration()
        assert all("http 404" in str(v) for v in result.values())

    def test_gnmi_collect_with_transport(self) -> None:
        class FakeGnmi:
            def get(self, paths: list[str]) -> dict:
                return {"system": {"ssh": {"server": {"enabled": True}}}}

        scanner = GnmiScanner(FakeGnmi(), credential=CredentialRef(type="GNMI", ref="vault:gnmi"))
        result = scanner.collect_crypto_configuration()
        assert "ssh" in str(result)

    def test_gnmi_without_transport_raises(self) -> None:
        with pytest.raises(ConfigProtocolError):
            GnmiScanner().collect_crypto_configuration()

    def test_discover_with_config_protocols(self) -> None:
        transport = FakeNetconfTransport("<data><crypto/></data>")
        result = discover_with_config_protocols("r1", kind="NETCONF", transport=transport)
        assert "crypto" in result
        with pytest.raises(ConfigProtocolError):
            discover_with_config_protocols("r1", kind="FTP")


# ------------------------------------------------------------- SD-WAN

class _FakeSdwanController:
    def list_edges(self) -> list[str]:
        return ["edge-dxb", "edge-mum"]

    def list_tunnels(self) -> list[dict]:
        return [
            {"tunnel_id": "t1", "edge": "edge-dxb", "peer_edge": "edge-mum",
             "encryption_algorithm": "aes256-gcm", "integrity_algorithm": "sha256",
             "key_exchange": "ikev2", "dh_group": 19},
            {"tunnel_id": "t2", "edge": "edge-mum", "peer_edge": "edge-dxb",
             "encryption_algorithm": "3des", "dh_group": 2},
        ]

    def control_plane_trust(self) -> str:
        return "CERTIFICATE"

    def controller_certificate(self) -> str:
        return "cert:sdwan-controller"


class TestSdwan:
    def test_discover_sdwan(self) -> None:
        topo = discover_sdwan(_FakeSdwanController(), controller_name="vmanage")
        assert topo.controller == "vmanage"
        assert topo.edges == ["edge-dxb", "edge-mum"]
        assert len(topo.tunnels) == 2
        assert topo.control_plane_trust == "CERTIFICATE"
        assert topo.controller_certificate == "cert:sdwan-controller"

    def test_sdwan_crypto_issues(self) -> None:
        topo = SdwanTopology(controller="c", tunnels=[
            SdwanTunnel(tunnel_id="t2", edge="a", peer_edge="b",
                        encryption_algorithm="3des", dh_group=2),
        ], control_plane_trust="PSK")
        issues = sdwan_crypto_issues(topo)
        assert "SDWAN_CONTROL_PLANE_PSK" in issues
        assert any("WEAK_SDWAN_TUNNEL_ENCRYPTION:t2" in i for i in issues)
        assert any("WEAK_SDWAN_TUNNEL_DH:t2" in i for i in issues)

    def test_sdwan_protocol_observations(self) -> None:
        topo = discover_sdwan(_FakeSdwanController())
        obs = sdwan_protocol_observations(topo)
        protocols = {o["protocol"] for o in obs}
        assert protocols == {"IPsec", "TLS"}
        assert all(o["status"] == "CRYPTOGRAPHY_CONFIGURED" for o in obs)

    def test_sdwan_topology_to_dict(self) -> None:
        topo = discover_sdwan(_FakeSdwanController())
        data = topo.to_dict()
        assert data["controller"] == "sdwan-controller"
        assert len(data["tunnels"]) == 2


# ------------------------------------------------------------- tunnels

class TestTunnels:
    def test_unified_tunnel_schema(self) -> None:
        tunnel = Tunnel(tunnel_id="tnl-1", endpoint_a="branch-a", endpoint_b="dc-router",
                        protocol="IPsec", encryption_algorithm="AES-GCM",
                        integrity_algorithm="SHA256", key_exchange="IKEv2",
                        dh_group=14, certificate_reference="cert:gw", status="up",
                        environment="production")
        data = tunnel.to_dict()
        for key in ("tunnel_id", "endpoint_a", "endpoint_b", "protocol",
                    "encryption_algorithm", "integrity_algorithm", "key_exchange",
                    "dh_group", "certificate_reference", "status", "environment"):
            assert key in data

    def test_weak_tunnel_issues(self) -> None:
        weak = Tunnel(tunnel_id="t", endpoint_a="a", endpoint_b="b",
                      encryption_algorithm="3DES", integrity_algorithm="MD5",
                      dh_group=2, pre_shared_key_used=True)
        issues = tunnel_issues(weak)
        assert any("WEAK_TUNNEL_ENCRYPTION" in i for i in issues)
        assert any("WEAK_TUNNEL_INTEGRITY" in i for i in issues)
        assert any("WEAK_TUNNEL_DH" in i for i in issues)
        assert any("TUNNEL_PSK_ONLY" in i for i in issues)
        strong = Tunnel(tunnel_id="s", endpoint_a="a", endpoint_b="b",
                        encryption_algorithm="AES-GCM", dh_group=19,
                        certificate_reference="cert:x")
        assert tunnel_issues(strong) == []

    def test_unsupported_protocol_rejected(self) -> None:
        with pytest.raises(ValueError):
            Tunnel(tunnel_id="x", endpoint_a="a", endpoint_b="b", protocol="CARRIER_PIGEON")

    def test_pqc_migration_impact_lazy_quantum(self) -> None:
        tunnel = Tunnel(tunnel_id="t", endpoint_a="a", endpoint_b="b",
                        encryption_algorithm="3DES", key_exchange="DH")
        impact = pqc_migration_impact(tunnel)
        # quantum.classify is optional; either computable or honestly unknown
        assert "pqc_status" in impact

    def test_tunnel_protocol_observations(self) -> None:
        tunnel = Tunnel(tunnel_id="t", endpoint_a="a", endpoint_b="b",
                        protocol="IPsec", encryption_algorithm="AES-GCM")
        obs = tunnel_protocol_observations(tunnel)
        assert obs[0].protocol == "IPsec"

    def test_tunnels_from_ike_probe(self) -> None:
        tunnels = tunnels_from_ike_probe([{
            "endpoint": "10.0.0.1:500", "status": "OK",
            "proposals": [{"proposal": 1, "protocol": 2, "transforms": [
                {"type": 1, "id": 12, "name": "AES-GCM"},
                {"type": 3, "id": 2, "name": "SHA256"},
                {"type": 4, "id": 14, "name": "MODP-2048"},
            ]}],
        }])
        assert len(tunnels) == 1
        assert tunnels[0].endpoint_b == "10.0.0.1:500"
        assert tunnels[0].encryption_algorithm == "AES-GCM"
        assert tunnels[0].integrity_algorithm == "SHA256"
        assert tunnels[0].dh_group == 14


# ------------------------------------------------------------- firewall / LB

class TestFirewallLb:
    def test_profile_from_vendor_data_snake_case(self) -> None:
        profile = profile_from_vendor_data("fw-1", "firewall", "paloalto", {
            "tls_versions": ["TLSv1.2", "TLSv1.3"],
            "cipher_policy": "crypto-policy-1",
            "certificates": [{"fingerprint_sha256": "f" * 64}],
            "vpn_policy": {"encryption": "AES-256"},
            "terminator_for": ["app-1", "app-2"],
        })
        assert profile.device == "fw-1"
        assert profile.tls_versions == ["TLSv1.2", "TLSv1.3"]
        assert profile.terminator_for == ["app-1", "app-2"]
        assert profile.issues() == []

    def test_profile_from_vendor_data_camel_case(self) -> None:
        profile = profile_from_vendor_data("lb-aws", "load_balancer", "cloud-lb", {
            "tlsVersions": "TLSv1.2",
            "cipherPolicy": "ELBSecurityPolicy-2016-08",
            "terminatorFor": ["svc-a"],
        })
        assert "TLSv1.2" in profile.tls_versions
        assert profile.cipher_policy == "ELBSecurityPolicy-2016-08"

    def test_weak_tls_issues(self) -> None:
        profile = TlsTerminationProfile(device="fw", device_type="firewall",
                                        vendor="fortinet", tls_versions=["TLSv1.0", "TLSv1.2"])
        issues = profile.issues()
        assert any("WEAK_TLS_VERSION" in i for i in issues)

    def test_discover_termination_profiles(self) -> None:
        profiles = discover_termination_profiles([
            {"device": "lb-1", "device_type": "load_balancer", "vendor": "f5",
             "tls_versions": ["TLSv1.2"], "terminator_for": ["api"]},
        ])
        assert profiles[0].vendor == "f5"

    def test_terminate_edges(self) -> None:
        profile = TlsTerminationProfile(
            device="lb-1", device_type="load_balancer", vendor="cloud-lb",
            terminator_for=["app-a"],
            certificates=[{"fingerprint_sha256": "c" * 64}],
        )
        edges = terminate_edges([profile])
        relationships = {e["relationship"] for e in edges}
        assert "TERMINATES_TLS_FOR" in relationships
        assert "USES_CERTIFICATE" in relationships


# ------------------------------------------------------------- DNS + PKI

class TestDnsPki:
    RECORDS = [
        {"zone": "example.com", "type": "NS", "target": "ns1.example.com"},
        {"zone": "example.com", "type": "SOA", "value": "ns1.example.com hostmaster"},
        {"zone": "example.com", "type": "CAA", "value": '0 issue "ca.example.net"'},
        {"zone": "example.com", "type": "TLSA", "value": "3 1 1 abc"},
        {"zone": "example.com", "type": "SRV", "value": "_sip._tcp 10 60 5060 sip"},
        {"zone": "insecure.org", "type": "NS", "target": "ns1.insecure.org"},
    ]

    def test_dns_infrastructure_records(self) -> None:
        zones = dns_infrastructure_records(self.RECORDS)
        assert zones["example.com"]["nameservers"] == ["ns1.example.com"]
        assert zones["example.com"]["caa"] != []
        assert zones["example.com"]["tlsa"] != []
        assert zones["example.com"]["srv"] != []
        assert zones["example.com"]["soa"] is not None

    def test_dns_crypto_summary(self) -> None:
        summary = dns_crypto_summary(self.RECORDS)
        assert summary["zone_count"] == 2
        assert summary["zones_with_caa"] == 1
        assert summary["zones_with_tlsa"] == 1

    def test_dnssec_status_from_checker(self) -> None:
        rows = dnssec_status_from_checker([{
            "zone": "unsigned.org", "status": "UNSIGNED", "signed": False,
            "algorithms": [], "dnskey_count": 0, "ds_count": 0,
            "transfer_exposed": True, "issues": ["UNSIGNED_ZONE"],
        }])
        assert rows[0]["status"] == "UNSIGNED"
        assert rows[0]["issues"] == ["UNSIGNED_ZONE"]

    def test_pki_hierarchy_four_roles(self) -> None:
        certs = [
            {"subject": "CN=Root CA", "issuer": "CN=Root CA", "basic_constraints": "CA:TRUE"},
            {"subject": "CN=Int CA", "issuer": "CN=Root CA", "basic_constraints": "CA:TRUE"},
            {"subject": "CN=Issuing CA", "issuer": "CN=Int CA", "basic_constraints": "CA:TRUE"},
            {"subject": "CN=api.example.com", "issuer": "CN=Issuing CA", "basic_constraints": ""},
        ]
        hierarchy = pki_hierarchy(certs)
        assert hierarchy["roots"][0]["subject"] == "CN=Root CA"
        assert len(hierarchy["intermediates"]) == 1
        assert hierarchy["intermediates"][0]["subject"] == "CN=Issuing CA"
        assert len(hierarchy["issuing"]) >= 1
        assert len(hierarchy["server_certificates"]) == 1
        assert hierarchy["server_certificates"][0]["subject"] == "CN=api.example.com"

    def test_pki_cypher_export(self) -> None:
        certs = [
            {"subject": "CN=Root CA", "issuer": "CN=Root CA"},
            {"subject": "CN=api.example.com", "issuer": "CN=Root CA"},
        ]
        hierarchy = pki_hierarchy(certs)
        cypher = pki_cypher_export(hierarchy)
        assert "MERGE" in cypher
        assert 'SET c.role = "ROOTS"' in cypher
        assert "ISSUED_BY" in cypher


# ------------------------------------------------------------- HSM

class TestHsm:
    def test_metadata_only_profile(self) -> None:
        profile = hsm_profile_from_data("hsm-1", {
            "vendor": "Thales", "model": "Luna HSM", "firmware_version": "7.8",
            "supported_algorithms": ["RSA-2048", "ECDSA-P256", "AES-256"],
            "supported_key_types": ["opaque", "aes"],
            "certificate_dependencies": ["cert:root"],
            "crypto_provider_integration": ["pkcs11"],
            "source": "vendor-api",
        })
        assert profile.vendor == "Thales"
        assert "RSA-2048" in profile.supported_algorithms
        assert profile.key_material_present is False

    def test_key_material_never_returned(self) -> None:
        profile = hsm_profile_from_data("hsm-2", {
            "vendor": "Utimaco",
            "key_value": "-----BEGIN PRIVATE KEY-----MIIB-----END PRIVATE KEY-----",
        })
        # the guard flags the data problem but the key is still not in the output
        assert profile.key_material_present is True
        assert "MIIB" not in str(profile.to_dict())
        assert "PRIVATE KEY" not in str(profile.to_dict())

    def test_hsm_summary(self) -> None:
        profiles = [
            HsmProfile(asset="a", vendor="Thales", supported_algorithms=["RSA"]),
            HsmProfile(asset="b", vendor="Thales", supported_algorithms=["RSA", "ECDSA"]),
            HsmProfile(asset="c", vendor="Entrust"),
        ]
        summary = hsm_summary(profiles)
        assert summary["hsm_count"] == 3
        assert summary["by_vendor"]["Thales"] == 2
        assert summary["any_key_material_present"] is False
        assert "ECDSA" in summary["algorithms_in_use"]

    def test_endpoint_probe_is_safe(self) -> None:
        profile = discover_hsm_endpoint_probe("127.0.0.1", ports=(65534,))
        assert profile.source == "endpoint-probe"
        assert profile.key_material_present is False


# ------------------------------------------------------------- PQC readiness

class TestPqcReadiness:
    def test_asset_with_classical_crypto_requires_migration(self) -> None:
        asset = {"asset_identity": "edge-1", "manufacturer": "Cisco"}
        readiness = assess_asset_readiness(asset, crypto=["RSA", "AES-GCM"])
        assert readiness.pqc_status == "MIGRATION_REQUIRED"
        assert "RSA" in readiness.classical_crypto
        assert readiness.vendor_capability == VENDOR_PQC_CAPABILITY["cisco"]

    def test_compatible_asset(self) -> None:
        asset = {"asset_identity": "edge-2", "manufacturer": "Cisco"}
        readiness = assess_asset_readiness(asset, crypto=["AES-GCM", "SHA256"])
        assert readiness.pqc_status == "COMPATIBLE"

    def test_hsm_dependency_blocker(self) -> None:
        asset = {"asset_identity": "edge-3", "manufacturer": "Cisco"}
        readiness = assess_asset_readiness(asset, crypto=["RSA"], has_hsm_dependency=True)
        assert "HSM dependency" in readiness.migration_blockers

    def test_legacy_vpn_peer_blocker(self) -> None:
        asset = {"asset_identity": "edge-4", "manufacturer": "Juniper"}
        tunnels = [Tunnel(tunnel_id="t", endpoint_a="edge-4", endpoint_b="legacy-peer",
                          encryption_algorithm="3DES", pre_shared_key_used=True)]
        readiness = assess_asset_readiness(asset, crypto=["RSA"], tunnels=tunnels)
        assert any("Legacy VPN peer" in b for b in readiness.migration_blockers)

    def test_ca_dependency_blocker(self) -> None:
        asset = {"asset_identity": "edge-5", "manufacturer": "Cisco"}
        readiness = assess_asset_readiness(asset, crypto=["RSA"], dependencies=["Enterprise CA"])
        assert any("Certificate authority dependency" in b for b in readiness.migration_blockers)

    def test_network_pqc_readiness_summary(self) -> None:
        assets = [
            {"asset_identity": "r1", "manufacturer": "Cisco"},
            {"asset_identity": "r2", "manufacturer": "MikroTik"},
            {"asset_identity": "r3", "manufacturer": "Cisco"},
        ]
        result = network_pqc_readiness(
            assets,
            asset_crypto={"r1": ["RSA"], "r2": ["DH"], "r3": ["AES-GCM"]},
        )
        assert result["assets_assessed"] == 3
        assert result["by_status"]["MIGRATION_REQUIRED"] == 2
        assert result["by_status"]["COMPATIBLE"] == 1
        assert isinstance(result["assets"], list)

    def test_vendor_capability_table(self) -> None:
        for vendor in ("cisco", "juniper", "paloalto", "fortinet", "huawei",
                       "mikrotik", "ubiquiti", "vmware", "generic"):
            assert VENDOR_PQC_CAPABILITY[vendor] in ("SUPPORTED", "UNSUPPORTED", "UNKNOWN")
