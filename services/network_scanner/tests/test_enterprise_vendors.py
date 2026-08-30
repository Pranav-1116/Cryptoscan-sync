"""Enterprise layer — multi-vendor plugin system (spec areas 3, 4, 5).

Cisco running-config parsers (IOS/IOS-XE/IOS-XR/NX-OS/ASA/Firepower),
VPN metadata with PSK metadata-only (never the key), the CiscoPlugin
contract, controller adapters, and the 12-plugin registry including the
10 thin vendor plugins.
"""

from __future__ import annotations

import pytest

from network_scanner.enterprise.vendors import REGISTRY
from network_scanner.enterprise.vendors.base import NetworkVendorPlugin, PluginRegistry
from network_scanner.enterprise.vendors.cisco import (
    AciControllerAdapter,
    CiscoControllerAdapter,
    CiscoPlugin,
    DnaCenterControllerAdapter,
    FirepowerControllerAdapter,
    MerakiControllerAdapter,
    SdwanControllerAdapter,
    classify_cisco_device,
    parse_cisco_running_config,
)
from network_scanner.enterprise.vendors.generic import GenericSNMPPlugin

CISCO_CONFIG = """\
hostname edge-router.dxb.example.com
!
crypto isakmp policy 10
 encryption 3des
 hash sha
 authentication pre-share
 group 2
crypto isakmp policy 20
 encryption aes
 hash sha256
 authentication pre-share
 group 14
crypto isakmp key super-secret-psk address 10.0.0.2
!
crypto ikev2 proposal strong-proposal
 encryption aes-cbc-256
 integrity sha256
 group 19
!
crypto ipsec transform-set TS1 esp-3des esp-md5-hmac
crypto ipsec transform-set TS2 esp-aes 256 esp-sha256-hmac
!
crypto map CMAP 10 ipsec-isakmp
 set pfs group14
 set peer 10.0.0.2
!
ip ssh version 2
ip ssh server algorithm encryption aes128-ctr aes256-ctr
ip ssh server algorithm mac hmac-sha2-256
!
crypto pki trustpoint TP-ROOT
 enrollment terminal
crypto pki certificate chain TP-ROOT
 certificate ca 01
  MIIB
  -----END CERTIFICATE-----
!
router ospf 1
 area 0 authentication message-digest
 network 10.0.0.0 0.255.255.255 area 0
!
router bgp 65000
 neighbor 10.0.0.2 remote-as 65001
 neighbor 10.0.0.2 password encrypted 7 08315C4D
!
crypto engine hardware acceleration
license feature crypto-strong enabled
"""


class TestCiscoParsers:
    def test_classify_platforms(self) -> None:
        assert classify_cisco_device("Cisco IOS Software, C3750")["platform"] == "IOS"
        assert classify_cisco_device("Cisco ASR 1000 Series")["platform"] == "ASR"
        assert classify_cisco_device("Cisco IOS XE Software")["platform"] == "IOS-XE"
        assert classify_cisco_device("Cisco IOS XR Software")["platform"] == "IOS-XR"
        assert classify_cisco_device("Cisco NX-OS")["platform"] == "NX-OS"
        assert classify_cisco_device("Adaptive Security Appliance")["platform"] == "ASA"
        assert classify_cisco_device("Firepower")["platform"] == "Firepower"
        assert classify_cisco_device("Cisco IOS XE Software, Catalyst 9300")["device_type"] == "switch"
        assert classify_cisco_device("", model="ISR4431")["device_type"] == "router"
        assert classify_cisco_device("", model="Meraki MX100")["device_type"] == "cloud_appliance"

    def test_parse_ikev1_policies(self) -> None:
        profile = parse_cisco_running_config(CISCO_CONFIG)
        assert profile["ikev1"][0]["policy"] == 10
        assert profile["ikev1"][0]["encryption"] == "3des"
        assert profile["ikev1"][1]["group"] == 14
        # PSK is metadata: the key value is never captured
        assert "super-secret-psk" not in str(profile)
        assert profile["vpn"]["psk_peers"] == ["10.0.0.2"]
        assert profile["vpn"]["pre_shared_key_used"] is True

    def test_parse_ikev2_proposals(self) -> None:
        profile = parse_cisco_running_config(CISCO_CONFIG)
        strong = profile["ikev2"][0]
        assert strong["name"] == "strong-proposal"
        assert "aes-cbc-256" in strong["encryption"]
        assert 19 in strong["group"]

    def test_parse_transform_sets(self) -> None:
        profile = parse_cisco_running_config(CISCO_CONFIG)
        by_name = {ts["name"]: ts for ts in profile["ipsec_transform_sets"]}
        assert "esp-3des" in by_name["TS1"]["esp"]
        assert "esp-aes" in by_name["TS2"]["esp"]
        assert "256" in by_name["TS2"]["esp"]

    def test_weakness_detection(self) -> None:
        profile = parse_cisco_running_config(CISCO_CONFIG)
        issues = profile["issues"]
        assert any("WEAK_IKEV1_ENCRYPTION:10:3des" in i for i in issues)
        assert any("WEAK_IKEV1_DH_GROUP:10:2" in i for i in issues)
        assert any("WEAK_IPSEC_ESP:TS1:esp-3des" in i for i in issues)

    def test_ssh_and_tls(self) -> None:
        profile = parse_cisco_running_config(CISCO_CONFIG)
        assert profile["ssh"]["version"] == 2
        assert profile["ssh"]["ciphers"] == ["aes128-ctr", "aes256-ctr"]
        assert profile["ssh"]["mac"] == ["hmac-sha2-256"]
        assert profile["tls"]["trustpoints"] == ["TP-ROOT"]

    def test_pki_chains_redacted(self) -> None:
        profile = parse_cisco_running_config(CISCO_CONFIG)
        chains = profile["pki"]["certificate_chains"]
        assert chains[0]["name"] == "TP-ROOT"
        # cert bodies are redacted, only presence is recorded
        assert all("MIIB" not in str(c) for c in chains)

    def test_routing_auth(self) -> None:
        profile = parse_cisco_running_config(CISCO_CONFIG)
        assert profile["routing_auth"]["ospf_authenticated_areas"] == [{"area": "0", "algorithm": "MD5"}]
        # BGP auth metadata only — password value never captured
        assert profile["routing_auth"]["bgp_neighbors"] == [
            {"neighbor": "10.0.0.2", "algorithm": "password", "secret_redacted": True}]
        assert "08315C4D" not in str(profile)

    def test_hardware_crypto_and_licenses(self) -> None:
        profile = parse_cisco_running_config(CISCO_CONFIG)
        assert "crypto engine" in str(profile["hardware"].get("hardware_crypto") or "")
        assert any("crypto-strong" in line for line in profile["licenses"]["crypto_licenses"])

    def test_no_pfs_detected(self) -> None:
        profile = parse_cisco_running_config(CISCO_CONFIG)
        assert "IPSEC_NO_PFS" not in profile["issues"]  # set pfs group14 present
        bare = parse_cisco_running_config("crypto map M 1 ipsec-isakmp\n set peer 10.0.0.2\n")
        assert "IPSEC_NO_PFS" in bare["issues"]


class TestCiscoPlugin:
    def test_plugin_registered(self) -> None:
        assert "cisco" in REGISTRY.names()
        assert issubclass(REGISTRY.get("cisco"), NetworkVendorPlugin)

    def test_normalize(self) -> None:
        plugin = CiscoPlugin()
        normalized = plugin.normalize({"ip": "10.1.1.1", "hostname": "r1",
                                       "version_banner": "Cisco IOS XE Software, ASR1000",
                                       "source": "controller", "model": "ASR1002"})
        assert normalized["asset_identity"] == "10.1.1.1"
        assert normalized["manufacturer"] == "Cisco"
        assert normalized["os"] == "IOS-XE"
        assert normalized["device_type"] == "router"
        assert normalized["discovery_confidence"] == 0.9

    def test_collect_crypto_from_running_config(self) -> None:
        plugin = CiscoPlugin()
        profile = plugin.collect_crypto_configuration({"ip": "10.0.0.1"},
                                                      running_config=CISCO_CONFIG)
        assert profile["config_available"] is True
        assert profile["ikev1"]
        # no secrets anywhere in the collected profile
        for secret in ("super-secret-psk", "08315C4D"):
            assert secret not in str(profile)

    def test_collect_protocols(self) -> None:
        plugin = CiscoPlugin()
        device = {"ip": "10.0.0.1"}
        profile = plugin.collect_crypto_configuration(device, running_config=CISCO_CONFIG)
        protocols = plugin.collect_protocols(device, crypto_profile=profile)
        by_proto = {p["protocol"]: p for p in protocols}
        assert by_proto["IPsec"]["status"] == "CRYPTOGRAPHY_CONFIGURED"
        assert by_proto["SSH"]["status"] == "CRYPTOGRAPHY_CONFIGURED"
        assert "OSPF-AUTH" in by_proto
        assert "BGP-AUTH" in by_proto

    def test_collect_certificates_redacted(self) -> None:
        plugin = CiscoPlugin()
        profile = plugin.collect_crypto_configuration({"ip": "10.0.0.1"},
                                                      running_config=CISCO_CONFIG)
        certs = plugin.collect_certificates({"ip": "10.0.0.1"}, crypto_profile=profile)
        assert certs[0]["name"] == "TP-ROOT"
        assert certs[0]["certificate_pem_redacted"] is True

    def test_collect_topology_from_routes(self) -> None:
        plugin = CiscoPlugin()
        edges = plugin.collect_topology([{
            "asset_identity": "r1", "routes": [{"routeNextHop": "10.0.0.254"}],
            "neighbors": ["sw1.example.com"],
        }])
        relationships = {e["relationship"] for e in edges}
        assert "ROUTES_TO" in relationships
        assert "CONNECTED_TO" in relationships

    def test_discover_devices_with_injected_client(self) -> None:
        class FakeClient:
            def list_devices(self) -> list[dict]:
                return [{"ip": "10.9.9.9", "source": "controller", "vendor": "Cisco"}]

        plugin = CiscoPlugin()
        devices = plugin.discover_devices(["10.0.0.1"], client=FakeClient())
        assert any(d.get("ip") == "10.9.9.9" for d in devices)
        assert any(d.get("ip") == "10.0.0.1" for d in devices)


class TestControllerAdapters:
    @pytest.mark.parametrize("adapter_cls", [
        CiscoControllerAdapter, MerakiControllerAdapter, DnaCenterControllerAdapter,
        SdwanControllerAdapter, AciControllerAdapter, FirepowerControllerAdapter,
    ])
    def test_adapter_interface(self, adapter_cls: type) -> None:
        class Empty:
            pass

        adapter = adapter_cls(Empty())
        assert adapter.collect_crypto({}) == {"config_available": False}
        assert adapter.collect_topology() == []
        with pytest.raises(NotImplementedError):
            adapter.list_devices()

    def test_adapter_accepts_real_client(self) -> None:
        class Fake:
            def list_devices(self) -> list[dict]:
                return [{"ip": "10.0.0.5"}]

        adapter = DnaCenterControllerAdapter(Fake())
        assert adapter.list_devices() == [{"ip": "10.0.0.5"}]


class TestVendorRegistry:
    EXPECTED_VENDORS = {"cisco", "snmp", "juniper", "paloalto", "fortinet",
                        "checkpoint", "f5", "arista", "huawei", "mikrotik",
                        "ubiquiti", "vmware"}

    def test_all_plugins_registered(self) -> None:
        assert set(REGISTRY.names()) == self.EXPECTED_VENDORS

    def test_every_plugin_implements_contract(self) -> None:
        for name in self.EXPECTED_VENDORS:
            plugin_cls = REGISTRY.get(name)
            plugin = plugin_cls()
            for method in ("discover_devices", "collect_inventory", "collect_crypto_configuration",
                           "collect_certificates", "collect_protocols", "collect_topology", "normalize"):
                assert callable(getattr(plugin, method)), f"{name}.{method}"

    def test_registry_override_is_last_wins(self) -> None:
        registry = PluginRegistry()
        registry.register(CiscoPlugin)

        class CustomCisco(CiscoPlugin):
            vendor = "cisco"
            custom = True

        registry.register(CustomCisco)
        assert registry.get("cisco") is CustomCisco

    def test_registry_instantiate_unknown_raises(self) -> None:
        registry = PluginRegistry()
        with pytest.raises(KeyError):
            registry.instantiate("acme")

    def test_thin_vendors_normalize(self) -> None:
        for name in ("juniper", "paloalto", "fortinet", "checkpoint", "f5",
                     "arista", "huawei", "mikrotik", "ubiquiti", "vmware"):
            plugin = REGISTRY.get(name)()
            normalized = plugin.normalize({"ip": "10.0.0.77", "vendor": name.title(),
                                           "hostname": "dev", "sys_descr": "device"})
            assert normalized["asset_identity"] == "10.0.0.77"
            assert normalized["manufacturer"] == name.title()

    def test_snmp_plugin_discovery_metadata_only(self) -> None:
        plugin = GenericSNMPPlugin(community="public")
        profile = plugin.collect_crypto_configuration({"ip": "10.0.0.1", "security_mode": "SNMPv3-authPriv"})
        assert profile["security_mode"] == "SNMPv3-authPriv"
        assert profile["config_available"] is False
        assert "community" not in profile
        assert not any("public" == v for k, v in profile.items() if isinstance(v, str))

    def test_can_handle(self) -> None:
        plugin = CiscoPlugin()
        assert plugin.can_handle("router")
        assert not plugin.can_handle("camera")
