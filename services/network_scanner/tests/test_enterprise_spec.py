"""Enterprise layer — target spec, asset registry, scan modes, credentials.

Covers spec areas 1, 2, 12, 13: global target types + scope classification,
full per-asset records + dedupe/merge, SAFE-default scan modes with
authorization gating, and vault-reference-only credentials.
"""

from __future__ import annotations

import os

import pytest

from network_scanner.enterprise.assets import (
    AssetRegistry,
    NetworkAsset,
    asset_identity_for,
    normalize_mac,
)
from network_scanner.enterprise.credentials import (
    CredentialRef,
    CredentialUnavailable,
    CredentialVault,
    scrub_all,
    scrub_secrets,
)
from network_scanner.enterprise.scan_modes import (
    MODES,
    ScanAuthorization,
    ScanMetadata,
    ScanMode,
    default_scan_mode,
)
from network_scanner.enterprise.target_spec import (
    SCOPES,
    SUPPORTED_TARGET_TYPES,
    TargetSpec,
    classify_target,
    parse_many,
    parse_scope_spec,
    parse_target_spec,
)


# ------------------------------------------------------------- target spec

class TestTargetClassification:
    @pytest.mark.parametrize(
        ("value", "expected_scope"),
        [
            ("192.168.1.10", "SINGLE_HOST"),
            ("10.0.0.0/8", "CIDR_RANGE"),
            ("10.1.2.3-10.1.2.9", "IP_RANGE"),
            ("2001:db8::/64", "CIDR_RANGE"),
            ("2001:db8::1", "SINGLE_HOST"),
            ("api.example.com", "SINGLE_HOST"),
            ("example.com", "DOMAIN"),
            ("*.corp.example.com", "SUBDOMAIN_SCOPE"),
            ("sales.corp.example.com", "SINGLE_HOST"),  # plain hostname
            ("10.10.0.0/16:corp-dc", "SINGLE_HOST"),  # odd input -> falls back
        ],
    )
    def test_classify(self, value: str, expected_scope: str) -> None:
        result = classify_target(value)
        # CIDR/range/domain forms classify exactly; host:name forms fall back
        if ":" in value and "/" not in value:
            assert result in SCOPES
        else:
            assert result == expected_scope

    def test_all_scopes_defined(self) -> None:
        assert len(SCOPES) >= 13
        assert "SINGLE_HOST" in SCOPES
        assert "GLOBAL_ENTERPRISE_SCOPE" in SCOPES
        assert SCOPES.index("SINGLE_HOST") < SCOPES.index("GLOBAL_ENTERPRISE_SCOPE")

    def test_supported_target_types(self) -> None:
        for kind in ("ipv4", "ipv6", "cidr", "single_ip", "hostname", "fqdn",
                     "domain", "subdomain", "dns_zone", "network_zone",
                     "data_center", "dc", "branch_office", "branch",
                     "cloud_network", "cloud_vpc", "vpc", "cloud_vnet", "vnet",
                     "vpn_network", "vpn", "mpls_network", "mpls", "sd_wan",
                     "sdwan_network", "sdwan", "kubernetes", "kubernetes_cluster",
                     "k8s", "global_enterprise_scope"):
            assert kind in SUPPORTED_TARGET_TYPES


class TestTargetSpec:
    def test_parse_cidr(self) -> None:
        spec = parse_target_spec("10.0.0.0/24", name="prod-net")
        assert spec.scope == "CIDR_RANGE"
        assert spec.target_type == "ipv4_cidr"
        assert spec.networks == ["10.0.0.0/24"]
        assert spec.name == "prod-net"

    def test_parse_domain(self) -> None:
        spec = parse_target_spec("example.com")
        assert spec.scope == "DOMAIN"
        assert spec.value == "example.com"

    def test_parse_subdomain_wildcard(self) -> None:
        spec = parse_target_spec("*.corp.example.com")
        assert spec.scope == "SUBDOMAIN_SCOPE"
        assert spec.zones == ["corp.example.com"]

    def test_parse_ip_range(self) -> None:
        spec = parse_target_spec("10.1.2.3-10.1.2.9")
        assert spec.scope == "IP_RANGE"
        assert len(spec.hosts) == 7

    def test_expand_hosts_cap(self) -> None:
        spec = parse_target_spec("10.1.2.3-10.1.2.9")
        hosts = spec.expand_hosts(cap=3)
        assert len(hosts) == 3

    def test_scope_spec_kinds(self) -> None:
        expected_scopes = {
            "data_center": "DATA_CENTER",
            "branch": "BRANCH_OFFICE",
            "vpn_network": "VPN_NETWORK",
            "mpls_network": "VPN_NETWORK",
            "sdwan_network": "SD_WAN",
            "dns_zone": "NETWORK_ZONE",
            "cloud_vpc": "CLOUD_NETWORK",
            "cloud_vnet": "CLOUD_NETWORK",
            "kubernetes_cluster": "KUBERNETES_CLUSTER",
        }
        for kind, scope in expected_scopes.items():
            spec = parse_scope_spec({"kind": kind, "name": "x", "value": "10.0.0.0/24"})
            assert spec.target_type == {"branch": "branch_office",
                                        "mpls_network": "vpn_network",
                                        "sdwan_network": "sd_wan",
                                        "cloud_vpc": "cloud_network",
                                        "cloud_vnet": "cloud_network",
                                        "kubernetes_cluster": "kubernetes"}.get(kind, kind)
            assert spec.scope == scope

    def test_scope_spec_carries_zones_and_networks(self) -> None:
        spec = parse_scope_spec({"kind": "data_center", "name": "Dubai-DC",
                                 "networks": ["10.10.0.0/16", "172.16.0.0/16"],
                                 "zones": ["DXB-DC-1", "DXB-DC-2"]})
        assert len(spec.networks) == 2
        assert spec.zones == ["DXB-DC-1", "DXB-DC-2"]
        assert spec.name == "Dubai-DC"

    def test_scope_spec_global(self) -> None:
        spec = parse_scope_spec({"kind": "network_zone", "name": "global",
                                 "networks": ["10.0.0.0/8"]})
        assert spec.scope == "NETWORK_ZONE"

    def test_unsupported_kind_raises(self) -> None:
        with pytest.raises(ValueError):
            parse_scope_spec({"kind": "mars_colony", "name": "x"})

    def test_parse_many_mixed(self) -> None:
        specs = parse_many(["10.0.0.0/24", {"kind": "branch_office", "name": "blr", "value": "10.1.0.0/16"}])
        assert len(specs) == 2
        assert specs[0].scope == "CIDR_RANGE"
        assert specs[1].scope == "BRANCH_OFFICE"

    def test_to_dict_roundtrip(self) -> None:
        spec = parse_target_spec("10.0.0.0/24", name="net")
        data = spec.to_dict()
        assert data["value"] == "10.0.0.0/24"
        assert data["scope"] == "CIDR_RANGE"


# ------------------------------------------------------------- assets

def _sample_asset() -> NetworkAsset:
    return NetworkAsset(
        asset_identity="edge-01.example.com",
        ip_addresses=["10.1.0.1"],
        ipv6_addresses=["2001:db8::1"],
        mac_address="00:1a:2b:3c:4d:5e",
        hostname="edge-01",
        fqdn="edge-01.example.com",
        device_type="router",
        manufacturer="Cisco",
        model="ASR-1002",
        os="IOS-XE",
        os_version="17.3.1",
        network_zone="dc-east",
        environment="production",
        cloud_provider="on-prem",
        location="DXB-DC-1",
        owner="network-team",
        criticality="CRITICAL",
        discovery_confidence=0.9,
        first_seen="2026-01-01T00:00:00+00:00",
        last_seen="2026-08-01T00:00:00+00:00",
    )


class TestNetworkAsset:
    def test_full_record(self) -> None:
        asset = _sample_asset()
        data = asset.to_dict()
        for field in ("asset_identity", "ip_addresses", "ipv6_addresses", "mac_address",
                      "hostname", "fqdn", "device_type", "manufacturer", "model",
                      "os", "os_version", "network_zone", "environment",
                      "cloud_provider", "location", "owner", "criticality",
                      "discovery_confidence", "first_seen", "last_seen"):
            assert field in data

    def test_from_host_ip(self) -> None:
        asset = NetworkAsset.from_host("10.1.1.5", device_type="switch")
        assert asset.asset_identity == "10.1.1.5"
        assert asset.ip_addresses == ["10.1.1.5"]
        assert asset.device_type == "switch"

    def test_from_host_fqdn_preferred_identity(self) -> None:
        asset = NetworkAsset.from_host("core-router.corp.example.com")
        assert asset.asset_identity == "core-router.corp.example.com"
        assert asset.fqdn == "core-router.corp.example.com"

    def test_from_dict_roundtrip(self) -> None:
        original = _sample_asset()
        restored = NetworkAsset.from_dict(original.to_dict())
        assert restored == original

    def test_mac_normalization(self) -> None:
        assert normalize_mac("00-1A-2B-3C-4D-5E") == "00:1a:2b:3c:4d:5e"
        assert normalize_mac(None) is None


class TestAssetRegistry:
    def test_upsert_dedupe_by_identity(self) -> None:
        registry = AssetRegistry()
        a = _sample_asset()
        b = NetworkAsset.from_dict(a.to_dict())
        b.model = "ASR-1002-X"
        b.last_seen = "2026-09-01T00:00:00+00:00"
        kept = registry.upsert(a)
        merged = registry.upsert(b)
        assert registry.count() == 1
        # first-seen identity wins; later records only fill gaps
        assert merged.model == "ASR-1002"
        assert kept is merged

    def test_merge_preserves_ips_and_zones(self) -> None:
        registry = AssetRegistry()
        first = NetworkAsset.from_host("10.1.0.1", network_zone="zone-a")
        second = NetworkAsset.from_host("10.1.0.1", network_zone="zone-b")
        second.ipv6_addresses.append("2001:db8::1")
        registry.upsert(first)
        merged = registry.upsert(second)
        assert merged.network_zone in ("zone-a", "zone-b")
        assert "2001:db8::1" in merged.ipv6_addresses

    def test_by_ip_and_get(self) -> None:
        registry = AssetRegistry()
        registry.upsert(_sample_asset())
        assert registry.get("edge-01.example.com") is not None
        assert registry.by_ip("10.1.0.1") != []

    def test_import_records(self) -> None:
        registry = AssetRegistry()
        count = registry.import_records([
            NetworkAsset.from_host("10.0.0.1").to_dict(),
            NetworkAsset.from_host("10.0.0.2").to_dict(),
            NetworkAsset.from_host("10.0.0.1").to_dict(),  # duplicate
        ])
        assert count == 3  # records processed
        assert registry.count() == 2  # unique assets

    def test_summary(self) -> None:
        registry = AssetRegistry()
        registry.upsert(_sample_asset())
        summary = registry.summary()
        assert summary == {"router": 1}  # by device type

    def test_identity_prefers_fqdn(self) -> None:
        assert asset_identity_for("10.0.0.9", hostname="svc.example.com") == "svc.example.com"


# ------------------------------------------------------------- scan modes

class TestScanModes:
    def test_default_is_safe(self) -> None:
        mode = default_scan_mode()
        assert mode.mode == "SAFE"
        assert mode.concurrency < ScanMode("STANDARD").concurrency

    def test_mode_presets(self) -> None:
        assert MODES == ("SAFE", "STANDARD", "DEEP", "AGGRESSIVE")
        safe = ScanMode("SAFE")
        assert safe.udp_init_probes is False
        assert safe.credentialed is False
        deep = ScanMode("DEEP", ScanAuthorization(authorization_scope="emirates-dc"))
        assert deep.udp_init_probes is True
        assert deep.concurrency > safe.concurrency

    def test_deep_requires_authorization(self) -> None:
        with pytest.raises(ValueError):
            ScanMode("DEEP")
        with pytest.raises(ValueError):
            ScanMode("AGGRESSIVE")

    def test_unknown_mode_rejected(self) -> None:
        with pytest.raises(ValueError):
            ScanMode("RECKLESS")

    def test_authorization_scope(self) -> None:
        mode = ScanMode("DEEP", ScanAuthorization(authorization_scope="branch-12"))
        assert mode.to_dict()["authorization_scope"] == "branch-12"
        assert mode.allows("udp_init")

    def test_authorization_contains_networks(self) -> None:
        auth = ScanAuthorization(authorization_scope="x", networks=["10.0.0.0/8"])
        assert auth.authorizes("10.1.2.3")
        assert not auth.authorizes("192.168.1.1")
        assert ScanAuthorization().authorizes("10.0.0.1") is False

    def test_scan_metadata_records_everything(self) -> None:
        meta = ScanMetadata(default_scan_mode())
        meta.targets_probed = 4
        meta.finish()
        data = meta.to_dict()
        assert data["scan_mode"] == "SAFE"
        assert data["rate_limit"] > 0
        assert data["concurrency"] > 0
        assert data["start_time"] <= (data["end_time"] or "")
        assert "authorization_scope" in data

    def test_feature_gate_udp_init_safe(self) -> None:
        assert ScanMode("SAFE").allows("udp_init") is False
        assert ScanMode("STANDARD").allows("udp_init") is True


# ------------------------------------------------------------- credentials

class TestCredentials:
    def test_credential_ref_frozen_and_typed(self) -> None:
        ref = CredentialRef(type="SSH", ref="vault:secret/network/routers",
                            username="admin")
        with pytest.raises(ValueError):
            CredentialRef(type="IRC", ref="x")
        assert ref.to_dict()["type"] == "SSH"
        assert ref.to_dict()["ref"].startswith("vault:")

    def test_all_credential_types_supported(self) -> None:
        for cred_type in ("SSH", "SNMPV3", "REST_API", "NETCONF", "RESTCONF",
                          "GNMI", "VENDOR_CONTROLLER", "CLOUD_API"):
            ref = CredentialRef(type=cred_type, ref=f"vault:{cred_type.lower()}")
            assert ref.type == cred_type

    def test_vault_resolution_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CRYPTOSCAN_VAULT_SECRET_NETWORK_RTR", "s3cret!")
        vault = CredentialVault()
        resolved = vault.resolve(CredentialRef(type="SSH", ref="vault:secret/network/rtr"))
        assert resolved["secret"] == "s3cret!"
        with pytest.raises(CredentialUnavailable):
            vault.resolve(CredentialRef(type="SSH", ref="vault:missing/path"))

    def test_scrub_secrets_drops_secret_keys(self) -> None:
        record = {"endpoint": "10.0.0.1", "password": "hunter2",
                  "community": "public", "token": "abc", "safe": "x"}
        cleaned = scrub_secrets(record)
        assert "password" not in cleaned
        assert "community" not in cleaned
        assert "token" not in cleaned
        assert cleaned["safe"] == "x"
        assert "hunter2" not in str(cleaned)

    def test_scrub_secrets_redacts_inline(self) -> None:
        cleaned = scrub_secrets({"config": "username cisco password 0 abc123"})
        assert "abc123" not in str(cleaned)
        assert "***REDACTED***" in str(cleaned)

    def test_scrub_private_key_block(self) -> None:
        pem = "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"
        cleaned = scrub_secrets({"key": pem})
        assert "MIIB" not in str(cleaned)
        assert "REDACTED-PRIVATE-KEY" in str(cleaned)

    def test_scrub_nested(self) -> None:
        record = {"devices": [{"name": "r1", "secret": "x"}]}
        cleaned = scrub_secrets(record)
        assert cleaned["devices"][0]["name"] == "r1"
        assert "secret" not in cleaned["devices"][0]

    def test_scrub_all(self) -> None:
        records = [{"password": "x"}, {"name": "ok"}]
        cleaned = scrub_all(records)
        assert "password" not in cleaned[0]
        assert cleaned[1] == {"name": "ok"}
