"""Network vendor plugins (spec §2A): Cisco, Juniper, Arista, MikroTik.

Discovery: routers/switches/wireless, VPN, SSH, TLS, IPsec, certificates,
topology, cryptographic configuration. All parsing is config/banner text
based — read-only, key material scrubbed.
"""

from __future__ import annotations

import re
from typing import Any

from universal_vendor.models import (
    AssetType,
    CryptoType,
    UniversalObservation,
    VendorCategory,
    Visibility,
)
from universal_vendor.plugin import scrub_secrets
from universal_vendor.plugins._helpers import (
    BannerPluginBase,
    extract_algorithms,
)

try:  # reuse the real Cisco running-config parser when available
    from network_scanner.enterprise.vendors.cisco import (
        parse_cisco_running_config,
        classify_cisco_device,
    )
except Exception:  # pragma: no cover - network scanner unavailable
    parse_cisco_running_config = None  # type: ignore[assignment]
    classify_cisco_device = None  # type: ignore[assignment]


class CiscoPlugin(BannerPluginBase):
    plugin_id = "cisco_ios_xe"
    vendor = "Cisco"
    product = "IOS-XE"
    category = VendorCategory.NETWORK
    supported_products = ["IOS-XE", "IOS", "IOS-XR", "NX-OS", "ASA"]
    supported_features = ["inventory", "ssh_crypto", "ipsec", "tls",
                          "certificates", "topology"]
    api_requirements = ["config text or SSH/NETCONF/RESTCONF session"]
    auth_methods = ["ssh", "netconf", "restconf"]
    trusted = True

    _patterns = [
        (r"cisco ios[- ]xe", "Cisco", "IOS-XE", 0.95),
        (r"cisco ios[- ]xr", "Cisco", "IOS-XR", 0.95),
        (r"cisco ios software", "Cisco", "IOS", 0.93),
        (r"cisco nx-os", "Cisco", "NX-OS", 0.95),
        (r"cisco (?:asa|adaptive security)", "Cisco", "ASA", 0.95),
        (r"crypto (?:isakmp|ipsec|pki)", "Cisco", "IOS", 0.7),
    ]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        config = context.get("config", "")
        if parse_cisco_running_config is not None:
            parsed = parse_cisco_running_config(config)
        else:  # minimal fallback
            parsed = {
                "ikev1_policies": [], "ikev2_proposals": [],
                "ipsec_transform_sets": [], "ssh": {}, "tls": {},
                "certificates": [], "routing_auth": {}, "vpn": {},
            }
        observations: list[dict[str, Any]] = []
        for policy in parsed.get("ikev1_policies") or []:
            observations.append(self._raw_observation(
                crypto_type=CryptoType.PROTOCOL.value, algorithm="IKEv1",
                asset_id="device", configuration=scrub_secrets(policy),
                protocol="IPsec/IKEv1"))
        for proposal in parsed.get("ikev2_proposals") or []:
            observations.append(self._raw_observation(
                crypto_type=CryptoType.PROTOCOL.value, algorithm="IKEv2",
                asset_id="device", configuration=scrub_secrets(proposal),
                protocol="IPsec/IKEv2"))
        for ts in parsed.get("ipsec_transform_sets") or []:
            observations.append(self._raw_observation(
                crypto_type=CryptoType.PROTOCOL.value, algorithm="IPsec",
                asset_id="device", configuration=scrub_secrets(ts),
                protocol="IPsec"))
        ssh = parsed.get("ssh") or {}
        if ssh:
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="SSH",
                asset_id="device", configuration=scrub_secrets(ssh),
                protocol="SSH"))
        tls = parsed.get("tls") or {}
        if tls:
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="TLS",
                asset_id="device", configuration=scrub_secrets(tls),
                protocol="TLS"))
        for algo in extract_algorithms(config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.ALGORITHM.value, algorithm=algo,
                asset_id="device"))
        return observations

    def discover_certificates(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        config = context.get("config", "")
        trustpoints: list[dict[str, Any]] = []
        for match in re.finditer(r"crypto pki trustpoint (\S+)", config):
            trustpoints.append({"name": match.group(1), "type": "trustpoint"})
        return [self._raw_observation(
            crypto_type=CryptoType.CERTIFICATE.value, asset_id="device",
            certificate=scrub_secrets(tp), visibility=Visibility.OBSERVED.value)
            for tp in trustpoints]

    def discover_dependencies(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        deps = []
        for match in re.finditer(r"crypto map (\S+)", context.get("config", "")):
            deps.append({"asset_id": "device", "target_asset": match.group(1),
                         "relationship": "USES_VPN"})
        return deps

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            product_version=raw.get("product_version"),
            asset_id=raw.get("asset_id") or "device",
            asset_type=AssetType.ROUTER.value,
            crypto_type=raw.get("crypto_type", CryptoType.ALGORITHM.value),
            algorithm=raw.get("algorithm"),
            protocol=raw.get("protocol"),
            certificate=raw.get("certificate"),
            configuration=raw.get("configuration"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.9),
            visibility=raw.get("visibility", Visibility.OBSERVED.value),
            vendor_specific=scrub_secrets(raw),
        )


class JuniperPlugin(BannerPluginBase):
    plugin_id = "juniper_junos"
    vendor = "Juniper"
    product = "Junos"
    category = VendorCategory.NETWORK
    supported_products = ["Junos", "ScreenOS"]
    supported_features = ["inventory", "ssh_crypto", "ipsec", "certificates"]
    trusted = True

    _patterns = [
        (r"juniper (?:networks )?(?:junos|screenos)", "Juniper", "Junos", 0.93),
        (r"set security ike", "Juniper", "Junos", 0.8),
    ]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        config = context.get("config", "")
        observations = []
        for algo in extract_algorithms(config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.ALGORITHM.value, algorithm=algo,
                asset_id="device"))
        for block in re.finditer(r"set security ike proposal (\S+)", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.PROTOCOL.value, algorithm="IKE",
                asset_id="device", configuration={"proposal": block.group(1)},
                protocol="IKE"))
        return observations

    def discover_certificates(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        certs = []
        for match in re.finditer(r"set security certificates (?:local )?(\S+)", context.get("config", "")):
            certs.append({"name": match.group(1), "type": "local-certificate"})
        return [self._raw_observation(
            crypto_type=CryptoType.CERTIFICATE.value, asset_id="device",
            certificate=cert) for cert in certs]

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            product_version=raw.get("product_version"),
            asset_id=raw.get("asset_id") or "device",
            asset_type=AssetType.ROUTER.value,
            crypto_type=raw.get("crypto_type", CryptoType.ALGORITHM.value),
            algorithm=raw.get("algorithm"),
            protocol=raw.get("protocol"),
            certificate=raw.get("certificate"),
            configuration=raw.get("configuration"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.88),
            visibility=raw.get("visibility", Visibility.OBSERVED.value),
            vendor_specific=scrub_secrets(raw),
        )


class AristaPlugin(BannerPluginBase):
    plugin_id = "arista_eos"
    vendor = "Arista"
    product = "EOS"
    category = VendorCategory.NETWORK
    supported_features = ["inventory", "ssh_crypto", "tls"]
    trusted = True

    _patterns = [
        (r"arista (?:networks )?eos", "Arista", "EOS", 0.93),
        (r"arista", "Arista", "EOS", 0.8),
    ]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        config = context.get("config", "")
        return [self._raw_observation(
            crypto_type=CryptoType.ALGORITHM.value, algorithm=algo,
            asset_id="device") for algo in extract_algorithms(config)]

    def discover_certificates(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        certs = []
        for match in re.finditer(r"(?:management api|ip security|ssl) certificate (\S+)", context.get("config", "")):
            certs.append({"name": match.group(1)})
        return [self._raw_observation(
            crypto_type=CryptoType.CERTIFICATE.value, asset_id="device",
            certificate=cert) for cert in certs]

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            asset_id=raw.get("asset_id") or "device",
            asset_type=AssetType.SWITCH.value,
            crypto_type=raw.get("crypto_type", CryptoType.ALGORITHM.value),
            algorithm=raw.get("algorithm"),
            certificate=raw.get("certificate"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.85),
            visibility=raw.get("visibility", Visibility.OBSERVED.value),
            vendor_specific=scrub_secrets(raw),
        )


class MikroTikPlugin(BannerPluginBase):
    plugin_id = "mikrotik_routeros"
    vendor = "MikroTik"
    product = "RouterOS"
    category = VendorCategory.NETWORK
    supported_features = ["inventory", "ssh_crypto", "ipsec"]
    trusted = True

    _patterns = [
        (r"mikrotik routeros", "MikroTik", "RouterOS", 0.93),
        (r"mikrotik", "MikroTik", "RouterOS", 0.8),
    ]

    def discover_configuration(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """RouterOS crypto-relevant settings: SSH strong-crypto, certs, TLS."""
        config = context.get("config", "")
        observations = []
        for match in re.finditer(r"/ip ssh set (strong-crypto=yes|strong-crypto=no)", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="SSH",
                asset_id="device", configuration={"strong_crypto": match.group(1).split("=")[1]},
                protocol="SSH"))
        for match in re.finditer(r"/certificate (?:add|import) name=(\S+)", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="certificate-store",
                asset_id="device", configuration={"certificate": match.group(1)}))
        return observations

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        config = context.get("config", "")
        observations = []
        for algo in extract_algorithms(config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.ALGORITHM.value, algorithm=algo,
                asset_id="device"))
        for match in re.finditer(r"/ip ipsec proposal set (\S+)", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.PROTOCOL.value, algorithm="IPsec",
                asset_id="device", configuration={"proposal": match.group(1)},
                protocol="IPsec"))
        for match in re.finditer(r"/ip ssh set strong-crypto=(\S+)", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="SSH",
                asset_id="device",
                configuration={"strong_crypto": match.group(1)},
                protocol="SSH"))
        return observations

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            asset_id=raw.get("asset_id") or "device",
            asset_type=AssetType.ROUTER.value,
            crypto_type=raw.get("crypto_type", CryptoType.ALGORITHM.value),
            algorithm=raw.get("algorithm"),
            configuration=raw.get("configuration"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.85),
            visibility=raw.get("visibility", Visibility.OBSERVED.value),
            vendor_specific=scrub_secrets(raw),
        )
