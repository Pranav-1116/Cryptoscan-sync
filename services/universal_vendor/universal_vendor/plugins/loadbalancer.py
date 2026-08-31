"""Load balancer / ADC vendor plugins (spec §2C): F5 BIG-IP, NGINX, HAProxy.

"One load balancer may protect hundreds of applications" — so these plugins
also emit *backend dependency* observations (TLS termination → backend TLS),
which feed the universal dependency graph.
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
from universal_vendor.plugins._helpers import BannerPluginBase, extract_algorithms


class F5Plugin(BannerPluginBase):
    plugin_id = "f5_bigip"
    vendor = "F5"
    product = "BIG-IP"
    category = VendorCategory.LOAD_BALANCER
    supported_features = ["tls_termination", "certificates", "cipher_policies",
                          "mtls", "backend_tls", "ssl_profiles"]
    trusted = True

    _patterns = [
        (r"f5 (?:networks )?(?:big-?ip|bigip)", "F5", "BIG-IP", 0.95),
        (r"ltm profile (?:client-ssl|server-ssl)", "F5", "BIG-IP", 0.85),
    ]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        config = context.get("config", "")
        observations = []
        for algo in extract_algorithms(config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.ALGORITHM.value, algorithm=algo,
                asset_id="lb"))
        # SSL profiles: client (front-end TLS) and server (backend TLS)
        for match in re.finditer(r"ltm profile client-ssl (\S+)", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="TLS",
                asset_id="lb", configuration={"profile": match.group(1),
                                              "side": "client"},
                protocol="TLS"))
        for match in re.finditer(r"ltm profile server-ssl (\S+)", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="TLS",
                asset_id="lb", configuration={"profile": match.group(1),
                                              "side": "server"},
                protocol="TLS"))
        for match in re.finditer(r"ltm cipher cipher group (\S+)", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="cipher-policy",
                asset_id="lb", configuration={"group": match.group(1)},
                protocol="TLS"))
        return observations

    def discover_certificates(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        certs = []
        for match in re.finditer(r"ltm certificate (\S+)", context.get("config", "")):
            certs.append({"name": match.group(1), "type": "server"})
        return [self._raw_observation(
            crypto_type=CryptoType.CERTIFICATE.value, asset_id="lb",
            certificate=cert) for cert in certs]

    def discover_dependencies(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """client-ssl profile → backend pool (protected-by relationship)."""
        config = context.get("config", "")
        deps = []
        for match in re.finditer(r"ltm pool (\S+)", config):
            deps.append({"asset_id": "lb", "target_asset": match.group(1),
                         "relationship": "PROTECTS"})
        return deps

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            asset_id=raw.get("asset_id") or "lb",
            asset_type=AssetType.LOAD_BALANCER.value,
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


class NginxPlugin(BannerPluginBase):
    plugin_id = "nginx"
    vendor = "NGINX"
    product = "NGINX"
    category = VendorCategory.LOAD_BALANCER
    supported_features = ["tls_termination", "certificates", "cipher_policies",
                          "mtls", "backend_tls"]
    trusted = True

    _patterns = [
        (r"nginx(?:/|\s)", "NGINX", "NGINX", 0.88),
        (r"server_name|listen 443 ssl", "NGINX", "NGINX", 0.7),
    ]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        config = context.get("config", "")
        observations = []
        for algo in extract_algorithms(config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.ALGORITHM.value, algorithm=algo,
                asset_id="nginx"))
        ssl_count = len(re.findall(r"listen\s+\S*\s*ssl", config))
        if ssl_count:
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="TLS",
                asset_id="nginx", configuration={"ssl_listen_blocks": ssl_count},
                protocol="TLS"))
        for match in re.finditer(r"ssl_ciphers\s+([^;]+);", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="cipher-policy",
                asset_id="nginx", configuration={"ciphers": match.group(1).strip()},
                protocol="TLS"))
        return observations

    def discover_certificates(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        certs = []
        for match in re.finditer(r"ssl_certificate\s+(\S+);", context.get("config", "")):
            certs.append({"path": match.group(1), "type": "server"})
        return [self._raw_observation(
            crypto_type=CryptoType.CERTIFICATE.value, asset_id="nginx",
            certificate=cert) for cert in certs]

    def discover_dependencies(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        deps = []
        for match in re.finditer(r"proxy_pass\s+(\S+);", context.get("config", "")):
            deps.append({"asset_id": "nginx", "target_asset": match.group(1).rstrip(";"),
                         "relationship": "PROXIES_TO"})
        return deps

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            asset_id=raw.get("asset_id") or "nginx",
            asset_type=AssetType.LOAD_BALANCER.value,
            crypto_type=raw.get("crypto_type", CryptoType.ALGORITHM.value),
            algorithm=raw.get("algorithm"),
            protocol=raw.get("protocol"),
            certificate=raw.get("certificate"),
            configuration=raw.get("configuration"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.85),
            visibility=raw.get("visibility", Visibility.OBSERVED.value),
            vendor_specific=scrub_secrets(raw),
        )


class HaProxyPlugin(BannerPluginBase):
    plugin_id = "haproxy"
    vendor = "HAProxy"
    product = "HAProxy"
    category = VendorCategory.LOAD_BALANCER
    supported_features = ["tls_termination", "certificates", "cipher_policies"]
    trusted = True

    _patterns = [
        (r"haproxy", "HAProxy", "HAProxy", 0.9),
    ]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        config = context.get("config", "")
        observations = []
        for algo in extract_algorithms(config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.ALGORITHM.value, algorithm=algo,
                asset_id="haproxy"))
        for match in re.finditer(r"bind\s+\S+\s+ssl(?:\s+[^#\n]*)", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="TLS",
                asset_id="haproxy", configuration={"bind": match.group(0)[:80]},
                protocol="TLS"))
        return observations

    def discover_certificates(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        certs = []
        for match in re.finditer(r"crt\s+(\S+)", context.get("config", "")):
            certs.append({"path": match.group(1)})
        return [self._raw_observation(
            crypto_type=CryptoType.CERTIFICATE.value, asset_id="haproxy",
            certificate=cert) for cert in certs]

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            asset_id=raw.get("asset_id") or "haproxy",
            asset_type=AssetType.LOAD_BALANCER.value,
            crypto_type=raw.get("crypto_type", CryptoType.ALGORITHM.value),
            algorithm=raw.get("algorithm"),
            protocol=raw.get("protocol"),
            certificate=raw.get("certificate"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.85),
            visibility=raw.get("visibility", Visibility.OBSERVED.value),
            vendor_specific=scrub_secrets(raw),
        )
