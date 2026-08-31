"""Middleware vendor plugins (spec §8): Apache httpd, Tomcat, IBM WebSphere,
Oracle WebLogic, Red Hat JBoss, IIS, Kafka, RabbitMQ.

Discover: TLS, mTLS, certificates, keystores, truststores, crypto libraries,
protocol versions, cipher configuration.
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


class _MiddlewarePluginBase(BannerPluginBase):
    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        config = context.get("config", "")
        observations = []
        for algo in extract_algorithms(config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.ALGORITHM.value, algorithm=algo,
                asset_id="middleware"))
        for match in re.finditer(r"SSLCipherSuite\s+(\S+)", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="cipher-policy",
                asset_id="middleware", configuration={"suite": match.group(1)},
                protocol="TLS"))
        for match in re.finditer(r"SSLProtocol\s+(\S+)", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="TLS",
                asset_id="middleware",
                configuration={"protocol": match.group(1)},
                protocol="TLS"))
        for match in re.finditer(r"(?:SSLVerifyClient|clientAuth)\s+(\S+)", config, re.IGNORECASE):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="mTLS",
                asset_id="middleware",
                configuration={"verify_client": match.group(1)},
                protocol="mTLS"))
        return observations

    def discover_certificates(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        certs = []
        config = context.get("config", "")
        for match in re.finditer(r"SSLCertificateFile\s+(\S+)", config):
            certs.append({"path": match.group(1), "type": "server"})
        for match in re.finditer(r"SSLCA(?:Certificate)?File\s+(\S+)", config):
            certs.append({"path": match.group(1), "type": "truststore"})
        for match in re.finditer(r"SSLVerifyClient\s+require", config):
            certs.append({"type": "client-auth-required"})
        return [self._raw_observation(
            crypto_type=CryptoType.CERTIFICATE.value, asset_id="middleware",
            certificate=cert) for cert in certs]

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            asset_id=raw.get("asset_id") or "middleware",
            asset_type=AssetType.MIDDLEWARE.value,
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


class ApacheHttpdPlugin(_MiddlewarePluginBase):
    plugin_id = "apache_httpd"
    vendor = "Apache"
    product = "HTTP Server"
    category = VendorCategory.MIDDLEWARE
    supported_features = ["tls", "mtls", "certificates", "cipher_policies"]
    trusted = True

    _patterns = [
        (r"apache(?:/|\s)", "Apache", "HTTP Server", 0.88),
        (r"SSLCipherSuite|SSLEngine on", "Apache", "HTTP Server", 0.8),
    ]


class TomcatPlugin(_MiddlewarePluginBase):
    plugin_id = "apache_tomcat"
    vendor = "Apache"
    product = "Tomcat"
    category = VendorCategory.MIDDLEWARE
    supported_features = ["tls", "certificates", "keystores", "cipher_policies"]
    trusted = True

    _patterns = [
        (r"tomcat", "Apache", "Tomcat", 0.9),
    ]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        config = context.get("config", "")
        observations = [super().discover_crypto(context)][0]
        for match in re.finditer(r'ciphers="([^"]+)"', config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="cipher-policy",
                asset_id="middleware", configuration={"ciphers": match.group(1)},
                protocol="TLS"))
        return observations

    def discover_certificates(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        certs = []
        config = context.get("config", "")
        for match in re.finditer(r'keystoreFile="([^"]+)"', config):
            certs.append({"keystore": match.group(1), "type": "keystore"})
        for match in re.finditer(r'truststoreFile="([^"]+)"', config):
            certs.append({"truststore": match.group(1), "type": "truststore"})
        return [self._raw_observation(
            crypto_type=CryptoType.CERTIFICATE.value, asset_id="middleware",
            certificate=cert) for cert in certs]


class WebSpherePlugin(_MiddlewarePluginBase):
    plugin_id = "ibm_websphere"
    vendor = "IBM"
    product = "WebSphere"
    category = VendorCategory.MIDDLEWARE
    supported_features = ["tls", "certificates", "keystores", "cipher_policies"]
    trusted = True

    _patterns = [
        (r"websphere", "IBM", "WebSphere", 0.9),
    ]


class WebLogicPlugin(_MiddlewarePluginBase):
    plugin_id = "oracle_weblogic"
    vendor = "Oracle"
    product = "WebLogic"
    category = VendorCategory.MIDDLEWARE
    supported_features = ["tls", "certificates", "keystores", "cipher_policies"]
    trusted = True

    _patterns = [
        (r"weblogic", "Oracle", "WebLogic", 0.9),
    ]


class JbossPlugin(_MiddlewarePluginBase):
    plugin_id = "redhat_jboss"
    vendor = "Red Hat"
    product = "JBoss"
    category = VendorCategory.MIDDLEWARE
    supported_features = ["tls", "certificates", "keystores"]
    trusted = True

    _patterns = [
        (r"jboss", "Red Hat", "JBoss", 0.9),
    ]
