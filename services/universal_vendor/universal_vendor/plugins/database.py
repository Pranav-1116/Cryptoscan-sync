"""Database vendor plugins (spec §7): PostgreSQL, MySQL, MariaDB, SQL Server,
MongoDB, Redis.

Discover: TLS configuration, certificate usage, encryption configuration,
key-management references, encryption-at-rest metadata, client encryption.
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


class _DatabasePluginBase(BannerPluginBase):
    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        config = context.get("config", "")
        observations = []
        for algo in extract_algorithms(config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.ALGORITHM.value, algorithm=algo,
                asset_id="database"))
        # TLS enabled: postgres style "ssl = on", mysql/mssql "require_secure_transport"
        for match in re.finditer(r"(?:^|\n)\s*(ssl|require_secure_transport|tls)\s*=\s*(\S+)",
                                 config, re.IGNORECASE):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="TLS",
                asset_id="database",
                configuration={match.group(1).lower(): match.group(2).strip("\"'")},
                protocol="TLS"))
        # TLS listener ports (redis tls-port 6379)
        for match in re.finditer(r"(?:tls|ssl)[_-]port\s+(\d+)", config, re.IGNORECASE):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="TLS",
                asset_id="database", configuration={"tls_port": match.group(1)},
                protocol="TLS"))
        # cipher policy lines (hyphen or underscore key style)
        for match in re.finditer(r"ssl[_-]cipher[s]?\s*=\s*(\S+)", config, re.IGNORECASE):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="cipher-policy",
                asset_id="database", configuration={"cipher": match.group(1)},
                protocol="TLS"))
        for match in re.finditer(r"(?:encrypt|encryption)\s*=\s*(\S+)", config, re.IGNORECASE):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="encryption-at-rest",
                asset_id="database",
                configuration={"encryption": match.group(1).strip("\"'")}))
        return observations

    def discover_certificates(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        certs = []
        pattern = (r"(?:ssl[_-]cert[_-]file|tls[_-]cert[_-]file|tls[_-]key[_-]file|"
                   r"ssl[_-]cert|server[_-]cert|ssl[_-]ca)\s*=\s*(\S+)")
        for match in re.finditer(pattern, context.get("config", ""), re.IGNORECASE):
            certs.append({"path": match.group(1),
                          "type": "server" if "cert" in match.group(0).lower()
                          else "truststore"})
        return [self._raw_observation(
            crypto_type=CryptoType.CERTIFICATE.value, asset_id="database",
            certificate=cert) for cert in certs]

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            asset_id=raw.get("asset_id") or "database",
            asset_type=AssetType.DATABASE.value,
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


class PostgreSqlPlugin(_DatabasePluginBase):
    plugin_id = "postgresql"
    vendor = "PostgreSQL"
    product = "PostgreSQL"
    category = VendorCategory.DATABASE
    supported_features = ["tls", "certificates", "encryption_at_rest"]
    trusted = True

    _patterns = [
        (r"postgresql|postgres", "PostgreSQL", "PostgreSQL", 0.92),
    ]


class MySqlPlugin(_DatabasePluginBase):
    plugin_id = "mysql"
    vendor = "MySQL"
    product = "MySQL"
    category = VendorCategory.DATABASE
    supported_features = ["tls", "certificates", "encryption_at_rest"]
    trusted = True

    _patterns = [
        (r"mysql", "MySQL", "MySQL", 0.92),
    ]


class MariaDbPlugin(_DatabasePluginBase):
    plugin_id = "mariadb"
    vendor = "MariaDB"
    product = "MariaDB"
    category = VendorCategory.DATABASE
    supported_features = ["tls", "certificates", "encryption_at_rest"]
    trusted = True

    _patterns = [
        (r"mariadb", "MariaDB", "MariaDB", 0.92),
    ]


class SqlServerPlugin(_DatabasePluginBase):
    plugin_id = "mssql"
    vendor = "Microsoft"
    product = "SQL Server"
    category = VendorCategory.DATABASE
    supported_features = ["tls", "certificates", "encryption"]
    trusted = True

    _patterns = [
        (r"microsoft sql server", "Microsoft", "SQL Server", 0.92),
    ]


class MongoDbPlugin(_DatabasePluginBase):
    plugin_id = "mongodb"
    vendor = "MongoDB"
    product = "MongoDB"
    category = VendorCategory.DATABASE
    supported_features = ["tls", "certificates", "encryption_at_rest"]
    trusted = True

    _patterns = [
        (r"mongodb", "MongoDB", "MongoDB", 0.9),
    ]


class RedisPlugin(_DatabasePluginBase):
    plugin_id = "redis"
    vendor = "Redis"
    product = "Redis"
    category = VendorCategory.DATABASE
    supported_features = ["tls", "certificates"]
    trusted = True

    _patterns = [
        (r"redis", "Redis", "Redis", 0.9),
    ]


class CassandraPlugin(_DatabasePluginBase):
    plugin_id = "cassandra"
    vendor = "Apache"
    product = "Cassandra"
    category = VendorCategory.DATABASE
    supported_features = ["tls", "certificates", "encryption_at_rest"]
    trusted = True

    _patterns = [
        (r"cassandra", "Apache", "Cassandra", 0.9),
    ]
