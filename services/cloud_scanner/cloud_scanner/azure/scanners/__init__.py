"""Azure service scanners. Accept injected clients so unit tests do not need SDKs."""

from __future__ import annotations

from typing import Any, Callable

from cloud_scanner.common.finding import cloud_finding
from cloud_scanner.common.objects import attr, iter_records, named, resource_group, safe
from cloud_scanner.core.reliability import ScanTelemetry, cap_items

KeyClientFactory = Callable[[str], Any]


def _records(client: Any, *path: str) -> list[Any]:
    if isinstance(client, list):
        return client
    current = client
    for name in path:
        if current is None:
            return []
        nxt = attr(current, name)
        if callable(nxt):
            current = safe(nxt, [])
        else:
            current = nxt
    if callable(current):
        current = safe(current, [])
    return iter_records(current)


def _key_bits(key_obj: Any, key_type: str | None) -> int | None:
    size = attr(key_obj, "key_size", "keySize", "n")
    if isinstance(size, int):
        # RSA modulus integers are huge; real key sizes are <= 8192 bits.
        if size > 16384:
            return int(size.bit_length())
        return size
    if size is not None and hasattr(size, "bit_length"):
        try:
            return int(size.bit_length())
        except Exception:
            return None
    inner = attr(key_obj, "key")
    if inner is not None and inner is not key_obj:
        return _key_bits(inner, key_type)
    raw = (key_type or "").upper()
    if "4096" in raw:
        return 4096
    if "3072" in raw:
        return 3072
    if "2048" in raw:
        return 2048
    if "P256" in raw or raw.endswith("256"):
        return 256
    if "P384" in raw:
        return 384
    if "P521" in raw:
        return 521
    return None


def _map_key_type(raw: str | None) -> tuple[str, int | None]:
    token = (raw or "RSA").upper()
    if token.startswith("EC") or "ECDSA" in token:
        bits = 384 if "384" in token else (521 if "521" in token else 256)
        return "ECDSA", bits
    if "RSA" in token:
        bits = 4096 if "4096" in token else (3072 if "3072" in token else 2048)
        return "RSA", bits
    if "OCT" in token or "AES" in token:
        return "AES-256", 256
    return token, None


def scan_key_vault(
    client: Any,
    *,
    subscription: str = "unknown",
    key_client_factory: KeyClientFactory | None = None,
    telemetry: ScanTelemetry | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    vaults = _records(client, "vaults", "list")
    if not vaults and not isinstance(client, list):
        vaults = _records(client, "list")
    for vault in cap_items(vaults, telemetry=telemetry, provider="AZURE", service="keyvault", region=subscription):
        name = named(vault, "vault")
        vault_id = str(attr(vault, "id", default=name) or name)
        findings.append(
            cloud_finding(
                source_type="AZURE_KEY_VAULT",
                resource=name,
                algorithm="RSA",
                purpose="KEY_MANAGEMENT",
                file_path=f"azure://keyvault/{name}",
                provider="AZURE",
                extra={
                    "subscription": subscription,
                    "scan_method": "LIVE_API",
                    "location": attr(vault, "location"),
                    "resource_id": vault_id,
                },
            )
        )
        keys: list[Any] = []
        if key_client_factory:
            url = attr(vault, "vault_uri", "vaultUri") or f"https://{name}.vault.azure.net"
            kclient = safe(lambda: key_client_factory(str(url)))
            if kclient is not None:
                listed = attr(kclient, "list_properties_of_keys")
                keys = iter_records(safe(listed, []) if callable(listed) else listed)
        else:
            keys = iter_records(attr(vault, "keys") or [])
        for key in cap_items(keys, telemetry=telemetry, provider="AZURE", service="keyvault-keys", region=subscription):
            details = key
            key_name = named(key, "key")
            if key_client_factory and kclient is not None and hasattr(kclient, "get_key"):
                details = safe(lambda: kclient.get_key(key_name), key) or key
            inner = attr(details, "key") or details
            kty = str(attr(inner, "kty", "key_type", "keyType", default="RSA") or "RSA")
            algo, bits = _map_key_type(kty)
            bits = _key_bits(details, kty) or bits
            enabled = attr(attr(details, "properties") or details, "enabled", default=True)
            ops = attr(inner, "key_ops", "keyOps") or []
            findings.append(
                cloud_finding(
                    source_type="AZURE_KEY_VAULT_KEY",
                    resource=f"{name}/{key_name}",
                    algorithm=algo,
                    key_size=bits,
                    purpose="KEY_MANAGEMENT",
                    file_path=f"azure://keyvault/{name}/{key_name}",
                    provider="AZURE",
                    issue=None if enabled else "KEY_DISABLED",
                    extra={
                        "subscription": subscription,
                        "scan_method": "LIVE_API",
                        "key_type": kty,
                        "operations": list(ops) if ops else [],
                        "enabled": bool(enabled),
                    },
                )
            )
    return findings


def scan_storage(client: Any, *, subscription: str = "unknown", telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    accounts = _records(client, "storage_accounts", "list")
    if not accounts and not isinstance(client, list):
        accounts = _records(client, "list")
    for account in cap_items(accounts, telemetry=telemetry, provider="AZURE", service="storage", region=subscription):
        name = named(account, "storage")
        https = attr(account, "enable_https_traffic_only", "https_traffic_only_enabled", "supportsHttpsTrafficOnly")
        if https is None:
            https = True
        encryption = attr(account, "encryption") or {}
        services = attr(encryption, "services") or {}
        blob = attr(services, "blob") or {}
        blob_on = attr(blob, "enabled", default=True)
        if blob_on is None:
            blob_on = True
        issue = None
        algo = "AES-256"
        if not blob_on:
            issue = "NO_ENCRYPTION"
            algo = None
        elif not https:
            issue = "NO_HTTPS_ONLY"
        findings.append(
            cloud_finding(
                source_type="AZURE_STORAGE_ACCOUNT",
                resource=name,
                algorithm=algo,
                purpose="DATA_AT_REST_ENCRYPTION",
                file_path=f"azure://storage/{name}",
                provider="AZURE",
                issue=issue,
                extra={
                    "subscription": subscription,
                    "scan_method": "LIVE_API",
                    "https_only": bool(https),
                    "blob_encryption": bool(blob_on),
                    "location": attr(account, "location"),
                },
            )
        )
    return findings


def scan_sql(client: Any, *, subscription: str = "unknown", telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if isinstance(client, list):
        for item in cap_items(list(client), telemetry=telemetry, provider="AZURE", service="sql", region=subscription):
            name = named(item, "sql")
            tde = attr(item, "transparent_data_encryption_enabled", "tde_enabled", "status", default=True)
            if isinstance(tde, str):
                tde_on = tde.lower() == "enabled"
            else:
                tde_on = bool(tde) if tde is not None else True
            findings.append(
                cloud_finding(
                    source_type="AZURE_SQL_DATABASE",
                    resource=name,
                    algorithm="AES-256" if tde_on else None,
                    purpose="DATABASE_ENCRYPTION",
                    file_path=f"azure://sql/{name}",
                    provider="AZURE",
                    issue=None if tde_on else "NO_ENCRYPTION_AT_REST",
                    extra={"subscription": subscription, "scan_method": "LIVE_API"},
                )
            )
        return findings
    servers = _records(client, "servers", "list")
    for server in cap_items(servers, telemetry=telemetry, provider="AZURE", service="sql", region=subscription):
        name = named(server, "sql")
        rg = resource_group(str(attr(server, "id", default="") or ""))
        listed = False
        if rg and hasattr(client, "databases"):
            dbs = iter_records(safe(lambda: client.databases.list_by_server(rg, name), []))
            for db in cap_items(dbs, telemetry=telemetry, provider="AZURE", service="sql-databases", region=subscription):
                listed = True
                db_name = named(db, "db")
                tde_on = True
                if hasattr(client, "transparent_data_encryptions"):
                    tde = safe(lambda: client.transparent_data_encryptions.get(rg, name, db_name, "current"))
                    status = attr(tde, "status", default="Enabled")
                    tde_on = str(status).lower() == "enabled"
                findings.append(
                    cloud_finding(
                        source_type="AZURE_SQL_DATABASE",
                        resource=f"{name}/{db_name}",
                        algorithm="AES-256" if tde_on else None,
                        purpose="DATABASE_ENCRYPTION",
                        file_path=f"azure://sql/{name}/{db_name}",
                        provider="AZURE",
                        issue=None if tde_on else "NO_ENCRYPTION_AT_REST",
                        extra={"subscription": subscription, "scan_method": "LIVE_API"},
                    )
                )
        if not listed:
            findings.append(
                cloud_finding(
                    source_type="AZURE_SQL_SERVER",
                    resource=name,
                    algorithm="AES-256",
                    purpose="DATABASE_ENCRYPTION",
                    file_path=f"azure://sql/{name}",
                    provider="AZURE",
                    extra={"subscription": subscription, "scan_method": "LIVE_API"},
                )
            )
    return findings


def _weak_tls(token: str | None) -> bool:
    raw = (token or "").upper().replace("-", "_").replace(".", "_")
    return any(part in raw for part in ("TLS1_0", "TLS_1_0", "TLSV1_0", "TLS1_1", "TLS_1_1", "TLSV1_1", "SSL"))


def scan_app_gateway(client: Any, *, subscription: str = "unknown", telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    gateways = _records(client, "application_gateways", "list_all")
    if not gateways:
        gateways = _records(client, "list_all") or _records(client, "list")
    for gw in cap_items(gateways, telemetry=telemetry, provider="AZURE", service="appgateway", region=subscription):
        name = named(gw, "appgw")
        ssl = attr(gw, "ssl_policy", "sslPolicy") or gw
        min_proto = str(attr(ssl, "min_protocol_version", "minProtocolVersion", "min_tls_version", default="") or "")
        weak = _weak_tls(min_proto)
        findings.append(
            cloud_finding(
                source_type="AZURE_APP_GATEWAY",
                resource=name,
                algorithm="TLS1.0" if weak else "TLS",
                purpose="LOAD_BALANCER_TLS",
                file_path=f"azure://appgw/{name}",
                provider="AZURE",
                issue="WEAK_TLS_VERSION" if weak else None,
                extra={"subscription": subscription, "scan_method": "LIVE_API", "min_protocol": min_proto},
            )
        )
    return findings


def scan_front_door(client: Any, *, subscription: str = "unknown", telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    doors = _records(client, "front_doors", "list")
    if not doors:
        doors = _records(client, "profiles", "list") or _records(client, "list")
    for door in cap_items(doors, telemetry=telemetry, provider="AZURE", service="frontdoor", region=subscription):
        name = named(door, "frontdoor")
        min_proto = str(
            attr(door, "min_tls_version", "minimum_tls_version", "minTlsVersion", default="")
            or attr(attr(door, "tls_settings") or {}, "minimum_tls_version", default="")
            or ""
        )
        weak = _weak_tls(min_proto) or min_proto.strip() in {"1.0", "1.1"}
        findings.append(
            cloud_finding(
                source_type="AZURE_FRONT_DOOR",
                resource=name,
                algorithm="TLS1.0" if weak else "TLS",
                purpose="LOAD_BALANCER_TLS",
                file_path=f"azure://frontdoor/{name}",
                provider="AZURE",
                issue="WEAK_TLS_VERSION" if weak else None,
                extra={"subscription": subscription, "scan_method": "LIVE_API", "min_protocol": min_proto},
            )
        )
    return findings


def scan_cosmosdb(client: Any, *, subscription: str = "unknown", telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    """Cosmos DB accounts: CMK encryption + minimum TLS version."""
    findings: list[dict[str, Any]] = []
    accounts = _records(client, "database_accounts", "list")
    if not accounts and not isinstance(client, list):
        accounts = _records(client, "list")
    for account in cap_items(accounts, telemetry=telemetry, provider="AZURE", service="cosmosdb", region=subscription):
        name = named(account, "cosmos")
        if isinstance(account, dict):
            cmk = bool((account.get("properties") or {}).get("keyVaultKeyUri") or account.get("key_vault_key_uri"))
            tls = (account.get("properties") or {}).get("minimalTlsVersion") or account.get("minimal_tls_version")
        else:
            cmk = bool(attr(account, "key_vault_key_uri", "keyVaultKeyUri"))
            tls = attr(account, "minimal_tls_version", "minimalTlsVersion")
        tls_token = str(tls or "Tls12")
        weak = any(part in tls_token.upper() for part in ("TLS1_0", "TLS1_1", "1.0", "1.1"))
        issue = None
        if weak:
            issue = "WEAK_TLS_VERSION"
        findings.append(
            cloud_finding(
                source_type="AZURE_COSMOSDB_ACCOUNT",
                resource=name,
                algorithm="AES-256" if cmk else "AES-256",
                purpose="DATA_AT_REST_ENCRYPTION",
                file_path=f"azure://cosmosdb/{name}",
                provider="AZURE",
                issue=issue,
                extra={
                    "subscription": subscription,
                    "scan_method": "LIVE_API",
                    "customer_managed_key": cmk,
                    "minimal_tls_version": tls_token,
                },
            )
        )
    return findings


def scan_redis(client: Any, *, subscription: str = "unknown", telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    """Redis caches: TLS-only access + minimum TLS version."""
    findings: list[dict[str, Any]] = []
    caches = _records(client, "redis", "list_by_subscription")
    if not caches and not isinstance(client, list):
        caches = _records(client, "list")
    for cache in cap_items(caches, telemetry=telemetry, provider="AZURE", service="redis", region=subscription):
        name = named(cache, "redis")
        if isinstance(cache, dict):
            props = cache.get("properties") or {}
            ssl = props.get("enableNonSslPort", cache.get("enable_non_ssl_port"))
            tls = props.get("minimumTlsVersion") or cache.get("minimum_tls_version")
        else:
            ssl = attr(cache, "enable_non_ssl_port", "enableNonSslPort")
            tls = attr(cache, "minimum_tls_version", "minimumTlsVersion")
        non_ssl = bool(ssl)
        tls_token = str(tls or "1.2")
        weak = any(part in tls_token for part in ("1.0", "1.1"))
        issue = None
        if non_ssl:
            issue = "NO_HTTPS_ONLY"
        elif weak:
            issue = "WEAK_TLS_VERSION"
        findings.append(
            cloud_finding(
                source_type="AZURE_REDIS_CACHE",
                resource=name,
                algorithm="TLS" if not weak else "TLS1.0",
                purpose="TRANSPORT_ENCRYPTION",
                file_path=f"azure://redis/{name}",
                provider="AZURE",
                issue=issue,
                extra={
                    "subscription": subscription,
                    "scan_method": "LIVE_API",
                    "non_ssl_port": non_ssl,
                    "minimum_tls_version": tls_token,
                },
            )
        )
    return findings


def scan_servicebus(client: Any, *, subscription: str = "unknown", telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    """Service Bus namespaces: CMK encryption + minimum TLS version."""
    findings: list[dict[str, Any]] = []
    namespaces = _records(client, "namespaces", "list")
    if not namespaces and not isinstance(client, list):
        namespaces = _records(client, "list")
    for ns in cap_items(namespaces, telemetry=telemetry, provider="AZURE", service="servicebus", region=subscription):
        name = named(ns, "sb")
        if isinstance(ns, dict):
            cmk = bool((ns.get("properties") or {}).get("keyVaultProperties") or ns.get("key_vault_properties"))
            tls = (ns.get("properties") or {}).get("minimumTlsVersion") or ns.get("minimum_tls_version")
        else:
            cmk = bool(attr(ns, "key_vault_properties", "keyVaultProperties"))
            tls = attr(ns, "minimum_tls_version", "minimumTlsVersion")
        tls_token = str(tls or "1.2")
        weak = any(part in tls_token for part in ("1.0", "1.1"))
        issue = None
        if weak:
            issue = "WEAK_TLS_VERSION"
        findings.append(
            cloud_finding(
                source_type="AZURE_SERVICEBUS_NAMESPACE",
                resource=name,
                algorithm="AES-256",
                purpose="DATA_AT_REST_ENCRYPTION",
                file_path=f"azure://servicebus/{name}",
                provider="AZURE",
                issue=issue,
                extra={
                    "subscription": subscription,
                    "scan_method": "LIVE_API",
                    "customer_managed_key": cmk,
                    "minimum_tls_version": tls_token,
                },
            )
        )
    return findings
