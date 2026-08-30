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


def scan_app_service(client: Any, *, subscription: str = "unknown", telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    """App Service sites: minimum TLS version, HTTPS-only, client-cert auth."""
    findings: list[dict[str, Any]] = []
    sites = _records(client, "web_apps", "list")
    if not sites and not isinstance(client, list):
        sites = _records(client, "list")
    for site in cap_items(sites, telemetry=telemetry, provider="AZURE", service="appservice", region=subscription):
        name = named(site, "site")
        if isinstance(site, dict):
            props = site.get("properties") or {}
            site_config = props.get("siteConfig") or {}
            min_tls = props.get("minTlsVersion") or site_config.get("minTlsVersion")
            https_only = props.get("httpsOnly")
            client_cert = props.get("clientCertEnabled")
        else:
            site_config = attr(site, "site_config", "siteConfig") or {}
            min_tls = attr(site, "min_tls_version", "minTlsVersion") or attr(site_config, "min_tls_version", "minTlsVersion")
            https_only = attr(site, "https_only", "httpsOnly")
            client_cert = attr(site, "client_cert_enabled", "clientCertEnabled")
        token = str(min_tls or "")
        weak = _weak_tls(token) or token.strip() in {"1.0", "1.1", "1.0;", "1.1;"}
        issue = None
        if not bool(https_only):
            issue = "NO_HTTPS_ONLY"
        elif weak:
            issue = "WEAK_TLS_VERSION"
        findings.append(
            cloud_finding(
                source_type="AZURE_APP_SERVICE",
                resource=name,
                algorithm="TLS1.0" if weak else "TLS",
                purpose="TRANSPORT_ENCRYPTION",
                file_path=f"azure://appservice/{name}",
                provider="AZURE",
                issue=issue,
                extra={
                    "subscription": subscription,
                    "scan_method": "LIVE_API",
                    "min_tls_version": token,
                    "https_only": bool(https_only),
                    "client_cert_enabled": bool(client_cert),
                },
            )
        )
    return findings


def scan_dns(client: Any, *, subscription: str = "unknown", telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    """Azure DNS zones: DNSSEC signing (public zones) — private zones exempt."""
    findings: list[dict[str, Any]] = []
    zones = _records(client, "zones", "list")
    if not zones and not isinstance(client, list):
        zones = _records(client, "list")
    for zone in cap_items(zones, telemetry=telemetry, provider="AZURE", service="dns", region=subscription):
        name = named(zone, "zone")
        zone_id = str(attr(zone, "id", default="") or "")
        rg = resource_group(zone_id)
        if isinstance(zone, dict):
            zone_type = str((zone.get("properties") or {}).get("zoneType") or zone.get("zone_type") or "Public")
        else:
            zone_type = str(attr(zone, "zone_type", "zoneType", default="Public") or "Public")
        private = zone_type.lower() == "private"
        dnssec_on = False
        signing_keys = 0
        if rg and hasattr(client, "dnssec_configs"):
            cfg = safe(lambda: client.dnssec_configs.get(rg, name, "default"))
            if cfg is not None:
                props = attr(cfg, "properties") or cfg
                keys = iter_records(attr(props, "signing_keys", "signingKeys") or [])
                signing_keys = len(keys)
                dnssec_on = signing_keys > 0 or str(attr(props, "provisioning_state", "provisioningState", default="")).lower() == "succeeded"
        issue = None if dnssec_on or private else "DNSSEC_DISABLED"
        findings.append(
            cloud_finding(
                source_type="AZURE_DNS_ZONE",
                resource=name,
                algorithm="ECDSA" if dnssec_on else None,
                purpose="DNS_SIGNING",
                file_path=f"azure://dns/{name}",
                provider="AZURE",
                issue=issue,
                extra={
                    "subscription": subscription,
                    "scan_method": "LIVE_API",
                    "dnssec_enabled": dnssec_on,
                    "signing_key_count": signing_keys,
                    "zone_type": zone_type,
                    "resource_group": rg,
                },
            )
        )
    return findings


def scan_acr(client: Any, *, subscription: str = "unknown", telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    """Container registries: CMK encryption, quarantine + content-trust policies."""
    findings: list[dict[str, Any]] = []
    registries = _records(client, "registries", "list")
    if not registries and not isinstance(client, list):
        registries = _records(client, "list")
    for reg in cap_items(registries, telemetry=telemetry, provider="AZURE", service="acr", region=subscription):
        name = named(reg, "registry")
        if isinstance(reg, dict):
            props = reg.get("properties") or {}
            enc = props.get("encryption") or {}
            policies = props.get("policies") or {}
            quar = (policies.get("quarantinePolicy") or {}).get("status")
            trust = (policies.get("trustPolicy") or {}).get("status")
            retention = (policies.get("retentionPolicy") or {}).get("status")
            network = props.get("publicNetworkAccess") or "Enabled"
        else:
            enc = attr(reg, "encryption") or {}
            policies = attr(reg, "policies") or {}
            quar = attr(attr(policies, "quarantine_policy", "quarantinePolicy") or {}, "status")
            trust = attr(attr(policies, "trust_policy", "trustPolicy") or {}, "status")
            retention = attr(attr(policies, "retention_policy", "retentionPolicy") or {}, "status")
            network = attr(reg, "public_network_access", "publicNetworkAccess", default="Enabled")
        kms = attr(enc, "key_vault_properties", "keyVaultProperties") or attr(enc, "key_vault", "keyVault")
        enc_status = str(attr(enc, "status", default="") or "")
        issue = None
        if str(quar or "").lower() != "enabled":
            issue = "QUARANTINE_DISABLED"
        elif str(trust or "").lower() != "enabled":
            issue = "CONTENT_TRUST_DISABLED"
        findings.append(
            cloud_finding(
                source_type="AZURE_CONTAINER_REGISTRY",
                resource=name,
                algorithm="AES-256",
                purpose="DATA_AT_REST_ENCRYPTION",
                file_path=f"azure://acr/{name}",
                provider="AZURE",
                issue=issue,
                extra={
                    "subscription": subscription,
                    "scan_method": "LIVE_API",
                    "encryption_status": enc_status,
                    "customer_managed_key": bool(kms),
                    "quarantine_policy": quar,
                    "content_trust": trust,
                    "retention_policy": retention,
                    "public_network_access": network,
                },
            )
        )
    return findings


def _weak_ike_token(token: str | None) -> bool:
    """Exact token match so DHGroup14 is never confused with DHGroup1."""
    raw = (token or "").upper().replace("-", "_").replace(".", "_").replace(" ", "_")
    tokens = {t for t in raw.split("_") if t}
    weak = {"DHGROUP1", "DHGROUP2", "DHGROUPNONE", "DES", "DES3", "MD5", "SHA1", "IKEV1", "NONE"}
    return bool(tokens & weak)


def scan_vpn_gateway(client: Any, *, subscription: str = "unknown", telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    """VPN gateways: IKE version + IPsec policies (DH group, encryption, integrity) per connection."""
    findings: list[dict[str, Any]] = []
    gateways = _records(client, "virtual_network_gateways", "list")
    if not gateways and not isinstance(client, list):
        gateways = _records(client, "list")
    for gw in cap_items(gateways, telemetry=telemetry, provider="AZURE", service="vpngateway", region=subscription):
        name = named(gw, "vnetgw")
        rg = resource_group(str(attr(gw, "id", default="") or ""))
        conns: list[Any] = []
        if rg and hasattr(client, "virtual_network_gateway_connections"):
            conns = iter_records(safe(lambda: client.virtual_network_gateway_connections.list(rg), []))
        weak_conns: list[str] = []
        conn_details: list[dict[str, Any]] = []
        for conn in cap_items(conns, telemetry=telemetry, provider="AZURE", service="vpnconn", region=subscription):
            conn_name = named(conn, "conn")
            if isinstance(conn, dict):
                cprops = conn.get("properties") or {}
                ike = cprops.get("ikeVersion")
                policies = cprops.get("ipsecPolicies") or []
            else:
                ike = attr(conn, "ike_version", "ikeVersion")
                policies = attr(conn, "ipsec_policies", "ipsecPolicies") or []
            conn_weak = _weak_ike_token(str(ike or ""))
            pol_list: list[dict[str, Any]] = []
            for policy in policies:
                dh = str(attr(policy, "dh_group", "dhGroup", default="") or "")
                enc = str(attr(policy, "ipsec_encryption", "ipsecEncryption", default="") or "")
                integ = str(attr(policy, "ipsec_integrity", "ipsecIntegrity", default="") or "")
                weak = _weak_ike_token(dh) or _weak_ike_token(enc) or _weak_ike_token(integ)
                if weak:
                    conn_weak = True
                pol_list.append({"dh_group": dh, "encryption": enc, "integrity": integ, "weak": weak})
            if conn_weak:
                weak_conns.append(conn_name)
            conn_details.append({"name": conn_name, "ike_version": str(ike or ""), "policies": pol_list, "weak": conn_weak})
        findings.append(
            cloud_finding(
                source_type="AZURE_VPN_GATEWAY",
                resource=name,
                algorithm="AES-256",
                purpose="NETWORK_ENCRYPTION",
                file_path=f"azure://vpngateway/{name}",
                provider="AZURE",
                issue="WEAK_IPSEC_POLICY" if weak_conns else None,
                extra={
                    "subscription": subscription,
                    "scan_method": "LIVE_API",
                    "gateway_type": str(attr(gw, "gateway_type", "gatewayType", default="") or ""),
                    "vpn_type": str(attr(gw, "vpn_type", "vpnType", default="") or ""),
                    "weak_connections": weak_conns,
                    "connections": conn_details,
                },
            )
        )
    return findings


def scan_managed_hsm(client: Any, *, subscription: str = "unknown", telemetry: ScanTelemetry | None = None) -> list[dict[str, Any]]:
    """Managed HSM pools: security-domain, purge protection, soft delete, network ACLs."""
    findings: list[dict[str, Any]] = []
    pools = _records(client, "managed_hsms", "list_by_subscription")
    if not pools and not isinstance(client, list):
        pools = _records(client, "list")
    for pool in cap_items(pools, telemetry=telemetry, provider="AZURE", service="managedhsm", region=subscription):
        name = named(pool, "hsm")
        if isinstance(pool, dict):
            props = pool.get("properties") or {}
            purge = props.get("enablePurgeProtection")
            soft = props.get("enableSoftDelete")
            secdom = props.get("securityDomain") or props.get("securityDomainProperties")
            network = props.get("networkAcls") or {}
        else:
            purge = attr(pool, "enable_purge_protection", "enablePurgeProtection")
            soft = attr(pool, "enable_soft_delete", "enableSoftDelete")
            secdom = attr(pool, "security_domain", "securityDomain")
            network = attr(pool, "network_acls", "networkAcls") or {}
        issues = []
        if not bool(purge):
            issues.append("NO_PURGE_PROTECTION")
        if not bool(soft):
            issues.append("NO_SOFT_DELETE")
        if not secdom:
            issues.append("NO_SECURITY_DOMAIN")
        findings.append(
            cloud_finding(
                source_type="AZURE_MANAGED_HSM",
                resource=name,
                algorithm="HSM",
                purpose="KEY_MANAGEMENT",
                file_path=f"azure://managedhsm/{name}",
                provider="AZURE",
                issue=";".join(issues) or None,
                extra={
                    "subscription": subscription,
                    "scan_method": "LIVE_API",
                    "purge_protection": bool(purge),
                    "soft_delete": bool(soft),
                    "security_domain_initialized": bool(secdom),
                    "bypass": str(attr(network, "bypass", "bypass", default="") or ""),
                    "default_action": str(attr(network, "default_action", "defaultAction", default="") or ""),
                },
            )
        )
    return findings
