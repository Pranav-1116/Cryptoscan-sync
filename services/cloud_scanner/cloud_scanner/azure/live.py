"""Optional live Azure scan. Requires azure-identity + azure-mgmt-*; fail-open otherwise."""

from __future__ import annotations

import os
from typing import Any

from cloud_scanner.common.finding import cloud_finding


def live_enabled(flag: bool | None = None) -> bool:
    if flag is not None:
        return bool(flag)
    return os.environ.get("CRYPTOSCAN_CLOUD_LIVE", "").strip().lower() in {"1", "true", "yes", "on"}


def scan_azure(*, subscription_id: str | None = None) -> list[dict[str, Any]]:
    sub = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID") or os.environ.get("CRYPTOSCAN_AZURE_SUBSCRIPTION")
    if not sub:
        return []
    try:
        from azure.identity import DefaultAzureCredential  # type: ignore
    except Exception:
        return []
    try:
        cred = DefaultAzureCredential(exclude_interactive_browser_credential=True)
    except Exception:
        return []
    findings: list[dict[str, Any]] = []
    findings.extend(_key_vaults(cred, sub))
    findings.extend(_storage(cred, sub))
    findings.extend(_sql(cred, sub))
    findings.extend(_app_gateways(cred, sub))
    return findings


def _key_vaults(cred, sub: str) -> list[dict[str, Any]]:
    try:
        from azure.mgmt.keyvault import KeyVaultManagementClient  # type: ignore
    except Exception:
        return []
    findings: list[dict[str, Any]] = []
    try:
        kv = KeyVaultManagementClient(cred, sub)
        for vault in list(kv.vaults.list())[:40]:
            findings.append(
                cloud_finding(
                    source_type="AZURE_KEY_VAULT",
                    resource=getattr(vault, "name", None) or getattr(vault, "id", "vault"),
                    algorithm="RSA",
                    purpose="KEY_MANAGEMENT",
                    file_path=f"azure://keyvault/{getattr(vault, 'name', 'vault')}",
                    provider="AZURE",
                    extra={"scan_method": "LIVE_API", "location": getattr(vault, "location", None)},
                )
            )
    except Exception:
        return findings
    return findings


def _storage(cred, sub: str) -> list[dict[str, Any]]:
    try:
        from azure.mgmt.storage import StorageManagementClient  # type: ignore
    except Exception:
        return []
    findings: list[dict[str, Any]] = []
    try:
        storage = StorageManagementClient(cred, sub)
        for account in list(storage.storage_accounts.list())[:40]:
            https = bool(getattr(account, "enable_https_traffic_only", True))
            findings.append(
                cloud_finding(
                    source_type="AZURE_STORAGE_ACCOUNT",
                    resource=getattr(account, "name", None) or "storage",
                    algorithm="AES-256" if https else None,
                    purpose="DATA_AT_REST_ENCRYPTION",
                    file_path=f"azure://storage/{getattr(account, 'name', 'storage')}",
                    provider="AZURE",
                    issue=None if https else "NO_HTTPS_ONLY",
                    extra={"scan_method": "LIVE_API"},
                )
            )
    except Exception:
        return findings
    return findings


def _sql(cred, sub: str) -> list[dict[str, Any]]:
    try:
        from azure.mgmt.sql import SqlManagementClient  # type: ignore
    except Exception:
        return []
    findings: list[dict[str, Any]] = []
    try:
        sql = SqlManagementClient(cred, sub)
        for server in list(sql.servers.list())[:30]:
            name = getattr(server, "name", None) or "sql"
            rg = _resource_group(getattr(server, "id", ""))
            tde_on = True
            if rg:
                try:
                    dbs = list(sql.databases.list_by_server(rg, name))[:10]
                    for db in dbs:
                        try:
                            tde = sql.transparent_data_encryptions.get(rg, name, db.name, "current")
                            tde_on = str(getattr(tde, "status", "Enabled")).lower() == "enabled"
                        except Exception:
                            continue
                        findings.append(
                            cloud_finding(
                                source_type="AZURE_SQL_DATABASE",
                                resource=f"{name}/{db.name}",
                                algorithm="AES-256" if tde_on else None,
                                purpose="DATABASE_ENCRYPTION",
                                file_path=f"azure://sql/{name}/{db.name}",
                                provider="AZURE",
                                issue=None if tde_on else "NO_ENCRYPTION_AT_REST",
                                extra={"scan_method": "LIVE_API"},
                            )
                        )
                except Exception:
                    findings.append(
                        cloud_finding(
                            source_type="AZURE_SQL_SERVER",
                            resource=name,
                            algorithm="AES-256",
                            purpose="DATABASE_ENCRYPTION",
                            file_path=f"azure://sql/{name}",
                            provider="AZURE",
                            extra={"scan_method": "LIVE_API"},
                        )
                    )
    except Exception:
        return findings
    return findings


def _app_gateways(cred, sub: str) -> list[dict[str, Any]]:
    try:
        from azure.mgmt.network import NetworkManagementClient  # type: ignore
    except Exception:
        return []
    findings: list[dict[str, Any]] = []
    try:
        net = NetworkManagementClient(cred, sub)
        for gw in list(net.application_gateways.list_all())[:20]:
            ssl = getattr(gw, "ssl_policy", None)
            min_proto = str(getattr(ssl, "min_protocol_version", "") or "").upper()
            weak = any(token in min_proto for token in ("TLS1_0", "TLS1_1", "SSL", "TLSv1_0", "TLSv1_1"))
            findings.append(
                cloud_finding(
                    source_type="AZURE_APP_GATEWAY",
                    resource=getattr(gw, "name", None) or getattr(gw, "id", "appgw"),
                    algorithm="TLS1.0" if weak else "TLS",
                    purpose="LOAD_BALANCER_TLS",
                    file_path=f"azure://appgw/{getattr(gw, 'name', 'appgw')}",
                    provider="AZURE",
                    issue="WEAK_TLS_VERSION" if weak else None,
                    extra={"scan_method": "LIVE_API", "min_protocol": min_proto},
                )
            )
    except Exception:
        return findings
    return findings


def _resource_group(resource_id: str) -> str:
    parts = (resource_id or "").split("/")
    for idx, part in enumerate(parts):
        if part.lower() == "resourcegroups" and idx + 1 < len(parts):
            return parts[idx + 1]
    return ""
