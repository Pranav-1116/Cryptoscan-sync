"""Optional live Azure scan. Requires azure-identity + azure-mgmt-*; fail-open otherwise."""

from __future__ import annotations

import os
from typing import Any

from cloud_scanner.azure.scanners import (
    scan_app_gateway,
    scan_front_door,
    scan_key_vault,
    scan_sql,
    scan_storage,
)


def live_enabled(flag: bool | None = None) -> bool:
    if flag is not None:
        return bool(flag)
    return os.environ.get("CRYPTOSCAN_CLOUD_LIVE", "").strip().lower() in {"1", "true", "yes", "on"}


def scan_azure(*, subscription_id: str | None = None) -> list[dict[str, Any]]:
    sub = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID") or os.environ.get("CRYPTOSCAN_AZURE_SUBSCRIPTION")
    if not sub:
        return []
    try:
        from cloud_scanner.azure.auth.credential_manager import azure_credential

        cred = azure_credential()
    except Exception:
        cred = None
    if cred is None:
        try:
            from azure.identity import DefaultAzureCredential  # type: ignore

            cred = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        except Exception:
            return []
    findings: list[dict[str, Any]] = []
    findings.extend(_with_client(lambda: _key_vaults(cred, sub), []))
    findings.extend(_with_client(lambda: _storage(cred, sub), []))
    findings.extend(_with_client(lambda: _sql(cred, sub), []))
    findings.extend(_with_client(lambda: _app_gateways(cred, sub), []))
    findings.extend(_with_client(lambda: _front_doors(cred, sub), []))
    return findings


def _with_client(call, default):
    try:
        return call()
    except Exception:
        return default


def _key_vaults(cred, sub: str) -> list[dict[str, Any]]:
    try:
        from azure.mgmt.keyvault import KeyVaultManagementClient  # type: ignore
    except Exception:
        return []
    kv = KeyVaultManagementClient(cred, sub)
    factory = None
    try:
        from azure.keyvault.keys import KeyClient  # type: ignore

        factory = lambda url, _cred=cred: KeyClient(vault_url=url, credential=_cred)
    except Exception:
        factory = None
    return scan_key_vault(kv, subscription=sub, key_client_factory=factory)


def _storage(cred, sub: str) -> list[dict[str, Any]]:
    try:
        from azure.mgmt.storage import StorageManagementClient  # type: ignore
    except Exception:
        return []
    return scan_storage(StorageManagementClient(cred, sub), subscription=sub)


def _sql(cred, sub: str) -> list[dict[str, Any]]:
    try:
        from azure.mgmt.sql import SqlManagementClient  # type: ignore
    except Exception:
        return []
    return scan_sql(SqlManagementClient(cred, sub), subscription=sub)


def _app_gateways(cred, sub: str) -> list[dict[str, Any]]:
    try:
        from azure.mgmt.network import NetworkManagementClient  # type: ignore
    except Exception:
        return []
    return scan_app_gateway(NetworkManagementClient(cred, sub), subscription=sub)


def _front_doors(cred, sub: str) -> list[dict[str, Any]]:
    try:
        from azure.mgmt.frontdoor import FrontDoorManagementClient  # type: ignore
    except Exception:
        return []
    try:
        return scan_front_door(FrontDoorManagementClient(cred, sub), subscription=sub)
    except Exception:
        return []
