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
        from azure.mgmt.keyvault import KeyVaultManagementClient  # type: ignore
        from azure.mgmt.storage import StorageManagementClient  # type: ignore
    except Exception:
        return []
    findings: list[dict[str, Any]] = []
    try:
        cred = DefaultAzureCredential(exclude_interactive_browser_credential=True)
    except Exception:
        return []
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
        pass
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
        pass
    return findings
