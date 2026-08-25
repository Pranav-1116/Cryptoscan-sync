"""DefaultAzureCredential wrapper. Fail-open when the SDK is missing."""

from __future__ import annotations

from typing import Any

from cloud_scanner.azure.auth.service_principal_auth import service_principal_kwargs


def azure_credential(*, sp: dict[str, Any] | None = None):
    try:
        from azure.identity import ClientSecretCredential, DefaultAzureCredential  # type: ignore
    except Exception:
        return None
    creds = sp or service_principal_kwargs()
    if creds:
        try:
            return ClientSecretCredential(
                tenant_id=creds["tenant_id"],
                client_id=creds["client_id"],
                client_secret=creds["client_secret"],
            )
        except Exception:
            return None
    try:
        return DefaultAzureCredential(exclude_interactive_browser_credential=True)
    except Exception:
        return None
