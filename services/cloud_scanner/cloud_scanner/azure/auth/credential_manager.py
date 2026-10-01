"""DefaultAzureCredential wrapper. Fail-open when the SDK is missing."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


from typing import Any

from cloud_scanner.azure.auth.service_principal_auth import service_principal_kwargs


def azure_credential(*, sp: dict[str, Any] | None = None):
    try:
        from azure.identity import ClientSecretCredential, DefaultAzureCredential  # type: ignore
    except Exception as _handler_exc:
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        return None
    creds = sp or service_principal_kwargs()
    if creds:
        try:
            return ClientSecretCredential(
                tenant_id=creds["tenant_id"],
                client_id=creds["client_id"],
                client_secret=creds["client_secret"],
            )
        except Exception as _handler_exc:
            logger.warning(
                "exception_suppressed",
                extra={"error_type": type(_handler_exc).__name__},
            )
            return None
    try:
        return DefaultAzureCredential(exclude_interactive_browser_credential=True)
    except Exception as _handler_exc:
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        return None
