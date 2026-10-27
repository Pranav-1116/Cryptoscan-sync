"""Google credentials wrapper. Fail-open when the SDK is missing."""

from __future__ import annotations

from typing import Any

from cloud_scanner.gcp.auth.service_account_auth import service_account_info


def gcp_credentials(*, info: dict[str, Any] | None = None):
    payload = info or service_account_info()
    try:
        from google.oauth2 import service_account  # type: ignore
    except Exception:
        return None
    if payload:
        try:
            return service_account.Credentials.from_service_account_info(payload)
        except Exception:
            return None
    try:
        import google.auth  # type: ignore

        creds, _project = google.auth.default()
        return creds
    except Exception:
        return None
