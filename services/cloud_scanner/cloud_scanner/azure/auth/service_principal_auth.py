"""Azure service principal auth kwargs from environment or explicit values."""

from __future__ import annotations

import os
from typing import Any


def service_principal_kwargs(
    *,
    tenant_id: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
) -> dict[str, Any] | None:
    tenant = tenant_id or os.environ.get("AZURE_TENANT_ID")
    cid = client_id or os.environ.get("AZURE_CLIENT_ID")
    secret = client_secret or os.environ.get("AZURE_CLIENT_SECRET")
    if not (tenant and cid and secret):
        return None
    return {"tenant_id": tenant, "client_id": cid, "client_secret": secret}
