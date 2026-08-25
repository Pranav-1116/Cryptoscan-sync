"""Certificate inventory endpoints (spec-named router)."""

from __future__ import annotations

from api.routers.network import (
    certificate_usages,
    check_revocation,
    get_certificate,
    list_certificates,
    router,
)

__all__ = [
    "certificate_usages",
    "check_revocation",
    "get_certificate",
    "list_certificates",
    "router",
]
