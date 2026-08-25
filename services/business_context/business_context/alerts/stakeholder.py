"""Notify business owners of P0 crypto risk. SMTP optional; always logs."""

from __future__ import annotations

import logging
from typing import Any, Iterable, Mapping

logger = logging.getLogger(__name__)


def notify_stakeholders(assets: Iterable[Mapping[str, Any]], *, smtp_host: str | None = None) -> list[dict[str, Any]]:
    sent: list[dict[str, Any]] = []
    for asset in assets:
        ctx = (asset.get("extra") or {}).get("business_context") or asset.get("business_context") or {}
        if ctx.get("priority") != "P0":
            continue
        owners = ctx.get("business_owners") or []
        payload = {
            "algorithm": asset.get("algorithm"),
            "file_path": asset.get("file_path"),
            "owners": owners,
            "revenue": ctx.get("total_revenue_at_risk"),
            "message": f"P0 crypto risk: {asset.get('algorithm')} at {asset.get('file_path')}",
        }
        logger.warning("stakeholder_alert", extra=payload)
        sent.append(payload)
    return sent
