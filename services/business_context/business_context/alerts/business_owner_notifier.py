"""Notify business owners of P0 crypto risk."""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from business_context.alerts.stakeholder import notify_stakeholders


def notify_owners(assets: Iterable[Mapping[str, Any]], *, smtp_host: str | None = None) -> list[dict[str, Any]]:
    return [row for row in notify_stakeholders(assets, smtp_host=smtp_host) if row.get("body")]
