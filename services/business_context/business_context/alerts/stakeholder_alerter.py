"""Named wrapper around notify_stakeholders."""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from business_context.alerts.stakeholder import notify_stakeholders


class StakeholderAlerter:
    def alert(
        self,
        assets: Iterable[Mapping[str, Any]],
        *,
        smtp_host: str | None = None,
    ) -> list[dict[str, Any]]:
        return notify_stakeholders(assets, smtp_host=smtp_host)


def alert_stakeholders(
    assets: Iterable[Mapping[str, Any]],
    *,
    smtp_host: str | None = None,
) -> list[dict[str, Any]]:
    return StakeholderAlerter().alert(assets, smtp_host=smtp_host)
