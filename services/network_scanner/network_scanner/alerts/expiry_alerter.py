"""Alert on certificate expiry."""

from __future__ import annotations

from typing import Any, Iterable

from network_scanner.inventory.expiry_monitor import expiry_alerts


def alert_expiring(certs: Iterable[dict[str, Any]], *, days: int = 30) -> list[dict[str, Any]]:
    return expiry_alerts(certs, days=days)
