"""Alert on certificate expiry."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from network_scanner.inventory.expiry_monitor import expiry_alerts

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


class _Default(dict):
    def __missing__(self, key: str) -> str:
        return ""


def _render(name: str, **values: Any) -> str:
    path = TEMPLATE_DIR / name
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    payload = {key: ("" if value is None else value) for key, value in values.items()}
    try:
        return text.format_map(_Default(payload))
    except Exception:
        return text


def alert_expiring(certs: Iterable[dict[str, Any]], *, days: int = 30) -> list[dict[str, Any]]:
    alerts = expiry_alerts(certs, days=days)
    for alert in alerts:
        remaining = int(alert.get("days_until_expiry") or 0)
        stem = "cert_expiring_7days" if remaining <= 7 else "cert_expiring_30days"
        values = {
            "subject": alert.get("certificate") or "",
            "days_until_expiry": remaining,
            "fingerprint": alert.get("fingerprint") or "",
            "endpoints": ", ".join(str(item) for item in (alert.get("endpoints") or [])),
        }
        alert["body"] = _render(f"{stem}.txt", **values)
        alert["html_body"] = _render(f"{stem}.html", **values)
    return alerts
