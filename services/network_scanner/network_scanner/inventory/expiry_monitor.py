"""Build certificate expiry alerts (email is sent by the drift alerter if SMTP is set)."""

from __future__ import annotations

from typing import Any, Iterable

from network_scanner.inventory.certificate_inventory import expiring


def expiry_alerts(certs: Iterable[dict[str, Any]], *, days: int = 30) -> list[dict[str, Any]]:
    alerts = []
    for cert in expiring(certs, days=days):
        remaining = int(cert.get("days_until_expiry") or 0)
        severity = "HIGH" if remaining <= 7 else "MEDIUM"
        alerts.append(
            {
                "type": "CERTIFICATE_EXPIRING",
                "severity": severity,
                "message": f"Certificate expires in {remaining} days",
                "certificate": cert.get("subject"),
                "fingerprint": cert.get("fingerprint_sha256"),
                "days_until_expiry": remaining,
                "endpoints": cert.get("usages") or ([cert["endpoint"]] if cert.get("endpoint") else []),
            }
        )
    return alerts
