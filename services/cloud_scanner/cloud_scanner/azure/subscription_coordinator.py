"""Multi-subscription Azure scan coordination."""

from __future__ import annotations

from typing import Any

from cloud_scanner.azure.live import scan_azure


def scan_subscriptions(subscription_ids: list[str] | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    ids = subscription_ids or []
    if not ids:
        return scan_azure()
    for sub in ids[:8]:
        findings.extend(scan_azure(subscription_id=sub))
    return findings
