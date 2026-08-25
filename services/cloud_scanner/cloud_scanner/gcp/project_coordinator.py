"""Multi-project GCP scan coordination."""

from __future__ import annotations

from typing import Any

from cloud_scanner.gcp.live import scan_gcp


def scan_projects(project_ids: list[str] | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    ids = project_ids or []
    if not ids:
        return scan_gcp()
    for project in ids[:8]:
        findings.extend(scan_gcp(project=project))
    return findings
