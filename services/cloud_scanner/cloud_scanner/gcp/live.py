"""Optional live GCP scan. Requires google-cloud-*; fail-open otherwise."""

from __future__ import annotations

import os
from typing import Any

from cloud_scanner.gcp.scanners import scan_cloud_kms, scan_cloud_sql, scan_gcs, scan_load_balancer


def scan_gcp(*, project: str | None = None) -> list[dict[str, Any]]:
    project_id = project or os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCP_PROJECT")
    if not project_id:
        return []
    findings: list[dict[str, Any]] = []
    findings.extend(_kms(project_id))
    findings.extend(_storage(project_id))
    findings.extend(_sql(project_id))
    findings.extend(_ssl_policies(project_id))
    return findings


def _kms(project_id: str) -> list[dict[str, Any]]:
    try:
        from google.cloud import kms  # type: ignore

        return scan_cloud_kms(kms.KeyManagementServiceClient(), project=project_id)
    except Exception:
        return []


def _storage(project_id: str) -> list[dict[str, Any]]:
    try:
        from google.cloud import storage  # type: ignore

        return scan_gcs(storage.Client(project=project_id), project=project_id)
    except Exception:
        return []


def _sql(project_id: str) -> list[dict[str, Any]]:
    try:
        from googleapiclient.discovery import build  # type: ignore

        return scan_cloud_sql(build("sqladmin", "v1beta4", cache_discovery=False), project=project_id)
    except Exception:
        return []


def _ssl_policies(project_id: str) -> list[dict[str, Any]]:
    try:
        from googleapiclient.discovery import build  # type: ignore

        return scan_load_balancer(build("compute", "v1", cache_discovery=False), project=project_id)
    except Exception:
        return []
